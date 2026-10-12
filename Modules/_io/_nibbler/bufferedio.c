/*
    An implementation of Buffered I/O as defined by PEP 3116 - "New I/O"

    Classes defined here: BufferedReader, BufferedWriter, BufferedRandom,
    BufferedRWPair, all derived from _io._BufferedIOBase.

    Originally written by Amaury Forgeot d'Arc and Antoine Pitrou; reworked
    around the "nibbler" model (see the notes before the buffered struct).
*/

#include "Python.h"
#include "pycore_abstract.h"            // _PyNumber_Index()
#include "pycore_fileutils.h"           // _PyFile_Flush()
#include "pycore_import.h"              // _PyImport_SetModuleString()
#include "pycore_object.h"              // _PyObject_GC_UNTRACK()
#include "pycore_pyatomic_ft_wrappers.h" // FT_ATOMIC_LOAD_PTR_RELAXED()
#include "pycore_pyerrors.h"            // _PyErr_ChainExceptions1()
#include "pycore_typeobject.h"          // _PyType_GetDict()
#include "pycore_weakref.h"             // FT_CLEAR_WEAKREFS()

#include "../_iomodule.h"
#include "nibbler.h"

/*[clinic input]
module _io
class _io._Buffered "buffered *" "clinic_state()->PyBufferedIOBase_Type"
class _io.BufferedReader "buffered *" "clinic_state()->PyBufferedReader_Type"
class _io.BufferedWriter "buffered *" "clinic_state()->PyBufferedWriter_Type"
class _io.BufferedRWPair "rwpair *" "clinic_state()->PyBufferedRWPair_Type"
class _io.BufferedRandom "buffered *" "clinic_state()->PyBufferedRandom_Type"
[clinic start generated code]*/
/*[clinic end generated code: output=da39a3ee5e6b4b0d input=c293ae41e3973d1f]*/

/* Per-module state: the five buffered types, and TextIOWrapper. */
typedef struct {
    PyTypeObject *PyBufferedIOBase_Type;
    PyTypeObject *PyBufferedReader_Type;
    PyTypeObject *PyBufferedWriter_Type;
    PyTypeObject *PyBufferedRandom_Type;
    PyTypeObject *PyBufferedRWPair_Type;
    PyTypeObject *PyTextIOWrapper_Type;
    /* _gather() context managers (see "Gathering" below). */
    PyTypeObject *Gather_Type;
    /* The nibblers of the initialized buffered objects: in the child of a
       fork, _PyIO_AfterForkChild() releases their mutexes that other
       threads held. */
    nibbler_set nibblers;
} nibblermodule_state;

static struct PyModuleDef _PyIO_nibbler_Module;

static inline nibblermodule_state *
get_nibblermodule_state(PyObject *module)
{
    void *state = _PyModule_GetState(module);
    assert(state != NULL);
    return (nibblermodule_state *)state;
}

static inline nibblermodule_state *
find_nibblermodule_state_by_def(PyTypeObject *type)
{
    PyObject *mod = PyType_GetModuleByDef(type, &_PyIO_nibbler_Module);
    assert(mod != NULL);
    return get_nibblermodule_state(mod);
}

/*
 * BufferedReader, BufferedWriter and BufferedRandom share one object layout
 * and most methods.
 *
 * Buffered data is held by a nibbler (see nibbler.h), which also does the
 * locking.  Data flows in one direction at a time, given by what is
 * buffered (with nothing buffered, the direction doesn't matter):
 *
 * - Writing: the morsels are pending writes, oldest first, and there is no
 *   reading end.  write() and flush() write them out together (in one call
 *   when the raw stream has a vectored _writev() method) with the I/O
 *   role, without holding the lock; meanwhile other threads can only queue
 *   more writes.  Small writes that fit are queued without the lock (see
 *   "The open end" in nibbler.h), so all code holding the lock sees them
 *   queued.  They check that an exact FileIO is open (one load of its
 *   fd), so the next write after raw.close() raises.  Other raw streams
 *   are asked through closed only with the lock: asking is a Python call
 *   that costs more than a whole lock-free write (about 1750-1950 against
 *   1120 instructions), and the counts of closes that would let small
 *   writes notice without asking were rejected as too complex (see
 *   "Closing the raw stream alone" in InternalDocs/io_nibbler.md).  Once
 *   one says it is closed, the open end is dropped, so that writes take
 *   the lock and raise; closing through the buffered object drops it too.
 *   So after such a raw stream was closed by itself, small writes are
 *   queued without an error until the room left in the current block is
 *   used up or an operation that takes the lock runs (flush(), a write
 *   that doesn't fit, seek(), ...), which raises.  Queued bytes never
 *   reach the closed raw stream: writing out asks closed first, and
 *   close() finds it closed and returns, keeping the open end, without
 *   writing them or warning; they are dropped with the object.
 *
 * - Reading: the reading end holds the bytes the last fill read (see "The
 *   open end" in nibbler.h).  Its position splits them: the bytes before
 *   it were returned already (seek() can move back over them), the rest are
 *   read-ahead, which reads take without the lock when they can.
 *
 * BufferedRandom switches direction as needed: before writing it hands
 * unread read-ahead back to the raw stream (by seeking), and before reading
 * it writes out everything pending.  So the logical position is always the
 * raw position plus pending writes, or minus unread read-ahead.
 *
 * With buffer size 0 (unbuffered; gh-148773), write() writes all of its
 * data straight to the raw stream, retrying partial writes, and keeps none
 * when the raw stream would block.  Reads go straight to the raw stream
 * too, retrying short reads as with a buffer but never asking for more
 * bytes than the caller wants: read1() with no size makes one raw read of
 * up to DEFAULT_BUFFER_SIZE bytes.  peek() and readline() (so also
 * iteration and readlines()) raise UnsupportedOperation, as they can't
 * look ahead without taking the bytes.  The only read-ahead is data kept
 * after a raw read raised (see buffered_push_back()), which reads, and peek(),
 * return first; readline() returns a line from it when all of it is there.
 *
 * With buffer size None (BufferedWriter and BufferedRandom), writes are
 * buffered without limit: the write-out threshold is PY_SSIZE_T_MAX, so
 * write() only queues its data (large exact bytes by reference, the rest
 * copied into blocks of DEFAULT_BUFFER_SIZE, or into a bytes object of its
 * own when larger) and never writes out.  Pending writes reach the raw
 * stream only through flush() and what has to write them out: close()
 * (and dealloc), detach(), seek(), truncate(), reads of BufferedRandom and
 * tell() in append mode.  Reads use blocks of DEFAULT_BUFFER_SIZE.  This
 * is what a _gather() block (see "Gathering") without a limit does, for all
 * writes, and in the pending writes themselves.
 */

typedef struct {
    PyObject_HEAD

    /* NULL while uninitialized or detached.  Only replaced with the lock
       held (and from GC clear and dealloc): code holding the lock uses
       it directly, code without takes a reference with buffered_get_raw().
       Everything below is set by __init__() and, unless noted, changed only
       with the lock held. */
    PyObject *raw;
    char finalizing;
    /* Fixed by __init__(): raw exactly FileIO (call its C implementation
       directly), raw has a vectored _writev() method, raw is a FileIO
       opened in append mode (it writes at the end, whatever the position;
       only set for writers).  The first is also read without the lock, so
       stored atomically. */
    uint8_t raw_fileio;
    uint8_t raw_vectored;
    /* Exact bytes written at least this large are kept by reference
       rather than copied into a block (see buffered_init()). */
    Py_ssize_t ref_min;
    uint8_t raw_appending;
    /* Fixed by __init__(): raw is an exact FileIO of a regular file, not in
       append mode, whose position the nibbler keeps (nib.raw_pos), so that
       tell() and seek() inside the read-ahead make no raw call.  Raw seek()
       and tell() set it, raw reads and writes advance it, and readall()
       and truncate() make it unknown; like _io's abs_pos, it assumes that
       nothing else moves the raw stream while data is buffered.  Not for a
       character device or a pipe, whose position does not follow what was
       read (GH-95782), nor in append mode, where writes go to the end; nor
       for other raw streams, whose methods could do anything. */
    uint8_t raw_regular;
    /* The records of _gather() blocks (see "Gathering"), in the order
       they were entered, and how many (also read without the lock, so
       stored atomically).  While there are some, there is no writing end
       and the reading end stays held, so that every write and read takes
       the lock and looks for the context's record. */
    struct gather *gather_first;
    struct gather **gather_last;
    int ngather;

    /* The buffered data and the lock.  Its capacity is the block size,
       which reads fill and small writes are copied into, and its threshold
       the number of pending bytes past which writes are written out; both
       are the buffer size (0: unbuffered; with buffer size None the
       threshold is PY_SSIZE_T_MAX, see above; the capacity is also read
       without the lock, by __sizeof__()).
       Whether the object is closed is up to raw: close() keeps it, so that
       name, mode and raw still work. */
    nibbler nib;

    /* Data the raw stream returned that follows the read-ahead but could
       not be put in it without a large allocation (see buffered_stash()).
       Raw reads take from it first, so it is read like the raw stream's own
       data.  Set only while reading. */
    morsel_list stash;

    PyObject *dict;
    PyObject *weakreflist;
    /* The module, whose state holds the set of nibblers this one is in
       (see buffered_track()), kept alive until dealloc removes it: in a
       garbage cycle, the type may drop its reference first. */
    PyObject *module;
} buffered;

static inline buffered *
buffered_cast(PyObject *op)
{
    return (buffered *)op;
}

/* The instance dict, or NULL: read without the lock (its creation, by
   setting an attribute, stores it atomically). */
static inline PyObject *
buffered_dict(buffered *self)
{
    return FT_ATOMIC_LOAD_PTR_RELAXED(self->dict);
}

static PyType_Spec nibbler_bufferedreader_spec;
static PyType_Spec nibbler_bufferedwriter_spec;
static PyType_Spec nibbler_bufferedrandom_spec;

/* Can it write: anything but a BufferedReader (or subclass)? */
static int
buffered_writable(buffered *self)
{
    return !PyType_GetBaseByToken(Py_TYPE(self),
                                  &nibbler_bufferedreader_spec, NULL);
}

/* Take the lock alone: to append, or to consume read-ahead (see "Locking"
   in nibbler.h). */
static inline int
buffered_lock(buffered *self)
{
    return nibbler_lock(&self->nib, (PyObject *)self);
}

static inline void
buffered_unlock(buffered *self)
{
    nibbler_unlock(&self->nib);
}

/* Release what buffered_enter() took for an operation other than
   appending: the I/O role and the lock. */
static inline void
buffered_leave(buffered *self)
{
    nibbler_unlock_io(&self->nib);
}

/* raw is set: initialized and not detached. */
static inline int
buffered_raw_usable(PyObject *raw)
{
    return raw != NULL;
}

static int
buffered_not_ready(void)
{
    PyErr_SetString(PyExc_ValueError,
                    "I/O operation on uninitialized or detached object");
    return -1;
}

/* raw is read without the lock by buffered_ref_raw(), which returns a new
   reference to it (NULL when uninitialized or detached): a concurrent
   detach() leaves the caller using the stream it took.  buffered_swap_raw()
   replaces it (with the lock held, or with no other users) and returns the
   old one.  With the GIL, plain loads and stores do. */
#ifdef Py_GIL_DISABLED
static inline PyObject *
buffered_ref_raw(buffered *self)
{
    return _Py_XGetRef(&self->raw);
}

static PyObject *
buffered_swap_raw(buffered *self, PyObject *raw)
{
    if (raw != NULL) {
        /* Lets buffered_ref_raw() take references without the lock. */
        _PyObject_SetMaybeWeakref(raw);
    }
    return _Py_atomic_exchange_ptr(&self->raw, raw);
}
#else
static inline PyObject *
buffered_ref_raw(buffered *self)
{
    return Py_XNewRef(self->raw);
}

static PyObject *
buffered_swap_raw(buffered *self, PyObject *raw)
{
    PyObject *old = self->raw;
    self->raw = raw;
    return old;
}
#endif

/* A new reference to a usable raw, or NULL with ValueError. */
static PyObject *
buffered_get_raw(buffered *self)
{
    PyObject *raw = buffered_ref_raw(self);
    if (!buffered_raw_usable(raw)) {
        buffered_not_ready();
    }
    return raw;
}

/* Are there pending writes?  Then there is no read-ahead.  (Called with
   the I/O role, so no other thread is writing them out.) */
static inline int
buffered_writing(buffered *self)
{
    return (nibbler_reading(&self->nib) == NULL
            && nibbler_nbytes(&self->nib) > 0);
}

/* Is it reading: is there a reading end (perhaps all read), or stashed
   data?  Then the raw position is past the logical one. */
static inline int
buffered_reading(buffered *self)
{
    return nibbler_reading(&self->nib) != NULL || self->stash.nbytes > 0;
}

/* Drop the stashed data.  Returns how many bytes it had. */
static Py_ssize_t
buffered_drop_stash(buffered *self)
{
    Py_ssize_t n = self->stash.nbytes;
    morsels_clear(&self->stash);
    return n;
}

/* Keep obj (bytes), data the raw stream returned, after the stashed data
   for the next reads.  Returns 0, or -1 on error (then it is lost). */
static int
buffered_stash(buffered *self, PyObject *obj)
{
    return morsels_push(&self->stash, obj, PyBytes_AS_STRING(obj),
                        PyBytes_GET_SIZE(obj));
}

/* Take up to len stashed bytes, copying them to dst.  Returns how many. */
static Py_ssize_t
buffered_take_stash(buffered *self, char *dst, Py_ssize_t len)
{
    Py_ssize_t done = 0;
    for (Py_ssize_t i = 0; i < self->stash.count && done < len; i++) {
        morsel *m = &self->stash.items[i];
        Py_ssize_t k = Py_MIN(m->len, len - done);
        memcpy(dst + done, m->ptr, k);
        done += k;
    }
    return morsels_consume(&self->stash, done);
}

/* Is raw closed (fileio: it is exactly a FileIO)?  Returns 1 if closed, 0
   if open, -1 on error. */
static int
buffered_raw_closed(PyObject *raw, int fileio)
{
    if (fileio) {
        return _PyFileIO_closed(raw);
    }
    PyObject *res = PyObject_GetAttr(raw, &_Py_ID(closed));
    if (res == NULL) {
        return -1;
    }
    int closed = PyObject_IsTrue(res);
    Py_DECREF(res);
    return closed;
}

/* Is raw (which must be set) closed?  Like buffered_raw_closed(). */
static int
buffered_is_closed(buffered *self)
{
    return buffered_raw_closed(self->raw, self->raw_fileio);
}

/* Like buffered_is_closed(), without the lock: raw is a reference taken
   with buffered_ref_raw(), and raw_fileio may already describe another
   raw stream (__init__() again), so its type is looked at. */
static int
buffered_ref_closed(PyObject *raw)
{
    return buffered_raw_closed(raw, _PyFileIO_CheckExact(raw));
}

/* Raise ValueError(closed_msg) if closed.  Then writes can't go on
   without the lock either. */
static int
buffered_check_closed(buffered *self, const char *closed_msg)
{
    int closed = buffered_is_closed(self);
    if (closed > 0) {
        nibbler_stop_appending(&self->nib);
        PyErr_SetString(PyExc_ValueError, closed_msg);
    }
    return closed == 0 ? 0 : -1;
}

static void
buffered_set_blocking_error(Py_ssize_t written)
{
    PyErr_Clear();
    PyObject *err = PyObject_CallFunction(
        PyExc_BlockingIOError, "isn", errno,
        "write could not complete without blocking", written);
    if (err != NULL) {
        PyErr_SetObject(PyExc_BlockingIOError, err);
        Py_DECREF(err);
    }
}

/*
 * Raw stream calls
 */

/* What raw calls (also FileIO's C functions) and the functions here return
   when the raw stream would block: one code for all of them. */
#define WOULD_BLOCK (-2)

/* With unlocked, release the lock around a raw call; take it again with
   buffered_relock_after_raw(). */
static inline void
buffered_unlock_for_raw(buffered *self, int unlocked)
{
    if (unlocked) {
        buffered_unlock(self);
    }
}

/* Undo buffered_unlock_for_raw(), keeping errno and the raised exception
   of the raw call.  A signal does not interrupt this (its handler runs
   later). */
static inline void
buffered_relock_after_raw(buffered *self, int unlocked)
{
    if (unlocked) {
        int errnum = errno;
        PyThreadState *tstate = _PyThreadState_GET();
        if (tstate->current_exception == NULL) {
            nibbler_relock(&self->nib, (PyObject *)self);
        }
        else {
            PyObject *exc = _PyErr_GetRaisedException(tstate);
            nibbler_relock(&self->nib, (PyObject *)self);
            _PyErr_SetRaisedException(tstate, exc);
        }
        errno = errnum;
    }
}

/* A raw read or write moved the raw position by n >= 0 bytes: advance it
   (an unknown one stays unknown, see raw_regular). */
static inline void
buffered_raw_moved(buffered *self, Py_ssize_t n)
{
    self->nib.raw_pos += n;
}

/* Keep pos, the raw position from raw.seek() or raw.tell() (-1 on error),
   if raw_regular. */
static inline void
buffered_raw_set(buffered *self, Py_off_t pos)
{
    self->nib.raw_pos = (self->raw_regular && pos >= 0
                         ? pos : NIBBLER_POS_UNKNOWN);
}

/* Convert the result of a raw readinto(), write() or _writev() of up to len
   bytes: the count, WOULD_BLOCK for None, or -1 on error. */
static Py_ssize_t
buffered_raw_result(PyObject *res, Py_ssize_t len, const char *method)
{
    if (res == NULL) {
        return -1;
    }
    if (res == Py_None) {
        Py_DECREF(res);
        return WOULD_BLOCK;
    }
    Py_ssize_t n = PyNumber_AsSsize_t(res, PyExc_ValueError);
    Py_DECREF(res);
    if (n == -1 && PyErr_Occurred()) {
        _PyErr_FormatFromCause(PyExc_OSError, "raw %s() failed", method);
        return -1;
    }
    if (n < 0 || n > len) {
        PyErr_Format(PyExc_OSError,
                     "raw %s() returned invalid length %zd "
                     "(should have been between 0 and %zd)", method, n, len);
        return -1;
    }
    return n;
}

/* Python code had view (see buffered_memory_view()): release it, so that
   keeping it gives no access to the memory any more (gh-60198, gh-157075).
   Returns 1 if the memory can still be reached anyway, through a view made
   from it or a buffer it exported: then memory of ours must neither be
   reused nor handed out without a copy.  Keeps the raised exception.
   Steals view. */
static int
buffered_release_view(PyObject *view)
{
    PyMemoryViewObject *mv = (PyMemoryViewObject *)view;
    int shared = mv->exports > 0 || mv->mbuf->exports > 1;
    PyObject *exc = PyErr_GetRaisedException();
    PyObject *r = PyObject_CallMethodNoArgs(view, &_Py_ID(release));
    if (r == NULL) {
        PyErr_Clear();
        shared = 1;
    }
    Py_XDECREF(r);
    PyErr_SetRaisedException(exc);
    Py_DECREF(view);
    return shared;
}

/* A memoryview of mem[0:len] for Python code (writable with PyBUF_WRITE),
   inside memobj: a bytes object of ours, the object whose buffer the
   caller passed, or the object holding the data of the current write()
   (bytes, str, or an exporter).  The view holds memobj, and an export of
   it when it has a buffer that can change, so that a view made from it
   keeps that memory valid like any other (also after the call, when the
   raw stream kept one).  Without memobj, the memory must stay valid
   otherwise.

   When memobj exports no buffer, or one that doesn't hold mem (as the
   wrapper of a class with __buffer__, PEP 688, or an exporter returning
   other memory each time), the view can't be bound to it: then a
   read-only view is of a copy, and NULL is returned with no exception set
   for a writable one (see buffered_raw_read()). */
static PyObject *
buffered_memory_view(char *mem, Py_ssize_t len, int flags, PyObject *memobj)
{
    if (memobj == NULL) {
        return PyMemoryView_FromMemory(mem, len, flags);
    }
    if (PyBytes_CheckExact(memobj) || PyUnicode_CheckExact(memobj)) {
        PyObject *view = PyMemoryView_FromMemory(mem, len, flags);
        if (view != NULL) {
            /* Immutable: released with the managed buffer, without
               bf_releasebuffer.  A read-only view shows it as its obj,
               as one made from it would; a writable one (into a block of
               ours) doesn't, so that Python code can't keep the block. */
            PyMemoryViewObject *mv = (PyMemoryViewObject *)view;
            mv->mbuf->master.obj = Py_NewRef(memobj);
            if (flags == PyBUF_READ) {
                mv->view.obj = memobj;
            }
        }
        return view;
    }
    /* The view keeps its own shape; the managed buffer releases the export
       when the last view made from it goes. */
    Py_buffer whole;
    if (PyObject_GetBuffer(memobj, &whole, (flags == PyBUF_WRITE
                                            ? PyBUF_WRITABLE
                                            : PyBUF_SIMPLE)) < 0)
    {
        if (!PyErr_ExceptionMatches(PyExc_TypeError)
            && !PyErr_ExceptionMatches(PyExc_BufferError))
        {
            return NULL;
        }
        PyErr_Clear();
        whole.obj = NULL;
    }
    else if (mem < (char *)whole.buf
             || mem + len > (char *)whole.buf + whole.len)
    {
        /* Not the memory the caller passed after all. */
        PyBuffer_Release(&whole);
    }
    if (whole.obj == NULL) {
        if (flags == PyBUF_WRITE) {
            return NULL;
        }
        PyObject *copy = PyBytes_FromStringAndSize(mem, len);
        if (copy == NULL) {
            return NULL;
        }
        PyObject *view = buffered_memory_view(PyBytes_AS_STRING(copy), len,
                                              flags, copy);
        Py_DECREF(copy);
        return view;
    }
    PyObject *view = PyMemoryView_FromMemory(mem, len, flags);
    if (view == NULL) {
        PyBuffer_Release(&whole);
        return NULL;
    }
    PyMemoryViewObject *mv = (PyMemoryViewObject *)view;
    mv->mbuf->master = whole;
    mv->view.obj = memobj;
    return view;
}

/* One raw readinto() of up to len bytes at dst, inside memobj (see
   buffered_memory_view()).  Returns the count (0 at EOF), WOULD_BLOCK if
   the raw stream would block, or -1 on error.  Sets *shared if Python code
   can still reach the memory (see buffered_release_view()). */
static Py_ssize_t
buffered_raw_read(buffered *self, char *dst, Py_ssize_t len, PyObject *memobj,
                  int *shared)
{
    if (self->stash.nbytes > 0) {
        /* Data the raw stream returned already. */
        return buffered_take_stash(self, dst, len);
    }
    if (self->raw_fileio) {
        Py_ssize_t n = _PyFileIO_readinto(self->raw, dst, len);
        if (n > 0) {
            buffered_raw_moved(self, n);
        }
        return n;
    }
    /* (Other raw streams have no known position to advance.) */
    assert(memobj != NULL);
    PyObject *view = buffered_memory_view(dst, len, PyBUF_WRITE, memobj);
    if (view == NULL) {
        if (PyErr_Occurred()) {
            return -1;
        }
        /* memobj can't hold a view of dst: read into a bytes object of our
           own, which the view keeps alive, and copy. */
        PyObject *tmp = PyBytes_FromStringAndSize(NULL, len);
        if (tmp == NULL) {
            return -1;
        }
        int tmp_shared = 0;
        Py_ssize_t n = buffered_raw_read(self, PyBytes_AS_STRING(tmp), len,
                                         tmp, &tmp_shared);
        if (n > 0) {
            memcpy(dst, PyBytes_AS_STRING(tmp), n);
        }
        Py_DECREF(tmp);
        return n;
    }
    /* PyErr_SetFromErrno() runs signal handlers on EINTR; retry if none
       raised (see issue #10956). */
    PyObject *res;
    do {
        res = PyObject_CallMethodOneArg(self->raw, &_Py_ID(readinto), view);
    } while (res == NULL && _PyIO_trap_eintr());
    if (buffered_release_view(view)) {
        *shared = 1;
    }
    return buffered_raw_result(res, len, "readinto");
}

/* A read-only memoryview of the morsel, which keeps its bytes alive.  Its
   obj may also be the object holding the data of the current write() call
   (see buffered_memory_view()), or NULL for memory only valid during the
   call. */
static inline PyObject *
buffered_view(const morsel *m)
{
    return buffered_memory_view((char *)m->ptr, m->len, PyBUF_READ, m->obj);
}

/* A raw write of len > 0 bytes that wrote none: raise, since retrying it
   could loop forever (gh-158414).  Returns n, or -1. */
static inline Py_ssize_t
buffered_check_progress(Py_ssize_t n, Py_ssize_t len, const char *method)
{
    if (n == 0 && len > 0) {
        PyErr_Format(PyExc_OSError, "raw %s() made no progress", method);
        return -1;
    }
    return n;
}

/* One raw write, without the lock, of spans[0:cnt] (total bytes), which
   are inside objs[0:cnt] (bytes of the morsels, or the object holding the
   data of the current write() call, see buffered_view()): one vectored
   write to an exact FileIO; else write() of one span, or _writev() of
   memoryviews of them when the raw stream has it.
   Returns the count, WOULD_BLOCK if the raw stream would block (errno set
   for the BlockingIOError), or -1 on error. */
Py_NO_INLINE static Py_ssize_t
buffered_raw_writev_py(buffered *self, const _PyIO_Span *spans,
                       PyObject *const *objs, Py_ssize_t cnt,
                       Py_ssize_t total)
{
    PyObject *arg = NULL;
    if (cnt == 1) {
        arg = buffered_view(&(morsel){objs[0], spans[0].ptr, spans[0].len});
    }
    else if ((arg = PyList_New(cnt)) != NULL) {
        for (Py_ssize_t i = 0; i < cnt; i++) {
            PyObject *view = buffered_view(
                &(morsel){objs[i], spans[i].ptr, spans[i].len});
            if (view == NULL) {
                Py_CLEAR(arg);
                break;
            }
            PyList_SET_ITEM(arg, i, view);
        }
    }
    if (arg == NULL) {
        return -1;
    }
    const char *method = cnt == 1 ? "write" : "_writev";
    PyObject *name = cnt == 1 ? &_Py_ID(write) : &_Py_ID(_writev);
    PyObject *res;
    int errnum;
    do {
        errno = 0;
        res = PyObject_CallMethodOneArg(self->raw, name, arg);
        errnum = errno;
    } while (res == NULL && _PyIO_trap_eintr());
    /* Views of the data of the current write() call are released, so that
       the raw stream can't use them after the call (views it made from
       them keep the data valid, through its object).  The others keep
       their bytes alive. */
    if (cnt == 1) {
        if (objs[0] == NULL || !PyBytes_CheckExact(objs[0])) {
            (void)buffered_release_view(arg);
        }
        else {
            Py_DECREF(arg);
        }
    }
    else {
        for (Py_ssize_t i = 0; i < cnt; i++) {
            if (objs[i] == NULL || !PyBytes_CheckExact(objs[i])) {
                (void)buffered_release_view(
                    Py_NewRef(PyList_GET_ITEM(arg, i)));
            }
        }
        Py_DECREF(arg);
    }
    Py_ssize_t n = buffered_check_progress(
        buffered_raw_result(res, total, method), total, method);
    /* Decrefs may have changed errno, which the BlockingIOError reports. */
    errno = errnum;
    return n;
}

static inline Py_ssize_t
buffered_raw_writev(buffered *self, const _PyIO_Span *spans,
                    PyObject *const *objs, Py_ssize_t cnt, Py_ssize_t total)
{
    if (self->raw_fileio) {
        return _PyFileIO_writev(self->raw, spans, cnt);
    }
    /* Out of line, so that the FileIO path stays small. */
    return buffered_raw_writev_py(self, spans, objs, cnt, total);
}

static Py_off_t
buffered_raw_offset(PyObject *res)
{
    if (res == NULL) {
        return -1;
    }
    Py_off_t n = PyNumber_AsOff_t(res, PyExc_ValueError);
    Py_DECREF(res);
    if (n < 0) {
        if (!PyErr_Occurred()) {
            PyErr_Format(PyExc_OSError,
                         "Raw stream returned invalid position %" PY_PRIdOFF,
                         (PY_OFF_T_COMPAT)n);
        }
        return -1;
    }
    return n;
}

/* The raw position, from raw.tell(); kept if raw_regular. */
static Py_off_t
buffered_raw_tell(buffered *self)
{
    Py_off_t pos = buffered_raw_offset(
        PyObject_CallMethodNoArgs(self->raw, &_Py_ID(tell)));
    buffered_raw_set(self, pos);
    return pos;
}

/* The raw position: the one kept, else raw.tell(). */
static inline Py_off_t
buffered_raw_pos(buffered *self)
{
    Py_off_t pos = self->nib.raw_pos;
    return pos >= 0 ? pos : buffered_raw_tell(self);
}

static Py_off_t
buffered_raw_seek(buffered *self, Py_off_t target, int whence)
{
    PyObject *posobj = PyLong_FromOff_t(target);
    if (posobj == NULL) {
        return -1;
    }
    PyObject *whenceobj = PyLong_FromLong(whence);
    if (whenceobj == NULL) {
        Py_DECREF(posobj);
        return -1;
    }
    PyObject *res = PyObject_CallMethodObjArgs(self->raw, &_Py_ID(seek),
                                               posobj, whenceobj, NULL);
    Py_DECREF(posobj);
    Py_DECREF(whenceobj);
    Py_off_t pos = buffered_raw_offset(res);
    buffered_raw_set(self, pos);
    return pos;
}

/* The logical position: the raw one adjusted for what is buffered, and
   for `gathered` bytes still to come (see "Gathering"). */
static PyObject *
buffered_position(buffered *self, Py_ssize_t gathered)
{
    /* With nothing buffered, ask the raw stream, as _io does: code sharing
       the file descriptor may have moved it. */
    Py_off_t pos = (nibbler_nbytes(&self->nib) == 0
                    && nibbler_unread(&self->nib) == 0
                    && self->stash.nbytes == 0
                    ? buffered_raw_tell(self) : buffered_raw_pos(self));
    if (pos == -1) {
        return NULL;
    }
    /* Gathered writes hand back read-ahead first; stashed data (only
       while reading) was read from the raw stream too. */
    pos += (nibbler_nbytes(&self->nib) - nibbler_unread(&self->nib)
            - self->stash.nbytes + gathered);
    // GH-95782
    return PyLong_FromOff_t(pos < 0 ? 0 : pos);
}

/*
 * Writing
 */

/* Add data[0:len], inside obj, to the pending writes, which must have
   room for it. */
static int
buffered_add_write(buffered *self, PyObject *obj, const char *data,
                   Py_ssize_t len)
{
    assert(nibbler_reading(&self->nib) == NULL);
    assert(nibbler_nbytes(&self->nib) + len <= self->nib.threshold);
    return nibbler_append(&self->nib, obj, data, len, self->ref_min);
}

/* How a write out stopped: everything written, an error, or the raw
   stream would block (WOULD_BLOCK). */
enum {
    WRITE_DONE = 0,
    WRITE_ERROR = -1,
};

/* Write spans[0:cnt] (total bytes, inside objs, see buffered_raw_writev())
   to the raw stream, with unlocked without the lock, retrying partial
   writes (advancing spans) until all of them are written, the raw stream
   would block or an error is raised: returns WRITE_DONE, WOULD_BLOCK or
   WRITE_ERROR, with the count in *written.  The lock is held again on
   return.  This is the one way data goes to the raw stream. */
static Py_ALWAYS_INLINE int
buffered_write_spans(buffered *self, _PyIO_Span *spans, PyObject **objs,
                     Py_ssize_t cnt, Py_ssize_t total, int unlocked,
                     Py_ssize_t *written)
{
    assert(total > 0);
    buffered_unlock_for_raw(self, unlocked);
    Py_ssize_t done = 0;
    int st = WRITE_DONE;
    for (;;) {
        Py_ssize_t r = buffered_raw_writev(self, spans, objs, cnt,
                                           total - done);
        if (r <= 0) {
            /* A raw write that wrote nothing raises, since retrying it
               could loop forever (gh-158414). */
            if (r == 0) {
                (void)buffered_check_progress(r, total - done, "write");
            }
            st = r == WOULD_BLOCK ? WOULD_BLOCK : WRITE_ERROR;
            break;
        }
        done += r;
        if (done == total) {
            break;
        }
        for (; r >= spans->len; spans++, objs++, cnt--) {
            r -= spans->len;
        }
        spans->ptr += r;
        spans->len -= r;
        /* Partial writes can return successfully when interrupted by a
           signal (see write(2)).  Run signal handlers before blocking
           another time, possibly indefinitely.  With unlocked, without
           the lock: a handler writing to this object (print()) then
           queues its data (gh-118143) instead of failing as a reentrant
           call. */
        if (PyErr_CheckSignals() < 0) {
            st = WRITE_ERROR;
            break;
        }
    }
    if (st == WRITE_DONE && unlocked) {
        nibbler_relock(&self->nib, (PyObject *)self);
    }
    else {
        /* Keeping errno and the exception. */
        buffered_relock_after_raw(self, unlocked);
    }
    /* With the lock again: only the holder of the I/O role uses it. */
    buffered_raw_moved(self, done);
    *written = done;
    return st;
}

/* buffered_write_out() with writes pending: in batches of as many pieces
   (morsels, then data) as one raw call takes, each gathered with the lock,
   written, and dropped once written.  Out of line, so that writing data
   with nothing pending stays small. */
Py_NO_INLINE static int
buffered_write_batches(buffered *self, Py_ssize_t target, PyObject *obj,
                       const char *data, Py_ssize_t len, int unlocked,
                       Py_ssize_t *done)
{
    nibbler *n = &self->nib;
    _PyIO_Span stack_spans[_PyIO_WRITEV_MAX];
    PyObject *stack_objs[_PyIO_WRITEV_MAX];
    _PyIO_Span *spans = stack_spans;
    PyObject **objs = stack_objs;
    Py_ssize_t limit = self->raw_vectored ? _PyIO_WRITEV_MAX : 1;
    int st = WRITE_DONE;
    if (_PyIO_WRITEV_LONG > _PyIO_WRITEV_MAX && self->raw_vectored
        && n->list.count >= _PyIO_WRITEV_MAX)
    {
        /* Many morsels: up to IOV_MAX per writev(). */
        limit = _PyIO_WRITEV_LONG;
        spans = PyMem_New(_PyIO_Span, limit);
        objs = PyMem_New(PyObject *, limit);
        if (spans == NULL || objs == NULL) {
            PyErr_NoMemory();
            st = WRITE_ERROR;
            goto end;
        }
    }
    if (!self->raw_fileio) {
        /* Python code may keep the views (and reach the block through
           them): it must not be written to again, also by appends without
           the lock. */
        nibbler_drop_end(n);
        nibbler_set_block(n, NULL);
    }
    while (st == WRITE_DONE && (target > 0 || *done < len)) {
        /* The first morsels, which the raw calls keep alive with
           references of their own (see "Locking" in nibbler.h); while this
           thread writes out, other threads only append, so they stay the
           first ones.  Then data. */
        Py_ssize_t cnt = 0;
        Py_ssize_t total = 0;
        for (; cnt < limit && cnt < n->list.count && total < target; cnt++) {
            morsel *m = &n->list.items[cnt];
            Py_ssize_t k = Py_MIN(m->len, target - total);
            spans[cnt] = (_PyIO_Span){m->ptr, k};
            objs[cnt] = Py_NewRef(m->obj);
            total += k;
        }
        Py_ssize_t held = cnt;
        n->inflight = total;
        if (*done < len && cnt < limit && total == target) {
            spans[cnt] = (_PyIO_Span){data + *done, len - *done};
            objs[cnt++] = obj;
            total += len - *done;
        }
        assert(cnt > 0);
        Py_ssize_t written;
        st = buffered_write_spans(self, spans, objs, cnt, total, unlocked,
                                  &written);
        for (Py_ssize_t i = 0; i < held; i++) {
            Py_DECREF(objs[i]);
        }
        Py_ssize_t k = nibbler_written(n, written);
        target -= k;
        *done += written - k;
    }
end:
    if (spans != stack_spans) {
        PyMem_Free(spans);
        PyMem_Free(objs);
    }
    return st;
}

/* Write the first `target` bytes of the pending writes followed by
   data[0:len] (inside obj, which the caller keeps alive) until all of it is written, the raw stream would block or
   an error is raised; *status says which.  Called with the lock and the
   I/O role.  Written bytes are dropped as they go, so on error the
   unwritten rest is still pending.  With unlocked, the lock is released
   around the raw calls; other threads can then only queue more writes,
   which are left pending.  Returns how much of data was written, also on
   error.  With nothing pending (as when writing without buffering), data
   goes out as one span. */
static Py_ssize_t
buffered_write_out(buffered *self, Py_ssize_t target, PyObject *obj,
                   const char *data, Py_ssize_t len, int *status,
                   int unlocked)
{
    assert(nibbler_io_is_mine(&self->nib));
    Py_ssize_t done = 0;
    int st = WRITE_DONE;
    if (target > 0) {
        st = buffered_write_batches(self, target, obj, data, len, unlocked,
                                    &done);
    }
    else if (len > 0) {
        _PyIO_Span span = {data, len};
        st = buffered_write_spans(self, &span, &obj, 1, len, unlocked,
                                  &done);
    }
    *status = st;
    return done;
}

/* Write out everything pending (with unlocked, what was pending at the
   start); BlockingIOError if the raw stream would block, keeping what is
   unwritten. */
static int
buffered_flush_writes(buffered *self, int unlocked)
{
    int status;
    (void)buffered_write_out(self, nibbler_nbytes(&self->nib), NULL, NULL,
                             0, &status, unlocked);
    if (status == WOULD_BLOCK) {
        buffered_set_blocking_error(0);
    }
    return status == WRITE_DONE ? 0 : -1;
}

/* Hand unread read-ahead back to the raw stream, so the raw position is
   the logical one. */
static int
buffered_rewind(buffered *self)
{
    Py_ssize_t unread = (nibbler_drop_unread(&self->nib)
                         + buffered_drop_stash(self));
    if (unread > 0 && buffered_raw_seek(self, -unread, SEEK_CUR) < 0) {
        return -1;
    }
    return 0;
}

/* Bring the raw stream to the logical position: write out pending writes
   (with unlocked, as buffered_flush_writes() does) or hand back
   read-ahead. */
static int
buffered_sync(buffered *self, int unlocked)
{
    return buffered_writing(self) ? buffered_flush_writes(self, unlocked)
                                  : buffered_rewind(self);
}

/*
 * Reading
 */

static void buffered_push_back(buffered *self, const char *data,
                               Py_ssize_t len);

/* Can a raw read write into the free tail of block, the reading end's,
   after the unread bytes?  Nothing was handed out from there, but Python
   code must not be able to reach the bytes object itself: only a raw
   stream given views of it can (through their obj), and then it has more
   references than ours (the reading end's, and maybe the nibbler's; the
   read-ahead is the end alone, with no morsel). */
static int
buffered_block_private(buffered *self, PyObject *block)
{
    if (self->raw_fileio) {
        return 1;
    }
    Py_ssize_t ours = 1 + (self->nib.block == block);
    return Py_REFCNT(block) <= ours;
}

/* buffered_fill() into the free tail of the reading end's block. */
static Py_ssize_t
buffered_fill_tail(buffered *self, Py_ssize_t room)
{
    nibbler_end *e = nibbler_reading(&self->nib);
    /* The read holds its own reference while it uses the block (see
       "Locking" in nibbler.h). */
    PyObject *block = Py_NewRef(e->block);
    char *start = (char *)nibbler_unread_ptr(&self->nib);
    Py_ssize_t unread = nibbler_unread(&self->nib);
    int shared = 0;
    Py_ssize_t n = buffered_raw_read(self, start + unread, room, block,
                                     &shared);
    if (n > 0 && !shared) {
        nibbler_extend(&self->nib, n);
    }
    else if (shared) {
        /* Python code can still write to the block: abandon it to that
           code, and keep a copy of what is unread.  An error of the raw
           read is the context of one raised here. */
        PyObject *exc = n == -1 ? PyErr_GetRaisedException() : NULL;
        if (block == self->nib.block) {
            nibbler_set_block(&self->nib, NULL);
        }
        PyObject *copy = PyBytes_FromStringAndSize(start,
                                                   unread + Py_MAX(n, 0));
        if (copy == NULL || nibbler_publish(&self->nib, copy,
                                            PyBytes_GET_SIZE(copy)) < 0)
        {
            n = -1;
        }
        Py_XDECREF(copy);
        _PyErr_ChainExceptions1(exc);
    }
    Py_DECREF(block);
    return n;
}

/* One raw read into the read-ahead, after the bytes still unread, which
   stay in front (TextIOWrapper leaves a partial character there, and
   readline() a partial line); unbuffered, into a new block of `size`
   bytes, so that no more are read.  Unread bytes are read after where
   they are when their block has room (at least half a block), else moved
   to the start of a fresh block, or of one twice their size when they
   take more than half a block: so a line of any length is copied a
   bounded number of times however it trickles in.  Returns the count (0
   at EOF), WOULD_BLOCK if the raw stream would block, or -1 on error. */
static Py_ssize_t
buffered_fill(buffered *self, Py_ssize_t size)
{
    nibbler *n = &self->nib;
    Py_ssize_t capacity = n->capacity;
    Py_ssize_t unread = nibbler_unread(n);
    if (unread > 0 && capacity > 0) {
        nibbler_end *e = nibbler_reading(n);
        Py_ssize_t room = PyBytes_GET_SIZE(e->block) - e->limit;
        if (room > 0 && room >= capacity / 2
            && buffered_block_private(self, e->block))
        {
            return buffered_fill_tail(self, room);
        }
    }
    /* A few bytes are copied aside, so that the block can be reused. */
    char aside[512];
    morsel keep = {NULL, NULL, 0};
    if (unread > 0) {
        keep = (morsel){n->end->block, nibbler_unread_ptr(n), unread};
        if (keep.len <= (Py_ssize_t)sizeof(aside)) {
            memcpy(aside, keep.ptr, keep.len);
            keep = (morsel){NULL, aside, keep.len};
        }
        else {
            Py_INCREF(keep.obj);
        }
    }
    (void)nibbler_drop_unread(n);
    /* The read holds its own reference while it uses the block (see
       "Locking" in nibbler.h). */
    PyObject *block = (capacity == 0
                       ? PyBytes_FromStringAndSize(NULL, size)
                       : keep.len > capacity / 2
                       ? PyBytes_FromStringAndSize(NULL, 2 * keep.len)
                       : Py_XNewRef(nibbler_fresh_block(n)));
    Py_ssize_t r = -1;
    if (block != NULL) {
        char *dst = PyBytes_AS_STRING(block);
        if (keep.len > 0) {
            memcpy(dst, keep.ptr, keep.len);
        }
        int shared = 0;
        r = buffered_raw_read(self, dst + keep.len,
                              PyBytes_GET_SIZE(block) - keep.len, block,
                              &shared);
        Py_ssize_t filled = keep.len + Py_MAX(r, 0);
        /* An error of the raw read is the context of one raised below. */
        PyObject *exc = r == -1 ? PyErr_GetRaisedException() : NULL;
        if (shared) {
            /* Python code can still write to the block: abandon it to that
               code, and keep a copy of what was read. */
            if (block == n->block) {
                nibbler_set_block(n, NULL);
            }
            PyObject *copy = PyBytes_FromStringAndSize(dst, filled);
            Py_SETREF(block, copy);
            if (block == NULL) {
                r = -1;
                filled = 0;
            }
        }
        if (filled > 0 && nibbler_publish(n, block, filled) < 0) {
            r = -1;
        }
        Py_XDECREF(block);
        _PyErr_ChainExceptions1(exc);
    }
    else if (keep.len > 0) {
        /* Keep the unread bytes. */
        PyObject *exc = PyErr_GetRaisedException();
        buffered_push_back(self, keep.ptr, keep.len);
        _PyErr_ChainExceptions1(exc);
    }
    Py_XDECREF(keep.obj);
    return r;
}

/* After a raw read raised: data[0:len], taken from the read-ahead or read
   for the failed call, ends at the raw position, so make it the read-ahead
   again for the next read to return (gh-51571).  The raised exception is
   kept. */
static void
buffered_push_back(buffered *self, const char *data, Py_ssize_t len)
{
    if (len == 0) {
        return;
    }
    PyObject *exc = PyErr_GetRaisedException();
    PyObject *block = PyBytes_FromStringAndSize(data, len);
    if (block == NULL || nibbler_publish(&self->nib, block, len) < 0) {
        _PyErr_ChainExceptions1(exc);
    }
    else {
        PyErr_SetRaisedException(exc);
    }
    Py_XDECREF(block);
}

/* Read up to len bytes into dst: read-ahead first, then from the raw
   stream until len bytes, EOF, or the raw stream would block.  A request
   of at least a buffer's worth is read directly into dst, smaller ones
   through the read-ahead.  read1 makes at most one raw read, and none into
   the read-ahead once there is data to return.  Returns the count,
   WOULD_BLOCK if the raw stream would block before anything was read, or
   -1 on error. */
static Py_ssize_t
buffered_read_into(buffered *self, char *dst, Py_ssize_t len, int read1,
                   PyObject *memobj, int *shared)
{
    Py_ssize_t written = 0;
    for (int reads = 0; ; reads++) {
        written += nibbler_take_into(&self->nib, dst + written,
                                     len - written);
        Py_ssize_t remaining = len - written;
        if (remaining == 0 || (read1 && reads > 0)) {
            break;
        }
        Py_ssize_t n;
        if (remaining >= self->nib.capacity) {
            /* Bypasses the read-ahead, which no longer precedes the raw
               position. */
            (void)nibbler_drop_unread(&self->nib);
            n = buffered_raw_read(self, dst + written, remaining, memobj,
                                  shared);
            written += Py_MAX(n, 0);
        }
        else if (read1 && written > 0) {
            break;
        }
        else {
            /* Copied out on the next pass. */
            n = buffered_fill(self, remaining);
        }
        if (n == 0 || (n == WOULD_BLOCK && written > 0)) {
            break;
        }
        if (n == -1) {
            buffered_push_back(self, dst, written);
        }
        if (n < 0) {
            return n;
        }
    }
    return written;
}

/* buffered_read_bytes() over a raw stream other than FileIO: its readinto()
   gets views of the result, which they keep alive. */
Py_NO_INLINE static PyObject *
buffered_read_bytes_views(buffered *self, Py_ssize_t n, int read1)
{
    PyObject *res = PyBytes_FromStringAndSize(NULL, n);
    if (res == NULL) {
        return NULL;
    }
    int shared = 0;
    Py_ssize_t r = buffered_read_into(self, PyBytes_AS_STRING(res), n, read1,
                                      res, &shared);
    if (r < 0) {
        Py_DECREF(res);
        return r == WOULD_BLOCK ? Py_NewRef(Py_None) : NULL;
    }
    if (shared) {
        /* Python code can still write to res: return a copy. */
        Py_SETREF(res, PyBytes_FromStringAndSize(PyBytes_AS_STRING(res), r));
    }
    else if (r < n) {
        (void)_PyBytes_Resize(&res, r);
    }
    return res;
}

/* read(n) and read1(n). */
static PyObject *
buffered_read_bytes(buffered *self, Py_ssize_t n, int read1)
{
    Py_ssize_t avail = nibbler_unread(&self->nib);
    if (read1 && avail == 0 && n > 0 && n < self->nib.capacity) {
        /* One raw read into the read-ahead: then all of it may be handed
           out without a copy. */
        Py_ssize_t r = buffered_fill(self, n);
        if (r <= 0) {
            /* EOF, or None if it would block. */
            return (r == 0 ? Py_GetConstant(Py_CONSTANT_EMPTY_BYTES)
                    : r == WOULD_BLOCK ? Py_NewRef(Py_None) : NULL);
        }
        avail = nibbler_unread(&self->nib);
    }
    if (avail > 0 && (read1 || avail >= n)) {
        /* All of it, or for read1(), what there is. */
        return nibbler_take_bytes(&self->nib, n);
    }
    if (n == 0) {
        return Py_GetConstant(Py_CONSTANT_EMPTY_BYTES);
    }
    if (!self->raw_fileio) {
        return buffered_read_bytes_views(self, n, read1);
    }
    PyBytesWriter *writer = PyBytesWriter_Create(n);
    if (writer == NULL) {
        return NULL;
    }
    Py_ssize_t r = buffered_read_into(self, PyBytesWriter_GetData(writer), n,
                                      read1, NULL, NULL);
    if (r < 0) {
        PyBytesWriter_Discard(writer);
        return r == WOULD_BLOCK ? Py_NewRef(Py_None) : NULL;
    }
    return PyBytesWriter_FinishWithSize(writer, r);
}

/* Call raw.read(size) (raw.read() without size) until EOF or it would
   block.  Returns the joined data, or the final b"" or None when there was
   none.  If a call raises, what was read is kept as read-ahead. */
static PyObject *
buffered_read_chunks(buffered *self, PyObject *size)
{
    PyObject *chunks = PyList_New(0);
    if (chunks == NULL) {
        return NULL;
    }
    PyObject *data;
    /* A chunk that couldn't be added to chunks. */
    PyObject *last = NULL;
    for (;;) {
        data = (size == NULL
                ? PyObject_CallMethodNoArgs(self->raw, &_Py_ID(read))
                : PyObject_CallMethodOneArg(self->raw, &_Py_ID(read), size));
        if (data == NULL) {
            if (_PyIO_trap_eintr()) {
                continue;
            }
            break;
        }
        if (data != Py_None && !PyBytes_Check(data)) {
            PyErr_SetString(PyExc_TypeError, "read() should return bytes");
            Py_CLEAR(data);
            break;
        }
        if (data == Py_None || PyBytes_GET_SIZE(data) == 0) {
            if (PyList_GET_SIZE(chunks) > 0) {
                Py_SETREF(data, PyBytes_Join(
                    Py_GetConstant(Py_CONSTANT_EMPTY_BYTES), chunks));
            }
            break;
        }
        if (PyList_Append(chunks, data) < 0) {
            last = data;
            data = NULL;
            break;
        }
        Py_DECREF(data);
    }
    if (data == NULL && (PyList_GET_SIZE(chunks) > 0 || last != NULL)) {
        /* A raw read raised (such as a socket timeout), or keeping or
           joining the chunks failed: keep what was read, after the
           read-ahead, for the next read (gh-51571), without copying it. */
        PyObject *exc = PyErr_GetRaisedException();
        int r = 0;
        for (Py_ssize_t i = 0; r == 0 && i < PyList_GET_SIZE(chunks); i++) {
            r = buffered_stash(self, PyList_GET_ITEM(chunks, i));
        }
        if (r < 0 || (last != NULL && buffered_stash(self, last) < 0)) {
            _PyErr_ChainExceptions1(exc);
        }
        else {
            PyErr_SetRaisedException(exc);
        }
    }
    Py_XDECREF(last);
    Py_DECREF(chunks);
    return data;
}

/* Everything from the raw stream to EOF, or until it would block. */
static PyObject *
buffered_raw_read_all(buffered *self)
{
    /* Even reading to EOF may stop anywhere (on an error). */
    self->nib.raw_pos = NIBBLER_POS_UNKNOWN;
    if (self->raw_fileio) {
        return _PyFileIO_readall(self->raw);
    }
    PyObject *readall;
    if (PyObject_GetOptionalAttr(self->raw, &_Py_ID(readall), &readall) < 0) {
        return NULL;
    }
    if (readall == NULL) {
        return buffered_read_chunks(self, NULL);
    }
    /* RawIOBase.readall() loses what it read when a later read raises (as
       a socket timeout can): read the chunks here instead, to keep them. */
    _PyIO_State *state = find_io_state_by_def(Py_TYPE(self));
    if (_PyType_Lookup(Py_TYPE(self->raw), &_Py_ID(readall))
        == _PyType_Lookup(state->PyRawIOBase_Type, &_Py_ID(readall)))
    {
        Py_DECREF(readall);
        /* With a size: read() without one is readall(). */
        PyObject *size = PyLong_FromSsize_t(Py_MAX(self->nib.capacity,
                                                   DEFAULT_BUFFER_SIZE));
        if (size == NULL) {
            return NULL;
        }
        PyObject *res = buffered_read_chunks(self, size);
        Py_DECREF(size);
        return res;
    }
    PyObject *res = PyObject_CallNoArgs(readall);
    Py_DECREF(readall);
    if (res != NULL && res != Py_None && !PyBytes_Check(res)) {
        PyErr_SetString(PyExc_TypeError, "readall() should return bytes");
        Py_CLEAR(res);
    }
    return res;
}

/* The read-ahead, the stashed data and the rest of the raw stream, to EOF
   or until it would block. */
static PyObject *
buffered_read_all(buffered *self)
{
    PyObject *rest = buffered_raw_read_all(self);
    if (rest == NULL) {
        /* The read-ahead, and what was read, are kept for the next read. */
        return NULL;
    }
    Py_ssize_t restlen = rest == Py_None ? 0 : PyBytes_GET_SIZE(rest);
    Py_ssize_t k = nibbler_unread(&self->nib);
    Py_ssize_t st = self->stash.nbytes;
    if (k == 0 && st == 0) {
        (void)nibbler_drop_unread(&self->nib);
        return rest;
    }
    PyObject *res = PyBytes_FromStringAndSize(NULL, k + st + restlen);
    if (res == NULL) {
        /* Lose nothing: what the raw stream returned follows the stashed
           data for the next read. */
        if (restlen > 0) {
            PyObject *exc = PyErr_GetRaisedException();
            if (buffered_stash(self, rest) < 0) {
                _PyErr_ChainExceptions1(exc);
            }
            else {
                PyErr_SetRaisedException(exc);
            }
        }
        Py_DECREF(rest);
        return NULL;
    }
    char *dst = PyBytes_AS_STRING(res);
    (void)nibbler_take_into(&self->nib, dst, k);
    (void)buffered_take_stash(self, dst + k, st);
    if (restlen > 0) {
        memcpy(dst + k + st, PyBytes_AS_STRING(rest), restlen);
    }
    Py_DECREF(rest);
    /* The raw stream moved past the read-ahead. */
    (void)nibbler_drop_unread(&self->nib);
    return res;
}

/* readline(): the line is found in the read-ahead, which keeps all of it
   as more is read (see buffered_fill()), and is only copied out once
   whole.  So a partial line kept when the raw stream would block, or
   raises, is not copied again, and the newline is only looked for in what
   came after the bytes looked at before. */
static PyObject *
buffered_readline(buffered *self, Py_ssize_t limit)
{
    if (limit == 0) {
        return Py_GetConstant(Py_CONSTANT_EMPTY_BYTES);
    }
    nibbler *n = &self->nib;
    /* The unread bytes known to have no end of line (an earlier call may
       have looked at them, see nibbler_noline()). */
    Py_ssize_t scanned = nibbler_noline(n);
    for (;;) {
        Py_ssize_t unread = nibbler_unread(n);
        Py_ssize_t end = limit >= 0 && limit < unread ? limit : unread;
        if (scanned < end) {
            const char *p = nibbler_unread_ptr(n);
            const char *nl = memchr(p + scanned, '\n', end - scanned);
            if (nl != NULL) {
                return nibbler_take_bytes(n, nl - p + 1);
            }
            scanned = end;
        }
        if (limit >= 0 && scanned >= limit) {
            return nibbler_take_bytes(n, limit);
        }
        Py_ssize_t r = buffered_fill(self, 0);
        if (r == -1 || r == WOULD_BLOCK) {
            /* The partial line stays for the next call (gh-51571), which
               looks for the end of the line after what was looked at.
               Would block: return None, unless, with or without a size, it
               is longer than the buffer size (the bound of every
               implementation): then it is returned as it is.  (The block
               grows for a longer line, see buffered_fill(), so that a
               readline() that blocks returns it whole.) */
            if (r == -1 || unread == 0 || unread <= n->capacity) {
                nibbler_set_noline(n, scanned);
                if (r == -1) {
                    return NULL;
                }
                Py_RETURN_NONE;
            }
            return nibbler_take_bytes(n, unread);
        }
        if (r == 0) {
            /* EOF: what there is (b"" for none). */
            return nibbler_take_bytes(n, unread);
        }
    }
}

/*
 * Gathering
 *
 * Inside a _gather() block, the write()s that the context which entered
 * it makes go to a morsel list of the block's own (its record) instead of
 * the pending writes, past the buffer size, and are moved to the pending
 * writes all at once, in one hold of the lock, so that no other data gets
 * between them: when the block ends, or earlier when the record holds
 * `limit` bytes or an operation of that context needs the real position
 * (reads, seek(), truncate()).  close(), detach() and __init__(), from any
 * context, move every record's data first.  flush() inside the block is
 * deferred to its end; tell() counts the gathered bytes.  A block nested
 * in one on the same stream (and context) gathers into that one.
 *
 * A record takes the writes made in the Context it was entered in (by
 * identity: a context copied inside the block, such as an asyncio task's,
 * writes as usual), whatever the order its blocks end in, and wherever
 * they end.  A block that spans a yield gathers the writes of whatever
 * runs in that context meanwhile, as a decimal.localcontext() block does.
 *
 * The stream lists its records (active, or ended but not moved yet, see
 * gather_end()), with the lock held, and counts them (ngather).  Every
 * field of a record but the fixed ones is used with the stream's lock.
 * While there are records, the stream has no writing end and its reading
 * end stays held (see "The open end" in nibbler.h): every write and read
 * takes the lock and looks for the context's record there, and operations
 * outside _gather() blocks pay nothing for it.  A record that is dropped
 * without its block ending (a thread or generator gone inside it) moves its
 * data then, with a ResourceWarning, or drops it when it can't.
 */

typedef struct gather {
    PyObject_HEAD
    /* Fixed: the stream, and the most it gathers before moving it. */
    buffered *stream;
    Py_ssize_t limit;
    /* Fixed once entered: the Context it was entered in. */
    PyObject *ctx;
    /* Set for a block nested in one on the same stream in the same
       context, which gathers into that one (and is not in the list). */
    struct gather *joined;
    /* In the stream's list of records: the next one and the pointer to
       it. */
    struct gather *next;
    struct gather **pprev;
    morsel_list list;
    /* Where small writes are copied: block[used:] is free.  Dropped once
       the data in it was moved to the stream. */
    PyObject *block;
    Py_ssize_t used;
    /* flush() was called inside the block. */
    char flush;
    char state;
} gather;

enum {
    GATHER_NEW,
    /* Gathering, in the stream's list. */
    GATHER_ACTIVE,
    /* Ended, but its data could not be moved: in the list until it is. */
    GATHER_PENDING,
    GATHER_DONE,
};

/* The default limit of _gather(). */
#define GATHER_LIMIT (20 * 1024 * 1024)
#define GATHER_BLOCK_MIN 1024
#define GATHER_BLOCK_MAX (64 * 1024)

/* Add g to the stream's records (with the lock held). */
static void
gather_link(buffered *self, gather *g)
{
    if (self->gather_last == NULL) {
        self->gather_last = &self->gather_first;
    }
    g->next = NULL;
    g->pprev = self->gather_last;
    *self->gather_last = g;
    self->gather_last = &g->next;
    FT_ATOMIC_STORE_INT_RELAXED(self->ngather, self->ngather + 1);
    self->nib.hold_reading = 1;
    /* Writes made from now on take the lock. */
    nibbler_stop_appending(&self->nib);
}

/* Remove g from the stream's records (with the lock held). */
static void
gather_unlink(buffered *self, gather *g)
{
    *g->pprev = g->next;
    if (g->next != NULL) {
        g->next->pprev = g->pprev;
    }
    else {
        self->gather_last = g->pprev;
    }
    g->next = NULL;
    g->pprev = NULL;
    FT_ATOMIC_STORE_INT_RELAXED(self->ngather, self->ngather - 1);
    self->nib.hold_reading = self->ngather > 0;
}

/* The active record of the current context on self (borrowed), or NULL
   (with the lock held). */
Py_NO_INLINE static gather *
gather_find(buffered *self)
{
    PyObject *ctx = _PyThreadState_GET()->context;
    for (gather *g = self->gather_first; g != NULL; g = g->next) {
        if (g->state == GATHER_ACTIVE && g->ctx == ctx) {
            return g;
        }
    }
    return NULL;
}

/* Move what g gathered to the pending writes, which follow what was read
   (with the lock and no read-ahead).  On error, g keeps it. */
static int
gather_splice(buffered *self, gather *g)
{
    if (g->list.nbytes == 0) {
        return 0;
    }
    assert(!buffered_reading(self));
    if (morsels_splice(&self->nib.list, &g->list) < 0) {
        return -1;
    }
    /* Shared from now on: never written to again. */
    Py_CLEAR(g->block);
    g->used = 0;
    return 0;
}

/* With the lock held, for an operation that needs the real position: move
   what the current context's record gathered, and what ended records
   could not move, to the pending writes.  With all, every record's (for
   close(), detach() and __init__(), which also do any deferred flush).
   Out of line, so that buffered_enter_locked() stays small. */
Py_NO_INLINE static int
gather_splice_records(buffered *self, int all)
{
    PyObject *ctx = _PyThreadState_GET()->context;
    gather *g = self->gather_first;
    while (g != NULL) {
        gather *next = g->next;
        if (all || g->state == GATHER_PENDING || g->ctx == ctx) {
            if (g->list.nbytes > 0 && buffered_reading(self)
                && buffered_rewind(self) < 0)
            {
                return -1;
            }
            if (gather_splice(self, g) < 0) {
                return -1;
            }
            if (all) {
                g->flush = 0;
            }
            if (g->state == GATHER_PENDING) {
                g->state = GATHER_DONE;
                gather_unlink(self, g);
            }
        }
        g = next;
    }
    return 0;
}

/* Add data[0:len], inside obj (or NULL), to what g gathered, with the
   lock and no read-ahead: by reference where the pending writes would keep
   it so (see nibbler_append()), else copied into g's block.  Once g holds
   `limit` bytes, they are moved to the pending writes (only: what can't be
   written out yet stays pending past the threshold, for the next write,
   flush or the end of the block). */
Py_NO_INLINE static int
gather_add(gather *g, PyObject *obj, const char *data, Py_ssize_t len)
{
    buffered *self = g->stream;
    if (len == 0) {
        return 0;
    }
    if ((len >= self->ref_min || len > self->nib.capacity)
        && len >= NIBBLER_REF_MIN && obj != NULL && PyBytes_CheckExact(obj))
    {
        if (morsels_push(&g->list, obj, data, len) < 0) {
            return -1;
        }
    }
    else {
        if (g->block == NULL || PyBytes_GET_SIZE(g->block) - g->used < len) {
            /* Blocks grow with what was gathered, or fit the data. */
            Py_ssize_t size = Py_MIN(GATHER_BLOCK_MAX,
                                     Py_MAX(GATHER_BLOCK_MIN,
                                            g->list.nbytes));
            Py_XSETREF(g->block,
                      PyBytes_FromStringAndSize(NULL, Py_MAX(size, len)));
            g->used = 0;
            if (g->block == NULL) {
                return -1;
            }
        }
        char *dst = PyBytes_AS_STRING(g->block) + g->used;
        memcpy(dst, data, len);
        if (morsels_push(&g->list, g->block, dst, len) < 0) {
            return -1;
        }
        g->used += len;
    }
    if (g->list.nbytes >= g->limit && gather_splice(self, g) < 0) {
        /* Kept: tried again at the next write, or the end of the block. */
        PyErr_Clear();
    }
    return 0;
}

/*
 * Entering methods
 */

enum {
    /* Like KEEP_DIRECTION, but leaves gathered writes alone. */
    LEAVE_GATHERED = -2,
    KEEP_DIRECTION = -1,
    READING = 0,
    WRITING = 1,
};

/* The rest of buffered_enter(), with the lock held.  Kept out of line so
   that buffered_enter() stays small enough to be inlined: small writes go
   lock-free, but writes under the lock still pay for a call otherwise
   (a 600-byte bytearray write() took 1656 instead of 1626 instructions
   in a GIL -O3 build; without this and the quick check for writes below,
   1289 instead of 1245 in a PGO+LTO build). */
Py_NO_INLINE static int
buffered_enter_locked(buffered *self, const char *closed_msg, int direction)
{
    if (!buffered_raw_usable(self->raw)) {
        buffered_not_ready();
        goto error;
    }
    /* Reading what is already buffered works after close(). */
    int check_closed = (closed_msg != NULL
                        && (direction == WRITING
                            || nibbler_unread(&self->nib) == 0));
    if (check_closed && buffered_check_closed(self, closed_msg) < 0) {
        goto error;
    }
    /* What the context gathered goes first, unless the stream is closed:
       then it stays gathered (and the end of the block raises). */
    if (self->ngather > 0 && direction != WRITING
        && direction != LEAVE_GATHERED)
    {
        int closed = check_closed ? 0 : buffered_is_closed(self);
        if (closed < 0
            || (closed == 0 && gather_splice_records(self, 0) < 0))
        {
            goto error;
        }
    }
    /* Switch direction: hand back read-ahead before writing, write out
       pending writes before reading. */
    if (direction == WRITING && buffered_reading(self)
        && buffered_rewind(self) < 0)
    {
        goto error;
    }
    if (direction == READING && buffered_writing(self)
        && buffered_flush_writes(self, 0) < 0)
    {
        goto error;
    }
    return 0;

error:
    if (direction == WRITING) {
        buffered_unlock(self);
    }
    else {
        buffered_leave(self);
    }
    return -1;
}

/* Common start of the I/O methods but write(): take the I/O role and the
   lock (see "Locking" in nibbler.h; the caller releases them with
   buffered_leave()), check the object is initialized and open (unless
   closed_msg is NULL), and make it buffer in the given direction (unless
   KEEP_DIRECTION).  Closed is checked with the lock held since another
   thread could be holding it while closing the file (issue #31976);
   leftover read-ahead can still be used.  Reading from the read-ahead
   needs only a quick check. */
static inline int
buffered_enter(buffered *self, const char *closed_msg, int direction)
{
    assert(direction != WRITING);
    if (nibbler_lock_io(&self->nib, (PyObject *)self) < 0) {
        return -1;
    }
    if (direction == READING && nibbler_unread(&self->nib) > 0
        && buffered_raw_usable(self->raw)
        && FT_ATOMIC_LOAD_INT_RELAXED(self->ngather) == 0)
    {
        return 0;
    }
    return buffered_enter_locked(self, closed_msg, direction);
}

/* Start of write(), which appends: take the lock alone (the caller
   releases it with buffered_unlock()), and check as buffered_enter() does.
   Writing to an open FileIO without read-ahead to hand back needs only
   quick checks (without them, a 600-byte bytearray write() took 1661
   instead of 1626 instructions in a GIL -O3 build). */
static inline int
buffered_enter_append(buffered *self)
{
    if (buffered_lock(self) < 0) {
        return -1;
    }
    if (self->raw_fileio && nibbler_reading(&self->nib) == NULL
        && self->stash.nbytes == 0 && buffered_raw_usable(self->raw)
        && !_PyFileIO_closed(self->raw))
    {
        return 0;
    }
    return buffered_enter_locked(self, "write to closed file", WRITING);
}

/* Take the I/O role and the lock and check the object is initialized and
   attached.  On success the caller must release them with
   buffered_leave(). */
static int
buffered_lock_ready(buffered *self)
{
    return buffered_enter(self, NULL, KEEP_DIRECTION);
}

/*
 * Gathering: ending a block
 */

/* What gather_end() did with the record's data. */
enum {
    GATHER_MOVED,
    GATHER_DROPPED,
    /* The record is pending (see gather_end()). */
    GATHER_KEPT,
};

/* End g, which is in the stream's list, with the lock held: move what it
   gathered to the pending writes, all at once, and remove it from the
   list.  When the stream is closed or detached, the data is dropped
   (*dropped says how many bytes) and ValueError raised if there was any
   (or flush was deferred).  When it can't be moved (handing back
   read-ahead failed, or no memory), g stays in the list, pending: the
   next operation needing the position, close(), detach(), __init__() or
   its dealloc tries again.  Returns GATHER_MOVED, GATHER_DROPPED or
   GATHER_KEPT, with an exception set unless moved. */
static int
gather_end(buffered *self, gather *g, Py_ssize_t *dropped)
{
    *dropped = 0;
    int closed = (buffered_raw_usable(self->raw) ? buffered_is_closed(self)
                                                 : 1);
    if (closed != 0) {
        *dropped = g->list.nbytes;
        if (closed > 0 && (*dropped > 0 || g->flush)) {
            PyErr_SetString(PyExc_ValueError,
                            *dropped > 0 ? "write to closed file"
                                         : "flush of closed file");
        }
        Py_CLEAR(g->block);
        morsels_clear(&g->list);
        g->state = GATHER_DONE;
        gather_unlink(self, g);
        return GATHER_DROPPED;
    }
    if (g->list.nbytes > 0 && buffered_reading(self)
        && buffered_rewind(self) < 0)
    {
        g->state = GATHER_PENDING;
        return GATHER_KEPT;
    }
    if (gather_splice(self, g) < 0) {
        g->state = GATHER_PENDING;
        return GATHER_KEPT;
    }
    g->state = GATHER_DONE;
    gather_unlink(self, g);
    return GATHER_MOVED;
}

/* The end of a block: gather_end(), then write out as write() does when
   the pending writes don't fit (with flush, all of them, as flush() does).
   Taking the lock is not interrupted, as data written was accepted.
   Returns 0, or -1 on error. */
static int
gather_commit(gather *g)
{
    buffered *self = g->stream;
    if (nibbler_mutex_lock(&self->nib.lock, (PyObject *)self, 0) < 0) {
        /* A reentrant call: the record stays active. */
        return -1;
    }
    nibbler_hold(&self->nib);
    /* (close() may have done the flush meanwhile.) */
    int flush = g->flush;
    Py_ssize_t dropped;
    if (gather_end(self, g, &dropped) != GATHER_MOVED) {
        buffered_unlock(self);
        return PyErr_Occurred() ? -1 : 0;
    }
    int r = 0;
    int have_io = 0;
    while (r == 0) {
        Py_ssize_t pending = nibbler_nbytes(&self->nib);
        if (pending == 0 || (!flush && pending <= self->nib.threshold)) {
            break;
        }
        if (!have_io) {
            int t = nibbler_take_io(&self->nib, (PyObject *)self);
            if (t == NIBBLER_IO_MINE) {
                /* Called from this thread's write out (a signal handler),
                   which writes it. */
                break;
            }
            if (t < 0) {
                return -1;
            }
            have_io = 1;
            if (t == NIBBLER_IO_WAITED) {
                /* Check again, as buffered_enter() does. */
                if (buffered_enter_locked(self, "write to closed file",
                                          WRITING) < 0)
                {
                    nibbler_end_io(&self->nib);
                    return -1;
                }
                continue;
            }
        }
        int status;
        (void)buffered_write_out(self, pending, NULL, NULL, 0, &status, 1);
        if (status == WRITE_ERROR) {
            r = -1;
        }
        else if (status == WOULD_BLOCK && flush) {
            buffered_set_blocking_error(0);
            r = -1;
        }
        /* Otherwise what could not be written stays pending. */
        break;
    }
    if (have_io) {
        nibbler_end_io(&self->nib);
    }
    buffered_unlock(self);
    return r;
}

/*
 * The _gather() context manager
 */

static PyObject *
gather_enter(PyObject *op, PyObject *Py_UNUSED(dummy))
{
    gather *g = (gather *)op;
    buffered *self = g->stream;
    if (g->state != GATHER_NEW) {
        PyErr_SetString(PyExc_RuntimeError,
                        "a _gather() block can only be entered once");
        return NULL;
    }
    PyThreadState *tstate = _PyThreadState_GET();
    if (tstate->context == NULL) {
        /* Make the thread's context, which the record is for. */
        PyObject *copy = PyContext_CopyCurrent();
        if (copy == NULL) {
            return NULL;
        }
        Py_DECREF(copy);
    }
    if (buffered_lock(self) < 0) {
        return NULL;
    }
    int r = -1;
    if (!buffered_raw_usable(self->raw)) {
        buffered_not_ready();
    }
    else if (buffered_check_closed(self, "gather on closed file") == 0) {
        gather *outer = gather_find(self);
        if (outer != NULL) {
            g->joined = (gather *)Py_NewRef(outer);
        }
        else {
            g->ctx = Py_NewRef(tstate->context);
            gather_link(self, g);
        }
        g->state = GATHER_ACTIVE;
        r = 0;
    }
    buffered_unlock(self);
    return r < 0 ? NULL : Py_NewRef(self);
}

static PyObject *
gather_exit(PyObject *op, PyObject *const *Py_UNUSED(args),
            Py_ssize_t Py_UNUSED(nargs))
{
    gather *g = (gather *)op;
    if (g->state != GATHER_ACTIVE) {
        PyErr_SetString(PyExc_RuntimeError, "_gather() block not entered");
        return NULL;
    }
    if (g->joined != NULL) {
        g->state = GATHER_DONE;
        Py_CLEAR(g->joined);
        Py_RETURN_FALSE;
    }
    /* What was gathered is written out also when the block raised, as
       buffered data would be. */
    if (gather_commit(g) < 0) {
        return NULL;
    }
    Py_RETURN_FALSE;
}

/* A record dropped while in the stream's list (its block never ended, or
   ending it failed): move its data, as dealloc of the stream writes its
   own, with a ResourceWarning if its block never ended; or drop it with
   one.  Takes the lock: other threads use the records in the list. */
static void
gather_finish(gather *g)
{
    buffered *self = g->stream;
    PyObject *exc = PyErr_GetRaisedException();
    /* Dropped by code running with the lock held (by this thread, further
       up its stack): the stream may be in the middle of something, so
       the data is dropped. */
    int mine = nibbler_mutex_is_mine(&self->nib.lock, _PyThreadState_GET());
    if (!mine) {
        (void)nibbler_mutex_lock(&self->nib.lock, (PyObject *)self, 0);
        nibbler_hold(&self->nib);
    }
    int active = 0;
    Py_ssize_t dropped = 0;
    if (g->pprev != NULL) {
        active = g->state == GATHER_ACTIVE;
        if (mine || gather_end(self, g, &dropped) == GATHER_KEPT) {
            dropped = g->list.nbytes;
            morsels_clear(&g->list);
            g->state = GATHER_DONE;
            gather_unlink(self, g);
        }
        PyErr_Clear();
    }
    if (!mine) {
        buffered_unlock(self);
    }
    Py_CLEAR(g->block);
    if (active || dropped > 0) {
        /* Without the lock: the warning may write to the stream. */
        int w = dropped > 0
            ? PyErr_WarnFormat(PyExc_ResourceWarning, 1,
                               "_gather() block %s: %zd gathered bytes "
                               "were dropped",
                               active ? "never ended" : "failed", dropped)
            : PyErr_WarnEx(PyExc_ResourceWarning,
                           "_gather() block never ended: its data was "
                           "written when it was dropped", 1);
        if (w < 0) {
            PyErr_WriteUnraisable((PyObject *)g);
        }
    }
    PyErr_SetRaisedException(exc);
}

static int
gather_traverse(PyObject *op, visitproc visit, void *arg)
{
    gather *g = (gather *)op;
    Py_VISIT(Py_TYPE(op));
    Py_VISIT(g->stream);
    Py_VISIT(g->ctx);
    Py_VISIT(g->joined);
    return 0;
}

static int
gather_clear(PyObject *op)
{
    gather *g = (gather *)op;
    /* ctx is set when the record joins the stream's list. */
    if (g->stream != NULL && g->ctx != NULL) {
        gather_finish(g);
    }
    Py_CLEAR(g->stream);
    Py_CLEAR(g->ctx);
    Py_CLEAR(g->joined);
    Py_CLEAR(g->block);
    morsels_clear(&g->list);
    return 0;
}

static void
gather_dealloc(PyObject *op)
{
    gather *g = (gather *)op;
    PyTypeObject *tp = Py_TYPE(op);
    PyObject_GC_UnTrack(op);
    (void)gather_clear(op);
    morsels_free(&g->list);
    tp->tp_free(op);
    Py_DECREF(tp);
}

static PyMethodDef gather_methods[] = {
    {"__enter__", gather_enter, METH_NOARGS},
    {"__exit__", _PyCFunction_CAST(gather_exit), METH_FASTCALL},
    {NULL, NULL}
};

static PyType_Slot gather_slots[] = {
    {Py_tp_dealloc, gather_dealloc},
    {Py_tp_traverse, gather_traverse},
    {Py_tp_clear, gather_clear},
    {Py_tp_methods, gather_methods},
    {0, NULL},
};

static PyType_Spec gather_spec = {
    .name = "_io._nibbler.Gather",
    .basicsize = sizeof(gather),
    .flags = (Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC |
              Py_TPFLAGS_IMMUTABLETYPE | Py_TPFLAGS_DISALLOW_INSTANTIATION),
    .slots = gather_slots,
};

/* A new _gather() context manager for self, or NULL on error.  limit_obj
   is NULL for the default, None for no limit, or a positive int. */
static PyObject *
gather_new(buffered *self, PyObject *limit_obj)
{
    Py_ssize_t limit = GATHER_LIMIT;
    if (limit_obj == Py_None) {
        limit = PY_SSIZE_T_MAX;
    }
    else if (limit_obj != NULL) {
        PyObject *index = _PyNumber_Index(limit_obj);
        if (index == NULL) {
            return NULL;
        }
        limit = PyLong_AsSsize_t(index);
        Py_DECREF(index);
        if (limit == -1 && PyErr_Occurred()) {
            return NULL;
        }
        if (limit <= 0) {
            PyErr_SetString(PyExc_ValueError, "limit must be positive");
            return NULL;
        }
    }
    PyTypeObject *tp = find_nibblermodule_state_by_def(
        Py_TYPE(self))->Gather_Type;
    gather *g = (gather *)tp->tp_alloc(tp, 0);
    if (g == NULL) {
        return NULL;
    }
    g->stream = (buffered *)Py_NewRef(self);
    g->limit = limit;
    return (PyObject *)g;
}

/*
 * Tracking for fork
 */

/* Called by PyOS_AfterFork_Child() in the child of a fork, before any
   Python after-fork hook (which may use these objects): release the
   mutexes of the buffered objects that threads gone in the fork held (see
   "Locking" in nibbler.h).  Finds the module with PyState_FindModule(),
   which runs no code. */
void
_PyIO_AfterForkChild(void)
{
    PyObject *module = PyState_FindModule(&_PyIO_nibbler_Module);
    if (module != NULL) {
        nibbler_set_after_fork(&get_nibblermodule_state(module)->nibblers);
    }
}

/* Add self, once, to the nibblers that the child of a fork releases. */
static void
buffered_track(buffered *self)
{
    if (self->module == NULL) {
        self->module = Py_NewRef(PyType_GetModuleByDef(
            Py_TYPE(self), &_PyIO_nibbler_Module));
    }
    nibbler_set_add(&get_nibblermodule_state(self->module)->nibblers,
                    &self->nib);
}

/*
 * Methods
 */

static int
buffered_clear(PyObject *op)
{
    buffered *self = buffered_cast(op);
    /* Writes without the lock use raw: there must be no writing end
       without it.  (No other thread can use the object any more.) */
    nibbler_stop_appending(&self->nib);
    Py_XDECREF(buffered_swap_raw(self, NULL));
    (void)buffered_drop_stash(self);
    Py_CLEAR(self->dict);
    return 0;
}

static void
buffered_dealloc(PyObject *op)
{
    buffered *self = buffered_cast(op);
    PyTypeObject *tp = Py_TYPE(self);
    self->finalizing = 1;
    if (_PyIOBase_finalize(op) < 0) {
        return;
    }
    _PyObject_GC_UNTRACK(self);
    FT_CLEAR_WEAKREFS(op, self->weakreflist);
    nibbler_set_remove(&self->nib);
    nibbler_free(&self->nib);
    (void)buffered_clear(op);
    morsels_free(&self->stash);
    Py_CLEAR(self->module);
    tp->tp_free(self);
    Py_DECREF(tp);
}

/*[clinic input]
_io._Buffered.__sizeof__
[clinic start generated code]*/

static PyObject *
_io__Buffered___sizeof___impl(buffered *self)
/*[clinic end generated code: output=0231ef7f5053134e input=753c782d808d34df]*/
{
    size_t res = _PyObject_SIZE(Py_TYPE(self));
    /* The buffer counts while it is allocated: it is allocated when first
       needed, and freed by close() and detach(). */
    if (FT_ATOMIC_LOAD_PTR_RELAXED(self->nib.block) != NULL) {
        res += (size_t)FT_ATOMIC_LOAD_SSIZE_RELAXED(self->nib.capacity);
    }
    return PyLong_FromSize_t(res);
}

static int
buffered_traverse(PyObject *op, visitproc visit, void *arg)
{
    buffered *self = buffered_cast(op);
    Py_VISIT(Py_TYPE(self));
    Py_VISIT(self->raw);
    Py_VISIT(self->dict);
    Py_VISIT(self->module);
    return 0;
}

/* Because this can call arbitrary code, it shouldn't be called when
   the refcount is 0 (that is, not directly from tp_dealloc unless
   the refcount has been temporarily re-incremented). */
/*[clinic input]
_io._Buffered._dealloc_warn

    source: object
    /

[clinic start generated code]*/

static PyObject *
_io__Buffered__dealloc_warn_impl(buffered *self, PyObject *source)
/*[clinic end generated code: output=d8db21c6dec0e614 input=8f845f2a4786391c]*/
{
    PyObject *raw = buffered_get_raw(self);
    if (raw != NULL) {
        PyObject *r;
        r = PyObject_CallMethodOneArg(raw, &_Py_ID(_dealloc_warn), source);
        Py_DECREF(raw);
        Py_XDECREF(r);
    }
    PyErr_Clear();
    Py_RETURN_NONE;
}

/*[clinic input]
_io._Buffered._discard_writes

Drop the pending writes; return how many bytes they were.

TextIOWrapper.close() calls this when its flush failed, so that the
close() of its buffer doesn't try to write them again.
[clinic start generated code]*/

static PyObject *
_io__Buffered__discard_writes_impl(buffered *self)
/*[clinic end generated code: output=4a612257ab62b745 input=8c98a37d7a14ddfa]*/
{
    if (buffered_lock_ready(self) < 0) {
        return NULL;
    }
    Py_ssize_t n = 0;
    if (buffered_writing(self)) {
        nibbler_stop_appending(&self->nib);
        n = nibbler_nbytes(&self->nib);
        morsels_clear(&self->nib.list);
    }
    buffered_leave(self);
    return PyLong_FromSsize_t(n);
}

/* .raw: None while uninitialized or detached. */
static PyObject *
buffered_raw_get(PyObject *op, void *Py_UNUSED(closure))
{
    PyObject *raw = buffered_ref_raw(buffered_cast(op));
    return raw != NULL ? raw : Py_None;
}

/* Methods and attributes passed straight on to the raw stream; no lock,
   so they never wait for I/O in another thread. */
static PyObject *
buffered_raw_call(buffered *self, PyObject *name)
{
    PyObject *raw = buffered_get_raw(self);
    if (raw == NULL) {
        return NULL;
    }
    PyObject *res = PyObject_CallMethodNoArgs(raw, name);
    Py_DECREF(raw);
    return res;
}

static PyObject *
buffered_raw_getattr(buffered *self, PyObject *name)
{
    PyObject *raw = buffered_get_raw(self);
    if (raw == NULL) {
        return NULL;
    }
    PyObject *res = PyObject_GetAttr(raw, name);
    Py_DECREF(raw);
    return res;
}

/* raw.flush() with the lock held, directly for an exact FileIO. */
static int
buffered_raw_flush(buffered *self)
{
    if (self->raw_fileio) {
        return _PyFileIO_flush(self->raw);
    }
    PyObject *res = PyObject_CallMethodNoArgs(self->raw, &_Py_ID(flush));
    Py_XDECREF(res);
    return res == NULL ? -1 : 0;
}

/* What flush() does, with the lock held: BufferedReader passes it on to
   the raw stream, the others write out pending data or hand back
   read-ahead. */
static int
buffered_flush_locked(buffered *self)
{
    return (buffered_writable(self) ? buffered_sync(self, 0)
                                    : buffered_raw_flush(self));
}

/* Is self.flush() ours: an exact class of ours, not shadowed in the
   instance dict?  Returns 1, 0, or -1 on error. */
static int
buffered_flush_is_ours(buffered *self)
{
    if (!_PyIO_is_nibbler_buffered_type(Py_TYPE(self))) {
        return 0;
    }
    PyObject *dict = buffered_dict(self);
    if (dict == NULL) {
        return 1;
    }
    int r = PyDict_Contains(dict, &_Py_ID(flush));
    return r < 0 ? -1 : !r;
}

/*[clinic input]
_io._Buffered.flush as _io__Buffered_simple_flush
[clinic start generated code]*/

static PyObject *
_io__Buffered_simple_flush_impl(buffered *self)
/*[clinic end generated code: output=29ebb3820db1bdfd input=f33ef045e7250767]*/
{
    return buffered_raw_call(self, &_Py_ID(flush));
}

/*[clinic input]
@getter
_io._Buffered.closed
[clinic start generated code]*/

static PyObject *
_io__Buffered_closed_get_impl(buffered *self)
/*[clinic end generated code: output=f08ce57290703a1a input=00b707b2517eaf8c]*/
{
    return buffered_raw_getattr(self, &_Py_ID(closed));
}

/*[clinic input]
_io._Buffered.close
[clinic start generated code]*/

static PyObject *
_io__Buffered_close_impl(buffered *self)
/*[clinic end generated code: output=7280b7b42033be0c input=d20b83d1ddd7d805]*/
{
    if (buffered_lock_ready(self) < 0) {
        return NULL;
    }
    PyObject *res = NULL;
    Py_ssize_t discarded = 0;
    int would_block = 0;
    /* gh-138720: Use the same closed check as flush(). */
    int r = buffered_is_closed(self);
    if (r != 0) {
        res = r > 0 ? Py_NewRef(Py_None) : NULL;
        goto end;
    }
    if (self->finalizing) {
        PyObject *w = _io__Buffered__dealloc_warn_impl(self,
                                                       (PyObject *)self);
        if (w != NULL) {
            Py_DECREF(w);
        }
        else {
            PyErr_Clear();
        }
    }
    PyObject *exc = NULL;
    r = buffered_flush_is_ours(self);
    if (r < 0) {
        goto end;
    }
    if (r) {
        /* Do what flush() does, without the method call, after adding
           what _gather() blocks gathered. */
        if ((self->ngather > 0 && gather_splice_records(self, 1) < 0)
            || buffered_flush_locked(self) < 0)
        {
            exc = PyErr_GetRaisedException();
        }
    }
    else {
        /* flush() was overridden; it takes the lock itself. */
        buffered_leave(self);
        if (_PyFile_Flush((PyObject *)self) < 0) {
            exc = PyErr_GetRaisedException();
        }
        /* Another thread may have detached it meanwhile. */
        if (buffered_lock_ready(self) < 0) {
            _PyErr_ChainExceptions1(exc);
            return NULL;
        }
        /* Inside a _gather() block, flush() only deferred flushing. */
        if (exc == NULL && self->ngather > 0
            && (gather_splice_records(self, 1) < 0
                || buffered_flush_locked(self) < 0))
        {
            exc = PyErr_GetRaisedException();
        }
    }

    if (exc != NULL && nibbler_reading(&self->nib) == NULL) {
        /* The flush failed: pending writes are freed below, and nothing
           writes them again (gh-83973, gh-55589). */
        discarded = nibbler_nbytes(&self->nib);
        would_block = PyErr_GivenExceptionMatches(exc, PyExc_BlockingIOError);
    }

    res = self->raw_fileio ? _PyFileIO_close(self->raw)
                           : PyObject_CallMethodNoArgs(self->raw,
                                                       &_Py_ID(close));
    /* Whether raw.close() succeeded or not, raw now says whether the
       object is closed. */
    nibbler_free(&self->nib);
    (void)buffered_drop_stash(self);

    if (exc != NULL) {
        _PyErr_ChainExceptions1(exc);
        Py_CLEAR(res);
    }
end:
    buffered_leave(self);
    if (discarded > 0) {
        /* Without the lock: the warning may write to this file. */
        _PyIO_warn_discarded(discarded, would_block);
    }
    return res;
}

/*[clinic input]
_io._Buffered.detach
[clinic start generated code]*/

static PyObject *
_io__Buffered_detach_impl(buffered *self)
/*[clinic end generated code: output=dd0fc057b8b779f7 input=482762a345cc9f44]*/
{
    /* flush() takes the lock itself.  Calls racing with detach() may run
       on either side of it; the lock keeps the buffers consistent. */
    if (!buffered_raw_usable(FT_ATOMIC_LOAD_PTR_RELAXED(self->raw))) {
        buffered_not_ready();
        return NULL;
    }
    if (_PyFile_Flush((PyObject *)self) < 0 || buffered_lock_ready(self) < 0) {
        return NULL;
    }
    /* Also write out what other threads wrote since flush(), and what
       _gather() blocks gathered. */
    if (buffered_writable(self)
        && ((self->ngather > 0 && gather_splice_records(self, 1) < 0)
            || buffered_sync(self, 0) < 0))
    {
        buffered_leave(self);
        return NULL;
    }
    PyObject *raw = buffered_swap_raw(self, NULL);
    nibbler_free(&self->nib);
    (void)buffered_drop_stash(self);
    buffered_leave(self);
    return raw;
}

/* Inquiries */

/*[clinic input]
_io._Buffered.seekable
[clinic start generated code]*/

static PyObject *
_io__Buffered_seekable_impl(buffered *self)
/*[clinic end generated code: output=90172abb5ceb6e8f input=7d35764f5fb5262b]*/
{
    return buffered_raw_call(self, &_Py_ID(seekable));
}

/*[clinic input]
_io._Buffered.readable
[clinic start generated code]*/

static PyObject *
_io__Buffered_readable_impl(buffered *self)
/*[clinic end generated code: output=92afa07661ecb698 input=640619addb513b8b]*/
{
    return buffered_raw_call(self, &_Py_ID(readable));
}

/*[clinic input]
_io._Buffered.writable
[clinic start generated code]*/

static PyObject *
_io__Buffered_writable_impl(buffered *self)
/*[clinic end generated code: output=4e3eee8d6f9d8552 input=b35ea396b2201554]*/
{
    return buffered_raw_call(self, &_Py_ID(writable));
}

/*[clinic input]
@getter
_io._Buffered.name
[clinic start generated code]*/

static PyObject *
_io__Buffered_name_get_impl(buffered *self)
/*[clinic end generated code: output=d2adf384051d3d10 input=5a60eb8d33149f6e]*/
{
    return buffered_raw_getattr(self, &_Py_ID(name));
}

/*[clinic input]
@getter
_io._Buffered.mode
[clinic start generated code]*/

static PyObject *
_io__Buffered_mode_get_impl(buffered *self)
/*[clinic end generated code: output=0feb205748892fa4 input=8d5e4c1fed38e6f0]*/
{
    return buffered_raw_getattr(self, &_Py_ID(mode));
}

/* Lower-level APIs */

/*[clinic input]
_io._Buffered.fileno
[clinic start generated code]*/

static PyObject *
_io__Buffered_fileno_impl(buffered *self)
/*[clinic end generated code: output=b717648d58a95ee3 input=768ea30b3f6314a7]*/
{
    return buffered_raw_call(self, &_Py_ID(fileno));
}

/*[clinic input]
_io._Buffered.isatty
[clinic start generated code]*/

static PyObject *
_io__Buffered_isatty_impl(buffered *self)
/*[clinic end generated code: output=c20e55caae67baea input=9ea007b11559bee4]*/
{
    return buffered_raw_call(self, &_Py_ID(isatty));
}

/*[clinic input]
_io._Buffered.flush
[clinic start generated code]*/

static PyObject *
_io__Buffered_flush_impl(buffered *self)
/*[clinic end generated code: output=da2674ef1ce71f3a input=fda63444697c6bf4]*/
{
    if (buffered_enter(self, "flush of closed file", LEAVE_GATHERED) < 0) {
        return NULL;
    }
    gather *g = self->ngather > 0 ? gather_find(self) : NULL;
    if (g != NULL) {
        /* Inside a _gather() block, flushing waits for its end. */
        g->flush = 1;
        buffered_leave(self);
        Py_RETURN_NONE;
    }
    int r = buffered_sync(self, 1);
    buffered_leave(self);
    if (r < 0) {
        return NULL;
    }
    Py_RETURN_NONE;
}

/*[clinic input]
_io._Buffered.peek
    size: Py_ssize_t = 0
    /

[clinic start generated code]*/

static PyObject *
_io__Buffered_peek_impl(buffered *self, Py_ssize_t size)
/*[clinic end generated code: output=ba7a097ca230102b input=37ffb97d06ff4adb]*/
{
    /* The read-ahead, however short (size is not looked at): reading
       more could block, as on a pipe that has no more yet, where
       pickle.load() peeks for more than it needs.  Only with none, one raw
       read.  Without the lock when there is some. */
    (void)size;
    PyObject *res = nibbler_peek(&self->nib);
    if (res == NULL || PyBytes_GET_SIZE(res) > 0) {
        return res;
    }
    res = NULL;
    if (buffered_enter(self, "peek of closed file", READING) < 0) {
        return NULL;
    }
    if (self->nib.capacity == 0 && nibbler_unread(&self->nib) == 0) {
        /* Unbuffered: it can't look ahead without taking the bytes. */
        _PyIO_State *state = find_io_state_by_def(Py_TYPE(self));
        PyErr_SetString(state->unsupported_operation,
                        "peek() needs a buffer (buffer_size is 0)");
        buffered_leave(self);
        return NULL;
    }
    Py_ssize_t r = (nibbler_unread(&self->nib) > 0
                    ? 1 : buffered_fill(self, 0));
    if (r == WOULD_BLOCK && nibbler_unread(&self->nib) == 0) {
        /* Would block, with nothing to return. */
        res = Py_NewRef(Py_None);
    }
    else if (r != -1) {
        res = nibbler_peek_held(&self->nib);
    }
    buffered_leave(self);
    return res;
}

/* read(n) (-1: all) and read1(n) with the lock: out of line, so that the
   lock-free paths stay small.  read(0) and read1(0) need no read-ahead:
   don't make BufferedRandom write out pending data for them. */
Py_NO_INLINE static PyObject *
buffered_read_locked(buffered *self, Py_ssize_t n, int read1)
{
    if (buffered_enter(self, "read of closed file",
                       n == 0 ? KEEP_DIRECTION : READING) < 0)
    {
        return NULL;
    }
    PyObject *res = (n == -1 ? buffered_read_all(self)
                             : buffered_read_bytes(self, n, read1));
    buffered_leave(self);
    return res;
}

/*[clinic input]
_io._Buffered.read
    size as n: Py_ssize_t(accept={int, NoneType}) = -1
    /
[clinic start generated code]*/

static PyObject *
_io__Buffered_read_impl(buffered *self, Py_ssize_t n)
/*[clinic end generated code: output=f41c78bb15b9bbe9 input=7df81e82e08a68a2]*/
{
    if (n < -1) {
        PyErr_SetString(PyExc_ValueError,
                        "read length must be non-negative or -1");
        return NULL;
    }
    /* Without the lock when the read-ahead has all of it. */
    nibbler_end *e = nibbler_end_get(&self->nib, 0);
    Py_ssize_t start;
    if (e != NULL && n >= 0 && nibbler_claim(e, n, 1, &start) >= 0) {
        return nibbler_end_bytes(e, start, n);
    }
    return buffered_read_locked(self, n, 0);
}

/*[clinic input]
_io._Buffered.readall

Read until EOF, like read() with no size.
[clinic start generated code]*/

static PyObject *
_io__Buffered_readall_impl(buffered *self)
/*[clinic end generated code: output=78e22877f49cb977 input=2c2a4790ffd94db6]*/
{
    if (buffered_enter(self, "read of closed file", READING) < 0) {
        return NULL;
    }
    PyObject *res = buffered_read_all(self);
    buffered_leave(self);
    return res;
}

/*[clinic input]
_io._Buffered.read1
    size as n: Py_ssize_t = -1
    /
[clinic start generated code]*/

static PyObject *
_io__Buffered_read1_impl(buffered *self, Py_ssize_t n)
/*[clinic end generated code: output=bcc4fb4e54d103a3 input=7d22de9630b61774]*/
{
    /* Without the lock (and no raw read) when there is read-ahead. */
    nibbler_end *e = nibbler_end_get(&self->nib, 0);
    Py_ssize_t start;
    Py_ssize_t k = e == NULL ? -1 : nibbler_claim(
        e, n < 0 ? PY_SSIZE_T_MAX : n, 0, &start);
    if (k > 0 || (k == 0 && n == 0)) {
        return nibbler_end_bytes(e, start, k);
    }
    if (n < 0) {
        Py_ssize_t capacity = FT_ATOMIC_LOAD_SSIZE_RELAXED(self->nib.capacity);
        n = capacity > 0 ? capacity : DEFAULT_BUFFER_SIZE;
    }
    return buffered_read_locked(self, n, 1);
}

static PyObject *
buffered_readinto_common(buffered *self, Py_buffer *buffer, int readinto1)
{
    if (buffered_enter(self, "readinto of closed file", READING) < 0) {
        return NULL;
    }
    /* The raw stream reads into the caller's memory itself, through a
       view bound to the caller's object (or into a copy, see
       buffered_raw_read()): what Python code keeps of it stays valid
       through that object, which is all `shared` would ask for. */
    int shared = 0;
    Py_ssize_t n = buffered_read_into(self, buffer->buf, buffer->len,
                                      readinto1, buffer->obj, &shared);
    buffered_leave(self);
    if (n == WOULD_BLOCK) {
        Py_RETURN_NONE;
    }
    return n < 0 ? NULL : PyLong_FromSsize_t(n);
}

/*[clinic input]
_io._Buffered.readinto
    buffer: Py_buffer(accept={rwbuffer})
    /
[clinic start generated code]*/

static PyObject *
_io__Buffered_readinto_impl(buffered *self, Py_buffer *buffer)
/*[clinic end generated code: output=bcb376580b1d8170 input=ed6b98b7a20a3008]*/
{
    return buffered_readinto_common(self, buffer, 0);
}

/*[clinic input]
_io._Buffered.readinto1
    buffer: Py_buffer(accept={rwbuffer})
    /
[clinic start generated code]*/

static PyObject *
_io__Buffered_readinto1_impl(buffered *self, Py_buffer *buffer)
/*[clinic end generated code: output=6e5c6ac5868205d6 input=4455c5d55fdf1687]*/
{
    return buffered_readinto_common(self, buffer, 1);
}

/* readline() with the lock: out of line, so that the lock-free path
   stays small. */
Py_NO_INLINE static PyObject *
buffered_readline_locked(buffered *self, Py_ssize_t size)
{
    if (buffered_enter(self, "readline of closed file",
                       size == 0 ? KEEP_DIRECTION : READING) < 0)
    {
        return NULL;
    }
    if (self->nib.capacity == 0) {
        /* Unbuffered: it can't find the end of the line without reading
           past it. */
        _PyIO_State *state = find_io_state_by_def(Py_TYPE(self));
        PyErr_SetString(state->unsupported_operation,
                        "readline() needs a buffer (buffer_size is 0)");
        buffered_leave(self);
        return NULL;
    }
    PyObject *res = buffered_readline(self, size);
    buffered_leave(self);
    return res;
}

/*[clinic input]
_io._Buffered.readline
    size: Py_ssize_t(accept={int, NoneType}) = -1
    /
[clinic start generated code]*/

static PyObject *
_io__Buffered_readline_impl(buffered *self, Py_ssize_t size)
/*[clinic end generated code: output=24dd2aa6e33be83c input=673b6240e315ef8a]*/
{
    /* Without the lock when the line is in the read-ahead. */
    nibbler_end *e = nibbler_end_get(&self->nib, 0);
    Py_ssize_t start, k;
    if (e != NULL && (k = nibbler_claim_line(e, size, &start)) >= 0) {
        return nibbler_end_bytes(e, start, k);
    }
    return buffered_readline_locked(self, size);
}

/*[clinic input]
_io._Buffered.tell
[clinic start generated code]*/

static PyObject *
_io__Buffered_tell_impl(buffered *self)
/*[clinic end generated code: output=386972ae84716c1e input=ad61e04a6b349573]*/
{
    if (buffered_enter(self, NULL, LEAVE_GATHERED) < 0) {
        return NULL;
    }
    /* Inside a _gather() block, the position is after what it gathered. */
    gather *g = self->ngather > 0 ? gather_find(self) : NULL;
    Py_ssize_t gathered = g != NULL ? g->list.nbytes : 0;
    PyObject *res = NULL;
    /* Pending writes to a raw stream in append mode go to the end of the
       file: write them out, and the raw position is the logical one
       (gh-80592). */
    if (!self->raw_appending || !buffered_writing(self)
        || buffered_flush_writes(self, 0) == 0)
    {
        res = buffered_position(self, gathered);
    }
    buffered_leave(self);
    return res;
}

/*[clinic input]
_io._Buffered.seek
    target as targetobj: object
    whence: int = 0
    /
[clinic start generated code]*/

static PyObject *
_io__Buffered_seek_impl(buffered *self, PyObject *targetobj, int whence)
/*[clinic end generated code: output=7ae0e8dc46efdefb input=a9c4920bfcba6163]*/
{
    /* Do some error checking instead of trusting OS 'seek()' error
       detection, just in case. */
    int supported = whence >= 0 && whence <= 2;
#ifdef SEEK_HOLE
    supported = supported || whence == SEEK_HOLE;
#endif
#ifdef SEEK_DATA
    supported = supported || whence == SEEK_DATA;
#endif
    if (!supported) {
        PyErr_Format(PyExc_ValueError,
                     "whence value %d unsupported", whence);
        return NULL;
    }
    /* Before taking the lock, as these can run Python code (which may use
       this object). */
    PyObject *raw = buffered_get_raw(self);
    if (raw == NULL) {
        return NULL;
    }
    /* Checked again with the lock. */
    int closed = buffered_ref_closed(raw);
    if (closed != 0) {
        if (closed > 0) {
            PyErr_SetString(PyExc_ValueError, "seek of closed file");
        }
        Py_DECREF(raw);
        return NULL;
    }
    _PyIO_State *state = find_io_state_by_def(Py_TYPE(self));
    PyObject *seekable = _PyIOBase_check_seekable(state, raw, Py_True);
    Py_DECREF(raw);
    if (seekable == NULL) {
        return NULL;
    }
    Py_off_t target = PyNumber_AsOff_t(targetobj, PyExc_ValueError);
    if (target == -1 && PyErr_Occurred()) {
        return NULL;
    }
    if (buffered_enter(self, "seek of closed file", KEEP_DIRECTION) < 0) {
        return NULL;
    }
    PyObject *res = NULL;
    if (nibbler_reading(&self->nib) != NULL && self->stash.nbytes == 0
        && (whence == SEEK_SET || whence == SEEK_CUR))
    {
        /* Move within the last fill if the target is in it: its bytes end
           at the raw position. */
        Py_off_t raw_pos = buffered_raw_pos(self);
        if (raw_pos == -1) {
            goto end;
        }
        Py_off_t offset = target;   /* from the current position */
        if (whence == SEEK_SET) {
            offset = target - (raw_pos - nibbler_unread(&self->nib));
        }
        Py_ssize_t unread = nibbler_move(&self->nib, offset);
        if (unread >= 0) {
            Py_off_t pos = raw_pos - (unread - offset);
            // GH-95782
            res = PyLong_FromOff_t(pos < 0 ? 0 : pos);
            goto end;
        }
    }
    /* The read-ahead and stashed data (all that is unread now) are given
       up. */
    Py_ssize_t unread = (nibbler_drop_unread(&self->nib)
                         + buffered_drop_stash(self));
    if (!buffered_writing(self) || buffered_flush_writes(self, 0) == 0) {
        if (whence == SEEK_CUR) {
            target -= unread;
        }
        Py_off_t pos = buffered_raw_seek(self, target, whence);
        if (pos != -1) {
            res = PyLong_FromOff_t(pos);
        }
    }
end:
    buffered_leave(self);
    return res;
}

/*[clinic input]
_io._Buffered.truncate
    cls: defining_class
    pos: object = None
    /
[clinic start generated code]*/

static PyObject *
_io__Buffered_truncate_impl(buffered *self, PyTypeObject *cls, PyObject *pos)
/*[clinic end generated code: output=fe3882fbffe79f1a input=f5b737d97d76303f]*/
{
    if (buffered_enter(self, "truncate of closed file", KEEP_DIRECTION) < 0) {
        return NULL;
    }
    PyObject *res = NULL;
    if (!buffered_writable(self)) {
        _PyIO_State *state = find_io_state_by_def(cls);
        PyErr_SetString(state->unsupported_operation, "truncate");
    }
    else if (buffered_sync(self, 0) == 0) {
        res = PyObject_CallMethodOneArg(self->raw, &_Py_ID(truncate), pos);
        self->nib.raw_pos = NIBBLER_POS_UNKNOWN;
    }
    buffered_leave(self);
    return res;
}

static PyObject *
buffered_iternext(PyObject *op)
{
    buffered *self = buffered_cast(op);
    PyObject *line;
    if (_PyIO_is_nibbler_buffered_type(Py_TYPE(self))) {
        /* Skip method call overhead for speed. */
        line = _io__Buffered_readline_impl(self, -1);
    }
    else {
        line = PyObject_CallMethodNoArgs((PyObject *)self,
                                         &_Py_ID(readline));
        if (line && line != Py_None && !PyBytes_Check(line)) {
            PyErr_Format(PyExc_OSError,
                         "readline() should have returned a bytes object, "
                         "not '%.200s'", Py_TYPE(line)->tp_name);
            Py_DECREF(line);
            return NULL;
        }
    }

    if (line == NULL) {
        return NULL;
    }
    if (line == Py_None) {
        /* Would block: raise BlockingIOError, since StopIteration would
           look like EOF. */
        Py_DECREF(line);
        _PyIO_set_read_blocking_error();
        return NULL;
    }

    if (PyBytes_GET_SIZE(line) == 0) {
        /* Reached EOF or would have blocked */
        Py_DECREF(line);
        return NULL;
    }

    return line;
}

static PyObject *
buffered_repr(PyObject *op)
{
    buffered *self = buffered_cast(op);
    PyObject *nameobj, *res;

    if (PyObject_GetOptionalAttr((PyObject *)self, &_Py_ID(name),
                                 &nameobj) < 0)
    {
        if (!PyErr_ExceptionMatches(PyExc_ValueError)) {
            return NULL;
        }
        /* Ignore ValueError raised if the underlying stream was detached */
        PyErr_Clear();
    }
    if (nameobj == NULL) {
        res = PyUnicode_FromFormat("<%s>", Py_TYPE(self)->tp_name);
    }
    else {
        int status = Py_ReprEnter((PyObject *)self);
        res = NULL;
        if (status == 0) {
            res = PyUnicode_FromFormat("<%s name=%R>",
                                       Py_TYPE(self)->tp_name, nameobj);
            Py_ReprLeave((PyObject *)self);
        }
        else if (status > 0) {
            PyErr_Format(PyExc_RuntimeError,
                         "reentrant call inside %s.__repr__",
                         Py_TYPE(self)->tp_name);
        }
        Py_DECREF(nameobj);
    }
    return res;
}

/* Check raw supports what the class needs (BufferedRandom: seeking too). */
static int
buffered_check_raw(_PyIO_State *state, PyObject *raw, int raw_fileio,
                   int readable, int writable, Py_ssize_t buffer_size)
{
    /* Unbuffered, it never seeks to switch between reading and writing
       (only to hand back data kept after a raw read raised), so that
       open(fd, "r+b", buffering=0) works for a pipe or terminal, as it
       does with FileIO. */
    if (readable && writable && buffer_size != 0
        && _PyIOBase_check_seekable(state, raw, Py_True) == NULL)
    {
        return -1;
    }
    if (raw_fileio) {
        /* Its flags answer readable() and writable() directly. */
        return _PyFileIO_check_access(raw, readable, writable);
    }
    if ((readable && _PyIOBase_check_readable(state, raw, Py_True) == NULL)
        || (writable && _PyIOBase_check_writable(state, raw, Py_True) == NULL))
    {
        return -1;
    }
    return 0;
}

/* Shared constructor: check raw supports the needed operations, then set
   the object up for it, with blocks of buffer_size bytes and pending
   writes written out past threshold bytes. */
static int
buffered_init(buffered *self, PyObject *raw, Py_ssize_t buffer_size,
              Py_ssize_t threshold, int readable, int writable)
{
    _PyIO_State *state = find_io_state_by_def(Py_TYPE(self));
    int raw_fileio = Py_IS_TYPE(raw, state->PyFileIO_Type);
    int err = buffered_check_raw(state, raw, raw_fileio, readable, writable,
                                 buffer_size);
    if (err == 0 && buffer_size < 0) {
        PyErr_SetString(PyExc_ValueError,
                        "buffer size must not be negative");
        err = -1;
    }

    /* (Re)initialize; a failed __init__() leaves the object uninitialized.
       Its exception is put aside meanwhile, and is the context of any
       raised here. */
    PyObject *exc = err < 0 ? PyErr_GetRaisedException() : NULL;
    buffered_track(self);
    if (nibbler_lock_io(&self->nib, (PyObject *)self) < 0) {
        _PyErr_ChainExceptions1(exc);
        return -1;
    }
    /* Pending writes first go to the raw stream they were written to, as
       FileIO.__init__() first closes the file it had open: if that fails,
       raise, leaving the object as it is. */
    if (buffered_raw_usable(self->raw)
        && ((self->ngather > 0 && gather_splice_records(self, 1) < 0)
            || (buffered_writing(self)
                && buffered_flush_writes(self, 0) < 0)))
    {
        buffered_leave(self);
        _PyErr_ChainExceptions1(exc);
        return -1;
    }
    nibbler_free(&self->nib);
    (void)buffered_drop_stash(self);
    FT_ATOMIC_STORE_SSIZE_RELAXED(self->nib.capacity,
                                  err == 0 ? buffer_size : 0);
    self->nib.threshold = err == 0 ? threshold : 0;
    if (err == 0) {
        /* Also read without the lock, by small writes. */
        FT_ATOMIC_STORE_UINT8_RELAXED(self->raw_fileio, (uint8_t)raw_fileio);
        /* Write several pieces with one _writev() call when the raw stream
           has one of its own (FileIO's writes them with one writev()), but
           not RawIOBase's, which only calls write() on each: joining small
           pieces in a block makes fewer write() calls (1000 writes of 600
           bytes and 16 bytes to a raw stream with only write(): 39 calls
           instead of 1000, 1679 instead of 8244 instructions per write).
           Not on a FileIO subclass, whose _writev() could bypass an
           overridden write().  (Readers skip the lookups.) */
        PyObject *writev = (writable
                            ? _PyType_Lookup(Py_TYPE(raw), &_Py_ID(_writev))
                            : NULL);
        int vectored = (
            writev != NULL
            && (raw_fileio || !PyObject_TypeCheck(raw, state->PyFileIO_Type))
            && writev != _PyType_Lookup(state->PyRawIOBase_Type,
                                        &_Py_ID(_writev)));
        self->raw_vectored = (uint8_t)vectored;
        /* Keep large writes by reference, to be written straight from
           them, where that beats copying them into a block: from 512 bytes
           to a FileIO (one writev() of them); from 2 KiB to other raw
           streams with a _writev() of their own, whose Python-level call
           costs more per piece (1000 writes to a SocketIO: by reference,
           5549 instructions per write at 512 bytes and 6710 at 1 KiB, but
           3674 and 5168 copied; 9304 and 9205 at 2 KiB; 13298 and 16298
           at 4 KiB); never otherwise. */
        self->ref_min = (raw_fileio ? NIBBLER_REF_MIN
                         : vectored ? 2048 : PY_SSIZE_T_MAX);
        self->raw_appending = (
            writable
            && PyObject_TypeCheck(raw, state->PyFileIO_Type)
            && _PyFileIO_appending(raw));
    }
    /* (nibbler_free() made the raw position unknown.) */
    self->raw_regular = (err == 0 && raw_fileio && !self->raw_appending
                         && _PyFileIO_regular(raw));
    PyObject *old = buffered_swap_raw(self, err == 0 ? Py_NewRef(raw) : NULL);
    buffered_leave(self);
    /* Releasing the old raw stream can run arbitrary code. */
    Py_XDECREF(old);
    if (exc != NULL) {
        _PyErr_ChainExceptions1(exc);
    }
    return err;
}

/*
 * class BufferedReader
 */

/*[clinic input]
_io.BufferedReader.__init__
    raw: object
    buffer_size: Py_ssize_t(c_default="DEFAULT_BUFFER_SIZE") = DEFAULT_BUFFER_SIZE

Create a new buffered reader using the given readable raw IO object.
[clinic start generated code]*/

static int
_io_BufferedReader___init___impl(buffered *self, PyObject *raw,
                                 Py_ssize_t buffer_size)
/*[clinic end generated code: output=cddcfefa0ed294c4 input=fb887e06f11b4e48]*/
{
    return buffered_init(self, raw, buffer_size, buffer_size, 1, 0);
}

/* The constructor of BufferedWriter and BufferedRandom: buffer_size is an
   int (or NULL for the default) or None to buffer writes without limit. */
static int
buffered_init_writer(buffered *self, PyObject *raw, PyObject *buffer_size,
                     int readable)
{
    Py_ssize_t size = DEFAULT_BUFFER_SIZE;
    Py_ssize_t threshold = PY_SSIZE_T_MAX;
    if (buffer_size != Py_None) {
        if (buffer_size != NULL) {
            /* As the Py_ssize_t converter of Argument Clinic does. */
            PyObject *index = _PyNumber_Index(buffer_size);
            if (index == NULL) {
                return -1;
            }
            size = PyLong_AsSsize_t(index);
            Py_DECREF(index);
            if (size == -1 && PyErr_Occurred()) {
                return -1;
            }
        }
        threshold = size;
    }
    return buffered_init(self, raw, size, threshold, readable, 1);
}

/*
 * class BufferedWriter
 */

/*[clinic input]
_io.BufferedWriter.__init__
    raw: object
    buffer_size: object(c_default="NULL") = DEFAULT_BUFFER_SIZE

A buffer for a writeable sequential RawIO object.

The constructor creates a BufferedWriter for the given writeable raw
stream. If the buffer_size is not given, it defaults to
DEFAULT_BUFFER_SIZE.  With buffer_size None, writes are buffered
without limit: they reach the raw stream only through flush(), and
operations that need it, such as close(), seek() and detach().
[clinic start generated code]*/

static int
_io_BufferedWriter___init___impl(buffered *self, PyObject *raw,
                                 PyObject *buffer_size)
/*[clinic end generated code: output=8d9fb8a003624cb5 input=8c1ff83965bd109e]*/
{
    return buffered_init_writer(self, raw, buffer_size, 0);
}

/* If the raised exception is an OSError or MemoryError (raised writing,
   or keeping data), make it say that n bytes of the data of write() were
   accepted (written, or kept pending), as BlockingIOError does, so that
   the caller knows what to write again.  (Others, such as one a signal
   handler raised, are left as they are.)  Keeps the exception. */
Py_NO_INLINE static void
buffered_set_written(Py_ssize_t n)
{
    PyObject *exc = PyErr_GetRaisedException();
    if (PyErr_GivenExceptionMatches(exc, PyExc_OSError)
        || PyErr_GivenExceptionMatches(exc, PyExc_MemoryError))
    {
        PyObject *v = PyLong_FromSsize_t(n);
        if (v == NULL
            || PyObject_SetAttrString(exc, "characters_written", v) < 0)
        {
            PyErr_Clear();
        }
        Py_XDECREF(v);
    }
    PyErr_SetRaisedException(exc);
}

/* write() raised an error other than BlockingIOError after `done` bytes of
   its data reached the raw stream: keep the rest pending, as much of it as
   fits, so that flush() writes it, and set the error's characters_written
   to how much of the data was accepted (written or kept), see
   buffered_set_written().  Without that,
   the caller couldn't tell what to write again.  Returns -1. */
Py_NO_INLINE static int
buffered_write_failed(buffered *self, PyObject *obj, const char *data,
                      Py_ssize_t len, Py_ssize_t done)
{
    if (done == 0) {
        /* None of the data was taken: the caller can just retry. */
        return -1;
    }
    PyObject *exc = PyErr_GetRaisedException();
    Py_ssize_t room = Py_MAX(0, self->nib.threshold
                                - nibbler_nbytes(&self->nib));
    Py_ssize_t keep = Py_MIN(len - done, room);
    if (buffered_add_write(self, obj, data + done, keep) < 0) {
        /* Raised instead, with exc as context. */
        _PyErr_ChainExceptions1(exc);
        keep = 0;
    }
    else {
        PyErr_SetRaisedException(exc);
    }
    buffered_set_written(done + keep);
    return -1;
}

/* Without the lock: queue data[0:len] at the writing end, if there is one
   with room.  Returns 1 when done, 0 when the lock is needed, or -1 on
   error (ValueError(closed_msg) if an exact FileIO is closed). */
static inline int
buffered_write_lockfree(buffered *self, const char *data, Py_ssize_t len,
                        const char *closed_msg)
{
    nibbler_end *e = nibbler_end_get(&self->nib, 1);
    Py_ssize_t r;
    if (e == NULL || (r = nibbler_reserve(e, len)) < 0) {
        return 0;
    }
    /* Until committed, nothing can replace raw.  When an exact FileIO was
       closed by itself, the bytes are given back, unless other threads
       reserved bytes after them meanwhile: then they are queued too, and
       nothing can write them out any more.  Other raw streams are not
       asked here (see "Writing" in the comment before the buffered
       struct). */
    PyObject *raw = FT_ATOMIC_LOAD_PTR_RELAXED(self->raw);
    if (FT_ATOMIC_LOAD_UINT8_RELAXED(self->raw_fileio)
        && _PyFileIO_closed(raw))
    {
        if (!nibbler_unreserve(e, r, len)) {
            nibbler_commit(e, r, data, len);
        }
        PyErr_SetString(PyExc_ValueError, closed_msg);
        return -1;
    }
    nibbler_commit(e, r, data, len);
    return 1;
}

/* write() of data[0:len], inside obj (or NULL), with the lock: buffer
   it, writing out what is pending first when it doesn't fit.  Called from
   code that the raw write of this thread's write out runs (such as a
   signal handler), it buffers all of the data, past the capacity if need
   be: the write out or the next flush writes it.  Returns 0 or -1.  Out of
   line, so that the lock-free paths before it stay small. */
Py_NO_INLINE static int
buffered_write_data(buffered *self, PyObject *obj, const char *data,
                    Py_ssize_t len)
{
    if (buffered_enter_append(self) < 0) {
        return -1;
    }
    if (self->ngather > 0) {
        /* Gather it if the context has a _gather() block. */
        gather *g = gather_find(self);
        if (g != NULL) {
            int r = gather_add(g, obj, data, len);
            buffered_unlock(self);
            return r;
        }
    }
    /* How much of data was written out. */
    Py_ssize_t done = 0;
    int have_io = 0;
    int r;
    for (;;) {
        Py_ssize_t threshold = self->nib.threshold;
        assert(threshold >= 0);
        Py_ssize_t rest = len - done;
        Py_ssize_t pending = nibbler_nbytes(&self->nib);
        /* Room for the rest of data: buffer it.  (Unbuffered, the threshold
           is 0: there is never room.) */
        if (rest < threshold && pending + rest <= threshold) {
            r = buffered_add_write(self, obj, data + done, rest);
            if (r < 0 && done > 0) {
                /* Some of data was written out before. */
                buffered_set_written(done);
            }
            break;
        }
        /* No room: write out, with the I/O role. */
        if (!have_io) {
            int t = nibbler_take_io(&self->nib, (PyObject *)self);
            if (t == NIBBLER_IO_MINE) {
                /* gh-118143 */
                r = nibbler_append_copy(&self->nib, data + done, rest);
                break;
            }
            if (t < 0) {
                return -1;
            }
            have_io = 1;
            if (t == NIBBLER_IO_WAITED) {
                /* Another thread was writing out, which may have made
                   room: check again, since anything may have changed. */
                if (buffered_enter_locked(self, "write to closed file",
                                          WRITING) < 0)
                {
                    nibbler_end_io(&self->nib);
                    return -1;
                }
                continue;
            }
        }
        /* Write out what is pending, and the rest of data with it when it
           is too large to buffer, or one vectored write takes both (with a
           Python-level _writev(), only data large enough to be kept by
           reference, see buffered_init(): smaller data costs less copied
           into the buffer than as one more piece), without the lock: other
           threads can queue writes meanwhile. */
        int status;
        int vectored = (self->raw_vectored
                        && (self->raw_fileio || rest >= self->ref_min));
        Py_ssize_t direct = rest >= threshold || vectored ? rest : 0;
        done += buffered_write_out(self, pending, obj, data + done, direct,
                                   &status, 1);
        rest = len - done;
        if (status == WRITE_DONE) {
            if (rest == 0 && nibbler_nbytes(&self->nib) == 0) {
                /* All written (unbuffered, the usual case). */
                r = 0;
                break;
            }
            continue;
        }
        if (status == WRITE_ERROR) {
            r = buffered_write_failed(self, obj, data, len, done);
            break;
        }
        /* Would block: keep as much of the rest as fits, and report the
           rest. */
        Py_ssize_t room = Py_MAX(0, threshold - nibbler_nbytes(&self->nib));
        if (rest <= room) {
            r = buffered_add_write(self, obj, data + done, rest);
            if (r < 0 && done > 0) {
                buffered_set_written(done);
            }
            break;
        }
        int errnum = errno;
        if (buffered_add_write(self, obj, data + done, room) == 0) {
            errno = errnum;
            buffered_set_blocking_error(done + room);
        }
        else if (done > 0) {
            buffered_set_written(done);
        }
        r = -1;
        break;
    }
    if (have_io) {
        nibbler_end_io(&self->nib);
    }
    if (r == 0 && self->ngather == 0) {
        /* The next writes may need no lock (unless gathering, see
           "Gathering"). */
        nibbler_start_appending(&self->nib);
    }
    buffered_unlock(self);
    return r;
}

/*[clinic input]
_io._Buffered._gather
    limit as limit_obj: object(c_default="NULL") = 20971520

Gather the writes of the current context in a with block.

Returns a context manager.  Inside its with block, what the current
context (thread, or asyncio task) writes is kept apart, also past
the buffer size, and added to the buffered data in one piece when
the block ends (also when it raises), so that no other output gets
in between.  Once the block gathered limit bytes, they are added,
and gathering goes on; with limit None, only at the end.  flush()
inside the block takes effect at its end.  Reads, seek() and
truncate() in the context add what it gathered first; close(),
detach() and __init__(), from any context, what every block
gathered.  A block on the same stream nested in one gathers into it.

Gathering is by context, as with decimal.localcontext(): a block
spanning a yield gathers what runs in the context meanwhile.  Data
of a block dropped before it ends is added then, or dropped when
the stream is closed, with a ResourceWarning.  Experimental.
[clinic start generated code]*/

static PyObject *
_io__Buffered__gather_impl(buffered *self, PyObject *limit_obj)
/*[clinic end generated code: output=707c4e9e896fa736 input=8590831af3586247]*/
{
    return gather_new(self, limit_obj);
}

/*[clinic input]
_io.BufferedWriter.readall

Not supported: a BufferedWriter can't read.
[clinic start generated code]*/

static PyObject *
_io_BufferedWriter_readall_impl(buffered *self)
/*[clinic end generated code: output=7637ea071b897d9d input=d1b433b1d223747c]*/
{
    _PyIO_State *state = find_io_state_by_def(Py_TYPE(self));
    PyErr_SetString(state->unsupported_operation, "readall");
    return NULL;
}

/* write() of an object other than exact bytes, through its buffer: out
   of line, so that the path for bytes stays small. */
Py_NO_INLINE static PyObject *
buffered_write_buffer(buffered *self, PyObject *obj)
{
    Py_buffer view;
    if (PyObject_GetBuffer(obj, &view, PyBUF_SIMPLE) < 0) {
        return NULL;
    }
    int r = 0;
    if (view.len < NIBBLER_REF_MIN) {
        r = buffered_write_lockfree(self, view.buf, view.len,
                                    "write to closed file");
    }
    if (r == 0) {
        r = buffered_write_data(self, view.obj, view.buf, view.len);
    }
    Py_ssize_t len = view.len;
    PyBuffer_Release(&view);
    return r < 0 ? NULL : PyLong_FromSsize_t(len);
}

/*[clinic input]
_io.BufferedWriter.write
    buffer as obj: object
    /
[clinic start generated code]*/

static PyObject *
_io_BufferedWriter_write_impl(buffered *self, PyObject *obj)
/*[clinic end generated code: output=4b5acd5810c0fa55 input=b4d277ddee118f17]*/
{
    if (!PyBytes_CheckExact(obj)) {
        return buffered_write_buffer(self, obj);
    }
    /* Exact bytes need no buffer export. */
    const char *data = PyBytes_AS_STRING(obj);
    Py_ssize_t len = PyBytes_GET_SIZE(obj);
    int r = (len < NIBBLER_REF_MIN
             ? buffered_write_lockfree(self, data, len, "write to closed file")
             : 0);
    if (r == 0) {
        r = buffered_write_data(self, obj, data, len);
    }
    return r < 0 ? NULL : PyLong_FromSsize_t(len);
}

/*
 * Bytes for TextIOWrapper
 *
 * _io._nibbler.TextIOWrapper (textio.c) uses an exact buffered object of
 * ours as the storage of its bytes, through the functions below (see
 * _iomodule.h) instead of its methods: it decodes from the unread bytes
 * and takes only those of the text it returns, and appends what it
 * encodes as write() does.  An instance dict could override the methods,
 * so objects with one are used through them (_PyIO_NIBBLER_NO): peek and
 * advance look for it again once they have the lock, so that no bytes are
 * taken here once the text layer may have read ahead through read1().
 * After the raw stream alone was closed, what was read ahead is served
 * (locked or not), as read() does; more raises ValueError.  A text read
 * that fails after taking bytes puts them back (_PyIONibbler_unread()), as
 * buffered_push_back() does for a binary read.
 */

#define TEXT_CLOSED "I/O operation on closed file."

/* How many unread bytes a peek gathers in one block, growing it (as
   buffered_fill() does for a long line), before it returns
   _PyIO_NIBBLER_FULL: so that text takes a line of up to that many bytes
   at once (and threads reading lines get them whole).  64 blocks, and at
   least DEFAULT_BUFFER_SIZE. */
#define TEXT_PEEK_MAX(capacity) \
    Py_MAX(64 * (capacity), (Py_ssize_t)DEFAULT_BUFFER_SIZE)

/* peek with the lock: out of line, so that the lock-free path stays
   small. */
Py_NO_INLINE static int
buffered_text_peek_locked(buffered *self, Py_ssize_t need, morsel *m,
                          uint64_t *key)
{
    if (buffered_enter(self, NULL, READING) < 0) {
        return -1;
    }
    if (buffered_dict(self) != NULL) {
        /* Got a dict while this waited (see _PyIONibbler_advance()). */
        buffered_leave(self);
        return _PyIO_NIBBLER_NO;
    }
    /* What was read ahead is there after the raw stream alone was closed
       (as with reads, and without the lock); more is not. */
    int r = 0;
    if (nibbler_unread(&self->nib) < need
        && buffered_check_closed(self, TEXT_CLOSED) < 0)
    {
        r = -1;
    }
    /* Until there are enough: fewer means the end of the stream.  (Other
       threads may have taken bytes while this one waited for the lock, so
       one fill may not do.) */
    while (r == 0 && nibbler_unread(&self->nib) < need) {
        if (self->nib.capacity == 0
            || need > TEXT_PEEK_MAX(self->nib.capacity))
        {
            /* Unbuffered, or more than a block may grow to. */
            r = _PyIO_NIBBLER_FULL;
            break;
        }
        Py_ssize_t n = buffered_fill(self, 0);
        if (n == 0) {
            break;
        }
        r = n == -1 ? -1 : n == WOULD_BLOCK ? _PyIO_NIBBLER_BLOCKED : 0;
    }
    Py_ssize_t unread = nibbler_unread(&self->nib);
    if (r >= 0 && unread > 0) {
        *m = (morsel){Py_NewRef(self->nib.end->block),
                      nibbler_unread_ptr(&self->nib), unread};
        *key = self->nib.end->id;
    }
    buffered_leave(self);
    return r;
}

int
_PyIONibbler_peek(PyObject *op, Py_ssize_t need, _PyIO_Morsel *m,
                  uint64_t *key)
{
    buffered *self = buffered_cast(op);
    assert(_PyIO_is_nibbler_buffered_type(Py_TYPE(op)) && need > 0);
    *m = (morsel){NULL, NULL, 0};
    if (buffered_dict(self) != NULL) {
        return _PyIO_NIBBLER_NO;
    }
    /* Without the lock, at the reading end's position.  (close() drops
       it; after the raw stream alone was closed, what was read ahead can
       still be read, as with read().) */
    nibbler_end *e = nibbler_end_get(&self->nib, 0);
    Py_ssize_t c = e == NULL ? -1 : FT_ATOMIC_LOAD_SSIZE_RELAXED(e->pos);
    Py_ssize_t limit = c < 0 ? 0 : nibbler_end_limit(e);
    if (c >= 0 && limit - c >= need) {
        *m = (morsel){Py_NewRef(e->block), PyBytes_AS_STRING(e->block) + c,
                      limit - c};
        *key = e->id;
        return 0;
    }
    return buffered_text_peek_locked(self, need, m, key);
}

/* advance with the lock: out of line, so that the lock-free path stays
   small. */
Py_NO_INLINE static int
buffered_text_advance_locked(buffered *self, uint64_t key, Py_ssize_t off,
                             Py_ssize_t n, char *copy)
{
    /* The caller's reference may be borrowed, and other threads run while
       this waits for the lock. */
    Py_INCREF(self);
    int r = buffered_lock(self);
    if (r == 0 && buffered_dict(self) != NULL) {
        /* Got a dict while this waited. */
        buffered_unlock(self);
        r = _PyIO_NIBBLER_NO;
    }
    else if (r == 0) {
        /* Bytes peeked are there after the raw stream alone was closed
           (see buffered_text_peek_locked()). */
        nibbler_end *e = nibbler_reading(&self->nib);
        if (e != NULL && e->id == key
            && nibbler_reading_pos(e) == off
            && nibbler_unread(&self->nib) >= n)
        {
            if (copy != NULL) {
                memcpy(copy, nibbler_unread_ptr(&self->nib), n);
            }
            nibbler_skip(&self->nib, n);
            r = 1;
        }
        buffered_unlock(self);
    }
    Py_DECREF(self);
    return r;
}

static inline int
buffered_text_advance(PyObject *op, uint64_t key, Py_ssize_t off,
                      Py_ssize_t n, char *copy)
{
    buffered *self = buffered_cast(op);
    /* Once it has a dict, its methods may be in use: then the bytes at its
       position may not be next any more. */
    if (buffered_dict(self) != NULL) {
        return _PyIO_NIBBLER_NO;
    }
    /* Without the lock: move the reading end's position from off, if it
       is still there (see _PyIONibbler_peek()). */
    nibbler_end *e = nibbler_end_get(&self->nib, 0);
    if (e != NULL && e->id == key && n <= nibbler_end_limit(e) - off) {
        Py_ssize_t c = off;
        if (FT_ATOMIC_COMPARE_EXCHANGE_SSIZE(e->pos, &c, off + n)) {
            if (copy != NULL) {
                /* Not written over before this thread waits (see
                   nibbler_fresh_block()). */
                memcpy(copy, PyBytes_AS_STRING(e->block) + off, n);
            }
            return 1;
        }
        if (c >= 0) {
            return 0;
        }
    }
    /* The end is held, or gone, or the raw stream must be asked. */
    return buffered_text_advance_locked(self, key, off, n, copy);
}

int
_PyIONibbler_advance(PyObject *op, uint64_t key, Py_ssize_t off,
                     Py_ssize_t n)
{
    return buffered_text_advance(op, key, off, n, NULL);
}

int
_PyIONibbler_take(PyObject *op, uint64_t key, Py_ssize_t off, Py_ssize_t n,
                  char *copy)
{
    return buffered_text_advance(op, key, off, n, copy);
}

int
_PyIONibbler_unread(PyObject *op, const char *data, Py_ssize_t len)
{
    buffered *self = buffered_cast(op);
    if (buffered_dict(self) != NULL) {
        return _PyIO_NIBBLER_NO;
    }
    /* The I/O role too, so that no fill is under way. */
    if (nibbler_lock_io(&self->nib, op) < 0) {
        return -1;
    }
    int r = 0;
    if (buffered_dict(self) != NULL) {
        r = _PyIO_NIBBLER_NO;
    }
    else if (buffered_raw_usable(self->raw) && !buffered_writing(self)
             && self->ngather == 0)
    {
        /* In front of the unread bytes (from a fresh block, as
           buffered_push_back() does).  Pending writes would be past
           them: then they are not kept. */
        Py_ssize_t unread = nibbler_unread(&self->nib);
        PyObject *block = PyBytes_FromStringAndSize(NULL, len + unread);
        if (block == NULL) {
            r = -1;
        }
        else {
            memcpy(PyBytes_AS_STRING(block), data, len);
            if (unread > 0) {
                memcpy(PyBytes_AS_STRING(block) + len,
                       nibbler_unread_ptr(&self->nib), unread);
            }
            r = nibbler_publish(&self->nib, block, len + unread) < 0 ? -1 : 1;
            Py_DECREF(block);
        }
    }
    buffered_leave(self);
    return r;
}

int
_PyIONibbler_write(PyObject *op, PyObject *obj, const char *data,
                   Py_ssize_t len)
{
    buffered *self = buffered_cast(op);
    assert(buffered_writable(self));
    if (buffered_dict(self) != NULL) {
        return _PyIO_NIBBLER_NO;
    }
    /* An exact FileIO is checked once the bytes are reserved; other raw
       streams, and writes that take the lock, first. */
    int fileio = FT_ATOMIC_LOAD_UINT8_RELAXED(self->raw_fileio);
    int r = (fileio && len < NIBBLER_REF_MIN
             ? buffered_write_lockfree(self, data, len, TEXT_CLOSED) : 0);
    if (r == 0 && (r = _PyIONibbler_closed(op)) > 0) {
        PyErr_SetString(PyExc_ValueError, TEXT_CLOSED);
        r = -1;
    }
    if (r == 0 && !fileio && len < NIBBLER_REF_MIN) {
        r = buffered_write_lockfree(self, data, len, TEXT_CLOSED);
    }
    if (r != 0) {
        return r < 0 ? -1 : 0;
    }
    /* The caller's reference is borrowed: raw.write() could drop it. */
    Py_INCREF(self);
    r = buffered_write_data(self, obj, data, len);
    Py_DECREF(self);
    return r;
}

char *
_PyIONibbler_reserve(PyObject *op, Py_ssize_t len, void **end, int *closed)
{
    buffered *self = buffered_cast(op);
    nibbler_end *e;
    Py_ssize_t r;
    /* Only over an exact FileIO (see _PyIONibbler_write()), which can only
       be looked at once the bytes are reserved: then raw and raw_fileio
       stay.  If it was closed by itself, the bytes are given back, unless
       others were reserved after them: then they are queued, as with
       write(), and can't be written out any more (*closed; see
       buffered_write_lockfree()). */
    if (buffered_dict(self) != NULL || len >= NIBBLER_REF_MIN
        || !FT_ATOMIC_LOAD_UINT8_RELAXED(self->raw_fileio)
        || (e = nibbler_end_get(&self->nib, 1)) == NULL
        || (r = nibbler_reserve(e, len)) < 0)
    {
        return NULL;
    }
    *closed = (FT_ATOMIC_LOAD_UINT8_RELAXED(self->raw_fileio)
               && _PyFileIO_closed(FT_ATOMIC_LOAD_PTR_RELAXED(self->raw)));
    if (*closed && nibbler_unreserve(e, r, len)) {
        return NULL;
    }
    *end = e;
    return PyBytes_AS_STRING(e->block) + r;
}

void
_PyIONibbler_commit(void *end, Py_ssize_t len)
{
    FT_ATOMIC_ADD_SSIZE(((nibbler_end *)end)->done, len);
}

Py_ssize_t
_PyIONibbler_capacity(PyObject *op)
{
    return FT_ATOMIC_LOAD_SSIZE_RELAXED(buffered_cast(op)->nib.capacity);
}

int
_PyIONibbler_closed(PyObject *op)
{
    buffered *self = buffered_cast(op);
    PyObject *raw = buffered_get_raw(self);
    if (raw == NULL) {
        return -1;
    }
    /* Without the lock: raw_fileio may be another raw stream's. */
    int r = buffered_ref_closed(raw);
    Py_DECREF(raw);
    return r;
}

/*
 * class BufferedRandom
 */

/*[clinic input]
_io.BufferedRandom.__init__
    raw: object
    buffer_size: object(c_default="NULL") = DEFAULT_BUFFER_SIZE

A buffered interface to random access streams.

The constructor creates a reader and writer for a seekable stream,
raw, given in the first argument. If the buffer_size is omitted it
defaults to DEFAULT_BUFFER_SIZE.  With buffer_size None, writes are
buffered without limit: they reach the raw stream only through flush(),
and operations that need it, such as close(), seek(), reads and
detach(); reads still fill blocks of DEFAULT_BUFFER_SIZE.
[clinic start generated code]*/

static int
_io_BufferedRandom___init___impl(buffered *self, PyObject *raw,
                                 PyObject *buffer_size)
/*[clinic end generated code: output=294b8035a5222c1c input=df212a8fc78925b5]*/
{
    return buffered_init_writer(self, raw, buffer_size, 1);
}

/*
 * BufferedRWPair
 */

/* XXX The usefulness of this (compared to having two separate IO objects) is
 * questionable.
 */

typedef struct {
    PyObject_HEAD
    buffered *reader;
    buffered *writer;
    PyObject *dict;
    PyObject *weakreflist;
} rwpair;

static inline rwpair *
rwpair_cast(PyObject *op)
{
    return (rwpair *)op;
}

/*[clinic input]
_io.BufferedRWPair.__init__
    reader: object
    writer: object
    buffer_size: Py_ssize_t(c_default="DEFAULT_BUFFER_SIZE") = DEFAULT_BUFFER_SIZE
    /

A buffered reader and writer object together.

A buffered reader object and buffered writer object put together to
form a sequential IO object that can read and write. This is typically
used with a socket or two-way pipe.

reader and writer are RawIOBase objects that are readable and
writeable respectively. If the buffer_size is omitted it defaults to
DEFAULT_BUFFER_SIZE.
[clinic start generated code]*/

static int
_io_BufferedRWPair___init___impl(rwpair *self, PyObject *reader,
                                 PyObject *writer, Py_ssize_t buffer_size)
/*[clinic end generated code: output=327e73d1aee8f984 input=620d42d71f33a031]*/
{
    _PyIO_State *state = find_io_state_by_def(Py_TYPE(self));
    nibblermodule_state *nstate =
        find_nibblermodule_state_by_def(Py_TYPE(self));
    if (_PyIOBase_check_readable(state, reader, Py_True) == NULL) {
        return -1;
    }
    if (_PyIOBase_check_writable(state, writer, Py_True) == NULL) {
        return -1;
    }

    self->reader = (buffered *)PyObject_CallFunction(
        (PyObject *)nstate->PyBufferedReader_Type, "On", reader,
        buffer_size);
    if (self->reader == NULL) {
        return -1;
    }

    self->writer = (buffered *)PyObject_CallFunction(
        (PyObject *)nstate->PyBufferedWriter_Type, "On", writer,
        buffer_size);
    if (self->writer == NULL) {
        Py_CLEAR(self->reader);
        return -1;
    }

    return 0;
}

static int
bufferedrwpair_traverse(PyObject *op, visitproc visit, void *arg)
{
    rwpair *self = rwpair_cast(op);
    Py_VISIT(Py_TYPE(self));
    Py_VISIT(self->dict);
    Py_VISIT(self->reader);
    Py_VISIT(self->writer);
    return 0;
}

static int
bufferedrwpair_clear(PyObject *op)
{
    rwpair *self = rwpair_cast(op);
    Py_CLEAR(self->reader);
    Py_CLEAR(self->writer);
    Py_CLEAR(self->dict);
    return 0;
}

static void
bufferedrwpair_dealloc(PyObject *op)
{
    rwpair *self = rwpair_cast(op);
    PyTypeObject *tp = Py_TYPE(self);
    _PyObject_GC_UNTRACK(self);
    FT_CLEAR_WEAKREFS(op, self->weakreflist);
    (void)bufferedrwpair_clear(op);
    tp->tp_free(self);
    Py_DECREF(tp);
}

/* Call the method of the underlying reader or writer.  The argument is
   only passed if it is not NULL, so that the default of that method is
   used otherwise. */
static PyObject *
rwpair_forward_call(buffered *self, PyObject *name, PyObject *arg)
{
    if (self == NULL) {
        PyErr_SetString(PyExc_ValueError,
                        "I/O operation on uninitialized object");
        return NULL;
    }

    if (arg == NULL) {
        return PyObject_CallMethodNoArgs((PyObject *)self, name);
    }
    return PyObject_CallMethodOneArg((PyObject *)self, name, arg);
}

/*[clinic input]
_io.BufferedRWPair.read
    size: object(c_default="NULL") = -1
    /
[clinic start generated code]*/

static PyObject *
_io_BufferedRWPair_read_impl(rwpair *self, PyObject *size)
/*[clinic end generated code: output=0668e3c5dbd3e93d input=eddb5e52aba9ebe5]*/
{
    return rwpair_forward_call(self->reader, &_Py_ID(read), size);
}

/*[clinic input]
_io.BufferedRWPair.readall
[clinic start generated code]*/

static PyObject *
_io_BufferedRWPair_readall_impl(rwpair *self)
/*[clinic end generated code: output=34f8123873a98737 input=815cdbaf5b6079fe]*/
{
    return rwpair_forward_call(self->reader, &_Py_ID(readall), NULL);
}

/*[clinic input]
_io.BufferedRWPair.peek
    size: object(c_default="NULL") = 0
    /
[clinic start generated code]*/

static PyObject *
_io_BufferedRWPair_peek_impl(rwpair *self, PyObject *size)
/*[clinic end generated code: output=190a267bd694efa0 input=36af95964bebe355]*/
{
    return rwpair_forward_call(self->reader, &_Py_ID(peek), size);
}

/*[clinic input]
_io.BufferedRWPair.readline
    size: object(c_default="NULL") = -1
    /
[clinic start generated code]*/

static PyObject *
_io_BufferedRWPair_readline_impl(rwpair *self, PyObject *size)
/*[clinic end generated code: output=ee5bb2364231e6e1 input=d29b33e6efa2f69e]*/
{
    /* The reader's, which can keep a partial line for the next call. */
    return rwpair_forward_call(self->reader, &_Py_ID(readline), size);
}

/*[clinic input]
_io.BufferedRWPair.read1
    size: object(c_default="NULL") = -1
    /
[clinic start generated code]*/

static PyObject *
_io_BufferedRWPair_read1_impl(rwpair *self, PyObject *size)
/*[clinic end generated code: output=17ec19608f2bb825 input=9e94db423e490b58]*/
{
    return rwpair_forward_call(self->reader, &_Py_ID(read1), size);
}

/*[clinic input]
_io.BufferedRWPair.readinto
    buffer: object
    /
[clinic start generated code]*/

static PyObject *
_io_BufferedRWPair_readinto_impl(rwpair *self, PyObject *buffer)
/*[clinic end generated code: output=16c86b071015f7a4 input=ccd86ce2666261f7]*/
{
    return rwpair_forward_call(self->reader, &_Py_ID(readinto), buffer);
}

/*[clinic input]
_io.BufferedRWPair.readinto1
    buffer: object
    /
[clinic start generated code]*/

static PyObject *
_io_BufferedRWPair_readinto1_impl(rwpair *self, PyObject *buffer)
/*[clinic end generated code: output=f1577b6f54c2b02a input=613d9bf127f88a4a]*/
{
    return rwpair_forward_call(self->reader, &_Py_ID(readinto1), buffer);
}

/*[clinic input]
_io.BufferedRWPair.write
    buffer: object
    /
[clinic start generated code]*/

static PyObject *
_io_BufferedRWPair_write_impl(rwpair *self, PyObject *buffer)
/*[clinic end generated code: output=6f7509a747410c68 input=66c602422e3ec36f]*/
{
    return rwpair_forward_call(self->writer, &_Py_ID(write), buffer);
}

/*[clinic input]
_io.BufferedRWPair.flush
[clinic start generated code]*/

static PyObject *
_io_BufferedRWPair_flush_impl(rwpair *self)
/*[clinic end generated code: output=0b2dcbe828718d6b input=e853da796ee61df1]*/
{
    return rwpair_forward_call(self->writer, &_Py_ID(flush), NULL);
}

/*[clinic input]
_io.BufferedRWPair._discard_writes

Drop the writer's pending writes; return how many bytes they were.
[clinic start generated code]*/

static PyObject *
_io_BufferedRWPair__discard_writes_impl(rwpair *self)
/*[clinic end generated code: output=aa59aa3f077b7fff input=ced7594605661a68]*/
{
    /* For TextIOWrapper.close() over the pair, as over a BufferedWriter. */
    return rwpair_forward_call(self->writer, &_Py_ID(_discard_writes), NULL);
}

/*[clinic input]
_io.BufferedRWPair.readable
[clinic start generated code]*/

static PyObject *
_io_BufferedRWPair_readable_impl(rwpair *self)
/*[clinic end generated code: output=615967d4aa58f122 input=0475ed73d0a3167f]*/
{
    return rwpair_forward_call(self->reader, &_Py_ID(readable), NULL);
}

/*[clinic input]
_io.BufferedRWPair.writable
[clinic start generated code]*/

static PyObject *
_io_BufferedRWPair_writable_impl(rwpair *self)
/*[clinic end generated code: output=c5a43c84e0195c11 input=3cfd44fb4757082f]*/
{
    return rwpair_forward_call(self->writer, &_Py_ID(writable), NULL);
}

/*[clinic input]
_io.BufferedRWPair.close
[clinic start generated code]*/

static PyObject *
_io_BufferedRWPair_close_impl(rwpair *self)
/*[clinic end generated code: output=5924ba5ecc78752a input=4087d69f2d8fc368]*/
{
    PyObject *exc = NULL;
    PyObject *ret = rwpair_forward_call(self->writer, &_Py_ID(close), NULL);
    if (ret == NULL) {
        exc = PyErr_GetRaisedException();
    }
    else {
        Py_DECREF(ret);
    }
    ret = rwpair_forward_call(self->reader, &_Py_ID(close), NULL);
    if (exc != NULL) {
        _PyErr_ChainExceptions1(exc);
        Py_CLEAR(ret);
    }
    return ret;
}

/*[clinic input]
_io.BufferedRWPair.isatty
[clinic start generated code]*/

static PyObject *
_io_BufferedRWPair_isatty_impl(rwpair *self)
/*[clinic end generated code: output=d017c621ed879cb7 input=92833e3d60586e14]*/
{
    PyObject *ret = rwpair_forward_call(self->writer, &_Py_ID(isatty), NULL);

    if (ret != Py_False) {
        /* either True or exception */
        return ret;
    }
    Py_DECREF(ret);

    return rwpair_forward_call(self->reader, &_Py_ID(isatty), NULL);
}

/*[clinic input]
@getter
_io.BufferedRWPair.closed
[clinic start generated code]*/

static PyObject *
_io_BufferedRWPair_closed_get_impl(rwpair *self)
/*[clinic end generated code: output=4117400c74766f21 input=8248430ac54e5b25]*/
{
    if (self->writer == NULL) {
        PyErr_SetString(
            PyExc_RuntimeError,
            "the BufferedRWPair object is being garbage-collected");
        return NULL;
    }
    return PyObject_GetAttr((PyObject *)self->writer, &_Py_ID(closed));
}

#define clinic_state() (find_nibblermodule_state_by_def(Py_TYPE(self)))
#include "clinic/bufferedio.c.h"
#undef clinic_state

static PyMethodDef bufferedreader_methods[] = {
    /* BufferedIOMixin methods */
    _IO__BUFFERED_DETACH_METHODDEF
    _IO__BUFFERED_SIMPLE_FLUSH_METHODDEF
    _IO__BUFFERED_CLOSE_METHODDEF
    _IO__BUFFERED_SEEKABLE_METHODDEF
    _IO__BUFFERED_READABLE_METHODDEF
    _IO__BUFFERED_FILENO_METHODDEF
    _IO__BUFFERED_ISATTY_METHODDEF
    _IO__BUFFERED__DEALLOC_WARN_METHODDEF
    _IO__BUFFERED__DISCARD_WRITES_METHODDEF

    _IO__BUFFERED_READ_METHODDEF
    _IO__BUFFERED_READALL_METHODDEF
    _IO__BUFFERED_PEEK_METHODDEF
    _IO__BUFFERED_READ1_METHODDEF
    _IO__BUFFERED_READINTO_METHODDEF
    _IO__BUFFERED_READINTO1_METHODDEF
    _IO__BUFFERED_READLINE_METHODDEF
    _IO__BUFFERED_SEEK_METHODDEF
    _IO__BUFFERED_TELL_METHODDEF
    _IO__BUFFERED_TRUNCATE_METHODDEF
    _IO__BUFFERED___SIZEOF___METHODDEF

    {"__getstate__", _PyIOBase_cannot_pickle, METH_NOARGS},
    {NULL, NULL}
};

/* Shared by BufferedReader, BufferedWriter and BufferedRandom. */
static PyMemberDef buffered_members[] = {
    {"_finalizing", Py_T_BOOL, offsetof(buffered, finalizing), 0},
    {"__weaklistoffset__", Py_T_PYSSIZET,
     offsetof(buffered, weakreflist), Py_READONLY},
    {"__dictoffset__", Py_T_PYSSIZET, offsetof(buffered, dict), Py_READONLY},
    {NULL}
};

static PyGetSetDef buffered_getset[] = {
    {"raw", buffered_raw_get, NULL, NULL, NULL},
    _IO__BUFFERED_CLOSED_GETSETDEF
    _IO__BUFFERED_NAME_GETSETDEF
    _IO__BUFFERED_MODE_GETSETDEF
    {NULL}
};

static PyType_Slot bufferedreader_slots[] = {
    {Py_tp_dealloc, buffered_dealloc},
    {Py_tp_repr, buffered_repr},
    {Py_tp_doc, (void *)_io_BufferedReader___init____doc__},
    {Py_tp_traverse, buffered_traverse},
    {Py_tp_clear, buffered_clear},
    {Py_tp_iternext, buffered_iternext},
    {Py_tp_methods, bufferedreader_methods},
    {Py_tp_members, buffered_members},
    {Py_tp_getset, buffered_getset},
    {Py_tp_init, _io_BufferedReader___init__},
    {Py_tp_token, &nibbler_bufferedreader_spec},
    {0, NULL},
};

static PyType_Spec nibbler_bufferedreader_spec = {
    .name = "_io._nibbler.BufferedReader",
    .basicsize = sizeof(buffered),
    .flags = (Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC |
              Py_TPFLAGS_IMMUTABLETYPE),
    .slots = bufferedreader_slots,
};

static PyMethodDef bufferedwriter_methods[] = {
    /* BufferedIOMixin methods */
    _IO__BUFFERED_CLOSE_METHODDEF
    _IO__BUFFERED_DETACH_METHODDEF
    _IO__BUFFERED_SEEKABLE_METHODDEF
    _IO__BUFFERED_WRITABLE_METHODDEF
    _IO__BUFFERED_FILENO_METHODDEF
    _IO__BUFFERED_ISATTY_METHODDEF
    _IO__BUFFERED__DEALLOC_WARN_METHODDEF
    _IO__BUFFERED__DISCARD_WRITES_METHODDEF

    _IO_BUFFEREDWRITER_WRITE_METHODDEF
    _IO_BUFFEREDWRITER_READALL_METHODDEF
    _IO__BUFFERED__GATHER_METHODDEF
    _IO__BUFFERED_TRUNCATE_METHODDEF
    _IO__BUFFERED_FLUSH_METHODDEF
    _IO__BUFFERED_SEEK_METHODDEF
    _IO__BUFFERED_TELL_METHODDEF
    _IO__BUFFERED___SIZEOF___METHODDEF

    {"__getstate__", _PyIOBase_cannot_pickle, METH_NOARGS},
    {NULL, NULL}
};

static PyType_Slot bufferedwriter_slots[] = {
    {Py_tp_dealloc, buffered_dealloc},
    {Py_tp_repr, buffered_repr},
    {Py_tp_doc, (void *)_io_BufferedWriter___init____doc__},
    {Py_tp_traverse, buffered_traverse},
    {Py_tp_clear, buffered_clear},
    {Py_tp_methods, bufferedwriter_methods},
    {Py_tp_members, buffered_members},
    {Py_tp_getset, buffered_getset},
    {Py_tp_init, _io_BufferedWriter___init__},
    {Py_tp_token, &nibbler_bufferedwriter_spec},
    {0, NULL},
};

static PyType_Spec nibbler_bufferedwriter_spec = {
    .name = "_io._nibbler.BufferedWriter",
    .basicsize = sizeof(buffered),
    .flags = (Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC |
              Py_TPFLAGS_IMMUTABLETYPE),
    .slots = bufferedwriter_slots,
};

static PyMethodDef bufferedrwpair_methods[] = {
    _IO_BUFFEREDRWPAIR_READ_METHODDEF
    _IO_BUFFEREDRWPAIR_READALL_METHODDEF
    _IO_BUFFEREDRWPAIR_PEEK_METHODDEF
    _IO_BUFFEREDRWPAIR_READ1_METHODDEF
    _IO_BUFFEREDRWPAIR_READLINE_METHODDEF
    _IO_BUFFEREDRWPAIR_READINTO_METHODDEF
    _IO_BUFFEREDRWPAIR_READINTO1_METHODDEF

    _IO_BUFFEREDRWPAIR_WRITE_METHODDEF
    _IO_BUFFEREDRWPAIR_FLUSH_METHODDEF
    _IO_BUFFEREDRWPAIR__DISCARD_WRITES_METHODDEF

    _IO_BUFFEREDRWPAIR_READABLE_METHODDEF
    _IO_BUFFEREDRWPAIR_WRITABLE_METHODDEF

    _IO_BUFFEREDRWPAIR_CLOSE_METHODDEF
    _IO_BUFFEREDRWPAIR_ISATTY_METHODDEF

    {NULL, NULL}
};

static PyMemberDef bufferedrwpair_members[] = {
    {"__weaklistoffset__", Py_T_PYSSIZET, offsetof(rwpair, weakreflist),
     Py_READONLY},
    {"__dictoffset__", Py_T_PYSSIZET, offsetof(rwpair, dict), Py_READONLY},
    {NULL}
};

static PyGetSetDef bufferedrwpair_getset[] = {
    _IO_BUFFEREDRWPAIR_CLOSED_GETSETDEF
    {NULL}
};

static PyType_Slot bufferedrwpair_slots[] = {
    {Py_tp_dealloc, bufferedrwpair_dealloc},
    {Py_tp_doc, (void *)_io_BufferedRWPair___init____doc__},
    {Py_tp_traverse, bufferedrwpair_traverse},
    {Py_tp_clear, bufferedrwpair_clear},
    {Py_tp_methods, bufferedrwpair_methods},
    {Py_tp_members, bufferedrwpair_members},
    {Py_tp_getset, bufferedrwpair_getset},
    {Py_tp_init, _io_BufferedRWPair___init__},
    {0, NULL},
};

static PyType_Spec nibbler_bufferedrwpair_spec = {
    .name = "_io._nibbler.BufferedRWPair",
    .basicsize = sizeof(rwpair),
    .flags = (Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC |
              Py_TPFLAGS_IMMUTABLETYPE),
    .slots = bufferedrwpair_slots,
};

static PyMethodDef bufferedrandom_methods[] = {
    /* BufferedIOMixin methods */
    _IO__BUFFERED_CLOSE_METHODDEF
    _IO__BUFFERED_DETACH_METHODDEF
    _IO__BUFFERED_SEEKABLE_METHODDEF
    _IO__BUFFERED_READABLE_METHODDEF
    _IO__BUFFERED_WRITABLE_METHODDEF
    _IO__BUFFERED_FILENO_METHODDEF
    _IO__BUFFERED_ISATTY_METHODDEF
    _IO__BUFFERED__DEALLOC_WARN_METHODDEF
    _IO__BUFFERED__DISCARD_WRITES_METHODDEF

    _IO__BUFFERED_FLUSH_METHODDEF

    _IO__BUFFERED_SEEK_METHODDEF
    _IO__BUFFERED_TELL_METHODDEF
    _IO__BUFFERED_TRUNCATE_METHODDEF
    _IO__BUFFERED_READ_METHODDEF
    _IO__BUFFERED_READALL_METHODDEF
    _IO__BUFFERED_READ1_METHODDEF
    _IO__BUFFERED_READINTO_METHODDEF
    _IO__BUFFERED_READINTO1_METHODDEF
    _IO__BUFFERED_READLINE_METHODDEF
    _IO__BUFFERED_PEEK_METHODDEF
    _IO_BUFFEREDWRITER_WRITE_METHODDEF
    _IO__BUFFERED__GATHER_METHODDEF
    _IO__BUFFERED___SIZEOF___METHODDEF

    {"__getstate__", _PyIOBase_cannot_pickle, METH_NOARGS},
    {NULL, NULL}
};

static PyType_Slot bufferedrandom_slots[] = {
    {Py_tp_dealloc, buffered_dealloc},
    {Py_tp_repr, buffered_repr},
    {Py_tp_doc, (void *)_io_BufferedRandom___init____doc__},
    {Py_tp_traverse, buffered_traverse},
    {Py_tp_clear, buffered_clear},
    {Py_tp_iternext, buffered_iternext},
    {Py_tp_methods, bufferedrandom_methods},
    {Py_tp_members, buffered_members},
    {Py_tp_getset, buffered_getset},
    {Py_tp_init, _io_BufferedRandom___init__},
    {Py_tp_token, &nibbler_bufferedrandom_spec},
    {0, NULL},
};

static PyType_Spec nibbler_bufferedrandom_spec = {
    .name = "_io._nibbler.BufferedRandom",
    .basicsize = sizeof(buffered),
    .flags = (Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC |
              Py_TPFLAGS_IMMUTABLETYPE),
    .slots = bufferedrandom_slots,
};

/* Is tp exactly _io._nibbler.BufferedReader, BufferedWriter or
   BufferedRandom (not a subclass)?  Lets TextIOWrapper apply the same
   fast paths it uses for the _io buffered classes. */
int
_PyIO_is_nibbler_buffered_type(PyTypeObject *tp)
{
    if (!_PyType_HasFeature(tp, Py_TPFLAGS_HEAPTYPE)) {
        return 0;
    }
    void *token = ((PyHeapTypeObject *)tp)->ht_token;
    return (token == &nibbler_bufferedreader_spec ||
            token == &nibbler_bufferedwriter_spec ||
            token == &nibbler_bufferedrandom_spec);
}

/* _io._nibbler submodule: GC, definition, and runtime creation. */

static int
nibblermodule_traverse(PyObject *mod, visitproc visit, void *arg)
{
    nibblermodule_state *state = get_nibblermodule_state(mod);
    Py_VISIT(state->PyBufferedIOBase_Type);
    Py_VISIT(state->PyBufferedReader_Type);
    Py_VISIT(state->PyBufferedWriter_Type);
    Py_VISIT(state->PyBufferedRandom_Type);
    Py_VISIT(state->PyBufferedRWPair_Type);
    Py_VISIT(state->PyTextIOWrapper_Type);
    Py_VISIT(state->Gather_Type);
    return 0;
}

static int
nibblermodule_clear(PyObject *mod)
{
    nibblermodule_state *state = get_nibblermodule_state(mod);
    Py_CLEAR(state->PyBufferedIOBase_Type);
    Py_CLEAR(state->PyBufferedReader_Type);
    Py_CLEAR(state->PyBufferedWriter_Type);
    Py_CLEAR(state->PyBufferedRandom_Type);
    Py_CLEAR(state->PyBufferedRWPair_Type);
    Py_CLEAR(state->PyTextIOWrapper_Type);
    Py_CLEAR(state->Gather_Type);
    return 0;
}

static void
nibblermodule_free(void *mod)
{
    (void)nibblermodule_clear((PyObject *)mod);
}

static struct PyModuleDef _PyIO_nibbler_Module = {
    .m_base = PyModuleDef_HEAD_INIT,
    .m_name = "_io._nibbler",
    .m_doc = "Buffered and text I/O classes mirroring _io, as an _io "
             "submodule.",
    .m_size = sizeof(nibblermodule_state),
    .m_traverse = nibblermodule_traverse,
    .m_clear = nibblermodule_clear,
    .m_free = nibblermodule_free,
};

/* Create a type from spec with base, named prefix + its class name, and
   add it to mod.  The class attribute _is_nibbler (True) tells tests these
   classes from _io's, also when they replace them.  With keeps_read, the
   class attribute _keeps_read_on_error (True) says that data read before
   a raw read raised (such as a socket timeout) is kept for the next read,
   so that reading can go on (socket.makefile() looks at it).  Returns a
   new reference, or NULL on error. */
static PyTypeObject *
nibbler_add_type(PyObject *mod, const PyType_Spec *spec, PyTypeObject *base,
                 const char *prefix, int keeps_read)
{
    const char *cls = strrchr(spec->name, '.');
    assert(cls != NULL);
    char name[64];
    PyType_Spec named = *spec;
    PyOS_snprintf(name, sizeof(name), "%s%s", prefix, cls + 1);
    named.name = name;  /* copied by PyType_FromModuleAndSpec() */
    PyTypeObject *type = (PyTypeObject *)PyType_FromModuleAndSpec(
        mod, &named, (PyObject *)base);
    if (type == NULL) {
        return NULL;
    }
    PyObject *dict = _PyType_GetDict(type);
    if (PyDict_SetItemString(dict, "_is_nibbler", Py_True) < 0
        || (keeps_read
            && PyDict_SetItemString(dict, "_keeps_read_on_error",
                                    Py_True) < 0))
    {
        Py_DECREF(type);
        return NULL;
    }
    PyType_Modified(type);
    if (PyModule_AddType(mod, type) < 0) {
        Py_DECREF(type);
        return NULL;
    }
    return type;
}

/* Create _io._nibbler, register its types, add it to sys.modules and to _io.
   With as_io, the types are named like _io's own ("_io.BufferedReader"),
   for when they replace them.  Returns a borrowed reference, or NULL on
   error. */
PyObject *
_PyIO_create_nibbler_submodule(PyObject *io_module, int as_io)
{
    _PyIO_State *io_state = get_io_state(io_module);

    PyObject *mod = PyModule_Create(&_PyIO_nibbler_Module);
    if (mod == NULL) {
        return NULL;
    }
    nibblermodule_state *state = get_nibblermodule_state(mod);

    const char *prefix = as_io ? "_io." : "_io._nibbler.";
    PyTypeObject *base = io_state->PyBufferedIOBase_Type;
    state->PyBufferedIOBase_Type = (PyTypeObject *)Py_NewRef(base);
    if ((state->PyBufferedReader_Type = nibbler_add_type(
             mod, &nibbler_bufferedreader_spec, base, prefix, 1)) == NULL
        || (state->PyBufferedWriter_Type = nibbler_add_type(
             mod, &nibbler_bufferedwriter_spec, base, prefix, 0)) == NULL
        || (state->PyBufferedRWPair_Type = nibbler_add_type(
             mod, &nibbler_bufferedrwpair_spec, base, prefix, 1)) == NULL
        || (state->PyBufferedRandom_Type = nibbler_add_type(
             mod, &nibbler_bufferedrandom_spec, base, prefix, 1)) == NULL
        || (state->PyTextIOWrapper_Type = nibbler_add_type(
             mod, &_PyIONibbler_textiowrapper_spec,
             io_state->PyTextIOBase_Type, prefix, 0)) == NULL)
    {
        Py_DECREF(mod);
        return NULL;
    }

    state->Gather_Type = (PyTypeObject *)PyType_FromModuleAndSpec(
        mod, &gather_spec, NULL);
    if (state->Gather_Type == NULL) {
        Py_DECREF(mod);
        return NULL;
    }

    /* For _PyIO_AfterForkChild(). */
    if (PyState_AddModule(mod, &_PyIO_nibbler_Module) < 0) {
        Py_DECREF(mod);
        return NULL;
    }

    if (_PyImport_SetModuleString("_io._nibbler", mod) < 0) {
        Py_DECREF(mod);
        return NULL;
    }

    if (PyModule_AddObjectRef(io_module, "_nibbler", mod) < 0) {
        Py_DECREF(mod);
        return NULL;
    }
    Py_DECREF(mod);
    return mod;
}


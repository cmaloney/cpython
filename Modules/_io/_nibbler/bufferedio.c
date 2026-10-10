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

#include "_iomodule.h"
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

/* Per-module state: the five buffered types. */
typedef struct {
    PyTypeObject *PyBufferedIOBase_Type;
    PyTypeObject *PyBufferedReader_Type;
    PyTypeObject *PyBufferedWriter_Type;
    PyTypeObject *PyBufferedRandom_Type;
    PyTypeObject *PyBufferedRWPair_Type;
    /* Gathered writes (see "Gathering" below). */
    PyTypeObject *Gather_Type;
    PyObject *gather_var;
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
 *   read window.  write() and
 *   flush() write them out together (in one call when the raw stream has a
 *   vectored _writev() method) with the I/O role, without holding the
 *   lock; meanwhile other threads can only queue more writes.  Small
 *   writes that fit are queued without the lock (see "The open end" in
 *   nibbler.h), so all code holding the lock sees them queued.  They
 *   check that an exact FileIO is open; other raw streams are asked with
 *   the lock, and once one says it is closed the open end is dropped, so
 *   that writes take the lock and raise (closing through the buffered
 *   object drops it too).
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
 * after a raw read raised (see buffered_unread()), which reads, and peek(),
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
 * is what a gather() block (see "Gathering") without a limit does, for all
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
       only set for writers). */
    uint8_t raw_fileio;
    uint8_t raw_vectored;
    uint8_t raw_appending;
    /* How many gather() blocks are active on it, in any context (changed
       atomically): while there are some, there is no writing end, so that
       every write takes the lock and looks at the context. */
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
       not be put in it without a large allocation (see buffered_stash()):
       a list of bytes objects, the first from offset stash_pos, `stashed`
       bytes in all; or NULL.  Raw reads take from it first, so it is read
       like the raw stream's own data.  Set only while reading. */
    PyObject *stash;
    Py_ssize_t stash_pos;
    Py_ssize_t stashed;

    PyObject *dict;
    PyObject *weakreflist;
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

/* Returns 0 with the lock held, or -1 with it released. */
static inline int
buffered_wait_io(buffered *self)
{
    return (nibbler_io_busy(&self->nib)
            ? nibbler_wait_io(&self->nib, (PyObject *)self) : 0);
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

/* Are there pending writes, or is another thread writing them out?  Then
   there is no read-ahead. */
static inline int
buffered_writing(buffered *self)
{
    return (nibbler_reading(&self->nib) == NULL
            && (nibbler_nbytes(&self->nib) > 0
                || nibbler_io_busy(&self->nib)));
}

/* Is it reading: is there a reading end (perhaps all read), or stashed
   data?  Then the raw position is past the logical one. */
static inline int
buffered_reading(buffered *self)
{
    return nibbler_reading(&self->nib) != NULL || self->stash != NULL;
}

/* Drop the stashed data.  Returns how many bytes it had. */
static Py_ssize_t
buffered_drop_stash(buffered *self)
{
    Py_ssize_t n = self->stashed;
    Py_CLEAR(self->stash);
    self->stash_pos = 0;
    self->stashed = 0;
    return n;
}

/* Keep the bytes objects of chunks (a list, which is stolen), data the
   raw stream returned, after the stashed data for the next reads.  Returns
   0, or -1 on error (then they are lost). */
static int
buffered_stash_list(buffered *self, PyObject *chunks)
{
    Py_ssize_t total = 0;
    for (Py_ssize_t i = 0; i < PyList_GET_SIZE(chunks); i++) {
        total += PyBytes_GET_SIZE(PyList_GET_ITEM(chunks, i));
    }
    if (self->stash == NULL) {
        self->stash = chunks;
    }
    else {
        Py_ssize_t end = PyList_GET_SIZE(self->stash);
        int r = PyList_SetSlice(self->stash, end, end, chunks);
        Py_DECREF(chunks);
        if (r < 0) {
            return -1;
        }
    }
    self->stashed += total;
    return 0;
}

/* Keep obj (non-empty bytes), data the raw stream returned, like
   buffered_stash_list(). */
static int
buffered_stash(buffered *self, PyObject *obj)
{
    PyObject *chunks = PyList_New(1);
    if (chunks == NULL) {
        return -1;
    }
    PyList_SET_ITEM(chunks, 0, Py_NewRef(obj));
    return buffered_stash_list(self, chunks);
}

/* Take up to len stashed bytes, copying them to dst.  Returns how many. */
static Py_ssize_t
buffered_take_stash(buffered *self, char *dst, Py_ssize_t len)
{
    Py_ssize_t done = 0;
    while (done < len && self->stash != NULL) {
        PyObject *b = PyList_GET_ITEM(self->stash, 0);
        Py_ssize_t k = Py_MIN(PyBytes_GET_SIZE(b) - self->stash_pos,
                              len - done);
        memcpy(dst + done, PyBytes_AS_STRING(b) + self->stash_pos, k);
        done += k;
        self->stash_pos += k;
        self->stashed -= k;
        if (self->stash_pos == PyBytes_GET_SIZE(b)) {
            self->stash_pos = 0;
            if (PyList_GET_SIZE(self->stash) == 1) {
                Py_CLEAR(self->stash);
            }
            else {
                /* Deleting one item needs no memory. */
                (void)PyList_SetSlice(self->stash, 0, 1, NULL);
            }
        }
    }
    return done;
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
buffered_ref_closed(buffered *self, PyObject *raw)
{
    _PyIO_State *state = find_io_state_by_def(Py_TYPE(self));
    return buffered_raw_closed(raw, Py_IS_TYPE(raw, state->PyFileIO_Type));
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

/* Convert the result of a raw readinto(), write() or _writev() of up to len
   bytes: the count, -2 for None ("would block"), or -1 on error. */
static Py_ssize_t
buffered_raw_result(PyObject *res, Py_ssize_t len, const char *method)
{
    if (res == NULL) {
        return -1;
    }
    if (res == Py_None) {
        Py_DECREF(res);
        return -2;
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

/* Python code had view (see buffered_owned_view()): release it, so that
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
   inside owner: a bytes object of ours, or the object whose buffer the
   caller passed (whose export the view holds, so that a view made from it
   keeps that memory valid like any other).  Without owner, the memory must
   stay valid otherwise. */
static PyObject *
buffered_owned_view(char *mem, Py_ssize_t len, int flags, PyObject *owner)
{
    PyObject *view = PyMemoryView_FromMemory(mem, len, flags);
    if (view == NULL || owner == NULL) {
        return view;
    }
    PyMemoryViewObject *mv = (PyMemoryViewObject *)view;
    Py_buffer *master = &mv->mbuf->master;
    if (PyBytes_CheckExact(owner)) {
        /* Released with the managed buffer; bytes have no
           bf_releasebuffer. */
        master->obj = Py_NewRef(owner);
        return view;
    }
    /* The view keeps its own shape; the managed buffer releases the export
       when the last view made from it goes. */
    Py_buffer whole;
    if (PyObject_GetBuffer(owner, &whole, PyBUF_WRITABLE) < 0) {
        Py_DECREF(view);
        return NULL;
    }
    char *start = whole.buf;
    if (mem < start || mem + len > start + whole.len) {
        /* Not the memory the caller passed after all. */
        PyBuffer_Release(&whole);
        return view;
    }
    *master = whole;
    mv->view.obj = owner;
    return view;
}

/* One raw readinto() of up to len bytes at dst, inside owner (see
   buffered_owned_view()).  Returns the count (0 at EOF), -2 if the raw
   stream would block, or -1 on error.  Sets *shared if Python code can
   still reach the memory (see buffered_release_view()). */
static Py_ssize_t
buffered_raw_read(buffered *self, char *dst, Py_ssize_t len, PyObject *owner,
                  int *shared)
{
    if (self->stash != NULL) {
        /* Data the raw stream returned already. */
        return buffered_take_stash(self, dst, len);
    }
    if (self->raw_fileio) {
        return _PyFileIO_readinto(self->raw, dst, len);
    }
    assert(owner != NULL);
    PyObject *view = buffered_owned_view(dst, len, PyBUF_WRITE, owner);
    if (view == NULL) {
        return -1;
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

/* A read-only memoryview of the morsel, which keeps its bytes alive; or,
   without obj (data of the current write() call), of memory only valid
   during the call. */
static PyObject *
buffered_view(const morsel *m)
{
    if (m->obj == NULL) {
        return PyMemoryView_FromMemory((char *)m->ptr, m->len, PyBUF_READ);
    }
    PyObject *whole = PyMemoryView_FromObject(m->obj);
    if (whole == NULL) {
        return NULL;
    }
    Py_ssize_t start = m->ptr - PyBytes_AS_STRING(m->obj);
    PyObject *view = PySequence_GetSlice(whole, start, start + m->len);
    Py_DECREF(whole);
    return view;
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
   are inside objs[0:cnt] (NULL: data of the current write() call, only
   valid during it): one vectored write to an exact FileIO; else write() of
   one span, or _writev() of memoryviews of them when the raw stream has it.
   Returns the count, -2 if the raw stream would block (errno set for the
   BlockingIOError), or -1 on error. */
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
    /* Views of the data of the current write() call have no exporter:
       release them, so that they give no access to it later.  (The others
       keep their bytes alive.) */
    if (cnt == 1) {
        if (objs[0] == NULL) {
            (void)buffered_release_view(arg);
        }
        else {
            Py_DECREF(arg);
        }
    }
    else {
        for (Py_ssize_t i = 0; i < cnt; i++) {
            if (objs[i] == NULL) {
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

static Py_off_t
buffered_raw_tell(buffered *self)
{
    return buffered_raw_offset(
        PyObject_CallMethodNoArgs(self->raw, &_Py_ID(tell)));
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
    return buffered_raw_offset(res);
}

/* The logical position: the raw one adjusted for what is buffered, and
   for `gathered` bytes still to come (see "Gathering"). */
static PyObject *
buffered_position(buffered *self, Py_ssize_t gathered)
{
    Py_off_t pos = buffered_raw_tell(self);
    if (pos == -1) {
        return NULL;
    }
    Py_ssize_t k = nibbler_nbytes(&self->nib);
    /* Gathered writes hand back read-ahead first; stashed data (only
       while reading) was read from the raw stream too. */
    pos += ((nibbler_reading(&self->nib) != NULL ? -k : k) - self->stashed
            + gathered);
    // GH-95782
    return PyLong_FromOff_t(pos < 0 ? 0 : pos);
}

/*
 * Writing
 */

/* Add data[0:len], owned by obj, to the pending writes, which must have
   room for it. */
static int
buffered_add_write(buffered *self, PyObject *obj, const char *data,
                   Py_ssize_t len)
{
    assert(nibbler_reading(&self->nib) == NULL);
    assert(nibbler_nbytes(&self->nib) + len <= self->nib.threshold);
    return nibbler_append(&self->nib, obj, data, len, self->raw_vectored);
}

/* How a write out stopped: everything written, the raw stream would
   block, or an error. */
enum {
    WRITE_DONE = 0,
    WRITE_BLOCKED = 1,
    WRITE_ERROR = -1,
};

/* Write spans[0:cnt] (total bytes, inside objs, see buffered_raw_writev())
   to the raw stream, with unlocked without the lock, retrying partial
   writes (advancing spans) until all of them are written, the raw stream
   would block or an error is raised: returns WRITE_DONE, WRITE_BLOCKED or
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
            st = r == -2 ? WRITE_BLOCKED : WRITE_ERROR;
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
    *written = done;
    return st;
}

/* buffered_write_out() with writes pending: in batches of as many pieces
   (morsels, then data) as one raw call takes, each gathered with the lock,
   written, and dropped once written.  Out of line, so that writing data
   with nothing pending stays small. */
Py_NO_INLINE static int
buffered_write_batches(buffered *self, Py_ssize_t target, const char *data,
                       Py_ssize_t len, int unlocked, Py_ssize_t *done)
{
    nibbler *n = &self->nib;
    _PyIO_Span stack_spans[_PyIO_WRITEV_MAX];
    PyObject *stack_objs[_PyIO_WRITEV_MAX];
    _PyIO_Span *spans = stack_spans;
    PyObject **objs = stack_objs;
    Py_ssize_t limit = self->raw_vectored ? _PyIO_WRITEV_MAX : 1;
    int st = WRITE_DONE;
    if (_PyIO_WRITEV_LONG > _PyIO_WRITEV_MAX && self->raw_vectored
        && self->raw_fileio && n->list.count >= _PyIO_WRITEV_MAX)
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
           references of their own (see nibbler_lock_wait()); while this
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
            objs[cnt++] = NULL;
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
   data[0:len] until all of it is written, the raw stream would block or
   an error is raised; *status says which.  Written bytes are dropped as
   they go, so on error the unwritten rest is still pending.  With
   unlocked, the lock is released around the raw calls; other threads can
   then only queue more writes, which are left pending.  Returns how much
   of data was written, also on error.  With nothing pending (as when
   writing without buffering), data goes out as one span. */
static Py_ssize_t
buffered_write_out(buffered *self, Py_ssize_t target, const char *data,
                   Py_ssize_t len, int *status, int unlocked)
{
    Py_ssize_t done = 0;
    int st = WRITE_DONE;
    nibbler_begin_io(&self->nib);
    if (target > 0) {
        st = buffered_write_batches(self, target, data, len, unlocked,
                                    &done);
    }
    else if (len > 0) {
        _PyIO_Span span = {data, len};
        PyObject *obj = NULL;
        st = buffered_write_spans(self, &span, &obj, 1, len, unlocked,
                                  &done);
    }
    nibbler_end_io(&self->nib);
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
    (void)buffered_write_out(self, nibbler_nbytes(&self->nib), NULL, 0,
                             &status, unlocked);
    if (status == WRITE_BLOCKED) {
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

static void buffered_unread(buffered *self, const char *data, Py_ssize_t len);

/* Can a raw read write into the free tail of block, the reading end's,
   after the unread bytes?  Nothing was handed out from there, but Python
   code must not be able to reach the bytes object itself: only a raw
   stream given views of it can (through their obj), and then it has more
   references than ours (the unread morsel's, the end's and maybe the
   nibbler's). */
static int
buffered_block_private(buffered *self, PyObject *block)
{
    if (self->raw_fileio) {
        return 1;
    }
    Py_ssize_t ours = 2 + (self->nib.block == block);
    return Py_REFCNT(block) <= ours;
}

/* buffered_fill() into the free tail of the reading end's block. */
static Py_ssize_t
buffered_fill_tail(buffered *self, Py_ssize_t room)
{
    nibbler_end *e = nibbler_reading(&self->nib);
    /* The read holds its own reference while it uses the block (see
       nibbler_lock_wait()). */
    PyObject *block = Py_NewRef(e->block);
    char *start = (char *)self->nib.list.items[0].ptr;
    Py_ssize_t unread = self->nib.list.items[0].len;
    int shared = 0;
    Py_ssize_t n = buffered_raw_read(self, start + unread, room, block,
                                     &shared);
    if (n > 0 && !shared) {
        nibbler_extend(&self->nib, n);
    }
    else if (shared) {
        /* Python code can still write to the block: abandon it to that
           code, and keep a copy of what is unread. */
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
   at EOF), -2 if the raw stream would block, or -1 on error. */
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
        keep = n->list.items[0];
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
       nibbler_lock_wait()). */
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
    }
    else if (keep.len > 0) {
        /* Keep the unread bytes. */
        PyObject *exc = PyErr_GetRaisedException();
        buffered_unread(self, keep.ptr, keep.len);
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
buffered_unread(buffered *self, const char *data, Py_ssize_t len)
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
   the read-ahead once there is data to return.  Returns the count, -2 if
   the raw stream would block before anything was read, or -1 on error. */
static Py_ssize_t
buffered_read_into(buffered *self, char *dst, Py_ssize_t len, int read1,
                   PyObject *owner, int *shared)
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
            n = buffered_raw_read(self, dst + written, remaining, owner,
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
        if (n == 0 || (n == -2 && written > 0)) {
            break;
        }
        if (n == -1) {
            buffered_unread(self, dst, written);
        }
        if (n < 0) {
            return n;
        }
    }
    return written;
}

/* Without a size, a partial line that would block is kept for the next
   readline() (which then returns None) until it is this many times the
   buffer size: then it is returned as it is. */
#define READLINE_KEEP_MAX 64

/* buffered_read_bytes() over a raw stream other than FileIO: its readinto()
   gets views of the result, which they keep alive. */
Py_NO_INLINE static PyObject *
buffered_read_bytes_owned(buffered *self, Py_ssize_t n, int read1)
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
        return r == -2 ? Py_NewRef(Py_None) : NULL;
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
                    : r == -2 ? Py_NewRef(Py_None) : NULL);
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
        return buffered_read_bytes_owned(self, n, read1);
    }
    PyBytesWriter *writer = PyBytesWriter_Create(n);
    if (writer == NULL) {
        return NULL;
    }
    Py_ssize_t r = buffered_read_into(self, PyBytesWriter_GetData(writer), n,
                                      read1, NULL, NULL);
    if (r < 0) {
        PyBytesWriter_Discard(writer);
        return r == -2 ? Py_NewRef(Py_None) : NULL;
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
        if ((PyList_GET_SIZE(chunks) > 0
             && buffered_stash_list(self, Py_NewRef(chunks)) < 0)
            || (last != NULL && buffered_stash(self, last) < 0))
        {
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
    Py_ssize_t st = self->stashed;
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
            const char *p = n->list.items[0].ptr;
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
        if (r == -1 || r == -2) {
            if (r == -1 || unread == 0 || limit >= 0
                || unread < READLINE_KEEP_MAX * n->capacity)
            {
                /* The partial line stays for the next call (gh-51571),
                   which looks for the end of the line after what was
                   looked at.  Would block: return None, unless it is too
                   long to keep. */
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
 * Inside a gather() block, the write()s that the context which entered it
 * makes go to a morsel list of the block's own (its record) instead of the
 * pending writes, past the buffer size, and are moved to the pending writes
 * all at once, in one hold of the lock, so that no other data gets between
 * them: when the block ends, or earlier when the record holds `limit` bytes
 * or an operation needs the real position (reads, seek(), truncate(),
 * close(), detach()).  flush() inside the block is deferred to its end;
 * tell() counts the gathered bytes.  A block nested in one on the same
 * stream gathers into that one.
 *
 * Active records are found through a ContextVar of the module, whose value
 * is the innermost record, linked to the outer ones.  A record also keeps
 * the Context it was entered in and only takes writes made in that one: a
 * context copied inside the block (such as an asyncio task's) sees the
 * records, but writes as usual.  A context runs in one thread at a time, so
 * a record needs no lock; only moving its data to the stream takes the
 * stream's.  Streams count their active records; while there are some they
 * have no writing end (see "The open end" in nibbler.h), so every write,
 * TextIOWrapper's too, takes the lock and looks at the context there, and
 * writes outside gather() blocks pay nothing for it.
 */

typedef struct gather {
    PyObject_HEAD
    buffered *stream;
    Py_ssize_t limit;
    /* Once entered: the Context it was entered in, and the record it is
       nested in (the ContextVar's previous value).  Fixed from then on,
       since threads running copies of the context read them. */
    PyObject *ctx;
    struct gather *outer;
    /* While active: the token from setting the ContextVar. */
    PyObject *token;
    /* Set for a block nested in one on the same stream (in the same
       context), which gathers into that one. */
    struct gather *joined;
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
    GATHER_ACTIVE,
    GATHER_DONE,
};

/* The default limit of gather(). */
#define GATHER_LIMIT (20 * 1024 * 1024)
#define GATHER_BLOCK_MIN 1024
#define GATHER_BLOCK_MAX (64 * 1024)

/* Store in *res a new reference to the record gathering the writes of the
   current context to self, or NULL if there is none.  Returns -1 on
   error. */
static int
gather_find(buffered *self, gather **res)
{
    nibblermodule_state *st = find_nibblermodule_state_by_def(Py_TYPE(self));
    PyObject *value;
    *res = NULL;
    if (PyContextVar_Get(st->gather_var, NULL, &value) < 0) {
        return -1;
    }
    PyObject *ctx = _PyThreadState_GET()->context;
    for (gather *g = (gather *)value; g != NULL; g = g->outer) {
        /* Threads running copies of the context only read the fixed
           fields. */
        if (g->stream == self && g->ctx == ctx
            && g->state == GATHER_ACTIVE)
        {
            *res = (gather *)Py_NewRef(g);
            break;
        }
    }
    Py_XDECREF(value);
    return 0;
}

/* With the lock held, for an operation that needs the real position: move
   what a gather() block of the current context gathered to the pending
   writes.  Out of line, so that buffered_enter_locked() stays small. */
Py_NO_INLINE static int
gather_splice_mine(buffered *self)
{
    gather *g;
    if (gather_find(self, &g) < 0) {
        return -1;
    }
    if (g == NULL) {
        return 0;
    }
    int r = 0;
    if (g->list.nbytes > 0) {
        /* The writes follow what was read. */
        if (buffered_reading(self)) {
            r = buffered_rewind(self);
        }
        if (r == 0) {
            Py_CLEAR(g->block);
            r = morsels_splice(&self->nib.list, &g->list);
        }
    }
    Py_DECREF(g);
    return r;
}

/*
 * Entering methods
 */

enum {
    /* Like KEEP_DIRECTION, but leaves gathered writes alone. */
    TELLING = -2,
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
    /* Only writes can go on while another thread writes out. */
    if (direction != WRITING && buffered_wait_io(self) < 0) {
        return -1;
    }
    if (!buffered_raw_usable(self->raw)) {
        buffered_unlock(self);
        return buffered_not_ready();
    }
    if (FT_ATOMIC_LOAD_INT_RELAXED(self->ngather) > 0
        && direction != WRITING && direction != TELLING
        && gather_splice_mine(self) < 0)
    {
        goto error;
    }
    /* Reading what is already buffered works after close(). */
    int check_closed = (closed_msg != NULL
                        && (direction == WRITING
                            || nibbler_unread(&self->nib) == 0));
    if (check_closed && buffered_check_closed(self, closed_msg) < 0) {
        goto error;
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
    buffered_unlock(self);
    return -1;
}

/* Common start of the I/O methods: lock the object, check it is
   initialized and open (unless closed_msg is NULL), and make it buffer in
   the given direction (unless KEEP_DIRECTION).  Closed is checked with the
   lock held since another thread could be holding it while closing the
   file (issue #31976); leftover read-ahead can still be used except by
   writes.  The common cases need only quick checks: reading from the
   read-ahead, and writing to an open FileIO without read-ahead to hand
   back (without it, a 600-byte bytearray write() took 1661 instead of
   1626 instructions in a GIL -O3 build).  On success the caller must
   unlock. */
static inline int
buffered_enter(buffered *self, const char *closed_msg, int direction)
{
    if (buffered_lock(self) < 0) {
        return -1;
    }
    if (direction == READING && nibbler_unread(&self->nib) > 0
        && buffered_raw_usable(self->raw))
    {
        return 0;
    }
    if (direction == WRITING && self->raw_fileio
        && nibbler_reading(&self->nib) == NULL && self->stash == NULL
        && buffered_raw_usable(self->raw) && !_PyFileIO_closed(self->raw))
    {
        return 0;
    }
    return buffered_enter_locked(self, closed_msg, direction);
}

/* Lock the object and check it is initialized and attached.  On success
   the caller must unlock. */
static int
buffered_lock_ready(buffered *self)
{
    return buffered_enter(self, NULL, KEEP_DIRECTION);
}

/*
 * Gathering: moving gathered data to the stream
 */

/* Move what g gathered to the pending writes, all at once, then write out
   as write() does when they don't fit (with flush, all of them, as flush()
   does).  With nothing gathered, only flush.  Returns 0, or -1 on error
   (when the stream is closed or detached, the data is dropped). */
static int
gather_commit(gather *g, int flush)
{
    buffered *self = g->stream;
    /* Shared from now on: never written to again. */
    Py_CLEAR(g->block);
    g->used = 0;
    if (g->list.nbytes == 0) {
        if (!flush) {
            return 0;
        }
        /* A deferred flush is moot once close() or detach() wrote
           everything out. */
        PyObject *raw = buffered_ref_raw(self);
        int closed = raw == NULL ? 1 : buffered_ref_closed(self, raw);
        Py_XDECREF(raw);
        if (closed != 0) {
            return closed < 0 ? -1 : 0;
        }
        if (buffered_enter(self, "flush of closed file", KEEP_DIRECTION) < 0) {
            return -1;
        }
        int r = buffered_sync(self, 1);
        buffered_unlock(self);
        return r;
    }
    if (buffered_enter(self, "write to closed file", WRITING) < 0) {
        morsels_clear(&g->list);
        return -1;
    }
    int r = morsels_splice(&self->nib.list, &g->list);
    if (r < 0) {
        morsels_clear(&g->list);
    }
    while (r == 0) {
        Py_ssize_t pending = nibbler_nbytes(&self->nib);
        if (pending == 0 || (!flush && pending <= self->nib.threshold)) {
            break;
        }
        if (nibbler_io_busy(&self->nib)) {
            if (nibbler_io_is_mine(&self->nib)) {
                /* Called from this thread's write out (a signal handler),
                   which writes it. */
                break;
            }
            if (nibbler_wait_io(&self->nib, (PyObject *)self) < 0) {
                return -1;
            }
            continue;
        }
        int status;
        (void)buffered_write_out(self, pending, NULL, 0, &status, 1);
        if (status == WRITE_ERROR) {
            r = -1;
        }
        else if (status == WRITE_BLOCKED && flush) {
            buffered_set_blocking_error(0);
            r = -1;
        }
        /* Otherwise what could not be written stays pending. */
        break;
    }
    buffered_unlock(self);
    return r;
}

/* Fail as write() would, without the lock; and hand back read-ahead, which
   gathered writes follow. */
static int
gather_check(buffered *self)
{
    if (nibbler_end_get(&self->nib, 0) != NULL) {
        if (buffered_enter(self, "write to closed file", WRITING) < 0) {
            return -1;
        }
        buffered_unlock(self);
        return 0;
    }
    PyObject *raw = buffered_get_raw(self);
    if (raw == NULL) {
        return -1;
    }
    int closed = buffered_ref_closed(self, raw);
    Py_DECREF(raw);
    if (closed > 0) {
        PyErr_SetString(PyExc_ValueError, "write to closed file");
    }
    return closed == 0 ? 0 : -1;
}

/* Add data[0:len], owned by obj (or NULL), to what g gathered: by
   reference where the pending writes would keep it so, else copied into
   g's block.  Moves it all to the stream once it reaches the limit. */
static int
gather_add(gather *g, PyObject *obj, const char *data, Py_ssize_t len)
{
    if (len == 0) {
        return 0;
    }
    if (FT_ATOMIC_LOAD_UINT8_RELAXED(g->stream->raw_vectored)
        && len >= NIBBLER_REF_MIN && obj != NULL
        && PyBytes_CheckExact(obj))
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
        g->used += len;
        if (morsels_push(&g->list, g->block, dst, len) < 0) {
            return -1;
        }
    }
    if (g->list.nbytes >= g->limit) {
        return gather_commit(g, 0);
    }
    return 0;
}

/* A write() of data[0:len], owned by obj (or NULL), made while the stream
   has active gather() blocks: gather it if one is the current context's.
   Returns 1 when gathered, 0 when the write is not in a block, -1 on
   error. */
Py_NO_INLINE static int
gather_try_write(buffered *self, PyObject *obj, const char *data,
                 Py_ssize_t len)
{
    gather *g;
    if (gather_find(self, &g) < 0) {
        return -1;
    }
    if (g == NULL) {
        return 0;
    }
    int r = (gather_check(self) < 0 || gather_add(g, obj, data, len) < 0
             ? -1 : 1);
    Py_DECREF(g);
    return r;
}

/*
 * The gather() context manager
 */

static PyObject *
gather_enter(PyObject *op, PyObject *Py_UNUSED(dummy))
{
    gather *g = (gather *)op;
    buffered *self = g->stream;
    if (g->state != GATHER_NEW) {
        PyErr_SetString(PyExc_RuntimeError,
                        "a gather() block can only be entered once");
        return NULL;
    }
    PyObject *raw = buffered_get_raw(self);
    if (raw == NULL) {
        return NULL;
    }
    int closed = buffered_ref_closed(self, raw);
    Py_DECREF(raw);
    if (closed != 0) {
        if (closed > 0) {
            PyErr_SetString(PyExc_ValueError, "gather on closed file");
        }
        return NULL;
    }
    gather *outer;
    if (gather_find(self, &outer) < 0) {
        return NULL;
    }
    if (outer != NULL) {
        g->joined = outer;
        g->state = GATHER_ACTIVE;
        return Py_NewRef(self);
    }
    nibblermodule_state *st = find_nibblermodule_state_by_def(Py_TYPE(self));
    PyObject *prev;
    if (PyContextVar_Get(st->gather_var, NULL, &prev) < 0) {
        return NULL;
    }
    PyObject *token = PyContextVar_Set(st->gather_var, op);
    if (token == NULL) {
        Py_XDECREF(prev);
        return NULL;
    }
    /* Writes made after this take the lock (see "Gathering"): count the
       block and drop the writing end with the lock held, so that no write
       out opens one again meanwhile. */
    if (buffered_lock(self) < 0) {
        PyObject *exc = PyErr_GetRaisedException();
        (void)PyContextVar_Reset(st->gather_var, token);
        _PyErr_ChainExceptions1(exc);
        Py_DECREF(token);
        Py_XDECREF(prev);
        return NULL;
    }
    (void)_Py_atomic_add_int(&self->ngather, 1);
    nibbler_stop_appending(&self->nib);
    buffered_unlock(self);
    g->outer = (gather *)prev;
    g->token = token;
    /* Setting the variable made sure there is a context. */
    g->ctx = Py_NewRef(_PyThreadState_GET()->context);
    g->state = GATHER_ACTIVE;
    return Py_NewRef(self);
}

/* Stop gathering: writes then go to the stream as usual. */
static void
gather_deactivate(gather *g)
{
    if (g->state == GATHER_ACTIVE && g->joined == NULL) {
        (void)_Py_atomic_add_int(&g->stream->ngather, -1);
    }
    g->state = GATHER_DONE;
}

static PyObject *
gather_exit(PyObject *op, PyObject *const *Py_UNUSED(args),
            Py_ssize_t Py_UNUSED(nargs))
{
    gather *g = (gather *)op;
    if (g->state != GATHER_ACTIVE) {
        PyErr_SetString(PyExc_RuntimeError, "gather() block not entered");
        return NULL;
    }
    if (g->joined != NULL) {
        g->state = GATHER_DONE;
        Py_CLEAR(g->joined);
        Py_RETURN_FALSE;
    }
    /* What was gathered is written out also when the block raised, as
       buffered data would be. */
    gather_deactivate(g);
    nibblermodule_state *st = find_nibblermodule_state_by_def(
        Py_TYPE(g->stream));
    PyObject *exc = NULL;
    if (PyContextVar_Reset(st->gather_var, g->token) < 0) {
        exc = PyErr_GetRaisedException();
    }
    Py_CLEAR(g->token);
    int r = gather_commit(g, g->flush);
    g->flush = 0;
    if (exc != NULL) {
        _PyErr_ChainExceptions1(exc);
        r = -1;
    }
    if (r < 0) {
        return NULL;
    }
    Py_RETURN_FALSE;
}

static int
gather_traverse(PyObject *op, visitproc visit, void *arg)
{
    gather *g = (gather *)op;
    Py_VISIT(Py_TYPE(op));
    Py_VISIT(g->stream);
    Py_VISIT(g->ctx);
    Py_VISIT(g->token);
    Py_VISIT(g->outer);
    Py_VISIT(g->joined);
    return 0;
}

/* A block never left drops what it gathered. */
static int
gather_clear(PyObject *op)
{
    gather *g = (gather *)op;
    if (g->stream != NULL) {
        gather_deactivate(g);
    }
    Py_CLEAR(g->stream);
    Py_CLEAR(g->ctx);
    Py_CLEAR(g->token);
    Py_CLEAR(g->outer);
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

/* A new gather() context manager for self, or NULL on error. */
static PyObject *
gather_new(buffered *self, Py_ssize_t limit)
{
    if (limit <= 0) {
        PyErr_SetString(PyExc_ValueError, "limit must be positive");
        return NULL;
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
 * Methods
 */

static int
buffered_clear(PyObject *op)
{
    buffered *self = buffered_cast(op);
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
    nibbler_free(&self->nib);
    (void)buffered_clear(op);
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
    Py_VISIT(self->stash);
    Py_VISIT(self->dict);
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
    buffered_unlock(self);
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
        /* Do what flush() does, without the method call. */
        if (buffered_flush_locked(self) < 0) {
            exc = PyErr_GetRaisedException();
        }
    }
    else {
        /* flush() was overridden; it takes the lock itself. */
        buffered_unlock(self);
        if (_PyFile_Flush((PyObject *)self) < 0) {
            exc = PyErr_GetRaisedException();
        }
        /* Another thread may have detached it meanwhile. */
        if (buffered_lock_ready(self) < 0) {
            _PyErr_ChainExceptions1(exc);
            return NULL;
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
    buffered_unlock(self);
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
    /* Also write out what other threads wrote since flush(). */
    if (buffered_writable(self) && buffered_sync(self, 0) < 0) {
        buffered_unlock(self);
        return NULL;
    }
    PyObject *raw = buffered_swap_raw(self, NULL);
    nibbler_free(&self->nib);
    (void)buffered_drop_stash(self);
    buffered_unlock(self);
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
    if (FT_ATOMIC_LOAD_INT_RELAXED(self->ngather) > 0) {
        /* Inside a gather() block, flushing waits for its end. */
        gather *g;
        if (gather_find(self, &g) < 0) {
            return NULL;
        }
        if (g != NULL) {
            g->flush = 1;
            Py_DECREF(g);
            Py_RETURN_NONE;
        }
    }
    if (buffered_enter(self, "flush of closed file", KEEP_DIRECTION) < 0) {
        return NULL;
    }
    int r = buffered_sync(self, 1);
    buffered_unlock(self);
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
    /* At least min(size, buffer size) bytes, when the raw stream has them
       (gh-50061). */
    Py_ssize_t capacity = FT_ATOMIC_LOAD_SSIZE_RELAXED(self->nib.capacity);
    Py_ssize_t want = Py_MAX(Py_MIN(size, capacity), 1);
    /* Without the lock when the read-ahead has them. */
    PyObject *res = nibbler_peek(&self->nib, want);
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
        buffered_unlock(self);
        return NULL;
    }
    /* With fewer than want unread, one raw read after them.  (The fill
       keeps them in front, which costs block alignment, so it is only done
       when asked for more than the read-ahead has.) */
    Py_ssize_t r = (nibbler_unread(&self->nib) >= want
                    ? 1 : buffered_fill(self, 0));
    if (r == -2 && nibbler_unread(&self->nib) == 0) {
        /* Would block, with nothing to return. */
        res = Py_NewRef(Py_None);
    }
    else if (r != -1) {
        res = nibbler_peek_held(&self->nib);
    }
    buffered_unlock(self);
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
    buffered_unlock(self);
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
    buffered_unlock(self);
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
    /* The raw stream reads into the caller's memory itself; what Python
       code keeps of it stays valid through the caller's object. */
    int shared = 0;
    Py_ssize_t n = buffered_read_into(self, buffer->buf, buffer->len,
                                      readinto1, buffer->obj, &shared);
    buffered_unlock(self);
    if (n == -2) {
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
        buffered_unlock(self);
        return NULL;
    }
    PyObject *res = buffered_readline(self, size);
    buffered_unlock(self);
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
    /* Inside a gather() block, the position is after what it gathered. */
    Py_ssize_t gathered = 0;
    if (FT_ATOMIC_LOAD_INT_RELAXED(self->ngather) > 0) {
        gather *g;
        if (gather_find(self, &g) < 0) {
            return NULL;
        }
        if (g != NULL) {
            gathered = g->list.nbytes;
            Py_DECREF(g);
        }
    }
    if (buffered_enter(self, NULL, TELLING) < 0) {
        return NULL;
    }
    PyObject *res = NULL;
    /* Pending writes to a raw stream in append mode go to the end of the
       file: write them out, and the raw position is the logical one
       (gh-80592). */
    if (!self->raw_appending || !buffered_writing(self)
        || buffered_flush_writes(self, 0) == 0)
    {
        res = buffered_position(self, gathered);
    }
    buffered_unlock(self);
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
    if (buffered_enter(self, "seek of closed file", KEEP_DIRECTION) < 0) {
        return NULL;
    }
    PyObject *res = NULL;
    _PyIO_State *state = find_io_state_by_def(Py_TYPE(self));
    Py_off_t target;
    if (_PyIOBase_check_seekable(state, self->raw, Py_True) == NULL
        || ((target = PyNumber_AsOff_t(targetobj, PyExc_ValueError)) == -1
            && PyErr_Occurred()))
    {
        goto end;
    }
    if (nibbler_reading(&self->nib) != NULL && self->stash == NULL
        && (whence == SEEK_SET || whence == SEEK_CUR))
    {
        /* Move within the last fill if the target is in it: its bytes end
           at the raw position. */
        Py_off_t raw_pos = buffered_raw_tell(self);
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
    buffered_unlock(self);
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
    }
    buffered_unlock(self);
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
        /* Would block: StopIteration would end the loop for good. */
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

    /* (Re)initialize; a failed __init__() leaves the object uninitialized. */
    if (buffered_lock(self) < 0 || buffered_wait_io(self) < 0) {
        return -1;
    }
    /* Pending writes first go to the raw stream they were written to, as
       FileIO.__init__() first closes the file it had open: if that fails,
       raise, leaving the object as it is. */
    if (buffered_raw_usable(self->raw) && buffered_writing(self)
        && buffered_flush_writes(self, 0) < 0)
    {
        buffered_unlock(self);
        return -1;
    }
    nibbler_free(&self->nib);
    (void)buffered_drop_stash(self);
    FT_ATOMIC_STORE_SSIZE_RELAXED(self->nib.capacity,
                                  err == 0 ? buffer_size : 0);
    self->nib.threshold = err == 0 ? threshold : 0;
    if (err == 0) {
        self->raw_fileio = (uint8_t)raw_fileio;
        /* Use _writev() only where it can't bypass an overridden write():
           on FileIO itself, or on raw types not derived from it.  (Readers
           skip the lookups.) */
        /* Also read without the lock, by gather(). */
        FT_ATOMIC_STORE_UINT8_RELAXED(self->raw_vectored, (uint8_t)(
            writable
            && (raw_fileio || !PyObject_TypeCheck(raw, state->PyFileIO_Type))
            && _PyType_Lookup(Py_TYPE(raw), &_Py_ID(_writev)) != NULL));
        self->raw_appending = (
            writable
            && PyObject_TypeCheck(raw, state->PyFileIO_Type)
            && _PyFileIO_appending(raw));
    }
    PyObject *old = buffered_swap_raw(self, err == 0 ? Py_NewRef(raw) : NULL);
    buffered_unlock(self);
    /* Releasing the old raw stream can run arbitrary code. */
    Py_XDECREF(old);
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

/* buffered_write_locked() returns this when another thread is writing out
   and data doesn't fit: wait for it (it may make room), then enter again,
   since anything may have changed. */
#define BUFFERED_WRITE_RETRY 1

/* write() raised an error other than BlockingIOError after `done` bytes of
   its data reached the raw stream: keep the rest pending, as much of it as
   fits, so that flush() writes it, and set the error's characters_written
   to how much of the data was accepted (written or kept).  Without that,
   the caller couldn't tell what to write again.  Returns -1. */
static int
buffered_write_failed(buffered *self, const morsel *w, Py_ssize_t done)
{
    if (done == 0) {
        /* None of the data was taken: the caller can just retry. */
        return -1;
    }
    PyObject *exc = PyErr_GetRaisedException();
    Py_ssize_t room = Py_MAX(0, self->nib.threshold
                                - nibbler_nbytes(&self->nib));
    Py_ssize_t keep = Py_MIN(w->len - done, room);
    if (buffered_add_write(self, w->obj, w->ptr + done,
                           keep) < 0)
    {
        _PyErr_ChainExceptions1(exc);
        return -1;
    }
    if (PyErr_GivenExceptionMatches(exc, PyExc_OSError)) {
        PyObject *n = PyLong_FromSsize_t(done + keep);
        if (n == NULL
            || PyObject_SetAttrString(exc, "characters_written", n) < 0)
        {
            PyErr_Clear();
        }
        Py_XDECREF(n);
    }
    PyErr_SetRaisedException(exc);
    return -1;
}

/* The body of write(), with the lock held: buffer the data after *done
   (the bytes of it written out so far), writing out what is pending first
   when it doesn't fit.  Called from code that the raw write of this
   thread's write out runs (such as a signal handler), it buffers all of
   the data, past the capacity if need be: the write out or the next flush
   writes it.  Returns 0, -1 on error, or BUFFERED_WRITE_RETRY; the lock
   stays held. */
static int
buffered_write_locked(buffered *self, const morsel *w, Py_ssize_t *done)
{
    PyObject *obj = w->obj;
    const char *data = w->ptr;
    Py_ssize_t len = w->len;
    Py_ssize_t threshold = self->nib.threshold;
    assert(threshold >= 0);
    for (;;) {
        Py_ssize_t rest = len - *done;
        Py_ssize_t pending = nibbler_nbytes(&self->nib);
        /* Room for the rest of data: buffer it.  (Unbuffered, the threshold
           is 0: there is never room.) */
        if (rest < threshold && pending + rest <= threshold) {
            return buffered_add_write(self, obj, data + *done, rest);
        }
        if (nibbler_io_busy(&self->nib)) {
            if (nibbler_io_is_mine(&self->nib)) {
                /* gh-118143 */
                return nibbler_append_copy(&self->nib, data + *done, rest);
            }
            return BUFFERED_WRITE_RETRY;
        }
        /* No room: write out what is pending, and the rest of data with it
           when one vectored write takes both or it is too large to buffer,
           without the lock: other threads can queue writes meanwhile. */
        int status;
        Py_ssize_t direct = rest >= threshold || self->raw_vectored ? rest : 0;
        *done += buffered_write_out(self, pending, data + *done, direct,
                                    &status, 1);
        rest = len - *done;
        if (status == WRITE_DONE) {
            if (rest == 0 && nibbler_nbytes(&self->nib) == 0) {
                /* All written (unbuffered, the usual case). */
                return 0;
            }
            continue;
        }
        if (status == WRITE_ERROR) {
            return buffered_write_failed(self, w, *done);
        }
        /* Would block: keep as much of the rest as fits, and report the
           rest. */
        Py_ssize_t room = Py_MAX(0, threshold - nibbler_nbytes(&self->nib));
        if (rest <= room) {
            return buffered_add_write(self, obj, data + *done, rest);
        }
        int errnum = errno;
        if (buffered_add_write(self, obj, data + *done, room) == 0) {
            errno = errnum;
            buffered_set_blocking_error(*done + room);
        }
        return -1;
    }
}

/* Without the lock: queue data[0:len] at the writing end, if there is one
   with room.  Returns 1 when done, 0 when the lock is needed, or -1 on
   error. */
static inline int
buffered_write_lockfree(buffered *self, const char *data, Py_ssize_t len,
                        int closed_checked)
{
    nibbler_end *e = nibbler_end_get(&self->nib, 1);
    Py_ssize_t r;
    if (e == NULL || (r = nibbler_reserve(e, len)) < 0) {
        return 0;
    }
    /* Until committed, nothing can replace raw.  Data written once an
       exact FileIO was closed by itself is queued too: nothing can write it
       out any more.  (Other raw streams: see buffered_check_closed().) */
    PyObject *raw = FT_ATOMIC_LOAD_PTR_RELAXED(self->raw);
    int closed = !closed_checked && self->raw_fileio && _PyFileIO_closed(raw);
    nibbler_commit(e, r, data, len);
    if (closed) {
        PyErr_SetString(PyExc_ValueError, "write to closed file");
        return -1;
    }
    return 1;
}

/* write() of w->ptr[0:w->len], owned by w->obj, with the lock.
   Returns 0 or -1.  Out of line, so that the lock-free paths before it
   stay small. */
Py_NO_INLINE static int
buffered_write_view(buffered *self, const morsel *w)
{
    if (FT_ATOMIC_LOAD_INT_RELAXED(self->ngather) > 0) {
        int r = gather_try_write(self, w->obj, w->ptr, w->len);
        if (r != 0) {
            return r < 0 ? -1 : 0;
        }
    }
    Py_ssize_t done = 0;
    for (;;) {
        if (buffered_enter(self, "write to closed file", WRITING) < 0) {
            return -1;
        }
        int r = buffered_write_locked(self, w, &done);
        if (r == 0 && FT_ATOMIC_LOAD_INT_RELAXED(self->ngather) == 0) {
            /* The next writes may need no lock (unless gathering, see
               "Gathering"). */
            nibbler_start_appending(&self->nib);
        }
        if (r == BUFFERED_WRITE_RETRY
            && nibbler_wait_io(&self->nib, (PyObject *)self) < 0)
        {
            return -1;
        }
        buffered_unlock(self);
        if (r != BUFFERED_WRITE_RETRY) {
            return r;
        }
    }
}

/*[clinic input]
_io._Buffered.gather
    limit: Py_ssize_t(c_default="GATHER_LIMIT") = 20971520

Gather the writes of the current context in a with block.

Returns a context manager.  Inside its with block, what the current
context (thread, or asyncio task) writes is kept apart, also past
the buffer size, and added to the buffered data in one piece when
the block ends, so that no other output gets in between.  Once the
block gathered limit bytes, they are added, and gathering goes on.
flush() inside the block takes effect at its end; reads, seek(),
truncate(), close() and detach() add what was gathered first.
[clinic start generated code]*/

static PyObject *
_io__Buffered_gather_impl(buffered *self, Py_ssize_t limit)
/*[clinic end generated code: output=f7d26dbe48e1df79 input=8c3eeb483940ac56]*/
{
    return gather_new(self, limit);
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

/* write() of obj with the lock: out of line, so that the lock-free path
   stays small. */
Py_NO_INLINE static PyObject *
buffered_write(buffered *self, PyObject *obj)
{
    /* Exact bytes need no buffer export: only obj, buf and len are used. */
    if (PyBytes_CheckExact(obj)) {
        morsel w = {obj, PyBytes_AS_STRING(obj), PyBytes_GET_SIZE(obj)};
        int r = buffered_write_view(self, &w);
        return r < 0 ? NULL : PyLong_FromSsize_t(w.len);
    }
    Py_buffer view;
    if (PyObject_GetBuffer(obj, &view, PyBUF_SIMPLE) < 0) {
        return NULL;
    }
    int r = 0;
    if (view.len < NIBBLER_REF_MIN) {
        r = buffered_write_lockfree(self, view.buf, view.len, 0);
    }
    if (r == 0) {
        morsel w = {view.obj, view.buf, view.len};
        r = buffered_write_view(self, &w);
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
    if (PyBytes_CheckExact(obj)) {
        Py_ssize_t len = PyBytes_GET_SIZE(obj);
        int r = (len < NIBBLER_REF_MIN
                 ? buffered_write_lockfree(self, PyBytes_AS_STRING(obj), len, 0)
                 : 0);
        if (r != 0) {
            return r < 0 ? NULL : PyLong_FromSsize_t(len);
        }
    }
    return buffered_write(self, obj);
}

/*
 * Bytes for TextIOWrapper
 *
 * Over an exact buffered object of ours, TextIOWrapper (textio.c) uses the
 * morsels directly (see _iomodule.h): it decodes straight from the
 * read-ahead and takes only the bytes of the characters it returns, so
 * what it doesn't return (a partial character, a line that hasn't ended)
 * stays here, the next fill keeping it in front, and the position is the
 * text position; and encoded text is appended as write() does.  An
 * instance dict could override the methods, so objects with one are used
 * through them.
 */

/* peek with the lock: out of line, so that the lock-free path stays
   small. */
Py_NO_INLINE static int
buffered_text_peek_locked(buffered *self, Py_ssize_t need, morsel *m)
{
    if (buffered_enter(self, "read of closed file", READING) < 0) {
        return -1;
    }
    int r = 0;
    if (need > self->nib.capacity) {
        /* The unread bytes and more can't fit in a block. */
        r = _PyIO_NIBBLER_NO;
    }
    else if (nibbler_unread(&self->nib) < need) {
        Py_ssize_t n = buffered_fill(self, 0);
        r = n == -1 ? -1 : n == -2 ? _PyIO_NIBBLER_BLOCKED : 0;
    }
    if (r >= 0 && nibbler_unread(&self->nib) > 0) {
        *m = self->nib.list.items[0];
        Py_INCREF(m->obj);
    }
    buffered_unlock(self);
    return r;
}

/* m views another block: out of line, so that _PyIONibbler_view() needs
   no stack frame. */
Py_NO_INLINE static int
nibbler_text_view_block(nibbler_end *e, Py_ssize_t c, Py_ssize_t limit,
                        _PyIO_Morsel *m)
{
    Py_XSETREF(m->obj, Py_NewRef(e->block));
    m->ptr = PyBytes_AS_STRING(e->block) + c;
    m->len = limit - c;
    return 1;
}

int
_PyIONibbler_view(PyObject *op, _PyIO_Morsel *m)
{
    buffered *self = buffered_cast(op);
    assert(_PyIO_is_nibbler_buffered_type(Py_TYPE(op)));
    nibbler_end *e = nibbler_end_get(&self->nib, 0);
    Py_ssize_t c = e == NULL ? -1 : FT_ATOMIC_LOAD_SSIZE_RELAXED(e->pos);
    Py_ssize_t limit = c < 0 ? 0 : nibbler_end_limit(e);
    if (c < 0 || c == limit || buffered_dict(self) != NULL) {
        return 0;
    }
    if (m->obj != e->block) {
        return nibbler_text_view_block(e, c, limit, m);
    }
    /* m keeps its reference to the block. */
    m->ptr = PyBytes_AS_STRING(e->block) + c;
    m->len = limit - c;
    return 1;
}

int
_PyIONibbler_peek(PyObject *op, Py_ssize_t need, _PyIO_Morsel *m)
{
    assert(need > 0);
    if (_PyIONibbler_view(op, m) && m->len >= need) {
        return 0;
    }
    /* Not to keep the block from being reused by the fill. */
    Py_CLEAR(m->obj);
    *m = (morsel){NULL, NULL, 0};
    buffered *self = buffered_cast(op);
    if (buffered_dict(self) != NULL) {
        return _PyIO_NIBBLER_NO;
    }
    return buffered_text_peek_locked(self, need, m);
}

/* consume with the lock: out of line, so that the lock-free path stays
   small. */
Py_NO_INLINE static int
buffered_text_consume_locked(buffered *self, _PyIO_Morsel *m, Py_ssize_t n)
{
    /* The caller's reference may be borrowed, and other threads run while
       this waits for the lock. */
    Py_INCREF(self);
    int r = buffered_lock(self);
    if (r == 0) {
        if (nibbler_unread(&self->nib) >= n
            && self->nib.list.items[0].ptr == m->ptr)
        {
            (void)morsels_consume(&self->nib.list, n);
            m->ptr += n;
            m->len -= n;
            r = 1;
        }
        buffered_unlock(self);
    }
    Py_DECREF(self);
    return r;
}

int
_PyIONibbler_consume(PyObject *op, _PyIO_Morsel *m, Py_ssize_t n)
{
    buffered *self = buffered_cast(op);
    assert(n <= m->len);
    if (n == 0) {
        return 1;
    }
    /* Without the lock: move the reading end's position from where m
       starts, if it is still there.  (m keeps the block alive, so it can't
       be reused for other bytes.) */
    nibbler_end *e = nibbler_end_get(&self->nib, 0);
    if (e != NULL && e->block == m->obj) {
        Py_ssize_t c = m->ptr - PyBytes_AS_STRING(e->block);
        if (FT_ATOMIC_COMPARE_EXCHANGE_SSIZE(e->pos, &c, c + n)) {
            m->ptr += n;
            m->len -= n;
            return 1;
        }
        if (c >= 0) {
            return 0;
        }
    }
    /* The end is held, or gone: check the front morsel with the lock. */
    return buffered_text_consume_locked(self, m, n);
}

/* _PyIONibbler_write() past its first case, out of line. */
Py_NO_INLINE static int
nibbler_text_write(buffered *self, PyObject *obj, const char *data,
                   Py_ssize_t len, int closed_checked)
{
    if (buffered_dict(self) != NULL
        || ((PyHeapTypeObject *)Py_TYPE(self))->ht_token
           == &nibbler_bufferedreader_spec)
    {
        return _PyIO_NIBBLER_NO;
    }
    int r = (len < NIBBLER_REF_MIN
             ? buffered_write_lockfree(self, data, len, closed_checked) : 0);
    if (r != 0) {
        return r < 0 ? -1 : 0;
    }
    /* The caller's reference is borrowed: raw.write() could drop it. */
    Py_INCREF(self);
    morsel w = {obj, data, len};
    r = buffered_write_view(self, &w);
    Py_DECREF(self);
    return r;
}

int
_PyIONibbler_write(PyObject *op, PyObject *obj, const char *data,
                   Py_ssize_t len, int closed_checked)
{
    buffered *self = buffered_cast(op);
    /* The common case: room at the writing end (only a writer has one),
       and the raw stream is known to be open. */
    nibbler_end *e;
    Py_ssize_t r;
    if (closed_checked && buffered_dict(self) == NULL && len < NIBBLER_REF_MIN
        && (e = nibbler_end_get(&self->nib, 1)) != NULL
        && (r = nibbler_reserve(e, len)) >= 0)
    {
        nibbler_commit(e, r, data, len);
        return 0;
    }
    return nibbler_text_write(self, obj, data, len, closed_checked);
}

char *
_PyIONibbler_reserve(PyObject *op, Py_ssize_t len, int closed_checked,
                     void **end)
{
    buffered *self = buffered_cast(op);
    nibbler_end *e;
    Py_ssize_t r;
    if (closed_checked && buffered_dict(self) == NULL && len < NIBBLER_REF_MIN
        && (e = nibbler_end_get(&self->nib, 1)) != NULL
        && (r = nibbler_reserve(e, len)) >= 0)
    {
        *end = e;
        return PyBytes_AS_STRING(e->block) + r;
    }
    return NULL;
}

void
_PyIONibbler_commit(void *end, Py_ssize_t len)
{
    FT_ATOMIC_ADD_SSIZE(((nibbler_end *)end)->done, len);
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
    _IO__BUFFERED_GATHER_METHODDEF
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
    _IO__BUFFERED_GATHER_METHODDEF
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
    Py_VISIT(state->Gather_Type);
    Py_VISIT(state->gather_var);
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
    Py_CLEAR(state->Gather_Type);
    Py_CLEAR(state->gather_var);
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
    .m_doc = "Buffered I/O classes mirroring _io, as an _io submodule.",
    .m_size = sizeof(nibblermodule_state),
    .m_traverse = nibblermodule_traverse,
    .m_clear = nibblermodule_clear,
    .m_free = nibblermodule_free,
};

/* Create a type from spec with base, named prefix + its class name, and
   add it to mod.  The class attribute _is_nibbler (True) tells tests these
   classes from _io's, also when they replace them.  Returns a new
   reference, or NULL on error. */
static PyTypeObject *
nibbler_add_type(PyObject *mod, const PyType_Spec *spec, PyTypeObject *base,
                 const char *prefix)
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
    if (PyDict_SetItemString(_PyType_GetDict(type), "_is_nibbler",
                             Py_True) < 0)
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
             mod, &nibbler_bufferedreader_spec, base, prefix)) == NULL
        || (state->PyBufferedWriter_Type = nibbler_add_type(
             mod, &nibbler_bufferedwriter_spec, base, prefix)) == NULL
        || (state->PyBufferedRWPair_Type = nibbler_add_type(
             mod, &nibbler_bufferedrwpair_spec, base, prefix)) == NULL
        || (state->PyBufferedRandom_Type = nibbler_add_type(
             mod, &nibbler_bufferedrandom_spec, base, prefix)) == NULL)
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
    state->gather_var = PyContextVar_New("_io._nibbler.gather", NULL);
    if (state->gather_var == NULL) {
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


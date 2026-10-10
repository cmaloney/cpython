/*
    An implementation of Buffered I/O as defined by PEP 3116 - "New I/O"

    Classes defined here: BufferedReader, BufferedWriter, BufferedRandom,
    BufferedRWPair, all derived from _io._BufferedIOBase.

    Originally written by Amaury Forgeot d'Arc and Antoine Pitrou; reworked
    around the "nibbler" model (see the notes before the buffered struct).
*/

#include "Python.h"
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

/* Per-module state: the five buffered types, and TextIOWrapper. */
typedef struct {
    PyTypeObject *PyBufferedIOBase_Type;
    PyTypeObject *PyBufferedReader_Type;
    PyTypeObject *PyBufferedWriter_Type;
    PyTypeObject *PyBufferedRandom_Type;
    PyTypeObject *PyBufferedRWPair_Type;
    PyTypeObject *PyTextIOWrapper_Type;
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

    /* The buffered data and the lock.  Its capacity is the buffer size (0:
       unbuffered, see above; also read without the lock, by __sizeof__()).
       Whether the object is closed is up to raw: close() keeps it, so that
       name, mode and raw still work. */
    nibbler nib;

    PyObject *dict;
    PyObject *weakreflist;
} buffered;

static inline buffered *
buffered_cast(PyObject *op)
{
    return (buffered *)op;
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

/* Is raw (which must be set) closed?  Returns 1 if closed, 0 if open, -1
   on error. */
static int
buffered_is_closed(buffered *self)
{
    if (self->raw_fileio) {
        return _PyFileIO_closed(self->raw);
    }
    PyObject *res = PyObject_GetAttr(self->raw, &_Py_ID(closed));
    if (res == NULL) {
        return -1;
    }
    int closed = PyObject_IsTrue(res);
    Py_DECREF(res);
    return closed;
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
static void
buffered_relock_after_raw(buffered *self, int unlocked)
{
    if (unlocked) {
        int errnum = errno;
        PyObject *exc = PyErr_GetRaisedException();
        nibbler_relock(&self->nib, (PyObject *)self);
        PyErr_SetRaisedException(exc);
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

/* One raw write of the pending writes followed by extra (a morsel of data
   not yet pending, or with len 0): as much as one vectored write takes when
   the raw stream has _writev(), else the first morsel.  Returns the count,
   -2 if the raw stream would block (errno set for the BlockingIOError), or
   -1 on error. */
static Py_ssize_t
buffered_raw_write(buffered *self, Py_ssize_t avail, const morsel *extra,
                   int unlocked)
{
    morsel pieces[_PyIO_WRITEV_MAX];
    Py_ssize_t limit = self->raw_vectored ? _PyIO_WRITEV_MAX : 1;
    Py_ssize_t total;
    Py_ssize_t cnt = nibbler_pieces(&self->nib, avail, pieces, limit, &total);
    if (extra->len > 0 && cnt < limit && total == avail) {
        pieces[cnt++] = *extra;
        total += extra->len;
    }
    assert(cnt > 0);

    if (self->raw_fileio) {
        /* The raw call holds its own references, see nibbler_lock_wait()
           (Python-level calls get views, which do). */
        _PyIO_Span spans[_PyIO_WRITEV_MAX];
        for (Py_ssize_t i = 0; i < cnt; i++) {
            spans[i] = (_PyIO_Span){pieces[i].ptr, pieces[i].len};
            Py_XINCREF(pieces[i].obj);
        }
        buffered_unlock_for_raw(self, unlocked);
        Py_ssize_t n = buffered_check_progress(
            _PyFileIO_writev(self->raw, spans, cnt), total, "write");
        buffered_relock_after_raw(self, unlocked);
        for (Py_ssize_t i = 0; i < cnt; i++) {
            Py_XDECREF(pieces[i].obj);
        }
        return n;
    }

    /* Python code may keep the views (and reach the block through them): it
       must not be written to again, also by appends without the lock. */
    nibbler_drop_end(&self->nib);
    nibbler_set_block(&self->nib, NULL);
    PyObject *arg = NULL;
    if (cnt == 1) {
        arg = buffered_view(&pieces[0]);
    }
    else if ((arg = PyList_New(cnt)) != NULL) {
        for (Py_ssize_t i = 0; i < cnt; i++) {
            PyObject *view = buffered_view(&pieces[i]);
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
    buffered_unlock_for_raw(self, unlocked);
    do {
        errno = 0;
        res = PyObject_CallMethodOneArg(self->raw, name, arg);
        errnum = errno;
    } while (res == NULL && _PyIO_trap_eintr());
    /* Views of the data of the current write() call have no exporter:
       release them, so that they give no access to it later.  (The others
       keep their bytes alive.) */
    if (cnt == 1) {
        if (pieces[0].obj == NULL) {
            (void)buffered_release_view(arg);
        }
        else {
            Py_DECREF(arg);
        }
    }
    else {
        for (Py_ssize_t i = 0; i < cnt; i++) {
            if (pieces[i].obj == NULL) {
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
    buffered_relock_after_raw(self, unlocked);
    return n;
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

/* The logical position: the raw one adjusted for what is buffered. */
static PyObject *
buffered_position(buffered *self)
{
    Py_off_t pos = buffered_raw_tell(self);
    if (pos == -1) {
        return NULL;
    }
    Py_ssize_t k = nibbler_nbytes(&self->nib);
    pos += nibbler_reading(&self->nib) != NULL ? -k : k;
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
    return nibbler_append(&self->nib, obj, data, len, self->raw_vectored);
}

/* How a write out stopped: everything written, the raw stream would
   block, or an error. */
enum {
    WRITE_DONE = 0,
    WRITE_BLOCKED = 1,
    WRITE_ERROR = -1,
};

/* Write the first `target` bytes of the pending writes followed by
   data[0:len] until all of it is written, the raw stream would block or
   an error is raised; *status says which.  Written bytes are dropped as
   they go, so on error the unwritten rest is still pending.  With
   unlocked, the lock is released around the raw calls; other threads can
   then only queue more writes, which are left pending.  Returns how much
   of data was written, also on error. */
static Py_ssize_t
buffered_write_out(buffered *self, Py_ssize_t target, const char *data,
                   Py_ssize_t len, int *status, int unlocked)
{
    morsel extra = {NULL, data, len};
    *status = WRITE_ERROR;
    nibbler_begin_io(&self->nib);
    while (target > 0 || extra.len > 0) {
        Py_ssize_t n = buffered_raw_write(self, target, &extra, unlocked);
        if (n == -1) {
            goto done;
        }
        if (n == -2) {
            *status = WRITE_BLOCKED;
            goto done;
        }
        Py_ssize_t k = nibbler_written(&self->nib, n);
        target -= k;
        extra.ptr += n - k;
        extra.len -= n - k;
        if (target == 0 && extra.len == 0) {
            break;
        }
        /* Partial writes can return successfully when interrupted by a
           signal (see write(2)).  Run signal handlers before blocking
           another time, possibly indefinitely.  With unlocked, without
           the lock: a handler writing to this object (print()) then
           queues its data (gh-118143) instead of failing as a reentrant
           call. */
        buffered_unlock_for_raw(self, unlocked);
        int r = PyErr_CheckSignals();
        buffered_relock_after_raw(self, unlocked);
        if (r < 0) {
            goto done;
        }
    }
    *status = WRITE_DONE;

done:
    nibbler_end_io(&self->nib);
    return len - extra.len;
}

/* Unbuffered write() to a FileIO with nothing pending: write data[0:len]
   straight to the raw stream, retrying partial writes, with the I/O role
   and without the lock, like buffered_write_out() but without its pending
   writes.  Signal handlers run only before retrying (and in the raw call
   on EINTR); writes they make are left pending.  Returns how much was
   written, also when *status is not WRITE_DONE. */
static Py_ssize_t
buffered_write_direct(buffered *self, const char *data, Py_ssize_t len,
                      int *status)
{
    assert(self->raw_fileio && !buffered_writing(self));
    Py_ssize_t done = 0;
    *status = WRITE_ERROR;
    nibbler_begin_io(&self->nib);
    buffered_unlock_for_raw(self, 1);
    for (;;) {
        _PyIO_Span span = {data + done, len - done};
        Py_ssize_t n = buffered_check_progress(
            _PyFileIO_writev(self->raw, &span, 1), span.len, "write");
        if (n < 0) {
            if (n == -2) {
                *status = WRITE_BLOCKED;
            }
            break;
        }
        done += n;
        /* A partial write may have been interrupted by a signal (see
           write(2)): run signal handlers before blocking again. */
        if (done == len) {
            *status = WRITE_DONE;
            break;
        }
        if (PyErr_CheckSignals() < 0) {
            break;
        }
    }
    if (*status == WRITE_DONE) {
        nibbler_relock(&self->nib, (PyObject *)self);
    }
    else {
        /* Keep errno for the BlockingIOError, and the exception. */
        buffered_relock_after_raw(self, 1);
    }
    nibbler_end_io(&self->nib);
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
    Py_ssize_t unread = nibbler_drop_unread(&self->nib);
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

/* Make the read-ahead one raw read into a fresh block, after the bytes
   still unread (only TextIOWrapper leaves some, fewer than the capacity:
   a partial character); unbuffered, into a new one of `size` bytes, so
   that no more are read.  Returns the count (0 at EOF), -2 if the raw
   stream would block, or -1 on error. */
static Py_ssize_t
buffered_fill(buffered *self, Py_ssize_t size)
{
    /* A few bytes are copied aside, so that the block can be reused. */
    char aside[512];
    morsel keep = {NULL, NULL, 0};
    if (nibbler_unread(&self->nib) > 0) {
        keep = self->nib.list.items[0];
        if (keep.len <= (Py_ssize_t)sizeof(aside)) {
            memcpy(aside, keep.ptr, keep.len);
            keep = (morsel){NULL, aside, keep.len};
        }
        else {
            Py_INCREF(keep.obj);
        }
    }
    assert(keep.len == 0 || keep.len < self->nib.capacity);
    (void)nibbler_drop_unread(&self->nib);
    /* The read holds its own reference while it uses the block (see
       nibbler_lock_wait()). */
    PyObject *block = (self->nib.capacity > 0
                       ? Py_XNewRef(nibbler_fresh_block(&self->nib))
                       : PyBytes_FromStringAndSize(NULL, size));
    Py_ssize_t n = -1;
    if (block != NULL) {
        char *dst = PyBytes_AS_STRING(block);
        if (keep.len > 0) {
            memcpy(dst, keep.ptr, keep.len);
        }
        int shared = 0;
        n = buffered_raw_read(self, dst + keep.len,
                              PyBytes_GET_SIZE(block) - keep.len, block,
                              &shared);
        Py_ssize_t filled = keep.len + Py_MAX(n, 0);
        if (shared) {
            /* Python code can still write to the block: abandon it to that
               code, and keep a copy of what was read. */
            if (block == self->nib.block) {
                nibbler_set_block(&self->nib, NULL);
            }
            PyObject *copy = PyBytes_FromStringAndSize(dst, filled);
            Py_SETREF(block, copy);
            if (block == NULL) {
                n = -1;
                filled = 0;
            }
        }
        if (filled > 0 && nibbler_publish(&self->nib, block, filled) < 0) {
            n = -1;
        }
        Py_XDECREF(block);
    }
    Py_XDECREF(keep.obj);
    return n;
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
        int err = PyList_Append(chunks, data);
        Py_DECREF(data);
        if (err < 0) {
            data = NULL;
            break;
        }
    }
    if (data == NULL && PyList_GET_SIZE(chunks) > 0) {
        /* A raw read raised (such as a socket timeout): put what was read
           back after the read-ahead, for the next read (gh-51571). */
        PyObject *exc = PyErr_GetRaisedException();
        Py_ssize_t k = nibbler_unread(&self->nib);
        PyObject *rest = PyBytes_Join(Py_GetConstant(Py_CONSTANT_EMPTY_BYTES),
                                      chunks);
        PyObject *all = NULL;
        if (rest != NULL) {
            all = PyBytes_FromStringAndSize(NULL, k + PyBytes_GET_SIZE(rest));
        }
        if (all != NULL) {
            char *dst = PyBytes_AS_STRING(all);
            (void)nibbler_take_into(&self->nib, dst, k);
            memcpy(dst + k, PyBytes_AS_STRING(rest), PyBytes_GET_SIZE(rest));
            (void)nibbler_drop_unread(&self->nib);
            PyErr_SetRaisedException(exc);
            buffered_unread(self, dst, PyBytes_GET_SIZE(all));
        }
        else {
            _PyErr_ChainExceptions1(exc);
        }
        Py_XDECREF(rest);
        Py_XDECREF(all);
    }
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

static PyObject *
buffered_read_all(buffered *self)
{
    PyObject *rest = buffered_raw_read_all(self);
    if (rest == NULL) {
        /* The read-ahead is kept for the next read. */
        return NULL;
    }
    Py_ssize_t restlen = rest == Py_None ? 0 : PyBytes_GET_SIZE(rest);
    PyObject *res = rest;
    Py_ssize_t k = nibbler_unread(&self->nib);
    if (k > 0) {
        res = PyBytes_FromStringAndSize(NULL, k + restlen);
        if (res != NULL) {
            char *dst = PyBytes_AS_STRING(res);
            (void)nibbler_take_into(&self->nib, dst, k);
            if (restlen > 0) {
                memcpy(dst + k, PyBytes_AS_STRING(rest), restlen);
            }
        }
        Py_DECREF(rest);
    }
    /* The raw stream moved past the read-ahead. */
    (void)nibbler_drop_unread(&self->nib);
    return res;
}

static PyObject *
buffered_readline(buffered *self, Py_ssize_t limit)
{
    if (limit == 0) {
        return Py_GetConstant(Py_CONSTANT_EMPTY_BYTES);
    }
    PyBytesWriter *writer = NULL;
    for (;;) {
        if (nibbler_unread(&self->nib) == 0) {
            Py_ssize_t r = buffered_fill(self, 0);
            if (r == -1) {
                if (writer != NULL) {
                    buffered_unread(self, PyBytesWriter_GetData(writer),
                                    PyBytesWriter_GetSize(writer));
                }
                goto error;
            }
            if (r == -2 && (writer == NULL
                            || limit >= 0
                            || (PyBytesWriter_GetSize(writer)
                                < READLINE_KEEP_MAX * self->nib.capacity)))
            {
                /* Would block before the end of the line: keep what there
                   is of it for the next call, and return None. */
                if (writer != NULL) {
                    buffered_unread(self, PyBytesWriter_GetData(writer),
                                    PyBytesWriter_GetSize(writer));
                    PyBytesWriter_Discard(writer);
                    if (PyErr_Occurred()) {
                        return NULL;
                    }
                }
                Py_RETURN_NONE;
            }
            if (r <= 0) {
                break;
            }
        }
        Py_ssize_t k = nibbler_line(&self->nib, limit);
        int done = k >= 0;
        if (done && writer == NULL) {
            /* The whole line was in the read-ahead. */
            return nibbler_take_bytes(&self->nib, k);
        }
        if (!done) {
            /* No end of line in the read-ahead, nor limit reached: take
               all of it. */
            k = nibbler_unread(&self->nib);
        }
        if (writer == NULL) {
            writer = PyBytesWriter_Create(0);
            if (writer == NULL) {
                return NULL;
            }
        }
        Py_ssize_t size = PyBytesWriter_GetSize(writer);
        if (PyBytesWriter_Grow(writer, k) < 0) {
            goto error;
        }
        (void)nibbler_take_into(&self->nib,
                                (char *)PyBytesWriter_GetData(writer) + size,
                                k);
        if (limit >= 0 && (limit -= k) == 0) {
            done = 1;
        }
        if (done) {
            break;
        }
    }
    if (writer == NULL) {
        return Py_GetConstant(Py_CONSTANT_EMPTY_BYTES);
    }
    return PyBytesWriter_Finish(writer);

error:
    PyBytesWriter_Discard(writer);
    return NULL;
}

/*
 * Entering methods
 */

enum {
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
    /* Reading what is already buffered works after close(). */
    int check_closed = (closed_msg != NULL
                        && (direction == WRITING
                            || nibbler_unread(&self->nib) == 0));
    if (check_closed && buffered_check_closed(self, closed_msg) < 0) {
        goto error;
    }
    /* Switch direction: hand back read-ahead before writing, write out
       pending writes before reading. */
    if (direction == WRITING && nibbler_reading(&self->nib) != NULL
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
        && nibbler_reading(&self->nib) == NULL
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
 * Methods
 */

static int
buffered_clear(PyObject *op)
{
    buffered *self = buffered_cast(op);
    Py_XDECREF(buffered_swap_raw(self, NULL));
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
    if (self->dict == NULL) {
        return 1;
    }
    int r = PyDict_Contains(self->dict, &_Py_ID(flush));
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
    Py_ssize_t want = Py_MAX(Py_MIN(size, self->nib.capacity), 1);
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
        n = self->nib.capacity > 0 ? self->nib.capacity : DEFAULT_BUFFER_SIZE;
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
    if (buffered_lock_ready(self) < 0) {
        return NULL;
    }
    PyObject *res = NULL;
    /* Pending writes to a raw stream in append mode go to the end of the
       file: write them out, and the raw position is the logical one
       (gh-80592). */
    if (!self->raw_appending || !buffered_writing(self)
        || buffered_flush_writes(self, 0) == 0)
    {
        res = buffered_position(self);
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
    if (nibbler_reading(&self->nib) != NULL
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
    /* The read-ahead (all that is unread now) is given up. */
    Py_ssize_t unread = nibbler_drop_unread(&self->nib);
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
   the object up for it. */
static int
buffered_init(buffered *self, PyObject *raw, Py_ssize_t buffer_size,
              int readable, int writable)
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
    nibbler_free(&self->nib);
    FT_ATOMIC_STORE_SSIZE_RELAXED(self->nib.capacity,
                                  err == 0 ? buffer_size : 0);
    if (err == 0) {
        self->raw_fileio = (uint8_t)raw_fileio;
        /* Use _writev() only where it can't bypass an overridden write():
           on FileIO itself, or on raw types not derived from it.  (Readers
           skip the lookups.) */
        self->raw_vectored = (
            writable
            && (raw_fileio || !PyObject_TypeCheck(raw, state->PyFileIO_Type))
            && _PyType_Lookup(Py_TYPE(raw), &_Py_ID(_writev)) != NULL);
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
    return buffered_init(self, raw, buffer_size, 1, 0);
}

/*
 * class BufferedWriter
 */

/*[clinic input]
_io.BufferedWriter.__init__
    raw: object
    buffer_size: Py_ssize_t(c_default="DEFAULT_BUFFER_SIZE") = DEFAULT_BUFFER_SIZE

A buffer for a writeable sequential RawIO object.

The constructor creates a BufferedWriter for the given writeable raw
stream. If the buffer_size is not given, it defaults to
DEFAULT_BUFFER_SIZE.
[clinic start generated code]*/

static int
_io_BufferedWriter___init___impl(buffered *self, PyObject *raw,
                                 Py_ssize_t buffer_size)
/*[clinic end generated code: output=c8942a020c0dee64 input=914be9b95e16007b]*/
{
    return buffered_init(self, raw, buffer_size, 0, 1);
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
buffered_write_failed(buffered *self, Py_buffer *buffer, Py_ssize_t done)
{
    if (done == 0) {
        /* None of the data was taken: the caller can just retry. */
        return -1;
    }
    PyObject *exc = PyErr_GetRaisedException();
    Py_ssize_t room = Py_MAX(0, self->nib.capacity
                                - nibbler_nbytes(&self->nib));
    Py_ssize_t keep = Py_MIN(buffer->len - done, room);
    if (buffered_add_write(self, buffer->obj, (const char *)buffer->buf + done,
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
buffered_write_locked(buffered *self, Py_buffer *buffer, Py_ssize_t *done)
{
    const char *data = buffer->buf;
    Py_ssize_t len = buffer->len;
    /* The loop below makes progress; unbuffered, it stops once everything
       is written. */
    assert(self->nib.capacity >= 0);
    if (self->nib.capacity == 0 && self->raw_fileio && len > *done
        && !buffered_writing(self))
    {
        /* Unbuffered: one raw write, without queueing.  Writes made
           meanwhile by signal handlers are written out below. */
        int status;
        *done += buffered_write_direct(self, data + *done, len - *done,
                                       &status);
        if (status == WRITE_ERROR) {
            return buffered_write_failed(self, buffer, *done);
        }
        if (status == WRITE_BLOCKED) {
            buffered_set_blocking_error(*done);
            return -1;
        }
        if (nibbler_nbytes(&self->nib) == 0) {
            return 0;
        }
    }
    while (len - *done >= self->nib.capacity
           || nibbler_nbytes(&self->nib) + (len - *done) > self->nib.capacity)
    {
        if (nibbler_io_busy(&self->nib)) {
            if (nibbler_io_is_mine(&self->nib)) {
                /* gh-118143 */
                return nibbler_append_copy(&self->nib, data + *done,
                                           len - *done);
            }
            return BUFFERED_WRITE_RETRY;
        }
        /* Write out what is pending, and the rest of data with it when one
           vectored write takes both or it is too large to buffer, without
           the lock: other threads can queue writes meanwhile. */
        int status;
        Py_ssize_t rest = len - *done;
        Py_ssize_t direct = (self->raw_vectored || rest >= self->nib.capacity
                             ? rest : 0);
        *done += buffered_write_out(self, nibbler_nbytes(&self->nib),
                                    data + *done, direct, &status, 1);
        if (status == WRITE_ERROR) {
            return buffered_write_failed(self, buffer, *done);
        }
        if (status == WRITE_BLOCKED) {
            Py_ssize_t room = Py_MAX(0, self->nib.capacity
                                        - nibbler_nbytes(&self->nib));
            if (len - *done > room) {
                /* Keep as much of the rest as fits, and report the rest. */
                int errnum = errno;
                if (buffered_add_write(self, buffer->obj, data + *done,
                                       room) == 0)
                {
                    errno = errnum;
                    buffered_set_blocking_error(*done + room);
                }
                return -1;
            }
            break;
        }
        if (*done == len && nibbler_nbytes(&self->nib) == 0) {
            /* Everything was written (unbuffered, nothing ever fits). */
            return 0;
        }
    }
    /* Buffer the rest of data. */
    return buffered_add_write(self, buffer->obj, data + *done, len - *done);
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

/* write() of view->buf[0:view->len], owned by view->obj, with the lock.
   Returns 0 or -1.  Out of line, so that the lock-free paths before it
   stay small. */
Py_NO_INLINE static int
buffered_write_view(buffered *self, Py_buffer *view)
{
    Py_ssize_t done = 0;
    for (;;) {
        if (buffered_enter(self, "write to closed file", WRITING) < 0) {
            return -1;
        }
        int r = buffered_write_locked(self, view, &done);
        if (r == 0) {
            /* The next writes may need no lock. */
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
    Py_buffer view;
    int exported = !PyBytes_CheckExact(obj);
    if (!exported) {
        view = (Py_buffer){.obj = obj, .buf = PyBytes_AS_STRING(obj),
                           .len = PyBytes_GET_SIZE(obj)};
    }
    else if (PyObject_GetBuffer(obj, &view, PyBUF_SIMPLE) < 0) {
        return NULL;
    }
    else if (view.len < NIBBLER_REF_MIN) {
        int r = buffered_write_lockfree(self, view.buf, view.len, 0);
        if (r != 0) {
            PyBuffer_Release(&view);
            return r < 0 ? NULL : PyLong_FromSsize_t(view.len);
        }
    }
    int r = buffered_write_view(self, &view);
    Py_ssize_t len = view.len;
    if (exported) {
        PyBuffer_Release(&view);
    }
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
 * _io._nibbler.TextIOWrapper (textio.c) uses an exact buffered object of
 * ours as the storage of its bytes, through the functions below (see
 * _iomodule.h) instead of its methods: it decodes from the unread bytes
 * and takes only those of the text it returns, and appends what it
 * encodes as write() does.  An instance dict could override the methods,
 * so objects with one are used through them (_PyIO_NIBBLER_NO).
 */

/* peek with the lock: out of line, so that the lock-free path stays
   small. */
Py_NO_INLINE static int
buffered_text_peek_locked(buffered *self, Py_ssize_t need, morsel *m,
                          uint64_t *key)
{
    if (buffered_enter(self, NULL, READING) < 0) {
        return -1;
    }
    /* Not even what is read ahead after close() (unlike reads). */
    int r = buffered_check_closed(self, "I/O operation on closed file.");
    if (r < 0) {
        buffered_unlock(self);
        return -1;
    }
    if (need > self->nib.capacity) {
        /* The unread bytes and more can't fit in a block. */
        r = _PyIO_NIBBLER_FULL;
    }
    else if (nibbler_unread(&self->nib) < need) {
        Py_ssize_t n = buffered_fill(self, 0);
        r = n == -1 ? -1 : n == -2 ? _PyIO_NIBBLER_BLOCKED : 0;
    }
    if (r >= 0 && nibbler_unread(&self->nib) > 0) {
        *m = self->nib.list.items[0];
        Py_INCREF(m->obj);
        *key = nibbler_reading(&self->nib)->id;
    }
    buffered_unlock(self);
    return r;
}

int
_PyIONibbler_peek(PyObject *op, Py_ssize_t need, _PyIO_Morsel *m,
                  uint64_t *key)
{
    buffered *self = buffered_cast(op);
    assert(_PyIO_is_nibbler_buffered_type(Py_TYPE(op)) && need > 0);
    *m = (morsel){NULL, NULL, 0};
    if (self->dict != NULL) {
        return _PyIO_NIBBLER_NO;
    }
    /* Without the lock, at the reading end's position.  (close() drops
       it; after the raw stream alone was closed, what was read ahead can
       still be read, as with read().) */
    nibbler_end *e = nibbler_end_get(&self->nib, 0);
    Py_ssize_t c = e == NULL ? -1 : FT_ATOMIC_LOAD_SSIZE_RELAXED(e->pos);
    if (c >= 0 && e->limit - c >= need) {
        *m = (morsel){Py_NewRef(e->block), PyBytes_AS_STRING(e->block) + c,
                      e->limit - c};
        *key = e->id;
        return 0;
    }
    return buffered_text_peek_locked(self, need, m, key);
}

/* advance with the lock: out of line, so that the lock-free path stays
   small. */
Py_NO_INLINE static int
buffered_text_advance_locked(buffered *self, uint64_t key, Py_ssize_t off,
                             Py_ssize_t n)
{
    /* The caller's reference may be borrowed, and other threads run while
       this waits for the lock. */
    Py_INCREF(self);
    int r = buffered_lock(self);
    if (r == 0) {
        r = buffered_check_closed(self, "I/O operation on closed file.");
        nibbler_end *e = nibbler_reading(&self->nib);
        if (r == 0 && e != NULL && e->id == key
            && nibbler_unread(&self->nib) >= n
            && self->nib.list.items[0].ptr
               == PyBytes_AS_STRING(e->block) + off)
        {
            (void)morsels_consume(&self->nib.list, n);
            r = 1;
        }
        buffered_unlock(self);
    }
    Py_DECREF(self);
    return r;
}

int
_PyIONibbler_advance(PyObject *op, uint64_t key, Py_ssize_t off,
                     Py_ssize_t n)
{
    buffered *self = buffered_cast(op);
    /* Without the lock: move the reading end's position from off, if it
       is still there (see _PyIONibbler_peek()). */
    nibbler_end *e = nibbler_end_get(&self->nib, 0);
    if (e != NULL && e->id == key && n <= e->limit - off) {
        Py_ssize_t c = off;
        if (FT_ATOMIC_COMPARE_EXCHANGE_SSIZE(e->pos, &c, off + n)) {
            return 1;
        }
        if (c >= 0) {
            return 0;
        }
    }
    /* The end is held, or gone, or the raw stream must be asked. */
    return buffered_text_advance_locked(self, key, off, n);
}

/* Is the raw stream an exact FileIO that is closed?  Then nothing is
   appended without the lock (writes raise instead). */
static inline int
buffered_fileio_closed(buffered *self)
{
    return (self->raw_fileio
            && _PyFileIO_closed(FT_ATOMIC_LOAD_PTR_RELAXED(self->raw)));
}

int
_PyIONibbler_write(PyObject *op, PyObject *obj, const char *data,
                   Py_ssize_t len)
{
    buffered *self = buffered_cast(op);
    assert(buffered_writable(self));
    if (self->dict != NULL) {
        return _PyIO_NIBBLER_NO;
    }
    int r = (len < NIBBLER_REF_MIN
             ? buffered_write_lockfree(self, data, len, 0) : 0);
    if (r != 0) {
        return r < 0 ? -1 : 0;
    }
    /* The caller's reference is borrowed: raw.write() could drop it. */
    Py_INCREF(self);
    Py_buffer view = {.obj = obj, .buf = (void *)data, .len = len};
    r = buffered_write_view(self, &view);
    Py_DECREF(self);
    return r;
}

char *
_PyIONibbler_reserve(PyObject *op, Py_ssize_t len, void **end)
{
    buffered *self = buffered_cast(op);
    nibbler_end *e;
    Py_ssize_t r;
    if (self->dict == NULL && len < NIBBLER_REF_MIN
        && (e = nibbler_end_get(&self->nib, 1)) != NULL
        && !buffered_fileio_closed(self)
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

int
_PyIONibbler_closed(PyObject *op)
{
    buffered *self = buffered_cast(op);
    PyObject *raw = buffered_get_raw(self);
    if (raw == NULL) {
        return -1;
    }
    int r;
    if (self->raw_fileio) {
        r = _PyFileIO_closed(raw);
    }
    else {
        PyObject *res = PyObject_GetAttr(raw, &_Py_ID(closed));
        r = res == NULL ? -1 : PyObject_IsTrue(res);
        Py_XDECREF(res);
    }
    Py_DECREF(raw);
    return r;
}

/*
 * class BufferedRandom
 */

/*[clinic input]
_io.BufferedRandom.__init__
    raw: object
    buffer_size: Py_ssize_t(c_default="DEFAULT_BUFFER_SIZE") = DEFAULT_BUFFER_SIZE

A buffered interface to random access streams.

The constructor creates a reader and writer for a seekable stream,
raw, given in the first argument. If the buffer_size is omitted it
defaults to DEFAULT_BUFFER_SIZE.
[clinic start generated code]*/

static int
_io_BufferedRandom___init___impl(buffered *self, PyObject *raw,
                                 Py_ssize_t buffer_size)
/*[clinic end generated code: output=d3d64eb0f64e64a3 input=a4e818fb86d0e50c]*/
{
    return buffered_init(self, raw, buffer_size, 1, 1);
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
             mod, &nibbler_bufferedrandom_spec, base, prefix)) == NULL
        || (state->PyTextIOWrapper_Type = nibbler_add_type(
             mod, &_PyIONibbler_textiowrapper_spec,
             io_state->PyTextIOBase_Type, prefix)) == NULL)
    {
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


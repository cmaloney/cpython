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
#include "pycore_lock.h"                // PyMutex_LockFast()
#include "pycore_object.h"              // _PyObject_GC_UNTRACK()
#include "pycore_pyerrors.h"            // _PyErr_ChainExceptions1()
#include "pycore_pylifecycle.h"         // _Py_IsInterpreterFinalizing()
#include "pycore_weakref.h"             // FT_CLEAR_WEAKREFS()

#include "_iomodule.h"

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
} nibbler_state;

static struct PyModuleDef _PyIO_nibbler_Module;

static inline nibbler_state *
get_nibbler_state(PyObject *module)
{
    void *state = _PyModule_GetState(module);
    assert(state != NULL);
    return (nibbler_state *)state;
}

static inline nibbler_state *
find_nibbler_state_by_def(PyTypeObject *type)
{
    PyObject *mod = PyType_GetModuleByDef(type, &_PyIO_nibbler_Module);
    assert(mod != NULL);
    return get_nibbler_state(mod);
}

/*
 * BufferedReader, BufferedWriter and BufferedRandom share one object layout
 * and most methods.
 *
 * Buffered data is a list of morsels: runs of bytes inside bytes objects.
 * Data flows in one direction at a time:
 *
 * - Writing: the morsels are pending writes, oldest first.  Large exact
 *   bytes objects are kept by reference; everything else is copied into
 *   `block`, a bytes object of buffer_size bytes filled in order.  The
 *   morsels are written together, in one call when the raw stream has a
 *   vectored _writev() method.
 *
 * - Reading: there is at most one morsel, the bytes the last fill read into
 *   `block`.  Its pointer is the read position: the bytes before it were
 *   returned already (seek() can move back over them), the rest are
 *   read-ahead.  Reading a whole fill hands out the block itself.
 *
 * BufferedRandom switches direction as needed: before writing it hands
 * unread read-ahead back to the raw stream (by seeking), and before reading
 * it writes out everything pending.  So the logical position is always the
 * raw position plus pending writes, or minus unread read-ahead.
 *
 * A block is only filled or copied into while nothing else references it,
 * so a bytes object never changes once a morsel was handed out or written
 * through a Python-level raw stream.
 */

enum {
    /* Exact bytes writes at least this large are kept by reference instead
       of being copied, when the raw stream takes vectored writes. */
    WREF_MIN = 512,
};

/* A run of bytes inside the bytes object obj, which keeps them alive. */
typedef struct {
    PyObject *obj;
    const char *ptr;
    Py_ssize_t len;
} morsel;

/* Morsels in order, with their total length. */
typedef struct {
    morsel *items;
    Py_ssize_t count;
    Py_ssize_t capacity;
    Py_ssize_t nbytes;
} morsel_list;

static void
morsels_clear(morsel_list *list)
{
    for (Py_ssize_t i = 0; i < list->count; i++) {
        Py_DECREF(list->items[i].obj);
    }
    list->count = 0;
    list->nbytes = 0;
}

static void
morsels_free(morsel_list *list)
{
    morsels_clear(list);
    PyMem_Free(list->items);
    list->items = NULL;
    list->capacity = 0;
}

/* Append ptr[0:len], inside obj; extends the last morsel when contiguous. */
static int
morsels_push(morsel_list *list, PyObject *obj, const char *ptr,
             Py_ssize_t len)
{
    morsel *last = list->count > 0 ? &list->items[list->count - 1] : NULL;
    if (last != NULL && last->obj == obj && last->ptr + last->len == ptr) {
        last->len += len;
    }
    else {
        if (list->count == list->capacity) {
            Py_ssize_t capacity = list->capacity ? 2 * list->capacity : 8;
            morsel *items = PyMem_Realloc(list->items,
                                          capacity * sizeof(morsel));
            if (items == NULL) {
                PyErr_NoMemory();
                return -1;
            }
            list->items = items;
            list->capacity = capacity;
        }
        list->items[list->count++] = (morsel){Py_NewRef(obj), ptr, len};
    }
    list->nbytes += len;
    return 0;
}

/* Drop n bytes from the front.  Returns how many there were (up to n). */
static Py_ssize_t
morsels_consume(morsel_list *list, Py_ssize_t n)
{
    Py_ssize_t taken = 0;
    Py_ssize_t done = 0;
    for (; done < list->count; done++) {
        morsel *m = &list->items[done];
        Py_ssize_t k = Py_MIN(m->len, n - taken);
        m->ptr += k;
        m->len -= k;
        taken += k;
        if (m->len > 0) {
            break;
        }
        Py_DECREF(m->obj);
    }
    list->count -= done;
    memmove(list->items, list->items + done,
            (size_t)list->count * sizeof(morsel));
    list->nbytes -= taken;
    return taken;
}

typedef struct {
    PyObject_HEAD

    /* NULL until initialized, None after detach().  Only replaced with the
       lock held (and from GC clear and dealloc): code holding the lock uses
       it directly, code without takes a reference with buffered_get_raw().
       Everything below is set by __init__() and, unless noted, changed only
       with the lock held. */
    PyObject *raw;
    char finalizing;
    /* Fixed by __init__(): writable, raw exactly FileIO (call its C
       implementation directly), raw has a vectored _writev() method. */
    uint8_t writable;
    uint8_t raw_fileio;
    uint8_t raw_vectored;
    /* buf holds pending writes rather than read-ahead. */
    uint8_t writing;
    /* close() has run (also read without the lock, by __sizeof__()). */
    uint8_t released;
    /* A raw write of the pending writes is in progress. */
    uint8_t raw_writing;

    Py_ssize_t buffer_size;
    morsel_list buf;
    /* Bytes object of buffer_size bytes that fills read into and small
       writes are copied into; NULL until needed. */
    PyObject *block;

    /* Held across raw I/O.  owner detects reentrant calls (a signal handler
       or finalizer running mid-I/O), which raise instead of deadlocking. */
    PyMutex lock;
    PyThreadState *owner;

    PyObject *dict;
    PyObject *weakreflist;
} buffered;

static inline buffered *
buffered_cast(PyObject *op)
{
    return (buffered *)op;
}

/* Slow path of buffered_lock(): another thread, or this one reentering,
   holds the lock. */
static int
buffered_lock_wait(buffered *self, PyThreadState *tstate)
{
    if (_Py_atomic_load_ptr_relaxed(&self->owner) == tstate) {
        PyErr_Format(PyExc_RuntimeError, "reentrant call inside %R", self);
        return -1;
    }
    if (!_Py_IsInterpreterFinalizing(tstate->interp)) {
        PyMutex_LockFlags(&self->lock, _PY_LOCK_DETACH);
        return 0;
    }
    /* Finalizing: every other thread hangs as soon as it attaches again,
       and the lock is only released by an attached thread, so its holder
       (a daemon thread) never will.  It holds it across a raw call or has
       just taken it, when the buffered state is consistent: take over.
       The lock stays locked; the caller unlocks it as if it had taken it.
       Give up on that raw call: what it writes may or may not reach the
       stream, and a system call may still be using the memory it was
       given, so drop its writes and the block without freeing them. */
    if (self->raw_writing) {
        self->buf = (morsel_list){0};  /* leaked */
        self->raw_writing = 0;
    }
    self->block = NULL;  /* leaked */
    return 0;
}

static inline int
buffered_lock(buffered *self)
{
    PyThreadState *tstate = _PyThreadState_GET();
    if (!PyMutex_LockFast(&self->lock)
        && buffered_lock_wait(self, tstate) < 0)
    {
        return -1;
    }
    _Py_atomic_store_ptr_relaxed(&self->owner, tstate);
    return 0;
}

static inline void
buffered_unlock(buffered *self)
{
    _Py_atomic_store_ptr_relaxed(&self->owner, NULL);
    PyMutex_Unlock(&self->lock);
}

/* raw is set and not detached. */
static inline int
buffered_raw_usable(PyObject *raw)
{
    return raw != NULL && raw != Py_None;
}

static int
buffered_not_ready(buffered *self)
{
    PyErr_SetString(PyExc_ValueError,
                    FT_ATOMIC_LOAD_PTR(self->raw) == Py_None
                    ? "raw stream has been detached"
                    : "I/O operation on uninitialized object");
    return -1;
}

/* A new reference to raw (NULL or None when uninitialized or detached).
   Needs no lock: a concurrent detach() leaves the caller using the stream
   it took. */
static inline PyObject *
buffered_ref_raw(buffered *self)
{
#ifdef Py_GIL_DISABLED
    return _Py_XGetRef(&self->raw);
#else
    return Py_XNewRef(self->raw);
#endif
}

/* A new reference to a usable raw, or NULL with ValueError. */
static PyObject *
buffered_get_raw(buffered *self)
{
    PyObject *raw = buffered_ref_raw(self);
    if (!buffered_raw_usable(raw)) {
        Py_XDECREF(raw);
        buffered_not_ready(self);
        return NULL;
    }
    return raw;
}

/* Replace raw (with the lock held, or with no other users) and return the
   old one. */
static PyObject *
buffered_swap_raw(buffered *self, PyObject *raw)
{
#ifdef Py_GIL_DISABLED
    if (raw != NULL) {
        /* Lets buffered_ref_raw() take references without the lock. */
        _PyObject_SetMaybeWeakref(raw);
    }
#endif
    return _Py_atomic_exchange_ptr(&self->raw, raw);
}

/* Lock the object and check it is initialized and attached.  On success
   the caller must unlock. */
static int
buffered_lock_ready(buffered *self)
{
    if (buffered_lock(self) < 0) {
        return -1;
    }
    if (!buffered_raw_usable(self->raw)) {
        buffered_unlock(self);
        return buffered_not_ready(self);
    }
    return 0;
}

/* The read-ahead morsel, or NULL when there is none. */
static inline morsel *
buffered_ahead(buffered *self)
{
    return self->writing || self->buf.count == 0 ? NULL : &self->buf.items[0];
}

static inline Py_ssize_t
buffered_readahead(buffered *self)
{
    return self->writing ? 0 : self->buf.nbytes;
}

/* Returns 1 if closed, 0 if open, -1 on error. */
static int
buffered_is_closed(buffered *self)
{
    if (self->released) {
        return 1;
    }
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

/* Raise ValueError(closed_msg) if closed. */
static int
buffered_check_closed(buffered *self, const char *closed_msg)
{
    int closed = buffered_is_closed(self);
    if (closed > 0) {
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

/* Discard all buffered data and release the memory holding it. */
static void
buffered_drop_buffers(buffered *self)
{
    morsels_free(&self->buf);
    Py_CLEAR(self->block);
}

/* The block, when nothing but this object references it (then all of it
   can be overwritten); else a new one. */
static PyObject *
buffered_fresh_block(buffered *self)
{
    if (self->block == NULL || !_PyObject_IsUniquelyReferenced(self->block)) {
        PyObject *block = PyBytes_FromStringAndSize(NULL, self->buffer_size);
        if (block == NULL) {
            return NULL;
        }
        Py_XSETREF(self->block, block);
    }
    return self->block;
}

/*
 * Raw stream calls
 */

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

/* One raw readinto() of up to len bytes.  Returns the count (0 at EOF),
   -2 if the raw stream would block, or -1 on error. */
static Py_ssize_t
buffered_raw_read(buffered *self, char *dst, Py_ssize_t len)
{
    if (self->raw_fileio) {
        return _PyFileIO_readinto(self->raw, dst, len);
    }
    PyObject *view = PyMemoryView_FromMemory(dst, len, PyBUF_WRITE);
    if (view == NULL) {
        return -1;
    }
    /* PyErr_SetFromErrno() runs signal handlers on EINTR; retry if none
       raised (see issue #10956). */
    PyObject *res;
    do {
        res = PyObject_CallMethodOneArg(self->raw, &_Py_ID(readinto), view);
    } while (res == NULL && _PyIO_trap_eintr());
    Py_DECREF(view);
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

/* One raw write of the pending writes followed by extra (a morsel of data
   not yet in buf, or with len 0): as much as one vectored write takes when
   the raw stream has _writev(), else the first morsel.  Returns the count,
   -2 if the raw stream would block (errno set for the BlockingIOError), or
   -1 on error. */
static Py_ssize_t
buffered_raw_write(buffered *self, const morsel *extra)
{
    morsel pieces[_PyIO_WRITEV_MAX];
    Py_ssize_t limit = self->raw_vectored ? _PyIO_WRITEV_MAX : 1;
    Py_ssize_t cnt = Py_MIN(self->buf.count, limit);
    Py_ssize_t total = 0;
    if (cnt > 0) {
        memcpy(pieces, self->buf.items, (size_t)cnt * sizeof(morsel));
    }
    if (extra->len > 0 && cnt < limit) {
        pieces[cnt++] = *extra;
    }
    assert(cnt > 0);

    if (self->raw_fileio) {
        _PyIO_Span spans[_PyIO_WRITEV_MAX];
        for (Py_ssize_t i = 0; i < cnt; i++) {
            spans[i] = (_PyIO_Span){pieces[i].ptr, pieces[i].len};
        }
        return _PyFileIO_writev(self->raw, spans, cnt);
    }

    /* Python code may keep the views (and reach the block through them): it
       must not be written to again. */
    Py_CLEAR(self->block);
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
    for (Py_ssize_t i = 0; i < cnt; i++) {
        total += pieces[i].len;
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
    Py_DECREF(arg);
    Py_ssize_t n = buffered_raw_result(res, total, method);
    /* Decrefs may have changed errno, which the BlockingIOError reports. */
    errno = errnum;
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
    pos += self->writing ? self->buf.nbytes : -self->buf.nbytes;
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
    assert(self->writing);
    assert(self->buf.nbytes + len <= self->buffer_size);
    if (len == 0) {
        return 0;
    }
    if (self->raw_vectored && len >= WREF_MIN && obj != NULL
        && PyBytes_CheckExact(obj))
    {
        return morsels_push(&self->buf, obj, data, len);
    }

    /* Copy into the block after the last pending copy in it, or into a
       fresh block. */
    Py_ssize_t used = -1;
    for (Py_ssize_t i = self->buf.count - 1; i >= 0; i--) {
        morsel *m = &self->buf.items[i];
        if (m->obj == self->block) {
            used = m->ptr + m->len - PyBytes_AS_STRING(self->block);
            break;
        }
    }
    if (used < 0 || self->buffer_size - used < len) {
        if (buffered_fresh_block(self) == NULL) {
            return -1;
        }
        used = 0;
    }
    char *dst = PyBytes_AS_STRING(self->block) + used;
    memcpy(dst, data, len);
    return morsels_push(&self->buf, self->block, dst, len);
}

/* Write the pending writes followed by data[0:len] until all of it is
   written or the raw stream would block (*blocked is then set).  Written
   bytes are dropped as they go, so on error the unwritten rest is still
   pending.  Returns how much of data was written, or -1 on error. */
static Py_ssize_t
buffered_write_out(buffered *self, const char *data, Py_ssize_t len,
                   int *blocked)
{
    morsel extra = {NULL, data, len};
    *blocked = 0;
    while (self->buf.count > 0 || extra.len > 0) {
        self->raw_writing = 1;
        Py_ssize_t n = buffered_raw_write(self, &extra);
        self->raw_writing = 0;
        if (n == -1) {
            return -1;
        }
        if (n == -2) {
            *blocked = 1;
            break;
        }
        n -= morsels_consume(&self->buf, n);
        extra.ptr += n;
        extra.len -= n;
        /* Partial writes can return successfully when interrupted by a
           signal (see write(2)).  Run signal handlers before blocking
           another time, possibly indefinitely. */
        if (PyErr_CheckSignals() < 0) {
            return -1;
        }
    }
    return len - extra.len;
}

/* Write out everything pending; BlockingIOError if the raw stream would
   block, keeping what is unwritten. */
static int
buffered_flush_writes(buffered *self)
{
    assert(self->writing);
    int blocked;
    if (buffered_write_out(self, NULL, 0, &blocked) < 0) {
        return -1;
    }
    if (blocked) {
        buffered_set_blocking_error(0);
        return -1;
    }
    return 0;
}

/* Hand unread read-ahead back to the raw stream, so the raw position is
   the logical one. */
static int
buffered_rewind(buffered *self)
{
    Py_ssize_t avail = buffered_readahead(self);
    if (avail > 0 && buffered_raw_seek(self, -avail, SEEK_CUR) < 0) {
        return -1;
    }
    morsels_clear(&self->buf);
    return 0;
}

/* Bring the raw stream to the logical position: write out pending writes
   or hand back read-ahead. */
static int
buffered_sync(buffered *self)
{
    return self->writing ? buffered_flush_writes(self) : buffered_rewind(self);
}

/* Switch between holding read-ahead and pending writes. */
static int
buffered_switch_direction(buffered *self)
{
    if (buffered_sync(self) < 0) {
        return -1;
    }
    self->writing = !self->writing;
    return 0;
}

/*
 * Reading
 */

/* Return the bytes object of a morsel that covers all of it.  Handing out
   the block gives it away: copied writes go into self->block in place, so
   it must never be visible outside. */
static PyObject *
buffered_hand_out(buffered *self, const morsel *m)
{
    if (m->obj == self->block) {
        Py_CLEAR(self->block);
    }
    return Py_NewRef(m->obj);
}

/* Return n bytes of read-ahead as a bytes object: the block itself, without
   a copy, when that is all of it. */
static PyObject *
buffered_take_bytes(buffered *self, Py_ssize_t n)
{
    morsel *m = buffered_ahead(self);
    if (n == 0 || m == NULL) {
        return Py_GetConstant(Py_CONSTANT_EMPTY_BYTES);
    }
    assert(n <= m->len);
    PyObject *res;
    if (m->ptr == PyBytes_AS_STRING(m->obj)
        && n == PyBytes_GET_SIZE(m->obj))
    {
        res = buffered_hand_out(self, m);
    }
    else {
        res = PyBytes_FromStringAndSize(m->ptr, n);
        if (res == NULL) {
            return NULL;
        }
    }
    m->ptr += n;
    m->len -= n;
    self->buf.nbytes -= n;
    return res;
}

/* Copy up to len bytes of read-ahead to dst.  Returns the count. */
static Py_ssize_t
buffered_take(buffered *self, char *dst, Py_ssize_t len)
{
    morsel *m = buffered_ahead(self);
    Py_ssize_t n = m == NULL ? 0 : Py_MIN(len, m->len);
    if (n > 0) {
        memcpy(dst, m->ptr, n);
        m->ptr += n;
        m->len -= n;
        self->buf.nbytes -= n;
    }
    return n;
}

/* Replace the (used up) read-ahead with one raw read into a fresh block.
   Returns the count (0 at EOF), -2 if the raw stream would block, or -1 on
   error. */
static Py_ssize_t
buffered_fill(buffered *self)
{
    assert(buffered_readahead(self) == 0);
    morsels_clear(&self->buf);
    PyObject *block = buffered_fresh_block(self);
    if (block == NULL) {
        return -1;
    }
    char *start = PyBytes_AS_STRING(block);
    Py_ssize_t n = buffered_raw_read(self, start, self->buffer_size);
    if (n > 0 && morsels_push(&self->buf, block, start, n) < 0) {
        return -1;
    }
    return n;
}

/* Read up to len bytes into dst: read-ahead first, then from the raw
   stream until len bytes, EOF, or the raw stream would block.  A request
   of at least a buffer's worth is read directly into dst, smaller ones
   through the read-ahead.  read1 makes at most one raw read, and none into
   the read-ahead once there is data to return.  Returns the count, -2 if
   the raw stream would block before anything was read, or -1 on error. */
static Py_ssize_t
buffered_read_into(buffered *self, char *dst, Py_ssize_t len, int read1)
{
    Py_ssize_t written = 0;
    for (int reads = 0; ; reads++) {
        written += buffered_take(self, dst + written, len - written);
        Py_ssize_t remaining = len - written;
        if (remaining == 0 || (read1 && reads > 0)) {
            break;
        }
        Py_ssize_t n;
        if (remaining >= self->buffer_size) {
            /* Bypasses the read-ahead, which no longer precedes the raw
               position. */
            morsels_clear(&self->buf);
            n = buffered_raw_read(self, dst + written, remaining);
            written += Py_MAX(n, 0);
        }
        else if (read1 && written > 0) {
            break;
        }
        else {
            /* Copied out on the next pass. */
            n = buffered_fill(self);
        }
        if (n == 0 || (n == -2 && written > 0)) {
            break;
        }
        if (n < 0) {
            return n;
        }
    }
    return written;
}

/* read(n) and read1(n). */
static PyObject *
buffered_read_bytes(buffered *self, Py_ssize_t n, int read1)
{
    Py_ssize_t avail = buffered_readahead(self);
    if (read1 && avail == 0 && n > 0 && n < self->buffer_size) {
        /* One raw read into the read-ahead: then all of it may be handed
           out without a copy. */
        Py_ssize_t r = buffered_fill(self);
        if (r <= 0) {
            /* EOF, or would block. */
            return r == -1 ? NULL : Py_GetConstant(Py_CONSTANT_EMPTY_BYTES);
        }
        avail = buffered_readahead(self);
    }
    if (n <= avail || (read1 && avail > 0)) {
        return buffered_take_bytes(self, Py_MIN(n, avail));
    }
    PyBytesWriter *writer = PyBytesWriter_Create(n);
    if (writer == NULL) {
        return NULL;
    }
    Py_ssize_t r = buffered_read_into(self, PyBytesWriter_GetData(writer), n,
                                      read1);
    if (r < 0) {
        PyBytesWriter_Discard(writer);
        if (r == -2 && !read1) {
            Py_RETURN_NONE;
        }
        return r == -2 ? Py_GetConstant(Py_CONSTANT_EMPTY_BYTES) : NULL;
    }
    return PyBytesWriter_FinishWithSize(writer, r);
}

/* Call raw.read() until EOF or it would block.  Returns the joined data,
   or the final b"" or None when there was none. */
static PyObject *
buffered_read_chunks(buffered *self)
{
    PyObject *chunks = PyList_New(0);
    if (chunks == NULL) {
        return NULL;
    }
    PyObject *data;
    for (;;) {
        data = PyObject_CallMethodNoArgs(self->raw, &_Py_ID(read));
        if (data == NULL) {
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
        return buffered_read_chunks(self);
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
    if (buffered_readahead(self) > 0) {
        res = PyBytes_FromStringAndSize(NULL, buffered_readahead(self)
                                              + restlen);
        if (res != NULL) {
            Py_ssize_t n = buffered_take(self, PyBytes_AS_STRING(res),
                                         PyBytes_GET_SIZE(res));
            if (restlen > 0) {
                memcpy(PyBytes_AS_STRING(res) + n, PyBytes_AS_STRING(rest),
                       restlen);
            }
        }
        Py_DECREF(rest);
    }
    /* The raw stream moved past the read-ahead. */
    morsels_clear(&self->buf);
    return res;
}

static PyObject *
buffered_readline(buffered *self, Py_ssize_t limit)
{
    /* Usually the whole line is in the read-ahead. */
    morsel *m = buffered_ahead(self);
    if (m != NULL) {
        Py_ssize_t n = limit >= 0 && limit < m->len ? limit : m->len;
        const char *s = memchr(m->ptr, '\n', n);
        if (s != NULL || n == limit) {
            return buffered_take_bytes(self, s ? s - m->ptr + 1 : n);
        }
    }

    PyBytesWriter *writer = NULL;
    for (;;) {
        if (buffered_readahead(self) == 0 && limit != 0) {
            Py_ssize_t r = buffered_fill(self);
            if (r == -1) {
                goto error;
            }
            if (r <= 0) {
                break;
            }
        }
        m = buffered_ahead(self);
        Py_ssize_t n = m == NULL ? 0 : m->len;
        if (limit >= 0 && n > limit) {
            n = limit;
        }
        const char *s = n > 0 ? memchr(m->ptr, '\n', n) : NULL;
        if (s != NULL) {
            n = s - m->ptr + 1;
        }
        int done = s != NULL || n == limit;
        if (done && writer == NULL) {
            /* The whole line was in the read-ahead. */
            return buffered_take_bytes(self, n);
        }
        if (writer == NULL) {
            writer = PyBytesWriter_Create(0);
            if (writer == NULL) {
                return NULL;
            }
        }
        if (n > 0) {
            if (PyBytesWriter_WriteBytes(writer, m->ptr, n) < 0) {
                goto error;
            }
            m->ptr += n;
            m->len -= n;
            self->buf.nbytes -= n;
        }
        if (limit >= 0) {
            limit -= n;
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
    buffered_drop_buffers(self);
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
    if (!FT_ATOMIC_LOAD_UINT8_RELAXED(self->released)) {
        res += (size_t)self->buffer_size;
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
    return self->writable ? buffered_sync(self) : buffered_raw_flush(self);
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
    /* Without the lock: call the method on the stream taken. */
    PyObject *raw = buffered_get_raw(self);
    if (raw == NULL) {
        return NULL;
    }
    PyObject *res = PyObject_CallMethodNoArgs(raw, &_Py_ID(flush));
    Py_DECREF(raw);
    return res;
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
    /* gh-138720: Use the same closed check as flush(). */
    int r = buffered_is_closed(self);
    if (r != 0) {
        res = r > 0 ? Py_NewRef(Py_None) : NULL;
        goto end;
    }
    if (self->finalizing) {
        PyObject *w = _io__Buffered__dealloc_warn_impl(self, (PyObject *)self);
        if (w) {
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

    res = self->raw_fileio ? _PyFileIO_close(self->raw)
                           : PyObject_CallMethodNoArgs(self->raw,
                                                       &_Py_ID(close));
    buffered_drop_buffers(self);
    FT_ATOMIC_STORE_UINT8_RELAXED(self->released, 1);

    if (exc != NULL) {
        _PyErr_ChainExceptions1(exc);
        Py_CLEAR(res);
    }
end:
    buffered_unlock(self);
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
    if (!buffered_raw_usable(FT_ATOMIC_LOAD_PTR(self->raw))) {
        buffered_not_ready(self);
        return NULL;
    }
    if (_PyFile_Flush((PyObject *)self) < 0 || buffered_lock_ready(self) < 0) {
        return NULL;
    }
    /* Also write out what other threads wrote since flush(). */
    if (self->writable && buffered_sync(self) < 0) {
        buffered_unlock(self);
        return NULL;
    }
    PyObject *raw = buffered_swap_raw(self, Py_None);
    buffered_drop_buffers(self);
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

enum {
    KEEP_DIRECTION = -1,
    READING = 0,
    WRITING = 1,
};

/* The rest of buffered_enter(), with the lock held. */
static int
buffered_enter_locked(buffered *self, const char *closed_msg, int direction)
{
    if (!buffered_raw_usable(self->raw)) {
        buffered_unlock(self);
        return buffered_not_ready(self);
    }
    /* Reading what is already buffered works after close(). */
    int check_closed = direction == WRITING || buffered_readahead(self) == 0;
    if (check_closed && buffered_check_closed(self, closed_msg) < 0) {
        goto error;
    }
    if (direction != KEEP_DIRECTION && self->writing != direction
        && buffered_switch_direction(self) < 0)
    {
        goto error;
    }
    return 0;

error:
    buffered_unlock(self);
    return -1;
}

/* Common start of the I/O methods: lock the object, check it is
   initialized and open, and make it buffer in the given direction.
   Closed is checked with the lock held since another thread could be
   holding it while closing the file (issue #31976); leftover read-ahead
   can still be used except by writes.  Reading from the read-ahead, the
   common case, needs none of the checks.  On success the caller must
   unlock. */
static inline int
buffered_enter(buffered *self, const char *closed_msg, int direction)
{
    if (buffered_lock(self) < 0) {
        return -1;
    }
    if (direction == READING && buffered_readahead(self) > 0
        && buffered_raw_usable(self->raw))
    {
        return 0;
    }
    return buffered_enter_locked(self, closed_msg, direction);
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
    int r = buffered_sync(self);
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
    if (buffered_enter(self, "peek of closed file", READING) < 0) {
        return NULL;
    }
    PyObject *res = NULL;
    /* Either return the read-ahead or refill it, never both: refilling a
       partly consumed buffer would lose block alignment. */
    if (buffered_readahead(self) > 0 || buffered_fill(self) != -1) {
        morsel *m = buffered_ahead(self);
        if (m == NULL || m->len == 0) {
            res = Py_GetConstant(Py_CONSTANT_EMPTY_BYTES);
        }
        else if (m->ptr == PyBytes_AS_STRING(m->obj)
                 && m->len == PyBytes_GET_SIZE(m->obj))
        {
            /* All of the block: no copy. */
            res = buffered_hand_out(self, m);
        }
        else {
            res = PyBytes_FromStringAndSize(m->ptr, m->len);
        }
    }
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
    /* read(0) needs no read-ahead: don't make BufferedRandom write out
       pending data for it. */
    if (buffered_enter(self, "read of closed file",
                       n == 0 ? KEEP_DIRECTION : READING) < 0)
    {
        return NULL;
    }
    PyObject *res = n == -1 ? buffered_read_all(self)
                            : buffered_read_bytes(self, n, 0);
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
    if (buffered_enter(self, "read of closed file",
                       n == 0 ? KEEP_DIRECTION : READING) < 0)
    {
        return NULL;
    }
    PyObject *res = buffered_read_bytes(self, n < 0 ? self->buffer_size : n,
                                        1);
    buffered_unlock(self);
    return res;
}

static PyObject *
buffered_readinto_common(buffered *self, Py_buffer *buffer, int readinto1)
{
    if (buffered_enter(self, "readinto of closed file", READING) < 0) {
        return NULL;
    }
    Py_ssize_t n = buffered_read_into(self, buffer->buf, buffer->len,
                                      readinto1);
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

/*[clinic input]
_io._Buffered.readline
    size: Py_ssize_t(accept={int, NoneType}) = -1
    /
[clinic start generated code]*/

static PyObject *
_io__Buffered_readline_impl(buffered *self, Py_ssize_t size)
/*[clinic end generated code: output=24dd2aa6e33be83c input=673b6240e315ef8a]*/
{
    if (buffered_enter(self, "readline of closed file",
                       size == 0 ? KEEP_DIRECTION : READING) < 0)
    {
        return NULL;
    }
    PyObject *res = buffered_readline(self, size);
    buffered_unlock(self);
    return res;
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
    PyObject *res = buffered_position(self);
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
    /* Do some error checking instead of trusting OS 'seek()'
    ** error detection, just in case.
    */
    if ((whence < 0 || whence > 2)
#ifdef SEEK_HOLE
        && (whence != SEEK_HOLE)
#endif
#ifdef SEEK_DATA
        && (whence != SEEK_DATA)
#endif
        ) {
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
    Py_ssize_t avail = buffered_readahead(self);
    morsel *m = buffered_ahead(self);
    if (m != NULL && (whence == SEEK_SET || whence == SEEK_CUR)) {
        /* Move within the last fill if the target is in it: its bytes are
           the ones before the raw position, read up to m->ptr. */
        Py_ssize_t done = m->ptr - PyBytes_AS_STRING(m->obj);
        Py_off_t raw_pos = -1;
        Py_off_t offset = target;   /* from the current position */
        if (whence == SEEK_SET) {
            raw_pos = buffered_raw_tell(self);
            if (raw_pos == -1) {
                goto end;
            }
            offset = target - (raw_pos - avail);
        }
        if (offset >= -done && offset <= avail) {
            if (raw_pos == -1 && (raw_pos = buffered_raw_tell(self)) == -1) {
                goto end;
            }
            m->ptr += offset;
            m->len -= offset;
            self->buf.nbytes -= offset;
            Py_off_t pos = raw_pos - m->len;
            // GH-95782
            res = PyLong_FromOff_t(pos < 0 ? 0 : pos);
            goto end;
        }
    }
    if (!self->writing || buffered_flush_writes(self) == 0) {
        if (whence == SEEK_CUR) {
            target -= avail;
        }
        Py_off_t pos = buffered_raw_seek(self, target, whence);
        if (pos != -1) {
            if (!self->writing) {
                morsels_clear(&self->buf);
            }
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
    if (!self->writable) {
        _PyIO_State *state = find_io_state_by_def(cls);
        PyErr_SetString(state->unsupported_operation, "truncate");
    }
    else if (buffered_sync(self) == 0) {
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
        /* Skip method call overhead for speed */
        line = _io__Buffered_readline_impl(self, -1);
    }
    else {
        line = PyObject_CallMethodNoArgs((PyObject *)self,
                                             &_Py_ID(readline));
        if (line && !PyBytes_Check(line)) {
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

/* Shared constructor: check raw supports the needed operations, then set
   the object up for it. */
/* Check raw supports what the class needs (BufferedRandom: seeking too). */
static int
buffered_check_raw(_PyIO_State *state, PyObject *raw, int raw_fileio,
                   int readable, int writable)
{
    if (readable && writable
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

static int
buffered_init(buffered *self, PyObject *raw, Py_ssize_t buffer_size,
              int readable, int writable)
{
    _PyIO_State *state = find_io_state_by_def(Py_TYPE(self));
    int raw_fileio = Py_IS_TYPE(raw, state->PyFileIO_Type);
    int err = buffered_check_raw(state, raw, raw_fileio, readable, writable);
    if (err == 0 && buffer_size <= 0) {
        PyErr_SetString(PyExc_ValueError,
            "buffer size must be strictly positive");
        err = -1;
    }

    /* (Re)initialize; a failed __init__() leaves the object uninitialized. */
    if (buffered_lock(self) < 0) {
        return -1;
    }
    buffered_drop_buffers(self);
    if (err == 0) {
        self->raw_fileio = (char)raw_fileio;
        /* Use _writev() only where it can't bypass an overridden write():
           on FileIO itself, or on raw types not derived from it. */
        self->raw_vectored = (
            writable
            && (raw_fileio || !PyObject_TypeCheck(raw, state->PyFileIO_Type))
            && _PyType_Lookup(Py_TYPE(raw), &_Py_ID(_writev)) != NULL);
        self->buffer_size = buffer_size;
        self->writable = (char)writable;
        self->writing = (char)(writable && !readable);
        FT_ATOMIC_STORE_UINT8_RELAXED(self->released, 0);
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

/*[clinic input]
_io.BufferedWriter.write
    buffer: Py_buffer
    /
[clinic start generated code]*/

static PyObject *
_io_BufferedWriter_write_impl(buffered *self, Py_buffer *buffer)
/*[clinic end generated code: output=7f8d1365759bfc6b input=dd87dd85fc7f8850]*/
{
    if (buffered_enter(self, "write to closed file", WRITING) < 0) {
        return NULL;
    }
    PyObject *res = NULL;
    const char *data = buffer->buf;
    Py_ssize_t len = buffer->len;
    Py_ssize_t done = 0;
    if (len >= self->buffer_size
        || self->buf.nbytes + len > self->buffer_size)
    {
        /* Doesn't fit: write out the pending writes, and data with them
           when one vectored write takes both or it is too large to
           buffer. */
        int blocked;
        Py_ssize_t direct = (self->raw_vectored || len >= self->buffer_size
                             ? len : 0);
        done = buffered_write_out(self, data, direct, &blocked);
        if (done < 0) {
            goto end;
        }
        Py_ssize_t room = self->buffer_size - self->buf.nbytes;
        if (blocked && len - done > room) {
            /* Keep as much of the rest as fits, and report the rest. */
            int errnum = errno;
            if (buffered_add_write(self, buffer->obj, data + done,
                                   room) == 0)
            {
                errno = errnum;
                buffered_set_blocking_error(done + room);
            }
            goto end;
        }
    }
    /* Buffer all of data, or what a blocked raw stream didn't take. */
    if (buffered_add_write(self, buffer->obj, data + done, len - done) == 0) {
        res = PyLong_FromSsize_t(len);
    }

end:
    buffered_unlock(self);
    return res;
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
    nibbler_state *nstate = find_nibbler_state_by_def(Py_TYPE(self));
    if (_PyIOBase_check_readable(state, reader, Py_True) == NULL) {
        return -1;
    }
    if (_PyIOBase_check_writable(state, writer, Py_True) == NULL) {
        return -1;
    }

    self->reader = (buffered *)PyObject_CallFunction(
            (PyObject *)nstate->PyBufferedReader_Type,
            "On", reader, buffer_size);
    if (self->reader == NULL) {
        return -1;
    }

    self->writer = (buffered *)PyObject_CallFunction(
            (PyObject *)nstate->PyBufferedWriter_Type,
            "On", writer, buffer_size);
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
        PyErr_SetString(PyExc_RuntimeError,
                "the BufferedRWPair object is being garbage-collected");
        return NULL;
    }
    return PyObject_GetAttr((PyObject *)self->writer, &_Py_ID(closed));
}



#define clinic_state() (find_nibbler_state_by_def(Py_TYPE(self)))
#include "clinic/bufferedio.c.h"
#undef clinic_state

static PyType_Spec nibbler_bufferedreader_spec;
static PyType_Spec nibbler_bufferedwriter_spec;
static PyType_Spec nibbler_bufferedrandom_spec;

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

    _IO__BUFFERED_READ_METHODDEF
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

    _IO_BUFFEREDWRITER_WRITE_METHODDEF
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
    _IO_BUFFEREDRWPAIR_PEEK_METHODDEF
    _IO_BUFFEREDRWPAIR_READ1_METHODDEF
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
    {"__weaklistoffset__", Py_T_PYSSIZET, offsetof(rwpair, weakreflist), Py_READONLY},
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

    _IO__BUFFERED_FLUSH_METHODDEF

    _IO__BUFFERED_SEEK_METHODDEF
    _IO__BUFFERED_TELL_METHODDEF
    _IO__BUFFERED_TRUNCATE_METHODDEF
    _IO__BUFFERED_READ_METHODDEF
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
nibbler_traverse(PyObject *mod, visitproc visit, void *arg)
{
    nibbler_state *state = get_nibbler_state(mod);
    Py_VISIT(state->PyBufferedIOBase_Type);
    Py_VISIT(state->PyBufferedReader_Type);
    Py_VISIT(state->PyBufferedWriter_Type);
    Py_VISIT(state->PyBufferedRandom_Type);
    Py_VISIT(state->PyBufferedRWPair_Type);
    return 0;
}

static int
nibbler_clear(PyObject *mod)
{
    nibbler_state *state = get_nibbler_state(mod);
    Py_CLEAR(state->PyBufferedIOBase_Type);
    Py_CLEAR(state->PyBufferedReader_Type);
    Py_CLEAR(state->PyBufferedWriter_Type);
    Py_CLEAR(state->PyBufferedRandom_Type);
    Py_CLEAR(state->PyBufferedRWPair_Type);
    return 0;
}

static void
nibbler_free(void *mod)
{
    (void)nibbler_clear((PyObject *)mod);
}

static struct PyModuleDef _PyIO_nibbler_Module = {
    .m_base = PyModuleDef_HEAD_INIT,
    .m_name = "_io._nibbler",
    .m_doc = "Buffered I/O classes mirroring _io, as an _io submodule.",
    .m_size = sizeof(nibbler_state),
    .m_traverse = nibbler_traverse,
    .m_clear = nibbler_clear,
    .m_free = nibbler_free,
};

/* Create a type from spec with base, named prefix + its class name, and
   add it to mod.  Returns a new reference, or NULL on error. */
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
    nibbler_state *state = get_nibbler_state(mod);

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


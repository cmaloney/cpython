/*
    An implementation of Buffered I/O as defined by PEP 3116 - "New I/O"

    Classes defined here: BufferedReader, BufferedWriter, BufferedRandom,
    BufferedRWPair, all derived from _io._BufferedIOBase.

    Originally written by Amaury Forgeot d'Arc and Antoine Pitrou; reworked
    for free threading as the "nibbler" (see InternalDocs/io_nibbler.md).
*/

#include "Python.h"
#include "pycore_abstract.h"            // _PyNumber_Index()
#include "pycore_context.h"             // PyContext
#include "pycore_fileutils.h"           // _PyFile_Flush()
#include "pycore_import.h"              // _PyImport_SetModuleString()
#include "pycore_modsupport.h"          // _PyArg_CheckPositional()
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

typedef struct {
    PyTypeObject *PyBufferedIOBase_Type;
    PyTypeObject *PyBufferedReader_Type;
    PyTypeObject *PyBufferedWriter_Type;
    PyTypeObject *PyBufferedRandom_Type;
    PyTypeObject *PyBufferedRWPair_Type;
    PyTypeObject *PyTextIOWrapper_Type;
    PyTypeObject *Gather_Type;
    PyTypeObject *Record_Type;
} nibblermodule_state;

static struct PyModuleDef _PyIO_nibbler_Module;

static inline nibblermodule_state *
find_nibblermodule_state_by_def(PyTypeObject *type)
{
    PyObject *mod = PyType_GetModuleByDef(type, &_PyIO_nibbler_Module);
    assert(mod != NULL);
    return (nibblermodule_state *)_PyModule_GetState(mod);
}

uint64_t _PyIO_nibbler_fork_gen;
uint64_t _PyIO_nibbler_fork_holder;

/* Called by PyOS_AfterFork_Child() before any Python code runs. */
void
_PyIO_AfterForkChild(void)
{
    _PyIO_nibbler_fork_gen++;
    _PyIO_nibbler_fork_holder = _PyThreadState_GET()->id;
}

/*
 * Morsel lists: runs of bytes inside the bytes objects keeping them alive,
 * in order, with their total.  items[head:count] are in use.
 */

typedef struct {
    PyObject *obj;
    const char *ptr;
    Py_ssize_t len;
} morsel;

typedef struct {
    morsel *items;
    Py_ssize_t head;
    Py_ssize_t count;
    Py_ssize_t cap;
    Py_ssize_t nbytes;
} morsel_list;

/* Room for one more morsel. */
Py_NO_INLINE static int
morsels_reserve(morsel_list *l)
{
    if (l->count < l->cap) {
        return 0;
    }
    if (l->head > 0) {
        /* Dropping from the front costs a move per half. */
        memmove(l->items, l->items + l->head,
                (l->count - l->head) * sizeof(morsel));
        l->count -= l->head;
        l->head = 0;
        return 0;
    }
    Py_ssize_t cap = Py_MAX(8, 2 * l->cap);
    morsel *items = PyMem_Realloc(l->items, cap * sizeof(morsel));
    if (items == NULL) {
        PyErr_NoMemory();
        return -1;
    }
    l->items = items;
    l->cap = cap;
    return 0;
}

/* Append ptr[0:len], inside obj (extending the last morsel when
   contiguous).  Can't fail after morsels_reserve(). */
static inline Py_ALWAYS_INLINE int
morsels_push(morsel_list *l, PyObject *obj, const char *ptr, Py_ssize_t len)
{
    morsel *last = l->count > l->head ? &l->items[l->count - 1] : NULL;
    if (last != NULL && last->obj == obj && last->ptr + last->len == ptr) {
        last->len += len;
    }
    else if (morsels_reserve(l) < 0) {
        return -1;
    }
    else {
        l->items[l->count++] = (morsel){Py_NewRef(obj), ptr, len};
    }
    FT_ATOMIC_STORE_SSIZE_RELAXED(l->nbytes, l->nbytes + len);
    return 0;
}

/* Drop up to n bytes from the front; returns how many. */
static Py_ssize_t
morsels_consume(morsel_list *l, Py_ssize_t n)
{
    Py_ssize_t taken = 0;
    while (l->head < l->count && taken < n) {
        morsel *m = &l->items[l->head];
        Py_ssize_t k = Py_MIN(m->len, n - taken);
        m->ptr += k;
        m->len -= k;
        taken += k;
        if (m->len > 0) {
            break;
        }
        Py_DECREF(m->obj);
        l->head++;
    }
    FT_ATOMIC_STORE_SSIZE_RELAXED(l->nbytes, l->nbytes - taken);
    if (l->head == l->count) {
        l->head = l->count = 0;
    }
    return taken;
}

static void
morsels_clear(morsel_list *l)
{
    (void)morsels_consume(l, l->nbytes);
}

/* Move src's morsels to the end of dst (as far as memory allows: the
   rest stay in src). */
static int
morsels_splice(morsel_list *dst, morsel_list *src)
{
    for (; src->head < src->count; src->head++) {
        morsel *m = &src->items[src->head];
        if (morsels_reserve(dst) < 0) {
            return -1;
        }
        dst->items[dst->count++] = *m;
        FT_ATOMIC_STORE_SSIZE_RELAXED(dst->nbytes, dst->nbytes + m->len);
        FT_ATOMIC_STORE_SSIZE_RELAXED(src->nbytes, src->nbytes - m->len);
    }
    src->head = src->count = 0;
    return 0;
}

/* Copy up to len bytes from the front to dst, dropping them. */
static Py_ssize_t
morsels_take(morsel_list *l, char *dst, Py_ssize_t len)
{
    Py_ssize_t done = 0;
    for (Py_ssize_t i = l->head; i < l->count && done < len; i++) {
        Py_ssize_t k = Py_MIN(l->items[i].len, len - done);
        memcpy(dst + done, l->items[i].ptr, k);
        done += k;
    }
    return morsels_consume(l, done);
}

/*
 * The buffered object.
 *
 * Data flows one way at a time.  Writing, `list` holds the pending writes:
 * copies in block[0:used], and large exact bytes kept by reference.
 * Reading, block[0:end] holds what the last fill read (but the room a
 * fresh one leaves in front, see buffered_fill()): block[0:pos] was
 * returned (seek() can move back over it), block[pos:end] is the
 * read-ahead, block[dlo:dhi] was written over in place by BufferedRandom
 * and not written out yet, and `list` is the stash: data a raw read
 * returned after the block's, kept after an error.  So the logical
 * position is the raw one plus the pending writes, or minus the
 * read-ahead and the stash.  A block is written into only while nothing
 * else can see that part of it (bytes handed out, or a view a Python raw
 * stream kept, make it abandoned).
 *
 * Every field is used with `lock` held, but raw (and the fields the
 * getters read: capacity, block, dict), which are stored atomically.  The
 * I/O role `io` is taken before the lock by everything that makes raw
 * calls; write() and flush() release the lock around their raw writes,
 * keeping the bytes in flight at the front of `list` (`inflight`), so that
 * other threads can only append meanwhile.
 */

typedef struct {
    PyObject_HEAD
    PyObject *raw;              /* NULL while uninitialized or detached */
    nibbler_mutex lock;
    nibbler_mutex io;
    Py_ssize_t capacity;        /* block size; 0: unbuffered */
    Py_ssize_t threshold;       /* pending bytes past which writes go out */
    Py_ssize_t ref_min;         /* exact bytes kept by reference from this */
    PyObject *block;
    Py_ssize_t used;
    Py_ssize_t pos;
    Py_ssize_t end;
    Py_ssize_t dlo;
    Py_ssize_t dhi;
    Py_ssize_t noline;          /* block[pos:noline] has no end of line */
    /* Fills stop here, PY_SSIZE_T_MAX: at the block's end (see
       buffered_fill()). */
    Py_ssize_t stop;
    morsel_list list;
    Py_ssize_t inflight;
    /* The raw position, kept for an exact FileIO of a regular file (not
       in append mode) as _io's abs_pos is; negative when unknown. */
    Py_off_t raw_pos;
    uint8_t raw_fileio;         /* raw is exactly a FileIO */
    uint8_t raw_vectored;       /* raw has a _writev() of its own */
    uint8_t raw_appending;
    uint8_t raw_regular;
    uint8_t raw_open;           /* raw said it is open (see buffered_write) */
    /* With the I/O role (the lock may be another thread's): a holder
       of it that can never return was taken over, but its bytes in
       flight could not be dropped yet. */
    uint8_t drop_inflight;
    uint8_t reading;            /* the data is read-ahead (and stash) */
    char finalizing;
    /* _gather() blocks write out themselves (see "Gathering"). */
    uint8_t direct;
    /* The records of _gather() blocks, and the context variable finding
       them. */
    struct record *recs;
    int ngather;
    PyObject *gvar;
    PyObject *dict;
    PyObject *weakreflist;
} buffered;

/* So far below 0 that what reads and writes add leaves it negative. */
#define POS_UNKNOWN (-((Py_off_t)1 << (8 * sizeof(Py_off_t) - 2)))
/* What raw calls (and the functions here) return when it would block. */
#define WOULD_BLOCK (-2)
#define REF_MIN 512
/* The room before a fresh fill's data in a block of the buffer's size. */
#define PAD 64

#define buffered_cast(op) ((buffered *)(op))

static PyType_Spec nibbler_bufferedreader_spec;
static PyType_Spec nibbler_bufferedwriter_spec;

static int
buffered_writable(buffered *self)
{
    return !PyType_GetBaseByToken(Py_TYPE(self),
                                  &nibbler_bufferedreader_spec, NULL);
}

static int
buffered_not_ready(void)
{
    PyErr_SetString(PyExc_ValueError,
                    "I/O operation on uninitialized or detached object");
    return -1;
}

static PyObject *
buffered_unsupported(buffered *self, const char *msg)
{
    PyErr_SetString(find_io_state_by_def(Py_TYPE(self))->unsupported_operation,
                    msg);
    return NULL;
}

/* raw for code without the lock: a new reference (a concurrent detach()
   leaves the caller with the stream it took). */
#ifdef Py_GIL_DISABLED
#  define buffered_ref_raw(self) _Py_XGetRef(&(self)->raw)
static PyObject *
buffered_swap_raw(buffered *self, PyObject *raw)
{
    if (raw != NULL) {
        _PyObject_SetMaybeWeakref(raw);
    }
    return _Py_atomic_exchange_ptr(&self->raw, raw);
}
#else
#  define buffered_ref_raw(self) Py_XNewRef((self)->raw)
static PyObject *
buffered_swap_raw(buffered *self, PyObject *raw)
{
    PyObject *old = self->raw;
    self->raw = raw;
    return old;
}
#endif

static PyObject *
buffered_get_raw(buffered *self)
{
    PyObject *raw = buffered_ref_raw(self);
    if (raw == NULL) {
        buffered_not_ready();
    }
    return raw;
}

/*
 * Locking (see nibbler.h)
 */

/* Take the lock (interruptible: a signal handler raising interrupts the
   wait).  Returns 0 or -1. */
static inline int
buffered_lock_ex(buffered *self, int interruptible)
{
    int r = nibbler_mutex_lock(&self->lock, (PyObject *)self, interruptible);
    if (r > 0) {
        /* A fork or a takeover: the raw stream may have moved. */
        self->raw_pos = POS_UNKNOWN;
    }
    return r < 0 ? -1 : 0;
}

#define buffered_lock(self) buffered_lock_ex((self), 1)

static inline void
buffered_unlock(buffered *self)
{
    nibbler_mutex_unlock(&self->lock);
}

/* Lock again after a raw call made without the lock: not interrupted (a
   signal handler runs later), keeping errno and the exception of a call
   that failed. */
static inline Py_ALWAYS_INLINE void
buffered_relock(buffered *self, int failed)
{
    if (!failed) {
        (void)buffered_lock_ex(self, 0);
        return;
    }
    int errnum = errno;
    PyObject *exc = PyErr_GetRaisedException();
    (void)buffered_lock_ex(self, 0);
    PyErr_SetRaisedException(exc);
    errno = errnum;
}

/* The I/O role was taken from a holder that will never return from its raw
   call: drop the bytes it was writing. */
static void
buffered_drop_inflight(buffered *self)
{
    (void)morsels_consume(&self->list, self->inflight);
    self->inflight = 0;
    self->drop_inflight = 0;
    self->raw_pos = POS_UNKNOWN;
}

/* Take the I/O role, then the lock. */
static int
buffered_lock_io(buffered *self)
{
    int taken_over = nibbler_mutex_lock(&self->io, (PyObject *)self, 1);
    if (taken_over < 0) {
        return -1;
    }
    if (buffered_lock(self) < 0) {
        /* A reentrant call while finalizing, or a wait interrupted: the
           next holder of the I/O role drops them. */
        self->drop_inflight |= taken_over;
        nibbler_mutex_unlock(&self->io);
        return -1;
    }
    if (taken_over || self->drop_inflight) {
        buffered_drop_inflight(self);
    }
    return 0;
}

static void
buffered_unlock_io(buffered *self)
{
    assert(self->inflight == 0);
    nibbler_mutex_unlock(&self->io);
    buffered_unlock(self);
}

/* With the lock: take the I/O role too.  Returns IO_TAKEN, IO_WAITED (the
   lock was released meanwhile: anything may have changed), IO_MINE (this
   thread writes out further up its stack, as when a signal handler
   writes), or -1 with neither held. */
enum { IO_TAKEN, IO_WAITED, IO_MINE };

static int
buffered_take_io(buffered *self)
{
    if (nibbler_mutex_trylock(&self->io)) {
        if (self->drop_inflight) {
            buffered_drop_inflight(self);
        }
        return IO_TAKEN;
    }
    if (nibbler_mutex_is_mine(&self->io)) {
        return IO_MINE;
    }
    buffered_unlock(self);
    return buffered_lock_io(self) < 0 ? -1 : IO_WAITED;
}

/*
 * Raw stream calls (with the lock and the I/O role, but where noted)
 */

/* Is raw closed?  1, 0 or -1.  Without the lock too (raw: a reference
   taken with buffered_ref_raw()). */
static int
buffered_ref_closed(PyObject *raw)
{
    if (_PyFileIO_CheckExact(raw)) {
        return _PyFileIO_closed(raw);
    }
    PyObject *res = PyObject_GetAttr(raw, &_Py_ID(closed));
    int r = res == NULL ? -1 : PyObject_IsTrue(res);
    Py_XDECREF(res);
    return r;
}

/* buffered_ref_closed() of raw, noted in raw_open (see buffered_write()). */
static int
buffered_is_closed(buffered *self)
{
    int r = buffered_ref_closed(self->raw);
    self->raw_open = r == 0;
    return r;
}

static int
buffered_check_closed(buffered *self, const char *msg)
{
    int r = buffered_is_closed(self);
    if (r > 0) {
        PyErr_SetString(PyExc_ValueError, msg);
    }
    return r == 0 ? 0 : -1;
}

/* The count of a raw readinto(), write() or _writev() of up to len bytes,
   WOULD_BLOCK for None, or -1. */
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

/* Release a view given to Python code (gh-60198, gh-157075).  Returns 1
   if its memory can still be reached, through a view made from it: then
   memory of ours must not be reused.  Keeps the raised exception. */
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

/* A memoryview of mem[0:len] for Python code (writable with PyBUF_WRITE)
   inside memobj: a bytes object of ours, or the object holding the
   caller's data (bytes, str, or an exporter).  The view keeps memobj (and
   an export of it) alive, so that a view made from it stays valid like any
   other.  When memobj doesn't export that memory (as a PEP 688 class may
   not), a read-only view is of a copy, and a writable one is NULL with no
   exception set. */
static PyObject *
buffered_memory_view(char *mem, Py_ssize_t len, int flags, PyObject *memobj)
{
    if (memobj == NULL) {
        return PyMemoryView_FromMemory(mem, len, flags);
    }
    Py_buffer whole = {.obj = NULL};
    int immutable = PyBytes_CheckExact(memobj) || PyUnicode_CheckExact(memobj);
    if (!immutable) {
        if (PyObject_GetBuffer(memobj, &whole, flags == PyBUF_WRITE
                               ? PyBUF_WRITABLE : PyBUF_SIMPLE) < 0)
        {
            if (!PyErr_ExceptionMatches(PyExc_TypeError)
                && !PyErr_ExceptionMatches(PyExc_BufferError))
            {
                return NULL;
            }
            PyErr_Clear();
        }
        else if (mem < (char *)whole.buf
                 || mem + len > (char *)whole.buf + whole.len)
        {
            PyBuffer_Release(&whole);
            whole.obj = NULL;
        }
        if (whole.obj == NULL) {
            if (flags == PyBUF_WRITE) {
                return NULL;
            }
            PyObject *copy = PyBytes_FromStringAndSize(mem, len);
            PyObject *view = copy ? buffered_memory_view(
                PyBytes_AS_STRING(copy), len, flags, copy) : NULL;
            Py_XDECREF(copy);
            return view;
        }
    }
    PyObject *view = PyMemoryView_FromMemory(mem, len, flags);
    if (view == NULL) {
        PyBuffer_Release(&whole);
        return NULL;
    }
    PyMemoryViewObject *mv = (PyMemoryViewObject *)view;
    if (immutable) {
        /* Released with the managed buffer.  A writable view (into a block
           of ours) doesn't show it as its obj. */
        mv->mbuf->master.obj = Py_NewRef(memobj);
        if (flags == PyBUF_READ) {
            mv->view.obj = memobj;
        }
    }
    else {
        mv->mbuf->master = whole;
        mv->view.obj = memobj;
    }
    return view;
}

/* One raw read of up to len bytes into dst, inside memobj (see
   buffered_memory_view()): the stash first.  Returns the count (0 at EOF),
   WOULD_BLOCK or -1; sets *shared if Python code can still reach dst. */
static Py_ssize_t
buffered_raw_read(buffered *self, char *dst, Py_ssize_t len, PyObject *memobj,
                  int *shared)
{
    if (self->list.nbytes > 0) {
        return morsels_take(&self->list, dst, len);
    }
    if (self->raw_fileio) {
        Py_ssize_t n = _PyFileIO_readinto(self->raw, dst, len);
        self->raw_pos += Py_MAX(n, 0);
        return n;
    }
    PyObject *view = buffered_memory_view(dst, len, PyBUF_WRITE, memobj);
    if (view == NULL) {
        if (PyErr_Occurred()) {
            return -1;
        }
        /* Into a bytes object of our own, copied. */
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
    PyObject *res;
    do {
        res = PyObject_CallMethodOneArg(self->raw, &_Py_ID(readinto), view);
    } while (res == NULL && _PyIO_trap_eintr());
    *shared |= buffered_release_view(view);
    return buffered_raw_result(res, len, "readinto");
}

/* One raw write of spans[0:cnt] (total bytes, inside objs, see
   buffered_memory_view()): one writev() to an exact FileIO, else write()
   of one span or _writev() of views of them.  Returns the count,
   WOULD_BLOCK (errno set) or -1.  Without the lock. */
Py_NO_INLINE static Py_ssize_t
buffered_raw_writev_py(buffered *self, const _PyIO_Span *spans,
                       PyObject *const *objs, Py_ssize_t cnt,
                       Py_ssize_t total)
{
    PyObject *arg = cnt == 1 ? NULL : PyList_New(cnt);
    if (cnt > 1 && arg == NULL) {
        return -1;
    }
    for (Py_ssize_t i = 0; i < cnt; i++) {
        PyObject *view = buffered_memory_view((char *)spans[i].ptr,
                                              spans[i].len, PyBUF_READ,
                                              objs[i]);
        if (view == NULL) {
            Py_XDECREF(arg);
            return -1;
        }
        if (cnt == 1) {
            arg = view;
        }
        else {
            PyList_SET_ITEM(arg, i, view);
        }
    }
    PyObject *name = cnt == 1 ? &_Py_ID(write) : &_Py_ID(_writev);
    PyObject *res;
    int errnum;
    do {
        errno = 0;
        res = PyObject_CallMethodOneArg(self->raw, name, arg);
        errnum = errno;
    } while (res == NULL && _PyIO_trap_eintr());
    /* Views of the caller's data are released: the raw stream keeps it
       only through views it made from them. */
    for (Py_ssize_t i = 0; i < cnt; i++) {
        PyObject *view = cnt == 1 ? arg : PyList_GET_ITEM(arg, i);
        if (objs[i] == NULL || !PyBytes_CheckExact(objs[i])) {
            (void)buffered_release_view(Py_NewRef(view));
        }
    }
    Py_DECREF(arg);
    Py_ssize_t n = buffered_raw_result(res, total,
                                       cnt == 1 ? "write" : "_writev");
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
    if (n < 0 && !PyErr_Occurred()) {
        PyErr_Format(PyExc_OSError,
                     "Raw stream returned invalid position %" PY_PRIdOFF,
                     (PY_OFF_T_COMPAT)n);
    }
    return n < 0 ? -1 : n;
}

/* Keep pos, a raw position from raw.seek() or raw.tell(), if raw_regular. */
static Py_off_t
buffered_raw_set(buffered *self, Py_off_t pos)
{
    self->raw_pos = self->raw_regular && pos >= 0 ? pos : POS_UNKNOWN;
    return pos;
}

static Py_off_t
buffered_raw_tell(buffered *self)
{
    return buffered_raw_set(self, buffered_raw_offset(
        PyObject_CallMethodNoArgs(self->raw, &_Py_ID(tell))));
}

static Py_off_t
buffered_raw_seek(buffered *self, Py_off_t target, int whence)
{
    PyObject *t = PyLong_FromOff_t(target);
    PyObject *w = t ? PyLong_FromLong(whence) : NULL;
    PyObject *res = w ? PyObject_CallMethodObjArgs(self->raw, &_Py_ID(seek),
                                                   t, w, NULL) : NULL;
    Py_XDECREF(t);
    Py_XDECREF(w);
    return buffered_raw_set(self, buffered_raw_offset(res));
}

/* Is anything buffered (pending writes, read-ahead or stash)? */
static inline int
buffered_holds(buffered *self)
{
    return self->list.nbytes > 0 || self->end > self->pos;
}

/* The logical position: the raw one (kept, else raw.tell(); asked anyway
   with nothing buffered, as code sharing the file descriptor may have
   moved it) adjusted for what is buffered, and `gathered` more. */
static PyObject *
buffered_position(buffered *self, Py_ssize_t gathered)
{
    Py_off_t pos = (buffered_holds(self) && self->raw_pos >= 0
                    ? self->raw_pos : buffered_raw_tell(self));
    if (pos == -1) {
        return NULL;
    }
    pos += (self->reading ? -(self->end - self->pos) - self->list.nbytes
                          : self->list.nbytes) + gathered;
    // GH-95782
    return PyLong_FromOff_t(pos < 0 ? 0 : pos);
}

/*
 * Blocks and pending writes (with the lock)
 */

/* Replace the block with block (a new reference, or NULL). */
static void
buffered_set_block(buffered *self, PyObject *block)
{
    PyObject *old = self->block;
    FT_ATOMIC_STORE_PTR_RELAXED(self->block, block);
    self->used = 0;
    Py_XDECREF(old);
}

/* Add data[0:len] (inside obj, or NULL) to the morsels in l: exact bytes
   by reference from ref_min (or when larger than a buffer), else copied
   into (*block)[*used:], or a block of size bytes when it has no room
   (the old one if nothing else references it), or past that size into a
   bytes object of its own.  The pending writes and _gather() records. */
static inline Py_ALWAYS_INLINE int
buffered_append_to(buffered *self, morsel_list *l, PyObject **block,
                   Py_ssize_t *used, Py_ssize_t size, PyObject *obj,
                   const char *data, Py_ssize_t len)
{
    if (len == 0) {
        return 0;
    }
    /* (Atomic: _gather() blocks append without the lock.) */
    if (len >= REF_MIN
        && (len >= FT_ATOMIC_LOAD_SSIZE_RELAXED(self->ref_min)
            || len > FT_ATOMIC_LOAD_SSIZE_RELAXED(self->capacity))
        && obj != NULL && PyBytes_CheckExact(obj))
    {
        return morsels_push(l, obj, data, len);
    }
    if (len > size) {
        PyObject *copy = PyBytes_FromStringAndSize(data, len);
        int r = copy ? morsels_push(l, copy, PyBytes_AS_STRING(copy), len)
                : -1;
        Py_XDECREF(copy);
        return r;
    }
    if (*used == 0 || PyBytes_GET_SIZE(*block) - *used < len) {
        if (*block == NULL || PyBytes_GET_SIZE(*block) < size
            || !_PyObject_IsUniquelyReferenced(*block))
        {
            PyObject *b = PyBytes_FromStringAndSize(NULL, size);
            if (b == NULL) {
                return -1;
            }
            PyObject *old = *block;
            FT_ATOMIC_STORE_PTR_RELAXED(*block, b);
            Py_XDECREF(old);
        }
        *used = 0;
    }
    char *dst = PyBytes_AS_STRING(*block) + *used;
    memcpy(dst, data, len);
    if (morsels_push(l, *block, dst, len) < 0) {
        return -1;
    }
    *used += len;
    return 0;
}

#define buffered_append(self, obj, data, len)                            \
    buffered_append_to((self), &(self)->list, &(self)->block,             \
                       &(self)->used, (self)->capacity, (obj), (data), (len))

/* Write spans[0:cnt] (total bytes) to the raw stream, retrying partial
   writes, until all of it is written (0), the raw stream would block
   (WOULD_BLOCK) or an error is raised (-1); *written gets the count.  With
   unlocked, without the lock meanwhile; -1: called without it (and the raw
   position, see "Gathering"). */
static inline Py_ALWAYS_INLINE int
buffered_write_spans(buffered *self, _PyIO_Span *spans, PyObject **objs,
                     Py_ssize_t cnt, Py_ssize_t total, int unlocked,
                     Py_ssize_t *written)
{
    if (unlocked > 0) {
        buffered_unlock(self);
    }
    Py_ssize_t done = 0;
    int st = 0;
    for (;;) {
        Py_ssize_t r = buffered_raw_writev(self, spans, objs, cnt,
                                           total - done);
        if (r == 0) {
            /* Retrying could loop forever (gh-158414). */
            PyErr_SetString(PyExc_OSError, "raw write() made no progress");
        }
        if (r <= 0) {
            st = r == WOULD_BLOCK ? WOULD_BLOCK : -1;
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
        /* A partial write may come from a signal: run its handlers before
           blocking again.  Without the lock, a handler writing to this
           object queues its data (gh-118143). */
        if (PyErr_CheckSignals() < 0) {
            st = -1;
            break;
        }
    }
    if (unlocked > 0) {
        buffered_relock(self, st != 0);
    }
    if (unlocked >= 0) {
        self->raw_pos += done;
    }
    *written = done;
    return st;
}

/* Write the first `target` bytes of the pending writes, then data[0:len]
   (inside obj), in batches of as many pieces as one raw call takes, until
   all is written, the raw stream would block or raises: *status 0,
   WOULD_BLOCK or -1.  Returns how much of data was written.  With the
   lock and the I/O role; with unlocked, the lock is released around raw
   calls (other threads can only append then).  Written bytes are dropped
   as they go, the rest stays pending. */
static Py_ssize_t
buffered_write_out(buffered *self, Py_ssize_t target, PyObject *obj,
                   const char *data, Py_ssize_t len, int unlocked,
                   int *status)
{
    Py_ssize_t done = 0;
    if (target == 0 && len == 0) {
        *status = 0;
        return 0;
    }
    _PyIO_Span stack_spans[_PyIO_WRITEV_MAX];
    PyObject *stack_objs[_PyIO_WRITEV_MAX];
    _PyIO_Span *spans = stack_spans;
    PyObject **objs = stack_objs;
    Py_ssize_t max = self->raw_vectored ? _PyIO_WRITEV_MAX : 1;
    int st = 0;
    if (_PyIO_WRITEV_LONG > _PyIO_WRITEV_MAX && self->raw_vectored
        && self->list.count - self->list.head >= _PyIO_WRITEV_MAX)
    {
        max = _PyIO_WRITEV_LONG;
        spans = PyMem_New(_PyIO_Span, max);
        objs = PyMem_New(PyObject *, max);
        if (spans == NULL || objs == NULL) {
            PyErr_NoMemory();
            st = -1;
        }
    }
    if (!self->raw_fileio) {
        /* Python code can reach the block through the views it gets. */
        buffered_set_block(self, NULL);
    }
    while (st == 0 && (target > 0 || done < len)) {
        Py_ssize_t cnt = 0, total = 0;
        for (Py_ssize_t i = self->list.head;
             i < self->list.count && cnt < max && total < target; i++)
        {
            morsel *m = &self->list.items[i];
            Py_ssize_t k = Py_MIN(m->len, target - total);
            spans[cnt] = (_PyIO_Span){m->ptr, k};
            objs[cnt++] = Py_NewRef(m->obj);
            total += k;
        }
        Py_ssize_t held = cnt;
        self->inflight = total;
        if (done < len && cnt < max && total == target) {
            spans[cnt] = (_PyIO_Span){data + done, len - done};
            objs[cnt++] = obj;
            total += len - done;
        }
        Py_ssize_t written;
        st = buffered_write_spans(self, spans, objs, cnt, total, unlocked,
                                  &written);
        for (Py_ssize_t i = 0; i < held; i++) {
            Py_DECREF(objs[i]);
        }
        Py_ssize_t k = morsels_consume(&self->list,
                                       Py_MIN(written, self->inflight));
        self->inflight = 0;
        target -= k;
        done += written - k;
    }
    if (spans != stack_spans) {
        PyMem_Free(spans);
        PyMem_Free(objs);
    }
    *status = st;
    return done;
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

/* Write out everything pending (with unlocked, what was pending at the
   start); BlockingIOError if the raw stream would block. */
static int
buffered_flush_writes(buffered *self, int unlocked)
{
    int st;
    (void)buffered_write_out(self, self->list.nbytes, NULL, NULL, 0, unlocked,
                             &st);
    if (st == WOULD_BLOCK) {
        buffered_set_blocking_error(0);
    }
    return st == 0 ? 0 : -1;
}

/* Forget the read-ahead and the stash. */
static void
buffered_drop_read(buffered *self)
{
    if (self->reading) {
        morsels_clear(&self->list);
    }
    self->pos = self->end = self->noline = self->dlo = self->dhi = 0;
    self->reading = 0;
}

/* Move the raw stream by delta bytes from the position kept (a file
   descriptor moved behind our back doesn't count, as with _io's abs_pos),
   or else from where it is. */
static int
buffered_raw_move(buffered *self, Py_off_t delta)
{
    if (delta == 0) {
        return 0;
    }
    Py_off_t r = (self->raw_pos >= 0
                  ? buffered_raw_seek(self, self->raw_pos + delta, SEEK_SET)
                  : buffered_raw_seek(self, delta, SEEK_CUR));
    return r < 0 ? -1 : 0;
}

/* Write out the bytes BufferedRandom wrote over the read-ahead in place
   (back where they start), then move the raw stream after the block
   (keep), or to the logical position. */
static int
buffered_flush_dirty(buffered *self, int keep)
{
    Py_ssize_t dhi = self->dhi, len = dhi - self->dlo;
    if (len == 0) {
        return 0;
    }
    _PyIO_Span span = {PyBytes_AS_STRING(self->block) + self->dlo, len};
    PyObject *obj = self->block;
    Py_ssize_t written = 0;
    int st = buffered_raw_move(self, -(self->end - self->dlo
                                       + self->list.nbytes));
    if (st == 0) {
        st = buffered_write_spans(self, &span, &obj, 1, len, 0, &written);
        self->dlo += written;
    }
    if (st == WOULD_BLOCK) {
        buffered_set_blocking_error(written);
    }
    if (st == 0) {
        self->dlo = self->dhi = 0;
        st = buffered_raw_move(self, keep ? self->end - dhi + self->list.nbytes
                                          : self->pos - dhi);
    }
    return st == 0 ? 0 : -1;
}

/* Hand the read-ahead and the stash back to the raw stream, so that its
   position is the logical one. */
static int
buffered_rewind(buffered *self)
{
    int r = (self->dhi > self->dlo ? buffered_flush_dirty(self, 0)
             : buffered_raw_move(self, -(self->end - self->pos
                                         + self->list.nbytes)));
    if (r == 0) {
        buffered_drop_read(self);
    }
    return r;
}

/* Bring the raw stream to the logical position. */
static int
buffered_sync(buffered *self, int unlocked)
{
    return self->reading ? buffered_rewind(self)
                         : buffered_flush_writes(self, unlocked);
}


/*
 * Gathering
 *
 * Inside a _gather() block, the write()s of the Context that entered it
 * (by identity: a context copied inside the block, such as an asyncio
 * task's, writes as usual) go to the context's record for the stream,
 * past the buffer size, so that no other data gets between them.  Writes
 * find it through a context variable of the stream and take only its lock,
 * which no other thread waits for but to move its data (see below): a
 * Context runs in one thread at a time.  A block nested in one on the same
 * stream and context gathers into that one.
 *
 * At its end, a block whose stream's lock is free (taken without waiting)
 * moves its record to the pending writes under it, as a write that fits
 * adds its data, and writes them out when they no longer fit if the I/O
 * role is free too: no system call per block.  When the lock is busy, the
 * block writes its record out itself, with one writev() and only the
 * record's lock, when the stream is a BufferedWriter of an exact FileIO of
 * a regular file with no pending writes: POSIX makes writes to a regular
 * file atomic with respect to each other, so the kernel orders it against
 * the other threads' writes.  (The stream no longer keeps the raw position
 * then, which these writes move.)  Otherwise, the record is moved to the
 * pending writes, waiting for the lock and the I/O role:
 * - pending writes may have been written before the block ended, and
 *   must come first;
 * - a read-ahead is ahead of the logical position, where data goes;
 * - pipes, sockets and terminals may split a large write, and Python raw
 *   streams are no help at all (nor is asking whether they are closed
 *   with the lock alone).
 * A record is also moved once it holds `limit` bytes (and there is no
 * read-ahead), and before an operation of its context needs the position
 * (reads, seek(), truncate()).  close(), detach() and __init__(), from any
 * context, move every record's data, and stop the blocks writing out
 * themselves, waiting for those doing so as they take each record's lock.
 * flush() inside a block takes effect at its end; tell() counts the
 * gathered bytes.
 *
 * A direct block, meant to last a thread's or task's life, writes out
 * the pending writes when it starts (its context's earlier writes, among
 * others), so that what is pending at its write-outs is other contexts'
 * data, which it needn't wait for: at its limit (by default the buffer
 * size), flush() and end it writes its record out itself when the stream
 * allows, without looking at the pending writes.  A line block writes
 * out its complete lines (tracked as written) after each write with a
 * newline, the same way, keeping the partial line.  On error, what wasn't
 * written stays for the next write-out.
 *
 * The stream lists its records with the lock held, and counts them
 * (ngather): every write and read checks the count, which is all
 * operations outside blocks pay.  A record stays listed when its block
 * ends, for the next block of its context, until an operation with the
 * I/O role drops it.  A block dropped before it ends (a thread or
 * generator gone inside it) ends then, with a ResourceWarning (its data is
 * dropped when the stream is closed, or this thread is busy with it).
 */

typedef struct record {
    PyObject_HEAD
    nibbler_mutex lock;         /* for the fields below, but next */
    buffered *stream;           /* borrowed; NULL once it is freed */
    PyObject *ctx;              /* borrowed: the context it is for */
    PyObject *raw;              /* borrowed: the block's raw stream */
    struct record *next;        /* in the stream's list (with its lock) */
    morsel_list list;
    PyObject *block;            /* small writes are copied to block[used:] */
    Py_ssize_t used;
    Py_ssize_t limit;           /* moved to the stream once it holds this */
    Py_ssize_t tail;            /* at least the bytes after the last \n */
    char flush;                 /* flush() was called inside the block */
    char direct, line;          /* the block's mode (see above) */
    uint8_t state;              /* stored atomically */
} record;

/* Listed but for REC_FREE; changed from or to it with both locks. */
enum { REC_FREE, REC_IDLE, REC_ACTIVE, REC_PENDING, REC_WRITING };

typedef struct gather {
    PyObject_HEAD
    buffered *stream;
    PyObject *ctx;              /* the Context it was entered in */
    PyObject *raw;              /* the raw stream then */
    record *rec;
    Py_ssize_t limit;
    char joined;                /* in the record of an outer block */
    char state;
    char direct, line;
} gather;

enum { GATHER_NEW, GATHER_ACTIVE, GATHER_DONE };

#define GATHER_LIMIT (20 * 1024 * 1024)
#define GATHER_BLOCK_MIN 1024
#define GATHER_BLOCK_MAX (64 * 1024)

#define rec_state(rec) FT_ATOMIC_LOAD_UINT8_RELAXED((rec)->state)
#define rec_set_state(rec, s) FT_ATOMIC_STORE_UINT8_RELAXED((rec)->state, (s))
#define rec_unlock(rec) nibbler_mutex_unlock(&(rec)->lock)

/* Take rec's lock (not interrupted).  Taken over from a holder gone while
   writing it out (in a fork, or hung while finalizing), which may have
   written any part: its data is dropped, as bytes in flight are. */
static int
rec_lock(record *rec)
{
    int r = nibbler_mutex_lock(&rec->lock, (PyObject *)rec->stream, 0);
    if (r > 0 && rec->state == REC_WRITING) {
        morsels_clear(&rec->list);
        rec_set_state(rec, REC_IDLE);
    }
    return r < 0 ? -1 : 0;
}

/* What gather_current() found last in this thread (rec borrowed, NULL
   for none), and for what.  It stays right while the thread state (by
   address and id), the stream's variable, the context, the context's
   variables (a set() replaces them) and the thread's context version
   (bumped on every switch of context) are the same: only this thread sets
   variables of the context then, and they keep rec alive.  No record may
   have been freed since either: a variable map freed and made again at
   the same address would pass for the old one.  It spares writes the
   variable's lookup, which free-threaded builds don't cache. */
static _Py_thread_local struct {
    PyThreadState *ts;
    uint64_t id;
    uint64_t ver;
    uint64_t freed;
    PyObject *var;
    PyObject *ctx;
    PyHamtObject *vars;
    record *rec;
} gather_last;

/* How many records were freed (see gather_last). */
static uint64_t gather_freed;

static inline void
gather_remember(PyThreadState *ts, PyObject *var, record *rec)
{
    gather_last.ts = ts;
    gather_last.id = ts->id;
    gather_last.ver = ts->context_ver;
    gather_last.freed = _Py_atomic_load_uint64_relaxed(&gather_freed);
    gather_last.var = var;
    gather_last.ctx = ts->context;
    gather_last.vars = ((PyContext *)ts->context)->ctx_vars;
    gather_last.rec = rec;
}

static void record_dealloc(PyObject *);

/* gather_current() without the last one found: look the variable up.
   Python code can reach it (iterating a context) and set it to anything:
   only a record of this stream and context counts. */
Py_NO_INLINE static record *
gather_lookup(buffered *self, PyThreadState *ts, PyObject *var)
{
    PyObject *rec = NULL;
    if (var == NULL) {
        return NULL;
    }
    if (PyContextVar_Get(var, NULL, &rec) < 0) {
        PyErr_Clear();
    }
    /* (The context keeps it.) */
    Py_XDECREF(rec);
    if (rec != NULL && (Py_TYPE(rec)->tp_dealloc != record_dealloc
                        || ((record *)rec)->stream != self
                        || ((record *)rec)->ctx != ts->context))
    {
        rec = NULL;
    }
    if (ts->context != NULL) {
        gather_remember(ts, var, (record *)rec);
    }
    return (record *)rec;
}

/* Without the lock: the current context's record, or NULL. */
static inline record *
gather_current(buffered *self)
{
    PyThreadState *ts = _PyThreadState_GET();
    PyObject *var = FT_ATOMIC_LOAD_PTR_ACQUIRE(self->gvar);
    if (gather_last.ts == ts && gather_last.var == var
        && gather_last.ctx == ts->context && gather_last.ver == ts->context_ver
        && gather_last.id == ts->id
        && gather_last.vars == ((PyContext *)ts->context)->ctx_vars
        && gather_last.freed == _Py_atomic_load_uint64_relaxed(&gather_freed))
    {
        return gather_last.rec;
    }
    return gather_lookup(self, ts, var);
}

/* With both locks and no read-ahead: move what rec gathered to the
   pending writes (its first n bytes, copied, if fewer).  On error, rec
   keeps the rest. */
static int
gather_move(buffered *self, record *rec, Py_ssize_t n)
{
    if (n < rec->list.nbytes) {
        PyObject *b = (morsels_reserve(&self->list) < 0 ? NULL
                       : PyBytes_FromStringAndSize(NULL, n));
        if (b == NULL) {
            return -1;
        }
        (void)morsels_take(&rec->list, PyBytes_AS_STRING(b), n);
        (void)morsels_push(&self->list, b, PyBytes_AS_STRING(b), n);
        Py_DECREF(b);
    }
    else if (rec->list.nbytes > 0) {
        if (morsels_splice(&self->list, &rec->list) < 0) {
            return -1;
        }
        /* Shared from now on: never written to again. */
        Py_CLEAR(rec->block);
        rec->used = 0;
    }
    return 0;
}

/* With the lock and the I/O role, for an operation needing the position
   on an open stream: move what the current context's record gathered,
   and what ended blocks could not move (with all, every record's data,
   doing their deferred flush, see above), and unlist idle records (all
   that is done with all -1, with the lock alone).  The read-ahead is
   handed back first, so that no raw call (Python code) runs while the
   list is walked. */
Py_NO_INLINE static int
gather_move_records(buffered *self, int all)
{
    PyObject *ctx = _PyThreadState_GET()->context;
#define MOVED(r) (all > 0 || (all == 0 && ((r)->ctx == ctx            \
                                          || rec_state(r) == REC_PENDING)))
    if (all > 0) {
        FT_ATOMIC_STORE_UINT8_RELAXED(self->direct, 0);
    }
    for (record *r = self->recs; self->reading && r != NULL; r = r->next) {
        if (all > 0 || (MOVED(r) && FT_ATOMIC_LOAD_SSIZE_RELAXED(
                                         r->list.nbytes)))
        {
            if (buffered_rewind(self) < 0) {
                return -1;
            }
            break;
        }
    }
    record **p = &self->recs;
    while (*p != NULL) {
        record *r = *p;
        if (rec_lock(r) < 0) {
            return -1;
        }
        int err = MOVED(r) ? gather_move(self, r, PY_SSIZE_T_MAX) : 0;
        if (err == 0 && MOVED(r)) {
            r->flush &= all == 0;
            if (r->state == REC_PENDING) {
                rec_set_state(r, REC_IDLE);
            }
        }
        int idle = r->state == REC_IDLE;
        if (idle) {
            *p = r->next;
            r->next = NULL;
            rec_set_state(r, REC_FREE);
            FT_ATOMIC_STORE_INT_RELAXED(self->ngather, self->ngather - 1);
        }
        else {
            p = &r->next;
        }
        rec_unlock(r);
        if (idle) {
            Py_DECREF(r);
        }
        if (err < 0) {
            return -1;
        }
    }
#undef MOVED
    return 0;
}

/* write() while the stream has records: add data[0:len] (inside obj, or
   NULL) to the current context's active record, as the pending writes
   would keep it, in blocks growing with what it gathered; at the limit,
   move it to the pending writes (which may go past the threshold: the
   next write, flush or the block's end writes it), or write it out in a
   direct block, as its complete lines in a line block.  Returns 1 if
   there is no such record. */
static int gather_end(buffered *, record *, Py_ssize_t, Py_ssize_t *);

/* What a direct or line block writes out after data[0:len] was added to
   rec: all of it at the limit of a direct block, else for a line block
   up to the last newline if data has one.  0: nothing. */
Py_NO_INLINE static Py_ssize_t
gather_out(record *rec, const char *data, Py_ssize_t len)
{
    Py_ssize_t n = rec->list.nbytes;
    const char *nl = NULL;
#ifdef HAVE_MEMRCHR
    nl = rec->line ? memrchr(data, '\n', len) : NULL;
#else
    for (const char *p = data + len; rec->line && nl == NULL && p > data;) {
        nl = *--p == '\n' ? p : NULL;
    }
#endif
    rec->tail = nl ? data + len - nl - 1 : Py_MIN(rec->tail, n - len) + len;
    return (rec->direct && n >= rec->limit ? PY_SSIZE_T_MAX
            : nl ? n - rec->tail : 0);
}

Py_NO_INLINE static int
gather_write(buffered *self, PyObject *obj, const char *data, Py_ssize_t len,
             const char *closed_msg)
{
    record *rec = gather_current(self);
    /* (A signal handler run while its block writes it out writes as
       usual.) */
    if (rec == NULL || rec_state(rec) != REC_ACTIVE
        || nibbler_mutex_is_mine(&rec->lock) || rec_lock(rec) < 0)
    {
        return 1;
    }
    int r = 1;
    Py_ssize_t out = 0;
    if (rec->state == REC_ACTIVE) {
        /* The block's raw stream is alive while it is active: no
           reference is needed while it is the stream's. */
        PyObject *raw = FT_ATOMIC_LOAD_PTR_RELAXED(self->raw);
        r = (raw == rec->raw ? buffered_ref_closed(raw) : -2);
        if (r == -2) {
            raw = buffered_get_raw(self);
            r = raw ? buffered_ref_closed(raw) : -1;
            Py_XDECREF(raw);
        }
        if (r > 0) {
            PyErr_SetString(PyExc_ValueError, closed_msg);
        }
        Py_ssize_t size = Py_MIN(GATHER_BLOCK_MAX,
                                 Py_MAX(GATHER_BLOCK_MIN, rec->list.nbytes));
        r = (r != 0 ? -1
             : buffered_append_to(self, &rec->list, &rec->block, &rec->used,
                                  size, obj, data, len));
        if (r == 0 && (rec->direct | rec->line)) {
            out = gather_out(rec, data, len);
        }
    }
    int full = r == 0 && rec->list.nbytes >= rec->limit;
    rec_unlock(rec);
    if (out > 0) {
        /* (Kept on error: written out at the next one or the end.) */
        (void)gather_end(self, rec, out, NULL);
        PyErr_Clear();
    }
    else if (full) {
        /* (Kept on error: moved at the next write or the end.) */
        if (buffered_lock_ex(self, 0) == 0) {
            if (!self->reading && rec_lock(rec) == 0) {
                (void)gather_move(self, rec, PY_SSIZE_T_MAX);
                rec_unlock(rec);
            }
            buffered_unlock(self);
        }
        PyErr_Clear();
    }
    return r;
}

/* Take the I/O role and the lock, not interrupted: the data a block
   gathered was accepted. */
static int
gather_lock(buffered *self)
{
    int t = nibbler_mutex_lock(&self->io, (PyObject *)self, 0);
    if (t < 0) {
        return -1;
    }
    if (buffered_lock_ex(self, 0) < 0) {
        nibbler_mutex_unlock(&self->io);
        return -1;
    }
    if (t > 0 || self->drop_inflight) {
        buffered_drop_inflight(self);
    }
    return 0;
}

/* With the lock and the I/O role, after a block's data was moved: write
   out the pending writes if they don't fit (all of them after a deferred
   flush()); what would block stays pending, but for flush().  Returns 0
   or -1. */
static int
gather_write_out(buffered *self, int flush)
{
    if (self->reading || !(self->list.nbytes > self->threshold
                           || (flush && self->list.nbytes > 0)))
    {
        return 0;
    }
    int st;
    (void)buffered_write_out(self, self->list.nbytes, NULL, NULL, 0, 1, &st);
    if (st == WOULD_BLOCK && flush) {
        buffered_set_blocking_error(0);
    }
    return st == -1 || (st != 0 && flush) ? -1 : 0;
}

/* End rec's block by moving its data to the pending writes with the lock
   taken without waiting, as a write that fits would add it (and the I/O
   role when they don't fit then).  Returns 1 when the lock is busy (or
   the I/O role is, for a deferred flush() or twice the threshold), or the
   stream needs more than that (a read-ahead to hand back, a raw stream
   other than an exact FileIO to ask whether it is closed), else 0 or -1
   (rec keeps what it couldn't move, as gather_end() does). */
static int
gather_splice(buffered *self, record *rec)
{
    if (!nibbler_mutex_trylock(&self->lock)) {
        return 1;
    }
    if (self->raw == NULL || !self->raw_fileio || self->reading
        || _PyFileIO_closed(self->raw) || nibbler_mutex_is_mine(&rec->lock)
        || rec_lock(rec) < 0)
    {
        buffered_unlock(self);
        return 1;
    }
    int flush = rec->flush, io = 0;
    Py_ssize_t over = self->list.nbytes + rec->list.nbytes - self->threshold;
    if (rec->state != REC_ACTIVE) {
        goto busy;
    }
    if (over > 0 || flush) {
        io = nibbler_mutex_trylock(&self->io);
        if (io && self->drop_inflight) {
            buffered_drop_inflight(self);
        }
        /* (Without the role, too much pending waits for it.) */
        if (!io && (flush || over > self->threshold)) {
            goto busy;
        }
    }
    int r = gather_move(self, rec, PY_SSIZE_T_MAX);
    rec_set_state(rec, r == 0 ? REC_IDLE : REC_PENDING);
    rec_unlock(rec);
    if (r == 0 && io) {
        r = gather_write_out(self, flush);
    }
    if (io) {
        nibbler_mutex_unlock(&self->io);
    }
    buffered_unlock(self);
    return r;
busy:
    rec_unlock(rec);
    buffered_unlock(self);
    return 1;
}

/* End rec's block by writing its data out with rec's lock alone, when the
   stream allows (see above); with n >= 0, write out its first n bytes in
   the block.  Returns 1 if it doesn't, or the raw stream would block, else
   0 or -1; rec keeps what wasn't written. */
static int
gather_direct(buffered *self, record *rec, Py_ssize_t n)
{
    if (!FT_ATOMIC_LOAD_UINT8_RELAXED(self->direct)) {
        return 1;
    }
    if (rec_lock(rec) < 0) {
        return -1;
    }
    morsel_list *l = &rec->list;
    /* (raw stays while direct is set and rec is locked.) */
    if (rec->state != REC_ACTIVE || !FT_ATOMIC_LOAD_UINT8(self->direct)
        || (!rec->direct && FT_ATOMIC_LOAD_SSIZE_RELAXED(self->list.nbytes))
        || _PyFileIO_closed(FT_ATOMIC_LOAD_PTR_RELAXED(self->raw)))
    {
        rec_unlock(rec);
        return 1;
    }
    int st = 0, end = n < 0;
    n = end ? l->nbytes : Py_MIN(n, l->nbytes);
    if (l->count - l->head > _PyIO_WRITEV_MAX) {
        /* Joined, for one writev(). */
        Py_ssize_t all = l->nbytes;
        PyObject *b = PyBytes_FromStringAndSize(NULL, all);
        if (b == NULL) {
            st = -1;
        }
        else {
            (void)morsels_take(l, PyBytes_AS_STRING(b), all);
            (void)morsels_push(l, b, PyBytes_AS_STRING(b), all);
            Py_DECREF(b);
        }
    }
    if (st == 0 && n > 0) {
        _PyIO_Span spans[_PyIO_WRITEV_MAX];
        PyObject *objs[_PyIO_WRITEV_MAX];
        Py_ssize_t cnt = 0, total = 0, written;
        for (Py_ssize_t i = l->head; total < n; i++, cnt++) {
            Py_ssize_t k = Py_MIN(l->items[i].len, n - total);
            spans[cnt] = (_PyIO_Span){l->items[i].ptr, k};
            objs[cnt] = Py_NewRef(l->items[i].obj);
            total += k;
        }
        rec_set_state(rec, REC_WRITING);
        st = buffered_write_spans(self, spans, objs, cnt, n, -1, &written);
        for (Py_ssize_t i = 0; i < cnt; i++) {
            Py_DECREF(objs[i]);
        }
        (void)morsels_consume(l, written);
    }
    if (st == 0 && l->nbytes == 0) {
        /* The block is free again for the next one. */
        rec->used = 0;
    }
    rec_set_state(rec, st == 0 && end ? REC_IDLE : REC_ACTIVE);
    rec_unlock(rec);
    return st == 0 ? 0 : st == WOULD_BLOCK ? 1 : -1;
}

/* End rec's block (n < 0): write it out directly (see above), else move
   it to the pending writes with the I/O role and the lock, then write
   them out when they don't fit (all of them after a deferred flush()); or
   drop it when the stream is closed or detached (*dropped: how many bytes;
   ValueError if any, or a deferred flush).  What can't be moved stays,
   pending (moved by the next operation needing the position, close(),
   detach() or __init__()).  With n >= 0, write out the first n bytes of
   the active block the same way (kept if closed; dropped is NULL).
   Returns 0, or -1 (with an exception set but when dropping or keeping). */
static int
gather_end(buffered *self, record *rec, Py_ssize_t n, Py_ssize_t *dropped)
{
    Py_ssize_t none;
    dropped = n < 0 ? dropped : &none;
    *dropped = 0;
    int r = rec->direct ? gather_direct(self, rec, n) : 1;
    if ((r > 0 && n < 0 && (r = gather_splice(self, rec)) <= 0)
        || (r < 0 && n >= 0))
    {
        /* (Kept in the block on error: written out in order later.) */
        return r;
    }
    if (r > 0 && !rec->direct) {
        r = gather_direct(self, rec, n);
    }
    if (r == 0) {
        return 0;
    }
    PyObject *exc = r < 0 ? PyErr_GetRaisedException() : NULL;
    int locked = gather_lock(self) == 0;
    int closed = (!locked ? 0 : self->raw == NULL ? 1
                  : buffered_is_closed(self));
    r = locked ? 0 : -1;
    if (locked && closed == 0 && self->reading
        && FT_ATOMIC_LOAD_SSIZE_RELAXED(rec->list.nbytes) > 0)
    {
        r = buffered_rewind(self);
    }
    int flush = 0;
    if (rec_lock(rec) < 0) {
        r = -1;
    }
    else {
        flush = n >= 0 || rec->flush;
        if (locked && closed != 0 && n >= 0) {
            r = -1;
        }
        else if (locked && closed != 0) {
            *dropped = rec->list.nbytes;
            if (closed > 0 && (*dropped > 0 || flush)) {
                PyErr_SetString(PyExc_ValueError,
                                *dropped > 0 ? "write to closed file"
                                             : "flush of closed file");
            }
            morsels_clear(&rec->list);
            r = -1;
        }
        else if (r == 0) {
            r = gather_move(self, rec, n < 0 ? PY_SSIZE_T_MAX : n);
        }
        if (n < 0) {
            rec_set_state(rec, r == 0 || closed != 0 ? REC_IDLE : REC_PENDING);
        }
        rec_unlock(rec);
    }
    if (r == 0 && exc == NULL) {
        r = gather_write_out(self, flush);
    }
    if (locked) {
        buffered_unlock_io(self);
    }
    if (exc != NULL) {
        _PyErr_ChainExceptions1(exc);
        r = -1;
    }
    return r;
}

/* With rec's lock: make it active for g's block. */
static void
rec_start(record *rec, gather *g)
{
    rec->raw = g->raw;
    rec->limit = g->limit;
    rec->flush = 0;
    rec->direct = g->direct;
    rec->line = g->line;
    rec_set_state(rec, REC_ACTIVE);
}

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
    PyObject *raw = buffered_get_raw(self);
    int r = raw == NULL ? -1 : buffered_ref_closed(raw);
    if (r > 0) {
        PyErr_SetString(PyExc_ValueError, "gather on closed file");
        r = -1;
    }
    Py_XSETREF(g->raw, raw);
    /* Its context's earlier writes first (see above). */
    if (r == 0 && g->direct && (r = buffered_lock_io(self)) == 0) {
        r = self->raw == NULL ? buffered_not_ready() : buffered_sync(self, 1);
        buffered_unlock_io(self);
    }
    /* The context's record: this block is in it if active; else made
       active, without the lock while still listed. */
    record *rec = r == 0 ? gather_current(self) : NULL;
    int state = REC_FREE;
    if (rec != NULL) {
        if (rec_lock(rec) < 0) {
            return NULL;
        }
        state = rec->state;
        if (state == REC_IDLE) {
            rec_start(rec, g);
        }
        rec_unlock(rec);
    }
    if (r == 0 && state != REC_ACTIVE && state != REC_IDLE) {
        if (rec == NULL || state != REC_FREE) {
            PyTypeObject *tp = find_nibblermodule_state_by_def(
                Py_TYPE(self))->Record_Type;
            rec = (record *)tp->tp_alloc(tp, 0);
            PyObject *token = rec ? PyContextVar_Set(self->gvar,
                                                     (PyObject *)rec) : NULL;
            /* (The context keeps it.) */
            Py_XDECREF(rec);
            if (token == NULL) {
                return NULL;
            }
            Py_DECREF(token);
            rec->stream = self;
            rec->ctx = tstate->context;
            gather_remember(tstate, self->gvar, rec);
        }
        /* Listed with the lock, dropping idle records; written out
           directly from now on if the stream allows (see above). */
        if ((r = buffered_lock_io(self)) == 0) {
            r = (self->raw == NULL ? buffered_not_ready()
                 : buffered_check_closed(self, "gather on closed file"));
            if (r == 0 && self->ngather > 0) {
                r = gather_move_records(self, -1);
            }
            if (r == 0 && (r = rec_lock(rec)) == 0) {
                rec->next = self->recs;
                self->recs = (record *)Py_NewRef(rec);
                FT_ATOMIC_STORE_INT_RELAXED(self->ngather, self->ngather + 1);
                rec_start(rec, g);
                rec_unlock(rec);
                int direct = (
                    self->raw_fileio && _PyFileIO_regular(self->raw)
                    && PyType_GetBaseByToken(Py_TYPE(self),
                                             &nibbler_bufferedwriter_spec,
                                             NULL) > 0);
                if (direct) {
                    self->raw_regular = 0;
                    self->raw_pos = POS_UNKNOWN;
                    /* Settled first, with the I/O role: FileIO keeps it in
                       a bit field next to those writes read, which tell()
                       would store. */
                    PyObject *res = PyObject_CallMethodNoArgs(
                        self->raw, &_Py_ID(seekable));
                    direct = res != NULL;
                    Py_XDECREF(res);
                    PyErr_Clear();
                }
                FT_ATOMIC_STORE_UINT8(self->direct, direct);
            }
            buffered_unlock_io(self);
        }
    }
    if (r < 0) {
        return NULL;
    }
    g->joined = state == REC_ACTIVE;
    g->rec = (record *)Py_NewRef(rec);
    g->ctx = Py_NewRef(tstate->context);
    g->state = GATHER_ACTIVE;
    return Py_NewRef(self);
}

/* The end of a block: what it gathered is written out or moved, also when
   the block raised (as buffered data would be written). */
static PyObject *
gather_exit(PyObject *op, PyObject *const *Py_UNUSED(args),
            Py_ssize_t Py_UNUSED(nargs))
{
    gather *g = (gather *)op;
    if (g->state != GATHER_ACTIVE) {
        PyErr_SetString(PyExc_RuntimeError, "_gather() block not entered");
        return NULL;
    }
    g->state = GATHER_DONE;
    Py_ssize_t dropped;
    if (!g->joined && gather_end(g->stream, g->rec, -1, &dropped) < 0
        && PyErr_Occurred())
    {
        return NULL;
    }
    Py_RETURN_FALSE;
}

/* A block dropped before it ended: end it, with a ResourceWarning. */
static void
gather_finalize(PyObject *op)
{
    gather *g = (gather *)op;
    if (g->state != GATHER_ACTIVE || g->joined) {
        return;
    }
    g->state = GATHER_DONE;
    buffered *self = g->stream;
    record *rec = g->rec;
    PyObject *exc = PyErr_GetRaisedException();
    Py_ssize_t dropped = 0;
    /* Code of this thread holding the locks further up its stack may be
       in the middle of something: the data is dropped then. */
    if (!nibbler_mutex_is_mine(&self->lock)
        && !nibbler_mutex_is_mine(&self->io))
    {
        (void)gather_end(self, rec, -1, &dropped);
    }
    else if (rec_lock(rec) == 0) {
        dropped = rec->list.nbytes;
        morsels_clear(&rec->list);
        rec_set_state(rec, REC_IDLE);
        rec_unlock(rec);
    }
    PyErr_Clear();
    /* Without the lock: the warning may write to the stream. */
    int w = dropped > 0
        ? PyErr_WarnFormat(PyExc_ResourceWarning, 1,
                           "_gather() block never ended: %zd gathered bytes "
                           "were dropped", dropped)
        : PyErr_WarnEx(PyExc_ResourceWarning,
                       "_gather() block never ended: its data was "
                       "written when it was dropped", 1);
    if (w < 0) {
        PyErr_WriteUnraisable((PyObject *)g);
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
    Py_VISIT(g->raw);
    return 0;
}

static int
gather_clear(PyObject *op)
{
    gather *g = (gather *)op;
    Py_CLEAR(g->stream);
    Py_CLEAR(g->ctx);
    Py_CLEAR(g->raw);
    Py_CLEAR(g->rec);
    return 0;
}

static void
gather_dealloc(PyObject *op)
{
    PyTypeObject *tp = Py_TYPE(op);
    if (PyObject_CallFinalizerFromDealloc(op) < 0) {
        return;
    }
    PyObject_GC_UnTrack(op);
    (void)gather_clear(op);
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
    {Py_tp_finalize, gather_finalize},
    {Py_tp_methods, gather_methods},
    {0, NULL},
};

static PyType_Spec gather_spec = {
    .name = "_io._nibbler.Gather",
    .basicsize = sizeof(gather),
    .flags = (Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC
              | Py_TPFLAGS_IMMUTABLETYPE | Py_TPFLAGS_DISALLOW_INSTANTIATION),
    .slots = gather_slots,
};

static void
record_dealloc(PyObject *op)
{
    PyTypeObject *tp = Py_TYPE(op);
    record *rec = (record *)op;
    _Py_atomic_add_uint64(&gather_freed, 1);
    morsels_clear(&rec->list);
    PyMem_Free(rec->list.items);
    Py_XDECREF(rec->block);
    tp->tp_free(op);
    Py_DECREF(tp);
}

static PyType_Slot record_slots[] = {
    {Py_tp_dealloc, record_dealloc},
    {0, NULL},
};

static PyType_Spec record_spec = {
    .name = "_io._nibbler.GatherRecord",
    .basicsize = sizeof(record),
    .flags = (Py_TPFLAGS_DEFAULT | Py_TPFLAGS_IMMUTABLETYPE
              | Py_TPFLAGS_DISALLOW_INSTANTIATION),
    .slots = record_slots,
};

/*
 * Writing
 */

/* Make the raised OSError or MemoryError say that n bytes of write()'s
   data were accepted (written, or kept pending). */
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

/* write() raised after `done` bytes of its data were written: keep as
   much of the rest as fits pending, and say how much was accepted, so
   that the caller knows what to write again.  Returns -1. */
static int
buffered_write_failed(buffered *self, PyObject *obj, const char *data,
                      Py_ssize_t len, Py_ssize_t done)
{
    if (done == 0) {
        return -1;
    }
    PyObject *exc = PyErr_GetRaisedException();
    Py_ssize_t keep = Py_MIN(len - done, Py_MAX(0, self->threshold
                                                   - self->list.nbytes));
    if (buffered_append(self, obj, data + done, keep) < 0) {
        _PyErr_ChainExceptions1(exc);
        keep = 0;
    }
    else {
        PyErr_SetRaisedException(exc);
    }
    buffered_set_written(done + keep);
    return -1;
}

/* BufferedRandom: write data over the read-ahead in place when it lies
   inside it and nothing else references the block, to be written out
   before the next raw call (as _io does).  Not with buffer size None,
   whose pending writes reads write out.  Returns 1 if done. */
static int
buffered_write_in_place(buffered *self, const char *data, Py_ssize_t len)
{
    if (len > self->end - self->pos || self->list.nbytes > 0
        || self->raw_appending || self->threshold == PY_SSIZE_T_MAX
        || !_PyObject_IsUniquelyReferenced(self->block))
    {
        return 0;
    }
    memcpy(PyBytes_AS_STRING(self->block) + self->pos, data, len);
    if (self->dhi == self->dlo) {
        self->dlo = self->pos;
    }
    self->dlo = Py_MIN(self->dlo, self->pos);
    self->pos += len;
    self->dhi = Py_MAX(self->dhi, self->pos);
    return 1;
}

/* write() past what fits, with the lock held: write out with the I/O
   role, without the lock. */
Py_NO_INLINE static int
buffered_write_slow(buffered *self, PyObject *obj, const char *data,
                    Py_ssize_t len, const char *closed_msg, int open_fileio)
{
    int t = buffered_take_io(self);
    if (t == IO_MINE) {
        /* From this thread's write out (a signal handler printing,
           gh-118143): queue it all, for that write out or the next. */
        int r = buffered_append(self, obj, data, len);
        buffered_unlock(self);
        return r;
    }
    if (t < 0) {
        return -1;
    }
    int r = -1;
    Py_ssize_t done = 0;
    if (self->raw == NULL) {
        buffered_not_ready();
        goto end;
    }
    /* (Not if the lock was held since write() found a FileIO open.) */
    if ((t == IO_WAITED || !open_fileio)
        && buffered_check_closed(self, closed_msg) < 0)
    {
        goto end;
    }
    if (self->reading) {
        if (buffered_write_in_place(self, data, len)) {
            r = 0;
            goto end;
        }
        if (buffered_rewind(self) < 0) {
            goto end;
        }
    }
    for (;;) {
        Py_ssize_t rest = len - done, th = self->threshold;
        if (rest == 0 || (rest < th && self->list.nbytes + rest <= th)) {
            r = buffered_append(self, obj, data + done, rest);
            if (r < 0 && done > 0) {
                buffered_set_written(done);
            }
            break;
        }
        int st;
        if (self->list.nbytes == 0) {
            /* Nothing pending (as unbuffered): the data alone. */
            _PyIO_Span span = {data + done, rest};
            Py_ssize_t written;
            st = buffered_write_spans(self, &span, &obj, 1, rest, 1,
                                      &written);
            done += written;
        }
        else {
            /* Pending writes, and data too when too large to buffer, or
               when one vectored write takes both (with a Python _writev(),
               only data large enough to be kept by reference). */
            int vectored = (self->raw_vectored
                            && (self->raw_fileio || rest >= self->ref_min));
            done += buffered_write_out(self, self->list.nbytes, obj,
                                       data + done,
                                       rest >= th || vectored ? rest : 0, 1,
                                       &st);
        }
        if (st == 0 && done == len) {
            r = 0;
            break;
        }
        if (st == 0) {
            continue;
        }
        if (st == -1) {
            r = buffered_write_failed(self, obj, data, len, done);
            break;
        }
        /* Would block: keep what fits, and say how much that is. */
        int errnum = errno;
        rest = len - done;
        Py_ssize_t keep = Py_MIN(rest, Py_MAX(0, th - self->list.nbytes));
        r = buffered_append(self, obj, data + done, keep);
        if (r == 0 && keep < rest) {
            errno = errnum;
            buffered_set_blocking_error(done + keep);
            r = -1;
        }
        else if (r < 0 && done > 0) {
            buffered_set_written(done);
        }
        break;
    }
end:
    buffered_unlock_io(self);
    return r;
}

/* write() of data[0:len], inside obj (or NULL).  A write that fits is
   queued with the lock alone, checking only that an exact FileIO is open:
   other raw streams are asked through `closed` (a Python call costing
   more than such a write) by operations taking the I/O role, and small
   writes (under REF_MIN bytes) that fit go on trusting the last answer
   (raw_open) until the buffer is full, freed, or another operation finds
   raw closed.  Returns 0 or -1. */
static int
buffered_write(buffered *self, PyObject *obj, const char *data,
               Py_ssize_t len, const char *closed_msg)
{
    if (FT_ATOMIC_LOAD_INT_RELAXED(self->ngather) > 0) {
        int r = gather_write(self, obj, data, len, closed_msg);
        if (r <= 0) {
            return r;
        }
    }
    if (buffered_lock(self) < 0) {
        return -1;
    }
    int done = 0;
    int open_fileio = self->raw_fileio && !_PyFileIO_closed(self->raw);
    /* Else raw is asked whether it is open, with the I/O role (see
       buffered_write_slow()). */
    int trusted = (self->raw_fileio ? open_fileio
                   : self->raw_open && len < REF_MIN);
    if (trusted && self->reading) {
        done = buffered_write_in_place(self, data, len);
    }
    else if (trusted && len < self->threshold
             && self->list.nbytes + len <= self->threshold)
    {
        done = buffered_append(self, obj, data, len) < 0 ? -1 : 1;
    }
    if (done == 0) {
        return buffered_write_slow(self, obj, data, len, closed_msg,
                                   open_fileio);
    }
    buffered_unlock(self);
    return done < 0 ? -1 : 0;
}

/*
 * Reading (with the lock; raw reads with the I/O role too)
 */

/* Take up to n bytes of the read-ahead: the block itself when that is all
   of it, else a copy. */
static PyObject *
buffered_take(buffered *self, Py_ssize_t n)
{
    Py_ssize_t k = Py_MIN(n, self->end - self->pos);
    if (k == 0) {
        return Py_GetConstant(Py_CONSTANT_EMPTY_BYTES);
    }
    const char *p = PyBytes_AS_STRING(self->block) + self->pos;
    self->pos += k;
    if (k == PyBytes_GET_SIZE(self->block)) {
        return Py_NewRef(self->block);
    }
    return PyBytes_FromStringAndSize(p, k);
}

/* Make data[0:len] the read-ahead again, in front of what is unread
   (bytes a failed read took, gh-51571).  Keeps the raised exception. */
static int
buffered_push_back(buffered *self, const char *data, Py_ssize_t len)
{
    if (len == 0) {
        return 0;
    }
    PyObject *exc = PyErr_GetRaisedException();
    Py_ssize_t unread = self->end - self->pos;
    PyObject *block = PyBytes_FromStringAndSize(NULL, len + unread);
    if (block != NULL) {
        memcpy(PyBytes_AS_STRING(block), data, len);
        if (unread > 0) {
            memcpy(PyBytes_AS_STRING(block) + len,
                   PyBytes_AS_STRING(self->block) + self->pos, unread);
        }
        buffered_set_block(self, block);
        self->pos = self->noline = 0;
        self->end = len + unread;
        self->stop = PY_SSIZE_T_MAX;
        self->reading = 1;
    }
    _PyErr_ChainExceptions1(exc);
    return block == NULL ? -1 : 0;
}

/* One raw read after the unread bytes, which stay in front (a partial
   line, or TextIOWrapper's partial character): into the tail of the block
   when it has room for half a block, else moved to the start of a block,
   a bigger one when they take more than half a block (half as big again,
   and a block more, up to grow_max or a block more), so that a line of
   any length is copied a bounded number of times.  Unbuffered, `size`
   bytes more.  Returns the count (0 at EOF), WOULD_BLOCK or -1. */
static Py_ssize_t
buffered_fill(buffered *self, Py_ssize_t size, Py_ssize_t grow_max)
{
    if (buffered_flush_dirty(self, 1) < 0) {
        return -1;
    }
    Py_ssize_t cap = self->capacity, unread = self->end - self->pos;
    PyObject *block = self->block;
    if (unread == 0 || cap == 0
        || Py_MIN(self->stop, PyBytes_GET_SIZE(block)) - self->end
           < Py_MAX(cap / 2, 1)
        || !_PyObject_IsUniquelyReferenced(block))
    {
        Py_ssize_t size_new = (cap == 0 ? unread + size
                               : unread == 0 ? cap + PAD
                               : unread <= cap / 2 ? cap
                               : Py_MIN(unread + Py_MAX(unread / 2, cap),
                                        Py_MAX(grow_max, unread + cap)));
        if (block != NULL && PyBytes_GET_SIZE(block) >= size_new
            && _PyObject_IsUniquelyReferenced(block))
        {
            memmove(PyBytes_AS_STRING(block),
                    PyBytes_AS_STRING(block) + self->pos, unread);
        }
        else {
            PyObject *b = PyBytes_FromStringAndSize(NULL, size_new);
            if (b == NULL) {
                return -1;
            }
            if (unread > 0) {
                memcpy(PyBytes_AS_STRING(b),
                       PyBytes_AS_STRING(block) + self->pos, unread);
            }
            buffered_set_block(self, b);
        }
        self->noline = Py_MAX(0, self->noline - self->pos);
        self->pos = 0;
        self->end = unread;
        self->stop = PY_SSIZE_T_MAX;
        if (unread == 0 && cap > 0) {
            /* A fresh fill of a block of the buffer's size reads cap bytes
               to the address congruent to the raw position mod PAD (where
               the kernel copies fastest), 64-aligned if unknown. */
            Py_off_t at = self->raw_pos >= 0 ? self->raw_pos : 0;
            self->pos = self->end = (Py_ssize_t)(
                ((uintptr_t)at - (uintptr_t)PyBytes_AS_STRING(self->block))
                % PAD);
            self->stop = self->pos + cap;
        }
    }
    self->reading = 1;
    /* The read holds its own reference to the block. */
    block = Py_NewRef(self->block);
    char *dst = PyBytes_AS_STRING(block);
    int shared = 0;
    Py_ssize_t n = buffered_raw_read(
        self, dst + self->end,
        Py_MIN(self->stop, PyBytes_GET_SIZE(block)) - self->end, block,
        &shared);
    self->end += Py_MAX(n, 0);
    if (shared && block == self->block) {
        /* Python code can still write to the block: abandon it to that
           code, keeping a copy. */
        PyObject *exc = PyErr_GetRaisedException();
        PyObject *copy = PyBytes_FromStringAndSize(dst, self->end);
        if (copy != NULL) {
            buffered_set_block(self, copy);
        }
        else {
            buffered_drop_read(self);
            n = -1;
        }
        _PyErr_ChainExceptions1(exc);
    }
    Py_DECREF(block);
    return n;
}

/* Read up to len bytes into dst (inside memobj, see buffered_memory_view()):
   the read-ahead, then from the raw stream until len bytes, EOF, or it
   would block; a request of at least a buffer's worth straight into dst.
   read1 makes one raw read at most, and none into the read-ahead once
   there is data.  Returns the count, WOULD_BLOCK if it would block before
   any data, or -1 (what was read stays for the next read). */
static Py_ssize_t
buffered_read_into(buffered *self, char *dst, Py_ssize_t len, int read1,
                   PyObject *memobj, int *shared)
{
    Py_ssize_t written = 0;
    for (int reads = 0; ; reads++) {
        Py_ssize_t k = Py_MIN(len - written, self->end - self->pos);
        if (k > 0) {
            memcpy(dst + written, PyBytes_AS_STRING(self->block) + self->pos,
                   k);
            self->pos += k;
            written += k;
        }
        Py_ssize_t rest = len - written, n;
        if (rest == 0 || (read1 && reads > 0)) {
            break;
        }
        if (rest >= self->capacity) {
            if (buffered_flush_dirty(self, 1) < 0) {
                n = -1;
            }
            else {
                /* The block no longer precedes the raw position. */
                self->pos = self->end = self->noline = 0;
                self->stop = PY_SSIZE_T_MAX;
                n = buffered_raw_read(self, dst + written, rest, memobj,
                                      shared);
                written += Py_MAX(n, 0);
            }
        }
        else if (read1 && written > 0) {
            break;
        }
        else {
            n = buffered_fill(self, rest, PY_SSIZE_T_MAX);
        }
        if (n == 0 || (n == WOULD_BLOCK && written > 0)) {
            break;
        }
        if (n == -1) {
            (void)buffered_push_back(self, dst, written);
        }
        if (n < 0) {
            return n;
        }
    }
    return written;
}

/* read(n) (n >= 0) and read1(n). */
static PyObject *
buffered_read_bytes(buffered *self, Py_ssize_t n, int read1)
{
    if (read1 && self->end == self->pos && n > 0 && n < self->capacity) {
        /* One raw read into the read-ahead, which may then be handed out
           whole. */
        Py_ssize_t r = buffered_fill(self, n, PY_SSIZE_T_MAX);
        if (r <= 0) {
            return (r == 0 ? Py_GetConstant(Py_CONSTANT_EMPTY_BYTES)
                    : r == WOULD_BLOCK ? Py_NewRef(Py_None) : NULL);
        }
    }
    Py_ssize_t avail = self->end - self->pos;
    if (n == 0 || (avail > 0 && (read1 || avail >= n))) {
        return buffered_take(self, n);
    }
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
        /* Python code can still write to res. */
        Py_SETREF(res, PyBytes_FromStringAndSize(PyBytes_AS_STRING(res), r));
    }
    else if (r < n) {
        (void)_PyBytes_Resize(&res, r);
    }
    return res;
}

/* Call raw.read(size) (raw.read() without size) until EOF or it would
   block, keeping each chunk in the stash (so that nothing is lost if a
   later call raises).  Returns the final b"" or None, or NULL. */
static PyObject *
buffered_read_chunks(buffered *self, PyObject *size)
{
    for (;;) {
        if (morsels_reserve(&self->list) < 0) {
            return NULL;
        }
        PyObject *data = (size == NULL
                          ? PyObject_CallMethodNoArgs(self->raw, &_Py_ID(read))
                          : PyObject_CallMethodOneArg(self->raw, &_Py_ID(read),
                                                      size));
        if (data == NULL && _PyIO_trap_eintr()) {
            continue;
        }
        if (data != NULL && data != Py_None && !PyBytes_Check(data)) {
            Py_DECREF(data);
            PyErr_SetString(PyExc_TypeError, "read() should return bytes");
            return NULL;
        }
        if (data == NULL || data == Py_None || PyBytes_GET_SIZE(data) == 0) {
            return data;
        }
        (void)morsels_push(&self->list, data, PyBytes_AS_STRING(data),
                           PyBytes_GET_SIZE(data));
        Py_DECREF(data);
        self->reading = 1;
    }
}

/* What the raw stream has to EOF (or until it would block): bytes or
   None, or NULL.  Some may be in the stash instead. */
static PyObject *
buffered_raw_read_all(buffered *self)
{
    self->raw_pos = POS_UNKNOWN;
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
    /* RawIOBase.readall() loses what it read when a later read raises:
       read its chunks here instead. */
    _PyIO_State *state = find_io_state_by_def(Py_TYPE(self));
    if (_PyType_Lookup(Py_TYPE(self->raw), &_Py_ID(readall))
        == _PyType_Lookup(state->PyRawIOBase_Type, &_Py_ID(readall)))
    {
        Py_DECREF(readall);
        PyObject *size = PyLong_FromSsize_t(Py_MAX(self->capacity,
                                                   DEFAULT_BUFFER_SIZE));
        PyObject *res = size ? buffered_read_chunks(self, size) : NULL;
        Py_XDECREF(size);
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

/* The read-ahead, the stash and the rest of the raw stream. */
static PyObject *
buffered_read_all(buffered *self)
{
    if (buffered_flush_dirty(self, 1) < 0
        || morsels_reserve(&self->list) < 0)
    {
        return NULL;
    }
    PyObject *rest = buffered_raw_read_all(self);
    if (rest == NULL) {
        return NULL;
    }
    Py_ssize_t k = self->end - self->pos, st = self->list.nbytes;
    Py_ssize_t rlen = rest == Py_None ? 0 : PyBytes_GET_SIZE(rest);
    if (k == 0 && st == 0) {
        buffered_drop_read(self);
        return rest;
    }
    PyObject *res = PyBytes_FromStringAndSize(NULL, k + st + rlen);
    if (res == NULL) {
        /* Lose nothing: the rest follows the stash. */
        if (rlen > 0) {
            (void)morsels_push(&self->list, rest, PyBytes_AS_STRING(rest),
                               rlen);
            self->reading = 1;
        }
        Py_DECREF(rest);
        return NULL;
    }
    char *dst = PyBytes_AS_STRING(res);
    if (k > 0) {
        memcpy(dst, PyBytes_AS_STRING(self->block) + self->pos, k);
    }
    (void)morsels_take(&self->list, dst + k, st);
    if (rlen > 0) {
        memcpy(dst + k + st, PyBytes_AS_STRING(rest), rlen);
    }
    Py_DECREF(rest);
    buffered_drop_read(self);
    return res;
}

/* The length of the line at the read-ahead's start, up to limit bytes
   unless that is negative; -1 if it may go on past the read-ahead. */
static Py_ssize_t
buffered_find_line(buffered *self, Py_ssize_t limit)
{
    Py_ssize_t unread = self->end - self->pos;
    Py_ssize_t stop = limit >= 0 && limit < unread ? limit : unread;
    Py_ssize_t scanned = Py_MAX(0, self->noline - self->pos);
    if (scanned < stop) {
        const char *p = PyBytes_AS_STRING(self->block) + self->pos;
        const char *nl = memchr(p + scanned, '\n', stop - scanned);
        if (nl != NULL) {
            return nl - p + 1;
        }
        self->noline = self->pos + stop;
    }
    return limit >= 0 && stop >= limit ? limit : -1;
}

/* readline(), with the I/O role: the read-ahead keeps a partial line as
   more is read (see buffered_fill()), so it is not copied again when the
   raw stream would block or raises, and noline remembers how far there is
   no end of line. */
static PyObject *
buffered_readline(buffered *self, Py_ssize_t limit)
{
    for (;;) {
        Py_ssize_t unread = self->end - self->pos;
        Py_ssize_t k = buffered_find_line(self, limit);
        if (k >= 0) {
            return buffered_take(self, k);
        }
        Py_ssize_t r = buffered_fill(self, 0, PY_SSIZE_T_MAX);
        if (r == 0 || (r == WOULD_BLOCK && unread > self->capacity)) {
            /* EOF, or a partial line longer than the buffer size (the
               bound of every implementation) that would block. */
            return buffered_take(self, self->end - self->pos);
        }
        if (r < 0) {
            /* The partial line stays for the next call (gh-51571). */
            return r == WOULD_BLOCK ? Py_NewRef(Py_None) : NULL;
        }
    }
}

/*
 * Methods
 */

/* Flags of buffered_enter(). */
enum { ENTER_READ = 1, ENTER_LEAVE_GATHERED = 2 };

/* Start of the methods making raw calls: take the I/O role and the lock,
   check that the object is initialized and, unless closed_msg is NULL,
   that raw is open (but reading what is buffered needs no open raw
   stream), move what the context's _gather() block gathered (but with
   ENTER_LEAVE_GATHERED), and with ENTER_READ, write out pending writes.
   Release with buffered_unlock_io(). */
static int
buffered_enter(buffered *self, const char *closed_msg, int flags)
{
    if (buffered_lock_io(self) < 0) {
        return -1;
    }
    if (self->raw == NULL) {
        buffered_not_ready();
        goto error;
    }
    if (closed_msg != NULL && (!(flags & ENTER_READ) || self->end == self->pos)
        && buffered_check_closed(self, closed_msg) < 0)
    {
        goto error;
    }
    if (self->ngather > 0 && !(flags & ENTER_LEAVE_GATHERED)) {
        /* (When the stream is closed, the block's end raises.) */
        int closed = buffered_is_closed(self);
        if (closed < 0 || (closed == 0 && gather_move_records(self, 0) < 0)) {
            goto error;
        }
    }
    if ((flags & ENTER_READ) && !self->reading && self->list.nbytes > 0
        && buffered_flush_writes(self, 0) < 0)
    {
        goto error;
    }
    return 0;
error:
    buffered_unlock_io(self);
    return -1;
}

/* Drop all data and the memory holding it. */
static void
buffered_free(buffered *self)
{
    buffered_drop_read(self);
    morsels_clear(&self->list);
    PyMem_Free(self->list.items);
    self->list = (morsel_list){NULL, 0, 0, 0, 0};
    buffered_set_block(self, NULL);
    self->raw_pos = POS_UNKNOWN;
    /* Writes ask again (raw may be NULL now). */
    self->raw_fileio = self->raw_open = 0;
    FT_ATOMIC_STORE_UINT8_RELAXED(self->direct, 0);
}

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
    buffered_free(self);
    while (self->recs != NULL) {
        record *rec = self->recs;
        self->recs = rec->next;
        rec->next = NULL;
        rec->stream = NULL;
        rec_set_state(rec, REC_FREE);
        Py_DECREF(rec);
    }
    Py_CLEAR(self->gvar);
    (void)buffered_clear(op);
    tp->tp_free(self);
    Py_DECREF(tp);
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

/*[clinic input]
_io._Buffered.__sizeof__
[clinic start generated code]*/

static PyObject *
_io__Buffered___sizeof___impl(buffered *self)
/*[clinic end generated code: output=0231ef7f5053134e input=753c782d808d34df]*/
{
    size_t res = _PyObject_SIZE(Py_TYPE(self));
    /* The block counts while allocated (from its first use to close()). */
    if (FT_ATOMIC_LOAD_PTR_RELAXED(self->block) != NULL) {
        res += (size_t)FT_ATOMIC_LOAD_SSIZE_RELAXED(self->capacity);
    }
    return PyLong_FromSize_t(res);
}

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
        PyObject *r = PyObject_CallMethodOneArg(raw, &_Py_ID(_dealloc_warn),
                                                source);
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
    if (buffered_enter(self, NULL, 0) < 0) {
        return NULL;
    }
    Py_ssize_t n = self->reading ? 0 : self->list.nbytes;
    if (n > 0) {
        morsels_clear(&self->list);
    }
    buffered_unlock_io(self);
    return PyLong_FromSsize_t(n);
}

/* Methods and attributes passed on to the raw stream, without the lock,
   so that they never wait for I/O in another thread. */
static PyObject *
buffered_raw_call(PyObject *op, PyObject *name)
{
    PyObject *raw = buffered_get_raw(buffered_cast(op));
    PyObject *res = raw ? PyObject_CallMethodNoArgs(raw, name) : NULL;
    Py_XDECREF(raw);
    return res;
}

static PyObject *
buffered_raw_getattr(PyObject *op, void *name)
{
    PyObject *raw = buffered_get_raw(buffered_cast(op));
    PyObject *res = raw ? PyObject_GetAttr(raw, (PyObject *)name) : NULL;
    Py_XDECREF(raw);
    return res;
}

#define BUFFERED_RAW_METHOD(name)                                       \
    static PyObject *                                                   \
    buffered_pass_##name(PyObject *op, PyObject *Py_UNUSED(dummy))      \
    {                                                                   \
        return buffered_raw_call(op, &_Py_ID(name));                    \
    }
BUFFERED_RAW_METHOD(flush)
BUFFERED_RAW_METHOD(seekable)
BUFFERED_RAW_METHOD(readable)
BUFFERED_RAW_METHOD(writable)
BUFFERED_RAW_METHOD(fileno)
BUFFERED_RAW_METHOD(isatty)
#undef BUFFERED_RAW_METHOD

#define RAW_METHODDEF(name) \
    {#name, buffered_pass_##name, METH_NOARGS, #name "($self, /)\n--\n\n"},

/* raw.flush(), directly for an exact FileIO. */
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

/* Is self.flush() ours: an exact class of ours, without an instance
   dict overriding it?  1, 0 or -1. */
static int
buffered_flush_is_ours(buffered *self)
{
    if (!_PyIO_is_nibbler_buffered_type(Py_TYPE(self))) {
        return 0;
    }
    PyObject *dict = FT_ATOMIC_LOAD_PTR_RELAXED(self->dict);
    int r = dict == NULL ? 0 : PyDict_Contains(dict, &_Py_ID(flush));
    return r < 0 ? -1 : !r;
}

/*[clinic input]
_io._Buffered.close
[clinic start generated code]*/

static PyObject *
_io__Buffered_close_impl(buffered *self)
/*[clinic end generated code: output=7280b7b42033be0c input=d20b83d1ddd7d805]*/
{
    if (buffered_enter(self, NULL, 0) < 0) {
        return NULL;
    }
    PyObject *res = NULL, *exc = NULL;
    Py_ssize_t discarded = 0;
    /* gh-138720: the same closed check as flush(). */
    int r = buffered_is_closed(self);
    if (r != 0) {
        res = r > 0 ? Py_NewRef(Py_None) : NULL;
        goto end;
    }
    if (self->finalizing) {
        Py_XDECREF(_io__Buffered__dealloc_warn_impl(self, (PyObject *)self));
    }
    /* What every _gather() block gathered first. */
    if (self->ngather > 0 && gather_move_records(self, 1) < 0) {
        goto end;
    }
    r = buffered_flush_is_ours(self);
    if (r < 0) {
        goto end;
    }
    if (r) {
        r = (buffered_writable(self) ? buffered_sync(self, 0)
                                     : buffered_raw_flush(self));
    }
    else {
        /* flush() was overridden: it takes the locks itself. */
        buffered_unlock_io(self);
        r = _PyFile_Flush((PyObject *)self);
        if (buffered_enter(self, NULL, 0) < 0) {
            return NULL;
        }
    }
    if (r < 0) {
        exc = PyErr_GetRaisedException();
        if (!self->reading) {
            /* Freed below, and never written again (gh-83973). */
            discarded = self->list.nbytes;
        }
    }
    res = (self->raw_fileio ? _PyFileIO_close(self->raw)
           : PyObject_CallMethodNoArgs(self->raw, &_Py_ID(close)));
    buffered_free(self);
    if (exc != NULL) {
        _PyErr_ChainExceptions1(Py_NewRef(exc));
        Py_CLEAR(res);
    }
end:
    buffered_unlock_io(self);
    if (discarded > 0) {
        /* Without the lock: the warning may write to this file. */
        _PyIO_warn_discarded(discarded, PyErr_GivenExceptionMatches(
            exc, PyExc_BlockingIOError));
    }
    Py_XDECREF(exc);
    return res;
}

/*[clinic input]
_io._Buffered.detach
[clinic start generated code]*/

static PyObject *
_io__Buffered_detach_impl(buffered *self)
/*[clinic end generated code: output=dd0fc057b8b779f7 input=482762a345cc9f44]*/
{
    if (FT_ATOMIC_LOAD_PTR_RELAXED(self->raw) == NULL) {
        buffered_not_ready();
        return NULL;
    }
    /* Also what other threads wrote since flush(). */
    if (_PyFile_Flush((PyObject *)self) < 0
        || buffered_enter(self, NULL, 0) < 0)
    {
        return NULL;
    }
    if ((self->ngather > 0 && gather_move_records(self, 1) < 0)
        || (buffered_writable(self) && buffered_sync(self, 0) < 0))
    {
        buffered_unlock_io(self);
        return NULL;
    }
    PyObject *raw = buffered_swap_raw(self, NULL);
    buffered_free(self);
    buffered_unlock_io(self);
    return raw;
}

/*[clinic input]
_io._Buffered.flush
[clinic start generated code]*/

static PyObject *
_io__Buffered_flush_impl(buffered *self)
/*[clinic end generated code: output=da2674ef1ce71f3a input=fda63444697c6bf4]*/
{
    /* But a direct block writes itself out (see "Gathering"). */
    record *rec = (FT_ATOMIC_LOAD_INT_RELAXED(self->ngather) > 0
                   ? gather_current(self) : NULL);
    if (rec != NULL && rec_state(rec) == REC_ACTIVE && rec->direct
        && !nibbler_mutex_is_mine(&rec->lock))
    {
        if (gather_end(self, rec, PY_SSIZE_T_MAX, NULL) < 0) {
            return (PyErr_Occurred() ? NULL
                    : PyErr_Format(PyExc_ValueError, "flush of closed file"));
        }
        Py_RETURN_NONE;
    }
    if (buffered_enter(self, "flush of closed file",
                       ENTER_LEAVE_GATHERED) < 0) {
        return NULL;
    }
    /* Inside a _gather() block, flushing waits for its end. */
    rec = self->ngather > 0 ? gather_current(self) : NULL;
    int deferred = 0;
    if (rec != NULL && !nibbler_mutex_is_mine(&rec->lock)
        && rec_lock(rec) == 0)
    {
        deferred = rec->state == REC_ACTIVE;
        rec->flush |= deferred;
        rec_unlock(rec);
    }
    int r = deferred ? 0 : buffered_sync(self, 1);
    buffered_unlock_io(self);
    return r < 0 ? NULL : Py_NewRef(Py_None);
}

/* The read-ahead, however short (peeking for more could block, as on a
   pipe where pickle.load() peeks for more than it needs): b"" if none. */
static PyObject *
buffered_peek_held(buffered *self)
{
    Py_ssize_t pos = self->pos;
    PyObject *res = buffered_take(self, self->end - pos);
    self->pos = pos;
    return res;
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
    if (buffered_lock(self) < 0) {
        return NULL;
    }
    if (self->end > self->pos && self->ngather == 0) {
        PyObject *res = buffered_peek_held(self);
        buffered_unlock(self);
        return res;
    }
    buffered_unlock(self);
    if (buffered_enter(self, "peek of closed file", ENTER_READ) < 0) {
        return NULL;
    }
    PyObject *res = NULL;
    Py_ssize_t r = 1;
    if (self->capacity == 0 && self->end == self->pos) {
        /* Unbuffered: it can't look ahead without taking the bytes. */
        buffered_unsupported(self, "peek() needs a buffer (buffer_size is 0)");
    }
    else if (self->end > self->pos
             || (r = buffered_fill(self, 0, PY_SSIZE_T_MAX)) >= 0)
    {
        res = buffered_peek_held(self);
    }
    else if (r == WOULD_BLOCK) {
        res = Py_NewRef(Py_None);
    }
    buffered_unlock_io(self);
    return res;
}

/* read(n) (-1: all) and read1(n) with the I/O role.  read(0) and read1(0)
   need no read-ahead: BufferedRandom doesn't write out for them. */
Py_NO_INLINE static PyObject *
buffered_read_locked(buffered *self, Py_ssize_t n, int read1)
{
    if (buffered_enter(self, "read of closed file",
                       n == 0 ? 0 : ENTER_READ) < 0)
    {
        return NULL;
    }
    PyObject *res = (n == -1 ? buffered_read_all(self)
                     : buffered_read_bytes(self, n, read1));
    buffered_unlock_io(self);
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
    if (n > 0) {
        /* With the lock alone when the read-ahead has all of it. */
        if (buffered_lock(self) < 0) {
            return NULL;
        }
        if (self->end - self->pos >= n && self->ngather == 0) {
            PyObject *res = buffered_take(self, n);
            buffered_unlock(self);
            return res;
        }
        buffered_unlock(self);
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
    return buffered_read_locked(self, -1, 0);
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
    if (buffered_lock(self) < 0) {
        return NULL;
    }
    if (self->end > self->pos && n != 0 && self->ngather == 0) {
        PyObject *res = buffered_take(self, n < 0 ? PY_SSIZE_T_MAX : n);
        buffered_unlock(self);
        return res;
    }
    if (n < 0) {
        n = self->capacity > 0 ? self->capacity : DEFAULT_BUFFER_SIZE;
    }
    buffered_unlock(self);
    return buffered_read_locked(self, n, 1);
}

static PyObject *
buffered_readinto_common(buffered *self, Py_buffer *buffer, int readinto1)
{
    if (buffered_enter(self, "readinto of closed file", ENTER_READ) < 0) {
        return NULL;
    }
    /* The raw stream reads into the caller's memory, through a view bound
       to the caller's object: what it keeps stays valid through that. */
    int shared = 0;
    Py_ssize_t n = buffered_read_into(self, buffer->buf, buffer->len,
                                      readinto1, buffer->obj, &shared);
    buffered_unlock_io(self);
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

/*[clinic input]
_io._Buffered.readline
    size: Py_ssize_t(accept={int, NoneType}) = -1
    /
[clinic start generated code]*/

static PyObject *
_io__Buffered_readline_impl(buffered *self, Py_ssize_t size)
/*[clinic end generated code: output=24dd2aa6e33be83c input=673b6240e315ef8a]*/
{
    if (buffered_lock(self) < 0) {
        return NULL;
    }
    Py_ssize_t k = (self->end > self->pos && self->ngather == 0
                    ? buffered_find_line(self, size) : -1);
    if (k >= 0) {
        PyObject *res = buffered_take(self, k);
        buffered_unlock(self);
        return res;
    }
    buffered_unlock(self);
    if (buffered_enter(self, "readline of closed file",
                       size == 0 ? 0 : ENTER_READ) < 0)
    {
        return NULL;
    }
    PyObject *res = (self->capacity == 0
                     ? buffered_unsupported(self, "readline() needs a buffer "
                                                  "(buffer_size is 0)")
                     : buffered_readline(self, size));
    buffered_unlock_io(self);
    return res;
}

/*[clinic input]
_io._Buffered.tell
[clinic start generated code]*/

static PyObject *
_io__Buffered_tell_impl(buffered *self)
/*[clinic end generated code: output=386972ae84716c1e input=ad61e04a6b349573]*/
{
    if (buffered_enter(self, NULL, ENTER_LEAVE_GATHERED) < 0) {
        return NULL;
    }
    /* Pending writes in append mode go to the end of the file: write them
       out, and the raw position is the logical one (gh-80592).  Inside a
       _gather() block, the position is after what it gathered. */
    PyObject *res = NULL;
    if (!self->raw_appending || self->reading
        || buffered_flush_writes(self, 0) == 0)
    {
        record *rec = self->ngather > 0 ? gather_current(self) : NULL;
        res = buffered_position(self, rec && rec_state(rec) == REC_ACTIVE
                                      ? rec->list.nbytes : 0);
    }
    buffered_unlock_io(self);
    return res;
}

/* seek() inside the block, whose bytes end at raw_pos (if known): only
   move.  Returns the position, or NULL (with no exception) if the target
   isn't in it. */
static PyObject *
buffered_seek_within(buffered *self, Py_off_t target, int whence,
                     Py_off_t raw_pos)
{
    if (!self->reading || self->list.nbytes > 0 || raw_pos < 0
        || (whence != SEEK_SET && whence != SEEK_CUR))
    {
        return NULL;
    }
    /* Where block[0] is, and its data (see buffered_fill()); the target
       is compared before it is added, which could overflow. */
    Py_off_t start = raw_pos - self->end;
    Py_off_t base = whence == SEEK_SET ? 0 : start + self->pos;
    Py_off_t lo = start + (self->stop == PY_SSIZE_T_MAX ? 0
                           : self->stop - self->capacity);
    if (target < lo - base || target > raw_pos - base) {
        return NULL;
    }
    Py_off_t at = base + target;
    self->pos = (Py_ssize_t)(at - start);
    self->noline = 0;
    // GH-95782
    return PyLong_FromOff_t(at < 0 ? 0 : at);
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
    int supported = whence >= 0 && whence <= 2;
#ifdef SEEK_HOLE
    supported |= whence == SEEK_HOLE;
#endif
#ifdef SEEK_DATA
    supported |= whence == SEEK_DATA;
#endif
    if (!supported) {
        PyErr_Format(PyExc_ValueError, "whence value %d unsupported", whence);
        return NULL;
    }
    /* Before taking the lock: its __index__() may use this object. */
    Py_off_t target = PyNumber_AsOff_t(targetobj, PyExc_ValueError);
    if ((target == -1 && PyErr_Occurred()) || buffered_lock(self) < 0) {
        return NULL;
    }
    /* Inside the block of a regular file, whose raw position is kept: with
       the lock alone. */
    PyObject *res = (self->raw_fileio && !_PyFileIO_closed(self->raw)
                     && self->ngather == 0
                     ? buffered_seek_within(self, target, whence,
                                            self->raw_pos) : NULL);
    buffered_unlock(self);
    if (res != NULL || PyErr_Occurred()) {
        return res;
    }
    /* Python calls, which may use this object: without the lock. */
    PyObject *raw = buffered_get_raw(self);
    if (raw == NULL) {
        return NULL;
    }
    int r = buffered_ref_closed(raw);
    if (r > 0) {
        PyErr_SetString(PyExc_ValueError, "seek of closed file");
    }
    PyObject *seekable = r ? NULL : PyObject_CallMethodNoArgs(
        raw, &_Py_ID(seekable));
    Py_DECREF(raw);
    r = seekable ? PyObject_IsTrue(seekable) : -1;
    Py_XDECREF(seekable);
    if (r == 0) {
        buffered_unsupported(self, "File or stream is not seekable.");
    }
    if (r <= 0
        || buffered_enter(self, "seek of closed file", 0) < 0)
    {
        return NULL;
    }
    Py_off_t pos = self->raw_pos;
    if (self->reading && pos < 0 && (whence == SEEK_SET || whence == SEEK_CUR)
        && (pos = buffered_raw_tell(self)) == -1)
    {
        goto end;
    }
    res = buffered_seek_within(self, target, whence, pos);
    if (res != NULL || PyErr_Occurred()) {
        goto end;
    }
    if (self->reading) {
        Py_ssize_t unread = self->end - self->pos + self->list.nbytes;
        if (buffered_flush_dirty(self, 1) < 0) {
            goto end;
        }
        buffered_drop_read(self);
        if (whence == SEEK_CUR) {
            target = (target < PY_OFF_T_MIN + unread ? PY_OFF_T_MIN
                      : target - unread);
        }
    }
    else if (self->list.nbytes > 0 && buffered_flush_writes(self, 0) < 0) {
        goto end;
    }
    pos = buffered_raw_seek(self, target, whence);
    if (pos != -1) {
        res = PyLong_FromOff_t(pos);
    }
end:
    buffered_unlock_io(self);
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
    if (buffered_enter(self, "truncate of closed file", 0) < 0) {
        return NULL;
    }
    PyObject *res = NULL;
    if (!buffered_writable(self)) {
        buffered_unsupported(self, "truncate");
    }
    else if (buffered_sync(self, 0) == 0) {
        res = PyObject_CallMethodOneArg(self->raw, &_Py_ID(truncate), pos);
        self->raw_pos = POS_UNKNOWN;
    }
    buffered_unlock_io(self);
    return res;
}

/* A subclass's readline(). */
Py_NO_INLINE static PyObject *
buffered_readline_method(PyObject *op)
{
    PyObject *line = PyObject_CallMethodNoArgs(op, &_Py_ID(readline));
    if (line && line != Py_None && !PyBytes_Check(line)) {
        PyErr_Format(PyExc_OSError,
                     "readline() should have returned a bytes object, "
                     "not '%.200s'", Py_TYPE(line)->tp_name);
        Py_CLEAR(line);
    }
    return line;
}

static PyObject *
buffered_iternext(PyObject *op)
{
    PyObject *line = (_PyIO_is_nibbler_buffered_type(Py_TYPE(op))
                      ? _io__Buffered_readline_impl(buffered_cast(op), -1)
                      : buffered_readline_method(op));
    if (line == Py_None) {
        /* Would block: StopIteration would look like EOF. */
        Py_DECREF(line);
        _PyIO_set_read_blocking_error();
        return NULL;
    }
    if (line != NULL && PyBytes_GET_SIZE(line) == 0) {
        Py_CLEAR(line);
    }
    return line;
}

static PyObject *
buffered_repr(PyObject *op)
{
    PyObject *name;
    if (PyObject_GetOptionalAttr(op, &_Py_ID(name), &name) < 0) {
        if (!PyErr_ExceptionMatches(PyExc_ValueError)) {
            return NULL;
        }
        /* Detached. */
        PyErr_Clear();
    }
    if (name == NULL) {
        return PyUnicode_FromFormat("<%s>", Py_TYPE(op)->tp_name);
    }
    PyObject *res = NULL;
    int status = Py_ReprEnter(op);
    if (status == 0) {
        res = PyUnicode_FromFormat("<%s name=%R>", Py_TYPE(op)->tp_name, name);
        Py_ReprLeave(op);
    }
    else if (status > 0) {
        PyErr_Format(PyExc_RuntimeError, "reentrant call inside %s.__repr__",
                     Py_TYPE(op)->tp_name);
    }
    Py_DECREF(name);
    return res;
}

/* Check raw supports what the class needs (BufferedRandom: seeking too,
   but unbuffered, which never seeks to switch direction, so that it
   works over a terminal or socket as FileIO does). */
static int
buffered_check_raw(_PyIO_State *state, PyObject *raw, int raw_fileio,
                   int readable, int writable, Py_ssize_t buffer_size)
{
    if (readable && writable && buffer_size != 0
        && _PyIOBase_check_seekable(state, raw, Py_True) == NULL)
    {
        return -1;
    }
    if (raw_fileio) {
        return _PyFileIO_check_access(raw, readable, writable);
    }
    if ((readable && _PyIOBase_check_readable(state, raw, Py_True) == NULL)
        || (writable && _PyIOBase_check_writable(state, raw, Py_True) == NULL))
    {
        return -1;
    }
    return 0;
}

/* Shared constructor: blocks of buffer_size bytes, pending writes written
   out past threshold bytes.  Pending writes first go to the raw stream
   they were written to, as FileIO.__init__() closes its file: if that
   fails, raise, leaving the object as it was; if it was closed, they are
   dropped with a ResourceWarning.  Otherwise a failed __init__() leaves
   it uninitialized. */
static int
buffered_init(buffered *self, PyObject *raw, Py_ssize_t buffer_size,
              Py_ssize_t threshold, int readable, int writable)
{
    _PyIO_State *state = find_io_state_by_def(Py_TYPE(self));
    int fileio = Py_IS_TYPE(raw, state->PyFileIO_Type);
    int err = buffered_check_raw(state, raw, fileio, readable, writable,
                                 buffer_size);
    if (err == 0 && buffer_size < 0) {
        PyErr_SetString(PyExc_ValueError, "buffer size must not be negative");
        err = -1;
    }
    PyObject *exc = err < 0 ? PyErr_GetRaisedException() : NULL;
    if (buffered_lock_io(self) < 0) {
        _PyErr_ChainExceptions1(exc);
        return -1;
    }
    int closed = self->raw == NULL ? 1 : buffered_is_closed(self);
    Py_ssize_t discarded = (closed <= 0 ? 0 : self->reading
                            ? self->dhi - self->dlo : self->list.nbytes);
    if (closed < 0
        || (closed == 0
            && ((self->ngather > 0 && gather_move_records(self, 1) < 0)
                || (self->reading ? buffered_flush_dirty(self, 1)
                    : self->list.nbytes > 0 ? buffered_flush_writes(self, 0)
                    : 0) < 0)))
    {
        buffered_unlock_io(self);
        _PyErr_ChainExceptions1(exc);
        return -1;
    }
    buffered_free(self);
    FT_ATOMIC_STORE_SSIZE_RELAXED(self->capacity, err ? 0 : buffer_size);
    self->threshold = err ? 0 : threshold;
    self->raw_fileio = !err && fileio;
    if (!err) {
        /* One _writev() call for several pieces when raw has its own
           (FileIO's is one writev()), but not RawIOBase's, which only
           calls write() on each (joining small pieces in a block makes
           fewer calls), nor on a FileIO subclass (it could bypass an
           overridden write()).  Large exact bytes are kept by reference
           where that beats copying them: from 512 bytes to a FileIO, from
           2 KiB to a Python _writev() (whose cost per piece is higher),
           never otherwise. */
        PyObject *writev = (writable
                            ? _PyType_Lookup(Py_TYPE(raw), &_Py_ID(_writev))
                            : NULL);
        self->raw_vectored = (
            writev != NULL
            && (fileio || !PyObject_TypeCheck(raw, state->PyFileIO_Type))
            && writev != _PyType_Lookup(state->PyRawIOBase_Type,
                                        &_Py_ID(_writev)));
        FT_ATOMIC_STORE_SSIZE_RELAXED(
            self->ref_min, (fileio ? REF_MIN : self->raw_vectored ? 2048
                            : PY_SSIZE_T_MAX));
        self->raw_appending = (writable
                               && PyObject_TypeCheck(raw, state->PyFileIO_Type)
                               && _PyFileIO_appending(raw));
        /* Not for pipes and character devices, whose position doesn't
           follow what was read (GH-95782), nor in append mode. */
        self->raw_regular = (fileio && !self->raw_appending
                             && _PyFileIO_regular(raw));
    }
    PyObject *old = buffered_swap_raw(self, err ? NULL : Py_NewRef(raw));
    buffered_unlock_io(self);
    Py_XDECREF(old);
    /* Without the lock: the warning may write to this object. */
    if (discarded > 0
        && PyErr_WarnFormat(PyExc_ResourceWarning, 1,
                            "__init__() discarded %zd buffered bytes: the raw "
                            "stream they were written to is closed",
                            discarded) < 0)
    {
        err = -1;
    }
    _PyErr_ChainExceptions1(exc);
    return err;
}

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

/* BufferedWriter and BufferedRandom: buffer_size is an int (or NULL for
   the default), or None to buffer writes without limit. */
static int
buffered_init_writer(buffered *self, PyObject *raw, PyObject *buffer_size,
                     int readable)
{
    Py_ssize_t size = DEFAULT_BUFFER_SIZE;
    if (buffer_size != NULL && buffer_size != Py_None) {
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
    return buffered_init(self, raw, size, buffer_size == Py_None
                         ? PY_SSIZE_T_MAX : size, readable, 1);
}

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

/*[clinic input]
_io._Buffered._gather
    limit as limit_obj: object(c_default="NULL") = 20971520
    *
    direct: bool = False
    line_flush: bool = False

Gather the writes of the current context in a with block.

Returns a context manager.  Inside its with block, what the current
context (thread, or asyncio task) writes is kept apart, also past
the buffer size, and added to the buffered data in one piece when
the block ends (also when it raises), so that no other output gets
in between; while another thread uses the buffer, a BufferedWriter
of a regular file with nothing buffered writes it to the file then.
Once the block gathered limit bytes, they are added, and gathering
goes on; with limit None, only at the end.  flush() inside the block
takes effect at its end.  Reads, seek() and truncate() in the
context add what it gathered first; close(), detach() and
__init__(), from any context, what every block gathered.  A block
on the same stream nested in one gathers into it.

A direct block is for the life of a thread or task: it writes out
the buffered data when it starts, then, at its limit (by default
the buffer size), flush() and its end, writes what it gathered
directly to a regular file (of a BufferedWriter of a FileIO) without
waiting for what other contexts buffered meanwhile.  With
line_flush, complete lines are written out after each write
containing a newline: that way in a direct block, else after what
is buffered.

Gathering is by context, as with decimal.localcontext(): a block
spanning a yield gathers what runs in the context meanwhile.  Data
of a block dropped before it ends is added then, or dropped when
the stream is closed, with a ResourceWarning.  Experimental.
[clinic start generated code]*/

static PyObject *
_io__Buffered__gather_impl(buffered *self, PyObject *limit_obj, int direct,
                           int line_flush)
/*[clinic end generated code: output=cc170613f177a7e5 input=969068e3f3cccfd9]*/
{
    Py_ssize_t limit = (!direct ? GATHER_LIMIT : Py_MAX(1,
                        FT_ATOMIC_LOAD_SSIZE_RELAXED(self->capacity)));
    if (limit_obj == Py_None) {
        limit = PY_SSIZE_T_MAX;
    }
    else if (limit_obj != NULL) {
        limit = PyNumber_AsSsize_t(limit_obj, PyExc_OverflowError);
        if (limit == -1 && PyErr_Occurred()) {
            return NULL;
        }
        if (limit <= 0) {
            PyErr_SetString(PyExc_ValueError, "limit must be positive");
            return NULL;
        }
    }
    if (FT_ATOMIC_LOAD_PTR_ACQUIRE(self->gvar) == NULL) {
        PyObject *var = PyContextVar_New("_gather", NULL), *none = NULL;
        if (var == NULL) {
            return NULL;
        }
        if (!_Py_atomic_compare_exchange_ptr(&self->gvar, &none, var)) {
            Py_DECREF(var);
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
    g->direct = direct;
    g->line = line_flush;
    return (PyObject *)g;
}

/*[clinic input]
_io.BufferedWriter.readall

Not supported: a BufferedWriter can't read.
[clinic start generated code]*/

static PyObject *
_io_BufferedWriter_readall_impl(buffered *self)
/*[clinic end generated code: output=7637ea071b897d9d input=d1b433b1d223747c]*/
{
    return buffered_unsupported(self, "readall");
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
        /* No buffer export needed. */
        Py_ssize_t len = PyBytes_GET_SIZE(obj);
        return (buffered_write(self, obj, PyBytes_AS_STRING(obj), len,
                               "write to closed file") < 0
                ? NULL : PyLong_FromSsize_t(len));
    }
    Py_buffer view;
    if (PyObject_GetBuffer(obj, &view, PyBUF_SIMPLE) < 0) {
        return NULL;
    }
    int r = buffered_write(self, view.obj, view.buf, view.len,
                           "write to closed file");
    Py_ssize_t len = view.len;
    PyBuffer_Release(&view);
    return r < 0 ? NULL : PyLong_FromSsize_t(len);
}
/*
 * Bytes for TextIOWrapper (see _iomodule.h)
 *
 * _io._nibbler.TextIOWrapper decodes from an exact buffered object's
 * read-ahead in place, and takes only the bytes of the text it returns.
 * An instance dict could override the methods: objects with one are used
 * through them (_PyIO_NIBBLER_NO).
 */

#define TEXT_CLOSED "I/O operation on closed file."

Py_ssize_t
_PyIONibbler_begin(PyObject *op, int io, PyObject **block, const char **p)
{
    buffered *self = buffered_cast(op);
    if (FT_ATOMIC_LOAD_PTR_RELAXED(self->dict) != NULL) {
        return _PyIO_NIBBLER_NO;
    }
    if ((io ? buffered_enter(self, NULL, ENTER_READ)
         : buffered_lock(self)) < 0)
    {
        return -1;
    }
    Py_ssize_t r = 0;
    PyObject *dict = FT_ATOMIC_LOAD_PTR_RELAXED(self->dict);
    if (dict != NULL || self->raw == NULL) {
        r = self->raw == NULL ? buffered_not_ready() : _PyIO_NIBBLER_NO;
    }
    else if (!io && ((!self->reading && self->list.nbytes > 0)
                     || self->ngather > 0))
    {
        r = _PyIO_NIBBLER_NEEDIO;
    }
    if (r != 0) {
        _PyIONibbler_end(op, io);
        return r;
    }
    return _PyIONibbler_view(op, 0, block, p);
}

void
_PyIONibbler_end(PyObject *op, int io)
{
    if (io) {
        buffered_unlock_io(buffered_cast(op));
    }
    else {
        buffered_unlock(buffered_cast(op));
    }
}

Py_ssize_t
_PyIONibbler_view(PyObject *op, Py_ssize_t k, PyObject **block,
                  const char **p)
{
    buffered *self = buffered_cast(op);
    self->pos += k;
    *block = self->block;
    *p = self->block ? PyBytes_AS_STRING(self->block) + self->pos : NULL;
    return self->end - self->pos;
}

/* With the lock: the rest of _PyIONibbler_take(). */
static inline int
buffered_take_at(buffered *self, const char *p, Py_ssize_t len,
                 Py_ssize_t k)
{
    int r = (FT_ATOMIC_LOAD_PTR_RELAXED(self->dict) == NULL
             && self->raw != NULL && self->block != NULL
             && (self->reading || self->list.nbytes == 0)
             && self->ngather == 0
             && PyBytes_AS_STRING(self->block) + self->pos == p
             && self->end - self->pos >= len);
    if (r) {
        self->pos += k;
    }
    buffered_unlock(self);
    return r;
}

/* (Out of line, so that the usual step needs no stack frame.) */
Py_NO_INLINE static int
buffered_take_wait(buffered *self, const char *p, Py_ssize_t len,
                   Py_ssize_t k)
{
    /* The lock is held briefly by everyone: not interrupted. */
    return (buffered_lock_ex(self, 0) < 0 ? -1
            : buffered_take_at(self, p, len, k));
}

int
_PyIONibbler_take(PyObject *op, const char *p, Py_ssize_t len, Py_ssize_t k)
{
    buffered *self = buffered_cast(op);
    if (FT_ATOMIC_LOAD_PTR_RELAXED(self->dict) != NULL) {
        return 0;
    }
    if (!nibbler_mutex_trylock(&self->lock)) {
        return buffered_take_wait(self, p, len, k);
    }
    return buffered_take_at(self, p, len, k);
}

Py_ssize_t
_PyIONibbler_fill(PyObject *op, Py_ssize_t size)
{
    buffered *self = buffered_cast(op);
    /* A long line is gathered in one block up to 64 blocks, and at least
       DEFAULT_BUFFER_SIZE. */
    Py_ssize_t max = Py_MAX(Py_MIN(self->capacity, PY_SSIZE_T_MAX / 64) * 64,
                            DEFAULT_BUFFER_SIZE);
    if (self->end - self->pos >= max) {
        return _PyIO_NIBBLER_FULL;
    }
    if (buffered_check_closed(self, TEXT_CLOSED) < 0) {
        return -1;
    }
    Py_ssize_t n = buffered_fill(self, size, max);
    return n == WOULD_BLOCK ? _PyIO_NIBBLER_BLOCKED : n;
}

int
_PyIONibbler_unread(PyObject *op, const char *data, Py_ssize_t len)
{
    return buffered_push_back(buffered_cast(op), data, len);
}

int
_PyIONibbler_write(PyObject *op, PyObject *obj, const char *data,
                   Py_ssize_t len)
{
    buffered *self = buffered_cast(op);
    if (FT_ATOMIC_LOAD_PTR_RELAXED(self->dict) != NULL) {
        return _PyIO_NIBBLER_NO;
    }
    return buffered_write(self, obj, data, len, TEXT_CLOSED);
}

int
_PyIONibbler_closed(PyObject *op)
{
    PyObject *raw = buffered_get_raw(buffered_cast(op));
    int r = raw ? buffered_ref_closed(raw) : -1;
    Py_XDECREF(raw);
    return r;
}

/*
 * BufferedRWPair: a reader and a writer passed on to.
 */

typedef struct {
    PyObject_HEAD
    PyObject *reader;
    PyObject *writer;
    PyObject *dict;
    PyObject *weakreflist;
} rwpair;

#define rwpair_cast(op) ((rwpair *)(op))

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
    nibblermodule_state *nstate = find_nibblermodule_state_by_def(
        Py_TYPE(self));
    if (_PyIOBase_check_readable(state, reader, Py_True) == NULL
        || _PyIOBase_check_writable(state, writer, Py_True) == NULL)
    {
        return -1;
    }
    Py_XSETREF(self->reader, PyObject_CallFunction(
        (PyObject *)nstate->PyBufferedReader_Type, "On", reader, buffer_size));
    if (self->reader == NULL) {
        return -1;
    }
    Py_XSETREF(self->writer, PyObject_CallFunction(
        (PyObject *)nstate->PyBufferedWriter_Type, "On", writer, buffer_size));
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
    PyTypeObject *tp = Py_TYPE(op);
    _PyObject_GC_UNTRACK(op);
    FT_CLEAR_WEAKREFS(op, rwpair_cast(op)->weakreflist);
    (void)bufferedrwpair_clear(op);
    tp->tp_free(op);
    Py_DECREF(tp);
}

/* Call the reader's or writer's method, with arg unless NULL (so that its
   default is used otherwise). */
static PyObject *
rwpair_call(PyObject *obj, PyObject *name, PyObject *arg)
{
    if (obj == NULL) {
        PyErr_SetString(PyExc_ValueError,
                        "I/O operation on uninitialized object");
        return NULL;
    }
    return (arg == NULL ? PyObject_CallMethodNoArgs(obj, name)
            : PyObject_CallMethodOneArg(obj, name, arg));
}

/* The methods passed on, in the calling conventions Argument Clinic would
   give them: no argument, one, or an optional one. */
#define RWPAIR_NOARGS(name, side)                                           \
    static PyObject *                                                       \
    rwpair_##name(PyObject *op, PyObject *Py_UNUSED(dummy))                 \
    {                                                                       \
        return rwpair_call(rwpair_cast(op)->side, &_Py_ID(name), NULL);     \
    }
#define RWPAIR_O(name, side)                                                \
    static PyObject *                                                       \
    rwpair_##name(PyObject *op, PyObject *arg)                              \
    {                                                                       \
        return rwpair_call(rwpair_cast(op)->side, &_Py_ID(name), arg);      \
    }
#define RWPAIR_OPTARG(name, side)                                           \
    static PyObject *                                                       \
    rwpair_##name(PyObject *op, PyObject *const *args, Py_ssize_t nargs)    \
    {                                                                       \
        if (!_PyArg_CheckPositional(#name, nargs, 0, 1)) {                  \
            return NULL;                                                    \
        }                                                                   \
        return rwpair_call(rwpair_cast(op)->side, &_Py_ID(name),            \
                           nargs > 0 ? args[0] : NULL);                     \
    }
RWPAIR_OPTARG(read, reader)
RWPAIR_NOARGS(readall, reader)
RWPAIR_OPTARG(peek, reader)
RWPAIR_OPTARG(readline, reader)
RWPAIR_OPTARG(read1, reader)
RWPAIR_O(readinto, reader)
RWPAIR_O(readinto1, reader)
RWPAIR_NOARGS(readable, reader)
RWPAIR_O(write, writer)
RWPAIR_NOARGS(flush, writer)
RWPAIR_NOARGS(_discard_writes, writer)
RWPAIR_NOARGS(writable, writer)
#undef RWPAIR_NOARGS
#undef RWPAIR_O
#undef RWPAIR_OPTARG

static PyObject *
rwpair_close(PyObject *op, PyObject *Py_UNUSED(dummy))
{
    rwpair *self = rwpair_cast(op);
    PyObject *ret = rwpair_call(self->writer, &_Py_ID(close), NULL);
    PyObject *exc = ret == NULL ? PyErr_GetRaisedException() : NULL;
    Py_XDECREF(ret);
    ret = rwpair_call(self->reader, &_Py_ID(close), NULL);
    if (exc != NULL) {
        _PyErr_ChainExceptions1(exc);
        Py_CLEAR(ret);
    }
    return ret;
}

static PyObject *
rwpair_isatty(PyObject *op, PyObject *Py_UNUSED(dummy))
{
    PyObject *ret = rwpair_call(rwpair_cast(op)->writer, &_Py_ID(isatty),
                                NULL);
    if (ret != Py_False) {
        /* True or an exception */
        return ret;
    }
    Py_DECREF(ret);
    return rwpair_call(rwpair_cast(op)->reader, &_Py_ID(isatty), NULL);
}

static PyObject *
rwpair_closed_get(PyObject *op, void *Py_UNUSED(closure))
{
    rwpair *self = rwpair_cast(op);
    if (self->writer == NULL) {
        PyErr_SetString(PyExc_RuntimeError,
                        "the BufferedRWPair object is being "
                        "garbage-collected");
        return NULL;
    }
    return PyObject_GetAttr(self->writer, &_Py_ID(closed));
}

#define clinic_state() (find_nibblermodule_state_by_def(Py_TYPE(self)))
#include "clinic/bufferedio.c.h"
#undef clinic_state

/*
 * Types and the module
 */

#define BUFFERED_COMMON_METHODS                 \
    _IO__BUFFERED_DETACH_METHODDEF              \
    _IO__BUFFERED_CLOSE_METHODDEF               \
    RAW_METHODDEF(seekable)                     \
    RAW_METHODDEF(fileno)                       \
    RAW_METHODDEF(isatty)                       \
    _IO__BUFFERED__DEALLOC_WARN_METHODDEF       \
    _IO__BUFFERED__DISCARD_WRITES_METHODDEF     \
    _IO__BUFFERED___SIZEOF___METHODDEF          \
    _IO__BUFFERED_SEEK_METHODDEF                \
    _IO__BUFFERED_TELL_METHODDEF                \
    _IO__BUFFERED_TRUNCATE_METHODDEF            \
    {"__getstate__", _PyIOBase_cannot_pickle, METH_NOARGS},

#define BUFFERED_READ_METHODS                   \
    RAW_METHODDEF(readable)                     \
    _IO__BUFFERED_READ_METHODDEF                \
    _IO__BUFFERED_READALL_METHODDEF             \
    _IO__BUFFERED_PEEK_METHODDEF                \
    _IO__BUFFERED_READ1_METHODDEF               \
    _IO__BUFFERED_READINTO_METHODDEF            \
    _IO__BUFFERED_READINTO1_METHODDEF           \
    _IO__BUFFERED_READLINE_METHODDEF

#define BUFFERED_WRITE_METHODS                  \
    RAW_METHODDEF(writable)                     \
    _IO_BUFFEREDWRITER_WRITE_METHODDEF          \
    _IO__BUFFERED_FLUSH_METHODDEF               \
    _IO__BUFFERED__GATHER_METHODDEF

static PyMethodDef bufferedreader_methods[] = {
    BUFFERED_COMMON_METHODS
    BUFFERED_READ_METHODS
    RAW_METHODDEF(flush)
    {NULL, NULL}
};

static PyMethodDef bufferedwriter_methods[] = {
    BUFFERED_COMMON_METHODS
    BUFFERED_WRITE_METHODS
    _IO_BUFFEREDWRITER_READALL_METHODDEF
    {NULL, NULL}
};

static PyMethodDef bufferedrandom_methods[] = {
    BUFFERED_COMMON_METHODS
    BUFFERED_READ_METHODS
    BUFFERED_WRITE_METHODS
    {NULL, NULL}
};

static PyMemberDef buffered_members[] = {
    {"_finalizing", Py_T_BOOL, offsetof(buffered, finalizing), 0},
    {"__weaklistoffset__", Py_T_PYSSIZET,
     offsetof(buffered, weakreflist), Py_READONLY},
    {"__dictoffset__", Py_T_PYSSIZET, offsetof(buffered, dict), Py_READONLY},
    {NULL}
};

static PyObject *
buffered_raw_get(PyObject *op, void *Py_UNUSED(closure))
{
    PyObject *raw = buffered_ref_raw(buffered_cast(op));
    return raw != NULL ? raw : Py_None;
}

static PyGetSetDef buffered_getset[] = {
    {"raw", buffered_raw_get, NULL, NULL, NULL},
    {"closed", buffered_raw_getattr, NULL, NULL, &_Py_ID(closed)},
    {"name", buffered_raw_getattr, NULL, NULL, &_Py_ID(name)},
    {"mode", buffered_raw_getattr, NULL, NULL, &_Py_ID(mode)},
    {NULL}
};

#define BUFFERED_SPEC(NAME, low, ITERNEXT)                                 \
    static PyType_Slot buffered##low##_slots[] = {                         \
        {Py_tp_dealloc, buffered_dealloc},                                  \
        {Py_tp_repr, buffered_repr},                                        \
        {Py_tp_doc, (void *)_io_##NAME##___init____doc__},                  \
        {Py_tp_traverse, buffered_traverse},                                \
        {Py_tp_clear, buffered_clear},                                      \
        ITERNEXT                                                            \
        {Py_tp_methods, buffered##low##_methods},                          \
        {Py_tp_members, buffered_members},                                  \
        {Py_tp_getset, buffered_getset},                                    \
        {Py_tp_init, _io_##NAME##___init__},                                \
        {Py_tp_token, &nibbler_buffered##low##_spec},                      \
        {0, NULL},                                                          \
    };                                                                      \
    static PyType_Spec nibbler_buffered##low##_spec = {                    \
        .name = "_io._nibbler." #NAME,                                      \
        .basicsize = sizeof(buffered),                                      \
        .flags = (Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE                  \
                  | Py_TPFLAGS_HAVE_GC | Py_TPFLAGS_IMMUTABLETYPE),         \
        .slots = buffered##low##_slots,                                    \
    };

static PyType_Spec nibbler_bufferedrandom_spec;
#define ITERNEXT_SLOT {Py_tp_iternext, buffered_iternext},
BUFFERED_SPEC(BufferedReader, reader, ITERNEXT_SLOT)
BUFFERED_SPEC(BufferedWriter, writer, )
BUFFERED_SPEC(BufferedRandom, random, ITERNEXT_SLOT)

#define RWPAIR_METHODDEF(name, flags, args) \
    {#name, _PyCFunction_CAST(rwpair_##name), flags, \
     #name "($self" args ", /)\n--\n\n"},

static PyMethodDef bufferedrwpair_methods[] = {
    RWPAIR_METHODDEF(read, METH_FASTCALL, ", size=-1")
    RWPAIR_METHODDEF(readall, METH_NOARGS, "")
    RWPAIR_METHODDEF(peek, METH_FASTCALL, ", size=0")
    RWPAIR_METHODDEF(read1, METH_FASTCALL, ", size=-1")
    RWPAIR_METHODDEF(readline, METH_FASTCALL, ", size=-1")
    RWPAIR_METHODDEF(readinto, METH_O, ", buffer")
    RWPAIR_METHODDEF(readinto1, METH_O, ", buffer")
    RWPAIR_METHODDEF(write, METH_O, ", buffer")
    RWPAIR_METHODDEF(flush, METH_NOARGS, "")
    RWPAIR_METHODDEF(_discard_writes, METH_NOARGS, "")
    RWPAIR_METHODDEF(readable, METH_NOARGS, "")
    RWPAIR_METHODDEF(writable, METH_NOARGS, "")
    RWPAIR_METHODDEF(close, METH_NOARGS, "")
    RWPAIR_METHODDEF(isatty, METH_NOARGS, "")
    {NULL, NULL}
};

static PyMemberDef bufferedrwpair_members[] = {
    {"__weaklistoffset__", Py_T_PYSSIZET, offsetof(rwpair, weakreflist),
     Py_READONLY},
    {"__dictoffset__", Py_T_PYSSIZET, offsetof(rwpair, dict), Py_READONLY},
    {NULL}
};

static PyGetSetDef bufferedrwpair_getset[] = {
    {"closed", rwpair_closed_get, NULL, NULL, NULL},
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

/* Is tp exactly one of the buffered classes (not a subclass)? */
int
_PyIO_is_nibbler_buffered_type(PyTypeObject *tp)
{
    if (!_PyType_HasFeature(tp, Py_TPFLAGS_HEAPTYPE)) {
        return 0;
    }
    void *token = ((PyHeapTypeObject *)tp)->ht_token;
    return (token == &nibbler_bufferedreader_spec ||
            token == &nibbler_bufferedrandom_spec ||
            token == &nibbler_bufferedwriter_spec);
}

static int
nibblermodule_traverse(PyObject *mod, visitproc visit, void *arg)
{
    nibblermodule_state *state = _PyModule_GetState(mod);
    Py_VISIT(state->PyBufferedIOBase_Type);
    Py_VISIT(state->PyBufferedReader_Type);
    Py_VISIT(state->PyBufferedWriter_Type);
    Py_VISIT(state->PyBufferedRandom_Type);
    Py_VISIT(state->PyBufferedRWPair_Type);
    Py_VISIT(state->PyTextIOWrapper_Type);
    Py_VISIT(state->Gather_Type);
    Py_VISIT(state->Record_Type);
    return 0;
}

static int
nibblermodule_clear(PyObject *mod)
{
    nibblermodule_state *state = _PyModule_GetState(mod);
    Py_CLEAR(state->PyBufferedIOBase_Type);
    Py_CLEAR(state->PyBufferedReader_Type);
    Py_CLEAR(state->PyBufferedWriter_Type);
    Py_CLEAR(state->PyBufferedRandom_Type);
    Py_CLEAR(state->PyBufferedRWPair_Type);
    Py_CLEAR(state->PyTextIOWrapper_Type);
    Py_CLEAR(state->Gather_Type);
    Py_CLEAR(state->Record_Type);
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

/* A type from spec with base, named prefix + its class name, in mod.  The
   class attribute _is_nibbler tells tests these classes from _io's, also
   when they replace them; with keeps_read, _keeps_read_on_error says that
   data (or text) read before a raw read raised is kept for the next read
   (socket.makefile() looks at it). */
static PyTypeObject *
nibbler_add_type(PyObject *mod, const PyType_Spec *spec, PyTypeObject *base,
                 const char *prefix, int keeps_read)
{
    char name[64];
    PyType_Spec named = *spec;
    PyOS_snprintf(name, sizeof(name), "%s%s", prefix,
                  strrchr(spec->name, '.') + 1);
    named.name = name;
    PyTypeObject *type = (PyTypeObject *)PyType_FromModuleAndSpec(
        mod, &named, (PyObject *)base);
    if (type == NULL) {
        return NULL;
    }
    PyObject *dict = _PyType_GetDict(type);
    if (PyDict_SetItemString(dict, "_is_nibbler", Py_True) < 0
        || (keeps_read && PyDict_SetItemString(dict, "_keeps_read_on_error",
                                               Py_True) < 0)
        || (PyType_Modified(type), PyModule_AddType(mod, type) < 0))
    {
        Py_DECREF(type);
        return NULL;
    }
    return type;
}

/* Create _io._nibbler, in sys.modules and _io.  With as_io, the types are
   named like _io's (for when they replace them).  Returns a borrowed
   reference, or NULL. */
PyObject *
_PyIO_create_nibbler_submodule(PyObject *io_module, int as_io)
{
    _PyIO_State *io_state = get_io_state(io_module);
    PyObject *mod = PyModule_Create(&_PyIO_nibbler_Module);
    if (mod == NULL) {
        return NULL;
    }
    nibblermodule_state *state = _PyModule_GetState(mod);
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
             io_state->PyTextIOBase_Type, prefix, 1)) == NULL
        || (state->Gather_Type = (PyTypeObject *)PyType_FromModuleAndSpec(
             mod, &gather_spec, NULL)) == NULL
        || (state->Record_Type = (PyTypeObject *)PyType_FromModuleAndSpec(
             mod, &record_spec, NULL)) == NULL
        || _PyImport_SetModuleString("_io._nibbler", mod) < 0
        || PyModule_AddObjectRef(io_module, "_nibbler", mod) < 0)
    {
        Py_DECREF(mod);
        return NULL;
    }
    Py_DECREF(mod);
    return mod;
}

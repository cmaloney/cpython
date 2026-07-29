/*
    An implementation of Buffered I/O as defined by PEP 3116 - "New I/O"

    Classes defined here: BufferedIOBase, BufferedReader, BufferedWriter,
    BufferedRandom.

    Written by Amaury Forgeot d'Arc and Antoine Pitrou
*/

#include "Python.h"
#include "pycore_call.h"                // _PyObject_CallNoArgs()
#include "pycore_fileutils.h"           // _PyFile_Flush
#include "pycore_lock.h"                // _PyRecursiveMutex
#include "pycore_pyatomic_ft_wrappers.h" // FT_ATOMIC_LOAD_SSIZE_RELAXED()
#include "pycore_object.h"              // _PyObject_GC_UNTRACK()
#include "pycore_pyerrors.h"            // _Py_FatalErrorFormat()
#include "pycore_pylifecycle.h"         // _Py_IsInterpreterFinalizing()
#include "pycore_weakref.h"             // FT_CLEAR_WEAKREFS()
#include "pycore_import.h"              // _PyImport_SetModule()

#include "_iomodule.h"

#include <limits.h>                     // IOV_MAX

/* Most chunks a morsel may pass to raw._writev(); larger morsels are
   coalesced into a single buffer first. */
#ifndef IOV_MAX
#  ifdef UIO_MAXIOV
#    define IOV_MAX UIO_MAXIOV
#  else
#    define IOV_MAX 16                  // POSIX minimum
#  endif
#endif

/*[clinic input]
module _io
class _io._BufferedIOBase "PyObject *" "clinic_state()->PyBufferedIOBase_Type"
class _io._Buffered "buffered *" "clinic_state()->PyBufferedIOBase_Type"
class _io.BufferedReader "buffered *" "clinic_state()->PyBufferedReader_Type"
class _io.BufferedWriter "buffered *" "clinic_state()->PyBufferedWriter_Type"
class _io.BufferedRWPair "rwpair *" "clinic_state()->PyBufferedRWPair_Type"
class _io.BufferedRandom "buffered *" "clinic_state()->PyBufferedRandom_Type"
[clinic start generated code]*/
/*[clinic end generated code: output=da39a3ee5e6b4b0d input=3b3ef9cbbbad4590]*/

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
 * BufferedIOBase class, inherits from IOBase.
 */
PyDoc_STRVAR(bufferediobase_doc,
    "Base class for buffered IO objects.\n"
    "\n"
    "The main difference with RawIOBase is that the read() method\n"
    "supports omitting the size argument, and does not have a default\n"
    "implementation that defers to readinto().\n"
    "\n"
    "In addition, read(), readinto() and write() may raise\n"
    "BlockingIOError if the underlying raw stream is in non-blocking\n"
    "mode and not ready; unlike their raw counterparts, they will never\n"
    "return None.\n"
    "\n"
    "A typical implementation should not inherit from a RawIOBase\n"
    "implementation, but wrap one.\n"
    );

static PyObject *
_bufferediobase_readinto_generic(PyObject *self, Py_buffer *buffer, char readinto1)
{
    Py_ssize_t len;
    PyObject *data;

    PyObject *attr = readinto1
        ? &_Py_ID(read1)
        : &_Py_ID(read);
    data = _PyObject_CallMethod(self, attr, "n", buffer->len);
    if (data == NULL)
        return NULL;

    if (!PyBytes_Check(data)) {
        Py_DECREF(data);
        PyErr_SetString(PyExc_TypeError, "read() should return bytes");
        return NULL;
    }

    len = PyBytes_GET_SIZE(data);
    if (len > buffer->len) {
        PyErr_Format(PyExc_ValueError,
                     "read() returned too much data: "
                     "%zd bytes requested, %zd returned",
                     buffer->len, len);
        Py_DECREF(data);
        return NULL;
    }
    memcpy(buffer->buf, PyBytes_AS_STRING(data), len);

    Py_DECREF(data);

    return PyLong_FromSsize_t(len);
}

/*[clinic input]
@critical_section
_io._BufferedIOBase.readinto
    buffer: Py_buffer(accept={rwbuffer})
    /
[clinic start generated code]*/

static PyObject *
_io__BufferedIOBase_readinto_impl(PyObject *self, Py_buffer *buffer)
/*[clinic end generated code: output=8c8cda6684af8038 input=5273d20db7f56e1a]*/
{
    return _bufferediobase_readinto_generic(self, buffer, 0);
}

/*[clinic input]
@critical_section
_io._BufferedIOBase.readinto1
    buffer: Py_buffer(accept={rwbuffer})
    /
[clinic start generated code]*/

static PyObject *
_io__BufferedIOBase_readinto1_impl(PyObject *self, Py_buffer *buffer)
/*[clinic end generated code: output=358623e4fd2b69d3 input=d6eb723dedcee654]*/
{
    return _bufferediobase_readinto_generic(self, buffer, 1);
}

static PyObject *
bufferediobase_unsupported(_PyIO_State *state, const char *message)
{
    PyErr_SetString(state->unsupported_operation, message);
    return NULL;
}

/*[clinic input]
_io._BufferedIOBase.detach

    cls: defining_class
    /

Disconnect this buffer from its underlying raw stream and return it.

After the raw stream has been detached, the buffer is in an unusable
state.
[clinic start generated code]*/

static PyObject *
_io__BufferedIOBase_detach_impl(PyObject *self, PyTypeObject *cls)
/*[clinic end generated code: output=b87b135d67cd4448 input=0b61a7b4357c1ea7]*/
{
    _PyIO_State *state = find_io_state_by_def(cls);
    return bufferediobase_unsupported(state, "detach");
}

/*[clinic input]
_io._BufferedIOBase.read

    cls: defining_class
    size: int(unused=True) = -1
    /

Read and return up to n bytes.

If the size argument is omitted, None, or negative, read and
return all data until EOF.

If the size argument is positive, and the underlying raw stream is
not 'interactive', multiple raw reads may be issued to satisfy
the byte count (unless EOF is reached first).
However, for interactive raw streams (as well as sockets and pipes),
at most one raw read will be issued, and a short result does not
imply that EOF is imminent.

Return an empty bytes object on EOF.

Return None if the underlying raw stream was open in non-blocking
mode and no data is available at the moment.
[clinic start generated code]*/

static PyObject *
_io__BufferedIOBase_read_impl(PyObject *self, PyTypeObject *cls,
                              int Py_UNUSED(size))
/*[clinic end generated code: output=aceb2765587b0a29 input=824f6f910465e61a]*/
{
    _PyIO_State *state = find_io_state_by_def(cls);
    return bufferediobase_unsupported(state, "read");
}

/*[clinic input]
@permit_long_summary
_io._BufferedIOBase.read1

    cls: defining_class
    size: int(unused=True) = -1
    /

Read and return up to size bytes, with at most one read() call to the underlying raw stream.

Return an empty bytes object on EOF.
A short result does not imply that EOF is imminent.
[clinic start generated code]*/

static PyObject *
_io__BufferedIOBase_read1_impl(PyObject *self, PyTypeObject *cls,
                               int Py_UNUSED(size))
/*[clinic end generated code: output=2e7fc62972487eaa input=1e76df255063afd6]*/
{
    _PyIO_State *state = find_io_state_by_def(cls);
    return bufferediobase_unsupported(state, "read1");
}

/*[clinic input]
_io._BufferedIOBase.write

    cls: defining_class
    b: object(unused=True)
    /

Write buffer b to the IO stream.

Return the number of bytes written, which is always
the length of b in bytes.

Raise BlockingIOError if the buffer is full and the
underlying raw stream cannot accept more data at the moment.
[clinic start generated code]*/

static PyObject *
_io__BufferedIOBase_write_impl(PyObject *self, PyTypeObject *cls,
                               PyObject *Py_UNUSED(b))
/*[clinic end generated code: output=712c635246bf2306 input=9793f5c8f71029ad]*/
{
    _PyIO_State *state = find_io_state_by_def(cls);
    return bufferediobase_unsupported(state, "write");
}


/* Object lifecycle: only READY objects accept I/O operations. */
#define STATE_UNINITIALIZED 0   /* __init__ has not completed */
#define STATE_READY         1
#define STATE_DETACHED      2   /* detach() removed the raw stream */

/* Directions the object supports; fixed per class at __init__. */
#define CAPS_READ  1
#define CAPS_WRITE 2
#define CAN_READ(self)   ((self)->caps & CAPS_READ)
#define CAN_WRITE(self)  ((self)->caps & CAPS_WRITE)

/* A gathered write, staged on `wstate` until a flusher takes it. */
typedef struct wnode {
    struct wnode *next;
    PyObject *chunk;        /* owned bytes */
} wnode;

/* wstate: one atomic word fusing the staged-write LIFO head with the
   nibbler's current direction. wnode allocations are pointer-aligned,
   freeing the low bits for the tag. Pushing a node, taking the whole
   list, and changing direction all linearize on this word, which is
   what lets gathering run without a lock: a push can only succeed
   against the WRITING tag, and a direction change can only succeed
   against an empty list -- there is no window between "the buffer
   emptied" and "the direction changed" for a write to slip through. */
#define WTAG_READING ((uintptr_t)0)  /* nibbler holds read-ahead */
#define WTAG_WRITING ((uintptr_t)1)  /* gathering allowed */
#define WTAG_DRAIN   ((uintptr_t)2)  /* gatherers divert to io_lock */
#define WTAG_MASK    ((uintptr_t)3)
#define WSTATE_PTR(w)   ((wnode *)((w) & ~WTAG_MASK))
#define WSTATE_TAG(w)   ((int)((w) & WTAG_MASK))
#define WSTATE(p, tag)  ((uintptr_t)(p) | (uintptr_t)(tag))

#define WTAG(self) WSTATE_TAG(_Py_atomic_load_uintptr(&(self)->wstate))
#define IS_READING(self) (WTAG(self) == WTAG_READING)
#define IS_WRITING(self) (!IS_READING(self))

/* A run of buffered bytes: a list of bytes objects ("chunks") consumed
   from the front. The object's live buffer is one; a detached morsel
   being written to the raw stream is another. */
typedef struct {
    /* List of bytes objects. In the live buffer, NULL only before
       __init__ and after close(). */
    PyObject *chunks;
    /* Consumed prefix of chunks[0]. */
    Py_ssize_t offset;
    /* Unconsumed bytes across all chunks. */
    Py_ssize_t nbytes;
} nibbler;

typedef struct {
    PyObject_HEAD

    PyObject *raw;
    char state;     /* STATE_UNINITIALIZED, STATE_READY or STATE_DETACHED */
    char finalizing;

    /* True if this is a vanilla Buffered object (rather than a user derived
       class) *and* the raw stream is a vanilla FileIO object. */
    int fast_closed_checks;

    /* Read-ahead, consumed under io_lock. */
    nibbler buf;
    /* Unwritten leftovers of a blocked flush; owned by the flusher
       (io_lock) and written out ahead of newly staged chunks. */
    nibbler pending;
    /* The fused staging word; see WTAG_* above. */
    uintptr_t wstate;
    /* Bytes gathered, pending, or in a morsel mid-write. tell() adds
       them to the raw position while writing. */
    Py_ssize_t write_pending;
    /* CAPS_READ / CAPS_WRITE. */
    uint8_t caps;

    /* raw._writev(buffers), when the raw stream provides it (else NULL).
       Lets a multi-chunk morsel be written without coalescing. */
    PyObject *raw_writev;

    /* Serializes raw stream I/O, whole read operations, and mode
       transitions. write() calls that only gather never take it. Used
       non-recursively; the recorded owner detects a reentrant call
       (signal handler or GC finalizer re-entering mid-I/O), which
       raises RuntimeError instead of deadlocking. */
    _PyRecursiveMutex io_lock;

    Py_ssize_t buffer_size;

    PyObject *dict;
    PyObject *weakreflist;
} buffered;

#define buffered_CAST(op)   ((buffered *)(op))

/*
    Implementation notes (nibbler):

    * BufferedReader, BufferedWriter and BufferedRandom share this one
      implementation; the members `readable` and `writable` plus per-type
      method tables gate which operations are allowed.
    * There is no pre-allocated buffer. write() appends bytes objects to
      the chunk list (immutable bytes without copying); once
      `buffer_size` is reached the gathered chunks -- the "morsel" --
      are detached and written out with raw._writev() when available, or
      coalesced into one buffer and passed to raw.write(). Reads append
      raw chunks to the same list and consume from the front.
    * The raw stream position is never cached. tell() queries the raw
      stream and offsets by the pending byte count; seek() flushes
      (writing) or compensates and drops read-ahead (reading).
    * Reads and writes never share buffered data: switching direction
      flushes pending writes, or rewinds the raw stream past unread
      read-ahead. buffer_size == 0 is supported; the buffer is then
      empty at rest and every write is submitted immediately.

    Locking: gathering is lock-free. write() stages its chunk as a
    node pushed onto `wstate` with a compare-exchange; the same word
    carries the direction tag, so a push can only succeed while
    WRITING, a direction change can only succeed against an empty
    list, and there is no window between "the buffer emptied" and "the
    direction changed" for a write to slip through. The DRAIN tag
    diverts gatherers to io_lock while a drain, seek, truncate or
    close() must keep the buffer stable, which also means one detach
    of the staged list covers a whole drain.

    io_lock serializes everything completion-shaped: raw stream I/O,
    whole read operations (each read() returns a contiguous span of
    the stream), flush/seek/truncate, direction changes, and closing
    or detaching the raw stream. A flusher takes the entire staged
    list in one exchange and writes it -- gathering continues
    meanwhile -- keeping unwritten leftovers in `pending`
    (flusher-owned) to go out first next time. A taken list is never
    traversed by another thread, so nodes are freed immediately; no
    deferred reclamation is needed.

    Scalars read without the lock (write_pending, buf.nbytes, and the
    buf.chunks NULL check in IS_CLOSED()) use atomic loads; tell() is
    therefore approximate while another thread is mid-operation.
    write_pending is credited before the push and debited as the
    flusher writes, so it never undercounts staged bytes.

    Reentrancy: re-entering an operation that needs io_lock from the
    thread holding it (a signal handler or GC finalizer interrupting
    I/O) raises RuntimeError. A reentrant write() just gathers and
    succeeds -- e.g. print() from a signal handler interrupting a
    flush stages its output instead of failing.

    Invariants:
    * For buf, pending and any morsel: nbytes == sum of chunk lengths
      minus offset; 0 <= offset < len(chunks[0]) whenever chunks is
      non-empty; chunks never contains an empty bytes object.
    * buf holds only read-ahead; pending and the staged list hold only
      writes. write_pending == staged + pending + in-flight morsel
      bytes (plus writes accounted just before their push).
    * A lone writer stays within buffer_size except between gathering
      and flushing its morsel; concurrent writers deferring to an
      active flusher can exceed it transiently.
*/

/* Acquire the I/O lock, the single lock of this implementation (see
   "Locking" in the implementation notes). Returns 1 on success, or 0
   with RuntimeError set on a reentrant call. */
static int
buffered_lock_io(buffered *self)
{
    if (_PyRecursiveMutex_IsLockedByCurrentThread(&self->io_lock)) {
        PyErr_Format(PyExc_RuntimeError,
                     "reentrant call inside %R", self);
        return 0;
    }
    PyInterpreterState *interp = _PyInterpreterState_GET();
    if (!_Py_IsInterpreterFinalizing(interp)) {
        (void)_PyRecursiveMutex_LockTimed(&self->io_lock, -1,
                                          _PY_LOCK_DETACH);
        return 1;
    }
    /* When finalizing, we don't want a deadlock to happen with daemon
     * threads abruptly shut down while they owned the lock.
     * Therefore, only wait for a grace period (1 s.).
     * Note that non-daemon threads have already exited here, so this
     * shouldn't affect carefully written threaded I/O code.
     */
    PyLockStatus st = _PyRecursiveMutex_LockTimed(
        &self->io_lock, (PyTime_t)1000000000, _PY_LOCK_DETACH);
    if (st != PY_LOCK_ACQUIRED) {
        PyObject *ascii = PyObject_ASCII((PyObject*)self);
        _Py_FatalErrorFormat(__func__,
            "could not acquire lock for %s at interpreter "
            "shutdown, possibly due to daemon threads",
            ascii ? PyUnicode_AsUTF8(ascii) : "<ascii(self) failed>");
    }
    return 1;
}

#define CHECK_INITIALIZED(self) \
    if (self->state != STATE_READY) { \
        if (self->state == STATE_DETACHED) { \
            PyErr_SetString(PyExc_ValueError, \
                 "raw stream has been detached"); \
        } else { \
            PyErr_SetString(PyExc_ValueError, \
                "I/O operation on uninitialized object"); \
        } \
        return NULL; \
    }

#define CHECK_INITIALIZED_INT(self) \
    if (self->state != STATE_READY) { \
        if (self->state == STATE_DETACHED) { \
            PyErr_SetString(PyExc_ValueError, \
                 "raw stream has been detached"); \
        } else { \
            PyErr_SetString(PyExc_ValueError, \
                "I/O operation on uninitialized object"); \
        } \
        return -1; \
    }

#define IS_CLOSED(self) \
    (FT_ATOMIC_LOAD_PTR_RELAXED(self->buf.chunks) == NULL ? 1 : \
    (self->fast_closed_checks \
     ? _PyFileIO_closed(self->raw) \
     : buffered_closed(self)))

/* Unconsumed read-ahead (0 when the chunks are pending writes). */
#define READAHEAD(self) \
    (IS_READING(self) ? FT_ATOMIC_LOAD_SSIZE_RELAXED(self->buf.nbytes) : 0)

#define CHECK_CLOSED(self, error_msg) \
    do { \
        int _closed = IS_CLOSED(self); \
        if (_closed < 0) { \
            return NULL; \
        } \
        if (_closed && READAHEAD(self) == 0) \
        { \
            PyErr_SetString(PyExc_ValueError, error_msg); \
            return NULL; \
        } \
    } while (0);


/* Set up an empty nibbler (usable from a zeroed struct or over an
   existing one). */
static int
nibbler_init(nibbler *nb)
{
    PyObject *chunks = PyList_New(0);
    if (chunks == NULL)
        return -1;
    PyObject *old = nb->chunks;
    FT_ATOMIC_STORE_PTR_RELEASE(nb->chunks, chunks);
    nb->offset = 0;
    FT_ATOMIC_STORE_SSIZE_RELAXED(nb->nbytes, 0);
    Py_XDECREF(old);
    return 0;
}

/* Release the nibbler's storage; nibbler_init() makes it usable
   again. */
static void
nibbler_fini(nibbler *nb)
{
    PyObject *old = nb->chunks;
    FT_ATOMIC_STORE_PTR_RELEASE(nb->chunks, NULL);
    nb->offset = 0;
    FT_ATOMIC_STORE_SSIZE_RELAXED(nb->nbytes, 0);
    Py_XDECREF(old);
}

/* Free a staged list, dropping the chunk references. */
static void
wnode_free_list(wnode *node)
{
    while (node != NULL) {
        wnode *next = node->next;
        Py_DECREF(node->chunk);
        PyMem_Free(node);
        node = next;
    }
}

/* Try to stage a node. Returns 1 when pushed (the node's reference is
   transferred), 0 when the tag forbids gathering and the caller must
   go through io_lock. With `locked` (io_lock held) a DRAIN tag is
   also accepted: it can only belong to a close() in its flush window,
   which drains again afterwards. */
static int
buffered_wpush(buffered *self, wnode *node, int locked)
{
    uintptr_t w = _Py_atomic_load_uintptr(&self->wstate);
    for (;;) {
        int tag = WSTATE_TAG(w);
        if (tag != WTAG_WRITING && !(locked && tag == WTAG_DRAIN)) {
            return 0;
        }
        node->next = WSTATE_PTR(w);
        if (_Py_atomic_compare_exchange_uintptr(&self->wstate, &w,
                                                WSTATE(node, tag))) {
            return 1;
        }
        /* w was reloaded by the failed compare-exchange. */
    }
}

/* Detach the entire staged list (newest first), leaving the tag. */
static wnode *
buffered_wtake(buffered *self)
{
    uintptr_t w = _Py_atomic_load_uintptr(&self->wstate);
    for (;;) {
        if (WSTATE_PTR(w) == NULL) {
            return NULL;
        }
        if (_Py_atomic_compare_exchange_uintptr(&self->wstate, &w,
                                                WSTATE(NULL, WSTATE_TAG(w)))) {
            return WSTATE_PTR(w);
        }
    }
}

/* Change the tag, carrying the staged list over unchanged. */
static void
buffered_wtag_set(buffered *self, int tag)
{
    uintptr_t w = _Py_atomic_load_uintptr(&self->wstate);
    while (!_Py_atomic_compare_exchange_uintptr(
               &self->wstate, &w, WSTATE(WSTATE_PTR(w), tag))) {
    }
}

static int
buffered_clear(PyObject *op)
{
    buffered *self = buffered_CAST(op);
    self->state = STATE_UNINITIALIZED;
    Py_CLEAR(self->raw);
    nibbler_fini(&self->buf);
    nibbler_fini(&self->pending);
    wnode_free_list(buffered_wtake(self));
    Py_CLEAR(self->raw_writev);
    Py_CLEAR(self->dict);
    return 0;
}

static void
buffered_dealloc(PyObject *op)
{
    buffered *self = buffered_CAST(op);
    PyTypeObject *tp = Py_TYPE(self);
    self->finalizing = 1;
    if (_PyIOBase_finalize(op) < 0)
        return;
    _PyObject_GC_UNTRACK(self);
    self->state = STATE_UNINITIALIZED;
    FT_CLEAR_WEAKREFS(op, self->weakreflist);
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
    /* Buffered data lives in separately-tracked bytes objects. */
    return PyLong_FromSize_t(_PyObject_SIZE(Py_TYPE(self)));
}

static int
buffered_traverse(PyObject *op, visitproc visit, void *arg)
{
    buffered *self = buffered_CAST(op);
    Py_VISIT(Py_TYPE(self));
    Py_VISIT(self->raw);
    Py_VISIT(self->buf.chunks);
    Py_VISIT(self->pending.chunks);
    /* Staged wnode chunks are plain bytes: never part of a cycle. */
    Py_VISIT(self->raw_writev);
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
    if (self->state == STATE_READY && self->raw) {
        PyObject *r;
        r = PyObject_CallMethodOneArg(self->raw, &_Py_ID(_dealloc_warn), source);
        if (r)
            Py_DECREF(r);
        else
            PyErr_Clear();
    }
    Py_RETURN_NONE;
}

/*
 * _BufferedIOMixin methods
 * This is not a class, just a collection of methods that will be reused
 * by BufferedReader and BufferedWriter
 */

/* Flush and close */
/*[clinic input]
_io._Buffered.flush as _io__Buffered_simple_flush
[clinic start generated code]*/

static PyObject *
_io__Buffered_simple_flush_impl(buffered *self)
/*[clinic end generated code: output=29ebb3820db1bdfd input=f33ef045e7250767]*/
{
    CHECK_INITIALIZED(self)
    return PyObject_CallMethodNoArgs(self->raw, &_Py_ID(flush));
}

static int
buffered_closed(buffered *self)
{
    int closed;
    PyObject *res;
    CHECK_INITIALIZED_INT(self)
    res = PyObject_GetAttr(self->raw, &_Py_ID(closed));
    if (res == NULL)
        return -1;
    closed = PyObject_IsTrue(res);
    Py_DECREF(res);
    return closed;
}

/*[clinic input]
@getter
_io._Buffered.closed
[clinic start generated code]*/

static PyObject *
_io__Buffered_closed_get_impl(buffered *self)
/*[clinic end generated code: output=f08ce57290703a1a input=00b707b2517eaf8c]*/
{
    CHECK_INITIALIZED(self)
    return PyObject_GetAttr(self->raw, &_Py_ID(closed));
}

/*[clinic input]
_io._Buffered.close
[clinic start generated code]*/

static PyObject *
_io__Buffered_close_impl(buffered *self)
/*[clinic end generated code: output=7280b7b42033be0c input=d20b83d1ddd7d805]*/
{
    PyObject *res = NULL;
    int prev_tag = -1;
    int r;

    CHECK_INITIALIZED(self)
    if (!buffered_lock_io(self)) {
        return NULL;
    }
    /* gh-138720: Use IS_CLOSED to match flush CHECK_CLOSED. */
    r = IS_CLOSED(self);
    if (r < 0)
        goto end;
    if (r > 0) {
        res = Py_NewRef(Py_None);
        goto end;
    }

    /* Keep write() from gathering until the raw stream is closed, so a
       racing write serializes behind the lock and sees the closed file
       (gh-31976). */
    prev_tag = WTAG(self);
    buffered_wtag_set(self, WTAG_DRAIN);

    if (self->finalizing) {
        PyObject *r = _io__Buffered__dealloc_warn_impl(self, (PyObject *)self);
        if (r)
            Py_DECREF(r);
        else
            PyErr_Clear();
    }
    /* flush() will most probably re-take the lock, so drop it first */
    _PyRecursiveMutex_Unlock(&self->io_lock);
    r = _PyFile_Flush((PyObject *)self);
    if (!buffered_lock_io(self)) {
        buffered_wtag_set(self, prev_tag);
        return NULL;
    }
    PyObject *exc = NULL;
    if (r < 0) {
        exc = PyErr_GetRaisedException();
    }

    res = PyObject_CallMethodNoArgs(self->raw, &_Py_ID(close));

    /* Drop the buffers; a NULL chunks also makes IS_CLOSED() true. */
    nibbler_fini(&self->buf);
    nibbler_fini(&self->pending);
    wnode_free_list(buffered_wtake(self));
    _Py_atomic_store_ssize(&self->write_pending, 0);

    if (exc != NULL) {
        _PyErr_ChainExceptions1(exc);
        Py_CLEAR(res);
    }

end:
    if (prev_tag != -1) {
        buffered_wtag_set(self, prev_tag);
    }
    _PyRecursiveMutex_Unlock(&self->io_lock);
    return res;
}

/*[clinic input]
_io._Buffered.detach
[clinic start generated code]*/

static PyObject *
_io__Buffered_detach_impl(buffered *self)
/*[clinic end generated code: output=dd0fc057b8b779f7 input=482762a345cc9f44]*/
{
    PyObject *raw;
    CHECK_INITIALIZED(self)
    if (_PyFile_Flush((PyObject *)self) < 0) {
        return NULL;
    }
    if (!buffered_lock_io(self)) {
        return NULL;
    }
    raw = self->raw;
    self->raw = NULL;
    self->state = STATE_DETACHED;
    _PyRecursiveMutex_Unlock(&self->io_lock);
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
    CHECK_INITIALIZED(self)
    return PyObject_CallMethodNoArgs(self->raw, &_Py_ID(seekable));
}

/*[clinic input]
_io._Buffered.readable
[clinic start generated code]*/

static PyObject *
_io__Buffered_readable_impl(buffered *self)
/*[clinic end generated code: output=92afa07661ecb698 input=640619addb513b8b]*/
{
    CHECK_INITIALIZED(self)
    return PyObject_CallMethodNoArgs(self->raw, &_Py_ID(readable));
}

/*[clinic input]
_io._Buffered.writable
[clinic start generated code]*/

static PyObject *
_io__Buffered_writable_impl(buffered *self)
/*[clinic end generated code: output=4e3eee8d6f9d8552 input=b35ea396b2201554]*/
{
    CHECK_INITIALIZED(self)
    return PyObject_CallMethodNoArgs(self->raw, &_Py_ID(writable));
}


/*[clinic input]
@getter
_io._Buffered.name
[clinic start generated code]*/

static PyObject *
_io__Buffered_name_get_impl(buffered *self)
/*[clinic end generated code: output=d2adf384051d3d10 input=5a60eb8d33149f6e]*/
{
    CHECK_INITIALIZED(self)
    return PyObject_GetAttr(self->raw, &_Py_ID(name));
}

/*[clinic input]
@getter
_io._Buffered.mode
[clinic start generated code]*/

static PyObject *
_io__Buffered_mode_get_impl(buffered *self)
/*[clinic end generated code: output=0feb205748892fa4 input=8d5e4c1fed38e6f0]*/
{
    CHECK_INITIALIZED(self)
    return PyObject_GetAttr(self->raw, &_Py_ID(mode));
}

/* Lower-level APIs */

/*[clinic input]
_io._Buffered.fileno
[clinic start generated code]*/

static PyObject *
_io__Buffered_fileno_impl(buffered *self)
/*[clinic end generated code: output=b717648d58a95ee3 input=768ea30b3f6314a7]*/
{
    CHECK_INITIALIZED(self)
    return PyObject_CallMethodNoArgs(self->raw, &_Py_ID(fileno));
}

/*[clinic input]
_io._Buffered.isatty
[clinic start generated code]*/

static PyObject *
_io__Buffered_isatty_impl(buffered *self)
/*[clinic end generated code: output=c20e55caae67baea input=9ea007b11559bee4]*/
{
    CHECK_INITIALIZED(self)
    return PyObject_CallMethodNoArgs(self->raw, &_Py_ID(isatty));
}

/*
 * Helpers
 */

/* Sets the current error to BlockingIOError */
static void
_set_BlockingIOError(const char *msg, Py_ssize_t written)
{
    PyObject *err;
    PyErr_Clear();
    err = PyObject_CallFunction(PyExc_BlockingIOError, "isn",
                                errno, msg, written);
    if (err)
        PyErr_SetObject(PyExc_BlockingIOError, err);
    Py_XDECREF(err);
}

static Py_off_t
_buffered_raw_tell(buffered *self)
{
    Py_off_t n;
    PyObject *res;
    res = PyObject_CallMethodNoArgs(self->raw, &_Py_ID(tell));
    if (res == NULL)
        return -1;
    n = PyNumber_AsOff_t(res, PyExc_ValueError);
    Py_DECREF(res);
    if (n < 0) {
        if (!PyErr_Occurred())
            PyErr_Format(PyExc_OSError,
                         "Raw stream returned invalid position %" PY_PRIdOFF,
                         (PY_OFF_T_COMPAT)n);
        return -1;
    }
    return n;
}

static Py_off_t
_buffered_raw_seek(buffered *self, Py_off_t target, int whence)
{
    PyObject *res, *posobj, *whenceobj;
    Py_off_t n;

    posobj = PyLong_FromOff_t(target);
    if (posobj == NULL)
        return -1;
    whenceobj = PyLong_FromLong(whence);
    if (whenceobj == NULL) {
        Py_DECREF(posobj);
        return -1;
    }
    res = PyObject_CallMethodObjArgs(self->raw, &_Py_ID(seek),
                                     posobj, whenceobj, NULL);
    Py_DECREF(posobj);
    Py_DECREF(whenceobj);
    if (res == NULL)
        return -1;
    n = PyNumber_AsOff_t(res, PyExc_ValueError);
    Py_DECREF(res);
    if (n < 0) {
        if (!PyErr_Occurred())
            PyErr_Format(PyExc_OSError,
                         "Raw stream returned invalid position %" PY_PRIdOFF,
                         (PY_OFF_T_COMPAT)n);
        return -1;
    }
    return n;
}

static int
_buffered_init(buffered *self)
{
    if (self->buffer_size < 0) {
        PyErr_SetString(PyExc_ValueError,
            "buffer size must be non-negative");
        return -1;
    }
    if (nibbler_init(&self->buf) < 0)
        return -1;
    if (nibbler_init(&self->pending) < 0)
        return -1;
    wnode_free_list(buffered_wtake(self));
    _Py_atomic_store_uintptr(
        &self->wstate,
        WSTATE(NULL, CAN_READ(self) ? WTAG_READING : WTAG_WRITING));
    _Py_atomic_store_ssize(&self->write_pending, 0);

    /* Vectored write support is optional on the raw stream. */
    Py_CLEAR(self->raw_writev);
    if (CAN_WRITE(self)
        && PyObject_GetOptionalAttrString(self->raw, "_writev",
                                          &self->raw_writev) < 0) {
        return -1;
    }

    self->io_lock = (_PyRecursiveMutex){0};
    return 0;
}

/* _PyIO_trap_eintr() is reused from _io (see _iomodule.h). */

/*
 * Nibbler core. Helpers return -1 (or NULL) with an exception set on
 * error. Raw I/O helpers return -2 when a non-blocking raw stream
 * signals "would block".
 */


/* Empty the chunk list. */
static int
nibbler_clear(nibbler *nb)
{
    Py_ssize_t nchunks = PyList_GET_SIZE(nb->chunks);
    if (nchunks > 0 && PyList_SetSlice(nb->chunks, 0, nchunks, NULL) < 0)
        return -1;
    nb->offset = 0;
    FT_ATOMIC_STORE_SSIZE_RELAXED(nb->nbytes, 0);
    return 0;
}

/* Append a chunk to the buffer. */
static int
nibbler_append(nibbler *nb, PyObject *chunk)
{
    assert(PyBytes_Check(chunk) && PyBytes_GET_SIZE(chunk) > 0);
    if (PyList_Append(nb->chunks, chunk) < 0)
        return -1;
    FT_ATOMIC_STORE_SSIZE_RELAXED(nb->nbytes,
                                  nb->nbytes + PyBytes_GET_SIZE(chunk));
    return 0;
}

/* Consume `n` bytes from the front of the buffer, copying them to `dst`
   unless it is NULL. */
static int
nibbler_consume(nibbler *nb, char *dst, Py_ssize_t n)
{
    assert(0 <= n && n <= nb->nbytes);
    Py_ssize_t whole = 0;    /* chunks fully consumed */
    Py_ssize_t offset = nb->offset;
    Py_ssize_t remaining = n;
    while (remaining > 0) {
        PyObject *chunk = PyList_GET_ITEM(nb->chunks, whole);
        Py_ssize_t avail = PyBytes_GET_SIZE(chunk) - offset;
        Py_ssize_t take = Py_MIN(avail, remaining);
        if (dst != NULL) {
            memcpy(dst, PyBytes_AS_STRING(chunk) + offset, take);
            dst += take;
        }
        remaining -= take;
        if (take == avail) {
            whole++;
            offset = 0;
        }
        else {
            offset += take;
        }
    }
    /* Commit last: a failed delete consumes nothing. */
    if (whole > 0 && PyList_SetSlice(nb->chunks, 0, whole, NULL) < 0)
        return -1;
    nb->offset = offset;
    FT_ATOMIC_STORE_SSIZE_RELAXED(nb->nbytes, nb->nbytes - n);
    return 0;
}

/* Take `n` buffered bytes as a bytes object; zero-copy when `n` is
   exactly the first (unconsumed) chunk. */
static PyObject *
nibbler_take_bytes(nibbler *nb, Py_ssize_t n)
{
    assert(0 <= n && n <= nb->nbytes);
    if (n == 0)
        return Py_GetConstant(Py_CONSTANT_EMPTY_BYTES);

    if (nb->offset == 0) {
        PyObject *chunk = PyList_GET_ITEM(nb->chunks, 0);
        if (PyBytes_GET_SIZE(chunk) == n) {
            Py_INCREF(chunk);
            if (PyList_SetSlice(nb->chunks, 0, 1, NULL) < 0) {
                Py_DECREF(chunk);
                return NULL;
            }
            FT_ATOMIC_STORE_SSIZE_RELAXED(nb->nbytes, nb->nbytes - n);
            return chunk;
        }
    }

    PyBytesWriter *writer = PyBytesWriter_Create(n);
    if (writer == NULL)
        return NULL;
    if (nibbler_consume(nb, PyBytesWriter_GetData(writer), n) < 0) {
        PyBytesWriter_Discard(writer);
        return NULL;
    }
    return PyBytesWriter_Finish(writer);
}

/* Merge everything buffered into a single chunk with no consumed
   prefix. No-op when already in that form. */
static int
nibbler_coalesce(nibbler *nb)
{
    Py_ssize_t nchunks = PyList_GET_SIZE(nb->chunks);
    if (nchunks == 0 || (nchunks == 1 && nb->offset == 0))
        return 0;

    PyObject *joined = nibbler_take_bytes(nb, nb->nbytes);
    if (joined == NULL)
        return -1;
    assert(PyList_GET_SIZE(nb->chunks) == 0);
    int err = nibbler_append(nb, joined);
    Py_DECREF(joined);
    return err;
}

/* Drop `excess` bytes from the tail of the buffer (the newest data). */
static int
nibbler_drop_tail(nibbler *nb, Py_ssize_t excess)
{
    assert(0 < excess && excess <= nb->nbytes);
    while (excess > 0) {
        Py_ssize_t i = PyList_GET_SIZE(nb->chunks) - 1;
        PyObject *chunk = PyList_GET_ITEM(nb->chunks, i);
        Py_ssize_t start = i == 0 ? nb->offset : 0;
        Py_ssize_t avail = PyBytes_GET_SIZE(chunk) - start;
        if (avail <= excess) {
            if (PyList_SetSlice(nb->chunks, i, i + 1, NULL) < 0)
                return -1;
            if (i == 0)
                nb->offset = 0;
            FT_ATOMIC_STORE_SSIZE_RELAXED(nb->nbytes, nb->nbytes - avail);
            excess -= avail;
        }
        else {
            PyObject *head = PyBytes_FromStringAndSize(
                PyBytes_AS_STRING(chunk) + start, avail - excess);
            if (head == NULL)
                return -1;
            PyList_SetItem(nb->chunks, i, head);    /* steals head */
            if (i == 0)
                nb->offset = 0;
            FT_ATOMIC_STORE_SSIZE_RELAXED(nb->nbytes, nb->nbytes - excess);
            excess = 0;
        }
    }
    return 0;
}


/* Call raw.readinto() to fill `len` bytes at `start`. Returns bytes
   read (0 on EOF), -1 on error, -2 when the raw stream would block. */
static Py_ssize_t
buffered_raw_read(buffered *self, char *start, Py_ssize_t len)
{
    Py_buffer buf;
    PyObject *memobj, *res;
    Py_ssize_t n;
    /* NOTE: the buffer needn't be released as its object is NULL. */
    if (PyBuffer_FillInfo(&buf, NULL, start, len, 0, PyBUF_CONTIG) == -1)
        return -1;
    memobj = PyMemoryView_FromBuffer(&buf);
    if (memobj == NULL)
        return -1;
    /* NOTE: PyErr_SetFromErrno() calls PyErr_CheckSignals() when EINTR
       occurs so we needn't do it ourselves.
       We then retry reading, ignoring the signal if no handler has
       raised (see issue #10956).
    */
    do {
        res = PyObject_CallMethodOneArg(self->raw, &_Py_ID(readinto), memobj);
    } while (res == NULL && _PyIO_trap_eintr());
    Py_DECREF(memobj);
    if (res == NULL)
        return -1;
    if (res == Py_None) {
        /* Non-blocking stream would have blocked. Special return code! */
        Py_DECREF(res);
        return -2;
    }
    n = PyNumber_AsSsize_t(res, PyExc_ValueError);
    Py_DECREF(res);

    if (n == -1 && PyErr_Occurred()) {
        _PyErr_FormatFromCause(
            PyExc_OSError,
            "raw readinto() failed"
        );
        return -1;
    }

    if (n < 0 || n > len) {
        PyErr_Format(PyExc_OSError,
                     "raw readinto() returned invalid length %zd "
                     "(should have been between 0 and %zd)", n, len);
        return -1;
    }
    return n;
}

/* Read up to `n` bytes from raw into a fresh chunk appended to the
   buffer. Same return convention as buffered_raw_read(). */
static Py_ssize_t
buffered_fill(buffered *self, Py_ssize_t n)
{
    assert(n > 0);
    PyBytesWriter *writer = PyBytesWriter_Create(n);
    if (writer == NULL)
        return -1;
    Py_ssize_t r = buffered_raw_read(self, PyBytesWriter_GetData(writer), n);
    if (r <= 0) {
        PyBytesWriter_Discard(writer);
        return r;
    }
    PyObject *chunk = PyBytesWriter_FinishWithSize(writer, r);
    if (chunk == NULL)
        return -1;
    int err = nibbler_append(&self->buf, chunk);
    Py_DECREF(chunk);
    return err < 0 ? -1 : r;
}

/* Interpret the result of a raw write() or _writev() call. Returns bytes
   written, -1 on error, -2 when the raw stream would block (with errno
   restored to `errnum` for _set_BlockingIOError()). */
static Py_ssize_t
raw_write_result(PyObject *res, Py_ssize_t len, int errnum,
                     const char *what)
{
    if (res == NULL)
        return -1;
    if (res == Py_None) {
        /* Non-blocking stream would have blocked. Special return code! */
        Py_DECREF(res);
        errno = errnum;
        return -2;
    }
    Py_ssize_t n = PyNumber_AsSsize_t(res, PyExc_ValueError);
    Py_DECREF(res);
    if (n < 0 || n > len) {
        PyErr_Format(PyExc_OSError,
                     "raw %s returned invalid length %zd "
                     "(should have been between 0 and %zd)", what, n, len);
        return -1;
    }
    return n;
}

/* Submit the morsel to the raw stream with one call: a plain write for
   a single chunk, raw._writev() for several, or coalesce-and-write
   when _writev is unavailable or the chunk count exceeds IOV_MAX.
   Returns bytes written, -1 on error, -2 on "would block". Consuming
   what was written is the caller's job. */
static Py_ssize_t
buffered_write_step(buffered *self, nibbler *m)
{
    assert(m->nbytes > 0);
    Py_ssize_t nchunks = PyList_GET_SIZE(m->chunks);

    if (nchunks > 1 && (self->raw_writev == NULL || nchunks > IOV_MAX)) {
        if (nibbler_coalesce(m) < 0)
            return -1;
        nchunks = 1;
    }

    PyObject *res;
    int errnum;
    if (nchunks == 1) {
        PyObject *chunk = PyList_GET_ITEM(m->chunks, 0);
        Py_ssize_t len = PyBytes_GET_SIZE(chunk) - m->offset;
        PyObject *arg;
        if (m->offset == 0) {
            arg = Py_NewRef(chunk);
        }
        else {
            /* Unwritten tail of a partly-written chunk. The chunk stays
               alive in the morsel across the call. */
            arg = PyMemoryView_FromMemory(
                PyBytes_AS_STRING(chunk) + m->offset, len,
                PyBUF_READ);
            if (arg == NULL)
                return -1;
        }
        do {
            errno = 0;
            res = PyObject_CallMethodOneArg(self->raw, &_Py_ID(write), arg);
            errnum = errno;
        } while (res == NULL && _PyIO_trap_eintr());
        Py_DECREF(arg);
        return raw_write_result(res, len, errnum, "write()");
    }

    /* Vectored write: chunks[0] may have a consumed prefix; every chunk
       is passed without copying. */
    PyObject *buffers = PyList_New(nchunks);
    if (buffers == NULL)
        return -1;
    for (Py_ssize_t i = 0; i < nchunks; i++) {
        PyObject *chunk = PyList_GET_ITEM(m->chunks, i);
        PyObject *item;
        if (i == 0 && m->offset > 0) {
            item = PyMemoryView_FromMemory(
                PyBytes_AS_STRING(chunk) + m->offset,
                PyBytes_GET_SIZE(chunk) - m->offset, PyBUF_READ);
            if (item == NULL) {
                Py_DECREF(buffers);
                return -1;
            }
        }
        else {
            item = Py_NewRef(chunk);
        }
        PyList_SET_ITEM(buffers, i, item);
    }
    do {
        errno = 0;
        res = PyObject_CallOneArg(self->raw_writev, buffers);
        errnum = errno;
    } while (res == NULL && _PyIO_trap_eintr());
    Py_DECREF(buffers);
    return raw_write_result(res, m->nbytes, errnum, "_writev()");
}

/* Build the morsel: leftovers of an earlier blocked flush first
   (oldest), then the staged chunks in FIFO order. When the final
   chunk is `own` -- the calling write()'s chunk -- *own_tail is its
   length: the only bytes a blocked flush may drop. Caller holds
   io_lock. */
static int
buffered_take_morsel(buffered *self, nibbler *morsel, PyObject *own,
                     Py_ssize_t *own_tail)
{
    *own_tail = 0;
    PyObject *fresh = PyList_New(0);
    if (fresh == NULL)
        return -1;
    *morsel = self->pending;
    self->pending.chunks = fresh;
    self->pending.offset = 0;
    self->pending.nbytes = 0;

    /* Reverse the staged LIFO into FIFO order. */
    wnode *fifo = NULL;
    for (wnode *node = buffered_wtake(self); node != NULL; ) {
        wnode *next = node->next;
        node->next = fifo;
        fifo = node;
        node = next;
    }
    int err = 0;
    while (fifo != NULL) {
        wnode *next = fifo->next;
        if (err == 0)
            err = nibbler_append(morsel, fifo->chunk);
        if (err != 0) {
            /* The chunk is dropped; keep the pending count honest. */
            _Py_atomic_add_ssize(&self->write_pending,
                                 -PyBytes_GET_SIZE(fifo->chunk));
        }
        Py_DECREF(fifo->chunk);
        PyMem_Free(fifo);
        fifo = next;
    }
    Py_ssize_t nchunks = PyList_GET_SIZE(morsel->chunks);
    if (own != NULL && nchunks > 0
        && PyList_GET_ITEM(morsel->chunks, nchunks - 1) == own) {
        *own_tail = PyBytes_GET_SIZE(own);
    }
    return err;
}

/* Write one morsel -- the pending leftovers plus everything staged --
   until done or the raw stream blocks. Unwritten leftovers stay with
   the flusher in `pending`, to go out first next time; gathering
   continues meanwhile and is not written. `own` and *dropped carry
   the blocked-write accounting (see buffered_take_morsel). Caller
   holds io_lock. Returns 0 when everything was written, 1 when the
   raw stream would block (no exception set), -1 on error. */
static int
buffered_flush_locked(buffered *self, PyObject *own, Py_ssize_t *dropped)
{
    if (dropped != NULL)
        *dropped = 0;
    if (_Py_atomic_load_ssize(&self->write_pending) == 0)
        return 0;
    nibbler morsel;
    Py_ssize_t own_tail;
    if (buffered_take_morsel(self, &morsel, own, &own_tail) < 0)
        return -1;
    int ret = 0;
    while (morsel.nbytes > 0) {
        Py_ssize_t n = buffered_write_step(self, &morsel);
        if (n < 0) {
            ret = n == -2 ? 1 : -1;
            break;
        }
        if (nibbler_consume(&morsel, NULL, n) < 0) {
            ret = -1;
            break;
        }
        _Py_atomic_add_ssize(&self->write_pending, -n);
        /* Partial writes can return successfully when interrupted by a
           signal (see write(2)). We must run signal handlers before
           blocking another time, possibly indefinitely. */
        if (PyErr_CheckSignals() < 0) {
            ret = -1;
            break;
        }
    }
    if (ret == 1 && own_tail > 0 && morsel.nbytes > self->buffer_size) {
        /* Blocked: beyond buffer_size, drop -- but only bytes of the
           calling write()'s own chunk, never other writers' data. */
        Py_ssize_t excess = Py_MIN(morsel.nbytes - self->buffer_size,
                                   own_tail);
        if (nibbler_drop_tail(&morsel, excess) < 0) {
            ret = -1;
        }
        else {
            _Py_atomic_add_ssize(&self->write_pending, -excess);
            if (dropped != NULL)
                *dropped = excess;
        }
    }
    if (morsel.nbytes > 0) {
        assert(self->pending.nbytes == 0);
        nibbler_fini(&self->pending);
        self->pending = morsel;
    }
    else {
        nibbler_fini(&morsel);
    }
    return ret;
}

/* Empty the buffer completely. The DRAIN tag makes gatherers divert
   to io_lock, so a single take covers everything; leftovers remain
   only when the raw stream blocked. Caller holds io_lock. Same
   returns as buffered_flush_locked(). */
static int
buffered_drain_locked(buffered *self)
{
    int prev = WTAG(self);
    if (prev == WTAG_READING)
        return 0;
    buffered_wtag_set(self, WTAG_DRAIN);
    int r = buffered_flush_locked(self, NULL, NULL);
    buffered_wtag_set(self, prev);
    return r;
}


/* Make the nibbler hold read-ahead, draining pending writes first.
   Under DRAIN no gather can land, so a clean drain really leaves the
   buffer empty and the flip is exact. Caller holds io_lock. A blocked
   drain raises BlockingIOError and leaves the object writing, with
   the unwritten data still buffered. */
static int
buffered_ensure_reading(buffered *self)
{
    if (IS_READING(self))
        return 0;
    buffered_wtag_set(self, WTAG_DRAIN);
    int r = buffered_flush_locked(self, NULL, NULL);
    if (r == 0) {
        _Py_atomic_store_uintptr(&self->wstate,
                                 WSTATE(NULL, WTAG_READING));
        return 0;
    }
    buffered_wtag_set(self, WTAG_WRITING);
    if (r > 0) {
        _set_BlockingIOError("write could not complete without blocking", 0);
    }
    return -1;
}

/* Make the nibbler hold pending writes, rewinding the raw stream
   past unread read-ahead so the next write lands at the logical
   position. Caller holds io_lock; gatherers cannot push while the
   tag is READING, so the store is safe. */
static int
buffered_ensure_writing(buffered *self)
{
    if (IS_WRITING(self))
        return 0;
    if (self->buf.nbytes > 0) {
        if (_buffered_raw_seek(self, -(Py_off_t)self->buf.nbytes, 1) == -1)
            return -1;
        if (nibbler_clear(&self->buf) < 0)
            return -1;
    }
    _Py_atomic_store_uintptr(&self->wstate, WSTATE(NULL, WTAG_WRITING));
    return 0;
}

/* Fill dst[0:len]: buffered bytes first, then the raw stream -- read
   directly into dst when more than buffer_size is wanted, otherwise via
   a buffered chunk (read-ahead). With read1, at most one raw read is
   made. Returns bytes read, -1 on error, -2 when the raw stream would
   block before anything was read. */
static Py_ssize_t
buffered_read_into(buffered *self, char *dst, Py_ssize_t len, int read1)
{
    Py_ssize_t written = 0;
    while (written < len) {
        if (self->buf.nbytes > 0) {
            Py_ssize_t take = Py_MIN(self->buf.nbytes, len - written);
            if (nibbler_consume(&self->buf, dst + written, take) < 0)
                return -1;
            written += take;
            if (written == len)
                break;
        }
        Py_ssize_t r;
        Py_ssize_t remaining = len - written;
        if (remaining > self->buffer_size) {
            r = buffered_raw_read(self, dst + written, remaining);
            if (r > 0) {
                written += r;
                /* In read1 mode, one raw read is enough. */
                if (read1)
                    break;
                continue;
            }
        }
        else if (!(read1 && written)) {
            r = buffered_fill(self, self->buffer_size);
            if (r > 0)
                continue;     /* loop back to drain the buffer */
        }
        else {
            break;
        }
        if (r == 0)
            break;            /* EOF */
        if (r == -2) {
            if (written > 0)
                break;
            return -2;
        }
        return -1;
    }
    return written;
}

/* read(-1): buffered bytes plus everything to EOF, using raw.readall()
   when available. Returns None when the raw stream would block before
   any data was read. On error everything gathered so far stays
   buffered. */
static PyObject *
buffered_read_all_locked(buffered *self)
{
    PyObject *readall;
    if (PyObject_GetOptionalAttr(self->raw, &_Py_ID(readall), &readall) < 0)
        return NULL;
    if (readall) {
        PyObject *tail = _PyObject_CallNoArgs(readall);
        Py_DECREF(readall);
        if (tail == NULL)
            return NULL;
        if (tail != Py_None && !PyBytes_Check(tail)) {
            PyErr_SetString(PyExc_TypeError, "readall() should return bytes");
            Py_DECREF(tail);
            return NULL;
        }
        if (self->buf.nbytes == 0)
            return tail;      /* bytes; or None when it would block */
        PyObject *prefix = nibbler_take_bytes(&self->buf, self->buf.nbytes);
        if (prefix == NULL || tail == Py_None) {
            Py_DECREF(tail);
            return prefix;
        }
        PyBytes_Concat(&prefix, tail);    /* sets prefix to NULL on error */
        Py_DECREF(tail);
        return prefix;
    }

    /* No readall(): gather raw.read() chunks into the buffer until EOF
       or blocked, then hand over the whole buffer. */
    for (;;) {
        PyObject *data = PyObject_CallMethodNoArgs(self->raw, &_Py_ID(read));
        if (data == NULL)
            return NULL;
        if (data != Py_None && !PyBytes_Check(data)) {
            Py_DECREF(data);
            PyErr_SetString(PyExc_TypeError, "read() should return bytes");
            return NULL;
        }
        if (data == Py_None || PyBytes_GET_SIZE(data) == 0) {
            if (self->buf.nbytes == 0)
                return data;      /* b"" at EOF, None when blocked */
            Py_DECREF(data);
            return nibbler_take_bytes(&self->buf, self->buf.nbytes);
        }
        int err = nibbler_append(&self->buf, data);
        Py_DECREF(data);
        if (err < 0)
            return NULL;
    }
}

/* Logical index one past the first '\n' in [start, end) of the
   unconsumed buffer, or -1 when absent. */
static Py_ssize_t
nibbler_find_newline(nibbler *nb, Py_ssize_t start, Py_ssize_t end)
{
    Py_ssize_t base = 0;
    Py_ssize_t nchunks = PyList_GET_SIZE(nb->chunks);
    for (Py_ssize_t i = 0; i < nchunks && base < end; i++) {
        PyObject *chunk = PyList_GET_ITEM(nb->chunks, i);
        const char *data = PyBytes_AS_STRING(chunk);
        Py_ssize_t size = PyBytes_GET_SIZE(chunk);
        if (i == 0) {
            data += nb->offset;
            size -= nb->offset;
        }
        Py_ssize_t lo = start > base ? start - base : 0;
        Py_ssize_t hi = Py_MIN(end - base, size);
        if (lo < hi) {
            const char *found = memchr(data + lo, '\n', hi - lo);
            if (found != NULL)
                return base + (found - data) + 1;
        }
        base += size;
    }
    return -1;
}

/* readline core: consume through the first newline, at most `limit`
   bytes (unlimited when negative). EOF or a blocked non-blocking raw
   stream ends the line early. */
static PyObject *
buffered_readline_locked(buffered *self, Py_ssize_t limit)
{
    if (buffered_ensure_reading(self) < 0)
        return NULL;

    Py_ssize_t scanned = 0;
    for (;;) {
        Py_ssize_t window = self->buf.nbytes;
        if (limit >= 0 && limit < window)
            window = limit;
        if (scanned < window) {
            Py_ssize_t end = nibbler_find_newline(&self->buf, scanned,
                                                   window);
            if (end >= 0)
                return nibbler_take_bytes(&self->buf, end);
            scanned = window;
        }
        if (limit >= 0 && self->buf.nbytes >= limit)
            return nibbler_take_bytes(&self->buf, limit);
        /* An unbuffered stream must not read past the newline: go byte
           by byte. */
        Py_ssize_t r = buffered_fill(
            self, self->buffer_size > 0 ? self->buffer_size : 1);
        if (r == -1)
            return NULL;
        if (r <= 0)      /* EOF, or non-blocking with no data */
            return nibbler_take_bytes(&self->buf, self->buf.nbytes);
    }
}

/*
 * Shared methods and wrappers
 */

/*[clinic input]
_io._Buffered.flush
[clinic start generated code]*/

static PyObject *
_io__Buffered_flush_impl(buffered *self)
/*[clinic end generated code: output=da2674ef1ce71f3a input=fda63444697c6bf4]*/
{
    PyObject *res = NULL;

    CHECK_INITIALIZED(self)
    CHECK_CLOSED(self, "flush of closed file")

    if (!buffered_lock_io(self))
        return NULL;
    if (IS_WRITING(self)) {
        int r = buffered_drain_locked(self);
        if (r > 0) {
            _set_BlockingIOError("write could not complete without blocking",
                                 0);
        }
        if (r != 0)
            goto end;
    }
    res = Py_NewRef(Py_None);
end:
    _PyRecursiveMutex_Unlock(&self->io_lock);
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
    PyObject *res = NULL;

    CHECK_INITIALIZED(self)
    CHECK_CLOSED(self, "peek of closed file")

    if (self->buffer_size == 0) {
        /* An unbuffered stream cannot hold data without advancing the
           logical position. */
        _PyIO_State *state = find_io_state_by_def(Py_TYPE(self));
        return bufferediobase_unsupported(state, "peek");
    }

    if (!buffered_lock_io(self))
        return NULL;
    if (buffered_ensure_reading(self) < 0)
        goto end;

    /* Top up with at most one raw read when the request is not already
       satisfied. */
    Py_ssize_t want = Py_MIN(size, self->buffer_size);
    if (self->buf.nbytes < want || self->buf.nbytes == 0) {
        Py_ssize_t to_read = self->buffer_size - self->buf.nbytes;
        if (to_read > 0 && buffered_fill(self, to_read) == -1)
            goto end;
    }

    /* Return a view of everything buffered, without consuming it. */
    if (nibbler_coalesce(&self->buf) < 0)
        goto end;
    if (PyList_GET_SIZE(self->buf.chunks) == 0)
        res = Py_GetConstant(Py_CONSTANT_EMPTY_BYTES);
    else
        res = Py_NewRef(PyList_GET_ITEM(self->buf.chunks, 0));

end:
    _PyRecursiveMutex_Unlock(&self->io_lock);
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
    PyObject *res = NULL;

    CHECK_INITIALIZED(self)
    if (n < -1) {
        PyErr_SetString(PyExc_ValueError,
                        "read length must be non-negative or -1");
        return NULL;
    }

    CHECK_CLOSED(self, "read of closed file")

    if (n == 0)
        return Py_GetConstant(Py_CONSTANT_EMPTY_BYTES);

    if (!buffered_lock_io(self))
        return NULL;
    if (buffered_ensure_reading(self) < 0)
        goto end;

    if (n == -1) {
        /* The number of bytes is unspecified, read until the end of stream */
        res = buffered_read_all_locked(self);
    }
    else if (n <= self->buf.nbytes) {
        res = nibbler_take_bytes(&self->buf, n);
    }
    else {
        PyBytesWriter *writer = PyBytesWriter_Create(n);
        if (writer == NULL)
            goto end;
        Py_ssize_t r = buffered_read_into(self, PyBytesWriter_GetData(writer),
                                         n, 0);
        if (r == -1) {
            PyBytesWriter_Discard(writer);
            goto end;
        }
        if (r == -2) {
            /* Would block, and nothing was read. */
            PyBytesWriter_Discard(writer);
            res = Py_NewRef(Py_None);
        }
        else {
            res = PyBytesWriter_FinishWithSize(writer, r);
        }
    }

end:
    _PyRecursiveMutex_Unlock(&self->io_lock);
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
    CHECK_INITIALIZED(self)
    if (n < 0) {
        n = self->buffer_size > 0 ? self->buffer_size : DEFAULT_BUFFER_SIZE;
    }

    CHECK_CLOSED(self, "read of closed file")

    if (n == 0) {
        return Py_GetConstant(Py_CONSTANT_EMPTY_BYTES);
    }

    if (!buffered_lock_io(self)) {
        return NULL;
    }
    PyObject *res = NULL;
    if (buffered_ensure_reading(self) < 0)
        goto end;

    /* Return up to n bytes.  If at least one byte is buffered, we
       only return buffered bytes.  Otherwise, we do one raw read. */
    if (self->buf.nbytes > 0) {
        res = nibbler_take_bytes(&self->buf, Py_MIN(n, self->buf.nbytes));
        goto end;
    }

    PyBytesWriter *writer = PyBytesWriter_Create(n);
    if (writer == NULL)
        goto end;
    Py_ssize_t r = buffered_raw_read(self, PyBytesWriter_GetData(writer), n);
    if (r == -1) {
        PyBytesWriter_Discard(writer);
        goto end;
    }
    if (r == -2) {
        r = 0;
    }
    res = PyBytesWriter_FinishWithSize(writer, r);

end:
    _PyRecursiveMutex_Unlock(&self->io_lock);
    return res;
}

static PyObject *
_buffered_readinto_generic(buffered *self, Py_buffer *buffer, char readinto1)
{
    PyObject *res = NULL;

    CHECK_INITIALIZED(self)
    CHECK_CLOSED(self, "readinto of closed file")

    if (!buffered_lock_io(self))
        return NULL;
    if (buffered_ensure_reading(self) < 0)
        goto end;

    Py_ssize_t n = buffered_read_into(self, (char *)buffer->buf, buffer->len,
                                     readinto1);
    if (n == -1)
        goto end;
    if (n == -2)
        res = Py_NewRef(Py_None);
    else
        res = PyLong_FromSsize_t(n);

end:
    _PyRecursiveMutex_Unlock(&self->io_lock);
    return res;
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
    return _buffered_readinto_generic(self, buffer, 0);
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
    return _buffered_readinto_generic(self, buffer, 1);
}


static PyObject *
_buffered_readline(buffered *self, Py_ssize_t limit)
{
    PyObject *res;

    CHECK_CLOSED(self, "readline of closed file")

    if (!buffered_lock_io(self))
        return NULL;
    res = buffered_readline_locked(self, limit);
    _PyRecursiveMutex_Unlock(&self->io_lock);
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
    CHECK_INITIALIZED(self)
    return _buffered_readline(self, size);
}


/*[clinic input]
_io._Buffered.tell
[clinic start generated code]*/

static PyObject *
_io__Buffered_tell_impl(buffered *self)
/*[clinic end generated code: output=386972ae84716c1e input=ad61e04a6b349573]*/
{
    Py_off_t pos;

    CHECK_INITIALIZED(self)
    pos = _buffered_raw_tell(self);
    if (pos == -1)
        return NULL;
    if (IS_WRITING(self)) {
        /* Pending writes -- gathered or in a morsel mid-write -- sit
           past the raw position. */
        pos += _Py_atomic_load_ssize(&self->write_pending);
    }
    else {
        /* Read-ahead sits between the logical and the raw position. */
        pos -= FT_ATOMIC_LOAD_SSIZE_RELAXED(self->buf.nbytes);

        // GH-95782
        if (pos < 0)
            pos = 0;
    }

    return PyLong_FromOff_t(pos);
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
    Py_off_t target, n;
    PyObject *res = NULL;

    CHECK_INITIALIZED(self)

    /* Do some error checking instead of trusting OS 'seek()'
    ** error detection, just in case.
    */
    if ((whence < 0 || whence >2)
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

    CHECK_CLOSED(self, "seek of closed file")

    _PyIO_State *state = find_io_state_by_def(Py_TYPE(self));
    if (_PyIOBase_check_seekable(state, self->raw, Py_True) == NULL) {
        return NULL;
    }

    target = PyNumber_AsOff_t(targetobj, PyExc_ValueError);
    if (target == -1 && PyErr_Occurred())
        return NULL;

    if (!buffered_lock_io(self))
        return NULL;

    int prev_tag = -1;
    if (IS_WRITING(self)) {
        /* The drain moves the raw position up to the logical position,
           so a SEEK_CUR target needs no adjustment. Keep gathering
           paused until the raw seek is done, so no write lands at the
           old position after the drain. */
        prev_tag = WTAG(self);
        buffered_wtag_set(self, WTAG_DRAIN);
        int r = buffered_drain_locked(self);
        if (r > 0) {
            _set_BlockingIOError("write could not complete without blocking",
                                 0);
        }
        if (r != 0)
            goto end;
    }
    else if (whence == 1) {
        /* The raw position is `buf.nbytes` ahead of the logical
           position; compensate relative seeks. */
        target -= self->buf.nbytes;
    }
    n = _buffered_raw_seek(self, target, whence);
    if (n == -1)
        goto end;
    /* Drop read-ahead only after a successful raw seek, so a failed
       seek does not lose buffered data. */
    if (IS_READING(self) && nibbler_clear(&self->buf) < 0)
        goto end;
    res = PyLong_FromOff_t(n);

end:
    if (prev_tag != -1) {
        buffered_wtag_set(self, prev_tag);
    }
    _PyRecursiveMutex_Unlock(&self->io_lock);
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
    PyObject *res = NULL;

    CHECK_INITIALIZED(self)
    CHECK_CLOSED(self, "truncate of closed file")
    if (!CAN_WRITE(self)) {
        _PyIO_State *state = find_io_state_by_def(cls);
        return bufferediobase_unsupported(state, "truncate");
    }
    if (!buffered_lock_io(self))
        return NULL;

    /* Drain pending writes, or rewind past read-ahead, so that
       raw.truncate(None) acts at the logical position; keep gathering
       paused until the raw truncate is done. */
    if (buffered_ensure_writing(self) < 0)
        goto end;
    buffered_wtag_set(self, WTAG_DRAIN);
    int r = buffered_drain_locked(self);
    if (r > 0) {
        _set_BlockingIOError("write could not complete without blocking", 0);
    }
    if (r != 0)
        goto end;

    res = PyObject_CallMethodOneArg(self->raw, &_Py_ID(truncate), pos);

end:
    if (IS_WRITING(self)) {
        buffered_wtag_set(self, WTAG_WRITING);
    }
    _PyRecursiveMutex_Unlock(&self->io_lock);
    return res;
}

static PyObject *
buffered_iternext(PyObject *op)
{
    buffered *self = buffered_CAST(op);
    PyObject *line;
    PyTypeObject *tp;

    CHECK_INITIALIZED(self);

    nibbler_state *state = find_nibbler_state_by_def(Py_TYPE(self));
    tp = Py_TYPE(self);
    if (tp == state->PyBufferedReader_Type ||
        tp == state->PyBufferedRandom_Type)
    {
        /* Skip method call overhead for speed */
        line = _buffered_readline(self, -1);
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

    if (line == NULL)
        return NULL;

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
    buffered *self = buffered_CAST(op);
    PyObject *nameobj, *res;

    if (PyObject_GetOptionalAttr((PyObject *) self, &_Py_ID(name), &nameobj) < 0) {
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
    self->state = STATE_UNINITIALIZED;

    _PyIO_State *state = find_io_state_by_def(Py_TYPE(self));
    nibbler_state *nstate = find_nibbler_state_by_def(Py_TYPE(self));
    if (_PyIOBase_check_readable(state, raw, Py_True) == NULL) {
        return -1;
    }

    Py_XSETREF(self->raw, Py_NewRef(raw));
    self->buffer_size = buffer_size;
    self->caps = CAPS_READ;

    if (_buffered_init(self) < 0)
        return -1;

    self->fast_closed_checks = (
        Py_IS_TYPE(self, nstate->PyBufferedReader_Type) &&
        Py_IS_TYPE(raw, state->PyFileIO_Type)
    );

    self->state = STATE_READY;
    return 0;
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
    self->state = STATE_UNINITIALIZED;

    _PyIO_State *state = find_io_state_by_def(Py_TYPE(self));
    nibbler_state *nstate = find_nibbler_state_by_def(Py_TYPE(self));
    if (_PyIOBase_check_writable(state, raw, Py_True) == NULL) {
        return -1;
    }

    Py_INCREF(raw);
    Py_XSETREF(self->raw, raw);
    self->caps = CAPS_WRITE;

    self->buffer_size = buffer_size;
    if (_buffered_init(self) < 0)
        return -1;

    self->fast_closed_checks = (
        Py_IS_TYPE(self, nstate->PyBufferedWriter_Type) &&
        Py_IS_TYPE(raw, state->PyFileIO_Type)
    );

    self->state = STATE_READY;
    return 0;
}

/* The morsel write of a write() that reached buffer_size; the gathered
   bytes are the morsel tail because nothing can gather between append
   and flush (no blocking points). Caller holds io_lock. Returns the
   write() result. */
static PyObject *
buffered_write_flush_locked(buffered *self, PyObject *own, Py_ssize_t len)
{
    Py_ssize_t dropped;
    if (buffered_flush_locked(self, own, &dropped) < 0)
        return NULL;
    if (dropped > 0) {
        /* Blocked, and not everything fit within buffer_size: the
           dropped tail of this write was not accepted. */
        _set_BlockingIOError("write could not complete without blocking",
                             len - dropped);
        return NULL;
    }
    return PyLong_FromSsize_t(len);
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
    CHECK_INITIALIZED(self)

    int r = IS_CLOSED(self);
    if (r < 0) {
        return NULL;
    }
    if (r > 0) {
        PyErr_SetString(PyExc_ValueError, "write to closed file");
        return NULL;
    }
    if (buffer->len == 0) {
        return PyLong_FromSsize_t(0);
    }

    /* Immutable bytes are gathered without a copy; everything else is
       copied because the caller may modify it after write() returns. */
    PyObject *chunk;
    if (PyBytes_CheckExact(buffer->obj)) {
        chunk = Py_NewRef(buffer->obj);
    }
    else {
        chunk = PyBytes_FromStringAndSize(buffer->buf, buffer->len);
        if (chunk == NULL)
            return NULL;
    }
    wnode *node = PyMem_Malloc(sizeof(wnode));
    if (node == NULL) {
        Py_DECREF(chunk);
        return PyErr_NoMemory();
    }
    assert(((uintptr_t)node & WTAG_MASK) == 0);
    node->chunk = Py_NewRef(chunk);

    /* Account before pushing: a flusher may take the node the instant
       it is staged, and it debits as it writes. */
    Py_ssize_t total = _Py_atomic_add_ssize(&self->write_pending,
                                            buffer->len) + buffer->len;
    PyObject *res = NULL;
    if (buffered_wpush(self, node, 0)) {
        if (total < self->buffer_size) {
            Py_DECREF(chunk);
            return PyLong_FromSsize_t(buffer->len);
        }
        /* buffer_size reached: write the morsel out. If a flusher is
           already active -- possibly this same thread, reentrantly --
           the staged bytes are left for it or for a later writer. */
        if (_PyRecursiveMutex_IsLockedByCurrentThread(&self->io_lock)
            || _PyRecursiveMutex_LockTimed(&self->io_lock, 0, 0)
               != PY_LOCK_ACQUIRED) {
            Py_DECREF(chunk);
            return PyLong_FromSsize_t(buffer->len);
        }
        res = buffered_write_flush_locked(self, chunk, buffer->len);
        _PyRecursiveMutex_Unlock(&self->io_lock);
        Py_DECREF(chunk);
        return res;
    }

    /* Reading direction, or a drain in progress: the lock path. */
    if (!buffered_lock_io(self)) {
        goto fail;
    }
    /* Issue #31976: re-check for a file closed while we waited. */
    r = IS_CLOSED(self);
    if (r > 0) {
        PyErr_SetString(PyExc_ValueError, "write to closed file");
    }
    if (r != 0 || buffered_ensure_writing(self) < 0) {
        _PyRecursiveMutex_Unlock(&self->io_lock);
        goto fail;
    }
    int pushed = buffered_wpush(self, node, 1);
    assert(pushed);
    (void)pushed;
    if (total < self->buffer_size)
        res = PyLong_FromSsize_t(buffer->len);
    else
        res = buffered_write_flush_locked(self, chunk, buffer->len);
    _PyRecursiveMutex_Unlock(&self->io_lock);
    Py_DECREF(chunk);
    return res;

fail:
    _Py_atomic_add_ssize(&self->write_pending, -buffer->len);
    Py_DECREF(node->chunk);
    PyMem_Free(node);
    Py_DECREF(chunk);
    return NULL;
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

#define rwpair_CAST(op) ((rwpair *)(op))

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

    self->reader = (buffered *) PyObject_CallFunction(
            (PyObject *)nstate->PyBufferedReader_Type,
            "On", reader, buffer_size);
    if (self->reader == NULL)
        return -1;

    self->writer = (buffered *) PyObject_CallFunction(
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
    rwpair *self = rwpair_CAST(op);
    Py_VISIT(Py_TYPE(self));
    Py_VISIT(self->dict);
    Py_VISIT(self->reader);
    Py_VISIT(self->writer);
    return 0;
}

static int
bufferedrwpair_clear(PyObject *op)
{
    rwpair *self = rwpair_CAST(op);
    Py_CLEAR(self->reader);
    Py_CLEAR(self->writer);
    Py_CLEAR(self->dict);
    return 0;
}

static void
bufferedrwpair_dealloc(PyObject *op)
{
    rwpair *self = rwpair_CAST(op);
    PyTypeObject *tp = Py_TYPE(self);
    _PyObject_GC_UNTRACK(self);
    FT_CLEAR_WEAKREFS(op, self->weakreflist);
    (void)bufferedrwpair_clear(op);
    tp->tp_free(self);
    Py_DECREF(tp);
}

static PyObject *
_forward_call(buffered *self, PyObject *name, PyObject *args)
{
    PyObject *func, *ret;
    if (self == NULL) {
        PyErr_SetString(PyExc_ValueError,
                        "I/O operation on uninitialized object");
        return NULL;
    }

    func = PyObject_GetAttr((PyObject *)self, name);
    if (func == NULL) {
        PyErr_SetObject(PyExc_AttributeError, name);
        return NULL;
    }

    ret = PyObject_CallObject(func, args);
    Py_DECREF(func);
    return ret;
}

static PyObject *
bufferedrwpair_read(PyObject *op, PyObject *args)
{
    rwpair *self = rwpair_CAST(op);
    return _forward_call(self->reader, &_Py_ID(read), args);
}

static PyObject *
bufferedrwpair_peek(PyObject *op, PyObject *args)
{
    rwpair *self = rwpair_CAST(op);
    return _forward_call(self->reader, &_Py_ID(peek), args);
}

static PyObject *
bufferedrwpair_read1(PyObject *op, PyObject *args)
{
    rwpair *self = rwpair_CAST(op);
    return _forward_call(self->reader, &_Py_ID(read1), args);
}

static PyObject *
bufferedrwpair_readinto(PyObject *op, PyObject *args)
{
    rwpair *self = rwpair_CAST(op);
    return _forward_call(self->reader, &_Py_ID(readinto), args);
}

static PyObject *
bufferedrwpair_readinto1(PyObject *op, PyObject *args)
{
    rwpair *self = rwpair_CAST(op);
    return _forward_call(self->reader, &_Py_ID(readinto1), args);
}

static PyObject *
bufferedrwpair_write(PyObject *op, PyObject *args)
{
    rwpair *self = rwpair_CAST(op);
    return _forward_call(self->writer, &_Py_ID(write), args);
}

static PyObject *
bufferedrwpair_flush(PyObject *op, PyObject *Py_UNUSED(dummy))
{
    rwpair *self = rwpair_CAST(op);
    return _forward_call(self->writer, &_Py_ID(flush), NULL);
}

static PyObject *
bufferedrwpair_readable(PyObject *op, PyObject *Py_UNUSED(dummy))
{
    rwpair *self = rwpair_CAST(op);
    return _forward_call(self->reader, &_Py_ID(readable), NULL);
}

static PyObject *
bufferedrwpair_writable(PyObject *op, PyObject *Py_UNUSED(dummy))
{
    rwpair *self = rwpair_CAST(op);
    return _forward_call(self->writer, &_Py_ID(writable), NULL);
}

static PyObject *
bufferedrwpair_close(PyObject *op, PyObject *Py_UNUSED(dummy))
{
    rwpair *self = rwpair_CAST(op);
    PyObject *exc = NULL;
    PyObject *ret = _forward_call(self->writer, &_Py_ID(close), NULL);
    if (ret == NULL) {
        exc = PyErr_GetRaisedException();
    }
    else {
        Py_DECREF(ret);
    }
    ret = _forward_call(self->reader, &_Py_ID(close), NULL);
    if (exc != NULL) {
        _PyErr_ChainExceptions1(exc);
        Py_CLEAR(ret);
    }
    return ret;
}

static PyObject *
bufferedrwpair_isatty(PyObject *op, PyObject *Py_UNUSED(dummy))
{
    rwpair *self = rwpair_CAST(op);
    PyObject *ret = _forward_call(self->writer, &_Py_ID(isatty), NULL);

    if (ret != Py_False) {
        /* either True or exception */
        return ret;
    }
    Py_DECREF(ret);

    return _forward_call(self->reader, &_Py_ID(isatty), NULL);
}

static PyObject *
bufferedrwpair_closed_get(PyObject *op, void *Py_UNUSED(dummy))
{
    rwpair *self = rwpair_CAST(op);
    if (self->writer == NULL) {
        PyErr_SetString(PyExc_RuntimeError,
                "the BufferedRWPair object is being garbage-collected");
        return NULL;
    }
    return PyObject_GetAttr((PyObject *) self->writer, &_Py_ID(closed));
}


/*
 * BufferedRandom
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
    self->state = STATE_UNINITIALIZED;

    _PyIO_State *state = find_io_state_by_def(Py_TYPE(self));
    nibbler_state *nstate = find_nibbler_state_by_def(Py_TYPE(self));
    if (_PyIOBase_check_seekable(state, raw, Py_True) == NULL) {
        return -1;
    }
    if (_PyIOBase_check_readable(state, raw, Py_True) == NULL) {
        return -1;
    }
    if (_PyIOBase_check_writable(state, raw, Py_True) == NULL) {
        return -1;
    }

    Py_INCREF(raw);
    Py_XSETREF(self->raw, raw);
    self->buffer_size = buffer_size;
    self->caps = CAPS_READ | CAPS_WRITE;

    if (_buffered_init(self) < 0)
        return -1;

    self->fast_closed_checks = (Py_IS_TYPE(self, nstate->PyBufferedRandom_Type) &&
                                Py_IS_TYPE(raw, state->PyFileIO_Type));

    self->state = STATE_READY;
    return 0;
}

#define clinic_state() (find_nibbler_state_by_def(Py_TYPE(self)))
#include "clinic/bufferedio.c.h"
#undef clinic_state

static PyMethodDef bufferediobase_methods[] = {
    _IO__BUFFEREDIOBASE_DETACH_METHODDEF
    _IO__BUFFEREDIOBASE_READ_METHODDEF
    _IO__BUFFEREDIOBASE_READ1_METHODDEF
    _IO__BUFFEREDIOBASE_READINTO_METHODDEF
    _IO__BUFFEREDIOBASE_READINTO1_METHODDEF
    _IO__BUFFEREDIOBASE_WRITE_METHODDEF
    {NULL, NULL}
};

static PyType_Slot bufferediobase_slots[] = {
    {Py_tp_doc, (void *)bufferediobase_doc},
    {Py_tp_methods, bufferediobase_methods},
    {0, NULL},
};

/* Do not set Py_TPFLAGS_HAVE_GC so that tp_traverse and tp_clear are inherited */
static PyType_Spec nibbler_bufferediobase_spec = {
    .name = "_io._nibbler._BufferedIOBase",
    .flags = (Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE |
              Py_TPFLAGS_IMMUTABLETYPE),
    .slots = bufferediobase_slots,
};

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

static PyMemberDef bufferedreader_members[] = {
    {"raw", _Py_T_OBJECT, offsetof(buffered, raw), Py_READONLY},
    {"_finalizing", Py_T_BOOL, offsetof(buffered, finalizing), 0},
    {"__weaklistoffset__", Py_T_PYSSIZET, offsetof(buffered, weakreflist), Py_READONLY},
    {"__dictoffset__", Py_T_PYSSIZET, offsetof(buffered, dict), Py_READONLY},
    {NULL}
};

static PyGetSetDef bufferedreader_getset[] = {
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
    {Py_tp_members, bufferedreader_members},
    {Py_tp_getset, bufferedreader_getset},
    {Py_tp_init, _io_BufferedReader___init__},
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

static PyMemberDef bufferedwriter_members[] = {
    {"raw", _Py_T_OBJECT, offsetof(buffered, raw), Py_READONLY},
    {"_finalizing", Py_T_BOOL, offsetof(buffered, finalizing), 0},
    {"__weaklistoffset__", Py_T_PYSSIZET, offsetof(buffered, weakreflist), Py_READONLY},
    {"__dictoffset__", Py_T_PYSSIZET, offsetof(buffered, dict), Py_READONLY},
    {NULL}
};

static PyGetSetDef bufferedwriter_getset[] = {
    _IO__BUFFERED_CLOSED_GETSETDEF
    _IO__BUFFERED_NAME_GETSETDEF
    _IO__BUFFERED_MODE_GETSETDEF
    {NULL}
};


static PyType_Slot bufferedwriter_slots[] = {
    {Py_tp_dealloc, buffered_dealloc},
    {Py_tp_repr, buffered_repr},
    {Py_tp_doc, (void *)_io_BufferedWriter___init____doc__},
    {Py_tp_traverse, buffered_traverse},
    {Py_tp_clear, buffered_clear},
    {Py_tp_methods, bufferedwriter_methods},
    {Py_tp_members, bufferedwriter_members},
    {Py_tp_getset, bufferedwriter_getset},
    {Py_tp_init, _io_BufferedWriter___init__},
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
    {"read", bufferedrwpair_read, METH_VARARGS},
    {"peek", bufferedrwpair_peek, METH_VARARGS},
    {"read1", bufferedrwpair_read1, METH_VARARGS},
    {"readinto", bufferedrwpair_readinto, METH_VARARGS},
    {"readinto1", bufferedrwpair_readinto1, METH_VARARGS},

    {"write", bufferedrwpair_write, METH_VARARGS},
    {"flush", bufferedrwpair_flush, METH_NOARGS},

    {"readable", bufferedrwpair_readable, METH_NOARGS},
    {"writable", bufferedrwpair_writable, METH_NOARGS},

    {"close", bufferedrwpair_close, METH_NOARGS},
    {"isatty", bufferedrwpair_isatty, METH_NOARGS},

    {NULL, NULL}
};

static PyMemberDef bufferedrwpair_members[] = {
    {"__weaklistoffset__", Py_T_PYSSIZET, offsetof(rwpair, weakreflist), Py_READONLY},
    {"__dictoffset__", Py_T_PYSSIZET, offsetof(rwpair, dict), Py_READONLY},
    {NULL}
};

static PyGetSetDef bufferedrwpair_getset[] = {
    {"closed", bufferedrwpair_closed_get, NULL, NULL},
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

static PyMemberDef bufferedrandom_members[] = {
    {"raw", _Py_T_OBJECT, offsetof(buffered, raw), Py_READONLY},
    {"_finalizing", Py_T_BOOL, offsetof(buffered, finalizing), 0},
    {"__weaklistoffset__", Py_T_PYSSIZET, offsetof(buffered, weakreflist), Py_READONLY},
    {"__dictoffset__", Py_T_PYSSIZET, offsetof(buffered, dict), Py_READONLY},
    {NULL}
};

static PyGetSetDef bufferedrandom_getset[] = {
    _IO__BUFFERED_CLOSED_GETSETDEF
    _IO__BUFFERED_NAME_GETSETDEF
    _IO__BUFFERED_MODE_GETSETDEF
    {NULL}
};


static PyType_Slot bufferedrandom_slots[] = {
    {Py_tp_dealloc, buffered_dealloc},
    {Py_tp_repr, buffered_repr},
    {Py_tp_doc, (void *)_io_BufferedRandom___init____doc__},
    {Py_tp_traverse, buffered_traverse},
    {Py_tp_clear, buffered_clear},
    {Py_tp_iternext, buffered_iternext},
    {Py_tp_methods, bufferedrandom_methods},
    {Py_tp_members, bufferedrandom_members},
    {Py_tp_getset, bufferedrandom_getset},
    {Py_tp_init, _io_BufferedRandom___init__},
    {0, NULL},
};

static PyType_Spec nibbler_bufferedrandom_spec = {
    .name = "_io._nibbler.BufferedRandom",
    .basicsize = sizeof(buffered),
    .flags = (Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC |
              Py_TPFLAGS_IMMUTABLETYPE),
    .slots = bufferedrandom_slots,
};


/* _io._nibbler submodule: GC, definition, and runtime creation. */

static int
nibbler_mod_traverse(PyObject *mod, visitproc visit, void *arg)
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
nibbler_mod_clear(PyObject *mod)
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
nibbler_mod_free(void *mod)
{
    (void)nibbler_mod_clear((PyObject *)mod);
}

static struct PyModuleDef _PyIO_nibbler_Module = {
    .m_base = PyModuleDef_HEAD_INIT,
    .m_name = "_io._nibbler",
    .m_doc = "Buffered I/O classes mirroring _io, exposed as an _io submodule.",
    .m_size = sizeof(nibbler_state),
    .m_traverse = nibbler_mod_traverse,
    .m_clear = nibbler_mod_clear,
    .m_free = nibbler_mod_free,
};

#define ADD_TYPE(MOD, TYPE, SPEC, BASE)                                  \
do {                                                                     \
    TYPE = (PyTypeObject *)PyType_FromModuleAndSpec(MOD, SPEC,           \
                                                    (PyObject *)BASE);   \
    if (TYPE == NULL) {                                                  \
        Py_DECREF(MOD);                                                  \
        return NULL;                                                     \
    }                                                                    \
    if (PyModule_AddType(MOD, TYPE) < 0) {                               \
        Py_DECREF(MOD);                                                  \
        return NULL;                                                     \
    }                                                                    \
} while (0)

/* Create _io._nibbler, register its types, add it to sys.modules and to _io.
   Returns a borrowed reference, or NULL on error. */
PyObject *
_PyIO_create_nibbler_submodule(PyObject *io_module)
{
    _PyIO_State *io_state = get_io_state(io_module);

    PyObject *mod = PyModule_Create(&_PyIO_nibbler_Module);
    if (mod == NULL) {
        return NULL;
    }
    nibbler_state *state = get_nibbler_state(mod);

    ADD_TYPE(mod, state->PyBufferedIOBase_Type, &nibbler_bufferediobase_spec,
             io_state->PyIOBase_Type);
    ADD_TYPE(mod, state->PyBufferedReader_Type, &nibbler_bufferedreader_spec,
             state->PyBufferedIOBase_Type);
    ADD_TYPE(mod, state->PyBufferedWriter_Type, &nibbler_bufferedwriter_spec,
             state->PyBufferedIOBase_Type);
    ADD_TYPE(mod, state->PyBufferedRWPair_Type, &nibbler_bufferedrwpair_spec,
             state->PyBufferedIOBase_Type);
    ADD_TYPE(mod, state->PyBufferedRandom_Type, &nibbler_bufferedrandom_spec,
             state->PyBufferedIOBase_Type);

    PyObject *name = PyUnicode_FromString("_io._nibbler");
    if (name == NULL) {
        Py_DECREF(mod);
        return NULL;
    }
    if (_PyImport_SetModule(name, mod) < 0) {
        Py_DECREF(name);
        Py_DECREF(mod);
        return NULL;
    }
    Py_DECREF(name);

    if (PyModule_AddObjectRef(io_module, "_nibbler", mod) < 0) {
        Py_DECREF(mod);
        return NULL;
    }
    Py_DECREF(mod);
    return mod;
}

#undef ADD_TYPE

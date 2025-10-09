/*
    An implementation of Buffered I/O as defined by PEP 3116 - "New I/O"

    Classes defined here: BufferedIOBase, BufferedReader, BufferedWriter,
    BufferedRandom.

    Written by Amaury Forgeot d'Arc and Antoine Pitrou
*/

#include "Python.h"
#include "pycore_call.h"                // _PyObject_CallNoArgs()
#include "pycore_fileutils.h"           // _PyFile_Flush
#include "pycore_object.h"              // _PyObject_GC_UNTRACK()
#include "pycore_pyerrors.h"            // _Py_FatalErrorFormat()
#include "pycore_pylifecycle.h"         // _Py_IsInterpreterFinalizing()
#include "pycore_weakref.h"             // FT_CLEAR_WEAKREFS()

#include "_iomodule.h"


static inline PyObject* bytes_get_empty(void)
{
    return Py_GetConstant(Py_CONSTANT_EMPTY_BYTES);
}

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
    // FIXME: is this useful to still have? would it be nicer to have read() do
    // the wrapping.
    Py_ssize_t len;
    PyObject *data;

    PyObject *attr = readinto1
        ? &_Py_ID(read1)
        : &_Py_ID(read);
    data = _PyObject_CallMethod(self, attr, "n", buffer->len);
    if (data == NULL) {
        return  NULL;
    }

    // FIXME: Should this actually do bytes-like?
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
    _PyIO_State *state = get_io_state_by_cls(cls);
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
    _PyIO_State *state = get_io_state_by_cls(cls);
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
    _PyIO_State *state = get_io_state_by_cls(cls);
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
    _PyIO_State *state = get_io_state_by_cls(cls);
    return bufferediobase_unsupported(state, "write");
}


typedef struct {
    PyObject_HEAD

    PyObject *raw;
    int ok;    /* Initialized? */
    int detached;
    int readable;
    int writable;
    char finalizing;

    /* True if this is a vanilla Buffered object (rather than a user derived
       class) *and* the raw stream is a vanilla FileIO object. */
    int fast_closed_checks;

    PyThread_type_lock lock;
    volatile unsigned long owner;

    /* Size passed from constructor */
    Py_ssize_t buffer_size;
    /* peek() requires a buffer

    If buffer_size is 0, then peek() is disabled. Any other value, fill a single
    read-buffer, non-interleaved.

    FIXME: This will become a list of operations, but this buffer is a short
    term fix so peek() stays working during refactoring.

    FIXME: This should actually be a memoryview probably / cheap slicing...
    */
    PyObject *read_buffer;
    PyObject *write_buffer;

    PyObject *dict;
    PyObject *weakreflist;
} buffered;

#define buffered_CAST(op)   ((buffered *)(op))

/*
    Implementation notes:

    * BufferedReader, BufferedWriter and BufferedRandom try to share most
      methods (this is helped by the members `readable` and `writable`, which
      are initialized in the respective constructors)
    * Three helpers, _bufferedreader_raw_read, _bufferedwriter_raw_write and
      _bufferedwriter_flush_unlocked do a lot of useful housekeeping.

*/

/* These macros protect the buffered object against concurrent operations. */

static int
_enter_buffered_busy(buffered *self)
{
    int relax_locking;
    PyLockStatus st;
    if (self->owner == PyThread_get_thread_ident()) {
        PyErr_Format(PyExc_RuntimeError,
                     "reentrant call inside %R", self);
        return 0;
    }
    PyInterpreterState *interp = _PyInterpreterState_GET();
    relax_locking = _Py_IsInterpreterFinalizing(interp);
    Py_BEGIN_ALLOW_THREADS
    if (!relax_locking)
        st = PyThread_acquire_lock(self->lock, 1);
    else {
        /* When finalizing, we don't want a deadlock to happen with daemon
         * threads abruptly shut down while they owned the lock.
         * Therefore, only wait for a grace period (1 s.).
         * Note that non-daemon threads have already exited here, so this
         * shouldn't affect carefully written threaded I/O code.
         */
        st = PyThread_acquire_lock_timed(self->lock, (PY_TIMEOUT_T)1e6, 0);
    }
    Py_END_ALLOW_THREADS
    if (relax_locking && st != PY_LOCK_ACQUIRED) {
        PyObject *ascii = PyObject_ASCII((PyObject*)self);
        _Py_FatalErrorFormat(__func__,
            "could not acquire lock for %s at interpreter "
            "shutdown, possibly due to daemon threads",
            ascii ? PyUnicode_AsUTF8(ascii) : "<ascii(self) failed>");
    }
    return 1;
}

#define ENTER_BUFFERED(self) \
    ( (PyThread_acquire_lock(self->lock, 0) ? \
       1 : _enter_buffered_busy(self)) \
     && (self->owner = PyThread_get_thread_ident(), 1) )

#define LEAVE_BUFFERED(self) \
    do { \
        self->owner = 0; \
        PyThread_release_lock(self->lock); \
    } while(0);

#define CHECK_INITIALIZED(self) \
    if (self->ok <= 0) { \
        if (self->detached) { \
            PyErr_SetString(PyExc_ValueError, \
                 "raw stream has been detached"); \
        } \
        else { \
            PyErr_SetString(PyExc_ValueError, \
                "I/O operation on uninitialized object"); \
        } \
        return NULL; \
    }

#define CHECK_INITIALIZED_INT(self) \
    if (self->ok <= 0) { \
        if (self->detached) { \
            PyErr_SetString(PyExc_ValueError, \
                 "raw stream has been detached"); \
        } \
        else { \
            PyErr_SetString(PyExc_ValueError, \
                "I/O operation on uninitialized object"); \
        } \
        return -1; \
    }

#define IS_CLOSED(self) \
    (self->ok <= 0 || \
    (self->fast_closed_checks \
     ? _PyFileIO_closed(self->raw) \
     : buffered_closed(self)))

#define CHECK_CLOSED(self, error_msg) \
    if (IS_CLOSED(self)) { \
        PyErr_SetString(PyExc_ValueError, error_msg); \
        return NULL; \
    } \


static int
buffered_clear(PyObject *op)
{
    buffered *self = buffered_CAST(op);
    self->ok = 0;
    Py_CLEAR(self->raw);
    Py_CLEAR(self->dict);
    Py_CLEAR(self->write_buffer);
    return 0;
}

static void
buffered_dealloc(PyObject *op)
{
    buffered *self = buffered_CAST(op);
    PyTypeObject *tp = Py_TYPE(self);
    self->finalizing = 1;
    if (_PyIOBase_finalize(op) < 0) {
        return;
    }
    _PyObject_GC_UNTRACK(self);
    self->ok = 0;
    FT_CLEAR_WEAKREFS(op, self->weakreflist);
    Py_CLEAR(self->read_buffer);
    if (self->lock) {
        PyThread_free_lock(self->lock);
        self->lock = NULL;
    }
    (void)buffered_clear(op);
    tp->tp_free(self);
    Py_DECREF(tp);
}

static Py_ssize_t
_buffered_get_write_buffer_size(buffered *self) {
    // TODO(cmaloney): Could this be made thread safe by doing a single pointer take + incref?
    if (self->write_buffer == NULL) {
        return 0;
    }
    // FIXME(cmaloney): Buffer protocol support.
    if (PyBytes_CheckExact(self->write_buffer)) {
        return PyBytes_GET_SIZE(self->write_buffer);
    }

    assert(PyList_CheckExact(self->write_buffer));
    Py_ssize_t len = PyList_Size(self->write_buffer);
    Py_ssize_t size = 0;
    for(Py_ssize_t idx = 0; idx < len; ++idx) {
        PyObject *elem = PyList_GET_ITEM(self->write_buffer, idx);
        assert(elem);
        assert(PyBytes_CheckExact(elem));
        size += PyBytes_GET_SIZE(elem);
    }
    return size;
}

/*[clinic input]
@critical_section
_io._Buffered.__sizeof__
[clinic start generated code]*/

static PyObject *
_io__Buffered___sizeof___impl(buffered *self)
/*[clinic end generated code: output=0231ef7f5053134e input=07a32d578073ea64]*/
{
    Py_ssize_t size = _PyObject_SIZE(Py_TYPE(self));
    if (self->read_buffer) {
        size += PyBytes_GET_SIZE(self->read_buffer);
    }
    size += _buffered_get_write_buffer_size(self);

    return PyLong_FromSsize_t(size);
}

static int
buffered_traverse(PyObject *op, visitproc visit, void *arg)
{
    buffered *self = buffered_CAST(op);
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
    if (self->ok && self->raw) {
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
@critical_section
_io._Buffered.flush as _io__Buffered_simple_flush
[clinic start generated code]*/

static PyObject *
_io__Buffered_simple_flush_impl(buffered *self)
/*[clinic end generated code: output=29ebb3820db1bdfd input=5248cb84a65f80bd]*/
{
    // NOTE: This is used for BufferedReader.
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
    if (res == NULL) {
        return -1;
    }
    closed = PyObject_IsTrue(res);
    Py_DECREF(res);
    return closed;
}

/*[clinic input]
@critical_section
@getter
_io._Buffered.closed
[clinic start generated code]*/

static PyObject *
_io__Buffered_closed_get_impl(buffered *self)
/*[clinic end generated code: output=f08ce57290703a1a input=18eddefdfe4a3d2f]*/
{
    CHECK_INITIALIZED(self)
    return PyObject_GetAttr(self->raw, &_Py_ID(closed));
}

/*[clinic input]
@critical_section
_io._Buffered.close
[clinic start generated code]*/

static PyObject *
_io__Buffered_close_impl(buffered *self)
/*[clinic end generated code: output=7280b7b42033be0c input=56d95935b03fd326]*/
{
    PyObject *res = NULL;
    int r;

    CHECK_INITIALIZED(self)
    if (!ENTER_BUFFERED(self)) {
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

    if (self->finalizing) {
        PyObject *r = _io__Buffered__dealloc_warn_impl(self, (PyObject *)self);
        if (r)
            Py_DECREF(r);
        else
            PyErr_Clear();
    }
    /* flush() will most probably re-take the lock, so drop it first */
    LEAVE_BUFFERED(self)
    r = _PyFile_Flush((PyObject *)self);
    if (!ENTER_BUFFERED(self)) {
        return NULL;
    }
    PyObject *exc = NULL;
    if (r < 0) {
        exc = PyErr_GetRaisedException();
    }

    // If this is a BufferedReader self->read_buffer may still have data
    // as _io__Buffered_simple_flush_impl is used which flushes underlying but
    // doesn't clear read_buffer. This is okay because unused read data is fine
    // to have.

    res = PyObject_CallMethodNoArgs(self->raw, &_Py_ID(close));

    if (exc != NULL) {
        _PyErr_ChainExceptions1(exc);
        Py_CLEAR(res);
    }
    Py_CLEAR(self->read_buffer);

    // FIXME(cmaloney): Write buffer having data here means data loss which is bad(tm)
    Py_CLEAR(self->write_buffer);

end:
    LEAVE_BUFFERED(self)
    return res;
}

/*[clinic input]
@critical_section
_io._Buffered.detach
[clinic start generated code]*/

static PyObject *
_io__Buffered_detach_impl(buffered *self)
/*[clinic end generated code: output=dd0fc057b8b779f7 input=d4ef1828a678be37]*/
{
    PyObject *raw;
    CHECK_INITIALIZED(self)
    if (_PyFile_Flush((PyObject *)self) < 0) {
        return NULL;
    }
    raw = self->raw;
    self->raw = NULL;
    self->detached = 1;
    self->ok = 0;
    return raw;
}

/* Inquiries */

/*[clinic input]
@critical_section
_io._Buffered.seekable
[clinic start generated code]*/

static PyObject *
_io__Buffered_seekable_impl(buffered *self)
/*[clinic end generated code: output=90172abb5ceb6e8f input=e3a4fc1d297b2fd3]*/
{
    CHECK_INITIALIZED(self)
    return PyObject_CallMethodNoArgs(self->raw, &_Py_ID(seekable));
}

/*[clinic input]
@critical_section
_io._Buffered.readable
[clinic start generated code]*/

static PyObject *
_io__Buffered_readable_impl(buffered *self)
/*[clinic end generated code: output=92afa07661ecb698 input=abe54107d59bca9a]*/
{
    CHECK_INITIALIZED(self)
    return PyObject_CallMethodNoArgs(self->raw, &_Py_ID(readable));
}

/*[clinic input]
@critical_section
_io._Buffered.writable
[clinic start generated code]*/

static PyObject *
_io__Buffered_writable_impl(buffered *self)
/*[clinic end generated code: output=4e3eee8d6f9d8552 input=45eb76bf6a10e6f7]*/
{
    CHECK_INITIALIZED(self)
    return PyObject_CallMethodNoArgs(self->raw, &_Py_ID(writable));
}


/*[clinic input]
@critical_section
@getter
_io._Buffered.name
[clinic start generated code]*/

static PyObject *
_io__Buffered_name_get_impl(buffered *self)
/*[clinic end generated code: output=d2adf384051d3d10 input=6b84a0e6126f545e]*/
{
    CHECK_INITIALIZED(self)
    return PyObject_GetAttr(self->raw, &_Py_ID(name));
}

/*[clinic input]
@critical_section
@getter
_io._Buffered.mode
[clinic start generated code]*/

static PyObject *
_io__Buffered_mode_get_impl(buffered *self)
/*[clinic end generated code: output=0feb205748892fa4 input=0762d5e28542fd8c]*/
{
    CHECK_INITIALIZED(self)
    return PyObject_GetAttr(self->raw, &_Py_ID(mode));
}

/* Lower-level APIs */

/*[clinic input]
@critical_section
_io._Buffered.fileno
[clinic start generated code]*/

static PyObject *
_io__Buffered_fileno_impl(buffered *self)
/*[clinic end generated code: output=b717648d58a95ee3 input=1c4fead777bae20a]*/
{
    CHECK_INITIALIZED(self)
    return PyObject_CallMethodNoArgs(self->raw, &_Py_ID(fileno));
}

/*[clinic input]
@critical_section
_io._Buffered.isatty
[clinic start generated code]*/

static PyObject *
_io__Buffered_isatty_impl(buffered *self)
/*[clinic end generated code: output=c20e55caae67baea input=e53d182d7e490e3a]*/
{
    CHECK_INITIALIZED(self)
    return PyObject_CallMethodNoArgs(self->raw, &_Py_ID(isatty));
}

/* Forward decls */
static Py_ssize_t
_bufferedwriter_flush_unlocked(buffered *);
static Py_ssize_t
_bufferedreader_fill_buffer(buffered *self);
static void
_buffered_reset_buf(buffered *self);
static PyObject *
_bufferedreader_peek_unlocked(buffered *self);
static PyObject *
_bufferedreader_read_all(buffered *self);
static PyObject *
_bufferedreader_read_fast(buffered *self, Py_ssize_t);
static PyObject *
_bufferedreader_read_generic(buffered *self, Py_ssize_t);
static Py_ssize_t
_bufferedreader_raw_read(buffered *self, char *start, Py_ssize_t len);

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
    if (err) {
        PyErr_SetObject(PyExc_BlockingIOError, err);
    }
    Py_XDECREF(err);
}

// FIXME: this helper is nice, should probably use it some.
#if 0
/* Returns the address of the `written` member if a BlockingIOError was
   raised, NULL otherwise. The error is always re-raised. */
static Py_ssize_t *
_buffered_check_blocking_error(void)
{
    PyObject *exc = PyErr_GetRaisedException();
    if (exc == NULL || !PyErr_GivenExceptionMatches(exc, PyExc_BlockingIOError)) {
        PyErr_SetRaisedException(exc);
        return NULL;
    }
    PyOSErrorObject *err = (PyOSErrorObject *)exc;
    /* TODO: sanity check (err->written >= 0) */
    PyErr_SetRaisedException(exc);
    return &err->written;
}
#endif

static Py_off_t
_buffered_raw_tell(buffered *self)
{
    Py_off_t n;
    PyObject *res;

    if (_bufferedwriter_flush_unlocked(self) != 0) {
        return -1;
    }

    res = PyObject_CallMethodNoArgs(self->raw, &_Py_ID(tell));
    if (res == NULL) {
        return -1;
    }
    n = PyNumber_AsOff_t(res, PyExc_ValueError);
    Py_DECREF(res);
    if (n < 0) {
        if (!PyErr_Occurred()) {
            PyErr_Format(PyExc_OSError,
                         "Raw stream returned invalid position %" PY_PRIdOFF,
                         (PY_OFF_T_COMPAT)n);
        }
        return -1;
    }

    // Reduce position by the amount of data currently buffered.
    // gh-95782: For character pseudo-devices like `/dev/urandom` lseek() may
    // return 0 bytes. Tell should forward that result / never return negative.
    if (self->read_buffer && n > 0) {
        n -= PyBytes_GET_SIZE(self->read_buffer);
        // buffer should always be smaller than bytes read so far.
        assert(n >= 0);
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
            "buffer size must be 0 or greater");
        return -1;
    }
    if (self->lock) {
        PyThread_free_lock(self->lock);
    }
    self->lock = PyThread_allocate_lock();
    if (self->lock == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "can't allocate read lock");
        return -1;
    }
    self->owner = 0;
    _buffered_reset_buf(self);
    return 0;
}

/* Return 1 if an OSError with errno == EINTR is set (and then
   clears the error indicator), 0 otherwise.
   Should only be called when PyErr_Occurred() is true.
*/
int
_PyIO_trap_eintr(void)
{
    if (!PyErr_ExceptionMatches(PyExc_OSError)) {
        return 0;
    }
    PyObject *exc = PyErr_GetRaisedException();
    PyOSErrorObject *env_err = (PyOSErrorObject *)exc;
    assert(env_err != NULL);
    if (env_err->myerrno != NULL) {
        assert(EINTR > 0 && EINTR < INT_MAX);
        assert(PyLong_CheckExact(env_err->myerrno));
        int overflow;
        int myerrno = PyLong_AsLongAndOverflow(env_err->myerrno, &overflow);
        PyErr_Clear();
        if (myerrno == EINTR) {
            Py_DECREF(exc);
            return 1;
        }
    }
    /* This silences any error set by PyObject_RichCompareBool() */
    PyErr_SetRaisedException(exc);
    return 0;
}

/*
 * Shared methods and wrappers
 */

static Py_ssize_t
buffered_flush_and_rewind_unlocked(buffered *self)
{
    Py_ssize_t n;

    if (_bufferedwriter_flush_unlocked(self) == -1) {
        return -1;
    }

    // FIXME(cmaloney): The flush on close really doesn't care about this...
    if (self->read_buffer) {
        /* Rewind the raw stream so that its position corresponds to
           the current logical position. */
        n = _buffered_raw_seek(self, -PyBytes_GET_SIZE(self->read_buffer), SEEK_CUR);
        if (n == -1) {
            return -1;
        }
        _buffered_reset_buf(self);
    }

    // FIXME: Buffer shold be flushed...
    assert(self->read_buffer == NULL);
    return 0;
}

/* FIXME: This should never need to allocate. Allocation == new failure state.

That is a later optimization point however.
*/
static int
buffered_shrink_read_buffer(buffered *self, Py_ssize_t consumed)
{
    if (consumed == 0) {
        return 0;
    }
    // Should have a buffer with more than being requested
    assert(self->read_buffer != NULL);
    Py_ssize_t available = PyBytes_GET_SIZE(self->read_buffer);
    assert(available >= consumed && consumed >= 0);

    if (available == consumed) {
        Py_CLEAR(self->read_buffer);
        return 0;
    }

    PyObject *new_buffer = PyBytes_FromStringAndSize(
            PyBytes_AS_STRING(self->read_buffer) + consumed,
            available - consumed);
    if (new_buffer == NULL) {
        assert(PyErr_Occurred());
        return -1;
    }
    Py_SETREF(self->read_buffer, new_buffer);
    return 0;
}

/*[clinic input]
@critical_section
_io._Buffered.flush
[clinic start generated code]*/

static PyObject *
_io__Buffered_flush_impl(buffered *self)
/*[clinic end generated code: output=da2674ef1ce71f3a input=6b30de9f083419c2]*/
{
    CHECK_INITIALIZED(self)
    CHECK_CLOSED(self, "flush of closed file")

    if (!ENTER_BUFFERED(self)) {
        return NULL;
    }
    Py_ssize_t res = buffered_flush_and_rewind_unlocked(self);
    LEAVE_BUFFERED(self)

    if (res == -1) {
        assert(PyErr_Occurred());
        return NULL;
    }
    Py_RETURN_NONE;
}

/*[clinic input]
@critical_section
_io._Buffered.peek
    size: Py_ssize_t = 0
    /

[clinic start generated code]*/

static PyObject *
_io__Buffered_peek_impl(buffered *self, Py_ssize_t size)
/*[clinic end generated code: output=ba7a097ca230102b input=56733376f926d982]*/
{
    PyObject *res = NULL;

    CHECK_INITIALIZED(self)
    CHECK_CLOSED(self, "peek of closed file")

    /* peek() needs buffering to return data without moving file position. */
    // FIXME: should this actually be around seekability? (Can't peek without going back?)
    if (self->buffer_size == 0) {
        PyErr_SetString(PyExc_ValueError, "peek requires buffer_size greater than zero");
        return NULL;
    }

    if (!ENTER_BUFFERED(self)) {
        return NULL;
    }

    if (_bufferedwriter_flush_unlocked(self) == -1) {
        LEAVE_BUFFERED(self);
        return NULL;
    }
    res = _bufferedreader_peek_unlocked(self);
    LEAVE_BUFFERED(self)
    return res;
}

/*[clinic input]
@critical_section
_io._Buffered.read
    size as n: Py_ssize_t(accept={int, NoneType}) = -1
    /
[clinic start generated code]*/

static PyObject *
_io__Buffered_read_impl(buffered *self, Py_ssize_t n)
/*[clinic end generated code: output=f41c78bb15b9bbe9 input=bdb4b0425b295472]*/
{
    PyObject *res;

    CHECK_INITIALIZED(self)
    if (n < -1) {
        PyErr_SetString(PyExc_ValueError,
                        "read length must be non-negative or -1");
        return NULL;
    }

    CHECK_CLOSED(self, "read of closed file")

    if (n == -1) {
        /* The number of bytes is unspecified, read until the end of stream */
        if (!ENTER_BUFFERED(self)) {
            return NULL;
        }
        res = _bufferedreader_read_all(self);
        LEAVE_BUFFERED(self);
        return res;
    }

    // FIXME(cmaloney): lock-free fast reading was in last version.
    return _bufferedreader_read_generic(self, n);
}

/*[clinic input]
@critical_section
_io._Buffered.read1
    size as n: Py_ssize_t = -1
    /
[clinic start generated code]*/

static PyObject *
_io__Buffered_read1_impl(buffered *self, Py_ssize_t n)
/*[clinic end generated code: output=bcc4fb4e54d103a3 input=3d0ad241aa52b36c]*/
{
    CHECK_INITIALIZED(self)

    CHECK_CLOSED(self, "read of closed file")

    if (n == 0) {
        return Py_GetConstant(Py_CONSTANT_EMPTY_BYTES);
    }


    /* Return up to n bytes.  If at least one byte is buffered, we
       only return buffered bytes.  Otherwise, we do one raw read. */
    // FIXME(cmaloney): the previous logic this wasn't special cased. Can this
    //                  get simplified back to that?
    if (!ENTER_BUFFERED(self)) {
        return NULL;
    }

    if (_bufferedwriter_flush_unlocked(self) != 0) {
        LEAVE_BUFFERED(self);
        return NULL;
    }


    if (n < 0) {
        // Called without an explicit size. Return available data or fill a buffer
        // a single time.
        if (self->read_buffer == NULL) {
            n = _bufferedreader_fill_buffer(self);
            if (n < 0) {
                LEAVE_BUFFERED(self);
                return NULL;
            }
        } else {
            n = PyBytes_GET_SIZE(self->read_buffer);
        }
        LEAVE_BUFFERED(self);
        return _bufferedreader_read_fast(self, n);
    }

    // FIXME: Just call _buffered_readinto_generic with readinto1=1

    /* Return up to n bytes.  If at least one byte is buffered, we
       only return buffered bytes.  Otherwise, we do one raw read. */
    if (self->read_buffer) {
        n = Py_MIN(PyBytes_GET_SIZE(self->read_buffer), n);
        PyObject *res = _bufferedreader_read_fast(self, n);
        LEAVE_BUFFERED(self);
        return res;
    }

    /* Flush the write buffer if necessary */
    if (buffered_flush_and_rewind_unlocked(self) == -1) {
        LEAVE_BUFFERED(self);
        return NULL;
    }

    // FIXME: Can this be replaced with just a _buffered_readinto_generic?
    // Really just need the byes on top / wrapping...
    // Need to do a read
    PyBytesWriter *writer = PyBytesWriter_Create(n);
    if (writer == NULL) {
        LEAVE_BUFFERED(self);
        return NULL;
    }

    Py_ssize_t r = _bufferedreader_raw_read(self,
                                            PyBytesWriter_GetData(writer), n);
    LEAVE_BUFFERED(self);
    if (r == -1) {
        PyBytesWriter_Discard(writer);
        return NULL;
    }
    if (r == -2) {
        r = 0;
    }

    return PyBytesWriter_FinishWithSize(writer, r);
}

static PyObject *
_buffered_readinto_generic(buffered *self, Py_buffer *buffer, char readinto1)
{
    CHECK_INITIALIZED(self)
    CHECK_CLOSED(self, "readinto of closed file")

    if (!ENTER_BUFFERED(self)) {
        return NULL;
    }
    Py_ssize_t written = 0;
    // FIXME(cmaloney): Optimize read case a lot more (bpo-9971)
    // see: https://github.com/python/cpython/commit/3486a98dcd7f11215b61be3428edbbc9b6aa3164
    if (self->read_buffer) {
        Py_ssize_t available = PyBytes_GET_SIZE(self->read_buffer);
        written = Py_MIN(buffer->len, available);
        memcpy(buffer->buf, PyBytes_AS_STRING(self->read_buffer), written);
        if (buffered_shrink_read_buffer(self, written) == -1) {
            LEAVE_BUFFERED(self);
            return NULL;
        }

        // Buffer filled from read_buffer; early exit.
        if (available >= buffer->len) {
            LEAVE_BUFFERED(self);
            return PyLong_FromSsize_t(written);
        }
    }

    // FIXME: with bufer_size = 0, I think write buffer should _always_ be empty.
    if (buffered_flush_and_rewind_unlocked(self) == -1) {
        LEAVE_BUFFERED(self);
        return NULL;
    }

    // read buffer should have been emptied.
    assert(self->read_buffer == NULL);
    Py_ssize_t n;
    while (1) {
        assert(buffer->len >= written);
        Py_ssize_t remaining = buffer->len - written;
        if (remaining == 0) {
            break;
        }

        // FIXME(cmaloney): Are the thresholds for when to do this right for
        // current version?
        // Do big reads directly. For small reads, bump up to a full buffer_size
        // to avoid small reads. This exchanges read() for memcpy().
        if (remaining > self->buffer_size) {
            n = _bufferedreader_raw_read(self, buffer->buf + written, remaining);
        }
        // FIXME(cmaloney): I don't understand why this behavior is optimal but
        // it is needed for readinto1 tests.
        /* In readinto1 mode, we do not want to fill the internal
           buffer if we already have some data to return */
        else if (!(readinto1 && written)) {
            // FIXME: Ideally need bytearray which is convertable to bytes without copy...
            //        (and handles the prefix cut memcpy when needed / is slicable...)
            Py_ssize_t filled_bytes = _bufferedreader_fill_buffer(self);
            // Adapt to match _bufferedreader_raw_read return + data filling.
            if (filled_bytes > 0) {
                assert(self->read_buffer);
                Py_ssize_t copied_out = Py_MIN(remaining, filled_bytes);
                memcpy(buffer->buf + written,
                       PyBytes_AS_STRING(self->read_buffer), copied_out);
                if (buffered_shrink_read_buffer(self, copied_out) == -1) {
                    LEAVE_BUFFERED(self);
                    return NULL;
                }
                n = copied_out;
            } else {
                n = filled_bytes;
            }
        }
        else {
            n = 0;
        }

        /* end of stream */
        if (n == 0) {
            break;
        }
        /* non-blocking would have blocked */
        else if (n == -2) {
            if (written == 0) {
                LEAVE_BUFFERED(self);
                Py_RETURN_NONE;
            }
            /* Return as much as read so far. */
            break;
        }
        /* Other errors */
        else if (n < 0) {
            LEAVE_BUFFERED(self);
            return NULL;
        }

        written += n;

        /* Only one read for readinto1 */
        if (readinto1) {
            break;
        }
    }

    LEAVE_BUFFERED(self);
    return PyLong_FromSsize_t(written);
}

/*[clinic input]
@critical_section
_io._Buffered.readinto
    buffer: Py_buffer(accept={rwbuffer})
    /
[clinic start generated code]*/

static PyObject *
_io__Buffered_readinto_impl(buffered *self, Py_buffer *buffer)
/*[clinic end generated code: output=bcb376580b1d8170 input=777c33e7adaa2bcd]*/
{
    return _buffered_readinto_generic(self, buffer, 0);
}

/*[clinic input]
@critical_section
_io._Buffered.readinto1
    buffer: Py_buffer(accept={rwbuffer})
    /
[clinic start generated code]*/

static PyObject *
_io__Buffered_readinto1_impl(buffered *self, Py_buffer *buffer)
/*[clinic end generated code: output=6e5c6ac5868205d6 input=ef03cc5fc92a6895]*/
{
    return _buffered_readinto_generic(self, buffer, 1);
}

// Return values:
// -1 -- Not Found
// 0-N -- Found or hit limit, length of string to take
static Py_ssize_t
_buffered_try_split_line(PyObject *bytes, Py_ssize_t limit) {
    const char *found, *start;
    Py_ssize_t size;

    // Must have a cached read to search inside of.
    assert(bytes);

    start = PyBytes_AsString(bytes);
    size = PyBytes_GET_SIZE(bytes);

    // FIXME: ASM check limit >= 0 && Py_MIN here
    // FIXME: Would a Py_MIN be better here?
    if (limit >= 0 && size > limit) {
        size = limit;
    }

    found = memchr(start, '\n', size);
    if (found == NULL) {
        /* Hit limit, return everything passed. */
        if (limit >= 0) {
            return limit;
        }
        /* no newline before limit, return all read data */
        return -1;
    }
    return found - start + 1;
}

static PyObject *
_buffered_readline(buffered *self, Py_ssize_t limit)
{
    PyObject *chunks = NULL;

    CHECK_CLOSED(self, "readline of closed file")

    // FIXME: 3.14/main has a fast unlocked case here.

    /* Now we try to get some more from the raw stream */
    if (!ENTER_BUFFERED(self)) {
        return NULL;
    }

    // FIXME: Move to an internal _Py_readfrom implementation?
    //        which calls a function in a loop with non-linear resizing of a
    //        mutable buffer.

    // FIXME: Flush the write buffer if there is one. This code handles having
    //        data in read_buffer fine.
    if (_bufferedwriter_flush_unlocked(self) == -1) {
        LEAVE_BUFFERED(self);
        return NULL;
    }

    // FIXME(cmaloney): Make this thread safe by not using self->read_buffer
    // that is, keep the data actually being worked on local to this thread
    // (that you interleave operations isn't the fault of this)

    // Gather chunks into read_buffer appending to list.
    while (1) {
        if (limit == 0) {
            LEAVE_BUFFERED(self);
            break;
        }

        /* Fill buffer if needed

           NOTE: It's critical not to issue a read() unless more data is
           definitely required as that may cause blocking / hanging. */
        if (!self->read_buffer) {
            Py_ssize_t n;
            // FIXME: This is reading in fixed size chunks of self->buffer_size.
            // When reading without a limit, that doesn't make a lot of sense as we
            // may need to read a lot more than buffer_size bytes, should move to
            // non-linear expansion of the buffer.
            n = _bufferedreader_fill_buffer(self);
            if (n == -1) {
                // FIXME: would it be better to put chunks back into
                // self->read_buffer?
                LEAVE_BUFFERED(self);
                Py_XDECREF(chunks);
                return NULL;
            }

            /* End of stream or would block, return all bytes so far. */
            if (n <= 0) {
                LEAVE_BUFFERED(self);
                break;
            }
        }
        assert(self->read_buffer != NULL);

        Py_ssize_t length = _buffered_try_split_line(self->read_buffer, limit);

        /* Found! Return data so far. */
        if (length >= 0) {
            PyObject *final_chunk = _bufferedreader_read_fast(self, length);

            // Unlock before string join + dealloc which may be expensive.
            // note nothing past this touches self->read_buffer.
            LEAVE_BUFFERED(self);

            if (chunks == NULL) {
                // Is first chunk, no need to join.
                return final_chunk;
            }

            if (PyList_Append(chunks, final_chunk) < 0) {
                // Note: Not clearing read buffer here, as it has the data after
                //       the newline which might still be useful.
                Py_DECREF(chunks);
                return NULL;
            }
            break;
        }

        /* Not found, will need another chunk. */
        if (chunks == NULL) {
            chunks = PyList_New(0);
            if (chunks == NULL) {
                LEAVE_BUFFERED(self);
                return  NULL;
            }
        }

        if (PyList_Append(chunks, self->read_buffer) < 0) {
            Py_CLEAR(self->read_buffer);
            LEAVE_BUFFERED(self);
            Py_DECREF(chunks);
            return NULL;
        }
        Py_CLEAR(self->read_buffer);

        if (limit >= 0) {
            limit = Py_MAX(limit - PyBytes_GET_SIZE(self->read_buffer), 0);
        }
    }

    // Need to return all the data in chunks joined together.
    // Happens for both hit limit and found in not first chunk.
    if (chunks == NULL) {
        return bytes_get_empty();
    }
    return PyBytes_Join(bytes_get_empty(), chunks);
}

/*[clinic input]
@critical_section
_io._Buffered.readline
    size: Py_ssize_t(accept={int, NoneType}) = -1
    /
[clinic start generated code]*/

static PyObject *
_io__Buffered_readline_impl(buffered *self, Py_ssize_t size)
/*[clinic end generated code: output=24dd2aa6e33be83c input=e81ca5abd4280776]*/
{
    CHECK_INITIALIZED(self)
    return _buffered_readline(self, size);
}


/*[clinic input]
@critical_section
_io._Buffered.tell
[clinic start generated code]*/

static PyObject *
_io__Buffered_tell_impl(buffered *self)
/*[clinic end generated code: output=386972ae84716c1e input=ab12e67d8abcb42f]*/
{
    Py_off_t pos;

    CHECK_INITIALIZED(self)
    pos = _buffered_raw_tell(self);
    if (pos == -1) {
        return NULL;
    }
    return PyLong_FromOff_t(pos);
}

/*[clinic input]
@critical_section
_io._Buffered.seek
    target as targetobj: object
    whence: int = 0
    /
[clinic start generated code]*/

static PyObject *
_io__Buffered_seek_impl(buffered *self, PyObject *targetobj, int whence)
/*[clinic end generated code: output=7ae0e8dc46efdefb input=b5a12be70e0ad07b]*/
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
    if (target == -1 && PyErr_Occurred()) {
        return NULL;
    }

    // FIXME: Optimize seeking inside of buffer w/o flushing to disk then seeking.
    // HACK / TODO / FIXME / DEFINITELY FIX THIS
    /* SEEK_SET and SEEK_CUR are special because we could seek inside the
       buffer. Other whence values must be managed without this optimization.
       Some Operating Systems can provide additional values, like
       SEEK_HOLE/SEEK_DATA. */
#if 0
    if (((whence == 0) || (whence == 1)) && self->readable) {
        Py_off_t current, avail;
        /* Check if seeking leaves us inside the current buffer,
           so as to return quickly if possible. Also, we needn't take the
           lock in this fast path.
           Don't know how to do that when whence == 2, though. */
        /* NOTE: RAW_TELL() can release the GIL but the object is in a stable
           state at this point. */
        current = RAW_TELL(self);
        avail = READAHEAD(self);
        if (avail > 0) {
            Py_off_t offset;
            if (whence == 0)
                offset = target - (current - RAW_OFFSET(self));
            else
                offset = target;
            if (offset >= -self->pos && offset <= avail) {
                self->pos += offset;

                // GH-95782
                if (current - avail + offset < 0)
                    return PyLong_FromOff_t(0);

                return PyLong_FromOff_t(current - avail + offset);
            }
        }
    }
#endif

    if (!ENTER_BUFFERED(self)) {
        return NULL;
    }

    /* slow path: empty all buffers and raw seek() */
    if (buffered_flush_and_rewind_unlocked(self) == -1) {
        LEAVE_BUFFERED(self);
        return NULL;
    }

    assert(!self->read_buffer);
    n = _buffered_raw_seek(self, target, whence);
    if (n != -1) {
        res = PyLong_FromOff_t(n);
    }

    LEAVE_BUFFERED(self)
    return res;
}

/*[clinic input]
@critical_section
_io._Buffered.truncate
    cls: defining_class
    pos: object = None
    /
[clinic start generated code]*/

static PyObject *
_io__Buffered_truncate_impl(buffered *self, PyTypeObject *cls, PyObject *pos)
/*[clinic end generated code: output=fe3882fbffe79f1a input=e3cbf794575bd794]*/
{
    PyObject *res = NULL;

    CHECK_INITIALIZED(self)
    CHECK_CLOSED(self, "truncate of closed file")
    if (!self->writable) {
        _PyIO_State *state = get_io_state_by_cls(cls);
        return bufferediobase_unsupported(state, "truncate");
    }
    if (!ENTER_BUFFERED(self)) {
        return NULL;
    }

    if (buffered_flush_and_rewind_unlocked(self) == -1) {
        LEAVE_BUFFERED(self)
        return NULL;
    }
    Py_CLEAR(res);

    res = PyObject_CallMethodOneArg(self->raw, &_Py_ID(truncate), pos);

    LEAVE_BUFFERED(self);
    return res;
}

static PyObject *
buffered_iternext(PyObject *op)
{
    buffered *self = buffered_CAST(op);
    PyObject *line;
    PyTypeObject *tp;

    CHECK_INITIALIZED(self);

    // FIXME: How cost effective are these type checks w/ modern interpreter?
    _PyIO_State *state = find_io_state_by_def(Py_TYPE(self));
    tp = Py_TYPE(self);
    if (Py_IS_TYPE(tp, state->PyBufferedReader_Type) ||
        Py_IS_TYPE(tp, state->PyBufferedRandom_Type))
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

static void _buffered_reset_buf(buffered *self)
{
    Py_CLEAR(self->read_buffer);
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
    self->ok = 0;
    self->detached = 0;

    _PyIO_State *state = find_io_state_by_def(Py_TYPE(self));
    if (_PyIOBase_check_readable(state, raw, Py_True) == NULL) {
        return -1;
    }

    Py_XSETREF(self->raw, Py_NewRef(raw));
    self->buffer_size = buffer_size;
    self->readable = 1;
    self->writable = 0;

    if (_buffered_init(self) < 0)
        return -1;

    self->fast_closed_checks = (
        Py_IS_TYPE(self, state->PyBufferedReader_Type) &&
        Py_IS_TYPE(raw, state->PyFileIO_Type)
    );

    self->ok = 1;
    return 0;
}

static Py_ssize_t
_bufferedreader_raw_read(buffered *self, char *start, Py_ssize_t len)
{
    Py_buffer buf;
    PyObject *memobj, *res;
    Py_ssize_t n;
    /* NOTE: the buffer needn't be released as its object is NULL. */
    if (PyBuffer_FillInfo(&buf, NULL, start, len, 0, PyBUF_CONTIG) == -1) {
        return -1;
    }
    // FIXME: If the memoryview lives on, should this return NULL / don't let
    // modifiable bytes live into the wild?
    memobj = PyMemoryView_FromBuffer(&buf);
    if (memobj == NULL) {
        return -1;
    }
    /* NOTE: PyErr_SetFromErrno() calls PyErr_CheckSignals() when EINTR
       occurs so we needn't do it ourselves.
       We then retry reading, ignoring the signal if no handler has
       raised (see issue #10956).
    */
    do {
        res = PyObject_CallMethodOneArg(self->raw, &_Py_ID(readinto), memobj);
    } while (res == NULL && _PyIO_trap_eintr());
    Py_DECREF(memobj);
    if (res == NULL) {
        return -1;
    }
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

static Py_ssize_t
_bufferedreader_fill_buffer(buffered *self)
{
    // Read buffer should be empty.
    assert (self->read_buffer == NULL);
    Py_ssize_t buffer_size = self->buffer_size;
    // FIXME(cmaloney): This should probably go away, or be the place that
    // always tests for it?
    if (buffer_size == 0) {
        buffer_size = DEFAULT_BUFFER_SIZE;
    }
    PyBytesWriter *writer = PyBytesWriter_Create(buffer_size);
    if (!writer) {
        return -1;
    }

    // FIXME(cmaloney): This exports a temporary buffer that could have a
    // reference escape (leading to a pointer to deallocated space).
    Py_ssize_t n = _bufferedreader_raw_read(self,
            PyBytesWriter_GetData(writer), buffer_size);

    if (n <= 0) {
        PyBytesWriter_Discard(writer);
        return n;
    }
    self->read_buffer = PyBytesWriter_FinishWithSize(writer, n);
    if (self->read_buffer == NULL) {
        return -1;
    }
    return n;
}

static PyObject *
_bufferedreader_raw_readall(buffered *self) {
    PyObject *raw_readall = NULL;
    if (PyObject_GetOptionalAttr(self->raw, &_Py_ID(readall), &raw_readall) <= 0) {
        return NULL;
    }

    assert(raw_readall);
    PyObject *res = _PyObject_CallNoArgs(raw_readall);
    Py_DECREF(raw_readall);
    if (res == NULL) {
        return NULL;
    }

    // FIXME: The "prepend self->readbuffer" should move to a wrapper function.
    //       for both the None and "got bytes" cases.

    /* Blocked but may already have data, return already read data. */
    if (res == Py_None) {
        if (self->read_buffer) {
            res = Py_NewRef(self->read_buffer);
            Py_CLEAR(self->read_buffer);
        }
        return res;
    }

    /* Readall is expected to return bytes. */
    if (!PyBytes_Check(res)) {
        PyErr_SetString(PyExc_TypeError, "readall() should return bytes");
        Py_DECREF(res);
        return NULL;
    }

    /* Combine read buffer with readall result. */
    if (self->read_buffer) {
        // FIXME(cmaloney): This whole function should probably take read_buffer
        // at the start / make it thread local.
        PyBytes_ConcatAndDel(&self->read_buffer, res);
        if (self->read_buffer == NULL) {
            assert(PyErr_Occurred());
            return NULL;
        }
        res = self->read_buffer;
        self->read_buffer = NULL;
    }
    return res;
}


static PyObject *
_bufferedreader_read_all(buffered *self)
{

    /* Ensure no unwritten data. */
    if (_bufferedwriter_flush_unlocked(self) == -1) {
        return NULL;
    }

    /* Use underlying readall if available. */
    PyObject *readall_result = _bufferedreader_raw_readall(self);
    if (readall_result) {
        return readall_result;
    }
    else if (PyErr_Occurred()) {
        return NULL;
    }

    PyObject *chunks = PyList_New(0);
    if (chunks == NULL) {
        return NULL;
    }

    PyObject *data = self->read_buffer;
    self->read_buffer = NULL;

    while (1) {
        if (data) {
            /* all chunks must have at least one byte. */
            assert(PyBytes_GET_SIZE(data) > 0);
            if (PyList_Append(chunks, data) < 0) {
                Py_CLEAR(data);
                break;
            }
            Py_CLEAR(data);
        }

        // FIXME(cmaloney): This should non-linearly resize the buffer, see
        // FileIO.readall for more details.
        /* Read until EOF or until read() would block. */
        data = PyObject_CallMethodNoArgs(self->raw, &_Py_ID(read));
        if (data == NULL) {
            assert(PyErr_Occurred());
            break;
        }
        if (data != Py_None && !PyBytes_Check(data)) {
            PyErr_SetString(PyExc_TypeError, "read() should return bytes");
            Py_CLEAR(data);
            break;
        }

        /* EOF or would block */
        if (data == Py_None || PyBytes_GET_SIZE(data) == 0) {
            if (PyList_Size(chunks) == 0) {
                break;
            }

            Py_SETREF(data, PyBytes_Join(bytes_get_empty(), chunks));
            break;
        }
    }

    Py_DECREF(chunks);
    return data;
}



/* Read n bytes from the buffer if it can, otherwise return None.
   FIXME:
   This function is simple enough that it can run unlocked. */
static PyObject *
_bufferedreader_read_fast(buffered *self, Py_ssize_t requested)
{
    // readall / negative should be handled by caller.
    assert(requested >= 0);

    if (self->read_buffer == NULL) {
        // No bytes available
        if (requested == 0) {
            return bytes_get_empty();
        }
        // More requested than available.
        return Py_None;
    }

    Py_ssize_t current_size = PyBytes_GET_SIZE(self->read_buffer);
    if (requested > current_size) {
        return Py_None;
    }

    // FIXME: This should probably be an atomic pointer swap.
    if (requested == current_size) {
        PyObject *res = self->read_buffer;
        // FIXME(cmaloney): Not sure this is right ref counting...
        Py_INCREF(res);
        Py_CLEAR(self->read_buffer);
        return res;
    }

    /* Return exactly as many bytes as requested.

       res, read_buffer = self->read_buffer[:n], self->read_buffer[n:] */
    // FIXME(cmaloney): Would be nice to take the head of read_buffer without a
    // memcpy. Maybe eventually can use bytearray...
    PyObject *res = PyBytes_FromStringAndSize(PyBytes_AS_STRING(self->read_buffer), requested);
    if (res == NULL) {
        return NULL;
    }
    if (buffered_shrink_read_buffer(self, requested) == -1) {
        Py_CLEAR(res);
        return NULL;
    }
    return res;
}

/* Generic read function: read from the stream until enough bytes are read,
 * or until an EOF occurs or until read() would block.
 */
static PyObject *
_bufferedreader_read_generic(buffered *self, Py_ssize_t size)
{
    // Have all the bytes, fast copy out. Note, handling this outside of
    // _readinto_generic, since if read_buffer already has the right data, don't
    // want to memcpy.
    PyObject *res = _bufferedreader_read_fast(self, size);
    if (res == NULL || !Py_IsNone(res)) {
        return res;
    }
    Py_CLEAR(res);

    // FIXME: This is very, very similar to fill_buffer, just allocating
    // for itself...
    /* Create a contiguous buffer and readinto it. */
    PyBytesWriter *writer = PyBytesWriter_Create(size);
    if (writer == NULL) {
        return NULL;
    }
    char *out = PyBytesWriter_GetData(writer);
    Py_buffer buf;
    // FIXME(cmaloney): Exporty to this buffer could escape in arbitrary
    // readinto code.
    if (PyBuffer_FillInfo(&buf, NULL, out, size, 0, PyBUF_CONTIG) == -1) {
        PyBytesWriter_Discard(writer);
        return NULL;
    }

    /* NOTE: the buffer needn't be released as its object is NULL. */
    res = _buffered_readinto_generic(self, &buf, 0);
    if (res == NULL) {
        PyBytesWriter_Discard(writer);
        return NULL;
    }
    /* Blocked with no data. */
    else if (Py_IsNone(res)) {
        PyBytesWriter_Discard(writer);
        return res;
    }

    Py_ssize_t actual = PyLong_AsSize_t(res);
    if (actual == -1 && PyErr_Occurred()) {
        PyBytesWriter_Discard(writer);
        return NULL;
    }

    return PyBytesWriter_FinishWithSize(writer, actual);
}

static PyObject *
_bufferedreader_peek_unlocked(buffered *self)
{
    Py_ssize_t r;
    // Already have bytes.
    if (self->read_buffer) {
        Py_INCREF(self->read_buffer);
        return self->read_buffer;
    }

    /* Fill the buffer from the raw stream, and copy it to the result. */
    r = _bufferedreader_fill_buffer(self);
    if (r == -1) {
        return NULL;
    }
    if (r == -2 || r == 0) {
        return bytes_get_empty();
    }
    assert(self->read_buffer != NULL);
    Py_INCREF(self->read_buffer);
    return self->read_buffer;
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
    self->ok = 0;
    self->detached = 0;

    _PyIO_State *state = find_io_state_by_def(Py_TYPE(self));
    if (_PyIOBase_check_writable(state, raw, Py_True) == NULL) {
        return -1;
    }

    Py_INCREF(raw);
    Py_XSETREF(self->raw, raw);
    self->readable = 0;
    self->writable = 1;

    self->buffer_size = buffer_size;
    if (_buffered_init(self) < 0)
        return -1;

    self->fast_closed_checks = (
        Py_IS_TYPE(self, state->PyBufferedWriter_Type) &&
        Py_IS_TYPE(raw, state->PyFileIO_Type)
    );

    self->ok = 1;
    return 0;
}

// FIXME(cmaloney): This should take a Py_buffer
static Py_ssize_t
_bufferedwriter_raw_write(buffered *self, char *start, Py_ssize_t len)
{
    Py_buffer buf;
    PyObject *memobj, *res;
    Py_ssize_t n;
    int errnum;
    /* NOTE: the buffer needn't be released as its object is NULL. */
    if (PyBuffer_FillInfo(&buf, NULL, start, len, 1, PyBUF_CONTIG_RO) == -1) {
        return -1;
    }
    memobj = PyMemoryView_FromBuffer(&buf);
    if (memobj == NULL) {
        return -1;
    }
    /* NOTE: PyErr_SetFromErrno() calls PyErr_CheckSignals() when EINTR
       occurs so we needn't do it ourselves.
       We then retry writing, ignoring the signal if no handler has
       raised (see issue #10956).
    */
    do {
        errno = 0;
        res = PyObject_CallMethodOneArg(self->raw, &_Py_ID(write), memobj);
        errnum = errno;
    } while (res == NULL && _PyIO_trap_eintr());
    Py_DECREF(memobj);
    if (res == NULL) {
        return -1;
    }
    if (res == Py_None) {
        /* Non-blocking stream would have blocked. Special return code!
           Being paranoid we reset errno in case it is changed by code
           triggered by a decref.  errno is used by _set_BlockingIOError(). */
        Py_DECREF(res);
        errno = errnum;
        return -2;
    }
    n = PyNumber_AsSsize_t(res, PyExc_ValueError);
    Py_DECREF(res);
    if (n < 0 || n > len) {
        PyErr_Format(PyExc_OSError,
                     "raw write() returned invalid length %zd "
                     "(should have been between 0 and %zd)", n, len);
        return -1;
    }
    return n;
}

// Append the given bytes to the write buffer.
static int _buffered_add_to_write_buffer(buffered *self, PyObject *new_bytes) {
    // TODO(cmaloney): Relax this to allow bytes-like.
    // Can save significant copies that way (at the cost of held references potentially).
    assert(PyBytes_CheckExact(new_bytes));

    if (self->write_buffer == NULL) {
        self->write_buffer = new_bytes;
        return 0;
    }

    if (PyBytes_CheckExact(self->write_buffer)) {
        // Make a list, append.
        PyObject *list = PyList_New(2);
        if (list == NULL) {
            Py_DECREF(new_bytes);
            return -1;
        }
        PyList_SET_ITEM(list, 0, self->write_buffer);
        PyList_SET_ITEM(list, 1, new_bytes);
        self->write_buffer = list;
        return 0;
    }

    assert(PyList_CheckExact(self->write_buffer));

    if (PyList_Append(self->write_buffer, new_bytes) < 0) {
        Py_DECREF(new_bytes);
        return -1;
    }
    Py_DECREF(new_bytes);
    return 0;
}

// FIXME(cmaloney): This shold take a Py_buffer...
static Py_ssize_t
_bufferedwriter_write_retrying(buffered *self, char *buffer, Py_ssize_t len, int add_to_buffer) {
    Py_ssize_t written = 0;
    Py_ssize_t n = 0;
    while (true) {
        n = _bufferedwriter_raw_write(self,
            buffer,
            len - written);
        if (n == -1) {
            return -1;
        }
        else if (n == -2) {
            /* FIXME(cmaloney): The data is already in memory and could just keep a memoryview on the bytes...

                That also saves the allocation and copy...
            */
            /* Buffer as much as possible. */
            if (add_to_buffer) {
                Py_ssize_t saved = Py_MIN(len - written, self->buffer_size);
                PyObject *new_bytes = PyBytes_FromStringAndSize(buffer, saved);
                // Couldn't save new bytes, abandon.
                if (new_bytes == NULL) {
                    PyErr_Clear();
                }
                else {
                    if (_buffered_add_to_write_buffer(self, new_bytes) == -1) {
                        PyErr_Clear();
                        Py_CLEAR(new_bytes);
                    }
                    else {
                        written += saved;
                    }
                }
            }

            _set_BlockingIOError("write could not complete without blocking",
                                 written);
            return -1;
        }

        written += n;
        assert(written <= len);
        if (written >= len) {
            return written;
        }

        // Advance in buffer
        buffer += n;

        // FIXME: This looses written length.
        /* Partial writes can return successfully when interrupted by a
           signal (see write(2)).  We must run signal handlers before
           blocking another time, possibly indefinitely. */
        if (PyErr_CheckSignals() < 0) {
            // FIXME(cmaloney): This shold likely return size and ensure error
            // is set.
            return -1;
        }
    }
}

static Py_ssize_t
_bufferedwriter_flush_write_chunk(buffered *self, PyObject *buffer) {
    // FIXME(cmaloney): Relax to allow bytes-like
    assert(PyBytes_CheckExact(buffer));

    Py_ssize_t size = PyBytes_GET_SIZE(buffer);
    char *buffer_bytes = PyBytes_AS_STRING(buffer);
    Py_ssize_t n = _bufferedwriter_write_retrying(self, buffer_bytes, size, 0);
    if (n == -1) {
        // FIXME(cmaloney): Remove actually written bytes from the cache?
        assert(PyErr_Occurred());
        return -1;
    }
    assert(n <= size);
    // FIXME: I don't think this is relevant anymore.
    /* This ensures that after return from this function,
    VALID_WRITE_BUFFER(self) returns false.

    This is a required condition because when a tell() is called
    after flushing and if VALID_READ_BUFFER(self) is false, we need
    VALID_WRITE_BUFFER(self) to be false to have
    RAW_OFFSET(self) == 0.

    Issue: https://bugs.python.org/issue32228 */
    return size - n;
}

/* Ensure all write buffering is empty.

   FIXME: Use this again when start buffering writes. For now leaving in
   callsites because they've often been added via bugs.

   0 == success,
   -1 == error
*/
static Py_ssize_t
_bufferedwriter_flush_unlocked(buffered *self)
{
    if (self->write_buffer == NULL) {
        return 0;
    }

    // If there's a list of buffers, coalesce them.
    // TODO(cmaloney): Fast path by using `writev` to write without any copies.
    // FIXME(cmaloney): Testing currently asserts one write / coalesced. Is that
    // actually best?
    if (PyList_CheckExact(self->write_buffer)) {
        PyObject *new_buffer = PyObject_CallMethodOneArg(
            Py_GetConstant(Py_CONSTANT_EMPTY_BYTES), &_Py_ID(join), self->write_buffer);
        if (new_buffer == NULL) {
            return -1;
        }
        Py_SETREF(self->write_buffer, new_buffer);
    }

    // Single buffer to write.
    // FIXME(cmaloney): Evaluate cost of having this always be a list.
    assert(PyBytes_CheckExact(self->write_buffer));

    Py_ssize_t res = _bufferedwriter_flush_write_chunk(self, self->write_buffer);
    if (res == -1) {
        return -1;
    }
    if (res == 0) {
        Py_CLEAR(self->write_buffer);
        return 0;
    }
    // FIXME(cmaloney): Use a buffer object here...
    // Partial write, stash back what remains.
    Py_ssize_t write_buffer_len = PyBytes_GET_SIZE(self->write_buffer);
    PyObject *leftover = PyBytes_FromStringAndSize(PyBytes_AS_STRING(self->write_buffer) + res, write_buffer_len - res);
    Py_CLEAR(self->write_buffer);
    if (leftover == NULL) {
        return -1;
    }
    self->write_buffer = leftover;
    return 0;
}


/*[clinic input]
@critical_section
_io.BufferedWriter.write
    buffer: Py_buffer
    /
[clinic start generated code]*/

static PyObject *
_io_BufferedWriter_write_impl(buffered *self, Py_buffer *buffer)
/*[clinic end generated code: output=7f8d1365759bfc6b input=6a9c041de0c337be]*/
{
    // FIXME: Should write guarantee it holds all bytes it was called with?
    // THEORY: It owns the length of bytes it returns from write. In standard
    // operation that _should_ be all. Only case it isn't is if OOM.

    CHECK_INITIALIZED(self)

    if (!ENTER_BUFFERED(self)) {
        return NULL;
    }

    /* Issue #31976: Check for closed file after acquiring the lock. Another
       thread could be holding the lock while closing the file. */
    if (IS_CLOSED(self)) {
        PyErr_SetString(PyExc_ValueError, "write to closed file");
        LEAVE_BUFFERED(self);
        return NULL;
    }

    // If the buffered has read some data, the actual position of the underlying
    // stream and the "percieved" position differ. Move them back into alignment.
    // FIXME(cmaloney): this should likely become a helper...
    if (self->read_buffer) {
        /* Rewind the raw stream so that its position corresponds to
           the current logical position. */
        Py_ssize_t n = _buffered_raw_seek(self, -PyBytes_GET_SIZE(self->read_buffer), SEEK_CUR);
        if (n == -1) {
            return NULL;
        }
        _buffered_reset_buf(self);
    }

    // TODO(cmaloney): This is all the same logic as TextIOWrapper write
    // around self->pending_bytes;
    /* Fast path: Just a write loop, no copying for big writes.

       NOTE: includes buffer_size == 0 (buffer->len is >= 0 always)*/
    if (buffer->len >= self->buffer_size) {
        if (_bufferedwriter_flush_unlocked(self) == -1) {
            LEAVE_BUFFERED(self);
            return NULL;
        }

        Py_ssize_t written = _bufferedwriter_write_retrying(self, buffer->buf, buffer->len, 1);
        LEAVE_BUFFERED(self);
        if (PyErr_Occurred()) {
            return NULL;
        }
        return PyLong_FromSsize_t(written);
    }

    /* Copy into the buffer. */
    // Always append to the list
    // FIXME(cmaloney): don't want to allocate a new buffer here ever...
    // FIXME(cmaloney): Much copy is bad.
    PyObject *new_bytes = PyBytes_FromStringAndSize(buffer->buf, buffer->len);
    if (new_bytes == NULL) {
        return NULL;
    }

    if (_buffered_add_to_write_buffer(self, new_bytes) == -1) {
        Py_DECREF(new_bytes);
        LEAVE_BUFFERED(self);
        return NULL;
    }

    if (_buffered_get_write_buffer_size(self) > self->buffer_size) {
        if (_bufferedwriter_flush_unlocked(self) == -1) {
            LEAVE_BUFFERED(self);
            return NULL;
        }
    }

    LEAVE_BUFFERED(self);

    return PyLong_FromSsize_t(buffer->len);
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
    if (_PyIOBase_check_readable(state, reader, Py_True) == NULL) {
        return -1;
    }
    if (_PyIOBase_check_writable(state, writer, Py_True) == NULL) {
        return -1;
    }

    self->reader = (buffered *) PyObject_CallFunction(
            (PyObject *)state->PyBufferedReader_Type,
            "On", reader, buffer_size);
    if (self->reader == NULL)
        return -1;

    self->writer = (buffered *) PyObject_CallFunction(
            (PyObject *)state->PyBufferedWriter_Type,
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
    self->ok = 0;
    self->detached = 0;

    _PyIO_State *state = find_io_state_by_def(Py_TYPE(self));
    if (_PyIOBase_check_seekable(state, raw, Py_True) == NULL) {
        return -1;
    }
    if (_PyIOBase_check_readable(state, raw, Py_True) == NULL) {
        return -1;
    }
    if (_PyIOBase_check_writable(state, raw, Py_True) == NULL) {
        return -1;
    }

    if (buffer_size < 0) {
        PyErr_SetString(PyExc_ValueError, "");
    }

    Py_INCREF(raw);
    Py_XSETREF(self->raw, raw);
    self->buffer_size = buffer_size;
    self->readable = 1;
    self->writable = 1;

    if (_buffered_init(self) < 0) {
        return -1;
    }

    self->fast_closed_checks = (Py_IS_TYPE(self, state->PyBufferedRandom_Type) &&
                                Py_IS_TYPE(raw, state->PyFileIO_Type));

    self->ok = 1;
    return 0;
}

#define clinic_state() (find_io_state_by_def(Py_TYPE(self)))
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
PyType_Spec bufferediobase_spec = {
    .name = "_io._BufferedIOBase",
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

PyType_Spec bufferedreader_spec = {
    .name = "_io.BufferedReader",
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

PyType_Spec bufferedwriter_spec = {
    .name = "_io.BufferedWriter",
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

PyType_Spec bufferedrwpair_spec = {
    .name = "_io.BufferedRWPair",
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

PyType_Spec bufferedrandom_spec = {
    .name = "_io.BufferedRandom",
    .basicsize = sizeof(buffered),
    .flags = (Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC |
              Py_TPFLAGS_IMMUTABLETYPE),
    .slots = bufferedrandom_slots,
};

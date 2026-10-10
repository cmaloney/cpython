/*[clinic input]
preserve
[clinic start generated code]*/

#if defined(Py_BUILD_CORE) && !defined(Py_BUILD_CORE_MODULE)
#  include "pycore_gc.h"          // PyGC_Head
#  include "pycore_runtime.h"     // _Py_ID()
#endif
#include "pycore_abstract.h"      // _PyNumber_Index()
#include "pycore_modsupport.h"    // _PyArg_CheckPositional()

PyDoc_STRVAR(_io__Buffered___sizeof____doc__,
"__sizeof__($self, /)\n"
"--\n"
"\n");

#define _IO__BUFFERED___SIZEOF___METHODDEF    \
    {"__sizeof__", (PyCFunction)_io__Buffered___sizeof__, METH_NOARGS, _io__Buffered___sizeof____doc__},

static PyObject *
_io__Buffered___sizeof___impl(buffered *self);

static PyObject *
_io__Buffered___sizeof__(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return _io__Buffered___sizeof___impl((buffered *)self);
}

PyDoc_STRVAR(_io__Buffered__dealloc_warn__doc__,
"_dealloc_warn($self, source, /)\n"
"--\n"
"\n");

#define _IO__BUFFERED__DEALLOC_WARN_METHODDEF    \
    {"_dealloc_warn", (PyCFunction)_io__Buffered__dealloc_warn, METH_O, _io__Buffered__dealloc_warn__doc__},

static PyObject *
_io__Buffered__dealloc_warn_impl(buffered *self, PyObject *source);

static PyObject *
_io__Buffered__dealloc_warn(PyObject *self, PyObject *source)
{
    PyObject *return_value = NULL;

    return_value = _io__Buffered__dealloc_warn_impl((buffered *)self, source);

    return return_value;
}

PyDoc_STRVAR(_io__Buffered__discard_writes__doc__,
"_discard_writes($self, /)\n"
"--\n"
"\n"
"Drop the pending writes; return how many bytes they were.\n"
"\n"
"TextIOWrapper.close() calls this when its flush failed, so that the\n"
"close() of its buffer doesn\'t try to write them again.");

#define _IO__BUFFERED__DISCARD_WRITES_METHODDEF    \
    {"_discard_writes", (PyCFunction)_io__Buffered__discard_writes, METH_NOARGS, _io__Buffered__discard_writes__doc__},

static PyObject *
_io__Buffered__discard_writes_impl(buffered *self);

static PyObject *
_io__Buffered__discard_writes(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return _io__Buffered__discard_writes_impl((buffered *)self);
}

PyDoc_STRVAR(_io__Buffered_simple_flush__doc__,
"flush($self, /)\n"
"--\n"
"\n");

#define _IO__BUFFERED_SIMPLE_FLUSH_METHODDEF    \
    {"flush", (PyCFunction)_io__Buffered_simple_flush, METH_NOARGS, _io__Buffered_simple_flush__doc__},

static PyObject *
_io__Buffered_simple_flush_impl(buffered *self);

static PyObject *
_io__Buffered_simple_flush(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return _io__Buffered_simple_flush_impl((buffered *)self);
}

static PyObject *
_io__Buffered_closed_get_impl(buffered *self);

static PyObject *
_io__Buffered_closed_get(PyObject *self, void *Py_UNUSED(context))
{
    return _io__Buffered_closed_get_impl((buffered *)self);
}

PyDoc_STRVAR(_io__Buffered_close__doc__,
"close($self, /)\n"
"--\n"
"\n");

#define _IO__BUFFERED_CLOSE_METHODDEF    \
    {"close", (PyCFunction)_io__Buffered_close, METH_NOARGS, _io__Buffered_close__doc__},

static PyObject *
_io__Buffered_close_impl(buffered *self);

static PyObject *
_io__Buffered_close(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return _io__Buffered_close_impl((buffered *)self);
}

PyDoc_STRVAR(_io__Buffered_detach__doc__,
"detach($self, /)\n"
"--\n"
"\n");

#define _IO__BUFFERED_DETACH_METHODDEF    \
    {"detach", (PyCFunction)_io__Buffered_detach, METH_NOARGS, _io__Buffered_detach__doc__},

static PyObject *
_io__Buffered_detach_impl(buffered *self);

static PyObject *
_io__Buffered_detach(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return _io__Buffered_detach_impl((buffered *)self);
}

PyDoc_STRVAR(_io__Buffered_seekable__doc__,
"seekable($self, /)\n"
"--\n"
"\n");

#define _IO__BUFFERED_SEEKABLE_METHODDEF    \
    {"seekable", (PyCFunction)_io__Buffered_seekable, METH_NOARGS, _io__Buffered_seekable__doc__},

static PyObject *
_io__Buffered_seekable_impl(buffered *self);

static PyObject *
_io__Buffered_seekable(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return _io__Buffered_seekable_impl((buffered *)self);
}

PyDoc_STRVAR(_io__Buffered_readable__doc__,
"readable($self, /)\n"
"--\n"
"\n");

#define _IO__BUFFERED_READABLE_METHODDEF    \
    {"readable", (PyCFunction)_io__Buffered_readable, METH_NOARGS, _io__Buffered_readable__doc__},

static PyObject *
_io__Buffered_readable_impl(buffered *self);

static PyObject *
_io__Buffered_readable(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return _io__Buffered_readable_impl((buffered *)self);
}

PyDoc_STRVAR(_io__Buffered_writable__doc__,
"writable($self, /)\n"
"--\n"
"\n");

#define _IO__BUFFERED_WRITABLE_METHODDEF    \
    {"writable", (PyCFunction)_io__Buffered_writable, METH_NOARGS, _io__Buffered_writable__doc__},

static PyObject *
_io__Buffered_writable_impl(buffered *self);

static PyObject *
_io__Buffered_writable(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return _io__Buffered_writable_impl((buffered *)self);
}

static PyObject *
_io__Buffered_name_get_impl(buffered *self);

static PyObject *
_io__Buffered_name_get(PyObject *self, void *Py_UNUSED(context))
{
    return _io__Buffered_name_get_impl((buffered *)self);
}

static PyObject *
_io__Buffered_mode_get_impl(buffered *self);

static PyObject *
_io__Buffered_mode_get(PyObject *self, void *Py_UNUSED(context))
{
    return _io__Buffered_mode_get_impl((buffered *)self);
}

PyDoc_STRVAR(_io__Buffered_fileno__doc__,
"fileno($self, /)\n"
"--\n"
"\n");

#define _IO__BUFFERED_FILENO_METHODDEF    \
    {"fileno", (PyCFunction)_io__Buffered_fileno, METH_NOARGS, _io__Buffered_fileno__doc__},

static PyObject *
_io__Buffered_fileno_impl(buffered *self);

static PyObject *
_io__Buffered_fileno(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return _io__Buffered_fileno_impl((buffered *)self);
}

PyDoc_STRVAR(_io__Buffered_isatty__doc__,
"isatty($self, /)\n"
"--\n"
"\n");

#define _IO__BUFFERED_ISATTY_METHODDEF    \
    {"isatty", (PyCFunction)_io__Buffered_isatty, METH_NOARGS, _io__Buffered_isatty__doc__},

static PyObject *
_io__Buffered_isatty_impl(buffered *self);

static PyObject *
_io__Buffered_isatty(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return _io__Buffered_isatty_impl((buffered *)self);
}

PyDoc_STRVAR(_io__Buffered_flush__doc__,
"flush($self, /)\n"
"--\n"
"\n");

#define _IO__BUFFERED_FLUSH_METHODDEF    \
    {"flush", (PyCFunction)_io__Buffered_flush, METH_NOARGS, _io__Buffered_flush__doc__},

static PyObject *
_io__Buffered_flush_impl(buffered *self);

static PyObject *
_io__Buffered_flush(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return _io__Buffered_flush_impl((buffered *)self);
}

PyDoc_STRVAR(_io__Buffered_peek__doc__,
"peek($self, size=0, /)\n"
"--\n"
"\n");

#define _IO__BUFFERED_PEEK_METHODDEF    \
    {"peek", _PyCFunction_CAST(_io__Buffered_peek), METH_FASTCALL, _io__Buffered_peek__doc__},

static PyObject *
_io__Buffered_peek_impl(buffered *self, Py_ssize_t size);

static PyObject *
_io__Buffered_peek(PyObject *self, PyObject *const *args, Py_ssize_t nargs)
{
    PyObject *return_value = NULL;
    Py_ssize_t size = 0;

    if (!_PyArg_CheckPositional("peek", nargs, 0, 1)) {
        goto exit;
    }
    if (nargs < 1) {
        goto skip_optional;
    }
    {
        Py_ssize_t ival = -1;
        PyObject *iobj = _PyNumber_Index(args[0]);
        if (iobj != NULL) {
            ival = PyLong_AsSsize_t(iobj);
            Py_DECREF(iobj);
        }
        if (ival == -1 && PyErr_Occurred()) {
            goto exit;
        }
        size = ival;
    }
skip_optional:
    return_value = _io__Buffered_peek_impl((buffered *)self, size);

exit:
    return return_value;
}

PyDoc_STRVAR(_io__Buffered_read__doc__,
"read($self, size=-1, /)\n"
"--\n"
"\n");

#define _IO__BUFFERED_READ_METHODDEF    \
    {"read", _PyCFunction_CAST(_io__Buffered_read), METH_FASTCALL, _io__Buffered_read__doc__},

static PyObject *
_io__Buffered_read_impl(buffered *self, Py_ssize_t n);

static PyObject *
_io__Buffered_read(PyObject *self, PyObject *const *args, Py_ssize_t nargs)
{
    PyObject *return_value = NULL;
    Py_ssize_t n = -1;

    if (!_PyArg_CheckPositional("read", nargs, 0, 1)) {
        goto exit;
    }
    if (nargs < 1) {
        goto skip_optional;
    }
    if (!_Py_convert_optional_to_ssize_t(args[0], &n)) {
        goto exit;
    }
skip_optional:
    return_value = _io__Buffered_read_impl((buffered *)self, n);

exit:
    return return_value;
}

PyDoc_STRVAR(_io__Buffered_readall__doc__,
"readall($self, /)\n"
"--\n"
"\n"
"Read until EOF, like read() with no size.");

#define _IO__BUFFERED_READALL_METHODDEF    \
    {"readall", (PyCFunction)_io__Buffered_readall, METH_NOARGS, _io__Buffered_readall__doc__},

static PyObject *
_io__Buffered_readall_impl(buffered *self);

static PyObject *
_io__Buffered_readall(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return _io__Buffered_readall_impl((buffered *)self);
}

PyDoc_STRVAR(_io__Buffered_read1__doc__,
"read1($self, size=-1, /)\n"
"--\n"
"\n");

#define _IO__BUFFERED_READ1_METHODDEF    \
    {"read1", _PyCFunction_CAST(_io__Buffered_read1), METH_FASTCALL, _io__Buffered_read1__doc__},

static PyObject *
_io__Buffered_read1_impl(buffered *self, Py_ssize_t n);

static PyObject *
_io__Buffered_read1(PyObject *self, PyObject *const *args, Py_ssize_t nargs)
{
    PyObject *return_value = NULL;
    Py_ssize_t n = -1;

    if (!_PyArg_CheckPositional("read1", nargs, 0, 1)) {
        goto exit;
    }
    if (nargs < 1) {
        goto skip_optional;
    }
    {
        Py_ssize_t ival = -1;
        PyObject *iobj = _PyNumber_Index(args[0]);
        if (iobj != NULL) {
            ival = PyLong_AsSsize_t(iobj);
            Py_DECREF(iobj);
        }
        if (ival == -1 && PyErr_Occurred()) {
            goto exit;
        }
        n = ival;
    }
skip_optional:
    return_value = _io__Buffered_read1_impl((buffered *)self, n);

exit:
    return return_value;
}

PyDoc_STRVAR(_io__Buffered_readinto__doc__,
"readinto($self, buffer, /)\n"
"--\n"
"\n");

#define _IO__BUFFERED_READINTO_METHODDEF    \
    {"readinto", (PyCFunction)_io__Buffered_readinto, METH_O, _io__Buffered_readinto__doc__},

static PyObject *
_io__Buffered_readinto_impl(buffered *self, Py_buffer *buffer);

static PyObject *
_io__Buffered_readinto(PyObject *self, PyObject *arg)
{
    PyObject *return_value = NULL;
    Py_buffer buffer = {NULL, NULL};

    if (PyObject_GetBuffer(arg, &buffer, PyBUF_WRITABLE) < 0) {
        _PyArg_BadArgument("readinto", "argument", "read-write bytes-like object", arg);
        goto exit;
    }
    return_value = _io__Buffered_readinto_impl((buffered *)self, &buffer);

exit:
    /* Cleanup for buffer */
    if (buffer.obj) {
       PyBuffer_Release(&buffer);
    }

    return return_value;
}

PyDoc_STRVAR(_io__Buffered_readinto1__doc__,
"readinto1($self, buffer, /)\n"
"--\n"
"\n");

#define _IO__BUFFERED_READINTO1_METHODDEF    \
    {"readinto1", (PyCFunction)_io__Buffered_readinto1, METH_O, _io__Buffered_readinto1__doc__},

static PyObject *
_io__Buffered_readinto1_impl(buffered *self, Py_buffer *buffer);

static PyObject *
_io__Buffered_readinto1(PyObject *self, PyObject *arg)
{
    PyObject *return_value = NULL;
    Py_buffer buffer = {NULL, NULL};

    if (PyObject_GetBuffer(arg, &buffer, PyBUF_WRITABLE) < 0) {
        _PyArg_BadArgument("readinto1", "argument", "read-write bytes-like object", arg);
        goto exit;
    }
    return_value = _io__Buffered_readinto1_impl((buffered *)self, &buffer);

exit:
    /* Cleanup for buffer */
    if (buffer.obj) {
       PyBuffer_Release(&buffer);
    }

    return return_value;
}

PyDoc_STRVAR(_io__Buffered_readline__doc__,
"readline($self, size=-1, /)\n"
"--\n"
"\n");

#define _IO__BUFFERED_READLINE_METHODDEF    \
    {"readline", _PyCFunction_CAST(_io__Buffered_readline), METH_FASTCALL, _io__Buffered_readline__doc__},

static PyObject *
_io__Buffered_readline_impl(buffered *self, Py_ssize_t size);

static PyObject *
_io__Buffered_readline(PyObject *self, PyObject *const *args, Py_ssize_t nargs)
{
    PyObject *return_value = NULL;
    Py_ssize_t size = -1;

    if (!_PyArg_CheckPositional("readline", nargs, 0, 1)) {
        goto exit;
    }
    if (nargs < 1) {
        goto skip_optional;
    }
    if (!_Py_convert_optional_to_ssize_t(args[0], &size)) {
        goto exit;
    }
skip_optional:
    return_value = _io__Buffered_readline_impl((buffered *)self, size);

exit:
    return return_value;
}

PyDoc_STRVAR(_io__Buffered_tell__doc__,
"tell($self, /)\n"
"--\n"
"\n");

#define _IO__BUFFERED_TELL_METHODDEF    \
    {"tell", (PyCFunction)_io__Buffered_tell, METH_NOARGS, _io__Buffered_tell__doc__},

static PyObject *
_io__Buffered_tell_impl(buffered *self);

static PyObject *
_io__Buffered_tell(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return _io__Buffered_tell_impl((buffered *)self);
}

PyDoc_STRVAR(_io__Buffered_seek__doc__,
"seek($self, target, whence=0, /)\n"
"--\n"
"\n");

#define _IO__BUFFERED_SEEK_METHODDEF    \
    {"seek", _PyCFunction_CAST(_io__Buffered_seek), METH_FASTCALL, _io__Buffered_seek__doc__},

static PyObject *
_io__Buffered_seek_impl(buffered *self, PyObject *targetobj, int whence);

static PyObject *
_io__Buffered_seek(PyObject *self, PyObject *const *args, Py_ssize_t nargs)
{
    PyObject *return_value = NULL;
    PyObject *targetobj;
    int whence = 0;

    if (!_PyArg_CheckPositional("seek", nargs, 1, 2)) {
        goto exit;
    }
    targetobj = args[0];
    if (nargs < 2) {
        goto skip_optional;
    }
    whence = PyLong_AsInt(args[1]);
    if (whence == -1 && PyErr_Occurred()) {
        goto exit;
    }
skip_optional:
    return_value = _io__Buffered_seek_impl((buffered *)self, targetobj, whence);

exit:
    return return_value;
}

PyDoc_STRVAR(_io__Buffered_truncate__doc__,
"truncate($self, pos=None, /)\n"
"--\n"
"\n");

#define _IO__BUFFERED_TRUNCATE_METHODDEF    \
    {"truncate", _PyCFunction_CAST(_io__Buffered_truncate), METH_METHOD|METH_FASTCALL|METH_KEYWORDS, _io__Buffered_truncate__doc__},

static PyObject *
_io__Buffered_truncate_impl(buffered *self, PyTypeObject *cls, PyObject *pos);

static PyObject *
_io__Buffered_truncate(PyObject *self, PyTypeObject *cls, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    PyObject *return_value = NULL;
    PyObject *pos = Py_None;

    if (!_PyArg_NoKwnames("truncate", kwnames)) {
        goto exit;
    }
    if (!_PyArg_CheckPositional("truncate", nargs, 0, 1)) {
        goto exit;
    }
    if (nargs < 1) {
        goto skip_optional;
    }
    pos = args[0];
skip_optional:
    return_value = _io__Buffered_truncate_impl((buffered *)self, cls, pos);

exit:
    return return_value;
}

PyDoc_STRVAR(_io_BufferedReader___init____doc__,
"BufferedReader(raw, buffer_size=DEFAULT_BUFFER_SIZE)\n"
"--\n"
"\n"
"Create a new buffered reader using the given readable raw IO object.");

static int
_io_BufferedReader___init___impl(buffered *self, PyObject *raw,
                                 Py_ssize_t buffer_size);

static int
_io_BufferedReader___init__(PyObject *self, PyObject *args, PyObject *kwargs)
{
    int return_value = -1;
    #if defined(Py_BUILD_CORE) && !defined(Py_BUILD_CORE_MODULE)

    #define NUM_KEYWORDS 2
    static struct {
        PyGC_Head _this_is_not_used;
        PyObject_VAR_HEAD
        Py_hash_t ob_hash;
        PyObject *ob_item[NUM_KEYWORDS];
    } _kwtuple = {
        .ob_base = PyVarObject_HEAD_INIT(&PyTuple_Type, NUM_KEYWORDS)
        .ob_hash = -1,
        .ob_item = { &_Py_ID(raw), &_Py_ID(buffer_size), },
    };
    #undef NUM_KEYWORDS
    #define KWTUPLE (&_kwtuple.ob_base.ob_base)

    #else  // !Py_BUILD_CORE
    #  define KWTUPLE NULL
    #endif  // !Py_BUILD_CORE

    static const char * const _keywords[] = {"raw", "buffer_size", NULL};
    static _PyArg_Parser _parser = {
        .keywords = _keywords,
        .fname = "BufferedReader",
        .kwtuple = KWTUPLE,
    };
    #undef KWTUPLE
    PyObject *argsbuf[2];
    PyObject * const *fastargs;
    Py_ssize_t nargs = PyTuple_GET_SIZE(args);
    Py_ssize_t noptargs = nargs + (kwargs ? PyDict_GET_SIZE(kwargs) : 0) - 1;
    PyObject *raw;
    Py_ssize_t buffer_size = DEFAULT_BUFFER_SIZE;

    fastargs = _PyArg_UnpackKeywords(_PyTuple_CAST(args)->ob_item, nargs, kwargs, NULL, &_parser,
            /*minpos*/ 1, /*maxpos*/ 2, /*minkw*/ 0, /*varpos*/ 0, argsbuf);
    if (!fastargs) {
        goto exit;
    }
    raw = fastargs[0];
    if (!noptargs) {
        goto skip_optional_pos;
    }
    {
        Py_ssize_t ival = -1;
        PyObject *iobj = _PyNumber_Index(fastargs[1]);
        if (iobj != NULL) {
            ival = PyLong_AsSsize_t(iobj);
            Py_DECREF(iobj);
        }
        if (ival == -1 && PyErr_Occurred()) {
            goto exit;
        }
        buffer_size = ival;
    }
skip_optional_pos:
    return_value = _io_BufferedReader___init___impl((buffered *)self, raw, buffer_size);

exit:
    return return_value;
}

PyDoc_STRVAR(_io_BufferedWriter___init____doc__,
"BufferedWriter(raw, buffer_size=DEFAULT_BUFFER_SIZE)\n"
"--\n"
"\n"
"A buffer for a writeable sequential RawIO object.\n"
"\n"
"The constructor creates a BufferedWriter for the given writeable raw\n"
"stream. If the buffer_size is not given, it defaults to\n"
"DEFAULT_BUFFER_SIZE.");

static int
_io_BufferedWriter___init___impl(buffered *self, PyObject *raw,
                                 Py_ssize_t buffer_size);

static int
_io_BufferedWriter___init__(PyObject *self, PyObject *args, PyObject *kwargs)
{
    int return_value = -1;
    #if defined(Py_BUILD_CORE) && !defined(Py_BUILD_CORE_MODULE)

    #define NUM_KEYWORDS 2
    static struct {
        PyGC_Head _this_is_not_used;
        PyObject_VAR_HEAD
        Py_hash_t ob_hash;
        PyObject *ob_item[NUM_KEYWORDS];
    } _kwtuple = {
        .ob_base = PyVarObject_HEAD_INIT(&PyTuple_Type, NUM_KEYWORDS)
        .ob_hash = -1,
        .ob_item = { &_Py_ID(raw), &_Py_ID(buffer_size), },
    };
    #undef NUM_KEYWORDS
    #define KWTUPLE (&_kwtuple.ob_base.ob_base)

    #else  // !Py_BUILD_CORE
    #  define KWTUPLE NULL
    #endif  // !Py_BUILD_CORE

    static const char * const _keywords[] = {"raw", "buffer_size", NULL};
    static _PyArg_Parser _parser = {
        .keywords = _keywords,
        .fname = "BufferedWriter",
        .kwtuple = KWTUPLE,
    };
    #undef KWTUPLE
    PyObject *argsbuf[2];
    PyObject * const *fastargs;
    Py_ssize_t nargs = PyTuple_GET_SIZE(args);
    Py_ssize_t noptargs = nargs + (kwargs ? PyDict_GET_SIZE(kwargs) : 0) - 1;
    PyObject *raw;
    Py_ssize_t buffer_size = DEFAULT_BUFFER_SIZE;

    fastargs = _PyArg_UnpackKeywords(_PyTuple_CAST(args)->ob_item, nargs, kwargs, NULL, &_parser,
            /*minpos*/ 1, /*maxpos*/ 2, /*minkw*/ 0, /*varpos*/ 0, argsbuf);
    if (!fastargs) {
        goto exit;
    }
    raw = fastargs[0];
    if (!noptargs) {
        goto skip_optional_pos;
    }
    {
        Py_ssize_t ival = -1;
        PyObject *iobj = _PyNumber_Index(fastargs[1]);
        if (iobj != NULL) {
            ival = PyLong_AsSsize_t(iobj);
            Py_DECREF(iobj);
        }
        if (ival == -1 && PyErr_Occurred()) {
            goto exit;
        }
        buffer_size = ival;
    }
skip_optional_pos:
    return_value = _io_BufferedWriter___init___impl((buffered *)self, raw, buffer_size);

exit:
    return return_value;
}

PyDoc_STRVAR(_io__Buffered_gather__doc__,
"gather($self, /, limit=20971520)\n"
"--\n"
"\n"
"Gather the writes of the current context in a with block.\n"
"\n"
"Returns a context manager.  Inside its with block, what the current\n"
"context (thread, or asyncio task) writes is kept apart, also past\n"
"the buffer size, and added to the buffered data in one piece when\n"
"the block ends, so that no other output gets in between.  Once the\n"
"block gathered limit bytes, they are added, and gathering goes on.\n"
"flush() inside the block takes effect at its end; reads, seek(),\n"
"truncate(), close() and detach() add what was gathered first.");

#define _IO__BUFFERED_GATHER_METHODDEF    \
    {"gather", _PyCFunction_CAST(_io__Buffered_gather), METH_FASTCALL|METH_KEYWORDS, _io__Buffered_gather__doc__},

static PyObject *
_io__Buffered_gather_impl(buffered *self, Py_ssize_t limit);

static PyObject *
_io__Buffered_gather(PyObject *self, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    PyObject *return_value = NULL;
    #if defined(Py_BUILD_CORE) && !defined(Py_BUILD_CORE_MODULE)

    #define NUM_KEYWORDS 1
    static struct {
        PyGC_Head _this_is_not_used;
        PyObject_VAR_HEAD
        Py_hash_t ob_hash;
        PyObject *ob_item[NUM_KEYWORDS];
    } _kwtuple = {
        .ob_base = PyVarObject_HEAD_INIT(&PyTuple_Type, NUM_KEYWORDS)
        .ob_hash = -1,
        .ob_item = { &_Py_ID(limit), },
    };
    #undef NUM_KEYWORDS
    #define KWTUPLE (&_kwtuple.ob_base.ob_base)

    #else  // !Py_BUILD_CORE
    #  define KWTUPLE NULL
    #endif  // !Py_BUILD_CORE

    static const char * const _keywords[] = {"limit", NULL};
    static _PyArg_Parser _parser = {
        .keywords = _keywords,
        .fname = "gather",
        .kwtuple = KWTUPLE,
    };
    #undef KWTUPLE
    PyObject *argsbuf[1];
    Py_ssize_t noptargs = nargs + (kwnames ? PyTuple_GET_SIZE(kwnames) : 0) - 0;
    Py_ssize_t limit = GATHER_LIMIT;

    args = _PyArg_UnpackKeywords(args, nargs, NULL, kwnames, &_parser,
            /*minpos*/ 0, /*maxpos*/ 1, /*minkw*/ 0, /*varpos*/ 0, argsbuf);
    if (!args) {
        goto exit;
    }
    if (!noptargs) {
        goto skip_optional_pos;
    }
    {
        Py_ssize_t ival = -1;
        PyObject *iobj = _PyNumber_Index(args[0]);
        if (iobj != NULL) {
            ival = PyLong_AsSsize_t(iobj);
            Py_DECREF(iobj);
        }
        if (ival == -1 && PyErr_Occurred()) {
            goto exit;
        }
        limit = ival;
    }
skip_optional_pos:
    return_value = _io__Buffered_gather_impl((buffered *)self, limit);

exit:
    return return_value;
}

PyDoc_STRVAR(_io_BufferedWriter_readall__doc__,
"readall($self, /)\n"
"--\n"
"\n"
"Not supported: a BufferedWriter can\'t read.");

#define _IO_BUFFEREDWRITER_READALL_METHODDEF    \
    {"readall", (PyCFunction)_io_BufferedWriter_readall, METH_NOARGS, _io_BufferedWriter_readall__doc__},

static PyObject *
_io_BufferedWriter_readall_impl(buffered *self);

static PyObject *
_io_BufferedWriter_readall(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return _io_BufferedWriter_readall_impl((buffered *)self);
}

PyDoc_STRVAR(_io_BufferedWriter_write__doc__,
"write($self, buffer, /)\n"
"--\n"
"\n");

#define _IO_BUFFEREDWRITER_WRITE_METHODDEF    \
    {"write", (PyCFunction)_io_BufferedWriter_write, METH_O, _io_BufferedWriter_write__doc__},

static PyObject *
_io_BufferedWriter_write_impl(buffered *self, PyObject *obj);

static PyObject *
_io_BufferedWriter_write(PyObject *self, PyObject *obj)
{
    PyObject *return_value = NULL;

    return_value = _io_BufferedWriter_write_impl((buffered *)self, obj);

    return return_value;
}

PyDoc_STRVAR(_io_BufferedRandom___init____doc__,
"BufferedRandom(raw, buffer_size=DEFAULT_BUFFER_SIZE)\n"
"--\n"
"\n"
"A buffered interface to random access streams.\n"
"\n"
"The constructor creates a reader and writer for a seekable stream,\n"
"raw, given in the first argument. If the buffer_size is omitted it\n"
"defaults to DEFAULT_BUFFER_SIZE.");

static int
_io_BufferedRandom___init___impl(buffered *self, PyObject *raw,
                                 Py_ssize_t buffer_size);

static int
_io_BufferedRandom___init__(PyObject *self, PyObject *args, PyObject *kwargs)
{
    int return_value = -1;
    #if defined(Py_BUILD_CORE) && !defined(Py_BUILD_CORE_MODULE)

    #define NUM_KEYWORDS 2
    static struct {
        PyGC_Head _this_is_not_used;
        PyObject_VAR_HEAD
        Py_hash_t ob_hash;
        PyObject *ob_item[NUM_KEYWORDS];
    } _kwtuple = {
        .ob_base = PyVarObject_HEAD_INIT(&PyTuple_Type, NUM_KEYWORDS)
        .ob_hash = -1,
        .ob_item = { &_Py_ID(raw), &_Py_ID(buffer_size), },
    };
    #undef NUM_KEYWORDS
    #define KWTUPLE (&_kwtuple.ob_base.ob_base)

    #else  // !Py_BUILD_CORE
    #  define KWTUPLE NULL
    #endif  // !Py_BUILD_CORE

    static const char * const _keywords[] = {"raw", "buffer_size", NULL};
    static _PyArg_Parser _parser = {
        .keywords = _keywords,
        .fname = "BufferedRandom",
        .kwtuple = KWTUPLE,
    };
    #undef KWTUPLE
    PyObject *argsbuf[2];
    PyObject * const *fastargs;
    Py_ssize_t nargs = PyTuple_GET_SIZE(args);
    Py_ssize_t noptargs = nargs + (kwargs ? PyDict_GET_SIZE(kwargs) : 0) - 1;
    PyObject *raw;
    Py_ssize_t buffer_size = DEFAULT_BUFFER_SIZE;

    fastargs = _PyArg_UnpackKeywords(_PyTuple_CAST(args)->ob_item, nargs, kwargs, NULL, &_parser,
            /*minpos*/ 1, /*maxpos*/ 2, /*minkw*/ 0, /*varpos*/ 0, argsbuf);
    if (!fastargs) {
        goto exit;
    }
    raw = fastargs[0];
    if (!noptargs) {
        goto skip_optional_pos;
    }
    {
        Py_ssize_t ival = -1;
        PyObject *iobj = _PyNumber_Index(fastargs[1]);
        if (iobj != NULL) {
            ival = PyLong_AsSsize_t(iobj);
            Py_DECREF(iobj);
        }
        if (ival == -1 && PyErr_Occurred()) {
            goto exit;
        }
        buffer_size = ival;
    }
skip_optional_pos:
    return_value = _io_BufferedRandom___init___impl((buffered *)self, raw, buffer_size);

exit:
    return return_value;
}

PyDoc_STRVAR(_io_BufferedRWPair___init____doc__,
"BufferedRWPair(reader, writer, buffer_size=DEFAULT_BUFFER_SIZE, /)\n"
"--\n"
"\n"
"A buffered reader and writer object together.\n"
"\n"
"A buffered reader object and buffered writer object put together to\n"
"form a sequential IO object that can read and write. This is typically\n"
"used with a socket or two-way pipe.\n"
"\n"
"reader and writer are RawIOBase objects that are readable and\n"
"writeable respectively. If the buffer_size is omitted it defaults to\n"
"DEFAULT_BUFFER_SIZE.");

static int
_io_BufferedRWPair___init___impl(rwpair *self, PyObject *reader,
                                 PyObject *writer, Py_ssize_t buffer_size);

static int
_io_BufferedRWPair___init__(PyObject *self, PyObject *args, PyObject *kwargs)
{
    int return_value = -1;
    PyTypeObject *base_tp = clinic_state()->PyBufferedRWPair_Type;
    PyObject *reader;
    PyObject *writer;
    Py_ssize_t buffer_size = DEFAULT_BUFFER_SIZE;

    if ((Py_IS_TYPE(self, base_tp) ||
         Py_TYPE(self)->tp_new == base_tp->tp_new) &&
        !_PyArg_NoKeywords("BufferedRWPair", kwargs)) {
        goto exit;
    }
    if (!_PyArg_CheckPositional("BufferedRWPair", PyTuple_GET_SIZE(args), 2, 3)) {
        goto exit;
    }
    reader = PyTuple_GET_ITEM(args, 0);
    writer = PyTuple_GET_ITEM(args, 1);
    if (PyTuple_GET_SIZE(args) < 3) {
        goto skip_optional;
    }
    {
        Py_ssize_t ival = -1;
        PyObject *iobj = _PyNumber_Index(PyTuple_GET_ITEM(args, 2));
        if (iobj != NULL) {
            ival = PyLong_AsSsize_t(iobj);
            Py_DECREF(iobj);
        }
        if (ival == -1 && PyErr_Occurred()) {
            goto exit;
        }
        buffer_size = ival;
    }
skip_optional:
    return_value = _io_BufferedRWPair___init___impl((rwpair *)self, reader, writer, buffer_size);

exit:
    return return_value;
}

PyDoc_STRVAR(_io_BufferedRWPair_read__doc__,
"read($self, size=-1, /)\n"
"--\n"
"\n");

#define _IO_BUFFEREDRWPAIR_READ_METHODDEF    \
    {"read", _PyCFunction_CAST(_io_BufferedRWPair_read), METH_FASTCALL, _io_BufferedRWPair_read__doc__},

static PyObject *
_io_BufferedRWPair_read_impl(rwpair *self, PyObject *size);

static PyObject *
_io_BufferedRWPair_read(PyObject *self, PyObject *const *args, Py_ssize_t nargs)
{
    PyObject *return_value = NULL;
    PyObject *size = NULL;

    if (!_PyArg_CheckPositional("read", nargs, 0, 1)) {
        goto exit;
    }
    if (nargs < 1) {
        goto skip_optional;
    }
    size = args[0];
skip_optional:
    return_value = _io_BufferedRWPair_read_impl((rwpair *)self, size);

exit:
    return return_value;
}

PyDoc_STRVAR(_io_BufferedRWPair_readall__doc__,
"readall($self, /)\n"
"--\n"
"\n");

#define _IO_BUFFEREDRWPAIR_READALL_METHODDEF    \
    {"readall", (PyCFunction)_io_BufferedRWPair_readall, METH_NOARGS, _io_BufferedRWPair_readall__doc__},

static PyObject *
_io_BufferedRWPair_readall_impl(rwpair *self);

static PyObject *
_io_BufferedRWPair_readall(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return _io_BufferedRWPair_readall_impl((rwpair *)self);
}

PyDoc_STRVAR(_io_BufferedRWPair_peek__doc__,
"peek($self, size=0, /)\n"
"--\n"
"\n");

#define _IO_BUFFEREDRWPAIR_PEEK_METHODDEF    \
    {"peek", _PyCFunction_CAST(_io_BufferedRWPair_peek), METH_FASTCALL, _io_BufferedRWPair_peek__doc__},

static PyObject *
_io_BufferedRWPair_peek_impl(rwpair *self, PyObject *size);

static PyObject *
_io_BufferedRWPair_peek(PyObject *self, PyObject *const *args, Py_ssize_t nargs)
{
    PyObject *return_value = NULL;
    PyObject *size = NULL;

    if (!_PyArg_CheckPositional("peek", nargs, 0, 1)) {
        goto exit;
    }
    if (nargs < 1) {
        goto skip_optional;
    }
    size = args[0];
skip_optional:
    return_value = _io_BufferedRWPair_peek_impl((rwpair *)self, size);

exit:
    return return_value;
}

PyDoc_STRVAR(_io_BufferedRWPair_readline__doc__,
"readline($self, size=-1, /)\n"
"--\n"
"\n");

#define _IO_BUFFEREDRWPAIR_READLINE_METHODDEF    \
    {"readline", _PyCFunction_CAST(_io_BufferedRWPair_readline), METH_FASTCALL, _io_BufferedRWPair_readline__doc__},

static PyObject *
_io_BufferedRWPair_readline_impl(rwpair *self, PyObject *size);

static PyObject *
_io_BufferedRWPair_readline(PyObject *self, PyObject *const *args, Py_ssize_t nargs)
{
    PyObject *return_value = NULL;
    PyObject *size = NULL;

    if (!_PyArg_CheckPositional("readline", nargs, 0, 1)) {
        goto exit;
    }
    if (nargs < 1) {
        goto skip_optional;
    }
    size = args[0];
skip_optional:
    return_value = _io_BufferedRWPair_readline_impl((rwpair *)self, size);

exit:
    return return_value;
}

PyDoc_STRVAR(_io_BufferedRWPair_read1__doc__,
"read1($self, size=-1, /)\n"
"--\n"
"\n");

#define _IO_BUFFEREDRWPAIR_READ1_METHODDEF    \
    {"read1", _PyCFunction_CAST(_io_BufferedRWPair_read1), METH_FASTCALL, _io_BufferedRWPair_read1__doc__},

static PyObject *
_io_BufferedRWPair_read1_impl(rwpair *self, PyObject *size);

static PyObject *
_io_BufferedRWPair_read1(PyObject *self, PyObject *const *args, Py_ssize_t nargs)
{
    PyObject *return_value = NULL;
    PyObject *size = NULL;

    if (!_PyArg_CheckPositional("read1", nargs, 0, 1)) {
        goto exit;
    }
    if (nargs < 1) {
        goto skip_optional;
    }
    size = args[0];
skip_optional:
    return_value = _io_BufferedRWPair_read1_impl((rwpair *)self, size);

exit:
    return return_value;
}

PyDoc_STRVAR(_io_BufferedRWPair_readinto__doc__,
"readinto($self, buffer, /)\n"
"--\n"
"\n");

#define _IO_BUFFEREDRWPAIR_READINTO_METHODDEF    \
    {"readinto", (PyCFunction)_io_BufferedRWPair_readinto, METH_O, _io_BufferedRWPair_readinto__doc__},

static PyObject *
_io_BufferedRWPair_readinto_impl(rwpair *self, PyObject *buffer);

static PyObject *
_io_BufferedRWPair_readinto(PyObject *self, PyObject *buffer)
{
    PyObject *return_value = NULL;

    return_value = _io_BufferedRWPair_readinto_impl((rwpair *)self, buffer);

    return return_value;
}

PyDoc_STRVAR(_io_BufferedRWPair_readinto1__doc__,
"readinto1($self, buffer, /)\n"
"--\n"
"\n");

#define _IO_BUFFEREDRWPAIR_READINTO1_METHODDEF    \
    {"readinto1", (PyCFunction)_io_BufferedRWPair_readinto1, METH_O, _io_BufferedRWPair_readinto1__doc__},

static PyObject *
_io_BufferedRWPair_readinto1_impl(rwpair *self, PyObject *buffer);

static PyObject *
_io_BufferedRWPair_readinto1(PyObject *self, PyObject *buffer)
{
    PyObject *return_value = NULL;

    return_value = _io_BufferedRWPair_readinto1_impl((rwpair *)self, buffer);

    return return_value;
}

PyDoc_STRVAR(_io_BufferedRWPair_write__doc__,
"write($self, buffer, /)\n"
"--\n"
"\n");

#define _IO_BUFFEREDRWPAIR_WRITE_METHODDEF    \
    {"write", (PyCFunction)_io_BufferedRWPair_write, METH_O, _io_BufferedRWPair_write__doc__},

static PyObject *
_io_BufferedRWPair_write_impl(rwpair *self, PyObject *buffer);

static PyObject *
_io_BufferedRWPair_write(PyObject *self, PyObject *buffer)
{
    PyObject *return_value = NULL;

    return_value = _io_BufferedRWPair_write_impl((rwpair *)self, buffer);

    return return_value;
}

PyDoc_STRVAR(_io_BufferedRWPair_flush__doc__,
"flush($self, /)\n"
"--\n"
"\n");

#define _IO_BUFFEREDRWPAIR_FLUSH_METHODDEF    \
    {"flush", (PyCFunction)_io_BufferedRWPair_flush, METH_NOARGS, _io_BufferedRWPair_flush__doc__},

static PyObject *
_io_BufferedRWPair_flush_impl(rwpair *self);

static PyObject *
_io_BufferedRWPair_flush(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return _io_BufferedRWPair_flush_impl((rwpair *)self);
}

PyDoc_STRVAR(_io_BufferedRWPair_readable__doc__,
"readable($self, /)\n"
"--\n"
"\n");

#define _IO_BUFFEREDRWPAIR_READABLE_METHODDEF    \
    {"readable", (PyCFunction)_io_BufferedRWPair_readable, METH_NOARGS, _io_BufferedRWPair_readable__doc__},

static PyObject *
_io_BufferedRWPair_readable_impl(rwpair *self);

static PyObject *
_io_BufferedRWPair_readable(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return _io_BufferedRWPair_readable_impl((rwpair *)self);
}

PyDoc_STRVAR(_io_BufferedRWPair_writable__doc__,
"writable($self, /)\n"
"--\n"
"\n");

#define _IO_BUFFEREDRWPAIR_WRITABLE_METHODDEF    \
    {"writable", (PyCFunction)_io_BufferedRWPair_writable, METH_NOARGS, _io_BufferedRWPair_writable__doc__},

static PyObject *
_io_BufferedRWPair_writable_impl(rwpair *self);

static PyObject *
_io_BufferedRWPair_writable(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return _io_BufferedRWPair_writable_impl((rwpair *)self);
}

PyDoc_STRVAR(_io_BufferedRWPair_close__doc__,
"close($self, /)\n"
"--\n"
"\n");

#define _IO_BUFFEREDRWPAIR_CLOSE_METHODDEF    \
    {"close", (PyCFunction)_io_BufferedRWPair_close, METH_NOARGS, _io_BufferedRWPair_close__doc__},

static PyObject *
_io_BufferedRWPair_close_impl(rwpair *self);

static PyObject *
_io_BufferedRWPair_close(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return _io_BufferedRWPair_close_impl((rwpair *)self);
}

PyDoc_STRVAR(_io_BufferedRWPair_isatty__doc__,
"isatty($self, /)\n"
"--\n"
"\n");

#define _IO_BUFFEREDRWPAIR_ISATTY_METHODDEF    \
    {"isatty", (PyCFunction)_io_BufferedRWPair_isatty, METH_NOARGS, _io_BufferedRWPair_isatty__doc__},

static PyObject *
_io_BufferedRWPair_isatty_impl(rwpair *self);

static PyObject *
_io_BufferedRWPair_isatty(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return _io_BufferedRWPair_isatty_impl((rwpair *)self);
}

static PyObject *
_io_BufferedRWPair_closed_get_impl(rwpair *self);

static PyObject *
_io_BufferedRWPair_closed_get(PyObject *self, void *Py_UNUSED(context))
{
    return _io_BufferedRWPair_closed_get_impl((rwpair *)self);
}
#define _IO__BUFFERED_CLOSED_GETSETDEF {"closed", (getter)_io__Buffered_closed_get, (setter)NULL, NULL},

#define _IO__BUFFERED_NAME_GETSETDEF {"name", (getter)_io__Buffered_name_get, (setter)NULL, NULL},

#define _IO__BUFFERED_MODE_GETSETDEF {"mode", (getter)_io__Buffered_mode_get, (setter)NULL, NULL},

#define _IO_BUFFEREDRWPAIR_CLOSED_GETSETDEF {"closed", (getter)_io_BufferedRWPair_closed_get, (setter)NULL, NULL},

/*[clinic end generated code: output=9da9a69e17a8684e input=a9049054013a1b77]*/

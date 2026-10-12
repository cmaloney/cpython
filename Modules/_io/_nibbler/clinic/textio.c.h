/*[clinic input]
preserve
[clinic start generated code]*/

#if defined(Py_BUILD_CORE) && !defined(Py_BUILD_CORE_MODULE)
#  include "pycore_gc.h"          // PyGC_Head
#  include "pycore_runtime.h"     // _Py_ID()
#endif
#include "pycore_abstract.h"      // _Py_convert_optional_to_ssize_t()
#include "pycore_critical_section.h"// Py_BEGIN_CRITICAL_SECTION()
#include "pycore_modsupport.h"    // _PyArg_BadArgument()
#include "pycore_unicodeobject.h" // _PyUnicode_AsUTF8NoNUL()

PyDoc_STRVAR(_io_TextIOWrapper_write__doc__,
"write($self, text, /)\n"
"--\n"
"\n");

#define _IO_TEXTIOWRAPPER_WRITE_METHODDEF    \
    {"write", (PyCFunction)_io_TextIOWrapper_write, METH_O, _io_TextIOWrapper_write__doc__},

static PyObject *
_io_TextIOWrapper_write_impl(textio *self, PyObject *text);

static PyObject *
_io_TextIOWrapper_write(PyObject *self, PyObject *arg)
{
    PyObject *return_value = NULL;
    PyObject *text;

    if (!PyUnicode_Check(arg)) {
        _PyArg_BadArgument("write", "argument", "str", arg);
        goto exit;
    }
    text = arg;
    return_value = _io_TextIOWrapper_write_impl((textio *)self, text);

exit:
    return return_value;
}

PyDoc_STRVAR(_io_TextIOWrapper_read__doc__,
"read($self, size=-1, /)\n"
"--\n"
"\n");

#define _IO_TEXTIOWRAPPER_READ_METHODDEF    \
    {"read", _PyCFunction_CAST(_io_TextIOWrapper_read), METH_FASTCALL, _io_TextIOWrapper_read__doc__},

static PyObject *
_io_TextIOWrapper_read_impl(textio *self, Py_ssize_t n);

static PyObject *
_io_TextIOWrapper_read(PyObject *self, PyObject *const *args, Py_ssize_t nargs)
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
    return_value = _io_TextIOWrapper_read_impl((textio *)self, n);

exit:
    return return_value;
}

PyDoc_STRVAR(_io_TextIOWrapper_readline__doc__,
"readline($self, size=-1, /)\n"
"--\n"
"\n");

#define _IO_TEXTIOWRAPPER_READLINE_METHODDEF    \
    {"readline", _PyCFunction_CAST(_io_TextIOWrapper_readline), METH_FASTCALL, _io_TextIOWrapper_readline__doc__},

static PyObject *
_io_TextIOWrapper_readline_impl(textio *self, Py_ssize_t size);

static PyObject *
_io_TextIOWrapper_readline(PyObject *self, PyObject *const *args, Py_ssize_t nargs)
{
    PyObject *return_value = NULL;
    Py_ssize_t size = -1;

    if (!_PyArg_CheckPositional("readline", nargs, 0, 1)) {
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
    return_value = _io_TextIOWrapper_readline_impl((textio *)self, size);

exit:
    return return_value;
}

PyDoc_STRVAR(_io_TextIOWrapper_tell__doc__,
"tell($self, /)\n"
"--\n"
"\n"
"Return the stream position as an opaque number.\n"
"\n"
"The return value of tell() can be given as input to seek(), to\n"
"restore a previous stream position.");

#define _IO_TEXTIOWRAPPER_TELL_METHODDEF    \
    {"tell", (PyCFunction)_io_TextIOWrapper_tell, METH_NOARGS, _io_TextIOWrapper_tell__doc__},

static PyObject *
_io_TextIOWrapper_tell_impl(textio *self);

static PyObject *
_io_TextIOWrapper_tell(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return _io_TextIOWrapper_tell_impl((textio *)self);
}

PyDoc_STRVAR(_io_TextIOWrapper_seek__doc__,
"seek($self, cookie, whence=os.SEEK_SET, /)\n"
"--\n"
"\n"
"Set the stream position, and return the new stream position.\n"
"\n"
"  cookie\n"
"    Zero or an opaque number returned by tell().\n"
"  whence\n"
"    The relative position to seek from.\n"
"\n"
"Four operations are supported, given by the following argument\n"
"combinations:\n"
"\n"
"- seek(0, SEEK_SET): Rewind to the start of the stream.\n"
"- seek(cookie, SEEK_SET): Restore a previous position;\n"
"  \'cookie\' must be a number returned by tell().\n"
"- seek(0, SEEK_END): Fast-forward to the end of the stream.\n"
"- seek(0, SEEK_CUR): Leave the current stream position unchanged.\n"
"\n"
"Any other argument combinations are invalid,\n"
"and may raise exceptions.");

#define _IO_TEXTIOWRAPPER_SEEK_METHODDEF    \
    {"seek", _PyCFunction_CAST(_io_TextIOWrapper_seek), METH_FASTCALL, _io_TextIOWrapper_seek__doc__},

static PyObject *
_io_TextIOWrapper_seek_impl(textio *self, PyObject *cookieObj, int whence);

static PyObject *
_io_TextIOWrapper_seek(PyObject *self, PyObject *const *args, Py_ssize_t nargs)
{
    PyObject *return_value = NULL;
    PyObject *cookieObj;
    int whence = 0;

    if (!_PyArg_CheckPositional("seek", nargs, 1, 2)) {
        goto exit;
    }
    cookieObj = args[0];
    if (nargs < 2) {
        goto skip_optional;
    }
    whence = PyLong_AsInt(args[1]);
    if (whence == -1 && PyErr_Occurred()) {
        goto exit;
    }
skip_optional:
    Py_BEGIN_CRITICAL_SECTION(self);
    return_value = _io_TextIOWrapper_seek_impl((textio *)self, cookieObj, whence);
    Py_END_CRITICAL_SECTION();

exit:
    return return_value;
}

PyDoc_STRVAR(_io_TextIOWrapper_truncate__doc__,
"truncate($self, pos=None, /)\n"
"--\n"
"\n");

#define _IO_TEXTIOWRAPPER_TRUNCATE_METHODDEF    \
    {"truncate", _PyCFunction_CAST(_io_TextIOWrapper_truncate), METH_FASTCALL, _io_TextIOWrapper_truncate__doc__},

static PyObject *
_io_TextIOWrapper_truncate_impl(textio *self, PyObject *pos);

static PyObject *
_io_TextIOWrapper_truncate(PyObject *self, PyObject *const *args, Py_ssize_t nargs)
{
    PyObject *return_value = NULL;
    PyObject *pos = Py_None;

    if (!_PyArg_CheckPositional("truncate", nargs, 0, 1)) {
        goto exit;
    }
    if (nargs < 1) {
        goto skip_optional;
    }
    pos = args[0];
skip_optional:
    Py_BEGIN_CRITICAL_SECTION(self);
    return_value = _io_TextIOWrapper_truncate_impl((textio *)self, pos);
    Py_END_CRITICAL_SECTION();

exit:
    return return_value;
}

PyDoc_STRVAR(_io_TextIOWrapper_flush__doc__,
"flush($self, /)\n"
"--\n"
"\n");

#define _IO_TEXTIOWRAPPER_FLUSH_METHODDEF    \
    {"flush", (PyCFunction)_io_TextIOWrapper_flush, METH_NOARGS, _io_TextIOWrapper_flush__doc__},

static PyObject *
_io_TextIOWrapper_flush_impl(textio *self);

static PyObject *
_io_TextIOWrapper_flush(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return _io_TextIOWrapper_flush_impl((textio *)self);
}

PyDoc_STRVAR(_io_TextIOWrapper_close__doc__,
"close($self, /)\n"
"--\n"
"\n");

#define _IO_TEXTIOWRAPPER_CLOSE_METHODDEF    \
    {"close", (PyCFunction)_io_TextIOWrapper_close, METH_NOARGS, _io_TextIOWrapper_close__doc__},

static PyObject *
_io_TextIOWrapper_close_impl(textio *self);

static PyObject *
_io_TextIOWrapper_close(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    PyObject *return_value = NULL;

    Py_BEGIN_CRITICAL_SECTION(self);
    return_value = _io_TextIOWrapper_close_impl((textio *)self);
    Py_END_CRITICAL_SECTION();

    return return_value;
}

PyDoc_STRVAR(_io_TextIOWrapper_detach__doc__,
"detach($self, /)\n"
"--\n"
"\n");

#define _IO_TEXTIOWRAPPER_DETACH_METHODDEF    \
    {"detach", (PyCFunction)_io_TextIOWrapper_detach, METH_NOARGS, _io_TextIOWrapper_detach__doc__},

static PyObject *
_io_TextIOWrapper_detach_impl(textio *self);

static PyObject *
_io_TextIOWrapper_detach(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    PyObject *return_value = NULL;

    Py_BEGIN_CRITICAL_SECTION(self);
    return_value = _io_TextIOWrapper_detach_impl((textio *)self);
    Py_END_CRITICAL_SECTION();

    return return_value;
}

static PyObject *
_io_TextIOWrapper_closed_get_impl(textio *self);

static PyObject *
_io_TextIOWrapper_closed_get(PyObject *self, void *Py_UNUSED(context))
{
    return _io_TextIOWrapper_closed_get_impl((textio *)self);
}

static PyObject *
_io_TextIOWrapper_newlines_get_impl(textio *self);

static PyObject *
_io_TextIOWrapper_newlines_get(PyObject *self, void *Py_UNUSED(context))
{
    return _io_TextIOWrapper_newlines_get_impl((textio *)self);
}

static PyObject *
_io_TextIOWrapper_errors_get_impl(textio *self);

static PyObject *
_io_TextIOWrapper_errors_get(PyObject *self, void *Py_UNUSED(context))
{
    return _io_TextIOWrapper_errors_get_impl((textio *)self);
}

static Py_ssize_t
_io_TextIOWrapper__CHUNK_SIZE_get_impl(textio *self);

static PyObject *
_io_TextIOWrapper__CHUNK_SIZE_get(PyObject *self, void *Py_UNUSED(context))
{
    PyObject *return_value = NULL;
    Py_ssize_t _return_value;

    _return_value = _io_TextIOWrapper__CHUNK_SIZE_get_impl((textio *)self);
    if ((_return_value == -1) && PyErr_Occurred()) {
        goto exit;
    }
    return_value = PyLong_FromSsize_t(_return_value);

exit:
    return return_value;
}

static int
_io_TextIOWrapper__CHUNK_SIZE_set_impl(textio *self, Py_ssize_t value);

static int
_io_TextIOWrapper__CHUNK_SIZE_set(PyObject *self, PyObject *arg, void *Py_UNUSED(context))
{
    int return_value = -1;
    Py_ssize_t value;

    if (arg == NULL) {
        PyErr_Format(PyExc_AttributeError,
                     "attribute '_CHUNK_SIZE' of '%.100s' objects cannot be deleted",
                     Py_TYPE(self)->tp_name);
        return -1;
    }
    {
        Py_ssize_t ival = -1;
        PyObject *iobj = _PyNumber_Index(arg);
        if (iobj != NULL) {
            ival = PyLong_AsSsize_t(iobj);
            Py_DECREF(iobj);
        }
        if (ival == -1 && PyErr_Occurred()) {
            goto exit;
        }
        value = ival;
    }
    Py_BEGIN_CRITICAL_SECTION(self);
    return_value = _io_TextIOWrapper__CHUNK_SIZE_set_impl((textio *)self, value);
    Py_END_CRITICAL_SECTION();

exit:
    return return_value;
}

static PyObject *
_io_TextIOWrapper_buffer_get_impl(textio *self);

static PyObject *
_io_TextIOWrapper_buffer_get(PyObject *self, void *Py_UNUSED(context))
{
    return _io_TextIOWrapper_buffer_get_impl((textio *)self);
}

PyDoc_STRVAR(_io_TextIOWrapper___init____doc__,
"TextIOWrapper(buffer, encoding=None, errors=None, newline=None,\n"
"              line_buffering=False, write_through=False)\n"
"--\n"
"\n"
"Character and line based layer over a BufferedIOBase object, buffer.\n"
"\n"
"encoding gives the name of the encoding that the stream will be\n"
"decoded or encoded with. It defaults to locale.getencoding().\n"
"\n"
"errors determines the strictness of encoding and decoding (see\n"
"help(codecs.Codec) or the documentation for codecs.register) and\n"
"defaults to \"strict\".\n"
"\n"
"newline controls how line endings are handled. It can be None, \'\',\n"
"\'\\n\', \'\\r\', and \'\\r\\n\'.  It works as follows:\n"
"\n"
"* On input, if newline is None, universal newlines mode is\n"
"  enabled. Lines in the input can end in \'\\n\', \'\\r\', or \'\\r\\n\', and\n"
"  these are translated into \'\\n\' before being returned to the\n"
"  caller. If it is \'\', universal newline mode is enabled, but line\n"
"  endings are returned to the caller untranslated. If it has any of\n"
"  the other legal values, input lines are only terminated by the given\n"
"  string, and the line ending is returned to the caller untranslated.\n"
"\n"
"* On output, if newline is None, any \'\\n\' characters written are\n"
"  translated to the system default line separator, os.linesep. If\n"
"  newline is \'\' or \'\\n\', no translation takes place. If newline is any\n"
"  of the other legal values, any \'\\n\' characters written are translated\n"
"  to the given string.\n"
"\n"
"If line_buffering is True, a call to flush is implied when a call to\n"
"write contains a newline character.");

static int
_io_TextIOWrapper___init___impl(textio *self, PyObject *buffer,
                                const char *encoding, PyObject *errors,
                                const char *newline, int line_buffering,
                                int write_through);

static int
_io_TextIOWrapper___init__(PyObject *self, PyObject *args, PyObject *kwargs)
{
    int return_value = -1;
    #if defined(Py_BUILD_CORE) && !defined(Py_BUILD_CORE_MODULE)

    #define NUM_KEYWORDS 6
    static struct {
        PyGC_Head _this_is_not_used;
        PyObject_VAR_HEAD
        Py_hash_t ob_hash;
        PyObject *ob_item[NUM_KEYWORDS];
    } _kwtuple = {
        .ob_base = PyVarObject_HEAD_INIT(&PyTuple_Type, NUM_KEYWORDS)
        .ob_hash = -1,
        .ob_item = { &_Py_ID(buffer), &_Py_ID(encoding), &_Py_ID(errors), &_Py_ID(newline), &_Py_ID(line_buffering), &_Py_ID(write_through), },
    };
    #undef NUM_KEYWORDS
    #define KWTUPLE (&_kwtuple.ob_base.ob_base)

    #else  // !Py_BUILD_CORE
    #  define KWTUPLE NULL
    #endif  // !Py_BUILD_CORE

    static const char * const _keywords[] = {"buffer", "encoding", "errors", "newline", "line_buffering", "write_through", NULL};
    static _PyArg_Parser _parser = {
        .keywords = _keywords,
        .fname = "TextIOWrapper",
        .kwtuple = KWTUPLE,
    };
    #undef KWTUPLE
    PyObject *argsbuf[6];
    PyObject * const *fastargs;
    Py_ssize_t nargs = PyTuple_GET_SIZE(args);
    Py_ssize_t noptargs = nargs + (kwargs ? PyDict_GET_SIZE(kwargs) : 0) - 1;
    PyObject *buffer;
    const char *encoding = NULL;
    PyObject *errors = Py_None;
    const char *newline = NULL;
    int line_buffering = 0;
    int write_through = 0;

    fastargs = _PyArg_UnpackKeywords(_PyTuple_CAST(args)->ob_item, nargs, kwargs, NULL, &_parser,
            /*minpos*/ 1, /*maxpos*/ 6, /*minkw*/ 0, /*varpos*/ 0, argsbuf);
    if (!fastargs) {
        goto exit;
    }
    buffer = fastargs[0];
    if (!noptargs) {
        goto skip_optional_pos;
    }
    if (fastargs[1]) {
        if (fastargs[1] == Py_None) {
            encoding = NULL;
        }
        else if (PyUnicode_Check(fastargs[1])) {
            encoding = _PyUnicode_AsUTF8NoNUL(fastargs[1]);
            if (encoding == NULL) {
                goto exit;
            }
        }
        else {
            _PyArg_BadArgument("TextIOWrapper", "argument 'encoding'", "str or None", fastargs[1]);
            goto exit;
        }
        if (!--noptargs) {
            goto skip_optional_pos;
        }
    }
    if (fastargs[2]) {
        errors = fastargs[2];
        if (!--noptargs) {
            goto skip_optional_pos;
        }
    }
    if (fastargs[3]) {
        if (fastargs[3] == Py_None) {
            newline = NULL;
        }
        else if (PyUnicode_Check(fastargs[3])) {
            newline = _PyUnicode_AsUTF8NoNUL(fastargs[3]);
            if (newline == NULL) {
                goto exit;
            }
        }
        else {
            _PyArg_BadArgument("TextIOWrapper", "argument 'newline'", "str or None", fastargs[3]);
            goto exit;
        }
        if (!--noptargs) {
            goto skip_optional_pos;
        }
    }
    if (fastargs[4]) {
        line_buffering = PyObject_IsTrue(fastargs[4]);
        if (line_buffering < 0) {
            goto exit;
        }
        if (!--noptargs) {
            goto skip_optional_pos;
        }
    }
    write_through = PyObject_IsTrue(fastargs[5]);
    if (write_through < 0) {
        goto exit;
    }
skip_optional_pos:
    Py_BEGIN_CRITICAL_SECTION(self);
    return_value = _io_TextIOWrapper___init___impl((textio *)self, buffer, encoding, errors, newline, line_buffering, write_through);
    Py_END_CRITICAL_SECTION();

exit:
    return return_value;
}

PyDoc_STRVAR(_io_TextIOWrapper_reconfigure__doc__,
"reconfigure($self, /, *, encoding=None, errors=None, newline=None,\n"
"            line_buffering=None, write_through=None)\n"
"--\n"
"\n"
"Reconfigure the text stream with new parameters.\n"
"\n"
"This also does an implicit stream flush.");

#define _IO_TEXTIOWRAPPER_RECONFIGURE_METHODDEF    \
    {"reconfigure", _PyCFunction_CAST(_io_TextIOWrapper_reconfigure), METH_FASTCALL|METH_KEYWORDS, _io_TextIOWrapper_reconfigure__doc__},

static PyObject *
_io_TextIOWrapper_reconfigure_impl(textio *self, PyObject *encoding,
                                   PyObject *errors, PyObject *newline_obj,
                                   PyObject *line_buffering_obj,
                                   PyObject *write_through_obj);

static PyObject *
_io_TextIOWrapper_reconfigure(PyObject *self, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    PyObject *return_value = NULL;
    #if defined(Py_BUILD_CORE) && !defined(Py_BUILD_CORE_MODULE)

    #define NUM_KEYWORDS 5
    static struct {
        PyGC_Head _this_is_not_used;
        PyObject_VAR_HEAD
        Py_hash_t ob_hash;
        PyObject *ob_item[NUM_KEYWORDS];
    } _kwtuple = {
        .ob_base = PyVarObject_HEAD_INIT(&PyTuple_Type, NUM_KEYWORDS)
        .ob_hash = -1,
        .ob_item = { &_Py_ID(encoding), &_Py_ID(errors), &_Py_ID(newline), &_Py_ID(line_buffering), &_Py_ID(write_through), },
    };
    #undef NUM_KEYWORDS
    #define KWTUPLE (&_kwtuple.ob_base.ob_base)

    #else  // !Py_BUILD_CORE
    #  define KWTUPLE NULL
    #endif  // !Py_BUILD_CORE

    static const char * const _keywords[] = {"encoding", "errors", "newline", "line_buffering", "write_through", NULL};
    static _PyArg_Parser _parser = {
        .keywords = _keywords,
        .fname = "reconfigure",
        .kwtuple = KWTUPLE,
    };
    #undef KWTUPLE
    PyObject *argsbuf[5];
    Py_ssize_t noptargs = nargs + (kwnames ? PyTuple_GET_SIZE(kwnames) : 0) - 0;
    PyObject *encoding = Py_None;
    PyObject *errors = Py_None;
    PyObject *newline_obj = NULL;
    PyObject *line_buffering_obj = Py_None;
    PyObject *write_through_obj = Py_None;

    args = _PyArg_UnpackKeywords(args, nargs, NULL, kwnames, &_parser,
            /*minpos*/ 0, /*maxpos*/ 0, /*minkw*/ 0, /*varpos*/ 0, argsbuf);
    if (!args) {
        goto exit;
    }
    if (!noptargs) {
        goto skip_optional_kwonly;
    }
    if (args[0]) {
        encoding = args[0];
        if (!--noptargs) {
            goto skip_optional_kwonly;
        }
    }
    if (args[1]) {
        errors = args[1];
        if (!--noptargs) {
            goto skip_optional_kwonly;
        }
    }
    if (args[2]) {
        newline_obj = args[2];
        if (!--noptargs) {
            goto skip_optional_kwonly;
        }
    }
    if (args[3]) {
        line_buffering_obj = args[3];
        if (!--noptargs) {
            goto skip_optional_kwonly;
        }
    }
    write_through_obj = args[4];
skip_optional_kwonly:
    Py_BEGIN_CRITICAL_SECTION(self);
    return_value = _io_TextIOWrapper_reconfigure_impl((textio *)self, encoding, errors, newline_obj, line_buffering_obj, write_through_obj);
    Py_END_CRITICAL_SECTION();

exit:
    return return_value;
}
#define _IO_TEXTIOWRAPPER_CLOSED_GETSETDEF {"closed", (getter)_io_TextIOWrapper_closed_get, (setter)NULL, NULL},

#define _IO_TEXTIOWRAPPER_NEWLINES_GETSETDEF {"newlines", (getter)_io_TextIOWrapper_newlines_get, (setter)NULL, NULL},

#define _IO_TEXTIOWRAPPER_ERRORS_GETSETDEF {"errors", (getter)_io_TextIOWrapper_errors_get, (setter)NULL, NULL},

#define _IO_TEXTIOWRAPPER__CHUNK_SIZE_GETSETDEF {"_CHUNK_SIZE", (getter)_io_TextIOWrapper__CHUNK_SIZE_get, (setter)_io_TextIOWrapper__CHUNK_SIZE_set, NULL},

#define _IO_TEXTIOWRAPPER_BUFFER_GETSETDEF {"buffer", (getter)_io_TextIOWrapper_buffer_get, (setter)NULL, NULL},

/*[clinic end generated code: output=4c48338c8bffc524 input=a9049054013a1b77]*/

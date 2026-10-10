/*
    An implementation of the new I/O lib as defined by PEP 3116 - "New I/O"

    Classes defined here: UnsupportedOperation, BlockingIOError.
    Functions defined here: open().

    Mostly written by Amaury Forgeot d'Arc
*/

#include "Python.h"
#include "pycore_abstract.h"      // _PyNumber_Index()
#include "pycore_global_strings.h" // _Py_LATIN1_CHR()
#include "pycore_interp.h"        // _PyInterpreterState_GetConfig()
#include "pycore_long.h"          // _PyLong_IsNegative()
#include "pycore_object.h"        // _Py_XGetRef()
#include "pycore_pyatomic_ft_wrappers.h" // FT_ATOMIC_LOAD_PTR_RELAXED()
#include "pycore_pyerrors.h"      // _PyErr_ChainExceptions1()
#include "pycore_pystate.h"       // _PyInterpreterState_GET()

#include "_iomodule.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif /* HAVE_SYS_STAT_H */

#ifdef MS_WINDOWS
#include <windows.h>
#endif

PyDoc_STRVAR(module_doc,
"The io module provides the Python interfaces to stream handling. The\n"
"builtin open function is defined in this module.\n"
"\n"
"At the top of the I/O hierarchy is the abstract base class IOBase. It\n"
"defines the basic interface to a stream. Note, however, that there is no\n"
"separation between reading and writing to streams; implementations are\n"
"allowed to raise an OSError if they do not support a given operation.\n"
"\n"
"Extending IOBase is RawIOBase which deals simply with the reading and\n"
"writing of raw bytes to a stream. FileIO subclasses RawIOBase to provide\n"
"an interface to OS files.\n"
"\n"
"BufferedIOBase deals with buffering on a raw byte stream (RawIOBase). Its\n"
"subclasses, BufferedWriter, BufferedReader, and BufferedRWPair buffer\n"
"streams that are readable, writable, and both respectively.\n"
"BufferedRandom provides a buffered interface to random access\n"
"streams. BytesIO is a simple stream of in-memory bytes.\n"
"\n"
"Another IOBase subclass, TextIOBase, deals with the encoding and decoding\n"
"of streams into text. TextIOWrapper, which extends it, is a buffered text\n"
"interface to a buffered raw stream (`BufferedIOBase`). Finally, StringIO\n"
"is an in-memory stream for text.\n"
"\n"
"Argument names are not part of the specification, and only the arguments\n"
"of open() are intended to be used as keyword arguments.\n"
"\n"
"data:\n"
"\n"
"DEFAULT_BUFFER_SIZE\n"
"\n"
"   An int containing the default buffer size used by the module's buffered\n"
"   I/O classes.\n"
    );


/* The buffered classes open() uses, which _io._set_open_impl() and
   _io._set_unbuffered_impl() may replace while open() runs in other
   threads: open() takes a new reference (or NULL) with
   iomodule_get_open_type().  With the GIL, plain loads and stores do. */
#ifdef Py_GIL_DISABLED
static PyObject *
iomodule_get_open_type(PyTypeObject **slot)
{
    return _Py_XGetRef((PyObject **)slot);
}

static void
iomodule_set_open_type(PyTypeObject **slot, PyObject *type)
{
    if (type != NULL) {
        /* Lets iomodule_get_open_type() take references to it. */
        _PyObject_SetMaybeWeakref(type);
    }
    Py_XDECREF(_Py_atomic_exchange_ptr(slot, type));
}
#else
static PyObject *
iomodule_get_open_type(PyTypeObject **slot)
{
    return Py_XNewRef(*slot);
}

static void
iomodule_set_open_type(PyTypeObject **slot, PyObject *type)
{
    Py_XSETREF(*slot, (PyTypeObject *)type);
}
#endif

/*
 * The main open() function
 */
/*[clinic input]
module _io

_io.open
    file: object
    mode: str = "r"
    buffering as buffering_obj: object(c_default="NULL") = -1
    encoding: str(accept={str, NoneType}) = None
    errors: str(accept={str, NoneType}) = None
    newline: str(accept={str, NoneType}) = None
    closefd: bool = True
    opener: object = None

Open file and return a stream.  Raise OSError upon failure.

file is either a text or byte string giving the name (and the path
if the file isn't in the current working directory) of the file to
be opened or an integer file descriptor of the file to be
wrapped.  (If a file descriptor is given, it is closed when the
returned I/O object is closed, unless closefd is set to False.)

mode is an optional string that specifies the mode in which the file
is opened.  It defaults to 'r' which means open for reading in text
mode.  Other common values are 'w' for writing (truncating the file if
it already exists), 'x' for creating and writing to a new file, and
'a' for appending (which on some Unix systems, means that all writes
append to the end of the file regardless of the current seek position).
In text mode, if encoding is not specified the encoding used is platform
dependent: locale.getencoding() is called to get the current locale
encoding.  (For reading and writing raw bytes use binary mode and leave
encoding unspecified.)  The available modes are:

========= ==========================================================
Character Meaning
--------- ----------------------------------------------------------
'r'       open for reading (default)
'w'       open for writing, truncating the file first
'x'       create a new file and open it for writing
'a'       open for writing, appending to the end of the file if it
          exists
'b'       binary mode
't'       text mode (default)
'+'       open a disk file for updating (reading and writing)
========= ==========================================================

The default mode is 'rt' (open for reading text).  For binary random
access, the mode 'w+b' opens and truncates the file to 0 bytes, while
'r+b' opens the file without truncation.  The 'x' mode implies 'w' and
raises an `FileExistsError` if the file already exists.

Python distinguishes between files opened in binary and text modes,
even when the underlying operating system doesn't.  Files opened in
binary mode (appending 'b' to the mode argument) return contents as
bytes objects without any decoding.  In text mode (the default, or when
't' is appended to the mode argument), the contents of the file are
returned as strings, the bytes having been first decoded using a
platform-dependent encoding or using the specified encoding if given.

buffering is an optional integer used to set the buffering policy.
Pass 0 to switch buffering off (only allowed in binary mode), 1 to
select line buffering (only usable in text mode), and an integer > 1 to
indicate the size of a fixed-size chunk buffer.   When no buffering
argument is given, the default buffering policy works as follows:

* Binary files are buffered in fixed-size chunks; the size of the buffer
  is max(min(blocksize, 8 MiB), DEFAULT_BUFFER_SIZE) when the device
  block size is available.
  On most systems, the buffer will typically be 128 kilobytes long.

* "Interactive" text files (files for which isatty() returns True)
  use line buffering.  Other text files use the policy described above
  for binary files.

encoding is the name of the encoding used to decode or encode the
file.  This should only be used in text mode.  The default encoding is
platform dependent, but any encoding supported by Python can be
passed.  See the codecs module for the list of supported encodings.

errors is an optional string that specifies how encoding errors are to
be handled---this argument should not be used in binary mode.  Pass
'strict' to raise a ValueError exception if there is an encoding error
(the default of None has the same effect), or pass 'ignore' to ignore
errors.  (Note that ignoring encoding errors can lead to data loss.)
See the documentation for codecs.register or run 'help(codecs.Codec)'
for a list of the permitted encoding error strings.

newline controls how universal newlines works (it only applies to text
mode).  It can be None, '', '\n', '\r', and '\r\n'.  It works as
follows:

* On input, if newline is None, universal newlines mode is enabled.
  Lines in the input can end in '\n', '\r', or '\r\n', and these are
  translated into '\n' before being returned to the caller.  If it is
  '', universal newline mode is enabled, but line endings are returned
  to the caller untranslated.  If it has any of the other legal values,
  input lines are only terminated by the given string, and the line
  ending is returned to the caller untranslated.

* On output, if newline is None, any '\n' characters written are
  translated to the system default line separator, os.linesep.  If
  newline is '' or '\n', no translation takes place.  If newline is any
  of the other legal values, any '\n' characters written are translated
  to the given string.

If closefd is False, the underlying file descriptor will be kept open
when the file is closed.  This does not work when a file name is given
and must be True in that case.

A custom opener can be used by passing a callable as *opener*.  The
underlying file descriptor for the file object is then obtained by
calling *opener* with (*file*, *flags*).  *opener* must return an open
file descriptor (passing os.open as *opener* results in functionality
similar to passing None).

open() returns a file object whose type depends on the mode, and
through which the standard file operations such as reading and writing
are performed.  When open() is used to open a file in a text mode ('w',
'r', 'wt', 'rt', etc.), it returns a TextIOWrapper.  When used to open
a file in a binary mode, the returned class varies: in read binary
mode, it returns a BufferedReader; in write binary and append binary
modes, it returns a BufferedWriter, and in read/write mode, it returns
a BufferedRandom.

It is also possible to use a string or bytearray as a file for both
reading and writing.  For strings StringIO can be used like a file
opened in a text mode, and for bytes a BytesIO can be used like a file
opened in a binary mode.
[clinic start generated code]*/

static PyObject *
_io_open_impl(PyObject *module, PyObject *file, const char *mode,
              PyObject *buffering_obj, const char *encoding,
              const char *errors, const char *newline, int closefd,
              PyObject *opener)
/*[clinic end generated code: output=7a5ec03cf5c02f7e input=911c8b986ebcf4fc]*/
{
    size_t i;

    /* buffering=None: buffer writes without limit, which only the
       _io._nibbler classes do (with _io._set_open_impl("_nibbler")).  Like
       a fixed size, it means no line buffering. */
    int buffering = -1;
    int unlimited = buffering_obj == Py_None;
    if (unlimited) {
        buffering = DEFAULT_BUFFER_SIZE;
    }
    else if (buffering_obj != NULL) {
        buffering = PyLong_AsInt(buffering_obj);
        if (buffering == -1 && PyErr_Occurred()) {
            return NULL;
        }
    }

    int creating = 0, reading = 0, writing = 0, appending = 0, updating = 0;
    int text = 0, binary = 0;

    char rawmode[6], *m;
    int line_buffering, is_number, isatty = 0;

    PyObject *raw, *modeobj = NULL, *buffer, *wrapper, *result = NULL, *path_or_fd = NULL;

    is_number = PyNumber_Check(file);

    if (is_number) {
        path_or_fd = Py_NewRef(file);
    } else {
        path_or_fd = PyOS_FSPath(file);
        if (path_or_fd == NULL) {
            return NULL;
        }
    }

    if (!is_number &&
        !PyUnicode_Check(path_or_fd) &&
        !PyBytes_Check(path_or_fd)) {
        PyErr_Format(PyExc_TypeError, "invalid file: %R", file);
        goto error;
    }

    /* Decode mode */
    for (i = 0; i < strlen(mode); i++) {
        char c = mode[i];

        switch (c) {
        case 'x':
            creating = 1;
            break;
        case 'r':
            reading = 1;
            break;
        case 'w':
            writing = 1;
            break;
        case 'a':
            appending = 1;
            break;
        case '+':
            updating = 1;
            break;
        case 't':
            text = 1;
            break;
        case 'b':
            binary = 1;
            break;
        default:
            goto invalid_mode;
        }

        /* c must not be duplicated */
        if (strchr(mode+i+1, c)) {
          invalid_mode:
            PyErr_Format(PyExc_ValueError, "invalid mode: '%s'", mode);
            goto error;
        }

    }

    m = rawmode;
    if (creating)  *(m++) = 'x';
    if (reading)   *(m++) = 'r';
    if (writing)   *(m++) = 'w';
    if (appending) *(m++) = 'a';
    if (updating)  *(m++) = '+';
    *m = '\0';

    /* Parameters validation */
    if (text && binary) {
        PyErr_SetString(PyExc_ValueError,
                        "can't have text and binary mode at once");
        goto error;
    }

    if (creating + reading + writing + appending > 1) {
        PyErr_SetString(PyExc_ValueError,
                        "must have exactly one of create/read/write/append mode");
        goto error;
    }

    if (binary && encoding != NULL) {
        PyErr_SetString(PyExc_ValueError,
                        "binary mode doesn't take an encoding argument");
        goto error;
    }

    if (binary && errors != NULL) {
        PyErr_SetString(PyExc_ValueError,
                        "binary mode doesn't take an errors argument");
        goto error;
    }

    if (binary && newline != NULL) {
        PyErr_SetString(PyExc_ValueError,
                        "binary mode doesn't take a newline argument");
        goto error;
    }

    if (binary && buffering == 1) {
        if (PyErr_WarnEx(PyExc_RuntimeWarning,
                         "line buffering (buffering=1) isn't supported in "
                         "binary mode, the default buffer size will be used",
                         1) < 0) {
           goto error;
        }
    }

    _PyIO_State *state = get_io_state(module);
    if (unlimited) {
        /* Check before the file is opened (and maybe truncated). */
        int writable = creating || writing || appending || updating;
        PyObject *type = iomodule_get_open_type(
            updating ? &state->open_random_type : &state->open_writer_type);
        int nibbler = (type != NULL
                       && _PyIO_is_nibbler_buffered_type((PyTypeObject *)type));
        Py_XDECREF(type);
        if (!nibbler) {
            PyErr_SetString(PyExc_TypeError,
                            "buffering=None (unlimited write buffering) "
                            "needs open() to use _io._nibbler");
            goto error;
        }
        if (!writable) {
            PyErr_SetString(PyExc_ValueError,
                            "buffering=None (unlimited write buffering) "
                            "needs a writable mode");
            goto error;
        }
    }

    /* Create the Raw file stream */
    {
        PyObject *RawIO_class = (PyObject *)state->PyFileIO_Type;
#ifdef HAVE_WINDOWS_CONSOLE_IO
        const PyConfig *config = _Py_GetConfig();
        if (!config->legacy_windows_stdio && _PyIO_get_console_type(path_or_fd) != '\0') {
            RawIO_class = (PyObject *)state->PyWindowsConsoleIO_Type;
            encoding = "utf-8";
        }
#endif
        /* Single-letter modes use a cached string. */
        PyObject *rawmodeobj = rawmode[1] == '\0'
                               ? _Py_LATIN1_CHR((unsigned char)rawmode[0])
                               : PyUnicode_FromString(rawmode);
        if (rawmodeobj == NULL) {
            goto error;
        }
        PyObject *args[] = {path_or_fd, rawmodeobj,
                            closefd ? Py_True : Py_False, opener};
        raw = PyObject_Vectorcall(RawIO_class, args, Py_ARRAY_LENGTH(args),
                                  NULL);
        Py_DECREF(rawmodeobj);
    }

    if (raw == NULL)
        goto error;
    result = raw;

    Py_SETREF(path_or_fd, NULL);

    /* buffering; whether the file is interactive only matters for text
       (line buffering): binary files then use the block size either way. */
    if (buffering < 0 && !binary) {
        PyObject *res = PyObject_CallMethodNoArgs(raw, &_Py_ID(_isatty_open_only));
        if (res == NULL)
            goto error;
        isatty = PyObject_IsTrue(res);
        Py_DECREF(res);
        if (isatty < 0)
            goto error;
    }

    if (buffering == 1 || isatty) {
        buffering = -1;
        line_buffering = 1;
    }
    else
        line_buffering = 0;

    if (buffering < 0) {
        PyObject *blksize_obj;
        blksize_obj = PyObject_GetAttr(raw, &_Py_ID(_blksize));
        if (blksize_obj == NULL)
            goto error;
        buffering = PyLong_AsLong(blksize_obj);
        Py_DECREF(blksize_obj);
        if (buffering == -1 && PyErr_Occurred())
            goto error;
        buffering = Py_MAX(Py_MIN(buffering, 8192 * 1024), DEFAULT_BUFFER_SIZE);
    }
    if (buffering < 0) {
        PyErr_SetString(PyExc_ValueError,
                        "invalid buffering size");
        goto error;
    }

    /* Unbuffered text can only be written, and only over a buffered object
       with buffer size 0 (with _io._set_unbuffered_impl("_nibbler"), see
       below): gh-61606. */
    if (buffering == 0 && !binary && (reading || updating)) {
        PyErr_SetString(PyExc_ValueError,
                        "can't have unbuffered text I/O");
        goto error;
    }

    /* wraps into a buffered file; if not buffering, returns the raw file
       object, or with _io._set_unbuffered_impl("_nibbler"), wraps it with
       buffer size 0 */
    {
        PyTypeObject **slot;
        if (updating) {
            slot = (buffering ? &state->open_random_type
                              : &state->open_unbuffered_random_type);
        }
        else if (creating || writing || appending) {
            slot = (buffering ? &state->open_writer_type
                              : &state->open_unbuffered_writer_type);
        }
        else if (reading) {
            slot = (buffering ? &state->open_reader_type
                              : &state->open_unbuffered_reader_type);
        }
        else {
            PyErr_Format(PyExc_ValueError,
                         "unknown mode: '%s'", mode);
            goto error;
        }

        PyObject *Buffered_class = iomodule_get_open_type(slot);
        if (Buffered_class == NULL) {
            assert(buffering == 0);
            if (!binary) {
                PyErr_SetString(PyExc_ValueError,
                                "can't have unbuffered text I/O");
                goto error;
            }
            return result;
        }
        PyObject *bufsize = (unlimited ? Py_NewRef(Py_None)
                                       : PyLong_FromLong(buffering));
        if (bufsize == NULL) {
            Py_DECREF(Buffered_class);
            goto error;
        }
        PyObject *args[] = {raw, bufsize};
        buffer = PyObject_Vectorcall(Buffered_class, args,
                                     Py_ARRAY_LENGTH(args), NULL);
        Py_DECREF(Buffered_class);
        Py_DECREF(bufsize);
    }
    if (buffer == NULL)
        goto error;
    result = buffer;
    Py_DECREF(raw);


    /* if binary, returns the buffered file */
    if (binary) {
        return result;
    }

    modeobj = PyUnicode_FromString(mode);
    if (modeobj == NULL)
        goto error;

    /* wraps into a TextIOWrapper; unbuffered, one that writes through */
    PyObject *Text_class = iomodule_get_open_type(&state->open_text_type);
    if (Text_class == NULL) {
        goto error;
    }
    if (buffering == 0) {
        wrapper = PyObject_CallFunction(Text_class, "OsssOO", buffer,
                                        encoding, errors, newline, Py_False,
                                        Py_True);
    }
    else {
        wrapper = PyObject_CallFunction(
            Text_class, "OsssO", buffer, encoding, errors, newline,
            line_buffering ? Py_True : Py_False);
    }
    Py_DECREF(Text_class);
    if (wrapper == NULL)
        goto error;
    result = wrapper;
    Py_DECREF(buffer);

    if (PyObject_SetAttr(wrapper, &_Py_ID(mode), modeobj) < 0)
        goto error;
    Py_DECREF(modeobj);
    return result;

  error:
    if (result != NULL) {
        PyObject *exc = PyErr_GetRaisedException();
        PyObject *close_result = PyObject_CallMethodNoArgs(result, &_Py_ID(close));
        _PyErr_ChainExceptions1(exc);
        Py_XDECREF(close_result);
        Py_DECREF(result);
    }
    Py_XDECREF(path_or_fd);
    Py_XDECREF(modeobj);
    return NULL;
}


/*[clinic input]
_io.text_encoding
    encoding: object
    stacklevel: int = 2
    /

A helper function to choose the text encoding.

When encoding is not None, this function returns it.
Otherwise, this function returns the default text encoding
(i.e. "locale" or "utf-8" depends on UTF-8 mode).

This function emits an EncodingWarning if encoding is None and
sys.flags.warn_default_encoding is true.

This can be used in APIs with an encoding=None parameter.
However, please consider using encoding="utf-8" for new APIs.
[clinic start generated code]*/

static PyObject *
_io_text_encoding_impl(PyObject *module, PyObject *encoding, int stacklevel)
/*[clinic end generated code: output=91b2cfea6934cc0c input=4999aa8b3d90f3d4]*/
{
    if (encoding == NULL || encoding == Py_None) {
        PyInterpreterState *interp = _PyInterpreterState_GET();
        if (_PyInterpreterState_GetConfig(interp)->warn_default_encoding) {
            if (PyErr_WarnEx(PyExc_EncodingWarning,
                             "'encoding' argument not specified", stacklevel)) {
                return NULL;
            }
        }
        const PyPreConfig *preconfig = &_PyRuntime.preconfig;
        if (preconfig->utf8_mode) {
            _Py_DECLARE_STR(utf_8, "utf-8");
            encoding = &_Py_STR(utf_8);
        }
        else {
            encoding = &_Py_ID(locale);
        }
    }
    return Py_NewRef(encoding);
}


/*[clinic input]
_io.open_code

    path : unicode

Opens the provided file with the intent to import the contents.

This may perform extra validation beyond open(), but is otherwise
interchangeable with calling open(path, 'rb').

[clinic start generated code]*/

static PyObject *
_io_open_code_impl(PyObject *module, PyObject *path)
/*[clinic end generated code: output=2fe4ecbd6f3d6844 input=2803c35aeb63c719]*/
{
    return PyFile_OpenCodeObject(path);
}

/*
 * Private helpers for the io module.
 */

Py_off_t
PyNumber_AsOff_t(PyObject *item, PyObject *err)
{
    Py_off_t result;
    PyObject *runerr;
    PyObject *value = _PyNumber_Index(item);
    if (value == NULL)
        return -1;

    /* We're done if PyLong_AsSsize_t() returns without error. */
    result = PyLong_AsOff_t(value);
    if (result != -1 || !(runerr = PyErr_Occurred()))
        goto finish;

    /* Error handling code -- only manage OverflowError differently */
    if (!PyErr_GivenExceptionMatches(runerr, PyExc_OverflowError))
        goto finish;

    PyErr_Clear();
    /* If no error-handling desired then the default clipping
       is sufficient.
     */
    if (!err) {
        assert(PyLong_Check(value));
        if (_PyLong_IsNegative((PyLongObject *)value))
            result = PY_OFF_T_MIN;
        else
            result = PY_OFF_T_MAX;
    }
    else {
        /* Otherwise replace the error with caller's error object. */
        PyErr_Format(err,
                     "cannot fit '%.200s' into an offset-sized integer",
                     Py_TYPE(item)->tp_name);
    }

 finish:
    Py_DECREF(value);
    return result;
}

/* Store in types new references to _io._nibbler's BufferedReader,
   BufferedWriter, BufferedRandom and TextIOWrapper. */
static int
iomodule_get_nibbler_types(PyObject *module, PyObject *types[4])
{
    PyObject *sub = PyObject_GetAttrString(module, "_nibbler");
    if (sub == NULL) {
        return -1;
    }
    static const char *const names[] = {
        "BufferedReader", "BufferedWriter", "BufferedRandom", "TextIOWrapper",
    };
    for (int i = 0; i < 4; i++) {
        types[i] = PyObject_GetAttrString(sub, names[i]);
        if (types[i] == NULL) {
            for (int j = 0; j < i; j++) {
                Py_DECREF(types[j]);
            }
            Py_DECREF(sub);
            return -1;
        }
    }
    Py_DECREF(sub);
    return 0;
}

/* Point open() at _io's buffered and text classes, or with nibbler set,
   at _io._nibbler's. */
static int
iomodule_set_open_impl(PyObject *module, int nibbler)
{
    _PyIO_State *state = get_io_state(module);
    PyObject *types[4];
    if (nibbler) {
        if (iomodule_get_nibbler_types(module, types) < 0) {
            return -1;
        }
    }
    else {
        types[0] = Py_NewRef(state->PyBufferedReader_Type);
        types[1] = Py_NewRef(state->PyBufferedWriter_Type);
        types[2] = Py_NewRef(state->PyBufferedRandom_Type);
        types[3] = Py_NewRef(state->PyTextIOWrapper_Type);
    }
    iomodule_set_open_type(&state->open_reader_type, types[0]);
    iomodule_set_open_type(&state->open_writer_type, types[1]);
    iomodule_set_open_type(&state->open_random_type, types[2]);
    iomodule_set_open_type(&state->open_text_type, types[3]);
    return 0;
}

/* Make open(buffering=0) return the raw file, or with nibbler set, wrap it
   in _io._nibbler's classes with buffer size 0. */
static int
iomodule_set_unbuffered_impl(PyObject *module, int nibbler)
{
    _PyIO_State *state = get_io_state(module);
    PyObject *types[4] = {NULL, NULL, NULL, NULL};
    if (nibbler && iomodule_get_nibbler_types(module, types) < 0) {
        return -1;
    }
    Py_XDECREF(types[3]);
    iomodule_set_open_type(&state->open_unbuffered_reader_type, types[0]);
    iomodule_set_open_type(&state->open_unbuffered_writer_type, types[1]);
    iomodule_set_open_type(&state->open_unbuffered_random_type, types[2]);
    return 0;
}

/* Parse the name of an implementation: 1 for "_nibbler", 0 for "_io", -1
   with ValueError otherwise. */
static int
iomodule_parse_impl(PyObject *name)
{
    if (PyUnicode_EqualToUTF8(name, "_nibbler")) {
        return 1;
    }
    if (PyUnicode_EqualToUTF8(name, "_io")) {
        return 0;
    }
    PyErr_Format(PyExc_ValueError, "unknown implementation %R", name);
    return -1;
}

/*[clinic input]
_io._set_open_impl
    name: unicode
    /

Make open() use the "_io" or "_nibbler" buffered and text classes.

Returns the previous name.  For tests.
[clinic start generated code]*/

static PyObject *
_io__set_open_impl_impl(PyObject *module, PyObject *name)
/*[clinic end generated code: output=da5db966fe58f749 input=a8efd7e301a3bde5]*/
{
    _PyIO_State *state = get_io_state(module);
    int was_nibbler = (FT_ATOMIC_LOAD_PTR_RELAXED(state->open_reader_type)
                       != state->PyBufferedReader_Type);
    int nibbler = iomodule_parse_impl(name);
    if (nibbler < 0 || iomodule_set_open_impl(module, nibbler) < 0) {
        return NULL;
    }
    return PyUnicode_FromString(was_nibbler ? "_nibbler" : "_io");
}

/*[clinic input]
_io._set_unbuffered_impl
    name: unicode
    /

Choose what binary open(buffering=0) returns: "_io" or "_nibbler".

With "_io", it returns the raw file.  With "_nibbler", it returns an
_io._nibbler BufferedReader, BufferedWriter or BufferedRandom (by mode)
with buffer size 0 wrapping it.  Returns the previous name.  For tests.
[clinic start generated code]*/

static PyObject *
_io__set_unbuffered_impl_impl(PyObject *module, PyObject *name)
/*[clinic end generated code: output=b7203c8226b4eb18 input=d3251f2c9b3103e5]*/
{
    _PyIO_State *state = get_io_state(module);
    int was_nibbler = (FT_ATOMIC_LOAD_PTR_RELAXED(
                           state->open_unbuffered_reader_type) != NULL);
    int nibbler = iomodule_parse_impl(name);
    if (nibbler < 0 || iomodule_set_unbuffered_impl(module, nibbler) < 0) {
        return NULL;
    }
    return PyUnicode_FromString(was_nibbler ? "_nibbler" : "_io");
}

static int
iomodule_traverse(PyObject *mod, visitproc visit, void *arg) {
    _PyIO_State *state = get_io_state(mod);
    Py_VISIT(state->unsupported_operation);

    Py_VISIT(state->PyIOBase_Type);
    Py_VISIT(state->PyIncrementalNewlineDecoder_Type);
    Py_VISIT(state->PyRawIOBase_Type);
    Py_VISIT(state->PyBufferedIOBase_Type);
    Py_VISIT(state->PyBufferedRWPair_Type);
    Py_VISIT(state->PyBufferedRandom_Type);
    Py_VISIT(state->PyBufferedReader_Type);
    Py_VISIT(state->PyBufferedWriter_Type);
    Py_VISIT(state->PyBytesIOBuffer_Type);
    Py_VISIT(state->PyBytesIO_Type);
    Py_VISIT(state->PyFileIO_Type);
    Py_VISIT(state->PyStringIO_Type);
    Py_VISIT(state->PyTextIOBase_Type);
    Py_VISIT(state->PyTextIOWrapper_Type);
    Py_VISIT(state->open_reader_type);
    Py_VISIT(state->open_writer_type);
    Py_VISIT(state->open_random_type);
    Py_VISIT(state->open_text_type);
    Py_VISIT(state->open_unbuffered_reader_type);
    Py_VISIT(state->open_unbuffered_writer_type);
    Py_VISIT(state->open_unbuffered_random_type);
#ifdef HAVE_WINDOWS_CONSOLE_IO
    Py_VISIT(state->PyWindowsConsoleIO_Type);
#endif
    return 0;
}


static int
iomodule_clear(PyObject *mod) {
    _PyIO_State *state = get_io_state(mod);
    Py_CLEAR(state->unsupported_operation);

    Py_CLEAR(state->PyIOBase_Type);
    Py_CLEAR(state->PyIncrementalNewlineDecoder_Type);
    Py_CLEAR(state->PyRawIOBase_Type);
    Py_CLEAR(state->PyBufferedIOBase_Type);
    Py_CLEAR(state->PyBufferedRWPair_Type);
    Py_CLEAR(state->PyBufferedRandom_Type);
    Py_CLEAR(state->PyBufferedReader_Type);
    Py_CLEAR(state->PyBufferedWriter_Type);
    Py_CLEAR(state->PyBytesIOBuffer_Type);
    Py_CLEAR(state->PyBytesIO_Type);
    Py_CLEAR(state->PyFileIO_Type);
    Py_CLEAR(state->PyStringIO_Type);
    Py_CLEAR(state->PyTextIOBase_Type);
    Py_CLEAR(state->PyTextIOWrapper_Type);
    Py_CLEAR(state->open_reader_type);
    Py_CLEAR(state->open_writer_type);
    Py_CLEAR(state->open_random_type);
    Py_CLEAR(state->open_text_type);
    Py_CLEAR(state->open_unbuffered_reader_type);
    Py_CLEAR(state->open_unbuffered_writer_type);
    Py_CLEAR(state->open_unbuffered_random_type);
#ifdef HAVE_WINDOWS_CONSOLE_IO
    Py_CLEAR(state->PyWindowsConsoleIO_Type);
#endif
    return 0;
}

static void
iomodule_free(void *mod)
{
    (void)iomodule_clear((PyObject *)mod);
}


/*
 * Module definition
 */

#define clinic_state() (get_io_state(module))
#include "clinic/_iomodule.c.h"
#undef clinic_state

static PyMethodDef module_methods[] = {
    _IO_OPEN_METHODDEF
    _IO_TEXT_ENCODING_METHODDEF
    _IO_OPEN_CODE_METHODDEF
    _IO__SET_OPEN_IMPL_METHODDEF
    _IO__SET_UNBUFFERED_IMPL_METHODDEF
    {NULL, NULL}
};

#define ADD_TYPE(module, type, spec, base)                               \
do {                                                                     \
    type = (PyTypeObject *)PyType_FromModuleAndSpec(module, spec,        \
                                                    (PyObject *)base);   \
    if (type == NULL) {                                                  \
        return -1;                                                       \
    }                                                                    \
    if (PyModule_AddType(module, type) < 0) {                            \
        return -1;                                                       \
    }                                                                    \
} while (0)

static int
iomodule_exec(PyObject *m)
{
    _PyIO_State *state = get_io_state(m);

    /* DEFAULT_BUFFER_SIZE */
    if (PyModule_AddIntMacro(m, DEFAULT_BUFFER_SIZE) < 0)
        return -1;

    /* UnsupportedOperation inherits from ValueError and OSError */
    state->unsupported_operation = PyObject_CallFunction(
        (PyObject *)&PyType_Type, "s(OO){}",
        "UnsupportedOperation", PyExc_OSError, PyExc_ValueError);
    if (state->unsupported_operation == NULL)
        return -1;
    if (PyObject_SetAttrString(state->unsupported_operation,
                               "__module__", &_Py_ID(io)) < 0)
    {
        return -1;
    }
    if (PyModule_AddObjectRef(m, "UnsupportedOperation",
                              state->unsupported_operation) < 0)
    {
        return -1;
    }

    /* BlockingIOError, for compatibility */
    if (PyModule_AddObjectRef(m, "BlockingIOError",
                              (PyObject *) PyExc_BlockingIOError) < 0) {
        return -1;
    }

    // Base classes
    ADD_TYPE(m, state->PyIncrementalNewlineDecoder_Type, &_Py_nldecoder_spec, NULL);
    ADD_TYPE(m, state->PyBytesIOBuffer_Type, &_Py_bytesiobuf_spec, NULL);
    ADD_TYPE(m, state->PyIOBase_Type, &_Py_iobase_spec, NULL);

    // PyIOBase_Type subclasses
    ADD_TYPE(m, state->PyTextIOBase_Type, &_Py_textiobase_spec,
             state->PyIOBase_Type);
    ADD_TYPE(m, state->PyBufferedIOBase_Type, &_Py_bufferediobase_spec,
             state->PyIOBase_Type);
    ADD_TYPE(m, state->PyRawIOBase_Type, &_Py_rawiobase_spec,
             state->PyIOBase_Type);

    // PyBufferedIOBase_Type(PyIOBase_Type) subclasses
    ADD_TYPE(m, state->PyBytesIO_Type, &_Py_bytesio_spec, state->PyBufferedIOBase_Type);
    ADD_TYPE(m, state->PyBufferedWriter_Type, &_Py_bufferedwriter_spec,
             state->PyBufferedIOBase_Type);
    ADD_TYPE(m, state->PyBufferedReader_Type, &_Py_bufferedreader_spec,
             state->PyBufferedIOBase_Type);
    ADD_TYPE(m, state->PyBufferedRWPair_Type, &_Py_bufferedrwpair_spec,
             state->PyBufferedIOBase_Type);
    ADD_TYPE(m, state->PyBufferedRandom_Type, &_Py_bufferedrandom_spec,
             state->PyBufferedIOBase_Type);

    // PyRawIOBase_Type(PyIOBase_Type) subclasses
    ADD_TYPE(m, state->PyFileIO_Type, &_Py_fileio_spec, state->PyRawIOBase_Type);

#ifdef HAVE_WINDOWS_CONSOLE_IO
    ADD_TYPE(m, state->PyWindowsConsoleIO_Type, &_Py_winconsoleio_spec,
             state->PyRawIOBase_Type);
#endif

    // PyTextIOBase_Type(PyIOBase_Type) subclasses
    ADD_TYPE(m, state->PyStringIO_Type, &_Py_stringio_spec, state->PyTextIOBase_Type);
    ADD_TYPE(m, state->PyTextIOWrapper_Type, &_Py_textiowrapper_spec,
             state->PyTextIOBase_Type);

#undef ADD_TYPE

    // _PYTHON_IO_DEFAULT_IMPL=_nibbler (honors -E / -I) makes the
    // _io._nibbler classes _io's buffered and text classes, so
    // io.BufferedReader, io.TextIOWrapper, isinstance() checks, open() and
    // the standard streams all use them.
    PyInterpreterState *interp = _PyInterpreterState_GET();
    const PyConfig *config = _PyInterpreterState_GetConfig(interp);
    const char *env = config->use_environment
        ? getenv("_PYTHON_IO_DEFAULT_IMPL") : NULL;
    int nibbler = env != NULL && strcmp(env, "_nibbler") == 0;

    // Create the _io._nibbler submodule (after IOBase/FileIO are registered).
    if (_PyIO_create_nibbler_submodule(m, nibbler) == NULL) {
        return -1;
    }
    if (iomodule_set_open_impl(m, nibbler) < 0) {
        return -1;
    }
    // _PYTHON_IO_UNBUFFERED_IMPL=_nibbler (also honors -E / -I) makes
    // open(buffering=0) wrap the raw file in the _io._nibbler classes with
    // buffer size 0.
    env = config->use_environment
        ? getenv("_PYTHON_IO_UNBUFFERED_IMPL") : NULL;
    if (env != NULL && strcmp(env, "_nibbler") == 0
        && iomodule_set_unbuffered_impl(m, 1) < 0)
    {
        return -1;
    }
    if (nibbler) {
        PyObject *sub = PyObject_GetAttrString(m, "_nibbler");
        if (sub == NULL) {
            return -1;
        }
        static const char *const names[] = {
            "BufferedReader", "BufferedWriter", "BufferedRandom",
            "BufferedRWPair", "TextIOWrapper",
        };
        for (size_t i = 0; i < Py_ARRAY_LENGTH(names); i++) {
            PyObject *cls = PyObject_GetAttrString(sub, names[i]);
            if (cls == NULL || PyObject_SetAttrString(m, names[i], cls) < 0) {
                Py_XDECREF(cls);
                Py_DECREF(sub);
                return -1;
            }
            Py_DECREF(cls);
        }
        Py_DECREF(sub);
    }

    return 0;
}

static struct PyModuleDef_Slot iomodule_slots[] = {
    _Py_ABI_SLOT,
    {Py_mod_exec, iomodule_exec},
    {Py_mod_multiple_interpreters, Py_MOD_PER_INTERPRETER_GIL_SUPPORTED},
    {Py_mod_gil, Py_MOD_GIL_NOT_USED},
    {0, NULL},
};

struct PyModuleDef _PyIO_Module = {
    .m_base = PyModuleDef_HEAD_INIT,
    .m_name = "io",
    .m_doc = module_doc,
    .m_size = sizeof(_PyIO_State),
    .m_methods = module_methods,
    .m_traverse = iomodule_traverse,
    .m_clear = iomodule_clear,
    .m_free = iomodule_free,
    .m_slots = iomodule_slots,
};

PyMODINIT_FUNC
PyInit__io(void)
{
    return PyModuleDef_Init(&_PyIO_Module);
}

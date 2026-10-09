/*
 * Declarations shared between the different parts of the io module
 */

#include "exports.h"

#include "pycore_fileutils.h"     // Py_off_t
#include "pycore_moduleobject.h"  // _PyModule_GetState()
#include "pycore_typeobject.h"    // _PyType_GetModuleState()
#include "structmember.h"

/* Type specs */
extern PyType_Spec _Py_bufferediobase_spec;
extern PyType_Spec _Py_bufferedrandom_spec;
extern PyType_Spec _Py_bufferedreader_spec;
extern PyType_Spec _Py_bufferedrwpair_spec;
extern PyType_Spec _Py_bufferedwriter_spec;
extern PyType_Spec _Py_bytesio_spec;
extern PyType_Spec _Py_bytesiobuf_spec;
extern PyType_Spec _Py_fileio_spec;
extern PyType_Spec _Py_iobase_spec;
extern PyType_Spec _Py_nldecoder_spec;
extern PyType_Spec _Py_rawiobase_spec;
extern PyType_Spec _Py_stringio_spec;
extern PyType_Spec _Py_textiobase_spec;
extern PyType_Spec _Py_textiowrapper_spec;

#ifdef HAVE_WINDOWS_CONSOLE_IO
extern PyType_Spec _Py_winconsoleio_spec;
#endif

/* These functions are used as METH_NOARGS methods, are normally called
 * with args=NULL, and return a new reference.
 * BUT when args=Py_True is passed, they return a borrowed reference.
 */
typedef struct _io_state _PyIO_State;  // Forward decl.
extern PyObject* _PyIOBase_check_readable(_PyIO_State *state,
                                          PyObject *self, PyObject *args);
extern PyObject* _PyIOBase_check_writable(_PyIO_State *state,
                                          PyObject *self, PyObject *args);
extern PyObject* _PyIOBase_check_seekable(_PyIO_State *state,
                                          PyObject *self, PyObject *args);
extern PyObject* _PyIOBase_check_closed(PyObject *self, PyObject *args);

/* Helper for finalization.
   This function will revive an object ready to be deallocated and try to
   close() it. It returns 0 if the object can be destroyed, or -1 if it
   is alive again. */
extern int _PyIOBase_finalize(PyObject *self);

/* Returns true if the given FileIO object is closed.
   Doesn't check the argument type, so be careful! */
extern int _PyFileIO_closed(PyObject *self);

/* Direct calls into an exact FileIO for the buffered layer.  The
   Py_ssize_t ones return the byte count, -2 if a non-blocking file would
   block, or -1 with an exception set. */
extern Py_ssize_t _PyFileIO_readinto(PyObject *self, char *buf,
                                     Py_ssize_t len);
/* Most buffers passed to one vectored write. */
enum { _PyIO_WRITEV_MAX = 64 };

/* A run of bytes for a vectored write. */
typedef struct {
    const char *ptr;
    Py_ssize_t len;
} _PyIO_Span;
/* Write spans[0:cnt] with one writev() (or, without it, write() the first
   span); fewer bytes may be written. */
extern Py_ssize_t _PyFileIO_writev(PyObject *self, const _PyIO_Span *spans,
                                   Py_ssize_t cnt);
extern PyObject *_PyFileIO_readall(PyObject *self);
/* flush() and close() of an exact FileIO; instance attribute overrides
   are still called.  _PyFileIO_flush() returns 0 or -1. */
extern int _PyFileIO_flush(PyObject *self);
extern PyObject *_PyFileIO_close(PyObject *self);
/* Raise like _PyIOBase_check_readable()/_writable() unless the FileIO is
   open and allows the requested access. */
extern int _PyFileIO_check_access(PyObject *self, int reading, int writing);
/* Was the FileIO (or subclass) opened in append mode? */
extern int _PyFileIO_appending(PyObject *self);

/* Byte-level access to an exact _io._nibbler buffered object, for
   TextIOWrapper: it decodes straight from the read-ahead and appends
   encoded text without method calls (see "Bytes for TextIOWrapper" in
   _nibbler/bufferedio.c).  Functions returning int return 0 on success,
   -1 with an exception set, or _PyIO_NIBBLER_NO (nothing done) when the
   object must be used through its methods instead. */
#define _PyIO_NIBBLER_NO (-3)

/* A run of bytes inside the bytes object obj, which keeps them alive. */
typedef struct {
    PyObject *obj;
    const char *ptr;
    Py_ssize_t len;
} _PyIO_Morsel;

/* The unread bytes, without taking them: at least `need` (reading more,
   after them, when fewer are unread) unless the raw stream reached EOF or
   would block.  *m gets a new reference (obj is NULL when len is 0). */
extern int _PyIONibbler_peek(PyObject *buffered, Py_ssize_t need,
                             _PyIO_Morsel *m);
/* Take the first n bytes of what _PyIONibbler_peek() gave in *m.  Returns
   1, or 0 (nothing taken) if they are no longer the unread bytes. */
extern int _PyIONibbler_consume(PyObject *buffered, const _PyIO_Morsel *m,
                                Py_ssize_t n);
/* A copy of the n bytes read last (before the unread ones), or NULL
   without an exception when they are no longer buffered. */
extern PyObject *_PyIONibbler_lookback(PyObject *buffered, Py_ssize_t n);
/* Like write(obj), for data[0:len] owned by obj, except that it returns
   _PyIO_NIBBLER_NO instead of waiting for another thread's lock. */
extern int _PyIONibbler_write(PyObject *buffered, PyObject *obj,
                              const char *data, Py_ssize_t len);

/* Shortcut to the core of the IncrementalNewlineDecoder.decode method */
extern PyObject *_PyIncrementalNewlineDecoder_decode(
    PyObject *self, PyObject *input, int final);

/* Finds the first line ending between `start` and `end`.
   If found, returns the index after the line ending and doesn't touch
   `*consumed`.
   If not found, returns -1 and sets `*consumed` to the number of characters
   which can be safely put aside until another search.

   NOTE: for performance reasons, `end` must point to a NUL character ('\0').
   Otherwise, the function will scan further and return garbage.

   There are three modes, in order of priority:
   * translated: Only find \n (assume newlines already translated)
   * universal: Use universal newlines algorithm
   * Otherwise, the line ending is specified by readnl, a str object */
extern Py_ssize_t _PyIO_find_line_ending(
    int translated, int universal, PyObject *readnl,
    int kind, const char *start, const char *end, Py_ssize_t *consumed);

/* Return 1 if an OSError with errno == EINTR is set (and then
   clears the error indicator), 0 otherwise.
   Should only be called when PyErr_Occurred() is true.
*/
extern int _PyIO_trap_eintr(void);

#define DEFAULT_BUFFER_SIZE (128 * 1024)  /* bytes */

/*
 * Offset type for positioning.
 */

/* Printing a variable of type off_t (with e.g., PyUnicode_FromFormat)
   correctly and without producing compiler warnings is surprisingly painful.
   We identify an integer type whose size matches off_t and then: (1) cast the
   off_t to that integer type and (2) use the appropriate conversion
   specification.  The cast is necessary: gcc complains about formatting a
   long with "%lld" even when both long and long long have the same
   precision. */

#ifdef MS_WINDOWS

# define PyLong_AsOff_t     PyLong_AsLongLong
# define PyLong_FromOff_t   PyLong_FromLongLong
# define PY_OFF_T_MAX       LLONG_MAX
# define PY_OFF_T_MIN       LLONG_MIN
# define PY_OFF_T_COMPAT    long long    /* type compatible with off_t */
# define PY_PRIdOFF         "lld"        /* format to use for that type */

#else

/* Other platforms use off_t */
#if (SIZEOF_OFF_T == SIZEOF_SIZE_T)
# define PyLong_AsOff_t     PyLong_AsSsize_t
# define PyLong_FromOff_t   PyLong_FromSsize_t
# define PY_OFF_T_MAX       PY_SSIZE_T_MAX
# define PY_OFF_T_MIN       PY_SSIZE_T_MIN
# define PY_OFF_T_COMPAT    Py_ssize_t
# define PY_PRIdOFF         "zd"
#elif (SIZEOF_OFF_T == SIZEOF_LONG_LONG)
# define PyLong_AsOff_t     PyLong_AsLongLong
# define PyLong_FromOff_t   PyLong_FromLongLong
# define PY_OFF_T_MAX       LLONG_MAX
# define PY_OFF_T_MIN       LLONG_MIN
# define PY_OFF_T_COMPAT    long long
# define PY_PRIdOFF         "lld"
#elif (SIZEOF_OFF_T == SIZEOF_LONG)
# define PyLong_AsOff_t     PyLong_AsLong
# define PyLong_FromOff_t   PyLong_FromLong
# define PY_OFF_T_MAX       LONG_MAX
# define PY_OFF_T_MIN       LONG_MIN
# define PY_OFF_T_COMPAT    long
# define PY_PRIdOFF         "ld"
#else
# error off_t does not match either size_t, long, or long long!
#endif

#endif

extern Py_off_t PyNumber_AsOff_t(PyObject *item, PyObject *err);

/* Implementation details */

/* IO module structure */

extern PyModuleDef _PyIO_Module;

struct _io_state {
    int initialized;
    PyObject *unsupported_operation;

    /* Types */
    PyTypeObject *PyIOBase_Type;
    PyTypeObject *PyIncrementalNewlineDecoder_Type;
    PyTypeObject *PyRawIOBase_Type;
    PyTypeObject *PyBufferedIOBase_Type;
    PyTypeObject *PyBufferedRWPair_Type;
    PyTypeObject *PyBufferedRandom_Type;
    PyTypeObject *PyBufferedReader_Type;
    PyTypeObject *PyBufferedWriter_Type;
    PyTypeObject *PyBytesIOBuffer_Type;
    PyTypeObject *PyBytesIO_Type;
    PyTypeObject *PyFileIO_Type;
    PyTypeObject *PyStringIO_Type;
    PyTypeObject *PyTextIOBase_Type;
    PyTypeObject *PyTextIOWrapper_Type;
#ifdef HAVE_WINDOWS_CONSOLE_IO
    PyTypeObject *PyWindowsConsoleIO_Type;
#endif

    /* The buffered classes open() uses: _io's own, or _io._nibbler's. */
    PyTypeObject *open_reader_type;
    PyTypeObject *open_writer_type;
    PyTypeObject *open_random_type;
};

static inline _PyIO_State *
get_io_state(PyObject *module)
{
    void *state = _PyModule_GetState(module);
    assert(state != NULL);
    return (_PyIO_State *)state;
}

static inline _PyIO_State *
get_io_state_by_cls(PyTypeObject *cls)
{
    void *state = _PyType_GetModuleState(cls);
    assert(state != NULL);
    return (_PyIO_State *)state;
}

static inline _PyIO_State *
find_io_state_by_def(PyTypeObject *type)
{
    PyObject *mod = PyType_GetModuleByDef(type, &_PyIO_Module);
    assert(mod != NULL);
    return get_io_state(mod);
}

extern PyObject *_PyIOBase_cannot_pickle(PyObject *self, PyObject *args);

/* Create and register the _io._nibbler submodule. */
extern PyObject *_PyIO_create_nibbler_submodule(PyObject *io_module,
                                                int as_io);
/* Is the type exactly one of the _io._nibbler buffered classes? */
extern int _PyIO_is_nibbler_buffered_type(PyTypeObject *tp);

#ifdef HAVE_WINDOWS_CONSOLE_IO
extern char _PyIO_get_console_type(PyObject *);
#endif

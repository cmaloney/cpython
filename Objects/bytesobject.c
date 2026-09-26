/* bytes object implementation */

#include "Python.h"
#include "pycore_abstract.h"      // _PyIndex_Check()
#include "pycore_bytes_methods.h" // _Py_bytes_startswith()
#include "pycore_bytesobject.h"   // _PyBytes_Find(), _PyBytes_RepeatBuffer()
#include "pycore_call.h"          // _PyObject_CallNoArgs()
#include "pycore_ceval.h"         // _PyEval_GetBuiltin()
#include "pycore_format.h"        // F_LJUST
#include "pycore_freelist.h"      // _Py_FREELIST_FREE()
#include "pycore_global_objects.h"// _Py_GET_GLOBAL_OBJECT()
#include "pycore_initconfig.h"    // _PyStatus_OK()
#include "pycore_long.h"          // _PyLong_DigitValue
#include "pycore_list.h"          // _PyList_GetItemRef
#include "pycore_object.h"        // _PyObject_GC_TRACK
#include "pycore_pymem.h"         // PYMEM_CLEANBYTE
#include "pycore_pyspec.h"        // _PySpecCallTable
#include "pycore_strhex.h"        // _Py_strhex_with_sep()
#include "pycore_unicodeobject.h" // _PyUnicode_FormatLong()

#include <stddef.h>

/*[clinic input]
class bytes "PyBytesObject *" "&PyBytes_Type"
[clinic start generated code]*/
/*[clinic end generated code: output=da39a3ee5e6b4b0d input=7a238f965d64892b]*/

/* The methods of bytes are declared in Objects/pyspec/bytesobject.py.
   Argument Clinic generates their argument parsing and the prototype of
   each bytes_<name>_impl() defined below into clinic/bytesobject.c.h. */
#include "clinic/bytesobject.c.h"

#define PyBytesObject_SIZE _PyBytesObject_SIZE

/* Forward declaration */
static void* _PyBytesWriter_ResizeAndUpdatePointer(PyBytesWriter *writer,
                                                   Py_ssize_t size, void *data);
static Py_ssize_t _PyBytesWriter_ResizeToAllocated(PyBytesWriter *writer);


#define CHARACTERS _Py_SINGLETON(bytes_characters)
#define CHARACTER(ch) \
     ((PyBytesObject *)&(CHARACTERS[ch]))
#define EMPTY (&_Py_SINGLETON(bytes_empty))


// Return a reference to the immortal empty bytes string singleton.
static inline PyObject* bytes_get_empty(void)
{
    PyObject *empty = &EMPTY->ob_base.ob_base;
    assert(_Py_IsImmortal(empty));
    return empty;
}


static inline void
set_ob_shash(PyBytesObject *a, Py_hash_t hash)
{
_Py_COMP_DIAG_PUSH
_Py_COMP_DIAG_IGNORE_DEPR_DECLS
#ifdef Py_GIL_DISABLED
    _Py_atomic_store_ssize_relaxed(&a->ob_shash, hash);
#else
    a->ob_shash = hash;
#endif
_Py_COMP_DIAG_POP
}

static inline Py_hash_t
get_ob_shash(PyBytesObject *a)
{
_Py_COMP_DIAG_PUSH
_Py_COMP_DIAG_IGNORE_DEPR_DECLS
#ifdef Py_GIL_DISABLED
    return _Py_atomic_load_ssize_relaxed(&a->ob_shash);
#else
    return a->ob_shash;
#endif
_Py_COMP_DIAG_POP
}


/*
   For PyBytes_FromString(), the parameter 'str' points to a null-terminated
   string containing exactly 'size' bytes.

   For PyBytes_FromStringAndSize(), the parameter 'str' is
   either NULL or else points to a string containing at least 'size' bytes.
   For PyBytes_FromStringAndSize(), the string in the 'str' parameter does
   not have to be null-terminated.  (Therefore it is safe to construct a
   substring by calling 'PyBytes_FromStringAndSize(origstring, substrlen)'.)
   If 'str' is NULL then PyBytes_FromStringAndSize() will allocate 'size+1'
   bytes (setting the last byte to the null terminating character) and you can
   fill in the data yourself.  If 'str' is non-NULL then the resulting
   PyBytes object must be treated as immutable and you must not fill in nor
   alter the data yourself, since the strings may be shared.

   The PyObject member 'op->ob_size', which denotes the number of "extra
   items" in a variable-size object, will contain the number of bytes
   allocated for string data, not counting the null terminating character.
   It is therefore equal to the 'size' parameter (for
   PyBytes_FromStringAndSize()) or the length of the string in the 'str'
   parameter (for PyBytes_FromString()).
*/
static PyObject *
_PyBytes_FromSize(Py_ssize_t size, int use_calloc)
{
    PyBytesObject *op;
    assert(size >= 0);

    if (size == 0) {
        return bytes_get_empty();
    }

    if ((size_t)size > (size_t)PY_SSIZE_T_MAX - PyBytesObject_SIZE) {
        PyErr_SetString(PyExc_OverflowError,
                        "byte string is too large");
        return NULL;
    }

    /* Inline PyObject_NewVar */
    if (use_calloc)
        op = (PyBytesObject *)PyObject_Calloc(1, PyBytesObject_SIZE + size);
    else
        op = (PyBytesObject *)PyObject_Malloc(PyBytesObject_SIZE + size);
    if (op == NULL) {
        return PyErr_NoMemory();
    }
    _PyObject_InitVar((PyVarObject*)op, &PyBytes_Type, size);
    set_ob_shash(op, -1);
    if (!use_calloc) {
        op->ob_sval[size] = '\0';
    }
    return (PyObject *) op;
}

PyObject *
PyBytes_FromStringAndSize(const char *str, Py_ssize_t size)
{
    PyBytesObject *op;
    if (size < 0) {
        PyErr_SetString(PyExc_SystemError,
            "Negative size passed to PyBytes_FromStringAndSize");
        return NULL;
    }
    if (size == 1 && str != NULL) {
        op = CHARACTER(*str & 255);
        assert(_Py_IsImmortal(op));
        return (PyObject *)op;
    }
    if (size == 0) {
        return bytes_get_empty();
    }

    op = (PyBytesObject *)_PyBytes_FromSize(size, 0);
    if (op == NULL)
        return NULL;
    if (str == NULL)
        return (PyObject *) op;

    memcpy(op->ob_sval, str, size);
    return (PyObject *) op;
}

PyObject *
PyBytes_FromString(const char *str)
{
    size_t size;
    PyBytesObject *op;

    assert(str != NULL);
    size = strlen(str);
    if (size > PY_SSIZE_T_MAX - PyBytesObject_SIZE) {
        PyErr_SetString(PyExc_OverflowError,
            "byte string is too long");
        return NULL;
    }

    if (size == 0) {
        return bytes_get_empty();
    }
    else if (size == 1) {
        op = CHARACTER(*str & 255);
        assert(_Py_IsImmortal(op));
        return (PyObject *)op;
    }

    /* Inline PyObject_NewVar */
    op = (PyBytesObject *)PyObject_Malloc(PyBytesObject_SIZE + size);
    if (op == NULL) {
        return PyErr_NoMemory();
    }
    _PyObject_InitVar((PyVarObject*)op, &PyBytes_Type, size);
    set_ob_shash(op, -1);
    memcpy(op->ob_sval, str, size+1);
    return (PyObject *) op;
}


static char*
bytes_fromformat(PyBytesWriter *writer, Py_ssize_t writer_pos,
                 const char *format, va_list vargs)
{
    const char *f;
    const char *p;
    Py_ssize_t prec;
    int longflag;
    int size_tflag;
    /* Longest 64-bit formatted numbers:
       - "18446744073709551615\0" (21 bytes)
       - "-9223372036854775808\0" (21 bytes)
       Decimal takes the most space (it isn't enough for octal.)

       Longest 64-bit pointer representation:
       "0xffffffffffffffff\0" (19 bytes). */
    char buffer[21];

    char *s = (char*)PyBytesWriter_GetData(writer) + writer_pos;

#define WRITE_BYTES_LEN(str, len_expr) \
    do { \
        size_t len = (len_expr); \
        s = PyBytesWriter_GrowAndUpdatePointer(writer, len, s); \
        if (s == NULL) { \
            goto error; \
        } \
        memcpy(s, (str), len); \
        s += len; \
    } while (0)
#define WRITE_BYTES(str) WRITE_BYTES_LEN(str, strlen(str))

    for (f = format; *f; f++) {
        if (*f != '%') {
            *s++ = *f;
            continue;
        }

        p = f++;

        /* ignore the width (ex: 10 in "%10s") */
        while (Py_ISDIGIT(*f))
            f++;

        /* parse the precision (ex: 10 in "%.10s") */
        prec = 0;
        if (*f == '.') {
            f++;
            for (; Py_ISDIGIT(*f); f++) {
                prec = (prec * 10) + (*f - '0');
            }
        }

        while (*f && *f != '%' && !Py_ISALPHA(*f))
            f++;

        /* handle the long flag ('l'), but only for %ld and %lu.
           others can be added when necessary. */
        longflag = 0;
        if (*f == 'l' && (f[1] == 'd' || f[1] == 'u')) {
            longflag = 1;
            ++f;
        }

        /* handle the size_t flag ('z'). */
        size_tflag = 0;
        if (*f == 'z' && (f[1] == 'd' || f[1] == 'u')) {
            size_tflag = 1;
            ++f;
        }

        switch (*f) {
        case 'c':
        {
            int c = va_arg(vargs, int);
            if (c < 0 || c > 255) {
                PyErr_SetString(PyExc_OverflowError,
                                "PyBytes_FromFormatV(): %c format "
                                "expects an integer in range [0; 255]");
                goto error;
            }
            *s++ = (unsigned char)c;
            break;
        }

        case 'd':
            if (longflag) {
                sprintf(buffer, "%ld", va_arg(vargs, long));
            }
            else if (size_tflag) {
                sprintf(buffer, "%zd", va_arg(vargs, Py_ssize_t));
            }
            else {
                sprintf(buffer, "%d", va_arg(vargs, int));
            }
            assert(strlen(buffer) < sizeof(buffer));
            WRITE_BYTES(buffer);
            break;

        case 'u':
            if (longflag) {
                sprintf(buffer, "%lu", va_arg(vargs, unsigned long));
            }
            else if (size_tflag) {
                sprintf(buffer, "%zu", va_arg(vargs, size_t));
            }
            else {
                sprintf(buffer, "%u", va_arg(vargs, unsigned int));
            }
            assert(strlen(buffer) < sizeof(buffer));
            WRITE_BYTES(buffer);
            break;

        case 'i':
            sprintf(buffer, "%i", va_arg(vargs, int));
            assert(strlen(buffer) < sizeof(buffer));
            WRITE_BYTES(buffer);
            break;

        case 'x':
            sprintf(buffer, "%x", va_arg(vargs, int));
            assert(strlen(buffer) < sizeof(buffer));
            WRITE_BYTES(buffer);
            break;

        case 's':
        {
            Py_ssize_t i;

            p = va_arg(vargs, const char*);
            if (prec <= 0) {
                i = strlen(p);
            }
            else {
                i = 0;
                while (i < prec && p[i]) {
                    i++;
                }
            }
            WRITE_BYTES_LEN(p, i);
            break;
        }

        case 'p':
            sprintf(buffer, "%p", va_arg(vargs, void*));
            assert(strlen(buffer) < sizeof(buffer));
            /* %p is ill-defined:  ensure leading 0x. */
            if (buffer[1] == 'X')
                buffer[1] = 'x';
            else if (buffer[1] != 'x') {
                memmove(buffer+2, buffer, strlen(buffer)+1);
                buffer[0] = '0';
                buffer[1] = 'x';
            }
            WRITE_BYTES(buffer);
            break;

        case '%':
            *s++ = '%';
            break;

        default:
            /* invalid format string: copy unformatted string and exit */
            WRITE_BYTES(p);
            return s;
        }
    }

#undef WRITE_BYTES
#undef WRITE_BYTES_LEN

    return s;

 error:
    return NULL;
}


PyObject *
PyBytes_FromFormatV(const char *format, va_list vargs)
{
    Py_ssize_t alloc = strlen(format);
    PyBytesWriter *writer = PyBytesWriter_Create(alloc);
    if (writer == NULL) {
        return NULL;
    }

    char *s = bytes_fromformat(writer, 0, format, vargs);
    if (s == NULL) {
        PyBytesWriter_Discard(writer);
        return NULL;
    }

    return PyBytesWriter_FinishWithPointer(writer, s);
}


PyObject *
PyBytes_FromFormat(const char *format, ...)
{
    PyObject* ret;
    va_list vargs;

    va_start(vargs, format);
    ret = PyBytes_FromFormatV(format, vargs);
    va_end(vargs);
    return ret;
}


/* Helpers for formatstring */

#define FORMAT_ERROR(EXC, FMT, ...) do {                                    \
    if (key != NULL) {                                                      \
        PyErr_Format((EXC), "format argument %R: " FMT,                     \
                     key, __VA_ARGS__);                                     \
    }                                                                       \
    else if (argidx >= 0) {                                                 \
        PyErr_Format((EXC), "format argument %zd: " FMT,                    \
                     argidx, __VA_ARGS__);                                  \
    }                                                                       \
    else {                                                                  \
        PyErr_Format((EXC), "format argument: " FMT, __VA_ARGS__);          \
    }                                                                       \
} while (0)

Py_LOCAL_INLINE(PyObject *)
getnextarg(PyObject *args, Py_ssize_t arglen, Py_ssize_t *p_argidx, int allowone)
{
    Py_ssize_t argidx = *p_argidx;
    if (argidx < arglen) {
        (*p_argidx)++;
        if (arglen >= 0) {
            return PyTuple_GetItem(args, argidx);
        }
        else if (allowone) {
            return args;
        }
    }
    PyErr_Format(PyExc_TypeError,
                 "not enough arguments for format string (got %zd)",
                 arglen < 0 ? 1 : arglen);
    return NULL;
}

/* Returns a new reference to a PyBytes object, or NULL on failure. */

static char*
formatfloat(PyObject *v, Py_ssize_t argidx, PyObject *key,
            int flags, int prec, int type,
            PyObject **p_result, PyBytesWriter *writer, char *str)
{
    char *p;
    PyObject *result;
    double x;
    size_t len;
    int dtoa_flags = 0;

    x = PyFloat_AsDouble(v);
    if (x == -1.0 && PyErr_Occurred()) {
        if (PyErr_ExceptionMatches(PyExc_TypeError)) {
            FORMAT_ERROR(PyExc_TypeError,
                         "%%%c requires a real number, not %T",
                         type, v);
        }
        return NULL;
    }

    if (prec < 0)
        prec = 6;

    if (flags & F_ALT) {
        dtoa_flags |= Py_DTSF_ALT;
    }
    p = PyOS_double_to_string(x, type, prec, dtoa_flags, NULL);

    if (p == NULL)
        return NULL;

    len = strlen(p);
    if (writer != NULL) {
        str = PyBytesWriter_GrowAndUpdatePointer(writer, len, str);
        if (str == NULL) {
            PyMem_Free(p);
            return NULL;
        }
        memcpy(str, p, len);
        PyMem_Free(p);
        str += len;
        return str;
    }

    result = PyBytes_FromStringAndSize(p, len);
    PyMem_Free(p);
    *p_result = result;
    return result != NULL ? str : NULL;
}

static PyObject *
formatlong(PyObject *v, Py_ssize_t argidx, PyObject *key,
           int flags, int prec, int type)
{
    PyObject *result, *iobj;
    if (PyLong_Check(v))
        return _PyUnicode_FormatLong(v, flags & F_ALT, prec, type);
    if (PyNumber_Check(v)) {
        /* make sure number is a type of integer for o, x, and X */
        if (type == 'o' || type == 'x' || type == 'X')
            iobj = _PyNumber_Index(v);
        else
            iobj = PyNumber_Long(v);
        if (iobj != NULL) {
            assert(PyLong_Check(iobj));
            result = _PyUnicode_FormatLong(iobj, flags & F_ALT, prec, type);
            Py_DECREF(iobj);
            return result;
        }
        if (!PyErr_ExceptionMatches(PyExc_TypeError))
            return NULL;
    }
    FORMAT_ERROR(PyExc_TypeError,
                 "%%%c requires %s, not %T",
                 type,
                 (type == 'o' || type == 'x' || type == 'X') ? "an integer"
                                                             : "a real number",
                 v);
    return NULL;
}

static int
byte_converter(PyObject *arg, Py_ssize_t argidx, PyObject *key, char *p)
{
    if (PyBytes_Check(arg)) {
        if (PyBytes_GET_SIZE(arg) != 1) {
            FORMAT_ERROR(PyExc_TypeError,
                         "%%c requires an integer in range(256) or "
                         "a single byte, not a bytes object of length %zd",
                         PyBytes_GET_SIZE(arg));
            return 0;
        }
        *p = PyBytes_AS_STRING(arg)[0];
        return 1;
    }
    else if (PyByteArray_Check(arg)) {
        if (PyByteArray_GET_SIZE(arg) != 1) {
            FORMAT_ERROR(PyExc_TypeError,
                         "%%c requires an integer in range(256) or "
                         "a single byte, not a bytearray object of length %zd",
                         PyByteArray_GET_SIZE(arg));
            return 0;
        }
        *p = PyByteArray_AS_STRING(arg)[0];
        return 1;
    }
    else if (PyIndex_Check(arg)) {
        int overflow;
        long ival = PyLong_AsLongAndOverflow(arg, &overflow);
        if (ival == -1 && PyErr_Occurred()) {
            return 0;
        }
        if (!(0 <= ival && ival <= 255)) {
            /* this includes an overflow in converting to C long */
            FORMAT_ERROR(PyExc_OverflowError,
                         "%%c argument not in range(256)%s", "");
            return 0;
        }
        *p = (char)ival;
        return 1;
    }
    FORMAT_ERROR(PyExc_TypeError,
                 "%%c requires an integer in range(256) or "
                 "a single byte, not %T",
                 arg);
    return 0;
}

static PyObject *_PyBytes_FromBuffer(PyObject *x);

static PyObject *
format_obj(PyObject *v, Py_ssize_t argidx, PyObject *key,
           const char **pbuf, Py_ssize_t *plen)
{
    PyObject *func, *result;
    /* is it a bytes object? */
    if (PyBytes_Check(v)) {
        *pbuf = PyBytes_AS_STRING(v);
        *plen = PyBytes_GET_SIZE(v);
        return Py_NewRef(v);
    }
    if (PyByteArray_Check(v)) {
        *pbuf = PyByteArray_AS_STRING(v);
        *plen = PyByteArray_GET_SIZE(v);
        return Py_NewRef(v);
    }
    /* does it support __bytes__? */
    func = _PyObject_LookupSpecial(v, &_Py_ID(__bytes__));
    if (func != NULL) {
        result = _PyObject_CallNoArgs(func);
        Py_DECREF(func);
        if (result == NULL)
            return NULL;
        if (!PyBytes_Check(result)) {
            PyErr_Format(PyExc_TypeError,
                         "%T.__bytes__() must return a bytes, not %T",
                         v, result);
            Py_DECREF(result);
            return NULL;
        }
        *pbuf = PyBytes_AS_STRING(result);
        *plen = PyBytes_GET_SIZE(result);
        return result;
    }
    /* does it support buffer protocol? */
    if (PyObject_CheckBuffer(v)) {
        /* maybe we can avoid making a copy of the buffer object here? */
        result = _PyBytes_FromBuffer(v);
        if (result == NULL)
            return NULL;
        *pbuf = PyBytes_AS_STRING(result);
        *plen = PyBytes_GET_SIZE(result);
        return result;
    }
    FORMAT_ERROR(PyExc_TypeError,
                 "%%b requires a bytes-like object, "
                 "or an object that implements __bytes__, not %T",
                 v);
    return NULL;
}

/* fmt%(v1,v2,...) is roughly equivalent to sprintf(fmt, v1, v2, ...) */

PyObject *
_PyBytes_FormatEx(const char *format, Py_ssize_t format_len,
                  PyObject *args, int use_bytearray)
{
    const char *fmt;
    Py_ssize_t arglen, argidx;
    Py_ssize_t fmtcnt;
    int args_owned = 0;
    PyObject *dict = NULL;
    PyObject *key = NULL;

    if (args == NULL) {
        PyErr_BadInternalCall();
        return NULL;
    }
    fmt = format;
    fmtcnt = format_len;

    PyBytesWriter *writer;
    if (use_bytearray) {
        writer = _PyBytesWriter_CreateByteArray(fmtcnt);
    }
    else {
        writer = PyBytesWriter_Create(fmtcnt);
    }
    if (writer == NULL) {
        return NULL;
    }
    char *res = PyBytesWriter_GetData(writer);

    if (PyTuple_Check(args)) {
        arglen = PyTuple_GET_SIZE(args);
        argidx = 0;
    }
    else {
        arglen = -1;
        argidx = -2;
    }
    if (Py_TYPE(args)->tp_as_mapping && Py_TYPE(args)->tp_as_mapping->mp_subscript &&
        !PyTuple_Check(args) && !PyBytes_Check(args) && !PyUnicode_Check(args) &&
        !PyByteArray_Check(args)) {
            dict = args;
    }

    while (--fmtcnt >= 0) {
        if (*fmt != '%') {
            Py_ssize_t len;
            char *pos;

            pos = (char *)memchr(fmt + 1, '%', fmtcnt);
            if (pos != NULL)
                len = pos - fmt;
            else
                len = fmtcnt + 1;
            assert(len != 0);

            memcpy(res, fmt, len);
            res += len;
            fmt += len;
            fmtcnt -= (len - 1);
        }
        else {
            /* Got a format specifier */
            int flags = 0;
            Py_ssize_t width = -1;
            int prec = -1;
            int c = '\0';
            int fill;
            PyObject *v = NULL;
            PyObject *temp = NULL;
            const char *pbuf = NULL;
            int sign;
            Py_ssize_t len = 0;
            char onechar; /* For byte_converter() */
            Py_ssize_t alloc;

            fmt++;
            if (*fmt == '%') {
                *res++ = '%';
                fmt++;
                fmtcnt--;
                continue;
            }
            Py_CLEAR(key);
            const char *fmtstart = fmt;
            if (*fmt == '(') {
                const char *keystart;
                Py_ssize_t keylen;
                int pcount = 1;

                if (dict == NULL) {
                    PyErr_Format(PyExc_TypeError,
                                 "format requires a mapping, not %T",
                                 args);
                    goto error;
                }
                ++fmt;
                --fmtcnt;
                keystart = fmt;
                /* Skip over balanced parentheses */
                while (pcount > 0 && --fmtcnt >= 0) {
                    if (*fmt == ')')
                        --pcount;
                    else if (*fmt == '(')
                        ++pcount;
                    fmt++;
                }
                keylen = fmt - keystart - 1;
                if (fmtcnt < 0 || pcount > 0) {
                    PyErr_Format(PyExc_ValueError,
                                 "stray %% or incomplete format key "
                                 "at position %zd",
                                 (Py_ssize_t)(fmtstart - format - 1));
                    goto error;
                }
                key = PyBytes_FromStringAndSize(keystart,
                                                 keylen);
                if (key == NULL)
                    goto error;
                if (args_owned) {
                    Py_DECREF(args);
                    args_owned = 0;
                }
                args = PyObject_GetItem(dict, key);
                if (args == NULL) {
                    goto error;
                }
                args_owned = 1;
                arglen = -3;
                argidx = -4;
            }
            else {
                if (arglen < -1) {
                    PyErr_Format(PyExc_ValueError,
                                 "format requires a parenthesised mapping key "
                                 "at position %zd",
                                 (Py_ssize_t)(fmtstart - format - 1));
                    goto error;
                }
            }

            /* Parse flags. Example: "%+i" => flags=F_SIGN. */
            while (--fmtcnt >= 0) {
                switch (c = *fmt++) {
                case '-': flags |= F_LJUST; continue;
                case '+': flags |= F_SIGN; continue;
                case ' ': flags |= F_BLANK; continue;
                case '#': flags |= F_ALT; continue;
                case '0': flags |= F_ZERO; continue;
                }
                break;
            }

            /* Parse width. Example: "%10s" => width=10 */
            if (c == '*') {
                if (arglen < -1) {
                    PyErr_Format(PyExc_ValueError,
                            "* cannot be used with a parenthesised mapping key "
                            "at position %zd",
                            (Py_ssize_t)(fmtstart - format - 1));
                    goto error;
                }
                v = getnextarg(args, arglen, &argidx, 0);
                if (v == NULL)
                    goto error;
                if (!PyLong_Check(v)) {
                    FORMAT_ERROR(PyExc_TypeError, "* requires int, not %T", v);
                    goto error;
                }
                width = PyLong_AsSsize_t(v);
                if (width == -1 && PyErr_Occurred()) {
                    if (PyErr_ExceptionMatches(PyExc_OverflowError)) {
                        FORMAT_ERROR(PyExc_OverflowError,
                                     "too big for width%s", "");
                    }
                    goto error;
                }
                if (width < 0) {
                    flags |= F_LJUST;
                    width = -width;
                }
                if (--fmtcnt >= 0)
                    c = *fmt++;
            }
            else if (c >= 0 && Py_ISDIGIT(c)) {
                width = c - '0';
                while (--fmtcnt >= 0) {
                    c = Py_CHARMASK(*fmt++);
                    if (!Py_ISDIGIT(c))
                        break;
                    if (width > (PY_SSIZE_T_MAX - ((int)c - '0')) / 10) {
                        PyErr_Format(PyExc_ValueError,
                                     "width too big at position %zd",
                                     (Py_ssize_t)(fmtstart - format - 1));
                        goto error;
                    }
                    width = width*10 + (c - '0');
                }
            }

            /* Parse precision. Example: "%.3f" => prec=3 */
            if (c == '.') {
                prec = 0;
                if (--fmtcnt >= 0)
                    c = *fmt++;
                if (c == '*') {
                    if (arglen < -1) {
                        PyErr_Format(PyExc_ValueError,
                                "* cannot be used with a parenthesised mapping key "
                                "at position %zd",
                                (Py_ssize_t)(fmtstart - format - 1));
                        goto error;
                    }
                    v = getnextarg(args, arglen, &argidx, 0);
                    if (v == NULL)
                        goto error;
                    if (!PyLong_Check(v)) {
                        FORMAT_ERROR(PyExc_TypeError,
                                     "* requires int, not %T", v);
                        goto error;
                    }
                    prec = PyLong_AsInt(v);
                    if (prec == -1 && PyErr_Occurred()) {
                        if (PyErr_ExceptionMatches(PyExc_OverflowError)) {
                            FORMAT_ERROR(PyExc_OverflowError,
                                         "too big for precision%s", "");
                        }
                        goto error;
                    }
                    if (prec < 0)
                        prec = 0;
                    if (--fmtcnt >= 0)
                        c = *fmt++;
                }
                else if (c >= 0 && Py_ISDIGIT(c)) {
                    prec = c - '0';
                    while (--fmtcnt >= 0) {
                        c = Py_CHARMASK(*fmt++);
                        if (!Py_ISDIGIT(c))
                            break;
                        if (prec > (INT_MAX - ((int)c - '0')) / 10) {
                            PyErr_Format(PyExc_ValueError,
                                "precision too big at position %zd",
                                (Py_ssize_t)(fmtstart - format - 1));
                            goto error;
                        }
                        prec = prec*10 + (c - '0');
                    }
                }
            } /* prec */
            if (fmtcnt >= 0) {
                if (c == 'h' || c == 'l' || c == 'L') {
                    if (--fmtcnt >= 0)
                        c = *fmt++;
                }
            }
            if (fmtcnt < 0) {
                PyErr_Format(PyExc_ValueError,
                             "stray %% at position %zd",
                             (Py_ssize_t)(fmtstart - format - 1));
                goto error;
            }
            v = getnextarg(args, arglen, &argidx, 1);
            if (v == NULL)
                goto error;

            if (fmtcnt == 0) {
                /* last write: disable writer overallocation */
                writer->overallocate = 0;
            }

            sign = 0;
            fill = ' ';
            switch (c) {
            case 'r':
                // %r is only for 2/3 code; 3 only code should use %a
            case 'a':
                temp = PyObject_ASCII(v);
                if (temp == NULL)
                    goto error;
                assert(PyUnicode_IS_ASCII(temp));
                pbuf = (const char *)PyUnicode_1BYTE_DATA(temp);
                len = PyUnicode_GET_LENGTH(temp);
                if (prec >= 0 && len > prec)
                    len = prec;
                break;

            case 's':
                // %s is only for 2/3 code; 3 only code should use %b
            case 'b':
                temp = format_obj(v, argidx, key, &pbuf, &len);
                if (temp == NULL)
                    goto error;
                if (prec >= 0 && len > prec)
                    len = prec;
                break;

            case 'i':
            case 'd':
            case 'u':
            case 'o':
            case 'x':
            case 'X':
                if (PyLong_CheckExact(v)
                    && width == -1 && prec == -1
                    && !(flags & (F_SIGN | F_BLANK))
                    && c != 'X')
                {
                    /* Fast path */
                    int alternate = flags & F_ALT;
                    int base;

                    switch(c)
                    {
                        default:
                            Py_UNREACHABLE();
                        case 'd':
                        case 'i':
                        case 'u':
                            base = 10;
                            break;
                        case 'o':
                            base = 8;
                            break;
                        case 'x':
                        case 'X':
                            base = 16;
                            break;
                    }

                    /* Fast path */
                    res = _PyLong_FormatBytesWriter(writer, res,
                                                    v, base, alternate);
                    if (res == NULL)
                        goto error;
                    continue;
                }

                temp = formatlong(v, argidx, key, flags, prec, c);
                if (!temp)
                    goto error;
                assert(PyUnicode_IS_ASCII(temp));
                pbuf = (const char *)PyUnicode_1BYTE_DATA(temp);
                len = PyUnicode_GET_LENGTH(temp);
                sign = 1;
                if (flags & F_ZERO)
                    fill = '0';
                break;

            case 'e':
            case 'E':
            case 'f':
            case 'F':
            case 'g':
            case 'G':
                if (width == -1 && prec == -1
                    && !(flags & (F_SIGN | F_BLANK)))
                {
                    /* Fast path */
                    res = formatfloat(v, argidx, key, flags, prec, c, NULL, writer, res);
                    if (res == NULL)
                        goto error;
                    continue;
                }

                if (!formatfloat(v, argidx, key, flags, prec, c, &temp, NULL, res))
                    goto error;
                pbuf = PyBytes_AS_STRING(temp);
                len = PyBytes_GET_SIZE(temp);
                sign = 1;
                if (flags & F_ZERO)
                    fill = '0';
                break;

            case 'c':
                pbuf = &onechar;
                len = byte_converter(v, argidx, key, &onechar);
                if (!len)
                    goto error;
                if (width == -1) {
                    /* Fast path */
                    *res++ = onechar;
                    continue;
                }
                break;

            default:
                if (Py_ISALPHA(c)) {
                    PyErr_Format(PyExc_ValueError,
                                 "unsupported format %%%c at position %zd",
                                 c, (Py_ssize_t)(fmtstart - format - 1));
                }
                else if (c == '\'') {
                    PyErr_Format(PyExc_ValueError,
                                 "stray %% at position %zd or unexpected "
                                 "format character \"'\" "
                                 "at position %zd",
                                 (Py_ssize_t)(fmtstart - format - 1),
                                 (Py_ssize_t)(fmt - format - 1));
                }
                else if (c >= 32 && c < 127 && c != '\'') {
                    PyErr_Format(PyExc_ValueError,
                                 "stray %% at position %zd or unexpected "
                                 "format character '%c' "
                                 "at position %zd",
                                 (Py_ssize_t)(fmtstart - format - 1),
                                 c, (Py_ssize_t)(fmt - format - 1));
                }
                else {
                    PyErr_Format(PyExc_ValueError,
                                 "stray %% at position %zd or unexpected "
                                 "format character with code 0x%02x "
                                 "at position %zd",
                                 (Py_ssize_t)(fmtstart - format - 1),
                                 Py_CHARMASK(c),
                                 (Py_ssize_t)(fmt - format - 1));
                }
                goto error;
            }

            if (sign) {
                if (*pbuf == '-' || *pbuf == '+') {
                    sign = *pbuf++;
                    len--;
                }
                else if (flags & F_SIGN)
                    sign = '+';
                else if (flags & F_BLANK)
                    sign = ' ';
                else
                    sign = 0;
            }
            if (width < len)
                width = len;

            alloc = width;
            if (sign != 0 && len == width)
                alloc++;
            /* 2: size preallocated for %s */
            if (alloc > 2) {
                res = PyBytesWriter_GrowAndUpdatePointer(writer, alloc - 2, res);
                if (res == NULL) {
                    Py_XDECREF(temp);
                    goto error;
                }
            }
#ifndef NDEBUG
            char *before = res;
#endif

            /* Write the sign if needed */
            if (sign) {
                if (fill != ' ')
                    *res++ = sign;
                if (width > len)
                    width--;
            }

            /* Write the numeric prefix for "x", "X" and "o" formats
               if the alternate form is used.
               For example, write "0x" for the "%#x" format. */
            if ((flags & F_ALT) && (c == 'o' || c == 'x' || c == 'X')) {
                assert(pbuf[0] == '0');
                assert(pbuf[1] == c);
                if (fill != ' ') {
                    *res++ = *pbuf++;
                    *res++ = *pbuf++;
                }
                width -= 2;
                if (width < 0)
                    width = 0;
                len -= 2;
            }

            /* Pad left with the fill character if needed */
            if (width > len && !(flags & F_LJUST)) {
                memset(res, fill, width - len);
                res += (width - len);
                width = len;
            }

            /* If padding with spaces: write sign if needed and/or numeric
               prefix if the alternate form is used */
            if (fill == ' ') {
                if (sign)
                    *res++ = sign;
                if ((flags & F_ALT) && (c == 'o' || c == 'x' || c == 'X')) {
                    assert(pbuf[0] == '0');
                    assert(pbuf[1] == c);
                    *res++ = *pbuf++;
                    *res++ = *pbuf++;
                }
            }

            /* Copy bytes */
            memcpy(res, pbuf, len);
            res += len;

            /* Pad right with the fill character if needed */
            if (width > len) {
                memset(res, ' ', width - len);
                res += (width - len);
            }

            if (dict && (argidx < arglen)) {
                // XXX: Never happens?
                PyErr_SetString(PyExc_TypeError,
                           "not all arguments converted during bytes formatting");
                Py_XDECREF(temp);
                goto error;
            }
            Py_XDECREF(temp);

#ifndef NDEBUG
            /* check that we computed the exact size for this write */
            assert((res - before) == alloc);
#endif
        } /* '%' */

        /* If overallocation was disabled, ensure that it was the last
           write. Otherwise, we missed an optimization */
        assert(writer->overallocate || fmtcnt == 0 || use_bytearray);
    } /* until end */

    if (argidx < arglen && !dict) {
        PyErr_Format(PyExc_TypeError,
                     "not all arguments converted during bytes formatting "
                     "(required %zd, got %zd)",
                     arglen < 0 ? 0 : argidx,
                     arglen < 0 ? 1 : arglen);
        goto error;
    }

    Py_XDECREF(key);
    if (args_owned) {
        Py_DECREF(args);
    }
    return PyBytesWriter_FinishWithPointer(writer, res);

 error:
    Py_XDECREF(key);
    PyBytesWriter_Discard(writer);
    if (args_owned) {
        Py_DECREF(args);
    }
    return NULL;
}

/* Unescape a backslash-escaped string. */
PyObject *_PyBytes_DecodeEscape2(const char *s,
                                Py_ssize_t len,
                                const char *errors,
                                int *first_invalid_escape_char,
                                const char **first_invalid_escape_ptr)
{
    PyBytesWriter *writer = PyBytesWriter_Create(len);
    if (writer == NULL) {
        return NULL;
    }
    char *p = PyBytesWriter_GetData(writer);

    *first_invalid_escape_char = -1;
    *first_invalid_escape_ptr = NULL;

    const char *end = s + len;
    while (s < end) {
        if (*s != '\\') {
            *p++ = *s++;
            continue;
        }

        s++;
        if (s == end) {
            PyErr_SetString(PyExc_ValueError,
                            "Trailing \\ in string");
            goto failed;
        }

        switch (*s++) {
        /* XXX This assumes ASCII! */
        case '\n': break;
        case '\\': *p++ = '\\'; break;
        case '\'': *p++ = '\''; break;
        case '\"': *p++ = '\"'; break;
        case 'b': *p++ = '\b'; break;
        case 'f': *p++ = '\014'; break; /* FF */
        case 't': *p++ = '\t'; break;
        case 'n': *p++ = '\n'; break;
        case 'r': *p++ = '\r'; break;
        case 'v': *p++ = '\013'; break; /* VT */
        case 'a': *p++ = '\007'; break; /* BEL, not classic C */
        case '0': case '1': case '2': case '3':
        case '4': case '5': case '6': case '7':
        {
            int c = s[-1] - '0';
            if (s < end && '0' <= *s && *s <= '7') {
                c = (c<<3) + *s++ - '0';
                if (s < end && '0' <= *s && *s <= '7')
                    c = (c<<3) + *s++ - '0';
            }
            if (c > 0377) {
                if (*first_invalid_escape_char == -1) {
                    *first_invalid_escape_char = c;
                    /* Back up 3 chars, since we've already incremented s. */
                    *first_invalid_escape_ptr = s - 3;
                }
            }
            *p++ = c;
            break;
        }
        case 'x':
            if (s+1 < end) {
                int digit1, digit2;
                digit1 = _PyLong_DigitValue[Py_CHARMASK(s[0])];
                digit2 = _PyLong_DigitValue[Py_CHARMASK(s[1])];
                if (digit1 < 16 && digit2 < 16) {
                    *p++ = (unsigned char)((digit1 << 4) + digit2);
                    s += 2;
                    break;
                }
            }
            /* invalid hexadecimal digits */

            if (!errors || strcmp(errors, "strict") == 0) {
                PyErr_Format(PyExc_ValueError,
                             "invalid \\x escape at position %zd",
                             s - 2 - (end - len));
                goto failed;
            }
            if (strcmp(errors, "replace") == 0) {
                *p++ = '?';
            } else if (strcmp(errors, "ignore") == 0)
                /* do nothing */;
            else {
                PyErr_Format(PyExc_ValueError,
                             "decoding error; unknown "
                             "error handling code: %.400s",
                             errors);
                goto failed;
            }
            /* skip \x */
            if (s < end && Py_ISXDIGIT(s[0]))
                s++; /* and a hexdigit */
            break;

        default:
            if (*first_invalid_escape_char == -1) {
                *first_invalid_escape_char = (unsigned char)s[-1];
                /* Back up one char, since we've already incremented s. */
                *first_invalid_escape_ptr = s - 1;
            }
            *p++ = '\\';
            s--;
        }
    }

    return PyBytesWriter_FinishWithPointer(writer, p);

  failed:
    PyBytesWriter_Discard(writer);
    return NULL;
}

PyObject *PyBytes_DecodeEscape(const char *s,
                                Py_ssize_t len,
                                const char *errors,
                                Py_ssize_t Py_UNUSED(unicode),
                                const char *Py_UNUSED(recode_encoding))
{
    int first_invalid_escape_char;
    const char *first_invalid_escape_ptr;
    PyObject *result = _PyBytes_DecodeEscape2(s, len, errors,
                                             &first_invalid_escape_char,
                                             &first_invalid_escape_ptr);
    if (result == NULL)
        return NULL;
    if (first_invalid_escape_char != -1) {
        if (first_invalid_escape_char > 0xff) {
            if (PyErr_WarnFormat(PyExc_DeprecationWarning, 1,
                                 "b\"\\%o\" is an invalid octal escape sequence. "
                                 "Such sequences will not work in the future. ",
                                 first_invalid_escape_char) < 0)
            {
                Py_DECREF(result);
                return NULL;
            }
        }
        else {
            if (PyErr_WarnFormat(PyExc_DeprecationWarning, 1,
                                 "b\"\\%c\" is an invalid escape sequence. "
                                 "Such sequences will not work in the future. ",
                                 first_invalid_escape_char) < 0)
            {
                Py_DECREF(result);
                return NULL;
            }
        }
    }
    return result;
}
/* -------------------------------------------------------------------- */
/* object api */

Py_ssize_t
PyBytes_Size(PyObject *op)
{
    if (!PyBytes_Check(op)) {
        PyErr_Format(PyExc_TypeError,
             "expected bytes, %.200s found", Py_TYPE(op)->tp_name);
        return -1;
    }
    return Py_SIZE(op);
}

char *
PyBytes_AsString(PyObject *op)
{
    if (!PyBytes_Check(op)) {
        PyErr_Format(PyExc_TypeError,
             "expected bytes, %.200s found", Py_TYPE(op)->tp_name);
        return NULL;
    }
    return ((PyBytesObject *)op)->ob_sval;
}

int
PyBytes_AsStringAndSize(PyObject *obj,
                         char **s,
                         Py_ssize_t *len)
{
    if (s == NULL) {
        PyErr_BadInternalCall();
        return -1;
    }

    if (!PyBytes_Check(obj)) {
        PyErr_Format(PyExc_TypeError,
             "expected bytes, %.200s found", Py_TYPE(obj)->tp_name);
        return -1;
    }

    *s = PyBytes_AS_STRING(obj);
    if (len != NULL)
        *len = PyBytes_GET_SIZE(obj);
    else if (strlen(*s) != (size_t)PyBytes_GET_SIZE(obj)) {
        PyErr_SetString(PyExc_ValueError,
                        "embedded null byte");
        return -1;
    }
    return 0;
}

/* -------------------------------------------------------------------- */
/* Methods */

#define STRINGLIB_GET_EMPTY() bytes_get_empty()

#include "stringlib/stringdefs.h"
#define STRINGLIB_MUTABLE 0

#include "stringlib/fastsearch.h"
#include "stringlib/count.h"
#include "stringlib/find.h"
#include "stringlib/join.h"
#include "stringlib/partition.h"
#include "stringlib/split.h"
#include "stringlib/ctype.h"

#include "stringlib/transmogrify.h"

#undef STRINGLIB_GET_EMPTY

Py_ssize_t
_PyBytes_Find(const char *haystack, Py_ssize_t len_haystack,
              const char *needle, Py_ssize_t len_needle,
              Py_ssize_t offset)
{
    assert(len_haystack >= 0);
    assert(len_needle >= 0);
    // Extra checks because stringlib_find accesses haystack[len_haystack].
    if (len_needle == 0) {
        return offset;
    }
    if (len_needle > len_haystack) {
        return -1;
    }
    assert(len_haystack >= 1);
    Py_ssize_t res = stringlib_find(haystack, len_haystack - 1,
                                    needle, len_needle, offset);
    if (res == -1) {
        Py_ssize_t last_align = len_haystack - len_needle;
        if (memcmp(haystack + last_align, needle, len_needle) == 0) {
            return offset + last_align;
        }
    }
    return res;
}

Py_ssize_t
_PyBytes_ReverseFind(const char *haystack, Py_ssize_t len_haystack,
                     const char *needle, Py_ssize_t len_needle,
                     Py_ssize_t offset)
{
    return stringlib_rfind(haystack, len_haystack,
                           needle, len_needle, offset);
}

PyObject *
PyBytes_Repr(PyObject *obj, int smartquotes)
{
    return _Py_bytes_repr(PyBytes_AS_STRING(obj), PyBytes_GET_SIZE(obj),
                          smartquotes, "bytes");
}

PyObject *
_Py_bytes_repr(const char *data, Py_ssize_t length, int smartquotes,
               const char *classname)
{
    Py_ssize_t i;
    Py_ssize_t newsize, squotes, dquotes;
    PyObject *v;
    unsigned char quote;
    Py_UCS1 *p;

    /* Compute size of output string */
    squotes = dquotes = 0;
    newsize = 3; /* b'' */
    for (i = 0; i < length; i++) {
        unsigned char c = data[i];
        Py_ssize_t incr = 1;
        switch(c) {
        case '\'': squotes++; break;
        case '"':  dquotes++; break;
        case '\\': case '\t': case '\n': case '\r':
            incr = 2; break; /* \C */
        default:
            if (c < ' ' || c >= 0x7f)
                incr = 4; /* \xHH */
        }
        if (newsize > PY_SSIZE_T_MAX - incr)
            goto overflow;
        newsize += incr;
    }
    quote = '\'';
    if (smartquotes && squotes && !dquotes)
        quote = '"';
    if (squotes && quote == '\'') {
        if (newsize > PY_SSIZE_T_MAX - squotes)
            goto overflow;
        newsize += squotes;
    }

    v = PyUnicode_New(newsize, 127);
    if (v == NULL) {
        return NULL;
    }
    p = PyUnicode_1BYTE_DATA(v);

    *p++ = 'b', *p++ = quote;
    for (i = 0; i < length; i++) {
        unsigned char c = data[i];
        if (c == quote || c == '\\')
            *p++ = '\\', *p++ = c;
        else if (c == '\t')
            *p++ = '\\', *p++ = 't';
        else if (c == '\n')
            *p++ = '\\', *p++ = 'n';
        else if (c == '\r')
            *p++ = '\\', *p++ = 'r';
        else if (c < ' ' || c >= 0x7f) {
            *p++ = '\\';
            *p++ = 'x';
            *p++ = Py_hexdigits[(c & 0xf0) >> 4];
            *p++ = Py_hexdigits[c & 0xf];
        }
        else
            *p++ = c;
    }
    *p++ = quote;
    assert(_PyUnicode_CheckConsistency(v, 1));
    return v;

  overflow:
    PyErr_Format(PyExc_OverflowError,
                 "%s object is too large to make repr", classname);
    return NULL;
}

static PyObject *
bytes_repr(PyObject *op)
{
    return PyBytes_Repr(op, 1);
}

static PyObject *
bytes_str(PyObject *op)
{
    if (_Py_GetConfig()->bytes_warning) {
        if (PyErr_WarnEx(PyExc_BytesWarning,
                         "str() on a bytes instance", 1)) {
            return NULL;
        }
    }
    return bytes_repr(op);
}

static Py_ssize_t
bytes_length(PyObject *self)
{
    PyBytesObject *a = _PyBytes_CAST(self);
    return Py_SIZE(a);
}

/* This is also used by PyBytes_Concat() and the specializing interpreter. */
PyObject *
_PyBytes_Concat(PyObject *a, PyObject *b)
{
    Py_buffer va, vb;
    PyObject *result = NULL;

    va.len = -1;
    vb.len = -1;
    if (PyObject_GetBuffer(a, &va, PyBUF_SIMPLE) != 0 ||
        PyObject_GetBuffer(b, &vb, PyBUF_SIMPLE) != 0) {
        PyErr_Format(PyExc_TypeError, "can't concat %.100s to %.100s",
                     Py_TYPE(b)->tp_name, Py_TYPE(a)->tp_name);
        goto done;
    }

    /* Optimize end cases */
    if (va.len == 0 && PyBytes_CheckExact(b)) {
        result = Py_NewRef(b);
        goto done;
    }
    if (vb.len == 0 && PyBytes_CheckExact(a)) {
        result = Py_NewRef(a);
        goto done;
    }

    if (va.len > PY_SSIZE_T_MAX - vb.len) {
        PyErr_NoMemory();
        goto done;
    }

    result = PyBytes_FromStringAndSize(NULL, va.len + vb.len);
    if (result != NULL) {
        memcpy(PyBytes_AS_STRING(result), va.buf, va.len);
        memcpy(PyBytes_AS_STRING(result) + va.len, vb.buf, vb.len);
    }

  done:
    if (va.len != -1)
        PyBuffer_Release(&va);
    if (vb.len != -1)
        PyBuffer_Release(&vb);
    return result;
}

PyObject *
_PyBytes_Repeat(PyObject *self, Py_ssize_t n)
{
    PyBytesObject *a = _PyBytes_CAST(self);
    if (n < 0)
        n = 0;
    /* watch out for overflows:  the size can overflow int,
     * and the # of bytes needed can overflow size_t
     */
    if (n > 0 && Py_SIZE(a) > PY_SSIZE_T_MAX / n) {
        PyErr_SetString(PyExc_OverflowError,
            "repeated bytes are too long");
        return NULL;
    }
    Py_ssize_t size = Py_SIZE(a) * n;
    if (size == Py_SIZE(a) && PyBytes_CheckExact(a)) {
        return Py_NewRef(a);
    }
    size_t nbytes = (size_t)size;
    if (nbytes + PyBytesObject_SIZE <= nbytes) {
        PyErr_SetString(PyExc_OverflowError,
            "repeated bytes are too long");
        return NULL;
    }
    PyBytesObject *op = PyObject_Malloc(PyBytesObject_SIZE + nbytes);
    if (op == NULL) {
        return PyErr_NoMemory();
    }
    _PyObject_InitVar((PyVarObject*)op, &PyBytes_Type, size);
    set_ob_shash(op, -1);
    op->ob_sval[size] = '\0';

    _PyBytes_RepeatBuffer(op->ob_sval, size, a->ob_sval, Py_SIZE(a));

    return (PyObject *) op;
}

static int
bytes_contains(PyObject *self, PyObject *arg)
{
    return _Py_bytes_contains(PyBytes_AS_STRING(self), PyBytes_GET_SIZE(self), arg);
}

static PyObject *
bytes_item(PyObject *self, Py_ssize_t i)
{
    PyBytesObject *a = _PyBytes_CAST(self);
    if (i < 0 || i >= Py_SIZE(a)) {
        PyErr_SetString(PyExc_IndexError, "index out of range");
        return NULL;
    }
    return _PyLong_FromUnsignedChar((unsigned char)a->ob_sval[i]);
}

static int
bytes_compare_eq(PyBytesObject *a, PyBytesObject *b)
{
    int cmp;
    Py_ssize_t len;

    len = Py_SIZE(a);
    if (Py_SIZE(b) != len)
        return 0;

    if (a->ob_sval[0] != b->ob_sval[0])
        return 0;

    cmp = memcmp(a->ob_sval, b->ob_sval, len);
    return (cmp == 0);
}

static PyObject*
bytes_richcompare(PyObject *aa, PyObject *bb, int op)
{
    /* Make sure both arguments are strings. */
    if (!(PyBytes_Check(aa) && PyBytes_Check(bb))) {
        if (_Py_GetConfig()->bytes_warning && (op == Py_EQ || op == Py_NE)) {
            if (PyUnicode_Check(aa) || PyUnicode_Check(bb)) {
                if (PyErr_WarnEx(PyExc_BytesWarning,
                                 "Comparison between bytes and string", 1))
                    return NULL;
            }
            if (PyLong_Check(aa) || PyLong_Check(bb)) {
                if (PyErr_WarnEx(PyExc_BytesWarning,
                                 "Comparison between bytes and int", 1))
                    return NULL;
            }
        }
        Py_RETURN_NOTIMPLEMENTED;
    }

    PyBytesObject *a = _PyBytes_CAST(aa);
    PyBytesObject *b = _PyBytes_CAST(bb);
    if (a == b) {
        switch (op) {
        case Py_EQ:
        case Py_LE:
        case Py_GE:
            /* a byte string is equal to itself */
            Py_RETURN_TRUE;
        case Py_NE:
        case Py_LT:
        case Py_GT:
            Py_RETURN_FALSE;
        default:
            PyErr_BadArgument();
            return NULL;
        }
    }
    else if (op == Py_EQ || op == Py_NE) {
        int eq = bytes_compare_eq(a, b);
        eq ^= (op == Py_NE);
        return PyBool_FromLong(eq);
    }
    else {
        Py_ssize_t len_a = Py_SIZE(a);
        Py_ssize_t len_b = Py_SIZE(b);
        Py_ssize_t min_len = Py_MIN(len_a, len_b);
        int c;
        if (min_len > 0) {
            c = Py_CHARMASK(*a->ob_sval) - Py_CHARMASK(*b->ob_sval);
            if (c == 0)
                c = memcmp(a->ob_sval, b->ob_sval, min_len);
        }
        else {
            c = 0;
        }
        if (c != 0) {
            Py_RETURN_RICHCOMPARE(c, 0, op);
        }
        Py_RETURN_RICHCOMPARE(len_a, len_b, op);
    }
}

static Py_hash_t
bytes_hash(PyObject *self)
{
    PyBytesObject *a = _PyBytes_CAST(self);
    Py_hash_t hash = get_ob_shash(a);
    if (hash == -1) {
        /* Can't fail */
        hash = Py_HashBuffer(a->ob_sval, Py_SIZE(a));
        set_ob_shash(a, hash);
    }
    return hash;
}

static PyObject*
bytes_subscript(PyObject *op, PyObject* item)
{
    PyBytesObject *self = _PyBytes_CAST(op);
    if (_PyIndex_Check(item)) {
        Py_ssize_t i = PyNumber_AsSsize_t(item, PyExc_IndexError);
        if (i == -1 && PyErr_Occurred())
            return NULL;
        if (i < 0)
            i += PyBytes_GET_SIZE(self);
        if (i < 0 || i >= PyBytes_GET_SIZE(self)) {
            PyErr_SetString(PyExc_IndexError,
                            "index out of range");
            return NULL;
        }
        return _PyLong_FromUnsignedChar((unsigned char)self->ob_sval[i]);
    }
    else if (PySlice_Check(item)) {
        Py_ssize_t start, stop, step, slicelength, i;
        size_t cur;
        const char* source_buf;
        char* result_buf;
        PyObject* result;

        if (PySlice_Unpack(item, &start, &stop, &step) < 0) {
            return NULL;
        }
        slicelength = PySlice_AdjustIndices(PyBytes_GET_SIZE(self), &start,
                                            &stop, step);

        if (slicelength <= 0) {
            return Py_GetConstant(Py_CONSTANT_EMPTY_BYTES);
        }
        else if (start == 0 && step == 1 &&
                 slicelength == PyBytes_GET_SIZE(self) &&
                 PyBytes_CheckExact(self)) {
            return Py_NewRef(self);
        }
        else if (step == 1) {
            return PyBytes_FromStringAndSize(
                PyBytes_AS_STRING(self) + start,
                slicelength);
        }
        else {
            source_buf = PyBytes_AS_STRING(self);
            result = PyBytes_FromStringAndSize(NULL, slicelength);
            if (result == NULL)
                return NULL;

            result_buf = PyBytes_AS_STRING(result);
            for (cur = start, i = 0; i < slicelength;
                 cur += step, i++) {
                result_buf[i] = source_buf[cur];
            }

            return result;
        }
    }
    else {
        PyErr_Format(PyExc_TypeError,
                     "byte indices must be integers or slices, not %.200s",
                     Py_TYPE(item)->tp_name);
        return NULL;
    }
}

static int
bytes_buffer_getbuffer(PyObject *op, Py_buffer *view, int flags)
{
    PyBytesObject *self = _PyBytes_CAST(op);
    return PyBuffer_FillInfo(view, (PyObject*)self, (void *)self->ob_sval, Py_SIZE(self),
                             1, flags);
}

#define LEFTSTRIP 0
#define RIGHTSTRIP 1
#define BOTHSTRIP 2

static PyObject *
bytes_split_impl(PyBytesObject *self, PyObject *sep, Py_ssize_t maxsplit)
{
    Py_ssize_t len = PyBytes_GET_SIZE(self), n;
    const char *s = PyBytes_AS_STRING(self), *sub;
    Py_buffer vsub;
    PyObject *list;

    if (maxsplit < 0)
        maxsplit = PY_SSIZE_T_MAX;
    if (sep == Py_None)
        return stringlib_split_whitespace((PyObject*) self, s, len, maxsplit);
    if (PyObject_GetBuffer(sep, &vsub, PyBUF_SIMPLE) != 0)
        return NULL;
    sub = vsub.buf;
    n = vsub.len;

    list = stringlib_split((PyObject*) self, s, len, sub, n, maxsplit);
    PyBuffer_Release(&vsub);
    return list;
}

static PyObject *
bytes_partition_impl(PyBytesObject *self, Py_buffer *sep)
{
    return stringlib_partition(
        (PyObject*) self,
        PyBytes_AS_STRING(self), PyBytes_GET_SIZE(self),
        sep->obj, (const char *)sep->buf, sep->len
        );
}

static PyObject *
bytes_rpartition_impl(PyBytesObject *self, Py_buffer *sep)
{
    return stringlib_rpartition(
        (PyObject*) self,
        PyBytes_AS_STRING(self), PyBytes_GET_SIZE(self),
        sep->obj, (const char *)sep->buf, sep->len
        );
}

static PyObject *
bytes_rsplit_impl(PyBytesObject *self, PyObject *sep, Py_ssize_t maxsplit)
{
    Py_ssize_t len = PyBytes_GET_SIZE(self), n;
    const char *s = PyBytes_AS_STRING(self), *sub;
    Py_buffer vsub;
    PyObject *list;

    if (maxsplit < 0)
        maxsplit = PY_SSIZE_T_MAX;
    if (sep == Py_None)
        return stringlib_rsplit_whitespace((PyObject*) self, s, len, maxsplit);
    if (PyObject_GetBuffer(sep, &vsub, PyBUF_SIMPLE) != 0)
        return NULL;
    sub = vsub.buf;
    n = vsub.len;

    list = stringlib_rsplit((PyObject*) self, s, len, sub, n, maxsplit);
    PyBuffer_Release(&vsub);
    return list;
}


static PyObject *
bytes_join_impl(PyBytesObject *self, PyObject *iterable_of_bytes)
{
    return stringlib_bytes_join((PyObject*)self, iterable_of_bytes);
}

PyObject *
PyBytes_Join(PyObject *sep, PyObject *iterable)
{
    if (sep == NULL) {
        PyErr_BadInternalCall();
        return NULL;
    }
    if (!PyBytes_Check(sep)) {
        PyErr_Format(PyExc_TypeError,
                     "sep: expected bytes, got %T", sep);
        return NULL;
    }

    return stringlib_bytes_join(sep, iterable);
}

static PyObject *
bytes_find_impl(PyBytesObject *self, PyObject *sub, Py_ssize_t start,
                Py_ssize_t end)
{
    return _Py_bytes_find(PyBytes_AS_STRING(self), PyBytes_GET_SIZE(self),
                          sub, start, end);
}

static PyObject *
bytes_index_impl(PyBytesObject *self, PyObject *sub, Py_ssize_t start,
                 Py_ssize_t end)
{
    return _Py_bytes_index(PyBytes_AS_STRING(self), PyBytes_GET_SIZE(self),
                           sub, start, end);
}

static PyObject *
bytes_rfind_impl(PyBytesObject *self, PyObject *sub, Py_ssize_t start,
                 Py_ssize_t end)
{
    return _Py_bytes_rfind(PyBytes_AS_STRING(self), PyBytes_GET_SIZE(self),
                           sub, start, end);
}

static PyObject *
bytes_rindex_impl(PyBytesObject *self, PyObject *sub, Py_ssize_t start,
                  Py_ssize_t end)
{
    return _Py_bytes_rindex(PyBytes_AS_STRING(self), PyBytes_GET_SIZE(self),
                            sub, start, end);
}


Py_LOCAL_INLINE(PyObject *)
do_xstrip(PyBytesObject *self, int striptype, PyObject *sepobj)
{
    Py_buffer vsep;
    const char *s = PyBytes_AS_STRING(self);
    Py_ssize_t len = PyBytes_GET_SIZE(self);
    char *sep;
    Py_ssize_t seplen;
    Py_ssize_t i, j;

    if (PyObject_GetBuffer(sepobj, &vsep, PyBUF_SIMPLE) != 0)
        return NULL;
    sep = vsep.buf;
    seplen = vsep.len;

    i = 0;
    if (striptype != RIGHTSTRIP) {
        while (i < len && memchr(sep, Py_CHARMASK(s[i]), seplen)) {
            i++;
        }
    }

    j = len;
    if (striptype != LEFTSTRIP) {
        do {
            j--;
        } while (j >= i && memchr(sep, Py_CHARMASK(s[j]), seplen));
        j++;
    }

    PyBuffer_Release(&vsep);

    if (i == 0 && j == len && PyBytes_CheckExact(self)) {
        return Py_NewRef(self);
    }
    else
        return PyBytes_FromStringAndSize(s+i, j-i);
}


Py_LOCAL_INLINE(PyObject *)
do_strip(PyBytesObject *self, int striptype)
{
    const char *s = PyBytes_AS_STRING(self);
    Py_ssize_t len = PyBytes_GET_SIZE(self), i, j;

    i = 0;
    if (striptype != RIGHTSTRIP) {
        while (i < len && Py_ISSPACE(s[i])) {
            i++;
        }
    }

    j = len;
    if (striptype != LEFTSTRIP) {
        do {
            j--;
        } while (j >= i && Py_ISSPACE(s[j]));
        j++;
    }

    if (i == 0 && j == len && PyBytes_CheckExact(self)) {
        return Py_NewRef(self);
    }
    else
        return PyBytes_FromStringAndSize(s+i, j-i);
}


Py_LOCAL_INLINE(PyObject *)
do_argstrip(PyBytesObject *self, int striptype, PyObject *bytes)
{
    if (bytes != Py_None) {
        return do_xstrip(self, striptype, bytes);
    }
    return do_strip(self, striptype);
}

static PyObject *
bytes_strip_impl(PyBytesObject *self, PyObject *bytes)
{
    return do_argstrip(self, BOTHSTRIP, bytes);
}

static PyObject *
bytes_lstrip_impl(PyBytesObject *self, PyObject *bytes)
{
    return do_argstrip(self, LEFTSTRIP, bytes);
}

static PyObject *
bytes_rstrip_impl(PyBytesObject *self, PyObject *bytes)
{
    return do_argstrip(self, RIGHTSTRIP, bytes);
}


static PyObject *
bytes_count_impl(PyBytesObject *self, PyObject *sub, Py_ssize_t start,
                 Py_ssize_t end)
{
    return _Py_bytes_count(PyBytes_AS_STRING(self), PyBytes_GET_SIZE(self),
                           sub, start, end);
}


static PyObject *
bytes_translate_impl(PyBytesObject *self, PyObject *table,
                     PyObject *deletechars)
{
    const char *input;
    char *output;
    Py_buffer table_view = {NULL, NULL};
    Py_buffer del_table_view = {NULL, NULL};
    const char *table_chars;
    Py_ssize_t i, c, changed = 0;
    PyObject *input_obj = (PyObject*)self;
    const char *output_start, *del_table_chars=NULL;
    Py_ssize_t inlen, tablen, dellen = 0;
    int trans_table[256];

    if (PyBytes_Check(table)) {
        table_chars = PyBytes_AS_STRING(table);
        tablen = PyBytes_GET_SIZE(table);
    }
    else if (table == Py_None) {
        table_chars = NULL;
        tablen = 256;
    }
    else {
        if (PyObject_GetBuffer(table, &table_view, PyBUF_SIMPLE) != 0)
            return NULL;
        table_chars = table_view.buf;
        tablen = table_view.len;
    }

    if (tablen != 256) {
        PyErr_SetString(PyExc_ValueError,
          "translation table must be 256 characters long");
        PyBuffer_Release(&table_view);
        return NULL;
    }

    if (deletechars != NULL) {
        if (PyBytes_Check(deletechars)) {
            del_table_chars = PyBytes_AS_STRING(deletechars);
            dellen = PyBytes_GET_SIZE(deletechars);
        }
        else {
            if (PyObject_GetBuffer(deletechars, &del_table_view, PyBUF_SIMPLE) != 0) {
                PyBuffer_Release(&table_view);
                return NULL;
            }
            del_table_chars = del_table_view.buf;
            dellen = del_table_view.len;
        }
    }
    else {
        del_table_chars = NULL;
        dellen = 0;
    }

    inlen = PyBytes_GET_SIZE(input_obj);
    PyBytesWriter *writer = PyBytesWriter_Create(inlen);
    if (writer == NULL) {
        PyBuffer_Release(&del_table_view);
        PyBuffer_Release(&table_view);
        return NULL;
    }
    output_start = output = PyBytesWriter_GetData(writer);
    input = PyBytes_AS_STRING(input_obj);

    if (dellen == 0 && table_chars != NULL) {
        /* If no deletions are required, use faster code */
        for (i = inlen; --i >= 0; ) {
            c = Py_CHARMASK(*input++);
            *output++ = table_chars[c];
        }
        PyObject *result = PyBytesWriter_Finish(writer);

        /* Check if anything changed (for returning original object) */
        /* We save this check until the end so that the compiler will */
        /* unroll the loop above leading to MUCH faster code. */
        if (result != NULL && PyBytes_CheckExact(input_obj)) {
            if (memcmp(PyBytes_AS_STRING(input_obj), output_start, inlen) == 0) {
                Py_SETREF(result, Py_NewRef(input_obj));
            }
        }

        PyBuffer_Release(&del_table_view);
        PyBuffer_Release(&table_view);
        return result;
    }

    if (table_chars == NULL) {
        for (i = 0; i < 256; i++)
            trans_table[i] = Py_CHARMASK(i);
    } else {
        for (i = 0; i < 256; i++)
            trans_table[i] = Py_CHARMASK(table_chars[i]);
    }
    PyBuffer_Release(&table_view);

    for (i = 0; i < dellen; i++)
        trans_table[(int) Py_CHARMASK(del_table_chars[i])] = -1;
    PyBuffer_Release(&del_table_view);

    for (i = inlen; --i >= 0; ) {
        c = Py_CHARMASK(*input++);
        if (trans_table[c] != -1)
            if (Py_CHARMASK(*output++ = (char)trans_table[c]) == c)
                continue;
        changed = 1;
    }
    if (!changed && PyBytes_CheckExact(input_obj)) {
        PyBytesWriter_Discard(writer);
        return Py_NewRef(input_obj);
    }
    /* Fix the size of the resulting byte string */
    return PyBytesWriter_FinishWithPointer(writer, output);
}


static PyObject *
bytes_maketrans_impl(Py_buffer *frm, Py_buffer *to)
{
    return _Py_bytes_maketrans(frm, to);
}


static PyObject *
bytes_replace_impl(PyBytesObject *self, Py_buffer *old, Py_buffer *new,
                   Py_ssize_t count)
{
    return stringlib_replace((PyObject *)self,
                             (const char *)old->buf, old->len,
                             (const char *)new->buf, new->len, count);
}

/** End DALKE **/

static PyObject *
bytes_removeprefix_impl(PyBytesObject *self, Py_buffer *prefix)
{
    const char *self_start = PyBytes_AS_STRING(self);
    Py_ssize_t self_len = PyBytes_GET_SIZE(self);
    const char *prefix_start = prefix->buf;
    Py_ssize_t prefix_len = prefix->len;

    if (self_len >= prefix_len
        && prefix_len > 0
        && memcmp(self_start, prefix_start, prefix_len) == 0)
    {
        return PyBytes_FromStringAndSize(self_start + prefix_len,
                                         self_len - prefix_len);
    }

    if (PyBytes_CheckExact(self)) {
        return Py_NewRef(self);
    }

    return PyBytes_FromStringAndSize(self_start, self_len);
}

static PyObject *
bytes_removesuffix_impl(PyBytesObject *self, Py_buffer *suffix)
{
    const char *self_start = PyBytes_AS_STRING(self);
    Py_ssize_t self_len = PyBytes_GET_SIZE(self);
    const char *suffix_start = suffix->buf;
    Py_ssize_t suffix_len = suffix->len;

    if (self_len >= suffix_len
        && suffix_len > 0
        && memcmp(self_start + self_len - suffix_len,
                  suffix_start, suffix_len) == 0)
    {
        return PyBytes_FromStringAndSize(self_start,
                                         self_len - suffix_len);
    }

    if (PyBytes_CheckExact(self)) {
        return Py_NewRef(self);
    }

    return PyBytes_FromStringAndSize(self_start, self_len);
}

static PyObject *
bytes_startswith_impl(PyBytesObject *self, PyObject *subobj,
                      Py_ssize_t start, Py_ssize_t end)
{
    return _Py_bytes_startswith(PyBytes_AS_STRING(self), PyBytes_GET_SIZE(self),
                                subobj, start, end);
}

static PyObject *
bytes_endswith_impl(PyBytesObject *self, PyObject *subobj, Py_ssize_t start,
                    Py_ssize_t end)
{
    return _Py_bytes_endswith(PyBytes_AS_STRING(self), PyBytes_GET_SIZE(self),
                              subobj, start, end);
}


static PyObject *
bytes_decode_impl(PyBytesObject *self, const char *encoding,
                  const char *errors)
{
    return PyUnicode_FromEncodedObject((PyObject*)self, encoding, errors);
}


static PyObject *
bytes_splitlines_impl(PyBytesObject *self, int keepends)
{
    return stringlib_splitlines(
        (PyObject*) self, PyBytes_AS_STRING(self),
        PyBytes_GET_SIZE(self), keepends
        );
}


PyObject*
_PyBytes_FromHex(PyObject *string, int use_bytearray)
{
    Py_ssize_t hexlen, invalid_char;
    unsigned int top, bot;
    const Py_UCS1 *str, *start, *end;
    PyBytesWriter *writer = NULL;
    Py_buffer view;
    view.obj = NULL;

    if (PyUnicode_Check(string)) {
        hexlen = PyUnicode_GET_LENGTH(string);

        if (!PyUnicode_IS_ASCII(string)) {
            const void *data = PyUnicode_DATA(string);
            int kind = PyUnicode_KIND(string);
            Py_ssize_t i;

            /* search for the first non-ASCII character */
            for (i = 0; i < hexlen; i++) {
                if (PyUnicode_READ(kind, data, i) >= 128)
                    break;
            }
            invalid_char = i;
            goto error;
        }

        assert(PyUnicode_KIND(string) == PyUnicode_1BYTE_KIND);
        str = PyUnicode_1BYTE_DATA(string);
    }
    else if (PyObject_CheckBuffer(string)) {
        if (PyObject_GetBuffer(string, &view, PyBUF_SIMPLE) != 0) {
            return NULL;
        }
        hexlen = view.len;
        str = view.buf;
    }
    else {
        PyErr_Format(PyExc_TypeError,
                     "fromhex() argument must be str or bytes-like, not %T",
                     string);
        return NULL;
    }

    /* This overestimates if there are spaces */
    if (use_bytearray) {
        writer = _PyBytesWriter_CreateByteArray(hexlen / 2);
    }
    else {
        writer = PyBytesWriter_Create(hexlen / 2);
    }
    if (writer == NULL) {
        goto release_buffer;
    }
    char *buf = PyBytesWriter_GetData(writer);

    start = str;
    end = str + hexlen;
    while (str < end) {
        /* skip over spaces in the input */
        if (Py_ISSPACE(*str)) {
            do {
                str++;
            } while (Py_ISSPACE(*str));
            if (str >= end)
                break;
        }

        top = _PyLong_DigitValue[*str];
        if (top >= 16) {
            invalid_char = str - start;
            goto error;
        }
        str++;

        bot = _PyLong_DigitValue[*str];
        if (bot >= 16) {
            /* Check if we had a second digit */
            if (str >= end){
                invalid_char = -1;
            } else {
                invalid_char = str - start;
            }
            goto error;
        }
        str++;

        *buf++ = (unsigned char)((top << 4) + bot);
    }

    if (view.obj != NULL) {
       PyBuffer_Release(&view);
    }
    return PyBytesWriter_FinishWithPointer(writer, buf);

  error:
    if (invalid_char == -1) {
        PyErr_SetString(PyExc_ValueError,
                        "fromhex() arg must contain an even number of hexadecimal digits");
    } else {
        PyErr_Format(PyExc_ValueError,
                     "non-hexadecimal number found in "
                     "fromhex() arg at position %zd", invalid_char);
    }
    PyBytesWriter_Discard(writer);

  release_buffer:
    if (view.obj != NULL) {
        PyBuffer_Release(&view);
    }
    return NULL;
}

static PyObject *
bytes_hex_impl(PyBytesObject *self, PyObject *sep, Py_ssize_t bytes_per_sep)
{
    const char *argbuf = PyBytes_AS_STRING(self);
    Py_ssize_t arglen = PyBytes_GET_SIZE(self);
    return _Py_strhex_with_sep(argbuf, arglen, sep, bytes_per_sep);
}

static PyObject *
bytes_getnewargs(PyObject *op, PyObject *Py_UNUSED(dummy))
{
    PyBytesObject *v = _PyBytes_CAST(op);
    return Py_BuildValue("(y#)", v->ob_sval, Py_SIZE(v));
}


static PyObject *
bytes_mod(PyObject *self, PyObject *arg)
{
    if (!PyBytes_Check(self)) {
        Py_RETURN_NOTIMPLEMENTED;
    }
    return _PyBytes_FormatEx(PyBytes_AS_STRING(self), PyBytes_GET_SIZE(self),
                             arg, 0);
}

static PyObject *
bytes_subtype_new(PyTypeObject *, PyObject *);
static Py_ssize_t _PyBytesWriter_ResizeToAllocated(PyBytesWriter *writer);
static void* _PyBytesWriter_ResizeAndUpdatePointer(PyBytesWriter *writer,
                                                   Py_ssize_t size,
                                                   void *data);

/* A PyBytesWriter written one byte at a time: the C.bytes_appender
   escape of Objects/pyspec/bytesobject.py.  The generated code keeps it
   in a local variable and only passes its address to the always inlined
   functions below; the rare paths take it by value.  Its address never
   escapes, so that the compiler keeps the cursor in registers. */
typedef struct {
    PyBytesWriter *writer;
    char *str;      /* where the next byte goes */
    char *end;      /* end of the buffer */
} bytes_appender;

/* A writer of at least size bytes; writer is NULL on error. */
static Py_NO_INLINE bytes_appender
bytes_appender_create(Py_ssize_t size)
{
    bytes_appender appender = {PyBytesWriter_Create(size), NULL, NULL};
    if (appender.writer != NULL) {
        size = _PyBytesWriter_ResizeToAllocated(appender.writer);
        appender.str = PyBytesWriter_GetData(appender.writer);
        appender.end = appender.str + size;
    }
    return appender;
}

/* Return 0, or -1 with an exception set. */
static inline Py_ALWAYS_INLINE int
bytes_appender_init(bytes_appender *appender, Py_ssize_t size)
{
    *appender = bytes_appender_create(size);
    return appender->writer == NULL ? -1 : 0;
}

/* The buffer is full: grow it by at least one byte.  str is NULL on
   error. */
static Py_NO_INLINE bytes_appender
bytes_appender_grow(bytes_appender appender)
{
    PyBytesWriter *writer = appender.writer;
    char *data = PyBytesWriter_GetData(writer);
    appender.str = _PyBytesWriter_ResizeAndUpdatePointer(
        writer, appender.end - data + 1, appender.str);
    if (appender.str != NULL) {
        Py_ssize_t size = _PyBytesWriter_ResizeToAllocated(writer);
        appender.end = (char *)PyBytesWriter_GetData(writer) + size;
    }
    return appender;
}

/* Return 0, or -1 with an exception set. */
static inline Py_ALWAYS_INLINE int
bytes_appender_append(bytes_appender *appender, unsigned char value)
{
    if (appender->str == appender->end) {
        *appender = bytes_appender_grow(*appender);
        if (appender->str == NULL) {
            return -1;
        }
    }
    *appender->str++ = (char)value;
    return 0;
}

/* bytes_new_impl(), the bytes_new_nargsN() functions called by
   bytes_vectorcall(), PyBytes_FromObject() and bytes_from_iterator()
   (with its list and tuple variants) are generated from
   Objects/pyspec/bytesobject.py by Argument Clinic. */
#include "clinic/bytesobject_pyspec.c.h"

static PyObject*
_PyBytes_FromBuffer(PyObject *x)
{
    Py_buffer view;
    if (PyObject_GetBuffer(x, &view, PyBUF_FULL_RO) < 0)
        return NULL;

    PyBytesWriter *writer = PyBytesWriter_Create(view.len);
    if (writer == NULL) {
        goto fail;
    }

    if (PyBuffer_ToContiguous(PyBytesWriter_GetData(writer),
                              &view, view.len, 'C') < 0) {
        goto fail;
    }

    PyBuffer_Release(&view);
    return PyBytesWriter_Finish(writer);

fail:
    PyBytesWriter_Discard(writer);
    PyBuffer_Release(&view);
    return NULL;
}

/* This allocator is needed for subclasses don't want to use __new__.
 * See https://github.com/python/cpython/issues/91020#issuecomment-1096793239
 *
 * This allocator will be removed when ob_shash is removed.
 */
static PyObject *
bytes_alloc(PyTypeObject *self, Py_ssize_t nitems)
{
    PyBytesObject *obj = (PyBytesObject*)PyType_GenericAlloc(self, nitems);
    if (obj == NULL) {
        return NULL;
    }
    set_ob_shash(obj, -1);
    return (PyObject*)obj;
}

static PyObject *
bytes_subtype_new(PyTypeObject *type, PyObject *tmp)
{
    PyObject *pnew;
    Py_ssize_t n;

    assert(PyType_IsSubtype(type, &PyBytes_Type));
    assert(PyBytes_Check(tmp));
    n = PyBytes_GET_SIZE(tmp);
    pnew = type->tp_alloc(type, n);
    if (pnew != NULL) {
        memcpy(PyBytes_AS_STRING(pnew),
                  PyBytes_AS_STRING(tmp), n+1);
        set_ob_shash((PyBytesObject *)pnew,
            get_ob_shash((PyBytesObject *)tmp));
    }
    return pnew;
}

static _PyObjectIndexPair
bytes_iteritem(PyObject *obj, Py_ssize_t index)
{
    PyBytesObject *a = _PyBytes_CAST(obj);
    if (index >= Py_SIZE(a)) {
        return (_PyObjectIndexPair) { .object = NULL, .index = index };
    }
    PyObject *l = _PyLong_FromUnsignedChar((unsigned char)a->ob_sval[index]);
    return (_PyObjectIndexPair) { .object = l, .index = index + 1 };
}

#ifdef Py_DEBUG
void
_PyBytes_CheckOverflow(PyObject *self, void *addr, const char *type_name)
{
    // Make sure that the trailing null byte was not modified
    char *data = PyBytes_AS_STRING(self);
    Py_ssize_t size = PyBytes_GET_SIZE(self);
    if (data[size] != '\0') {
        _Py_FatalErrorFormat(__func__,
                             "Buffer overflow detected in %s object %p "
                             "at position %zd",
                             type_name, addr, size);
    }
}


static void
bytes_dealloc(PyObject *op)
{
    PyBytesObject *self = _PyBytes_CAST(op);
    _PyBytes_CheckOverflow(op, op, "bytes");
    Py_TYPE(self)->tp_free((PyObject *)self);
}
#else
/* Release builds inherit the tp_dealloc of object. */
#  define bytes_dealloc NULL
#endif


void
PyBytes_Concat(PyObject **pv, PyObject *w)
{
    assert(pv != NULL);
    if (*pv == NULL)
        return;
    if (w == NULL) {
        Py_CLEAR(*pv);
        return;
    }

    if (_PyObject_IsUniquelyReferenced(*pv) && PyBytes_CheckExact(*pv)) {
        /* Only one reference, so we can resize in place */
        Py_ssize_t oldsize;
        Py_buffer wb;

        if (PyObject_GetBuffer(w, &wb, PyBUF_SIMPLE) != 0) {
            PyErr_Format(PyExc_TypeError, "can't concat %.100s to %.100s",
                         Py_TYPE(w)->tp_name, Py_TYPE(*pv)->tp_name);
            Py_CLEAR(*pv);
            return;
        }

        oldsize = PyBytes_GET_SIZE(*pv);
        if (oldsize > PY_SSIZE_T_MAX - wb.len) {
            PyErr_NoMemory();
            goto error;
        }
        if (_PyBytes_Resize(pv, oldsize + wb.len) < 0)
            goto error;

        memcpy(PyBytes_AS_STRING(*pv) + oldsize, wb.buf, wb.len);
        PyBuffer_Release(&wb);
        return;

      error:
        PyBuffer_Release(&wb);
        Py_CLEAR(*pv);
        return;
    }

    else {
        /* Multiple references, need to create new object */
        PyObject *v;
        v = _PyBytes_Concat(*pv, w);
        Py_SETREF(*pv, v);
    }
}

void
PyBytes_ConcatAndDel(PyObject **pv, PyObject *w)
{
    PyBytes_Concat(pv, w);
    Py_XDECREF(w);
}


#ifndef NDEBUG
// Make sure that a bytes object can still be mutated.
//
// Usage: assert(_PyBytes_IsMutable(obj)).
int
_PyBytes_IsMutable(PyObject *self)
{
    assert(PyBytes_Check(self));
    // Do not use _PyObject_IsUniquelyReferenced(): this function is called
    // by bytearray and PyBytesWriter which can be used by multiple threads.
    assert(Py_REFCNT(self) == 1);
    assert(!_Py_IsImmortal(self));

    // Check that the object is not a singleton
    Py_ssize_t size = PyBytes_GET_SIZE(self);
    if (size == 0) {
        assert(self != bytes_get_empty());
    }
    else if (size == 1) {
        unsigned char ch = PyBytes_AS_STRING(self)[0];
        assert(self != (PyObject*)CHARACTER(ch));
    }
    return 1;
}
#endif


/* The following function breaks the notion that bytes are immutable:
   it changes the size of a bytes object.  You can think of it
   as creating a new bytes object and destroying the old one, only
   more efficiently.
   Note that if there's not enough memory to resize the bytes object, the
   original bytes object at *pv is deallocated, *pv is set to NULL, an "out of
   memory" exception is set, and -1 is returned.  Else (on success) 0 is
   returned, and the value in *pv may or may not be the same as on input.
   As always, an extra byte is allocated for a trailing \0 byte (newsize
   does *not* include that), and a trailing \0 byte is stored.
*/

// Similar to _PyBytes_Resize(), but leaves the object unchanged on error.
int
_PyBytes_ResizeKeepOnError(PyObject **pv, Py_ssize_t newsize)
{
    PyObject *v = *pv;
    PyObject *result;

    if (!PyBytes_Check(v) || newsize < 0) {
        PyErr_BadInternalCall();
        return -1;
    }

    Py_ssize_t oldsize = PyBytes_GET_SIZE(v);
    if (oldsize == newsize) {
        /* return early if newsize equals to v->ob_size */
        return 0;
    }

    if (oldsize == 0) {
        result = _PyBytes_FromSize(newsize, 0);
        if (result == NULL) {
            return -1;
        }
        *pv = result;
        Py_DECREF(v);
        assert(_PyBytes_IsMutable(*pv));
        return 0;
    }

    if (newsize == 0) {
        *pv = bytes_get_empty();  // cannot fail
        Py_DECREF(v);
        return 0;
    }

    if (!_PyObject_IsUniquelyReferenced(v)) {
        // Allocate and then copy so we don't get a shared immortal
        // one-character singleton!
        result = _PyBytes_FromSize(newsize, 0);
        if (!result) {
            return -1;
        }

        memcpy(PyBytes_AS_STRING(result), PyBytes_AS_STRING(v),
               Py_MIN(oldsize, newsize));
        *pv = result;
        Py_DECREF(v);
        assert(_PyBytes_IsMutable(*pv));
        return 0;
    }

    // Only mutable bytes can be resized in-place
    assert(_PyBytes_IsMutable(v));

    if ((size_t)newsize > (size_t)PY_SSIZE_T_MAX - PyBytesObject_SIZE) {
        PyErr_SetString(PyExc_OverflowError,
                        "byte string is too large");
        return -1;
    }

#ifdef Py_TRACE_REFS
    _Py_ForgetReference(v);
#endif
    _PyReftracerTrack(v, PyRefTracer_DESTROY);

    result = (PyObject *)PyObject_Realloc(v, PyBytesObject_SIZE + newsize);
    if (result == NULL) {
#ifdef Py_TRACE_REFS
        _Py_AddToAllObjects(v);
#endif
        _PyReftracerTrack(v, PyRefTracer_CREATE);

        PyErr_NoMemory();
        return -1;
    }

    *pv = result;
    v = result;
    _Py_NewReferenceNoTotal(v);
    PyBytesObject *sv = (PyBytesObject *)v;
    Py_SET_SIZE(sv, newsize);
    sv->ob_sval[newsize] = '\0';
    set_ob_shash(sv, -1);          /* invalidate cached hash value */
    assert(_PyBytes_IsMutable(*pv));
    return 0;
}


int
_PyBytes_Resize(PyObject **pv, Py_ssize_t newsize)
{
    int res = _PyBytes_ResizeKeepOnError(pv, newsize);
    if (res < 0) {
        PyObject *v = *pv;
        *pv = NULL;
        Py_DECREF(v);
    }
    return res;
}


/*********************** Bytes Iterator ****************************/

typedef struct {
    PyObject_HEAD
    Py_ssize_t it_index;
    PyBytesObject *it_seq; /* Set to NULL when iterator is exhausted */
} striterobject;

/*[clinic input]
class bytes_iterator "striterobject *" "&PyBytesIter_Type"
[clinic start generated code]*/
/*[clinic end generated code: output=da39a3ee5e6b4b0d input=69924e510f28861b]*/

#define _striterobject_CAST(op)  ((striterobject *)(op))

static void
striter_dealloc(PyObject *op)
{
    striterobject *it = _striterobject_CAST(op);
    _PyObject_GC_UNTRACK(it);
    Py_XDECREF(it->it_seq);
    PyObject_GC_Del(it);
}

static int
striter_traverse(PyObject *op, visitproc visit, void *arg)
{
    striterobject *it = _striterobject_CAST(op);
    Py_VISIT(it->it_seq);
    return 0;
}

static PyObject *
striter_next(PyObject *op)
{
    striterobject *it = _striterobject_CAST(op);
    PyBytesObject *seq;

    assert(it != NULL);
    seq = it->it_seq;
    if (seq == NULL)
        return NULL;
    assert(PyBytes_Check(seq));

    if (it->it_index < PyBytes_GET_SIZE(seq)) {
        return _PyLong_FromUnsignedChar(
            (unsigned char)seq->ob_sval[it->it_index++]);
    }

    it->it_seq = NULL;
    Py_DECREF(seq);
    return NULL;
}

static PyObject *
striter_len(PyObject *op, PyObject *Py_UNUSED(ignored))
{
    striterobject *it = _striterobject_CAST(op);
    Py_ssize_t len = 0;
    if (it->it_seq)
        len = PyBytes_GET_SIZE(it->it_seq) - it->it_index;
    return PyLong_FromSsize_t(len);
}

static PyObject *
striter_reduce(PyObject *op, PyObject *Py_UNUSED(ignored))
{
    PyObject *iter = _PyEval_GetBuiltin(&_Py_ID(iter));

    /* _PyEval_GetBuiltin can invoke arbitrary code,
     * call must be before access of iterator pointers.
     * see issue #101765 */
    striterobject *it = _striterobject_CAST(op);
    if (it->it_seq != NULL) {
        return Py_BuildValue("N(O)n", iter, it->it_seq, it->it_index);
    } else {
        return Py_BuildValue("N(())", iter);
    }
}

static PyObject *
striter_setstate(PyObject *op, PyObject *state)
{
    Py_ssize_t index = PyLong_AsSsize_t(state);
    if (index == -1 && PyErr_Occurred())
        return NULL;
    striterobject *it = _striterobject_CAST(op);
    if (it->it_seq != NULL) {
        if (index < 0)
            index = 0;
        else if (index > PyBytes_GET_SIZE(it->it_seq))
            index = PyBytes_GET_SIZE(it->it_seq); /* iterator exhausted */
        it->it_index = index;
    }
    Py_RETURN_NONE;
}

static PyObject *
bytes_iter(PyObject *seq)
{
    striterobject *it;

    if (!PyBytes_Check(seq)) {
        PyErr_BadInternalCall();
        return NULL;
    }
    it = PyObject_GC_New(striterobject, &PyBytesIter_Type);
    if (it == NULL)
        return NULL;
    it->it_index = 0;
    it->it_seq = (PyBytesObject *)Py_NewRef(seq);
    _PyObject_GC_TRACK(it);
    return (PyObject *)it;
}


void
_PyBytes_RepeatBuffer(char* dest, Py_ssize_t len_dest,
    const char* src, Py_ssize_t len_src)
{
    if (len_dest == 0) {
        return;
    }
    if (len_src == 1) {
        memset(dest, src[0], len_dest);
    }
    else {
        if (src != dest) {
            memcpy(dest, src, len_src);
        }
        Py_ssize_t copied = len_src;
        while (copied < len_dest) {
            Py_ssize_t bytes_to_copy = Py_MIN(copied, len_dest - copied);
            memcpy(dest + copied, dest, bytes_to_copy);
            copied += bytes_to_copy;
        }
    }
}


// --- PyBytesWriter API -----------------------------------------------------

// Byte pattern to fill newly allocated bytes
#define PyBytesWrite_NEW_BYTE 0xff

// Use a value different than NUL (0) to be able to detect overflow writing
// one extra NUL byte which is a common error.
#define PyBytesWriter_CANARY_BYTE PYMEM_DEADBYTE

static inline char*
byteswriter_data(PyBytesWriter *writer)
{
    return _PyBytesWriter_GetData(writer);
}


static inline Py_ssize_t
byteswriter_allocated(PyBytesWriter *writer)
{
    if (writer->obj == NULL) {
        // Reserve the last byte for the canary byte
        return sizeof(writer->small_buffer) - 1;
    }
    else if (writer->use_bytearray) {
        return PyByteArray_GET_SIZE(writer->obj);
    }
    else {
        return PyBytes_GET_SIZE(writer->obj);
    }
}


#ifdef Py_DEBUG
static void
byteswriter_write_canary_byte(PyBytesWriter *writer)
{
    unsigned char *data = (unsigned char*)byteswriter_data(writer);
    data[writer->size] = PyBytesWriter_CANARY_BYTE;
}


static void
byteswriter_reset_trailing_byte(PyBytesWriter *writer)
{
    // PyBytesWriter writes non-zero canary byte as the last byte.
    // bytes/bytearray expects the last byte to be a null byte.
    // Reset the last byte to null for bytes/bytearray.
    Py_ssize_t allocated = byteswriter_allocated(writer);
    char *data = byteswriter_data(writer);
    data[allocated] = '\0';
}
#endif


#ifndef NDEBUG
static int
byteswriter_check_consistency(PyBytesWriter *writer)
{
    PyObject *obj = writer->obj;
    if (obj != NULL) {
        if (writer->use_bytearray) {
            assert(PyByteArray_CheckExact(obj));
            // Do not use _PyObject_IsUniquelyReferenced(): the caller can have
            // its own lock to prevent a writer from being used by two threads
            // at the same time.
            assert(Py_REFCNT(obj) == 1);
            PyByteArrayObject *bytearray = (PyByteArrayObject*)obj;
            obj = bytearray->ob_bytes_object;
            assert(obj != NULL);
        }

        // Code adapted from _PyBytes_IsMutable()
        assert(PyBytes_CheckExact(obj));
        assert(_PyBytes_IsMutable(obj));
        // -1 since the last small buffer byte is used as the canary byte
        assert((size_t)PyBytes_GET_SIZE(obj) > (sizeof(writer->small_buffer) - 1));
    }

#ifdef Py_DEBUG
    const unsigned char *data = (const unsigned char*)byteswriter_data(writer);
    unsigned char canary = data[writer->size];
    if (canary != PyBytesWriter_CANARY_BYTE) {
        _Py_FatalErrorFormat(__func__,
                             "Buffer overflow detected in PyBytesWriter %p "
                             "at position %zd",
                             writer, writer->size);
    }
#endif
    return 1;
}
#endif


#ifdef MS_WINDOWS
   /* On Windows, overallocate by 50% is the best factor */
#  define OVERALLOCATE_FACTOR 2
#else
   /* On Linux, overallocate by 25% is the best factor */
#  define OVERALLOCATE_FACTOR 4
#endif

static inline int
byteswriter_resize(PyBytesWriter *writer, Py_ssize_t new_size, int resize)
{
    assert(new_size >= 0);

    Py_ssize_t old_allocated = byteswriter_allocated(writer);
    if (new_size <= old_allocated) {
        // Do not shrink the buffer before PyBytesWriter_FinishWithSize()
        return 0;
    }

    Py_ssize_t alloc = new_size;
    if (resize && writer->overallocate) {
        if (alloc <= (PY_SSIZE_T_MAX - alloc / OVERALLOCATE_FACTOR)) {
            alloc += alloc / OVERALLOCATE_FACTOR;
        }
    }

    if (writer->obj != NULL) {
        if (writer->use_bytearray) {
            if (PyByteArray_Resize(writer->obj, alloc)) {
#ifdef Py_DEBUG
                // bytearray can override the canary byte on error
                byteswriter_write_canary_byte(writer);
#endif
                assert(byteswriter_check_consistency(writer));
                return -1;
            }
        }
        else {
            // Can raise MemoryError or OverflowError
            if (_PyBytes_ResizeKeepOnError(&writer->obj, alloc)) {
                assert(writer->obj != NULL);
                assert(byteswriter_check_consistency(writer));
                return -1;
            }
            assert(_PyBytes_IsMutable(writer->obj));
        }
        assert(writer->obj != NULL);
    }
    else {
        char *data;
        if (writer->use_bytearray) {
            writer->obj = PyByteArray_FromStringAndSize(NULL, alloc);
            if (writer->obj == NULL) {
                return -1;
            }
            data = PyByteArray_AS_STRING(writer->obj);
        }
        else {
            writer->obj = PyBytes_FromStringAndSize(NULL, alloc);
            if (writer->obj == NULL) {
                return -1;
            }
            assert(_PyBytes_IsMutable(writer->obj));
            data = PyBytes_AS_STRING(writer->obj);
        }

        if (resize) {
            // Copy data from the small buffer
            Py_ssize_t old_size = writer->size;
            assert((size_t)old_size <= sizeof(writer->small_buffer));
            assert(old_size <= alloc);
            memcpy(data, writer->small_buffer, old_size);
        }
    }

#ifdef Py_DEBUG
    Py_ssize_t allocated = byteswriter_allocated(writer);
    if (resize) {
        Py_ssize_t old_size = writer->size;
        assert(allocated > old_size);
        memset(byteswriter_data(writer) + old_size, PyBytesWrite_NEW_BYTE,
               allocated - old_size);
    }
#endif

    return 0;
}


static PyBytesWriter*
byteswriter_create(Py_ssize_t size, int use_bytearray)
{
    if (size < 0) {
        PyErr_SetString(PyExc_ValueError, "size must be >= 0");
        return NULL;
    }

    PyBytesWriter *writer = _Py_FREELIST_POP_MEM(bytes_writers);
    if (writer == NULL) {
        writer = (PyBytesWriter *)PyMem_Malloc(sizeof(PyBytesWriter));
        if (writer == NULL) {
            PyErr_NoMemory();
            return NULL;
        }
    }
    writer->obj = NULL;
    writer->size = 0;
    writer->use_bytearray = use_bytearray;
    writer->overallocate = !use_bytearray;

    if (size >= 1) {
        if (byteswriter_resize(writer, size, 0) < 0) {
#ifdef Py_DEBUG
            // Write the canary byte so byteswriter_check_consistency()
            // doesn't fail in PyBytesWriter_Discard()
            byteswriter_write_canary_byte(writer);
#endif
            PyBytesWriter_Discard(writer);
            return NULL;
        }
        writer->size = size;
    }
#ifdef Py_DEBUG
    memset(byteswriter_data(writer), PyBytesWrite_NEW_BYTE,
           byteswriter_allocated(writer));
    byteswriter_write_canary_byte(writer);
#endif
    assert(byteswriter_check_consistency(writer));
    return writer;
}

PyBytesWriter*
PyBytesWriter_Create(Py_ssize_t size)
{
    return byteswriter_create(size, 0);
}

PyBytesWriter*
_PyBytesWriter_CreateByteArray(Py_ssize_t size)
{
    return byteswriter_create(size, 1);
}


void
PyBytesWriter_Discard(PyBytesWriter *writer)
{
    if (writer == NULL) {
        return;
    }

    assert(byteswriter_check_consistency(writer));
#ifdef Py_DEBUG
    if (writer->obj != NULL) {
        byteswriter_reset_trailing_byte(writer);
    }
#endif

    Py_XDECREF(writer->obj);
    _Py_FREELIST_FREE(bytes_writers, writer, PyMem_Free);
}


PyObject*
PyBytesWriter_FinishWithSize(PyBytesWriter *writer, Py_ssize_t size)
{
    assert(byteswriter_check_consistency(writer));

    // Check for negative size here to raise ValueError in all cases, rather
    // than having a different exception depending on the code path. For
    // example, _PyBytes_Resize() raises SystemError on negative size.
    if (size < 0) {
        PyErr_Format(PyExc_ValueError, "size must be positive");
        goto error;
    }

    if (size > writer->size) {
        PyErr_SetString(PyExc_ValueError, "size larger than allocated size");
        goto error;
    }

    PyObject *result;
    if (size == 0) {
        result = bytes_get_empty();
    }
    else if (writer->obj != NULL) {
        // Truncate the bytes/bytearray object if needed
#ifdef Py_DEBUG
        byteswriter_reset_trailing_byte(writer);
#endif

        if (writer->use_bytearray) {
            if (size != PyByteArray_GET_SIZE(writer->obj)) {
                if (PyByteArray_Resize(writer->obj, size)) {
                    goto error;
                }
            }
        }
        else {
            if (size == 1) {
                // Get the single byte singleton
                unsigned char ch = PyBytes_AS_STRING(writer->obj)[0];
                PyObject *op = (PyObject*)CHARACTER(ch);
                assert(_Py_IsImmortal(op));
                Py_SETREF(writer->obj, op);
            }
            else if (size != PyBytes_GET_SIZE(writer->obj)) {
                if (_PyBytes_Resize(&writer->obj, size)) {
                    goto error;
                }
            }
        }

        result = writer->obj;
        writer->obj = NULL;
    }
    else {
        // Create an object from the small buffer
        if (writer->use_bytearray) {
            result = PyByteArray_FromStringAndSize(writer->small_buffer, size);
        }
        else {
            // The function returns single byte singleton if size equals 1
            result = PyBytes_FromStringAndSize(writer->small_buffer, size);
        }
    }

#ifdef Py_DEBUG
    // Reset the writer, so byteswriter_check_consistency() doesn't fail
    // in PyBytesWriter_Discard().
    writer->size = 0;
    byteswriter_write_canary_byte(writer);
#endif

    PyBytesWriter_Discard(writer);
    return result;

error:
    PyBytesWriter_Discard(writer);
    return NULL;
}

PyObject*
PyBytesWriter_Finish(PyBytesWriter *writer)
{
    return PyBytesWriter_FinishWithSize(writer, writer->size);
}


PyObject*
PyBytesWriter_FinishWithPointer(PyBytesWriter *writer, void *buf)
{
    Py_ssize_t size = (char*)buf - byteswriter_data(writer);
    return PyBytesWriter_FinishWithSize(writer, size);
}


void*
PyBytesWriter_GetData(PyBytesWriter *writer)
{
    assert(byteswriter_check_consistency(writer));

    return byteswriter_data(writer);
}


Py_ssize_t
PyBytesWriter_GetSize(PyBytesWriter *writer)
{
    assert(byteswriter_check_consistency(writer));

    return _PyBytesWriter_GetSize(writer);
}


int
PyBytesWriter_Resize(PyBytesWriter *writer, Py_ssize_t new_size)
{
    assert(byteswriter_check_consistency(writer));

    if (new_size < 0) {
        PyErr_SetString(PyExc_ValueError, "size must be >= 0");
        return -1;
    }
    if (writer->size < new_size) {
        if (byteswriter_resize(writer, new_size, 1) < 0) {
            return -1;
        }
    }
    else {
        // The buffer is already large enough. Never shrink the buffer.
    }
    writer->size = new_size;
#ifdef Py_DEBUG
    byteswriter_write_canary_byte(writer);
#endif
    assert(byteswriter_check_consistency(writer));
    return 0;
}


static void*
_PyBytesWriter_ResizeAndUpdatePointer(PyBytesWriter *writer, Py_ssize_t size,
                                      void *data)
{
    Py_ssize_t pos = (char*)data - byteswriter_data(writer);
    if (PyBytesWriter_Resize(writer, size) < 0) {
        return NULL;
    }
    return byteswriter_data(writer) + pos;
}


int
PyBytesWriter_Grow(PyBytesWriter *writer, Py_ssize_t grow)
{
    assert(byteswriter_check_consistency(writer));

    if (grow == 0) {
        // Nothing to do
        return 0;
    }

    if (grow > 0) {
        if (grow > PY_SSIZE_T_MAX - writer->size) {
            PyErr_NoMemory();
            return -1;
        }
        Py_ssize_t new_size = writer->size + grow;

        if (byteswriter_resize(writer, new_size, 1) < 0) {
            return -1;
        }
        writer->size = new_size;
    }
    else {
        if (writer->size + grow < 0) {
            PyErr_SetString(PyExc_ValueError, "invalid size");
            return -1;
        }
        // The buffer is already large enough. Never shrink the buffer.
        writer->size = writer->size + grow;
    }

#ifdef Py_DEBUG
    byteswriter_write_canary_byte(writer);
#endif
    assert(byteswriter_check_consistency(writer));
    return 0;
}


void*
PyBytesWriter_GrowAndUpdatePointer(PyBytesWriter *writer, Py_ssize_t size,
                                   void *buf)
{
    Py_ssize_t pos = (char*)buf - byteswriter_data(writer);
    if (PyBytesWriter_Grow(writer, size) < 0) {
        return NULL;
    }
    return byteswriter_data(writer) + pos;
}


int
PyBytesWriter_WriteBytes(PyBytesWriter *writer,
                         const void *bytes, Py_ssize_t size)
{
    if (size < 0) {
        size_t len = strlen(bytes);
        if (len > (size_t)PY_SSIZE_T_MAX) {
            PyErr_NoMemory();
            return -1;
        }
        size = (Py_ssize_t)len;
    }

    Py_ssize_t pos = writer->size;
    if (PyBytesWriter_Grow(writer, size) < 0) {
        return -1;
    }
    char *buf = byteswriter_data(writer);
    memcpy(buf + pos, bytes, size);

    assert(byteswriter_check_consistency(writer));
    return 0;
}


int
PyBytesWriter_Format(PyBytesWriter *writer, const char *format, ...)
{
    Py_ssize_t pos = writer->size;
    if (PyBytesWriter_Grow(writer, strlen(format)) < 0) {
        return -1;
    }

    va_list vargs;
    va_start(vargs, format);
    char *buf = bytes_fromformat(writer, pos, format, vargs);
    va_end(vargs);

    Py_ssize_t size = buf - byteswriter_data(writer);
    return PyBytesWriter_Resize(writer, size);
}


// Resize the writer to its allocated size.
// Return the new size.
// The function cannot fail.
static Py_ssize_t
_PyBytesWriter_ResizeToAllocated(PyBytesWriter *writer)
{
    Py_ssize_t allocated = byteswriter_allocated(writer);
    writer->size = allocated;
#ifdef Py_DEBUG
    byteswriter_write_canary_byte(writer);
#endif

    assert(byteswriter_check_consistency(writer));
    return allocated;
}


/* PyBytes_Type and PyBytesIter_Type, with their method and slot tables,
   are generated from Objects/pyspec/bytesobject.py by Argument Clinic. */
#include "clinic/bytesobject_types.c.h"

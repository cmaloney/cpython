"""The bytes type, written as Python: the spec of Objects/bytesobject.c.

Argument Clinic reads this file while processing bytesobject.c (see
Tools/clinic/libclinic/pyspec/).  The methods of ``class bytes`` give the
parameters and docstrings of the clinic blocks of bytesobject.c, which only
name the function.  Methods with a body of ``...`` are implemented in C by
hand.  bytes.__new__ is implemented here: clinic generates bytes_new_impl()
and, for its vectorcall, bytes_new_nargsN() -- the method partially
evaluated for exactly bytes and N positional arguments -- into
Objects/clinic/bytesobject_pyspec.c.h.  Top-level functions are C
functions of the same name.

Lib/test/test_clinic.py runs this file as Python and compares it with the
interpreter's bytes().
"""

from libclinic.pyspec.runtime import NULL, C, isinstance, fqname, tp_name


class bytes:
    def __new__(
        cls,
        source: object(c_name='x') = NULL,
        encoding: str = NULL,
        errors: str = NULL,
    ):
        if cls is not bytes:
            value = bytes.__new__(bytes, source, encoding, errors)
            return C.bytes_subtype_new(cls, value)
        if source is NULL:
            if encoding is not NULL:
                raise TypeError("encoding without a string argument")
            if errors is not NULL:
                raise TypeError("errors without a string argument")
            return b""
        if encoding is not NULL:
            if not isinstance(source, str):
                raise TypeError("encoding without a string argument")
            return C.PyUnicode_AsEncodedString(source, encoding, errors)
        if errors is not NULL:
            if isinstance(source, str):
                raise TypeError("string argument without an encoding")
            raise TypeError("errors without a string argument")
        # We'd like to call PyObject_Bytes here, but we need to check for an
        # integer argument before deferring to PyBytes_FromObject, something
        # PyObject_Bytes doesn't do.
        if (func := C.lookup_special(source, "__bytes__")) is not NULL:
            result = func()
            if not isinstance(result, bytes):
                raise TypeError(f"{fqname(type(source))}.__bytes__() must return "
                                f"a bytes, not {fqname(type(result))}")
            return result
        if isinstance(source, str):
            raise TypeError("string argument without an encoding")
        # Is it an integer?
        if hasattr(type(source), "__index__"):
            try:
                size = C.PyNumber_AsSsize_t(source, OverflowError)
            except TypeError:
                return PyBytes_FromObject(source)
            if size < 0:
                raise ValueError("negative count")
            return C._PyBytes_FromSize(size, True)
        return PyBytes_FromObject(source)


def PyBytes_FromObject(x: object):
    if x is NULL:
        raise C.PyErr_BadInternalCall()
    if type(x) is bytes:
        return x
    # Use the modern buffer interface
    if hasattr(type(x), "__buffer__"):
        return C._PyBytes_FromBuffer(x)
    if type(x) is list or type(x) is tuple:
        with C.critical_section_sequence_fast(x):
            result = C._PyBytes_FromSequence_lock_held(x)
        if result is not NULL:
            return result
    if not isinstance(x, str):
        try:
            it = iter(x)
        except TypeError:
            pass
        else:
            return C._PyBytes_FromIterator(it, x)
    raise TypeError(f"cannot convert '{tp_name(type(x))}' object to bytes")

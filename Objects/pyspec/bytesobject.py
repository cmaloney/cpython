"""bytes() construction, written as Python.

Tools/pyspec/emit_c.py generates Objects/clinic/bytesobject_pyspec.c.h
from this file.  Run Tools/pyspec/test_bytes_spec.py to compare the spec
(executed as Python) with the built interpreter's bytes().
"""

from pyspec_runtime import NULL, C, cstr, isinstance, fqname, tp_name


def bytes_new(cls, source=NULL, encoding: cstr = NULL, errors: cstr = NULL):
    """bytes.__new__; the subtype step stays in bytes_new_impl."""
    result = bytes_new_exact(source, encoding, errors)
    if cls is not bytes:
        result = bytes.__new__(cls, result)
    return result


def bytes_new_exact(source: object, encoding: cstr, errors: cstr):
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
            return bytes_from_object(source)
        if size < 0:
            raise ValueError("negative count")
        return C._PyBytes_FromSize(size, True)
    return bytes_from_object(source)


def bytes_from_object(x: object):
    """PyBytes_FromObject()"""
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


# What emit_c.py generates from this file.
PYSPEC = {
    'functions': ['bytes_new_exact', 'bytes_from_object'],
    # bytes_new_exact_nargsN(): bytes_new_exact() partially evaluated for
    # N positional arguments.  Called by the Argument Clinic generated
    # bytes_vectorcall() (@vectorcall exact=bytes_new_exact) after it
    # converted the arguments.
    'arities': {
        'entry': 'bytes_new_exact',
        'nargs': [0, 1, 2, 3],
    },
}

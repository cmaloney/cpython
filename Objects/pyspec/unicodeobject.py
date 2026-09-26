"""Spec of Objects/unicodeobject.c: the functions other specs call.

Each is @c_implemented: the C is the authority; the body is its Python
reference (see Objects/pyspec/README.rst).
"""

from libclinic.pyspec.runtime import (
    NULL, c_implemented, runs_python, unknown)


@c_implemented
def PyUnicode_AsEncodedString(unicode: object, encoding: str, errors: str):
    """unicode encoded with the codec encoding (UTF-8 when NULL).  The
    codec may be Python code, and may return an instance of a bytes
    subclass."""
    runs_python()
    return unknown(str.encode(
        unicode, 'utf-8' if encoding is NULL else encoding,
        'strict' if errors is NULL else errors))

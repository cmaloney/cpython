"""Spec of Objects/unicodeobject.c: the functions other specs call.

Each is @native: the C is the authority; the body is its Python
reference (see Objects/pyspec/README.rst).  The codecs are the edge of
the model of bytes (README.rst, "Pure Python"): a codec is host code
that reads a buffer and returns str, or bytes (machine.from_host()).
"""

import codecs
import sys

from libclinic.pyspec.runtime import (
    NULL, isinstance, native, runs_python, tp_name, unknown)
from libclinic.pyspec.machine import from_host


@native
def PyUnicode_AsEncodedString(unicode: object, encoding: str, errors: str):
    """unicode encoded with the codec encoding (UTF-8 when NULL).  The
    codec may be Python code, and may return an instance of a bytes
    subclass."""
    runs_python()
    return unknown(from_host(bytes, str.encode(
        unicode, 'utf-8' if encoding is NULL else encoding,
        'strict' if errors is NULL else errors)))


@native(facts=False)
def PyUnicode_FromEncodedObject(obj: object, encoding: str, errors: str):
    """The buffer of obj decoded with the text codec encoding (UTF-8
    when NULL)."""
    unicode_check_encoding_errors(encoding, errors)
    encoding = 'utf-8' if encoding is NULL else encoding
    info = codecs.lookup(encoding)
    if not info._is_text_encoding:
        raise LookupError(f"'{encoding}' is not a text encoding; use "
                          "codecs.decode() to handle arbitrary codecs")
    unicode = info.decode(obj, 'strict' if errors is NULL else errors)[0]
    if not isinstance(unicode, str):
        raise TypeError(f"'{encoding}' decoder returned "
                        f"'{tp_name(type(unicode))}' instead of 'str'; use "
                        "codecs.decode() to decode to arbitrary types")
    return unicode


@native(facts=False)
def unicode_check_encoding_errors(encoding: str, errors: str) -> int:
    """In a debug build or the development mode (-X dev), the codec and
    the error handler exist, even when nothing is decoded."""
    if not (hasattr(sys, 'gettotalrefcount') or sys.flags.dev_mode):
        return 0
    if encoding is not NULL and encoding not in ('utf-8', 'utf8', 'ascii'):
        codecs.lookup(encoding)
    if errors is not NULL and errors not in (
            'strict', 'ignore', 'replace', 'surrogateescape',
            'surrogatepass'):
        codecs.lookup_error(errors)
    return 0

"""Spec of Objects/unicodeobject.c: the functions other specs call.

Each is ``@ac.stub``: the C is the authority; the body is its Python
reference (``optimizer_info=True``) or, for PyUnicode_FromEncodedObject(),
its pure-Python implementation (see Objects/pyspec/README.rst).  The
codecs are the edge of the model of bytes (README.rst, "Pure Python"): a
codec is host code that reads a buffer and returns str, or bytes
(machine.from_host()).
"""

import codecs
import sys

from libclinic.pyspec import ac, rt, machine


@ac.stub(optimizer_info=True)
def PyUnicode_AsEncodedString(unicode: ac.object, encoding: ac.str,
                              errors: ac.str):
    """unicode encoded with the codec encoding (UTF-8 when NULL).  The
    codec may be Python code, and may return an instance of a bytes
    subclass."""
    rt.runs_python()
    return rt.unknown(machine.from_host(bytes, str.encode(
        unicode, 'utf-8' if encoding is rt.NULL else encoding,
        'strict' if errors is rt.NULL else errors)))


@ac.stub
def PyUnicode_FromEncodedObject(obj: ac.object, encoding: ac.str,
                                errors: ac.str):
    """The buffer of obj decoded with the text codec encoding (UTF-8
    when NULL)."""
    unicode_check_encoding_errors(encoding, errors)
    encoding = 'utf-8' if encoding is rt.NULL else encoding
    info = codecs.lookup(encoding)
    if not info._is_text_encoding:
        raise LookupError(f"'{encoding}' is not a text encoding; use "
                          "codecs.decode() to handle arbitrary codecs")
    unicode = info.decode(obj, 'strict' if errors is rt.NULL else errors)[0]
    if not rt.isinstance(unicode, str):
        raise TypeError(f"'{encoding}' decoder returned "
                        f"'{rt.tp_name(type(unicode))}' instead of 'str'; use "
                        "codecs.decode() to decode to arbitrary types")
    return unicode


@ac.stub
def unicode_check_encoding_errors(encoding: ac.str, errors: ac.str) -> ac.int:
    """In a debug build or the development mode (-X dev), the codec and
    the error handler exist, even when nothing is decoded."""
    if not (hasattr(sys, 'gettotalrefcount') or sys.flags.dev_mode):
        return 0
    if encoding is not rt.NULL and encoding not in ('utf-8', 'utf8', 'ascii'):
        codecs.lookup(encoding)
    if errors is not rt.NULL and errors not in (
            'strict', 'ignore', 'replace', 'surrogateescape',
            'surrogatepass'):
        codecs.lookup_error(errors)
    return 0

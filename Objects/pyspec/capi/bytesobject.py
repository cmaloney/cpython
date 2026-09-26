"""Facts about the C API functions of Objects/bytesobject.c that no other
file records.

Everything else about them is read from where it is already written: the
C types from the headers and the C definitions, the documented signatures
from Doc/c-api/bytes.rst, ownership from Doc/data/refcounts.dat,
stable ABI membership from Misc/stable_abi.toml and thread safety from
Doc/data/threadsafety.dat.  A function whose body is in the spec
(PyBytes_FromObject, and @c_implemented _PyBytes_FromHex, in
Objects/pyspec/bytesobject.py) has its facts derived from its body and is
not listed here.

Lib/test/test_pyspec_catalog.py checks that every other non-static
Py*/_Py* function defined in bytesobject.c is in exactly one of the sets
(see Tools/clinic/libclinic/pyspec/disconnects.py).
"""

# May run arbitrary Python code: __index__, __buffer__, __iter__, codecs,
# warnings, ...
RUNS_PYTHON = {
    'PyBytes_Concat',
    'PyBytes_ConcatAndDel',
    'PyBytes_DecodeEscape',
    'PyBytes_Join',
    '_PyBytes_Concat',
    '_PyBytes_FormatEx',
}

# Never runs Python code.
NO_PYTHON = {
    'PyBytesWriter_Create',
    'PyBytesWriter_Discard',
    'PyBytesWriter_Finish',
    'PyBytesWriter_FinishWithPointer',
    'PyBytesWriter_FinishWithSize',
    'PyBytesWriter_Format',
    'PyBytesWriter_GetData',
    'PyBytesWriter_GetSize',
    'PyBytesWriter_Grow',
    'PyBytesWriter_GrowAndUpdatePointer',
    'PyBytesWriter_Resize',
    'PyBytesWriter_WriteBytes',
    'PyBytes_AsString',
    'PyBytes_AsStringAndSize',
    'PyBytes_FromFormat',
    'PyBytes_FromFormatV',
    'PyBytes_FromString',
    'PyBytes_FromStringAndSize',
    'PyBytes_Repr',
    'PyBytes_Size',
    '_PyBytesWriter_CreateByteArray',
    '_PyBytes_CheckOverflow',
    '_PyBytes_DecodeEscape2',
    '_PyBytes_Find',
    '_PyBytes_IsMutable',
    '_PyBytes_Repeat',
    '_PyBytes_RepeatBuffer',
    '_PyBytes_Resize',
    '_PyBytes_ResizeKeepOnError',
    '_PyBytes_ReverseFind',
    '_Py_bytes_repr',
}

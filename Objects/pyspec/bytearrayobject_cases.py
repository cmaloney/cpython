"""Test data for Objects/pyspec/bytearrayobject.py (see test_clinic's
PyspecFilesTest).

TYPES maps each class of the spec to the type it describes; the spec
has no bodies, hence no CASES.
"""

TYPES = {
    'bytearray': bytearray,
    'bytearray_iterator': type(iter(bytearray())),
}

CASES = {}

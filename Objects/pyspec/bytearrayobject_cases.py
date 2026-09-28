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

# For Tools/clinic/pyspec_parity.py: see bytesobject_cases.py.
PARITY = {
    'bytearray': {
        'samples': {
            "bytearray(b'a b')": lambda: bytearray(b'a b'),
            'bytearray()': lambda: bytearray(),
            "bytearray(b'\\x00\\xffAz \\t')":
                lambda: bytearray(b'\x00\xffAz \t'),
        },
        'pool': {
            "b' '": lambda: b' ',
            "b'\\x00'": lambda: b'\x00',
            "'strict'": lambda: 'strict',
            "'ascii'": lambda: 'ascii',
        },
    },
    'bytearray_iterator': {
        'samples': {
            "iter(bytearray(b'abc'))": lambda: iter(bytearray(b'abc')),
            'iter(bytearray())': lambda: iter(bytearray()),
        },
    },
}

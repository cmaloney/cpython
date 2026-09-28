"""Test data for Objects/pyspec/abstract.py (see the docstring of
Objects/pyspec/bytesobject_cases.py for the names).

The spec has no classes and no bodies: only the Python references of C
functions, called by test_pyspec_facts HelperTest (HELPERS) and pinned by
the facts derived from them (FACTS).
"""

import collections
import operator
import types


class NULL:
    """C NULL: an argument, or a fact about a parameter."""


class IntSubclass(int):
    pass


class IndexOnly:
    def __init__(self, value):
        self.value = value

    def __index__(self):
        return self.value


class IterOnly:
    def __iter__(self):
        return iter([1, 2])


HELPERS = {
    'PyNumber_AsSsize_t': [
        (5, NULL), (True, NULL), (-7, NULL), (2**40, NULL),
        (2**70, NULL), (-2**70, NULL), (2**70, OverflowError),
        (2**70, IndexError), (IntSubclass(9), NULL),
        (IndexOnly(4), NULL), (IndexOnly(2**70), OverflowError),
        (1.5, NULL), ('x', NULL)],
    '_PyNumber_Index': [(5,), (True,), (IntSubclass(3),), (IndexOnly(2),),
                        (1.5,), ('x',)],
    'PyObject_LengthHint': [
        ([1, 2], 64), ((1,), 64), (range(5), 64), ({1: 2}, 64),
        (iter([1, 2, 3]), 64), (IterOnly(), 64), (5, 64),
        (bytearray(b'ab'), 64), ('abc', 64)],
}


class _Mapping(collections.UserDict):
    def __len__(self):
        return 3

    def __iter__(self):
        return iter([1, 2, 3])


class _Sequence:
    def __len__(self):
        return 2

    def __getitem__(self, i):
        return [65, 66][i]


# F3: "an exact static type never runs Python code" is false for types
# that forward to another object: builtin_types.py must not list them.
# run(input()) makes the call of expr and must run Python code.
FACTS = [
    dict(expr='PyObject_LengthHint(x, 0)',
         env={'x': types.MappingProxyType}, runs_python=True,
         run=operator.length_hint,
         input=lambda: types.MappingProxyType(_Mapping())),
    dict(expr='PyObject_LengthHint(x, 0)', env={'x': reversed},
         runs_python=True, run=operator.length_hint,
         input=lambda: reversed(_Sequence())),
    dict(expr='iter(x)', env={'x': types.MappingProxyType},
         runs_python=True, run=iter,
         input=lambda: types.MappingProxyType(_Mapping())),
    # The leaf types the table lists run none.
    dict(expr='PyObject_LengthHint(x, 0)', env={'x': range},
         runs_python=False),
]

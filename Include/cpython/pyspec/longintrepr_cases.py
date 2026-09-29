"""Test data for Include/cpython/pyspec/longintrepr.py (see the docstring
of Objects/pyspec/bytesobject_cases.py for the names).  Both functions
are static inline: the pyspec_helpers[] table of
Modules/_testinternalcapi.c calls them through wrappers of the right
pointer type, and _testinternalcapi.pyspec_helper() calls a row."""

# The bounds of a digit of either size (PyLong_SHIFT 15 or 30), on both
# sides.
HELPERS = {
    '_PyLong_IsCompact': [(0,), (5,), (True,), (2**15 - 1,), (2**15,),
                          (-2**15 + 1,), (-2**15,), (2**29,),
                          (2**30 - 1,), (2**30,), (-2**30 + 1,),
                          (-2**30,), (2**70,)],
    '_PyLong_CompactValue': [(0,), (-5,), (2**15 - 1,), (True,)],
}

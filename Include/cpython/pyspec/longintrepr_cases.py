"""Test data for Include/cpython/pyspec/longintrepr.py (see the docstring
of Objects/pyspec/bytesobject_cases.py for the names).  Both functions
are static inline: _testinternalcapi.pyspec_inline_helpers() gives their
addresses."""

# The bounds of a digit of either size (PyLong_SHIFT 15 or 30), on both
# sides.
HELPERS = {
    '_PyLong_IsCompact': [(0,), (5,), (True,), (2**15 - 1,), (2**15,),
                          (-2**15 + 1,), (-2**15,), (2**29,),
                          (2**30 - 1,), (2**30,), (-2**30 + 1,),
                          (-2**30,), (2**70,)],
    '_PyLong_CompactValue': [(0,), (-5,), (2**15 - 1,), (True,)],
}

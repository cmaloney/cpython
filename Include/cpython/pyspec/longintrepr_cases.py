"""Test data for Include/cpython/pyspec/longintrepr.py (see the docstring
of Objects/pyspec/bytesobject_cases.py for the names).  Both functions
are static inline: _testinternalcapi.pyspec_inline_helpers() gives their
addresses."""

HELPERS = {
    '_PyLong_IsCompact': [(0,), (5,), (2**29,), (2**30,), (2**70,),
                          (True,)],
    '_PyLong_CompactValue': [(0,), (-5,), (2**29,), (True,)],
}

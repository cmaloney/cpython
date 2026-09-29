"""Spec of Objects/longobject.c: the functions other specs call.

Each is ``@native(facts=False)``: C written by hand, the body its
pure-Python implementation, which only the model runs
(Objects/pyspec/README.rst, "Pure Python").
"""

from libclinic.pyspec.runtime import PY_SSIZE_T_MAX, isinstance, native


@native(facts=False)
def PyLong_AsSsize_t(vv: object) -> Py_ssize_t:
    """vv, an int, as a Py_ssize_t (no __index__)."""
    if not isinstance(vv, int):
        raise TypeError("an integer is required")
    if not -PY_SSIZE_T_MAX - 1 <= vv <= PY_SSIZE_T_MAX:
        raise OverflowError("Python int too large to convert to C ssize_t")
    return int(vv)

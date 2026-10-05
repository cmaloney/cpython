"""Spec of Objects/longobject.c: the functions other specs call.

Each is ``@ac.stub``: C written by hand, the body its pure-Python
implementation, which only the model runs (Objects/pyspec/README.rst,
"Pure Python").
"""

from libclinic.pyspec import ac, rt


@ac.stub
def PyLong_AsSsize_t(vv: ac.object) -> ac.Py_ssize_t:
    """vv, an int, as a Py_ssize_t (no __index__)."""
    if not rt.isinstance(vv, int):
        raise TypeError("an integer is required")
    if not -rt.PY_SSIZE_T_MAX - 1 <= vv <= rt.PY_SSIZE_T_MAX:
        raise OverflowError("Python int too large to convert to C ssize_t")
    return int(vv)

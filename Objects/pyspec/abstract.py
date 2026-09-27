"""Spec of Objects/abstract.c: the functions other specs call.

Each is @c_implemented: the C is the authority; the body is its Python
reference, run when a spec runs as Python and read for the facts of its
calls (see Objects/pyspec/README.rst).  A leading ``if <test>: return
<value>`` is a fast path: where a call knows the test holds, Argument
Clinic writes the value instead of the call.
"""

import operator

from libclinic.pyspec.runtime import (
    NULL, PY_SSIZE_T_MAX, c_implemented, calls, isinstance, runs_python,
    tp_name)

from Include.cpython.pyspec.longintrepr import (
    _PyLong_CompactValue, _PyLong_IsCompact)
from pyspec.typeobject import _PyObject_LookupSpecial


@c_implemented
def _PyNumber_Index(o: object):
    """o itself if it is an int, else o.__index__(), which must return an
    int."""
    if o is NULL:
        raise SystemError("null argument to internal routine")
    if isinstance(o, int):
        return o
    if not hasattr(type(o), "__index__"):
        raise TypeError(f"'{tp_name(type(o))}' object cannot be "
                        "interpreted as an integer")
    calls(o, "__index__")
    # A result of a strict subclass of int is deprecated: a warning, whose
    # filters may be Python code.
    runs_python()
    return operator.index(o)


@c_implemented
def PyNumber_AsSsize_t(o: object, exc: object) -> Py_ssize_t:
    """o (with its __index__) as a Py_ssize_t: exc is raised when it does
    not fit, or, when exc is NULL, the nearest bound is returned."""
    if (type(o) is int or type(o) is bool) and _PyLong_IsCompact(o):
        return _PyLong_CompactValue(o)
    value = _PyNumber_Index(o)
    if -PY_SSIZE_T_MAX - 1 <= value <= PY_SSIZE_T_MAX:
        return int(value)
    if exc is NULL:
        return PY_SSIZE_T_MAX if value > 0 else -PY_SSIZE_T_MAX - 1
    raise exc(f"cannot fit '{tp_name(type(o))}' into an index-sized "
              "integer")


@c_implemented
def PyObject_LengthHint(o: object, defaultvalue: Py_ssize_t) -> Py_ssize_t:
    """len(o), else o.__length_hint__(), else defaultvalue: a TypeError
    from either means it has none."""
    if type(o) is list or type(o) is tuple:
        return len(o)
    if hasattr(type(o), "__len__"):
        try:
            return len(o)
        except TypeError:
            pass
    hint = _PyObject_LookupSpecial(o, "__length_hint__")
    if hint is NULL:
        return defaultvalue
    runs_python()       # the call of hint
    return operator.length_hint(o, defaultvalue)

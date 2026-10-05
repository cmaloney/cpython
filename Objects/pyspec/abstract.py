"""Spec of Objects/abstract.c: the functions other specs call.

The ``@ac.stub(optimizer_info=True)`` ones are the C of abstract.c: the C is
the authority; the body is its Python reference, run when a spec runs as
Python and read for the facts of its calls, never compiled (see
Objects/pyspec/README.rst).  The ``@ac.inline`` ones are fast paths that
spec bodies call instead: generated code, written once here, which calls
the native function last.
"""

import operator

from libclinic.pyspec import ac, rt

from Include.cpython.pyspec import longintrepr
from Objects.pyspec import typeobject


@ac.stub(optimizer_info=True)
def _PyNumber_Index(o: ac.object):
    """o itself if it is an int, else o.__index__(), which must return an
    int."""
    if o is rt.NULL:
        raise SystemError("null argument to internal routine")
    if rt.isinstance(o, int):
        return o
    if not hasattr(type(o), "__index__"):
        raise TypeError(f"'{rt.tp_name(type(o))}' object cannot be "
                        "interpreted as an integer")
    rt.calls(o, "__index__")
    # A result of a strict subclass of int is deprecated: a warning, whose
    # filters may be Python code.
    rt.runs_python()
    return operator.index(o)


@ac.stub(optimizer_info=True)
def PyNumber_AsSsize_t(o: ac.object, exc: ac.object) -> ac.Py_ssize_t:
    """o (with its __index__) as a Py_ssize_t: exc is raised when it does
    not fit, or, when exc is NULL, the nearest bound is returned."""
    value = _PyNumber_Index(o)
    if -rt.PY_SSIZE_T_MAX - 1 <= value <= rt.PY_SSIZE_T_MAX:
        return int(value)
    if exc is rt.NULL:
        return rt.PY_SSIZE_T_MAX if value > 0 else -rt.PY_SSIZE_T_MAX - 1
    raise exc(f"cannot fit '{rt.tp_name(type(o))}' into an index-sized "
              "integer")


@ac.stub(optimizer_info=True)
def PyObject_LengthHint(o: ac.object, defaultvalue: ac.Py_ssize_t
                        ) -> ac.Py_ssize_t:
    """len(o), else o.__length_hint__(), else defaultvalue: a TypeError
    from either means it has none."""
    if hasattr(type(o), "__len__"):
        try:
            return len(o)
        except TypeError:
            pass
    hint = typeobject._PyObject_LookupSpecial(o, "__length_hint__")
    if hint is rt.NULL:
        return defaultvalue
    rt.runs_python()       # the call of hint
    return operator.length_hint(o, defaultvalue)


# Fast paths, generated into the spec bodies that call them.

@ac.inline
def PyNumber_AsSsize_t_fast(o: ac.object, exc: ac.object) -> ac.Py_ssize_t:
    """PyNumber_AsSsize_t(o, exc), read inline for a compact int."""
    if ((type(o) is int or type(o) is bool)
            and longintrepr._PyLong_IsCompact(o)):
        return longintrepr._PyLong_CompactValue(o)
    return PyNumber_AsSsize_t(o, exc)


@ac.inline
def PyObject_LengthHint_fast(o: ac.object, defaultvalue: ac.Py_ssize_t
                             ) -> ac.Py_ssize_t:
    """PyObject_LengthHint(o, defaultvalue), read inline for an exact list
    or tuple: its size (the len() of PyObject_LengthHint())."""
    if type(o) is list:
        return len(o)
    if type(o) is tuple:
        return len(o)
    return PyObject_LengthHint(o, defaultvalue)

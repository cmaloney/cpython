"""Spec of Objects/typeobject.c: the functions other specs call.

Each is ``@ac.stub(optimizer_info=True)``: the C is the authority; the body
is its Python reference (see Objects/pyspec/README.rst).
"""

import inspect

from libclinic.pyspec import ac, rt


@ac.stub(optimizer_info=True)
def _PyObject_LookupSpecial(obj: ac.object, name: ac.object):
    """The attribute name of type(obj), bound to obj by its __get__ (if
    it has one); NULL, not an error, when type(obj) has none."""
    if not hasattr(type(obj), name):
        return rt.NULL
    attr = inspect.getattr_static(type(obj), name)
    rt.calls(attr, "__get__")
    get = getattr(type(attr), '__get__', None)
    return rt.unknown(attr if get is None else get(attr, obj, type(obj)))

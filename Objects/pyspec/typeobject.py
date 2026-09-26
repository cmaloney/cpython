"""Spec of Objects/typeobject.c: the functions other specs call.

Each is @c_implemented: the C is the authority; the body is its Python
reference (see Objects/pyspec/README.rst).
"""

import inspect

from libclinic.pyspec.runtime import NULL, c_implemented, calls, unknown


@c_implemented
def _PyObject_LookupSpecial(obj: object, name: object):
    """The attribute name of type(obj), bound to obj by its __get__ (if
    it has one); NULL, not an error, when type(obj) has none."""
    if not hasattr(type(obj), name):
        return NULL
    attr = inspect.getattr_static(type(obj), name)
    calls(attr, "__get__")
    get = getattr(type(attr), '__get__', None)
    return unknown(attr if get is None else get(attr, obj, type(obj)))

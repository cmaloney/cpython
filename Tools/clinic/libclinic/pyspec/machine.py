"""The machine primitives: what a spec body cannot say in Python.

A spec body that is Python all the way down (Objects/pyspec/README.rst,
"Pure Python") computes with the host types no spec describes (int, str,
tuple, list, slice, the exceptions) and calls other spec functions.  What
is left is the object layout and memory, which C has and Python does not:
these primitives.  Each has one Python meaning per machine and one C
meaning, the C it stands for (it is never lowered: a body calling one is
native, and the C does what it says):

====================  =================================  ====================
primitive             Python                             C
====================  =================================  ====================
ob_alloc(tp, items)   a new tp holding the bytes items   PyBytes_FromStringAnd
                      (a sequence of ints in range(256))  Size(), tp_alloc()
ob_items(o)           the bytes o holds, a tuple of int  PyBytes_AS_STRING(o),
                                                         Py_SIZE(o)
ob_new(tp)            a new tp, its fields NULL           PyObject_GC_New()
buffer_items(o)       the bytes of the buffer o exports,  PyObject_GetBuffer(),
                      NULL if it exports none             PyBuffer_Release()
buffer_export(o)      the view of o's bytes (__buffer__)  bf_getbuffer
hash_secret()         (k0, k1): the key of the hash of    _Py_HashSecret
                      bytes (sys.hash_info.algorithm)
has_slot(tp, slot)    whether type tp fills slot          tp->tp_as_...->slot
from_host(tp, v)      v, which host code outside the      (nothing: one bytes
                      model returned (a codec), as a tp   type)
====================  =================================  ====================

Two machines give them a meaning:

* the host (runtime.load(), the tests of the Python references): the
  classes of a spec are the builtins, and a primitive reads or makes the
  host object, e.g. ``ob_items(b)`` is ``tuple(b)``;
* the model (model.py): the classes of a spec are Python classes built
  from it (instances of ``VarObject``/``Object``), which hold their bytes
  in ``_ob_items`` and their fields in slots; nothing of the host's
  bytes, bytearray or memoryview is used except here, at the edges
  (buffer_items() of a host object, buffer_export(), from_host()).

A primitive picks its machine from the type or object it is given.
"""

import builtins
import sys

from .runtime import NULL

__all__ = [
    'ob_alloc', 'ob_items', 'ob_new', 'buffer_items', 'buffer_export',
    'hash_secret', 'has_slot', 'from_host',
]


class Buffer(tuple):
    """A Py_buffer (clinic's Py_buffer converter): the bytes of the
    buffer; ``obj``, the object that exports it."""

    def __new__(cls, items, obj):
        self = super().__new__(cls, items)
        self.obj = obj
        return self


class _NoSignature:
    """inspect.signature() of a static type: from its docstring, which
    has none for a type with a __new__ of its own (bytes: ValueError),
    else the ``()`` of object's."""

    def __get__(self, obj, cls):
        if obj is not None:
            raise AttributeError('__signature__')
        if any('__new__' in c.__dict__ for c in cls.__mro__
               if c in MODELS):
            raise ValueError(f'no signature found for builtin type {cls!r}')
        import inspect
        return inspect.Signature()


# tp_flags of the PyTypeObject of a model class (set_type_flags()).
Py_TPFLAGS_BASETYPE = 1 << 10
Py_TPFLAGS_DISALLOW_INSTANTIATION = 1 << 7
FINAL = set()               # model classes that are not a BASETYPE
NOT_CALLABLE = set()        # model classes with no tp_new


def set_type_flags(model, flags):
    """What model class *model* takes from the flags of its PyTypeObject
    (which stays C): whether it can be subclassed and instantiated."""
    if not flags & Py_TPFLAGS_BASETYPE:
        FINAL.add(model)
    if flags & Py_TPFLAGS_DISALLOW_INSTANTIATION:
        NOT_CALLABLE.add(model)


class _Static:
    """What the model classes share with a static type."""
    __slots__ = ()
    __signature__ = _NoSignature()

    def __new__(cls, *args, **kwargs):
        if cls in NOT_CALLABLE:
            raise TypeError(f"cannot create '{cls.__name__}' instances")
        return super().__new__(cls)

    def __init_subclass__(cls, **kwargs):
        for base in cls.__mro__[1:]:
            if base in FINAL:
                raise TypeError(f"type '{base.__name__}' is not an "
                                "acceptable base type")
        super().__init_subclass__(**kwargs)


class Object(_Static):
    """An instance of a model class with fixed fields (its annotations,
    ``it_index: Py_ssize_t``), NULL until set."""
    __slots__ = ()


class VarObject(_Static):
    """An instance of a model class holding bytes (bytes)."""
    __slots__ = ('_ob_items',)


def _is_model(tp):
    return builtins.issubclass(tp, (Object, VarObject))


def ob_alloc(tp, items):
    """A new object of type *tp* (a spec class or a subclass) holding
    *items*, a sequence of ints in range(256)."""
    if _is_model(tp):
        obj = object.__new__(tp)
        obj._ob_items = builtins.tuple(items)
        return obj
    # The host: the builtin (or a subclass of it) with those bytes.
    base = next(t for t in tp.__mro__ if t.__module__ == 'builtins')
    if tp is base:
        return base(items)
    return base.__new__(tp, items)


def ob_items(obj):
    """The bytes *obj* holds, a tuple of ints."""
    if builtins.isinstance(obj, VarObject):
        return obj._ob_items
    return builtins.tuple(builtins.memoryview(obj).cast('B'))


def ob_new(tp):
    """A new object of model class *tp*, its fields NULL."""
    obj = object.__new__(tp)
    for cls in tp.__mro__:
        for name in cls.__dict__.get('__slots__', ()):
            if name != '__dict__' and name != '__weakref__':
                setattr(obj, name, NULL)
    return obj


def buffer_items(obj):
    """The bytes of the buffer *obj* exports (C order), a tuple of ints;
    NULL if it exports none.  Runs its __buffer__ and
    __release_buffer__."""
    if builtins.isinstance(obj, VarObject) and \
            '__buffer__' not in _python_dict(type(obj)):
        return obj._ob_items
    try:
        view = builtins.memoryview(obj)
    except TypeError:
        return NULL
    with view:
        return builtins.tuple(view.tobytes())


# The model classes built from specs (model.py): {class: model}.
MODELS = {}


def _python_dict(tp):
    """The names the Python subclasses of a model class define."""
    names = set()
    for cls in tp.__mro__:
        if cls in MODELS:
            break
        names |= set(cls.__dict__)
    return names


PyBUF_WRITABLE = 0x0001


def buffer_export(obj, flags=0):
    """The read-only view of the bytes of *obj* that __buffer__ returns
    (PyBuffer_FillInfo() of a read-only buffer)."""
    if builtins.isinstance(obj, VarObject):
        if flags & PyBUF_WRITABLE:
            raise BufferError('Object is not writable.')
        import array
        return builtins.memoryview(
            array.array('B', obj._ob_items)).toreadonly()
    return builtins.memoryview(obj)


def hash_secret():
    """(k0, k1): the key of the interpreter's SipHash of bytes."""
    import ctypes
    key = (ctypes.c_uint64 * 2).in_dll(ctypes.pythonapi, '_Py_HashSecret')
    return key[0], key[1]


# The sub-tables of a PyTypeObject that has_slot() reads, and the slots of
# each, in order (Include/cpython/object.h).
_SUBTABLES = {
    'tp_as_sequence': ('sq_length', 'sq_concat', 'sq_repeat', 'sq_item'),
}


def has_slot(tp, slot):
    """Whether type *tp* fills *slot* (``'sq_repeat'``): what the
    interpreter's dispatch (abstract.c) looks at and Python cannot see,
    e.g. which operand of ``a * b`` repeats a sequence."""
    import ctypes
    for table, names in _SUBTABLES.items():
        if slot in names:
            break
    else:
        raise ValueError(f'has_slot() does not know {slot}')
    # tp_as_sequence is the 11th pointer after the PyVarObject header.
    header = object.__basicsize__ + ctypes.sizeof(ctypes.c_ssize_t)
    fields = ('tp_name', 'tp_basicsize', 'tp_itemsize', 'tp_dealloc',
              'tp_vectorcall_offset', 'tp_getattr', 'tp_setattr',
              'tp_as_async', 'tp_repr', 'tp_as_number', 'tp_as_sequence')
    pointer = ctypes.sizeof(ctypes.c_void_p)
    address = ctypes.c_void_p.from_address(
        id(tp) + header + fields.index(table) * pointer).value
    if not address:
        return False
    return bool(ctypes.c_void_p.from_address(
        address + names.index(slot) * pointer).value)


def from_host(tp, value):
    """*value*, which host code outside the model returned (the bytes of
    a codec), as an object of the machine of *tp*: itself on the host, a
    new *tp* with its bytes in the model."""
    if _is_model(tp) and builtins.isinstance(value, builtins.bytes):
        return ob_alloc(tp, value)
    return value


# The Python meaning of the primitives, per machine, for the report of
# model.py: which touch host bytes, bytearray or memoryview.
HOST_EDGES = ('buffer_items', 'buffer_export', 'from_host')

del sys

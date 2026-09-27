"""The builtin types the pyspec tools know, in one table.

A row describes a builtin type implemented in C without a spec: its C
type object and checks, its base, its immortal constants, how to get its
size, and the special methods it defines itself, in C.  It is written
out, not read from the builtins of the Python running Argument Clinic
(PYTHON_FOR_REGEN may be older than the Python being built: before 3.12
no type has __buffer__); test_clinic checks it against the Python being
built.

The special methods are audited facts about C code that has no spec:
each one listed runs no Python code.  Its value is the exact type of its
result, or None when not known.  For ``__iter__`` it is the exact type
of every item: iter(x) and iterating it run no Python code (``object``:
items of any type).  A type whose special method may run Python code
(it forwards to another object, like mappingproxy's __len__, reversed's
__length_hint__ or PickleBuffer's __buffer__) is not in the table, or
lists the method as PYTHON: nothing is claimed about it.

A spec class that declares the slots of its type (bytes) describes the
type itself; TypeFacts reads it instead of the table.
"""

import builtins
import types


# A special method that may run Python code.
PYTHON = 'PYTHON'


class Row:
    def __init__(self, type_object, check=None, check_exact=None,
                 base=object, slots=None, constants=None, size=None,
                 candidate=False):
        self.type_object = type_object      # '&PyLong_Type'
        self.check = check                  # 'PyLong_Check'
        self.check_exact = check_exact      # 'PyLong_CheckExact'
        self.base = base
        self.slots = slots or {}
        self.constants = constants or {}    # value -> Py_CONSTANT_* name
        self.size = size                    # 'PyList_GET_SIZE': len()
        # Tried as the exact type of the argument of a one-argument call
        # (the per-type entries of the tier-2 call table, call_table.py).
        self.candidate = candidate


def _row(name, base=object, slots=None, constants=None, size=None,
         candidate=False, check=True, exact=True):
    c = {'int': 'Long', 'str': 'Unicode', 'bytearray': 'ByteArray',
         'memoryview': 'MemoryView', 'frozenset': 'FrozenSet'}.get(
             name, name.capitalize())
    return Row(f'&Py{c}_Type', f'Py{c}_Check' if check else None,
               f'Py{c}_CheckExact' if exact else None, base, slots,
               constants, size, candidate)


TABLE = {
    # The candidates first, in the order of the call table.
    bytes: _row('bytes', candidate=True,
                constants={b'': 'Py_CONSTANT_EMPTY_BYTES'},
                slots={'__buffer__': memoryview, '__bytes__': bytes,
                       '__iter__': int, '__len__': int}),
    bytearray: _row('bytearray', candidate=True,
                    slots={'__buffer__': memoryview, '__iter__': int,
                           '__len__': int, '__release_buffer__': None}),
    memoryview: _row('memoryview', candidate=True, exact=False,
                     slots={'__buffer__': memoryview, '__iter__': object,
                            '__len__': int, '__release_buffer__': None}),
    list: _row('list', candidate=True, size='PyList_GET_SIZE',
               slots={'__iter__': object, '__len__': int}),
    tuple: _row('tuple', candidate=True, size='PyTuple_GET_SIZE',
                constants={(): 'Py_CONSTANT_EMPTY_TUPLE'},
                slots={'__iter__': object, '__len__': int}),
    int: _row('int', candidate=True, slots={'__index__': int},
              constants={0: 'Py_CONSTANT_ZERO', 1: 'Py_CONSTANT_ONE'}),
    str: _row('str', candidate=True, constants={'': 'Py_CONSTANT_EMPTY_STR'},
              slots={'__iter__': str, '__len__': int}),
    range: _row('range', candidate=True, exact=False,
                slots={'__iter__': int, '__len__': int}),
    object: Row('&PyBaseObject_Type', base=None),
    # bool has no subclasses: PyBool_Check is exact.
    bool: Row('&PyBool_Type', 'PyBool_Check', 'PyBool_Check', base=int,
              constants={False: 'Py_CONSTANT_FALSE',
                         True: 'Py_CONSTANT_TRUE'}),
    float: _row('float'),
    complex: _row('complex'),
    dict: _row('dict', slots={'__iter__': object, '__len__': int}),
    set: _row('set', slots={'__iter__': object, '__len__': int}),
    frozenset: _row('frozenset', slots={'__iter__': object, '__len__': int}),
    types.GeneratorType: Row('&PyGen_Type',
                             slots={'__iter__': PYTHON, '__next__': PYTHON}),
    type(iter([])): Row('&PyListIter_Type',
                        slots={'__iter__': object, '__next__': object,
                               '__length_hint__': int}),
    types.NoneType: Row('&_PyNone_Type',
                        constants={None: 'Py_CONSTANT_NONE'}),
}

# The special methods TypeFacts answers hasattr(type(x), name) for: every
# row lists those its type defines.
SPECIALS = ('__buffer__', '__bytes__', '__index__', '__iter__', '__len__',
            '__length_hint__', '__next__', '__release_buffer__')

CANDIDATES = [tp for tp, row in TABLE.items() if row.candidate]


def by_name(name):
    """The builtin type called *name* that the table knows, or None."""
    tp = getattr(builtins, name, None)
    return tp if tp in TABLE else None


def constant(value):
    """The Py_CONSTANT_* name of an immortal constant, or None."""
    row = TABLE.get(type(value))
    return None if row is None else row.constants.get(value)


class TypeFacts:
    """What the tools know about builtin types: from the spec for its
    complete classes, else from TABLE; nothing about other types.
    Never from the Python running Argument Clinic."""

    def __init__(self, spec):
        self.spec = spec

    def spec_class(self, tp):
        """The complete spec class of builtin tp, or None.  A class that
        declares a slot (a dunder of slotdefs[]) declares them all:
        test_clinic checks it against the slot wrappers of the type."""
        node = self.spec.classes.get(tp.__name__)
        if node is None or getattr(builtins, tp.__name__, None) is not tp:
            return None
        return node if self.spec.declares_slots(tp.__name__) else None

    def mro(self, tp):
        """The MRO of tp, or None when tp is not known."""
        out = []
        while tp is not None:
            if self.spec_class(tp) is not None:
                out.append(tp)
                tp = object
            elif tp in TABLE:
                out.append(tp)
                tp = TABLE[tp].base
            else:
                return None
        return out

    def defines(self, tp, name):
        """Whether tp itself defines special method *name* (in SPECIALS)."""
        if self.spec_class(tp) is not None:
            full = f'{tp.__name__}.{name}'
            return full in self.spec.functions or full in self.spec.shared
        return name in TABLE[tp].slots

    def owner(self, tp, name):
        """The class of the MRO of tp that defines *name*: False when none
        does, None when not known."""
        mro = self.mro(tp)
        if mro is None or name not in SPECIALS:
            return None
        for klass in mro:
            if self.defines(klass, name):
                return klass
        return False

    def has(self, tp, name):
        """hasattr(tp, name) for a special method; None when not known."""
        owner = self.owner(tp, name)
        return None if owner is None else owner is not False

    def special(self, tp, name):
        """The special method *name* of exact type tp: (the spec function
        that implements it, None) for a spec class, (None, its TABLE
        value) for a table type, (None, False) when tp does not have it,
        and None when not known."""
        owner = self.owner(tp, name)
        if owner is None:
            return None
        if owner is False:
            return None, False
        if self.spec_class(owner) is not None:
            return f'{owner.__name__}.{name}', None
        return None, TABLE[owner].slots[name]

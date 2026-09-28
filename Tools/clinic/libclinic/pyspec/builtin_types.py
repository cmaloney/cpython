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

A spec class that declares the slots of its type (bytes, in any spec of
the tree) describes the type itself; TypeFacts reads it instead of the
table.  The row of such a type lists only what no spec gives: its C
names, constants, and the audited facts of the special methods its spec
writes in C without a Python reference (``...``); test_clinic checks
that a row repeats nothing a spec derives.
"""

from __future__ import annotations

import ast
import builtins
import types
from collections.abc import Callable, Mapping
from typing import Any, Final, Literal, Protocol

# A special method that may run Python code.
PYTHON: Final = 'PYTHON'

# What a row says of a special method: the exact type of its result (for
# __iter__, of the items), None when not known, or PYTHON.
SlotValue = type | str | None

# TypeFacts.special(): (the spec function, None), or (None, a SlotValue,
# or False when the type does not have the method).
Special = tuple[str, None] | tuple[None, SlotValue | Literal[False]]


class Row:
    def __init__(self, type_object: str, check: str | None = None,
                 check_exact: str | None = None, base: type | None = object,
                 slots: dict[str, SlotValue] | None = None,
                 constants: dict[object, str] | None = None,
                 size: str | None = None, candidate: bool = False) -> None:
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


def _row(name: str, base: type = object,
         slots: dict[str, SlotValue] | None = None,
         constants: dict[object, str] | None = None, size: str | None = None,
         candidate: bool = False, check: bool = True,
         exact: bool = True) -> Row:
    c = {'int': 'Long', 'str': 'Unicode', 'bytearray': 'ByteArray',
         'memoryview': 'MemoryView', 'frozenset': 'FrozenSet'}.get(
             name, name.capitalize())
    return Row(f'&Py{c}_Type', f'Py{c}_Check' if check else None,
               f'Py{c}_CheckExact' if exact else None, base, slots,
               constants, size, candidate)


TABLE: dict[type, Row] = {
    # The candidates first, in the order of the call table.
    # bytes and bytearray have a spec (Objects/pyspec/): only the special
    # methods it writes as ... are listed.
    bytes: _row('bytes', candidate=True,
                constants={b'': 'Py_CONSTANT_EMPTY_BYTES'},
                slots={'__iter__': int}),
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


def by_name(name: str) -> type | None:
    """The builtin type called *name* that the table knows, or None."""
    tp = getattr(builtins, name, None)
    return tp if tp in TABLE else None


def constant(value: object) -> str | None:
    """The Py_CONSTANT_* name of an immortal constant, or None."""
    row = TABLE.get(type(value))
    return None if row is None else row.constants.get(value)


class Spec(Protocol):
    """What TypeFacts reads of a spec (frontend.Spec)."""

    @property
    def classes(self) -> Mapping[str, ast.ClassDef]: ...

    @property
    def functions(self) -> Mapping[str, ast.FunctionDef]: ...

    @property
    def shared(self) -> Mapping[str, object]: ...

    def declares_slots(self, cls_name: str) -> bool: ...

    def declaration(self, name: str) -> tuple[Spec, str]: ...


class Facts(Protocol):
    """What TypeFacts reads of the facts of a method (facts.Facts)."""

    @property
    def runs_python(self) -> bool: ...

    @property
    def result_type(self) -> type | None: ...


class TypeFacts:
    """What the tools know about builtin types: from the spec for its
    complete classes (of this spec, else of another spec of the tree),
    else from TABLE; nothing about other types.  Never from the Python
    running Argument Clinic."""

    def __init__(self, spec: Spec, classes: Mapping[type, Spec],
                 derive: Callable[[Any, str, type], Facts | None]) -> None:
        """*spec*: the spec whose classes are this spec's; *classes*:
        {builtin type: spec} of the complete classes of the specs of the
        tree (frontend.spec_classes()); *derive(spec, name, tp)*: the
        facts of special method *name* ("T.meth" of *spec*) for self of
        exact type tp, from its body or Python reference, or None for a
        method written in C only (facts.Analyzer.method_facts(), which
        the context of the passes, context.py, gives)."""
        self.spec = spec
        self.classes = classes
        self.derive = derive

    def class_spec(self, tp: type) -> Spec | None:
        """The spec with the complete class of builtin tp: this spec, or
        another spec of the tree; None when there is none."""
        if getattr(builtins, tp.__name__, None) is not tp:
            return None
        if (tp.__name__ in self.spec.classes
                and self.spec.declares_slots(tp.__name__)):
            return self.spec
        return self.classes.get(tp)

    def spec_class(self, tp: type) -> ast.ClassDef | None:
        """The complete spec class of builtin tp, or None.  A class that
        declares a slot (a dunder of slotdefs[]) declares them all:
        test_clinic checks it against the slot wrappers of the type."""
        spec = self.class_spec(tp)
        return None if spec is None else spec.classes[tp.__name__]

    def derived(self, spec: Spec, tp: type, name: str) -> SlotValue:
        """The TABLE value of special method *name* of builtin tp, whose
        complete class is in *spec*, another spec: derived from its body
        or Python reference; for a method written in C only (a stub, and
        __iter__, whose value is the type of the items), the audited value
        of the row of tp, else PYTHON."""
        other, full = spec.declaration(f'{tp.__name__}.{name}')
        found = None if name == '__iter__' else self.derive(other, full, tp)
        if found is not None:
            return PYTHON if found.runs_python else found.result_type
        row = TABLE.get(tp)
        if row is not None and name in row.slots:
            return row.slots[name]
        return PYTHON

    def mro(self, tp: type | None) -> list[type] | None:
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

    def defines(self, tp: type, name: str) -> bool:
        """Whether tp itself defines special method *name* (in SPECIALS)."""
        spec = self.class_spec(tp)
        if spec is not None:
            full = f'{tp.__name__}.{name}'
            return full in spec.functions or full in spec.shared
        return name in TABLE[tp].slots

    def owner(self, tp: type | None,
              name: str) -> type | Literal[False] | None:
        """The class of the MRO of tp that defines *name*: False when none
        does, None when not known."""
        mro = self.mro(tp)
        if mro is None or name not in SPECIALS:
            return None
        for klass in mro:
            if self.defines(klass, name):
                return klass
        return False

    def has(self, tp: type | None, name: str) -> bool | None:
        """hasattr(tp, name) for a special method; None when not known."""
        owner = self.owner(tp, name)
        return None if owner is None else owner is not False

    def special(self, tp: type | None, name: str) -> Special | None:
        """The special method *name* of exact type tp: (the spec function
        that implements it, None) for a class of this spec, (None, its
        TABLE value) for a class of another spec (derived()) or a table
        type, (None, False) when tp does not have it, and None when not
        known."""
        owner = self.owner(tp, name)
        if owner is None:
            return None
        if owner is False:
            return None, False
        spec = self.class_spec(owner)
        if spec is self.spec:
            return f'{owner.__name__}.{name}', None
        if spec is not None:
            return None, self.derived(spec, owner, name)
        return None, TABLE[owner].slots[name]

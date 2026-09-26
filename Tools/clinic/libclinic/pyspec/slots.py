"""The type slots behind the special methods: ``slotdefs[]`` of
Objects/typeobject.c, read by Argument Clinic.

``slotdefs[]`` is the table the interpreter itself uses to connect a
dunder to its C slot: add_operators() creates the wrapper descriptors of a
static type from it, and a class defining the dunder in Python gets the
slot function listed there.  It is therefore the machine-readable source of
truth for "dunder <-> slot" (Doc/c-api/typeobj.rst documents the same slots
in prose and tables; test_pyspec_catalog tracks where the two disagree).

Each entry gives the dunder, the slot (``tp_repr``, ``nb_add`` in
``tp_as_number``, ...), and the docstring of the wrapper descriptor, whose
text signature (``__getitem__($self, key, /)``) is the Python signature of
the slot.  Entries without a wrapper (the legacy ``tp_getattr`` and
``tp_setattr``, ``__getattr__`` and ``__new__``) never create a descriptor
and are not slots a spec can fill.
"""

from __future__ import annotations

import dataclasses as dc
import functools
import os
import re

# The PyTypeObject member holding the sub-table of a slot kind, and the C
# type of that sub-table.
SUBTABLES = {
    'as_async': 'PyAsyncMethods',
    'as_number': 'PyNumberMethods',
    'as_mapping': 'PyMappingMethods',
    'as_sequence': 'PySequenceMethods',
    'as_buffer': 'PyBufferProcs',
}

_MACROS = {
    # macro: (sub-table or None, index of the docstring argument)
    'TPSLOT': (None, 4),
    'FLSLOT': (None, 4),
    'BUFSLOT': ('as_buffer', 4),
    'AMSLOT': ('as_async', 4),
    'SQSLOT': ('as_sequence', 4),
    'MPSLOT': ('as_mapping', 4),
    'NBSLOT': ('as_number', 4),
    'UNSLOT': ('as_number', 4),
    'IBSLOT': ('as_number', 4),
    'BINSLOT': ('as_number', 3),
    'RBINSLOT': ('as_number', 3),
    'BINSLOTNOTINFIX': ('as_number', 3),
    'RBINSLOTNOTINFIX': ('as_number', 3),
}


@dc.dataclass(frozen=True)
class SlotDef:
    name: str           # "__getitem__"
    slot: str           # "mp_subscript"
    subtable: str | None    # "as_mapping", or None for a PyTypeObject slot
    doc: str            # the wrapper docstring: "__getitem__($self, key, /)\n--\n\n..."

    @property
    def signature(self) -> str:
        """The text signature of the wrapper: ``($self, key, /)``."""
        return self.doc.partition('\n--\n\n')[0][len(self.name):]

    @property
    def member(self) -> str:
        """The PyTypeObject member: ``tp_repr`` or ``tp_as_mapping``."""
        return f'tp_{self.subtable}' if self.subtable else self.slot


def typeobject_path() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, '..', '..', '..', '..', 'Objects',
                        'typeobject.c')


def _c_strings(text: str) -> str:
    """The value of adjacent C string literals."""
    value = []
    for literal in re.findall(r'"((?:[^"\\]|\\.)*)"', text):
        value.append(literal.encode('latin-1').decode('unicode_escape'))
    return ''.join(value)


def _split_args(text: str) -> list[str]:
    """Split the arguments of a macro call at top-level commas."""
    args, depth, current, in_string = [], 0, [], False
    i = 0
    while i < len(text):
        c = text[i]
        if in_string:
            current.append(c)
            if c == '\\':
                current.append(text[i + 1])
                i += 1
            elif c == '"':
                in_string = False
        elif c == '"':
            in_string = True
            current.append(c)
        elif c == '(':
            depth += 1
            current.append(c)
        elif c == ')':
            depth -= 1
            current.append(c)
        elif c == ',' and depth == 0:
            args.append(''.join(current).strip())
            current = []
        else:
            current.append(c)
        i += 1
    args.append(''.join(current).strip())
    return args


def _doc(macro: str, name: str, doc: str) -> str:
    """The docstring an entry macro builds from its DOC argument."""
    match macro:
        case 'UNSLOT':
            return f'{name}($self, /)\n--\n\n{doc}'
        case 'IBSLOT' | 'BINSLOT':
            return f'{name}($self, value, /)\n--\n\nReturn self{doc}value.'
        case 'RBINSLOT':
            return f'{name}($self, value, /)\n--\n\nReturn value{doc}self.'
        case 'BINSLOTNOTINFIX' | 'RBINSLOTNOTINFIX':
            return f'{name}($self, value, /)\n--\n\n{doc}'
    return doc


def parse(source: str) -> list[SlotDef]:
    """The entries of ``slotdefs[]`` that have a wrapper, in order."""
    start = source.index('static pytype_slotdef slotdefs[] = {')
    end = source.index('\n};', start)
    table = source[start:end]
    # Drop comments.
    table = re.sub(r'/\*.*?\*/', '', table, flags=re.DOTALL)
    entries = []
    pos = table.index('{') + 1
    call = re.compile(r'\b([A-Z]+SLOT[A-Z]*)\(')
    while (m := call.search(table, pos)):
        macro = m.group(1)
        depth, i = 1, m.end()
        in_string = False
        while depth:
            c = table[i]
            if in_string:
                if c == '\\':
                    i += 1
                elif c == '"':
                    in_string = False
            elif c == '"':
                in_string = True
            elif c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
            i += 1
        args = _split_args(table[m.end():i - 1])
        pos = i
        subtable, doc_index = _MACROS[macro]
        name, slot = args[0], args[1]
        if doc_index == 4 and args[3] == 'NULL':
            continue        # no wrapper: never a descriptor
        doc = _doc(macro, name, _c_strings(args[doc_index]))
        entries.append(SlotDef(name, slot, subtable, doc))
    return entries


@functools.cache
def slotdefs(path: str | None = None) -> tuple[SlotDef, ...]:
    with open(path or typeobject_path(), encoding='utf-8') as f:
        return tuple(parse(f.read()))


def candidates(name: str) -> list[SlotDef]:
    """The slots a dunder can fill, in slotdefs order (the first one
    filled is the one Python sees)."""
    return [s for s in slotdefs() if s.name == name]


def group(slot: str) -> list[str]:
    """The dunders a slot creates wrappers for (``__lt__`` ... ``__ge__``
    for ``tp_richcompare``, ``__mul__`` and ``__rmul__`` for
    ``sq_repeat``)."""
    return [s.name for s in slotdefs() if s.slot == slot]


def is_slot(name: str) -> bool:
    """A dunder that a spec declares as a slot.  ``__new__`` and
    ``__init__`` are clinic functions: clinic generates their slot
    function."""
    return name not in ('__new__', '__init__') and bool(candidates(name))

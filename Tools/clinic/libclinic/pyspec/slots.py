"""The type slots behind the special methods: ``slotdefs[]`` of
Objects/typeobject.c, read by Argument Clinic.

``slotdefs[]`` is the interpreter's own table from a dunder to its C slot
(add_operators() makes the wrapper descriptors of a static type from
it), so it is the source of truth for "dunder <-> slot".  Each entry
gives the dunder, the slot, and the docstring of the wrapper, whose text
signature is the Python signature of the slot.  Entries without a
wrapper (``tp_getattr``, ``__new__``...) are not slots a spec can fill.
"""

from __future__ import annotations

import dataclasses as dc
import functools
import os
import re

from . import specfiles

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


def _c_strings(text: str) -> str:
    """The value of adjacent C string literals."""
    value = []
    for literal in re.findall(r'"((?:[^"\\]|\\.)*)"', text):
        value.append(literal.encode('latin-1').decode('unicode_escape'))
    return ''.join(value)


def _macro_args(text: str, i: int) -> tuple[list[str], int]:
    """The arguments of the macro call whose ``(`` ends at *i*, split at
    top-level commas, and the index after its ``)``."""
    args, current, depth = [], [], 1
    while True:
        c = text[i]
        if c == '"':            # a string literal, whole
            end = i + 1
            while text[end] != '"':
                end += 2 if text[end] == '\\' else 1
            current.append(text[i:end + 1])
            i = end + 1
            continue
        i += 1
        depth += {'(': 1, ')': -1}.get(c, 0)
        if depth == 0 or (c == ',' and depth == 1):
            args.append(''.join(current).strip())
            current = []
            if depth == 0:
                return args, i
        else:
            current.append(c)


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
        args, pos = _macro_args(table, m.end())
        subtable, doc_index = _MACROS[m.group(1)]
        name, slot = args[0], args[1]
        if doc_index == 4 and args[3] == 'NULL':
            continue        # no wrapper: never a descriptor
        doc = _doc(m.group(1), name, _c_strings(args[doc_index]))
        entries.append(SlotDef(name, slot, subtable, doc))
    return entries


@functools.cache
def slotdefs(path: str | None = None) -> tuple[SlotDef, ...]:
    path = path or os.path.join(specfiles.srcdir(), 'Objects',
                                'typeobject.c')
    with open(path, encoding='utf-8') as f:
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

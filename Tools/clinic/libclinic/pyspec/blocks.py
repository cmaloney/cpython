"""The one-line blocks of the C file, and those clinic inserts.

Each clinic function of a spec class that the C file declares (``class
T`` directive) has a one-line block, ``T.meth`` (or ``@getter`` /
``T.attr``), above its impl.  Clinic writes a missing one itself
(missing()), in the order of the class body: after the block of the
function before it that has one (before the next block, or the include
of clinic/<stem>_pyspec.c.h, or at the end of the file), else before the
block of the function after it, else before that include; always after
the ``class`` directive, and under its ``#if`` only (the first such place
after the block before, the last one before the block after).  A function
written in C gets a placeholder impl (placeholder()); the method table,
tp_new and tp_getset written in C need an entry (entry_note()).  A
function with no such place is left to Clinic.check_spec_blocks().
"""

from __future__ import annotations

import ast
import dataclasses as dc
import os
import re
import shlex
from collections.abc import Collection

from libclinic import cpp
from libclinic.function import ACCESSORS, METHOD_INIT, METHOD_NEW, Function
from . import frontend


@dc.dataclass
class Missing:
    """A block clinic inserts: the clinic function *name* ("T.meth"),
    or its *accessor* ('getter' or 'setter')."""
    name: str
    accessor: str = ''
    # Whether the C must name the function (entry_note()).
    entry: bool = False

    @property
    def input(self) -> str:
        decorator = f'@{self.accessor}\n' if self.accessor else ''
        return f'{decorator}{self.name}\n'


def block_functions(spec: frontend.Spec, cls_name: str
                    ) -> list[tuple[str, str, ast.FunctionDef]]:
    """(name, accessor, def) of the functions of class *cls_name* that
    have a block in the C file, in the order of the class body: its
    clinic methods (accessor '') and accessors ('getter', 'setter')."""
    methods = set(spec.methods(cls_name))
    found = []
    for stmt in spec.classes[cls_name].body:
        if isinstance(stmt, ast.FunctionDef):
            accessor = frontend.accessor_kind(stmt)
            if accessor or stmt.name in methods:
                found.append((stmt.name, accessor, stmt))
    return found


def _scan_block(lines: list[str], directives: Collection[str]
                ) -> tuple[list[str], tuple[str, str] | None]:
    """(the classes declared, (function, accessor) or None) of the
    clinic block of *lines*: its lines up to the function line."""
    classes = []
    accessor = ''
    for line in lines:
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        fields = shlex.split(line)
        if fields[0] == 'class' and len(fields) > 1:
            classes.append(fields[1])
        elif fields[0] in ('@getter', '@setter'):
            accessor = fields[0][1:]
        elif fields[0] not in directives:
            name = line.partition('->')[0].partition('=')[0]
            return classes, (name.partition(' as ')[0].strip(), accessor)
    return classes, None


def missing(spec: frontend.Spec, filename: str, text: str,
            directives: Collection[str]) -> dict[int, list[Missing]]:
    """{line of *text*: the blocks clinic writes before it}.
    *directives*: those of clinic (DSLParser.directives)."""
    from libclinic.block_parser import BlockParser
    from libclinic.clanguage import CLanguage

    # conditions[n]: the #if condition after line n.
    monitor = cpp.Monitor(filename)
    conditions = ['']
    for line in text.splitlines():
        monitor.writeline(line)
        conditions.append(monitor.condition())
    include = re.compile(r'\s*#\s*include\s+"clinic/%s"' % re.escape(
        os.path.basename(frontend.output_path(filename))))

    # Where a block can go: (line, the last line clinic has read when it
    # writes there); the #if at both is the one where the block goes.
    points: list[tuple[int, int]] = []
    include_point: tuple[int, int] | None = None
    classes: dict[str, int] = {}
    block_lines: dict[tuple[str, str], int] = {}
    scan = BlockParser(text, CLanguage(filename), verify=False)
    for block in scan:
        if block.dsl_name is None:
            first = scan.block_start_line_number + 1
            for lineno, line in enumerate(block.input.splitlines(), first):
                if include_point is None and include.match(line):
                    include_point = (lineno, scan.line_number)
                    points.append(include_point)
        elif block.dsl_name == 'clinic':
            lineno = scan.block_start_line_number - 1
            points.append((lineno, lineno))
            declared, function = _scan_block(block.input.split('\n'),
                                             directives)
            for path in declared:
                classes.setdefault(path, lineno)
            if function is not None:
                block_lines.setdefault(function, lineno)
    # (The end of the file: after the last block.)
    points.append((len(conditions), len(conditions) - 1))
    points.sort()

    inserts: dict[int, list[Missing]] = {}
    for path, class_line in classes.items():
        cls_name = path.rpartition('.')[2]
        if cls_name not in spec.classes:
            continue
        condition = conditions[class_line]
        # The method table of an @ac.generate class is generated (unless
        # methods=False); tp_getset, tp_new and tp_init are C.
        tables = spec.class_output(cls_name)
        in_table = tables is not None and tables.methods
        wanted = [(f'{path}.{meth}', accessor)
                  for meth, accessor, _ in block_functions(spec, cls_name)]
        present = [key in block_lines for key in wanted]
        for i, (name, accessor) in enumerate(wanted):
            if present[i]:
                continue
            # The first place after the block of the function before it,
            # else the last one before the block of the function after.
            before = [block_lines[k] for k, p in zip(wanted[:i], present)
                      if p]
            after = [block_lines[k]
                     for k, p in zip(wanted[i + 1:], present[i + 1:]) if p]
            end = len(conditions)
            if after and not (before and before[-1] > after[0]):
                end = after[0]
            candidates: list[tuple[int, int] | None]
            if before:
                candidates = [p for p in points if before[-1] < p[0] <= end]
            elif after:
                candidates = [p for p in points if p[0] <= end][::-1]
            else:
                candidates = []
            candidates.append(include_point)
            # After the class is declared, under its #if.
            point = next((p for p in candidates if p is not None
                          and p[0] > class_line
                          and conditions[p[0] - 1] == conditions[p[1]]
                          == condition), None)
            if point is None:
                continue
            if accessor:
                # Only the first accessor of a new attribute.
                entry = not any(k[0] == name and (present[j] or j < i)
                                for j, k in enumerate(wanted) if k[1])
            else:
                meth = name.rpartition('.')[2]
                entry = not in_table or meth in ('__new__', '__init__')
            inserts.setdefault(point[0], []).append(
                Missing(name, accessor, entry))
    return inserts


def placeholder(func: Function) -> str:
    """The impl clinic writes after the inserted block of *func*: none
    for a spec body, else one that raises NotImplementedError."""
    if func.pyspec:
        return ''
    rtype = func.return_converter.type
    if rtype.endswith('*'):
        error = 'NULL'
    elif rtype == 'int':
        error = '-1'
    else:
        error = f'({rtype})-1'
    basename = (func.accessor_basename if func.kind in ACCESSORS
                else func.c_basename)
    return ('{\n'
            f'    /* TODO: write {basename}_impl() */\n'
            '    PyErr_SetString(PyExc_NotImplementedError,\n'
            f'                    "{func.full_name}");\n'
            f'    return {error};\n'
            '}\n')


def entry_note(func: Function) -> str:
    """What the C must add to name inserted function *func*."""
    assert func.cls is not None
    if func.property is not None:
        what = (f"add {func.property.getset_name}_GETSETDEF to the "
                f"tp_getset of {func.cls.name}")
    elif func.kind is METHOD_NEW:
        what = f"set the tp_new of {func.cls.name} to {func.c_basename}"
    elif func.kind is METHOD_INIT:
        what = f"set the tp_init of {func.cls.name} to {func.c_basename}"
    else:
        what = (f"add {func.c_basename.upper()}_METHODDEF to the method "
                f"table of {func.cls.name}")
    return f"clinic inserted the block of {func.full_name}; {what}"

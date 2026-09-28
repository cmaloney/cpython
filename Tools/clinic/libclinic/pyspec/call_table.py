"""Generate the call table of a spec'd type for the tier-2 optimizer.

For a clinic __new__ implemented by a spec (``def __new__(cls, ...)`` in
``class bytes:``, the clinic function bytes.__new__, C basename
bytes_new), emit.py generates NAME_nargsN(): the spec partially evaluated
for exactly that type and N positional arguments.  generate() here adds
to the same generated file, after them (emit.generate() calls it back;
Argument Clinic writes the file; there is no separate command):

* NAME_nargs1_T(): NAME_nargs1 partially evaluated for an argument of
  exact type T, for the candidates of builtin_types.py.  A variant is kept
  only when its residual code is much smaller than the generic one
  (KEEP_RATIO); variants with identical code share one C function, and a
  variant that would only call a shared specialization
  (marks.Specialization, e.g. bytes_from_iterator_list()) is that
  function.

* ``const _PySpecCallTable _PySpec_<class>_calls`` for each class of
  table_classes() (declared in the registry of
  Include/internal/pycore_pyspec.h, see below): per arity with object-only arguments
  and per argument type, the C function and facts about its result, all
  derived from the residual code; and the same facts for the other
  methods the spec implements (bytes.__bytes__, bytes.fromhex), per exact
  type of their first argument, keyed by their ml_meth.  The generic
  entry of a class method holds for any class (a subclass shares the
  ml_meth), the others only for the type itself
  (_PySpec_FindMethod()):

    - result_const: the residual is just ``return <constant>``: no side
      effects, and the constant is immortal;
    - result_alias: every ``return`` returns argument k itself (a new
      reference to it), e.g. ``return self`` under ``type(self) is
      bytes``;
    - result_type: every ``return`` gives an object of that exact type:
      a constant, a call whose own returns all do (``exact(T)`` in the
      Python reference of a C function), or a name whose exact type the
      path proves (``type(x) is K`` or the argument's known type).
      ``isinstance`` checks allow subclasses and prove nothing;
    - _PySpec_ALWAYS_RAISES: no ``return`` is left;
    - _PySpec_MAY_RUN_PYTHON: some call on a path may run Python code.

* ``const _PySpecSlot <class>_spec_slots[]``: the facts of the slots of
  the class that have a Python reference (``@native`` dunders:
  bytes.__getitem__, bytes_iterator.__next__), for self of exactly the
  class: per slot, a generic entry, and an entry per exact type of the
  argument after self whose facts differ from it (unless it always
  raises).  They are the facts of the special method as Python calls
  it, keyed by its C slot: the first slot of the dunder in slotdefs[]
  that the class fills, the one its wrapper calls
  (``_PySpec_SLOT(as_mapping.mp_subscript)``, see slot_member()).  A
  specialized uop that does what a slot does
  (_BINARY_OP_SUBSCR_BYTES_INT for bytes.__getitem__) takes its result
  facts from them (_PySpec_FindSlot()).

The facts are those of facts.py, derived from the residual code and from
the Python references of the C functions it calls.  They hold only for
the exact argument types of their entry: a subclass instance uses the
generic entry.

The interpreter finds the table of a type in the registry: the generated
part of Include/internal/pycore_pyspec.h, which declares every table and
lists them in ``_PySpec_REGISTRY``.  Argument Clinic rewrites it while
processing the C file of any spec of a core C file (registry_outputs()),
from the syntax of all those specs (table_classes()): a new spec'd class
is picked up without editing C.
"""

from __future__ import annotations

import ast
import os
from collections.abc import Sequence

from libclinic.errors import SpecError, SpecErrorKind
from . import builtin_types, emit, frontend, marks, slots, specfiles
from .facts import Facts
from .frontend import Spec, SpecFunction, SpecParameter
from .known import NOTNULL, Env, Value

# An entry of a call table: (arity, argument type, C function, facts,
# constant result).
Entry = tuple[int, type | None, str, Facts, str | None]

# Keep a type-specialized variant when its residual has at most this
# fraction of the AST nodes of the generic residual.
KEEP_RATIO = 0.5


def node_count(stmts: list[ast.stmt]) -> int:
    return sum(1 for stmt in stmts for _ in ast.walk(stmt))


def residual_key(stmts: list[ast.stmt]) -> str:
    """Residuals with equal keys lower to the same C: the AST, and the
    marks of the partial evaluator (e.g. whether a loop iterates a list
    or a tuple by index)."""
    found = [(type(node).__name__, marks.of(node))
             for stmt in stmts for node in ast.walk(stmt) if marks.of(node)]
    return ast.dump(ast.Module(stmts, [])) + repr(found)


def _const_name(residual: list[ast.stmt]) -> str | None:
    """Py_CONSTANT_* name if the residual is just ``return <constant>``."""
    match residual:
        case [ast.Return(value=ast.Constant() as value)]:
            return builtin_types.constant(value.value)
    return None


def _flags(facts: Facts) -> str:
    flags = []
    if facts.runs_python:
        flags.append('_PySpec_MAY_RUN_PYTHON')
    if facts.always_raises:
        flags.append('_PySpec_ALWAYS_RAISES')
    return ' | '.join(flags) or '0'


def _describe(facts: Facts, const: str | None,
              arg_names: Sequence[str] = ()) -> str:
    parts = []
    if const is not None:
        parts.append(f'always {const}, no side effects')
    else:
        if facts.alias is not None:
            name = (arg_names[facts.alias] if facts.alias < len(arg_names)
                    else '')
            parts.append(f'result is argument {facts.alias}'
                         + (f' ({name})' if name else ''))
        if facts.result_type is not None:
            parts.append(f'result is exactly {facts.result_type.__name__}')
        elif not facts.always_raises:
            parts.append('result type not known exactly')
    if facts.always_raises:
        parts.append('always raises')
    parts.append('may run Python code' if facts.runs_python
                 else 'runs no Python code')
    return '; '.join(parts)


def _type_object(tp: type | None) -> str:
    return builtin_types.TABLE[tp].type_object if tp is not None else 'NULL'


def _entry(comment: str, nargs: int, facts: Facts, const: str | None,
           arg_type: type | None, func: tuple[str, str] | None,
           arg_names: Sequence[str] = ()) -> list[str]:
    """The lines of a _PySpecCall; *func* is (union member, C name), or
    None for none."""
    result_type = _type_object(facts.result_type)
    alias = facts.alias if const is None and facts.alias is not None else -1
    return [
        f'    /* {comment}: {_describe(facts, const, arg_names)} */',
        '    {',
        f'        .nargs = {nargs},',
        f'        .flags = {_flags(facts)},',
        f'        .result_const = {const if const else -1},',
        f'        .result_alias = {alias},',
        f'        .arg_type = {_type_object(arg_type)},',
        f'        .result_type = {result_type},',
        *([f'        .func.{func[0]} = {func[1]},'] if func else []),
        '    },',
    ]


def table_classes(spec: Spec) -> list[str]:
    """The classes of *spec* that get a call table, in the order of the
    spec: those with a __new__ or a method implemented by the spec, or a
    slot with a Python reference (a @native dunder).

    Only the syntax of the spec decides, so that the registry lists
    exactly the tables generate() defines without generating them."""
    if not spec.implemented_functions():
        return []           # Argument Clinic generates no call table
    out = []
    for cls_name in spec.classes:
        for meth in spec.entries(cls_name):
            name = f'{cls_name}.{meth}'
            node = spec.functions.get(name)
            if spec.implemented(name) or (
                    node is not None and slots.is_slot(meth)
                    and frontend.is_native(node)):
                out.append(cls_name)
                break
    return out


def table_name(cls_name: str) -> str:
    """The C name of the call table of spec class *cls_name*."""
    return f'_PySpec_{cls_name}_calls'


def generate(generator: emit.Generator,
             descriptions: list[SpecFunction]) -> list[str]:
    """C lines: the type-specialized variants and the call table of each
    class of table_classes(), from *descriptions* (frontend.SpecFunction:
    the implemented functions compiled unconditionally).

    *generator* is the emit.Generator of the spec."""
    out = []
    news: dict[str, SpecFunction] = {}      # class name -> __new__
    methods: dict[str, list[SpecFunction]] = {}
    for description in descriptions:
        cls_name, _, meth = description.name.rpartition('.')
        if not cls_name:
            continue
        if meth == '__new__':
            news[cls_name] = description
        else:
            methods.setdefault(cls_name, []).append(description)
    for cls_name in table_classes(generator.spec):
        type_object = _class_type_object(generator, cls_name)
        new = news.get(cls_name)
        calls = method_table = None
        if new is not None:
            lines, calls = generate_calls(generator, new)
            out += lines
        if methods.get(cls_name):
            lines, method_table = generate_methods(generator, cls_name,
                                                   methods[cls_name])
            out += lines
        lines, slot_table = generate_slots(generator, cls_name, type_object)
        out += lines
        out += [
            f'const _PySpecCallTable {table_name(cls_name)} = {{',
            f'    .type = {type_object},',
        ]
        if calls:
            out += [f'    .ncalls = Py_ARRAY_LENGTH({calls}),',
                    f'    .calls = {calls},']
        if method_table:
            out += [f'    .nmethods = Py_ARRAY_LENGTH({method_table}),',
                    f'    .methods = {method_table},']
        if slot_table:
            out += [f'    .nslots = Py_ARRAY_LENGTH({slot_table}),',
                    f'    .slots = {slot_table},']
        out += ['};', '']
    return out


def _class_type_object(generator: emit.Generator, cls_name: str) -> str:
    """The C type object of spec class *cls_name*: a builtin type's, or
    the one its clinic class declaration in the C file names."""
    tp = builtin_types.by_name(cls_name)
    if tp is not None:
        return _type_object(tp)
    type_object = generator.type_objects.get(cls_name)
    if type_object is None:
        spec = generator.spec
        raise spec.error(spec.classes[cls_name],
                         f'class {cls_name} has a call table: declare it in '
                         f'the C file (class {cls_name} "T *" "&T_Type")',
                         SpecErrorKind.BINDING)
    return type_object


def generate_calls(generator: emit.Generator,
                   description: SpecFunction) -> tuple[list[str], str]:
    """The variants and the calls array of a clinic __new__."""
    analyzer = generator.context.analyzer()
    params = description.parameters[1:]
    # The spec function ("bytes.__new__") and the C basename of its
    # clinic function ("bytes_new").
    name = description.name
    basename = generator.c_basename(name)
    out = []
    entries: list[Entry] = []
    for env, _, given, missing in generator.arities(description):
        nargs = len(given)
        if any(p.ctype != emit.OBJECT for p in given):
            continue
        arg_names = [p.name for p in given]
        generic = generator.residual(name, env)
        generic_size = node_count(generic)
        if nargs == 1:
            functions: dict[str, str] = {}  # residual_key() -> C name
            for tp in builtin_types.CANDIDATES:
                typed_env = env | {given[0].name: tp}
                residual = generator.residual(name, typed_env)
                if node_count(residual) > KEEP_RATIO * generic_size:
                    continue
                key = residual_key(residual)
                found = analyzer.facts(residual, typed_env, arg_names)
                const = _const_name(residual)
                special = _just_calls(residual, given)
                if special is not None:
                    # The variant would only call it.
                    generator.use(special.name)
                    functions[key] = special.name
                elif key not in functions:
                    functions[key] = c_name = (
                        f'{basename}_nargs1_{tp.__name__}')
                    out += _variant(generator, description, c_name,
                                    residual, given, missing, tp, found,
                                    const)
                entries.append((nargs, tp, functions[key], found, const))
        found = analyzer.facts(generic, env, arg_names)
        entries.append((nargs, None, f'{basename}_nargs{nargs}', found,
                        _const_name(generic)))

    table = f'{basename}_spec_calls'
    out += [
        f'/* Call table of {description.new_type}() for the tier-2 '
        'optimizer, see',
        ' * Include/internal/pycore_pyspec.h.  Generated by '
        'Argument Clinic',
        ' * (Tools/clinic/libclinic/pyspec/call_table.py). */',
        f'static const _PySpecCall {table}[] = {{',
    ]
    for nargs, arg_type, function, found, const in entries:
        shown = '' if nargs == 0 else getattr(arg_type, '__name__', 'x')
        comment = f'{description.new_type}({shown})'
        out += _entry(comment, nargs, found, const, arg_type,
                      (f'f{nargs}', function),
                      [p.name for p in params[:nargs]])
    out += ['};', '']
    return out, table


def generate_methods(generator: emit.Generator, type_name: str,
                     descriptions: list[SpecFunction]
                     ) -> tuple[list[str], str]:
    """The facts of the methods and class methods of a type implemented by
    the spec: per method, a generic entry, and an entry per exact type of
    the first argument whose facts differ from it (for a class method,
    called on exactly the type).

    The arguments are those the C function sees besides the class: for a
    method, self and the others; for a class method, the others (the class
    is the type itself).  Only calls with all parameters, all objects, are
    described."""
    spec = generator.spec
    analyzer = generator.context.analyzer()
    # The type as the partial evaluator knows it; None for a class that
    # is not a builtin type (only its generic entries are derived).
    type_value = builtin_types.by_name(type_name)
    entries: list[tuple[str, int, type | None, Facts, list[str], str,
                        str]] = []
    for description in descriptions:
        name = description.name
        node = spec.functions[name]
        decorators = {d.id for d in node.decorator_list
                      if isinstance(d, ast.Name)}
        if 'staticmethod' in decorators:
            continue
        first, *params = description.parameters
        if any(p.optional or p.ctype != emit.OBJECT for p in params):
            continue
        env: Env = {p.name: NOTNULL for p in params}
        env[first.name] = NOTNULL
        if 'classmethod' in decorators:
            # The generic entry holds for any class (a subclass shares
            # the ml_meth); the others only when the class is the type
            # (_PySpec_FindMethod() checks the class the method is bound
            # to).
            typed_base = env | {first.name: Value(type_value)}
            args = params
            candidates = builtin_types.CANDIDATES
            on = f', on exactly {type_name}'
        else:
            typed_base = env
            args = [first, *params]
            candidates = [type_value] if type_value else []
            on = ''
        if type_value is None:
            candidates = []
        if not args:
            continue
        arg_names = [a.name for a in args]
        meth = f'(PyCFunction){generator.c_basename(name)}'
        generic = generator.residual(name, env)
        generic_facts = analyzer.facts(generic, env, arg_names)
        for tp in candidates:
            typed_env = typed_base | {args[0].name: tp}
            residual = generator.residual(name, typed_env)
            found = analyzer.facts(residual, typed_env, arg_names)
            if found.key() != generic_facts.key():
                entries.append((name, len(args), tp, found, arg_names, meth,
                                on))
        entries.append((name, len(args), None, generic_facts, arg_names,
                        meth, ''))

    table = f'{type_name}_spec_methods'
    out = [
        f'/* Facts of the {type_name} methods implemented by the spec, '
        'for the tier-2',
        ' * optimizer, keyed by ml_meth (see '
        'Include/internal/pycore_pyspec.h). */',
        f'static const _PySpecCall {table}[] = {{',
    ]
    for name, nargs, arg_type, found, arg_names, meth, on in entries:
        shown = [getattr(arg_type, '__name__', 'x')] + ['_'] * (nargs - 1)
        comment = f'{name}({", ".join(shown)}){on}'
        out += _entry(comment, nargs, found, None, arg_type,
                      ('meth', meth), arg_names)
    out += ['};', '']
    return out, table


def slot_member(spec: Spec, cls_name: str, dunder: str) -> str:
    """The C slot that keys the facts of special method *dunder* of spec
    class *cls_name*, as a member of PyHeapTypeObject
    (``as_mapping.mp_subscript``, ``ht_type.tp_iternext``): the first slot
    of the dunder in slotdefs[] that the class fills (all of them unless
    its @c_name names some), which is the one its wrapper calls."""
    _, named = spec.c_name(f'{cls_name}.{dunder}')
    for slotdef in slots.candidates(dunder):
        if not named or slotdef.slot in named:
            return f'{slotdef.subtable or "ht_type"}.{slotdef.slot}'
    raise ValueError(f'{cls_name}.{dunder} fills no slot')


def generate_slots(generator: emit.Generator, cls_name: str,
                   type_object: str) -> tuple[list[str], str]:
    """(C lines, array name) of the facts of the slots of class
    *cls_name* (whose type object is *type_object*) that have a Python
    reference, for self of exactly the class; ([], '') when there are
    none."""
    spec = generator.spec
    analyzer = generator.context.analyzer()
    tp = builtin_types.by_name(cls_name)
    entries: list[tuple[str, list[str], type | None, Facts]] = []
    for name in spec.native_functions():
        owner, _, dunder = name.rpartition('.')
        if owner != cls_name or not slots.is_slot(dunder):
            continue
        arg_names = spec.params(name)
        env: Env = {arg_names[0]: tp or NOTNULL}
        env |= {p: NOTNULL for p in arg_names[1:]}
        generic = analyzer.reference_facts(name, env)
        if len(arg_names) > 1:
            for candidate in builtin_types.CANDIDATES:
                found = analyzer.reference_facts(
                    name, env | {arg_names[1]: candidate})
                # (An argument type that always raises is left to the
                # generic entry: nothing uses that.)
                if found.key() != generic.key() and not found.always_raises:
                    entries.append((dunder, arg_names, candidate, found))
        entries.append((dunder, arg_names, None, generic))
    if not entries:
        return [], ''
    table = f'{cls_name}_spec_slots'
    out = [
        f'/* Facts of the slots of {cls_name} ({type_object}), derived '
        'from their',
        ' * Python references, for self of exactly the class, keyed by '
        'slot',
        ' * (see Include/internal/pycore_pyspec.h). */',
        f'static const _PySpecSlot {table}[] = {{',
    ]
    for dunder, arg_names, arg_type, found in entries:
        shown = ['self', getattr(arg_type, '__name__', 'x')][:len(arg_names)]
        # The entry of a call, without the function.
        entry = _entry(f'{cls_name}.{dunder}({", ".join(shown)})',
                       len(arg_names), found, None, arg_type, None,
                       arg_names)
        member = slot_member(spec, cls_name, dunder)
        out += [entry[0], '    {',
                f'        .slot = _PySpec_SLOT({member}),',
                f'        .name = "{dunder}",',
                '        .facts = {',
                *['    ' + line for line in entry[2:-1]],
                '        },',
                '    },']
    out += ['};', '']
    return out, table


def _just_calls(residual: list[ast.stmt], given: list[SpecParameter]
                ) -> marks.Specialization | None:
    """The Specialization a residual only calls with the given arguments
    (the same C signature), or None."""
    match residual:
        case [ast.Return(value=ast.Call(args=args) as call)]:
            mark = marks.get(call, marks.Specialized)
            if mark and mark.called and [ast.unparse(a) for a in args] == [
                    p.name for p in given]:
                return mark.special
    return None


def _variant(generator: emit.Generator, description: SpecFunction,
             c_name: str, residual: list[ast.stmt],
             given: list[SpecParameter], missing: list[SpecParameter],
             tp: type, facts: Facts, const: str | None) -> list[str]:
    described = _describe(facts, const, [p.name for p in given])
    return generator.commented_function(
        f'{generator.c_basename(description.name)}() for exactly '
        f'{description.new_type} with 1 positional argument of exact type '
        f'{tp.__name__}\n * ({described})',
        c_name, residual, [(p.name, p.ctype) for p in given],
        [p.name for p in missing])


# -- the registry ------------------------------------------------------------

REGISTRY_HEADER = os.path.join('Include', 'internal', 'pycore_pyspec.h')
REGISTRY_START = '/*[pyspec registry start]*/'
REGISTRY_END = '/*[pyspec registry end]*/'


def registry(root: str) -> list[tuple[str, str]]:
    """(table name, spec path relative to *root*) of the call table of
    every class of table_classes() of the specs of the core C files."""
    out = []
    for spec_path, _ in specfiles.core_spec_files(root):
        spec = Spec.load(spec_path)
        assert spec is not None
        rel = os.path.relpath(spec_path, root).replace(os.sep, '/')
        out += [(table_name(cls_name), rel)
                for cls_name in table_classes(spec)]
    names = [name for name, _ in out]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise SpecError(f"two spec classes have the call table "
                                 f"{', '.join(duplicates)}: rename one")
    return out


def registry_text(entries: list[tuple[str, str]]) -> str:
    """The generated part of the registry header, between the markers."""
    lines = [
        '/* Generated by Argument Clinic (Tools/clinic/libclinic/pyspec/'
        'call_table.py)',
        ' * from the specs of the core C files; do not edit: run clinic on '
        'a spec\'d',
        ' * C file. */',
    ]
    spec = None
    for name, rel in entries:
        if rel != spec:
            spec = rel
            lines.append(f'/* {rel} */')
        lines.append(f'PyAPI_DATA(const _PySpecCallTable) {name};')
    lines.append('#define _PySpec_REGISTRY(X)' + (' \\' if entries else ''))
    for i, (name, _) in enumerate(entries):
        lines.append(f'    X({name})' + (' \\' if i < len(entries) - 1
                                          else ''))
    return '\n'.join(lines) + '\n'


def registry_outputs(filename: str) -> list[tuple[str, str]]:
    """[(path, text)] of the registry header rewritten for the specs of
    the tree of *filename*, a C file being processed by Argument Clinic:
    [] unless it is a core C file (specfiles.is_core()) of a tree with the
    header."""
    filename = os.path.abspath(filename)
    root = os.path.dirname(os.path.dirname(filename))
    header = os.path.join(root, REGISTRY_HEADER)
    if not specfiles.is_core(root, filename) or not os.path.exists(header):
        return []
    with open(header, encoding='utf-8') as f:
        text = f.read()
    start = text.index(REGISTRY_START) + len(REGISTRY_START) + 1
    end = text.index(REGISTRY_END, start)
    return [(header, text[:start] + registry_text(registry(root))
             + text[end:])]

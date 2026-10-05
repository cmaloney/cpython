"""The call tables of the spec'd types, for the tier-2 optimizer.

emit.generate() calls generate() after the functions of a spec, in the
same generated file.  For each class of table_classes():

* NAME_nargs1_T(): the NAME_nargs1() of a __new__ partially evaluated for
  an argument of exact type T, for the candidates of builtin_types.py,
  kept when its residual is at most KEEP_RATIO of the generic one;
  variants with the same code share one C function, and one that only
  calls a shared specialization is that function;
* ``_PySpec_<class>_calls``: per arity of the __new__ (object arguments)
  and per argument type, the C function and the facts of its result;
  the same facts for the other methods the spec implements, per exact
  type of their first argument, keyed by ml_meth (the generic entry of a
  class method holds for a subclass, which shares the ml_meth); and per
  slot with a Python reference (a dunder with
  @ac.stub(optimizer_info=True)), for self of exactly the class, keyed by the
  slot the dunder's wrapper calls (slot_member()), which a uop that does
  what the slot does reads (_BINARY_OP_SUBSCR_BYTES_INT and
  _PySpec_FindSlot()).

The facts (facts.py) hold only for the exact argument types of their
entry: a constant result, a result that is argument k, the exact type
of the result, "always raises", "may run Python code".

The interpreter finds the tables in the registry, the generated header
Include/internal/pycore_pyspec_registry.h (included by pycore_pyspec.h),
which clinic rewrites from the syntax of all the core specs
(registry_outputs()): a new spec'd class is picked up without editing
C.
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

# Keep a type-specialized variant when its residual has at most this
# fraction of the AST nodes of the generic residual.
KEEP_RATIO = 0.5


def node_count(stmts: list[ast.stmt]) -> int:
    return sum(1 for stmt in stmts for _ in ast.walk(stmt))


def residual_key(stmts: list[ast.stmt]) -> str:
    """Residuals with equal keys lower to the same C: the AST and marks."""
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
    """The classes of *spec* that get a call table: with an implemented
    method or a slot with a Python reference.  Only the syntax decides,
    so that the registry lists the tables without generating them."""
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
    """The variants and the call table of each class of table_classes(),
    from *descriptions*, the implemented functions compiled
    unconditionally."""
    out: list[str] = []
    news: dict[str, SpecFunction] = {}      # class name -> __new__
    methods: dict[str, list[SpecFunction]] = {}
    for description in descriptions:
        cls_name, _, meth = description.name.rpartition('.')
        if meth == '__new__':
            news[cls_name] = description
        elif cls_name:
            methods.setdefault(cls_name, []).append(description)
    for cls_name in table_classes(generator.spec):
        type_object = _class_type_object(generator, cls_name)
        arrays = {
            'calls': generate_calls(generator, news[cls_name], out)
            if cls_name in news else '',
            'methods': generate_methods(generator, cls_name,
                                        methods[cls_name], out)
            if methods.get(cls_name) else '',
            'slots': generate_slots(generator, cls_name, type_object, out),
        }
        out += [f'const _PySpecCallTable {table_name(cls_name)} = {{',
                f'    .type = {type_object},']
        for field, array in arrays.items():
            if array:
                out += [f'    .n{field} = Py_ARRAY_LENGTH({array}),',
                        f'    .{field} = {array},']
        out += ['};', '']
    return out


def _array(out: list[str], ctype: str, name: str, comment: list[str],
           entries: list[str]) -> str:
    """Add the C array *name* of *entries* after *comment* to *out*."""
    out += [*comment, f'static const {ctype} {name}[] = {{', *entries,
            '};', '']
    return name


def _class_type_object(generator: emit.Generator, cls_name: str) -> str:
    """The type object of a builtin type, or of the clinic class."""
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


def generate_calls(generator: emit.Generator, description: SpecFunction,
                   out: list[str]) -> str:
    """Add the variants and the calls array of a clinic __new__ to *out*;
    the name of the array."""
    analyzer = generator.context.analyzer()
    name = description.name
    basename = generator.c_basename(name)
    entries: list[str] = []

    def entry(nargs: int, tp: type | None, function: str, found: Facts,
              const: str | None) -> None:
        shown = '' if nargs == 0 else getattr(tp, '__name__', 'x')
        entries.extend(_entry(
            f'{description.new_type}({shown})', nargs, found, const, tp,
            (f'f{nargs}', function),
            [p.name for p in description.parameters[1:nargs + 1]]))

    for env, _, given, missing in generator.arities(description):
        nargs = len(given)
        if any(p.ctype != emit.OBJECT for p in given):
            continue
        arg_names = [p.name for p in given]
        generic = generator.residual(name, env)
        if nargs == 1:
            functions: dict[str, str] = {}  # residual_key() -> C name
            for tp in builtin_types.CANDIDATES:
                typed_env = env | {given[0].name: tp}
                residual = generator.residual(name, typed_env)
                if node_count(residual) > KEEP_RATIO * node_count(generic):
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
                entry(nargs, tp, functions[key], found, const)
        entry(nargs, None, f'{basename}_nargs{nargs}',
              analyzer.facts(generic, env, arg_names), _const_name(generic))
    return _array(out, '_PySpecCall', f'{basename}_spec_calls', [
        f'/* Call table of {description.new_type}() for the tier-2 '
        'optimizer, see',
        ' * Include/internal/pycore_pyspec.h.  Generated by '
        'Argument Clinic',
        ' * (Tools/clinic/libclinic/pyspec/call_table.py). */'], entries)


def generate_methods(generator: emit.Generator, type_name: str,
                     descriptions: list[SpecFunction],
                     out: list[str]) -> str:
    """Add the facts of the methods and class methods of a type that the
    spec implements to *out*: per method, a generic entry, and an entry
    per exact type of the first argument whose facts differ (for a class
    method, called on exactly the type).  The arguments are those the C
    function sees besides the class; only calls with all of them, all
    objects, are described."""
    spec = generator.spec
    analyzer = generator.context.analyzer()
    # None for a class that is not a builtin type: only generic entries.
    type_value = builtin_types.by_name(type_name)
    entries: list[str] = []
    for description in descriptions:
        name = description.name
        node = spec.functions[name]
        if frontend.has_decorator(node, 'staticmethod'):
            continue
        first, *params = description.parameters
        if any(p.optional or p.ctype != emit.OBJECT for p in params):
            continue
        env: Env = {p.name: NOTNULL for p in description.parameters}
        if frontend.has_decorator(node, 'classmethod'):
            # The generic entry holds for any class (a subclass shares
            # the ml_meth); the others only when the class is the type
            # (_PySpec_FindMethod() checks the class the method is bound
            # to).
            typed_base = env | {first.name: Value(type_value)}
            args = params
            candidates = builtin_types.CANDIDATES if type_value else []
            on = f', on exactly {type_name}'
        else:
            typed_base = env
            args = [first, *params]
            candidates = [type_value] if type_value else []
            on = ''
        if not args:
            continue
        arg_names = [a.name for a in args]
        meth = ('meth', f'(PyCFunction){generator.c_basename(name)}')
        rest = ['_'] * (len(args) - 1)
        generic = analyzer.facts(generator.residual(name, env), env,
                                 arg_names)
        for tp in candidates:
            typed_env = typed_base | {args[0].name: tp}
            found = analyzer.facts(generator.residual(name, typed_env),
                                   typed_env, arg_names)
            if found.key() != generic.key():
                entries += _entry(
                    f'{name}({", ".join([tp.__name__, *rest])}){on}',
                    len(args), found, None, tp, meth, arg_names)
        entries += _entry(f'{name}({", ".join(["x", *rest])})', len(args),
                          generic, None, None, meth, arg_names)
    return _array(out, '_PySpecCall', f'{type_name}_spec_methods', [
        f'/* Facts of the {type_name} methods implemented by the spec, '
        'for the tier-2',
        ' * optimizer, keyed by ml_meth (see '
        'Include/internal/pycore_pyspec.h). */'], entries)


def slot_member(spec: Spec, cls_name: str, dunder: str) -> str:
    """The slot keying the facts of *dunder* of class *cls_name*, as a
    member of PyHeapTypeObject (``as_mapping.mp_subscript``): the first
    one in slotdefs[] the class fills, which its wrapper calls."""
    _, c_names = spec.c_name(f'{cls_name}.{dunder}')
    # (The METH_ flags name the C of a method table entry, not a slot.)
    named = {key for key in c_names if not key.startswith('METH_')}
    for slotdef in slots.candidates(dunder):
        if not named or slotdef.slot in named:
            return f'{slotdef.subtable or "ht_type"}.{slotdef.slot}'
    raise ValueError(f'{cls_name}.{dunder} fills no slot')


def generate_slots(generator: emit.Generator, cls_name: str,
                   type_object: str, out: list[str]) -> str:
    """Add the facts of the slots of class *cls_name* that have a Python
    reference, for self of exactly the class, to *out*; the name of the
    array, or '' when there are none."""
    spec = generator.spec
    analyzer = generator.context.analyzer()
    tp = builtin_types.by_name(cls_name)
    entries: list[str] = []

    def entry(dunder: str, arg_names: list[str], arg_type: type | None,
              found: Facts) -> None:
        shown = ['self', getattr(arg_type, '__name__', 'x')][:len(arg_names)]
        # The entry of a call, without the function.
        lines = _entry(f'{cls_name}.{dunder}({", ".join(shown)})',
                       len(arg_names), found, None, arg_type, None,
                       arg_names)
        member = slot_member(spec, cls_name, dunder)
        entries.extend([lines[0], '    {',
                        f'        .slot = _PySpec_SLOT({member}),',
                        f'        .name = "{dunder}",',
                        '        .facts = {',
                        *['    ' + line for line in lines[2:-1]],
                        '        },',
                        '    },'])

    for name in spec.native_functions():
        owner, _, dunder = name.rpartition('.')
        if owner != cls_name or not slots.is_slot(dunder):
            continue
        arg_names = spec.params(name)
        env: Env = {arg_names[0]: tp or NOTNULL}
        env |= {p: NOTNULL for p in arg_names[1:]}
        generic = analyzer.reference_facts(name, env)
        for candidate in builtin_types.CANDIDATES if arg_names[1:] else ():
            found = analyzer.reference_facts(
                name, env | {arg_names[1]: candidate})
            # (An argument type that always raises is left to the
            # generic entry: nothing uses that.)
            if found.key() != generic.key() and not found.always_raises:
                entry(dunder, arg_names, candidate, found)
        entry(dunder, arg_names, None, generic)
    if not entries:
        return ''
    return _array(out, '_PySpecSlot', f'{cls_name}_spec_slots', [
        f'/* Facts of the slots of {cls_name} ({type_object}), derived '
        'from their',
        ' * Python references, for self of exactly the class, keyed by '
        'slot',
        ' * (see Include/internal/pycore_pyspec.h). */'], entries)


def _just_calls(residual: list[ast.stmt], given: list[SpecParameter]
                ) -> marks.Specialization | None:
    """The Specialization *residual* only calls with *given*, or None."""
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

REGISTRY_HEADER = os.path.join('Include', 'internal',
                               'pycore_pyspec_registry.h')
# The header that defines _PySpecCallTable and includes the registry.
PYSPEC_HEADER = os.path.join('Include', 'internal', 'pycore_pyspec.h')


def registry(root: str) -> list[tuple[str, str]]:
    """(table name, spec path relative to *root*) of every call table of
    the core specs."""
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
    """The registry header: every call table (defined in the Objects/
    clinic/<file>_pyspec.c.h of its spec, exported for
    _testinternalcapi), and _PySpec_REGISTRY(X), which is X(table) for
    each."""
    lines = [
        '// This file is generated by Argument Clinic '
        '(Tools/clinic/libclinic/pyspec/',
        '// call_table.py) from the specs of the core C files.  Do not '
        'edit: run',
        '// clinic on a spec\'d C file ("make clinic").',
        '',
        '#ifndef Py_INTERNAL_PYSPEC_REGISTRY_H',
        '#define Py_INTERNAL_PYSPEC_REGISTRY_H',
        '#ifdef __cplusplus',
        'extern "C" {',
        '#endif',
        '',
        '#ifndef Py_BUILD_CORE',
        '#  error "this header requires Py_BUILD_CORE define"',
        '#endif',
        '',
        '/* The call tables (_PySpecCallTable: pycore_pyspec.h, which '
        'includes this',
        ' * file), and _PySpec_REGISTRY(X), which is X(table) for each. */',
    ]
    spec = None
    for name, rel in entries:
        if rel != spec:
            spec = rel
            lines.append(f'/* {rel} */')
        lines.append("// Export for '_testinternalcapi' shared extension")
        lines.append(f'PyAPI_DATA(const _PySpecCallTable) {name};')
    lines.append('#define _PySpec_REGISTRY(X)' + (' \\' if entries else ''))
    for i, (name, _) in enumerate(entries):
        lines.append(f'    X({name})' + (' \\' if i < len(entries) - 1
                                          else ''))
    lines += [
        '',
        '#ifdef __cplusplus',
        '}',
        '#endif',
        '#endif  // !Py_INTERNAL_PYSPEC_REGISTRY_H',
    ]
    return '\n'.join(lines) + '\n'


def registry_outputs(filename: str) -> list[tuple[str, str]]:
    """[(path, text)] of the registry header, when clinic processes
    *filename*, a core C file of a tree with pycore_pyspec.h."""
    filename = os.path.abspath(filename)
    root = os.path.dirname(os.path.dirname(filename))
    if (not specfiles.is_core(root, filename)
            or not os.path.exists(os.path.join(root, PYSPEC_HEADER))):
        return []
    return [(os.path.join(root, REGISTRY_HEADER),
             registry_text(registry(root)))]

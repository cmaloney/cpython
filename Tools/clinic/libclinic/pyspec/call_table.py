"""Generate the call table of a spec'd type for the tier-2 optimizer.

For a clinic __new__ implemented by a spec (``def __new__(cls, ...)`` in
``class bytes:``, the clinic function bytes.__new__, C basename
bytes_new), emit.py generates NAME_nargsN(): the spec partially evaluated
for exactly that type and N positional arguments.  emit.py then calls
generate() here, which adds to the same generated file (Argument Clinic
writes it; there is no separate command):

* NAME_nargs1_T(): NAME_nargs1 partially evaluated for an argument of
  exact type T, for T from a fixed list of common builtin types
  (CANDIDATE_TYPES).  No annotation chooses them: a variant is kept only
  when its residual code is much smaller than the generic one
  (KEEP_RATIO); variants with identical code share one C function, and a
  variant that would only call a shared specialization
  (partial_eval.Specialization, e.g. bytes_from_iterator_list()) is that
  function.

* ``const _PySpecCallTable _PySpec_<type>_calls`` (declared in
  Include/internal/pycore_pyspec.h): per arity with object-only arguments
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
      a constant, an escape whose stub says New[T], a spec function whose
      own returns all do, or a name whose exact type the path proves
      (``type(x) is K`` or the argument's known type).  ``isinstance``
      checks allow subclasses and prove nothing;
    - _PySpec_ALWAYS_RAISES: no ``return`` is left;
    - _PySpec_MAY_RUN_PYTHON: some call on a path may run Python code:
      an escape whose stub says RunsPython (for RunsPython[T, 'p'], only
      when the exact type of p is not known to be a static type) unless
      it is lowered by a fast path, an exact type or unchecked lowering,
      a call of an object (e.g. a method found by lookup_special), or a
      spec function or specialization that may.

The facts of the escapes come from the stubs of the same name in the spec
(runtime.stub_facts()): there is no second table here.  All facts hold
only for the exact argument types of their entry: a subclass instance
uses the generic entry.
"""

import ast
import builtins

from . import builtin_types, emit, facts, partial_eval
from .partial_eval import NOTNULL, NULL, Value

# Keep a type-specialized variant when its residual has at most this
# fraction of the AST nodes of the generic residual.
KEEP_RATIO = 0.5


def node_count(stmts):
    return sum(1 for stmt in stmts for _ in ast.walk(stmt))


def residual_key(stmts):
    """Residuals with equal keys lower to the same C: the AST, and the
    marks of the partial evaluator that the emitter reads (e.g. whether a
    loop iterates a list or a tuple by index)."""
    marks = [(type(node).__name__, name, repr(value))
             for stmt in stmts for node in ast.walk(stmt)
             for name, value in vars(node).items()
             if name.startswith('pyspec_')]
    return ast.dump(ast.Module(stmts, [])) + repr(marks)


def _const_name(residual):
    """Py_CONSTANT_* name if the residual is just ``return <constant>``."""
    match residual:
        case [ast.Return(value=ast.Constant() as value)]:
            return builtin_types.constant(value.value)
    return None


def _flags(facts):
    flags = []
    if facts.runs_python:
        flags.append('_PySpec_MAY_RUN_PYTHON')
    if facts.always_raises:
        flags.append('_PySpec_ALWAYS_RAISES')
    return ' | '.join(flags) or '0'


def _describe(facts, const, arg_names=()):
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


def _type_object(tp):
    return builtin_types.TABLE[tp].type_object if tp is not None else 'NULL'


def _entry(comment, nargs, facts, const, arg_type, func, arg_names=()):
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
        f'        .func.{func[0]} = {func[1]},',
        '    },',
    ]


def generate(generator, descriptions):
    """C lines: the type-specialized variants and the call table of each
    type with a clinic __new__ or methods implemented by the spec, in
    *descriptions* (frontend.SpecFunction).

    *generator* is the emit.Generator of the spec."""
    out = []
    by_type = {}            # type name -> [__new__ description, methods]
    for description in descriptions:
        cls_name, _, meth = description.name.rpartition('.')
        if builtin_types.by_name(cls_name) is None:
            continue
        new, methods = by_type.setdefault(cls_name, [None, []])
        if meth == '__new__':
            by_type[cls_name][0] = description
        else:
            methods.append(description)
    for type_name, (new, methods) in by_type.items():
        calls = None
        if new is not None:
            lines, calls = generate_calls(generator, new)
            out += lines
        method_table = None
        if methods:
            lines, method_table = generate_methods(generator, type_name,
                                                   methods)
            out += lines
        out += [
            f'const _PySpecCallTable _PySpec_{type_name}_calls = {{',
            f'    .type = {_type_object(builtin_types.by_name(type_name))},',
        ]
        if calls:
            out += [f'    .ncalls = Py_ARRAY_LENGTH({calls}),',
                    f'    .calls = {calls},']
        if method_table:
            out += [f'    .nmethods = Py_ARRAY_LENGTH({method_table}),',
                    f'    .methods = {method_table},']
        out += ['};', '']
    return out


def generate_calls(generator, description):
    """The variants and the calls array of a clinic __new__."""
    spec = generator.spec
    analyzer = facts.analyzer(spec)
    cls, *params = description.parameters
    required = sum(not p.optional for p in params)
    type_value = getattr(builtins, description.new_type)
    # The spec function ("bytes.__new__") and the C basename of its
    # clinic function ("bytes_new").
    name = description.name
    basename = generator.c_basename(name)
    out = []
    entries = []            # (nargs, arg type name, function, facts, const)
    for nargs in range(required, len(params) + 1):
        given, missing = params[:nargs], params[nargs:]
        if any(p.ctype != emit.OBJECT for p in given):
            continue
        arg_names = [p.name for p in given]
        env = {cls.name: Value(type_value)}
        env |= {p.name: NOTNULL for p in given}
        env |= {p.name: NULL for p in missing}
        generic = partial_eval.specialize(spec, name, env)
        generic_size = node_count(generic)
        if nargs == 1:
            functions = {}      # ast dump of the residual -> C name
            for tp in builtin_types.CANDIDATES:
                typed_env = env | {given[0].name: tp}
                residual = partial_eval.specialize(spec, name, typed_env)
                if node_count(residual) > KEEP_RATIO * generic_size:
                    continue
                key = residual_key(residual)
                found = analyzer.facts(residual, typed_env, arg_names)
                const = _const_name(residual)
                special = _just_calls(spec, residual, given)
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


def generate_methods(generator, type_name, descriptions):
    """The facts of the methods and class methods of a type implemented by
    the spec: per method, a generic entry, and an entry per exact type of
    the first argument whose facts differ from it (for a class method,
    called on exactly the type).

    The arguments are those the C function sees besides the class: for a
    method, self and the others; for a class method, the others (the class
    is the type itself).  Only calls with all parameters, all objects, are
    described."""
    spec = generator.spec
    analyzer = facts.analyzer(spec)
    type_value = getattr(builtins, type_name)
    entries = []
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
        env = {p.name: NOTNULL for p in params}
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
            candidates = [type_value]
            on = ''
        if not args:
            continue
        arg_names = [a.name for a in args]
        meth = f'(PyCFunction){generator.c_basename(name)}'
        generic = partial_eval.specialize(spec, name, env)
        generic_facts = analyzer.facts(generic, env, arg_names)
        for tp in candidates:
            typed_env = typed_base | {args[0].name: tp}
            residual = partial_eval.specialize(spec, name, typed_env)
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


def _just_calls(spec, residual, given):
    """The Specialization a residual only calls with the given arguments
    (the same C signature), or None."""
    match residual:
        case [ast.Return(value=ast.Call(args=args) as call)]:
            special = partial_eval.specialization_of(spec, call)
            if special is not None and [ast.unparse(a) for a in args] == [
                    p.name for p in given]:
                return special
    return None


def _variant(generator, description, c_name, residual, given, missing, tp,
             facts, const):
    emitter = emit.FunctionEmitter(
        generator, [(p.name, p.ctype) for p in given],
        known_null=[p.name for p in missing])
    code = ast.unparse(ast.Module(residual, [])).replace('*/', '* /')
    return [
        f'/* {generator.c_basename(description.name)}() for exactly '
        f'{description.new_type} with '
        f'1 positional argument of exact type {tp.__name__}',
        f' * ({_describe(facts, const, [p.name for p in given])}):',
        *[' * ' + line if line else ' *' for line in code.splitlines()],
        ' */',
        *emitter.function(c_name, residual),
        '',
    ]

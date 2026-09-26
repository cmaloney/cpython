"""Generate the call table of a spec'd type for the tier-2 optimizer.

For a clinic __new__ implemented by a spec (``def __new__(cls, ...)`` in
``class bytes:``, used by the clinic block ``bytes.__new__ as bytes_new``),
emit.py generates NAME_nargsN(): the spec partially evaluated for exactly
that type and N positional arguments.  emit.py then calls generate() here,
which adds to the same generated file (Argument Clinic writes it; there is
no separate command):

* NAME_nargs1_T(): NAME_nargs1 partially evaluated for an argument of
  exact type T, for T from a fixed list of builtin types.  No annotation
  chooses them: a variant is kept only when its residual code is much
  smaller than the generic one (KEEP_RATIO); variants with identical code
  share one C function.

* ``const _PySpecCallTable _PySpec_<type>_calls`` (declared in
  Include/internal/pycore_pyspec.h): per arity with object-only arguments
  and per argument type, the C function and facts about its result, all
  derived from the residual code; and the same facts for the other
  methods the spec implements (bytes.__bytes__, bytes.fromhex), per exact
  type of their first argument, keyed by their ml_meth:

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
      when the exact type of p is not known to be a static type), a call
      of an object (e.g. a method found by lookup_special) or a spec
      function that may.

The facts of the escapes come from the stubs of the same name in the spec
(runtime.stub_facts()): there is no second table here.  All facts hold
only for the exact argument types of their entry: a subclass instance
uses the generic entry.
"""

import ast
import builtins

from . import emit, partial_eval, runtime
from .partial_eval import NOTNULL, NULL, Value

# Exact argument types tried for one-argument calls.
CANDIDATE_TYPES = [bytes, bytearray, memoryview, list, tuple, int, str,
                   range, dict, float]

# C type objects of the candidates and of result types.
TYPE_OBJECTS = {
    'bytes': '&PyBytes_Type',
    'bytearray': '&PyByteArray_Type',
    'memoryview': '&PyMemoryView_Type',
    'list': '&PyList_Type',
    'tuple': '&PyTuple_Type',
    'int': '&PyLong_Type',
    'str': '&PyUnicode_Type',
    'range': '&PyRange_Type',
    'dict': '&PyDict_Type',
    'float': '&PyFloat_Type',
}

# Keep a type-specialized variant when its residual has at most this
# fraction of the AST nodes of the generic residual.
KEEP_RATIO = 0.5


def node_count(stmts):
    return sum(1 for stmt in stmts for _ in ast.walk(stmt))


class Facts:
    """Facts about the results of a list of statements."""

    def __init__(self):
        # Per return: (exact type or None, index of the argument it
        # returns or None).
        self.returns = []
        self.runs_python = False

    @property
    def always_raises(self):
        return not self.returns

    @property
    def result_type(self):
        types = {tp for tp, _ in self.returns}
        if len(types) == 1 and None not in types:
            return types.pop()
        return None

    @property
    def alias(self):
        aliases = {alias for _, alias in self.returns}
        if len(aliases) == 1 and None not in aliases:
            return aliases.pop()
        return None

    def key(self):
        return (self.runs_python, self.always_raises, self.result_type,
                self.alias)


class Analyzer:
    def __init__(self, spec):
        self.spec = spec
        self._function_facts = {}
        self._stub_facts = {}
        self.params = []

    # -- whole functions ----------------------------------------------------

    def function_facts(self, name):
        """Facts of spec function *name* for any arguments."""
        if name not in self._function_facts:
            # Recursion: assume the worst while analyzing.
            unknown = Facts()
            unknown.returns.append((None, None))
            unknown.runs_python = True
            self._function_facts[name] = unknown
            self._function_facts[name] = self.facts(self.spec.body(name), {})
        return self._function_facts[name]

    def escape_facts(self, name):
        """runtime.StubFacts of escape C.<name>, from the stub of that name
        in the spec, or None."""
        if name not in self._stub_facts:
            node = self.spec.functions.get(name)
            facts = None
            if node is not None and not self.spec.implemented(name):
                facts = runtime.stub_facts(node)
            self._stub_facts[name] = facts
        return self._stub_facts[name]

    def facts(self, stmts, types, params=()):
        """Facts of *stmts*; *types* maps names to their exact types;
        *params* are the names of the call arguments, in order (a return
        of one of them is an alias of that argument)."""
        facts = Facts()
        saved, self.params = self.params, list(params)
        try:
            self.block(stmts, dict(types), {}, facts)
        finally:
            self.params = saved
        return facts

    # -- statements ---------------------------------------------------------

    def block(self, stmts, types, local_types, facts):
        for stmt in stmts:
            self.statement(stmt, types, local_types, facts)

    def statement(self, stmt, types, local_types, facts):
        match stmt:
            case ast.Pass():
                pass
            case ast.If(test=test, body=body, orelse=orelse):
                self.expression(test, types, local_types, facts)
                true_types, false_types = self.refine(test)
                self.block(body, types | true_types, dict(local_types), facts)
                self.block(orelse, types | false_types, dict(local_types),
                           facts)
            case ast.Assign(targets=[ast.Name(name)], value=value):
                local_types[name] = self.call(value, types, local_types,
                                              facts)
            case ast.Return(value=value):
                facts.returns.append(self.value(value, types, local_types,
                                                facts))
            case ast.Raise():
                # Building the message only formats type names.
                pass
            case ast.Try(body=body, handlers=handlers, orelse=orelse):
                self.block(body, types, local_types, facts)
                for handler in handlers:
                    self.block(handler.body, types, dict(local_types), facts)
                self.block(orelse, types, dict(local_types), facts)
            case ast.With(body=body):
                self.block(body, types, local_types, facts)
            case _:
                facts.runs_python = True
                facts.returns.append((None, None))

    def expression(self, node, types, local_types, facts):
        """Account for the calls a condition makes (walrus operands)."""
        for child in ast.walk(node):
            if isinstance(child, ast.NamedExpr):
                local_types[child.target.id] = self.call(
                    child.value, types, local_types, facts)

    @staticmethod
    def refine(test):
        """Exact types proven by *test* in the (body, else) of an if."""
        match test:
            case ast.Compare(left=ast.Call(func=ast.Name('type'),
                                           args=[ast.Name(name)]),
                             ops=[ast.Is() | ast.IsNot() as op],
                             comparators=[ast.Name(cls)]):
                tp = getattr(builtins, cls, None)
                if isinstance(tp, type):
                    known = {name: tp}
                    if isinstance(op, ast.IsNot):
                        return {}, known
                    return known, {}
            case ast.BoolOp(op=ast.And(), values=values):
                known = {}
                for value in values:
                    known |= Analyzer.refine(value)[0]
                return known, {}
        return {}, {}

    # -- values -------------------------------------------------------------

    def value(self, node, types, local_types, facts):
        """(exact type or None, argument index or None) of a returned
        value."""
        alias = None
        if isinstance(node, ast.Name) and node.id in self.params:
            alias = self.params.index(node.id)
        return self.value_type(node, types, local_types, facts), alias

    def value_type(self, node, types, local_types, facts):
        match node:
            case ast.Constant(value=value):
                return type(value)
            case ast.Name(name) if name in types:
                return types[name]
            case ast.Name(name) if name in local_types:
                return local_types[name]
            case ast.Name():
                return None
            case ast.Call():
                return self.call(node, types, local_types, facts)
        facts.runs_python = True
        return None

    def call(self, node, types, local_types, facts):
        """Exact result type of call *node*; record if it runs Python."""
        if not isinstance(node, ast.Call):
            facts.runs_python = True
            return None
        func = node.func
        if (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                and func.value.id == 'C'):
            stub = self.escape_facts(func.attr)
            if stub is None:
                # No stub: assume the worst.
                facts.runs_python = True
                return None
            arg_types = [self.arg_type(a, types) for a in node.args]
            facts.runs_python |= stub.runs_python_for(arg_types)
            return stub.result_type
        callee_name = self.spec.call_target(func)
        if callee_name is not None:
            # An implemented spec function (a stub is a hand-written C
            # function: assume the worst below).
            callee = self.function_facts(callee_name)
            facts.runs_python |= callee.runs_python
            return callee.result_type
        if isinstance(func, ast.Name):
            if func.id == 'iter' and len(node.args) == 1:
                tp = self.arg_type(node.args[0], types)
                facts.runs_python |= (tp is None
                                      or not runtime.is_static_type(tp))
                return None
        # e.g. calling the result of lookup_special, or cls(result)
        facts.runs_python = True
        return None

    @staticmethod
    def arg_type(node, types):
        if isinstance(node, ast.Name):
            value = types.get(node.id)
            if isinstance(value, type):
                return value
        return None


def _type_env(env):
    return {name: value for name, value in env.items()
            if isinstance(value, type)}


def _const_name(residual):
    """Py_CONSTANT_* name if the residual is just ``return <constant>``."""
    match residual:
        case [ast.Return(value=ast.Constant() as value)]:
            return emit.CONSTANT_OBJECTS.get(repr(value.value))
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


def _entry(comment, nargs, facts, const, arg_type, func, arg_names=()):
    result_type = (TYPE_OBJECTS[facts.result_type.__name__]
                   if facts.result_type is not None else 'NULL')
    alias = facts.alias if const is None and facts.alias is not None else -1
    return [
        f'    /* {comment}: {_describe(facts, const, arg_names)} */',
        '    {',
        f'        .nargs = {nargs},',
        f'        .flags = {_flags(facts)},',
        f'        .result_const = {const if const else -1},',
        f'        .result_alias = {alias},',
        f'        .arg_type = {TYPE_OBJECTS[arg_type] if arg_type else "NULL"},',
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
        if not cls_name or cls_name not in TYPE_OBJECTS:
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
            f'    .type = {TYPE_OBJECTS[type_name]},',
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
    analyzer = Analyzer(spec)
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
            for tp in CANDIDATE_TYPES:
                typed_env = env | {given[0].name: tp}
                residual = partial_eval.specialize(spec, name, typed_env)
                if node_count(residual) > KEEP_RATIO * generic_size:
                    continue
                key = ast.dump(ast.Module(residual, []))
                facts = analyzer.facts(residual, _type_env(typed_env),
                                       arg_names)
                const = _const_name(residual)
                if key not in functions:
                    functions[key] = c_name = (
                        f'{basename}_nargs1_{tp.__name__}')
                    out += _variant(generator, description, c_name,
                                    residual, given, missing, tp, facts,
                                    const)
                entries.append((nargs, tp.__name__, functions[key], facts,
                                const))
        facts = analyzer.facts(generic, _type_env(env), arg_names)
        entries.append((nargs, None, f'{basename}_nargs{nargs}', facts,
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
    for nargs, arg_type, function, facts, const in entries:
        comment = (f'{description.new_type}('
                   f'{"" if nargs == 0 else (arg_type or "x")})')
        out += _entry(comment, nargs, facts, const, arg_type,
                      (f'f{nargs}', function),
                      [p.name for p in params[:nargs]])
    out += ['};', '']
    return out, table


def generate_methods(generator, type_name, descriptions):
    """The facts of the methods and class methods of a type implemented by
    the spec: per method, a generic entry, and an entry per exact type of
    the first argument whose facts differ from it.

    The arguments are those the C function sees besides the class: for a
    method, self and the others; for a class method, the others (the class
    is the type itself).  Only calls with all parameters, all objects, are
    described."""
    spec = generator.spec
    analyzer = Analyzer(spec)
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
        if 'classmethod' in decorators:
            env[first.name] = Value(type_value)
            args = params
            candidates = CANDIDATE_TYPES
        else:
            env[first.name] = NOTNULL
            args = [first, *params]
            candidates = [type_value]
        if not args:
            continue
        arg_names = [a.name for a in args]
        meth = f'(PyCFunction){generator.c_basename(name)}'
        generic = partial_eval.specialize(spec, name, env)
        generic_facts = analyzer.facts(generic, _type_env(env), arg_names)
        for tp in candidates:
            typed_env = env | {args[0].name: tp}
            residual = partial_eval.specialize(spec, name, typed_env)
            facts = analyzer.facts(residual, _type_env(typed_env),
                                   arg_names)
            if facts.key() != generic_facts.key():
                entries.append((name, len(args), tp.__name__, facts,
                                arg_names, meth))
        entries.append((name, len(args), None, generic_facts, arg_names,
                        meth))

    table = f'{type_name}_spec_methods'
    out = [
        f'/* Facts of the {type_name} methods implemented by the spec, '
        'for the tier-2',
        ' * optimizer, keyed by ml_meth (see '
        'Include/internal/pycore_pyspec.h). */',
        f'static const _PySpecCall {table}[] = {{',
    ]
    for name, nargs, arg_type, facts, arg_names, meth in entries:
        shown = [arg_type or 'x'] + ['_'] * (nargs - 1)
        comment = f'{name}({", ".join(shown)})'
        out += _entry(comment, nargs, facts, None, arg_type,
                      ('meth', meth), arg_names)
    out += ['};', '']
    return out, table


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

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
  derived from the residual code:

    - result_const: the residual is just ``return <constant>``;
    - result_type: every ``return`` gives an object of that exact type:
      a constant, an escape declared below as returning exactly it, a
      spec function whose own returns all do, or a name whose exact type
      the path proves (``type(x) is K`` or the argument's known type).
      ``isinstance`` checks allow subclasses and prove nothing;
    - _PySpec_ALWAYS_RAISES: no ``return`` is left;
    - _PySpec_MAY_RUN_PYTHON: some call on a path may run Python code.
"""

import ast
import builtins

from . import emit, partial_eval
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

# Result facts of escapes, for now declared here rather than in
# runtime.py: (exact result type or None, may run Python code).
# 'arg0' for the latter means "only if the type of the first argument is
# not a builtin (static) type", e.g. a Python class defining __buffer__.
ESCAPE_FACTS = {
    'lookup_special': (None, 'arg0'),
    # A codec may return a bytes subclass instance.
    'PyUnicode_AsEncodedString': (None, True),
    'PyNumber_AsSsize_t': (None, 'arg0'),
    '_PyBytes_FromSize': (bytes, False),
    '_PyBytes_FromBuffer': (bytes, 'arg0'),
    '_PyBytes_FromSequence_lock_held': (bytes, False),
    # Calls __index__ of the items.
    '_PyBytes_FromIterator': (bytes, True),
    # Returns an instance of the subtype.
    'bytes_subtype_new': (None, True),
}

HEAPTYPE = 1 << 9


def _is_static_type(tp):
    return isinstance(tp, type) and not tp.__flags__ & HEAPTYPE


def node_count(stmts):
    return sum(1 for stmt in stmts for _ in ast.walk(stmt))


class Facts:
    """Facts about the results of a list of statements."""

    def __init__(self):
        self.returns = []           # exact type (or None) per return
        self.runs_python = False

    @property
    def always_raises(self):
        return not self.returns

    @property
    def result_type(self):
        types = set(self.returns)
        if len(types) == 1 and None not in types:
            return types.pop()
        return None


class Analyzer:
    def __init__(self, spec):
        self.spec = spec
        self._function_facts = {}

    # -- whole functions ----------------------------------------------------

    def function_facts(self, name):
        """Facts of spec function *name* for any arguments."""
        if name not in self._function_facts:
            # Recursion: assume the worst while analyzing.
            unknown = Facts()
            unknown.returns.append(None)
            unknown.runs_python = True
            self._function_facts[name] = unknown
            self._function_facts[name] = self.facts(self.spec.body(name), {})
        return self._function_facts[name]

    def facts(self, stmts, types):
        """Facts of *stmts*; *types* maps names to their exact types."""
        facts = Facts()
        self.block(stmts, dict(types), {}, facts)
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
                facts.returns.append(self.value_type(value, types,
                                                     local_types, facts))
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
                facts.returns.append(None)

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
            result, runs_python = ESCAPE_FACTS.get(func.attr, (None, True))
            if runs_python == 'arg0':
                runs_python = not _is_static_type(
                    self.arg_type(node.args[0], types))
            facts.runs_python |= runs_python
            return result
        callee_name = self.spec.call_target(func)
        if callee_name is not None:
            # An implemented spec function (a stub is a hand-written C
            # function: assume the worst below).
            callee = self.function_facts(callee_name)
            facts.runs_python |= callee.runs_python
            return callee.result_type
        if isinstance(func, ast.Name):
            if func.id == 'iter' and len(node.args) == 1:
                facts.runs_python |= not _is_static_type(
                    self.arg_type(node.args[0], types))
                return None
        # e.g. calling the result of lookup_special
        facts.runs_python = True
        return None

    @staticmethod
    def arg_type(node, types):
        if isinstance(node, ast.Name):
            return types.get(node.id)
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


def _describe(facts, const):
    parts = []
    if const is not None:
        parts.append(f'always {const}, no side effects')
    elif facts.result_type is not None:
        parts.append(f'result is exactly {facts.result_type.__name__}')
    elif not facts.always_raises:
        parts.append('result type not known exactly')
    if facts.always_raises:
        parts.append('always raises')
    parts.append('may run Python code' if facts.runs_python
                 else 'runs no Python code')
    return '; '.join(parts)


def generate(generator, descriptions):
    """C lines: the type-specialized variants and the call table of each
    clinic __new__ in *descriptions* (frontend.SpecFunction).

    *generator* is the emit.Generator of the spec."""
    out = []
    for description in descriptions:
        if description.new_type is not None:
            out += generate_table(generator, description)
    return out


def generate_table(generator, description):
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
                facts = analyzer.facts(residual, _type_env(typed_env))
                const = _const_name(residual)
                if key not in functions:
                    functions[key] = c_name = (
                        f'{basename}_nargs1_{tp.__name__}')
                    out += _variant(generator, description, c_name,
                                    residual, given, missing, tp, facts,
                                    const)
                entries.append((nargs, tp.__name__, functions[key], facts,
                                const))
        facts = analyzer.facts(generic, _type_env(env))
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
        result_type = (TYPE_OBJECTS[facts.result_type.__name__]
                       if facts.result_type is not None else 'NULL')
        out += [
            f'    /* {description.new_type}('
            f'{"" if nargs == 0 else (arg_type or "x")}): '
            f'{_describe(facts, const)} */',
            '    {',
            f'        .nargs = {nargs},',
            f'        .flags = {_flags(facts)},',
            f'        .result_const = {const if const else -1},',
            f'        .arg_type = '
            f'{TYPE_OBJECTS[arg_type] if arg_type else "NULL"},',
            f'        .result_type = {result_type},',
            f'        .func.f{nargs} = {function},',
            '    },',
        ]
    out += [
        '};',
        '',
        f'const _PySpecCallTable _PySpec_{description.new_type}_calls = {{',
        f'    .type = {TYPE_OBJECTS[description.new_type]},',
        f'    .ncalls = Py_ARRAY_LENGTH({table}),',
        f'    .calls = {table},',
        '};',
        '',
    ]
    return out


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
        f' * ({_describe(facts, const)}):',
        *[' * ' + line if line else ' *' for line in code.splitlines()],
        ' */',
        *emitter.function(c_name, residual),
        '',
    ]

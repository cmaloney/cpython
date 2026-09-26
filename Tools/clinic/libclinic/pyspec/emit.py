"""Generate C from the implemented functions of a pyspec file.

Argument Clinic calls generate() after processing a C file with a spec
and writes the result next to its other output
(Objects/clinic/bytesobject_pyspec.c.h for Objects/bytesobject.c).

Every implemented spec function becomes a C function:
  * a method of a spec class implements the clinic function of that name.
    For a method or class method (``bytes.__bytes__``) it becomes the
    NAME_impl() that clinic's parsing code calls; the first parameter is
    clinic's self (or class) parameter.  For ``bytes.__new__ as bytes_new`` it
    becomes bytes_new_impl() (Argument Clinic declares it and no longer
    expects a hand-written body), plus bytes_new_nargsN() for each
    positional argument count N -- the function partially evaluated for
    exactly the class and N arguments, called by the clinic generated
    vectorcall;
  * a top-level function becomes the C function of the same name: names
    starting with Py or _Py are defined non-static (their public or
    internal header declares them); everything else is static.

Functions whose body is only a docstring and/or ``...`` are stubs
(frontend.is_stub()) and are never lowered to C.

For a __new__ implemented by the spec, call_table.py then adds
type-specialized variants of NAME_nargs1() and the call table the tier-2
optimizer reads (Include/internal/pycore_pyspec.h).

The accepted Python subset is small on purpose; anything else is an error.

Statements:
  if/else, return, raise E("...") / raise E(f"..."), raise C.<escape>(),
  pass,
  x = <call>, C.<escape>(...) (an escape returning an int status),
  try: x = <call> / except E: ... / else: ...,
  with C.<context escape>(x): x = <call>,
  for item in it: ... (it = iter(x); lowered to PyIter_Next() calls, or
  to an index loop over x when the partial evaluator knows x is an exact
  list or tuple, see partial_eval.py)
Conditions:
  x is [not] NULL, type(x) is K, cls is [not] K, isinstance(x, K),
  hasattr(type(x), "__dunder__"), (v := C.<escape>(...)) is [not] NULL,
  integer comparisons, and/or/not
Calls (result is a new reference or a Py_ssize_t):
  C.<escape>(...), iter(x), f() for an object variable f, f(x) for an
  object or type variable f (e.g. cls(result)),
  <spec function>(...), T.<spec method>(...)

The partial evaluator adds (see partial_eval.py): calls of shared
specializations, fast path guards ``C.<escape>.fast(x)``, the marks of
escape calls with a cheaper lowering (pyspec_fast, pyspec_exact,
pyspec_unchecked: they cannot fail), and for snapshots, ``return
FALLBACK`` (Py_None, never a result: the caller restarts),
``x is [not] FALLBACK`` and ``with C.critical_section(x):``.

Reference ownership: parameters are borrowed; every object local is a new
reference, declared NULL at the top and released with Py_XDECREF at every
exit except the one returning it; it may be assigned again only where it
holds no reference (e.g. in the other branch of an if).  A loop variable
is a new reference, released right after its last use in the loop body;
it is borrowed for a tuple item (the tuple keeps it alive) and in a
snapshot, where no Python code runs (the list, locked, keeps it alive):
"borrowed until Python code may run".  A C local initialized by an
escape (e.g. a bytes_appender) is released like an object, with the
release statement of its escape, unless an escape that steals it was
called.
"""

import ast
import builtins

from . import call_table, frontend, partial_eval, runtime
from .partial_eval import NOTNULL, NULL, Value
from .runtime import (ContextEscape, Escape, ERR_MINUS1, ERR_NEGATIVE,
                      ERR_NULL, ERR_NULL_OR_MISSING, RaiseEscape)

OBJECT = 'PyObject *'
SSIZE = 'Py_ssize_t'
TYPE = frontend.TYPE_CTYPE
TYPE_OBJECTS = frontend.TYPE_OBJECTS

TYPE_CHECK = {
    'bytes': 'PyBytes_Check',
    'str': 'PyUnicode_Check',
    'int': 'PyLong_Check',
    'list': 'PyList_Check',
    'tuple': 'PyTuple_Check',
}

TYPE_CHECK_EXACT = {name: check + 'Exact'
                    for name, check in TYPE_CHECK.items()}
TYPE_CHECK_EXACT['bool'] = 'PyBool_Check'   # bool has no subclasses

SLOT_CHECK = {
    '__index__': '_PyIndex_Check({0})',
    '__buffer__': 'PyObject_CheckBuffer({0})',
}

CONSTANT_OBJECTS = {
    repr(b''): 'Py_CONSTANT_EMPTY_BYTES',
    repr(''): 'Py_CONSTANT_EMPTY_STR',
    repr(()): 'Py_CONSTANT_EMPTY_TUPLE',
    repr(None): 'Py_CONSTANT_NONE',
    repr(0): 'Py_CONSTANT_ZERO',
    repr(1): 'Py_CONSTANT_ONE',
}

COMPARE_OPS = {ast.Lt: '<', ast.LtE: '<=', ast.Gt: '>', ast.GtE: '>=',
               ast.Eq: '==', ast.NotEq: '!='}


def c_decl(ctype, name):
    return f'{ctype}{name}' if ctype.endswith('*') else f'{ctype} {name}'


def c_not(expr):
    if expr.replace('_', '').replace('(', '').replace(')', '').isalnum():
        return f'!{expr}'
    return f'!({expr})'


class SpecError(Exception):
    def __init__(self, node, message):
        line = getattr(node, 'lineno', '?')
        super().__init__(f'line {line}: {message}')


def c_string(text):
    out = ['"']
    for ch in text:
        if ch in '\\"':
            out.append('\\' + ch)
        elif ch == '\n':
            out.append('\\n')
        elif ' ' <= ch <= '~':
            out.append(ch)
        else:
            raise ValueError(f'non-ASCII character in C string: {text!r}')
    out.append('"')
    return ''.join(out)


def escape_of(node):
    """Return the escape for a ``C.<name>`` node."""
    if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
            and node.value.id == 'C'):
        value = getattr(runtime.C, node.attr, None)
        if isinstance(value, (Escape, ContextEscape, RaiseEscape)):
            return value
        raise SpecError(node, f'unknown escape C.{node.attr}')
    return None


class FunctionEmitter:
    """Lower one list of spec statements to the body of a C function."""

    def __init__(self, generator, params, known_null=()):
        self.generator = generator
        self.spec = generator.spec
        # name -> C type; parameters are borrowed references
        self.params = dict(params)
        self.known_null = set(known_null)
        self.locals = {}            # name -> C type
        # Object locals and C locals with a release statement, in
        # declaration order.
        self.owned = []
        self.releases = {}          # C local -> its release statement
        self.live = set()           # owned locals that may hold a value
        self.loop_vars = []         # owned variables of enclosing loops
        self.lines = []
        self.indent = 1

    # -- output ------------------------------------------------------------

    def emit(self, line):
        self.lines.append('    ' * self.indent + line if line else '')

    def cleanup(self, keep=None, null=()):
        for name in self.owned:
            if name in self.live and name != keep and name not in null:
                if name in self.releases:
                    self.emit(self.releases[name].format(name))
                else:
                    self.emit(f'Py_XDECREF({name});')

    def release_dead(self, used):
        """Release the loop variables not in *used* (the names used from
        here on): the reference is dropped right after its last use."""
        for name in self.loop_vars:
            if name in self.live and name not in used:
                self.emit(f'Py_DECREF({name});')
                self.live.discard(name)

    def error_exit(self, null=()):
        self.cleanup(null=null)
        self.emit('return NULL;')

    def error_check(self, name, ctype, convention):
        self.emit(f'if ({self.error_condition(name, ctype, convention)}) {{')
        self.indent += 1
        self.error_exit(null={name})
        self.indent -= 1
        self.emit('}')

    # -- declarations ------------------------------------------------------

    def ctype_of(self, name):
        if name in self.params:
            return self.params[name]
        if name in self.locals:
            return self.locals[name]
        return None

    def declare(self, target, ctype, node, release=None):
        name = target.id
        if name in self.params:
            raise SpecError(node, f'{name!r} is a parameter')
        if name in self.locals:
            # Assigned again (e.g. in both branches of an if): assign()
            # checks that it holds no reference then.
            if self.locals[name] != ctype:
                raise SpecError(node, f'{name!r} changes type')
            return
        self.locals[name] = ctype
        if ctype == OBJECT or release is not None:
            self.owned.append(name)
        if release is not None:
            self.releases[name] = release

    def collect_locals(self, stmts):
        """Declare every local up front so exits can release all of them."""
        for stmt in stmts:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Assign):
                    escape = escape_of(node.value.func) if isinstance(
                        node.value, ast.Call) else None
                    self.declare(node.targets[0], self.call_ctype(node.value),
                                 node, getattr(escape, 'release', None))
                elif isinstance(node, ast.NamedExpr):
                    self.declare(node.target, self.call_ctype(node.value),
                                 node)
                elif isinstance(node, ast.For):
                    if not isinstance(node.target, ast.Name):
                        raise SpecError(node, 'the loop variable must be a '
                                        'name')
                    self.declare(node.target, OBJECT, node)

    def declarations(self):
        out = []
        for name, ctype in self.locals.items():
            if ctype == OBJECT:
                out.append(f'    PyObject *{name} = NULL;')
            else:
                out.append(f'    {c_decl(ctype, name)};')
        return out

    @staticmethod
    def escape_ctype(escape):
        if escape.returns == 'object':
            return OBJECT
        return escape.returns

    # -- calls -------------------------------------------------------------

    def call_ctype(self, call):
        if not isinstance(call, ast.Call):
            raise SpecError(call, 'only call results can be assigned')
        escape = escape_of(call.func)
        if isinstance(escape, Escape):
            return self.escape_ctype(escape)
        return OBJECT

    def lower_call(self, call, target=None):
        """Return (C expression, C type, error convention).

        *target*: the local assigned, for an escape that initializes it in
        place (then the expression is an int status)."""
        special = partial_eval.specialization_of(self.spec, call)
        if special is not None:
            self.generator.use(special.name)
            args = ', '.join(self.lower_value(a) for a in call.args)
            return f'{special.name}({args})', OBJECT, ERR_NULL
        escape = escape_of(call.func)
        if isinstance(escape, Escape):
            fields = {}
            for i, arg in enumerate(call.args):
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    fields[f'id{i}'] = arg.value
                    fields[str(i)] = c_string(arg.value)
                else:
                    fields[str(i)] = self.lower_value(arg)
            if escape.initializes:
                if target is None:
                    raise SpecError(call, f'the result of '
                                    f'{ast.unparse(call.func)} must be '
                                    'assigned to a local')
                fields['target'] = target
            # The marks of the partial evaluator: cheaper lowerings that
            # cannot fail (None: no error convention).
            template, error = escape.template, escape.error
            exact = getattr(call, 'pyspec_exact', None)
            if exact is not None:
                template, error = escape.exact[exact], None
            elif getattr(call, 'pyspec_fast', False):
                template, error = escape.fast.template, None
            elif getattr(call, 'pyspec_unchecked', False):
                template, error = escape.unchecked, None
            expr = template.format(
                *[fields[str(i)] for i in range(len(call.args))],
                **{k: v for k, v in fields.items() if not k.isdigit()})
            return expr, self.escape_ctype(escape), error
        target = self.spec.call_target(call.func)
        if target is not None:
            args = ', '.join(self.lower_value(a) for a in call.args)
            return (f'{self.generator.c_name(target)}({args})',
                    OBJECT, ERR_NULL)
        if isinstance(call.func, ast.Name):
            name = call.func.id
            if name == 'iter' and len(call.args) == 1:
                return (f'PyObject_GetIter({self.lower_value(call.args[0])})',
                        OBJECT, ERR_NULL)
            if self.ctype_of(name) == OBJECT and not call.args:
                return f'_PyObject_CallNoArgs({name})', OBJECT, ERR_NULL
            if self.ctype_of(name) in (OBJECT, TYPE) and len(call.args) == 1:
                callable_ = name if self.ctype_of(name) == OBJECT else (
                    f'(PyObject *){name}')
                return (f'PyObject_CallOneArg({callable_}, '
                        f'{self.lower_value(call.args[0])})', OBJECT, ERR_NULL)
        raise SpecError(call, f'unsupported call {ast.unparse(call)}')

    @staticmethod
    def error_condition(var, ctype, convention):
        if convention == ERR_NULL:
            return f'{var} == NULL'
        if convention == ERR_NULL_OR_MISSING:
            return f'{var} == NULL && PyErr_Occurred()'
        if convention == ERR_MINUS1:
            return f'{var} == -1 && PyErr_Occurred()'
        if convention == ERR_NEGATIVE:
            return f'{var} < 0'
        raise AssertionError(convention)

    # -- expressions -------------------------------------------------------

    def lower_value(self, node):
        """A non-raising C expression used as an argument or operand."""
        match node:
            case ast.Name('NULL' | 'None'):
                return 'NULL'
            case ast.Name(id) if id in self.known_null:
                return 'NULL'
            case ast.Name(id) if self.ctype_of(id) is not None:
                return id
            case ast.Name(id) if id in TYPE_OBJECTS:
                return TYPE_OBJECTS[id]
            case ast.Name(id) if (
                    isinstance(getattr(builtins, id, None), type)
                    and issubclass(getattr(builtins, id), BaseException)):
                return f'PyExc_{id}'
            case ast.Constant(bool() as value):
                return '1' if value else '0'
            case ast.Constant(int() as value):
                return str(value)
        raise SpecError(node, f'unsupported value {ast.unparse(node)}')

    def lower_condition(self, node):
        match node:
            case ast.UnaryOp(op=ast.Not(), operand=operand):
                return c_not(self.lower_condition(operand))
            case ast.BoolOp(op=op, values=values):
                joiner = ' && ' if isinstance(op, ast.And) else ' || '
                parts = [self.lower_condition(v) for v in values]
                return joiner.join(p if c_not(p) == f'!{p}' else f'({p})'
                                   for p in parts)
            case ast.Compare(left=left, ops=[ast.Is() | ast.IsNot() as op],
                             comparators=[ast.Name('NULL')]):
                equal = '!=' if isinstance(op, ast.IsNot) else '=='
                if isinstance(left, ast.NamedExpr):
                    left = left.target
                return f'{self.lower_value(left)} {equal} NULL'
            case ast.Compare(left=ast.Name(name),
                             ops=[ast.Is() | ast.IsNot() as op],
                             comparators=[ast.Name(partial_eval.FALLBACK)]):
                equal = '!=' if isinstance(op, ast.IsNot) else '=='
                return f'{name} {equal} Py_None'
            case ast.Call() if partial_eval.fast_guard(node):
                name, item = partial_eval.fast_guard(node)
                fast = getattr(runtime.C, name).fast
                obj = self.lower_value(ast.Name(item))
                guard = fast.guard.format(obj)
                if getattr(node, 'pyspec_item_type', None) is not None:
                    return guard
                checks = ' || '.join(f'{TYPE_CHECK_EXACT[tp.__name__]}({obj})'
                                     for tp in fast.types)
                if len(fast.types) > 1:
                    checks = f'({checks})'
                return f'{checks} && {guard}'
            case ast.Compare(left=ast.Call(func=ast.Name('type'), args=[obj]),
                             ops=[ast.Is() | ast.IsNot() as op],
                             comparators=[ast.Name(cls)]) \
                    if cls in TYPE_CHECK_EXACT:
                check = f'{TYPE_CHECK_EXACT[cls]}({self.lower_value(obj)})'
                return f'!{check}' if isinstance(op, ast.IsNot) else check
            case ast.Compare(left=ast.Name(name),
                             ops=[ast.Is() | ast.IsNot() as op],
                             comparators=[ast.Name(cls)]) \
                    if self.ctype_of(name) == TYPE and cls in TYPE_OBJECTS:
                equal = '!=' if isinstance(op, ast.IsNot) else '=='
                return f'{name} {equal} {TYPE_OBJECTS[cls]}'
            case ast.Call(func=ast.Name('isinstance'),
                          args=[obj, ast.Name(cls)]) if cls in TYPE_CHECK:
                return f'{TYPE_CHECK[cls]}({self.lower_value(obj)})'
            case ast.Call(func=ast.Name('hasattr'),
                          args=[ast.Call(func=ast.Name('type'), args=[obj]),
                                ast.Constant(str() as name)]) \
                    if name in SLOT_CHECK:
                return SLOT_CHECK[name].format(self.lower_value(obj))
            case ast.Compare(left=left, ops=[op], comparators=[right]) \
                    if type(op) in COMPARE_OPS:
                return (f'{self.lower_value(left)} {COMPARE_OPS[type(op)]} '
                        f'{self.lower_value(right)}')
        raise SpecError(node, f'unsupported condition {ast.unparse(node)}')

    def hoist_named(self, node):
        """Emit the assignment of a walrus that leads an if condition."""
        if (isinstance(node, ast.Compare)
                and isinstance(node.left, ast.NamedExpr)):
            named = node.left
            self.assign(named.target, named.value, named)
        for child in ast.walk(node):
            if isinstance(child, ast.NamedExpr) and (
                    not isinstance(node, ast.Compare)
                    or child is not node.left):
                raise SpecError(child,
                                'walrus only as the left operand of "is"')

    # -- statements --------------------------------------------------------

    def assign(self, target, value, node, check=True, later=None):
        """*later*: the names used after this statement (see
        statements()), to release the loop variables used last here."""
        name = target.id
        if name in self.live:
            raise SpecError(node, f'{name!r} is assigned again while it '
                            'holds a reference')
        expr, ctype, convention = self.lower_call(value, target=name)
        if self.locals.get(name) != ctype:
            raise SpecError(node, f'{name!r} changes type')
        escape = escape_of(value.func)
        if isinstance(escape, Escape) and escape.initializes:
            if not check:
                raise SpecError(node, 'cannot initialize a C local here')
            self.emit(f'if ({expr} < 0) {{')
            self.indent += 1
            self.error_exit()
            self.indent -= 1
            self.emit('}')
            if name in self.releases:
                self.live.add(name)
            return name, ctype, convention
        self.emit(f'{name} = {expr};')
        if ctype == OBJECT:
            self.live.add(name)
        if later is not None:
            self.release_dead(later)
        if check and convention is not None:
            self.error_check(name, ctype, convention)
        return name, ctype, convention

    def call_statement(self, call, node, later):
        """``C.<escape>(...)`` as a statement: an int status."""
        escape = escape_of(call.func)
        if not isinstance(escape, Escape) or escape.returns != 'int':
            raise SpecError(node, 'only an escape returning an int status '
                            'can be called as a statement')
        expr, _, convention = self.lower_call(call)
        if convention is None:
            self.emit(f'{expr};')
        elif convention != ERR_NEGATIVE:
            raise SpecError(node, 'a status must be negative on error')
        else:
            self.emit(f'if ({expr} < 0) {{')
            self.indent += 1
            self.error_exit()
            self.indent -= 1
            self.emit('}')
        self.release_dead(later)

    def statements(self, stmts, later=frozenset()):
        """*later*: the names used after *stmts*.  Loop variables no
        longer used are released before each statement, and at the end."""
        uses = [loaded_names(stmt) for stmt in stmts]
        for i, stmt in enumerate(stmts):
            rest = set(later).union(*uses[i + 1:])
            self.release_dead(rest | uses[i])
            self.statement(stmt, rest)
        if not partial_eval.terminates(stmts):
            self.release_dead(later)

    def statement(self, stmt, later=frozenset()):
        match stmt:
            case ast.Pass():
                pass
            case ast.Expr(ast.Constant(str())):
                pass                                    # docstring
            case ast.If(test=test, body=body, orelse=orelse):
                self.hoist_named(test)
                null_in_body, null_in_else = self.null_refinement(test)
                self.emit(f'if ({self.lower_condition(test)}) {{')
                branches = [self.block(body, null=null_in_body, later=later)]
                self.emit('}')
                dying = [name for name in self.loop_vars
                         if name in self.live and name not in later]
                if orelse or dying:
                    self.lines.pop()
                    self.emit('}')
                    self.emit('else {')
                    branches.append(self.block(orelse, null=null_in_else,
                                               later=later))
                    self.emit('}')
                else:
                    branches.append(self.live - null_in_else)
                self.join(branches)
            case ast.Assign(targets=[ast.Name() as target], value=value):
                self.assign(target, value, stmt, later=later)
            case ast.Expr(ast.Call() as call):
                self.call_statement(call, stmt, later)
            case ast.For(target=ast.Name(item), iter=ast.Name() as iterable,
                         body=body, orelse=[]):
                self.for_(stmt, item, iterable, body, later)
            case ast.Return(value=value):
                self.return_(value, stmt)
                self.live = set()
            case ast.Raise(exc=ast.Call(func=ast.Attribute() as func,
                                        args=[])):
                escape = escape_of(func)
                if not isinstance(escape, RaiseEscape):
                    raise SpecError(stmt, 'raise needs a C raise escape')
                self.emit(escape.template)
                self.error_exit()
                self.live = set()
            case ast.Raise(exc=ast.Call(func=ast.Name(exc), args=[message])):
                self.raise_(exc, message, stmt)
                self.live = set()
            case ast.Try(body=[ast.Assign(targets=[ast.Name() as target],
                                          value=value)],
                         handlers=handlers, orelse=orelse, finalbody=[]):
                self.try_(target, value, handlers, orelse, stmt)
            case ast.With(items=[ast.withitem(
                    context_expr=ast.Call(func=func, args=[obj]),
                    optional_vars=None)], body=body):
                self.with_(func, obj, body, stmt)
            case _:
                raise SpecError(stmt,
                                f'unsupported statement {ast.unparse(stmt)}')

    def block(self, stmts, null=(), later=frozenset()):
        """Emit a nested block; return its live set, or None if it exits."""
        saved = self.live
        self.live = saved - set(null)
        self.indent += 1
        self.statements(stmts, later)
        self.indent -= 1
        live = None if partial_eval.terminates(stmts) else self.live
        self.live = saved
        return live

    def join(self, branches):
        """Continue after branches; None marks a branch that exits."""
        falling = [live for live in branches if live is not None]
        self.live = set().union(*falling) if falling else set()

    @staticmethod
    def null_refinement(test):
        """Names known NULL in the (body, else) of ``if test``."""
        match test:
            case ast.Compare(left=left, ops=[ast.Is() | ast.IsNot() as op],
                             comparators=[ast.Name('NULL' | 'FALLBACK')]):
                # Py_None as FALLBACK is not a reference either.
                if isinstance(left, ast.NamedExpr):
                    left = left.target
                if isinstance(left, ast.Name):
                    if isinstance(op, ast.IsNot):
                        return set(), {left.id}
                    return {left.id}, set()
        return set(), set()

    def return_(self, value, node):
        match value:
            case ast.Name(partial_eval.FALLBACK):
                self.cleanup()
                self.emit('return Py_None;')
            case ast.Name(id) if id in self.params:
                self.cleanup()
                self.emit(f'return Py_NewRef({id});')
            case ast.Name(id) if self.locals.get(id) == OBJECT:
                self.cleanup(keep=id)
                self.emit(f'return {id};')
            case ast.Constant() | ast.Tuple():
                key = repr(ast.literal_eval(value))
                if key not in CONSTANT_OBJECTS:
                    raise SpecError(node, f'no Py_GetConstant() for {key}')
                self.cleanup()
                self.emit(f'return Py_GetConstant({CONSTANT_OBJECTS[key]});')
            case ast.Call():
                expr, ctype, convention = self.lower_call(value)
                if ctype != OBJECT or convention != ERR_NULL:
                    raise SpecError(node, 'can only return a new reference')
                escape = escape_of(value.func)
                for index in getattr(escape, 'steals', ()):
                    # Taken over by the escape.
                    self.live.discard(value.args[index].id)
                if not self.live:
                    self.emit(f'return {expr};')
                    return
                self.emit('{')
                self.indent += 1
                self.emit(f'PyObject *_return_value = {expr};')
                self.cleanup()
                self.emit('return _return_value;')
                self.indent -= 1
                self.emit('}')
            case _:
                raise SpecError(node, f'unsupported return {ast.unparse(value)}')

    def raise_(self, exc, message, node):
        exc_c = self.lower_value(ast.Name(exc))
        match message:
            case ast.Constant(str() as text):
                self.emit(f'PyErr_SetString({exc_c}, {c_string(text)});')
            case ast.JoinedStr(values=values):
                fmt, args = [], []
                for part in values:
                    match part:
                        case ast.Constant(str() as text):
                            fmt.append(text.replace('%', '%%'))
                        case ast.FormattedValue(
                                value=ast.Call(
                                    func=ast.Name('fqname'),
                                    args=[ast.Call(func=ast.Name('type'),
                                                   args=[obj])]),
                                conversion=-1, format_spec=None):
                            fmt.append('%T')
                            args.append(self.lower_value(obj))
                        case ast.FormattedValue(
                                value=ast.Call(
                                    func=ast.Name('tp_name'),
                                    args=[ast.Call(func=ast.Name('type'),
                                                   args=[obj])]),
                                conversion=-1, format_spec=None):
                            fmt.append('%.200s')
                            args.append(
                                f'Py_TYPE({self.lower_value(obj)})->tp_name')
                        case _:
                            raise SpecError(node, 'unsupported f-string part '
                                            f'{ast.unparse(part)}')
                call_args = ', '.join([exc_c, c_string(''.join(fmt)), *args])
                self.emit(f'PyErr_Format({call_args});')
            case _:
                raise SpecError(node, 'raise needs a str or f-string message')
        self.error_exit()

    def try_(self, target, value, handlers, orelse, node):
        name, ctype, convention = self.assign(target, value, node, check=False)
        if convention is None:
            raise SpecError(node, 'try around a call that cannot fail')
        matches = []
        for handler in handlers:
            if handler.name is not None:
                raise SpecError(handler, '"except E as name" is not supported')
            types = (handler.type.elts if isinstance(handler.type, ast.Tuple)
                     else [handler.type])
            matches.append(' || '.join(
                f'PyErr_ExceptionMatches({self.lower_value(t)})'
                for t in types))
        self.emit(f'if ({self.error_condition(name, ctype, convention)}) {{')
        self.indent += 1
        # In the error branch the target holds no reference.
        saved = self.live
        self.live = saved - {name}
        branches = []
        for i, (handler, match_expr) in enumerate(zip(handlers, matches)):
            keyword = 'if' if i == 0 else 'else if'
            self.emit(f'{keyword} ({match_expr}) {{')
            self.indent += 1
            self.emit('PyErr_Clear();')
            self.indent -= 1
            branches.append(self.block(handler.body))
            self.emit('}')
        self.emit('else {')
        self.indent += 1
        self.error_exit()
        self.indent -= 1
        self.emit('}')
        self.live = saved
        self.indent -= 1
        self.emit('}')
        if orelse:
            self.emit('else {')
            branches.append(self.block(orelse))
            self.emit('}')
        else:
            branches.append(set(saved))
        self.join(branches)

    def for_(self, stmt, item, iterable, body, later):
        """``for item in it:`` or, marked by the partial evaluator, an
        index loop over an exact list or tuple (see partial_eval.py)."""
        seq = self.lower_value(iterable)
        live_before = set(self.live)
        owned = True
        if getattr(stmt, 'pyspec_sequence', False):
            index = f'{item}_index'
            tp = stmt.pyspec_iterable
            count = f'{item}_count'
            if tp is tuple:
                # The tuple holds a reference to every item: borrowed.
                # Its size cannot change.
                owned = False
                self.emit(f'for (Py_ssize_t {index} = 0, {count} = '
                          f'PyTuple_GET_SIZE({seq}); {index} < {count}; '
                          f'{index}++) {{')
                self.indent += 1
                self.emit(f'{item} = PyTuple_GET_ITEM({seq}, {index});')
            elif tp is list and getattr(stmt, 'pyspec_python_free', False):
                # A snapshot (partial_eval.py): the list is locked and no
                # Python code runs, so the list cannot change and keeps
                # its items alive: borrowed, and the size and the items
                # are read once.
                owned = False
                items = f'{item}_items'
                self.emit(f'PyObject **{items} = _PyList_ITEMS({seq});')
                self.emit(f'for (Py_ssize_t {index} = 0, {count} = '
                          f'PyList_GET_SIZE({seq}); {index} < {count}; '
                          f'{index}++) {{')
                self.indent += 1
                self.emit(f'{item} = {items}[{index}];')
            elif tp is list:
                # What the list iterator does: the size is read again for
                # every item, since the loop body may change the list.
                self.emit(f'for (Py_ssize_t {index} = 0; ; {index}++) {{')
                self.indent += 1
                self.lines.append('#ifdef Py_GIL_DISABLED')
                self.emit(f'{item} = _PyList_GetItemRef((PyListObject *){seq}, '
                          f'{index});')
                self.lines.append('#else')
                self.emit(f'{item} = {index} < PyList_GET_SIZE({seq}) ? '
                          f'Py_NewRef(PyList_GET_ITEM({seq}, {index})) : NULL;')
                self.lines.append('#endif')
                self.emit(f'if ({item} == NULL) {{')
                self.emit('    break;')
                self.emit('}')
            else:
                raise SpecError(stmt, f'no index loop for {tp!r}')
        else:
            self.emit('for (;;) {')
            self.indent += 1
            self.emit(f'{item} = PyIter_Next({seq});')
            self.emit(f'if ({item} == NULL) {{')
            self.indent += 1
            self.emit('if (PyErr_Occurred()) {')
            self.indent += 1
            self.error_exit()
            self.indent -= 1
            self.emit('}')
            self.emit('break;')
            self.indent -= 1
            self.emit('}')
        if owned:
            self.live.add(item)
            self.loop_vars.append(item)
        # The names used by the next iterations stay alive.
        self.statements(body, (set(later) | loaded_names(stmt)) - {item})
        if owned:
            self.loop_vars.pop()
        if self.live != live_before:
            raise SpecError(stmt, 'a loop body must release what it '
                            'assigns: ' + ', '.join(sorted(
                                self.live ^ live_before)))
        self.indent -= 1
        self.emit('}')

    def with_(self, func, obj, body, node):
        context = escape_of(func)
        if not isinstance(context, ContextEscape):
            raise SpecError(node, 'with needs a C context escape')
        checks = []
        self.emit(context.begin.format(self.lower_value(obj)))
        for stmt in body:
            # Errors are checked after the end of the block, so the
            # block is always closed.
            if not (isinstance(stmt, ast.Assign)
                    and isinstance(stmt.targets[0], ast.Name)):
                raise SpecError(stmt, 'with bodies may only assign calls')
            checks.append(self.assign(stmt.targets[0], stmt.value, stmt,
                                      check=False))
        self.emit(context.end)
        for name, ctype, convention in checks:
            if convention is not None:
                self.error_check(name, ctype, convention)

    # -- whole function ----------------------------------------------------

    def function(self, c_name, stmts):
        self.collect_locals(stmts)
        self.statements(stmts)
        if not partial_eval.terminates(stmts):
            raise SpecError(stmts[-1] if stmts else None,
                            f'{c_name}: control reaches the end')
        params = ', '.join(c_decl(ctype, name)
                           for name, ctype in self.params.items()) or 'void'
        return [
            'PyObject *' if exported(c_name) else 'static PyObject *',
            f'{c_name}({params})',
            '{',
            *self.declarations(),
            *([''] if self.locals else []),
            *self.lines,
            '}',
        ]


def loaded_names(node):
    """The names read in *node* (a statement)."""
    return {child.id for child in ast.walk(node)
            if isinstance(child, ast.Name)
            and isinstance(child.ctx, ast.Load)}


def exported(name):
    return name.startswith(('Py', '_Py'))


def c_params(description):
    return [(p.name, p.ctype) for p in description.parameters]


def prototype(name, params):
    text = ', '.join(c_decl(ctype, n) for n, ctype in params) or 'void'
    return f'static PyObject *{name}({text});'


class Generator:
    """Generate the C for a spec.

    c_basenames maps the implemented spec methods ("bytes.__new__") to the
    C basename of their clinic function ("bytes_new").
    """

    def __init__(self, spec, c_basenames, self_ctypes=None):
        self.spec = spec
        self.c_basenames = c_basenames
        self.self_ctypes = self_ctypes or {}
        # The shared specializations the generated code calls, in order.
        self.specializations = []

    def use(self, name):
        """Emit specialization *name* (partial_eval.Specialization)."""
        if name not in self.specializations:
            self.specializations.append(name)

    def describe(self, name):
        try:
            cls_name, _, meth = name.rpartition('.')
            if cls_name and meth != '__new__':
                self.c_basename(name)       # used by a clinic block?
                return describe_method(self.spec, name,
                                       self.self_ctypes[name])
            return self.spec.describe(name)
        except frontend.SpecError as exc:
            raise SpecError(self.spec.functions[name], str(exc)) from None

    def c_basename(self, name):
        """C basename: the clinic one for a method, else the name."""
        if '.' not in name:
            return name
        try:
            return self.c_basenames[name]
        except KeyError:
            raise SpecError(self.spec.functions[name],
                            f'{name} has a body, but no clinic block in '
                            'the C file uses it') from None

    def c_name(self, name):
        """C name of spec function *name*: NAME_impl() for a method."""
        if '.' in name:
            return f'{self.c_basename(name)}_impl'
        return name

    def generate(self, spec_path):
        out = [
            '/*[pyspec]',
            f'Generated by Argument Clinic from {spec_path}.',
            'Do not edit; edit the spec and run "make clinic".',
            '[pyspec]*/',
            '',
        ]
        names = self.spec.implemented_functions()
        descriptions = [self.describe(name) for name in names]
        for description in descriptions:
            name = self.c_name(description.name)
            if not exported(name):
                out.append(prototype(name, c_params(description)))
        prototypes = len(out)
        out.append('')

        for description in descriptions:
            # Nothing is known about the arguments; the evaluator still
            # specializes loops (see partial_eval.py), but keeps calls
            # of other spec functions as calls.
            body = partial_eval.specialize(self.spec, description.name, {},
                                           inline=False)
            emitter = FunctionEmitter(self, c_params(description))
            out += emitter.function(self.c_name(description.name), body)
            out.append('')

        for description in descriptions:
            if description.new_type is not None:
                out += self.generate_arities(description)
        # The call table of the tier-2 optimizer: see call_table.py.
        out += call_table.generate(self, descriptions)
        # The specializations, which may use others.
        done = 0
        while done < len(self.specializations):
            special = partial_eval.specialization(
                self.spec, self.specializations[done])
            done += 1
            params = self.specialization_params(special)
            out[prototypes:prototypes] = [prototype(special.name, params)]
            prototypes += 1
            out += self.generate_specialization(special, params)
        return '\n'.join(out)

    def specialization_params(self, special):
        ctypes = dict(c_params(self.describe(special.callee)))
        return [(p, ctypes[p]) for p in special.params]

    def generate_specialization(self, special, params):
        facts = ', '.join(
            f'{p} of exact type {fact.__name__}' if isinstance(fact, type)
            else f'{p} = iter({fact.source})'
            for p, fact in special.env.items()
            if isinstance(fact, (type, partial_eval.IterOf)))
        what = f'{special.callee}() for {facts}'
        if special.lock is not None:
            what += (f', the snapshot: called in the critical section of '
                     f'{special.lock}, runs no Python code; FALLBACK '
                     '(Py_None) when that could run Python code')
        code = ast.unparse(ast.Module(special.body, []))
        emitter = FunctionEmitter(self, params)
        return [
            f'/* {what}:',
            *[' * ' + line if line else ' *'
              for line in code.replace('*/', '* /').splitlines()],
            ' */',
            *emitter.function(special.name, special.body),
            '',
        ]

    def generate_arities(self, description):
        """NAME_nargsN() for each allowed N: the __new__ spec partially
        evaluated for exactly its class and a call with N positional
        arguments; the rest are NULL.  Argument Clinic declares them and
        calls them from the vectorcall with converted values."""
        cls, *params = description.parameters
        required = sum(not p.optional for p in params)
        type_value = getattr(builtins, description.new_type)
        basename = self.c_basename(description.name)
        out = []
        for nargs in range(required, len(params) + 1):
            given, missing = params[:nargs], params[nargs:]
            env = {cls.name: Value(type_value)}
            env |= {p.name: NOTNULL for p in given}
            env |= {p.name: NULL for p in missing}
            residual = partial_eval.specialize(self.spec, description.name,
                                               env)
            emitter = FunctionEmitter(self,
                                      [(p.name, p.ctype) for p in given],
                                      known_null=[p.name for p in missing])
            out += [f'/* {basename}() for exactly '
                    f'{description.new_type} with {nargs} positional '
                    'argument(s):',
                    *[' * ' + line if line else ' *'
                      for line in ast.unparse(ast.Module(residual, []))
                      .replace('*/', '* /').splitlines()],
                    ' */']
            out += emitter.function(f'{basename}_nargs{nargs}', residual)
            out.append('')
        return out


def describe_method(spec, name, self_ctype):
    """The C signature (frontend.SpecFunction) of implemented spec method
    *name*, other than __new__: a method or class method whose first
    parameter is clinic's implicit self (or class) parameter, of C type
    *self_ctype* (from the clinic class, e.g. "PyBytesObject *").

    The other parameters follow the rules of frontend.Spec.describe().
    (Kept here while frontend.py is being changed by another workstream;
    it belongs in Spec.describe().)
    """
    node = spec.functions[name]
    where = f"{spec.where(node)}: {name}()"
    args = node.args
    for other in (args.vararg, *args.kwonlyargs, args.kwarg):
        if other is not None:
            raise frontend.SpecError(f"{where}: a spec needs positional "
                                     f"parameters only; {other.arg!r} is "
                                     "not")
    positional = args.posonlyargs + args.args
    if not positional or positional[0].annotation is not None:
        raise frontend.SpecError(f"{where}: the first parameter must be "
                                 "the unannotated self (or class)")
    first_optional = len(positional) - len(args.defaults)
    parameters = [frontend.SpecParameter(positional[0].arg, self_ctype,
                                         False)]
    for i, arg in enumerate(positional[1:], 1):
        match arg.annotation:
            case ast.Name(conv) | ast.Call(func=ast.Name(conv)) \
                    if conv in frontend.SPEC_CTYPES:
                ctype = frontend.SPEC_CTYPES[conv]
            case _:
                raise frontend.SpecError(
                    f"{where}: parameter {arg.arg!r} needs an annotation "
                    f"from {sorted(frontend.SPEC_CTYPES)}")
        optional = i >= first_optional
        if optional:
            default = args.defaults[i - first_optional]
            if not (isinstance(default, ast.Name) and default.id == 'NULL'):
                raise frontend.SpecError(f"{where}: parameter {arg.arg!r} "
                                         "may only default to NULL")
        parameters.append(frontend.SpecParameter(arg.arg, ctype, optional))
    return frontend.SpecFunction(name, spec.filename, node.lineno,
                                 parameters)


def generate(spec: frontend.Spec, spec_path: str,
             c_basenames: dict[str, str],
             self_ctypes: dict[str, str] | None = None) -> str:
    """C for the implemented functions of *spec*, a frontend.Spec.

    *spec_path* is only named in the header comment.  *self_ctypes* maps
    the implemented spec methods other than __new__ to the C type of their
    self (or class) parameter.
    """
    text: str = Generator(spec, c_basenames, self_ctypes).generate(spec_path)
    return text

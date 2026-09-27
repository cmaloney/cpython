"""Generate C from the implemented functions of a pyspec file.

Argument Clinic calls generate() after processing a C file with a spec
and writes the result next to its other output
(Objects/clinic/bytesobject_pyspec.c.h for Objects/bytesobject.c).

Every implemented spec function becomes a C function:
  * a method of a spec class implements the clinic function of that name.
    For a method or class method (``bytes.__bytes__``) it becomes the
    NAME_impl() that clinic's parsing code calls; the first parameter is
    clinic's self (or class) parameter.  ``bytes.__new__`` (C basename
    bytes_new) becomes bytes_new_impl() (Argument Clinic declares it and
    no longer expects a hand-written body), plus bytes_new_nargsN() for
    each positional argument count N -- the function partially evaluated
    for exactly the class and N arguments, called by the clinic generated
    vectorcall; bytes_new_impl() calls one where the rest of its body is
    that function;
  * a top-level function becomes the C function of the same name: names
    starting with Py or _Py are defined non-static (their public or
    internal header declares them); everything else is static.

Functions whose body is only a docstring and/or ``...`` (stubs,
frontend.is_stub()) and @c_implemented functions are C written by hand:
they are never lowered to C, only called.

For a __new__ implemented by the spec, call_table.py then adds
type-specialized variants of NAME_nargs1() and the call table the tier-2
optimizer reads (Include/internal/pycore_pyspec.h).  Last come the
shared specializations the code calls (partial_eval.Specialization),
e.g. bytes_from_iterator_list().

The accepted Python subset is small on purpose; anything else is an error.

Statements:
  if/else, return, raise E("...") / raise E(f"..."), raise f() (f a C
  function that sets the exception), pass,
  x = <call>, f(...) (a C function returning void or an int status),
  try: x = <call> / except E: ... / else: ...,
  try: ... / finally: <calls> (the finally calls run at every exit),
  for item in it: ... (it = iter(x); lowered to PyIter_Next() calls, or
  to an index loop over x when the partial evaluator knows x is an exact
  list or tuple, see partial_eval.py)
Conditions:
  x is [not] NULL, type(x) is K, cls is [not] K, isinstance(x, K),
  hasattr(type(x), "__dunder__"), (v := f(...)) is [not] NULL,
  f(...) (a C function that cannot fail), integer comparisons,
  and/or/not
Calls (result is a new reference, or the C type of a C function):
  f(...) for a hand-written C function f (@c_implemented, or ``...``),
  iter(x), len(x) of an exact list or tuple, f() for an object
  variable f, f(x) for an object or type variable f (e.g. cls(result)),
  <spec function>(...), T.<spec method>(...)

A call of a hand-written C function f is f(args) in C.  The C types of
its parameters and result are its annotations (frontend.c_signature()):
a str constant is ``&_Py_ID(...)`` for an object parameter and a C
string for a ``str`` one, and a pointer of another C type is cast.  Its
error check comes from its facts for the call (facts.py, marked on the
call by the partial evaluator): none if it cannot raise; else NULL for an
object (NULL and an exception set when it may return NULL, an absent
result), -1 and an exception set for a Py_ssize_t, a negative value for
an int.  A function whose result is a C struct initializes the local
assigned in place, ``f(&x, args)``, which returns 0 or -1 with an
exception set; that local is passed by address.

The partial evaluator adds (see partial_eval.py): calls of shared
specializations, the marks of the calls, and for snapshots, ``return
FALLBACK`` (Py_None, never a result: the caller restarts),
``x is [not] FALLBACK`` and ``with critical_section(x):``.

Reference ownership: parameters are borrowed; every object local is a new
reference, declared NULL at the top and released with Py_XDECREF at every
exit except the one returning it; it may be assigned again only where it
holds no reference (e.g. in the other branch of an if).  A loop variable
is a new reference, released right after its last use in the loop body;
it is borrowed for a tuple item (the tuple keeps it alive) and in a
snapshot, where no Python code runs (the list, locked, keeps it alive):
"borrowed until Python code may run".  A C struct local (a buffer) is
released by the ``finally`` clause the spec writes around its use.
"""

import ast
import builtins

from . import builtin_types, call_table, facts, frontend, partial_eval
from .partial_eval import NOTNULL, NULL, Value

OBJECT = 'PyObject *'
SSIZE = 'Py_ssize_t'
TYPE = frontend.TYPE_CTYPE
TYPE_OBJECTS = frontend.TYPE_OBJECTS

# Error conventions of calls.
ERR_NULL = 'NULL'                # NULL means an exception is set
ERR_NULL_OR_MISSING = 'MISSING'  # NULL without an exception means "absent"
ERR_MINUS1 = 'MINUS1'            # -1 with an exception set
ERR_NEGATIVE = 'NEGATIVE'        # a negative int: an exception is set

SLOT_CHECK = {
    '__index__': '_PyIndex_Check({0})',
    '__buffer__': 'PyObject_CheckBuffer({0})',
}


def type_check(name, exact):
    """The C check of builtin type *name* (exactly with *exact*), or
    None."""
    row = builtin_types.TABLE.get(builtin_types.by_name(name))
    if row is None:
        return None
    return row.check_exact if exact else row.check

COMPARE_OPS = {ast.Lt: '<', ast.LtE: '<=', ast.Gt: '>', ast.GtE: '>=',
               ast.Eq: '==', ast.NotEq: '!='}


def c_decl(ctype, name):
    return f'{ctype}{name}' if ctype.endswith('*') else f'{ctype} {name}'


def _atomic(expr):
    """Whether C expression *expr* is a name or a call: f(...)."""
    head, paren, rest = expr.partition('(')
    if not paren:
        return head.replace('_', '').isalnum()
    depth = 1
    for i, ch in enumerate(rest):
        depth += {'(': 1, ')': -1}.get(ch, 0)
        if depth == 0:
            return i == len(rest) - 1 and head.replace('_', '').isalnum()
    return False


def c_not(expr):
    return f'!{expr}' if _atomic(expr) else f'!({expr})'


class SpecError(Exception):
    def __init__(self, node, message):
        self.lineno = getattr(node, 'lineno', None)
        self.message = message
        super().__init__(f'line {self.lineno or "?"}: {message}')


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


class FunctionEmitter:
    """Lower one list of spec statements to the body of a C function."""

    def __init__(self, generator, params, known_null=()):
        self.generator = generator
        self.spec = generator.spec
        self.analyzer = facts.analyzer(generator.spec)
        # name -> C type; parameters are borrowed references
        self.params = dict(params)
        self.known_null = set(known_null)
        self.locals = {}            # name -> C type
        # Object locals, in declaration order.
        self.owned = []
        self.live = set()           # owned locals that may hold a value
        self.loop_vars = []         # owned variables of enclosing loops
        # The finally clauses around the statement emitted, innermost last.
        self.finally_blocks = []
        self.lines = []
        self.indent = 1

    # -- output ------------------------------------------------------------

    def emit(self, line):
        self.lines.append('    ' * self.indent + line if line else '')

    def cleanup(self, keep=None, null=()):
        """Release what an exit releases: the finally clauses, then the
        object locals."""
        for block in reversed(self.finally_blocks):
            for stmt in block:
                if not (isinstance(stmt, ast.Expr)
                        and isinstance(stmt.value, ast.Call)):
                    raise SpecError(stmt, 'a finally clause only calls C '
                                    'functions that cannot fail')
                expr, _, convention = self.lower_call(stmt.value)
                if convention is not None:
                    raise SpecError(stmt, 'a finally clause only calls C '
                                    'functions that cannot fail')
                self.emit(f'{expr};')
        for name in self.owned:
            if name in self.live and name != keep and name not in null:
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

    def declare(self, target, ctype, node):
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
        if ctype == OBJECT:
            self.owned.append(name)

    def collect_locals(self, stmts):
        """Declare every local up front so exits can release all of them."""
        for stmt in stmts:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Assign):
                    self.declare(node.targets[0], self.call_ctype(node.value),
                                 node)
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

    # -- calls -------------------------------------------------------------

    def c_function(self, call):
        """(C name, parameter C types, return C type) of the hand-written
        C function *call* calls, or None."""
        found = self.spec.c_function(call)
        if found is None:
            return None
        spec, node = found
        if frontend.is_c_implemented(node):
            params, returns = frontend.c_signature(node)
            return node.name, [ctype for _, ctype in params], returns
        # A stub: objects in, an object out.
        return node.name, [OBJECT] * len(call.args), OBJECT

    def call_ctype(self, call):
        if not isinstance(call, ast.Call):
            raise SpecError(call, 'only call results can be assigned')
        function = self.c_function(call)
        if function is not None:
            return function[2]
        if getattr(call, 'pyspec_exact', None) is not None:
            return SSIZE        # len()
        return OBJECT

    def convention(self, call, returns):
        """The error convention of a call of a hand-written C function
        (see the module docstring)."""
        raises = getattr(call, 'pyspec_raises', None)
        null = getattr(call, 'pyspec_null', None)
        if raises is None:
            # Not marked by the partial evaluator: the facts for any
            # arguments.
            callee = self.analyzer.call_facts(call, {})
            raises, null = bool(callee.raises), callee.returns_null
        if frontend.is_struct(returns):
            return ERR_NEGATIVE
        if not raises or returns == 'void':
            return None
        if returns == OBJECT:
            return ERR_NULL_OR_MISSING if null else ERR_NULL
        if returns == 'int':
            return ERR_NEGATIVE
        return ERR_MINUS1

    def lower_arg(self, arg, ctype):
        """Argument *arg* of a C function parameter of type *ctype*."""
        match arg:
            case ast.Constant(str() as text) if ctype == OBJECT:
                return f'&_Py_ID({text})'
            case ast.Constant(str() as text):
                return c_string(text)
            case ast.Name(name) if frontend.is_struct(
                    self.ctype_of(name) or '*'):
                return f'&{name}'
        value = self.lower_value(arg)
        actual = self.ctype_of(arg.id) if isinstance(arg, ast.Name) else None
        if (actual and actual != ctype and actual.endswith('*')
                and ctype.endswith('*')):
            return f'({ctype}){value}'
        return value

    def lower_call(self, call, target=None):
        """Return (C expression, C type, error convention).

        *target*: the local assigned, for a C function that initializes
        it in place (then the expression is an int status)."""
        special = partial_eval.specialization_of(self.spec, call)
        if special is not None:
            self.generator.use(special.name)
            args = ', '.join(self.lower_value(a) for a in call.args)
            return f'{special.name}({args})', OBJECT, ERR_NULL
        c_function = getattr(call, 'pyspec_c_function', None)
        if c_function is not None:
            args = ', '.join(self.lower_value(a) for a in call.args)
            return f'{c_function}({args})', OBJECT, ERR_NULL
        function = self.c_function(call)
        if function is not None:
            name, params, returns = function
            if len(params) != len(call.args):
                raise SpecError(call, f'{name}() takes {len(params)} '
                                'arguments')
            args = [self.lower_arg(a, t) for a, t in zip(call.args, params)]
            if frontend.is_struct(returns):
                if target is None:
                    raise SpecError(call, f'the result of {name}() must '
                                    'be assigned to a local')
                args.insert(0, f'&{target}')
            return (f'{name}({", ".join(args)})', returns,
                    self.convention(call, returns))
        exact = getattr(call, 'pyspec_exact', None)
        if exact is not None:
            # len() of an exact list or tuple.
            size = builtin_types.TABLE[exact].size
            return f'{size}({self.lower_value(call.args[0])})', SSIZE, None
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
            case ast.Call() if self.c_function(node) is not None:
                expr, _, convention = self.lower_call(node)
                if convention is not None:
                    raise SpecError(node, 'a call in a condition cannot '
                                    f'fail: {ast.unparse(node)}')
                return expr
            case ast.Compare(left=ast.Call(func=ast.Name('type'), args=[obj]),
                             ops=[ast.Is() | ast.IsNot() as op],
                             comparators=[ast.Name(cls)]) \
                    if type_check(cls, True):
                check = f'{type_check(cls, True)}({self.lower_value(obj)})'
                return f'!{check}' if isinstance(op, ast.IsNot) else check
            case ast.Compare(left=ast.Name(name),
                             ops=[ast.Is() | ast.IsNot() as op],
                             comparators=[ast.Name(cls)]) \
                    if self.ctype_of(name) == TYPE and cls in TYPE_OBJECTS:
                equal = '!=' if isinstance(op, ast.IsNot) else '=='
                return f'{name} {equal} {TYPE_OBJECTS[cls]}'
            case ast.Call(func=ast.Name('isinstance'),
                          args=[obj, ast.Name(cls)]) if type_check(cls, False):
                return f'{type_check(cls, False)}({self.lower_value(obj)})'
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
        if frontend.is_struct(ctype):
            if not check:
                raise SpecError(node, 'cannot initialize a C local here')
            self.emit(f'if ({expr} < 0) {{')
            self.indent += 1
            self.error_exit()
            self.indent -= 1
            self.emit('}')
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
        """``f(...)`` as a statement: a C function returning void or an
        int status."""
        function = self.c_function(call)
        if function is None or function[2] not in ('void', 'int'):
            raise SpecError(node, 'only a C function returning void or an '
                            'int status can be called as a statement')
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
            case ast.Raise(exc=ast.Call() as call) \
                    if self.c_function(call) is not None:
                # A C function that sets the exception.
                expr, _, _ = self.lower_call(call)
                self.emit(f'{expr};')
                self.error_exit()
                self.live = set()
            case ast.Raise(exc=ast.Call(func=ast.Name(exc), args=[message])):
                self.raise_(exc, message, stmt)
                self.live = set()
            case ast.Try(body=[ast.Assign(targets=[ast.Name() as target],
                                          value=value)],
                         handlers=[_, *_] as handlers, orelse=orelse,
                         finalbody=[]):
                self.try_(target, value, handlers, orelse, stmt)
            case ast.Try(body=body, handlers=[], orelse=[],
                         finalbody=[_, *_] as finalbody):
                self.finally_blocks.append(finalbody)
                self.statements(body, later)
                self.finally_blocks.pop()
                if not partial_eval.terminates(body):
                    self.statements(finalbody, later)
            case ast.With(items=[ast.withitem(
                    context_expr=ast.Call(func=ast.Name('critical_section'),
                                          args=[obj]),
                    optional_vars=None)], body=body):
                self.with_(obj, body, stmt)
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
                constant = ast.literal_eval(value)
                name = builtin_types.constant(constant)
                if name is None:
                    raise SpecError(node, 'no Py_GetConstant() for '
                                    f'{constant!r}')
                self.cleanup()
                self.emit(f'return Py_GetConstant({name});')
            case ast.Call():
                expr, ctype, convention = self.lower_call(value)
                if ctype != OBJECT or convention not in (ERR_NULL, None):
                    raise SpecError(node, 'can only return a new reference')
                if not self.live and not self.finally_blocks:
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

    def with_(self, obj, body, node):
        """``with critical_section(x):``: the critical section of x (the
        partial evaluator writes it for snapshots)."""
        checks = []
        self.emit(f'Py_BEGIN_CRITICAL_SECTION({self.lower_value(obj)});')
        for stmt in body:
            # Errors are checked after the end of the block, so the
            # block is always closed.
            if not (isinstance(stmt, ast.Assign)
                    and isinstance(stmt.targets[0], ast.Name)):
                raise SpecError(stmt, 'with bodies may only assign calls')
            checks.append(self.assign(stmt.targets[0], stmt.value, stmt,
                                      check=False))
        self.emit('Py_END_CRITICAL_SECTION();')
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
                return self.spec.describe(name, self.self_ctypes[name])
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
            # of other spec functions as calls.  Where the rest of a
            # __new__ is an arity function, it is called.
            body = partial_eval.specialize(
                self.spec, description.name, {}, inline=False,
                arities=[(env, name, [p.name for p in given])
                         for env, name, given, _ in self.arities(description)])
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

    def arities(self, description):
        """(facts, C name, given, missing parameters) of the NAME_nargsN()
        functions of a __new__ (none for other functions)."""
        if description.new_type is None:
            return []
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
            out.append((env, f'{basename}_nargs{nargs}', given, missing))
        return out

    def generate_arities(self, description):
        """NAME_nargsN() for each allowed N: the __new__ spec partially
        evaluated for exactly its class and a call with N positional
        arguments; the rest are NULL.  Argument Clinic declares them and
        calls them from the vectorcall with converted values."""
        basename = self.c_basename(description.name)
        out = []
        for env, name, given, missing in self.arities(description):
            nargs = len(given)
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

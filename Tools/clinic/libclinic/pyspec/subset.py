"""The lowered subset of the spec language: the one place that says it.

(For contributors: "The spec language" and "The lowered subset" in
Objects/pyspec/README.rst.)

A spec may contain any Python.  Only part of it is *wired up*:

* a spec body that clinic generates as C (``Spec.implemented()``) is
  lowered: partially evaluated (partial_eval.py), then emitted (emit.py).
  Its signature and its statements must be in the lowered subset;
  lowered() lists what is not, and check_lowered() reports the first as
  "expressible, but not lowered to C yet", before any partial evaluation;
* the body of an ``@inline`` function is lowered into each of its
  callers: fast paths ``if <condition>: return <value>``, then
  ``return <value>``, with the conditions and values of the lowered
  subset; its signature is that of a native function (C types).
  check_inline() reports what is not;
* the Python reference of a native function (``@native``) is never
  lowered, not even in part, but read for facts (facts.py): its control
  flow is followed, and every effect (a call of a primitive or of a C
  function, ``return``, ``raise``) must be where facts.py follows it.
  analysed() lists what is not; facts.py then gives the function the
  worst facts (any result, may raise anything, may run Python code)
  instead of reading the reference;
* anything else (a stub, ``...``) is C about which nothing is known.

The checks are syntactic (with the names the spec defines): the emitter
still reports the uses it cannot lower, e.g. a local assigned objects of
two C types (SpecErrorKind.LOWERING).

The statements of the subset have one vocabulary, Kind (kind()): a
walker over them (Walker) has one method per kind, named by the value of
the kind.  The walkers are Lowered here, the facts analysis
(facts.Analyzer), the partial evaluator (partial_eval.Evaluator, and its
snapshot) and the emitter (emit.FunctionLowering).

To add a construct to the lowered subset: accept it here (the method of
Lowered for its kind of node: a statement method, condition(), value(),
call(), or signature(); a new kind of statement is a new Kind, with a
method in each walker), lower it in emit.py, give its facts in facts.py
if it has effects, evaluate it in partial_eval.py if the facts of a call
site decide it, and add a row to "The lowered subset" in README.rst and
a test to PyspecLanguageTest of Lib/test/test_clinic.py.
"""

from __future__ import annotations

import ast
import builtins
import enum
import weakref
from collections.abc import Callable
from typing import Generic, Protocol, TypeVar, cast

from libclinic.errors import SpecError, SpecErrorKind
from . import builtin_types

# One construct outside a subset: (node, what it is, for messages).
Unsupported = tuple[ast.AST, str]

# Converters (annotations) of the parameters of a lowered function, and
# the C type of the argument.
LOWERED_CTYPES = {
    'object': 'PyObject *',
    'str': 'const char *',
}

# The C types of the annotations of a @native or @inline function: these,
# and a string, which is the C type itself ('PyTypeObject *').
C_CTYPES = LOWERED_CTYPES | {'Py_ssize_t': 'Py_ssize_t', 'int': 'int',
                             'None': 'void'}

# The primitives of a Python reference (runtime.py): calls with effects.
PRIMITIVES = ('exact', 'unknown', 'calls', 'runs_python')

# Builtins a lowered body may call, by name: iter(x) is
# PyObject_GetIter(); len(x) of an exact list or tuple is read inline.
LOWERED_BUILTINS = ('iter', 'len')

# The clinic decorators a lowered method may not have.
NOT_LOWERED_DECORATORS = ('critical_section', 'staticmethod', 'getter',
                          'setter')

# The builtin types a condition may test (``type(x) is K``,
# ``isinstance(x, K)``): the rows of builtin_types.py with C checks.
TYPE_CHECKS = {tp.__name__: (row.check, row.check_exact)
               for tp, row in builtin_types.TABLE.items()}

# The dunders ``hasattr(type(x), "__dunder__")`` is lowered for.
HASATTR_SLOTS = ('__index__', '__buffer__')

COMPARE_OPS = (ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Eq, ast.NotEq)


def is_struct(ctype: str) -> bool:
    """Whether C type *ctype* (of c_signature()) is a C struct: neither a
    pointer nor a scalar."""
    return '*' not in ctype and ctype not in C_CTYPES.values() \
        and ctype.split()[-1] not in ('char', 'short', 'int', 'long')


def c_signature(node: ast.FunctionDef) -> tuple[list[tuple[str, str]], str]:
    """([(parameter, C type)], C return type) of a @native or
    @inline function: an annotation of C_CTYPES or a string (the C type); no
    return annotation is ``PyObject *``.  A return type that is neither
    a scalar nor a pointer is a C struct that the function initializes in
    place (see emit.py)."""
    def ctype(annotation: ast.expr | None, default: str | None) -> str:
        match annotation:
            case None if default is not None:
                return default
            case ast.Constant(str() as text):
                return text
            case ast.Name(name) if name in C_CTYPES:
                return C_CTYPES[name]
            case ast.Constant(None):
                return 'void'
        raise SpecError(f"{node.name}(): the annotations of a "
                        f"@native or @inline function are C types: "
                        f"{sorted(C_CTYPES)} or a string",
                        lineno=getattr(annotation, 'lineno', node.lineno))
    args = node.args.posonlyargs + node.args.args
    return ([(a.arg, ctype(a.annotation, None)) for a in args],
            ctype(node.returns, 'PyObject *'))


class Spec(Protocol):
    """What the checks read of a spec (frontend.Spec)."""
    functions: dict[str, ast.FunctionDef]

    def body(self, name: str) -> list[ast.stmt]: ...

    def c_function(self, call: ast.Call) -> object | None: ...

    def inline_function(self, call: ast.Call) -> object | None: ...

    def call_target(self, func: ast.expr) -> str | None: ...

    def error(self, node: ast.AST | None, message: str,
              kind: SpecErrorKind = ...) -> SpecError: ...


# -- the statements ----------------------------------------------------------

class Kind(enum.Enum):
    """The kinds of statements of the lowered subset, and of the residual
    code of the partial evaluator; the value is the name of the method of
    a Walker for the kind."""
    PASS = 'pass_'          # pass, a docstring
    IF = 'if_'
    ASSIGN = 'assign'       # x = <call>
    CALL = 'call_'          # f(...)
    RETURN = 'return_'
    RAISE = 'raise_'
    TRY = 'try_'            # try: x = <call> / except E: ... / else: ...
    FINALLY = 'finally_'    # try: ... / finally: <calls>
    FOR = 'for_'            # for item in it:
    WITH = 'with_'          # with critical_section(x): (residual code only)


def kind(stmt: ast.stmt) -> Kind | None:
    """The Kind of *stmt*, or None."""
    match stmt:
        case ast.Pass() | ast.Expr(ast.Constant(str())):
            return Kind.PASS
        case ast.If():
            return Kind.IF
        case ast.Assign(targets=[ast.Name()]):
            return Kind.ASSIGN
        case ast.Expr(ast.Call()):
            return Kind.CALL
        case ast.Return():
            return Kind.RETURN
        case ast.Raise():
            return Kind.RAISE
        case ast.Try(handlers=[_, *_]):
            return Kind.TRY
        case ast.Try():
            return Kind.FINALLY
        case ast.For():
            return Kind.FOR
        case ast.With():
            return Kind.WITH
    return None


A = TypeVar('A')
R = TypeVar('R')


class Walker(Generic[A, R]):
    """A pass over statements: statement() calls the method of the Kind
    of the statement, with *arg*, the state of the walk; other() is for
    a statement of no kind, and for a kind without a method."""

    def statement(self, stmt: ast.stmt, arg: A) -> R:
        found = kind(stmt)
        method = self.other if found is None else getattr(self, found.value)
        return cast(Callable[[ast.stmt, A], R], method)(stmt, arg)

    def other(self, stmt: ast.stmt, arg: A) -> R:
        raise NotImplementedError(type(stmt).__name__)

    def pass_(self, stmt: ast.stmt, arg: A) -> R:
        return self.other(stmt, arg)

    def if_(self, stmt: ast.If, arg: A) -> R:
        return self.other(stmt, arg)

    def assign(self, stmt: ast.Assign, arg: A) -> R:
        return self.other(stmt, arg)

    def call_(self, stmt: ast.Expr, arg: A) -> R:
        return self.other(stmt, arg)

    def return_(self, stmt: ast.Return, arg: A) -> R:
        return self.other(stmt, arg)

    def raise_(self, stmt: ast.Raise, arg: A) -> R:
        return self.other(stmt, arg)

    def try_(self, stmt: ast.Try, arg: A) -> R:
        return self.other(stmt, arg)

    def finally_(self, stmt: ast.Try, arg: A) -> R:
        return self.other(stmt, arg)

    def for_(self, stmt: ast.For, arg: A) -> R:
        return self.other(stmt, arg)

    def with_(self, stmt: ast.With, arg: A) -> R:
        return self.other(stmt, arg)


def blocks(stmt: ast.stmt) -> list[list[ast.stmt]]:
    """The blocks of statements nested in *stmt*."""
    out = [getattr(stmt, field) for field in ('body', 'orelse', 'finalbody')
           if isinstance(getattr(stmt, field, None), list)]
    return out + [handler.body for handler in getattr(stmt, 'handlers', ())]


def terminates(stmts: list[ast.stmt]) -> bool:
    """True if control never falls off the end of *stmts*."""
    if not stmts:
        return False
    last = stmts[-1]
    if isinstance(last, (ast.Return, ast.Raise)):
        return True
    if isinstance(last, ast.If):
        return terminates(last.body) and terminates(last.orelse)
    if isinstance(last, ast.Try) and not last.handlers:
        return terminates(last.body) or terminates(last.finalbody)
    return False


def loaded_names(stmts: list[ast.stmt]) -> set[str]:
    """The names read in *stmts*."""
    return {node.id for stmt in stmts for node in ast.walk(stmt)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}


def assigned_names(stmts: list[ast.stmt]) -> set[str]:
    """The names assigned in *stmts*."""
    return {node.id for stmt in stmts for node in ast.walk(stmt)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)}


def handler_names(handler: ast.ExceptHandler) -> list[str] | None:
    """The builtin exceptions ``except E:`` or ``except (E1, E2):``
    catches, or None if it is not in the subset."""
    types = (handler.type.elts if isinstance(handler.type, ast.Tuple)
             else [handler.type])
    names = [t.id for t in types if isinstance(t, ast.Name)]
    if types and len(names) == len(types) and all(map(_is_exception, names)):
        return names
    return None


def _is_exception(name: str) -> bool:
    value = getattr(builtins, name, None)
    return isinstance(value, type) and issubclass(value, BaseException)


def _text(node: ast.AST) -> str:
    text = ast.unparse(node)
    return text if len(text) <= 60 else text[:57] + '...'


class Lowered(Walker[None, None]):
    """The lowered subset: signatures, statements, conditions, values and
    calls that emit.py lowers to C."""

    def __init__(self, spec: Spec, name: str) -> None:
        self.spec = spec
        self.name = name
        self.node = spec.functions[name]
        self.found: list[Unsupported] = []
        args = self.node.args
        self.params = {a.arg for a in args.posonlyargs + args.args}
        self.locals = {n.id for n in ast.walk(self.node)
                       if isinstance(n, ast.Name)
                       and isinstance(n.ctx, ast.Store)}

    def unsupported(self, node: ast.AST, what: str) -> None:
        self.found.append((node, what))

    def check(self) -> list[Unsupported]:
        self.signature()
        self.statements(self.spec.body(self.name))
        return self.found

    # -- the signature -------------------------------------------------------

    def signature(self) -> None:
        node = self.node
        cls_name, _, meth = self.name.rpartition('.')
        for decorator in node.decorator_list:
            match decorator:
                case ast.Name(name) | ast.Call(func=ast.Name(name)) \
                        if name in NOT_LOWERED_DECORATORS:
                    self.unsupported(decorator, f'@{name}')
        if cls_name and meth == '__init__':
            self.unsupported(node, '__init__ (an int-returning initproc)')
        if cls_name and meth == '__new__' \
                and cls_name not in _type_objects():
            self.unsupported(node, f'__new__ of type {cls_name!r}, which '
                             'has no row in builtin_types.py (unknown type '
                             f'{cls_name!r}; known: '
                             f'{sorted(_type_objects())})')
        args = node.args
        if args.vararg:
            self.unsupported(args.vararg, f'*{args.vararg.arg}')
        for arg in args.kwonlyargs:
            self.unsupported(arg, f'keyword-only parameter {arg.arg!r}')
        if args.kwarg:
            self.unsupported(args.kwarg, f'**{args.kwarg.arg}')
        positional = args.posonlyargs + args.args
        defaults: list[ast.expr | None] = [None] * (
            len(positional) - len(args.defaults)) + list(args.defaults)
        for i, (arg, default) in enumerate(zip(positional, defaults)):
            if cls_name and i == 0:
                if arg.annotation is not None:
                    self.unsupported(arg, f'a converter on the self (or '
                                     f'class) parameter {arg.arg!r}')
                continue
            match arg.annotation:
                case ast.Name(conv) | ast.Call(func=ast.Name(conv)) \
                        if conv in LOWERED_CTYPES:
                    pass
                case None:
                    self.unsupported(arg, f'parameter {arg.arg!r} without '
                                     'a converter (lowered: '
                                     f'{sorted(LOWERED_CTYPES)})')
                case annotation:
                    self.unsupported(arg, f'parameter {arg.arg!r} with '
                                     f'converter {_text(annotation)} '
                                     '(lowered: '
                                     f'{sorted(LOWERED_CTYPES)})')
            if default is not None and not (isinstance(default, ast.Name)
                                            and default.id == 'NULL'):
                self.unsupported(default, f'default {_text(default)} of '
                                 f'parameter {arg.arg!r} (lowered: NULL)')
        if node.returns is not None and not (
                isinstance(node.returns, ast.Name)
                and node.returns.id == 'object'):
            what = 'return converter' if cls_name else 'return type'
            self.unsupported(node.returns, f'{what} {_text(node.returns)}')

    # -- statements ------------------------------------------------------------

    def statements(self, stmts: list[ast.stmt]) -> None:
        for stmt in stmts:
            self.statement(stmt, None)

    def other(self, stmt: ast.stmt, arg: None) -> None:
        self.unsupported(stmt, f'{_kind(stmt)} {_text(stmt)!r}')

    def pass_(self, stmt: ast.stmt, arg: None) -> None:
        pass

    def if_(self, stmt: ast.If, arg: None) -> None:
        self.condition(stmt.test)
        self.statements(stmt.body)
        self.statements(stmt.orelse)

    def assign(self, stmt: ast.Assign, arg: None) -> None:
        if isinstance(stmt.value, ast.Call):
            self.call(stmt.value)
        else:
            self.unsupported(stmt.value, f'assignment of {_text(stmt.value)} '
                             '(lowered: of a call)')

    def call_(self, stmt: ast.Expr, arg: None) -> None:
        call = stmt.value
        assert isinstance(call, ast.Call)
        if (self.spec.c_function(call) is not None
                or self.spec.inline_function(call) is not None):
            self.arguments(call)
        else:
            self.unsupported(call, f'call {_text(call)} as a statement '
                             '(lowered: of a C function)')

    def for_(self, stmt: ast.For, arg: None) -> None:
        match stmt:
            case ast.For(target=ast.Name(), iter=ast.Name(), orelse=[]):
                self.statements(stmt.body)
            case _:
                self.unsupported(stmt, 'this form of for loop (lowered: '
                                 '"for item in it:", no else)')

    def return_(self, stmt: ast.Return, arg: None) -> None:
        match stmt.value:
            case ast.Name(name) if name in self.params or name in self.locals:
                pass
            case ast.Constant() | ast.Tuple() as value:
                try:
                    ast.literal_eval(value)
                except ValueError:
                    self.unsupported(value, f'return of {_text(value)}')
            case ast.Call() as call:
                self.call(call)
            case value:
                self.unsupported(stmt, f'return of '
                                 f'{_text(value) if value else "nothing"}')

    def raise_(self, stmt: ast.Raise, arg: None) -> None:
        match stmt:
            case ast.Raise(exc=ast.Call() as call, cause=None) \
                    if self.spec.c_function(call) is not None:
                self.arguments(call)
            case ast.Raise(exc=ast.Call(func=ast.Name(exc), args=[message],
                                        keywords=[]),
                           cause=None) if _is_exception(exc):
                self.message(message)
            case _:
                self.unsupported(stmt, f'raise statement {_text(stmt)!r}')

    def try_(self, stmt: ast.Try, arg: None) -> None:
        match stmt:
            case ast.Try(body=[ast.Assign(targets=[ast.Name()],
                                          value=ast.Call() as call)],
                         finalbody=[]):
                self.call(call)
                for handler in stmt.handlers:
                    if handler_names(handler) is None:
                        self.unsupported(handler, 'except clause '
                                         f'{_text(handler.type or stmt)} '
                                         '(lowered: except E, except (E1, '
                                         'E2), builtin exceptions)')
                    if handler.name is not None:
                        self.unsupported(handler, f'except ... as '
                                         f'{handler.name}')
                    self.statements(handler.body)
                self.statements(stmt.orelse)
            case _:
                self.unsupported(stmt, 'this form of try statement')

    def finally_(self, stmt: ast.Try, arg: None) -> None:
        self.statements(stmt.body)
        for final in stmt.finalbody:
            match final:
                case ast.Expr(value=ast.Call() as call) \
                        if self.spec.c_function(call) is not None:
                    self.arguments(call)
                case _:
                    self.unsupported(final, f'{_text(final)} in a '
                                     'finally clause (lowered: '
                                     'calls of C functions)')

    def message(self, node: ast.expr) -> None:
        """The message of ``raise E(message)``: a str or an f-string of
        type names."""
        match node:
            case ast.Constant(str()):
                return
            case ast.JoinedStr(values=values):
                for part in values:
                    match part:
                        case ast.Constant(str()):
                            pass
                        case ast.FormattedValue(
                                value=ast.Call(
                                    func=ast.Name('fqname' | 'tp_name'),
                                    args=[ast.Call(func=ast.Name('type'),
                                                   args=[obj])]),
                                conversion=-1, format_spec=None):
                            self.value(obj)
                        case _:
                            self.unsupported(part, 'f-string part '
                                             f'{_text(part)} (lowered: '
                                             'fqname(type(x)), '
                                             'tp_name(type(x)))')
                return
        self.unsupported(node, f'exception message {_text(node)} (lowered: '
                         'a str or an f-string)')

    # -- conditions ------------------------------------------------------------

    def condition(self, node: ast.expr) -> None:
        match node:
            case ast.UnaryOp(op=ast.Not(), operand=operand):
                self.condition(operand)
            case ast.BoolOp(values=values):
                for value in values:
                    self.condition(value)
            case ast.Compare(left=ast.NamedExpr(target=ast.Name(),
                                                value=ast.Call() as call),
                             ops=[ast.Is() | ast.IsNot()],
                             comparators=[ast.Name('NULL')]):
                self.call(call)
            case ast.Compare(left=left, ops=[ast.Is() | ast.IsNot()],
                             comparators=[ast.Name('NULL')]):
                self.value(left)
            case ast.Compare(left=ast.Call(func=ast.Name('type'), args=[obj]),
                             ops=[ast.Is() | ast.IsNot()],
                             comparators=[ast.Name(cls)]) \
                    if TYPE_CHECKS.get(cls, (None, None))[1]:
                self.value(obj)
            case ast.Compare(left=ast.Name(name),
                             ops=[ast.Is() | ast.IsNot()],
                             comparators=[ast.Name(cls)]) \
                    if cls in _type_objects() and name in self.params:
                pass
            case ast.Call(func=ast.Name('isinstance'),
                          args=[obj, ast.Name(cls)], keywords=[]) \
                    if TYPE_CHECKS.get(cls, (None, None))[0]:
                self.value(obj)
            case ast.Call(func=ast.Name('hasattr'),
                          args=[ast.Call(func=ast.Name('type'), args=[obj]),
                                ast.Constant(str() as dunder)],
                          keywords=[]) if dunder in HASATTR_SLOTS:
                self.value(obj)
            case ast.Call() if self.spec.c_function(node) is not None:
                self.arguments(node)
            case ast.Compare(left=left, ops=[op], comparators=[right]) \
                    if isinstance(op, COMPARE_OPS):
                self.value(left)
                self.value(right)
            case _:
                self.unsupported(node, f'condition {_text(node)}')

    # -- values and calls ------------------------------------------------------

    def value(self, node: ast.expr) -> None:
        """An operand or an argument: a name, NULL, a type, an exception
        class, a bool or an int."""
        match node:
            case ast.Name(name) if (name in ('NULL', 'None')
                                    or name in self.params
                                    or name in self.locals
                                    or name in _type_objects()
                                    or _is_exception(name)):
                pass
            case ast.Constant(value=bool() | int()):
                pass
            case _:
                self.unsupported(node, f'value {_text(node)} (lowered: '
                                 'names, NULL, types, exceptions, bool '
                                 'and int constants)')

    def arguments(self, call: ast.Call, strings: bool = True) -> None:
        if call.keywords:
            self.unsupported(call, f'keyword arguments in {_text(call)}')
        for arg in call.args:
            if strings and isinstance(arg, ast.Constant) \
                    and isinstance(arg.value, str):
                continue        # a C string, or &_Py_ID() for an object
            self.value(arg)

    def call(self, call: ast.Call) -> None:
        """A call whose result is used: of a hand-written C function, of
        an @inline function, of another spec function (``f(...)``,
        ``T.meth(...)``), iter() or len(), or of a local object or type
        (``f()``, ``cls(x)``)."""
        func = call.func
        if (self.spec.c_function(call) is not None
                or self.spec.inline_function(call) is not None):
            self.arguments(call)
        elif self.spec.call_target(func) is not None:
            self.arguments(call, strings=False)
        elif (isinstance(func, ast.Name) and func.id in LOWERED_BUILTINS
                and len(call.args) == 1):
            self.arguments(call, strings=False)
        elif (isinstance(func, ast.Name)
                and (func.id in self.params or func.id in self.locals)
                and len(call.args) <= 1):
            self.arguments(call, strings=False)
        elif (isinstance(func, ast.Name) and func.id in PRIMITIVES):
            self.unsupported(call, f'{func.id}() outside the Python '
                             'reference of a @native function')
        else:
            self.unsupported(call, f'call {_text(call)} (lowered: of C '
                             'functions, spec functions, iter(), len(), '
                             'and of local objects with at most one '
                             'argument)')


class Inline(Lowered):
    """The body of an @inline function, which partial_eval.py generates
    into each caller: fast paths ``if <condition>: return <value>``, then
    ``return <value>``; a value is a call (Lowered.call()) or an operand
    (Lowered.value()).  Its signature is that of a native function: any
    C types (c_signature()), positional parameters without
    defaults."""

    def signature(self) -> None:
        args = self.node.args
        if args.vararg:
            self.unsupported(args.vararg, f'*{args.vararg.arg}')
        for arg in args.kwonlyargs:
            self.unsupported(arg, f'keyword-only parameter {arg.arg!r}')
        if args.kwarg:
            self.unsupported(args.kwarg, f'**{args.kwarg.arg}')
        for default in args.defaults:
            self.unsupported(default, f'default {_text(default)} (an '
                             '@inline function has none)')
        c_signature(self.node)      # a SpecError if not C types

    def statements(self, stmts: list[ast.stmt]) -> None:
        for i, stmt in enumerate(stmts):
            last = i == len(stmts) - 1
            match stmt:
                case ast.If(test=test, body=[ast.Return(value=value)],
                            orelse=[]) if not last and value is not None:
                    self.condition(test)
                    self.result(value)
                case ast.Return(value=value) if last and value is not None:
                    self.result(value)
                case _:
                    self.unsupported(stmt, f'{_text(stmt)!r} in an @inline '
                                     'function (lowered: fast paths "if '
                                     '<condition>: return <value>", then '
                                     '"return <value>")')

    def result(self, value: ast.expr) -> None:
        if isinstance(value, ast.Call):
            self.call(value)
        else:
            self.value(value)


def _kind(stmt: ast.stmt) -> str:
    """'while loop', 'with statement', ...: the kind of *stmt*."""
    names = {
        ast.While: 'while loop', ast.With: 'with statement',
        ast.AugAssign: 'augmented assignment',
        ast.AnnAssign: 'annotated assignment', ast.Assign: 'assignment',
        ast.Match: 'match statement', ast.Assert: 'assert statement',
        ast.Delete: 'del statement', ast.FunctionDef: 'nested def',
        ast.ClassDef: 'nested class', ast.Global: 'global statement',
        ast.Nonlocal: 'nonlocal statement', ast.Import: 'import',
        ast.ImportFrom: 'import', ast.Break: 'break', ast.Continue: 'continue',
        ast.Expr: 'expression statement', ast.AsyncFor: 'async for loop',
        ast.AsyncWith: 'async with statement',
        ast.AsyncFunctionDef: 'nested async def',
    }
    return names.get(type(stmt), type(stmt).__name__)


def _type_objects() -> set[str]:
    """The builtin types a spec class may describe (with a C check)."""
    return {name for name, (check, _) in TYPE_CHECKS.items() if check}


# -- the Python reference of a C function ---------------------------------------

class Analysed:
    """What facts.py follows in the Python reference of a @native
    function: control flow of the lowered subset, with every effect where
    facts.py accounts for it; any other code is a model of the values the
    C computes (facts.py: it has no effects), and must have none.

    Effects are ``return``, ``raise``, ``assert`` and the calls of
    primitives (runtime.py), of hand-written C functions and of spec
    functions."""

    def __init__(self, spec: Spec, name: str) -> None:
        self.spec = spec
        self.name = name
        self.found: list[Unsupported] = []

    def check(self) -> list[Unsupported]:
        self.statements(self.spec.body(self.name))
        return self.found

    def is_effect(self, node: ast.AST) -> bool:
        match node:
            case ast.Return() | ast.Raise() | ast.Assert():
                return True
            case ast.Call(func=ast.Name(name)) if name in PRIMITIVES:
                return True
            case ast.Call(func=ast.Name()) as call:
                # (``T.meth(...)`` in a reference is the builtin's: a
                # model, see runtime.load().)
                return (self.spec.c_function(call) is not None
                        or self.spec.inline_function(call) is not None
                        or self.spec.call_target(call.func) is not None)
        return False

    def effect_free(self, node: ast.AST | None, what: str) -> None:
        """*node* is a model: it has no effect."""
        if node is None:
            return
        for child in ast.walk(node):
            if self.is_effect(child):
                self.found.append((child, f'{_text(child)} in {what}'))
                return

    def call(self, call: ast.expr) -> None:
        """A value computed by one call: its effects are followed, not
        those of its arguments."""
        if isinstance(call, ast.Call):
            for arg in [*call.args, *(kw.value for kw in call.keywords)]:
                self.effect_free(arg, f'an argument of {_text(call.func)}()')
        else:
            self.effect_free(call, 'an expression')

    def statements(self, stmts: list[ast.stmt]) -> None:
        for stmt in stmts:
            self.statement(stmt)

    def statement(self, stmt: ast.stmt) -> None:
        match stmt:
            case ast.If(body=body, orelse=orelse):
                # facts.py accounts for every call of a condition.
                self.statements(body)
                self.statements(orelse)
            case ast.Assign(targets=[ast.Name()], value=value) \
                    | ast.Return(value=value) | ast.Expr(value=value):
                if value is not None:
                    self.call(value)
            case ast.Raise(exc=exc, cause=cause):
                if exc is not None:
                    self.call(exc)
                self.effect_free(cause, 'the cause of an exception')
            case ast.Try(body=[ast.Assign(targets=[ast.Name()]) | ast.Return()
                               | ast.Expr()],
                         handlers=[_, *_] as handlers, orelse=orelse,
                         finalbody=[]) if all(
                    isinstance(h.type, (ast.Name, ast.Tuple))
                    for h in handlers):
                self.statements(stmt.body)
                for handler in handlers:
                    self.statements(handler.body)
                self.statements(orelse)
            case ast.Try(body=body, handlers=[], orelse=[],
                         finalbody=finalbody):
                self.statements(body)
                self.statements(finalbody)
            case ast.For(target=ast.Name(), iter=ast.Name(), body=body,
                         orelse=[]):
                self.statements(body)
            case ast.Try():
                # partial_eval.py evaluates only the lowered forms.
                self.found.append((stmt, 'this form of try statement'))
            case ast.For():
                self.found.append((stmt, 'this form of for loop'))
            case ast.With(items=items, body=body):
                for item in items:
                    self.effect_free(item.context_expr, 'a with item')
                self.statements(body)
            case _:
                self.effect_free(stmt, _kind(stmt))


# -- the checks ------------------------------------------------------------------

_lowered_cache: weakref.WeakKeyDictionary[Spec, dict[str, list[Unsupported]]]
_lowered_cache = weakref.WeakKeyDictionary()
_analysed_cache: weakref.WeakKeyDictionary[Spec, dict[str, list[Unsupported]]]
_analysed_cache = weakref.WeakKeyDictionary()
_inline_cache: weakref.WeakKeyDictionary[Spec, dict[str, list[Unsupported]]]
_inline_cache = weakref.WeakKeyDictionary()


def lowered(spec: Spec, name: str) -> list[Unsupported]:
    """What of spec function *name* (its signature and body) is outside
    the lowered subset, in order."""
    cache = _lowered_cache.setdefault(spec, {})
    if name not in cache:
        cache[name] = Lowered(spec, name).check()
    return cache[name]


def analysed(spec: Spec, name: str) -> list[Unsupported]:
    """What of the Python reference of @native function *name*
    facts.py cannot follow, in order: if anything, its facts are the
    worst."""
    cache = _analysed_cache.setdefault(spec, {})
    if name not in cache:
        cache[name] = Analysed(spec, name).check()
    return cache[name]


def check_lowered(spec: Spec, name: str) -> None:
    """Raise a SpecError (NOT_LOWERED) at the first construct of spec
    function *name* outside the lowered subset."""
    found = lowered(spec, name)
    if found:
        node, what = found[0]
        raise spec.error(node, f"{name}(): {what} is expressible, but not "
                         "lowered to C yet", SpecErrorKind.NOT_LOWERED)


def inline(spec: Spec, name: str) -> list[Unsupported]:
    """What of @inline function *name* (its signature and body) is outside
    the lowered subset, in order."""
    cache = _inline_cache.setdefault(spec, {})
    if name not in cache:
        cache[name] = Inline(spec, name).check()
    return cache[name]


def check_inline(spec: Spec, name: str) -> None:
    """Raise a SpecError (NOT_LOWERED) at the first construct of @inline
    function *name* outside the lowered subset."""
    found = inline(spec, name)
    if found:
        node, what = found[0]
        raise spec.error(node, f"{name}(): {what} is expressible, but not "
                         "lowered to C yet", SpecErrorKind.NOT_LOWERED)

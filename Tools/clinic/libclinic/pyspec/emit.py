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
frontend.is_stub()) and @native functions are C written by hand:
they are never lowered to C, only called.

The passes: the body is checked against the lowered subset (subset.py),
partially evaluated (partial_eval.py, which marks its residual code,
marks.py), lowered here to the form of ir.py (FunctionLowering: C types,
ownership, error checks), and written out by the backend of the language
(c_backend.py).  Then come the tables of the caller (call_table.py: the
type-specialized variants of NAME_nargs1() and the call table of the
tier-2 optimizer) and the shared specializations the code calls
(marks.Specialization, e.g. bytes_from_iterator_list()).  The passes
share one context.Context.

A call of a hand-written C function f is f(args) in C.  The C types of
its parameters and result are its annotations (subset.c_signature()):
a str constant is an interned str object for an object parameter and a
C string for a ``str`` one, and a pointer of another C type is cast.
Its error check comes from its facts for the call (facts.py, marked on
the call by the partial evaluator, marks.CallCheck): none if it cannot
raise; else NULL for an object (NULL and an exception set when it may
return NULL, an absent result), -1 and an exception set for a
Py_ssize_t, a negative value for an int (ir.Convention).  A function
whose result is a C struct initializes the local assigned in place,
``f(&x, args)``, which returns 0 or -1 with an exception set; that local
is passed by address.

Reference ownership: parameters are borrowed; every object local is a new
reference, declared NULL at the top and released at every exit except
the one returning it; it may be assigned again only where it holds no
reference (e.g. in the other branch of an if).  A loop variable is a new
reference, released right after its last use in the loop body; it is
borrowed for a tuple item (the tuple keeps it alive) and in a snapshot,
where no Python code runs (the list, locked, keeps it alive): "borrowed
until Python code may run".  A C struct local (a buffer) is released by
the ``finally`` clause the spec writes around its use.
"""

from __future__ import annotations

import ast
import builtins
from collections.abc import Callable, Collection, Iterable
from typing import TYPE_CHECKING

from libclinic.errors import SpecError, SpecErrorKind
from . import (builtin_types, c_backend, frontend, ir, known, marks,
               specfiles, subset, typeobj)
from .context import Context
from .known import NOTNULL, NULL, Env, Value
from .subset import Kind, loaded_names, terminates

if TYPE_CHECKING:
    from .frontend import PyspecBindings, Spec, SpecFunction

OBJECT = 'PyObject *'
SSIZE = 'Py_ssize_t'
TYPE = frontend.TYPE_CTYPE
TYPE_OBJECTS = frontend.TYPE_OBJECTS

# The lines that follow the functions of a spec (call_table.generate()).
Tables = Callable[['Generator', list['SpecFunction']], list[str]]

# What a branch leaves: (the owned locals that may hold a value, those of
# them known not NULL), or None when it exits.
Branch = tuple[set[str], set[str]] | None


def spec_error(node: ast.AST | None, message: str,
               kind: SpecErrorKind = SpecErrorKind.LOWERING) -> SpecError:
    """A SpecError at *node*, in the spec it was written in (app.py fills
    in the spec of the C file): LOWERING, a use of the lowered subset
    this emitter cannot lower; NOT_LOWERED, a construct outside the
    lowered subset (subset.py reports those first)."""
    return SpecError.at(node, message, kind)


class FunctionLowering(subset.Walker[frozenset[str], None]):
    """Lower one list of residual statements to an ir.Function."""

    def __init__(self, generator: Generator, params: Iterable[tuple[str, str]],
                 known_null: Collection[str] = ()) -> None:
        self.generator = generator
        self.spec = generator.spec
        self.analyzer = generator.context.analyzer()
        # name -> C type; parameters are borrowed references
        self.params = dict(params)
        self.known_null = set(known_null)
        self.locals: dict[str, str] = {}    # name -> C type
        # Object locals, in declaration order.
        self.owned: list[str] = []
        self.live: set[str] = set()     # owned locals that may hold a value
        self.nonnull: set[str] = set()  # locals known not NULL
        self.loop_vars: list[str] = []  # owned variables of enclosing loops
        # The finally clauses around the statement lowered, innermost last.
        self.finally_blocks: list[list[ast.stmt]] = []
        self.body: list[ir.Stmt] = []
        # (spec, last line) of the statement lowered last: see locate().
        self.located: tuple[str, int] = ('', 0)
        # The local whose error check follows the if chain lowered (see
        # if_()).
        self.checked_after: str | None = None

    # -- output ------------------------------------------------------------

    def add(self, *stmts: ir.Stmt) -> None:
        self.body.extend(stmts)

    def collect(self, lower: Callable[[], object]) -> list[ir.Stmt]:
        """The statements *lower()* adds, apart."""
        saved, self.body = self.body, []
        try:
            lower()
            return self.body
        finally:
            self.body = saved

    def cleanup(self, keep: str | None = None,
                null: Collection[str] = ()) -> list[ir.Stmt]:
        """What an exit releases: the finally clauses, then the object
        locals."""
        out: list[ir.Stmt] = []
        for block in reversed(self.finally_blocks):
            for stmt in block:
                expr = convention = None
                if isinstance(stmt, ast.Expr) and isinstance(stmt.value,
                                                             ast.Call):
                    expr, _, convention = self.lower_call(stmt.value)
                if expr is None or convention is not None:
                    raise spec_error(stmt, 'a finally clause only calls C '
                                     'functions that cannot fail')
                out.append(ir.Eval(expr))
        for name in self.owned:
            if name in self.live and name != keep and name not in null:
                out.append(ir.Release(name, name not in self.nonnull))
        return out

    def release_dead(self, used: Collection[str]) -> None:
        """Release the loop variables not in *used* (the names used from
        here on): the reference is dropped right after its last use."""
        for name in self.loop_vars:
            if name in self.live and name not in used:
                self.add(ir.Release(name, maybe_null=False))
                self.live.discard(name)

    def error_exit(self, null: Collection[str] = ()) -> list[ir.Stmt]:
        return [*self.cleanup(null=null), ir.Return(ir.Null())]

    def error_check(self, name: str, convention: ir.Convention) -> None:
        self.add(ir.If(ir.Failed(ir.Name(name), convention),
                       self.error_exit(null={name})))
        if convention == ir.Convention.NULL:
            self.nonnull.add(name)

    def locate(self, stmt: ast.stmt) -> None:
        """Say where *stmt* is in the spec (ir.Location), unless it
        directly follows the statement lowered before it there (with only
        blank lines, comments or ``else:`` between them)."""
        if not getattr(stmt, 'lineno', 0) or subset.kind(stmt) is Kind.PASS:
            return
        path = marks.scope(stmt) or self.spec.filename
        match stmt:
            case ast.If(test=header) | ast.For(iter=header):
                # (The test of an @inline function is from its spec.)
                end = header.end_lineno or 0
                last = (end if stmt.lineno <= end <= (stmt.end_lineno or 0)
                        else stmt.lineno)
            case ast.Try() | ast.With():
                last = stmt.lineno
            case _:
                last = stmt.end_lineno or stmt.lineno
        before, self.located = self.located, (path, last)
        if before[0] == path and before[1] <= stmt.lineno and all(
                line.strip() in ('', 'else:', 'try:')
                or line.lstrip().startswith('#')
                for line in self.spec.load_spec(path).source.splitlines()[
                    before[1]:stmt.lineno - 1]):
            return
        self.add(ir.Location(specfiles.display_path(path), stmt.lineno))

    # -- declarations ------------------------------------------------------

    def ctype_of(self, name: str) -> str | None:
        if name in self.params:
            return self.params[name]
        return self.locals.get(name)

    def declare(self, target: ast.expr, ctype: str, node: ast.AST) -> None:
        name = ast.unparse(target)
        if name in self.params:
            raise spec_error(node, f'{name!r} is a parameter')
        if name in self.locals:
            # Assigned again (e.g. in both branches of an if): store()
            # checks that it holds no reference then.
            if self.locals[name] != ctype:
                raise spec_error(node, f'{name!r} changes type')
            return
        self.locals[name] = ctype
        if ctype == OBJECT:
            self.owned.append(name)

    def collect_locals(self, stmts: list[ast.stmt]) -> None:
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
                        raise spec_error(node, 'the loop variable must be a '
                                         'name')
                    self.declare(node.target, OBJECT, node)

    # -- calls -------------------------------------------------------------

    def c_function(self, call: ast.Call
                   ) -> tuple[str, list[str], str] | None:
        """(C name, parameter C types, return C type) of the hand-written
        C function *call* calls, or None."""
        found = self.spec.c_function(call)
        if found is None:
            return None
        _, node = found
        if frontend.is_native(node):
            params, returns = subset.c_signature(node)
            return node.name, [ctype for _, ctype in params], returns
        # A stub: objects in, an object out.
        return node.name, [OBJECT] * len(call.args), OBJECT

    def call_ctype(self, call: ast.expr) -> str:
        if not isinstance(call, ast.Call):
            raise spec_error(call, 'only call results can be assigned')
        function = self.c_function(call)
        if function is not None:
            return function[2]
        if marks.get(call, marks.Length) is not None:
            return SSIZE        # len()
        return OBJECT

    def convention(self, call: ast.Call,
                   returns: str) -> ir.Convention | None:
        """The error convention of a call of a hand-written C function
        (see the module docstring)."""
        check = marks.get(call, marks.CallCheck)
        if check is None:
            # Not marked by the partial evaluator: the facts for any
            # arguments.
            self.analyzer.mark_call(call, {})
            check = marks.get(call, marks.CallCheck)
            assert check is not None
        if subset.is_struct(returns):
            return ir.Convention.NEGATIVE
        if not check.raises or returns == 'void':
            return None
        if returns == OBJECT:
            return (ir.Convention.NULL_OR_MISSING if check.null
                    else ir.Convention.NULL)
        return (ir.Convention.NEGATIVE if returns == 'int'
                else ir.Convention.MINUS1)

    def lower_arg(self, arg: ast.expr, ctype: str) -> ir.Expr:
        """Argument *arg* of a C function parameter of type *ctype*."""
        match arg:
            case ast.Constant(str() as text) if ctype == OBJECT:
                return ir.Identifier(text)
            case ast.Constant(str() as text):
                return ir.String(text)
            case ast.Name(name) if subset.is_struct(
                    self.ctype_of(name) or '*'):
                return ir.AddressOf(name)
        value = self.lower_value(arg)
        actual = self.ctype_of(arg.id) if isinstance(arg, ast.Name) else None
        if (actual and actual != ctype and actual.endswith('*')
                and ctype.endswith('*')):
            return ir.Cast(ctype, value)
        return value

    def lower_call(self, call: ast.Call, target: str | None = None
                   ) -> tuple[ir.Expr, str, ir.Convention | None]:
        """Return (expression, C type, error convention).

        *target*: the local assigned, for a C function that initializes
        it in place (then the expression is an int status)."""
        def values() -> tuple[ir.Expr, ...]:
            return tuple(self.lower_value(a) for a in call.args)

        special = marks.get(call, marks.Specialized)
        if special is not None and special.called:
            self.generator.use(special.name)
            return ir.Call(special.name, values()), OBJECT, ir.Convention.NULL
        arity = marks.get(call, marks.ArityCall)
        if arity is not None:
            return ir.Call(arity.c_name, values()), OBJECT, ir.Convention.NULL
        function = self.c_function(call)
        if function is not None:
            name, params, returns = function
            if len(params) != len(call.args):
                raise spec_error(call, f'{name}() takes {len(params)} '
                                 'arguments')
            args = [self.lower_arg(a, t) for a, t in zip(call.args, params)]
            if subset.is_struct(returns):
                if target is None:
                    raise spec_error(call, f'the result of {name}() must '
                                     'be assigned to a local')
                args.insert(0, ir.AddressOf(target))
            return (ir.Call(name, tuple(args)), returns,
                    self.convention(call, returns))
        length = marks.get(call, marks.Length)
        if length is not None:
            # len() of an exact list or tuple.
            size = builtin_types.TABLE[length.tp].size
            assert size is not None
            return ir.Call(size, values()), SSIZE, None
        spec_target = self.spec.call_target(call.func)
        if spec_target is not None:
            spec_args = subset.call_arguments(self.spec, spec_target, call)
            return (ir.Call(self.generator.c_name(spec_target),
                            tuple(self.lower_value(a) for a in spec_args)),
                    OBJECT, ir.Convention.NULL)
        if isinstance(call.func, ast.Name):
            name = call.func.id
            if name == 'iter' and len(call.args) == 1:
                return (ir.Call('PyObject_GetIter', values()), OBJECT,
                        ir.Convention.NULL)
            if self.ctype_of(name) == OBJECT and not call.args:
                return (ir.Call('_PyObject_CallNoArgs', (ir.Name(name),)),
                        OBJECT, ir.Convention.NULL)
            if self.ctype_of(name) in (OBJECT, TYPE) and len(call.args) == 1:
                callable_: ir.Expr = ir.Name(name)
                if self.ctype_of(name) != OBJECT:
                    callable_ = ir.Cast(OBJECT, callable_)
                return (ir.Call('PyObject_CallOneArg',
                                (callable_, *values())),
                        OBJECT, ir.Convention.NULL)
        raise spec_error(call, f'unsupported call {ast.unparse(call)}',
                         SpecErrorKind.NOT_LOWERED)

    # -- expressions -------------------------------------------------------

    def lower_value(self, node: ast.expr) -> ir.Expr:
        """A non-raising expression used as an argument or operand."""
        match node:
            case ast.Name('NULL' | 'None'):
                return ir.Null()
            case ast.Name(id) if id in self.known_null:
                return ir.Null()
            case ast.Name(id) if self.ctype_of(id) is not None:
                return ir.Name(id)
            case ast.Name(id) if id in TYPE_OBJECTS:
                return ir.TypeObject(id)
            case ast.Name(id) if subset.is_exception(id):
                return ir.ExceptionType(id)
            case ast.Constant(bool() as value):
                return ir.Int(int(value))
            case ast.Constant(int() as value):
                return ir.Int(value)
        raise spec_error(node, f'unsupported value {ast.unparse(node)}',
                         SpecErrorKind.NOT_LOWERED)

    def lower_condition(self, node: ast.expr) -> ir.Expr:
        match node:
            case ast.UnaryOp(op=ast.Not(), operand=operand):
                return ir.Not(self.lower_condition(operand))
            case ast.BoolOp(op=op, values=values):
                return ir.BoolOp('and' if isinstance(op, ast.And) else 'or',
                                 tuple(self.lower_condition(v)
                                       for v in values))
            case ast.Compare(left=left, ops=[ast.Is() | ast.IsNot() as op],
                             comparators=[ast.Name('NULL')]):
                if isinstance(left, ast.NamedExpr):
                    left = left.target
                return ir.Compare(_equal(op), self.lower_value(left),
                                  ir.Null())
            case ast.Compare(left=ast.Name(name),
                             ops=[ast.Is() | ast.IsNot() as op],
                             comparators=[ast.Name(known.FALLBACK)]):
                return ir.Compare(_equal(op), ir.Name(name), ir.Fallback())
            case ast.Call() if self.c_function(node) is not None:
                expr, _, convention = self.lower_call(node)
                if convention is not None:
                    raise spec_error(node, 'a call in a condition cannot '
                                     f'fail: {ast.unparse(node)}')
                return expr
            case ast.Compare(left=ast.Call(func=ast.Name('type'), args=[obj]),
                             ops=[ast.Is() | ast.IsNot() as op],
                             comparators=[ast.Name(cls)]) \
                    if subset.TYPE_CHECKS.get(cls, (0, 0))[1]:
                check = ir.TypeCheck(cls, True, self.lower_value(obj))
                return ir.Not(check) if isinstance(op, ast.IsNot) else check
            case ast.Compare(left=ast.Name(name),
                             ops=[ast.Is() | ast.IsNot() as op],
                             comparators=[ast.Name(cls)]) \
                    if self.ctype_of(name) == TYPE and cls in TYPE_OBJECTS:
                return ir.Compare(_equal(op), ir.Name(name),
                                  ir.TypeObject(cls))
            case ast.Call(func=ast.Name('isinstance'),
                          args=[obj, ast.Name(cls)]) \
                    if subset.TYPE_CHECKS.get(cls, (0, 0))[0]:
                return ir.TypeCheck(cls, False, self.lower_value(obj))
            case ast.Call(func=ast.Name('hasattr'),
                          args=[ast.Call(func=ast.Name('type'), args=[obj]),
                                ast.Constant(str() as name)]) \
                    if name in subset.HASATTR_SLOTS:
                return ir.HasSlot(name, self.lower_value(obj))
            case ast.Compare(left=left, ops=[op], comparators=[right]) \
                    if type(op) in subset.COMPARE_OPS:
                return ir.Compare(subset.COMPARE_OPS[type(op)],
                                  self.lower_value(left),
                                  self.lower_value(right))
        raise spec_error(node, f'unsupported condition {ast.unparse(node)}',
                         SpecErrorKind.NOT_LOWERED)

    def hoist_named(self, node: ast.expr) -> None:
        """Lower the assignment of a walrus that leads an if condition."""
        if (isinstance(node, ast.Compare)
                and isinstance(node.left, ast.NamedExpr)):
            named = node.left
            self.store(named.target, named.value, named)
        for child in ast.walk(node):
            if isinstance(child, ast.NamedExpr) and (
                    not isinstance(node, ast.Compare)
                    or child is not node.left):
                raise spec_error(child,
                                 'walrus only as the left operand of "is"')

    # -- statements --------------------------------------------------------

    def store(self, target: ast.expr, value: ast.expr, node: ast.AST,
              check: bool = True, later: Collection[str] | None = None
              ) -> tuple[str, str, ir.Convention | None]:
        """``target = value``.  *later*: the names used after this
        statement (see statements()), to release the loop variables used
        last here."""
        name = ast.unparse(target)
        if name in self.live:
            raise spec_error(node, f'{name!r} is assigned again while it '
                             'holds a reference')
        if not isinstance(value, ast.Call):
            raise spec_error(value, 'only call results can be assigned')
        expr, ctype, convention = self.lower_call(value, target=name)
        if self.locals.get(name) != ctype:
            raise spec_error(node, f'{name!r} changes type')
        if subset.is_struct(ctype):
            if not check:
                raise spec_error(node, 'cannot initialize a C local here')
            self.add(ir.If(ir.Failed(expr, ir.Convention.NEGATIVE),
                           self.error_exit()))
            return name, ctype, convention
        self.add(ir.Assign(name, expr))
        self.nonnull.discard(name)
        if ctype == OBJECT:
            self.live.add(name)
        if later is not None:
            self.release_dead(later)
        if check and convention is not None:
            self.error_check(name, convention)
        return name, ctype, convention

    def statements(self, stmts: list[ast.stmt],
                   later: Collection[str] = frozenset()) -> None:
        """*later*: the names used after *stmts*.  Loop variables no
        longer used are released before each statement, and at the end."""
        uses = [loaded_names([stmt]) for stmt in stmts]
        for i, stmt in enumerate(stmts):
            rest = frozenset(later).union(*uses[i + 1:])
            self.release_dead(rest | uses[i])
            self.locate(stmt)
            self.statement(stmt, rest)
        if not terminates(stmts):
            self.release_dead(later)

    def block(self, stmts: list[ast.stmt], null: Collection[str] = (),
              later: Collection[str] = frozenset(),
              nonnull: Collection[str] = ()) -> tuple[list[ir.Stmt], Branch]:
        """A nested block, where the locals *null* are NULL and *nonnull*
        are not, and what it leaves (see Branch)."""
        saved = self.live, self.nonnull
        self.live = saved[0] - set(null)
        self.nonnull = saved[1] - set(null) | set(nonnull)
        body = self.collect(lambda: self.statements(stmts, later))
        left = None if terminates(stmts) else (self.live, self.nonnull)
        self.live, self.nonnull = saved
        return body, left

    def join(self, branches: list[Branch]) -> None:
        """Continue after branches; None marks a branch that exits."""
        falling = [branch for branch in branches if branch is not None]
        self.live = set().union(*(live for live, _ in falling))
        self.nonnull = (set.intersection(*(nonnull for _, nonnull in falling))
                        if falling else set())

    def other(self, stmt: ast.stmt, later: frozenset[str]) -> None:
        raise spec_error(stmt, f'unsupported statement {ast.unparse(stmt)}',
                         SpecErrorKind.NOT_LOWERED)

    def pass_(self, stmt: ast.stmt, later: frozenset[str]) -> None:
        pass

    def if_(self, stmt: ast.If, later: frozenset[str]) -> None:
        """An if; one error check after an if chain whose every branch
        assigns the same local a call with the same error convention (the
        dispatch of a __new__ by arity, partial_eval.py)."""
        convention = None
        if self.checked_after is None:
            target, convention = self.chain(stmt)
            self.checked_after = target
        self.if_else(stmt, later)
        if convention is not None:
            self.error_check(self.checked_after or '', convention)
            self.checked_after = None

    def chain(self, stmt: ast.If) -> tuple[str | None, ir.Convention | None]:
        """(target, convention) of an if chain (see if_()), else None."""
        assigns: list[tuple[str, ast.Call]] = []
        branches: list[list[ast.stmt]] = [stmt.body, stmt.orelse]
        while branches:
            match branches.pop():
                case [ast.If(body=body, orelse=orelse)]:
                    branches += [body, orelse]
                case [ast.Assign(targets=[ast.Name(target)],
                                 value=ast.Call() as call)]:
                    assigns.append((target, call))
                case _:
                    return None, None
        found = {(target, *self.lower_call(call, target)[1:])
                 for target, call in assigns}
        if len(found) != 1:
            return None, None
        (target, ctype, convention), = found
        if convention is None or subset.is_struct(ctype):
            return None, None
        return target, convention

    def if_else(self, stmt: ast.If, later: frozenset[str]) -> None:
        test = stmt.test
        self.hoist_named(test)
        null_in_body, null_in_else = self.null_refinement(test)
        # A name NULL in one branch is not NULL in the other (but the
        # FALLBACK of a snapshot is not NULL either).
        nonnull_in_body, nonnull_in_else = self.null_refinement(test, True)
        condition = self.lower_condition(test)
        body, left = self.block(stmt.body, null_in_body, later,
                                nonnull_in_body)
        branches = [left]
        dying = [name for name in self.loop_vars
                 if name in self.live and name not in later]
        orelse: list[ir.Stmt] = []
        if stmt.orelse or dying:
            orelse, left = self.block(stmt.orelse, null_in_else, later,
                                      nonnull_in_else)
            branches.append(left)
        else:
            branches.append((self.live - null_in_else,
                             self.nonnull | nonnull_in_else))
        self.add(ir.If(condition, body, orelse))
        self.join(branches)

    def assign(self, stmt: ast.Assign, later: frozenset[str]) -> None:
        self.store(stmt.targets[0], stmt.value, stmt, later=later,
                   check=ast.unparse(stmt.targets[0]) != self.checked_after)

    def call_(self, stmt: ast.Expr, later: frozenset[str]) -> None:
        """``f(...)`` as a statement: a C function returning void or an
        int status."""
        call = stmt.value
        assert isinstance(call, ast.Call)
        function = self.c_function(call)
        if function is None or function[2] not in ('void', 'int'):
            raise spec_error(stmt, 'only a C function returning void or an '
                             'int status can be called as a statement')
        expr, _, convention = self.lower_call(call)
        if convention is None:
            self.add(ir.Eval(expr))
        elif convention != ir.Convention.NEGATIVE:
            raise spec_error(stmt, 'a status must be negative on error')
        else:
            self.add(ir.If(ir.Failed(expr, convention), self.error_exit()))
        self.release_dead(later)

    def return_(self, stmt: ast.Return, later: frozenset[str]) -> None:
        value = stmt.value
        match value:
            case ast.Name(known.FALLBACK):
                self.add(*self.cleanup(), ir.Return(ir.Fallback()))
            case ast.Name(id) if id in self.params:
                self.add(*self.cleanup(), ir.Return(ir.NewRef(ir.Name(id))))
            case ast.Name(id) if self.locals.get(id) == OBJECT:
                self.add(*self.cleanup(keep=id), ir.Return(ir.Name(id)))
            case ast.Constant() | ast.Tuple():
                constant = ast.literal_eval(value)
                name = builtin_types.constant(constant)
                if name is None:
                    raise spec_error(stmt, 'no Py_GetConstant() for '
                                     f'{constant!r}')
                self.add(*self.cleanup(), ir.Return(
                    ir.Call('Py_GetConstant', (ir.Name(name),))))
            case ast.Call():
                expr, ctype, convention = self.lower_call(value)
                if ctype != OBJECT or convention not in (ir.Convention.NULL,
                                                         None):
                    raise spec_error(stmt, 'can only return a new reference')
                after = ([] if not self.live and not self.finally_blocks
                         else self.cleanup())
                self.add(ir.Return(expr, after))
            case _:
                raise spec_error(stmt, 'unsupported return '
                                 f'{ast.unparse(value) if value else ""}',
                                 SpecErrorKind.NOT_LOWERED)
        self.live = set()

    def raise_(self, stmt: ast.Raise, later: frozenset[str]) -> None:
        match stmt:
            case ast.Raise(exc=ast.Call() as call) \
                    if self.c_function(call) is not None:
                # A C function that sets the exception.
                self.add(ir.Eval(self.lower_call(call)[0]))
            case ast.Raise(exc=ast.Call(func=ast.Name(exc), args=[message])):
                self.add(self.set_exception(exc, message, stmt))
            case _:
                return self.other(stmt, later)
        self.add(*self.error_exit())
        self.live = set()
        return None

    def set_exception(self, exc: str, message: ast.expr,
                      node: ast.AST) -> ir.Stmt:
        """``raise exc(message)`` sets the exception."""
        exc_c = self.lower_value(ast.Name(exc))
        match message:
            case ast.Constant(str() as text):
                return ir.Eval(ir.Call('PyErr_SetString',
                                       (exc_c, ir.String(text))))
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
                            args.append(ir.TypeName(self.lower_value(obj)))
                        case _:
                            raise spec_error(node, 'unsupported f-string part '
                                             f'{ast.unparse(part)}',
                                             SpecErrorKind.NOT_LOWERED)
                return ir.Eval(ir.Call('PyErr_Format', (
                    exc_c, ir.String(''.join(fmt)), *args)))
        raise spec_error(node, 'raise needs a str or f-string message')

    def try_(self, stmt: ast.Try, later: frozenset[str]) -> None:
        """``try: x = f(...)`` / ``except E:`` ... / ``else:`` ..."""
        match stmt:
            case ast.Try(body=[ast.Assign(targets=[ast.Name() as target],
                                          value=value)],
                         finalbody=[]):
                pass
            case _:
                return self.other(stmt, later)
        name, ctype, convention = self.store(target, value, stmt, check=False)
        if convention is None:
            raise spec_error(stmt, 'try around a call that cannot fail')
        matches = []
        for handler in stmt.handlers:
            if handler.name is not None:
                raise spec_error(handler,
                                 '"except E as name" is not supported')
            assert handler.type is not None
            types = (handler.type.elts if isinstance(handler.type, ast.Tuple)
                     else [handler.type])
            tests = tuple(ir.Call('PyErr_ExceptionMatches',
                                  (self.lower_value(t),)) for t in types)
            matches.append(tests[0] if len(tests) == 1
                           else ir.BoolOp('or', tests))
        # In the error branch the target holds no reference; in the other,
        # it holds one (not NULL if NULL is an error).
        saved = self.live
        self.live = saved - {name}
        branches: list[Branch] = []
        handlers = []
        for handler, test in zip(stmt.handlers, matches):
            body, left = self.block(handler.body, {name})
            branches.append(left)
            handlers.append((test, [ir.Eval(ir.Call('PyErr_Clear')), *body]))
        failed = self.error_exit()
        self.live = saved
        for test, body in reversed(handlers):
            failed = [ir.If(test, body, failed)]
        nonnull = {name} if convention == ir.Convention.NULL else set()
        orelse: list[ir.Stmt] = []
        if stmt.orelse:
            orelse, left = self.block(stmt.orelse, nonnull=nonnull)
            branches.append(left)
        else:
            branches.append((set(saved), self.nonnull | nonnull))
        self.add(ir.If(ir.Failed(ir.Name(name), convention), failed, orelse))
        self.join(branches)
        return None

    def finally_(self, stmt: ast.Try, later: frozenset[str]) -> None:
        """``try: ...`` / ``finally: <calls>``."""
        self.finally_blocks.append(stmt.finalbody)
        self.statements(stmt.body, later)
        self.finally_blocks.pop()
        if not terminates(stmt.body):
            self.statements(stmt.finalbody, later)

    def for_(self, stmt: ast.For, later: frozenset[str]) -> None:
        """``for item in it:`` or, marked by the partial evaluator, an
        index loop over an exact list or tuple (see partial_eval.py)."""
        match stmt:
            case ast.For(target=ast.Name(item), iter=ast.Name() as iterable,
                         orelse=[]):
                pass
            case _:
                return self.other(stmt, later)
        seq = self.lower_value(iterable)
        live_before = set(self.live)
        owned = True
        mark = marks.get(stmt, marks.Loop)
        on_error: list[ir.Stmt] = []
        kind = None
        if mark is not None and mark.by_index:
            if mark.iterable is tuple:
                # The tuple holds a reference to every item: borrowed.
                # Its size cannot change.
                kind, owned = ir.Items.TUPLE, False
            elif mark.iterable is list and mark.snapshot:
                # A snapshot (partial_eval.py): the list is locked and no
                # Python code runs, so the list cannot change and keeps
                # its items alive: borrowed, and the size and the items
                # are read once.
                kind, owned = ir.Items.SNAPSHOT, False
            elif mark.iterable is list:
                # What the list iterator does: the size is read again for
                # every item, since the loop body may change the list.
                kind = ir.Items.LIST
            else:
                raise spec_error(stmt, f'no index loop for {mark.iterable!r}')
        else:
            on_error = self.error_exit()
        if owned:
            self.live.add(item)
            self.nonnull.add(item)
            self.loop_vars.append(item)
        # The names used by the next iterations stay alive.
        body = self.collect(lambda: self.statements(
            stmt.body, (set(later) | loaded_names([stmt])) - {item}))
        if owned:
            self.loop_vars.pop()
        if self.live != live_before:
            raise spec_error(stmt, 'a loop body must release what it '
                             'assigns: ' + ', '.join(sorted(
                                 self.live ^ live_before)))
        if kind is None:
            self.add(ir.ForIter(item, seq, on_error, body))
        else:
            self.add(ir.ForIndex(item, seq, kind, body))
        return None

    def with_(self, stmt: ast.With, later: frozenset[str]) -> None:
        """``with critical_section(x): v = f(...)``: the critical section
        of x (the partial evaluator writes it for snapshots).  The error
        check comes after its end, so it is always closed."""
        match stmt:
            case ast.With(items=[ast.withitem(
                    context_expr=ast.Call(func=ast.Name('critical_section'),
                                          args=[obj]),
                    optional_vars=None)], body=[ast.Assign() as assign]):
                pass
            case ast.With(items=[ast.withitem(
                    context_expr=ast.Call(func=ast.Name('critical_section')),
                    optional_vars=None)]):
                raise spec_error(stmt, 'a with body assigns one call')
            case _:
                return self.other(stmt, later)
        lock = self.lower_value(obj)
        stored = []
        body = self.collect(lambda: stored.append(self.store(
            assign.targets[0], assign.value, assign, check=False)))
        self.add(ir.Locked(lock, body))
        name, _, convention = stored[0]
        if convention is not None:
            self.error_check(name, convention)
        return None

    @staticmethod
    def null_refinement(test: ast.expr, nonnull: bool = False
                        ) -> tuple[set[str], set[str]]:
        """Names known NULL in the (body, else) of ``if test`` (the
        FALLBACK of a snapshot is not a reference either); with
        *nonnull*, the names known not NULL."""
        match test:
            case ast.Compare(left=left, ops=[ast.Is() | ast.IsNot() as op],
                             comparators=[ast.Name(null)]) \
                    if null == 'NULL' or null == known.FALLBACK \
                    and not nonnull:
                if isinstance(left, ast.NamedExpr):
                    left = left.target
                if isinstance(left, ast.Name):
                    if isinstance(op, ast.IsNot) != nonnull:
                        return set(), {left.id}
                    return {left.id}, set()
        return set(), set()

    # -- whole function ----------------------------------------------------

    def function(self, c_name: str, stmts: list[ast.stmt]) -> ir.Function:
        self.collect_locals(stmts)
        self.statements(stmts)
        if not terminates(stmts):
            raise spec_error(stmts[-1] if stmts else None,
                             f'{c_name}: control reaches the end')
        return ir.Function(c_name, list(self.params.items()),
                           list(self.locals.items()), self.body,
                           exported(c_name))


def _equal(op: ast.cmpop) -> str:
    return '!=' if isinstance(op, ast.IsNot) else '=='


def exported(name: str) -> bool:
    return name.startswith(('Py', '_Py'))


def c_params(description: SpecFunction) -> list[tuple[str, str]]:
    return [(p.name, p.ctype) for p in description.parameters]


class Generator:
    """Generate the C for a spec.

    c_basenames maps the implemented spec methods ("bytes.__new__") to the
    C basename of their clinic function ("bytes_new"); conditions maps
    those whose block is under #if to the condition (clinic's);
    type_objects maps the clinic classes of the C file to their type
    object ("&PyBytesIter_Type").
    """

    def __init__(self, context: Context, bindings: PyspecBindings,
                 backend: c_backend.CBackend | None = None) -> None:
        self.context = context
        self.spec = context.spec
        self.backend = backend or c_backend.CBackend()
        functions = bindings.functions
        self.c_basenames = {n: b.c_basename for n, b in functions.items()}
        self.self_ctypes = {n: b.self_ctype for n, b in functions.items()}
        self.conditions = {n: b.condition for n, b in functions.items()
                           if b.condition}
        self.type_objects = bindings.type_objects
        # The shared specializations the generated code calls, in order.
        self.specializations: list[str] = []

    def use(self, name: str) -> None:
        """Emit specialization *name* (marks.Specialization)."""
        if name not in self.specializations:
            self.specializations.append(name)

    def describe(self, name: str) -> SpecFunction:
        if '.' in name:
            self.c_basename(name)       # used by a clinic block?
            return self.spec.describe(name, self.self_ctypes[name])
        return self.spec.describe(name)

    def c_basename(self, name: str) -> str:
        """C basename: the clinic one for a method, else the name."""
        if '.' not in name:
            return name
        try:
            return self.c_basenames[name]
        except KeyError:
            raise spec_error(self.spec.functions[name],
                             f'{name} has a body, but no clinic block in '
                             'the C file uses it',
                             SpecErrorKind.BINDING) from None

    def guard(self, name: str, lines: list[str]) -> list[str]:
        """*lines* under the condition of the block of *name*."""
        return self.backend.guard(self.conditions.get(name, ''), lines)

    def c_name(self, name: str) -> str:
        """C name of spec function *name*: NAME_impl() for a method."""
        if '.' in name:
            return f'{self.c_basename(name)}_impl'
        return name

    def residual(self, name: str, env: Env, inline: bool = True,
                 arities: list[tuple[Env, str, list[str]]] | None = None
                 ) -> list[ast.stmt]:
        """The residual code of spec function *name* under *env*."""
        return self.context.residual(self.spec, name, env, inline=inline,
                                     arities=arities or ())

    def generate(self, spec_path: str, tables: Tables | None) -> str:
        out = [typeobj.header(spec_path), '']
        names = self.spec.implemented_functions()
        descriptions = [self.describe(name) for name in names]
        for description in descriptions:
            name = self.c_name(description.name)
            if not exported(name):
                out += self.guard(description.name, [self.backend.prototype(
                    name, c_params(description))])
        prototypes = len(out)
        out.append('')

        for description in descriptions:
            # Nothing is known about the arguments; the evaluator still
            # specializes loops (see partial_eval.py), but keeps calls
            # of other spec functions as calls.  Where the rest of a
            # __new__ is an arity function, it is called.
            body = self.residual(
                description.name, {}, inline=False,
                arities=[(env, name, [p.name for p in given])
                         for env, name, given, _ in self.arities(description)])
            lowering = FunctionLowering(self, c_params(description))
            out += self.guard(description.name, self.backend.function(
                lowering.function(self.c_name(description.name), body)))
            out.append('')

        for description in descriptions:
            if description.new_type is not None:
                out += self.guard(description.name,
                                  self.generate_arities(description))
        if tables is not None:
            # The functions compiled unconditionally.
            out += tables(self, [d for d in descriptions
                                 if d.name not in self.conditions])
        # The specializations, which may use others.
        done = 0
        while done < len(self.specializations):
            special = self.context.specializations()[
                self.specializations[done]]
            done += 1
            params = self.specialization_params(special)
            out[prototypes:prototypes] = [self.backend.prototype(
                special.name, params)]
            prototypes += 1
            out += self.generate_specialization(special, params)
        return '\n'.join(out)

    def specialization_params(self, special: marks.Specialization
                              ) -> list[tuple[str, str]]:
        ctypes = dict(c_params(self.describe(special.callee)))
        return [(p, ctypes[p]) for p in special.params]

    def generate_specialization(self, special: marks.Specialization,
                                params: list[tuple[str, str]]) -> list[str]:
        facts = ', '.join(
            f'{p} of exact type {fact.__name__}' if isinstance(fact, type)
            else f'{p} = iter({fact.source})'
            for p, fact in special.env.items()
            if isinstance(fact, (type, known.IterOf)))
        what = f'{special.callee}() for {facts}'
        if special.lock is not None:
            what += (f', the snapshot: called in the critical section of '
                     f'{special.lock}, runs no Python code; FALLBACK '
                     f'({self.backend.expr(ir.Fallback())}) when that could '
                     'run Python code')
        return self.commented_function(what, special.name, special.body,
                                       params)

    def commented_function(self, title: str, c_name: str,
                           stmts: list[ast.stmt],
                           params: list[tuple[str, str]],
                           known_null: Collection[str] = ()) -> list[str]:
        """The C function *c_name* lowered from *stmts*, after a comment:
        *title* and the Python code."""
        code = ast.unparse(ast.Module(stmts, []))
        function = FunctionLowering(self, params, known_null).function(
            c_name, stmts)
        return [*self.backend.comment(title, code),
                *self.backend.function(function), '']

    def arities(self, description: SpecFunction
                ) -> list[tuple[Env, str, list[frontend.SpecParameter],
                                list[frontend.SpecParameter]]]:
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
            env: Env = {cls.name: Value(type_value)}
            env |= {p.name: NOTNULL for p in given}
            env |= {p.name: NULL for p in missing}
            out.append((env, f'{basename}_nargs{nargs}', given, missing))
        return out

    def generate_arities(self, description: SpecFunction) -> list[str]:
        """NAME_nargsN() for each allowed N: the __new__ spec partially
        evaluated for exactly its class and a call with N positional
        arguments; the rest are NULL.  Argument Clinic declares them and
        calls them from the vectorcall with converted values."""
        basename = self.c_basename(description.name)
        out = []
        for env, name, given, missing in self.arities(description):
            nargs = len(given)
            residual = self.residual(description.name, env)
            out += self.commented_function(
                f'{basename}() for exactly {description.new_type} with '
                f'{nargs} positional argument(s)',
                name, residual,
                [(p.name, p.ctype) for p in given], [p.name for p in missing])
        return out


def generate(spec: Spec, spec_path: str, bindings: PyspecBindings,
             tables: Tables | None = None) -> str:
    """C for the implemented functions of *spec*, a frontend.Spec, bound
    to the clinic functions of the C file by *bindings*; *tables*: what
    follows the functions and their arity functions, before the shared
    specializations they call (call_table.generate()).

    *spec_path* is only named in the header comment.
    """
    return Generator(Context(spec), bindings).generate(spec_path, tables)

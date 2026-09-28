"""Partial evaluation of spec functions for the facts of a call site.

Given facts about the arguments (known.py: NULL or not, an exact type, a
value), Evaluator folds the branches they decide, inlines tail calls of
other spec functions (or calls a shared specialization, below), and
after an ``if`` whose one branch exits, keeps the facts of the other.
The residual is ast in the same subset (subset.Kind), with typed marks
(marks.py) on the nodes for facts.py and emit.py.

Calls.  A @native function is analysed through its Python reference
(facts.py), never generated: a call whose result is NULL on every path
is that NULL, and a ``try`` around a call that cannot raise what its
handlers catch is its body (``iter(x)`` of a list).  An @inline body
(``if <test>: return <value>`` paths, then ``return <value>``) is
generated into every statement calling it (expand()): the statement with
each value, under its test; a test the facts decide selects or drops
its path, and what they decide of a test is dropped from it.

Loops.  ``for item in it:`` over ``it = iter(x)``, for x of a known
exact type whose iteration runs no Python code: a list or tuple is
iterated by index without an iterator (``it = iter(x)`` is then dead),
reading the size of a list for every item as its iterator does; the
exact type of the items is known in the body.  Where the type of x is
not known at ``it = iter(x)``, the rest of the block is versioned for an
exact list and tuple when that gives an index loop (VERSIONED_ITERABLES).

Arity functions.  Where the rest of a __new__ body is one of its
NAME_nargsN() functions (emit.py), it calls it (arity_call()); where
the __new__ calls itself for its type (``T.__new__(T, ...)``), it calls
the arity function of the arguments not NULL, tested at run time as the
vectorcall does (dispatch()).

Shared specializations.  A tail call whose residual has a loop is not
inlined: the residual becomes a C function of its own
(marks.Specialization) called by every call with the same facts; one
that does not iterate by index keeps calling the generic function, with
the facts of the residual.

Snapshots.  The residual of a list loop is split in two, as the
hand-written _PyBytes_FromSequence_lock_held() was: every statement that
may run Python code becomes ``return FALLBACK``, and the rest runs with
the list locked (``with critical_section(x):``), so it iterates a
consistent snapshot, borrows its items and reads its size once.  On
FALLBACK the call restarts through the generic function; as the
snapshot ran no Python code, that cannot be observed.

Capacity.  A buffer (a C struct local) initialized with the length of a
sequence, ``w = init(len(x))``, has room for one unit per item of x: in
a loop over x with a fixed number of iterations (a tuple, a snapshot)
whose one use of w is one call of an @inline function writing w, the
first path of that call is taken without its test (presize()); the
debug build checks it (bytes_appender_append_unchecked()).
"""

from __future__ import annotations

import ast
import copy
import dataclasses as dc
import itertools
from collections.abc import Hashable, Sequence
from typing import TYPE_CHECKING, Protocol, cast

from . import builtin_types, facts, frontend, marks, subset
from .known import (FALLBACK, NOTNULL, NULL, SEQUENCES, Env, Fact, IterOf,
                    Other, Value, arg_fact, builtin_type, exact_type,
                    fact_key, is_type_call, refine)
from .marks import Specialization
from .subset import assigned_names, loaded_names, terminates

if TYPE_CHECKING:
    from .frontend import Spec

class Context(facts.Passes, Protocol):
    """What the evaluator needs of the other passes: the context of the
    passes (context.Context)."""

    def specializations(self, spec: Spec | None = None) -> Specializations:
        ...


# An iterable of unknown type is versioned for these exact types.
VERSIONED_ITERABLES = SEQUENCES

MAX_INLINE_DEPTH = 8

# (facts, C function, arguments) of the arity functions of a __new__.
Arity = tuple[Env, str, list[str]]


def _only_null(callee: facts.Facts | None) -> bool:
    """Whether facts.Facts *callee* are those of ``return NULL``."""
    return (callee is not None and not callee.returns
            and callee.returns_null and not callee.runs_python
            and not callee.raises)


def evaluate(expr: ast.expr, env: Env, ev: Evaluator) -> bool | None:
    """Return True, False, or None when *expr* is not decided by *env*.
    *ev*: the Evaluator."""
    match expr:
        case ast.UnaryOp(op=ast.Not(), operand=operand):
            value = evaluate(operand, env, ev)
            return None if value is None else not value
        case ast.BoolOp(op=op, values=values):
            results = [evaluate(v, env, ev) for v in values]
            decisive = isinstance(op, ast.Or)   # True decides an or
            if decisive in results:
                return decisive
            return None if None in results else not decisive
        case ast.Compare(left=left, ops=[ast.Is() | ast.IsNot() as op],
                         comparators=[right]):
            value = _evaluate_is(left, right, env, ev)
            if value is None:
                return None
            return value != isinstance(op, ast.IsNot)
        case ast.Call(func=ast.Name('isinstance'), args=[obj, cls]):
            tp, klass = exact_type(obj, env), builtin_type(cls)
            other = env.get(obj.id) if isinstance(obj, ast.Name) else None
            if isinstance(other, Other) and klass in other.instances:
                return False
            mro = tp and klass and ev.types.mro(tp)
            return klass in mro if mro else None
        case ast.Call(func=ast.Name('hasattr'), args=[type_call, name]) \
                if is_type_call(type_call):
            assert isinstance(type_call, ast.Call)
            attr = getattr(arg_fact(name, env), 'obj', None)
            if not isinstance(attr, str):
                return None
            return ev.types.has(exact_type(type_call.args[0], env), attr)
        case ast.Name(name) if isinstance(env.get(name), Value):
            return bool(getattr(env[name], 'obj'))
    return None


def _evaluate_is(left: ast.expr, right: ast.expr, env: Env,
                 ev: Evaluator) -> bool | None:
    right_is_null = isinstance(right, ast.Name) and right.id == 'NULL'
    if right_is_null and isinstance(left, ast.Name):
        value = env.get(left.id)
        if value == NULL:
            return True
        if value == NOTNULL or isinstance(value, (type, Value, IterOf,
                                                  Other)):
            return False
        return None
    if isinstance(left, ast.Name) and isinstance(env.get(left.id), Value):
        klass = builtin_type(right)
        if klass is None:
            return None
        return getattr(env[left.id], 'obj') is klass
    if right_is_null and isinstance(left, ast.NamedExpr):
        if isinstance(left.value, ast.Call) and _only_null(
                ev.analyzer.call_facts(left.value, env)):
            return True
        return None
    if isinstance(left, ast.Call) and is_type_call(left):
        tp, klass = exact_type(left.args[0], env), builtin_type(right)
        if klass is None:
            return None
        if tp is None:
            other = (env.get(left.args[0].id)
                     if isinstance(left.args[0], ast.Name) else None)
            if isinstance(other, Other) and (klass in other.types
                                             or klass in other.instances):
                return False
            return None
        return tp is klass
    return None


def simplify(expr: ast.expr, env: Env, ev: Evaluator) -> bool | ast.expr:
    """*expr* without the parts *env* decides: True, False or an ast
    node."""
    value = evaluate(expr, env, ev)
    if value is not None:
        return value
    if isinstance(expr, ast.BoolOp):
        parts = [simplify(v, env, ev) for v in expr.values]
        keep = isinstance(expr.op, ast.Or)     # False parts of an or go
        parts = [p for p in parts if p is not (not keep)]
        if len(parts) == 1:
            return parts[0]
        # (A part the facts decide decides the whole, or goes.)
        return ast.BoolOp(expr.op, cast(list[ast.expr], parts))
    return expr


def _type_test(name: str, klass: type) -> ast.expr:
    """``type(name) is klass``"""
    return ast.Compare(
        left=ast.Call(func=ast.Name('type', ast.Load()),
                      args=[ast.Name(name, ast.Load())], keywords=[]),
        ops=[ast.Is()], comparators=[ast.Name(klass.__name__, ast.Load())])


def _iter_assignment(stmt: ast.stmt) -> tuple[str, str] | None:
    """(target, source) for ``target = iter(source)`` or for ``try:
    target = iter(source)`` with only ``except TypeError`` handlers, else
    None."""
    if isinstance(stmt, ast.Try) and not stmt.finalbody and set(
            facts.caught(stmt.handlers)) == {'TypeError'} \
            and len(stmt.body) == 1:
        stmt = stmt.body[0]
    match stmt:
        case ast.Assign(targets=[ast.Name(target)], value=ast.Call(
                func=ast.Name('iter'), args=[ast.Name(source)])):
            return target, source
    return None


def _index_loops(stmts: list[ast.stmt]) -> set[str]:
    """The names iterated by index in *stmts*, directly or by the
    specializations called."""
    names = set()
    for stmt in stmts:
        for node in ast.walk(stmt):
            loop = marks.get(node, marks.Loop)
            if (loop and loop.by_index and isinstance(node, ast.For)
                    and isinstance(node.iter, ast.Name)):
                names.add(node.iter.id)
            mark = marks.get(node, marks.Specialized)
            if mark and mark.called and isinstance(node, ast.Call):
                called = mark.special
                names.update(arg.id for param, arg in zip(called.params,
                                                          node.args)
                             if param in called.index_params
                             and isinstance(arg, ast.Name))
    return names


def _top_call(stmt: ast.stmt) -> ast.Call | None:
    """The call *stmt* makes at its top level: ``x = f()``, ``f()``,
    ``return f()`` or ``try: x = f()``."""
    match stmt:
        case (ast.Assign(value=ast.Call() as call)
              | ast.Expr(value=ast.Call() as call)
              | ast.Return(value=ast.Call() as call)
              | ast.Try(body=[ast.Assign(value=ast.Call() as call)])):
            return call
    return None


def _with_call(stmt: ast.stmt, value: ast.expr) -> ast.stmt:
    """A copy of *stmt* with *value* in place of its top level call (for
    ``try: x = f()``, the try statement)."""
    stmt = copy.deepcopy(stmt)
    holder = stmt.body[0] if isinstance(stmt, ast.Try) else stmt
    if isinstance(holder, ast.Expr) and not isinstance(value, ast.Call):
        return ast.Pass()
    assert isinstance(holder, (ast.Assign, ast.Expr, ast.Return))
    holder.value = value
    return stmt


def inline_paths(spec: Spec, name: str
                 ) -> tuple[list[tuple[ast.expr, ast.expr]], ast.expr,
                            list[str]]:
    """([(test, value)], last value, parameters) of @inline function
    *name* of *spec*: its fast paths ``if test: return value``, then its
    ``return value`` (subset.Inline, which check_inline() checks)."""
    subset.check_inline(spec, name)
    *paths, last = spec.body(name)
    out = []
    for stmt in paths:
        assert isinstance(stmt, ast.If)
        path = stmt.body[0]
        assert isinstance(path, ast.Return) and path.value is not None
        out.append((stmt.test, path.value))
    assert isinstance(last, ast.Return) and last.value is not None
    return out, last.value, spec.params(name)


class _Rename(ast.NodeTransformer):
    def __init__(self, mapping: dict[str, ast.expr]) -> None:
        self.mapping = mapping

    def visit_Name(self, node: ast.Name) -> ast.expr:
        replacement = self.mapping.get(node.id)
        if replacement is None:
            return node
        new = copy.deepcopy(replacement)
        if isinstance(new, ast.Name):
            new.ctx = node.ctx
        return ast.copy_location(new, node)


def _mark_len(node: ast.AST, env: Env) -> None:
    """Mark the ``len(x)`` calls in *node* with the exact type of x, when
    its size is read inline (builtin_types.Row.size)."""
    for child in ast.walk(node):
        match child:
            case ast.Call(func=ast.Name('len'), args=[arg]):
                tp = exact_type(arg, env)
                if tp is not None and builtin_types.TABLE[tp].size:
                    marks.put(child, marks.Length(tp))


@dc.dataclass
class _Block:
    """The state of the evaluation of a block: its statements (the rest
    may be rewritten), the index of the next one, the facts, the residual
    so far, and *done* when the rest has been evaluated (versioned)."""
    stmts: list[ast.stmt]
    env: Env
    depth: int
    inline: bool
    out: list[ast.stmt] = dc.field(default_factory=list)
    i: int = 0
    done: bool = False

    def evaluated(self, stmts: list[ast.stmt], env: Env | None = None
                  ) -> None:
        self.out += stmts
        if env is not None:
            self.env = env


class Evaluator(subset.Walker[_Block, None]):
    """Partial evaluation of the code of one spec (see the module
    docstring); one method per kind of statement (subset.Kind)."""

    def __init__(self, context: Context, spec: Spec,
                 arities: Sequence[Arity] = (),
                 function: str | None = None) -> None:
        self.context = context
        self.spec = spec
        self.types = context.types(spec)
        self.analyzer = context.analyzer(spec)
        self._suffix = itertools.count(1)
        # The __new__ evaluated, and the (facts, C function, arguments)
        # of its arity functions: see arity_call() and dispatch().
        self.arities = arities
        self.function = function

    def block(self, stmts: Sequence[ast.stmt], env: Env, depth: int = 0,
              inline: bool = True, top: bool = False) -> list[ast.stmt]:
        """*stmts* evaluated under *env*.  *inline*: tail calls of spec
        functions are inlined (or call specializations); *top*: *stmts*
        is a whole function body (see arity_call())."""
        state = _Block(list(stmts), env, depth, inline)
        while state.i < len(state.stmts) and not state.done:
            if top and state.i and self.arities:
                call = self.arity_call(state.stmts, state.i, state.env)
                if call is not None:
                    state.out += call
                    break
            stmt = state.stmts[state.i]
            state.i += 1
            self.statement(stmt, state)
            if terminates(state.out):
                break
        return state.out

    def arity_call(self, stmts: list[ast.stmt], i: int,
                   env: Env) -> list[ast.stmt] | None:
        """``[return F(args)]`` when the rest of a function body,
        stmts[i:], under *env*, is the whole body under the facts of the
        arity function F (NAME_nargsN(), emit.py): the facts about the
        parameters are the same, and stmts[:i] do nothing under them."""
        for facts_, c_name, args in self.arities:
            if any(fact_key(env.get(p)) != fact_key(fact)
                   for p, fact in facts_.items()):
                continue
            if Evaluator(self.context, self.spec).block(
                    copy.deepcopy(stmts[:i]), facts_):
                continue
            call = ast.Call(ast.Name(c_name, ast.Load()),
                            [ast.Name(a, ast.Load()) for a in args], [])
            marks.put(call, marks.ArityCall(c_name))
            return [ast.Return(call, lineno=0)]
        return None

    # -- statements (subset.Kind) ------------------------------------------

    def other(self, stmt: ast.stmt, state: _Block) -> None:
        """pass, raise: as is, its calls marked."""
        self.mark(stmt, state.env)
        state.evaluated([stmt])

    def if_(self, stmt: ast.If, state: _Block) -> None:
        env, depth, inline = state.env, state.depth, state.inline
        value = evaluate(stmt.test, env, self)
        if value is True:
            left = getattr(stmt.test, 'left', None)
            if isinstance(left, ast.NamedExpr):
                state.evaluated([ast.Assign([left.target], left.value,
                                            lineno=0)])
            state.evaluated(self.block(stmt.body, env, depth, inline))
            return
        if value is False:
            state.evaluated(self.block(stmt.orelse, env, depth, inline))
            return
        body_env, else_env = refine(stmt.test, env)
        stmt = copy.copy(stmt)
        self.mark(stmt.test, env)
        stmt.body = (self.block(stmt.body, body_env, depth, inline)
                     or [ast.Pass()])
        stmt.orelse = self.block(stmt.orelse, else_env, depth, inline)
        state.evaluated([stmt])
        # After an if whose one branch exits, the facts of the other
        # hold.
        if terminates(stmt.body):
            state.env = else_env
        elif terminates(stmt.orelse):
            state.env = body_env

    def assign(self, stmt: ast.Assign, state: _Block) -> None:
        if not self.iteration(stmt, state):
            state.evaluated(*self.c_statement(stmt, state.env))

    def call_(self, stmt: ast.Expr, state: _Block) -> None:
        state.evaluated(*self.c_statement(stmt, state.env))

    def return_(self, stmt: ast.Return, state: _Block) -> None:
        call = stmt.value
        if (state.inline and isinstance(call, ast.Call)
                and self.spec.call_target(call.func) is not None
                and state.depth < MAX_INLINE_DEPTH):
            state.evaluated(self.inline(call, state.env, state.depth))
        else:
            state.evaluated(*self.c_statement(stmt, state.env))

    def try_(self, stmt: ast.Try, state: _Block) -> None:
        """``try: x = <call>`` / ``except E:`` ... / ``else:`` ..."""
        if self.iteration(stmt, state):
            return
        env = state.env
        raises = self.analyzer.facts(stmt.body, env)
        if not raises.raises_any(facts.caught(stmt.handlers)):
            # No handler can run.
            state.stmts[state.i:state.i] = [stmt.body[0], *stmt.orelse]
            return
        stmt = copy.deepcopy(stmt)
        # Handlers and else clauses are cold: keep calls as calls.
        for handler in stmt.handlers:
            handler.body = self.block(handler.body, env, state.depth, False)
        stmt.orelse = self.block(stmt.orelse, env, state.depth, False)
        state.evaluated(*self.c_statement(stmt, env))

    def finally_(self, stmt: ast.Try, state: _Block) -> None:
        """``try:`` ... ``finally: <release>``"""
        stmt = copy.copy(stmt)
        stmt.body = self.block(stmt.body, state.env, state.depth,
                               state.inline)
        stmt.finalbody = copy.deepcopy(stmt.finalbody)
        state.evaluated([stmt])

    def with_(self, stmt: ast.With, state: _Block) -> None:
        stmt = copy.deepcopy(stmt)
        stmt.body = self.block(stmt.body, state.env, state.depth, False)
        state.evaluated([stmt])

    def for_(self, stmt: ast.For, state: _Block) -> None:
        state.evaluated([self.loop(stmt, state.env, state.depth,
                                   state.inline)])

    def iteration(self, stmt: ast.Assign | ast.Try, state: _Block) -> bool:
        """``it = iter(x)`` (possibly in a try): for x of a known exact
        type whose iteration runs no Python code, the iterator stands for
        x (IterOf), and the assignment is dead unless *it* is used
        (marks.PureIter); for x of an unknown type, the rest of the block
        is versioned.  Whether *stmt* was evaluated."""
        found = _iter_assignment(stmt)
        if found is None:
            return False
        target, source = found
        tp = state.env.get(source)
        if (isinstance(stmt, ast.Assign) and isinstance(tp, type)
                and self.analyzer.iteration(tp)[0]):
            assign = copy.deepcopy(stmt)
            marks.put(assign, marks.PureIter())
            state.evaluated([assign], state.env | {target: IterOf(source,
                                                                   tp)})
            return True
        if self.can_version(state.env, source):
            versioned = self.version(source,
                                     [stmt, *state.stmts[state.i:]],
                                     state.env, state.depth, state.inline)
            if versioned is not None:
                state.evaluated(versioned)
                state.done = True
                return True
        return False

    # -- calls ---------------------------------------------------------------

    def c_statement(self, stmt: ast.stmt, env: Env
                    ) -> tuple[list[ast.stmt], Env]:
        """*stmt* (see _top_call()) with the facts of its call of a
        @native function, or its call of an @inline function
        expanded: (statements, env).  See "Calls of hand-written C
        functions" and "Calls of @inline functions" in the module
        docstring."""
        call = _top_call(stmt)
        if call is None:
            return [stmt], env
        inline = self.spec.inline_function(call)
        if inline:
            return self.expand(stmt, call, inline, env), env
        if self.arities and self.spec.call_target(call.func) == self.function:
            return self.dispatch(stmt, call, env), env
        if not self.spec.c_function(call):
            return [stmt], env
        callee = self.analyzer.mark_call(call, env)
        if isinstance(stmt, ast.Assign) and _only_null(callee):
            return [], env | {ast.unparse(stmt.targets[0]): NULL}
        return [stmt], env

    def dispatch(self, stmt: ast.stmt, call: ast.Call,
                 env: Env) -> list[ast.stmt]:
        """*stmt*, whose call *call* calls the __new__ evaluated (``T.
        __new__(T, ...)``), as the vectorcall of T would call it: under
        ``if`` tests of which arguments are NULL, the call of the arity
        function (NAME_nargsN()) whose facts they are, and else *call*."""
        args = subset.call_arguments(self.spec, self.function or '', call)
        params = self.spec.params(self.function or '')
        out = [stmt]
        for facts_, c_name, given in reversed(self.arities):
            tests: list[ast.expr] = []
            for param, arg in zip(params, args):
                want, have = facts_[param], arg_fact(arg, env)
                if fact_key(want) == fact_key(have) or (
                        want is NOTNULL and have not in (None, NULL)):
                    continue
                if not (want in (NULL, NOTNULL) and have is None
                        and isinstance(arg, ast.Name)):
                    break       # not the facts of this arity function
                tests.append(ast.Compare(
                    arg, [ast.Is() if want is NULL else ast.IsNot()],
                    [ast.Name('NULL', ast.Load())]))
            else:
                arity = ast.Call(ast.Name(c_name, ast.Load()),
                                 [args[params.index(p)] for p in given], [])
                marks.put(arity, marks.ArityCall(c_name))
                body = [_with_call(stmt, arity)]
                out = body if not tests else [ast.copy_location(ast.If(
                    tests[0] if len(tests) == 1
                    else ast.BoolOp(ast.And(), tests), body, out), stmt)]
        return out

    def mark(self, node: ast.AST, env: Env) -> None:
        """Mark the calls of @native functions in *node* (a
        condition or a raise) with their facts for the emitter
        (facts.Analyzer.mark_call())."""
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                self.analyzer.mark_call(child, env)

    def expand(self, stmt: ast.stmt, call: ast.Call,
               found: tuple[Spec, ast.FunctionDef],
               env: Env) -> list[ast.stmt]:
        """*stmt*, which calls @inline function *found* (spec, def) as
        *call*, with its body in place of the call (see "Calls of @inline
        functions" in the module docstring).  The ``if`` of the first
        path is marked (marks.FirstPath, see presize())."""
        spec, node = found
        paths, last, params = inline_paths(spec, node.name)
        rename = _Rename(dict(zip(params, call.args)))
        first = call.args[0] if call.args else None

        def copied(expr: ast.expr) -> ast.expr:
            new = cast(ast.expr, rename.visit(copy.deepcopy(expr)))
            marks.scoped(new, spec.filename)
            return new

        def with_value(value: ast.expr, env: Env) -> list[ast.stmt]:
            new = _with_call(stmt, copied(value))
            if isinstance(new, ast.Try) and not self.analyzer.facts(
                    new.body, env).raises_any(facts.caught(new.handlers)):
                parts = [new.body[0], *new.orelse]     # no handler runs
            else:
                parts = [new]
            out = []
            for part in parts:
                _mark_len(part, env)
                out += self.c_statement(part, env)[0]
            return out

        def paths_from(i: int, env: Env) -> list[ast.stmt]:
            if i == len(paths):
                return with_value(last, env)
            test, value = paths[i]
            decided = simplify(copied(test), env, self)
            if decided is False:
                return paths_from(i + 1, env)
            if decided is True:
                return with_value(value, env)
            assert isinstance(decided, ast.expr)
            body_env, else_env = refine(decided, env)
            branch = ast.copy_location(
                ast.If(decided, with_value(value, body_env),
                       paths_from(i + 1, else_env)), stmt)
            if i == 0:
                marks.put(branch, marks.FirstPath(
                    first.id if isinstance(first, ast.Name) else None))
            return [branch]
        return paths_from(0, env)

    def inline(self, call: ast.Call, env: Env,
               depth: int) -> list[ast.stmt]:
        outlined = self.outline(call, env, depth)
        if outlined is not None:
            return outlined
        name = self.spec.call_target(call.func)
        assert name is not None
        params = self.spec.params(name)
        body = self.spec.body(name)
        mapping: dict[str, ast.expr] = dict(zip(
            params, subset.call_arguments(self.spec, name, call)))
        suffix = next(self._suffix)
        for local in assigned_names(body) - set(params):
            mapping[local] = ast.Name(f'{local}_{suffix}', ast.Load())
        body = [_Rename(mapping).visit(copy.deepcopy(s)) for s in body]
        return self.block(body, env, depth + 1)

    def outline(self, call: ast.Call, env: Env,
                depth: int) -> list[ast.stmt] | None:
        """``[return <call of a Specialization>]`` for a tail call of a
        spec function whose residual for the facts of the call has a
        loop, else None."""
        name = self.spec.call_target(call.func)
        assert name is not None
        params = self.spec.params(name)
        if ('.' in name or len(call.args) != len(params)
                or not all(isinstance(a, ast.Name) for a in call.args)):
            return None
        args = [ast.unparse(a) for a in call.args]
        callee_env: Env = {}
        for param, arg in zip(params, args):
            fact = env.get(arg)
            if isinstance(fact, IterOf):
                fact = (IterOf(params[args.index(fact.source)], fact.tp)
                        if fact.source in args else NOTNULL)
            if fact is not None:
                callee_env[param] = fact
        special = self.context.specializations(self.spec).make(
            self.context, self.spec, name, callee_env, depth + 1)
        if special is None:
            return None
        if not special.index_params:
            # Not worth its own code: the generic function, with the
            # facts of the specialization.
            call = copy.copy(call)
            marks.put(call, marks.Specialized(special, called=False))
            return [ast.Return(call, lineno=0)]
        return [ast.Return(special.call([call.args[params.index(p)]
                                         for p in special.params]),
                           lineno=0)]

    # -- loops ---------------------------------------------------------------

    @staticmethod
    def can_version(env: Env, name: str) -> bool:
        value = env.get(name)
        return not (value == NULL or isinstance(value, (type, Value, IterOf)))

    def version(self, name: str, tail: list[ast.stmt], env: Env,
                depth: int, inline: bool) -> list[ast.stmt] | None:
        """*tail*, which starts iterating *name* (of unknown type),
        specialized for each exact type of VERSIONED_ITERABLES that gives
        an index loop, and kept generic for the other types, as a chain of
        ``if type(name) is K:``; None if no type gives an index loop."""
        known = env.get(name)
        other = known if isinstance(known, Other) else Other()
        branches = []
        for tp in VERSIONED_ITERABLES:
            if tp in other.types:
                continue
            residual = self.block(copy.deepcopy(tail), env | {name: tp},
                                  depth, True)
            if name in _index_loops(residual):
                branches.append((tp, residual))
        if not branches:
            return None
        other = dc.replace(other, types=(*other.types,
                                         *(tp for tp, _ in branches)))
        out = self.block(tail, env | {name: other}, depth, inline)
        for tp, residual in reversed(branches):
            out = [ast.copy_location(ast.If(_type_test(name, tp), residual,
                                            out), tail[0])]
        return out

    def loop(self, stmt: ast.For, env: Env, depth: int,
             inline: bool) -> ast.For:
        """``for item in it:``, specialized: see the module docstring.
        The copy is marked (marks.Loop) with the exact type of the
        iterated object (None if unknown), and whether it iterates a list
        or tuple by index (``for item in x:``)."""
        if (stmt.orelse or not isinstance(stmt.target, ast.Name)
                or not isinstance(stmt.iter, ast.Name)):
            raise ValueError(f'unsupported loop {ast.unparse(stmt)}')
        item = stmt.target.id
        new = copy.copy(stmt)
        fact = env.get(stmt.iter.id)
        iterable = None
        sequence = False
        if isinstance(fact, IterOf):
            iterable = fact.tp
            if iterable in SEQUENCES:
                new.iter = ast.Name(fact.source, ast.Load())
                sequence = True
        elif isinstance(fact, type) and fact in SEQUENCES:
            iterable = fact
            sequence = True
        item_type: Fact = self.analyzer.iteration(iterable)[1] or NOTNULL
        new.body = self.block(stmt.body, env | {item: item_type}, depth,
                              inline)
        marks.put(new, marks.Loop(iterable, sequence))
        return new


# -- shared specializations (see the module docstring) -----------------------

class Specializations:
    """The shared specializations of one spec, made once per (callee,
    facts), found by name; the context of the passes keeps them."""

    def __init__(self) -> None:
        self._made: dict[Hashable, Specialization | None] = {}
        self._named: dict[str, Specialization] = {}

    def __getitem__(self, name: str) -> Specialization:
        """The Specialization called *name*."""
        return self._named[name]

    def add(self, special: Specialization) -> None:
        self._named[special.name] = special

    def unique_name(self, base: str) -> str:
        name, suffix = base, itertools.count(2)
        while name in self._named:
            name = f'{base}_{next(suffix)}'
        return name

    def make(self, context: Context, spec: Spec, callee: str, env: Env,
             depth: int = 0) -> Specialization | None:
        """The Specialization of spec function *callee* for the facts
        *env* about its parameters, or None when its residual has no loop
        (the call is inlined instead)."""
        params = spec.params(callee)
        key = (callee, tuple((p, fact_key(env.get(p))) for p in params))
        if key in self._made:
            return self._made[key]
        self._made[key] = None      # while evaluating: recursion inlines
        body = Evaluator(context, spec).block(spec.body(callee), env, depth)
        # A private copy: the residual shares nodes with the spec, and the
        # snapshot and presize() change them.
        body = copy.deepcopy(remove_dead_iterators(body))
        if not any(isinstance(node, ast.For)
                   for stmt in body for node in ast.walk(stmt)):
            return None
        type_names = [fact.__name__ for p in params
                      if isinstance(fact := env.get(p), type)]
        name = self.unique_name('_'.join([callee, *type_names]))
        special = _snapshot(context, spec, callee, name, params, env, body)
        if special is None:
            presize(spec, body)
            loaded = loaded_names(body)
            special = Specialization(name, callee,
                                     [p for p in params if p in loaded],
                                     env, body)
            special.index_params = _index_loops(body) & set(special.params)
        self._made[key] = special
        self.add(special)
        return special


def _snapshot(context: Context, spec: Spec, callee: str, name: str,
              params: list[str], env: Env,
              body: list[ast.stmt]) -> Specialization | None:
    """For a *body* iterating one list parameter by index: the
    Specialization *name* that calls NAME_lock_held(), the snapshot of
    *body*, in the critical section of the list, and on FALLBACK restarts
    with the generic callee.  None when the body is not a list loop or has
    no path without Python code."""
    loops = [node for stmt in body for node in ast.walk(stmt)
             if isinstance(node, ast.For)]
    match loops:
        case [ast.For(iter=ast.Name(seq)) as loop] if (
                (mark := marks.get(loop, marks.Loop)) is not None
                and mark.by_index and mark.iterable is list
                and seq in params):
            pass
        case _:
            return None
    snapshot = _Snapshot(context.analyzer(spec), loop)
    free = snapshot.block(body, env)
    if free is None or not snapshot.returns:
        return None
    presize(spec, free)
    loaded = loaded_names(free)
    held = Specialization(f'{name}_lock_held', callee,
                          [p for p in params if p in loaded], env, free,
                          lock=seq)
    held.index_params = {seq}
    context.specializations(spec).add(held)

    # The arguments of the restart: an iterator iter(p) of a parameter p
    # is made again.
    rebuilt = {p: fact.source for p in params
               if isinstance(fact := env.get(p), IterOf)
               and p not in held.params and fact.source in params}
    result = 'result'
    for i in itertools.count(2):
        if result not in params:
            break
        result = f'result_{i}'

    def load(n: str) -> ast.Name:
        return ast.Name(n, ast.Load())

    def store(n: str) -> ast.Name:
        return ast.Name(n, ast.Store())

    lock = ast.Call(load('critical_section'), [load(seq)], [])
    glue: list[ast.stmt] = [
        ast.With([ast.withitem(lock)],
                 [ast.Assign([store(result)],
                             held.call([load(p) for p in held.params]),
                             lineno=0)],
                 lineno=0),
        ast.If(ast.Compare(load(result), [ast.IsNot()],
                           [load(FALLBACK.value)]),
               [ast.Return(load(result))], []),
        *[ast.Assign([store(p)], ast.Call(load('iter'), [load(source)], []),
                     lineno=0)
          for p, source in rebuilt.items()],
        ast.Return(ast.Call(load(callee), [load(p) for p in params], [])),
    ]
    special = Specialization(name, callee,
                             [p for p in params if p not in rebuilt], env,
                             glue)
    special.index_params = {seq}
    return special


@dc.dataclass
class _Path:
    """The state of the snapshot of a path: the facts, and whether it is
    in the loop."""
    env: Env
    in_loop: bool = False


class _Snapshot(subset.Walker[_Path, list[ast.stmt] | None]):
    """The snapshot of a list loop: see _snapshot().  A statement maps to
    the statements of the snapshot, or None when it may run Python code
    outside the loop (there is no snapshot)."""

    def __init__(self, analyzer: facts.Analyzer, loop: ast.For) -> None:
        self.analyzer = analyzer
        self.loop = loop
        self.returns = False        # some path returns a result

    def runs_python(self, stmts: list[ast.stmt], env: Env) -> bool:
        return self.analyzer.facts(stmts, env).runs_python

    def block(self, stmts: list[ast.stmt], env: Env,
              in_loop: bool = False) -> list[ast.stmt] | None:
        """*stmts* with the statements that may run Python code replaced
        by ``return FALLBACK``; None if one is outside the loop."""
        out: list[ast.stmt] = []
        for stmt in stmts:
            new = self.statement(stmt, _Path(env, in_loop))
            if new is None:
                return None
            out += new
            if terminates(out):
                break
        return out

    def other(self, stmt: ast.stmt, path: _Path) -> list[ast.stmt] | None:
        if not self.runs_python([stmt], path.env):
            return [stmt]
        if not path.in_loop:
            return None
        return [ast.Return(ast.Name(FALLBACK.value, ast.Load()))]

    def return_(self, stmt: ast.Return,
                path: _Path) -> list[ast.stmt] | None:
        new = self.other(stmt, path)
        if new is not None and new[0] is stmt:
            self.returns = True
        return new

    def if_(self, stmt: ast.If, path: _Path) -> list[ast.stmt] | None:
        if self.runs_python([ast.If(stmt.test, [ast.Pass()], [])],
                            path.env):
            return self.other(stmt, path)
        body_env, else_env = refine(stmt.test, path.env)
        new = copy.copy(stmt)
        body = self.block(stmt.body, body_env, path.in_loop)
        orelse = self.block(stmt.orelse, else_env, path.in_loop)
        if body is None or orelse is None:
            return None
        new.body, new.orelse = body or [ast.Pass()], orelse
        return [new]

    def finally_(self, stmt: ast.Try,
                 path: _Path) -> list[ast.stmt] | None:
        if self.runs_python(stmt.finalbody, path.env):
            return None
        new = copy.copy(stmt)
        body = self.block(stmt.body, path.env, path.in_loop)
        if body is None:
            return None
        new.body = body
        return [new]

    def for_(self, stmt: ast.For, path: _Path) -> list[ast.stmt] | None:
        if stmt is not self.loop:
            return self.other(stmt, path)
        new = copy.copy(stmt)
        body = self.block(stmt.body, path.env, True)
        if body is None:
            return None
        new.body = body
        mark = marks.get(stmt, marks.Loop)
        assert mark is not None
        marks.put(new, dc.replace(mark, snapshot=True))
        return [new]


def presize(spec: Spec, stmts: list[ast.stmt]) -> None:
    """Take the first path of the @inline calls that write to a buffer
    that has room for all of them: see Capacity in the module docstring.
    The top level of *stmts* (a function body, and the body of its try)
    is scanned."""
    lengths = {}            # local -> the sequence it is the length of
    capacity: dict[str, str] = {}   # buffer local -> the sequence it has
    for stmt in stmts:              # room for
        match stmt:
            case ast.Assign(targets=[ast.Name(target)],
                            value=ast.Call(args=[ast.Name(arg)]) as call):
                found = spec.c_function(call)
                if marks.get(call, marks.Length):       # len(arg)
                    lengths[target] = arg
                    continue
                if (arg in lengths and found
                        and frontend.is_native(found[1])
                        and subset.is_struct(
                            subset.c_signature(found[1])[1])):
                    capacity[target] = lengths[arg]     # init(len(seq))
                    continue
            case ast.Try(finalbody=[_, *_], handlers=[]):
                # The release in the finally clause runs after the loop.
                _presize_loops(stmt.body, capacity)
                continue
        _presize_loops([stmt], capacity)
        loaded = loaded_names([stmt])
        capacity = {b: q for b, q in capacity.items() if b not in loaded}


def _presize_loops(stmts: list[ast.stmt], capacity: dict[str, str]) -> None:
    for stmt in stmts:
        mark = marks.get(stmt, marks.Loop)
        match stmt:
            case ast.For(iter=ast.Name(seq)) if mark and mark.by_index and (
                    mark.iterable is tuple or mark.snapshot):
                inner = [node for part in stmt.body
                         for node in ast.walk(part)]
                if any(isinstance(node, ast.For) for node in inner):
                    continue
                for buffer, sequence in capacity.items():
                    writes = [node for node in inner
                              if _writes(node, buffer)]
                    if sequence != seq or len(writes) != 1:
                        continue
                    # The one use of the buffer in the loop.
                    within = {id(node) for node in ast.walk(writes[0])}
                    if any(isinstance(node, ast.Name) and node.id == buffer
                           and id(node) not in within for node in inner):
                        continue
                    # Its first path, in place, without its test.
                    first = writes[0]
                    assert isinstance(first, ast.If)
                    _replace(stmt.body, first, first.body)


def _writes(node: ast.AST, buffer: str) -> bool:
    """Whether *node* is the ``if`` of the first path of an @inline call
    (expand()) whose first argument is *buffer*."""
    mark = marks.get(node, marks.FirstPath)
    return isinstance(node, ast.If) and mark is not None \
        and mark.buffer == buffer


def _replace(stmts: list[ast.stmt], old: ast.stmt,
             new: list[ast.stmt]) -> bool:
    """Replace statement *old*, in *stmts* or in a block nested in them,
    with the statements *new*; return whether it was found."""
    for i, stmt in enumerate(stmts):
        if stmt is old:
            stmts[i:i + 1] = new
            return True
        if any(_replace(block, old, new) for block in subset.blocks(stmt)):
            return True
    return False


def remove_dead_iterators(stmts: list[ast.stmt],
                          live: frozenset[str] = frozenset()
                          ) -> list[ast.stmt]:
    """Remove the ``it = iter(x)`` marked pure (x of a type whose iter()
    only allocates) when *it* is not used afterwards.  *live*: the names
    used after *stmts*."""
    out = []
    alive = set(live)
    for stmt in reversed(stmts):
        if (marks.get(stmt, marks.PureIter)
                and isinstance(stmt, ast.Assign)
                and ast.unparse(stmt.targets[0]) not in alive):
            continue
        after = frozenset(alive | (loaded_names([stmt])
                                   if isinstance(stmt, ast.For) else set()))
        for field in ('body', 'orelse', 'finalbody'):
            block = getattr(stmt, field, None)
            if isinstance(block, list) and block:
                block = remove_dead_iterators(block, after)
                if not block and field == 'body':
                    block = [ast.Pass()]
                setattr(stmt, field, block)
        for handler in getattr(stmt, 'handlers', ()):
            handler.body = remove_dead_iterators(handler.body, after)
        if isinstance(stmt, ast.Assign):
            alive -= {target.id for target in stmt.targets
                      if isinstance(target, ast.Name)}
        alive |= loaded_names([stmt])
        out.append(stmt)
    out.reverse()
    return out


def specialize(context: Context, spec: Spec, name: str, env: Env,
               inline: bool = True,
               arities: Sequence[Arity] = ()) -> list[ast.stmt]:
    """Residual statements of spec function *name* of *spec* under facts
    *env* (see context.Context.residual()).

    With *inline* false, tail calls of other spec functions stay calls,
    except where the block is versioned.  *arities*: (facts, C function,
    arguments) of the arity functions of a __new__ (see
    Evaluator.arity_call())."""
    residual = Evaluator(context, spec, arities, name).block(
        spec.body(name), env, inline=inline, top=True)
    return remove_dead_iterators(residual)

"""Facts derived from the bodies of a spec.

The facts of statements (Facts) are what their paths do: per ``return``
the exact type of the result and the argument it returns, if any
(``return NULL`` is an absent result, not an error); whether some path
may run Python code; which exceptions some path may raise.

They come from the statements only.  A spec function called is analysed
in turn, an @inline one through its body and a @native one through its
Python reference, each partially evaluated for the facts of the call
(partial_eval.py, through context.py).  In a reference, only the
primitives (runtime.py) and the calls of C and spec functions have
effects: the rest models the values the C computes.  ``calls(x,
"__name__")``, ``len(x)`` and ``iter(x)`` run what the special method of
type(x) runs (builtin_types.TypeFacts); a call of an object and a
function about which nothing is known may do anything.

Anything outside what this follows (subset.py) has the worst facts: any
result, NULL or not, may raise anything, may run Python code.  Nothing
here fails on a construct it does not know.
"""

from __future__ import annotations

import ast
import builtins
import dataclasses as dc
from collections.abc import Callable, Hashable, Iterable, Sequence
from typing import TYPE_CHECKING, Protocol, TypeVar

from . import builtin_types, frontend, known, marks, subset
from .known import Env

if TYPE_CHECKING:
    from .frontend import Spec

# Raises any exception.
ANY = 'ANY'

# The builtins whose calls have no effects.
PURE_BUILTINS = ('isinstance', 'hasattr', 'type', 'tp_name', 'fqname')


class Facts:
    """The facts of statements; with *worst*, those of code about which
    nothing is known."""

    def __init__(self, worst: bool = False) -> None:
        # Per return: (exact type, index of the argument returned).
        self.returns: list[tuple[type | None, int | None]] = (
            [(None, None)] if worst else [])
        self.returns_null = worst
        self.runs_python = worst
        self.raises: set[str] = {ANY} if worst else set()

    def add(self, other: Facts) -> None:
        """The effects of *other* (a call) happen here."""
        self.runs_python |= other.runs_python
        self.raises |= other.raises

    def python(self) -> None:
        """Python code may run here, and raise anything."""
        self.add(Facts(worst=True))

    @property
    def always_raises(self) -> bool:
        return not self.returns and not self.returns_null

    @property
    def result_type(self) -> type | None:
        return _only({tp for tp, _ in self.returns})

    @property
    def alias(self) -> int | None:
        return _only({alias for _, alias in self.returns})

    def raises_any(self, names: Sequence[str]) -> bool:
        """Whether it may raise an exception that ``except names`` (the
        names of builtin exception classes) catches."""
        classes = tuple(value for name in names
                        if isinstance(value := getattr(builtins, name, None),
                                      type))
        if ANY in self.raises or len(classes) != len(names):
            return True
        return any(issubclass(getattr(builtins, raised), classes)
                   for raised in self.raises)

    def key(self) -> tuple[bool, bool, type | None, int | None]:
        return (self.runs_python, self.always_raises, self.result_type,
                self.alias)


T = TypeVar('T')


def _only(values: set[T | None]) -> T | None:
    """The one value of *values*, if it is not None."""
    return values.pop() if len(values) == 1 and None not in values else None


def caught(handlers: list[ast.ExceptHandler]) -> list[str]:
    """The exceptions *handlers* catch (another form is kept as its text:
    any exception for Facts.raises_any())."""
    out = []
    for handler in handlers:
        names = subset.handler_names(handler)
        out += names if names is not None else [ast.unparse(handler)]
    return out


def _exception_name(node: ast.expr | None, env: Env) -> str:
    """The builtin exception class ``raise node`` raises, or ANY."""
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Name):
        value = getattr(env.get(node.id), 'obj', None)
        if value is None:
            value = getattr(builtins, node.id, None)
        if isinstance(value, type) and issubclass(value, BaseException):
            return value.__name__
    return ANY


class Passes(Protocol):
    """What the analysis needs of context.Context."""

    def analyzer(self, spec: Spec | None = None) -> Analyzer: ...

    def types(self, spec: Spec | None = None) -> builtin_types.TypeFacts:
        ...

    def residual(self, spec: Spec, name: str, env: Env) -> list[ast.stmt]:
        ...


@dc.dataclass
class Flow:
    """The state of the analysis of a path; *facts* are shared by the
    paths."""
    env: Env
    facts: Facts
    params: Sequence[str] = ()
    reference: bool = False
    # The parameters assigned on the path: they no longer hold the
    # argument (no alias).
    moved: frozenset[str] = frozenset()

    def branch(self, env: Env) -> Flow:
        return dc.replace(self, env=dict(env))

    def forget(self, names: Iterable[str]) -> None:
        """Names assigned (by code whose values are not followed): no
        facts about them."""
        names = set(names)
        for name in names:
            self.env.pop(name, None)
        self.moved |= names.intersection(self.params)

    def join(self, before: Env, paths: Sequence[tuple[Flow, list[ast.stmt]]]
             ) -> None:
        """This path continues after the *paths* (a Flow, the statements
        it ran), which started from the facts *before*: of the paths that
        fall through, a name keeps a fact they all agree on, and a name
        none of them assigns keeps its fact before them."""
        through = [(flow, stmts) for flow, stmts in paths
                   if not subset.terminates(stmts)]
        if not through:
            return      # Unreachable after them.
        assigned = subset.assigned_names(
            [stmt for _, stmts in through for stmt in stmts])
        env: Env = {name: fact for name, fact in before.items()
                    if name not in assigned}
        for name in assigned:
            facts = [flow.env.get(name) for flow, _ in through]
            first = facts[0]
            if first is not None and all(fact == first for fact in facts):
                env[name] = first
        self.env = env
        self.moved = frozenset().union(*(flow.moved for flow, _ in through))


class Analyzer(subset.Walker[Flow, None]):
    """The facts of the code of one spec (one per spec, in the context)."""

    def __init__(self, context: Passes, spec: Spec) -> None:
        self.context = context
        self.spec = spec
        self.types = context.types(spec)
        self._cache: dict[Hashable, Facts] = {}

    def _cached(self, key: Hashable, compute: Callable[[], Facts]) -> Facts:
        """compute(), once; the worst while computing (recursion)."""
        if key not in self._cache:
            self._cache[key] = Facts(worst=True)
            self._cache[key] = compute()
        return self._cache[key]

    def _key(self, *prefix: Hashable, name: str, env: Env) -> Hashable:
        return (*prefix, name, *(known.fact_key(env.get(p))
                                 for p in self.spec.params(name)))

    # -- whole functions ----------------------------------------------------

    def function_facts(self, name: str,
                       special: marks.Specialization | None = None
                       ) -> Facts:
        """Facts of spec function *name* for any arguments, or of the
        Specialization *special* for its facts."""
        if special is None:
            if subset.lowered(self.spec, name):
                return Facts(worst=True)
            return self._cached(name, lambda: self.facts(
                self.spec.body(name), {}))
        return self._cached(('specialization', special.name),
                            lambda: self.facts(special.body, special.env))

    def reference_facts(self, name: str, env: Env,
                        inline: bool = False) -> Facts:
        """Facts of a call of @native function *name* with the facts *env*
        (of an @inline one, with *inline*): of its Python reference (its
        body), partially evaluated for them."""
        if (subset.inline if inline else subset.analysed)(self.spec, name):
            # Code facts.py cannot follow: the worst facts.
            return Facts(worst=True)
        return self._cached(self._key(inline, name=name, env=env),
                            lambda: self.facts(
            self.context.residual(self.spec, name, env), env,
            self.spec.params(name), reference=not inline))

    def method_facts(self, name: str, tp: type) -> Facts | None:
        """Facts of method *name* ("T.meth") for self of exact type tp; None
        for a method written in C only."""
        node = self.spec.functions[name]
        if frontend.is_stub(node):
            return None
        params = self.spec.params(name)
        env: Env = {params[0]: tp} if params else {}
        if frontend.is_native(node):
            return self.reference_facts(name, env)
        return self.facts(self.context.residual(self.spec, name, env), env,
                          params)

    def call_facts(self, call: ast.Call, env: Env) -> Facts | None:
        """Facts of *call* of a C function (@native, or ``...``: the worst)
        or of an @inline function; None when it is neither."""
        inline = self.spec.inline_function(call)
        found = inline or self.spec.c_function(call)
        if found is None:
            return None
        spec, node = found
        if not (inline or frontend.is_native(node)):
            return Facts(worst=True)
        callee_env: Env = {}
        for param, arg in zip(spec.params(node.name), call.args):
            fact = known.arg_fact(arg, env)
            if fact is not None:
                callee_env[param] = fact
        return self.context.analyzer(spec).reference_facts(
            node.name, callee_env, inline=bool(inline))

    def mark_call(self, call: ast.Call, env: Env) -> Facts | None:
        """call_facts(), and *call* marked with them (marks.CallCheck)."""
        callee = self.call_facts(call, env)
        if callee is not None:
            marks.put(call, marks.CallCheck(bool(callee.raises),
                                            callee.returns_null))
        return callee

    def facts(self, stmts: list[ast.stmt], env: Env,
              params: Sequence[str] = (), reference: bool = False) -> Facts:
        """Facts of *stmts* under *env*; *params*: the arguments, in
        order; *reference*: *stmts* are a Python reference."""
        flow = Flow(dict(env), Facts(), params, reference)
        self.block(stmts, flow)
        return flow.facts

    # -- statements ---------------------------------------------------------

    def block(self, stmts: list[ast.stmt], flow: Flow) -> None:
        for stmt in stmts:
            self.statement(stmt, flow)

    def other(self, stmt: ast.stmt, flow: Flow) -> None:
        if not flow.reference:
            flow.facts.python()
            flow.facts.returns.append((None, None))
        # (In a Python reference: the model of a value, no effects.)
        # Its values are not followed: no facts about what it assigns.
        flow.forget(subset.assigned_names([stmt]))

    def pass_(self, stmt: ast.stmt, flow: Flow) -> None:
        pass

    def if_(self, stmt: ast.If, flow: Flow) -> None:
        self.expression(stmt.test, flow)
        body_env, else_env = known.refine(stmt.test, flow.env)
        body, orelse = flow.branch(body_env), flow.branch(else_env)
        self.block(stmt.body, body)
        self.block(stmt.orelse, orelse)
        flow.join(flow.env, [(body, stmt.body), (orelse, stmt.orelse)])

    def assign(self, stmt: ast.Assign, flow: Flow) -> None:
        name = ast.unparse(stmt.targets[0])
        tp = self.value_type(stmt.value, flow)
        flow.forget([name])
        if tp is not None:
            flow.env[name] = tp

    def return_(self, stmt: ast.Return, flow: Flow) -> None:
        match stmt.value:
            case ast.Name(known.FALLBACK):
                # A snapshot restarts: the caller returns another result.
                pass
            case ast.Name('NULL'):
                flow.facts.returns_null = True
            case value:
                alias = (list(flow.params).index(value.id)
                         if isinstance(value, ast.Name)
                         and value.id in flow.params
                         and value.id not in flow.moved else None)
                flow.facts.returns.append((self.value_type(value, flow),
                                           alias))

    def raise_(self, stmt: ast.Raise, flow: Flow) -> None:
        if isinstance(stmt.exc, ast.Call) and self.spec.c_function(stmt.exc):
            self.call(stmt.exc, flow)
        else:
            # Building the message only formats type names.
            flow.facts.raises.add(_exception_name(stmt.exc, flow.env))

    def try_(self, stmt: ast.Try, flow: Flow) -> None:
        before = flow.env
        # A handler or the finally clause may start anywhere in the body:
        # without the facts of the names it assigns.
        raised = flow.branch(before)
        raised.forget(subset.assigned_names(stmt.body))
        body = flow.branch(before)
        self.block(stmt.body, body)
        self.block(stmt.orelse, body)
        paths = [(body, stmt.body + stmt.orelse)]
        for handler in stmt.handlers:
            handled = raised.branch(raised.env)
            if handler.name:
                handled.forget([handler.name])
            self.block(handler.body, handled)
            paths.append((handled, handler.body))
        if stmt.finalbody:
            # Also after an exception no handler catches: every name the
            # statement assigns may be anything.
            paths.append((raised, []))
            raised.forget(subset.assigned_names(
                [*stmt.orelse, *(stmt for handler in stmt.handlers
                                 for stmt in handler.body)]))
        flow.join(before, paths)
        self.block(stmt.finalbody, flow)

    finally_ = try_

    def with_(self, stmt: ast.With, flow: Flow) -> None:
        self.block(stmt.body, flow)

    def call_(self, stmt: ast.Expr, flow: Flow) -> None:
        assert isinstance(stmt.value, ast.Call)
        self.call(stmt.value, flow)

    def for_(self, stmt: ast.For, flow: Flow) -> None:
        if not isinstance(stmt.target, ast.Name):
            return self.other(stmt, flow)
        loop = marks.get(stmt, marks.Loop)
        is_known, item_type = self.iteration(loop.iterable if loop else None)
        if not is_known:
            flow.facts.python()
        item: known.Fact = item_type or known.NOTNULL
        # The body runs any number of times: what it assigns has no facts
        # when it starts, nor after the loop.
        flow.forget(subset.assigned_names([stmt]))
        body = flow.branch(flow.env | {stmt.target.id: item})
        self.block(stmt.body, body)
        flow.moved |= body.moved
        return None

    def expression(self, node: ast.expr, flow: Flow) -> None:
        """Account for the calls a condition makes."""
        named = [child.value for child in ast.walk(node)
                 if isinstance(child, ast.NamedExpr)]
        for child in ast.walk(node):
            if isinstance(child, ast.NamedExpr):
                self.value_type(child.value, flow)
                flow.forget([child.target.id])
            elif (isinstance(child, ast.Call)
                    and not any(child is value for value in named)
                    and not (isinstance(child.func, ast.Name)
                             and child.func.id in PURE_BUILTINS)):
                self.call(child, flow)

    def iteration(self, tp: type | None) -> tuple[bool, type | None]:
        """(iterating an object of exact type tp runs no Python code, the
        exact type of the items or None)."""
        if tp in known.SEQUENCES:
            return True, None
        special = self.types.special(tp, '__iter__')
        if special is None or special[0] is not None or special[1] in (
                False, None, builtin_types.PYTHON):
            return False, None
        items = special[1]
        return True, (items if isinstance(items, type) and items is not object
                      else None)

    # -- values -------------------------------------------------------------

    def value_type(self, node: ast.expr | None, flow: Flow) -> type | None:
        """The exact type of *node*, or None; its effects go to the
        facts of *flow*."""
        match node:
            case ast.Constant(value=value):
                return type(value)
            case ast.Name(name):
                fact = flow.env.get(name)
                return fact if isinstance(fact, type) else None
            case ast.Call():
                return self.call(node, flow)
        if not flow.reference:
            flow.facts.python()
        return None

    def call(self, node: ast.Call, flow: Flow) -> type | None:
        """Exact result type of call *node*; its effects go to the facts
        of *flow*."""
        facts, env = flow.facts, flow.env
        mark = marks.get(node, marks.Specialized)
        callee = (self.function_facts(mark.special.callee, mark.special)
                  if mark else self.call_facts(node, env))
        if callee is None and (name := self.spec.call_target(node.func)):
            callee = self.function_facts(name)      # a spec function
        if callee is not None:
            facts.add(callee)
            return callee.result_type
        name = node.func.id if isinstance(node.func, ast.Name) else None
        match name, node.args:
            case 'exact', [ast.Name(tp_name), *_]:
                facts.raises.add('MemoryError')
                return builtin_types.by_name(tp_name)
            case 'unknown', _:
                facts.raises.add('MemoryError')
            case 'runs_python', []:
                facts.python()
            case 'calls', [obj, ast.Constant(str() as special)]:
                facts.add(self.special_facts(obj, special, env))
            case 'len', [ast.Name() as obj]:
                tp = known.exact_type(obj, env)
                row = builtin_types.TABLE.get(tp) if tp else None
                if row is None or row.size is None:
                    facts.add(self.special_facts(obj, '__len__', env))
                return int
            case 'iter', [ast.Name() as obj]:
                tp = known.exact_type(obj, env)
                if self.iteration(tp)[0]:
                    facts.raises.add('MemoryError')
                elif self.types.special(tp, '__iter__') == (None, False):
                    facts.raises.add('TypeError')
                else:
                    facts.add(self.special_facts(obj, '__iter__', env))
            case _ if not (name in PURE_BUILTINS or flow.reference):
                # A call of an object: a method found, cls(result), ...
                facts.python()
            # (In a Python reference, other calls model a value.)
        return None

    def special_facts(self, obj: ast.expr, name: str, env: Env) -> Facts:
        """Facts of invoking special method *name* of type(obj)."""
        tp = known.exact_type(obj, env)
        special = self.types.special(tp, name)
        if tp is None or special is None:
            return Facts(worst=True)
        spec_name, value = special
        if spec_name is None and value is False:
            return Facts()      # no such method: nothing is called
        if spec_name is None and value != builtin_types.PYTHON:
            facts = Facts()     # audited: runs no Python code
            facts.raises.add(ANY)
            return facts
        if spec_name is not None and frontend.is_native(
                self.spec.functions[spec_name]):
            params = self.spec.params(spec_name)
            return self.reference_facts(spec_name, {params[0]: tp})
        return Facts(worst=True)

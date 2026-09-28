"""Facts derived from the bodies of a spec.

The facts of a list of statements (Facts) are what every path does:

* returns: per ``return``, the exact type of the result (or None) and
  the index of the argument it returns (or None); ``return NULL`` is an
  absent result, not an error (returns_null);
* runs_python: some path may run Python code;
* raises: the exceptions some path may raise: the names of builtin
  exception classes, or ANY.

They come from the statements only: a spec function called is analyzed
in turn, an @inline function through its body, and a @native function
through its Python reference, each partially evaluated for the facts
known about the arguments of the call (partial_eval.py, through the
context of the passes, context.py).  The primitives of runtime.py say
what plain Python cannot: exact(T) and unknown() are new objects (of
type T, or of a type not known exactly) and may fail with MemoryError;
calls(x, "__name__") runs what the special method of type(x) runs
(builtin_types.TypeFacts: the spec of the type, or the audited table of
builtin_types.py; anything else may run Python code and raise anything);
runs_python() may run Python code and raise anything.  ``len(x)`` and
``iter(x)`` call ``__len__`` and ``__iter__``.  A call of an object (a
method found, ``cls(result)``) and a function about which nothing is
known (a body of ``...``) may do anything.

In the Python reference of a @native function, what is not one of
these is the model of the values the C computes: it has no effects (the
effects of the C are the ones stated).  The c_calls dimension of
disconnects.py checks them against the C: every call in the C function
that may run Python code must be accounted for by one of them.

Anything outside the subset this analysis follows (subset.py: a body
outside the lowered subset, a reference with an effect where it is not
followed, such as a primitive in a while loop or in the argument of a
call) has the worst facts: any result, NULL or not, may raise anything,
may run Python code.  Nothing here fails on a construct it does not
know.
"""

from __future__ import annotations

import ast
import builtins
import dataclasses as dc
from collections.abc import Callable, Hashable, Sequence
from typing import TYPE_CHECKING, Protocol

from . import builtin_types, frontend, known, marks, subset
from .known import Env

if TYPE_CHECKING:
    from .frontend import Spec

# Raises any exception.
ANY = 'ANY'

# The builtins whose calls have no effects.
PURE_BUILTINS = ('isinstance', 'hasattr', 'type', 'tp_name', 'fqname')


class Facts:
    """Facts about the results of a list of statements; with *worst*,
    those of code about which nothing is known."""

    def __init__(self, worst: bool = False) -> None:
        # Per return: (exact type or None, index of the argument it
        # returns or None).
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
        types = {tp for tp, _ in self.returns}
        return types.pop() if len(types) == 1 and None not in types else None

    @property
    def alias(self) -> int | None:
        aliases = {alias for _, alias in self.returns}
        return (aliases.pop() if len(aliases) == 1 and None not in aliases
                else None)

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


def caught(handlers: list[ast.ExceptHandler]) -> list[str]:
    """The names of the exceptions *handlers* catch (``except E:``, and
    ``except (E1, E2):``); a name that is not a builtin exception is kept
    as is (Facts.raises_any() then assumes it is raised)."""
    out = []
    for handler in handlers:
        types = (handler.type.elts if isinstance(handler.type, ast.Tuple)
                 else [handler.type])
        out += [ast.unparse(t) if t is not None else 'BaseException'
                for t in types]
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
    """What the analysis needs of the other passes: the context of the
    passes (context.Context)."""

    def analyzer(self, spec: Spec | None = None) -> Analyzer: ...

    def types(self, spec: Spec | None = None) -> builtin_types.TypeFacts:
        ...

    def residual(self, spec: Spec, name: str, env: Env) -> list[ast.stmt]:
        ...


@dc.dataclass
class Flow:
    """The state of the analysis of a path: the facts about the names
    (*env*), the facts found (shared by the paths), the names of the
    arguments (a return of one is an alias of it), and whether the code
    is a Python reference (where other code models values, without
    effects)."""
    env: Env
    facts: Facts
    params: Sequence[str] = ()
    reference: bool = False

    def branch(self, env: Env) -> Flow:
        return dc.replace(self, env=dict(env))


class Analyzer(subset.Walker[Flow, None]):
    """The facts of the code of one spec; made by the context of the
    passes, which keeps one per spec."""

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

    def reference_facts(self, name: str, env: Env) -> Facts:
        """Facts of @native function *name* of this spec, called
        with the facts *env* about its parameters: of its Python
        reference, partially evaluated for them."""
        if subset.analysed(self.spec, name):
            # Code facts.py cannot follow: the worst facts.
            return Facts(worst=True)
        return self._cached(self._key(name=name, env=env), lambda: self.facts(
            self.context.residual(self.spec, name, env), env,
            self.spec.params(name), reference=True))

    def inline_facts(self, name: str, env: Env) -> Facts:
        """Facts of @inline function *name* of this spec, called with the
        facts *env* about its parameters: of its body, partially
        evaluated for them, as generated into the caller."""
        if subset.inline(self.spec, name):
            return Facts(worst=True)
        return self._cached(self._key('inline', name=name, env=env),
                            lambda: self.facts(
            self.context.residual(self.spec, name, env), env,
            self.spec.params(name)))

    def method_facts(self, name: str, tp: type) -> Facts | None:
        """Facts of method *name* ("T.meth") of this spec for self of
        exact type tp, from its body or its Python reference; None for a
        method written in C only (builtin_types.TypeFacts.derived())."""
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
        """Facts of the call of a hand-written C function (@native,
        or a stub: worst) or of an @inline function, with the facts *env*
        of the caller; None when *call* is neither."""
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
        analyzer = self.context.analyzer(spec)
        if inline:
            return analyzer.inline_facts(node.name, callee_env)
        return analyzer.reference_facts(node.name, callee_env)

    def mark_call(self, call: ast.Call, env: Env) -> Facts | None:
        """call_facts(), and the mark of *call* with its error check
        (marks.CallCheck), which emit.py reads."""
        callee = self.call_facts(call, env)
        if callee is not None:
            marks.put(call, marks.CallCheck(bool(callee.raises),
                                            callee.returns_null))
        return callee

    def facts(self, stmts: list[ast.stmt], env: Env,
              params: Sequence[str] = (), reference: bool = False) -> Facts:
        """Facts of *stmts*; *env* holds the facts about names (exact
        types, NULL, ... see known.py); *params* are the names of the
        call arguments, in order (a return of one of them is an alias
        of that argument); *reference*: *stmts* are a Python reference."""
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

    def pass_(self, stmt: ast.stmt, flow: Flow) -> None:
        pass

    def if_(self, stmt: ast.If, flow: Flow) -> None:
        self.expression(stmt.test, flow)
        body_env, else_env = known.refine(stmt.test, flow.env)
        self.block(stmt.body, flow.branch(body_env))
        self.block(stmt.orelse, flow.branch(else_env))

    def assign(self, stmt: ast.Assign, flow: Flow) -> None:
        name = ast.unparse(stmt.targets[0])
        tp = self.value_type(stmt.value, flow)
        flow.env.pop(name, None)
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
                         and value.id in flow.params else None)
                flow.facts.returns.append((self.value_type(value, flow),
                                           alias))

    def raise_(self, stmt: ast.Raise, flow: Flow) -> None:
        if isinstance(stmt.exc, ast.Call) and self.spec.c_function(stmt.exc):
            self.call(stmt.exc, flow)
        else:
            # Building the message only formats type names.
            flow.facts.raises.add(_exception_name(stmt.exc, flow.env))

    def try_(self, stmt: ast.Try, flow: Flow) -> None:
        self.block(stmt.body, flow)
        for handler in stmt.handlers:
            self.block(handler.body, flow.branch(flow.env))
        self.block(stmt.orelse, flow.branch(flow.env))
        self.block(stmt.finalbody, flow)

    def finally_(self, stmt: ast.Try, flow: Flow) -> None:
        self.try_(stmt, flow)

    def with_(self, stmt: ast.With, flow: Flow) -> None:
        self.block(stmt.body, flow)

    def call_(self, stmt: ast.Expr, flow: Flow) -> None:
        assert isinstance(stmt.value, ast.Call)
        self.call(stmt.value, flow)

    def for_(self, stmt: ast.For, flow: Flow) -> None:
        if not isinstance(stmt.target, ast.Name):
            return self.other(stmt, flow)
        # The partial evaluator marks the exact type of the iterated
        # object when it knows it (see partial_eval.py).
        loop = marks.get(stmt, marks.Loop)
        is_known, item_type = self.iteration(loop.iterable if loop else None)
        if not is_known:
            flow.facts.python()
        item: known.Fact = item_type or known.NOTNULL
        self.block(stmt.body, dc.replace(flow, env=flow.env | {
            stmt.target.id: item}))
        return None

    def expression(self, node: ast.expr, flow: Flow) -> None:
        """Account for the calls a condition makes."""
        named = [child.value for child in ast.walk(node)
                 if isinstance(child, ast.NamedExpr)]
        for child in ast.walk(node):
            if isinstance(child, ast.NamedExpr):
                self.value_type(child.value, flow)
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
        special = self.types.special(tp, '__iter__') if tp else None
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
        special = None if tp is None else self.types.special(tp, name)
        if special is None or tp is None:
            return Facts(worst=True)
        spec_name, value = special
        if spec_name is None and value is False:
            return Facts()      # no such method: nothing is called
        if spec_name is None and value is not builtin_types.PYTHON:
            facts = Facts()
            facts.raises.add(ANY)
            return facts
        if spec_name is not None and frontend.is_native(
                self.spec.functions[spec_name]):
            params = self.spec.params(spec_name)
            return self.reference_facts(spec_name, {params[0]: tp})
        return Facts(worst=True)

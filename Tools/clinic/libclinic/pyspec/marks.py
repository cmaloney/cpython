"""Typed marks: what the passes know about a node beyond its syntax.

Residual code (partial_eval.py) is Python ast.  What the partial
evaluator decides about a node, for the facts analysis (facts.py) and
the emitter (emit.py), is a mark: a small immutable dataclass, at most
one of each kind per node, kept in one attribute of the node (ATTRIBUTE)
so that a copy of the node (copy.deepcopy()) has the marks of the
original.  get() reads a mark, put() sets one.
"""

from __future__ import annotations

import ast
import copy
import dataclasses as dc
from typing import Any, TypeVar

from .known import Env

ATTRIBUTE = 'pyspec_marks'


class Mark:
    """A mark: immutable, shared by the copies of its node."""

    def __deepcopy__(self, memo: dict[int, Any]) -> Mark:
        return self


M = TypeVar('M', bound=Mark)


def get(node: ast.AST, kind: type[M]) -> M | None:
    """The mark of *kind* of *node*, or None."""
    mark = getattr(node, ATTRIBUTE, {}).get(kind)
    assert mark is None or isinstance(mark, kind)
    return mark


def put(node: ast.AST, mark: Mark) -> None:
    """Mark *node* (not a node it was copied from, or copied to)."""
    marks = getattr(node, ATTRIBUTE, {})
    setattr(node, ATTRIBUTE, marks | {type(mark): mark})


def of(node: ast.AST) -> list[Mark]:
    """The marks of *node*, in a fixed order."""
    marks: dict[type, Mark] = getattr(node, ATTRIBUTE, {})
    return [marks[kind] for kind in sorted(marks, key=lambda k: k.__name__)]


@dc.dataclass(frozen=True)
class Scope(Mark):
    """A node written in the spec *filename*, copied into the code of
    another (the body of an @inline function): its calls use the names
    of that spec (frontend.Spec.c_function()) and its errors are reported
    in it (SpecError.at())."""
    filename: str


def scope(node: ast.AST | None) -> str | None:
    """The spec *node* was written in, if copied from another."""
    mark = None if node is None else get(node, Scope)
    return None if mark is None else mark.filename


def scoped(node: ast.AST, filename: str) -> ast.AST:
    """*node*, every node of it marked as written in *filename* (unless
    already marked)."""
    for child in ast.walk(node):
        if get(child, Scope) is None:
            put(child, Scope(filename))
    return node


@dc.dataclass(frozen=True)
class CallCheck(Mark):
    """A call of a native function, with its facts at the call: whether
    it may raise, and whether it may return NULL without an exception (an
    absent result).  They decide its error check (emit.py)."""
    raises: bool
    null: bool


@dc.dataclass(frozen=True)
class Length(Mark):
    """``len(x)`` of x of exact type *tp*, whose size is read inline
    (builtin_types.Row.size)."""
    tp: type


@dc.dataclass(frozen=True)
class ArityCall(Mark):
    """A call of the arity function *c_name* of a __new__
    (NAME_nargsN(), emit.py)."""
    c_name: str


@dc.dataclass(frozen=True)
class Specialized(Mark):
    """A call of a spec function for which *special* was made: with
    *called*, the call calls it; else the call calls the generic function,
    with the facts of *special*."""
    special: Specialization = dc.field(repr=False)
    called: bool
    name: str = ''

    def __post_init__(self) -> None:
        object.__setattr__(self, 'name', self.special.name)


@dc.dataclass(frozen=True)
class Loop(Mark):
    """A ``for`` loop over an object of exact type *iterable* (None if
    not known); *by_index*: it iterates a list or tuple by index (``for
    item in x:``); *snapshot*: in the snapshot of a list, where no
    Python code runs (partial_eval.py)."""
    iterable: type | None
    by_index: bool
    snapshot: bool = False


@dc.dataclass(frozen=True)
class FirstPath(Mark):
    """The ``if`` of the first fast path of an @inline call whose first
    argument is the name *buffer* (None if it is not a name): see
    "Capacity" in partial_eval.py."""
    buffer: str | None


@dc.dataclass(frozen=True)
class PureIter(Mark):
    """``it = iter(x)`` that only allocates: removed when it is unused."""


class Specialization:
    """Spec function *callee* partially evaluated for the facts *env*
    about its parameters: the C function *name*(*params*) whose body is
    *body* (partial_eval.py).  *params* are the parameters the body uses,
    in order.

    *index_params*: the parameters iterated by index.  *lock*: for a
    snapshot (the body may return FALLBACK), the parameter whose critical
    section the caller holds."""

    def __init__(self, name: str, callee: str, params: list[str],
                 env: Env, body: list[ast.stmt],
                 lock: str | None = None) -> None:
        self.name = name
        self.callee = callee
        self.params = params
        self.env = env
        self.body = body
        self.lock = lock
        self.index_params: set[str] = set()

    def call(self, args: list[ast.expr]) -> ast.Call:
        node = ast.Call(ast.Name(self.name, ast.Load()),
                        [copy.copy(a) for a in args], [])
        put(node, Specialized(self, called=True))
        return node

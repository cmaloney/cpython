"""Overload sets in a pyspec: desugar them into the if-tree the pipeline
already understands (PROTOTYPE, scratch only).

Spelling (typing.overload / typeshed convention)::

    @overload
    def f(cls, source: Exact[bytes]):          # one form: signature + body
        return source
    ...
    @c_name("bytes_new")
    def f(cls, source: object = NULL, ...):    # the implementation: the
        ...                                    # parser's signature, body ...

A run of ``@overload def name`` directly followed by a plain ``def name``
(in a class body or at top level) is one overload set.  The plain def is
the implementation signature: its converters parse the arguments once
(clinic), its decorators and docstring are the function's.  The overloads
are tried in order on the bound parameters; the first that matches runs.

What an overload's signature means, parameter by parameter (by NAME; the
parser already bound positional and keyword arguments):

* omitted                      -> the parameter is NULL (not passed)
* ``p=NULL``                   -> no test
* ``p`` (no default)           -> passed: ``p is not NULL`` (no test when
                                  the implementation requires it and the
                                  parser binds it: a method)
* annotation (object params only; a converted parameter is already typed):
    ``object`` / none          -> no test
    ``Exact[T]``               -> ``type(p) is T``
    ``T`` (a class)            -> ``isinstance(p, T)`` (the real type:
                                  PyXxx_Check)
    ``SupportsIndex``          -> ``hasattr(type(p), "__index__")``
    ``Buffer``                 -> ``hasattr(type(p), "__buffer__")``

Body conventions:

* leading ``if C: return NotImplemented`` statements are guards: they
  become part of the match (``not C``), before any other statement runs;
* ``return NotImplemented`` elsewhere hands the call to the next overload
  (binary operator convention).  Lowered as: the rest of the chain copied
  in place when it is a single ``return`` (tail duplication: what the
  hand-written if-tree does for PyBytes_FromObject in bytes.__new__), or,
  for ``try: ... except E: return NotImplemented`` at the top of the body,
  ``except E: pass`` with the statements after the try moved to its
  ``else:``, so control falls out of the overload's if into the next one.

Desugaring (desugar_module()):

* tests of an overload, in order: presence tests (parameter order), type
  tests (parameter order), guards (body order);
* a test already known (implied by the implementation, or by the failure
  of an earlier exhaustive branch) is dropped; an overload with a test
  known false is unreachable (an error);
* consecutive overloads with the same first test share one ``if`` (nested
  ifs: every body returns or raises, so falling out of an ``if`` is
  exactly "try the next overload");
* after an ``if T:`` whose inside always returns or raises, ``not T`` is
  known;
* the chain must end with an overload that always matches and always
  returns or raises (else: "not every call is covered").
"""

from __future__ import annotations

import ast
import copy
import dataclasses as dc
import inspect
import typing
from collections.abc import Buffer
from typing import SupportsIndex, overload  # noqa: F401 (re-exported)

try:
    from libclinic.errors import SpecError
except ImportError:                       # standalone use
    class SpecError(Exception):           # type: ignore[no-redef]
        @classmethod
        def at(cls, node, message, filename=None):
            return cls(f'{filename}:{getattr(node, "lineno", "?")}: '
                       f'{message}')


# -- the annotation vocabulary, as Python objects (dispatch mode) --------------

class _ExactType:
    def __init__(self, tp: type) -> None:
        self.tp = tp

    def __repr__(self) -> str:
        return f'Exact[{self.tp.__name__}]'


class Exact:
    """``Exact[T]``: an object of exactly type T (``type(p) is T``)."""

    def __class_getitem__(cls, tp: type) -> _ExactType:
        return _ExactType(tp)


# -- desugaring: AST -> AST -----------------------------------------------------

def _is_overload(node: ast.stmt) -> bool:
    return (isinstance(node, ast.FunctionDef)
            and any(isinstance(d, ast.Name) and d.id == 'overload'
                    for d in node.decorator_list))


def _is_null(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Name) and node.id == 'NULL'


def _is_not_implemented(stmt: ast.stmt) -> bool:
    return (isinstance(stmt, ast.Return)
            and isinstance(stmt.value, ast.Name)
            and stmt.value.id == 'NotImplemented')


def _params(fn: ast.FunctionDef) -> dict[str, tuple[ast.arg, ast.expr | None]]:
    """name -> (arg, default or None), in order."""
    a = fn.args
    positional = a.posonlyargs + a.args
    defaults = [None] * (len(positional) - len(a.defaults)) + a.defaults
    out = {arg.arg: (arg, d) for arg, d in zip(positional, defaults)}
    out.update({arg.arg: (arg, d)
                for arg, d in zip(a.kwonlyargs, a.kw_defaults)})
    return out


def _converted(annotation: ast.expr | None) -> bool:
    """Whether the implementation's converter types the parameter (str,
    Py_ssize_t...): not ``object`` or ``object(c_param=...)``."""
    if annotation is None:
        return False
    if isinstance(annotation, ast.Call):
        annotation = annotation.func
    return not (isinstance(annotation, ast.Name)
                and annotation.id == 'object')


def _key(test: ast.expr) -> str:
    return ast.dump(test)


def negate(test: ast.expr) -> ast.expr:
    flip = {ast.Is: ast.IsNot, ast.IsNot: ast.Is, ast.Eq: ast.NotEq,
            ast.NotEq: ast.Eq, ast.In: ast.NotIn, ast.NotIn: ast.In}
    if isinstance(test, ast.Compare) and len(test.ops) == 1 \
            and type(test.ops[0]) in flip:
        new = ast.Compare(test.left, [flip[type(test.ops[0])]()],
                          test.comparators)
    elif isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return test.operand
    else:
        new = ast.UnaryOp(ast.Not(), test)
    return ast.copy_location(new, test)


def _call(func: str, *args: ast.expr) -> ast.Call:
    return ast.Call(ast.Name(func, ast.Load()), list(args), [])


def _type_of(name: str) -> ast.Call:
    return _call('type', ast.Name(name, ast.Load()))


def _type_test(name: str, annotation: ast.expr) -> ast.expr | None:
    p = ast.Name(name, ast.Load())
    match annotation:
        case ast.Name('object'):
            return None
        case ast.Subscript(ast.Name('Exact'), ast.Name() as tp):
            return ast.Compare(_type_of(name), [ast.Is()], [tp])
        case ast.Name('SupportsIndex'):
            return _call('hasattr', _type_of(name), ast.Constant('__index__'))
        case ast.Name('Buffer'):
            return _call('hasattr', _type_of(name),
                         ast.Constant('__buffer__'))
        case ast.Name() as tp:
            return _call('isinstance', p, tp)
    return None


@dc.dataclass
class Overload:
    node: ast.FunctionDef
    tests: list[ast.expr]
    body: list[ast.stmt]


class Desugarer:
    def __init__(self, impl: ast.FunctionDef, overloads: list[ast.FunctionDef],
                 qualname: str, parser_bound: bool, filename: str) -> None:
        self.impl = impl
        self.qualname = qualname
        self.filename = filename
        self.parser_bound = parser_bound
        self.impl_params = _params(impl)
        self.overloads = [self._overload(o) for o in overloads]
        self.reached: set[int] = set()

    def error(self, node: ast.AST, message: str) -> Exception:
        return SpecError.at(node, f'{self.qualname}: {message}',
                            filename=self.filename)

    def _overload(self, node: ast.FunctionDef) -> Overload:
        mine = _params(node)
        for name, (arg, default) in mine.items():
            if name not in self.impl_params:
                raise self.error(arg, f'overload parameter {name!r} is not '
                                 'a parameter of the implementation')
            if default is not None and not _is_null(default):
                raise self.error(default, 'an overload parameter defaults '
                                 'to NULL (either) or has no default')
        presence: list[ast.expr] = []
        types: list[ast.expr] = []
        for name, (impl_arg, impl_default) in self.impl_params.items():
            p = ast.Name(name, ast.Load())
            required = impl_default is None
            if name not in mine:
                if required and self.parser_bound:
                    raise self.error(node, f'omits {name!r}, which the '
                                     'implementation requires')
                presence.append(ast.copy_location(
                    ast.Compare(p, [ast.Is()], [ast.Name('NULL', ast.Load())]),
                    node))
                continue
            arg, default = mine[name]
            if default is None and not (required and self.parser_bound):
                presence.append(ast.copy_location(
                    ast.Compare(p, [ast.IsNot()],
                                [ast.Name('NULL', ast.Load())]), arg))
            if arg.annotation is not None:
                if default is not None:
                    raise self.error(arg, f'{name!r} has a type and may be '
                                     'NULL: split the overload')
                if _converted(impl_arg.annotation):
                    raise self.error(arg, f'{name!r} is converted by the '
                                     'parser: an overload cannot test its '
                                     'type')
                test = _type_test(name, arg.annotation)
                if test is None and not (isinstance(arg.annotation, ast.Name)
                                         and arg.annotation.id == 'object'):
                    raise self.error(arg, 'unsupported overload annotation '
                                     f'{ast.unparse(arg.annotation)!r}')
                if test is not None:
                    types.append(ast.copy_location(test, arg.annotation))
        body = list(node.body)
        if body and isinstance(body[0], ast.Expr) \
                and isinstance(body[0].value, ast.Constant) \
                and isinstance(body[0].value.value, str):
            body = body[1:]
        guards = []
        while (body and isinstance(body[0], ast.If) and not body[0].orelse
               and len(body[0].body) == 1
               and _is_not_implemented(body[0].body[0])):
            guards.append(negate(body[0].test))
            body = body[1:]
        return Overload(node, presence + types + guards, body)

    # -- the tree ---------------------------------------------------------------

    @staticmethod
    def _live(ov: Overload, facts: set[str]) -> list[ast.expr] | None:
        """The tests of *ov* not decided by *facts*; None if one is false."""
        out = []
        for test in ov.tests:
            if _key(test) in facts:
                continue
            if _key(negate(test)) in facts:
                return None
            out.append(test)
        return out

    def build(self, ovs: list[Overload], facts: set[str],
              after: list[Overload]) -> tuple[list[ast.stmt], bool]:
        """The statements trying *ovs* in order under *facts*, and whether
        they always return or raise.  *after*: the overloads tried when
        these fall through (for ``return NotImplemented``)."""
        facts = set(facts)
        out: list[ast.stmt] = []
        i = 0
        while i < len(ovs):
            tests = self._live(ovs[i], facts)
            if tests is None:
                i += 1
                continue
            if not tests:
                self.reached.add(id(ovs[i]))
                body, terminal = self.lower_body(
                    ovs[i], facts, ovs[i + 1:] + after)
                out += body
                if terminal:
                    return out, True
                i += 1
                continue
            first = tests[0]
            j = i + 1
            while j < len(ovs):
                t = self._live(ovs[j], facts)
                if not t or _key(t[0]) != _key(first):
                    break
                j += 1
            inner, terminal = self.build(ovs[i:j], facts | {_key(first)},
                                         ovs[j:] + after)
            out.append(ast.copy_location(
                ast.If(copy.deepcopy(first), inner, []), first))
            if terminal:
                facts.add(_key(negate(first)))
            i = j
        return out, False

    def lower_body(self, ov: Overload, facts: set[str],
                   rest: list[Overload]) -> tuple[list[ast.stmt], bool]:
        body = copy.deepcopy(ov.body)
        sites = [n for stmt in body for n in ast.walk(stmt)
                 if isinstance(n, ast.stmt) and _is_not_implemented(n)]
        if not sites:
            return body, terminal(body)
        here = facts | {_key(t) for t in ov.tests}
        cont, cont_terminal = self.build(rest, here, [])
        single_return = (len(cont) == 1 and isinstance(cont[0], ast.Return))
        if not single_return:
            # try: ... except E: return NotImplemented  ->  except E: pass,
            # the rest of the body in else:, falling into the next overload.
            for t, stmt in enumerate(body):
                if (isinstance(stmt, ast.Try) and not stmt.orelse
                        and not stmt.finalbody and len(sites) == 1
                        and any(h.body == [sites[0]] for h in stmt.handlers)):
                    for h in stmt.handlers:
                        if h.body == [sites[0]]:
                            h.body = [ast.copy_location(ast.Pass(),
                                                        sites[0])]
                    stmt.orelse = body[t + 1:]
                    return body[:t + 1], False
        if not cont_terminal:
            raise self.error(sites[0],
                             'return NotImplemented here needs the next '
                             'overloads to cover every call')

        class Splice(ast.NodeTransformer):
            def visit_Return(self, node: ast.Return) -> typing.Any:
                if _is_not_implemented(node):
                    return copy.deepcopy(cont)
                return node
        body = [Splice().visit(stmt) for stmt in body]
        return body, terminal(body)

    def function(self) -> ast.FunctionDef:
        tree, covered = self.build(self.overloads, set(), [])
        if not covered:
            raise self.error(self.impl, 'the overloads do not cover every '
                             'call: end with an overload that always '
                             'matches (e.g. one that raises TypeError)')
        for ov in self.overloads:
            if id(ov) not in self.reached:
                raise self.error(ov.node, 'this overload can never be '
                                 'reached (an earlier one takes all its '
                                 'calls)')
        new = copy.copy(self.impl)
        doc = [s for s in self.impl.body[:1]
               if isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
               and isinstance(s.value.value, str)]
        new.body = doc + tree
        return ast.fix_missing_locations(new)


def terminal(stmts: list[ast.stmt]) -> bool:
    """Whether *stmts* always return or raise."""
    if not stmts:
        return False
    last = stmts[-1]
    match last:
        case ast.Return() | ast.Raise():
            return True
        case ast.If():
            return terminal(last.body) and terminal(last.orelse)
        case ast.Try():
            main = last.orelse if last.orelse else last.body
            return (terminal(last.finalbody)
                    or (terminal(main)
                        and all(terminal(h.body) for h in last.handlers)))
        case ast.With():
            return terminal(last.body)
    return False


def _desugar_body(body: list[ast.stmt], prefix: str, parser_bound: bool,
                  filename: str) -> list[ast.stmt]:
    out: list[ast.stmt] = []
    pending: list[ast.FunctionDef] = []
    for stmt in body:
        if _is_overload(stmt):
            assert isinstance(stmt, ast.FunctionDef)
            if pending and pending[0].name != stmt.name:
                raise SpecError.at(stmt, f'overloads of {pending[0].name} '
                                   'have no implementation', filename=filename)
            pending.append(stmt)
            continue
        if pending:
            if not (isinstance(stmt, ast.FunctionDef)
                    and stmt.name == pending[0].name):
                raise SpecError.at(stmt, f'overloads of {pending[0].name} '
                                   'must be followed by its implementation '
                                   '(a def of the same name)',
                                   filename=filename)
            stmt = Desugarer(stmt, pending, prefix + stmt.name, parser_bound,
                             filename).function()
            pending = []
        out.append(stmt)
    if pending:
        raise SpecError.at(pending[-1], f'overloads of {pending[0].name} '
                           'have no implementation', filename=filename)
    return out


def desugar_module(tree: ast.Module, filename: str = '<spec>') -> ast.Module:
    """*tree* with each overload set replaced by one def: the
    implementation with the dispatch if-tree as its body.  The hook of
    frontend.Spec.__init__(), runtime.load() and model.py: everything
    after it sees an ordinary spec."""
    tree.body = _desugar_body(tree.body, '', False, filename)
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            node.body = _desugar_body(node.body, node.name + '.', True,
                                      filename)
    return ast.fix_missing_locations(tree)


# -- dispatch mode: the same semantics, interpreted (for cross-checking) --------

def _matches(annotation: typing.Any, value: typing.Any) -> bool:
    from libclinic.pyspec.runtime import isinstance as real_isinstance
    if annotation is inspect.Parameter.empty or annotation is object:
        return True
    if isinstance(annotation, _ExactType):
        return type(value) is annotation.tp
    if annotation is SupportsIndex:
        return hasattr(type(value), '__index__')
    if annotation is Buffer:
        return hasattr(type(value), '__buffer__')
    if isinstance(annotation, type):
        return real_isinstance(value, annotation)
    raise TypeError(f'unsupported overload annotation {annotation!r}')


def dispatch(impl: typing.Callable[..., typing.Any]
             ) -> typing.Callable[..., typing.Any]:
    """Run the overloads of *impl* (typing.get_overloads()) in order:
    the reference semantics the desugaring must preserve."""
    from libclinic.pyspec.runtime import NULL
    sig = inspect.signature(impl)

    def wrapper(*args: typing.Any, **kwargs: typing.Any) -> typing.Any:
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        values = bound.arguments
        for ov in typing.get_overloads(impl):
            params = inspect.signature(ov).parameters
            ok = True
            for name, value in values.items():
                if name not in params:
                    ok = value is NULL          # omitted: not passed
                elif params[name].default is inspect.Parameter.empty:
                    ok = (value is not NULL     # passed, of that type
                          and _matches(params[name].annotation, value))
                else:
                    ok = True                   # p=NULL: either
                if not ok:
                    break
            if not ok:
                continue
            result = ov(**{name: values[name] for name in params})
            if result is NotImplemented:
                continue
            return result
        raise AssertionError(f'no overload of {impl.__qualname__} matches')
    wrapper.__qualname__ = impl.__qualname__
    wrapper.__name__ = impl.__name__
    wrapper.__module__ = impl.__module__
    return wrapper


def prepare_dispatch(tree: ast.Module) -> ast.Module:
    """Dispatch mode: decorate each implementation of an overload set with
    dispatch() (as Python, the overloads register with typing.overload)."""
    def visit(body: list[ast.stmt]) -> None:
        previous = None
        for stmt in body:
            if (isinstance(stmt, ast.FunctionDef) and not _is_overload(stmt)
                    and previous is not None and previous.name == stmt.name):
                stmt.decorator_list.append(ast.Attribute(
                    ast.Name('_pyspec_overloads', ast.Load()), 'dispatch',
                    ast.Load()))
            previous = stmt if _is_overload(stmt) else None
    visit(tree.body)
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            visit(node.body)
    tree.body.insert(0, ast.Import([ast.alias('libclinic.pyspec.overloads',
                                              '_pyspec_overloads')]))
    return ast.fix_missing_locations(tree)

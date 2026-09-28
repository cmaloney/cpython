"""The names a spec imports, with their meaning as Python.

A spec imports them with ``from libclinic.pyspec.runtime import ...``;
load() runs a spec as Python (the reference behaviour, for the tests),
while clinic reads the same file with the ast module.  They are:

* builtins with a fixed C meaning: ``NULL``, ``isinstance`` (the real
  type), ``iter`` (PyObject_GetIter()), ``tp_name`` and ``fqname`` (type
  names in messages).  Clinic gives isinstance and iter their C meaning
  by name, so a spec must import them (SHADOWED_BUILTINS);
* the clinic decorators and ``@c_name``, ``@native``, ``@inline``:
  identity decorators for Python;
* the primitives of a Python reference, where the effect happens:
  ``exact(T, value)``, ``unknown(value)``, ``calls(x, "__name__")``,
  ``runs_python()`` (Objects/pyspec/README.rst, "Native functions").
  As Python they only return their value (exact() checks its type).
"""

import ast
import builtins
import os
import sys
import types
from collections.abc import Callable, Iterator
from typing import Any, TypeVar

_F = TypeVar('_F', bound=Callable[..., Any])

__all__ = [
    'NULL', 'PY_SSIZE_T_MAX', 'isinstance', 'iter', 'tp_name', 'fqname',
    'native', 'inline', 'exact', 'unknown', 'calls', 'runs_python',
]

# The builtins this module redefines with their C meaning: a spec that
# uses one must import it from here (check_shadowed_builtins()).
SHADOWED_BUILTINS = ('isinstance', 'iter')


class _Null:
    """C NULL: an argument that was not passed, or a result that is
    absent."""

    def __repr__(self) -> str:
        return 'NULL'

    def __bool__(self) -> bool:
        raise TypeError('compare with "is NULL", do not test truthiness')


NULL = _Null()

PY_SSIZE_T_MAX = sys.maxsize


def _clinic_decorator(*args: Any) -> Any:
    """``@d`` or ``@d(args)``: return the function unchanged."""
    if len(args) == 1 and callable(args[0]):
        return args[0]
    return lambda func: func


# The clinic decorators other than @classmethod and @staticmethod: for
# Python, identity decorators.
def _define_clinic_decorators() -> list[str]:
    from libclinic.dsl_parser import DSLParser
    names = [name for name in DSLParser.decorator_names()
             if name not in ('classmethod', 'staticmethod')]
    for name in names:
        globals()[name] = _clinic_decorator
    return names


CLINIC_DECORATORS = _define_clinic_decorators()


def c_name(*args: str, **kwargs: str) -> Callable[[_F], _F]:
    """The C name of a method, or the prefix of the tables of a class."""
    return lambda func: func


def native(func: _F) -> _F:
    """Implemented natively; the body is its Python reference, run as
    Python and read for facts, never compiled."""
    return func


def inline(func: _F) -> _F:
    """The body is generated into each caller."""
    return func


def exact(tp: type, value: Any = None) -> Any:
    """*value*, a new object of exactly type *tp*."""
    if value is not None and type(value) is not tp:
        raise AssertionError(f'exact({tp.__name__}, ...) is a '
                             f'{type(value).__name__}')
    return value


def unknown(value: Any = None) -> Any:
    """*value*, a new object whose exact type is not known."""
    return value


def calls(obj: object, name: str) -> None:
    """The C invokes the special method *name* of type(obj) here."""


def runs_python() -> None:
    """The C may run any Python code here."""


def isinstance(obj: object, cls: type | tuple[type, ...]) -> bool:
    """PyXxx_Check(): looks at the real type only, never at __class__."""
    return issubclass(type(obj), cls)


class _Iterator:
    """The result of iter(): a for loop over it only calls __next__."""

    def __init__(self, it: Iterator[Any]) -> None:
        self._it = it

    def __iter__(self) -> '_Iterator':
        return self

    def __next__(self) -> Any:
        return next(self._it)


def iter(obj: Any) -> _Iterator:
    """PyObject_GetIter().  ``for item in it:`` over the result is
    PyIter_Next() calls in C; a Python for loop would first call
    ``it.__iter__()``, which the wrapper makes a no-op, as in C."""
    return _Iterator(builtins.iter(obj))


def tp_name(tp: type) -> str:
    """``Py_TYPE(x)->tp_name``; used as ``%.200s`` in error messages."""
    if tp.__flags__ & (1 << 9):     # Py_TPFLAGS_HEAPTYPE
        return tp.__name__
    if tp.__module__ == 'builtins':
        return tp.__qualname__
    return f'{tp.__module__}.{tp.__qualname__}'


def fqname(tp: type) -> str:
    """Fully qualified type name; used as ``%T`` in error messages."""
    if tp.__module__ in ('builtins', '__main__'):
        return tp.__qualname__
    return f'{tp.__module__}.{tp.__qualname__}'


# The imported specs check_shadowed_builtins() accepted.
_checked: set[str] = set()


def check_shadowed_builtins(tree: ast.Module, path: str) -> None:
    """A SpecError at the first use of a SHADOWED_BUILTINS name that the
    spec *tree* does not import from here: as Python it would be the
    builtin, whose meaning is not the C's."""
    from libclinic.errors import SpecError
    imported = {alias.name for node in tree.body
                if builtins.isinstance(node, ast.ImportFrom)
                and node.module == __name__
                for alias in node.names
                if alias.asname in (None, alias.name)}
    for node in ast.walk(tree):
        if (builtins.isinstance(node, ast.Name)
                and node.id in SHADOWED_BUILTINS
                and node.id not in imported):
            raise SpecError(f"{node.id}() is the builtin here, not the C's: "
                            f"import it with 'from {__name__} import "
                            f"{node.id}'", filename=path, lineno=node.lineno)


def load(path: str) -> dict[str, Callable[..., Any]]:
    """Run the spec at *path*: {"PyBytes_FromObject" or "bytes.__new__":
    the Python function}.  Once the spec has run, a global T of ``class
    T:`` is the builtin again (bodies compare with the real type), while
    ``T.m(...)`` calls the spec method, as in the generated C (except in
    a Python reference, which models with the builtin)."""
    from . import specfiles
    with open(path, encoding='utf-8') as f:
        tree = ast.parse(f.read(), path)
    check_shadowed_builtins(tree, path)
    classes = {node.name for node in tree.body
               if builtins.isinstance(node, ast.ClassDef)}
    bases = [specfiles.import_root(path)]

    class SpecCalls(ast.NodeTransformer):
        def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
            # Only the bodies of methods: a shared method of a class body
            # (``__reduce__ = bytearray.__reduce__``) is the spec's.
            node.body = [self.visit(stmt)
                         if builtins.isinstance(stmt, ast.FunctionDef)
                         else stmt
                         for stmt in node.body]
            return node

        def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
            # The Python reference of a C function models it with the
            # builtins.
            if any(builtins.isinstance(d, ast.Name)
                   and d.id == 'native'
                   for d in node.decorator_list):
                return node
            return self.generic_visit(node)

        def visit_Attribute(self, node: ast.Attribute) -> ast.Attribute:
            self.generic_visit(node)
            if (builtins.isinstance(node.value, ast.Name)
                    and node.value.id in classes
                    and builtins.isinstance(node.ctx, ast.Load)):
                node.value = ast.copy_location(
                    ast.Name(f'_spec_{node.value.id}', ast.Load()),
                    node.value)
            return node

    tree = ast.fix_missing_locations(SpecCalls().visit(tree))
    stem = os.path.splitext(os.path.basename(path))[0]
    module = types.ModuleType(f'_pyspec_{stem}')
    module.__file__ = path
    sys.path[:0] = bases
    try:
        exec(compile(tree, path, 'exec'), module.__dict__)
    finally:
        for entry in bases:
            sys.path.remove(entry)
    # The specs it imported, which the import system ran.
    for name, imported in list(sys.modules.items()):
        spec_path = getattr(imported, '__file__', None)
        if (spec_path and 'pyspec' in name.split('.')
                and not name.startswith('libclinic.')
                and spec_path not in _checked):
            with open(spec_path, encoding='utf-8') as f:
                check_shadowed_builtins(ast.parse(f.read(), spec_path),
                                        spec_path)
            _checked.add(spec_path)
    functions: dict[str, Any] = {}
    for node in tree.body:
        if builtins.isinstance(node, ast.FunctionDef):
            functions[node.name] = getattr(module, node.name)
        elif builtins.isinstance(node, ast.ClassDef):
            spec_class = getattr(module, node.name)
            setattr(module, f'_spec_{node.name}', spec_class)
            # A class that is not a builtin (bytes_iterator) stays the
            # spec class.
            setattr(module, node.name,
                    getattr(builtins, node.name, spec_class))
            for item in node.body:
                if builtins.isinstance(item, ast.FunctionDef):
                    functions[f'{node.name}.{item.name}'] = (
                        spec_class.__dict__[item.name])
    return {name: getattr(func, '__func__', func)
            for name, func in functions.items()}

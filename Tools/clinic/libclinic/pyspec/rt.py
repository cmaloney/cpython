"""The primitives of a spec body with a C meaning:
``from libclinic.pyspec import rt``.

A spec writes them qualified (``rt.NULL``, ``rt.isinstance(x, str)``),
so that a bare ``isinstance`` or ``iter`` is always Python's, which a
spec may not use (frontend.py and runtime.check_shadowed_builtins()
reject it).  They are:

* builtins with a fixed C meaning: ``NULL``, ``PY_SSIZE_T_MAX``,
  ``isinstance`` (the real type: PyXxx_Check()), ``iter``
  (PyObject_GetIter()), ``tp_name`` and ``fqname`` (type names in
  messages);
* the primitives of a Python reference, where the effect happens:
  ``exact(T, value)``, ``unknown(value)``, ``calls(x, "__name__")``,
  ``runs_python()`` (Objects/pyspec/README.rst, "Native functions").
  As Python they only return their value (exact() checks its type).

The code of this file uses the builtins it redefines as
``builtins.isinstance`` and ``builtins.iter``.
"""

import builtins
import sys
from collections.abc import Iterator
from typing import Any

__all__ = [
    'NULL', 'PY_SSIZE_T_MAX', 'isinstance', 'iter', 'tp_name', 'fqname',
    'exact', 'unknown', 'calls', 'runs_python',
]

# The builtins this module redefines with their C meaning: a spec that
# uses one bare uses Python's (runtime.check_shadowed_builtins()).
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

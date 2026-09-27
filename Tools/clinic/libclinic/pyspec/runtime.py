"""Names a pyspec file may use, with their meaning as Python.

A pyspec file is ordinary Python: it imports these names with
``from libclinic.pyspec.runtime import ...``.  Running it (see load())
gives the reference behavior; Argument Clinic reads the same file with the
ast module (frontend.py), derives facts from it (call_table.py) and lowers
it to C (emit.py).  Besides the functions of the specs themselves, a spec
uses:

* builtins with a fixed C meaning: ``NULL``, ``isinstance`` (the real
  type), ``iter`` (PyObject_GetIter()), ``tp_name`` and ``fqname`` (type
  names in error messages);
* the Argument Clinic decorators, and ``@c_name`` and ``@static_type``
  (frontend.py, typeobj.py): identity decorators for Python;
* ``@c_implemented`` and a few primitives that say what plain Python
  cannot, placed where the effect happens, so that the control flow
  around them gives their conditions (see Objects/pyspec/README.rst):

  exact(T, value)       value is a new object of exactly type T
  unknown(value)        value is a new object of a type not known exactly
  calls(x, "__name__")  here the C invokes the special method of type(x):
                        Python code runs only if that method is Python code
  runs_python()         here the C may run any Python code
  NULL                  returned: absent (not an error)

  exact() and unknown() may fail (MemoryError); calls() and runs_python()
  may raise anything.  When the spec runs as Python they only return
  their value (exact() checks its type): the code around them models what
  the C computes.
"""

import ast
import builtins
import os
import sys
import types

__all__ = [
    'NULL', 'PY_SSIZE_T_MAX', 'isinstance', 'iter', 'tp_name', 'fqname',
    'c_implemented', 'exact', 'unknown', 'calls', 'runs_python',
]


class _Null:
    """C NULL: an argument that was not passed, or a result that is
    absent."""

    def __repr__(self):
        return 'NULL'

    def __bool__(self):
        raise TypeError('compare with "is NULL", do not test truthiness')


NULL = _Null()

PY_SSIZE_T_MAX = sys.maxsize


def _clinic_decorator(*args):
    """``@d`` or ``@d(args)``: return the function unchanged."""
    if len(args) == 1 and callable(args[0]):
        return args[0]
    return lambda func: func


# The Argument Clinic decorators other than @classmethod and @staticmethod
# (see frontend.py): they only affect the generated C, so for Python they
# are identity decorators.
coexist = critical_section = deleter = disable = getter = _clinic_decorator
permit_long_docstring_body = permit_long_summary = _clinic_decorator
setter = text_signature = vectorcall = _clinic_decorator


def c_name(*args, **kwargs):
    """``@c_name("x")`` / ``@c_name(slot="x")``: the C function of a
    method (see frontend.py).  An identity decorator for Python."""
    return lambda func: func


def static_type(**members):
    """``@static_type(tp_member="C expression", ...)``: clinic generates
    the static PyTypeObject of the class (see typeobj.py).  An identity
    decorator for Python."""
    return lambda cls: cls


def c_implemented(func):
    """The C function of the same name is written by hand and is the
    authority; the body is its Python reference: run when the spec runs
    as Python, and read for the facts of its calls.  It is never lowered
    to C."""
    return func


def exact(tp, value=None):
    """*value*, a new object of exactly type *tp*."""
    if value is not None and type(value) is not tp:
        raise AssertionError(f'exact({tp.__name__}, ...) is a '
                             f'{type(value).__name__}')
    return value


def unknown(value=None):
    """*value*, a new object whose exact type is not known."""
    return value


def calls(obj, name):
    """The C invokes the special method *name* of type(obj) here."""


def runs_python():
    """The C may run any Python code here."""


def isinstance(obj, cls):
    """PyXxx_Check(): looks at the real type only, never at __class__."""
    return issubclass(type(obj), cls)


class _Iterator:
    """The result of iter(): a for loop over it only calls __next__."""

    def __init__(self, it):
        self._it = it

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._it)


def iter(obj):
    """PyObject_GetIter().

    ``for item in it:`` over its result is lowered to PyIter_Next() calls:
    tp_iternext only.  A Python for loop would call ``it.__iter__()``
    first, which C does not do; the wrapper makes the spec, run as
    Python, do the same as C."""
    return _Iterator(builtins.iter(obj))


def tp_name(tp):
    """``Py_TYPE(x)->tp_name``; used as ``%.200s`` in error messages."""
    if tp.__flags__ & (1 << 9):     # Py_TPFLAGS_HEAPTYPE
        return tp.__name__
    if tp.__module__ == 'builtins':
        return tp.__qualname__
    return f'{tp.__module__}.{tp.__qualname__}'


def fqname(tp):
    """Fully qualified type name; used as ``%T`` in error messages."""
    if tp.__module__ in ('builtins', '__main__'):
        return tp.__qualname__
    return f'{tp.__module__}.{tp.__qualname__}'


def load(path):
    """Execute the spec at *path*; return its functions and methods.

    The result maps "PyBytes_FromObject" or "bytes.__new__" to the Python
    function.  ``class T:`` in a spec describes the builtin type T, so once
    the spec has run, the global T is the builtin again: bodies compare
    with the real type.  Calls ``T.m(...)`` of spec methods call the spec
    method, as in the generated C (except in the Python reference of a
    @c_implemented function, which uses the builtin).  The specs it
    imports (``from pyspec.abstract import PyNumber_AsSsize_t``) are found
    relative to the directory of the C file, or to the source root
    (frontend.py).
    """
    with open(path, encoding='utf-8') as f:
        tree = ast.parse(f.read(), path)
    classes = {node.name for node in tree.body
               if isinstance(node, ast.ClassDef)}
    base = os.path.dirname(os.path.dirname(os.path.abspath(path)))
    bases = [base, os.path.dirname(base)]

    class SpecCalls(ast.NodeTransformer):
        def visit_ClassDef(self, node):
            # Only the bodies of methods: a shared method of a class body
            # (``__reduce__ = bytearray.__reduce__``) is the spec's.
            node.body = [self.visit(stmt)
                         if isinstance(stmt, ast.FunctionDef) else stmt
                         for stmt in node.body]
            return node

        def visit_FunctionDef(self, node):
            # The Python reference of a C function models it with the
            # builtins.
            if any(isinstance(d, ast.Name) and d.id == 'c_implemented'
                   for d in node.decorator_list):
                return node
            return self.generic_visit(node)

        def visit_Attribute(self, node):
            self.generic_visit(node)
            if (isinstance(node.value, ast.Name)
                    and node.value.id in classes
                    and isinstance(node.ctx, ast.Load)):
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
    functions = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            functions[node.name] = getattr(module, node.name)
        elif isinstance(node, ast.ClassDef):
            spec_class = getattr(module, node.name)
            setattr(module, f'_spec_{node.name}', spec_class)
            # A class that is not a builtin (bytes_iterator) stays the
            # spec class.
            setattr(module, node.name,
                    getattr(builtins, node.name, spec_class))
            for item in node.body:
                if isinstance(item, ast.FunctionDef):
                    functions[f'{node.name}.{item.name}'] = (
                        spec_class.__dict__[item.name])
    return {name: getattr(func, '__func__', func)
            for name, func in functions.items()}

"""Names a pyspec file may use, with Python reference implementations.

A pyspec file is ordinary Python: it imports these names with
``from libclinic.pyspec.runtime import ...``.  Running it (see load())
gives the reference behavior; Argument Clinic reads the same file with the
ast module and lowers it to C (see emit.py).  Three kinds of names appear
in a spec:

* functions defined in the spec itself (lowered to static C functions,
  or inlined by the partial evaluator);
* the builtins below, which have fixed C meanings;
* escapes, ``C.<name>(...)``: C functions called directly.  Each carries
  its C call template, result type and error convention for the emitter;
* the C API facts vocabulary (New[object], Steals[...], OnError[...], ...):
  annotations of top-level stubs, read by the C API catalog (capi.py).
"""

import ast
import builtins
import operator
import os
import sys
import types

__all__ = [
    'NULL', 'C', 'cstr', 'isinstance', 'tp_name', 'fqname',
    # C API facts vocabulary
    'char_p', 'void_p', 'const_void_p', 'Py_ssize_t', 'va_list', 'pointer',
    'Out', 'InOut', 'New', 'Borrowed', 'Steals', 'OnError', 'NoError',
    'NullIn', 'RunsPython',
]


class _Null:
    """C NULL: an argument that was not passed, or a lookup that failed."""

    def __repr__(self):
        return 'NULL'

    def __bool__(self):
        raise TypeError('compare with "is NULL", do not test truthiness')


NULL = _Null()

# Annotation for a ``const char *`` parameter (NULL when not given).
cstr = str


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


def isinstance(obj, cls):
    """PyXxx_Check(): looks at the real type only, never at __class__."""
    return issubclass(type(obj), cls)


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


# Error conventions of escapes.
ERR_NULL = 'NULL'                # NULL means an exception is set
ERR_NULL_OR_MISSING = 'MISSING'  # NULL without an exception means "absent"
ERR_MINUS1 = 'MINUS1'            # -1 with an exception set


class Escape:
    """A C function with a Python reference implementation.

    template: C expression; ``{0}``, ``{1}`` are the lowered arguments and
        ``{id0}``, ``{id1}`` are string-constant arguments used as C
        identifiers (e.g. ``&_Py_ID({id1})``).
    returns: 'object' (new reference) or 'Py_ssize_t'.
    """

    def __init__(self, func, template, returns, error):
        self.func = func
        self.template = template
        self.returns = returns
        self.error = error

    def __call__(self, *args):
        return self.func(*args)


class ContextEscape:
    """A ``with C.<name>(x):`` block lowered to begin/end macros."""

    def __init__(self, begin, end):
        self.begin = begin
        self.end = end

    def __call__(self, obj):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class RaiseEscape:
    """``raise C.<name>()``: a C statement that sets an exception.

    Called from Python it returns the exception to raise.
    """

    def __init__(self, template, func):
        self.template = template
        self.func = func

    def __call__(self):
        return self.func()


def escape(template, *, returns='object', error=ERR_NULL):
    def decorator(func):
        return Escape(func, template, returns, error)
    return decorator


PY_SSIZE_T_MAX = sys.maxsize


def _lookup_special(obj, name):
    for klass in type(obj).__mro__:
        if name in klass.__dict__:
            attr = klass.__dict__[name]
            get = getattr(type(attr), '__get__', None)
            if get is None:
                return attr
            return get(attr, obj, type(obj))
    return NULL


def _as_ssize_t(o, exc):
    i = operator.index(o)
    if -PY_SSIZE_T_MAX - 1 <= i <= PY_SSIZE_T_MAX:
        return i
    if exc is None:
        return PY_SSIZE_T_MAX if i > 0 else -PY_SSIZE_T_MAX - 1
    raise exc(f"cannot fit '{tp_name(type(o))}' into an index-sized integer")


def _bytes_from_sequence(x):
    out = bytearray()
    for item in x:
        if not issubclass(type(item), int):
            return NULL
        try:
            value = _as_ssize_t(item, OverflowError)
        except OverflowError:
            return NULL
        if not 0 <= value < 256:
            raise ValueError("bytes must be in range(0, 256)")
        out.append(value)
    return bytes(out)


def _bytes_from_iterator(it, x):
    operator.length_hint(x, 64)
    out = bytearray()
    for item in it:
        value = _as_ssize_t(item, None)
        if not 0 <= value < 256:
            raise ValueError("bytes must be in range(0, 256)")
        out.append(value)
    return bytes(out)


class C:
    lookup_special = escape(
        '_PyObject_LookupSpecial({0}, &_Py_ID({id1}))',
        error=ERR_NULL_OR_MISSING)(_lookup_special)

    PyUnicode_AsEncodedString = escape(
        'PyUnicode_AsEncodedString({0}, {1}, {2})')(
        lambda s, encoding, errors: str.encode(
            s, encoding, 'strict' if errors is NULL else errors))

    PyNumber_AsSsize_t = escape(
        'PyNumber_AsSsize_t({0}, {1})',
        returns='Py_ssize_t', error=ERR_MINUS1)(_as_ssize_t)

    _PyBytes_FromSize = escape('_PyBytes_FromSize({0}, {1})')(
        lambda size, zero: b'\0' * size)

    _PyBytes_FromBuffer = escape('_PyBytes_FromBuffer({0})')(
        lambda x: memoryview(x).tobytes())

    # NULL without an exception: an item is not an int in range of
    # Py_ssize_t, use the generic iterator path.
    _PyBytes_FromSequence_lock_held = escape(
        '_PyBytes_FromSequence_lock_held({0})',
        error=ERR_NULL_OR_MISSING)(_bytes_from_sequence)

    _PyBytes_FromIterator = escape('_PyBytes_FromIterator({0}, {1})')(
        _bytes_from_iterator)

    # Borrows its second argument.
    bytes_subtype_new = escape('bytes_subtype_new({0}, {1})')(
        lambda cls, value: bytes.__new__(cls, value))

    PyErr_BadInternalCall = RaiseEscape(
        'PyErr_BadInternalCall();',
        lambda: SystemError('bad argument to internal function'))

    critical_section_sequence_fast = ContextEscape(
        'Py_BEGIN_CRITICAL_SECTION_SEQUENCE_FAST({0});',
        'Py_END_CRITICAL_SECTION_SEQUENCE_FAST();')


# ---------------------------------------------------------------------------
# C API facts vocabulary
#
# Annotations of the top-level functions of a spec, which describe C
# functions (the C API catalog, checked by capi.py).  Plain Python values:
# the spec is executed to evaluate them.
#
# C types (parameter and return annotations)
#     object          PyObject *
#     cstr            const char *        (defined above)
#     char_p          char *
#     void_p          void *
#     const_void_p    const void *
#     Py_ssize_t      Py_ssize_t
#     int             int
#     va_list         va_list
#     pointer('T')    T *                 (e.g. pointer('PyBytesWriter'))
#     None            void                (return only)
#     *args: ...      C varargs ``...``
#     Out[T]          T *: the callee stores a T in it (Out[object] stores a
#                     new reference)
#     InOut[object]   PyObject **: a reference owned by the caller, which the
#                     callee may replace (releasing the old one)
#
# Ownership
#     New[object]     return: a new (strong) reference
#     Borrowed[object] return: a borrowed reference
#     Steals[T]       parameter: the callee takes over the caller's reference
#                     (or, for a non-object such as a PyBytesWriter *,
#                     consumes it); other object parameters are borrowed
#
# Error convention (return annotation)
#     New[...] / Borrowed[...]   NULL with an exception set on error
#     None                       cannot fail (unless OnError says otherwise)
#     OnError[T, v, ...]         returns v (NULL or -1) with an exception
#                                set on error; NullIn('p') means that on
#                                error *p is released and set to NULL
#     NoError[T]                 cannot fail (any value is a valid result)
#     Any other return type must say OnError or NoError.
#
# Side effects
#     RunsPython[T]   (return) may run arbitrary Python code (__index__,
#                     __buffer__, __iter__, warnings, ...).  A stub without it
#                     claims the function never runs Python code.
#
# For a function with a real body, these facts are derived, not declared.


class CType:
    """A C type that has no Python spelling."""

    def __init__(self, c):
        self.c = c

    def __repr__(self):
        return f'CType({self.c!r})'


char_p = CType('char *')
void_p = CType('void *')
const_void_p = CType('const void *')
Py_ssize_t = CType('Py_ssize_t')
va_list = CType('va_list')


def pointer(name):
    """``name *``: pointer to a C struct, e.g. pointer('PyBytesWriter')."""
    return CType(f'{name} *')


class Fact:
    """``Name[args]``: an annotation wrapper."""

    def __init__(self, kind, args):
        self.kind = kind
        self.args = args

    def __repr__(self):
        return f'{self.kind}[{", ".join(map(repr, self.args))}]'


class _Wrapper:
    def __init__(self, kind, doc):
        self.kind = kind
        self.__doc__ = doc

    def __getitem__(self, args):
        if not isinstance(args, tuple):
            args = (args,)
        return Fact(self.kind, args)

    def __repr__(self):
        return self.kind


New = _Wrapper('New', 'Return: a new reference; NULL on error.')
Borrowed = _Wrapper('Borrowed', 'Return: a borrowed reference; NULL on error.')
Steals = _Wrapper('Steals', 'Parameter: the callee takes the reference.')
Out = _Wrapper('Out', 'Parameter: T *, the callee stores a T.')
InOut = _Wrapper('InOut', 'Parameter: PyObject **, the callee may replace '
                          'the caller-owned reference.')
OnError = _Wrapper('OnError', 'Return: OnError[T, value, ...]: value with '
                              'an exception set on error.')
NoError = _Wrapper('NoError', 'Return: cannot fail.')
RunsPython = _Wrapper('RunsPython', 'Return: may run arbitrary Python code.')


class NullIn:
    """Error convention: on error, *param is released and set to NULL."""

    def __init__(self, param):
        self.param = param

    def __repr__(self):
        return f'NullIn({self.param!r})'

    def __eq__(self, other):
        return isinstance(other, NullIn) and other.param == self.param

    def __hash__(self):
        return hash(('NullIn', self.param))


def load(path):
    """Execute the spec at *path*; return its functions and methods.

    The result maps "PyBytes_FromObject" or "bytes.__new__" to the Python
    function.  ``class T:`` in a spec describes the builtin type T, so once
    the spec has run, the global T is the builtin again: bodies compare
    with the real type.  Calls ``T.m(...)`` of spec methods call the spec
    method, as in the generated C.
    """
    with open(path, encoding='utf-8') as f:
        tree = ast.parse(f.read(), path)
    classes = {node.name for node in tree.body
               if isinstance(node, ast.ClassDef)}

    class SpecCalls(ast.NodeTransformer):
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
    exec(compile(tree, path, 'exec'), module.__dict__)
    functions = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            functions[node.name] = getattr(module, node.name)
        elif isinstance(node, ast.ClassDef):
            spec_class = getattr(module, node.name)
            setattr(module, f'_spec_{node.name}', spec_class)
            setattr(module, node.name, getattr(builtins, node.name))
            for item in node.body:
                if isinstance(item, ast.FunctionDef):
                    functions[f'{node.name}.{item.name}'] = (
                        spec_class.__dict__[item.name])
    return {name: getattr(func, '__func__', func)
            for name, func in functions.items()}

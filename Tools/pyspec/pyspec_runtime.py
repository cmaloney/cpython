"""Names a pyspec file may use, with Python reference implementations.

A pyspec file is ordinary Python.  Running it with this module gives the
reference behavior; Tools/pyspec/emit_c.py reads the same file with the
ast module and lowers it to C.  Three kinds of names appear in a spec:

* functions defined in the spec itself (lowered to static C functions,
  or inlined by the partial evaluator);
* the builtins below, which have fixed C meanings;
* escapes, ``C.<name>(...)``: C functions called directly.  Each carries
  its C call template, result type and error convention for the emitter.
"""

import operator
import sys

__all__ = ['NULL', 'C', 'cstr', 'isinstance', 'tp_name', 'fqname']


class _Null:
    """C NULL: an argument that was not passed, or a lookup that failed."""

    def __repr__(self):
        return 'NULL'

    def __bool__(self):
        raise TypeError('compare with "is NULL", do not test truthiness')


NULL = _Null()

# Annotation for a ``const char *`` parameter (NULL when not given).
cstr = str


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

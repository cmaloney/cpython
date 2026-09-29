"""Run a spec as a pure-Python type: the model.

``Model(path).types`` are Python classes built from the classes of the
spec at *path* (and of the specs it imports): each method and slot runs
its spec body -- a generated one, a ``@native`` reference or a
``@native(facts=False)`` pure-Python body -- through what the C around
it does: the argument parsing clinic generates for its signature (Parser)
and the descriptors and slot wrappers of Objects/descrobject.c and
Objects/typeobject.c.  The specs run with their class names bound to the
model classes, and store their bytes and fields with the primitives of
machine.py.  Pyspec_parity.py compares the model with the C type
(``pyspec_parity.py model``; Objects/pyspec/README.rst, "Pure Python").

A method whose body is still ``...`` is *delegated*: its model converts
its arguments to host objects, calls the C method and converts the
result back.  That is circular (the model uses the type it describes),
and coverage() says which methods are.

Two rules keep a body non-circular (check_circular()): a type another
spec describes (bytearray, memoryview...) may be named as a type (type
tests), never called or its attributes read; only the primitives of
machine.py touch host bytes.
"""

import ast
import builtins
import functools
import os
import sys
import types

from . import frontend, machine, specfiles
from .runtime import NULL, tp_name

SPEC_ROOTS = ('Objects', 'Modules', 'Python', 'Include')

# What the C API calls an absent default: c_default values of the specs.
C_DEFAULTS = {'NULL': NULL, '0': 0, 'PY_SSIZE_T_MAX': sys.maxsize}

# Host types a model may name as types but never call or read attributes
# of, besides those the specs describe: the view of an exported buffer.
TYPE_ONLY = ('memoryview',)


class CircularError(AssertionError):
    """A model used a host type it describes."""


# -- the descriptors (Objects/descrobject.c) ---------------------------------
#
# The model's methods are these descriptors, named after the C types they
# model (type(x).__name__ is ``method_descriptor``...), so that the tools
# that probe a type see the same kinds of attributes.  A call is
# ``_call(obj, args, kwargs, where)``: *where* names the callable in the
# messages of its argument parsing (the class of a bound self:
# ``Sub.partition()``).

def _named(name):
    """A class decorator: the class is named after the C type it models."""
    def rename(cls):
        cls.__name__ = cls.__qualname__ = name
        cls.__module__ = 'builtins'
        return cls
    return rename


class _Callable:
    """What the descriptors and their bound forms share: the name,
    docstring and text signature clinic generates, and the call."""

    def __init__(self, owner, name, call, doc, text_signature):
        self._owner = owner         # the model class
        self.__name__ = name
        self.__qualname__ = f'{owner.__name__}.{name}'
        self._call = call
        self.__doc__ = doc
        self.__text_signature__ = text_signature

    def __repr__(self):
        return self._repr

    def __reduce__(self):
        return (getattr, (self._owner, self.__name__))


class _Bound(_Callable):
    def __init__(self, descr, obj):
        where = obj if builtins.isinstance(obj, type) else type(obj)
        super().__init__(where, descr.__name__, descr._call,
                         descr.__doc__, descr.__text_signature__)
        self.__self__ = obj

    def __call__(self, *args, **kwargs):
        return self._call(self.__self__, args, kwargs, self.__qualname__)

    def __eq__(self, other):
        return (type(other) is type(self) and other._call is self._call
                and other.__self__ is self.__self__)

    def __hash__(self):
        return hash((self._call, id(self.__self__)))


@_named('builtin_function_or_method')
class BuiltinMethod(_Bound):
    """A method bound to self (or to the class: METH_CLASS)."""

    def __init__(self, descr, obj):
        super().__init__(descr, obj)
        self.__module__ = None
        if builtins.isinstance(obj, type):
            self._repr = (f'<built-in method {self.__name__} of type object '
                          f'at {hex(id(obj))}>')
        else:
            self._repr = (f'<built-in method {self.__name__} of '
                          f'{type(obj).__name__} object at {hex(id(obj))}>')


@_named('method-wrapper')
class MethodWrapper(_Bound):
    """A slot wrapper bound to self."""

    def __init__(self, descr, obj):
        super().__init__(descr, obj)
        self._repr = (f"<method-wrapper '{self.__name__}' of "
                      f"{type(obj).__name__} object at {hex(id(obj))}>")


class _Descriptor(_Callable):
    def __init__(self, *args):
        super().__init__(*args)
        self._repr = (f"<method '{self.__name__}' of "
                      f"'{self._owner.__name__}' objects>")

    @property
    def __objclass__(self):
        return self._owner


@_named('method_descriptor')
class MethodDescriptor(_Descriptor):
    """A method of the method table of a type (PyMethodDef)."""

    def __get__(self, obj, cls=None):
        if obj is None:
            return self
        return BuiltinMethod(self, obj)

    def __call__(self, *args, **kwargs):
        if not args:
            raise TypeError(f"unbound method {self.__qualname__}() needs "
                            "an argument")
        obj = args[0]
        if not builtins.isinstance(obj, self._owner):
            raise TypeError(f"descriptor '{self.__name__}' for "
                            f"'{self._owner.__name__}' objects doesn't apply "
                            f"to a '{tp_name(type(obj))}' object")
        return self._call(obj, args[1:], kwargs, self.__qualname__)


@_named('classmethod_descriptor')
class ClassMethodDescriptor(_Descriptor):
    """A METH_CLASS method: bound to the class."""

    def __get__(self, obj, cls=None):
        return BuiltinMethod(self, type(obj) if cls is None else cls)

    def __call__(self, *args, **kwargs):
        owner = self._owner.__name__
        if not args:
            raise TypeError(f"descriptor '{self.__name__}' of '{owner}' "
                            "object needs an argument")
        cls = args[0]
        if not builtins.isinstance(cls, type):
            raise TypeError(f"descriptor '{self.__name__}' for type "
                            f"'{owner}' needs a type, not a "
                            f"'{tp_name(type(cls))}' as arg 2")
        if not builtins.issubclass(cls, self._owner):
            raise TypeError(f"descriptor '{self.__name__}' requires a "
                            f"subtype of '{owner}' but received "
                            f"'{tp_name(cls)}'")
        return self._call(cls, args[1:], kwargs, f'{cls.__name__}.'
                          f'{self.__name__}')


@_named('builtin_function_or_method')
class StaticMethod(_Callable):
    """A METH_STATIC method (``bytes.maketrans``), in a staticmethod."""

    def __init__(self, *args):
        super().__init__(*args)
        self.__self__ = None
        self.__module__ = None
        self._repr = f'<built-in method {self.__name__}>'

    def __call__(self, *args, **kwargs):
        return self._call(None, args, kwargs, self.__qualname__)


@_named('wrapper_descriptor')
class WrapperDescriptor(_Descriptor):
    """A slot of the type as a method (the wrap_* of slotdefs[])."""

    def __init__(self, *args):
        super().__init__(*args)
        self._repr = (f"<slot wrapper '{self.__name__}' of "
                      f"'{self._owner.__name__}' objects>")

    def __get__(self, obj, cls=None):
        if obj is None:
            return self
        return MethodWrapper(self, obj)

    def __call__(self, *args, **kwargs):
        if not args:
            raise TypeError(f"descriptor '{self.__name__}' of "
                            f"'{self._owner.__name__}' object needs an "
                            "argument")
        obj = args[0]
        if not builtins.isinstance(obj, self._owner):
            raise TypeError(f"descriptor '{self.__name__}' requires a "
                            f"'{self._owner.__name__}' object but received "
                            f"a '{tp_name(type(obj))}'")
        return self._call(obj, args[1:], kwargs, self.__qualname__)


@_named('builtin_function_or_method')
class NewWrapper(_Callable):
    """``T.__new__``: tp_new_wrapper() of typeobject.c."""

    def __init__(self, owner, call):
        super().__init__(owner, '__new__', call,
                         'Create and return a new object.  See help(type) '
                         'for accurate signature.',
                         '($type, *args, **kwargs)')
        self.__self__ = owner
        self.__module__ = None
        self._repr = (f'<built-in method __new__ of type object at '
                      f'{hex(id(owner))}>')

    def __get__(self, obj, cls=None):
        return self

    def __call__(self, *args, **kwargs):
        owner = self._owner
        if not args:
            raise TypeError(f'{owner.__name__}.__new__(): not enough '
                            'arguments')
        sub = args[0]
        if not builtins.isinstance(sub, type):
            raise TypeError(f'{owner.__name__}.__new__(X): X is not a type '
                            f'object ({tp_name(type(sub))})')
        if not builtins.issubclass(sub, owner):
            raise TypeError(f'{owner.__name__}.__new__({sub.__name__}): '
                            f'{sub.__name__} is not a subtype of '
                            f'{owner.__name__}')
        return self._call(sub, args[1:], kwargs, owner.__name__)


# -- the slot wrappers (slotdefs[] of Objects/typeobject.c) ------------------

def _check_num_args(args, n):
    if len(args) != n:
        raise TypeError(f"expected {n} argument{'' if n == 1 else 's'}, "
                        f"got {len(args)}")


def slot_doc(name):
    """(__doc__, __text_signature__) of the slot wrapper of *name*."""
    from . import slots
    doc = slots.candidates(name)[0].doc
    signature, _, text = doc.partition('\n--\n\n')
    return text, signature[len(name):]


# The number of arguments of the slot wrappers after self.
SLOT_ARITY = {
    '__repr__': 0, '__str__': 0, '__hash__': 0, '__iter__': 0,
    '__next__': 0, '__len__': 0,
    '__lt__': 1, '__le__': 1, '__eq__': 1, '__ne__': 1, '__gt__': 1,
    '__ge__': 1, '__getitem__': 1, '__add__': 1, '__mul__': 1,
    '__rmul__': 1, '__mod__': 1, '__rmod__': 1, '__contains__': 1,
    '__buffer__': 1,
}


def slot_call(name, body):
    """The call of the slot wrapper of dunder *name*, calling *body* (the
    slot's function) as the wrap_* function of slotdefs[] does."""
    arity = SLOT_ARITY[name]

    def call(obj, args, kwargs, where):
        if kwargs:
            raise TypeError(f'wrapper {name}() takes no keyword arguments')
        if name == '__buffer__':
            # wrap_buffer(): PyArg_UnpackTuple(), then the flags.
            if len(args) != 1:
                raise TypeError(f'__buffer__ expected 1 argument, got '
                                f'{len(args)}')
            flags = _index_arg(args[0], OverflowError)
            if not -2**31 <= flags < 2**31:
                raise OverflowError('buffer flags out of range')
            return body(obj, flags)
        _check_num_args(args, arity)
        if name == '__next__':
            result = body(obj)
            if result is NULL:
                raise StopIteration
            return result
        if name == '__contains__':
            return bool(body(obj, *args))
        return body(obj, *args)
    return call


def _index_arg(o, exc):
    """PyNumber_AsSsize_t(o, exc)."""
    abstract = _current.function('Objects/pyspec/abstract.py',
                                 'PyNumber_AsSsize_t')
    return abstract(o, exc)


# -- clinic's argument parsing (Tools/clinic/libclinic/parse_args.py) --------

@functools.cache
def _suggest(candidates, word):
    try:
        from _suggestions import _generate_suggestions
    except ImportError:
        return None
    return _generate_suggestions(list(candidates), word)


class Param:
    """A parameter of a spec signature: its converter and defaults."""

    def __init__(self, arg, kind, default):
        self.name = arg.arg
        self.kind = kind            # 'posonly', 'pos' or 'kwonly'
        self.converter = 'object'
        self.options = {}
        match arg.annotation:
            case ast.Name(conv):
                self.converter = conv
            case ast.Call(func=ast.Name(conv), keywords=keywords):
                self.converter = conv
                self.options = {kw.arg: kw.value for kw in keywords}
        self.required = default is None
        self.default = NULL
        if default is not None:
            c_default = self.options.get('c_default')
            if c_default is not None:
                self.default = C_DEFAULTS[ast.literal_eval(c_default)]
            elif isinstance(default, ast.Name) and default.id == 'NULL':
                self.default = NULL
            else:
                value = ast.literal_eval(default)
                if self.converter == 'char':
                    value = value[0]
                self.default = value


class Parser:
    """The argument parsing clinic generates for a spec signature: which
    convention (METH_NOARGS, METH_O, positional only, keywords) and each
    converter, with its error messages."""

    def __init__(self, node, name, qualname, *, is_new=False,
                 convention=None, self_param=True):
        args = node.args
        positional = args.posonlyargs + args.args
        if self_param:
            positional = positional[1:]
        ndefaults = len(args.defaults)
        defaults = [None] * (len(args.posonlyargs + args.args)
                             - ndefaults) + list(args.defaults)
        if self_param:
            defaults = defaults[1:]
        posonly = {a.arg for a in args.posonlyargs}
        self.params = [Param(a, 'posonly' if a.arg in posonly else 'pos', d)
                       for a, d in zip(positional, defaults)]
        self.params += [Param(a, 'kwonly', d) for a, d in
                        zip(args.kwonlyargs, args.kw_defaults)]
        self.varargs = args.vararg is not None
        self.varkw = args.kwarg is not None
        self.name = name            # clinic's {name}: "split", "bytes"
        self.qualname = qualname    # "bytes.split"
        self.is_new = is_new
        if convention is None:
            convention = self._convention()
        self.convention = convention
        self.pos_only = sum(p.kind == 'posonly' for p in self.params)
        self.max_pos = sum(p.kind != 'kwonly' for p in self.params)
        self.min_pos = max((i + 1 for i, p in enumerate(self.params)
                            if p.kind != 'kwonly' and p.required),
                           default=0)
        self.min_kw = sum(p.kind == 'kwonly' and p.required
                          for p in self.params)

    def _convention(self):
        params = self.params
        if not params and not self.varargs and not self.varkw:
            return 'METH_NOARGS'
        if (len(params) == 1 and params[0].kind == 'posonly'
                and params[0].required and not self.varargs
                and not self.is_new):
            return 'METH_O'
        if all(p.kind == 'posonly' for p in params) and not self.varkw:
            return 'positional'
        return 'keywords'

    def __call__(self, args, kwargs, where=None):
        """The values of the parameters (converted; the default, often
        NULL, where absent); *where* names the callable (``Sub.split``)."""
        where = where or self.qualname
        convention = self.convention
        nargs = len(args)
        if convention in ('METH_VARARGS', 'METH_FASTCALL'):
            if kwargs and not self.varkw:
                raise TypeError(f'{where}() takes no keyword '
                                'arguments')
            return [args, kwargs] if self.varkw else [args]
        if convention == 'METH_NOARGS':
            if kwargs:
                raise TypeError(f'{where}() takes no keyword '
                                'arguments')
            if nargs:
                raise TypeError(f'{where}() takes no arguments '
                                f'({nargs} given)')
            return []
        if convention == 'METH_O':
            if kwargs:
                raise TypeError(f'{where}() takes no keyword '
                                'arguments')
            if nargs != 1:
                raise TypeError(f'{where}() takes exactly one '
                                f'argument ({nargs} given)')
            return [self.convert(self.params[0], args[0], 'argument')]
        if convention == 'positional':
            if kwargs:
                where = f'{self.name}()' if self.is_new else \
                    f'{where}()'
                raise TypeError(f'{where} takes no keyword arguments')
            self._check_positional(nargs)
            values = []
            for i, p in enumerate(self.params):
                if i < nargs:
                    values.append(self.convert(p, args[i],
                                               f'argument {i + 1}'))
                else:
                    values.append(p.default)
            return values
        return self._unpack_keywords(args, kwargs)

    def _check_positional(self, nargs):
        """_PyArg_CheckPositional()."""
        lo, hi = self.min_pos, self.max_pos
        if lo <= nargs <= hi:
            return
        if lo == hi:
            which = ''
        elif nargs < lo:
            which = 'at least '
        else:
            which = 'at most '
        n = lo if nargs < lo else hi
        raise TypeError(f"{self.name} expected {which}{n} argument"
                        f"{'' if n == 1 else 's'}, got {nargs}")

    def _unpack_keywords(self, args, kwargs):
        """_PyArg_UnpackKeywords(), then each converter."""
        fname = f'{self.name}()'
        nargs = len(args)
        kwnames = [p.name for p in self.params if p.kind != 'posonly']
        posonly = self.pos_only
        maxargs = posonly + len(kwnames)
        maxpos, minpos, minkw = self.max_pos, self.min_pos, self.min_kw
        reqlimit = maxpos + minkw if minkw else minpos
        minposonly = min(posonly, minpos)
        nkwargs = len(kwargs)
        if not (nkwargs == 0 and minkw == 0 and minpos <= nargs
                and nargs <= maxpos):
            if nargs + nkwargs > maxargs:
                raise TypeError(
                    f"{fname} takes at most {maxargs} "
                    f"{'keyword ' if nargs == 0 else ''}argument"
                    f"{'' if maxargs == 1 else 's'} ({nargs + nkwargs} given)")
            if nargs > maxpos:
                if maxpos == 0:
                    raise TypeError(f'{fname} takes no positional arguments')
                raise TypeError(
                    f"{fname} takes {'at most' if minpos < maxpos else 'exactly'}"
                    f" {maxpos} positional argument{'' if maxpos == 1 else 's'}"
                    f" ({nargs} given)")
            if nargs < minposonly:
                raise TypeError(
                    f"{fname} takes "
                    f"{'at least' if minposonly < maxpos else 'exactly'}"
                    f" {minposonly} positional argument"
                    f"{'' if minposonly == 1 else 's'} ({nargs} given)")
        buf = list(args) + [NULL] * (len(self.params) - nargs)
        left = dict(kwargs)
        for i in range(max(nargs, posonly), maxargs):
            name = kwnames[i - posonly]
            if name in left:
                buf[i] = left.pop(name)
            elif nkwargs == 0 and i >= reqlimit:
                break
            elif i < minpos or (maxpos <= i < reqlimit):
                raise TypeError(f"{fname} missing required argument "
                                f"'{name}' (pos {i + 1})")
        if left:
            for i in range(posonly, nargs):
                name = kwnames[i - posonly]
                if name in kwargs:
                    raise TypeError(f"argument for {fname} given by name "
                                    f"('{name}') and position ({i + 1})")
            for key in kwargs:
                if not builtins.isinstance(key, str):
                    raise TypeError('keywords must be strings')
                if key not in kwnames:
                    hint = _suggest(tuple(kwnames), key)
                    if hint:
                        raise TypeError(f"{fname} got an unexpected keyword "
                                        f"argument '{key}'. Did you mean "
                                        f"'{hint}'?")
                    raise TypeError(f"{fname} got an unexpected keyword "
                                    f"argument '{key}'")
            raise TypeError(f'invalid keyword argument for {fname}')
        values = []
        for i, (p, value) in enumerate(zip(self.params, buf)):
            if value is NULL:
                values.append(p.default)
            else:
                display = (f'argument {i + 1}' if p.kind == 'posonly'
                           else f'argument {p.name!r}')
                values.append(self.convert(p, value, display))
        return values

    def bad_argument(self, display, expected, arg):
        """_PyArg_BadArgument()."""
        return TypeError(f"{self.name}() {display} must be {expected}, not "
                         f"{'None' if arg is None else tp_name(type(arg))}")

    def convert(self, p, value, display):
        """The value of parameter *p* for argument *value*."""
        conv = p.converter
        if conv in ('object', 'self'):
            return value
        if conv == 'Py_ssize_t':
            value = _index(value)
            if not -sys.maxsize - 1 <= value <= sys.maxsize:
                raise OverflowError('Python int too large to convert to C '
                                    'ssize_t')
            return value
        if conv == 'int':
            value = _index(value)
            if not -2**31 <= value < 2**31:
                raise OverflowError('Python int too large to convert to C '
                                    'int')
            return value
        if conv == 'slice_index':
            # _PyEval_SliceIndex(): None keeps the default.
            if value is None:
                return p.default
            if not hasattr(type(value), '__index__'):
                raise TypeError('slice indices must be integers or have an '
                                '__index__ method')
            value = _index(value)
            return max(-sys.maxsize - 1, min(value, sys.maxsize))
        if conv == 'str':
            if not builtins.isinstance(value, str):
                raise self.bad_argument(display, 'str', value)
            value.encode('utf-8')           # PyUnicode_AsUTF8AndSize()
            if '\0' in value:
                raise ValueError('embedded null character')
            return value
        if conv == 'bool':
            return builtins.bool(value)
        if conv == 'char':
            for tp in _BYTES_TYPES():
                if builtins.isinstance(value, tp):
                    items = machine.buffer_items(value)
                    if len(items) != 1:
                        raise TypeError(
                            f'{self.name}(): {display} must be a byte string '
                            f'of length 1, not a {tp.__name__} object of '
                            f'length {len(items)}')
                    return items[0]
            raise self.bad_argument(display, 'a byte string of length 1',
                                    value)
        if conv == 'Py_buffer':
            items = machine.buffer_items(value)
            if items is NULL:
                raise TypeError('a bytes-like object is required, not '
                                f"'{tp_name(type(value))}'")
            return machine.Buffer(items, value)
        raise NotImplementedError(f'converter {conv} in the model')


def _BYTES_TYPES():
    """The types of clinic's char converter: bytes, then bytearray (the
    model's where there is one)."""
    return (_current.builtins['bytes'], _current.builtins['bytearray'])


def _index(o):
    """_PyNumber_Index() (Objects/pyspec/abstract.py), as clinic's
    integer converters call it."""
    return _current.function('Objects/pyspec/abstract.py',
                             '_PyNumber_Index')(o)


# The Model whose classes are being called (the converters need its
# bytes).  One model at a time.
_current = None


# -- running the specs as the model -----------------------------------------

class _SpecCalls(ast.NodeTransformer):
    """``T.meth(...)`` in a body calls the spec method (the C impl), not
    the model's parsing entry: ``_spec_T.meth``.  A bytes literal in a
    body is a bytes of the model (``_pyspec_bytes(items)``)."""

    def __init__(self, classes):
        self.classes = classes
        self.in_body = False

    def visit_FunctionDef(self, node):
        outer, self.in_body = self.in_body, True
        node.body = [self.visit(stmt) for stmt in node.body]
        self.in_body = outer
        return node

    def visit_Constant(self, node):
        if self.in_body and isinstance(node.value, bytes):
            return ast.copy_location(ast.Call(
                ast.Name('_pyspec_bytes', ast.Load()),
                [ast.Constant(tuple(node.value))], []), node)
        return node

    def visit_Attribute(self, node):
        self.generic_visit(node)
        if (isinstance(node.value, ast.Name)
                and node.value.id in self.classes
                and isinstance(node.ctx, ast.Load)
                and not node.attr.startswith('__')
                or isinstance(node.value, ast.Name)
                and node.value.id in self.classes
                and node.attr == '__new__'):
            node.value = ast.copy_location(
                ast.Name(f'_spec_{node.value.id}', ast.Load()), node.value)
        return node


def _decorators(node):
    return [frontend.decorator_name(d) for d in node.decorator_list]


def has_body(node):
    """Whether spec function *node* has a body the model runs: generated,
    a @native reference or a pure-Python @native(facts=False) body."""
    return not frontend.is_literal_stub(node)


class Model:
    """The model classes of the spec at *path* and of the specs it
    imports: ``types`` by class name."""

    def __init__(self, path, srcdir=None):
        global _current
        self.srcdir = srcdir or specfiles.srcdir()
        self.modules = {}           # absolute path -> module
        self.specs = {}             # absolute path -> frontend.Spec
        self.types = {}             # class name -> model class
        self.raw = {}               # class name -> spec class
        self.kinds = {}             # "T.meth" -> 'pure' or 'delegated'
        self.nodes = {}             # "T.meth" -> (spec, def)
        self.templates = {}         # see template()
        self.module_of_type = {}    # model class -> module of its spec
        self.builtins = dict(vars(builtins))
        self.builtins['__import__'] = self._import
        self.builtins['_pyspec_bytes'] = lambda items: self.function(
            'Objects/pyspec/bytesobject.py', 'new_bytes')(items)
        _current = self
        self.module(os.path.abspath(path))

    def function(self, rel, name):
        return getattr(self.module(os.path.join(self.srcdir, rel)), name)

    def _import(self, name, globals=None, locals=None, fromlist=(),
                level=0):
        root = name.partition('.')[0]
        if level or root not in SPEC_ROOTS:
            return builtins.__import__(name, globals, locals, fromlist,
                                       level)
        path = os.path.join(self.srcdir, *name.split('.'))
        if os.path.isfile(path + '.py'):
            return self.module(path + '.py')
        package = types.SimpleNamespace()
        for item in fromlist or ():
            setattr(package, item,
                    self.module(os.path.join(path, item + '.py')))
        return package

    def __hash__(self):
        return id(self)

    def module(self, path):
        path = os.path.abspath(path)
        if path in self.modules:
            return self.modules[path]
        with open(path, encoding='utf-8') as f:
            source = f.read()
        tree = ast.parse(source, path)
        classes = {n.name for n in tree.body if isinstance(n, ast.ClassDef)}
        tree = ast.fix_missing_locations(_SpecCalls(classes).visit(tree))
        stem = os.path.splitext(os.path.basename(path))[0]
        module = types.ModuleType(f'_pyspec_model_{stem}')
        module.__file__ = path
        module.__builtins__ = self.builtins
        import importlib.machinery
        module.__loader__ = importlib.machinery.SourceFileLoader(
            module.__name__, path)
        module.__spec__ = importlib.machinery.ModuleSpec(
            module.__name__, module.__loader__, origin=path)
        self.modules[path] = module
        exec(compile(tree, path, 'exec'), module.__dict__)
        spec = frontend.Spec.load(path)
        self.specs[path] = spec
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            raw = getattr(module, node.name)
            setattr(module, f'_spec_{node.name}', raw)
            if not (spec.declares_slots(node.name)
                    or node.name in self.builtins):
                continue            # stringlib's B: methods only
            self.raw[node.name] = raw
            model = self.build(spec, node, raw, module)
            self.types[node.name] = model
            setattr(module, node.name, model)
            self.builtins[node.name] = model
        return module

    # -- the model classes -----------------------------------------------

    def build(self, spec, node, raw, module):
        """The model class of spec class *node*: its fields (``ob_sval:
        'char[]'``, ``it_index: Py_ssize_t``) in a base of their own, its
        methods, and what it takes from its PyTypeObject, which the spec
        does not describe: whether it can be subclassed or instantiated
        (machine.Object)."""
        fields = [(stmt.target.id, ast.unparse(stmt.annotation))
                  for stmt in node.body if isinstance(stmt, ast.AnnAssign)]
        var = any(ann.strip('\'"').endswith('[]') for _, ann in fields)
        base = machine.VarObject if var else machine.Object
        slots = tuple(name for name, ann in fields
                      if not ann.strip('\'"').endswith('[]'))
        if slots:
            base = type(f'{node.name} fields', (base,),
                        {'__slots__': slots, '__module__': 'builtins'})
        model = type(node.name, (base,), {'__slots__': (),
                                          '__module__': 'builtins',
                                          '__doc__': raw.__doc__})
        del model.__slots__
        machine.MODELS[model] = self
        self.module_of_type[model] = module
        host = host_types().get(node.name)
        if host is not None:
            machine.set_type_flags(model, host.__flags__)
        for meth in spec.entries(node.name):
            setattr(model, meth, self.member(spec, node.name, meth, raw,
                                             model))
        return model

    def body(self, raw, meth, owner, model):
        """The function of the body of *meth*, for class *model*.  A
        method shared from a template (``ctype.B.lower``) runs in the
        template instantiated for *model* (template())."""
        func = raw.__dict__[meth]
        func = getattr(func, '__func__', func)
        if owner != model.__name__ and 'B' in func.__globals__:
            func = self.template(func.__globals__, model)[1](func)
        return func

    def template(self, globals, model):
        """The functions of the template module with *globals*
        (Objects/stringlib/pyspec/), for class *model*: in C each file
        that includes the template defines STRINGLIB_NEW and friends
        before; here B is *model* and STRINGLIB_NEW the function of that
        name of the spec of *model* (its constructor from bytes)."""
        key = (id(globals), model)
        if key in self.templates:
            return self.templates[key]
        own = self.module_of_type[model]
        namespace = dict(globals)
        namespace['B'] = model
        namespace['STRINGLIB_NEW'] = getattr(own, 'STRINGLIB_NEW')
        namespace['STRINGLIB_MUTABLE'] = getattr(own, 'STRINGLIB_MUTABLE')

        def instantiate(func):
            return types.FunctionType(func.__code__, namespace,
                                      func.__name__, func.__defaults__,
                                      func.__closure__)
        for name, value in globals.items():
            if isinstance(value, types.FunctionType) \
                    and value.__module__ == globals['__name__']:
                namespace[name] = instantiate(value)
        self.templates[key] = namespace, instantiate
        return self.templates[key]

    def member(self, spec, cls_name, meth, raw, model):
        """The descriptor of method *meth* of class *cls_name*."""
        name = f'{cls_name}.{meth}'
        kind = spec.method_kind(name)
        owner_spec, owner = spec, cls_name
        if kind == frontend.SHARED:
            shared = spec.shared[name]
            owner_spec = spec.imported(shared.module) if shared.module \
                else spec
            owner = shared.cls
            node = owner_spec.functions[f'{owner}.{meth}']
            decorators = shared.decorators
            c_name = next((d for d in decorators
                           if frontend.decorator_name(d) == 'c_name'), None)
            kind = owner_spec.method_kind(f'{owner}.{meth}')
            if c_name is not None:
                kind = frontend.PYCFUNCTION
        else:
            node = spec.functions[name]
        self.nodes[name] = (owner_spec, node)
        pure = has_body(node)
        self.kinds[name] = 'pure' if pure else 'delegated'
        func = self.body(raw, meth, owner, model) if pure else None
        doc = self.docstring(owner_spec, f'{owner}.{meth}', node)
        decorators = _decorators(node)
        if meth == '__new__':
            parser = Parser(node, cls_name, f'{cls_name}.__new__',
                            is_new=True)
            if func is None:
                raise ValueError(f'{name}: __new__ has no body')
            return NewWrapper(model, lambda cls, args, kwargs, where:
                              func(cls, *parser(args, kwargs, where)))
        if kind == frontend.SLOT:
            call = slot_call(meth, func) if pure else \
                self.delegate(model, meth, slot=True)
            return WrapperDescriptor(model, meth, call, *slot_doc(meth))
        convention = None
        if kind == frontend.PYCFUNCTION:
            keywords = owner_spec.c_name(f'{owner}.{meth}')[1]
            if spec is not owner_spec or name in spec.shared:
                keywords = spec.c_name(name)[1] or keywords
            convention = next(k for k in keywords
                              if k in frontend.PYCFUNCTION_FLAGS)
            if convention == 'METH_FASTCALL' and not node.args.kwarg:
                convention = 'METH_FASTCALL'
        static = 'staticmethod' in decorators
        parser = Parser(node, meth, f'{cls_name}.{meth}',
                        convention=convention, self_param=not static)
        if pure:
            if static:
                def call(obj, args, kwargs, where):
                    return func(*parser(args, kwargs, where))
            else:
                def call(obj, args, kwargs, where):
                    return func(obj, *parser(args, kwargs, where))
        else:
            call = self.delegate(model, meth)
        text = self.text_signature(node, kind, convention)
        if static:
            return staticmethod(StaticMethod(model, meth, call, doc, text))
        if 'classmethod' in decorators:
            return ClassMethodDescriptor(model, meth, call, doc, text)
        return MethodDescriptor(model, meth, call, doc, text)

    def docstring(self, spec, name, node):
        if frontend.docstring_of(node.body) is None:
            return None
        return spec.docstring(name)

    @staticmethod
    def text_signature(node, kind, convention=None):
        """The __text_signature__ of *node*: clinic's, or the one the
        interpreter gives a METH_NOARGS or METH_O function without one in
        its docstring (_PyType_GetTextSignatureFromInternalDoc())."""
        for d in node.decorator_list:
            if (isinstance(d, ast.Call)
                    and frontend.decorator_name(d) == 'text_signature'):
                return ast.literal_eval(d.args[0])
        if kind == frontend.PYCFUNCTION:
            first = ('' if 'staticmethod' in _decorators(node) else
                     '$type, ' if 'classmethod' in _decorators(node)
                     else '$self, ')
            return {'METH_NOARGS': f'({first}/)',
                    'METH_O': f'({first}object, /)'}.get(convention)
        return _text_signature(node, kind)

    # -- delegation: a method without a body calls the C ------------------

    def delegate(self, model, meth, slot=False):
        """(self, args, kwargs) -> the C method *meth* of the host type,
        on host copies of the arguments, its result as model objects."""
        host = getattr(builtins, model.__name__, None)
        if host is None:
            host = self.host_types()[model.__name__]
        method = getattr(host, meth)

        def call(obj, args, kwargs, where):
            pairs = []
            h_obj = to_host(obj, pairs)
            h_args = [to_host(a, pairs) for a in args]
            h_kwargs = {k: to_host(v, pairs) for k, v in kwargs.items()}
            result = method(h_obj, *h_args, **h_kwargs)
            return to_model(result, self, pairs)
        return call

    def host_types(self):
        """{class name: host type} of the classes the specs describe."""
        return host_types()


def _text_signature(node, kind):
    """The __text_signature__ clinic generates for a def: ``($self, /,
    sep=None, maxsplit=-1)`` (a slot's or a PyCFunction's: typeobj.py)."""
    if kind in (frontend.SLOT, frontend.PYCFUNCTION):
        from .typeobj import _text_signature as c_signature
        return c_signature(node)
    args = node.args
    static = 'staticmethod' in _decorators(node)
    positional = args.posonlyargs + args.args
    defaults = [None] * (len(positional) - len(args.defaults)) + \
        list(args.defaults)
    n_posonly = len(args.posonlyargs)
    parts = []
    if not static:
        parts.append('$type' if 'classmethod' in _decorators(node)
                     or node.name == '__new__' else '$self')
        positional, defaults = positional[1:], defaults[1:]
        n_posonly = max(n_posonly - 1, 0)
        if not n_posonly:
            parts.append('/')
    for i, (a, d) in enumerate(zip(positional, defaults)):
        parts.append(a.arg if d is None else f'{a.arg}={_py_default(a, d)}')
        if i + 1 == n_posonly:
            parts.append('/')
    if args.vararg:
        parts.append('*' + args.vararg.arg)
    elif args.kwonlyargs:
        parts.append('*')
    for a, d in zip(args.kwonlyargs, args.kw_defaults):
        parts.append(a.arg if d is None else f'{a.arg}={_py_default(a, d)}')
    if args.kwarg:
        parts.append('**' + args.kwarg.arg)
    return '(' + ', '.join(parts) + ')'


def _py_default(arg, default):
    if isinstance(default, ast.Name) and default.id == 'NULL':
        return '<unrepresentable>'
    return repr(ast.literal_eval(default))


# -- values across the edge of the model -------------------------------------

def to_host(value, pairs=None):
    """*value* with the model objects in it as host objects (a copy);
    *pairs* collects (host, model) of each."""
    if builtins.isinstance(value, machine.VarObject):
        host = getattr(builtins, _base_model(type(value)).__name__)(
            value._ob_items)
        if pairs is not None:
            pairs.append((host, value))
        return host
    if type(value) in (list, tuple):
        return type(value)(to_host(v, pairs) for v in value)
    return value


def _base_model(tp):
    for cls in tp.__mro__:
        if cls in machine.MODELS:
            return cls
    raise TypeError(tp)


def to_model(value, model=None, pairs=()):
    """*value* with the host objects of the types *model* describes in it
    as model objects; a host object of *pairs* is its model object."""
    model = model or _current
    for host, obj in pairs:
        if value is host:
            return obj
    tp = type(value)
    if tp is builtins.bytes and 'bytes' in model.types:
        # As a bytes literal of the spec (singletons included).
        return model.builtins['_pyspec_bytes'](
            builtins.tuple(builtins.memoryview(value)))
    if tp in (list, tuple):
        return tp(to_model(v, model, pairs) for v in value)
    for name, host_tp in model.host_types().items():
        if tp is host_tp and name in model.types and \
                getattr(builtins, name, None) is not tp:
            # An iterator: rebuilt from its state (__reduce__).
            func, args, *state = value.__reduce__()
            obj = func(*to_model(args, model))
            if state:
                obj.__setstate__(*state)
            return obj
    return value


@functools.cache
def host_types():
    """{class name: host type} of the classes the specs describe (the
    TYPES of their _cases.py)."""
    out = {}
    for path, _ in specfiles.spec_files():
        cases = specfiles.load_cases(path)
        out.update(getattr(cases, 'TYPES', {}) if cases else {})
    return out


# -- the non-circularity check -----------------------------------------------

def check_circular(model):
    """{"T.meth" or function: [what]}: the uses of host types the specs
    describe in the bodies the model runs (other than as a type), and
    the methods it delegates to the C."""
    described = set(model.host_types()) | set(TYPE_ONLY)
    described -= set(model.types)
    out = {}
    for name, kind in model.kinds.items():
        if kind == 'delegated':
            out.setdefault(name, []).append('delegated to the C')
    for path, spec in model.specs.items():
        for name, node in spec.functions.items():
            if not has_body(node):
                continue
            for what in _circular_uses(node, described, spec):
                out.setdefault(name, []).append(what)
    return out


def _circular_uses(node, described, spec):
    for child in ast.walk(node):
        match child:
            case ast.Call(func=ast.Name(name)) if name in described:
                yield f'calls {name}() at line {child.lineno}'
            case ast.Attribute(value=ast.Name(name), attr=attr) \
                    if name in described:
                yield f'uses {name}.{attr} at line {child.lineno}'

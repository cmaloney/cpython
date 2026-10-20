"""Argument Clinic, as a spec names it: ``from libclinic.pyspec import ac``.

Every name a spec takes from Argument Clinic is qualified by this module
(Objects/pyspec/README.rst, "The spec language"), derived from clinic's
own registries so that it cannot drift from them:

* the converters (``ac.object``, ``ac.Py_ssize_t``, ``ac.slice_index(
  accept={int, ac.NoneType}, c_default='0')``, ``ac.str(c_default=
  "NULL")``, ``ac.object(c_param='x')`` for clinic's ``name as x``) and
  return converters (``-> ac.Py_ssize_t``): Converter objects.  Called,
  a converter checks its keyword names against clinic's (its
  converter_init(), and c_default, py_default, annotation, unused,
  c_param), and raises TypeError on a typo.  A converter a C file
  defines in its ``[python input]`` block (``ac.bytesvalue``) is found
  by the module __getattr__; clinic reports an unknown one.  The names
  clinic evaluates converter arguments with are here too (``ac.NoneType``,
  ``ac.buffer``, ``ac.robuffer``, ``ac.rwbuffer``, ``ac.unspecified``);
* the clinic decorators (``@ac.permit_long_summary``, ``@ac.text_signature
  ("(...)")``, ``@ac.critical_section``, ``@ac.getter``...), identity
  decorators in Python; ``@classmethod`` and ``@staticmethod`` stay
  Python's;
* the decorators of the spec itself, which say what Argument Clinic
  outputs for a def or class (nothing without one): ``@ac.generate``,
  ``@ac.stub`` and ``@ac.inline`` (README.rst, "Decorators").

In a top-level function (the C functions spec bodies call) an annotation
is a C type: ``ac.object``, ``ac.str``, ``ac.int``, ``ac.Py_ssize_t``, or a
string (``'PyTypeObject *'``).

The module defines names such as ``str``, ``int`` and ``object``: the
code of this file uses the builtins as ``builtins.X``.
"""

import builtins
import contextlib
import inspect
import sys
from collections.abc import Iterator
from typing import Any

# Imported to register the converters and the return converters.
import libclinic.converters
import libclinic.return_converters  # noqa: F401
from libclinic.converter import CConverter, converters
from libclinic.dsl_parser import DSLParser
from libclinic.errors import SpecError
from libclinic.parser import create_parser_namespace
from libclinic.pyspec.frontend import (CLASS_OPTIONS, GENERATE, INLINE,
                                       STUB, ClassOutput, Output)
from libclinic.return_converters import return_converters

# The options every converter takes, and clinic's ``name as c_param``.
COMMON_OPTIONS = frozenset(
    set(inspect.signature(CConverter.__init__).parameters)
    - {'self', 'name', 'py_name', 'function', 'default', 'kwargs'}
    | {'c_param'})

# Python's decorators, which a spec writes bare.
PYTHON_DECORATORS = ('classmethod', 'staticmethod')


def _options(init: Any) -> set[builtins.str] | None:
    """The keyword names of *init*, or None when it takes any."""
    if init is None:
        return builtins.set()
    params = inspect.signature(init).parameters
    if any(p.kind is p.VAR_KEYWORD for p in params.values()):
        return None
    return builtins.set(params) - {'self'}


class Converter:
    """A clinic converter or return converter, with the options it is
    called with."""

    def __init__(self, name: builtins.str,
                 options: builtins.dict[builtins.str, Any] | None = None
                 ) -> None:
        self.name = name
        self.options = options or {}

    def allowed(self) -> builtins.set[builtins.str] | None:
        """The option names clinic takes for this converter, or None when
        it does not know it (a converter of a C file)."""
        if self.name not in converters and \
                self.name not in return_converters:
            return None
        allowed = builtins.set()
        if self.name in converters:
            conv = converters[self.name]
            found = _options(getattr(conv, 'converter_init', None))
            if found is None:
                return None
            allowed |= found | COMMON_OPTIONS
        if self.name in return_converters:
            found = _options(getattr(return_converters[self.name],
                                     'return_converter_init', None))
            if found is None:
                return None
            allowed |= found | {'py_default'}
        return allowed

    def __call__(self, *args: Any, **options: Any) -> Any:
        if args:
            if (self.name not in converters
                    and self.name not in return_converters):
                # Not a converter clinic knows: a clinic decorator it does
                # not know either (@ac.cname("x")), which clinic reports.
                return _identity(*args, **options)
            raise TypeError(f'ac.{self.name}() takes only keyword options')
        allowed = self.allowed()
        if allowed is not None:
            bad = builtins.sorted(builtins.set(options) - allowed)
            if bad:
                raise TypeError(f'ac.{self.name}(): unknown option'
                                f'{"s" if builtins.len(bad) > 1 else ""} '
                                f'{", ".join(bad)}; clinic takes '
                                f'{", ".join(builtins.sorted(allowed))}')
        return Converter(self.name, options)

    def __repr__(self) -> builtins.str:
        if not self.options:
            return f'ac.{self.name}'
        args = ', '.join(f'{k}={v!r}' for k, v in self.options.items())
        return f'ac.{self.name}({args})'


def _decorated(args: tuple[Any, ...], kwargs: dict[builtins.str, Any]
               ) -> bool:
    """Whether a decorator called with *args* and *kwargs* was applied
    (``@d``: one argument, the function, class or classmethod object),
    not called with its own arguments (``@d("x")``, which are strings)."""
    return (builtins.len(args) == 1 and not kwargs
            and not builtins.isinstance(args[0], builtins.str))


def _identity(*args: Any, **kwargs: Any) -> Any:
    """``@d`` or ``@d(args)``: return the function (or class) unchanged."""
    if _decorated(args, kwargs):
        return args[0]
    return lambda func: func


class Recorded:
    """What the spec decorators of a spec said while it ran (recording()),
    read by frontend.Spec."""

    def __init__(self) -> None:
        # The Output of each def, by (file, first line of the def): the
        # line of its first decorator.
        self.defs: builtins.dict[builtins.tuple[builtins.str, builtins.int],
                                 Output] = {}
        # The Output of each ``meth = ac.stub(...)(X.meth)``, by (file,
        # line it is applied on).
        self.shared: builtins.dict[builtins.tuple[builtins.str,
                                                  builtins.int], Output] = {}
        # The ClassOutput of each class with @ac.generate.
        self.classes: builtins.dict[builtins.type, ClassOutput] = {}


_recorded: Recorded | None = None


@contextlib.contextmanager
def recording() -> Iterator[Recorded]:
    """Record what the spec decorators say while the spec runs."""
    global _recorded
    saved, _recorded = _recorded, Recorded()
    try:
        yield _recorded
    finally:
        _recorded = saved


def _output(kind: builtins.str, name: builtins.str,
            args: builtins.tuple[Any, ...],
            kwargs: builtins.dict[builtins.str, Any] | None) -> Output:
    """The Output of ``@ac.<kind>(*args, **kwargs)`` (*kwargs* None for
    ``@ac.<kind>``) on def *name*; a SpecError if they are not its
    options."""
    def error(message: builtins.str) -> SpecError:
        return SpecError(f'{name}: {message}')

    out = Output(kind)
    if kwargs is None:
        return out
    if kind == INLINE:
        raise error('@ac.inline takes no arguments')
    if builtins.len(args) > 1 or not builtins.all(
            builtins.isinstance(a, builtins.str) for a in args):
        raise error(f'@ac.{kind}("f") takes one argument, the C name, a '
                    'string')
    if args:
        out.name = args[0]
    for key, value in kwargs.items():
        if kind == GENERATE:
            raise error('@ac.generate() of a def takes only the C name')
        if key == 'optimizer_info':
            if not builtins.isinstance(value, builtins.bool):
                raise error('optimizer_info=True or optimizer_info=False')
            out.optimizer_info = value
        elif key == 'slots':
            if not (builtins.isinstance(value, (builtins.list,
                                                builtins.tuple))
                    and value and builtins.all(
                        builtins.isinstance(v, builtins.str) for v in value)):
                raise error('slots= is a list of slot names: '
                            'slots=["mp_length", "sq_length"]')
            for slot in value:
                out.keywords.setdefault(slot, None)
        elif builtins.isinstance(value, builtins.str):
            out.keywords[key] = value
        else:
            raise error(f'@ac.stub({key}=...): the C name, a string')
    return out


def _class_output(cls: builtins.type, args: builtins.tuple[Any, ...],
                  kwargs: builtins.dict[builtins.str, Any]) -> ClassOutput:
    """The ClassOutput of ``@ac.generate(*args, **kwargs)`` on *cls*."""
    name = cls.__name__
    out = ClassOutput(name)
    if args:
        raise SpecError(f'class {name}: the prefix of the tables is '
                        '@ac.generate(prefix="x")')
    for key, value in kwargs.items():
        if key == 'prefix' and builtins.isinstance(value, builtins.str):
            out.prefix = value
        elif (key in CLASS_OPTIONS and key != 'prefix'
              and builtins.isinstance(value, builtins.bool)):
            builtins.setattr(out, key, value)
        else:
            raise SpecError(f'class {name}: the options of @ac.generate are '
                            'prefix="x" and doc, methods, slots=True or '
                            'False')
    return out


def _apply(kind: builtins.str, args: builtins.tuple[Any, ...],
           kwargs: builtins.dict[builtins.str, Any] | None, target: Any,
           caller: Any) -> Any:
    """Apply ``@ac.<kind>`` to *target* in the frame *caller*: check its
    options, record them (recording()), return *target* unchanged."""
    if builtins.isinstance(target, builtins.type):
        # (frontend.Spec checks that a class takes only @ac.generate.)
        if kind == GENERATE:
            found = _class_output(target, args, kwargs or {})
            if _recorded is not None:
                _recorded.classes[target] = found
        return target
    func = builtins.getattr(target, '__func__', target)
    output = _output(kind, func.__name__, args, kwargs)
    if _recorded is None:
        return target
    code = func.__code__
    if code in caller.f_code.co_consts:
        # A def of the body running: the decorators of one def.
        key = (code.co_filename, code.co_firstlineno)
        if key in _recorded.defs:
            raise SpecError(f'{func.__name__}: one of @ac.generate, '
                            '@ac.stub and @ac.inline')
        _recorded.defs[key] = output
    else:
        # ``meth = ac.stub(...)(X.meth)``: a method shared with X.
        _recorded.shared[(caller.f_code.co_filename,
                          caller.f_lineno)] = output
    return target


def _is_target(value: Any) -> bool:
    """Whether a spec decorator called with *value* alone was applied to
    it (``@ac.stub``), not called with its options (``@ac.stub("f")``)."""
    return (inspect.isfunction(value) or builtins.isinstance(
        value, (builtins.classmethod, builtins.staticmethod, builtins.type)))


class SpecDecorator:
    """``@ac.<kind>(*args, **kwargs)``, to apply to a def or a class; the
    value of ``meth = ac.stub("f")`` in a class, the C function f of a
    header (frontend.Spec._add_c_method())."""

    def __init__(self, kind: builtins.str, args: builtins.tuple[Any, ...],
                 kwargs: builtins.dict[builtins.str, Any]) -> None:
        self.kind = kind
        self.args = args
        self.kwargs = kwargs

    def __call__(self, target: Any) -> Any:
        return _apply(self.kind, self.args, self.kwargs, target,
                      sys._getframe(1))


def _spec_decorator(kind: builtins.str) -> Any:
    """``@ac.<kind>``, or ``@ac.<kind>(...)`` with its options: the def or
    class unchanged, what the decorator says recorded (recording())."""
    def decorator(*args: Any, **kwargs: Any) -> Any:
        if builtins.len(args) == 1 and not kwargs and _is_target(args[0]):
            return _apply(kind, (), None, args[0], sys._getframe(1))
        return SpecDecorator(kind, args, kwargs)
    decorator.__name__ = decorator.__qualname__ = kind
    decorator.__doc__ = (f'@ac.{kind}: see Objects/pyspec/README.rst, '
                         '"Decorators"')
    return decorator


# @ac.generate: clinic generates C from the body (or, on a class, its
# tables); @ac.stub: the clinic parts only, the C is written by hand;
# @ac.inline: the body is generated into each caller.
generate = _spec_decorator(GENERATE)
stub = _spec_decorator(STUB)
inline = _spec_decorator(INLINE)


SPEC_DECORATORS = ('generate', 'stub', 'inline')
CLINIC_DECORATORS = [name for name in DSLParser.decorator_names()
                     if name not in PYTHON_DECORATORS]
CONVERTERS = builtins.sorted(builtins.set(converters)
                             | builtins.set(return_converters))
# The names clinic evaluates the options of a converter with, other than
# the converter classes: NoneType, buffer, robuffer, rwbuffer...
PARSER_NAMES = builtins.sorted(
    name for name in create_parser_namespace()
    if not name.endswith('_converter') and name not in (
        'CConverter', 'CReturnConverter'))


def __getattr__(name: builtins.str) -> Converter:
    """A converter a C file defines (``ac.bytesvalue``): clinic says
    whether it exists."""
    if name.startswith('_'):
        raise AttributeError(name)
    if name in PYTHON_DECORATORS:
        raise AttributeError(f'@{name} is Python\'s: write @{name}, not '
                             f'@ac.{name}')
    return Converter(name)


def _define() -> None:
    namespace = builtins.globals()
    parser = create_parser_namespace()
    for name in PARSER_NAMES:
        namespace[name] = parser[name]
    for name in CONVERTERS:
        namespace[name] = Converter(name)
    for name in CLINIC_DECORATORS:
        namespace[name] = _identity


_define()

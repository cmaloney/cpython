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
import inspect
from typing import Any

# Imported to register the converters and the return converters.
import libclinic.converters
import libclinic.return_converters  # noqa: F401
from libclinic.converter import CConverter, converters
from libclinic.dsl_parser import DSLParser
from libclinic.parser import create_parser_namespace
from libclinic.return_converters import return_converters

# The options every converter takes, and clinic's ``name as c_param``.
COMMON_OPTIONS = frozenset(
    set(inspect.signature(CConverter.__init__).parameters)
    - {'self', 'name', 'py_name', 'function', 'default', 'kwargs'}
    | {'c_param'})

# The options of each spec decorator (checked again by the frontend).
STUB_OPTIONS = ('optimizer_info', 'slots', 'critical_section')
CLASS_OPTIONS = ('prefix', 'doc', 'methods', 'slots')

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

    def __call__(self, *args: Any, **options: Any) -> 'Converter':
        if args:
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


def _spec_decorator(name: builtins.str, options: tuple[builtins.str, ...]
                    ) -> Any:
    """``@ac.<name>``, ``@ac.<name>("c_name")`` or ``@ac.<name>(option=
    ...)``: the function unchanged.  The frontend checks the options (a
    slot name or METH_ flag, for @ac.stub); here only their form."""
    def decorator(*args: Any, **kwargs: Any) -> Any:
        if _decorated(args, kwargs):
            return args[0]
        if builtins.len(args) > 1 or (args and not builtins.isinstance(
                args[0], builtins.str)):
            raise TypeError(f'@ac.{name}() takes the C name, a string')
        return lambda func: func
    decorator.__name__ = decorator.__qualname__ = name
    decorator.__doc__ = (f'@ac.{name}: see Objects/pyspec/README.rst, '
                         '"Decorators"; options: '
                         + (', '.join(options) or 'none'))
    return decorator


# @ac.generate: clinic generates C from the body (or, on a class, its
# tables); @ac.stub: the clinic parts only, the C is written by hand;
# @ac.inline: the body is generated into each caller.
generate = _spec_decorator('generate', CLASS_OPTIONS)
stub = _spec_decorator('stub', STUB_OPTIONS)


def inline(func: Any) -> Any:
    """@ac.inline: the body is generated into each caller."""
    return func


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

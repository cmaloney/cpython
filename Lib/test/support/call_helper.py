"""Helpers for testing how callables treat their arguments."""

import functools
import inspect
from test.support import import_helper


# Methods that C code commonly ends up calling on its arguments.
_TRIGGER_METHODS = (
    '__index__', '__int__', '__float__', '__complex__', '__bool__',
    '__abs__', '__neg__', '__pos__', '__invert__', '__round__',
    '__trunc__', '__floor__', '__ceil__',
    '__add__', '__radd__', '__sub__', '__rsub__', '__mul__', '__rmul__',
    '__truediv__', '__rtruediv__', '__floordiv__', '__rfloordiv__',
    '__mod__', '__rmod__', '__divmod__', '__rdivmod__',
    '__pow__', '__rpow__', '__lshift__', '__rlshift__',
    '__rshift__', '__rrshift__', '__and__', '__rand__',
    '__or__', '__ror__', '__xor__', '__rxor__',
    '__eq__', '__ne__', '__lt__', '__le__', '__gt__', '__ge__', '__hash__',
    '__str__', '__repr__', '__format__', '__bytes__', '__fspath__',
    '__len__', '__iter__', '__getitem__', '__contains__',
)


def _methods(base):
    return [name for name in _TRIGGER_METHODS
            if getattr(base, name, None) is not None]


def _copy(cls, sample):
    try:
        value = cls(sample)
    except Exception:
        return None
    # Compare with the base type's __eq__, not a trigger's.
    return value if type(sample).__eq__(value, sample) is True else None


@functools.cache
def _value_type(base):
    # Instances of a Python subclass are really freed when released, while
    # instances of the base type may be cached or kept on a free list,
    # which hides a use-after-free.
    try:
        return type(base.__name__, (base,), {})
    except TypeError:
        return None


def _make_value(sample):
    cls = _value_type(type(sample))
    value = _copy(cls, sample) if cls is not None else None
    return sample if value is None else value


def _subclass_trigger(sample, release):
    # A subclass whose dunder methods call release() first.
    base = type(sample)
    def wrap(name):
        base_method = getattr(base, name)
        def method(self, /, *args, **kwargs):
            release()
            return base_method(self, *args, **kwargs)
        return method
    try:
        cls = type(base.__name__, (base,),
                   {name: wrap(name) for name in _methods(base)})
    except TypeError:
        return None
    return _copy(cls, sample)


def _proxy_trigger(sample, release):
    # An object of an unrelated type that forwards dunder methods to sample,
    # so that C code has to call them (e.g. __index__ for an int parameter).
    def wrap(name):
        def method(self, /, *args, **kwargs):
            release()
            return getattr(sample, name)(*args, **kwargs)
        return method
    names = _methods(type(sample))
    if not names:
        return None
    return type(type(sample).__name__ + 'Proxy', (),
                {name: wrap(name) for name in names})()


_TRIGGERS = {'subclass': _subclass_trigger, 'proxy': _proxy_trigger}


def _parameters(func, samples):
    try:
        params = [p for p in inspect.signature(func).parameters.values()
                  if p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)]
    except (ValueError, TypeError):
        # No usable signature: the samples are the parameters, in order.
        return [inspect.Parameter(name, inspect.Parameter.POSITIONAL_OR_KEYWORD)
                for name in samples]
    for p in params:
        if p.name not in samples:
            if p.default is p.empty:
                raise TypeError(f'no sample value for {p.name!r}')
            samples[p.name] = p.default
    return params


def check_arguments_released_during_call(test, func, /, **samples):
    """Check that func keeps its arguments alive while running Python code.

    Arguments are passed as borrowed references which a dunder method of
    one argument releases.  Sample values default to the parameter defaults.
    """
    _testcapi = import_helper.import_module('_testcapi')
    params = _parameters(func, samples)
    fired = False

    def make_args(trigger, kind, by_keyword, release):
        args, kwargs = [], {}
        for p in params:
            sample = samples[p.name]
            if p.name == trigger:
                value = _TRIGGERS[kind](sample, release)
            else:
                value = _make_value(sample)
            if p.kind == p.KEYWORD_ONLY or (
                    by_keyword and p.kind == p.POSITIONAL_OR_KEYWORD):
                kwargs[p.name] = value
            else:
                args.append(value)
        return args, kwargs

    for mode in ('vectorcall', 'tp_call'):
        for by_keyword in (False, True):
            for p in params:
                for kind, make_trigger in _TRIGGERS.items():
                    if make_trigger(samples[p.name], lambda: None) is None:
                        continue
                    with test.subTest(mode=mode, by_keyword=by_keyword,
                                      trigger=p.name, kind=kind):
                        args, kwargs = make_args(p.name, kind, by_keyword,
                                                 lambda: None)
                        try:
                            expected = func(*args, **kwargs)
                        except Exception:
                            continue  # func rejects this argument
                        del args, kwargs

                        containers = []
                        def release():
                            nonlocal fired
                            for container in containers:
                                fired = fired or bool(container)
                                container.clear()
                        containers.extend(
                            make_args(p.name, kind, by_keyword, release))
                        result = _testcapi.call_with_borrowed_args(
                            func, *containers, mode)
                        test.assertEqual(result, expected)

    test.assertTrue(fired, f'no argument of {func!r} ran Python code')

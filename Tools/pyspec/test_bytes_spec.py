"""Compare Objects/pyspec/bytesobject.py, executed as Python, with bytes().

Run with the interpreter under test:  ./python Tools/pyspec/test_bytes_spec.py
Also checks that Objects/clinic/bytesobject_pyspec.c.h is up to date.
"""

import array
import os
import sys
import types
import unittest

TOOLS = os.path.dirname(os.path.abspath(__file__))
SRCDIR = os.path.dirname(os.path.dirname(TOOLS))
SPEC = os.path.join(SRCDIR, 'Objects', 'pyspec', 'bytesobject.py')
GENERATED = os.path.join(SRCDIR, 'Objects', 'clinic',
                         'bytesobject_pyspec.c.h')

sys.path.insert(0, TOOLS)
sys.path.insert(0, os.path.dirname(SPEC))

import emit_c                                   # noqa: E402
import partial_eval                             # noqa: E402
from bytesobject import bytes_new               # noqa: E402


class HasBytes:
    def __bytes__(self):
        return b'hb'


class BadBytes:
    def __bytes__(self):
        return 'nope'


class RaisingBytes:
    def __bytes__(self):
        raise KeyError('boom')


class IndexOnly:
    def __init__(self, value):
        self.value = value

    def __index__(self):
        return self.value


class IndexRaisesTypeError:
    def __index__(self):
        raise TypeError('no')

    def __iter__(self):
        return iter([7])


class IndexIsNone:
    __index__ = None

    def __iter__(self):
        return iter([66])


class ClassLiesStr:
    __class__ = property(lambda self: str)

    def __iter__(self):
        return iter([65])


class IterOnly:
    def __iter__(self):
        return iter([1, 2, 3])


class IterRaises:
    def __iter__(self):
        raise KeyError('iter')


class GetItemSequence:
    def __getitem__(self, i):
        if i < 3:
            return i
        raise IndexError


class BytesSubclass(bytes):
    pass


class StrWithBytes(str):
    def __bytes__(self):
        return b'swb'


class IntSubclass(int):
    pass


def generator():
    yield 1
    yield 2


# Each case is a function returning fresh (args, kwargs): iterators are
# consumed by the first call.
CASES = [
    lambda: ((), {}),
    lambda: ((b'ab',), {}),
    lambda: ((BytesSubclass(b'x'),), {}),
    lambda: ((bytearray(b'x'),), {}),
    lambda: ((memoryview(b'xy'),), {}),
    lambda: ((memoryview(b'abcd')[::2],), {}),
    lambda: ((array.array('h', [1, 2]),), {}),
    lambda: (([1, 2],), {}),
    lambda: (((1, 2),), {}),
    lambda: (([],), {}),
    lambda: (([1, 300],), {}),
    lambda: (([1, -1],), {}),
    lambda: (([1, 'a'],), {}),
    lambda: (([True, 2],), {}),
    lambda: (([IntSubclass(5)],), {}),
    lambda: (([IndexOnly(3)],), {}),
    lambda: (([IndexOnly(300)],), {}),
    lambda: (([2**70],), {}),
    lambda: ((3,), {}),
    lambda: ((0,), {}),
    lambda: ((True,), {}),
    lambda: ((IntSubclass(2),), {}),
    lambda: ((-1,), {}),
    lambda: ((2**70,), {}),
    lambda: ((IndexOnly(2),), {}),
    lambda: ((IndexOnly(-2),), {}),
    lambda: ((IndexRaisesTypeError(),), {}),
    lambda: ((IndexIsNone(),), {}),
    lambda: ((ClassLiesStr(),), {}),
    lambda: (('s',), {}),
    lambda: (('s', 'utf-8'), {}),
    lambda: (('s', 'ascii', 'strict'), {}),
    lambda: (('\xe9', 'ascii', 'replace'), {}),
    lambda: (('\xe9', 'ascii'), {}),
    lambda: (('s', 'no-such-codec'), {}),
    lambda: ((StrWithBytes('q'),), {}),
    lambda: ((StrWithBytes('q'), 'ascii'), {}),
    lambda: ((b'x', 'utf-8'), {}),
    lambda: ((b'x',), {'errors': 'strict'}),
    lambda: (('s',), {'errors': 'strict'}),
    lambda: (('s',), {'encoding': 'ascii'}),
    lambda: ((), {'source': [1]}),
    lambda: ((), {'encoding': 'utf-8'}),
    lambda: ((), {'errors': 'strict'}),
    lambda: ((HasBytes(),), {}),
    lambda: ((BadBytes(),), {}),
    lambda: ((RaisingBytes(),), {}),
    lambda: ((IterOnly(),), {}),
    lambda: ((IterRaises(),), {}),
    lambda: ((GetItemSequence(),), {}),
    lambda: ((generator(),), {}),
    lambda: ((iter([5, 6]),), {}),
    lambda: (({1: 2},), {}),
    lambda: (({3},), {}),
    lambda: ((range(3),), {}),
    lambda: ((object(),), {}),
    lambda: ((types.SimpleNamespace(),), {}),
    lambda: ((1.5,), {}),
    lambda: ((None,), {}),
    # Argument count and converter errors come from the clinic parser,
    # which the spec does not model.
]


def outcome(func, args, kwargs):
    try:
        result = func(*args, **kwargs)
    except Exception as exc:
        return ('raises', type(exc), str(exc))
    return ('returns', type(result), result)


class SpecMatchesInterpreter(unittest.TestCase):
    def test_cases(self):
        for make_case in CASES:
            args, kwargs = make_case()
            with self.subTest(args=args, kwargs=kwargs):
                expected = outcome(bytes, args, kwargs)
                args, kwargs = make_case()
                actual = outcome(lambda *a, **k: bytes_new(bytes, *a, **k),
                                 args, kwargs)
                self.assertEqual(actual, expected)

    def test_subclass(self):
        self.assertEqual(bytes_new(BytesSubclass, [1]), BytesSubclass([1]))
        self.assertIs(type(bytes_new(BytesSubclass, [1])), BytesSubclass)

    def test_identity(self):
        b = b'abc'
        self.assertIs(bytes(b), b)
        self.assertIs(bytes_new(bytes, b), b)


class Generated(unittest.TestCase):
    def test_up_to_date(self):
        with open(SPEC) as f:
            spec = partial_eval.Spec(f.read(), SPEC)
        text = emit_c.generate(spec, os.path.relpath(SPEC, SRCDIR)) + '\n'
        with open(GENERATED) as f:
            self.assertEqual(f.read(), text,
                             'regenerate with Tools/pyspec/emit_c.py')


if __name__ == '__main__':
    unittest.main()

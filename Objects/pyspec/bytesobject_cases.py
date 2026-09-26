"""Test data for Objects/pyspec/bytesobject.py.

Lib/test/test_clinic.py (PyspecFilesTest) runs each spec function named
in CASES as Python on each case and checks that the interpreter's
function gives the same outcome: the same exception type and message, or
an equal result of the same type, which is one of the arguments exactly
when the interpreter's is.  It also checks that each class of the spec is
the type TYPES names.  Add a case here when you change a spec body.
"""

import array
import types


# The types the classes of the spec describe.
TYPES = {
    'bytes': bytes,
    'bytes_iterator': type(iter(b'')),
}

# What the interpreter runs for the top-level (C API) functions of the
# spec: "module.function", imported when the module exists.
C_FUNCTIONS = {
    'PyBytes_FromObject': '_testlimitedcapi.bytes_fromobject',
}


def call(*args, **kwargs):
    """A case: the arguments of the call, including self or cls."""
    return args, kwargs


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


class BytesOverridingDunderBytes(bytes):
    def __bytes__(self):
        return BytesSubclass(b'sub')


class StrWithBytes(str):
    def __bytes__(self):
        return b'swb'


class IntSubclass(int):
    pass


def generator():
    yield 1
    yield 2


def generator_raises():
    yield 1
    raise KeyError('mid-way')


class IteratorRaises:
    """Raises from __next__ after two items."""

    def __init__(self):
        self.n = 0

    def __iter__(self):
        return self

    def __next__(self):
        self.n += 1
        if self.n > 2:
            raise KeyError('mid-way')
        return self.n


class OddIterator:
    """An iterator whose __iter__ does not return itself: iteration only
    calls __next__, and never __iter__ again."""

    def __init__(self):
        self.n = 0

    def __iter__(self):
        return iter([99])

    def __next__(self):
        self.n += 1
        if self.n > 2:
            raise StopIteration
        return self.n


class IterReturnsOdd:
    def __iter__(self):
        return OddIterator()


class LengthHint:
    """Iterates [1, 2]; __length_hint__ gives *hint* (or raises it)."""

    def __init__(self, hint):
        self.hint = hint

    def __iter__(self):
        return iter([1, 2])

    def __length_hint__(self):
        if isinstance(self.hint, BaseException):
            raise self.hint
        return self.hint


class LenLies:
    """__len__ says 5; iteration yields 2 items."""

    def __len__(self):
        return 5

    def __iter__(self):
        return iter([1, 2])


class IntSubclassWithIndex(int):
    """An int: its __index__ is not called."""

    def __index__(self):
        return 7


class IndexMutates:
    """__index__ calls mutate(items) on the list being converted."""

    def __init__(self, items, mutate, value=2):
        self.items = items
        self.mutate = mutate
        self.value = value

    def __index__(self):
        self.mutate(self.items)
        return self.value


def list_mutated_by_index(mutate):
    items = [1]
    items += [IndexMutates(items, mutate), 3]
    return items


class ListSubclass(list):
    pass


# The arguments of bytes(): bytes.__new__ and PyBytes_FromObject() take
# them after the class.
SOURCES = [
    lambda: call(),
    lambda: call(b'ab'),
    lambda: call(BytesSubclass(b'x')),
    lambda: call(BytesOverridingDunderBytes(b'x')),
    lambda: call(bytearray(b'x')),
    lambda: call(memoryview(b'xy')),
    lambda: call(memoryview(b'abcd')[::2]),
    lambda: call(array.array('h', [1, 2])),
    lambda: call([1, 2]),
    lambda: call((1, 2)),
    lambda: call([]),
    lambda: call([1, 300]),
    lambda: call([1, -1]),
    lambda: call([1, 'a']),
    lambda: call([True, 2]),
    lambda: call([IntSubclass(5)]),
    lambda: call([IndexOnly(3)]),
    lambda: call([IndexOnly(300)]),
    lambda: call([2**70]),
    lambda: call(3),
    lambda: call(0),
    lambda: call(True),
    lambda: call(IntSubclass(2)),
    lambda: call(-1),
    lambda: call(2**70),
    lambda: call(IndexOnly(2)),
    lambda: call(IndexOnly(-2)),
    lambda: call(IndexRaisesTypeError()),
    lambda: call(IndexIsNone()),
    lambda: call(ClassLiesStr()),
    lambda: call('s'),
    lambda: call('s', 'utf-8'),
    lambda: call('s', 'ascii', 'strict'),
    lambda: call('\xe9', 'ascii', 'replace'),
    lambda: call('\xe9', 'ascii'),
    lambda: call('s', 'no-such-codec'),
    lambda: call(StrWithBytes('q')),
    lambda: call(StrWithBytes('q'), 'ascii'),
    lambda: call(b'x', 'utf-8'),
    lambda: call(b'x', errors='strict'),
    lambda: call('s', errors='strict'),
    lambda: call('s', encoding='ascii'),
    lambda: call(source=[1]),
    lambda: call(encoding='utf-8'),
    lambda: call(errors='strict'),
    lambda: call(HasBytes()),
    lambda: call(BadBytes()),
    lambda: call(RaisingBytes()),
    lambda: call(IterOnly()),
    lambda: call(IterRaises()),
    lambda: call(GetItemSequence()),
    lambda: call(generator()),
    lambda: call(iter([5, 6])),
    lambda: call({1: 2}),
    lambda: call({3}),
    lambda: call(range(3)),
    lambda: call(object()),
    lambda: call(types.SimpleNamespace()),
    lambda: call(1.5),
    lambda: call(None),
    # Iterables, including lists and tuples, which Argument Clinic
    # iterates by index with a fast path for exact ints.
    lambda: call(generator_raises()),
    lambda: call(IteratorRaises()),
    lambda: call(IterReturnsOdd()),
    lambda: call(iter(range(3))),
    lambda: call(iter([1, IndexOnly(2), 3])),
    lambda: call({IndexOnly(3), IndexOnly(3)}),
    lambda: call(frozenset([IndexOnly(4)])),
    lambda: call({IndexOnly(300)}),
    lambda: call(range(256)),
    lambda: call(range(250, 260)),
    lambda: call(range(-1, 3)),
    lambda: call(range(2**70, 2**70 + 1)),
    lambda: call({'a': 1}),
    lambda: call([True, False, 1]),
    lambda: call((True, 2)),
    lambda: call([IntSubclassWithIndex(5)]),
    lambda: call((IntSubclass(255), IntSubclass(256))),
    lambda: call([-2**70]),
    lambda: call((2**70,)),
    lambda: call((1, 2**64, 'a')),
    lambda: call(iter([2**64])),
    lambda: call(['a', 300]),
    lambda: call([300, 'a']),
    lambda: call((1, IndexRaisesTypeError())),
    lambda: call([1, IndexOnly(-1)]),
    lambda: call(tuple(range(256))),
    lambda: call(list(range(300))),
    lambda: call(list(range(200)) * 3),
    lambda: call(ListSubclass([1, 2])),
    lambda: call(list_mutated_by_index(list.clear)),
    lambda: call(list_mutated_by_index(lambda l: l.append(4))),
    lambda: call(list_mutated_by_index(lambda l: l.pop())),
    lambda: call(list_mutated_by_index(
        lambda l: l.insert(0, 9) if len(l) < 4 else None)),
    lambda: call(list_mutated_by_index(lambda l: l.append('x'))),
    lambda: call(LengthHint(KeyError('hint'))),
    lambda: call(LengthHint('x')),
    lambda: call(LengthHint(-1)),
    lambda: call(LengthHint(0)),
    lambda: call(LengthHint(1000)),
    lambda: call(LengthHint(2**70)),
    lambda: call(LengthHint(NotImplemented)),
    lambda: call(LenLies()),
    # Argument count and converter errors come from the clinic parser,
    # which the spec does not model.
]


def _with(first, source):
    """The case *source* with *first* (the class) prepended."""
    def case():
        args, kwargs = source()
        return (first, *args), kwargs
    return case


def _c_api_arg(source):
    """True if the case *source* passes exactly one positional argument,
    other than None (_testlimitedcapi passes None as NULL)."""
    args, kwargs = source()
    return len(args) == 1 and not kwargs and args[0] is not None


HEX_STRINGS = ['', '00ff', ' 0a 1B ', 'abc', 'zz', b'00ff',
               bytearray(b'0a'), memoryview(b'ab'), 1, None]

# Spec function -> cases (functions returning fresh arguments: an
# iterator is consumed by the first call).
CASES = {
    'bytes.__new__':
        [_with(cls, source) for cls in (bytes, BytesSubclass)
         for source in SOURCES],
    'PyBytes_FromObject':
        [source for source in SOURCES if _c_api_arg(source)],
    'bytes.__bytes__':
        [lambda: call(b'abc'),
         lambda: call(b''),
         lambda: call(BytesSubclass(b'xy')),
         lambda: call(BytesSubclass()),
         lambda: call(BytesOverridingDunderBytes(b'x'))],
    'bytes.fromhex':
        [lambda cls=cls, s=s: call(cls, s)
         for cls in (bytes, BytesSubclass) for s in HEX_STRINGS],
}

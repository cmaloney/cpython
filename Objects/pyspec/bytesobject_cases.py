"""Test data for Objects/pyspec/bytesobject.py.

Lib/test/test_clinic.py (PyspecFilesTest) runs each spec function named
in CASES as Python on each case and checks that the interpreter's
function gives the same outcome: the same exception type and message, or
an equal result of the same type, which is one of the arguments exactly
when the interpreter's is.  It also checks that each class of the spec is
the type TYPES names.  Add a case here when you change a spec body.

The other names are data of the generic tests of the facts (see
Objects/pyspec/README.rst, "Test data"): FACTS (test_clinic
PyspecFactsTest), HELPERS, HELPER_CALLERS, NOT_CALLABLE, FACTS_ONLY and
SLOT_USES (test_pyspec_facts).  The call-table entries of a class are
called with the cases of CASES["<class>.__new__"] and
CASES["<class>.<method>"] (test_pyspec_facts DirectCallTest).
"""

import array
import codecs
import pickle
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


class StrWithIndex(str):
    """A str: its __index__ is not called."""

    def __index__(self):
        return 1


class PythonBuffer:
    """The buffer protocol in Python."""

    def __buffer__(self, flags):
        return memoryview(b'pb')

    def __release_buffer__(self, view):
        pass


class BytesNewReturnsInt(bytes):
    """cls.fromhex(s) returns cls(bytes.fromhex(s)): here 42."""

    def __new__(cls, value=b''):
        return 42


def subclass_codec():
    """The name of a codec whose encoder returns a bytes subclass (so
    bytes(s, encoding) may too), registered on first use."""
    name = 'pyspec_cases_subclass'
    if not _CODECS:
        def search(wanted):
            if wanted != name:
                return None
            return codecs.CodecInfo(
                name=name,
                encode=lambda s, errors='strict': (BytesSubclass(s.encode()),
                                                   len(s)),
                decode=lambda b, errors='strict': (bytes(b).decode(),
                                                   len(b)))
        codecs.register(search)
        _CODECS.append(search)
    return name


_CODECS = []


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
    lambda: call(BytesOverridingDunderBytes()),
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
    # Iterables, including lists and tuples, which the generated C
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
    # A list is first copied in a snapshot that only takes compact
    # exact ints and bools; any other item restarts with the iterator.
    lambda: call([1, 2, IndexOnly(3)]),
    lambda: call([True, IndexOnly(1), False]),
    lambda: call([1, 2**40, 3]),
    lambda: call([1, 2**40, 'a']),
    lambda: call([1, IntSubclass(2), 3]),
    lambda: call([300, IndexOnly(3)]),
    lambda: call([IndexOnly(300), 5]),
    lambda: call([5, IndexRaisesTypeError(), 300]),
    lambda: call([0, 255, 256]),
    lambda: call([-1, IndexOnly(1)]),
    lambda: call(list(range(256)) * 40),
    lambda: call(list(range(256)) * 40 + [IndexOnly(7)]),
    lambda: call([IndexOnly(i) for i in range(300)]),
    lambda: call(list_mutated_by_index(lambda l: l.extend(range(100)))),
    # A tuple is copied in one pass; its size cannot change.
    lambda: call((IndexOnly(1),) * 300),
    lambda: call(tuple(range(256)) * 40 + (IndexOnly(7), 2**40)),
    lambda: call((1, 2**40, 3)),
    lambda: call((True, False, IntSubclass(9))),
    # Inputs of exact types with an entry of their own in the call table,
    # and Python code under a C type (__buffer__, __index__).
    lambda: call(memoryview(PythonBuffer())),
    lambda: call(memoryview(bytearray(b'ab'))),
    lambda: call(PythonBuffer()),
    lambda: call((IndexOnly(3),)),
    lambda: call({IndexOnly(4): 0}),
    lambda: call(StrWithIndex('x')),
    lambda: call(range(0)),
    lambda: call(bytearray()),
    lambda: call(b''),
    # An encoding may return a bytes subclass (F6).
    lambda: call('x', subclass_codec()),
    # Argument count and converter errors come from the clinic parser,
    # which the spec does not model.
]


# -- the facts derived from the spec -------------------------------------
#
# FACTS (test_clinic PyspecFactsTest, test_pyspec_facts SoundnessTest):
# what the derivation finds for a spec function (or a call expression, as
# written in this spec) with facts about its arguments.  env maps each
# parameter to a type (an object of exactly that type), ANY (any object),
# NULL (C NULL) or is_(value) (that very object).  Every other key is
# checked when present (see Lib/test/test_clinic.py, PyspecFactsTest).

class NULL:
    """C NULL: an argument, or a fact about a parameter."""


class ANY:
    """Any object (not NULL): a fact about a parameter."""


def is_(value):
    return ('is', value)


def _new(source, **expected):
    """bytes(source): bytes.__new__ for exactly bytes, one argument."""
    env = {'cls': is_(bytes), 'source': source, 'encoding': NULL,
           'errors': NULL}
    return dict(function='bytes.__new__', env=env, args=['source'],
                **expected)


FACTS = [
    # bytes(b) is b for an exact bytes b (what b.__bytes__() returns).
    _new(bytes, residual='return source', alias=0, result_type=bytes,
         runs_python=False),
    # A subclass may override __bytes__, even later: nothing is decided,
    # and the generic entry has the same facts.
    *[_new(tp, alias=None, result_type=None, runs_python=True,
           contains=['_PyObject_LookupSpecial'])
      for tp in (BytesSubclass, BytesOverridingDunderBytes, ANY)],
    # An exact bytes is returned before the __bytes__ lookup; after that
    # test, the later test of PyBytes_FromObject() is gone.
    _new(ANY, first='if type(source) is bytes:\n    return source',
         contains=['_PyObject_LookupSpecial'], count={'is bytes': 1}),
    *[_new(tp, alias=None, result_type=bytes, runs_python=False)
      for tp in (bytearray, memoryview)],
    _new(list, alias=None, runs_python=True),
    # PyNumber_AsSsize_t() of an exact int runs no Python code and only
    # raises OverflowError: the except TypeError is dead.  A compact int
    # is read inline.
    _new(int, result_type=bytes, runs_python=False, lacks=['except'],
         contains=['if _PyLong_IsCompact(source):\n'
                   '    size = _PyLong_CompactValue(source)']),
    _new(IntSubclass, runs_python=True),
    # A range yields exact ints: no __next__ or __index__ in Python.  The
    # generic bytes_from_iterator() is called with its facts for a range.
    _new(range, result_type=bytes, runs_python=False,
         last='return bytes_from_iterator(it_1, source)',
         called=dict(loop=(False, range))),
    *[_new(tp, result_type=bytes, runs_python=True)
      for tp in (list, tuple, dict, set)],
    # A list or a tuple is iterated by index in a specialization shared
    # by every caller, exact ints on a fast path; a list is copied in its
    # critical section by a loop that runs no Python code, and restarts
    # with the generic function on an item that could.
    _new(list, residual='return bytes_from_iterator_list(source)',
         specializations={
             'bytes_from_iterator_list': dict(
                 params=['x'],
                 contains=['with critical_section(x):',
                           'return bytes_from_iterator(it, x)']),
             'bytes_from_iterator_list_lock_held': dict(
                 lock='x', loop=(True, list),
                 contains=['size = len(x)', 'return FALLBACK',
                           'if (type(item) is int or type(item) is bool) '
                           'and _PyLong_IsCompact(item):'],
                 lacks=['iter('],
                 calls=['bytes_appender_append_unchecked'],
                 no_calls=['bytes_appender_append'])}),
    _new(tuple, residual='return bytes_from_iterator_tuple(source)',
         specializations={
             'bytes_from_iterator_tuple': dict(
                 params=['x'], loop=(True, tuple),
                 contains=['size = len(x)',
                           'if (type(item) is int or type(item) is bool) '
                           'and _PyLong_IsCompact(item):'],
                 lacks=['iter(', 'return FALLBACK'],
                 calls=['bytes_appender_append_unchecked'],
                 no_calls=['bytes_appender_append'])}),
    # An argument of unknown type is versioned for list and tuple.
    _new(ANY, runs_python=True,
         contains=['if type(source) is list:', 'if type(source) is tuple:',
                   'bytes_from_iterator(it_1, source)']),
    dict(function='bytes_from_iterator', env={'it': ANY, 'x': ANY},
         args=['it', 'x'], runs_python=True),
    # After the checks of bytes_new_impl(), the rest is the arity
    # function: called, not repeated.
    dict(function='bytes.__new__', env={}, inline=False,
         arities=[({'cls': is_(bytes), 'source': ANY,
                    'encoding': NULL, 'errors': NULL},
                   'bytes_new_nargs1', ['source'])],
         last='return bytes_new_nargs1(source)',
         lacks=['_PyObject_LookupSpecial']),
    # b.__bytes__(): b itself for an exact bytes, an exact copy for a
    # subclass instance.
    dict(function='bytes.__bytes__', env={'self': bytes}, args=['self'],
         alias=0, result_type=bytes, runs_python=False),
    *[dict(function='bytes.__bytes__', env={'self': tp}, args=['self'],
           alias=None, result_type=bytes, runs_python=False)
      for tp in (BytesSubclass, ANY)],
    # bytes.fromhex(s): __buffer__ of a Python class may run; a subclass
    # calls cls(result), which runs Python code and returns anything.
    dict(function='bytes.fromhex', env={'cls': is_(bytes), 'string': str},
         args=['string'], result_type=bytes, runs_python=False),
    dict(function='bytes.fromhex', env={'cls': is_(bytes), 'string': ANY},
         args=['string'], result_type=bytes, runs_python=True),
    dict(function='bytes.fromhex', env={'cls': ANY, 'string': ANY},
         args=['string'], result_type=None, runs_python=True),
    # F6: an encoding with a codec may return a bytes subclass.
    dict(function='bytes.__new__',
         env={'cls': is_(bytes), 'source': str, 'encoding': ANY,
              'errors': NULL},
         args=['source', 'encoding'], result_type=None),
    # bytes_iterator.__next__ returns exact(int) and states no effect.
    dict(function='bytes_iterator.__next__', env={}, reference=True,
         result_type=int, runs_python=False),
    # F3: PickleBuffer forwards getbuffer to the object it wraps (a Python
    # __buffer__ cannot be observed today because of an upstream bug, see
    # review F7); the leaf types of builtin_types.py run none.
    dict(expr='_PyBytes_FromBuffer(x)', env={'x': pickle.PickleBuffer},
         runs_python=True),
    dict(expr='_PyBytes_FromBuffer(x)', env={'x': bytearray},
         runs_python=False),
]


# -- the hand-written C functions ------------------------------------------
#
# HELPERS (test_pyspec_facts HelperTest): the inputs of each C function of
# the spec with a Python reference (@c_implemented) that can be called
# from Python, as its reference takes them (a function making them when
# they must be fresh); NULL is C NULL.  An exported function is called
# through ctypes; a dunder through the slot wrapper of TYPES;
# HELPER_CALLERS names the C entry point of the others.  NOT_CALLABLE:
# static functions, which only their callers (the spec functions) call.
# FACTS_ONLY: references with no model of the value (exact(T) alone).

HELPERS = {
    '_PyBytes_FromHex': [('00ff', False), ('0a 1B', True), ('zz', False),
                         (b'41', False), (memoryview(b'42'), True),
                         (PythonBuffer(), False), (5, False)],
    'bytes.__buffer__': [(b'abc', 0)],
    'bytes.__len__': [(b'',), (b'abc',), (BytesSubclass(b'ab'),)],
    'bytes.__getitem__': [
        (b'abc', 0), (b'abc', 2), (b'abc', -1), (b'abc', -3),
        (b'abc', 3), (b'abc', -4), (b'\xff', 0), (b'', 0),
        (b'abc', True), (b'abc', 2**70), (b'abc', -2**70),
        (b'abc', IntSubclass(1)), (b'abc', IndexOnly(1)),
        (BytesSubclass(b'abc'), 1), (b'abcdef', slice(1, 5, 2)),
        (b'abc', slice(None)), (b'abc', slice(5, 1)), (b'abc', 'x'),
        (b'abc', 1.5)],
    'bytes_iterator.__next__': [lambda: (iter(b'a'),),
                                lambda: (iter(b''),)],
}

HELPER_CALLERS = {
    '_PyBytes_FromHex': lambda s, use_bytearray: (
        (bytearray.fromhex if use_bytearray else bytes.fromhex), (s,)),
}

NOT_CALLABLE = {
    '_PyBytes_FromSize', '_PyBytes_FromBuffer', 'bytes_copy',
    'bytes_subtype_new', 'bytes_appender_init', 'bytes_appender_append',
    'bytes_appender_append_unchecked', 'bytes_appender_finish',
    'bytes_appender_discard',
}

FACTS_ONLY = {'bytes_iterator.__next__'}


# -- the uops that use the facts of a slot ---------------------------------
#
# SLOT_USES (test_pyspec_facts SlotFactsTest): each specialized uop that
# does what a slot of a class does takes its result facts from the call
# table (_PySpec_FindSlot()).  cls and slot: the class and its dunder;
# arg_type: the exact type of the argument after self, or None; run: a
# function whose loop runs the uop, and returns the outcome of each
# step; reference: the same through the slot wrapper; inputs: arguments
# of both; compact: the uop also claims a compact int.

def _outcomes(func, b, keys):
    out = []
    for key in keys:
        try:
            out.append(('returns', func(b, key)))
        except IndexError as exc:
            out.append(('raises', str(exc)))
    return out


def subscripts(b, keys):
    out = []
    for key in keys:
        try:
            out.append(('returns', b[key]))
        except IndexError as exc:
            out.append(('raises', str(exc)))
    return out


def items(b):
    return [('returns', c) for c in b]


def items_through_slot(b):
    it = iter(b)
    return [('returns', type(it).__next__(it)) for _ in range(len(b))]


SLOT_USES = {
    '_BINARY_OP_SUBSCR_BYTES_INT': dict(
        cls='bytes', slot='__getitem__', arg_type=int, compact=True,
        run=subscripts,
        reference=lambda b, keys: _outcomes(bytes.__getitem__, b, keys),
        inputs=[(bytes(range(256)), range(-257, 258)),
                (b'', range(-2, 3)),
                (b'\x00\xff', [0, 1, 2, 2**62, -1, -2, -3, True])]),
    '_ITER_NEXT_BYTES': dict(
        cls='bytes_iterator', slot='__next__', arg_type=None, compact=True,
        run=items, reference=items_through_slot,
        inputs=[(bytes(range(256)),), (b'',), (b'\x00',),
                (b'\xff' * 3,)]),
}


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


# The arguments of fromhex(): functions making them.
HEX_INPUTS = [
    lambda: '', lambda: '00ff', lambda: ' 0a 1B ', lambda: 'abc',
    lambda: 'zz', lambda: b'00ff', lambda: bytearray(b'0a'),
    lambda: memoryview(b'ab'), lambda: 1, lambda: None,
    lambda: [IndexOnly(1)], lambda: (1,), lambda: {1: 2},
    lambda: range(2), lambda: 1.5, lambda: StrWithIndex('41'),
    lambda: memoryview(PythonBuffer()), lambda: PythonBuffer(),
    lambda: BytesSubclass(b'41'),
]

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
    # A class method: the class first.  A subclass shares the C function
    # of bytes.fromhex (F2).
    'bytes.fromhex':
        [lambda cls=cls, s=s: call(cls, s())
         for cls in (bytes, BytesSubclass, BytesNewReturnsInt)
         for s in HEX_INPUTS],
}

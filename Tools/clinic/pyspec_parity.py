#!/usr/bin/env python3
"""Check that moving a type to a pyspec keeps everything it does.

Migrating a type (MIGRATING.rst) replaces clinic blocks, a method table
and slot tables by what Argument Clinic generates from a spec.  This
records everything observable about the types, on the interpreter before
the migration and on the one after, and shows every difference:

* the Python surface: ``vars()`` in order, each attribute's kind,
  ``__doc__``, ``__text_signature__``, ``inspect.signature()``, ``help()``;
* the C layout: flags, sizes, which slots are set and whether each is
  inherited, generic or shared with another slot, each ``PyMethodDef``'s
  flags and doc, the members and getsets;
* the behaviour of every method and of the type itself: each arity,
  keyword use and, one parameter at a time, each value of a pool of
  arguments, with the exact result (or exception type and message, and
  warnings);
* the behaviour of the protocols: operators both ways, comparisons,
  ``in``, subscripts, in-place operators, conversions, iteration, hash,
  pickling and copying, of each sample instance.

Usage, from a build of the tree after the migration::

    # a build of the tree before the migration is still around:
    ./python Tools/clinic/pyspec_parity.py compare ../build-main/python \\
        bytes bytes_iterator

    # or capture before migrating, and check after rebuilding:
    ./python Tools/clinic/pyspec_parity.py capture bytes -o bytes.parity
    ./python Tools/clinic/pyspec_parity.py check bytes.parity

A type is named as a builtin (``bytes``), ``module.name`` (``mmap.mmap``)
or a name of SPECIAL_TYPES (``bytes_iterator``).  Both interpreters must
be the same Python version and build configuration (free-threaded,
debug).  Only the standard library is used, so the build before the
migration runs this file by path.  A difference the migration makes on
purpose goes into KNOWN_DIFFERENCES, with the reason.

This complements the unit tests of the type (test_bytes, ...): they check
what the type should do, this checks that the migration changed nothing.
"""

import argparse
import copy
import difflib
import functools
import importlib
import inspect
import itertools
import math
import operator
import os
import pickle
import pydoc
import re
import signal
import struct
import subprocess
import sys
import sysconfig
import tempfile
import warnings
import weakref


# Types that have no public name: name -> an instance, whose type it is
# (and the sample of that type when SAMPLES has none).
SPECIAL_TYPES = {
    'bytes_iterator': "iter(b'abc')",
    'bytearray_iterator': "iter(bytearray(b'abc'))",
    'tuple_iterator': 'iter((1, 2))',
    'list_iterator': 'iter([1, 2])',
    'list_reverseiterator': 'reversed([1, 2])',
    'str_ascii_iterator': "iter('ab')",
    'str_iterator': "iter('\\u20ac')",
    'range_iterator': 'iter(range(2))',
    'longrange_iterator': 'iter(range(2**100, 2**100 + 2))',
    'set_iterator': 'iter({1})',
    'dict_keyiterator': "iter({'a': 1})",
    'dict_valueiterator': "iter({'a': 1}.values())",
    'dict_itemiterator': "iter({'a': 1}.items())",
}


class Index:
    """An object with __index__ only."""
    def __init__(self, value):
        self.value = value

    def __index__(self):
        return self.value

    def __repr__(self):
        return f'Index({self.value})'


def _mmap(size=16, data=b'ab cd\x00ef'):
    import mmap
    with tempfile.TemporaryFile() as f:
        f.write(data.ljust(size, b'\x00'))
        f.flush()
        return mmap.mmap(f.fileno(), size)


# Sample instances of a type: label -> factory, called for every use, so
# that a mutation does not leak into the next call.  Probing every
# argument happens on the first sample; the others see a few calls each.
# A type with no entry uses the pool values of exactly its type, or type().
SAMPLES = {
    'bytes': {
        "b'a b'": lambda: b'a b',
        "b''": lambda: b'',
        "b'\\x00\\xffAz \\t'": lambda: b'\x00\xffAz \t',
    },
    'bytearray': {
        "bytearray(b'a b')": lambda: bytearray(b'a b'),
        'bytearray()': lambda: bytearray(),
        "bytearray(b'\\x00\\xffAz \\t')": lambda: bytearray(b'\x00\xffAz \t'),
    },
    'bytes_iterator': {
        "iter(b'abc')": lambda: iter(b'abc'),
        "iter(b'')": lambda: iter(b''),
    },
    'bytearray_iterator': {
        "iter(bytearray(b'abc'))": lambda: iter(bytearray(b'abc')),
        'iter(bytearray())': lambda: iter(bytearray()),
    },
    'tuple': {
        '(1, 2)': lambda: (1, 2),
        '()': lambda: (),
        "(1, 'a', None, 1)": lambda: (1, 'a', None, 1),
    },
    'list': {
        '[1, 2]': lambda: [1, 2],
        '[]': lambda: [],
        "[3, 1, 'a', None]": lambda: [3, 1, 'a', None],
    },
    'int': {
        '5': lambda: 5,
        '0': lambda: 0,
        '-7': lambda: -7,
        '2**100': lambda: 2**100,
        'True': lambda: True,
    },
    'str': {
        "'a b'": lambda: 'a b',
        "''": lambda: '',
        "'\\xe9\\u20ac \\t\\U0001f600'": lambda: '\xe9€ \t\U0001f600',
    },
    'mmap.mmap': {
        'mmap(16)': _mmap,
    },
}

# Arguments each method is called with, besides the samples of the type
# and EXTRA_POOL: label -> factory.  The order matters: the first values
# a parameter accepts make up the baseline call (see Prober.baseline).
POOL = {
    '1': lambda: 1,
    "b'ab'": lambda: b'ab',
    "'utf-8'": lambda: 'utf-8',
    "'ab'": lambda: 'ab',
    'None': lambda: None,
    '0': lambda: 0,
    '-1': lambda: -1,
    '3': lambda: 3,
    'True': lambda: True,
    '2**100': lambda: 2**100,
    '1.5': lambda: 1.5,
    "bytearray(b'ab')": lambda: bytearray(b'ab'),
    "memoryview(b'ab')": lambda: memoryview(b'ab'),
    '[1, 2]': lambda: [1, 2],
    '(1, 2)': lambda: (1, 2),
    "{'a': 1}": lambda: {'a': 1},
    'Index(2)': lambda: Index(2),
    'slice(1, None)': lambda: slice(1, None),
    'object()': lambda: object(),
}

# What methods are called on instead of an instance, in an unbound call.
FOREIGN_SELF = ['None', "b'ab'", "'ab'", "bytearray(b'ab')", 'object()']

# More arguments for the methods of one type, where POOL misses the
# interesting ones.
EXTRA_POOL = {
    'bytes': {"b' '": lambda: b' ', "b'\\x00'": lambda: b'\x00'},
    'bytearray': {"b' '": lambda: b' ', "b'\\x00'": lambda: b'\x00'},
    'str': {"' '": lambda: ' ', "'\\u20ac'": lambda: '€'},
}

# Differences a migration makes on purpose: type name -> [(regex, reason)].
# A line of either capture whose key (the text before ' = ') matches is
# left out of the comparison.
KNOWN_DIFFERENCES = {
    'bytes': [
        (r'^C tp_vectorcall$',
         'bytes() is called through the vectorcall the spec generates'),
    ],
}

TIMEOUT = 10        # seconds for one call

def _hash(obj):
    h = hash(obj)
    return 'id-based' if h == object.__hash__(obj) else h


BINARY = [
    ('+', operator.add), ('-', operator.sub), ('*', operator.mul),
    ('@', operator.matmul), ('/', operator.truediv),
    ('//', operator.floordiv), ('%', operator.mod), ('divmod', divmod),
    ('**', pow), ('<<', operator.lshift), ('>>', operator.rshift),
    ('&', operator.and_), ('|', operator.or_), ('^', operator.xor),
    ('<', operator.lt), ('<=', operator.le), ('==', operator.eq),
    ('!=', operator.ne), ('>', operator.gt), ('>=', operator.ge),
]
INPLACE = [
    ('+=', operator.iadd), ('-=', operator.isub), ('*=', operator.imul),
    ('@=', operator.imatmul), ('/=', operator.itruediv),
    ('//=', operator.ifloordiv), ('%=', operator.imod),
    ('<<=', operator.ilshift), ('>>=', operator.irshift),
    ('&=', operator.iand), ('|=', operator.ior), ('^=', operator.ixor),
]
UNARY = [
    ('-', operator.neg), ('+', operator.pos), ('~', operator.invert),
    ('abs', abs), ('bool', bool), ('len', len), ('hash', _hash),
    ('int', int), ('float', float), ('complex', complex),
    ('operator.index', operator.index), ('round', round),
    ('math.trunc', math.trunc), ('math.floor', math.floor),
    ('math.ceil', math.ceil), ('repr', repr), ('str', str),
    ('ascii', ascii), ('format', format), ('reversed', reversed),
    ('iter', iter), ('next', next), ('sys.getsizeof', sys.getsizeof),
    ('copy.copy', copy.copy), ('copy.deepcopy', copy.deepcopy),
    ('weakref.ref', weakref.ref),
]
# Too slow for large operands: (operator, operand labels to skip).
SLOW = {'**': {'2**100'}}

# Functions the C layout names, rather than calling them "own".
GENERIC_FUNCTIONS = [
    'PyObject_GenericGetAttr', 'PyObject_GenericSetAttr',
    'PyObject_GenericGetDict', 'PyObject_GenericSetDict',
    'PyObject_SelfIter', 'PyObject_HashNotImplemented',
    'PyType_GenericAlloc', 'PyType_GenericNew', 'PyObject_Free',
    'PyObject_GC_Del', 'PyObject_Del', 'PyVectorcall_Call',
]

# PyTypeObject from tp_name to tp_vectorcall (the fields that follow
# change with the version and say nothing about the type).
TYPE_FIELDS = [
    ('tp_name', 's'), ('tp_basicsize', 'n'), ('tp_itemsize', 'n'),
    ('tp_dealloc', 'f'), ('tp_vectorcall_offset', 'n'), ('tp_getattr', 'f'),
    ('tp_setattr', 'f'), ('tp_as_async', 'AM'), ('tp_repr', 'f'),
    ('tp_as_number', 'NB'), ('tp_as_sequence', 'SQ'),
    ('tp_as_mapping', 'MP'), ('tp_hash', 'f'), ('tp_call', 'f'),
    ('tp_str', 'f'), ('tp_getattro', 'f'), ('tp_setattro', 'f'),
    ('tp_as_buffer', 'BF'), ('tp_flags', 'flags'), ('tp_doc', 's'),
    ('tp_traverse', 'f'), ('tp_clear', 'f'), ('tp_richcompare', 'f'),
    ('tp_weaklistoffset', 'n'), ('tp_iter', 'f'), ('tp_iternext', 'f'),
    ('tp_methods', 'methods'), ('tp_members', 'members'),
    ('tp_getset', 'getset'), ('tp_base', None), ('tp_dict', None),
    ('tp_descr_get', 'f'), ('tp_descr_set', 'f'), ('tp_dictoffset', 'n'),
    ('tp_init', 'f'), ('tp_alloc', 'f'), ('tp_new', 'f'), ('tp_free', 'f'),
    ('tp_is_gc', 'f'), ('tp_bases', None), ('tp_mro', None),
    ('tp_cache', None), ('tp_subclasses', None), ('tp_weaklist', None),
    ('tp_del', 'f'), ('tp_version_tag', 'u'), ('tp_finalize', 'f'),
    ('tp_vectorcall', 'f'),
]
SUBTABLES = {
    'NB': ['nb_add', 'nb_subtract', 'nb_multiply', 'nb_remainder',
           'nb_divmod', 'nb_power', 'nb_negative', 'nb_positive',
           'nb_absolute', 'nb_bool', 'nb_invert', 'nb_lshift', 'nb_rshift',
           'nb_and', 'nb_xor', 'nb_or', 'nb_int', 'nb_reserved', 'nb_float',
           'nb_inplace_add', 'nb_inplace_subtract', 'nb_inplace_multiply',
           'nb_inplace_remainder', 'nb_inplace_power', 'nb_inplace_lshift',
           'nb_inplace_rshift', 'nb_inplace_and', 'nb_inplace_xor',
           'nb_inplace_or', 'nb_floor_divide', 'nb_true_divide',
           'nb_inplace_floor_divide', 'nb_inplace_true_divide', 'nb_index',
           'nb_matrix_multiply', 'nb_inplace_matrix_multiply'],
    'SQ': ['sq_length', 'sq_concat', 'sq_repeat', 'sq_item', 'was_sq_slice',
           'sq_ass_item', 'was_sq_ass_slice', 'sq_contains',
           'sq_inplace_concat', 'sq_inplace_repeat'],
    'MP': ['mp_length', 'mp_subscript', 'mp_ass_subscript'],
    'AM': ['am_await', 'am_aiter', 'am_anext', 'am_send'],
    'BF': ['bf_getbuffer', 'bf_releasebuffer'],
}
# tp_flags bits that depend on what ran before, not on the type.
VOLATILE_FLAGS = 1 << 19        # Py_TPFLAGS_VALID_VERSION_TAG

ADDRESS = re.compile(r' at 0x[0-9a-fA-F]+')


class Timeout(BaseException):
    pass


def _alarm(signum, frame):
    raise Timeout


def alarm(seconds):
    if hasattr(signal, 'SIGALRM'):
        signal.alarm(seconds)


def resolve_type(name):
    if name in SPECIAL_TYPES:
        return type(eval(SPECIAL_TYPES[name]))
    module, _, attr = name.rpartition('.')
    obj = importlib.import_module(module or 'builtins')
    for part in attr.split('.'):
        obj = getattr(obj, part)
    if not isinstance(obj, type):
        raise ValueError(f'{name} is not a type')
    return obj


def type_name(tp):
    """The name resolve_type() takes for tp."""
    for name, expr in SPECIAL_TYPES.items():
        if type(eval(expr)) is tp:
            return name
    if tp.__module__ == 'builtins':
        return tp.__qualname__
    return f'{tp.__module__}.{tp.__qualname__}'


def spec_types(srcdir=None):
    """The names of the types described by the specs of a source tree:
    the TYPES of every <stem>_cases.py next to a spec."""
    import glob
    import importlib.util
    if srcdir is None:
        srcdir = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))))
    names = []
    for top in ('Objects', 'Modules', 'Python', 'Include'):
        pattern = os.path.join(srcdir, top, '**', 'pyspec', '*_cases.py')
        for path in sorted(glob.glob(pattern, recursive=True)):
            name = '_pyspec_parity_' + os.path.basename(path)[:-3]
            spec = importlib.util.spec_from_file_location(name, path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            for tp in getattr(module, 'TYPES', {}).values():
                if type_name(tp) not in names:
                    names.append(type_name(tp))
    return names


def clean(text):
    return ADDRESS.sub(' at 0x...', text)


def describe(value, known=()):
    """The type and repr of a value, or which known object it is."""
    for label, obj in known:
        if value is obj:
            return label
    try:
        text = repr(value)
    except Exception as exc:
        text = f'<repr raised {type(exc).__qualname__}: {exc}>'
    if len(text) > 2000:
        text = text[:2000] + f'...<{len(text)} chars>'
    return f'{type(value).__qualname__} {clean(text)}'


def outcome(func, *args, known=(), watch=None, **kwargs):
    """What calling func does: its result, or the exception it raises,
    then the warnings it emits and, if watch is given, what the call did
    to that object (its repr before and after)."""
    before = describe(watch) if watch is not None else None
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter('always')
        alarm(TIMEOUT)
        try:
            result = func(*args, **kwargs)
        except Timeout:
            text = '!TIMEOUT'
        except BaseException as exc:
            if isinstance(exc, (SystemExit, KeyboardInterrupt)):
                raise
            if isinstance(exc, NameError) and own_bug(exc):
                raise
            text = f'!{type(exc).__qualname__}: {clean(str(exc))}'
        else:
            text = describe(result, known)
        finally:
            alarm(0)
    for w in caught:
        text += f' [{w.category.__name__}: {clean(str(w.message))}]'
    if watch is not None:
        after = describe(watch)
        if after != before:
            text += f' [changed to {after}]'
    return text


def own_bug(exc):
    """Whether exc comes from this file rather than the call it probes
    (it would be recorded on both sides, hiding the bug)."""
    tb = exc.__traceback__
    while tb.tb_next is not None:
        tb = tb.tb_next
    return tb.tb_frame.f_code.co_filename == __file__


def call_text(name, args, kwargs=()):
    parts = list(args) + [f'{k}={v}' for k, v in kwargs]
    return f'{name}({", ".join(parts)})'


class Capture:
    def __init__(self):
        self.lines = []

    def add(self, key, value):
        value = str(value).replace('\n', '\\n')
        self.lines.append(f'{key} = {value}')


class TypeCapture:
    """Everything observable about one type, as lines "key = value"."""

    def __init__(self, name, tp, out):
        self.name = name
        self.tp = tp
        self.out = out
        samples = SAMPLES.get(name)
        if samples is None and name in SPECIAL_TYPES:
            expr = SPECIAL_TYPES[name]
            samples = {expr: lambda: eval(expr)}
        if samples is None:
            samples = {label: f for label, f in POOL.items()
                       if type(f()) is tp}
        if not samples:
            try:
                tp()
            except Exception:
                raise ValueError(
                    f'{name}: add sample instances to SAMPLES') from None
            samples = {f'{name}()': tp}
        self.samples = dict(samples)
        self.pool = dict(POOL)
        for label, f in list(self.samples.items())[:2]:
            self.pool.setdefault(label, f)
        self.pool.update(EXTRA_POOL.get(name, {}))
        self.sub = None
        if tp.__flags__ & (1 << 10):        # Py_TPFLAGS_BASETYPE
            self.sub = type('Sub', (tp,), {'__module__': 'parity'})
            label, first = next(iter(self.samples.items()))
            try:
                self.sub(first())
            except Exception:
                pass
            else:
                self.samples[f'Sub({label})'] = lambda: self.sub(first())

    def add(self, key, value):
        self.out.add(f'{self.name} {key}', value)

    def run(self):
        self.surface()
        self.c_layout()
        self.probe_type()
        for attr, value in vars(self.tp).items():
            self.probe_attribute(attr, value)
        for label, factory in self.samples.items():
            self.probe_instance(label, factory)

    # -- the Python surface ------------------------------------------------

    def surface(self):
        tp = self.tp
        for attr in ('__name__', '__qualname__', '__module__', '__doc__',
                     '__text_signature__', '__basicsize__', '__itemsize__',
                     '__dictoffset__', '__weakrefoffset__'):
            self.add(attr, repr(getattr(tp, attr, '<missing>')))
        self.add('__flags__', hex(tp.__flags__ & ~VOLATILE_FLAGS))
        self.add('__mro__', [t.__qualname__ for t in tp.__mro__])
        self.add('signature', outcome(lambda: str(inspect.signature(tp))))
        self.add('vars', list(vars(tp)))
        self.add('dir', dir(tp))
        for attr, value in vars(tp).items():
            key = f'.{attr}'
            self.add(key, type(value).__qualname__)
            if not (callable(value) or hasattr(value, '__get__')):
                continue
            for meta in ('__doc__', '__text_signature__', '__qualname__',
                         '__name__'):
                if hasattr(value, meta):
                    self.add(f'{key}.{meta}', repr(getattr(value, meta)))
            objclass = getattr(value, '__objclass__', None)
            if objclass is not None:
                self.add(f'{key}.__objclass__', objclass.__qualname__)
            if callable(value):
                self.add(f'{key} signature',
                         outcome(lambda v=value: str(inspect.signature(v))))
        text = pydoc.render_doc(tp, renderer=pydoc.plaintext)
        for i, line in enumerate(clean(text).splitlines()):
            self.add(f'help {i:03}', line)

    # -- the C layout --------------------------------------------------------

    def c_layout(self):
        try:
            import ctypes
        except ImportError:
            self.add('C', 'ctypes is not available')
            return
        P = ctypes.c_void_p
        kinds = {'s': ctypes.c_char_p, 'n': ctypes.c_ssize_t,
                 'flags': ctypes.c_ulong, 'u': ctypes.c_uint}
        fields = [(n, kinds.get(k, P)) for n, k in TYPE_FIELDS]

        class TypeObject(ctypes.Structure):
            _fields_ = fields

        class MethodDef(ctypes.Structure):
            _fields_ = [('name', ctypes.c_char_p), ('meth', P),
                        ('flags', ctypes.c_int), ('doc', ctypes.c_char_p)]

        class MemberDef(ctypes.Structure):
            _fields_ = [('name', ctypes.c_char_p), ('type', ctypes.c_int),
                        ('offset', ctypes.c_ssize_t), ('flags', ctypes.c_int),
                        ('doc', ctypes.c_char_p)]

        class GetSetDef(ctypes.Structure):
            _fields_ = [('name', ctypes.c_char_p), ('get', P), ('set', P),
                        ('doc', ctypes.c_char_p), ('closure', P)]

        # PyVarObject: the object header (object's size), then ob_size.
        header = object.__basicsize__ + ctypes.sizeof(ctypes.c_ssize_t)

        def struct(tp):
            return TypeObject.from_address(id(tp) + header)

        generic = {}
        for fname in GENERIC_FUNCTIONS:
            try:
                fn = getattr(ctypes.pythonapi, fname)
            except AttributeError:
                continue
            generic[ctypes.cast(fn, P).value] = fname
        own = {}

        def slot(field, addr, inherited):
            """Name a function pointer by what it is, not where it is."""
            if not addr:
                return 'NULL'
            if addr in generic:
                return generic[addr]
            for base, base_addr in inherited:
                if addr == base_addr:
                    return f'inherited from {base.__qualname__}'
            first = own.setdefault(addr, field)
            return 'own' if first == field else f'own, same as {first}'

        def subtable(tp, field, kind):
            addr = getattr(struct(tp), field)
            if not addr:
                return None
            names = SUBTABLES[kind]
            return dict(zip(names, (P * len(names)).from_address(addr),
                            strict=True))

        t = struct(self.tp)
        bases = self.tp.__mro__[1:]
        for field, kind in TYPE_FIELDS:
            key = f'C {field}'
            value = getattr(t, field)
            if kind in (None, 'u'):
                continue
            elif kind == 's':
                self.add(key, repr(value))
            elif kind == 'n':
                self.add(key, value)
            elif kind == 'flags':
                self.add(key, hex(value & ~VOLATILE_FLAGS))
            elif kind == 'f':
                self.add(key, slot(field, value, [
                    (b, getattr(struct(b), field)) for b in bases]))
            elif kind in SUBTABLES:
                table = subtable(self.tp, field, kind)
                if table is None:
                    self.add(key, 'NULL')
                    continue
                base_tables = [(b, subtable(b, field, kind)) for b in bases]
                for sub, addr in table.items():
                    self.add(f'C {field}.{sub}', slot(sub, addr, [
                        (b, bt[sub]) for b, bt in base_tables if bt]))
            elif kind == 'methods':
                for i, md in enumerate(self.array(MethodDef, value)):
                    self.add(f'C {field}[{i}]', (
                        f'{md.name.decode()} flags={md.flags:#x} '
                        f'{slot(md.name.decode(), md.meth, ())} '
                        f'doc={md.doc!r}'))
            elif kind == 'members':
                for i, md in enumerate(self.array(MemberDef, value)):
                    self.add(f'C {field}[{i}]', (
                        f'{md.name.decode()} type={md.type} '
                        f'offset={md.offset} flags={md.flags:#x} '
                        f'doc={md.doc!r}'))
            elif kind == 'getset':
                for i, gs in enumerate(self.array(GetSetDef, value)):
                    self.add(f'C {field}[{i}]', (
                        f'{gs.name.decode()} '
                        f'get={slot("get " + gs.name.decode(), gs.get, ())} '
                        f'set={slot("set " + gs.name.decode(), gs.set, ())} '
                        f'doc={gs.doc!r}'))

    @staticmethod
    def array(struct, addr):
        import ctypes
        i = 0
        while addr:
            entry = struct.from_address(addr + i * ctypes.sizeof(struct))
            if not entry.name:
                return
            yield entry
            i += 1

    # -- calls ---------------------------------------------------------------

    def probe_type(self):
        """Calls of the type itself and of its subclass."""
        receivers = {self.name: lambda: (None, self.tp)}
        if self.sub is not None:
            receivers['Sub'] = lambda: (None, self.sub)
        Prober(self, '', receivers).run()

    def probe_attribute(self, attr, value):
        tp = self.tp
        kind = type(value).__name__
        if isinstance(value, type):
            return
        if kind in ('getset_descriptor', 'member_descriptor', 'property'):
            self.probe_data(attr)
            return
        if not callable(value) and not isinstance(value, (classmethod,
                                                          staticmethod)):
            return
        if attr == '__new__':
            # tp.__new__(cls, ...): the parameters are those of tp().
            new = getattr(tp, attr)
            receivers = {self.name: lambda: (None, functools.partial(new, tp))}
            if self.sub is not None:
                receivers['Sub'] = lambda: (None,
                                            functools.partial(new, self.sub))
            for cls in (object, int, str, type):
                self.add(f'call {tp.__name__}.__new__({cls.__name__})',
                         outcome(new, cls))
            self.add(f'call {tp.__name__}.__new__()', outcome(new))
            Prober(self, f'.{attr}', receivers, signature_of=tp).run()
            return
        if kind in ('classmethod_descriptor', 'classmethod'):
            receivers = {self.name: lambda: (None, getattr(tp, attr))}
            if self.sub is not None:
                receivers['Sub'] = lambda: (None, getattr(self.sub, attr))
            unbound = None
        elif isinstance(value, staticmethod):
            receivers = {self.name: lambda: (None, getattr(tp, attr))}
            unbound = None
        else:
            receivers = {label: (lambda f=f: self.bound(f(), attr))
                         for label, f in self.samples.items()}
            unbound = value
        prober = Prober(self, f'.{attr}', receivers)
        prober.run()
        if unbound is not None:
            # Called on something else than an instance.
            name = f'{tp.__name__}.{attr}'
            for label in FOREIGN_SELF:
                f = self.pool[label]
                if type(f()) is tp:
                    continue
                self.add(f'call {call_text(name, [label, *prober.base])}',
                         outcome(unbound, f(), *prober.values(prober.base)))
            self.add(f'call {name}()', outcome(unbound))

    @staticmethod
    def bound(obj, attr):
        return obj, getattr(obj, attr)

    def probe_data(self, attr):
        for label, f in self.samples.items():
            obj = f()
            self.add(f'get {label}.{attr}',
                     outcome(getattr, obj, attr, known=[('self', obj)]))
            for v in (1, None):
                obj = f()
                self.add(f'set {label}.{attr} = {v}',
                         outcome(setattr, obj, attr, v))
            obj = f()
            self.add(f'del {label}.{attr}', outcome(delattr, obj, attr))

    # -- protocols -----------------------------------------------------------

    def probe_instance(self, label, factory):
        for name, func in UNARY:
            obj = factory()
            self.add(f'{name}({label})',
                     outcome(func, obj, known=[('self', obj)], watch=obj))
        obj = factory()
        items = outcome(lambda: list(itertools.islice(iter(obj), 20)))
        self.add(f'list(iter({label}))[:20]', items)
        for proto in range(pickle.HIGHEST_PROTOCOL + 1):
            obj = factory()
            self.add(f'pickle.dumps({label}, {proto})',
                     outcome(pickle.dumps, obj, proto))
            self.add(f'{label}.__reduce_ex__({proto})',
                     outcome(obj.__reduce_ex__, proto, known=[('self', obj)]))
            self.add(f'pickle round trip {label} {proto}',
                     outcome(lambda o=obj, p=proto: pickle.loads(
                         pickle.dumps(o, p))))
        for vlabel, vf in self.pool.items():
            for op, func in BINARY:
                if {label, vlabel} & SLOW.get(op, set()):
                    continue
                obj, v = factory(), vf()
                known = [('self', obj), ('arg', v)]
                self.add(f'{label} {op} {vlabel}',
                         outcome(func, obj, v, known=known))
                obj, v = factory(), vf()
                known = [('self', obj), ('arg', v)]
                self.add(f'{vlabel} {op} {label}',
                         outcome(func, v, obj, known=known))
            for op, func in INPLACE:
                obj, v = factory(), vf()
                self.add(f'{label} {op} {vlabel}',
                         outcome(func, obj, v, watch=obj,
                                 known=[('self', obj), ('arg', v)]))
            obj, v = factory(), vf()
            self.add(f'{vlabel} in {label}',
                     outcome(operator.contains, obj, v))
            obj, v = factory(), vf()
            self.add(f'{label}[{vlabel}]',
                     outcome(operator.getitem, obj, v, known=[('self', obj)]))
            obj, v = factory(), vf()
            self.add(f'{label}[{vlabel}] = 1',
                     outcome(operator.setitem, obj, v, 1, watch=obj))
            obj, v = factory(), vf()
            self.add(f'{label}[0] = {vlabel}',
                     outcome(operator.setitem, obj, 0, v, watch=obj))
            obj, v = factory(), vf()
            self.add(f'del {label}[{vlabel}]',
                     outcome(operator.delitem, obj, v, watch=obj))
            obj = factory()
            self.add(f'format({label}, {vlabel})',
                     outcome(format, obj, vf()))


class Prober:
    """Calls of one callable: each arity, keyword use, and each value of
    the pool for one parameter at a time, the others at the baseline."""

    MAX_ARGS = 3            # when the signature is unknown

    def __init__(self, tc, name, receivers, signature_of=None):
        self.tc = tc
        self.name = name
        self.receivers = receivers
        self.base = []
        self.seen = set()
        if signature_of is None:
            # The first receiver's callable, bound to self if a method.
            signature_of = next(iter(receivers.values()))()[1]
        try:
            sig = inspect.signature(signature_of)
        except (TypeError, ValueError):
            self.params = None
        else:
            self.params = list(sig.parameters.values())

    def values(self, labels):
        return [self.tc.pool[label]() for label in labels]

    def call(self, receiver, args, kwargs=()):
        rlabel, make = receiver
        key = (rlabel, tuple(args), tuple(kwargs))
        if key in self.seen:
            return
        self.seen.add(key)
        obj, func = make()
        argv = self.values(args)
        kwv = {k: self.tc.pool[v]() for k, v in kwargs}
        known = [('self', obj)] if obj is not None else []
        known += [(f'arg{i}', v) for i, v in enumerate(argv)]
        known += [(f'arg {k}', v) for k, v in kwv.items()]
        # A mutable receiver shows what the call did to it.
        watch = obj if obj is not None and type(obj).__hash__ is None else None
        text = outcome(func, *argv, known=known, watch=watch, **kwv)
        self.tc.add(f'call {call_text(f"{rlabel}{self.name}", args, kwargs)}',
                    text)

    def accepts(self, receiver, args, kwargs=()):
        rlabel, make = receiver
        obj, func = make()
        try:
            alarm(TIMEOUT)
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                func(*self.values(args),
                     **{k: self.tc.pool[v]() for k, v in kwargs})
        except TypeError:
            return False
        except BaseException as exc:
            if isinstance(exc, (SystemExit, KeyboardInterrupt)):
                raise
            return True
        finally:
            alarm(0)
        return True

    def positional(self):
        return [p for p in self.params or ()
                if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]

    def first_accepted(self, receiver, n):
        """The first n positional arguments (in pool order) that the
        callable accepts, or None."""
        labels = list(self.tc.pool)
        if n > 2:
            labels = labels[:8]
        candidates = [[]]
        for _ in range(n):
            candidates = [c + [v] for c in candidates for v in labels]
        for args in candidates:
            if self.accepts(receiver, args):
                return args
        return None

    def baselines(self, receiver):
        """Positional arguments the callable accepts, which the probes
        vary one at a time: the fewest it accepts, each optional one then
        added in turn; and the most it accepts together."""
        positional = self.positional()
        if self.params is not None:
            required = sum(p.default is p.empty for p in positional)
            most = len(positional)
            lengths = [required]
        else:
            most = self.MAX_ARGS
            lengths = range(most + 1)
        base = None
        for n in lengths:
            base = self.first_accepted(receiver, n)
            if base is not None:
                break
        if base is None:
            return [[]]
        while len(base) < most:
            for v in self.tc.pool:
                if self.accepts(receiver, base + [v]):
                    base = base + [v]
                    break
            else:
                break
        bases = [base]
        for n in range(most, len(base), -1):
            longest = self.first_accepted(receiver, n)
            if longest is not None:
                bases.append(longest)
                break
        return bases

    def run(self):
        receivers = list(self.receivers.items())
        first = receivers[0]
        bases = self.baselines(first)
        self.base = base = bases[0]
        self.tc.add(f'baseline {self.name or "()"}', bases)
        params = self.params
        positional = self.positional()
        nmax = len(positional) + 1 if params is not None else self.MAX_ARGS
        filler = '1'
        # Each arity: too few and too many arguments.
        for n in range(nmax + 1):
            self.call(first, (base + [filler] * n)[:n])
        # Each value for one parameter, the others from a baseline.
        nvary = len(positional) if params is not None else self.MAX_ARGS
        for b in bases:
            for i in range(min(len(b) + 1, nvary)):
                for v in self.tc.pool:
                    self.call(first, b[:i] + [v] + b[i + 1:])
        # Keywords.
        for i, p in enumerate(positional[:len(base)]):
            kwargs = [(q.name, base[j]) for j, q in
                      enumerate(positional[i:len(base)], i)]
            self.call(first, base[:i], kwargs)
            self.call(first, base[:i + 1], [(p.name, base[i])])
        for p in params or ():
            if p.kind == p.KEYWORD_ONLY:
                for v in self.tc.pool:
                    self.call(first, base, [(p.name, v)])
        self.call(first, base, [('bogus', '1')])
        # The other receivers.
        for receiver in receivers[1:]:
            self.call(receiver, base)
            if base:
                self.call(receiver, [])

def capture(names):
    """The lines describing the named types, header first."""
    return capture_types([(name, resolve_type(name)) for name in names])


def capture_types(types):
    """The lines describing each type of the (name, type) pairs."""
    out = Capture()
    out.lines.append(header())
    if hasattr(signal, 'SIGALRM'):
        old = signal.signal(signal.SIGALRM, _alarm)
    try:
        for name, tp in types:
            TypeCapture(name, tp, out).run()
    finally:
        if hasattr(signal, 'SIGALRM'):
            signal.signal(signal.SIGALRM, old)
    return out.lines


def header():
    free_threaded = bool(sysconfig.get_config_var('Py_GIL_DISABLED'))
    return ('# python {}.{} free-threaded={} debug={} pointer={}'.format(
        *sys.version_info[:2], free_threaded,
        hasattr(sys, 'gettotalrefcount'), 8 * struct.calcsize('P')))


def known_differences(names):
    for name in names:
        for pattern, reason in KNOWN_DIFFERENCES.get(name, ()):
            yield name, re.compile(pattern), reason


def compare(before, after, names=None):
    """A unified diff of two captures, less the known differences, or ''."""
    if before[0] != after[0]:
        raise ValueError(f'different interpreters: {before[0]!r} and '
                         f'{after[0]!r}; capture with the same version and '
                         'configuration')
    if names is None:
        names = types_of(before)
    known = list(known_differences(names))

    def keep(line):
        key = line.partition(' = ')[0]
        for name, pattern, _ in known:
            if key.startswith(name + ' ') and pattern.search(
                    key[len(name) + 1:]):
                return False
        return True

    before = [line for line in before if keep(line)]
    after = [line for line in after if keep(line)]
    return ''.join(difflib.unified_diff(
        [line + '\n' for line in before], [line + '\n' for line in after],
        'before', 'after', n=0))


def types_of(lines):
    names = []
    for line in lines[1:]:
        name = line.split(' ', 1)[0]
        if name not in names:
            names.append(name)
    return names


def run_capture(python, names):
    """Capture in another interpreter (hash randomization off)."""
    env = dict(os.environ, PYTHONHASHSEED='0')
    proc = subprocess.run(
        [python, '-X', 'utf8', os.path.abspath(__file__), 'capture',
         *names], capture_output=True, text=True, encoding='utf-8', env=env)
    if proc.returncode:
        raise RuntimeError(f'{python} capture failed '
                           f'({proc.returncode}):\n{proc.stderr}')
    return proc.stdout.splitlines()


def report(diff, names):
    if not diff:
        print(f'no difference in {", ".join(names)}')
        return 0
    print(diff, end='')
    changed = sum(1 for line in diff.splitlines()
                  if line[:1] in '+-' and line[:3] not in ('+++', '---'))
    print(f'\n{changed} lines differ; a difference made on purpose goes '
          'into KNOWN_DIFFERENCES with the reason', file=sys.stderr)
    return 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__.split('\n\n')[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    all_specs = 'default: every type a spec describes'
    p = sub.add_parser('capture', help='write what the types do')
    p.add_argument('types', nargs='*', help=all_specs)
    p.add_argument('-o', '--output', help='file (default: stdout)')
    p = sub.add_parser('check', help='compare with a capture')
    p.add_argument('file')
    p.add_argument('types', nargs='*', help='default: those of the file')
    p = sub.add_parser('compare', help='compare with another interpreter')
    p.add_argument('baseline', help='the python before the migration')
    p.add_argument('types', nargs='*', help=all_specs)
    args = parser.parse_args(argv)
    if args.command != 'check' and not args.types:
        args.types = spec_types()

    if args.command == 'capture':
        if os.environ.get('PYTHONHASHSEED') != '0':
            lines = run_capture(sys.executable, args.types)
        else:
            lines = capture(args.types)
        text = '\n'.join(lines) + '\n'
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(text)
        else:
            sys.stdout.write(text)
        return 0
    if args.command == 'check':
        with open(args.file, encoding='utf-8') as f:
            before = f.read().splitlines()
        names = args.types or types_of(before)
        before = [before[0]] + [line for line in before[1:]
                                if line.split(' ', 1)[0] in names]
        after = run_capture(sys.executable, names)
        return report(compare(before, after, names), names)
    before = run_capture(args.baseline, args.types)
    after = run_capture(sys.executable, args.types)
    return report(compare(before, after, args.types), args.types)


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""Check that moving a type to a pyspec keeps everything it does.

Migrating a type (MIGRATING.rst) replaces clinic blocks, a method table
and slot tables by what Argument Clinic generates from a spec.  This
records everything observable about the types and shows every
difference, section by section (the type, its help, its C layout, each
attribute, each protocol):

* the Python surface: ``vars()`` in order, each attribute's kind,
  ``__doc__``, ``__text_signature__``, ``inspect.signature()``, ``help()``;
* the C layout: flags, sizes, which slots are set and whether each is
  inherited, generic or shared with another slot, each ``PyMethodDef``'s
  flags and doc, the members and getsets;
* the behaviour of every method and of the type itself: each arity,
  keyword use, each value of a pool of arguments for one parameter at a
  time and for each pair of parameters, on an instance and on an instance
  of a subclass, with the exact result (or exception type and message,
  and warnings) and what the call did to its receiver (the new repr of a
  mutable one, what an iterator yields next);
* the behaviour of the protocols: operators both ways, comparisons,
  ``in``, subscripts, in-place operators, conversions, iteration, hash,
  pickling and copying, of each sample instance; data descriptors.

Usage, from a build of the tree::

    # the committed record (Tools/clinic/pyspec-baseline/parity.txt),
    # no other build needed:
    ./python Tools/clinic/pyspec_parity.py check
    ./python Tools/clinic/pyspec_parity.py check --update  # on purpose

    # every line, against a build of the tree before the change:
    ./python Tools/clinic/pyspec_parity.py compare ../build-main/python

    # or capture before changing, and check after rebuilding:
    ../build-main/python Tools/clinic/pyspec_parity.py capture list -o list.parity
    ./python Tools/clinic/pyspec_parity.py check list.parity

The types are those of the TYPES of every ``<stem>_cases.py`` next to a
spec; one is named as a class of TYPES (``bytes_iterator``, ``mmap``), a
builtin (``tuple``) or ``module.name``.  The PARITY of the same
``_cases.py`` holds what is specific to a type: sample instances, more
argument values, and the differences a migration makes on purpose, with
the reason.  The record holds one line per section (probes, digest) per
build configuration; the same version and configuration (free-threaded,
debug, pointer size, platform) is needed on both sides of a comparison.
Only the standard library is used, so a build before the migration runs
this file by path.

This complements the unit tests of the type (test_bytes, ...): they check
what the type should do, this checks that the migration changed nothing.
"""

import argparse
import ast
import copy
import functools
import glob
import hashlib
import importlib
import importlib.util
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
import warnings
import weakref


SRCDIR = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
RECORD = os.path.join('Tools', 'clinic', 'pyspec-baseline', 'parity.txt')
RECORD_TITLE = '# Parity record of the types the specs describe'


class Index:
    """An object with __index__ only."""
    def __init__(self, value):
        self.value = value

    def __index__(self):
        return self.value

    def __repr__(self):
        return f'Index({self.value})'


# Arguments each method is called with, besides the samples of the type
# and the "pool" of its PARITY: label -> factory, called for every use,
# so that a mutation does not leak into the next call.  The order
# matters: the first values a parameter accepts make up the baseline call
# (see Prober.baselines).
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

# What methods are called on instead of an instance, in an unbound call,
# and what data descriptors are used on.
FOREIGN_SELF = ['None', "b'ab'", "'ab'", "bytearray(b'ab')", 'object()']

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
# Between the key and the value of a line of a capture.
SEP = ' => '


class Timeout(BaseException):
    pass


def _alarm(signum, frame):
    raise Timeout


def alarm(seconds):
    if hasattr(signal, 'SIGALRM'):
        signal.alarm(seconds)


# -- the types and their data -----------------------------------------------

class TypeData:
    """One type: its name, the type, and its PARITY entry, from the
    <stem>_cases.py that names it in TYPES (if any):

    * "samples": label -> factory of an instance.  Probing every argument
      happens on the first sample (and its subclass); the others see a
      few calls each.  Default: the pool values of exactly the type, or
      the type called with no arguments;
    * "pool": more argument values, label -> factory;
    * "known": differences the migration makes on purpose, regex of the
      key of a line (without the type name) -> the reason;
    * "generated": differences in the generated C from main on purpose,
      regex of a C name -> the reason (for Tools/clinic/pyspec_review.py).
    """

    def __init__(self, name, tp, cases_path=None, parity=None,
                 convert=None):
        parity = parity or {}
        unknown = set(parity) - {'samples', 'pool', 'known', 'generated'}
        if unknown:
            raise ValueError(f'{cases_path}: PARITY[{name!r}] has unknown '
                             f'keys {sorted(unknown)}')
        self.name = name
        self.tp = tp
        self.cases_path = cases_path
        self.samples = dict(parity.get('samples', {}))
        self.pool = dict(parity.get('pool', {}))
        self.known = {pattern: (re.compile(pattern), reason)
                      for pattern, reason in parity.get('known', {}).items()}
        self.generated = dict(parity.get('generated', {}))
        # What every argument value and sample goes through first: for a
        # model of the type (model_types()), the host objects of the
        # types it models become model objects.
        self.convert = convert

    def is_known(self, key):
        """The pattern of "known" matching the key of a line, or None."""
        for pattern, (regex, _) in self.known.items():
            if regex.search(key):
                return pattern
        return None

    @property
    def spec_path(self):
        if self.cases_path is None:
            return None
        return self.cases_path.removesuffix('_cases.py') + '.py'

    @property
    def c_path(self):
        spec = self.spec_path
        if spec is None:
            return None
        stem = os.path.basename(spec).removesuffix('.py')
        parent = os.path.dirname(os.path.dirname(spec))
        for ext in ('.c', '.h'):
            path = os.path.join(parent, stem + ext)
            if os.path.exists(path):
                return path
        return None

    def location(self, section):
        """Where a section comes from: the spec's line (and the clinic
        block's line in the C file), as 'path:line' strings."""
        found = []
        spec = self.spec_path
        if spec is None or not os.path.exists(spec):
            return found
        attr = section[1:] if section.startswith('.') else None
        with open(spec, encoding='utf-8') as f:
            tree = ast.parse(f.read())
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name == self.name:
                line = node.lineno
                for item in node.body:
                    names = []
                    if isinstance(item, (ast.FunctionDef,
                                         ast.AsyncFunctionDef)):
                        names = [item.name]
                    elif isinstance(item, ast.Assign):
                        names = [t.id for t in item.targets
                                 if isinstance(t, ast.Name)]
                    if attr in names:
                        line = item.lineno
                found.append(f'{relpath(spec)}:{line}')
                break
        c_file = self.c_path
        if attr and c_file:
            block = re.compile(rf'{re.escape(self.name)}\.{re.escape(attr)}'
                               r'(\s|$)')
            with open(c_file, encoding='utf-8') as f:
                for n, text in enumerate(f, 1):
                    if block.match(text):
                        found.append(f'{relpath(c_file)}:{n}')
                        break
        return found


def type_data(name):
    """resolve(name), or the name alone (no type, no PARITY): enough to
    compare captures."""
    try:
        return resolve(name)
    except ValueError:
        return TypeData(name, None)


def relpath(path):
    return os.path.relpath(path, SRCDIR)


def cases_files(srcdir=SRCDIR):
    """Every <stem>_cases.py next to a spec, in a stable order."""
    paths = []
    for top in ('Objects', 'Modules', 'Python', 'Include'):
        pattern = os.path.join(srcdir, top, '**', 'pyspec', '*_cases.py')
        paths += sorted(glob.glob(pattern, recursive=True))
    return paths


@functools.cache
def load_cases(path):
    name = '_pyspec_parity_' + os.path.basename(path).removesuffix('.py')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def spec_types(srcdir=SRCDIR):
    """The TypeData of the types described by the specs of a source tree:
    the TYPES of every <stem>_cases.py next to a spec, by name."""
    return _spec_types(os.path.abspath(srcdir))


@functools.cache
def _spec_types(srcdir):
    types = {}
    for path in cases_files(srcdir):
        module = load_cases(path)
        parity = getattr(module, 'PARITY', {})
        for name, tp in getattr(module, 'TYPES', {}).items():
            if name in types:
                raise ValueError(f'{name} is in the TYPES of both '
                                 f'{types[name].cases_path} and {path}')
            types[name] = TypeData(name, tp, path, parity.get(name))
        extra = set(parity) - set(getattr(module, 'TYPES', {}))
        if extra:
            raise ValueError(f'{path}: PARITY names {sorted(extra)}, '
                             'which are not in TYPES')
    return types


def resolve(name, srcdir=SRCDIR):
    """The TypeData of a type named as a class of the TYPES of a
    <stem>_cases.py, a builtin or module.name."""
    known = spec_types(srcdir)
    if name in known:
        return known[name]
    module, _, attr = name.rpartition('.')
    try:
        obj = importlib.import_module(module or 'builtins')
        for part in attr.split('.'):
            obj = getattr(obj, part)
    except (ImportError, AttributeError):
        obj = None
    if not isinstance(obj, type):
        raise ValueError(f'{name} is not a type: name a builtin, '
                         'module.name, or add it to the TYPES of its '
                         '<stem>_cases.py')
    return TypeData(name, obj)


# -- recording one call ------------------------------------------------------

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


def is_iterator(obj):
    return (hasattr(type(obj), '__next__')
            and getattr(type(obj), '__iter__', None) is not None)


def watchable(obj):
    """Whether a call can change obj in a way its repr (or, for an
    iterator, what it yields next) shows."""
    return obj is not None and (type(obj).__hash__ is None
                                or is_iterator(obj))


def rest(iterator):
    """What an iterator yields next (consumes it)."""
    return outcome(lambda: list(itertools.islice(iterator, 20)))


def outcome(func, *args, known=(), watch=None, **kwargs):
    """What calling func does: its result, or the exception it raises,
    then the warnings it emits and, if watch is given, what the call did
    to that object: its new repr, or what it yields next if an iterator
    (which consumes it)."""
    iterator = watch is not None and is_iterator(watch)
    before = describe(watch) if watch is not None and not iterator else None
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
    if iterator:
        text += f' [then yields {rest(watch)}]'
    elif watch is not None:
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


# -- capturing ---------------------------------------------------------------

class Capture:
    """Lines "type key => value", in sections "[type section]"."""

    def __init__(self):
        self.sections = {}

    def add(self, name, section, key, value):
        if SEP in key:
            raise ValueError(f'{SEP!r} in key {key!r}')
        value = str(value).replace('\n', '\\n')
        self.sections.setdefault((name, section), []).append(
            f'{name} {key}{SEP}{value}')

    def lines(self):
        out = [header()]
        for (name, section), lines in self.sections.items():
            out.append(f'[{name} {section}]')
            out += lines
        return out


class TypeCapture:
    """Everything observable about one type."""

    def __init__(self, data, out):
        self.data = data
        self.name = name = data.name
        self.tp = tp = data.tp
        self.out = out
        self.section = 'type'
        convert = data.convert or (lambda value: value)

        def converted(factories):
            return {label: (lambda f=f: convert(f()))
                    for label, f in factories.items()}

        samples = converted(data.samples) or {
            label: f for label, f in converted(POOL).items()
            if type(f()) is tp}
        if not samples:
            try:
                tp()
            except Exception:
                raise ValueError(
                    f'{name}: add sample instances to the "samples" of '
                    'its PARITY in its <stem>_cases.py') from None
            samples = {f'{name}()': tp}
        self.samples = dict(samples)
        self.pool = converted(POOL)
        for label, f in list(self.samples.items())[:2]:
            self.pool.setdefault(label, f)
        self.pool.update(converted(data.pool))
        # Receivers probed as fully as the first sample.
        self.full = {'Sub'}
        self.sub = None
        if tp.__flags__ & (1 << 10):        # Py_TPFLAGS_BASETYPE
            try:
                self.sub = type('Sub', (tp,), {'__module__': 'parity'})
            except TypeError:
                # A model of a type that is not a BASETYPE (model_types()):
                # a heap type always has the flag.
                self.sub = None
        if self.sub is not None:
            label, first = next(iter(self.samples.items()))
            try:
                self.sub(first())
            except Exception:
                pass
            else:
                self.samples[f'Sub({label})'] = lambda: self.sub(first())
                self.full.add(f'Sub({label})')

    def add(self, key, value):
        self.out.add(self.name, self.section, key, value)

    def run(self):
        self.surface()
        self.section = 'help'
        text = pydoc.render_doc(self.tp, renderer=pydoc.plaintext)
        for i, line in enumerate(clean(text).splitlines()):
            self.add(f'help {i:03}', line)
        self.section = 'C'
        self.c_layout()
        self.section = '()'
        self.probe_type()
        for attr, value in vars(self.tp).items():
            self.section = f'.{attr}'
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
            self.section = f'.{attr}'
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
        self.section = 'type'

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
        """Calls of the type itself and of its subclass, and subscripts
        of the type (__class_getitem__)."""
        receivers = {self.name: lambda: (None, self.tp)}
        if self.sub is not None:
            receivers['Sub'] = lambda: (None, self.sub)
        Prober(self, '', receivers).run()
        for args in (int, (int, str)):
            text = getattr(args, '__name__', 'int, str')
            self.add(f'{self.name}[{text}]',
                     outcome(operator.getitem, self.tp, args))

    def probe_attribute(self, attr, value):
        tp = self.tp
        kind = type(value).__name__
        if isinstance(value, type):
            return
        if kind in ('getset_descriptor', 'member_descriptor', 'property'):
            self.probe_data(attr, value)
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

    def probe_data(self, attr, descr):
        """A data descriptor: get, set and delete on each sample, the
        descriptor itself, and used on other objects."""
        for label, f in self.samples.items():
            obj = f()
            self.add(f'get {label}.{attr}',
                     outcome(getattr, obj, attr, known=[('self', obj)]))
            for v in (1, None):
                obj = f()
                self.add(f'set {label}.{attr} = {v}',
                         outcome(setattr, obj, attr, v, watch=obj))
            obj = f()
            self.add(f'del {label}.{attr}',
                     outcome(delattr, obj, attr, watch=obj))
        self.add(f'get {self.name}.{attr}', outcome(getattr, self.tp, attr))
        if hasattr(descr, '__get__'):
            self.add(f'{attr}.__get__(None, {self.name})',
                     outcome(descr.__get__, None, self.tp))
        for label in FOREIGN_SELF:
            if hasattr(descr, '__get__'):
                self.add(f'{attr}.__get__({label})',
                         outcome(descr.__get__, self.pool[label]()))
            if hasattr(descr, '__set__'):
                self.add(f'{attr}.__set__({label}, 1)',
                         outcome(descr.__set__, self.pool[label](), 1))

    # -- protocols -----------------------------------------------------------

    def probe_instance(self, label, factory):
        self.section = 'unary'
        for name, func in UNARY:
            obj = factory()
            self.add(f'{name}({label})',
                     outcome(func, obj, known=[('self', obj)], watch=obj))
        self.section = 'iteration'
        obj = factory()
        items = outcome(lambda: list(itertools.islice(iter(obj), 20)))
        self.add(f'list(iter({label}))[:20]', items)
        self.section = 'pickle'
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
            self.section = 'binary'
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
            self.section = 'inplace'
            for op, func in INPLACE:
                obj, v = factory(), vf()
                self.add(f'{label} {op} {vlabel}',
                         outcome(func, obj, v, watch=obj,
                                 known=[('self', obj), ('arg', v)]))
            self.section = 'contains'
            obj, v = factory(), vf()
            self.add(f'{vlabel} in {label}',
                     outcome(operator.contains, obj, v))
            self.section = 'subscript'
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
            self.section = 'format'
            obj = factory()
            self.add(f'format({label}, {vlabel})',
                     outcome(format, obj, vf()))


class Prober:
    """Calls of one callable: each arity, keyword use, each value of the
    pool for one parameter at a time and for each pair of parameters, the
    others at a baseline."""

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
        watch = obj if watchable(obj) else None
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
        vary: the fewest it accepts, each optional one then added in
        turn; and the most it accepts together."""
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

    def vary(self, receiver, bases, nvary):
        """Each value for one parameter, the others from a baseline."""
        for b in bases:
            for i in range(min(len(b) + 1, nvary)):
                for v in self.tc.pool:
                    self.call(receiver, b[:i] + [v] + b[i + 1:])

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
        nvary = len(positional) if params is not None else self.MAX_ARGS
        self.vary(first, bases, nvary)
        # Each pair of values for two parameters (e.g. encoding and
        # errors), the others from the longest baseline.
        longest = bases[-1]
        for i, j in itertools.combinations(range(min(len(longest), nvary)),
                                           2):
            for v, w in itertools.product(self.tc.pool, repeat=2):
                args = list(longest)
                args[i], args[j] = v, w
                self.call(first, args)
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
        # The other receivers: an instance of the subclass as fully as
        # the first, the others at the baselines.
        for receiver in receivers[1:]:
            if receiver[0] in self.tc.full:
                self.vary(receiver, bases, nvary)
            for b in bases:
                self.call(receiver, b)
            if base:
                self.call(receiver, [])


def capture(names):
    """The lines describing the named types, header first."""
    return capture_types([resolve(name) for name in names])


def capture_types(types):
    """The lines describing each type: TypeData or (name, type) pairs."""
    out = Capture()
    if hasattr(signal, 'SIGALRM'):
        old = signal.signal(signal.SIGALRM, _alarm)
    try:
        for data in types:
            if not isinstance(data, TypeData):
                data = TypeData(*data)
            TypeCapture(data, out).run()
    finally:
        if hasattr(signal, 'SIGALRM'):
            signal.signal(signal.SIGALRM, old)
    return out.lines()


def header():
    """The version and configuration: captures of two interpreters can
    be compared only if they are the same."""
    free_threaded = bool(sysconfig.get_config_var('Py_GIL_DISABLED'))
    return ('# python {}.{} free-threaded={} debug={} pointer={} '
            'platform={}'.format(
                *sys.version_info[:2], free_threaded,
                hasattr(sys, 'gettotalrefcount'), 8 * struct.calcsize('P'),
                sys.platform))


def run_capture(python, names):
    """Capture in another interpreter: hash randomization off, and the
    same file descriptors whoever runs it (mmap(0, 1) maps stdin)."""
    env = dict(os.environ, PYTHONHASHSEED='0')
    proc = subprocess.run(
        [python, '-X', 'utf8', os.path.abspath(__file__), 'capture',
         *names], capture_output=True, stdin=subprocess.DEVNULL, text=True,
        encoding='utf-8', env=env)
    if proc.returncode:
        raise RuntimeError(f'{python} capture failed '
                           f'({proc.returncode}):\n{proc.stderr}')
    return proc.stdout.splitlines()


# -- comparing ---------------------------------------------------------------

def parse(lines):
    """The header and {(type, section): [(key, value)]} of a capture;
    a key is without its type name."""
    sections = {}
    current = None
    for line in lines[1:]:
        if line.startswith('['):
            name, _, section = line[1:-1].partition(' ')
            current = sections.setdefault((name, section), [])
            continue
        name, _, rest = line.partition(' ')
        key, sep, value = rest.partition(SEP)
        if current is None or not sep:
            raise ValueError(f'not a capture line: {line!r}')
        current.append((key, value))
    return lines[0], sections


def type_names(sections):
    names = []
    for name, _ in sections:
        if name not in names:
            names.append(name)
    return names


class Comparison:
    """The differences between two captures, by type and section.

    changed: [(TypeData, section, probes, [(key, before, after)])], where
             before or after is None for a line only on one side;
    known:   [(TypeData, pattern, key, before, after)]: lines that
             differ, left out by the PARITY "known" of the type;
    probes:  {type name: lines compared}.
    """

    def __init__(self, before, after, types=None):
        header_before, before = parse(before)
        header_after, after = parse(after)
        if header_before != header_after:
            raise ValueError(f'different interpreters: {header_before!r} '
                             f'and {header_after!r}; capture with the same '
                             'version and configuration')
        if types is None:
            types = [type_data(name) for name in type_names(before)]
        self.types = [t if isinstance(t, TypeData) else TypeData(*t)
                      for t in types]
        self.changed = []
        self.known = []
        self.probes = {}
        for data in self.types:
            keys = [k for k in {**before, **after} if k[0] == data.name]
            for key in keys:
                self.compare_section(data, key[1], before.get(key, []),
                                     after.get(key, []))

    @staticmethod
    def differences(before, after):
        """(key, before, after) of each line that differs; before or after
        is None for a line only on one side."""
        changes = []
        for key in {**after, **before}:
            old, new = before.get(key, []), after.get(key, [])
            for i in range(max(len(old), len(new))):
                a = old[i] if i < len(old) else None
                b = new[i] if i < len(new) else None
                if a != b:
                    changes.append((key, a, b))
        return changes

    def compare_section(self, data, section, before, after):
        def by_key(entries, known):
            out = {}
            for key, value in entries:
                if (data.is_known(key) is not None) == known:
                    out.setdefault(key, []).append(value)
            return out

        for key, a, b in self.differences(by_key(before, True),
                                          by_key(after, True)):
            self.known.append((data, data.is_known(key), key, a, b))
        before, after = by_key(before, False), by_key(after, False)
        probes = sum(map(len, after.values()))
        self.probes[data.name] = self.probes.get(data.name, 0) + probes
        changes = self.differences(before, after)
        if changes:
            self.changed.append((data, section, probes, changes))

    def known_seen(self):
        """{(type name, pattern): [keys]} of the known differences that
        occur."""
        seen = {}
        for data, pattern, key, *_ in self.known:
            seen.setdefault((data.name, pattern), []).append(key)
        return seen

    def __bool__(self):
        return bool(self.changed)

    def text(self, limit=10):
        """The differences, section by section, before and after."""
        out = []
        for data, section, probes, changes in self.changed:
            where = data.location(section)
            where = f'  [{", ".join(where)}]' if where else ''
            out.append(f'{data.name} {section}: {len(changes)} of {probes} '
                       f'lines differ{where}')
            shown = changes if limit is None else changes[:limit]
            for key, before, after in shown:
                out.append(f'    {key}')
                out.append(f'        before: '
                           f'{"(no such line)" if before is None else before}')
                out.append(f'        after:  '
                           f'{"(no such line)" if after is None else after}')
            if len(shown) < len(changes):
                out.append(f'    ... {len(changes) - len(shown)} more '
                           '(--all shows them)')
        return '\n'.join(out) + '\n' if out else ''


def compare(before, after, types=None, limit=10):
    """The differences of two captures, less the known ones, or ''."""
    return Comparison(before, after, types).text(limit)


# -- the record --------------------------------------------------------------

def digests(lines, types=None):
    """{(type, section): (lines, digest)} of a capture, less the known
    differences, and its header."""
    head, sections = parse(lines)
    types = {t.name: t for t in types or ()}
    out = {}
    for (name, section), entries in sections.items():
        data = types.get(name) or type_data(name)
        kept = [f'{key}{SEP}{value}' for key, value in entries
                if data.is_known(key) is None]
        digest = hashlib.sha256('\n'.join(kept).encode('utf-8'))
        out[name, section] = (len(kept), digest.hexdigest()[:12])
    return head, out


def read_record(path=None):
    """{configuration header: {(type, section): (lines, digest)}}."""
    path = path or os.path.join(SRCDIR, RECORD)
    if not os.path.exists(path):
        return {}
    with open(path, encoding='utf-8') as f:
        return parse_record(f.read())


def parse_record(text):
    record = {}
    block = None
    for line in text.splitlines():
        if line.startswith('# python '):
            block = record.setdefault(line, {})
        elif line and not line.startswith('#'):
            name, section, count, digest = line.split(' ')
            block[name, section] = (int(count), digest)
    return record


def write_record(record, path=None):
    path = path or os.path.join(SRCDIR, RECORD)
    lines = [
        f'{RECORD_TITLE}: what Tools/clinic/pyspec_parity.py',
        '# captures, per build configuration; "type section lines digest",',
        '# known differences (PARITY of the <stem>_cases.py) left out.',
        '# A change that keeps behaviour leaves this file unchanged.',
        '# "pyspec_parity.py check" compares this interpreter with it;',
        '# "check --update" rewrites the block of its configuration.',
    ]
    for head, block in sorted(record.items()):
        lines.append(head)
        for (name, section), (count, digest) in block.items():
            lines.append(f'{name} {section} {count} {digest}')
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')


def record_types(block):
    """The types of a record block and those the specs describe."""
    names = list(spec_types())
    for name, _ in block:
        if name not in names:
            names.append(name)
    return names


def check_record(expected, actual, types):
    """Lines saying how the sections of a capture's digests differ from
    those of the record; [] if they do not."""
    by_name = {t.name: t for t in types}
    out = []
    recorded = {name for name, _ in expected}
    for name in by_name:
        if name not in recorded:
            out.append(f'{name}: not in the record (a type is recorded '
                       'before it is migrated: "check --update" on a tree '
                       'before the migration)')
    for key in {**actual, **expected}:
        name, section = key
        if name not in recorded:
            continue
        old, new = expected.get(key), actual.get(key)
        if old == new:
            continue
        data = by_name.get(name) or type_data(name)
        where = data.location(section)
        where = f'  [{", ".join(where)}]' if where else ''
        if old is None:
            out.append(f'{name} {section}: new section, {new[0]} lines'
                       f'{where}')
        elif new is None:
            out.append(f'{name} {section}: gone ({old[0]} lines recorded)')
        else:
            out.append(f'{name} {section}: {new[0]} lines (recorded '
                       f'{old[0]}), digest {new[1]} (recorded {old[1]})'
                       f'{where}')
    return out


def check_against_record(update=False, names=None, path=None):
    """Compare this interpreter with the record; with update, rewrite
    the block of this configuration.  Returns the header of this
    configuration, the messages of check_record() (None if the record has
    no block for it) and the digests of this interpreter."""
    record = read_record(path)
    head = header()
    block = record.get(head, {})
    names = names or record_types(block)
    types = [resolve(name) for name in names]
    current_head, current = digests(run_capture(sys.executable, names),
                                    types)
    assert current_head == head, (current_head, head)
    if update:
        # Keep the recorded types that were not captured this time.
        kept = {k: v for k, v in block.items() if k[0] not in names}
        record[head] = {**kept, **current}
        write_record(record, path)
        return head, [], current
    if not block:
        return head, None, current
    expected = {k: v for k, v in block.items() if k[0] in names}
    return head, check_record(expected, current, types), current


# -- the model: the spec run as a pure-Python type --------------------------
#
# ``model`` compares the C type with its spec run as Python
# (Tools/clinic/libclinic/pyspec/model.py): every line of every section,
# less what a Python class cannot have like a static C type, below, with
# the reason.  Objects/pyspec/README.rst, "Pure Python".

MODEL_EXCLUDED_SECTIONS = {
    'type': 'the type object: flags, sizes, MRO and module are those of a '
            'heap type (the PyTypeObject stays C)',
    'help': "pydoc's rendering of the type object (its MRO and flags)",
    'C': 'the C layout of the type object',
    'pickle': 'pickle and copyreg find the builtin by identity (the model '
              'is another class of the same name)',
    '.__getattribute__': 'tp_getattro is in the PyTypeObject, not in the '
                         'spec',
    '.__module__': 'a heap type keeps __module__ in its dict',
}
MODEL_EXCLUDED_KEYS = {
    r'^sys\.getsizeof\(': 'the size of the C struct',
    r'^copy\.(deep)?copy\(': 'copy.py dispatches on the builtin by identity',
}
# Lines where a model differs because it is a Python class, not because
# of its bodies: (section regex, key regex) -> the reason.  They count as
# differing; the report gives the reason.
MODEL_LIMITS = {
    (r'^\.__r?mul__$', r'\.__r?mul__\('):
        'a Python class has no sq_repeat apart from nb_multiply: the '
        'operator and an explicit call of the slot wrapper '
        '(wrap_indexargfunc(), which converts the operand first) are one '
        'method; the model reports the operator\'s errors',
    (r'^unary$', r'^weakref\.ref\(Sub\('):
        'a subclass of a Python class gets __weakref__, one of a '
        'variable-size C type cannot',
    (r'^binary$', r'^bytearray\(.*\) % '):
        "bytearray's % tests PyBytes_Check() on its operand: the builtin "
        'type, by identity',
    (r'^(inplace|subscript)$', r'( \*= |^del |\] = )'):
        'a heap type always has tp_as_sequence: PyNumber_InPlaceMultiply(), '
        'PyObject_SetItem() and PyObject_DelItem() take another path for a '
        'type without one',
}


def model_types(names, model=None):
    """(the TypeData of the models of the named types, the Model): each
    converts the argument values and samples to model objects."""
    tools = os.path.dirname(os.path.abspath(__file__))
    saved = list(sys.path)
    sys.path.insert(0, tools)
    try:
        from libclinic.pyspec import model as pymodel
        datas = [resolve(name) for name in names]
        if model is None:
            model = pymodel.Model(datas[0].spec_path)
    finally:
        sys.path[:] = saved
    out = []
    for data in datas:
        twin = copy.copy(data)
        twin.tp = model.types[data.name]
        twin.convert = functools.partial(pymodel.to_model, model=model)
        out.append(twin)
    return out, model


def model_excluded(section, key):
    """The reason line *key* of *section* is left out of a comparison of
    a model, or None."""
    if section in MODEL_EXCLUDED_SECTIONS:
        return MODEL_EXCLUDED_SECTIONS[section]
    for pattern, reason in MODEL_EXCLUDED_KEYS.items():
        if re.search(pattern, key):
            return reason
    return None


def model_limit(section, key):
    """The reason a differing line of a model is a limit of a Python
    class (MODEL_LIMITS), or None."""
    for (sections, keys), reason in MODEL_LIMITS.items():
        if re.search(sections, section) and re.search(keys, key):
            return reason
    return None


class ModelComparison:
    """The C types and their models (the specs run as pure Python), line
    by line.

    sections: {(type, section): Counts};
    changed:  {(type, section): [(key, C, model, limit reason or None)]}.
    """

    class Counts:
        def __init__(self):
            self.lines = self.identical = self.excluded = self.limits = 0

        @property
        def compared(self):
            return self.lines - self.excluded

        def add(self, other):
            for name in ('lines', 'identical', 'excluded', 'limits'):
                setattr(self, name, getattr(self, name)
                        + getattr(other, name))

    def __init__(self, names, model=None):
        datas = [resolve(name) for name in names]
        twins, self.model = model_types(names, model)
        host = capture_types(datas)
        modelled = capture_types(twins)
        _, host = parse(host)
        _, modelled = parse(modelled)
        self.sections = {}
        self.changed = {}
        for key in {**host, **modelled}:
            data = next(d for d in datas if d.name == key[0])
            lines = {}
            for side, entries in ((0, host.get(key, [])),
                                  (1, modelled.get(key, []))):
                for k, v in entries:
                    if data.is_known(k) is None:
                        lines.setdefault(k, [[], []])[side].append(v)
            counts = self.Counts()
            for k, (a, b) in lines.items():
                n = max(len(a), len(b))
                counts.lines += n
                if model_excluded(key[1], k):
                    counts.excluded += n
                    continue
                for i in range(n):
                    x = a[i] if i < len(a) else None
                    y = b[i] if i < len(b) else None
                    if x == y:
                        counts.identical += 1
                        continue
                    limit = model_limit(key[1], k)
                    counts.limits += limit is not None
                    self.changed.setdefault(key, []).append((k, x, y, limit))
            self.sections[key] = counts

    def kind(self, name, section):
        """'pure', 'delegated' or '' (not a method) of a section."""
        if section.startswith('.'):
            return self.model.kinds.get(f'{name}{section}', '')
        return ''

    def totals(self, kind=None):
        """The Counts over the sections of *kind* (all by default)."""
        total = self.Counts()
        for (name, section), counts in self.sections.items():
            if kind is None or self.kind(name, section) == kind:
                total.add(counts)
        return total

    def diverging(self):
        """{(type, section): [(key, C, model)]}: the lines that differ
        for no known limit, in the sections of pure methods and the
        protocols (not those of delegated methods)."""
        out = {}
        for (name, section), changes in self.changed.items():
            if self.kind(name, section) == 'delegated':
                continue
            lines = [c[:3] for c in changes if c[3] is None]
            if lines:
                out[name, section] = lines
        return out

    @staticmethod
    def percent(counts):
        if not counts.compared:
            return 'no lines'
        return (f'{counts.identical}/{counts.compared} identical '
                f'({100 * counts.identical / counts.compared:.1f}%)')

    def text(self, limit=3):
        out = []
        for (name, section), counts in self.sections.items():
            kind = self.kind(name, section)
            if counts.excluded == counts.lines:
                status = 'excluded: ' + model_excluded(section, '')
            else:
                status = f'{counts.identical}/{counts.compared} identical'
                if counts.limits:
                    status += f', {counts.limits} limits of a Python class'
                if counts.excluded:
                    status += f' ({counts.excluded} excluded)'
            out.append(f'{name} {section}: {status}'
                       + (f' [{kind}]' if kind else ''))
            changes = self.changed.get((name, section), [])
            for key, a, b, reason in (changes if limit is None
                                      else changes[:limit]):
                out.append(f'    {key}\n        C:     {a}\n'
                           f'        model: {b}')
                if reason:
                    out.append(f'        limit: {reason}')
        out.append('')
        for kind, label in (('pure', 'methods with a Python body'),
                            ('delegated', 'methods delegated to the C'),
                            ('', 'protocols, type calls, iteration')):
            out.append(f'{label}: {self.percent(self.totals(kind))}')
        total = self.totals()
        out.append(f'all: {self.percent(total)}; {total.limits} lines '
                   f'differ for a limit of a Python class; '
                   f'{total.excluded} lines excluded')
        return '\n'.join(out) + '\n'


# -- the command line --------------------------------------------------------

def report(comparison, limit):
    names = [t.name for t in comparison.types]
    for data, pattern, key, before, after in comparison.known:
        print(f'known: {data.name} {key}: {before} -> {after} '
              f'({data.known[pattern][1]})')
    if not comparison:
        counts = ', '.join(f'{n} ({comparison.probes.get(n, 0)} lines)'
                           for n in names)
        print(f'no difference in {counts}')
        return 0
    print(comparison.text(limit), end='')
    sys.stdout.flush()
    changed = sum(len(c) for *_, c in comparison.changed)
    print(f'\n{changed} lines differ; a difference made on purpose goes '
          'into the "known" of the PARITY of the type\'s <stem>_cases.py, '
          'with the reason', file=sys.stderr)
    return 1


def check_command(update, names, path):
    head, messages, _ = check_against_record(update, names, path)
    where = path or RECORD
    config = head.removeprefix('# ')
    if update:
        print(f'updated {where} for {config}')
        return 0
    if messages is None:
        print(f'{where} has no block for {config}: nothing to compare '
              'with (compare with a build before the change, or run '
              '"check --update" on one)')
        return 0
    if not messages:
        print(f'same as {where} ({config})')
        return 0
    print('\n'.join(messages), flush=True)
    print(f'\nThese sections differ from {where}.  To see the lines, '
          'compare with a build before the change ("compare '
          'BASELINE_PYTHON TYPE").  If the change is on purpose: '
          '"check --update", and say why in the PR (or add the lines '
          'to the "known" of the PARITY of the type).', file=sys.stderr)
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
    p = sub.add_parser('check', help='compare with the record, or with a '
                                     'capture')
    p.add_argument('file', nargs='?',
                   help=f'a capture (default: the record, {RECORD})')
    p.add_argument('types', nargs='*', help='default: those of the file')
    p.add_argument('--update', action='store_true',
                   help='rewrite the record for this configuration')
    p.add_argument('--all', action='store_true',
                   help='show every differing line')
    p = sub.add_parser('model', help='compare with the spec run as '
                                     'pure Python')
    p.add_argument('types', nargs='*', help='default: bytes, '
                                            'bytes_iterator')
    p.add_argument('--all', action='store_true',
                   help='show every differing line')
    p = sub.add_parser('compare', help='compare with another interpreter')
    p.add_argument('baseline', help='the python before the change')
    p.add_argument('types', nargs='*', help=all_specs)
    p.add_argument('--all', action='store_true',
                   help='show every differing line')
    args = parser.parse_args(argv)
    limit = None if getattr(args, 'all', False) else 10

    if args.command == 'model':
        names = args.types or ['bytes', 'bytes_iterator']
        comparison = ModelComparison(names)
        sys.stdout.write(comparison.text(limit=None if args.all else 3))
        return 0
    if args.command == 'capture':
        names = args.types or list(spec_types())
        if os.environ.get('PYTHONHASHSEED') != '0':
            lines = run_capture(sys.executable, names)
        else:
            lines = capture(names)
        text = '\n'.join(lines) + '\n'
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(text)
        else:
            sys.stdout.write(text)
        return 0
    record = None
    if (args.command == 'check' and args.file is not None
            and not os.path.exists(args.file)):
        # "check bytes": a type, against the record.
        args.file, args.types = None, [args.file, *args.types]
    if args.command == 'check' and args.file is not None:
        with open(args.file, encoding='utf-8') as f:
            if f.readline().startswith(RECORD_TITLE):
                args.file, record = None, args.file
    if args.command == 'check' and args.file is None:
        return check_command(args.update, args.types, record)
    if args.command == 'check':
        with open(args.file, encoding='utf-8') as f:
            before = f.read().splitlines()
        _, sections = parse(before)
        names = args.types or type_names(sections)
        before = [before[0]] + [
            line for (name, section), entries in sections.items()
            if name in names
            for line in [f'[{name} {section}]'] + [
                f'{name} {k}{SEP}{v}' for k, v in entries]]
        after = run_capture(sys.executable, names)
        return report(Comparison(before, after,
                                 [resolve(n) for n in names]), limit)
    names = args.types or list(spec_types())
    before = run_capture(args.baseline, names)
    after = run_capture(sys.executable, names)
    return report(Comparison(before, after, [resolve(n) for n in names]),
                  limit)


if __name__ == '__main__':
    sys.exit(main())

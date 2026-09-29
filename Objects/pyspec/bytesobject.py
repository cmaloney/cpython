"""The bytes type, written as Python: the spec of Objects/bytesobject.c.

Argument Clinic reads this file while processing bytesobject.c (see
Objects/pyspec/README.rst).  Each method of ``class bytes`` is a clinic
function (parameters, docstring and clinic decorators); bytesobject.c has
a one-line block for it (``bytes.split``) above its impl.  Methods with a
body of ``...`` are implemented in C by hand.  The others (``__new__``,
``__bytes__``, ``fromhex``) are implemented here: clinic generates their
impls into Objects/clinic/bytesobject_pyspec.c.h and, for the vectorcall
of ``__new__``, bytes_new_nargsN(): ``__new__`` partially evaluated for
exactly bytes and N positional arguments.  Top-level functions are C
functions of the same name: generated from their body, or, with
``@native``, written by hand in C, the body being their Python
reference (never compiled); an ``@inline`` function is generated into
its callers.  The C functions of other files the bodies call are
imported from the specs of those files.

The classes are the whole types: clinic generates their docstring, method
tables and slot tables at the end of Objects/clinic/bytesobject_pyspec.c.h,
which PyBytes_Type and PyBytesIter_Type (in C) name.  Dunders are slots
(C functions with the slot's signature), ``@c_name(METH_NOARGS=...)``
methods are hand-written PyCFunctions, and ``center =
transmogrify.B.center`` shares a method with bytearray (see
libclinic/pyspec/frontend.py).

Lib/test/test_clinic.py runs this file as Python and compares it with the
interpreter on the cases of bytesobject_cases.py.
"""

import builtins
import sys
import types
import warnings

from libclinic.pyspec.runtime import (
    NULL, PY_SSIZE_T_MAX, calls, exact, fqname, inline, isinstance, iter,
    native, runs_python, tp_name, unknown)

# Argument Clinic decorators (no-ops in Python).
from libclinic.pyspec.runtime import permit_long_summary, text_signature
from libclinic.pyspec.runtime import c_name

# The object layout and memory (Objects/pyspec/README.rst, "Pure Python").
from libclinic.pyspec.machine import (
    buffer_export, buffer_items, has_slot, ob_alloc, ob_items, ob_new)

# The C functions of other files the bodies call.
from Objects.pyspec.abstract import (
    PyNumber_AsSsize_t, PyNumber_AsSsize_t_fast, PyObject_LengthHint_fast)
from Objects.pyspec.typeobject import _PyObject_LookupSpecial
from Objects.pyspec.unicodeobject import (
    PyUnicode_AsEncodedString, PyUnicode_FromEncodedObject)
from Objects.pyspec.longobject import PyLong_AsSsize_t
from Objects.pyspec.bytes_methods import (
    _Py_bytes_contains, _Py_bytes_count, _Py_bytes_endswith, _Py_bytes_find,
    _Py_bytes_index, _Py_bytes_maketrans, _Py_bytes_repr, _Py_bytes_rfind,
    _Py_bytes_rindex, _Py_bytes_startswith, SPACE, getbuffer,
    stringlib_count, stringlib_find, stringlib_rfind)
from Python.pyspec.errors import PyErr_BadInternalCall
from Python.pyspec.pyhash import Py_HashBuffer
from Python.pyspec.pystrhex import _Py_strhex_with_sep

# Methods shared with bytearray (Objects/stringlib/pyspec/).
from Objects.stringlib.pyspec import ctype, transmogrify


class bytes:
    """bytes(iterable_of_ints) -> bytes
    bytes(string, encoding[, errors]) -> bytes
    bytes(bytes_or_buffer) -> immutable copy of bytes_or_buffer
    bytes(int) -> bytes object of size given by the parameter initialized with null bytes
    bytes() -> empty bytes object

    Construct an immutable array of bytes from:
      - an iterable yielding integers in range(256)
      - a text string encoded using the specified encoding
      - any object implementing the buffer API.
      - an integer
    """

    # The bytes (PyBytesObject: the struct stays C; the model allocates
    # this field, see machine.py).
    ob_sval: 'char[]'

    @c_name("bytes_new")
    def __new__(
        cls,
        source: object = NULL,
        encoding: str = NULL,
        errors: str = NULL,
    ):
        if cls is not bytes:
            value = bytes.__new__(bytes, source, encoding, errors)
            return bytes_subtype_new(cls, value)
        if source is NULL:
            if encoding is not NULL:
                raise TypeError("encoding without a string argument")
            if errors is not NULL:
                raise TypeError("errors without a string argument")
            return b""
        if encoding is not NULL:
            if not isinstance(source, str):
                raise TypeError("encoding without a string argument")
            return PyUnicode_AsEncodedString(source, encoding, errors)
        if errors is not NULL:
            if isinstance(source, str):
                raise TypeError("string argument without an encoding")
            raise TypeError("errors without a string argument")
        # bytes.__bytes__ of an exact bytes returns it: no lookup, no call.
        if type(source) is bytes:
            return source
        # We'd like to call PyObject_Bytes here, but we need to check for an
        # integer argument before deferring to PyBytes_FromObject, something
        # PyObject_Bytes doesn't do.
        # An exact int has no __bytes__: no lookup (a type-cache probe for
        # every bytes(n) the tier-2 call table does not reach, and Sub(n)).
        if type(source) is not int:
            if (func := _PyObject_LookupSpecial(source, "__bytes__")) is not NULL:
                result = func()
                if not isinstance(result, bytes):
                    raise TypeError(f"{fqname(type(source))}.__bytes__() must "
                                    f"return a bytes, not {fqname(type(result))}")
                return result
        if isinstance(source, str):
            raise TypeError("string argument without an encoding")
        # Is it an integer?
        if hasattr(type(source), "__index__"):
            try:
                size = PyNumber_AsSsize_t_fast(source, OverflowError)
            except TypeError:
                return PyBytes_FromObject(source)
            if size < 0:
                raise ValueError("negative count")
            return _PyBytes_FromSize(size, True)
        return PyBytes_FromObject(source)

    @native(facts=False)
    @c_name(METH_NOARGS="bytes_getnewargs")
    def __getnewargs__(self, /):
        return (bytes_copy(self),)

    def __bytes__(self):
        """Convert this value to exact type bytes."""
        if type(self) is bytes:
            return self
        return bytes_copy(self)

    capitalize = ctype.B.capitalize

    center = transmogrify.B.center

    @native(facts=False)
    @permit_long_summary
    @text_signature("($self, sub[, start[, end]], /)")
    def count(
        self,
        sub: object,
        start: slice_index(accept={int, NoneType}, c_default='0') = None,
        end: slice_index(accept={int, NoneType}, c_default='PY_SSIZE_T_MAX') = None,
        /,
    ):
        """Return the number of non-overlapping occurrences of subsection 'sub' in bytes B[start:end].

          start
            Optional start position. Default: start of the bytes.
          end
            Optional stop position. Default: end of the bytes.
        """
        s = ob_items(self)
        return _Py_bytes_count(s, len(s), sub, start, end)

    @native(facts=False)
    def decode(
        self,
        encoding: str(c_default="NULL") = 'utf-8',
        errors: str(c_default="NULL") = 'strict',
    ):
        """Decode the bytes using the codec registered for encoding.

          encoding
            The encoding with which to decode the bytes.
          errors
            The error handling scheme to use for the handling of decoding
            errors.  The default is 'strict' meaning that decoding errors
            raise a UnicodeDecodeError.  Other possible values are 'ignore'
            and 'replace' as well as any other name registered with
            codecs.register_error that can handle UnicodeDecodeErrors.
        """
        return PyUnicode_FromEncodedObject(self, encoding, errors)

    @native(facts=False)
    @permit_long_summary
    @text_signature("($self, suffix[, start[, end]], /)")
    def endswith(
        self,
        suffix: object(c_param='subobj'),
        start: slice_index(accept={int, NoneType}, c_default='0') = None,
        end: slice_index(accept={int, NoneType}, c_default='PY_SSIZE_T_MAX') = None,
        /,
    ):
        """Return True if the bytes ends with the specified suffix, False otherwise.

          suffix
            A bytes or a tuple of bytes to try.
          start
            Optional start position. Default: start of the bytes.
          end
            Optional stop position. Default: end of the bytes.
        """
        s = ob_items(self)
        return _Py_bytes_endswith(s, len(s), suffix, start, end)

    expandtabs = transmogrify.B.expandtabs

    @native(facts=False)
    @permit_long_summary
    @text_signature("($self, sub[, start[, end]], /)")
    def find(
        self,
        sub: object,
        start: slice_index(accept={int, NoneType}, c_default='0') = None,
        end: slice_index(accept={int, NoneType}, c_default='PY_SSIZE_T_MAX') = None,
        /,
    ):
        """Return the lowest index in B where subsection 'sub' is found, such that 'sub' is contained within B[start,end].

          start
            Optional start position. Default: start of the bytes.
          end
            Optional stop position. Default: end of the bytes.

        Return -1 on failure.
        """
        s = ob_items(self)
        return _Py_bytes_find(s, len(s), sub, start, end)

    @classmethod
    def fromhex(cls, string: object, /):
        r"""Create a bytes object from a string of hexadecimal numbers.

        Spaces between two numbers are accepted.
        Example: bytes.fromhex('B9 01EF') -> b'\\xb9\\x01\\xef'.
        """
        if cls is bytes:
            return _PyBytes_FromHex(string, False)
        result = _PyBytes_FromHex(string, False)
        return cls(result)

    @native(facts=False)
    def hex(self, sep: object = NULL, bytes_per_sep: Py_ssize_t = 1):
        r"""Create a string of hexadecimal numbers from a bytes object.

          sep
            An optional single character or byte to separate hex bytes.
          bytes_per_sep
            How many bytes between separators.  Positive values count from
            the right, negative values count from the left.

        Example:
        >>> value = b'\xb9\x01\xef'
        >>> value.hex()
        'b901ef'
        >>> value.hex(':')
        'b9:01:ef'
        >>> value.hex(':', 2)
        'b9:01ef'
        >>> value.hex(':', -2)
        'b901:ef'
        """
        s = ob_items(self)
        return _Py_strhex_with_sep(s, len(s), sep, bytes_per_sep)

    @native(facts=False)
    @permit_long_summary
    @text_signature("($self, sub[, start[, end]], /)")
    def index(
        self,
        sub: object,
        start: slice_index(accept={int, NoneType}, c_default='0') = None,
        end: slice_index(accept={int, NoneType}, c_default='PY_SSIZE_T_MAX') = None,
        /,
    ):
        """Return the lowest index in B where subsection 'sub' is found, such that 'sub' is contained within B[start,end].

          start
            Optional start position. Default: start of the bytes.
          end
            Optional stop position. Default: end of the bytes.

        Raise ValueError if the subsection is not found.
        """
        s = ob_items(self)
        return _Py_bytes_index(s, len(s), sub, start, end)

    isalnum = ctype.B.isalnum

    isalpha = ctype.B.isalpha

    isascii = ctype.B.isascii

    isdigit = ctype.B.isdigit

    islower = ctype.B.islower

    isspace = ctype.B.isspace

    istitle = ctype.B.istitle

    isupper = ctype.B.isupper

    @native(facts=False)
    def join(self, iterable_of_bytes: object, /):
        """Concatenate any number of bytes objects.

        The bytes whose method is called is inserted in between each pair.

        The result is returned as a new bytes object.

        Example: b'.'.join([b'ab', b'pq', b'rs']) -> b'ab.pq.rs'.
        """
        return stringlib_bytes_join(self, iterable_of_bytes)

    ljust = transmogrify.B.ljust

    lower = ctype.B.lower

    @native(facts=False)
    def lstrip(self, bytes: object = None, /):
        """Strip leading bytes contained in the argument.

        If the argument is omitted or None, strip leading  ASCII whitespace.
        """
        return do_argstrip(self, LEFTSTRIP, bytes)

    @native(facts=False)
    @permit_long_summary
    @staticmethod
    def maketrans(frm: Py_buffer, to: Py_buffer, /):
        """Return a translation table usable for the bytes or bytearray translate method.

        The returned table will be one where each byte in frm is mapped to
        the byte at the same position in to.

        The bytes objects frm and to must be of the same length.
        """
        return new_bytes(_Py_bytes_maketrans(frm, to))

    @native(facts=False)
    def partition(self, sep: Py_buffer, /):
        """Partition the bytes into three parts using the given separator.

        This will search for the separator sep in the bytes.  If the
        separator is found, returns a 3-tuple containing the part before the
        separator, the separator itself, and the part after it.

        If the separator is not found, returns a 3-tuple containing the
        original bytes object and two empty bytes objects.
        """
        return stringlib_partition(self, ob_items(self), sep.obj, sep)

    @native(facts=False)
    def replace(self, old: Py_buffer, new: Py_buffer, /,
                count: Py_ssize_t = -1):
        """Return a copy with all occurrences of substring old replaced by new.

          count
            Maximum number of occurrences to replace.
            -1 (the default value) means replace all occurrences.

        If count is given, only the first count occurrences are replaced.
        If count is not specified or -1, then all occurrences are replaced.
        """
        return stringlib_replace(self, old, new, count)

    @native(facts=False)
    @permit_long_summary
    def removeprefix(self, prefix: Py_buffer, /):
        """Return a bytes object with the given prefix string removed if present.

        If the bytes starts with the prefix string, return
        bytes[len(prefix):].  Otherwise, return a copy of the original
        bytes.
        """
        s = ob_items(self)
        if len(s) >= len(prefix) and len(prefix) > 0 and \
                s[:len(prefix)] == tuple(prefix):
            return new_bytes(s[len(prefix):])
        return return_self(self)

    @native(facts=False)
    @permit_long_summary
    def removesuffix(self, suffix: Py_buffer, /):
        """Return a bytes object with the given suffix string removed if present.

        If the bytes ends with the suffix string and that suffix is not
        empty, return bytes[:-len(prefix)].  Otherwise, return a copy of the
        original bytes.
        """
        s = ob_items(self)
        if len(s) >= len(suffix) and len(suffix) > 0 and \
                s[len(s) - len(suffix):] == tuple(suffix):
            return new_bytes(s[:len(s) - len(suffix)])
        return return_self(self)

    @native(facts=False)
    @permit_long_summary
    @text_signature("($self, sub[, start[, end]], /)")
    def rfind(
        self,
        sub: object,
        start: slice_index(accept={int, NoneType}, c_default='0') = None,
        end: slice_index(accept={int, NoneType}, c_default='PY_SSIZE_T_MAX') = None,
        /,
    ):
        """Return the highest index in B where subsection 'sub' is found, such that 'sub' is contained within B[start,end].

          start
            Optional start position. Default: start of the bytes.
          end
            Optional stop position. Default: end of the bytes.

        Return -1 on failure.
        """
        s = ob_items(self)
        return _Py_bytes_rfind(s, len(s), sub, start, end)

    @native(facts=False)
    @permit_long_summary
    @text_signature("($self, sub[, start[, end]], /)")
    def rindex(
        self,
        sub: object,
        start: slice_index(accept={int, NoneType}, c_default='0') = None,
        end: slice_index(accept={int, NoneType}, c_default='PY_SSIZE_T_MAX') = None,
        /,
    ):
        """Return the highest index in B where subsection 'sub' is found, such that 'sub' is contained within B[start,end].

          start
            Optional start position. Default: start of the bytes.
          end
            Optional stop position. Default: end of the bytes.

        Raise ValueError if the subsection is not found.
        """
        s = ob_items(self)
        return _Py_bytes_rindex(s, len(s), sub, start, end)

    rjust = transmogrify.B.rjust

    @native(facts=False)
    def rpartition(self, sep: Py_buffer, /):
        """Partition the bytes into three parts using the given separator.

        This will search for the separator sep in the bytes, starting at the
        end.  If the separator is found, returns a 3-tuple containing the
        part before the separator, the separator itself, and the part after
        it.

        If the separator is not found, returns a 3-tuple containing two
        empty bytes objects and the original bytes object.
        """
        return stringlib_rpartition(self, ob_items(self), sep.obj, sep)

    @native(facts=False)
    @permit_long_summary
    def rsplit(self, sep: object = None, maxsplit: Py_ssize_t = -1):
        """Return a list of the sections in the bytes, using sep as the delimiter.

          sep
            The delimiter according which to split the bytes.
            None (the default value) means split on ASCII whitespace
            characters (space, tab, return, newline, formfeed, vertical tab).
          maxsplit
            Maximum number of splits to do.
            -1 (the default value) means no limit.

        Splitting is done starting at the end of the bytes and working to
        the front.
        """
        if maxsplit < 0:
            maxsplit = PY_SSIZE_T_MAX
        if sep is None:
            return stringlib_rsplit_whitespace(self, ob_items(self), maxsplit)
        sub = buffer_items(sep)
        if sub is NULL:
            raise TypeError("a bytes-like object is required, not "
                            f"'{tp_name(type(sep))}'")
        return stringlib_rsplit(self, ob_items(self), sub, maxsplit)

    @native(facts=False)
    def rstrip(self, bytes: object = None, /):
        """Strip trailing bytes contained in the argument.

        If the argument is omitted or None, strip trailing ASCII whitespace.
        """
        return do_argstrip(self, RIGHTSTRIP, bytes)

    @native(facts=False)
    @permit_long_summary
    def split(self, sep: object = None, maxsplit: Py_ssize_t = -1):
        """Return a list of the sections in the bytes, using sep as the delimiter.

          sep
            The delimiter according which to split the bytes.
            None (the default value) means split on ASCII whitespace
            characters (space, tab, return, newline, formfeed, vertical tab).
          maxsplit
            Maximum number of splits to do.
            -1 (the default value) means no limit.
        """
        if maxsplit < 0:
            maxsplit = PY_SSIZE_T_MAX
        if sep is None:
            return stringlib_split_whitespace(self, ob_items(self), maxsplit)
        sub = buffer_items(sep)
        if sub is NULL:
            raise TypeError("a bytes-like object is required, not "
                            f"'{tp_name(type(sep))}'")
        return stringlib_split(self, ob_items(self), sub, maxsplit)

    @native(facts=False)
    @permit_long_summary
    def splitlines(self, keepends: bool = False):
        """Return a list of the lines in the bytes, breaking at line boundaries.

        Line breaks are not included in the resulting list unless keepends
        is given and true.
        """
        return stringlib_splitlines(self, ob_items(self), keepends)

    @native(facts=False)
    @permit_long_summary
    @text_signature("($self, prefix[, start[, end]], /)")
    def startswith(
        self,
        prefix: object(c_param='subobj'),
        start: slice_index(accept={int, NoneType}, c_default='0') = None,
        end: slice_index(accept={int, NoneType}, c_default='PY_SSIZE_T_MAX') = None,
        /,
    ):
        """Return True if the bytes starts with the specified prefix, False otherwise.

          prefix
            A bytes or a tuple of bytes to try.
          start
            Optional start position. Default: start of the bytes.
          end
            Optional stop position. Default: end of the bytes.
        """
        s = ob_items(self)
        return _Py_bytes_startswith(s, len(s), prefix, start, end)

    @native(facts=False)
    def strip(self, bytes: object = None, /):
        """Strip leading and trailing bytes contained in the argument.

        If the argument is omitted or None, strip leading and trailing ASCII
        whitespace.
        """
        return do_argstrip(self, BOTHSTRIP, bytes)

    swapcase = ctype.B.swapcase

    title = ctype.B.title

    @native(facts=False)
    @permit_long_summary
    def translate(
        self,
        table: object,
        /,
        delete: object(c_param='deletechars', c_default="NULL") = b'',
    ):
        """Return a copy with each character mapped by the given translation table.

          table
            Translation table, which must be a bytes object of length 256.

        All characters occurring in the optional argument delete are
        removed.  The remaining characters are mapped through the given
        translation table.
        """
        return bytes_translate(self, table, delete)

    upper = ctype.B.upper

    zfill = transmogrify.B.zfill

    # -- Slots: C functions with the signature of their slot (see "Methods
    # that are not clinic functions" in libclinic/pyspec/frontend.py).  The
    # C name is bytes_ plus the slot without its prefix (bytes_repr for
    # tp_repr) unless @c_name gives it.

    @native(facts=False)
    def __repr__(self, /):
        s = ob_items(self)
        return _Py_bytes_repr(s, len(s), 1, "bytes")
    @native(facts=False)
    def __hash__(self, /):
        s = ob_items(self)
        return Py_HashBuffer(s, len(s))
    @native(facts=False)
    def __str__(self, /):
        if sys.flags.bytes_warning:
            warnings.warn("str() on a bytes instance", BytesWarning, 1)
        return bytes.__repr__(self)

    # tp_richcompare: one C function, bytes_richcompare(), for all six.
    @native(facts=False)
    def __lt__(self, value, /):
        return bytes_richcompare(self, value, Py_LT)
    @native(facts=False)
    def __le__(self, value, /):
        return bytes_richcompare(self, value, Py_LE)
    @native(facts=False)
    def __eq__(self, value, /):
        return bytes_richcompare(self, value, Py_EQ)
    @native(facts=False)
    def __ne__(self, value, /):
        return bytes_richcompare(self, value, Py_NE)
    @native(facts=False)
    def __gt__(self, value, /):
        return bytes_richcompare(self, value, Py_GT)
    @native(facts=False)
    def __ge__(self, value, /):
        return bytes_richcompare(self, value, Py_GE)

    @native(facts=False)
    def __iter__(self, /):
        it = ob_new(bytes_iterator)
        it.it_index = 0
        it.it_seq = self
        return it

    @c_name("bytes_buffer_getbuffer")
    @native
    def __buffer__(self, flags, /):
        return exact(memoryview, buffer_export(self, flags))

    # nb_remainder: bytes_mod() for both.
    @c_name("bytes_mod")
    def __mod__(self, value, /): ...
    def __rmod__(self, value, /): ...

    @c_name(mp_length="bytes_length", sq_length="bytes_length")
    @native
    def __len__(self, /):
        return len(ob_items(self))

    # The tier-2 optimizer uses the facts of b[i] for an exact bytes b and
    # an exact int i (an exact int, no Python code; the only error is
    # IndexError) for _BINARY_OP_SUBSCR_BYTES_INT (see pycore_pyspec.h).
    @c_name(mp_subscript="bytes_subscript", sq_item="bytes_item")
    @native
    def __getitem__(self, key, /):
        if hasattr(type(key), "__index__"):
            i = PyNumber_AsSsize_t(key, IndexError)
            if i < -len(self) or i >= len(self):
                raise IndexError("index out of range")
            return exact(int, ob_items(self)[i])
        if isinstance(key, slice):
            # PySlice_Unpack(): the __index__ of start, stop and step.
            runs_python()
            return exact(bytes, bytes_subscript_slice(self, key))
        raise TypeError("byte indices must be integers or slices, not "
                        f"{tp_name(type(key))}")

    @native(facts=False)
    @c_name(sq_concat="_PyBytes_Concat")
    def __add__(self, value, /):
        return _PyBytes_Concat(self, value)

    # sq_repeat: _PyBytes_Repeat() for both.
    @native(facts=False)
    @c_name(sq_repeat="_PyBytes_Repeat")
    def __mul__(self, value, /):
        # sequence_repeat() of abstract.c (a Python class fills
        # nb_multiply, not sq_repeat: the conversion of the operand is
        # here, see machine.has_slot()).
        if not hasattr(type(value), "__index__"):
            raise TypeError("can't multiply sequence by non-int of type "
                            f"'{tp_name(type(value))}'")
        return _PyBytes_Repeat(self, PyNumber_AsSsize_t(value, OverflowError))
    @native(facts=False)
    def __rmul__(self, value, /):
        if not hasattr(type(value), "__index__"):
            if has_slot(type(value), "sq_repeat"):
                # value * self: the sq_repeat of value comes first.
                return NotImplemented
            raise TypeError("can't multiply sequence by non-int of type "
                            f"'{tp_name(type(value))}'")
        return _PyBytes_Repeat(self, PyNumber_AsSsize_t(value, OverflowError))

    @native(facts=False)
    def __contains__(self, key, /):
        s = ob_items(self)
        return _Py_bytes_contains(s, len(s), key)


# iter(bytes).  No docstring: tp_doc is NULL.  PyBytesIter_Type, the
# struct (striterobject), its dealloc and traverse are C; the method table
# is striter_methods.
@c_name("striter")
class bytes_iterator:
    # The fields of striterobject (the struct stays C).
    it_index: Py_ssize_t
    it_seq: 'PyBytesObject *'

    @native(facts=False)
    @c_name("PyObject_SelfIter")
    def __iter__(self, /):
        return self

    # Exact ints in range(256) (immortal small ints); NULL without an
    # exception when exhausted (tp_iternext).
    @c_name("striter_next")
    @native
    def __next__(self, /):
        seq = self.it_seq
        if seq is NULL:
            return NULL
        if self.it_index < len(ob_items(seq)):
            item = ob_items(seq)[self.it_index]
            self.it_index += 1
            return exact(int, item)
        self.it_seq = NULL
        return NULL

    @native(facts=False)
    @c_name(METH_NOARGS="striter_len")
    def __length_hint__(self, /):
        """Private method returning an estimate of len(list(it))."""
        if self.it_seq is NULL:
            return 0
        return len(ob_items(self.it_seq)) - self.it_index

    @native(facts=False)
    @c_name(METH_NOARGS="striter_reduce")
    def __reduce__(self, /):
        """Return state information for pickling."""
        if self.it_seq is not NULL:
            return (builtins.iter, (self.it_seq,), self.it_index)
        return (builtins.iter, ((),))

    @native(facts=False)
    @c_name(METH_O="striter_setstate")
    def __setstate__(self, state, /):
        """Set state information for unpickling."""
        index = PyLong_AsSsize_t(state)
        if self.it_seq is not NULL:
            if index < 0:
                index = 0
            elif index > len(ob_items(self.it_seq)):
                # The iterator is exhausted.
                index = len(ob_items(self.it_seq))
            self.it_index = index
        return None


def PyBytes_FromObject(x: object):
    r"""Return the bytes representation of object *o* that implements the buffer
    protocol.

    .. note::
       If the object implements the buffer protocol, then the buffer
       must not be mutated while the bytes object is being created.
    """
    if x is NULL:
        raise PyErr_BadInternalCall()
    if type(x) is bytes:
        return x
    # Use the modern buffer interface
    if hasattr(type(x), "__buffer__"):
        return _PyBytes_FromBuffer(x)
    # Argument Clinic specializes the iteration for an exact list or
    # tuple: an index loop, without an iterator; a list of compact ints
    # is copied atomically, in its critical section (see partial_eval.py).
    if not isinstance(x, str):
        try:
            it = iter(x)
        except TypeError:
            pass
        else:
            return bytes_from_iterator(it, x)
    raise TypeError(f"cannot convert '{tp_name(type(x))}' object to bytes")


def bytes_from_iterator(it: object, x: object):
    """The bytes of the ints (or objects with __index__) of iterator it,
    iter(x)."""
    size = PyObject_LengthHint_fast(x, 64)
    writer = bytes_appender_init(size)
    try:
        for item in it:
            value = PyNumber_AsSsize_t_fast(item, NULL)
            if value < 0 or value >= 256:
                raise ValueError("bytes must be in range(0, 256)")
            bytes_appender_append_fast(writer, value)
        return bytes_appender_finish(writer)
    finally:
        bytes_appender_discard(writer)


# ---------------------------------------------------------------------------
# The C functions of bytesobject.c the bodies above call.  Each is
# @native: its C is the authority; the body is its Python
# reference, run when the spec runs as Python and read for the facts of
# the calls, never compiled (see Objects/pyspec/README.rst).


@native
def _PyBytes_FromSize(size: Py_ssize_t, use_calloc: int):
    """size bytes: null bytes with use_calloc, else not initialized."""
    return exact(bytes, new_bytes((0,) * size, written=True))


@native
def _PyBytes_FromBuffer(x: object):
    """A copy of the buffer of x (in C order)."""
    calls(x, "__buffer__")
    calls(x, "__release_buffer__")
    return exact(bytes, new_bytes(buffer_items(x)))


@native
def _PyBytes_FromHex(string: object, use_bytearray: int):
    """The bytes (a bytearray with use_bytearray) of the hexadecimal
    numbers in str or buffer string."""
    if not isinstance(string, str):
        calls(string, "__buffer__")
        calls(string, "__release_buffer__")
    if use_bytearray:
        return exact(bytearray, ob_alloc(bytearray, fromhex_items(string)))
    return exact(bytes, new_bytes(fromhex_items(string)))


@native(facts=False)
def fromhex_items(string: object):
    """The loop of _PyBytes_FromHex(): the bytes of the pairs of
    hexadecimal digits in str or buffer string, with ASCII whitespace
    (Py_ISSPACE) before each pair and at the end."""
    if isinstance(string, str):
        if not string.isascii():
            position = next(i for i, c in enumerate(string) if ord(c) >= 128)
            raise ValueError("non-hexadecimal number found in fromhex() "
                             f"arg at position {position}")
        digits = [ord(c) for c in string]
    else:
        digits = buffer_items(string)
        if digits is NULL:
            raise TypeError("fromhex() argument must be str or "
                            f"bytes-like, not {fqname(type(string))}")
    items = []
    i = 0
    while i < len(digits):
        if chr(digits[i]) in ' \t\n\r\v\f':
            i += 1
            continue
        top = int(chr(digits[i]), 16) if chr(digits[i]) in HEXDIGITS else -1
        if top < 0:
            raise ValueError("non-hexadecimal number found in fromhex() "
                             f"arg at position {i}")
        if i + 1 == len(digits):
            raise ValueError("fromhex() arg must contain an even number of "
                             "hexadecimal digits")
        bot = int(chr(digits[i + 1]), 16) \
            if chr(digits[i + 1]) in HEXDIGITS else -1
        if bot < 0:
            raise ValueError("non-hexadecimal number found in fromhex() "
                             f"arg at position {i + 1}")
        items.append(top * 16 + bot)
        i += 2
    return items


HEXDIGITS = '0123456789abcdefABCDEF'


@native
def bytes_copy(b: object):
    """An exact bytes copy of b, a bytes (or bytes subclass) instance."""
    return exact(bytes, new_bytes(ob_items(b)))


@native
def bytes_subtype_new(type: 'PyTypeObject *', tmp: object):
    """An instance of type, a subtype of bytes, with the bytes of tmp."""
    return unknown(ob_alloc(type, ob_items(tmp)))


# A bytes_appender is a PyBytesWriter written one byte at a time: a C
# struct.  A function returning one initializes the local it is assigned
# to, in place (bytes_appender_init(&writer, size): 0, or -1 with an
# exception), and the local is passed by address.  Here, a namespace with
# the bytes written (a list of ints) and the room left models it.

@native
def bytes_appender_init(size: Py_ssize_t) -> 'bytes_appender':
    """An appender with room for size bytes."""
    return unknown(types.SimpleNamespace(data=[], room=size))


@native
def bytes_appender_has_room(appender: 'const bytes_appender *') -> int:
    """Whether the buffer has room for one more byte."""
    return appender.room > 0


@native
def bytes_appender_append_unchecked(appender: 'bytes_appender *',
                                    value: 'unsigned char') -> None:
    """Append a byte to a buffer that has room for it."""
    appender.data.append(value)
    appender.room -= 1


@native
def bytes_appender_append(appender: 'bytes_appender *',
                          value: 'unsigned char') -> int:
    """Append a byte, growing the buffer first when it is full."""
    if not bytes_appender_has_room(appender):
        if len(appender.data) == PY_SSIZE_T_MAX:
            raise MemoryError()
        appender.room = len(appender.data) + 1
    bytes_appender_append_unchecked(appender, value)
    return 0


@inline
def bytes_appender_append_fast(appender: 'bytes_appender *',
                               value: 'unsigned char') -> int:
    """bytes_appender_append(), in place where the buffer has room.  A
    loop over a sequence the buffer was sized for takes the first path
    without its test (Capacity in libclinic/pyspec/partial_eval.py)."""
    if bytes_appender_has_room(appender):
        return bytes_appender_append_unchecked(appender, value)
    return bytes_appender_append(appender, value)


@native
def bytes_appender_finish(appender: 'bytes_appender *'):
    """The bytes written.  The appender is left empty."""
    data, appender.data = appender.data, None
    return exact(bytes, new_bytes(data))


@native
def bytes_appender_discard(appender: 'bytes_appender *') -> None:
    """Release the buffer of the appender, if it has one."""
    appender.data = None


# ---------------------------------------------------------------------------
# The rest of bytesobject.c and of the stringlib templates it includes, as
# pure Python (@native(facts=False): only the model runs them, see
# Objects/pyspec/README.rst, "Pure Python").  A body works on the bytes
# of an object (ob_items(), a tuple of ints) and makes new objects with
# ob_alloc().

LEFTSTRIP, RIGHTSTRIP, BOTHSTRIP = 0, 1, 2

# The comparison operators of tp_richcompare (Include/object.h).
Py_LT, Py_LE, Py_EQ, Py_NE, Py_GT, Py_GE = range(6)


@native(facts=False)
def new_bytes(items: 'const char *', written: int = False):
    """PyBytes_FromStringAndSize(items, len(items)): the empty bytes, and
    those of one byte, are singletons of the interpreter.  *written*:
    PyBytes_FromStringAndSize(NULL, len(items)), then the items written
    (or a PyBytesWriter): only the empty bytes is the singleton."""
    if len(items) > 1 or written and items:
        return ob_alloc(bytes, items)
    if tuple(items) not in SINGLETONS:
        SINGLETONS[tuple(items)] = ob_alloc(bytes, items)
    return SINGLETONS[tuple(items)]


SINGLETONS = {}

# The constructor of the stringlib templates (Objects/stringlib/pyspec/)
# for bytes: the #define of bytesobject.c.
STRINGLIB_NEW = new_bytes
STRINGLIB_MUTABLE = 0


@native(facts=False)
def bytes_subscript_slice(self: object, item: object):
    """self[item] for a slice item (PySlice_Unpack(): __index__)."""
    start, stop, step = item.indices(len(ob_items(self)))
    items = ob_items(self)[item]
    if not items:
        return new_bytes(())
    if (start == 0 and step == 1 and len(items) == len(ob_items(self))
            and type(self) is bytes):
        return self
    if step == 1:
        return new_bytes(items)
    return ob_alloc(bytes, items)


@native(facts=False)
def return_self(self: object):
    """self if an exact bytes, else an exact bytes copy of it."""
    if type(self) is bytes:
        return self
    return new_bytes(ob_items(self))


@native(facts=False)
def bytes_richcompare(aa: object, bb: object, op: int):
    if not (isinstance(aa, bytes) and isinstance(bb, bytes)):
        if sys.flags.bytes_warning and (op == Py_EQ or op == Py_NE):
            if isinstance(aa, str) or isinstance(bb, str):
                warnings.warn("Comparison between bytes and string",
                              BytesWarning, 1)
            if isinstance(aa, int) or isinstance(bb, int):
                warnings.warn("Comparison between bytes and int",
                              BytesWarning, 1)
        return NotImplemented
    a, b = ob_items(aa), ob_items(bb)
    if aa is bb:
        return op in (Py_EQ, Py_LE, Py_GE)
    if op == Py_EQ:
        return a == b
    if op == Py_NE:
        return a != b
    # memcmp() of the common part, then the lengths.
    return [a < b, a <= b, None, None, a > b, a >= b][op]


@native(facts=False)
def _PyBytes_Concat(a: object, b: object):
    va, vb = buffer_items(a), buffer_items(b)
    if va is NULL or vb is NULL:
        raise TypeError(f"can't concat {tp_name(type(b))} to "
                        f"{tp_name(type(a))}")
    if not va and type(b) is bytes:
        return b
    if not vb and type(a) is bytes:
        return a
    return new_bytes(va + vb, written=True)


@native(facts=False)
def _PyBytes_Repeat(self: object, n: Py_ssize_t):
    s = ob_items(self)
    if n < 0:
        n = 0
    if n > 0 and len(s) > PY_SSIZE_T_MAX // n:
        raise OverflowError("repeated bytes are too long")
    if len(s) * n == len(s) and type(self) is bytes:
        return self
    return ob_alloc(bytes, s * n)


@native(facts=False)
def do_argstrip(self: 'PyBytesObject *', striptype: int, sepobj: object):
    """do_xstrip() with the bytes of the buffer of sepobj, do_strip()
    (ASCII whitespace) for None."""
    s = ob_items(self)
    chars = SPACE if sepobj is None else frozenset(getbuffer(sepobj))
    i = 0
    if striptype != RIGHTSTRIP:
        while i < len(s) and s[i] in chars:
            i += 1
    j = len(s)
    if striptype != LEFTSTRIP:
        while j > i and s[j - 1] in chars:
            j -= 1
    if i == 0 and j == len(s) and type(self) is bytes:
        return self
    return new_bytes(s[i:j])


@native(facts=False)
def stringlib_bytes_join(sep: object, iterable: object):
    # PySequence_Fast()
    if type(iterable) is list or type(iterable) is tuple:
        seq = iterable
    else:
        try:
            it = iter(iterable)
        except TypeError:
            raise TypeError("can only join an iterable") from None
        seq = list(it)
    if not seq:
        return new_bytes(())
    if len(seq) == 1 and type(seq[0]) is bytes:
        return seq[0]
    parts = []
    for i, item in enumerate(seq):
        items = buffer_items(item)
        if items is NULL:
            raise TypeError(f"sequence item {i}: expected a bytes-like "
                            f"object, {tp_name(type(item))[:80]} found")
        parts.append(items)
    result = []
    for i, items in enumerate(parts):
        if i:
            result.extend(ob_items(sep))
        result.extend(items)
    return new_bytes(result, written=True)


@native(facts=False)
def stringlib_partition(str_obj: object, str: 'const char *',
                        sep_obj: object, sep: 'const char *'):
    if not sep:
        raise ValueError("empty separator")
    pos = stringlib_find(str, sep, 0, len(str))
    if pos < 0:
        return (str_obj, new_bytes(()), new_bytes(()))
    return (new_bytes(str[:pos]), sep_obj,
            new_bytes(str[pos + len(sep):]))


@native(facts=False)
def stringlib_rpartition(str_obj: object, str: 'const char *',
                         sep_obj: object, sep: 'const char *'):
    if not sep:
        raise ValueError("empty separator")
    pos = stringlib_rfind(str, sep, 0, len(str))
    if pos < 0:
        return (new_bytes(()), new_bytes(()), str_obj)
    return (new_bytes(str[:pos]), sep_obj,
            new_bytes(str[pos + len(sep):]))


@native(facts=False)
def stringlib_split_whitespace(str_obj: object, str: 'const char *',
                               maxcount: Py_ssize_t):
    result = []
    i = 0
    while maxcount > 0:
        maxcount -= 1
        while i < len(str) and str[i] in SPACE:
            i += 1
        if i == len(str):
            break
        j = i
        while i < len(str) and str[i] not in SPACE:
            i += 1
        if j == 0 and i == len(str) and type(str_obj) is bytes:
            return [str_obj]
        result.append(new_bytes(str[j:i]))
    while i < len(str) and str[i] in SPACE:
        i += 1
    if i < len(str):
        result.append(new_bytes(str[i:]))
    return result


@native(facts=False)
def stringlib_rsplit_whitespace(str_obj: object, str: 'const char *',
                                maxcount: Py_ssize_t):
    result = []
    i = len(str)
    while maxcount > 0:
        maxcount -= 1
        while i > 0 and str[i - 1] in SPACE:
            i -= 1
        if i == 0:
            break
        j = i
        while i > 0 and str[i - 1] not in SPACE:
            i -= 1
        if j == len(str) and i == 0 and type(str_obj) is bytes:
            return [str_obj]
        result.append(new_bytes(str[i:j]))
    while i > 0 and str[i - 1] in SPACE:
        i -= 1
    if i > 0:
        result.append(new_bytes(str[:i]))
    result.reverse()
    return result


@native(facts=False)
def stringlib_split(str_obj: object, str: 'const char *',
                    sep: 'const char *', maxcount: Py_ssize_t):
    if not sep:
        raise ValueError("empty separator")
    result = []
    i = 0
    while maxcount > 0:
        maxcount -= 1
        pos = stringlib_find(str, sep, i, len(str))
        if pos < 0:
            break
        result.append(new_bytes(str[i:pos]))
        i = pos + len(sep)
    if not result and type(str_obj) is bytes:
        return [str_obj]
    result.append(new_bytes(str[i:]))
    return result


@native(facts=False)
def stringlib_rsplit(str_obj: object, str: 'const char *',
                     sep: 'const char *', maxcount: Py_ssize_t):
    if not sep:
        raise ValueError("empty separator")
    result = []
    j = len(str)
    while maxcount > 0:
        maxcount -= 1
        pos = stringlib_rfind(str, sep, 0, j)
        if pos < 0:
            break
        result.append(new_bytes(str[pos + len(sep):j]))
        j = pos
    if not result and type(str_obj) is bytes:
        return [str_obj]
    result.append(new_bytes(str[:j]))
    result.reverse()
    return result


@native(facts=False)
def stringlib_splitlines(str_obj: object, str: 'const char *',
                         keepends: int):
    result = []
    i = j = 0
    while i < len(str):
        while i < len(str) and str[i] not in (10, 13):
            i += 1
        eol = i
        if i < len(str):
            if str[i] == 13 and i + 1 < len(str) and str[i + 1] == 10:
                i += 2
            else:
                i += 1
            if keepends:
                eol = i
        if j == 0 and eol == len(str) and type(str_obj) is bytes:
            return [str_obj]
        result.append(new_bytes(str[j:eol]))
        j = i
    return result


@native(facts=False)
def stringlib_replace(self: object, old: 'const char *',
                      new: 'const char *', maxcount: Py_ssize_t):
    s = ob_items(self)
    if len(s) < len(old):
        return return_self(self)
    if maxcount < 0:
        maxcount = PY_SSIZE_T_MAX
    elif maxcount == 0:
        return return_self(self)
    if not old:
        if not new:
            return return_self(self)
        # Insert new before each byte and at the end, maxcount times.
        count = min(len(s) + 1, maxcount)
        result = []
        for i in range(count):
            result.extend(new)
            if i < len(s):
                result.append(s[i])
        result.extend(s[count:])
        return new_bytes(result, written=True)
    if stringlib_count(s, old, maxcount) == 0:
        return return_self(self)
    result = []
    i = 0
    while maxcount > 0:
        pos = stringlib_find(s, old, i, len(s))
        if pos < 0:
            break
        result.extend(s[i:pos])
        result.extend(new)
        i = pos + len(old)
        maxcount -= 1
    result.extend(s[i:])
    return new_bytes(result, written=True)


@native(facts=False)
def bytes_translate(self: object, table: object, deletechars: object):
    if isinstance(table, bytes):
        table_chars = ob_items(table)
    elif table is None:
        table_chars = NULL
    else:
        table_chars = getbuffer(table)
    if (256 if table_chars is NULL else len(table_chars)) != 256:
        raise ValueError("translation table must be 256 characters long")
    if deletechars is NULL:
        delete = ()
    elif isinstance(deletechars, bytes):
        delete = ob_items(deletechars)
    else:
        delete = getbuffer(deletechars)
    s = ob_items(self)
    if table_chars is NULL:
        table_chars = tuple(range(256))
    result = [table_chars[c] for c in s if c not in delete]
    if tuple(result) == s and type(self) is bytes:
        return self
    return new_bytes(result)

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

import types

from libclinic.pyspec.runtime import (
    NULL, PY_SSIZE_T_MAX, calls, exact, fqname, inline, isinstance, iter,
    native, runs_python, tp_name, unknown)

# Argument Clinic decorators (no-ops in Python).
from libclinic.pyspec.runtime import permit_long_summary, text_signature
from libclinic.pyspec.runtime import c_name

# The C functions of other files the bodies call.
from Objects.pyspec.abstract import (
    PyNumber_AsSsize_t, PyNumber_AsSsize_t_fast, PyObject_LengthHint_fast)
from Objects.pyspec.typeobject import _PyObject_LookupSpecial
from Objects.pyspec.unicodeobject import PyUnicode_AsEncodedString
from Python.pyspec.errors import PyErr_BadInternalCall

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

    @c_name(METH_NOARGS="bytes_getnewargs")
    def __getnewargs__(self, /):
        ...

    def __bytes__(self):
        """Convert this value to exact type bytes."""
        if type(self) is bytes:
            return self
        return bytes_copy(self)

    capitalize = ctype.B.capitalize

    center = transmogrify.B.center

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
        ...

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
        ...

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
        ...

    expandtabs = transmogrify.B.expandtabs

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
        ...

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
        ...

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
        ...

    isalnum = ctype.B.isalnum

    isalpha = ctype.B.isalpha

    isascii = ctype.B.isascii

    isdigit = ctype.B.isdigit

    islower = ctype.B.islower

    isspace = ctype.B.isspace

    istitle = ctype.B.istitle

    isupper = ctype.B.isupper

    def join(self, iterable_of_bytes: object, /):
        """Concatenate any number of bytes objects.

        The bytes whose method is called is inserted in between each pair.

        The result is returned as a new bytes object.

        Example: b'.'.join([b'ab', b'pq', b'rs']) -> b'ab.pq.rs'.
        """
        ...

    ljust = transmogrify.B.ljust

    lower = ctype.B.lower

    def lstrip(self, bytes: object = None, /):
        """Strip leading bytes contained in the argument.

        If the argument is omitted or None, strip leading  ASCII whitespace.
        """
        ...

    @permit_long_summary
    @staticmethod
    def maketrans(frm: Py_buffer, to: Py_buffer, /):
        """Return a translation table usable for the bytes or bytearray translate method.

        The returned table will be one where each byte in frm is mapped to
        the byte at the same position in to.

        The bytes objects frm and to must be of the same length.
        """
        ...

    def partition(self, sep: Py_buffer, /):
        """Partition the bytes into three parts using the given separator.

        This will search for the separator sep in the bytes.  If the
        separator is found, returns a 3-tuple containing the part before the
        separator, the separator itself, and the part after it.

        If the separator is not found, returns a 3-tuple containing the
        original bytes object and two empty bytes objects.
        """
        ...

    def replace(self, old: Py_buffer, new: Py_buffer, /,
                count: Py_ssize_t = -1):
        """Return a copy with all occurrences of substring old replaced by new.

          count
            Maximum number of occurrences to replace.
            -1 (the default value) means replace all occurrences.

        If count is given, only the first count occurrences are replaced.
        If count is not specified or -1, then all occurrences are replaced.
        """
        ...

    @permit_long_summary
    def removeprefix(self, prefix: Py_buffer, /):
        """Return a bytes object with the given prefix string removed if present.

        If the bytes starts with the prefix string, return
        bytes[len(prefix):].  Otherwise, return a copy of the original
        bytes.
        """
        ...

    @permit_long_summary
    def removesuffix(self, suffix: Py_buffer, /):
        """Return a bytes object with the given suffix string removed if present.

        If the bytes ends with the suffix string and that suffix is not
        empty, return bytes[:-len(prefix)].  Otherwise, return a copy of the
        original bytes.
        """
        ...

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
        ...

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
        ...

    rjust = transmogrify.B.rjust

    def rpartition(self, sep: Py_buffer, /):
        """Partition the bytes into three parts using the given separator.

        This will search for the separator sep in the bytes, starting at the
        end.  If the separator is found, returns a 3-tuple containing the
        part before the separator, the separator itself, and the part after
        it.

        If the separator is not found, returns a 3-tuple containing two
        empty bytes objects and the original bytes object.
        """
        ...

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
        ...

    def rstrip(self, bytes: object = None, /):
        """Strip trailing bytes contained in the argument.

        If the argument is omitted or None, strip trailing ASCII whitespace.
        """
        ...

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
        ...

    @permit_long_summary
    def splitlines(self, keepends: bool = False):
        """Return a list of the lines in the bytes, breaking at line boundaries.

        Line breaks are not included in the resulting list unless keepends
        is given and true.
        """
        ...

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
        ...

    def strip(self, bytes: object = None, /):
        """Strip leading and trailing bytes contained in the argument.

        If the argument is omitted or None, strip leading and trailing ASCII
        whitespace.
        """
        ...

    swapcase = ctype.B.swapcase

    title = ctype.B.title

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
        ...

    upper = ctype.B.upper

    zfill = transmogrify.B.zfill

    # -- Slots: C functions with the signature of their slot (see "Methods
    # that are not clinic functions" in libclinic/pyspec/frontend.py).  The
    # C name is bytes_ plus the slot without its prefix (bytes_repr for
    # tp_repr) unless @c_name gives it.

    def __repr__(self, /): ...
    def __hash__(self, /): ...
    def __str__(self, /): ...

    # tp_richcompare: one C function, bytes_richcompare(), for all six.
    def __lt__(self, value, /): ...
    def __le__(self, value, /): ...
    def __eq__(self, value, /): ...
    def __ne__(self, value, /): ...
    def __gt__(self, value, /): ...
    def __ge__(self, value, /): ...

    def __iter__(self, /): ...

    @c_name("bytes_buffer_getbuffer")
    @native
    def __buffer__(self, flags, /):
        return exact(memoryview, memoryview(self))

    # nb_remainder: bytes_mod() for both.
    @c_name("bytes_mod")
    def __mod__(self, value, /): ...
    def __rmod__(self, value, /): ...

    @c_name(mp_length="bytes_length", sq_length="bytes_length")
    @native
    def __len__(self, /):
        return len(bytes(self))

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
            return exact(int, bytes(self)[i])
        if isinstance(key, slice):
            # PySlice_Unpack(): the __index__ of start, stop and step.
            runs_python()
            return exact(bytes, bytes(self)[key])
        raise TypeError("byte indices must be integers or slices, not "
                        f"{tp_name(type(key))}")

    @c_name(sq_concat="_PyBytes_Concat")
    def __add__(self, value, /): ...

    # sq_repeat: _PyBytes_Repeat() for both.
    @c_name(sq_repeat="_PyBytes_Repeat")
    def __mul__(self, value, /): ...
    def __rmul__(self, value, /): ...

    def __contains__(self, key, /): ...


# iter(bytes).  No docstring: tp_doc is NULL.  PyBytesIter_Type, the
# struct (striterobject), its dealloc and traverse are C; the method table
# is striter_methods.
@c_name("striter")
class bytes_iterator:
    @c_name("PyObject_SelfIter")
    def __iter__(self, /): ...

    # Exact ints in range(256) (immortal small ints); NULL without an
    # exception when exhausted (tp_iternext).
    @c_name("striter_next")
    @native
    def __next__(self, /):
        return exact(int)

    @c_name(METH_NOARGS="striter_len")
    def __length_hint__(self, /):
        """Private method returning an estimate of len(list(it))."""
        ...

    @c_name(METH_NOARGS="striter_reduce")
    def __reduce__(self, /):
        """Return state information for pickling."""
        ...

    @c_name(METH_O="striter_setstate")
    def __setstate__(self, state, /):
        """Set state information for unpickling."""
        ...


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
    return exact(bytes, bytes(size))


@native
def _PyBytes_FromBuffer(x: object):
    """A copy of the buffer of x (in C order)."""
    calls(x, "__buffer__")
    calls(x, "__release_buffer__")
    return exact(bytes, memoryview(x).tobytes())


@native
def _PyBytes_FromHex(string: object, use_bytearray: int):
    """The bytes (a bytearray with use_bytearray) of the hexadecimal
    numbers in str or buffer string."""
    if not isinstance(string, str):
        calls(string, "__buffer__")
        calls(string, "__release_buffer__")
    if use_bytearray:
        return exact(bytearray, bytearray.fromhex(string))
    return exact(bytes, bytes.fromhex(string))


@native
def bytes_copy(b: object):
    """An exact bytes copy of b, a bytes (or bytes subclass) instance."""
    return exact(bytes, bytes(memoryview(b)))


@native
def bytes_subtype_new(type: 'PyTypeObject *', tmp: object):
    """An instance of type, a subtype of bytes, with the bytes of tmp."""
    return unknown(bytes.__new__(type, tmp))


# A bytes_appender is a PyBytesWriter written one byte at a time: a C
# struct.  A function returning one initializes the local it is assigned
# to, in place (bytes_appender_init(&writer, size): 0, or -1 with an
# exception), and the local is passed by address.  Here, a namespace with
# the bytes written and the room left models it.

@native
def bytes_appender_init(size: Py_ssize_t) -> 'bytes_appender':
    """An appender with room for size bytes."""
    return unknown(types.SimpleNamespace(data=bytearray(), room=size))


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
    return exact(bytes, bytes(data))


@native
def bytes_appender_discard(appender: 'bytes_appender *') -> None:
    """Release the buffer of the appender, if it has one."""
    appender.data = None

"""The bytearray type, written as Python: the spec of Objects/bytearrayobject.c.

Argument Clinic reads this file while processing bytearrayobject.c (see
Objects/pyspec/README.rst).  Each method of ``class bytearray`` is a
clinic function (parameters, docstring and clinic decorators) with a
one-line block in bytearrayobject.c above its hand-written impl.

A method declared elsewhere is shared, not repeated:

* ``strip = critical_section(bytesobject.bytes.strip)``: bytes.strip's
  parameters, docstring and decorators, and @critical_section; the block
  ``bytearray.strip`` makes it a clinic function of bytearray;
* ``center = critical_section(transmogrify.B.center)``: the C function of
  the stringlib template, which clinic calls from bytearray_center() in a
  critical section on self (no block: bytearray has no impl of its own);
* ``__length_hint__ = c_name(METH_NOARGS="f")(...)``: the docstring of
  another method, with its own hand-written C function f.

The classes are the whole types: ``@static_type`` makes clinic generate
PyByteArray_Type and PyByteArrayIter_Type, their method tables and slot
tables, at the end of Objects/clinic/bytearrayobject_pyspec.c.h.  Dunders
are slots (C functions with the slot's signature, from slotdefs[]).
"""

from typing import final

from libclinic.pyspec.runtime import NULL

# Argument Clinic decorators (no-ops in Python).
from libclinic.pyspec.runtime import (
    critical_section, permit_long_summary, text_signature)
from libclinic.pyspec.runtime import c_name, static_type

# Methods declared by bytes, and by the stringlib templates.
from pyspec import bytesobject
from stringlib.pyspec import ctype, transmogrify


@static_type(
    tp_dealloc="bytearray_dealloc",
    tp_flags="_Py_TPFLAGS_MATCH_SELF",
    tp_alloc="PyType_GenericAlloc",
    tp_new="bytearray_new",
    tp_free="PyObject_Free",
    tp_version_tag="_Py_TYPE_VERSION_BYTEARRAY",
)
class bytearray:
    """bytearray(iterable_of_ints) -> bytearray
    bytearray(string, encoding[, errors]) -> bytearray
    bytearray(bytes_or_buffer) -> mutable copy of bytes_or_buffer
    bytearray(int) -> bytes array of size given by the parameter initialized with null bytes
    bytearray() -> empty bytes array

    Construct a mutable bytearray object from:
      - an iterable yielding integers in range(256)
      - a text string encoded using the specified encoding
      - a bytes or a buffer object
      - any object implementing the buffer API.
      - an integer
    """

    def __init__(
        self,
        source: object(c_param='arg') = NULL,
        encoding: str = NULL,
        errors: str = NULL,
    ):
        ...

    @c_name(METH_NOARGS="bytearray_alloc")
    def __alloc__(self, /):
        """B.__alloc__() -> int

        Return the number of bytes actually allocated.
        """
        ...

    @critical_section
    @c_name("bytearray_reduce")
    def __reduce__(self):
        """Return state information for pickling."""
        ...

    @critical_section
    @c_name("bytearray_reduce_ex")
    def __reduce_ex__(self, proto: int = 0, /):
        """Return state information for pickling."""
        ...

    @c_name("bytearray_sizeof")
    def __sizeof__(self):
        """Returns the size of the bytearray object in memory, in bytes."""
        ...

    @critical_section
    def append(self, item: bytesvalue, /):
        """Append a single item to the end of the bytearray.

          item
            The item to be appended.
        """
        ...

    capitalize = critical_section(ctype.B.capitalize)

    center = critical_section(transmogrify.B.center)

    def clear(self):
        """Remove all items from the bytearray."""
        ...

    @critical_section
    def copy(self):
        """Return a copy of B."""
        ...

    count = critical_section(bytesobject.bytes.count)

    @critical_section
    def decode(
        self,
        encoding: str(c_default="NULL") = 'utf-8',
        errors: str(c_default="NULL") = 'strict',
    ):
        """Decode the bytearray using the codec registered for encoding.

          encoding
            The encoding with which to decode the bytearray.
          errors
            The error handling scheme to use for the handling of decoding
            errors.  The default is 'strict' meaning that decoding errors
            raise a UnicodeDecodeError.  Other possible values are 'ignore'
            and 'replace' as well as any other name registered with
            codecs.register_error that can handle UnicodeDecodeErrors.
        """
        ...

    @permit_long_summary
    @critical_section
    @text_signature("($self, suffix[, start[, end]], /)")
    def endswith(
        self,
        suffix: object(c_param='subobj'),
        start: slice_index(accept={int, NoneType}, c_default='0') = None,
        end: slice_index(accept={int, NoneType}, c_default='PY_SSIZE_T_MAX') = None,
        /,
    ):
        """Return True if the bytearray ends with the specified suffix, False otherwise.

          suffix
            A bytes or a tuple of bytes to try.
          start
            Optional start position. Default: start of the bytearray.
          end
            Optional stop position. Default: end of the bytearray.
        """
        ...

    expandtabs = critical_section(transmogrify.B.expandtabs)

    @permit_long_summary
    @critical_section
    def extend(self, iterable_of_ints: object, /):
        """Append all the items from the iterator or sequence to the end of the bytearray.

          iterable_of_ints
            The iterable of items to append.
        """
        ...

    @permit_long_summary
    @critical_section
    @text_signature("($self, sub[, start[, end]], /)")
    def find(
        self,
        sub: object,
        start: slice_index(accept={int, NoneType}, c_default='0') = None,
        end: slice_index(accept={int, NoneType}, c_default='PY_SSIZE_T_MAX') = None,
        /,
    ):
        """Return the lowest index in B where subsection 'sub' is found, such that 'sub' is contained within B[start:end].

          start
            Optional start position. Default: start of the bytes.
          end
            Optional stop position. Default: end of the bytes.

        Return -1 on failure.
        """
        ...

    @classmethod
    def fromhex(cls, string: object, /):
        r"""Create a bytearray object from a string of hexadecimal numbers.

        Spaces between two numbers are accepted.
        Example:
            bytearray.fromhex('B9 01EF') -> bytearray(b'\\xb9\\x01\\xef')
        """
        ...

    @critical_section
    def hex(self, sep: object = NULL, bytes_per_sep: Py_ssize_t = 1):
        """Create a string of hexadecimal numbers from a bytearray object.

          sep
            An optional single character or byte to separate hex bytes.
          bytes_per_sep
            How many bytes between separators.  Positive values count from
            the right, negative values count from the left.

        Example:
        >>> value = bytearray([0xb9, 0x01, 0xef])
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
    @critical_section
    @text_signature("($self, sub[, start[, end]], /)")
    def index(
        self,
        sub: object,
        start: slice_index(accept={int, NoneType}, c_default='0') = None,
        end: slice_index(accept={int, NoneType}, c_default='PY_SSIZE_T_MAX') = None,
        /,
    ):
        """Return the lowest index in B where subsection 'sub' is found, such that 'sub' is contained within B[start:end].

          start
            Optional start position. Default: start of the bytes.
          end
            Optional stop position. Default: end of the bytes.

        Raise ValueError if the subsection is not found.
        """
        ...

    @critical_section
    def insert(self, index: Py_ssize_t, item: bytesvalue, /):
        """Insert a single item into the bytearray before the given index.

          index
            The index where the value is to be inserted.
          item
            The item to be inserted.
        """
        ...

    isalnum = critical_section(ctype.B.isalnum)

    isalpha = critical_section(ctype.B.isalpha)

    isascii = critical_section(ctype.B.isascii)

    isdigit = critical_section(ctype.B.isdigit)

    islower = critical_section(ctype.B.islower)

    isspace = critical_section(ctype.B.isspace)

    istitle = critical_section(ctype.B.istitle)

    isupper = critical_section(ctype.B.isupper)

    @critical_section
    def join(self, iterable_of_bytes: object, /):
        """Concatenate any number of bytes/bytearray objects.

        The bytearray whose method is called is inserted in between each
        pair.

        The result is returned as a new bytearray object.
        """
        ...

    ljust = critical_section(transmogrify.B.ljust)

    lower = critical_section(ctype.B.lower)

    # Not bytes.lstrip, whose docstring has "leading  ASCII" (two spaces).
    @critical_section
    def lstrip(self, bytes: object = None, /):
        """Strip leading bytes contained in the argument.

        If the argument is omitted or None, strip leading ASCII whitespace.
        """
        ...

    maketrans = bytesobject.bytes.maketrans

    @critical_section
    def partition(self, sep: object, /):
        """Partition the bytearray into three parts using the given separator.

        This will search for the separator sep in the bytearray.  If the
        separator is found, returns a 3-tuple containing the part before the
        separator, the separator itself, and the part after it as new
        bytearray objects.

        If the separator is not found, returns a 3-tuple containing the copy
        of the original bytearray object and two empty bytearray objects.
        """
        ...

    @critical_section
    def pop(self, index: Py_ssize_t = -1, /):
        """Remove and return a single item from B.

          index
            The index from where to remove the item.
            -1 (the default value) means remove the last item.

        If no index argument is given, will pop the last item.
        """
        ...

    @critical_section
    def remove(self, value: bytesvalue, /):
        """Remove the first occurrence of a value in the bytearray.

          value
            The value to remove.
        """
        ...

    replace = critical_section(bytesobject.bytes.replace)

    @critical_section
    def removeprefix(self, prefix: Py_buffer, /):
        """Return a bytearray with the given prefix string removed if present.

        If the bytearray starts with the prefix string, return
        bytearray[len(prefix):].  Otherwise, return a copy of the original
        bytearray.
        """
        ...

    @critical_section
    def removesuffix(self, suffix: Py_buffer, /):
        """Return a bytearray with the given suffix string removed if present.

        If the bytearray ends with the suffix string and that suffix is not
        empty, return bytearray[:-len(suffix)].  Otherwise, return a copy of
        the original bytearray.
        """
        ...

    @critical_section
    def resize(self, size: Py_ssize_t, /):
        """Resize the internal buffer of bytearray to len.

          size
            New size to resize to.
        """
        ...

    @critical_section
    def reverse(self):
        """Reverse the order of the values in B in place."""
        ...

    @permit_long_summary
    @critical_section
    @text_signature("($self, sub[, start[, end]], /)")
    def rfind(
        self,
        sub: object,
        start: slice_index(accept={int, NoneType}, c_default='0') = None,
        end: slice_index(accept={int, NoneType}, c_default='PY_SSIZE_T_MAX') = None,
        /,
    ):
        """Return the highest index in B where subsection 'sub' is found, such that 'sub' is contained within B[start:end].

          start
            Optional start position. Default: start of the bytes.
          end
            Optional stop position. Default: end of the bytes.

        Return -1 on failure.
        """
        ...

    @permit_long_summary
    @critical_section
    @text_signature("($self, sub[, start[, end]], /)")
    def rindex(
        self,
        sub: object,
        start: slice_index(accept={int, NoneType}, c_default='0') = None,
        end: slice_index(accept={int, NoneType}, c_default='PY_SSIZE_T_MAX') = None,
        /,
    ):
        """Return the highest index in B where subsection 'sub' is found, such that 'sub' is contained within B[start:end].

          start
            Optional start position. Default: start of the bytes.
          end
            Optional stop position. Default: end of the bytes.

        Raise ValueError if the subsection is not found.
        """
        ...

    rjust = critical_section(transmogrify.B.rjust)

    @critical_section
    def rpartition(self, sep: object, /):
        """Partition the bytearray into three parts using the given separator.

        This will search for the separator sep in the bytearray, starting at
        the end.  If the separator is found, returns a 3-tuple containing
        the part before the separator, the separator itself, and the part
        after it as new bytearray objects.

        If the separator is not found, returns a 3-tuple containing two
        empty bytearray objects and the copy of the original bytearray
        object.
        """
        ...

    @permit_long_summary
    @critical_section
    def rsplit(self, sep: object = None, maxsplit: Py_ssize_t = -1):
        """Return a list of the sections in the bytearray, using sep as the delimiter.

          sep
            The delimiter according which to split the bytearray.
            None (the default value) means split on ASCII whitespace
            characters (space, tab, return, newline, formfeed, vertical tab).
          maxsplit
            Maximum number of splits to do.
            -1 (the default value) means no limit.

        Splitting is done starting at the end of the bytearray and working
        to the front.
        """
        ...

    rstrip = critical_section(bytesobject.bytes.rstrip)

    @permit_long_summary
    @critical_section
    def split(self, sep: object = None, maxsplit: Py_ssize_t = -1):
        """Return a list of the sections in the bytearray, using sep as the delimiter.

          sep
            The delimiter according which to split the bytearray.
            None (the default value) means split on ASCII whitespace
            characters (space, tab, return, newline, formfeed, vertical tab).
          maxsplit
            Maximum number of splits to do.
            -1 (the default value) means no limit.
        """
        ...

    @permit_long_summary
    @critical_section
    def splitlines(self, keepends: bool = False):
        """Return a list of the lines in the bytearray, breaking at line boundaries.

        Line breaks are not included in the resulting list unless keepends
        is given and true.
        """
        ...

    @permit_long_summary
    @critical_section
    @text_signature("($self, prefix[, start[, end]], /)")
    def startswith(
        self,
        prefix: object(c_param='subobj'),
        start: slice_index(accept={int, NoneType}, c_default='0') = None,
        end: slice_index(accept={int, NoneType}, c_default='PY_SSIZE_T_MAX') = None,
        /,
    ):
        """Return True if the bytearray starts with the specified prefix, False otherwise.

          prefix
            A bytes or a tuple of bytes to try.
          start
            Optional start position. Default: start of the bytearray.
          end
            Optional stop position. Default: end of the bytearray.
        """
        ...

    strip = critical_section(bytesobject.bytes.strip)

    swapcase = critical_section(ctype.B.swapcase)

    @critical_section
    def take_bytes(self, n: object = None, /):
        """Take *n* bytes from the bytearray and return them as a bytes object.

          n
            Bytes to take, negative indexes from end. None indicates all bytes.
        """
        ...

    title = critical_section(ctype.B.title)

    translate = critical_section(bytesobject.bytes.translate)

    upper = critical_section(ctype.B.upper)

    zfill = critical_section(transmogrify.B.zfill)

    # -- Slots: C functions with the signature of their slot (see "Methods
    # that are not clinic functions" in libclinic/pyspec/frontend.py).  The
    # C name is bytearray_ plus the slot without its prefix (bytearray_repr
    # for tp_repr) unless @c_name gives it.  No __hash__: PyType_Ready()
    # makes bytearray unhashable (tp_hash is PyObject_HashNotImplemented).

    def __repr__(self, /): ...
    def __str__(self, /): ...

    # tp_richcompare: one C function, bytearray_richcompare(), for all six.
    def __lt__(self, value, /): ...
    def __le__(self, value, /): ...
    def __eq__(self, value, /): ...
    def __ne__(self, value, /): ...
    def __gt__(self, value, /): ...
    def __ge__(self, value, /): ...

    def __iter__(self, /): ...

    # The buffer (bytearray_getbuffer) and its release: exports forbid
    # resizing.
    def __buffer__(self, flags, /): ...
    def __release_buffer__(self, buffer, /): ...

    # nb_remainder: bytearray_mod() for both.
    @c_name("bytearray_mod")
    def __mod__(self, value, /): ...
    def __rmod__(self, value, /): ...

    @c_name(mp_length="bytearray_length", sq_length="bytearray_length")
    def __len__(self, /): ...

    @c_name(mp_subscript="bytearray_subscript", sq_item="bytearray_getitem")
    def __getitem__(self, key, /): ...

    # mp_ass_subscript and sq_ass_item: one C function each for both.
    @c_name(mp_ass_subscript="bytearray_ass_subscript",
            sq_ass_item="bytearray_setitem")
    def __setitem__(self, key, value, /): ...
    def __delitem__(self, key, /): ...

    @c_name(sq_concat="PyByteArray_Concat")
    def __add__(self, value, /): ...

    # sq_repeat: bytearray_repeat() for both.
    @c_name(sq_repeat="bytearray_repeat")
    def __mul__(self, value, /): ...
    def __rmul__(self, value, /): ...

    def __contains__(self, key, /): ...

    @c_name(sq_inplace_concat="bytearray_iconcat")
    def __iadd__(self, value, /): ...

    @c_name(sq_inplace_repeat="bytearray_irepeat")
    def __imul__(self, value, /): ...


# iter(bytearray).  No docstring: tp_doc is NULL.  The struct
# (bytesiterobject), its dealloc, traverse and next are C.
@final
@static_type(tp_dealloc="bytearrayiter_dealloc",
             tp_traverse="bytearrayiter_traverse")
class bytearray_iterator:
    @c_name("PyObject_SelfIter")
    def __iter__(self, /): ...

    @c_name("bytearrayiter_next")
    def __next__(self, /): ...

    __length_hint__ = c_name(METH_NOARGS="bytearrayiter_length_hint")(
        bytesobject.bytes_iterator.__length_hint__)

    # The docstring (and text signature) of bytearray.__reduce__.
    __reduce__ = c_name(METH_NOARGS="bytearrayiter_reduce")(
        bytearray.__reduce__)

    __setstate__ = c_name(METH_O="bytearrayiter_setstate")(
        bytesobject.bytes_iterator.__setstate__)

"""The bytearray type, written as Python: the spec of Objects/bytearrayobject.c.

Argument Clinic reads this file while processing bytearrayobject.c (see
Objects/pyspec/README.rst).  Each method of ``class bytearray`` is a
clinic function (parameters, docstring and clinic decorators) with a
one-line block in bytearrayobject.c above its hand-written impl
(``@ac.stub``).

A method declared elsewhere is shared, not repeated:

* ``strip = ac.critical_section(bytesobject.bytes.strip)``: bytes.strip's
  parameters, docstring and decorators, and @critical_section; the block
  ``bytearray.strip`` makes it a clinic function of bytearray;
* ``center = ac.stub("stringlib_center", critical_section=True)``: the
  C function of the stringlib template (transmogrify.h, which
  bytearrayobject.c includes; clinic reads its signature and docstring
  from the C), which clinic calls from bytearray_center() in a critical
  section on self (no block: bytearray has no impl of its own);
* ``__length_hint__ = ac.stub(METH_NOARGS="f")(...)``: the docstring of
  another method, with its own hand-written C function f.

The classes are the whole types (``@ac.generate``): clinic generates
their docstring, method tables and slot tables at the end of
Objects/clinic/bytearrayobject_pyspec.c.h, which PyByteArray_Type and
PyByteArrayIter_Type (in C) name.  Dunders are slots (C functions with the
slot's signature, from slotdefs[]).
"""

# Argument Clinic (converters, decorators) and the primitives with a C
# meaning (rt.NULL).
from libclinic.pyspec import ac, rt

# Methods declared by bytes.
from Objects.pyspec import bytesobject

@ac.generate
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

    @ac.stub
    def __init__(
        self,
        source: ac.object(c_param='arg') = rt.NULL,
        encoding: ac.str = rt.NULL,
        errors: ac.str = rt.NULL,
    ):
        ...

    @ac.stub(METH_NOARGS="bytearray_alloc")
    def __alloc__(self, /):
        """B.__alloc__() -> int

        Return the number of bytes actually allocated.
        """
        ...

    @ac.critical_section
    @ac.stub("bytearray_reduce")
    def __reduce__(self):
        """Return state information for pickling."""
        ...

    @ac.critical_section
    @ac.stub("bytearray_reduce_ex")
    def __reduce_ex__(self, proto: ac.int = 0, /):
        """Return state information for pickling."""
        ...

    @ac.stub("bytearray_sizeof")
    def __sizeof__(self):
        """Returns the size of the bytearray object in memory, in bytes."""
        ...

    @ac.stub
    @ac.critical_section
    def append(self, item: ac.bytesvalue, /):
        """Append a single item to the end of the bytearray.

          item
            The item to be appended.
        """
        ...

    capitalize = ac.stub("stringlib_capitalize", critical_section=True)

    center = ac.stub("stringlib_center", critical_section=True)

    @ac.stub
    def clear(self):
        """Remove all items from the bytearray."""
        ...

    @ac.stub
    @ac.critical_section
    def copy(self):
        """Return a copy of B."""
        ...

    count = ac.critical_section(bytesobject.bytes.count)

    @ac.stub
    @ac.critical_section
    def decode(
        self,
        encoding: ac.str(c_default="NULL") = 'utf-8',
        errors: ac.str(c_default="NULL") = 'strict',
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

    @ac.stub
    @ac.permit_long_summary
    @ac.critical_section
    @ac.text_signature("($self, suffix[, start[, end]], /)")
    def endswith(
        self,
        suffix: ac.object(c_param='subobj'),
        start: ac.slice_index(accept={int, ac.NoneType}, c_default='0') = None,
        end: ac.slice_index(accept={int, ac.NoneType}, c_default='PY_SSIZE_T_MAX') = None,
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

    expandtabs = ac.stub("stringlib_expandtabs", critical_section=True)

    @ac.stub
    @ac.permit_long_summary
    @ac.critical_section
    def extend(self, iterable_of_ints: ac.object, /):
        """Append all the items from the iterator or sequence to the end of the bytearray.

          iterable_of_ints
            The iterable of items to append.
        """
        ...

    @ac.stub
    @ac.permit_long_summary
    @ac.critical_section
    @ac.text_signature("($self, sub[, start[, end]], /)")
    def find(
        self,
        sub: ac.object,
        start: ac.slice_index(accept={int, ac.NoneType}, c_default='0') = None,
        end: ac.slice_index(accept={int, ac.NoneType}, c_default='PY_SSIZE_T_MAX') = None,
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

    @ac.stub
    @classmethod
    def fromhex(cls, string: ac.object, /):
        r"""Create a bytearray object from a string of hexadecimal numbers.

        Spaces between two numbers are accepted.
        Example:
            bytearray.fromhex('B9 01EF') -> bytearray(b'\\xb9\\x01\\xef')
        """
        ...

    @ac.stub
    @ac.critical_section
    def hex(self, sep: ac.object = rt.NULL, bytes_per_sep: ac.Py_ssize_t = 1):
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

    @ac.stub
    @ac.permit_long_summary
    @ac.critical_section
    @ac.text_signature("($self, sub[, start[, end]], /)")
    def index(
        self,
        sub: ac.object,
        start: ac.slice_index(accept={int, ac.NoneType}, c_default='0') = None,
        end: ac.slice_index(accept={int, ac.NoneType}, c_default='PY_SSIZE_T_MAX') = None,
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

    @ac.stub
    @ac.critical_section
    def insert(self, index: ac.Py_ssize_t, item: ac.bytesvalue, /):
        """Insert a single item into the bytearray before the given index.

          index
            The index where the value is to be inserted.
          item
            The item to be inserted.
        """
        ...

    isalnum = ac.stub("stringlib_isalnum", critical_section=True)

    isalpha = ac.stub("stringlib_isalpha", critical_section=True)

    isascii = ac.stub("stringlib_isascii", critical_section=True)

    isdigit = ac.stub("stringlib_isdigit", critical_section=True)

    islower = ac.stub("stringlib_islower", critical_section=True)

    isspace = ac.stub("stringlib_isspace", critical_section=True)

    istitle = ac.stub("stringlib_istitle", critical_section=True)

    isupper = ac.stub("stringlib_isupper", critical_section=True)

    @ac.stub
    @ac.critical_section
    def join(self, iterable_of_bytes: ac.object, /):
        """Concatenate any number of bytes/bytearray objects.

        The bytearray whose method is called is inserted in between each
        pair.

        The result is returned as a new bytearray object.
        """
        ...

    ljust = ac.stub("stringlib_ljust", critical_section=True)

    lower = ac.stub("stringlib_lower", critical_section=True)

    # Not bytes.lstrip, whose docstring has "leading  ASCII" (two spaces).
    @ac.stub
    @ac.critical_section
    def lstrip(self, bytes: ac.object = None, /):
        """Strip leading bytes contained in the argument.

        If the argument is omitted or None, strip leading ASCII whitespace.
        """
        ...

    maketrans = bytesobject.bytes.maketrans

    @ac.stub
    @ac.critical_section
    def partition(self, sep: ac.object, /):
        """Partition the bytearray into three parts using the given separator.

        This will search for the separator sep in the bytearray.  If the
        separator is found, returns a 3-tuple containing the part before the
        separator, the separator itself, and the part after it as new
        bytearray objects.

        If the separator is not found, returns a 3-tuple containing the copy
        of the original bytearray object and two empty bytearray objects.
        """
        ...

    @ac.stub
    @ac.critical_section
    def pop(self, index: ac.Py_ssize_t = -1, /):
        """Remove and return a single item from B.

          index
            The index from where to remove the item.
            -1 (the default value) means remove the last item.

        If no index argument is given, will pop the last item.
        """
        ...

    @ac.stub
    @ac.critical_section
    def remove(self, value: ac.bytesvalue, /):
        """Remove the first occurrence of a value in the bytearray.

          value
            The value to remove.
        """
        ...

    replace = ac.critical_section(bytesobject.bytes.replace)

    @ac.stub
    @ac.critical_section
    def removeprefix(self, prefix: ac.Py_buffer, /):
        """Return a bytearray with the given prefix string removed if present.

        If the bytearray starts with the prefix string, return
        bytearray[len(prefix):].  Otherwise, return a copy of the original
        bytearray.
        """
        ...

    @ac.stub
    @ac.critical_section
    def removesuffix(self, suffix: ac.Py_buffer, /):
        """Return a bytearray with the given suffix string removed if present.

        If the bytearray ends with the suffix string and that suffix is not
        empty, return bytearray[:-len(suffix)].  Otherwise, return a copy of
        the original bytearray.
        """
        ...

    @ac.stub
    @ac.critical_section
    def resize(self, size: ac.Py_ssize_t, /):
        """Resize the internal buffer of bytearray to len.

          size
            New size to resize to.
        """
        ...

    @ac.stub
    @ac.critical_section
    def reverse(self):
        """Reverse the order of the values in B in place."""
        ...

    @ac.stub
    @ac.permit_long_summary
    @ac.critical_section
    @ac.text_signature("($self, sub[, start[, end]], /)")
    def rfind(
        self,
        sub: ac.object,
        start: ac.slice_index(accept={int, ac.NoneType}, c_default='0') = None,
        end: ac.slice_index(accept={int, ac.NoneType}, c_default='PY_SSIZE_T_MAX') = None,
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

    @ac.stub
    @ac.permit_long_summary
    @ac.critical_section
    @ac.text_signature("($self, sub[, start[, end]], /)")
    def rindex(
        self,
        sub: ac.object,
        start: ac.slice_index(accept={int, ac.NoneType}, c_default='0') = None,
        end: ac.slice_index(accept={int, ac.NoneType}, c_default='PY_SSIZE_T_MAX') = None,
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

    rjust = ac.stub("stringlib_rjust", critical_section=True)

    @ac.stub
    @ac.critical_section
    def rpartition(self, sep: ac.object, /):
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

    @ac.stub
    @ac.permit_long_summary
    @ac.critical_section
    def rsplit(self, sep: ac.object = None, maxsplit: ac.Py_ssize_t = -1):
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

    rstrip = ac.critical_section(bytesobject.bytes.rstrip)

    @ac.stub
    @ac.permit_long_summary
    @ac.critical_section
    def split(self, sep: ac.object = None, maxsplit: ac.Py_ssize_t = -1):
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

    @ac.stub
    @ac.permit_long_summary
    @ac.critical_section
    def splitlines(self, keepends: ac.bool = False):
        """Return a list of the lines in the bytearray, breaking at line boundaries.

        Line breaks are not included in the resulting list unless keepends
        is given and true.
        """
        ...

    @ac.stub
    @ac.permit_long_summary
    @ac.critical_section
    @ac.text_signature("($self, prefix[, start[, end]], /)")
    def startswith(
        self,
        prefix: ac.object(c_param='subobj'),
        start: ac.slice_index(accept={int, ac.NoneType}, c_default='0') = None,
        end: ac.slice_index(accept={int, ac.NoneType}, c_default='PY_SSIZE_T_MAX') = None,
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

    strip = ac.critical_section(bytesobject.bytes.strip)

    swapcase = ac.stub("stringlib_swapcase", critical_section=True)

    @ac.stub
    @ac.critical_section
    def take_bytes(self, n: ac.object = None, /):
        """Take *n* bytes from the bytearray and return them as a bytes object.

          n
            Bytes to take, negative indexes from end. None indicates all bytes.
        """
        ...

    title = ac.stub("stringlib_title", critical_section=True)

    translate = ac.critical_section(bytesobject.bytes.translate)

    upper = ac.stub("stringlib_upper", critical_section=True)

    zfill = ac.stub("stringlib_zfill", critical_section=True)

    # -- Slots: C functions with the signature of their slot (see "Methods
    # that are not clinic functions" in libclinic/pyspec/frontend.py).  The
    # C name is bytearray_ plus the slot without its prefix (bytearray_repr
    # for tp_repr) unless @ac.stub gives it.  No __hash__: PyType_Ready()
    # makes bytearray unhashable (tp_hash is PyObject_HashNotImplemented).

    @ac.stub
    def __repr__(self, /): ...
    @ac.stub
    def __str__(self, /): ...

    # tp_richcompare: one C function, bytearray_richcompare(), for all six.
    @ac.stub
    def __lt__(self, value, /): ...
    @ac.stub
    def __le__(self, value, /): ...
    @ac.stub
    def __eq__(self, value, /): ...
    @ac.stub
    def __ne__(self, value, /): ...
    @ac.stub
    def __gt__(self, value, /): ...
    @ac.stub
    def __ge__(self, value, /): ...

    @ac.stub
    def __iter__(self, /): ...

    # The buffer (bytearray_getbuffer) and its release: exports forbid
    # resizing.
    @ac.stub
    def __buffer__(self, flags, /): ...
    @ac.stub
    def __release_buffer__(self, buffer, /): ...

    # nb_remainder: bytearray_mod() for both.
    @ac.stub("bytearray_mod")
    def __mod__(self, value, /): ...
    @ac.stub
    def __rmod__(self, value, /): ...

    @ac.stub(slots=["mp_length", "sq_length"])
    def __len__(self, /): ...

    @ac.stub(slots=["mp_subscript"], sq_item="bytearray_getitem")
    def __getitem__(self, key, /): ...

    # mp_ass_subscript and sq_ass_item: one C function each for both.
    @ac.stub(slots=["mp_ass_subscript"], sq_ass_item="bytearray_setitem")
    def __setitem__(self, key, value, /): ...
    @ac.stub
    def __delitem__(self, key, /): ...

    @ac.stub(sq_concat="PyByteArray_Concat")
    def __add__(self, value, /): ...

    # sq_repeat: bytearray_repeat() for both.
    @ac.stub(slots=["sq_repeat"])
    def __mul__(self, value, /): ...
    @ac.stub
    def __rmul__(self, value, /): ...

    @ac.stub
    def __contains__(self, key, /): ...

    @ac.stub(sq_inplace_concat="bytearray_iconcat")
    def __iadd__(self, value, /): ...

    @ac.stub(sq_inplace_repeat="bytearray_irepeat")
    def __imul__(self, value, /): ...


# iter(bytearray).  No docstring: tp_doc is NULL.  PyByteArrayIter_Type,
# the struct (bytesiterobject), its dealloc, traverse, __iter__
# (PyObject_SelfIter) and __next__ are C; the method table is
# bytearrayiter_methods.
@ac.generate(prefix="bytearrayiter")
class bytearray_iterator:
    @ac.stub
    def __iter__(self, /): ...
    @ac.stub
    def __next__(self, /): ...

    __length_hint__ = ac.stub(METH_NOARGS="bytearrayiter_length_hint")(
        bytesobject.bytes_iterator.__length_hint__)

    # The docstring (and text signature) of bytearray.__reduce__.
    __reduce__ = ac.stub(METH_NOARGS="bytearrayiter_reduce")(
        bytearray.__reduce__)

    __setstate__ = ac.stub(METH_O="bytearrayiter_setstate")(
        bytesobject.bytes_iterator.__setstate__)

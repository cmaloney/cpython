"""The bytes type, written as Python: the spec of Objects/bytesobject.c.

Argument Clinic reads this file while processing bytesobject.c (see
Tools/clinic/libclinic/pyspec/).  Each method of ``class bytes`` is a
clinic function (parameters, docstring and clinic decorators);
bytesobject.c has no block for them, only the ``class bytes`` directive.
Methods with a body of ``...`` are implemented in C by hand: bytesobject.c
defines their bytes_<name>_impl(), declared in
Objects/clinic/bytesobject.c.h.  bytes.__new__ is implemented here: clinic generates bytes_new_impl()
and, for its vectorcall, bytes_new_nargsN() -- the method partially
evaluated for exactly bytes and N positional arguments -- into
Objects/clinic/bytesobject_pyspec.c.h.  Top-level functions are C
functions of the same name.

Lib/test/test_clinic.py runs this file as Python and compares it with the
interpreter's bytes().
"""

from libclinic.pyspec.runtime import (
    NULL, C, isinstance, iter, fqname, tp_name)

# Argument Clinic decorators (no-ops in Python).
from libclinic.pyspec.runtime import permit_long_summary, text_signature


class bytes:
    def __new__(
        cls,
        source: object(c_name='x') = NULL,
        encoding: str = NULL,
        errors: str = NULL,
    ):
        if cls is not bytes:
            value = bytes.__new__(bytes, source, encoding, errors)
            return C.bytes_subtype_new(cls, value)
        if source is NULL:
            if encoding is not NULL:
                raise TypeError("encoding without a string argument")
            if errors is not NULL:
                raise TypeError("errors without a string argument")
            return b""
        if encoding is not NULL:
            if not isinstance(source, str):
                raise TypeError("encoding without a string argument")
            return C.PyUnicode_AsEncodedString(source, encoding, errors)
        if errors is not NULL:
            if isinstance(source, str):
                raise TypeError("string argument without an encoding")
            raise TypeError("errors without a string argument")
        # We'd like to call PyObject_Bytes here, but we need to check for an
        # integer argument before deferring to PyBytes_FromObject, something
        # PyObject_Bytes doesn't do.
        if (func := C.lookup_special(source, "__bytes__")) is not NULL:
            result = func()
            if not isinstance(result, bytes):
                raise TypeError(f"{fqname(type(source))}.__bytes__() must return "
                                f"a bytes, not {fqname(type(result))}")
            return result
        if isinstance(source, str):
            raise TypeError("string argument without an encoding")
        # Is it an integer?
        if hasattr(type(source), "__index__"):
            try:
                size = C.PyNumber_AsSsize_t(source, OverflowError)
            except TypeError:
                return PyBytes_FromObject(source)
            if size < 0:
                raise ValueError("negative count")
            return C._PyBytes_FromSize(size, True)
        return PyBytes_FromObject(source)

    def __bytes__(self):
        """Convert this value to exact type bytes."""
        if type(self) is bytes:
            return self
        return C.bytes_copy(self)

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

    def partition(self, sep: Py_buffer, /):
        """Partition the bytes into three parts using the given separator.

        This will search for the separator sep in the bytes.  If the
        separator is found, returns a 3-tuple containing the part before the
        separator, the separator itself, and the part after it.

        If the separator is not found, returns a 3-tuple containing the
        original bytes object and two empty bytes objects.
        """
        ...

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

    rsplit = permit_long_summary(split)
    """Return a list of the sections in the bytes, using sep as the delimiter.

    Splitting is done starting at the end of the bytes and working to
    the front.
    """

    def join(self, iterable_of_bytes: object, /):
        """Concatenate any number of bytes objects.

        The bytes whose method is called is inserted in between each pair.

        The result is returned as a new bytes object.

        Example: b'.'.join([b'ab', b'pq', b'rs']) -> b'ab.pq.rs'.
        """
        ...

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

    index = permit_long_summary(find)
    """Return the lowest index in B where subsection 'sub' is found, such that 'sub' is contained within B[start,end].

    Raise ValueError if the subsection is not found.
    """

    rfind = permit_long_summary(find)
    """Return the highest index in B where subsection 'sub' is found, such that 'sub' is contained within B[start,end].

    Return -1 on failure.
    """

    rindex = permit_long_summary(find)
    """Return the highest index in B where subsection 'sub' is found, such that 'sub' is contained within B[start,end].

    Raise ValueError if the subsection is not found.
    """

    def strip(self, bytes: object = None, /):
        """Strip leading and trailing bytes contained in the argument.

        If the argument is omitted or None, strip leading and trailing ASCII
        whitespace.
        """
        ...

    def lstrip(self, bytes: object = None, /):
        """Strip leading bytes contained in the argument.

        If the argument is omitted or None, strip leading  ASCII whitespace.
        """
        ...

    def rstrip(self, bytes: object = None, /):
        """Strip trailing bytes contained in the argument.

        If the argument is omitted or None, strip trailing ASCII whitespace.
        """
        ...

    count = permit_long_summary(find)
    """Return the number of non-overlapping occurrences of subsection 'sub' in bytes B[start:end]."""

    @permit_long_summary
    def translate(
        self,
        table: object,
        /,
        delete: object(c_name='deletechars', c_default="NULL") = b'',
    ):
        """Return a copy with each character mapped by the given translation table.

          table
            Translation table, which must be a bytes object of length 256.

        All characters occurring in the optional argument delete are
        removed.  The remaining characters are mapped through the given
        translation table.
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
    @text_signature("($self, prefix[, start[, end]], /)")
    def startswith(
        self,
        prefix: object(c_name='subobj'),
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

    @permit_long_summary
    @text_signature("($self, suffix[, start[, end]], /)")
    def endswith(
        self,
        suffix: object(c_name='subobj'),
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
    def splitlines(self, keepends: bool = False):
        """Return a list of the lines in the bytes, breaking at line boundaries.

        Line breaks are not included in the resulting list unless keepends
        is given and true.
        """
        ...

    @classmethod
    def fromhex(cls, string: object, /):
        r"""Create a bytes object from a string of hexadecimal numbers.

        Spaces between two numbers are accepted.
        Example: bytes.fromhex('B9 01EF') -> b'\\xb9\\x01\\xef'.
        """
        result = C.bytes_from_hex(string)
        if cls is not bytes:
            return cls(result)
        return result

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


def PyBytes_FromObject(x: object):
    r"""Return the bytes representation of object *o* that implements the buffer
    protocol.

    .. note::
       If the object implements the buffer protocol, then the buffer
       must not be mutated while the bytes object is being created.
    """
    if x is NULL:
        raise C.PyErr_BadInternalCall()
    if type(x) is bytes:
        return x
    # Use the modern buffer interface
    if hasattr(type(x), "__buffer__"):
        return C._PyBytes_FromBuffer(x)
    # Argument Clinic specializes the iteration for an exact list or
    # tuple: an index loop, without an iterator (see partial_eval.py).
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
    size = C.PyObject_LengthHint(x, 64)
    writer = C.bytes_appender(size)
    for item in it:
        value = C.PyNumber_AsSsize_t(item, NULL)
        if value < 0 or value >= 256:
            raise ValueError("bytes must be in range(0, 256)")
        C.bytes_appender_append(writer, value)
    return C.bytes_appender_finish(writer)


# ---------------------------------------------------------------------------
# C API catalog
#
# One entry per C API function defined in Objects/bytesobject.c (public
# PyBytes_* / PyBytesWriter_* and internal _PyBytes_* / _Py_bytes_*):
# its C signature, reference ownership, error convention and whether it
# may run Python code, written with the facts vocabulary of
# Tools/clinic/libclinic/pyspec/runtime.py.  Body ``...`` means the C
# function is written by hand (a stub: never lowered to C); PyBytes_FromObject
# above has a real body, so its facts are derived from it and not repeated
# here.  Parameter names and docstrings are the ones of Doc/c-api/bytes.rst
# (the future single source for the docs and Doc/data/refcounts.dat); stable
# ABI membership is read from Misc/stable_abi.toml, not repeated.
# Lib/test/test_capi/test_pyspec_catalog.py compares all of this with the
# headers, the C definitions, the docs, refcounts.dat and the stable ABI data
# (see Tools/clinic/libclinic/pyspec/capi.py).

from libclinic.pyspec.runtime import (  # noqa: E402
    InOut, New, NoError, NullIn, OnError, Out, Py_ssize_t, RunsPython,
    Steals, char_p, const_void_p, cstr, pointer, va_list, void_p)

PyBytesWriter_p = pointer('PyBytesWriter')


def PyBytes_FromStringAndSize(v: cstr, len: Py_ssize_t) -> New[object]:
    r"""Return a new bytes object with a copy of the string *v* as value and length
    *len* on success, and ``NULL`` on failure.  If *v* is ``NULL``, the contents of
    the bytes object are uninitialized.

    .. soft-deprecated:: 3.15
       Use the :c:type:`PyBytesWriter` API instead of
       ``PyBytes_FromStringAndSize(NULL, len)``.
    """
    ...


def PyBytes_FromString(v: cstr) -> New[object]:
    r"""Return a new bytes object with a copy of the string *v* as value on success,
    and ``NULL`` on failure.  The parameter *v* must not be ``NULL``; it will not be
    checked.
    """
    ...


def PyBytes_FromFormatV(format: cstr, vargs: va_list) -> New[object]:
    r"""Identical to :c:func:`PyBytes_FromFormat` except that it takes exactly two
    arguments.
    """
    ...


def PyBytes_FromFormat(format: cstr, *args: ...) -> New[object]:
    r"""Take a C :c:func:`printf`\ -style *format* string and a variable number of
    arguments, calculate the size of the resulting Python bytes object and return
    a bytes object with the values formatted into it.  The variable arguments
    must be C types and must correspond exactly to the format characters in the
    *format* string.  The following format characters are allowed:

    .. % XXX: This should be exactly the same as the table in PyErr_Format.
    .. % One should just refer to the other.

    .. tabularcolumns:: |l|l|L|

    +-------------------+---------------+--------------------------------+
    | Format Characters | Type          | Comment                        |
    +===================+===============+================================+
    | ``%%``            | *n/a*         | The literal % character.       |
    +-------------------+---------------+--------------------------------+
    | ``%c``            | int           | A single byte,                 |
    |                   |               | represented as a C int.        |
    +-------------------+---------------+--------------------------------+
    | ``%d``            | int           | Equivalent to                  |
    |                   |               | ``printf("%d")``. [1]_         |
    +-------------------+---------------+--------------------------------+
    | ``%u``            | unsigned int  | Equivalent to                  |
    |                   |               | ``printf("%u")``. [1]_         |
    +-------------------+---------------+--------------------------------+
    | ``%ld``           | long          | Equivalent to                  |
    |                   |               | ``printf("%ld")``. [1]_        |
    +-------------------+---------------+--------------------------------+
    | ``%lu``           | unsigned long | Equivalent to                  |
    |                   |               | ``printf("%lu")``. [1]_        |
    +-------------------+---------------+--------------------------------+
    | ``%zd``           | :c:type:`\    | Equivalent to                  |
    |                   | Py_ssize_t`   | ``printf("%zd")``. [1]_        |
    +-------------------+---------------+--------------------------------+
    | ``%zu``           | size_t        | Equivalent to                  |
    |                   |               | ``printf("%zu")``. [1]_        |
    +-------------------+---------------+--------------------------------+
    | ``%i``            | int           | Equivalent to                  |
    |                   |               | ``printf("%i")``. [1]_         |
    +-------------------+---------------+--------------------------------+
    | ``%x``            | int           | Equivalent to                  |
    |                   |               | ``printf("%x")``. [1]_         |
    +-------------------+---------------+--------------------------------+
    | ``%s``            | const char\*  | A null-terminated C character  |
    |                   |               | array.                         |
    +-------------------+---------------+--------------------------------+
    | ``%p``            | const void\*  | The hex representation of a C  |
    |                   |               | pointer. Mostly equivalent to  |
    |                   |               | ``printf("%p")`` except that   |
    |                   |               | it is guaranteed to start with |
    |                   |               | the literal ``0x`` regardless  |
    |                   |               | of what the platform's         |
    |                   |               | ``printf`` yields.             |
    +-------------------+---------------+--------------------------------+

    An unrecognized format character causes all the rest of the format string to be
    copied as-is to the result object, and any extra arguments discarded.

    .. [1] For integer specifiers (d, u, ld, lu, zd, zu, i, x): the 0-conversion
       flag has effect even when a precision is given.
    """
    ...


def _PyBytes_FormatEx(
        format: cstr,
        format_len: Py_ssize_t,
        args: object,
        use_bytearray: int
) -> RunsPython[New[object]]:
    ...


def _PyBytes_DecodeEscape2(
        s: cstr,
        len: Py_ssize_t,
        errors: cstr,
        first_invalid_escape_char: Out[int],
        first_invalid_escape_ptr: Out[cstr]
) -> New[object]:
    ...


def PyBytes_DecodeEscape(
        s: cstr,
        len: Py_ssize_t,
        errors: cstr,
        unicode: Py_ssize_t,
        recode_encoding: cstr
) -> RunsPython[New[object]]:
    r"""Unescape a backslash-escaped string *s*. *s* must not be ``NULL``.
    *len* must be the size of *s*.

    *errors* must be one of ``"strict"``, ``"replace"``, or ``"ignore"``. If
    *errors* is ``NULL``, then ``"strict"`` is used by default.

    On success, this function returns a :term:`strong reference` to a Python
    :class:`bytes` object containing the unescaped string. On failure, this
    function returns ``NULL`` with an exception set.

    .. versionchanged:: 3.9
       *unicode* and *recode_encoding* are now unused.
    """
    ...


def PyBytes_Size(o: object) -> OnError[Py_ssize_t, -1]:
    r"""Return the length of the bytes in bytes object *o*.
    """
    ...


def PyBytes_AsString(o: object) -> OnError[char_p, NULL]:
    r"""Return a pointer to the contents of *o*.  The pointer
    refers to the internal buffer of *o*, which consists of ``len(o) + 1``
    bytes.  The last byte in the buffer is always null, regardless of
    whether there are any other null bytes.  The data must not be
    modified in any way, unless the object was just created using
    ``PyBytes_FromStringAndSize(NULL, size)``. It must not be deallocated.  If
    *o* is not a bytes object at all, :c:func:`PyBytes_AsString` returns ``NULL``
    and raises :exc:`TypeError`.
    """
    ...


def PyBytes_AsStringAndSize(
        obj: object,
        buffer: Out[char_p],
        length: Out[Py_ssize_t]
) -> OnError[int, -1]:
    r"""Return the null-terminated contents of the object *obj*
    through the output variables *buffer* and *length*.
    Returns ``0`` on success.

    If *length* is ``NULL``, the bytes object
    may not contain embedded null bytes;
    if it does, the function returns ``-1`` and a :exc:`ValueError` is raised.

    The buffer refers to an internal buffer of *obj*, which includes an
    additional null byte at the end (not counted in *length*).  The data
    must not be modified in any way, unless the object was just created using
    ``PyBytes_FromStringAndSize(NULL, size)``.  It must not be deallocated.  If
    *obj* is not a bytes object at all, :c:func:`PyBytes_AsStringAndSize`
    returns ``-1`` and raises :exc:`TypeError`.

    .. versionchanged:: 3.5
       Previously, :exc:`TypeError` was raised when embedded null bytes were
       encountered in the bytes object.
    """
    ...


def _PyBytes_Find(
        haystack: cstr,
        len_haystack: Py_ssize_t,
        needle: cstr,
        len_needle: Py_ssize_t,
        offset: Py_ssize_t
) -> NoError[Py_ssize_t]:
    ...


def _PyBytes_ReverseFind(
        haystack: cstr,
        len_haystack: Py_ssize_t,
        needle: cstr,
        len_needle: Py_ssize_t,
        offset: Py_ssize_t
) -> NoError[Py_ssize_t]:
    ...


def PyBytes_Repr(bytes: object, smartquotes: int) -> New[object]:
    r"""Get the string representation of *bytes*. This function is currently used to
    implement :meth:`!bytes.__repr__` in Python.

    This function does not do type checking; it is undefined behavior to pass
    *bytes* as a non-bytes object or ``NULL``.

    If *smartquotes* is true, the representation will use a double-quoted string
    instead of single-quoted string when single-quotes are present in *bytes*.
    For example, the byte string ``'Python'`` would be represented as
    ``b"'Python'"`` when *smartquotes* is true, or ``b'\'Python\''`` when it is
    false.

    On success, this function returns a :term:`strong reference` to a
    :class:`str` object containing the representation. On failure, this
    returns ``NULL`` with an exception set.
    """
    ...


def _Py_bytes_repr(
        data: cstr,
        length: Py_ssize_t,
        smartquotes: int,
        classname: cstr
) -> New[object]:
    ...


def _PyBytes_Concat(a: object, b: object) -> RunsPython[New[object]]:
    ...


def _PyBytes_Repeat(self: object, n: Py_ssize_t) -> New[object]:
    ...


def PyBytes_Join(sep: object, iterable: object) -> RunsPython[New[object]]:
    r"""Similar to ``sep.join(iterable)`` in Python.

    *sep* must be Python :class:`bytes` object.
    (Note that :c:func:`PyUnicode_Join` accepts ``NULL`` separator and treats
    it as a space, whereas :c:func:`PyBytes_Join` doesn't accept ``NULL``
    separator.)

    *iterable* must be an iterable object yielding objects that implement the
    :ref:`buffer protocol <bufferobjects>`.

    On success, return a new :class:`bytes` object.
    On error, set an exception and return ``NULL``.

    .. versionadded:: 3.14

    .. note::
       If *iterable* objects implement the buffer protocol, then the buffers
       must not be mutated while the new bytes object is being created.
    """
    ...


def _PyBytes_FromHex(string: object, use_bytearray: int
                     ) -> RunsPython[New[object]]:
    ...


def _PyBytes_CheckOverflow(
        self: object,
        addr: void_p,
        type_name: cstr
) -> None:
    ...


def PyBytes_Concat(bytes: InOut[object], newpart: object
                   ) -> RunsPython[OnError[None, NullIn('bytes')]]:
    r"""Create a new bytes object in *\*bytes* containing the contents of *newpart*
    appended to *bytes*; the caller will own the new reference.
    The reference to the old value of *bytes* will be ":term:`stolen <steal>`".
    If the new object cannot be created, the old reference to *bytes* will still
    be "stolen", the value of *\*bytes* will be set to ``NULL``, and
    the appropriate exception will be set.

    .. note::
       If *newpart* implements the buffer protocol, then the buffer
       must not be mutated while the new bytes object is being created.
    """
    ...


def PyBytes_ConcatAndDel(bytes: InOut[object], newpart: Steals[object]
                         ) -> RunsPython[OnError[None, NullIn('bytes')]]:
    r"""Create a new bytes object in *\*bytes* containing the contents of *newpart*
    appended to *bytes*.  This version releases the :term:`strong reference`
    to *newpart* (i.e. decrements its reference count).

    .. note::
       If *newpart* implements the buffer protocol, then the buffer
       must not be mutated while the new bytes object is being created.
    """
    ...


def _PyBytes_IsMutable(self: object) -> NoError[int]:
    ...


def _PyBytes_ResizeKeepOnError(
        pv: InOut[object],
        newsize: Py_ssize_t
) -> OnError[int, -1]:
    ...


def _PyBytes_Resize(
        bytes: InOut[object],
        newsize: Py_ssize_t
) -> OnError[int, -1, NullIn('bytes')]:
    r"""Resize a bytes object. *newsize* will be the new length of the bytes object.
    You can think of it as creating a new bytes object and destroying the old
    one, only more efficiently.

    Pass the address of an
    existing bytes object as an lvalue (it may be written into), and the new size
    desired.  On success, *\*bytes* holds the resized bytes object and ``0`` is
    returned; the address in *\*bytes* may differ from its input value.  If the
    reallocation fails, the original bytes object at *\*bytes* is deallocated,
    *\*bytes* is set to ``NULL``, :exc:`MemoryError` is set, and ``-1`` is
    returned.

    While bytes objects are usually immutable in Python, this special C API
    allows mutating a bytes object in-place. The returned bytes object can still
    be mutated using :c:func:`PyBytes_AsString`; except if *newsize* is
    zero in which case it returns the immutable empty bytes string.

    .. soft-deprecated:: 3.15
       Use the :c:type:`PyBytesWriter` API instead.
    """
    ...


def _PyBytes_RepeatBuffer(
        dest: char_p,
        len_dest: Py_ssize_t,
        src: cstr,
        len_src: Py_ssize_t
) -> None:
    ...


def PyBytesWriter_Create(size: Py_ssize_t
                         ) -> OnError[PyBytesWriter_p, NULL]:
    r"""Create a :c:type:`PyBytesWriter` to write *size* bytes.

    If *size* is greater than zero, allocate *size* bytes, and set the
    writer size to *size*. The caller is responsible to write *size*
    bytes using :c:func:`PyBytesWriter_GetData`.
    This function does not overallocate.

    On error, set an exception and return ``NULL``.

    *size* must be positive or zero.
    """
    ...


def _PyBytesWriter_CreateByteArray(
        size: Py_ssize_t
) -> OnError[PyBytesWriter_p, NULL]:
    ...


def PyBytesWriter_Discard(writer: Steals[PyBytesWriter_p]) -> None:
    r"""Discard a :c:type:`PyBytesWriter` created by :c:func:`PyBytesWriter_Create`.

    Do nothing if *writer* is ``NULL``.

    The writer instance is invalid after the call.
    No API can be called on the writer after :c:func:`PyBytesWriter_Discard`.
    """
    ...


def PyBytesWriter_FinishWithSize(
        writer: Steals[PyBytesWriter_p],
        size: Py_ssize_t
) -> New[object]:
    r"""Similar to :c:func:`PyBytesWriter_Finish`, but resize the writer
    to *size* bytes before creating the :class:`bytes` object.
    """
    ...


def PyBytesWriter_Finish(writer: Steals[PyBytesWriter_p]) -> New[object]:
    r"""Finish a :c:type:`PyBytesWriter` created by
    :c:func:`PyBytesWriter_Create`.

    On success, return a Python :class:`bytes` object.
    On error, set an exception and return ``NULL``.

    The writer instance is invalid after the call in any case.
    No API can be called on the writer after :c:func:`PyBytesWriter_Finish`.
    """
    ...


def PyBytesWriter_FinishWithPointer(
        writer: Steals[PyBytesWriter_p],
        buf: void_p
) -> New[object]:
    r"""Similar to :c:func:`PyBytesWriter_Finish`, but resize the writer
    using *buf* pointer before creating the :class:`bytes` object.

    Set an exception and return ``NULL`` if *buf* pointer is outside the
    internal buffer bounds.

    Function pseudo-code::

        Py_ssize_t size = (char*)buf - (char*)PyBytesWriter_GetData(writer);
        return PyBytesWriter_FinishWithSize(writer, size);
    """
    ...


def PyBytesWriter_GetData(writer: PyBytesWriter_p) -> NoError[void_p]:
    r"""Get the writer data: start of the internal buffer.

    The pointer remains valid until a :c:type:`PyBytesWriter` function other
    than :c:func:`PyBytesWriter_GetData` or :c:func:`PyBytesWriter_GetSize` is
    called on *writer*.

    The function cannot fail.
    """
    ...


def PyBytesWriter_GetSize(writer: PyBytesWriter_p) -> NoError[Py_ssize_t]:
    r"""Get the writer size.

    The function does not invalidate pointers returned by
    :c:func:`PyBytesWriter_GetData`.

    The function cannot fail.
    """
    ...


def PyBytesWriter_Resize(
        writer: PyBytesWriter_p,
        size: Py_ssize_t
) -> OnError[int, -1]:
    r"""Resize the writer to *size* bytes. It can be used to enlarge or to
    shrink the writer.
    This function typically overallocates to achieve amortized performance when
    resizing multiple times.

    Newly allocated bytes are left uninitialized.

    On success, return ``0``.
    On error, set an exception and return ``-1``.

    *size* must be positive or zero.
    """
    ...


def PyBytesWriter_Grow(
        writer: PyBytesWriter_p,
        grow: Py_ssize_t
) -> OnError[int, -1]:
    r"""Resize the writer by adding *grow* bytes to the current writer size.
    This function typically overallocates to achieve amortized performance when
    resizing multiple times.

    Newly allocated bytes are left uninitialized.

    On success, return ``0``.
    On error, set an exception and return ``-1``.

    *grow* can be negative to shrink the writer.
    """
    ...


def PyBytesWriter_GrowAndUpdatePointer(
        writer: PyBytesWriter_p,
        size: Py_ssize_t,
        buf: void_p
) -> OnError[void_p, NULL]:
    r"""Similar to :c:func:`PyBytesWriter_Grow`, but update also the *buf*
    pointer.

    The *buf* pointer is moved if the internal buffer is moved in memory.
    The *buf* relative position within the internal buffer is left
    unchanged.

    On error, set an exception and return ``NULL``.

    *buf* must not be ``NULL``.

    Function pseudo-code::

        Py_ssize_t pos = (char*)buf - (char*)PyBytesWriter_GetData(writer);
        if (PyBytesWriter_Grow(writer, size) < 0) {
            return NULL;
        }
        return (char*)PyBytesWriter_GetData(writer) + pos;
    """
    ...


def PyBytesWriter_WriteBytes(
        writer: PyBytesWriter_p,
        bytes: const_void_p,
        size: Py_ssize_t
) -> OnError[int, -1]:
    r"""Grow the *writer* internal buffer by *size* bytes,
    write *size* bytes of *bytes* at the *writer* end,
    and add *size* to the *writer* size.

    If *size* is equal to ``-1``, call ``strlen(bytes)`` to get the
    string length.

    On success, return ``0``.
    On error, set an exception and return ``-1``.
    """
    ...


def PyBytesWriter_Format(
        writer: PyBytesWriter_p,
        format: cstr,
        *args: ...
) -> OnError[int, -1]:
    r"""Similar to :c:func:`PyBytes_FromFormat`, but write the output directly at
    the writer end. Grow the writer internal buffer on demand. Then add the
    written size to the writer size.

    On success, return ``0``.
    On error, set an exception and return ``-1``.
    """
    ...


# ---------------------------------------------------------------------------
# Escapes
#
# The C functions the bodies above call directly, as C.<name>(...) (their C
# call templates are in Tools/clinic/libclinic/pyspec/runtime.py): one stub
# per escape, named like it, with its facts in the vocabulary of the catalog.
# Argument Clinic derives the facts of the bodies from them (the call table
# of the tier-2 optimizer, see call_table.py), and the catalog derives
# whether a body runs Python code.  @helper marks a C function outside the
# C API of bytesobject.c (static, or defined in another file): the catalog
# skips it.  New[bytes] means a new reference to an exact bytes object.

from libclinic.pyspec.runtime import helper  # noqa: E402


def lookup_special(obj: object, name: object
                   ) -> RunsPython[New[object], 'obj']:
    """_PyObject_LookupSpecial(): NULL without an exception if the type of
    obj has no such attribute; calls the __get__ of the attribute found."""
    ...


@helper
def PyUnicode_AsEncodedString(unicode: object, encoding: cstr, errors: cstr
                              ) -> RunsPython[New[object]]:
    """Runs the codec, which may return an instance of a bytes subclass."""
    ...


@helper
def PyNumber_AsSsize_t(o: object, exc: object
                       ) -> RunsPython[OnError[Py_ssize_t, -1], 'o']:
    ...


@helper
def _PyBytes_FromSize(size: Py_ssize_t, use_calloc: int) -> New[bytes]:
    ...


@helper
def _PyBytes_FromBuffer(x: object) -> RunsPython[New[bytes], 'x']:
    ...


@helper
def PyObject_LengthHint(o: object, defaultvalue: Py_ssize_t
                        ) -> RunsPython[OnError[Py_ssize_t, -1], 'o']:
    ...


def bytes_appender(size: Py_ssize_t) -> OnError[int, -1]:
    """bytes_appender_init(): a PyBytesWriter written byte by byte."""
    ...


def bytes_appender_append(appender: pointer('bytes_appender'), value: int
                          ) -> OnError[int, -1]:
    ...


def bytes_appender_finish(appender: pointer('bytes_appender')) -> New[bytes]:
    """PyBytesWriter_FinishWithPointer(): takes over the appender."""
    ...


def bytes_subtype_new(type: pointer('PyTypeObject'), tmp: object
                      ) -> RunsPython[New[object]]:
    """An instance of the subtype."""
    ...


def bytes_copy(b: object) -> New[bytes]:
    """An exact bytes copy of a bytes (or bytes subclass) instance."""
    ...


def bytes_from_hex(string: object) -> RunsPython[New[bytes], 'string']:
    """_PyBytes_FromHex(string, 0): a str, or the buffer of string."""
    ...

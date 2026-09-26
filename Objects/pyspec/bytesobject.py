"""The bytes type, written as Python: the spec of Objects/bytesobject.c.

Argument Clinic reads this file while processing bytesobject.c (see
Tools/clinic/libclinic/pyspec/).  The methods of ``class bytes`` give the
parameters and docstrings of the clinic blocks of bytesobject.c, which only
name the function.  Methods with a body of ``...`` are implemented in C by
hand.  bytes.__new__ is implemented here: clinic generates bytes_new_impl()
and, for its vectorcall, bytes_new_nargsN() -- the method partially
evaluated for exactly bytes and N positional arguments -- into
Objects/clinic/bytesobject_pyspec.c.h.  Top-level functions are C
functions of the same name.

Lib/test/test_clinic.py runs this file as Python and compares it with the
interpreter's bytes().
"""

from libclinic.pyspec.runtime import NULL, C, isinstance, fqname, tp_name

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
        ...

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
    if x is NULL:
        raise C.PyErr_BadInternalCall()
    if type(x) is bytes:
        return x
    # Use the modern buffer interface
    if hasattr(type(x), "__buffer__"):
        return C._PyBytes_FromBuffer(x)
    if type(x) is list or type(x) is tuple:
        with C.critical_section_sequence_fast(x):
            result = C._PyBytes_FromSequence_lock_held(x)
        if result is not NULL:
            return result
    if not isinstance(x, str):
        try:
            it = iter(x)
        except TypeError:
            pass
        else:
            return C._PyBytes_FromIterator(it, x)
    raise TypeError(f"cannot convert '{tp_name(type(x))}' object to bytes")

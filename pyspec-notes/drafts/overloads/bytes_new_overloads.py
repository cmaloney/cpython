"""DRAFT: bytes.__new__ (and PyBytes_FromObject) as overload sets, side by
side with today's if-tree.  Not a spec: check_equivalence.py splices the
OVERLOADS section into a scratch copy of Objects/pyspec/bytesobject.py.

The overload spelling follows typing.overload (typeshed's builtins.pyi
writes bytes.__new__ as three @overload defs + the implementation): a run
of ``@overload def __new__`` then the plain ``def __new__``, whose
signature (the clinic converters) parses the arguments once, and whose
decorators and docstring are the function's.  Unlike typing, each overload
has a body, and ORDER is the dispatch: the first overload that matches
runs (as a type checker picks the first matching overload).  See
overloads.py for the exact rules; in short:

  parameter omitted          -> not passed (NULL)
  ``p`` / ``p: T``           -> passed / passed and a T
  ``p=NULL``                 -> either
  ``Exact[T]``, ``T``, ``SupportsIndex``, ``Buffer``
                             -> type(p) is T, isinstance(p, T),
                                hasattr(type(p), "__index__"/"__buffer__")
  leading ``if C: return NotImplemented``
                             -> a guard: part of the match
  ``return NotImplemented`` elsewhere
                             -> "not me after all": the next overload

Row by row (current if-tree  <->  overload):

  cls is not bytes                         subclass: delegate
  source NULL, encoding                    error overload
  source NULL, errors                      error overload
  source NULL                              bytes() -> b""
  encoding, not str                        error overload (guard)
  encoding                                 bytes(string, encoding[, errors])
  errors, str                              error overload
  errors                                   error overload
  type(source) is bytes                    bytes(bytes) -> itself
  not exact int, __bytes__                 bytes(SupportsBytes) (2 guards)
  str                                      error overload
  __index__ (TypeError -> FromObject)      bytes(int) (NotImplemented)
  else                                     bytes(buffer or iterable)
"""

# ---------------------------------------------------------------------------
# CURRENT (verbatim from Objects/pyspec/bytesobject.py)
# ---------------------------------------------------------------------------

class bytes:

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


# ---------------------------------------------------------------------------
# OVERLOADS (the spec would import:
#     from typing import SupportsIndex, overload
#     from collections.abc import Buffer
#     from libclinic.pyspec.overloads import Exact)
# ---------------------------------------------------------------------------

class bytes:

    # A subclass: the bytes of the same arguments, as an instance of cls.
    @overload
    def __new__(cls, source=NULL, encoding=NULL, errors=NULL):
        if cls is bytes:
            return NotImplemented
        value = bytes.__new__(bytes, source, encoding, errors)
        return bytes_subtype_new(cls, value)

    # No source: only bytes().
    @overload
    def __new__(cls, *, encoding, errors=NULL):
        raise TypeError("encoding without a string argument")

    @overload
    def __new__(cls, *, errors):
        raise TypeError("errors without a string argument")

    @overload
    def __new__(cls):
        """bytes() -> empty bytes object"""
        return b""

    # bytes(string, encoding[, errors]) -> bytes
    @overload
    def __new__(cls, source, encoding, errors=NULL):
        if isinstance(source, str):
            return NotImplemented
        raise TypeError("encoding without a string argument")

    @overload
    def __new__(cls, source: str, encoding, errors=NULL):
        return PyUnicode_AsEncodedString(source, encoding, errors)

    # errors without encoding.
    @overload
    def __new__(cls, source: str, *, errors):
        raise TypeError("string argument without an encoding")

    @overload
    def __new__(cls, source, *, errors):
        raise TypeError("errors without a string argument")

    # One argument.  bytes(bytes_or_buffer) of an exact bytes: itself
    # (bytes.__bytes__ of an exact bytes returns it: no lookup, no call).
    @overload
    def __new__(cls, source: Exact[bytes]):
        return source

    # An object with __bytes__ (typing.SupportsBytes).  We'd like to call
    # PyObject_Bytes here, but an integer must be checked for before
    # PyBytes_FromObject, which PyObject_Bytes doesn't do.
    @overload
    def __new__(cls, source):
        # An exact int has no __bytes__: no lookup (a type-cache probe for
        # every bytes(n) the tier-2 call table does not reach, and Sub(n)).
        if type(source) is int:
            return NotImplemented
        if (func := _PyObject_LookupSpecial(source, "__bytes__")) is NULL:
            return NotImplemented
        result = func()
        if not isinstance(result, bytes):
            raise TypeError(f"{fqname(type(source))}.__bytes__() must "
                            f"return a bytes, not {fqname(type(result))}")
        return result

    @overload
    def __new__(cls, source: str):
        raise TypeError("string argument without an encoding")

    # bytes(int) -> bytes object of size given by the parameter
    # initialized with null bytes
    @overload
    def __new__(cls, source: SupportsIndex):
        try:
            size = PyNumber_AsSsize_t_fast(source, OverflowError)
        except TypeError:
            return NotImplemented   # __index__ said no: not an integer
        if size < 0:
            raise ValueError("negative count")
        return _PyBytes_FromSize(size, True)

    # bytes(iterable_of_ints), bytes(bytes_or_buffer) -> a copy (and the
    # TypeError of anything else).
    @overload
    def __new__(cls, source):
        return PyBytes_FromObject(source)

    # The implementation signature: what the clinic parser binds, once.
    @c_name("bytes_new")
    def __new__(
        cls,
        source: object = NULL,
        encoding: str = NULL,
        errors: str = NULL,
    ):
        ...


@overload
def PyBytes_FromObject():
    raise PyErr_BadInternalCall()


@overload
def PyBytes_FromObject(x: Exact[bytes]):
    return x


# Use the modern buffer interface
@overload
def PyBytes_FromObject(x: Buffer):
    return _PyBytes_FromBuffer(x)


# Argument Clinic specializes the iteration for an exact list or
# tuple: an index loop, without an iterator; a list of compact ints
# is copied atomically, in its critical section (see partial_eval.py).
@overload
def PyBytes_FromObject(x):
    if isinstance(x, str):
        return NotImplemented
    try:
        it = iter(x)
    except TypeError:
        return NotImplemented
    return bytes_from_iterator(it, x)


@overload
def PyBytes_FromObject(x):
    raise TypeError(f"cannot convert '{tp_name(type(x))}' object to bytes")


def PyBytes_FromObject(x: object):
    r"""Return the bytes representation of object *o* that implements the buffer
    protocol.

    .. note::
       If the object implements the buffer protocol, then the buffer
       must not be mutated while the bytes object is being created.
    """
    ...

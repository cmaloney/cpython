"""The C functions of Objects/stringlib/ctype.h, written as Python.

ctype.h is a C template included by bytesobject.c and bytearrayobject.c.
Its functions are PyCFunctions written by hand, not clinic functions; the
spec of a type names one as a method, ``isalnum =
ac.stub("stringlib_isalnum")`` (bytearray: ``ac.stub("stringlib_isalnum",
critical_section=True)``, which clinic calls in a critical section), and
Argument Clinic reads its calling convention from its definition in
ctype.h, ``(PyObject *self, PyObject *Py_UNUSED(ignored))``: METH_NOARGS
(Tools/clinic/libclinic/pyspec/cfunctions.py).

This file is their model and their docstrings (the C has none): each def
is the C function of its name, written by hand (``@ac.stub``), with the
parameters of its calling convention; its docstring is the __doc__ of the
method as is, and its body its pure-Python implementation, which only
the model runs.  Like the C, the defs are a template: B is the class and
STRINGLIB_NEW its constructor from bytes, those of the spec that names
the method (Tools/clinic/libclinic/pyspec/model.py).
"""

from libclinic.pyspec import ac, machine

from Objects.pyspec import bytes_methods


@ac.stub
def stringlib_isspace(self, /):
    """B.isspace() -> bool

    Return True if all characters in B are whitespace
    and there is at least one character in B, False otherwise.
    """
    s = machine.ob_items(self)
    return bytes_methods._Py_bytes_isspace(s, len(s))


@ac.stub
def stringlib_isalpha(self, /):
    """B.isalpha() -> bool

    Return True if all characters in B are alphabetic
    and there is at least one character in B, False otherwise.
    """
    s = machine.ob_items(self)
    return bytes_methods._Py_bytes_isalpha(s, len(s))


@ac.stub
def stringlib_isalnum(self, /):
    """B.isalnum() -> bool

    Return True if all characters in B are alphanumeric
    and there is at least one character in B, False otherwise.
    """
    s = machine.ob_items(self)
    return bytes_methods._Py_bytes_isalnum(s, len(s))


@ac.stub
def stringlib_isascii(self, /):
    """B.isascii() -> bool

    Return True if B is empty or all characters in B are ASCII,
    False otherwise.
    """
    s = machine.ob_items(self)
    return bytes_methods._Py_bytes_isascii(s, len(s))


@ac.stub
def stringlib_isdigit(self, /):
    """B.isdigit() -> bool

    Return True if all characters in B are digits
    and there is at least one character in B, False otherwise.
    """
    s = machine.ob_items(self)
    return bytes_methods._Py_bytes_isdigit(s, len(s))


@ac.stub
def stringlib_islower(self, /):
    """B.islower() -> bool

    Return True if all cased characters in B are lowercase and there is
    at least one cased character in B, False otherwise.
    """
    s = machine.ob_items(self)
    return bytes_methods._Py_bytes_islower(s, len(s))


@ac.stub
def stringlib_isupper(self, /):
    """B.isupper() -> bool

    Return True if all cased characters in B are uppercase and there is
    at least one cased character in B, False otherwise.
    """
    s = machine.ob_items(self)
    return bytes_methods._Py_bytes_isupper(s, len(s))


@ac.stub
def stringlib_istitle(self, /):
    """B.istitle() -> bool

    Return True if B is a titlecased string and there is at least one
    character in B, i.e. uppercase characters may only follow uncased
    characters and lowercase characters only cased ones. Return False
    otherwise.
    """
    s = machine.ob_items(self)
    return bytes_methods._Py_bytes_istitle(s, len(s))


@ac.stub
def stringlib_lower(self, /):
    """B.lower() -> copy of B

    Return a copy of B with all ASCII characters converted to lowercase.
    """
    s = machine.ob_items(self)
    return STRINGLIB_NEW(bytes_methods._Py_bytes_lower(s, len(s)),
                         written=True)


@ac.stub
def stringlib_upper(self, /):
    """B.upper() -> copy of B

    Return a copy of B with all ASCII characters converted to uppercase.
    """
    s = machine.ob_items(self)
    return STRINGLIB_NEW(bytes_methods._Py_bytes_upper(s, len(s)),
                         written=True)


@ac.stub
def stringlib_title(self, /):
    """B.title() -> copy of B

    Return a titlecased version of B, i.e. ASCII words start with
    uppercase characters, all remaining cased characters have lowercase.
    """
    s = machine.ob_items(self)
    return STRINGLIB_NEW(bytes_methods._Py_bytes_title(s, len(s)),
                         written=True)


@ac.stub
def stringlib_capitalize(self, /):
    """B.capitalize() -> copy of B

    Return a copy of B with only its first character capitalized (ASCII)
    and the rest lower-cased.
    """
    s = machine.ob_items(self)
    return STRINGLIB_NEW(bytes_methods._Py_bytes_capitalize(s, len(s)),
                         written=True)


@ac.stub
def stringlib_swapcase(self, /):
    """B.swapcase() -> copy of B

    Return a copy of B with uppercase ASCII characters converted
    to lowercase ASCII and vice versa.
    """
    s = machine.ob_items(self)
    return STRINGLIB_NEW(bytes_methods._Py_bytes_swapcase(s, len(s)),
                         written=True)

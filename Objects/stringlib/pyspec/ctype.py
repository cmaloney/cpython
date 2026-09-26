"""Methods of Objects/stringlib/ctype.h, written as Python.

ctype.h is a C template included by bytesobject.c and bytearrayobject.c;
``class B`` stands for either type.  Its functions are hand-written
PyCFunctions, not clinic functions: ``@c_name(METH_NOARGS="f")`` gives the
C function and its calling convention, and the docstring is the __doc__ of
the method as is.  No clinic runs on ctype.h: the specs of the types
import this module and share its methods with
``isalnum = ctype.B.isalnum``.  The docstrings are also defined in
Objects/bytes_methods.c (_Py_isalnum__doc__, ...), for the types that
have no spec yet.
"""

from libclinic.pyspec.runtime import c_name


class B:
    @c_name(METH_NOARGS="stringlib_isspace")
    def isspace(self, /):
        """B.isspace() -> bool

        Return True if all characters in B are whitespace
        and there is at least one character in B, False otherwise.
        """
        ...

    @c_name(METH_NOARGS="stringlib_isalpha")
    def isalpha(self, /):
        """B.isalpha() -> bool

        Return True if all characters in B are alphabetic
        and there is at least one character in B, False otherwise.
        """
        ...

    @c_name(METH_NOARGS="stringlib_isalnum")
    def isalnum(self, /):
        """B.isalnum() -> bool

        Return True if all characters in B are alphanumeric
        and there is at least one character in B, False otherwise.
        """
        ...

    @c_name(METH_NOARGS="stringlib_isascii")
    def isascii(self, /):
        """B.isascii() -> bool

        Return True if B is empty or all characters in B are ASCII,
        False otherwise.
        """
        ...

    @c_name(METH_NOARGS="stringlib_isdigit")
    def isdigit(self, /):
        """B.isdigit() -> bool

        Return True if all characters in B are digits
        and there is at least one character in B, False otherwise.
        """
        ...

    @c_name(METH_NOARGS="stringlib_islower")
    def islower(self, /):
        """B.islower() -> bool

        Return True if all cased characters in B are lowercase and there is
        at least one cased character in B, False otherwise.
        """
        ...

    @c_name(METH_NOARGS="stringlib_isupper")
    def isupper(self, /):
        """B.isupper() -> bool

        Return True if all cased characters in B are uppercase and there is
        at least one cased character in B, False otherwise.
        """
        ...

    @c_name(METH_NOARGS="stringlib_istitle")
    def istitle(self, /):
        """B.istitle() -> bool

        Return True if B is a titlecased string and there is at least one
        character in B, i.e. uppercase characters may only follow uncased
        characters and lowercase characters only cased ones. Return False
        otherwise.
        """
        ...

    @c_name(METH_NOARGS="stringlib_lower")
    def lower(self, /):
        """B.lower() -> copy of B

        Return a copy of B with all ASCII characters converted to lowercase.
        """
        ...

    @c_name(METH_NOARGS="stringlib_upper")
    def upper(self, /):
        """B.upper() -> copy of B

        Return a copy of B with all ASCII characters converted to uppercase.
        """
        ...

    @c_name(METH_NOARGS="stringlib_title")
    def title(self, /):
        """B.title() -> copy of B

        Return a titlecased version of B, i.e. ASCII words start with
        uppercase characters, all remaining cased characters have lowercase.
        """
        ...

    @c_name(METH_NOARGS="stringlib_capitalize")
    def capitalize(self, /):
        """B.capitalize() -> copy of B

        Return a copy of B with only its first character capitalized (ASCII)
        and the rest lower-cased.
        """
        ...

    @c_name(METH_NOARGS="stringlib_swapcase")
    def swapcase(self, /):
        """B.swapcase() -> copy of B

        Return a copy of B with uppercase ASCII characters converted
        to lowercase ASCII and vice versa.
        """
        ...

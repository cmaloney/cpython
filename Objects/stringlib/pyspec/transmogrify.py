"""Methods of Objects/stringlib/transmogrify.h, written as Python: its spec.

transmogrify.h is a C template included by bytesobject.c and
bytearrayobject.c; clinic class B stands for either type.  Argument Clinic
reads this file while processing transmogrify.h (see
Tools/clinic/libclinic/pyspec/): each method of ``class B`` is a clinic
function, implemented in C by hand.  The specs of the types share these
methods with ``center = transmogrify.B.center``.
"""

from libclinic.pyspec.runtime import c_name, permit_long_summary


class B:
    @c_name("stringlib_expandtabs")
    def expandtabs(self, tabsize: int = 8):
        """Return a copy where all tab characters are expanded using spaces.

        If tabsize is not given, a tab size of 8 characters is assumed.
        """
        ...

    @c_name("stringlib_ljust")
    def ljust(self, width: Py_ssize_t, fillchar: char = b' ', /):
        """Return a left-justified string of length width.

        Padding is done using the specified fill character.
        """
        ...

    @c_name("stringlib_rjust")
    def rjust(self, width: Py_ssize_t, fillchar: char = b' ', /):
        """Return a right-justified string of length width.

        Padding is done using the specified fill character.
        """
        ...

    @c_name("stringlib_center")
    def center(self, width: Py_ssize_t, fillchar: char = b' ', /):
        """Return a centered string of length width.

        Padding is done using the specified fill character.
        """
        ...

    @permit_long_summary
    @c_name("stringlib_zfill")
    def zfill(self, width: Py_ssize_t, /):
        """Pad a numeric string with zeros on the left, to fill a field of the given width.

        The original string is never truncated.
        """
        ...

"""Methods of Objects/stringlib/transmogrify.h, written as Python: its spec.

transmogrify.h is a C template included by bytesobject.c and
bytearrayobject.c; clinic class B stands for either type.  Argument Clinic
reads this file while processing transmogrify.h (see
Objects/pyspec/README.rst): each method of ``class B`` is a clinic
function, implemented in C by hand; its body is its pure-Python
implementation (``@native(facts=False)``, README.rst "Pure Python"),
which only the model runs.  The spec of a type shares these methods
with ``center = transmogrify.B.center``.
"""

from libclinic.pyspec.runtime import (
    PY_SSIZE_T_MAX, c_name, native, permit_long_summary)
from libclinic.pyspec.machine import ob_items


class B:
    @native(facts=False)
    @c_name("stringlib_expandtabs")
    def expandtabs(self, tabsize: int = 8):
        """Return a copy where all tab characters are expanded using spaces.

        If tabsize is not given, a tab size of 8 characters is assumed.
        """
        return stringlib_expandtabs(self, tabsize)

    @native(facts=False)
    @c_name("stringlib_ljust")
    def ljust(self, width: Py_ssize_t, fillchar: char = b' ', /):
        """Return a left-justified string of length width.

        Padding is done using the specified fill character.
        """
        if len(ob_items(self)) >= width:
            return return_self(self)
        return pad(self, 0, width - len(ob_items(self)), fillchar)

    @native(facts=False)
    @c_name("stringlib_rjust")
    def rjust(self, width: Py_ssize_t, fillchar: char = b' ', /):
        """Return a right-justified string of length width.

        Padding is done using the specified fill character.
        """
        if len(ob_items(self)) >= width:
            return return_self(self)
        return pad(self, width - len(ob_items(self)), 0, fillchar)

    @native(facts=False)
    @c_name("stringlib_center")
    def center(self, width: Py_ssize_t, fillchar: char = b' ', /):
        """Return a centered string of length width.

        Padding is done using the specified fill character.
        """
        if len(ob_items(self)) >= width:
            return return_self(self)
        marg = width - len(ob_items(self))
        left = marg // 2 + (marg & width & 1)
        return pad(self, left, marg - left, fillchar)

    @native(facts=False)
    @permit_long_summary
    @c_name("stringlib_zfill")
    def zfill(self, width: Py_ssize_t, /):
        """Pad a numeric string with zeros on the left, to fill a field of the given width.

        The original string is never truncated.
        """
        if len(ob_items(self)) >= width:
            return return_self(self)
        fill = width - len(ob_items(self))
        s = list(ob_items(pad(self, fill, 0, ord('0'))))
        # (The C reads the NUL after the bytes when fill is their length.)
        if fill < len(s) and s[fill] in (ord('+'), ord('-')):
            # Move the sign to the beginning.
            s[0], s[fill] = s[fill], ord('0')
        return STRINGLIB_NEW(s, written=True)


# The static functions of transmogrify.h, pure Python
# (@native(facts=False), see Objects/pyspec/README.rst, "Pure Python").
# Like the C, they are a template: B is the class and STRINGLIB_NEW its
# constructor from bytes, those of the spec that shares the methods
# (Tools/clinic/libclinic/pyspec/model.py).

@native(facts=False)
def return_self(self: object):
    """self if an exact B (immutable: STRINGLIB_MUTABLE is 0), else a
    new B with its bytes."""
    if type(self) is B and not STRINGLIB_MUTABLE:
        return self
    return STRINGLIB_NEW(ob_items(self))


@native(facts=False)
def pad(self: object, left: Py_ssize_t, right: Py_ssize_t, fill: 'char'):
    left = max(left, 0)
    right = max(right, 0)
    if left == 0 and right == 0:
        return return_self(self)
    return STRINGLIB_NEW((fill,) * left + ob_items(self) + (fill,) * right,
                         written=True)


@native(facts=False)
def stringlib_expandtabs(self: object, tabsize: int):
    out = []
    column = 0
    for c in ob_items(self):
        if c == ord('\t'):
            if tabsize > 0:
                incr = tabsize - column % tabsize
                column += incr
                out.extend((ord(' '),) * incr)
        else:
            column += 1
            out.append(c)
            if c in (ord('\n'), ord('\r')):
                column = 0
    if len(out) > PY_SSIZE_T_MAX:
        raise OverflowError("result too long")
    return STRINGLIB_NEW(out, written=True)

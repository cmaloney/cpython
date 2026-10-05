"""The C functions of Objects/stringlib/transmogrify.h, written as Python.

transmogrify.h is a C template included by bytesobject.c and
bytearrayobject.c.  Its methods are clinic functions of transmogrify.h
itself (``B.center as stringlib_center``, with its parameters and
docstring, in C); the spec of a type names the C function,
``center = ac.stub("stringlib_center")``, and Argument Clinic reads the
rest from the C (Tools/clinic/libclinic/pyspec/cfunctions.py).

This file is their model: each def is the C function of its name,
written by hand (``@ac.stub``), with its pure-Python implementation
(Objects/pyspec/README.rst, "Pure Python"), which only the model runs.
A def of a method has the parameters of its clinic function, checked
against the C.  Like the C, the defs are a template: B is the class and
STRINGLIB_NEW its constructor from bytes, those of the spec that names
the method (Tools/clinic/libclinic/pyspec/model.py).
"""

from libclinic.pyspec import ac, rt, machine


@ac.stub
def return_self(self: ac.object):
    """self if an exact B (immutable: STRINGLIB_MUTABLE is 0), else a
    new B with its bytes."""
    if type(self) is B and not STRINGLIB_MUTABLE:
        return self
    return STRINGLIB_NEW(machine.ob_items(self))


@ac.stub
def stringlib_expandtabs(self, /, tabsize=8):
    out = []
    column = 0
    for c in machine.ob_items(self):
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
    if len(out) > rt.PY_SSIZE_T_MAX:
        raise OverflowError("result too long")
    return STRINGLIB_NEW(out, written=True)


@ac.stub
def pad(self: ac.object, left: ac.Py_ssize_t, right: ac.Py_ssize_t,
        fill: 'char'):
    left = max(left, 0)
    right = max(right, 0)
    if left == 0 and right == 0:
        return return_self(self)
    return STRINGLIB_NEW(
        (fill,) * left + machine.ob_items(self) + (fill,) * right,
        written=True)


@ac.stub
def stringlib_ljust(self, width, fillchar=b' ', /):
    if len(machine.ob_items(self)) >= width:
        return return_self(self)
    return pad(self, 0, width - len(machine.ob_items(self)), fillchar)


@ac.stub
def stringlib_rjust(self, width, fillchar=b' ', /):
    if len(machine.ob_items(self)) >= width:
        return return_self(self)
    return pad(self, width - len(machine.ob_items(self)), 0, fillchar)


@ac.stub
def stringlib_center(self, width, fillchar=b' ', /):
    if len(machine.ob_items(self)) >= width:
        return return_self(self)
    marg = width - len(machine.ob_items(self))
    left = marg // 2 + (marg & width & 1)
    return pad(self, left, marg - left, fillchar)


@ac.stub
def stringlib_zfill(self, width, /):
    if len(machine.ob_items(self)) >= width:
        return return_self(self)
    fill = width - len(machine.ob_items(self))
    s = list(machine.ob_items(pad(self, fill, 0, ord('0'))))
    # (The C reads the NUL after the bytes when fill is their length.)
    if fill < len(s) and s[fill] in (ord('+'), ord('-')):
        # Move the sign to the beginning.
        s[0], s[fill] = s[fill], ord('0')
    return STRINGLIB_NEW(s, written=True)

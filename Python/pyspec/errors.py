"""Spec of Python/errors.c: the functions other specs call.

Each is ``@ac.stub(optimizer_info=True)``: the C is the authority; the body
is its Python reference (see Objects/pyspec/README.rst).
"""

from libclinic.pyspec import ac


@ac.stub(optimizer_info=True)
def PyErr_BadInternalCall() -> None:
    """A C API function was called with a bad argument (NULL)."""
    raise SystemError("bad argument to internal function")

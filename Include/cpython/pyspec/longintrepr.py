"""Spec of Include/cpython/longintrepr.h: the functions other specs call.

Each is ``@ac.stub(optimizer_info=True)``: the C is the authority; the body
is its Python reference (see Objects/pyspec/README.rst).
"""

import sys

from libclinic.pyspec import ac


@ac.stub(optimizer_info=True)
def _PyLong_IsCompact(op: 'const PyLongObject *') -> ac.int:
    """Whether op, an int, has at most one digit (PyLong_SHIFT bits: 30,
    or 15 with --enable-big-digits=15)."""
    bound = 1 << sys.int_info.bits_per_digit
    return -bound < op < bound


@ac.stub(optimizer_info=True)
def _PyLong_CompactValue(op: 'const PyLongObject *') -> ac.Py_ssize_t:
    """The value of op, a compact int."""
    return int(op)

"""Test data for Python/pyspec/errors.py (see the docstring of
Objects/pyspec/bytesobject_cases.py for the names)."""

# PyErr_BadInternalCall() fails an assertion in debug builds.
NOT_CALLABLE = {'PyErr_BadInternalCall'}

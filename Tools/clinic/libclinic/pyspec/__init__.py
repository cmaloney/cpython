"""pyspec: Argument Clinic functions described (and implemented) in Python.

For Objects/foo.c, Objects/pyspec/foo.py is its spec (the contributor
guide: Objects/pyspec/README.rst).  Clinic processing foo.c also writes
Objects/clinic/foo_pyspec.c.h, which foo.c includes at its end.

  frontend      reads a spec; completes the one-line clinic blocks
  runtime       the names a spec imports, as Python; runs a spec (tests)
  subset        the lowered subset, checked first; the statement walker
  builtin_types the audited table of builtin types without a spec
  known, marks  facts about names; typed marks on residual nodes
  facts         the facts of statements and of calls of native functions
  partial_eval  folds a spec function for the facts of a call site
  context       the state the passes share, one object per spec
  emit, ir      lowers the implemented functions to the form of ir.py...
  c_backend     ...which it writes as C
  call_table    the call tables of the tier-2 optimizer, and their
                registry (Include/internal/pycore_pyspec.h)
  typeobj       the method and slot tables of the types
  slots         the dunder <-> slot table, from slotdefs[]
  specfiles     every spec of the tree (one glob) and its test data
  disconnects   the ratchet of disagreements between the code and the
                files describing it (Lib/test/test_pyspec_catalog.py)
"""

"""pyspec: Argument Clinic functions described (and implemented) in Python.

For Objects/foo.c, Objects/pyspec/foo.py is its spec:

  frontend      reads the spec; turns a spec method into the clinic input
                of the one-line clinic block naming it in the C file
  runtime       names a spec imports, with their meaning as Python: the
                builtins with a C meaning, @c_implemented and the
                primitives exact(), unknown(), calls(), runs_python();
                load() runs a spec as Python (for tests)
  builtin_types the one table of builtin types without a spec (C type
                objects, checks, constants, audited special methods)
  facts         derives the facts of statements and of the calls of C
                functions from their Python references
  partial_eval  folds a spec function for facts known at a call site
  emit          generates C from the implemented spec functions
  call_table    adds the call table of the tier-2 optimizer to that C
                (Include/internal/pycore_pyspec.h)
  disconnects   where the code and the files describing it by hand
                disagree, per dimension (C API, docs, slots, docstrings,
                typeshed); a ratchet run by Lib/test/test_pyspec_catalog.py
                against Tools/clinic/pyspec-baseline/
  slots         the dunder <-> slot table, read from slotdefs[] in
                Objects/typeobject.c
  typeobj       generates the static type objects of the @static_type
                classes, with their method and slot tables

Argument Clinic uses all of this while processing foo.c: `make clinic`
regenerates Objects/clinic/foo_pyspec.c.h too (the implemented functions
and their call table, then the type objects), which foo.c includes at its
end.  See
Objects/pyspec/README.rst.
"""

"""pyspec: Argument Clinic functions described (and implemented) in Python.

For Objects/foo.c, Objects/pyspec/foo.py is its spec:

  frontend      reads the spec; turns a spec method into the clinic input
                of the one-line clinic block naming it in the C file
  runtime       names a spec imports, with their meaning as Python: the
                builtins with a C meaning, @native, @inline and the
                primitives exact(), unknown(), calls(), runs_python();
                load() runs a spec as Python (for tests)
  subset        the lowered subset: what of a spec is generated as C and
                analysed for facts, checked before partial evaluation;
                the kinds of its statements, and the walker over them
  builtin_types the one table of builtin types without a spec (C type
                objects, checks, constants, audited special methods)
  known, marks  what the passes know about names, and the typed marks
                the partial evaluator puts on the nodes of its result
  facts         derives the facts of statements and of the calls of
                native functions from their Python references (which
                are never compiled)
  partial_eval  folds a spec function for facts known at a call site,
                and generates @inline functions into their callers
  context       the state the passes share, one object per spec
  emit          lowers the implemented spec functions to the form of
                ir, which c_backend writes as C
  call_table    adds the call table of each class for the tier-2
                optimizer to that C, and writes the registry of all of
                them (Include/internal/pycore_pyspec.h)
  specfiles     finds every spec of the tree (one glob) and its test
                data (<stem>_cases.py)
  disconnects   where the code and the files describing it by hand
                disagree, per dimension (C API, docs, slots, docstrings,
                typeshed, and the native code of @native functions, read
                by the checker of its language); a ratchet run by
                Lib/test/test_pyspec_catalog.py against
                Tools/clinic/pyspec-baseline/
  slots         the dunder <-> slot table, read from slotdefs[] in
                Objects/typeobject.c
  typeobj       generates the method and slot tables of the types of
                a spec (their PyTypeObject is written in C)

Argument Clinic uses all of this while processing foo.c: `make clinic`
regenerates Objects/clinic/foo_pyspec.c.h too (the implemented functions
and their call table, then the tables of the types), which foo.c
includes at its end.  See Objects/pyspec/README.rst.
"""

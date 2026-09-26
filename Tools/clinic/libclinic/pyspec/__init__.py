"""pyspec: Argument Clinic functions described (and implemented) in Python.

For Objects/foo.c, Objects/pyspec/foo.py is its spec:

  frontend      reads the spec; turns a spec method into the clinic input
                of the one-line clinic block naming it in the C file
  runtime       names a spec imports, with Python reference implementations,
                and the C API facts vocabulary (New[...], Steals[...], ...);
                load() runs a spec as Python (for tests)
  partial_eval  folds a spec function for facts known at a call site
  emit          generates C from the implemented spec functions
  capi          the C API catalog: checks the facts of the top-level
                functions against headers, docs and ABI data (run by
                Lib/test/test_capi/test_pyspec_catalog.py)

Argument Clinic uses all of this while processing foo.c: `make clinic`
regenerates Objects/clinic/foo_pyspec.c.h too.
"""

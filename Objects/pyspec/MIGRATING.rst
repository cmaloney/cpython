Migrating a C file to a spec
============================

This is how to move the Argument Clinic input of ``Objects/foo.c`` into
its spec ``Objects/pyspec/foo.py``, in small PRs, and how to decide
whether a function's C should become a spec body at all.  What a spec
file contains and how to do each task in it is in `README.rst
<README.rst>`_; this guide does not repeat it.

The model in one paragraph: the spec holds the signatures, docstrings
and clinic decorators of a class's methods, and declares its slots as
dunders.  The ``PyTypeObject`` stays hand-written in ``foo.c``.  Clinic
generates only what comes from the spec: ``<prefix>_doc`` (the class
docstring), ``<prefix>_methods[]`` and the sub-tables
``<prefix>_as_number``, ``_as_sequence``, ``_as_mapping`` and
``_as_buffer``, into ``Objects/clinic/foo_pyspec.c.h``; ``foo.c``
includes that file and then defines the ``PyTypeObject``\ s that name
them.  The prefix is the class name, or the class's ``@c_name``.


Levels of migration
-------------------

Each level is its own PR (but see level 1), one C file (or one class)
per PR.  Don't mix
Tools/clinic changes with a conversion, and don't reorder methods in the
PR that moves them.

=====  =================================  ==============================
Level  What moves                         Parity check (and the review)
=====  =================================  ==============================
1      signatures and docstrings          ``Objects/clinic/foo.c.h``
                                          byte-identical
2      method and slot tables, tp_doc     parity record unchanged
3      function internals (spec bodies)   parity record unchanged,
                                          difftest, ``HelperTest``,
                                          ``c_calls``, "Does a spec
                                          body help" below
4      facts used by the specializer      ``test_opt``,
       or the JIT                         ``test_pyspec_facts`` (debug)
5      C API facts                        ``test_pyspec_catalog``
                                          (the ratchet)
=====  =================================  ==============================

Levels 1 and 2 need no new tooling knowledge beyond Argument Clinic;
level 3 is where the spec language, ``@native`` and ``@inline`` come
in; levels 4 and 5 need a consumer (the optimizer) or a data file (the
docs) and are independent of each other.

Before every PR: regenerate with ``./python Tools/clinic/clinic.py
Objects/foo.c`` (not ``--make`` from a checkout that contains other
worktrees), rebuild, and paste the output of the review (below) into
the PR description.

Validating a change: the review
'''''''''''''''''''''''''''''''

One command answers the reviewer's questions, on a build of the change
(a debug build: it also asserts the facts)::

    ./python Tools/clinic/pyspec_review.py

It takes about 20 seconds, needs no other build, and prints a summary
ready to paste; the exit status is 0 when every answer is fine.  For
example, the whole experiment branch against main, with ``--baseline``
naming a debug build of main (so the record and the ratchet baseline
are new, where a migration PR would leave both unchanged)::

    pyspec review of 63ce50f2c9b against main (merge base ee1bbf037ff), python 3.16 free-threaded=False debug=True pointer=64 platform=linux

    - Behaviour: same as Tools/clinic/pyspec-baseline/parity.txt for bytearray, bytearray_iterator, bytes, bytes_iterator, mmap (87,737 lines in 251 sections)
      - Tools/clinic/pyspec-baseline/parity.txt: new since the base
      - vs ../build-main/python: no difference in 87,737 lines
      - on purpose: bytes /^C tp_vectorcall$/: bytes() is called through the vectorcall the spec generates (differs from the baseline: C tp_vectorcall)
      - (`python Tools/clinic/pyspec_parity.py check`; `... compare ../build-main/python`)
    - Generated code: up to date (clinic --dry-run on 10 C files of specs)
      - Objects/clinic/bytearrayobject_pyspec.c.h: new (384 lines, generated from Objects/pyspec/bytearrayobject.py)
      - Objects/clinic/bytesobject.c.h: +94/-9 lines, in bytes_new_impl, bytes_new, bytes_new_helper, bytes_new_nargs0, bytes_new_nargs1, bytes_new_nargs2, ... (8 names)
        - on purpose (bytes_new_impl, bytes_new, bytes_new_helper, ... (8 names)): bytes.__new__ has a spec body: clinic generates its vectorcall and per-arity entries around the parser
      - Objects/clinic/bytesobject_pyspec.c.h: new (1096 lines, generated from Objects/pyspec/bytesobject.py)
      - every other clinic output: identical to the base
    - Specs vs interpreter: passed, 509 tests (`python -m test test_clinic`: ...)
    - Facts: passed, 21 tests; debug build: facts also asserted at run time (`python -m test test_pyspec_facts`: ...)
    - Ratchet: passed, 12 tests (skipped=1); c_calls 0, capi 20, docs 0, docstrings 2, slots 3 (`python -m test test_pyspec_catalog`: ...)
      - ratchet baseline: +51/-0 lines since the base (added lines are new disconnects: say why)

    Result: OK

The questions, and the command that answers each on its own:

1. *Did any observable behaviour of the spec'd types change?*
   ``./python Tools/clinic/pyspec_parity.py check`` (also run by
   ``test_tools.test_pyspec_parity``): the types against the committed
   record, ``Tools/clinic/pyspec-baseline/parity.txt``.  A section that
   differs is named with the spec line and the clinic block it comes
   from.  The review also says which sections of the record the change
   touched: a migration touches none.
2. *Is the generated code up to date, and which generated files differ
   from main, where and why?*  ``./python Tools/clinic/clinic.py
   --dry-run Objects/foo.c`` says ``would update ...`` when not; the
   review lists every clinic output that differs from the merge base,
   with the C functions whose part changed, and the reason from the
   ``PARITY`` of the type (``NOT EXPLAINED`` otherwise).
3. *Are the facts sound?*  ``./python -m test test_pyspec_facts`` on a
   debug build, where every fact is also asserted when the optimized
   code runs; ``test_clinic`` (``PyspecFilesTest``) runs the spec as
   Python against the interpreter.
4. *Is the ratchet ok?*  ``./python -m test -v test_pyspec_catalog``;
   the review shows the counts and how the baseline files changed since
   the base (only deletions are fine).

``--baseline ../build-main/python`` adds a line-by-line comparison with
a build of the merge base (same configuration) and says whether each
``known`` difference still occurs; ``--base REF`` names the branch the
change goes into (default: ``main``, ``upstream/main`` or
``origin/main``); ``--no-tests`` skips the test modules.

Checking parity with the interpreter before the migration
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''

``Tools/clinic/pyspec_parity.py`` records everything observable about a
type, in sections (the type, its help, its C layout, each attribute,
each protocol):

- the Python surface: ``vars()`` in order, docstrings, text signatures
  and ``help()``;
- the C layout: which slots are set, and whether each is inherited,
  generic or shared; every ``PyMethodDef``'s flags and doc; the members
  and getsets;
- probed calls (about 34,000 lines for ``bytes``): each method at each
  arity, with keywords (keyword-only ones with every pool value), and
  with a pool of argument values for one parameter at a time and for
  each pair of parameters (``encoding`` with ``errors``), on an instance
  and, as fully, on an instance of a subclass.  It keeps the exact
  result, or the exception type and message, any warnings, and what the
  call did to its receiver (the new repr of a mutable one; what an
  iterator yields next, e.g. after ``__setstate__``);
- operators, subscripts, conversions, iteration, hashing, pickling and
  copying of sample instances; ``T[int]``; data descriptors on
  instances, on the type and on other objects.

*The record.*  ``Tools/clinic/pyspec-baseline/parity.txt`` holds, per
build configuration, one line per section: its number of lines and a
digest (about 250 lines per configuration for the five spec'd types, 26
KB for three configurations, instead of 9.6 MB of captured text per
configuration; a
capture takes about 4 seconds).  A change that keeps behaviour leaves
it unchanged, so a reviewer needs no build of main: the test suite
checks the record, and the PR's diff shows it untouched.  The blocks
recorded so far were captured on main (Linux, 64-bit: GIL release, GIL
debug, free-threaded debug; a debug build rejects unknown error
handlers where a release build does not, so each configuration has its
own block); a configuration with no block skips the check.  To see *which* lines of
a section differ, compare with a build of the base::

    ./python Tools/clinic/pyspec_parity.py compare ../build-main/python [bytes]

It prints each differing line before and after, grouped by section,
with the spec line and clinic block responsible (``--all`` for every
line)::

    bytes .decode: 1 of 700 lines differ  [Objects/pyspec/bytesobject.py:144, Objects/bytesobject.c:2343]
        call b'a b'.decode('utf-8', 'ascii')
            before: !LookupError: unknown error handler name 'ascii'
            after:  str 'a b'

If the old build is gone, capture on it first and check later::

    ../build-main/python Tools/clinic/pyspec_parity.py capture list -o list.parity
    ./python Tools/clinic/pyspec_parity.py check list.parity

The same comparison runs in the test suite when
``PYSPEC_PARITY_BASELINE`` names the old python::

    PYSPEC_PARITY_BASELINE=../build-main/python ./python -m test test_tools.test_pyspec_parity

*Migrating the next type* (``list``): record it first, on the tree
before the migration (ideally in a small PR of its own, so that main's
CI checks the record against main):

1. add the class to ``TYPES`` in ``Objects/pyspec/listobject_cases.py``
   and, if needed, its ``PARITY`` (below);
2. ``./python Tools/clinic/pyspec_parity.py check --update`` on a build
   of that tree (once per configuration you can build);
3. migrate; ``check`` must say ``same as ...``, and the PR must not
   touch the record.

A change of behaviour on purpose is either a ``known`` entry of the
type's ``PARITY`` (left out of the record, listed by the review with its
reason) or a ``check --update`` with the reason in the PR.  An unrelated
change on main can change a section too (a docstring inherited from
``object`` in ``help()``, the message of another type's error):
re-record with ``check --update`` and say so.

*What is specific to a type* lives with its data, in the ``PARITY`` of
its ``_cases.py``, keyed by the class names of ``TYPES`` (see
``Objects/pyspec/bytesobject_cases.py``)::

    PARITY = {
        'bytes': {
            'samples': {"b'a b'": lambda: b'a b'},       # instances to probe
            'pool': {"'strict'": lambda: 'strict'},      # more argument values
            'known': {r'^C tp_vectorcall$': 'why'},      # keys of capture lines
            'generated': {r'^bytes_(new|vectorcall)': 'why'},  # C names
        },
    }

A type with no samples is probed on the pool values of exactly its
type, or on ``T()``; an iterator, or a type ``T()`` cannot make, needs
samples.  Both sides of a comparison must be the same Python version
and configuration (debug, free-threaded, pointer size, platform).  Pairs
of parameters are probed on the first sample only, with values from the
pool: a behaviour that only a value outside the pool shows is not
covered.  This checks that nothing changed; the type's own tests
(``test_bytes``, ...) still check that it is right.

Level 1: signatures and docstrings
''''''''''''''''''''''''''''''''''

*Needs:* ``Objects/pyspec/foo.py`` with a ``class`` per clinic class,
one ``def`` per clinic function with the body ``...``, parameters
written as clinic parameter lines (converter as annotation), the
docstring, and the clinic decorators (``@c_name`` for ``as``).  Each
block in ``foo.c`` shrinks to its function line (``bytes.split``).  The
``class`` directives and ``[python input]`` converter blocks stay in
``foo.c``; a spec names a custom converter in its annotation.  A
``TYPES`` entry and an empty ``CASES`` in ``foo_cases.py``.

*Gives:* one place for each signature and docstring, readable as
Python; the docs and typeshed ratchets can compare with it.

*Parity:* ``git diff HEAD~ -- Objects/clinic/foo.c.h`` is empty.  In
``foo.c`` only the blocks and their ``input=`` checksums change.

*A PR of its own:* a class that declares no slot declares its methods
only, so clinic generates no tables for it and the hand-written method
table stays (``Modules/pyspec/mmapmodule.py`` is such a spec).

*Size:* a census of the tree's clinic blocks: ``tupleobject.c`` 4 functions (29 block lines
become 6, spec 29 lines), ``floatobject.c`` 14 (91 to 19, spec 96),
``listobject.c`` 14 (98 to 22, spec 82), ``bytesobject.c`` 26 (267 to
46, spec 205), ``unicodeobject.c`` 49 (409 to 73, spec 372).

Checklist:

- [ ] the class body order is the order of the existing method table;
- [ ] every block of the class is a one-line block (clinic refuses a
  class that is half in the spec);
- [ ] ``Objects/clinic/foo.c.h`` unchanged; ``test_clinic`` passes.

Level 2: method and slot tables
'''''''''''''''''''''''''''''''

*Needs:* the slots as dunders in the class (``def __len__(self, /):
...``, no docstring, the whole richcompare group); declaring a slot is
what makes clinic generate the tables of the class.  ``@c_name`` where
the C name is not the default, and hand-written ``PyCFunction``\ s as
``@c_name(METH_O="f")``.  In ``foo.c``: delete the hand-written
``PyDoc_STRVAR`` of the type, the ``PyMethodDef`` array and the
sub-tables; include ``clinic/foo_pyspec.c.h`` before the
``PyTypeObject``, which keeps its text and names the generated symbols.
The ``PyTypeObject`` itself is not generated.

*Gives:* adding a method or slot is one ``def`` plus its C; nothing to
add to a table by hand.

*Parity:* the parity record unchanged (``pyspec_parity.py check``,
"Validating a change" above): the same attributes, docstrings,
signatures, slots, method table entries and behaviour; ``nm -S
Objects/foo.o`` lists the same table symbols.

*Size:* bytes: about 100 lines of tables and ``PyDoc_STRVAR`` (both
types) become about 45 lines of dunders and a class docstring.

Checklist:

- [ ] parity record unchanged, for every type of the file (iterators
  too, each in ``TYPES``);
- [ ] ``test_clinic`` (slot wrappers vs dunders) passes;
- [ ] accessors (``@getter``/``@setter`` in the class) keep their
  ``tp_getset`` table in C.

Level 3: spec bodies
''''''''''''''''''''

*Needs:* a body in the lowered subset of `README.rst <README.rst>`__
(signature and statements) instead of ``...``; every C function the
body calls declared ``@native``, with its Python reference, in the spec
of its own C file; cases in ``foo_cases.py`` (``CASES`` for the body,
``HELPERS`` for each new native function).

A reference describes its C and nothing more: it is never compiled.  A
fast path the generated code should take (read a compact int inline,
the size of an exact tuple) is an ``@inline`` function next to the C
function (README.rst, "Fast paths: ``@inline``"), never an ``if`` in
the reference that the C does not have.

*Gives:* the C impl is generated; for ``__new__`` also a vectorcall,
per-arity and per-type entries and the tier-2 call table; the logic is
tested as Python (the difftest).  Whether that is worth it is "Does a
spec body help, or just rewrite the C?" below.

*Parity:* ``PyspecFilesTest.test_cases`` (difftest), ``HelperTest``, the
``c_calls`` dimension of ``test_pyspec_catalog``, and the measurements
of "Does a spec body help".  Review the generated ``foo_pyspec.c.h``
like hand-written C (each group of lines names the spec line it comes
from).

*Size:* one function per PR.  The worked example below: spec +35 lines,
hand-written C unchanged in size (the impls become helpers), generated
C +54/-20.

Checklist:

- [ ] the decision of "Does a spec body help" recorded in the PR (numbers, not adjectives);
- [ ] cases cover each branch of the body, errors included;
- [ ] each reference models the exceptions of its C, messages included;
- [ ] each reference describes only its C: no path the C does not have,
  no constant of one build (``sys.int_info.bits_per_digit``, not 30),
  and the native functions it calls are the ones the C calls
  (``c_calls``);
- [ ] a fast path is an ``@inline`` function, measured as in "Performance" below
  where it is taken and where its test runs for nothing.

Level 4: facts for the specializer and the JIT
''''''''''''''''''''''''''''''''''''''''''''''

*Needs:* a consumer.  Today the tier-2 optimizer reads the call table in
``_CALL_BUILTIN_CLASS`` (``tp_new``: ``_PySpec_FindCall()``) and
``_CALL_METHOD_DESCRIPTOR_NOARGS`` (``_PySpec_FindMethod()``), and the
facts of a slot through ``_PySpec_FindSlot()`` (see README.rst, "Give
the optimizer the facts of a slot").  A ``METH_O`` or ``METH_FASTCALL``
method's facts are generated but read by nobody.

*Gives:* removed guards, constant results, alias results (``bytes(b)``
is ``b``), direct calls, "runs no Python" calls.

*Parity:* ``test_opt`` expectations for the new uops; the trace
(``_opcode.get_executor``); ``test_pyspec_facts`` on a debug build,
which asserts the facts at run time and aborts when Python runs where
the facts say it does not.

*Size:* small in ``Python/optimizer_bytecodes.c`` plus regenerated
cases; one fact or uop per PR.

Checklist:

- [ ] the consumer and its test land in the same PR as the fact;
- [ ] ``make regen-cases`` leaves the tree clean;
- [ ] instruction counts with the JIT on show the gain ("Performance" below).

A new type is data only: running clinic on its C file gives each class
with facts its call table and its entry in the registry of
``Include/internal/pycore_pyspec_registry.h``, which the interpreter and the tests
iterate over.  In ``foo_cases.py``:

- [ ] ``TYPES`` names the type of every class; a class with a table that
  is not a builtin type (an iterator) is declared in the C file
  (``class T "..." "&T_Type"``);
- [ ] ``CASES["T.__new__"]`` and ``CASES["T.meth"]`` have inputs for every
  call-table entry (``DirectCallTest`` fails on an entry none reaches);
- [ ] ``HELPERS`` has inputs for every ``@native`` function, or it
  is in ``NOT_CALLABLE`` (static) or ``HELPER_CALLERS`` (hidden: its C
  entry point); an exported or header one also needs its row in
  ``pyspec_helpers`` of ``Modules/_testinternalcapi.c`` (its signature
  is checked against the spec);
- [ ] ``SLOT_USES`` lists each uop that takes the facts of a slot;
  ``FACTS`` pins what the derivation must find;
- [ ] the row of the type in ``builtin_types.py`` (if any) keeps only its
  C names, constants and the facts of the dunders the spec writes as
  ``...`` (``test_clinic`` checks it).

Level 5: C API facts and the disconnect ratchet
'''''''''''''''''''''''''''''''''''''''''''''''

*Needs:* nothing to list: every builtin type described by a class of the
spec of a core C file is checked (``spec_types()`` of
``Tools/clinic/libclinic/pyspec/disconnects.py``: its C file, and its C
API prefixes from its type object).  The first PR records what disagrees
today in ``Tools/clinic/pyspec-baseline/*.txt``; later PRs fix
``Doc/c-api/*.rst``, ``Doc/data/refcounts.dat``,
``Doc/data/threadsafety.dat``, ``Misc/stable_abi.toml`` or the
docstrings, and delete the lines.

*Gives:* every place that describes the C API by hand is checked
against the headers and definitions; the baselines may only shrink.

*Parity:* ``./python -m test test_pyspec_catalog -v`` (prints the count
per dimension).  A new disconnect fails, and so does a fixed one still
listed.

*Size:* one baseline file per PR; fixes grouped by file.

Checklist:

- [ ] baseline lines sorted; no new line without a reason in the PR;
- [ ] fixes to the docs are upstreamable on their own.

Replacing native C by another language (proposed, not implemented)
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

A function that is ``@native`` has a reference, cases in ``HELPERS``
and no line in the ``c_calls`` baseline.  Rewriting its native code in
another language keeps all three: the spec does not change, generated
callers still call it through its C interface, and the same
``HelperTest`` and parity record decide whether behaviour changed.
What that language must bring first is its checker (README.rst,
"Checking a reference against its native code"); no language but C has
one today.


Choosing what to migrate
------------------------

Done: ``bytesobject`` (levels 1 to 5), ``bytearrayobject`` (levels 1,
2 and 5, sharing the stringlib specs), ``mmapmodule`` (level 1, methods
only, with ``#if``).  Order for the rest (by that census): the easy
``Objects`` files first (``interpolationobject``, ``moduleobject``,
``sentinelobject``, ``structseq``, ``descrobject``, ``enumobject``,
``classobject``, ``tupleobject``), then small ones
(``complexobject``, ``rangeobject``, ``funcobject``, ``odictobject``,
``memoryobject``, ``longobject``, ``typeobject``, ``dictobject``,
``floatobject``, ``listobject``, ``exceptions``), then those needing
rules (``codeobject``, ``setobject``, ``unicodeobject``), then Modules.
108 non-test files (1261 functions) use none of the features below.

Features that need care:

``#if`` blocks
    The one-line block stays under its ``#if`` in the C file; build once
    with the condition false to check the generated table.  A name
    defined twice under different ``#if``\ s with different signatures
    (11 names in the tree) cannot be one ``def``: keep that class in
    plain clinic.
Custom converters
    Keep the ``[python input]`` block in the C file, above the first
    block that uses it; the spec names the converter.  A spec *body*
    cannot take one (only ``object`` and ``str``).
Optional groups
    Not supported (41 functions).  Keep the class in plain clinic.
Getters and setters
    Declared in the spec (``@getter``, ``@setter``), their blocks keep
    the decorator; the ``tp_getset`` table stays hand-written.
Shared stringlib code
    Declare the method once in ``Objects/stringlib/pyspec/`` and share
    it (``center = transmogrify.B.center``).  Convert both users (bytes
    and bytearray) in one PR series so the docstring is written once.
Module-level functions
    Not handled: only methods of classes of the spec take their input
    from it.

When not to migrate a function's internals (level 3): when nothing in
"Does a spec body help" comes out positive.  In practice: a method whose call
overhead is a small part of its cost (most ``bytes`` methods: 0 to 8 %,
measured with callgrind); logic that needs ``Py_buffer``, a struct, pointer arithmetic or a
loop over raw memory (it ends up in ``@native`` helpers, so the
C just moves); anything whose fact has no consumer.  Levels 1 and 2
cost no speed and apply to any class without the features above; level
3 only where it pays.


Does a spec body help, or just rewrite the C?
---------------------------------------------

Answer four questions with numbers, then apply the table at the end.
The helper ``Tools/clinic/pyspec_bench.py`` does the measuring.

Performance
'''''''''''

1. **Bound it first.**  The most a change can gain end to end is
   *calls per iteration × saving per call / instructions per
   iteration*.  Count calls of a C function with ``sys.setprofile``
   (``c_call`` events; type calls such as ``bytes(x)`` need a callgrind
   or perf count), and a benchmark's instructions with ``perf stat -e
   instructions:u``.  Example: ``b[i]`` on pyflate, 1.28 M
   subscripts × 84 instructions = 107 M of 4.7 G, at most 2.3 %.  Only
   run pyperformance when the bound is well above its noise: two runs
   of the *same* binary differ by 1 to 2 % and pyperf calls it
   significant.

2. **Build before and after with identical flags**, release (non-PGO is
   fine for instruction counts, and much more reproducible), out of
   tree, plus a second build of the *before* commit::

       mkdir -p ../exp/before
       git archive --prefix=src/ HEAD | tar -x -C ../exp
       cd ../exp/before
       systemd-run --user --scope -q -p MemoryMax=12G -p MemorySwapMax=0 -- \
           sh -c '../src/configure -q CC=clang --enable-experimental-jit \
                  --with-tail-call-interp && make -j8'

   (the memory cap keeps a runaway job from taking the machine down; run
   builds one at a time).  Repeat for ``before2`` (same source) and for
   ``after``.

3. **Measure instructions per iteration** of each affected call shape,
   JIT on and off::

       python Tools/clinic/pyspec_bench.py --cpu 15 \
           -p before=../exp/before/python -p before2=../exp/before2/python \
           -p after=../exp/after/python \
           -s "b = b'abcdefghijklmnop'; p = b'ab'" pass "b.removeprefix(p)"

   Each statement runs in a function loop of N1 and N2 iterations
   under ``perf stat``; the difference divided by N2 - N1 cancels
   startup, warm-up and JIT compilation.  Setup names are fast locals;
   ``pass`` gives the loop alone.  It warns when the interpreters were
   configured differently, and falls back to ``time.perf_counter``
   (much noisier, and says so) when ``perf`` does not work.

4. **Read the A/A pair first.**  ``before`` vs ``before2`` is the noise.
   On non-PGO builds instruction counts of non-allocating shapes are
   identical; allocating ones vary by a few instructions (about 1 %).
   PGO builds of one commit differ by 1 to 3 % on unrelated shapes: do
   not trust a ±1 to 3 % result from a single PGO pair.

5. **Cycles** (``--cycles``) only on a quiet machine, pinned
   (``--cpu``), with the ``performance`` governor.  Tier-1 loop cycles
   move by up to 30 % between builds with identical instructions
   (code layout), so cycles alone never decide.

6. **Code size**: ``size Objects/foo.o`` and the per-function sizes,
   ``nm -S --size-sort Objects/foo.o``, before and after.

Generated C review
''''''''''''''''''

Read ``Objects/clinic/foo_pyspec.c.h`` as if it were a hand-written
patch.  It should have the shape of good C.  The pitfalls found so far
(in migrating bytes):

- a struct passed to or returned from an out-of-line helper, which puts
  it in memory: the appender's cursor spilled to the stack on every
  item of ``bytes(list)`` until the helpers took and returned bare
  pointers;
- an incref and decref per item where the item could be borrowed (it
  can until Python may run);
- the size or item array reloaded on every item of an exact list or
  tuple;
- error checks that cannot fire (``== -1 && PyErr_Occurred()`` after a
  call that cannot fail) instead of a fast path;
- the same loop emitted several times (per caller, per type).

A spec body that measures slower than the C it replaces is a bug to fix
in the emitter, or a reason to stay in C.

Facts
'''''

Diff the call-table entries (the ``_PySpecCall`` arrays at the end of
``foo_pyspec.c.h``) before and after.  For each new or changed fact,
name its consumer (section "Level 4") and show it in a trace or a
``test_opt`` test.  A fact nobody reads is not a win: ``bytes.fromhex``
has derived facts, but ``bytes.fromhex(h)`` stops the trace at the
unspecialized class-method ``LOAD_ATTR``, so they are never used.

Simplification
''''''''''''''

Count, in the PR description:

- hand-written C lines removed, spec lines added (bodies plus helper
  references);
- duplication removed: a hand-written fast path, a second copy of a
  loop, a table of facts, now derived from one body;
- concepts a reader of the file must know that are new (a helper, a
  primitive, a lowering rule) or gone;
- whether behaviour-defining logic is now tested as Python (the
  difftest), and whether it was worth testing that way.

Decision
''''''''

==============================================  ==========================
Outcome                                          Decision
==============================================  ==========================
Measurable gain beyond the A/A noise on a        migrate
shape that matters (bounded end to end), or a
fact with a consumer
Duplication removed or real logic becomes        migrate if performance is
testable as Python, performance neutral          neutral (within noise)
No measurable gain, no consumed fact, no         keep in C
duplication removed
Any shape slower beyond noise                    keep in C until the
                                                 emitter is fixed
==============================================  ==========================

Negative outcomes seen in this experiment:

- ``bytes(list)`` got 28 % *slower* (31.8 against 22.8 instructions per
  item) with the first derived loops, from the pitfalls above, until
  the emitter was fixed; it is now 25 % faster than main.
- ``bytes.fromhex`` facts: derived, never consumed (above).
- Most ``bytes`` methods: call overhead is 0 to 8 % of their cost
  (callgrind), so a generated impl cannot gain more than that.

Worked example: ``bytes.removeprefix``/``removesuffix``
'''''''''''''''''''''''''''''''''''''''''''''''''''''''

The candidate: two methods whose C is a type-dispatch shell around a
``memcmp``.  The spec body::

    def removeprefix(self, prefix: object, /):
        n = bytes_prefix_len(self, prefix)
        if n > 0:
            return bytes_trim(self, n, 0)
        if type(self) is bytes:
            return self
        return bytes_copy(self)

with three ``@native`` helpers in C (``bytes_prefix_len``,
``bytes_suffix_len``, ``bytes_trim``).  The first attempt kept the
parameter ``prefix: Py_buffer`` and clinic refused it (``parameter
'prefix' needs an annotation from ['object', 'str']``), so the buffer
is taken in the helper.  To separate the effect of that converter
change from the spec, a third build keeps the hand-written C with the
``object`` converter (``c_object``).

Builds: release JIT, non-PGO, identical flags (``CC=clang
--enable-experimental-jit --with-tail-call-interp``), clang 22, at
b79959af9ce.  Instructions per iteration including the loop, CPU 15,
``--repeat 5``:

========================  ===  ======  ========  ========  ====  =======
statement                 JIT  before  before2   c_object  spec  spec vs
                                       (A/A)                     before
========================  ===  ======  ========  ========  ====  =======
``pass``                  on   172     172       172       172   0
``b.removeprefix(p)``     on   635     630       624       621   -2.2 %
``b.removeprefix(p)``     off  728     728       727       719   -1.3 %
``b.removeprefix(q)``     on   433     433       426       416   -4.0 %
(no match)
``b.removeprefix(q)``     off  527     527       520       510   -3.2 %
``b.removesuffix(s)``     on   633     627       628       623   -1.5 %
``b.removeprefix(ba)``    on   651     651       645       642   -1.4 %
``sub.removeprefix(q)``   on   1027    1027      1020      1012  -1.5 %
``sub.removeprefix(q)``   off  984     984       976       970   -1.5 %
========================  ===  ======  ========  ========  ====  =======

- *Performance:* at most 17 instructions per call (-0.5 to -4 %).  About
  half comes from the ``object`` converter, which hand-written C gets
  too (``c_object``); the rest (0 to 10 instructions) is within twice
  the A/A spread on the allocating shapes (6 instructions).  No
  pyperformance benchmark calls these methods: the end-to-end bound is
  about 0, so pyperformance was not run.  Code size: ``bytesobject.o``
  text -10 bytes, data +64 bytes (two call-table entries).
- *Generated C:* the shape of the hand-written C; the helpers are
  inlined.  One redundant ``PyErr_Occurred()`` on the error path only.
- *Facts:* two new entries, "result is exactly bytes; may run Python
  code" (the buffer protocol may).  Both are ``METH_O`` methods: no
  consumer.
- *Simplification:* hand-written C -36/+37 lines (the impls became
  helpers), spec +35 lines, generated C +54 lines; no duplication
  removed; three new helpers with references.  The testable logic is a
  three-line type dispatch.  The ratchet and the difftest each found a
  gap (``memcmp`` missing from the audited list of C functions that run
  no Python; the reference's ``TypeError`` message), both in the model,
  not the C.
- *Decision:* **keep in C.**  The experiment was not committed.  The
  converter change alone (``Py_buffer`` to ``object`` plus a hand-written
  buffer acquisition) gives about half the gain without a spec, and is
  a separate, ordinary C change to weigh on its own.


Troubleshooting
---------------

The common messages (the format and the kinds of error are in
README.rst, "Errors"):

``'T.m' has no parameters or docstring, and class T in ... has no method 'm'``
    The class is in the spec, so every block of it needs a ``def``: add
    it, or keep the whole class in plain clinic.
``T.m has no clinic block in foo.c; put this block above its impl``
    Add the one-line block it prints.
``'T.m': @x of a spec method is written in ...`` / ``the C name is written in ... (@c_name)``
    Move the decorator or the ``as`` name from the C block to the spec.
``unknown clinic decorator @x``
    A typo, or a decorator clinic does not have.
``f(): ... is expressible, but not lowered to C yet; see "The lowered subset" ...``
    The signature or the body of a function clinic would generate is
    outside the lowered subset of README.rst: a converter other than
    ``object`` and ``str`` (take ``object`` and convert in a
    ``@native`` helper, see the worked example: that changes the
    generated parser), a default other than ``NULL``, a keyword-only
    parameter, a statement or expression the table does not list
    (assign a call to a local before comparing it).  Or keep the C:
    ``...``, or ``@native`` with the body as its reference.
``unsupported ...`` (the same hint)
    A use the partial evaluation produced that the emitter cannot lower
    yet, e.g. in the body of an ``@inline`` function of another spec
    (reported there).
``f(): 'x = ...' in an @inline function (lowered: fast paths ...)``
    The body of an ``@inline`` function is ``if <test>: return
    <value>`` statements, then ``return <value>``.
``isinstance() is the builtin here, not the C's: import it ...``
    Running as Python, the spec (or a spec it imports) calls the builtin
    ``isinstance()`` or ``iter()``: import them from
    ``libclinic.pyspec.runtime``.
``imported spec ... not found: a spec imports another by its path from the source root``
    Write ``from Objects.pyspec.abstract import ...``, not ``from
    pyspec.abstract import ...``.
``m: use ... as the body of a function implemented in C, not pass``
    Write ``...``.
``the body of a @native function is its Python reference``
    Give the reference a body, or drop ``@native``.
``'T.x' is an accessor in ...: its block starts with @getter or @setter``
    Write ``@getter`` (or ``@setter``) above ``T.x`` in the block.
``conflicting types for 'x_impl'`` (C compiler)
    Rerun clinic; it rewrites the impl head.
``the spec and the interpreter differ`` (``test_clinic``)
    Rebuild the interpreter after regenerating.
A difftest failure on an exception message
    The reference does not model the C's error: raise the same
    exception and message in the reference.
``calls f(), which may run Python code: account for it with runs_python()`` (``test_pyspec_catalog``)
    The C of a ``@native`` helper calls ``f``.  If ``f`` can run
    Python code, add ``calls(x, "__slot__")`` or ``runs_python()`` to
    the reference.  If it cannot (``memcmp``), add it to the audited
    ``NO_PYTHON`` set of ``native_check.py``.  ``f`` may be a call
    through a pointer, named by its expression (``(*fn)``).
``its reference calls f(), which its native code does not`` (``test_pyspec_catalog``)
    The reference says the C calls ``f``; the C (or a function of its
    file it calls) does not.  Correct whichever is wrong.
``New disconnects: fix them (or ... add these lines to ...)``
    Fix the docs or data file; add a baseline line only on purpose.
``Fixed disconnects: delete these lines``
    Delete them: the ratchet only goes down.
``Checksum mismatch!``
    As with plain clinic: someone edited generated code; regenerate
    (``-f`` after checking the diff).

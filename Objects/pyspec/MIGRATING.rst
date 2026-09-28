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
Level  What moves                         Parity check
=====  =================================  ==============================
1      signatures and docstrings          ``Objects/clinic/foo.c.h``
                                          byte-identical
2      method and slot tables, tp_doc     ``pyspec_parity.py`` (below)
3      function internals (spec bodies)   difftest, ``HelperTest``,
                                          ``c_calls``, section 3 below
4      facts used by the specializer      ``test_opt``,
       or the JIT                         ``test_pyspec_facts`` (debug)
5      C API facts                        ``test_pyspec_catalog``
                                          (the ratchet)
=====  =================================  ==============================

Before every PR: regenerate with ``./python Tools/clinic/clinic.py
Objects/foo.c`` (not ``--make`` from a checkout that contains other
worktrees), rebuild, and run::

    ./python -m test test_clinic test_pyspec_facts test_pyspec_catalog

``PyspecFilesTest`` of ``test_clinic`` checks that the generated files
are up to date, runs the spec as Python against the interpreter on the
``CASES`` of ``foo_cases.py``, checks each class against ``TYPES``, and
checks that each type has exactly the slot wrappers its class declares.
When it says "the spec and the interpreter differ", rebuild first.

Checking parity with the interpreter before the migration
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''

``Tools/clinic/pyspec_parity.py`` records everything observable about a
type and compares it with a build of the tree before the migration.  It
records:

- the Python surface: ``vars()`` in order, docstrings, text signatures
  and ``help()``;
- the C layout: which slots are set, and whether each is inherited,
  generic or shared; every ``PyMethodDef``'s flags and doc; the members
  and getsets;
- a few thousand probed calls per type (about 2,700 for ``bytes``):
  each method at each arity,
  with keywords and with a pool of argument values, one parameter at a
  time.  It keeps the exact result, or the exception type and message,
  and any warnings;
- operators, subscripts, conversions, iteration, hashing, pickling and
  copying of sample instances.

Keep a build of the tree before the migration (``../build-main``), then
after rebuilding::

    ./python Tools/clinic/pyspec_parity.py compare ../build-main/python

With no type names it checks every type in the ``TYPES`` of a
``_cases.py``, so add the migrated class there first.  It prints a
unified diff of what changed, and ``no difference`` otherwise.  If the
old build is gone, capture on it before migrating and check later::

    ../build-main/python Tools/clinic/pyspec_parity.py capture list -o list.parity
    ./python Tools/clinic/pyspec_parity.py check list.parity

The same check runs in the test suite when ``PYSPEC_PARITY_BASELINE``
names the old python::

    PYSPEC_PARITY_BASELINE=../build-main/python ./python -m test test_tools.test_pyspec_parity

Both builds must be the same Python version and configuration (debug,
free-threaded).  A difference the migration makes on purpose goes into
``KNOWN_DIFFERENCES`` of the tool, with the reason; so far that is only
``bytes``'s vectorcall.  A type the tool cannot construct needs sample
instances in its ``SAMPLES``.  This checks that nothing changed; the
type's own tests (``test_bytes``, ...) still check that it is right.

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

*Size:* WS7's census: ``tupleobject.c`` 4 functions (29 block lines
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

*Parity:* the same attributes, docstrings and signatures before and
after, dumped with the interpreter built from each commit::

    ./python -c "
    import sys; T = eval(sys.argv[1])
    print(T.__name__, T.__flags__, T.__basicsize__, T.__itemsize__, repr(T.__doc__))
    for k, v in T.__dict__.items():
        print(k, type(v).__name__, repr(getattr(v, '__doc__', None)),
              getattr(v, '__text_signature__', None))" bytes > after.txt

``diff before.txt after.txt`` must be empty; ``nm -S
Objects/foo.o`` lists the same table symbols.

*Size:* bytes: about 100 lines of tables and ``PyDoc_STRVAR`` (both
types) become about 45 lines of dunders and a class docstring.

Checklist:

- [ ] type dump identical, for every type of the file (iterators too);
- [ ] ``test_clinic`` (slot wrappers vs dunders) passes;
- [ ] accessors (``@getter``/``@setter`` in the class) keep their
  ``tp_getset`` table in C.

Level 3: spec bodies
''''''''''''''''''''

*Needs:* a body in the subset of `README.rst <README.rst>`__ instead of
``...``; every C function the body calls declared ``@c_implemented``,
with its Python reference, in the spec of its own C file; cases in
``foo_cases.py``; each new helper in ``HelperTest`` of
``test_pyspec_facts``.  Only ``object`` and ``str`` parameters (and
``NULL`` defaults) are accepted.

*Gives:* the C impl is generated; for ``__new__`` also a vectorcall,
per-arity and per-type entries and the tier-2 call table; the logic is
tested as Python (the difftest).  Whether that is worth it is section 3.

*Parity:* ``PyspecFilesTest.test_cases`` (difftest), ``HelperTest``, the
``c_calls`` dimension of ``test_pyspec_catalog``, and section 3's
measurements.  Review the generated ``foo_pyspec.c.h`` like hand-written
C.

*Size:* one function per PR.  The worked example below: spec +35 lines,
hand-written C unchanged in size (the impls become helpers), generated
C +54/-20.

Checklist:

- [ ] section 3's decision recorded in the PR (numbers, not adjectives);
- [ ] cases cover each branch of the body, errors included;
- [ ] each reference models the exceptions of its C, messages included.

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
- [ ] instruction counts with the JIT on show the gain (section 3).

Level 5: C API facts and the disconnect ratchet
'''''''''''''''''''''''''''''''''''''''''''''''

*Needs:* the type in ``TYPES`` of
``Tools/clinic/libclinic/pyspec/disconnects.py`` (its C file and C API
prefixes).  The first PR records what disagrees today in
``Tools/clinic/pyspec-baseline/*.txt``; later PRs fix
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


Choosing what to migrate
------------------------

Order (WS7's census): the easy ``Objects`` files first
(``interpolationobject``, ``moduleobject``, ``sentinelobject``,
``structseq``, ``descrobject``, ``enumobject``, ``classobject``,
``tupleobject``), then small ones (``complexobject``, ``rangeobject``,
``funcobject``, ``odictobject``, ``memoryobject``, ``longobject``,
``typeobject``, ``dictobject``, ``floatobject``, ``listobject``,
``exceptions``), then those needing rules (``codeobject``,
``setobject``, ``bytearrayobject``, ``unicodeobject``), then Modules.
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
section 3 comes out positive.  In practice: a method whose call
overhead is a small part of its cost (most ``bytes`` methods: 0 to 8 %,
WS6); logic that needs ``Py_buffer``, a struct, pointer arithmetic or a
loop over raw memory (it ends up in ``@c_implemented`` helpers, so the
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
   instructions:u``.  Example (WS6/review): ``b[i]`` on pyflate, 1.28 M
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
(phase 1, workstream A):

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
  workstream A fixed the emitter; it is now 25 % faster than main.
- ``bytes.fromhex`` facts: derived, never consumed (above).
- Most ``bytes`` methods: call overhead is 0 to 8 % of their cost
  (WS6), so a generated impl cannot gain more than that.

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

with three ``@c_implemented`` helpers in C (``bytes_prefix_len``,
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

Clinic reports spec errors as ``path:line: error: message`` at the spec
line.  The common ones:

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
    ``@c_implemented`` helper, see the worked example: that changes the
    generated parser), a default other than ``NULL``, a keyword-only
    parameter, a statement or expression the table does not list
    (assign a call to a local before comparing it).  Or keep the C:
    ``...``, or ``@c_implemented`` with the body as its reference.
``unsupported ...`` (the same hint)
    A use the partial evaluation produced that the emitter cannot lower
    yet, e.g. a fast path of a reference in another spec (reported
    there).
``m: use ... as the body of a function implemented in C, not pass``
    Write ``...``.
``the body of a @c_implemented function is its Python reference``
    Give the reference a body, or drop ``@c_implemented``.
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
    The C of a ``@c_implemented`` helper calls ``f``.  If ``f`` can run
    Python code, add ``calls(x, "__slot__")`` or ``runs_python()`` to
    the reference.  If it cannot (``memcmp``), add it to the audited
    ``NO_PYTHON`` set of ``disconnects.py``.
``New disconnects: fix them (or ... add these lines to ...)``
    Fix the docs or data file; add a baseline line only on purpose.
``Fixed disconnects: delete these lines``
    Delete them: the ratchet only goes down.
``Checksum mismatch!``
    As with plain clinic: someone edited generated code; regenerate
    (``-f`` after checking the diff).

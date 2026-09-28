# Phase 4 brief: general mechanisms, bytes as data (2026-09-27)

Base: branch `exp/ac_python_overloads_v0` at the commit that adds this file.
Read `pyspec-notes/README.md` (state, decisions in force) and
`pyspec-notes/DESIGN.md` (goals, resource rules) first.  This brief overrides
them where they conflict.

## The user's goals for this phase
1. **Nothing specific to bytes in the mechanisms.**  Build general mechanisms;
   bytes, bytearray and mmap are *data* inside them.  Adding the next type
   (tuple, int, list, str) must be adding data (a spec, a `_cases.py`, rows in
   tables), never editing interpreter C, test classes, or tool code keyed on a
   type name.  It must be obvious how to add the next one.
2. **Spec bodies can express anything** (any Python the reference needs:
   keyword and keyword-only parameters, any constant default, `*args`,
   `**kwargs`, any statement).  Only a subset is *wired up* (lowered to C /
   used for facts) for now; everything outside it is accepted, analysed as
   worst case, and reported clearly as "expressible, not lowered yet" where
   lowering is asked for.  The boundary must be one explicit, documented place.
3. **Fix `@c_implemented`.**  Today the reference's leading `if` is inlined
   into callers (a "fast path"), so the Python reference is partly compiled
   and can drift from the C (e.g. `PyObject_LengthHint`'s list/tuple path is
   not in `abstract.c`; `_PyLong_IsCompact` hardcodes 30-bit digits).
4. **Easy to validate** for a reviewer and an implementer: one obvious
   command per question ("did behaviour change?", "is the generated code up to
   date?", "are the facts sound?"), with output a reviewer can read.
5. The whole thing must be presentable to the CPython developer community as a
   concept that works end to end, with clear ways to move existing CPython C
   code and, later, **pieces implemented in Rust**.  The spec is the
   language-neutral contract (signatures, docs, slots, semantics as reference
   bodies, facts); an implementation is generated from a body or written
   natively (C today, Rust later) and checked against the same spec.

Decisions in force from README.md still hold: a win across the board vs main
(no micro regressions), `PyTypeObject`s stay in C, generated output
byte-identical to main wherever possible, one-line clinic blocks, ratchets only
go down, F1 (free-threaded `bytes(list)` atomic snapshot).

## Workstreams and file ownership
Phases run in order; workstreams of one phase run in parallel, each in its own
worktree.  Stay inside your files; if you must touch another stream's file,
keep the edit minimal and say so in your report (the merge is done by hand).

**Phase 1**
- **A: registry, de-bytes the interpreter and the tests.**
  Owns: `Include/internal/pycore_pyspec.h`, `Tools/clinic/libclinic/pyspec/call_table.py`,
  `Tools/clinic/libclinic/pyspec/builtin_types.py`, the `TYPES`/`DOCSTRING_FILES`
  part of `disconnects.py`, `Modules/_testinternalcapi.c` (pyspec part),
  `Python/optimizer_analysis.c` / `optimizer_bytecodes.c` (only the slot lookup
  call sites), `Lib/test/test_pyspec_facts.py`, the pyspec part of
  `Lib/test/test_clinic.py`, `Objects/pyspec/*_cases.py`, `Modules/pyspec/*_cases.py`.
  Clinic generates one registry of every spec'd type (iterators included, each
  class its own slots); `_PySpec_GetCallTable`/`_PySpec_FindSlot` read it;
  slots keyed by slot id/offset, not strcmp.  Tests are data-driven over the
  `_cases.py` files (move per-type inputs, helper cases, slot uses there), one
  shared `spec_files()`.  `_testinternalcapi`: minimal surface (e.g.
  enter/leave "no Python" + a generic call), checked errors.  `disconnects`
  lists from the glob.  `builtin_types.py` loses rows a spec derives.
- **B1: the spec language front end.**
  Owns: `frontend.py`, `runtime.py`, `facts.py`, `dsl_parser.py`, `app.py`,
  `Tools/clinic/libclinic/errors.py`, `Objects/pyspec/README.rst`.
  Full signatures in specs (every clinic parameter form; keyword, kw-only,
  defaults, varargs) with byte-identical clinic output; bodies accept any
  Python; one explicit "lowerable subset" check that runs up front with clear
  errors; facts analysis treats anything outside the subset as worst case.
  Thin hook in `DSLParser.parse` (spec policy moves to `frontend`), one
  `bind_spec` for the two duplicated check paths, one `PyspecBindings`
  dataclass instead of three dicts, one `SpecError` (kind enum, filename from
  the node's scope), `emit`/`typeobj` imported lazily.  Do not refactor
  `partial_eval.py`/`emit.py` internals (phase 3); only the minimum to consume
  the new front end.
- **D: parity and reviewer validation.**
  Owns: `Tools/clinic/pyspec_parity.py`, `Lib/test/test_tools/test_pyspec_parity.py`,
  any new reviewer/implementer entry point, `Objects/pyspec/MIGRATING.rst`
  (validation sections).  Make validation trivially simple (see goal 4).

**Phase 2** (after phase 1 is merged): C `@c_implemented` (goal 3, and the
native-implementation concept of goal 5), E cleanups (optimizer readability,
brittle tests, stale items, free-threaded re-test, magic number question).
**Phase 3**: B2 lowering internals (`partial_eval`/`emit`: typed marks instead
of `pyspec_*` node attributes, one context object instead of hidden caches, no
import cycles, a backend boundary so C is one target, `/* spec.py:N */`
traceability), then F presentation (docs, Rust path, upstream PR series).

## Rules (in addition to DESIGN.md's resource rules, which are MANDATORY)
- Worktree + your own out-of-tree build dir `../build-p4-<ws>` (`CC=clang
  --with-pydebug --enable-experimental-jit`, like `build-exp`), `make -j8`
  inside `systemd-run --user --scope -q -p MemoryMax=12G -p MemorySwapMax=0`;
  tests capped at 6G; check `free -g` first.  No callgrind, perf record or
  pyperformance in phase 1 (measurement happens at integration).
- Regenerate with `./python Tools/clinic/clinic.py <files>` on the specific
  files (list in README.md "Resuming"), never `--make` from a checkout that
  contains `.claude/worktrees/`.  Generated files are committed.
- Small logical commits on your worktree branch, message ending with
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.  Never rebase,
  amend or push; never touch other branches.
- Bugs outside your task: report, don't fix.
- Before you finish: clinic on the spec-backed files leaves the tree clean;
  `test_clinic test_bytes test_mmap test_pyspec_facts test_pyspec_catalog
  test_tools.test_pyspec_parity test_opcache test_generated_cases` pass on your
  build; `PYSPEC_PARITY_BASELINE=/home/firebird347/projects/python/build-str1-dbg/python`
  parity passes (main at the merge base; same configuration).
- Report (<= 700 words): what changed (files, commits), design choices, what
  "adding the next type" now takes in your area, test commands + results, open
  problems, anything that conflicts with this brief.

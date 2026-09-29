# pyspec experiment: saved state

Branch `exp/ac_python_overloads_v0` (local only, never pushed); merge base with main
`ee1bbf037ff`.  State as of `c9d7955088f`: phase 4, the final PGO+LTO check, phase 5's
pure-Python workstream (PY) and the three review fix waves are merged.
This directory records where the experiment stands so work can resume without the
original sessions.  It is experiment bookkeeping, not part of any upstream change: drop
it before proposing anything.

**Start here:** `drafts/CONCEPT.md` (the concept end to end, with numbers and their
sources), `drafts/PR_SERIES.md` (the upstream plan), `Objects/pyspec/README.rst` (the
reference), `Objects/pyspec/MIGRATING.rst` (the procedure and validation).

## What the branch does
Types are described by Python-syntax specs that Argument Clinic reads
(`<dir>/pyspec/<stem>.py` for `<dir>/<stem>.c` or `.h`, found by one glob in
`Tools/clinic/libclinic/pyspec/specfiles.py`):

- `Objects/pyspec/bytesobject.py`: `class bytes` / `class bytes_iterator` (signatures,
  docstrings, clinic decorators, slots as dunders), spec bodies (`__new__`, `__bytes__`,
  `fromhex`, `PyBytes_FromObject`, `bytes_from_iterator`), `@native` functions (C written
  by hand; the body is the Python reference, never compiled, read for facts) and an
  `@inline` fast path (generated into callers).
- `Objects/pyspec/{abstract,typeobject,unicodeobject,longobject,bytes_methods}.py`,
  `Python/pyspec/{errors,pyhash,pystrhex}.py`,
  `Include/cpython/pyspec/longintrepr.py`: native functions of other files, imported by
  their path from the source root (`from Objects.pyspec.abstract import ...`), with
  `@inline` fast paths (`PyNumber_AsSsize_t_fast`, `PyObject_LengthHint_fast`).
- `Objects/pyspec/bytearrayobject.py` (levels 1, 2, 5; shares methods with bytes and the
  stringlib specs `Objects/stringlib/pyspec/{transmogrify,ctype}.py`);
  `Modules/pyspec/mmapmodule.py` (methods only, `#if`-guarded methods).
- Each spec has `<stem>_cases.py`: `TYPES`, `CASES` (difftest), `HELPERS` (native
  functions called directly), `FACTS`, `SLOT_USES`, `PARITY` (per-type parity data).
  Adding a type is adding data; no interpreter C, test class or tool code names a type.
- The spec language accepts any Python; `subset.py` is the one place that says what is
  **lowered** (generated as C) and what is **analysed** for facts; everything else is
  reported as "expressible, but not lowered to C yet" where lowering is asked for.
- Lowering: `subset` check → `partial_eval` (facts of each entry, typed marks in
  `marks.py`, one `context.Context`) → `emit` to the typed form of `ir.py` →
  `c_backend.CBackend`.  Generated C names its spec lines.
- `PyTypeObject`s stay in C; clinic generates `<prefix>_doc`, `<prefix>_methods[]` and the
  `tp_as_*` sub-tables into `Objects/clinic/<stem>_pyspec.c.h`, plus the spec bodies, the
  tier-2 call tables and the registry of every spec'd class (the generated header
  `Include/internal/pycore_pyspec_registry.h`; the lookups `_PySpec_FindCall`,
  `_PySpec_FindMethod`, `_PySpec_FindSlot` are in `Include/internal/pycore_pyspec.h`).  The optimizer uses the facts in `_CALL_BUILTIN_CLASS`,
  `_CALL_METHOD_DESCRIPTOR_NOARGS` and the `BINARY_OP_SUBSCR_BYTES_INT` / `FOR_ITER_BYTES`
  uops; debug builds assert them (`_ASSERT_RESULT_*`, no-Python tripwire).
- Validation: `Tools/clinic/pyspec_review.py` (one summary), `pyspec_parity.py` and the
  committed record `Tools/clinic/pyspec-baseline/parity.txt` (GIL release, GIL debug,
  FT debug blocks), `test_pyspec_facts`, `test_pyspec_catalog` (ratchet: capi, docs,
  slots, docstrings, typeshed, `c_calls` via `NATIVE_CHECKERS` / `CChecker` in
  `native_check.py`), `Tools/clinic/pyspec_bench.py` (instruction counts).
- Pure Python (phase 5, PY): `bytes` and its iterator have pure-Python bodies for every
  member but `%` (`@native(facts=False)`, eight machine primitives in
  `libclinic/pyspec/machine.py`); `pyspec_parity.py model` runs the spec as Python classes
  (`libclinic/pyspec/model.py`) against the C type: 36,086 of 36,189 lines identical.

## Workstreams and where their results are
| WS | Topic | State | Report |
|---|---|---|---|
| WS1 | clinic as the one tool; signatures in the spec | merged | (commit messages) |
| WS2 | C API catalog vs docs | merged, then replaced by D | `reports/ws2_capi_disconnects.md` |
| WS4 | tier-2 call table + direct-call uop | merged | (commit messages) |
| WS5 | integration of WS2+WS4 | merged | `reports/ws5.md` |
| WS6 | profiling: where time goes | analysis | `reports/ws6.md` |
| WS7 | tree-wide adoption census | analysis | `reports/ws7.md` |
| WS8 | clinic decorators in the spec | merged | `reports/ws8.md` |
| WS9 | spec vs docs vs typeshed | analysis | `reports/ws9.md` |
| WS10 | derived facts, `__bytes__`/`fromhex` bodies | merged | `reports/ws10.md` |
| WS11 | `_PyBytes_FromIterator` in the spec, sequence path derived | merged | `reports/ws11.md` |
| WS12 | type objects / slots / method tables generated | merged | `reports/ws12.md` |
| Review | performance / legibility / integration | done | `reports/review_{perf,dx,int}.md` |
| B | one-line blocks only, errors not silence, output parity | merged | `reports/phase1_B.md` |
| D | catalog out of the spec, disconnect ratchet | merged | `reports/phase1_D.md` |
| E | debug fact assertions, tripwire, direct-call difftest, F5 | merged | `reports/phase1_E.md` |
| S | `_CALL_STR_1` exact-str bug fix (based on main) | merged here; local branch `fix-call-str-1-subclass` | `bugreports/call-str-1-subclass/`, `drafts/call-str-1-UPSTREAM.md` |
| S2 | `_pylong.int_to_decimal_string()` must return an exact str (based on main) | merged here; local branch `fix-pylong-str-exact` | commit message of c490a0e38f2 |
| A | `bytes(list)` regression, F1/F2/F4, code size | merged | `reports/phase1_A.md` |
| Audit | comments and docstrings match the code | merged | `reports/comment_audit.md` |
| P1+P2 | helpers by name, facts derived from bodies, F3, one types table, C-side check | merged | `reports/phase2_P1P2.md` |
| 3b | bytearray from a spec; PyTypeObject back in C | merged | `reports/phase3b_bytearray.md` |
| Cond | `#if` handled as plain clinic; mmap sample | merged | `reports/phase3_conditionals.md` |
| Guide | MIGRATING.rst + pyspec_bench.py; removeprefix worked example: keep in C | merged | `reports/phase3_migration_guide.md` |
| 3a | bytes slot facts; `BINARY_OP_SUBSCR_BYTES_INT`, `FOR_ITER_BYTES` | merged | `reports/phase3a_slot_specializations.md` |
| **Phase 4** | general mechanisms, bytes as data (brief: `PHASE4.md`) | | |
| 4-D | parity record, `pyspec_review.py`, per-type `PARITY` data | merged `f4b03fd9f9f` | commit messages |
| 4-B1 | spec language front end: full signatures, any body, one lowered subset, one `SpecError` | merged `adf1bf6a04d` | commit messages |
| 4-A | one registry of spec'd classes, data-driven tests, generic `_testinternalcapi` | merged `a2aff724d86` | commit messages |
| 4-E | optimizer helpers, brittle tests, FT parity block, magic number, upstream split | merged `bb32433383b` | `reports/phase4_E.md` |
| 4-C | `@c_implemented` → `@native` (never compiled), `@inline` fast paths, pluggable native checkers | merged `c7242273486` | commit messages |
| 4-P | PGO+LTO cost of `@inline`; `Sub(n)` below main | merged `2545b5e477c` | `reports/phase4_P.md` |
| 4-B2 | typed marks, one context, IR + C backend, spec-line traceability, `except (A, B)`, `__new__` by arity | merged `63ce50f2c9b` | commit messages |
| 4-S | simplify `Tools/clinic/libclinic/pyspec/` (code only) | merged | commit messages |
| 4-F | presentation: CONCEPT, PR series, README/MIGRATING consolidated, this file | merged | `drafts/CONCEPT.md`, `drafts/PR_SERIES.md` |
| 4-final | PGO+LTO check of the finished branch; `bytes.fromhex` tail call (`737069ca773`) | merged | `reports/phase4_final_perf.md` |
| 5-PY | "Python which is lowered": machine primitives, pure bodies for bytes, the model | merged `506a01c2694` | `reports/phase5_pure_python.md` |
| 5-fix core | review fixes, tool core: facts join after branches, alias after reassignment, borrowed loop items, NULL locals, front-end errors (`PyspecSoundnessTest`) | merged `f1cc4c39dda` | commit messages |
| 5-fix interp | review fixes, interpreter/tests: UB-free helper calls, structural uop tests, `test_independent_of_host` in a subprocess, PEP 7; upstream test_iter/test_opt issue draft | merged `b2891bfcf81` | `reports/phase5_fixes_interp.md` |
| 5-fix tooling | review fixes, tooling: exact parity comparisons, `parity.txt` recaptured, strict exit codes, `NOT EXPLAINED` fails the review, `native_check.py`, non-circularity checks, `pycore_pyspec_registry.h` | merged `c9d7955088f` | commit messages |
| 5-docs | final documentation pass (this file, CONCEPT, README/MIGRATING, drafts) | on its worktree branch | commit messages |

`DESIGN.md` (the brief of the early workstreams), `PHASE4.md` (the phase 4 brief) and
`PROPOSALS.md` (P1/P2, implemented) are historical; this file and
`Objects/pyspec/README.rst` supersede them.

## User decisions in force
- The branch must be a win across the board vs main (no micro regressions).
- One mode: a one-line clinic block per spec method; clinic writes impl heads.
- `PyTypeObject` definitions stay in C; the spec generates only what it derives
  (method table, slot sub-tables, doc string).
- Generated output byte-for-byte identical to main wherever possible; bracket
  `@text_signature`s stay (help() parity); typeshed is checked from the spec instead.
- Free-threaded `bytes(list)` keeps main's atomic snapshot for all-int lists (F1).
- P1 + P2 approved and implemented (see PROPOSALS.md, `reports/phase2_P1P2.md`).
- Integration is measured as a ratchet that may only go down.
- **General mechanisms with per-type data**: nothing in the interpreter, the tests or the
  tool is keyed on a type name; a type is a spec, a `_cases.py` and table rows.
- **Spec language: expressible vs lowered.**  A spec may say anything in Python; one
  explicit boundary (`subset.py`) says what is generated and analysed; the rest is
  worst case and reported as "expressible, not lowered yet".
- **`@native` / `@inline`**: a native function's reference is never compiled, not even
  in part; a fast path generated code takes is an `@inline` function next to it, never an
  `if` in the reference that the C does not have.
- **PGO+LTO arbitrates micro costs** (with an A/A pair and a fixed `PYTHONHASHSEED`);
  **must-inline markers only as a rare exception** (none needed so far: `reports/phase4_P.md`).
- Heavy commands run memory-capped (`systemd-run --user --scope -p MemoryMax=...`),
  serially, `make -j8` (an OOM once took down the desktop).
- **Scope (2026-09-29): purely "can this be done".**  Nothing is pushed or proposed yet;
  publishing the branch happens later, by the user.  Commit history stays as it is (no
  squashing or splitting into the PR series now; PR_SERIES.md is a plan, not a task).
- **Parity must eventually run on PRs as checks reviewers can see** (CI output, not
  only a local command); the committed record vs a base build is not decided.
- **Bracket `@text_signature`: undecided** (it keeps help()'s `sub[, start[, end]]`
  notation but makes `inspect.signature` raise, hiding 13 bytes/bytearray methods from
  stubtest).

## Performance vs main
PGO+LTO release JIT, clang 21, `PYTHONHASHSEED=1`, instructions / cycles per iteration,
main `ee1bbf037ff` -> branch `737069ca773` (the fix build of `reports/phase4_final_perf.md`;
up to `c9d7955088f` the generated and interpreter C changed only in comments, braces and
the registry's header): `bytes(16)` 911/171 -> 445/97; `bytes(iter(l16))` 3193/659 ->
2353/486; `bytes(range(256))` 25567 -> 16714; `bytes(l256)` 6845 -> 5123; `Sub(16)` 1313 ->
1263; `Sub(b16)` 1326 -> 1037; `Sub(l16)` 1748 -> 1714 (thinnest margin, -1.1 to -1.9 %
across seeds 0, 1, 7); `b16[i]` 306 -> 207; `for c in b16` 1652 -> 1109; every `bytes()`
shape 11-77 % below main.  Cross-build A/A: up to 10 instructions, +-3 % cycles; no shape
is above main by more (the +1 to +6 left are in code unchanged from main or equal to main
under callgrind).  Where the gain comes from (`reports/review_perf.md`): the generated
`tp_vectorcall` is the whole JIT-off gain (a hand-written one would give the same); alias,
constant fold and direct calls need the facts (JIT on).  End to end: pyflate -3.1 %
instructions from the `b[i]`/iteration specializations, wall clock inside pyperformance
noise; no bytes-attributable pyperformance change; startup neutral.  Code size (debug
builds, `build-exp` vs `build-str1-dbg`, `size`): `bytesobject.o` text +8.2 KB,
`bytearrayobject.o` +1.8 KB, `optimizer_analysis.o` +7.9 KB.

## Test status (`c9d7955088f`)
Debug JIT build `../build-exp` (srcdir: the main checkout at `c9d7955088f`; its version
string says `-dirty`):
- `PYSPEC_PARITY_BASELINE=../build-str1-dbg/python -m test -j4 test_clinic test_bytes
  test_mmap test_pyspec_facts test_pyspec_catalog test_tools.test_pyspec_parity
  test_tools.test_pyspec_bench test_opcache test_generated_cases test_capi`: 10 files,
  2,769 tests (50 skipped), pass (30 s).
- The same list with `test_capi.test_opt` in place of `test_capi`, without `-j` (one
  process, so order dependences show): 1,503 tests (43 skipped), pass (50 s).
- `Tools/clinic/pyspec_review.py --baseline ../build-str1-dbg/python`: Result OK (26 s);
  no difference in 87,737 lines; clinic `--dry-run` on 14 C files up to date; 535 / 21 / 12
  tests; c_calls 0, capi 20, docs 0, docstrings 2, slots 3.
- `Tools/clinic/pyspec_parity.py model`: 36,086 of 36,189 lines identical (6 s).
- Free-threaded debug: suites passed at `bb32433383b` (`reports/phase4_E.md`); the branch's
  debug JIT, release JIT and FT debug builds matched the recaptured record at
  `b07c2e648db` (`check --strict`).  Not re-run at `c9d7955088f`.
- Upstream order dependence: `test_iter` before `test_capi.test_opt` fails 16 test_opt
  tests on main too (issue draft in `reports/phase5_fixes_interp.md`).

## Open items
1. **Upstream filings** (the user files them): `_CALL_STR_1` (issue text in
   `drafts/call-str-1-UPSTREAM.md`, replace `gh-NNNNNN`), `_pylong` exact str
   (`fix-pylong-str-exact`), the test_iter/test_opt order dependence
   (`reports/phase5_fixes_interp.md`), then `drafts/PR_SERIES.md` Part A.  Magic number:
   bump in the upstream specialization PR, not here (`reports/phase4_E.md` section 5).
2. **Publication**: the branch is local.  `drafts/CONCEPT.md` is self-contained (numbers
   inline with their commits), but where the branch or its evidence would be published is
   undecided.
3. **Tool size**: `Tools/clinic/libclinic/pyspec/` 9,647 lines (6,872 code; model and
   machine 1,368) + `pyspec_parity.py` 1,788, `pyspec_review.py` 433.
4. **Parity record churn**: unrelated upstream changes can alter a section (inherited
   docstrings, other types' messages) and need a re-record; only Linux 64-bit blocks.
5. **Not lowered yet**: keyword-only parameters, non-`NULL` defaults, converters other
   than `object`/`str`, `while`, `__init__`, `@critical_section` on generated methods.
   Not expressible: optional groups, deprecation markers, module-level functions.
6. **Pure Python next**: `%` (format strings in the parity samples: a record update);
   bytearray (a mutable-storage primitive; own or template bodies for shared methods);
   mmap (a mapped-memory primitive); promoting `@native(facts=False)` to `@native`
   (call-table slot entries gated on a consumer, the C checker reading clinic `_impl`s,
   `HelperTest` calling methods).  A PEP 399 pair (`bisect`): analysis only.
7. **Rust**: design only (`CBackend` interface, `NativeChecker`), no Rust code.
8. Optional from 4-P: prune `@inline` paths by call-site hints (saves 7 instructions per
   iterator call of `bytes_from_iterator`); `PyObject_LengthHint` of a list iterator costs
   362 instructions (main too).  Fix `PYTHONHASHSEED` in all future micro tables.
9. `test_opt.test_binary_op_subscr_constant_frozendict_known_hash` (and
   `test_binary_op_subscr_init_frame`) once found no executor after other modules; not
   reproduced since (`reports/phase5_fixes_interp.md`).  `../build-ft` is broken
   (`pybuilddir.txt` missing; `make` there fixes it).
10. Carried over: the C-side check is per function, not per path, and treats refcount
   releases as running no Python (so does the tripwire); a JIT refleak in HelperTest with
   fresh functions per `-R` repetition was worked around; a constant +1 refcount on the
   subclass in `repro_type_refleak.py` under the JIT; `threadsafety.dat` levels for three
   bytearray entries are the agent's judgement; ctype docstrings compiled per type
   (+1.4 KB); `pycore_bytes_methods.h` declares nine never-defined docstrings
   (pre-existing); the spec's type-level slot C names are only checked for existence;
   `bytes.lstrip` docstring has a double space; "a byte is a small int" is a uop claim
   (no value ranges in the facts); `==` specialization skipped (below noise); string
   C-type annotations trigger ruff F722; `_ASSERT_RESULT_*` uops exist in release builds
   (never emitted there); `_CALL_BUILTIN_CLASS_0_INLINE` is unreached by today's data
   (kept for the next type).
11. **Next types** (need the user's go-ahead): generated constructor vectorcall for every
   spec'd type; then tuple, int, list, str.

## Resuming
- Worktrees of finished agents are removed; their branches remain as
  `worktree-agent-*`.
- Build dirs (outside the repo): `build-exp` (debug JIT, srcdir the main checkout: use
  it), `build-str1-dbg` (main at the merge base, debug tier-2; the parity baseline),
  `build_perf_base_jit` (main, PGO+LTO JIT, clang 22: do not compare with clang-21
  builds), `build-p4-*` (phase 4 agents' debug builds; `build-p4-e-ft` branch FT debug,
  `build-p4-e-ft-main` main FT debug; their source worktrees were removed, so they run
  but cannot be rebuilt).
- The spec'd C files (14 at `c9d7955088f`) are derived, not listed by hand:
  ```
  ./python -c "import sys; sys.path.insert(0, 'Tools/clinic'); from libclinic.pyspec import specfiles; print(*(c for _, c in specfiles.spec_files('.')))"
  ```
- Regenerate with `./python Tools/clinic/clinic.py` and that list, today
  `Include/cpython/longintrepr.h Modules/mmapmodule.c Objects/abstract.c
  Objects/bytearrayobject.c Objects/bytes_methods.c Objects/bytesobject.c
  Objects/longobject.c Objects/typeobject.c Objects/unicodeobject.c
  Objects/stringlib/ctype.h Objects/stringlib/transmogrify.h Python/errors.c
  Python/pyhash.c Python/pystrhex.c` (not `--make` from a checkout containing
  `.claude/worktrees/`, which it would also scan); `--dry-run` checks.
- Validate: `./python Tools/clinic/pyspec_review.py --baseline ../build-str1-dbg/python`,
  and `./python Tools/clinic/pyspec_parity.py model` for the pure bodies.

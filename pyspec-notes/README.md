# pyspec experiment: saved state

Branch `exp/ac_python_overloads_v0` (local only, never pushed); merge base with main
`ee1bbf037ff`.  This directory records where the experiment stands so work can resume
without the original sessions.  It is experiment bookkeeping, not part of any upstream
change: drop it before proposing anything.

## What the branch does
`bytes` is described by Python-syntax specs that Argument Clinic reads:

- `Objects/pyspec/bytesobject.py`: `class bytes` / `class bytes_iterator` (method
  signatures, docstrings, slot stubs), spec bodies (`__new__`, `__bytes__`,
  `fromhex`, `PyBytes_FromObject`, `bytes_from_iterator`), and `@c_implemented`
  helpers (hand-written C; the body is the Python reference, facts derived from it).
- `Objects/pyspec/{abstract,typeobject,unicodeobject}.py`, `Python/pyspec/errors.py`,
  `Include/cpython/pyspec/longintrepr.py`: helpers of other C files, imported by name.
- `Objects/pyspec/bytearrayobject.py`: `class bytearray` / its iterator; shares methods
  with bytes (`strip = critical_section(bytesobject.bytes.strip)`).
- `Objects/stringlib/pyspec/{transmogrify,ctype}.py`: methods shared by bytes and bytearray.
- The `PyTypeObject` structs stay hand-written in C (user decision); clinic generates
  only `<prefix>_doc`, `<prefix>_methods[]` and the `as_number/sequence/mapping/buffer`
  sub-tables, which the structs (after the generated include) name as on main.
- `Objects/pyspec/bytesobject_cases.py`: difftest data (spec run as Python vs the
  interpreter).
- Facts come from bodies plus four primitives (`exact(T, v)`, `unknown(v)`,
  `calls(x, "__slot__")`, `runs_python()`); `...` means worst case; one audited table
  of builtin types: `Tools/clinic/libclinic/pyspec/builtin_types.py`.
- `Objects/pyspec/README.rst`: the contributor guide ("to do X, edit Y").
- Clinic generates `Objects/clinic/bytesobject.c.h` (byte-identical to main outside
  `bytes.__new__`) and `Objects/clinic/bytesobject_pyspec.c.h` (spec bodies, per-arity
  and per-type entries, the tier-2 call table, the method and slot tables);
  `bytearrayobject.c.h` and `transmogrify.h.h` are byte-identical to main.
- The tier-2 optimizer uses derived facts (alias, constant, no-Python, exact type);
  debug builds assert them at run time.
- `Lib/test/test_pyspec_catalog.py`: a disconnect ratchet over C API files, docs
  signatures, typeobj.rst, duplicated docstrings, the C of `@c_implemented` helpers
  (`c_calls`: every call that may run Python is accounted for in the reference, using
  the cases generator's lexer) and (optionally) typeshed; baselines in
  `Tools/clinic/pyspec-baseline/*.txt` may only shrink.
- `Lib/test/test_pyspec_facts.py`: every call-table entry and every callable helper
  called directly against the interpreter / its reference, with fact checks and a
  "no Python" tripwire.

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
| 3b | bytearray from a spec; PyTypeObject back in C (`@static_type`/`@final` removed) | merged | `reports/phase3b_bytearray.md` |

`DESIGN.md` is the shared brief every agent read (goals, decisions, resource rules);
`PROPOSALS.md` holds P1/P2.

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
- Heavy commands run memory-capped (`systemd-run --user --scope -p MemoryMax=...`),
  serially, `make -j8` (an OOM once took down the desktop).

## Performance vs main (PGO+LTO release JIT, instructions / cycles per iteration)
Every `bytes()` call shape is below main, JIT on and off (full table:
`reports/phase1_A.md`).  Examples, main -> branch: `bytes(list256)` 6849/1227 ->
5124/872; `bytes(list16)` 1329/250 -> 798/157; `bytes(b16)` 923/187 -> 218/43;
`bytes(range256)` 25572/5149 -> 15412/3000; `Sub(b16)` 1332/269 -> 1058/201.
Methods, slots and startup are neutral; pyperformance shows no bytes-attributable
change (bytes calls are <1% of every benchmark).  bytes code is +1.3 KB vs main.
P2 changed no shape for the worse (non-PGO instruction counts); `bytes(16)` now uses
the no-Python call (442 -> 433 instructions).

## Test status (after merging 3b)
Debug JIT build `../build-exp` (srcdir: this checkout): test_clinic, test_bytes,
test_inspect, test_iter, test_pydoc, test_descr, test_pickle, test_buffer, test_int,
test_pyspec_catalog, test_pyspec_facts pass (2820 tests); test_capi alone passes.
Running test_opt after other modules in one invocation fails guard-removal tests, as on
main (upstream order dependency).  `PYTHON_JIT=0 -R 3:3` on the four pyspec suites
passes.  Free-threaded debug (3b's agent): test_bytes incl. bytearray free-threading
tests, test_free_threading, test_pyspec_facts, test_clinic pass.  No expected failures.
Clinic on the six spec-backed files and `make regen-cases` leave the tree clean.
Parity with main: `bytearrayobject.c.h`, `transmogrify.h.h` identical; `bytesobject.c.h`
differs only in the `bytes.__new__` section; bytes/bytearray type dumps identical except
`bytes.tp_vectorcall`.  Ratchet: docstrings 22 -> 2, capi 23 -> 20, docs 1 -> 0.

## Open items
1. Tool code is flat after P2 (5710 -> 5691 lines; the C-side check costs ~200).
   P2 deleted `Objects/pyspec/capi/bytesobject.py` (hand-written runs-Python name sets
   nothing consumed); the user approved the deletion.  The C-side check is per function,
   not per path, and treats refcount releases as running no Python (audited
   assumption).  A JIT refleak in HelperTest with fresh functions per `-R` repetition
   was worked around, not investigated (maybe the same class as item 2's).  String
   C-type annotations trigger ruff F722.  bytes `__iter__`/`__len__` are `...` (the old
   ITERATION fact had no consumer).  Two PGO builds of one commit differ by +-1-3%.
2. `_CALL_STR_1` upstream: the user files the issue (text in `drafts/`), replaces
   `gh-NNNNNN` in the commit and NEWS name.  `str(int)` keeps the exact-str claim; the
   companion fix makes it always true: local branch `fix-pylong-str-exact` (c490a0e38f2,
   based on main, merged here) requires `_pylong.int_to_decimal_string()` to return an
   exact str (`PyUnicode_CheckExact` in `Objects/longobject.c`, test in test_int, NEWS
   with a `gh-NNNNNN` placeholder); file it as its own small issue/PR.  A constant
   +1 refcount on the subclass remains in `repro_type_refleak.py` under the JIT
   (was +12007), not investigated.
2b. From 3b: `threadsafety.dat` levels for three bytearray entries are the agent's
   judgement (review before upstream); ctype docstrings now compiled per type (+1.4 KB);
   `pycore_bytes_methods.h` declares nine never-defined docstrings (pre-existing); the
   spec's type-level slot C names are not compared with the C struct (only existence);
   `bytes.lstrip` docstring has a double space (fixing it lets bytearray share it).
3. Phase 3 (3b bytearray done): `b[i]` and `FOR_ITER` over bytes specializations from slot facts (the only
   measurable end-to-end lever, ~1.5-2% pyflate), then bytearray (shares the stringlib
   specs, removes duplicated docstrings), then tuple, int, list, str.
4. Upstreamable pieces (see `reports/review_int.md` section 5): doc/docstring/typeshed
   fixes from WS9, typeobj.rst missing rows, refcounts.dat gaps, `PickleBuffer` over a
   Python `__buffer__` (F7), the devguide section (`drafts/devguide_draft.rst`).

## Resuming
- Worktrees of finished agents are removed; their branches remain as
  `worktree-agent-*`.
- Build dirs (outside the repo): `build-exp` (debug JIT, srcdir this checkout: use
  it), `build_perf_base_jit` (main, PGO+LTO JIT), `build-str1-dbg` (main, debug tier-2
  interpreter).  Stale build dirs of finished agents were deleted.
- Regenerate with `Tools/clinic/clinic.py Objects/bytesobject.c
  Objects/stringlib/transmogrify.h Objects/bytearrayobject.c Objects/abstract.c
  Objects/typeobject.c Objects/unicodeobject.c` (not `--make` from a checkout containing
  `.claude/worktrees/`, which it would also scan).

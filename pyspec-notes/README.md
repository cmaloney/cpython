# pyspec experiment: saved state

Branch `exp/ac_python_overloads_v0` (local only, never pushed); merge base with main
`ee1bbf037ff`.  This directory records where the experiment stands so work can resume
without the original sessions.  It is experiment bookkeeping, not part of any upstream
change: drop it before proposing anything.

## What the branch does
`bytes` is described by Python-syntax specs that Argument Clinic reads:

- `Objects/pyspec/bytesobject.py`: `class bytes` / `class bytes_iterator` (method
  signatures, docstrings, slots, `@static_type`), spec bodies (`__new__`, `__bytes__`,
  `fromhex`, `PyBytes_FromObject`, `bytes_from_iterator`), and the escape stubs.
- `Objects/stringlib/pyspec/{transmogrify,ctype}.py`: methods shared with bytearray.
- `Objects/pyspec/bytesobject_cases.py`: difftest data (spec run as Python vs the
  interpreter); `Objects/pyspec/capi/bytesobject.py`: the only hand-written C API facts.
- `Objects/pyspec/README.rst`: the contributor guide ("to do X, edit Y").
- Clinic generates `Objects/clinic/bytesobject.c.h` (byte-identical to main outside
  `bytes.__new__`) and `Objects/clinic/bytesobject_pyspec.c.h` (spec bodies, per-arity
  and per-type entries, the tier-2 call table, the type objects).
- The tier-2 optimizer uses derived facts (alias, constant, no-Python, exact type);
  debug builds assert them at run time.
- `Lib/test/test_pyspec_catalog.py`: a disconnect ratchet over C API files, docs
  signatures, typeobj.rst, duplicated docstrings and (optionally) typeshed; baselines in
  `Tools/clinic/pyspec-baseline/*.txt` may only shrink.
- `Lib/test/test_pyspec_facts.py`: every call-table entry called directly against
  `bytes()`, with fact checks and a "no Python" tripwire.

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
| A | `bytes(list)` regression, F1/F2/F4, code size | merged | `reports/phase1_A.md` |
| Audit | comments and docstrings match the code | merged | `reports/comment_audit.md` |

`DESIGN.md` is the shared brief every agent read (goals, decisions, resource rules);
`PROPOSALS.md` holds P1/P2.

## User decisions in force
- The branch must be a win across the board vs main (no micro regressions).
- One mode: a one-line clinic block per spec method; clinic writes impl heads.
- Generated output byte-for-byte identical to main wherever possible; bracket
  `@text_signature`s stay (help() parity); typeshed is checked from the spec instead.
- Free-threaded `bytes(list)` keeps main's atomic snapshot for all-int lists (F1).
- P1 + P2 approved for phase 2 (see PROPOSALS.md).
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

## Test status (commit 04079e991e4)
Debug JIT build (`../build-merge`): test_clinic, test_bytes, test_capi, test_inspect,
test_pydoc, test_descr, test_pickle, test_iter, test_pyspec_catalog, test_pyspec_facts
pass, except that running test_opt after other modules in one invocation fails 33
guard-removal tests (the same upstream order dependency fails 21 on main; test_capi
alone passes, 1599 tests).  `PYTHON_JIT=0 -R 3:3` on the four pyspec-related suites
passes.  Free-threaded debug build (`../build-merge-ft`): test_bytes,
test_free_threading, test_clinic, test_pyspec_facts pass; the F1 snapshot script
gives 0 torn results.  Only expected failure: `test_static_type_rule` (F3, needs P2).
Parity with main: `transmogrify.h.h` identical; `bytesobject.c.h` differs only in the
`bytes.__new__` section.

## Open items
1. Tool code grew in A (+979/-209 in libclinic/pyspec, mostly partial_eval.py); P2
   should net-remove it.  `bytes(16)` still "may run Python" (the `except TypeError`
   fallback is not provably dead for an exact int; a spec for `PyNumber_AsSsize_t`
   fixes it).  Two PGO builds of one commit differ by +-1-3% on unrelated shapes.
2. `_CALL_STR_1` upstream: the user files the issue (text in `drafts/`), replaces
   `gh-NNNNNN` in the commit and NEWS name.  Open choice: `str(int)` keeps the exact-str
   claim (a monkeypatched `_pylong` can break it; main has the same claim); suggested
   separate one-line fix in `Objects/longobject.c` (`PyUnicode_CheckExact`).  A constant
   +1 refcount on the subclass remains in `repro_type_refleak.py` under the JIT
   (was +12007), not investigated.
3. Phase 2: P1 + P2 (helpers by name, facts derived from bodies with
   `exact()/unknown()/calls()/runs_python()`, ownership from refcounts.dat, C-side
   token-level escape check reusing `Tools/cases_generator/analyzer.py`); one table of
   builtin types in place of seven; replace the "exact static type runs no Python" rule (F3).
4. Phase 3: `b[i]` and `FOR_ITER` over bytes specializations from slot facts (the only
   measurable end-to-end lever, ~1.5-2% pyflate), then bytearray (shares the stringlib
   specs, removes duplicated docstrings), then tuple, int, list, str.
5. Upstreamable pieces (see `reports/review_int.md` section 5): doc/docstring/typeshed
   fixes from WS9, typeobj.rst missing rows, refcounts.dat gaps, `PickleBuffer` over a
   Python `__buffer__` (F7), the devguide section (`drafts/devguide_draft.rst`).

## Resuming
- Worktrees of finished agents are removed; their branches remain as
  `worktree-agent-*`.
- Build dirs (outside the repo): `build-merge` / `build-merge-ft` (debug JIT /
  free-threaded debug of 04079e991e4), `build-exp` (older debug JIT of this branch),
  `build_perf_base_jit` (main, PGO+LTO JIT), `build_review_pgo` (PGO+LTO JIT of
  62cc16504fe), `build-str1-dbg` (main, debug tier-2 interpreter).
- Regenerate with `Tools/clinic/clinic.py Objects/bytesobject.c
  Objects/stringlib/transmogrify.h` (not `--make` from a checkout containing
  `.claude/worktrees/`, which it would also scan).

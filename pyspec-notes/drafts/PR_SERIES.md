# Upstream PR series (draft)

Ordered small PRs, each useful on its own.  Sources: the split of the interpreter pieces
in `reports/phase4_E.md` section 7, the level structure of `Objects/pyspec/MIGRATING.rst`,
the fixes found in `reports/ws9.md` and `reports/review_int.md` section 5.  Commits named
are on `exp/ac_python_overloads_v0` (or its local fix branches); every PR is rebuilt on
current main, with generated files (`make regen-cases`, `make clinic`) regenerated in the
PR itself.  Nothing here has been filed.

Legend: **Indep.** = independent of pyspec (useful even if the concept is rejected).
"Deps" names earlier PRs of this list.

## Part A: independent fixes and interpreter pieces

| # | PR | files | deps | reviewers check |
|---|---|---|---|---|
| A1 | **`_CALL_STR_1`: exact str only for an exact int/float argument** (use-after-free with a `str` subclass from `__str__`). **Indep.** Local branch `fix-call-str-1-subclass` (`969928f3ba2`), issue text in `drafts/call-str-1-UPSTREAM.md` | `Python/optimizer_bytecodes.c`, `Python/optimizer_cases.c.h`, 3 tests in `Lib/test/test_capi/test_opt.py`, NEWS | none | the repro crashes before, passes after; no other `sym_new_type` claim of the same kind (backport to 3.15) |
| A2 | **`_pylong.int_to_decimal_string()` must return an exact str** (companion of A1: keeps `str(int)`'s exact-str claim true). **Indep.** Local branch `fix-pylong-str-exact` (`c490a0e38f2`) | `Objects/longobject.c` (`PyUnicode_CheckExact`), `Lib/test/test_int.py`, NEWS | none | error message; the huge-int path only |
| A3 | **Clinic errors as `path:line: error: message`**. **Indep.** Part of `e96b995a261` | `Tools/clinic/libclinic/errors.py` (`ClinicError.report()`), `warn_or_fail` `end=""`, one hunk of `test_clinic` | none | editor/CI-parsable messages; no behaviour change for valid input |
| A4 | **Debug-build `_ASSERT_RESULT_TYPE` / `_ASSERT_RESULT_IS`** after existing optimizer-typed calls (`_CALL_STR_1`, `_CALL_ISINSTANCE`, `_CALL_TUPLE_1`, `_CALL_LEN`). **Indep.** Part of `c771db06606` | `Python/bytecodes.c` (two `replicate(0:4)` uops), `Tools/cases_generator/analyzer.py` (`_PyObject_ASSERT_WITH_MSG` non-escaping), `Python/optimizer_analysis.c` (`keep_this_instr`, `assert_result_facts`), `test_opt` (`iter_opnames` filter, `test_call_len_result_type_asserted`) | none (textual conflict with A1 only) | release builds emit nothing; a wrong fact aborts in debug (it would have caught A1) |
| A5 | **`_POP_TOP_OPARG` → `_NOP`** when nothing is popped. **Indep.** From `ad1c4836588` | 3-line hunk in `optimizer_bytecodes.c`, `optimizer_cases.c.h`, `test_call_builtin_class_no_args_pops_nothing` | none | trace shape only |
| A6 | **`BINARY_OP_SUBSCR_BYTES_INT` and `FOR_ITER_BYTES`**. **Indep.** `9e605b2e0a3` without the spec part: results are `sym_new_compact_int(ctx)` | `Python/bytecodes.c`, `Python/specialize.c`, `Python/optimizer.c`, `Tools/cases_generator/tier2_generator.py`, `optimizer_bytecodes.c` (`_GUARD_NOS_BYTES`, `_ITER_CHECK_BYTES`), `test_opt`, `test_opcache`, **magic number bump** (recommended in phase4_E section 5), NEWS | none | `b[i]` 304→206 and `for c in b16` 1652→1110 instructions (`reports/phase4_P.md`); pyflate −3.1 % instructions, wall clock within noise (`reports/phase3a_slot_specializations.md`) |
| A7 | **Docs and docstring fixes for bytes** (WS9 items 1, 2, 6–10, 13, 14). **Indep.** Not written yet | `Doc/builtins/stdtypes.rst`, `Doc/builtins/functions.rst`, `Doc/c-api/bytes.rst`, the `removesuffix`/`fromhex`/`lstrip` docstrings (clinic blocks in `Objects/bytesobject.c`) | none | each item has a one-line repro in `reports/ws9.md` section 5 |
| A8 | **C API data gaps**: `typeobj.rst` rows `__rfloordiv__`, `__rtruediv__`, `__rmul__`; the bytes entries missing from `refcounts.dat` and `threadsafety.dat`. **Indep.** Not written yet; the lines are listed in `Tools/clinic/pyspec-baseline/{slots,capi}.txt` | `Doc/c-api/typeobj.rst`, `Doc/data/refcounts.dat`, `Doc/data/threadsafety.dat` | none | against the headers; the three bytearray `threadsafety.dat` levels need a human judgement |
| A9 | **typeshed** (separate project): `bytes.partition`/`rpartition` element type, `center` fillchar `bytes \| bytearray`, `bytes.__new__` keyword `source`. **Indep.** | typeshed `stdlib/builtins.pyi` | none | mypy repros in `reports/ws9.md` |

Issues to file rather than PRs (**Indep.**, from WS9): `bytes.partition` returns the
separator object itself (non-bytes in a "bytes" tuple); `b.hex(None)` error message;
`startswith` error message says "bytes" but accepts any buffer; test order dependency of
`test_dis`/`test_opt` specialization tests (README "Test status").  Not proposed: dropping
the bracket `@text_signature` of the find family (WS9 R1): the user decided to keep it
for `help()` parity.

## Part B: specs, level by level

| # | PR | files | deps | reviewers check |
|---|---|---|---|---|
| B1 | **Argument Clinic reads a spec file (level 1 machinery), with its first user `mmap`** (methods only, `#if`-guarded methods, output byte-identical) | `Tools/clinic/libclinic/pyspec/{__init__,frontend,runtime,specfiles,subset}.py` (front end only: signatures and docstrings), `Tools/clinic/libclinic/{dsl_parser,app,errors}.py` (the hook, `SpecError`), `Modules/pyspec/mmapmodule.py`, `Modules/mmapmodule.c` (one-line blocks), `test_clinic` `PyspecStubTest` and the signature part of `PyspecLanguageTest`, `Objects/pyspec/README.rst` (level 1 sections) | A3 | `Modules/clinic/mmapmodule.c.h` byte-identical; `make clinic` still the only generator; error messages point at spec lines |
| B2 | **The parity tool and record**, recorded for the types of B1 | `Tools/clinic/pyspec_parity.py`, `Lib/test/test_tools/test_pyspec_parity.py`, `Tools/clinic/pyspec-baseline/parity.txt`, `Modules/pyspec/mmapmodule_cases.py` (`TYPES`, `PARITY`) | B1 (finds types through the spec glob) | the record reproduces on main's CI configurations; a configuration without a block skips |
| B3 | **bytes level 1** (and the shared stringlib specs) | `Objects/pyspec/bytesobject.py` (every body `...`), `Objects/stringlib/pyspec/{transmogrify,ctype}.py`, `Objects/bytesobject.c`, `Objects/stringlib/transmogrify.h` (one-line blocks), `Objects/pyspec/bytesobject_cases.py` (`TYPES`, `PARITY`); record bytes in `parity.txt` **first**, in this PR or before | B1, B2 | `Objects/clinic/bytesobject.c.h` and `transmogrify.h.h` byte-identical; only blocks and `input=` checksums change in C |
| B4 | **Generated method and slot tables (level 2), for bytes and its iterator** | `Tools/clinic/libclinic/pyspec/{typeobj,slots}.py`, `test_clinic` `PyspecTypeTest`, `PyspecSlotdefsTest`, `Objects/bytesobject.c` (tables and `PyDoc_STRVAR` deleted, include of `clinic/bytesobject_pyspec.c.h` before `PyTypeObject`), `Objects/clinic/bytesobject_pyspec.c.h` | B3 | parity record unchanged; `nm -S` lists the same table symbols; the `PyTypeObject` is still hand-written |
| B5 | **bytearray levels 1–2** (shares the stringlib specs; ctype docstrings compiled per type) | `Objects/pyspec/bytearrayobject.py`, `_cases.py`, `Objects/bytearrayobject.c`, `Objects/clinic/bytearrayobject_pyspec.c.h` | B4 | `bytearrayobject.c.h` byte-identical; parity unchanged; +1.4 KB of docstrings (phase 3b) acceptable? |
| B6 | **The disconnect ratchet (level 5)** without `c_calls` | `Tools/clinic/libclinic/pyspec/disconnects.py` (capi, docs, slots, docstrings, typeshed), `Lib/test/test_pyspec_catalog.py`, `Tools/clinic/pyspec-baseline/{capi,docs,slots,docstrings,typeshed}.txt` | B3 (spec'd types); fixes from A7/A8 shrink its baselines | only deletions to baselines later; the typeshed dimension skips without a checkout |
| B7 | **`pyspec_review.py`** (one summary for reviewers) | `Tools/clinic/pyspec_review.py`, its tests in `test_pyspec_parity.py`, `Objects/pyspec/MIGRATING.rst` | B2, B6 | output of the review pasted in its own PR |
| B8 | **Spec bodies (level 3), small first: `bytes.__bytes__`, `bytes.fromhex`** | `Tools/clinic/libclinic/pyspec/{facts,partial_eval,known,marks,context,emit,ir,c_backend,builtin_types}.py`, `runtime.py` (`@native`, primitives), `subset.py` (lowered part), specs of the called C functions (`Objects/pyspec/{abstract,typeobject,unicodeobject}.py`, `Python/pyspec/errors.py`, `Include/cpython/pyspec/longintrepr.py` and their `_cases.py`), `test_clinic` `PyspecTest`, `PyspecFilesTest` (difftest), `PyspecNativeTest`, the lowered part of `PyspecLanguageTest`, the `c_calls` dimension (`CChecker`, `c_calls.txt`) | B4, B6 | generated C reviewed like hand-written C (spec lines named); difftest; `c_calls` 0; instruction counts per MIGRATING "Does a spec body help" |
| B9 | **`bytes.__new__` and `PyBytes_FromObject` from bodies**: per-arity entries, list/tuple specializations with the free-threaded snapshot, `@inline` fast paths | `Objects/pyspec/bytesobject.py`, `Objects/pyspec/abstract.py` (`@inline`), `Objects/bytesobject.c` (the C these replace deleted; appender pieces kept native), generated files, `bytesobject_cases.py` | B8 | the PGO+LTO table of `reports/phase4_P.md` redone on the PR; FT snapshot test (F1); parity unchanged except `C tp_vectorcall` (known) |
| B10 | **Call tables and the tier-2 consumer** (`_RECORD_ARG0_TYPE`, `_CALL_BUILTIN_CLASS_*_INLINE*`, `_CALL_METHOD_DESCRIPTOR_NOARGS`) | `Include/internal/pycore_pyspec.h`, `Tools/clinic/libclinic/pyspec/call_table.py`, `Python/bytecodes.c`, `Python/record_functions.c.h`, `Python/ceval.h` and `Tools/jit/template.c` includes, `Python/optimizer_analysis.c` helpers, `Python/optimizer_bytecodes.c` handlers, `Modules/_testinternalcapi.c` (pyspec part), `Lib/test/test_pyspec_facts.py` (`RegistryTest`, `DirectCallTest`, `HelperTest`, `SoundnessTest`), `test_clinic` `PyspecFactsTest`, `test_opt` | B9, A4, A5 | facts asserted in debug; each entry called directly; `test_opt` traces |
| B11 | **The no-Python tripwire** | `Include/internal/pycore_tstate.h` field, one line in `Python/ceval.c`, Enter/Leave/Check in `pycore_pyspec.h`, `_testinternalcapi.pyspec_no_python`, `DebugAssertionTest` | B10 | debug only; the decref assumption documented in `pycore_pyspec.h` |
| B12 | **Slot facts for the A6 uops** (`_PySpec_FindSlot`, `spec_slot_result()`, `SlotFactsTest`): `bytes.__getitem__`, `__len__`, `bytes_iterator.__next__` get `@native` references | `bytesobject.py`, `call_table.py`, `pycore_pyspec.h`, `optimizer_analysis.c`, `optimizer_bytecodes.c`, `test_pyspec_facts` | A6, B10 | table equals the derivation; uops agree with slots on all 256 values |
| B13 | **Devguide section** on spec files | devguide repo (`drafts/devguide_draft.rst`) | B1–B4 merged | matches `Objects/pyspec/README.rst` |

## Notes

- The split into B8/B9 follows `reports/review_int.md` section 5 item 11; B8 is the
  largest PR (the partial evaluator and emitter) and is where review effort goes.  If
  it is too large, B8 can land the reference/facts half (`@native`, `facts.py`,
  `c_calls`) with no generated body, since the facts of `@native` slots (B12) need no
  emitter.
- Every B PR after B2 must leave `parity.txt` untouched (or change it on purpose, with
  the reason) and include the output of `Tools/clinic/pyspec_review.py`.
- `pyspec-notes/` is experiment bookkeeping and is not part of any PR.
- Tool code in B1–B12 will shrink after the simplification pass (workstream S of phase
  4); the file lists above are those at `63ce50f2c9b`.

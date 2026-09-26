## Workstream E report: derived facts are now checked by the normal test suite

Everything asked for is done. There are 5 commits in worktree `/home/firebird347/projects/python/cpython/.claude/worktrees/agent-ac172a385fe667836` (branch `worktree-agent-ac172a385fe667836`, on top of 62cc16504fe). Nothing was rebased, amended or pushed.

| Commit | What |
|---|---|
| `c771db06606` | M4: debug-build fact assertions and the "no Python" tripwire |
| `5b8aea5742a` | M3: `_testinternalcapi` hooks that call call-table entries directly |
| `728908cf814` | New `Lib/test/test_pyspec_facts.py`: direct-call difftest, debug-assertion tests, soundness tests |
| `f043d455bcd` | F5: `_PySpec_CallNoPython1` removed from `NON_ESCAPING_FUNCTIONS` |
| `ffb3967dac3` | Test fix: a GC flake that showed up under `-R` |

**One test fails on purpose:** `SoundnessTest.test_fromhex_cls` (16 subtests), the F2 regression test. It needs A's F2 change; see "Still open" below.

### 1. M4: fact assertions in debug builds

**(a) Result assertions.**
- **Mechanism:** two tier-2 uops in `Python/bytecodes.c`, `_ASSERT_RESULT_TYPE` (checks `Py_IS_TYPE`) and `_ASSERT_RESULT_IS` (checks identity with an immortal constant).
  - `oparg` is the number of stack items above the result. They are replicated for 0–3 so the stack-cache variants exist.
  - They fail through `_PyObject_ASSERT_WITH_MSG`, which I added to `NON_ESCAPING_FUNCTIONS`; without that, the analyzer marked the uops as escaping, which would have kept extra `_SET_IP`s in debug traces.
- **Where they are emitted:** `assert_result_facts()` in `Python/optimizer_analysis.c` (+30 lines, `#ifdef Py_DEBUG` only; in release `ASSERT_RESULT_FACTS` is `((void)0)`). It first emits the call itself if the handler kept the original instruction, then the check. It is called from 8 places in `optimizer_bytecodes.c`:
  - the pyspec call and the alias in `_CALL_BUILTIN_CLASS`;
  - both branches of `_CALL_METHOD_DESCRIPTOR_NOARGS`;
  - `_CALL_STR_1`, `_CALL_TUPLE_1`, `_CALL_LEN` and the non-folded `_CALL_ISINSTANCE`.
- **The alias fact:** the call is removed there, so at run time only the exact type (the argument's type) is asserted. Identity is verified per entry by the M3 difftest.
- **test_opt:** `iter_opnames` in `test_opt.py` now skips `_ASSERT_RESULT_*` (+3 lines). test_opt passes: no existing case hits the `_CALL_STR_1` bug, so nothing in test_opt needed an expected-failure mark.
- **Demonstration**, `build-E/python bugreports/call-str-1-subclass/repro_type_check.py`. It aborts at the `str(c)` line, before `_POP_TOP_UNICODE`; `repro_del_skipped.py` aborts the same way:
  ```
  _ASSERT_RESULT_TYPE_1_r22.c:182: _JIT_ENTRY: Assertion "_Py_IS_TYPE_impl(...res..., type)" failed: the tier-2 optimizer's exact result type is wrong
  object type name: S
  File ".../repro_type_check.py", line 17 in f
  ```
  The same check is in my module as `test_call_str_1_subclass`, an expected failure pointing to the bug report.

**(b) The "no Python" tripwire** (+~45 lines in `pycore_pyspec.h`).
- `_PySpec_EnterNoPython()` / `_PySpec_LeaveNoPython()` save and set `_PyThreadStateImpl.pyspec_no_python`, a new debug-only field in `pycore_tstate.h` (+5 lines).
- `_PySpec_CallNoPython1()` now takes `tstate` and wraps the call in them.
- **One hook point:** `_PySpec_CheckPythonAllowed()` at the top of `_PyEval_EvalFrameDefault` (`ceval.c`, +1 line). Every Python function, slot wrapper into Python, generator, finalizer and trace hook runs through it; in release builds it expands to nothing.
- **Demonstration** with a deliberately wrong fact (the generic entry, which may run Python, called through the tripwire); covered by `test_no_python_tripwire`:
  ```
  Fatal Python error: _PySpec_CheckPythonAllowed: H.__bytes__ (<string>:4) runs inside a call that the pyspec facts say runs no Python code: a derived fact is wrong (see Include/internal/pycore_pyspec.h)
  ```

### 2. F5: I removed the `NON_ESCAPING_FUNCTIONS` entry
The alternative, a separate derived "does not escape" fact, needs new vocabulary in the stubs, derivation in `call_table.py` and a new flag, all to save a few instructions per call.

Release JIT builds, not PGO, instructions per call, best of 5, `PYTHONHASHSEED=0`, CPU 15, `performance` governor:

| Case | Entry kept | Entry removed |
|---|---|---|
| `bytes(bytearray16)` | 752 / 757 | 761 |
| `bytes(memoryview16)` | 740 / 745 | 749 |
| `bytes(range16)` | 2148 | 2157 / 2162 |
| `bytes(range256)` | 19668 | 19677 |
| `bytes(list16)` (control) | 1144 | 1139 / 1144 |

- The cost is about +9 instructions per call (about 1%). Cycles are unchanged within noise. This is half of WS10's estimate of 18.
- The trace gains a `_SET_IP` before the call and a `_CHECK_VALIDITY` after it.
- `_CALL_BUILTIN_CLASS_1_INLINE_NO_PYTHON` stays: it still skips the decref of the immortal class, and it is where the tripwire runs under the JIT.

### 3. M3: direct-call difftest
**Hooks** in `Modules/_testinternalcapi.c` (+~350 lines, `METH_VARARGS`, so no clinic changes):
- `pyspec_table(tp)`: the entries as dicts.
- `pyspec_find_call(tp, nargs, arg_type)`.
- `pyspec_find_method(tp, name, self_or_cls, nargs, arg_type)`.
- `pyspec_call(tp, index, args, no_python=False)` and `pyspec_call_method(tp, index, self_or_cls, args, no_python=False)`. Both refuse arguments the entry's guard rejects, so a typed variant is never called with the wrong type.

To link these, `_PySpec_bytes_calls` is now declared `PyAPI_DATA` in `pycore_pyspec.h`. The generator output is unchanged.

**Tests** in `Lib/test/test_pyspec_facts.py`; no JIT needed:
- **Inputs:** 109 positional inputs, `test_clinic.BytesSpecTest.CASES` (imported) plus 13 extra recording cases.
- **Pairs:** 159 (input, entry) pairs over all 12 call entries. Per entry: generic nargs1 101, list 25, tuple 8, range 6, memoryview 4, int 4, bytes 3, dict 3, bytearray 2, str 1, float 1, `bytes()` 1.
- **Method entries:** 40 pairs over all 13 method entries (`__bytes__` and `fromhex` with `cls=bytes`).
- **Each pair is checked for:**
  - the same outcome as the interpreter;
  - exact type, alias identity, constant identity and "always raises";
  - no Python run, seen by `sys.setprofile` and by recording special methods;
  - for no-Python entries, a second call through the tripwire.
- `test_find_call` checks that the entry the optimizer picks accepts the argument's exact type, and that an unknown type or a subclass gets the generic entry.
- **Result:** every entry agrees with `bytes()` and every claimed fact holds, with the JIT on and off, in debug and release.

### 4. Soundness regression tests (same module)
- **F2, `test_fromhex_cls`:** with `cls` = a plain subclass or `H` (whose `__new__` returns 42), the entry a consumer finds must have no false facts. It fails now (for H: `int is not bytes`).
  - I simulated your contract locally: typed entries match only `cls is bytes`, and the generic entry carries no facts. The test then passed. That edit was reverted.
- **F3, `test_static_type_rule`:** marked expected failure until P2. mappingproxy and `reversed` run `__len__` / `__iter__` in Python, yet the derivation claims no Python; PickleBuffer is claimed Python-free too.
  - `test_derivation_of_forwarding_types` is not marked expected failure, so if the analyzer API breaks it fails instead of hiding behind the expected failure.
- **F6, `test_codec_subclass_result`:** passes. It shows `bytes('x', codec)` and `str.encode` return a subclass, and checks that neither the `PyUnicode_AsEncodedString` stub nor the derived facts of `bytes(str, encoding)` claim an exact type.

### Verification
All on `/home/firebird347/projects/python/build-E` (`CC=clang --with-pydebug --enable-experimental-jit LLVM_TOOLS_INSTALL_DIR=/usr/lib/llvm21`):
- **Suites:** `-m test test_capi test_clinic test_bytes test_pyspec_facts -j4`: 2424 tests; everything passes except the 16 F2 subtests.
- **Leaks:** `PYTHON_JIT=0 -R 3:3` on `test_pyspec_facts`, `test_capi.test_opt`, `test_capi.test_bytes`, `test_clinic` and `test_bytes`, with `-i test_fromhex_cls` because a failing test never reaches the leak loop: SUCCESS. `test_pyspec_facts -R 3:3` with the JIT on: SUCCESS.
- **Regen:** `make regen-cases` leaves the tree clean.
- **Release unaffected** (`build-E-relbase` = 62cc16504fe vs `build-E-rel` = M4 + M3 + tests, both release JIT, not PGO):
  - **Object code:** normalized disassembly differs only in `_testinternalcapi`, and in uop-ID immediates in `optimizer*.o`, `jit.o` and `ceval.o` (one constant), because the new uops renumber the IDs. Nothing in the assertion or tripwire code is compiled in.
  - **Micro cases:** all 71 review_perf cases, JIT on and off: deltas are within the same-build repeat noise (up to about ±24 instructions; e.g. `contains` 2641 vs 2665 on the same build).
  - **Not strictly zero:** two cases show a consistent small drop: `center` −18 and `ref_str_hash` −5. Their functions' object code is identical in both builds, so I attribute it to layout. Data: `scratchpad/E/rel_delta.txt` and `noise.txt`.

### Edits outside my area
- `Include/internal/pycore_tstate.h`: +5, a debug-only field.
- `Python/ceval.c`: +1.
- `Lib/test/test_capi/test_opt.py`: the `iter_opnames` filter and one comment.

### Still open
- **F2 merge step:** in `Modules/_testinternalcapi.c` `pyspec_find_method`, the XXX line `(void)self_or_cls;` must pass `self_or_cls` to A's new `_PySpec_FindMethod`. The test fails until then.
- **Couplings with other workstreams:** the test imports `BytesSpecTest.CASES` from `test.test_clinic`, so B's restructuring may move it. The F3/F6 tests use A's `Analyzer.call`, `Facts`, `escape_facts` and `partial_eval.specialize`.
- **Tripwire limits:** it only sees Python frames. It does not catch escaping C code (the F5 kind), and it is per thread.
- **Alias under the JIT:** only the type is checked at run time; identity is checked by M3 alone.
- **Clean-up:** `build-E-relbase` (its source is `scratchpad/E/src-base` on tmpfs), `build-E-rel` and `build-E-rel-f5` can be deleted.

## Phase 3a report: bytes slot facts feed the new `b[i]` and `for c in b` specializations

**Summary:** `b[i]` and iterating an exact bytes are now specialized, and the tier-2 optimizer gets their result facts from the spec. Per operation this is 3× faster for `b[i]` and about 1.6× faster per item when iterating. On pyflate, instructions drop 3.1 % (exactly the estimated 107 M) and cycles drop about 1.2–2.2 %, but wall-clock time is only about −0.4 %, well short of the estimated 1.5–2 %. `==` was skipped. All requested tests pass and the tree is clean after regen-all. The exception is a new JIT-on `-R 3:3` failure in test_pyspec_facts (see open problems).

**Branch:** `worktree-agent-a020237e55ec39d41`, worktree `/home/firebird347/projects/python/cpython/.claude/worktrees/agent-a020237e55ec39d41`. It has 5 commits on 4e8812177fa, with nothing rebased, amended or pushed:
- `878570ea094` slot facts in the call table
- `9e605b2e0a3` BINARY_OP_SUBSCR_BYTES_INT and FOR_ITER_BYTES
- `a2330f26f54` SlotFactsTest
- `8a796a26b8d` README row
- `641237d3cd0` test tweak

### Where the facts live and how the spec links to the uops
1. **Spec** (`Objects/pyspec/bytesobject.py`, slot declarations only): `bytes.__getitem__` and `bytes.__len__` are now `@c_implemented`, with Python references that mirror `bytes_subscript` and `bytes_length`.
   - Derived for `(exact bytes, exact int)`: exact int, runs no Python, raises only IndexError (plus the generic MemoryError of `exact()`).
   - `bytes_iterator.__next__` already derived exact int, no Python.
   - `__len__`'s reference also restores the "lost fact" from P2 open item 6.
2. **Clinic** (`call_table.py` `generate_slots`, and `app.py`/`emit.py` pass the clinic class type objects): for every `@c_implemented` dunder that is a slot, it emits a `_PySpecSlot` table into `bytesobject_pyspec.c.h`.
   - Each entry covers self of exactly the class. There is a generic entry, plus one per exact type of the argument after self whose facts differ, unless that type always raises.
   - `Include/internal/pycore_pyspec.h` gains `_PySpecSlot`, the `.nslots`/`.slots` fields and `_PySpec_FindSlot(tp, "__getitem__", arg_type)`.
3. **Uops** are hand-written copies of the slot's C, inline and non-escaping, modelled on STR_INT and TUPLE:
   - `_GUARD_NOS_BYTES` and `_BINARY_OP_SUBSCR_BYTES_INT`. It exits on a negative, non-compact or out-of-range index, so IndexError always goes through the generic path.
   - `_ITER_CHECK_BYTES`, `_ITER_JUMP_BYTES`, `_GUARD_NOT_EXHAUSTED_BYTES` and `_ITER_NEXT_BYTES`.
   - The new instructions are `BINARY_OP_SUBSCR_BYTES_INT` and `FOR_ITER_BYTES`, wired into `specialize.c`, `optimizer.c` and `tier2_generator.py`.
4. **Optimizer:** `spec_slot_result()` in `optimizer_analysis.c` takes the result type from `_PySpec_FindSlot`; it is not copied into `optimizer_bytecodes.c`.
   - Compactness is added on top ("a byte is a small int"). It comes from the uop's own code, because the facts vocabulary has no value range. This is the one hand-written claim.
   - Downstream `_GUARD_*_INT` guards are removed, and `ASSERT_RESULT_FACTS` follows both uops.

**Why this is the smallest honest link:** the uop cannot call the slot and still be fast. So the specializer's fast path stays hand-written, and three checks keep it tied to the spec:
- the result facts come from the table derived from the spec;
- a test checks that the table equals the derivation and that each uop agrees with its slot;
- debug builds assert the facts at run time.

A deliberate wrong fact (`exact(bool, …)` in `__getitem__`) was caught by `_ASSERT_RESULT_TYPE` ("the tier-2 optimizer's exact result type is wrong"), and the reference's `exact()` check fails too. It was reverted.

### Tests added
- **HelperTest:** 19 `bytes.__getitem__` cases and 3 `bytes.__len__` cases, difftested against the references with the "no Python" tripwire. They cover bools, int subclasses, `__index__` objects, huge values, slices, bad types and a bytes subclass.
- **SlotFactsTest:**
  - the table equals `reference_facts`;
  - neither uop has `HAS_ESCAPES_FLAG`, justified by the spec's no-Python facts;
  - all 256 byte values at indices −257..257, empty bytes, and iteration agree with the slots, with immortal exact ints;
  - the debug-JIT trace has `_ASSERT_RESULT_TYPE` after each uop.
- **Elsewhere:** `_testinternalcapi.pyspec_find_slot()`, two test_opt tests (guard removal) and two test_opcache specialization tests.

### Numbers
PGO+LTO release JIT builds with the same flags as `build_perf_base_jit` (plus `LLVM_TOOLS_INSTALL_DIR`): `3a-perf/build-before` (4e8812177fa) and `build-after` (a2330f26f54). Governor was `performance`.

**Micro** (review_perf `measure.sh`, instructions/cycles per iteration, before → after):

| op | JIT on | JIT off |
|---|---|---|
| `b16[i]` | 304/60 → 207/42 (net 141 → 44 instr) | 322/63 → 228/45 |
| `for j in r16: t += b16[j]` | 5447/1069 → 3799/766 | 6293/1798 → 4797/1003 |
| `for c in b16` | 1652/333 → 1109/205 (93 → 59 instr per item) | 1454/424 → 1164/222 |
| `for c in b256` | 20855/4203 → 14312/2639 | 19940/5381 → 15570/2927 |
| `iter16_sum` | 3236/663 → 2581/500 | 3657/833 → 3361/703 |

- `==`, slice, `in` and the list/str references are unchanged.
- All bytes() shapes, `__bytes__` and `len` have identical instruction counts (±5).
- Two cycle outliers in the first pass (`dunder_bytes` 46 → 72, `len` 54 → 102) were machine load: on rerun they were 46 → 48 and 55 → 56.
- Raw data: `scratchpad/3a/micro.txt`.

**pyflate under perf stat** (`scratchpad/3a/perfstat.sh`, one benchmark loop, pinned, repeated twice):
- JIT on: 3457 → 3348 M instructions per loop (−3.1 %, exactly the estimated 107 M); cycles 892/900 → 881/880 (−1.2 to −2.2 %).
- JIT off: −2.3 % instructions, cycles within noise.
- Control richards: 201.4 M instructions in both builds, cycles within ±1 %.

**pyperformance, wall clock:**
- The first full A/B/A/B plus JIT-off run was unusable: other agents pushed the load average to 7, and A/A spread reached ±29 %. I discarded it.
- On a quiet machine (load about 1):
  - pyflate `--rigorous`, two A/B pairs of 120 values each: 162.13/162.27 → 161.50/161.69 ms, about −0.4 % and consistent, but inside the ±1–2 % A/A noise.
  - dulwich_log, three pairs: +0.8 %, which is noise.
- I did not re-run base64 or nbody on the quiet machine.

### Test results (debug JIT, `/home/firebird347/projects/python/build-3a`)
- **Pass:** test_bytes, test_clinic, test_pyspec_facts, test_pyspec_catalog (c_calls 0), test_dis, test_opcache, test_iter, test_capi.test_opt and test_generated_cases (`-j4`, 1567 tests).
- **test_capi alone:** passes (1589).
- **JIT off:** test_opcache, test_dis, test_pyspec_facts and test_bytes pass.
- **`PYTHON_JIT=0 -R 3:3`** on test_pyspec_facts, test_pyspec_catalog, test_bytes, test_clinic and test_opcache: passes.
- **Regen:** `make regen-cases` and `make regen-all`, plus clinic on `Objects/bytesobject.c`, leave the tree clean.
- **The PGO profile run** (the test suite) passed for both release builds.

### Open problems
1. **JIT-on `-R 3:3` on test_pyspec_facts fails; base passes.**
   - It reports [726, 337, 199] references. With `-R 3:12` it decays to noise ([…, 0, 116, 142, 190, 10, 19]), which looks like JIT warm-up of the HelperTest/SoundnessTest reference functions rather than a steady leak. It only appears when HelperTest runs with SoundnessTest, and base shows the same erratic "fine" counts.
   - Separately, fresh functions that get JIT-compiled leak a few memory blocks per repetition for list and tuple as well as bytes. That part is pre-existing, and I moved the test loops to module level because of it.
   - This is probably the same class as README open item 1. I did not investigate it further.
2. **End-to-end gain is below the estimate:** instructions −3.1 % and cycles about −1.5 % by perf stat, but only about −0.4 % in pyperformance wall clock.
3. **No magic-number bump** for the two new specialized opcodes. Base opcode numbers are unchanged; upstream usually bumps.
4. **The free-threaded build was not built or tested.** Bytes are immutable, so no locking is needed.
5. **COMPARE_OP_BYTES (`==`) skipped:** the gain is below noise end to end (review estimate 0.3–0.5 % of dulwich). It would also need a `__eq__` reference that covers the whole `bytes_richcompare` group, including the BytesWarning path, and an exported `_PyBytes_Equal`.
6. **Compactness of the result** is a uop claim, not a spec fact; the facts vocabulary has no value range.
7. **`_PySpec_FindSlot`** looks at `_PySpec_bytes_calls` only; each future spec file needs one line there.

### On the coordinator's heads-up (@static_type removal)
- Nothing I did uses the generated PyTypeObject, `@static_type` or typeobj.py.
- The slot table takes bytes' type object from `builtin_types.TABLE` and bytes_iterator's from the clinic class directive (`class bytes_iterator "…" "&PyBytesIter_Type"`), so that directive must stay.
- One knock-on effect: once `@static_type` is gone, `TypeFacts.spec_class(bytes)` returns None, so bytes' special methods come from the TABLE row (`'__len__': int`) instead of the spec. The derived slot table should stay the same, since the facts key ignores `raises`. 3b should still re-run `test_pyspec_facts` SlotFactsTest and HelperTest after merging.

### Files
- **Main code:**
  - `Tools/clinic/libclinic/pyspec/call_table.py`
  - `Include/internal/pycore_pyspec.h`
  - `Objects/pyspec/bytesobject.py`
  - `Python/bytecodes.c`
  - `Python/optimizer_bytecodes.c`
  - `Python/optimizer_analysis.c`
  - `Python/specialize.c`
  - `Lib/test/test_pyspec_facts.py`
- **Scratch:** scripts and data are in `/tmp/claude-1000/-home-firebird347-projects-python/2290c1d8-9873-48d1-a600-904f809b5565/scratchpad/3a/`: `micro.txt`, `perfstat_*.txt`, `pyperf/`, and the tmpfs sources `src-before` and `src-after` that the release builds need.
- **Builds** (under `/home/firebird347/projects/python/`):
  - `build-3a`: debug JIT build of the branch.
  - `build-3a-base`: debug JIT build of 4e8812177fa, made for the leak comparison; safe to delete.
  - `3a-perf/build-before` and `3a-perf/build-after`: the PGO release builds.

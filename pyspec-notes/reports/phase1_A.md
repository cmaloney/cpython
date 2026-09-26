## Workstream A (performance): report

**Result:** every `bytes()` call shape is now well below main in instructions and cycles, with the JIT on and off.
- `bytes(list256)` is now **-25 % instructions and -29 % cycles** (it was +28 % / +38 %).
- `Sub(b)` is -21 %, and `Sub.fromhex` is -10 %.
- F1, F2 and F4 are done and verified.
- Bytes code is 5.5 KB smaller than at 62cc16504fe, but still 1.3 KB above main.
- Two things fall short of the brief: tool code grew by about 600 lines net instead of shrinking, and a few `fromhex`/`in` shapes measure +1 to 3 % in my final build. The first is explained in "Rules added" below; the second is PGO/LTO noise, explained under "Remaining differences".

- **Worktree branch:** `worktree-agent-a04cd2c8ab8f08e5b`, on 62cc16504fe. 10 commits, no rebase, no amend, nothing pushed:
  - 049b9010e1a appender: the struct is never passed through memory (E1)
  - 9dda4a07628 F4
  - e164b90c844 F2, and the dict/float variants are dropped
  - 78d32701d60 shared loop specializations and the derived list snapshot (bulk of #1, F1 and the code sharing)
  - af2e42c3052 versioned `__bytes__` lookup (the `Sub(b)` fix)
  - 04ee520513b a specialization is emitted only when it iterates by index
  - 63a6ad26536 fast paths for arguments whose exact type is known (`bytes(16)`)
  - e28db5d4df2 `bytes_new_impl()` calls `bytes_new_nargs1()` for the rest of its body
  - 113facd3cfd a spec comment
  - bf74d29f123 "pyspec: make comments match the code" (your request)

### Micro table
Values are main / 62cc16504fe / HEAD, per loop iteration: instructions, then minimum cycles.
- **HEAD build:** my PGO+LTO release JIT build (h4b, same flags as `build_perf_base_jit` plus `LLVM_TOOLS_INSTALL_DIR`), from a `git archive` of e28db5d4df2. The only later source change that isn't a comment is the one-line `capi.py` check, which is used only by the catalog tests, not by the build.
- **Method:** review_perf's `measure.sh`, CPU 15, `performance` governor, load average 1.2 to 1.9 while measuring.
- **Full table:** all 70 shapes are in `scratchpad/perf/table2.md`; raw data is in `full2.txt`.

| shape | JIT on instructions | JIT on cycles | JIT off instructions | JIT off cycles |
|---|---|---|---|---|
| `bytes(list16)` | 1329 / 1088 / 798 | 250 / 222 / 157 | 1331 / 1273 / 1018 | 244 / 247 / 190 |
| `bytes(list256)` | 6849 / 8772 / 5124 | 1227 / 1682 / 872 | 6845 / 8711 / 5336 | 1224 / 1669 / 909 |
| `bytes(tuple16)` | 1333 / 998 / 802 | 249 / 215 / 160 | 1335 / 1182 / 1019 | 242 / 222 / 193 |
| `bytes([T,F]*8)` | 1330 / 1136 / 851 | 252 / 219 / 174 | 1331 / 1338 / 1065 | 246 / 261 / 200 |
| `bytes(range256)` | 25572 / 18755 / 15412 | 5149 / 4266 / 3000 | 25574 / 16673 / 15642 | 5140 / 3306 / 3043 |
| `bytes(b16)` | 923 / 219 / 218 | 187 / 43 / 43 | 947 / 728 / 386 | 192 / 152 / 73 |
| `bytes(16)` | 900 / 449 / 443 | 169 / 93 / 92 | 902 / 702 / 693 | 164 / 133 / 132 |
| `Sub(b16)` | 1332 / 1379 / 1058 | 269 / 277 / 201 | 1308 / 1353 / 1034 | 270 / 278 / 196 |
| `Sub.fromhex` | 2554 / 2610 / 2291 | 526 / 536 / 448 | 2460 / 2508 / 2214 | 508 / 509 / 440 |
| `bytes(set8)`, `bytes(dict8)`, `bytes(gen())`, `bytes(iter(l16))`, `bytes(sub)`, `bytes(obj with __bytes__)`, `bytes(s, …)` | -13 to -38 % | similar | -12 to -35 % | similar |

**Remaining differences, all outside bytes code I changed:**
- **Build-to-build variance.** Two PGO builds of the *same* commit (h4 and h4b) differ by up to 24 instructions on `int('12')`, `hex`, `decode` and `replace`, and by 43 on `bytes.fromhex` (1523 in h4, below main's 1540; 1566 in h4b). That brackets the +1 to 3 % seen on the `fromhex` family, `center`, `hash` and the reference shapes.
- **`x in b16`: +52 instructions in both builds.** All of it is inside `unicode_from_format` (unicodeobject.c, untouched), so it is inliner code generation.
- **JIT-off tier-1 loop cycles.** This is review §4's layout artifact again. With identical instructions, h4 measured the empty loop at 46 cycles and `for c in b256` at 5038, while h4b measured 26 and 3932 (main: 3931). The table uses h4b; what remains there is +0 to 8 % on small ops, which is within noise.

### Rules added (emitter and evaluator)
1. **E1: the appender never goes through memory.** The out-of-line helpers take and return only the cursor pointers, which travel in registers. A three-pointer struct is passed through memory, which forced the cursor onto the stack in every loop.
2. **Shared specializations.** A tail call whose specialized body contains a loop becomes one C function per (function, facts), shared by every caller. A loop costs far more than a call. A per-type entry that would only call it points at it directly. A specialization that doesn't iterate by index (range) is not emitted: the call keeps the generic function, with the specialized facts.
3. **Snapshot, for F1 and item (b).** In a list loop, every statement that may run Python (per `call_table.Analyzer`) becomes `return FALLBACK`. The Python-free rest runs under `Py_BEGIN_CRITICAL_SECTION(list)`. On FALLBACK it restarts through the generic iterator function, which is main's `_PyBytes_FromSequence_lock_held` structure, derived rather than hand-written.
   - "Borrowed until Python may run" follows from this: items are borrowed only in the snapshot and in tuple loops, and the size and item array are read once.
   - Every path that may run Python restarts through the generic function instead of taking a reference in place. The general incref-on-that-path lowering is not needed for bytes, so I didn't add it.
4. **Escape fast paths, items (d) and (e).** `Escape.fast` is a guard plus a lowering that cannot fail. For `PyNumber_AsSsize_t` the guard is `(PyLong_CheckExact || PyBool_Check) && _PyLong_IsCompact`: one branch covers bool and int, and there is no `-1`/`PyErr_Occurred` check. It is applied in loops, and outside loops when the argument's exact type is known.
5. **Exact-type lowerings, item (c).** An exact-type lowering cannot fail; `PyObject_LengthHint` of an exact list or tuple becomes `Py*_GET_SIZE`.
6. **Capacity, item (f).** A buffer sized from a sequence's length, appended at most once per iteration of a loop that cannot run longer (a tuple, or a snapshot list), uses `bytes_appender_append_unchecked`. The resulting loop is 18 instructions per item, against 23 on main.
7. **`__bytes__` lookup versioning.** The lookup is versioned for the spec types whose method is provably pure: `if type(x) is bytes: return x`. The later exact-bytes test is folded away.
8. **Fall-through facts and arity calls.** After an `if` whose one branch exits, the other branch's facts hold. Where the rest of a `__new__` body is exactly an arity function, the body calls that function.

**Lines of tool code:** +979 / −209 across `Tools/clinic/libclinic/pyspec`. Most of the additions are in `partial_eval.py` (+655/−97), much of it docstrings. The generated `bytesobject_pyspec.c.h` went +251/−765.

### Code size (release PGO+LTO)
| build | `.text` | bytes code |
|---|---|---|
| main | 4,250,851 | 67,784 |
| 62cc16504fe | 4,303,987 | 74,573 |
| HEAD | 4,288,115 | 69,067 |

- `PyBytes_FromObject` 1535 → 309 bytes, `bytes_new_nargs1` 2440 → 976, `bytes_new_impl` 904 → 315.
- The list/tuple/dict/float/range variants are gone. What replaces them: `bytes_from_iterator_list` (447, snapshot inlined), `_tuple` (336), and a 69-byte range entry.
- The remaining +1.3 KB against main is mostly clinic's `bytes_vectorcall` plus `bytes_new_helper` (1 KB), which is generic clinic output.

### Code-size pruning of the `fromhex` entries
The entries dropped from 11 to 8 typed ones, not to zero. Under the agreed F2 contract (no new field or flag), they are the only place the exact-bytes facts for `cls is bytes` can live, because the generic entry must now hold for any class. They are data, not code.

### F1 evidence
- `ft_snapshot.py`, three runs on my free-threaded debug build: torn results `[0, 0, 0]` every time. The review's 62cc16504fe FT build gives `[3000, 3000, 3000]` and main gives `[0, 0, 0]`.
- `scratchpad/ft_stress.py`: 4 readers against 2 writers that append, pop, clear and splice in `__index__` objects, int subclasses, big ints and bools. Three 10-second runs were clean, with no assertion failures.
- FT build: test_bytes, test_free_threading, test_clinic and test_capi.test_bytes pass.

### F2
- **Signature change:** `_PySpec_FindMethod(tp, meth, self, nargs, arg_type)`, as agreed with E. For a class method, the typed entries match only when `self == tp`; otherwise the generic entry is returned, now derived for any class ("result type not known exactly; may run Python code").
- **Class-method detection:** read from `tp_methods` (`METH_CLASS`), so the table has no new field.
- **Outside my area:** the existing caller in `optimizer_bytecodes.c` now passes `NULL` (one line), and `optimizer_cases.c.h` is regenerated.
- **Tests:** `test_fromhex_table` checks the generated entries, and `test_fromhex` checks that `H.fromhex` can return 42.

### F4
- Facts about builtin types now come from the spec's `@static_type` classes and one table, `partial_eval.BUILTIN_TYPES`: bases, plus `__buffer__`, `__bytes__` and `__index__`. They are no longer read from the host.
- `test_builtin_type_facts` checks the table against the Python being built.
- `test_independent_of_host` regenerates bytesobject.c with `hasattr` patched to act like a 3.11 host and requires identical output. That test fails on the old evaluator.
- `host_dependence.py` now gives `_PyBytes_FromBuffer` for memoryview on both the current and the simulated old host.

### `Sub(b)` root cause
The +54 instructions come from call structure. PGO leaves `bytes_new_helper` (clinic) out of line, and `bytes_new_impl` recurses on itself: about 26 instructions of prologue and epilogue per level. On top of that, every call pays for the `__bytes__` lookup, the bound-method creation and the call on an exact bytes object. Rule 7 removes that last part, which is why the shape ends up 21 % below main.

### Verification (debug JIT build `build-A`)
- test_clinic, test_bytes, test_capi, test_inspect and test_iter: 2870 tests, all pass.
- `PYTHON_JIT=0 -R 3:3` on test_clinic, test_bytes and test_capi.test_bytes / test_opt / test_pyspec_catalog: no leaks.
- Clinic on bytesobject.c, bytearrayobject.c and transmogrify.h, and `make regen-cases`, both leave the tree clean.
- About 20 new difftest cases: fallback and restart, error order, non-compact ints, 10k-item lists, tuples whose items run Python, and `Sub(x)` sources. Also new facts tests for the snapshot, unchecked appends, lookup versioning and the arity call.

### Edits outside my area (all minimal)
- **`capi.py` (D):** two lines, so `_outcomes` treats a return of a specialization as an iteration. And the `__pyspec_helper__` check became "skip the names of escapes", so `@helper` could be deleted in my tree. D's moved catalog supersedes both on merge.
- **`pycore_pyspec.h`:** `_PySpec_FindMethod` as above.
- **`optimizer_bytecodes.c` (E):** one argument, plus the regenerated `optimizer_cases.c.h`.
- **test_clinic (B's structure):** new test methods and cases only.
- **bytesobject.c:** the `pycore_critical_section.h` include is restored (main had it).

### Stale comments fixed (bf74d29f123)
- **`@helper`:** removed the decorator, its `__all__` entry, its five uses and the spec's Escapes header text about it.
- **Escape stubs:** `bytes_appender_finish` now says `Steals`, matching its escape; `bytes_appender_append` documents the unchecked lowering.
- **runtime.py:** it said the vocabulary is read by "capi.py from the AST"; it now says Argument Clinic reads it from the AST and the catalog check executes the spec.
- **emit.py and call_table.py:** no longer say "clinic block `bytes.__new__ as bytes_new`"; `describe_method` loses its workstream-status note.
- **partial_eval.py:** "the list size is read again for every item" is no longer claimed for snapshots; the module docstring describes outlining, lookup versioning and arity calls; the evaluator no longer depends on `Spec.clones`.

### Open problems
- **Build variance:** two PGO builds of the same source vary by ±1 to 3 % in instructions on unrelated shapes and up to +28 % in JIT-off loop cycles. Any "at or below main" claim for those shapes is within that noise.
- **Merge overlap:** the `_PySpec_FindMethod` signature change and the `capi.py` lines overlap with E's and D's work; expect small conflicts.
- **Possible next lever:** `bytes(16)` still says "may run Python", because the `except TypeError` fallback isn't provably dead for an exact int.

Everything is in the scratchpad at `/tmp/claude-1000/-home-firebird347-projects-python/2290c1d8-9873-48d1-a600-904f809b5565/scratchpad/`:
- `perf/table2.md` (full table), `perf/full2.txt` (raw), `perf/cyc1.txt` (h4 vs h4b cycles)
- `ft_stress.py`
- Builds: `/home/firebird347/projects/python/A-perf/{h1,h2,h3,h4,h4b}`, `build-A` (debug JIT) and `build-A-ft` (FT debug).
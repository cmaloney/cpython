# Phase 4 E (phase 2): interpreter cleanups, free-threaded re-test, upstream split

Base `ccc530c947e`. Build `../build-p4-e` (debug JIT), `../build-p4-e-ft`
(free-threaded debug, this branch), `../build-p4-e-ft-main` (free-threaded
debug, `cpython-base` = merge base `ee1bbf037ff`).

## Commits
- `817c96e6f50` optimizer: pyspec call handling in named helpers
- `8123708be12` pycore_pyspec.h: document the tripwire's decref assumption
- `192be937633` pyspec tests: assert only what matters
- `c90cfa71947` pyspec baselines: headers name what is checked
- `d7561e995b8` parity.txt: free-threaded debug block
- `f1041c85d36` test_opt: tests of the `_ASSERT_RESULT_*` and `_POP_TOP_OPARG` changes alone

## 1. Optimizer readability (behaviour identical: every exact-uop test passes unchanged)
- `_CALL_BUILTIN_CLASS` shrinks from about 90 lines to 40. It is one `if` chain over
  helpers in `optimizer_analysis.c`:
  - `find_spec_class_call()`: lookup, plus speculation on the recorded type with `_GUARD_TYPE`.
  - `fold_spec_class_call()`
  - `alias_spec_class_call()`: the handler still updates the two stack slots, so the swap is visible.
  - `direct_spec_class_call()`
  - `spec_call_result()`: constant, else type, else not-null. `_CALL_METHOD_DESCRIPTOR_NOARGS` shares it.
- `_CALL_METHOD_DESCRIPTOR_NOARGS` checks the descriptor once (a `method` local).
- `keep_this_instr()` names the rule that "a handler that emitted nothing keeps
  `this_instr`". `assert_result_facts()` and the optimizer loop both call it.
  `assert_result_facts()` also says that it skips the check when the buffer is full.
- `spec_slot_result()` loses `bool byte`. The two byte uops call
  `sym_set_compact_int()` at the call site, with a comment saying this comes
  from the uop's code, not from the spec. Side effect (item 7): with no spec
  entry, the result is still a compact int.
- `Tools/jit/template.c`'s `#include "pycore_pyspec.h"` is **not redundant**.
  Compiling a stencil of `_CALL_BUILTIN_CLASS_{0,1}_INLINE*` without it fails
  (`_PySpecFunc0/1` undeclared). No header that template.c includes pulls it in;
  `ceval.h` does that for ceval.c only. Kept.

## 2. Tripwire
- Documented in `pycore_pyspec.h`: the tripwire treats every decref as running
  no Python, as the C-side check does. A `__del__` or weakref callback run
  inside such a call would be a debug-only fatal error, not a wrong
  optimization: the uops still escape, so no symbol kept across the call
  depends on it. Edit outside my files (A's header), comment only.
- `pyspec_no_python` placement is correct. gh-144438's `char __padding[64]` is
  the last member, to keep *the fields above it* (thread-owned) off cache lines
  of other allocations. The field is thread-owned and sits above the padding,
  as it should. Unchanged.

## 3. Brittle tests
- test_opt: `pops_after()` checks that the first two pops after `_SWAP_3` are
  `_POP_TOP_NOP`. The descriptor test checks that `_MAKE_HEAP_SAFE` comes
  between `_COPY_1` and `_SWAP_3`. Neither assumes adjacency.
- test_pyspec_facts: the tripwire message is checked with a regex, without its
  line number. `test_uops_do_not_escape` uses the cases generator's
  `analyze_files()` (`properties.escapes`) instead of grepping
  `pycore_uop_metadata.h`.
- test_clinic `test_types_mismatch` (it had become line surgery on the real
  spec) now builds a class from each spec'd type: a stub per wrapper and
  method. It checks "missing" and "extra", with a control that the unchanged
  class passes the slot check.

## 4. Stale items
The `capi.txt` header no longer names `Objects/pyspec/capi/`, and `docs.txt`
no longer names bytes. No other stale references in my files.

## 5. Magic number: no bump needed on this branch; bump in the upstream PR
- Only specialized opcodes (129 and up) were renumbered. Base opcodes and
  `Lib/opcode.py` are unchanged, and the compiler is untouched.
- Specialized opcodes never reach a .pyc: `marshal` writes
  `_PyCode_GetCode()`, which deoptimizes. Checked: after `f` specializes to
  `FOR_ITER_BYTES`/`BINARY_OP_SUBSCR_BYTES_INT`, `marshal.dumps(f.__code__)`
  is byte-identical to before. `importlib` only compares the magic.
- Upstream still usually bumps for specialized-only additions: 3657 USTR_INT,
  3659, 3665, 3666, `3893a92d956`, `c13e7d98fb8`. Exceptions are
  `5529213d4ef` (list slice) and `5d3201fe3f7` (shadowed LOAD_ATTR).
- Recommendation: add the bump (next number, upcoming alpha tag) in the
  upstream specialization PR. A bump here would only conflict with every
  upstream bump.

## 6. Free-threaded
- `build-ft` diagnosis (read-only): `pybuilddir.txt` is missing, and since
  gh-151544 getpath needs it (no landmark fallback), so `sys.prefix` falls back
  to `/usr/local`. With `PYTHONPATH` given, the binary runs. Other findings:
  - It is not main. Its srcdir is `../cpython` (branch `exp/...`), and the
    binary is `gh-158219-bytearray-stale-hash-dirty:bfb322e5b2f` from Sep 25.
  - It was reconfigured at 00:58 and a rebuild stopped at 01:37 (only
    `bytesobject.o` is newer).
  - The `pybuilddir.txt` rule deletes the file when `generate-posix-vars`
    fails, which is the likely cause.
  - Fix: `make` there. Not touched.
- Branch FT debug build:
  - test_bytes, test_pyspec_facts, test_clinic, test_capi.test_opt, test_opcache,
    test_mmap, test_pyspec_catalog and test_generated_cases pass (no tier 2
    there: 330 skips).
  - test_pyspec_parity passes with `PYSPEC_PARITY_BASELINE=../build-p4-e-ft-main/python`.
    It **errors** with the GIL baseline (different configuration): the test
    should skip instead (D's file, not changed).
- F1 holds: `ft_snapshot.py` gives torn results `[0,0,0]` three times; main FT
  gives `[0,0,0]`.
- The FT debug parity block was captured with main FT (`check --update`). The
  branch FT build matches it.
- There is no separate test_bytearray; bytearray tests are in test_bytes.
- `cpython-base` has no new files; its version string already said `-dirty`.

## 7. Upstream split (each its own PR; generated files regenerated in each)
1. **`_CALL_STR_1` fix** (local branch `fix-call-str-1-subclass`, `969928f3ba2`):
   - `optimizer_bytecodes.c` `_CALL_STR_1` (exact int/float only)
   - `optimizer_cases.c.h`
   - 3 test_opt tests
   - NEWS `QCJD0g`
   The `ASSERT_RESULT_FACTS` line belongs to PR 3. Companion: `fix-pylong-str-exact`
   (longobject.c, test_int, NEWS `pylStr`). No dependencies.
2. **Clinic message format** (`e96b995a261`, part):
   - `errors.py` `ClinicError.report()` (`path:line: error: msg`)
   - `warn_or_fail` `end=""`
   - the `test_non_ascii_character_in_docstring` hunk
   `SpecError`/`SpecErrorKind` and the `app.py`/`dsl_parser.py` hunks are pyspec. No dependencies.
3. **Debug `_ASSERT_RESULT_*`** (`c771db06606`, part):
   - `bytecodes.c`: the two `replicate(0:4)` uops
   - `analyzer.py`: `_PyObject_ASSERT_WITH_MSG` non-escaping
   - `optimizer_analysis.c`: `keep_this_instr`, `assert_result_facts`, the macro
   - `ASSERT_RESULT_FACTS` lines in `_CALL_STR_1`, `_CALL_ISINSTANCE`, `_CALL_TUPLE_1`, `_CALL_LEN`
   - test_opt: the `iter_opnames` filter and `test_call_len_result_type_asserted`
   Independent (conflicts textually with PR 1 only).
4. **`_POP_TOP_OPARG` `_NOP`** (from `ad1c4836588`):
   - the 3-line hunk in `optimizer_bytecodes.c` and `optimizer_cases.c.h`
   - `test_call_builtin_class_no_args_pops_nothing`
   Independent.
5. **`BINARY_OP_SUBSCR_BYTES_INT` / `FOR_ITER_BYTES`** (`9e605b2e0a3`):
   - `bytecodes.c` (the ops, macros and family entries)
   - `specialize.c`
   - `optimizer.c` (replacement, `is_for_iter_test`)
   - `tier2_generator.py`
   - `optimizer_bytecodes.c`: `_GUARD_NOS_BYTES`, `_ITER_CHECK_BYTES`, and
     `res`/`next = sym_new_compact_int(ctx)` instead of `spec_slot_result`
   - tests in test_opt and test_opcache
   - magic bump and NEWS
   Independent. The later pyspec PR swaps in `spec_slot_result()` and keeps
   `sym_set_compact_int()`.
6. **pyspec call tables + `_RECORD_ARG0_TYPE` + direct-call uops** (`ad1c4836588`, `367c05639bd`, `e164b90c844`, `f043d455bcd`):
   - `pycore_pyspec.h`
   - `bytecodes.c`: the three `_CALL_BUILTIN_CLASS_*_INLINE*` uops, `_RECORD_ARG0_TYPE`, the macro
   - `record_functions.c.h`
   - `ceval.h` and `template.c` includes
   - the helpers in `optimizer_analysis.c`, the `_CALL_BUILTIN_CLASS`/`NOARGS`/`_RECORD_ARG0_TYPE` handlers
   - generated `*_pyspec.c.h`
   Depends on clinic's pyspec generator and on PRs 3 and 4 (its tests use both).
7. **No-Python tripwire** (`c771db06606` + `5b8aea5742a`, part):
   - `pycore_tstate.h` field, `ceval.c` line, Enter/Leave/Check in `pycore_pyspec.h`
   - `_testinternalcapi.pyspec_no_python`, `DebugAssertionTest`
   Depends on 6 (its only user is `_NO_PYTHON`).

## Tests (debug JIT build)
- The PHASE4 list plus test_capi.test_opt: 1448 tests pass.
- `PYTHON_JIT=0` test_pyspec_facts and test_capi.test_opt pass.
- `pyspec_review.py --baseline build-str1-dbg/python`: OK (87,737 lines identical).
- Clinic on the 7 files and `make regen-cases` leave the tree clean.

# Phase 5 fix wave: interpreter side (2026-09-28)

Branch base `0ba52ad421a`; debug JIT build `../build-p4-fi`, release non-PGO JIT
build `../build-p4-fi-rel` (both clang 21, srcdir this worktree).

## Commits
1. `_testinternalcapi`: `_PyLong_IsCompact`/`_PyLong_CompactValue` called through
   `PyObject *` wrappers (the table's other five helpers already take `PyObject *`;
   the call-table `f0`/`f1` members are assigned without casts, so the compiler checks
   them).
2. `test_clinic`: the four pyspec tests capture (stdout, where clinic's `warn()`
   prints) and assert the "Destination buffer 'buffer' not empty" warning.  Two
   warnings about buffer `'block'` remain; they come from the upstream
   `ClinicWholeFileTest.test_deleter`/`test_setter_deletion_check`.
3. `test_pyspec_facts`: `test_uops_agree` asserts the specialized instruction that
   contains the uop ran (from the cases generator's analysis of `bytecodes.c`) and,
   with the JIT on, that the uop is in an executor; `test_uop_names_the_slot` reads the
   uop body through `analyzer.analyze_files(optimizer_bytecodes.c)` and checks the
   arguments of its `spec_slot_result()` call (class, `_PySpec_SLOT(member)`, argument
   type); `test_find_call` asserts the generic entry.
4. `bytecodes.c`: `_CALL_BUILTIN_CLASS_1_INLINE_NO_PYTHON` keeps overwriting the
   immortal callable; PyStackRef_CLOSE measured +8 instructions/call with the JIT
   (`bytes(16)` 432 -> 440, `bytes(bytearray(b16))` 2076 -> 2084, `bytes(b16)` 225 ->
   225; release non-PGO, `pyspec_bench.py`, PYTHONHASHSEED=1, repeat 5).  Comment says so.
5. PEP 7 braces (`optimizer_bytecodes.c` x2, `_testinternalcapi.c` x5); cases regenerated.
6. `test_opt`: new exit tests for `_BINARY_OP_SUBSCR_BYTES_INT` (negative index) and
   `_GUARD_NOT_EXHAUSTED_BYTES`; the subclass test asserts instead of `if ex`; the seven
   pyspec class-call tests use `builtins_as_globals()` (below).

## Not changed
- `_CALL_BUILTIN_CLASS_0_INLINE`: not dead by construction.  `direct_spec_class_call()`
  emits it for any `nargs == 0` entry without a constant result, and
  `call_table.py` emits such an entry for every spec'd `__new__` whose no-argument
  residual is not a constant (a future `list()`/`bytearray()` spec).  Only today's data
  (bytes: `bytes()` is `Py_CONSTANT_EMPTY_BYTES`) never reaches it; removing it would
  make the next type an interpreter edit (PHASE4 goal 1).  No test can reach it without
  such data.
- `pycore_pyspec.h` (other stream): `call_table.py:447` should emit
  `// Export for '_testinternalcapi'` before the generated `PyAPI_DATA(const
  _PySpecCallTable)` lines.
- Report-only: `_ASSERT_RESULT_*` uops exist in release builds (never emitted there);
  `_RECORD_ARG0_TYPE` adds a record per traced `CALL_BUILTIN_CLASS`.
- `test_clinic.PyspecFilesTest.test_independent_of_host` (other stream) patches
  `builtins.hasattr` per spec file: 2 of the process's 3
  `_Py_MAX_ALLOWED_BUILTINS_MODIFICATIONS`, each of which also invalidates every
  executor.  Patching the name in the libclinic modules instead would avoid it.

## Upstream issue draft: test_opt depends on the state of builtins left by other tests

`./python -m test test_iter test_capi.test_opt` fails 16 tests on main
(`ee1bbf037ff`, debug, `PYTHON_JIT=1` or not): test_call_builtin_class,
test_call_builtin_fast(_with_keywords), test_call_builtin_o,
test_call_isinstance_{guards_removed,is_false,is_true,subclass}, test_call_len,
test_call_str_1, test_call_super, test_call_tuple_1,
test_call_type_1_{guards_removed,known_type},
test_check_is_not_py_callable_{ex,kw}.  `test_capi.test_opt` alone passes.

Cause: `test_iter.TestCase.test_reduce_mutating_builtins_iter` replaces builtins keys
with keys of a `str` subclass and back.  Afterwards
1. `builtins.__dict__`'s keys are `DICT_KEYS_GENERAL` for the rest of the process, so
   `specialize_load_global_lock_held()` fails with
   `SPEC_FAIL_LOAD_GLOBAL_NON_STRING_OR_SPLIT`: every `LOAD_GLOBAL` of a builtin stays
   generic (`_LOAD_GLOBAL` in traces);
2. it modifies builtins 22 times; after `_Py_MAX_ALLOWED_BUILTINS_MODIFICATIONS` (3)
   the optimizer stops promoting builtins to constants.
The failing tests assert that a guard on a builtin callable is removed, which needs
the callable to be a constant.  Any test module that modifies builtins three times
(counter: `_testinternalcapi.get_rare_event_counters()["builtin_dict"]`) has effect 2.

Suggested fixes: make the tests independent (look the builtin up in fresh globals
built by insertion, as the branch's `builtins_as_globals()` does, or run them in a
subprocess), and/or restore a unicode keys table when the last non-exact-str key is
removed from a dict.

Also seen (not reproduced here in 5 runs of the PHASE4 list + test_opt, nor with
0-1999 executors created first, `order_probe.py`): `test_binary_op_subscr_init_frame`
and `test_binary_op_subscr_constant_frozendict_known_hash` finding no executor
("unexpectedly None") after other modules.  Not the cold-executor sweep:
`_Py_Executors_InvalidateCold()` only invalidates an executor that was already
marked cold by the previous sweep and did not run since, and sweeps come every
`JIT_CLEANUP_THRESHOLD` (1000) executor creations, while these executors are created
and inspected within one test.  Candidates: `_Py_Executors_InvalidateAll()` from one
of the first three builtins modifications happening during the test, or a
dependency invalidation (bloom filter false positive) triggered by a watched
dict/type/function changed by a finalizer of an earlier module's garbage.

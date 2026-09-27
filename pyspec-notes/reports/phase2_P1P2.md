## Phase 2 (P1 + P2) report

P1 and P2 are both in, along with F3, the single builtin-types table, the C-side check and the extended dynamic check. All requested tests pass. Tool code shrank, but only barely: 5710 → 5691 total lines (−19) and 4026 → 4025 code lines (−1). Generated C is functionally identical or better, and no bytes shape got slower.

- **Branch:** `worktree-agent-a4af2b404bf7d3daa`, worktree `/home/firebird347/projects/python/cpython/.claude/worktrees/agent-a4af2b404bf7d3daa`.
- **History:** 22 commits on 3ff249cc1ff. Nothing rebased, amended or pushed. The tree is clean.

### What changed

**P1: helpers are called by name.**
- The `C.` namespace, `Escape`/`FastPath`/`ContextEscape`/`RaiseEscape`, the per-escape C templates and the escape-stub test are gone.
- A hand-written helper is one spec function with `@c_implemented`. Its body is the Python reference; it is never lowered to C.
- Helpers from other files live in new minimal specs of their own file and are imported:
  - `Objects/pyspec/abstract.py`: `PyNumber_AsSsize_t`, `_PyNumber_Index`, `PyObject_LengthHint`
  - `Objects/pyspec/typeobject.py`: `_PyObject_LookupSpecial`
  - `Objects/pyspec/unicodeobject.py`: `PyUnicode_AsEncodedString`
  - `Python/pyspec/errors.py`: `PyErr_BadInternalCall`
  - `Include/cpython/pyspec/longintrepr.py`: `_PyLong_IsCompact`, `_PyLong_CompactValue`
- Imports resolve relative to the C file's directory, then the source root.

**How A's special lowerings are spelled now:**
- **Fast paths and exact-type lowerings:** a leading `if test: return value` in the reference. Where the call's facts decide the test, the value replaces the call. A call on a loop item, or one where only the type tests are decided, is split into both branches. Two examples:
  - `PyNumber_AsSsize_t`: `if (type(o) is int or type(o) is bool) and _PyLong_IsCompact(o): return _PyLong_CompactValue(o)`
  - `PyObject_LengthHint`: `if type(o) is list or type(o) is tuple: return len(o)`
- **The appender:**
  - A function whose return annotation is a C struct initializes the local it is assigned to, in place, and that local is passed by address.
  - The body releases it with `try: ... finally: bytes_appender_discard(writer)`.
  - The new C `bytes_appender_finish()` leaves the appender empty, so there is no "steals" concept at all. After inlining this compiles to the same hot loop.
  - The new C helpers are `bytes_appender_finish`, `bytes_appender_discard` and `bytes_copy`.
- **Unchecked append:** A's presize rule stays as an evaluator rule. The buffer's length now comes from the derived `size = len(x)`, and the unchecked append from the append reference's fast path.

**P2: facts are derived from bodies** (new `Tools/clinic/libclinic/pyspec/facts.py`).
- Primitives: `exact(T, v)`, `unknown(v)`, `calls(x, "__name__")`, `runs_python()`, and `return NULL` for an absent result.
- Derived per call site: exact result type, alias, constant, which exceptions can be raised, and whether Python runs.
- The error check of a call comes from "can raise" plus the C return kind.
- `...` now means the worst case.
- `New/Borrowed/OnError/NoError/RunsPython/pointer/cstr` are removed; the only C types left are annotations (`object`, `str`, `int`, `Py_ssize_t`, `None`, or the C type as a string).
- A `try` whose handlers can't match what the body raises is removed. That is what makes **`bytes(16)` derive "runs no Python code"**: the `except TypeError` fallback is gone from `bytes_new_nargs1_int`, and the JIT now uses `_CALL_BUILTIN_CLASS_1_INLINE_NO_PYTHON` (three test_opt expectations updated).

**F3 and the one table.**
- `is_static_type`, `RunsPython[T,'p']`, `ITERATION` and `BUILTIN_TYPES` are replaced by facts from type specs, plus one audited table, `Tools/clinic/libclinic/pyspec/builtin_types.py`. It also replaces `TYPE_OBJECTS` ×2, `TYPE_CHECK`, `CONSTANT_OBJECTS` and `CANDIDATE_TYPES`.
- Forwarding types are not in the table. `test_static_type_rule` passes and its expectedFailure is removed.

**Other removals:**
- **Lookup versioning:** about 100 lines of it (`Bound`, `bind_special`) are replaced by one explicit spec line, `if type(source) is bytes: return source`. The generated C is the same apart from nesting.
- **Hand-written C API facts:** `Objects/pyspec/capi/bytesobject.py` (`RUNS_PYTHON`/`NO_PYTHON`) is removed.
  - Nothing consumed or checked those sets (review_dx task (e)).
  - The capi baseline loses 6 lines as a result.
  - This is a judgement call beyond the brief; please confirm.

### Spec spelling, before and after
```python
# before
writer = C.bytes_appender(size)
for item in it:
    value = C.PyNumber_AsSsize_t(item, NULL)
    ...
    C.bytes_appender_append(writer, value)
return C.bytes_appender_finish(writer)
def PyNumber_AsSsize_t(o: object, exc: object) -> RunsPython[OnError[Py_ssize_t, -1], 'o']: ...
# plus runtime.py: escape('PyNumber_AsSsize_t({0}, {1})', returns=..., error=ERR_MINUS1, fast=_COMPACT_INT)

# after
writer = bytes_appender_init(size)
try:
    for item in it:
        value = PyNumber_AsSsize_t(item, NULL)
        ...
        bytes_appender_append(writer, value)
    return bytes_appender_finish(writer)
finally:
    bytes_appender_discard(writer)

@c_implemented
def _PyBytes_FromBuffer(x: object):
    calls(x, "__buffer__")
    calls(x, "__release_buffer__")
    return exact(bytes, memoryview(x).tobytes())
```

### Validation
- **C side** (new `c_calls` dimension in `disconnects.py`, baseline `Tools/clinic/pyspec-baseline/c_calls.txt`, which is empty):
  - It reads each `@c_implemented` C function, and the functions of its file it calls, with the cases generator's lexer and `escaping_call_in_simple_stmt`.
  - Every call that may run Python must be accounted for: the reference calls the same function, a `calls()` of the special method it invokes (slot calls come from slotdefs, including locals assigned from a slot), or `runs_python()`.
  - One audited list names about 35 C functions from other files that run no Python.
  - It also flags a reference that "cannot fail" while its C makes escaping calls.
- **Dynamic:** a new `HelperTest` in `test_pyspec_facts` uses a new `_testinternalcapi.pyspec_helper` hook.
  - It covers every non-static helper, plus `bytearray.fromhex`/`bytes.fromhex` for `_PyBytes_FromHex`, and the slot wrappers of `bytes.__buffer__` and `bytes_iterator.__next__`.
  - Each is difftested against its reference and its derived facts are checked: exact type, cannot raise, and no Python (recorded, then run again under the debug tripwire).
  - It already found a real bug: `PyNumber_AsSsize_t`'s reference returned an int subclass (fixed).
- **Not called directly:** the static helpers (`_PyBytes_FromSize`, `_PyBytes_FromBuffer`, `bytes_copy`, `bytes_subtype_new`, the appender functions) are reached only through the spec entries and the difftest. `PyErr_BadInternalCall()` asserts in debug builds. The test forces every new helper into one of the two lists.

**Deliberate stale facts, each reverted afterwards** (script: `scratchpad/P2/demo.sh`):

| Stale fact | Caught by |
|---|---|
| review_dx task (e): `PyErr_WarnEx` added to `_PyBytes_FromBuffer`'s C | c_calls: "calls PyErr_WarnEx(), which may run Python code" |
| Dropping `calls(x, "__buffer__")`/`"__release_buffer__"` from its reference | c_calls names `PyObject_GetBuffer` and `PyBuffer_Release`; `test_static_type_rule` fails for PickleBuffer |
| Dropping `calls(o, "__index__")` and `runs_python()` from `_PyNumber_Index` | c_calls names `nb_index` and `PyErr_WarnFormat`; HelperTest fails with "claims: runs no Python" (RecordingIndex) |
| A wrong value in `_PyLong_IsCompact`'s reference | The HelperTest difftest |

### Performance
Release JIT builds, not PGO, identical flags: `P2-perf/build-before` (3ff249cc1ff) vs `build-after`. I ran the full review_perf micro set twice per build, JIT on and off.

| shape | before (instructions, 2 runs) | after (2 runs) |
|---|---|---|
| `bytes(16)`, JIT on | 442 / 442 | 433 / 434 (faster) |
| `bytes(list256)` | 5190 / 5190 | 5190 / 5190 |
| `bytes(tuple16)` | 863 / 863 | 863 / 868 |
| `bytes(bools16)` | 898 / 898 | 898 / 898 |
| `bytes(range256)` | 19420 / 19420 | 19420 / 19420 |
| `bytes(b16)` | 227 / 227 | 227 / 227 |
| `Sub(b16)` | 1262 / 1262 | 1262 / 1262 |

Two shapes land just outside the run-to-run spread: `sub.__bytes__()` JIT on (850 → 856) and `bytes.fromhex` JIT on (1852 → 1857). The machine code of both functions is byte-identical between the builds, so I attribute this to layout.

In `bytesobject.o` only two functions changed: `bytes_new_nargs1_int` shrank from 294 to 255 bytes, and `bytes_from_iterator` grew by 11 bytes in an error path only. `bytesobject.c.h` and `transmogrify.h.h` are unchanged.

Full table: `scratchpad/P2/perf_table.md`.

### Tests
- **Debug JIT** (`build-P2`):
  - test_clinic, test_bytes, test_inspect, test_iter, test_pyspec_catalog and test_pyspec_facts pass (1296 tests); test_capi alone passes (1587).
  - `PYTHON_JIT=0 -R 3:3` on test_pyspec_facts, test_pyspec_catalog, test_clinic and test_bytes passes, and test_pyspec_facts `-R` with the JIT on passes too.
- **Free-threaded debug** (`build-P2-ft`): test_bytes, test_pyspec_facts, test_clinic and test_free_threading pass. The F1 snapshot script gives `[0, 0, 0]` torn results.
- **Clean tree:** `make regen-cases` and clinic, run with the build Python and with host 3.14, leave the tree clean.

### Code size and concepts
Tool code in libclinic/pyspec, total lines (code lines):

| file | before | after |
|---|---|---|
| __init__ | 28 (0) | 33 (0) |
| call_table | 612 (444) | 329 (225) |
| disconnects | 765 (597) | 945 (726) |
| emit | 1068 (833) | 1050 (796) |
| frontend | 798 (517) | 855 (572) |
| partial_eval | 1209 (854) | 1051 (745) |
| runtime | 564 (286) | 226 (106) |
| slots | 194 (133) | 194 (133) |
| typeobj | 472 (362) | 474 (363) |
| builtin_types | new | 189 (122) |
| facts | new | 345 (237) |
| **total** | **5710 (4026)** | **5691 (4025)** |

The C check costs about 200 lines; everything else is net smaller. Spec data: bytesobject.py grew by 30 lines, the new helper specs add 141, and the capi facts file (−62) is gone.

**Concepts (review_dx §1):**
- **Removed:** #8 `C.` escapes, #38 the Escape machinery, #42 `ITERATION`, #45 New/Borrowed, #47 OnError/NoError, #48 RunsPython and `RunsPython[T,'p']`, #50 the escape-stub test, and the capi facts sets. #9 went from 7 tables to 1.
- **Added:** `@c_implemented`, the 4 primitives, the fast-path shape, the struct-buffer rule (in-place init plus `finally`), and importing a helper from the spec of its file.
- **Net:** about −3 items, and about 39 → 10 words in the helper and facts vocabulary. Unannotated `...` now means the worst case.

### Open problems
1. **Granularity:** the C check is per function, not per path. It also treats reference-count releases (Py_DECREF and similar macros) as running no Python, a justified but audited assumption.
2. **Presize assumption:** "a struct init's argument is its capacity, and the call's fast path is the path with room" is an evaluator rule. Only the debug assert in `bytes_appender_append_unchecked` checks it.
3. **Model code is trusted:** code in a reference other than the primitives is assumed to have no effects and raise nothing. It is checked only by c_calls (Python effects) and by HelperTest (values and facts, for the helpers that can be called directly).
4. **Lint:** string C-type annotations trigger ruff F722, "forward annotation".
5. **JIT leak, not investigated:** with the JIT on, creating fresh functions on every `-R` repetition leaked references in HelperTest. I worked around it by loading each reference once per process. It may be the same class as the JIT refleak noted earlier and still open (README open item 2).
6. **Lost fact:** bytes `__iter__`/`__len__` are now `...` (worst case). The old `ITERATION[bytes]=int` fact had no consumer.
7. **Test scope:** test_up_to_date now also runs clinic on abstract.c, typeobject.c and unicodeobject.c. PyspecFilesTest restores the converters clinic registers there.

Build directories: `/home/firebird347/projects/python/build-P2`, `build-P2-ft` and `P2-perf/` (both release builds and their sources). Scratch files are in `/tmp/claude-1000/-home-firebird347-projects-python/2290c1d8-9873-48d1-a600-904f809b5565/scratchpad/P2/`.
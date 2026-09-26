# JIT optimizer: `_CALL_STR_1` claims an exact `str` result, but `str(x)` can return a `str` subclass

Found by the pyspec WS4 agent while deriving result types for `bytes()`; reproduced
independently on unmodified `main`. Nothing has been fixed or filed.

## Summary

`Python/optimizer_bytecodes.c:1649` (on `main` at `ee1bbf037ff`):

```c
op(_CALL_STR_1, (unused, unused, arg -- res, a)) {
    if (sym_matches_type(arg, &PyUnicode_Type)) {
        res = PyJitRef_StripReferenceInfo(arg);
    }
    else {
        res = sym_new_type(ctx, &PyUnicode_Type);   // <-- claims EXACT str
    }
    a = arg;
}
```

At runtime, `_CALL_STR_1` (`Python/bytecodes.c:4707`) returns `PyObject_Str(arg)`.
`PyObject_Str` only requires `PyUnicode_Check(res)` (`Objects/object.c:833`), so a
`__str__` that returns a `str` subclass passes that subclass through. The tier-1
interpreter agrees: `str(c)` returns the `S` instance. `sym_new_type` means "exact
type", so tier 2 is told something false whenever the argument isn't already known to
be an exact `str`.

## Consequences (release JIT build, `main` @ `ee1bbf037ff`)

| Symptom | Mechanism | Repro |
|---|---|---|
| **Segfault (use-after-free)** | `optimize_pop_top` (`Python/optimizer_analysis.c:448`) narrows the `POP_TOP` of the discarded result to `_POP_TOP_UNICODE`, which frees it with `_PyUnicode_ExactDealloc`. That bypasses `subtype_dealloc`, so weakrefs to the object are never cleared. The GC later dereferences the freed object in `clear_weakref_lock_held` (`Objects/weakrefobject.c:82`) | `repro_weakref_crash.py`: exit 139 |
| `__del__` not called | same: `subtype_dealloc` is skipped | `repro_del_skipped.py`: 4002 of 16008 calls |
| Heap-type refcount leak | same: `subtype_dealloc`'s `Py_DECREF(type)` is skipped (instance `__dict__`s leak too) | `repro_type_refleak.py`: `refcount(S)` grows by 12007 |
| Wrong result | the optimizer folds `type(str(c)) is str` to `True` | `repro_type_check.py`: 6671 hits, expected 0 |

On the same binary with `PYTHON_JIT=0`, every repro is correct. A debug build
(`--with-pydebug --enable-experimental-jit=interpreter`) aborts in the tier-2
interpreter:

```
Python/executor_cases.c.h:2481: _PyTier2Interpreter: Assertion
`PyUnicode_CheckExact(PyStackRef_AsPyObjectBorrow(value))' failed.     (in _POP_TOP_UNICODE_r21)
```

Backtrace of the release crash:

```
#0 _PyObject_GET_WEAKREFS_LISTPTR  Include/internal/pycore_object.h:786
#1 clear_weakref_lock_held         Objects/weakrefobject.c:82
#2 _PyWeakref_ClearRef             Objects/weakrefobject.c:137
#3 clear_weakrefs                  Python/gc.c:975
#4 gc_collect_main (reason=_Py_GC_REASON_SHUTDOWN)
```

Minimal trigger (`repro_weakref_crash.py`), with no C extensions:

```python
class S(str): pass
class C:
    def __str__(self):
        s = S("x"); refs.append(weakref.ref(s)); return s
def f(n):
    c = C()
    for _ in range(n):
        str(c)        # CALL_STR_1, result discarded -> _POP_TOP_UNICODE
```

## History and affected branches

- The wrong fact came from 0a387b311e6, "GH-131798: Split up and optimize CALL_STR_1
  in the JIT (GH-132849)", 2025-04-24. It is in `3.14` and `3.15`.
- The memory-safety part needs the type-based `POP_TOP` narrowing from 569fc6870f0,
  "gh-134584: Specialize POP_TOP by reference and type in JIT (GH-135761)",
  2025-06-24. `3.15` has `_POP_TOP_UNICODE` narrowing and `3.14` does not.
  - On 3.14 I'd expect only the wrong-result symptom. **I haven't tested 3.14.**
- I found no existing issue: I searched python/cpython for `_CALL_STR_1` and
  `CALL_STR_1 subclass`.

## Fix direction (not implemented)

Only claim an exact `str` when it's actually guaranteed:

- **Known exact str argument:** keep the existing first branch.
- **Unknown argument:** `res = sym_new_not_null(ctx)`. There's no "`str` or subclass"
  symbol kind; if one were added it could keep more information, but it must not count
  as exact for `POP_TOP` narrowing or for guard removal.
- **Optional:** exact `str` for argument types whose `tp_str` is known to return an
  exact `str` (e.g. exact `int`, `float`), when the symbol's type is known.

Regression test: add a case to `Lib/test/test_capi/test_opt.py` next to the existing
`CALL_STR_1` tests from GH-132849, with a `__str__` that returns a subclass.

## Related audit notes

- The other `sym_new_type(ctx, &PyUnicode_Type)` sites in `optimizer_bytecodes.c`
  (lines 489, 561, 592, 598, 2114: `_BINARY_OP_ADD_UNICODE`, `_BINARY_OP_SUBSCR_STR_INT`,
  `_BINARY_OP_SUBSCR_USTR_INT`, `_BUILD_STRING`) produce new exact `str` objects, so
  they look correct.
- It's worth checking every result-type claim on a call that runs user code
  (`tp_str`, `__index__`, `__iter__`, ...) for the same "subclass is allowed" gap. I
  haven't done that sweep.

## How it was verified

- Release: `build_perf_base_jit` (PGO+LTO, `--enable-experimental-jit`, `main` @
  `ee1bbf037ff`). Each script was run with and without `PYTHON_JIT=0`.
- Debug: `build-str1-dbg` (`CC=clang --with-pydebug
  --enable-experimental-jit=interpreter`, same commit). `repro_type_check.py` and
  `repro_del_skipped.py` both hit the assertion.

# Upstream drafts: `_CALL_STR_1` exact-`str` result

Local branch `fix-call-str-1-subclass` (commit `969928f3ba2`, based on `main` @
`ee1bbf037ff`). Not pushed. Replace `NNNNNN` in the commit subject and in the NEWS
file name (`Misc/NEWS.d/next/Core_and_Builtins/2026-09-26-12-00-00.gh-issue-NNNNNN.QCJD0g.rst`)
with the issue number once it is filed.

---

## Issue

**Title:** JIT: `str(x)` is assumed to return an exact `str`, but `__str__` may return a subclass (use-after-free)

**Labels (suggested):** `type-crash`, `interpreter-core`, `topic-JIT`

### Bug report

The tier 2 optimizer's `_CALL_STR_1` (`Python/optimizer_bytecodes.c`) records the
result of `str(x)` as an exact `str` whenever `x` is not already known to be an exact
`str`:

```c
else {
    res = sym_new_type(ctx, &PyUnicode_Type);
}
```

At runtime `_CALL_STR_1` calls `PyObject_Str()`, which accepts any `str` subclass
returned by `__str__`. The false fact has these effects:

- `type(str(x)) is str` is folded to `True`.
- When the result is discarded, `POP_TOP` is narrowed to `_POP_TOP_UNICODE`, which
  frees the subclass instance with `_PyUnicode_ExactDealloc`. That skips
  `subtype_dealloc`, so `__del__` is not called, the heap type's reference is leaked,
  and weakrefs to the object are not cleared. The GC later dereferences the freed
  object and crashes.

Reproducer (pure Python, JIT build):

```python
import weakref
from _testinternalcapi import TIER2_THRESHOLD

class S(str):
    pass

refs = []

class C:
    def __str__(self):
        s = S("x")
        refs.append(weakref.ref(s))
        return s

def f(n):
    c = C()
    for _ in range(n):
        str(c)

f(TIER2_THRESHOLD * 4)
print(sum(r() is not None for r in refs), "live weakrefs; expected 0")
```

On a release `--enable-experimental-jit` build this segfaults at shutdown in
`clear_weakref_lock_held` (via `gc_collect_main` -> `clear_weakrefs`). On a debug build
it aborts on the `PyUnicode_CheckExact` assertion in `_POP_TOP_UNICODE`. With
`PYTHON_JIT=0` it behaves correctly.

A variant that only shows the wrong result:

```python
from _testinternalcapi import TIER2_THRESHOLD

class S(str): pass
class C:
    def __str__(self): return S("x")

def f(n):
    c = C()
    hits = 0
    for _ in range(n):
        if type(str(c)) is str:
            hits += 1
    return hits

print(f(TIER2_THRESHOLD * 4), "expected 0")
```

### Affected versions

- `main` and 3.15: wrong results and memory unsafety (use-after-free, skipped
  `__del__`, type refcount leak).
- 3.14: carries the wrong type fact (introduced by GH-132849) but has no type-based
  `POP_TOP` narrowing (added by GH-135761), so only wrong results are expected there.
  (Not tested on 3.14.)

### CPython versions tested on

CPython main branch (`ee1bbf037ff`)

### Operating systems tested on

Linux

---

## Pull request

**Title:** gh-NNNNNN: Don't assume str() returns an exact str in the JIT optimizer

`_CALL_STR_1` told the optimizer that `str(x)` returns an exact `str` whenever `x`
was not already known to be an exact `str`. But `__str__()` may return a `str`
subclass, which `PyObject_Str()` passes through. That false fact let the optimizer
fold `type(str(x))` to `str` and narrow the `POP_TOP` of a discarded result to
`_POP_TOP_UNICODE`. That uop frees the subclass instance with
`_PyUnicode_ExactDealloc`, which skips `__del__`, leaks a reference to the type and
leaves weakrefs pointing at freed memory.

The fix only claims an exact `str` result when it is guaranteed:

- the argument is known to be an exact `str` (unchanged: the result is the argument);
- the argument is known to be an exact `int` or `float`, whose `str()` builds an exact
  `str`. This keeps the existing `str(42) + 'foo'` optimization. (One exception is
  fixed separately: for an `int` of more than about 1000 digits, `str()` returns what
  `_pylong.int_to_decimal_string()` returns if it is any `str`, so a monkeypatched
  `_pylong` can make it a subclass; the companion issue, "Require an exact str from
  `_pylong.int_to_decimal_string()`", checks `PyUnicode_CheckExact()`, so the claim
  holds for every `int`);
- otherwise the result is only known to be non-NULL.

Tests added to `test_capi.test_opt`, next to the existing `CALL_STR_1` tests:

- `test_call_str_1_result_can_be_str_subclass`: `type(str(c))` is the subclass;
- `test_call_str_1_str_subclass_result_is_deallocated`: every `__del__` runs and the
  `POP_TOP` is not narrowed to `_POP_TOP_UNICODE`;
- `test_call_str_1_str_subclass_result_weakref`: weakrefs are cleared, with no crash.

Without the fix, all three abort on a debug JIT build. With it, all of
`test_capi.test_opt` passes.

`_CALL_TUPLE_1` has the same shape, but `PySequence_Tuple()` always returns an exact
`tuple`, so its result type is correct.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

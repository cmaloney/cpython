WS9 report: how the four descriptions of `bytes` line up (spec, runtime, docs, typeshed)

## SUMMARY (≤70 lines)

Sources I used:
- **Spec:** cpython `Objects/pyspec/bytesobject.py` at f62ffd1fe3e.
- **Runtime:** build-ws1 (the branch) and build_perf_base (main at merge-base ee1bbf037ff).
- **Docs:** they have moved to `Doc/builtins/stdtypes.rst` (bytes entries at L3608–4668) and `Doc/builtins/functions.rst` L260, plus `Doc/c-api/bytes.rst`.
- **typeshed:** 249fa03490c26bf2aa83c8d94136ff33635588c0 (2026-09-25).

Nothing was modified in cpython. Everything I made is in `scratchpad/ws9/`.

**The branch changed nothing at runtime.** A dump of name, descriptor kind, `__text_signature__`, `inspect.signature` and `__doc__` for all 80 attributes of `bytes` is byte-identical on the branch and on main (`rt_branch.json` vs `rt_main.json`). A 150-case behaviour probe also gives identical output on both.

**What the spec covers.** It covers 25 attributes: `__new__` (with a real body), `__bytes__`, split, rsplit, partition, rpartition, join, find, index, rfind, rindex, count, strip, lstrip, rstrip, translate, maketrans, replace, removeprefix, removesuffix, startswith, endswith, decode, splitlines, fromhex, hex.

The brief assumed `hex`, `fromhex` and `__bytes__` are not clinic functions. They are clinic functions, and the spec covers them.

**What the spec does not cover:**
- **Clinic functions of class `B` in `Objects/stringlib/transmogrify.h`:** center, ljust, rjust, zfill, expandtabs. They are shared with bytearray, and the brief's rule "spec file = `Objects/pyspec/<cfile stem>.py`" gives them no home. This is an open design question.
- **METH_NOARGS methods with shared docstrings from `Objects/bytes_methods.c`:** isalnum, isalpha, isascii, isdigit, islower, isspace, istitle, isupper, lower, upper, capitalize, swapcase, title. They are implemented in `Objects/stringlib/ctype.h`.
- **`__getnewargs__`:** `bytes_getnewargs`, `bytesobject.c` L2563.
- **Slots in `bytesobject.c`:**
  - tp_repr and tp_str (`bytes_repr`, `bytes_str`), tp_hash (`bytes_hash`), tp_richcompare (`bytes_richcompare`), tp_iter (`bytes_iter`)
  - sq_length (`bytes_length`), sq_concat (`_PyBytes_Concat`), sq_repeat (`_PyBytes_Repeat`), sq_contains (`bytes_contains`)
  - mp_subscript (`bytes_subscript`), nb_remainder (`bytes_mod`), bf_getbuffer (`bytes_buffer_getbuffer`)

**Where the four sources disagree, by root cause:**
- **(a) The format cannot express it:**
  - Seven methods carry the hand-written clinic override `@text_signature "($self, sub[, start[, end]], /)"`: find, index, rfind, rindex, count, startswith, endswith. `inspect.signature()` raises ValueError on them. The override has been there since gh-117431 (2024). The spec already holds the true, representable signature, `(sub, start=None, end=None, /)`, which is exactly typeshed's shape.
  - `hex`: `sep=<unrepresentable>` (a NULL default).
  - `bytes()` has no signature at all.
  - The docs use two signature lines for `hex` and for `bytes()`.
  - typeshed cannot say "exact bytes".
- **(b) Deliberate modelling choices:**
  - typeshed uses `ReadableBuffer`, `SupportsIndex` and `bool` (runtime accepts any object for `keepends`), and has three `__new__` overloads.
  - The docs rename positional-only parameters: fillbyte for fillchar, from for frm, iterable for iterable_of_bytes.
- **(c) Real inaccuracies:** see the bug list below.
- **(d) Version drift:** nothing bytes-specific on 3.16. All versionadded/versionchanged notes agree with typeshed's `sys.version_info` gates (fromhex 3.14, replace keyword `count` 3.15, `__bytes__` 3.11). The one drift: the runtime `fromhex` docstring never mentions the 3.14 bytes-like input.
- **(e) Information only one source has:**
  - Spec: C converters and NULL "absent" defaults; the error branches and branch order of `__new__` (`__bytes__` before str, int and buffer); exact result types through the call table.
  - typeshed: return types, and the element types of `tuple`/`Iterable`.
  - Docs: "returns the original if width <= len", the bytearray not-in-place notes, the versionchanged history.

**stubtest has a blind spot, shown by mutation.** Today stubtest reports no `bytes` errors on the 3.16 interpreter, and the allowlists have no `bytes` entries. I then corrupted the stub on purpose:
- Changed `find` to `(needle: int, *, begin, zzz)`.
- Renamed `startswith`'s parameter to `pfx`.
- Gave `__new__` a required keyword argument.

stubtest reported none of these, while it did catch the same kind of damage in `split` and `hex` (mypy parses `<unrepresentable>` itself). So the 7 bracket-signature methods and `__new__` are never checked, for bytes and likewise for bytearray and str. test_inspect already lists them in `methods_unsupported_signature`.

**Bugs found (one-line repros in section 5 of the full report):**
1. CPython docstring: `bytes.removesuffix.__doc__` says `bytes[:-len(prefix)]`; bytearray's says `suffix`.
2. `functions.rst`: "constructor arguments are interpreted as for bytearray()" is false for `__bytes__`. `bytes(H())` works, `bytearray(H())` raises TypeError.
3. typeshed: `bytes.partition` and `rpartition` return `tuple[bytes, bytes, bytes]`, but a non-bytes separator comes back as the very object passed in. mypy reveals `tuple[bytes, bytes, bytes]`; runtime returns `(b'a', <memory>, b'c')`. This is also a questionable CPython behaviour.
4. typeshed: `bytes.center` and `bytearray.center` take `fillchar: bytes`, but runtime accepts a bytearray, and `ljust`/`rjust` already say `bytes | bytearray`. mypy rejects valid code.
5. typeshed: the `bytes.__new__` overloads make the first parameter positional-only, so `bytes(source=b'x')` is rejected by mypy but valid at runtime. stubtest cannot see this.
6. Docs are imprecise about copy vs identity: partition "a copy of the original sequence", removeprefix, strip and replace "a copy". For exact bytes the original object is returned; partition even returns the subclass instance itself.
7. Docs `count`: "in the range [start, end]" (also in `str.count`). The range is half-open.
8. Docs `center`, `ljust`, `rjust`, `zfill`: "for bytes objects the original is returned". This does not hold for subclasses, which get an exact bytes copy.
9. Docs and docstring `translate`: "table must be a bytes object" is too narrow; any buffer works.
10. C-API docs `PyBytes_FromObject` mention only buffers. It also accepts list, tuple and iterables of ints, returns `o` itself for exact bytes, and rejects str and objects that only have `__bytes__`.
11. Minor CPython items:
    - `b.hex(None)` fails with "object of type 'NoneType' has no len()" (same for bytearray and memoryview).
    - The startswith error "must be bytes or a tuple of bytes" is wrong for memoryview, which is accepted.
    - The `fromhex` docstring never says bytes-like input is accepted (3.14 drift).
    - `lstrip` docstring has a double space.

**Recommendations**
- **Which source owns which fact:**
  - The spec (clinic input) owns signature shape: names, kinds, defaults and docstrings.
  - C code, plus spec bodies where they exist, owns behaviour.
  - The docs own the prose and the version history.
  - typeshed owns static types.
  - What is checked: docs against runtime, and typeshed against runtime (stubtest). Nothing is generated across project boundaries.
- **R1, highest value and smallest change:** drop the bracket `@text_signature` overrides for the find family in bytes, bytearray and str. That is 7 lines per type, clinic only. `inspect`, `help()` and typeshed's stubtest then cover 21 more methods, and entries can be removed from test_inspect's `methods_unsupported_signature`.
- **R2:** add a Lib/test check (skipped when `Doc/` is absent) that parses the `.. method:: bytes.X(...)` lines and compares kinds and defaults with `inspect.signature`. It should ignore names of positional-only parameters and treat `[, x]` as optional positional-only. Check the docs; do not generate them. Hand-written multi-form lines and the shared bytes/bytearray entries would fight any generator.
- **R3:** keep clinic converters as the spec's annotations. A converter-to-typeshed map works for the converter-typed ones (Py_buffer→ReadableBuffer, Py_ssize_t→SupportsIndex, slice_index(accept={int, NoneType})→SupportsIndex | None, str, bool); the 16 `object` parameters carry no type information. Return annotations are already clinic return converters, so typeshed return types cannot go there.
- **R4:** give facts through bodies, not new annotations. For example, a real body for `bytes.__bytes__` turns the call-table entry "bytes(bytes): result type not known; may run Python" into an exact result with no Python run. Where overloads come from `__new__`'s branches, a check that typeshed's overload set covers the spec's non-raising paths can live on the pyspec side, but only as an informational report. Do not generate a `.pyi`: CPython ships no stubs, and typeshed is separate and supports several versions.
- **R5:** file the typeshed and doc items upstream separately (small PRs).

---

## FULL REPORT

### 0. Method and artifacts (all in /tmp/claude-1000/-home-firebird347-projects-python/50cf0ce0-5ab0-4e7c-ba5f-65e16f35a2bb/scratchpad/ws9/)
| File | What it is |
|---|---|
| `dump.py` → `rt_branch.json`, `rt_main.json` | Runtime dump on both builds. `diff` says IDENTICAL. |
| `probe.py` → `probe_branch.txt`, `probe_main.txt` | About 150 behaviour probes. Identical on both builds. |
| `probe2.py` | Partition identity on subclasses, `__bytes__` on bytes vs bytearray, `PyBytes_FromObject` through ctypes. |
| `align.py` → `align.txt`, `align.json` | Parses the four sources mechanically (ast for spec and typeshed, regex for rst) and builds the per-attribute table. |
| `typeshed/` | Shallow clone at 249fa03490c26bf2aa83c8d94136ff33635588c0. |
| `venv/` | mypy 2.3.1, pure Python, on build_perf_base. |
| `stubtest_builtins.txt` | stubtest on unmodified typeshed. |
| `ts_mut/`, `stubtest_mut.txt` | stubtest on the deliberately corrupted stub. |
| `tc.py` | mypy check of code that is valid at runtime. |

- **Runtime versions:** 3.16.0a0 f62ffd1fe3e (branch, debug) and ee1bbf037ff (main).
- **Branch vs main source:** clinic generated code differs only in `bytes_new` (vectorcall helper). Every docstring and text signature is unchanged.

### 1. Per-attribute alignment table
Legend:
- P = positional-only, PK = positional-or-keyword, K = keyword-only.
- "rt" = `__text_signature__` without `$self`; "insp" = whether `inspect.signature` succeeds.
- ✗ marks a mismatch; the letter is its root-cause class.

**A. Attributes in the spec**

| attr | spec (clinic lines) | rt / insp | docs | typeshed | mismatches |
|---|---|---|---|---|---|
| `__new__` | `(source: object(c_name='x')=NULL, encoding: str=NULL, errors: str=NULL)`, all PK, real body | `($type, *args, **kwargs)`; `inspect.signature(bytes)` raises (tp_doc has no `--`) | `bytes(source=b'')` / `bytes(source, encoding, errors='strict')`; functions.rst says "as for bytearray" | 3 overloads: `(o: Iterable[SupportsIndex]\|SupportsIndex\|SupportsBytes\|ReadableBuffer, /)`, `(string: str, /, encoding: str, errors: str='strict')`, `()`, all `-> Self` | ✗a no runtime signature; ✗a NULL vs `b''`/`'strict'`; ✗c typeshed P (`bytes(source=b'x')` rejected); ✗c functions.rst `__bytes__` claim |
| `__bytes__` | `()` | `(/)` ok | not in stdtypes (datamodel `object.__bytes__`) | `() -> bytes` if ≥3.11 | ok |
| `split`, `rsplit` (clone) | `(sep: object=None, maxsplit: Py_ssize_t=-1)` PK | `(/, sep=None, maxsplit=-1)` ok | same | `sep: ReadableBuffer\|None, maxsplit: SupportsIndex -> list[bytes]` | ok (b: the spec's `object` carries no type) |
| `partition`, `rpartition` | `(sep: Py_buffer, /)` | `(sep, /)` ok | `(sep, /)`; "copy of the original sequence" | `-> tuple[bytes, bytes, bytes]` | ✗c typeshed middle element; ✗c docs "copy" |
| `join` | `(iterable_of_bytes: object, /)` | ok | `(iterable, /)` | `Iterable[ReadableBuffer] -> bytes` | ✗b name (P, harmless) |
| `find`, `index`, `rfind`, `rindex`, `count` (clones of `find`) | `(sub: object, start: slice_index(accept={int,NoneType})=None, end: …=None, /)` | `(sub[, start[, end]], /)`; insp ValueError | `(sub[, start[, end]])` | `(sub: ReadableBuffer\|SupportsIndex, start: SupportsIndex\|None=None, end: …=None, /) -> int` | ✗a override hides the true signature; stubtest blind; ✗c docs `count` "[start, end]" |
| `strip`, `lstrip`, `rstrip` | `(bytes: object=None, /)` | ok | ok; "Return a copy" | `ReadableBuffer\|None -> bytes` | ✗c-minor: returns self when nothing is stripped |
| `translate` | `(table: object, /, delete: object(c_name='deletechars', c_default='NULL')=b'')` | `(table, /, delete=b'')` ok | same; "table must be a bytes object of length 256" | `table: ReadableBuffer\|None, delete: ReadableBuffer -> bytes` | ✗c-minor docs/docstring too narrow |
| `maketrans` (static) | `(frm: Py_buffer, to: Py_buffer, /)` | ok | `(from, to, /)` | `ReadableBuffer x2 -> bytes` | ✗b name |
| `replace` | `(old: Py_buffer, new: Py_buffer, /, count: Py_ssize_t=-1)` | ok | same, with versionchanged 3.15 | gated ≥3.15 (else all P) | ok |
| `removeprefix`, `removesuffix` | `(prefix\|suffix: Py_buffer, /)` | ok | ok; "return a copy" | `ReadableBuffer -> bytes` | ✗c docstring `len(prefix)`; ✗c-minor "copy" |
| `startswith`, `endswith` | `(prefix: object(c_name='subobj'), start, end same as find, /)` | bracket override; insp ValueError | bracket | `ReadableBuffer\|tuple[ReadableBuffer,...]`, start/end `-> bool` | ✗a, stubtest blind |
| `decode` | `(encoding: str(c_default="NULL")='utf-8', errors: str(...)='strict')` PK | ok | ok | `str='utf-8', str='strict' -> str` | ok (None is rejected everywhere) |
| `splitlines` | `(keepends: bool=False)` | ok | ok | `bool -> list[bytes]` | b: runtime takes any object (`splitlines(2.5)` works) |
| `fromhex` (classmethod) | `(string: object, /)` | `(string, /)` ok | `classmethod fromhex(string, /)`, versionchanged 3.14 | ≥3.14 `str\|ReadableBuffer`, else `str` `-> Self` | ✗d docstring does not mention bytes-like input |
| `hex` | `(sep: object=NULL, bytes_per_sep: Py_ssize_t=1)` PK | `(/, sep=<unrepresentable>, bytes_per_sep=1)`; insp ValueError | `hex(*, bytes_per_sep=1)` / `hex(sep, bytes_per_sep=1)` | `sep: str\|bytes=..., bytes_per_sep: SupportsIndex=1 -> str` | ✗a unrepresentable default (stubtest still checks it) |

**B. Attributes not in the spec**

| attr | where defined in C | rt | docs | typeshed | mismatches |
|---|---|---|---|---|---|
| `center`, `ljust`, `rjust` | clinic `B.center as stringlib_center` etc., `Objects/stringlib/transmogrify.h` | `(width, fillchar=b' ', /)` | `(width, fillbyte=b' ', /)` | center `fillchar: bytes`; ljust/rjust `bytes\|bytearray` | ✗b name; ✗c typeshed center |
| `zfill` | same file (clinic `B`) | `(width, /)` | same | `SupportsIndex -> bytes` | ok |
| `expandtabs` | same file (clinic `B`) | `(/, tabsize=8)` | `(tabsize=8)` | `SupportsIndex=8` | ok |
| is\*, lower, upper, capitalize, swapcase, title | METH_NOARGS in `bytes_methods[]`; implementation `Objects/stringlib/ctype.h` → `Objects/bytes_methods.c` (shared docstrings, 14 `PyDoc_STRVAR_shared`) | `()` | `()` | `-> bool` / `-> bytes` | ok |
| `__getnewargs__` | `bytes_getnewargs`, bytesobject.c:2563 | `()` | – | `-> tuple[bytes]` | ok (returns an exact copy for subclasses) |
| `__len__`, `__add__`, `__mul__`, `__rmul__`, `__contains__` | `bytes_as_sequence` (bytesobject.c:1808): `bytes_length`, `_PyBytes_Concat`, `_PyBytes_Repeat`, `bytes_contains` | `(value, /)` etc. | prose (common sequence ops) | `__add__(ReadableBuffer)`, `__mul__(SupportsIndex)`, `__contains__(SupportsIndex\|ReadableBuffer)` | ok |
| `__getitem__` | `bytes_as_mapping` → `bytes_subscript` (:1735) | `(key, /)` | prose | overloads: `SupportsIndex -> int`, `slice[...] -> bytes` | ok |
| `__mod__`, `__rmod__` | `bytes_as_number` → `bytes_mod` (:2630) | `(value, /)` | printf-style section | `__mod__(Any) -> bytes`; `__rmod__` absent | b (not flagged by stubtest) |
| `__hash__`, `__iter__`, `__repr__`, `__str__`, `__eq__`/`__ne__`/`__lt__`/`__le__`/`__gt__`/`__ge__` | tp_hash `bytes_hash`, tp_iter `bytes_iter`, tp_repr `bytes_repr`, tp_str `bytes_str`, tp_richcompare `bytes_richcompare` | – | – | comparisons take `value: bytes` (`b < bytearray()` still type-checks through bytearray's reflected method); `__repr__`/`__str__` inherited from object | ok |
| `__buffer__` | `bytes_as_buffer` → `bytes_buffer_getbuffer` (:1801) | `(flags, /)` | – | `(flags: int) -> memoryview` | ok |

### 2. Every difference, by root cause

**(a) The format cannot represent it**
1. **Bracket optionals.** The docs' `[, start[, end]]` form was copied into clinic through `@text_signature` in gh-117431 (commits deb921f8517 and 7ecd55d604a), to keep the old docstring form. As a result:
   - `inspect.signature` raises ValueError for 7 bytes methods (and the same set on bytearray and str).
   - test_inspect records them in `methods_unsupported_signature`.
   - stubtest cannot check them (§3.4).
   - The spec, and clinic without the override, already produce `(sub, start=None, end=None, /)`, which is true (`b.find(b'b', None, None)` works) and matches typeshed. This representation limit was chosen, not forced.
2. **NULL defaults** (`hex` sep; `__new__` source, encoding, errors). The only Python spelling is `<unrepresentable>` or `...`.
   - The docs work around this with two signature lines.
   - typeshed writes `= ...`, or uses overloads for `__new__`.
   - `bytes()` itself has no signature: tp_doc is the hand-written legacy text, and `bytes.__new__` is the generic `(*args, **kwargs)`.
3. **typeshed cannot say "exact type".** Methods return `bytes`; the call table knows "exactly bytes". typeshed's `-> bytes` on methods is right, because a subclass gets an exact bytes back, but it cannot express "returns self" (`b.strip(b'z') is b`, `b*1 is b`, `b+b'' is b`, `b[:] is b`).

**(b) Deliberate modelling choices**
- typeshed:
  - `ReadableBuffer` where clinic uses Py_buffer or checks buffers itself.
  - `SupportsIndex` for Py_ssize_t and slice_index (both call `__index__`: `split(b'b', 1.0)` gives TypeError).
  - `keepends: bool` although the clinic `bool` converter takes any truthy object.
  - `__mod__(Any)`; no `__rmod__`.
  - A three-overload `__new__` that splits out the str+encoding path and hides the always-TypeError branches.
- Docs:
  - Readable names for positional-only parameters (fillbyte, from, iterable).
  - Shared bytes/bytearray entries, and dunders described in prose rather than as methods.

**(c) Real inaccuracies:** see §5 (each checked on both interpreters).

**(d) Version drift**
- For bytes, typeshed and the docs match 3.16 main. stubtest on 3.16 reports no bytes errors. typeshed CI tests only up to 3.15.
- Unrelated, noticed in passing: `memoryview.cast` has a new `order` parameter on 3.16, which the stub lacks.
- The runtime `fromhex` docstring did not follow the 3.14 change (bytes-like input accepted).

**(e) Information only one source has**
- **Spec:**
  - C converters, `c_default`, `c_name`; which parameters are "absent" rather than defaulted.
  - The precedence in `__new__`: `__bytes__` beats str/int/buffer (verified: an int subclass with `__bytes__` gives `b'IB'`, a str subclass with `__bytes__` works).
  - The exact error conditions ("encoding without a string argument", "errors without a string argument").
  - `PyBytes_FromObject` accepts list, tuple and iterables, returns `x` itself for exact bytes, and does not use `__bytes__`.
  - Call-table facts: result exactly bytes, may run Python, always raises for str.
- **typeshed:** return types for every method; element types (`tuple[ReadableBuffer, ...]`, `Iterable[ReadableBuffer]`); version gates.
- **Docs:** identity semantics for center/ljust/rjust/zfill; bytearray does not operate in place; `versionchanged` history; `devmode` checking of `errors`.
- **Docstrings:** example values and parameter descriptions.

### 3. What each source can express that the others cannot

1. **Could spec annotations be typeshed types and still drive clinic?** Not as replacements.
   - A converter carries C semantics that no type has: `c_default`, `c_name`, `accept={int, NoneType}`, NULL meaning absent, and Py_buffer's acquire/release.
   - A type carries shape that no converter has: `tuple[ReadableBuffer, ...]`, `Iterable[ReadableBuffer]`, `str | bytes`.
   - The mapping runs one way only, and only for converter-typed parameters:

     | converter | typeshed type |
     |---|---|
     | Py_buffer | ReadableBuffer |
     | Py_ssize_t | SupportsIndex |
     | slice_index(accept={int, NoneType}) | SupportsIndex \| None |
     | str | str |
     | bool | bool (lossy) |

   - The 16 `object` parameters give nothing: source, sep of split and hex, iterable_of_bytes, sub, prefix, suffix, strip's bytes, table, delete, string. Counted with clones, `object` parameters are about half of all parameters.
   - Return annotations are already clinic return converters (`frontend.py` L17, L307), so typeshed return types cannot go there.
   - Changing that would add a second annotation vocabulary, a new concept, for no C-side gain.
2. **Could spec bodies justify typeshed's overloads?** Yes, for `__new__`, and the correspondence is clean. The non-raising return paths of the body are:

   | spec guard | result | typeshed overload |
   |---|---|---|
   | `source is NULL` | `b""` | `()` |
   | `encoding` given, `isinstance(source, str)` | encoded string | `(string: str, /, encoding, errors)` |
   | `lookup_special(__bytes__)` | result of `__bytes__` | SupportsBytes |
   | `hasattr(type, '__index__')` | zero-filled bytes | SupportsIndex |
   | `hasattr(type, '__buffer__')` in `PyBytes_FromObject` | copy of buffer | ReadableBuffer |
   | list/tuple/`iter()` | bytes from items | `Iterable[...]` |

   - The `cls is not bytes` branch justifies `-> Self`.
   - The raising branches justify why typeshed has no `errors`-without-`encoding` overload and excludes str from overload 1.
   - The element type `SupportsIndex` lives in the C callee `_PyBytes_FromIterator`, not in the body, so it would need a stub fact.
   - The same partial-evaluation machinery that emits `bytes_new_nargs1_*` could enumerate these paths.
   - The one real disagreement, keyword `source=`, is visible only from the spec, since the runtime signature is `(*args, **kwargs)`.
3. **Could return types come from bodies?** Only where a body exists (`__new__`, `PyBytes_FromObject`).
   - For the 24 `...` stubs there is nothing to derive from.
   - The generated table even says "bytes(bytes): result type not known exactly; may run Python code" (`bytesobject_pyspec.c.h` L493). The cause: `bytes.__bytes__` is a stub. At runtime `bytes(b) is b` holds and no Python code runs.
   - A 3-line body for `__bytes__` (`if type(self) is bytes: return self; return C.PyBytes_FromStringAndSize(...)`) would fix that and document the identity rule the docs get wrong.
   - Facts like "returns self when `type(self) is bytes`" for strip, replace, partition and the rest need bodies, or they stay in C.
4. **What typeshed's stubtest can and cannot check today** (mutation experiment):
   - **Caught:** mutations of `split` and `hex`.
   - **Silently missed:** the `find` mutation (renamed parameter, keyword-only, required `zzz`), the `startswith` rename, and a required keyword on `__new__`.
   - stubtest checks only what `__text_signature__` exposes. Making the signatures parseable (R1) is the lever that improves typeshed without CPython shipping stubs.

### 4. Recommendations

**Which source owns which fact**
- Parameter names, kinds and defaults: the spec, that is, clinic input. It already generates `__text_signature__` and docstrings. The runtime is its output, so "runtime" and "spec" are the same authority for shape.
- Behaviour: C code, or the spec body where there is one. The spec runs as Python in test_clinic's difftest.
- Static types and overloads: typeshed. Checked by stubtest against the runtime.
- Prose, version history, user-facing parameter names: the docs. Checked against the runtime for shape only.

**What to change**
- **R1: drop the bracket `@text_signature` overrides.** It is one line each in `bytesobject.c`, `bytearrayobject.c` and `unicodeobject.c`; for bytes, the remaining lines are the three `@text_signature` decorators, and the spec needs no change.
  - Effect: 7×3 methods become introspectable, stubtest starts checking them, and the test_inspect exclusions shrink.
  - Cost: `help()` shows `start=None, end=None` instead of brackets. This is more accurate: None is accepted.
  - No new concept. Fits a normal small CPython PR (the gh-117431 follow-up).
- **R2: a docs-shape test in Lib/test.** It would parse `.. method:: bytes.X(...)` and `.. method:: bytearray.X(...)`, the class-nested `hex` and `fromhex`, and the `.. class:: bytes(...)` lines from `Doc/builtins/stdtypes.rst`, and skip when `Doc/` is absent.
  - Compare: the set of names; kinds; defaults; positional-only-ness (treat `[...]` as optional positional-only; allow two-line alternatives by checking that their union matches).
  - Do not compare names of positional-only parameters; the docs are free to choose them.
  - It would have flagged nothing wrong in bytes today. It guards future drift, for example the 3.15 change that made `count` a keyword needed a manual docs edit.
  - Generating the docs lines from the spec is not recommended. Multi-form lines, shared bytes/bytearray entries and chosen names would all need escape hatches, which is more machinery than a check.
- **R3: do not put typeshed types into the spec, and do not generate a `.pyi` in CPython.**
  - CPython ships no stubs.
  - typeshed spans 3.10–3.15 with version gates and has its own review process.
  - The honest interface between the projects is the introspectable runtime signature, which R1 improves.
- **R4: express facts as spec bodies, not new annotations.**
  - Start with `bytes.__bytes__`, which is cheap and improves the call table.
  - Later, if wanted, a pyspec-side informational report could compare the shapes of typeshed's `__new__` overloads with the spec's return paths. Keep it out of tier-1 tests, because it depends on an external checkout.
- **R5: open the stubs and the spec file question.**
  - Decide where specs for the shared stringlib `B` clinic class live (`transmogrify.h`: center, ljust, rjust, zfill, expandtabs). The brief's `Objects/pyspec/<cfile stem>.py` rule does not cover `.h` files included into two types.
  - Carry the §5 typeshed items upstream as separate typeshed PRs.

### 5. Bugs found (reported, not fixed; checked on build-ws1 and build_perf_base)
1. **CPython docstring bug.**
   - `bytes.removesuffix.__doc__` contains "return bytes[:-len(prefix)]"; it should say `suffix`. bytearray's is correct.
   - Location: spec `Objects/pyspec/bytesobject.py` (removesuffix docstring) = main's clinic block.
   - Repro: `python -c "print(bytes.removesuffix.__doc__)"`
2. **Docs bug.** `Doc/builtins/functions.rst` (`bytes` entry, around L268) says "constructor arguments are interpreted as for bytearray()". bytes() honours `__bytes__`; bytearray() does not.
   - Repro: `class H: __bytes__=lambda s: b'x'` then `bytes(H())` gives `b'x'`, but `bytearray(H())` raises TypeError.
3. **typeshed bug, and a CPython oddity.**
   - The bytes partition/rpartition stub returns `tuple[bytes, bytes, bytes]`, but the separator element is the argument object itself.
   - Repro: `b'abc'.partition(memoryview(b'b'))` gives `(b'a', <memory ...>, b'c')`, and `[1] is mv` is True. mypy reveals `tuple[bytes, bytes, bytes]`.
   - bytearray copies the separator; bytes returns a non-bytes object in its "bytes" tuple. Worth a CPython issue too.
4. **typeshed bug.** `bytes.center` and `bytearray.center` declare `fillchar: bytes`.
   - Repro: `b'abc'.center(5, bytearray(b'x'))` gives `b'xabcx'`, while mypy reports `arg-type`. ljust/rjust already allow `bytes | bytearray`.
5. **typeshed inaccuracy.** The `__new__` overloads make the argument positional-only (`o`, `string`).
   - Repro: `bytes(source=b'x')` gives `b'x'`; mypy reports "Unexpected keyword argument 'source'". The same applies to `bytes(source='x', encoding='ascii')`.
   - stubtest cannot see this (runtime signature is `(*args, **kwargs)`).
6. **Docs imprecise about copy vs identity** (stdtypes.rst L4050, L4111, L3904, L3926, strip/replace entries). For exact bytes the object itself comes back, and partition returns even a subclass instance unchanged.
   - Repro: `b=b'abc'; b.partition(b'z')[0] is b, b.removeprefix(b'z') is b, b.strip(b'z') is b, b.replace(b'z', b'y') is b` gives all True.
   - Subclass case: `class B(bytes): pass; type(B(b'a').partition(b'z')[0])` gives B.
7. **Docs `bytes.count`** (L3890, and the `str.count` wording at L2181): "in the range [start, end]" reads as a closed interval.
   - Repro: `b'aa'.count(b'a', 0, 1)` gives 1.
8. **Docs center/ljust/rjust/zfill:** "For bytes objects, the original sequence is returned". This is false for subclasses.
   - Repro: `class B(bytes): pass; type(B(b'abc').center(1))` gives bytes.
9. **Docs and docstring `translate`:** "must be a bytes object of length 256". Any buffer works.
   - Repro: `b'abc'.translate(bytearray(range(256)))` gives `b'abc'`.
10. **C-API docs `PyBytes_FromObject`** (`Doc/c-api/bytes.rst` L132) says "object that implements the buffer protocol". It also accepts list, tuple and iterators of ints, returns `o` itself for exact bytes, and rejects str and objects that only define `__bytes__`.
    - Repro: `import ctypes; f=ctypes.pythonapi.PyBytes_FromObject; f.restype=f.argtypes[0]=ctypes.py_object` (set `argtypes=[ctypes.py_object]`), then `f([1, 2])` gives `b'\x01\x02'`.
11. **CPython: poor error for `hex(None)`.**
    - Repro: `b'a'.hex(None)` raises "TypeError: object of type 'NoneType' has no len()". bytearray.hex and memoryview.hex behave the same.
12. **CPython: misleading startswith/endswith error.** The message says "must be bytes or a tuple of bytes" although any buffer is accepted.
    - Repro: `b'abc'.startswith(memoryview(b'a'))` gives True; `b'abc'.startswith(97)` raises with that message.
13. **CPython docstring drift:** `bytes.fromhex.__doc__` says "from a string", but since 3.14 it accepts bytes-like input.
    - Repro: `bytes.fromhex(memoryview(b'61'))` gives `b'a'`.
14. **Trivial:** `bytes.lstrip.__doc__` contains "strip leading  ASCII whitespace" (double space).
15. **Process gap, not a bug in any one source:** stubtest silently skips find, index, rfind, rindex, count, startswith, endswith and `__new__` for bytes (and the same families on bytearray and str). To reproduce, corrupt the find stub in a copy of typeshed and run `python -m mypy.stubtest --custom-typeshed-dir <copy> builtins`: it reports no find error, while a corrupted split is reported.

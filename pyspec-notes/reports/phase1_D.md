## Workstream D: C API catalog moved out of the spec, and one ratchet for every dimension

The work is done and committed in two commits on top of 62cc16504fe, in worktree `/home/firebird347/projects/python/cpython/.claude/worktrees/agent-aa7673356f6b55b4b`. The tree is clean. On build-exp with `PYTHONPATH=<worktree>/Lib`, test_pyspec_catalog, test_clinic and test_capi all pass (2077 tests, 11 skipped). `test_tools.basepath` and `REPO_ROOT` resolve to the worktree. Running clinic on bytesobject.c and bytearrayobject.c changes no generated file.

- `bf5b97efaca` pyspec: measure disconnects as a ratchet with a checked-in baseline
- `30cebd8114e` pyspec: move the C API catalog out of the bytes spec

### Starting counts per dimension
`-v` prints this summary at the end of the run. The test itself takes about 0.37 s (12 tests).

| Dimension | Lines | What they are |
|---|---|---|
| capi | 29 | 6 bytearray functions with no "may run Python" fact yet; 17 documented functions missing from threadsafety.dat (12 `PyBytesWriter_*`, Check/CheckExact ×2 types, `PyByteArray_Resize`); 6 documented `PyObject *` functions missing from refcounts.dat (`DecodeEscape`, `Join`, `Repr`, 3 `PyBytesWriter_Finish*`) |
| docs | 1 | `bytearray()` has no runtime signature to compare with |
| slots | 3 | `__rfloordiv__`, `__rtruediv__`, `__rmul__` missing from typeobj.rst |
| docstrings | 22 | 13 ctype docstrings (spec and `bytes_methods.c`); 7 bytearray clinic docstrings identical to the bytes spec (lstrip, rstrip, strip, maketrans, replace, translate, plus reduce/reduce_ex); 2 iterator docstrings |
| typeshed | 1 | `bytes.__new__`: typeshed makes the first argument positional-only (WS9 bug 5). Only runs with `PYSPEC_TYPESHED=<checkout>` |

All five dimensions cover both bytes and bytearray where the data allows.

The old 41 pins are gone:
- The 15 header/C parameter-name pins and the docs/refcounts name pins were noise. Parameter names are no longer compared.
- `declared-elsewhere` and the prose-keyword heuristics (`error-unstated`, `behavior:*-unstated`) were dropped.
- The refcounts check now only flags entries whose absence changes the rendered docs (a documented function returning `PyObject *`).
- The 15 `test_typeobj_rst` pins shrank to the 3 real omissions, because rows for non-slot attributes are no longer compared.

### Mutation checks
Each edit was applied to the tree, the checker run, and the file restored.

**Caught as a new line:**
- refcounts.dat: an added parameter, and a renamed function.
- `bytes.rst`: `PyBytes_Size` return type changed.
- threadsafety.dat: an entry removed, and a typo entry added.
- `Include/bytesobject.h`: a parameter added (reported against the docs, refcounts.dat and the C definition).
- stable_abi.toml: an entry renamed.
- The facts file: an entry removed.
- stdtypes.rst: an added `/`, a dropped `[, end]`, a changed default.
- typeobj.rst: `__len__` renamed.
- A new duplicated docstring in bytearrayobject.c.

**Caught as a fixed line** (the test says to delete it): editing the `bytes_methods.c` copy of a docstring.

**typeshed:** WS9's stubtest blind-spot mutation (find → `(needle, *, begin, zzz)`) is caught. Renaming a positional-only parameter (`startswith` `pfx`) is ignored on purpose, per the R2 rules.

### File layout
- **`Tools/clinic/libclinic/pyspec/disconnects.py`** (new, replaces `capi.py`). One small reader per source, one function per dimension, and the signature rules: parse, merge several lines or overloads into one, compare shapes.
- **`Tools/clinic/pyspec-baseline/{capi,docs,slots,docstrings,typeshed}.txt`**. One sorted, human-readable line per disconnect, with no line numbers.
  - I put them next to the tool that checks them, like `Tools/build/.warningignore_*` and `Doc/tools/.nitignore`.
  - Not in Lib/ (the check needs the source tree: Doc/, Include/, Objects/) and not in Misc/ (which holds data that builds and docs consume).
- **`Objects/pyspec/capi/bytesobject.py`** (62 lines). The only hand-written C API facts left: `RUNS_PYTHON` and `NO_PYTHON`, two sets of names.
  - Every non-static function defined in bytesobject.c must be in exactly one set, so an unclassified new function fails the test.
  - `PyBytes_FromObject` is not listed: its spec body gives the facts.
  - It is read with `ast.literal_eval`, so it is easy to move when P1/P2 land.
- **`Lib/test/test_pyspec_catalog.py`**, moved out of `test_capi/` so that `python -m test test_pyspec_catalog -v` works as you asked.
- **`Objects/pyspec/bytesobject.py`** went from 1196 to 631 lines. The catalog and its copied Doc/c-api prose are gone, as is the doc-equality check.
  - It is not down to ~550 because I left the 80 lines of escape stubs in place. `call_table` looks them up in the same spec, so moving them would mean editing A's code, and P1 removes them anyway.
  - They still work. Their vocabulary import moved to the top of the file, which also fixes "`New` used before import".

### Infrastructure added and removed
- **Code:** `disconnects.py` (770) + the new test (141) = 911 lines, against `capi.py` (1089) + the old test (286) + `test_typeobj_rst` (54) = 1429. That is 518 fewer lines.
- **Spec:** 565 fewer lines.
- **`runtime.py`:** 40 fewer lines. The vocabulary only the catalog used is removed (`Out`, `InOut`, `NullIn`, `Steals`, `char_p`, `void_p`, `const_void_p`, `va_list`).
- **Data added:** 76 lines of baselines and 62 lines of facts.
- **Overall:** +1086 / −2075 lines.

### How a contributor ratchets it down
1. Fix a disconnect in the real file: add the refcounts.dat or threadsafety.dat entry, fix the rst line, delete the duplicated docstring, or classify a bytearray function in a new `Objects/pyspec/capi/bytearrayobject.py`.
2. Run `./python -m test test_pyspec_catalog`. It fails with "Fixed disconnects: delete these lines from `Tools/clinic/pyspec-baseline/<dim>.txt`:" followed by the exact lines.
3. Delete those lines and commit.

A new disconnect fails with "New disconnects: fix them (or, if that is the intent, add these lines to …)", followed by the exact lines. Adding a line is visible in review. `-v` prints the count per dimension.

### Open problems
- **The docs dimension compares with the running interpreter** (the spec only for `bytes()`), so it needs a rebuilt Python after a signature change.
- **The typeshed baseline depends on the typeshed commit** (noted in the file header). Methods typeshed inherits, such as `bytearray.clear`, and `bytearray()`, which has no runtime signature, are skipped.
- **Facts the catalog held that no source has, and nothing consumed, were dropped:** error conventions, `InOut`/`NullIn`, steals of non-objects (the writer), and the "implied refcounts.dat lines" report. P2 needs a home for these. refcounts.dat can't express them.
- **The limited-API check assumes a top-level `Include/*.h` declaration is limited.** That holds for bytes and bytearray; types with `#ifndef Py_LIMITED_API` sections in those headers would need a better rule.
- **Files outside my ownership that I edited or left stale:**
  - `Lib/test/test_clinic.py` (B's structure): I deleted `test_typeobj_rst` and its two pin sets (54 lines, a contiguous block).
  - `slots.py` (B's) still says "test_clinic checks that the two agree". I did not edit it.
  - `runtime.py` has no listed owner; I trimmed its vocabulary and comments.
  - `@helper` now has no consumer (it only marks stubs); P1 is expected to remove it.

Scratch scripts (`mutate.py`, `mut_ts.py`, `gen.py`, `run.py`) are in `/tmp/claude-1000/-home-firebird347-projects-python/2290c1d8-9873-48d1-a600-904f809b5565/scratchpad/`.
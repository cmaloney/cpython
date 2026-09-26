## SUMMARY (legibility / developer-experience review of exp/ac_python_overloads_v0 @ 62cc16504fe vs main ee1bbf037ff)

**Verdict.** The spec reads well where it restates Argument Clinic: method signatures, docstrings and slot stubs. Adding a C method is now easier than on main, because the method table is generated. Three things make it much harder to work with:
- Most of the spec file is not about the type. It is 1196 lines, of which 566 are the C API catalog with copied RST docs and 80 are escape stubs.
- Several mistakes are accepted silently, or produce wrong output with no error (list below).
- A spec body needs edits to 3 or 4 files, 3 of them in Tools/.

**Concept count.** A contributor working on bytes now needs about 51 concepts (about 40 distinct), against about 14 for plain Argument Clinic on main plus 3 C-API bookkeeping files. By my rating, 16 are essential, 20 incidental and 15 removable. P1+P2, the other recommended deletions and merges, and one mode would bring this to about 26–28.

**Contributor tasks, done in the throwaway tree** (clinic from the tree; bytesobject.c compiled with clang against build-exp's pyconfig):
- **(a) Keyword parameter for bytes.split:** about 10 min. I edited the spec, ran clinic, got a C error `conflicting types for 'bytes_split_impl'`, and fixed both heads by hand. The `rsplit` clone got the parameter too, which I didn't expect. I also had to run regen-global-objects, as on main.
- **(b) New C method:** about 5 min, and nicer than main: `BYTES_ISBINARY_METHODDEF` is added to the table automatically. If the C impl is missing you get only a warning (`-Wundefined-internal`), and the real failure comes at link time.
- **(c) New method with a spec body:** about 45 min. `return len(self) == 0` gave "unsupported return". `if C.PyBytes_Size(self) == 0` gave "unsupported value C.PyBytes_Size(self)" whether or not the escape existed. `return True` gave "no Py_GetConstant() for True". Once that was fixed, I got a KeyError 'bool' traceback from call_table. Four files needed edits: spec, runtime.py, emit.py, call_table.py. **clinic exited 1 after writing bytesobject.c.h**, which leaves the tree inconsistent.
- **(d) Slots:**
  - Renaming `__len__`'s C name is trivial.
  - `@classmethod @c_name(METH_O="Py_GenericAlias") def __class_getitem__` produces `{..., METH_O, ...}` **without METH_CLASS**. That is silently wrong.
- **(e) Stale facts, nothing caught any of them:**
  - I made `_PyBytes_FromBuffer` run Python code (a warning); the stub still says no Python code for bytearray.
  - I changed `PyBytes_AsString` to `NoError`.
  - I added `RunsPython` to `PyBytes_Repr`.

  In all three cases test_clinic and test_pyspec_catalog still pass. The tier-2 NO_PYTHON uop trusts the first fact. A stub with no RunsPython *claims* that no Python code runs, so the default is the unsafe answer.
- **(f) Error messages for deliberate mistakes:**
  - Good (file:line and what to do): wrong converter, docstring on a slot, partial richcompare group, slot parameters, unknown clinic decorator on a method, METH_O arity, missing class directive, parameter docs out of order.
  - Bad:
    - A clone placed before its target is accepted by clinic; only a NameError in a test catches it.
    - A typo in a shared method name gives a raw traceback, and the advice ("write centre = transmogrify.B.centre") is wrong.
    - `@cname(...)` on a slot is silently ignored, and the default C name is used.
    - `import transmogrify as tm` **silently drops center, expandtabs, ljust, rjust and zfill from bytes**.
    - A `@getter` generates `BYTES_NBYTES_METHODDEF`, which then fails to compile, far from the cause.
    - Error messages come in 4 different formats.

**Other findings**
- The Makefile doesn't list `clinic/*.h` as dependencies. In no-block mode a docstring- or decorator-only spec edit changes only the .c.h, so `make` leaves a stale bytesobject.o.
- Generated C is readable. Amplification is 15–25×: a 1-line spec edit gives 30 changed generated lines, and a 3-line edit gives 93.
- There are no source-line markers from the C back to the spec, and `_pyspec.c.h`/`_types.c.h` have no checksum.
- There are 3 generated includes, at 3 positions in bytesobject.c.

**Top recommendations** (ranked by burden removed per unit of effort)
1. Make every silent acceptance an error, and make clinic write nothing when any stage fails. Each is a small fix (list in §5.1).
2. Take the C API catalog and escape stubs out of the type spec, and stop copying Doc/c-api text; the catalog already parses the RST. That removes 566 lines and the docs-equality rule.
3. Write a contributor how-to: a new "Declaring a type in a spec file" section on the devguide's Argument Clinic page, plus a 1-page `Objects/pyspec/README.rst` with a "to do X, edit Y" table.
4. Add `clinic/*.h` (with `$(wildcard)`) to the Makefile object dependencies.
5. P1: one place per helper. It removes `C.`, Escape(template, returns, error, release, steals, exact), `@helper` and the escape-stub consistency test (net −3 concepts).
6. P2 (net −6 to −8), plus reading C parameter types from the headers (−1 more). Make an unannotated `...` stub mean "worst case".
7. Pick one mode. I recommend one-line blocks: they fix `#if`, hand-written heads, reorder churn, the lost C→spec link and much of the Makefile hazard.
8. Merge the 7 per-type tables in Tools/ into one. Merge `_types.c.h` into `_pyspec.c.h` and include it once, at the end.
9. Write clones as full `def`s (Python has no clone concept). This removes the ordering rule and the class-dict order change. Also drop the bracket `@text_signature`s.
10. Keep PRs small by landing in this order:
    1. signatures only, with byte-identical `.c.h`;
    2. types generation;
    3. bodies;
    4. JIT facts;
    5. the catalog.

    Convert one type per PR, starting with tuple/float.

**Caveat:** `build-exp/python` is actually `6ebfa788782-dirty` (the WS12 merge, the parent of 62cc), not 62cc16504fe. I used it only to run clinic and the Python-level tests with `PYTHONPATH=<tree>/Lib`; I checked that REPO_ROOT and test_tools.basepath resolved to the tree. BytesSpecTypeTest compares the spec with the *built* interpreter, so it fails until you rebuild ("Lists differ"); I did not rebuild. The worktree is removed, and the main checkout is untouched at 62cc16504fe.

---

## FULL REPORT

Line numbers are at 62cc16504fe. "Spec" means `Objects/pyspec/bytesobject.py`.

### 1. Concept inventory

Ratings: **E** = essential (needed by any spec mechanism), **I** = incidental (a consequence of how it is built now), **R** = removable (P1/P2 or another recommendation removes it).

**A. Files and places a contributor must know**

| # | Concept | Where | Rating |
|---|---|---|---|
| 1 | The spec file, the one new file kind | spec | E |
| 2 | A spec of a `.h` template, processed when clinic runs on the `.h` | `Objects/stringlib/pyspec/transmogrify.py`; `frontend.spec_path` frontend.py:223 | I |
| 3 | An import-only spec with no C file ("No clinic runs on ctype.h") | `Objects/stringlib/pyspec/ctype.py:1-12` | I (merge with 2) |
| 4 | bytesobject.c: 2 class directives (L23, L2777), hand-written impl heads, and 3 generated includes at 3 fixed positions (L31, L2469, L3428) | bytesobject.c | I |
| 5 | `clinic/bytesobject.c.h` | same as AC | E |
| 6 | `clinic/bytesobject_pyspec.c.h` (bodies, variants, call table) | | E (only when bodies exist) |
| 7 | `clinic/bytesobject_types.c.h` | | I (merge with 6) |
| 8 | `runtime.py class C` escapes, edited in Tools/ for any new C call from a body | runtime.py:236-301 | R (P1) |
| 9 | Tables in Tools/ a body author may have to extend | `emit.CONSTANT_OBJECTS` emit.py:88, `emit.TYPE_CHECK` :71, `frontend.TYPE_OBJECTS` frontend.py:152, `call_table.TYPE_OBJECTS` call_table.py:57 (a different copy), `CANDIDATE_TYPES` :53, `partial_eval.ITERATION` partial_eval.py:78, `SLOT_CHECK` emit.py:83 | I |
| 10 | Doc/c-api/bytes.rst docstrings copied into the spec; test_facts asserts they are equal (test_pyspec_catalog.py:147-151) | spec L510-1115 | R |
| 11 | `EXPECTED_DISCONNECTS` pinned list | test_pyspec_catalog.py:27 | I |
| 12 | `Include/internal/pycore_pyspec.h` | only for JIT work | I |

**B. Spec method syntax** (the Argument Clinic concepts in a new spelling)

| # | Concept | Rating |
|---|---|---|
| 13 | Converter as the annotation, including converter arguments (`slice_index(accept={int, NoneType}, c_default='0')`, spec L127) | E |
| 14 | `NULL` default | E |
| 15 | Implicit self/cls; `/` and `*` | E |
| 16 | `@classmethod`/`@staticmethod`; `__new__` is implicitly a class method | E |
| 17 | Clinic decorators as identity decorators (runtime.py:50-62) | E |
| 18 | Docstring layout: summary, then a "  name" plus 4-indent parameter section, in signature order (frontend.py:22-24) | E |
| 19 | The return annotation means a return converter on clinic methods (frontend.py:21) but facts on slots and stubs (frontend.py:102-103, spec L454/465/492). One place, two meanings | I |
| 20 | Clones: `meth = other`, `meth = deco(other)`, a bare string after it is the docstring, and the clone must follow its target (spec L142-143, L219, L320, L326, L361) | R |
| 21 | The converter pseudo-argument `c_name='x'` (parameter rename). Its name collides with `@c_name`, and at spec L65 it is a leftover from `source as x` (only the parser local is `x`) | I |
| 22 | Stub vs body: `...` or docstring-only is hand-written; anything else is generated (frontend.py:267-276). `pass` counts as a body and gives "control reaches the end" | E |

**C. C naming rules**

| # | Concept | Rating |
|---|---|---|
| 23 | Default C basename, except that `T.__new__` is `T_new` while `T.__init__` stays `T___init__` (frontend.py:38-42) | I |
| 24 | `@c_name("x")`, which is clinic's `as` | E |
| 25 | `@c_name(mp_length=..., sq_length=...)` for dunders that several slots can implement; a group partner inherits the choice | I |
| 26 | `@c_name(METH_NOARGS=...)` / `METH_O` for hand-written PyCFunctions | I |
| 27 | Top-level names starting with `Py`/`_Py` are non-static and catalogued; others are static (emit.py:17-19). That is why `_PyBytes_FromIterator` became `bytes_from_iterator` | I |
| 28 | A slot's C name defaults to `<class>_<slot minus prefix>` | I |

**D. Types**

| # | Concept | Rating |
|---|---|---|
| 29 | Slots: a dunder listed in slotdefs is a slot; its parameters are unannotated, it has no docstring, and its whole group must be declared | E (once types are generated) |
| 30 | `@static_type(member=...)` with a derived-members list (typeobj.py:17-31); `@final` | E |
| 31 | The `class` directive in the .c decides which spec classes are generated, and gives the C type used for tp_basicsize | I |
| 32 | Shared methods: `from stringlib.pyspec import ...` resolved relative to the C file's directory, `meth = mod.B.meth` with the same name | E-ish |
| 33 | Spec order is the method-table order, which also changes `bytes.__dict__` order (find before count) | I |

**E. Modes and regeneration**

| # | Concept | Rating |
|---|---|---|
| 34 | No-block mode vs one-line-block mode. In no-block mode heads are hand-written, block methods come first and the others follow in spec order, and methods under `#if` need a block (app.py parse_spec_methods / _parse_spec_method) | R (pick one) |
| 35 | `make clinic` / clinic.py on a file, and `test_up_to_date` (test_clinic.py:7005, :7020). The Makefile doesn't track `.c.h` | E, plus an I trap |

**F. Spec bodies**

| # | Concept | Rating |
|---|---|---|
| 36 | The accepted Python subset (emit.py:27-43) | E |
| 37 | Ownership rules for locals (emit.py:45-53) | E for authors, but should stay invisible |
| 38 | `C.<name>` escapes and `Escape(template, returns, error, release, steals, exact)`, `ContextEscape`, `RaiseEscape` (runtime.py:129-203) | R (P1) |
| 39 | Spec builtins with C meanings: `NULL`, `isinstance` (real type), `iter` (wrapper), `hasattr(type(x), "__dunder__")`, `tp_name`, `fqname` | E (small) |
| 40 | `bytes.meth(...)` in a body calls the spec method, through an AST rewrite (runtime.py:540-570) | I |
| 41 | Per-type variants, `KEEP_RATIO`, `CANDIDATE_TYPES` (call_table.py:10-14, :53, :72) | I (reviewers only) |
| 42 | The `ITERATION` facts table | I (belongs in type specs) |
| 43 | Loop lowering: index loops, versioning, item-type split (partial_eval.py:8-31) | I (reviewers only) |

**G. Facts vocabulary** (runtime.py:304-365, 368-448)

| # | Concept | Rating |
|---|---|---|
| 44 | C types: `cstr`, `char_p`, `void_p`, `const_void_p`, `Py_ssize_t`, `int`, `va_list`, `pointer('T')`, `None`, `*args: ...` | R (read from the headers the catalog already parses) |
| 45 | `New[object]`, `New[T]` (exact type), `Borrowed` | R (P2 plus refcounts.dat) |
| 46 | `Steals`, `Out`, `InOut` | R (refcounts.dat) |
| 47 | `OnError[T, v]`, `NullIn('p')`, `NoError` | R (P2) |
| 48 | `RunsPython`, `RunsPython[T, 'p']` | R (P2) |
| 49 | `@helper`, needed only for Py-prefixed names from other files: lookup_special, bytes_copy and bytes_from_hex have no `@helper` (spec L1132, L1189, L1194) | R (P1) |
| 50 | Each escape needs a stub whose error convention matches `Escape.error` (test_clinic `test_escape_stubs` :7343) | R (P1) |

**H. Tests**

| # | Concept | Rating |
|---|---|---|
| 51 | Tests that guard the spec, listed below | E in kind, I in number |

The tests in #51:
- **BytesSpecTest** (test_clinic.py:6829) runs the spec as Python against the interpreter, for `__new__`, `__bytes__` and fromhex only.
- **BytesSpecTypeTest** (:7032) compares the spec with the *built* interpreter.
- **BytesSpecFactsTest** (:7195) covers the derived facts and the escape stubs.
- **PyspecSlotdefsTest** (:7106).
- **Pyspec{,Stub,NoBlock,Type}Test** cover the tool.
- **test_up_to_date** checks both `bytes*.c.h` files and transmogrify.
- **test_pyspec_catalog** pins disconnects.
- **test_opt** checks the uops.

**Plain Argument Clinic on main:** about 14 concepts:
1. block markers and checksums;
2. the function line and `as`;
3. converters and their arguments;
4. defaults, including NULL;
5. `/` and `*`;
6. the docstring and parameter docs;
7. `class`/`module` directives;
8. decorators;
9. clones;
10. return converters;
11. the `clinic/*.c.h` include;
12. adding `*_METHODDEF` to a hand-written table;
13. the hand-written PyTypeObject and slot tables;
14. `make clinic`.

It also has 3 bookkeeping files kept by hand: rst, refcounts.dat and stable_abi.toml.

**Totals:** about 51 items (about 40 distinct) on the branch against about 17. By my rating: 16 E, 20 I, 15 R.

**How P1 and P2 change the count**
- **P1:** removes #8, #38, #49 and #50 and adds `@c_implemented`, net −3. It also removes the "3 places per helper" rule: the C definition, the `runtime.C` entry at runtime.py:259 for `_PyBytes_FromBuffer`, and the stub at spec L1157.
- **P2:** replaces #45–#48 (about 10 words) with `exact(T)`, `unknown()`, `calls(x, "__slot__")` and `runs_python()`. That is about −6 words. It also flips the unsafe default, since `...` would mean worst case.
- **Reading C types from headers:** −1 (#44).
- **Dropping the docs copies:** −1 (#10).
- **One mode:** −1 (#34).
- **Clones as full defs:** −2 (#20, #33).
- **Merging tables and outputs:** −2 (#7, #9).
- **Merging `.h` spec kinds:** −1 (#2/#3).

Result: about 26–28.

### 2. Contributor tasks (done in the throwaway tree)

Setup notes:
- Tree: `git worktree add .../review_dx/tree 62cc16504fe --detach`, now removed.
- Clinic: `build-exp/python Tools/clinic/clinic.py Objects/bytesobject.c` takes 0.49 s.
- Compile: clang `-c` of bytesobject.c using `-I` for tree/Include and build-exp's pyconfig.h.
- Tests: `PYTHONPATH=<tree>/Lib systemd-run --user --scope -q -p MemoryMax=6G -p MemorySwapMax=0 -- build-exp/python -m test test_clinic test_capi.test_pyspec_catalog`. The baseline gives SUCCESS, 493 tests in 1.9 s.

**(a) Add keyword `keepempty: bool = True` to bytes.split.** About 10 min.
- Files: the spec (signature plus a docstring parameter section), the two impl heads in bytesobject.c, `bytesobject.c.h` (regenerated, +72/−35 lines), and the 4 global-string headers.
- Errors:
  - `Objects/bytesobject.c:1815:1: error: conflicting types for 'bytes_split_impl' … note: previous declaration is here Objects/clinic/bytesobject.c.h:1121`. It points at the right place, and a C developer knows what to do.
  - The `_Py_ID(keepempty)` error needs `Tools/build/generate_global_objects.py`, the same as on main.
- Surprises:
  - `rsplit = permit_long_summary(split)` 13 lines below also got the parameter.
  - On main, clinic would have rewritten the head itself.
  - bytearray.split is still an Argument Clinic block in bytearrayobject.c, so the same change on both types uses two different mechanisms.

**(b) New C method `isbinary(self, /, strict: bool = False)`.** About 5 min.
- Files: the spec (+4), bytesobject.c (hand-written impl), `bytesobject.c.h` (+68) and `bytesobject_types.c.h` (+1, `BYTES_ISBINARY_METHODDEF` inserted in spec order).
- Before the impl exists you get only a warning: `bytesobject.c.h:649: warning: function 'bytes_isbinary_impl' has internal linkage but is not defined`. The hard error comes at link time.
- `test_clinic` then fails in `BytesSpecTypeTest.test_bytes` with a truncated "Lists differ: [...] != [...'isbinary'...]" until the interpreter is rebuilt. The message doesn't say "rebuild".
- This is better than main, where you add the METHODDEF to the table by hand.

**(c) New method with a spec body (`isempty`).** About 45 min.
1. `return len(self) == 0` gave `Objects/pyspec/bytesobject.py: line 120: unsupported return len(self) == 0`. Nothing says where the subset is documented (emit.py:27-43).
2. `if C.PyBytes_Size(self) == 0:` gave `unsupported value C.PyBytes_Size(self)`, both before and after adding the escape. This is misleading:
   - comparisons only take names (emit.py:325-344, 378-381);
   - the "unknown escape" message (emit.py:139) is only reached in statement position.
3. Adding the escape meant editing **Tools/clinic/libclinic/pyspec/runtime.py** `class C`, with a template, `returns` and `error` (ERR_MINUS1 is needed even though `PyBytes_GET_SIZE` cannot fail, so the emitted code has a dead `n == -1 && PyErr_Occurred()`). Its facts came silently from the unrelated catalog stub `PyBytes_Size` (spec L708).
4. `return True` gave `no Py_GetConstant() for True`: `emit.CONSTANT_OBJECTS` (emit.py:88-95) has no True/False. I edited **emit.py**.
5. Then a raw traceback: `KeyError: 'bool'` at call_table.py:352. `call_table.TYPE_OBJECTS` (:57) differs from `frontend.TYPE_OBJECTS`. I edited **call_table.py**.
6. **Partial write:** when clinic exits 1 at step 1, `Objects/clinic/bytesobject.c.h` has already been rewritten (it declares `bytes_isempty_impl` and its parser), but `_pyspec.c.h` and `_types.c.h` have not. Main's clinic leaves nothing half-written.

Result: 4 hand-edited files (spec, runtime.py, emit.py, call_table.py) plus 3 generated ones. The output is correct (bytesobject_pyspec.c.h +26, including a call-table entry "result is exactly bool; runs no Python code"), and nothing asks for a difftest case.

**(d) Slots.**
- Renaming: `@c_name(mp_length="bytes_len", sq_length="bytes_len")` changes 2 lines in `_types.c.h`, and the C error names the undeclared identifier. Fine.
- Removing the `@c_name` gives `bytes.py:464: bytes.__len__: several slots can implement __len__ (mp_length, sq_length); name them: @c_name(mp_length="...", ...)`. Good.
- `@c_name(sq_length=...)` alone silently drops mp_length. That is legal, and nothing flags it.
- `__class_getitem__` written as `@classmethod @c_name(METH_O="Py_GenericAlias")` generates `{"__class_getitem__", Py_GenericAlias, METH_O, ...}`. **METH_CLASS is missing and there is no error.** The result is silently wrong: `bytes[int]` would fail at runtime. METH_CLASS is unsupported (as WS12 noted), but `@classmethod` should then be rejected.

**(e) Changing a C helper (`_PyBytes_FromBuffer`).**
- I added `PyErr_WarnEx(...)` at bytesobject.c:2474, so the helper now runs Python code (warning filters) for every argument. Clinic output is unchanged. test_clinic and test_pyspec_catalog both pass.
- The stale fact `RunsPython[New[bytes], 'x']` (spec L1157) still says bytearray and memoryview run no Python code. The tier-2 `_CALL_BUILTIN_CLASS_1_INLINE_NO_PYTHON` relies on that.
- No check could catch it:
  - `@helper` stubs are skipped by the catalog.
  - The difftest compares only results and exceptions (test_clinic.py:6948-6966), and it uses the Python stand-in `memoryview(x).tobytes()` (runtime.py:259) rather than the C.
- Stale facts on catalog functions aren't caught either. `PyBytes_AsString -> NoError[char_p]` (docs say NULL plus TypeError) and `PyBytes_Repr -> RunsPython[...]` both pass. test_facts only pins a few examples.
- To understand the one helper you must read 3 places: C at bytesobject.c:2472, the escape at runtime.py:259 and the stub at spec L1157.

**(f) Deliberate mistakes** (✓ = says what to do and points at the right file:line):

| Mistake | Message | Verdict |
|---|---|---|
| Wrong converter `Py_ssize_tt` | `Error in file 'Objects/pyspec/bytesobject.py' on line 348: 'Py_ssize_tt' is not a valid converter (in the clinic input taken from bytes.split in …:348)` | ✓ (location repeated) |
| Docstring on a slot | `…:442: bytes.__repr__: a slot has no docstring: its wrapper's comes from slotdefs in Objects/typeobject.c` | ✓ |
| Partial richcompare | `…:49: class bytes: tp_richcompare also implements __ge__: declare it too` | ✓ (points at the class, not the group) |
| Wrong slot parameters | `…:478: bytes.__contains__($self, /): the signature of sq_contains is __contains__($self, key, /)` | ✓ |
| Annotated slot parameter | `…the C signature of a slot is fixed: parameters are not annotated` | ✓ |
| Stale fact | none (see e) | ✗ |
| Head mismatch in no-block mode | clang `conflicting types`, with a note at the `.c.h` prototype | ✓ (C-level) |
| Missing impl | warning only; link error | ~ |
| Clone before its target | **clinic accepts it** and reorders `_types.c.h`. Only `BytesSpecTest.setUpClass` fails, with `NameError: name 'find' is not defined` | ✗ (the spec isn't valid Python and clinic doesn't notice) |
| Shared name typo `transmogrify.B.centre` | **raw traceback**, `SpecError: …:120: a shared method keeps its name: write centre = transmogrify.B.centre`. Wrong advice; the real problem is that `centre` is not in B. The SpecError is raised in `Spec.__init__` and `app.pyspec` only catches SyntaxError (app.py pyspec property) | ✗ |
| `@cname(...)` on a slot | **silently ignored**; the default `bytes_getbuffer` is used, and the C error comes later | ✗ |
| `@permit_long_sumary` on a method | `'bytes.find': unknown clinic decorator @permit_long_sumary` plus the spec line | ✓ |
| METH_O on a no-args method | `…:109: bytes.__getnewargs__: a METH_O function takes (self, arg, /)` | ✓ |
| Unknown escape in statement position | `line 116: unknown escape C.bytes_kopy` | ✓ (does not say "add it to runtime.py C") |
| `import transmogrify as tm` | **silently drops 5 methods** (center, expandtabs, ljust, rjust, zfill) from `bytes_methods[]`. Unrecognized class-body statements are ignored (frontend.py:347-372) | ✗✗ |
| `@getter def nbytes` in a `@static_type` class | generates `BYTES_NBYTES_METHODDEF` in the method table; C error `use of undeclared identifier 'BYTES_NBYTES_METHODDEF'`; no tp_getset | ✗ |
| `@setter` with the same name | the second def replaces the first; `parameter 'value' needs a converter` | ✗ (design gap) |
| Missing class directive for bytes_iterator | `…:485: class bytes_iterator needs a clinic class directive in the C file (its C type and type object)` | ✓ |
| `pass` instead of `...` | `bytes_join_impl: control reaches the end` | ~ (should say "use `...` for a C implementation") |

Four error formats are in use: `Error in file 'X' on line N:` + `X:N:`; `Error:\nX: line N:`; `Error:\nX:N:`; and a Python traceback.

### 3. Legibility of the generated code and the spec

**Generated `bytesobject_pyspec.c.h` (1305 lines).** Reviewable. `bytes_new_impl` (L11-97) reads like the old hand-written C. Problems:
- Each variant carries its partially evaluated Python as a comment (L339-405), which is useful, but:
  - The comments contain renamed locals (`item_2`, `writer_3`).
  - They show three *identical* branches, `if type(item_2) is int: value_2 = C.PyNumber_AsSsize_t(item_2, NULL) elif … bool: (same) else: (same)` (L373, L649, L728). The difference only exists as a hidden `call.pyspec_exact` mark (partial_eval.py:26-31). That confuses reviewers; print the lowering choice (e.g. `# exact int: inline`).
- Amplification: a 1-line message change gives +15/−15 generated lines; splitting one `if` gives +77/−16. It is repetitive and diffable, but noisy.
- `bytes_new_nargs1_bytearray` is also used for the memoryview entry (L1069, L1079), because deduplication keeps the first name. Name shared variants neutrally, e.g. `_buffer` or by a hash.
- There are 11 `fromhex` table entries that differ only in `arg_type` (L1183-1300).
- The code uses `Py_XDECREF` on values known to be non-NULL (L63, L69) and `{ PyObject *_return_value … }` blocks (L23-27, L119). This is harmless.
- There are no `/* bytesobject.py:NN */` markers or `#line`, so a gdb backtrace into generated code can't be mapped back to the spec.
- The `[pyspec]` header (L1-4) has no checksum, so hand edits are caught only by `test_up_to_date`.

**`bytesobject_types.c.h` (225 lines):** very readable, with designated initializers. It reproduces the old-style `B.capitalize() -> copy of B` ctype docstrings.

**`bytesobject.c.h`:** the net diff against main is 1381 lines, almost all reordering, because spec order is now the table order (WS12). Switching one method to block mode reorders it again (I saw 398 changed lines).

**Spec (1196 lines).** Composition:
- `class bytes`: L39-478;
- iterator: L481-507;
- bodies: L510-547;
- **catalog: L550-1115 (566 lines, mostly Doc/c-api RST copied verbatim, including a 50-line RST table at L613-655)**;
- escapes: L1117-1196.

A newcomer opening "the bytes spec" is mostly reading C API documentation. Confusing spots:
- **L1-24:** the docstring explains 4 mechanisms. L9 is over-long.
- **L28-36, L567, L1129:** three import blocks, two of them mid-file with `# noqa: E402`.
- **L65:** `source: object(c_name='x') = NULL`. `c_name='x'` is dead weight: only the parser local is `x`, and the generated impl uses `source`. It also shares a name with `@c_name`.
- **L69-71:** `bytes.__new__(bytes, source, …)` calls the *spec* method only because `runtime.load` rewrites the AST (runtime.py:540-570). A reader expects the builtin.
- **L89, L98, L100:** these look like Python but are special forms: the walrus with `C.lookup_special`, `hasattr(type(x), "__index__")` → `_PyIndex_Check`, and passing an exception class as an argument.
- **L142-143, L219-223, L320-330, L361-366:** clones with a bare-string docstring after them. As Python, `bytes.count.__doc__` is find's doc, so "runs as Python" is not faithful here.
- **L123, L164, L385:** `@text_signature("($self, sub[, start[, end]], /)")` makes `inspect.signature` fail (WS9 R1).
- **L438-441:** you need frontend.py to understand the slot rules.
- **L454, L465, L492:** the return annotations `New[...]`/`NoError[...]` are facts here but return converters on clinic methods. `New` is used before it is imported at L567; this only works because annotations are lazy and clinic reads the AST. `-> New[int]` meaning "and never runs Python" is a negative fact expressed by *omission*.
- **L525-526:** a comment points into partial_eval.py.
- **L537-547 vs L1168:** `writer = C.bytes_appender(size)`, but the stub says `-> OnError[int, -1]`; the escape actually returns the struct `bytes_appender` with ERR_NEGATIVE (runtime.py:265-269).
- **L1132-1196:** the escape stubs break the module-docstring rule "top-level functions are C functions of the same name" (L12-13). `lookup_special`, `bytes_copy`, `bytes_from_hex` and `bytes_appender` are escape names, not C names, and `@helper` appears on only 5 of 11.

### 4. Odd cases, and how to make each simpler

- **`#if` code:** no-block methods are emitted at end of file, so they need a block when under `#if`. An unclosed `#if` puts every no-block method under it. → One mode (blocks), or allow `@c_if("defined(X)")`. Blocks are simpler.
- **Clones:** there are the ordering rule, the bare-string docstring, the class-dict order change, and clinic accepts invalid order. → Write clones as full `def`s (typeshed-style; WS7 counts 185 clones). Clinic can detect that two defs have the same signature and share parser code. At minimum, error when a clone precedes its target.
- **Getters/setters:** broken in `@static_type` classes (METHODDEF emitted, no tp_getset), and same-named defs collapse. → Use Python's `@property` / `@x.setter` and route them to tp_getset. Until then, reject them.
- **Shared stringlib code:** there are two `.h` spec kinds: transmogrify.py is processed via transmogrify.h, while ctype.py is import-only. → One rule: `Objects/stringlib/pyspec/*.py` are shared specs; each declares a clinic function or a `@c_name(METH_*)`. Make unrecognized class-body statements an error (frontend.py:347-372).
- **bytes/bytearray docstring duplication:** the ctype docstrings are now in ctype.py and in Objects/bytes_methods.c (about 1.4 KB), and split/find/etc. are still duplicated in bytearrayobject.c. → Convert bytearray in the same PR series, and delete the bytes_methods.c copies when bytearray uses ctype.py.
- **`__new__`/`__init__`:** `T_new` vs `T___init__` is asymmetric (frontend.py:38-42). → Pick one rule: clinic's default everywhere with `@c_name` where needed, or `T_new`/`T_init` everywhere.
- **Text signatures:** drop the bracket overrides (WS9 R1). `bytes()` has none, and the class docstring holds pseudo-signatures (L50-54). Fine as is.
- **Spec files for `.h`:** `spec_path` keys on the stem (frontend.py:223-227), so `foo.c` and `foo.h` in the same directory would collide. Document this, or key on the full name.
- **Stub vs body:** `...` and a docstring-only body are stubs; `pass` is a body. → Accept `pass` as a stub too, or give the error "use `...` for a C implementation".
- **The `iter()` wrapper (runtime.py:83-103):** correct (C doesn't call `it.__iter__()`), but it is a silent semantic override of a builtin, like `isinstance` (:78). → Keep the explicit imports (spec L28-29) and document "spec builtins" in one place. Better, spell them as C names (`PyObject_GetIter(x)`), which P1 makes plain calls.
- **The `ITERATION` table (partial_eval.py:78-89):** facts about list, dict, str and other types' C live in the tool. → Move it next to the other builtin-type tables (see Recommendation 8) now, and into the types' own specs when they exist (e.g. `list_iterator.__next__`).
- **Class-dict order:** the spec order drives both the method table and `.c.h` order. → Accept it, but land it in a separate "reorder only" PR. Or keep the old table order in the spec for the first PR, so the `.c.h` stays byte-identical.
- **Makefile:** `Objects/bytesobject.o` depends only on `.c` and `BYTESTR_DEPS` (Makefile.pre.in:2041-2050, :2070). In no-block mode a spec docstring or decorator edit changes only `clinic/*.h`, so `make` doesn't rebuild. Main has the same gap, but there the `.c` changes too. `stringlib/clinic/transmogrify.h.h` isn't in `BYTESTR_DEPS` either. → Add `$(wildcard $(srcdir)/Objects/clinic/bytesobject*.h)` to the rule (and `transmogrify.h.h` to `BYTESTR_DEPS`), or add a generic `Objects/%.o: $(wildcard …/clinic/%*.h)`.
- **Partial writes:** make clinic generate all outputs in memory (the `.c.h`, `_pyspec`, `_types`) and write them only if every stage succeeds (app.py `parse`: `write_pyspec_output`/`write_type_objects` run after the destinations are filled).

### 5. Recommendations, ranked by burden removed per unit of effort

1. **Turn silent acceptances into errors; make failures atomic (small, very high value).**
   - Error on unrecognized class-body statements, unknown decorators on slots and PyCFunctions, `@classmethod` with `@c_name(METH_*)`, `@getter`/`@setter` in `@static_type` classes, and a clone before its target.
   - Catch `SpecError` from `Spec.__init__` (app.py pyspec property). Fix the shared-typo advice.
   - Map `KeyError` in call_table to a SpecError.
   - In emit, say "comparisons take names; assign the call first" and "escape C.X is not in runtime.C".
   - Use one error format `path:line: message`.
   - Write nothing on failure.
2. **Split the spec by concern; stop copying docs (small to medium, high value).**
   - Keep `Objects/pyspec/bytesobject.py` for the types and bodies only (about 550 lines).
   - Move the C API catalog out, e.g. to `Objects/pyspec/capi/bytes.py`, or better, make it data-only and derive it from headers, rst and refcounts.dat, which capi.py already parses.
   - Drop the rst docstring copies and the equality check at test_pyspec_catalog.py:147-151.
   - Removes 566 lines, #10, and the "two places per doc fix" rule.
3. **Documentation (small).**
   - In the devguide (python/devguide, `development-tools/clinic/`), add a section "Declaring a type in a spec file". It should have a task table: add a parameter, add a C method, add a spec-body method, add or rename a slot, share a stringlib method, add a C API function, regenerate and test. It should also list the decorators (`@c_name` forms, `@static_type`, `@final`, clinic decorators) and the body subset.
   - Put a 1-page `Objects/pyspec/README.rst` in the tree with the same table and links. Keep module docstrings for internals.
   - Point every "unsupported …" error at the section.
4. **Makefile dependencies** (a few lines; see §4).
5. **P1 (medium).** One spec function per helper, `@c_implemented`, and plain-name calls. Removes `runtime.C` (runtime.py:236-301), the Escape machinery exposed to authors, `@helper`, and `test_escape_stubs`. Task (c) would have needed 1 file instead of 4.
6. **P2 plus reading C types from headers (medium to large).** Removes about 10 vocabulary words and the unsafe default ("no RunsPython means no Python"). The facts that task (e) showed going stale become derived or validated. Stubs become plain `def f(o, /): ...` with the C signature from the header.
7. **One mode (small to medium).** I recommend one-line blocks (`bytes.split`), which is still the Argument Clinic mental model. Clinic writes and updates heads, `#if` works, the `.c.h` order stays the C order (no reorder PRs), there is a visible link from C to the spec, and the `.c` changes on signature edits. The cost is about 4 lines per method. If no-block mode stays, drop the block option instead. Either way, one mode.
8. **Merge tables and outputs (small).**
   - Put one builtin-types table in runtime.py (C type object, `Check`/`CheckExact`, `Py_GetConstant`, iteration facts). It replaces `frontend.TYPE_OBJECTS`, `call_table.TYPE_OBJECTS`, `emit.TYPE_CHECK`, `CONSTANT_OBJECTS`, `CANDIDATE_TYPES` and `ITERATION`.
   - Emit `_types` into `_pyspec.c.h`, included once at the end of the `.c` (the appender helpers are already before it). That leaves 2 includes, not 3.
9. **Python fidelity of the spec (small).**
   - Write clones as full defs.
   - Drop the dead `c_name='x'` (L65).
   - Rename the converter pseudo-argument (e.g. `c_param=`) so it doesn't collide with `@c_name`.
   - Drop the bracket `@text_signature`s.
   - Make the spec a module that `python -c "import ast; compile(...)"` and `exec` both accept in order: clinic should `compile()` it and reject NameErrors of names it resolves statically.
10. **Tests that scale (medium).** Replace the bytes-specific test classes with one generic harness per `Objects/pyspec/*.py`: up-to-date, spec-as-Python vs interpreter over a per-spec `CASES` list kept next to the spec, and type-table vs interpreter. A new type then adds data, not a test class. Make the "spec vs built interpreter" failure say "rebuild Python".
11. **Keep PRs small.** Land in this order, one type per PR:
    1. signature-only spec with byte-identical `.c.h` (WS7: tuple 4 functions, float 14);
    2. `@static_type` with a runtime-identical dump;
    3. spec bodies plus a difftest;
    4. call table and optimizer;
    5. catalog.

    Keep Tools/clinic feature PRs separate from type conversions. Don't reorder methods in the same PR that moves them.

### Environment notes
- `build-exp/python` reports `heads/exp/ac_python_overloads_v0-dirty:6ebfa788782`, the parent of 62cc16504fe, not 62cc16504fe. It was only used to run clinic and Python tests from the tree via `PYTHONPATH=<tree>/Lib`; `support.REPO_ROOT` and `test_tools.basepath` resolved to the tree. I did not rebuild the interpreter, so runtime effects of tasks (b), (c) and (d) were checked by compiling bytesobject.c only.
- The throwaway worktree was removed (`git worktree remove`); the main checkout is clean at 62cc16504fe. No report file was written.

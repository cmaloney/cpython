## Workstream B report: fewer concepts, no silent failures, one mode

All 10 items are done and committed on the worktree branch (base 62cc16504fe, 10 commits, no rebase or amend). Worktree: `/home/firebird347/projects/python/cpython/.claude/worktrees/agent-a0847ce760a83a694`. Build: `/home/firebird347/projects/python/build-B` (clang, `--with-pydebug`).

Everything Python can see of `bytes` and `bytes_iterator` is identical to main, `__dict__` order included. `Objects/stringlib/clinic/transmogrify.h.h` is byte-identical to main. `Objects/clinic/bytesobject.c.h` differs from main only inside the `bytes.__new__` section.

**One commit defect:** `ca8ec863acd` contains only the deletion of `bytesobject_types.c.h`, because my `git add` failed on the already-removed path. `8cbc910768e` carries the rest of that change. So `ca8ec863acd` alone does not build. I did not amend, per the rules.

### Commits
| Commit | Item |
|---|---|
| `3924a9f3bd1` | 2: clones become full defs; spec order is main's `bytes_methods[]` order |
| `e67b4406ce2` | 1: one mode, a one-line block per spec method; no-block mode removed |
| `e96b995a261` | 3 + 5: one error format, errors located in the spec, every silent acceptance is an error |
| `08135bcb63f` | 4: clinic writes nothing if any stage fails |
| `ca8ec863acd` + `8cbc910768e` | 6: `_types.c.h` merged into `_pyspec.c.h`, included once at the end |
| `416c8d010a1` | 7: `c_param=`, one C naming rule, dead `c_name='x'` dropped |
| `bf7d034a076` | 8: Makefile dependencies |
| `b9795c9c052` | 9: generic `PyspecFilesTest` plus `Objects/pyspec/bytesobject_cases.py` |
| `653e6880f1d` | 10: `Objects/pyspec/README.rst`; "unsupported …" errors point at it |

### What changed, per item
- **1. One mode**
  - A spec method with no block in the .c is an error. It gives the spec line and prints the block to add.
  - Blocks are back where main has them in `Objects/bytesobject.c` and `Objects/stringlib/transmogrify.h`, and clinic writes the impl heads again.
  - Every block's `output=` checksum equals main's, except the three whose impl the spec generates (`__bytes__`, `fromhex`, `__new__`, whose blocks now have empty output) and the new `class bytes_iterator` directive.
- **2. Clones as full defs**
  - `count`, `index`, `rfind`, `rindex` and `rsplit` are full defs, and clinic generates exactly what a clinic clone gives.
  - `x = y` in a class body is an error ("Python has no clones: write count as a full def").
  - Where the table order comes from: WS12's method table follows the spec's class-body order (`Spec.entries()`). I kept that rule, since it is Python's own (class body order = `__dict__` order), and reordered the spec to main's `bytes_methods[]` order. Once clones were gone nothing forced `find` before `count`. The `.c.h` order follows the C blocks, as on main.
- **3. Silent acceptances that are now errors**
  - Unrecognised class-body statements (the review's `import transmogrify as tm` case, which dropped 5 methods).
  - A top-level `import x`.
  - A shared-method typo, which now names the missing method and its file; the old wrong advice is gone.
  - Any decorator other than `@c_name` on a slot, or other than `@c_name`/`@classmethod` on a PyCFunction.
  - `@getter`/`@setter` in a `@static_type` class.
  - The same name defined twice.
  - `pass` as a body, which says "use ...".
  - `SpecError` and `SyntaxError` no longer escape as tracebacks.
  - `@classmethod` with `@c_name(METH_O=…)` is now supported and generates `METH_O | METH_CLASS`.
- **4. Atomic output:** every output is generated in memory and written only after all stages succeed.
- **5. One error format:** every clinic error and warning prints as `path:line: error: message`. Errors in input taken from the spec point at the exact spec line (the parameter, decorator or docstring); checks of a whole function point at its `def`.
- **6. Two includes, not three:** the type objects go at the end of `clinic/<stem>_pyspec.c.h` (file name unchanged), which bytesobject.c includes once as its last line.
- **7. Python fidelity**
  - The converter pseudo-argument is renamed `c_param='x'`.
  - One naming rule: clinic's default C basename or `@c_name`. The `T_new` special case is gone, and `bytes.__new__` now says `@c_name("bytes_new")`.
  - The dead `c_name='x'` on `__new__`'s `source` is dropped.
- **8. Makefile**
  - A generic `$(foreach … $(wildcard Objects/clinic/*.c.h) … $(eval …))` makes `Objects/foo.o` depend on `clinic/foo.c.h` and `clinic/foo_pyspec.c.h`.
  - `transmogrify.h.h` is added to `BYTESTR_DEPS`.
  - Verified: touching only `bytesobject_pyspec.c.h`, `transmogrify.h.h` or `floatobject.c.h` now recompiles the object. A spec-docstring-only edit followed by clinic recompiles too.
  - Clinic already touched the .c after regenerating, so the real hazard this fixes is a checkout or pull that changes only generated headers.
- **9. Generic test harness:** `PyspecFilesTest` runs over every `Objects/pyspec/*.py` and `Objects/stringlib/pyspec/*.py`:
  - generated files are up to date;
  - each spec function run as Python vs the interpreter over `CASES` in `<stem>_cases.py`: same exception and message, or an equal result of the same type, including identity with an argument;
  - each `@static_type` class vs the type in `TYPES`: order, slots, docs and flags.
  - It replaces `BytesSpecTest` and `BytesSpecTypeTest`, whose subclass, identity, `__bytes__` and `fromhex` checks are now data.
  - `PyBytes_FromObject` is now also compared with `_testlimitedcapi.bytes_fromobject`.
  - A spec/interpreter mismatch says: run "make clinic", rebuild Python (make) and rerun.
  - `test_iterator_next_facts` moved to `BytesSpecFactsTest`.
- **10. Docs**
  - `Objects/pyspec/README.rst` has the "to do X, edit Y" task table, the decorator list and what a spec may contain; it validates with docutils.
  - The devguide draft could not go to `pyspec-notes/`: this environment refuses writes outside my worktree. It is at `/tmp/claude-1000/-home-firebird347-projects-python/2290c1d8-9873-48d1-a600-904f809b5565/scratchpad/wsB/devguide_draft.rst` (it also validates) and needs copying to `/home/firebird347/projects/python/pyspec-notes/devguide_draft.rst`.

### Concept count (review_dx §1)
51 items (about 40 distinct) before, 46 (about 35 distinct) after.

| Removed | What it was |
|---|---|
| #7 | `_types.c.h` |
| #20 | clones and the "must follow its target" rule |
| #23 | `T_new` vs `T___init__` |
| #33 | spec order changing `__dict__` order |
| #34 | two modes |

- **Simplified but kept:** #4 (clinic writes the heads; 2 includes instead of 3), #21 (no longer collides with `@c_name`), #22 (`pass` is an error), #35 (the Makefile trap is fixed), #51 (one test class plus data).
- **Added:** none that is new to learn. `<stem>_cases.py` replaces "edit the bytes test class".
- **Ratings:** 16 E / 20 I / 15 R becomes 16 E / 18 I / 12 R.
- **Left:** the remaining R items are P1/P2 and the catalog (A's and D's areas).

### Generated files vs main (ee1bbf037ff)
- `transmogrify.h.h`: byte-identical.
- `bytesobject.c.h`: 103 diff lines, all in the `bytes.__new__` section:
  - 4 lines rename the parser local `x` to `source`, from dropping the dead `c_name='x'` as asked;
  - 5 lines turn `bytes_new` into `bytes_new_helper(args, nargs, nkw, kwargs, kwnames)`, the keyword parser shared by `tp_new` and the vectorcall;
  - about 85 lines are the new `bytes_new` wrapper, the `bytes_new_nargsN` prototypes and `bytes_vectorcall`, which is new functionality;
  - 1 line is the checksum.
- **Type dump** (WS12 `dump_types.py`, build-B vs build-str1-dbg = main at ee1bbf037ff): identical except
  - `tp_vectorcall = bytes_vectorcall` (new);
  - the iterator's `tp_methods` symbol is `bytes_iterator_methods` instead of `striter_methods`. It is a static C symbol, not visible from Python, and matching it would need a new naming knob.

### Tool lines
- Tools/clinic: +433 / −481, **net −48**.
- test_clinic.py: +401 / −608. Most of what left went into the new data file `Objects/pyspec/bytesobject_cases.py` (+364).

### Contributor tasks redone
Times are my tool time; the "before" column is the review's.

| Task | Before | After |
|---|---|---|
| (a) `keepempty` on `split` | ~10 min; C "conflicting types" error; `rsplit` changed too | spec edit, then clinic (0.22 s) rewrites the impl head. Only `regen-global-objects` remains (same as on main); `rsplit` is untouched. |
| (b) new C method `isbinary` | ~5 min; warning, then link error | Spec alone gives `bytesobject.py:259: error: bytes.isbinary has no clinic block…` with the block to paste. Clinic then writes the head. Before a rebuild, the test says to rebuild Python. |
| (c) spec body `isempty` | ~45 min; 4 files; partial write | `…:261: error: unsupported return len(self) == 0; see Objects/pyspec/README.rst`, and no partial write. The next steps (`unsupported value C.PyBytes_Size(self)`, `unknown escape C.PyBytes_Size`) still need runtime.py and emit.py, which is A's area (P1). |
| (d) slots | `__class_getitem__` silently missing `METH_CLASS` | generates `METH_O | METH_CLASS`; `@cname` on a slot is an error |
| (e) stale facts | not caught | not addressed (P2; A's and D's areas) |
| (f) deliberate mistakes | 6 of 19 ✗ | all 19 give one-format, spec-located errors (output: `scratchpad/wsB/mistakes.out`) |

### Test results
All commands ran under `systemd-run --user --scope -q -p MemoryMax=… -p MemorySwapMax=0`, serially, with make at `-j8`. The build has 0 compiler warnings.

| Command | Result |
|---|---|
| `build-B/python -m test test_clinic test_bytes test_capi test_inspect test_pydoc test_descr test_pickle` | SUCCESS, 4,163 tests, 391 skipped |
| `-R 3:3 test_clinic test_bytes` | no leaks |
| `clinic.py Objects/bytesobject.c Objects/stringlib/transmogrify.h` | tree clean |
| `clinic.py --make --srcdir .` from the worktree | tree clean |

### Edits outside my area
- `Tools/clinic/libclinic/pyspec/emit.py` (A's), 2 hunks: `SpecError` now keeps `lineno` and `message`, and `describe_method` stopped calling the removed `Spec.where()`.
- `Tools/clinic/libclinic/errors.py`: `ClinicError.report()` changes clinic's error format for all files (two tests updated).
- `Tools/clinic/libclinic/pyspec/__init__.py`: docstring only.
- Spec: `bytes.__new__` got `@c_name("bytes_new")` and lost `c_name='x'`. The C API catalog section (D's) is untouched.

### Open problems
- Merging the include moves A's generated bodies to the end of bytesobject.c. That is semantically neutral (the appender helpers are static inline and defined earlier), but A should confirm there is no performance change.
- Not done, because they are in A's area: mapping the call_table `KeyError` to a `SpecError`, and making "unknown escape" say where to add the escape.
- `@c_name(sq_length=…)` alone still silently leaves `mp_length` unset; it is legal and was not on the list.
- The Makefile rule needs GNU make (`$(eval)`/`$(wildcard)`); `$(if)` and `$(patsubst)` are already used there.
- mypy is not installed, so the Tools/clinic types were not checked; ruff passed in the pre-commit hooks.
- The one-line blocks of the three spec-body methods have empty output, which a reader may find odd.

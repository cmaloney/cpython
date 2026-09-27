Conditional compilation now works the way it does in plain Argument Clinic. The committed mmap sample produces a byte-identical `Modules/clinic/mmapmodule.c.h`.

**Worktree:** `/home/firebird347/projects/python/cpython/.claude/worktrees/agent-a3d317febfa53016d`, branch `worktree-agent-a3d317febfa53016d`, base b79959af9ce. Three commits, no rebase or amend:
- `fe4b1f3b7a3` pyspec: conditional compilation as with plain clinic (tools + tests)
- `88219f1a058` pyspec README: conditional compilation
- `13fd59e6866` pyspec: mmap from a spec, a sample of conditional compilation

## Case by case

**Already worked, tests only (1, 2 and the mixed file):**
- **1. Spec method in C under `#if`:** a one-line block inside the `#if` picks up the condition from `cpp.Monitor` as any block does. `test_stub_in_ifdef` shows the output is byte-identical to the same full block, including the `#if defined(CONDITION)` / `#endif` wrapper and the `#ifndef BYTES_METH_METHODDEF` fallback.
- **2. Generated method table:** it already lists `X_METHODDEF` unconditionally. The fallback is emitted for spec methods too, and it lands in the `.c.h`, which comes before `_pyspec.c.h`.
- **Mixed file:** spec methods and ordinary full blocks already coexist (`test_mixed_file`). One limit: a full-block variant that has no parameters and no docstring would be read as a one-line block. The real case in the tree (`_curses.window.noutrefresh`) has docstrings, so it is not affected.

**Needed code (53 lines added, 14 removed, in my files only):**
- **3. Signature depends on `#if`** (`dsl_parser.py` +12/−3, `frontend.py` +9):
  - Declaring a name in both the spec and a full block is still an error. The message now states the rule: a function whose signature depends on `#if` keeps its clinic input in C, and is only `def meth(self): ...` in the spec.
  - For a generated method table I chose "the spec lists a placeholder": `def meth(self): ...` with no docstring gives the method its place in the table, and the full C blocks stay as they are. The table entry is its `X_METHODDEF` (`test_method_table_with_ifdef`).
  - Why this option: it needs no change to `typeobj.py`, which I was told not to touch, and it keeps table order equal to class-body order. The other option, "the table appends blocks not in the spec", would need `typeobj.py` changes and would move those methods to the end of `__dict__`.
  - A method with no generated table can simply be left out of the spec.
- **4. Spec body under `#if`** (`emit.py` +28/−10, `app.py` +4/−1): the generated impl, its prototype and any arity functions in `_pyspec.c.h` are wrapped in the block's condition, in the same `#if X` / `#endif /* X */` form clinic uses. The condition is `func.condition`, passed through a `pyspec_conditions` dict. Conditional functions are left out of the tier-2 call table, which would otherwise reference a symbol that may not be compiled. Test: `test_body_in_ifdef`.
- **5. Conditional slots:** detecting this cheaply isn't possible, because a slot has no block position. So the rule is documented only: such a slot stays in the hand-written C sub-table.
- **6. Spec-vs-interpreter tests** (`test_clinic.py`): a new helper `compiled_out(c_file, types)` runs clinic's parser and returns methods whose block has a `func.condition` and whose type lacks the attribute (`hasattr`). `test_cases` and `check_type` skip those methods. Test: `test_compiled_out`.

**README:** a 20-line "Conditional compilation" section in `Objects/pyspec/README.rst` with the rules above.

No case is more complex than plain clinic. Cases 1, 2 and 4 are exactly clinic's form, with the condition read from the block position; case 4 only extends clinic's existing wrapping to the second generated file. Case 3 is today's full clinic block plus, only when a generated table exists, a one-line placeholder.

## mmap sample
- **Why `Modules/mmapmodule.c`:** it is small (one class, 21 methods) and needs no unsupported features. Four methods are conditional:
  - `resize` (`MS_WINDOWS || HAVE_MREMAP`)
  - `__sizeof__` (`MS_WINDOWS`)
  - `_protect` (`MS_WINDOWS && Py_DEBUG`)
  - `madvise` (`HAVE_MADVISE`)

  Its hand-written method table lists their `METHODDEF`s unconditionally, relying on the fallback.
- **No platform-dependent signature in the sample:** among class methods in the tree, only `_curses.window.noutrefresh` has one, and that sits in a very large file that uses optional groups, which the spec does not support. That rule is shown in test_clinic instead.
- **Before/after:** clinic input in `mmapmodule.c` goes from 79 to 21 non-blank lines. The new spec `Modules/pyspec/mmapmodule.py` is 111 lines. The `rfind` clone became a full def, and the `@critical_section` decorators moved into the spec.
- **Parity:** after running clinic, `git diff --exit-code Modules/clinic/mmapmodule.c.h` is empty, and HEAD's copy is itself identical to main (`ee1bbf037ff`). All 21 `output=` checksums in `mmapmodule.c` are unchanged; only the `input=` checksums change.
- I added `Modules/pyspec` to `PYSPEC_DIRS`, so `PyspecFilesTest.test_up_to_date` now covers the mmap spec. There is no cases file and no static type, so there is nothing further to compare or skip on Linux.

## Tests
All runs used `systemd-run --user --scope -q -p MemoryMax=... -p MemorySwapMax=0`, one at a time, with `free -g` checked first (48–50 GB available).
- `PYTHONPATH=<worktree>/Lib build-exp/python -m test test_clinic test_pyspec_catalog test_pyspec_facts`: SUCCESS, 513 tests, 1 skipped.
- New debug build of the worktree at `/home/firebird347/projects/python/build-cond` (clang, `--with-pydebug`, `make -j8` under a 12G cap):
  - `./python -m test test_mmap test_clinic test_pyspec_catalog test_pyspec_facts`: SUCCESS, 568 tests.
  - test_mmap alone: 55 tests, 7 skipped as "requires Windows".
  - The build log has no warnings for mmapmodule.
- Running `Tools/clinic/clinic.py` on `Objects/bytesobject.c`, `Objects/stringlib/transmogrify.h`, `Objects/bytearrayobject.c` and `Modules/mmapmodule.c` leaves the tree clean.

## Coordination risks
- My new `test_method_table_with_ifdef` and the `check_type` skip in `test_clinic.py` use `@static_type`, which another agent is removing. Expect small conflicts there.
- A shared specialization used only by a conditional spec body could become an unused static function when the condition is false. No real case exists yet, so I left it alone.
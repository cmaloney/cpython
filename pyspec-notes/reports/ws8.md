## WS8 report: shrinking the clinic input in Objects/bytesobject.c

Both goals are done. With commit 1 alone, the generated `.c.h` files are byte-identical to before. With commit 2, `bytesobject.c.h` changes in one way only: the `bytes.__new__` section (180 lines) moves from the end to the start. The line multisets are identical apart from the trailing checksum line. `bytesobject_pyspec.c.h` stays byte-identical. `help(bytes)`, `inspect.signature` and `__text_signature__` for every bytes attribute match `/home/firebird347/projects/python/build/python` after each commit, and all tests pass.

Worktree `/home/firebird347/projects/python/cpython/.claude/worktrees/agent-a4e3983d68720133a`, branch `worktree-agent-a4e3983d68720133a`, on top of f62ffd1fe3e. Nothing was rebased or amended.
- `9a249846d6e` commit 1: clinic decorators are written on the spec method.
- `9bc669a7c7a` commit 2 (droppable): spec methods need no clinic block in the C file.
- `82db7dc87fa` follow-up: keep clinic's default C basename for `__init__`. It touches lines commit 2 also edited (frontend docstring, the split `__init__` test), so dropping commit 2 means resolving a small conflict in this commit.

Files changed: `Tools/clinic/libclinic/pyspec/frontend.py`, `Tools/clinic/libclinic/pyspec/runtime.py`, `Tools/clinic/libclinic/dsl_parser.py`, `Tools/clinic/libclinic/app.py`, `Objects/bytesobject.c`, `Objects/pyspec/bytesobject.py`, `Objects/clinic/bytesobject.c.h` (commit 2 only), `Lib/test/test_clinic.py`.

## Clinic lines in bytesobject.c

The starting state differs slightly from the brief: 26 function blocks (not 27) plus the class block, and 14 `@permit_long_summary` (not 15).

| | blocks | input lines (with markers) | non-blank DSL lines | generated heads + end markers |
|---|---|---|---|---|
| before | 27 | 98 | 44 | 87 |
| after commit 1 | 27 | 81 | 27 (class + 26 function lines) | 87 |
| after commit 2 | 1 | 3 | 1 (`class bytes ...`) | 1 |

## Rules added, and why

1. **Decorator rule (commit 1).** Any clinic decorator can be written on a spec method as a Python decorator with the same name and arguments: `@permit_long_summary`, `@text_signature("($self, sub[, start[, end]], /)")`, `@critical_section("a", "b")`, `@vectorcall`, and so on.
   - `runtime.py` defines each one as an identity decorator (one shared `_clinic_decorator`), so the spec still runs as plain Python.
   - The frontend turns each back into its DSL line and does not keep its own list of meanings: clinic checks names and arguments as it does in a .c file.
   - The frontend docstring explains why this is the whole rule. A clinic decorator is already a per-function fact written above the function line, in the same shape as a Python decorator. And none of them changes Python behaviour, so identity is the exact Python meaning; only `@classmethod` and `@staticmethod` change it, and those are Python's own.
   - Arguments must be string or integer constants, because a DSL line holds only words.
   - A decorated clone is written as the call the decorator stands for: `index = permit_long_summary(find)`. Clones still take their kind (class/static method) from their target; clinic copies the rest.
   - Decorators in the .c block of a spec method are now an error (`'bytes.meth': @critical_section of a spec method is written in <spec>`), so each fact lives in one place.
   - An unknown name fails with `unknown clinic decorator @x`, followed by the spec location.
   - The "Remove the @permit_long_summary decorator" warning (and the one for `@permit_long_docstring_body`) now points at the decorator's line in the spec.
2. **`__new__` naming (commit 1, narrowed in the follow-up).** A spec-backed `T.__new__` with no `as` clause gets the C basename `T_new`. Clinic's own default would be `T`. This removed all three `as` clauses in bytesobject.c (`bytes_removeprefix` and `bytes_removesuffix` were already the default).
   - Counts of `X.__new__` across Objects/, Modules/, Python/ and PC/: 49 have an `as` clause (19 are exactly the dotted name + `_new`, 7 are the class name + `_new`, 23 end in some other `..._new`) and 34 have none. In Objects/ alone, 16 of 23 are exactly `<class>_new`, 5 are other `_new` names, and 2 have no `as` (typevartuple, memoryview).
   - I dropped the `__init__` → `T_init` half: 3 of the 4 `__init__` in Objects/ use clinic's default `T___init__`, so it would not remove any `as` clause.
   - The rule only applies to functions filled from a spec, so no other file changes.
3. **Spec methods need no block (commit 2).**
   - Every method of a spec class that the .c file declares with a `class` directive is a clinic function. A block for it is optional.
   - Methods without a block are generated after the file's blocks, in spec order, into the file destination (`clinic/<file>.c.h`). Their impl definition head is dropped: the C author writes it by hand, exactly as before minus the clinic comments.
   - If such a method's output would land in the `block` destination (for example with `output preset block`), clinic fails with a clear message.
   - Errors in a method without a block are reported at the spec file and line.
4. **Where the class declaration lives.** `class bytes "PyBytesObject *" "&PyBytes_Type"` stays as the one directive block in the .c. That adds no new concept (no `@clinic_class` decorator). `--make` still finds the file through its existing "any clinic marker" check. It is C naming information, like `as`. And it states which spec classes this file generates.

## Verification

All heavy commands ran under `systemd-run --user --scope -q -p MemoryMax=... -p MemorySwapMax=0`, one at a time, after a `free -g` check. Build: `/home/firebird347/projects/python/build-ws8` (CC=clang, --with-pydebug), 0 compiler warnings.
- **Regeneration:** `build-ws8/python Tools/clinic/clinic.py --make --srcdir .`
  - Commit 1: both `.c.h` files compare equal (`cmp`) to the baseline, and every `output=` checksum in the .c is unchanged. Only the `input=` checksums of the edited blocks changed, which is unavoidable because the block text changed.
  - Commit 2: the `__new__` move described above.
  - Re-running changes nothing, and `make clinic` (`--force --make`) produces the same bytes.
  - A hand-edit to the `.c.h` is still caught (`Checksum mismatch! ...`).
- **Tests:** `./python -m test test_clinic test_bytes test_capi.test_bytes test_inspect` passes after each commit (1,220 tests before the new ones, 1,224 after, 8 skipped).
- **New test_clinic tests:**
  - Decorator rule: `test_clinic_decorators`, `test_clinic_decorator_arguments`, `test_decorated_clone`, `test_unneeded_permit_long_summary` (checks the warning points at the spec line), `test_unknown_clinic_decorator`, `test_clinic_decorator_non_constant_argument`.
  - `test_runtime_clinic_decorators`: the runtime decorator set equals DSLParser's `at_*` set minus class/static method, and each returns the function unchanged.
  - Naming: `test_new_c_basename`; `test_clinic_decorator_in_block` replaces the old test that expected clinic decorators in the spec to fail.
  - No-block mode, in the new `PyspecNoBlockTest`:
    - `test_no_block`: the .c is left alone, and the output equals the one-line-block version.
    - `test_mixed`: blocks come first, then the rest in spec order.
    - `test_class_not_declared` and `test_error_names_spec`: undeclared spec classes are skipped, and errors name the spec file and line.
  - `test_body_without_block` now expects the file-destination error.
- **Signatures and help:** a scratch script compared `pydoc.render_doc(bytes)` text plus `inspect.signature` and `__text_signature__` for every bytes attribute. For example, `find` still has `'($self, sub[, start[, end]], /)'`.

## Signature mismatch diagnostic (reverted)

I changed `Py_ssize_t maxsplit` to `int maxsplit` in the hand-written head:
```
Objects/bytesobject.c:1847:1: error: conflicting types for 'bytes_split_impl'
 1847 | bytes_split_impl(PyBytesObject *self, PyObject *sep, int maxsplit)
      | ^
Objects/clinic/bytesobject.c.h:228:1: note: previous declaration is here
  228 | bytes_split_impl(PyBytesObject *self, PyObject *sep, Py_ssize_t maxsplit);
```
A missing definition (I renamed `bytes_hex_impl`) is only a compiler warning: `.c.h:1473: warning: function 'bytes_hex_impl' has internal linkage but is not defined [-Wundefined-internal]`, with a note pointing at the call. The hard error comes at link time: `undefined reference to 'bytes_hex_impl'`. Both experiments were reverted and the tree rebuilt clean.

## Tradeoffs of commit 2

- **What a contributor loses:**
  - The visual link from a C impl to its Python name and signature: there is no `bytes.split` block above `bytes_split_impl`. I added one comment near the include pointing to the spec.
  - Clinic no longer writes or updates the heads. When a parameter changes in the spec, the C author edits the head by hand, guided by the error above.
  - A missing definition shows up late (warning, then link error).
  - Generation order now follows the spec, not the C file.
- **What they gain:**
  - Clinic never rewrites the .c file.
  - No checksum churn and no clinic-caused merge conflicts in the .c: each change lives in the spec and the generated `.c.h`.
  - The .c shrinks to plain C plus one directive block.
- **Mixed files:** blocks are still allowed next to block-less spec methods. A spec method with a one-line block behaves as in commit 1 (clinic writes its head). The rest are generated at the end of the file.

## Open problems

- **Conditional compilation:** methods without a block are generated at the end of the file, so they lose any `#if` around them; such methods need a block. Likewise, `output` directives in force at the end of the file apply to them.
- **Getter/setter pairs:** the rule translates `@getter` and `@setter`, but two spec `def`s with the same name collapse in `Spec.functions`, and in no-block mode the name would be listed twice. Accessors in specs need a design (e.g. Python's `@x.setter`).
- **`runtime.__all__`:** I did not add the decorator names to it, to avoid a conflict with WS5. Explicit imports work. The spec imports them on a separate line, away from the existing import line.
- **Brief is out of date:** PYSPEC_DESIGN.md D2 still says the .c keeps clinic-only decorators and `as` clauses.
- **For WS5's merge:** my edits to `runtime.py` are one inserted block after `cstr = str`, and I did not touch `emit.py` or the end of the spec file.
- **Pre-existing, not fixed:** a hand-edited `.c.h` is reported as "Error in file 'Objects/bytesobject.c' on line 1543", i.e. the `.c` file name with a `.c.h` line number. `--make` also prints existing "Remove the @permit_long_summary" warnings for `Modules/_elementtree.c` and `Modules/pyexpat.c`.
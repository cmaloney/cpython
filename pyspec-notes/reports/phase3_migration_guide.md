I added the guide, the measurement helper and its test, and applied the procedure to `bytes.removeprefix`/`removesuffix`. The answer is **keep in C**. The guide validates with docutils, `test_clinic` and the helper's test pass, and the helper runs against both interpreters you named.

The auto-mode permission check blocked my edits to `Objects/bytesobject.c` and `Objects/pyspec/bytesobject.py` in the worktree (reason: shared files). So I ran the experiment in `git archive` copies of HEAD under `/home/firebird347/projects/python/pyspec-mig/`, outside any repo, as the earlier perf review did. It was never in the worktree, so there was nothing to revert.

**Commits** on `worktree-agent-ad70d10ccdf7e279f`, on top of b79959af9ce (no rebase or amend):
- **acc20e7ac13:** `Tools/clinic/pyspec_bench.py` (155 lines, stdlib only) and `Lib/test/test_tools/test_pyspec_bench.py` (3 tests).
  - It runs statements with a setup as fast locals in a function loop, on several interpreters, JIT on and off.
  - Instructions per iteration come from `perf stat` at two loop counts, differenced; `--cycles` and `--cpu` are optional.
  - Without a working `perf` it differences `time.perf_counter` and prints that it is doing so.
  - It warns when the interpreters were configured differently.
  - It lives next to clinic because all the pyspec tooling is there, and removing the experiment removes it too.
- **f6813a0ff7e:** `Objects/pyspec/MIGRATING.rst` (509 lines) and a two-line link at the end of `Objects/pyspec/README.rst`.
  - The five levels, each with what it needs and gives, its parity check, typical size and a checklist.
  - What to migrate first (from WS7), and the features that need care.
  - The decision procedure with commands, a decision table with this experiment's negative outcomes, the worked example, and troubleshooting.

**Worked example.** Builds were release JIT, non-PGO, with identical flags (`CC=clang --enable-experimental-jit --with-tail-call-interp`):
- `before` and `before2`: the A/A pair.
- `c_object`: a control that keeps the hand-written C but switches the parameter to the `object` converter.
- `spec`: the spec body.

The first attempt failed: clinic refused `prefix: Py_buffer` ("needs an annotation from ['object', 'str']"). So the spec body takes `object`, and the buffer is acquired in a `@c_implemented` helper; the control build exists to separate that converter change from the spec.

| shape (instructions per iteration, incl. loop) | before | before2 | c_object | spec |
|---|---|---|---|---|
| `b.removeprefix(p)`, JIT on | 635 | 630 | 624 | 621 |
| `b.removeprefix(q)` (no match), JIT on | 433 | 433 | 426 | 416 |
| `b.removeprefix(q)`, JIT off | 527 | 527 | 520 | 510 |
| `sub.removeprefix(q)`, JIT on | 1027 | 1027 | 1020 | 1012 |

- **Performance:** at most 17 instructions per call (−0.5 to −4 %). About half comes from the converter change, which hand-written C gets too. The rest is 0–10 instructions, within about twice the A/A spread on shapes that allocate (6 instructions). No pyperformance benchmark calls these methods, so the end-to-end bound is about 0 and I did not run pyperformance.
- **Code size:** `bytesobject.o` text −10 bytes, data +64 bytes (two call-table entries).
- **Generated C:** the same shape as the hand-written C, with the helpers inlined.
- **Facts:** two new "exactly bytes, may run Python" entries. Both methods are `METH_O`, and the optimizer only reads method facts in `_CALL_METHOD_DESCRIPTOR_NOARGS`, so nothing consumes them.
- **Lines:** hand-written C −36/+37, spec +35, generated +54/−20. No duplication removed.
- **Checks:** `test_pyspec_catalog` flagged `memcmp` as possibly running Python (it is missing from the audited `NO_PYTHON` set). The difftest flagged the reference's `TypeError` message. Both are gaps in the model, not in the C. `HelperTest` was not run, because no debug build contains the new helpers.
- **Side finding:** the converter change alone gives about half the gain with no spec; it is an ordinary C change to judge on its own.

**Verification:**
- `docutils --halt=info` on `MIGRATING.rst` and README: clean (run with the peps_venv docutils).
- `PYTHONPATH=<worktree>/Lib build-exp/python -m test test_clinic test_tools.test_pyspec_bench`: 485 tests, success.
- The helper runs against `build-exp/python` and `build_perf_base_jit/python`, prints the configuration warning for that pair, and takes the timing fallback when `perf` is not on the PATH.

**What depends on the pending `@static_type` removal:** I read the other agent's commits (c09ec37fdd1, 2b657c75aaf) and wrote the guide for that model.
- **Model paragraph and level 2:** they assume clinic generates `<prefix>_doc`, `<prefix>_methods[]` and the `_as_*` tables, with the prefix being the class name or `@c_name("x")`. They also assume the C file includes `clinic/foo_pyspec.c.h` and then defines the `PyTypeObject`, and that `PyspecFilesTest` checks slot wrappers against dunders.
- **Levels 1 and 2 are one PR for now:** the guide says they must land together. Clinic generates the tables for every spec class the C file declares, so a signatures-only PR would define `<prefix>_methods[]` twice. Making level 1 a PR of its own would need a clinic option to leave the tables to the C.
- **Slot facts:** level 4 cites `_PySpec_FindSlot()` and README's "Give the optimizer the facts of a slot". Those come from another pending branch (878570ea094..8a796a26b8d), not from HEAD.
- **README link:** it is appended at the very end of README.rst, which the other agent is also editing, so a small merge conflict is possible.

**Scratch, outside the repo:** `/home/firebird347/projects/python/pyspec-mig/` holds the four measured builds plus a control, their sources, the raw runs (`run1.txt`–`run3.txt`) and the experiment diffs (`exp_spec_body.diff`, `exp_c_object.diff`). It can be deleted.
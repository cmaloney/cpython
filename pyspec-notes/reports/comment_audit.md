## Comment and docstring audit of the pyspec files in my scope

I fixed 38 stale or wrong comments and docstrings in 19 files. No code changed and no generated file changed. They are in one commit, **9da44551ea7**, on branch `worktree-agent-a564b42e39e3b36ca`, on top of ad9a63990ee (no rebase or amend). Worktree: /home/firebird347/projects/python/cpython/.claude/worktrees/agent-a564b42e39e3b36ca

**Verification:**
- Clinic on `Objects/bytesobject.c` and `Objects/stringlib/transmogrify.h` (build-exp python) left every generated file unchanged.
- `bytecodes.c` and `optimizer_bytecodes.c` were not edited, so regen-cases was not needed.
- `PYTHONPATH=<worktree>/Lib build-exp/python -m test test_clinic test_pyspec_catalog test_pyspec_facts`, run under the 6G systemd-run cap, passes: 499 run, 1 skipped (typeshed).

I left agent A's regions untouched. That covers the 4 files it owns plus the bodies and the Escapes section of `bytesobject.py`.

### Fixes (file:line of the new text: what was wrong → what it says now)

**Tools/clinic/libclinic**
- `pyspec/__init__.py:24`: said `foo_pyspec.c.h` holds "the implemented functions, then the type objects", leaving out the call table → "the implemented functions and their call table, then the type objects".
- `pyspec/frontend.py:16`: a line over 100 characters → rewrapped.
- `pyspec/disconnects.py`:
  - `:16`: the docs dimension compared "vs the runtime signatures" → adds "(the spec's for `__new__`)".
  - `:22`: typeshed fell back to "the runtime for types without a spec", but the fallback is per method → "the runtime's for methods without a spec".
  - `:24`: pointed at "(R2 of the pyspec notes)", i.e. the notes → removed.
  - `:238`: the `load_facts()` docstring said it returns "{name: runs Python}, or None", but it returns `(path, facts)` and facts can hold `'both'` → describes the tuple, `'both'`, and None when the file is missing.
- `pyspec/slots.py:9`: said "test_clinic checks that the two agree", but that check moved to the ratchet → "test_pyspec_catalog tracks where the two disagree".
- `pyspec/typeobj.py:20`: the member table left out `tp_base`, which is derived and rejected in `@static_type` → adds "tp_base: the base class, if any".
- `app.py:115`: "C type of the self … of the other spec methods" was vague → "of the implemented spec methods other than `__new__`".
- `dsl_parser.py:603`: `spec_input()` said it returns "the Python decorators" → "the clinic decorators of the spec method".
- `parse_args.py:1589,1592`: the `_vectorcall_spec_positional` docstring was broken mid-sentence, and "call count check" → rewrapped, "argument count check".

**Objects**
- `pyspec/bytesobject.py`:
  - `:7`: the module docstring implied only `bytes_new_impl()` is generated → says `__new__`, `__bytes__` and `fromhex` are implemented in the spec (their impls, plus `bytes_new_nargsN()` for the vectorcall of `__new__`).
  - `:16`: a line over 79 characters → rewrapped.
  - `:512`: "The C name is bytes_<slot>" is wrong, since the prefix is dropped → "bytes_ plus the slot without its prefix (bytes_repr for tp_repr)".
- `pyspec/README.rst`:
  - `:49`: had the same wrong `<class>_<slot>` rule → adds "without the slot's prefix (`bytes_repr`)".
  - `:65`: the Test row named only `test_clinic` → `test_clinic test_pyspec_facts test_pyspec_catalog`.
- `pyspec/bytesobject_cases.py:279`: "which Argument Clinic iterates by index" → "which the generated C iterates by index".
- `pyspec/capi/bytesobject.py:5`: claimed "documented names and prose" are read from `Doc/c-api/bytes.rst`, but only `c:function` signatures are read → "the documented signatures".
- `stringlib/pyspec/ctype.py:7` and `transmogrify.py:7`: "the specs of the types share", but only bytes has a spec → "the spec of a type shares…".
- `bytesobject.c:3546`: the comment on the `_pyspec.c.h` include listed "bytes_from_iterator() (with its list and tuple variants)", which don't exist (the list/tuple variants are `bytes_new_nargs1_*`). It also left out the `__bytes__`/`fromhex` impls and the call table → lists what the file actually contains.

**Include**
- `internal/pycore_pyspec.h:15`: a paragraph with a broken wrap → rewrapped.

**Lib/test**
- `test_capi/test_opt.py:3470`: "This is the case `_CALL_STR_1` gets wrong for str subclasses" is fixed now → sentence deleted.
- `test_clinic.py`:
  - `:5561`: the `PyspecTest` docstring said "implements a clinic `__new__`", but the class also tests methods and top-level functions → "Spec functions with a body: their C is generated."
  - `:6761`: said the `BYTES_CASES` users were only `BytesSpecFactsTest` → also `test_pyspec_facts` (its `SOURCES`).
  - `:6964`: "(`_CALL_STR_1` claims an exact str for str subclasses.)" is fixed now → deleted.
  - `:7006`: "the old hand-written `_PyBytes_FromSequence_lock_held()`, derived" narrated history → "and exact ints take a fast path."
- `test_pyspec_facts.py`:
  - `:1`: an awkward module summary → "Check the facts Argument Clinic derives from the pyspec files."
  - `:341`: said the assertions follow `_CALL_LEN` too, but the test only checks `_CALL_STR_1` → mentions `_CALL_STR_1` only.
  - `:375`: "used to claim … (fixed by the merged fix-call-str-1-subclass branch)" narrated history → states the rule and what the wrong fact would do.
  - `:400`: the `SoundnessTest` docstring cited `pyspec-notes/review_int.md`, a wrong path (it is under `reports/`) and a note → reference removed.
  - `:407` and `:415`: two overlapping comments ("workstream A's F2 change" plus an `XXX` inside the test) → one `XXX` comment above `@expectedFailure` stating the condition. I kept the `XXX` so the notes README's "the XXX line" still points at it.
  - `:496`: "Masked today … P2 replaces the rule" pointed at a note → "Masked because … Fails until the rule is replaced."

`pyspec-notes/README.md`: I found nothing factually wrong at this HEAD, so it is unchanged.

### Code issues and dead code (reported, not fixed)
1. **Dead branch in `disconnects.py:694-699`.** The `elif (isinstance(prev, ast.Assign) … # a clone's docstring` branch of `_docstrings()` can never be reached: `frontend.Spec._add_class` rejects any string statement that is not first in a class body, so a spec that parses has no string after an assignment. It and its comment can go.
2. **`@helper` does nothing.** `runtime.helper` sets `__pyspec_helper__`, which nothing reads. It is still imported and used five times in the Escapes section of `bytesobject.py` (line 35 import; A's region), and the Escapes comment still describes it. That is A's to remove.
3. **`frontend.Spec.implemented()` swallows errors.** It catches `SpecError` from `method_kind()` and returns True, so a malformed `@c_name` keyword on a method with a body is treated as implemented. The error then surfaces elsewhere. This looks intentional but is worth knowing.
4. **`find_stub()` treats `@deleter` like a directive (`dsl_parser.py:589`).** It checks for `'@deleter'` alongside `@getter`/`@setter`. `runtime.py` defines a `deleter` identity decorator, so it may be a real clinic directive; I did not check whether it is. This is harmless either way.
5. **`PyspecFilesTest.test_up_to_date` runs clinic on `ctype.h`.** It dry-runs clinic on `Objects/stringlib/ctype.h`, which the ctype spec's own docstring says clinic never processes. Harmless, since there are no changes, but wasted work.
6. **The F2 limitation is still present.** `_testinternalcapi.c:3494` and `optimizer_bytecodes.c` (`_PySpec_FindMethod(..., sym_get_type(self_or_null))`) still ignore cls, as documented. It is expected until A's F2 lands; the comments are accurate.

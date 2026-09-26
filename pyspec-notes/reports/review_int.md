## Summary (≤60 lines)

**Verdict.** On the merged branch (62cc16504fe; build-exp was checked to be current) the tier-2 consumers are sound for the facts they use today. I could not make the JIT misbehave with bytes: 18 targeted probes and a 77-case differential test of the JIT-only typed variants all gave identical results on JIT on, JIT off, and main (debug). There are 5 latent unsound or fragile facts that are masked today, one real behaviour change in the free-threaded build, and several dimensions that are claimed but not enforced.

**Findings with repros (nothing fixed; everything is under `scratchpad/review_int/`)**
- **F1, behaviour change on the FT build (goal 3).** WS11 dropped the critical section, so `bytes(list)` no longer takes an atomic snapshot of an all-int list.
  - `ft_snapshot.py`: main FT gives 0 torn results out of 9000; the branch FT gives 9000 out of 9000.
  - It is still memory-safe and within `threadsafety.dat` "shared", but it is observable.
- **F2, latent: the `fromhex` facts drop their `cls` condition.** The method table claims "exact bytes, no Python" for `bytes.fromhex(str)` and the other typed entries, keyed only by `ml_meth`.
  - `call_table.generate_methods` binds `cls=Value(bytes)`.
  - `B.fromhex` has the same `ml_meth` and can return anything: `attack.py fromhex_subclass` returns 42.
  - This is the `_CALL_STR_1` shape. No consumer reaches it yet.
- **F3, latent: the rule "exact static type ⇒ no Python" (`runtime.is_static_type`, `RunsPython[T,'p']`, `Analyzer.call(iter)`) is false.**
  - Counterexamples: mappingproxy (`__len__`, `__iter__`), `reversed`/seq-iterator `__length_hint__`, and PickleBuffer (forwards `getbuffer`).
  - `static_rule_probe.py` shows the stubs say `runs_python=False` while Python runs.
  - It is masked only because `CANDIDATE_TYPES` is a short list and loops over types outside `ITERATION` count as "may run Python".
- **F4, fragile: derivation reads the regen host's builtins** (`hasattr(tp, name)` and `__dict__` in `partial_eval`).
  - `configure` accepts python3.10+ as `PYTHON_FOR_REGEN`, and `__buffer__` only exists from 3.12 on.
  - `host_dependence.py`: with a simulated <3.12 host, the memoryview variant turns into iteration, so `bytes(mv of 'h')` would raise ValueError in the JIT.
  - Today only `test_clinic.test_up_to_date` would catch it.
- **F5, latent: `_PySpec_CallNoPython1` in `NON_ESCAPING_FUNCTIONS` treats "runs no Python" as "does not escape".**
  - That doesn't hold on the FT build: bytearray's `getbuffer` takes a critical section, which can detach the thread and let a stop-the-world run.
  - It also doesn't hold for exporters whose release decrefs another object.
  - Tier 2 is disabled on FT today, so nothing triggers it.
- **F6, found in passing: the codec path allows a subclass result.** `bytes('x', codec)` and `'x'.encode(codec)` return a bytes *subclass*; `decode` does not (`codec_subclass.py`, same on main). WS10's proposed "str.encode → exact bytes" fact would be wrong. The spec stub already says this correctly.
- **F7, upstream bug on main:** `pickle.PickleBuffer(obj)` is unusable when `obj` has a Python-level `__buffer__`. `raw()` and `bytes()` raise "TypeError: … not '_buffer_wrapper'" (`picklebuf_bug.py`).
- **Still present:** the `_CALL_STR_1` assertion reproduces on build-exp. It is not fixed on the branch.
- **Minor goal-3 deviation:** `bytes.__dict__` order changed (find/count, split/rsplit). No test pins it.

**Dimension status (end to end on the merged tree)**
- **Pass (build-exp):**
  - 11 suites, 3175 tests: test_clinic, test_bytes, test_capi.test_bytes, test_pyspec_catalog, test_opt, test_inspect, test_pydoc, test_builtin, test_pickle, test_iter, test_descr.
  - `PYTHON_JIT=0 -R 3:3` on the 4 pyspec suites: no leaks.
- **Regen:** `make regen-cases` and `make clinic` leave a scratch copy clean. Python 3.14, 3.15 and 3.16 hosts give identical output. `--make` notices edits to the spec and to imported specs.
- **Stable ABI:** `stable_abi.py --all` is OK, test_stable_abi_ctypes is OK, and the catalog has 0 stable-ABI pins. Single-sourced.
- **C API catalog:** 41 pins (16 refcounts, 10 C, 6 docs, 5 headers, 4 behaviour). A mutation test caught refcounts.dat, rst, header and stable_abi edits. `threadsafety.dat` is not read at all.
- **Runtime vs main:** WS9's 80-attribute runtime dump and 143-line probe are identical to main after all merges.
- **Docs vs runtime:** no docs-shape test exists (WS9's R2 was not done).
- **Typeshed:** nothing in-tree. The bracket `@text_signature` overrides are still in the spec, so the stubtest blind spot remains.
- **Difftest:** the spec-vs-interpreter difftest only exercises the generic C path. The JIT-only typed variants have no difftest (my `typed_variants_diff.py` fills the gap once).
- **FT build of the merged tree:** builds with 0 warnings, and 7 suites pass. See F1.

**Single-source matrix (details below).** These facts are written twice with no check:
- stdtypes.rst signatures;
- the 13 ctype docstrings (spec and `bytes_methods.c`);
- `Escape.steals` vs the stub (`bytes_appender_finish` disagrees);
- `Escape.returns` vs the stub type;
- the stub `New[T]` claims vs C;
- the `ITERATION` table;
- the `threadsafety.dat` level.

These generated-then-checked loops could be removed:
- stub docstrings copied from bytes.rst, plus the equality test;
- `Escape.error` vs stub `OnError` (`test_escape_stubs`);
- 15 param-name pins;
- `test_up_to_date` (duplicates CI regen, once F4 is fixed).

**P1/P2.**
- **P1 would subsume:** `runtime.C` escapes, `@helper` stubs, `test_escape_stubs`, and the duplicated error/steals/returns.
- **P1 risks:**
  - The Python reference body of a `@c_implemented` static helper can't be difftested.
  - Template escapes (`{target}`, `.writer`, `exact=`) have no plain-call form.
  - Cross-file spec imports affect `--make` dependencies.
- **P2 would subsume:** the `RunsPython`/`OnError`/`New`/`Steals` vocabulary, the static-type rule (F3), and `ITERATION`.
- **P2 risks:**
  - `calls(x, slot)` must be transitive through forwarding static types (F3).
  - refcounts.dat can't hold static-helper ownership or InOut/NullIn.
  - A token-level escape check is per function, not per path.
- **Smallest set of mechanisms:**
  - **M1:** clinic reads the specs and generates everything.
  - **M2:** one Lib/test checker comparing spec facts with every hand artifact, with pinned disconnects.
  - **M3:** a difftest that also calls every call-table entry directly and records Python calls.
  - **M4:** one audited trust table for unspecified C, plus debug-build fact assertions.

**Top-ranked next steps**
1. Upstream the `_CALL_STR_1` fix.
2. Add debug-build fact assertions: an "exact result type" assert after table-typed calls, and a "no Python" tripwire in `_PySpec_CallNoPython1`.
3. Fix F2–F5 before adding any candidate types.
4. Add a JIT typed-variant difftest hook in `_testinternalcapi`.
5. Drop the bracket text signatures in bytes, bytearray and str.
6. Upstream the doc/docstring/typeshed/typeobj.rst fixes, plus F7.
7. Decide the FT snapshot question (F1).
8. Next: bytearray, then tuple, int, list, str.

---

# Full report

## 0. Setup and artifacts
- **Branch:** exp/ac_python_overloads_v0 at 62cc16504fe; cpython working tree clean and untouched. build-exp (debug JIT) matches the tree: binary newer than the sources, and `bytes_from_iterator` is present.
- **References:**
  - build-str1-dbg: main ee1bbf037ff, debug, JIT interpreter;
  - build_perf_base: main, release;
  - review_int/build-mainft and review_int/build-ft: FT debug builds of main and of the branch, built for this review (both about 1 GB; delete when done).
- **Scratch dir:** `/tmp/claude-1000/-home-firebird347-projects-python/50cf0ce0-5ab0-4e7c-ba5f-65e16f35a2bb/scratchpad/review_int/`.
  - Probes: `attack.py` + `run_attack.sh` → `attack_out.txt`; `typed_variants_diff.py` → `tv_{jit,nojit,main}.txt`.
  - Latent-fact and upstream-bug repros: `facts_probe.py`, `static_rule_probe.py`, `host_dependence.py`, `ft_snapshot.py`, `codec_subclass.py`, `picklebuf_bug.py`.
  - `catalog_mut.py`: catalog mutation test.
  - `src/`: configured scratch copy used for the regen and stable-ABI runs.
  - Logs: `tests_main.log`, `leaks.log`.
- Heavy commands ran under `systemd-run --user --scope -q -p MemoryMax=6G` (12G for builds), one at a time.

## 1. Single-source-of-truth matrix (bytes)

| Fact | Written by hand | Generated | Checks (test) | Verdict |
|---|---|---|---|---|
| **Py signature, docstring, text sig** | Spec params, docstrings and `@text_signature` (`Objects/pyspec/bytesobject.py`, `stringlib/pyspec/{transmogrify,ctype}.py`); class docstring (tp_doc); `Doc/builtins/stdtypes.rst` `.. method::` lines; typeshed builtins.pyi; the 13 ctype docstrings **also** in `Objects/bytes_methods.c` (used by bytearray) | `Objects/clinic/bytesobject.c.h`, `stringlib/clinic/transmogrify.h.h`, `bytesobject_types.c.h` | `test_clinic` test_up_to_date / test_transmogrify_up_to_date; `BytesSpecTypeTest.check_type` (PyCFunction docs, tp_doc); `test_inspect` (bracket methods listed as unsupported); stubtest (external, blind for 7 methods and `__new__`) | **Twice, unchecked:** stdtypes.rst vs spec; ctype docs spec vs `bytes_methods.c` (editing ctype.py changes bytes but not bytearray). The bracket overrides hide the true signature |
| **C signature** | Impl heads in bytesobject.c (no-block mode); C API definitions; Include/bytesobject.h, cpython/bytesobject.h, pycore_bytesobject.h; catalog stub C types; c-api/bytes.rst `c:function`; refcounts.dat types; `Escape(template, returns=)` in runtime.py | Clinic prototypes and parsers; C of spec bodies | Compiler (head vs prototype, generated vs headers); `test_pyspec_catalog.test_disconnects`/`test_complete` | `Escape.returns` vs stub return type: twice, unchecked. 15 of the 41 pins are param-name noise |
| **C name** | `class bytes ...` directive; `@c_name` (defaults `T_new`, `<class>_<slot>`); `TYPE_OBJECTS` in call_table.py; `_PySpec_bytes_calls` extern plus the `_PySpec_GetCallTable` line in pycore_pyspec.h | Prototypes, method/slot tables, variant names | Compiler/linker; clinic errors | OK; the registration line per type is manual |
| **Behaviour** | C code (most); spec bodies (`__new__`, `__bytes__`, `fromhex`, `PyBytes_FromObject`, `bytes_from_iterator`); runtime.C Python stand-ins for escapes; docs prose | C of the bodies, including the JIT-only `bytes_new_nargs1_<T>` | `BytesSpecTest` difftest (spec as Python vs interpreter; generic path only); test_bytes; `CatalogTest.test_behavior(_matches_interpreter)`; a few test_opt tests | **Gap:** typed variants are never difftested (my 77 cases agree). Escape stand-ins are unchecked against C. No pinned reference to pre-branch C behaviour once the C is deleted |
| **Result type / alias / constant** | Stub `New[bytes]` on escapes; `ITERATION` item types; hand facts on other ops in optimizer_bytecodes.c (`_CALL_STR_1`, `_CALL_TUPLE_1`, `_CALL_LEN`, …); typeshed returns; docs "copy" | Derived per argument type by call_table → `_PySpecCall` tables | `BytesSpecFactsTest` (subclass and `__bytes__`-override conditioning), test_opt alias/subclass | Stub `New[T]` vs C: unchecked. Class-method `cls` condition implicit (F2) |
| **Runs Python** | `RunsPython[...]` stubs; the `is_static_type` rule; `ITERATION`; the `NON_ESCAPING_FUNCTIONS` entry; Analyzer rules (Raise, `iter`) | Flags | `BytesSpecFactsTest` (static only) | No dynamic check that Python really doesn't run. General rule unsound (F3). No-Python ≠ non-escaping (F5) |
| **Error convention** | `Escape(error=)` **and** stub `OnError`/`New`; docs prose | Derived for bodies | `test_escape_stubs` (maps MISSING→NULL, which hides that `lookup_special`'s absent-convention has no vocabulary); 6 `docs:error-unstated` pins | Written twice but checked: a loop P1 would remove |
| **Ownership** | Stub `New`/`Borrowed`/`Steals`/`InOut`/`Out`/`NullIn`; refcounts.dat; `Escape(steals=, release=)`; Sphinx renders "New reference" from refcounts.dat | – | Catalog refcounts check (16 pins), `test_refcounts_lines` | **Disagrees, unchecked:** `bytes_appender_finish` has `steals=(0,)` in runtime.py but no `Steals` in its stub |
| **Stable ABI** | `Misc/stable_abi.toml` only; `Py_LIMITED_API` guards | stable_abi.dat, python3dll.c, test_stable_abi_ctypes.py | Catalog `check_stable_abi` (0 pins; mutation detected); `stable_abi.py --all`; test_stable_abi_ctypes | Single-sourced |
| **Docs prose** | Doc/c-api/bytes.rst; stdtypes.rst; catalog stub docstrings are verbatim copies of bytes.rst | – | `CatalogTest.test_facts` (stub doc == rst body); 4 `behavior:*-unstated` pins | Copy-then-compare loop: remove the copies |
| **typeshed types** | builtins.pyi (external); spec converters give a partial mapping | – | stubtest (external) | Nothing in-tree; blind spot remains |
| **Slot ↔ dunder** | `slotdefs[]` (source); typeobj.rst tables; spec slot stubs + `@c_name(slot=)` | Slot tables in `bytesobject_types.c.h` | Clinic generation checks (params vs slotdefs text sig; groups); `PyspecSlotdefsTest.test_wrappers`; `test_typeobj_rst` (pinned) | Good. test_wrappers is a parser test; keep it |
| **Type flags, sizes** | `@static_type(...)`, `@final`; struct/macros in headers | tp_name, BASETYPE, HAVE_GC, tp_doc, tables, tp_base → `bytesobject_types.c.h` | `BytesSpecTypeTest` (order, wrappers, docs, 2 flag bits); compiler; test_sys | `__dict__` order changed and is not pinned |

**Generated-then-checked loops that could be removed**
- (a) Stub docstrings copied from bytes.rst, plus `test_facts`' equality.
- (b) `Escape.error` vs stub errors (`test_escape_stubs`), once P1 lands.
- (c) The 15 header/C param-name pins.
- (d) `test_up_to_date` duplicates CI's `make regen-all` diff. Keep it only until F4 is fixed, since today it is the only guard against host-dependent output.

## 2. End-to-end verification
- **Tests on build-exp:** the 11 suites passed (run=3175, skipped=77). Pyspec classes, all OK:

  | Class | Tests |
  |---|---|
  | PyspecTest | 14 |
  | PyspecStubTest | 24 |
  | PyspecNoBlockTest | 4 |
  | PyspecTypeTest | 9 |
  | PyspecSlotdefsTest | 2 |
  | BytesSpecTest | 7 |
  | BytesSpecTypeTest | 3 |
  | BytesSpecFactsTest | 7 |
  | CatalogTest | 8 |
  | VocabularyTest | 3 |

  - `PYTHON_JIT=0 -R 3:3` on test_bytes, test_capi.test_bytes, test_pyspec_catalog and test_clinic: OK.
  - `-R` with the JIT on was not rerun; it is known broken on base.
- **C API catalog:** 41 pins. A mutation run (`catalog_mut.py` on a scratch copy) reported new disconnects for:
  - `refcounts:PyBytes_FromString:return`
  - `docs:PyBytes_Size:param-names`
  - `headers:PyBytes_Size:param-names`
  - `stable_abi:PyBytes_AsString:dat-version`

  A `threadsafety.dat` change was **not** detected (the file is never read), although goal 6 names it.
- **Docs vs runtime:** there is no docs-shape test.
- **Typeshed:** no in-tree check. WS9's runtime dump and probe are byte-identical to main after all merges (`rt_exp.json` vs `rt_main.json`, `probe_*.txt`), so WS9's stubtest results still hold, including the blind spot.
- **Tier-2 conditioning:** `BytesSpecFactsTest` and test_opt's `pyspec_alias_subclass` pass. My probes (`attack_out.txt`) cover:
  - an alias trace fed a subclass whose `__bytes__` returns another subclass;
  - folding `type(bytes(x)) is bytes`;
  - refcount balance of the alias, both call and method;
  - a bytearray trace fed a subclass with Python `__buffer__`;
  - memoryview over a Python buffer (no extra `__buffer__` call);
  - a released memoryview raising inside the non-escaping uop (right line);
  - range errors;
  - list/tuple/dict mutated from `__index__`, with `__del__` side effects;
  - int subclasses and huge ints;
  - `__length_hint__`;
  - speculation fed another type.

  All agree with JIT off and with main.
- **Spec vs interpreter difftests:** they exist for the generic path. `typed_variants_diff.py` warms a loop per candidate type so the trace guards on that type, then feeds 77 edge cases, including list mutation (clear/append/pop/insert/grow), huge ints, and released or strided or 'h'/'d' memoryviews. All three builds give identical output. str and float variants are never traced, because the warm-up raises.
- **Regen:** in a configured scratch copy, `make regen-cases` and `make clinic` (build-exp as `PYTHON_FOR_REGEN`) leave the tree clean. Running `clinic.py --force` on the bytes files with 3.14 and 3.15 gives identical output. `--make` regenerates after edits to bytesobject.py, transmogrify.py and ctype.py (imported spec → `bytesobject_types.c.h`).
- **FT:** the FT debug build of the merged tree has 0 warnings. test_bytes, test_capi.test_bytes, test_clinic, test_pyspec_catalog, test_free_threading, test_iter and test_buffer pass (1292 tests). F1 is the one behaviour difference.
- **Stable ABI:** `Tools/build/stable_abi.py --all Misc/stable_abi.toml` passes (rc 0). test_stable_abi_ctypes passes. `PyBytes_Type` and `PyBytesIter_Type` are D symbols.
- **Claimed but not enforced:**
  - threadsafety.dat;
  - docs shape;
  - typeshed (blind spot);
  - JIT typed variants (no difftest);
  - "runs no Python" (no dynamic check);
  - stub `New[T]` result claims vs C;
  - class-method `cls` condition;
  - independence from the regen host.

## 3. Soundness audit (detail)
**The tier-2 consumers** (`_CALL_BUILTIN_CLASS` and `_CALL_METHOD_DESCRIPTOR_NOARGS` in optimizer_bytecodes.c) are sound for the current tables:
- Typed entries match only an exact symbol type, or the recorded probable type plus `_GUARD_TYPE`, and only when the entry has a result type.
- Subclass and heap types fall to the generic entry, which claims no type and may run Python.
- The alias needs `result_alias == 0` plus an exact-type match. The class is immortal.
- The method path uses `d_type` and self's exact type. The generic `__bytes__` entry claiming "exact bytes" is true, because `bytes_copy` makes an exact copy.
- Other `sym_new_type` sites I swept (`_CONTAINS_OP`, `_GET_LEN`, `_CALL_LEN`, `_CALL_TUPLE_1`, `_BINARY_OP`, which needs both operands exactly typed) are fine. `_CALL_STR_1` is the only wrong one, and it still asserts on build-exp.

**F1 (FT behaviour change).**
- Reproduce with `review_int/build-ft/python ft_snapshot.py` versus `review_int/build-mainft/python ft_snapshot.py`: one writer flips `lst[:]` between `[1]*4096` and `[2]*4096`, and three readers call `bytes(lst)`.
- Torn results: branch [3000, 3000, 3000] in both runs; main [0, 0, 0].
- Main held `Py_BEGIN_CRITICAL_SECTION_SEQUENCE_FAST` in `_PyBytes_FromSequence_lock_held`.
- Decide whether to keep an all-exact-int versioned path under the list lock, or to accept and document the change.

**F2 (fromhex facts).**
- `bytesobject_pyspec.c.h` `bytes_spec_methods[]` lists entries like "bytes.fromhex(str): result is exactly bytes; runs no Python code".
- `generate_methods` binds `cls=Value(bytes)`. `BytesSpecFactsTest.test_fromhex` itself shows that with `cls` NOTNULL the result type is None and Python may run.
- `_PySpec_FindMethod` keys only on `ml_meth` and the argument type. A future `_CALL_BUILTIN_O` consumer on the bound `B.fromhex` would claim exact bytes: at runtime `H.fromhex('4142')` returns 42 (`attack.py fromhex_subclass`).
- Fix: key the entry on `cls` (arg 0 = the type), or have consumers require `m_self == tp`.

**F3 (static-type rule).**
- `static_rule_probe.py` output: the stubs say `PyObject_LengthHint(mappingproxy)`, `PyObject_LengthHint(reversed)` and `lookup_special(mappingproxy)` run no Python, and `Analyzer.call` says `iter(mappingproxy)` runs no Python.
- At runtime, `__len__`, `Seq.__len__` and `__iter__` all run Python code.
- `facts_probe.py` shows that if PickleBuffer were a candidate, `bytes(PickleBuffer)` would be derived as "no Python, exact bytes", while `picklebuf_getbuf` forwards to the wrapped object.
- Masking relies on `CANDIDATE_TYPES` and on loops over types outside `ITERATION`.
- Fix: replace `is_static_type` with an explicit allowlist of leaf types, or with facts from those types' specs.

**F4 (host dependence).**
- `partial_eval.py` L139, L176 and L405 consult the host's `tp.__mro__`, `__dict__` and `hasattr`.
- `host_dependence.py` shows the memoryview residual changes when `__buffer__` is absent (<3.12 host). The JIT variant would then raise ValueError for `memoryview(array('h', …))`, where the buffer path gives 6 bytes.
- Fix: read these facts from spec declarations, or have clinic refuse a regen host older than the target.

**F5 (`NON_ESCAPING_FUNCTIONS`).**
- `_PySpec_CallNoPython1` is a generic trampoline in the allowlist. Its safety depends only on the optimizer's flag check.
- "No Python" does not imply non-escaping:
  - bytearray `getbuffer`/`releasebuffer` take a critical section on FT, which can detach the thread and let a stop-the-world run;
  - `PyBuffer_Release` decrefs `view.obj`, which for forwarding exporters is another object.
- Tier 2 is off on FT and the current candidates are safe, so this is latent.
- Suggested tripwire: in Py_DEBUG, `_PySpec_CallNoPython1` sets a thread-state flag, and the eval loop and `PyObject_Call*` assert it is clear.

**F6 and F7:** see the summary. F6 corrects WS10's "How this generalizes": `str.encode` cannot get an exact-bytes fact, while `bytes.decode` → exact str does hold.

**Tables and stubs checked and found correct for their entries:**
- `ITERATION` (list, tuple, dict, set, frozenset, range→int, bytes→int, bytearray→int, str→str);
- stubs `bytes_iterator.__next__ -> New[int]`, `__len__ -> NoError`, `PyUnicode_AsEncodedString` (RunsPython, not exact), `bytes_copy`, `_PyBytes_FromSize`;
- range items are always exact ints (`PyNumber_Index` normalizes them).

## 4. P1 / P2 vs what exists
- **P1 (helpers by name, `@c_implemented`)** would subsume:
  - `runtime.C` Escape objects (template, returns, error, steals, release, exact);
  - `@helper` stubs, and stubs for C functions that don't exist (e.g. `bytes_from_hex` wrapping `_PyBytes_FromHex(…, 0)`);
  - `test_escape_stubs`;
  - the disagreements between steals/returns/error and the stubs.
  - It also makes a body the natural place for per-constant facts (`use_bytearray`).

  Risks:
  - A Python body for a *static* C helper can't be difftested (no Python entry point), so its facts are derived from unexecuted Python. That is the `_CALL_STR_1` risk class, unless a `_testinternalcapi` hook or the token check backs it.
  - Templates with `{target}`, struct fields (`.writer`, `.str`) and `exact=` inline lowerings have no plain-call form.
  - Cross-file imports (`abstract.py`) widen `--make` dependencies, and name clashes with macros or `#if` duplicates become possible.
- **P2 (derived facts with `exact`/`unknown`/`calls`/`runs_python`/`NULL`)** would subsume:
  - the `New`/`Borrowed`/`Steals`/`Out`/`InOut`/`OnError`/`NoError`/`RunsPython` vocabulary;
  - `RunsPython[T,'p']` and `is_static_type` (F3);
  - `ITERATION` (becomes facts in each type's spec);
  - the `Escape.error` duplication.

  Risks:
  - `calls(x, "__len__")` on a static type is only Python-free if that type's slot is leaf C. Forwarding types (mappingproxy, PickleBuffer, reversed, seq-iterator) need their own specs or an allowlist, so the transitivity must be designed in.
  - Ownership from refcounts.dat can't express static helpers (`bytes_appender_finish` steals), `InOut`, `NullIn` or "steals on success". Also, 16 bytes entries and 428 tree-wide documented functions are missing from it.
  - The cases-generator escape check is token-level and per function, not per path, and decref makes nearly everything "escape". Expect many accounted-for false positives.
  - The dynamic call-recording difftest is the strongest part; it also needs a way to call the JIT typed variants.
- **Smallest set of mechanisms for full single-sourcing:**
  - **M1:** clinic generates from the spec: signatures, docs, C names, types, slots, bodies, and call tables.
  - **M2:** one Lib/test checker compares derived facts with every hand artifact, with pinned disconnects: headers, c-api rst, refcounts.dat, stable_abi.toml, threadsafety.dat, stdtypes.rst method lines, typeobj.rst.
  - **M3:** one difftest harness covers the spec, the interpreter and every call-table entry called directly, with call-recording dunders.
  - **M4:** one audited trust table for C without a spec (replacing `ITERATION`, `is_static_type`, `CANDIDATE_TYPES` and the `NON_ESCAPING` entry), backed by debug-build fact assertions: "exact type" after table-typed results, and a "no Python" tripwire.

## 5. Ideas, ranked
1. **Upstream the `_CALL_STR_1` fix:** use `sym_new_not_null` unless the argument is known exact str, and add a test_opt case. Memory-safety bug in 3.15; independent of pyspec.
2. **Debug-build fact assertions** (M4 tripwires): a cheap uop asserting `Py_IS_TYPE(res, T)` after any table- or optimizer-typed call result, and a "no Python" flag checked in eval entry. This would have turned `_CALL_STR_1` into a test-suite failure, and it enforces goal 2 inside the normal test suite.
3. **Fix F2–F5 before adding candidate types or consumers:** key `fromhex` on `cls`; allowlist leaf static types; make derivation independent of the host; separate no-Python from non-escaping.
4. **A `_testinternalcapi` hook to call `_PySpec_*` entries directly,** and run `BytesSpecTest.CASES` through every typed variant (M3). Closes the largest verification gap.
5. **Drop the bracket `@text_signature` in bytes/bytearray/str** (3 lines per type, gh-117431 follow-up). stubtest then covers 21 more methods, and test_inspect's exclusions shrink.
6. **Upstream small fixes:**
   - Docs and docstrings from WS9: removesuffix `prefix`, the functions.rst `__bytes__` claim, half-open `count`, c-api `PyBytes_FromObject` scope, `translate`, "copy" vs identity.
   - typeshed: partition middle element, `center` fillchar, `__new__` keyword `source`.
   - typeobj.rst: missing `__rfloordiv__`, `__rtruediv__`, `__rmul__`; slotdefs `__ipow__`/`__iadd__` doc inconsistencies.
   - refcounts.dat: the 16 missing bytes entries (the catalog already renders these lines).
   - New from this review: PickleBuffer over Python buffers (F7); documenting that `bytes(s, codec)` can return a subclass (F6).
7. **Decide F1** (FT snapshot): keep a locked exact-int list path, or document the change.
8. **Checks, not generation, for docs:**
   - add threadsafety.dat to the catalog;
   - add WS9's R2 docs-shape test;
   - drop the stub docstring copies and the param-name pins.
   - Generating refcounts.dat or rst is not recommended: Sphinx consumes those files, they are cross-file, and multi-form lines don't fit a generator.
9. **bytearray next.** It shares the transmogrify/ctype specs, removes the duplicated ctype docstrings, and stress-tests mutability and FT critical sections.
10. **Type order after that: tuple → int → list → str.**
    - tuple is small and immutable; it derives `_CALL_TUPLE_1` and exercises type generation a second time.
    - int gives `__index__`/`PyNumber_AsSsize_t` facts that other specs consume; this makes `bytes(16)` Python-free.
    - list needs the FT lock design first.
    - str is the largest, has codec subclass pitfalls, and `_CALL_STR_1` should already be fixed upstream by then.
11. **Rollout of small PRs:**
    1. `_CALL_STR_1` fix.
    2. Doc/docstring/typeshed fixes.
    3. Bracket signatures.
    4. Clinic spec files with byte-identical output (stub-only bytes spec).
    5. slotdefs parser plus the typeobj.rst check (test only).
    6. C API catalog checker (trimmed pins).
    7. Generated static types (decide the `__dict__` order).
    8. Emitter plus small bodies (`__bytes__`, `fromhex`).
    9. `bytes.__new__` / `PyBytes_FromObject` bodies with the difftest.
    10. Call table plus tier-2 consumer, with fact assertions and the direct-call difftest.
    11. Iterator derivation, after F1 is decided.

    One .c file per PR.

**Not done:** mypy/stubtest was not rerun (the runtime is identical to main, so WS9's result stands); no TSAN run.

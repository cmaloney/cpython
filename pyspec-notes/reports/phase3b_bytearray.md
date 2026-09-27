## Phase 3b: bytearray now comes from a spec, and PyTypeObjects are back in C

bytearray is described by `Objects/pyspec/bytearrayobject.py`, and your mid-task decision (the PyTypeObject stays in C, clinic generates only the method and slot tables) is applied to both bytes and bytearray. Python sees exactly what main shows for both types. All the requested test suites pass, in the debug JIT build and the free-threaded build.

- **Worktree:** `/home/firebird347/projects/python/cpython/.claude/worktrees/agent-af74d1e66e6ec3f32`, branch `worktree-agent-af74d1e66e6ec3f32`, on top of 4e8812177fa. Six commits; nothing rebased or amended; the tree is clean.
- **Build dirs:** `/home/firebird347/projects/python/build-3b` (debug JIT) and `build-3b-ft` (free-threaded debug).
- **Scripts and dumps:** `scratchpad/3b/` holds `dump_ba.py`, `dump_bytes.py`, `measure.py` and `mismatch_ba.py`, plus the dump outputs.

### Commits
1. `8254734e4d1` Shared methods can be wrapped in decorators and can name a method of the same spec.
   - `strip = critical_section(bytesobject.bytes.strip)` plus the one-line block `bytearray.strip`: bytearray gets its own clinic function with bytes' signature, docstring and decorators, and `@critical_section` added.
   - `center = critical_section(transmogrify.B.center)` with no block: clinic generates the `bytearray_center()` wrapper that takes the critical section. For a clinic function, the calling convention is read from its generated `*_METHODDEF`.
   - `__reduce__ = c_name(METH_NOARGS="f")(bytearray.__reduce__)`: an entry calling `f`, with the other method's docstring.
2. `34fcefe419f` bytearray from a spec: 38 one-line blocks (including `__init__`) and 18 hand-written critical-section wrappers removed. The message says "37 clinic functions" and "9 lines fixed"; the correct numbers are 38, and 8 fixed plus 2 relabeled. I didn't amend.
3. `50312bedd2a` Removes the 13 ctype docstring copies from `bytes_methods.c` and their externs from `pycore_bytes_methods.h`.
4. `d4c555e6cf7` The docs ratchet compares a documented constructor with the spec's `__new__`, else its `__init__`. `Doc/data/threadsafety.dat` gets the three missing bytearray entries.
5. `c09ec37fdd1` "pyspec: PyTypeObject stays in C; generate only method and slot tables" (bytes).
   - At this commit alone, bytearray's generated file is stale, so `test_up_to_date` fails until the next commit. This is stated in the commit message.
6. `2b657c75aaf` The same rule applied to bytearray.

### Your decision: PyTypeObject back in C
- **Structs:** `PyBytes_Type`, `PyBytesIter_Type`, `PyByteArray_Type` and `PyByteArrayIter_Type` are main's text again.
  - They now sit after `#include "clinic/<stem>_pyspec.c.h"` at the end of each file, because the tables they name are generated there.
  - A static array of unknown size can't be forward-declared portably, so keeping them at main's position would have needed more infrastructure.
  - The only line that isn't main's is `.tp_vectorcall = bytes_vectorcall`, which is this branch's addition.
- **What clinic generates:** only `<prefix>_doc`, `<prefix>_methods[]` and the `_as_number`, `_as_sequence`, `_as_mapping` and `_as_buffer` sub-tables.
- **Which classes:** every spec class that its `.c` file declares with a clinic `class` directive. A header's spec (`transmogrify.h`) gets nothing.
  - That rule needs the iterators' class directives: 4 lines each, not on main. They also record which `PyTypeObject` each class describes.
- **Symbol names are all main's:**
  - `bytes_doc` and `bytearray_doc`: the doc symbol is now `<prefix>_doc`.
  - `striter_methods` and `bytearrayiter_methods`: through `@c_name("striter")` / `@c_name("bytearrayiter")` on the class. This reuses `@c_name` and is the only form a class decorator can take.
- **Removed:** `@static_type`, `@final`, the struct generation (parsing `object.h`, derived members, derived flags, `tp_basicsize` from the directive, `tp_base` from bases), and the README rows. `typeobj.py` went from 474 to 437 lines; this commit alone is +82/−221 in `libclinic`.
- **Completeness for facts:** `builtin_types.TypeFacts` used `@static_type` to know a spec class is complete. It now treats a spec class that declares any slot as complete.
- **Mismatch check:**
  - `PyspecFilesTest.check_type` compares the type's slot wrappers with the class's dunders, now with a message naming the C struct.
  - New `test_types_mismatch` removes `__hash__` and `__contains__` from the bytes spec, and adds `__index__`. All three are caught.
  - For bytearray (`mismatch_ba.py`), adding `__hash__` and dropping `__release_buffer__` or `__imul__` are all caught.
  - Not checked: the spec's C name for a type-level slot (for example `@c_name("PyObject_SelfIter")`) is not compared with the struct. Only whether the slot exists is checked. For that reason I left type-level C names out of the bytearray spec.
- **bytes dump vs main:** identical except `tp_vectorcall`.
- **bytesobject.c diff vs main:** `git diff --stat` grows from 878 to 959 lines, because git counts the moved structs as deleted and re-added. With the unchanged, moved struct text excluded, it shrinks from +171/−729 to +170/−648.
- **Concepts:** about 6 removed (`@static_type` and its member rules, `@final`, derived flags, size and base derivation, static-vs-exported naming). 2 added: the class `@c_name` prefix, and "the struct after the include names these tables".

### Lines
| What | Change |
|---|---|
| `bytearrayobject.c` vs main | 3195 → 2561 lines; git +117/−751 (+64/−698 without the moved structs) |
| `bytes_methods.c` | −78 |
| `pycore_bytes_methods.h` | −13 |
| Spec | `bytearrayobject.py` +582, `_cases.py` +13; bytes spec −21 (decorator lines and docstring only) |
| Tool code (`libclinic`) | +336/−297 overall (net +39): shared-method work +255/−77, `@static_type` removal +82/−221 |
| `test_clinic.py` | +205/−113 |
| Generated | `bytearrayobject_pyspec.c.h` +384 |

### Ratchet baseline counts
| Dimension | Before | After |
|---|---|---|
| capi | 23 | 20 |
| docs | 1 | 0 |
| docstrings | 22 | 2 |
| slots | 3 | 3 |
| c_calls | 0 | 0 |
| typeshed | 1 | not run |

- **Docstrings removed:** the 13 ctype copies, count, maketrans, replace, rstrip, strip, translate, and the iterator's `__length_hint__` and `__setstate__`.
- **Two docstring lines remain, now labelled by the spec:**
  - `lstrip`: bytes' docstring has "leading  ASCII" with two spaces. Sharing it would change `bytearray.lstrip.__doc__`, so bytearray keeps its own. A one-character fix to the bytes docstring would allow sharing.
  - The one-sentence "Return state information for pickling." used by `__reduce__`/`__reduce_ex__` and `bytes_iterator.__reduce__`. These have different signatures, so there is nothing to share.
- **typeshed:** there is no typeshed checkout on this machine, so this optional dimension could not be run.

### Parity
- `Objects/clinic/bytearrayobject.c.h` and `transmogrify.h.h` are byte-identical to main (ee1bbf037ff). `bytesobject.c.h` still differs only in the `__new__` section.
- The bytearray and iterator dump is identical to main: attributes, docs, signatures, flags, `__dict__` order, `help()`, pickling, and every PyTypeObject field and table resolved to a symbol.

### Tests
All runs were memory-capped and serial, with `make -j8`, after checking `free -g`. Both builds have 0 compiler warnings.
- **Debug JIT build:** test_bytes, test_clinic, test_inspect, test_pydoc, test_descr, test_pickle, test_buffer, test_pyspec_catalog and test_pyspec_facts pass (2700 tests). test_capi alone passes (1587).
- **Refleaks:** `PYTHON_JIT=0 -R 3:3` on test_bytes, test_clinic, test_pyspec_catalog, test_pyspec_facts and test_buffer shows no leaks.
- **Free-threaded debug build:** test_bytes, test_free_threading, test_pyspec_facts and test_clinic pass. The bytearray free-threading tests (`test_bytes` `test_free_threading_bytearray*`) passed 5 runs out of 5. There is no `test_free_threading.test_bytearray`.
- **Clean tree:** clinic on the six spec-backed files (host Python and the built Python) and `make regen-cases` leave the tree clean.

### Scope decisions
- **Slot kinds:** all the mutable-sequence slots (`sq_ass_item`, `mp_ass_subscript`, `sq_inplace_concat`, `sq_inplace_repeat`, `bf_releasebuffer`) went through the existing slotdefs machinery with no generator change. Only the test needed changes: `__init__` is a wrapper, and `__hash__ = None` comes from `PyType_Ready`.
- **`__init__` body not moved into the spec:** it shares little with `bytes.__new__` (a different order of checks, and no `__bytes__`). It also mutates self in place: reusing a uniquely referenced encoded object, a resize loop, the list fast path. Moving it would not be simpler.
- **No `__next__` fact for bytearray's iterator:** nothing consumes such a fact yet, and adding one would need HelperTest cases.

### Feedback on the mechanism: what a second type needed that bytes didn't
- The same declaration in two types with different implementations and locking: sharing with an own impl, and `critical_section(...)`.
- One method's docstring on another type's method: `c_name(...)(T.m)`.
- Reading another file's clinic calling convention from its generated `METHODDEF`. This is a small dependency on regeneration order.
- `runtime.load()` had to stop rewriting class-body references.

### Open problems
- The `threadsafety.dat` levels are my judgement and are worth a look before anything goes upstream: `Check` and `CheckExact` atomic, `Resize` shared because it takes a critical section.
- The ctype docstrings are now compiled once per type (`bytes_isalnum__doc__` and `bytearray_isalnum__doc__`). Main had one shared copy, so the binary carries about 1.4 KB of duplicated text.
- `pycore_bytes_methods.h` still declares `_Py_count__doc__` and eight other docstrings that are never defined, and `_Py_maketrans__doc__` is unused. This predates the branch and I didn't touch it.
- The bytearray row of `builtin_types.TABLE` still holds audited facts that the bytearray spec's `...` stubs don't carry.

### Shared-file edits
- Bytes spec: the `@static_type`/`@final` lines, their imports, the module-docstring paragraph about them, and the iterator comment.
- `bytesobject.c`: structs restored, and the `#else` that WS12 added to `bytes_dealloc` removed.
- Also edited: `test_clinic.py`, `threadsafety.dat`, `bytes_methods.c` and its header.
- I did not touch `bytecodes.c`, `specialize.c` or the optimizer.
- I did not update `pyspec-notes/`, which is outside the worktree and wasn't requested.
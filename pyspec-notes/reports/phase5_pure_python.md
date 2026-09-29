# Phase 5, workstream PY: "Python which is lowered" (2026-09-28)

The user's question: *can the implementation be 100 % "Python which is lowered": behaviour
would not change if we ran the pure-Python implementation, we just choose not to, for
performance?*

Short answer: **for bytes, yes, up to a short, explained list.**  Every method and slot of
`bytes` and `bytes_iterator` except printf-style `%` now has a pure-Python body in the
spec; run as a Python class built from the spec (the *model*), it agrees with the C type on
**36,086 of 36,189 compared parity lines (99.7 %)**.  The 103 other lines are limits of
a Python class, not of the bodies (below); 889 lines (type object, C layout, pickle,
`sys.getsizeof`) are excluded with a reason.  Nothing new is compiled: clinic's output,
the facts, the call tables and the committed parity record are unchanged (the only
generated-file change is the `/* spec.py:N */` line comments, which follow the lines of the
spec).

Branch `worktree-agent-adb5e3b3887a4b87d` (from `exp/ac_python_overloads_v0` at
0ba52ad421a), debug build `../build-p4-py` (`CC=clang --with-pydebug
--enable-experimental-jit`).

## 1. Definition

A spec'd type is **Python which is lowered** when running the spec's Python would behave
exactly as the C does; the C is the same program, lowered (by hand, or by clinic) for speed.
Precisely:

1. **Complete**: every method and slot of the class, and every function its bodies call,
   has a Python body: generated (lowered by clinic), `@native` (a reference the facts read)
   or `@native(facts=False)` (a pure-Python implementation only the model runs).  No
   `...` is left.
2. **Non-circular**: the bodies compute with host types no spec describes (`int`, `str`,
   `tuple`, `list`, `slice`, exceptions), call other spec functions, and name a type a
   spec describes (`bytearray`) or `memoryview` only *as a type* (type tests, `exact()`),
   never calling it or reading its attributes.  The classes of the spec stand for
   themselves: `bytes(...)` or a `b'..'` literal in a body is the model's bytes.
3. **Machine primitives** are the only exception: a short fixed list, each with a Python
   meaning (to run) and a C meaning (what the lowering does), for what Python cannot say:
   object layout and memory, the buffer protocol, the hash key, the slot tables abstract.c
   dispatches on, and values from host code outside the model (codecs).
4. **Observable equivalence**: the model and the C type give the same line for every probe
   of `Tools/clinic/pyspec_parity.py`, except the sections a Python class cannot have like
   a static C type, each listed with its reason.

The PyTypeObject stays C (a decision in force); the model takes from it only what the spec
does not describe (whether the type can be subclassed or instantiated).

## 2. Design

**Two kinds of reference.**  A body of a C function is either a *C-oriented reference*
(`@native`: effects written where the facts see them, read for facts, held to the C by
the checker and `HelperTest`) or a *pure-Python implementation* (`@native(facts=False)`).
Both mean "C written by hand; the body is the Python"; the second is not (yet) a source of
facts.  Making every signature-only method plain `@native` would have changed generated C
(every `@native` slot gets a call-table entry), required the C checker to read clinic
`_impl` functions and account for every call that may run Python code, and required
`HelperTest` inputs for 60 methods.  `facts=False` keeps all tools exactly as they were
(`frontend.is_stub()` is true for it, `is_native()` false); in a C-oriented reference a
call of a pure function is part of the model of a value, like a builtin (`subset.py`,
`facts.py`: two lines each).  Promoting a body to `@native` later is the step that makes
it a source of facts (section 5).

**Machine primitives** (`Tools/clinic/libclinic/pyspec/machine.py`):

| primitive | Python (model) | C |
|---|---|---|
| `ob_alloc(tp, items)` | a new instance of model class `tp` holding the tuple of ints | `PyBytes_FromStringAndSize()`, `tp_alloc` |
| `ob_items(o)` | the tuple of ints `o` holds | `PyBytes_AS_STRING()`, `Py_SIZE()` |
| `ob_new(tp)` | an instance with its declared fields NULL | `PyObject_GC_New()` |
| `buffer_items(o)` | the bytes of `o`'s buffer, or NULL | `PyObject_GetBuffer()`, release |
| `buffer_export(o, flags)` | a read-only view (BufferError for a writable request) | `bf_getbuffer` / `PyBuffer_FillInfo()` |
| `hash_secret()` | (k0, k1) of the interpreter (`_Py_HashSecret`, via ctypes) | `_Py_HashSecret` |
| `has_slot(tp, 'sq_repeat')` | reads the type's slot table (ctypes) | `tp->tp_as_sequence->sq_repeat` |
| `from_host(tp, v)` | a codec's bytes result as a model bytes | nothing (one bytes type) |

On the *host* (the existing `runtime.load()`, `HelperTest`, the difftest) the classes of a
spec are the builtins and each primitive reads the builtin, so the C-oriented references
keep working there unchanged.  Singletons are spec, not machine: `new_bytes()` in
bytesobject.py returns the empty and one-byte singletons as `PyBytes_FromStringAndSize()`
does (with `written=True` for `PyBytes_FromStringAndSize(NULL, n)`: only the empty one).

**Spec conventions added** (README.rst): `@native(facts=False)`; struct fields in a class
(`ob_sval: 'char[]'`, `it_index: Py_ssize_t`; the struct stays C); a template spec
(`Objects/stringlib/pyspec/`) is instantiated per including type: `B` and
`STRINGLIB_NEW`/`STRINGLIB_MUTABLE` come from the spec that shares the method (bytesobject.py
defines `STRINGLIB_NEW = new_bytes`), as the `#define`s before `#include` do in C.

**The model** (`Tools/clinic/libclinic/pyspec/model.py`, ~1,040 lines) runs a spec without
touching the host builtins: each spec file (and those it imports) is executed with a
builtins dict whose `__import__` loads other specs the same way and whose spec class names
are the model classes; `T.meth(...)` in a body calls the spec function (the C impl), a
bytes literal in a body is `new_bytes()`.  A model class is a Python class named like the
builtin (`__module__ == 'builtins'`), a subclass of `machine.VarObject` (holds bytes) or
`machine.Object` (declared fields), with, per method:

* clinic's argument parsing, derived from the spec signature exactly as clinic chooses it
  (`METH_NOARGS`, `METH_O`, positional-only `_PyArg_CheckPositional()`, or
  `_PyArg_UnpackKeywords()`; each converter: `object`, `Py_ssize_t`, `int`,
  `slice_index`, `str`, `bool`, `char`, `Py_buffer`) with the C's messages;
* descriptors modelling `descrobject.c` (`method_descriptor`, `classmethod_descriptor`,
  `wrapper_descriptor`, bound `builtin_function_or_method`/`method-wrapper`, the
  `tp_new_wrapper`), named after the C types so the parity tool probes them the same way;
  docstrings and text signatures as clinic and `slotdefs[]` give them;
* slot wrappers as `typeobject.c`'s `wrap_*` (arity, `__next__` NULL -> StopIteration,
  `__buffer__` flags).

**Values across the edge.**  The pool of the parity tool is host objects; `to_model()`
turns host bytes into model bytes (as a literal, singletons included) and a host iterator
into a model one (through `__reduce__`).  Host code outside the model gets model objects
through Python protocols only: `bytearray(b'ab') + m` reads `m.__buffer__` (PEP 688).
**The codec boundary**: `decode()` hands the model object to the host codec
(`codecs.lookup(enc).decode(obj, errors)`), which reads its buffer; `bytes(s, enc)` takes
the codec's host bytes through `from_host()`.  Codecs are outside the described set
(`str` and `int` are host types a bytes model may use); only host `bytes`, `bytearray`
and `memoryview` are off limits.

**Delegation.**  A method still `...` calls the C on host copies of its arguments and
converts the result back (identity is kept for results that are arguments).  It is
circular by definition, reported by `model.check_circular()` and counted apart.

## 3. The proof: parity of the model

`./python Tools/clinic/pyspec_parity.py model [TYPES]` captures the C types and their
models in one process with the same probes (so the hash key is the same whatever
`PYTHONHASHSEED` is) and compares every line.  `pyspec_parity.py` gained a `convert` hook
on `TypeData` (samples and pool values pass through it) and a guard for a type that
cannot be subclassed; nothing else of the tool changed, and `capture`, `check`, `compare`
and the record are untouched.

**Excluded, with reasons** (`MODEL_EXCLUDED_SECTIONS`/`_KEYS`): the `type` section (flags,
sizes, MRO, module of a heap type), `help` (pydoc renders the type object), `C` (layout),
`pickle` (pickle and copyreg find the builtin by identity), `.__getattribute__`
(tp_getattro is in the PyTypeObject), `.__module__` (a heap type keeps it in its dict),
`sys.getsizeof()` (struct size), `copy.copy`/`deepcopy` (copy.py dispatches on the builtin
by identity): 889 lines.

**Limits of a Python class** (`MODEL_LIMITS`, counted as differing, reason printed):

| lines | where | why |
|---|---|---|
| 72 | explicit `b.__mul__(x)`, `b.__rmul__(x)` with a non-integer | a Python class has no `sq_repeat` apart from `nb_multiply`: the operator and `wrap_indexargfunc` are one method; the model gives the operator's error (`can't multiply sequence by non-int`), the explicit C call converts first (`'str' object cannot be interpreted as an integer`) |
| 26 | `bytes_iterator` `*=`, `del it[k]`, `it[2**100] = 1` | a heap type always has `tp_as_sequence`: `PyNumber_InPlaceMultiply()`, `PyObject_SetItem()`, `PyObject_DelItem()` take another path |
| 4 | `bytearray(b'ab') % b` | bytearray's `%` tests `PyBytes_Check()` on its operand (the builtin, by identity) |
| 1 | `weakref.ref(Sub(b))` | a subclass of a Python class gets `__weakref__`; of a variable-size C type it cannot |

**Result** (debug build, `pyspec_parity.py model`):

| | compared | identical |
|---|---|---|
| sections of methods with a Python body (65) | 25,686 | 25,614 (99.7 %; the 72 are the `__mul__` limit) |
| sections of delegated methods (`__mod__`, `__rmod__`) | 146 | 146 |
| protocols, calls of the type, iteration | 10,357 | 10,326 (99.7 %; the 31 are limits) |
| **all** | **36,189** | **36,086 (99.7 %)** |

Per section: every method section is 100 % identical except `.__mul__`/`.__rmul__`
(37/73 each, the rest limits): `__new__` 1990/1990, `count`/`find`/`index`/`rfind`/
`rindex`/`startswith`/`endswith` 1896/1896 each, `replace` 1903/1903, `hex` 745/745,
`center`/`ljust`/`rjust`/`split`/`rsplit`/`translate`/`decode` 700/700, `maketrans`
639/639, `fromhex` 64/64, the slots and ctype methods 19/19 or 73/73, `bytes_iterator`
methods 18/18 and `__setstate__` 42/42.  Protocols: `bytes ()` 1981/1981, `binary`
3988/3992, `inplace` 1200/1200, `subscript` 400/400, `contains` 100/100, `format`
100/100, `unary` 91/92; `bytes_iterator` `binary` 1676/1676, `inplace` 494/504,
`subscript` 152/168.  (`pyspec_parity.py model` prints the table; `--all` every line.)

`ModelTest` (`Lib/test/test_tools/test_pyspec_parity.py`) runs this comparison and fails
when a method or protocol with a Python body diverges for a reason not in `MODEL_LIMITS`
(checked by breaking `_Py_bytes_isspace`: the test names `call b''.isspace()`), when
another method becomes delegated, or when a body is circular.

What the probes do not reach: printf-style `%` with a format (the samples contain no `%`,
and adding samples would change the committed record), non-contiguous buffers, and the
one-byte singletons in paths the C builds with `PyBytes_FromStringAndSize(NULL, 1)` (not
observable through the probes; modelled anyway).

## 4. What changed

Commits (small, on the worktree branch):

1. `362ff499bb4` pyspec: `@native(facts=False)`, struct fields, machine primitives
   (`machine.py`, `runtime.native`, `frontend.is_pure_python()`/`is_literal_stub()`,
   class fields; `subset.py`/`facts.py`: a pure function in a reference is value code;
   `test_clinic`: `test_class_fields`, `test_pure_python_body`, `test_class_body`).
2. `c373dd7d417` bytes and bytes_iterator as pure Python: bodies in bytesobject.py,
   stringlib `ctype.py`/`transmogrify.py`; C-oriented references of bytes made
   non-circular (`_PyBytes_FromSize`, `_PyBytes_FromBuffer`, `_PyBytes_FromHex` (+
   `fromhex_items`), `bytes_copy`, `bytes_subtype_new`, the appender, `__len__`,
   `__getitem__`, `__buffer__`, `bytes_iterator.__next__`, `PyUnicode_AsEncodedString`)
   with their facts unchanged; new specs `Objects/pyspec/bytes_methods.py` (34 functions),
   `longobject.py`, `Python/pyspec/pyhash.py` (SipHash-1-3 as `pyhash.c`, key from
   `hash_secret()`, `sys.hash_info` checked), `pystrhex.py`.
3. `f81d865e969` the model and `pyspec_parity.py model`, `ModelTest`.
4. `b3f823cf5a9` tidy of the model; `399c2af5280` docs: this report, README.rst ("Pure
   Python", decorators, class fields), CONCEPT.md 7.3; a last commit adds the `model`
   command to the usage of pyspec_parity.py.

**Generated C**: clinic on the spec-backed files leaves every generated file identical to
the base except `Objects/clinic/bytesobject_pyspec.c.h`, where only the 23 `/*
Objects/pyspec/bytesobject.py:N */` comments change, because the bodies added lines above
the generated ones.  Keeping them fixed would mean keeping the bodies out of the class;
the traceability comments are meant to follow the spec.  The committed parity record is
unchanged.

**Validation** (`../build-p4-py`):

* `./python Tools/clinic/clinic.py <the 10 files of README.md "Resuming">`: tree clean
  (after the commit of the moved comments).
* `PYSPEC_PARITY_BASELINE=../build-str1-dbg/python ./python -m test test_clinic test_bytes
  test_mmap test_pyspec_facts test_pyspec_catalog test_tools.test_pyspec_parity
  test_opcache test_generated_cases`: all 8 OK (1,139 tests, 34 s; ModelTest is 4 of the 23 in
  test_pyspec_parity).
* `./python Tools/clinic/pyspec_review.py --baseline ../build-str1-dbg/python`: OK
  (behaviour: no difference in 87,737 lines vs the baseline; generated code up to date;
  ratchet unchanged).  The first run failed only on `test_class_body`, which expected a
  class-body annotation to be an error; fields are now allowed (the test now checks
  `center: int = 1`).

**Cost of running the model**: capture of bytes + bytes_iterator 1.0 s for the C, 3.1 s for
the model (debug build); single calls 100-900x slower than C (`find` 9 µs vs 0.08 µs,
`hash` 92 µs vs 0.1 µs).  Fine for tests; not a usable bytes.

## 5. Feasibility

**bytes: done, 65 of 67 members.**  `__mod__`/`__rmod__` (`_PyBytes_FormatEx`, ~600
lines of C) is the one piece left; it is ~200 lines of Python (numbers can use `str %`, a
host type), but the parity probes would not check it until the samples include format
strings, which changes the record.  The model's argument parsing, descriptors and
slot-wrapper models are generic (they read the spec), so the next type reuses them.

**bytearray** (58 own `...` methods + 27 shared): needs (a) a mutable storage primitive
(`ob_resize`, `ob_setitems`, and the `ob_exports` counter that makes resizing raise
`BufferError` while a view exists; `buffer_export` would have to hand out a view of the
live storage, e.g. a host `array` per object); (b) a fix to *sharing*: `strip =
critical_section(bytesobject.bytes.strip)` shares the declaration, not the C impl
(`bytearray_strip_impl` is its own), but the model would run bytes' body.  Either such
bodies move to templates (`B`, `STRINGLIB_NEW`, `STRINGLIB_MUTABLE`, as ctype and
transmogrify already are) or a sharing spec gives its own body; (c) `@critical_section` is
a no-op in the model: the model states single-threaded semantics; the free-threaded
guarantees (F1: `bytes(list)` snapshots a list of ints atomically) are properties of the
lowering, checked by the C tests, not by the model.  Estimate: 85-90 % of bytearray's
lines reachable the same way; the rest are the same limits plus buffer-export identity.

**mmap**: the behaviour is the OS's (`mmap(2)`, `msync`, `madvise`, file sizes, access
modes).  A pure-Python mmap would be protocol logic (bounds, the position, slicing,
`find`, `read`/`write`/`seek`, closed and exported states) over one more primitive, "mapped
memory" (open, read, write, resize, flush), which on the host *is* the host mmap.  Perhaps
half of its parity lines are protocol logic; the rest is the primitive.  Not "100 %
Python" in any useful sense, but the same shape as bytes.

**stringlib**: `ctype.py` and `transmogrify.py` are fully pure; the search, split,
partition, join, replace and count algorithms are pure (semantics, not fastsearch's
algorithm: the lowering is free to be faster).

**Hard cases, and how the prototype handles them**:

* Identity (`bytes(b) is b`, `b[:] is b`, `b.strip() is b`, the empty and one-byte
  singletons): expressible, and in the bodies (`return self`, `new_bytes()`); all identity
  lines agree.
* Error messages naming C details: they are part of the behaviour; the model reproduces
  them (`%T` -> `fqname()`, `%.200s` of `tp_name` -> `tp_name()`, clinic's parsers,
  descriptor and slot-wrapper messages, the debug-build codec check).  The C-shaped ones
  are part of the definition (the Python says `tp_name`, not `__qualname__`).
* `sys.getsizeof`, type flags, the MRO, `help()`: the PyTypeObject, excluded.
* The buffer protocol from Python: PEP 688 `__buffer__` makes a model exporter and lets
  host C read model objects; the export is a view of a copy (its `.obj` is not the model
  object) and flags beyond `PyBUF_WRITABLE` are not modelled.
* Free threading, critical sections: outside the model (above).
* Dispatch a Python class cannot express: `sq_repeat` without `nb_multiply`,
  `tp_as_sequence` NULL; the model uses `has_slot()` where it can (`n * b` where `n`
  repeats) and lists the rest as limits.
* Host code testing builtin identity (pickle, copy, `bytearray %`): excluded or limits;
  a real implementation in another VM would be the builtin itself, so these vanish there.
* Speed: 2-3x for a parity run; irrelevant for tests, disqualifying for use.

**What the tool needs next**:

1. A non-circularity checker in the test suite (exists: `model.check_circular()`, static:
   calls and attribute reads of described host types, plus delegated methods; bytes
   literals are the model's).  Next: run it over every spec, and a dynamic check (the
   model with host `bytes`/`bytearray` constructors unreachable).
2. Merge `@native(facts=False)` into `@native` where facts are wanted: gate call-table
   slot entries on a consumer (`SLOT_USES`) instead of on "has a reference", teach the C
   checker clinic methods (`<c_name>_impl`), and let `HelperTest` call methods.  Then the
   pure body *is* the reference, and its effects (`calls()`, `runs_python()`) must be
   written where they happen, which the checker enforces.
3. Template-or-own bodies for shared declarations (bytearray).
4. Format-string samples in the parity data (a record update, on purpose) for `%`.

## 6. PEP 399 and Rust

PEP 399 pairs (`bisect`/`_bisect`, `heapq`, `datetime`, `json`) have two independent
implementations and one test suite run against both.  This prototype shows the other
direction for builtins: one Python source that *is* the implementation (a model any VM
could run, given the machine primitives and a descriptor/argument-parsing runtime), with C
as its lowering, and a mechanical equivalence check (the parity tool) in place of "the
same tests against both".  For a stdlib pair the machine primitives mostly vanish (the
pure module already runs on any VM), so the spec could be `Lib/bisect.py` itself with
`_bisect.c` as `@native` lowering, checked by the same model comparison.  What a pure
spec does not give a PEP 399 module: a runnable module without this repository's model
runtime (`model.py` stands in for `descrobject.c`/clinic's parsing); for builtins, other VMs
already have their own object model, so the bodies, not the runtime, are what they could
reuse.

For Rust the pure body is the contract a native function is checked against, exactly as
for C: a Rust `bytes.split` would be `@native` with the same Python body, the parity model
comparison and `HelperTest` would run unchanged, and the machine primitives are the list of
object-layout operations a Rust implementation must provide through the C API
(`PyBytes_AS_STRING`, `tp_alloc`, `PyObject_GetBuffer`).  Nothing in the model is C-specific.

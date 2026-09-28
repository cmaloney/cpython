# Specs for C types: one Python-syntax contract that Argument Clinic reads

*Draft for discussion (discuss.python.org, Core Development), not a PEP.  It describes a
working experiment on the branch `exp/ac_python_overloads_v0` (at `63ce50f2c9b`, based on
main `ee1bbf037ff`), where `bytes`, `bytearray` and `mmap`'s methods are migrated.  Paths
are relative to the repository root.  Every number says where it comes from: a report of
the experiment (`pyspec-notes/reports/…`) or a command run on the branch.*

## In short

- Each C file that defines types gets a **spec**: a Python file, written like a typeshed
  stub, next to it (`Objects/pyspec/bytesobject.py` for `Objects/bytesobject.c`).
  **Argument Clinic reads it**; `make clinic` stays the only generator.
- The spec is the **language-neutral contract** of the file: signatures, docstrings, the
  slots of each type, and optionally the semantics of a function as a Python body.
  Facts the optimizer needs (exact result type, "returns its argument", "runs no Python
  code") are **derived from bodies**, not written by hand.
- An implementation is either **generated from a body** or **written natively** (C today;
  in principle Rust later) and **checked against the body**, which is then its *reference*
  and is never compiled.
- Correctness has one command for a reviewer (`Tools/clinic/pyspec_review.py`): a
  differential test of the spec against the interpreter, a committed behaviour record of
  every spec'd type, facts asserted at run time in debug builds, and a ratchet over every
  hand-written description of the C API.
- On `bytes`, every measured `bytes()` construction, `b[i]` and iteration shape runs
  fewer instructions than main under PGO+LTO (other methods: unchanged within build
  noise), the generated argument parsing is byte-identical to main except
  `bytes.__new__`, and 87,737 probed lines of observable behaviour are identical to main.

## 1. The problem

What CPython says about one C function lives in many places, written by hand:

| fact about `bytes` | where it is written on main |
|---|---|
| signature, docstring | clinic block in `Objects/bytesobject.c` |
| method table, `tp_as_*` tables, type docstring | hand-written C next to `PyBytes_Type` |
| user documentation | `Doc/builtins/stdtypes.rst`, `Doc/builtins/functions.rst` |
| C API contract | `Doc/c-api/bytes.rst`, `Doc/data/refcounts.dat`, `threadsafety.dat`, `Misc/stable_abi.toml` |
| static types | typeshed's `builtins.pyi` |
| what the specializer/JIT may assume | hand-written in `Python/optimizer_bytecodes.c` |

They drift.  A read of the four descriptions of `bytes` alone (`reports/ws9.md`) found
14 inaccuracies: a docstring that says `prefix` in `removesuffix`, docs that say
`count`'s range is closed, a C API page that says `PyBytes_FromObject` takes only
buffers, typeshed signatures that reject valid calls, and seven methods whose bracket
`@text_signature` hides them from `inspect` and from typeshed's stubtest.  The
optimizer's facts drift too, and there it is a memory-safety problem: `_CALL_STR_1`
recorded `str(x)` as an exact `str`, but `__str__` may return a subclass, and the
narrowed `POP_TOP` then freed it as an exact `str` (use-after-free; a fix is ready,
`drafts/call-str-1-UPSTREAM.md`).  Nothing ties those facts to the code they describe.

## 2. The idea, on `bytes`

The spec is ordinary Python.  A method with body `...` is implemented in C by hand,
exactly as with plain Argument Clinic; its parameters are clinic's, with the converter
as the annotation:

```python
class bytes:
    @permit_long_summary
    def rsplit(self, sep: object = None, maxsplit: Py_ssize_t = -1):
        """Return a list of the sections in the bytes, using sep as the delimiter.
        ...
        """
        ...
```

`bytesobject.c` keeps a one-line clinic block (`bytes.rsplit`) above the hand-written
impl; clinic writes the impl head and `Objects/clinic/bytesobject.c.h`, byte for byte what
the full block gave.  Slots are dunders (`def __len__(self, /): ...`), so clinic also
generates the method table and the `tp_as_*` sub-tables.

A function can also have a **body**.  `bytes.__new__` is written as the Python
equivalent of main's C (abridged; `Objects/pyspec/bytesobject.py`):

```python
    def __new__(cls, source: object = NULL, encoding: str = NULL, errors: str = NULL):
        if cls is not bytes:
            value = bytes.__new__(bytes, source, encoding, errors)
            return bytes_subtype_new(cls, value)
        if source is NULL:
            ...
            return b""
        ...
        if type(source) is bytes:
            return source
        if type(source) is not int:
            if (func := _PyObject_LookupSpecial(source, "__bytes__")) is not NULL:
                ...
        if hasattr(type(source), "__index__"):
            try:
                size = PyNumber_AsSsize_t_fast(source, OverflowError)
            except TypeError:
                return PyBytes_FromObject(source)
            ...
            return _PyBytes_FromSize(size, True)
        return PyBytes_FromObject(source)
```

The C functions it calls are called by name.  Each is declared, once, in the spec of
the file that defines it, as **`@native`**: the C is the authority, and the body is its
**Python reference**, never compiled, which describes it:

```python
@native
def _PyBytes_FromBuffer(x: object):
    """A copy of the buffer of x (in C order)."""
    calls(x, "__buffer__")
    calls(x, "__release_buffer__")
    return exact(bytes, memoryview(x).tobytes())
```

Four primitives say what plain Python cannot: `exact(T, v)` (a new object of exactly
type `T`), `unknown(v)`, `calls(x, "__slot__")` (the C invokes that special method of
`type(x)`: Python runs only if it is Python code) and `runs_python()`.  From bodies and
references clinic derives, per call shape, the exact result type, aliasing, constants,
whether the call can raise and whether it may run Python code.

Where generated code has a cheaper way to a native function's result for some
arguments, that fast path is written once, as an **`@inline`** function next to the
native function; it is generated into its callers and never assumed to exist in the C:

```python
@inline
def PyNumber_AsSsize_t_fast(o: object, exc: object) -> Py_ssize_t:
    if (type(o) is int or type(o) is bool) and _PyLong_IsCompact(o):
        return _PyLong_CompactValue(o)
    return PyNumber_AsSsize_t(o, exc)
```

The **spec language** accepts any Python (keyword-only parameters, any default,
`*args`, `while`, anything).  Only a documented subset is **lowered** to C; everything
else is analysed as worst case and reported, where lowering is asked for, as
"expressible, but not lowered to C yet" (one module decides: `Tools/clinic/libclinic/pyspec/subset.py`).

## 3. What is generated, what stays hand-written

| generated by clinic from the spec | stays hand-written |
|---|---|
| argument parsing (`clinic/bytesobject.c.h`), as today | the `PyTypeObject` structs (they name the generated tables) |
| `bytes_doc`, `bytes_methods[]`, `bytes_as_number/sequence/mapping/buffer` | every `@native` function, and every method whose body is `...` |
| the C of each body (`bytes_new_impl`, `PyBytes_FromObject`, `bytes.__bytes__`, `bytes.fromhex`), with per-arity entries `bytes_new_nargsN()` and per-type specializations (`bytes_from_iterator_list` for an exact list, in its critical section) | the specialized uops (`BINARY_OP_SUBSCR_BYTES_INT`, `FOR_ITER_BYTES`): the spec gives their result facts, not their code |
| the tier-2 **call table** of each class, and one registry of them in `Include/internal/pycore_pyspec.h` | the optimizer code that reads the table (`Python/optimizer_analysis.c`) |

The generated C reads like hand-written C and names the spec line of each group of
statements (`/* Objects/pyspec/bytesobject.py:616 */`).  A call-table entry carries its
derived facts, for example:

```c
/* bytes(bytes): result is argument 0 (source); result is exactly bytes; runs no Python code */
/* bytes(list): result is exactly bytes; may run Python code */
```

The tier-2 optimizer uses them in `_CALL_BUILTIN_CLASS` (a direct C call, a folded
constant, `bytes(b)` replaced by `b`, a result type that removes later guards) and in
`_CALL_METHOD_DESCRIPTOR_NOARGS`, and takes the result facts of the slot uops from the
spec (`_PySpec_FindSlot`).

## 4. Two ways code moves

1. **Generated from a body.**  The body is the implementation; clinic partially
   evaluates it for the facts of each entry (arity, exact argument type), lowers it to a
   small typed form (`ir.py`: ownership, error conventions, loops) and writes C
   (`c_backend.CBackend`).  The body also runs as Python in the tests.
2. **Native.**  The implementation is written by hand; the body is its reference.  The
   reference is checked against the native code in two ways: dynamically (the native
   function is called with the inputs of the spec's test data and compared with the
   reference) and statically, by a **checker of the native code's language**: every
   call that may run Python code must be accounted for by the reference, and the native
   functions the reference calls must be the ones the code calls.  For C, the checker
   reuses the lexer and escape analysis of the cases generator
   (`Tools/cases_generator/`).  Checkers are registered by file extension
   (`NATIVE_CHECKERS` in `disconnects.py`), so native code in another language needs
   its own checker and nothing else changes: callers reach it through its C interface.

Moving a function between the two is a local change to the spec: drop `@native` and
delete the C (generated from then on), or add `@native` and write the C (native from then
on).  Section 7 describes both directions, and Rust.

## 5. How correctness is guaranteed

| question | mechanism | command |
|---|---|---|
| Does the spec mean what the interpreter does? | **difftest**: each spec body runs as Python on the cases of `<stem>_cases.py` and must give the interpreter's result or exception (message included) | `./python -m test test_clinic` |
| Did any observable behaviour change? | **parity record**: probes of every method, arity, keyword, argument pool, operator, pickling… of each spec'd type, stored as one digest per section per build configuration (`Tools/clinic/pyspec-baseline/parity.txt`) | `./python Tools/clinic/pyspec_parity.py check` (or `compare ../main/python` for every line) |
| Are the derived facts sound? | every call-table entry and native function is called directly against the interpreter and its reference; **debug builds assert the facts** at run time (`_ASSERT_RESULT_TYPE`/`_ASSERT_RESULT_IS` after each call the optimizer typed, and a tripwire that aborts if Python code starts inside a call said to run none) | `./python -m test test_pyspec_facts` |
| Does a reference describe its C? | the C checker above | `./python -m test test_pyspec_catalog` (`c_calls`) |
| Do the hand-written descriptions agree with the code? | **ratchet** per dimension (C API vs docs, `refcounts.dat`, `threadsafety.dat`; docs signatures; slots vs `typeobj.rst`; duplicated docstrings; optionally typeshed); baselines may only shrink | `./python -m test test_pyspec_catalog` |
| Is generated code up to date, and what differs from main? | clinic `--dry-run`, and a diff of every clinic output against the merge base, each difference explained by the type's data | all of the above in one summary: `./python Tools/clinic/pyspec_review.py` |

The review on the branch against main (run for this document, debug JIT build, about
20 seconds; `--baseline` names a debug build of main):

```
- Behaviour: same as Tools/clinic/pyspec-baseline/parity.txt for bytearray, bytearray_iterator,
  bytes, bytes_iterator, mmap (87,737 lines in 251 sections)
  - vs .../build-str1-dbg/python: no difference in 87,737 lines
- Generated code: up to date (clinic --dry-run on 10 C files of specs)
  - Objects/clinic/bytesobject.c.h: +94/-9 lines, in bytes_new_impl, bytes_new, ... (on purpose:
    bytes.__new__ has a spec body)
  - every other clinic output: identical to the base
- Specs vs interpreter: passed, 509 tests
- Facts: passed, 21 tests; debug build: facts also asserted at run time
- Ratchet: passed; c_calls 0, capi 20, docs 0, docstrings 2, slots 3
Result: OK
```

The debug assertions have caught real errors: a deliberately wrong fact
(`exact(bool, …)` in `bytes.__getitem__`'s reference) aborts with "the tier-2
optimizer's exact result type is wrong" (`reports/phase3a_slot_specializations.md`).

## 6. Measured results

**Micro benchmarks** (`reports/phase4_P.md`): PGO+LTO release JIT builds, one compiler
(clang 21), `Tools/clinic/pyspec_bench.py`, instructions / minimum cycles per
iteration including the loop, `PYTHONHASHSEED=1` (a missing-method lookup's cost depends
on the hash seed since the per-type method cache; deltas were checked at seeds 0–7).
main = `ee1bbf037ff`, branch = `edd5f1f6cfd`.

| shape | JIT on: main → branch | JIT off: main → branch |
|---|---|---|
| `bytes(16)` | 911/171 → 447/98 | 912/167 → 602/117 |
| `bytes(ix)` (an `__index__` object) | 1458/288 → 1118/242 | 1367/270 → 1142/233 |
| `bytes(iter(l16))` | 3191/660 → 2349/486 | 3250/675 → 2487/504 |
| `bytes(range(256))` | 25573/5150 → 16710/3255 | 25563 → 16916 |
| `Sub(16)` (a `bytes` subclass) | 1318/262 → 1278/251 | 1296/259 → 1254/241 |
| `Sub(b16)` | 1316 → 1044 | 1292 → 1025 |
| `Sub(l16)` | 1745 → 1732 | 1720 → 1706 |
| `b16[i]` | 304/60 → 206/41 | 315 → 218 |
| `for c in b16` | 1652/334 → 1110/205 | 1454 → 1163 |
| the other 29 `bytes()` shapes | −25 to −76 % | −11 to −59 % |

A/A noise between two builds of one commit: ±9 instructions, ±3 % cycles.  The
`@inline` fast paths cost 6–11 instructions on the shapes where their test fails
(0.04–0.8 %, within noise) and save 30 where it succeeds; no "must inline" marker was
needed.  `Sub(l16)` is the thinnest margin (−0.1 to −1.1 % across seeds).  The last
change of the generated code (`ec33bf398b0`: a subclass's `__new__` calls the arity
entry instead of the whole impl) came after these measurements and was not re-measured
under PGO+LTO.

**End to end** (`reports/phase3a_slot_specializations.md`, `reports/ws6.md`): `bytes`
calls are under 1 % of every pyperformance benchmark, and pyperformance shows no
bytes-attributable change.  The slot facts made `b[i]` and `for c in b` specializable;
pyflate runs 3.1 % fewer instructions and 1.2–2.2 % fewer cycles under `perf stat`,
about −0.4 % wall clock, inside pyperformance's A/A noise.  Startup is unchanged.

**Parity with main** (run for this document): the 5 spec'd types behave identically
to main in 87,737 probed lines (debug build); `bytearrayobject.c.h`, `transmogrify.h.h`
and `mmapmodule.c.h` are byte-identical to main; `bytesobject.c.h` differs only in
`bytes.__new__`, whose vectorcall is now generated.

**Free-threaded** (`reports/phase4_E.md`): the test suites pass on a free-threaded debug
build, whose parity block matches main's; `bytes(list)` keeps main's atomic snapshot of
an all-int list (the loop is derived, run in the list's critical section, and restarts
on the generic path if an item could run Python code).

**Code**: `bytesobject.c` −717/+256 lines, `bytearrayobject.c` −751/+117 against main
(signatures, docstrings and tables moved to specs); bytes' machine code was +1.3 KB
against main at `reports/phase1_A.md` (mostly clinic's generic vectorcall).

## 7. Moving code

### 7.1 Existing C to a spec (exists)

Five levels, each its own small PR, one C file per PR (`Objects/pyspec/MIGRATING.rst`):

| level | what moves | validated by |
|---|---|---|
| 1 | signatures and docstrings into the spec; one-line blocks in C | `clinic/foo.c.h` byte-identical |
| 2 | method and slot tables, the type docstring | parity record unchanged |
| 3 | function internals: spec bodies, `@native` references, `@inline` fast paths | parity unchanged, difftest, `HELPERS` checks, `c_calls` ratchet, instruction counts (keep in C when nothing improves) |
| 4 | facts for the specializer/JIT | a consumer and its `test_opt` test in the same PR; debug assertions |
| 5 | C API facts | the ratchet: record today's disconnects, then fix docs and delete lines |

Adding the next type is data: a spec, a `<stem>_cases.py` (the type in `TYPES`, cases,
native-function inputs), the parity record captured **before** the migration (ideally in
its own PR, so main's CI checks it), and regenerated clinic output.  No interpreter C,
test class or tool code names a type.  Level 3 is optional and decided with numbers: the
guide's worked example (`bytes.removeprefix`) measured −0.5 to −4 % and was **kept in C**,
because half of that came from a converter change plain C can make too.

### 7.2 A native implementation in Rust (proposed, not implemented)

What the spec already gives any implementation language, unchanged:

- the signature (clinic still generates the argument parsing and the entry the method
  table names), the docstring and the slot it fills;
- the reference, which the difftest runs as Python, and from which callers derive facts;
- the test data (`HELPERS`), the parity record and the review.

What a Rust native function would need, per `Objects/pyspec/README.rst`:

| piece | status |
|---|---|
| the function exported with the C signature the spec declares (`extern "C"`), linked into libpython | proposed (depends on CPython's Rust build support) |
| a checker: a `NativeChecker` subclass registered for `.rs` in `NATIVE_CHECKERS`, giving the code of a function, the calls it makes, which calls may run Python code, which are audited to run none, and which special method a call runs | interface exists (the C checker implements it); no Rust checker |
| a ratchet dimension next to `c_calls` | proposed |
| the call from `test_pyspec_facts` (`HelperTest`) through the C interface, compared with the reference | exists, language-neutral |
| the parity record and the difftest | exist, language-neutral |

For bodies *generated* in Rust instead of C, the seam is the backend: everything up to
the lowered form (`ir.py`: locals' types, ownership, each call's error check, loops)
is language-neutral, and a Rust backend would implement `CBackend`'s methods (functions
with a C signature, type checks, reference counts, index loops, critical sections, type
names).  The call tables stay C data of the interpreter.  This is a design, checked only
against the C backend's interface.

## 8. Costs and open questions

- **Tool size.**  `Tools/clinic/libclinic/pyspec/` is 7,794 lines (5,610 lines of code)
  (front end, lowered-subset check, facts, partial evaluator, emitter, C backend, call
  tables, tables of types, disconnect checks), plus `pyspec_parity.py` (1,459),
  `pyspec_review.py` (390) and `pyspec_bench.py` (155); tests add about 4,200 lines.
  The partial evaluator is most of the cost of level 3; levels 1, 2 and 5 need little
  of it.
- **The committed parity record churns.**  One digest per section per configuration
  (26 KB for three configurations) keeps reviewers from needing a build of main, but an
  unrelated change on main (a docstring inherited in `help()`, another type's error
  message) changes a section and must be re-recorded; only Linux 64-bit blocks exist,
  and other configurations skip the check.
- **Not lowered yet**: keyword-only parameters, defaults other than `NULL`, converters
  other than `object`/`str`, `while`, `__init__`, `@critical_section` on a generated
  method.  Not expressible in a spec at all: optional groups, deprecation markers,
  module-level functions (they stay plain clinic).
- **Few consumers.**  The optimizer reads the call table in two uops and slot facts in
  two; the facts of `METH_O`/`METH_FASTCALL` methods are generated but unread.  The
  specialized uops themselves stay hand-written copies of the slot's C, tied to the spec
  by tests and assertions.
- **Checks with stated assumptions.**  The C checker works per function, not per path,
  and treats a reference release as running no Python code (the debug tripwire makes the
  same assumption).
- **Rust** is a design: interfaces exist, no Rust code or checker does.
- **Measurement noise.**  PGO builds of one commit differ by 1–3 % on unrelated shapes;
  results depend on the hash seed.  Claims above are instruction counts with A/A pairs.

Questions for the community:

1. Is a per-file Python spec read by Argument Clinic an acceptable home for signatures
   and docstrings (levels 1–2), independent of everything else?
2. Should the specializer's facts about builtins come from a derived table, with debug
   assertions, rather than from hand-written cases in `optimizer_bytecodes.c`?
3. Is a disconnect ratchet over `Doc/c-api`, `refcounts.dat` and `threadsafety.dat`
   wanted in the test suite?
4. Is a committed behaviour record the right review aid for migrations, or should parity
   be checked only against a build of the base?
5. For Rust: is "the spec is the contract, a per-language checker validates native code
   against its reference" the right shape for mixing languages inside one type?

## 9. The incremental path

Each level is useful without the next:

- **Independent of specs**: the `_CALL_STR_1` fix and the `_pylong` exact-`str` fix; the
  WS9 doc, docstring and typeshed fixes; debug-build result assertions for existing
  optimizer facts; the `BINARY_OP_SUBSCR_BYTES_INT`/`FOR_ITER_BYTES` specializations.
- **Level 1–2** (clinic reads specs; tables generated): no interpreter change, output
  byte-identical, reviewed with the parity record.
- **Level 5** (the ratchet): needs only level 1 specs.
- **Levels 3–4** (bodies, call tables, tier-2 consumers): the part that needs the
  partial evaluator; one type at a time, with numbers.

The proposed order of small PRs, with files, dependencies and what reviewers check, is
in `pyspec-notes/drafts/PR_SERIES.md`.  The contributor reference is
`Objects/pyspec/README.rst`; the migration procedure is `Objects/pyspec/MIGRATING.rst`.

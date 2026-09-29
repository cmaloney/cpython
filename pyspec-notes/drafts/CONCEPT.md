# Specs for C types: one Python-syntax contract that Argument Clinic reads

*Draft for discussion (discuss.python.org, Core Development), not a PEP.  It describes a
working experiment on the branch `exp/ac_python_overloads_v0` at `c9d7955088f`, based on
main `ee1bbf037ff`, where `bytes`, `bytearray` and `mmap`'s methods are migrated.  Paths
are relative to the repository root.  Every number below gives the commit it was measured
at and how; the full tables and the details are in the appendices, so the
sections above them can be read on their own.  Commands shown with their output were
run for this document at `c9d7955088f` on a debug build with the JIT
(`--with-pydebug --enable-experimental-jit`, clang 21).*

## In short

- Each C file that defines types gets a **spec**: a Python file, written like a typeshed
  stub, next to it (`Objects/pyspec/bytesobject.py` for `Objects/bytesobject.c`).
  **Argument Clinic reads it**; `make clinic` stays the only generator.
- The spec is the **language-neutral contract** of the file: signatures, docstrings, the
  slots of each type, and optionally the semantics of a function as a Python body.
  The **facts** the optimizer needs (exact result type, "returns its argument", "runs no
  Python code") are **derived from bodies**, not written by hand.
- An implementation is either **generated from a body** or **written natively** (C today;
  in principle Rust later) and **checked against the body**, which is then its *reference*
  and is never compiled.
- For `bytes` the bodies go all the way: every method but printf-style `%` has a
  pure-Python body, and the spec run as Python classes agrees with the C type on 99.7 %
  of 36,189 probed lines, without calling the builtin `bytes` (section 7).
- On `bytes`, every measured `bytes()` construction, `b[i]` and iteration shape runs
  fewer instructions than main under PGO+LTO (other methods: unchanged within the noise
  between two builds of one commit); the generated argument parsing is byte-identical to
  main except `bytes.__new__`; and 87,737 probed lines of observable behaviour are
  identical to main.

## What is asked

A trial of **levels 1 and 2** (below) on two files, `Modules/mmapmodule.c` and
`Objects/bytesobject.c`: Argument Clinic reads signatures and docstrings from a spec and
generates the method and slot tables; the output is byte-identical, no interpreter C
changes, and the review is one command.  The later levels are separate decisions, each
with its own numbers.  The questions for the community are in section 10.

| level | what moves into the spec | validated by |
|---|---|---|
| 1 | signatures and docstrings; one-line clinic blocks stay in C | `clinic/foo.c.h` byte-identical |
| 2 | method and slot tables, the type docstring | parity record unchanged |
| 3 | function internals: spec bodies, `@native` references, `@inline` fast paths | parity unchanged, difftest, native checks, instruction counts (keep in C when nothing improves) |
| 4 | facts for the specializer/JIT | a consumer and its `test_opt` test in the same PR; debug assertions |
| 5 | C API facts | the ratchet: record today's disconnects, then fix docs and delete lines |

## Terms

- **spec**: the Python file `<dir>/pyspec/<stem>.py` of `<dir>/<stem>.c` (or `.h`).
- **lowered**: generated as C by clinic.  The spec language accepts any Python; one
  module (`Tools/clinic/libclinic/pyspec/subset.py`) says which part is lowered.
- **`@native` / reference**: a function written by hand in C; its Python body (the
  *reference*) describes it and is never compiled.
- **facts**: what the optimizer may assume about a call: exact result type, alias of an
  argument, constant result, can raise, may run Python code.
- **call shape**: a call with a given number of arguments and known exact argument types
  (`bytes(list)`); the **call table** of a class has an entry per call shape clinic
  specializes, with its facts.
- **residual**: the copy of a body that partial evaluation leaves for one call shape, with
  the branches the shape decides removed; it is what clinic lowers for that entry.
- **difftest**: each spec body run as Python on test cases, compared with the interpreter.
- **parity record**: a digest per section of everything observable about each spec'd type,
  committed so a review needs no build of main.
- **disconnect / ratchet**: a disagreement between a hand-written description of the C API
  (docs, `refcounts.dat`, ...) and the code; the ratchet is a committed list of them that
  may only shrink.
- **model**: the spec run as Python classes in place of the C type (section 7).

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

They drift.  A read of the four descriptions of `bytes` alone found 14 inaccuracies: a
docstring that says `prefix` in `removesuffix`, docs that say `count`'s range is closed, a
C API page that says `PyBytes_FromObject` takes only buffers, typeshed signatures that
reject valid calls, and seven methods whose bracket `@text_signature` hides them from
`inspect` and from typeshed's stubtest.  The optimizer's facts drift too, and there it is
a memory-safety problem: `_CALL_STR_1` recorded `str(x)` as an exact `str`, but `__str__`
may return a subclass, and the narrowed `POP_TOP` then freed it as an exact `str`
(use-after-free on main and 3.15; a fix and its issue text are ready, not yet filed).
Nothing ties those facts to the code they describe.

## 2. The idea, on `bytes`

The spec is ordinary Python.  A method with body `...` is implemented in C by hand,
exactly as with plain Argument Clinic; its parameters are clinic's, with the converter
as the annotation (`Objects/pyspec/bytearrayobject.py`):

```python
class bytearray:
    @permit_long_summary
    @critical_section
    def rsplit(self, sep: object = None, maxsplit: Py_ssize_t = -1):
        """Return a list of the sections in the bytearray, using sep as the delimiter.
        ...
        """
        ...
```

`bytearrayobject.c` keeps a one-line clinic block (`bytearray.rsplit`) above the
hand-written impl; clinic writes the impl head and `Objects/clinic/bytearrayobject.c.h`,
byte for byte what the full block gave.  Slots are dunders (`def __len__(self, /): ...`),
so clinic also generates the method table and the `tp_as_*` sub-tables.

A function can also have a **body** that clinic lowers.  `bytes.__new__` is written as the
Python equivalent of main's C (abridged; `Objects/pyspec/bytesobject.py`):

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

These are C semantics in Python syntax: `NULL` is C's absent value, `is NULL` its test,
and the C functions it calls are called by name.  Each is declared, once, in the spec of
the file that defines it, as **`@native`**: the C is the authority, and the body is its
**Python reference**, never compiled, which describes it:

```python
@native
def _PyBytes_FromBuffer(x: object):
    """A copy of the buffer of x (in C order)."""
    calls(x, "__buffer__")
    calls(x, "__release_buffer__")
    return exact(bytes, new_bytes(buffer_items(x)))
```

Four primitives (`exact`, `unknown`, `calls`, `runs_python`) say what plain Python cannot,
and from bodies and references clinic derives, per call shape, the exact result type,
aliasing, constants, whether the call can raise and whether it may run Python code.  A
fast path that generated code may take is written once as an **`@inline`** function next
to the native one.  The spec language accepts any Python; only a documented subset is
lowered to C, and the rest is analysed as worst case (appendix D has the primitives,
`@inline` and the subset).

## 3. What is generated, what stays hand-written

| generated by clinic from the spec | stays hand-written |
|---|---|
| argument parsing (`clinic/bytesobject.c.h`), as today | the `PyTypeObject` structs (they name the generated tables) |
| `bytes_doc`, `bytes_methods[]`, `bytes_as_number/sequence/mapping/buffer` | every `@native` function, and every method whose body is `...` or pure Python only the model runs (section 7) |
| the C of each lowered body (`bytes_new_impl`, `PyBytes_FromObject`, `bytes.__bytes__`, `bytes.fromhex`), with per-arity entries `bytes_new_nargsN()` and per-type specializations (`bytes_from_iterator_list` for an exact list, in its critical section) | the specialized uops (`BINARY_OP_SUBSCR_BYTES_INT`, `FOR_ITER_BYTES`): the spec gives their result facts, not their code |
| the tier-2 **call table** of each class, and the registry of them, `Include/internal/pycore_pyspec_registry.h` (a generated header) | the lookup and the optimizer code that reads the tables (`Include/internal/pycore_pyspec.h`, `Python/optimizer_analysis.c`) |

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
   evaluates it for each call shape, lowers the residual to a small typed form (`ir.py`)
   and writes C (`c_backend.CBackend`).  The body also runs as Python in the tests.
2. **Native.**  The implementation is written by hand; the body is its reference,
   checked against the native code dynamically (called on the spec's test data and
   compared) and statically by a checker of the native code's language (every call that
   may run Python code must be accounted for by the reference).  The C checker reuses the
   cases generator's lexer and escape analysis; checkers are registered per language
   (appendix D).

Moving a function between the two is a local change to the spec: drop `@native` and
delete the C, or add `@native` and write the C.

## 5. How correctness is checked

| question | mechanism | command |
|---|---|---|
| Does the spec mean what the interpreter does? | **difftest**: each spec body runs as Python on the cases of `<stem>_cases.py` and must give the interpreter's result or exception (message included) | `./python -m test test_clinic` |
| Did any observable behaviour change? | **parity record**: probes of every method, arity, keyword, argument pool, operator, pickling… of each spec'd type, stored as one digest per section per build configuration (`Tools/clinic/pyspec-baseline/parity.txt`) | `./python Tools/clinic/pyspec_parity.py check` (or `compare ../build-main/python` for every line) |
| Is the spec's Python, run on its own, the type? | the **model** comparison (section 7): the spec run as Python classes against the C type, with checks that no body uses the builtin | `./python Tools/clinic/pyspec_parity.py model` |
| Are the derived facts sound? | every call-table entry and native function is called directly against the interpreter and its reference; in **debug builds with the tier-2 optimizer on**, optimized traces assert the facts at run time (`_ASSERT_RESULT_TYPE`/`_ASSERT_RESULT_IS` after each call the optimizer typed, and a tripwire that aborts if Python code starts inside a call said to run none) | `./python -m test test_pyspec_facts` |
| Does a reference describe its C? | the C checker above | `./python -m test test_pyspec_catalog` (`c_calls`) |
| Do the hand-written descriptions agree with the code? | **ratchet** per dimension (C API vs docs, `refcounts.dat`, `threadsafety.dat`; docs signatures; slots vs `typeobj.rst`; duplicated docstrings; optionally typeshed); baselines may only shrink | `./python -m test test_pyspec_catalog` |
| Is generated code up to date, and what differs from main? | clinic `--dry-run`, and a diff of every clinic output against the merge base, each difference explained by the type's data (an unexplained one fails) | all of the above in one summary: `./python Tools/clinic/pyspec_review.py` |

In one line: the review runs all of it in about 25 seconds and prints a summary to paste
into a PR; at the tip it reports behaviour identical to main in 87,737 probed lines and
generated code up to date.  The checks have limits (the difftest runs on CPython, the
probes cover what they probe, the fact assertions need a debug build with tier 2 on);
appendix B lists them and shows the review's output.

## 6. Measured results

**Where the speed comes from** (appendix A has the attribution table): the whole
JIT-off gain of `bytes()` is a generated `tp_vectorcall` and per-arity entries, which a
hand-written vectorcall would give too; with the JIT on, the call-table facts add a
direct call of the per-type entry, `bytes(b)` replaced by `b`, `bytes()` folded to a
constant, and "runs no Python code"; loops over lists, tuples, ranges and iterators come
from one body; `b[i]` and `for c in b` are new specializations whose result facts come
from the spec.  The facts could also be written by hand in `optimizer_bytecodes.c`; what
the spec adds is that they are derived from the code and asserted.

**Micro benchmarks** (PGO+LTO release JIT builds, clang 21, instructions/cycles per
iteration, `PYTHONHASHSEED=1`, main `ee1bbf037ff` → branch `737069ca773`; method and all
40 statements in appendix A):

| shape | JIT on: main → branch | JIT off: main → branch |
|---|---|---|
| `bytes(16)` | 911/171 → 445/97 | 912/167 → 606/117 |
| `bytes(l256)` (a list) | 6845/1220 → 5123/860 | 6840/1218 → 5341/893 |
| `Sub(l16)` (a `bytes` subclass; the thinnest margin) | 1748/344 → 1714/337 | 1715/344 → 1691/334 |
| `b16[i]` | 306/60 → 207/41 | 315/59 → 220/41 |
| `for c in b16: pass` | 1652/333 → 1109/205 | 1454/371 → 1165/308 |

Every `bytes()` shape is 11–77 % below main; no shape is above main by more than the
difference between two builds of one commit.  End to end, `bytes` calls are under 1 % of
every pyperformance benchmark and pyperformance shows no bytes-attributable change;
startup is unchanged.  The five spec'd types behave identically to main in 87,737 probed
lines, and the free-threaded build passes the same checks (appendix A).

## 7. Pure Python: `bytes` as "Python which is lowered"

A spec'd type is *Python which is lowered* when running the spec's Python would behave
exactly as the C does, the C being the same program lowered for speed.  That takes four
things: every member has a Python body; the bodies never use a host type that a spec
describes (they compute with `int`, `str`, `tuple`, `list`); eight explicit *machine
primitives* (`machine.py`: allocation, item storage, the buffer protocol, the hash key, …)
say what Python cannot, each with a Python and a C meaning; and the spec run as Python
matches the C type on every probe.  A pure body (`@native(facts=False)`) is run only by
the model: nothing new is compiled and the call tables do not change.

For `bytes` and its iterator, 67 of 69 members have pure bodies (all but printf-style
`%`).  Run for this document:

```
$ ./python Tools/clinic/pyspec_parity.py model
...
all: 36086/36189 identical (99.7%); 103 lines differ for a limit of a Python class; 889 lines excluded
```

The 103 lines are things a Python class cannot express (a heap type always has
`tp_as_sequence`; `sq_repeat` cannot be separated from `nb_multiply`); the 889 excluded
lines are the type object, `sys.getsizeof`, pickling and copying.  A test fails if any
body diverges or uses the builtin.  For Rust, the pure body is the language-neutral
contract a native implementation is checked against; for PEP 399 it points the other way
from today's pairs: one Python source, with C as its lowering and a mechanical
equivalence check.  Details, the 103 lines, what is not done and the feasibility for
`bytearray` and `mmap` are in appendix C.

## 8. Moving code

Five levels (table in "What is asked"), each its own small PR, one C file per PR
(`Objects/pyspec/MIGRATING.rst`).  Adding the next type is data: a spec, a
`<stem>_cases.py` (the type in `TYPES`, cases, native-function inputs), the parity record
captured **before** the migration (ideally in its own PR, so main's CI checks it), and
regenerated clinic output.  No interpreter C, test class or tool code names a type.
Level 3 is optional and decided with numbers: the guide's worked example
(`bytes.removeprefix`, non-PGO release builds) measured −0.5 to −4 % and was **kept in C**,
because half of that came from a converter change plain C can make too.

A native implementation in **Rust** is a design (appendix F): the spec, the reference, the
difftest, `HelperTest`, the parity record and the model comparison are language-neutral
already; a Rust checker and the build support are not written.

## 9. Costs and counter-arguments

- **Tool size**: `Tools/clinic/libclinic/pyspec/` is 9,647 lines (about 4,200 of them the
  level 3–4 machinery: partial evaluator, facts, emitter, C backend), plus the parity,
  review and bench tools and about 5,700 lines of tests.  Levels 1, 2 and 5 need little of
  the level 3 machinery.  It has one author and would need co-maintainers.
- **Interpreter side**: a header of call-table types and lookups, a generated registry
  header, about 160 lines of uops, about 300 lines in the optimizer, a debug-only
  tripwire; the public C API and the stable ABI are unchanged.
- **C semantics in Python syntax**: bodies test `is NULL` and call C functions by name;
  a reader must know a body is not ordinary Python.
- **Annotations are converters**, not types, so specs are not type-checkable.
- **Debugging** steps through generated `.c.h` (comments name spec lines, no `#line`).
- **Merge conflicts** in the generated registry header when two PRs add a type.
- **Spec syntax** is bounded by `PYTHON_FOR_REGEN`'s `ast`.
- **Not lowered yet**: keyword-only parameters, most converters, `while`, `__init__`,
  `@critical_section` on a generated method; module-level functions are not expressible.
- **Few consumers**: the optimizer reads the facts in four uops.
- **The committed parity record churns** when unrelated changes on main touch what it
  probes.

Alternatives considered: extending the clinic DSL (a second Python-like language without
Python's tooling, and bodies could not run as Python), and hand-written tables and facts
with debug assertions (the assertions are useful alone, but do not derive the facts).
Appendix E has the numbers and the full discussion.

## 10. Questions for the community

1. **The ask:** may levels 1–2 go in as a trial for `mmap` and `bytes` (a per-file Python
   spec read by Argument Clinic for signatures, docstrings and tables), independent of
   everything else?
2. Is Python syntax with C semantics (`is NULL`, C functions by name, converters as
   annotations) acceptable in a spec?
3. Who would co-maintain the spec tooling in Argument Clinic, and the partial evaluator in
   particular?
4. Should the specializer's facts about builtins come from a derived table, with debug
   assertions, rather than from hand-written cases in `optimizer_bytecodes.c`?  (A
   question for the JIT and specializer maintainers.)
5. Is a disconnect ratchet over `Doc/c-api`, `refcounts.dat` and `threadsafety.dat`
   wanted in the test suite?
6. Is a committed behaviour record the right review aid for migrations, or should parity
   be checked only against a build of the base?
7. PEP 399: given the `bytes` result, should a stdlib pair (`bisect`) be tried with its
   pure module as the spec and the C checked against it?  And for Rust: is "the spec is
   the contract, a per-language checker validates native code against its reference" the
   right shape for mixing languages inside one type?

## 11. The incremental path

Each level is useful without the next:

- **Independent of specs**: the `_CALL_STR_1` fix and its companion (`_pylong` must return
  an exact `str` for huge ints); the doc, docstring and typeshed fixes of section 1;
  debug-build result assertions for existing optimizer facts; the
  `BINARY_OP_SUBSCR_BYTES_INT`/`FOR_ITER_BYTES` specializations.
- **Level 1–2** (clinic reads specs; tables generated): no interpreter change, output
  byte-identical, reviewed with the parity record.
- **Level 5** (the ratchet): needs only level 1 specs.
- **Levels 3–4** (bodies, call tables, tier-2 consumers): the part that needs the
  partial evaluator; one type at a time, with numbers.
- **Pure bodies** (`@native(facts=False)` and the model): need nothing compiled; they can
  follow levels 1–2 for a type whenever an executable reference is wanted.

The contributor reference is `Objects/pyspec/README.rst`; the migration procedure is
`Objects/pyspec/MIGRATING.rst`.

---
## Appendix A: measurements

### Where the speed comes from

Attribution by pairs of builds, JIT on and off (a PGO+LTO
review build of the branch at `62cc16504fe` against main `ee1bbf037ff`, instructions per
call):

| source of the gain | needs | size |
|---|---|---|
| a generated `tp_vectorcall` and per-arity entries for `bytes()` (main has no vectorcall for `bytes`) | nothing of pyspec: a hand-written vectorcall gives the same | −200 to −260 per `bytes()` call, −610 with a keyword; **all of the JIT-off gain** |
| a direct call of the per-type entry from tier 2 | call-table facts, JIT on | `bytes(16)` −249, `bytes(bytearray)` −235 |
| `bytes(b)` replaced by `b` (alias) | facts, JIT on | −509 beyond the direct call |
| `bytes()` folded to the empty-bytes constant | facts, JIT on | −141 |
| "runs no Python code" (no spill, no `_SET_IP`) | facts, JIT on | about −18 |
| loops over lists, tuples, ranges, iterators derived from one body | generated bodies, JIT on or off | e.g. `bytes(range(256))` −27 per item |
| `b[i]`, `for c in b` specialized | hand-written uops (useful without specs); the spec gives their result facts | about −100 and −540 per iteration (table below) |

The facts could also be written by hand in `optimizer_bytecodes.c`, as `_CALL_STR_1`'s
are; what the spec adds is that they are derived from the code and asserted, not that
they exist.

### Micro benchmarks: method and all statements

PGO+LTO release JIT builds with one compiler (clang 21),
`--with-tail-call-interp --with-lto --enable-optimizations --enable-experimental-jit`;
`Tools/clinic/pyspec_bench.py --cpu 15 --repeat 5 --cycles`, instructions / minimum
cycles per iteration including the loop, `PYTHONHASHSEED=1` (a missing-method lookup's
cost depends on the hash seed since the per-type method cache; seeds 0 and 7 were
checked too).  main = `ee1bbf037ff`, branch = `737069ca773` (between it and
`c9d7955088f` the generated C and the interpreter C changed only in comments, braces and
the header the registry lives in).  All statements, seed 1:

Instructions/cycles per iteration including the loop, and the instruction change.  Setup:
`b16 = b'abcdefghijklmnop'`, `b16c = bytes(bytearray(b16))`, `b16s = b'ab cd ef gh ij k'`,
`ba16 = bytearray(b16)`, `mv16 = memoryview(b16)`, `s16` a 16-character str,
`l16 = list(range(16))`, `l256`/`t256` 256 ints below 256, `t16 = tuple(range(16))`,
`bl16 = [True, False] * 8`, `r16`/`r256` ranges, `s8 = set(range(8))`,
`d8 = dict.fromkeys(range(8))`, `h16` 32 hex digits, `fromhex = bytes.fromhex`,
`class Sub(bytes)`, `sub = Sub(b16)`, `hb` an object with `__bytes__`, `ix` an object with
`__index__` returning 16, `gen()` a generator over `l16`.

| shape | JIT on: main → branch | JIT off: main → branch |
|---|---|---|
| `pass` | 163/34 → 163/34 (+0.1%) | 138/26 → 138/26 (+0.0%) |
| `bytes()` | 433/81 → 184/38 (-57.5%) | 425/77 → 325/60 (-23.5%) |
| `bytes(b16)` | 926/187 → 218/43 (-76.5%) | 937/189 → 385/73 (-58.9%) |
| `len(bytes(b16))` | 1021/205 → 313/63 (-69.4%) | 1049/211 → 497/97 (-52.6%) |
| `bytes(ba16)` | 1134/227 → 678/151 (-40.2%) | 1132/227 → 902/192 (-20.4%) |
| `bytes(mv16)` | 1167/235 → 689/154 (-41.0%) | 1165/234 → 911/194 (-21.8%) |
| `bytes(16)` | 911/171 → 445/97 (-51.2%) | 912/167 → 606/117 (-33.5%) |
| `bytes(s16, 'ascii')` | 1074/197 → 789/152 (-26.5%) | 1089/201 → 830/157 (-23.8%) |
| `bytes(s16, 'utf-8')` | 1108/204 → 818/157 (-26.2%) | 1123/208 → 859/163 (-23.5%) |
| `bytes(s16, encoding='ascii')` | 1687/317 → 1071/198 (-36.5%) | 1737/330 → 1117/208 (-35.7%) |
| `bytes(l16)` | 1340/254 → 812/159 (-39.4%) | 1336/247 → 1029/193 (-23.0%) |
| `bytes(l256)` | 6845/1220 → 5123/860 (-25.2%) | 6840/1218 → 5341/893 (-21.9%) |
| `bytes(t16)` | 1353/256 → 816/165 (-39.7%) | 1349/249 → 1046/196 (-22.4%) |
| `bytes(t256)` | 6864/1220 → 5133/855 (-25.2%) | 6860/1215 → 5364/890 (-21.8%) |
| `bytes(bl16)` | 1340/253 → 860/170 (-35.8%) | 1336/248 → 1077/199 (-19.4%) |
| `bytes(r16)` | 2779/548 → 1836/366 (-33.9%) | 2775/551 → 2047/402 (-26.2%) |
| `bytes(r256)` | 25567/5141 → 16714/3248 (-34.6%) | 25568/5148 → 16924/3296 (-33.8%) |
| `bytes(iter(l16))` | 3193/659 → 2353/486 (-26.3%) | 3250/675 → 2495/504 (-23.2%) |
| `bytes(gen())` | 7097/1475 → 6258/1313 (-11.8%) | 6805/1441 → 6050/1277 (-11.1%) |
| `bytes(s8)` | 2416/479 → 1807/366 (-25.2%) | 2418/484 → 1930/388 (-20.2%) |
| `bytes(d8)` | 2230/457 → 1623/334 (-27.2%) | 2227/458 → 1740/356 (-21.9%) |
| `bytes(sub)` | 1133/226 → 784/167 (-30.8%) | 1134/224 → 901/181 (-20.6%) |
| `bytes(hb)` | 1305/261 → 965/191 (-26.0%) | 1227/242 → 1008/202 (-17.8%) |
| `bytes(ix)` | 1456/289 → 1115/232 (-23.4%) | 1365/272 → 1145/232 (-16.1%) |
| `Sub(16)` | 1313/259 → 1263/253 (-3.8%) | 1296/256 → 1245/246 (-4.0%) |
| `Sub(b16)` | 1326/270 → 1037/200 (-21.8%) | 1307/272 → 1010/192 (-22.7%) |
| `Sub(l16)` | 1748/344 → 1714/337 (-1.9%) | 1715/344 → 1691/334 (-1.4%) |
| `b16.__bytes__()` | 272/53 → 235/46 (-13.6%) | 313/61 → 314/60 (+0.3%) |
| `sub.__bytes__()` | 724/142 → 722/141 (-0.1%) | 633/122 → 632/122 (-0.2%) |
| `bytes.fromhex(h16)` | 1602/323 → 1604/327 (+0.1%) | 1532/314 → 1534/316 (+0.2%) |
| `fromhex(h16)` | 1051/202 → 1051/206 (+0.0%) | 975/182 → 975/183 (+0.1%) |
| `b16.fromhex(h16)` | 1502/304 → 1503/308 (+0.1%) | 1412/296 → 1413/294 (+0.1%) |
| `Sub.fromhex(h16)` | 2578/539 → 2283/465 (-11.4%) | 2486/523 → 2196/450 (-11.7%) |
| `b16[i]` | 306/60 → 207/41 (-32.3%) | 315/59 → 220/41 (-30.2%) |
| `for c in b16: pass` | 1652/333 → 1109/205 (-32.9%) | 1454/371 → 1165/308 (-19.9%) |
| `b16s.split()` | 1811/340 → 1790/344 (-1.2%) | 1811/343 → 1844/349 (+1.8%, bimodal) |
| `b16.hex()` | 602/120 → 581/116 (-3.5%) | 602/114 → 599/114 (-0.5%) |
| `b16 == b16c` | 348/67 → 350/68 (+0.6%) | 339/71 → 341/64 (+0.5%) |
| `hash(b16)` | 479/100 → 479/100 (+0.0%) | 499/102 → 499/102 (+0.0%) |
| `bytearray(b16)` | 1251/247 → 1248/245 (-0.2%) | 1249/243 → 1249/242 (-0.0%) |

At seeds 0 and 7 the shapes within 2 % of main at seed 1 give: `Sub(l16)` −1.1 to −1.5 %,
`Sub(16)` −3.8 to −7.3 %, `bytes.fromhex(h16)` +1 to +2, `hash(b16)` JIT off +6 (seed 0)
and +1, `b16.hex()` JIT off +4 and +2, `bytearray(b16)` −14 to 0.  Cycles (minimum of
five) follow instructions except for JIT-off tier-1 loops, which move by up to 30 %
between builds with identical instructions (code layout).

### Noise and the regressions that were resolved

Every `bytes()` shape is 11–77 % below main.  `Sub(l16)` is the thinnest margin, −1.1 to
−1.9 % across seeds 0, 1 and 7.  Noise: two builds of one commit differ by up to 10
instructions on unchanged code (`hash(b16)` JIT off 504 vs 494) and ±3 % in cycles.  No
shape is above main by more than that: the largest excesses are `b16s.split()`
(bimodal, 1811 or 1844 on main too), `hash(b16)` JIT off +6 at seed 0, `b16.hex()` JIT
off +4, `bytes.fromhex` +1 to +2, `b16 == b16c` +2 and `b16.__bytes__()` JIT off +1, all
in code unchanged from main or equal to main under callgrind.  Two earlier regressions
were resolved: `bytes.fromhex` was +5 in real code (callgrind self cost of
`bytes_fromhex` 20 instructions against main's 15), fixed in the spec by testing
`cls is bytes` first so the call is a tail call (15 again); and a +24 on `bytearray(b16)`
was a PGO artifact in code identical to main's (non-atomic training counters lost three
increments, clang derived an underflowed branch weight and stopped inlining
`_PyBytes_FromSize`; a second build of the same source was at main).  The `@inline` fast
paths cost 6–11 instructions on shapes where their test fails and save 30 where it
succeeds; no "must inline" marker was needed.

### End to end, parity, free-threaded, code size

**End to end.**  `bytes` calls are under 1 % of every pyperformance benchmark, and
pyperformance (13 benchmarks, branch at `62cc16504fe` vs main) shows no
bytes-attributable change beyond its A/A noise of ±1–2 %.  The `b[i]` and iteration
specializations cut pyflate's instructions by 3.1 % and cycles by 1.2–2.2 % under
`perf stat` (branch before and after them, PGO+LTO), about −0.4 % wall clock, inside
pyperformance's A/A noise.  Startup is unchanged (`-S -c pass` 27.09 M → 27.12 M
instructions, same builds).

**Parity with main** (run for this document): the 5 spec'd types behave identically
to main in 87,737 probed lines (debug build); `bytearrayobject.c.h`, `transmogrify.h.h`
and `mmapmodule.c.h` are byte-identical to main; `bytesobject.c.h` differs only in
`bytes.__new__`, whose vectorcall is now generated.

**Free-threaded.**  At `bb32433383b` the test suites passed on a free-threaded debug
build of the branch, and `bytes(list)` keeps main's atomic snapshot of an all-int list
(the loop is derived, runs in the list's critical section, and restarts on the generic
path if an item could run Python code).  At `b07c2e648db` the parity record was
recaptured from main (GIL debug, GIL release, free-threaded debug, all at `ee1bbf037ff`)
and the branch's debug JIT, release JIT and free-threaded debug builds matched it
(`check --strict`).

**Code.**  `bytesobject.c` −717/+256 lines, `bytearrayobject.c` −751/+117 against main
(signatures, docstrings and tables moved to specs); specs are 3,977 lines in all.
Machine code, debug builds (`-Og`; main at the merge base with the tier-2 interpreter,
the branch with the JIT; `size`): `bytesobject.o` text 107,635 → 115,873 bytes and data
4,352 → 5,376, `bytearrayobject.o` text 88,824 → 90,646, `bytes_methods.o`
14,872 → 12,981, `optimizer_analysis.o` 71,554 → 79,410.  In a PGO+LTO release build
(at `62cc16504fe`) about 11 KB of `.text` was attributable to the branch: bytes code
+6.9 KB (the generic one-argument entry and per-type variants), `optimize_uops` +3.9 KB,
JIT stencils about 0.7 KB.

## Appendix B: the checks in detail

What these checks do not give: the difftest runs the bodies *on CPython*, where the
classes a spec names are the builtins and the machine primitives read them, so for most
of a type it compares the C with itself in part.  Where the model applies (`bytes` and its
iterator today) the comparison is independent of the C type: the model's bytes holds
its own tuple of ints and never calls the builtin, which is checked statically over every
spec and at run time (section 7, appendix C).  The parity record and the model
compare on the probes only: a behaviour no probe reaches is not covered, and the
type's own tests (`test_bytes`) still say what is right.  The fact assertions run only in debug builds,
only for calls in optimized traces, and the tripwire, like the C checker, treats a
reference release as running no Python code.

The review on the branch against main (run for this document; about 25 seconds;
`--baseline` names a debug build of main at the merge base):

```
pyspec review of c9d7955088f against main (merge base ee1bbf037ff), python 3.16 free-threaded=False debug=True pointer=64 platform=linux

- Behaviour: same as Tools/clinic/pyspec-baseline/parity.txt for bytearray, bytearray_iterator,
  bytes, bytes_iterator, mmap (87,737 lines in 251 sections)
  - vs .../build-str1-dbg/python: no difference in 87,737 lines
  - on purpose: bytes /^C tp_vectorcall$/: bytes() is called through the vectorcall the spec generates
- Generated code: up to date (clinic --dry-run on 14 C files of specs)
  - Objects/clinic/bytesobject.c.h: +94/-9 lines, in bytes_new_impl, bytes_new, ... (on purpose:
    bytes.__new__ has a spec body)
  - every other clinic output: identical to the base
- Specs vs interpreter: passed, 535 tests
- Facts: passed, 21 tests; debug build: facts also asserted at run time
- Ratchet: passed, 12 tests (skipped=1); c_calls 0, capi 20, docs 0, docstrings 2, slots 3
Result: OK
```

The assertions do fire: in an injected-fault test, a deliberately wrong fact
(`exact(bool, …)` in the reference of `bytes.__getitem__`) aborts with "the tier-2
optimizer's exact result type is wrong".

## Appendix C: pure Python in detail

**Definition.**  A spec'd type is *Python which is lowered* when running the spec's Python
would behave exactly as the C does; the C is the same program, lowered (by hand or by
clinic) for speed:

1. **Complete**: every method and slot of the class, and every function its bodies call,
   has a Python body: lowered by clinic, `@native` (a reference the facts read) or
   `@native(facts=False)` (a pure-Python body only the model runs; clinic, the facts and
   the checker read it as `...`, so nothing new is compiled and the call tables do not
   change).
2. **Non-circular**: the bodies compute with host types no spec describes (`int`, `str`,
   `tuple`, `list`, `slice`, exceptions), name a described type (`bytearray`) or
   `memoryview` only as a type, never calling it; the spec's own classes stand for
   themselves.
3. **Eight machine primitives** (`Tools/clinic/libclinic/pyspec/machine.py`) say what
   Python cannot, each with a Python meaning and a C one: `ob_alloc`/`ob_items` (allocate
   an object, read the bytes it holds), `ob_new` (an object with its declared fields),
   `buffer_items`/`buffer_export` (the buffer protocol), `hash_secret` (the hash key),
   `has_slot` (a slot of another type, as abstract.c dispatches), `from_host` (a codec's
   result).
4. **Observable equivalence**: the spec run as Python gives the same line as the C type
   for every probe of the parity tool, except sections a Python class cannot have like a
   static C type, each listed with its reason.

A pure body reads like the C it stands for (`bytes.split`):

```python
    @native(facts=False)
    def split(self, sep: object = None, maxsplit: Py_ssize_t = -1):
        if maxsplit < 0:
            maxsplit = PY_SSIZE_T_MAX
        if sep is None:
            return stringlib_split_whitespace(self, ob_items(self), maxsplit)
        sub = buffer_items(sep)
        if sub is NULL:
            raise TypeError("a bytes-like object is required, not "
                            f"'{tp_name(type(sep))}'")
        return stringlib_split(self, ob_items(self), sub, maxsplit)
```

**The model** (`Tools/clinic/libclinic/pyspec/model.py`) builds Python classes from a
spec: clinic's argument parsing derived from each signature, models of the descriptors and
slot wrappers of `descrobject.c` and `typeobject.c`, the spec's class names bound to the
model classes.  A method still `...` is *delegated* to the C (and counted as circular).

**The result**, for `bytes` and `bytes_iterator`: 67 of their 69 members have pure bodies
(all but `%`, `__mod__`/`__rmod__`), with the stringlib templates, `bytes_methods.c`,
SipHash-1-3 of `pyhash.c` and `pystrhex.c` as new specs.  Run for this document (6 s):

```
$ ./python Tools/clinic/pyspec_parity.py model
...
methods with a Python body: 25614/25686 identical (99.7%)
methods delegated to the C: 146/146 identical (100.0%)
protocols, type calls, iteration: 10326/10357 identical (99.7%)
all: 36086/36189 identical (99.7%); 103 lines differ for a limit of a Python class; 889 lines excluded
```

The 103 lines: explicit `b.__mul__(x)`/`__rmul__(x)` with a non-integer (72; a Python class
cannot have `sq_repeat` apart from `nb_multiply`), a heap type always having
`tp_as_sequence` (26), `bytearray % b` testing `PyBytes_Check()` (4), weakrefs to a
subclass (1).  Excluded, 889 lines: the type object (flags, sizes, `help()`, layout),
`sys.getsizeof`, pickle and copy (they find the builtin by identity).  `ModelTest` fails
when a method with a Python body diverges, and when a body is circular: statically over
the bodies of every spec, and at run time (`sys.monitoring` sees any call of a described
builtin from the code of a spec while the probes run).  The model is slow (a parity run
3 s against 1 s for the C; single calls 100–900× slower): a proof and a reference, not a
`bytes` to use.

**What this buys.**  The spec of `bytes` is now an executable description that does not
lean on the C it describes, so the model comparison is a real equivalence check on the
probes, where the difftest alone was partly CPython against itself.  For **Rust** the pure
body is the language-neutral contract: a native implementation in Rust would be `@native`
with the same body and checked by the same comparison, and the machine primitives are the
list of object-layout operations it must provide through the C API.  For **PEP 399** it is
the other direction from today's pairs: one Python source that is the semantics, with C as
its lowering and a mechanical equivalence check in place of "the same tests against both"
(appendix G; applying it to a stdlib pair such as `bisect` is analysis, not implemented).

**Not done.**  `%` needs format strings in the parity samples (a record update);
`bytearray` needs a mutable-storage primitive and bodies of its own for the methods it
shares with `bytes` (estimated 85–90 % of its lines reachable); `mmap` is protocol logic
over an OS "mapped memory" primitive (perhaps half its lines).  `@critical_section` is a
no-op in the model: the free-threaded guarantees are properties of the lowering, checked
by the C tests.  Promoting a pure body to a source of facts (`@native` proper) needs the
checker to read clinic `_impl`s and `HelperTest` to call methods.

## Appendix D: the spec language in more detail

Four primitives say what plain Python cannot: `exact(T, v)` (a new object of exactly
type `T`), `unknown(v)`, `calls(x, "__slot__")` (the C invokes that special method of
`type(x)`: Python runs only if it is Python code) and `runs_python()`.  From bodies and
references clinic derives, per call shape, the exact result type, aliasing, constants,
whether the call can raise and whether it may run Python code.  (`buffer_items()` is a
*machine primitive*, section 7.)

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
`*args`, `while`, anything).  Only a documented subset is lowered to C; everything
else is analysed as worst case and reported, where lowering is asked for, as
"expressible, but not lowered to C yet".

The C checker of native functions reuses the lexer and escape analysis of the cases
generator (`Tools/cases_generator/`).  Checkers are registered by file extension
(`NATIVE_CHECKERS` in `Tools/clinic/libclinic/pyspec/native_check.py`), so native code in
another language needs its own checker and nothing else changes: callers reach it through
its C interface.


## Appendix E: costs in detail

**Tool size.**  `Tools/clinic/libclinic/pyspec/` is 9,647 lines (6,872 lines of code):
the front end, subset and runtime (about 2,270), level 2 tables (about 570), the level 3–4
machinery (partial evaluator, facts, emitter, IR, C backend, call tables: about 4,200),
the checks (disconnects, native checker: about 1,250), the model and machine primitives
(about 1,370).  Plus `pyspec_parity.py` (1,788), `pyspec_review.py` (433),
`pyspec_bench.py` (155), +479/−29 lines in clinic proper (`app.py`, `dsl_parser.py`,
`errors.py`, `function.py`, `parse_args.py`), and about 5,700 lines of tests.  Levels 1, 2
and 5 need little of the level 3 machinery.  A partial evaluator of this size inside
clinic needs co-maintainers; today it has one author.

**Interpreter-side cost** (against the merge base): `Include/internal/pycore_pyspec.h`
(295 lines: the call-table types, lookups, the debug tripwire) and the generated
`Include/internal/pycore_pyspec_registry.h` (29); `Python/bytecodes.c` +162 (the direct-call
and record uops, `_ASSERT_RESULT_*`, the bytes specializations), `optimizer_analysis.c`
+167/−3, `optimizer_bytecodes.c` +148/−15, `specialize.c` +8, `optimizer.c` +2;
`Modules/_testinternalcapi.c` +500 (the helper table, direct calls of entries); a
debug-only field `pyspec_no_python` in `_PyThreadStateImpl` and one debug hook line in
`_PyEval_EvalFrameDefault` (a no-op macro in release builds); includes in `ceval.h` and
`Tools/jit/template.c`; `Makefile.pre.in` (the two headers, and a rule that makes
`Objects/foo.o` depend on its generated `clinic/*.c.h`) and `PCbuild` (the two headers).
Exported symbols: the only additions are two private data symbols for
`_testinternalcapi` (`_PySpec_bytes_calls`, `_PySpec_bytes_iterator_calls`); the public
C API (`PyBytes_FromObject` stays an exported function), `Misc/stable_abi.toml` and the
public headers are unchanged (`nm -D` of both builds; only the generated
`Include/opcode_ids.h` changes, for the new specialized opcodes).

**Counter-arguments, and where they stand:**

- *C semantics in Python syntax.*  Bodies test `is NULL`, call C functions by name, and
  `isinstance()`/`iter()` mean the C's only when imported from the runtime (a spec that
  forgets the import fails to load).  A reader must know that a body is not ordinary
  Python.  References used to model the C with the host's builtins (circularly); for
  `bytes` that is gone and checked for every spec, but the difftest still runs on the host.
- *Annotations are converters*, not types (`maxsplit: Py_ssize_t`, `'char[]'`): specs are
  not type-checkable, and ruff reports the string annotations as F722.
- *Debugging.*  gdb steps through the generated `.c.h`, not the spec: the generated C
  names spec lines in comments, but there are no `#line` directives.
- *Merge conflicts.*  The registry header is generated from every spec; two PRs adding a
  type both change it (as generated opcode headers conflict today).
- *Spec syntax is bounded by `PYTHON_FOR_REGEN`*: clinic parses specs with that
  interpreter's `ast` (configure accepts 3.10 or newer), so newer syntax cannot be used in specs.
- *Not lowered yet*: keyword-only parameters, defaults other than `NULL`, converters other
  than `object`/`str`, `while`, `__init__`, `@critical_section` on a generated method.
  Not expressible at all: optional groups, deprecation markers, module-level functions.
- *Few consumers.*  The optimizer reads the call table in two uops and slot facts in two;
  the facts of `METH_O`/`METH_FASTCALL` methods are generated but unread.
- *Checks with stated assumptions.*  The C checker works per function, not per path, and
  treats a reference release as running no Python code (so does the tripwire).
- *The committed parity record churns.*  An unrelated change on main (a docstring
  inherited in `help()`, another type's error message) changes a section and must be
  re-recorded; only Linux 64-bit blocks exist, and other configurations skip the check.
- *Measurement noise.*  PGO builds of one commit differ by 1–3 % on unrelated shapes;
  results depend on the hash seed.  Claims above are instruction counts with A/A pairs.

**Alternatives considered.**  (a) *Extend the clinic DSL* with slot and table
declarations and body syntax: keeps one language for clinic users, but the DSL would grow
into a second Python-like language without Python's tooling, and a body could not run as
Python for the difftest or the model.  (b) *Hand-written tables and facts, plus debug
assertions*: the assertions (`_ASSERT_RESULT_*`) are useful alone and are proposed
independently; they catch a wrong fact when a test happens to exercise it, but do not
derive the fact, and leave the tables and descriptions to drift.

## Appendix F: a native implementation in Rust (proposed, not implemented)

What the spec already gives any implementation language, unchanged: the signature (clinic
still generates the argument parsing and the entry the method table names), the docstring
and the slot it fills; the reference, which the difftest runs as Python and from which
callers derive facts; for a type with pure bodies, the model comparison; the test data
(`HELPERS`), the parity record and the review.

| piece a Rust native function needs | status |
|---|---|
| the function exported with the C signature the spec declares (`extern "C"`), linked into libpython | proposed (depends on CPython's Rust build support) |
| a checker: a `NativeChecker` subclass registered for `.rs` in `NATIVE_CHECKERS`, giving the code of a function, the calls it makes, which may run Python code, which are audited to run none, and which special method a call runs | interface exists (the C checker implements it); no Rust checker |
| a ratchet dimension next to `c_calls` | proposed |
| the call from `test_pyspec_facts` (`HelperTest`) through the C interface, compared with the reference | exists, language-neutral |
| the parity record, the difftest and the model comparison | exist, language-neutral |

For bodies *generated* in Rust instead of C, the seam is the backend: everything up to
the lowered form (`ir.py`: locals' types, ownership, each call's error check, loops)
is language-neutral, and a Rust backend would implement `CBackend`'s methods (functions
with a C signature, type checks, reference counts, index loops, critical sections, type
names).  The call tables stay C data of the interpreter.  This is a design, checked only
against the C backend's interface.

## Appendix G: how much is Python, and PEP 399

**Counts at `c9d7955088f`** (over the 14 spec'd C files; a *member* is a `def` in a class
or a shared assignment `x = other.Class.x`):

| | signature only (`...`) | lowered body | `@native` reference | pure body (`@native(facts=False)`) | shared |
|---|---|---|---|---|---|
| `bytes` (64 members) | 2 (`__mod__`, `__rmod__`) | 3 (`__new__`, `__bytes__`, `fromhex`) | 3 (`__buffer__`, `__len__`, `__getitem__`) | 38 | 18 (stringlib, pure) |
| `bytes_iterator` (5) | | | 1 (`__next__`) | 4 | |
| stringlib templates `B` (18) | | | | 18 | |
| `bytearray` (80) and its iterator (5) | 58 | | | | 27 |
| `mmap` (21) | 21 | | | | |
| **all classes**: 148 `def`s + 45 shared | 81 | 3 | 4 | 60 | 45 |
| top-level functions (88) | | 2 (`PyBytes_FromObject`, `bytes_from_iterator`) | 19 | 64 | 3 `@inline` |

C keeps the object layout and memory (behind the machine primitives), every method of
`bytearray` and `mmap`, the native functions, argument parsing (generated) and the
specialized uops.

**PEP 399** ([PEP 399](https://peps.python.org/pep-0399/)) asks that a stdlib module with
a C accelerator also ship a pure-Python version tested against the same suite
(`import_fresh_module`), so other VMs get a usable implementation.

| | PEP 399 | pyspec |
|---|---|---|
| scope | stdlib modules | builtins and core C files (where pure Python cannot bootstrap the type) |
| direction | two independent implementations, Python and C | one source; C generated from it or checked against it |
| role of the Python | a runnable implementation for any VM | a contract; for `bytes`, also a complete pure-Python implementation run by the model |
| equivalence | the same tests run against both | the parity probes compare model and C line by line |

*Analysis, not implemented:* the existing pairs (`bisect`/`_bisect`, `heapq`/`_heapq`,
`datetime`/`_datetime`, `json`/`_json`, `pickle`/`_pickle`) could make the pure-Python
module the spec, with clinic generating the accelerator or checking a hand-written one
(`@native`) against it by the model comparison, which removes the duplication PEP 399
accepts as a cost.  For a stdlib pair the machine primitives mostly vanish (the pure
module already runs on any VM).  What it would take: module-level functions in specs
(not expressible yet) and the parity tool probing module functions; for generated
accelerators, lowering Python semantics (`<`, `+`, indexing, attributes, `while`) to
generic C API calls, competitive with hand-written C only where the facts let clinic
specialize.  A small first experiment: `Lib/bisect.py` as the spec of
`Modules/_bisectmodule.c`, the C kept `@native`.  What a pure spec does not give a
PEP 399 module: a runnable module without the model runtime (`model.py` stands in for
`descrobject.c` and clinic's parsing); for builtins, other VMs have their own object
model, so the bodies, not the runtime, are what they could reuse.

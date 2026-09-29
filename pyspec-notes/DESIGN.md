# pyspec v1 design brief (shared by all workstreams)

> **Historical** (the brief of the early workstreams, at `bc4667e90c0`).  Superseded by
> `pyspec-notes/README.md` (state and decisions in force) and `Objects/pyspec/README.rst`.

Repo: /home/firebird347/projects/python/cpython, branch exp/ac_python_overloads_v0,
checkpoint commit bc4667e90c0.  Read these first:
  Objects/pyspec/bytesobject.py        (current spec: bytes_new + PyBytes_FromObject bodies)
  Tools/clinic/libclinic/pyspec.py     (clinic finds spec functions by C basename)
  Tools/pyspec/{emit_c,partial_eval,pyspec_runtime,test_bytes_spec}.py
  Objects/bytesobject.c, Objects/clinic/bytesobject.c.h, Objects/clinic/bytesobject_pyspec.c.h
  Lib/test/test_clinic.py (class PyspecTest)

## Goals (from the user)
1. Python's C API keeps working.
2. The interpreter/JIT get detailed facts (which paths/types can be removed) derived
   from the code, without extra manual annotation.
3. Implementations behave exactly as today.
4. Fastest call path everywhere: direct C, falling back to vectorcall, then tp_call.
5. ONE mechanism usable everywhere (like Argument Clinic), internal to CPython.
6. Connects to the C API docs (Doc/c-api/*.rst, Doc/data/refcounts.dat,
   Misc/stable_abi.toml) and exposes disconnects.
7. Contributors use FEWER bespoke tools: Argument Clinic stays the single generator
   (`make clinic` / `Tools/clinic/clinic.py --make`); checks run in the normal test
   suite (`python -m test`).  No new standalone scripts contributors must remember.
8. Performance keeps improving as more gets declared; small reviewable PRs.

## Decisions
D1 Single tool.  All pyspec code moves into Argument Clinic as the package
   Tools/clinic/libclinic/pyspec/ (runtime, partial evaluation, C emission, stub
   front end, C API catalog checks).  Tools/pyspec/ is removed.  Running clinic on a
   .c file also regenerates everything its spec produces.  The spec-vs-interpreter
   difftest becomes part of Lib/test.

D2 Spec file = Objects/pyspec/<cfile stem>.py, ordinary Python, typeshed-like:
   - `class bytes:` with one method per clinic function of that class.  Parameters are
     written exactly like clinic parameter lines (converter as annotation, default,
     `/`, `*`); `@classmethod` / `@staticmethod` as in Python; the docstring is the
     clinic docstring.  Body `...` means "C impl is hand-written" (clinic behaves as
     today).  A real body means "the spec implements it" (C impl generated).
   - Top-level functions are C functions: C API (PyBytes_*) and internal helpers.
     Name = C name.  Body `...` = stub describing a hand-written C function (its facts);
     real body = generated.
   - The .c file keeps a minimal clinic block per function: optional clinic-only
     decorators (@critical_section, @text_signature, ...) plus the function line with
     any `as c_name` rename, e.g.
         /*[clinic input]
         bytes.__new__ as bytes_new
         [clinic start generated code]*/
     Parameters and docstring come from the spec method with that full name.
     `class bytes "PyBytesObject *" "&PyBytes_Type"` stays in the .c file.
   - For stub-only functions, generated clinic output must be byte-identical to today.

D3 Facts vocabulary (C API catalog) is plain Python annotations, defined in
   libclinic/pyspec/runtime.py.  Keep it tiny: C types (object, cstr, Py_ssize_t, int,
   char_p, ...), ownership (return New[...] / Borrowed[...]; params Steals[...]),
   error convention, and "may run Python code".  Stable ABI membership/version is NOT
   duplicated: read Misc/stable_abi.toml.

D4 Interpreter/JIT consume generated static C data (no runtime cost, no startup cost):
   per type, per positional arity (object-typed args only), optionally per exact arg
   type: direct C function pointer + result facts (exact result type or none, constant
   result, may-run-Python).  The tier-2 optimizer uses it to emit a direct-call uop
   (function pointer operand, like _CALL_METHOD_DESCRIPTOR_O_INLINE) and to set the
   result symbol's type / fold constants.

## Rules for every workstream
- Work only in your git worktree; build out of tree in your OWN build dir
  (e.g. /home/firebird347/projects/python/build-<ws>), `CC=clang`, `--with-pydebug`
  unless told otherwise.  `make -j8` (see Resource rules).  Never touch /home/firebird347/projects/python/build.
- Regenerate clinic output with `./build-dir/python Tools/clinic/clinic.py --make --srcdir .`
  (or on single files).  Generated files are committed, like clinic output.
- Commit your work on your worktree branch in small logical commits ending with
  "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>".  Never rebase/amend
  other branches; never push.
- Do not "fix" unrelated bugs you find; report them.
- Report: what you changed (files), design choices you had to make, test results
  (exact commands + outcomes), open problems, and anything that conflicts with this
  brief.

## Resource rules (MANDATORY; a previous run OOM-killed the whole machine: 61 GB RAM,
## three parallel callgrind runs reached 54 GB)
- Run every memory-heavy command inside its own memory-capped cgroup so only it dies:
      systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 -- <command>
  Heavy = valgrind/callgrind, perf record, builds (make/configure), test suite runs,
  benchmarks, anything running a large Python workload.  Caps: callgrind/perf 8G,
  builds 12G, tests 6G.  Exit code 137 means it hit the cap: shrink the workload
  (fewer loops, smaller input); do NOT raise the cap above 12G.
- Never run memory-heavy tools in parallel (no `&` fan-out, no `xargs -P`).  One
  callgrind at a time, at the smallest loop count that answers the question; prefer
  `perf stat -e instructions:u` over callgrind for whole benchmarks.
- `make -j8` (not -j16): several agents build at once on a 32-core box.
- Before starting a heavy job, check `free -g`; if "available" < 16 GB, wait
  (poll with a short sleep loop) instead of starting it.

## Updates after WS8 (branch exp/ac_python_overloads_v0 >= 44bb7b369cf)
- D2 superseded: clinic decorators (@permit_long_summary, @text_signature(...),
  @critical_section, ...) are written on the SPEC method as identity decorators from
  libclinic.pyspec.runtime; decorators in a .c block of a spec method are an error.
- Spec-backed `T.__new__` defaults to C basename `T_new` (no `as` needed).
- Spec methods need no clinic block at all: the .c keeps only
  `class bytes "PyBytesObject *" "&PyBytes_Type"`; the C author writes each impl head by
  hand, checked by the compiler against the prototype in clinic/<file>.c.h.  A one-line
  block is still allowed (clinic then writes the head).  Methods under #if need a block.
- `clinic.py --make` from the main checkout also scans .claude/worktrees/*: run clinic on
  specific files (e.g. `Tools/clinic/clinic.py Objects/bytesobject.c`) or from your own
  worktree.

## User decisions after the review (2026-09-26), base commit 62cc16504fe
- Goal: the branch must be a WIN ACROSS THE BOARD versus main (no micro regressions,
  incl. bytes(list), Sub(b)); less infrastructure, less cognitive load, more value.
- ONE mode: one-line clinic blocks per spec method (`bytes.split`); remove no-block mode.
  Clinic writes impl heads again. Generated output should be byte-for-byte identical to
  main wherever possible; every remaining diff must be justified.
- Keep bracket @text_signature (runtime/help() parity). Check typeshed from the spec instead.
- Free-threaded bytes(list) must keep main's atomic snapshot for all-int lists (F1).
- P1 + P2 approved (after the tactical phase): @c_implemented, plain-name helper calls,
  facts derived from bodies with primitives exact()/unknown()/calls()/runs_python(),
  ownership from refcounts.dat, C-side token-level escape check reusing
  Tools/cases_generator/analyzer.py, dynamic call-recording difftest.
- Integration measurement must be a RATCHET: counts of disconnects per dimension with a
  checked-in baseline that may only go down (pattern: Tools/build/check_warnings.py).
- Reports of all prior work: /home/firebird347/projects/python/pyspec-notes/*.md
  (review_perf.md, review_dx.md, review_int.md are the review).

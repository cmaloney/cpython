# Phase 4 P: performance of @inline at undecided sites; Sub(n)

Base `34d046efccb` (phase 2 merged). One commit:
`edd5f1f6cfd` pyspec: bytes(): no `__bytes__` lookup for an exact int.

## Builds and method
- PGO+LTO release JIT builds, all with the same compiler (clang 21.1.8, `PATH=/usr/lib/llvm21/bin`):
  `--with-static-libpython --with-tail-call-interp --with-lto --enable-optimizations
  --enable-experimental-jit LLVM_TOOLS_INSTALL_DIR=/usr/lib/llvm21`, out of tree in
  `../p4p-perf/<name>`, sources in detached worktrees `../p4p-src/<name>` (removed after
  measuring, so those build dirs no longer run).
  - main = `ee1bbf037ff`; before = `bb32433383b` (Merge phase 4 E, before the phase-2 C
    merge); after = `34d046efccb`; after2 = a second build of the same source (A/A);
    fixed = `edd5f1f6cfd`.
  - `build_perf_base_jit` has main's sources, but it was built with clang 22.1.8. It was not
    used, so no compiler difference enters the comparison.
- Measurement: `Tools/clinic/pyspec_bench.py --cpu 15 --repeat 5 --cycles`. Instructions and
  minimum cycles are per iteration, loop included, JIT on and off. Runs were serial under
  `systemd-run MemoryMax=8G`, with the `performance` governor.
- **New noise source: the hash seed.** Since the per-type method cache
  (`Python/typecache.c`, open addressing keyed by the string hash), the cost of a missing
  lookup such as `_PyObject_LookupSpecial(int, "__bytes__")` depends on `PYTHONHASHSEED`.
  - It costs 50–150 instructions (callgrind: 103 at seed 0), so the same binary measures
    `Sub(16)` at anywhere from 1291 to 1386.
  - The tables therefore use `PYTHONHASHSEED=1`. Deltas between builds are the same at
    every seed (checked for seeds 0–7).
- A/A: after vs after2 differ by up to ±9 instructions on 1000–7000-instruction shapes.
  Cycles differ by ±3 %, and by more on JIT-off tier-1 loops.

## Table (seed 1; instructions / cycles; main / before / after / fixed; after2 in the note)
| shape | JIT on | JIT off |
|---|---|---|
| `bytes(16)` | 911/445/445/447 · 171/96/98/98 | 912/706/676/**602** · 167/136/128/117 |
| `bytes(ix)` (`__index__`) | 1458/1100/1110/1118 · 288/233/239/242 | 1367/1131/1140/1142 · 270/237/238/233 |
| `bytes(iter(l16))` | 3191/2339/2345/2349 · 660/482/484/486 | 3250/2483/2489/2487 · 675/502/508/504 |
| `bytes(r256)` | 25573/16707/16707/16710 · 5150/3263/3244/3255 | 25563/16913/16919/16916 |
| `bytes(gen())` / `bytes(s8)` / `bytes(d8)` | after − before: +9 / +7 / +7 | +6 / +13 / +18 (after2 − before: +6 / +12 / +6) |
| **`Sub(16)`** | 1318/1379/1349/**1278** · 262/277/268/**251** | 1296/1361/1330/**1254** · 259/278/257/**241** |
| `Sub(b16)` | 1316/1047/1047/1044 | 1292/1025/1025/1025 |
| `Sub(l16)` | 1745/1730/1724/1732 | 1720/1709/1708/1706 |
| `b16[i]` | 304/205/205/206 · 60/41/41/41 | 315/220/220/218 |
| `for c in b16` | 1652/1109/1109/1110 · 334/204/205/205 | 1454/1165/1165/1163 |
| every other `bytes()` shape of phase1_A (29 in all) | −25 to −76 % vs main in every build; before = after = fixed ±9 | −11 to −59 % |

- **`Sub(16)` across seeds 0–4, fixed vs main:** −3.1 to −9.3 %. after was +2.4 to +3.0 % at
  every seed.
- **`Sub(l16)` across seeds 0–6:** −0.1 to −1.1 %, so still a thin margin (see the proposal).
- Full data: scratchpad `bench1.txt` (random seeds) and `bench2_seed1.txt`.

## 1. Is the @inline cost still there under PGO+LTO?
Yes, and it is small.
- **The fast path's type test cannot be folded.** It is a run-time type test on an unknown
  object. PGO only lays out the branch, and LTO keeps the functions out of line: `bytes_new_nargs1`,
  `bytes_from_iterator` and `bytes_new_impl` all stay separate functions in the PGO binaries.
  - In `bytes_new_nargs1`, the int test compiles to seven branch-free instructions
    (`cmp/setne/cmp/setne/test/jne` plus the size check).
  - In `bytes_from_iterator`, callgrind measures exactly +7 instructions of self cost per call,
    from `PyObject_LengthHint_fast`'s two tests. The per-item loop is unchanged.
- **Measured cost:** +6 to +11 instructions per call on `bytes(ix)`, `bytes(iter(l16))`,
  `bytes(range)`, `bytes(gen())`, `bytes(set)` and `bytes(dict)`. That is 0.04–0.8 % of those
  shapes, the size of the A/A noise, and invisible in cycles.
- **What it buys:** −30 instructions (−8 cycles) on every `bytes(n)` that the tier-2 call table
  does not reach (`bytes(16)` with the JIT off), and −30 on `Sub(16)`.
- **Order of the tests:** already by likelihood (exact int first).

**Conclusion:** not performance-sensitive. Hand-written C with the same fast path would pay the
same test, and every shape stays 17–76 % below main. No "must inline" marker is needed.

## 2. Sub(16)
Callgrind of main vs after (seed 0, inclusive per call; `incl.py`):
- **After spends 74 more instructions in call structure than main.**
  - `bytes_new` is 12 instructions that only call `bytes_new_helper`, which clinic's
    `@vectorcall` generates upstream.
  - `bytes_new_impl(Sub)` calls `bytes_new_impl(&PyBytes_Type)` (22 instructions: a frame,
    and the NULL tests again), which then jumps to `bytes_new_nargs1`, which has its own frame.
- **The inline int path saves 41 of them** (the call of `PyNumber_AsSsize_t`), leaving +33.
- **Both builds pay 103 instructions** for the `int.__bytes__` lookup.

**Fix (spec, `edd5f1f6cfd`):** skip `_PyObject_LookupSpecial(source, "__bytes__")` when
`type(source) is not int`. An exact int has no `__bytes__`; this is the same kind of line as the
existing exact-bytes one.
- **Cost for everything else:** one flag test.
- **New difftest case:** `IntWithBytes(int)` with `__bytes__`.
- **Result:** `Sub(16)` is 3–9 % below main at every seed, and `bytes(16)` with the JIT off
  drops from 676 to 602.
- **Side effects:** `bytes(hb)` +12 and `bytes(ix)` +8 vs after, which is PGO layout: still
  −19 to −27 % vs main.

## 3. Proposals for B2's files (not implemented)
1. **`emit.py` / `partial_eval.py`: lower the call of a spec'd `__new__` with its own exact
   class, `T.__new__(T, a, b, c)` in `Generator.generate()`'s generic body, as the vectorcall's
   arity dispatch.**
   - The dispatch: `b == NULL && c == NULL ? (a == NULL ? T_new_nargs0() : T_new_nargs1(a)) : ...`.
   - Today it is lowered as `T_new_impl(&T_Type, ...)`.
   - This saves the 22-instruction level on every subclass construction of every spec'd type
     (`Sub(l16)` margin: −1 % to about −2 %).
   - The descriptions of `arities()` already have the facts.
2. **@inline paths may be pruned by hints, not only by facts.**
   - An @inline function equals its last return on every path; that is its contract, so a
     test could check each path against the native call. Dropping a path is therefore always
     sound.
   - In `Evaluator.expand()` (`paths_from`), a path could be dropped when a *hint* environment
     decides its test is false.
   - Hints: record, for each static spec function emitted generically, the environments at
     its call sites (`Evaluator.inline()`/`outline()`), treating `return FALLBACK` restarts as
     cold, and pass their meet as hints to `expand()` only.
   - `bytes_from_iterator` would lose the list/tuple tests: every caller except the
     snapshot's restart holds `Other({list, tuple})`. That saves 7 per call on iterators,
     generators, sets, dicts and ranges, with no annotation.
   - This is optional given section 1.
3. **Bug found:** a spec call with fewer arguments than parameters,
   `bytes.__new__(bytes, source)`, is emitted as `bytes_new_impl(&PyBytes_Type, source)`,
   which is a C call with the wrong arity. Defaults are not filled in, and no error is raised.

## Tests (debug JIT `../build-p4-p`)
- `test_clinic test_bytes test_mmap test_pyspec_facts test_pyspec_catalog
  test_tools.test_pyspec_parity test_opcache test_generated_cases`: SUCCESS.
- Parity with `PYSPEC_PARITY_BASELINE=../build-str1-dbg/python`: passes.
- `Tools/clinic/pyspec_review.py --baseline ../build-str1-dbg/python`: Result OK. There are
  no differences in 87,737 lines, and clinic's output is up to date.

## Open
- The hash-seed dependence of missing-method lookups affects every earlier micro table: they
  were taken with random seeds and best-of-5. Future comparisons should fix `PYTHONHASHSEED`.
- `PyObject_LengthHint` of a list iterator costs 362 instructions (a bound `__length_hint__`
  is created and called), 15 % of `bytes(iter(l16))`. Main pays the same.

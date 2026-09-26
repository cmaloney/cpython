## Performance review: exp/ac_python_overloads_v0 @ 62cc16504fe vs merge-base ee1bbf037ff

### Summary
**Builds.** I built a PGO+LTO release JIT build of 62cc16504fe in `/home/firebird347/projects/python/build_review_pgo`. It uses the same configure flags as `build_perf_base_jit`, plus `LLVM_TOOLS_INSTALL_DIR=/usr/lib/llvm21`, and was built from a `git archive` copy (the cpython checkout was not touched). Every measurement was taken with the JIT both on and off (`PYTHON_JIT=0`), serially, pinned to CPU 15, with the `performance` governor.

**Bottom line.** The branch makes `bytes()` *calls* much cheaper, but has no measurable end-to-end effect. Its one real regression is `bytes(list)` with many items, and I recovered most of that in a scratch experiment.

**Where the speed comes from** (instructions per loop iteration, including a 164-instruction empty loop; JIT on, base → branch):
- **Alias fact.** `bytes(b)` 923 → 219 (−76 %, cycles 186 → 43), `len(bytes(b))` 1018 → 314, `b.__bytes__()` 273 → 236. This only happens with the JIT on.
- **Constant fold.** `bytes()` 433 → 185.
- **Direct per-type C entry in tier 2.** `bytes(16)` 901 → 448, `bytes(bytearray)` 1124 → 657, `bytes(memoryview)` 1158 → 665, `bytes(sub)` 1131 → 776.
- **Generated `tp_vectorcall` and per-arity entries** (bytes had no vectorcall on main). This is the whole JIT-off gain: −20 to −24 % on every `bytes()` shape, and `bytes(s, encoding=)` −36 %. It is not specific to pyspec; a hand-written vectorcall would give the same.
- **WS11's derived iterator paths.** `bytes(range(256))` −27 % instructions (−19 % cycles JIT on, −36 % JIT off). `set`, `dict`, `iter(list)` and generators −12 to −26 %.
- **No-Python flag:** worth about 18 instructions per call (WS10's figure). Small.

**Neutral.** All bytes methods (within ±1 %, apart from hex/strip −3 to −5 % from the unrelated `_POP_TOP_OPARG(0)` → `_NOP` change), `==`, `hash`, `+`, `in`, `b[i]`, slicing, iteration, every `fromhex` form, `sub.__bytes__()`. WS12's generated types cost nothing. Startup: +0.1 % instructions, cycles within noise (−S −c pass 27.09 M → 27.12 M).

**Costs.**
1. **`bytes(list256)`:** +28 % instructions (6848 → 8777) and +38 % cycles (1222 → 1682), JIT on and off alike. That is 31.8 instructions per item against 22.8 on main, so WS11 understated it; WS11's baseline was already a pyspec build without PGO. `bytes(list16)` is still −18 % net because of the call savings, but +2 % cycles with the JIT off.
2. **`Sub(b)` and `Sub.fromhex`:** +54 instructions (+4 % / +2 %). Measured, root cause not investigated.
3. **Code size:** about +11 KB attributable to the branch:
   - bytes code +6.9 KB: the generic nargs1 is 2.4 KB, the per-type variants 2.8 KB, and the list/tuple loops are emitted three times;
   - `optimize_uops` +3.9 KB;
   - new stencils about 0.7 KB.

   Total .text grew +53 KB (+1.25 %), but about 42 KB of that is PGO/LTO inlining noise in unrelated functions.

**pyperformance (13 benchmarks, 3 JIT-on passes plus 1 JIT-off pass).**
- No benchmark shows a bytes-attributable change beyond the noise. Base-vs-base (A/A) runs of the *same binary* already come out "significant" by pyperf at ±1–2 %, so I don't trust any ±1–2 % result.
- Geomean: JIT on −0.9 % / −0.5 % over the two passes, with the A/A pair at −0.5 %. JIT off −1.0 %.
- **regex_dna −10 to −15 % is not caused by the branch.** Instructions only drop 2.4 %. `sre_ucs1_charset` falls from 30.6 % to 23.2 % of cycles, which is different `_sre` code generation from PGO/LTO. WS6 bounded bytes calls there at ≤ 0.05 %.
- **A layout artifact to be aware of:** JIT-off `for c in b16/l16/t16/s16` loops show +25 to +35 % cycles with *identical* instruction counts. Across three builds that differ only in bytesobject.c, the same loop measures 298, 356 and 413 cycles. Single-build cycle comparisons of tier-1 loops are only good to about ±30 %.

**Recovering the list regression (scratch experiments; cpython untouched):**
- **E1:** keep the appender in registers. `bytes_appender_create` and `grow` return a 24-byte struct through memory, which forces the cursor onto the stack; I changed them to scalar arguments and a two-pointer return. Result: −270 to −530 instructions on list256, −40 to −50 on list16/tuple16, −6 to −8 % cycles on range256 and tuple16.
- **E2 = E1 plus "borrowed until Python may run" (done by hand in the generated code) plus `PyList_GET_SIZE` for exact lists:**
  - list256: 8772 → 7433 instructions (main 6849); JIT-off cycles 1645 → 1187 (main 1216, so fully recovered); JIT-on cycles 1679 → 1655 (not recovered, and branch misses are negligible, so this looks like layout/memory effects).
  - list16: 1088 → 952 (main 1330).
  - The remaining gap is about 4 instructions per item: a capacity check on every append, the separate bool branch, and the −1/`PyErr` check.

**Next levers**, estimated from reference ops measured on the same builds:
1. **`BINARY_OP_SUBSCR_BYTES_INT`:** `b[i]` costs 141 instructions net against 58 for `l[i]` and 56 for `s[i]`, a saving of about 84 instructions and 16 cycles per op. On pyflate (1.28 M bytes subscripts per loop) that is about 2.3 % of instructions, roughly 1.5–2 % of time. This is the largest end-to-end bytes lever.
2. **`FOR_ITER` over bytes, using the `bytes_iterator.__next__` facts:** 93 → about 62 instructions per item and 18.7 → about 11 cycles per item. On pyflate (672 K items per loop) that is about 0.45 %. The exact-int fact on the loop variable saves another 2–3 instructions per item.
3. **Bytes `==`:** saves about 96 instructions per op (str is the reference). `hash(b)` offers nothing to gain. `+` only matters with an in-place `+=` (pickle_pure_python's `_PyBytes_Concat` is 4.3 %; realistic gain 1–2 %).
4. **`bytes.fromhex`:** 1539 → about 1040 (−33 %) if class-method `LOAD_ATTR` were specialized. The trace currently stops there, so the derived fromhex facts are never used.
5. **`PyNumber_AsSsize_t` as a spec:** about 18 instructions per `bytes(16)` call and the list-loop lowering. End-to-end speed ≈ 0; its value is in correct facts.
6. **Other types:**
   - `int(i)`: 163 instructions net through the generic `_CALL_BUILTIN_CLASS`; an alias fact would bring it to about 55 (−108).
   - `float(i)` (288 net) and `list(l16)` (924 net) could gain about 30–200 from a direct per-type entry.
   - `str(x)` and `tuple(x)` already have hand-written `_CALL_STR_1` / `_CALL_TUPLE_1` (113 / 93 net). pyspec would add correctness there (the `_CALL_STR_1` exact-type bug), not speed.

---

## Full report

### 1. Builds

| build | commit | configure | notes |
|---|---|---|---|
| `build_perf_base_jit` (existing) | ee1bbf037ff (`../cpython-base`) | `--with-static-libpython --with-tail-call-interp --with-lto --enable-optimizations --enable-experimental-jit CC=clang LDFLAGS=` | clang 22.1.8 |
| `build_review_pgo` (new) | 62cc16504fe (archived to `scratchpad/review_perf/src`) | same flags + `LLVM_TOOLS_INSTALL_DIR=/usr/lib/llvm21` | 10 min PGO; profile task passed |
| `review_perf/build_e1`, `build_e2` | 62cc16504fe + experiments | same | scratch only |

- **Command:** `systemd-run --user --scope -q -p MemoryMax=12G -p MemorySwapMax=0 -- review_perf/build.sh` runs configure, then `make -j8`. Builds ran serially after a `free -g` check.
- **Source location:** `build_review_pgo`'s srcdir is the tmpfs copy `scratchpad/review_perf/src`. It must stay in place for `build_review_pgo/python` to find `Lib/`.

### 2. Micro method (same as ws6/ws10/ws11)

- **Script:** `review_perf/measure.sh PY LABEL [ops]` runs `perf stat -x, -e instructions:u,cycles:u taskset -c 15 PY micro.py OP N` for N = 0.1 M and 1.1 M, 5 runs each.
  - Instructions = (best of 1.1 M − best of 0.1 M) / 1 M.
  - Cycles = difference of the minimums (the spread of paired diffs is in the raw files).
- **Driver:** `run_micro.sh` does JIT on then off, base then review, under `systemd-run ... MemoryMax=8G`.
- **Kernel:** `review_perf/micro.py`, the ws6/ws11 shapes plus extra ops. Setup is in locals with no closure cells: an earlier pilot had `b16`/`l16` as cells, and those numbers were discarded.
- **Traces:** from `_opcode.get_executor` via `review_perf/traces.py`, in `traces_build_*.txt`.
- **Raw data:** `micro_run2.txt` (all ops), `micro_run3.txt` (rerun plus reference ops), `micro_exp*.txt`.

**Table (instructions per iteration including the loop; cycles are min-diff and stable to within about 2 % unless noted). Arrows are base → branch.**

| op | JIT on instr | JIT on cyc | JIT off instr | JIT off cyc | branch trace (JIT) |
|---|---|---|---|---|---|
| empty | 164 → 164 | 35 → 34 | 136 → 136 | 25 → 25 | |
| `bytes()` | 433 → 185 (−57 %) | 83 → 38 | 423 → 326 (−23 %) | 78 → 59 | const fold |
| `bytes(b16)` | 923 → 219 (−76 %) | 186 → 43 | 936 → 728 (−22 %) | 190 → 152 | `_GUARD_TYPE _MAKE_HEAP_SAFE _SWAP_3` (no call) |
| `len(bytes(b16))` | 1018 → 314 | 203 → 63 | 1049 → 841 | 209 → 177 | |
| `bytes(ba16)` | 1124 → 657 (−42 %) | 225 → 145 | 1122 → 892 | 226 → 187 | `_CALL_BUILTIN_CLASS_1_INLINE_NO_PYTHON` |
| `bytes(mv16)` | 1158 → 665 | 233 → 155 | 1156 → 897 | 233 → 201 | NO_PYTHON |
| `bytes(16)` | 901 → 448 (−50 %) | 168 → 92 | 902 → 697 | 164 → 132 | `_1_INLINE` (may run Python) |
| `bytes(s,'ascii')` | 1046 → 766 (−27 %) | 190 → 145 | 1059 → 802 | 189 → 149 | generic `_CALL_BUILTIN_CLASS` |
| `bytes(s,'utf-8')` | 1082 → 787 | 198 → 152 | 1090 → 828 | 201 → 154 | |
| `bytes(s, encoding=)` | 1658 → 1044 (−37 %) | 313 → 190 | 1698 → 1087 | 323 → 196 | `_CALL_KW_NON_PY` |
| `bytes(list16)` | 1329 → 1088 (−18 %) | 249 → 223 | 1331 → 1268 (−5 %) | 245 → 250 (+2 %) | `_GUARD_TYPE _1_INLINE` |
| **`bytes(list256)`** | **6848 → 8777 (+28 %)** | **1222 → 1682 (+38 %)** | **6845 → 8711 (+27 %)** | **1217 → 1642 (+35 %)** | |
| `bytes(tuple16)` | 1339 → 993 (−26 %) | 248 → 214 | 1336 → 1175 | 244 → 220 | |
| `bytes([T,F]*8)` | 1330 → 1136 | 249 → 218 | 1331 → 1332 | 244 → 258 (+6 %) | |
| `bytes(range16)` | 2775 → 1951 (−30 %) | 543 → 416 | 2766 → 2034 | 542 → 402 | NO_PYTHON |
| `bytes(range256)` | 25572 → 18755 (−27 %) | 5144 → 4188 | 25568 → 16673 (−35 %) | 5168 → 3309 | |
| `bytes(iter(l16))` | 3193 → 2354 | 659 → 497 | 3249 → 2486 | 687 → 528 | |
| `bytes(gen())` | 7093 → 6247 | 1498 → 1340 | 6790 → 6032 | 1452 → 1305 | |
| `bytes(set8)` / `bytes(dict8)` | 2306 → 1711 / 2215 → 1637 | −25 % / −24 % | −21 % / −22 % | −21 % / −22 % | |
| `bytes(sub)` | 1131 → 776 (−31 %) | 221 → 161 | 1128 → 890 | 217 → 174 | generic entry (correct) |
| `bytes(obj with __bytes__)` | 1313 → 964 | 258 → 195 | 1237 → 1006 | 245 → 205 | |
| **`Sub(b16)`** | **1326 → 1380 (+4 %)** | 268 → 277 | **1308 → 1358 (+4 %)** | 271 → 277 | |
| `b16.__bytes__()` | 273 → 236 (−14 %) | 53 → 46 | 310 → 310 | 58 → 58 | `_COPY_1 _MAKE_HEAP_SAFE _SWAP_3` |
| `sub.__bytes__()` | 713 → 713 | = | 615 → 620 | = | |
| `bytes.fromhex(h)` | 1549 → 1539 | = | 1461 → 1476 | +2 % | trace ends at `_LOAD_ATTR` |
| `fromhex(h)` (bound local) | 1036 → 1041 | = | 957 → 962 | = | |
| `b.fromhex(h)` | 1449 → 1453 | = | 1350 → 1359 | = | |
| `Sub.fromhex(h)` | 2543 → 2598 (+2 %) | 520 → 523 | 2458 → 2518 | 500 → 520 | |
| split / find / decode / join / hex | ±0 to −3 % | ±3 % | ±0 to +2 % | ±3 % | |
| startswith / replace / upper / strip / center / isalpha / count / len | ±0 (strip −5 %) | ±2 % | ±0 | ±2 % | |
| `==` / `hash` / `+` / `in` / `b[i]` / `b[1:5]` | ±0 | ±3 % | ±0 | noise | generic `_COMPARE_OP`, `_CALL_BUILTIN_O`, `_BINARY_OP_EXTEND`, `_CONTAINS_OP`, `_BINARY_OP` |
| `for c in b16` / `b256` | 1653 → 1653 / 20856 → 20856 | = | 1452 = / 19938 = | **282 → 352, 3926 → 5004 (layout artifact, see §4)** | `_FOR_ITER_VIRTUAL_TIER_TWO` |
| `for j in r16: t += b16[j]` | 5450 = | = | 6282 = | = | |

**Reference points on the same builds** (instructions per iteration, JIT on; cycles in parentheses):
- **Subscript:** `l16[i]` 222 (44), `s16[i]` 220 (43), `ba16[i]` 333, `b16[i]` 305 (60).
- **Iteration:** `for c in l16` 1197 (208), `for c in t16` 1115 (191), `for c in s16` 2321, `for c in b16` 1653 (333).
- **Str ops:** `s == s2` 253 (54) against `b == b2` 349 (72); `s + s` 511; `hash(s)` 478.
- **Calls:** `str(s)` 277, `tuple(t16)` 257, `tuple(l16)` 721, `list(l16)` 1088, `int(i)` 327, `int('12')` 767, `float(i)` 452, `str(i)` 759.

### 3. Attribution: what helps, by how much
Per call, from the JIT on/off and base/branch pairs:

- **Generated vectorcall and per-arity entry** (tier 1 now specializes `CALL_BUILTIN_CLASS`): −200 to −260 instructions per `bytes()` call in both tiers, and −610 for the keyword form. This is the whole JIT-off gain, and it matches WS6's −225 to −261. Any hand-written bytes vectorcall gets this.
- **Tier-2 direct call to the per-type function** (compared with the same branch with the JIT off): `bytes(16)` −249, `bytes(ba16)` −235, `bytes(sub)` −114. Two-argument calls have no direct entry: `bytes(s,'ascii')` gains only −36.
- **Alias fact** (WS10): `bytes(b)` −509 beyond the direct call (728 JIT off → 219). `b.__bytes__()` −37 compared with base with the JIT on.
- **Constant fold:** `bytes()` −141 compared with the JIT-off branch.
- **No-Python flag:** about 18 instructions per call (WS10 measurement); it skips the spill and `_SET_IP`.
- **Exact result type:** only removes downstream guards (the `len(bytes(b))` chain). A few instructions per use.
- **WS11 derived loops:** faster for range/set/dict/iter/generators (range256 −27 instructions per item), slower for list/bool (below).
- **WS12 generated types:** neutral. It is the enabler for the slot and iterator facts.

### 4. Costs
- **`bytes(list)` per item** (branch disassembly of `bytes_new_nargs1_list`): about 30 instructions per item against about 23 on main, where each item was one call to `PyLong_AsSsize_t`. The extra work per item:
  - an immortal check on incref and decref of each item (small ints are immortal, but the checks still run);
  - two type compares (int, bool);
  - a −1/`PyErr` check;
  - a capacity check on every append;
  - a size reload;
  - the appender cursor spilled to the stack, because `bytes_appender_create`/`grow` return a 24-byte struct through a hidden memory pointer, so clang keeps the struct in memory. This is a loop-carried dependency through memory, and is the likely source of the +2 cycles per item.
- **`Sub(b)` and `Sub.fromhex`:** +54 instructions (subclass `tp_new` path).
- **Code size.** `size -A` .text: 4,250,851 → 4,303,987 (+53 KB). The symbol-level diff (`syms_*.txt`) attributes about 11 KB to the branch:
  - `bytes_new_nargs1` +2440 bytes
  - per-type variants: list 595, tuple 538, range 630, dict 653, int 177, float 150
  - `bytes_new_impl` 904, `bytes_from_iterator` 815
  - `bytes_vectorcall` 527, `bytes_new_helper` 487
  - `_PySpec_FindCall` 324
  - appender 403
  - `PyBytes_FromObject` −690, `bytes_new` −1334
  - `optimize_uops` +3872
  - new JIT stencils: about 0.7 KB of `emit__CALL_BUILTIN_CLASS_*`

  The remaining roughly 42 KB is PGO/LTO inlining noise in unrelated functions (`_PyTokenizer_Get` +6.7 KB, `unicode_from_format` +4.6 KB, `_PyType_LookupStackRefAndVersion` −3.7 KB, …). Stripped binary: 7,746,240 → 7,807,680 bytes.
- **Worth pruning:**
  - The list/tuple loops appear three times: in `PyBytes_FromObject`, in the generic nargs1, and in the per-type entries.
  - The dict and float variants cover rare shapes.
- **Layout artifact, not a cost of the branch:** in JIT-off iteration over bytes, lists, tuples and str, instructions are identical but cycles are +25 to +35 %. The same `for c in b16` loop measured 298, 356 and 413 cycles in review, E1 and E2, which differ only in bytesobject.c.

### 5. End to end
**Command:** `review_perf/run_pyperf.sh base:1 review:1 base:0 review:0 base:1 review:1`
- It runs `perf_runner_venv/bin/pyperformance run --inherit-environ PYTHON_JIT -b dulwich_log,base64,asyncio_tcp,bpe_tokeniser,pyflate,pickle_pure_python,unpickle_pure_python,regex_dna,tornado_http,nbody,richards,json_loads,go --python=... -o review_perf/pyperf/<b>_jit<j>_<HHMM>.json`.
- The whole run was inside `systemd-run ... MemoryMax=12G`. Governor `performance`, load average about 1, serial.
- No benchmarks failed. dask, genshi and fastapi were not in the list.
- `pyperf compare_to -G` output for every pair is in `review_perf/pyperf/compare.txt`.

**Median change, branch vs base** (negative = faster):

| benchmark | JIT pass A | JIT pass B | A/A base | A/A branch | JIT off | pyperf sig. (A / B / off) |
|---|---|---|---|---|---|---|
| asyncio_tcp | +1.6 % | +0.8 % | +0.1 | −0.7 | +0.5 | 1.02x slower / 1.01x slower / ns |
| base64 group (12 sub-benchmarks) | −0.1 to −2.5 % | 0 to −1.8 % | 0 to −1.2 | ≤ 0.8 | −1.2 to +3.5 | several "1.00–1.03x" |
| bpe_tokeniser | +1.0 % | +1.4 % | −0.4 | 0.0 | −0.7 | 1.01x / 1.02x slower / 1.01x faster |
| dulwich_log | +0.2 % | +0.8 % | −0.8 | −0.2 | −0.2 | ns / ns / ns |
| go | +0.5 % | +0.5 % | −0.1 | −0.1 | −1.9 | ns |
| json_loads | −0.8 % | +0.2 % | −1.8 | −0.8 | −0.7 | ns (but A/A 1.02x "sig") |
| nbody | +0.7 % | +0.2 % | −0.7 | −1.2 | −4.3 | ns / ns / 1.03x faster |
| pickle_pure_python | −1.0 % | −1.1 % | −0.6 | −0.7 | −3.5 | 1.01x / 1.02x / 1.04x faster |
| pyflate | −0.5 % | −0.8 % | +0.3 | 0.0 | −1.9 | ns / 1.01x / 1.02x faster |
| regex_dna | −13.7 % | −9.8 % | −0.5 | +4.1 | −11.1 | 1.15x / 1.10x / 1.13x faster (not bytes, see below) |
| richards | +0.9 % | +1.3 % | −0.7 | −0.3 | −0.4 | 1.01x / 1.03x slower / ns |
| tornado_http | +0.7 % | +0.8 % | +0.1 | +0.1 | −2.0 | ns |
| unpickle_pure_python | +1.4 % | +0.3 % | +0.3 | −0.8 | +0.4 | 1.01x slower / ns / ns |
| geomean | −0.9 % | −0.5 % | −0.5 | −0.1 | −1.0 | |

**Reading it:**
- pyperf marks 13 of 23 results "significant" between two runs of the *same* base binary, so anything within ±1–2 % is noise.
- **pickle_pure_python** (−1 % JIT on, −3.5 % JIT off) is the only small, consistent candidate, but WS6 found no Python-to-C bytes calls in it. I don't attribute it to the branch.
- **regex_dna** is `_sre` code generation. `review_perf/regex_dna_run.py` under perf stat gives, per iteration:

  | build | instructions | cycles |
  |---|---|---|
  | base | 1960.6 M | 626 M |
  | branch | 1913.0 M | 522 M |
  | E1 | 1888.7 M | 545 M |
  | E2 | 1897.4 M | 545 M |

  `perf record` shows `sre_ucs1_charset` at 30.6 % of cycles on base against 23.2 % on the branch (`sre_ucs1_match` +1443 bytes in the branch binary). WS6 bounded bytes calls in regex_dna at ≤ 0.05 %.
- **Conclusion:** no bytes-attributable end-to-end change. That is consistent with WS6's bounds: ≤ 0.7 % for dulwich_log, ≤ 0.1 % for the rest.

**Startup** (`review_perf/startup.sh`: `perf stat -r 40`, CPU 15, two repeats; base → branch):

| command | instructions | cycles | task-clock (ms) |
|---|---|---|---|
| `-S -c pass` | 27.09 M → 27.12 M (+0.1 %) | 16.78 M → 16.79–16.85 M | 4.75 → 4.73 |
| `-c pass` | 39.21 M → 39.25 M | 24.46 M → 24.45 M | 6.39 → 6.35 |
| `-X importtime -c pass` | 39.29 M → 39.33 M | = | = |
| import json, re, asyncio, base64, pickle, email.parser | 260.94 M → 260.92 M | 164.0 M → 163.3 M | 37.6 → 37.5 |

Median summed top-level `-X importtime` (30 runs): 3144 µs base, 3129 µs branch. Startup effect: none.

### 6. Recovering the list regression (experiments, scratch only)
- **E1** (`review_perf/e1_appender.diff`, bytesobject.c): no noinline helper takes or returns the whole appender struct. `bytes_appender_start(writer)` and `bytes_appender_grow(writer, str, end)` return a two-pointer struct in registers, and `init`/`append` stay always-inline.
- **E2** (E1 plus `review_perf/e2_generated.diff`, a hand edit of the generated `bytesobject_pyspec.c.h`, GIL build only):
  - list items are borrowed (`PyList_GET_ITEM` without `Py_NewRef`);
  - the int and bool branches take no reference;
  - the generic branch does `Py_INCREF`, then `PyNumber_AsSsize_t`, then `Py_DECREF`;
  - `PyObject_LengthHint(list, 64)` becomes `PyList_GET_SIZE`.
- **Checks:** a semantic spot check (bool, `__index__`, out-of-range) passed on both, and `test_bytes` passed on E2. The builds used the same flags as `build_review_pgo`.

| op | base | branch | E1 | E2 |
|---|---|---|---|---|
| list256 instr JIT on / off | 6849 / 6844 | 8772 / 8712 | 8502 / 8185 | 7433 / 7370 |
| list256 cyc JIT on / off | 1223 / 1216 | 1679 / 1645 | 1671 / 1518 | 1655 / **1187** |
| list16 instr JIT on / off | 1330 / 1332 | 1088 / 1273 | 1049 / 1224 | **952 / 1126** |
| bools16 instr JIT on / off | 1329 / 1325 | 1136 / 1332 | 1098 / 1362 | 995 / 1269 |
| tuple16 instr JIT on | 1333 | 993 | 939 | 941 |
| range256 instr / cyc JIT on | 25572 / 5144 | 18755 / 4243 | 18225 / 3917 | 18228 / 3938 |

**Reading the experiments:**
- E2 recovers most of the instructions: list256 is still +8.5 % against main, and every short list/tuple/bool case is now 17–29 % faster than main.
- It also recovers all the JIT-off cycles.
- The JIT-on per-type copy stays at about 1655 cycles. Branch misses are 0.4–1.5 M per run, so negligible; it is layout/memory-order sensitive in the same way as §4.

**Recommendations for the emitter:**
1. Never pass the appender struct through a noinline helper by value or through a returned struct; E1's shape is the one to use.
2. Add the "borrowed until Python may run" ownership rule. A borrowed load stays borrowed along paths whose statements the evaluator proves run no Python (here: exact int/bool, compact read, range check, append). A path that may run Python takes a strong reference first. In the free-threaded build, keep `_PyList_GetItemRef`, or borrow only under a critical section when the whole loop body is proven Python-free, which is never provable for a list.
3. For an exact list or tuple, use the known length and not `PyObject_LengthHint`.
4. To close the last ~4 instructions per item:
   - merge the bool branch into int (bool items are compact ints);
   - drop the −1/`PyErr` test on the compact path, which cannot fail;
   - hoist the capacity check. Pre-size to the length and check once per restart, since only the Python-running generic branch can grow the list.

### 7. Next levers (estimates from the measurements above)

| lever | per-op saving (measured proxy) | end-to-end estimate |
|---|---|---|
| `BINARY_OP_SUBSCR_BYTES_INT` (result: exact small immortal int, no Python, IndexError only) | `b[i]` 141 → ~57 instructions net, 26 → ~10 cycles (proxies: `l[i]` 58, `s[i]` 56) | pyflate: 1.28 M subscripts/loop × 84 ≈ 107 M of 4.7 G instructions ≈ 2.3 %, about 1.5–2 % time. Others ≈ 0 |
| `FOR_ITER` specialized for `bytes_iterator`, using WS12's `__next__ -> New[int]` fact (no escape, loop variable exact int, drops `_GUARD_TOS_INT` downstream) | 93 → ~62 instructions per item, 18.7 → ~11 cycles per item (proxies: list 64.5, tuple 59) | pyflate 672 K items/loop ≈ 0.45 %; dulwich/base64 < 0.1 % |
| Bytes `==` specialization (`COMPARE_OP_BYTES`) | 185 → ~89 net (str proxy) | dulwich_log part of its 2.8 % slot share; about 0.3–0.5 % |
| `hash(b)` | already equal to `hash(s)` | 0 |
| `b + x` / `+=` | `+` already `_BINARY_OP_EXTEND` (≈ str + str); only an in-place resize for `+=` would help | pickle_pure_python ≤ 4.3 % bound, realistic 1–2 % |
| Class-method `LOAD_ATTR` specialization, so `bytes.fromhex(...)` reaches the fromhex facts | 1539 → ~1040 (bound-local proxy), −33 % | small; `fromhex` is rare in the benchmarks |
| `PyNumber_AsSsize_t` as a spec | `bytes(16)` → NO_PYTHON variant, about −18 instructions (~4 % of call); derives the int/bool lowering WS11 wrote by hand | ≈ 0 speed; facts value only |
| Apply to `int`/`float`/`list` constructors | `int(i)` 163 net through generic `_CALL_BUILTIN_CLASS` → ~55 with an alias fact (like `bytes(b)`); `float(i)` 288 and `list(l16)` 924 net → direct per-type entries save ~30–250 | real but unmeasured in pyperformance; `int(x)`/`list(x)` are common |
| Apply to `str`/`tuple` | `str(s)` 113 net and `tuple(t)` 93 net already come from hand-written `_CALL_STR_1`/`_CALL_TUPLE_1` | ≈ 0 speed; gain is correctness (conditioned facts fix the `_CALL_STR_1` exact-type UAF in bugreports/call-str-1-subclass) and replacing the hand-written rules WS10 listed |
| Method result facts (`decode` → str, `encode` → bytes, `_CALL_METHOD_DESCRIPTOR_O`/`_CALL_BUILTIN_O` rules) | removes downstream type guards, a few instructions each | < 0.5 % |
| Two-argument direct entries for `bytes(s, 'ascii')` (constant encoding, no Python) | blocked on per-constant table entries; the generic path costs 766 against about 450 for the one-argument direct shapes | small |

**Priorities:**
1. Put the list fix into the emitter: E1's shape plus borrowing.
2. Slot facts plus hand-written specializations for bytes subscript, iteration and `==`. This is the only place with measurable end-to-end gains (~2 % pyflate).
3. Extend the constructor/alias machinery to `int`, `float` and `list`.
4. Prune the triplicated list/tuple loops and the rare per-type variants (dict, float) to hold the code size down.

### Files (all under `/tmp/claude-1000/-home-firebird347-projects-python/50cf0ce0-5ab0-4e7c-ba5f-65e16f35a2bb/scratchpad/review_perf/`)
- **Scripts:** `micro.py`, `measure.sh`, `run_micro.sh`, `run_exp.sh`, `traces.py`, `startup.sh`, `run_pyperf.sh`, `regex_dna_run.py`, `build.sh`, `build_exp.sh`
- **Data:** `micro_run2.txt`, `micro_table.txt`, `micro_run3.txt`, `micro_exp.txt`, `micro_exp2.txt`, `traces_build_*.txt`, `startup.txt`, `syms_*.txt`, `pyperf/*.json`, `pyperf/compare.txt`, `rdna_*.data`
- **Experiments:** `e1_appender.diff`, `e2_generated.diff`, `src_e1/`, `src_e2/`, `build_e1/`, `build_e2/` (about 580 MB each on tmpfs; can be deleted)
- **Build:** `/home/firebird347/projects/python/build_review_pgo`, whose source is `review_perf/src`
- **Not used:** `micro_pilot_cells.txt`, the discarded pilot with closure cells.

# Phase 4 final: performance of the branch tip vs main

**Verdict: not a win across the board.** Every `bytes()` call shape, `Sub(...)`, `Sub.fromhex`,
`b16[i]` and iteration are 1–77 % below main. But `bytearray(b16)` is **+24 instructions
(+1.9 %) and +1–2 % cycles** at every seed. The `fromhex` family is +5 to +7 instructions
(+0.4 %) at every seed, with flat cycles. `b16 == b16c` is +2 instructions.

## Builds and method (phase4_P's)
- main = `ee1bbf037ff`, tip = `e9cb6e365a4`. Sources were in detached worktrees
  `../p4f-src/{main,tip}` (removed after measuring). Builds are out of tree in
  `../p4f-perf/{main,tip}`, and no longer run without their sources.
- Configure: `--with-static-libpython --with-tail-call-interp --with-lto --enable-optimizations
  --enable-experimental-jit LLVM_TOOLS_INSTALL_DIR=/usr/lib/llvm21`, with CC=clang 21.1.8
  (`PATH=/usr/lib/llvm21/bin`). Each build was made serially with `make -j8` under
  `systemd-run MemoryMax=12G`.
- Measurement: `Tools/clinic/pyspec_bench.py --cpu 15 --repeat 5 --cycles`, JIT on and off,
  `PYTHONHASHSEED=1`, under `systemd-run MemoryMax=8G`. The governor was `performance` and
  the load average 1.1–1.5; the seed-1 run began at 8 while the builds wound down.
  - Instructions and minimum cycles are per iteration, loop included.
  - `tip_aa` is a second measurement of the same tip binary, interleaved in the same run (A/A).
  - Shapes within 2 % of main were measured again at seeds 0 and 7.
- Setup and statements: phase4_P's setup, plus phase1_A's `b16c`, `b16s`, `h16` and
  `fromhex`. The statements are the 29 `bytes()` shapes of phase1_A (`pass` … `Sub.fromhex`),
  phase4_P's extras (`t256`, `bytes(ix)`, `Sub(16)`, `Sub(l16)`, `b16[i]`,
  `for c in b16`) and five methods.
- Raw data and scripts: `../p4f-perf/data/` (`seed1.txt`, `seed0.txt`, `seed7.txt`,
  `setup.py`, `stmts.txt`, `run.sh`, `build.sh`).

## Table (seed 1; instructions · cycles; main → tip; A/A in the note)
| shape | JIT on | JIT off |
|---|---|---|
| `bytes()` | 433→184 · 81→38 | 425→325 · 84→60 |
| `bytes(b16)` | 926→218 · 187→42 | 937→385 · 190→72 |
| `len(bytes(b16))` | 1021→313 · 204→63 | 1049→497 · 211→98 |
| `bytes(ba16)` | 1134→678 · 227→152 | 1132→902 · 227→193 |
| `bytes(mv16)` | 1167→689 · 237→154 | 1165→911 · 236→190 |
| `bytes(16)` | 911→445 · 170→97 | 912→606 · 168→119 |
| `bytes(s16,'ascii')` | 1074→789 · 195→152 | 1089→830 · 202→158 |
| `bytes(s16,'utf-8')` | 1108→818 · 205→157 | 1123→859 · 208→164 |
| `bytes(s16,encoding=)` | 1687→1070 · 317→198 | 1737→1122 · 329→210 |
| `bytes(l16)` | 1340→812 · 255→160 | 1336→1029 · 249→192 |
| `bytes(l256)` | 6845→5123 · 1220→859 | 6840→5340 · 1216→894 |
| `bytes(t16)` | 1353→816 · 255→164 | 1349→1046 · 249→195 |
| `bytes(t256)` | 6863→5134 · 1220→855 | 6854→5358 · 1215→889 |
| `bytes(bl16)` | 1340→860 · 254→178 | 1336→1077 · 247→202 |
| `bytes(r16)` | 2779→1836 · 546→366 | 2775→2047 · 549→401 |
| `bytes(r256)` | 25567→16714 · 5140→3257 | 25563→16918 · 5141→3273 |
| `bytes(iter(l16))` | 3193→2352 · 657→485 | 3250→2494 · 674→502 |
| `bytes(gen())` | 7098→6257 · 1476→1315 | 6805→6050 · 1441→1266 |
| `bytes(s8)` | 2422→1813 · 483→363 | 2418→1930 · 485→383 |
| `bytes(d8)` | 2230→1623 · 454→327 | 2227→1740 · 455→348 |
| `bytes(sub)` | 1133→784 · 225→165 | 1129→901 · 225→179 |
| `bytes(hb)` | 1305→957 · 259→192 | 1227→1000 · 243→200 |
| `bytes(ix)` | 1456→1115 · 287→233 | 1365→1145 · 270→230 |
| `Sub(16)` | 1312→1266 · 259→252 | 1296→1244 · 255→246 |
| `Sub(b16)` | 1332→1035 · 272→198 | 1307→1010 · 273→192 |
| `Sub(l16)` | 1747→1723 · 346→335 | 1720→1697 · 345→334 |
| `b16.__bytes__()` | 272→235 · 53→46 | **313→314** · 59→60 |
| `sub.__bytes__()` | 724→722 · 141→141 | 634→632 · 121→121 |
| `bytes.fromhex(h16)` | **1607→1609** · 322→324 | **1532→1539** · 313→314 |
| `fromhex(h16)` | **1051→1061** · 198→204 | **975→980** · 180→180 |
| `b16.fromhex(h16)` | **1502→1508** · 301→300 | **1412→1418** · 294→295 |
| `Sub.fromhex(h16)` | 2578→2289 · 539→464 | 2487→2197 · 523→448 |
| `b16[i]` | 306→207 · 60→41 | 315→220 · 59→41 |
| `for c in b16: pass` | 1652→1109 · 334→205 | 1454→1165 · 372→283 |
| `b16s.split()` | 1811→1790 · 342→342 | 1811→1808 · 348→345 |
| `b16.hex()` | 602→586 · 118→116 | 602→598 · 114→113 |
| `b16 == b16c` | **348→350** · 67→68 | **339→341** · 78→63 |
| `hash(b16)` | 484→484 · 101→100 | **498→499** · 104→102 |
| `bytearray(b16)` | **1251→1275 · 242→249** | **1249→1273 · 242→247** |
| `pass` (loop) | 163→163 · 34→34 | 138→138 · 25→26 |

- **A/A (tip vs tip_aa, same binary):** most shapes agree within ±7 instructions and ±2 cycles.
  - `b16s.split()`, `b16.hex()` and `hash(b16)` are bimodal: split takes 1790/1811 or
    1826/1844 from process to process, and hex and hash vary by ±5 to 6.
  - So their ±2 % against main is noise, and main shows the same two modes (1811 vs 1844).

## Seeds 0 and 7 (shapes within 2 % of main at seed 1)
| shape | seed 0 on/off (instr) | seed 7 on/off (instr) |
|---|---|---|
| `Sub(16)` | −6.3 / −6.4 % | −3.9 / −4.4 % |
| `Sub(l16)` | −1.7 / −1.4 % | −1.3 / −1.4 % |
| `b16.__bytes__()` | −13.6 % / **+1** | −13.6 % / **+1** |
| `sub.__bytes__()` | −2 / −1 | −1 / −1 |
| `bytes.fromhex(h16)` | **+6 / +6** | **+7 / +7** |
| `fromhex(h16)` | **+5 / +5** | **+5 / +5** |
| `b16.fromhex(h16)` | **+5 / +5** | **+6 / +6** |
| `b16s.split()` | −18 / 0 (A/A −54 / −33) | −51 / 0 |
| `b16.hex()` | −21 / −4 | −22 / +2 (A/A −5) |
| `b16 == b16c` | **+2 / +2** | **+2 / +2** |
| `hash(b16)` | +5 / −1 (A/A 0 / 0) | +1 / +1 |
| `bytearray(b16)` | **+24 / +24** (cycles +5 / +2) | **+24 / +24** (cycles +3 / 0) |

## Conclusion
- **At or above main at every seed:**
  - `bytearray(b16)`: +24 instructions (+1.9 %), with cycles +1–2 %. This is the only real
    regression. `bytearray` is spec'd on the branch (phase 3b), so it is branch code, not
    layout.
  - `bytes.fromhex`, `fromhex` and `b16.fromhex`: +5 to +7 instructions (+0.4 %). Cycles are
    flat, and phase1_A saw the same +1–2 % from PGO build variance.
  - `b16 == b16c`: +2 instructions, with equal or lower cycles.
  - `b16.__bytes__()` with the JIT off: +1 instruction.
- **Within A/A noise:** `hash(b16)`, `b16.hex()` and `b16s.split()`.
- **Everything else is below main**, JIT on and off.
  - `Sub(l16)` is −1.3 to −1.7 %, a thin but consistent margin.
  - `Sub(16)` is −3.5 to −6.4 %.
- **Not a win across the board:** `bytearray(b16)` needs a fix first. The `fromhex` +0.4 %
  should be checked with a second PGO build.

## Follow-up: root causes and fix (fix = `737069ca773`)
Builds: `tip2` is a second PGO+LTO build of the tip source (A/A across builds), and `fix` is
`737069ca773`. Both use the same flags, and both are kept in `../p4f-perf/`. Data:
`../p4f-perf/data/fix_seed{1,0,7}.txt` (full list at seed 1; `fix_close.txt` at seeds 0 and 7).
Callgrind: seed 0, JIT off, 2000 iterations minus 0, one run at a time under an 8G cap.

### `bytearray(b16)` +24: PGO profile noise in unchanged code, not branch code
- **Callgrind (main / tip / tip2):** 1241 / 1265 / 1237 per iteration.
  - The only difference: `_PyBytes_FromSize` is 0 / 40 / 0 instructions of self cost, and
    `_PyBytes_ResizeKeepOnError` is 57 / 41 / 57.
  - In tip, the `oldsize == 0` call is out of line. In main and tip2 it is inlined.
  - `bytearray___init__`, the buffer calls, `type_call` and `bytearray_new` are identical.
    `Objects/clinic/bytearrayobject.c.h` is byte-identical to main.
- **Inline remarks** (`-Rpass-missed=inline` with each build's `code.profclangd`): main
  inlines at `cost=185, threshold=250`. Tip gives the site the cold threshold, 45.
- **Cause: clang front-end branch weights.** `_PyBytes_ResizeKeepOnError` is the same source
  on both branches (`if (!PyBytes_Check(v) || newsize < 0)`).
  - In tip's profile, the entry count is 171127 but the `newsize < 0` operand ran 171124
    times. So 3 increments were lost: the profile counters are not atomic, and training runs
    threads.
  - Clang derives the count of `newsize < 0` being true as 0 − 3, which underflows to the
    weight `UINT32_MAX : 1`. The rest of the function is then cold, so `_PyBytes_FromSize`
    is not inlined.
  - main (171011/171012) and tip2 (171093/171093) happened not to underflow.
  - It is random per training run, so it can equally hit main.
- **No change was made:** the code is main's, unchanged. The tip2 and fix builds both inline
  the call. A robust fix would be upstream (two separate `if`s, or
  `-fprofile-update=atomic` for PGO), not branch code.

### `fromhex` +5: real, fixed in the spec
- `bytes_fromhex` is 15 / 20 / 20 instructions of self cost (main / tip / tip2).
- The spec body `result = _PyBytes_FromHex(...); if cls is not bytes: return cls(result);
  return result` lowered to a NULL check on the hot path plus a merged return. Main tests the
  type first and checks NULL only on the subclass path.
- Fix `737069ca773`: the spec tests `cls is bytes` first and returns `_PyBytes_FromHex(...)`,
  which is a tail call.
  - `bytes_fromhex` is now 15. The callgrind total is 1471.8 vs main's 1471.7.
  - Parity, facts and the review are unchanged. Only `bytesobject_pyspec.c.h` changes.

### `b16 == b16c` +2: build layout
- The +2 is all in `_TAIL_CALL_COMPARE_OP` (74 / 76 / 74 / 76 for main / tip / tip2 / fix).
- The generic `COMPARE_OP` source is the same as main's, and tip2 equals main.

### Results (instructions, JIT on / off; main → tip → tip2 → fix)
| shape | seed 1 | seed 0 | seed 7 |
|---|---|---|---|
| `bytearray(b16)` | 1251/1249 → 1275/1273 → 1249/1244 → **1248/1249** | 1251/1249 → 1275/1273 → 1249/1244 → **1248/1249** | 1262/1249 → 1275/1273 → 1249/1244 → **1248/1249** |
| `bytes.fromhex(h16)` | 1602/1532 → 1609/1539 → 1603/1530 → **1604/1534** | 1563/1493 → 1569/1499 → 1564/1491 → **1564/1494** | 1572/1502 → 1579/1509 → 1573/1500 → **1574/1504** |
| `fromhex(h16)` | 1051/975 → 1056/980 → 1055/976 → **1051/975** | same | 1050/975 → … → **1051/975** |
| `b16.fromhex(h16)` | 1502/1412 → 1508/1418 → 1504/1411 → **1503/1413** | 1463/1373 → … → **1463/1373** | 1472/1382 → … → **1473/1383** |
| `b16 == b16c` | 348/339 → 350/341 → 349/337 → 350/341 | same | same |

- **Everything else in the seed-1 list:** fix is within ±9 of tip, the cross-build A/A range
  (tip vs tip2 differ by up to 9 on unchanged code, e.g. `hash(b16)` off 504 vs 494).
  - It stays below main by the same margins as before: `bytes(hb)` −26 %/−18 %,
    `Sub(l16)` −1.1 to −1.9 %, `Sub(16)` −3.8 to −7.3 %.
  - `b16s.split()` off (1844) is its known second mode.
- **Cycles:** flat or lower. `bytearray(b16)` is 242–245 vs main's 241–247.

### Verdict
- **Real regressions:** none left. `bytearray(b16)` is at or below main at seeds 0, 1 and 7
  (the tip build's +24 was profile noise), and fromhex's real +5 is fixed.
- **Remaining +1 to +2** (`bytes.fromhex`, `==`, `b16.__bytes__()` off): all in code that is
  unchanged from main or equal to main under callgrind. They fall within the cross-build A/A
  range, and tip2 shows the same shapes at or below main.
- **Tests:** debug JIT `../build-p4-fix`. `pyspec_review.py --baseline ../build-str1-dbg/python`
  gives Result OK (87,737 lines, no difference). The 8 test files pass, and clinic on the
  spec-backed files leaves the tree clean.

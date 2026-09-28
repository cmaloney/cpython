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

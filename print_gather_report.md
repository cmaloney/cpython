# exp/print_gather (45a1fd5a8f7) vs nibbler_gather (53abfea6468)

Summary (agent report, 2026-10-15; raw data in this directory):
- Atomicity: lines stay whole only on files with _gather (nibbler). Stock _io files lose the writer's guarantee
  (FT: ~55-60% of 16000 lines interleave; GIL: ~10 per 16000).
- Memory (print of a 100 MB str): BASE default 200 MB peak, nib 100 MB; EXP 100 MB in both. In nib mode the
  _gather record copies the str (str isn't kept by reference), so nothing is saved there.
- Speed (PGO+LTO pyperf): small prints 1.2-2.7x slower in default mode (one write() per piece), 3-5.4x slower in
  nib mode (the _gather block costs ~3.6k instructions, more than a whole BASE print()). print(1 MB str) on stock
  is 1.9x faster from the saved copy; the 526 us GIL BASE figure is a glibc trim cliff (3 brk per print, 481 page
  faults/print; MALLOC_MMAP_THRESHOLD_/TRIM_THRESHOLD_=256M -> 31.9 us).
- Behaviour: str() raising mid-print writes 'a ' in EXP, nothing in BASE. test_print.test_one_write fails (by design).
- Callgrind (Ir/print, GIL PGO): default one/three/StringIO BASE 2907/3685/2771, EXP 3522/7350/3170;
  nib BASE 2872/3641/2771, EXP 6524/10679/3170.
Tables: pyperf_tables.md, probes_all.out, cg_*.out.

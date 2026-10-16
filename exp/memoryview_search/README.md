# Supporting material for the array/memoryview search change

Not part of the change itself; kept on the branch so it can be shared.

- `issue.md`: draft of the GitHub issue.
- `adversarial.py`: differential tests of the raw item search in
  `array.array` and `memoryview`. Compares each operation with an exact
  `int` value against the same operation with an `int` subclass that
  overrides `__eq__`, which always takes the generic (object comparison)
  path. Covers boundary values for every integer format, strided,
  reversed and unaligned views, exotic exporters from `_testbuffer`,
  odd value types, random fuzzing, memoryview item assignment (against
  `struct.pack`) and reentrancy. Run with a build of this tree:
  `./python.exe exp/memoryview_search/adversarial.py`
- `mutate.py`: plants bugs in the C code one at a time and checks that
  `adversarial.py` and the regression tests catch each one:
  `python3 exp/memoryview_search/mutate.py BUILD_DIR`
- `race.py`: searches an array while another thread frees and reallocates
  its buffer; for free-threaded builds with AddressSanitizer.
- `bench.c`: C microbenchmark of the typed stringlib search against
  byte-level alternatives (stringlib bytes search, `memmem`,
  `memchr` + `memcmp`) and a plain loop; build instructions at the top.

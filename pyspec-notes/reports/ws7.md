# WS7: adopting the stub-per-.c-file model across CPython

(Saved by coordinator from the WS7 agent's returned text; data in ws7/data/.)

## Summary
1. **Census:** 2898 clinic functions in 159 files (Modules 2371, Objects 310, Python 164, PC 53).
   - Natural `def` mapping: `/` 1359, `*` 179, `*args/**kwargs` 48/5, defaults 777, converter
     annotations 355, return converter `->` 200, @classmethod/@staticmethod 125/3,
     getter/setter/deleter → @property/@x.setter/@x.deleter 99/36/6, explicit self 123,
     defining_class 166.
   - Pseudo-keyword inside annotation: `c_name=` 320, `doc=` 280, `until=` 2.
   - New concept needed: optional groups (41; `group=/depth=/default=`), deprecation
     decorators (27), clones 185 (expanded + 2 rules), custom `[python]` converters (201 funcs),
     11 names defined twice under different `#if` (23 funcs, 9 differing signatures).
   - Stays in .c: `as c_name` 302, @critical_section 478, @permit_long_summary 235,
     @text_signature, @vectorcall, directives.
   - **Conflict with D2:** 1398 module functions also want the stub's top level; 14 share a
     name with a C function in the same file (e.g. `_pickle.dump`, `zlib.decompress`).
2. **Round-trip** (fingerprints + block output + generated `.c.h`):
   | variant | identical | failures |
   |---|---|---|
   | A: `doc=` per-param docs, clones copy source `@text_signature` | 2896/2898 | 2 |
   | A without the text-signature rule | 2884 | 14 |
   | B: per-param docs folded into docstring | 2866 | 32 |
   Remaining A failures: clones of `__new__`/`__init__` get `self` where source's first
   param is `type`; one more rule → 2898/2898. B loses information. Duplicate names only
   matched via file order.
3. **Hand-written parsing (non-test):** PTAK 44, PT 95, Parse 50, Unpack 42, `_PyArg_*` 109,
   36 vectorcall fns, 74 files (tests add 468 PT). Reasons: parsing data not args (sockaddr,
   array setitem, lzma filters); builtin types with hand-written tp_new/tp_init + vectorcall
   (set, super, filter/map/zip, itertools, operator getters — matters most for goal 4;
   clinic @vectorcall used by only 7 functions); overloaded signatures (setsockopt, sendto,
   min/max); exception `__init__`s; slot wrappers; never-converted modules.
4. **C API in Objects/:** 899 exported (491 limited, 234 cpython, 174 internal), 485 stable
   ABI, 656 documented, 431 in refcounts.dat. Of 646 public, 2 undocumented; 223 documented
   have no refcounts.dat entry. Tree-wide: 428 documented missing from refcounts.dat, 59
   stable-ABI undocumented, 51 stable-ABI without PyAPI_FUNC, 154 refcounts.dat names undeclared.
5. **Risks:** name-based .c↔stub linking (#if duplicates, clones); `input=` checksum must cover
   stub content and `--make` must treat the stub as input; two files per signature change;
   custom converters invisible to the stub; pseudo-kw collisions with real converter args;
   D2 namespace conflict; byte-identical check should live in test_clinic.
   **Order:** 108 non-test files (1261 funcs) have no hard features. Trivial Objects files
   (interpolation, module, sentinel, structseq, descr, enum, class, tuple) → small Objects
   (complex, range, func, odict, memory, long, type, dict, float, list, exceptions, ...) →
   Objects needing rules (codeobject, setobject, bytes, bytearray, unicode) → easy Modules →
   hard Modules (_decimal, _operator, cmath, _curses, posixmodule, winreg/_winapi, _testclinic).
   **PR size:** one .c per PR, `.c.h` byte-identical.
   | file | funcs | .c clinic-input lines → minimal | stub lines |
   |---|---:|---|---:|
   | moduleobject | 1 | 7 → 1 | 11 |
   | tupleobject | 4 | 29 → 6 | 29 |
   | floatobject | 14 | 91 → 19 | 96 |
   | listobject | 14 | 98 → 22 | 82 |
   | bytesobject | 26 | 267 → 46 | 205 |
   | unicodeobject | 49 | 409 → 73 | 372 |
   | sysmodule | 67 | 443 → 76 | 458 |
   | posixmodule | 231 | 2097 → 255 | 1558 |
   | whole tree | 2898 | 21815 → ~3920 | 18219 |
6. **Found, not fixed:** clinic warns @permit_long_summary unnecessary on
   `_elementtree.XMLParser.__init__` (Modules/_elementtree.c ~3758) and
   `pyexpat.xmlparser.GetInputContext` (Modules/pyexpat.c:1083).

Data: data/census.json, census_summary.txt, roundtrip_{A,A_noclonetextsig,B}.{json,txt},
diffs/, diffs_noclone/, stubs/{A,B}, manual_parsing.json, capi_catalog.{json,txt},
migration_order.txt, stub_stats.txt, pr_size.txt.

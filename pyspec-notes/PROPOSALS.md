# Pending design proposals (discussed with the user, not implemented)

## P1: helpers connect to C by name (replaces `C.` escapes + `@helper` stubs)
Today, one hand-written C helper appears in 3 places: the C definition, a `runtime.C`
escape (C call template, return kind, error convention, Python stand-in), and a
`@helper` stub in the spec (C signature types plus facts).
Proposal: one spec function per helper, decorated `@c_implemented` (C is authoritative;
the body is the Python reference, never lowered). Call sites use the plain name (no `C.`).
Helpers defined in other C files get stubs in *their* file's spec (e.g.
Objects/pyspec/abstract.py) and are imported. The user does NOT want clinic to parse all
the C; token-level reads of a single named function are acceptable for validation only.

## P2: "runs Python" / error facts as a small Python sub-language, derived and validated
The user dislikes RunsPython / OnError / NoError / New / Steals / Out / InOut annotations
("not pythonic", "only apply sometimes"). Goal: one uniform A→B rule.
- The body is the meaning. Derive facts (exact result type, alias, constant, can-raise,
  runs-Python per path) from the body whenever possible; `...` = unknown = worst case.
- A few primitives for what plain Python can't say, placed where the effect happens
  (so control flow gives the conditions): `exact(T)` (new object of exact type T),
  `unknown()`, `calls(x, "__slot__")` (invokes type(x)'s special method; Python only if
  Python-level), `runs_python()` (escape hatch), `NULL` as a value (absent, not an error).
- Error convention from "can the body raise" plus the return kind (object → NULL, int → -1).
- Ownership (steals, borrowed, out params) is not in the spec: it comes from Doc/data/refcounts.dat.
- Validation: (1) the spec side is static by construction; (2) the C side reuses the
  cases generator's token-level escape check (Tools/cases_generator/analyzer.py,
  NON_ESCAPING_FUNCTIONS / find_escaping_api_calls) on the one named C function plus its
  static callees; every escaping C call must be accounted for by `calls()`/`runs_python()`
  on that path; (3) a dynamic difftest with call-recording dunders asserts that no Python
  runs where the spec says none.

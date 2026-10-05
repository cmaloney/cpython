# bytes.__new__ as overloads (draft, side by side)

Asked 2026-09-29: could `bytes.__new__`'s if-tree be a set of overloads instead?
To compare, not to replace.  Written against the spec of `b78a86d7019` (before the
`ac.`/`rt.` surface), so it uses the old spelling (`@c_name`, bare `NULL`).

- `bytes_new_overloads.py`: today's `bytes.__new__` and `PyBytes_FromObject`, then the
  same as `typing.overload` sets (13 overloads + the implementation signature; 5).
- `overloads.py`: `desugar_module()` (overload sets -> the if-tree, ast -> ast) and
  `dispatch()` (an independent interpreter of the same rules).
- `check_ast.py`: the desugared bodies are `ast.dump`-equal to today's.
- `check_equivalence.py`, `make_variant.py`, `hooks.patch`: the runtime comparison (380
  `CASES` runs, 0 mismatches) on a scratch copy of the tree with the three hooks
  (`frontend.Spec.__init__`, `runtime.load()`, `model.module()`); clinic's output was
  identical but for `/* file:line */` comments.

Rules: order is dispatch (first match wins, as a type checker picks overloads); a
parameter left out = not passed (NULL), `p=NULL` = either; annotations on `object`
parameters are fixed C tests (`Exact[T]`, `T` = real-type isinstance, `SupportsIndex`,
`Buffer`); `if C: return NotImplemented` at the top of a body is a guard; `except E:
return NotImplemented` falls through to the next overload.

Pitfalls: the order of mutually exclusive overloads still changes the C (branch order);
shared tests must be pure; `return NotImplemented` as "next" clashes with binary slots
that really return it; presence is by name, not position.  See "Open decisions" in
`../../README.md`.

"""The context of the passes: the state they share, in one object.

The passes call each other: the partial evaluator needs the facts of the
calls it folds (facts.py), and the facts of a call are those of the
residual of the callee (partial_eval.py again).  A Context is that
wiring, for one spec and the specs it loads (``spec.loaded``), with the
state kept per spec: its facts.Analyzer, its builtin_types.TypeFacts
and its shared specializations.  emit.generate() makes one per spec; a
caller that only wants facts (disconnects.py, the tests) makes its own.
"""

from __future__ import annotations

import ast
from collections.abc import Sequence

from . import builtin_types, facts, frontend, partial_eval
from .frontend import Spec
from .known import Env


class Context:
    def __init__(self, spec: Spec) -> None:
        self.spec = spec
        self.loaded = spec.loaded
        self._analyzers: dict[Spec, facts.Analyzer] = {}
        self._types: dict[Spec, builtin_types.TypeFacts] = {}
        self._specializations: dict[Spec, partial_eval.Specializations] = {}

    def analyzer(self, spec: Spec | None = None) -> facts.Analyzer:
        """The facts analysis of *spec* (by default, the spec of the
        context)."""
        spec = spec or self.spec
        if spec not in self._analyzers:
            self._analyzers[spec] = facts.Analyzer(self, spec)
        return self._analyzers[spec]

    def types(self, spec: Spec | None = None) -> builtin_types.TypeFacts:
        """The facts about builtin types for the code of *spec*."""
        spec = spec or self.spec
        if spec not in self._types:
            self._types[spec] = builtin_types.TypeFacts(
                spec, frontend.spec_classes(),
                lambda other, name, tp: self.analyzer(other).method_facts(
                    name, tp))
        return self._types[spec]

    def specializations(self, spec: Spec | None = None
                        ) -> partial_eval.Specializations:
        """The shared specializations of *spec*."""
        spec = spec or self.spec
        if spec not in self._specializations:
            self._specializations[spec] = partial_eval.Specializations()
        return self._specializations[spec]

    def residual(self, spec: Spec, name: str, env: Env, *,
                 inline: bool = True,
                 arities: Sequence[partial_eval.Arity] = ()
                 ) -> list[ast.stmt]:
        """The residual statements of spec function *name* of *spec*
        under the facts *env* (partial_eval.specialize())."""
        return partial_eval.specialize(self, spec, name, env, inline=inline,
                                       arities=arities)

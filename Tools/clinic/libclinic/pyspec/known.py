"""What the passes know about the names of residual code.

The partial evaluator (partial_eval.py) and the facts analysis (facts.py)
keep one fact per name, in an environment (Env):

* NULL or NOTNULL;
* an exact type (``list``): the name refers to an object of exactly
  that type;
* Value(obj): the name refers to this object (``cls is bytes``);
* IterOf(source, tp): the name refers to ``iter(source)``, source of
  exact type tp, whose iteration runs no Python code;
* Other(types, instances): an object of none of these exact types, and
  an instance of none of these classes.

A name without a fact may be anything, NULL included.  The facts about
builtin types come from the spec and from builtin_types.py, never from
the Python running Argument Clinic.
"""

from __future__ import annotations

import ast
import builtins
import dataclasses as dc
import enum
from collections.abc import Hashable


class Null(enum.Enum):
    NULL = 'NULL'
    NOTNULL = 'NOTNULL'


NULL = Null.NULL
NOTNULL = Null.NOTNULL


# ``return FALLBACK`` in a snapshot (partial_eval.py): no result, the
# caller restarts through the generic function.
FALLBACK = 'FALLBACK'


@dc.dataclass(frozen=True)
class Value:
    obj: object


@dc.dataclass(frozen=True)
class IterOf:
    source: str
    tp: type


@dc.dataclass(frozen=True)
class Other:
    types: tuple[type, ...] = ()
    instances: tuple[type, ...] = ()


Fact = Null | type | Value | IterOf | Other
Env = dict[str, Fact]

# Types iterated by index (for item in x:), without an iterator.
SEQUENCES: tuple[type, ...] = (list, tuple)


def builtin_type(node: ast.expr) -> type | None:
    """The builtin type *node* names, or None."""
    if isinstance(node, ast.Name):
        value = getattr(builtins, node.id, None)
        if isinstance(value, type):
            return value
    return None


def exact_type(node: ast.expr, env: Env) -> type | None:
    """The exact type of name *node* in *env*, or None."""
    if isinstance(node, ast.Name):
        value = env.get(node.id)
        if isinstance(value, type):
            return value
    return None


def arg_fact(node: ast.expr, env: Env) -> Fact | None:
    """The fact about an argument of a call, for the callee: from *env*
    for a name, the value of a constant or a builtin; None if none."""
    match node:
        case ast.Name('NULL'):
            return NULL
        case ast.Name(name) if name in env:
            fact = env[name]
            return NOTNULL if isinstance(fact, IterOf) else fact
        case ast.Name(name) if hasattr(builtins, name):
            return Value(getattr(builtins, name))
        case ast.Constant(value):
            return Value(value)
    return None


def fact_key(fact: Fact | None) -> Hashable:
    """A hashable form of a fact, equal for equal facts (``Value(1)``
    and ``Value(True)`` differ)."""
    if isinstance(fact, (Value, IterOf, Other)):
        return repr(fact)
    return fact


def _excluding(fact: Fact | None, **more: tuple[type, ...]) -> Other:
    """*fact* (NULL excluded), and not of the *more* types or classes."""
    other = fact if isinstance(fact, Other) else Other()
    return dc.replace(other, **{field: (*getattr(other, field), *values)
                                for field, values in more.items()})


def refine(test: ast.expr, env: Env) -> tuple[Env, Env]:
    """The environments of the body and of the else clause of ``if
    test``, which *env* does not decide: ``type(x) is K`` gives x the
    exact type K in the body (in the else clause for ``is not``), and in
    the other clause, x is not exactly K; after a false
    ``isinstance(x, K)``, x is no instance of K; ``x is NULL`` and ``x
    is K`` (x is the type K) are decided."""
    match test:
        case ast.UnaryOp(op=ast.Not(), operand=operand):
            body, orelse = refine(operand, env)
            return orelse, body
        case ast.Compare(left=ast.Name(name),
                         ops=[ast.Is() | ast.IsNot() as op],
                         comparators=[right]) if env.get(name) is None:
            klass = builtin_type(right)
            if isinstance(right, ast.Name) and right.id == 'NULL':
                known, other = env | {name: NULL}, env | {name: NOTNULL}
            elif klass is not None:
                known, other = env | {name: Value(klass)}, env
            else:
                return env, env
            if isinstance(op, ast.IsNot):
                return other, known
            return known, other
        case ast.Compare(left=ast.Call(func=ast.Name('type'),
                                       args=[ast.Name(name)]),
                         ops=[ast.Is() | ast.IsNot() as op],
                         comparators=[right]):
            klass = builtin_type(right)
            if klass is not None:
                known = env | {name: klass}
                other = env
                if env.get(name) in (None, NOTNULL) or isinstance(
                        env.get(name), Other):
                    other = env | {name: _excluding(env.get(name),
                                                    types=(klass,))}
                if isinstance(op, ast.IsNot):
                    return other, known
                return known, other
        case ast.Call(func=ast.Name('isinstance'),
                      args=[ast.Name(name), cls]):
            klass = builtin_type(cls)
            fact = env.get(name)
            if klass is not None and (fact in (None, NOTNULL)
                                      or isinstance(fact, Other)):
                return env, env | {name: _excluding(fact,
                                                    instances=(klass,))}
        case ast.BoolOp(op=ast.And(), values=values):
            body = env
            for value in values:
                body = refine(value, body)[0]
            return body, env
    return env, env

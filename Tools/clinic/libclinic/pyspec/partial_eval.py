"""Partial evaluation of pyspec functions.

Given facts a call site knows -- which arguments are NULL, and optionally
the exact type of an argument -- fold the branches those facts decide and
inline tail calls to other spec functions.  The result is a list of ast
statements in the same Python subset the C emitter accepts.

Loops.  ``for item in it:`` iterates an iterator ``it = iter(x)``.  When
the exact type of x is known (from the call site, or from a
``type(x) is K`` test), the evaluator uses the facts of ITERATION:

* ``iter(x)`` cannot raise TypeError: ``try: it = iter(x) except
  TypeError: ... else: ...`` keeps only the assignment and the else
  clause;
* a list or a tuple is iterated by index, without an iterator object
  (``for item in x:``, lowered by emit.py; ``it = iter(x)`` is then
  dead and removed), with the same semantics as its iterator: the size is
  read again for every item;
* the exact type of the items, when all have the same, is known in the
  loop body.

When the exact type of x is not known where ``it = iter(x)`` is
evaluated, the rest of the block is versioned: specialized for an exact
list and an exact tuple when that gives an index loop, and kept generic
for other types (VERSIONED_ITERABLES).

In a loop body where the type of the items is not known, a statement
that passes the item to an escape with a cheaper lowering for an exact
type (Escape.exact, e.g. PyNumber_AsSsize_t() of an exact int) is split:
``if type(item) is int: <statement> else: <statement>``, the first one
with the call marked with the type (``call.pyspec_exact``) for the
emitter.  The rest of the body is shared.
"""

import ast
import builtins
import copy
import itertools

from . import runtime

# Fact values in an environment: NULL, NOTNULL, an exact type (of the
# object the name refers to), Value(obj) for the object itself, IterOf(x,
# K) for the result of iter(x), or Other(types) for an object of none of
# these exact types.
NULL = 'NULL'
NOTNULL = 'NOTNULL'


class Value:
    """The name refers to exactly this object (e.g. cls is bytes)."""

    def __init__(self, obj):
        self.obj = obj


class IterOf:
    """The name refers to iter(source), where source (a name) is of exact
    type tp, a key of ITERATION."""

    def __init__(self, source, tp):
        self.source = source
        self.tp = tp


class Other:
    """Not NULL, and not of one of these exact types."""

    def __init__(self, types):
        self.types = tuple(types)


# Iterating an object of one of these exact builtin types: iter() cannot
# raise TypeError, and neither iter() nor the iteration runs Python code.
# The value is the exact type of every item, or None when it varies.
# (Facts of the C code of these types, which belong to their specs when
# they have one; list and tuple iteration is also lowered by emit.py.)
ITERATION = {
    list: None,
    tuple: None,
    dict: None,
    set: None,
    frozenset: None,
    range: int,
    bytes: int,
    bytearray: int,
    str: str,
}

# Types iterated by index (for item in x:), without an iterator.
SEQUENCES = (list, tuple)

# An iterable of unknown type is versioned for these exact types.
VERSIONED_ITERABLES = SEQUENCES


class Bound:
    """The name refers to a spec method bound to an argument, whose call
    evaluates to *value* (an ast node) without side effects.

    ``(func := C.lookup_special(x, "__bytes__")) is not NULL`` binds func
    when the exact type of x is a static type whose __bytes__ is a spec
    method, and that method, partially evaluated for x, is just
    ``return self`` (or a constant): ``result = func()`` then becomes
    ``result`` is x.  A static type cannot change, so the lookup is
    decided by the type alone; a heap type (e.g. a subclass) is not.
    """

    def __init__(self, name, value):
        self.name = name
        self.value = value


MAX_INLINE_DEPTH = 8


def _builtin_type(node):
    if isinstance(node, ast.Name):
        value = getattr(builtins, node.id, None)
        if isinstance(value, type):
            return value
    return None


def _is_type_call(node):
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == 'type' and len(node.args) == 1)


def _known_type(env, node):
    if isinstance(node, ast.Name):
        value = env.get(node.id)
        if isinstance(value, type):
            return value
    return None


def _has_special(tp, name):
    return any(name in klass.__dict__ for klass in tp.__mro__)


def evaluate(expr, env):
    """Return True, False, or None when *expr* is not decided by *env*."""
    match expr:
        case ast.UnaryOp(op=ast.Not(), operand=operand):
            value = evaluate(operand, env)
            return None if value is None else not value
        case ast.BoolOp(op=op, values=values):
            results = [evaluate(v, env) for v in values]
            if isinstance(op, ast.And):
                if False in results:
                    return False
                if all(r is True for r in results):
                    return True
            else:
                if True in results:
                    return True
                if all(r is False for r in results):
                    return False
            return None
        case ast.Compare(left=left, ops=[ast.Is() | ast.IsNot() as op],
                         comparators=[right]):
            value = _evaluate_is(left, right, env)
            if value is None:
                return None
            return value != isinstance(op, ast.IsNot)
        case ast.Call(func=ast.Name('isinstance'), args=[obj, cls]):
            tp, klass = _known_type(env, obj), _builtin_type(cls)
            if tp is None or klass is None:
                return None
            return issubclass(tp, klass)
        case ast.Call(func=ast.Name('hasattr'),
                      args=[type_call, ast.Constant(str() as name)]) \
                if _is_type_call(type_call):
            tp = _known_type(env, type_call.args[0])
            return None if tp is None else hasattr(tp, name)
    return None


def _evaluate_is(left, right, env):
    right_is_null = isinstance(right, ast.Name) and right.id == 'NULL'
    if right_is_null and isinstance(left, ast.Name):
        value = env.get(left.id)
        if value == NULL:
            return True
        if value == NOTNULL or isinstance(value, (type, Value, IterOf,
                                                  Other)):
            return False
        return None
    if isinstance(left, ast.Name) and isinstance(env.get(left.id), Value):
        klass = _builtin_type(right)
        if klass is None:
            return None
        return env[left.id].obj is klass
    if right_is_null and isinstance(left, ast.NamedExpr):
        match left.value:
            case ast.Call(func=ast.Attribute(ast.Name('C'), 'lookup_special'),
                          args=[obj, ast.Constant(str() as name)]):
                tp = _known_type(env, obj)
                if tp is not None and not _has_special(tp, name):
                    return True
        return None
    if _is_type_call(left):
        tp, klass = _known_type(env, left.args[0]), _builtin_type(right)
        if klass is None:
            return None
        if tp is None:
            other = (env.get(left.args[0].id)
                     if isinstance(left.args[0], ast.Name) else None)
            if isinstance(other, Other) and klass in other.types:
                return False
            return None
        return tp is klass
    return None


def refine(test, env):
    """The environments of the body and of the else clause of
    ``if test`` that is not decided by *env*: ``type(x) is K`` gives x
    the exact type K in the body (and in the else clause for ``is
    not``)."""
    match test:
        case ast.Compare(left=ast.Call(func=ast.Name('type'),
                                       args=[ast.Name(name)]),
                         ops=[ast.Is() | ast.IsNot() as op],
                         comparators=[right]):
            klass = _builtin_type(right)
            if klass is not None:
                known = env | {name: klass}
                if isinstance(op, ast.IsNot):
                    return env, known
                return known, env
        case ast.BoolOp(op=ast.And(), values=values):
            body = env
            for value in values:
                body = refine(value, body)[0]
            return body, env
    return env, env


def _type_test(name, klass):
    """``type(name) is klass``"""
    return ast.Compare(
        left=ast.Call(func=ast.Name('type', ast.Load()),
                      args=[ast.Name(name, ast.Load())], keywords=[]),
        ops=[ast.Is()], comparators=[ast.Name(klass.__name__, ast.Load())])


def _escape(func):
    """The runtime.Escape of a ``C.<name>`` node, or None."""
    if (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
            and func.value.id == 'C'):
        value = getattr(runtime.C, func.attr, None)
        if isinstance(value, runtime.Escape):
            return value
    return None


def _iter_call(node):
    """x for ``iter(x)`` (x a name), else None."""
    match node:
        case ast.Call(func=ast.Name('iter'), args=[ast.Name(name)],
                      keywords=[]):
            return name
    return None


def _iter_assignment(stmt):
    """(target, source) for ``target = iter(source)`` or for ``try:
    target = iter(source)`` with only ``except TypeError`` handlers, else
    None."""
    match stmt:
        case ast.Assign(targets=[ast.Name(target)], value=value) \
                if _iter_call(value):
            return target, _iter_call(value)
        case ast.Try(body=[ast.Assign(targets=[ast.Name(target)],
                                      value=value)],
                     handlers=handlers, finalbody=[]) \
                if _iter_call(value) and all(
                    isinstance(h.type, ast.Name) and h.type.id == 'TypeError'
                    for h in handlers):
            return target, _iter_call(value)
    return None


def _names_loaded(stmts):
    return {node.id for stmt in stmts for node in ast.walk(stmt)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}


def _has_index_loop(stmts, name):
    return any(isinstance(node, ast.For)
               and getattr(node, 'pyspec_sequence', False)
               and isinstance(node.iter, ast.Name) and node.iter.id == name
               for stmt in stmts for node in ast.walk(stmt))


def annotate_exact(stmt, env):
    """A copy of *stmt* (an assignment, an expression statement or a
    return) with the escape calls whose first argument has a known exact
    type that the escape lowers more cheaply marked with it
    (``call.pyspec_exact``); None when there is none."""
    marked = False
    stmt = copy.deepcopy(stmt)
    for node in ast.walk(stmt):
        if isinstance(node, ast.Call) and node.args:
            escape = _escape(node.func)
            first = node.args[0]
            if (escape is not None and isinstance(first, ast.Name)
                    and env.get(first.id) in escape.exact):
                node.pyspec_exact = env[first.id]
                marked = True
    return stmt if marked else None


def _split_on_item_type(stmt, item):
    """[stmt], or, if *stmt* (an assignment or an expression statement)
    passes *item* to an escape with a cheaper lowering for its exact type
    (Escape.exact), ``if type(item) is K: <stmt, marked> else: <stmt>``
    for each such type K."""
    if not isinstance(stmt, (ast.Assign, ast.Expr)):
        return [stmt]
    out = [stmt]
    for tp in reversed(_exact_types_for([stmt], item)):
        marked = annotate_exact(stmt, {item: tp})
        out = [ast.If(_type_test(item, tp), [marked], out)]
    return out


def _exact_types_for(stmts, name):
    """The types for which an escape called on *name* in *stmts* has a
    cheaper lowering (Escape.exact)."""
    types = []
    for stmt in stmts:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Call) and node.args:
                escape = _escape(node.func)
                first = node.args[0]
                if (escape is not None and isinstance(first, ast.Name)
                        and first.id == name):
                    types += [tp for tp in escape.exact if tp not in types]
    return types


def terminates(stmts):
    """True if control never falls off the end of *stmts*."""
    if not stmts:
        return False
    last = stmts[-1]
    if isinstance(last, (ast.Return, ast.Raise)):
        return True
    if isinstance(last, ast.If):
        return terminates(last.body) and terminates(last.orelse)
    return False


def assigned_names(stmts):
    names = set()
    for stmt in stmts:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                names.add(node.id)
    return names


class _Rename(ast.NodeTransformer):
    def __init__(self, mapping):
        self.mapping = mapping

    def visit_Name(self, node):
        replacement = self.mapping.get(node.id)
        if replacement is None:
            return node
        new = copy.deepcopy(replacement)
        if isinstance(new, ast.Name):
            new.ctx = node.ctx
        return ast.copy_location(new, node)


def _is_static_type(tp):
    return isinstance(tp, type) and not tp.__flags__ & (1 << 9)


def _pure_value(residual, param):
    """The value of a residual that is just ``return <param or constant>``
    (the parameter as ast.Name), or None."""
    match residual:
        case [ast.Return(value=ast.Name(name) as value)] if name == param:
            return value
        case [ast.Return(value=ast.Constant() as value)]:
            return value
    return None


class Evaluator:
    def __init__(self, spec):
        self.spec = spec
        self._suffix = itertools.count(1)

    def special_method(self, tp, name):
        """The spec method (name) that C.lookup_special(x, name) finds for
        an object x of exact type tp, or None when not known statically."""
        if not _is_static_type(tp):
            return None
        for klass in tp.__mro__:
            if name in klass.__dict__:
                spec_name = f'{klass.__name__}.{name}'
                node = self.spec.functions.get(spec_name)
                if (klass is getattr(builtins, klass.__name__, None)
                        and self.spec.implemented(spec_name)
                        and not node.decorator_list):
                    return spec_name
                return None
        return None

    def bind_special(self, test, env, depth):
        """For ``if (v := C.lookup_special(x, "name")) is [not] NULL``
        that finds a spec method whose call on x is pure: (v, Bound, is the
        test true).  Otherwise None."""
        match test:
            case ast.Compare(
                    left=ast.NamedExpr(
                        target=ast.Name(target),
                        value=ast.Call(
                            func=ast.Attribute(ast.Name('C'),
                                               'lookup_special'),
                            args=[ast.Name(obj) as obj_node,
                                  ast.Constant(str() as name)])),
                    ops=[ast.Is() | ast.IsNot() as op],
                    comparators=[ast.Name('NULL')]):
                pass
            case _:
                return None
        tp = env.get(obj)
        if not isinstance(tp, type) or depth >= MAX_INLINE_DEPTH:
            return None
        spec_name = self.special_method(tp, name)
        if spec_name is None:
            return None
        self_param = self.spec.params(spec_name)[0]
        residual = Evaluator(self.spec).block(self.spec.body(spec_name),
                                              {self_param: tp}, depth + 1)
        value = _pure_value(residual, self_param)
        if value is None:
            return None
        if isinstance(value, ast.Name):
            value = copy.copy(obj_node)
        return target, Bound(spec_name, value), isinstance(op, ast.IsNot)

    def _is_spec_call(self, node):
        return (isinstance(node, ast.Call)
                and self.spec.call_target(node.func) is not None)

    def inline(self, call, env, depth):
        name = self.spec.call_target(call.func)
        params = self.spec.params(name)
        body = self.spec.body(name)
        mapping = dict(zip(params, call.args))
        suffix = next(self._suffix)
        for local in assigned_names(body) - set(params):
            mapping[local] = ast.Name(f'{local}_{suffix}', ast.Load())
        body = [_Rename(mapping).visit(copy.deepcopy(s)) for s in body]
        return self.block(body, env, depth + 1)

    def block(self, stmts, env, depth=0, inline=True):
        out = []
        stmts = list(stmts)
        i = 0
        while i < len(stmts):
            stmt = stmts[i]
            i += 1
            match stmt:
                case ast.Assign(targets=[ast.Name(target)],
                                value=ast.Call(func=ast.Name(func), args=[]))\
                        if isinstance(env.get(func), Bound):
                    # result = func() of a pure bound spec method: result
                    # is its value from here on.
                    rename = _Rename({target: env[func].value})
                    stmts[i:] = [rename.visit(copy.deepcopy(s))
                                 for s in stmts[i:]]
                    continue
            iteration = _iter_assignment(stmt)
            if iteration is not None:
                target, source = iteration
                tp = env.get(source)
                if isinstance(tp, type) and tp in ITERATION:
                    # iter() cannot raise TypeError: no handler runs.
                    assign = ast.Assign(
                        [ast.Name(target, ast.Store())],
                        ast.Call(ast.Name('iter', ast.Load()),
                                 [ast.Name(source, ast.Load())], []),
                        lineno=0)
                    assign.pyspec_pure = True
                    out.append(assign)
                    env = env | {target: IterOf(source, tp)}
                    if isinstance(stmt, ast.Try):
                        stmts[i:i] = stmt.orelse
                    continue
                if self.can_version(env, source):
                    versioned = self.version(source, [stmt, *stmts[i:]],
                                             env, depth, inline)
                    if versioned is not None:
                        out += versioned
                        break
            bound = (self.bind_special(stmt.test, env, depth)
                     if isinstance(stmt, ast.If) else None)
            if bound is not None:
                target, method, value = bound
                env = env | {target: method}
                out += self.block(stmt.body if value else stmt.orelse, env,
                                  depth, inline)
            elif isinstance(stmt, ast.If):
                value = evaluate(stmt.test, env)
                if value is True:
                    left = getattr(stmt.test, 'left', None)
                    if isinstance(left, ast.NamedExpr):
                        out.append(ast.Assign([left.target], left.value,
                                              lineno=0))
                    out += self.block(stmt.body, env, depth, inline)
                elif value is False:
                    out += self.block(stmt.orelse, env, depth, inline)
                else:
                    body_env, else_env = refine(stmt.test, env)
                    stmt = copy.copy(stmt)
                    stmt.body = (self.block(stmt.body, body_env, depth,
                                            inline)
                                 or [ast.Pass()])
                    stmt.orelse = self.block(stmt.orelse, else_env, depth,
                                             inline)
                    out.append(stmt)
            elif (inline and isinstance(stmt, ast.Return)
                    and self._is_spec_call(stmt.value)
                    and depth < MAX_INLINE_DEPTH):
                out += self.inline(stmt.value, env, depth)
            elif isinstance(stmt, ast.Try):
                stmt = copy.deepcopy(stmt)
                stmt.body = self.block(stmt.body, env, depth, inline)
                # Handlers and else clauses are cold: keep calls as calls.
                for handler in stmt.handlers:
                    handler.body = self.block(handler.body, env, depth, False)
                stmt.orelse = self.block(stmt.orelse, env, depth, False)
                out.append(stmt)
            elif isinstance(stmt, ast.With):
                stmt = copy.deepcopy(stmt)
                stmt.body = self.block(stmt.body, env, depth, False)
                out.append(stmt)
            elif isinstance(stmt, ast.For):
                out.append(self.loop(stmt, env, depth, inline))
            elif isinstance(stmt, (ast.Assign, ast.Expr, ast.Return)):
                out.append(annotate_exact(stmt, env) or stmt)
            else:
                out.append(stmt)
            if terminates(out):
                break
        return out

    # -- loops ---------------------------------------------------------------

    @staticmethod
    def can_version(env, name):
        value = env.get(name)
        return not (value == NULL or isinstance(value, (type, Value, IterOf,
                                                        Other)))

    def version(self, name, tail, env, depth, inline):
        """*tail*, which starts iterating *name* (of unknown type),
        specialized for each exact type of VERSIONED_ITERABLES that gives
        an index loop, and kept generic for the other types, as a chain of
        ``if type(name) is K:``; None if no type gives an index loop."""
        branches = []
        for tp in VERSIONED_ITERABLES:
            residual = self.block(copy.deepcopy(tail), env | {name: tp},
                                  depth, True)
            if _has_index_loop(residual, name):
                branches.append((tp, residual))
        if not branches:
            return None
        other = Other(tp for tp, _ in branches)
        out = self.block(tail, env | {name: other}, depth, inline)
        for tp, residual in reversed(branches):
            out = [ast.If(_type_test(name, tp), residual, out)]
        return out

    def loop(self, stmt, env, depth, inline):
        """``for item in it:``, specialized: see the module docstring.
        The copy is marked with ``pyspec_iterable``, the exact type of the
        iterated object (None if unknown), and ``pyspec_sequence``, true
        when it iterates a list or tuple by index (``for item in x:``)."""
        if (stmt.orelse or not isinstance(stmt.target, ast.Name)
                or not isinstance(stmt.iter, ast.Name)):
            raise ValueError(f'unsupported loop {ast.unparse(stmt)}')
        item = stmt.target.id
        new = copy.copy(stmt)
        fact = env.get(stmt.iter.id)
        iterable = None
        sequence = False
        if isinstance(fact, IterOf):
            iterable = fact.tp
            if iterable in SEQUENCES:
                new.iter = ast.Name(fact.source, ast.Load())
                sequence = True
        elif isinstance(fact, type) and fact in SEQUENCES:
            iterable = fact
            sequence = True
        item_type = ITERATION.get(iterable)
        body = self.block(stmt.body, env | {item: item_type or NOTNULL},
                          depth, inline)
        if item_type is None:
            body = [split for part in body
                    for split in _split_on_item_type(part, item)]
        new.body = body
        new.pyspec_iterable = iterable
        new.pyspec_sequence = sequence
        return new


def remove_dead_iterators(stmts, live=frozenset()):
    """Remove the ``it = iter(x)`` marked pure (x of a type of ITERATION,
    whose iter() only allocates) when *it* is not used afterwards.
    *live*: the names used after *stmts*."""
    out = []
    live = set(live)
    for stmt in reversed(stmts):
        if (getattr(stmt, 'pyspec_pure', False)
                and stmt.targets[0].id not in live):
            continue
        after = live | (_names_loaded([stmt])
                        if isinstance(stmt, ast.For) else set())
        for field in ('body', 'orelse'):
            block = getattr(stmt, field, None)
            if isinstance(block, list) and block:
                block = remove_dead_iterators(block, after)
                if not block and field == 'body':
                    block = [ast.Pass()]
                setattr(stmt, field, block)
        for handler in getattr(stmt, 'handlers', ()):
            handler.body = remove_dead_iterators(handler.body, after)
        live |= _names_loaded([stmt])
        out.append(stmt)
    out.reverse()
    return out


def specialize(spec, name, env, inline=True):
    """Residual statements of spec function *name* under facts *env*.

    *spec* is a frontend.Spec.  With *inline* false, tail calls of other
    spec functions stay calls, except where the block is versioned.
    """
    residual = Evaluator(spec).block(spec.body(name), env, inline=inline)
    return remove_dead_iterators(residual)

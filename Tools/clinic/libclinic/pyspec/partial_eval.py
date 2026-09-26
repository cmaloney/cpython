"""Partial evaluation of pyspec functions.

Given facts a call site knows -- which arguments are NULL, and optionally
the exact type of an argument -- fold the branches those facts decide and
inline tail calls to other spec functions.  The result is a list of ast
statements in the same Python subset the C emitter accepts.
"""

import ast
import builtins
import copy
import itertools

# Fact values in an environment: NULL, NOTNULL, an exact type (of the
# object the name refers to), or Value(obj) for the object itself.
NULL = 'NULL'
NOTNULL = 'NOTNULL'


class Value:
    """The name refers to exactly this object (e.g. cls is bytes)."""

    def __init__(self, obj):
        self.obj = obj


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
        if value == NOTNULL or isinstance(value, (type, Value)):
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
        if tp is None or klass is None:
            return None
        return tp is klass
    return None


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
                    stmt = copy.copy(stmt)
                    stmt.body = (self.block(stmt.body, env, depth, inline)
                                 or [ast.Pass()])
                    stmt.orelse = self.block(stmt.orelse, env, depth, inline)
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
            else:
                out.append(stmt)
            if terminates(out):
                break
        return out


def specialize(spec, name, env):
    """Residual statements of spec function *name* under facts *env*.

    *spec* is a frontend.Spec.
    """
    return Evaluator(spec).block(spec.body(name), env)

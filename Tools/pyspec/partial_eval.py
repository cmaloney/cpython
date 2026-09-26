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

MAX_INLINE_DEPTH = 8


class Spec:
    def __init__(self, source, filename='<spec>'):
        self.filename = filename
        self.module = ast.parse(source, filename)
        self.functions = {node.name: node for node in self.module.body
                          if isinstance(node, ast.FunctionDef)}
        self.config = {}
        for node in self.module.body:
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id == 'PYSPEC'):
                self.config = ast.literal_eval(node.value)

    def body(self, name):
        """Statements of function *name*, without its docstring."""
        body = self.functions[name].body
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            body = body[1:]
        return body

    def params(self, name):
        return [a.arg for a in self.functions[name].args.args]


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


class Evaluator:
    def __init__(self, spec):
        self.spec = spec
        self._suffix = itertools.count(1)

    def _is_spec_call(self, node):
        return (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in self.spec.functions)

    def inline(self, call, env, depth):
        name = call.func.id
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
        for i, stmt in enumerate(stmts):
            if isinstance(stmt, ast.If):
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
    """Residual statements of spec function *name* under facts *env*."""
    return Evaluator(spec).block(spec.body(name), env)

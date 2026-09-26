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

In a loop body, a statement that passes the item to an escape with a
fast path (Escape.fast, e.g. PyNumber_AsSsize_t() of a compact exact
int) is split: ``if C.<escape>.fast(item): <statement> else:
<statement>``, the first one with the call marked ``call.pyspec_fast``
for the emitter.  The rest of the body is shared.

Shared specializations.  A tail call of a spec function whose residual
for the facts of the call has a loop is not inlined: the residual becomes
a C function of its own (a Specialization), emitted once and called by
every call with the same facts.  A loop costs far more than a call, and
the loop code is not duplicated.  A residual that does not iterate by
index is not worth its own code: the call stays a call of the generic
function, and only its facts come from the residual.

Snapshots.  The residual of a list loop is split in two, as the
hand-written _PyBytes_FromSequence_lock_held() was: every statement that
may run Python code (per the facts of call_table.Analyzer) is replaced by
``return FALLBACK``, and the rest, which runs no Python code, is called
with the list locked (a critical section; nothing without free
threading): nothing can change the list meanwhile, so it iterates a
consistent snapshot, borrows its items, and reads its size once.  On
FALLBACK the call restarts through the generic, unspecialized function.
As the snapshot ran no Python code, the restart cannot be observed.

Capacity.  A buffer created with the length of a sequence (Escape.length,
Escape.capacity) that a loop over the sequence appends to at most once
per iteration needs no capacity check in that loop
(Escape.unchecked), when the loop runs a fixed number of iterations: a
tuple, or a list in a snapshot.
"""

import ast
import builtins
import copy
import itertools
import types
import weakref

from . import runtime

# Fact values in an environment: NULL, NOTNULL, an exact type (of the
# object the name refers to), Value(obj) for the object itself, IterOf(x,
# K) for the result of iter(x), or Other(types) for an object of none of
# these exact types.
NULL = 'NULL'
NOTNULL = 'NOTNULL'

# ``return FALLBACK`` in a snapshot (see the module docstring): restart
# through the generic function.
FALLBACK = 'FALLBACK'


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

# The special methods a spec may test, with hasattr(type(x), name) or
# C.lookup_special(x, name).
SPECIALS = ('__buffer__', '__bytes__', '__index__')

# The builtin types without a spec class that the evaluator may know as
# exact types: (base, the SPECIALS the type itself defines).  Written out
# instead of read from the builtins of the Python running Argument Clinic
# (PYTHON_FOR_REGEN may be older than the Python being built: before 3.12
# no type has __buffer__).  A spec class decorated with @static_type (the
# whole type, e.g. bytes) is described by its own methods instead.
# test_clinic checks this table against the Python being built.
BUILTIN_TYPES = {
    object: (None, ()),
    int: (object, ('__index__',)),
    bool: (int, ()),
    float: (object, ()),
    str: (object, ()),
    bytearray: (object, ('__buffer__',)),
    memoryview: (object, ('__buffer__',)),
    list: (object, ()),
    tuple: (object, ()),
    dict: (object, ()),
    set: (object, ()),
    frozenset: (object, ()),
    range: (object, ()),
    types.GeneratorType: (object, ()),
    type(iter([])): (object, ()),       # list_iterator
    types.NoneType: (object, ()),
}


class TypeFacts:
    """What the evaluator knows about builtin types: from the spec for its
    @static_type classes, else from BUILTIN_TYPES; nothing about other
    types.  Never from the Python running Argument Clinic."""

    def __init__(self, spec):
        self.spec = spec

    def spec_class(self, tp):
        """The complete spec class (@static_type) of builtin tp, or None."""
        node = self.spec.classes.get(tp.__name__)
        if node is None or getattr(builtins, tp.__name__, None) is not tp:
            return None
        for decorator in node.decorator_list:
            if (isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Name)
                    and decorator.func.id == 'static_type'):
                return node
        return None

    def mro(self, tp):
        """The MRO of tp, or None when tp is not known."""
        out = []
        while tp is not None:
            if self.spec_class(tp) is not None:
                out.append(tp)
                tp = object
            elif tp in BUILTIN_TYPES:
                out.append(tp)
                tp = BUILTIN_TYPES[tp][0]
            else:
                return None
        return out

    def defines(self, tp, name):
        """Whether tp itself defines special method *name* (in SPECIALS)."""
        if self.spec_class(tp) is not None:
            full = f'{tp.__name__}.{name}'
            return (full in self.spec.functions or full in self.spec.clones
                    or full in self.spec.shared)
        return name in BUILTIN_TYPES[tp][1]

    def owner(self, tp, name):
        """The class of the MRO of tp that defines *name*: False when none
        does, None when not known."""
        mro = self.mro(tp)
        if mro is None or name not in SPECIALS:
            return None
        for klass in mro:
            if self.defines(klass, name):
                return klass
        return False

    def has(self, tp, name):
        """hasattr(tp, name) for a special method; None when not known."""
        owner = self.owner(tp, name)
        return None if owner is None else owner is not False

    def is_subclass(self, tp, klass):
        mro = self.mro(tp)
        if mro is None:
            return None
        return klass in mro


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


def evaluate(expr, env, facts):
    """Return True, False, or None when *expr* is not decided by *env*.
    *facts*: the TypeFacts of the spec."""
    match expr:
        case ast.UnaryOp(op=ast.Not(), operand=operand):
            value = evaluate(operand, env, facts)
            return None if value is None else not value
        case ast.BoolOp(op=op, values=values):
            results = [evaluate(v, env, facts) for v in values]
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
            value = _evaluate_is(left, right, env, facts)
            if value is None:
                return None
            return value != isinstance(op, ast.IsNot)
        case ast.Call(func=ast.Name('isinstance'), args=[obj, cls]):
            tp, klass = _known_type(env, obj), _builtin_type(cls)
            if tp is None or klass is None:
                return None
            return facts.is_subclass(tp, klass)
        case ast.Call(func=ast.Name('hasattr'),
                      args=[type_call, ast.Constant(str() as name)]) \
                if _is_type_call(type_call):
            tp = _known_type(env, type_call.args[0])
            return None if tp is None else facts.has(tp, name)
    return None


def _evaluate_is(left, right, env, facts):
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
                if tp is not None and facts.has(tp, name) is False:
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


def _index_loops(spec, stmts):
    """The names iterated by index in *stmts*, directly or by the
    specializations called."""
    names = set()
    for stmt in stmts:
        for node in ast.walk(stmt):
            if (isinstance(node, ast.For)
                    and getattr(node, 'pyspec_sequence', False)
                    and isinstance(node.iter, ast.Name)):
                names.add(node.iter.id)
            called = specialization_of(spec, node)
            if called is not None:
                names.update(arg.id for param, arg in zip(called.params,
                                                          node.args)
                             if param in called.index_params
                             and isinstance(arg, ast.Name))
    return names


def annotate_exact(stmt, env):
    """A copy of *stmt* (an assignment, an expression statement or a
    return) with the escape calls whose first argument has a known exact
    type that the escape lowers more cheaply (Escape.exact) marked with it
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


def fast_guard(node):
    """(escape name, item name) for ``C.<escape>.fast(item)``, else None."""
    match node:
        case ast.Call(func=ast.Attribute(
                          ast.Attribute(ast.Name('C'), name), 'fast'),
                      args=[ast.Name(item)]):
            return name, item
    return None


def _split_fast(stmt, item, item_type):
    """[stmt], or, if *stmt* (an assignment or an expression statement)
    passes *item* (of exact type item_type, None if unknown) as the first
    argument of an escape with a fast path (Escape.fast) for that type,
    ``if C.<escape>.fast(item): <stmt, marked> else: <stmt>``.  The guard
    is marked with item_type (``pyspec_item_type``): the emitter only
    tests the type when it is not known."""
    if not isinstance(stmt, (ast.Assign, ast.Expr)):
        return [stmt]
    marked = copy.deepcopy(stmt)
    for node in ast.walk(marked):
        if not (isinstance(node, ast.Call) and node.args
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == item):
            continue
        escape = _escape(node.func)
        fast = getattr(escape, 'fast', None)
        if fast is None or (item_type is not None
                            and item_type not in fast.types):
            continue
        node.pyspec_fast = True
        guard = ast.Call(
            ast.Attribute(ast.Attribute(ast.Name('C', ast.Load()),
                                        node.func.attr, ast.Load()),
                          'fast', ast.Load()),
            [ast.Name(item, ast.Load())], [])
        guard.pyspec_item_type = item_type
        return [ast.If(guard, [marked], [stmt])]
    return [stmt]


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
        self.facts = TypeFacts(spec)
        self._suffix = itertools.count(1)

    def special_method(self, tp, name):
        """The spec method (name) that C.lookup_special(x, name) finds for
        an object x of exact type tp, or None when not known statically.
        The types TypeFacts knows are static types: their methods cannot
        change."""
        owner = self.facts.owner(tp, name)
        if not owner:
            return None
        spec_name = f'{owner.__name__}.{name}'
        node = self.spec.functions.get(spec_name)
        if self.spec.implemented(spec_name) and not node.decorator_list:
            return spec_name
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
        outlined = self.outline(call, env, depth)
        if outlined is not None:
            return outlined
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
            specials = (self.pure_specials(stmt.test)
                        if isinstance(stmt, ast.If) and bound is None
                        else None)
            if specials and specials[1] and self.can_version(env,
                                                             specials[0]):
                # The lookup and the call are known for these exact types:
                # versioned, as for iteration.
                versioned = self.version(specials[0], [stmt, *stmts[i:]],
                                         env, depth, inline, specials[1])
                if versioned is not None:
                    out += versioned
                    break
            if bound is not None:
                target, method, value = bound
                env = env | {target: method}
                out += self.block(stmt.body if value else stmt.orelse, env,
                                  depth, inline)
            elif isinstance(stmt, ast.If):
                value = evaluate(stmt.test, env, self.facts)
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

    def outline(self, call, env, depth):
        """``[return <call of a Specialization>]`` for a tail call of a
        spec function whose residual for the facts of the call has a
        loop, else None."""
        name = self.spec.call_target(call.func)
        params = self.spec.params(name)
        if ('.' in name or len(call.args) != len(params)
                or not all(isinstance(a, ast.Name) for a in call.args)):
            return None
        args = [a.id for a in call.args]
        callee_env = {}
        for param, arg in zip(params, args):
            fact = env.get(arg)
            if isinstance(fact, IterOf):
                fact = (IterOf(params[args.index(fact.source)], fact.tp)
                        if fact.source in args else NOTNULL)
            if fact is not None and not isinstance(fact, Bound):
                callee_env[param] = fact
        special = specialize_call(self.spec, name, callee_env, depth + 1)
        if special is None:
            return None
        if not special.index_params:
            # Not worth its own code: the generic function, with the
            # facts of the specialization.
            call = copy.copy(call)
            call.pyspec_facts = special.name
            return [ast.Return(call, lineno=0)]
        return [ast.Return(special.call([call.args[params.index(p)]
                                         for p in special.params]),
                           lineno=0)]

    # -- loops ---------------------------------------------------------------

    @staticmethod
    def can_version(env, name):
        value = env.get(name)
        return not (value == NULL or isinstance(value, (type, Value, IterOf)))

    def version(self, name, tail, env, depth, inline, types=None):
        """*tail*, which starts iterating *name* (of unknown type),
        specialized for each exact type of VERSIONED_ITERABLES that gives
        an index loop (or for each of *types*), and kept generic for the
        other types, as a chain of ``if type(name) is K:``; None if no
        type gives an index loop."""
        known = env.get(name)
        excluded = known.types if isinstance(known, Other) else ()
        branches = []
        for tp in types or VERSIONED_ITERABLES:
            if tp in excluded:
                continue
            residual = self.block(copy.deepcopy(tail), env | {name: tp},
                                  depth, True)
            if types or name in _index_loops(self.spec, residual):
                branches.append((tp, residual))
        if not branches:
            return None
        other = Other([*excluded, *(tp for tp, _ in branches)])
        out = self.block(tail, env | {name: other}, depth, inline)
        for tp, residual in reversed(branches):
            out = [ast.If(_type_test(name, tp), residual, out)]
        return out

    def pure_specials(self, test):
        """(x, the types whose special method the test looks up is pure
        on x: see bind_special()) for ``if (v := C.lookup_special(x,
        "name")) is [not] NULL``; else None."""
        match test:
            case ast.Compare(
                    left=ast.NamedExpr(value=ast.Call(
                        func=ast.Attribute(ast.Name('C'), 'lookup_special'),
                        args=[ast.Name(obj), ast.Constant(str())])),
                    comparators=[ast.Name('NULL')]):
                pass
            case _:
                return None
        types = []
        for cls_name in self.spec.classes:
            tp = getattr(builtins, cls_name, None)
            if (isinstance(tp, type) and self.facts.spec_class(tp)
                    and self.bind_special(test, {obj: tp}, 0) is not None):
                types.append(tp)
        return obj, types

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
        new.body = [split for part in body
                    for split in _split_fast(part, item, item_type)]
        new.pyspec_iterable = iterable
        new.pyspec_sequence = sequence
        return new


# -- shared specializations (see the module docstring) -----------------------

# spec -> {(callee, facts): Specialization or None, and name: Specialization}
_SPECIALIZATIONS = weakref.WeakKeyDictionary()


class Specialization:
    """Spec function *callee* partially evaluated for the facts *env*
    about its parameters: the C function *name*(*params*) whose body is
    *body*.  *params* are the parameters the body uses, in order.

    *index_params*: the parameters iterated by index.  *lock*: for a
    snapshot (the body may return FALLBACK), the parameter whose critical
    section the caller holds."""

    def __init__(self, name, callee, params, env, body, lock=None):
        self.name = name
        self.callee = callee
        self.params = params
        self.env = env
        self.body = body
        self.lock = lock
        self.index_params = set()

    def call(self, args):
        node = ast.Call(ast.Name(self.name, ast.Load()),
                        [copy.copy(a) for a in args], [])
        node.pyspec_specialization = self.name
        return node

    def types(self):
        """The exact types of the parameters."""
        return {p: v for p, v in self.env.items() if isinstance(v, type)}


def _registry(spec):
    try:
        return _SPECIALIZATIONS[spec]
    except KeyError:
        return _SPECIALIZATIONS.setdefault(spec, {})


def specialization(spec, name):
    """The Specialization called *name*."""
    return _registry(spec)[name]


def specialization_of(spec, node, facts=False):
    """The Specialization a call node calls, or None.  With *facts*, also
    the one whose facts a call of the generic function has
    (``pyspec_facts``)."""
    name = getattr(node, 'pyspec_specialization', None)
    if name is None and facts:
        name = getattr(node, 'pyspec_facts', None)
    return None if name is None else specialization(spec, name)


def _fact_key(fact):
    match fact:
        case type():
            return fact.__name__
        case Value():
            return ('value', repr(fact.obj))
        case IterOf():
            return ('iter', fact.source, fact.tp.__name__)
        case Other():
            return ('other', tuple(tp.__name__ for tp in fact.types))
    return fact


def _has_loop(stmts):
    return any(isinstance(node, ast.For)
               for stmt in stmts for node in ast.walk(stmt))


def _unique_name(taken, base):
    name, suffix = base, itertools.count(2)
    while name in taken:
        name = f'{base}_{next(suffix)}'
    return name


def specialize_call(spec, callee, env, depth=0):
    """The Specialization of spec function *callee* for the facts *env*
    about its parameters, or None when its residual has no loop (the
    call is inlined instead).  Made once per (callee, facts)."""
    registry = _registry(spec)
    params = spec.params(callee)
    key = (callee, tuple((p, _fact_key(env.get(p))) for p in params))
    if key in registry:
        return registry[key]
    registry[key] = None            # while evaluating: recursion inlines
    body = Evaluator(spec).block(spec.body(callee), env, depth)
    # A private copy: the residual shares nodes with the spec, and the
    # snapshot and mark_presized() mark them.
    body = copy.deepcopy(remove_dead_iterators(body))
    if not _has_loop(body):
        return None
    type_names = [env[p].__name__ for p in params
                  if isinstance(env.get(p), type)]
    name = _unique_name(registry, '_'.join([callee, *type_names]))
    special = _snapshot(spec, callee, name, params, env, body)
    if special is None:
        mark_presized(body)
        loaded = _names_loaded(body)
        special = Specialization(name, callee,
                                 [p for p in params if p in loaded], env,
                                 body)
        special.index_params = (_index_loops(spec, body)
                                & set(special.params))
    registry[key] = registry[name] = special
    return special


def _snapshot(spec, callee, name, params, env, body):
    """For a *body* iterating one list parameter by index: the
    Specialization *name* that calls NAME_lock_held(), the snapshot of
    *body*, in the critical section of the list, and on FALLBACK restarts
    with the generic callee.  None when the body is not a list loop or has
    no path without Python code."""
    loops = [node for stmt in body for node in ast.walk(stmt)
             if isinstance(node, ast.For)]
    match loops:
        case [ast.For(iter=ast.Name(seq)) as loop] if (
                loop.pyspec_sequence and loop.pyspec_iterable is list
                and seq in params):
            pass
        case _:
            return None
    from .call_table import Analyzer
    snapshot = _Snapshot(Analyzer(spec), loop)
    free = snapshot.block(body, {p: v for p, v in env.items()
                                 if isinstance(v, type)})
    if free is None or not snapshot.returns:
        return None
    mark_presized(free)
    loaded = _names_loaded(free)
    held = Specialization(f'{name}_lock_held', callee,
                          [p for p in params if p in loaded], env, free,
                          lock=seq)
    held.index_params = {seq}
    _registry(spec)[held.name] = held

    # The arguments of the restart: an iterator iter(p) of a parameter p
    # is made again.
    rebuilt = {p: env[p].source for p in params
               if isinstance(env.get(p), IterOf) and p not in held.params
               and env[p].source in params}
    result = _unique_name(set(params), 'result')

    def load(n):
        return ast.Name(n, ast.Load())

    def store(n):
        return ast.Name(n, ast.Store())

    lock = ast.Call(ast.Attribute(load('C'), 'critical_section', ast.Load()),
                    [load(seq)], [])
    glue = [
        ast.With([ast.withitem(lock)],
                 [ast.Assign([store(result)],
                             held.call([load(p) for p in held.params]),
                             lineno=0)],
                 lineno=0),
        ast.If(ast.Compare(load(result), [ast.IsNot()], [load(FALLBACK)]),
               [ast.Return(load(result))], []),
        *[ast.Assign([store(p)], ast.Call(load('iter'), [load(source)], []),
                     lineno=0)
          for p, source in rebuilt.items()],
        ast.Return(ast.Call(load(callee), [load(p) for p in params], [])),
    ]
    special = Specialization(name, callee,
                             [p for p in params if p not in rebuilt], env,
                             glue)
    special.index_params = {seq}
    return special


class _Snapshot:
    """The snapshot of a list loop: see _snapshot()."""

    def __init__(self, analyzer, loop):
        self.analyzer = analyzer
        self.loop = loop
        self.returns = False        # some path returns a result

    def runs_python(self, stmts, types):
        return self.analyzer.facts(stmts, types).runs_python

    def block(self, stmts, types, in_loop=False):
        """*stmts* with the statements that may run Python code replaced
        by ``return FALLBACK``; None if one is outside the loop."""
        out = []
        for stmt in stmts:
            if isinstance(stmt, ast.If) and not self.runs_python(
                    [ast.If(stmt.test, [ast.Pass()], [])], types):
                body_types, else_types = self.analyzer.refine(stmt.test)
                new = copy.copy(stmt)
                new.body = self.block(stmt.body, types | body_types, in_loop)
                new.orelse = self.block(stmt.orelse, types | else_types,
                                        in_loop)
                if new.body is None or new.orelse is None:
                    return None
                new.body = new.body or [ast.Pass()]
                stmt = new
            elif stmt is self.loop:
                new = copy.copy(stmt)
                new.body = self.block(stmt.body, types, True)
                if new.body is None:
                    return None
                new.pyspec_python_free = True
                stmt = new
            elif self.runs_python([stmt], types):
                if not in_loop:
                    return None
                out.append(ast.Return(ast.Name(FALLBACK, ast.Load())))
                break
            elif isinstance(stmt, ast.Return):
                self.returns = True
            out.append(stmt)
            if terminates(out):
                break
        return out


def mark_presized(stmts):
    """Mark ``call.pyspec_unchecked`` the appends to a buffer that has
    room for all of them: see Capacity in the module docstring.  Only the
    top level of *stmts* (a function body) is scanned."""
    lengths = {}            # local -> the sequence it is the length of
    capacity = {}           # buffer local -> the sequence it has room for
    for stmt in stmts:
        match stmt:
            case ast.Assign(targets=[ast.Name(target)],
                            value=ast.Call(func=func,
                                           args=[ast.Name(arg), *_]) as call):
                escape = _escape(func)
                if (getattr(escape, 'length', False)
                        and getattr(call, 'pyspec_exact', None)):
                    lengths[target] = arg
                    continue
                if getattr(escape, 'capacity', False) and arg in lengths:
                    capacity[target] = lengths[arg]
                    continue
            case ast.For(iter=ast.Name(seq)) if (
                    stmt.pyspec_sequence
                    and (stmt.pyspec_iterable is tuple
                         or getattr(stmt, 'pyspec_python_free', False))):
                inner = [node for part in stmt.body
                         for node in ast.walk(part)]
                if not any(isinstance(node, ast.For) for node in inner):
                    for buffer, sequence in capacity.items():
                        appends = [node for node in inner
                                   if _appends_to(node, buffer)]
                        if sequence == seq and len(appends) <= 1:
                            for node in appends:
                                node.pyspec_unchecked = True
        # Any other use of a buffer: it is no longer known to have room.
        loaded = _names_loaded([stmt])
        capacity = {b: q for b, q in capacity.items() if b not in loaded}


def _appends_to(node, buffer):
    return (isinstance(node, ast.Call)
            and getattr(_escape(node.func), 'unchecked', None) is not None
            and node.args and isinstance(node.args[0], ast.Name)
            and node.args[0].id == buffer)


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
        if isinstance(stmt, ast.Assign):
            live -= {target.id for target in stmt.targets
                     if isinstance(target, ast.Name)}
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

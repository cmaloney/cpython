"""Facts derived from the bodies of a spec.

The facts of a list of statements (Facts) are what every path does:

* returns: per ``return``, the exact type of the result (or None) and
  the index of the argument it returns (or None); ``return NULL`` is an
  absent result, not an error (returns_null);
* runs_python: some path may run Python code;
* raises: the exceptions some path may raise: the names of builtin
  exception classes, or ANY.

They come from the statements only: a spec function called is analyzed
in turn, and a @c_implemented function through its Python reference,
partially evaluated for the facts known about the arguments of the call
(partial_eval.py).  The primitives of runtime.py say what plain Python
cannot: exact(T) and unknown() are new objects (of type T, or of a type
not known exactly) and may fail with MemoryError; calls(x, "__name__")
runs what the special method of type(x) runs (builtin_types.TypeFacts:
the spec of the type, or the audited table of builtin_types.py; anything
else may run Python code and raise anything); runs_python() may run
Python code and raise anything.  ``len(x)`` and ``iter(x)`` call
``__len__`` and ``__iter__``.  A call of an object (a method found,
``cls(result)``) and a function about which nothing is known (a body of
``...``) may do anything.

In the Python reference of a @c_implemented function, what is not one of
these is the model of the values the C computes: it has no effects (the
effects of the C are the ones stated).  The c_calls dimension of
disconnects.py checks them against the C: every call in the C function
that may run Python code must be accounted for by one of them.
"""

import ast
import builtins
import weakref

from . import builtin_types, frontend

# Raises any exception.
ANY = 'ANY'

# The builtins whose calls have no effects.
PURE_BUILTINS = ('isinstance', 'hasattr', 'type', 'tp_name', 'fqname')


class Facts:
    """Facts about the results of a list of statements."""

    def __init__(self):
        # Per return: (exact type or None, index of the argument it
        # returns or None).
        self.returns = []
        self.returns_null = False
        self.runs_python = False
        self.raises = set()

    def worst(self):
        self.returns.append((None, None))
        self.returns_null = self.runs_python = True
        self.raises.add(ANY)

    def add(self, other):
        """The effects of *other* (a call) happen here."""
        self.runs_python |= other.runs_python
        self.raises |= other.raises

    @property
    def always_raises(self):
        return not self.returns and not self.returns_null

    @property
    def result_type(self):
        types = {tp for tp, _ in self.returns}
        if len(types) == 1 and None not in types:
            return types.pop()
        return None

    @property
    def alias(self):
        aliases = {alias for _, alias in self.returns}
        if len(aliases) == 1 and None not in aliases:
            return aliases.pop()
        return None

    def raises_any(self, names):
        """Whether it may raise an exception that ``except names`` (the
        names of builtin exception classes) catches."""
        if ANY in self.raises:
            return True
        classes = [getattr(builtins, name, None) for name in names]
        if None in classes:
            return True
        return any(issubclass(getattr(builtins, raised), tuple(classes))
                   for raised in self.raises)

    def key(self):
        return (self.runs_python, self.always_raises, self.result_type,
                self.alias)


def _exception_name(node, env):
    """The builtin exception class ``raise node`` raises, or ANY."""
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Name):
        value = getattr(env.get(node.id), 'obj', None)
        if value is None:
            value = getattr(builtins, node.id, None)
        if isinstance(value, type) and issubclass(value, BaseException):
            return value.__name__
    return ANY


_ANALYZERS = weakref.WeakKeyDictionary()


def analyzer(spec):
    """The Analyzer of *spec* (a frontend.Spec)."""
    try:
        return _ANALYZERS[spec]
    except KeyError:
        return _ANALYZERS.setdefault(spec, Analyzer(spec))


class Analyzer:
    def __init__(self, spec):
        self.spec = spec
        self.types = builtin_types.TypeFacts(spec)
        self._function_facts = {}
        self._callee_facts = {}
        self.params = []
        self.reference = False

    # -- whole functions ----------------------------------------------------

    def function_facts(self, name, special=None):
        """Facts of spec function *name* for any arguments, or of the
        partial_eval.Specialization *special* for its facts."""
        key = name if special is None else ('specialization', special.name)
        if key not in self._function_facts:
            # Recursion: assume the worst while analyzing.
            self._function_facts[key] = worst = Facts()
            worst.worst()
            if special is None:
                facts = self.facts(self.spec.body(name), {})
            else:
                facts = self.facts(special.body, special.env)
            self._function_facts[key] = facts
        return self._function_facts[key]

    def reference_facts(self, name, env):
        """Facts of @c_implemented function *name* of this spec, called
        with the facts *env* about its parameters: of its Python
        reference, partially evaluated for them."""
        from . import partial_eval
        params = self.spec.params(name)
        key = (name, tuple(partial_eval.fact_key(env.get(p))
                           for p in params))
        if key not in self._callee_facts:
            self._callee_facts[key] = worst = Facts()
            worst.worst()
            residual = partial_eval.specialize(self.spec, name, env)
            saved, self.reference = self.reference, True
            try:
                facts = self.facts(residual, env, params)
            finally:
                self.reference = saved
            self._callee_facts[key] = facts
        return self._callee_facts[key]

    def call_facts(self, call, env):
        """Facts of the call of a hand-written C function (@c_implemented,
        or a stub: worst), with the facts *env* of the caller; None when
        *call* is not one."""
        from . import partial_eval
        found = self.spec.c_function(call)
        if found is None:
            return None
        spec, node = found
        if not frontend.is_c_implemented(node):
            facts = Facts()
            facts.worst()
            return facts
        params = spec.params(node.name)
        callee_env = {}
        for param, arg in zip(params, call.args):
            fact = partial_eval.arg_fact(arg, env)
            if fact is not None:
                callee_env[param] = fact
        return analyzer(spec).reference_facts(node.name, callee_env)

    def facts(self, stmts, env, params=()):
        """Facts of *stmts*; *env* holds the facts about names (exact
        types, NULL, ... see partial_eval.py); *params* are the names of
        the call arguments, in order (a return of one of them is an alias
        of that argument)."""
        facts = Facts()
        saved, self.params = self.params, list(params)
        try:
            self.block(stmts, dict(env), facts)
        finally:
            self.params = saved
        return facts

    # -- statements ---------------------------------------------------------

    def block(self, stmts, env, facts):
        for stmt in stmts:
            self.statement(stmt, env, facts)

    def statement(self, stmt, env, facts):
        from . import partial_eval
        match stmt:
            case ast.Pass() | ast.Expr(ast.Constant()):
                pass
            case ast.If(test=test, body=body, orelse=orelse):
                self.expression(test, env, facts)
                body_env, else_env = partial_eval.refine(test, env)
                self.block(body, dict(body_env), facts)
                self.block(orelse, dict(else_env), facts)
            case ast.Assign(targets=[ast.Name(name)], value=value):
                tp = self.value_type(value, env, facts)
                if tp is not None:
                    env[name] = tp
                else:
                    env.pop(name, None)
            case ast.Return(value=ast.Name(partial_eval.FALLBACK)):
                # A snapshot restarts: the caller returns another result.
                pass
            case ast.Return(value=ast.Name('NULL')):
                facts.returns_null = True
            case ast.Return(value=value):
                facts.returns.append(self.value(value, env, facts))
            case ast.Raise(exc=exc):
                # Building the message only formats type names.
                if isinstance(exc, ast.Call) and self._c_call(exc):
                    self.call(exc, env, facts)
                else:
                    facts.raises.add(_exception_name(exc, env))
            case ast.Try(body=body, handlers=handlers, orelse=orelse,
                         finalbody=finalbody):
                self.block(body, env, facts)
                for handler in handlers:
                    self.block(handler.body, dict(env), facts)
                self.block(orelse, dict(env), facts)
                self.block(finalbody, env, facts)
            case ast.With(body=body):
                self.block(body, env, facts)
            case ast.Expr(value=ast.Call() as call):
                self.call(call, env, facts)
            case ast.For(target=ast.Name(item), body=body):
                # The partial evaluator marks the exact type of the
                # iterated object when it knows it (see partial_eval.py).
                iterable = getattr(stmt, 'pyspec_iterable', None)
                known, item_type = self.iteration(iterable)
                if not known:
                    facts.runs_python = True
                    facts.raises.add(ANY)
                body_env = dict(env)
                body_env[item] = item_type or partial_eval.NOTNULL
                self.block(body, body_env, facts)
            case _ if self.reference:
                pass        # the model of a value: no effects
            case _:
                facts.worst()

    def expression(self, node, env, facts):
        """Account for the calls a condition makes."""
        named = [child.value for child in ast.walk(node)
                 if isinstance(child, ast.NamedExpr)]
        for child in ast.walk(node):
            if isinstance(child, ast.NamedExpr):
                self.value_type(child.value, env, facts)
            elif (isinstance(child, ast.Call)
                    and not any(child is value for value in named)
                    and not (isinstance(child.func, ast.Name)
                             and child.func.id in PURE_BUILTINS)):
                self.call(child, env, facts)

    def iteration(self, tp):
        """(iterating an object of exact type tp runs no Python code, the
        exact type of the items or None)."""
        from . import partial_eval
        if tp in partial_eval.SEQUENCES:
            return True, None
        special = self.types.special(tp, '__iter__') if tp else None
        if special is None or special[0] is not None:
            return False, None
        item = special[1]
        if item in (False, None, builtin_types.PYTHON):
            return False, None
        return True, (None if item is object else item)

    # -- values -------------------------------------------------------------

    def value(self, node, env, facts):
        """(exact type or None, argument index or None) of a returned
        value."""
        alias = None
        if isinstance(node, ast.Name) and node.id in self.params:
            alias = self.params.index(node.id)
        return self.value_type(node, env, facts), alias

    def value_type(self, node, env, facts):
        match node:
            case ast.Constant(value=value):
                return type(value)
            case ast.Name(name):
                value = env.get(name)
                return value if isinstance(value, type) else None
            case ast.Call():
                return self.call(node, env, facts)
        if not self.reference:
            facts.worst()
        return None

    def _c_call(self, call):
        return self.spec.c_function(call) is not None

    def call(self, node, env, facts):
        """Exact result type of call *node*; its effects go to *facts*."""
        from . import partial_eval
        func = node.func
        special = partial_eval.specialization_of(self.spec, node,
                                                 facts=True)
        if special is not None:
            facts.add(self.function_facts(special.callee, special))
            return self.function_facts(special.callee, special).result_type
        callee = self.call_facts(node, env)
        if callee is not None:
            facts.add(callee)
            return callee.result_type
        callee_name = self.spec.call_target(func)
        if callee_name is not None:
            # An implemented spec function.
            callee = self.function_facts(callee_name)
            facts.add(callee)
            return callee.result_type
        name = func.id if isinstance(func, ast.Name) else None
        args = node.args
        match name, args:
            case 'exact', [ast.Name(tp_name), *_]:
                facts.raises.add('MemoryError')
                tp = builtin_types.by_name(tp_name)
                return tp if tp is not None else self._spec_type(tp_name)
            case 'unknown', _:
                facts.raises.add('MemoryError')
                return None
            case 'runs_python', []:
                facts.runs_python = True
                facts.raises.add(ANY)
                return None
            case 'calls', [obj, ast.Constant(str() as special)]:
                facts.add(self.special_facts(obj, special, env))
                return None
            case 'len', [ast.Name() as obj]:
                row = builtin_types.TABLE.get(
                    partial_eval.exact_type(obj, env))
                if row is None or row.size is None:
                    facts.add(self.special_facts(obj, '__len__', env))
                return int
            case 'iter', [ast.Name() as obj]:
                tp = partial_eval.exact_type(obj, env)
                known, _ = self.iteration(tp)
                if known:
                    facts.raises.add('MemoryError')
                elif self.types.special(tp, '__iter__') == (None, False):
                    facts.raises.add('TypeError')
                else:
                    facts.add(self.special_facts(obj, '__iter__', env))
                return None
        if name in PURE_BUILTINS or self.reference:
            # In a Python reference, the model of a value.
            return None
        # A call of an object: a method found, cls(result), ...
        facts.runs_python = True
        facts.raises.add(ANY)
        return None

    def _spec_type(self, name):
        """The builtin type a spec class describes, or None."""
        tp = getattr(builtins, name, None)
        return tp if isinstance(tp, type) and name in self.spec.classes \
            else None

    def special_facts(self, obj, name, env):
        """Facts of invoking special method *name* of type(obj)."""
        from . import partial_eval
        facts = Facts()
        tp = partial_eval.exact_type(obj, env)
        special = None if tp is None else self.types.special(tp, name)
        match special:
            case None:
                facts.worst()
            case (None, False):
                # The type has no such method: nothing is called.
                pass
            case (None, builtin_types.PYTHON):
                facts.worst()
            case (None, _):
                facts.raises.add(ANY)
            case (spec_name, None):
                node = self.spec.functions[spec_name]
                if frontend.is_c_implemented(node):
                    params = self.spec.params(spec_name)
                    facts.add(self.reference_facts(
                        spec_name, {params[0]: tp}))
                else:
                    facts.worst()
        return facts

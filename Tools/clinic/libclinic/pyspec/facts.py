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

from . import builtin_types, frontend, partial_eval, subset

# Raises any exception.
ANY = 'ANY'

# The builtins whose calls have no effects.
PURE_BUILTINS = ('isinstance', 'hasattr', 'type', 'tp_name', 'fqname')


class Facts:
    """Facts about the results of a list of statements; with *worst*,
    those of code about which nothing is known."""

    def __init__(self, worst=False):
        # Per return: (exact type or None, index of the argument it
        # returns or None).
        self.returns = [(None, None)] if worst else []
        self.returns_null = worst
        self.runs_python = worst
        self.raises = {ANY} if worst else set()

    def add(self, other):
        """The effects of *other* (a call) happen here."""
        self.runs_python |= other.runs_python
        self.raises |= other.raises

    def python(self):
        """Python code may run here, and raise anything."""
        self.add(Facts(worst=True))

    @property
    def always_raises(self):
        return not self.returns and not self.returns_null

    @property
    def result_type(self):
        types = {tp for tp, _ in self.returns}
        return types.pop() if len(types) == 1 and None not in types else None

    @property
    def alias(self):
        aliases = {alias for _, alias in self.returns}
        return (aliases.pop() if len(aliases) == 1 and None not in aliases
                else None)

    def raises_any(self, names):
        """Whether it may raise an exception that ``except names`` (the
        names of builtin exception classes) catches."""
        classes = tuple(getattr(builtins, name, None) for name in names)
        return ANY in self.raises or None in classes or any(
            issubclass(getattr(builtins, raised), classes)
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


def analyzer(spec):
    """The Analyzer of *spec* (a frontend.Spec), kept by the spec."""
    if getattr(spec, 'analyzer', None) is None:
        spec.analyzer = Analyzer(spec)
    return spec.analyzer


class Analyzer:
    def __init__(self, spec):
        self.spec = spec
        self.types = builtin_types.TypeFacts(spec)
        self._cache = {}
        self.params = []
        self.reference = False

    def _cached(self, key, compute):
        """compute(), once; the worst while computing (recursion)."""
        if key not in self._cache:
            self._cache[key] = Facts(worst=True)
            self._cache[key] = compute()
        return self._cache[key]

    # -- whole functions ----------------------------------------------------

    def function_facts(self, name, special=None):
        """Facts of spec function *name* for any arguments, or of the
        partial_eval.Specialization *special* for its facts."""
        if special is None:
            if subset.lowered(self.spec, name):
                return Facts(worst=True)
            return self._cached(name, lambda: self.facts(
                self.spec.body(name), {}))
        return self._cached(('specialization', special.name),
                            lambda: self.facts(special.body, special.env))

    def reference_facts(self, name, env):
        """Facts of @c_implemented function *name* of this spec, called
        with the facts *env* about its parameters: of its Python
        reference, partially evaluated for them."""
        params = self.spec.params(name)
        if subset.analysed(self.spec, name):
            # Code facts.py cannot follow: the worst facts.
            return Facts(worst=True)

        def compute():
            residual = partial_eval.specialize(self.spec, name, env)
            saved, self.reference = self.reference, True
            try:
                return self.facts(residual, env, params)
            finally:
                self.reference = saved
        return self._cached(
            (name, *(partial_eval.fact_key(env.get(p)) for p in params)),
            compute)

    def call_facts(self, call, env):
        """Facts of the call of a hand-written C function (@c_implemented,
        or a stub: worst), with the facts *env* of the caller; None when
        *call* is not one."""
        found = self.spec.c_function(call)
        if found is None:
            return None
        spec, node = found
        if not frontend.is_c_implemented(node):
            return Facts(worst=True)
        callee_env = {}
        for param, arg in zip(spec.params(node.name), call.args):
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
                env.pop(name, None)
                if tp is not None:
                    env[name] = tp
            case ast.Return(value=ast.Name(partial_eval.FALLBACK)):
                # A snapshot restarts: the caller returns another result.
                pass
            case ast.Return(value=ast.Name('NULL')):
                facts.returns_null = True
            case ast.Return(value=value):
                alias = (self.params.index(value.id)
                         if isinstance(value, ast.Name)
                         and value.id in self.params else None)
                facts.returns.append((self.value_type(value, env, facts),
                                      alias))
            case ast.Raise(exc=ast.Call() as call) \
                    if self.spec.c_function(call):
                self.call(call, env, facts)
            case ast.Raise(exc=exc):
                # Building the message only formats type names.
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
                known, item_type = self.iteration(
                    getattr(stmt, 'pyspec_iterable', None))
                if not known:
                    facts.python()
                self.block(body, env | {
                    item: item_type or partial_eval.NOTNULL}, facts)
            case _ if not self.reference:
                facts.python()
                facts.returns.append((None, None))
            # (In a Python reference: the model of a value, no effects.)

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
        if tp in partial_eval.SEQUENCES:
            return True, None
        special = self.types.special(tp, '__iter__') if tp else None
        if special is None or special[0] is not None or special[1] in (
                False, None, builtin_types.PYTHON):
            return False, None
        return True, (None if special[1] is object else special[1])

    # -- values -------------------------------------------------------------

    def value_type(self, node, env, facts):
        """The exact type of *node*, or None; its effects go to *facts*."""
        match node:
            case ast.Constant(value=value):
                return type(value)
            case ast.Name(name):
                value = env.get(name)
                return value if isinstance(value, type) else None
            case ast.Call():
                return self.call(node, env, facts)
        if not self.reference:
            facts.python()
        return None

    def call(self, node, env, facts):
        """Exact result type of call *node*; its effects go to *facts*."""
        special = partial_eval.specialization_of(self.spec, node,
                                                 facts=True)
        callee = (self.function_facts(special.callee, special) if special
                  else self.call_facts(node, env))
        if callee is None and (name := self.spec.call_target(node.func)):
            callee = self.function_facts(name)      # a spec function
        if callee is not None:
            facts.add(callee)
            return callee.result_type
        name = node.func.id if isinstance(node.func, ast.Name) else None
        match name, node.args:
            case 'exact', [ast.Name(tp_name), *_]:
                facts.raises.add('MemoryError')
                return builtin_types.by_name(tp_name)
            case 'unknown', _:
                facts.raises.add('MemoryError')
            case 'runs_python', []:
                facts.python()
            case 'calls', [obj, ast.Constant(str() as special)]:
                facts.add(self.special_facts(obj, special, env))
            case 'len', [ast.Name() as obj]:
                row = builtin_types.TABLE.get(
                    partial_eval.exact_type(obj, env))
                if row is None or row.size is None:
                    facts.add(self.special_facts(obj, '__len__', env))
                return int
            case 'iter', [ast.Name() as obj]:
                tp = partial_eval.exact_type(obj, env)
                if self.iteration(tp)[0]:
                    facts.raises.add('MemoryError')
                elif self.types.special(tp, '__iter__') == (None, False):
                    facts.raises.add('TypeError')
                else:
                    facts.add(self.special_facts(obj, '__iter__', env))
            case _ if not (name in PURE_BUILTINS or self.reference):
                # A call of an object: a method found, cls(result), ...
                facts.python()
            # (In a Python reference, other calls model a value.)
        return None

    def special_facts(self, obj, name, env):
        """Facts of invoking special method *name* of type(obj)."""
        tp = partial_eval.exact_type(obj, env)
        match None if tp is None else self.types.special(tp, name):
            case (None, False):
                return Facts()      # no such method: nothing is called
            case (None, value) if value is not builtin_types.PYTHON:
                facts = Facts()
                facts.raises.add(ANY)
                return facts
            case (spec_name, None) if frontend.is_c_implemented(
                    self.spec.functions[spec_name]):
                params = self.spec.params(spec_name)
                return self.reference_facts(spec_name, {params[0]: tp})
        return Facts(worst=True)

"""Check the facts Argument Clinic derives from the pyspec files.

The pyspec call tables (Include/internal/pycore_pyspec.h, generated from
the specs, one per spec'd class, found through the registry) give the
tier-2 optimizer direct C entry points and facts about their results: an
exact result type, a constant, an alias of an argument, and whether the
call may run Python code.  The JIT trusts them.  These tests check them
without the JIT, for every class of the registry and every spec, with
the test data of the <stem>_cases.py next to each spec (the names are
described in Objects/pyspec/bytesobject_cases.py); nothing here names a
type:

* RegistryTest: the registry is the classes the tools give tables.
* DirectCallTest calls every table entry directly (through
  _testinternalcapi) with every case of CASES its guard accepts, compares
  the outcome with the interpreter, and checks each claimed fact on the
  result.  "Runs no Python code" is checked dynamically (sys.setprofile),
  and by calling the entry in the debug-build tripwire
  (_testinternalcapi.pyspec_no_python()).
* HelperTest calls the hand-written C functions the specs call
  (@ac.stub(optimizer_info=True), HELPERS) directly, compares them with their
  Python references, and checks the facts derived from the references
  the same way.
* SlotFactsTest checks the slot facts that specialized uops use
  (_PySpec_FindSlot(), SLOT_USES) against the derivation, and the uops
  against the slots.
* DebugAssertionTest checks the debug-build run-time assertions of
  optimizer facts and the "no Python" tripwire.
* SoundnessTest pins soundness problems found in review (the class
  methods of a subclass, FACTS with a run).
"""

import builtins
import dis
import functools
import gc
import os
import sys
import textwrap
import types
import unittest
from test import support, test_tools
from test.support import import_helper, script_helper

_testinternalcapi = import_helper.import_module('_testinternalcapi')
test_tools.skip_if_missing('clinic')
with test_tools.imports_under_tool('clinic'):
    from libclinic.pyspec import (builtin_types, call_table, context,
                                  frontend, known, rt, runtime, subset,
                                  specfiles)

SRCDIR = test_tools.basepath


class SpecInfo:
    """A spec file: its path, the C file it describes, the spec, and its
    test data (the <stem>_cases.py module, or None)."""

    def __init__(self, path, c_file):
        self.path = path
        self.c_file = c_file
        self.spec = frontend.Spec.load(path)
        self.cases = specfiles.load_cases(path)

    def data(self, name, default):
        return getattr(self.cases, name, default)

    @functools.cached_property
    def analyzer(self):
        return context.Context(self.spec).analyzer()

    @functools.cached_property
    def references(self):
        """The spec run as Python (once: runtime.load() makes new
        functions each time)."""
        return runtime.load(self.path)


@functools.cache
def specs():
    found = [SpecInfo(path, c_file)
             for path, c_file in specfiles.spec_files(SRCDIR)]
    if not found:
        raise unittest.SkipTest('needs the spec files of the source tree')
    return found


@functools.cache
def registry():
    """[(type, class name, SpecInfo)] of the classes with a call table,
    in the order of the registry the tools generate."""
    out = []
    for info in specs():
        if not specfiles.is_core(SRCDIR, info.c_file):
            continue
        for cls_name in call_table.table_classes(info.spec):
            out.append((info.data('TYPES', {})[cls_name], cls_name, info))
    return out


def spec_class(tp):
    """(class name, SpecInfo) of the registry class tp."""
    for other, cls_name, info in registry():
        if other is tp:
            return cls_name, info
    raise LookupError(tp)


def outcome(func, *args):
    try:
        result = func(*args)
    except Exception as exc:
        return ('raises', type(exc), str(exc)), None
    return ('returns', type(result), result), result


def python_calls(func, *args):
    """Call func(*args) (a C function); return (outcome, result, the
    Python functions that ran during the call, as sys.setprofile sees
    them: every Python frame, special methods included)."""
    ran = []

    def profile(frame, event, arg):
        if event == 'call':
            ran.append(frame.f_code.co_qualname)

    old = sys.getprofile()
    # No cyclic GC: finalizers of unrelated garbage must not count.
    gc_enabled = gc.isenabled()
    gc.disable()
    exc = result = None
    sys.setprofile(profile)
    try:
        result = func(*args)
    except Exception as e:
        exc = e
    finally:
        sys.setprofile(old)
        if gc_enabled:
            gc.enable()
    if exc is not None:
        return ('raises', type(exc), str(exc)), None, ran
    return ('returns', type(result), result), result, ran


def no_python(func, *args):
    """func(*args) in the "no Python" tripwire: in debug builds, running
    Python code is a fatal error."""
    return _testinternalcapi.pyspec_no_python(func, args)


def cases_of(info, name):
    """The cases (args, kwargs) of spec function *name*, fresh each."""
    for make_case in info.data('CASES', {}).get(name, ()):
        yield make_case


def check_facts(test, entry, args, out, result, ran):
    """The facts of a table entry hold for a call with args."""
    kind = out[0]
    if entry['always_raises']:
        test.assertEqual(kind, 'raises', 'claims: always raises')
    if kind == 'returns':
        if entry['result_type'] is not None:
            test.assertIs(type(result), entry['result_type'],
                          'claims: exact result type')
        if entry['result_alias'] >= 0:
            test.assertIs(result, args[entry['result_alias']],
                          'claims: result is an argument')
        if entry['has_const']:
            test.assertIs(result, entry['result_const'],
                          'claims: constant result')
    if not entry['may_run_python']:
        test.assertEqual(ran, [], 'claims: runs no Python code')


def guard_accepts(entry, args):
    """Whether the entry holds for these arguments (counted as the entry
    counts them)."""
    if entry['nargs'] != len(args):
        return False
    return entry['arg_type'] is None or type(args[0]) is entry['arg_type']


def method_call(tp, entry, args):
    """(bound method, its arguments, the arguments as the entry counts
    them) of a case of a method entry, or None when the entry is not for
    it: a class method is called on the class of the case, exactly tp (a
    subclass is SoundnessTest's)."""
    if entry['classmethod'] and args[0] is not tp:
        return None
    return (bound(tp, entry['name'], args[0]), args[1:],
            args[1:] if entry['classmethod'] else args)


def bound(tp, name, self_or_cls):
    """Method *name* of tp (its C function, even if a subclass overrides
    it) bound to self, or to the class for a class method."""
    descriptor = vars(tp)[name]
    if isinstance(descriptor, types.ClassMethodDescriptorType):
        return descriptor.__get__(None, self_or_cls)
    return descriptor.__get__(self_or_cls)


class RegistryTest(unittest.TestCase):

    def test_registry(self):
        # The interpreter's registry (the generated part of
        # pycore_pyspec.h) lists exactly the classes the tools give a
        # table: a new spec'd class needs no C edit.
        self.assertEqual(_testinternalcapi.pyspec_classes(),
                         [tp for tp, _, _ in registry()])

    def test_each_class_has_its_own_slots(self):
        # The slots of a table are those of its class.
        for tp, cls_name, info in registry():
            for entry in _testinternalcapi.pyspec_table(tp)['slots']:
                with self.subTest(cls=cls_name, slot=entry['name']):
                    self.assertIn(entry['name'],
                                  info.spec.entries(cls_name))


class DirectCallTest(unittest.TestCase):
    """Every entry of every call table, called directly."""

    maxDiff = None

    def test_calls(self):
        # T(*args) through every entry whose guard accepts args, for the
        # cases of T.__new__ with the class exactly T.
        for tp, cls_name, info in registry():
            calls = _testinternalcapi.pyspec_table(tp)['calls']
            checked = {i: 0 for i in range(len(calls))}
            for make_case in cases_of(info, f'{cls_name}.__new__'):
                args, kwargs = make_case()
                if kwargs or args[0] is not tp:
                    continue    # the table: exactly T, positional only
                expected, _ = outcome(tp, *args[1:])
                for index, entry in enumerate(calls):
                    if not guard_accepts(entry, args[1:]):
                        continue
                    with self.subTest(cls=cls_name, args=args[1:],
                                      entry=index):
                        call_args = make_case()[0][1:]
                        out, result, ran = python_calls(
                            _testinternalcapi.pyspec_call, tp, index,
                            call_args)
                        self.assertEqual(out, expected)
                        check_facts(self, entry, call_args, out, result,
                                    ran)
                        checked[index] += 1
                        if not entry['may_run_python'] and not ran:
                            # The way the JIT calls it.
                            out, _ = outcome(
                                no_python, _testinternalcapi.pyspec_call,
                                tp, index, make_case()[0][1:])
                            self.assertEqual(out, expected)
            with self.subTest(cls=cls_name):
                # Every entry was tested with at least one input.
                self.assertEqual([i for i, n in checked.items() if n == 0],
                                 [])

    def test_find_call(self):
        # The entry the optimizer picks accepts the argument's exact type,
        # and an unknown type gets the generic entry (a subclass instance
        # never gets the facts of its base).
        for tp, cls_name, info in registry():
            calls = _testinternalcapi.pyspec_table(tp)['calls']
            typed = {e['arg_type'] for e in calls}
            for make_case in cases_of(info, f'{cls_name}.__new__'):
                args, kwargs = make_case()
                args = args[1:]
                if kwargs or len(args) > 1:
                    continue
                arg_type = type(args[0]) if args else None
                index = _testinternalcapi.pyspec_find_call(tp, len(args),
                                                           arg_type)
                with self.subTest(cls=cls_name, args=args):
                    self.assertIsNotNone(index)
                    self.assertTrue(guard_accepts(calls[index], args))
                    if args and arg_type not in typed:
                        self.assertIsNone(calls[index]['arg_type'])
            # An unknown argument type: the generic entry, if any.
            index = _testinternalcapi.pyspec_find_call(tp, 1, None)
            with self.subTest(cls=cls_name, arg_type=None):
                if any(e['nargs'] == 1 and e['arg_type'] is None
                       for e in calls):
                    self.assertIsNotNone(index)
                    self.assertEqual(calls[index]['nargs'], 1)
                    self.assertIsNone(calls[index]['arg_type'])
                else:
                    self.assertIsNone(index)

    def test_methods(self):
        # Each method entry, with the cases of the method: self and the
        # arguments, or the class and the arguments of a class method.
        for tp, cls_name, info in registry():
            methods = _testinternalcapi.pyspec_table(tp)['methods']
            checked = {i: 0 for i in range(len(methods))}
            for index, entry in enumerate(methods):
                name = f'{cls_name}.{entry["name"]}'
                for make_case in cases_of(info, name):
                    args, kwargs = make_case()
                    call = method_call(tp, entry, args)
                    if kwargs or call is None or \
                            not guard_accepts(entry, call[2]):
                        continue
                    with self.subTest(method=name, entry=index, args=args):
                        func, rest, counted = call
                        expected, _ = outcome(func, *rest)
                        func, rest, counted = method_call(
                            tp, entry, make_case()[0])
                        out, result, ran = python_calls(func, *rest)
                        self.assertEqual(out, expected)
                        check_facts(self, entry, counted, out, result, ran)
                        checked[index] += 1
                        if not entry['may_run_python'] and not ran:
                            func, rest, _ = method_call(
                                tp, entry, make_case()[0])
                            out, _ = outcome(no_python, func, *rest)
                            self.assertEqual(out, expected)
            with self.subTest(cls=cls_name):
                self.assertEqual([i for i, n in checked.items() if n == 0],
                                 [])

    def test_guard(self):
        # The hook refuses arguments the entry's guard rejects: the typed C
        # variants rely on the exact type.
        for tp, cls_name, _ in registry():
            calls = _testinternalcapi.pyspec_table(tp)['calls']
            for index, entry in enumerate(calls):
                if entry['arg_type'] is not None:
                    with self.subTest(cls=cls_name, entry=index):
                        with self.assertRaises(TypeError):
                            _testinternalcapi.pyspec_call(tp, index,
                                                          (object(),))


# The C NULL of test data without a NULL: nothing is NULL.
NO_NULL = object()


@functools.cache
def helpers():
    """{C function: SpecInfo of its spec} of every function written in C
    with a Python reference (@ac.stub(optimizer_info=True)) of the specs."""
    defined = {}
    for info in specs():
        for name in info.spec.native_functions():
            defined[name] = info
    return defined


def c_shape(node):
    """The shape of the C signature of spec function *node*, as
    _testinternalcapi.pyspec_helper_shapes() writes it: "OO->n"."""
    codes = {'Py_ssize_t': 'n', 'const char *': 's', 'int': 'i'}
    params, returns = subset.c_signature(node)
    return (''.join(codes.get(c, 'O') for _, c in params) + '->'
            + codes.get(returns, 'O'))


class HelperTest(unittest.TestCase):
    """Every hand-written C function with a reference a spec calls that
    can be called from Python, called directly with the HELPERS of its
    spec's cases: the same outcome as its Python reference, and the facts
    derived from the reference for the exact types of the arguments hold
    (runs no Python code, checked by sys.setprofile and by the debug-build
    tripwire; exact result type; cannot raise)."""

    def test_every_helper(self):
        # Each is called, or listed as NOT_CALLABLE, in the cases of its
        # spec.
        for name, info in helpers().items():
            with self.subTest(helper=name, spec=info.path):
                self.assertIn(name, set(info.data('HELPERS', {}))
                              | info.data('NOT_CALLABLE', set()))

    def test_helper_shapes(self):
        # The rows of _testinternalcapi calling the C functions agree with
        # the C signatures of the specs.
        shapes = _testinternalcapi.pyspec_helper_shapes()
        for name, shape in shapes.items():
            with self.subTest(helper=name):
                self.assertIn(name, helpers())
                node = helpers()[name].spec.functions[name]
                self.assertEqual(shape, c_shape(node))

    def c_call(self, info, name, args):
        """(callable, its arguments, whether the C result is a scalar) of
        C function *name* for *args* (the arguments of its reference)."""
        callers = info.data('HELPER_CALLERS', {})
        if name in callers:
            func, c_args = callers[name](*args)
            return func, c_args, False
        cls_name, _, meth = name.rpartition('.')
        if cls_name:
            # A slot: the slot wrapper of the type.
            return vars(info.cases.TYPES[cls_name])[meth], args, False
        shape = _testinternalcapi.pyspec_helper_shapes().get(name)
        if shape is None:
            self.fail(f'{name} cannot be called: add a row to '
                      'pyspec_helpers in Modules/_testinternalcapi.c, or '
                      'add it to HELPER_CALLERS or NOT_CALLABLE in '
                      f'{specfiles.cases_path(info.path)}')
        return (_testinternalcapi.pyspec_helper,
                (name, tuple(args), getattr(info.cases, 'NULL', NO_NULL)),
                not shape.endswith('O'))

    def env(self, info, name, args):
        """The facts about the parameters of the reference for *args*."""
        node = info.spec.functions[name]
        if '.' in name:
            params = [(a.arg, 'PyObject *') for a in node.args.args]
        else:
            params = subset.c_signature(node)[0]
        null = getattr(info.cases, 'NULL', NO_NULL)
        env = {}
        for (param, ctype), arg in zip(params, args):
            if arg is null:
                env[param] = known.NULL
            elif ctype == 'PyObject *' and not isinstance(arg, str):
                if type(arg) in builtin_types.TABLE:
                    env[param] = type(arg)
            else:
                env[param] = known.Value(arg)
        return env

    def test_helpers(self):
        for name, info in helpers().items():
            cases = info.data('HELPERS', {}).get(name, [])
            facts_only = name in info.data('FACTS_ONLY', set())
            null = getattr(info.cases, 'NULL', NO_NULL)
            for case in cases:
                args = case() if callable(case) else case
                with self.subTest(helper=name, args=args):
                    func, c_args, scalar = self.c_call(info, name, args)
                    out, result, ran = python_calls(func, *c_args)
                    if not facts_only:
                        ref_args = [rt.NULL if a is null else a
                                    for a in args]
                        expected, ref = outcome(info.references[name],
                                                *ref_args)
                        if ref is rt.NULL:
                            expected = ('returns', type(None), None)
                        elif scalar and expected[0] == 'returns':
                            # A C int for a Python int or bool.
                            expected = ('returns', int, int(ref))
                        self.assertEqual(out, expected)
                    found = info.analyzer.reference_facts(
                        name, self.env(info, name, args))
                    if out[0] == 'returns' and found.result_type \
                            and not scalar:
                        self.assertIs(type(result), found.result_type,
                                      'claims: exact result type')
                    if not found.raises:
                        self.assertEqual(out[0], 'returns',
                                         'claims: cannot raise')
                    if not found.runs_python:
                        self.assertEqual(ran, [], 'claims: runs no Python')
                        # In debug builds, running Python code is fatal.
                        args = case() if callable(case) else case
                        func, c_args, _ = self.c_call(info, name, args)
                        self.assertEqual(
                            outcome(no_python, func, *c_args)[0][0],
                            out[0])


JIT_ON = {'PYTHON_JIT': '1'}


def requires_jit():
    jit = getattr(sys, '_jit', None)
    return unittest.skipUnless(jit is not None and jit.is_available(),
                               'requires the JIT')


# The uops of the executors of functions, printed by a subprocess (see
# executor_uops()).  The code runs in main(): changing the globals would
# invalidate the traces.
_DUMP = '''
import _opcode
import importlib.util
from _testinternalcapi import TIER2_THRESHOLD

def load(path):
    spec = importlib.util.spec_from_file_location('cases', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def dump(label, func):
    code = func.__code__
    for i in range(0, len(code.co_code), 2):
        try:
            ex = _opcode.get_executor(code, i)
        except ValueError:
            continue
        print(label, *[op[0] for op in ex])

def main():
'''


def executor_uops(body):
    """{label: [uops]} of the executors dump(label, func) prints, from
    *body*, the code of main() (after _DUMP), with the JIT on."""
    script = _DUMP + textwrap.indent(textwrap.dedent(body), '    ')
    script += '\nmain()\n'
    rc, out, err = script_helper.assert_python_ok('-c', script, **JIT_ON)
    uops = {}
    for line in out.decode().splitlines():
        label, *ops = line.split()
        uops.setdefault(label, []).extend(ops)
    return uops


def followed_by_assertion(test, uops, uop):
    i = uops.index(uop)
    test.assertTrue(uops[i + 1].startswith('_ASSERT_RESULT_TYPE'), uops)


class DebugAssertionTest(unittest.TestCase):
    """Debug builds check the optimizer's facts and the "runs no Python
    code" facts at run time; release builds have no such checks."""

    @support.requires_subprocess()
    def test_no_python_tripwire(self):
        # Python code run in the tripwire.
        code = textwrap.dedent('''
            import _testinternalcapi
            def python():
                return 'x'
            print(_testinternalcapi.pyspec_no_python(python, ()))
        ''')
        if support.Py_DEBUG:
            rc, out, err = script_helper.assert_python_failure('-c', code)
            # The error names the function that ran.
            self.assertIn(b'Fatal Python error: _PySpec_CheckPythonAllowed',
                          err)
            self.assertRegex(err, rb'python \(<string>:\d+\) runs inside a '
                                  rb'call that the pyspec facts say runs no '
                                  rb'Python code')
        else:
            rc, out, err = script_helper.assert_python_ok('-c', code)
            self.assertEqual(out.strip(), b'x')

    def test_no_python_tripwire_nests(self):
        # A call that runs no Python code passes, and the flag is restored
        # afterwards.
        tripwire = _testinternalcapi.pyspec_no_python
        self.assertEqual(tripwire(tripwire, (len, ([1],))), 1)
        self.assertEqual(eval('1 + 1'), 2)

    @requires_jit()
    @unittest.skipUnless(support.Py_DEBUG, 'debug builds only')
    @support.requires_subprocess()
    def test_result_assertions_emitted(self):
        # After a call of a class through its table: for each typed entry
        # that runs no Python code, a uop calling it followed by the
        # assertion of its facts, or, for an alias (T(x) is x), a swap.
        for tp, cls_name, info in registry():
            if getattr(builtins, tp.__name__, None) is not tp:
                continue        # called by its builtin name
            name = f'{cls_name}.__new__'
            calls = _testinternalcapi.pyspec_table(tp)['calls']
            body, expect = [], {}
            for index, entry in enumerate(calls):
                if (entry['nargs'] != 1 or entry['arg_type'] is None
                        or entry['may_run_python']
                        or entry['result_type'] is None):
                    continue
                for i, make_case in enumerate(cases_of(info, name)):
                    args, kwargs = make_case()
                    if (not kwargs and args[0] is tp and len(args) == 2
                            and type(args[1]) is entry['arg_type']):
                        break
                else:
                    continue
                body.append(f'''
                    x = cases.CASES[{name!r}][{i}]()[0][1]
                    def f(n, x):
                        for _ in range(n):
                            {tp.__name__}(x)
                    f(TIER2_THRESHOLD * 2, x)
                    dump('e{index}', f)
                ''')
                expect[f'e{index}'] = entry
            if not body:
                continue
            uops = executor_uops(
                f'cases = load({info.cases.__file__!r})\n'
                + ''.join(textwrap.dedent(b) for b in body))
            for label, entry in expect.items():
                with self.subTest(cls=cls_name, arg_type=entry['arg_type']):
                    if entry['result_alias'] == 0:
                        self.assertIn('_SWAP_3', uops[label])
                    else:
                        followed_by_assertion(
                            self, uops[label],
                            '_CALL_BUILTIN_CLASS_1_INLINE_NO_PYTHON')

    @requires_jit()
    @unittest.skipUnless(support.Py_DEBUG, 'debug builds only')
    @support.requires_subprocess()
    def test_call_str_1_assertion_emitted(self):
        # _CALL_STR_1 claims an exact str for an exact int argument.
        uops = executor_uops('''
            def f(n, k):
                x = 0
                for _ in range(n):
                    x += len(str(len(k)))
                return x
            f(TIER2_THRESHOLD * 2, 'abc')
            dump('f', f)
        ''')
        followed_by_assertion(self, uops['f'], '_CALL_STR_1')

    @requires_jit()
    @support.requires_subprocess()
    def test_call_str_1_subclass(self):
        # str(x) may return a str subclass: _CALL_STR_1 must not claim an
        # exact str.  With that wrong fact, debug builds fail
        # _ASSERT_RESULT_TYPE right after the str() call and release builds
        # fold type(str(c)) is str to True.
        code = textwrap.dedent('''
            from _testinternalcapi import TIER2_THRESHOLD
            class S(str):
                pass
            class C:
                def __str__(self):
                    return S('x')
            def f(n):
                c = C()
                hits = 0
                for _ in range(n):
                    if type(str(c)) is str:
                        hits += 1
                return hits
            print(f(TIER2_THRESHOLD * 4))
        ''')
        rc, out, err = script_helper.assert_python_ok('-c', code, **JIT_ON)
        self.assertEqual(out.strip(), b'0')


def specialize_and_run(func, *args):
    """func(*args), called often enough for the specializing interpreter
    (and, when enabled, the JIT) to use its specialized code."""
    for _ in range(_testinternalcapi.TIER2_THRESHOLD + 2):
        result = func(*args)
    return result


@functools.cache
def cases_analysis(name):
    """The cases generator's analysis of Python/<name>."""
    with test_tools.imports_under_tool('cases_generator'):
        import analyzer
    return analyzer.analyze_files([os.path.join(SRCDIR, 'Python', name)])


def call_args(tokens, func):
    """The arguments (as text, without spaces) of the first call of *func*
    in *tokens* (of the cases generator's lexer), or None."""
    texts = [t.text for t in tokens]
    for i, text in enumerate(texts[:-1]):
        if text == func and texts[i + 1] == '(':
            break
    else:
        return None
    args, current, depth = [], '', 0
    for text in texts[i + 2:]:
        if text == ')' and depth == 0:
            return args + [current]
        if text == ',' and depth == 0:
            args.append(current)
            current = ''
            continue
        depth += (text == '(') - (text == ')')
        current += text
    return None


def instructions_with(uop):
    """The (specialized) instructions whose code includes *uop*."""
    return {name for name, inst in cases_analysis('bytecodes.c')
            .instructions.items()
            if any(part.name == uop for part in inst.parts)}


def executors_uops(func):
    """The uops of the executors of func's code."""
    import _opcode
    code = func.__code__
    uops = []
    for i in range(0, len(code.co_code), 2):
        try:
            ex = _opcode.get_executor(code, i)
        except ValueError:
            continue
        uops.extend(op[0] for op in ex)
    return uops


@functools.cache
def slot_uses():
    """[(uop, use, SpecInfo)] of the SLOT_USES of every spec."""
    return [(uop, use, info) for info in specs()
            for uop, use in info.data('SLOT_USES', {}).items()]


class SlotFactsTest(unittest.TestCase):
    """The slot facts (_PySpec_FindSlot()) of the specialized uops that
    do what a slot does (SLOT_USES).  The optimizer takes their result
    facts from the table; here the table must be the facts derived from
    the references (which HelperTest checks against the slots), each uop
    must agree with its slot, and a uop that cannot escape needs a slot
    that runs no Python code."""

    def slot_entry(self, use, info):
        """(type, the table entry the optimizer finds for the use)."""
        tp = info.cases.TYPES[use['cls']]
        slots = _testinternalcapi.pyspec_table(tp)['slots']
        ids = {e['slot'] for e in slots if e['name'] == use['slot']}
        self.assertEqual(len(ids), 1, ids)
        index = _testinternalcapi.pyspec_find_slot(tp, ids.pop(),
                                                   use['arg_type'])
        self.assertIsNotNone(index)
        return tp, slots[index]

    def test_table_is_derived(self):
        for uop, use, info in slot_uses():
            with self.subTest(uop=uop):
                tp, entry = self.slot_entry(use, info)
                name = f'{use["cls"]}.{use["slot"]}'
                params = info.spec.params(name)
                env = {}
                if builtin_types.by_name(use['cls']) is tp:
                    env[params[0]] = tp
                if use['arg_type'] is not None:
                    env[params[1]] = use['arg_type']
                found = info.analyzer.reference_facts(name, env)
                self.assertIs(entry['result_type'], found.result_type)
                self.assertIs(entry['may_run_python'], found.runs_python)
                self.assertIs(entry['always_raises'], found.always_raises)
                # What the uops rely on.
                self.assertIsNotNone(entry['result_type'])
                self.assertFalse(entry['may_run_python'])

    def test_uop_names_the_slot(self):
        # The uop's optimizer code (as the cases generator reads
        # Python/optimizer_bytecodes.c) looks the facts up by the class,
        # the slot the table keys them by (call_table.slot_member()) and
        # the argument type of the use: spec_slot_result(ctx, &T,
        # _PySpec_SLOT(member), &A or NULL).
        abstract = cases_analysis('optimizer_bytecodes.c')
        for uop, use, info in slot_uses():
            with self.subTest(uop=uop):
                args = call_args(abstract.uops[uop].body.tokens(),
                                 'spec_slot_result')
                self.assertIsNotNone(args)
                self.assertEqual(len(args), 4, args)
                member = call_table.slot_member(info.spec, use['cls'],
                                                use['slot'])
                self.assertEqual(args[2], f'_PySpec_SLOT({member})')
                self.assertEqual(args[3],
                                 call_table._type_object(use['arg_type']))
                tp = info.cases.TYPES[use['cls']]
                if tp in builtin_types.TABLE:
                    self.assertEqual(args[1], call_table._type_object(tp))
                else:
                    # Declared in the C file (class T "..." "&T_Type").
                    self.assertTrue(args[1].startswith('&'), args)

    def test_uops_do_not_escape(self):
        # A uop that does not escape (no HAS_ESCAPES_FLAG, as the cases
        # generator analyses Python/bytecodes.c) runs no Python code: the
        # slot it copies must not either (test_table_is_derived).
        analysis = cases_analysis('bytecodes.c')
        for uop, _, _ in slot_uses():
            with self.subTest(uop=uop):
                self.assertFalse(analysis.uops[uop].properties.escapes)

    @support.requires_specialization
    def test_uops_agree(self):
        # The specialized code gives what the slot gives, with the facts;
        # the specialized instruction (and, with the JIT, the uop in an
        # executor) is what ran.
        jit = getattr(sys, '_jit', None)
        jit = jit is not None and jit.is_enabled()
        for uop, use, info in slot_uses():
            _, entry = self.slot_entry(use, info)
            specialized = instructions_with(uop)
            self.assertTrue(specialized, uop)
            ran, in_executor = set(), False
            for args in use['inputs']:
                with self.subTest(uop=uop, args=args):
                    support.reset_code(use['run'])
                    got = specialize_and_run(use['run'], *args)
                    self.assertEqual(got, use['reference'](*args))
                    for kind, value in got:
                        if kind == 'returns':
                            self.assertIs(type(value), entry['result_type'])
                            if use.get('compact'):
                                self.assertTrue(sys._is_immortal(value))
                    ran |= {i.opname for i in
                            dis.get_instructions(use['run'], adaptive=True)}
                    in_executor |= uop in executors_uops(use['run'])
            with self.subTest(uop=uop):
                self.assertTrue(ran & specialized, (specialized, ran))
                if jit:
                    self.assertTrue(in_executor, uop)

    @requires_jit()
    @unittest.skipUnless(support.Py_DEBUG, 'debug builds only')
    @support.requires_subprocess()
    def test_result_assertions_emitted(self):
        # Debug builds check the slot facts at run time after the uops.
        for uop, use, info in slot_uses():
            with self.subTest(uop=uop):
                uops = executor_uops(f'''
                    use = load({info.cases.__file__!r}).SLOT_USES[{uop!r}]
                    args = use['inputs'][-1]
                    for _ in range(TIER2_THRESHOLD * 2):
                        use['run'](*args)
                    dump('run', use['run'])
                ''')
                followed_by_assertion(self, uops['run'], uop)


class SoundnessTest(unittest.TestCase):
    """Soundness problems of the derived facts found in review; these
    fail if the facts are (or become) wrong."""

    def test_classmethod_on_subclass(self):
        # F2: the facts of the typed entries of a class method hold only
        # when cls is exactly the type: Sub.fromhex(s) calls Sub(result),
        # which may return anything and run Python code.  The entry a
        # consumer finds for a subclass must have no facts that are false
        # for it.
        for tp, cls_name, info in registry():
            methods = _testinternalcapi.pyspec_table(tp)['methods']
            for meth in {e['name'] for e in methods if e['classmethod']}:
                name = f'{cls_name}.{meth}'
                for make_case in cases_of(info, name):
                    args, kwargs = make_case()
                    cls, rest = args[0], args[1:]
                    if kwargs or cls is tp or len(rest) != 1:
                        continue
                    index = _testinternalcapi.pyspec_find_method(
                        tp, meth, cls, 1, type(rest[0]))
                    if index is None:
                        continue
                    entry = methods[index]
                    with self.subTest(method=name, cls=cls, args=rest):
                        expected, _ = outcome(bound(tp, meth, cls), *rest)
                        cls, *rest = make_case()[0]
                        out, result, ran = python_calls(bound(tp, meth, cls),
                                                        *rest)
                        self.assertEqual(out, expected)
                        if out[0] == 'returns' and entry['result_type']:
                            self.assertIs(type(result), entry['result_type'],
                                          'claims: exact result type')
                        if not entry['may_run_python']:
                            self.assertEqual(ran, [],
                                             'claims: runs no Python code')

    def test_facts_observed(self):
        # F3: a FACTS entry with a run: run(input()) makes the call, and
        # runs Python code exactly when the derivation says it may.
        for info in specs():
            for fact in info.data('FACTS', []):
                if 'run' not in fact:
                    continue
                with self.subTest(spec=info.path, expr=fact['expr'],
                                  env=fact['env']):
                    _, _, ran = python_calls(fact['run'], fact['input']())
                    self.assertEqual(bool(ran), fact['runs_python'], ran)


if __name__ == '__main__':
    unittest.main()

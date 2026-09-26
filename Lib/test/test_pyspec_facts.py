"""The facts Argument Clinic derives from the pyspec files are verified.

The pyspec call tables (Include/internal/pycore_pyspec.h, generated from
Objects/pyspec/*.py) give the tier-2 optimizer direct C entry points and
facts about their results: an exact result type, a constant, an alias of
an argument, and whether the call may run Python code.  The JIT trusts
them.  These tests check them without the JIT:

* DirectCallTest calls every table entry directly (through
  _testinternalcapi) with every input its guard accepts, compares the
  outcome with the interpreter, and checks each claimed fact on the result.
  "Runs no Python code" is checked dynamically (sys.setprofile and
  recording special methods), and by calling the entry through the
  debug-build tripwire (_PySpec_CallNoPython1).
* DebugAssertionTest checks the debug-build run-time assertions of
  optimizer facts and the "no Python" tripwire.
* SoundnessTest pins latent soundness problems found in review.
"""

import ast
import codecs
import gc
import os
import sys
import textwrap
import types
import unittest
from test import support, test_tools
from test.support import import_helper, script_helper

_testinternalcapi = import_helper.import_module('_testinternalcapi')


def bytes_spec_cases():
    """The inputs of the spec difftest (test_clinic.BytesSpecTest.CASES)."""
    try:
        from test.test_clinic import BytesSpecTest
    except unittest.SkipTest as exc:
        raise unittest.SkipTest(f'test_clinic is not available: {exc}')
    return BytesSpecTest.CASES


def outcome(func, *args):
    try:
        result = func(*args)
    except Exception as exc:
        return ('raises', type(exc), str(exc)), None
    return ('returns', type(result), result), result


def python_calls(func, *args):
    """Call func(*args) (a C function); return (outcome, result, the Python
    functions that ran during the call: their names as seen by
    sys.setprofile, and the recording special methods below that were
    called)."""
    ran = []

    def profile(frame, event, arg):
        if event == 'call':
            ran.append(frame.f_code.co_qualname)

    old = sys.getprofile()
    # No cyclic GC: finalizers of unrelated garbage must not count.
    gc_enabled = gc.isenabled()
    gc.disable()
    exc = result = None
    RECORDED.clear()
    sys.setprofile(profile)
    try:
        result = func(*args)
    except Exception as e:
        exc = e
    finally:
        sys.setprofile(old)
        ran += [f'recorded {name}' for name in RECORDED]
        if gc_enabled:
            gc.enable()
    if exc is not None:
        return ('raises', type(exc), str(exc)), None, ran
    return ('returns', type(result), result), result, ran


# Recording special methods: an extra, explicit check that the calls the
# facts say run no Python code really call none of them.
RECORDED = []


class RecordingIndex:
    def __init__(self, value):
        self.value = value

    def __index__(self):
        RECORDED.append('__index__')
        return self.value


class RecordingBuffer:
    recorded = RECORDED     # still reachable at interpreter shutdown

    def __buffer__(self, flags):
        self.recorded.append('__buffer__')
        return memoryview(b'rb')

    def __release_buffer__(self, view):
        self.recorded.append('__release_buffer__')


class RecordingIter:
    def __iter__(self):
        RECORDED.append('__iter__')
        return iter([1, 2])


class RecordingBytes:
    def __bytes__(self):
        RECORDED.append('__bytes__')
        return b'rbytes'


class BytesSubclass(bytes):
    pass


class RecordingStr(str):
    def __index__(self):
        RECORDED.append('__index__')
        return 1


# More inputs, for the exact types of the typed entries.
EXTRA_CASES = [
    lambda: ((memoryview(RecordingBuffer()),), {}),
    lambda: ((memoryview(bytearray(b'ab')),), {}),
    lambda: (([RecordingIndex(1), RecordingIndex(2)],), {}),
    lambda: (((RecordingIndex(3),),), {}),
    lambda: (({RecordingIndex(4): 0},), {}),
    lambda: (([RecordingIndex(300)],), {}),
    lambda: ((RecordingIter(),), {}),
    lambda: ((RecordingBytes(),), {}),
    lambda: ((RecordingStr('x'),), {}),
    lambda: ((range(0),), {}),
    lambda: ((bytearray(),), {}),
    lambda: ((b'',), {}),
    lambda: ((BytesSubclass(b'sub'),), {}),
]


class DirectCallTest(unittest.TestCase):
    """Every entry of the bytes call table, called directly."""

    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.calls, cls.methods = _testinternalcapi.pyspec_table(bytes)

    def check_facts(self, entry, args, out, result, ran):
        kind = out[0]
        if entry['always_raises']:
            self.assertEqual(kind, 'raises', 'claims: always raises')
        if kind == 'returns':
            if entry['result_type'] is not None:
                self.assertIs(type(result), entry['result_type'],
                              'claims: exact result type')
            if entry['result_alias'] >= 0:
                self.assertIs(result, args[entry['result_alias']],
                              'claims: result is an argument')
            if entry['has_const']:
                self.assertIs(result, entry['result_const'],
                              'claims: constant result')
        if not entry['may_run_python']:
            self.assertEqual(ran, [], 'claims: runs no Python code')

    def guard_accepts(self, entry, args, nargs=None):
        if entry['nargs'] != (len(args) if nargs is None else nargs):
            return False
        return entry['arg_type'] is None or type(args[0]) is entry['arg_type']

    def test_calls(self):
        # bytes(*args) through every entry whose guard accepts args.
        checked = {i: 0 for i in range(len(self.calls))}
        for make_case in bytes_spec_cases() + EXTRA_CASES:
            args, kwargs = make_case()
            if kwargs:
                continue    # the table is for positional arguments only
            expected, _ = outcome(bytes, *args)
            for index, entry in enumerate(self.calls):
                if not self.guard_accepts(entry, args):
                    continue
                with self.subTest(args=args, entry=index,
                                  arg_type=entry['arg_type']):
                    args, _ = make_case()
                    out, result, ran = python_calls(
                        _testinternalcapi.pyspec_call, bytes, index, args)
                    self.assertEqual(out, expected)
                    self.check_facts(entry, args, out, result, ran)
                    checked[index] += 1
                    if not entry['may_run_python'] and not ran:
                        # The way the JIT calls it: in debug builds, running
                        # Python code is a fatal error.
                        args, _ = make_case()
                        out, _ = outcome(_testinternalcapi.pyspec_call,
                                         bytes, index, args, True)
                        self.assertEqual(out, expected)
        # Every entry was tested with at least one input.
        self.assertEqual([i for i, n in checked.items() if n == 0], [])

    def test_find_call(self):
        # The entry the optimizer picks accepts the argument's exact type,
        # and an unknown type gets the generic entry (a subclass instance
        # never gets the facts of its base).
        for make_case in bytes_spec_cases() + EXTRA_CASES:
            args, kwargs = make_case()
            if kwargs or len(args) > 1:
                continue
            arg_type = type(args[0]) if args else None
            index = _testinternalcapi.pyspec_find_call(bytes, len(args),
                                                       arg_type)
            with self.subTest(args=args):
                self.assertIsNotNone(index)
                self.assertTrue(self.guard_accepts(self.calls[index], args))
                if args and arg_type not in {e['arg_type'] for e in self.calls}:
                    self.assertIsNone(self.calls[index]['arg_type'])
        index = _testinternalcapi.pyspec_find_call(bytes, 1, None)
        self.assertIsNone(self.calls[index]['arg_type'])
        self.assertTrue(self.calls[index]['may_run_python'])
        self.assertIsNone(self.calls[index]['result_type'])

    @staticmethod
    def method_inputs(name):
        """Fresh inputs (self and the arguments, or the arguments of a
        class method) of the methods the spec implements."""
        if name == '__bytes__':
            return [(b'',), (b'abc',), (BytesSubclass(b'xy'),),
                    (BytesSubclass(),)]
        assert name == 'fromhex', name
        return [('',), ('00ff',), (' 0a 1B ',), ('abc',), ('zz',),
                (b'00ff',), (bytearray(b'0a'),), (memoryview(b'ab'),),
                (1,), (None,), ([RecordingIndex(1)],), ((1,),), ({1: 2},),
                (range(2),), (1.5,), (RecordingStr('41'),),
                (memoryview(RecordingBuffer()),), (RecordingBuffer(),),
                (BytesSubclass(b'41'),)]

    def test_methods(self):
        # Each method entry, with self (a method) or cls=bytes (a class
        # method); subclasses as cls are SoundnessTest.test_fromhex_cls.
        checked = {i: 0 for i in range(len(self.methods))}
        for index, entry in enumerate(self.methods):
            name = entry['method']
            is_class = bool(entry['method_flags'] & 0x0010)    # METH_CLASS
            for inputs in self.method_inputs(name):
                if is_class:
                    self_or_cls, args = bytes, inputs
                else:
                    self_or_cls, args = inputs[0], inputs[1:]
                if not self.guard_accepts(entry, inputs):
                    continue
                with self.subTest(method=name, entry=index, inputs=inputs):
                    expected, _ = outcome(getattr(bytes, name),
                                          *(() if is_class else
                                            (self_or_cls,)), *args)
                    out, result, ran = python_calls(
                        _testinternalcapi.pyspec_call_method, bytes, index,
                        self_or_cls, args)
                    self.assertEqual(out, expected)
                    self.check_facts(entry, inputs, out, result, ran)
                    checked[index] += 1
                    if not entry['may_run_python'] and not ran:
                        out, _ = outcome(
                            _testinternalcapi.pyspec_call_method, bytes,
                            index, self_or_cls, args, True)
                        self.assertEqual(out, expected)
        self.assertEqual([i for i, n in checked.items() if n == 0], [])

    def test_guard(self):
        # The hook refuses arguments the entry's guard rejects: the typed C
        # variants rely on the exact type.
        for index, entry in enumerate(self.calls):
            if entry['arg_type'] is not None:
                with self.subTest(entry=index):
                    with self.assertRaises(TypeError):
                        _testinternalcapi.pyspec_call(
                            bytes, index, (BytesSubclass(b'x'),))


JIT_ON = {'PYTHON_JIT': '1'}


def requires_jit():
    jit = getattr(sys, '_jit', None)
    return unittest.skipUnless(jit is not None and jit.is_available(),
                               'requires the JIT')


class DebugAssertionTest(unittest.TestCase):
    """Debug builds check the optimizer's facts and the "runs no Python
    code" facts at run time; release builds have no such checks."""

    @support.requires_subprocess()
    def test_no_python_tripwire(self):
        # A deliberately wrong fact: the generic bytes(x) entry, which may
        # run Python code, called as if it could not.
        code = textwrap.dedent('''
            import _testinternalcapi
            calls, _ = _testinternalcapi.pyspec_table(bytes)
            index = _testinternalcapi.pyspec_find_call(bytes, 1, None)
            assert calls[index]['may_run_python']
            class HasBytes:
                def __bytes__(self):
                    return b'x'
            print(_testinternalcapi.pyspec_call(bytes, index, (HasBytes(),),
                                                True))
        ''')
        if support.Py_DEBUG:
            rc, out, err = script_helper.assert_python_failure('-c', code)
            self.assertIn(b'Fatal Python error: _PySpec_CheckPythonAllowed: '
                          b'HasBytes.__bytes__ (<string>:7) runs inside a '
                          b'call that the pyspec facts say runs no Python '
                          b'code', err)
        else:
            rc, out, err = script_helper.assert_python_ok('-c', code)
            self.assertEqual(out.strip(), b"b'x'")

    def test_no_python_tripwire_nests(self):
        # A correct fact passes, and the flag is restored afterwards.
        calls, _ = _testinternalcapi.pyspec_table(bytes)
        index = _testinternalcapi.pyspec_find_call(bytes, 1, bytearray)
        self.assertFalse(calls[index]['may_run_python'])
        self.assertEqual(
            _testinternalcapi.pyspec_call(bytes, index, (bytearray(b'a'),),
                                          True), b'a')
        self.assertEqual(eval('1 + 1'), 2)

    @requires_jit()
    @unittest.skipUnless(support.Py_DEBUG, 'debug builds only')
    @support.requires_subprocess()
    def test_result_assertions_emitted(self):
        # After a call with facts from the pyspec table, and after the
        # hand-written result types of _CALL_STR_1 and _CALL_LEN.
        # (In a function: changing the globals would invalidate the trace.)
        code = textwrap.dedent('''
            import _opcode
            from _testinternalcapi import TIER2_THRESHOLD
            def main():
                def f(n, ba, b, s):
                    x = 0
                    for _ in range(n):
                        x += len(bytes(ba)) + len(bytes(b)) + len(str(s))
                    return x
                f(TIER2_THRESHOLD * 2, bytearray(b'ab'), b'cd', 3)
                code = f.__code__
                for i in range(0, len(code.co_code), 2):
                    try:
                        ex = _opcode.get_executor(code, i)
                    except ValueError:
                        continue
                    print(*[op[0] for op in ex])
            main()
        ''')
        rc, out, err = script_helper.assert_python_ok('-c', code, **JIT_ON)
        uops = out.decode().split()
        i = uops.index('_CALL_BUILTIN_CLASS_1_INLINE_NO_PYTHON')
        self.assertTrue(uops[i + 1].startswith('_ASSERT_RESULT_TYPE'), uops)
        self.assertIn('_SWAP_3', uops)     # the bytes(b) alias
        i = uops.index('_CALL_STR_1')
        self.assertTrue(uops[i + 1].startswith('_ASSERT_RESULT_TYPE'), uops)

    @requires_jit()
    @support.requires_subprocess()
    @unittest.expectedFailure
    def test_call_str_1_subclass(self):
        # Known bug, not pyspec: _CALL_STR_1 claims an exact str result,
        # but str(x) may return a str subclass (see
        # bugreports/call-str-1-subclass; the upstream fix is separate).
        # Debug builds fail _ASSERT_RESULT_TYPE right after the str() call;
        # release builds fold type(str(c)) is str to True.
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


class SoundnessTest(unittest.TestCase):
    """Latent soundness problems found in review (pyspec-notes/review_int.md);
    these fail if the facts are (or become) wrong."""

    @classmethod
    def setUpClass(cls):
        cls.calls, cls.methods = _testinternalcapi.pyspec_table(bytes)

    def test_fromhex_cls(self):
        # F2: the facts of the typed bytes.fromhex entries hold only when
        # cls is exactly bytes: B.fromhex(s) calls B(result), which may
        # return anything and run Python code.  The entry a consumer finds
        # for B.fromhex must have no facts that are false for B.
        # XXX Needs _PySpec_FindMethod() to take cls (F2 fix): until then,
        # the lookup ignores cls and this fails.
        class H(bytes):
            def __new__(cls, value):
                return 42

        for cls in (BytesSubclass, H):
            for inputs in DirectCallTest.method_inputs('fromhex'):
                (arg,) = inputs
                index = _testinternalcapi.pyspec_find_method(
                    bytes, 'fromhex', cls, 1, type(arg))
                if index is None:
                    continue
                entry = self.methods[index]
                with self.subTest(cls=cls, arg=arg, entry=index):
                    expected, _ = outcome(cls.fromhex, arg)
                    out, result, ran = python_calls(
                        _testinternalcapi.pyspec_call_method, bytes, index,
                        cls, inputs)
                    self.assertEqual(out, expected)
                    if out[0] == 'returns' and entry['result_type']:
                        self.assertIs(type(result), entry['result_type'],
                                      'claims: exact result type')
                    if not entry['may_run_python']:
                        self.assertEqual(ran, [],
                                         'claims: runs no Python code')

    @classmethod
    def analyzer(cls):
        test_tools.skip_if_missing('clinic')
        with test_tools.imports_under_tool('clinic'):
            from libclinic.pyspec import call_table, frontend, partial_eval
        path = os.path.join(test_tools.basepath, 'Objects', 'pyspec',
                            'bytesobject.py')
        with open(path, encoding='utf-8') as f:
            spec = frontend.Spec(f.read(), path)
        return spec, call_table, partial_eval, call_table.Analyzer(spec)

    def derived_runs_python(self, expr, tp):
        """Whether the facts derivation says that call *expr*, with x of
        exact type tp, may run Python code."""
        _, call_table, _, analyzer = self.analyzer()
        facts = call_table.Facts()
        analyzer.call(ast.parse(expr, mode='eval').body, {'x': tp}, {},
                      facts)
        return facts.runs_python

    def forwarding_cases(self):
        import collections
        import operator

        class Mapping(collections.UserDict):
            def __len__(self):
                return 3

            def __iter__(self):
                return iter([1, 2, 3])

        class Seq:
            def __len__(self):
                return 2

            def __getitem__(self, i):
                return [65, 66][i]

        proxy = types.MappingProxyType(Mapping())
        rev = reversed(Seq())
        return [
            ('C.PyObject_LengthHint(x, 0)', proxy, operator.length_hint),
            ('C.PyObject_LengthHint(x, 0)', rev, operator.length_hint),
            ('iter(x)', proxy, iter),
        ]

    def test_derivation_of_forwarding_types(self):
        # The derivation used by the next test works for these types.
        for expr, arg, run in self.forwarding_cases():
            with self.subTest(expr=expr, type=type(arg)):
                self.assertIn(self.derived_runs_python(expr, type(arg)),
                              (True, False))

    # F3: "an exact static type never runs Python code" (the is_static_type
    # rule of libclinic/pyspec/runtime.py) is false for types that forward
    # to another object.  Masked today because the call table only has
    # entries for a few leaf types.  P2 replaces the rule.
    @unittest.expectedFailure
    def test_static_type_rule(self):
        import pickle
        for expr, arg, run in self.forwarding_cases():
            with self.subTest(expr=expr, type=type(arg)):
                _, _, ran = python_calls(run, arg)
                self.assertNotEqual(ran, [])
                self.assertTrue(self.derived_runs_python(expr, type(arg)))
        # PickleBuffer forwards getbuffer to the object it wraps (a Python
        # __buffer__ cannot be observed today because of an upstream bug,
        # see review F7).
        self.assertTrue(self.derived_runs_python('C._PyBytes_FromBuffer(x)',
                                                 pickle.PickleBuffer))

    def test_codec_subclass_result(self):
        # F6: an encoding with a codec may return a bytes subclass, so
        # neither bytes(str, encoding) nor its escape may claim an exact
        # bytes result.
        class B(bytes):
            pass

        def search(name):
            if name != 'pyspec_facts_subclass':
                return None
            return codecs.CodecInfo(
                name=name,
                encode=lambda s, errors='strict': (B(s.encode()), len(s)),
                decode=lambda b, errors='strict': (bytes(b).decode(), len(b)))

        codecs.register(search)
        self.addCleanup(codecs.unregister, search)
        self.assertIs(type(bytes('x', 'pyspec_facts_subclass')), B)
        self.assertIs(type('x'.encode('pyspec_facts_subclass')), B)

        spec, call_table, partial_eval, analyzer = self.analyzer()
        stub = analyzer.escape_facts('PyUnicode_AsEncodedString')
        self.assertIsNotNone(stub)
        self.assertIsNone(stub.result_type)
        env = {'cls': partial_eval.Value(bytes), 'source': str,
               'encoding': partial_eval.NOTNULL, 'errors': partial_eval.NULL}
        residual = partial_eval.specialize(spec, 'bytes.__new__', env)
        facts = analyzer.facts(residual, call_table._type_env(env),
                               ['source', 'encoding'])
        self.assertIsNone(facts.result_type)


if __name__ == '__main__':
    unittest.main()

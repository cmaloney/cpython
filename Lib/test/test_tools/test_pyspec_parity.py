"""Tests for Tools/clinic/pyspec_parity.py and Tools/clinic/pyspec_review.py.

RecordTest compares the types the specs describe with the committed
record (Tools/clinic/pyspec-baseline/parity.txt), when it has a block for
the configuration of this build.  ParityTest compares them line by line
with a build of the tree before their migration when
PYSPEC_PARITY_BASELINE names its python, e.g.:

    PYSPEC_PARITY_BASELINE=../build-main/python \\
        ./python -m test test_tools.test_pyspec_parity
"""

import contextlib
import io
import os
import sys
import unittest

from test import support
from test.support import os_helper
from test.test_tools import imports_under_tool, skip_if_missing

skip_if_missing('clinic')
with imports_under_tool('clinic'):
    import pyspec_parity
    import pyspec_review


def make_class(message='x must be an int', arity=1, length=None,
               pair=None, sub=None):
    """A class named T, whose method m and length vary; m(x, y) returns
    *pair* for m(0, 0) if given; Sub(T()).m(3) returns *sub* if given."""
    class T:
        def __init__(self, *args):
            pass

        def m(self, x, *rest):
            if len(rest) >= arity:
                raise TypeError(f'm() takes {arity} arguments')
            if not isinstance(x, int):
                raise TypeError(message)
            if sub is not None and type(self) is not T and x == 3:
                return sub
            return x + 1

        def two(self, x, y):
            if pair is not None and (x, y) == (0, 0):
                return pair
            return (x, y)

        def __repr__(self):
            return 'T()'

    if length is not None:
        T.__len__ = lambda self: length
    return T


def make_iterator(stop=3):
    """An iterator class whose __setstate__ clamps at *stop*."""
    class It:
        def __init__(self, *args):
            self.i = 0

        def __iter__(self):
            return self

        def __next__(self):
            if self.i >= 3:
                raise StopIteration
            self.i += 1
            return self.i

        def __setstate__(self, i):
            self.i = min(i, stop)

    return It


def capture(cls, name='T', **parity):
    return pyspec_parity.capture_types(
        [pyspec_parity.TypeData(name, cls, parity=parity)])


def changed(before, after, name='T', **parity):
    """{(section, key)} of the lines that differ."""
    data = pyspec_parity.TypeData(name, None, parity=parity)
    comparison = pyspec_parity.Comparison(before, after, [data])
    return {(section, key) for _, section, _, changes in comparison.changed
            for key, _, _ in changes}


class ToolTest(unittest.TestCase):
    def test_same_type(self):
        self.assertEqual(pyspec_parity.compare(capture(make_class()),
                                               capture(make_class())), '')

    def test_error_message(self):
        keys = changed(capture(make_class()),
                       capture(make_class('other message')))
        self.assertIn(('.m', "call T().m('ab')"), keys)
        self.assertNotIn(('.m', 'call T().m(1)'), keys)

    def test_arity(self):
        keys = changed(capture(make_class()), capture(make_class(arity=2)))
        self.assertIn(('.m', 'call T().m(1, 1)'), keys)

    def test_slot(self):
        keys = changed(capture(make_class()), capture(make_class(length=3)))
        self.assertIn(('type', 'vars'), keys)
        self.assertIn(('unary', 'len(T())'), keys)
        self.assertIn(('C', 'C tp_as_sequence.sq_length'), keys)

    def test_pairs(self):
        # Only m(0, 0) differs: one parameter at a time misses it.
        keys = changed(capture(make_class()),
                       capture(make_class(pair='zero')))
        self.assertEqual(keys, {('.two', 'call T().two(0, 0)')})

    def test_subclass_receiver(self):
        # Probed as fully as an instance of the type.
        keys = changed(capture(make_class()),
                       capture(make_class(sub='sub')))
        self.assertEqual(keys, {('.m', 'call Sub(T()).m(3)')})

    def test_iterator_state(self):
        # What __setstate__ did shows in what the iterator yields next.
        keys = changed(capture(make_iterator(), 'It'),
                       capture(make_iterator(stop=1), 'It'), 'It')
        self.assertIn(('.__setstate__', 'call It().__setstate__(3)'), keys)

    def test_readable_diff(self):
        text = pyspec_parity.compare(capture(make_class()),
                                     capture(make_class('other')))
        self.assertIn('T .m: ', text)
        self.assertIn("    call T().m('ab')\n"
                      "        before: !TypeError: x must be an int\n"
                      "        after:  !TypeError: other\n", text)
        self.assertIn('more (--all shows them)', text)

    def test_known_differences(self):
        before = capture(make_class())
        after = capture(make_class('other message'))
        known = {'known': {r"call .*\)\.m\(.*": 'on purpose'}}
        self.assertEqual(changed(before, after, **known), set())
        data = pyspec_parity.TypeData('T', None, parity=known)
        comparison = pyspec_parity.Comparison(before, after, [data])
        self.assertIn(('T', r"call .*\)\.m\(.*"), comparison.known_seen())

    def test_known_matches_the_whole_key(self):
        # A pattern is not searched in the key: '\.m\(' excuses no line.
        before = capture(make_class())
        after = capture(make_class('other message'))
        known = {'known': {r"\.m\(": 'too broad'}}
        self.assertIn(('.m', "call T().m('ab')"),
                      changed(before, after, **known))

    def test_iterator_result(self):
        # What an iterator a call returns yields: not only its type.
        def make(order):
            class T:
                def __reversed__(self):
                    return iter(order)

                def __repr__(self):
                    return 'T()'
            return T
        keys = changed(capture(make([3, 2, 1])), capture(make([1, 2, 3])))
        self.assertIn(('.__reversed__', 'call T().__reversed__()'), keys)
        self.assertIn(('unary', 'reversed(T())'), keys)
        # Bounded, and what it raises is shown.
        self.assertEqual(pyspec_parity.describe(iter(range(100))),
                         'range_iterator <range_iterator object at 0x...> '
                         'yielding [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, '
                         '12, 13, 14, 15, 16, 17, 18, 19] ...')

        def gen():
            yield 1
            raise ValueError('bad')
        self.assertEndsWith(pyspec_parity.describe(gen()),
                            'yielding [1] then !ValueError: bad')

    def test_memoryview_result(self):
        def make(data, fmt='B'):
            class T:
                def view(self):
                    return memoryview(data).cast(fmt)

                def __repr__(self):
                    return 'T()'
            return T
        before = capture(make(b'ab'))
        self.assertEqual(changed(before, capture(make(b'ab'))), set())
        self.assertIn(('.view', 'call T().view()'),
                      changed(before, capture(make(b'ba'))))
        self.assertIn(('.view', 'call T().view()'),
                      changed(before, capture(make(b'ab', 'c'))))
        view = memoryview(b'ab')
        view.release()
        self.assertIn('!ValueError', pyspec_parity.describe(view))

    def test_long_result(self):
        # A long repr differing after its first MAX_REPR characters.
        def make(last):
            class T:
                def big(self):
                    return 'a' * pyspec_parity.MAX_REPR + last

                def __repr__(self):
                    return 'T()'
            return T
        self.assertIn(('.big', 'call T().big()'),
                      changed(capture(make('X')), capture(make('Y'))))

    def test_hashable_receiver_changed(self):
        # A hashable receiver is watched too.
        def make(mutate):
            class T:
                def __init__(self):
                    self.x = 0

                def m(self, a):
                    if mutate and a == 1:
                        self.x = 5

                def __repr__(self):
                    return f'T(x={self.x})'
            return T
        self.assertIsNotNone(make(False).__hash__)
        keys = changed(capture(make(False)), capture(make(True)))
        self.assertIn(('.m', 'call T().m(1)'), keys)

    def test_escaping(self):
        # One line per value, and different values give different lines.
        values = ['a\nb', 'a\\nb', 'a\\\nb', 'a\rb', 'a\\rb', 'a\x0bb',
                  'a\u2028b', 'a\\u2028b', 'a\\b']
        out = pyspec_parity.Capture()
        for i, value in enumerate(values):
            out.add('T', 's', f'k{i}', value)
        lines = out.lines()
        text = '\n'.join(lines)
        self.assertEqual(text.splitlines(), lines)
        _, sections = pyspec_parity.parse(lines)
        found = [v for _, v in sections['T', 's']]
        self.assertEqual(len(set(found)), len(values))
        self.assertEqual(found[0], 'a\\nb')
        with self.assertRaisesRegex(ValueError, 'line break'):
            out.add('T', 's', 'a\rb', 1)

    def test_unknown_parity_key(self):
        with self.assertRaisesRegex(ValueError, 'unknown keys'):
            pyspec_parity.TypeData('T', None, parity={'sample': {}})

    def test_other_interpreter(self):
        before = capture(make_class())
        after = ['# python 0.0 free-threaded=False debug=False pointer=64',
                 *before[1:]]
        with self.assertRaisesRegex(ValueError, 'different interpreters'):
            pyspec_parity.compare(before, after)

    def test_record(self):
        types = [pyspec_parity.TypeData('T', None)]
        head, expected = pyspec_parity.digests(capture(make_class()), types)
        _, actual = pyspec_parity.digests(
            capture(make_class('other message')), types)
        self.assertEqual(head, pyspec_parity.header())
        messages = pyspec_parity.check_record(expected, actual, types)
        self.assertEqual(len(messages), 1)
        self.assertStartsWith(messages[0], 'T .m: ')
        self.assertEqual(
            pyspec_parity.check_record(expected, expected, types), [])
        with os_helper.temp_dir() as tmp:
            path = os.path.join(tmp, 'parity.txt')
            pyspec_parity.write_record({head: expected}, path)
            self.assertEqual(pyspec_parity.read_record(path),
                             {head: expected})

    def test_spec_types(self):
        types = pyspec_parity.spec_types()
        self.assertIn('bytes', types)
        for name, data in types.items():
            with self.subTest(name):
                self.assertIs(pyspec_parity.resolve(name), data)
                for label, factory in data.samples.items():
                    self.assertIs(type(factory()), data.tp, label)
        self.assertIs(pyspec_parity.resolve('tuple').tp, tuple)
        with self.assertRaisesRegex(ValueError, 'TYPES'):
            pyspec_parity.resolve('no_such_type')

    def test_location(self):
        data = pyspec_parity.resolve('bytes')
        spec, block = data.location('.decode')
        path, line = spec.rsplit(':', 1)
        with open(os.path.join(pyspec_parity.SRCDIR, path)) as f:
            self.assertIn('def decode', f.readlines()[int(line) - 1])
        path, line = block.rsplit(':', 1)
        with open(os.path.join(pyspec_parity.SRCDIR, path)) as f:
            self.assertEqual(f.readlines()[int(line) - 1].split()[0],
                             'bytes.decode')

    @support.requires_subprocess()
    def test_check(self):
        # Captured in a subprocess, twice: identical.
        with os_helper.temp_dir() as tmp:
            path = os.path.join(tmp, 'it.parity')
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                pyspec_parity.main(['capture', 'bytes_iterator', '-o', path])
                status = pyspec_parity.main(['check', path])
            self.assertEqual(status, 0)
            self.assertIn('no difference in bytes_iterator', out.getvalue())

    @support.requires_subprocess()
    def test_check_without_block(self):
        # A record without a block for this configuration, or no record:
        # a SKIP line; a failure with --strict.
        with os_helper.temp_dir() as tmp:
            record = os.path.join(tmp, 'parity.txt')
            other = '# python 0.0 free-threaded=False debug=False'
            pyspec_parity.write_record({other: {}}, record)
            for path in (record, os.path.join(tmp, 'missing.txt')):
                for strict, expected in ((False, 0), (True, 1)):
                    with self.subTest(path=path, strict=strict):
                        out = io.StringIO()
                        with contextlib.redirect_stdout(out):
                            status = pyspec_parity.check_command(
                                False, ['bytes_iterator'], path, strict)
                        self.assertEqual(status, expected)
                        self.assertStartsWith(out.getvalue(), 'SKIP: ')


class ReviewTest(unittest.TestCase):
    OLD = '''\
PyDoc_STRVAR(f__doc__,
"f()");

#define F_METHODDEF    \\
    {"f", (PyCFunction)f, METH_NOARGS, f__doc__},

static PyObject *
f_impl(PyObject *module);

static PyObject *
g(PyObject *module)
{
    return g_impl(module);
}
'''

    def test_changed_names(self):
        new = self.OLD.replace('return g_impl(module);',
                               'return g_impl(module, 1);')
        new += 'static PyObject *\nh(void);\n'
        names, added, removed = pyspec_review.changed_names(self.OLD, new)
        self.assertEqual(names, ['g', 'h'])
        self.assertEqual((added, removed), (3, 1))
        new = self.OLD.replace('"f()"', '"f(x)"')
        self.assertEqual(pyspec_review.changed_names(self.OLD, new)[0],
                         ['f'])
        new = self.OLD.replace('METH_NOARGS', 'METH_O')
        self.assertEqual(pyspec_review.changed_names(self.OLD, new)[0],
                         ['f'])

    def test_not_explained(self):
        # A changed C function no "generated" explains fails the review.
        new = self.OLD.replace('return g_impl(module);',
                               'return g_impl(module, 1);')
        lines, ok = pyspec_review.changed_output('f.c.h', self.OLD, new)
        self.assertFalse(ok)
        self.assertIn('NOT EXPLAINED: g', lines[-1])
        old = self.OLD.replace('g(', 'bytes_new(')
        new = old.replace('return g_impl(module);',
                          'return g_impl(module, 1);')
        lines, ok = pyspec_review.changed_output('f.c.h', old, new)
        self.assertTrue(ok)
        self.assertIn('on purpose', lines[-1])

    def test_missing_block(self):
        # No block for this configuration: a failure when the record is
        # gone or had a block at the base or HEAD; else a SKIP, which
        # fails with --strict.
        missing = pyspec_review.missing_block
        line, ok = missing('bytes', [], False, False)
        self.assertFalse(ok)
        self.assertIn('MISSING RECORD', line)
        line, ok = missing('bytes', ['HEAD'], True, False)
        self.assertFalse(ok)
        self.assertIn('MISSING BLOCK', line)
        line, ok = missing('bytes', [], True, False)
        self.assertTrue(ok)
        self.assertIn('SKIP', line)
        self.assertFalse(missing('bytes', [], True, True)[1])

    def test_explain(self):
        reasons, unexplained = pyspec_review.explain(
            ['bytes_new', 'bytes_vectorcall', 'bytes_split'])
        self.assertEqual(list(reasons.values()),
                         [['bytes_new', 'bytes_vectorcall']])
        self.assertEqual(unexplained, ['bytes_split'])


@support.requires_subprocess()
class RecordTest(unittest.TestCase):
    """The spec'd types against the committed record."""

    def test_record(self):
        head, messages, _ = pyspec_parity.check_against_record()
        if messages is None:
            self.skipTest(f'{pyspec_parity.RECORD} has no block for '
                          f'{head[2:]}')
        self.assertFalse(messages, '\n'.join([
            f'the types differ from {pyspec_parity.RECORD}:', *messages,
            'To see the lines: "python Tools/clinic/pyspec_parity.py '
            'compare BASELINE_PYTHON TYPE" with a build before the change. '
            'On purpose: "python Tools/clinic/pyspec_parity.py check '
            '--update", and say why in the PR.']))


@support.requires_subprocess()
class ParityTest(unittest.TestCase):
    """The spec'd types against the interpreter before their migration."""

    def test_spec_types(self):
        baseline = os.environ.get('PYSPEC_PARITY_BASELINE')
        if not baseline:
            self.skipTest('set PYSPEC_PARITY_BASELINE to the python of a '
                          'build before the migration')
        # Relative to where regrtest started, not its temporary directory.
        baseline = os.path.join(os_helper.SAVEDCWD, baseline)
        types = list(pyspec_parity.spec_types().values())
        names = [t.name for t in types]
        before = pyspec_parity.run_capture(baseline, names)
        after = pyspec_parity.run_capture(sys.executable, names)
        header_before = pyspec_parity.parse(before)[0]
        header_after = pyspec_parity.parse(after)[0]
        if header_before != header_after:
            # Debug and free-threaded builds differ observably.
            self.skipTest(f'{baseline} is another configuration: '
                          f'{header_before} (this python: {header_after})')
        diff = pyspec_parity.compare(before, after, types)
        self.assertFalse(diff, f'the types differ from {baseline}; a '
                         'difference made on purpose goes into the "known" '
                         "of the PARITY of the type's <stem>_cases.py"
                         f'\n{diff}')


class ModelTest(unittest.TestCase):
    """The specs of bytes and bytes_iterator run as pure Python (their
    model: Tools/clinic/libclinic/pyspec/model.py) against the C types,
    every line of the parity tool but the excluded sections
    (MODEL_EXCLUDED_SECTIONS) and the limits of a Python class
    (MODEL_LIMITS): a method or a protocol with a Python body that
    diverges fails.  ``pyspec_parity.py model`` shows the lines."""

    NAMES = ['bytes', 'bytes_iterator']

    @classmethod
    def setUpClass(cls):
        cls.comparison = pyspec_parity.ModelComparison(cls.NAMES)

    def test_python_bodies_agree(self):
        diverging = self.comparison.diverging()
        lines = [f'{name} {section}: {key}\n    C:     {c}\n    model: {m}'
                 for (name, section), changes in diverging.items()
                 for key, c, m in changes[:5]]
        self.assertFalse(diverging, 'the model differs from the C type '
                         '("python Tools/clinic/pyspec_parity.py model '
                         '--all"):\n' + '\n'.join(lines))

    def test_what_is_pure(self):
        # Every method and slot runs a Python body but printf-style
        # formatting, which calls the C.
        kinds = self.comparison.model.kinds
        self.assertEqual(sorted(k for k, v in kinds.items()
                                if v == 'delegated'),
                         ['bytes.__mod__', 'bytes.__rmod__'])
        self.assertGreater(len(kinds), 60)

    def test_not_circular(self):
        # No body calls a host type the specs describe; only the
        # delegated methods use the C.
        with imports_under_tool('clinic'):
            from libclinic.pyspec import model
        self.assertEqual(model.check_circular(self.comparison.model), {
            'bytes.__mod__': ['delegated to the C'],
            'bytes.__rmod__': ['delegated to the C'],
        })

    def test_coverage(self):
        total = self.comparison.totals()
        self.assertGreater(total.compared, 30_000)
        self.assertLess(total.limits, 150)


if __name__ == '__main__':
    unittest.main()

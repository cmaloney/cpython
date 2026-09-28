"""Tests for Tools/clinic/pyspec_parity.py.

ParityTest compares the types the specs describe with a build of the
tree before their migration when PYSPEC_PARITY_BASELINE names its
python, e.g.:

    PYSPEC_PARITY_BASELINE=../build-main/python \\
        ./python -m test test_tools.test_pyspec_parity
"""

import contextlib
import io
import os
import sys
import unittest
from unittest import mock

from test import support
from test.support import os_helper
from test.test_tools import imports_under_tool, skip_if_missing

skip_if_missing('clinic')
with imports_under_tool('clinic'):
    import pyspec_parity


def make_class(message='x must be an int', arity=1, length=None):
    """A class named T, whose method m and length vary."""
    class T:
        def m(self, x, *rest):
            if len(rest) >= arity:
                raise TypeError(f'm() takes {arity} arguments')
            if not isinstance(x, int):
                raise TypeError(message)
            return x + 1

        def __repr__(self):
            return 'T()'

    if length is not None:
        T.__len__ = lambda self: length
    return T


def capture(cls, name='T'):
    return pyspec_parity.capture_types([(name, cls)])


class ToolTest(unittest.TestCase):
    def changed_keys(self, before, after):
        diff = pyspec_parity.compare(before, after)
        return {line[1:].partition(' = ')[0] for line in diff.splitlines()
                if line[:1] in '+-' and line[:3] not in ('+++', '---')}

    def test_same_type(self):
        self.assertEqual(pyspec_parity.compare(capture(make_class()),
                                               capture(make_class())), '')

    def test_error_message(self):
        keys = self.changed_keys(capture(make_class()),
                                 capture(make_class('other message')))
        self.assertIn("T call T().m('ab')", keys)
        self.assertNotIn('T call T().m(1)', keys)

    def test_arity(self):
        keys = self.changed_keys(capture(make_class()),
                                 capture(make_class(arity=2)))
        self.assertIn('T call T().m(1, 1)', keys)

    def test_slot(self):
        keys = self.changed_keys(capture(make_class()),
                                 capture(make_class(length=3)))
        self.assertIn('T vars', keys)
        self.assertIn('T len(T())', keys)
        self.assertIn('T C tp_as_sequence.sq_length', keys)

    def test_known_differences(self):
        before = capture(make_class())
        after = capture(make_class('other message'))
        known = {'T': [(r"^call T\(\)\.m\(", 'on purpose')]}
        with mock.patch.dict(pyspec_parity.KNOWN_DIFFERENCES, known):
            self.assertEqual(pyspec_parity.compare(before, after), '')

    def test_other_interpreter(self):
        before = capture(make_class())
        after = ['# python 0.0 free-threaded=False debug=False pointer=64',
                 *before[1:]]
        with self.assertRaisesRegex(ValueError, 'different interpreters'):
            pyspec_parity.compare(before, after)

    def test_spec_types(self):
        names = pyspec_parity.spec_types()
        self.assertIn('bytes', names)
        for name in names:
            tp = pyspec_parity.resolve_type(name)
            self.assertEqual(pyspec_parity.type_name(tp), name)

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
class ParityTest(unittest.TestCase):
    """The spec'd types against the interpreter before their migration."""

    def test_spec_types(self):
        baseline = os.environ.get('PYSPEC_PARITY_BASELINE')
        if not baseline:
            self.skipTest('set PYSPEC_PARITY_BASELINE to the python of a '
                          'build before the migration')
        # Relative to where regrtest started, not its temporary directory.
        baseline = os.path.join(os_helper.SAVEDCWD, baseline)
        names = pyspec_parity.spec_types()
        before = pyspec_parity.run_capture(baseline, names)
        after = pyspec_parity.run_capture(sys.executable, names)
        diff = pyspec_parity.compare(before, after, names)
        self.assertFalse(diff, f'the types differ from {baseline}; a '
                         'difference made on purpose goes into '
                         'KNOWN_DIFFERENCES of Tools/clinic/pyspec_parity.py'
                         f'\n{diff}')


if __name__ == '__main__':
    unittest.main()

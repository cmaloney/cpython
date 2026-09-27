"""Tests for Tools/clinic/pyspec_bench.py."""

import contextlib
import io
import unittest

from test.test_tools import imports_under_tool, skip_if_missing

skip_if_missing('clinic')
with imports_under_tool('clinic'):
    import pyspec_bench


class PyspecBenchTest(unittest.TestCase):
    def run_main(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            pyspec_bench.main(['--loops', '10,110', '--repeat', '1',
                               '--jit', 'off', *args])
        return out.getvalue().splitlines()

    def check_rows(self, lines, stmts):
        header = lines.index(next(l for l in lines
                                  if l.startswith('statement |')))
        rows = [l.split(' | ') for l in lines[header + 1:]]
        self.assertEqual([r[0] for r in rows], stmts)
        for row in rows:
            self.assertEqual(row[1], 'off')
            float(row[2])

    def test_timing(self):
        lines = self.run_main('--timing', '-s', 'x = [1, 2]\ny = 3',
                              'len(x)', 'y + 1\ny - 1')
        self.assertIn('statement | jit | ', lines[0])
        self.check_rows(lines, ['len(x)', 'y + 1; y - 1'])

    def test_perf(self):
        if not pyspec_bench.perf_works():
            self.skipTest('perf stat is not available')
        lines = self.run_main('pass')
        self.check_rows(lines, ['pass'])

    def test_failing_statement(self):
        with self.assertRaises(SystemExit):
            self.run_main('--timing', '1/0')


if __name__ == '__main__':
    unittest.main()

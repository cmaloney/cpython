"""Where the code and the files describing it by hand disagree: a ratchet.

Tools/clinic/libclinic/pyspec/disconnects.py lists the disconnects of each
dimension (C API, docs, slots, docstrings, typeshed).  The known ones are
in Tools/clinic/pyspec-baseline/<dimension>.txt, which may only shrink:
a new disconnect fails the test, and so does a baseline line that no
longer matches (delete it).  -v prints the count per dimension.

The typeshed dimension runs only when PYSPEC_TYPESHED is the path of a
checkout of https://github.com/python/typeshed.
"""

import os
import unittest
from test import support, test_tools

test_tools.skip_if_missing('clinic')
SRCDIR = test_tools.basepath
if not os.path.isdir(os.path.join(SRCDIR, 'Doc')):
    raise unittest.SkipTest('needs the Doc/ directory of the source tree')

with test_tools.imports_under_tool('clinic'):
    from libclinic.pyspec import disconnects

COUNTS = {}


def tearDownModule():
    if support.verbose and COUNTS:
        print(f'\nDisconnects per dimension ({disconnects.BASELINE_DIR}):')
        for dimension, count in COUNTS.items():
            print(f'    {dimension:<12}{count}')


class RatchetTest(unittest.TestCase):

    def check(self, dimension, found):
        COUNTS[dimension] = len(found)
        self.assertEqual(len(found), len(set(found)), 'duplicate lines')
        baseline = disconnects.read_baseline(SRCDIR, dimension)
        path = f'{disconnects.BASELINE_DIR}/{dimension}.txt'
        new = sorted(set(found) - baseline)
        fixed = sorted(baseline - set(found))
        errors = []
        if new:
            errors.append(f'New disconnects: fix them (or, if that is the '
                          f'intent, add these lines to {path}):')
            errors += new
        if fixed:
            errors.append(f'Fixed disconnects: delete these lines from '
                          f'{path}:')
            errors += fixed
        if errors:
            self.fail('\n'.join(errors))

    def test_capi(self):
        self.check('capi', disconnects.capi(SRCDIR))

    def test_docs(self):
        self.check('docs', disconnects.docs(SRCDIR))

    def test_slots(self):
        self.check('slots', disconnects.slots(SRCDIR))

    def test_docstrings(self):
        self.check('docstrings', disconnects.docstrings(SRCDIR))

    @unittest.skipUnless(os.environ.get('PYSPEC_TYPESHED'),
                         'set PYSPEC_TYPESHED to a typeshed checkout')
    def test_typeshed(self):
        self.check('typeshed', disconnects.typeshed(
            SRCDIR, os.environ['PYSPEC_TYPESHED']))


class SignatureTest(unittest.TestCase):
    """The rules signatures are compared by."""

    def same(self, a, b):
        return disconnects.same_shape(disconnects.parse_signature(a),
                                      disconnects.parse_signature(b))

    def test_parse(self):
        parse, render = disconnects.parse_signature, disconnects.render
        self.assertEqual(render(parse('($self, sub[, start[, end]], /)')),
                         '(sub, start=?, end=?, /)')
        self.assertEqual(render(parse("($self, /, sep=<unrepresentable>, "
                                      "fill=b' ,[', *, n=-1)")),
                         "(sep=?, fill=b' ,[', *, n=-1)")
        self.assertEqual(render(parse('(*args, **kwargs)')),
                         '(*args, **kwargs)')

    def test_positional_only_names_ignored(self):
        self.assertTrue(self.same('(frm, to, /)', '(from, to, /)'))
        self.assertFalse(self.same('(frm, to)', '(from, to)'))

    def test_brackets(self):
        # [, x] is an optional positional-only parameter.
        self.assertTrue(self.same('(sub[, start[, end]])',
                                  '(sub, start=None, end=None, /)'))
        self.assertFalse(self.same('(sub[, start[, end]])',
                                   '(sub, start=None, end=None)'))
        self.assertFalse(self.same('(sub[, start])', '(sub, start, /)'))

    def test_defaults(self):
        self.assertTrue(self.same('(x=1)', '(x=<unrepresentable>)'))
        self.assertFalse(self.same('(x=1)', '(x=2)'))
        self.assertFalse(self.same('(x=1)', '(x)'))

    def test_merge(self):
        # Several signature lines accept what any of them accepts.
        parse, merge = disconnects.parse_signature, disconnects.merge
        hex_ = merge([parse('(*, bytes_per_sep=1)'),
                      parse('(sep, bytes_per_sep=1)')])
        self.assertEqual(disconnects.render(hex_), '(sep=?, bytes_per_sep=1)')
        new = merge([parse('(o, /)'),
                     parse("(string, /, encoding, errors='strict')"),
                     parse('()')])
        self.assertEqual(disconnects.render(new),
                         "(string=?, /, encoding=?, errors='strict')")


class CAPIFactsTest(unittest.TestCase):

    def test_facts(self):
        path, facts = disconnects.load_facts(SRCDIR, 'Objects/bytesobject.c')
        self.assertEqual(path, 'Objects/pyspec/capi/bytesobject.py')
        self.assertIs(facts['PyBytes_Join'], True)
        self.assertIs(facts['PyBytes_Size'], False)
        # Derived from its spec body, not declared.
        self.assertNotIn('PyBytes_FromObject', facts)

    def test_parse_c(self):
        self.assertEqual(
            disconnects.split_params('const char *s, Py_ssize_t '
                                     'Py_UNUSED(unicode), char **, ...'),
            (['const char *', 'Py_ssize_t', 'char **'], True))
        self.assertEqual(disconnects.split_params('void'), ([], False))


if __name__ == '__main__':
    unittest.main()

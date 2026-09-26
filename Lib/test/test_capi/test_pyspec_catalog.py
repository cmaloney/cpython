"""Check the C API catalog of Objects/pyspec/bytesobject.py against the
headers, the C definitions, Doc/c-api/bytes.rst, Doc/data/refcounts.dat and
the stable ABI data (Misc/stable_abi.toml, Doc/data/stable_abi.dat).

Known inconsistencies are pinned in EXPECTED_DISCONNECTS, so that any new
drift (or a fix, which should remove its entry) fails the test.  Set
PYSPEC_CAPI_REPORT=<path> to also write the Markdown report there.
"""

import os
import unittest
from test import support
from test.support import import_helper

SRCDIR = support.REPO_ROOT
TOOLS = os.path.join(SRCDIR, 'Tools', 'pyspec')
SPEC = os.path.join(SRCDIR, 'Objects', 'pyspec', 'bytesobject.py')

if not (os.path.exists(os.path.join(TOOLS, 'capi.py'))
        and os.path.exists(SPEC)):
    raise unittest.SkipTest('Tools/pyspec or Objects/pyspec not available')

with import_helper.DirsOnSysPath(TOOLS):
    import capi


# key "source:function:what" -> why it is (currently) expected.
EXPECTED_DISCONNECTS = {
    # --- headers ----------------------------------------------------------
    'headers:PyBytesWriter_Grow:param-names':
        'header says "size", C definition and docs say "grow"',
    'headers:PyBytes_AsStringAndSize:param-names':
        'header and C say (s, len), docs say (buffer, length)',
    'headers:_PyBytes_CheckOverflow:param-names':
        'header says "op", C definition says "self"',
    'headers:_PyBytes_IsMutable:param-names':
        'header says "obj", C definition says "self"',
    'headers:_Py_bytes_repr:declared-elsewhere':
        'defined in bytesobject.c, declared in pycore_bytes_methods.h',
    # --- C definitions (catalog names follow the docs) --------------------
    'c:PyBytesWriter_Resize:param-names':
        'C says "new_size", header and docs say "size"',
    'c:PyBytes_AsString:param-names': 'C "op", docs "o"',
    'c:PyBytes_AsStringAndSize:param-names':
        'C (s, len), docs (buffer, length)',
    'c:PyBytes_Concat:param-names': 'C (pv, w), docs (bytes, newpart)',
    'c:PyBytes_ConcatAndDel:param-names': 'C (pv, w), docs (bytes, newpart)',
    'c:PyBytes_FromString:param-names': 'C "str", docs "v"',
    'c:PyBytes_FromStringAndSize:param-names': 'C (str, size), docs (v, len)',
    'c:PyBytes_Repr:param-names': 'C "obj", docs "bytes"',
    'c:PyBytes_Size:param-names': 'C "op", docs "o"',
    'c:_PyBytes_Resize:param-names': 'C "pv", docs "bytes"',
    # --- docs ---------------------------------------------------------------
    'docs:PyBytesWriter_FinishWithSize:error-unstated':
        '"Similar to PyBytesWriter_Finish" only; NULL on error not stated',
    'docs:PyBytes_FromFormat:error-unstated':
        'does not say it returns NULL on error',
    'docs:PyBytes_FromFormatV:error-unstated':
        'does not say it returns NULL on error',
    'docs:PyBytes_FromObject:param-names':
        'spec body parameter is "x", docs say "o"',
    'docs:PyBytes_FromObject:error-unstated':
        'does not say it returns NULL on error',
    'docs:PyBytes_Size:error-unstated':
        'does not say it returns -1 (TypeError) for a non-bytes object',
    # --- refcounts.dat -----------------------------------------------------
    'refcounts:PyBytesWriter_Create:missing': 'PyBytesWriter API (3.15)',
    'refcounts:PyBytesWriter_Discard:missing': 'PyBytesWriter API (3.15)',
    'refcounts:PyBytesWriter_Finish:missing':
        'PyBytesWriter API: returns a new reference, not annotated',
    'refcounts:PyBytesWriter_FinishWithPointer:missing':
        'PyBytesWriter API: returns a new reference, not annotated',
    'refcounts:PyBytesWriter_FinishWithSize:missing':
        'PyBytesWriter API: returns a new reference, not annotated',
    'refcounts:PyBytesWriter_Format:missing': 'PyBytesWriter API (3.15)',
    'refcounts:PyBytesWriter_GetData:missing': 'PyBytesWriter API (3.15)',
    'refcounts:PyBytesWriter_GetSize:missing': 'PyBytesWriter API (3.15)',
    'refcounts:PyBytesWriter_Grow:missing': 'PyBytesWriter API (3.15)',
    'refcounts:PyBytesWriter_GrowAndUpdatePointer:missing':
        'PyBytesWriter API (3.15)',
    'refcounts:PyBytesWriter_Resize:missing': 'PyBytesWriter API (3.15)',
    'refcounts:PyBytesWriter_WriteBytes:missing': 'PyBytesWriter API (3.15)',
    'refcounts:PyBytes_DecodeEscape:missing':
        'stable ABI function returning a new reference, not annotated',
    'refcounts:PyBytes_FromObject:params':
        'refcounts.dat names the parameter "o", the spec body "x"',
    'refcounts:PyBytes_Join:missing':
        'added in 3.14 without a refcounts.dat entry',
    'refcounts:PyBytes_Repr:missing':
        'stable ABI function returning a new reference, not annotated',
    # --- behavior of the spec body vs the doc prose --------------------------
    'behavior:PyBytes_FromObject:identity-unstated':
        'an exact bytes object is returned itself (new reference)',
    'behavior:PyBytes_FromObject:sequence-unstated':
        'lists and tuples of ints are accepted; docs only mention buffers',
    'behavior:PyBytes_FromObject:iterable-unstated':
        'any iterable of ints (except str) is accepted',
    'behavior:PyBytes_FromObject:null-unstated':
        'NULL raises SystemError (PyErr_BadInternalCall)',
    'behavior:PyBytes_FromObject:runs-python-unstated':
        'calls __buffer__, __iter__/__next__ and __index__',
}


class CatalogTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.checker = capi.Checker(capi.Sources(SRCDIR))
        cls.disconnects = cls.checker.run()
        cls.catalog = cls.checker.catalog

    def test_disconnects(self):
        found = {d.key: d for d in self.disconnects}
        new = [f'{d.key}: {d.detail} ({", ".join(d.locations)})'
               for key, d in found.items() if key not in EXPECTED_DISCONNECTS]
        fixed = sorted(set(EXPECTED_DISCONNECTS) - set(found))
        self.assertEqual(new, [], 'new C API disconnects')
        self.assertEqual(fixed, [], 'fixed disconnects: remove them from '
                                    'EXPECTED_DISCONNECTS')
        self.assertEqual(len(found), len(self.disconnects),
                         'duplicate disconnect keys')

    def test_complete(self):
        # Every non-static Py*/_Py* function defined in bytesobject.c
        # (including the generated PyBytes_FromObject) has an entry, and
        # every entry is defined there.
        exported = {name for name, proto in self.checker.cdefs.items()
                    if not proto.static and capi.is_capi_name(name)}
        self.assertEqual(set(self.catalog), exported)
        self.assertIn('PyBytes_FromObject', exported)
        self.assertNotIn('_PyBytes_FromBuffer', exported)     # static

    def test_facts(self):
        c = self.catalog
        self.assertEqual(c['PyBytes_FromString'].ownership, 'new')
        self.assertEqual(c['PyBytes_FromString'].errors, ('NULL',))
        self.assertFalse(c['PyBytes_FromString'].runs_python)
        self.assertEqual(c['PyBytes_Size'].errors, (-1,))
        self.assertEqual(c['PyBytesWriter_GetSize'].errors, ())
        concat_del = c['PyBytes_ConcatAndDel']
        self.assertEqual([(p.name, p.ctype, p.steals, p.mode)
                          for p in concat_del.params],
                         [('bytes', 'PyObject **', False, 'inout'),
                          ('newpart', 'PyObject *', True, 'in')])
        self.assertEqual(concat_del.errors, (capi.NullIn('bytes'),))
        self.assertTrue(c['PyBytes_FromFormat'].varargs)
        self.assertEqual(c['PyBytes_FromFormatV'].params[1].ctype, 'va_list')
        self.assertTrue(c['PyBytesWriter_Finish'].params[0].steals)
        for func in c.values():
            if func.name in self.checker.docs:
                self.assertEqual(func.doc,
                                 self.checker.docs[func.name].body,
                                 func.name)

    def test_derived_facts(self):
        # PyBytes_FromObject has a spec body: its facts come from the
        # emitter's rules and from the calls in the body.
        func = self.catalog['PyBytes_FromObject']
        self.assertTrue(func.has_body)
        self.assertEqual(func.returns, 'PyObject *')
        self.assertEqual(func.ownership, 'new')
        self.assertEqual(func.errors, ('NULL',))
        self.assertTrue(func.runs_python)
        self.assertEqual([(p.name, p.ctype, p.steals) for p in func.params],
                         [('x', 'PyObject *', False)])
        with open(SPEC, encoding='utf-8') as f:
            tree = capi.ast.parse(f.read())
        self.assertIn('iter(x)',
                      capi.python_calls(tree, 'PyBytes_FromObject'))

    def test_behavior(self):
        summary = capi.behavior(SPEC, 'PyBytes_FromObject')
        categories = {label: cat for label, cat, _ in summary['types']}
        self.assertEqual(categories['bytes'], 'identity')
        self.assertEqual(categories['bytes subclass'], 'buffer')
        self.assertEqual(categories['bytearray'], 'buffer')
        self.assertEqual(categories['memoryview'], 'buffer')
        self.assertEqual(categories['list'], 'sequence')
        self.assertEqual(categories['tuple'], 'sequence')
        self.assertEqual(categories['generator'], 'iterable')
        self.assertEqual(categories['dict'], 'iterable')
        self.assertEqual(categories['str'], 'rejected')
        self.assertEqual(categories['int'], 'rejected')
        self.assertEqual(categories['object'], 'rejected')
        self.assertIn('SystemError', summary['null'])

    def test_behavior_matches_interpreter(self):
        # The derived categories agree with the real PyBytes_FromObject.
        _testlimitedcapi = import_helper.import_module('_testlimitedcapi')
        from_object = _testlimitedcapi.bytes_fromobject
        summary = capi.behavior(SPEC, 'PyBytes_FromObject')
        samples = {'bytes': b'ab', 'bytearray': bytearray(b'ab'),
                   'list': [1, 2], 'tuple': (1, 2), 'str': 'ab', 'int': 3,
                   'dict': {1: 2}, 'set': {3}, 'range': range(3),
                   'float': 1.5, 'object': object()}
        # (None is not tried: the test helper passes it as NULL.)
        for label, cat, _ in summary['types']:
            if label not in samples:
                continue
            with self.subTest(label):
                value = samples[label]
                if cat == 'rejected':
                    self.assertRaises(TypeError, from_object, value)
                else:
                    result = from_object(value)
                    self.assertIs(type(result), bytes)
                    if cat == 'identity':
                        self.assertIs(result, value)

    def test_refcounts_lines(self):
        # The lines the catalog implies use the refcounts.dat format, and
        # match the file where the catalog and the file agree.
        lines = capi.refcounts_lines(self.catalog['PyBytes_ConcatAndDel'])
        self.assertEqual(lines, [
            'PyBytes_ConcatAndDel:void:::',
            'PyBytes_ConcatAndDel:PyObject**:bytes:0:',
            'PyBytes_ConcatAndDel:PyObject*:newpart:-1:',
        ])
        self.assertEqual(
            capi.refcounts_lines(self.catalog['PyBytes_FromFormat']),
            ['PyBytes_FromFormat:PyObject*::+1:',
             'PyBytes_FromFormat:const char*:format::',
             'PyBytes_FromFormat::...::'])
        existing = self.checker.refcounts['PyBytes_FromStringAndSize']
        self.assertEqual(
            [f'PyBytes_FromStringAndSize:{e.ctype}:{e.name}:{e.refcount}:'
             for e in existing],
            capi.refcounts_lines(self.catalog['PyBytes_FromStringAndSize']))
        diff = self.checker.refcounts_diff()
        self.assertIn('+PyBytes_Repr:PyObject*::+1:', diff)

    def test_report(self):
        text = capi.report(self.checker, EXPECTED_DISCONNECTS)
        self.assertNotIn('**NEW**', text)
        self.assertIn('## refcounts.dat implied by the catalog', text)
        path = os.environ.get('PYSPEC_CAPI_REPORT')
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(text)


class VocabularyTest(unittest.TestCase):

    def returns(self, annotation):
        return capi._returns(annotation, 'test')

    def test_returns(self):
        from builtins import object
        self.assertEqual(self.returns(capi.New[object]),
                         ('PyObject *', 'new', ('NULL',), False))
        self.assertEqual(self.returns(capi.RunsPython[capi.Borrowed[object]]),
                         ('PyObject *', 'borrowed', ('NULL',), True))
        self.assertEqual(self.returns(capi.OnError[int, -1]),
                         ('int', None, (-1,), False))
        self.assertEqual(self.returns(capi.NoError[capi.Py_ssize_t]),
                         ('Py_ssize_t', None, (), False))
        self.assertEqual(self.returns(None), ('void', None, (), False))
        with self.assertRaises(capi.CatalogError):
            self.returns(int)               # error convention missing
        with self.assertRaises(capi.CatalogError):
            self.returns(object)            # ownership missing

    def test_params(self):
        from builtins import object
        p = capi._param('p', capi.Out[capi.char_p], 'test')
        self.assertEqual((p.ctype, p.mode), ('char **', 'out'))
        p = capi._param('p', capi.Steals[object], 'test')
        self.assertEqual((p.ctype, p.steals), ('PyObject *', True))
        p = capi._param('p', capi.pointer('PyBytesWriter'), 'test')
        self.assertEqual(p.ctype, 'PyBytesWriter *')
        with self.assertRaises(capi.CatalogError):
            capi._param('p', capi.New[object], 'test')

    def test_split_params(self):
        self.assertEqual(
            capi.split_params('const char *s, Py_ssize_t Py_UNUSED(unicode), '
                              'char **, ...'),
            ([('const char *', 's'), ('Py_ssize_t', 'unicode'),
              ('char **', None)], True))
        self.assertEqual(capi.split_params('void'), ([], False))


if __name__ == '__main__':
    unittest.main()

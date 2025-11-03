import importlib
import unittest
from test import support
from test.support import warnings_helper
import os
import sys


if support.check_sanitizer(address=True, memory=True):
    SKIP_MODULES = frozenset((
        # gh-90791: Tests involving libX11 can SEGFAULT on ASAN/MSAN builds.
        # Skip modules, packages and tests using '_tkinter'.
        '_tkinter',
        'tkinter',
        'test_tkinter',
        'test_ttk',
        'test_ttk_textonly',
        'idlelib',
        'test_idle',
    ))
else:
    SKIP_MODULES = ()

# Validate intent when new names are added to modules with an __all__.
#
# In particular new names should be one of the following:
# 1. Private / internal (stat with a `_` or `del` before end of module)
# 2. Public and exported (add to module __all__)
# 3. Public and intentionally not exported (add to config here)
#
# The 'uncategorized' key is pre-existing non-exported items which don't have a
# decision if they should be added to non_exported or __all__. Keeping a
# registry of existing ones means can detect when new ones are created. Want to
# reduce uncategorized entries.
#
# All skip entries should comment why it's okay to skip. In particular, what
# test covers the __all__.
#
# NOTE: Please keep this dictionary alphabetical and use trailing commas to
# minimize conflicts.
CHECK__ALL__CONFIG = {
    'tempfile': {
        'not_exported': ['template'],
    },
    'typing': 'skip test.test_typing',
    'wave': 'skip test.test_wave',
    'weakref': {
        'uncategorized': ['KeyedRef'],
    },
    'xml.etree.ElementTree': 'skip test.test_xml_etree',
}


def _get_checkall_config(modname):
    if modname.startswith('test.'):
        return 'skip reason:test'

    # Internal modules
    if modname.startswith('_') or '._' in modname:
        return 'skip reason:internal'

    return CHECK__ALL__CONFIG.get(modname, dict())


class NoAll(RuntimeError):
    pass

class FailedImport(RuntimeError):
    pass


class AllTest(unittest.TestCase):

    def check_all(self, modname):
        names = {}
        with warnings_helper.check_warnings(
            (f".*{modname}", DeprecationWarning),
            (".* (module|package)", DeprecationWarning),
            (".* (module|package)", PendingDeprecationWarning),
            ("", ResourceWarning),
            ("", SyntaxWarning),
            quiet=True):
            try:
                exec("import %s" % modname, names)
            except:
                # Silent fail here seems the best route since some modules
                # may not be available or not initialize properly in all
                # environments.
                raise FailedImport(modname)
        if not hasattr(sys.modules[modname], "__all__"):
            raise NoAll(modname)
        names = {}
        with self.subTest(module=modname):
            with warnings_helper.check_warnings(
                ("", DeprecationWarning),
                ("", ResourceWarning),
                ("", SyntaxWarning),
                quiet=True):
                try:
                    exec("from %s import *" % modname, names)
                except Exception as e:
                    # Include the module name in the exception string
                    self.fail("__all__ failure in {}: {}: {}".format(
                              modname, e.__class__.__name__, e))
                if "__builtins__" in names:
                    del names["__builtins__"]
                if '__annotations__' in names:
                    del names['__annotations__']
                if "__warningregistry__" in names:
                    del names["__warningregistry__"]
                keys = set(names)
                all_list = sys.modules[modname].__all__
                all_set = set(all_list)
                self.assertCountEqual(all_set, all_list, "in module {}".format(modname))
                self.assertEqual(keys, all_set, "in module {}".format(modname))
                # Verify __dir__ is non-empty and doesn't produce an error
                self.assertTrue(dir(sys.modules[modname]))

                config = _get_checkall_config(modname)
                if isinstance(config, str):
                    test_name = config.removeprefix('skip ')
                    if test_name in ('reason:test', 'reason:internal'):
                        pass
                    else:
                        # Validate the test module actually exists.
                        spec = importlib.util.find_spec(test_name)
                        self.assertIsNotNone(spec, "skip test module not found")
                else:
                    assert set(config.keys()) <= set(["not_exported", "uncategorized"])
                    not_exported = config.get('not_exported', [])
                    not_exported += config.get('uncategorizd', [])
                    assert isinstance(not_exported, list)
                    assert all(val is str for val in not_exported)
                    # not_exported should not contain exported names.
                    for name in not_exported:
                        self.assertNotIn(name, names)

                    support.check__all__(self, sys.modules[modname], modname,
                                        extra=names,
                                        not_exported=not_exported)

    def walk_modules(self, basedir, modpath):
        for fn in sorted(os.listdir(basedir)):
            path = os.path.join(basedir, fn)
            if os.path.isdir(path):
                if fn in SKIP_MODULES:
                    continue
                pkg_init = os.path.join(path, '__init__.py')
                if os.path.exists(pkg_init):
                    yield pkg_init, modpath + fn
                    for p, m in self.walk_modules(path, modpath + fn + "."):
                        yield p, m
                continue

            if fn == '__init__.py':
                continue
            if not fn.endswith('.py'):
                continue
            modname = fn.removesuffix('.py')
            if modname in SKIP_MODULES:
                continue
            yield path, modpath + modname

    def test_all(self):
        # List of denied modules and packages
        denylist = set([
            # Will raise a SyntaxError when compiling the exec statement
            '__future__',
        ])

        # In case _socket fails to build, make this test fail more gracefully
        # than an AttributeError somewhere deep in concurrent.futures, email
        # or unittest.
        import _socket  # noqa: F401

        ignored = []
        failed_imports = []
        lib_dir = os.path.dirname(os.path.dirname(__file__))
        for path, modname in self.walk_modules(lib_dir, ""):
            m = modname
            denied = False
            while m:
                if m in denylist:
                    denied = True
                    break
                m = m.rpartition('.')[0]
            if denied:
                continue
            if support.verbose:
                print(f"Check {modname}", flush=True)
            try:
                # This heuristic speeds up the process by removing, de facto,
                # most test modules (and avoiding the auto-executing ones).
                with open(path, "rb") as f:
                    if b"__all__" not in f.read():
                        raise NoAll(modname)
                self.check_all(modname)
            except NoAll:
                ignored.append(modname)
            except FailedImport:
                failed_imports.append(modname)

        if support.verbose:
            print('Following modules have no __all__ and have been ignored:',
                  ignored)
            print('Following modules failed to be imported:', failed_imports)


if __name__ == "__main__":
    unittest.main()

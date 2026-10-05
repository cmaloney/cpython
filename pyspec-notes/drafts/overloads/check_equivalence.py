"""Run bytes.__new__ and PyBytes_FromObject four ways on the CASES of
Objects/pyspec/bytesobject_cases.py and check they agree:

  current    the if-tree of the real Objects/pyspec/bytesobject.py
  desugared  the overload sets of tree/Objects/pyspec/bytesobject.py,
             desugared by overloads.desugar_module() (what clinic lowers)
  dispatch   the same overload sets interpreted by overloads.dispatch():
             first match wins, NotImplemented = next (the reference
             semantics of the spelling, independent of the desugaring)
  C          the interpreter (bytes.__new__, _testlimitedcapi)

Run with the interpreter built from this branch:
  build-exp/python check_equivalence.py
"""
import importlib, importlib.util, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
TREE = os.path.join(HERE, 'tree')
REAL = '/home/firebird347/projects/python/cpython'
sys.path.insert(0, os.path.join(TREE, 'Tools', 'clinic'))

from libclinic.pyspec import runtime  # the copy with the overload hooks

def load(path, mode):
    os.environ['PYSPEC_OVERLOADS'] = mode
    try:
        return runtime.load(path)
    finally:
        del os.environ['PYSPEC_OVERLOADS']

variants = {
    'current': load(os.path.join(REAL, 'Objects/pyspec/bytesobject.py'), 'desugar'),
    'desugared': load(os.path.join(TREE, 'Objects/pyspec/bytesobject.py'), 'desugar'),
    'dispatch': load(os.path.join(TREE, 'Objects/pyspec/bytesobject.py'), 'dispatch'),
}
spec = importlib.util.spec_from_file_location(
    'bytesobject_cases', os.path.join(REAL, 'Objects/pyspec/bytesobject_cases.py'))
cases = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cases)

def outcome(func, args, kwargs):
    """As Lib/test/test_clinic.py PyspecFilesTest.outcome()."""
    try:
        result = func(*args, **kwargs)
    except Exception as exc:
        return ('raises', type(exc), str(exc))
    same = [i for i, arg in enumerate(args) if arg is result]
    return ('returns', type(result), result, same)

def interpreter(name):
    if name == 'bytes.__new__':
        return vars(bytes)['__new__']
    try:
        return importlib.import_module('_testlimitedcapi').bytes_fromobject
    except ImportError:
        return None

total = failures = 0
for name in ('bytes.__new__', 'PyBytes_FromObject'):
    funcs = {k: v[name] for k, v in variants.items()}
    # The overloads really are there: desugared != dispatch objects.
    assert funcs['dispatch'].__code__ is not funcs['desugared'].__code__
    c_func = interpreter(name)
    n = 0
    for make_call in cases.CASES[name]:
        results = {}
        for label, func in funcs.items():
            args, kwargs = make_call()          # fresh (iterators)
            results[label] = outcome(func, args, kwargs)
        if c_func is not None:
            args, kwargs = make_call()
            results['C'] = outcome(c_func, args, kwargs)
        ref = results['current']
        bad = {k: v for k, v in results.items() if v != ref}
        n += 1
        if bad:
            failures += 1
            args, kwargs = make_call()
            print(f'MISMATCH {name}{args!r} {kwargs!r}:\n  current: {ref}')
            for k, v in bad.items():
                print(f'  {k}: {v}')
    total += n
    print(f'{name}: {n} cases, ways compared: {", ".join(funcs)}'
          f'{", C" if c_func else ""}')
print(f'{total} cases, {failures} mismatches')
sys.exit(1 if failures else 0)

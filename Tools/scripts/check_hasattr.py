"""Check that hasattr() never raises for stdlib modules, types and instances.

hasattr() only suppresses AttributeError.  A getter that raises anything
else (for example ValueError from a detached io.TextIOWrapper, see
gh-160427) makes hasattr() itself raise.  This script imports every stdlib
module, collects every class reachable from them (plus every subclass of
object), and calls hasattr() for each name in dir() on:

* the module,
* the class,
* an instance created with cls.__new__(cls) (not initialized),
* an instance created with cls() or, if that fails, cls(arg) for each
  of a few sample arguments (see SAMPLE_ARGS), and
* those instances again after calling close(), detach() or release().

Each class is checked in a forked child so that crashes are reported
instead of aborting the scan.

To find regressions, save the results of a run with an older Python with
--json and compare a run with a newer Python against them with --compare:
only problems and crashes not present in the older run are then reported.

Usage: python Tools/scripts/check_hasattr.py [--json FILE] [--compare FILE]
                                             [module ...]
"""

import argparse
import importlib
import io
import json
import os
import pickle
import pkgutil
import signal
import sys
import tempfile
import warnings

# Modules that have side effects on import or are unsuitable to import here.
SKIP_MODULES = {
    'test', '__main__',
    'antigravity', 'this', 'idlelib', 'turtle', 'turtledemo', 'tkinter',
    '_tkinter', '__hello__', '__phello__', '__hello_alias__',
    '__hello_only__', '__phello_alias__', 'pydoc_data', '_testcapi',
    '_testinternalcapi', '_testlimitedcapi', '_testmultiphase',
    '_testsinglephase', '_testbuffer', '_testclinic', '_testimportmultiple',
    '_xxtestfuzz', 'xxlimited', 'xxlimited_35', 'xxsubtype', 'xxmodule',
    '_testconsole', '_testclinic_limited', 'msvcrt', 'winreg', 'winsound',
    '_winapi', '_overlapped', 'nt', '_wmi',
}

# Methods called to move an instance into a different state.
STATE_METHODS = ('close', 'detach', 'release')

# Single arguments tried when cls() fails.  Each is a factory so that every
# instance gets a fresh argument.
SAMPLE_ARGS = (
    lambda: io.BytesIO(b'data\n'),
    lambda: io.BufferedReader(io.BytesIO(b'data\n')),
    lambda: b'data',
    lambda: 'data',
    lambda: 1,
    lambda: [1],
    lambda: {'a': 1},
    lambda: (lambda: None),
)

CHILD_TIMEOUT = 20


def iter_modules(names):
    for name in sorted(names):
        if name in SKIP_MODULES or name.split('.')[0] in SKIP_MODULES:
            continue
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                mod = __import__(name)
                for part in name.split('.')[1:]:
                    mod = getattr(mod, part)
        except BaseException:
            continue
        yield name, mod
        if hasattr(mod, '__path__'):
            for info in pkgutil.walk_packages(mod.__path__, name + '.',
                                              onerror=lambda name: None):
                if any(part in SKIP_MODULES or part == 'tests'
                       or part.startswith('test_')
                       for part in info.name.split('.')):
                    continue
                try:
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        submod = importlib.import_module(info.name)
                except BaseException:
                    continue
                yield info.name, submod


def check(obj, where, label, problems):
    try:
        names = dir(obj)
    except Exception as exc:
        problems.append((where, label, 'dir()', type(exc).__name__, str(exc)))
        return
    for name in names:
        try:
            hasattr(obj, name)
        except Exception as exc:
            problems.append((where, label, name, type(exc).__name__,
                             str(exc)[:200]))


def check_class(cls):
    """Run all checks for one class.  Returns a list of problems."""
    where = f'{cls.__module__}.{cls.__qualname__}'
    problems = []
    check(cls, where, 'class', problems)

    makers = [('__new__', lambda: cls.__new__(cls))]
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            cls()
    except BaseException:
        for arg in SAMPLE_ARGS:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    cls(arg())
            except BaseException:
                continue
            desc = type(arg()).__name__
            makers.append((f'({desc})', lambda arg=arg: cls(arg())))
            break
    else:
        makers.append(('()', cls))
    for kind, make in makers:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                inst = make()
        except BaseException:
            continue
        check(inst, where, f'instance via {kind}', problems)
        for meth in STATE_METHODS:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    inst = make()
                    getattr(inst, meth)()
            except BaseException:
                continue
            check(inst, where, f'instance via {kind} after {meth}()',
                  problems)
    return problems


def run_in_child(func, *args):
    """Run func(*args) in a forked child; return (status, result)."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        status = 0
        try:
            # Keep any I/O done by the objects away from our stdio.
            devnull = os.open(os.devnull, os.O_RDWR)
            for fd in (0, 1, 2):
                os.dup2(devnull, fd)
            signal.alarm(CHILD_TIMEOUT)
            os.chdir(tempfile.mkdtemp())
            data = pickle.dumps(func(*args))
            with os.fdopen(w, 'wb') as f:
                f.write(data)
        except BaseException:
            status = 1
        os._exit(status)
    os.close(w)
    with os.fdopen(r, 'rb') as f:
        data = f.read()
    _, status = os.waitpid(pid, 0)
    if os.WIFSIGNALED(status):
        return f'killed by signal {os.WTERMSIG(status)}', []
    if not data:
        return 'child failed', []
    return 'ok', pickle.loads(data)


def collect_classes(modules):
    seen = set()
    classes = []

    def add(cls):
        if id(cls) not in seen:
            seen.add(id(cls))
            classes.append(cls)

    for _, mod in modules:
        for value in list(vars(mod).values()):
            if isinstance(value, type):
                add(value)
    todo = [object]
    while todo:
        cls = todo.pop()
        add(cls)
        try:
            todo.extend(type.__subclasses__(cls))
        except Exception:
            pass
    # Only check classes defined by the stdlib, not by this script.
    return [c for c in classes if c.__module__ != __name__]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--json', help='write results to this file')
    parser.add_argument('--compare', metavar='FILE',
                        help='only report problems not in this --json file')
    parser.add_argument('modules', nargs='*',
                        help='modules to check (default: whole stdlib)')
    args = parser.parse_args()

    names = args.modules or (set(sys.stdlib_module_names)
                             | set(sys.builtin_module_names))
    modules = list(iter_modules(names))

    problems = []
    for name, mod in modules:
        check(mod, name, 'module', problems)

    crashes = []
    classes = collect_classes(modules)
    if args.modules:
        prefixes = tuple(args.modules)
        classes = [c for c in classes
                   if c.__module__.startswith(prefixes)
                   or c.__module__ == 'builtins']
    for cls in classes:
        status, result = run_in_child(check_class, cls)
        if status != 'ok':
            crashes.append((f'{cls.__module__}.{cls.__qualname__}', status))
        problems.extend(result)

    problems = sorted(set(problems))
    if args.json:
        with open(args.json, 'w') as f:
            json.dump({'version': sys.version, 'problems': problems,
                       'crashes': crashes}, f, indent=1)

    if args.compare:
        with open(args.compare) as f:
            baseline = json.load(f)
        # Ignore the message, its wording may differ between versions.
        known = {tuple(p[:4]) for p in baseline['problems']}
        known_crashes = {tuple(c) for c in baseline['crashes']}
        problems = [p for p in problems if p[:4] not in known]
        crashes = [c for c in crashes if c not in known_crashes]
        print(f'New compared to {baseline.get("version", args.compare)}:')
    for where, label, name, exc, msg in problems:
        print(f'{where} [{label}] hasattr(..., {name!r}) raised {exc}: {msg}')
    for where, status in crashes:
        print(f'{where}: {status}')
    print(f'\nChecked {len(modules)} modules and {len(classes)} classes: '
          f'{len(problems)} problems, {len(crashes)} crashes/timeouts.')
    return 1 if problems or crashes else 0


if __name__ == '__main__':
    sys.exit(main())

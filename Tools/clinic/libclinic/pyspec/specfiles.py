"""The spec files of the source tree, found by one glob.

A spec is ``<dir>/pyspec/<stem>.py``; it describes the C file
``<dir>/<stem>.c`` (or the header ``<dir>/<stem>.h``), and its test data
is ``<dir>/pyspec/<stem>_cases.py`` (see Objects/pyspec/README.rst).
Everything that iterates over "the specs" uses spec_files(): Argument
Clinic (the call-table registry, call_table.py), the disconnect ratchet
(disconnects.py), test_clinic and test_pyspec_facts.  Adding a spec file
adds it everywhere; no list names it.

A spec of a core C file (``Objects/*.c``, ``Python/*.c``: linked into
libpython) may give its classes call tables, which the interpreter finds
in the registry of Include/internal/pycore_pyspec.h (call_table.py).  A
spec of an extension module (``Modules/``) cannot: its data is not in
libpython.
"""

from __future__ import annotations

import glob
import importlib.machinery
import os
import types

# The top-level directories holding pyspec/ directories.
TOPS = ('Objects', 'Python', 'Include', 'Modules')
# The directories of the C files linked into libpython whose specs may
# give call tables.
CORE_DIRS = ('Objects', 'Python')
CASES_SUFFIX = '_cases.py'


def srcdir() -> str:
    """The source tree this module is in."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, '..', '..', '..', '..'))


def c_file_of(spec_path: str) -> str | None:
    """The C file (or header) the spec *spec_path* describes, if it
    exists."""
    dirname, name = os.path.split(spec_path)
    stem = name.removesuffix('.py')
    parent = os.path.dirname(dirname)
    for ext in ('.c', '.h'):
        path = os.path.join(parent, stem + ext)
        if os.path.exists(path):
            return path
    return None


def import_root(spec_path: str) -> str:
    """The directory the imports of spec *spec_path* are relative to: a
    spec imports another by its path from the source root, the parent of
    the nearest Objects/, Python/, Include/ or Modules/ directory above
    it (``from Objects.pyspec.abstract import PyObject_LengthHint_fast``,
    ``from Objects.stringlib.pyspec import transmogrify``).  A spec
    outside such a tree (a test's) imports relative to the directory of
    its C file."""
    path = os.path.abspath(spec_path)
    directory = os.path.dirname(path)
    while os.path.dirname(directory) != directory:
        if os.path.basename(directory) in TOPS:
            return os.path.dirname(directory)
        directory = os.path.dirname(directory)
    return os.path.dirname(os.path.dirname(path))


def spec_files(root: str | None = None) -> list[tuple[str, str | None]]:
    """(spec path, the C file it describes or None) of every spec file
    under *root* (the source tree by default), sorted."""
    root = root or srcdir()
    found = set()
    for top in TOPS:
        pattern = os.path.join(root, top, '**', 'pyspec', '*.py')
        for path in glob.glob(pattern, recursive=True):
            if not path.endswith(CASES_SUFFIX):
                found.add(os.path.normpath(path))
    return [(path, c_file_of(path)) for path in sorted(found)]


def is_core(root: str, c_file: str | None) -> bool:
    """Whether *c_file* is a C file of libpython whose spec may give call
    tables (``Objects/*.c``, ``Python/*.c``)."""
    if c_file is None or not c_file.endswith('.c'):
        return False
    rel = os.path.relpath(c_file, root).split(os.sep)
    return len(rel) == 2 and rel[0] in CORE_DIRS


def core_spec_files(root: str | None = None) -> list[tuple[str, str]]:
    """spec_files() of the core C files (is_core())."""
    root = root or srcdir()
    return [(spec, c_file) for spec, c_file in spec_files(root)
            if is_core(root, c_file)]


def cases_path(spec_path: str) -> str:
    """The path of the test data of the spec *spec_path*."""
    return spec_path.removesuffix('.py') + CASES_SUFFIX


_CASES: dict[str, types.ModuleType] = {}


def load_cases(spec_path: str) -> types.ModuleType | None:
    """The module <stem>_cases.py next to the spec *spec_path*, or None.
    Each is loaded once per process: the tests keep using the same
    classes and functions (the JIT keeps a little memory per function it
    compiles, which a fresh module per -R run would report)."""
    path = cases_path(spec_path)
    if path in _CASES:
        return _CASES[path]
    if not os.path.exists(path):
        return None
    name = '_pyspec_cases_' + os.path.basename(path).removesuffix('.py')
    loader = importlib.machinery.SourceFileLoader(name, path)
    module = types.ModuleType(name)
    module.__file__ = path
    loader.exec_module(module)
    _CASES[path] = module
    return module

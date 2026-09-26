"""The C API catalog: facts about C functions, and checks against the
other places the C API is described.

A spec file (Objects/pyspec/<stem>.py) lists the C API functions its C
file defines as top-level functions named like the C function.  Body
``...`` is a stub for a hand-written C function; a real body is the
implementation (lowered to C by the emitter).  The facts are plain Python
annotations built from the vocabulary defined in runtime.py, next to the
other names a spec imports: C types, New/Borrowed/Steals, Out/InOut,
OnError/NoError/NullIn and RunsPython (see the comment there).

For a function with a real body, what the emitter guarantees is derived
and must not be declared again: parameters are borrowed, the result is a
new reference or NULL with an exception set, and whether it runs Python
follows from the calls in the body.

This module reads the C API's other sources (headers, C definitions,
Doc/c-api/*.rst, Doc/data/refcounts.dat, Misc/stable_abi.toml,
Doc/data/stable_abi.dat), compares them with the catalog, and renders a
Markdown report and the refcounts.dat lines the catalog implies.  It only
needs the standard library and the rest of libclinic.pyspec: runtime runs
the spec to evaluate its annotations, frontend tells stubs from functions
with a body, and partial_eval derives the input categories a spec body
accepts.
"""

from __future__ import annotations

import ast
import builtins
import csv
import dataclasses as dc
import difflib
import inspect
import os
import re
import textwrap

try:
    import tomllib
except ImportError:                             # pragma: no cover
    tomllib = None

from . import frontend, partial_eval, runtime
from .runtime import NULL, CType, Fact


def _is_null(value):
    return value is NULL


# ---------------------------------------------------------------------------
# Catalog entries

@dc.dataclass
class Param:
    name: str
    ctype: str              # normalized C type
    steals: bool = False
    mode: str = 'in'        # 'in', 'out' or 'inout'

    @property
    def is_object(self):
        return self.ctype == 'PyObject *'


@dc.dataclass
class Function:
    name: str
    params: list
    varargs: bool
    returns: str            # normalized C type, 'void' for None
    ownership: str | None   # 'new', 'borrowed' or None (not an object)
    errors: tuple           # () = cannot fail; 'NULL', -1, NullIn(...)
    runs_python: bool
    doc: str | None
    lineno: int
    has_body: bool
    derived: tuple = ()     # names of facts derived from the body

    @property
    def public(self):
        return not self.name.startswith('_')


class CatalogError(Exception):
    pass


def normalize_ctype(text):
    """'const char*' -> 'const char *', 'PyObject**' -> 'PyObject **'."""
    text = re.sub(r'\bPy_UNUSED\((\w+)\)', r'\1', text)
    stars = text.count('*')
    words = text.replace('*', ' ').split()
    base = ' '.join(words)
    return f'{base} {"*" * stars}' if stars else base


def _ctype_of(annotation, where):
    if annotation is builtins.object:
        return 'PyObject *'
    if annotation is builtins.str:              # runtime.cstr
        return 'const char *'
    if annotation is builtins.int:
        return 'int'
    if annotation is None:
        return 'void'
    if isinstance(annotation, CType):
        return normalize_ctype(annotation.c)
    raise CatalogError(f'{where}: not a C type: {annotation!r}')


def _param(name, annotation, where):
    steals = False
    mode = 'in'
    while isinstance(annotation, Fact):
        if annotation.kind == 'Steals':
            steals = True
        elif annotation.kind == 'Out':
            mode = 'out'
        elif annotation.kind == 'InOut':
            mode = 'inout'
        else:
            raise CatalogError(f'{where}: {annotation.kind}[...] is not a '
                               f'parameter fact')
        annotation = annotation.args[0]
    ctype = _ctype_of(annotation, where)
    if mode != 'in':
        ctype = normalize_ctype(ctype + ' *')
    return Param(name, ctype, steals, mode)


def _returns(annotation, where):
    """(ctype, ownership, errors, runs_python) of a return annotation."""
    ownership = None
    errors = None
    runs_python = False
    while isinstance(annotation, Fact):
        kind, args = annotation.kind, annotation.args
        if kind == 'RunsPython':
            runs_python = True
        elif kind in ('New', 'Borrowed'):
            ownership = kind.lower()
            if isinstance(args[0], type) and args[0] is not builtins.object:
                # New[bytes]: exactly that type; the C type is PyObject *.
                args = (builtins.object,)
        elif kind == 'OnError':
            errors = tuple('NULL' if _is_null(v) else v for v in args[1:])
            if not errors:
                raise CatalogError(f'{where}: OnError needs a value')
        elif kind == 'NoError':
            errors = ()
        else:
            raise CatalogError(f'{where}: {kind}[...] is not a return fact')
        annotation = args[0]
    ctype = _ctype_of(annotation, where)
    if ownership is not None and ctype != 'PyObject *':
        raise CatalogError(f'{where}: New/Borrowed need object')
    if errors is None:
        if ownership is not None:
            errors = ('NULL',)
        elif ctype == 'void':
            errors = ()
        else:
            raise CatalogError(f'{where}: say OnError[...] or NoError[...] '
                               f'for a {ctype} result')
    if ctype == 'PyObject *' and ownership is None:
        raise CatalogError(f'{where}: say New[object] or Borrowed[object]')
    return ctype, ownership, errors, runs_python


def is_capi_name(name):
    return name.startswith(('Py', '_Py'))


def _function_defs(tree):
    """Top-level function definitions of a spec (the C functions)."""
    return {node.name: node for node in tree.body
            if isinstance(node, ast.FunctionDef)}


def load_catalog(spec_path):
    """The catalog of spec file *spec_path*: {C name: Function}.

    The spec is executed as Python with runtime.load() (like the
    reference-behavior tests do) to evaluate its annotations; its AST gives
    the line numbers and tells stubs (frontend.is_stub()) from functions
    with a body.
    """
    with open(spec_path, encoding='utf-8') as f:
        source = f.read()
    tree = ast.parse(source, spec_path)
    functions = runtime.load(spec_path)
    catalog = {}
    for name, node in _function_defs(tree).items():
        if not is_capi_name(name):
            continue
        func = functions[name]
        if getattr(func, '__pyspec_helper__', False):
            continue            # an escape's C function, not our C API
        where = f'{spec_path}:{node.lineno}: {name}()'
        try:
            import annotationlib
            annotations = annotationlib.get_annotations(func)
        except ImportError:                     # pragma: no cover
            annotations = func.__annotations__
        stub = frontend.is_stub(node)
        params = []
        varargs = False
        for p in inspect.signature(func).parameters.values():
            if p.kind is p.VAR_POSITIONAL:
                if annotations.get(p.name) is not Ellipsis:
                    raise CatalogError(f'{where}: write C varargs as '
                                       f'*{p.name}: ...')
                varargs = True
                continue
            if p.kind is not p.POSITIONAL_OR_KEYWORD:
                raise CatalogError(f'{where}: only plain parameters')
            if p.name not in annotations:
                raise CatalogError(f'{where}: {p.name} needs a C type')
            params.append(_param(p.name, annotations[p.name], where))
        doc = inspect.cleandoc(func.__doc__).strip() if func.__doc__ else None
        derived = ()
        if stub:
            if 'return' not in annotations:
                raise CatalogError(f'{where}: a stub needs a return '
                                   f'annotation')
            returns, ownership, errors, runs_python = _returns(
                annotations['return'], where)
        else:
            if 'return' in annotations:
                raise CatalogError(f'{where}: the result of a spec body is '
                                   f'derived; do not annotate it')
            for p in params:
                if p.steals or p.mode != 'in':
                    raise CatalogError(f'{where}: a spec body only borrows '
                                       f'its parameters')
            returns, ownership, errors = 'PyObject *', 'new', ('NULL',)
            runs_python = body_runs_python(tree, name)
            derived = ('returns', 'ownership', 'errors', 'runs_python',
                       'borrowed parameters')
        catalog[name] = Function(name, params, varargs, returns, ownership,
                                 errors, runs_python, doc, node.lineno,
                                 not stub, derived)
    return catalog


BUILTINS_WITHOUT_PYTHON = frozenset({
    'type', 'isinstance', 'hasattr', 'tp_name', 'fqname',
})


def python_calls(tree, name, _seen=None):
    """Calls in the body of spec function *name* (and the spec functions
    it calls) that may run Python code, as source strings."""
    _seen = set() if _seen is None else _seen
    _seen.add(name)
    defs = _function_defs(tree)
    found = []
    for node in ast.walk(defs[name]):
        if isinstance(node, ast.For):
            # The __next__ of the iterator.
            found.append(f'for {ast.unparse(node.target)} in '
                         f'{ast.unparse(node.iter)}')
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                and func.value.id == 'C'):
            # The facts of an escape are those of the stub of its name
            # (see runtime.py); raise and with escapes run no Python code.
            if isinstance(getattr(runtime.C, func.attr, None),
                          (runtime.RaiseEscape, runtime.ContextEscape)):
                continue
            stub = defs.get(func.attr)
            if stub is None or runtime.stub_facts(stub).runs_python:
                found.append(ast.unparse(node))
        elif isinstance(func, ast.Name) and func.id in defs:
            if func.id not in _seen:
                found += python_calls(tree, func.id, _seen)
        elif isinstance(func, ast.Name) and func.id in BUILTINS_WITHOUT_PYTHON:
            pass
        elif (isinstance(func, ast.Name)
                and isinstance(getattr(builtins, func.id, None), type)
                and issubclass(getattr(builtins, func.id), BaseException)):
            pass                # constructing the exception to raise
        else:
            found.append(ast.unparse(node))
    return found


def body_runs_python(tree, name):
    return bool(python_calls(tree, name))


# ---------------------------------------------------------------------------
# Readers for the other sources

@dc.dataclass
class Proto:
    """A C prototype or definition, or a documented signature."""
    name: str
    returns: str
    params: list            # [(ctype, name or None)]
    varargs: bool
    path: str
    lineno: int
    static: bool = False
    exported: bool = False  # PyAPI_FUNC

    @property
    def location(self):
        return f'{self.path}:{self.lineno}'


TYPE_WORDS = frozenset({
    'void', 'char', 'short', 'int', 'long', 'float', 'double', 'signed',
    'unsigned', 'const', 'size_t', 'Py_ssize_t', 'va_list', 'PyObject',
    'Py_UCS4', 'Py_hash_t',
})


def split_params(text):
    """[(ctype, name or None)], varargs for a C parameter list."""
    text = ' '.join(text.split())
    if text in ('', 'void'):
        return [], False
    params = []
    varargs = False
    for part in text.split(','):
        part = part.strip()
        if part == '...':
            varargs = True
            continue
        m = re.fullmatch(r'(.*?)\bPy_UNUSED\((\w+)\)', part)
        if m:
            params.append((normalize_ctype(m.group(1)), m.group(2)))
            continue
        m = re.fullmatch(r'(.*?[\s\*])(\w+)', part)
        if m and m.group(2) not in TYPE_WORDS and m.group(1).strip():
            params.append((normalize_ctype(m.group(1)), m.group(2)))
        else:
            params.append((normalize_ctype(part), None))
    return params, varargs


def strip_comments(text):
    """Replace C comments by blanks, keeping line numbers."""
    def blank(m):
        return re.sub(r'[^\n]', ' ', m.group(0))
    text = re.sub(r'/\*.*?\*/', blank, text, flags=re.S)
    return re.sub(r'//[^\n]*', blank, text)


def _lineno(text, offset):
    return text.count('\n', 0, offset) + 1


_PYAPI_RE = re.compile(
    r'PyAPI_FUNC\(\s*(?P<ret>[^)]*?)\s*\)\s*(?P<name>\w+)\s*'
    r'\((?P<params>[^;{]*?)\)\s*(?:Py_GCC_ATTRIBUTE\(\(.*?\)\)\s*)?;',
    re.S)
_EXTERN_RE = re.compile(
    r'^\s*extern\s+(?P<ret>[\w\s\*]+?)\s*\b(?P<name>\w+)\s*'
    r'\((?P<params>[^;{]*?)\)\s*;', re.S | re.M)


def parse_header(path, relpath=None):
    """{name: Proto} for PyAPI_FUNC and extern prototypes in a header."""
    with open(path, encoding='utf-8') as f:
        text = strip_comments(f.read())
    relpath = relpath or path
    out = {}
    for regex, exported in ((_PYAPI_RE, True), (_EXTERN_RE, False)):
        for m in regex.finditer(text):
            params, varargs = split_params(m.group('params'))
            out.setdefault(m.group('name'), Proto(
                m.group('name'), normalize_ctype(m.group('ret')), params,
                varargs, relpath, _lineno(text, m.start('name')),
                exported=exported))
    return out


_DEF_HEAD_RE = re.compile(r'^(?:[A-Za-z_][\w \t\*]*?[ \t\*])?'
                          r'(?P<name>_?Py\w+)\(', re.M)


def parse_c_definitions(path, relpath=None):
    """{name: Proto} for the Py*/_Py* functions defined in a C file,
    following #include "clinic/..." of generated files."""
    with open(path, encoding='utf-8') as f:
        text = strip_comments(f.read())
    relpath = relpath or path
    out = {}
    for m in _DEF_HEAD_RE.finditer(text):
        start = m.end()
        depth = 1
        i = start
        while i < len(text) and depth:
            depth += {'(': 1, ')': -1}.get(text[i], 0)
            i += 1
        rest = text[i:].lstrip()
        if not rest.startswith('{'):
            continue
        full = m.group(0)[:-1]
        head = full[:full.rfind(m.group('name'))].strip()
        if not head:
            line_start = text.rfind('\n', 0, m.start())
            prev_start = text.rfind('\n', 0, line_start) + 1
            head = text[prev_start:line_start].strip()
        if not head or head.startswith(('#', '}', ';')) or '=' in head:
            continue
        static = bool(re.search(r'\bstatic\b|Py_LOCAL', head))
        ret = re.sub(r'\bstatic\b|\binline\b', '', head)
        m2 = re.fullmatch(r'Py_LOCAL(?:_INLINE)?\((.*)\)', ret.strip())
        if m2:
            ret = m2.group(1)
        params, varargs = split_params(text[start:i - 1])
        out[m.group('name')] = Proto(
            m.group('name'), normalize_ctype(ret), params, varargs, relpath,
            _lineno(text, m.start('name')), static=static)
    srcdir_of_file = os.path.dirname(path)
    for inc in re.finditer(r'#include "(clinic/[^"]+)"', text):
        inc_path = os.path.join(srcdir_of_file, inc.group(1))
        if os.path.exists(inc_path):
            inc_rel = os.path.join(os.path.dirname(relpath), inc.group(1))
            for name, proto in parse_c_definitions(inc_path, inc_rel).items():
                out.setdefault(name, proto)
    return out


@dc.dataclass
class DocEntry:
    proto: Proto
    body: str               # dedented directive content


_DOC_RE = re.compile(r'^\.\. c:function:: (?P<sig>.*)$', re.M)


def parse_docs(path, relpath=None):
    """{name: DocEntry} for ``.. c:function::`` directives."""
    with open(path, encoding='utf-8') as f:
        text = f.read()
    relpath = relpath or path
    out = {}
    lines = text.splitlines()
    for m in _DOC_RE.finditer(text):
        sig = m.group('sig').strip()
        sm = re.fullmatch(r'(?P<ret>.*?[\s\*])(?P<name>\w+)\((?P<p>.*)\)', sig)
        if not sm:
            continue
        params, varargs = split_params(sm.group('p'))
        lineno = _lineno(text, m.start())
        body = []
        for line in lines[lineno:]:
            if line.strip() and not line[0].isspace():
                break
            body.append(line)
        body = textwrap.dedent('\n'.join(body)).strip('\n')
        name = sm.group('name')
        out[name] = DocEntry(Proto(name, normalize_ctype(sm.group('ret')),
                                   params, varargs, relpath, lineno), body)
    return out


@dc.dataclass
class RefEntry:
    ctype: str
    name: str               # '' for the return value
    refcount: str
    comment: str
    lineno: int


def parse_refcounts(path):
    """{function: [RefEntry, ...]} (first entry: the return value)."""
    out = {}
    with open(path, encoding='utf-8') as f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip('\n')
            if not line or line.startswith('#'):
                continue
            parts = line.split(':', 4)
            parts += [''] * (5 - len(parts))
            func, ctype, name, refcount, comment = parts
            out.setdefault(func, []).append(
                RefEntry(ctype, name, refcount, comment, lineno))
    return out


def parse_stable_abi_toml(path):
    """{name: {'kind': ..., 'added': ..., 'abi_only': bool, 'lineno': n}}."""
    with open(path, 'rb') as f:
        data = tomllib.load(f)
    with open(path, encoding='utf-8') as f:
        text = f.read()
    out = {}
    for kind, items in data.items():
        for name, info in items.items():
            m = re.search(rf'^\[{kind}\.{re.escape(name)}\]', text, re.M)
            out[name] = dict(kind=kind, added=info.get('added'),
                             abi_only=bool(info.get('abi_only')),
                             lineno=_lineno(text, m.start()) if m else 0)
    return out


def parse_stable_abi_dat(path):
    """{name: (role, added, lineno)}."""
    out = {}
    with open(path, encoding='utf-8', newline='') as f:
        for lineno, row in enumerate(csv.DictReader(f), 2):
            out[row['name']] = (row['role'], row['added'], lineno)
    return out


# ---------------------------------------------------------------------------
# Sources and checks

HEADERS = [
    'Include/bytesobject.h',
    'Include/cpython/bytesobject.h',
    'Include/internal/pycore_bytesobject.h',
]
LIMITED_HEADERS = ['Include/bytesobject.h']


@dc.dataclass
class Sources:
    srcdir: str
    spec: str = 'Objects/pyspec/bytesobject.py'
    cfile: str = 'Objects/bytesobject.c'
    docs: str = 'Doc/c-api/bytes.rst'
    headers: list = dc.field(default_factory=lambda: list(HEADERS))
    refcounts: str = 'Doc/data/refcounts.dat'
    stable_abi_toml: str = 'Misc/stable_abi.toml'
    stable_abi_dat: str = 'Doc/data/stable_abi.dat'

    def path(self, rel):
        return os.path.join(self.srcdir, rel)


@dc.dataclass
class Disconnect:
    source: str             # headers, c, docs, refcounts, stable_abi,
                            # behavior, catalog
    name: str
    what: str
    detail: str
    locations: tuple = ()

    @property
    def key(self):
        return f'{self.source}:{self.name}:{self.what}'


def _all_header_protos(srcdir):
    """{name: Proto} over every header under Include/ (first wins)."""
    out = {}
    include = os.path.join(srcdir, 'Include')
    for dirpath, dirnames, filenames in os.walk(include):
        dirnames.sort()
        for filename in sorted(filenames):
            if filename.endswith('.h'):
                path = os.path.join(dirpath, filename)
                rel = os.path.relpath(path, srcdir)
                for name, proto in parse_header(path, rel).items():
                    out.setdefault(name, proto)
    return out


class Checker:
    def __init__(self, sources):
        self.sources = sources
        src = sources.path
        self.spec_path = src(sources.spec)
        self.catalog = load_catalog(self.spec_path)
        self.headers = {}
        for rel in sources.headers:
            for name, proto in parse_header(src(rel), rel).items():
                self.headers.setdefault(name, proto)
        self.all_headers = _all_header_protos(sources.srcdir)
        self.cdefs = parse_c_definitions(src(sources.cfile), sources.cfile)
        self.docs = parse_docs(src(sources.docs), sources.docs)
        self.refcounts = parse_refcounts(src(sources.refcounts))
        self.stable_abi = parse_stable_abi_toml(src(sources.stable_abi_toml))
        self.stable_abi_dat = parse_stable_abi_dat(src(sources.stable_abi_dat))
        self.disconnects = []

    def spec_loc(self, func):
        return f'{self.sources.spec}:{func.lineno}'

    def add(self, source, name, what, detail, *locations):
        self.disconnects.append(
            Disconnect(source, name, what, detail, tuple(locations)))

    # -- signatures -----------------------------------------------------

    def compare_signature(self, source, func, proto, *, names=True):
        loc = (self.spec_loc(func), proto.location)
        if proto.returns != func.returns:
            self.add(source, func.name, 'return-type',
                     f'{proto.returns!r}, catalog says {func.returns!r}', *loc)
        types = [t for t, n in proto.params]
        mine = [p.ctype for p in func.params]
        if types != mine or proto.varargs != func.varargs:
            self.add(source, func.name, 'param-types',
                     f'({", ".join(types)}{", ..." if proto.varargs else ""})'
                     f', catalog says ({", ".join(mine)}'
                     f'{", ..." if func.varargs else ""})', *loc)
        if names and len(proto.params) == len(func.params):
            theirs = [n for t, n in proto.params]
            mine = [p.name for p in func.params]
            pairs = [(a, b) for a, b in zip(theirs, mine)
                     if a is not None and a != b]
            if pairs:
                self.add(source, func.name, 'param-names',
                         ', '.join(f'{a} (catalog: {b})' for a, b in pairs),
                         *loc)

    # -- checks -----------------------------------------------------------

    def check_catalog(self):
        exported = {n: p for n, p in self.cdefs.items()
                    if not p.static and is_capi_name(n)}
        for name, proto in sorted(exported.items()):
            if name not in self.catalog:
                self.add('catalog', name, 'missing-stub',
                         f'defined in C, no entry in {self.sources.spec}',
                         proto.location)
        for name, func in sorted(self.catalog.items()):
            proto = self.cdefs.get(name)
            if proto is None:
                self.add('catalog', name, 'not-in-c',
                         f'no definition in {self.sources.cfile}',
                         self.spec_loc(func))
            elif proto.static:
                self.add('catalog', name, 'static-in-c',
                         'the C definition is static', self.spec_loc(func),
                         proto.location)

    def check_c(self):
        for name, func in sorted(self.catalog.items()):
            proto = self.cdefs.get(name)
            if proto is not None:
                self.compare_signature('c', func, proto)

    def check_headers(self):
        for name, func in sorted(self.catalog.items()):
            proto = self.headers.get(name)
            if proto is None:
                other = self.all_headers.get(name)
                if other is None:
                    self.add('headers', name, 'not-declared',
                             'no prototype in Include/', self.spec_loc(func))
                    continue
                self.add('headers', name, 'declared-elsewhere',
                         f'declared in {other.path}, not in '
                         f'{", ".join(self.sources.headers)}',
                         self.spec_loc(func), other.location)
                proto = other
            if func.public and not proto.exported:
                self.add('headers', name, 'not-exported',
                         'public name declared without PyAPI_FUNC',
                         proto.location)
            self.compare_signature('headers', func, proto)

    def check_docs(self):
        for name, func in sorted(self.catalog.items()):
            entry = self.docs.get(name)
            if entry is None:
                if func.public:
                    self.add('docs', name, 'undocumented',
                             f'public function not in {self.sources.docs}',
                             self.spec_loc(func))
                elif func.doc:
                    self.add('docs', name, 'docstring-without-docs',
                             'catalog has a docstring, docs have no entry',
                             self.spec_loc(func))
                continue
            proto = entry.proto
            self.compare_signature('docs', func, proto)
            if func.doc is None:
                self.add('docs', name, 'no-docstring',
                         'documented, but the catalog entry has no docstring',
                         self.spec_loc(func), proto.location)
            elif func.doc != entry.body:
                self.add('docs', name, 'docstring-differs',
                         'catalog docstring differs from the documentation',
                         self.spec_loc(func), proto.location)
            text = entry.body
            for error in func.errors:
                if error == 'NULL' and '``NULL``' not in text:
                    self.add('docs', name, 'error-unstated',
                             'returns NULL on error; docs do not say so',
                             proto.location)
                elif error == -1 and '``-1``' not in text:
                    self.add('docs', name, 'error-unstated',
                             'returns -1 on error; docs do not say so',
                             proto.location)

    def check_refcounts(self):
        generated = self.refcounts_blocks()
        for name, func in sorted(self.catalog.items()):
            existing = self.refcounts.get(name)
            if existing is None:
                if name in self.docs:
                    self.add('refcounts', name, 'missing',
                             'documented, but no entry in refcounts.dat',
                             self.docs[name].proto.location)
                continue
            loc = f'{self.sources.refcounts}:{existing[0].lineno}'
            want = generated[name]
            have = [f'{name}:{e.ctype}:{e.name}:{e.refcount}:'
                    for e in existing]
            if [_ref_key(x) for x in have] == [_ref_key(x) for x in want]:
                continue
            ret_have, ret_want = _ref_key(have[0]), _ref_key(want[0])
            if ret_have != ret_want:
                self.add('refcounts', name, 'return',
                         f'{have[0]!r}, catalog implies {want[0]!r}',
                         self.spec_loc(func), loc)
            if [_ref_key(x) for x in have[1:]] != [_ref_key(x)
                                                  for x in want[1:]]:
                diffs = [f'{a!r} vs {b!r}' for a, b in
                         zip(have[1:], want[1:]) if _ref_key(a) != _ref_key(b)]
                if len(have) != len(want):
                    diffs.append(f'{len(have) - 1} params, catalog has '
                                 f'{len(want) - 1}')
                self.add('refcounts', name, 'params',
                         '; '.join(diffs) + ' (refcounts.dat vs catalog)',
                         self.spec_loc(func), loc)

    def check_stable_abi(self):
        limited = {}
        for rel in LIMITED_HEADERS:
            limited.update(parse_header(self.sources.path(rel), rel))
        toml = self.sources.stable_abi_toml
        dat = self.sources.stable_abi_dat
        for name, func in sorted(self.catalog.items()):
            info = self.stable_abi.get(name)
            in_dat = name in self.stable_abi_dat
            if info is None:
                if name in limited:
                    self.add('stable_abi', name, 'limited-header-not-in-abi',
                             f'declared in {limited[name].path} (limited '
                             f'API) but not in {toml}',
                             limited[name].location)
                if in_dat:
                    self.add('stable_abi', name, 'dat-not-toml',
                             f'in {dat} but not in {toml}',
                             f'{dat}:{self.stable_abi_dat[name][2]}')
                continue
            tloc = f'{toml}:{info["lineno"]}'
            if info['kind'] != 'function':
                self.add('stable_abi', name, 'kind',
                         f'listed as {info["kind"]}', tloc)
            if not info['abi_only'] and name not in limited:
                self.add('stable_abi', name, 'not-in-limited-header',
                         f'in the stable ABI but not declared in '
                         f'{", ".join(LIMITED_HEADERS)}', tloc)
            if not func.public and not info['abi_only']:
                self.add('stable_abi', name, 'private-name',
                         'underscore name in the limited API', tloc)
            if not in_dat and not info['abi_only']:
                self.add('stable_abi', name, 'toml-not-dat',
                         f'in {toml} but not in {dat} (regenerate)', tloc)
            elif in_dat and self.stable_abi_dat[name][1] != info['added']:
                self.add('stable_abi', name, 'dat-version',
                         f'{dat} says {self.stable_abi_dat[name][1]}, '
                         f'{toml} says {info["added"]}', tloc)

    def check_behavior(self):
        for name, func in sorted(self.catalog.items()):
            if not func.has_body or name not in self.docs:
                continue
            entry = self.docs[name]
            text = entry.body.lower()
            loc = (self.spec_loc(func), entry.proto.location)
            summary = behavior(self.spec_path, name)
            for cat, label in CATEGORY_LABELS.items():
                accepted = [t for t, c, _ in summary['types'] if c == cat]
                if not accepted:
                    continue
                if not any(k in text for k in CATEGORY_KEYWORDS[cat]):
                    self.add('behavior', name, f'{cat}-unstated',
                             f'{label} ({", ".join(accepted)}); '
                             f'the docs do not mention it', *loc)
            if summary['null'] and 'null' not in text:
                self.add('behavior', name, 'null-unstated',
                         f'NULL argument: {summary["null"]}; docs do not '
                         f'say', *loc)
            if func.runs_python and 'python code' not in text:
                calls = ', '.join(sorted(set(summary['python_calls'])))
                self.add('behavior', name, 'runs-python-unstated',
                         f'may run Python code via {calls}', *loc)

    def run(self):
        self.check_catalog()
        self.check_headers()
        self.check_c()
        self.check_docs()
        self.check_refcounts()
        self.check_stable_abi()
        self.check_behavior()
        return self.disconnects

    # -- refcounts.dat ------------------------------------------------------

    def refcounts_blocks(self):
        """{name: [line, ...]} the catalog implies, in refcounts.dat format.

        Parameter names are the catalog's (the documented names)."""
        return {name: refcounts_lines(func)
                for name, func in self.catalog.items()}

    def refcounts_diff(self, names=None):
        """Unified diff from refcounts.dat to what the catalog implies,
        for documented catalog functions (and any already listed)."""
        if names is None:
            names = sorted(n for n in self.catalog
                           if n in self.docs or n in self.refcounts)
        have, want = [], []
        for name in names:
            existing = self.refcounts.get(name, [])
            have += [f'{name}:{e.ctype}:{e.name}:{e.refcount}:{e.comment}'
                     for e in existing] + ([''] if existing else [])
            want += refcounts_lines(self.catalog[name]) + ['']
        return list(difflib.unified_diff(
            have, want, self.sources.refcounts, 'catalog', lineterm='', n=1))


def _ref_type(ctype):
    """refcounts.dat spelling of a normalized C type."""
    return ctype.replace(' *', '*')


def _ref_key(line):
    """Compare refcounts lines ignoring type spacing and the comment."""
    func, ctype, name, refcount, *_ = line.split(':') + ['']
    return func, ctype.replace(' ', ''), name, refcount


def refcounts_lines(func):
    """The refcounts.dat block for catalog entry *func*."""
    ref = {'new': '+1', 'borrowed': '0'}.get(func.ownership, '')
    lines = [f'{func.name}:{_ref_type(func.returns)}::{ref}:']
    for p in func.params:
        if p.is_object:
            ref = '-1' if p.steals else '0'
        elif p.ctype == 'PyObject **':
            ref = '0'
        else:
            ref = ''
        lines.append(f'{func.name}:{_ref_type(p.ctype)}:{p.name}:{ref}:')
    if func.varargs:
        lines.append(f'{func.name}::...::')
    return lines


# ---------------------------------------------------------------------------
# Behavior of a spec body, by exact argument type

CATEGORY_LABELS = {
    'identity': 'returned unchanged (same object, new reference)',
    'buffer': 'copied through the buffer protocol',
    'iterable': 'iterated; each item converted with __index__, '
                'must be in range(256)',
}
CATEGORY_KEYWORDS = {
    'identity': ('same object', 'unchanged', 'itself'),
    'buffer': ('buffer protocol',),
    'iterable': ('iterable', 'iterator', 'iterat'),
}


class _BytesSubclass(bytes):
    pass


def _gen():
    yield 0


def probe_types():
    """(label, type) pairs used to specialize a spec body."""
    import array
    return [
        ('bytes', bytes), ('bytes subclass', _BytesSubclass),
        ('bytearray', bytearray), ('memoryview', memoryview),
        ('array.array', array.array), ('list', list), ('tuple', tuple),
        ('str', str), ('int', int), ('bool', bool), ('float', float),
        ('dict', dict), ('set', set), ('range', range),
        ('generator', type(_gen())), ('list_iterator', type(iter([]))),
        ('NoneType', type(None)), ('object', object),
    ]


def _iterable(tp):
    return (getattr(tp, '__iter__', None) is not None
            or getattr(tp, '__getitem__', None) is not None)


def _outcomes(stmts, tp, param):
    """Reachable results of residual statements, in order: 'identity',
    C escape names, 'iter', or 'raise <Exc>'."""
    out = []
    for stmt in stmts:
        match stmt:
            case ast.Return(value=ast.Name(id=n)) if n == param:
                out.append('identity')
            case ast.Return(value=ast.Call() as call) if hasattr(
                    call, 'pyspec_specialization'):
                out.append('iter')  # a shared specialization has a loop
            case ast.Return(value=ast.Call(func=ast.Attribute(attr=attr))):
                out.append(attr)
            case ast.Return(value=ast.Name()):
                pass    # returns a local assigned by an escape below
            case ast.Raise(exc=ast.Call(func=ast.Attribute(attr=attr))):
                out.append(f'raise C.{attr}')
            case ast.Raise(exc=ast.Call(func=ast.Name(id=exc))):
                out.append(f'raise {exc}')
            case ast.If(body=body, orelse=orelse):
                out += _outcomes(body, tp, param) + _outcomes(orelse, tp,
                                                              param)
            case ast.For():
                out.append('iter')
            case ast.With(body=body):
                for s in body:
                    if isinstance(s, ast.Assign):
                        out.append(ast.unparse(s.value.func).removeprefix(
                            'C.'))
            case ast.Try(body=body, orelse=orelse):
                calls_iter = any(isinstance(n, ast.Call)
                                 and isinstance(n.func, ast.Name)
                                 and n.func.id == 'iter'
                                 for n in ast.walk(ast.Module(body, [])))
                if calls_iter and tp is not None and not _iterable(tp):
                    continue        # iter() raises TypeError: handled
                out += ['iter'] + _outcomes(orelse, tp, param)
    return out


def _category(outcomes):
    for o in outcomes:
        if o == 'identity':
            return 'identity'
        if o == '_PyBytes_FromBuffer':
            return 'buffer'
        if o == 'iter':
            return 'iterable'
    return 'rejected'


def behavior(spec_path, name):
    """Input categories of spec function *name* (one object parameter),
    derived by partially evaluating it for exact argument types."""
    spec = frontend.Spec.load(spec_path)
    source = spec.source
    param, = spec.params(name)
    types = []
    for label, tp in probe_types():
        residual = partial_eval.specialize(spec, name, {param: tp})
        outcomes = _outcomes(residual, tp, param)
        errors = [o for o in outcomes if o.startswith('raise')]
        types.append((label, _category(outcomes), errors[-1:]))
    residual = partial_eval.specialize(spec, name,
                                       {param: partial_eval.NULL})
    null = [o for o in _outcomes(residual, None, param)]
    null_text = {'raise C.PyErr_BadInternalCall':
                 'SystemError (PyErr_BadInternalCall)'}.get(
                     null[0] if null else '', ', '.join(null))
    return {'types': types, 'null': null_text,
            'python_calls': python_calls(ast.parse(source), name)}


# ---------------------------------------------------------------------------
# Report

SOURCE_TITLES = {
    'catalog': 'Catalog completeness',
    'headers': 'Headers',
    'c': 'C definitions',
    'docs': 'Docs (Doc/c-api)',
    'refcounts': 'Doc/data/refcounts.dat',
    'stable_abi': 'Stable ABI (Misc/stable_abi.toml, Doc/data/stable_abi.dat)',
    'behavior': 'Behavior (spec body) vs doc prose',
}


def report(checker, expected=None):
    """Markdown report of the checker's disconnects.

    *expected*: {key: comment} of known disconnects (the test's pinned
    list); new ones are marked NEW."""
    disconnects = checker.disconnects or checker.run()
    expected = expected or {}
    s = checker.sources
    out = [f'# C API catalog disconnects: {s.spec}', '',
           f'Catalog: {len(checker.catalog)} functions from `{s.spec}`, '
           f'compared with `{s.cfile}`, {", ".join(f"`{h}`" for h in s.headers)}, '
           f'`{s.docs}`, `{s.refcounts}`, `{s.stable_abi_toml}`, '
           f'`{s.stable_abi_dat}`.', '',
           f'{len(disconnects)} disconnects.', '']
    for source, title in SOURCE_TITLES.items():
        items = [d for d in disconnects if d.source == source]
        out += [f'## {title}', '']
        if not items:
            out += ['None found.', '']
            if source == 'stable_abi':
                abi = sorted(n for n in checker.catalog
                             if n in checker.stable_abi)
                out += [f'Checked: {len(abi)} catalog functions are in the '
                        f'stable ABI ({", ".join(f"`{n}`" for n in abi)}); '
                        f'each is declared in {", ".join(LIMITED_HEADERS)}, '
                        f'listed in `{s.stable_abi_dat}` with the same '
                        f'version, not abi_only, and no other catalog '
                        f'function is declared in the limited header.', '']
            continue
        for d in items:
            mark = '' if d.key in expected or not expected else ' **NEW**'
            locs = ', '.join(f'`{loc}`' for loc in d.locations)
            out.append(f'- `{d.name}` {d.what}{mark}: {d.detail} ({locs})')
            if expected.get(d.key):
                out.append(f'  - note: {expected[d.key]}')
        out.append('')
    stale = sorted(set(expected) - {d.key for d in disconnects})
    if stale:
        out += ['## Pinned but no longer found', '']
        out += [f'- `{k}`' for k in stale] + ['']

    out += ['## Catalog overview', '',
            '| function | facts | C definition | header | docs | '
            'refcounts.dat | stable ABI |', '|---|---|---|---|---|---|---|']
    for name, func in sorted(checker.catalog.items()):
        cdef = checker.cdefs.get(name)
        header = checker.headers.get(name) or checker.all_headers.get(name)
        doc = checker.docs.get(name)
        refs = checker.refcounts.get(name)
        abi = checker.stable_abi.get(name)
        facts = [func.ownership or func.returns,
                 'errors: ' + (', '.join(map(str, func.errors)) or 'none')]
        facts += [f'steals {p.name}' for p in func.params if p.steals]
        if func.runs_python:
            facts.append('runs Python')
        if func.has_body:
            facts.append('spec body')
        out.append(
            f'| `{name}` | {"; ".join(facts)} '
            f'| {cdef.location if cdef else "-"} '
            f'| {header.location if header else "-"} '
            f'| {doc.proto.location if doc else "-"} '
            f'| {f"{s.refcounts}:{refs[0].lineno}" if refs else "-"} '
            f'| {abi["added"] if abi else "-"} |')
    out.append('')

    out += ['## Behavior derived from spec bodies', '']
    for name, func in sorted(checker.catalog.items()):
        if not func.has_body:
            continue
        summary = behavior(checker.spec_path, name)
        out += [f'### {name} (`{checker.spec_loc(func)}`)', '',
                f'Derived facts: {", ".join(func.derived)}: returns '
                f'`{func.returns}` new reference, NULL on error, '
                f'runs Python: {func.runs_python}.', '',
                '| exact argument type | outcome |', '|---|---|']
        for label, cat, errors in summary['types']:
            text = CATEGORY_LABELS.get(cat, 'rejected: ' + ', '.join(
                e.removeprefix('raise ') for e in errors))
            out.append(f'| `{label}` | {text} |')
        out += ['', f'NULL argument: {summary["null"]}.', '',
                'Calls that may run Python code: '
                + ', '.join(f'`{c}`' for c in summary['python_calls']), '']
        if name in checker.docs:
            quoted = checker.docs[name].body.replace('\n', '\n> ')
            out += [f'Doc prose (`{checker.docs[name].proto.location}`):',
                    '', f'> {quoted}', '']

    documented_elsewhere = sorted(n for n in checker.docs
                                  if n not in checker.catalog)
    if documented_elsewhere:
        out += ['## Documented, not in the catalog', '',
                'Macros or static inline functions in headers (not defined '
                f'in `{s.cfile}`): '
                + ', '.join(f'`{n}`' for n in documented_elsewhere), '']

    diff = checker.refcounts_diff()
    out += ['## refcounts.dat implied by the catalog', '',
            'Diff from the current file to the lines the catalog implies '
            '(documented functions and those already listed):', '',
            '```diff', *diff, '```', '']
    return '\n'.join(out)

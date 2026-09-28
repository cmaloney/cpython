"""Disconnects between the code and the hand-written files describing it.

Each dimension below reads two or more places where the same facts are
written by hand and returns their disagreements as plain text lines, one
per disconnect, without line numbers.  Lib/test/test_pyspec_catalog.py
compares them with the checked-in baseline Tools/clinic/pyspec-baseline/
<dimension>.txt, which may only shrink (like Tools/build/check_warnings.py
and its .warningignore files): a new disconnect fails the test, and so
does a fixed one that is still listed.

capi        For each C API function of a type: the headers (Include/), the
            C definitions, Doc/c-api/*.rst, Doc/data/refcounts.dat,
            Misc/stable_abi.toml and Doc/data/threadsafety.dat.
docs        The ``.. method:: bytes.x(...)`` and ``.. class::`` lines of
            Doc/builtins/stdtypes.rst vs the runtime signatures (the
            spec's for the constructor: its ``__new__`` or ``__init__``).
slots       The slot tables of Doc/c-api/typeobj.rst vs slotdefs[] in
            Objects/typeobject.c.
docstrings  The same docstring written by hand in two places.
typeshed    Optional: typeshed's stdlib/builtins.pyi vs the signatures of
            the spec (the runtime's for methods without a spec).
c_calls     The C of each @native function vs its Python reference (the
            C checker of native_calls()): every call that may run Python
            code (by the token-level escape analysis of
            Tools/cases_generator/analyzer.py) is accounted for by the
            reference: a call of the same function, a calls() of the
            special method it invokes, or runs_python(); and the C calls
            the native functions the reference calls.

Signatures are compared by shape: the kind and optionality of each
parameter, its name unless it is positional-only, and its default when
both sides give one.  ``[, x]`` is an optional
positional-only parameter, and several signature lines (or @overloads)
are merged into the one signature that accepts all of them.
"""

from __future__ import annotations

import ast
import builtins
import dataclasses as dc
import inspect
import os
import re
import sys
import tomllib

from . import frontend, specfiles, subset


def spec_types(srcdir):
    """{type name: dict(cfile=..., prefixes=...)} of the builtin types a
    class of a core spec describes: their C file, and the prefixes of
    their C API (&PyBytes_Type: PyBytes and _PyBytes)."""
    out = {}
    for spec_path, c_file in specfiles.core_spec_files(srcdir):
        spec = frontend.Spec.load(spec_path)
        for cls_name in spec.classes:
            type_object = frontend.TYPE_OBJECTS.get(cls_name)
            if type_object is None or \
                    getattr(builtins, cls_name, None) is None:
                continue
            base = type_object.removeprefix('&').removesuffix('_Type')
            out[cls_name] = dict(
                cfile=os.path.relpath(c_file, srcdir).replace(os.sep, '/'),
                prefixes=(base, '_' + base))
    return out

BASELINE_DIR = 'Tools/clinic/pyspec-baseline'
DIMENSIONS = ('capi', 'docs', 'slots', 'docstrings', 'typeshed', 'c_calls')


def read_baseline(srcdir, dimension):
    path = os.path.join(srcdir, BASELINE_DIR, f'{dimension}.txt')
    with open(path, encoding='utf-8') as f:
        return {line for line in map(str.strip, f)
                if line and not line.startswith('#')}


def _read(srcdir, rel):
    """The text of *rel*, a path relative to *srcdir* with '/'."""
    with open(os.path.join(srcdir, rel), encoding='utf-8') as f:
        return f.read()


# -- C prototypes

@dc.dataclass
class Proto:
    returns: str
    types: list             # parameter C types; names are not compared
    varargs: bool
    path: str
    exported: bool = False  # PyAPI_FUNC
    static: bool = False

    def __str__(self):
        params = self.types + (['...'] if self.varargs else [])
        return f'{self.returns} ({", ".join(params) or "void"})'

    def same_types(self, other):
        return (self.returns, self.types, self.varargs) == (
            other.returns, other.types, other.varargs)


def normalize_ctype(text):
    """'const char*' -> 'const char *'."""
    stars = text.count('*')
    base = ' '.join(text.replace('*', ' ').split())
    return f'{base} {"*" * stars}' if stars else base


TYPE_WORDS = frozenset({
    'void', 'char', 'short', 'int', 'long', 'float', 'double', 'signed',
    'unsigned', 'const', 'size_t', 'Py_ssize_t', 'va_list', 'PyObject',
    'Py_UCS4', 'Py_hash_t',
})


def split_params(text):
    """(C types, varargs) of a C parameter list; names are dropped."""
    text = ' '.join(text.split())
    if text in ('', 'void'):
        return [], False
    types, varargs = [], False
    for part in text.split(','):
        part = re.sub(r'\bPy_UNUSED\((\w+)\)', r'\1', part.strip())
        if part == '...':
            varargs = True
            continue
        m = re.fullmatch(r'(.*?[\s*])(\w+)', part)
        if m and m.group(2) not in TYPE_WORDS and m.group(1).strip():
            part = m.group(1)
        types.append(normalize_ctype(part))
    return types, varargs


def strip_comments(text):
    """Blank out C comments, keeping line numbers."""
    def blank(m):
        return re.sub(r'[^\n]', ' ', m.group(0))
    return re.sub(r'//[^\n]*', blank,
                  re.sub(r'/\*.*?\*/', blank, text, flags=re.S))


_PROTO_RE = re.compile(
    r'(?:(?P<api>PyAPI_FUNC)\(\s*(?P<ret>[^)]*?)\s*\)|^\s*extern\s+'
    r'(?P<eret>[\w\s*]+?))\s*\b(?P<name>\w+)\s*\((?P<params>[^;{]*?)\)'
    r'\s*(?:Py_GCC_ATTRIBUTE\(\(.*?\)\)\s*)?;', re.S | re.M)
_MACRO_RE = re.compile(r'^\s*#\s*define\s+(\w+)\(|'
                       r'^static inline [^;{(]*?\b(\w+)\(', re.M)


def parse_headers(srcdir):
    """({name: Proto}, {macro and static inline names}) of Include/."""
    protos, macros = {}, set()
    include = os.path.join(srcdir, 'Include')
    for dirpath, dirnames, filenames in os.walk(include):
        dirnames.sort()
        for filename in sorted(filenames):
            if not filename.endswith('.h'):
                continue
            path = os.path.join(dirpath, filename)
            rel = os.path.relpath(path, srcdir).replace(os.sep, '/')
            text = strip_comments(_read(srcdir, rel))
            for m in _PROTO_RE.finditer(text):
                types, varargs = split_params(m['params'])
                protos.setdefault(m['name'], Proto(
                    normalize_ctype(m['ret'] or m['eret']), types, varargs,
                    rel, exported=bool(m['api'])))
            macros.update(a or b for a, b in _MACRO_RE.findall(text))
    return protos, macros


_DEF_RE = re.compile(r'^(?:[A-Za-z_][\w \t*]*?[ \t*])?(?P<name>_?Py\w+)\(',
                     re.M)


def parse_c_definitions(srcdir, rel):
    """{name: Proto} of the Py*/_Py* functions defined in a C file,
    including the generated files it includes from clinic/."""
    text = strip_comments(_read(srcdir, rel))
    out = {}
    for m in _DEF_RE.finditer(text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            depth += {'(': 1, ')': -1}.get(text[i], 0)
            i += 1
        if not text[i:].lstrip().startswith('{'):
            continue
        head = m.group(0)[:-1 - len(m['name'])].strip()
        if not head:        # the return type is on the previous line
            end = text.rfind('\n', 0, m.start())
            head = text[text.rfind('\n', 0, end) + 1:end].strip()
        if not head or head.startswith(('#', '}', ';')) or '=' in head:
            continue
        static = bool(re.search(r'\bstatic\b|Py_LOCAL', head))
        ret = re.sub(r'\bstatic\b|\binline\b', '', head).strip()
        ret = re.sub(r'^Py_LOCAL(?:_INLINE)?\((.*)\)$', r'\1', ret)
        types, varargs = split_params(text[m.end():i - 1])
        out[m['name']] = Proto(normalize_ctype(ret), types, varargs, rel,
                               static=static)
    for inc in re.findall(r'#include "(clinic/[^"]+)"', text):
        inc = f'{rel.rpartition("/")[0]}/{inc}'
        if os.path.exists(os.path.join(srcdir, inc)):
            for name, proto in parse_c_definitions(srcdir, inc).items():
                out.setdefault(name, proto)
    return out


def parse_capi_docs(srcdir):
    """{name: Proto} of the ``.. c:function::`` lines of Doc/c-api/."""
    out = {}
    docdir = os.path.join(srcdir, 'Doc', 'c-api')
    for filename in sorted(os.listdir(docdir)):
        if not filename.endswith('.rst'):
            continue
        rel = f'Doc/c-api/{filename}'
        for sig in re.findall(r'^\s*\.\. c:function:: (.*)$',
                              _read(srcdir, rel), re.M):
            m = re.fullmatch(r'(.*?[\s*])(\w+)\((.*)\)', sig.strip())
            if m:
                types, varargs = split_params(m[3])
                out.setdefault(m[2], Proto(normalize_ctype(m[1]), types,
                                           varargs, rel))
    return out


def _data_lines(srcdir, rel):
    """Fields of the non-comment lines of a Doc/data/*.dat file."""
    for line in _read(srcdir, rel).splitlines():
        if line.strip() and not line.startswith('#'):
            yield [field.strip() for field in line.split(':')]


def parse_refcounts(srcdir):
    """{function: Proto} of Doc/data/refcounts.dat (C types only)."""
    out = {}
    for func, ctype, name, *_ in _data_lines(
            srcdir, 'Doc/data/refcounts.dat'):
        proto = out.setdefault(func, Proto('', [], False,
                                           'Doc/data/refcounts.dat'))
        if ctype == '' and name == '...':
            proto.varargs = True
        elif name:
            proto.types.append(normalize_ctype(ctype))
        else:
            proto.returns = normalize_ctype(ctype)
    return out


# -- Dimension: C API

def capi(srcdir):
    headers, macros = parse_headers(srcdir)
    docs = parse_capi_docs(srcdir)
    refcounts = parse_refcounts(srcdir)
    threadsafety = {f[0] for f in _data_lines(
        srcdir, 'Doc/data/threadsafety.dat')}
    with open(os.path.join(srcdir, 'Misc', 'stable_abi.toml'), 'rb') as f:
        stable_abi = tomllib.load(f)['function']
    out = []
    for tp, config in spec_types(srcdir).items():
        cfile = config['cfile']
        cdefs = {n: p for n, p in parse_c_definitions(srcdir, cfile).items()
                 if not p.static}
        listed = set(docs) | set(refcounts) | threadsafety | set(stable_abi)
        names = set(cdefs) | {n for n in listed
                              if n.startswith(config['prefixes'])}

        def add(name, message):
            out.append(f'{name}: {message}')

        for name in sorted(names):
            cdef = cdefs.get(name)
            header = headers.get(name)
            doc = docs.get(name)
            declared = header is not None or name in macros
            public = not name.startswith('_')
            if not declared:
                where = cfile if cdef else 'the docs or Doc/data'
                add(name, f'in {where} but not declared in Include/')
            if cdef and header:
                if public and not header.exported:
                    add(name, f'declared without PyAPI_FUNC in {header.path}')
                if not cdef.same_types(header):
                    add(name, f'{header.path} says {header}, {cfile} says '
                              f'{cdef}')
            # Doc/c-api
            if (cdef and header and public and doc is None
                    and '/internal/' not in header.path):
                add(name, 'not documented in Doc/c-api')
            if doc and header and not doc.same_types(header):
                add(name, f'{doc.path} says {doc}, {header.path} says '
                          f'{header}')
            # Doc/data/refcounts.dat: Sphinx renders "Return value: New
            # reference" from it.
            ref = refcounts.get(name)
            if doc and ref is None and doc.returns == 'PyObject *':
                add(name, 'returns PyObject * but has no entry in '
                          'Doc/data/refcounts.dat')
            proto = header or doc
            if ref and proto and not ref.same_types(proto):
                add(name, f'Doc/data/refcounts.dat says {ref}, '
                          f'{proto.path} says {proto}')
            # Misc/stable_abi.toml
            limited = (header is not None and header.exported
                       and '/cpython/' not in header.path
                       and '/internal/' not in header.path)
            abi = stable_abi.get(name)
            if abi and not abi.get('abi_only') and not limited:
                add(name, 'in Misc/stable_abi.toml but not declared in a '
                          'limited API header')
            if limited and public and not abi:
                add(name, f'declared in the limited API ({header.path}) '
                          f'but not in Misc/stable_abi.toml')
            # Doc/data/threadsafety.dat
            if doc and name not in threadsafety:
                add(name, 'documented but has no entry in '
                          'Doc/data/threadsafety.dat')
            if name in threadsafety and not doc:
                add(name, 'in Doc/data/threadsafety.dat but not documented '
                          'with .. c:function::')
    return sorted(out)


# -- Signatures

UNKNOWN = object()          # a default with no Python value (NULL, ...)


@dc.dataclass
class Param:
    name: str
    kind: str               # 'P' (positional-only), 'PK', 'K', '*', '**'
    optional: bool = False
    default: object = UNKNOWN

    def __str__(self):
        if self.kind in ('*', '**'):
            return self.kind + self.name
        if not self.optional:
            return self.name
        value = '?' if self.default is UNKNOWN else repr(self.default)
        return f'{self.name}={value}'


def render(params):
    """``(a, b=?, /, c=1, *, d)``: ``=?`` is optional with no known
    default."""
    parts = []
    for i, p in enumerate(params):
        if p.kind == 'K' and (i == 0 or params[i - 1].kind in ('P', 'PK')):
            parts.append('*')
        parts.append(str(p))
        if p.kind == 'P' and (i + 1 == len(params)
                              or params[i + 1].kind != 'P'):
            parts.append('/')
    return f'({", ".join(parts)})'


def _default(text):
    try:
        value = ast.literal_eval(text)
    except (ValueError, SyntaxError):
        return UNKNOWN
    return UNKNOWN if value is Ellipsis else value


def parse_signature(text):
    """[Param] of a signature text: ``(sub[, start[, end]], /)``,
    ``($self, /, sep=None)``, ``(*, bytes_per_sep=1)``."""
    text = text.strip()
    if text.startswith('('):
        text = text[1:text.rindex(')')]
    items, current, depth, quote, paren = [], [], 0, None, 0
    item_depth, brackets = 0, False
    for c in text + ',':
        if quote:
            current.append(c)
            quote = None if c == quote else quote
        elif c in '\'"':
            quote = c
            current.append(c)
        elif c in '[]' and not paren:
            depth += 1 if c == '[' else -1
            brackets = True
        elif c in '({':
            paren += 1
            current.append(c)
        elif c in ')}':
            paren -= 1
            current.append(c)
        elif c == ',' and not paren:
            item = ''.join(current).strip()
            if item:
                items.append((item, item_depth))
            current = []
        else:
            if not ''.join(current).strip() and not c.isspace():
                item_depth = depth
            current.append(c)
    params, kind = [], 'PK'
    for item, in_brackets in items:
        if item.startswith('$'):
            continue
        if item == '/':
            for p in params:
                p.kind = 'P' if p.kind == 'PK' else p.kind
        elif item == '*':
            kind = 'K'
        elif item.startswith('**'):
            params.append(Param(item[2:], '**', True))
        elif item.startswith('*'):
            params.append(Param(item[1:], '*', True))
            kind = 'K'
        else:
            name, eq, default = item.partition('=')
            params.append(Param(name.strip(), kind, bool(eq or in_brackets),
                                _default(default) if eq else UNKNOWN))
    if brackets:        # the bracket notation: positional-only
        for p in params:
            p.kind = 'P' if p.kind == 'PK' else p.kind
    return params


def signature_of_def(node, method=True):
    """[Param] of an ast.FunctionDef (a spec or a typeshed function)."""
    args = node.args
    positional = args.posonlyargs + args.args
    defaults = [None] * (len(positional) - len(args.defaults)) + args.defaults
    params = []
    for i, (arg, default) in enumerate(zip(positional, defaults)):
        kind = 'P' if i < len(args.posonlyargs) else 'PK'
        params.append(Param(arg.arg, kind, default is not None,
                            UNKNOWN if default is None
                            else _default(ast.unparse(default))))
    static = any(isinstance(d, ast.Name) and d.id == 'staticmethod'
                 for d in node.decorator_list)
    if method and not static:
        params = params[1:]
    if args.vararg:
        params.append(Param(args.vararg.arg, '*', True))
    for arg, default in zip(args.kwonlyargs, args.kw_defaults):
        params.append(Param(arg.arg, 'K', default is not None,
                            UNKNOWN if default is None
                            else _default(ast.unparse(default))))
    if args.kwarg:
        params.append(Param(args.kwarg.arg, '**', True))
    return params


def merge(forms):
    """The one signature accepting what any of *forms* accepts."""
    def positional(form):
        return [p for p in form if p.kind in ('P', 'PK')]
    merged = [dc.replace(p) for p in max(map(positional, forms), key=len)]
    for form in forms:
        pos = positional(form)
        keywords = {p.name: p for p in form if p.kind == 'K'}
        for i, m in enumerate(merged):
            p = pos[i] if i < len(pos) else keywords.get(m.name)
            if p is None:
                m.optional = True
                continue
            if p.kind != 'P':
                m.kind, m.name = 'PK', p.name
            m.optional |= p.optional
            if m.default is UNKNOWN:
                m.default = p.default
        for p in form:
            if p.kind in ('K', '*', '**') and p.name not in {
                    m.name for m in merged}:
                merged.append(dc.replace(p))
    for m in merged:
        if m.kind == 'K' and not all(m.name in {p.name for p in f}
                                     for f in forms):
            m.optional = True
    return merged


def same_shape(a, b):
    """True if the signatures agree, ignoring the names of positional-only
    parameters and defaults that one side does not give."""
    def canon(params):
        return ([p for p in params if p.kind in ('P', 'PK')],
                sorted((p for p in params if p.kind not in ('P', 'PK')),
                       key=lambda p: (p.kind, p.name)))
    for xs, ys in zip(canon(a), canon(b)):
        if len(xs) != len(ys):
            return False
        for p, q in zip(xs, ys):
            if (p.kind, p.optional) != (q.kind, q.optional):
                return False
            if p.kind in ('PK', 'K') and p.name != q.name:
                return False
            if UNKNOWN not in (p.default, q.default) \
                    and p.default != q.default:
                return False
    return True


def runtime_signature(tp, name):
    """[Param] of the runtime method, or None."""
    attr = getattr(tp, name, None)
    if name == '__new__':
        attr = tp.__init__ if tp.__init__ is not object.__init__ else attr
    text = getattr(attr, '__text_signature__', None)
    if not text or '*args' in text:
        return None
    return parse_signature(text)


def spec_signatures(srcdir, tp):
    """{method name: [Param]} of the spec of *tp*, or {} if it has none."""
    cfile = spec_types(srcdir)[tp]['cfile']
    path = frontend.spec_path(os.path.join(srcdir, cfile))
    spec = frontend.Spec.load(path)
    if spec is None or tp not in spec.classes:
        return {}
    out = {}
    for meth in spec.entries(tp):
        full = f'{tp}.{meth}'
        other, name = spec.declaration(full)
        node = other.functions[name]
        out[meth] = signature_of_def(node)
    return out


def public_methods(tp):
    return sorted(name for name, value in vars(tp).items()
                  if not name.startswith('_') and callable(value))


# -- Dimension: Doc/builtins/stdtypes.rst

_DIRECTIVE_RE = re.compile(r'^(?P<indent> *)\.\. (?P<kind>method|classmethod|'
                           r'staticmethod|class):: (?P<sig>.*)$')


def parse_stdtypes(text):
    """{'bytes.count': [form, ...]} of the method and class lines."""
    out = {}
    lines = text.splitlines()
    classes = []            # (indent, class name) of enclosing classes
    for i, line in enumerate(lines):
        m = _DIRECTIVE_RE.match(line)
        if not m:
            continue
        indent = len(m['indent'])
        classes = [(n, c) for n, c in classes if n < indent]
        column = line.index(':: ') + 3
        sigs = [m['sig']]
        for cont in lines[i + 1:]:
            if len(cont) - len(cont.lstrip()) != column or not cont.strip() \
                    or cont.lstrip().startswith(':'):
                break
            sigs.append(cont.strip())
        for sig in sigs:
            sm = re.fullmatch(r'([\w.]+)\((.*)\)', sig.strip())
            if not sm:
                continue
            name = sm[1]
            if m['kind'] == 'class':
                classes.append((indent, name))
                name = f'{name}.__new__'
            elif '.' not in name and classes:
                name = f'{classes[-1][1]}.{name}'
            out.setdefault(name, []).append(parse_signature(sm[2]))
    return out


def docs(srcdir):
    rel = 'Doc/builtins/stdtypes.rst'
    documented = parse_stdtypes(_read(srcdir, rel))
    out = []
    for tp_name in spec_types(srcdir):
        tp = getattr(builtins, tp_name)
        spec = spec_signatures(srcdir, tp_name)
        for meth in ['__new__'] + public_methods(tp):
            full = f'{tp_name}.{meth}'
            label = f'{tp_name}()' if meth == '__new__' else full
            forms = documented.get(full)
            if forms is None:
                out.append(f'{label}: not documented in {rel}')
                continue
            runtime = runtime_signature(tp, meth)
            source = 'runtime'
            # The constructor: the spec's __new__, else its __init__.
            ctor = [m for m in ('__new__', '__init__') if m in spec]
            if meth == '__new__' and ctor:
                runtime, source = spec[ctor[0]], 'spec'
            if runtime is None:
                out.append(f'{label}: no runtime signature to compare with '
                           f'{rel}')
                continue
            doc = merge(forms)
            if not same_shape(doc, runtime):
                out.append(f'{label}: {rel} {render(doc)} != {source} '
                           f'{render(runtime)}')
        for full in sorted(documented):
            meth = full.partition('.')[2]
            if full.startswith(f'{tp_name}.') and not hasattr(tp, meth):
                out.append(f'{full}: documented in {rel} but not a '
                           f'method')
    return sorted(out)


# -- Dimension: Doc/c-api/typeobj.rst vs slotdefs[]

def slots(srcdir):
    source = _read(srcdir, 'Objects/typeobject.c')
    start = source.index('static pytype_slotdef slotdefs[] = {')
    table = source[start:source.index('\n};', start)]
    in_slotdefs = set(re.findall(r'\b[A-Z]+SLOT[A-Z]*\(\s*(__\w+__)\s*,'
                                 r'\s*(\w+)', table))
    in_slotdefs = {(slot, name) for name, slot in in_slotdefs}
    rst = 'Doc/c-api/typeobj.rst'
    cells, slot = {}, None
    for line in _read(srcdir, rst).splitlines():
        line = line.strip()
        if not line.startswith('|'):
            if not line.startswith('+'):
                slot = None
            continue
        row = [c.strip() for c in line.strip('|').split('|')]
        m = re.search(r':c:member:`~Py\w+\.(\w+)`', row[0])
        if m:
            slot = m.group(1)
        elif row[0]:
            slot = None
        if slot and len(row) > 2:
            cells[slot] = cells.get(slot, '') + row[2]
    in_rst = {(slot, name) for slot, text in cells.items()
              for name in re.findall(r'__\w+?__', text.replace('\\', ''))}
    # Rows of attributes that are not slots (tp_name: __name__) are not
    # compared.
    known = {slot for slot, _ in in_slotdefs}
    out = [f'{slot}: {name} is in {rst}, not in slotdefs[]'
           for slot, name in in_rst - in_slotdefs if slot in known]
    out += [f'{slot}: {name} is in slotdefs[], not in {rst}'
            for slot, name in in_slotdefs - in_rst]
    return sorted(out)


# -- Dimension: docstrings written twice

def docstring_files(srcdir):
    """Every spec with a class, and its C file."""
    out = []
    for spec_path, c_file in specfiles.spec_files(srcdir):
        if not frontend.Spec.load(spec_path).classes:
            continue
        for path in (spec_path, c_file):
            if path is not None:
                out.append(os.path.relpath(path, srcdir).replace(os.sep, '/'))
    return sorted(out)


def _docstrings(srcdir, rel):
    """[(label, text)] of the docstrings of a C or spec file."""
    text = _read(srcdir, rel)
    if rel.endswith('.py'):
        out = []
        def visit(node, prefix):
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.ClassDef)):
                    doc = ast.get_docstring(child)
                    if doc:
                        out.append((f'{prefix}{child.name}', doc))
                    if isinstance(child, ast.ClassDef):
                        visit(child, f'{child.name}.')
        visit(ast.parse(text), '')
        return out
    out = []
    for name, literals in re.findall(
            r'PyDoc_STRVAR(?:_shared)?\(\s*(\w+)\s*,'
            r'((?:\s*"(?:[^"\\]|\\.)*")+)\s*\)', text, re.S):
        value = ''.join(s.encode().decode('unicode_escape')
                        for s in re.findall(r'"((?:[^"\\]|\\.)*)"',
                                            literals, re.S))
        out.append((name, value.partition('\n--\n\n')[2] or value))
    return out


def docstrings(srcdir):
    seen = {}
    for rel in docstring_files(srcdir):
        for label, text in _docstrings(srcdir, rel):
            key = ' '.join(inspect.cleandoc(text).split())
            seen.setdefault(key, []).append(f'{rel}:{label}')
    return sorted(' = '.join(sorted(where)) for where in seen.values()
                  if len(where) > 1)


# -- Dimension: typeshed (optional)

def _typeshed_class(tree, name):
    """{method: [[Param], ...]} of class *name* of a .pyi, taking the
    ``if sys.version_info ...`` branches that hold for this Python."""
    out = {}

    def visit(body):
        for node in body:
            if isinstance(node, ast.If):
                test = eval(compile(ast.Expression(node.test), '<pyi>',
                                    'eval'), {'sys': sys})
                visit(node.body if test else node.orelse)
            elif isinstance(node, ast.FunctionDef):
                out.setdefault(node.name, []).append(signature_of_def(node))
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == name:
            visit(node.body)
    return out


def typeshed(srcdir, typeshed_dir):
    with open(os.path.join(typeshed_dir, 'stdlib', 'builtins.pyi'),
              encoding='utf-8') as f:
        tree = ast.parse(f.read())
    out = []
    for tp_name in spec_types(srcdir):
        tp = getattr(builtins, tp_name)
        stubs = _typeshed_class(tree, tp_name)
        spec = spec_signatures(srcdir, tp_name)
        for meth in ['__new__'] + public_methods(tp):
            full = f'{tp_name}.{meth}'
            forms = stubs.get(meth)
            if forms is None and meth == '__new__':
                forms = stubs.get('__init__')
            if meth in spec:
                mine, source = spec[meth], 'spec'
            else:
                mine, source = runtime_signature(tp, meth), 'runtime'
            if forms is None or mine is None:
                continue    # inherited in typeshed (MutableSequence.clear)
            theirs = merge(forms)
            if not same_shape(theirs, mine):
                out.append(f'{full}: typeshed {render(theirs)} != {source} '
                           f'{render(mine)}')
    return sorted(out)


# -- Dimension: the native code of the @native functions (README.rst,
# "Checking a reference against its native code")

# C functions that run Python code only through a special method of an
# argument: the calls(x, "__name__") that accounts for them.  A call
# through a slot (``->nb_index(...)``, or a local set from one) is read
# from slotdefs[] (slots.py).
SLOT_CALLS = {'PyObject_GetBuffer': '__buffer__',
              'PyBuffer_Release': '__release_buffer__',
              'PyObject_Length': '__len__', 'PyObject_Size': '__len__',
              'PyObject_GetIter': '__iter__', 'PyIter_Next': '__next__'}

# Audited: C functions without a spec, outside the file checked, that run
# no Python code (errors, memory, exact builtin types; a fatal error does
# not return; Python code cannot define tp_alloc).
NO_PYTHON = {
    'PyErr_Format', 'PyErr_SetString', 'PyErr_NoMemory', 'PyErr_Clear',
    'PyErr_Occurred', 'PyErr_GivenExceptionMatches', '_PyErr_Format',
    '_PyErr_SetString', '_PyErr_Clear', '_PyThreadState_GET', 'memcpy',
    'memset', 'PyMem_Malloc', 'PyObject_Malloc', 'PyObject_Calloc',
    'PyObject_Realloc', '_PyObject_InitVar', '_PyReftracerTrack',
    '_Py_AddToAllObjects', '_Py_ForgetReference', '_Py_NewReferenceNoTotal',
    '_Py_atomic_load_ssize_relaxed', '_Py_atomic_store_ssize_relaxed',
    'PyLong_AsSsize_t', '_PyLong_IsNegative', '_PyLong_Copy',
    '_PyLong_FromUnsignedChar', '_PyType_LookupRef', '_PyObject_HasLen',
    'PyObject_CheckBuffer', 'PyBuffer_ToContiguous', 'PyBuffer_FillInfo',
    'PyByteArray_FromStringAndSize', 'PyByteArray_Resize',
    '_PyBytesWriter_GetData',
    '_Py_FatalErrorFormat', 'tp_alloc',
}


class NativeChecker:
    """Reads the native code of one file.  A Rust checker would read
    Objects/foo.rs the same way, with a ratchet dimension of its own."""

    def __init__(self, path: str) -> None:
        self.path = path

    def function(self, name: str) -> object | None:
        """The code of function *name* of the file, or None."""
        raise NotImplementedError

    def calls(self, code: object) -> set[str]:
        """The names of the functions *code* calls."""
        raise NotImplementedError

    def escaping_calls(self, code: object) -> set[str]:
        """Those that may run Python code (a call through a slot: the
        slot, ``tp_iternext``)."""
        raise NotImplementedError

    def runs_no_python(self, name: str) -> bool:
        """Whether a call of *name* was audited to run no Python code."""
        raise NotImplementedError

    def special_method(self, name: str) -> set[str]:
        """The special methods whose Python code a call of *name* runs, if
        that is all the Python code it runs."""
        raise NotImplementedError


# Comments, literals and preprocessor lines, blanked before lexing (the
# lexer of the cases generator does not know them all, and a macro body is
# not code).
_LITERALS = re.compile(r"""/\*.*?\*/|//[^\n]*|"(?:[^"\\]|\\.)*"|"""
                       r"""'(?:[^'\\]|\\.)*'|^[ \t]*\#(?:\\\n|[^\n])*""",
                       re.S | re.M)


def _blank(match):
    return '0' + '\n' * match.group().count('\n')


# A macro-style name (PyBytes_AS_STRING, Py_SET_SIZE, _PyBytes_CAST): an
# accessor, or the release of a reference (Py_DECREF): the functions
# checked release only references they made or whose object their caller
# keeps alive, so no finalizer runs.
_ACCESSOR = re.compile(r'_?[A-Za-z]+_[A-Z0-9_]+')

_C_KEYWORDS = {'if', 'while', 'for', 'switch', 'return', 'sizeof',
               'defined', '_Alignof', 'alignof'}


class CChecker(NativeChecker):
    """The checker of a C file (or header): the token-level escape
    analysis of the cases generator (Tools/cases_generator/analyzer.py,
    escaping_call_in_simple_stmt()) on the tokens of its lexer."""

    def __init__(self, path: str) -> None:
        super().__init__(path)
        tools = os.path.join(specfiles.srcdir(), 'Tools', 'cases_generator')
        sys.path.insert(0, tools)
        try:
            import analyzer, lexer, parsing
        finally:
            sys.path.remove(tools)
        self.analyzer, self.lexer, self.parsing = analyzer, lexer, parsing
        with open(path, encoding='utf-8') as f:
            self.text = _LITERALS.sub(_blank, f.read())
        self.dunders: dict[str, set[str]] = {}
        from . import slots
        for slotdef in slots.slotdefs():
            self.dunders.setdefault(slotdef.slot, set()).add(slotdef.name)
        self.dunders['tp_descr_get'] = {'__get__'}

    def function(self, name):
        """The tokens of the body of the C function *name*, or None."""
        # Its name, after its return type (on this line or the one before),
        # then its parameters and ``{``.
        text = self.text
        for match in re.finditer(rf'^[^;{{}}()=\n]*?\b{name}\(', text,
                                 re.M):
            parens, depth, body = 0, 0, []
            for tkn in self.lexer.tokenize(text[match.end() - len(name)
                                                - 1:]):
                if not body and parens == 0 and tkn.kind not in (
                        'IDENTIFIER', 'LPAREN', 'LBRACE'):
                    break           # a declaration or a call
                parens += {'LPAREN': 1, 'RPAREN': -1}.get(tkn.kind, 0)
                depth += {'LBRACE': 1, 'RBRACE': -1}.get(tkn.kind, 0)
                if depth or body:
                    body.append(tkn)
                if body and not depth:
                    return body
        return None

    def calls(self, code):
        return {tkn.text for tkn, after in zip(code, code[1:])
                if tkn.kind == 'IDENTIFIER' and after.kind == 'LPAREN'
                and tkn.text not in _C_KEYWORDS}

    def escaping_calls(self, code):
        """The calls the escape analysis reports in *code*: the names
        called, with a call through a slot as the slot."""
        body = code
        aliases = {}
        for i, tkn in enumerate(body[:-3]):
            # x = ... ->slot ...; : a local set from a slot.
            if tkn.kind == 'IDENTIFIER' and body[i + 1].kind == 'EQUALS':
                for j in range(i + 2, len(body) - 1):
                    if body[j].kind == 'SEMI':
                        break
                    if (body[j].kind == 'ARROW'
                            and body[j + 1].text in self.dunders):
                        aliases[tkn.text] = body[j + 1].text
        names = set()
        skip = 0            # the end of an assert(...): a check, not code
        for i, (tkn, after) in enumerate(zip(body, body[1:])):
            if i < skip:
                continue
            if tkn.text == 'assert':
                depth = 0
                for skip in range(i + 1, len(body)):
                    depth += {'LPAREN': 1, 'RPAREN': -1}.get(
                        body[skip].kind, 0)
                    if depth == 0:
                        break
                continue
            if (tkn.kind != 'IDENTIFIER' or after.kind != 'LPAREN'
                    or _ACCESSOR.fullmatch(tkn.text)):
                continue
            found = {}
            self.analyzer.escaping_call_in_simple_stmt(
                self.parsing.SimpleStmt([tkn, after]), found)
            if found:
                names.add(aliases.get(tkn.text, tkn.text))
        return names

    def runs_no_python(self, name):
        return name in NO_PYTHON

    def special_method(self, name):
        return self.dunders.get(name, {SLOT_CALLS.get(name)}) - {None}


# The checker of each language, by the extension of the native file.
NATIVE_CHECKERS = {'.c': CChecker, '.h': CChecker}


def native_calls(srcdir, extensions):
    """The disconnects of the @native functions whose native file (the
    file their spec describes) has one of *extensions*."""
    from . import context
    specs = [frontend.Spec.load(path)
             for path, _ in specfiles.spec_files(srcdir)]
    contexts: dict[frontend.Spec, context.Context] = {}

    def reference_facts(name, spec=None):
        """The facts of @native function *name* (of *spec*, else of the
        spec defining it), for any arguments."""
        if spec is None:
            spec = next(s.resolve(name) for s in specs if s.resolve(name))[0]
        if spec not in contexts:
            contexts[spec] = context.Context(spec)
        return contexts[spec].analyzer(spec).reference_facts(name, {})

    native = {name for spec in specs for name in spec.native_functions()}
    out = []
    for spec in specs:
        rel = os.path.relpath(spec.filename, srcdir).replace(os.sep, '/')
        # Objects/pyspec/foo.py describes Objects/foo.c (or foo.h).
        base = rel.replace('/pyspec/', '/').removesuffix('.py')
        found = next((base + ext for ext in extensions
                      if os.path.exists(os.path.join(srcdir, base + ext))),
                     None)
        if found is None or not spec.native_functions():
            continue
        checker = NATIVE_CHECKERS[os.path.splitext(found)[1]](
            os.path.join(srcdir, found))
        for name in spec.native_functions():
            out += _check_native(spec, name, checker, found, rel, native,
                                 reference_facts)
    return sorted(out)


def _check_native(spec, name, checker, native_file, rel, native,
                  reference_facts):
    node = spec.functions[name]
    positional, keywords = spec.c_name(name)
    c_name = positional or next(iter(keywords.values()), name)
    where = f'{rel}: {name}'
    code = checker.function(c_name)
    if code is None:
        return [f'{where}: no function {c_name} in {native_file}']
    out = []
    called = set()
    specials = set()
    for call in ast.walk(node):
        match call:
            case ast.Call(func=ast.Name('calls'),
                          args=[_, ast.Constant(str() as special)]):
                specials.add(special)
            case ast.Call(func=ast.Name('len' | 'iter' as f),
                          args=[ast.Name()]):
                specials.add(f'__{f}__')
            case ast.Call(func=ast.Name(f)):
                called.add(f)
    # The calls of the native function, and of the functions of its file
    # it calls (read in turn) unless accounted for.
    todo, seen, calls = [code], set(), set()
    while todo:
        for callee in checker.escaping_calls(todo.pop()):
            calls.add(callee)
            if (callee in called or checker.runs_no_python(callee)
                    or 'runs_python' in called
                    or checker.special_method(callee) & specials
                    or callee in seen):
                continue
            seen.add(callee)
            if callee in native:
                # Its facts; whether its native code agrees is its own
                # check.
                if not reference_facts(callee).runs_python:
                    continue
                out.append(f'{where}: calls {callee}(), which may '
                           'run Python code, and its reference does '
                           'not')
            elif (inner := checker.function(callee)) is not None:
                todo.append(inner)
            else:
                what = ''.join(f'calls(x, "{d}") or ' for d in
                               sorted(checker.special_method(callee)))
                out.append(f'{where}: calls {callee}(), which may '
                           'run Python code: account for it with '
                           f'{what}runs_python()')
    # The native functions the reference calls: the native code calls
    # them, or a function of its file does (the reference describes what
    # it calls).
    todo, everything = [checker.function(c_name)], {c_name}
    while todo:
        for callee in checker.calls(todo.pop()) - everything:
            everything.add(callee)
            if (callee not in native
                    and (inner := checker.function(callee)) is not None):
                todo.append(inner)
    for callee in sorted(called & native - everything):
        out.append(f'{where}: its reference calls {callee}(), which its '
                   'native code does not')
    # A reference that cannot fail: the native code calls nothing that
    # can (a native function whose reference cannot fail cannot).
    def may_fail(callee):
        return callee not in native or reference_facts(callee).raises
    returns = subset.c_signature(node)[1] if '.' not in name \
        else 'void'
    failing = sorted(filter(may_fail, calls))
    if (returns != 'void' and not subset.is_struct(returns)
            and failing and not reference_facts(name, spec).raises):
        out.append(f'{where}: its reference cannot fail, but the C '
                   f'calls {", ".join(failing)}')
    return out


def c_calls(srcdir):
    """The disconnects of the @native functions implemented in C."""
    return native_calls(srcdir, ('.c', '.h'))

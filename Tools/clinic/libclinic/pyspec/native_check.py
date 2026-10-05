"""The native code of the functions with a Python reference vs the
references (@ac.stub(optimizer_info=True)).

The c_calls dimension of the ratchet (disconnects.py,
Lib/test/test_pyspec_catalog.py; Objects/pyspec/README.rst, "Checking a
reference against its native code").  The checker of the language of
the native file (NATIVE_CHECKERS, by extension) reads the native code of
each function with a reference, and _check_native() compares it with
the reference:

* every call that may run Python code is accounted for by the
  reference: a call of the same function, a calls() of the special
  method it invokes, or runs_python();
* the native code calls every native function the reference calls;
* a reference that cannot fail has native code that calls nothing that
  can.

What counts as a call that may run Python code, in C (CChecker):

* a call the escape analysis of the cases generator reports
  (Tools/cases_generator/analyzer.py, escaping_call_in_simple_stmt()),
  less the functions audited to run none (NO_PYTHON), plus those its
  list of non-escaping functions has but which do run Python code
  (ESCAPING: PyLong_AsLong() calls __index__);
* a call through a pointer, ``(*fn)(o)``, ``table[0](o)``,
  ``((unaryfunc)fn)(o)``: named by its expression, it may run anything
  unless audited in NO_PYTHON (a call through a slot, ``->tp_iternext(``,
  is the slot, whose special methods slotdefs[] gives);
* the calls in the body of a macro the file defines (expanded where it
  is used), and a call of another name the file gives a function
  (``#define A B``) is a call of that function; a macro of a header (an
  all-caps name such as ``PyBytes_AS_STRING``) is an accessor;
* the calls of the static functions of the file it calls, read in turn
  unless the reference accounts for the call;
* every definition of a function counts (``#ifdef``/``#else``
  variants): the escaping calls of all of them, and each must call the
  native functions the reference calls;
* a call in an ``assert()`` counts (a debug build runs it).

The release of a reference (RELEASES: ``Py_DECREF``, ``Py_CLEAR``,
``Py_SETREF``...) runs a finalizer only if it releases the last
reference.  Assumed: the functions checked release only references they
made or whose object their caller keeps alive, so no finalizer runs, and
the release itself is not a call that may run Python code; the calls in
its arguments are (``Py_SETREF(x, PyObject_Str(o))`` calls
PyObject_Str()).

``runs_python()`` in a reference accounts for every call of its native
code that may run Python code.  The facts of the reference already say
that a call of it may run any Python code, which a finer accounting
would not change; but facts are per argument types, and a runs_python()
on one path of the reference (an argument of an unknown type) does not
say that the C runs no Python code on the others: that is checked for
the inputs of HelperTest (test_pyspec_facts), where a debug build
aborts when Python code runs in a call whose facts say it runs none, not
here.
"""

from __future__ import annotations

import ast
import os
import re
import sys

from . import frontend, specfiles, subset


# C functions that run Python code only through a special method of an
# argument: the calls(x, "__name__") that accounts for them.  A call
# through a slot (``->nb_index(...)``, or a local set from one) is read
# from slotdefs[] (slots.py).
SLOT_CALLS = {'PyObject_GetBuffer': '__buffer__',
              'PyBuffer_Release': '__release_buffer__',
              'PyObject_Length': '__len__', 'PyObject_Size': '__len__',
              'PyObject_GetIter': '__iter__', 'PyIter_Next': '__next__'}

# Functions the cases generator lists as not escaping (NON_ESCAPING_
# FUNCTIONS: its uses of them run no Python code) that may run Python
# code in general, and the special method each one runs (None: any).
ESCAPING = {
    'PyLong_AsLong': '__index__',       # of an object that is not an int
    'PyCell_SwapTakeRef': None,         # releases the old contents
}

# Audited: C functions without a spec, outside the file checked, that run
# no Python code (errors, memory, exact builtin types; a fatal error does
# not return; Python code cannot define tp_alloc).  A call through a
# pointer is audited by its expression (``(*fn)``).
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
    'PyType_IsSubtype',         # the MRO of a type
}

# The release of a reference: see the module docstring.
RELEASES = {'Py_DECREF', 'Py_XDECREF', 'Py_CLEAR', 'Py_SETREF',
            'Py_XSETREF', 'Py_DecRef', 'Py_XDecRef', '_Py_DECREF_SPECIALIZED'}


class NativeChecker:
    """Reads the native code of one file.  A Rust checker would read
    Objects/foo.rs the same way, with a ratchet dimension of its own."""

    def __init__(self, path: str) -> None:
        self.path = path

    def functions(self, name: str) -> list[object]:
        """The code of each definition of function *name* in the file
        (one per conditional variant), or []."""
        raise NotImplementedError

    def function(self, name: str) -> object | None:
        """The code of the first definition of function *name*, or
        None."""
        return next(iter(self.functions(name)), None)

    def calls(self, code: object) -> set[str]:
        """The names of the functions *code* calls."""
        raise NotImplementedError

    def escaping_calls(self, code: object) -> set[str]:
        """Those that may run Python code (a call through a slot: the
        slot, ``tp_iternext``; through another pointer: its expression,
        ``(*fn)``)."""
        raise NotImplementedError

    def runs_no_python(self, name: str) -> bool:
        """Whether a call of *name* was audited to run no Python code."""
        raise NotImplementedError

    def special_method(self, name: str) -> set[str]:
        """The special methods whose Python code a call of *name* runs, if
        that is all the Python code it runs."""
        raise NotImplementedError


# Comments and literals, blanked before lexing, and preprocessor lines
# (the lexer of the cases generator does not know them all, and a macro
# body is not code where it is defined).
_COMMENTS = (r"""/\*.*?\*/|//[^\n]*|"(?:[^"\\]|\\.)*"|"""
             r"""'(?:[^'\\]|\\.)*'""")
_LITERALS = re.compile(_COMMENTS + r"""|^[ \t]*\#(?:\\\n|[^\n])*""",
                       re.S | re.M)
_COMMENTS = re.compile(_COMMENTS, re.S)
# A function-like macro the file defines: its name and its body.
_DEFINE = re.compile(r'^[ \t]*\#[ \t]*define[ \t]+(\w+)\(([^)]*)\)'
                     r'((?:\\\n|[^\n])*)', re.M)
# Another name of a function the file defines:
# ``#define PyUnstable_Long_IsCompact _PyLong_IsCompact``.
_ALIAS = re.compile(r'^[ \t]*\#[ \t]*define[ \t]+(\w+)[ \t]+([A-Za-z_]\w*)'
                    r'[ \t]*$', re.M)


def _blank(match):
    return '0' + '\n' * match.group().count('\n')


# A macro-style name (PyBytes_AS_STRING, Py_SET_SIZE, _PyBytes_CAST) of a
# header: an accessor.  The macros of the file are expanded, and the
# releases are RELEASES.
_ACCESSOR = re.compile(r'_?[A-Za-z]+_[A-Z0-9_]+')

_C_KEYWORDS = {'if', 'while', 'for', 'switch', 'return', 'sizeof',
               'defined', '_Alignof', 'alignof'}
# Words of the language of the cases generator its lexer makes keywords:
# in C they are names.
_DSL_WORDS = {'INST', 'OP', 'MACRO', 'LABEL', 'SPILLED'}
# The tokens of a C type name, in a cast.
_TYPE_KINDS = {'CHAR', 'CONST', 'DOUBLE', 'FLOAT', 'INT', 'LONG', 'SHORT',
               'SIGNED', 'STRUCT', 'UNION', 'UNSIGNED', 'VOID', 'VOLATILE',
               'ENUM', 'RESTRICT'}


def _is_name(tkn):
    return tkn.kind == 'IDENTIFIER' or tkn.kind in _DSL_WORDS


def _looks_like_type(name):
    """A typedef name, by CPython's conventions (PyObject, Py_ssize_t,
    size_t, Py_UCS4), rather than a variable (fn, func)."""
    return (name[0].isupper() or name.endswith('_t')
            or name.startswith(('Py', '_Py')))


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
            raw = f.read()
        self.text = _LITERALS.sub(_blank, raw)
        # The function-like macros of the file: name -> tokens of the body.
        self.macros: dict[str, list] = {}
        for match in _DEFINE.finditer(_COMMENTS.sub(' ', raw)):
            body = match.group(3).replace('\\\n', ' ')
            self.macros.setdefault(match.group(1), [
                tkn for tkn in lexer.tokenize(body) if tkn.kind != '\n'])
        # Other names of functions: ``#define A B``.
        self.aliases = dict(_ALIAS.findall(_COMMENTS.sub(' ', raw)))
        self.dunders: dict[str, set[str]] = {}
        from . import slots
        for slotdef in slots.slotdefs():
            self.dunders.setdefault(slotdef.slot, set()).add(slotdef.name)
        self.dunders['tp_descr_get'] = {'__get__'}

    def functions(self, name):
        """The tokens of the body of each definition of the C function
        *name* (the file's macros expanded)."""
        if not re.fullmatch(r'\w+', name):
            return []           # a call through a pointer
        # Its name, after its return type (on this line or the one before),
        # then its parameters and ``{``.
        text = self.text
        bodies = []
        for match in re.finditer(rf'^[^;{{}}()=\n]*?\b{name}\(', text,
                                 re.M):
            parens, depth, body = 0, 0, []
            for tkn in self.lexer.tokenize(text[match.end() - len(name)
                                                - 1:]):
                if not body and parens == 0 and tkn.kind not in (
                        'IDENTIFIER', 'LPAREN', 'LBRACE', *_DSL_WORDS):
                    break           # a declaration or a call
                parens += {'LPAREN': 1, 'RPAREN': -1}.get(tkn.kind, 0)
                depth += {'LBRACE': 1, 'RBRACE': -1}.get(tkn.kind, 0)
                if depth or body:
                    body.append(tkn)
                if body and not depth:
                    bodies.append(self.expand(body))
                    break
        return bodies

    def expand(self, tokens, seen=frozenset()):
        """*tokens* with the body of each macro of the file after its
        name (the arguments stay where they are)."""
        out = []
        for i, tkn in enumerate(tokens):
            out.append(tkn)
            if (tkn.text in self.macros and tkn.text not in seen
                    and i + 1 < len(tokens) and tokens[i + 1].kind == 'LPAREN'):
                out += self.expand(self.macros[tkn.text], seen | {tkn.text})
                # The body is a statement of its own.
                out.append(self.lexer.Token('', 'SEMI', ';', (0, 0),
                                            (0, 0)))
        return out

    def calls(self, code):
        return {self.aliases.get(tkn.text, tkn.text)
                for tkn, after in zip(code, code[1:])
                if _is_name(tkn) and after.kind == 'LPAREN'
                and tkn.text not in _C_KEYWORDS
                and tkn.text not in self.macros}

    def escaping_calls(self, code):
        """The calls the escape analysis reports in *code*: the names
        called, with a call through a slot as the slot, and through
        another pointer as its expression."""
        body = code
        aliases = {}
        for i, tkn in enumerate(body[:-3]):
            # x = ... ->slot ...; : a local set from a slot.
            if _is_name(tkn) and body[i + 1].kind == 'EQUALS':
                for j in range(i + 2, len(body) - 1):
                    if body[j].kind == 'SEMI':
                        break
                    if (body[j].kind == 'ARROW'
                            and body[j + 1].text in self.dunders):
                        aliases[tkn.text] = body[j + 1].text
        names = set()
        for i, (tkn, after) in enumerate(zip(body, body[1:])):
            if after.kind != 'LPAREN':
                continue
            if tkn.kind in ('RPAREN', 'RBRACKET'):
                callee = self.indirect_callee(body, i)
                if callee is not None:
                    names.add(callee)
                continue
            if not _is_name(tkn) or tkn.text in self.macros:
                continue
            if tkn.text in self.aliases:
                tkn = self.lexer.Token(tkn.filename, tkn.kind,
                                       self.aliases[tkn.text], tkn.begin,
                                       tkn.end)
            if tkn.text in ESCAPING:
                names.add(tkn.text)
                continue
            if tkn.text in RELEASES or (_ACCESSOR.fullmatch(tkn.text)
                                        and tkn.kind == 'IDENTIFIER'):
                continue
            found = {}
            if tkn.kind in _DSL_WORDS:
                found[tkn] = True       # a name such as op: not audited
            else:
                self.analyzer.escaping_call_in_simple_stmt(
                    self.parsing.SimpleStmt([tkn, after]), found)
            if found:
                names.add(aliases.get(tkn.text, tkn.text))
        return names

    def indirect_callee(self, body, i):
        """The callee of a call through a pointer whose expression ends
        at body[i] (``)`` or ``]``), or None if the parentheses are a cast
        or a condition: the slot, for ``(*tp->tp_iternext)``; else the
        expression."""
        close, open_ = body[i].kind, {'RPAREN': 'LPAREN',
                                      'RBRACKET': 'LBRACKET'}[body[i].kind]
        depth, start = 0, i
        for start in range(i, -1, -1):
            depth += {close: 1, open_: -1}.get(body[start].kind, 0)
            if depth == 0:
                break
        inner = body[start + 1:i]
        if close == 'RBRACKET':
            # table[0](o), self->table[i](o): the whole postfix
            # expression.
            while start > 0 and (_is_name(body[start - 1])
                                 or body[start - 1].kind in ('ARROW',
                                                             'PERIOD')):
                start -= 1
        else:
            before = body[start - 1] if start else None
            if before is not None and before.kind in (
                    'IF', 'WHILE', 'FOR', 'SWITCH', 'SIZEOF'):
                return None         # if (x) (void)f(); ...
            if inner and all(t.kind in _TYPE_KINDS or t.kind == 'TIMES'
                             or _is_name(t) for t in inner) \
                    and inner[0].kind != 'TIMES' and (
                        inner[-1].kind == 'TIMES'
                        or any(t.kind in _TYPE_KINDS for t in inner)
                        or len(inner) > 1
                        or _looks_like_type(inner[0].text)):
                return None         # a cast: (PyObject *)(x)
            if (len(inner) >= 2 and inner[-2].kind == 'ARROW'
                    and inner[-1].text in self.dunders):
                return inner[-1].text       # (*tp->tp_iternext)(o)
        text = ''
        for prev, tkn in zip([None, *body[start:i]], body[start:i + 1]):
            if prev is not None and _is_name(prev) and _is_name(tkn):
                text += ' '
            text += tkn.text
        return text

    def runs_no_python(self, name):
        return name in NO_PYTHON

    def special_method(self, name):
        if name in ESCAPING:
            return {ESCAPING[name]} - {None}
        return self.dunders.get(name, {SLOT_CALLS.get(name)}) - {None}


# The checker of each language, by the extension of the native file.
NATIVE_CHECKERS = {'.c': CChecker, '.h': CChecker}


def native_calls(srcdir, extensions):
    """The disconnects of the functions with a Python reference whose
    native file (the file their spec describes) has one of
    *extensions*."""
    from . import context
    specs = [frontend.Spec.load(path)
             for path, _ in specfiles.spec_files(srcdir)]
    contexts: dict[frontend.Spec, context.Context] = {}

    def reference_facts(name, spec=None):
        """The facts of the reference of function *name* (of *spec*,
        else of the spec defining it), for any arguments."""
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
    c_name = spec.native_c_name(name)
    where = f'{rel}: {name}'
    variants = checker.functions(c_name)
    if not variants:
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
    # The calls of the native function (every definition), and of the
    # functions of its file it calls (read in turn) unless accounted for.
    todo, seen, calls = list(variants), set(), set()
    while todo:
        for callee in sorted(checker.escaping_calls(todo.pop())):
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
            elif inner := checker.functions(callee):
                todo += inner
            else:
                what = ''.join(f'rt.calls(x, "{d}") or ' for d in
                               sorted(checker.special_method(callee)))
                out.append(f'{where}: calls {callee}(), which may '
                           'run Python code: account for it with '
                           f'{what}rt.runs_python()')
    # The native functions the reference calls: each definition of the
    # native code calls them, or a function of its file does (the
    # reference describes what it calls).
    for n, variant in enumerate(variants, 1):
        todo, everything = [variant], {c_name}
        while todo:
            for callee in checker.calls(todo.pop()) - everything:
                everything.add(callee)
                if callee not in native:
                    todo += checker.functions(callee)
        which = (f' (definition {n} of {len(variants)})'
                 if len(variants) > 1 else '')
        for callee in sorted(called & native - everything):
            out.append(f'{where}: its reference calls {callee}(), which '
                       f'its native code{which} does not')
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
    """The disconnects of the functions with a Python reference
    implemented in C."""
    return native_calls(srcdir, ('.c', '.h'))

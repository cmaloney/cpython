"""The C functions a spec class names as its methods.

A method that several types share is one C function of a template
header their C files include (Objects/stringlib/transmogrify.h,
ctype.h): the spec of each type names only that function,
``center = ac.stub("stringlib_center")``, and Argument Clinic reads the
rest from the C (find()):

* a clinic function of a local header the C file ``#include``s
  (``B.center as stringlib_center``, its parameters and docstring, in
  transmogrify.h): clinic's own BlockParser and DSLParser parse the
  header in a throwaway Clinic (clinic_functions()); its Function gives
  the entry of the method table (``STRINGLIB_CENTER_METHODDEF``), the
  calling convention and the docstring;
* a PyCFunction written by hand (``stringlib_isalnum`` in ctype.h): the
  calling convention is read from the parameters of its definition
  (``(PyObject *self, PyObject *Py_UNUSED(ignored))``: METH_NOARGS);
  where they do not decide it (``(PyObject *self, PyObject *arg)``:
  METH_O or METH_VARARGS) the spec gives it, ``ac.stub(METH_O="f")``.
  Such a function has no docstring in C: it is that of its model.

The model of such a function is the def of its name in the spec of the
header (Objects/stringlib/pyspec/transmogrify.py: ``def
stringlib_center(self, width, fillchar=b' ', /)``), a template like the
header: model.py runs it with B the class of the type that names it.
Its parameters must be those of the C (check_model()).
"""

from __future__ import annotations

import ast
import dataclasses as dc
import os
import re
from typing import TYPE_CHECKING, Any

from libclinic.errors import SpecError

if TYPE_CHECKING:
    from libclinic.function import Function
    from .frontend import Spec


# The calling conventions read from the parameters after self of a
# hand-written PyCFunction (normalised: one space, no parameter names
# but those that decide).
_CONVENTIONS = [
    (re.compile(r'PyObject \*Py_UNUSED\(\w+\)$'), 'METH_NOARGS'),
    (re.compile(r'PyObject \*const \*\w+, Py_ssize_t \w+$'),
     'METH_FASTCALL'),
    (re.compile(r'PyObject \*const \*\w+, Py_ssize_t \w+, PyObject \*\w+$'),
     'METH_FASTCALL|METH_KEYWORDS'),
    (re.compile(r'PyObject \*\w+, PyObject \*\w+$'),
     'METH_VARARGS|METH_KEYWORDS'),
]
# (``(PyObject *self, PyObject *arg)`` is METH_O or METH_VARARGS: the
# spec says which.)

_INCLUDE = re.compile(r'^\s*#\s*include\s+"([^"]+)"', re.M)


@dc.dataclass
class CMethod:
    """A C function that is a method of a type (see the module
    docstring)."""
    c_name: str
    # The header that defines it, and the line.
    header: str
    lineno: int
    # Its calling convention (``METH_FASTCALL``, ``METH_NOARGS``), or
    # None when its definition does not decide it (the spec gives it).
    flags: str | None
    # Clinic's Function, for a clinic function; None for one written by
    # hand.
    function: Function | None = None

    @property
    def methoddef(self) -> str:
        """The ``*_METHODDEF`` macro of a clinic function."""
        return f'{self.c_name.upper()}_METHODDEF'

    @property
    def doc_name(self) -> str:
        """The docstring variable of a clinic function."""
        return f'{self.c_name}__doc__'

    def clinic_doc(self) -> tuple[str, str | None]:
        """(__doc__, __text_signature__) of a clinic function."""
        assert self.function is not None
        doc = self.function.docstring
        signature, sep, text = doc.partition('\n--\n\n')
        if not sep:
            return doc, None
        return text, signature[len(self.function.name):]

    def where(self) -> str:
        return f'{self.header}:{self.lineno}'


def local_includes(c_file: str, text: str | None = None) -> list[str]:
    """The local headers *c_file* (its *text*, else read) includes
    (``#include "x.h"``, relative to its directory), in order, but for
    clinic's output (``clinic/``)."""
    if text is None:
        with open(c_file, encoding='utf-8') as f:
            text = f.read()
    directory = os.path.dirname(os.path.abspath(c_file))
    out = []
    for m in _INCLUDE.finditer(text):
        name = m.group(1)
        path = os.path.normpath(os.path.join(directory, name))
        if (name.split('/')[0] != 'clinic' and os.path.isfile(path)
                and path not in out):
            out.append(path)
    return out


_PARSED: dict[tuple[str, int, int], dict[str, CMethod]] = {}


def _key(path: str) -> tuple[str, int, int]:
    stat = os.stat(path)
    return (os.path.abspath(path), stat.st_mtime_ns, stat.st_size)


def clinic_functions(header: str) -> dict[str, CMethod]:
    """{C basename: CMethod} of the clinic functions of *header*, parsed
    once by clinic in a throwaway Clinic (no spec, nothing written)."""
    key = _key(header)
    if key in _PARSED:
        return _PARSED[key]
    with open(header, encoding='utf-8') as f:
        text = f.read()
    out: dict[str, CMethod] = {}
    from libclinic.block_parser import BlockParser
    if BlockParser('', _language(header)).find_start_re.search(text):
        from libclinic.app import Clinic
        language = _language(header)
        clinic = Clinic(language, filename=header, limited_capi=False,
                        verify=False)
        # The clinic blocks only: not the spec of the header.
        clinic._pyspec_read = True
        clinic.block_parser = BlockParser(text, language, verify=False)
        functions: list[tuple[Function, int]] = []
        for block in clinic.block_parser:
            if block.dsl_name:
                parser = clinic.get_parser(block.dsl_name)
                parser.parse(block)
                function = getattr(parser, 'function', None)
                if function is not None and not any(
                        function is f for f, _ in functions):
                    functions.append(
                        (function,
                         clinic.block_parser.block_start_line_number))
        for function, lineno in functions:
            if function.kind.new_or_init or function.kind.name in (
                    'GETTER', 'SETTER', 'SETTER_AND_DELETER'):
                continue
            templates = language.output_templates(function, clinic.codegen)
            m = re.search(r'\{c_basename\}\),?\s*([\w|]+),|'
                          r'\{c_basename\},\s*([\w|]+),',
                          templates['methoddef_define'])
            assert m is not None, templates['methoddef_define']
            flags = m.group(1) or m.group(2)
            out[function.c_basename] = CMethod(function.c_basename, header,
                                               lineno, flags, function)
    _PARSED[key] = out
    return out


def _language(header: str) -> Any:
    from libclinic.clanguage import CLanguage
    return CLanguage(header)


def hand_written(header: str, c_name: str) -> CMethod | None:
    """The PyCFunction *c_name* defined by hand in *header*, or None."""
    with open(header, encoding='utf-8') as f:
        text = f.read()
    m = re.search(rf'^(?:static\s+)?PyObject\s*\*\s*\n?{re.escape(c_name)}'
                  r'\s*\(([^)]*(?:\([^)]*\)[^)]*)*)\)\s*\{', text, re.M)
    if m is None:
        return None
    params = [' '.join(p.replace('*', ' *').split()).replace('* ', '*')
              for p in m.group(1).split(',')]
    rest = ', '.join(params[1:])
    flags = None
    for pattern, convention in _CONVENTIONS:
        if pattern.match(rest):
            flags = convention
            break
    lineno = text.count('\n', 0, m.start(1)) + 1
    return CMethod(c_name, header, lineno, flags)


def find(c_file: str, c_name: str, text: str | None = None
         ) -> CMethod | None:
    """C function *c_name* of the local headers *c_file* (its *text*,
    else read) includes: a clinic function, else one written by hand;
    None if none defines it."""
    for header in local_includes(c_file, text):
        found = clinic_functions(header).get(c_name)
        if found is None:
            found = hand_written(header, c_name)
        if found is not None:
            return found
    return None


# -- the model: the def named like the C function ----------------------------

def model_def(spec: Spec, method: CMethod
              ) -> tuple[Spec, ast.FunctionDef] | None:
    """(spec of the header, def) of the model of *method*: the def of its
    C name in the spec of its header, if any.  *spec* shares its loaded
    specs."""
    from .frontend import spec_path
    path = spec_path(method.header)
    if not os.path.exists(path):
        return None
    other = spec.load_spec(path)
    node = other.functions.get(method.c_name)
    return None if node is None else (other, node)


def _converter_names() -> dict[type, str]:
    from libclinic.converter import converters
    names: dict[type, str] = {}
    for name, cls in converters.items():
        names.setdefault(cls, name)
    return names


def clinic_def(method: CMethod) -> ast.FunctionDef:
    """The spec def of clinic function *method*: its parameters with
    their converter (``width: Py_ssize_t``) and default, and its text
    signature (@text_signature) and docstring; what the model parses
    arguments with."""
    import inspect
    from libclinic.converters import self_converter
    from libclinic import unspecified
    assert method.function is not None
    names = _converter_names()
    posonly, args, kwonly = [], [], []
    defaults, kw_defaults = [], []
    vararg = None
    for p in method.function.parameters.values():
        conv = p.converter
        if isinstance(conv, self_converter):
            posonly.append(ast.arg('self'))
            continue
        annotation = ast.Name(names.get(type(conv), 'object'), ast.Load())
        arg = ast.arg(p.name, annotation)
        default = None
        if p.default is not unspecified:
            try:
                default = ast.parse(conv.py_default, mode='eval').body
                ast.literal_eval(default)
            except (SyntaxError, ValueError, TypeError):
                default = ast.Name('NULL', ast.Load())
        match p.kind:
            case inspect.Parameter.POSITIONAL_ONLY:
                posonly.append(arg)
            case inspect.Parameter.POSITIONAL_OR_KEYWORD:
                args.append(arg)
            case inspect.Parameter.KEYWORD_ONLY:
                kwonly.append(arg)
                kw_defaults.append(default)
                continue
            case inspect.Parameter.VAR_POSITIONAL:
                vararg = arg
                continue
        if default is not None:
            defaults.append(default)
    doc, signature = method.clinic_doc()
    decorators = []
    if signature is not None:
        decorators.append(ast.Call(ast.Name('text_signature', ast.Load()),
                                   [ast.Constant(signature)], []))
    node = ast.FunctionDef(
        method.function.name,
        ast.arguments(posonly, args, vararg, kwonly, kw_defaults, None,
                      defaults),
        [ast.Expr(ast.Constant(doc)), ast.Expr(ast.Constant(...))],
        decorators, None, None, [])
    return ast.fix_missing_locations(node)


def _signature(node: ast.FunctionDef) -> list[tuple[str, str, str | None]]:
    """[(name, kind, default)] of the parameters of *node*."""
    args = node.args
    positional = args.posonlyargs + args.args
    defaults: list[ast.expr | None] = [None] * (
        len(positional) - len(args.defaults)) + list(args.defaults)
    out = [(a.arg, 'posonly' if i < len(args.posonlyargs) else 'pos',
            None if d is None else ast.unparse(d))
           for i, (a, d) in enumerate(zip(positional, defaults))]
    if args.vararg:
        out.append((args.vararg.arg, 'varargs', None))
    out += [(a.arg, 'kwonly', None if d is None else ast.unparse(d))
            for a, d in zip(args.kwonlyargs, args.kw_defaults)]
    if args.kwarg:
        out.append((args.kwarg.arg, 'varkw', None))
    return out


# The parameters after self of the model of a hand-written PyCFunction,
# by calling convention.
_MODEL_PARAMS = {
    'METH_NOARGS': '(self, /)',
    'METH_O': '(self, arg, /)',
    'METH_VARARGS': '(self, *args)',
    'METH_FASTCALL': '(self, *args)',
    'METH_VARARGS|METH_KEYWORDS': '(self, *args, **kwargs)',
    'METH_FASTCALL|METH_KEYWORDS': '(self, *args, **kwargs)',
}


def convention_def(method: CMethod) -> ast.FunctionDef:
    """A def with the parameters of the calling convention of
    hand-written *method*, for the model when the spec has none."""
    assert method.flags is not None
    source = f'def {method.c_name}{_MODEL_PARAMS[method.flags]}: ...'
    node = ast.parse(source).body[0]
    assert isinstance(node, ast.FunctionDef)
    return node


def check_model(spec: Spec, node: ast.FunctionDef, method: CMethod) -> None:
    """The model def *node* (in *spec*) of *method* has the parameters of
    the C: those of the clinic function, or of its calling convention."""
    wanted = clinic_def(method) if method.function is not None \
        else convention_def(method)
    have, want = _signature(node), _signature(wanted)
    if method.function is None:
        # Only the shape of a calling convention; names are free.
        have = [(kind, default) for _, kind, default in have]
        want = [(kind, default) for _, kind, default in want]
    if have != want:
        text = ast.unparse(wanted.args)
        raise SpecError(f"{method.c_name}: the model of the C function "
                        f"{method.c_name} ({method.where()}) takes its "
                        f"parameters: def {method.c_name}({text})",
                        filename=spec.filename, lineno=node.lineno)

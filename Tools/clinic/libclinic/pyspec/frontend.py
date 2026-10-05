"""Read a pyspec file: the Python side of Argument Clinic functions.

For Objects/foo.c the spec is Objects/pyspec/foo.py (the contributor
guide is Objects/pyspec/README.rst).  It is read with the ast module;
clinic never executes it.

A spec names the tooling by group, ``from libclinic.pyspec import ac,
rt, machine`` (``ac.object``, ``@ac.stub``, ``rt.NULL``), and the
functions of other specs by their module (``from Objects.pyspec import
abstract``, ``abstract.PyNumber_AsSsize_t(...)``).  Spec() normalises
``ac.X`` and ``rt.X`` to the name ``X``, and a call of a function of
another spec to its name (Qualified), so that the passes read names;
the text clinic reads (converters, defaults) is the source less these
qualifiers (_segment()).

Spec is one spec file: its top-level functions (C functions named like
the function), its classes, and per class the methods by "T.meth".  A
method is one of the kinds of method_kind():

* CLINIC: a clinic function.  Its one-line block in the C file
  (``bytes.split``, or ``@getter`` / ``T.attr`` for an ACCESSOR) is
  completed from the spec by complete_block(): the clinic decorators,
  parameter lines (converter as annotation, ``c_param='x'`` for ``name
  as x``) and docstring (clinic_input());
* SLOT: a dunder of slotdefs[] (slots.py), a C function with the slot's
  typedef; its @ac.stub(slot="f") names it (typeobj.py);
* PYCFUNCTION: a hand-written PyCFunction, ``@ac.stub(METH_O="f")``
  (pycfunction());
* SHARED: ``meth = ac.stub("f")``, the C function f of a header the C
  file includes (stringlib_center of transmogrify.h), its signature and
  docstring read from the C (c_method(), cfunctions.py); or ``meth =
  module.Class.meth``, a method another spec (or class) declares,
  possibly wrapped in ``ac.critical_section(...)`` or
  ``ac.stub(METH_NOARGS="f")(...)``.

What clinic outputs for a def is opt-in, by its decorator (Output,
output()): ``@ac.generate``, C generated from the body (implemented());
``@ac.stub``, C written by hand, whose body is ``...`` (nothing is known
of it, is_literal_stub()), its pure-Python implementation that only the
model runs (is_pure_python()), or, with ``optimizer_info=True``, its Python
reference, read for facts (is_native()); ``@ac.inline``, generated into
each caller (is_inline()).  A top-level def without one is a Python
helper of the model and the references (is_helper()); a method without
one is an error.  A class outputs its tables only with ``@ac.generate``
(class_output()).  A spec imports other specs by their path from the
source root (specfiles.import_root()).
"""


from __future__ import annotations

import ast
import builtins
import dataclasses as dc
import functools
import os
import re
import shlex
import sys

from collections.abc import Collection

from libclinic.errors import PYSPEC_README as README
from libclinic.errors import SpecError, SpecErrorKind
from . import builtin_types, cfunctions, marks, slots, specfiles, subset


TYPE_CTYPE = 'PyTypeObject *'

# Builtin types a spec class may describe, and their C type objects.
TYPE_OBJECTS = builtin_types.TYPE_OBJECTS

# Clinic decorators that are also Python's, written bare; the spec's own,
# which say what clinic outputs (Output).  Any other decorator is a clinic
# one (``@ac.critical_section``).
METHOD_DECORATORS = ('classmethod', 'staticmethod')
GENERATE, STUB, INLINE = 'generate', 'stub', 'inline'
SPEC_DECORATORS = (GENERATE, STUB, INLINE)

# The groups of names of the tooling a spec imports (``from
# libclinic.pyspec import ac, rt, machine``); ``ac.X`` and ``rt.X`` are
# normalised to the name X (Spec.__init__()).
GROUP_PACKAGE = 'libclinic.pyspec'
GROUPS = ('ac', 'rt', 'machine')
NORMALISED_GROUPS = ('ac', 'rt')
# The names of rt (rt.py): a spec writes them qualified.
RT_NAMES = ('NULL', 'PY_SSIZE_T_MAX', 'isinstance', 'iter', 'tp_name',
            'fqname', 'exact', 'unknown', 'calls', 'runs_python')
# Builtins with another meaning in rt: bare, they are Python's.
SHADOWED_BUILTINS = ('isinstance', 'iter')
# The options of @ac.generate on a class (ClassOutput).
CLASS_OPTIONS = ('prefix', 'doc', 'methods', 'slots')

# The clinic decorators of an accessor, repeated by its block in C.
ACCESSOR_DECORATORS = ('getter', 'setter')

# The calling conventions of a hand-written PyCFunction, and the
# parameters each takes (``**kwargs`` adds METH_KEYWORDS).
PYCFUNCTION_FLAGS = {
    'METH_NOARGS': '(self, /)',
    'METH_O': '(self, arg, /)',
    'METH_VARARGS': '(self, /, *args[, **kwargs])',
    'METH_FASTCALL': '(self, /, *args[, **kwargs])',
}

# The kinds of the methods of a spec class (method_kind()).
CLINIC, SLOT, PYCFUNCTION, SHARED, ACCESSOR = (
    'clinic', 'slot', 'pycfunction', 'shared', 'accessor')

# Where a line is written: (file, line number).
Location = tuple[str, int]


@dc.dataclass
class SpecParameter:
    name: str
    ctype: str
    optional: bool


@dc.dataclass
class SpecFunction:
    """The C signature of an implemented spec function."""
    # "PyBytes_FromObject", or "bytes.__new__" for a method.
    name: str
    path: str
    parameters: list[SpecParameter]
    # For a __new__: the Python name of its class.
    new_type: str | None = None


@dc.dataclass
class PyCFunctionEntry:
    """A hand-written PyCFunction of a method table
    (``@ac.stub(METH_O="f")``)."""
    c_function: str
    flags: str      # of its PyMethodDef: "METH_VARARGS | METH_KEYWORDS"


@dc.dataclass
class SpecBinding:
    """How clinic binds an implemented spec method to the clinic function
    of its block in the C file (DSLParser.bind_spec())."""
    c_basename: str
    # The C type of clinic's self (or class) parameter.
    self_ctype: str
    # The #if condition of the block, or ''.
    condition: str = ''


@dc.dataclass
class PyspecBindings:
    """What clinic learns from the C file for the C it generates from the
    spec: the bindings of the implemented methods ("bytes.__new__"), and
    the type object of each clinic class ("bytes": "&PyBytes_Type")."""
    functions: dict[str, SpecBinding] = dc.field(default_factory=dict)
    type_objects: dict[str, str] = dc.field(default_factory=dict)


def _beside(filename: str, directory: str, suffix: str) -> str:
    dirname, basename = os.path.split(filename)
    stem = os.path.splitext(basename)[0]
    return os.path.join(dirname, directory, stem + suffix)


def spec_path(filename: str) -> str:
    """Path of the spec file for the C file *filename*."""
    return _beside(filename, 'pyspec', '.py')


def output_path(filename: str) -> str:
    """Path of the C generated from the spec of the C file *filename*."""
    return _beside(filename, 'clinic', '_pyspec.c.h')


def docstring_of(body: list[ast.stmt]) -> str | None:
    """The docstring of a def or class with *body*, or None."""
    if (body and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)):
        return body[0].value.value
    return None


def _quote(word: str) -> str:
    """Quote *word* for a clinic decorator line (split with shlex)."""
    if shlex.quote(word) == word:
        return word
    return '"' + word.replace('\\', '\\\\').replace('"', '\\"') + '"'


def without_docstring(node: ast.FunctionDef) -> list[ast.stmt]:
    return node.body[1:] if docstring_of(node.body) is not None else node.body


def is_literal_stub(node: ast.FunctionDef) -> bool:
    """True if the body is only a docstring and/or ``...``."""
    body = without_docstring(node)
    return not body or (len(body) == 1 and isinstance(body[0], ast.Expr)
                        and isinstance(body[0].value, ast.Constant)
                        and body[0].value.value is Ellipsis)


@dc.dataclass
class Output:
    """What clinic outputs for a def: its ``@ac.generate``, ``@ac.stub``
    or ``@ac.inline`` (output())."""
    kind: str       # GENERATE, STUB or INLINE
    decorator: ast.expr
    # The C name (``@ac.stub("f")``), if not the default.
    name: str | None = None
    # {slot or METH_ flag: C name, or None for the default of the slot}:
    # ``@ac.stub(mp_length="f")``, ``@ac.stub(METH_O="f")``,
    # ``@ac.stub(slots=["mp_length", "sq_length"])``.
    keywords: dict[str, str | None] = dc.field(default_factory=dict)
    # ``@ac.stub(optimizer_info=True)``: the body is the Python reference of
    # the C, read for facts.
    optimizer_info: bool = False


def _string(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def parse_output(decorator: ast.expr, where: str = '') -> Output:
    """The Output of spec decorator *decorator* (normalised: ``stub``,
    ``stub(...)``); a SpecError if its arguments are not its options."""
    kind = decorator_name(decorator)
    assert kind in SPEC_DECORATORS
    out = Output(kind, decorator)
    if not isinstance(decorator, ast.Call):
        return out

    def error(node: ast.AST, message: str) -> SpecError:
        return SpecError.at(node, f"{where}{message}", SpecErrorKind.INVALID,
                            None)

    if kind == INLINE:
        raise error(decorator, "@ac.inline takes no arguments")
    if len(decorator.args) > 1 or any(_string(a) is None
                                      for a in decorator.args):
        raise error(decorator, f"@ac.{kind}(\"f\") takes one argument, the "
                    "C name, a string")
    if decorator.args:
        out.name = _string(decorator.args[0])
    for kw in decorator.keywords:
        if kind == GENERATE or kw.arg is None:
            raise error(kw, f"@ac.{kind}() of a def takes only the C name"
                        if kind == GENERATE else
                        "@ac.stub() takes the C name and keyword options")
        value = kw.value
        if kw.arg == 'optimizer_info':
            if not (isinstance(value, ast.Constant)
                    and isinstance(value.value, bool)):
                raise error(kw, "optimizer_info=True or optimizer_info=False")
            out.optimizer_info = value.value
        elif kw.arg == 'slots':
            items = (value.elts if isinstance(value, (ast.List, ast.Tuple))
                     else None)
            if not items or any(_string(e) is None for e in items):
                raise error(kw, "slots= is a list of slot names: "
                            "slots=[\"mp_length\", \"sq_length\"]")
            for e in items:
                out.keywords.setdefault(str(_string(e)), None)
        elif _string(value) is not None:
            out.keywords[kw.arg] = _string(value)
        else:
            raise error(kw, f"@ac.stub({kw.arg}=...): the C name, a string")
    return out


def output(node: ast.FunctionDef) -> Output | None:
    """The Output of *node*, or None when it has no spec decorator."""
    found = [d for d in node.decorator_list
             if decorator_name(d) in SPEC_DECORATORS]
    if not found:
        return None
    if len(found) > 1:
        raise SpecError.at(found[1], f"{node.name}: one of @ac.generate, "
                           "@ac.stub and @ac.inline", SpecErrorKind.INVALID,
                           None)
    cached = getattr(node, '_pyspec_output', None)
    if cached is None:
        cached = parse_output(found[0], f"{node.name}: ")
        node._pyspec_output = cached    # type: ignore[attr-defined]
    return cached


def _kind(node: ast.FunctionDef) -> str | None:
    found = output(node)
    return None if found is None else found.kind


def is_generated(node: ast.FunctionDef) -> bool:
    """``@ac.generate``: clinic generates the body as C."""
    return _kind(node) == GENERATE


def is_helper(node: ast.FunctionDef) -> bool:
    """A top-level def without a spec decorator: Python the model and
    the references may call, which clinic neither generates nor calls."""
    return output(node) is None


def is_pure_python(node: ast.FunctionDef) -> bool:
    """``@ac.stub`` with a body: C written by hand; the body is its
    pure-Python implementation, which only the model runs (model.py);
    for clinic and the facts it is ``...``."""
    found = output(node)
    return (found is not None and found.kind == STUB
            and not found.optimizer_info and not is_literal_stub(node))


def is_stub(node: ast.FunctionDef) -> bool:
    """``@ac.stub`` without ``optimizer_info=True``: C about which nothing is
    known (a call of it may do anything), whether its body is ``...`` or
    pure Python (is_pure_python())."""
    found = output(node)
    return found is not None and found.kind == STUB and not found.optimizer_info


def is_placeholder(node: ast.FunctionDef) -> bool:
    """True for ``def meth(self): ...``: only the place of a method whose
    signature depends on #if, which keeps its full clinic block in C."""
    args = node.args
    return (is_literal_stub(node) and docstring_of(node.body) is None
            and len(args.posonlyargs + args.args) == 1
            and not (args.vararg or args.kwonlyargs or args.kwarg))


def decorator_name(decorator: ast.expr) -> str | None:
    """``name`` for ``@name`` and ``@name(...)``."""
    if isinstance(decorator, ast.Call):
        decorator = decorator.func
    return decorator.id if isinstance(decorator, ast.Name) else None


def accessor_kind(node: ast.FunctionDef) -> str:
    """'getter' or 'setter' for an accessor, else ''."""
    for decorator in node.decorator_list:
        name = decorator_name(decorator)
        if name in ACCESSOR_DECORATORS:
            return name
    return ''


def has_decorator(node: ast.FunctionDef, name: str) -> bool:
    return any(decorator_name(d) == name for d in node.decorator_list)


def is_native(node: ast.FunctionDef) -> bool:
    """``@ac.stub(optimizer_info=True)``: C written by hand; the body is its
    Python reference, never compiled, read for facts."""
    found = output(node)
    return found is not None and found.kind == STUB and found.optimizer_info


def is_inline(node: ast.FunctionDef) -> bool:
    """``@ac.inline``: the body is generated into each caller
    (partial_eval.py), never a C function of its own."""
    return _kind(node) == INLINE


@dc.dataclass
class ClassOutput:
    """The tables clinic generates for a class with ``@ac.generate``
    (typeobj.py): its docstring (``<prefix>_doc``), its method table and
    its slot sub-tables."""
    prefix: str
    doc: bool = True
    methods: bool = True
    slots: bool = True


@dc.dataclass
class Shared:
    """``meth = [decorator(...)(]module.Class.meth[)]`` in a class, or
    ``meth = ac.stub("f")``: the C function f of a header the C file
    includes (c_function; see cfunctions.py)."""
    module: str | None
    cls: str
    meth: str
    lineno: int
    decorators: list[ast.expr] = dc.field(default_factory=list)
    # ``ac.stub("f")``: the C function f; ``ac.stub(METH_O="f")`` gives
    # its calling convention too; ``critical_section=True``: clinic calls
    # it in a critical section on self.
    c_function: str | None = None
    convention: str | None = None
    critical_section: bool = False


@functools.cache
def spec_classes() -> dict[type, Spec]:
    """{builtin type: Spec} of the classes of the tree that describe
    their whole type (Spec.describes_type(); builtin_types.TypeFacts)."""
    out = {}
    for path, _ in specfiles.spec_files():
        spec = Spec.load(path)
        assert spec is not None
        for name in spec.classes:
            tp = getattr(builtins, name, None)
            if isinstance(tp, type) and spec.describes_type(name):
                out[tp] = spec
    return out


def _stdlib(module: str) -> bool:
    """Whether *module* (``collections.abc``) is of the standard
    library."""
    return module.partition('.')[0] in sys.stdlib_module_names


# The decorators a shared method may have.
SHARED_DECORATORS = ('critical_section', STUB)


_DEFS: dict[tuple[str, int, int], frozenset[str]] = {}


def top_level_functions(path: str) -> frozenset[str]:
    """The names of the top-level defs of the spec at *path* (read with
    the ast module only: a spec imported by one it imports is fine)."""
    stat = os.stat(path)
    key = (os.path.abspath(path), stat.st_mtime_ns, stat.st_size)
    if key not in _DEFS:
        with open(path, encoding='utf-8') as f:
            tree = ast.parse(f.read(), path)
        _DEFS[key] = frozenset(node.name for node in tree.body
                               if isinstance(node, ast.FunctionDef))
    return _DEFS[key]


def group_aliases(tree: ast.Module) -> dict[str, str]:
    """{local name: group} of ``from libclinic.pyspec import ac, rt,
    machine`` (``as`` names included) in *tree*."""
    return {alias.asname or alias.name: alias.name
            for node in tree.body
            if isinstance(node, ast.ImportFrom)
            and node.module == GROUP_PACKAGE and node.level == 0
            for alias in node.names if alias.name in GROUPS}


def _bound_names(tree: ast.Module) -> set[str]:
    """The names *tree* binds anywhere: assigned, parameters, defs,
    classes, imports, loop and except targets."""
    names = set()
    for node in ast.walk(tree):
        match node:
            case ast.Name(id=name, ctx=ast.Store() | ast.Del()):
                names.add(name)
            case ast.arg(arg=name):
                names.add(name)
            case ast.FunctionDef(name=name) | ast.ClassDef(name=name):
                names.add(name)
            case ast.ExceptHandler(name=str() as name):
                names.add(name)
            case ast.alias(name=name, asname=asname):
                names.add(asname or name.partition('.')[0])
    return names


class Normaliser(ast.NodeTransformer):
    """``ac.X`` and ``rt.X`` become the name X, and ``module.f`` of a
    function f of an imported spec the name f (resolved by
    Spec.imported_functions): the passes match names.  Each qualifier
    removed is recorded, by line, for Spec._segment().  Checks that the
    names of rt are written qualified, and a function of another spec
    too."""

    def __init__(self, spec: Spec, groups: dict[str, str],
                 modules: dict[str, str]) -> None:
        self.spec = spec
        self.groups = groups
        # {spec module alias: path}; their functions by name.
        self.modules = modules
        self.module_functions = {alias: top_level_functions(path)
                                 for alias, path in modules.items()}
        self.bound = _bound_names(spec.module)
        self.local = {node.name for node in spec.module.body
                      if isinstance(node, ast.FunctionDef)}
        # (lineno, start, end) byte offsets of the removed qualifiers.
        self.qualifiers: list[tuple[int, int, int]] = []

    def _record(self, node: ast.Attribute) -> None:
        if node.lineno != node.end_lineno:
            return      # (_segment() refuses text on several lines)
        self.qualifiers.append((node.lineno, node.col_offset,
                                node.end_col_offset - len(node.attr)))

    def visit_Attribute(self, node: ast.Attribute) -> ast.AST:
        value = node.value
        if isinstance(value, ast.Name) and isinstance(node.ctx, ast.Load):
            group = self.groups.get(value.id)
            if group in NORMALISED_GROUPS:
                if group == 'rt' and node.attr not in RT_NAMES:
                    raise self.spec.error(node, f"rt has no {node.attr!r}; "
                                          f"its names are "
                                          f"{', '.join(RT_NAMES)}")
                if group == 'ac' and node.attr in RT_NAMES:
                    raise self.spec.error(node, f"write rt.{node.attr}, "
                                          f"not ac.{node.attr}")
                self._record(node)
                name = ast.copy_location(ast.Name(node.attr, ast.Load()),
                                         node)
                name._pyspec_group = group  # type: ignore[attr-defined]
                return name
            if node.attr in self.module_functions.get(value.id, ()):
                return self._function(node, value.id)
        return self.generic_visit(node)

    def _function(self, node: ast.Attribute, module: str) -> ast.AST:
        """``module.f``, a function of the spec imported as *module*."""
        spec, name = self.spec, node.attr
        path = self.modules[module]
        where = f"{module}.{name}"
        if name in self.local:
            raise spec.error(node, f"{where}: this spec defines {name} too: "
                             "rename one (the C names are one namespace)")
        known = spec.imported_functions.get(name)
        if known is not None and known != (path, name):
            raise spec.error(node, f"{where}: {name} is also a function of "
                             f"{known[0]}: rename one (the C names are one "
                             "namespace)")
        spec.imported_functions[name] = (path, name)
        self._record(node)
        found = ast.copy_location(ast.Name(name, ast.Load()), node)
        found._pyspec_module = module   # type: ignore[attr-defined]
        return found

    def visit_Name(self, node: ast.Name) -> ast.AST:
        if not isinstance(node.ctx, ast.Load):
            return node
        name = node.id
        if name in SHADOWED_BUILTINS:
            raise self.spec.error(node, f"{name}() is Python's builtin "
                                  f"here, not the C's: write rt.{name}() "
                                  "(from libclinic.pyspec import rt)")
        if name in RT_NAMES and name not in self.bound:
            raise self.spec.error(node, f"write rt.{name} (from "
                                  "libclinic.pyspec import rt)")
        if name not in self.bound:
            for module, functions in self.module_functions.items():
                if name in functions:
                    raise self.spec.error(node, f"{name} is a function of "
                                          f"the spec {module}: call it as "
                                          f"{module}.{name}")
        return node


def decorator_text(decorator: ast.expr) -> str:
    """*decorator* (normalised) as the spec writes it: ``@ac.stub(...)``,
    ``@classmethod``."""
    group = 'ac.' if _qualified(decorator, 'ac') else ''
    return f'@{group}{ast.unparse(decorator)}'


def written(name: str) -> str:
    """The decorator *name* as a spec writes it: ``@ac.name``, or
    ``@classmethod``."""
    return f'@{name}' if name in METHOD_DECORATORS else f'@ac.{name}'


def _qualified(node: ast.expr | None, group: str) -> bool:
    """Whether normalised *node* was written ``group.X`` (ac.object) or
    ``group.X(...)``."""
    if isinstance(node, ast.Call):
        node = node.func
    return getattr(node, '_pyspec_group', None) == group


class Spec:
    def __init__(self, source: str, filename: str = '<spec>',
                 loaded: dict[str, Spec] | None = None) -> None:
        self.filename = filename
        self.source = source
        self._lines: list[str] | None = None     # (_segment())
        self.module = ast.parse(source, filename)
        # Top-level functions by name and methods by "T.name", in the
        # order of the file.
        self.functions: dict[str, ast.FunctionDef] = {}
        self.classes: dict[str, ast.ClassDef] = {}
        self.shared: dict[str, Shared] = {}
        # The C functions of ``meth = ac.stub("f")``, by "T.meth"
        # (c_method()).
        self._c_methods: dict[str, cfunctions.CMethod] = {}
        # (path, text) of the C file clinic is processing, whose includes
        # c_method() reads; else the C file of the spec, read from disk.
        self.c_input: tuple[str, str] | None = None
        # Accessors by "T.name": {"getter": def, "setter": def}.
        self.accessors: dict[str, dict[str, ast.FunctionDef]] = {}
        # Specs imported with ``from pkg import module``: name -> path.
        self.imports: dict[str, str] = {}
        # One Spec per file (absolute path), shared with the specs it
        # imports (load_spec()).
        self.loaded: dict[str, Spec] = {} if loaded is None else loaded
        # Functions of imported specs, called ``module.f(...)`` (the name
        # f after Normaliser): name -> (path of the spec, name there).
        self.imported_functions: dict[str, tuple[str, str]] = {}
        for node in self.module.body:
            if isinstance(node, ast.ImportFrom):
                self._add_import(node)
        normaliser = Normaliser(self, group_aliases(self.module),
                                self.imports)
        self.module = normaliser.visit(self.module)
        # The qualifiers Normaliser removed, by line: {lineno: [(start,
        # end)]} (byte offsets), for _segment().
        self.qualifiers: dict[int, list[tuple[int, int]]] = {}
        for lineno, start, end in normaliser.qualifiers:
            self.qualifiers.setdefault(lineno, []).append((start, end))
        for node in self.module.body:
            match node:
                case ast.FunctionDef(name=name):
                    self._add_function(name, node)
                case ast.ClassDef(name=name) if name in self.classes:
                    raise self.error(node, f"class {name} is defined "
                                     "twice")
                case ast.ClassDef():
                    self._add_class(node)
                case ast.ImportFrom():
                    pass    # (above)
                case ast.Import(names=names) if all(
                        _stdlib(a.name) for a in names):
                    pass    # for the Python reference of a function
                case ast.Import():
                    raise self.error(node, "import a spec as 'from "
                                     "Objects.stringlib.pyspec import "
                                     "transmogrify' (its path from the "
                                     "source root)")
                case (ast.Assign() | ast.AnnAssign() | ast.Pass()
                      | ast.Expr(ast.Constant(str()))):
                    pass    # (constants of the Python references)
                case _:
                    # (A spec has no conditional compilation: see
                    # "Conditional compilation" in the README.)
                    raise self.error(node, "unsupported top-level "
                                     f"statement in a spec: "
                                     f"{ast.unparse(node).splitlines()[0]!r}"
                                     "; a spec holds imports, functions, "
                                     f"classes and assignments; see {README}")
        self.loaded.setdefault(os.path.abspath(filename), self)

    def error(self, node: ast.AST | None, message: str,
              kind: SpecErrorKind = SpecErrorKind.INVALID) -> SpecError:
        """A SpecError at the line of *node*, in this spec unless *node*
        was copied from another (see SpecError.at())."""
        return SpecError.at(node, message, kind, self.filename)

    def output(self, node: ast.FunctionDef) -> Output | None:
        """output() of *node*, its errors located in this spec."""
        try:
            return output(node)
        except SpecError as exc:
            if exc.filename is None:
                exc.filename = self.filename
            raise

    def _check_decorators(self, name: str,
                          decorators: list[ast.expr]) -> None:
        """Every decorator is ``@ac.<name>[(...)]``, or Python's
        @classmethod and @staticmethod."""
        for decorator in decorators:
            if isinstance(decorator, ast.Name) and \
                    decorator.id in METHOD_DECORATORS:
                continue
            if not _qualified(decorator, 'ac'):
                raise self.error(decorator, f"{name}: a spec decorator is "
                                 "@ac.<name> (from libclinic.pyspec import "
                                 "ac), or @classmethod or @staticmethod, not "
                                 f"@{ast.unparse(decorator)}")

    def _check_annotations(self, name: str, node: ast.FunctionDef) -> None:
        """A method's annotations are clinic converters,
        ``ac.<converter>[(...)]``; a top-level function's are C types,
        ``ac.<C type>``, a string or None."""
        args = node.args
        annotated = [(a, a.annotation) for a in (
            *args.posonlyargs, *args.args, *args.kwonlyargs,
            *filter(None, (args.vararg, args.kwarg)))]
        annotated.append((node, node.returns))
        method = '.' in name
        for where, annotation in annotated:
            if annotation is None:
                continue
            if method and _qualified(annotation, 'ac'):
                continue
            if not method and (_string(annotation) is not None
                               or (isinstance(annotation, ast.Constant)
                                   and annotation.value is None)
                               or isinstance(annotation, ast.Name)
                               and _qualified(annotation, 'ac')):
                continue
            what = (getattr(where, 'arg', None) and
                    f"parameter {where.arg!r}" or "the return annotation")
            wanted = ("a clinic converter, ac.<converter> or "
                      "ac.<converter>(...)" if method else
                      "a C type: ac.<C type> (ac.object, ac.Py_ssize_t, "
                      "...), a string or None")
            raise self.error(annotation, f"{name}(): {what}: an annotation "
                             f"is {wanted}, not {ast.unparse(annotation)}")

    def _check_def(self, name: str, node: ast.FunctionDef) -> None:
        self._check_decorators(name, node.decorator_list)
        self._check_annotations(name, node)
        found = self.output(node)
        method = '.' in name
        body = without_docstring(node)
        if len(body) == 1 and isinstance(body[0], ast.Pass):
            raise self.error(body[0], f"{name}: use ... as the body of a "
                             "function implemented in C, not pass")
        if found is None:
            if method:
                raise self.error(node, f"{name} needs @ac.stub (C written "
                                 "by hand) or @ac.generate (C generated "
                                 "from its body): a method of a spec class "
                                 "without one is a mistake")
            if is_literal_stub(node):
                raise self.error(node, f"{name}: a C function is declared "
                                 "with @ac.stub; a function without a spec "
                                 "decorator is Python only, and needs a "
                                 "body")
            return
        if not method and (found.name is not None or found.keywords):
            raise self.error(found.decorator, f"{name}: the C name of a "
                             "top-level function is its name")
        if found.kind == STUB and found.optimizer_info and is_literal_stub(node):
            raise self.error(node, f"{name}: the body of "
                             "@ac.stub(optimizer_info=True) is the Python "
                             "reference of the C; write @ac.stub for a C "
                             "function about which nothing is known")
        if found.kind == GENERATE:
            if is_literal_stub(node):
                raise self.error(node, f"{name}: @ac.generate needs a body "
                                 "to generate the C from; write @ac.stub "
                                 "for C written by hand")
            if method and slots.is_slot(name.rpartition('.')[2]):
                raise self.error(node, f"{name}: a slot is a C function "
                                 "written by hand: @ac.stub, with its "
                                 "Python as the body")
        if found.kind == INLINE:
            if is_literal_stub(node):
                raise self.error(node, f"{name}: an @ac.inline function "
                                 "needs a body: it is generated into its "
                                 "callers")
            if method:
                raise self.error(node, f"{name}: only a top-level "
                                 "function can be @ac.inline")

    def _add_function(self, name: str, node: ast.FunctionDef) -> None:
        self._check_def(name, node)
        if (name in self.functions or name in self.shared
                or name in self.accessors):
            raise self.error(node, f"{name} is defined twice")
        self.functions[name] = node

    def _add_accessor(self, name: str, kind: str,
                      node: ast.FunctionDef) -> None:
        """``@ac.getter def attr(self)`` or ``@ac.setter def attr(self,
        value)``: an accessor of "T.attr" (*kind*: getter or setter)."""
        if sum(decorator_name(d) in ACCESSOR_DECORATORS
               for d in node.decorator_list) > 1:
            raise self.error(node, f"{name}: only one of @ac.getter and "
                             "@ac.setter")
        accessors = self.accessors.setdefault(name, {})
        if kind in accessors or name in self.functions \
                or name in self.shared:
            raise self.error(node, f"{name} is defined twice")
        if is_generated(node) and not is_literal_stub(node):
            raise self.error(node, f"{name}(): an accessor with a body is "
                             "expressible, but not lowered to C yet",
                             SpecErrorKind.NOT_LOWERED)
        self._check_def(name, node)
        accessors[kind] = node

    def _add_import(self, node: ast.ImportFrom) -> None:
        """``from libclinic.pyspec import ac, rt, machine`` (the tooling),
        ``from Objects.stringlib.pyspec import transmogrify`` (a spec, by
        its path from the source root, whose functions are called
        ``transmogrify.f(...)``).  Imports of the standard library are
        for Python references."""
        if node.module is None or node.level:
            raise self.error(node, "a spec imports by the path from the "
                             "source root, not relatively")
        if node.module == GROUP_PACKAGE:
            for alias in node.names:
                if alias.name not in GROUPS:
                    raise self.error(node, f"{GROUP_PACKAGE} has the groups "
                                     f"{', '.join(GROUPS)}, not "
                                     f"{alias.name}")
            return
        if node.module.partition('.')[0] == 'libclinic':
            raise self.error(node, "a spec names the tooling by group: "
                             f"'from {GROUP_PACKAGE} import ac, rt, "
                             "machine', then ac.X, rt.X, machine.X")
        if _stdlib(node.module):
            return
        root = specfiles.import_root(self.filename)
        parts = node.module.split('.')
        for alias in node.names:
            name = alias.asname or alias.name
            path = os.path.join(root, *parts, alias.name + '.py')
            module = os.path.join(root, *parts) + '.py'
            if os.path.exists(path):
                self.imports[name] = path
            elif os.path.exists(module):
                package, _, stem = node.module.rpartition('.')
                raise self.error(node, f"import the spec, 'from {package} "
                                 f"import {stem}', and call "
                                 f"{stem}.{alias.name}(...)")
            else:
                raise self.error(node, f"imported spec {path} not found: a "
                                 "spec imports another by its path from the "
                                 "source root ('from Objects.pyspec import "
                                 "abstract', 'from Objects.stringlib.pyspec "
                                 "import transmogrify')")

    def imported(self, module: str) -> Spec:
        """The spec imported as *module*."""
        return self.load_spec(self.imports[module])

    def load_spec(self, path: str) -> Spec:
        """The spec at *path*, read once for this spec and its imports."""
        path = os.path.abspath(path)
        if path not in self.loaded:
            spec = Spec.load(path, self.loaded)
            assert spec is not None
        return self.loaded[path]

    def resolve(self, name: str) -> tuple[Spec, ast.FunctionDef] | None:
        """(spec, def) of function *name* of this spec or imported."""
        if name in self.functions:
            return self, self.functions[name]
        imported = self.imported_functions.get(name)
        if imported is None:
            return None
        path, original = imported
        return self.load_spec(path).resolve(original)

    def _called(self, call: ast.Call
                ) -> tuple[Spec, ast.FunctionDef] | None:
        """(spec, def) of the function *call* calls by name; a call copied
        from another spec (an @ac.inline body) resolves there
        (marks.Scope)."""
        func = call.func
        if not isinstance(func, ast.Name):
            return None
        return self.load_spec(marks.scope(call)
                              or self.filename).resolve(func.id)

    def c_function(self, call: ast.Call
                   ) -> tuple[Spec, ast.FunctionDef] | None:
        """(spec, def) of the C function written by hand (@ac.stub)
        *call* calls."""
        found = self._called(call)
        if found is None or _kind(found[1]) != STUB:
            return None
        return found

    def helper_function(self, call: ast.Call
                        ) -> tuple[Spec, ast.FunctionDef] | None:
        """(spec, def) of the Python helper (no spec decorator) *call*
        calls."""
        found = self._called(call)
        if found is None or not is_helper(found[1]):
            return None
        return found

    def pure_python_function(self, call: ast.Call
                             ) -> tuple[Spec, ast.FunctionDef] | None:
        """(spec, def) of the function *call* calls if it is Python only
        (a helper) or pure Python (``@ac.stub`` with a body): in a Python
        reference, part of the model of a value."""
        found = self.helper_function(call)
        if found is not None:
            return found
        found = self.c_function(call)
        if found is None or not is_pure_python(found[1]):
            return None
        return found

    def inline_function(self, call: ast.Call
                        ) -> tuple[Spec, ast.FunctionDef] | None:
        """(spec, def) of the @ac.inline function *call* calls."""
        found = self._called(call)
        if found is None or not is_inline(found[1]):
            return None
        return found

    @classmethod
    def load(cls, path: str,
             loaded: dict[str, Spec] | None = None) -> Spec | None:
        """The spec at *path*, or None; *loaded*: see __init__()."""
        try:
            with open(path, encoding='utf-8') as f:
                source = f.read()
        except FileNotFoundError:
            return None
        return cls(source, path, loaded)

    def _add_class(self, node: ast.ClassDef) -> None:
        """Only these statements may be in a spec class: a docstring,
        ``def``, ``meth = ac.stub("f")``, ``meth = module.Class.meth``,
        ``field: ctype`` and ``pass``."""
        self.classes[node.name] = node
        self.class_output(node.name)    # (checks the decorators)
        for i, stmt in enumerate(node.body):
            match stmt:
                case ast.Expr(ast.Constant(str())) if i == 0:
                    pass
                case ast.Pass():
                    pass
                case ast.AnnAssign(target=ast.Name(), value=None,
                                   annotation=annotation):
                    # A field of the C struct (``it_index:
                    # ac.Py_ssize_t``, ``ob_sval: 'char[]'``): the struct
                    # stays C; the model (model.py) allocates the fields.
                    if not (_string(annotation) is not None
                            or isinstance(annotation, ast.Name)
                            and _qualified(annotation, 'ac')):
                        raise self.error(stmt, f"class {node.name}: a field "
                                         "is annotated with its C type, "
                                         "ac.<C type> or a string")
                case ast.FunctionDef(name=name) if accessor_kind(stmt):
                    self._add_accessor(f'{node.name}.{name}',
                                       accessor_kind(stmt), stmt)
                case ast.FunctionDef(name=name):
                    self._add_function(f'{node.name}.{name}', stmt)
                case ast.Assign(targets=[ast.Name(name)],
                                value=ast.Call(func=ast.Name('stub')) as call) \
                        if _qualified(call.func, 'ac'):
                    self._add_c_method(node.name, stmt, name, call)
                case ast.Assign(targets=[ast.Name(name)], value=value) \
                        if (source := self._shared_source(value)) is not None:
                    self._add_shared(node.name, stmt, name, *source)
                case ast.Assign(targets=[ast.Name(name)],
                                value=ast.Name() | ast.Call()):
                    raise self.error(stmt, f"Python has no clones: write "
                                     f"{name} as a full def (clinic "
                                     "generates the same code)")
                case _:
                    raise self.error(stmt, f"unsupported statement in "
                                     f"spec class {node.name}: "
                                     f"{ast.unparse(stmt)!r}; see {README}")

    def _shared_source(self, value: ast.expr
                       ) -> tuple[str | None, str, str, list[ast.expr]] | None:
        """(module or None, class, method, decorators) of the value of
        ``meth = [decorator(...)(]module.Class.meth[)]``, or None."""
        decorators = []
        while (isinstance(value, ast.Call) and len(value.args) == 1
               and not value.keywords):
            decorators.append(value.func)
            value = value.args[0]
        match value:
            case ast.Attribute(ast.Attribute(ast.Name(module), cls), meth):
                return module, cls, meth, decorators
            case ast.Attribute(ast.Name(cls), meth) if cls in self.classes:
                return None, cls, meth, decorators
        return None

    def _add_shared(self, cls_name: str, stmt: ast.stmt, name: str,
                    module: str | None, cls: str, meth: str,
                    decorators: list[ast.expr]) -> None:
        """``name = module.cls.meth``."""
        where = f'{module}.{cls}' if module else cls
        if module is not None and module not in self.imports:
            raise self.error(stmt, f"{module} is not a spec imported with "
                             f"'from <package> import {module}'")
        other = self.imported(module) if module else self
        if f'{cls}.{meth}' not in other.functions:
            raise self.error(stmt, f"{where} has no method {meth!r} "
                             f"({other.filename})")
        if meth != name:
            raise self.error(stmt, f"a shared method keeps its name: write "
                             f"{meth} = {where}.{meth}")
        if f'{cls_name}.{name}' in self.functions:
            raise self.error(stmt, f"{cls_name}.{name} is defined twice")
        for decorator in decorators:
            if (decorator_name(decorator) not in SHARED_DECORATORS
                    or not _qualified(decorator, 'ac')):
                raise self.error(decorator, "a shared method takes only "
                                 "ac.critical_section() and ac.stub(), not "
                                 f"{decorator_text(decorator)[1:]}")
        self.shared[f'{cls_name}.{name}'] = Shared(module, cls, meth,
                                                   stmt.lineno, decorators)

    def _add_c_method(self, cls_name: str, stmt: ast.stmt, name: str,
                      call: ast.Call) -> None:
        """``name = ac.stub("f", critical_section=True)``: the C function f
        of a header the C file includes is the method (cfunctions.py);
        ``ac.stub(METH_O="f")`` also gives its calling convention."""
        full = f'{cls_name}.{name}'
        usage = ("a method that is a C function of a header is "
                 f"{name} = ac.stub(\"f\"), with critical_section=True to "
                 "call it in a critical section, or ac.stub(METH_O=\"f\") "
                 "when its definition does not say its calling convention")
        c_function = convention = None
        locked = False
        if len(call.args) > 1 or any(_string(a) is None for a in call.args):
            raise self.error(call, f"{full}: {usage}")
        if call.args:
            c_function = _string(call.args[0])
        for kw in call.keywords:
            value = kw.value
            if (kw.arg == 'critical_section'
                    and isinstance(value, ast.Constant)
                    and isinstance(value.value, bool)):
                locked = value.value
            elif (kw.arg in PYCFUNCTION_FLAGS and _string(value) is not None
                  and c_function is None):
                convention, c_function = kw.arg, _string(value)
            else:
                raise self.error(kw, f"{full}: {usage}")
        if c_function is None:
            raise self.error(call, f"{full}: {usage}")
        if full in self.functions or full in self.shared:
            raise self.error(stmt, f"{full} is defined twice")
        self.shared[full] = Shared(None, cls_name, name, stmt.lineno,
                                   c_function=c_function,
                                   convention=convention,
                                   critical_section=locked)

    def c_method(self, name: str) -> cfunctions.CMethod:
        """The C function that shared method *name* (``ac.stub("f")``)
        is, read from the headers the C file of the spec includes, with
        its calling convention (cfunctions.find())."""
        cached = self._c_methods.get(name)
        if cached is not None:
            return cached
        shared = self.shared[name]
        c_function = shared.c_function
        assert c_function is not None

        def error(message: str) -> SpecError:
            return SpecError(message, filename=self.filename,
                             lineno=shared.lineno)

        c_file, text = self.c_input or (specfiles.c_file_of(self.filename),
                                        None)
        found = None if c_file is None else cfunctions.find(c_file,
                                                             c_function,
                                                             text)
        if found is None:
            headers = ([os.path.relpath(h, os.path.dirname(c_file))
                        for h in cfunctions.local_includes(c_file, text)]
                       if c_file else [])
            raise error(f"{name}: no C function {c_function!r} in the "
                        f"headers {c_file or 'the C file'} includes ("
                        f"{', '.join(headers) or 'none'}): a clinic "
                        f"function (\"B.meth as {c_function}\") or a "
                        "PyCFunction defined there")
        found = dc.replace(found)
        if shared.convention is not None:
            if found.function is not None:
                raise error(f"{name}: {c_function} is a clinic function "
                            f"({found.where()}): clinic knows its calling "
                            f"convention; write ac.stub(\"{c_function}\")")
            if found.flags not in (None, shared.convention):
                raise error(f"{name}: {c_function} is {found.flags} "
                            f"({found.where()}), not {shared.convention}")
            found.flags = shared.convention
        elif found.flags is None:
            raise error(f"{name}: the definition of {c_function} "
                        f"({found.where()}) does not say its calling "
                        f"convention: write ac.stub(METH_O=\"{c_function}\") "
                        "or another of "
                        f"{', '.join(sorted(PYCFUNCTION_FLAGS))}")
        model = cfunctions.model_def(self, found)
        if model is not None:
            cfunctions.check_model(model[0], model[1], found)
        self._c_methods[name] = found
        return found

    def declaration(self, name: str) -> tuple[Spec, str]:
        """(spec, "Class.meth") of the def declaring method *name* (for a
        shared method, the method it shares; for a C function of a
        header, ``ac.stub("f")``, (spec of the header, "f"), its model)."""
        shared = self.shared.get(name)
        if shared is None:
            return self, name
        if shared.c_function is not None:
            found = cfunctions.model_def(self, self.c_method(name))
            if found is None:
                raise SpecError(f"{name}: the C function "
                                f"{shared.c_function} has no model (a def "
                                "of that name in the spec of its header)",
                                filename=self.filename, lineno=shared.lineno)
            return found[0], shared.c_function
        other = self.imported(shared.module) if shared.module else self
        return other, f'{shared.cls}.{shared.meth}'

    def shared_decorators(self, name: str) -> list[tuple[str, int]]:
        """The clinic decorator lines of shared method *name*, with their
        line in this spec: ``critical_section(...)``."""
        return [(self._decorator_line(d), d.lineno)
                for d in self.shared[name].decorators
                if decorator_name(d) not in SPEC_DECORATORS]

    # -- implemented functions ---------------------------------------------

    def implemented(self, name: str) -> bool:
        """Whether spec function *name* has a body generated as a C
        function of its own (``@ac.generate``): a top-level function or a
        clinic method."""
        node = self.functions.get(name)
        if node is None or not is_generated(node):
            return False
        return '.' not in name or self.method_kind(name) == CLINIC

    def implemented_functions(self) -> list[str]:
        return [name for name in self.functions if self.implemented(name)]

    def body(self, name: str) -> list[ast.stmt]:
        """Statements of function *name*, without its docstring."""
        return without_docstring(self.functions[name])

    def params(self, name: str) -> list[str]:
        args = self.functions[name].args
        return [a.arg for a in args.posonlyargs + args.args]

    def call_target(self, func: ast.expr) -> str | None:
        """The implemented spec function called as *func* (``f(...)``,
        ``T.m(...)``), if any."""
        match func:
            case ast.Name(name):
                pass
            case ast.Attribute(ast.Name(cls), meth) if cls in self.classes:
                name = f'{cls}.{meth}'
            case _:
                return None
        return name if self.implemented(name) else None

    def native_functions(self) -> list[str]:
        return [name for name, node in self.functions.items()
                if is_native(node)]

    def describe(self, name: str,
                 self_ctype: str = 'PyObject *') -> SpecFunction:
        """The C signature of implemented spec function *name*, whose self
        (or class) parameter has C type *self_ctype* (a __new__'s is a
        type).  A SpecError (NOT_LOWERED) first if *name* is not in the
        lowered subset."""
        subset.check_lowered(self, name)
        node = self.functions[name]
        args = node.args
        cls_name, _, meth = name.rpartition('.')
        positional = args.posonlyargs + args.args
        first_optional = len(positional) - len(args.defaults)
        parameters = []
        new_type = None
        for i, arg in enumerate(positional):
            if cls_name and i == 0:
                if meth == '__new__':
                    new_type, self_ctype = cls_name, TYPE_CTYPE
                parameters.append(SpecParameter(arg.arg, self_ctype, False))
                continue
            match arg.annotation:
                case ast.Name(conv) | ast.Call(func=ast.Name(conv)):
                    ctype = subset.LOWERED_CTYPES[conv]
                case _:
                    raise AssertionError('checked by subset.py')
            parameters.append(SpecParameter(arg.arg, ctype,
                                            i >= first_optional))
        return SpecFunction(name, self.filename, parameters,
                            new_type)

    # -- kinds of methods and C names --------------------------------------

    def c_name(self, name: str
               ) -> tuple[str | None, dict[str, str | None]]:
        """(C name or None, {slot or METH_ flag: C name, or None for the
        default}) of the @ac.stub or @ac.generate of method *name* (of a
        shared method: ``ac.stub(...)(X.meth)``)."""
        if name in self.shared:
            found = None
            for decorator in self.shared[name].decorators:
                if decorator_name(decorator) == STUB:
                    found = parse_output(decorator, f"{name}: ")
        elif name in self.functions:
            found = self.output(self.functions[name])
        else:
            return None, {}
        if found is None:
            return None, {}
        return found.name, found.keywords

    def class_output(self, cls_name: str) -> ClassOutput | None:
        """The tables of class *cls_name* clinic generates: those its
        ``@ac.generate(prefix="x", doc=..., methods=..., slots=...)``
        asks for (all of them by default), or None without it."""
        node = self.classes[cls_name]
        found = None
        for decorator in node.decorator_list:
            if decorator_name(decorator) != GENERATE \
                    or not _qualified(decorator, 'ac') or found is not None:
                raise self.error(decorator, f"class {cls_name}: a spec "
                                 "class takes only @ac.generate("
                                 "prefix=\"x\", doc=..., methods=..., "
                                 "slots=...), which generates its tables")
            found = ClassOutput(cls_name)
            if not isinstance(decorator, ast.Call):
                continue
            if decorator.args:
                raise self.error(decorator, f"class {cls_name}: the prefix "
                                 "of the tables is "
                                 "@ac.generate(prefix=\"x\")")
            for kw in decorator.keywords:
                value = kw.value
                if kw.arg == 'prefix' and _string(value) is not None:
                    found.prefix = str(_string(value))
                elif (kw.arg in CLASS_OPTIONS and kw.arg != 'prefix'
                      and isinstance(value, ast.Constant)
                      and isinstance(value.value, bool)):
                    setattr(found, kw.arg, value.value)
                else:
                    raise self.error(kw, f"class {cls_name}: the options of "
                                     "@ac.generate are prefix=\"x\" and "
                                     "doc, methods, slots=True or False")
        return found

    def class_prefix(self, cls_name: str) -> str:
        """The C prefix of the tables of class *cls_name* and of the
        default names of its slots: the prefix of its @ac.generate, else
        its name."""
        found = self.class_output(cls_name)
        return cls_name if found is None else found.prefix

    def slot_c_name(self, cls_name: str, slot: str) -> str:
        """The default C name of *slot* of class *cls_name*: the prefix and
        the slot without its prefix (bytes_repr for tp_repr)."""
        return f'{self.class_prefix(cls_name)}_{slot.split("_", 1)[1]}'

    def native_c_name(self, name: str) -> str:
        """The C name of the function written by hand for spec function
        *name*: its own name, a slot's (the first it names, else its only
        one), or the name given for a method."""
        positional, keywords = self.c_name(name)
        if positional is not None:
            return positional
        cls_name, _, meth = name.rpartition('.')
        if not cls_name:
            return name
        for key, c_name in keywords.items():
            if not key.startswith('METH_'):
                return c_name or self.slot_c_name(cls_name, key)
        if keywords:
            return next(iter(keywords.values())) or name
        candidates = slots.candidates(meth)
        if len(candidates) == 1:
            return self.slot_c_name(cls_name, candidates[0].slot)
        return name

    def pycfunction(self, name: str) -> PyCFunctionEntry | None:
        """The hand-written PyCFunction entry of method *name*
        (``@ac.stub(METH_O="f")``), or None; its parameters must be those
        of the calling convention."""
        _, keywords = self.c_name(name)
        given = [(k, v) for k, v in keywords.items()
                 if k in PYCFUNCTION_FLAGS]
        if not given:
            return None
        node = self.functions[name]
        if len(given) > 1:
            raise self.error(node, f"{name}: one calling convention of "
                             f"{sorted(PYCFUNCTION_FLAGS)} in @ac.stub")
        (convention, c_function), = given
        decorators = [decorator_name(d) for d in node.decorator_list]
        static = 'staticmethod' in decorators
        args = node.args
        positional = args.posonlyargs + args.args
        if not static:
            positional = positional[1:]
        if convention in ('METH_NOARGS', 'METH_O'):
            ok = (len(positional) == (convention == 'METH_O')
                  and not (args.vararg or args.kwarg))
        else:
            ok = not positional and args.vararg is not None
        if not ok or args.kwonlyargs or args.defaults or args.args:
            wanted = PYCFUNCTION_FLAGS[convention]
            if static:
                wanted = wanted.replace('self, ', '').replace('self', '')
            raise self.error(node, f"{name}: a {convention} function takes "
                             f"{wanted}")
        flags = [convention]
        for flag, on in (('METH_KEYWORDS', args.kwarg is not None),
                         ('METH_CLASS', 'classmethod' in decorators),
                         ('METH_STATIC', static),
                         ('METH_COEXIST', 'coexist' in decorators)):
            if on:
                flags.append(flag)
        return PyCFunctionEntry(c_function, ' | '.join(flags))

    def method_kind(self, name: str) -> str:
        """CLINIC, SLOT, PYCFUNCTION, SHARED or ACCESSOR."""
        if name in self.shared:
            return SHARED
        if name in self.accessors:
            return ACCESSOR
        meth = name.rpartition('.')[2]
        if slots.is_slot(meth):
            return SLOT
        _, keywords = self.c_name(name)
        if any(k in PYCFUNCTION_FLAGS for k in keywords):
            return PYCFUNCTION
        if keywords:
            raise self.error(self.functions[name], f"{name}: @ac.stub with "
                             "a keyword names a slot of a dunder or one of "
                             f"{sorted(PYCFUNCTION_FLAGS)}")
        return CLINIC

    def entries(self, cls_name: str) -> list[str]:
        """The methods and shared methods of class *cls_name*, in order
        (not its accessors: tp_getset is written in C)."""
        names = []
        for stmt in self.classes[cls_name].body:
            match stmt:
                case ast.FunctionDef(name=name) if not accessor_kind(stmt):
                    names.append(name)
                case ast.Assign(targets=[ast.Name(name)]):
                    names.append(name)
        return names

    def declares_slots(self, cls_name: str) -> bool:
        """Whether class *cls_name* declares a slot (a dunder)."""
        return any(self.method_kind(f'{cls_name}.{meth}') == SLOT
                   for meth in self.entries(cls_name))

    def describes_type(self, cls_name: str) -> bool:
        """Whether class *cls_name* describes its whole type: clinic
        generates its slot tables (``@ac.generate``, not ``slots=False``),
        so its dunders are all the slots of the type.  A class without
        @ac.generate may declare some methods and slots only (their facts,
        their clinic blocks) and leaves its tables to the C."""
        found = self.class_output(cls_name)
        return found is not None and found.slots

    def docstring(self, name: str) -> str | None:
        """The docstring of method *name* as __doc__ shows it, or None."""
        node = self.functions[name]
        doc = docstring_of(node.body)
        if doc is None:
            return None
        return '\n'.join(self._clean_docstring(node.body[0], doc))

    # -- clinic input ------------------------------------------------------

    def has_method(self, name: str) -> bool:
        """True if *name* is a clinic function of the spec."""
        if '.' not in name or name not in self.functions:
            return False
        return self.method_kind(name) == CLINIC

    def methods(self, cls_name: str) -> list[str]:
        """Names of the clinic functions of class *cls_name*, in order."""
        return [meth for meth in self.entries(cls_name)
                if self.method_kind(f'{cls_name}.{meth}') == CLINIC]

    def clinic_input(self, name: str, accessor: str = ''
                     ) -> tuple[list[tuple[str, int]], str,
                                list[tuple[str, int]]]:
        """(decorator lines, text to append to the function line, the
        lines after it) of spec method *name* (or of its *accessor*), each
        line with its line in the spec, where clinic reports errors."""
        node = (self.accessors[name][accessor] if accessor
                else self.functions[name])
        decorators, kind = self._decorators(node, skip=accessor)
        suffix = ''
        if node.returns is not None:
            suffix = f' -> {self._segment(node.returns, "return converter")}'
        params = self._parameter_lines(node, kind)
        names = [pname for _, pname, _ in params if pname]
        param_docs: dict[str, list[str]] = {}
        docstring: list[str] = []
        doc = docstring_of(node.body)
        doc_lineno = node.body[0].lineno
        if doc is not None:
            lines = self._clean_docstring(node.body[0], doc)
            docstring, param_docs = self._split_docstring(node, lines, names)
        out = [('', node.lineno)]
        for param_line, pname, lineno in params:
            out.append((f'    {param_line}', lineno))
            for doc_line in param_docs.get(pname or '', ()):
                out.append((f'        {doc_line}', doc_lineno))
        if docstring:
            out += [(line, doc_lineno) for line in ['', *docstring]]
        return decorators, suffix, out

    def _decorator_line(self, decorator: ast.expr) -> str:
        """The clinic DSL line of a decorator: ``@name arg ...``."""
        match decorator:
            case ast.Name(name):
                return f'@{name}'
            case ast.Call(func=ast.Name(name), args=args, keywords=[]):
                words = []
                for arg in args:
                    match arg:
                        case ast.Constant(value=str() | int() as value) \
                                if not isinstance(value, bool):
                            words.append(_quote(str(value)))
                        case _:
                            raise self.error(arg, "the arguments of a "
                                             "clinic decorator must be "
                                             "string or integer constants")
                return ' '.join([f'@{name}', *words])
        raise self.error(decorator, "a spec decorator is a clinic "
                         "decorator: @name or @name(args)")

    def _decorators(self, node: ast.FunctionDef, skip: str = ''
                    ) -> tuple[list[tuple[str, int]], str]:
        """The clinic decorator lines of *node* with their line in the
        spec, and its kind; *skip*: a decorator the C file writes."""
        kind = 'method'
        decorators = []
        for decorator in node.decorator_list:
            if decorator_name(decorator) in (*SPEC_DECORATORS, skip):
                continue
            line = self._decorator_line(decorator)
            if line[1:] in METHOD_DECORATORS:
                if kind != 'method':
                    raise self.error(decorator, "only one of @classmethod "
                                     "and @staticmethod")
                kind = line[1:]
            decorators.append((line, decorator.lineno))
        if node.name == '__new__':
            if kind != 'method':
                raise self.error(node, "__new__ is implicitly a class "
                                 "method; remove the decorator")
            kind = 'classmethod'
            decorators.insert(0, ('@classmethod', node.lineno))
        return decorators, kind

    def _segment(self, node: ast.expr | ast.keyword, what: str) -> str:
        """The source text of *node*, on one line, less the qualifiers
        ``ac.`` and ``rt.`` (Normaliser): the text clinic reads."""
        text = ast.get_source_segment(self.source, node)
        assert text is not None
        if '\n' in text:
            raise self.error(node, f"write the {what} on one line")
        start, end = node.col_offset, node.end_col_offset
        assert end is not None
        if self._lines is None:
            self._lines = re.split(r'\r\n|\r|\n', self.source)
        line = self._lines[node.lineno - 1].encode()
        segment = line[start:end]
        for q_start, q_end in sorted(self.qualifiers.get(node.lineno, ()),
                                     reverse=True):
            if start <= q_start and q_end <= end:
                segment = (segment[:q_start - start]
                           + segment[q_end - start:])
        return segment.decode()

    def _converter(self, arg: ast.arg) -> tuple[str, str | None]:
        """The clinic converter of *arg* and its C parameter name
        (``c_param``), if any."""
        annotation = arg.annotation
        assert annotation is not None
        if isinstance(annotation, ast.Call):
            c_params = [kw for kw in annotation.keywords
                        if kw.arg == 'c_param']
            if c_params:
                value = c_params[0].value
                if not (isinstance(value, ast.Constant)
                        and isinstance(value.value, str)):
                    raise self.error(value, "c_param must be a string")
                args = [self._segment(a, 'converter')
                        for a in annotation.args]
                args += [self._segment(kw, 'converter')
                         for kw in annotation.keywords
                         if kw.arg != 'c_param']
                func = self._segment(annotation.func, 'converter')
                converter = f'{func}({", ".join(args)})' if args else func
                return converter, value.value
        return self._segment(annotation, 'converter'), None

    def _parameter_line(self, arg: ast.arg, default: ast.expr | None,
                        prefix: str = '') -> str:
        if arg.annotation is None:
            raise self.error(arg, f"parameter {arg.arg!r} needs a converter "
                             "as its annotation")
        converter, c_param = self._converter(arg)
        line = prefix + arg.arg
        if c_param is not None:
            line += f' as {c_param}'
        line += f': {converter}'
        if default is not None:
            line += f' = {self._segment(default, "default")}'
        return line

    def _parameter_lines(self, node: ast.FunctionDef, kind: str
                         ) -> list[tuple[str, str | None, int]]:
        """Clinic parameter lines, with the Python name of the parameter
        (None for the / and * markers) and its line in the spec."""
        args = node.args
        positional = args.posonlyargs + args.args
        defaults: list[ast.expr | None] = [None] * (
            len(positional) - len(args.defaults)) + list(args.defaults)
        pairs = list(zip(positional, defaults))
        n_posonly = len(args.posonlyargs)
        if kind != 'staticmethod':
            if not pairs:
                raise self.error(node, f"{node.name}() needs the self or "
                                 "class parameter first")
            if pairs[0][0].annotation is None:
                # Clinic's implicit self (or class) parameter.
                pairs = pairs[1:]
                n_posonly = max(n_posonly - 1, 0)
        lines: list[tuple[str, str | None, int]] = []
        for i, (arg, default) in enumerate(pairs):
            lines.append((self._parameter_line(arg, default), arg.arg,
                          arg.lineno))
            if i == n_posonly - 1:
                lines.append(('/', None, arg.lineno))
        if args.vararg:
            lines.append((self._parameter_line(args.vararg, None, '*'),
                          args.vararg.arg, args.vararg.lineno))
        elif args.kwonlyargs:
            lines.append(('*', None, args.kwonlyargs[0].lineno))
        for arg, kw_default in zip(args.kwonlyargs, args.kw_defaults):
            lines.append((self._parameter_line(arg, kw_default), arg.arg,
                          arg.lineno))
        if args.kwarg:
            lines.append((self._parameter_line(args.kwarg, None, '**'),
                          args.kwarg.arg, args.kwarg.lineno))
        return lines

    def _clean_docstring(self, node: ast.stmt, text: str) -> list[str]:
        """Lines of docstring *text* of statement *node*, less the
        indentation of the statement."""
        margin = node.col_offset
        lines = [line.rstrip() for line in text.split('\n')]
        for i in range(1, len(lines)):
            if lines[i]:
                if lines[i][:margin].strip():
                    raise self.error(node, f"docstring line {lines[i]!r} is "
                                     "indented less than the docstring")
                lines[i] = lines[i][margin:]
        while lines and not lines[0]:
            del lines[0]
        while lines and not lines[-1]:
            del lines[-1]
        return lines

    def _split_docstring(self, node: ast.FunctionDef, lines: list[str],
                         names: list[str]
                         ) -> tuple[list[str], dict[str, list[str]]]:
        """(clinic docstring, parameter docstrings): the parameter
        section clinic renders after the summary, taken out."""
        param_docs: dict[str, list[str]] = {}
        if len(lines) < 3 or lines[1]:
            return lines, param_docs
        i = 2
        remaining = list(names)
        while (i < len(lines) and lines[i].startswith('  ')
                and lines[i][2:] in remaining):
            name = lines[i][2:]
            remaining = remaining[remaining.index(name) + 1:]
            i += 1
            doc = []
            while i < len(lines) and lines[i].startswith('    '):
                doc.append(lines[i][4:])
                i += 1
            if not doc:
                raise self.error(node.body[0], f"{node.name}(): no "
                                 f"docstring for parameter {name!r} in the "
                                 "parameter section")
            param_docs[name] = doc
        if i == 2:
            return lines, param_docs
        if i < len(lines):
            if lines[i]:
                raise self.error(node.body[0], f"{node.name}(): expected an "
                                 "empty line after the parameter section, "
                                 f"got {lines[i]!r} (parameters are "
                                 "documented in the order of the "
                                 "signature)")
            return [lines[0], '', *lines[i + 1:]], param_docs
        return lines[:1], param_docs


# -- one-line clinic blocks completed from the spec ---------------------------

@dc.dataclass
class SpecBlock:
    """A one-line clinic block of the C file completed from the spec."""
    # The spec method: "T.meth".
    name: str
    # The lines replacing the function line, with where each is written.
    lines: list[tuple[str, Location]]
    # Where the method is declared: its def, or the shared method.
    location: Location
    # Where each clinic decorator of the method is written: {name: where}.
    decorators: dict[str, Location]
    # Where its docstring starts, or None (the checks of the docstring).
    docstring: Location | None = None


def _valid_line(line: str) -> bool:
    """A line of the start of a block that is not blank or a comment."""
    return bool(line.strip()) and not line.lstrip().startswith('#')


def function_line_index(lines: list[str],
                        directives: Collection[str]) -> int | None:
    """The index of the function line of a block, if the block is only
    that line (and directives, and @getter or @setter): such a block may
    take the rest of its input from the spec (complete_block()).  A
    function line that clones (``=``) does not qualify."""
    stub = None
    for index, line in enumerate(lines):
        if not _valid_line(line):
            continue
        if stub is not None:
            # Parameters or a docstring: a complete block.
            return None
        name = shlex.split(line)[0]
        if name == '@deleter':
            return None
        if name not in directives:
            stub = index
    if stub is None or '=' in lines[stub]:
        return None
    return stub


def _binding_error(message: str) -> SpecError:
    """An error of a block of the C file: clinic reports it there."""
    return SpecError(message, kind=SpecErrorKind.BINDING)


def complete_block(spec: Spec, function_line: str, head: list[str],
                   cls_name: str | None, directives: Collection[str]
                   ) -> SpecBlock | None:
    """The rest of a one-line block from the spec method it names: the
    lines replacing *function_line* (decorators, function line,
    parameters and docstring), or None for a class the spec does not
    declare.  *head*: the lines of the block before the function line;
    *directives*: those of clinic (DSLParser.directives).  The checksum
    of the block is still that of the input in the C file."""
    names = function_line.partition('->')[0].partition(' as ')[0].strip()
    meth = names.rpartition('.')[2]
    if cls_name is None or cls_name not in spec.classes:
        return None
    name = f'{cls_name}.{meth}'
    accessor = ''
    for line in head:
        if _valid_line(line) and line.lstrip().startswith('@'):
            decorator = shlex.split(line)[0]
            if decorator[1:] in ACCESSOR_DECORATORS and not accessor:
                accessor = decorator[1:]
                continue
            raise _binding_error(f"{names!r}: {decorator} of a spec method "
                                 f"is written in {spec.filename}")
    # A shared method with a block is a clinic function of this class
    # declared by the method it names.
    decl_spec, decl_name = spec, name
    if accessor:
        if accessor not in spec.accessors.get(name, {}):
            raise _binding_error(f"{names!r} has no parameters or "
                                 f"docstring, and class {cls_name} in "
                                 f"{spec.filename} has no @{accessor} "
                                 f"{meth!r} to take them from")
    elif name in spec.shared and spec.shared[name].c_function is not None:
        raise _binding_error(f"{names!r} is the C function "
                             f"{spec.shared[name].c_function} "
                             f"({spec.filename}): remove its block")
    elif name in spec.shared:
        decl_spec, decl_name = spec.declaration(name)
        kind = decl_spec.method_kind(decl_name)
        if kind != CLINIC:
            raise _binding_error(f"{names!r} is not a clinic function: it "
                                 f"shares {decl_name}, a {kind} of "
                                 f"{decl_spec.filename}; remove its block")
        if spec.c_name(name)[1]:
            raise _binding_error(f"{names!r} is a clinic function: its "
                                 f"ac.stub() in {spec.filename} takes no "
                                 "keyword")
    elif name in spec.accessors:
        raise _binding_error(f"{names!r} is an accessor in {spec.filename}: "
                             "its block starts with @getter or @setter")
    elif name in spec.functions:
        kind = spec.method_kind(name)
        if kind != CLINIC:
            raise _binding_error(f"{names!r} is not a clinic function: it is "
                                 f"a {kind} of {spec.filename}; remove its "
                                 "block")
    if not accessor and not decl_spec.has_method(decl_name):
        raise _binding_error(f"{names!r} has no parameters or docstring, "
                             f"and class {cls_name} in {spec.filename} has "
                             f"no method {meth!r} to take them from")
    decl_decorators, suffix, rest = decl_spec.clinic_input(decl_name,
                                                           accessor)
    where = decl_spec.filename
    spec_decorators = [(line, (where, lineno))
                       for line, lineno in decl_decorators]
    if name in spec.shared:
        spec_decorators += [(line, (spec.filename, lineno)) for line, lineno
                            in spec.shared_decorators(name)]
    for line, (filename, lineno) in spec_decorators:
        decorator = line.split()[0]
        if decorator not in directives:
            raise SpecError(f"{names!r}: unknown clinic decorator "
                            f"{decorator}", filename=filename, lineno=lineno)
    if suffix.startswith(' -> ') and '->' in function_line:
        raise _binding_error(f"{names!r}: the return converter is written "
                             f"in {spec.filename}")
    c_name, _ = spec.c_name(name)
    if c_name is not None:
        if ' as ' in function_line:
            raise _binding_error(f"{names!r}: the C name is written in "
                                 f"{spec.filename} (@ac.stub(\"x\") or "
                                 "@ac.generate(\"x\"))")
        left, arrow, right = function_line.partition('->')
        function_line = (f'{left.rstrip()} as {c_name}'
                         + (f' {arrow}{right}' if arrow else ''))
    node = (spec.accessors[name][accessor] if accessor
            else decl_spec.functions[decl_name])
    location = (spec.filename, spec.shared[name].lineno
                if name in spec.shared else node.lineno)
    indent = function_line[:len(function_line) - len(function_line.lstrip())]
    docstring = ((where, node.body[0].lineno)
                 if docstring_of(node.body) is not None else None)
    return SpecBlock(
        name, [*spec_decorators,
               (function_line.rstrip() + suffix, (where, node.lineno)),
               *[(indent + line if line else line, (where, lineno))
                 for line, lineno in rest]],
        location, {line.split()[0][1:]: loc for line, loc in spec_decorators},
        docstring)

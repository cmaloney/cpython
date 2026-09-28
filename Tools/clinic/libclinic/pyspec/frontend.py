"""Read a pyspec file: the Python side of Argument Clinic functions.

(For contributors: Objects/pyspec/README.rst.  This docstring is about the
implementation.)

For Objects/foo.c the spec is Objects/pyspec/foo.py, ordinary Python in
the style of a typeshed stub.  It is read with the ast module; clinic never
executes it.

``class T:`` holds one method per clinic function of the clinic class
named T.  A method is written like the clinic block it replaces:

* parameters are clinic parameter lines: the converter is the annotation,
  then the default; ``/`` and ``*`` as in clinic (and Python).  The
  pseudo-argument ``c_param='x'`` of the converter is clinic's
  ``name as x`` (the name of the C parameter).  The first parameter of
  a method or a class method (``self``, ``cls``), when not annotated, is
  clinic's implicit one;
* ``@classmethod`` and ``@staticmethod`` as in Python (``__new__`` is
  implicitly a class method, like in Python);
* any other clinic decorator is written as a Python decorator of the same
  name and arguments: ``@permit_long_summary``,
  ``@text_signature("($self, sub[, start[, end]], /)")``,
  ``@critical_section``, ``@vectorcall``, ...  (see "Decorators" below);
* the return annotation, if any, is the clinic return converter;
* the docstring is the text help() shows after the signature: the summary,
  then the parameter section clinic renders ("  name" and the parameter
  docstring indented by 4), then the rest of the docstring;
* there are no clones, as Python has none: two methods with the same
  signature (``find`` and ``count``) are two full ``def`` statements, and
  clinic generates for the second what it generates for a clone;
* a body of ``...`` (or only a docstring) means the C impl is
  hand-written.  A real body implements the function (emit.py), if it
  and the signature are in the lowered subset (subset.py; describe()
  checks it first); with ``@c_implemented`` the C impl is hand-written
  and the body, any Python, is its Python reference.

Any signature clinic can state is a spec signature, and any Python is a
spec body: only the lowered subset is generated as C.

Each spec method has a one-line block in the .c file, above its impl:
the function line only (``bytes.split``).  complete_block() turns the
spec method into the rest of the block (clinic_input()), and clinic
writes the impl head into the block's output, as usual.  A missing
block is an error.  An accessor, ``@getter def attr(self)`` or
``@setter def attr(self, value: object)``, is a clinic function too; its
block names it with the same decorator (``@getter`` / ``T.attr``).
Clinic then binds the functions with a body to their clinic function
(DSLParser.bind_spec(), PyspecBindings).

The C basename of a spec method is clinic's default (``T`` for
``T.__new__``, ``T___init__`` for ``T.__init__``, ``T_meth`` otherwise);
``@c_name("x")`` gives another, as ``as x`` does in a block.

Top-level functions are C functions named like the function.  A real
body is generated.  ``@c_implemented`` marks a hand-written C function
whose body is its Python reference, never lowered to C; its annotations
are the C types of its parameters and result (see c_signature()).  A body
of ``...`` (or only a docstring) is a hand-written C function about which
nothing is known.  A spec imports the functions of other specs by name:
``from pyspec.abstract import PyNumber_AsSsize_t``, a path relative to
the directory of the C file, or to the source root (``from
Python.pyspec.errors import PyErr_BadInternalCall``).

Decorators
----------
Any clinic decorator may be written on a spec method as a Python
decorator with the same name and arguments (string or integer constants),
which runtime.py defines as an identity decorator: it only chooses how
clinic renders C, and clinic validates it as in a .c file.
(``@classmethod`` and ``@staticmethod`` are Python's own.)

C names: @c_name
----------------
``@c_name("x")`` names the C function of a method: it is clinic's
``meth as x``.  It is not passed to clinic as a decorator.  The keyword
form names the C function *and* the C interface it has, for methods that
are not clinic functions (see "Methods that are not clinic functions"):
``@c_name(sq_item="bytes_item")`` (a slot) or
``@c_name(METH_NOARGS="bytes_getnewargs")`` (a PyCFunction).

Methods that are not clinic functions (method_kind())
------------------------------------------------------
* A slot: a dunder of ``slotdefs[]`` (slots.py) other than ``__new__``
  and ``__init__``, a C function with the slot's typedef, with a body of
  ``...`` or, with ``@c_implemented``, a Python reference.  Its parameters
  are those of the slot wrapper, unannotated; it has no docstring.  Its C
  function is ``<class>_<slot without its prefix>`` unless @c_name says
  otherwise; a dunder that several slots can implement names them
  (``@c_name(mp_length="f", sq_length="f")``) unless another dunder of
  the class selected a slot it shares; a class declares every dunder of
  the slots it fills (typeobj.py).
* A hand-written PyCFunction: ``@c_name(METH_NOARGS="f")``,
  ``METH_O``, ``METH_VARARGS`` or ``METH_FASTCALL`` (pycfunction()):
  parameters unannotated, ``(self, /)``, ``(self, arg, /)`` or ``(self,
  /, *args)``, with ``**kwargs`` for METH_KEYWORDS; @classmethod,
  @staticmethod and @coexist add METH_CLASS, METH_STATIC and
  METH_COEXIST; its docstring as is, after the signature of
  @text_signature if any.  A slot may also have such an entry in the
  method table (``@c_name(mp_subscript="f", METH_O="f")`` and
  ``@coexist``).
* Shared: ``meth = module.Class.meth``, a method another spec declares
  (``from stringlib.pyspec import transmogrify``), or ``Class.meth`` of
  another class of this spec.  If the C file has a clinic block for it
  (``bytearray.strip``), it is a clinic function of this class with the
  parameters, docstring and decorators of that method; else its entry in
  the method table is the other's.  It may be decorated by calls:
  ``critical_section(...)`` (the clinic decorator; for an entry, clinic
  generates ``<class>_<meth>()`` calling the other's C function in a
  critical section on self) and ``c_name(METH_NOARGS="f")(...)`` (the
  entry calls f, a PyCFunction, with the other's docstring).

For the classes of the spec of a C file, clinic generates the method and
slot tables their PyTypeObject (written in C) names (typeobj.py).
"""


from __future__ import annotations

import ast
import dataclasses as dc
import os
import shlex
import sys

from collections.abc import Collection

from libclinic.errors import PYSPEC_README as README
from libclinic.errors import SpecError, SpecErrorKind
from . import builtin_types, slots, subset


# Annotations of the parameters of implemented spec functions, and the C
# type they stand for (the lowered subset, subset.py).  For methods, the
# annotations are clinic converters; Argument Clinic checks that they
# agree.
SPEC_CTYPES = subset.LOWERED_CTYPES

# The C types of the annotations of a @c_implemented function: these, and
# a string, which is the C type itself ('PyTypeObject *').
C_CTYPES = SPEC_CTYPES | {'Py_ssize_t': 'Py_ssize_t', 'int': 'int',
                          'None': 'void'}

TYPE_CTYPE = 'PyTypeObject *'

# Builtin types a spec class may describe, and their C type objects.
TYPE_OBJECTS = {tp.__name__: row.type_object
                for tp, row in builtin_types.TABLE.items()
                if row.check is not None}

# Clinic decorators that are also Python's: they set the kind of the
# method.  Any other decorator is a clinic-only one (see "Decorators"),
# except the spec's own: @c_name and @c_implemented.
METHOD_DECORATORS = ('classmethod', 'staticmethod')
SPEC_DECORATORS = ('c_name', 'c_implemented')

# The clinic decorators that make a def an accessor: in the C file, its
# one-line block names the accessor with the same decorator.
ACCESSOR_DECORATORS = ('getter', 'setter')

# The C calling conventions of a hand-written PyCFunction entry
# (``@c_name(METH_O="f")``), with the Python parameters after self each
# takes: none, one positional-only, or ``*args`` (and ``**kwargs``, which
# adds METH_KEYWORDS).
PYCFUNCTION_FLAGS = {
    'METH_NOARGS': '(self, /)',
    'METH_O': '(self, arg, /)',
    'METH_VARARGS': '(self, /, *args[, **kwargs])',
    'METH_FASTCALL': '(self, /, *args[, **kwargs])',
}

# Kinds of the methods of a spec class (see "Methods that are not clinic
# functions").
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
    lineno: int
    parameters: list[SpecParameter]
    # For a __new__: the Python name of its class.
    new_type: str | None = None


@dc.dataclass
class PyCFunctionEntry:
    """A hand-written PyCFunction of a method table
    (``@c_name(METH_O="f")``)."""
    c_function: str
    # METH_NOARGS, METH_O, METH_VARARGS or METH_FASTCALL.
    convention: str
    # The flags of its PyMethodDef: "METH_VARARGS | METH_KEYWORDS".
    flags: str


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
    spec (emit.py, typeobj.py): the bindings of the implemented spec
    methods ("bytes.__new__"), and the type object of each clinic class
    ("bytes": "&PyBytes_Type")."""
    functions: dict[str, SpecBinding] = dc.field(default_factory=dict)
    type_objects: dict[str, str] = dc.field(default_factory=dict)


def spec_path(filename: str) -> str:
    """Path of the spec file for the C file *filename*."""
    dirname, basename = os.path.split(filename)
    stem = os.path.splitext(basename)[0]
    return os.path.join(dirname, 'pyspec', stem + '.py')


def output_path(filename: str) -> str:
    """Path of the C generated from the spec of the C file *filename*."""
    dirname, basename = os.path.split(filename)
    stem = os.path.splitext(basename)[0]
    return os.path.join(dirname, 'clinic', stem + '_pyspec.c.h')


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


def is_stub(node: ast.FunctionDef) -> bool:
    """True if the body is only a docstring and/or ``...``.

    A stub is a function implemented in C by hand about which nothing is
    known: it is never lowered to C, and a call of it may do anything.
    """
    body = without_docstring(node)
    return not body or (len(body) == 1 and isinstance(body[0], ast.Expr)
                        and isinstance(body[0].value, ast.Constant)
                        and body[0].value.value is Ellipsis)


def is_placeholder(node: ast.FunctionDef) -> bool:
    """True for ``def meth(self): ...``: only the place of a method whose
    signature depends on #if, which keeps its full clinic block in C."""
    args = node.args
    return (is_stub(node) and docstring_of(node.body) is None
            and len(args.posonlyargs + args.args) == 1
            and not (args.vararg or args.kwonlyargs or args.kwarg))


def decorator_name(decorator: ast.expr) -> str | None:
    """``name`` for ``@name`` and ``@name(...)``."""
    if isinstance(decorator, ast.Call):
        decorator = decorator.func
    return decorator.id if isinstance(decorator, ast.Name) else None


def accessor_kind(node: ast.FunctionDef) -> str:
    """'getter' or 'setter' for an accessor (``@getter``, ``@setter``),
    else ''."""
    for decorator in node.decorator_list:
        name = decorator_name(decorator)
        if name in ACCESSOR_DECORATORS:
            return name
    return ''


def is_c_implemented(node: ast.FunctionDef) -> bool:
    """True for ``@c_implemented``: a hand-written C function whose body
    is its Python reference."""
    return any(decorator_name(d) == 'c_implemented'
               for d in node.decorator_list)


def is_struct(ctype: str) -> bool:
    """Whether C type *ctype* (of c_signature()) is a C struct: neither a
    pointer nor a scalar."""
    return '*' not in ctype and ctype not in C_CTYPES.values() \
        and ctype.split()[-1] not in ('char', 'short', 'int', 'long')


def c_signature(node: ast.FunctionDef) -> tuple[list[tuple[str, str]], str]:
    """([(parameter, C type)], C return type) of a @c_implemented
    function: an annotation of C_CTYPES or a string (the C type); no
    return annotation is ``PyObject *``.  A return type that is neither
    a scalar nor a pointer is a C struct that the function initializes in
    place (see emit.py)."""
    def ctype(annotation: ast.expr | None, default: str | None) -> str:
        match annotation:
            case None if default is not None:
                return default
            case ast.Constant(str() as text):
                return text
            case ast.Name(name) if name in C_CTYPES:
                return C_CTYPES[name]
            case ast.Constant(None):
                return 'void'
        raise SpecError(f"{node.name}(): the annotations of a "
                        f"@c_implemented function are C types: "
                        f"{sorted(C_CTYPES)} or a string",
                        lineno=getattr(annotation, 'lineno', node.lineno))
    args = node.args.posonlyargs + node.args.args
    return ([(a.arg, ctype(a.annotation, None)) for a in args],
            ctype(node.returns, 'PyObject *'))


@dc.dataclass
class Shared:
    """``meth = module.Class.meth`` in a spec class (``Class.meth`` for a
    class of the same spec), possibly decorated by calls:
    ``critical_section(...)``, ``c_name(METH_NOARGS="f")(...)``."""
    module: str | None
    cls: str
    meth: str
    lineno: int
    decorators: list[ast.expr] = dc.field(default_factory=list)

# The decorators a shared method may have (see "Methods that are not
# clinic functions").
SHARED_DECORATORS = ('critical_section', 'c_name')


class Spec:
    def __init__(self, source: str, filename: str = '<spec>') -> None:
        self.filename = filename
        self.source = source
        self.module = ast.parse(source, filename)
        # Top-level functions by name and methods by "T.name", in the
        # order of the file.
        self.functions: dict[str, ast.FunctionDef] = {}
        self.classes: dict[str, ast.ClassDef] = {}
        self.shared: dict[str, Shared] = {}
        # Accessors by "T.name": {"getter": def, "setter": def}.
        self.accessors: dict[str, dict[str, ast.FunctionDef]] = {}
        # Specs imported with ``from pkg import module``: name -> path.
        self.imports: dict[str, str] = {}
        self._specs: dict[str, Spec] = {}     # load_spec()
        # Functions imported with ``from pkg.module import f``: name ->
        # path of the spec.
        self.imported_functions: dict[str, str] = {}
        for node in self.module.body:
            match node:
                case ast.FunctionDef(name=name):
                    self._add_function(name, node)
                case ast.ClassDef():
                    self._add_class(node)
                case ast.ImportFrom():
                    self._add_import(node)
                case ast.Import(names=names) if all(
                        a.name in sys.stdlib_module_names for a in names):
                    pass    # for the Python reference of a function
                case ast.Import():
                    raise self.error(node, "import a spec as 'from "
                                     "stringlib.pyspec import transmogrify' "
                                     "(a path relative to the directory of "
                                     "the C file)")

    def error(self, node: ast.AST | None, message: str,
              kind: SpecErrorKind = SpecErrorKind.INVALID) -> SpecError:
        """A SpecError at the line of *node*, in this spec unless *node*
        was copied from another (see SpecError.at())."""
        return SpecError.at(node, message, kind, self.filename)

    def _check_def(self, name: str, node: ast.FunctionDef) -> None:
        if is_c_implemented(node) and is_stub(node):
            raise self.error(node, f"{name}: the body of a @c_implemented "
                             "function is its Python reference; write ... "
                             "without @c_implemented for a C function "
                             "about which nothing is known")
        body = without_docstring(node)
        if len(body) == 1 and isinstance(body[0], ast.Pass):
            raise self.error(body[0], f"{name}: use ... as the body of a "
                             "function implemented in C, not pass")

    def _add_function(self, name: str, node: ast.FunctionDef) -> None:
        self._check_def(name, node)
        if (name in self.functions or name in self.shared
                or name in self.accessors):
            raise self.error(node, f"{name} is defined twice")
        self.functions[name] = node

    def _add_accessor(self, name: str, kind: str,
                      node: ast.FunctionDef) -> None:
        """``@getter def attr(self)`` / ``@setter def attr(self, value)``
        in a class: the accessors of attribute *name* ("T.attr"), each a
        clinic function whose one-line block in the C file starts with
        the same decorator."""
        self._check_def(name, node)
        if sum(decorator_name(d) in ACCESSOR_DECORATORS
               for d in node.decorator_list) > 1:
            raise self.error(node, f"{name}: only one of @getter and "
                             "@setter")
        accessors = self.accessors.setdefault(name, {})
        if kind in accessors or name in self.functions \
                or name in self.shared:
            raise self.error(node, f"{name} is defined twice")
        if not (is_stub(node) or is_c_implemented(node)):
            raise self.error(node, f"{name}(): an accessor with a body is "
                             "expressible, but not lowered to C yet",
                             SpecErrorKind.NOT_LOWERED)
        accessors[kind] = node

    def _add_import(self, node: ast.ImportFrom) -> None:
        """``from stringlib.pyspec import transmogrify``: the spec
        Objects/stringlib/pyspec/transmogrify.py; ``from pyspec.abstract
        import PyNumber_AsSsize_t``: that function of the spec
        Objects/pyspec/abstract.py.  Paths are relative to the directory
        of the C file of this spec, else to the source root (its
        parent).  Imports of the standard library are for the Python
        references of @c_implemented functions."""
        if node.module is None or node.module.startswith('libclinic') \
                or node.module in sys.stdlib_module_names:
            return
        base = os.path.dirname(os.path.dirname(os.path.abspath(
            self.filename)))
        parts = node.module.split('.')
        for alias in node.names:
            name = alias.asname or alias.name
            for root in (base, os.path.dirname(base)):
                path = os.path.join(root, *parts, alias.name + '.py')
                if os.path.exists(path):
                    self.imports[name] = path
                    break
                path = os.path.join(root, *parts) + '.py'
                if os.path.exists(path):
                    self.imported_functions[name] = path
                    break
            else:
                path = os.path.join(base, *parts, alias.name + '.py')
                raise self.error(node, f"imported spec {path} not found")

    def imported(self, module: str) -> Spec:
        """The spec imported as *module*."""
        return self.load_spec(self.imports[module])

    def load_spec(self, path: str) -> Spec:
        """The spec at *path*, imported by this one (or by a spec it
        imports): read once."""
        path = os.path.abspath(path)
        if path == os.path.abspath(self.filename):
            return self
        if path not in self._specs:
            spec = Spec.load(path)
            assert spec is not None
            self._specs[path] = spec
        return self._specs[path]

    def resolve(self, name: str) -> tuple[Spec, ast.FunctionDef] | None:
        """(the spec defining it, its def) of the function *name* of this
        spec or imported by it, or None."""
        if name in self.functions:
            return self, self.functions[name]
        path = self.imported_functions.get(name)
        if path is None:
            return None
        return self.load_spec(path).resolve(name)

    def c_function(self, call: ast.Call
                   ) -> tuple[Spec, ast.FunctionDef] | None:
        """(spec, def) of the hand-written C function *call* calls (by
        name): @c_implemented or a stub, of this spec or imported.  A
        call copied from another spec (a fast path, see partial_eval.py)
        names the spec it was written in (``pyspec_scope``)."""
        func = call.func
        if not isinstance(func, ast.Name):
            return None
        found = self.load_spec(getattr(call, 'pyspec_scope',
                                       self.filename)).resolve(func.id)
        if found is None or found[0].implemented(func.id):
            return None
        return found

    @classmethod
    def load(cls, path: str) -> Spec | None:
        try:
            with open(path, encoding='utf-8') as f:
                source = f.read()
        except FileNotFoundError:
            return None
        return cls(source, path)

    def _add_class(self, node: ast.ClassDef) -> None:
        """Only these statements may be in a spec class: a docstring,
        ``def``, ``meth = module.Class.meth`` and ``pass``."""
        self.classes[node.name] = node
        for i, stmt in enumerate(node.body):
            match stmt:
                case ast.Expr(ast.Constant(str())) if i == 0:
                    pass
                case ast.Pass():
                    pass
                case ast.FunctionDef(name=name) if accessor_kind(stmt):
                    self._add_accessor(f'{node.name}.{name}',
                                       accessor_kind(stmt), stmt)
                case ast.FunctionDef(name=name):
                    self._add_function(f'{node.name}.{name}', stmt)
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
        """``name = module.cls.meth``: a method declared in another spec
        (or another class of this one)."""
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
            if decorator_name(decorator) not in SHARED_DECORATORS:
                raise self.error(decorator, f"a shared method takes only "
                                 f"{' and '.join(SHARED_DECORATORS)}, not "
                                 f"{ast.unparse(decorator)}")
        self.shared[f'{cls_name}.{name}'] = Shared(module, cls, meth,
                                                   stmt.lineno, decorators)

    def shared_source(self, name: str) -> tuple[Spec, str]:
        """(spec, "Class.meth") declaring shared method *name*."""
        shared = self.shared[name]
        other = self.imported(shared.module) if shared.module else self
        return other, f'{shared.cls}.{shared.meth}'

    def declaration(self, name: str) -> tuple[Spec, str]:
        """(spec, "Class.meth") of the def declaring method *name*."""
        if name in self.shared:
            return self.shared_source(name)
        return self, name

    def shared_decorators(self, name: str) -> list[tuple[str, int]]:
        """The clinic decorator lines of shared method *name*, with their
        line in this spec: ``critical_section(...)``."""
        return [(self._decorator_line(d), d.lineno)
                for d in self.shared[name].decorators
                if decorator_name(d) not in SPEC_DECORATORS]

    def is_locked(self, name: str) -> bool:
        """Whether shared method *name* is ``critical_section(...)``."""
        return any(decorator_name(d) == 'critical_section'
                   for d in self.shared[name].decorators)

    # -- implemented functions ---------------------------------------------

    def implemented(self, name: str) -> bool:
        """Whether spec function *name* has a body lowered to C: a
        top-level function or a clinic method with a body other than
        ``...``, not @c_implemented.  (Slots and hand-written
        PyCFunctions are C: typeobj.py rejects a body.)"""
        node = self.functions.get(name)
        if node is None or is_stub(node) or is_c_implemented(node):
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
        """The implemented spec function called as *func*, if any.

        ``f(...)`` calls top-level f; ``T.m(...)`` calls method m of the
        spec class T.
        """
        match func:
            case ast.Name(name):
                pass
            case ast.Attribute(ast.Name(cls), meth) if cls in self.classes:
                name = f'{cls}.{meth}'
            case _:
                return None
        return name if self.implemented(name) else None

    def c_implemented_functions(self) -> list[str]:
        return [name for name, node in self.functions.items()
                if is_c_implemented(node)]

    def describe(self, name: str,
                 self_ctype: str = 'PyObject *') -> SpecFunction:
        """The C signature of implemented spec function *name*: a
        top-level function, a __new__ (its class is a PyTypeObject *), or
        another method, whose self (or class) parameter has C type
        *self_ctype* (clinic's, see SpecBinding).

        First, the signature and the body must be in the lowered subset
        (subset.py): else a SpecError (NOT_LOWERED) says what is not."""
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
                    ctype = SPEC_CTYPES[conv]
                case _:
                    raise AssertionError('checked by subset.py')
            parameters.append(SpecParameter(arg.arg, ctype,
                                            i >= first_optional))
        return SpecFunction(name, self.filename, node.lineno, parameters,
                            new_type)

    # -- kinds of methods and C names --------------------------------------

    def c_name(self, name: str) -> tuple[str | None, dict[str, str]]:
        """The arguments of @c_name of method *name*: (positional C name
        or None, {slot or METH_ flag: C name}).  For a shared method, the
        @c_name of this spec (``c_name(...)(module.Class.meth)``)."""
        if name in self.shared:
            decorators = self.shared[name].decorators
        elif name in self.functions:
            decorators = self.functions[name].decorator_list
        else:
            return None, {}
        for decorator in decorators:
            match decorator:
                case ast.Call(func=ast.Name('c_name'), args=args,
                              keywords=keywords):
                    values = [*args, *(kw.value for kw in keywords)]
                    strings = [v.value for v in values
                               if isinstance(v, ast.Constant)
                               and isinstance(v.value, str)]
                    if len(strings) != len(values) \
                            or any(kw.arg is None for kw in keywords):
                        raise self.error(decorator, "the arguments of "
                                         "@c_name are strings")
                    if len(args) > 1 or (args and keywords) or not values:
                        raise self.error(decorator, "write @c_name(\"x\") "
                                         "or @c_name(slot=\"x\", ...)")
                    if args:
                        return strings[0], {}
                    return None, {str(kw.arg): value
                                  for kw, value in zip(keywords, strings)}
                case ast.Name('c_name'):
                    raise self.error(decorator, "@c_name needs the C name")
        return None, {}

    def pycfunction(self, name: str) -> PyCFunctionEntry | None:
        """The hand-written PyCFunction entry of method *name*
        (``@c_name(METH_O="f")``), or None.  The parameters of the def
        after self give its calling convention; @classmethod,
        @staticmethod and @coexist add METH_CLASS, METH_STATIC and
        METH_COEXIST."""
        _, keywords = self.c_name(name)
        given = [(k, v) for k, v in keywords.items()
                 if k in PYCFUNCTION_FLAGS]
        if not given:
            return None
        node = self.functions[name]
        if len(given) > 1:
            raise self.error(node, f"{name}: one calling convention of "
                             f"{sorted(PYCFUNCTION_FLAGS)} in @c_name")
        (convention, c_function), = given
        decorators = [decorator_name(d) for d in node.decorator_list]
        static = 'staticmethod' in decorators
        args = node.args
        positional = args.posonlyargs + args.args
        if not static:
            positional = positional[1:]
        match convention:
            case 'METH_NOARGS':
                ok = not positional
            case 'METH_O':
                ok = len(positional) == 1
            case _:
                ok = not positional and args.vararg is not None
        if (not ok or args.kwonlyargs or args.defaults
                or (args.kwarg and convention in ('METH_NOARGS', 'METH_O'))
                or (args.vararg and convention in ('METH_NOARGS', 'METH_O'))
                or args.args):
            wanted = PYCFUNCTION_FLAGS[convention]
            if static:
                wanted = wanted.replace('self, ', '').replace('self', '')
            raise self.error(node, f"{name}: a {convention} function takes "
                             f"{wanted}")
        flags = [convention]
        if args.kwarg:
            flags.append('METH_KEYWORDS')
        if 'classmethod' in decorators:
            flags.append('METH_CLASS')
        if static:
            flags.append('METH_STATIC')
        if 'coexist' in decorators:
            flags.append('METH_COEXIST')
        return PyCFunctionEntry(c_function, convention, ' | '.join(flags))

    def method_kind(self, name: str) -> str:
        """CLINIC, SLOT, PYCFUNCTION, SHARED or ACCESSOR (see "Methods
        that are not clinic functions")."""
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
            raise self.error(self.functions[name], f"{name}: @c_name with a "
                             "keyword names a slot of a dunder or one of "
                             f"{sorted(PYCFUNCTION_FLAGS)}")
        return CLINIC

    def entries(self, cls_name: str) -> list[str]:
        """Names of all the methods and shared methods of class
        *cls_name*, in order (not its accessors: their table, tp_getset,
        is written in C)."""
        names = []
        for stmt in self.classes[cls_name].body:
            match stmt:
                case ast.FunctionDef(name=name) if not accessor_kind(stmt):
                    names.append(name)
                case ast.Assign(targets=[ast.Name(name)]):
                    names.append(name)
        return names

    def declares_slots(self, cls_name: str) -> bool:
        """True if class *cls_name* declares a slot (a dunder of
        slotdefs[]).  Such a class describes its whole type: Argument
        Clinic generates its method and slot tables, and test_clinic
        compares all its slots with the type.  A class without slots
        declares methods only; their table stays in C."""
        return any(self.method_kind(f'{cls_name}.{meth}') == SLOT
                   for meth in self.entries(cls_name))

    def docstring(self, name: str) -> str | None:
        """The docstring of method *name* as __doc__ shows it (the
        indentation of the source removed), or None."""
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
        """Clinic DSL for spec method *name*, or for its *accessor*
        ('getter' or 'setter', which the block in the C file names).

        Return (decorator lines, text to append to the function line,
        the lines after the function line); each line comes with the line
        of the spec it is taken from, where clinic reports its errors.
        """
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
        """Clinic decorator lines of *node*, in order, with their line in
        the spec, and the kind of *node*.  *skip*: a decorator written
        in the block of the C file (@getter, @setter)."""
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
        """The source text of *node*, on one line."""
        text = ast.get_source_segment(self.source, node)
        assert text is not None
        if '\n' in text:
            raise self.error(node, f"write the {what} on one line")
        return text

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
        """Separate the parameter section clinic renders after the summary.

        Return the clinic docstring and the parameter docstrings.
        """
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
    """The rest of a one-line block from the spec method it names, if it
    names a method of a class of the spec: the lines replacing
    *function_line* (the clinic decorators of the method, the function
    line, and the parameters and docstring).  None for a function of a
    class the spec does not declare.

    *head* holds the lines of the block before the function line;
    *cls_name* is the clinic class of the function; *directives* are the
    clinic directives and decorators (DSLParser.directives).  The
    checksum of the block is still computed on the input in the C file.
    """
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
    elif name in spec.shared:
        decl_spec, decl_name = spec.declaration(name)
        kind = decl_spec.method_kind(decl_name)
        if kind != CLINIC:
            raise _binding_error(f"{names!r} is not a clinic function: it "
                                 f"shares {decl_name}, a {kind} of "
                                 f"{decl_spec.filename}; remove its block")
        if spec.c_name(name)[1]:
            raise _binding_error(f"{names!r} is a clinic function: its "
                                 f"@c_name in {spec.filename} takes no "
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
                                 f"{spec.filename} (@c_name)")
        left, arrow, right = function_line.partition('->')
        function_line = (f'{left.rstrip()} as {c_name}'
                         + (f' {arrow}{right}' if arrow else ''))
    if accessor:
        node = spec.accessors[name][accessor]
        location = (spec.filename, node.lineno)
    elif name in spec.shared:
        node = decl_spec.functions[decl_name]
        location = (spec.filename, spec.shared[name].lineno)
    else:
        node = spec.functions[name]
        location = (spec.filename, node.lineno)
    indent = function_line[:len(function_line) - len(function_line.lstrip())]
    return SpecBlock(
        name, [*spec_decorators,
               (function_line.rstrip() + suffix, (where, node.lineno)),
               *[(indent + line if line else line, (where, lineno))
                 for line, lineno in rest]],
        location, {line.split()[0][1:]: loc for line, loc in spec_decorators})

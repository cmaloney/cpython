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
  hand-written.  A real body implements the function: see emit.py.

Each spec method has a one-line block in the .c file, above its impl:
the function line only (``bytes.split``).  clinic_input() turns the spec
method into the rest of the block, and clinic writes the impl head into
the block's output, as usual.  A missing block is an error.

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
* A hand-written PyCFunction: ``@c_name(METH_NOARGS="f")`` or
  ``@c_name(METH_O="f")``, parameters ``(self, /)`` or ``(self, arg, /)``
  unannotated, its docstring as is.
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

A class decorated with ``@static_type(...)`` has its PyTypeObject
generated (typeobj.py); its keyword arguments are the members the spec
cannot derive, as C expressions.
"""


from __future__ import annotations

import ast
import dataclasses as dc
import os
import shlex
import sys

from libclinic.errors import ClinicError
from . import builtin_types, slots


# Where errors about unsupported spec code send the reader.
README = 'Objects/pyspec/README.rst'

# Annotations of the parameters of implemented spec functions, and the C
# type they stand for.  For methods, the annotations are clinic converters;
# Argument Clinic checks that they agree.
SPEC_CTYPES = {
    'object': 'PyObject *',
    'str': 'const char *',
}

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
# except the spec's own: @c_name.
METHOD_DECORATORS = ('classmethod', 'staticmethod')
SPEC_DECORATORS = ('c_name',)

# The C calling conventions of a hand-written PyCFunction entry, with the
# number of parameters after self.
PYCFUNCTION_FLAGS = {'METH_NOARGS': 0, 'METH_O': 1}

# Kinds of the methods of a spec class (see "Methods that are not clinic
# functions").
CLINIC, SLOT, PYCFUNCTION, SHARED = 'clinic', 'slot', 'pycfunction', 'shared'


class SpecError(ClinicError):
    """An error in a spec file, located at its line, reported by clinic
    as ``path:line: error: message``."""


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


def _docstring(body: list[ast.stmt]) -> str | None:
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


def _without_docstring(node: ast.FunctionDef) -> list[ast.stmt]:
    return node.body[1:] if _docstring(node.body) is not None else node.body


def is_stub(node: ast.FunctionDef) -> bool:
    """True if the body is only a docstring and/or ``...``.

    A stub is a function implemented in C by hand about which nothing is
    known: it is never lowered to C, and a call of it may do anything.
    """
    body = _without_docstring(node)
    return not body or (len(body) == 1 and isinstance(body[0], ast.Expr)
                        and isinstance(body[0].value, ast.Constant)
                        and body[0].value.value is Ellipsis)


def decorator_name(decorator: ast.expr) -> str | None:
    """``name`` for ``@name`` and ``@name(...)``."""
    if isinstance(decorator, ast.Call):
        decorator = decorator.func
    return decorator.id if isinstance(decorator, ast.Name) else None


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

    def error(self, node: ast.AST | None, message: str) -> SpecError:
        """A SpecError at the line of *node*."""
        return SpecError(message, filename=self.filename,
                         lineno=getattr(node, 'lineno', None))

    def _add_function(self, name: str, node: ast.FunctionDef) -> None:
        if is_c_implemented(node) and is_stub(node):
            raise self.error(node, f"{name}: the body of a @c_implemented "
                             "function is its Python reference; write ... "
                             "without @c_implemented for a C function "
                             "about which nothing is known")
        if name in self.functions or name in self.shared:
            hint = ''
            if any(decorator_name(d) in ('getter', 'setter')
                   for d in node.decorator_list):
                hint = f" (accessors are not supported yet: see {README})"
            raise self.error(node, f"{name} is defined twice{hint}")
        body = _without_docstring(node)
        if len(body) == 1 and isinstance(body[0], ast.Pass):
            raise self.error(body[0], f"{name}: use ... as the body of a "
                             "function implemented in C, not pass")
        self.functions[name] = node

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
        static = any(decorator_name(d) == 'static_type'
                     for d in node.decorator_list)
        for i, stmt in enumerate(node.body):
            match stmt:
                case ast.Expr(ast.Constant(str())) if i == 0:
                    pass
                case ast.Pass():
                    pass
                case ast.FunctionDef(name=name):
                    self._add_function(f'{node.name}.{name}', stmt)
                    for d in stmt.decorator_list:
                        if static and decorator_name(d) in ('getter',
                                                            'setter'):
                            raise self.error(d, f"{node.name}.{name}: "
                                             "accessors (@getter, @setter) "
                                             "of a @static_type class are "
                                             f"not supported yet; see "
                                             f"{README}")
                case ast.Assign(targets=[ast.Name(name)], value=value) \
                        if self._shared_source(value) is not None:
                    self._add_shared(node.name, stmt, name,
                                     *self._shared_source(value))
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
        """Whether spec function *name* has a body lowered to C."""
        node = self.functions.get(name)
        if node is None or is_stub(node) or is_c_implemented(node):
            return False
        # Slots and hand-written PyCFunctions are C: typeobj.py rejects a
        # body.
        try:
            return '.' not in name or self.method_kind(name) == CLINIC
        except SpecError:
            return True

    def implemented_functions(self) -> list[str]:
        return [name for name in self.functions if self.implemented(name)]

    def body(self, name: str) -> list[ast.stmt]:
        """Statements of function *name*, without its docstring."""
        return _without_docstring(self.functions[name])

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
                 self_ctype: str | None = None) -> SpecFunction:
        """The C signature of implemented spec function *name*: a
        top-level function, a __new__, or, with *self_ctype* (the C type
        of clinic's implicit self or class parameter, e.g.
        "PyBytesObject *"), another method."""
        node = self.functions[name]
        args = node.args
        cls_name, _, meth = name.rpartition('.')

        def error(node: ast.AST, message: str) -> SpecError:
            return self.error(node, f"{name}(): {message}")

        if cls_name and meth != '__new__' and self_ctype is None:
            raise error(node, "a spec can only implement __new__")
        others = [args.vararg, *args.kwonlyargs, args.kwarg]
        for other in others:
            if other is not None:
                raise error(other, "a spec needs positional parameters "
                            f"only; {other.arg!r} is not")
        positional = args.posonlyargs + args.args
        first_optional = len(positional) - len(args.defaults)
        parameters = []
        new_type = None
        for i, arg in enumerate(positional):
            if cls_name and i == 0:
                if arg.annotation is not None:
                    raise error(arg, f"the self (or class) parameter "
                                f"{arg.arg!r} must not be annotated")
                if meth == '__new__':
                    if cls_name not in TYPE_OBJECTS:
                        raise error(node, f"unknown type {cls_name!r}; "
                                    f"known: {sorted(TYPE_OBJECTS)}")
                    new_type, self_ctype = cls_name, TYPE_CTYPE
                parameters.append(SpecParameter(arg.arg, self_ctype, False))
                continue
            match arg.annotation:
                case ast.Name(conv) | ast.Call(func=ast.Name(conv)) \
                        if conv in SPEC_CTYPES:
                    ctype = SPEC_CTYPES[conv]
                case _:
                    raise error(arg, f"parameter {arg.arg!r} needs an "
                                f"annotation from {sorted(SPEC_CTYPES)}")
            optional = i >= first_optional
            if optional:
                default = args.defaults[i - first_optional]
                if not (isinstance(default, ast.Name)
                        and default.id == 'NULL'):
                    raise error(arg, f"parameter {arg.arg!r} may only "
                                "default to NULL")
            parameters.append(SpecParameter(arg.arg, ctype, optional))
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
                    if not all(isinstance(v, ast.Constant)
                               and isinstance(v.value, str)
                               for v in values):
                        raise self.error(decorator, "the arguments of "
                                         "@c_name are strings")
                    if len(args) > 1 or (args and keywords) or not values:
                        raise self.error(decorator, "write @c_name(\"x\") "
                                         "or @c_name(slot=\"x\", ...)")
                    positional = args[0].value if args else None
                    return positional, {kw.arg: kw.value.value
                                        for kw in keywords}
                case ast.Name('c_name'):
                    raise self.error(decorator, "@c_name needs the C name")
        return None, {}

    def method_kind(self, name: str) -> str:
        """CLINIC, SLOT, PYCFUNCTION or SHARED (see "Methods that are not
        clinic functions")."""
        if name in self.shared:
            return SHARED
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
        *cls_name*, in order."""
        names = []
        for stmt in self.classes[cls_name].body:
            match stmt:
                case ast.FunctionDef(name=name):
                    names.append(name)
                case ast.Assign(targets=[ast.Name(name)]):
                    names.append(name)
        return names

    def docstring(self, name: str) -> str | None:
        """The docstring of method *name* as __doc__ shows it (the
        indentation of the source removed), or None."""
        node = self.functions[name]
        doc = _docstring(node.body)
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

    def clinic_input(self, name: str
                     ) -> tuple[list[tuple[str, int]], str,
                                list[tuple[str, int]]]:
        """Clinic DSL for spec method *name*.

        Return (decorator lines, text to append to the function line,
        the lines after the function line); each line comes with the line
        of the spec it is taken from, where clinic reports its errors.
        """
        node = self.functions[name]
        decorators, kind = self._decorators(node)
        suffix = ''
        if node.returns is not None:
            suffix = f' -> {self._segment(node.returns, "return converter")}'
        params = self._parameter_lines(node, kind)
        names = [pname for _, pname, _ in params if pname]
        param_docs: dict[str, list[str]] = {}
        docstring: list[str] = []
        doc = _docstring(node.body)
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

    def _decorators(self, node: ast.FunctionDef
                    ) -> tuple[list[tuple[str, int]], str]:
        """Clinic decorator lines of *node*, in order, with their line in
        the spec, and the kind of *node*."""
        kind = 'method'
        decorators = []
        for decorator in node.decorator_list:
            if decorator_name(decorator) in SPEC_DECORATORS:
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

"""Read a pyspec file: the Python side of Argument Clinic functions.

For Objects/foo.c the spec is Objects/pyspec/foo.py, ordinary Python in
the style of a typeshed stub.  It is read with the ast module; clinic never
executes it.

``class T:`` holds one method per clinic function of the clinic class
named T.  A method is written like the clinic block it replaces:

* parameters are clinic parameter lines: the converter is the annotation,
  then the default; ``/`` and ``*`` as in clinic (and Python).  The
  pseudo-argument ``c_name='x'`` of the converter is clinic's
  ``name as x``.  The first parameter of a method or a class method
  (``self``, ``cls``), when not annotated, is clinic's implicit one;
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
* ``meth = other`` in the class body is a clinic clone
  (``T.meth = T.other``); the string literal following it, if any, is its
  docstring.  A decorated clone is written as the call a decorator stands
  for: ``meth = permit_long_summary(other)``;
* a body of ``...`` (or only a docstring) means the C impl is
  hand-written.  A real body implements the function: see emit.py.

The .c file keeps, per function, a clinic block with the function line
only (``bytes.split``); clinic_input() turns the spec method into the rest
of the block.  The C basename of a spec method is clinic's default, except
that ``T.__new__`` and ``T.__init__`` are named ``T_new`` and ``T_init``,
as most hand-written ``as`` clauses of Objects/ name them (clinic's
default would be ``T`` and ``T___init__``).

Top-level functions are C functions named like the function.  A body of
``...`` (or only a docstring) describes a hand-written C function; a real
body is generated.

Decorators
----------
The rule is: any clinic decorator may be written on a spec method as a
Python decorator with the same name and arguments, and runtime.py defines
each as an identity decorator.  This is the whole rule, because:

* a clinic decorator already is a per-function fact written above the
  function line, and a Python decorator is written in the same place with
  the same shape (``@name`` or ``@name(args)``), so the translation is
  mechanical both ways and needs no table of meanings in the frontend:
  clinic itself validates the names and arguments, as it does in a .c
  file;
* none of them changes what the function does when called from Python:
  they choose how clinic renders C (text signature, calling convention,
  locking, accessor kind) or silence a docstring lint.  An identity
  decorator is therefore the exact Python meaning, and the spec stays an
  ordinary, runnable Python file.  (``@classmethod`` and ``@staticmethod``
  are the two that do change the Python meaning; they are Python's own.)

A decorator's arguments must be string or integer constants, since a
clinic decorator line only holds words.
"""

from __future__ import annotations

import ast
import dataclasses as dc
import os
import shlex


# Annotations of the parameters of implemented spec functions, and the C
# type they stand for.  For methods, the annotations are clinic converters;
# Argument Clinic checks that they agree.
SPEC_CTYPES = {
    'object': 'PyObject *',
    'str': 'const char *',
    'cstr': 'const char *',
}

TYPE_CTYPE = 'PyTypeObject *'

# Builtin types a spec class may describe, and their C type objects.
TYPE_OBJECTS = {
    'bytes': '&PyBytes_Type',
    'bytearray': '&PyByteArray_Type',
    'str': '&PyUnicode_Type',
    'int': '&PyLong_Type',
    'float': '&PyFloat_Type',
    'complex': '&PyComplex_Type',
    'bool': '&PyBool_Type',
    'list': '&PyList_Type',
    'tuple': '&PyTuple_Type',
    'dict': '&PyDict_Type',
    'set': '&PySet_Type',
    'frozenset': '&PyFrozenSet_Type',
}

# Clinic decorators that are also Python's: they set the kind of the
# method.  Any other decorator is a clinic-only one (see "Decorators").
METHOD_DECORATORS = ('classmethod', 'staticmethod')


class SpecError(Exception):
    pass


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

    @property
    def type_object(self) -> str | None:
        if self.new_type is None:
            return None
        return TYPE_OBJECTS[self.new_type]


@dc.dataclass
class Clone:
    """``meth = target`` in a spec class."""
    target: str
    lineno: int
    # ``meth = deco(target)``: the decorators, outermost first.
    decorators: list[ast.expr] = dc.field(default_factory=list)
    docstring: str | None = None
    # Column of the docstring, stripped from its lines.
    docstring_margin: int = 0


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


def _clone_target(value: ast.expr) -> tuple[str, list[ast.expr]] | None:
    """For ``meth = d1(d2(args)(target))``: target and [d1, d2(args)].

    None if *value* is not a (decorated) name.
    """
    decorators = []
    while isinstance(value, ast.Call) and len(value.args) == 1 \
            and not value.keywords:
        decorators.append(value.func)
        value = value.args[0]
    if isinstance(value, ast.Name):
        return value.id, decorators
    return None


def is_stub(node: ast.FunctionDef) -> bool:
    """True if the body is only a docstring and/or ``...``.

    A stub describes a function implemented in C by hand: it is never
    lowered to C, and its annotations are not C types for the emitter.
    """
    body = node.body[1:] if _docstring(node.body) is not None else node.body
    return not body or (len(body) == 1 and isinstance(body[0], ast.Expr)
                        and isinstance(body[0].value, ast.Constant)
                        and body[0].value.value is Ellipsis)


class Spec:
    def __init__(self, source: str, filename: str = '<spec>') -> None:
        self.filename = filename
        self.source = source
        self.module = ast.parse(source, filename)
        # Top-level functions by name and methods by "T.name", in the
        # order of the file.
        self.functions: dict[str, ast.FunctionDef] = {}
        self.classes: dict[str, ast.ClassDef] = {}
        self.clones: dict[str, Clone] = {}
        for node in self.module.body:
            if isinstance(node, ast.FunctionDef):
                self.functions[node.name] = node
            elif isinstance(node, ast.ClassDef):
                self._add_class(node)

    @classmethod
    def load(cls, path: str) -> Spec | None:
        try:
            with open(path, encoding='utf-8') as f:
                source = f.read()
        except FileNotFoundError:
            return None
        return cls(source, path)

    def where(self, node: ast.AST) -> str:
        return f"{self.filename}:{getattr(node, 'lineno', '?')}"

    def _add_class(self, node: ast.ClassDef) -> None:
        self.classes[node.name] = node
        body = node.body
        for i, stmt in enumerate(body):
            match stmt:
                case ast.FunctionDef(name=name):
                    self.functions[f'{node.name}.{name}'] = stmt
                case ast.Assign(targets=[ast.Name(name)],
                                value=value) if _clone_target(value):
                    target, decorators = _clone_target(value)
                    clone = Clone(target, stmt.lineno, decorators)
                    doc = _docstring(body[i + 1:i + 2])
                    if doc is not None:
                        clone.docstring = doc
                        clone.docstring_margin = body[i + 1].col_offset
                    self.clones[f'{node.name}.{name}'] = clone

    # -- implemented functions ---------------------------------------------

    def implemented(self, name: str) -> bool:
        node = self.functions.get(name)
        return node is not None and not is_stub(node)

    def implemented_functions(self) -> list[str]:
        return [name for name in self.functions if self.implemented(name)]

    def body(self, name: str) -> list[ast.stmt]:
        """Statements of function *name*, without its docstring."""
        body = self.functions[name].body
        if _docstring(body) is not None:
            body = body[1:]
        return body

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

    def describe(self, name: str) -> SpecFunction:
        """The C signature of implemented spec function *name*."""
        node = self.functions[name]
        where = f"{self.where(node)}: {name}()"
        args = node.args
        cls_name, _, meth = name.rpartition('.')
        if cls_name and meth != '__new__':
            raise SpecError(f"{where}: a spec can only implement __new__")
        others = [args.vararg, *args.kwonlyargs, args.kwarg]
        for other in others:
            if other is not None:
                raise SpecError(f"{where}: a spec needs positional "
                                f"parameters only; {other.arg!r} is not")
        positional = args.posonlyargs + args.args
        first_optional = len(positional) - len(args.defaults)
        parameters = []
        new_type = None
        for i, arg in enumerate(positional):
            if cls_name and i == 0:
                if cls_name not in TYPE_OBJECTS:
                    raise SpecError(f"{where}: unknown type {cls_name!r}; "
                                    f"known: {sorted(TYPE_OBJECTS)}")
                if arg.annotation is not None:
                    raise SpecError(f"{where}: the class parameter "
                                    f"{arg.arg!r} must not be annotated")
                new_type = cls_name
                parameters.append(SpecParameter(arg.arg, TYPE_CTYPE, False))
                continue
            match arg.annotation:
                case ast.Name(conv) | ast.Call(func=ast.Name(conv)) \
                        if conv in SPEC_CTYPES:
                    ctype = SPEC_CTYPES[conv]
                case _:
                    raise SpecError(f"{where}: parameter {arg.arg!r} needs "
                                    f"an annotation from "
                                    f"{sorted(SPEC_CTYPES)}")
            optional = i >= first_optional
            if optional:
                default = args.defaults[i - first_optional]
                if not (isinstance(default, ast.Name)
                        and default.id == 'NULL'):
                    raise SpecError(f"{where}: parameter {arg.arg!r} may "
                                    "only default to NULL")
            parameters.append(SpecParameter(arg.arg, ctype, optional))
        return SpecFunction(name, self.filename, node.lineno, parameters,
                            new_type)

    # -- clinic input ------------------------------------------------------

    def has_method(self, name: str) -> bool:
        return name in self.clones or (
            '.' in name and name in self.functions)

    def decorator_lineno(self, name: str, decorator: str) -> int:
        """Line of decorator *decorator* of method (or clone) *name*."""
        clone = self.clones.get(name)
        if clone is not None:
            decorators, lineno = clone.decorators, clone.lineno
        else:
            node = self.functions[name]
            decorators, lineno = node.decorator_list, node.lineno
        for d in decorators:
            if isinstance(d, ast.Call):
                d = d.func
            if isinstance(d, ast.Name) and d.id == decorator:
                return d.lineno
        return lineno

    def clinic_input(self, name: str, clinic_class: str
                     ) -> tuple[list[str], str, list[str]]:
        """Clinic DSL for spec method (or clone) *name*.

        Return (decorator lines, text to append to the function line,
        the lines after the function line).  *clinic_class* is the dotted
        clinic name of the class, used for the target of a clone.
        """
        clone = self.clones.get(name)
        if clone is not None:
            cls_name = name.partition('.')[0]
            target = f'{cls_name}.{clone.target}'
            if target not in self.functions:
                raise SpecError(f"{self.filename}:{clone.lineno}: {name} "
                                f"clones {target}, which is not a spec "
                                "method")
            # Clinic requires the kind of a clone to be that of its
            # target, and copies everything else from it.
            _, kind = self._decorators(self.functions[target])
            decorators = [f'@{kind}'] if kind in METHOD_DECORATORS else []
            decorators += [self._decorator_line(d) for d in clone.decorators]
            lines = []
            if clone.docstring is not None:
                lines = ['', *self._clean_docstring(
                    clone.docstring, clone.docstring_margin)]
            return (decorators,
                    f' = {clinic_class}.{clone.target}', lines)

        node = self.functions[name]
        decorators, kind = self._decorators(node)
        suffix = ''
        if node.returns is not None:
            suffix = f' -> {self._segment(node.returns, "return converter")}'
        params = self._parameter_lines(node, kind)
        names = [pname for _, pname in params if pname]
        param_docs: dict[str, list[str]] = {}
        docstring: list[str] = []
        doc = _docstring(node.body)
        if doc is not None:
            lines = self._clean_docstring(doc, node.body[0].col_offset)
            docstring, param_docs = self._split_docstring(node, lines, names)
        lines = ['']
        for param_line, pname in params:
            lines.append(f'    {param_line}')
            for doc_line in param_docs.get(pname or '', ()):
                lines.append(f'        {doc_line}')
        if docstring:
            lines += ['', *docstring]
        return decorators, suffix, lines

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
                            raise SpecError(
                                f"{self.where(arg)}: the arguments of a "
                                "clinic decorator must be string or "
                                "integer constants")
                return ' '.join([f'@{name}', *words])
        raise SpecError(f"{self.where(decorator)}: a spec decorator is "
                        "a clinic decorator: @name or @name(args)")

    def _decorators(self, node: ast.FunctionDef) -> tuple[list[str], str]:
        """Clinic decorator lines of *node*, in order, and its kind."""
        kind = 'method'
        decorators = []
        for decorator in node.decorator_list:
            line = self._decorator_line(decorator)
            if line[1:] in METHOD_DECORATORS:
                if kind != 'method':
                    raise SpecError(f"{self.where(decorator)}: only "
                                    "one of @classmethod and "
                                    "@staticmethod")
                kind = line[1:]
            decorators.append(line)
        if node.name == '__new__':
            if kind != 'method':
                raise SpecError(f"{self.where(node)}: __new__ is implicitly "
                                "a class method; remove the decorator")
            kind = 'classmethod'
            decorators.insert(0, '@classmethod')
        return decorators, kind

    def _segment(self, node: ast.expr | ast.keyword, what: str) -> str:
        """The source text of *node*, on one line."""
        text = ast.get_source_segment(self.source, node)
        assert text is not None
        if '\n' in text:
            raise SpecError(f"{self.where(node)}: write the {what} on "
                            "one line")
        return text

    def _converter(self, arg: ast.arg) -> tuple[str, str | None]:
        """The clinic converter of *arg* and its c_name, if any."""
        annotation = arg.annotation
        assert annotation is not None
        if isinstance(annotation, ast.Call):
            c_names = [kw for kw in annotation.keywords
                       if kw.arg == 'c_name']
            if c_names:
                value = c_names[0].value
                if not (isinstance(value, ast.Constant)
                        and isinstance(value.value, str)):
                    raise SpecError(f"{self.where(value)}: c_name must be "
                                    "a string")
                args = [self._segment(a, 'converter')
                        for a in annotation.args]
                args += [self._segment(kw, 'converter')
                         for kw in annotation.keywords
                         if kw.arg != 'c_name']
                func = self._segment(annotation.func, 'converter')
                converter = f'{func}({", ".join(args)})' if args else func
                return converter, value.value
        return self._segment(annotation, 'converter'), None

    def _parameter_line(self, arg: ast.arg, default: ast.expr | None,
                        prefix: str = '') -> str:
        if arg.annotation is None:
            raise SpecError(f"{self.where(arg)}: parameter {arg.arg!r} "
                            "needs a converter as its annotation")
        converter, c_name = self._converter(arg)
        line = prefix + arg.arg
        if c_name is not None:
            line += f' as {c_name}'
        line += f': {converter}'
        if default is not None:
            line += f' = {self._segment(default, "default")}'
        return line

    def _parameter_lines(self, node: ast.FunctionDef, kind: str
                         ) -> list[tuple[str, str | None]]:
        """Clinic parameter lines, with the Python name of the parameter
        (None for the / and * markers)."""
        args = node.args
        positional = args.posonlyargs + args.args
        defaults: list[ast.expr | None] = [None] * (
            len(positional) - len(args.defaults)) + list(args.defaults)
        pairs = list(zip(positional, defaults))
        n_posonly = len(args.posonlyargs)
        if kind != 'staticmethod':
            if not pairs:
                raise SpecError(f"{self.where(node)}: {node.name}() needs "
                                "the self or class parameter first")
            if pairs[0][0].annotation is None:
                # Clinic's implicit self (or class) parameter.
                pairs = pairs[1:]
                n_posonly = max(n_posonly - 1, 0)
        lines: list[tuple[str, str | None]] = []
        for i, (arg, default) in enumerate(pairs):
            lines.append((self._parameter_line(arg, default), arg.arg))
            if i == n_posonly - 1:
                lines.append(('/', None))
        if args.vararg:
            lines.append((self._parameter_line(args.vararg, None, '*'),
                          args.vararg.arg))
        elif args.kwonlyargs:
            lines.append(('*', None))
        for arg, kw_default in zip(args.kwonlyargs, args.kw_defaults):
            lines.append((self._parameter_line(arg, kw_default), arg.arg))
        if args.kwarg:
            lines.append((self._parameter_line(args.kwarg, None, '**'),
                          args.kwarg.arg))
        return lines

    def _clean_docstring(self, text: str, margin: int) -> list[str]:
        """Lines of a docstring, less the indentation of its statement."""
        lines = [line.rstrip() for line in text.split('\n')]
        for i in range(1, len(lines)):
            if lines[i]:
                if lines[i][:margin].strip():
                    raise SpecError(f"{self.filename}: docstring line "
                                    f"{lines[i]!r} is indented less than "
                                    "the docstring")
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
                raise SpecError(f"{self.where(node)}: {node.name}(): no "
                                f"docstring for parameter {name!r} in the "
                                "parameter section")
            param_docs[name] = doc
        if i == 2:
            return lines, param_docs
        if i < len(lines):
            if lines[i]:
                raise SpecError(f"{self.where(node)}: {node.name}(): "
                                "expected an empty line after the parameter "
                                f"section, got {lines[i]!r} (parameters "
                                "are documented in the order of the "
                                "signature)")
            return [lines[0], '', *lines[i + 1:]], param_docs
        return lines[:1], param_docs

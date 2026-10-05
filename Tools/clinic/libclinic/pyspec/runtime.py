"""Run a spec as Python: load() (the reference behaviour, for the tests).

Clinic reads a spec with the ast module (frontend.py); the tests run the
same file as Python.  The names it uses from the tooling are imported by
group (``from libclinic.pyspec import ac, rt, machine``): ac.py (Argument
Clinic: converters and decorators, identities for Python), rt.py (the
primitives with a C meaning) and machine.py (the object memory, for pure
Python bodies).  A bare ``isinstance`` or ``iter`` would be Python's
builtin, not the C's: load() refuses a spec that uses one
(check_shadowed_builtins()), and checks the annotations the way clinic
does (check_annotations()).
"""

import ast
import builtins
import os
import sys
import types
from collections.abc import Callable
from typing import Any

from .rt import SHADOWED_BUILTINS


# The imported specs check_shadowed_builtins() accepted.
_checked: set[str] = set()


def check_shadowed_builtins(tree: ast.Module, path: str) -> None:
    """A SpecError at the first use of a bare SHADOWED_BUILTINS name in
    the spec *tree*: as Python it is the builtin, whose meaning is not the
    C's (``rt.isinstance``, ``rt.iter``)."""
    from libclinic.errors import SpecError
    for node in ast.walk(tree):
        if (builtins.isinstance(node, ast.Name)
                and node.id in SHADOWED_BUILTINS):
            raise SpecError(f"{node.id}() is Python's builtin here, not the "
                            f"C's: write rt.{node.id}() (from "
                            "libclinic.pyspec import rt)", filename=path,
                            lineno=node.lineno)


def check_annotations(tree: ast.Module, path: str) -> None:
    """A SpecError at the first annotation of a def of *tree* that is not
    what clinic reads: in a class, ``ac.<converter>`` or
    ``ac.<converter>(...)``; at the top level, ``ac.<C type>``, a string
    or None (frontend.Spec checks the same)."""
    from libclinic.errors import SpecError
    from .frontend import group_aliases
    aliases = {name for name, group in group_aliases(tree).items()
               if group == 'ac'}

    def qualified(node: ast.expr, call: bool) -> bool:
        if call and builtins.isinstance(node, ast.Call):
            node = node.func
        return (builtins.isinstance(node, ast.Attribute)
                and builtins.isinstance(node.value, ast.Name)
                and node.value.id in aliases)

    def check(func: ast.FunctionDef, method: bool) -> None:
        args = func.args
        annotations = [a.annotation for a in (
            *args.posonlyargs, *args.args, *args.kwonlyargs,
            *filter(None, (args.vararg, args.kwarg)))] + [func.returns]
        for annotation in annotations:
            if annotation is None or qualified(annotation, call=method):
                continue
            if not method and builtins.isinstance(annotation, ast.Constant) \
                    and (annotation.value is None
                         or builtins.isinstance(annotation.value, str)):
                continue
            wanted = ('ac.<converter>(...)' if method
                      else 'ac.<C type>, a string or None')
            raise SpecError(f"{func.name}(): an annotation is {wanted}, not "
                            f"{ast.unparse(annotation)}", filename=path,
                            lineno=annotation.lineno)

    for node in tree.body:
        if builtins.isinstance(node, ast.FunctionDef):
            check(node, method=False)
        elif builtins.isinstance(node, ast.ClassDef):
            for item in node.body:
                if builtins.isinstance(item, ast.FunctionDef):
                    check(item, method=True)


def _is_reference(decorator: ast.expr) -> bool:
    """``@ac.stub(optimizer_info=True)`` (the qualifier is not checked here)."""
    return (builtins.isinstance(decorator, ast.Call)
            and builtins.isinstance(decorator.func, ast.Attribute)
            and decorator.func.attr == 'stub'
            and any(kw.arg == 'optimizer_info'
                    and builtins.isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                    for kw in decorator.keywords))


def _check(tree: ast.Module, path: str) -> None:
    check_shadowed_builtins(tree, path)
    check_annotations(tree, path)


def _c_functions(path: str, module: types.ModuleType
                 ) -> dict[str, Callable[..., Any]]:
    """{"T.meth": function} of the methods ``meth = ac.stub("f")`` of the
    spec at *path* (run as *module*): the C function f of a header the C
    file includes, whose model is the def f of the spec of the header
    (frontend.Spec.c_method(), cfunctions.model_def()).  That spec is a
    template: here B is the builtin T, and STRINGLIB_NEW and
    STRINGLIB_MUTABLE those of *module*.  The class attribute becomes
    the function."""
    import importlib
    from . import cfunctions, frontend, specfiles
    spec = frontend.Spec.load(path)
    assert spec is not None
    out = {}
    # The template instantiated for each class: {(template, class):
    # namespace}.
    instances: dict[tuple[str, str], dict[str, Any]] = {}
    for name, shared in spec.shared.items():
        if shared.c_function is None:
            continue
        found = cfunctions.model_def(spec, spec.c_method(name))
        if found is None:
            continue
        rel = os.path.splitext(specfiles.display_path(found[0].filename))[0]
        template = importlib.import_module(rel.replace('/', '.'))
        cls_name, _, meth = name.partition('.')
        spec_class = getattr(module, cls_name)
        namespace = instances.get((template.__name__, cls_name))
        if namespace is None:
            namespace = dict(template.__dict__)
            namespace['B'] = getattr(builtins, cls_name, spec_class)
            for macro in ('STRINGLIB_NEW', 'STRINGLIB_MUTABLE'):
                if hasattr(module, macro):
                    namespace[macro] = getattr(module, macro)
            for key, value in template.__dict__.items():
                if (builtins.isinstance(value, types.FunctionType)
                        and value.__module__ == template.__name__):
                    namespace[key] = types.FunctionType(
                        value.__code__, namespace, value.__name__,
                        value.__defaults__, value.__closure__)
            instances[(template.__name__, cls_name)] = namespace
        out[name] = namespace[shared.c_function]
        setattr(spec_class, meth, out[name])
    return out


def load(path: str) -> dict[str, Callable[..., Any]]:
    """Run the spec at *path*: {"PyBytes_FromObject" or "bytes.__new__":
    the Python function}.  Once the spec has run, a global T of ``class
    T:`` is the builtin again (bodies compare with the real type), while
    ``T.m(...)`` calls the spec method, as in the generated C (except in
    a Python reference, which models with the builtin)."""
    from . import specfiles
    with open(path, encoding='utf-8') as f:
        tree = ast.parse(f.read(), path)
    _check(tree, path)
    classes = {node.name for node in tree.body
               if builtins.isinstance(node, ast.ClassDef)}
    bases = [specfiles.import_root(path)]

    class SpecCalls(ast.NodeTransformer):
        def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
            # Only the bodies of methods: a shared method of a class body
            # (``__reduce__ = bytearray.__reduce__``) is the spec's.
            node.body = [self.visit(stmt)
                         if builtins.isinstance(stmt, ast.FunctionDef)
                         else stmt
                         for stmt in node.body]
            return node

        def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
            # The Python reference of a C function models it with the
            # builtins.
            if any(_is_reference(d) for d in node.decorator_list):
                return node
            return self.generic_visit(node)

        def visit_Attribute(self, node: ast.Attribute) -> ast.Attribute:
            self.generic_visit(node)
            if (builtins.isinstance(node.value, ast.Name)
                    and node.value.id in classes
                    and builtins.isinstance(node.ctx, ast.Load)):
                node.value = ast.copy_location(
                    ast.Name(f'_spec_{node.value.id}', ast.Load()),
                    node.value)
            return node

    tree = ast.fix_missing_locations(SpecCalls().visit(tree))
    stem = os.path.splitext(os.path.basename(path))[0]
    module = types.ModuleType(f'_pyspec_{stem}')
    module.__file__ = path
    sys.path[:0] = bases
    try:
        exec(compile(tree, path, 'exec'), module.__dict__)
        c_functions = _c_functions(path, module)
    finally:
        for entry in bases:
            sys.path.remove(entry)
    # The specs it imported, which the import system ran.
    for name, imported in list(sys.modules.items()):
        spec_path = getattr(imported, '__file__', None)
        if (spec_path and 'pyspec' in name.split('.')
                and not name.startswith('libclinic.')
                and spec_path not in _checked):
            with open(spec_path, encoding='utf-8') as f:
                _check(ast.parse(f.read(), spec_path), spec_path)
            _checked.add(spec_path)
    functions: dict[str, Any] = {}
    lines: dict[str, int] = {}
    for node in tree.body:
        if builtins.isinstance(node, ast.FunctionDef):
            functions[node.name] = getattr(module, node.name)
            lines[node.name] = node.lineno
        elif builtins.isinstance(node, ast.ClassDef):
            spec_class = getattr(module, node.name)
            setattr(module, f'_spec_{node.name}', spec_class)
            # A class that is not a builtin (bytes_iterator) stays the
            # spec class.
            setattr(module, node.name,
                    getattr(builtins, node.name, spec_class))
            for item in node.body:
                if builtins.isinstance(item, ast.FunctionDef):
                    functions[f'{node.name}.{item.name}'] = (
                        spec_class.__dict__[item.name])
                    lines[f'{node.name}.{item.name}'] = item.lineno
    functions.update(c_functions)
    out = {name: getattr(func, '__func__', func)
           for name, func in functions.items()}
    # The annotations are evaluated only on use: evaluate them, so that an
    # option a converter does not have fails here (ac.Converter).
    from libclinic.errors import SpecError
    for name, func in out.items():
        try:
            func.__annotations__
        except TypeError as exc:
            raise SpecError(f"{name}(): {exc}", filename=path,
                            lineno=lines[name]) from None
    return out

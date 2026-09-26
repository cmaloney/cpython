"""Find the pyspec function implementing a clinic __new__.

For Objects/foo.c the spec file is Objects/pyspec/foo.py.  A spec function
named like the C basename of a clinic ``__new__`` (``bytes_new`` for
``bytes.__new__ as bytes_new``) is its implementation:

    def bytes_new(cls: type[bytes], source: object = NULL, ...):

Its first parameter is the class, annotated ``type[T]`` with T the type
the __new__ belongs to; the others match the clinic parameters, and those
defaulting to NULL are optional.  Tools/pyspec/emit_c.py generates from it
NAME_impl() and, for each positional argument count N, NAME_nargsN(): the
function partially evaluated for exactly T and N arguments.  Argument
Clinic then leaves the impl definition to the spec and generates a
vectorcall calling NAME_nargsN().

The spec is read with the ast module; it is never executed here.
"""

from __future__ import annotations

import ast
import dataclasses as dc
import os


# Parameter annotations in a spec and the C type they stand for.
SPEC_CTYPES = {
    'object': 'PyObject *',
    'cstr': 'const char *',
}

TYPE_CTYPE = 'PyTypeObject *'

# Builtin types a spec may name, and their C type objects.
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


class SpecError(Exception):
    pass


@dc.dataclass
class SpecParameter:
    name: str
    ctype: str
    optional: bool


@dc.dataclass
class SpecFunction:
    name: str
    path: str
    lineno: int
    parameters: list[SpecParameter]
    # For a __new__: the Python name of the type (first parameter
    # annotated type[T]).
    new_type: str | None = None

    @property
    def type_object(self) -> str | None:
        if self.new_type is None:
            return None
        return TYPE_OBJECTS[self.new_type]


def spec_path(filename: str) -> str:
    """Path of the spec file for the C file *filename*."""
    dirname, basename = os.path.split(filename)
    stem = os.path.splitext(basename)[0]
    return os.path.join(dirname, 'pyspec', stem + '.py')


def _new_type(annotation: ast.expr | None) -> str | None:
    match annotation:
        case ast.Subscript(value=ast.Name('type'), slice=ast.Name(name)):
            return name
    return None


def spec_function(node: ast.FunctionDef, path: str) -> SpecFunction:
    """Describe the parameters of spec function *node*."""
    args = node.args
    where = f"{path}:{node.lineno}"
    if args.posonlyargs or args.vararg or args.kwonlyargs or args.kwarg:
        raise SpecError(f"{where}: {node.name}() may only have plain "
                        "positional parameters")
    first_optional = len(args.args) - len(args.defaults)
    parameters = []
    new_type = None
    for i, arg in enumerate(args.args):
        annotation = arg.annotation
        type_name = _new_type(annotation)
        if type_name is not None:
            if i != 0:
                raise SpecError(f"{where}: only the first parameter of "
                                f"{node.name}() can be a type[...]")
            if type_name not in TYPE_OBJECTS:
                raise SpecError(f"{where}: unknown type {type_name!r} in "
                                f"type[...]; known: {sorted(TYPE_OBJECTS)}")
            new_type = type_name
            ctype = TYPE_CTYPE
        elif (isinstance(annotation, ast.Name)
                and annotation.id in SPEC_CTYPES):
            ctype = SPEC_CTYPES[annotation.id]
        else:
            raise SpecError(f"{where}: parameter {arg.arg!r} of "
                            f"{node.name}() needs an annotation from "
                            f"{sorted(SPEC_CTYPES)} or type[...]")
        optional = i >= first_optional
        if optional:
            default = args.defaults[i - first_optional]
            if not (isinstance(default, ast.Name) and default.id == 'NULL'):
                raise SpecError(f"{where}: parameter {arg.arg!r} of "
                                f"{node.name}() may only default to NULL")
        parameters.append(SpecParameter(arg.arg, ctype, optional))
    return SpecFunction(node.name, path, node.lineno, parameters, new_type)


def load_spec_functions(path: str) -> dict[str, ast.FunctionDef]:
    """The top-level functions of the spec at *path*, by name."""
    try:
        with open(path, encoding='utf-8') as f:
            source = f.read()
    except FileNotFoundError:
        return {}
    module = ast.parse(source, path)
    return {node.name: node for node in module.body
            if isinstance(node, ast.FunctionDef)}


def find_spec(filename: str, c_basename: str) -> SpecFunction | None:
    """The spec function implementing clinic function *c_basename*."""
    path = spec_path(filename)
    node = load_spec_functions(path).get(c_basename)
    if node is None:
        return None
    return spec_function(node, path)

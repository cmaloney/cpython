"""Generate the static type objects of a spec.

For each class of the spec decorated with ``@static_type(...)``, Argument
Clinic generates at the end of Objects/clinic/<stem>_pyspec.c.h (included
at the end of the C file, after every function it names):

* the method table ``<class>_methods[]``: one entry per method of the
  class that is not a slot, in the order of the spec.  A clinic function
  is its ``*_METHODDEF`` macro; a hand-written PyCFunction
  (``@c_name(METH_NOARGS="f")``) is written out with its docstring; a
  shared method is the entry the other spec declares;
* the sub-tables ``<class>_as_number`` etc. holding the slots of the
  dunders (see slots.py);
* ``PyTypeObject <Name>_Type`` with designated initializers: a static,
  immortal type, readied at startup like every static builtin type.

What each member of PyTypeObject comes from:

  tp_name           the class name (or @static_type(tp_name=...))
  tp_base           the base class, if any
  tp_basicsize      sizeof(the C type of the class directive), or given
  tp_doc            the class docstring, as is
  tp_flags          Py_TPFLAGS_DEFAULT
                    | Py_TPFLAGS_BASETYPE unless the class is @final
                    | Py_TPFLAGS_HAVE_GC if tp_traverse is given
                    | @static_type(tp_flags=...)
  tp_new, tp_init, tp_vectorcall
                    the clinic functions __new__ and __init__
  tp_methods        the generated method table
  dunder slots      the slots of the dunders of the class
  anything else     @static_type(member=...), as a C expression; members
                    left out are 0, inherited by PyType_Ready() as usual.
"""

from __future__ import annotations

import ast
import os
import re

from libclinic.formatting import docstring_for_c_string

from . import frontend, slots
from .frontend import CLINIC, PYCFUNCTION, README, SHARED, SLOT, SpecError

# Members of PyTypeObject that the spec derives; @static_type cannot set
# them.  tp_new, tp_init and tp_vectorcall come from the clinic __new__ and
# __init__, or from @static_type when they are not clinic functions
# (tp_new = PyType_GenericNew).
FROM_CLINIC = {'tp_new', 'tp_init', 'tp_vectorcall'}
DERIVED = {
    'tp_base', 'tp_doc', 'tp_methods',
    'tp_as_async', 'tp_as_number', 'tp_as_sequence', 'tp_as_mapping',
    'tp_as_buffer',
} | {s.slot for s in slots.slotdefs() if s.subtable is None} - FROM_CLINIC

SUBTABLE_ORDER = ['as_async', 'as_number', 'as_sequence', 'as_mapping',
                  'as_buffer']

# The decorators a method implemented in C by hand may have, by kind.
C_DECORATORS = {
    'slot': {'c_name', 'c_implemented'},
    'PyCFunction': {'c_name', 'classmethod', 'c_implemented'},
}


def object_h_path() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, '..', '..', '..', '..', 'Include', 'cpython',
                        'object.h')


_members: list[str] | None = None


def type_members() -> list[str]:
    """The members of PyTypeObject, in order (Include/cpython/object.h)."""
    global _members
    if _members is None:
        with open(object_h_path(), encoding='utf-8') as f:
            source = f.read()
        start = source.index('struct _typeobject {')
        body = source[start:source.index('\n};', start)]
        body = re.sub(r'/\*.*?\*/|//[^\n]*', '', body, flags=re.DOTALL)
        body = body.partition('PyObject_VAR_HEAD')[2]
        names = []
        for decl in body.split(';'):
            names += re.findall(r'(\w+)\s*(?:,|$)', decl.strip())
        _members = names
    return _members


def static_type(spec: frontend.Spec, cls_name: str
                ) -> dict[str, str] | None:
    """The keywords of @static_type of class *cls_name*, or None."""
    for decorator in spec.classes[cls_name].decorator_list:
        match decorator:
            case ast.Call(func=ast.Name('static_type'), args=[],
                          keywords=keywords):
                members = {}
                for kw in keywords:
                    if not (isinstance(kw.value, ast.Constant)
                            and isinstance(kw.value.value, str)):
                        raise spec.error(kw, "the members of @static_type "
                                         "are C expressions in strings")
                    members[kw.arg] = kw.value.value
                return members
            case ast.Name('static_type') | ast.Call(
                    func=ast.Name('static_type')):
                raise spec.error(decorator, "write "
                                 "@static_type(member=\"C expression\", ...)")
    return None


def _is_final(node: ast.ClassDef) -> bool:
    return any(isinstance(d, ast.Name) and d.id == 'final'
               for d in node.decorator_list)


def _text_signature(node: ast.FunctionDef) -> str:
    """The text signature of a slot method: ``($self, key, /)``."""
    args = node.args
    params = []
    positional = args.posonlyargs + args.args
    defaults = [None] * (len(positional) - len(args.defaults)) + \
        list(args.defaults)
    for i, (arg, default) in enumerate(zip(positional, defaults)):
        text = '$' + arg.arg if i == 0 else arg.arg
        if default is not None:
            text += '=' + ast.unparse(default)
        params.append(text)
        if i == len(args.posonlyargs) - 1:
            params.append('/')
    if args.vararg:
        params.append('*' + args.vararg.arg)
    for arg in args.kwonlyargs:
        params.append(arg.arg)
    if args.kwarg:
        params.append('**' + args.kwarg.arg)
    return f'({", ".join(params)})'


def _c_string(text: str) -> str:
    return docstring_for_c_string(text)


def _c_stub(spec: frontend.Spec, name: str, kind: str) -> ast.FunctionDef:
    """The def of a method implemented in C by hand, with the fixed C
    signature of its *kind* (a slot or a PyCFunction): a body of ``...``,
    or its Python reference with @c_implemented."""
    node = spec.functions[name]
    if not (frontend.is_stub(node) or frontend.is_c_implemented(node)):
        raise spec.error(node, f"{name} is a {kind} implemented in C: its "
                         "body is ..., or its Python reference with "
                         "@c_implemented")
    for decorator in node.decorator_list:
        if frontend.decorator_name(decorator) not in C_DECORATORS[kind]:
            allowed = ' and '.join(f'@{d}' for d in
                                   sorted(C_DECORATORS[kind]))
            raise spec.error(decorator, f"{name}: a {kind} takes only "
                             f"{allowed}, not @{ast.unparse(decorator)}; "
                             f"see {README}")
    for arg in node.args.posonlyargs + node.args.args:
        if arg.annotation is not None:
            raise spec.error(arg, f"{name}: the C signature of a {kind} is "
                             "fixed: parameters are not annotated")
    return node


def _exported(name: str) -> bool:
    return name.startswith(('Py', '_Py'))


class TypeGenerator:
    def __init__(self, spec: frontend.Spec, cls_name: str,
                 members: dict[str, str],
                 clinic_class: tuple[str, str],
                 functions: dict[str, tuple[str, str | None]]):
        self.spec = spec
        self.cls_name = cls_name
        self.node = spec.classes[cls_name]
        self.members = members
        self.c_type, type_object = clinic_class
        if not type_object.startswith('&'):
            raise self.error(f"class {cls_name}: the class directive needs "
                             "the type object, e.g. \"&PyBytes_Type\"")
        self.type_object = type_object[1:]
        self.functions = functions
        self.prefix = cls_name.replace('.', '_')
        for member in members:
            if member not in type_members():
                raise self.error(f"@static_type: {member!r} is not a "
                                 "member of PyTypeObject")
            if member in DERIVED:
                raise self.error(f"@static_type: {member} is derived from "
                                 "the spec; declare the method (or "
                                 "docstring) instead")

    def error(self, message: str) -> SpecError:
        """A SpecError at the class."""
        return self.spec.error(self.node, message)

    # -- methods -----------------------------------------------------------

    def _pycfunction_entry(self, spec: frontend.Spec, name: str,
                           meth: str) -> tuple[list[str], str]:
        """(docstring definition, method table entry) of a hand-written
        PyCFunction of *spec*."""
        node = _c_stub(spec, name, 'PyCFunction')
        _, keywords = spec.c_name(name)
        (flag, c_func), = keywords.items()
        nparams = frontend.PYCFUNCTION_FLAGS[flag]
        args = node.args
        first = 'self'
        if any(frontend.decorator_name(d) == 'classmethod'
               for d in node.decorator_list):
            first = 'cls'
            flag += ' | METH_CLASS'
        wanted = f'({first}, /)' if nparams == 0 else f'({first}, arg, /)'
        if (args.args or args.vararg or args.kwonlyargs or args.kwarg
                or args.defaults
                or len(args.posonlyargs) != nparams + 1):
            raise spec.error(node, f"{name}: a {flag} function takes "
                             f"{wanted}")
        doc = spec.docstring(name)
        docs = []
        doc_name = 'NULL'
        if doc is not None:
            doc_name = f'{self.prefix}_{meth}__doc__'
            docs = [f'PyDoc_STRVAR({doc_name},', _c_string(doc) + ');', '']
        return docs, f'    {{"{meth}", {c_func}, {flag}, {doc_name}}},'

    def _clinic_entry(self, name: str) -> str:
        node = self.spec.functions[name]
        try:
            c_basename, _ = self.functions[name]
        except KeyError:
            raise self.spec.error(node, f"{name} is not a clinic function "
                                  "of the C file") from None
        return f'    {c_basename.upper()}_METHODDEF'

    def _shared_entry(self, name: str) -> tuple[list[str], str]:
        shared = self.spec.shared[name]
        other = self.spec.imported(shared.module)
        other_name = f'{shared.cls}.{shared.meth}'
        kind = other.method_kind(other_name)
        if kind == PYCFUNCTION:
            return self._pycfunction_entry(other, other_name, shared.meth)
        if kind != CLINIC:
            raise SpecError(f"{other_name} of {other.filename} is a {kind}; "
                            "only methods can be shared",
                            filename=self.spec.filename,
                            lineno=shared.lineno)
        c_basename, _ = other.c_name(other_name)
        if c_basename is None:
            c_basename = other_name.replace('.', '_')
        return [], f'    {c_basename.upper()}_METHODDEF'

    # -- slots -------------------------------------------------------------

    def resolve_slots(self, dunders: list[str]) -> dict[str, str]:
        """The C function of each slot filled by the dunders of the class:
        {slot: C name}."""
        spec = self.spec
        selected: dict[str, str | None] = {}
        where: dict[str, str] = {}

        def select(slot, c_name, dunder):
            if slot in selected and c_name is not None \
                    and selected[slot] not in (None, c_name):
                raise spec.error(spec.functions[f'{self.cls_name}.{dunder}'],
                                 f"{dunder}: {slot} is already "
                                 f"{selected[slot]} (from {where[slot]})")
            if selected.get(slot) is None:
                selected[slot] = c_name
                where[slot] = dunder

        deferred = []
        for meth in dunders:
            name = f'{self.cls_name}.{meth}'
            node = _c_stub(spec, name, 'slot')
            if frontend._docstring(node.body) is not None:
                raise spec.error(node, f"{name}: a slot has no docstring: "
                                 "its wrapper's comes from slotdefs in "
                                 "Objects/typeobject.c")
            candidates = [s.slot for s in slots.candidates(meth)]
            positional, keywords = spec.c_name(name)
            if keywords:
                for slot, c_name in keywords.items():
                    if slot not in candidates:
                        raise spec.error(node, f"{name}: {slot} is not a "
                                         f"slot of {meth}; its slots are "
                                         f"{candidates}")
                    select(slot, c_name, meth)
            elif len(candidates) == 1:
                select(candidates[0], positional, meth)
            else:
                deferred.append((meth, positional))
        for meth, positional in deferred:
            name = f'{self.cls_name}.{meth}'
            candidates = [s.slot for s in slots.candidates(meth)]
            covered = [s for s in candidates if s in selected]
            if not covered:
                raise spec.error(spec.functions[name], f"{name}: several "
                                 f"slots can implement {meth} "
                                 f"({', '.join(candidates)}); name them: "
                                 f"@c_name({candidates[0]}=\"...\", ...)")
            for slot in covered:
                select(slot, positional, meth)

        declared = set(dunders)
        for slot in selected:
            missing = [d for d in slots.group(slot) if d not in declared]
            if missing:
                raise self.error(
                    f"class {self.cls_name}: {slot} also implements "
                    f"{', '.join(missing)}: declare "
                    f"{'it' if len(missing) == 1 else 'them'} too "
                    "(one C function serves the whole group)")
        # The parameters are those of the wrapper of each slot.
        for meth in dunders:
            name = f'{self.cls_name}.{meth}'
            node = spec.functions[name]
            actual = _text_signature(node)
            for slotdef in slots.candidates(meth):
                if slotdef.slot in selected and \
                        slotdef.signature != actual:
                    raise spec.error(node, f"{name}{actual}: the signature "
                                     f"of {slotdef.slot} is "
                                     f"{meth}{slotdef.signature}")
        return {slot: c_name or f'{self.prefix}_{slot.split("_", 1)[1]}'
                for slot, c_name in selected.items()}

    # -- the type ----------------------------------------------------------

    def generate(self) -> list[str]:
        spec = self.spec
        members: dict[str, str] = {}
        docs: list[str] = []
        table: list[str] = []
        dunders: list[str] = []
        for meth in spec.entries(self.cls_name):
            name = f'{self.cls_name}.{meth}'
            kind = spec.method_kind(name)
            if kind == SLOT:
                dunders.append(meth)
            elif kind == PYCFUNCTION:
                doc, entry = self._pycfunction_entry(spec, name, meth)
                docs += doc
                table.append(entry)
            elif kind == SHARED:
                doc, entry = self._shared_entry(name)
                docs += doc
                table.append(entry)
            elif meth in ('__new__', '__init__'):
                try:
                    c_basename, vectorcall = self.functions[name]
                except KeyError:
                    raise spec.error(spec.functions[name], f"{name} is not "
                                     "a clinic function of the C "
                                     "file") from None
                members['tp_new' if meth == '__new__' else 'tp_init'] = \
                    c_basename
                if vectorcall:
                    members['tp_vectorcall'] = vectorcall
            else:
                table.append(self._clinic_entry(name))

        out = [f'/* {self.cls_name} */', '']
        class_doc = frontend._docstring(self.node.body)
        if class_doc is not None:
            doc_name = f'{self.prefix}__doc__'
            lines = spec._clean_docstring(self.node.body[0], class_doc)
            out += [f'PyDoc_STRVAR({doc_name},',
                    _c_string('\n'.join(lines)) + ');', '']
            members['tp_doc'] = doc_name
        out += docs

        if table:
            methods = f'{self.prefix}_methods'
            out += [f'static PyMethodDef {methods}[] = {{', *table,
                    '    {NULL, NULL}  /* sentinel */', '};', '']
            members['tp_methods'] = methods

        slot_funcs = self.resolve_slots(dunders)
        by_subtable: dict[str | None, dict[str, str]] = {}
        slotdefs = {s.slot: s for s in slots.slotdefs()}
        for slot, c_name in slot_funcs.items():
            by_subtable.setdefault(slotdefs[slot].subtable, {})[slot] = c_name
        for subtable in SUBTABLE_ORDER:
            if subtable not in by_subtable:
                continue
            var = f'{self.prefix}_{subtable}'
            ctype = slots.SUBTABLES[subtable]
            out.append(f'static {ctype} {var} = {{')
            for slot in _in_struct_order(by_subtable[subtable]):
                out.append(f'    .{slot} = {by_subtable[subtable][slot]},')
            out += ['};', '']
            members[f'tp_{subtable}'] = f'&{var}'
        members |= by_subtable.get(None, {})

        for base in self.node.bases:
            if not (isinstance(base, ast.Name)
                    and base.id in frontend.TYPE_OBJECTS):
                raise self.error("the base of a static type is one of "
                                 f"{sorted(frontend.TYPE_OBJECTS)}")
            members['tp_base'] = frontend.TYPE_OBJECTS[base.id]
        members.setdefault('tp_name', f'"{self.cls_name}"')
        for member in FROM_CLINIC & members.keys() & self.members.keys():
            raise self.error(f"@static_type: {member} is already the "
                             "clinic function")
        members |= {k: v for k, v in self.members.items()
                    if k != 'tp_flags'}
        if 'tp_basicsize' not in members:
            members['tp_basicsize'] = \
                f'sizeof({self.c_type.rstrip(" *")})'
        flags = ['Py_TPFLAGS_DEFAULT']
        if not _is_final(self.node):
            flags.append('Py_TPFLAGS_BASETYPE')
        if 'tp_traverse' in members:
            flags.append('Py_TPFLAGS_HAVE_GC')
        if 'tp_flags' in self.members:
            flags.append(self.members['tp_flags'])
        members['tp_flags'] = ' |\n        '.join(flags)

        storage = '' if _exported(self.type_object) else 'static '
        out.append(f'{storage}PyTypeObject {self.type_object} = {{')
        out.append('    PyVarObject_HEAD_INIT(&PyType_Type, 0)')
        for member in type_members():
            if member in members:
                out.append(f'    .{member} = {members[member]},')
        out += ['};', '']
        return out


def _in_struct_order(slot_funcs: dict[str, str]) -> list[str]:
    order = [s.slot for s in slots.slotdefs()]
    return sorted(slot_funcs, key=order.index)


def header(spec_path: str) -> str:
    """The comment starting Objects/clinic/<stem>_pyspec.c.h."""
    return ('/*[pyspec]\n'
            f'Generated by Argument Clinic from {spec_path}.\n'
            'Do not edit; edit the spec and run "make clinic".\n'
            '[pyspec]*/')


def generate(spec: frontend.Spec,
             classes: dict[str, tuple[str, str]],
             functions: dict[str, tuple[str, str | None]]) -> str | None:
    """The type objects of the @static_type classes of *spec*, or None.

    *classes* maps the clinic classes of the C file to (C type, type
    object); *functions* maps clinic functions ("bytes.split") to (C
    basename, vectorcall C name or None).  They are the end of
    Objects/clinic/<stem>_pyspec.c.h.
    """
    out = []
    for cls_name in spec.classes:
        members = static_type(spec, cls_name)
        if members is None:
            continue
        if cls_name not in classes:
            raise spec.error(spec.classes[cls_name], f"class {cls_name} "
                             "needs a clinic class directive in the C file "
                             "(its C type and type object)")
        out += TypeGenerator(spec, cls_name, members, classes[cls_name],
                             functions).generate()
    if not out:
        return None
    while out[-1] == '':
        out.pop()
    return '\n'.join(out)

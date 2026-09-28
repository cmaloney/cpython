"""Generate the method and slot tables of the types of a spec.

For each class of the spec of a C file that the C file declares (``class
bytes_iterator "striterobject *" "&PyBytesIter_Type"``; the spec of a
header only declares methods other specs share), Argument Clinic
generates at the end of Objects/clinic/<stem>_pyspec.c.h (included at the
end of the C file, after every function it names):

* ``<prefix>_doc``: the class docstring;
* the method table ``<prefix>_methods[]``: one entry per method of the
  class that is not a slot, in the order of the spec.  A clinic function
  is its ``*_METHODDEF`` macro; a hand-written PyCFunction
  (``@c_name(METH_NOARGS="f")``, frontend.Spec.pycfunction()) is written
  out with its docstring, as is a slot that also has one
  (``@c_name(mp_subscript="f", METH_O="f")`` and ``@coexist``); a shared
  method is the entry the other spec declares (see _shared_entry());
* the sub-tables ``<prefix>_as_number`` etc. holding the slots of the
  dunders (see slots.py).

The prefix is the class name, or the ``@c_name("striter")`` of the class.
The PyTypeObject itself is written in C, after the include, and names
these tables; its own slots (tp_repr, tp_iter...) are C functions it
names.  The dunders of those slots are declared in the class all the
same: test_clinic checks that the type has exactly the slot wrappers the
class declares.
"""

from __future__ import annotations

import ast
import os
import re

from libclinic.formatting import docstring_for_c_string

from . import frontend, slots
from .frontend import CLINIC, PYCFUNCTION, README, SHARED, SLOT, SpecError

SUBTABLE_ORDER = ['as_async', 'as_number', 'as_sequence', 'as_mapping',
                  'as_buffer']

# The decorators a method implemented in C by hand may have, by kind.
C_DECORATORS = {
    'slot': {'c_name', 'c_implemented', 'coexist', 'text_signature'},
    'PyCFunction': {'c_name', 'classmethod', 'staticmethod', 'coexist',
                    'text_signature', 'c_implemented'},
}


def class_prefix(spec: frontend.Spec, cls_name: str) -> str:
    """The C prefix of the tables of class *cls_name*: its
    ``@c_name("x")``, else its name."""
    for decorator in spec.classes[cls_name].decorator_list:
        match decorator:
            case ast.Call(func=ast.Name('c_name'),
                          args=[ast.Constant(str() as prefix)], keywords=[]):
                return prefix
            case _:
                raise spec.error(decorator, f"class {cls_name}: a spec "
                                 "class takes only @c_name(\"prefix\"), "
                                 "the prefix of its C tables")
    return cls_name


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


# ``critical_section(module.Class.meth)``: the C function calling a shared
# method in a critical section on self, by calling convention: its
# parameters after self, and the arguments it passes on.
LOCKED_WRAPPERS = {
    'METH_NOARGS': ('PyObject *Py_UNUSED(ignored)', 'NULL'),
    'METH_O': ('PyObject *arg', 'arg'),
    'METH_FASTCALL': ('PyObject *const *args, Py_ssize_t nargs',
                      'args, nargs'),
    'METH_FASTCALL|METH_KEYWORDS': (
        'PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames',
        'args, nargs, kwnames'),
}

_METHODDEF_FLAGS = r'\s*\\\n\s*\{"\w+",\s*[^,]+,\s*([\w|]+),'


def _clinic_flags(spec: frontend.Spec, c_basename: str, error) -> str:
    """The calling convention of clinic function *c_basename*, declared
    by *spec*: the flags of the ``*_METHODDEF`` clinic generated for the
    C file of *spec* (``stringlib/clinic/transmogrify.h.h``)."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(spec.filename)))
    stem = os.path.splitext(os.path.basename(spec.filename))[0]
    paths = [os.path.join(root, 'clinic', f'{stem}{ext}.h')
             for ext in ('.c', '.h')]
    macro = f'{c_basename.upper()}_METHODDEF'
    for path in paths:
        if os.path.exists(path):
            with open(path, encoding='utf-8') as f:
                m = re.search(rf'#define {macro}{_METHODDEF_FLAGS}',
                              f.read())
            if m:
                return m.group(1)
    raise error(f"no {macro} in {' or '.join(paths)}: run clinic on the "
                f"C file of {spec.filename} first")


class TypeGenerator:
    def __init__(self, spec: frontend.Spec, cls_name: str,
                 functions: dict[str, tuple[str, str | None]]):
        self.spec = spec
        self.cls_name = cls_name
        self.node = spec.classes[cls_name]
        self.functions = functions
        self.prefix = class_prefix(spec, cls_name)

    def error(self, message: str) -> SpecError:
        """A SpecError at the class."""
        return self.spec.error(self.node, message)

    # -- methods -----------------------------------------------------------

    def _pycfunction(self, spec: frontend.Spec, name: str, meth: str,
                     kind: str = 'PyCFunction'
                     ) -> tuple[list[str], str, str, str]:
        """(docstring definition, C function, flags, docstring name) of a
        hand-written PyCFunction of *spec*, or of the entry of a slot
        (*kind*).  With @text_signature, the docstring starts with the
        signature, as clinic writes it."""
        node = _c_stub(spec, name, kind)
        entry = spec.pycfunction(name)
        assert entry is not None
        doc = spec.docstring(name)
        for decorator in node.decorator_list:
            match decorator:
                case ast.Call(func=ast.Name('text_signature'),
                              args=[ast.Constant(str() as signature)]):
                    doc = f'{meth}{signature}\n--\n\n{doc or ""}'
        docs = []
        doc_name = 'NULL'
        if doc is not None:
            doc_name = f'{self.prefix}_{meth}__doc__'
            docs = [f'PyDoc_STRVAR({doc_name},', _c_string(doc) + ');', '']
        return docs, entry.c_function, entry.flags, doc_name

    def _clinic_entry(self, name: str) -> str:
        node = self.spec.functions[name]
        try:
            c_basename, _ = self.functions[name]
        except KeyError:
            raise self.spec.error(node, f"{name} is not a clinic function "
                                  "of the C file") from None
        return f'    {c_basename.upper()}_METHODDEF'

    def _shared_entry(self, name: str, meth: str) -> tuple[list[str], str]:
        """(docstrings and C functions to define first, method table
        entry) of shared method *name*."""
        spec = self.spec
        if name in self.functions:
            # It has a block in the C file: a clinic function of the class.
            c_basename, _ = self.functions[name]
            return [], f'    {c_basename.upper()}_METHODDEF'
        shared = spec.shared[name]
        other, other_name = spec.shared_source(name)

        def error(message: str) -> SpecError:
            return SpecError(message, filename=spec.filename,
                             lineno=shared.lineno)

        kind = other.method_kind(other_name)
        _, keywords = spec.c_name(name)
        locked = spec.is_locked(name)
        if kind == PYCFUNCTION:
            docs, c_func, flag, doc_name = self._pycfunction(
                other, other_name, meth)
        elif kind == CLINIC:
            docs = []
            if other is spec:
                c_basename, _ = self.functions[other_name]
            else:
                c_basename = (other.c_name(other_name)[0]
                              or other_name.replace('.', '_'))
            if not keywords and not locked:
                return [], f'    {c_basename.upper()}_METHODDEF'
            c_func, doc_name = c_basename, f'{c_basename}__doc__'
            flag = None if keywords else _clinic_flags(other, c_basename,
                                                       error)
        else:
            raise error(f"{other_name} of {other.filename} is a {kind}; "
                        "only methods can be shared")
        if keywords:
            (given, c_func), = keywords.items()
            if given not in frontend.PYCFUNCTION_FLAGS or \
                    flag not in (None, given):
                raise error(f"{name}: write c_name({flag or 'METH_NOARGS'}"
                            f"=\"f\")(...), the calling convention of "
                            f"{other_name}")
            if locked:
                raise error(f"{name}: critical_section() generates the C "
                            "function; remove c_name()")
            flag = given
        if locked:
            if flag not in LOCKED_WRAPPERS:
                raise error(f"{name}: critical_section() of a {flag} "
                            "function is not supported")
            params, call_args = LOCKED_WRAPPERS[flag]
            wrapper = f'{self.prefix}_{meth}'
            docs += ['static PyObject *',
                     f'{wrapper}(PyObject *self, {params})',
                     '{',
                     '    PyObject *ret;',
                     '    Py_BEGIN_CRITICAL_SECTION(self);',
                     f'    ret = {c_func}(self, {call_args});',
                     '    Py_END_CRITICAL_SECTION();',
                     '    return ret;',
                     '}',
                     '']
            c_func = wrapper
        if flag not in ('METH_NOARGS', 'METH_O'):
            c_func = f'_PyCFunction_CAST({c_func})'
        return docs, f'    {{"{meth}", {c_func}, {flag}, {doc_name}}},'

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
            has_entry = spec.pycfunction(name) is not None
            if frontend.docstring_of(node.body) is not None \
                    and not has_entry:
                raise spec.error(node, f"{name}: a slot has no docstring: "
                                 "its wrapper's comes from slotdefs in "
                                 "Objects/typeobject.c")
            candidates = [s.slot for s in slots.candidates(meth)]
            positional, keywords = spec.c_name(name)
            # A METH_ keyword: the entry of the slot in the method table.
            keywords = {k: v for k, v in keywords.items()
                        if k not in frontend.PYCFUNCTION_FLAGS}
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

    # -- the tables -------------------------------------------------------

    def generate(self) -> list[str]:
        spec = self.spec
        docs: list[str] = []
        table: list[str] = []
        dunders: list[str] = []
        for meth in spec.entries(self.cls_name):
            name = f'{self.cls_name}.{meth}'
            kind = spec.method_kind(name)
            if kind == SLOT:
                dunders.append(meth)
                if spec.pycfunction(name) is not None:
                    # Also in the method table (METH_COEXIST).
                    doc, c_func, flag, doc_name = self._pycfunction(
                        spec, name, meth, 'slot')
                    docs += doc
                    table.append(_method_def(meth, c_func, flag, doc_name))
            elif kind == PYCFUNCTION:
                doc, c_func, flag, doc_name = self._pycfunction(spec, name,
                                                                meth)
                docs += doc
                table.append(_method_def(meth, c_func, flag, doc_name))
            elif kind == SHARED:
                doc, entry = self._shared_entry(name, meth)
                docs += doc
                table.append(entry)
            elif meth not in ('__new__', '__init__'):
                # (tp_new and tp_init: the C of the type names them.)
                table.append(self._clinic_entry(name))

        out = [f'/* {self.cls_name} */', '']
        class_doc = frontend.docstring_of(self.node.body)
        if class_doc is not None:
            lines = spec._clean_docstring(self.node.body[0], class_doc)
            out += [f'PyDoc_STRVAR({self.prefix}_doc,',
                    _c_string('\n'.join(lines)) + ');', '']
        out += docs

        if table:
            out += [f'static PyMethodDef {self.prefix}_methods[] = {{',
                    *table, '    {NULL, NULL}  /* sentinel */', '};', '']

        # The slots of the sub-tables; those of the type itself (subtable
        # None) are named by its C.
        slot_funcs = self.resolve_slots(dunders)
        by_subtable: dict[str | None, dict[str, str]] = {}
        slotdefs = {s.slot: s for s in slots.slotdefs()}
        for slot, c_name in slot_funcs.items():
            by_subtable.setdefault(slotdefs[slot].subtable, {})[slot] = c_name
        for subtable in SUBTABLE_ORDER:
            if subtable not in by_subtable:
                continue
            ctype = slots.SUBTABLES[subtable]
            out.append(f'static {ctype} {self.prefix}_{subtable} = {{')
            for slot in _in_struct_order(by_subtable[subtable]):
                out.append(f'    .{slot} = {by_subtable[subtable][slot]},')
            out += ['};', '']
        return out if len(out) > 2 else []


def _method_def(meth: str, c_func: str, flags: str, doc_name: str) -> str:
    """The PyMethodDef of a hand-written PyCFunction."""
    if flags.split(' | ')[0] not in ('METH_NOARGS', 'METH_O'):
        c_func = f'_PyCFunction_CAST({c_func})'
    return f'    {{"{meth}", {c_func}, {flags}, {doc_name}}},'


def _in_struct_order(slot_funcs: dict[str, str]) -> list[str]:
    order = [s.slot for s in slots.slotdefs()]
    return sorted(slot_funcs, key=order.index)


def header(spec_path: str) -> str:
    """The comment starting Objects/clinic/<stem>_pyspec.c.h."""
    return ('/*[pyspec]\n'
            f'Generated by Argument Clinic from {spec_path}.\n'
            'Do not edit; edit the spec and run "make clinic".\n'
            '[pyspec]*/')


def generate(spec: frontend.Spec, classes: set[str],
             functions: dict[str, tuple[str, str | None]]) -> str | None:
    """The tables of the classes of *spec*, the spec of a C file, that
    the C file declares (clinic *classes*) and that declare slots
    (Spec.declares_slots()), or None.

    *functions* maps the clinic functions of the C file ("bytes.split")
    to (C basename, vectorcall C name or None).  They are the end of
    Objects/clinic/<stem>_pyspec.c.h.
    """
    out = []
    for cls_name in spec.classes:
        class_prefix(spec, cls_name)    # checks the class decorators
        if cls_name in classes and spec.declares_slots(cls_name):
            out += TypeGenerator(spec, cls_name, functions).generate()
    if not out:
        return None
    while out[-1] == '':
        out.pop()
    return '\n'.join(out)

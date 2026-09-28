"""Write the lowered form (ir.py) as C.

CBackend is the one place that knows C syntax, the C spelling of the
operations of ir.py (``PyBytes_CheckExact(x)``, ``Py_XDECREF(x)``, the
loops over a tuple or a list) and the layout of the generated file:
prototypes, functions, the comments before them and ``#if`` guards.
emit.py decides what the code does; the call tables of call_table.py are
C data of the interpreter, written there.
"""

from __future__ import annotations

from . import builtin_types, ir

OBJECT = 'PyObject *'
INDENT = '    '

# The C checks of the builtin types: name -> (check, exact check).
TYPE_CHECKS = {tp.__name__: (row.check, row.check_exact)
               for tp, row in builtin_types.TABLE.items()}

# The type objects of the builtin types, by name.
TYPE_OBJECTS = {tp.__name__: row.type_object
                for tp, row in builtin_types.TABLE.items()}

# ``hasattr(type(x), "__dunder__")``: whether the type fills the slot.
SLOT_CHECKS = {
    '__index__': '_PyIndex_Check({0})',
    '__buffer__': 'PyObject_CheckBuffer({0})',
}

FAILED = {
    ir.Convention.NULL: '{0} == NULL',
    ir.Convention.NULL_OR_MISSING: '{0} == NULL && PyErr_Occurred()',
    ir.Convention.MINUS1: '{0} == -1 && PyErr_Occurred()',
    ir.Convention.NEGATIVE: '{0} < 0',
}


def c_decl(ctype: str, name: str) -> str:
    return f'{ctype}{name}' if ctype.endswith('*') else f'{ctype} {name}'


def c_string(text: str) -> str:
    out = ['"']
    for ch in text:
        if ch in '\\"':
            out.append('\\' + ch)
        elif ch == '\n':
            out.append('\\n')
        elif ' ' <= ch <= '~':
            out.append(ch)
        else:
            raise ValueError(f'non-ASCII character in C string: {text!r}')
    out.append('"')
    return ''.join(out)


def _atomic(expr: str) -> bool:
    """Whether C expression *expr* is a name or a call: f(...)."""
    head, paren, rest = expr.partition('(')
    if not paren:
        return head.replace('_', '').isalnum()
    depth = 1
    for i, ch in enumerate(rest):
        depth += {'(': 1, ')': -1}.get(ch, 0)
        if depth == 0:
            return i == len(rest) - 1 and head.replace('_', '').isalnum()
    return False


def c_not(expr: str) -> str:
    return f'!{expr}' if _atomic(expr) else f'!({expr})'


class CBackend:
    """The C text of the lowered form."""

    # -- the file ------------------------------------------------------------

    @staticmethod
    def prototype(name: str, params: list[tuple[str, str]]) -> str:
        text = ', '.join(c_decl(ctype, n) for n, ctype in params) or 'void'
        return f'static PyObject *{name}({text});'

    @staticmethod
    def comment(title: str, code: str) -> list[str]:
        """A comment: *title*, then *code* (Python)."""
        code = code.replace('*/', '* /')
        return [f'/* {title}:',
                *[' * ' + line if line else ' *'
                  for line in code.splitlines()],
                ' */']

    @staticmethod
    def guard(condition: str, lines: list[str]) -> list[str]:
        """*lines* under the preprocessor *condition*, as clinic wraps
        the code of a block under #if."""
        if not condition:
            return lines
        return [f'#if {condition}', *lines, f'#endif /* {condition} */']

    def function(self, function: ir.Function) -> list[str]:
        params = ', '.join(c_decl(ctype, name)
                           for name, ctype in function.params) or 'void'
        declarations = [
            f'{INDENT}PyObject *{name} = NULL;' if ctype == OBJECT
            else f'{INDENT}{c_decl(ctype, name)};'
            for name, ctype in function.locals]
        return [
            'PyObject *' if function.exported else 'static PyObject *',
            f'{function.name}({params})',
            '{',
            *declarations,
            *([''] if function.locals else []),
            *self.block(function.body, 1),
            '}',
        ]

    # -- statements ----------------------------------------------------------

    def block(self, stmts: list[ir.Stmt], depth: int) -> list[str]:
        out = []
        for stmt in stmts:
            out += self.statement(stmt, depth)
        return out

    def statement(self, stmt: ir.Stmt, depth: int) -> list[str]:
        pad = INDENT * depth
        match stmt:
            case ir.Location(path, line):
                return [f'{pad}/* {path}:{line} */']
            case ir.Assign(target, value):
                return [f'{pad}{target} = {self.expr(value)};']
            case ir.Eval(value):
                return [f'{pad}{self.expr(value)};']
            case ir.If():
                return self.if_(stmt, depth)
            case ir.Return(value, []):
                return [f'{pad}return {self.expr(value)};']
            case ir.Return(value, after):
                return [f'{pad}{{',
                        f'{pad}{INDENT}PyObject *_return_value = '
                        f'{self.expr(value)};',
                        *self.block(after, depth + 1),
                        f'{pad}{INDENT}return _return_value;',
                        f'{pad}}}']
            case ir.Release(name, maybe_null):
                return [f'{pad}Py_{"X" if maybe_null else ""}DECREF({name});']
            case ir.ForIndex():
                return self.for_index(stmt, depth)
            case ir.ForIter(item, iterator, on_error, body):
                inner = pad + INDENT
                return [f'{pad}for (;;) {{',
                        f'{inner}{item} = PyIter_Next({self.expr(iterator)});',
                        f'{inner}if ({item} == NULL) {{',
                        f'{inner}{INDENT}if (PyErr_Occurred()) {{',
                        *self.block(on_error, depth + 3),
                        f'{inner}{INDENT}}}',
                        f'{inner}{INDENT}break;',
                        f'{inner}}}',
                        *self.block(body, depth + 1),
                        f'{pad}}}']
            case ir.Locked(obj, body):
                return [f'{pad}Py_BEGIN_CRITICAL_SECTION({self.expr(obj)});',
                        *self.block(body, depth),
                        f'{pad}Py_END_CRITICAL_SECTION();']
        raise AssertionError(stmt)

    def if_(self, stmt: ir.If, depth: int, keyword: str = 'if') -> list[str]:
        pad = INDENT * depth
        out = [f'{pad}{keyword} ({self.expr(stmt.test)}) {{',
               *self.block(stmt.body, depth + 1),
               f'{pad}}}']
        match stmt.orelse:
            case []:
                pass
            case [ir.If() as nested] if stmt.chain:
                out += self.if_(nested, depth, 'else if')
            case orelse:
                out += [f'{pad}else {{', *self.block(orelse, depth + 1),
                        f'{pad}}}']
        return out

    def for_index(self, stmt: ir.ForIndex, depth: int) -> list[str]:
        pad = INDENT * depth
        inner = pad + INDENT
        item, seq = stmt.item, self.expr(stmt.seq)
        index, count = f'{item}_index', f'{item}_count'
        match stmt.kind:
            case ir.Items.TUPLE:
                head = [f'{pad}for (Py_ssize_t {index} = 0, {count} = '
                        f'PyTuple_GET_SIZE({seq}); {index} < {count}; '
                        f'{index}++) {{',
                        f'{inner}{item} = PyTuple_GET_ITEM({seq}, {index});']
            case ir.Items.SNAPSHOT:
                items = f'{item}_items'
                head = [f'{pad}PyObject **{items} = _PyList_ITEMS({seq});',
                        f'{pad}for (Py_ssize_t {index} = 0, {count} = '
                        f'PyList_GET_SIZE({seq}); {index} < {count}; '
                        f'{index}++) {{',
                        f'{inner}{item} = {items}[{index}];']
            case ir.Items.LIST:
                head = [f'{pad}for (Py_ssize_t {index} = 0; ; {index}++) {{',
                        '#ifdef Py_GIL_DISABLED',
                        f'{inner}{item} = _PyList_GetItemRef('
                        f'(PyListObject *){seq}, {index});',
                        '#else',
                        f'{inner}{item} = {index} < PyList_GET_SIZE({seq}) ? '
                        f'Py_NewRef(PyList_GET_ITEM({seq}, {index})) : NULL;',
                        '#endif',
                        f'{inner}if ({item} == NULL) {{',
                        f'{inner}{INDENT}break;',
                        f'{inner}}}']
        return [*head, *self.block(stmt.body, depth + 1), f'{pad}}}']

    # -- expressions ---------------------------------------------------------

    def expr(self, node: ir.Expr) -> str:
        match node:
            case ir.Name(name):
                return name
            case ir.Null():
                return 'NULL'
            case ir.Int(value):
                return str(value)
            case ir.TypeObject(name):
                return TYPE_OBJECTS[name]
            case ir.ExceptionType(name):
                return f'PyExc_{name}'
            case ir.Identifier(text):
                return f'&_Py_ID({text})'
            case ir.String(text):
                return c_string(text)
            case ir.Cast(ctype, value):
                return f'({ctype}){self.expr(value)}'
            case ir.AddressOf(name):
                return f'&{name}'
            case ir.Call(func, args):
                return f'{func}({", ".join(self.expr(a) for a in args)})'
            case ir.NewRef(value):
                return f'Py_NewRef({self.expr(value)})'
            case ir.Not(value):
                return c_not(self.expr(value))
            case ir.BoolOp(op, values):
                parts = [self.expr(v) for v in values]
                joiner = ' && ' if op == 'and' else ' || '
                return joiner.join(p if _atomic(p) else f'({p})'
                                   for p in parts)
            case ir.Compare(op, left, right):
                return f'{self.expr(left)} {op} {self.expr(right)}'
            case ir.TypeCheck(type_name, exact, value):
                check = TYPE_CHECKS[type_name][1 if exact else 0]
                return f'{check}({self.expr(value)})'
            case ir.HasSlot(dunder, value):
                return SLOT_CHECKS[dunder].format(self.expr(value))
            case ir.TypeName(value):
                return f'Py_TYPE({self.expr(value)})->tp_name'
            case ir.Failed(value, convention):
                return FAILED[convention].format(self.expr(value))
            case ir.Fallback():
                return 'Py_None'
        raise AssertionError(node)

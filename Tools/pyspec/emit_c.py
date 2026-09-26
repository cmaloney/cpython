"""Generate C from a pyspec file.

Usage: python Tools/pyspec/emit_c.py Objects/pyspec/bytesobject.py \\
           -o Objects/clinic/bytesobject_pyspec.c.h

Every function in the spec becomes a C function of the same name:
  * a function whose first parameter is annotated ``type[T]`` implements a
    clinic __new__: it becomes NAME_impl() (Argument Clinic declares it and
    no longer expects a hand-written body), plus NAME_nargsN() for each
    positional argument count N -- the function partially evaluated for
    exactly T and N arguments, called by the clinic generated vectorcall;
  * names starting with Py or _Py are defined non-static (their public or
    internal header declares them);
  * everything else is static.

The accepted Python subset is small on purpose; anything else is an error.

Statements:
  if/else, return, raise E("...") / raise E(f"..."), raise C.<escape>(),
  pass,
  x = <call>, try: x = <call> / except E: ... / else: ...,
  with C.<context escape>(x): x = <call>
Conditions:
  x is [not] NULL, type(x) is K, cls is [not] K, isinstance(x, K),
  hasattr(type(x), "__dunder__"), (v := C.<escape>(...)) is [not] NULL,
  integer comparisons, and/or/not
Calls (result is a new reference or a Py_ssize_t):
  C.<escape>(...), iter(x), f() for an object variable f,
  <spec function>(...)

Reference ownership: parameters are borrowed; every object local is a new
reference, assigned once, declared NULL at the top and released with
Py_XDECREF at every exit except the one returning it.
"""

import argparse
import ast
import builtins
import os
import sys

TOOLS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(TOOLS, 'pyspec'))
sys.path.insert(0, os.path.join(TOOLS, 'clinic'))

from libclinic import pyspec as clinic_pyspec              # noqa: E402
import partial_eval                                         # noqa: E402
from partial_eval import NOTNULL, NULL, Spec, Value        # noqa: E402
import pyspec_runtime                                       # noqa: E402
from pyspec_runtime import (ContextEscape, Escape, ERR_MINUS1,  # noqa: E402
                            ERR_NULL, ERR_NULL_OR_MISSING, RaiseEscape)

OBJECT = 'PyObject *'
SSIZE = 'Py_ssize_t'
TYPE = clinic_pyspec.TYPE_CTYPE
TYPE_OBJECTS = clinic_pyspec.TYPE_OBJECTS

TYPE_CHECK = {
    'bytes': 'PyBytes_Check',
    'str': 'PyUnicode_Check',
    'int': 'PyLong_Check',
    'list': 'PyList_Check',
    'tuple': 'PyTuple_Check',
}

TYPE_CHECK_EXACT = {name: check + 'Exact'
                    for name, check in TYPE_CHECK.items()}

SLOT_CHECK = {
    '__index__': '_PyIndex_Check({0})',
    '__buffer__': 'PyObject_CheckBuffer({0})',
}

CONSTANT_OBJECTS = {
    repr(b''): 'Py_CONSTANT_EMPTY_BYTES',
    repr(''): 'Py_CONSTANT_EMPTY_STR',
    repr(()): 'Py_CONSTANT_EMPTY_TUPLE',
    repr(None): 'Py_CONSTANT_NONE',
    repr(0): 'Py_CONSTANT_ZERO',
    repr(1): 'Py_CONSTANT_ONE',
}

COMPARE_OPS = {ast.Lt: '<', ast.LtE: '<=', ast.Gt: '>', ast.GtE: '>=',
               ast.Eq: '==', ast.NotEq: '!='}


def c_decl(ctype, name):
    return f'{ctype}{name}' if ctype.endswith('*') else f'{ctype} {name}'


def c_not(expr):
    if expr.replace('_', '').replace('(', '').replace(')', '').isalnum():
        return f'!{expr}'
    return f'!({expr})'


class SpecError(Exception):
    def __init__(self, node, message):
        line = getattr(node, 'lineno', '?')
        super().__init__(f'line {line}: {message}')


def c_string(text):
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


def escape_of(node):
    """Return the escape for a ``C.<name>`` node."""
    if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
            and node.value.id == 'C'):
        value = getattr(pyspec_runtime.C, node.attr, None)
        if isinstance(value, (Escape, ContextEscape, RaiseEscape)):
            return value
        raise SpecError(node, f'unknown escape C.{node.attr}')
    return None


class FunctionEmitter:
    """Lower one list of spec statements to the body of a C function."""

    def __init__(self, spec, params, known_null=()):
        self.spec = spec
        # name -> C type; parameters are borrowed references
        self.params = dict(params)
        self.known_null = set(known_null)
        self.locals = {}            # name -> C type
        self.owned = []             # object locals, in declaration order
        self.live = set()           # object locals that may be non-NULL
        self.lines = []
        self.indent = 1

    # -- output ------------------------------------------------------------

    def emit(self, line):
        self.lines.append('    ' * self.indent + line if line else '')

    def cleanup(self, keep=None, null=()):
        for name in self.owned:
            if name in self.live and name != keep and name not in null:
                self.emit(f'Py_XDECREF({name});')

    def error_exit(self, null=()):
        self.cleanup(null=null)
        self.emit('return NULL;')

    def error_check(self, name, ctype, convention):
        self.emit(f'if ({self.error_condition(name, ctype, convention)}) {{')
        self.indent += 1
        self.error_exit(null={name})
        self.indent -= 1
        self.emit('}')

    # -- declarations ------------------------------------------------------

    def ctype_of(self, name):
        if name in self.params:
            return self.params[name]
        if name in self.locals:
            return self.locals[name]
        return None

    def declare(self, target, ctype, node):
        name = target.id
        if name in self.params or name in self.locals:
            raise SpecError(node, f'{name!r} is assigned more than once')
        self.locals[name] = ctype
        if ctype == OBJECT:
            self.owned.append(name)

    def collect_locals(self, stmts):
        """Declare every local up front so exits can release all of them."""
        for stmt in stmts:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Assign):
                    self.declare(node.targets[0], self.call_ctype(node.value),
                                 node)
                elif isinstance(node, ast.NamedExpr):
                    self.declare(node.target, self.call_ctype(node.value),
                                 node)

    def declarations(self):
        out = []
        for name, ctype in self.locals.items():
            if ctype == OBJECT:
                out.append(f'    PyObject *{name} = NULL;')
            else:
                out.append(f'    {c_decl(ctype, name)};')
        return out

    # -- calls -------------------------------------------------------------

    def call_ctype(self, call):
        if not isinstance(call, ast.Call):
            raise SpecError(call, 'only call results can be assigned')
        escape = escape_of(call.func)
        if isinstance(escape, Escape):
            return OBJECT if escape.returns == 'object' else SSIZE
        return OBJECT

    def lower_call(self, call):
        """Return (C expression, C type, error convention)."""
        escape = escape_of(call.func)
        if isinstance(escape, Escape):
            fields = {}
            for i, arg in enumerate(call.args):
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    fields[f'id{i}'] = arg.value
                    fields[str(i)] = c_string(arg.value)
                else:
                    fields[str(i)] = self.lower_value(arg)
            expr = escape.template.format(
                *[fields[str(i)] for i in range(len(call.args))],
                **{k: v for k, v in fields.items() if k.startswith('id')})
            ctype = OBJECT if escape.returns == 'object' else SSIZE
            return expr, ctype, escape.error
        if isinstance(call.func, ast.Name):
            name = call.func.id
            if name == 'iter' and len(call.args) == 1:
                return (f'PyObject_GetIter({self.lower_value(call.args[0])})',
                        OBJECT, ERR_NULL)
            if name in self.spec.functions:
                args = ', '.join(self.lower_value(a) for a in call.args)
                return (f'{c_name(describe(self.spec, name))}({args})',
                        OBJECT, ERR_NULL)
            if self.ctype_of(name) == OBJECT and not call.args:
                return f'_PyObject_CallNoArgs({name})', OBJECT, ERR_NULL
        raise SpecError(call, f'unsupported call {ast.unparse(call)}')

    @staticmethod
    def error_condition(var, ctype, convention):
        if convention == ERR_NULL:
            return f'{var} == NULL'
        if convention == ERR_NULL_OR_MISSING:
            return f'{var} == NULL && PyErr_Occurred()'
        if convention == ERR_MINUS1:
            return f'{var} == -1 && PyErr_Occurred()'
        raise AssertionError(convention)

    # -- expressions -------------------------------------------------------

    def lower_value(self, node):
        """A non-raising C expression used as an argument or operand."""
        match node:
            case ast.Name('NULL' | 'None'):
                return 'NULL'
            case ast.Name(id) if id in self.known_null:
                return 'NULL'
            case ast.Name(id) if self.ctype_of(id) is not None:
                return id
            case ast.Name(id) if id in TYPE_OBJECTS:
                return TYPE_OBJECTS[id]
            case ast.Name(id) if (
                    isinstance(getattr(builtins, id, None), type)
                    and issubclass(getattr(builtins, id), BaseException)):
                return f'PyExc_{id}'
            case ast.Constant(bool() as value):
                return '1' if value else '0'
            case ast.Constant(int() as value):
                return str(value)
        raise SpecError(node, f'unsupported value {ast.unparse(node)}')

    def lower_condition(self, node):
        match node:
            case ast.UnaryOp(op=ast.Not(), operand=operand):
                return c_not(self.lower_condition(operand))
            case ast.BoolOp(op=op, values=values):
                joiner = ' && ' if isinstance(op, ast.And) else ' || '
                parts = [self.lower_condition(v) for v in values]
                return joiner.join(p if c_not(p) == f'!{p}' else f'({p})'
                                   for p in parts)
            case ast.Compare(left=left, ops=[ast.Is() | ast.IsNot() as op],
                             comparators=[ast.Name('NULL')]):
                equal = '!=' if isinstance(op, ast.IsNot) else '=='
                if isinstance(left, ast.NamedExpr):
                    left = left.target
                return f'{self.lower_value(left)} {equal} NULL'
            case ast.Compare(left=ast.Call(func=ast.Name('type'), args=[obj]),
                             ops=[ast.Is() | ast.IsNot() as op],
                             comparators=[ast.Name(cls)]) \
                    if cls in TYPE_CHECK_EXACT:
                check = f'{TYPE_CHECK_EXACT[cls]}({self.lower_value(obj)})'
                return f'!{check}' if isinstance(op, ast.IsNot) else check
            case ast.Compare(left=ast.Name(name),
                             ops=[ast.Is() | ast.IsNot() as op],
                             comparators=[ast.Name(cls)]) \
                    if self.ctype_of(name) == TYPE and cls in TYPE_OBJECTS:
                equal = '!=' if isinstance(op, ast.IsNot) else '=='
                return f'{name} {equal} {TYPE_OBJECTS[cls]}'
            case ast.Call(func=ast.Name('isinstance'),
                          args=[obj, ast.Name(cls)]) if cls in TYPE_CHECK:
                return f'{TYPE_CHECK[cls]}({self.lower_value(obj)})'
            case ast.Call(func=ast.Name('hasattr'),
                          args=[ast.Call(func=ast.Name('type'), args=[obj]),
                                ast.Constant(str() as name)]) \
                    if name in SLOT_CHECK:
                return SLOT_CHECK[name].format(self.lower_value(obj))
            case ast.Compare(left=left, ops=[op], comparators=[right]) \
                    if type(op) in COMPARE_OPS:
                return (f'{self.lower_value(left)} {COMPARE_OPS[type(op)]} '
                        f'{self.lower_value(right)}')
        raise SpecError(node, f'unsupported condition {ast.unparse(node)}')

    def hoist_named(self, node):
        """Emit the assignment of a walrus that leads an if condition."""
        if (isinstance(node, ast.Compare)
                and isinstance(node.left, ast.NamedExpr)):
            named = node.left
            self.assign(named.target, named.value, named)
        for child in ast.walk(node):
            if isinstance(child, ast.NamedExpr) and (
                    not isinstance(node, ast.Compare)
                    or child is not node.left):
                raise SpecError(child,
                                'walrus only as the left operand of "is"')

    # -- statements --------------------------------------------------------

    def assign(self, target, value, node, check=True):
        expr, ctype, convention = self.lower_call(value)
        name = target.id
        if self.locals.get(name) != ctype:
            raise SpecError(node, f'{name!r} changes type')
        self.emit(f'{name} = {expr};')
        if ctype == OBJECT:
            self.live.add(name)
        if check:
            self.error_check(name, ctype, convention)
        return name, ctype, convention

    def statements(self, stmts):
        for stmt in stmts:
            self.statement(stmt)

    def statement(self, stmt):
        match stmt:
            case ast.Pass():
                pass
            case ast.Expr(ast.Constant(str())):
                pass                                    # docstring
            case ast.If(test=test, body=body, orelse=orelse):
                self.hoist_named(test)
                null_in_body, null_in_else = self.null_refinement(test)
                self.emit(f'if ({self.lower_condition(test)}) {{')
                branches = [self.block(body, null=null_in_body)]
                self.emit('}')
                if orelse:
                    self.lines.pop()
                    self.emit('}')
                    self.emit('else {')
                    branches.append(self.block(orelse, null=null_in_else))
                    self.emit('}')
                else:
                    branches.append(self.live - null_in_else)
                self.join(branches)
            case ast.Assign(targets=[ast.Name() as target], value=value):
                self.assign(target, value, stmt)
            case ast.Return(value=value):
                self.return_(value, stmt)
                self.live = set()
            case ast.Raise(exc=ast.Call(func=ast.Attribute() as func,
                                        args=[])):
                escape = escape_of(func)
                if not isinstance(escape, RaiseEscape):
                    raise SpecError(stmt, 'raise needs a C raise escape')
                self.emit(escape.template)
                self.error_exit()
                self.live = set()
            case ast.Raise(exc=ast.Call(func=ast.Name(exc), args=[message])):
                self.raise_(exc, message, stmt)
                self.live = set()
            case ast.Try(body=[ast.Assign(targets=[ast.Name() as target],
                                          value=value)],
                         handlers=handlers, orelse=orelse, finalbody=[]):
                self.try_(target, value, handlers, orelse, stmt)
            case ast.With(items=[ast.withitem(
                    context_expr=ast.Call(func=func, args=[obj]),
                    optional_vars=None)], body=body):
                self.with_(func, obj, body, stmt)
            case _:
                raise SpecError(stmt,
                                f'unsupported statement {ast.unparse(stmt)}')

    def block(self, stmts, null=()):
        """Emit a nested block; return its live set, or None if it exits."""
        saved = self.live
        self.live = saved - set(null)
        self.indent += 1
        self.statements(stmts)
        self.indent -= 1
        live = None if partial_eval.terminates(stmts) else self.live
        self.live = saved
        return live

    def join(self, branches):
        """Continue after branches; None marks a branch that exits."""
        falling = [live for live in branches if live is not None]
        self.live = set().union(*falling) if falling else set()

    @staticmethod
    def null_refinement(test):
        """Names known NULL in the (body, else) of ``if test``."""
        match test:
            case ast.Compare(left=left, ops=[ast.Is() | ast.IsNot() as op],
                             comparators=[ast.Name('NULL')]):
                if isinstance(left, ast.NamedExpr):
                    left = left.target
                if isinstance(left, ast.Name):
                    if isinstance(op, ast.IsNot):
                        return set(), {left.id}
                    return {left.id}, set()
        return set(), set()

    def return_(self, value, node):
        match value:
            case ast.Name(id) if id in self.params:
                self.cleanup()
                self.emit(f'return Py_NewRef({id});')
            case ast.Name(id) if self.locals.get(id) == OBJECT:
                self.cleanup(keep=id)
                self.emit(f'return {id};')
            case ast.Constant() | ast.Tuple():
                key = repr(ast.literal_eval(value))
                if key not in CONSTANT_OBJECTS:
                    raise SpecError(node, f'no Py_GetConstant() for {key}')
                self.cleanup()
                self.emit(f'return Py_GetConstant({CONSTANT_OBJECTS[key]});')
            case ast.Call():
                expr, ctype, convention = self.lower_call(value)
                if ctype != OBJECT or convention != ERR_NULL:
                    raise SpecError(node, 'can only return a new reference')
                if not self.live:
                    self.emit(f'return {expr};')
                    return
                self.emit('{')
                self.indent += 1
                self.emit(f'PyObject *_return_value = {expr};')
                self.cleanup()
                self.emit('return _return_value;')
                self.indent -= 1
                self.emit('}')
            case _:
                raise SpecError(node, f'unsupported return {ast.unparse(value)}')

    def raise_(self, exc, message, node):
        exc_c = self.lower_value(ast.Name(exc))
        match message:
            case ast.Constant(str() as text):
                self.emit(f'PyErr_SetString({exc_c}, {c_string(text)});')
            case ast.JoinedStr(values=values):
                fmt, args = [], []
                for part in values:
                    match part:
                        case ast.Constant(str() as text):
                            fmt.append(text.replace('%', '%%'))
                        case ast.FormattedValue(
                                value=ast.Call(
                                    func=ast.Name('fqname'),
                                    args=[ast.Call(func=ast.Name('type'),
                                                   args=[obj])]),
                                conversion=-1, format_spec=None):
                            fmt.append('%T')
                            args.append(self.lower_value(obj))
                        case ast.FormattedValue(
                                value=ast.Call(
                                    func=ast.Name('tp_name'),
                                    args=[ast.Call(func=ast.Name('type'),
                                                   args=[obj])]),
                                conversion=-1, format_spec=None):
                            fmt.append('%.200s')
                            args.append(
                                f'Py_TYPE({self.lower_value(obj)})->tp_name')
                        case _:
                            raise SpecError(node, 'unsupported f-string part '
                                            f'{ast.unparse(part)}')
                call_args = ', '.join([exc_c, c_string(''.join(fmt)), *args])
                self.emit(f'PyErr_Format({call_args});')
            case _:
                raise SpecError(node, 'raise needs a str or f-string message')
        self.error_exit()

    def try_(self, target, value, handlers, orelse, node):
        name, ctype, convention = self.assign(target, value, node, check=False)
        matches = []
        for handler in handlers:
            if handler.name is not None:
                raise SpecError(handler, '"except E as name" is not supported')
            types = (handler.type.elts if isinstance(handler.type, ast.Tuple)
                     else [handler.type])
            matches.append(' || '.join(
                f'PyErr_ExceptionMatches({self.lower_value(t)})'
                for t in types))
        self.emit(f'if ({self.error_condition(name, ctype, convention)}) {{')
        self.indent += 1
        # In the error branch the target holds no reference.
        saved = self.live
        self.live = saved - {name}
        branches = []
        for i, (handler, match_expr) in enumerate(zip(handlers, matches)):
            keyword = 'if' if i == 0 else 'else if'
            self.emit(f'{keyword} ({match_expr}) {{')
            self.indent += 1
            self.emit('PyErr_Clear();')
            self.indent -= 1
            branches.append(self.block(handler.body))
            self.emit('}')
        self.emit('else {')
        self.indent += 1
        self.error_exit()
        self.indent -= 1
        self.emit('}')
        self.live = saved
        self.indent -= 1
        self.emit('}')
        if orelse:
            self.emit('else {')
            branches.append(self.block(orelse))
            self.emit('}')
        else:
            branches.append(set(saved))
        self.join(branches)

    def with_(self, func, obj, body, node):
        context = escape_of(func)
        if not isinstance(context, ContextEscape):
            raise SpecError(node, 'with needs a C context escape')
        checks = []
        self.emit(context.begin.format(self.lower_value(obj)))
        for stmt in body:
            # Errors are checked after the end of the block, so the
            # block is always closed.
            if not (isinstance(stmt, ast.Assign)
                    and isinstance(stmt.targets[0], ast.Name)):
                raise SpecError(stmt, 'with bodies may only assign calls')
            checks.append(self.assign(stmt.targets[0], stmt.value, stmt,
                                      check=False))
        self.emit(context.end)
        for name, ctype, convention in checks:
            self.error_check(name, ctype, convention)

    # -- whole function ----------------------------------------------------

    def function(self, c_name, stmts):
        self.collect_locals(stmts)
        self.statements(stmts)
        if not partial_eval.terminates(stmts):
            raise SpecError(stmts[-1] if stmts else None,
                            f'{c_name}: control reaches the end')
        params = ', '.join(c_decl(ctype, name)
                           for name, ctype in self.params.items()) or 'void'
        return [
            'PyObject *' if exported(c_name) else 'static PyObject *',
            f'{c_name}({params})',
            '{',
            *self.declarations(),
            *([''] if self.locals else []),
            *self.lines,
            '}',
        ]


def describe(spec, name):
    """The libclinic.pyspec description of spec function *name*."""
    try:
        return clinic_pyspec.spec_function(spec.functions[name],
                                           spec.filename)
    except clinic_pyspec.SpecError as exc:
        raise SpecError(spec.functions[name], str(exc)) from None


def c_name(description):
    """C name of a spec function: NAME_impl() for a clinic __new__."""
    if description.new_type is not None:
        return f'{description.name}_impl'
    return description.name


def exported(name):
    return name.startswith(('Py', '_Py'))


def c_params(description):
    return [(p.name, p.ctype) for p in description.parameters]


def prototype(name, params):
    text = ', '.join(c_decl(ctype, n) for n, ctype in params) or 'void'
    return f'static PyObject *{name}({text});'


def generate(spec, spec_path):
    out = [
        '/*[pyspec]',
        f'Generated by Tools/pyspec/emit_c.py from {spec_path}.',
        'Do not edit; edit the spec and regenerate.',
        '[pyspec]*/',
        '',
    ]
    descriptions = [describe(spec, name) for name in spec.functions]
    for description in descriptions:
        name = c_name(description)
        if not exported(name):
            out.append(prototype(name, c_params(description)))
    out.append('')

    for description in descriptions:
        emitter = FunctionEmitter(spec, c_params(description))
        out += emitter.function(c_name(description),
                                spec.body(description.name))
        out.append('')

    for description in descriptions:
        if description.new_type is not None:
            out += generate_arities(spec, description)
    return '\n'.join(out)


def generate_arities(spec, description):
    """NAME_nargsN() for each allowed N: the clinic __new__ spec NAME
    partially evaluated for exactly its type and a call with N positional
    arguments; the rest are NULL.  Argument Clinic declares them and calls
    them from the vectorcall with converted values."""
    cls, *params = description.parameters
    required = sum(not p.optional for p in params)
    type_value = getattr(builtins, description.new_type)
    out = []
    for nargs in range(required, len(params) + 1):
        given, missing = params[:nargs], params[nargs:]
        env = {cls.name: Value(type_value)}
        env |= {p.name: NOTNULL for p in given}
        env |= {p.name: NULL for p in missing}
        residual = partial_eval.specialize(spec, description.name, env)
        emitter = FunctionEmitter(spec, [(p.name, p.ctype) for p in given],
                                  known_null=[p.name for p in missing])
        out += [f'/* {description.name}() for exactly '
                f'{description.new_type} with {nargs} positional '
                'argument(s):',
                *[' * ' + line if line else ' *'
                  for line in ast.unparse(ast.Module(residual, [])).replace(
                      '*/', '* /').splitlines()],
                ' */']
        out += emitter.function(f'{description.name}_nargs{nargs}', residual)
        out.append('')
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('spec')
    parser.add_argument('-o', '--output', required=True)
    args = parser.parse_args(argv)
    with open(args.spec) as f:
        spec = Spec(f.read(), args.spec)
    srcdir = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    spec_path = os.path.relpath(os.path.abspath(args.spec), srcdir)
    try:
        text = generate(spec, spec_path)
    except SpecError as exc:
        sys.exit(f'{args.spec}: {exc}')
    with open(args.output, 'w') as f:
        f.write(text + '\n')


if __name__ == '__main__':
    main()

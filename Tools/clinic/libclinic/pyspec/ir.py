"""The lowered form: a function as emit.py lowers it, for a backend.

emit.py lowers the residual code of a spec function (partial_eval.py)
to this form, which has made every decision that does not depend on the
language written: the C types of the locals, which references are owned
and where each is released (Release), the error check of every call
(Failed, with its Convention), and how a loop iterates (ForIndex,
ForIter).  A backend writes it out as the text of one language:
c_backend.py writes C.  Calls name functions and macros of the C API,
which any language calls through its C interface; the operations a
backend writes its own way (type checks, reference counting, loops,
critical sections, the fallback of a snapshot) are nodes of their own.
"""

from __future__ import annotations

import dataclasses as dc
import enum


class Convention(enum.Enum):
    """How a call reports an error (the error checks of emit.py)."""
    NULL = 'NULL'                   # NULL means an exception is set
    NULL_OR_MISSING = 'MISSING'     # NULL without an exception: absent
    MINUS1 = 'MINUS1'               # -1 with an exception set
    NEGATIVE = 'NEGATIVE'           # a negative int: an exception is set


class Items(enum.Enum):
    """How a ForIndex loop reads the items of its sequence."""
    TUPLE = 'tuple'         # borrowed; the size cannot change
    LIST = 'list'           # a new reference; the size is read each time
    SNAPSHOT = 'snapshot'   # a list in its critical section, where no
    #                         Python code runs: borrowed, size read once


# -- expressions -------------------------------------------------------------

@dc.dataclass(frozen=True)
class Name:                 # a parameter, a local, a constant of the C API
    id: str


@dc.dataclass(frozen=True)
class Null:                 # the null pointer
    pass


@dc.dataclass(frozen=True)
class Int:
    value: int


@dc.dataclass(frozen=True)
class TypeObject:           # the type object of a builtin type
    name: str


@dc.dataclass(frozen=True)
class ExceptionType:        # a builtin exception class
    name: str


@dc.dataclass(frozen=True)
class Identifier:           # a str constant passed as an (interned) object
    text: str


@dc.dataclass(frozen=True)
class String:               # a str constant passed as ``const char *``
    text: str


@dc.dataclass(frozen=True)
class Cast:
    ctype: str
    value: Expr


@dc.dataclass(frozen=True)
class AddressOf:            # of a local C struct
    name: str


@dc.dataclass(frozen=True)
class Call:
    func: str
    args: tuple[Expr, ...] = ()


@dc.dataclass(frozen=True)
class NewRef:               # a new reference to value
    value: Expr


@dc.dataclass(frozen=True)
class Not:
    value: Expr


@dc.dataclass(frozen=True)
class BoolOp:
    op: str                 # 'and', 'or'
    values: tuple[Expr, ...]


@dc.dataclass(frozen=True)
class Compare:
    op: str                 # '==', '!=', '<', '<=', '>', '>='
    left: Expr
    right: Expr


@dc.dataclass(frozen=True)
class TypeCheck:            # type(value) is T (exact), isinstance(value, T)
    type_name: str
    exact: bool
    value: Expr


@dc.dataclass(frozen=True)
class HasSlot:              # hasattr(type(value), dunder): the slot is set
    dunder: str
    value: Expr


@dc.dataclass(frozen=True)
class TypeName:             # the name of type(value), for a message
    value: Expr


@dc.dataclass(frozen=True)
class Failed:               # value, a result, reports an error
    value: Expr
    convention: Convention


@dc.dataclass(frozen=True)
class Fallback:             # the result of a snapshot that restarts
    pass                    # through the generic function; no reference


Expr = (Name | Null | Int | TypeObject | ExceptionType | Identifier
        | String | Cast | AddressOf | Call | NewRef | Not | BoolOp | Compare
        | TypeCheck | HasSlot | TypeName | Failed | Fallback)


# -- statements --------------------------------------------------------------

@dc.dataclass
class Location:             # the line of the spec the code lowered from
    path: str
    line: int


@dc.dataclass
class Assign:
    target: str
    value: Expr


@dc.dataclass
class Eval:                 # value, for its effect
    value: Expr


@dc.dataclass
class If:
    test: Expr
    body: list[Stmt]
    orelse: list[Stmt] = dc.field(default_factory=list)
    chain: bool = False


@dc.dataclass
class Return:               # after: run after value is computed (releases)
    value: Expr
    after: list[Stmt] = dc.field(default_factory=list)


@dc.dataclass
class Release:              # the reference of a local, maybe NULL
    name: str
    maybe_null: bool


@dc.dataclass
class ForIndex:             # the items of seq, by index, into local item
    item: str
    seq: Expr
    kind: Items
    body: list[Stmt]


@dc.dataclass
class ForIter:              # iterate into local item (a new reference);
    item: str               # on an error, on_error (which exits)
    iterator: Expr
    on_error: list[Stmt]
    body: list[Stmt]


@dc.dataclass
class Locked:               # body in the critical section of obj
    obj: Expr
    body: list[Stmt]


Stmt = Location | Assign | Eval | If | Return | Release | ForIndex | ForIter \
    | Locked


@dc.dataclass
class Function:
    """A function returning a new reference (or NULL with an exception
    set).  *locals*: (name, C type) in order; an object local starts as
    NULL.  *exported*: not static (a header declares it)."""
    name: str
    params: list[tuple[str, str]]
    locals: list[tuple[str, str]]
    body: list[Stmt]
    exported: bool

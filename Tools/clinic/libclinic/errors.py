import ast
import dataclasses as dc
import enum
from typing import Literal,  NoReturn, overload


@dc.dataclass
class ClinicError(Exception):
    message: str
    _: dc.KW_ONLY
    lineno: int | None = None
    filename: str | None = None

    def __post_init__(self) -> None:
        super().__init__(self.message)

    def report(self, *, warn_only: bool = False) -> str:
        """The message as compilers print it: ``path:line: error: msg``."""
        where = [str(x) for x in (self.filename, self.lineno)
                 if x is not None]
        kind = "warning" if warn_only else "error"
        return ": ".join([":".join(where), kind] if where
                         else [kind]) + f": {self.message}\n"


class ParseError(ClinicError):
    pass


# Where errors about the spec language send the reader.
PYSPEC_README = 'Objects/pyspec/README.rst'


class SpecErrorKind(enum.Enum):
    """What is wrong with a spec (see Objects/pyspec/README.rst)."""
    # Not valid in the spec language.
    INVALID = 'invalid'
    # Valid, but outside the lowered subset (libclinic/pyspec/subset.py):
    # it cannot be lowered to C yet.
    NOT_LOWERED = 'not lowered'
    # In the lowered subset, but this use of it cannot be lowered (a
    # local that changes type, a call that cannot fail in a try, ...).
    LOWERING = 'lowering'
    # The spec and the clinic blocks of the C file disagree.
    BINDING = 'binding'


# The hint added to the message of an error of each kind.
SPEC_ERROR_HINTS = {
    SpecErrorKind.NOT_LOWERED: (
        f'see "The lowered subset" in {PYSPEC_README}; a hand-written C '
        'function keeps this as its Python reference with @c_implemented'),
}


@dc.dataclass
class SpecError(ClinicError):
    """An error in a spec file (libclinic/pyspec), reported by clinic as
    ``path:line: error: message`` at the line of the spec."""
    _: dc.KW_ONLY
    kind: SpecErrorKind = SpecErrorKind.INVALID

    def __post_init__(self) -> None:
        hint = SPEC_ERROR_HINTS.get(self.kind)
        if hint is not None and hint not in self.message:
            self.message = f'{self.message}; {hint}'
        super().__post_init__()

    @classmethod
    def at(cls, node: ast.AST | None, message: str,
           kind: SpecErrorKind = SpecErrorKind.INVALID,
           filename: str | None = None) -> 'SpecError':
        """An error at the line of *node*, in the spec it was written in:
        a node copied from another spec (a fast path, partial_eval.py)
        is marked with that spec (``pyspec_scope``), else *filename*."""
        return cls(message, kind=kind,
                   filename=getattr(node, 'pyspec_scope', None) or filename,
                   lineno=getattr(node, 'lineno', None) or None)


@overload
def warn_or_fail(
    *args: object,
    fail: Literal[True],
    filename: str | None = None,
    line_number: int | None = None,
) -> NoReturn: ...

@overload
def warn_or_fail(
    *args: object,
    fail: Literal[False] = False,
    filename: str | None = None,
    line_number: int | None = None,
) -> None: ...

def warn_or_fail(
    *args: object,
    fail: bool = False,
    filename: str | None = None,
    line_number: int | None = None,
) -> None:
    joined = " ".join([str(a) for a in args])
    error = ClinicError(joined, filename=filename, lineno=line_number)
    if fail:
        raise error
    else:
        print(error.report(warn_only=True), end="")


def warn(
    *args: object,
    filename: str | None = None,
    line_number: int | None = None,
) -> None:
    return warn_or_fail(*args, filename=filename, line_number=line_number, fail=False)

def fail(
    *args: object,
    filename: str | None = None,
    line_number: int | None = None,
) -> NoReturn:
    warn_or_fail(*args, filename=filename, line_number=line_number, fail=True)

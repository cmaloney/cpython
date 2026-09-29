"""Spec of Objects/bytes_methods.c: what bytes and bytearray share.

Each function is ``@native(facts=False)``: C written by hand, the body
its pure-Python implementation, which only the model runs
(Tools/clinic/libclinic/pyspec/model.py; Objects/pyspec/README.rst,
"Pure Python"); for clinic and the facts it is ``...``.  Some are a
macro or a static function of the file, or of the stringlib templates it
includes (``stringlib_find``).  ``str`` is the bytes, a tuple of ints
(what the machine gives for ``const char *``, machine.ob_items()),
``len`` their number; what the C writes to ``char *result`` is returned,
a list of ints.
"""

from libclinic.pyspec.runtime import (
    NULL, PY_SSIZE_T_MAX, isinstance, native, tp_name)
from libclinic.pyspec.machine import buffer_items

from Objects.pyspec.abstract import PyNumber_AsSsize_t


# Py_ISSPACE(), Py_ISLOWER()... of Include/pyctype.h: ASCII only.
SPACE = frozenset(map(ord, ' \t\n\r\x0b\x0c'))
LOWER = frozenset(range(ord('a'), ord('z') + 1))
UPPER = frozenset(range(ord('A'), ord('Z') + 1))
DIGIT = frozenset(range(ord('0'), ord('9') + 1))
ALPHA = LOWER | UPPER
ALNUM = ALPHA | DIGIT


@native(facts=False)
def Py_TOLOWER(c: 'unsigned char') -> 'unsigned char':
    return c + 32 if c in UPPER else c


@native(facts=False)
def Py_TOUPPER(c: 'unsigned char') -> 'unsigned char':
    return c - 32 if c in LOWER else c


@native(facts=False)
def _Py_bytes_isspace(str: 'const char *', len: Py_ssize_t):
    return len > 0 and all(c in SPACE for c in str)


@native(facts=False)
def _Py_bytes_isalpha(str: 'const char *', len: Py_ssize_t):
    return len > 0 and all(c in ALPHA for c in str)


@native(facts=False)
def _Py_bytes_isalnum(str: 'const char *', len: Py_ssize_t):
    return len > 0 and all(c in ALNUM for c in str)


@native(facts=False)
def _Py_bytes_isascii(str: 'const char *', len: Py_ssize_t):
    return all(c < 128 for c in str)


@native(facts=False)
def _Py_bytes_isdigit(str: 'const char *', len: Py_ssize_t):
    return len > 0 and all(c in DIGIT for c in str)


@native(facts=False)
def _Py_bytes_islower(str: 'const char *', len: Py_ssize_t):
    return (any(c in LOWER for c in str)
            and not any(c in UPPER for c in str))


@native(facts=False)
def _Py_bytes_isupper(str: 'const char *', len: Py_ssize_t):
    return (any(c in UPPER for c in str)
            and not any(c in LOWER for c in str))


@native(facts=False)
def _Py_bytes_istitle(str: 'const char *', len: Py_ssize_t):
    cased = False
    previous_is_cased = False
    for c in str:
        if c in UPPER:
            if previous_is_cased:
                return False
            previous_is_cased = cased = True
        elif c in LOWER:
            if not previous_is_cased:
                return False
            previous_is_cased = cased = True
        else:
            previous_is_cased = False
    return cased


@native(facts=False)
def _Py_bytes_lower(str: 'const char *', len: Py_ssize_t):
    return [Py_TOLOWER(c) for c in str]


@native(facts=False)
def _Py_bytes_upper(str: 'const char *', len: Py_ssize_t):
    return [Py_TOUPPER(c) for c in str]


@native(facts=False)
def _Py_bytes_title(str: 'const char *', len: Py_ssize_t):
    result = []
    previous_is_cased = False
    for c in str:
        if c in LOWER:
            if not previous_is_cased:
                c = Py_TOUPPER(c)
            previous_is_cased = True
        elif c in UPPER:
            if previous_is_cased:
                c = Py_TOLOWER(c)
            previous_is_cased = True
        else:
            previous_is_cased = False
        result.append(c)
    return result


@native(facts=False)
def _Py_bytes_capitalize(str: 'const char *', len: Py_ssize_t):
    return [Py_TOUPPER(c) if i == 0 else Py_TOLOWER(c)
            for i, c in enumerate(str)]


@native(facts=False)
def _Py_bytes_swapcase(str: 'const char *', len: Py_ssize_t):
    return [Py_TOLOWER(c) if c in UPPER else Py_TOUPPER(c) for c in str]


@native(facts=False)
def _Py_bytes_maketrans(frm: 'Py_buffer *', to: 'Py_buffer *'):
    """The 256 bytes of the table (the caller makes the object)."""
    if len(frm) != len(to):
        raise ValueError("maketrans arguments must have same length")
    table = list(range(256))
    for i, c in enumerate(frm):
        table[c] = to[i]
    return table


@native(facts=False)
def ADJUST_INDICES(start: Py_ssize_t, end: Py_ssize_t, len: Py_ssize_t):
    """start and end made bounds of a slice of len items: (start, end)."""
    if end > len:
        end = len
    elif end < 0:
        end += len
        if end < 0:
            end = 0
    if start < 0:
        start += len
        if start < 0:
            start = 0
    return start, end


@native(facts=False)
def getbuffer(obj: object):
    """PyObject_GetBuffer(obj, PyBUF_SIMPLE): the bytes of its buffer."""
    items = buffer_items(obj)
    if items is NULL:
        raise TypeError("a bytes-like object is required, not "
                        f"'{tp_name(type(obj))}'")
    return items


@native(facts=False)
def parse_args_finds_byte(function_name: 'const char *', subobj: object):
    """The bytes to look for: of the buffer of subobj, or the one byte
    subobj is (an int in range(256))."""
    if hasattr(type(subobj), '__buffer__'):
        return getbuffer(subobj)
    if not hasattr(type(subobj), '__index__'):
        raise TypeError("argument should be integer or bytes-like object, "
                        f"not '{tp_name(type(subobj))}'")
    ival = PyNumber_AsSsize_t(subobj, NULL)
    if ival < 0 or ival > 255:
        raise ValueError("byte must be in range(0, 256)")
    return (ival,)


@native(facts=False)
def stringlib_find(str: 'const char *', sub: 'const char *',
                   start: Py_ssize_t, end: Py_ssize_t):
    """The first index of sub in str[start:end], or -1."""
    for i in range(start, end - len(sub) + 1):
        if str[i:i + len(sub)] == sub:
            return i
    return -1


@native(facts=False)
def stringlib_rfind(str: 'const char *', sub: 'const char *',
                    start: Py_ssize_t, end: Py_ssize_t):
    """The last index of sub in str[start:end], or -1."""
    for i in range(end - len(sub), start - 1, -1):
        if str[i:i + len(sub)] == sub:
            return i
    return -1


@native(facts=False)
def stringlib_count(str: 'const char *', sub: 'const char *',
                    maxcount: Py_ssize_t):
    """The non-overlapping occurrences of sub in str, at most
    maxcount."""
    if not sub:
        return min(len(str) + 1, maxcount)
    n = i = 0
    while n < maxcount and i <= len(str) - len(sub):
        if str[i:i + len(sub)] == sub:
            n += 1
            i += len(sub)
        else:
            i += 1
    return n


@native(facts=False)
def find_internal(str: 'const char *', len: Py_ssize_t,
                  function_name: 'const char *', subobj: object,
                  start: Py_ssize_t, end: Py_ssize_t, dir: int):
    sub = parse_args_finds_byte(function_name, subobj)
    start, end = ADJUST_INDICES(start, end, len)
    if end - start < builtin_len(sub):
        return -1
    if dir > 0:
        return stringlib_find(str, sub, start, end)
    return stringlib_rfind(str, sub, start, end)


builtin_len = len


@native(facts=False)
def _Py_bytes_find(str: 'const char *', len: Py_ssize_t, sub: object,
                   start: Py_ssize_t, end: Py_ssize_t):
    return find_internal(str, len, "find", sub, start, end, +1)


@native(facts=False)
def _Py_bytes_index(str: 'const char *', len: Py_ssize_t, sub: object,
                    start: Py_ssize_t, end: Py_ssize_t):
    result = find_internal(str, len, "index", sub, start, end, +1)
    if result == -1:
        raise ValueError("subsection not found")
    return result


@native(facts=False)
def _Py_bytes_rfind(str: 'const char *', len: Py_ssize_t, sub: object,
                    start: Py_ssize_t, end: Py_ssize_t):
    return find_internal(str, len, "rfind", sub, start, end, -1)


@native(facts=False)
def _Py_bytes_rindex(str: 'const char *', len: Py_ssize_t, sub: object,
                     start: Py_ssize_t, end: Py_ssize_t):
    result = find_internal(str, len, "rindex", sub, start, end, -1)
    if result == -1:
        raise ValueError("subsection not found")
    return result


@native(facts=False)
def _Py_bytes_count(str: 'const char *', len: Py_ssize_t, sub_obj: object,
                    start: Py_ssize_t, end: Py_ssize_t):
    sub = parse_args_finds_byte("count", sub_obj)
    start, end = ADJUST_INDICES(start, end, len)
    if end - start < 0:
        return 0
    return stringlib_count(str[start:end], sub, PY_SSIZE_T_MAX)


@native(facts=False)
def _Py_bytes_contains(str: 'const char *', len: Py_ssize_t,
                       arg: object) -> int:
    try:
        ival = PyNumber_AsSsize_t(arg, NULL)
    except Exception:
        # (C clears any error and tries the buffer.)
        return stringlib_find(str, getbuffer(arg), 0, len) >= 0
    if ival < 0 or ival >= 256:
        raise ValueError("byte must be in range(0, 256)")
    return ival in str


@native(facts=False)
def tailmatch(str: 'const char *', len: Py_ssize_t, substr: object,
              start: Py_ssize_t, end: Py_ssize_t, direction: int) -> int:
    sub = getbuffer(substr)
    slen = builtin_len(sub)
    start, end = ADJUST_INDICES(start, end, len)
    if direction < 0:
        # startswith
        if start > len - slen:
            return False
    else:
        # endswith
        if end - start < slen or start > len:
            return False
        if end - slen > start:
            start = end - slen
    if end - start < slen:
        return False
    return str[start:start + slen] == sub


@native(facts=False)
def _Py_bytes_tailmatch(str: 'const char *', len: Py_ssize_t,
                        function_name: 'const char *', subobj: object,
                        start: Py_ssize_t, end: Py_ssize_t, direction: int):
    if isinstance(subobj, tuple):
        return any(tailmatch(str, len, item, start, end, direction)
                   for item in subobj)
    try:
        return tailmatch(str, len, subobj, start, end, direction)
    except TypeError:
        raise TypeError(f"{function_name} first arg must be bytes or a "
                        "tuple of bytes, not "
                        f"{tp_name(type(subobj))}") from None


@native(facts=False)
def _Py_bytes_startswith(str: 'const char *', len: Py_ssize_t,
                         subobj: object, start: Py_ssize_t,
                         end: Py_ssize_t):
    return _Py_bytes_tailmatch(str, len, "startswith", subobj, start, end,
                               -1)


@native(facts=False)
def _Py_bytes_endswith(str: 'const char *', len: Py_ssize_t, subobj: object,
                       start: Py_ssize_t, end: Py_ssize_t):
    return _Py_bytes_tailmatch(str, len, "endswith", subobj, start, end, +1)


@native(facts=False)
def _Py_bytes_repr(data: 'const char *', length: Py_ssize_t,
                   smartquotes: int, classname: 'const char *'):
    squotes = data.count(ord("'"))
    dquotes = data.count(ord('"'))
    quote = '"' if smartquotes and squotes and not dquotes else "'"
    out = ['b', quote]
    for c in data:
        if c == ord(quote) or c == ord('\\'):
            out.append('\\' + chr(c))
        elif c == ord('\t'):
            out.append('\\t')
        elif c == ord('\n'):
            out.append('\\n')
        elif c == ord('\r'):
            out.append('\\r')
        elif c < 32 or c >= 0x7f:
            out.append(f'\\x{c:02x}')
        else:
            out.append(chr(c))
    out.append(quote)
    return ''.join(out)

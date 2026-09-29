"""Spec of Python/pystrhex.c: bytes as hexadecimal numbers.

Each function is ``@native(facts=False)``: C written by hand, the body
its pure-Python implementation, which only the model runs
(Objects/pyspec/README.rst, "Pure Python").
"""

from libclinic.pyspec.runtime import NULL, isinstance, native


@native(facts=False)
def _Py_strhex_with_sep(argbuf: 'const char *', arglen: Py_ssize_t,
                        sep: object, bytes_per_sep: Py_ssize_t):
    """The str of two hexadecimal digits per byte of argbuf, with sep
    (a str or bytes of length 1, or NULL) between groups of
    bytes_per_sep bytes, counted from the end (from the start if
    negative)."""
    sep_char = ''
    if sep is not NULL:
        if len(sep) != 1:
            raise ValueError("sep must be length 1.")
        if isinstance(sep, str):
            if ord(sep) > 255:
                raise ValueError("sep must be ASCII.")
            sep_char = sep
        elif isinstance(sep, bytes):
            sep_char = chr(sep[0])
        else:
            raise TypeError("sep must be str or bytes.")
        if ord(sep_char) > 127:
            raise ValueError("sep must be ASCII.")
    else:
        bytes_per_sep = 0
    digits = [f'{c:02x}' for c in argbuf]
    group = abs(bytes_per_sep)
    if group == 0 or group >= arglen:
        return ''.join(digits)
    if bytes_per_sep > 0:
        first = arglen % group or group
        groups = [digits[:first]] + [digits[i:i + group]
                                     for i in range(first, arglen, group)]
    else:
        groups = [digits[i:i + group] for i in range(0, arglen, group)]
    return sep_char.join(''.join(g) for g in groups)

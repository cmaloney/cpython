"""Spec of Python/pyhash.c: the hash of bytes.

Each function is ``@native(facts=False)``: C written by hand, the body
its pure-Python implementation, which only the model runs
(Objects/pyspec/README.rst, "Pure Python").  The key is a parameter of
the interpreter (machine.hash_secret(): PYTHONHASHSEED, or random).
"""

import sys

from libclinic.pyspec.runtime import native
from libclinic.pyspec.machine import hash_secret


MASK = (1 << 64) - 1


@native(facts=False)
def ROTATE(x: 'uint64_t', b: int) -> 'uint64_t':
    return ((x << b) | (x >> (64 - b))) & MASK


@native(facts=False)
def SINGLE_ROUND(v: 'uint64_t[4]') -> None:
    """HALF_ROUND(v0,v1,v2,v3,13,16); HALF_ROUND(v2,v1,v0,v3,17,21)."""
    for a, b, c, d, s, t in ((0, 1, 2, 3, 13, 16), (2, 1, 0, 3, 17, 21)):
        v[a] = (v[a] + v[b]) & MASK
        v[c] = (v[c] + v[d]) & MASK
        v[b] = ROTATE(v[b], s) ^ v[a]
        v[d] = ROTATE(v[d], t) ^ v[c]
        v[a] = ROTATE(v[a], 32)


@native(facts=False)
def siphash13(k0: 'uint64_t', k1: 'uint64_t', src: 'const void *',
              src_sz: Py_ssize_t) -> 'uint64_t':
    b = (src_sz << 56) & MASK
    v = [k0 ^ 0x736f6d6570736575, k1 ^ 0x646f72616e646f6d,
         k0 ^ 0x6c7967656e657261, k1 ^ 0x7465646279746573]
    whole = src_sz - src_sz % 8
    for i in range(0, whole, 8):
        mi = int.from_bytes(src[i:i + 8], 'little')
        v[3] ^= mi
        SINGLE_ROUND(v)
        v[0] ^= mi
    b |= int.from_bytes(src[whole:], 'little')
    v[3] ^= b
    SINGLE_ROUND(v)
    v[0] ^= b
    v[2] ^= 0xff
    SINGLE_ROUND(v)
    SINGLE_ROUND(v)
    SINGLE_ROUND(v)
    return (v[0] ^ v[1]) ^ (v[2] ^ v[3])


@native(facts=False)
def Py_HashBuffer(ptr: 'const void *', len: Py_ssize_t) -> 'Py_hash_t':
    """The hash of len bytes (a tuple of ints): 0 for none; never -1."""
    if len == 0:
        return 0
    info = sys.hash_info
    if info.cutoff > 0 and len < info.cutoff:
        raise NotImplementedError('the model has no DJBX33A (Py_HASH_CUTOFF)')
    if info.algorithm != 'siphash13':
        raise NotImplementedError(f'the model has no {info.algorithm}')
    k0, k1 = hash_secret()
    x = siphash13(k0, k1, bytes_of(ptr), len)
    x -= (x >> 63) << 64            # Py_hash_t is signed
    return -2 if x == -1 else x


@native(facts=False)
def bytes_of(items: 'const void *') -> 'const void *':
    """The bytes as int.from_bytes() takes them: a list of ints."""
    return list(items)

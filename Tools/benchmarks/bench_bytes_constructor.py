"""Benchmark bytes() and bytearray() construction paths.

Companion to bench_str_constructor.py, covering the paths the clinic
@vectorcall conversion of bytes.__new__ and bytearray.__init__ touches:
no-arg, a count, each accepted source type, positional and keyword
encoding/errors, subclass construction and the explicit slot calls.

The "unique temporary" group exists because the vectorcall is what makes
PyUnstable_Object_IsUniqueReferencedTemporary() usable on a constructor
argument at all.  _PyObject_MakeTpCall() puts the argument in an args
tuple on the way to type_call(), which is a second reference, so the
check always failed before.  Each of those benchmarks is paired with a
control that only builds the source object, so the difference is the
constructor's own cost.

Each body is unrolled 10x so loop overhead does not dominate.
"""

import pyperf

SIZE = 4096


# --- bytes() --------------------------------------------------------------

def bench_bytes_no_args(loops):
    """bytes() -- nargs == 0, returns the empty-bytes singleton."""
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytes()
        bytes()
        bytes()
        bytes()
        bytes()
        bytes()
        bytes()
        bytes()
        bytes()
        bytes()
    return pyperf.perf_counter() - t0


def bench_bytes_from_count(loops):
    """bytes(8) -- the _PyIndex_Check() branch, allocate and zero."""
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytes(8)
        bytes(8)
        bytes(8)
        bytes(8)
        bytes(8)
        bytes(8)
        bytes(8)
        bytes(8)
        bytes(8)
        bytes(8)
    return pyperf.perf_counter() - t0


def bench_bytes_from_bytes(loops):
    """bytes(b) where b is already bytes -- returns it unchanged."""
    b = b"hello world"
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytes(b)
        bytes(b)
        bytes(b)
        bytes(b)
        bytes(b)
        bytes(b)
        bytes(b)
        bytes(b)
        bytes(b)
        bytes(b)
    return pyperf.perf_counter() - t0


def bench_bytes_from_list(loops):
    """bytes([...]) -- the list-of-ints fast path."""
    values = [1, 2, 3, 4, 5, 6, 7, 8]
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytes(values)
        bytes(values)
        bytes(values)
        bytes(values)
        bytes(values)
        bytes(values)
        bytes(values)
        bytes(values)
        bytes(values)
        bytes(values)
    return pyperf.perf_counter() - t0


def bench_bytes_from_bytearray(loops):
    """bytes(ba) -- goes through the buffer interface and copies."""
    ba = bytearray(b"hello world")
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytes(ba)
        bytes(ba)
        bytes(ba)
        bytes(ba)
        bytes(ba)
        bytes(ba)
        bytes(ba)
        bytes(ba)
        bytes(ba)
        bytes(ba)
    return pyperf.perf_counter() - t0


def bench_bytes_enc_pos(loops):
    """bytes(s, 'utf-8') -- two positional, hits the encoding converter."""
    s = "hello world"
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytes(s, "utf-8")
        bytes(s, "utf-8")
        bytes(s, "utf-8")
        bytes(s, "utf-8")
        bytes(s, "utf-8")
        bytes(s, "utf-8")
        bytes(s, "utf-8")
        bytes(s, "utf-8")
        bytes(s, "utf-8")
        bytes(s, "utf-8")
    return pyperf.perf_counter() - t0


def bench_bytes_enc_err_pos(loops):
    """bytes(s, 'utf-8', 'strict') -- all three positional."""
    s = "hello world"
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytes(s, "utf-8", "strict")
        bytes(s, "utf-8", "strict")
        bytes(s, "utf-8", "strict")
        bytes(s, "utf-8", "strict")
        bytes(s, "utf-8", "strict")
        bytes(s, "utf-8", "strict")
        bytes(s, "utf-8", "strict")
        bytes(s, "utf-8", "strict")
        bytes(s, "utf-8", "strict")
        bytes(s, "utf-8", "strict")
    return pyperf.perf_counter() - t0


def bench_bytes_enc_kw(loops):
    """bytes(s, encoding='utf-8') -- one keyword.

    Before the change this built an args tuple and a kwargs dict on the
    way into tp_new.
    """
    s = "hello world"
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytes(s, encoding="utf-8")
        bytes(s, encoding="utf-8")
        bytes(s, encoding="utf-8")
        bytes(s, encoding="utf-8")
        bytes(s, encoding="utf-8")
        bytes(s, encoding="utf-8")
        bytes(s, encoding="utf-8")
        bytes(s, encoding="utf-8")
        bytes(s, encoding="utf-8")
        bytes(s, encoding="utf-8")
    return pyperf.perf_counter() - t0


def bench_bytes_all_kw(loops):
    """bytes(source=s, encoding='utf-8', errors='strict') -- all keyword."""
    s = "hello world"
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytes(source=s, encoding="utf-8", errors="strict")
        bytes(source=s, encoding="utf-8", errors="strict")
        bytes(source=s, encoding="utf-8", errors="strict")
        bytes(source=s, encoding="utf-8", errors="strict")
        bytes(source=s, encoding="utf-8", errors="strict")
        bytes(source=s, encoding="utf-8", errors="strict")
        bytes(source=s, encoding="utf-8", errors="strict")
        bytes(source=s, encoding="utf-8", errors="strict")
        bytes(source=s, encoding="utf-8", errors="strict")
        bytes(source=s, encoding="utf-8", errors="strict")
    return pyperf.perf_counter() - t0


def bench_bytes_subclass(loops):
    """Subclass construction -- tp_vectorcall is not inherited, so this
    still goes through type_call() and tp_new."""

    class MyBytes(bytes):
        pass

    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        MyBytes(b"ab")
        MyBytes(b"ab")
        MyBytes(b"ab")
        MyBytes(b"ab")
        MyBytes(b"ab")
        MyBytes(b"ab")
        MyBytes(b"ab")
        MyBytes(b"ab")
        MyBytes(b"ab")
        MyBytes(b"ab")
    return pyperf.perf_counter() - t0


def bench_bytes_new_explicit(loops):
    """bytes.__new__(bytes, b'ab') -- the explicit tp_new path."""
    new = bytes.__new__
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        new(bytes, b"ab")
        new(bytes, b"ab")
        new(bytes, b"ab")
        new(bytes, b"ab")
        new(bytes, b"ab")
        new(bytes, b"ab")
        new(bytes, b"ab")
        new(bytes, b"ab")
        new(bytes, b"ab")
        new(bytes, b"ab")
    return pyperf.perf_counter() - t0


# --- bytearray() ----------------------------------------------------------

def bench_bytearray_no_args(loops):
    """bytearray() -- nargs == 0, tp_new plus an __init__ that only
    resizes to 0."""
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytearray()
        bytearray()
        bytearray()
        bytearray()
        bytearray()
        bytearray()
        bytearray()
        bytearray()
        bytearray()
        bytearray()
    return pyperf.perf_counter() - t0


def bench_bytearray_from_count(loops):
    """bytearray(8) -- resize plus memset."""
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytearray(8)
        bytearray(8)
        bytearray(8)
        bytearray(8)
        bytearray(8)
        bytearray(8)
        bytearray(8)
        bytearray(8)
        bytearray(8)
        bytearray(8)
    return pyperf.perf_counter() - t0


def bench_bytearray_from_bytes(loops):
    """bytearray(b) where b is a named local -- the buffer copy path.

    b is not a unique temporary (LOAD_FAST_BORROW), so this always
    copies, whatever the zero-copy paths do.
    """
    b = b"hello world"
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytearray(b)
        bytearray(b)
        bytearray(b)
        bytearray(b)
        bytearray(b)
        bytearray(b)
        bytearray(b)
        bytearray(b)
        bytearray(b)
        bytearray(b)
    return pyperf.perf_counter() - t0


def bench_bytearray_from_list(loops):
    """bytearray([...]) -- the list-of-ints fast path."""
    values = [1, 2, 3, 4, 5, 6, 7, 8]
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytearray(values)
        bytearray(values)
        bytearray(values)
        bytearray(values)
        bytearray(values)
        bytearray(values)
        bytearray(values)
        bytearray(values)
        bytearray(values)
        bytearray(values)
    return pyperf.perf_counter() - t0


def bench_bytearray_enc_pos(loops):
    """bytearray(s, 'utf-8') -- two positional.

    The encoded result is a fresh unique bytes, which __init__ already
    adopts without copying.
    """
    s = "hello world"
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytearray(s, "utf-8")
        bytearray(s, "utf-8")
        bytearray(s, "utf-8")
        bytearray(s, "utf-8")
        bytearray(s, "utf-8")
        bytearray(s, "utf-8")
        bytearray(s, "utf-8")
        bytearray(s, "utf-8")
        bytearray(s, "utf-8")
        bytearray(s, "utf-8")
    return pyperf.perf_counter() - t0


def bench_bytearray_enc_err_pos(loops):
    """bytearray(s, 'utf-8', 'strict') -- all three positional."""
    s = "hello world"
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytearray(s, "utf-8", "strict")
        bytearray(s, "utf-8", "strict")
        bytearray(s, "utf-8", "strict")
        bytearray(s, "utf-8", "strict")
        bytearray(s, "utf-8", "strict")
        bytearray(s, "utf-8", "strict")
        bytearray(s, "utf-8", "strict")
        bytearray(s, "utf-8", "strict")
        bytearray(s, "utf-8", "strict")
        bytearray(s, "utf-8", "strict")
    return pyperf.perf_counter() - t0


def bench_bytearray_enc_kw(loops):
    """bytearray(s, encoding='utf-8') -- one keyword."""
    s = "hello world"
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytearray(s, encoding="utf-8")
        bytearray(s, encoding="utf-8")
        bytearray(s, encoding="utf-8")
        bytearray(s, encoding="utf-8")
        bytearray(s, encoding="utf-8")
        bytearray(s, encoding="utf-8")
        bytearray(s, encoding="utf-8")
        bytearray(s, encoding="utf-8")
        bytearray(s, encoding="utf-8")
        bytearray(s, encoding="utf-8")
    return pyperf.perf_counter() - t0


def bench_bytearray_all_kw(loops):
    """bytearray(source=s, encoding='utf-8', errors='strict')."""
    s = "hello world"
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytearray(source=s, encoding="utf-8", errors="strict")
        bytearray(source=s, encoding="utf-8", errors="strict")
        bytearray(source=s, encoding="utf-8", errors="strict")
        bytearray(source=s, encoding="utf-8", errors="strict")
        bytearray(source=s, encoding="utf-8", errors="strict")
        bytearray(source=s, encoding="utf-8", errors="strict")
        bytearray(source=s, encoding="utf-8", errors="strict")
        bytearray(source=s, encoding="utf-8", errors="strict")
        bytearray(source=s, encoding="utf-8", errors="strict")
        bytearray(source=s, encoding="utf-8", errors="strict")
    return pyperf.perf_counter() - t0


def bench_bytearray_subclass(loops):
    """Subclass construction -- still type_call() plus tp_new/tp_init."""

    class MyByteArray(bytearray):
        pass

    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        MyByteArray(b"ab")
        MyByteArray(b"ab")
        MyByteArray(b"ab")
        MyByteArray(b"ab")
        MyByteArray(b"ab")
        MyByteArray(b"ab")
        MyByteArray(b"ab")
        MyByteArray(b"ab")
        MyByteArray(b"ab")
        MyByteArray(b"ab")
    return pyperf.perf_counter() - t0


def bench_bytearray_init_explicit(loops):
    """ba.__init__(b'ab') -- the explicit tp_init path."""
    init = bytearray.__init__
    ba = bytearray()
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        init(ba, b"ab")
        init(ba, b"ab")
        init(ba, b"ab")
        init(ba, b"ab")
        init(ba, b"ab")
        init(ba, b"ab")
        init(ba, b"ab")
        init(ba, b"ab")
        init(ba, b"ab")
        init(ba, b"ab")
    return pyperf.perf_counter() - t0


# --- unique temporaries ---------------------------------------------------
#
# bytes(n) allocates a fresh zeroed bytes object of length n and leaves it
# on the operand stack as a unique temporary, which is the shape a
# zero-copy constructor can take over.  Each "control" benchmark builds
# the same source object and throws it away, so control vs. constructor is
# the constructor's own cost.

def bench_control_bytes(loops, size):
    """bytes(size) alone -- the control for bytearray(bytes(size))."""
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytes(size)
        bytes(size)
        bytes(size)
        bytes(size)
        bytes(size)
        bytes(size)
        bytes(size)
        bytes(size)
        bytes(size)
        bytes(size)
    return pyperf.perf_counter() - t0


def bench_bytearray_unique_bytes(loops, size):
    """bytearray(bytes(size)) -- source is a unique temporary bytes."""
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytearray(bytes(size))
        bytearray(bytes(size))
        bytearray(bytes(size))
        bytearray(bytes(size))
        bytearray(bytes(size))
        bytearray(bytes(size))
        bytearray(bytes(size))
        bytearray(bytes(size))
        bytearray(bytes(size))
        bytearray(bytes(size))
    return pyperf.perf_counter() - t0


def bench_bytearray_named_bytes(loops, size):
    """bytearray(b) with b preallocated -- always copies, for comparison."""
    b = bytes(size)
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytearray(b)
        bytearray(b)
        bytearray(b)
        bytearray(b)
        bytearray(b)
        bytearray(b)
        bytearray(b)
        bytearray(b)
        bytearray(b)
        bytearray(b)
    return pyperf.perf_counter() - t0


def bench_control_bytearray(loops, size):
    """bytearray(size) alone -- the control for bytes(bytearray(size))."""
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytearray(size)
        bytearray(size)
        bytearray(size)
        bytearray(size)
        bytearray(size)
        bytearray(size)
        bytearray(size)
        bytearray(size)
        bytearray(size)
        bytearray(size)
    return pyperf.perf_counter() - t0


def bench_bytes_unique_bytearray(loops, size):
    """bytes(bytearray(size)) -- source is a unique temporary bytearray."""
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytes(bytearray(size))
        bytes(bytearray(size))
        bytes(bytearray(size))
        bytes(bytearray(size))
        bytes(bytearray(size))
        bytes(bytearray(size))
        bytes(bytearray(size))
        bytes(bytearray(size))
        bytes(bytearray(size))
        bytes(bytearray(size))
    return pyperf.perf_counter() - t0


def bench_bytes_named_bytearray(loops, size):
    """bytes(ba) with ba preallocated -- always copies, for comparison."""
    ba = bytearray(size)
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytes(ba)
        bytes(ba)
        bytes(ba)
        bytes(ba)
        bytes(ba)
        bytes(ba)
        bytes(ba)
        bytes(ba)
        bytes(ba)
        bytes(ba)
    return pyperf.perf_counter() - t0


if __name__ == "__main__":
    runner = pyperf.Runner()

    runner.bench_time_func("bytes()", bench_bytes_no_args)
    runner.bench_time_func("bytes(int)", bench_bytes_from_count)
    runner.bench_time_func("bytes(bytes)", bench_bytes_from_bytes)
    runner.bench_time_func("bytes(list)", bench_bytes_from_list)
    runner.bench_time_func("bytes(bytearray)", bench_bytes_from_bytearray)
    runner.bench_time_func("bytes(str,enc)", bench_bytes_enc_pos)
    runner.bench_time_func("bytes(str,enc,err)", bench_bytes_enc_err_pos)
    runner.bench_time_func("bytes(str,enc=)", bench_bytes_enc_kw)
    runner.bench_time_func("bytes(src=,enc=,err=)", bench_bytes_all_kw)
    runner.bench_time_func("bytes_subclass", bench_bytes_subclass)
    runner.bench_time_func("bytes.__new__", bench_bytes_new_explicit)

    runner.bench_time_func("bytearray()", bench_bytearray_no_args)
    runner.bench_time_func("bytearray(int)", bench_bytearray_from_count)
    runner.bench_time_func("bytearray(bytes)", bench_bytearray_from_bytes)
    runner.bench_time_func("bytearray(list)", bench_bytearray_from_list)
    runner.bench_time_func("bytearray(str,enc)", bench_bytearray_enc_pos)
    runner.bench_time_func("bytearray(str,enc,err)", bench_bytearray_enc_err_pos)
    runner.bench_time_func("bytearray(str,enc=)", bench_bytearray_enc_kw)
    runner.bench_time_func("bytearray(src=,enc=,err=)", bench_bytearray_all_kw)
    runner.bench_time_func("bytearray_subclass", bench_bytearray_subclass)
    runner.bench_time_func("bytearray.__init__", bench_bytearray_init_explicit)

    for size in (16, SIZE):
        runner.bench_time_func(f"control bytes({size})",
                               bench_control_bytes, size)
        runner.bench_time_func(f"bytearray(unique bytes({size}))",
                               bench_bytearray_unique_bytes, size)
        runner.bench_time_func(f"bytearray(named bytes({size}))",
                               bench_bytearray_named_bytes, size)
        runner.bench_time_func(f"control bytearray({size})",
                               bench_control_bytearray, size)
        runner.bench_time_func(f"bytes(unique bytearray({size}))",
                               bench_bytes_unique_bytearray, size)
        runner.bench_time_func(f"bytes(named bytearray({size}))",
                               bench_bytes_named_bytearray, size)

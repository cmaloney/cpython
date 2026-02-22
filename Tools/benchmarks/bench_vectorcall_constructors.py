"""Benchmark vectorcall constructors for builtin types.

Validates that clinic-generated vectorcall functions perform
equivalently to the previous hand-written implementations.
"""

import pyperf


def bench_list_no_args(loops):
    """Benchmark list() with no arguments."""
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        list()
        list()
        list()
        list()
        list()
        list()
        list()
        list()
        list()
        list()
    return pyperf.perf_counter() - t0


def bench_list_from_tuple(loops):
    """Benchmark list(small_tuple)."""
    src = (1, 2, 3, 4, 5)
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        list(src)
        list(src)
        list(src)
        list(src)
        list(src)
        list(src)
        list(src)
        list(src)
        list(src)
        list(src)
    return pyperf.perf_counter() - t0


def bench_list_from_range(loops):
    """Benchmark list(range(100))."""
    src = range(100)
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        list(src)
        list(src)
        list(src)
        list(src)
        list(src)
    return pyperf.perf_counter() - t0


def bench_list_subclass(loops):
    """Benchmark subclass construction to verify no regression."""
    class MyList(list):
        pass

    src = (1, 2, 3)
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        MyList()
        MyList(src)
        MyList()
        MyList(src)
        MyList()
        MyList(src)
        MyList()
        MyList(src)
        MyList()
        MyList(src)
    return pyperf.perf_counter() - t0


def bench_bytearray_no_args(loops):
    """Benchmark bytearray() with no arguments."""
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


def bench_bytearray_from_bytes(loops):
    """Benchmark bytearray(b'hello world')."""
    src = b"hello world"
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytearray(src)
        bytearray(src)
        bytearray(src)
        bytearray(src)
        bytearray(src)
        bytearray(src)
        bytearray(src)
        bytearray(src)
        bytearray(src)
        bytearray(src)
    return pyperf.perf_counter() - t0


def bench_bytearray_from_int(loops):
    """Benchmark bytearray(100)."""
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytearray(100)
        bytearray(100)
        bytearray(100)
        bytearray(100)
        bytearray(100)
    return pyperf.perf_counter() - t0


def bench_float_no_args(loops):
    """Benchmark float() with no arguments."""
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        float()
        float()
        float()
        float()
        float()
        float()
        float()
        float()
        float()
        float()
    return pyperf.perf_counter() - t0


def bench_float_from_int(loops):
    """Benchmark float(42)."""
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        float(42)
        float(42)
        float(42)
        float(42)
        float(42)
        float(42)
        float(42)
        float(42)
        float(42)
        float(42)
    return pyperf.perf_counter() - t0


def bench_float_from_str(loops):
    """Benchmark float('3.14')."""
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        float("3.14")
        float("3.14")
        float("3.14")
        float("3.14")
        float("3.14")
        float("3.14")
        float("3.14")
        float("3.14")
        float("3.14")
        float("3.14")
    return pyperf.perf_counter() - t0


def bench_bytes_no_args(loops):
    """Benchmark bytes() with no arguments."""
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


def bench_bytes_from_int(loops):
    """Benchmark bytes(10)."""
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        bytes(10)
        bytes(10)
        bytes(10)
        bytes(10)
        bytes(10)
        bytes(10)
        bytes(10)
        bytes(10)
        bytes(10)
        bytes(10)
    return pyperf.perf_counter() - t0


def bench_str_no_args(loops):
    """Benchmark str() with no arguments."""
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        str()
        str()
        str()
        str()
        str()
        str()
        str()
        str()
        str()
        str()
    return pyperf.perf_counter() - t0


def bench_str_from_int(loops):
    """Benchmark str(42)."""
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        str(42)
        str(42)
        str(42)
        str(42)
        str(42)
        str(42)
        str(42)
        str(42)
        str(42)
        str(42)
    return pyperf.perf_counter() - t0


def bench_str_from_bytes(loops):
    """Benchmark str(b'hello', 'utf-8')."""
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        str(b"hello", "utf-8")
        str(b"hello", "utf-8")
        str(b"hello", "utf-8")
        str(b"hello", "utf-8")
        str(b"hello", "utf-8")
        str(b"hello", "utf-8")
        str(b"hello", "utf-8")
        str(b"hello", "utf-8")
        str(b"hello", "utf-8")
        str(b"hello", "utf-8")
    return pyperf.perf_counter() - t0


def bench_tuple_no_args(loops):
    """Benchmark tuple() with no arguments."""
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        tuple()
        tuple()
        tuple()
        tuple()
        tuple()
        tuple()
        tuple()
        tuple()
        tuple()
        tuple()
    return pyperf.perf_counter() - t0


def bench_tuple_from_list(loops):
    """Benchmark tuple([1, 2, 3, 4, 5])."""
    src = [1, 2, 3, 4, 5]
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        tuple(src)
        tuple(src)
        tuple(src)
        tuple(src)
        tuple(src)
        tuple(src)
        tuple(src)
        tuple(src)
        tuple(src)
        tuple(src)
    return pyperf.perf_counter() - t0


def bench_int_no_args(loops):
    """Benchmark int() with no arguments."""
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        int()
        int()
        int()
        int()
        int()
        int()
        int()
        int()
        int()
        int()
    return pyperf.perf_counter() - t0


def bench_int_from_str(loops):
    """Benchmark int('42')."""
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        int("42")
        int("42")
        int("42")
        int("42")
        int("42")
        int("42")
        int("42")
        int("42")
        int("42")
        int("42")
    return pyperf.perf_counter() - t0


def bench_int_from_str_base(loops):
    """Benchmark int('ff', 16)."""
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        int("ff", 16)
        int("ff", 16)
        int("ff", 16)
        int("ff", 16)
        int("ff", 16)
        int("ff", 16)
        int("ff", 16)
        int("ff", 16)
        int("ff", 16)
        int("ff", 16)
    return pyperf.perf_counter() - t0


def bench_reversed_list(loops):
    """Benchmark reversed([1, 2, 3])."""
    src = [1, 2, 3]
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        reversed(src)
        reversed(src)
        reversed(src)
        reversed(src)
        reversed(src)
        reversed(src)
        reversed(src)
        reversed(src)
        reversed(src)
        reversed(src)
    return pyperf.perf_counter() - t0


def bench_enumerate_list(loops):
    """Benchmark enumerate([1, 2, 3])."""
    src = [1, 2, 3]
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        enumerate(src)
        enumerate(src)
        enumerate(src)
        enumerate(src)
        enumerate(src)
        enumerate(src)
        enumerate(src)
        enumerate(src)
        enumerate(src)
        enumerate(src)
    return pyperf.perf_counter() - t0


def bench_enumerate_start(loops):
    """Benchmark enumerate([1, 2, 3], 1)."""
    src = [1, 2, 3]
    range_it = range(loops)
    t0 = pyperf.perf_counter()
    for _ in range_it:
        enumerate(src, 1)
        enumerate(src, 1)
        enumerate(src, 1)
        enumerate(src, 1)
        enumerate(src, 1)
        enumerate(src, 1)
        enumerate(src, 1)
        enumerate(src, 1)
        enumerate(src, 1)
        enumerate(src, 1)
    return pyperf.perf_counter() - t0


if __name__ == "__main__":
    runner = pyperf.Runner()
    runner.bench_time_func("list()", bench_list_no_args)
    runner.bench_time_func("list(tuple)", bench_list_from_tuple)
    runner.bench_time_func("list(range)", bench_list_from_range)
    runner.bench_time_func("list_subclass", bench_list_subclass)
    runner.bench_time_func("float()", bench_float_no_args)
    runner.bench_time_func("float(int)", bench_float_from_int)
    runner.bench_time_func("float(str)", bench_float_from_str)
    runner.bench_time_func("str()", bench_str_no_args)
    runner.bench_time_func("str(int)", bench_str_from_int)
    runner.bench_time_func("str(bytes,enc)", bench_str_from_bytes)
    runner.bench_time_func("bytes()", bench_bytes_no_args)
    runner.bench_time_func("bytes(int)", bench_bytes_from_int)
    runner.bench_time_func("bytearray()", bench_bytearray_no_args)
    runner.bench_time_func("bytearray(bytes)", bench_bytearray_from_bytes)
    runner.bench_time_func("bytearray(int)", bench_bytearray_from_int)
    runner.bench_time_func("tuple()", bench_tuple_no_args)
    runner.bench_time_func("tuple(list)", bench_tuple_from_list)
    runner.bench_time_func("int()", bench_int_no_args)
    runner.bench_time_func("int(str)", bench_int_from_str)
    runner.bench_time_func("int(str,base)", bench_int_from_str_base)
    runner.bench_time_func("reversed(list)", bench_reversed_list)
    runner.bench_time_func("enumerate(list)", bench_enumerate_list)
    runner.bench_time_func("enumerate(list,start)", bench_enumerate_start)

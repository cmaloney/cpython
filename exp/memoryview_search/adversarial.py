"""Adversarial tests for the raw item search in array and memoryview.

Oracle: I(v) for an int subclass I without __eq__ compares exactly like v
but always takes the generic (object comparison) path, so any difference
between seq.op(v) and seq.op(I(v)) is a fast path bug.
"""
import array
import enum
import random
import struct
import sys
import _testbuffer
from _testbuffer import ndarray, ND_PIL, ND_WRITABLE, ND_FORTRAN

failures = []
checks = 0


class I(int):
    # Overriding __eq__ (even with int's) forces the generic path.
    def __eq__(self, other):
        return int.__eq__(self, other)
    __hash__ = int.__hash__


def oracle(v):
    # Wrap ints so they take the generic path; leave other values alone.
    return I(v) if isinstance(v, int) and type(v).__eq__ is int.__eq__ else v


def outcome(f, *args):
    try:
        return ('ok', f(*args))
    except Exception as e:
        return ('exc', type(e).__name__, str(e))


def check(desc, seq, value, starts=((0, sys.maxsize),)):
    global checks
    ov = oracle(value)
    for name in ('count',):
        checks += 1
        a, b = outcome(seq.count, value), outcome(seq.count, ov)
        if a != b:
            failures.append(f"{desc}: count({value!r}) = {a}, generic {b}")
    for start, stop in starts:
        checks += 1
        a = outcome(seq.index, value, start, stop)
        b = outcome(seq.index, ov, start, stop)
        if a != b:
            failures.append(f"{desc}: index({value!r}, {start}, {stop}) = {a},"
                            f" generic {b}")
    if isinstance(seq, array.array):
        checks += 2
        a, b = outcome(seq.__contains__, value), outcome(seq.__contains__, ov)
        if a != b:
            failures.append(f"{desc}: {value!r} in a = {a}, generic {b}")
        x, y = array.array(seq.typecode, seq), array.array(seq.typecode, seq)
        a, b = outcome(x.remove, value), outcome(y.remove, ov)
        if a != b or x.tobytes() != y.tobytes():
            failures.append(f"{desc}: remove({value!r}) differs: {a} vs {b}")


INT_FORMATS = 'bBhHiIlLqQnN'


def bounds(fmt):
    size = struct.calcsize(fmt)
    if fmt.islower():
        return -2**(size * 8 - 1), 2**(size * 8 - 1) - 1
    return 0, 2**(size * 8) - 1


def interesting_values(fmt):
    lo, hi = bounds(fmt) if fmt in INT_FORMATS else (0, 255)
    vals = {0, 1, -1, 255, 256, -128, -129, 127, 128, 0x100, 0x10000,
            2**30 - 1, 2**30, -2**30, -2**30 - 1,  # compact int boundary
            2**31 - 1, 2**31, -2**31, -2**31 - 1,
            2**32 - 1, 2**32, 2**63 - 1, 2**63, -2**63, -2**63 - 1,
            2**64 - 1, 2**64, 2**100, -2**100,
            lo, hi, lo - 1, hi + 1, lo + 1, hi - 1}
    return sorted(vals)


def starts_for(n):
    return [(0, sys.maxsize), (0, n), (1, n - 1), (-1, n), (n, n),
            (n + 5, n + 10), (-n - 5, 2), (3, 1), (0, 0), (-3, -1),
            (0, -sys.maxsize), (-sys.maxsize, sys.maxsize)]


def data_with(fmt, n, values):
    """Items for fmt: values that fit, padded with random in-range ints."""
    lo, hi = bounds(fmt)
    items = [v for v in values if lo <= v <= hi]
    items += [random.randint(lo, hi) for _ in range(n)]
    random.shuffle(items)
    return items


# ---------------------------------------------------------------------------
# 1. Boundary values for every integer format, array and memoryview,
#    contiguous, strided, reversed, sliced and unaligned views.
# ---------------------------------------------------------------------------
def test_boundaries():
    for fmt in INT_FORMATS:
        values = interesting_values(fmt)
        items = data_with(fmt, 100, values)
        raw = struct.pack(f'{len(items)}{fmt}', *items)
        size = struct.calcsize(fmt)
        mv = memoryview(raw).cast(fmt)
        unaligned = memoryview(b'\0' + raw)[1:].cast(fmt) if size > 1 else mv
        views = {'mv': mv, 'mv[::2]': mv[::2], 'mv[::-1]': mv[::-1],
                 'mv[3:-3]': mv[3:-3], 'mv[5:6]': mv[5:6], 'mv[0:0]': mv[0:0],
                 'unaligned': unaligned}
        if fmt in array.typecodes:
            views['array'] = array.array(fmt, items)
            views['array[0:0]'] = array.array(fmt)
        for vname, view in views.items():
            n = len(view)
            for value in values:
                check(f"{fmt} {vname}", view, value, starts_for(n))
                check(f"{fmt} {vname} Plain", view, Plain(value),
                      starts_for(n))
                if value in (0, 1):
                    check(f"{fmt} {vname} bool", view, bool(value),
                          starts_for(n))


# ---------------------------------------------------------------------------
# 2. Odd value types: bool, IntEnum, int subclass overriding __eq__,
#    __index__ objects, floats equal to ints, big floats, complex.
# ---------------------------------------------------------------------------
class Color(enum.IntEnum):
    RED = 1
    BIG = 300


class EqAll(int):
    def __eq__(self, other):
        return True
    __hash__ = int.__hash__


class Index:
    def __init__(self, v):
        self.v = v

    def __index__(self):
        return self.v

    def __eq__(self, other):
        return other == self.v


class Plain(int):
    pass


class LtOnly(int):
    def __lt__(self, other):
        return True


class Flag(enum.IntFlag):
    A = 1
    B = 256


def test_value_types():
    vals = [True, False, Color.RED, Color.BIG, EqAll(7), Index(1), 1.0,
            300.0, float('nan'), 1 + 0j, b'\x01', '1', None, Plain(1),
            Plain(300), LtOnly(1), Flag.A, Flag.B, Flag.A | Flag.B]
    for fmt in INT_FORMATS:
        items = data_with(fmt, 50, [0, 1, 300])
        raw = struct.pack(f'{len(items)}{fmt}', *items)
        seqs = [memoryview(raw).cast(fmt)]
        if fmt in array.typecodes:
            seqs.append(array.array(fmt, items))
        for seq in seqs:
            for v in vals:
                # The generic path is the oracle for non-int values too:
                # compare against a list.
                lst = seq.tolist()
                global checks
                checks += 2
                a = outcome(seq.count, v)
                b = ('ok', sum(1 for x in lst if x == v))
                if a != b:
                    failures.append(f"{fmt} {type(seq).__name__}: count({v!r})"
                                    f" = {a}, list {b}")
                a = outcome(seq.index, v)
                try:
                    b = ('ok', next(i for i, x in enumerate(lst) if x == v))
                except StopIteration:
                    b = a if a[0] == 'exc' and a[1] == 'ValueError' else 'VE'
                if a != b:
                    failures.append(f"{fmt} {type(seq).__name__}: index({v!r})"
                                    f" = {a}, list {b}")


# ---------------------------------------------------------------------------
# 3. Unusual exporters via _testbuffer.ndarray: non-native byte orders,
#    standard sizes, repeat counts, PIL-style suboffsets, odd strides,
#    shape-1 views with bogus strides, Fortran order, offsets.
# ---------------------------------------------------------------------------
def test_exporters():
    n = 64
    for fmt in INT_FORMATS:
        lo, hi = bounds(fmt)
        items = data_with(fmt, n, [0, 1, 255, 256, lo, hi])[:n]
        values = [0, 1, 255, 256, lo, hi, items[n // 2], items[-1]]
        for prefix in ('', '@', '<', '>', '=', '!'):
            f = prefix + fmt
            try:
                nd = ndarray(items, shape=[n], format=f)
            except Exception:
                continue
            try:
                mv = memoryview(nd)
            except Exception:
                continue
            for v in values:
                check(f"ndarray format={f!r}", mv, v, starts_for(n))
        size = struct.calcsize(fmt)
        cases = {
            'PIL': dict(shape=[n], format=fmt, flags=ND_PIL),
            'stride*2': dict(shape=[n // 2], strides=[2 * size], format=fmt),
            'neg stride': dict(shape=[n], strides=[-size],
                               offset=(n - 1) * size, format=fmt),
            'shape1 bogus stride': dict(shape=[1], strides=[7 * size],
                                        offset=5 * size, format=fmt),
            'offset': dict(shape=[n - 3], offset=3 * size, format=fmt),
            'fortran': dict(shape=[n], format=fmt, flags=ND_FORTRAN),
            '2d': dict(shape=[8, n // 8], format=fmt),
        }
        for cname, kw in cases.items():
            try:
                nd = ndarray(items, **kw)
                mv = memoryview(nd)
            except Exception as e:
                continue
            for v in values:
                if mv.ndim != 1:
                    global checks
                    checks += 1
                    a = outcome(mv.count, v)
                    if a[0] == 'ok':
                        failures.append(f"{fmt} {cname}: count on ndim "
                                        f"{mv.ndim} unexpectedly {a}")
                    continue
                check(f"ndarray {cname} {fmt}", mv, v, starts_for(len(mv)))
    # Repeat counts and multi-item formats are never native single items.
    for f in ('2B', '1i', 'xB', 'Bx', 'i2', '?', 'c', 'P', 'e', 'f', 'd'):
        try:
            items = [1, 2, 3, 4] if f not in ('c',) else [b'a', b'b']
            if f in ('e', 'f', 'd'):
                items = [0.0, -0.0, 1.0, 2.0]
            nd = ndarray(items, shape=[len(items)], format=f)
            mv = memoryview(nd)
        except Exception:
            continue
        for v in (0, 1, 2, 3):
            check(f"ndarray format={f!r}", mv, v)


# ---------------------------------------------------------------------------
# 4. Random differential fuzzing.
# ---------------------------------------------------------------------------
def test_fuzz(iterations=3000):
    rng = random.Random(1234)
    for _ in range(iterations):
        fmt = rng.choice(INT_FORMATS)
        size = struct.calcsize(fmt)
        lo, hi = bounds(fmt)
        n = rng.choice([0, 1, 2, 3, 15, 16, 17, 39, 40, 41, 100, 300])
        # Values clustered around few byte patterns to provoke false hits.
        pool = [rng.randint(lo, hi) for _ in range(3)] + [0, lo, hi]
        pool += [p ^ (1 << rng.randrange(size * 8)) for p in pool]
        pool = [min(max(p, lo), hi) for p in pool]
        items = [rng.choice(pool) for _ in range(n)]
        raw = struct.pack(f'{n}{fmt}', *items)
        mv = memoryview(raw).cast(fmt)
        step = rng.choice([1, 1, 1, 2, -1, 3])
        view = mv[::step]
        value = rng.choice(pool + [lo - 1, hi + 1, rng.randint(-2**70, 2**70)])
        starts = [(rng.randint(-n - 2, n + 2), rng.randint(-n - 2, n + 2))
                  for _ in range(3)] + [(0, sys.maxsize)]
        check(f"fuzz {fmt} n={n} step={step}", view, value, starts)
        if fmt in array.typecodes:
            check(f"fuzz array {fmt} n={n}", array.array(fmt, items), value,
                  starts)


# ---------------------------------------------------------------------------
# 5. pack_single refactor: memoryview item assignment must agree with
#    struct.pack (success iff struct accepts, same bytes stored).
# ---------------------------------------------------------------------------
def test_setitem():
    global checks
    for fmt in INT_FORMATS:
        size = struct.calcsize(fmt)
        for v in interesting_values(fmt) + [True, Color.RED, Index(5),
                                            Index(2**70), 1.0, 'x']:
            buf = bytearray(b'\xaa' * size * 2)
            mv = memoryview(buf).cast(fmt)
            checks += 1
            a = outcome(mv.__setitem__, 0, v)
            try:
                expected = struct.pack(fmt, v)
            except (struct.error, TypeError, OverflowError):
                expected = None
            if a[0] == 'ok':
                if expected is None or bytes(buf[:size]) != expected:
                    failures.append(f"setitem {fmt} {v!r}: stored "
                                    f"{bytes(buf[:size])!r}, struct "
                                    f"{expected!r}")
            else:
                if expected is not None:
                    failures.append(f"setitem {fmt} {v!r}: raised {a}, "
                                    f"struct packs {expected!r}")
                if bytes(buf) != b'\xaa' * size * 2:
                    failures.append(f"setitem {fmt} {v!r}: failed but "
                                    f"modified the buffer {bytes(buf)!r}")
            # Neighbour must never change.
            if bytes(buf[size:]) != b'\xaa' * size:
                failures.append(f"setitem {fmt} {v!r}: clobbered neighbour")


# ---------------------------------------------------------------------------
# 6. Reentrancy: __eq__ that mutates or releases while the generic path
#    runs must keep working (fast path must not be confused afterwards).
# ---------------------------------------------------------------------------
def test_reentrancy():
    global checks
    a = array.array('i', range(100))

    class Mut:
        def __eq__(self, other):
            del a[50:]
            return False
    checks += 1
    r = outcome(a.index, Mut())
    if r[0] != 'exc':
        failures.append(f"mutating __eq__: {r}")
    checks += 1
    if a.index(49) != 49 or 50 in a or a.count(49) != 1:
        failures.append("array after mutation gives wrong results")

    b = bytearray(range(10))
    m = memoryview(b)

    class Rel:
        def __eq__(self, other):
            m.release()
            return False
    checks += 1
    r = outcome(m.index, Rel())
    checks += 1
    r = outcome(m.count, 3)
    if r[0] != 'exc' or r[1] != 'ValueError':
        failures.append(f"count on released view: {r}")
    r = outcome(m.index, 3)
    if r[0] != 'exc' or r[1] != 'ValueError':
        failures.append(f"index on released view: {r}")


def test_late_eq_override():
    # Adding __eq__ to a class after its instances took the fast path must
    # switch them to the generic path.
    global checks
    class Late(int):
        pass
    v = Late(5)
    a = array.array('i', [1, 2, 3, 5])
    m = memoryview(a)
    checks += 4
    if a.index(v) != 3 or m.count(v) != 1:
        failures.append("Late before override")
    Late.__eq__ = lambda self, other: True
    if a.index(v) != 0 or m.count(v) != 4 or a.count(v) != 4:
        failures.append(f"Late after override: index {a.index(v)}, "
                        f"count {m.count(v)}")
    del Late.__eq__
    if a.index(v) != 3 or a.count(v) != 1:
        failures.append("Late after removing override")


for test in (test_late_eq_override, test_boundaries, test_value_types, test_exporters, test_fuzz,
             test_setitem, test_reentrancy):
    before = len(failures)
    test()
    print(f"{test.__name__}: {len(failures) - before} failures")
print(f"{checks} checks, {len(failures)} failures")
for f in failures[:40]:
    print("  ", f)

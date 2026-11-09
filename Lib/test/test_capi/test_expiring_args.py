"""Tests for bytes(tmp) and bytearray(tmp) taking a temporary's buffer.

Required tests the optimization still fires: if a change to the interpreter alters
what a CALL looks like on the stack, it fails rather than the speedup quietly going
away.  Update _PyEval_CallArgIsExpiring() in Python/ceval.c to match.

Operations under test must be C callables: a Python function adds a local reference
and hides the bug.
"""

import bisect
import functools
import itertools
import operator
import queue
import sys
import threading
import tracemalloc
import types
import unittest

from test.support import import_helper
from test.support.script_helper import assert_python_ok

_testcapi = import_helper.import_module("_testcapi")
_testinternalcapi = import_helper.import_module("_testinternalcapi")
probe = _testinternalcapi.ExpiringProbe

FREE_THREADED = not getattr(sys, "_is_gil_enabled", lambda: True)()
JIT = hasattr(sys, "_jit") and sys._jit.is_enabled()
# Past specialization, or past trace formation when the JIT tier is running.
LOOPS = _testinternalcapi.TIER2_THRESHOLD * 3 if JIT else 300
ORIGINAL = b"aaB-original-contents"
CONVERSIONS = ((bytes, bytearray), (bytearray, bytes), (bytearray, bytearray))


def tmp():
    return bytearray(b"abc")


def fresh_bytes():
    return bytes(bytearray(ORIGINAL))


def fresh_bytearray():
    return bytearray(ORIGINAL)


def in_new_thread(func):
    results = []
    t = threading.Thread(target=lambda: results.append(func()))
    t.start()
    t.join()
    return results[0]


class Required(unittest.TestCase):
    SIZE = 8 * 1024 * 1024

    def peak(self, func, warm=True):
        """Peak allocation as a multiple of SIZE: near 1 adopts, near 2 copies."""
        for _ in range(LOOPS if warm else 0):
            func(1024)
        tracemalloc.start()
        try:
            base, _ = tracemalloc.get_traced_memory()
            result = func(self.SIZE)
            _, peak = tracemalloc.get_traced_memory()
            del result
        finally:
            tracemalloc.stop()
        return (peak - base) / self.SIZE

    def test_conversions_cold_and_warm(self):
        for op, make in CONVERSIONS:
            for warm in (False, True):
                with self.subTest(op=op, make=make, warm=warm):
                    def f(n):
                        return op(make(n))
                    self.assertLess(self.peak(f, warm), 1.5)

    def test_call_shapes(self):
        def deep_stack(n):
            return (1, 2, [3, bytes(bytearray(n))])[2][1]
        def generator(n):
            def g():
                yield bytes(bytearray(n))
            return next(g())
        for f in (deep_stack, generator):
            with self.subTest(f.__name__):
                self.assertLess(self.peak(f), 1.5)

    def test_new_thread(self):
        def f(n):
            return bytes(bytearray(n))
        self.assertLess(in_new_thread(lambda: self.peak(f)), 1.5)

    def test_local_copies(self):
        def f(n):
            x = bytearray(n)
            return bytes(x), x
        self.assertGreater(self.peak(f), 1.5)

    def test_every_iteration(self):
        # Cold, specialized and traced all count, so no warm-up.
        for i in range(LOOPS):
            self.assertIs(probe(tmp()), True, i)

    def test_earlier_monitoring_does_not_turn_it_off(self):
        # Code run after any monitoring change gets monitoring data even with no
        # events, so the check can't just require that data to be absent.
        sys.setprofile(lambda *a: None)
        tmp()
        sys.setprofile(None)
        def f():
            return probe(tmp())
        for i in range(LOOPS):
            self.assertIs(f(), True, i)


class NotExpiring(unittest.TestCase):
    """The check must say no: someone else holds the argument, or C is in between."""

    def test_holders_and_c_callers(self):
        def local():
            x = tmp()
            return probe(x)
        def list_element():
            held = [tmp()]
            return probe(held[0])
        def bisect_key():
            # Fools PyUnstable_Object_IsUniqueReferencedTemporary().  True would
            # sort after the existing False.
            a = [bytearray(b"z")]
            bisect.insort_left(a, tmp(), key=probe)
            return a[0] != bytearray(b"abc")
        cases = [
            local, list_element, bisect_key,
            lambda: probe(*[tmp()]),
            lambda: next(map(probe, [tmp()])),
            lambda: next(itertools.starmap(probe, [(tmp(),)])),
            lambda: functools.partial(probe)(tmp()),
            lambda: operator.call(probe, tmp()),
            lambda: types.MethodType(probe, tmp())(),
            lambda: probe(bytes(0)),  # Immortal.
            lambda: probe([0]),  # Same callable, an argument C still holds.
        ]
        for i, case in enumerate(cases):
            with self.subTest(i):
                for j in range(LOOPS):
                    self.assertIs(case(), False, j)

    def test_watched(self):
        def f():
            return probe(tmp())
        sys.setprofile(lambda *a: None)
        try:
            self.assertIs(f(), False)
        finally:
            sys.setprofile(None)

    def test_allocated_by_another_thread(self):
        # A false negative on free-threaded builds, which must only ever mean
        # "use the generic path" (gh-156995).
        q = queue.SimpleQueue()
        in_new_thread(lambda: q.put(tmp()))
        self.assertIs(probe(q.get()), not FREE_THREADED)
        in_new_thread(lambda: q.put(tmp()))
        self.assertEqual(bytes(q.get()), b"abc")

    def test_documented_limit(self):
        # The check can't see a callable calling itself from C with the same
        # arguments, which is why callers must ask on entry.
        self.assertIs(probe([]), True)


class Sound(unittest.TestCase):
    """Whoever still holds the argument finds it unchanged."""

    def test_holders(self):
        def insort(op, make):
            a = []
            bisect.insort(a, make(), key=op)
            return a[0], None
        def star_args(op, make):
            args = (make(),)
            return args[0], op(*args)
        def list_element(op, make):
            held = [make()]
            return held[0], op(held[0])
        def local(op, make):
            x = make()
            return x, op(x)
        for run in (insort, star_args, list_element, local):
            for op in (bytes, bytearray):
                for make in (fresh_bytes, fresh_bytearray):
                    with self.subTest(run.__name__, op=op, make=make):
                        for _ in range(LOOPS):
                            subject, res = run(op, make)
                            if isinstance(res, bytearray):
                                res[:1] = b"XX"
                            self.assertEqual(subject, ORIGINAL)

    def test_subclasses_are_not_adopted(self):
        class B(bytearray):
            pass
        for _ in range(LOOPS):
            self.assertEqual(bytes(B(ORIGINAL)), ORIGINAL)
            self.assertIs(type(B(bytearray(ORIGINAL))), B)

    def test_export_and_cached_hash(self):
        for _ in range(LOOPS):
            ba = fresh_bytearray()
            with memoryview(ba) as m:
                self.assertEqual(bytes(m.obj), ORIGINAL)
            self.assertEqual(ba, ORIGINAL)
            def hashed():
                b = fresh_bytes()
                hash(b)
                return b
            self.assertEqual(bytearray(hashed()), ORIGINAL)

    def test_threads(self):
        shared = [fresh_bytearray() for _ in range(4)]
        errors = []
        def worker(n):
            for _ in range(min(LOOPS * 10, 3000)):
                if (bytes(shared[n]) != ORIGINAL
                        or bytes(shared[(n + 1) % 4]) != ORIGINAL
                        or bytearray(bytes(fresh_bytearray())) != ORIGINAL):
                    errors.append(n)
        threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])


class Neutral(unittest.TestCase):
    """Adopting must be invisible apart from speed."""

    def test_sizes_and_later_use(self):
        for n in (0, 1, 2, 3, 16, 4096):
            data = bytes(i % 251 for i in range(n))
            for _ in range(LOOPS):
                a = bytes(bytearray(data))
                self.assertEqual((type(a), a, hash(a)), (bytes, data, hash(data)))
                b = bytearray(bytes(bytearray(data)))
                self.assertIs(type(b), bytearray)
                b += b"tail"
                self.assertEqual(b.take_bytes(), data + b"tail")
                self.assertEqual(bytearray(bytearray(data)), data)

    def test_singletons(self):
        # Identity, pickle memoization and marshal can all see these.
        one, empty = bytes([97]), bytes(0)
        for _ in range(LOOPS):
            self.assertIs(bytes(bytearray(b"a")), one)
            self.assertIs(bytes(bytearray()), empty)
            ba = bytearray(bytes(bytearray(b"a")))
            ba[0] = ord("z")
        self.assertEqual((one, empty), (b"a", b""))

    def test_allocation_failure(self):
        for op, make in CONVERSIONS:
            expected = op(make(ORIGINAL))
            for start in range(12):
                _testcapi.set_nomemory(start, start + 1)
                try:
                    res = op(make(ORIGINAL))
                except MemoryError:
                    continue
                finally:
                    _testcapi.remove_mem_hooks()
                self.assertEqual(res, expected)

    def test_no_python_frame(self):
        # A thread's base frame has no instructions to read.
        for code in (
            "import atexit; atexit.register(bytes, bytearray(b'abc'))",
            "import _thread, functools; _thread.start_joinable_thread("
            "functools.partial(bytes, bytearray(b'abc'))).join()",
            "from concurrent import interpreters; "
            "assert interpreters.create().call(bytes, bytearray(b'abc')) == b'abc'",
        ):
            with self.subTest(code):
                assert_python_ok("-c", code)

    def test_disable_during_call(self):
        # A CALL callback returning DISABLE de-instruments the running instruction,
        # but C_RETURN still reports the first argument afterward.
        mon = sys.monitoring
        for op, make in ((bytes, fresh_bytearray), (bytearray, fresh_bytes)):
            with self.subTest(op=op):
                kept = []
                def f():
                    return op(make())
                mon.use_tool_id(3, "test")
                try:
                    mon.register_callback(3, mon.events.CALL, lambda *a: mon.DISABLE)
                    mon.register_callback(
                        3, mon.events.C_RETURN,
                        lambda c, o, func, arg: func is op and kept.append(arg))
                    mon.set_local_events(3, f.__code__, mon.events.CALL)
                    res = f()
                finally:
                    mon.set_local_events(3, f.__code__, 0)
                    mon.register_callback(3, mon.events.CALL, None)
                    mon.register_callback(3, mon.events.C_RETURN, None)
                    mon.free_tool_id(3)
                self.assertEqual(kept, [ORIGINAL])
                if op is bytearray:
                    res[0] = 88  # Must not write into the bytes C_RETURN kept.
                    self.assertEqual(kept, [ORIGINAL])

    def test_tracemalloc(self):
        # The buffer is charged to the adopting line, as a copy would be.
        def make(op):
            return op(8192)
        for op, source in ((bytes, bytearray), (bytearray, bytes)):
            with self.subTest(op=op):
                tracemalloc.start()
                try:
                    res = op(make(source))
                    line = sys._getframe().f_lineno - 1
                    stats = tracemalloc.take_snapshot().statistics("lineno")
                finally:
                    tracemalloc.stop()
                self.assertEqual(
                    [s.traceback[0].lineno for s in stats if s.size >= 8192],
                    [line])
                del res


if __name__ == "__main__":
    unittest.main()

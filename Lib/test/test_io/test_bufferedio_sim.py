"""Behavioral tests for the buffered I/O layer under realistic workloads.

* Concurrent readers and writers sharing one buffered object.

Each test class runs against the C (_io) and Python (_pyio)
implementations.  Behavior differences are gated on is_C (see utils.py).
"""
import threading
import unittest

from test.support import os_helper, threading_helper
from .utils import CTestCase, PyTestCase


# --- Concurrency ---------------------------------------------------------------

@threading_helper.requires_working_threading()
class ConcurrentAccessTest:
    """Each buffered call is atomic with respect to other threads."""

    nthreads = 8
    records_per_thread = 2_000

    def check_concurrent_readers(self, read_record, buffering):
        # Each record is read whole, by one reader, even when it spans a
        # refill of the read-ahead (buffering not a multiple of rec).
        count = self.nthreads * self.records_per_thread
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        with open(os_helper.TESTFN, "wb") as f:
            for i in range(count):
                f.write(b"%015d\n" % i)
        seen = [[] for _ in range(self.nthreads)]
        with self.open(os_helper.TESTFN, "rb", buffering=buffering) as f:
            def reader(tid):
                while chunk := read_record(f):
                    seen[tid].append(chunk)

            threads = [threading.Thread(target=reader, args=(t,))
                       for t in range(self.nthreads)]
            with threading_helper.start_threads(threads):
                pass
        everything = sorted(c for s in seen for c in s)
        self.assertEqual(everything, [b"%015d\n" % i for i in range(count)])
        for s in seen:
            self.assertEqual(s, sorted(s))

    def test_concurrent_readline_gets_each_line_once(self):
        if not self.is_C:
            self.skipTest("readline() can split lines between threads")
        for buffering in (1000, 24):
            with self.subTest(buffering=buffering):
                self.check_concurrent_readers(lambda f: f.readline(),
                                              buffering)

    def test_concurrent_readinto_gets_each_record_once(self):
        if not self.is_C:
            self.skipTest("readinto() can split records between threads")

        def readinto(f):
            b = bytearray(16)
            return bytes(b[:f.readinto(b)])

        self.check_concurrent_readers(readinto, 24)


class CConcurrentAccessTest(ConcurrentAccessTest, CTestCase):
    pass


class PyConcurrentAccessTest(ConcurrentAccessTest, PyTestCase):
    pass


if __name__ == "__main__":
    unittest.main()

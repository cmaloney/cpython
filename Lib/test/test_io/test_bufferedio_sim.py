"""Behavioral tests for the buffered I/O layer under realistic workloads.

* Simulated slow and misbehaving devices: short reads and writes, "would
  block" (None) results, EINTR, transient errors, and real pipes.
* Concurrent readers and writers sharing one buffered object.

Each test class runs against the C (_io) and Python (_pyio)
implementations.  Behavior differences are gated on is_C (see utils.py).
"""
import errno
import random
import threading
import unittest

from test import support
from test.support import os_helper, threading_helper
from .utils import CTestCase, PyTestCase

# Skip reason for tests of _pyio TextIOWrapper fixes that _io lacks.
C_TEXT_GAP = "_io.TextIOWrapper lacks this _pyio fix"


# --- Scripted raw devices --------------------------------------------------
#
# A "plan" scripts what each raw call does; once the plan is exhausted every
# call is fully satisfied.  Plan steps:
#   int n           transfer at most n bytes (a short read/write)
#   None            would block: readinto()/write() return None
#   an exception    raised from the call (then the call is not performed)

def _next_step(plan):
    return plan.pop(0) if plan else -1


def make_scripted_reader(base):
    class ScriptedReader(base):
        def __init__(self, data, plan=()):
            self.data = bytes(data)
            self.pos = 0
            self.plan = list(plan)
            self.calls = 0

        def readable(self):
            return True

        def readinto(self, b):
            self.calls += 1
            step = _next_step(self.plan)
            if step is None:
                return None
            if isinstance(step, BaseException):
                raise step
            n = len(b) if step < 0 else min(step, len(b))
            chunk = self.data[self.pos:self.pos + n]
            b[:len(chunk)] = chunk
            self.pos += len(chunk)
            return len(chunk)

    return ScriptedReader


def make_scripted_writer(base):
    class ScriptedWriter(base):
        def __init__(self, plan=()):
            self.received = bytearray()
            self.plan = list(plan)
            self.calls = 0

        def writable(self):
            return True

        def write(self, b):
            self.calls += 1
            step = _next_step(self.plan)
            if step is None:
                return None
            if isinstance(step, BaseException):
                raise step
            with memoryview(b) as view:
                n = len(view) if step < 0 else min(step, len(view))
                self.received += view[:n]
            return n

    return ScriptedWriter


def sample_data(size, seed=0):
    rng = random.Random(seed)
    words = [b"alpha", b"beta", b"gamma", b"delta", b"\n", b"\r\n", b" ",
             b"\x00\xff", b"line\n"]
    out = bytearray()
    while len(out) < size:
        out += rng.choice(words)
    return bytes(out[:size])


# --- Simulated slow / misbehaving devices ------------------------------------

class SlowDeviceTest:
    """Buffered objects over raw devices that transfer a little at a time."""

    def scripted_reader(self, data, plan=()):
        return make_scripted_reader(self.RawIOBase)(data, plan)

    def scripted_writer(self, plan=()):
        return make_scripted_writer(self.RawIOBase)(plan)

    # Reading

    def test_text_read_would_block_keeps_partial_char(self):
        if self.is_C:
            self.skipTest(C_TEXT_GAP)
        # A raw stream that would block in the middle of a multibyte
        # character: its first bytes stay buffered for the next read,
        # instead of being decoded as if at EOF.
        data = "a\xe9€b".encode()
        raw = self.scripted_reader(data, [2, None, 2, None])
        f = self.TextIOWrapper(self.BufferedReader(raw, 16), encoding="utf-8")
        self.assertEqual(f.read(10), "a")
        self.assertEqual(f.read(10), "\xe9")
        self.assertEqual(f.read(10), "€b")
        self.assertEqual(f.read(10), "")

    # Writing

    def test_write_error_keeps_rest_that_fits(self):
        # An error (other than BlockingIOError) after part of write()'s
        # data was written keeps the rest pending when it fits in the
        # buffer: write() raises, and flush() writes the rest.
        data = sample_data(100)
        raw = self.scripted_writer([36, OSError(errno.EIO, "EIO")])
        f = self.BufferedWriter(raw, 64)
        with self.assertRaises(OSError) as cm:
            f.write(data)
        self.assertNotIsInstance(cm.exception, BlockingIOError)
        self.assertEqual(cm.exception.errno, errno.EIO)
        self.assertEqual(cm.exception.characters_written, 100)
        self.assertEqual(bytes(raw.received), data[:36])
        f.flush()
        self.assertEqual(bytes(raw.received), data)

    def test_write_error_keeps_what_fits(self):
        # When the rest doesn't fit, as much of it as fits is kept, and
        # characters_written says how much of the data was accepted
        # (written or kept): the caller writes the rest again.
        data = sample_data(200)
        raw = self.scripted_writer([30, TimeoutError("timed out")])
        f = self.BufferedWriter(raw, 64)
        with self.assertRaises(TimeoutError) as cm:
            f.write(data)
        n = cm.exception.characters_written
        self.assertEqual(n, 30 + 64)
        f.write(data[n:])
        f.flush()
        self.assertEqual(bytes(raw.received), data)

    def test_write_interrupted_keeps_rest(self):
        # The same for an exception that isn't an OSError (such as one a
        # signal handler raises), which has no characters_written.
        data = sample_data(100)
        raw = self.scripted_writer([36, KeyboardInterrupt()])
        f = self.BufferedWriter(raw, 64)
        with self.assertRaises(KeyboardInterrupt) as cm:
            f.write(data)
        self.assertNotHasAttr(cm.exception, "characters_written")
        f.flush()
        self.assertEqual(bytes(raw.received), data)

    def test_close_flush_error_discards(self):
        # When the flush of close() fails, for any reason, close() still
        # closes completely: the pending data is discarded with a warning,
        # and nothing writes it again (gh-83973, gh-55589).
        for step, exc in ((OSError(errno.EPIPE, "EPIPE"), BrokenPipeError),
                          (None, BlockingIOError),
                          (KeyboardInterrupt(), KeyboardInterrupt)):
            with self.subTest(exc=exc):
                raw = self.scripted_writer([step])
                f = self.BufferedWriter(raw, 64)
                f.write(b"x" * 10)
                with self.assertWarnsRegex(RuntimeWarning,
                                           "discarded 10 buffered bytes"):
                    with self.assertRaises(exc):
                        f.close()
                self.assertTrue(f.closed)
                self.assertTrue(raw.closed)
                calls = raw.calls
                f.close()
                del f
                support.gc_collect()
                self.assertEqual(raw.calls, calls)
                self.assertEqual(raw.received, b"")

    def test_text_close_flush_error_no_retry(self):
        if self.is_C:
            self.skipTest(C_TEXT_GAP)
        # TextIOWrapper.close() doesn't write the data again through the
        # close() of its buffer either.
        raw = self.scripted_writer([OSError(errno.EPIPE, "EPIPE")])
        f = self.TextIOWrapper(self.BufferedWriter(raw, 64), encoding="ascii")
        f.write("abc")
        with self.assertWarnsRegex(RuntimeWarning,
                                   "discarded 3 buffered bytes"):
            with self.assertRaises(BrokenPipeError):
                f.close()
        self.assertTrue(f.closed)
        self.assertEqual(raw.calls, 1)
        self.assertEqual(raw.received, b"")


class CSlowDeviceTest(SlowDeviceTest, CTestCase):
    pass


class PySlowDeviceTest(SlowDeviceTest, PyTestCase):
    pass


# --- Positioning within the buffer ---------------------------------------------

class PositionTest:
    """seek() within buffered data, and what it costs in raw calls."""

    def test_append_mode_write_after_read(self):
        # gh-64281: a raw stream in append mode writes at the end of the
        # file whatever the position, so data read before a write must
        # still read back as it is in the file.
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        with self.open(os_helper.TESTFN, "wb") as f:
            f.write(b"testest")
        with self.open(os_helper.TESTFN, "a+b") as f:
            f.write(b"A")
            f.seek(0)
            self.assertEqual(f.read(), b"testestA")
            f.seek(0)
            self.assertEqual(f.read(1), b"t")
            f.write(b"B")
            f.seek(0)
            self.assertEqual(f.read(), b"testestAB")
        with self.open(os_helper.TESTFN, "rb") as f:
            self.assertEqual(f.read(), b"testestAB")

    def test_append_mode_tell_after_write(self):
        # gh-80592: a write to a raw file in append mode goes to the end of
        # the file, so tell() is the end of the file after it.
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        for mode in ("ab", "a+b"):
            with self.subTest(mode=mode):
                with self.open(os_helper.TESTFN, "wb") as f:
                    f.write(b"abc")
                with self.open(os_helper.TESTFN, mode) as f:
                    self.assertEqual(f.tell(), 3)
                    f.write(b"def")
                    self.assertEqual(f.tell(), 6)
                    self.assertEqual(f.seek(0), 0)
                    self.assertEqual(f.tell(), 0)
                    f.write(b"ghi")
                    self.assertEqual(f.tell(), 9)
                    f.write(b"jkl")
                    self.assertEqual(f.tell(), 12)
                    self.assertEqual(f.seek(0, 1), 12)
                with self.open(os_helper.TESTFN, "rb") as f:
                    self.assertEqual(f.read(), b"abcdefghijkl")


class CPositionTest(PositionTest, CTestCase):
    pass


class PyPositionTest(PositionTest, PyTestCase):
    pass


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

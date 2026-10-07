"""Behavioral tests for the buffered I/O layer under realistic workloads.

* Reading every documentation and stdlib source file (the gh-120754
  Path.read_bytes() workload) and checking the bytes match the raw file.
* Simulated slow and misbehaving devices: short reads and writes, "would
  block" (None) results, EINTR, transient errors, and real pipes.
* A differential test running random operation sequences against
  BufferedRandom and an io.BytesIO model.
* Concurrent readers and writers sharing one buffered object.

Each test class runs against the C (_io), Python (_pyio) and C nibbler
(_io._nibbler) implementations.  Behavior differences are gated on
capability attributes (see utils.py); is_C only picks error messages and
known _pyio quirks.
"""
import errno
import glob
import os
import random
import select
import sys
import threading
import unittest

from test import support
from test.support import os_helper, threading_helper
from .utils import CTestCase, PyTestCase, NibblerMixin


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


def make_memory_raw(base):
    """Seekable in-memory raw file with random short reads and writes."""
    class MemoryRaw(base):
        def __init__(self, data=b"", rng=None, max_transfer=None):
            self.buf = bytearray(data)
            self.pos = 0
            self.rng = rng
            self.max_transfer = max_transfer

        def _limit(self, n):
            if self.rng is None or n == 0:
                return n
            return min(n, self.rng.randint(1, self.max_transfer))

        def readable(self):
            return True

        def writable(self):
            return True

        def seekable(self):
            return True

        def readinto(self, b):
            n = self._limit(len(b))
            chunk = self.buf[self.pos:self.pos + n]
            b[:len(chunk)] = chunk
            self.pos += len(chunk)
            return len(chunk)

        def write(self, b):
            with memoryview(b) as view:
                n = self._limit(len(view))
                if self.pos > len(self.buf):
                    self.buf += bytes(self.pos - len(self.buf))
                self.buf[self.pos:self.pos + n] = view[:n]
            self.pos += n
            return n

        def seek(self, pos, whence=0):
            if whence == 0:
                new = pos
            elif whence == 1:
                new = self.pos + pos
            elif whence == 2:
                new = len(self.buf) + pos
            else:
                raise ValueError("invalid whence")
            if new < 0:
                raise OSError(errno.EINVAL, "negative seek position")
            self.pos = new
            return new

        def tell(self):
            return self.pos

        def truncate(self, size=None):
            if size is None:
                size = self.pos
            del self.buf[size:]
            if size > len(self.buf):
                self.buf += bytes(size - len(self.buf))
            return size

    return MemoryRaw


def eintr():
    return InterruptedError(errno.EINTR, os.strerror(errno.EINTR))


def sample_data(size, seed=0):
    rng = random.Random(seed)
    words = [b"alpha", b"beta", b"gamma", b"delta", b"\n", b"\r\n", b" ",
             b"\x00\xff", b"line\n"]
    out = bytearray()
    while len(out) < size:
        out += rng.choice(words)
    return bytes(out[:size])


# --- Reading all docs / stdlib sources ---------------------------------------

def _repo_files(pattern):
    return sorted(glob.glob(os.path.join(support.REPO_ROOT, pattern),
                            recursive=True))


class ReadAllDocsTest:
    """Every Doc/*.rst and Lib/*.py file reads back byte-for-byte.

    Mirrors the gh-120754 Path.read_bytes() workload.  The reference is the
    raw FileIO.readall(); every buffered path must produce the same bytes.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.rst_files = _repo_files("Doc/**/*.rst")
        cls.py_files = _repo_files("Lib/**/*.py")
        if not cls.rst_files or not cls.py_files:
            raise unittest.SkipTest("requires a CPython source checkout")

    def reference(self, path):
        with self.FileIO(path) as raw:
            return raw.readall()

    def check_files(self, paths, read):
        for path in paths:
            expected = self.reference(path)
            got = read(path)
            if got != expected:
                self.fail(f"{os.path.relpath(path, support.REPO_ROOT)}: "
                          f"read {len(got)} bytes, expected {len(expected)}")

    def test_open_read(self):
        def read(path):
            with self.open(path, "rb") as f:
                return f.read()
        self.check_files(self.rst_files + self.py_files, read)

    def test_open_read_buffering_zero(self):
        def read(path):
            with self.open(path, "rb", buffering=0) as f:
                return f.read()
        self.check_files(self.rst_files + self.py_files, read)

    def test_read_whole_buffer_sizes(self):
        for size in (1, 7, 4096, 4097):
            with self.subTest(buffer_size=size):
                def read(path):
                    with self.BufferedReader(self.FileIO(path), size) as f:
                        return f.read()
                self.check_files(self.rst_files, read)

    def test_read_chunks(self):
        for size, chunk in ((7, 97), (4096, 97), (4096, 5000), (8192, 1)):
            with self.subTest(buffer_size=size, chunk=chunk):
                def read(path):
                    out = []
                    with self.BufferedReader(self.FileIO(path), size) as f:
                        while data := f.read(chunk):
                            self.assertLessEqual(len(data), chunk)
                            out.append(data)
                    return b"".join(out)
                # One byte at a time over everything is too slow; sample.
                paths = self.rst_files if chunk > 1 else self.rst_files[:20]
                self.check_files(paths, read)

    def test_readline_iteration(self):
        def read(path):
            with self.open(path, "rb") as f:
                return b"".join(f)
        self.check_files(self.rst_files, read)

    def test_read1_peek(self):
        def read(path):
            out = []
            with self.BufferedReader(self.FileIO(path), 512) as f:
                while f.peek(1):
                    out.append(f.read1(300))
            return b"".join(out)
        self.check_files(self.rst_files, read)

    def test_read_text(self):
        for path in self.rst_files:
            expected = self.reference(path).decode("utf-8")
            with self.open(path, encoding="utf-8", newline="") as f:
                self.assertEqual(f.read(), expected, path)


class CReadAllDocsTest(ReadAllDocsTest, CTestCase):
    pass


class PyReadAllDocsTest(ReadAllDocsTest, PyTestCase):
    pass


class NibblerReadAllDocsTest(NibblerMixin, ReadAllDocsTest, CTestCase):
    pass


# --- Simulated slow / misbehaving devices ------------------------------------

class SlowDeviceTest:
    """Buffered objects over raw devices that transfer a little at a time."""

    def scripted_reader(self, data, plan=()):
        return make_scripted_reader(self.RawIOBase)(data, plan)

    def scripted_writer(self, plan=()):
        return make_scripted_writer(self.RawIOBase)(plan)

    def trickle_plan(self, seed, calls, max_step):
        rng = random.Random(seed)
        return [rng.randint(1, max_step) for _ in range(calls)]

    # Reading

    def test_trickle_read_all(self):
        data = sample_data(50_000)
        for max_step in (1, 13, 1000):
            with self.subTest(max_step=max_step):
                raw = self.scripted_reader(
                    data, self.trickle_plan(max_step, 100_000, max_step))
                f = self.BufferedReader(raw, 4096)
                self.assertEqual(f.read(), data)
                self.assertEqual(f.read(), b"")

    def test_trickle_read_n_is_exact(self):
        # A blocking read(n) keeps calling the raw stream until it has n
        # bytes or reaches EOF, however little each raw call returns.
        data = sample_data(20_000)
        for size, n in ((16, 100), (4096, 100), (4096, 10_000), (64, 64)):
            with self.subTest(buffer_size=size, n=n):
                raw = self.scripted_reader(
                    data, self.trickle_plan(n, 100_000, 7))
                f = self.BufferedReader(raw, size)
                pos = 0
                while pos < len(data):
                    chunk = f.read(n)
                    self.assertEqual(chunk, data[pos:pos + n])
                    pos += len(chunk)
                self.assertEqual(f.read(n), b"")

    def test_trickle_readinto_is_exact(self):
        data = sample_data(10_000)
        raw = self.scripted_reader(data, self.trickle_plan(1, 100_000, 5))
        f = self.BufferedReader(raw, 128)
        out = bytearray()
        buf = bytearray(300)
        while n := f.readinto(buf):
            if len(out) + n < len(data):
                self.assertEqual(n, len(buf))
            out += buf[:n]
        self.assertEqual(out, data)

    def test_trickle_readline(self):
        data = sample_data(30_000)
        raw = self.scripted_reader(data, self.trickle_plan(2, 100_000, 9))
        f = self.BufferedReader(raw, 32)
        self.assertEqual(list(f), data.splitlines(keepends=True))

    def test_read1_and_peek_make_at_most_one_raw_call(self):
        data = sample_data(5_000)
        raw = self.scripted_reader(data, self.trickle_plan(3, 100_000, 50))
        f = self.BufferedReader(raw, 256)
        out = bytearray()
        while True:
            before = raw.calls
            peeked = f.peek(1)
            self.assertLessEqual(raw.calls - before, 1)
            before = raw.calls
            chunk = f.read1(100)
            self.assertLessEqual(raw.calls - before, 1)
            self.assertLessEqual(len(chunk), 100)
            if peeked:
                self.assertTrue(chunk)
                self.assertTrue(chunk.startswith(peeked[:len(chunk)]))
            if not chunk:
                break
            out += chunk
        self.assertEqual(out, data)

    def test_read_would_block(self):
        # None ("would block") from the raw stream surfaces as a short or
        # None result; retrying eventually yields all data, in order.
        data = sample_data(5_000)
        rng = random.Random(4)
        plan = [None if rng.random() < 0.3 else rng.randint(1, 40)
                for _ in range(10_000)]
        raw = self.scripted_reader(data, plan)
        f = self.BufferedReader(raw, 64)
        out = bytearray()
        for _ in range(100_000):
            chunk = f.read(50)
            if chunk is None:
                continue
            if not chunk and not raw.plan:
                break
            out += chunk
        self.assertEqual(out, data)

    def test_read_eintr_is_retried(self):
        if not self.retries_raw_eintr:
            self.skipTest("buffered layer does not retry raw EINTR")
        data = sample_data(1_000)
        plan = [eintr(), 10, eintr(), eintr(), 5, eintr()] * 20
        raw = self.scripted_reader(data, plan)
        f = self.BufferedReader(raw, 16)
        self.assertEqual(f.read(), data)

    def test_read_error_then_resume(self):
        # An OSError from the device propagates.  Data returned before the
        # error is never repeated, and reading resumes after it.
        data = sample_data(1_000)
        raw = self.scripted_reader(data, [100, OSError(errno.EIO, "EIO")])
        f = self.BufferedReader(raw, 64)
        self.assertEqual(f.read(30), data[:30])
        got = bytearray(data[:30])
        with self.assertRaises(OSError):
            while True:
                got += f.read1(50)
        got += f.read()
        self.assertEqual(bytes(got), data)

    # Writing

    def test_trickle_write(self):
        data = sample_data(50_000)
        rng = random.Random(5)
        for max_step in (1, 13, 1000):
            with self.subTest(max_step=max_step):
                raw = self.scripted_writer(
                    self.trickle_plan(max_step, 200_000, max_step))
                f = self.BufferedWriter(raw, 256)
                pos = 0
                while pos < len(data):
                    n = rng.choice((1, 3, 100, 255, 256, 257, 4000))
                    self.assertEqual(f.write(data[pos:pos + n]),
                                     len(data[pos:pos + n]))
                    pos += n
                f.flush()
                self.assertEqual(bytes(raw.received), data)

    def test_buffered_amount_is_bounded(self):
        # Once more than buffer_size bytes are written, all but at most
        # buffer_size of them have reached the device.
        raw = self.scripted_writer(self.trickle_plan(6, 100_000, 7))
        size = 100
        f = self.BufferedWriter(raw, size)
        total = 0
        for i in range(2_000):
            chunk = bytes([i % 256]) * (i % 37 + 1)
            f.write(chunk)
            total += len(chunk)
            self.assertGreaterEqual(len(raw.received), total - size)
        f.flush()
        self.assertEqual(len(raw.received), total)

    def test_write_mutable_buffer_after_write(self):
        # Mutating a buffer after write() returns must not change what
        # was written.
        raw = self.scripted_writer(self.trickle_plan(7, 10_000, 3))
        f = self.BufferedWriter(raw, 64)
        buf = bytearray(b"a" * 10)
        expected = bytearray()
        for i in range(200):
            f.write(buf)
            expected += buf
            buf[:] = bytes([97 + i % 26]) * 10
        f.flush()
        self.assertEqual(raw.received, expected)

    def test_write_would_block(self):
        # Retrying with the unwritten tail reported by BlockingIOError
        # delivers every byte exactly once.
        data = sample_data(20_000)
        rng = random.Random(8)
        plan = [None if rng.random() < 0.3 else rng.randint(1, 60)
                for _ in range(20_000)]
        raw = self.scripted_writer(plan)
        f = self.BufferedWriter(raw, 128)
        pos = 0
        while pos < len(data):
            n = rng.choice((1, 50, 127, 128, 129, 1000))
            chunk = data[pos:pos + n]
            try:
                written = f.write(chunk)
            except BlockingIOError as e:
                written = e.characters_written
            self.assertLessEqual(written, len(chunk))
            pos += written
        for _ in range(100_000):
            try:
                f.flush()
                break
            except BlockingIOError:
                pass
        self.assertEqual(bytes(raw.received), data)

    def test_empty_writes_between_large_writes(self):
        # Empty writes mixed with writes large enough to be kept by
        # reference must not stall flushing.
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        with self.open(os_helper.TESTFN, "wb") as f:
            for size in (2000, 0, 3000, 0, 0, 10, 0, 9000, 0):
                f.write(b"x" * size)
            f.write(b"")
        with open(os_helper.TESTFN, "rb") as f:
            self.assertEqual(f.read(), b"x" * 14010)

    def test_write_after_raw_closed_with_readahead(self):
        # Leftover read-ahead must not let writes through once the raw
        # stream is closed.
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        raw = self.FileIO(os_helper.TESTFN, "w+b")
        raw.write(b"x" * 100)
        raw.seek(0)
        f = self.BufferedRandom(raw, 16)
        self.assertEqual(f.read(1), b"x")
        raw.close()
        # (_pyio reports the raw stream's error message.)
        msg = "write to closed file" if self.is_C else "closed file"
        with self.assertRaisesRegex(ValueError, msg):
            f.write(b"y")

    def test_fileio_subclass_write_is_used(self):
        # Vectored writes must not bypass a write() override.
        written = []

        class RecordingFileIO(self.FileIO):
            def write(self, b):
                written.append(bytes(b))
                return super().write(b)

        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        with self.BufferedWriter(RecordingFileIO(os_helper.TESTFN, "w"),
                                 64) as f:
            for i in range(10):
                f.write(bytes([65 + i]) * 600)
                f.write(b"small")
        self.assertEqual(b"".join(written),
                         b"".join(bytes([65 + i]) * 600 + b"small"
                                  for i in range(10)))

    def test_raw_instance_overrides_are_called(self):
        # flush() and close() set on a FileIO instance are used by the
        # buffered object's close().
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        with open(os_helper.TESTFN, "wb") as f:
            f.write(b"data")
        calls = []
        raw = self.FileIO(os_helper.TESTFN)
        real_close = raw.close
        raw.flush = lambda: calls.append("flush")
        raw.close = lambda: (calls.append("close"), real_close())[1]
        f = self.BufferedReader(raw)
        self.assertEqual(f.read(), b"data")
        f.close()
        # The real close() flushes once more, through the override.
        self.assertEqual(calls, ["flush", "close", "flush"])
        self.assertTrue(raw.closed)

    def test_write_eintr_is_retried(self):
        if not self.retries_raw_eintr:
            self.skipTest("buffered layer does not retry raw EINTR")
        plan = [eintr(), 3, eintr(), eintr(), 50] * 100
        raw = self.scripted_writer(plan)
        f = self.BufferedWriter(raw, 32)
        data = sample_data(5_000)
        for i in range(0, len(data), 77):
            f.write(data[i:i + 77])
        f.flush()
        self.assertEqual(bytes(raw.received), data)

    def test_write_error_then_flush(self):
        # A failed flush keeps the unwritten data; a later flush sends it
        # without loss or duplication.
        raw = self.scripted_writer([5, OSError(errno.EIO, "EIO")])
        f = self.BufferedWriter(raw, 64)
        f.write(b"x" * 40)
        with self.assertRaises(OSError):
            f.flush()
        f.flush()
        self.assertEqual(bytes(raw.received), b"x" * 40)

    # Real file descriptors

    @threading_helper.requires_working_threading()
    def test_pipe_slow_producer(self):
        data = sample_data(200_000)
        r, w = os.pipe()

        def producer():
            rng = random.Random(9)
            try:
                pos = 0
                while pos < len(data):
                    n = rng.randint(1, 3000)
                    pos += os.write(w, data[pos:pos + n])
            finally:
                os.close(w)

        with threading_helper.start_threads([threading.Thread(target=producer)]):
            with self.open(r, "rb") as f:
                out = bytearray()
                rng = random.Random(10)
                while True:
                    n = rng.choice((1, 100, 4096, 10_000))
                    chunk = f.read(n)
                    if not chunk:
                        break
                    if len(out) + len(chunk) < len(data):
                        # Blocking read(n) only returns short at EOF.
                        self.assertEqual(len(chunk), n)
                    out += chunk
        self.assertEqual(bytes(out), data)

    @threading_helper.requires_working_threading()
    @unittest.skipUnless(hasattr(os, "set_blocking"), "requires set_blocking")
    @unittest.skipIf(sys.platform == "win32", "select() needs sockets")
    def test_pipe_slow_consumer_nonblocking(self):
        data = sample_data(500_000)
        r, w = os.pipe()
        os.set_blocking(w, False)
        received = bytearray()

        def consumer():
            with open(r, "rb", buffering=0) as rf:
                while chunk := rf.read(997):
                    received.extend(chunk)

        with threading_helper.start_threads([threading.Thread(target=consumer)]):
            with self.open(w, "wb", buffering=4096) as f:
                rng = random.Random(11)
                pos = 0
                while pos < len(data):
                    n = rng.choice((10, 1000, 4096, 50_000))
                    try:
                        pos += f.write(data[pos:pos + n])
                    except BlockingIOError as e:
                        pos += e.characters_written
                        select.select([], [w], [], support.SHORT_TIMEOUT)
                while True:
                    try:
                        f.flush()
                        break
                    except BlockingIOError:
                        select.select([], [w], [], support.SHORT_TIMEOUT)
        self.assertEqual(bytes(received), data)

    # buffer_size=0: no internal buffer, but partial transfers are retried.

    def check_buffer_size_zero(self):
        if not self.supports_buffer_size_zero:
            self.skipTest("buffer_size=0 not supported")

    def test_size_zero_write_retries(self):
        self.check_buffer_size_zero()
        raw = self.scripted_writer(self.trickle_plan(12, 10_000, 7))
        f = self.BufferedWriter(raw, 0)
        data = sample_data(3_000)
        for i in range(0, len(data), 100):
            self.assertEqual(f.write(data[i:i + 100]), 100)
            # Nothing is held back: the device already has every byte.
            self.assertEqual(bytes(raw.received), data[:i + 100])

    def test_size_zero_read_is_exact(self):
        self.check_buffer_size_zero()
        data = sample_data(3_000)
        raw = self.scripted_reader(data, self.trickle_plan(13, 10_000, 7))
        f = self.BufferedReader(raw, 0)
        self.assertEqual(f.read(100), data[:100])
        buf = bytearray(100)
        self.assertEqual(f.readinto(buf), 100)
        self.assertEqual(buf, data[100:200])
        self.assertEqual(f.read(), data[200:])
        # Nothing read ahead: the device position matches the logical one.
        self.assertEqual(raw.pos, len(data))


class CSlowDeviceTest(SlowDeviceTest, CTestCase):
    pass


class PySlowDeviceTest(SlowDeviceTest, PyTestCase):
    # _pyio BufferedReader._readinto() sizes the copy from its buffer with
    # len(buf) instead of len(buf) - written, so a readinto() that needs
    # more than one refill raises ValueError (memoryview assignment).
    @unittest.expectedFailure
    def test_trickle_readinto_is_exact(self):
        super().test_trickle_readinto_is_exact()


class NibblerSlowDeviceTest(NibblerMixin, SlowDeviceTest, CTestCase):
    pass


# --- Positioning within the buffer ---------------------------------------------

class PositionTest:
    """seek() within buffered data, and what it costs in raw calls."""

    def counting_raw(self, data):
        class CountingRaw(make_memory_raw(self.RawIOBase)):
            reads = seeks = writes = 0

            def readinto(self, b):
                self.reads += 1
                return super().readinto(b)

            def seek(self, pos, whence=0):
                self.seeks += 1
                return super().seek(pos, whence)

            def write(self, b):
                self.writes += 1
                return super().write(b)

        return CountingRaw(data)

    def test_seek_back_after_direct_read(self):
        # A read too large for the buffer bypasses it; seeking back must
        # not return the bytes the buffer held before.
        data = bytes(range(256)) * 4
        f = self.BufferedReader(self.counting_raw(data), 8)
        self.assertEqual(f.read(3), data[:3])
        self.assertEqual(f.read(20), data[3:23])
        self.assertEqual(f.seek(-2, 1), 21)
        self.assertEqual(f.read(2), data[21:23])

        f = self.BufferedReader(self.counting_raw(data), 8)
        self.assertEqual(f.read(3), data[:3])
        self.assertEqual(f.read(), data[3:])
        self.assertEqual(f.seek(-2, 1), len(data) - 2)
        self.assertEqual(f.read(), data[-2:])

    def test_seek_within_buffer(self):
        data = bytes(range(64))
        raw = self.counting_raw(data)
        f = self.BufferedReader(raw, 16)
        self.assertEqual(f.read(1), data[:1])
        self.assertEqual(f.seek(10), 10)
        self.assertEqual(f.read(1), data[10:11])
        self.assertEqual(f.seek(-8, 1), 3)
        self.assertEqual(f.read(2), data[3:5])
        self.assertEqual(f.seek(0), 0)
        self.assertEqual(f.read(16), data[:16])
        if self.is_C:
            # Served from the first fill (_pyio always seeks the raw).
            self.assertEqual(raw.reads, 1)
            self.assertEqual(raw.seeks, 0)

    def test_read0_keeps_pending_writes(self):
        raw = self.counting_raw(b"")
        f = self.BufferedRandom(raw, 16)
        f.write(b"abc")
        self.assertEqual(f.read(0), b"")
        self.assertEqual(f.read1(0), b"")
        self.assertEqual(f.readline(0), b"")
        if self.is_C:
            # _pyio's read() always flushes first.
            self.assertEqual(raw.writes, 0)
        f.flush()
        self.assertEqual(bytes(raw.buf), b"abc")


    def test_returned_bytes_never_change(self):
        # Data handed out (possibly without a copy) stays as returned
        # while the buffer is refilled.
        data = bytes(range(256)) * 16
        f = self.BufferedReader(self.counting_raw(data), 64)
        got = []
        while True:
            for chunk in (f.peek(), f.read1(64), f.read1(10), f.read(70)):
                if chunk:
                    got.append((chunk, bytes(chunk)))
            if not f.peek():
                break
        for chunk, copy in got:
            self.assertEqual(chunk, copy)

    def test_write_back_handed_out_block(self):
        # A block handed out by read() and written back must not be the
        # target of later copied writes.
        data = bytes(range(256)) * 8
        with self.open(os_helper.TESTFN, "wb") as f:
            f.write(data)
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        with self.open(os_helper.TESTFN, "r+b", buffering=1024) as f:
            block = f.read(1024)
            expected = bytes(block)
            f.write(block[:600])
            f.write(block)
            f.write(b"x")
            self.assertEqual(block, expected)
            f.write(b"y" * 100)
            self.assertEqual(block, expected)

    def test_raw_keeping_write_view(self):
        if not self.isolates_raw_views:
            self.skipTest("buffer memory is reused under raw views")
        # A raw stream that keeps the views given to write() sees data that
        # stays as written.
        class KeepingRaw(make_memory_raw(self.RawIOBase)):
            kept = []

            def write(self, b):
                self.kept.append((b, bytes(b)))
                return super().write(b)

        raw = KeepingRaw()
        f = self.BufferedWriter(raw, 16)
        for i in range(50):
            f.write(bytes([i]) * 7)
        f.flush()
        for view, copy in raw.kept:
            self.assertEqual(bytes(view), copy)

    def test_overflow_keeps_small_write_buffered(self):
        # Without vectored writes, a small write that doesn't fit after
        # the pending data writes out the pending data and buffers itself.
        raw = self.counting_raw(b"")
        f = self.BufferedWriter(raw, 8)
        f.write(b"abcde")
        f.write(b"fghij")
        if self.is_C:
            # _pyio writes both at once.
            self.assertEqual(bytes(raw.buf), b"abcde")
        f.flush()
        self.assertEqual(bytes(raw.buf), b"abcdefghij")


    @property
    def detached_errors(self):
        # _pyio reaches into the missing raw stream instead.
        return ValueError if self.is_C else (ValueError, AttributeError)

    def test_detach_writes_pending(self):
        raw = self.counting_raw(b"")
        f = self.BufferedWriter(raw, 64)
        f.write(b"pending")
        self.assertIs(f.detach(), raw)
        self.assertEqual(bytes(raw.buf), b"pending")
        self.assertIsNone(f.raw)
        self.assertRaises(self.detached_errors, f.write, b"x")
        self.assertRaises(self.detached_errors, f.flush)

    def test_detach_reader(self):
        raw = self.counting_raw(b"abcdef")
        f = self.BufferedReader(raw, 4)
        self.assertEqual(f.read(1), b"a")
        self.assertIs(f.detach(), raw)
        self.assertIsNone(f.raw)
        self.assertRaises(self.detached_errors, f.read)
        self.assertRaises(self.detached_errors, f.peek)


class CPositionTest(PositionTest, CTestCase):
    pass


class PyPositionTest(PositionTest, PyTestCase):
    pass


class NibblerPositionTest(NibblerMixin, PositionTest, CTestCase):
    pass


# --- Differential test against an io.BytesIO model ---------------------------

class RandomOpsTest:
    """Random operation sequences on BufferedRandom match io.BytesIO."""

    seeds = range(150)
    ops_per_seed = 60

    def run_seed(self, seed, make_raw, size):
        rng = random.Random(seed)
        initial = sample_data(rng.randint(0, 3000), seed)
        model = self.io.BytesIO(initial)
        raw = make_raw(initial, rng)
        f = self.BufferedRandom(raw, size)
        log = []

        def check(what, got, expected):
            if got != expected:
                self.fail(f"seed {seed}, buffer_size {size}: {what}: "
                          f"{got!r:.80} != {expected!r:.80}\nops: {log}")

        for _ in range(self.ops_per_seed):
            op = rng.choice(("read", "read", "read1", "readline", "peek",
                             "readinto", "write", "write", "seek", "seek",
                             "tell", "truncate", "flush"))
            if op == "read":
                n = rng.choice((-1, 0, 1, 5, 64, 300, size, size + 1))
                log.append((op, n))
                check(op, f.read(n), model.read(n))
            elif op == "read1":
                n = rng.choice((1, 5, 64, 300))
                log.append((op, n))
                got = f.read1(n)
                expected = model.read(len(got))
                check(op, got, expected)
                self.assertLessEqual(len(got), n)
                if not got:
                    check("read1 at EOF", model.read(1), b"")
            elif op == "readline":
                n = rng.choice((-1, 1, 10, 100))
                log.append((op, n))
                check(op, f.readline(n), model.readline(n))
            elif op == "peek":
                log.append((op,))
                got = f.peek(1)
                pos = model.tell()
                rest = model.read()
                model.seek(pos)
                check(op, rest.startswith(got), True)
                check("peek non-empty", bool(got), bool(rest))
            elif op == "readinto":
                n = rng.choice((0, 1, 7, 100, 500))
                log.append((op, n))
                buf = bytearray(n)
                got = f.readinto(buf)
                expected = model.read(n)
                check(op, bytes(buf[:got]), expected)
            elif op == "write":
                data = sample_data(rng.choice((1, 3, 50, size, 2 * size)),
                                   rng.randrange(1 << 30))
                log.append((op, len(data)))
                check(op, f.write(data), model.write(data))
            elif op == "seek":
                whence = rng.choice((0, 1, 2))
                end = len(model.getvalue())
                cur = model.tell()
                if rng.random() < 0.5:
                    # Nearby, often within the buffer.
                    target = max(0, cur + rng.randint(-2 * size, 2 * size))
                else:
                    target = rng.randint(0, end + 100)
                off = target - (0, cur, end)[whence]
                log.append((op, off, whence))
                check(op, f.seek(off, whence), model.seek(off, whence))
            elif op == "tell":
                log.append((op,))
            elif op == "truncate":
                # BytesIO.truncate() never extends; files do.  Stay in range
                # (can extend once BytesIO.truncate() matches files).
                end = len(model.getvalue())
                n = rng.choice((None, 0, end // 2, end))
                if n is None and model.tell() > end:
                    n = end
                log.append((op, n))
                check(op, f.truncate(n), model.truncate(n))
            elif op == "flush":
                log.append((op,))
                f.flush()
            check("tell", f.tell(), model.tell())

        f.detach()  # Flushes; the caller owns raw.
        return raw, model.getvalue(), check

    def test_file(self):
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        for seed in self.seeds:
            size = (1, 16, 512, 4096)[seed % 4]
            with self.subTest(seed=seed, buffer_size=size):
                def make_raw(initial, rng):
                    with open(os_helper.TESTFN, "wb") as init:
                        init.write(initial)
                    return self.FileIO(os_helper.TESTFN, "r+")

                raw, expected, check = self.run_seed(seed, make_raw, size)
                raw.close()
                with open(os_helper.TESTFN, "rb") as result:
                    check("file content", result.read(), expected)

    def test_short_transfer_device(self):
        MemoryRaw = make_memory_raw(self.RawIOBase)
        for seed in self.seeds:
            size = (1, 16, 512, 4096)[seed % 4]
            with self.subTest(seed=seed, buffer_size=size):
                def make_raw(initial, rng):
                    return MemoryRaw(initial, rng, max_transfer=37)
                raw, expected, check = self.run_seed(seed, make_raw, size)
                check("device content", bytes(raw.buf), expected)


class CRandomOpsTest(RandomOpsTest, CTestCase):
    pass


class PyRandomOpsTest(RandomOpsTest, PyTestCase):
    # Known _pyio bugs these sequences hit (C gets them right):
    # * readline(size) can return more than size bytes: IOBase.readline's
    #   nreadahead() clamps each step to size, not to what is still needed
    #   (BufferedRandom(raw, 16): readline(100); readline(10) -> 15 bytes).
    # * truncate() keeps read-ahead data, so reads return bytes past the
    #   new end (BufferedRandom(raw, 512): readinto(100); truncate(100);
    #   read1(64) -> data instead of b"").
    # * The _readinto() ValueError described on PySlowDeviceTest.
    @unittest.expectedFailure
    def test_file(self):
        super().test_file()

    @unittest.expectedFailure
    def test_short_transfer_device(self):
        super().test_short_transfer_device()


class NibblerRandomOpsTest(NibblerMixin, RandomOpsTest, CTestCase):
    pass


# --- Concurrency ---------------------------------------------------------------

@threading_helper.requires_working_threading()
class ConcurrentAccessTest:
    """Each buffered call is atomic with respect to other threads."""

    nthreads = 8
    records_per_thread = 2_000

    def test_concurrent_writers_keep_records_whole(self):
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        with self.open(os_helper.TESTFN, "wb", buffering=1000) as f:
            def writer(tid):
                for i in range(self.records_per_thread):
                    f.write(b"%02d:%06d|" % (tid, i) + b"." * (i % 50) + b"\n")

            threads = [threading.Thread(target=writer, args=(t,))
                       for t in range(self.nthreads)]
            with threading_helper.start_threads(threads):
                pass
        with open(os_helper.TESTFN, "rb") as f:
            lines = f.read().splitlines()
        expected = sorted(b"%02d:%06d|" % (t, i) + b"." * (i % 50)
                          for t in range(self.nthreads)
                          for i in range(self.records_per_thread))
        self.assertEqual(sorted(lines), expected)
        # Per-thread order is preserved.
        for t in range(self.nthreads):
            prefix = b"%02d:" % t
            mine = [line for line in lines if line.startswith(prefix)]
            self.assertEqual(mine, sorted(mine))

    def test_concurrent_readers_get_each_record_once(self):
        rec = 16
        count = self.nthreads * self.records_per_thread
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        with open(os_helper.TESTFN, "wb") as f:
            for i in range(count):
                f.write(b"%015d\n" % i)
        seen = [[] for _ in range(self.nthreads)]
        with self.open(os_helper.TESTFN, "rb", buffering=1000) as f:
            def reader(tid):
                while chunk := f.read(rec):
                    seen[tid].append(chunk)

            threads = [threading.Thread(target=reader, args=(t,))
                       for t in range(self.nthreads)]
            with threading_helper.start_threads(threads):
                pass
        everything = sorted(c for s in seen for c in s)
        self.assertEqual(everything, [b"%015d\n" % i for i in range(count)])
        for s in seen:
            self.assertEqual(s, sorted(s))


    def test_detach_racing_io(self):
        # detach() racing writes and attribute reads may land on either side
        # of them; the only allowed failures are "detached"/"closed" errors
        # (AttributeError from _pyio, whose raw becomes None).
        detached_errors = (ValueError, AttributeError)
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        for _ in range(20):
            raw = self.FileIO(os_helper.TESTFN, "w")
            f = self.BufferedWriter(raw, 64)
            go = threading.Event()
            errors = []
            detached = []

            def writer():
                go.wait()
                for i in range(500):
                    try:
                        f.write(b"x" * (i % 100))
                    except detached_errors:
                        return

            def reader():
                go.wait()
                for _ in range(500):
                    try:
                        f.closed, f.name, f.fileno(), f.writable()
                    except detached_errors:
                        return

            def detacher():
                go.wait()
                try:
                    detached.append(f.detach())
                except ValueError as e:
                    errors.append(e)

            threads = ([threading.Thread(target=writer) for _ in range(3)]
                       + [threading.Thread(target=reader) for _ in range(3)]
                       + [threading.Thread(target=detacher)])
            with threading_helper.start_threads(threads):
                go.set()
            self.assertEqual(errors, [])
            # Closed only now: FileIO itself doesn't synchronize close()
            # with other threads using it.
            self.assertEqual(detached, [raw])
            raw.close()


class CConcurrentAccessTest(ConcurrentAccessTest, CTestCase):
    pass


class PyConcurrentAccessTest(ConcurrentAccessTest, PyTestCase):
    pass


class NibblerConcurrentAccessTest(NibblerMixin, ConcurrentAccessTest,
                                  CTestCase):
    pass


if __name__ == "__main__":
    unittest.main()

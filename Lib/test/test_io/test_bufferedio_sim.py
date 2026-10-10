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
is_nibbler, is_C and is_stock_C (see utils.py).
"""
import array
import errno
import glob
import os
import random
import select
import signal
import subprocess
import sys
import textwrap
import threading
import time
import unittest
import warnings

from test import support
from test.support import import_helper, os_helper, threading_helper
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

    def test_peek_never_reads_with_readahead(self):
        if not self.is_C:
            self.skipTest("_pyio's peek(n) tops up to min(n, buffer size)")
        # peek() returns the read-ahead when there is some, however short,
        # without a raw read, which could block (on a pipe, pickle.load()
        # peeks for more than is buffered); with none, one raw read.
        data = sample_data(1_000)
        raw = self.scripted_reader(data, [16, 16, 16])
        f = self.BufferedReader(raw, 16)
        self.assertEqual(f.read(10), data[:10])
        calls = raw.calls
        self.assertEqual(f.peek(10), data[10:16])
        self.assertEqual(f.peek(100), data[10:16])
        self.assertEqual(raw.calls, calls)
        self.assertEqual(f.read(6), data[10:16])
        peeked = f.peek(10)
        self.assertEqual(raw.calls, calls + 1)
        self.assertEqual(peeked, data[16:32])
        # At EOF: what there is.
        f = self.BufferedReader(self.scripted_reader(data[:12]), 16)
        self.assertEqual(f.read(10), data[:10])
        self.assertEqual(f.peek(10), data[10:12])

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

    def test_text_read_would_block_keeps_partial_char(self):
        if self.is_stock_C:
            self.skipTest("_io.TextIOWrapper is as upstream has it")
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

    def test_text_readline_error_keeps_partial_line(self):
        if self.is_stock_C:
            self.skipTest("_io.TextIOWrapper is as upstream has it")
        # gh-51571: a raw read that raises (such as a socket timeout) in the
        # middle of a line loses nothing: the next readline() returns the
        # whole line.
        data = "ab\xe9cd\nef".encode()
        raw = self.scripted_reader(data, [4, TimeoutError("timed out")])
        f = self.TextIOWrapper(self.BufferedReader(raw, 16), encoding="utf-8")
        self.assertRaises(TimeoutError, f.readline)
        self.assertEqual(f.readline(), "ab\xe9cd\n")
        self.assertEqual(f.readline(), "ef")

    def test_read_all_error_keeps_data(self):
        # read() of a raw stream with only RawIOBase.readall() keeps what
        # it read before a raw read raised.
        if not self.is_nibbler:
            self.skipTest("data read before a raw error is lost")
        data = sample_data(100)
        raw = self.scripted_reader(data, [30, 20, TimeoutError("timed out")])
        f = self.BufferedReader(raw, 16)
        self.assertEqual(f.read(5), data[:5])
        self.assertRaises(TimeoutError, f.read)
        self.assertEqual(f.read(), data[5:])

    def test_read_all_memory_error_keeps_data(self):
        # A MemoryError while read() puts the read-ahead and the rest of
        # the stream together loses neither: the next read() returns all.
        if not self.is_nibbler:
            self.skipTest("data is lost on MemoryError")
        if support.Py_GIL_DISABLED:
            # One failed allocation is retried there.
            self.skipTest("can't make one allocation fail")
        _testcapi = import_helper.import_module('_testcapi')
        data = sample_data(5_000)

        class PoppingRaw(self.RawIOBase):
            # Hands out prebuilt parts with pop(), which can't fail for lack
            # of memory once called: only the buffered layer can lose data.
            def __init__(self, parts):
                self.parts = parts[::-1]
            def readable(self):
                return True
            def readinto(self, b):
                part = self.parts.pop()
                b[:len(part)] = part
                return len(part)        # 16: a cached int
            def read(self, size=-1):
                # RawIOBase.readall() calls this.
                return self.parts.pop() if self.parts else b""

        class ReadAllRaw(PoppingRaw):
            # The rest comes in one piece.
            readall = PoppingRaw.read

        parts = [data[:16], data[16:1000], data[1000:3000], data[3000:]]
        raws = {
            "readall": lambda: ReadAllRaw([data[:16], data[16:]]),
            "read chunks": lambda: PoppingRaw(parts),
            # Seekable: positions count what was kept.
            "seekable": lambda: self.BytesIO(data),
        }
        for name, make_raw in raws.items():
            with self.subTest(raw=name):
                # Fail each allocation in turn (a few are retried).
                failures = 0
                for start in range(300):
                    f = self.BufferedReader(make_raw(), 16)
                    self.assertEqual(f.read(5), data[:5])
                    try:
                        got = _testcapi.call_with_nomemory(start, start + 1,
                                                           f.read)
                    except MemoryError:
                        failures += 1
                        got = b""
                        if name == "seekable":
                            self.assertEqual(f.tell(), 5)
                            f.seek(-2, 1)
                            self.assertEqual(f.read(2), data[3:5])
                    self.assertEqual(got + f.read(), data[5:], start)
                self.assertGreater(failures, 0)

    def test_write_memory_error_after_partial_write(self):
        # write() wrote part of its data, then the raw stream would block
        # and keeping the rest fails for lack of memory: the MemoryError
        # says how much was written.
        if not self.is_nibbler:
            self.skipTest("no characters_written")
        _testcapi = import_helper.import_module('_testcapi')

        class Raw(self.RawIOBase):
            calls = 0
            def writable(self):
                return True
            def write(self, b):
                self.calls += 1
                if self.calls == 1:
                    return 60
                _testcapi.set_nomemory(0, 1)
                return None

        f = self.BufferedWriter(Raw(), 16)
        try:
            f.write(bytearray(100))
        except MemoryError as exc:
            _testcapi.remove_mem_hooks()
            self.assertEqual(exc.characters_written, 60)
        except BlockingIOError as exc:
            # Keeping the rest didn't need memory after all.
            _testcapi.remove_mem_hooks()
            self.assertEqual(exc.characters_written, 76)
        finally:
            _testcapi.remove_mem_hooks()

    def test_fill_memory_error_keeps_raw_error(self):
        # A raw read raising, then keeping the partial line failing for
        # lack of memory: the raw error is the MemoryError's context.
        if not self.is_nibbler:
            self.skipTest("no partial line is kept")
        _testcapi = import_helper.import_module('_testcapi')

        class Raw(self.RawIOBase):
            def __init__(self, start):
                self.calls = 0
                self.start = start
            def readable(self):
                return True
            def readinto(self, b):
                self.calls += 1
                if self.calls == 1:
                    b[:12] = b'x' * 12
                    return 12
                exc = OSError("raw failed")
                # The start-th allocation fails: for some start, one
                # made to keep the partial line.
                _testcapi.set_nomemory(self.start, self.start + 1)
                raise exc

        # Only an allocation of the raise itself may lose the raw error:
        # every later MemoryError has it as context.
        lost = []
        for start in range(100):
            f = self.BufferedReader(Raw(start), 16)
            self.assertEqual(f.read(10), b'x' * 10)
            try:
                f.readline()
            except MemoryError as exc:
                _testcapi.remove_mem_hooks()
                if not isinstance(exc.__context__, OSError):
                    lost.append(start)
            except OSError:
                pass
            finally:
                _testcapi.remove_mem_hooks()
        self.assertLessEqual(len(lost), 1, lost)

    def test_readline_long_line_trickling_in_is_linear(self):
        # A line that arrives a little at a time, the raw stream blocking in
        # between, is kept by readline() (which returns None) until it is
        # whole: keeping it, and looking for its end, takes time linear in
        # its length, not quadratic.
        if not self.is_nibbler:
            self.skipTest("copies the partial line on each call")
        step = 100

        class Trickle(self.RawIOBase):
            def __init__(self, data):
                self.data = data
                self.pos = 0
                self.block = False
            def readable(self):
                return True
            def readinto(self, b):
                self.block = not self.block
                if self.block:
                    return None
                n = min(len(b), step, len(self.data) - self.pos)
                b[:n] = self.data[self.pos:self.pos + n]
                self.pos += n
                return n

        def read_line(size):
            line = b"x" * (size - 1) + b"\n"
            # A buffer the size of the line: the partial line is kept.
            f = self.BufferedReader(Trickle(line), size)
            start = time.perf_counter()
            while (got := f.readline()) is None:
                pass
            elapsed = time.perf_counter() - start
            self.assertEqual(got, line)
            return elapsed

        # 8 times longer: about 8 times slower if linear, 64 if quadratic.
        # (Without the garbage collector, whose passes cost more as the
        # heap grows.)
        with support.disable_gc():
            small = min(read_line(64 * 1024) for _ in range(3))
            large = min(read_line(512 * 1024) for _ in range(3))
        self.assertLess(large, 24 * small)

    def test_readline_after_seek_back_over_partial_line(self):
        # A readline() that kept a partial line (here because the raw
        # stream raised) remembers where it looked for the end of the
        # line; seeking back inside the read-ahead must not skip an end of
        # line before that.
        if not self.is_nibbler:
            self.skipTest("data read before a raw error is lost")
        data = b"ab\ncdefgh\nij\n"

        class Raw(self.RawIOBase):
            def __init__(self):
                self.pos = 0
                self.plan = [9, TimeoutError("timed out")]
            def readable(self):
                return True
            def seekable(self):
                return True
            def tell(self):
                return self.pos
            def seek(self, pos, whence=0):
                self.pos = pos if whence == 0 else self.pos + pos
                return self.pos
            def readinto(self, b):
                step = self.plan.pop(0) if self.plan else len(b)
                if isinstance(step, BaseException):
                    raise step
                chunk = data[self.pos:self.pos + min(step, len(b))]
                b[:len(chunk)] = chunk
                self.pos += len(chunk)
                return len(chunk)

        f = self.BufferedReader(Raw(), 64)
        self.assertEqual(f.readline(), b"ab\n")
        self.assertRaises(TimeoutError, f.readline)
        self.assertEqual(f.seek(0), 0)
        self.assertEqual(f.readline(), b"ab\n")
        self.assertEqual(f.readline(), b"cdefgh\n")
        self.assertEqual(f.readline(), b"ij\n")
        self.assertEqual(f.readline(), b"")

    def test_read_eintr_is_retried(self):
        if not self.is_C:
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

    def test_read_error_keeps_partial_data(self):
        if not self.is_nibbler:
            self.skipTest("data read before a raw error is lost")
        # gh-51571: a raw error (such as a socket timeout) in the middle of
        # a readline() or read(n) loses none of the data read before it.
        data = b"abcdefghij\n" + b"klm\n"

        def readinto(f):
            b = bytearray(len(data))
            return bytes(b[:f.readinto(b)])

        reads = {
            "readline": (lambda f: f.readline(), 11),
            "read": (lambda f: f.read(len(data)), len(data)),
            "readinto": (readinto, len(data)),
        }
        for name, (read, size) in reads.items():
            # Through the read-ahead, then directly into the result.
            for buffer_size in (64, 4):
                with self.subTest(read=name, buffer_size=buffer_size):
                    raw = self.scripted_reader(data, [8, TimeoutError()])
                    f = self.BufferedReader(raw, buffer_size)
                    self.assertRaises(TimeoutError, read, f)
                    self.assertEqual(read(f), data[:size])
                    self.assertEqual(f.read(), data[size:])

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

    def test_write_after_raw_closed(self):
        # Also once small writes went to the buffer without checks that
        # need the lock.
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        raw = self.FileIO(os_helper.TESTFN, "w")
        f = self.BufferedWriter(raw, 16)
        f.write(b"a")
        f.write(b"b")
        raw.close()
        msg = "write to closed file" if self.is_C else "closed file"
        with self.assertRaisesRegex(ValueError, msg):
            f.write(b"c")
        # The failed write left nothing queued.
        if hasattr(f, "_discard_writes"):
            self.assertEqual(f._discard_writes(), 2)

    def test_write_after_other_raw_closed(self):
        # Raw streams other than FileIO say whether they are closed when
        # asked with the lock: from then on, writes queued without it raise
        # too.
        raw = self.MockRawIO()
        f = self.BufferedWriter(raw, 16)
        f.write(b"a")
        f.write(b"b")
        raw.close()
        with self.assertRaises(ValueError):
            f.flush()
        with self.assertRaises(ValueError):
            f.write(b"c")

    def test_closed_follows_raw(self):
        # close() keeps the raw stream, which says whether it is closed:
        # closing it directly closes the buffered object, and close() after
        # that or twice is a no-op.
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        for unbuffered in (False, True):
            if unbuffered and not self.is_nibbler:
                continue
            size = 0 if unbuffered else 16
            with self.subTest(buffer_size=size):
                raw = self.FileIO(os_helper.TESTFN, "w+b")
                f = self.BufferedRandom(raw, size)
                f.write(b"abc")
                f.close()
                self.assertTrue(f.closed)
                self.assertIs(f.raw, raw)
                self.assertEqual(f.name, os_helper.TESTFN)
                self.assertEqual(f.mode, "wb+")
                f.close()
                with self.assertRaises(ValueError):
                    f.write(b"x")
                with self.assertRaises(ValueError):
                    f.read(1)

                raw = self.FileIO(os_helper.TESTFN, "r+b")
                f = self.BufferedRandom(raw, size)
                self.assertEqual(f.read(1), b"a")
                raw.close()
                self.assertTrue(f.closed)
                with self.assertRaises(ValueError):
                    f.write(b"x")
                f.close()
                self.assertTrue(f.closed)

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
        if not self.is_C:
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

    def test_size_zero_write_error_reports_written(self):
        if not self.is_nibbler:
            self.skipTest("buffer_size=0 not supported")
        data = sample_data(100)
        raw = self.scripted_writer([30, OSError(errno.EIO, "EIO")])
        f = self.BufferedWriter(raw, 0)
        with self.assertRaises(OSError) as cm:
            f.write(data)
        self.assertEqual(cm.exception.characters_written, 30)
        f.flush()
        self.assertEqual(bytes(raw.received), data[:30])

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
        if self.is_stock_C:
            self.skipTest("_io.TextIOWrapper is as upstream has it")
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
        if not self.is_nibbler:
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

    def test_size_zero_readline_unsupported(self):
        self.check_buffer_size_zero()
        data = sample_data(100)
        raw = self.scripted_reader(data)
        f = self.BufferedReader(raw, 0)
        # Finding the end of the line would mean reading past it.
        self.assertRaises(self.UnsupportedOperation, f.readline)
        self.assertRaises(self.UnsupportedOperation, f.readline, 10)
        self.assertRaises(self.UnsupportedOperation, next, f)
        with self.assertRaises(self.UnsupportedOperation):
            for line in f:
                pass
        self.assertRaises(self.UnsupportedOperation, f.readlines)
        self.assertEqual(raw.calls, 0)
        self.assertEqual(f.read(), data)

    def test_size_zero_read1(self):
        self.check_buffer_size_zero()
        data = sample_data(1_000)
        raw = self.scripted_reader(data, [5, 3])
        f = self.BufferedReader(raw, 0)
        # One raw read each, of no more than asked for.
        self.assertEqual(f.read1(10), data[:5])
        self.assertEqual(f.read1(2), data[5:7])
        buf = bytearray(4)
        self.assertEqual(f.readinto1(buf), 4)
        self.assertEqual(buf, data[7:11])
        self.assertEqual(raw.calls, 3)
        self.assertEqual(raw.pos, 11)
        # Without a size: one raw read of some bytes.
        self.assertEqual(f.read1(), data[11:])
        self.assertEqual(f.read1(), b"")

    def test_size_zero_peek_unsupported(self):
        self.check_buffer_size_zero()
        data = sample_data(100)
        raw = self.scripted_reader(data)
        f = self.BufferedReader(raw, 0)
        self.assertRaises(self.UnsupportedOperation, f.peek)
        self.assertRaises(self.UnsupportedOperation, f.peek, 10)
        self.assertEqual(raw.calls, 0)
        self.assertEqual(f.read(), data)

    def test_size_zero_write_would_block(self):
        self.check_buffer_size_zero()
        raw = self.scripted_writer([4, 3, None])
        f = self.BufferedWriter(raw, 0)
        with self.assertRaises(BlockingIOError) as cm:
            f.write(b"0123456789")
        self.assertEqual(cm.exception.characters_written, 7)
        self.assertEqual(bytes(raw.received), b"0123456")
        # Nothing was kept to write later.
        f.flush()
        self.assertEqual(raw.calls, 3)
        self.assertEqual(f.write(b"789"), 3)
        self.assertEqual(bytes(raw.received), b"0123456789")

    def test_size_zero_empty_write(self):
        # gh-148773: an empty write makes no raw call (a tty may take a
        # write of 0 bytes as a hangup).
        self.check_buffer_size_zero()
        raw = self.scripted_writer()
        f = self.BufferedWriter(raw, 0)
        self.assertEqual(f.write(b""), 0)
        self.assertEqual(f.write(bytearray()), 0)
        f.flush()
        self.assertEqual(raw.calls, 0)
        self.assertEqual(f.write(b"x"), 1)
        self.assertEqual(raw.calls, 1)

    def test_size_zero_write_no_progress(self):
        # gh-158414: a raw write() returning 0 is not retried forever.
        self.check_buffer_size_zero()
        raw = self.scripted_writer([3, 0, 0])
        f = self.BufferedWriter(raw, 0)
        self.assertRaises(OSError, f.write, b"0123456789")
        self.assertEqual(raw.calls, 2)
        self.assertEqual(bytes(raw.received), b"012")

    def test_size_zero_random_unseekable(self):
        # Unbuffered, BufferedRandom needs no seeking: it works over a
        # read-write stream that can't seek, such as a terminal or socket,
        # like the FileIO that open(fd, "r+b", buffering=0) used to return.
        self.check_buffer_size_zero()
        Reader = make_scripted_reader(self.RawIOBase)
        class Duplex(Reader):
            def writable(self):
                return True
            def seekable(self):
                return False
            def write(self, b):
                self.received += b
                return len(b)
        raw = Duplex(b"hello world")
        raw.received = bytearray()
        f = self.BufferedRandom(raw, 0)
        self.assertEqual(f.read(5), b"hello")
        self.assertEqual(f.write(b"abc"), 3)
        self.assertEqual(f.read(), b" world")
        self.assertEqual(f.write(b"de"), 2)
        self.assertEqual(bytes(raw.received), b"abcde")
        self.assertRaises(self.UnsupportedOperation, f.seek, 0)

    @unittest.skipUnless(hasattr(os, "openpty"), "requires openpty")
    def test_size_zero_random_pty(self):
        self.check_buffer_size_zero()
        master, slave = os.openpty()
        with self.FileIO(master, "r+b") as m_raw, \
             self.FileIO(slave, "r+b") as s_raw:
            m = self.BufferedRandom(m_raw, 0)
            s = self.BufferedRandom(s_raw, 0)
            self.assertEqual(s.write(b"ping\n"), 5)
            self.assertEqual(m.read(5), b"ping\r\n"[:5])

    def test_size_zero_seek_tell(self):
        self.check_buffer_size_zero()
        data = sample_data(500)
        raw = make_memory_raw(self.RawIOBase)(data, random.Random(15), 7)
        f = self.BufferedRandom(raw, 0)
        expected = bytearray(data)
        self.assertEqual(f.read(10), data[:10])
        self.assertEqual((f.tell(), raw.pos), (10, 10))
        self.assertEqual(f.write(b"X" * 20), 20)
        expected[10:30] = b"X" * 20
        self.assertEqual((f.tell(), raw.pos), (30, 30))
        self.assertEqual(f.seek(5), 5)
        self.assertEqual(f.read(30), bytes(expected[5:35]))
        self.assertEqual(f.seek(-3, 1), 32)
        self.assertRaises(self.UnsupportedOperation, f.readline)
        self.assertEqual(f.read(10), bytes(expected[32:42]))
        self.assertEqual(f.tell(), raw.pos)
        self.assertEqual(f.seek(-5, 2), 495)
        self.assertEqual(f.write(b"YYYYYYY"), 7)
        expected[495:] = b"YYYYYYY"
        self.assertEqual(f.tell(), 502)
        self.assertEqual(f.read(), b"")
        self.assertEqual(f.seek(0), 0)
        self.assertEqual(f.read(), bytes(expected))
        self.assertEqual(bytes(raw.buf), bytes(expected))


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


# --- Text over a buffered object ------------------------------------------------

class TextTest:
    """TextIOWrapper over a buffered object."""

    def setUp(self):
        super().setUp()
        if not self.is_nibbler:
            self.skipTest("text keeps bytes of its own")

    def test_text_and_buffer_writes_keep_order(self):
        # gh-52203: sys.stdout.write() then sys.stdout.buffer.write() come
        # out in that order.
        for enc in ("utf-8", "latin-1"):
            with self.subTest(encoding=enc):
                raw = self.BytesIO()
                t = self.TextIOWrapper(self.BufferedWriter(raw), encoding=enc)
                t.write("unicode ")
                t.buffer.write(b"bytes ")
                t.write("\xe9 ")
                t.buffer.write(b"more")
                t.flush()
                self.assertEqual(raw.getvalue(),
                                 b"unicode bytes " + "\xe9".encode(enc)
                                 + b" more")

    def test_text_reads_use_buffer_size(self):
        # gh-153656: text reads make raw reads of the buffer size, not of
        # TextIOWrapper's chunk size (8192).
        Reader = make_scripted_reader(self.RawIOBase)
        class RecordingReader(Reader):
            def readinto(self, b):
                self.sizes.append(len(b))
                return super().readinto(b)
        data = b"line\n" * 50_000
        for encoding in ("utf-8", "latin-1"):
            with self.subTest(encoding=encoding):
                raw = RecordingReader(data)
                raw.sizes = []
                t = self.TextIOWrapper(self.BufferedReader(raw, 100_000),
                                       encoding=encoding)
                for _ in range(1000):
                    self.assertEqual(t.readline(), "line\n")
                self.assertEqual(raw.sizes, [100_000])


class CTextTest(TextTest, CTestCase):
    pass


class PyTextTest(TextTest, PyTestCase):
    pass


class NibblerTextTest(NibblerMixin, TextTest, CTestCase):
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
        if not self.is_nibbler:
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

    def test_raw_keeping_read_view(self):
        if not self.is_nibbler:
            self.skipTest("buffer memory is reused under raw views")
        # gh-60198, gh-157075: a raw stream that keeps the views given to
        # readinto(), and views made from them, and writes through them
        # later, crashes nothing and changes no bytes already returned.
        class StashingRaw(self.RawIOBase):
            def __init__(self, data):
                self.data = data
                self.pos = 0
                self.views = []

            def readable(self):
                return True

            def readinto(self, b):
                self.views.append(b)
                if len(self.views) % 2:
                    self.views.append(b[:])
                n = min(len(b), len(self.data) - self.pos)
                b[:n] = self.data[self.pos:self.pos + n]
                self.pos += n
                return n

            def scribble(self):
                for view in self.views:
                    try:
                        view[:] = b"\xff" * len(view)
                    except ValueError:
                        pass  # released

        data = sample_data(5_000)
        raw = StashingRaw(data)
        f = self.BufferedReader(raw, 64)
        got = []
        for read in (lambda: f.read(10), lambda: f.read1(30),
                     lambda: f.read(200), lambda: f.peek(5)[:5],
                     lambda: f.read(5), lambda: f.read1(100)):
            got.append(read())
            copies = [bytes(b) for b in got]
            raw.scribble()
            self.assertEqual(got, copies)
        read = got[:3] + got[4:]  # peek() doesn't consume
        pos = sum(map(len, read))
        self.assertEqual(b"".join(read), data[:pos])
        # readinto() hands the raw stream the caller's own memory: a view
        # it keeps writes there later, but keeps that memory alive.
        buf = bytearray(300)
        n = f.readinto(buf)
        self.assertEqual(bytes(buf[:n]), data[pos:pos + n])
        raw.scribble()
        rest = f.read()
        raw.scribble()
        self.assertEqual(rest, data[pos + n:])
        del f, buf
        support.gc_collect()
        raw.scribble()

    def test_readinto_reads_into_callers_buffer(self):
        # readinto() of at least a buffer's worth gives the raw stream the
        # caller's own memory to read into, without a copy.
        ctypes = import_helper.import_module('ctypes')

        def address(b):
            c = ctypes.c_char.from_buffer(b)
            try:
                return ctypes.addressof(c)
            finally:
                del c

        class AddressRaw(self.RawIOBase):
            def __init__(self):
                self.addresses = []

            def readable(self):
                return True

            def readinto(self, b):
                self.addresses.append(address(b))
                b[:] = b"x" * len(b)
                return len(b)

        raw = AddressRaw()
        f = self.BufferedReader(raw, 16)
        for buf in (bytearray(100), memoryview(bytearray(100)),
                    array.array('b', bytes(100))):
            with self.subTest(type(buf).__name__):
                raw.addresses.clear()
                self.assertEqual(f.readinto(buf), 100)
                self.assertEqual(raw.addresses, [address(buf)])
                self.assertEqual(bytes(buf), b"x" * 100)

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


# --- Writing out without the lock ---------------------------------------------

@threading_helper.requires_working_threading()
class WriteOutTest:
    """write() and flush() write out without holding the lock: other
    threads can queue writes meanwhile, and nothing else interleaves."""

    def setUp(self):
        super().setUp()
        if not self.is_nibbler:
            self.skipTest("the lock is held across raw writes")

    def gated(self, buffer_size=16):
        # A raw stream whose writes from `blocked_thread` wait for
        # `release`, after setting `entered`.
        test = self

        class Raw(self.RawIOBase):
            blocked_thread = None
            on_write = None
            entered = threading.Event()
            release = threading.Event()
            out = bytearray()

            def writable(self):
                return True

            def seekable(self):
                return True

            def tell(self):
                return len(self.out)

            def seek(self, pos, whence=0):
                return len(self.out)

            def write(self, b):
                if threading.current_thread() is self.blocked_thread:
                    self.entered.set()
                    test.assertTrue(self.release.wait(support.SHORT_TIMEOUT))
                if self.on_write is not None:
                    on_write, self.on_write = self.on_write, None
                    on_write()
                self.out += b
                return len(b)

        raw = Raw()
        return self.BufferedWriter(raw, buffer_size), raw

    def start_blocked_write(self, f, raw, data):
        t = threading.Thread(target=f.write, args=(data,))
        raw.blocked_thread = t
        t.start()
        self.assertTrue(raw.entered.wait(support.SHORT_TIMEOUT))
        self.addCleanup(t.join)
        self.addCleanup(raw.release.set)
        return t

    def test_write_while_other_thread_in_raw_write(self):
        f, raw = self.gated()
        t = self.start_blocked_write(f, raw, b"a" * 20)
        f.write(b"bbbb")  # fits: queued without waiting
        self.assertTrue(t.is_alive())
        raw.release.set()
        t.join()
        f.flush()
        self.assertEqual(bytes(raw.out), b"a" * 20 + b"bbbb")

    def check_waits_for_write_out(self, op):
        f, raw = self.gated()
        t = self.start_blocked_write(f, raw, b"a" * 20)
        f.write(b"bbbb")
        results = []
        other = threading.Thread(target=lambda: results.append(op(f)))
        other.start()
        raw.release.set()
        t.join()
        other.join()
        return f, raw, results

    def test_tell_waits_for_write_out(self):
        f, raw, results = self.check_waits_for_write_out(
            lambda f: f.tell())
        self.assertEqual(results, [24])

    def test_close_waits_for_write_out(self):
        # Writes queued during the write out are written by close().
        f, raw, results = self.check_waits_for_write_out(
            lambda f: f.close())
        self.assertTrue(f.closed)
        self.assertEqual(bytes(raw.out), b"a" * 20 + b"bbbb")

    def test_raw_write_calling_write(self):
        f, raw = self.gated()
        raw.on_write = lambda: f.write(b"c")
        f.write(b"a" * 20)
        f.flush()
        self.assertEqual(bytes(raw.out), b"a" * 20 + b"c")

    def test_raw_write_calling_large_write(self):
        if not self.is_nibbler:
            self.skipTest("raises RuntimeError")
        # gh-118143: a signal handler printing while the raw write it
        # interrupted runs, with more than the buffer holds.  The data is
        # kept for the write out, or the next flush, to write.
        for op in ("write", "flush"):
            with self.subTest(op=op):
                f, raw = self.gated()
                raw.on_write = lambda: f.write(b"c" * 40)
                if op == "write":
                    f.write(b"a" * 20)
                else:
                    f.write(b"a" * 10)
                    f.flush()
                f.flush()
                self.assertEqual(bytes(raw.out),
                                 b"a" * (20 if op == "write" else 10)
                                 + b"c" * 40)

    @unittest.skipUnless(hasattr(signal, "setitimer"), "requires setitimer")
    def test_signal_handler_printing_during_writes(self):
        if not self.is_nibbler:
            self.skipTest("raises RuntimeError")
        # gh-112608: a signal handler that print()s to a file while the
        # main code writes to it, with signals arriving during write outs
        # (gh-118143).  Its text is queued, never "reentrant call".
        with self.open(os.devnull, "w", encoding="ascii") as f:
            def handler(*args):
                print("handler", file=f)
            old = signal.signal(signal.SIGALRM, handler)
            self.addCleanup(signal.signal, signal.SIGALRM, old)
            signal.setitimer(signal.ITIMER_REAL, 0.0005, 0.0005)
            try:
                deadline = time.monotonic() + 0.5
                while time.monotonic() < deadline:
                    print("loop" * 50, file=f)
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)

    def test_fileio_write_while_other_thread_in_raw_write(self):
        # With a FileIO raw stream (where writes may be queued without the
        # lock), writes that fit are queued while another thread's write out
        # blocks on a full pipe, and written after it.
        r, w = os.pipe()
        self.addCleanup(os.close, r)
        f = self.open(w, "wb", buffering=64)
        self.addCleanup(f.close)
        big = b"a" * (1 << 20)
        t = threading.Thread(target=f.write, args=(big,))
        t.start()
        self.addCleanup(t.join)
        received = bytearray(os.read(r, 1))
        records = [b"rec%d\n" % i for i in range(8)]
        writer = threading.Thread(target=lambda: [f.write(rec)
                                                  for rec in records])
        writer.start()
        writer.join(support.SHORT_TIMEOUT)
        self.assertFalse(writer.is_alive())
        expected = big + b"".join(records)
        def drain():
            while chunk := os.read(r, 1 << 16):
                received.extend(chunk)
        reader = threading.Thread(target=drain)
        reader.start()
        t.join()
        f.close()
        reader.join()
        self.assertEqual(bytes(received), expected)

    def test_raw_write_calling_flush(self):
        f, raw = self.gated()
        raw.on_write = f.flush
        with self.assertRaisesRegex(RuntimeError, "reentrant"):
            f.write(b"a" * 20)


class CWriteOutTest(WriteOutTest, CTestCase):
    pass


class NibblerWriteOutTest(NibblerMixin, WriteOutTest, CTestCase):
    pass


# --- Reentrant calls -----------------------------------------------------------

class ReentrantCallTest:
    """Code run by a buffered method (a raw stream method, the __index__()
    of an argument) closing or detaching the object it runs for."""

    def detaching(self, tp, raw, buffer_size):
        # A tp over raw whose detach() is called from raw methods through
        # fire(), once; flush() then does nothing, so detach() goes
        # straight to the buffered object's lock.
        class Detaching(tp):
            detach_error = None
            fired = firing = False

            def flush(self):
                if not self.firing:
                    super().flush()

            def fire(self):
                if self.fired:
                    return
                self.fired = self.firing = True
                try:
                    self.detach()
                except Exception as exc:
                    self.detach_error = exc
                finally:
                    self.firing = False

        f = Detaching(raw, buffer_size)
        raw.owner = f
        return f

    def assertDetachRefused(self, f, raw):
        self.assertIsInstance(f.detach_error, RuntimeError)
        self.assertIs(f.raw, raw)

    def test_close_with_flush_detaching(self):
        # gh-154997
        class Detaching(self.BufferedWriter):
            armed = True

            def flush(self):
                if self.armed:
                    self.armed = False
                    self.detach()

        f = Detaching(self.BytesIO())
        self.assertRaises(ValueError, f.close)
        self.assertIsNone(f.raw)

    def test_raw_readinto_detaching(self):
        # gh-154997
        class Raw(self.RawIOBase):
            def readable(self):
                return True

            def readinto(self, b):
                self.owner.fire()
                b[0:1] = b"a"
                return 1

        raw = Raw()
        f = self.detaching(self.BufferedReader, raw, 4)
        self.assertEqual(f.read(64), b"a" * 64)
        self.assertDetachRefused(f, raw)

    def test_raw_read_all_detaching(self):
        # gh-154997
        class Raw(self.RawIOBase):
            def readable(self):
                return True

            def readall(self):
                self.owner.fire()
                return b"abcdef"

        raw = Raw()
        f = self.detaching(self.BufferedReader, raw, 4)
        self.assertEqual(f.read(), b"abcdef")
        self.assertDetachRefused(f, raw)

    def test_raw_write_detaching(self):
        # gh-154997
        class Raw(self.RawIOBase):
            out = bytearray()

            def writable(self):
                return True

            def write(self, b):
                self.owner.fire()
                self.out += bytes(b)[:1]
                return 1

        raw = Raw()
        f = self.detaching(self.BufferedWriter, raw, 4)
        data = b"0123456789abcdef"
        self.assertEqual(f.write(data), len(data))
        self.assertDetachRefused(f, raw)
        f.close()
        self.assertEqual(raw.out, data)

    def seekable_raw(self, method):
        # A seekable raw stream whose `method` detaches its owner.
        class Raw(self.RawIOBase):
            out = bytearray()

            def readable(self):
                return True

            def writable(self):
                return True

            def seekable(self):
                return True

            def _fire(self, name):
                if name == method:
                    self.owner.fire()

            def readinto(self, b):
                self._fire("readinto")
                return 0

            def write(self, b):
                self._fire("write")
                self.out += b
                return len(b)

            def seek(self, pos, whence=0):
                self._fire("seek")
                return 0

            def tell(self):
                self._fire("tell")
                return len(self.out)

            def truncate(self, pos=None):
                self._fire("truncate")
                return 0

        return Raw()

    def test_raw_calls_detaching(self):
        # gh-154997: truncate() and seek() go on with the raw stream after
        # calling raw methods.
        for tp in (self.BufferedWriter, self.BufferedRandom):
            for method in ("write", "truncate", "tell", "seek"):
                with self.subTest(tp=tp.__name__, method=method):
                    raw = self.seekable_raw(method)
                    f = self.detaching(tp, raw, 64)
                    f.write(b"012")
                    f.truncate(1)
                    f.write(b"34")
                    self.assertEqual(f.tell(), 5)
                    f.seek(0)
                    self.assertDetachRefused(f, raw)
                    f.close()
                    self.assertEqual(raw.out, b"01234")

    def test_seek_target_detaching(self):
        # gh-154997: seek() either converts its target with the object in
        # use, or finds it detached afterwards.
        raw = self.seekable_raw(None)
        f = self.detaching(self.BufferedRandom, raw, 64)
        f.write(b"012")

        class Target:
            def __index__(self):
                f.fire()
                return 0

        try:
            self.assertEqual(f.seek(Target()), 0)
        except ValueError:
            # Detached before seeking.
            self.assertIsNone(f.detach_error)
            self.assertIsNone(f.raw)
        else:
            self.assertDetachRefused(f, raw)
            f.close()
            self.assertEqual(raw.out, b"012")

    def test_seek_target_closing(self):
        if not self.is_nibbler:
            self.skipTest("crashes (gh-143375)")
        # gh-143375: the target closing the object while seek() has a
        # partly written buffer to write out.
        class Raw(self.RawIOBase):
            calls = 0
            out = bytearray()

            def writable(self):
                return True

            def seekable(self):
                return True

            def seek(self, pos, whence=0):
                return 0

            def write(self, b):
                self.calls += 1
                if self.calls == 2:
                    raise BlockingIOError
                n = len(b) - 1 if self.calls == 1 else len(b)
                self.out += bytes(b)[:n]
                return n

        raw = Raw()
        f = self.BufferedWriter(raw)
        f.write(b"ABCD")

        class Target:
            def __index__(self):
                try:
                    f.close()
                except RuntimeError:
                    pass
                return 0

        # The target is converted before seek() takes the lock, so the
        # close() in it runs: writing out would block, and the rest of the
        # buffer is discarded (with a warning).
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with self.assertRaises(BlockingIOError):
                f.seek(Target())
        self.assertTrue(f.closed)
        f.close()
        self.assertEqual(raw.out, b"ABC")


class CReentrantCallTest(ReentrantCallTest, CTestCase):
    pass


class NibblerReentrantCallTest(NibblerMixin, ReentrantCallTest, CTestCase):
    pass


# --- Locks that can never be released --------------------------------------

# A raw stream whose calls named in GATED block forever when made from a
# thread other than the main one, after setting `entered`.  Writes go to
# stdout.
GATED_RAW = """if 1:
    import io, os
    from threading import current_thread, Event, main_thread

    entered = Event()

    class GatedRaw(io.RawIOBase):
        name = '<gated>'

        def readable(self):
            return True

        def writable(self):
            return True

        def seekable(self):
            return True

        def _gate(self, method):
            if method in GATED and current_thread() is not main_thread():
                entered.set()
                Event().wait()

        def write(self, b):
            self._gate('write')
            return os.write(1, b)

        def readinto(self, b):
            self._gate('readinto')
            return 0

        def seek(self, pos, whence=0):
            self._gate('seek')
            return 0
"""


class LockReleaseTest:
    """No buffered call waits forever for a holder that can never release
    the lock: a daemon thread at shutdown, or a thread gone in a fork."""

    def run_child(self, code):
        if not self.is_nibbler:
            self.skipTest("only _io._nibbler takes over such locks")
        code = ("from _io._nibbler import BufferedRandom\n"
                + GATED_RAW + textwrap.dedent(code))
        # The timeout only stops a hang from blocking the test run.
        proc = subprocess.run([sys.executable, "-I", "-c", code],
                              capture_output=True,
                              timeout=support.SHORT_TIMEOUT)
        return proc.returncode, proc.stdout, proc.stderr.decode()

    def check_shutdown(self, daemon_op, waiters=0):
        # A daemon thread blocks in a raw call holding the lock (others
        # wait for it), so at shutdown it can never release it: flushing
        # sys.stdout while finalizing takes it over.  (The main thread
        # writes first: a text write now waits for the lock, so made at
        # exit before finalizing it would wait forever, like a buffered
        # write.)
        code = f"""
            import atexit, sys
            from threading import Thread

            GATED = {{'write', 'readinto', 'seek'}}
            f = io.TextIOWrapper(BufferedRandom(GatedRaw()), encoding='ascii')
            sys.stdout = f

            def holder():
                {daemon_op}

            def waiter():
                f.buffer.flush()

            @atexit.register
            def block_at_exit():
                f.write('!')
                f.flush()
                Thread(target=holder, daemon=True).start()
                entered.wait()
                for _ in range({waiters}):
                    Thread(target=waiter, daemon=True).start()
            """
        self.assertEqual(self.run_child(code), (0, b"!", ""))

    @threading_helper.requires_working_threading()
    def test_shutdown_holder_in_raw_write(self):
        self.check_shutdown("f.write('.'); f.flush()")

    @threading_helper.requires_working_threading()
    def test_shutdown_holder_in_raw_readinto(self):
        self.check_shutdown("f.buffer.read(1)")

    @threading_helper.requires_working_threading()
    def test_shutdown_holder_in_raw_seek(self):
        self.check_shutdown("f.buffer.seek(1)")

    @threading_helper.requires_working_threading()
    def test_shutdown_with_threads_waiting(self):
        self.check_shutdown("f.write('.'); f.flush()", waiters=3)

    @threading_helper.requires_working_threading()
    def test_shutdown_lock_handed_on_during_raw_write(self):
        # At exit the flush of sys.stdout takes the lock over from a daemon
        # thread blocked holding it (in raw.closed), and releases it around
        # its raw write: a daemon thread waiting for the lock is handed it,
        # and blocks as it attaches.  Taking the lock again after the raw
        # write takes it over once more.
        code = """
            import sys, time
            from threading import Thread, current_thread

            GATED = set()

            class Raw(GatedRaw):
                @property
                def closed(self):
                    if current_thread() is not main_thread():
                        entered.set()
                        Event().wait()
                    return False

            f = BufferedRandom(Raw())
            f.write(b'!')
            sys.stdout = f
            # Writes this large take the lock, and check raw.closed.
            Thread(target=f.write, args=(b'h' * 600,), daemon=True).start()
            entered.wait()
            Thread(target=f.write, args=(b'w' * 600,), daemon=True).start()
            time.sleep(0.1)
            """
        self.assertEqual(self.run_child(code), (0, b"!", ""))

    @threading_helper.requires_working_threading()
    def test_shutdown_with_daemons_writing(self):
        # Daemon threads write to sys.stdout's buffer as fast as they can
        # while the main thread exits.  (Not through the TextIOWrapper:
        # on free-threaded builds a daemon thread can hang holding its
        # critical section, which flushing sys.stdout at exit then waits
        # for.)  Finalizing takes the lock over only from
        # threads that can never run again (they hang as soon as they
        # attach), so the output stays whole: every line complete, each
        # thread's in order, and the main thread's last line written.
        if not self.is_nibbler:
            self.skipTest("only _io._nibbler takes over such locks")
        code = textwrap.dedent("""
            import sys, threading
            started = threading.Barrier(5)
            def daemon(i):
                started.wait()
                n = 0
                while True:
                    sys.stdout.buffer.write(b"d%d:%08d\\n" % (i, n))
                    n += 1
                    if n % 7 == 0:
                        sys.stdout.buffer.flush()
            for i in range(4):
                threading.Thread(target=daemon, args=(i,), daemon=True).start()
            started.wait()
            sys.stdout.buffer.write(b"main:end\\n")
            """)
        env = dict(os.environ, _PYTHON_IO_DEFAULT_IMPL="_nibbler")
        for _ in range(5):
            proc = subprocess.run([sys.executable, "-c", code], env=env,
                                  capture_output=True,
                                  timeout=support.SHORT_TIMEOUT)
            self.assertEqual((proc.returncode, proc.stderr), (0, b""))
            lines = proc.stdout.decode().split("\n")
            self.assertEqual(lines.pop(), "")
            self.assertIn("main:end", lines)
            last = {}
            for line in lines:
                if line == "main:end":
                    continue
                self.assertRegex(line, r"\Ad[0-3]:\d{8}\Z")
                t, n = line[1], int(line[3:])
                self.assertGreater(n, last.get(t, -1))
                last[t] = n

    @threading_helper.requires_working_threading()
    def test_shutdown_takeover_in_reentrant_call(self):
        # While finalizing, a call made with the lock held (from raw.closed
        # here) takes the I/O role over from a daemon thread blocked writing
        # out, but can't have the lock, and raises.  The bytes in flight
        # given to the gone thread are dropped by the next holder of both.
        code = """
            import sys
            from threading import Thread

            GATED = {'write'}

            class Raw(GatedRaw):
                calls = 0

                @property
                def closed(self, sys=sys):
                    if sys.is_finalizing() and not self.calls:
                        self.calls += 1
                        try:
                            f.tell()
                        except RuntimeError:
                            os.write(1, b'reentrant ')
                    return False

            f = BufferedRandom(Raw(), 16)

            class Out:
                def write(self, s):
                    return len(s)

                def flush(self, f=f, sys=sys):
                    if sys.is_finalizing():
                        f.write(b'late')
                        f.tell()
                        f.flush()

            sys.stdout = Out()

            def holder():
                f.write(b'D' * 10)
                f.flush()

            Thread(target=holder, daemon=True).start()
            entered.wait()
            """
        self.assertEqual(self.run_child(code), (0, b"reentrant late", ""))

    def check_fork(self, gated, holder_op):
        code = f"""
            import warnings
            from threading import Thread
            warnings.simplefilter('ignore', DeprecationWarning)

            GATED = {{{gated!r}}}
            f = BufferedRandom(GatedRaw())

            def holder():
                {holder_op}

            Thread(target=holder, daemon=True).start()
            entered.wait()
            pid = os.fork()
            if pid == 0:
                f.write(b'child ')
                f.flush()
                os._exit(0)
            status = os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
            os.write(1, b'exit %d' % status)
            """
        self.assertEqual(self.run_child(code), (0, b"child exit 0", ""))

    @threading_helper.requires_working_threading()
    @support.requires_fork()
    def test_fork_while_other_thread_holds_lock(self):
        # The gone thread holds the lock, in a raw seek().
        self.check_fork('seek', "f.seek(1)")

    @threading_helper.requires_working_threading()
    @support.requires_fork()
    def test_fork_while_other_thread_writes_out(self):
        # The gone thread holds the I/O role, in a raw write() made without
        # the lock.
        self.check_fork('write', "f.write(b'.'); f.flush()")

    @threading_helper.requires_working_threading()
    @support.requires_fork()
    def test_fork_with_earlier_after_fork_hook(self):
        # The locks are released before any Python after-fork hook runs,
        # also one registered before the first buffered object was made.
        code = """
            import signal, warnings
            from threading import Thread
            warnings.simplefilter('ignore', DeprecationWarning)

            GATED = {'readinto'}

            def child_hook():
                signal.alarm(10)    # in case it hangs
                os.write(1, b'tell %d ' % f.tell())

            os.register_at_fork(after_in_child=child_hook)
            f = BufferedRandom(GatedRaw())
            Thread(target=f.read, args=(1,), daemon=True).start()
            entered.wait()
            pid = os.fork()
            if pid == 0:
                os._exit(0)
            status = os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
            os.write(1, b'exit %d' % status)
            """
        self.assertEqual(self.run_child(code), (0, b"tell 0 exit 0", ""))

    @threading_helper.requires_working_threading()
    @support.requires_fork()
    def test_fork_while_other_thread_writes_out_to_fileio(self):
        # The gone thread writes out to a FileIO without the lock, which
        # leaves the writing end open: the child drops the bytes in flight
        # with the end held, so that its lock-free writes and its next
        # holds of the lock see consistent morsels.
        code = """
            import threading, time, warnings
            from _io._nibbler import BufferedWriter
            warnings.simplefilter('ignore', DeprecationWarning)

            r, w = os.pipe()
            f = BufferedWriter(io.FileIO(w, 'w', closefd=False), 8192)
            f.write(b'a' * 100)     # opens the writing end
            f.write(b'b' * 100)     # lock-free
            os.set_blocking(w, False)
            try:
                while True:
                    os.write(w, b'z' * 4096)
            except BlockingIOError:
                pass
            os.set_blocking(w, True)
            # Past the buffer size: writes out, and blocks on the full pipe.
            threading.Thread(target=f.write, args=(b'x' * 10000,),
                             daemon=True).start()
            time.sleep(0.2)
            pid = os.fork()
            if pid == 0:
                f.write(b'y' * 10)  # lock-free
                os.set_blocking(r, False)
                try:
                    while os.read(r, 65536):
                        pass
                except BlockingIOError:
                    pass
                f.flush()
                os._exit(0)
            status = os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
            os.write(1, b'exit %d' % status)
            os.set_blocking(r, False)
            try:
                while os.read(r, 65536):
                    pass
            except BlockingIOError:
                pass
            """
        self.assertEqual(self.run_child(code), (0, b"exit 0", ""))

    @threading_helper.requires_working_threading()
    @support.requires_fork()
    def test_fork_while_other_thread_takes_lock(self):
        # A thread waiting for the lock is handed it while detached, and
        # waits to attach again (for the GIL, or for the world stopped by
        # the fork) when the main thread forks: it never got to record
        # itself as the holder, and is gone in the child.  The timing is
        # not controlled, so try many times.
        code = """
            import sys, threading, time, warnings
            warnings.simplefilter('ignore', DeprecationWarning)

            GATED = set()

            class Raw(GatedRaw):
                gate = None

                def write(self, b):
                    return len(b)

                def seek(self, pos, whence=0):
                    gate, self.gate = self.gate, None
                    if gate is not None:
                        entered.set()
                        gate.wait()
                    return 0

            hangs = 0
            for _ in range(50):
                if hangs:
                    break
                raw = Raw()
                gate = raw.gate = threading.Event()
                entered.clear()
                f = BufferedRandom(raw)
                holder = threading.Thread(target=f.seek, args=(1,))
                holder.start()
                entered.wait()
                waiter = threading.Thread(target=f.tell)
                waiter.start()
                time.sleep(0.002)
                # The holder releases the lock, which the waiter takes.
                gate.set()
                for _ in range(5):
                    time.sleep(0)
                pid = os.fork()
                if pid == 0:
                    f.write(b'.')
                    f.flush()
                    os._exit(0)
                deadline = time.monotonic() + 5
                while not os.waitpid(pid, os.WNOHANG)[0]:
                    if time.monotonic() > deadline:
                        os.kill(pid, 9)
                        os.waitpid(pid, 0)
                        hangs += 1
                        break
                    time.sleep(0.001)
                holder.join()
                waiter.join()
            sys.stdout.write(f'hangs {hangs}')
            """
        self.assertEqual(self.run_child(code), (0, b"hangs 0", ""))

    @threading_helper.requires_working_threading()
    @unittest.skipUnless(hasattr(signal, "pthread_kill"),
                         "requires signal.pthread_kill")
    def test_signal_interrupts_lock_wait(self):
        code = """
            import signal
            from threading import Event, Thread, main_thread

            GATED = {'write'}
            f = BufferedRandom(GatedRaw())
            waiting = False

            class Interrupted(Exception):
                pass

            def handler(signum, frame):
                if waiting:
                    raise Interrupted

            signal.signal(signal.SIGUSR1, handler)

            def holder():
                f.write(b'.')
                f.flush()

            Thread(target=holder, daemon=True).start()
            entered.wait()
            done = Event()

            def interrupt_main():
                # Until the main thread gets interrupted.
                while not done.wait(0.01):
                    signal.pthread_kill(main_thread().ident, signal.SIGUSR1)

            Thread(target=interrupt_main, daemon=True).start()
            try:
                waiting = True
                f.flush()
            except Interrupted:
                os.write(1, b'interrupted')
            finally:
                waiting = False
                done.set()
            """
        self.assertEqual(self.run_child(code), (0, b"interrupted", ""))


class CLockReleaseTest(LockReleaseTest, CTestCase):
    pass


class NibblerLockReleaseTest(NibblerMixin, LockReleaseTest, CTestCase):
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

    def test_many_writers_overflowing_buffer(self):
        # Writers that don't fit wait for the one writing out: each must
        # get its turn (letting the turn go after waiting, and trying
        # again, could leave every writer handing it to the next forever).
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        nthreads = 16
        with self.open(os_helper.TESTFN, "wb", buffering=1000) as f:
            def writer():
                for i in range(1000):
                    f.write(b"x" * (i % 100) + b"\n")

            threads = [threading.Thread(target=writer)
                       for _ in range(nthreads)]
            for t in threads:
                t.start()
            deadline = time.monotonic() + support.SHORT_TIMEOUT
            for t in threads:
                t.join(max(0, deadline - time.monotonic()))
            self.assertFalse(any(t.is_alive() for t in threads))
        self.assertEqual(os.path.getsize(os_helper.TESTFN),
                         nthreads * sum(i % 100 + 1 for i in range(1000)))

    def test_text_write_waits_for_raw_read(self):
        # A text write while another thread is in a raw read of the
        # buffered object below may wait for it, then goes through.
        import io
        in_read = threading.Event()
        release = threading.Event()

        class Raw(io.RawIOBase):
            out = b""
            def readable(self):
                return True
            def writable(self):
                return True
            def seekable(self):
                return True
            def seek(self, pos, whence=0):
                return 0
            def readinto(self, b):
                in_read.set()
                release.wait(support.SHORT_TIMEOUT)
                return 0
            def write(self, b):
                self.out += bytes(b)
                return len(b)

        raw = Raw()
        f = self.BufferedRandom(raw)
        t = io.TextIOWrapper(f, encoding="ascii")

        def write():
            t.write("text")
            t.flush()

        reader = threading.Thread(target=f.read, args=(1,))
        writer = threading.Thread(target=write)
        with threading_helper.start_threads([reader]):
            self.assertTrue(in_read.wait(support.SHORT_TIMEOUT))
            with threading_helper.start_threads([writer]):
                writer.join(0.05)
                release.set()
        self.assertEqual(raw.out, b"text")

    def test_small_writes_racing_other_calls(self):
        # Small writes stay whole and in order per thread while other
        # threads flush(), tell(), seek(), read() and close(); none that
        # raised is in the file, and every write that returned is, where
        # close() can't drop a write racing it.
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        for mode in ("wb", "w+b"):
            with self.subTest(mode=mode):
                self.check_small_writes_racing(mode)

    def check_small_writes_racing(self, mode):
        f = self.open(os_helper.TESTFN, mode, buffering=256)
        written = [[] for _ in range(self.nthreads)]
        halfway = threading.Event()
        closing = threading.Event()
        errors = []
        # (_pyio's raw calls can fail on the file descriptor being closed.)
        closed_errors = ValueError if self.is_nibbler else (
            ValueError, OSError)

        def writer(tid):
            for i in range(self.records_per_thread):
                rec = b"%02d:%06d|" % (tid, i) + b"." * (i % 40) + b"\n"
                try:
                    f.write(rec)
                except closed_errors:
                    if not closing.is_set():
                        raise
                    return
                written[tid].append(rec)
                if tid == 0 and i == self.records_per_thread // 2:
                    halfway.set()

        def other(op):
            last = 0
            while not closing.is_set():
                try:
                    if op == "flush":
                        f.flush()
                    elif op == "tell":
                        pos = f.tell()
                        if pos < last and self.is_nibbler:
                            errors.append((last, pos))
                        last = pos
                    elif op == "seek":
                        f.seek(0, os.SEEK_END)
                        f.seek(0, os.SEEK_CUR)
                    elif op == "read":
                        if f.read(1) != b"":
                            errors.append("read past the end")
                except closed_errors:
                    if not closing.is_set():
                        raise
                    return

        def closer():
            halfway.wait(support.SHORT_TIMEOUT)
            closing.set()
            f.close()

        ops = ["flush", "tell", "seek"] + (["read"] if "+" in mode else [])
        threads = ([threading.Thread(target=writer, args=(t,))
                    for t in range(self.nthreads)]
                   + [threading.Thread(target=other, args=(op,))
                      for op in ops]
                   + [threading.Thread(target=closer)])
        with threading_helper.start_threads(threads):
            pass
        self.assertEqual(errors, [])
        with open(os_helper.TESTFN, "rb") as result:
            lines = result.read().splitlines(keepends=True)
        everything = [r for w in written for r in w]
        if self.is_nibbler:
            self.assertEqual(sorted(lines), sorted(everything))
        else:
            # A write racing close() can't be shown to come before it, so
            # it may be dropped.
            self.assertLessEqual(set(lines), set(everything))
        for t in range(self.nthreads):
            prefix = b"%02d:" % t
            mine = [r for r in lines if r.startswith(prefix)]
            if not self.is_C:
                self.assertEqual(mine, sorted(mine))
            elif self.is_nibbler:
                self.assertEqual(mine, written[t])
            else:
                # Only the last writes, those racing close(), can be lost.
                self.assertEqual(mine, written[t][:len(mine)])

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

    def test_concurrent_readers_get_each_record_once(self):
        for buffering in (1000, 24):
            with self.subTest(buffering=buffering):
                self.check_concurrent_readers(lambda f: f.read(16),
                                              buffering)

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

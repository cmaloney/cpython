"""Tests for the private vectored write of raw streams, RawIOBase._writev(),
and its use by the _io._nibbler buffered classes."""
import errno
import io
import socket
import threading
import unittest

import _pyio as pyio
from _io import _nibbler

from test.support import threading_helper


class DefaultWritevTest:
    # RawIOBase._writev() calls write() on each buffer in order.

    def make_raw(self, steps):
        # write() takes at most the next step's bytes (None: would block).
        class Raw(self.RawIOBase):
            def __init__(self):
                self.out = bytearray()
                self.steps = list(steps)
                self.calls = []
            def writable(self):
                return True
            def write(self, b):
                b = bytes(b)
                self.calls.append(b)
                step = self.steps.pop(0) if self.steps else len(b)
                if step is None:
                    return None
                n = min(step, len(b))
                self.out += b[:n]
                return n
        return Raw()

    def test_all_written(self):
        raw = self.make_raw([])
        self.assertEqual(raw._writev([b"ab", bytearray(b"cde"),
                                      memoryview(b"f")]), 6)
        self.assertEqual(raw.out, b"abcdef")
        self.assertEqual(raw.calls, [b"ab", b"cde", b"f"])
        self.assertEqual(raw._writev([]), 0)

    def test_partial_stops(self):
        # A short write stops it, also in the middle of a buffer.
        raw = self.make_raw([2, 1])
        self.assertEqual(raw._writev([b"ab", b"cde", b"f"]), 3)
        self.assertEqual(raw.out, b"abc")
        self.assertEqual(raw.calls, [b"ab", b"cde"])

    def test_would_block(self):
        # None when nothing was written, else the count so far.
        raw = self.make_raw([None])
        self.assertIsNone(raw._writev([b"ab", b"cd"]))
        self.assertEqual(raw.calls, [b"ab"])
        raw = self.make_raw([2, None])
        self.assertEqual(raw._writev([b"ab", b"cd", b"ef"]), 2)
        self.assertEqual(raw.out, b"ab")

    def test_invalid_count(self):
        class Raw(self.RawIOBase):
            def writable(self):
                return True
            def write(self, b):
                return 5
        self.assertRaises(ValueError, Raw()._writev, [b"ab"])

    def test_error(self):
        class Raw(self.RawIOBase):
            def writable(self):
                return True
            def write(self, b):
                raise OSError(errno.EIO, "EIO")
        self.assertRaises(OSError, Raw()._writev, [b"ab"])

    def test_subclass_write_used(self):
        # A subclass overriding only write() gets a _writev() using it.
        class Upper(self.RawIOBase):
            def __init__(self):
                self.out = bytearray()
            def writable(self):
                return True
            def write(self, b):
                self.out += bytes(b).upper()
                return len(b)
        raw = Upper()
        self.assertEqual(raw._writev([b"ab", b"cd"]), 4)
        self.assertEqual(raw.out, b"ABCD")


class CDefaultWritevTest(DefaultWritevTest, unittest.TestCase):
    RawIOBase = io.RawIOBase


class PyDefaultWritevTest(DefaultWritevTest, unittest.TestCase):
    RawIOBase = pyio.RawIOBase


@unittest.skipUnless(hasattr(socket, "socketpair"), "needs socketpair()")
class SocketIOWritevTest(unittest.TestCase):

    def setUp(self):
        self.a, self.b = socket.socketpair()
        self.addCleanup(self.a.close)
        self.addCleanup(self.b.close)

    def test_writev(self):
        f = socket.SocketIO(self.a, "w")
        self.assertEqual(f._writev([b"ab", bytearray(b"cd"),
                                    memoryview(b"ef")]), 6)
        self.assertEqual(self.b.recv(100), b"abcdef")

    def test_partial_and_would_block(self):
        # Non-blocking, with little room: a large vectored write is partial,
        # then would block (None); what was sent is a prefix, in order.
        self.a.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        self.a.setblocking(False)
        f = socket.SocketIO(self.a, "w")
        parts = [bytes([i]) * 50_000 for i in range(1, 6)]
        sent = 0
        n = f._writev(parts)
        self.assertIsNotNone(n)
        self.assertLess(n, sum(map(len, parts)))
        while n is not None:
            sent += n
            n = f._writev([memoryview(b"".join(parts))[sent:]])
        received = bytearray()
        self.b.setblocking(False)
        try:
            while chunk := self.b.recv(1 << 20):
                received += chunk
        except BlockingIOError:
            pass
        self.assertEqual(bytes(received), b"".join(parts)[:sent])

    def test_closed(self):
        f = socket.SocketIO(self.a, "w")
        f.close()
        self.assertRaises(ValueError, f._writev, [b"x"])

    def test_not_writable(self):
        f = socket.SocketIO(self.a, "r")
        self.assertRaises(io.UnsupportedOperation, f._writev, [b"x"])

    @threading_helper.requires_working_threading()
    def test_buffered_large_writes(self):
        # Through _io._nibbler.BufferedWriter, whose pieces go to one
        # sendmsg(): partial sends of a blocking socket with a small buffer
        # lose and reorder nothing.
        self.a.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        received = bytearray()

        def reader():
            while chunk := self.b.recv(1 << 16):
                received.extend(chunk)

        t = threading.Thread(target=reader)
        t.start()
        try:
            f = _nibbler.BufferedWriter(socket.SocketIO(self.a, "w"), 8192)
            expected = bytearray()
            for i in range(200):
                data = bytes([i % 251]) * (17 + 997 * (i % 7))
                f.write(data)
                expected += data
            f.flush()
            self.a.shutdown(socket.SHUT_WR)
        finally:
            t.join()
        self.assertEqual(bytes(received), bytes(expected))


class Recorder(io.RawIOBase):
    """Records the write() and _writev() calls; _writev() takes at most
    the next step's bytes, then may raise."""

    def __init__(self, steps=()):
        self.out = bytearray()
        self.writes = 0
        self.writevs = []
        self.steps = list(steps)

    def writable(self):
        return True

    def _take(self, data):
        step = self.steps.pop(0) if self.steps else len(data)
        if isinstance(step, BaseException):
            raise step
        n = min(step, len(data))
        self.out += data[:n]
        return n

    def write(self, b):
        self.writes += 1
        return self._take(bytes(b))

    def _writev(self, buffers):
        buffers = [bytes(b) for b in buffers]
        self.writevs.append([len(b) for b in buffers])
        return self._take(b"".join(buffers))


class NibblerWritevTest(unittest.TestCase):

    def test_one_call_per_batch(self):
        # Large writes kept by reference go out together in one _writev().
        raw = Recorder()
        f = _nibbler.BufferedWriter(raw, 8192)
        parts = [bytes([i]) * 3000 for i in range(3)]
        for p in parts:
            f.write(p)
        # The third didn't fit: the two pending and it, in one call.
        self.assertEqual(raw.writevs, [[3000, 3000, 3000]])
        self.assertEqual(raw.writes, 0)
        self.assertEqual(raw.out, b"".join(parts))

    def test_batches_of_iov_max(self):
        # Many pieces are written in batches, each one _writev() call.
        raw = Recorder()
        f = _nibbler.BufferedWriter(raw, None)
        parts = [bytes([i % 256]) * 2048 for i in range(3000)]
        for p in parts:
            f.write(p)
        self.assertEqual(raw.writevs, [])
        f.flush()
        self.assertEqual(raw.out, b"".join(parts))
        self.assertEqual(sum(map(len, raw.writevs)), 3000)
        self.assertLessEqual(len(raw.writevs), 3000 // 64 + 1)
        self.assertEqual(raw.writes, 0)

    def test_partial_writev_retried(self):
        # A partial _writev(), also inside a piece, is retried from there.
        raw = Recorder([1000, 2500, 1])
        f = _nibbler.BufferedWriter(raw, 8192)
        parts = [bytes([i]) * 3000 for i in range(3)]
        for p in parts:
            f.write(p)
        f.flush()
        self.assertEqual(raw.out, b"".join(parts))
        self.assertEqual(raw.writevs[0], [3000, 3000, 3000])
        self.assertEqual(raw.writevs[1], [2000, 3000, 3000])
        self.assertEqual(raw.writevs[2], [2500, 3000])
        self.assertEqual(raw.writevs[3], [2499, 3000])

    def test_partial_writev_then_error(self):
        # write() raising after a partial _writev() of its data: the rest
        # is kept as far as it fits, and characters_written counts the
        # data written or kept.
        raw = Recorder([3500, OSError(errno.EIO, "EIO")])
        f = _nibbler.BufferedWriter(raw, 8192)
        a = b"a" * 3000
        b = b"b" * 6000
        f.write(a)
        with self.assertRaises(OSError) as cm:
            f.write(b)
        # 500 bytes of b were written; 8192 more fit in the buffer.
        self.assertEqual(cm.exception.characters_written, 500 + 5500)
        self.assertEqual(raw.out, a + b[:500])
        f.flush()
        self.assertEqual(raw.out, a + b)

    def test_default_writev_not_used(self):
        # A raw stream with only RawIOBase's _writev() (a loop of write())
        # gets small and large writes joined in blocks instead.
        class WriteOnly(io.RawIOBase):
            def __init__(self):
                self.calls = 0
                self.out = bytearray()
            def writable(self):
                return True
            def write(self, b):
                self.calls += 1
                self.out += b
                return len(b)
        raw = WriteOnly()
        f = _nibbler.BufferedWriter(raw, 8192)
        expected = bytearray()
        for i in range(100):
            data = b"s" * 16 if i % 2 else bytes([i]) * 600
            f.write(data)
            expected += data
        f.flush()
        self.assertEqual(raw.out, expected)
        self.assertLessEqual(raw.calls, len(expected) // 8192 + 2)


if __name__ == "__main__":
    unittest.main()

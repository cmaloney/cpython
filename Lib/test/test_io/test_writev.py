"""Tests for the private vectored write of raw streams, RawIOBase._writev()."""
import errno
import io
import socket
import unittest

import _pyio as pyio


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


if __name__ == "__main__":
    unittest.main()

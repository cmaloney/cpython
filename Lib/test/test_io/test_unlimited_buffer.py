"""Tests for unlimited write buffering: buffer_size=None of the
_io._nibbler BufferedWriter and BufferedRandom, and open(buffering=None)
when open() uses them."""
import io
import os
import sys
import threading
import unittest

import _io
from _io import _nibbler

from test.support import os_helper, script_helper, threading_helper


MiB = 1024 * 1024


class RecordingRaw(io.RawIOBase):
    """A raw stream recording what reaches it."""

    def __init__(self):
        self.data = bytearray()
        self.calls = 0
        self.objs = []
        self.plan = []

    def writable(self):
        return True

    def write(self, b):
        self.calls += 1
        if self.plan:
            step = self.plan.pop(0)
            if isinstance(step, BaseException):
                raise step
            if step is None:
                return None
        with memoryview(b) as m:
            self.objs.append(m.obj)
            self.data += m
            return m.nbytes


class VectoredRaw(RecordingRaw):
    """Has _writev(), so that large exact bytes are kept by reference."""

    def _writev(self, buffers):
        self.calls += 1
        n = 0
        for b in buffers:
            with memoryview(b) as m:
                self.objs.append(m.obj)
                self.data += m
                n += m.nbytes
        return n


class UnlimitedTest(unittest.TestCase):

    def setUp(self):
        self.path = os_helper.TESTFN
        self.addCleanup(os_helper.unlink, self.path)

    def size(self):
        return os.path.getsize(self.path)

    def read(self):
        with open(self.path, 'rb') as f:
            return f.read()

    def writer(self, mode='wb'):
        """An unlimited BufferedWriter (BufferedRandom with '+') on
        self.path."""
        raw = _io.FileIO(self.path, mode)
        cls = _nibbler.BufferedRandom if '+' in mode else _nibbler.BufferedWriter
        return cls(raw, buffer_size=None)

    def fill(self, f, nbytes):
        """Write nbytes in writes of mixed sizes; returns what was
        written."""
        sizes = [1, 16, 100, 600, 5000, 70000, 300000]
        parts = []
        total = i = 0
        while total < nbytes:
            n = min(sizes[i % len(sizes)], nbytes - total)
            b = bytes([i % 251]) * n
            self.assertEqual(f.write(b), n)
            parts.append(b)
            total += n
            i += 1
        return b''.join(parts)

    # Nothing is written out before a trigger.

    def test_nothing_written_before_flush(self):
        r = VectoredRaw()
        f = _nibbler.BufferedWriter(r, None)
        expected = self.fill(f, 24 * MiB)
        f.write(bytearray(b'z' * (3 * MiB)))
        expected += b'z' * (3 * MiB)
        self.assertEqual(r.calls, 0)
        f.flush()
        self.assertEqual(bytes(r.data), expected)

    def test_nothing_written_before_flush_unvectored(self):
        r = RecordingRaw()
        f = _nibbler.BufferedWriter(r, None)
        expected = self.fill(f, 8 * MiB)
        self.assertEqual(r.calls, 0)
        f.flush()
        self.assertEqual(bytes(r.data), expected)

    def test_file_not_written_before_flush(self):
        with self.writer() as f:
            expected = self.fill(f, 20 * MiB)
            self.assertEqual(self.size(), 0)
            self.assertEqual(f.tell(), 20 * MiB)
            self.assertEqual(self.size(), 0)
            f.flush()
            self.assertEqual(self.size(), 20 * MiB)
            f.write(b'tail')
            self.assertEqual(self.size(), 20 * MiB)
        self.assertEqual(self.read(), expected + b'tail')

    def test_small_buffer_writes_out(self):
        # For comparison: a limited buffer writes out on its own.
        r = RecordingRaw()
        f = _nibbler.BufferedWriter(r, 1024)
        self.fill(f, 100000)
        self.assertGreater(r.calls, 0)

    # Large exact bytes are kept by reference.

    def test_large_bytes_by_reference(self):
        big = os.urandom(MiB)
        with self.writer() as f:
            before = sys.getrefcount(big)
            f.write(big)
            self.assertEqual(sys.getrefcount(big), before + 1)
            f.flush()
            self.assertEqual(sys.getrefcount(big), before)
        self.assertEqual(self.read(), big)

    def test_large_bytes_handed_to_raw(self):
        for raw_type in VectoredRaw, RecordingRaw:
            with self.subTest(raw_type=raw_type.__name__):
                r = raw_type()
                f = _nibbler.BufferedWriter(r, None)
                big = os.urandom(io.DEFAULT_BUFFER_SIZE + 1)
                f.write(b'a')
                f.write(big)
                f.flush()
                # The raw stream got a view of the object itself.
                self.assertTrue(any(o is big for o in r.objs))
                self.assertEqual(bytes(r.data), b'a' + big)

    def test_mutable_data_copied(self):
        r = VectoredRaw()
        f = _nibbler.BufferedWriter(r, None)
        small = bytearray(b'abc')
        large = bytearray(b'x' * (2 * io.DEFAULT_BUFFER_SIZE))
        f.write(small)
        f.write(large)
        f.write(memoryview(large)[:10])
        small[:] = b'ABC'
        large[:] = b'y' * len(large)
        f.flush()
        self.assertEqual(bytes(r.data),
                         b'abc' + b'x' * (2 * io.DEFAULT_BUFFER_SIZE + 10))

    def test_flush_many_morsels(self):
        # More morsels than IOV_MAX (1024 on Linux) and than one stack
        # batch (64): several vectored writes, in order.
        objs = [bytes([i % 256]) * (600 + i % 7) for i in range(5000)]
        with self.writer() as f:
            for i, b in enumerate(objs):
                f.write(b)
                if i % 3 == 0:
                    f.write(b'%d,' % i)
            self.assertEqual(self.size(), 0)
            f.flush()
        expected = b''.join(b + (b'%d,' % i if i % 3 == 0 else b'')
                            for i, b in enumerate(objs))
        self.assertEqual(self.read(), expected)
        # A Python-level _writev() keeps pieces of 2 KiB and more by
        # reference (smaller ones are joined in blocks): batches of up to
        # IOV_MAX of them.
        big = [bytes([i % 256]) * (2048 + i % 7) for i in range(5000)]
        r = VectoredRaw()
        f = _nibbler.BufferedWriter(r, None)
        for b in big:
            f.write(b)
        f.flush()
        self.assertEqual(bytes(r.data), b''.join(big))
        self.assertGreater(r.calls, 1)
        self.assertLessEqual(r.calls, len(big) // 64 + 1)

    # Write-out triggers.

    def check_trigger(self, trigger, mode='wb'):
        f = self.writer(mode)
        try:
            f.write(b'abc')
            f.write(b'd' * MiB)
            self.assertEqual(self.size(), 0)
            trigger(f)
            self.assertEqual(self.size(), 3 + MiB)
        finally:
            f.close()
        self.assertEqual(self.read(), b'abc' + b'd' * MiB)

    def test_trigger_flush(self):
        self.check_trigger(lambda f: f.flush())

    def test_trigger_close(self):
        self.check_trigger(lambda f: f.close())

    def test_trigger_dealloc(self):
        f = self.writer()
        f.write(b'abc')
        f.write(b'd' * MiB)
        self.assertEqual(self.size(), 0)
        with self.assertWarns(ResourceWarning):
            del f
        self.assertEqual(self.read(), b'abc' + b'd' * MiB)

    def test_trigger_seek(self):
        self.check_trigger(lambda f: self.assertEqual(f.seek(0, 1), 3 + MiB))

    def test_trigger_truncate(self):
        self.check_trigger(lambda f: f.truncate())

    def test_trigger_detach(self):
        def detach(f):
            raw = f.detach()
            self.addCleanup(raw.close)
        f = self.writer()
        f.write(b'abc')
        detach(f)
        self.assertEqual(self.read(), b'abc')

    def test_trigger_read_random(self):
        for read in (lambda f: f.read(), lambda f: f.read(1),
                     lambda f: f.read1(), lambda f: f.peek(),
                     lambda f: f.readline(), lambda f: f.readinto(bytearray(5))):
            with self.subTest(read=read):
                self.check_trigger(read, 'w+b')

    def test_trigger_tell_append(self):
        with open(self.path, 'wb') as f:
            f.write(b'0123')
        def tell(f):
            self.assertEqual(f.tell(), 4 + 3 + MiB)
        f = self.writer('ab')
        try:
            f.write(b'abc')
            f.write(b'd' * MiB)
            self.assertEqual(self.size(), 4)
            tell(f)
            self.assertEqual(self.size(), 4 + 3 + MiB)
        finally:
            f.close()

    def test_tell_does_not_write_out(self):
        with self.writer() as f:
            f.write(b'abc')
            self.assertEqual(f.tell(), 3)
            self.assertEqual(self.size(), 0)

    def test_trigger_exit(self):
        code = f"""if 1:
            import _io
            f = _io._nibbler.BufferedWriter(_io.FileIO({self.path!r}, 'wb'),
                                            None)
            f.write(b'x' * {3 * MiB})
            g = _io._nibbler.BufferedWriter(_io.FileIO({self.path!r}, 'r+b'),
                                            None)
            g.write(b'abc')
            # A cycle: collected at exit.
            g.cycle = g
            """
        script_helper.assert_python_ok('-c', code)
        data = self.read()
        self.assertEqual(len(data), 3 * MiB)
        self.assertIn(data[:3], (b'abc', b'xxx'))

    def test_nonblocking_flush(self):
        r = RecordingRaw()
        f = _nibbler.BufferedWriter(r, None)
        f.write(b'abc')
        f.write(b'def')
        r.plan = [None]
        with self.assertRaises(BlockingIOError):
            f.flush()
        self.assertEqual(r.data, b'')
        f.flush()
        self.assertEqual(r.data, b'abcdef')

    def test_close_failing_raw(self):
        # close() reports the error of the write out; the raw stream is
        # closed and the data is dropped.
        r = RecordingRaw()
        f = _nibbler.BufferedWriter(r, None)
        f.write(b'abc')
        r.plan = [OSError('boom')]
        with self.assertRaisesRegex(OSError, 'boom'):
            f.close()
        self.assertTrue(r.closed)
        self.assertTrue(f.closed)
        self.assertEqual(r.data, b'')
        f.close()
        self.assertEqual(r.data, b'')

    # BufferedRandom.

    def test_random_read_after_write(self):
        with open(self.path, 'wb') as f:
            f.write(b'0123456789')
        with self.writer('r+b') as f:
            self.assertEqual(f.read(2), b'01')
            f.write(b'ab')
            self.assertEqual(f.tell(), 4)
            self.assertEqual(self.read(), b'0123456789')
            self.assertEqual(f.read(2), b'45')
            self.assertEqual(self.read(), b'01ab456789')
            f.seek(0)
            self.assertEqual(f.read(), b'01ab456789')
            f.write(b'x' * (3 * MiB))
            self.assertEqual(self.size(), 10)
            f.seek(0)
            self.assertEqual(f.read(4), b'01ab')
            self.assertEqual(self.size(), 10 + 3 * MiB)

    def test_random_reads_use_blocks(self):
        with open(self.path, 'wb') as f:
            f.write(b'x' * (3 * io.DEFAULT_BUFFER_SIZE))
        with self.writer('r+b') as f:
            self.assertEqual(len(f.peek()), io.DEFAULT_BUFFER_SIZE)
            self.assertEqual(len(f.read1()), io.DEFAULT_BUFFER_SIZE)

    # The text layer.

    def text(self, **kwargs):
        return io.TextIOWrapper(self.writer(), encoding='ascii', **kwargs)

    def test_text(self):
        with self.text() as t:
            for i in range(100000):
                t.write(f'line {i}\n')
            self.assertEqual(self.size(), 0)
            t.flush()
            self.assertGreater(self.size(), 0)
            t.write('end')
        with open(self.path, encoding='ascii') as t:
            lines = t.read().split('\n')
        self.assertEqual(lines, [f'line {i}' for i in range(100000)] + ['end'])

    def test_text_line_buffering(self):
        with self.text(line_buffering=True) as t:
            t.write('abc')
            self.assertEqual(self.size(), 0)
            t.write('def\nghi')
            self.assertEqual(self.read(), b'abcdef\nghi')
            t.write('jkl')
            self.assertEqual(self.read(), b'abcdef\nghi')
        self.assertEqual(self.read(), b'abcdef\nghijkl')

    def test_text_write_through(self):
        # write_through only skips the text layer's buffering: the data
        # stays in the buffer.
        with self.text(write_through=True) as t:
            t.write('abc\n')
            self.assertEqual(self.size(), 0)
            self.assertEqual(t.buffer.tell(), 4)
        self.assertEqual(self.read(), b'abc\n')

    # Threads.

    @threading_helper.requires_working_threading()
    def test_concurrent_writers(self):
        nthreads, nlines = 8, 5000
        with self.writer() as f:
            def worker(i):
                big = b'%d' % i * 1000 + b'\n'
                for j in range(nlines):
                    f.write(b'%d:%d\n' % (i, j))
                    if j % 100 == 0:
                        f.write(big)
            def flusher():
                for _ in range(20):
                    f.flush()
            threads = [threading.Thread(target=worker, args=(i,))
                       for i in range(nthreads)]
            threads.append(threading.Thread(target=flusher))
            with threading_helper.start_threads(threads):
                pass
        lines = self.read().splitlines()
        for i in range(nthreads):
            mine = [l for l in lines if l.startswith(b'%d:' % i)]
            self.assertEqual(mine, [b'%d:%d' % (i, j) for j in range(nlines)])
        bigs = [l for l in lines if b':' not in l]
        self.assertEqual(len(bigs), nthreads * nlines // 100)
        for l in bigs:
            self.assertEqual(len(set(l)), 1)

    # Arguments and introspection.

    def test_buffer_size_argument(self):
        for cls in _nibbler.BufferedWriter, _nibbler.BufferedRandom:
            with self.subTest(cls=cls.__name__):
                with _io.FileIO(self.path, 'w+b') as raw:
                    f = cls(raw, None)
                    f.write(b'a')
                    self.assertEqual(self.size(), 0)
                    f.__init__(raw, buffer_size=None)
                    f.__init__(raw)
                    f.write(b'a' * (io.DEFAULT_BUFFER_SIZE + 1))
                    self.assertGreater(self.size(), 0)
                    with self.assertRaises(TypeError):
                        cls(raw, 1.5)
                    with self.assertRaises(ValueError):
                        cls(raw, -1)
        with self.assertRaises(TypeError):
            _nibbler.BufferedReader(RecordingRaw(), None)

    def test_repr_and_sizeof(self):
        with self.writer() as f:
            limited = _nibbler.BufferedWriter(_io.FileIO(self.path, 'ab'),
                                              io.DEFAULT_BUFFER_SIZE)
            self.addCleanup(limited.close)
            # As with a buffer size.
            self.assertEqual(repr(f), repr(limited))
            self.assertIn(f"name={self.path!r}", repr(f))
            # No block yet.
            self.assertEqual(f.__sizeof__(), limited.__sizeof__())
            f.write(b'a')
            limited.write(b'a')
            # The current block counts, not all pending data.
            self.assertEqual(f.__sizeof__(), limited.__sizeof__())
            f.write(b'b' * (4 * io.DEFAULT_BUFFER_SIZE))
            self.assertEqual(f.__sizeof__(), limited.__sizeof__())


class OpenUnlimitedTest(unittest.TestCase):

    def setUp(self):
        self.path = os_helper.TESTFN
        self.addCleanup(os_helper.unlink, self.path)
        with open(self.path, 'wb') as f:
            f.write(b'old')

    def read(self):
        with open(self.path, 'rb') as f:
            return f.read()

    def nibbler(self):
        prev = _io._set_open_impl('_nibbler')
        self.addCleanup(_io._set_open_impl, prev)

    def test_without_nibbler(self):
        prev = _io._set_open_impl('_io')
        self.addCleanup(_io._set_open_impl, prev)
        for mode in 'wb', 'w', 'ab', 'r+b', 'rb':
            with self.subTest(mode=mode):
                with self.assertRaisesRegex(TypeError, '_nibbler'):
                    open(self.path, mode, buffering=None)
                # Raised before opening: not truncated.
                self.assertEqual(self.read(), b'old')

    def test_switched_while_opening(self):
        # The class checked before the file is opened is the one used, also
        # when _io._set_open_impl() replaces it meanwhile (here from the
        # opener, called in between).
        self.nibbler()
        def opener(path, flags):
            _io._set_open_impl('_io')
            return os.open(path, flags)
        with open(self.path, 'wb', buffering=None, opener=opener) as f:
            self.assertIs(type(f), _nibbler.BufferedWriter)
            f.write(b'new')
        self.assertEqual(self.read(), b'new')

    def test_binary(self):
        self.nibbler()
        for mode, cls in [('wb', _nibbler.BufferedWriter),
                          ('ab', _nibbler.BufferedWriter),
                          ('r+b', _nibbler.BufferedRandom),
                          ('w+b', _nibbler.BufferedRandom)]:
            with self.subTest(mode=mode):
                with open(self.path, mode, buffering=None) as f:
                    self.assertIs(type(f), cls)
                    f.write(b'x' * (2 * MiB))
                    if mode == 'r+b':
                        self.assertEqual(self.read(), b'old')
                    elif mode == 'ab':
                        self.assertEqual(len(self.read()), 3)
                    else:
                        self.assertEqual(self.read(), b'')
                with open(self.path, 'wb') as f:
                    f.write(b'old')

    def test_text(self):
        self.nibbler()
        with open(self.path, 'w', buffering=None, encoding='ascii') as t:
            self.assertIs(type(t.buffer), _nibbler.BufferedWriter)
            self.assertFalse(t.line_buffering)
            t.write('abc\n' * 100000)
            self.assertEqual(self.read(), b'')
        self.assertEqual(self.read(), b'abc\n' * 100000)

    def test_read_only(self):
        self.nibbler()
        for mode in 'rb', 'r':
            with self.subTest(mode=mode):
                with self.assertRaisesRegex(ValueError, 'writable'):
                    open(self.path, mode, buffering=None)

    def test_other_values(self):
        self.nibbler()
        with self.assertRaises(TypeError):
            open(self.path, 'wb', buffering=1.5)
        with open(self.path, 'wb', buffering=16) as f:
            f.write(b'x' * 100)
            self.assertEqual(len(self.read()), 100)


if __name__ == '__main__':
    unittest.main()

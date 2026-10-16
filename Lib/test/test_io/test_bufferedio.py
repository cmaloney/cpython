import array
import errno
import os
import pickle
import random
import sys
import threading
import time
import unittest
import warnings
import weakref
from collections import deque, UserList
from itertools import cycle, count
from test import support
from test.support import (check_sanitizer, import_helper, os_helper,
                          threading_helper)
from .utils import byteslike, CTestCase, PyTestCase, NibblerMixin


import io # C implementation.
import _pyio as pyio # Python implementation.
from _io import _nibbler # Nibbler C implementation.

class CommonBufferedTests:
    # Tests common to BufferedReader, BufferedWriter and BufferedRandom

    def test_detach(self):
        raw = self.MockRawIO()
        buf = self.tp(raw)
        self.assertIs(buf.detach(), raw)
        self.assertRaises(ValueError, buf.detach)

        repr(buf)  # Should still work

    def test_fileno(self):
        rawio = self.MockRawIO()
        bufio = self.tp(rawio)

        self.assertEqual(42, bufio.fileno())

    def test_invalid_args(self):
        rawio = self.MockRawIO()
        bufio = self.tp(rawio)
        # Invalid whence
        self.assertRaises(ValueError, bufio.seek, 0, -1)
        self.assertRaises(ValueError, bufio.seek, 0, 9)

    def test_override_destructor(self):
        tp = self.tp
        record = []
        class MyBufferedIO(tp):
            def __del__(self):
                record.append(1)
                try:
                    f = super().__del__
                except AttributeError:
                    pass
                else:
                    f()
            def close(self):
                record.append(2)
                super().close()
            def flush(self):
                record.append(3)
                super().flush()
        rawio = self.MockRawIO()
        bufio = MyBufferedIO(rawio)
        del bufio
        support.gc_collect()
        self.assertEqual(record, [1, 2, 3])

    def test_context_manager(self):
        # Test usability as a context manager
        rawio = self.MockRawIO()
        bufio = self.tp(rawio)
        def _with():
            with bufio:
                pass
        _with()
        # bufio should now be closed, and using it a second time should raise
        # a ValueError.
        self.assertRaises(ValueError, _with)

    def test_error_through_destructor(self):
        # Test that the exception state is not modified by a destructor,
        # even if close() fails.
        rawio = self.CloseFailureIO()
        with support.catch_unraisable_exception() as cm:
            with self.assertRaises(AttributeError):
                self.tp(rawio).xyzzy

            self.assertEqual(cm.unraisable.exc_type, OSError)

    def test_repr(self):
        raw = self.MockRawIO()
        b = self.tp(raw)
        clsname = r"(%s\.)?%s" % (self.tp.__module__, self.tp.__qualname__)
        self.assertRegex(repr(b), "<%s>" % clsname)
        raw.name = "dummy"
        self.assertRegex(repr(b), "<%s name='dummy'>" % clsname)
        raw.name = b"dummy"
        self.assertRegex(repr(b), "<%s name=b'dummy'>" % clsname)

    def test_recursive_repr(self):
        # Issue #25455
        raw = self.MockRawIO()
        b = self.tp(raw)
        with support.swap_attr(raw, 'name', b), support.infinite_recursion(25):
            with self.assertRaises(RuntimeError):
                repr(b)  # Should not crash

    def test_flush_error_on_close(self):
        # Test that buffered file is closed despite failed flush
        # and that flush() is called before file closed.
        raw = self.MockRawIO()
        closed = []
        def bad_flush():
            closed[:] = [b.closed, raw.closed]
            raise OSError()
        raw.flush = bad_flush
        b = self.tp(raw)
        self.assertRaises(OSError, b.close) # exception not swallowed
        self.assertTrue(b.closed)
        self.assertTrue(raw.closed)
        self.assertTrue(closed)      # flush() called
        self.assertFalse(closed[0])  # flush() called before file closed
        self.assertFalse(closed[1])
        raw.flush = lambda: None  # break reference loop

    def test_close_error_on_close(self):
        raw = self.MockRawIO()
        def bad_flush():
            raise OSError('flush')
        def bad_close():
            raise OSError('close')
        raw.close = bad_close
        b = self.tp(raw)
        b.flush = bad_flush
        with self.assertRaises(OSError) as err: # exception not swallowed
            b.close()
        self.assertEqual(err.exception.args, ('close',))
        self.assertIsInstance(err.exception.__context__, OSError)
        self.assertEqual(err.exception.__context__.args, ('flush',))
        self.assertFalse(b.closed)

        # Silence destructor error
        raw.close = lambda: None
        b.flush = lambda: None

    def test_nonnormalized_close_error_on_close(self):
        # Issue #21677
        raw = self.MockRawIO()
        def bad_flush():
            raise non_existing_flush
        def bad_close():
            raise non_existing_close
        raw.close = bad_close
        b = self.tp(raw)
        b.flush = bad_flush
        with self.assertRaises(NameError) as err: # exception not swallowed
            b.close()
        self.assertIn('non_existing_close', str(err.exception))
        self.assertIsInstance(err.exception.__context__, NameError)
        self.assertIn('non_existing_flush', str(err.exception.__context__))
        self.assertFalse(b.closed)

        # Silence destructor error
        b.flush = lambda: None
        raw.close = lambda: None

    def test_multi_close(self):
        raw = self.MockRawIO()
        b = self.tp(raw)
        b.close()
        b.close()
        b.close()
        self.assertRaises(ValueError, b.flush)

    def test_unseekable(self):
        bufio = self.tp(self.MockUnseekableIO(b"A" * 10))
        self.assertRaises(self.UnsupportedOperation, bufio.tell)
        self.assertRaises(self.UnsupportedOperation, bufio.seek, 0)

    def test_readonly_attributes(self):
        raw = self.MockRawIO()
        buf = self.tp(raw)
        x = self.MockRawIO()
        with self.assertRaises(AttributeError):
            buf.raw = x

    def test_pickling_subclass(self):
        global MyBufferedIO
        class MyBufferedIO(self.tp):
            def __init__(self, raw, tag):
                super().__init__(raw)
                self.tag = tag
            def __getstate__(self):
                return self.tag, self.raw.getvalue()
            def __setstate__(slf, state):
                tag, value = state
                slf.__init__(self.BytesIO(value), tag)

        raw = self.BytesIO(b'data')
        buf = MyBufferedIO(raw, tag='ham')
        for proto in range(pickle.HIGHEST_PROTOCOL + 1):
            with self.subTest(protocol=proto):
                pickled = pickle.dumps(buf, proto)
                newbuf = pickle.loads(pickled)
                self.assertEqual(newbuf.raw.getvalue(), b'data')
                self.assertEqual(newbuf.tag, 'ham')
        del MyBufferedIO


class SizeofTest:

    def make_used(self, buffer_size):
        # A buffered object that used its buffer once (some implementations
        # only allocate it when first needed).
        bufio = self.tp(self.MockRawIO(), buffer_size=buffer_size)
        if bufio.readable():
            bufio.read(1)
        else:
            bufio.write(b"x")
        return bufio

    @support.cpython_only
    def test_sizeof(self):
        bufsize1 = 4096
        bufsize2 = 8192
        bufio = self.make_used(bufsize1)
        size = sys.getsizeof(bufio) - bufsize1
        bufio = self.make_used(bufsize2)
        self.assertEqual(sys.getsizeof(bufio), size + bufsize2)

    @support.cpython_only
    def test_buffer_freeing(self) :
        bufsize = 4096
        bufio = self.make_used(bufsize)
        size = sys.getsizeof(bufio) - bufsize
        bufio.close()
        self.assertEqual(sys.getsizeof(bufio), size)

    @unittest.skipIf(check_sanitizer(thread=True),
                     'ThreadSanitizer aborts on huge allocations (exit code 66).')
    def test_huge_buffer_size(self):
        # A buffer no allocation can give is a MemoryError, not sizes
        # overflowing as they are computed from it.
        for size in (sys.maxsize, sys.maxsize - 32, sys.maxsize // 2 + 10):
            with self.subTest(size=size):
                self.assertRaises(MemoryError, self.tp,
                                  self.MockRawIO([b'abc\n']), size)

class BufferedReaderTest(CommonBufferedTests):
    read_mode = "rb"

    def test_constructor(self):
        rawio = self.MockRawIO([b"abc"])
        bufio = self.tp(rawio)
        bufio.__init__(rawio)
        bufio.__init__(rawio, buffer_size=1024)
        bufio.__init__(rawio, buffer_size=16)
        self.assertEqual(b"abc", bufio.read())
        self.assertRaises(ValueError, bufio.__init__, rawio, buffer_size=0)
        self.assertRaises(ValueError, bufio.__init__, rawio, buffer_size=-16)
        self.assertRaises(ValueError, bufio.__init__, rawio, buffer_size=-1)
        rawio = self.MockRawIO([b"abc"])
        bufio.__init__(rawio)
        self.assertEqual(b"abc", bufio.read())

    def test_uninitialized(self):
        bufio = self.tp.__new__(self.tp)
        del bufio
        bufio = self.tp.__new__(self.tp)
        self.assertRaisesRegex((ValueError, AttributeError),
                               'uninitialized|has no attribute',
                               bufio.read, 0)
        bufio.__init__(self.MockRawIO())
        self.assertEqual(bufio.read(0), b'')

    def test_read(self):
        for arg in (None, 7):
            rawio = self.MockRawIO((b"abc", b"d", b"efg"))
            bufio = self.tp(rawio)
            self.assertEqual(b"abcdefg", bufio.read(arg))
        # Invalid args
        self.assertRaises(ValueError, bufio.read, -2)

    def test_read1(self):
        rawio = self.MockRawIO((b"abc", b"d", b"efg"))
        bufio = self.tp(rawio)
        self.assertEqual(b"a", bufio.read(1))
        self.assertEqual(b"b", bufio.read1(1))
        self.assertEqual(rawio._reads, 1)
        self.assertEqual(b"", bufio.read1(0))
        self.assertEqual(b"c", bufio.read1(100))
        self.assertEqual(rawio._reads, 1)
        self.assertEqual(b"d", bufio.read1(100))
        self.assertEqual(rawio._reads, 2)
        self.assertEqual(b"efg", bufio.read1(100))
        self.assertEqual(rawio._reads, 3)
        self.assertEqual(b"", bufio.read1(100))
        self.assertEqual(rawio._reads, 4)

    def test_read1_arbitrary(self):
        rawio = self.MockRawIO((b"abc", b"d", b"efg"))
        bufio = self.tp(rawio)
        self.assertEqual(b"a", bufio.read(1))
        self.assertEqual(b"bc", bufio.read1())
        self.assertEqual(b"d", bufio.read1())
        self.assertEqual(b"efg", bufio.read1(-1))
        self.assertEqual(rawio._reads, 3)
        self.assertEqual(b"", bufio.read1())
        self.assertEqual(rawio._reads, 4)

    def test_readinto(self):
        rawio = self.MockRawIO((b"abc", b"d", b"efg"))
        bufio = self.tp(rawio)
        b = bytearray(2)
        self.assertEqual(bufio.readinto(b), 2)
        self.assertEqual(b, b"ab")
        self.assertEqual(bufio.readinto(b), 2)
        self.assertEqual(b, b"cd")
        self.assertEqual(bufio.readinto(b), 2)
        self.assertEqual(b, b"ef")
        self.assertEqual(bufio.readinto(b), 1)
        self.assertEqual(b, b"gf")
        self.assertEqual(bufio.readinto(b), 0)
        self.assertEqual(b, b"gf")
        rawio = self.MockRawIO((b"abc", None))
        bufio = self.tp(rawio)
        self.assertEqual(bufio.readinto(b), 2)
        self.assertEqual(b, b"ab")
        self.assertEqual(bufio.readinto(b), 1)
        self.assertEqual(b, b"cb")

    def test_readinto_several_refills(self):
        # A readinto() that needs more than one refill of the buffer, the
        # last one returning more than is left of b, fills b exactly.
        rawio = self.MockRawIO((b"abc", b"defgh"))
        bufio = self.tp(rawio, 8)
        b = bytearray(6)
        self.assertEqual(bufio.readinto(b), 6)
        self.assertEqual(b, b"abcdef")
        self.assertEqual(bufio.read(), b"gh")

    def test_readinto1(self):
        buffer_size = 10
        rawio = self.MockRawIO((b"abc", b"de", b"fgh", b"jkl"))
        bufio = self.tp(rawio, buffer_size=buffer_size)
        b = bytearray(2)
        self.assertEqual(bufio.peek(3), b'abc')
        self.assertEqual(rawio._reads, 1)
        self.assertEqual(bufio.readinto1(b), 2)
        self.assertEqual(b, b"ab")
        self.assertEqual(rawio._reads, 1)
        self.assertEqual(bufio.readinto1(b), 1)
        self.assertEqual(b[:1], b"c")
        self.assertEqual(rawio._reads, 1)
        self.assertEqual(bufio.readinto1(b), 2)
        self.assertEqual(b, b"de")
        self.assertEqual(rawio._reads, 2)
        b = bytearray(2*buffer_size)
        self.assertEqual(bufio.peek(3), b'fgh')
        self.assertEqual(rawio._reads, 3)
        self.assertEqual(bufio.readinto1(b), 6)
        self.assertEqual(b[:6], b"fghjkl")
        self.assertEqual(rawio._reads, 4)

    def test_readinto_array(self):
        buffer_size = 60
        data = b"a" * 26
        rawio = self.MockRawIO((data,))
        bufio = self.tp(rawio, buffer_size=buffer_size)

        # Create an array with element size > 1 byte
        b = array.array('i', b'x' * 32)
        assert len(b) != 16

        # Read into it. We should get as many *bytes* as we can fit into b
        # (which is more than the number of elements)
        n = bufio.readinto(b)
        self.assertGreater(n, len(b))

        # Check that old contents of b are preserved
        bm = memoryview(b).cast('B')
        self.assertLess(n, len(bm))
        self.assertEqual(bm[:n], data[:n])
        self.assertEqual(bm[n:], b'x' * (len(bm[n:])))

    def test_readinto1_array(self):
        buffer_size = 60
        data = b"a" * 26
        rawio = self.MockRawIO((data,))
        bufio = self.tp(rawio, buffer_size=buffer_size)

        # Create an array with element size > 1 byte
        b = array.array('i', b'x' * 32)
        assert len(b) != 16

        # Read into it. We should get as many *bytes* as we can fit into b
        # (which is more than the number of elements)
        n = bufio.readinto1(b)
        self.assertGreater(n, len(b))

        # Check that old contents of b are preserved
        bm = memoryview(b).cast('B')
        self.assertLess(n, len(bm))
        self.assertEqual(bm[:n], data[:n])
        self.assertEqual(bm[n:], b'x' * (len(bm[n:])))

    def test_readlines(self):
        def bufio():
            rawio = self.MockRawIO((b"abc\n", b"d\n", b"ef"))
            return self.tp(rawio)
        self.assertEqual(bufio().readlines(), [b"abc\n", b"d\n", b"ef"])
        self.assertEqual(bufio().readlines(5), [b"abc\n", b"d\n"])
        self.assertEqual(bufio().readlines(None), [b"abc\n", b"d\n", b"ef"])

    def test_buffering(self):
        data = b"abcdefghi"
        dlen = len(data)

        tests = [
            [ 100, [ 3, 1, 4, 8 ], [ dlen, 0 ] ],
            [ 100, [ 3, 3, 3],     [ dlen ]    ],
            [   4, [ 1, 2, 4, 2 ], [ 4, 4, 1 ] ],
        ]

        for bufsize, buf_read_sizes, raw_read_sizes in tests:
            rawio = self.MockFileIO(data)
            bufio = self.tp(rawio, buffer_size=bufsize)
            pos = 0
            for nbytes in buf_read_sizes:
                self.assertEqual(bufio.read(nbytes), data[pos:pos+nbytes])
                pos += nbytes
            # this is mildly implementation-dependent
            self.assertEqual(rawio.read_history, raw_read_sizes)

    def test_read_non_blocking(self):
        # Inject some None's in there to simulate EWOULDBLOCK
        rawio = self.MockRawIO((b"abc", b"d", None, b"efg", None, None, None))
        bufio = self.tp(rawio)
        self.assertEqual(b"abcd", bufio.read(6))
        self.assertEqual(b"e", bufio.read(1))
        self.assertEqual(b"fg", bufio.read())
        self.assertIsNone(bufio.peek(1))
        self.assertIsNone(bufio.read())
        self.assertEqual(b"", bufio.read())

        rawio = self.MockRawIO((b"a", None, None))
        self.assertEqual(b"a", rawio.readall())
        self.assertIsNone(rawio.readall())

    def test_read1_peek_readinto_non_blocking(self):
        # gh-57531: they return None when the raw stream would block with
        # nothing buffered, as read() does; b"" and 0 mean EOF.
        rawio = self.MockRawIO((None, None, None, None, b"abc"))
        bufio = self.tp(rawio)
        self.assertIsNone(bufio.peek(1))
        self.assertIsNone(bufio.read1(10))
        self.assertIsNone(bufio.readinto1(bytearray(10)))
        self.assertIsNone(bufio.readinto(bytearray(10)))
        self.assertEqual(bufio.read1(10), b"abc")
        self.assertEqual(bufio.peek(1), b"")
        self.assertEqual(bufio.read1(10), b"")
        self.assertEqual(bufio.readinto1(bytearray(10)), 0)

    def test_readline_would_block_keeps_partial_line(self):
        # gh-57531: readline() that would block before the end of the line
        # returns None and keeps the partial line for the next call;
        # iteration raises BlockingIOError.
        rawio = self.MockRawIO((b"ab", None, b"c", None, b"d\nef", None,
                                b"g"))
        bufio = self.tp(rawio)
        self.assertIsNone(bufio.readline())
        self.assertIsNone(bufio.readline())
        self.assertEqual(bufio.readline(), b"abcd\n")
        self.assertRaises(BlockingIOError, next, bufio)
        self.assertEqual(next(bufio), b"efg")
        self.assertRaises(StopIteration, next, bufio)

    @unittest.skipUnless(hasattr(os, "set_blocking"),
                         "requires os.set_blocking()")
    def test_readline_nonblocking_pipe(self):
        # The same on a real non-blocking pipe.
        if self.tp is not self.BufferedReader:
            self.skipTest("a pipe is not seekable")
        r, w = os.pipe()
        try:
            os.set_blocking(r, False)
            raw = self.FileIO(r, "r", closefd=False)
            with self.tp(raw) as bufio:
                self.assertIsNone(bufio.readline())
                os.write(w, b"ab")
                self.assertIsNone(bufio.readline())
                self.assertRaises(BlockingIOError, next, bufio)
                os.write(w, b"c\nd")
                self.assertEqual(bufio.readline(), b"abc\n")
                self.assertIsNone(bufio.readline())
                os.write(w, b"e\n")
                self.assertEqual(next(bufio), b"de\n")
                os.close(w)
                w = None
                self.assertEqual(bufio.readline(), b"")
        finally:
            os.close(r)
            if w is not None:
                os.close(w)

    def test_readlines_would_block(self):
        # readlines() that would block returns the complete lines so far
        # and keeps the partial last line for the next call; with none,
        # it returns None, as readline() does.
        rawio = self.MockRawIO((b"ab\ncd\nef", None, b"g\nh", None, None,
                                b"i\n"))
        bufio = self.tp(rawio)
        self.assertEqual(bufio.readlines(), [b"ab\n", b"cd\n"])
        self.assertEqual(bufio.readlines(), [b"efg\n"])
        self.assertIsNone(bufio.readlines())
        self.assertEqual(bufio.readlines(), [b"hi\n"])
        self.assertEqual(bufio.readlines(), [])
        # With a hint.
        rawio = self.MockRawIO((b"ab\ncd\nef", None, b"g\n", None))
        bufio = self.tp(rawio)
        self.assertEqual(bufio.readlines(2), [b"ab\n"])
        self.assertEqual(bufio.readlines(100), [b"cd\n"])
        self.assertEqual(bufio.readlines(100), [b"efg\n"])
        self.assertEqual(bufio.readlines(100), [])

    def test_readline_would_block_limit(self):
        # With a limit: what arrived up to it is a line.
        rawio = self.MockRawIO((b"ab", None, b"cdef", None, b"g\n"))
        bufio = self.tp(rawio)
        self.assertIsNone(bufio.readline(3))
        self.assertEqual(bufio.readline(3), b"abc")
        self.assertIsNone(bufio.readline(5))
        self.assertEqual(bufio.readline(5), b"defg\n")
        self.assertEqual(bufio.readline(5), b"")

    def test_readline_would_block_long_partial_line(self):
        # A partial line is kept up to the buffer size; a longer one is
        # returned as it is, with or without a size.
        for size in -1, 100:
            with self.subTest(size=size):
                rawio = self.MockRawIO((b"x" * 16, None, b"y\n"))
                bufio = self.tp(rawio, 16)
                self.assertIsNone(bufio.readline(size))
                self.assertEqual(bufio.readline(size), b"x" * 16 + b"y\n")
                rawio = self.MockRawIO((b"x" * 17, None, b"y\n"))
                bufio = self.tp(rawio, 16)
                self.assertEqual(bufio.readline(size), b"x" * 17)
                self.assertEqual(bufio.readline(size), b"y\n")

    def test_read_past_eof(self):
        rawio = self.MockRawIO((b"abc", b"d", b"efg"))
        bufio = self.tp(rawio)

        self.assertEqual(b"abcdefg", bufio.read(9000))

    def test_read_all(self):
        rawio = self.MockRawIO((b"abc", b"d", b"efg"))
        bufio = self.tp(rawio)

        self.assertEqual(b"abcdefg", bufio.read())

    def test_readall(self):
        if not self.is_nibbler:
            self.skipTest("no readall()")
        for size in (16, 4096):
            with self.subTest(buffer_size=size):
                rawio = self.MockRawIO((b"abc", b"d", b"efg"))
                bufio = self.tp(rawio, buffer_size=size)
                self.assertEqual(bufio.read(2), b"ab")
                self.assertEqual(bufio.readall(), b"cdefg")
                self.assertEqual(bufio.readall(), b"")
                # Would block before any data: None, like read().
                rawio = self.MockRawIO((b"abc", None, None, b"d"))
                bufio = self.tp(rawio, buffer_size=size)
                self.assertEqual(bufio.readall(), b"abc")
                self.assertIsNone(bufio.readall())
                self.assertEqual(bufio.readall(), b"d")
                bufio.close()
                self.assertRaises(ValueError, bufio.readall)

    @threading_helper.requires_working_threading()
    @support.requires_resource('cpu')
    def test_threads(self):
        try:
            # Write out many bytes with exactly the same number of 0's,
            # 1's... 255's. This will help us check that concurrent reading
            # doesn't duplicate or forget contents.
            N = 1000
            l = list(range(256)) * N
            random.shuffle(l)
            s = bytes(bytearray(l))
            with self.open(os_helper.TESTFN, "wb") as f:
                f.write(s)
            with self.open(os_helper.TESTFN, self.read_mode, buffering=0) as raw:
                bufio = self.tp(raw, 8)
                errors = []
                results = []
                def f():
                    try:
                        # Intra-buffer read then buffer-flushing read
                        for n in cycle([1, 19]):
                            s = bufio.read(n)
                            if not s:
                                break
                            # list.append() is atomic
                            results.append(s)
                    except Exception as e:
                        errors.append(e)
                        raise
                threads = [threading.Thread(target=f) for x in range(20)]
                with threading_helper.start_threads(threads):
                    time.sleep(0.02) # yield
                self.assertFalse(errors,
                    "the following exceptions were caught: %r" % errors)
                s = b''.join(results)
                for i in range(256):
                    c = bytes(bytearray([i]))
                    self.assertEqual(s.count(c), N)
        finally:
            os_helper.unlink(os_helper.TESTFN)

    def test_unseekable(self):
        bufio = self.tp(self.MockUnseekableIO(b"A" * 10))
        self.assertRaises(self.UnsupportedOperation, bufio.tell)
        self.assertRaises(self.UnsupportedOperation, bufio.seek, 0)
        bufio.read(1)
        self.assertRaises(self.UnsupportedOperation, bufio.seek, 0)
        self.assertRaises(self.UnsupportedOperation, bufio.tell)

    def test_misbehaved_io(self):
        rawio = self.MisbehavedRawIO((b"abc", b"d", b"efg"))
        bufio = self.tp(rawio)
        self.assertRaises(OSError, bufio.seek, 0)
        self.assertRaises(OSError, bufio.tell)

        # Silence destructor error
        bufio.close = lambda: None

    def test_no_extraneous_read(self):
        # Issue #9550; when the raw IO object has satisfied the read request,
        # we should not issue any additional reads, otherwise it may block
        # (e.g. socket).
        bufsize = 16
        for n in (2, bufsize - 1, bufsize, bufsize + 1, bufsize * 2):
            rawio = self.MockRawIO([b"x" * n])
            bufio = self.tp(rawio, bufsize)
            self.assertEqual(bufio.read(n), b"x" * n)
            # Simple case: one raw read is enough to satisfy the request.
            self.assertEqual(rawio._extraneous_reads, 0,
                             "failed for {}: {} != 0".format(n, rawio._extraneous_reads))
            # A more complex case where two raw reads are needed to satisfy
            # the request.
            rawio = self.MockRawIO([b"x" * (n - 1), b"x"])
            bufio = self.tp(rawio, bufsize)
            self.assertEqual(bufio.read(n), b"x" * n)
            self.assertEqual(rawio._extraneous_reads, 0,
                             "failed for {}: {} != 0".format(n, rawio._extraneous_reads))

    def test_read_on_closed(self):
        # Issue #23796
        b = self.BufferedReader(self.BytesIO(b"12"))
        b.read(1)
        b.close()
        with self.subTest('peek'):
            self.assertRaises(ValueError, b.peek)
        with self.subTest('read1'):
            self.assertRaises(ValueError, b.read1, 1)
        with self.subTest('read'):
            self.assertRaises(ValueError, b.read)
        with self.subTest('readinto'):
            self.assertRaises(ValueError, b.readinto, bytearray())
        with self.subTest('readinto1'):
            self.assertRaises(ValueError, b.readinto1, bytearray())
        with self.subTest('flush'):
            self.assertRaises(ValueError, b.flush)
        with self.subTest('truncate'):
            self.assertRaises(ValueError, b.truncate)
        with self.subTest('seek'):
            self.assertRaises(ValueError, b.seek, 0)

    def test_truncate_on_read_only(self):
        rawio = self.MockFileIO(b"abc")
        bufio = self.tp(rawio)
        self.assertFalse(bufio.writable())
        self.assertRaises(self.UnsupportedOperation, bufio.truncate)
        self.assertRaises(self.UnsupportedOperation, bufio.truncate, 0)

    def test_tell_character_device_file(self):
        # GH-95782
        # For the (former) bug in BufferedIO to manifest, the wrapped IO obj
        # must be able to produce at least 2 bytes.
        raw = self.MockCharPseudoDevFileIO(b"12")
        buf = self.tp(raw)
        self.assertEqual(buf.tell(), 0)
        self.assertEqual(buf.read(1), b"1")
        self.assertEqual(buf.tell(), 0)

    def test_seek_character_device_file(self):
        raw = self.MockCharPseudoDevFileIO(b"12")
        buf = self.tp(raw)
        self.assertEqual(buf.seek(0, io.SEEK_CUR), 0)
        self.assertEqual(buf.seek(1, io.SEEK_SET), 0)
        self.assertEqual(buf.seek(0, io.SEEK_CUR), 0)
        self.assertEqual(buf.read(1), b"1")

        # In the C implementation, tell() sets the BufferedIO's abs_pos to 0,
        # which means that the next seek() could return a negative offset if it
        # does not sanity-check:
        self.assertEqual(buf.tell(), 0)
        self.assertEqual(buf.seek(0, io.SEEK_CUR), 0)


class CBufferedReaderTest(BufferedReaderTest, SizeofTest, CTestCase):
    tp = io.BufferedReader

    def test_read_memory_error_loses_nothing(self):
        # A read failing to allocate its result leaves the data for the
        # next read.
        _testcapi = import_helper.import_module('_testcapi')
        data = b'01234\n6789\n'
        for meth in ('read', 'read1', 'readline', 'peek'):
            with self.subTest(meth=meth):
                bufio = self.tp(self.MockRawIO([data]), 16)
                self.assertEqual(bufio.read(1), b'0')
                _testcapi.set_nomemory(0, 1)
                try:
                    res = getattr(bufio, meth)(3)
                except MemoryError:
                    res = b''
                finally:
                    _testcapi.remove_mem_hooks()
                if meth == 'peek':
                    res = b''
                self.assertEqual(res + bufio.read(), data[1:])

    @threading_helper.requires_working_threading()
    def test_concurrent_reads_keep_records_whole(self):
        # A readline() or readinto() needing more than the buffer holds must
        # not let another thread take the rest of its data while it waits
        # for the lock.
        records = [b"%015d\n" % i for i in range(4000)]
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        with self.open(os_helper.TESTFN, "wb") as f:
            f.write(b"".join(records))

        def readline(bufio):
            return bufio.readline()

        def readinto(bufio):
            b = bytearray(16)
            return bytes(b[:bufio.readinto(b)])

        for read_record in (readline, readinto):
            with self.subTest(read=read_record.__name__):
                got = []
                raw = self.FileIO(os_helper.TESTFN, "rb")
                with self.tp(raw, 24) as bufio:
                    def reader():
                        while record := read_record(bufio):
                            got.append(record)

                    threads = [threading.Thread(target=reader)
                               for _ in range(8)]
                    with threading_helper.start_threads(threads):
                        pass
                self.assertEqual(sorted(got), records)

    def test_initialization(self):
        rawio = self.MockRawIO([b"abc"])
        bufio = self.tp(rawio)
        self.assertRaises(ValueError, bufio.__init__, rawio, buffer_size=0)
        self.assertRaises(ValueError, bufio.read)
        self.assertRaises(ValueError, bufio.__init__, rawio, buffer_size=-16)
        self.assertRaises(ValueError, bufio.read)
        self.assertRaises(ValueError, bufio.__init__, rawio, buffer_size=-1)
        self.assertRaises(ValueError, bufio.read)

    def test_misbehaved_io_read(self):
        rawio = self.MisbehavedRawIO((b"abc", b"d", b"efg"))
        bufio = self.tp(rawio)
        # _pyio.BufferedReader seems to implement reading different, so that
        # checking this is not so easy.
        self.assertRaises(OSError, bufio.read, 10)

    def test_garbage_collection(self):
        # C BufferedReader objects are collected.
        # The Python version has __del__, so it ends into gc.garbage instead
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        # Note that using warnings_helper.check_warnings() will keep the
        # file alive due to the `source` argument to warn().  So, use
        # catch_warnings() instead.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)
            rawio = self.FileIO(os_helper.TESTFN, "w+b")
            f = self.tp(rawio)
            f.f = f
            wr = weakref.ref(f)
            del f
            support.gc_collect()
        self.assertIsNone(wr(), wr)

    def test_args_error(self):
        # Issue #17275
        with self.assertRaisesRegex(TypeError, "BufferedReader"):
            self.tp(self.BytesIO(), 1024, 1024, 1024)

    def test_bad_readinto_value(self):
        rawio = self.tp(self.BytesIO(b"12"))
        rawio.readinto = lambda buf: -1
        bufio = self.tp(rawio)
        with self.assertRaises(OSError) as cm:
            bufio.readline()
        self.assertIsNone(cm.exception.__cause__)

    def test_bad_readinto_type(self):
        rawio = self.tp(self.BytesIO(b"12"))
        rawio.readinto = lambda buf: b''
        bufio = self.tp(rawio)
        with self.assertRaises(OSError) as cm:
            bufio.readline()
        self.assertIsInstance(cm.exception.__cause__, TypeError)

    @unittest.skipUnless(sys.maxsize > 2**32, 'requires 64bit platform')
    @unittest.skipIf(check_sanitizer(thread=True),
                     'ThreadSanitizer aborts on huge allocations (exit code 66).')
    def test_read1_error_does_not_cause_reentrant_failure(self):
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        with self.open(os_helper.TESTFN, "wb") as f:
            f.write(b"hello")

        with self.open(os_helper.TESTFN, "rb", buffering=0) as raw:
            bufio = self.tp(raw, buffer_size=8)
            # To request a size that is far too huge to ever be satisfied,
            # so that the internal buffer allocation reliably fails with MemoryError.
            huge = sys.maxsize // 2 + 1
            with self.assertRaises(MemoryError):
                bufio.read1(huge)

            # Used to crash before gh-143689:
            self.assertEqual(bufio.read1(1), b"h")


class PyBufferedReaderTest(BufferedReaderTest, PyTestCase):
    tp = pyio.BufferedReader


class BufferedWriterTest(CommonBufferedTests):
    write_mode = "wb"

    def test_constructor(self):
        rawio = self.MockRawIO()
        bufio = self.tp(rawio)
        bufio.__init__(rawio)
        bufio.__init__(rawio, buffer_size=1024)
        bufio.__init__(rawio, buffer_size=16)
        self.assertEqual(3, bufio.write(b"abc"))
        bufio.flush()
        self.assertRaises(ValueError, bufio.__init__, rawio, buffer_size=0)
        self.assertRaises(ValueError, bufio.__init__, rawio, buffer_size=-16)
        self.assertRaises(ValueError, bufio.__init__, rawio, buffer_size=-1)
        bufio.__init__(rawio)
        self.assertEqual(3, bufio.write(b"ghi"))
        bufio.flush()
        self.assertEqual(b"".join(rawio._write_stack), b"abcghi")

    def test_uninitialized(self):
        bufio = self.tp.__new__(self.tp)
        del bufio
        bufio = self.tp.__new__(self.tp)
        self.assertRaisesRegex((ValueError, AttributeError),
                               'uninitialized|has no attribute',
                               bufio.write, b'')
        bufio.__init__(self.MockRawIO())
        self.assertEqual(bufio.write(b''), 0)

    def test_reinit_writes_pending(self):
        # __init__() again writes what is pending to the raw stream it was
        # written to, as FileIO.__init__() closes the file it had, instead
        # of dropping it.
        if not self.is_nibbler:
            self.skipTest("__init__() drops pending writes")
        rawio = self.MockRawIO()
        bufio = self.tp(rawio, 16)
        bufio.write(b"abc")
        rawio2 = self.MockRawIO()
        bufio.__init__(rawio2, 16)
        self.assertEqual(b"".join(rawio._write_stack), b"abc")
        self.assertIs(bufio.raw, rawio2)
        bufio.write(b"def")
        bufio.flush()
        self.assertEqual(b"".join(rawio2._write_stack), b"def")

    def test_reinit_write_error(self):
        # If they can't be written, __init__() raises and leaves the object
        # as it was, with its raw stream and what is pending.
        if not self.is_nibbler:
            self.skipTest("__init__() drops pending writes")
        rawio = self.MockRawIO()
        bufio = self.tp(rawio, 16)
        bufio.write(b"abc")
        rawio.write = lambda b: 1 / 0
        self.assertRaises(ZeroDivisionError, bufio.__init__,
                          self.MockRawIO(), 16)
        self.assertIs(bufio.raw, rawio)
        del rawio.write
        bufio.flush()
        self.assertEqual(b"".join(rawio._write_stack), b"abc")

    def test_reinit_closed_raw(self):
        # What is pending for a raw stream closed meanwhile is dropped with
        # a ResourceWarning, rather than written to the closed stream (or
        # failing every __init__() over a FileIO).
        if not self.is_nibbler:
            self.skipTest("__init__() drops pending writes")
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        def mock():
            return self.MockRawIO()
        def fileio():
            return self.FileIO(os_helper.TESTFN, "w+")
        for make in (mock, fileio):
            with self.subTest(make.__name__):
                rawio = make()
                bufio = self.tp(rawio, 16)
                bufio.write(b"abc")
                rawio.close()
                rawio2 = self.MockRawIO()
                with self.assertWarnsRegex(ResourceWarning,
                                           "discarded 3 buffered bytes"):
                    bufio.__init__(rawio2, 16)
                if make is mock:
                    self.assertEqual(rawio._write_stack, [])
                self.assertIs(bufio.raw, rawio2)
                bufio.write(b"def")
                bufio.flush()
                self.assertEqual(rawio2._write_stack, [b"def"])

    def test_detach_flush(self):
        raw = self.MockRawIO()
        buf = self.tp(raw)
        buf.write(b"howdy!")
        self.assertFalse(raw._write_stack)
        buf.detach()
        self.assertEqual(raw._write_stack, [b"howdy!"])

    def test_write(self):
        # Write to the buffered IO but don't overflow the buffer.
        writer = self.MockRawIO()
        bufio = self.tp(writer, 8)
        bufio.write(b"abc")
        self.assertFalse(writer._write_stack)
        buffer = bytearray(b"def")
        bufio.write(buffer)
        buffer[:] = b"***"  # Overwrite our copy of the data
        bufio.flush()
        self.assertEqual(b"".join(writer._write_stack), b"abcdef")

    def test_write_overflow(self):
        writer = self.MockRawIO()
        bufio = self.tp(writer, 8)
        contents = b"abcdefghijklmnop"
        for n in range(0, len(contents), 3):
            bufio.write(contents[n:n+3])
        flushed = b"".join(writer._write_stack)
        # At least (total - 8) bytes were implicitly flushed, perhaps more
        # depending on the implementation.
        self.assertStartsWith(flushed, contents[:-8])

    def check_writes(self, intermediate_func):
        # Lots of writes, test the flushed output is as expected.
        contents = bytes(range(256)) * 1000
        n = 0
        writer = self.MockRawIO()
        bufio = self.tp(writer, 13)
        # Generator of write sizes: repeat each N 15 times then proceed to N+1
        def gen_sizes():
            for size in count(1):
                for i in range(15):
                    yield size
        sizes = gen_sizes()
        while n < len(contents):
            size = min(next(sizes), len(contents) - n)
            self.assertEqual(bufio.write(contents[n:n+size]), size)
            intermediate_func(bufio)
            n += size
        bufio.flush()
        self.assertEqual(contents, b"".join(writer._write_stack))

    def test_writes(self):
        self.check_writes(lambda bufio: None)

    def test_writes_and_flushes(self):
        self.check_writes(lambda bufio: bufio.flush())

    def test_writes_and_seeks(self):
        def _seekabs(bufio):
            pos = bufio.tell()
            bufio.seek(pos + 1, 0)
            bufio.seek(pos - 1, 0)
            bufio.seek(pos, 0)
        self.check_writes(_seekabs)
        def _seekrel(bufio):
            pos = bufio.seek(0, 1)
            bufio.seek(+1, 1)
            bufio.seek(-1, 1)
            bufio.seek(pos, 0)
        self.check_writes(_seekrel)

    def test_writes_and_truncates(self):
        self.check_writes(lambda bufio: bufio.truncate(bufio.tell()))

    def test_write_non_blocking(self):
        raw = self.MockNonBlockWriterIO()
        bufio = self.tp(raw, 8)

        self.assertEqual(bufio.write(b"abcd"), 4)
        self.assertEqual(bufio.write(b"efghi"), 5)
        # 1 byte will be written, the rest will be buffered
        raw.block_on(b"k")
        self.assertEqual(bufio.write(b"jklmn"), 5)

        # 8 bytes will be written, 8 will be buffered and the rest will be lost
        raw.block_on(b"0")
        try:
            bufio.write(b"opqrwxyz0123456789")
        except self.BlockingIOError as e:
            written = e.characters_written
        else:
            self.fail("BlockingIOError should have been raised")
        self.assertEqual(written, 16)
        self.assertEqual(raw.pop_written(),
            b"abcdefghijklmnopqrwxyz")

        self.assertEqual(bufio.write(b"ABCDEFGHI"), 9)
        s = raw.pop_written()
        # Previously buffered bytes were flushed
        self.assertStartsWith(s, b"01234567A")

    def test_write_and_rewind(self):
        raw = self.BytesIO()
        bufio = self.tp(raw, 4)
        self.assertEqual(bufio.write(b"abcdef"), 6)
        self.assertEqual(bufio.tell(), 6)
        bufio.seek(0, 0)
        self.assertEqual(bufio.write(b"XY"), 2)
        bufio.seek(6, 0)
        self.assertEqual(raw.getvalue(), b"XYcdef")
        self.assertEqual(bufio.write(b"123456"), 6)
        bufio.flush()
        self.assertEqual(raw.getvalue(), b"XYcdef123456")

    def test_flush(self):
        writer = self.MockRawIO()
        bufio = self.tp(writer, 8)
        bufio.write(b"abc")
        bufio.flush()
        self.assertEqual(b"abc", writer._write_stack[0])

    def test_writelines(self):
        l = [b'ab', b'cd', b'ef']
        writer = self.MockRawIO()
        bufio = self.tp(writer, 8)
        bufio.writelines(l)
        bufio.flush()
        self.assertEqual(b''.join(writer._write_stack), b'abcdef')

    def test_writelines_userlist(self):
        l = UserList([b'ab', b'cd', b'ef'])
        writer = self.MockRawIO()
        bufio = self.tp(writer, 8)
        bufio.writelines(l)
        bufio.flush()
        self.assertEqual(b''.join(writer._write_stack), b'abcdef')

    def test_writelines_error(self):
        writer = self.MockRawIO()
        bufio = self.tp(writer, 8)
        self.assertRaises(TypeError, bufio.writelines, [1, 2, 3])
        self.assertRaises(TypeError, bufio.writelines, None)
        self.assertRaises(TypeError, bufio.writelines, 'abc')

    def test_destructor(self):
        writer = self.MockRawIO()
        bufio = self.tp(writer, 8)
        bufio.write(b"abc")
        del bufio
        support.gc_collect()
        self.assertEqual(b"abc", writer._write_stack[0])

    def test_truncate(self):
        # Truncate implicitly flushes the buffer.
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        with self.open(os_helper.TESTFN, self.write_mode, buffering=0) as raw:
            bufio = self.tp(raw, 8)
            bufio.write(b"abcdef")
            self.assertEqual(bufio.truncate(3), 3)
            self.assertEqual(bufio.tell(), 6)
        with self.open(os_helper.TESTFN, "rb", buffering=0) as f:
            self.assertEqual(f.read(), b"abc")

    def test_truncate_after_write(self):
        # Ensure that truncate preserves the file position after
        # writes longer than the buffer size.
        # Issue: https://bugs.python.org/issue32228
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        with self.open(os_helper.TESTFN, "wb") as f:
            # Fill with some buffer
            f.write(b'\x00' * 10000)
        buffer_sizes = [8192, 4096, 200]
        for buffer_size in buffer_sizes:
            with self.open(os_helper.TESTFN, "r+b", buffering=buffer_size) as f:
                f.write(b'\x00' * (buffer_size + 1))
                # After write write_pos and write_end are set to 0
                f.read(1)
                # read operation makes sure that pos != raw_pos
                f.truncate()
                self.assertEqual(f.tell(), buffer_size + 2)

    @threading_helper.requires_working_threading()
    @support.requires_resource('cpu')
    def test_threads(self):
        try:
            # Write out many bytes from many threads and test they were
            # all flushed.
            N = 1000
            contents = bytes(range(256)) * N
            sizes = cycle([1, 19])
            n = 0
            queue = deque()
            while n < len(contents):
                size = next(sizes)
                queue.append(contents[n:n+size])
                n += size
            del contents
            # We use a real file object because it allows us to
            # exercise situations where the GIL is released before
            # writing the buffer to the raw streams. This is in addition
            # to concurrency issues due to switching threads in the middle
            # of Python code.
            with self.open(os_helper.TESTFN, self.write_mode, buffering=0) as raw:
                bufio = self.tp(raw, 8)
                errors = []
                def f():
                    try:
                        while True:
                            try:
                                s = queue.popleft()
                            except IndexError:
                                return
                            bufio.write(s)
                    except Exception as e:
                        errors.append(e)
                        raise
                threads = [threading.Thread(target=f) for x in range(20)]
                with threading_helper.start_threads(threads):
                    time.sleep(0.02) # yield
                self.assertFalse(errors,
                    "the following exceptions were caught: %r" % errors)
                bufio.close()
            with self.open(os_helper.TESTFN, "rb") as f:
                s = f.read()
            for i in range(256):
                self.assertEqual(s.count(bytes([i])), N)
        finally:
            os_helper.unlink(os_helper.TESTFN)

    @threading_helper.requires_working_threading()
    def test_tell_racing_writes(self):
        # tell() racing write()s returns a position the stream actually
        # passed through (a whole number of records), never a mix of the
        # raw position and the pending buffer seen at different times.
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        record = b"abcdefg"
        nwriters, nrecords = 4, 2000
        with self.open(os_helper.TESTFN, self.write_mode, buffering=0) as raw:
            # A buffer size that isn't a multiple of the record size, so
            # that flushes split records.
            bufio = self.tp(raw, 100)
            done = threading.Event()
            bad = []

            def writer():
                for _ in range(nrecords):
                    bufio.write(record)

            def teller():
                last = 0
                while not done.is_set():
                    pos = bufio.tell()
                    if pos % len(record) or pos < last:
                        bad.append((last, pos))
                    last = pos

            writers = [threading.Thread(target=writer)
                       for _ in range(nwriters)]
            tellers = [threading.Thread(target=teller) for _ in range(2)]
            with threading_helper.start_threads(tellers):
                with threading_helper.start_threads(writers):
                    pass
                done.set()
            self.assertEqual(bad, [])
            self.assertEqual(bufio.tell(), nwriters * nrecords * len(record))
            bufio.close()

    def test_append_mode_tell_after_write(self):
        # gh-80592: a write to a raw file in append mode goes to the end of
        # the file, so tell() is the end of the file after it.
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        with self.open(os_helper.TESTFN, "wb") as f:
            f.write(b"abc")
        with self.tp(self.FileIO(os_helper.TESTFN,
                                 self.write_mode.replace("w", "a"))) as f:
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

    def test_misbehaved_io(self):
        rawio = self.MisbehavedRawIO()
        bufio = self.tp(rawio, 5)
        self.assertRaises(OSError, bufio.seek, 0)
        self.assertRaises(OSError, bufio.tell)
        self.assertRaises(OSError, bufio.write, b"abcdef")

        # Silence destructor error
        bufio.close = lambda: None

    def test_max_buffer_size_removal(self):
        with self.assertRaises(TypeError):
            self.tp(self.MockRawIO(), 8, 12)

    def scripted_raw(self, plan):
        # A raw stream whose write() follows plan, one step per call: an int
        # n writes at most n bytes; an exception instance is raised.  Once
        # plan is used up, writes are whole.
        class ScriptedRawIO(self.MockRawIO):
            def write(self, b):
                step = plan.pop(0) if plan else None
                if isinstance(step, BaseException):
                    raise step
                with memoryview(b) as view:
                    n = len(view) if step is None else min(step, len(view))
                    self._write_stack.append(bytes(view[:n]))
                return n
        return ScriptedRawIO()

    def test_write_error_keeps_rest_that_fits(self):
        # An error (other than BlockingIOError) after part of write()'s
        # data was written keeps the rest pending when it fits in the
        # buffer: write() raises, and flush() writes the rest.
        data = bytes(range(100))
        raw = self.scripted_raw([36, OSError(errno.EIO, "EIO")])
        bufio = self.tp(raw, 64)
        self.addCleanup(bufio.close)
        with self.assertRaises(OSError) as cm:
            bufio.write(data)
        self.assertNotIsInstance(cm.exception, BlockingIOError)
        self.assertEqual(cm.exception.errno, errno.EIO)
        self.assertEqual(cm.exception.characters_written, 100)
        self.assertEqual(b"".join(raw._write_stack), data[:36])
        bufio.flush()
        self.assertEqual(b"".join(raw._write_stack), data)

    def test_write_error_keeps_what_fits(self):
        # When the rest doesn't fit, as much of it as fits is kept, and
        # characters_written says how much of the data was accepted
        # (written or kept): the caller writes the rest again.
        data = bytes(range(200))
        raw = self.scripted_raw([30, TimeoutError("timed out")])
        bufio = self.tp(raw, 64)
        self.addCleanup(bufio.close)
        with self.assertRaises(TimeoutError) as cm:
            bufio.write(data)
        n = cm.exception.characters_written
        self.assertEqual(n, 30 + 64)
        bufio.write(data[n:])
        bufio.flush()
        self.assertEqual(b"".join(raw._write_stack), data)

    def test_write_error_before_data_takes_none(self):
        # An error while writing the data pending before write()'s data
        # takes none of it: write() raises without characters_written,
        # and only the earlier data stays pending.
        raw = self.scripted_raw([2, OSError(errno.EIO, "EIO")])
        bufio = self.tp(raw, 64)
        self.addCleanup(bufio.close)
        bufio.write(b"abc")
        with self.assertRaises(OSError) as cm:
            bufio.write(b"x" * 100)
        self.assertEqual(cm.exception.errno, errno.EIO)
        self.assertNotHasAttr(cm.exception, "characters_written")
        bufio.flush()
        self.assertEqual(b"".join(raw._write_stack), b"abc")

    def test_write_interrupted_keeps_rest(self):
        # The same for an exception that isn't an OSError (such as one a
        # signal handler raises): it gets characters_written too.
        class Interrupt(Exception):
            pass
        data = bytes(range(100))
        raw = self.scripted_raw([36, Interrupt()])
        bufio = self.tp(raw, 64)
        self.addCleanup(bufio.close)
        with self.assertRaises(Interrupt) as cm:
            bufio.write(data)
        self.assertEqual(cm.exception.characters_written, 100)
        bufio.flush()
        self.assertEqual(b"".join(raw._write_stack), data)

    def test_write_interrupted_refusing_attribute(self):
        class Interrupt(Exception):
            characters_written = property()
        raw = self.scripted_raw([30, Interrupt()])
        bufio = self.tp(raw, 64)
        self.addCleanup(bufio.close)
        self.assertRaises(Interrupt, bufio.write, bytes(range(100)))

    def test_write_interrupted_says_what_was_taken(self):
        # When the rest doesn't fit, a KeyboardInterrupt says how much of
        # the data was taken: writing the rest again duplicates nothing.
        data = bytes(range(100))
        raw = self.scripted_raw([30, KeyboardInterrupt()])
        bufio = self.tp(raw, 64)
        self.addCleanup(bufio.close)
        with self.assertRaises(KeyboardInterrupt) as cm:
            bufio.write(data)
        n = cm.exception.characters_written
        self.assertEqual(n, 30 + 64)
        bufio.write(data[n:])
        bufio.flush()
        self.assertEqual(b"".join(raw._write_stack), data)

    def test_raw_write_no_progress(self):
        # gh-158414: retrying a raw write() that returns 0 could loop
        # forever, so flush() and write() raise OSError instead.
        class ZeroWriter(self.MockRawIO):
            zeros = 10

            def write(self, b):
                if self.zeros:
                    self.zeros -= 1
                    return 0
                return super().write(b)
        raw = ZeroWriter()
        with self.tp(raw, 8) as bufio:
            bufio.write(b"abc")
            with self.assertRaisesRegex(OSError, "no progress"):
                bufio.flush()
            self.assertEqual(raw.zeros, 9)
            raw.zeros = 10
            with self.assertRaisesRegex(OSError, "no progress"):
                bufio.write(b"x" * 20)
            self.assertEqual(raw.zeros, 9)
            # The pending data was kept, and none of write()'s.
            raw.zeros = 0
            bufio.flush()
            self.assertEqual(b"".join(raw._write_stack), b"abc")

    def test_close_blocked_flush_warns(self):
        # When the final flush would block, close() still closes the raw
        # stream and raises, but warns that the pending data is discarded.
        raw = self.MockNonBlockWriterIO()
        bufio = self.tp(raw, 8)
        bufio.write(b"abc")
        raw.block_on(b"b")
        with self.assertWarnsRegex(ResourceWarning,
                                   "discarded 2 buffered bytes"):
            with self.assertRaises(self.BlockingIOError):
                bufio.close()
        self.assertTrue(bufio.closed)
        self.assertEqual(raw.pop_written(), b"a")

    def test_write_error_on_close(self):
        raw = self.MockRawIO()
        def bad_write(b):
            raise OSError()
        raw.write = bad_write
        b = self.tp(raw)
        b.write(b'spam')
        self.assertRaises(OSError, b.close) # exception not swallowed
        self.assertTrue(b.closed)

    @threading_helper.requires_working_threading()
    def test_slow_close_from_thread(self):
        # Issue #31976
        rawio = self.SlowFlushRawIO()
        bufio = self.tp(rawio, 8)
        t = threading.Thread(target=bufio.close)
        t.start()
        rawio.in_flush.wait()
        self.assertRaises(ValueError, bufio.write, b'spam')
        self.assertTrue(bufio.closed)
        t.join()


class CBufferedWriterTest(BufferedWriterTest, SizeofTest, CTestCase):
    tp = io.BufferedWriter

    def test_readall(self):
        if not self.is_nibbler:
            self.skipTest("no readall()")
        bufio = self.tp(self.MockRawIO())
        self.assertRaises(self.UnsupportedOperation, bufio.readall)

    def test_initialization(self):
        rawio = self.MockRawIO()
        bufio = self.tp(rawio)
        self.assertRaises(ValueError, bufio.__init__, rawio, buffer_size=0)
        self.assertRaises(ValueError, bufio.write, b"def")
        self.assertRaises(ValueError, bufio.__init__, rawio, buffer_size=-16)
        self.assertRaises(ValueError, bufio.write, b"def")
        self.assertRaises(ValueError, bufio.__init__, rawio, buffer_size=-1)
        self.assertRaises(ValueError, bufio.write, b"def")

    def test_garbage_collection(self):
        # C BufferedWriter objects are collected, and collecting them flushes
        # all data to disk.
        # The Python version has __del__, so it ends into gc.garbage instead
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        # Note that using warnings_helper.check_warnings() will keep the
        # file alive due to the `source` argument to warn().  So, use
        # catch_warnings() instead.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)
            rawio = self.FileIO(os_helper.TESTFN, "w+b")
            f = self.tp(rawio)
            f.write(b"123xxx")
            f.x = f
            wr = weakref.ref(f)
            del f
            support.gc_collect()
        self.assertIsNone(wr(), wr)
        with self.open(os_helper.TESTFN, "rb") as f:
            self.assertEqual(f.read(), b"123xxx")

    def test_args_error(self):
        # Issue #17275
        with self.assertRaisesRegex(TypeError, "BufferedWriter"):
            self.tp(self.BytesIO(), 1024, 1024, 1024)

    @threading_helper.requires_working_threading()
    def test_write_detach_race(self):
        # write() waiting for the buffered lock while detach() ran used to
        # use the cleared raw stream: a segfault.  Waiting for the lock
        # releases the GIL, so this crashed GIL builds too.
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        for _ in range(50):
            bufio = self.tp(self.FileIO(os_helper.TESTFN, "w"), 64)
            go = threading.Event()

            def writer():
                go.wait()
                for i in range(500):
                    try:
                        bufio.write(b"x" * (i % 100))
                    except ValueError:  # detached
                        return

            def detacher():
                go.wait()
                bufio.detach().close()

            threads = [threading.Thread(target=func)
                       for func in [writer] * 3 + [detacher]]
            with threading_helper.start_threads(threads):
                go.set()

    def test_non_boolean_closed_attr(self):
        # gh-140650: check TypeError is raised
        class MockRawIOWithoutClosed(self.MockRawIO):
            closed = NotImplemented

        bufio = self.tp(MockRawIOWithoutClosed())
        self.assertRaises(TypeError, bufio.write, b"")
        self.assertRaises(TypeError, bufio.flush)
        self.assertRaises(TypeError, bufio.close)

    def test_closed_attr_raises(self):
        class MockRawIOClosedRaises(self.MockRawIO):
            @property
            def closed(self):
                raise ValueError("test")

        bufio = self.tp(MockRawIOClosedRaises())
        self.assertRaisesRegex(ValueError, "test", bufio.write, b"")
        self.assertRaisesRegex(ValueError, "test", bufio.flush)
        self.assertRaisesRegex(ValueError, "test", bufio.close)


class PyBufferedWriterTest(BufferedWriterTest, PyTestCase):
    tp = pyio.BufferedWriter

class BufferedRWPairTest:

    def test_constructor(self):
        pair = self.tp(self.MockRawIO(), self.MockRawIO())
        self.assertFalse(pair.closed)

    def test_uninitialized(self):
        pair = self.tp.__new__(self.tp)
        del pair
        pair = self.tp.__new__(self.tp)
        self.assertRaisesRegex((ValueError, AttributeError),
                               'uninitialized|has no attribute',
                               pair.read, 0)
        self.assertRaisesRegex((ValueError, AttributeError),
                               'uninitialized|has no attribute',
                               pair.write, b'')
        pair.__init__(self.MockRawIO(), self.MockRawIO())
        self.assertEqual(pair.read(0), b'')
        self.assertEqual(pair.write(b''), 0)

    def test_detach(self):
        pair = self.tp(self.MockRawIO(), self.MockRawIO())
        self.assertRaises(self.UnsupportedOperation, pair.detach)

    def test_constructor_max_buffer_size_removal(self):
        with self.assertRaises(TypeError):
            self.tp(self.MockRawIO(), self.MockRawIO(), 8, 12)

    def test_constructor_with_not_readable(self):
        class NotReadable(self.MockRawIO):
            def readable(self):
                return False

        self.assertRaises(OSError, self.tp, NotReadable(), self.MockRawIO())

    def test_constructor_with_not_writeable(self):
        class NotWriteable(self.MockRawIO):
            def writable(self):
                return False

        self.assertRaises(OSError, self.tp, self.MockRawIO(), NotWriteable())

    def test_read(self):
        pair = self.tp(self.BytesIO(b"abcdef"), self.MockRawIO())

        self.assertEqual(pair.read(3), b"abc")
        self.assertEqual(pair.read(1), b"d")
        self.assertEqual(pair.read(), b"ef")
        pair = self.tp(self.BytesIO(b"abc"), self.MockRawIO())
        self.assertEqual(pair.read(None), b"abc")

    def test_readall(self):
        if not self.is_nibbler:
            self.skipTest("no readall()")
        pair = self.tp(self.BytesIO(b"abcdef"), self.MockRawIO())
        self.assertEqual(pair.read(2), b"ab")
        self.assertEqual(pair.readall(), b"cdef")
        self.assertEqual(pair.readall(), b"")

    def test_readlines(self):
        pair = lambda: self.tp(self.BytesIO(b"abc\ndef\nh"), self.MockRawIO())
        self.assertEqual(pair().readlines(), [b"abc\n", b"def\n", b"h"])
        self.assertEqual(pair().readlines(), [b"abc\n", b"def\n", b"h"])
        self.assertEqual(pair().readlines(5), [b"abc\n", b"def\n"])

    def test_readline_would_block(self):
        # readline() is the reader's: when the raw stream would block, it
        # returns None and keeps a partial line for the next call.
        raw = self.MockRawIO((b"ab", None, b"c\nd", None, None, b"e"))
        pair = self.tp(raw, self.MockRawIO())
        self.assertIsNone(pair.readline())
        self.assertEqual(pair.readline(), b"abc\n")
        self.assertIsNone(pair.readline())
        self.assertRaises(BlockingIOError, next, pair)
        self.assertEqual(pair.readline(), b"de")
        self.assertEqual(pair.readline(), b"")

    def test_read1(self):
        # .read1() is delegated to the underlying reader object, so this test
        # can be shallow.
        pair = self.tp(self.BytesIO(b"abcdef"), self.MockRawIO())

        self.assertEqual(pair.read1(3), b"abc")
        self.assertEqual(pair.read1(), b"def")

    def test_readinto(self):
        for method in ("readinto", "readinto1"):
            with self.subTest(method):
                pair = self.tp(self.BytesIO(b"abcdef"), self.MockRawIO())

                data = byteslike(b'\0' * 5)
                self.assertEqual(getattr(pair, method)(data), 5)
                self.assertEqual(bytes(data), b"abcde")

        # gh-138720: C BufferedRWPair would destruct in a bad order resulting in
        # an unraisable exception.
        support.gc_collect()

    def test_write(self):
        w = self.MockRawIO()
        pair = self.tp(self.MockRawIO(), w)

        pair.write(b"abc")
        pair.flush()
        buffer = bytearray(b"def")
        pair.write(buffer)
        buffer[:] = b"***"  # Overwrite our copy of the data
        pair.flush()
        self.assertEqual(w._write_stack, [b"abc", b"def"])

    def test_peek(self):
        pair = self.tp(self.BytesIO(b"abcdef"), self.MockRawIO())

        self.assertStartsWith(pair.peek(3), b"abc")
        self.assertEqual(pair.read(3), b"abc")

    def test_readable(self):
        pair = self.tp(self.MockRawIO(), self.MockRawIO())
        self.assertTrue(pair.readable())

    def test_writeable(self):
        pair = self.tp(self.MockRawIO(), self.MockRawIO())
        self.assertTrue(pair.writable())

    def test_seekable(self):
        # BufferedRWPairs are never seekable, even if their readers and writers
        # are.
        pair = self.tp(self.MockRawIO(), self.MockRawIO())
        self.assertFalse(pair.seekable())

    # .flush() is delegated to the underlying writer object and has been
    # tested in the test_write method.

    def test_close_and_closed(self):
        pair = self.tp(self.MockRawIO(), self.MockRawIO())
        self.assertFalse(pair.closed)
        pair.close()
        self.assertTrue(pair.closed)

    def test_reader_close_error_on_close(self):
        def reader_close():
            reader_non_existing
        reader = self.MockRawIO()
        reader.close = reader_close
        writer = self.MockRawIO()
        pair = self.tp(reader, writer)
        with self.assertRaises(NameError) as err:
            pair.close()
        self.assertIn('reader_non_existing', str(err.exception))
        self.assertTrue(pair.closed)
        self.assertFalse(reader.closed)
        self.assertTrue(writer.closed)

        # Silence destructor error
        reader.close = lambda: None

    def test_writer_close_error_on_close(self):
        def writer_close():
            writer_non_existing
        reader = self.MockRawIO()
        writer = self.MockRawIO()
        writer.close = writer_close
        pair = self.tp(reader, writer)
        with self.assertRaises(NameError) as err:
            pair.close()
        self.assertIn('writer_non_existing', str(err.exception))
        self.assertFalse(pair.closed)
        self.assertTrue(reader.closed)
        self.assertFalse(writer.closed)

        # Silence destructor error
        writer.close = lambda: None
        writer = None

        # Ignore BufferedWriter (of the BufferedRWPair) unraisable exception
        with support.catch_unraisable_exception():
            # Ignore BufferedRWPair unraisable exception
            with support.catch_unraisable_exception():
                pair = None
                support.gc_collect()
            support.gc_collect()

    def test_reader_writer_close_error_on_close(self):
        def reader_close():
            reader_non_existing
        def writer_close():
            writer_non_existing
        reader = self.MockRawIO()
        reader.close = reader_close
        writer = self.MockRawIO()
        writer.close = writer_close
        pair = self.tp(reader, writer)
        with self.assertRaises(NameError) as err:
            pair.close()
        self.assertIn('reader_non_existing', str(err.exception))
        self.assertIsInstance(err.exception.__context__, NameError)
        self.assertIn('writer_non_existing', str(err.exception.__context__))
        self.assertFalse(pair.closed)
        self.assertFalse(reader.closed)
        self.assertFalse(writer.closed)

        # Silence destructor error
        reader.close = lambda: None
        writer.close = lambda: None

    def test_isatty(self):
        class SelectableIsAtty(self.MockRawIO):
            def __init__(self, isatty):
                super().__init__()
                self._isatty = isatty

            def isatty(self):
                return self._isatty

        pair = self.tp(SelectableIsAtty(False), SelectableIsAtty(False))
        self.assertFalse(pair.isatty())

        pair = self.tp(SelectableIsAtty(True), SelectableIsAtty(False))
        self.assertTrue(pair.isatty())

        pair = self.tp(SelectableIsAtty(False), SelectableIsAtty(True))
        self.assertTrue(pair.isatty())

        pair = self.tp(SelectableIsAtty(True), SelectableIsAtty(True))
        self.assertTrue(pair.isatty())

    def test_weakref_clearing(self):
        brw = self.tp(self.MockRawIO(), self.MockRawIO())
        ref = weakref.ref(brw)
        brw = None
        ref = None # Shouldn't segfault.

class CBufferedRWPairTest(BufferedRWPairTest, CTestCase):
    tp = io.BufferedRWPair

class PyBufferedRWPairTest(BufferedRWPairTest, PyTestCase):
    tp = pyio.BufferedRWPair


class BufferedRandomTest(BufferedReaderTest, BufferedWriterTest):
    read_mode = "rb+"
    write_mode = "wb+"

    def test_constructor(self):
        BufferedReaderTest.test_constructor(self)
        BufferedWriterTest.test_constructor(self)

    def test_uninitialized(self):
        BufferedReaderTest.test_uninitialized(self)
        BufferedWriterTest.test_uninitialized(self)

    def test_read_and_write(self):
        raw = self.MockRawIO((b"asdf", b"ghjk"))
        rw = self.tp(raw, 8)

        self.assertEqual(b"as", rw.read(2))
        rw.write(b"ddd")
        rw.write(b"eee")
        self.assertFalse(raw._write_stack) # Buffer writes
        self.assertEqual(b"ghjk", rw.read())
        self.assertEqual(b"dddeee", raw._write_stack[0])

    def test_seek_and_tell(self):
        raw = self.BytesIO(b"asdfghjkl")
        rw = self.tp(raw)

        self.assertEqual(b"as", rw.read(2))
        self.assertEqual(2, rw.tell())
        rw.seek(0, 0)
        self.assertEqual(b"asdf", rw.read(4))

        rw.write(b"123f")
        rw.seek(0, 0)
        self.assertEqual(b"asdf123fl", rw.read())
        self.assertEqual(9, rw.tell())
        rw.seek(-4, 2)
        self.assertEqual(5, rw.tell())
        rw.seek(2, 1)
        self.assertEqual(7, rw.tell())
        self.assertEqual(b"fl", rw.read(11))
        rw.flush()
        self.assertEqual(b"asdf123fl", raw.getvalue())

        self.assertRaises(TypeError, rw.seek, 0.0)

    def check_flush_and_read(self, read_func):
        raw = self.BytesIO(b"abcdefghi")
        bufio = self.tp(raw)

        self.assertEqual(b"ab", read_func(bufio, 2))
        bufio.write(b"12")
        self.assertEqual(b"ef", read_func(bufio, 2))
        self.assertEqual(6, bufio.tell())
        bufio.flush()
        self.assertEqual(6, bufio.tell())
        self.assertEqual(b"ghi", read_func(bufio))
        raw.seek(0, 0)
        raw.write(b"XYZ")
        # flush() resets the read buffer
        bufio.flush()
        bufio.seek(0, 0)
        self.assertEqual(b"XYZ", read_func(bufio, 3))

    def test_flush_and_read(self):
        self.check_flush_and_read(lambda bufio, *args: bufio.read(*args))

    def test_flush_and_readinto(self):
        def _readinto(bufio, n=-1):
            b = bytearray(n if n >= 0 else 9999)
            n = bufio.readinto(b)
            b.resize(n)
            return b.take_bytes()
        self.check_flush_and_read(_readinto)

    def test_flush_and_peek(self):
        def _peek(bufio, n=-1):
            # This relies on the fact that the buffer can contain the whole
            # raw stream, otherwise peek() can return less.
            b = bufio.peek(n)
            if n != -1:
                b = b[:n]
            bufio.seek(len(b), 1)
            return b
        self.check_flush_and_read(_peek)

    def test_flush_and_write(self):
        raw = self.BytesIO(b"abcdefghi")
        bufio = self.tp(raw)

        bufio.write(b"123")
        bufio.flush()
        bufio.write(b"45")
        bufio.flush()
        bufio.seek(0, 0)
        self.assertEqual(b"12345fghi", raw.getvalue())
        self.assertEqual(b"12345fghi", bufio.read())

    def test_threads(self):
        BufferedReaderTest.test_threads(self)
        BufferedWriterTest.test_threads(self)

    def test_writes_and_peek(self):
        def _peek(bufio):
            bufio.peek(1)
        self.check_writes(_peek)
        def _peek(bufio):
            pos = bufio.tell()
            bufio.seek(-1, 1)
            bufio.peek(1)
            bufio.seek(pos, 0)
        self.check_writes(_peek)

    def test_writes_and_reads(self):
        def _read(bufio):
            bufio.seek(-1, 1)
            bufio.read(1)
        self.check_writes(_read)

    def test_writes_and_read1s(self):
        def _read1(bufio):
            bufio.seek(-1, 1)
            bufio.read1(1)
        self.check_writes(_read1)

    def test_writes_and_readintos(self):
        def _read(bufio):
            bufio.seek(-1, 1)
            bufio.readinto(bytearray(1))
        self.check_writes(_read)

    def test_write_after_readahead(self):
        # Issue #6629: writing after the buffer was filled by readahead should
        # first rewind the raw stream.
        for overwrite_size in [1, 5]:
            raw = self.BytesIO(b"A" * 10)
            bufio = self.tp(raw, 4)
            # Trigger readahead
            self.assertEqual(bufio.read(1), b"A")
            self.assertEqual(bufio.tell(), 1)
            # Overwriting should rewind the raw stream if it needs so
            bufio.write(b"B" * overwrite_size)
            self.assertEqual(bufio.tell(), overwrite_size + 1)
            # If the write size was smaller than the buffer size, flush() and
            # check that rewind happens.
            bufio.flush()
            self.assertEqual(bufio.tell(), overwrite_size + 1)
            s = raw.getvalue()
            self.assertEqual(s,
                b"A" + b"B" * overwrite_size + b"A" * (9 - overwrite_size))

    def test_write_rewind_write(self):
        # Various combinations of reading / writing / seeking backwards / writing again
        def mutate(bufio, pos1, pos2):
            assert pos2 >= pos1
            # Fill the buffer
            bufio.seek(pos1)
            bufio.read(pos2 - pos1)
            bufio.write(b'\x02')
            # This writes earlier than the previous write, but still inside
            # the buffer.
            bufio.seek(pos1)
            bufio.write(b'\x01')

        b = b"\x80\x81\x82\x83\x84"
        for i in range(0, len(b)):
            for j in range(i, len(b)):
                raw = self.BytesIO(b)
                bufio = self.tp(raw, 100)
                mutate(bufio, i, j)
                bufio.flush()
                expected = bytearray(b)
                expected[j] = 2
                expected[i] = 1
                self.assertEqual(raw.getvalue(), expected,
                                 "failed result for i=%d, j=%d" % (i, j))

    def test_truncate_after_read_or_write(self):
        raw = self.BytesIO(b"A" * 10)
        bufio = self.tp(raw, 100)
        self.assertEqual(bufio.read(2), b"AA") # the read buffer gets filled
        self.assertEqual(bufio.truncate(), 2)
        self.assertEqual(bufio.write(b"BB"), 2) # the write buffer increases
        self.assertEqual(bufio.truncate(), 4)

    def test_truncate_drops_read_ahead(self):
        # Bytes cut away are not read back, and the next write goes to
        # the position.
        raw = self.BytesIO(b"0123456789" * 3)
        bufio = self.tp(raw, 100)
        self.assertEqual(bufio.read(3), b"012")
        self.assertEqual(bufio.truncate(), 3)
        self.assertEqual(bufio.tell(), 3)
        self.assertEqual(bufio.read(), b"")
        bufio.write(b"X")
        bufio.flush()
        self.assertEqual(raw.getvalue(), b"012X")

        raw = self.BytesIO(b"0123456789" * 3)
        bufio = self.tp(raw, 100)
        self.assertEqual(bufio.read(3), b"012")
        self.assertEqual(bufio.truncate(5), 5)
        self.assertEqual(bufio.tell(), 3)
        self.assertEqual(bufio.read(), b"34")

    def test_truncate_below_position(self):
        # The position is not changed: reads return nothing, and a write
        # lands at the position, after a gap of zero bytes.
        for prep in ("read", "write", "seek", "readall"):
            with self.subTest(prep=prep):
                raw = self.BytesIO(b"0123456789abcdefghij")
                bufio = self.tp(raw, 100)
                if prep == "read":
                    bufio.read(8)
                elif prep == "write":
                    bufio.write(b"x" * 8)
                elif prep == "seek":
                    bufio.seek(8)
                else:
                    bufio.read()
                pos = bufio.tell()
                self.assertEqual(bufio.truncate(3), 3)
                self.assertEqual(bufio.tell(), pos)
                self.assertEqual(bufio.read(), b"")
                self.assertEqual(bufio.write(b"Z"), 1)
                self.assertEqual(bufio.tell(), pos + 1)
                bufio.flush()
                head = b"xxx" if prep == "write" else b"012"
                self.assertEqual(raw.getvalue(),
                                 head + b"\0" * (pos - 3) + b"Z")

    def test_misbehaved_io(self):
        BufferedReaderTest.test_misbehaved_io(self)
        BufferedWriterTest.test_misbehaved_io(self)

    def test_interleaved_read_write(self):
        # Test for issue #12213
        with self.BytesIO(b'abcdefgh') as raw:
            with self.tp(raw, 100) as f:
                f.write(b"1")
                self.assertEqual(f.read(1), b'b')
                f.write(b'2')
                self.assertEqual(f.read1(1), b'd')
                f.write(b'3')
                buf = bytearray(1)
                f.readinto(buf)
                self.assertEqual(buf, b'f')
                f.write(b'4')
                self.assertEqual(f.peek(1), b'h')
                f.flush()
                self.assertEqual(raw.getvalue(), b'1b2d3f4h')

        with self.BytesIO(b'abc') as raw:
            with self.tp(raw, 100) as f:
                self.assertEqual(f.read(1), b'a')
                f.write(b"2")
                self.assertEqual(f.read(1), b'c')
                f.flush()
                self.assertEqual(raw.getvalue(), b'a2c')

    def test_read1_after_write(self):
        with self.BytesIO(b'abcdef') as raw:
            with self.tp(raw, 3) as f:
                f.write(b"1")
                self.assertEqual(f.read1(1), b'b')
                f.flush()
                self.assertEqual(raw.getvalue(), b'1bcdef')
        with self.BytesIO(b'abcdef') as raw:
            with self.tp(raw, 3) as f:
                f.write(b"1")
                self.assertEqual(f.read1(), b'bcd')
                f.flush()
                self.assertEqual(raw.getvalue(), b'1bcdef')
        with self.BytesIO(b'abcdef') as raw:
            with self.tp(raw, 3) as f:
                f.write(b"1")
                # XXX: read(100) returns different numbers of bytes
                # in Python and C implementations.
                self.assertEqual(f.read1(100)[:3], b'bcd')
                f.flush()
                self.assertEqual(raw.getvalue(), b'1bcdef')

    def test_interleaved_readline_write(self):
        with self.BytesIO(b'ab\ncdef\ng\n') as raw:
            with self.tp(raw) as f:
                f.write(b'1')
                self.assertEqual(f.readline(), b'b\n')
                f.write(b'2')
                self.assertEqual(f.readline(), b'def\n')
                f.write(b'3')
                self.assertEqual(f.readline(), b'\n')
                f.flush()
                self.assertEqual(raw.getvalue(), b'1b\n2def\n3\n')

    def test_append_mode_write_after_read(self):
        # gh-64281: a raw stream in append mode writes at the end of the
        # file whatever the position, so data read before a write must
        # still read back as it is in the file.
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        with self.open(os_helper.TESTFN, "wb") as f:
            f.write(b"testest")
        with self.tp(self.FileIO(os_helper.TESTFN, "a+")) as f:
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

    def test_append_mode_seek_in_buffer_after_write(self):
        # A write to a raw file in append mode lands at the end of the
        # file, not at the position the buffered object last knew: seek()
        # within the read buffer afterwards must not count from there.
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        with self.open(os_helper.TESTFN, "wb") as f:
            f.write(b"0123456789")
        with self.tp(self.FileIO(os_helper.TESTFN, "a+"), 8) as f:
            f.seek(0)
            f.write(b"X" * 20)
            with self.open(os_helper.TESTFN, "ab") as g:
                g.write(b"abcdef")
            self.assertEqual(f.read(1), b"a")
            self.assertEqual(f.seek(1, 1), 32)
            self.assertEqual(f.read(1), b"c")
            self.assertEqual(f.seek(-3, 1), 30)
            self.assertEqual(f.read(2), b"ab")
            self.assertEqual(f.tell(), 32)

    def make_seek_file(self, size=300000):
        data = bytes((i * 7 + i // 251) % 256 for i in range(size))
        data = data.replace(b'\x0a', b'.')
        data = bytearray(data)
        for i in range(0, size, 97):
            data[i] = 0x0a
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        with self.open(os_helper.TESTFN, "wb") as f:
            f.write(data)
        return data

    def check_seek_pattern(self, name, op, bufsize, n=300):
        # Run op(f, model, i) n times on a BufferedRandom over a FileIO,
        # model being what the file should hold, checking every read and
        # tell() against it, then the file itself.
        model = self.make_seek_file()
        with self.subTest(pattern=name, bufsize=bufsize):
            raw = self.FileIO(os_helper.TESTFN, "r+")
            with self.tp(raw, bufsize) as f:
                pos = 0
                for i in range(n):
                    pos = op(f, model, i, pos)
                    self.assertEqual(f.tell(), pos, (name, i))
                self.assertEqual(f.seek(0, io.SEEK_END), len(model))
                self.assertEqual(f.tell(), len(model))
            with self.open(os_helper.TESTFN, "rb") as f:
                self.assertEqual(f.read(), model)

    def test_seek_patterns(self):
        # Seeking inside and outside the read-ahead, tell(), and read,
        # modify, write in place keep the position right.
        def read(f, model, pos, k):
            self.assertEqual(f.read(k), model[pos:pos + k])
            return min(pos + k, len(model))
        def write(f, model, pos, b):
            f.write(b)
            model[pos:pos + len(b)] = b
            return pos + len(b)
        def seek_within(f, model, i, pos):
            return read(f, model, f.seek((i * 37) % 4000), 16)
        def seek_back(f, model, i, pos):
            pos = read(f, model, pos, 64)
            return f.seek(-16, 1)
        def tell_seek(f, model, i, pos):
            p = f.tell()
            read(f, model, p, 32)
            self.assertEqual(f.seek(p), p)
            return read(f, model, p, 48)
        def tell_line(f, model, i, pos):
            self.assertEqual(f.tell(), pos)
            line = f.readline()
            end = model.find(b'\n', pos)
            end = len(model) if end < 0 else end + 1
            self.assertEqual(line, model[pos:end])
            return end
        def peek_seek(f, model, i, pos):
            pos = read(f, model, pos, 30)
            return read(f, model, f.seek(-30, 1), 46)
        def rmw_seq(f, model, i, pos):
            r = f.read(64)
            self.assertEqual(r, model[pos:pos + 64])
            self.assertEqual(f.seek(-64, 1), pos)
            return write(f, model, pos, r[::-1])
        def rmw_rand(f, model, i, pos):
            off = ((i * 7919) % 1024) * 64
            self.assertEqual(f.seek(off), off)
            r = f.read(64)
            self.assertEqual(r, model[off:off + 64])
            self.assertEqual(f.seek(off), off)
            return write(f, model, off, r[::-1])
        def hdr_patch(f, model, i, pos):
            if i == 0:
                f.seek(len(model))
                pos = len(model)
            pos = write(f, model, pos, b'd' * 512)
            self.assertEqual(f.tell(), pos)
            self.assertEqual(f.seek(4), 4)
            write(f, model, 4, pos.to_bytes(4, 'little'))
            return f.seek(pos)
        def rand_read(f, model, i, pos):
            off = ((i * 7919) % 4096) * 64
            self.assertEqual(f.seek(off), off)
            return read(f, model, off, 64)
        def seq_after_seek(f, model, i, pos):
            pos = f.seek(((i * 3) % 4) * 65536 + i)
            for j in range(16):
                pos = read(f, model, pos, 4096)
            return pos
        def seek_cur_far(f, model, i, pos):
            pos = read(f, model, pos, 10)
            step = 5000 if pos + 5000 < len(model) else -pos
            return read(f, model, f.seek(step, 1), 10)
        patterns = [seek_within, seek_back, tell_seek, tell_line, peek_seek,
                    rmw_seq, rmw_rand, hdr_patch, rand_read, seq_after_seek,
                    seek_cur_far]
        for bufsize in (16, 1000, 8192, 131072):
            for op in patterns:
                self.check_seek_pattern(op.__name__, op, bufsize)

    def test_text_tell_seek_back(self):
        # TextIOWrapper's cookies, from the buffered position.
        model = self.make_seek_file(20000)
        with self.open(os_helper.TESTFN, "w", encoding="latin-1") as f:
            f.write(model.decode('latin-1'))
        lines = bytes(model).split(b'\n')
        for bufsize in (16, 1000, 8192):
            raw = self.FileIO(os_helper.TESTFN, "r+")
            with self.TextIOWrapper(self.tp(raw, bufsize),
                                    encoding="latin-1", newline='\n') as t:
                for line in lines[:100]:
                    line = (line + b'\n').decode('latin-1')
                    c = t.tell()
                    self.assertEqual(t.readline(), line)
                    self.assertEqual(t.seek(c), c)
                    self.assertEqual(t.readline(), line)

    def test_append_mode_position(self):
        # In append mode writes go to the end, wherever the position was.
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        with self.open(os_helper.TESTFN, "wb") as f:
            f.write(b'0123456789' * 10)
        for bufsize in (16, 1000):
            raw = self.FileIO(os_helper.TESTFN, "a+")
            with self.tp(raw, bufsize) as f:
                size = f.seek(0, io.SEEK_END)
                self.assertEqual(f.tell(), size)
                f.write(b'x' * 10)
                self.assertEqual(f.tell(), size + 10)
                self.assertEqual(f.seek(3), 3)
                self.assertEqual(f.read(5), b'34567')
                f.write(b'y' * 3)
                self.assertEqual(f.tell(), size + 13)
                self.assertEqual(f.seek(-13, io.SEEK_END), size)
                self.assertEqual(f.read(), b'x' * 10 + b'yyy')
                self.assertEqual(f.tell(), size + 13)

    def test_truncate_position(self):
        model = self.make_seek_file(5000)
        for bufsize in (16, 1000, 8192):
            with self.open(os_helper.TESTFN, "wb") as f:
                f.write(model)
            raw = self.FileIO(os_helper.TESTFN, "r+")
            with self.tp(raw, bufsize) as f:
                self.assertEqual(f.read(100), model[:100])
                self.assertEqual(f.truncate(50), 50)
                self.assertEqual(f.tell(), 100)
                self.assertEqual(f.read(10), b'')
                f.write(b'z')
                self.assertEqual(f.tell(), 101)
                self.assertEqual(f.seek(40), 40)
                self.assertEqual(f.read(10), model[40:50])
                self.assertEqual(f.tell(), 50)
                self.assertEqual(f.truncate(), 50)
                self.assertEqual(f.tell(), 50)
                f.write(b'w')
                self.assertEqual(f.seek(0, io.SEEK_END), 51)
                self.assertEqual(f.seek(45), 45)
                self.assertEqual(f.read(), model[45:50] + b'w')
            with self.open(os_helper.TESTFN, "rb") as f:
                self.assertEqual(f.read(), model[:50] + b'w')

    def test_tell_after_external_move(self):
        # With nothing buffered, tell() asks the raw stream: code sharing
        # the file descriptor may have moved it.
        model = self.make_seek_file(5000)
        raw = self.FileIO(os_helper.TESTFN, "r+")
        with self.tp(raw, 16) as f:
            self.assertEqual(f.tell(), 0)
            os.lseek(raw.fileno(), 100, os.SEEK_SET)
            self.assertEqual(f.tell(), 100)
            self.assertEqual(f.read(4), model[100:104])
            self.assertEqual(f.read(12), model[104:116])
            self.assertEqual(f.tell(), 116)
            os.lseek(raw.fileno(), 500, os.SEEK_SET)
            self.assertEqual(f.tell(), 500)
            self.assertEqual(f.read(4), model[500:504])
            self.assertEqual(f.tell(), 504)
            self.assertEqual(f.seek(-2, 1), 502)
            self.assertEqual(f.read(2), model[502:504])
            f.write(b'abc')
            f.flush()
            self.assertEqual(f.tell(), 507)
            os.lseek(raw.fileno(), 1000, os.SEEK_SET)
            self.assertEqual(f.tell(), 1000)
            f.write(b'def')
            self.assertEqual(f.tell(), 1003)
            self.assertEqual(f.seek(998), 998)
            self.assertEqual(f.read(7),
                             model[998:1000] + b'def' + model[1003:1005])

    def test_reinit_position(self):
        # A new raw stream comes with a new position.
        model = self.make_seek_file(5000)
        f = self.tp(self.FileIO(os_helper.TESTFN, "r+"), 1000)
        self.assertEqual(f.read(10), model[:10])
        self.assertEqual(f.tell(), 10)
        self.assertEqual(f.seek(3000), 3000)
        self.assertEqual(f.read(10), model[3000:3010])
        self.assertEqual(f.tell(), 3010)
        f.raw.close()
        raw = self.FileIO(os_helper.TESTFN, "r+")
        raw.seek(7)
        f.__init__(raw, 1000)
        self.assertEqual(f.read(10), model[7:17])
        self.assertEqual(f.tell(), 17)
        self.assertEqual(f.seek(9), 9)
        self.assertEqual(f.read(2), model[9:11])
        raw = f.detach()
        pos = raw.tell()
        f = self.tp(raw, 1000)
        self.assertEqual(f.read(3), model[pos:pos + 3])
        self.assertEqual(f.tell(), pos + 3)
        f.close()

    def test_pipe_and_char_device_position(self):
        # The position of a pipe or a character device doesn't follow what
        # was read: reads still work, and tell() asks the raw stream.
        r, w = os.pipe()
        os.write(w, b'0123456789' * 10)
        os.close(w)
        with self.BufferedReader(self.FileIO(r, "r"), 16) as f:
            self.assertEqual(f.read(5), b'01234')
            self.assertRaises(OSError, f.tell)
            self.assertRaises(OSError, f.seek, 0)
            self.assertEqual(f.read(10), b'5678901234')
            self.assertEqual(len(f.read()), 85)
        if os.path.exists('/dev/zero'):
            with self.BufferedReader(self.FileIO('/dev/zero', "r"), 16) as f:
                self.assertEqual(f.read(5), bytes(5))
                f.tell()
                self.assertEqual(f.read(100), bytes(100))
                self.assertEqual(f.seek(0), 0)
                self.assertEqual(f.read(20), bytes(20))
                self.assertGreaterEqual(f.tell(), 0)

    def test_read_failing_to_write_out_keeps_written_data(self):
        # A read that fails writing out data written over the read-ahead,
        # after taking some of the read-ahead, keeps that data (and puts
        # the bytes taken back).
        class Raw(self.BytesIO):
            fail = False
            def write(self, b):
                if self.fail:
                    self.fail = False
                    raise OSError(errno.EIO, 'EIO')
                return super().write(b)
        raw = Raw(bytes(range(97, 123)) * 4)
        f = self.tp(raw, 16)
        self.assertEqual(f.read(2), b'ab')
        f.write(b'XYZ')
        raw.fail = True
        self.assertRaises(OSError, f.read, 40)
        f.flush()
        self.assertEqual(raw.getvalue()[:8], b'abXYZfgh')
        if not self.is_stock_C:
            # (_io drops what a failed read took.)
            self.assertEqual(f.read(3), b'fgh')

    @unittest.skipUnless(hasattr(os, 'O_APPEND'), 'needs os.O_APPEND')
    def test_tell_over_append_mode_fd(self):
        # Writes to a file descriptor opened with O_APPEND go to the end of
        # the file, whatever mode the FileIO over it was given.
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        with self.open(os_helper.TESTFN, 'wb') as f:
            f.write(b'0123456789')
        fd = os.open(os_helper.TESTFN, os.O_RDWR | os.O_APPEND)
        with self.tp(self.FileIO(fd, 'r+b')) as f:
            f.seek(0)
            f.write(b'AAAA')
            f.flush()
            f.write(b'B')
            self.assertEqual(f.tell(), 15)
            f.seek(0)
            self.assertEqual(f.read(), b'0123456789AAAAB')

    def test_flush_after_partly_failed_write_over_read_ahead(self):
        # A write-out of data written over the read-ahead that fails after
        # writing part of it leaves the rest where it belongs.
        class Raw(self.BytesIO):
            plan = []
            def write(self, b):
                step = self.plan.pop(0) if self.plan else None
                if isinstance(step, BaseException):
                    raise step
                with memoryview(b) as view:
                    return super().write(view[:step])
        raw = Raw(b'a' * 100)
        f = self.tp(raw, 16)
        self.assertEqual(f.read(1), b'a')
        f.write(b'X' * 10)
        Raw.plan = [4, OSError(errno.EFBIG, 'too big')]
        self.assertRaises(OSError, f.flush)
        f.flush()
        self.assertEqual(f.tell(), 11)
        self.assertEqual(f.read(2), b'aa')
        self.assertEqual(raw.getvalue(), b'a' + b'X' * 10 + b'a' * 89)

    # You can't construct a BufferedRandom over a non-seekable stream.
    test_unseekable = None

    # writable() returns True, so there's no point to test it over
    # a writable stream.
    test_truncate_on_read_only = None


class CBufferedRandomTest(BufferedRandomTest, SizeofTest, CTestCase):
    tp = io.BufferedRandom

    def test_garbage_collection(self):
        CBufferedReaderTest.test_garbage_collection(self)
        CBufferedWriterTest.test_garbage_collection(self)

    def test_args_error(self):
        # Issue #17275
        with self.assertRaisesRegex(TypeError, "BufferedRandom"):
            self.tp(self.BytesIO(), 1024, 1024, 1024)


class PyBufferedRandomTest(BufferedRandomTest, PyTestCase):
    tp = pyio.BufferedRandom


# _io._nibbler buffered classes, run through the full C test suites.
class NibblerBufferedReaderTest(NibblerMixin, CBufferedReaderTest):
    tp = _nibbler.BufferedReader

    def test_extreme_offsets_and_sizes(self):
        # Offsets and sizes near the limits of their types fail as for any
        # other bad value, with no arithmetic overflowing (for UBSan).
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        with self.open(os_helper.TESTFN, "wb") as f:
            f.write(b"0123456789" * 100)
        with self.open(os_helper.TESTFN, "rb") as f:
            for target, whence in ((sys.maxsize, 1), (-sys.maxsize - 1, 1),
                                   (sys.maxsize, 0), (-sys.maxsize - 1, 2)):
                f.seek(0)
                f.read(5)
                with self.subTest(target=target, whence=whence):
                    self.assertRaises((OSError, OverflowError), f.seek,
                                      target, whence)
        b = self.tp(self.FileIO(os_helper.TESTFN), 2**58)
        with self.TextIOWrapper(b, encoding="ascii") as t:
            self.assertRaises(MemoryError, t.readline)

    def test_returned_bytes_hash(self):
        # Bytes returned are hashed by their contents, also when they are
        # the block, which was returned before with other contents.
        class Raw(self.RawIOBase):
            chunks = [b'a' * 500, OSError('boom'), b'b' * 16,
                      b'c' * 484 + b'\n']
            def readable(self):
                return True
            def readinto(self, b):
                c = self.chunks.pop(0)
                if isinstance(c, BaseException):
                    raise c
                b[:len(c)] = c
                return len(c)
        bufio = self.tp(Raw(), 16)
        self.assertRaises(OSError, bufio.read, 1000)
        hash(bufio.read(500))
        self.assertEqual(bufio.read(1), b'b')
        line = bufio.readline()
        self.assertEqual(line, b'b' * 15 + b'c' * 484 + b'\n')
        self.assertEqual(hash(line), hash(bytes(bytearray(line))))

    def test_stash_in_reference_cycle(self):
        # Data kept after a raw read failed is seen by the garbage
        # collector: a cycle through it is collected.
        import gc
        class Chunk(bytes):
            pass
        class Raw(self.RawIOBase):
            def readable(self):
                return True
            def read(self, size=-1):
                if hasattr(self, 'done'):
                    raise OSError('boom')
                self.done = chunk = Chunk(b'data')
                chunk.bufio = bufio
                return chunk
        bufio = self.tp(Raw())
        self.assertRaises(OSError, bufio.read)
        ref = weakref.ref(bufio)
        bufio.raw.done = None
        del bufio
        gc.collect()
        self.assertIsNone(ref())

    def test_reentrant_call_with_failing_repr(self):
        # A reentrant call raises RuntimeError also when the object's
        # repr() (in the message) raises.
        class Raw(self.MockRawIO):
            @property
            def name(self):
                raise KeyError('name')
            def readinto(self, b):
                return bufio.read(1)
        bufio = self.tp(Raw())
        with self.assertRaisesRegex(RuntimeError, 'reentrant call'):
            bufio.read(1)

    def test_readinto_python_buffer(self):
        # readinto() into a class with __buffer__ (PEP 688), also when the
        # read goes straight to a raw stream other than FileIO.
        class Buf:
            def __init__(self, size):
                self.ba = bytearray(size)
            def __buffer__(self, flags):
                return memoryview(self.ba)
            def __release_buffer__(self, view):
                view.release()
        for size in (8, 64):
            with self.subTest(size=size):
                rawio = self.MockRawIO([b'x' * 100])
                bufio = self.tp(rawio, 16)
                buf = Buf(size)
                self.assertEqual(bufio.readinto(buf), size)
                self.assertEqual(buf.ba, b'x' * size)
                self.assertEqual(bufio.read(), b'x' * (100 - size))


class NibblerBufferedWriterTest(NibblerMixin, CBufferedWriterTest):
    tp = _nibbler.BufferedWriter

    def test_stdout_in_cycle_at_exit(self):
        # The final garbage collection may clear the module before a
        # buffered object in a cycle with it; dealloc still uses the
        # module's state.
        import os, subprocess
        env = dict(os.environ, _PYTHON_IO_DEFAULT_IMPL='_nibbler')
        proc = subprocess.run(
            [sys.executable, '-c',
             'import sys; sys.stdout.cycle = sys.stdout; print("x")'],
            env=env, capture_output=True, timeout=support.SHORT_TIMEOUT)
        self.assertEqual((proc.returncode, proc.stdout), (0, b'x\n'))

    def test_failed_reinit_writes_pending_data(self):
        # __init__() with a raw stream it can't use writes what is pending
        # to the old one first, then raises.
        old = self.MockRawIO()
        bufio = self.tp(old, 16)
        bufio.write(b'abc')
        new = self.MockRawIO()
        new.writable = lambda: False
        self.assertRaises(self.UnsupportedOperation, bufio.__init__, new)
        self.assertEqual(old._write_stack, [b'abc'])
        self.assertRaises(ValueError, bufio.write, b'x')

    def test_raw_keeps_view_of_written_data(self):
        # A raw stream keeping a view made from the one it is given keeps
        # the data of the write() valid, through the caller's object.
        kept = []
        class Raw(self.MockRawIO):
            def write(self, b):
                kept.append(b[1:])
                return len(b)
        for size in (16,):
            kept.clear()
            data = bytearray(b'A' * 100000)
            bufio = self.tp(Raw(), size)
            bufio.write(data)
            self.assertEqual(len(kept), 1)
            view = kept[0]
            self.assertIs(view.obj, data)
            # The bytearray can't be resized while the view is kept.
            with self.assertRaises(BufferError):
                del data[:]
            self.assertEqual(view.tobytes(), b'A' * 99999)
            kept.clear()
            view.release()
            del data[:]

    def test_raw_keeps_view_of_written_text(self):
        kept = []
        class Raw(self.MockRawIO):
            def write(self, b):
                kept.append(b[1:])
                return len(b)
        text = self.TextIOWrapper(self.tp(Raw(), 16), encoding='ascii')
        n = 100000
        text.write('A' * n)
        text.flush()
        del text
        junk = [bytes(100000) for _ in range(5)]
        self.assertEqual(b''.join(kept), b'A' * 99999)


class NibblerBufferedRWPairTest(NibblerMixin, CBufferedRWPairTest):
    tp = _nibbler.BufferedRWPair


class NibblerBufferedRandomTest(NibblerMixin, CBufferedRandomTest):
    tp = _nibbler.BufferedRandom

    def test_seek_target_uses_object(self):
        # The target is converted before the lock is taken: its
        # __index__() can use the object, as with _io.
        bufio = self.tp(self.BytesIO(b'0123456789'))
        bufio.read(5)
        class Target:
            def __index__(self):
                return bufio.tell() - 2
        self.assertEqual(bufio.seek(Target()), 3)
        self.assertEqual(bufio.read(2), b'34')

    def test_seek_and_tell_keep_raw_position(self):
        # Over an exact FileIO of a regular file, the raw position is kept:
        # tell() and seek() inside the read-ahead, and tell() with pending
        # writes, make no raw call.  A probe: they don't see the file
        # descriptor moved behind their back (which is meaningless while
        # data is buffered, as with _io), and don't move it.
        model = self.make_seek_file(50000)
        raw = self.FileIO(os_helper.TESTFN, "r+")
        fd = raw.fileno()
        with self.tp(raw, 1000) as f:
            self.assertEqual(f.read(10), model[:10])
            self.assertEqual(f.tell(), 10)
            os.lseek(fd, 20000, os.SEEK_SET)
            for i in range(20):
                p = (i * 37) % 990
                self.assertEqual(f.seek(p), p)
                self.assertEqual(f.tell(), p)
                self.assertEqual(f.seek(5, 1), p + 5)
                self.assertEqual(f.read(5), model[p + 5:p + 10])
                self.assertEqual(f.tell(), p + 10)
            self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 20000)
            os.lseek(fd, 1000, os.SEEK_SET)
            # A seek out of the read-ahead sets it, reads advance it (also
            # direct ones).
            self.assertEqual(f.seek(3000), 3000)
            self.assertEqual(f.read(500), model[3000:3500])
            self.assertEqual(f.read(800), model[3500:4300])
            self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 5000)
            self.assertEqual(f.read(700), model[4300:5000])
            self.assertEqual(f.read(2000), model[5000:7000])
            self.assertEqual(f.read(10), model[7000:7010])
            self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 8000)
            os.lseek(fd, 30000, os.SEEK_SET)
            self.assertEqual(f.tell(), 7010)
            self.assertEqual(f.seek(7005), 7005)
            self.assertEqual(f.read(10), model[7005:7015])
            os.lseek(fd, 8000, os.SEEK_SET)
            # Pending writes.
            f.write(b'abc')
            os.lseek(fd, 30000, os.SEEK_SET)
            self.assertEqual(f.tell(), 7018)
            os.lseek(fd, 7015, os.SEEK_SET)
            f.flush()
            self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 7018)
            f.write(b'def')
            os.lseek(fd, 30000, os.SEEK_SET)
            self.assertEqual(f.tell(), 7021)

    @support.requires_fork()
    def test_raw_position_after_fork(self):
        # The child of a fork shares the file position with the parent:
        # what the parent kept is not trusted there.
        model = self.make_seek_file(50000)
        raw = self.FileIO(os_helper.TESTFN, "r+")
        fd = raw.fileno()
        with self.tp(raw, 1000) as f:
            self.assertEqual(f.read(10), model[:10])
            self.assertEqual(f.tell(), 10)
            pid = os.fork()
            if pid == 0:
                code = 1
                try:
                    os.lseek(fd, 20000, os.SEEK_SET)
                    # 990 bytes are unread.
                    if f.tell() == 19010:
                        code = 0
                finally:
                    os._exit(code)
            support.wait_process(pid, exitcode=0)

    @support.requires_fork()
    @threading_helper.requires_working_threading()
    def test_fork_destructor_uses_object_of_gone_thread(self):
        # In the child of a fork, the objects of the threads gone in it are
        # freed before any Python code runs: a destructor using a buffered
        # object such a thread was reading from doesn't wait for it.
        from test.support.script_helper import assert_python_ok
        code = """if 1:
            import io, os, threading, warnings, _io
            from test import support
            warnings.simplefilter('ignore', DeprecationWarning)
            entered = threading.Event()
            class Raw(io.RawIOBase):
                def readable(self):
                    return True
                def readinto(self, b):
                    entered.set()
                    threading.Event().wait()
            f = _io._nibbler.BufferedReader(Raw())
            class D:
                def __del__(self):
                    try:
                        f.tell()
                    except Exception:
                        pass
            local = threading.local()
            def reader():
                local.d = D()
                f.read(1)
            threading.Thread(target=reader, daemon=True).start()
            entered.wait()
            pid = os.fork()
            if pid == 0:
                os._exit(0)
            support.wait_process(pid, exitcode=0,
                                 timeout=support.SHORT_TIMEOUT)
            """
        assert_python_ok('-c', code)


# Simple test to ensure that optimizations in the IO library deliver the
# expected results.  For best testing, run this under a debug-build Python too
# (to exercise asserts in the C code).

lengths = list(range(1, 257)) + [512, 1000, 1024, 2048, 4096, 8192, 10000,
                                 16384, 32768, 65536, 1000000]

class BufferSizeTest:
    def try_one(self, s):
        # Write s + "\n" + s to file, then open it and ensure that successive
        # .readline()s deliver what we wrote.

        # Ensure we can open TESTFN for writing.
        os_helper.unlink(os_helper.TESTFN)

        # Since C doesn't guarantee we can write/read arbitrary bytes in text
        # files, use binary mode.
        f = self.open(os_helper.TESTFN, "wb")
        try:
            # write once with \n and once without
            f.write(s)
            f.write(b"\n")
            f.write(s)
            f.close()
            f = self.open(os_helper.TESTFN, "rb")
            line = f.readline()
            self.assertEqual(line, s + b"\n")
            line = f.readline()
            self.assertEqual(line, s)
            line = f.readline()
            self.assertFalse(line) # Must be at EOF
            f.close()
        finally:
            os_helper.unlink(os_helper.TESTFN)

    def drive_one(self, pattern):
        for length in lengths:
            # Repeat string 'pattern' as often as needed to reach total length
            # 'length'.  Then call try_one with that string, a string one larger
            # than that, and a string one smaller than that.  Try this with all
            # small sizes and various powers of 2, so we exercise all likely
            # stdio buffer sizes, and "off by one" errors on both sides.
            q, r = divmod(length, len(pattern))
            teststring = pattern * q + pattern[:r]
            self.assertEqual(len(teststring), length)
            self.try_one(teststring)
            self.try_one(teststring + b"x")
            self.try_one(teststring[:-1])

    def test_primepat(self):
        # A pattern with prime length, to avoid simple relationships with
        # stdio buffer sizes.
        self.drive_one(b"1234567890\00\01\02\03\04\05\06")

    def test_nullpat(self):
        self.drive_one(b'\0' * 1000)


class CBufferSizeTest(BufferSizeTest, unittest.TestCase):
    open = io.open

class PyBufferSizeTest(BufferSizeTest, unittest.TestCase):
    open = staticmethod(pyio.open)


if __name__ == "__main__":
    unittest.main()

"""Tests for gathered writes: _gather() of the _io._nibbler buffered
classes, also with text written through a TextIOWrapper over them."""
import asyncio
import contextlib
import contextvars
import gc
import io
import os
import threading
import unittest
import warnings

import _io
from _io import _nibbler

from test.support import import_helper, os_helper, threading_helper


class GatherTest(unittest.TestCase):

    def setUp(self):
        prev = _io._set_open_impl('_nibbler')
        self.addCleanup(_io._set_open_impl, prev)
        prev = _io._set_unbuffered_impl('_nibbler')
        self.addCleanup(_io._set_unbuffered_impl, prev)
        self.path = os_helper.TESTFN
        self.addCleanup(os_helper.unlink, self.path)

    def size(self):
        return os.path.getsize(self.path)

    def read(self):
        with open(self.path, 'rb') as f:
            return f.read()

    def test_gathers_past_buffer_size(self):
        with open(self.path, 'wb', buffering=16) as f:
            self.assertIsInstance(f, _nibbler.BufferedWriter)
            f.write(b'a')
            with f._gather() as g:
                self.assertIs(g, f)
                for i in range(10):
                    f.write(b'%d' % i * 10)
                self.assertEqual(self.size(), 0)
            # Past the buffer size: written out at the end of the block.
            self.assertEqual(self.size(), 101)
            f.write(b'z')
        self.assertEqual(self.read(),
                         b'a' + b''.join(b'%d' % i * 10 for i in range(10))
                         + b'z')

    def test_text(self):
        with open(self.path, 'w', encoding='utf-8', buffering=16) as f:
            f.write('a')
            with f.buffer._gather() as g:
                self.assertIs(g, f.buffer)
                f.write('b')
                f.write('\xe9' * 10000)
                f.write('c')
                self.assertEqual(self.size(), 0)
            self.assertGreater(self.size(), 0)
            f.write('d')
        with open(self.path, encoding='utf-8') as f:
            self.assertEqual(f.read(), 'ab' + '\xe9' * 10000 + 'cd')

    def test_unbuffered(self):
        with open(self.path, 'wb', buffering=0) as f:
            with f._gather():
                f.write(b'ab')
                f.write(b'cd')
                self.assertEqual(self.size(), 0)
            self.assertEqual(self.size(), 4)

    def check_threads(self, mode, gather=True, nthreads=4, blocks=50,
                      lines=10):
        # Gathering threads write blocks of lines, and plain writers write
        # single lines meanwhile.  A barrier makes the threads wait inside
        # their first blocks until all of them wrote: without gathering
        # (the control), those blocks are always split.
        barrier = threading.Barrier(2 * nthreads)

        def write(f, line):
            f.write(line if mode == 'w' else line.encode())

        def gatherer(f, i):
            buf = f.buffer if mode == 'w' else f
            for k in range(blocks):
                with buf._gather() if gather else contextlib.nullcontext():
                    for j in range(lines):
                        write(f, f'g{i}:{k:03}:{j:03}\n')
                        if j == 0 and k < 2:
                            barrier.wait()

        def plain(f, i):
            for k in range(blocks):
                if k < 2:
                    barrier.wait()
                write(f, f'p{i}:{k:03}\n')

        with open(self.path, mode) as f:
            threads = [threading.Thread(target=gatherer, args=(f, i))
                       for i in range(nthreads)]
            threads += [threading.Thread(target=plain, args=(f, i))
                        for i in range(nthreads)]
            with threading_helper.start_threads(threads):
                pass
        with open(self.path) as f:
            got = f.read().splitlines()
        self.assertEqual(len(got), nthreads * blocks * (lines + 1))
        # Each thread's lines in its order.
        last = {}
        for line in got:
            who, rest = line.split(':', 1)
            self.assertGreater(rest, last.get(who, ''))
            last[who] = rest
        # Whole blocks.
        split = 0
        pos = 0
        while pos < len(got):
            if got[pos].startswith('p'):
                pos += 1
                continue
            who, k, _ = got[pos].split(':')
            block = got[pos:pos + lines]
            if block != [f'{who}:{k}:{j:03}' for j in range(lines)]:
                split += 1
                pos += 1
            else:
                pos += lines
        if gather:
            self.assertEqual(split, 0)
        else:
            self.assertGreater(split, 0)

    @threading_helper.requires_working_threading()
    def test_threads_binary(self):
        self.check_threads('wb')
        self.check_threads('wb', gather=False)

    @threading_helper.requires_working_threading()
    def test_threads_text(self):
        self.check_threads('w')
        self.check_threads('w', gather=False)

    def test_asyncio_tasks(self):
        async def task(f, name):
            with f.buffer._gather():
                for i in range(5):
                    f.write(f'{name}{i}\n')
                    await asyncio.sleep(0)

        async def main(f):
            await asyncio.gather(*(task(f, name) for name in 'abc'))

        with open(self.path, 'w') as f:
            asyncio.run(main(f))
        with open(self.path) as f:
            self.assertEqual(f.read().split(),
                             [f'{name}{i}' for name in 'abc' for i in range(5)])

    def test_task_created_in_block(self):
        # A task copies the context, but writes as usual.
        async def child(f):
            f.write('child\n')
            f.flush()

        async def main(f):
            with f.buffer._gather():
                f.write('outer1\n')
                await asyncio.create_task(child(f))
                f.write('outer2\n')

        with open(self.path, 'w') as f:
            asyncio.run(main(f))
        with open(self.path) as f:
            self.assertEqual(f.read().split(), ['child', 'outer1', 'outer2'])

    def test_limit(self):
        with open(self.path, 'wb', buffering=4) as f:
            with f._gather(limit=10):
                f.write(b'01234')
                f.write(b'56789')
                # Reached the limit: added to the buffer (past its size, as
                # data accepted), so that other writes can come after it.
                contextvars.copy_context().run(f.write, b'X')
                f.write(b'ab')
            self.assertEqual(self.read(), b'0123456789X')
        self.assertEqual(self.read(), b'0123456789Xab')
        for limit in (0, -1):
            with open(self.path, 'wb') as f:
                self.assertRaises(ValueError, f._gather, limit)
                self.assertRaises(ValueError, f._gather, limit=limit)
        with open(self.path, 'wb') as f:
            self.assertRaises(TypeError, f._gather, 1.5)
            self.assertRaises(OverflowError, f._gather, 2**64)

    def test_no_limit(self):
        with open(self.path, 'wb', buffering=4) as f:
            with f._gather(limit=None):
                for i in range(1000):
                    f.write(b'%04d' % i)
                self.assertEqual(self.size(), 0)
            self.assertEqual(self.size(), 4000)

    def test_limit_write_error(self):
        # Moving the data to the buffer at the limit only adds it, as
        # write() does: it is written out once, later.
        out = []
        class Raw(io.RawIOBase):
            fail = True
            def writable(self):
                return True
            def write(self, b):
                if self.fail:
                    raise OSError('fails')
                out.append(bytes(b))
                return len(b)
        raw = Raw()
        f = _nibbler.BufferedWriter(raw, 4)
        g = f._gather(limit=8)
        g.__enter__()
        f.write(b'abcdefghij')
        with self.assertRaises(OSError):
            g.__exit__(None, None, None)
        raw.fail = False
        f.flush()
        self.assertEqual(b''.join(out), b'abcdefghij')

    def test_large_bytes_by_reference(self):
        # Large bytes are kept by reference, also for a raw stream that
        # has no _writev() of its own.
        objs = []
        class Raw(io.RawIOBase):
            def writable(self):
                return True
            def write(self, b):
                objs.append(b.obj)
                return len(b)
        data = b'x' * 100_000
        f = _nibbler.BufferedWriter(Raw(), 16)
        with f._gather():
            f.write(data)
        self.assertIs(objs[0], data)

    def test_nesting(self):
        other = self.path + '2'
        self.addCleanup(os_helper.unlink, other)
        with open(self.path, 'wb', buffering=0) as f, \
             open(other, 'wb', buffering=0) as f2:
            with f._gather():
                f.write(b'a')
                with f._gather(), f2._gather():
                    f.write(b'b')
                    f2.write(b'x')
                # The inner block on the same stream gathers into the outer.
                self.assertEqual(self.size(), 0)
                self.assertEqual(os.path.getsize(other), 1)
                f.write(b'c')
            self.assertEqual(self.read(), b'abc')

    def test_exception(self):
        with open(self.path, 'wb', buffering=0) as f:
            with self.assertRaises(ZeroDivisionError):
                with f._gather():
                    f.write(b'kept')
                    1/0
            self.assertEqual(self.read(), b'kept')

    def test_tell(self):
        with open(self.path, 'wb') as f:
            f.write(b'abc')
            with f._gather():
                f.write(b'de')
                self.assertEqual(f.tell(), 5)
                self.assertEqual(self.size(), 0)
            self.assertEqual(f.tell(), 5)
        with open(self.path, 'ab') as f:
            f.write(b'f')
            with f._gather():
                f.write(b'gh')
                self.assertEqual(f.tell(), 8)
        with open(self.path, 'w') as f:
            f.write('abc')
            with f.buffer._gather():
                f.write('de')
                self.assertEqual(f.tell(), 5)
        self.assertEqual(self.size(), 5)

    def test_flush_deferred(self):
        with open(self.path, 'wb') as f:
            f.write(b'a')
            with f._gather():
                f.write(b'b')
                f.flush()
                self.assertEqual(self.size(), 0)
            # The flush takes effect at the end of the block.
            self.assertEqual(self.size(), 2)
            with f._gather():
                f.write(b'c')
            self.assertEqual(self.size(), 2)

    def test_line_buffering(self):
        r, w = os.pipe()
        self.addCleanup(os.close, r)
        os.set_blocking(r, False)
        with open(w, 'w', buffering=1) as f:
            with f.buffer._gather():
                print('a', file=f)
                print('b', file=f)
                self.assertRaises(BlockingIOError, os.read, r, 100)
            self.assertEqual(os.read(r, 100), b'a\nb\n')

    def test_read_and_seek(self):
        # Operations needing the real position add what was gathered first.
        with open(self.path, 'w+b') as f:
            self.assertIsInstance(f, _nibbler.BufferedRandom)
            f.write(b'0123456789')
            f.seek(2)
            self.assertEqual(f.read(2), b'23')
            with f._gather():
                f.write(b'AB')
                self.assertEqual(f.tell(), 6)
                self.assertEqual(f.read(2), b'67')
                f.write(b'CD')
                f.seek(0)
                self.assertEqual(f.read(), b'0123AB67CD')
                f.write(b'E')
                f.truncate(11)
                self.assertEqual(f.tell(), 11)
        self.assertEqual(self.read(), b'0123AB67CDE')

    def test_close_and_detach(self):
        f = open(self.path, 'wb')
        g = f._gather()
        g.__enter__()
        f.write(b'ab')
        f.close()
        self.assertEqual(self.read(), b'ab')
        self.assertFalse(g.__exit__(None, None, None))

        f = open(self.path, 'wb')
        with f._gather():
            f.write(b'cd')
            f.flush()
            raw = f.detach()
        raw.close()
        self.assertEqual(self.read(), b'cd')

    def test_closed_by_other(self):
        f = open(self.path, 'wb')
        with self.assertRaises(ValueError):
            with f._gather():
                f.write(b'ab')
                f.raw.close()
        f.close()
        with open(self.path, 'wb') as f:
            pass
        self.assertRaises(ValueError, f._gather().__enter__)
        self.assertRaises(ValueError, f.write, b'x')

    def test_out_of_order_exits(self):
        # Blocks on two streams, ended in the order they were entered: the
        # second still gathers.
        other = self.path + '2'
        self.addCleanup(os_helper.unlink, other)
        with open(self.path, 'wb', buffering=0) as f, \
             open(other, 'wb', buffering=0) as f2:
            g = f._gather()
            g2 = f2._gather()
            g.__enter__()
            g2.__enter__()
            f.write(b'a')
            f2.write(b'b1')
            g.__exit__(None, None, None)
            self.assertEqual(self.read(), b'a')
            f2.write(b'b2')
            self.assertEqual(os.path.getsize(other), 0)
            g2.__exit__(None, None, None)
            self.assertEqual(os.path.getsize(other), 4)

    def test_exit_in_other_context(self):
        with open(self.path, 'wb', buffering=0) as f:
            g = f._gather()
            g.__enter__()
            f.write(b'ab')
            self.assertFalse(
                contextvars.copy_context().run(g.__exit__, None, None, None))
            self.assertEqual(self.read(), b'ab')
            # It no longer gathers.
            f.write(b'c')
            self.assertEqual(self.read(), b'abc')

    def test_close_from_other_context(self):
        # close(), detach() and __init__() from any context add what every
        # block gathered first.
        def run(func, *args):
            return contextvars.copy_context().run(func, *args)

        f = open(self.path, 'wb')
        with f._gather():
            f.write(b'ab')
            run(f.close)
            self.assertEqual(self.read(), b'ab')
            self.assertRaises(ValueError, f.write, b'c')
            self.assertRaises(ValueError, f.seek, 0, 1)

        f = open(self.path, 'wb')
        with f._gather():
            f.write(b'cd')
            f.flush()
            raw = run(f.detach)
            self.assertEqual(self.read(), b'cd')
        raw.close()

        f = open(self.path, 'wb')
        with f._gather():
            f.write(b'ef')
            raw = f.raw
            run(f.__init__, io.FileIO(self.path, 'ab'))
            self.assertEqual(self.read(), b'ef')
            raw.close()
            f.write(b'gh')
        f.close()
        self.assertEqual(self.read(), b'efgh')

    def test_raw_closed_by_other(self):
        # The raw stream closed meanwhile: operations needing the position
        # raise, and the block keeps its data, which its end can't write.
        with open(self.path, 'w+b') as f:
            f.write(b'0123456789')
            f.seek(0)
            raw = f.raw
            with self.assertRaisesRegex(ValueError, 'write to closed'):
                with f._gather():
                    f.write(b'lost')
                    raw.close()
                    self.assertRaises(ValueError, f.seek, 0, 1)
                    self.assertRaises(ValueError, f.read)
                    self.assertRaises(ValueError, f.flush)
            # Nothing is left to write to it: initialized again, it works.
            f.__init__(io.FileIO(self.path, 'r+b'))
            self.assertEqual(f.read(), b'0123456789')

    def test_deferred_flush_closed(self):
        with open(self.path, 'wb') as f:
            raw = f.raw
            with self.assertRaisesRegex(ValueError, 'flush of closed'):
                with f._gather():
                    f.flush()
                    raw.close()

    def test_read_by_other_context(self):
        # Another context reading between a write in the block and a read
        # in it: the block's read adds what it gathered first, at the
        # position then current.
        with open(self.path, 'w+b') as f:
            f.write(b'0123456789')
            f.seek(0)
            self.assertEqual(f.read(2), b'01')
            with f._gather():
                f.write(b'AB')
                self.assertEqual(contextvars.copy_context().run(f.read, 1),
                                 b'2')
                self.assertEqual(f.read(2), b'56')
        self.assertEqual(self.read(), b'012AB56789')

    def test_memory_error_at_end(self):
        # Moving the data at the end of a block failing for lack of
        # memory keeps it: close() writes it.
        _testcapi = import_helper.import_module('_testcapi')
        data = [b'%03d' % i for i in range(100)]
        failed = 0
        for start in range(20):
            f = open(self.path, 'wb', buffering=4)
            g = f._gather()
            g.__enter__()
            for d in data:
                f.write(d)
            try:
                _testcapi.call_with_nomemory(start, start + 1, g.__exit__,
                                             None, None, None)
            except MemoryError:
                failed += 1
            f.close()
            self.assertEqual(self.read(), b''.join(data))
        self.assertGreater(failed, 0)

    def test_never_ended(self):
        # A block dropped before it ends adds its data, with a
        # ResourceWarning.
        f = open(self.path, 'wb')
        g = f._gather()
        g.__enter__()
        f.write(b'ab')
        with self.assertWarnsRegex(ResourceWarning, 'never ended'):
            del g
            gc.collect()
        self.assertEqual(self.size(), 0)
        f.close()
        self.assertEqual(self.read(), b'ab')

        # Or drops it, when the stream was closed.
        f = open(self.path, 'wb')
        g = f._gather()
        g.__enter__()
        f.write(b'cd')
        f.raw.close()
        with self.assertWarnsRegex(ResourceWarning, '2 gathered bytes'):
            del g
            gc.collect()
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            f.close()

    def test_dropped_in_raw_call(self):
        # A block dropped from Python code a raw call runs (here from the
        # raw stream; a signal handler or the GC are others): its data is
        # dropped, with the lock, with a ResourceWarning.  With threads
        # writing meanwhile (for TSan).
        held = []
        class Raw(io.RawIOBase):
            def __init__(self):
                self.b = io.BytesIO(b"0123456789" * 10)
            def readable(self):
                return True
            def writable(self):
                return True
            def seekable(self):
                return True
            def readinto(self, b):
                return self.b.readinto(b)
            def write(self, b):
                held.clear()
                return self.b.write(b)
            def tell(self):
                return self.b.tell()
            def seek(self, *args):
                held.clear()
                return self.b.seek(*args)
        def other_block(f, data):
            g = f._gather()
            ctx = contextvars.copy_context()
            ctx.run(g.__enter__)
            ctx.run(f.write, data)
            held.append(g)

        # The read-ahead handed back before moving the current context's
        # data: the raw seek() drops the block after it in the list.
        raw = Raw()
        f = _nibbler.BufferedRandom(raw, 16)
        self.assertEqual(f.read(2), b"01")
        with f._gather():
            f.write(b"AB")
            other_block(f, b"CD")
            with self.assertWarnsRegex(ResourceWarning, "2 gathered bytes"):
                self.assertEqual(f.read(1), b"4")
        f.flush()
        self.assertEqual(raw.b.getvalue()[:6], b"01AB45")

        # A write-out releases the lock around the raw write.
        raw = Raw()
        f = _nibbler.BufferedWriter(raw, 16)
        stop = threading.Event()
        def writer():
            while not stop.is_set():
                f.write(b"t")
        with warnings.catch_warnings():
            # (Any thread's write-out may drop them.)
            warnings.simplefilter("ignore", ResourceWarning)
            t = threading.Thread(target=writer)
            with threading_helper.start_threads([t], stop.set):
                for i in range(20):
                    other_block(f, b"CD")
                    f.write(b"x" * 100)
            f.flush()
        self.assertEqual(raw.b.getvalue().count(b"x"), 2000)
        self.assertNotIn(b"C", raw.b.getvalue())

    @threading_helper.requires_working_threading()
    def test_thread_gone_in_block(self):
        f = open(self.path, 'wb')
        def worker():
            g = f._gather()
            g.__enter__()
            f.write(b'thread-data')
        with self.assertWarnsRegex(ResourceWarning, 'never ended'):
            t = threading.Thread(target=worker)
            t.start()
            t.join()
            gc.collect()
        f.close()
        self.assertEqual(self.read(), b'thread-data')

    def test_enter_once(self):
        with open(self.path, 'wb') as f:
            g = f._gather()
            with g:
                self.assertRaises(RuntimeError, g.__enter__)
            self.assertRaises(RuntimeError, g.__enter__)
            self.assertRaises(RuntimeError, g.__exit__, None, None, None)
            self.assertRaises(RuntimeError, f._gather().__exit__,
                              None, None, None)

    def test_not_nibbler(self):
        # _io's buffered classes can't gather.
        if not getattr(_io.BufferedWriter, '_is_nibbler', False):
            self.assertNotHasAttr(_io.BufferedWriter, '_gather')

if __name__ == '__main__':
    unittest.main()

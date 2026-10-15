"""Tests for gathered writes: _gather() of the _io._nibbler buffered
classes, also with text written through a TextIOWrapper over them."""
import asyncio
import contextlib
import contextvars
import errno
import gc
import io
import os
import signal
import subprocess
import sys
import textwrap
import threading
import unittest
import warnings

import _io
from _io import _nibbler

from test import support
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
            f.write(b'c')
            with f._gather():
                f.write(b'd')
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
            # (A BufferedRandom: its blocks never write out themselves.)
            f = open(self.path, 'w+b', buffering=4)
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

    def test_memory_error_at_limit(self):
        # Moving the data at the limit failing for lack of memory raises
        # from write(), which says all of its data was accepted: kept, and
        # written once.
        _testcapi = import_helper.import_module('_testcapi')
        failed = 0
        for start in range(10):
            with open(self.path, 'wb') as f:
                with f._gather(limit=8):
                    f.write(b'abc')
                    f.write(b'def')
                    try:
                        _testcapi.call_with_nomemory(start, start + 1,
                                                     f.write, b'ghi')
                    except MemoryError as e:
                        self.assertEqual(e.characters_written, 3)
                        failed += 1
            self.assertEqual(self.read(), b'abcdefghi')
        self.assertGreater(failed, 0)

    def test_never_ended(self):
        # A block dropped before it ends ends then, with a
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

    def test_never_ended_in_cycle(self):
        # A dropped block in a reference cycle with its stream ends from
        # its finalizer, before either is cleared, with Python code (the
        # raw stream) run meanwhile: its data is written.
        out = []
        class Raw(io.RawIOBase):
            def writable(self):
                return True
            def write(self, b):
                out.append(bytes(b))
                return len(b)
        raw = Raw()
        f = _nibbler.BufferedWriter(raw)
        f.g = g = f._gather()
        g.__enter__()
        f.write(b'ab')
        del f, g
        with self.assertWarnsRegex(ResourceWarning, 'never ended'):
            gc.collect()
        self.assertEqual(b''.join(out), b'ab')
        self.assertTrue(raw.closed)

    @threading_helper.requires_working_threading()
    def test_closed_asked_without_record_lock(self):
        # A raw stream's closed, asked by a write in a block, uses the
        # stream while detach() in another thread holds its lock and waits
        # for the block's record: no deadlock.  (In a child process: a
        # deadlock can't be undone.)
        code = textwrap.dedent('''
            import io, threading, time
            from _io import _nibbler
            class Raw(io.RawIOBase):
                hook = None
                def writable(self):
                    return True
                def write(self, b):
                    return len(b)
                @property
                def closed(self):
                    hook, Raw.hook = Raw.hook, None
                    if hook:
                        hook()
                    return super().closed
            f = _nibbler.BufferedWriter(Raw())
            t = threading.Thread(target=f.detach)
            def hook():
                t.start()
                time.sleep(0.5)
                try:
                    f.write(b'x')
                except ValueError:
                    pass
            try:
                with f._gather():
                    Raw.hook = hook
                    f.write(b'a')
            except ValueError:
                pass
            t.join()
        ''')
        subprocess.run([sys.executable, '-c', code], check=True,
                       timeout=support.SHORT_TIMEOUT)

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

    def gather_vars(self):
        # The streams' private context variables, which Python code can
        # reach by iterating a context.
        return [k for k in contextvars.copy_context() if k.name == '_gather']

    def test_private_variable(self):
        # Setting a stream's variable doesn't make its writes go to
        # another stream's record, or read something else as one.
        other = self.path + '2'
        self.addCleanup(os_helper.unlink, other)
        def run(f, g):
            with f._gather():
                f.write(b'F0')
            [vf] = self.gather_vars()
            with g._gather():
                [vg] = set(self.gather_vars()) - {vf}
                vf.set(vg.get())
                f.write(b'F1')
                def bad():
                    vf.set(b'\x02' * 200)
                    f.write(b'F2')
                contextvars.copy_context().run(bad)
                with f._gather():
                    f.write(b'F3')
                g.write(b'G')
        with open(self.path, 'wb') as f, open(other, 'wb') as g:
            contextvars.Context().run(run, f, g)
        self.assertEqual(self.read(), b'F0F1F2F3')
        with open(other, 'rb') as r:
            self.assertEqual(r.read(), b'G')

    @threading_helper.requires_working_threading()
    def test_private_variable_set(self):
        # Setting the variable takes effect at once: writes don't go on
        # using the record found last (freed when nothing else holds it).
        def run(f):
            with f._gather():
                [v] = self.gather_vars()
                f.write(b'a')
                v.set(None)
                f.write(b'b' * 20)
                self.assertEqual(self.read(), b'b' * 20)
        with open(self.path, 'wb', buffering=8) as f:
            contextvars.Context().run(run, f)
        self.assertEqual(self.read(), b'b' * 20 + b'a')

        ready, done = threading.Event(), threading.Event()
        def other(f):
            # Keeps a record listed.
            with f._gather():
                ready.set()
                done.wait()
        def run(f):
            with f._gather():
                f.write(b'a')
            [v] = self.gather_vars()
            t = threading.Thread(target=other, args=(f,),
                                 context=contextvars.Context())
            with threading_helper.start_threads([t], done.set):
                ready.wait()
                v.set(None)
                # Unlists the idle record: freed.
                f.seek(0, 1)
                f.write(b'x')
                with f._gather():
                    f.write(b'y')
        with open(self.path, 'wb') as f:
            contextvars.Context().run(run, f)
        self.assertEqual(self.read(), b'axy')

    def test_not_nibbler(self):
        # _io's buffered classes can't gather.
        if not getattr(_io.BufferedWriter, '_is_nibbler', False):
            self.assertNotHasAttr(_io.BufferedWriter, '_gather')

    # A block's end moves its data to the pending writes when it gets the
    # stream's lock without waiting.  When another thread holds it, a
    # BufferedWriter of a regular file with nothing pending writes the
    # block out itself; else the end waits for the lock.

    @contextlib.contextmanager
    def lock_held(self, f, release_after=support.SHORT_TIMEOUT):
        # Another thread holds f's lock and I/O role, in raw.tell() of
        # f.tell(), until the with block ends or release_after seconds
        # passed.  The context's record is listed first (listing takes the
        # lock).
        with f._gather():
            pass
        raw = f.raw
        entered, release = threading.Event(), threading.Event()
        def tell():
            entered.set()
            release.wait()
            return os.lseek(raw.fileno(), 0, os.SEEK_CUR)
        raw.tell = tell
        t = threading.Thread(target=f.tell)
        timer = threading.Timer(release_after, release.set)
        try:
            t.start()
            entered.wait()
            timer.start()
            yield release
        finally:
            release.set()
            t.join()
            timer.cancel()
            if timer.is_alive():
                timer.join()
            del raw.tell

    def test_splice(self):
        with open(self.path, 'wb', buffering=8192) as f:
            with f._gather():
                f.write(b'abc')
            # Moved to the pending writes.
            self.assertEqual(self.size(), 0)
            self.assertEqual(f.tell(), 3)
            f.write(b'd')
            with f._gather():
                f.write(b'x' * 10000)
            # Past the threshold: written out at the end.
            self.assertEqual(self.size(), 10004)
            with f._gather():
                f.write(b'e')
                f.flush()
            # The deferred flush.
            self.assertEqual(self.size(), 10005)
        self.assertEqual(self.read(), b'abcd' + b'x' * 10000 + b'e')

    @threading_helper.requires_working_threading()
    def test_direct(self):
        with open(self.path, 'wb') as f:
            with self.lock_held(f):
                with f._gather():
                    f.write(b'abc')
                    f.write(b'x' * 1000)
                    self.assertEqual(self.size(), 0)
                self.assertEqual(self.size(), 1003)
            self.assertEqual(f.tell(), 1003)
            f.write(b'd')
            self.assertEqual(f.tell(), 1004)
            f.flush()
            f.seek(0)
            with self.lock_held(f):
                with f._gather():
                    f.write(b'A')
                self.assertEqual(self.read()[:2], b'Ab')
            self.assertEqual(f.tell(), 1)
            # More pieces than one writev() takes at once.
            f.seek(0, 2)
            pieces = [b'%04d' % i * 200 for i in range(100)]
            with self.lock_held(f):
                with f._gather():
                    for p in pieces:
                        f.write(p)
                self.assertEqual(self.size(), 1004 + 80000)
        self.assertEqual(self.read(),
                         b'Abc' + b'x' * 1000 + b'd' + b''.join(pieces))
        # Append mode, with another writer of the file.
        with open(self.path, 'ab') as f, \
             open(self.path, 'ab', buffering=0) as other:
            with self.lock_held(f):
                with f._gather():
                    f.write(b'1')
                    other.write(b'2')
                    f.write(b'3')
                other.write(b'4')
        self.assertEqual(self.read()[-4:], b'2134')

    @threading_helper.requires_working_threading()
    def test_wait_for_lock(self):
        # With the lock busy and writes pending, which must come first,
        # the end waits for the lock and adds the block after them.
        with open(self.path, 'wb') as f:
            with self.lock_held(f, release_after=0.2) as release:
                f.write(b'p')
                with f._gather():
                    f.write(b'B')
                self.assertTrue(release.is_set())
                self.assertEqual(self.size(), 0)
        self.assertEqual(self.read(), b'pB')

    @threading_helper.requires_working_threading()
    def test_pending_writes_first(self):
        # A write that happened before the block's end and is still
        # pending comes first.
        with open(self.path, 'wb') as f:
            with f._gather():
                f.write(b'a1')
                t = threading.Thread(target=f.write, args=(b'b',))
                t.start()
                t.join()
                f.write(b'a2')
            self.assertEqual(self.size(), 0)
        self.assertEqual(self.read(), b'ba1a2')

    def test_read_ahead(self):
        # The data goes at the logical position, not after the read-ahead.
        with open(self.path, 'w+b') as f:
            f.write(b'0123456789')
            f.seek(0)
            self.assertEqual(f.read(2), b'01')
            with f._gather():
                f.write(b'AB')
            self.assertEqual(f.read(2), b'45')
        self.assertEqual(self.read(), b'01AB456789')

    @unittest.skipUnless(hasattr(signal, 'SIGXFSZ'), 'needs SIGXFSZ')
    def test_direct_partial_write_and_error(self):
        # Past RLIMIT_FSIZE, writev() writes part, then fails: the rest
        # stays pending, the error is raised, nothing is written twice.
        resource = import_helper.import_module('resource')
        old = signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        self.addCleanup(signal.signal, signal.SIGXFSZ, old)
        soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        data = [b'%04d' % i for i in range(1000)]
        with open(self.path, 'wb') as f:
            resource.setrlimit(resource.RLIMIT_FSIZE, (1000, hard))
            try:
                # (The rest waits for the lock.)
                with self.lock_held(f, release_after=0.1), \
                     self.assertRaises(OSError) as cm:
                    with f._gather():
                        for d in data:
                            f.write(d)
            finally:
                resource.setrlimit(resource.RLIMIT_FSIZE, (soft, hard))
            self.assertEqual(cm.exception.errno, errno.EFBIG)
            self.assertEqual(self.size(), 1000)
        self.assertEqual(self.read(), b''.join(data))

    def test_partial_writes_and_error(self):
        # A Python raw stream writing in pieces, then failing once.
        out = bytearray()
        class Raw(io.RawIOBase):
            calls = 0
            def writable(self):
                return True
            def write(self, b):
                self.calls += 1
                if self.calls == 3:
                    raise OSError('fails')
                out.extend(bytes(b[:5]))
                return min(len(b), 5)
        f = _nibbler.BufferedWriter(Raw(), 8)
        data = [b'%03d' % i for i in range(20)]
        with self.assertRaisesRegex(OSError, 'fails'):
            with f._gather():
                for d in data:
                    f.write(d)
        f.flush()
        self.assertEqual(bytes(out), b''.join(data))

    def check_blocks(self, lines, per_thread):
        # Lines b'i:k:j:n...': block k of thread i has n lines, j = 0..n-1.
        # Every block is whole and contiguous, and appears once.
        pos = 0
        seen = set()
        while pos < len(lines):
            i, k, j, n = map(int, lines[pos].split(b':')[:4])
            self.assertEqual(j, 0)
            self.assertNotIn((i, k), seen)
            seen.add((i, k))
            block = [line.split(b':')[:4] for line in lines[pos:pos + n]]
            self.assertEqual(block, [[b'%d' % x for x in (i, k, j, n)]
                                     for j in range(n)])
            pos += n
        self.assertEqual(len(seen), per_thread * len({i for i, k in seen}))

    @threading_helper.requires_working_threading()
    def test_threads_direct(self):
        # Threads ending blocks at once.  Their sizes vary, from one line
        # to many pieces kept by reference (joined for one writev()).
        nthreads, blocks = 8, 100
        def worker(f, i):
            for k in range(blocks):
                n = 100 if k % 25 == 0 else 1 + (k * 7 + i) % 23
                with f._gather():
                    for j in range(n):
                        tail = b'x' * 600 if j % 3 == 0 else b''
                        f.write(b'%d:%d:%d:%d:%s\n' % (i, k, j, n, tail))
        for mode in ('wb', 'ab'):
            with open(self.path, mode) as f:
                threads = [threading.Thread(target=worker, args=(f, i))
                           for i in range(nthreads)]
                with threading_helper.start_threads(threads):
                    pass
            with open(self.path, 'rb') as f:
                self.check_blocks(f.read().splitlines(), blocks)
            os_helper.unlink(self.path)

    @threading_helper.requires_working_threading()
    def test_close_while_gathering(self):
        # close() while threads write in blocks: what each had gathered is
        # written once, as a whole; the blocks' later writes and ends
        # raise ValueError.
        def worker(f, i, start):
            start.wait()
            try:
                for k in range(10**9):
                    with f._gather():
                        for j in range(5):
                            f.write(b'%d:%d:%d:5\n' % (i, k, j))
            except ValueError:
                pass
        for _ in range(20):
            f = open(self.path, 'wb')
            start = threading.Barrier(5)
            threads = [threading.Thread(target=worker, args=(f, i, start))
                       for i in range(4)]
            with threading_helper.start_threads(threads):
                start.wait()
                f.close()
            last = {}
            for line in self.read().splitlines():
                i, k, j, n = map(int, line.split(b':'))
                # In order, each block from its start, cut only at the end.
                pk, pj = last.get(i, (-1, 4))
                self.assertIn((k, j), [(pk, pj + 1), (pk + 1, 0)])
                if k != pk:
                    self.assertEqual(pj, 4)
                last[i] = k, j

    @support.requires_fork()
    @threading_helper.requires_working_threading()
    @support.skip_if_sanitizer("TSan doesn't start threads after a "
                               "multi-threaded fork", thread=True)
    def test_fork_while_writing_out(self):
        # A fork while another thread writes a block out: in the child,
        # its record is free (and its data, written by the parent, gone).
        f = open(self.path, 'wb')
        stop = threading.Event()
        def worker():
            while not stop.is_set():
                with f._gather():
                    f.write(b'0123456789' * 10 + b'\n')
        t = threading.Thread(target=worker)
        with threading_helper.start_threads([t], stop.set):
            for _ in range(10):
                with warnings.catch_warnings():
                    # (This test is about forking a multi-threaded process.)
                    warnings.simplefilter("ignore", DeprecationWarning)
                    pid = os.fork()
                if pid == 0:
                    try:
                        with f._gather():
                            f.write(b'child\n')
                        f.close()
                    finally:
                        os._exit(0)
                support.wait_process(pid, exitcode=0)
        f.close()
        lines = set(self.read().splitlines())
        self.assertLessEqual(lines, {b'0123456789' * 10, b'child'})

    # Direct blocks (direct=True), meant to last a thread's life: written
    # out at their start, then written out themselves at their limit,
    # flush() and end, without waiting for other contexts' pending writes.

    @threading_helper.requires_working_threading()
    def test_direct_mode_entry(self):
        with open(self.path, 'wb') as f:
            f.write(b'p')
            with f._gather(direct=True):
                # The context's earlier writes first.
                self.assertEqual(self.read(), b'p')
                f.write(b'B')
                t = threading.Thread(target=f.write, args=(b'o',))
                t.start()
                t.join()
                with self.lock_held(f):
                    f.write(b'C')
                    self.assertEqual(self.size(), 1)
                    f.flush()
                    # Without waiting for the lock nor the pending 'o'.
                    self.assertEqual(self.read(), b'pBC')
                    f.write(b'D')
                self.assertEqual(self.read(), b'pBC')
            # The end as well.
            self.assertEqual(self.read(), b'pBCD')
        self.assertEqual(self.read(), b'pBCDo')

    def test_direct_mode_limit(self):
        with open(self.path, 'wb', buffering=10) as f:
            with f._gather(direct=True):
                # The buffer size by default.
                f.write(b'012345678')
                self.assertEqual(self.size(), 0)
                f.write(b'9')
                self.assertEqual(self.size(), 10)
                f.write(b'x' * 25)
                self.assertEqual(self.size(), 35)
                f.write(b'abc')
                self.assertEqual(f.tell(), 38)
            self.assertEqual(self.size(), 38)
            with f._gather(limit=3, direct=True):
                f.write(b'de')
                self.assertEqual(self.size(), 38)
                f.write(b'f')
                self.assertEqual(self.size(), 41)
            with f._gather(limit=None, direct=True):
                f.write(b'g' * 100)
                self.assertEqual(self.size(), 41)
        self.assertEqual(self.read(), b'0123456789' + b'x' * 25 + b'abcdef'
                         + b'g' * 100)

    def test_line_flush(self):
        for direct in (False, True):
            with open(self.path, 'wb') as f:
                with f._gather(line_flush=True, direct=direct):
                    f.write(b'a\nb')
                    self.assertEqual(self.read(), b'a\n')
                    f.write(b'c')
                    self.assertEqual(self.read(), b'a\n')
                    f.write(b'\nd\ne')
                    self.assertEqual(self.read(), b'a\nbc\nd\n')
                    # Large pieces kept by reference, and more pieces than
                    # one writev() takes.
                    f.write(b'y' * 100_000)
                    for i in range(100):
                        f.write(b'%d' % (i % 10))
                    self.assertEqual(self.size(), 7)
                    f.write(b'z\n')
                    self.assertEqual(self.size(), 100_110)
                    f.write(b'tail')
                self.assertEqual(self.size(), 100_110 if not direct
                                 else 100_114)
            self.assertEqual(self.read(),
                             b'a\nbc\nd\ne' + b'y' * 100_000
                             + b'0123456789' * 10 + b'z\ntail')

    @threading_helper.requires_working_threading()
    def test_line_flush_pending(self):
        # Without direct, lines go after the pending writes, waiting for
        # the lock; with it, before them.
        for direct, expected in ((False, b'pA\nB'), (True, b'A\nBp')):
            with open(self.path, 'wb') as f:
                with f._gather(line_flush=True, direct=direct):
                    contextvars.copy_context().run(f.write, b'p')
                    with self.lock_held(f, release_after=0.2):
                        f.write(b'A\nB')
                        self.assertEqual(self.read(), expected[:-1 - direct])
            self.assertEqual(self.read(), expected)

    def test_line_flush_errors(self):
        # A failed write-out of lines keeps them for the next one, quietly
        # for an OSError, else raising (all of the data was accepted).
        out = []
        class Raw(io.RawIOBase):
            fail = None
            def writable(self):
                return True
            def write(self, b):
                if self.fail:
                    e, self.fail = self.fail, None
                    raise e
                out.append(bytes(b))
                return len(b)
        raw = Raw()
        f = _nibbler.BufferedWriter(raw)
        with f._gather(line_flush=True):
            raw.fail = KeyboardInterrupt()
            self.assertRaises(KeyboardInterrupt, f.write, b'a\n')
            raw.fail = MemoryError()
            with self.assertRaises(MemoryError) as cm:
                f.write(b'b\n')
            self.assertEqual(cm.exception.characters_written, 2)
            raw.fail = OSError()
            f.write(b'c\n')
        self.assertEqual(out, [])
        f.flush()
        self.assertEqual(b''.join(out), b'a\nb\nc\n')

    def test_line_flush_text(self):
        with open(self.path, 'w', encoding='utf-8') as f:
            with f.buffer._gather(line_flush=True, direct=True):
                f.write('a\nb')
                f.flush()
                self.assertEqual(self.read(), b'a\nb')
                print('c', file=f)
                f.write('\xe9')
                # (TextIOWrapper may keep text until its flush.)
                f.flush()
                self.assertEqual(self.read(), b'a\nbc\n\xc3\xa9')
            self.assertEqual(self.read(), b'a\nbc\n\xc3\xa9')

    def test_direct_mode_fallbacks(self):
        # Where direct writes aren't possible: written out with the lock,
        # after the pending writes.
        out = bytearray()
        class Raw(io.RawIOBase):
            def writable(self):
                return True
            def write(self, b):
                out.extend(b)
                return len(b)
        f = _nibbler.BufferedWriter(Raw(), 8)
        f.write(b'p')
        with f._gather(direct=True, line_flush=True):
            self.assertEqual(out, b'p')
            f.write(b'0123')
            contextvars.copy_context().run(f.write, b'X')
            f.write(b'\n45')
            self.assertEqual(out, b'pX0123\n')
            # At the limit (the buffer size).
            f.write(b'6789ab')
            self.assertEqual(out, b'pX0123\n456789ab')
            f.write(b'c')
            f.flush()
            self.assertEqual(out, b'pX0123\n456789abc')
            f.write(b'd')
        # The end as for other blocks: buffered.
        self.assertEqual(out, b'pX0123\n456789abc')
        f.flush()
        self.assertEqual(out, b'pX0123\n456789abcd')
        # A read-ahead: at the logical position.
        with open(self.path, 'w+b') as f:
            f.write(b'0123456789')
            f.seek(0)
            self.assertEqual(f.read(2), b'01')
            with f._gather(direct=True, line_flush=True):
                f.write(b'A\n')
                f.write(b'B')
            self.assertEqual(f.read(2), b'56')
        self.assertEqual(self.read(), b'01A\nB56789')
        # A pipe.
        r, w = os.pipe()
        self.addCleanup(os.close, r)
        os.set_blocking(r, False)
        with open(w, 'wb') as f:
            f.write(b'p')
            with f._gather(direct=True, line_flush=True):
                self.assertEqual(os.read(r, 100), b'p')
                f.write(b'a\nb')
                self.assertEqual(os.read(r, 100), b'a\n')
            self.assertRaises(BlockingIOError, os.read, r, 100)
        self.assertEqual(os.read(r, 100), b'b')

    def test_direct_mode_closed(self):
        f = open(self.path, 'wb')
        with f._gather(direct=True, line_flush=True):
            f.write(b'a\nb')
            # What the block gathered is written.
            f.close()
            self.assertRaises(ValueError, f.write, b'c\n')
            self.assertRaises(ValueError, f.flush)
        self.assertEqual(self.read(), b'a\nb')
        self.assertRaises(ValueError, f._gather(direct=True).__enter__)

    @unittest.skipUnless(hasattr(signal, 'SIGXFSZ'), 'needs SIGXFSZ')
    def test_direct_mode_write_error(self):
        # Past RLIMIT_FSIZE: the limit's write-out writes part and fails,
        # quietly; the end raises; nothing is written twice.
        resource = import_helper.import_module('resource')
        old = signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        self.addCleanup(signal.signal, signal.SIGXFSZ, old)
        soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        data = [b'%04d' % i for i in range(500)]
        with open(self.path, 'wb', buffering=100) as f:
            resource.setrlimit(resource.RLIMIT_FSIZE, (1000, hard))
            try:
                with self.assertRaises(OSError) as cm:
                    with f._gather(direct=True):
                        for d in data:
                            f.write(d)
                        self.assertEqual(self.size(), 1000)
            finally:
                resource.setrlimit(resource.RLIMIT_FSIZE, (soft, hard))
            self.assertEqual(cm.exception.errno, errno.EFBIG)
        self.assertEqual(self.read(), b''.join(data))

    @threading_helper.requires_working_threading()
    def test_threads_whole_life(self):
        # Threads in one direct block each for their whole life, with
        # plain writers meanwhile: every line whole, in its thread's order,
        # once.
        nthreads, lines = 8, 3000
        def worker(f, i, **kw):
            with f._gather(direct=True, **kw):
                for k in range(lines):
                    tail = b'x' * 600 if k % 97 == 0 else b''
                    f.write(b'%d:%d:%s\n' % (i, k, tail))
                    if kw.get('line_flush') and k % 10 == 0:
                        f.write(b'%d:' % i)
                        f.write(b'p:\n')
        def plain(f, i):
            for k in range(lines):
                f.write(b'%d:%d:\n' % (i, k))
        for mode, kw in (('wb', {}), ('ab', {}), ('wb', {'line_flush': True}),
                         ('wb', {'limit': 1000})):
            with self.subTest(mode=mode, **kw):
                with open(self.path, mode, buffering=4096) as f:
                    threads = [threading.Thread(target=worker, args=(f, i),
                                                kwargs=kw)
                               for i in range(nthreads)]
                    threads += [threading.Thread(target=plain,
                                                 args=(f, nthreads + i))
                                for i in range(2)]
                    with threading_helper.start_threads(threads):
                        pass
                seen = {}
                extra = 0
                for line in self.read().splitlines():
                    i, k, tail = line.split(b':')
                    if k == b'p':
                        extra += 1
                        continue
                    i, k = int(i), int(k)
                    self.assertEqual(k, seen.get(i, -1) + 1)
                    self.assertIn(tail, (b'', b'x' * 600))
                    seen[i] = k
                self.assertEqual(seen, {i: lines - 1
                                        for i in range(nthreads + 2)})
                self.assertEqual(extra, nthreads * (lines // 10)
                                 if kw.get('line_flush') else 0)
                os_helper.unlink(self.path)

if __name__ == '__main__':
    unittest.main()

"""Tests for gathered writes: gather() of the _io._nibbler buffered classes,
also with text written through a TextIOWrapper over them."""
import asyncio
import os
import threading
import time
import unittest

import _io
from _io import _nibbler

from test.support import os_helper, threading_helper


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
            with f.gather() as g:
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
            with f.buffer.gather() as g:
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
            with f.gather():
                f.write(b'ab')
                f.write(b'cd')
                self.assertEqual(self.size(), 0)
            self.assertEqual(self.size(), 4)

    def check_threads(self, mode, nthreads=8, blocks=100, lines=20):
        def worker(f, i):
            for k in range(blocks):
                with (f.buffer if mode == 'w' else f).gather():
                    for j in range(lines):
                        line = f'{i}:{k}:{j}\n'
                        f.write(line if mode == 'w' else line.encode())
                        if j % 5 == 0:
                            # Let the other threads run.
                            time.sleep(0)

        with open(self.path, mode) as f:
            threads = [threading.Thread(target=worker, args=(f, i))
                       for i in range(nthreads)]
            with threading_helper.start_threads(threads):
                pass
        with open(self.path) as f:
            got = f.read().splitlines()
        self.assertEqual(len(got), nthreads * blocks * lines)
        seen = set()
        for start in range(0, len(got), lines):
            block = [line.split(':') for line in got[start:start + lines]]
            i, k = block[0][:2]
            self.assertEqual(block, [[i, k, str(j)] for j in range(lines)])
            seen.add((i, k))
        self.assertEqual(len(seen), nthreads * blocks)

    @threading_helper.requires_working_threading()
    def test_threads_binary(self):
        self.check_threads('wb')

    @threading_helper.requires_working_threading()
    def test_threads_text(self):
        self.check_threads('w')

    def test_asyncio_tasks(self):
        async def task(f, name):
            with f.buffer.gather():
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
            with f.buffer.gather():
                f.write('outer1\n')
                await asyncio.create_task(child(f))
                f.write('outer2\n')

        with open(self.path, 'w') as f:
            asyncio.run(main(f))
        with open(self.path) as f:
            self.assertEqual(f.read().split(), ['child', 'outer1', 'outer2'])

    def test_limit(self):
        with open(self.path, 'wb', buffering=4) as f:
            with f.gather(limit=10):
                f.write(b'01234')
                f.write(b'56789')
                # Reached the limit: added to the buffer, past its size.
                self.assertEqual(self.size(), 10)
                f.write(b'ab')
                self.assertEqual(self.size(), 10)
            self.assertEqual(self.size(), 10)
        self.assertEqual(self.size(), 12)
        for limit in (0, -1):
            with open(self.path, 'wb') as f:
                self.assertRaises(ValueError, f.gather, limit)
                self.assertRaises(ValueError, f.gather, limit=limit)

    def test_nesting(self):
        other = self.path + '2'
        self.addCleanup(os_helper.unlink, other)
        with open(self.path, 'wb', buffering=0) as f, \
             open(other, 'wb', buffering=0) as f2:
            with f.gather():
                f.write(b'a')
                with f.gather(), f2.gather():
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
                with f.gather():
                    f.write(b'kept')
                    1/0
            self.assertEqual(self.read(), b'kept')

    def test_tell(self):
        with open(self.path, 'wb') as f:
            f.write(b'abc')
            with f.gather():
                f.write(b'de')
                self.assertEqual(f.tell(), 5)
                self.assertEqual(self.size(), 0)
            self.assertEqual(f.tell(), 5)
        with open(self.path, 'ab') as f:
            f.write(b'f')
            with f.gather():
                f.write(b'gh')
                self.assertEqual(f.tell(), 8)
        with open(self.path, 'w') as f:
            f.write('abc')
            with f.buffer.gather():
                f.write('de')
                self.assertEqual(f.tell(), 5)
        self.assertEqual(self.size(), 5)

    def test_flush_deferred(self):
        with open(self.path, 'wb') as f:
            f.write(b'a')
            with f.gather():
                f.write(b'b')
                f.flush()
                self.assertEqual(self.size(), 0)
            # The flush takes effect at the end of the block.
            self.assertEqual(self.size(), 2)
            with f.gather():
                f.write(b'c')
            self.assertEqual(self.size(), 2)

    def test_line_buffering(self):
        r, w = os.pipe()
        self.addCleanup(os.close, r)
        os.set_blocking(r, False)
        with open(w, 'w', buffering=1) as f:
            with f.buffer.gather():
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
            with f.gather():
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
        g = f.gather()
        g.__enter__()
        f.write(b'ab')
        f.close()
        self.assertEqual(self.read(), b'ab')
        self.assertFalse(g.__exit__(None, None, None))

        f = open(self.path, 'wb')
        with f.gather():
            f.write(b'cd')
            f.flush()
            raw = f.detach()
        raw.close()
        self.assertEqual(self.read(), b'cd')

    def test_closed_by_other(self):
        f = open(self.path, 'wb')
        with self.assertRaises(ValueError):
            with f.gather():
                f.write(b'ab')
                f.raw.close()
        f.close()
        with open(self.path, 'wb') as f:
            pass
        self.assertRaises(ValueError, f.gather().__enter__)
        self.assertRaises(ValueError, f.write, b'x')

    def test_enter_once(self):
        with open(self.path, 'wb') as f:
            g = f.gather()
            with g:
                self.assertRaises(RuntimeError, g.__enter__)
            self.assertRaises(RuntimeError, g.__enter__)
            self.assertRaises(RuntimeError, g.__exit__, None, None, None)
            self.assertRaises(RuntimeError, f.gather().__exit__,
                              None, None, None)

    def test_not_nibbler(self):
        # _io's buffered classes can't gather.
        if not getattr(_io.BufferedWriter, '_is_nibbler', False):
            self.assertNotHasAttr(_io.BufferedWriter, 'gather')

if __name__ == '__main__':
    unittest.main()

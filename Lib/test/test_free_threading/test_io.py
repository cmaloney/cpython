import codecs
import errno
import io
import os
import _pyio as pyio
import threading
from unittest import TestCase
from test import support
from test.support import os_helper, threading_helper
from test.support.threading_helper import run_concurrently
from random import randint
from sys import getsizeof

threading_helper.requires_working_threading(module=True)


class ThreadSafetyMixin:
    # Test pretty much everything that can break under free-threading.
    # Non-deterministic, but at least one of these things will fail if
    # BytesIO object is not free-thread safe.

    def check(self, funcs, *args):
        barrier = threading.Barrier(len(funcs))
        threads = []

        for func in funcs:
            thread = threading.Thread(target=func, args=(barrier, *args))

            threads.append(thread)

        with threading_helper.start_threads(threads):
            pass

    @threading_helper.requires_working_threading()
    @threading_helper.reap_threads
    def test_free_threading(self):
        """Test for segfaults and aborts."""

        def write(barrier, b, *ignore):
            barrier.wait()
            try: b.write(b'0' * randint(100, 1000))
            except ValueError: pass  # ignore write fail to closed file

        def writelines(barrier, b, *ignore):
            barrier.wait()
            b.write(b'0\n' * randint(100, 1000))

        def truncate(barrier, b, *ignore):
            barrier.wait()
            try: b.truncate(0)
            except BufferError: pass  # ignore exported buffer

        def read(barrier, b, *ignore):
            barrier.wait()
            b.read()

        def read1(barrier, b, *ignore):
            barrier.wait()
            b.read1()

        def readline(barrier, b, *ignore):
            barrier.wait()
            b.readline()

        def readlines(barrier, b, *ignore):
            barrier.wait()
            b.readlines()

        def readinto(barrier, b, into, *ignore):
            barrier.wait()
            b.readinto(into)

        def peek(barrier, b, *ignore):
            barrier.wait()
            b.peek()

        def close(barrier, b, *ignore):
            barrier.wait()
            b.close()

        def getvalue(barrier, b, *ignore):
            barrier.wait()
            b.getvalue()

        def getbuffer(barrier, b, *ignore):
            barrier.wait()
            b.getbuffer()

        def iter(barrier, b, *ignore):
            barrier.wait()
            list(b)

        def getstate(barrier, b, *ignore):
            barrier.wait()
            b.__getstate__()

        def setstate(barrier, b, st, *ignore):
            barrier.wait()
            b.__setstate__(st)

        def sizeof(barrier, b, *ignore):
            barrier.wait()
            getsizeof(b)

        self.check([write] * 10, self.ioclass())
        self.check([writelines] * 10, self.ioclass())
        self.check([write] * 10 + [truncate] * 10, self.ioclass())
        self.check([truncate] + [read] * 10, self.ioclass(b'0\n'*204800))
        self.check([truncate] + [read1] * 10, self.ioclass(b'0\n'*204800))
        self.check([truncate] + [readline] * 10, self.ioclass(b'0\n'*20480))
        self.check([truncate] + [readlines] * 10, self.ioclass(b'0\n'*20480))
        self.check([truncate] + [readinto] * 10, self.ioclass(b'0\n'*204800), bytearray(b'0\n'*204800))
        self.check([truncate] + [peek] * 10, self.ioclass(b'0\n'*204800))
        self.check([close] + [write] * 10, self.ioclass())
        self.check([truncate] + [getvalue] * 10, self.ioclass(b'0\n'*204800))
        self.check([truncate] + [getbuffer] * 10, self.ioclass(b'0\n'*204800))
        self.check([truncate] + [iter] * 10, self.ioclass(b'0\n'*20480))
        self.check([truncate] + [getstate] * 10, self.ioclass(b'0\n'*204800))
        state = self.ioclass(b'123').__getstate__()
        self.check([truncate] + [setstate] * 10, self.ioclass(b'0\n'*204800), state)
        self.check([truncate] + [sizeof] * 10, self.ioclass(b'0\n'*204800))

        # no tests for seek or tell because they don't break anything

class CBytesIOTest(ThreadSafetyMixin, TestCase):
    ioclass = io.BytesIO

    @threading_helper.requires_working_threading()
    @threading_helper.reap_threads
    def test_concurrent_setstate_and_method_call(self):
        # gh-153290: __setstate__() installed the instance __dict__ with a
        # plain store, racing the lock-free LOAD_ATTR method fast path that
        # reads the dict slot with an atomic acquire load.
        states = [(b"A" * 64, 0, {}), (b"B" * 128, 32, {}), (b"C" * 256, 0, {})]
        nreaders = 4
        for _ in range(25):
            shared = self.ioclass(b"initial payload")
            barrier = threading.Barrier(1 + nreaders)

            def setter():
                barrier.wait()
                for state in states:
                    shared.__setstate__(state)

            def reader():
                barrier.wait()
                for _ in range(100):
                    shared.read(8)

            threads = [threading.Thread(target=setter)]
            threads += [threading.Thread(target=reader)
                        for _ in range(nreaders)]
            with threading_helper.start_threads(threads):
                pass

    @threading_helper.requires_working_threading()
    @threading_helper.reap_threads
    def test_concurrent_whole_buffer_read_and_resize(self):
        shared = self.ioclass(b"x" * 64)
        writers = 2
        readers = 8
        loops = 2000
        barrier = threading.Barrier(writers + readers)

        def writer():
            barrier.wait()
            for i in range(loops):
                shared.seek(0)
                shared.write(b"a" * (64 + (i & 63)))

        def reader():
            barrier.wait()
            for _ in range(loops):
                shared.seek(0)
                shared.read()
                shared.seek(0)
                shared.peek()
                shared.getvalue()

        threads = [threading.Thread(target=writer) for _ in range(writers)]
        threads += [threading.Thread(target=reader) for _ in range(readers)]
        with threading_helper.start_threads(threads):
            pass

class PyBytesIOTest(ThreadSafetyMixin, TestCase):
     ioclass = pyio.BytesIO


class IncrementalNewlineDecoderTest(TestCase):
    def make_decoder(self):
        utf8_decoder = codecs.getincrementaldecoder('utf-8')()
        return io.IncrementalNewlineDecoder(utf8_decoder, translate=True)

    def test_concurrent_reset(self):
        decoder = self.make_decoder()

        def worker():
            for _ in range(100):
                decoder.reset()

        run_concurrently(worker_func=worker, nthreads=2)

    def test_concurrent_decode(self):
        decoder = self.make_decoder()

        def worker():
            for _ in range(100):
                decoder.decode(b"line\r\n", final=False)

        run_concurrently(worker_func=worker, nthreads=2)

    def test_concurrent_getstate_setstate(self):
        decoder = self.make_decoder()
        state = decoder.getstate()

        def getstate_worker():
            for _ in range(100):
                decoder.getstate()

        def setstate_worker():
            for _ in range(100):
                decoder.setstate(state)

        run_concurrently([getstate_worker] * 2 + [setstate_worker] * 2)

    def test_concurrent_decode_and_reset(self):
        decoder = self.make_decoder()

        def decode_worker():
            for _ in range(100):
                decoder.decode(b"line\r\n", final=False)

        def reset_worker():
            for _ in range(100):
                decoder.reset()

        run_concurrently([decode_worker] * 2 + [reset_worker] * 2)


class FileIOTest(TestCase):
    def test_close_race(self):
        # close() wrote the file descriptor while fileno(), isatty() and
        # the closed attribute read it from other threads without
        # synchronization.
        for _ in range(100):
            f = io.FileIO(os.devnull, "rb")

            def reader():
                for _ in range(100):
                    try:
                        f.closed
                        f.fileno()
                        f.isatty()
                        f.readable()
                    except ValueError:  # I/O operation on closed file
                        pass
                    except OSError as exc:
                        if exc.errno != errno.EBADF:
                            raise

            run_concurrently([reader] * 3 + [f.close])

    def test_concurrent_close(self):
        # Only one of concurrent close() calls closes the file descriptor:
        # the others must not close it again (OSError EBADF, or worse
        # closing a reused descriptor).
        for _ in range(200):
            f = io.FileIO(os.devnull, "rb")

            def closer():
                try:
                    f.close()
                except ValueError:
                    # IOBase.close() flushes, which raises once another
                    # close() marked the file closed.
                    pass

            run_concurrently([closer] * 4)
            self.assertTrue(f.closed)

    def _stat_reader(self, f):
        # readall(), _blksize and isatty() use the stat result saved when
        # the file was opened.
        # TSan reports read() racing with close() or open() reusing the
        # descriptor, which no lock prevents; readall() still runs in
        # other builds.
        readall = not support.check_sanitizer(thread=True)
        def reader():
            for _ in range(20):
                try:
                    if readall:
                        f.readall()
                    f._blksize
                    f._isatty_open_only()
                    f.isatty()
                except (ValueError, OSError):
                    # Closed file, or a descriptor closed under the call.
                    pass
        return reader

    def test_stat_close_race(self):
        # close() freed the stat result while readers used it.
        path = os_helper.TESTFN
        self.addCleanup(os_helper.unlink, path)
        with open(path, "wb") as f:
            f.write(b"x" * 100)
        for _ in range(100):
            f = io.FileIO(path, "rb")
            run_concurrently([self._stat_reader(f)] * 3 + [f.close])
            self.assertTrue(f.closed)

    def test_stat_reinit_race(self):
        # Re-initializing a FileIO replaces its stat result while readers
        # use the old one.
        paths = [os_helper.TESTFN + str(i) for i in range(3)]
        for i, path in enumerate(paths):
            self.addCleanup(os_helper.unlink, path)
            with open(path, "wb") as f:
                f.write(b"x" * (100 << i))
        for _ in range(50):
            f = io.FileIO(paths[0], "rb")

            def reinit():
                for path in paths * 5:
                    f.__init__(path, "rb")

            run_concurrently([self._stat_reader(f)] * 3 + [reinit])
            f.close()


class TextIOWrapperTest(TestCase):
    def test_buffer_detach_race(self):
        make = lambda: io.TextIOWrapper(io.BytesIO())
        slot = [make()]

        def reader():
            for _ in range(1000):
                try:
                    slot[0].buffer
                except ValueError:
                    pass

        def detacher():
            for _ in range(1000):
                slot[0] = make()
                slot[0].detach()

        run_concurrently([reader, detacher])


class BufferedWriterTest(TestCase):
    def test_write_detach_race(self):
        # write() waiting for the buffered lock while detach() ran used to
        # use the cleared raw stream: a segfault.
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        for _ in range(200):
            buffered = io.BufferedWriter(io.FileIO(os_helper.TESTFN, "w"), 64)
            go = threading.Event()

            def writer():
                go.wait()
                for i in range(500):
                    try:
                        buffered.write(b"x" * (i % 100))
                    except ValueError:  # detached
                        return

            def reader():
                go.wait()
                for _ in range(500):
                    try:
                        (buffered.closed, buffered.name, buffered.fileno(),
                         buffered.writable())
                    except ValueError:  # detached
                        return

            def detacher():
                go.wait()
                buffered.detach().close()

            threads = [threading.Thread(target=func)
                       for func in [writer] * 3 + [reader] * 3 + [detacher]]
            with threading_helper.start_threads(threads):
                go.set()

    def test_discard_writes_race(self):
        # _discard_writes() changes the buffer offsets that the unlocked
        # fast paths of reads use: it must hold the critical section, as
        # every other method does (a data race TSan reports otherwise).
        f = io.BufferedRandom(io.BytesIO(b"line\n" * 1000), 64)

        def reader():
            for _ in range(500):
                f.peek(1)
                f.read1(3)
                f.readline()
                f.seek(0)

        def writer():
            for _ in range(500):
                f.write(b"ab")
                f._discard_writes()

        run_concurrently([reader] * 2 + [writer] * 2)

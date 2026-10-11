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


class NibblerTextIOWrapperTest(TestCase):
    """_io._nibbler.TextIOWrapper over a nibbler buffered object, used by
    several threads at once."""

    def setUp(self):
        import _io
        self.nib = _io._nibbler
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)

    def open(self, mode, encoding="utf-8", **kwargs):
        cls = {"r": self.nib.BufferedReader, "w": self.nib.BufferedWriter,
               "r+": self.nib.BufferedRandom}[mode]
        raw = io.FileIO(os_helper.TESTFN, mode)
        return self.nib.TextIOWrapper(cls(raw, **kwargs), encoding=encoding)

    def lines(self, n):
        return ["%05d \xe9\u20ac%s\n" % (i, "x" * (i % 50)) for i in range(n)]

    def test_concurrent_readline(self):
        # Each line is returned once, whole, to one of the threads, also
        # with tell() and iteration mixed in.  (UTF-16 goes through the
        # codec's decoder, with the critical section, which another thread
        # can take while one waits for the buffer: only no crash there.)
        for encoding in ("utf-8", "latin-1", "utf-16"):
            lines = self.lines(3000)
            if encoding == "latin-1":
                lines = [line.replace("\u20ac", "") for line in lines]
            with self.subTest(encoding=encoding):
                with open(os_helper.TESTFN, "w", encoding=encoding) as f:
                    f.writelines(lines)
                with self.open("r", encoding, buffer_size=1000) as f:
                    got = [[] for _ in range(4)]

                    def reader(i):
                        while True:
                            if i % 2:
                                line = f.readline()
                                f.tell()
                            else:
                                line = next(f, "")
                            if not line:
                                return
                            got[i].append(line)

                    run_concurrently([lambda i=i: reader(i) for i in range(4)])
                    if encoding == "utf-16":
                        continue
                    self.assertEqual(sorted(sum(got, [])), lines)
                    for g in got:
                        self.assertEqual(g, sorted(g))

    def test_text_and_binary_reads(self):
        # Text reads and binary reads of its buffer take every byte once.
        # (ASCII: a binary read may stop inside a character.)
        data = "".join(self.lines(2000)).encode("ascii", "ignore")
        with open(os_helper.TESTFN, "wb") as f:
            f.write(data)
        with self.open("r") as f:
            text, binary = [], []

            def text_reader():
                while line := f.readline():
                    text.append(line.encode())
                    text.append(f.read(3).encode())

            def binary_reader():
                while chunk := f.buffer.read(7):
                    binary.append(chunk)

            run_concurrently([text_reader, binary_reader])
            self.assertEqual(sum(map(len, text)) + sum(map(len, binary)),
                             len(data))
            self.assertEqual(f.read(), "")

    def test_concurrent_write(self):
        # Each write lands whole, in its thread's order, also with flush()
        # and tell() racing them.
        nthreads, count = 4, 2000
        stop = threading.Event()
        with self.open("w", buffer_size=700) as f:
            def writer(t):
                for i in range(count):
                    f.write("%d:%05d \xe9%s\n" % (t, i, "." * (i % 30)))

            def other():
                while not stop.is_set():
                    f.flush()
                    f.tell()

            others = [threading.Thread(target=other) for _ in range(2)]
            with threading_helper.start_threads(others):
                try:
                    run_concurrently([lambda t=t: writer(t)
                                      for t in range(nthreads)])
                finally:
                    stop.set()
        with open(os_helper.TESTFN, encoding="utf-8") as f:
            lines = f.read().splitlines()
        self.assertEqual(len(lines), nthreads * count)
        for t in range(nthreads):
            mine = [line for line in lines if line.startswith("%d:" % t)]
            self.assertEqual(mine, ["%d:%05d \xe9%s" % (t, i, "." * (i % 30))
                                    for i in range(count)])

    def test_read_write_close_race(self):
        # Reads, writes, flush(), tell(), seek() and close() of one file in
        # several threads: no crash, and only the errors of a closed file.
        for _ in range(20):
            with open(os_helper.TESTFN, "w", encoding="utf-8") as f:
                f.writelines(self.lines(300))
            f = self.open("r+", buffer_size=500)

            def worker(op):
                for i in range(200):
                    try:
                        op(i)
                    except ValueError:
                        # Closed (by another thread).
                        return

            ops = [
                lambda i: f.readline(),
                lambda i: f.read(7),
                lambda i: f.write("w%d\xe9\n" % i),
                lambda i: (f.flush(), f.tell()),
                lambda i: f.seek(0) if i % 50 == 0 else f.tell(),
                lambda i: i == 150 and f.close(),
            ]
            run_concurrently([lambda op=op: worker(op) for op in ops])
            f.close()


    def test_reconfigure_detach_race(self):
        # reconfigure() of what can change after reading, tell(), reads and
        # writes racing, then detach() racing them: no crash, and only the
        # errors of a detached file.
        for _ in range(20):
            with open(os_helper.TESTFN, "w", encoding="utf-8") as f:
                f.writelines(self.lines(300))
            f = self.open("r+", buffer_size=500)
            stop = threading.Event()

            def worker(op):
                while not stop.is_set():
                    try:
                        op()
                    except ValueError:
                        return

            def reconfigure():
                for i in range(200):
                    try:
                        f.reconfigure(line_buffering=bool(i % 2),
                                      write_through=bool(i % 3))
                    except ValueError:
                        return
                    f.line_buffering, f.write_through, f.encoding, f.errors

            def detach():
                for _ in range(100):
                    f.tell()
                stop.set()
                f.detach().close()

            ops = [lambda: f.readline(), lambda: f.write("x\n"),
                   lambda: (f.tell(), f.newlines, f.name, f.buffer)]
            run_concurrently([lambda op=op: worker(op) for op in ops]
                             + [reconfigure, detach])

    @support.requires_subprocess()
    def test_daemon_writers_at_exit(self):
        # Daemon threads still writing through sys.stdout when the process
        # exits: no hang at the exit flush (a writer waiting on a lock held
        # by a thread that can't run any more).
        import subprocess, sys
        code = """if 1:
            import sys, threading, time
            def w():
                while True:
                    sys.stdout.write("x" * 50 + "\\n")
            for _ in range(4):
                threading.Thread(target=w, daemon=True).start()
            time.sleep(0.01)
            """
        env = dict(os.environ, _PYTHON_IO_DEFAULT_IMPL="_nibbler")
        for _ in range(30):
            proc = subprocess.run([sys.executable, "-c", code], env=env,
                                  stdout=subprocess.DEVNULL,
                                  timeout=support.SHORT_TIMEOUT)
            self.assertEqual(proc.returncode, 0)


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

    def test_small_writes_with_flush_and_tell(self):
        # Small writes from many threads, racing flush() and tell(), each
        # land whole and in their thread's order.
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        nthreads, count = 6, 3000
        stop = threading.Event()
        with open(os_helper.TESTFN, "wb", buffering=512) as f:
            def writer(tid):
                for i in range(count):
                    f.write(b"%d:%05d%s\n" % (tid, i, b"." * (i % 30)))

            def other():
                while not stop.is_set():
                    f.flush()
                    f.tell()

            others = [threading.Thread(target=other) for _ in range(2)]
            with threading_helper.start_threads(others):
                try:
                    run_concurrently([lambda t=t: writer(t)
                                      for t in range(nthreads)])
                finally:
                    stop.set()
        with open(os_helper.TESTFN, "rb") as f:
            lines = f.read().splitlines()
        self.assertEqual(len(lines), nthreads * count)
        for t in range(nthreads):
            mine = [line for line in lines if line.startswith(b"%d:" % t)]
            self.assertEqual(mine, [b"%d:%05d%s" % (t, i, b"." * (i % 30))
                                    for i in range(count)])

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


class NibblerReinitTest(TestCase):
    """_io._nibbler buffered objects re-initialized, or given an instance
    dict, while other threads use them (for TSan, and crashes)."""

    def setUp(self):
        global _nibbler
        from _io import _nibbler
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        self.addCleanup(os_helper.unlink, os_helper.TESTFN + "2")

    class PyRaw(io.RawIOBase):
        # Not a FileIO, with a vectored write: re-initializing with it and
        # with a FileIO changes every raw_* flag of the buffered object.
        def __init__(self):
            self.data = bytearray(b"line\n" * 1000)
        def readable(self):
            return True
        def writable(self):
            return True
        def readinto(self, b):
            n = min(len(b), len(self.data))
            b[:n] = self.data[:n]
            del self.data[:n]
            return n
        def write(self, b):
            return len(b)
        def _writev(self, buffers):
            return sum(len(b) for b in buffers)

    def raws(self):
        # FileIO in append mode, FileIO, a Python raw stream.
        return [lambda: io.FileIO(os_helper.TESTFN, "a"),
                lambda: io.FileIO(os_helper.TESTFN + "2", "w"),
                self.PyRaw]

    def run_with_reinit(self, f, users, make_raws, rounds=500):
        stop = threading.Event()

        def reinit():
            try:
                for i in range(rounds):
                    old = f.raw
                    try:
                        f.__init__(make_raws[i % len(make_raws)](), 64)
                    except (OSError, ValueError):
                        pass
                    if isinstance(old, io.FileIO):
                        old.close()
            finally:
                stop.set()

        def use(func):
            def run():
                while not stop.is_set():
                    try:
                        func()
                    except (OSError, ValueError, RuntimeError):
                        pass
            return run

        run_concurrently([reinit] + [use(u) for u in users])

    def close_text(self, f, t):
        # Over an open raw stream.  (TextIOWrapper may still check the raw
        # stream its buffer had when it was created, closed by now.)
        f.__init__(self.PyRaw(), 64)
        try:
            t.close()
        except ValueError:
            pass

    def test_reinit_while_writing(self):
        f = _nibbler.BufferedWriter(self.raws()[1](), 64)
        t = io.TextIOWrapper(f, encoding="utf-8", write_through=True)

        def gather():
            with f._gather():
                f.write(b"g" * 600)

        users = [lambda: f.write(b"x" * 10),
                 lambda: f.write(bytearray(b"z" * 10)),
                 lambda: f.write(b"y" * 600),
                 lambda: t.write("text\n"),
                 lambda: t.write("\xe9t\xe9\n"),
                 gather,
                 f.flush, f.tell]
        self.run_with_reinit(f, users, self.raws())
        self.close_text(f, t)

    def test_reinit_while_reading(self):
        with open(os_helper.TESTFN, "wb") as w:
            w.write(b"line\n" * 10000)
        make_raws = [lambda: io.FileIO(os_helper.TESTFN, "r"),
                     self.PyRaw]
        f = _nibbler.BufferedReader(make_raws[0](), 64)
        t = io.TextIOWrapper(f, encoding="utf-8")
        users = [lambda: f.read(3), f.readline, lambda: f.peek(1),
                 lambda: f.read1(10), t.readline, lambda: t.read(5)]
        self.run_with_reinit(f, users, make_raws)
        self.close_text(f, t)

    def test_instance_dict_while_used(self):
        # The text layer looks at the instance dict without the lock (an
        # attribute could override a method): give one to an object in use.
        with open(os_helper.TESTFN, "wb") as w:
            w.write(b"line\n" * 10000)
        for _ in range(100):
            r = _nibbler.BufferedReader(io.FileIO(os_helper.TESTFN, "r"), 64)
            w = _nibbler.BufferedWriter(
                io.FileIO(os_helper.TESTFN + "2", "w"), 64)
            tr = io.TextIOWrapper(r, encoding="utf-8")
            tw = io.TextIOWrapper(w, encoding="utf-8", write_through=True)

            def reader():
                for _ in range(50):
                    tr.readline()

            def writer():
                for _ in range(50):
                    tw.write("text\n")

            def setter():
                r.attr = 1
                w.attr = 1

            run_concurrently([reader, writer, setter])
            tr.close()
            tw.close()


class SetOpenImplTest(TestCase):
    def test_open_set_open_impl_race(self):
        # open() read the buffered classes _io._set_open_impl() replaces
        # without synchronization or a reference of its own.
        import _io
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        with open(os_helper.TESTFN, "wb") as f:
            f.write(b"x")
        prev = _io._set_open_impl("_io")
        self.addCleanup(_io._set_open_impl, prev)

        def opener():
            for _ in range(200):
                with open(os_helper.TESTFN, "rb") as f:
                    self.assertEqual(f.read(), b"x")

        def switcher():
            for i in range(200):
                _io._set_open_impl("_nibbler" if i % 2 else "_io")

        run_concurrently([opener] * 3 + [switcher])

    def test_open_set_unbuffered_impl_race(self):
        # open(buffering=0) gets the class _io._set_unbuffered_impl()
        # replaces (or unsets) as one reference.
        import _io
        self.addCleanup(os_helper.unlink, os_helper.TESTFN)
        with open(os_helper.TESTFN, "wb") as f:
            f.write(b"x")
        prev = _io._set_unbuffered_impl("_io")
        self.addCleanup(_io._set_unbuffered_impl, prev)

        def opener():
            for _ in range(200):
                with open(os_helper.TESTFN, "rb", buffering=0) as f:
                    self.assertEqual(f.read(), b"x")

        def switcher():
            for i in range(200):
                _io._set_unbuffered_impl("_nibbler" if i % 2 else "_io")

        run_concurrently([opener] * 3 + [switcher])

    def test_set_impl_returns_previous(self):
        # Each call returns the name it replaced: of all the names set and
        # the first one, those replaced and the last one are the same.
        import _io
        from collections import Counter
        for func in _io._set_open_impl, _io._set_unbuffered_impl:
            with self.subTest(func=func.__name__):
                first = func("_io")
                self.addCleanup(func, first)
                names = Counter()
                returned = Counter()
                lock = threading.Lock()

                def switcher(i):
                    mine, got = Counter(), Counter()
                    for k in range(500):
                        name = "_nibbler" if (i + k) % 2 else "_io"
                        mine[name] += 1
                        got[func(name)] += 1
                    with lock:
                        names.update(mine)
                        returned.update(got)

                run_concurrently([lambda i=i: switcher(i) for i in range(4)])
                last = func("_io")
                self.assertEqual(returned + Counter([last]),
                                 names + Counter(["_io"]))

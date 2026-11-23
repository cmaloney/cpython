import asyncio
import threading
import time
import unittest
from threading import Thread
from unittest import TestCase
import weakref
from test import support
from test.support import threading_helper

threading_helper.requires_working_threading(module=True)


class MyException(Exception):
    pass


def tearDownModule():
    asyncio.set_event_loop(None)


class TestFreeThreading:
    def test_all_tasks_race(self) -> None:
        async def main():
            loop = asyncio.get_running_loop()
            future = loop.create_future()

            async def coro():
                await future

            tasks = set()

            async with asyncio.TaskGroup() as tg:
                for _ in range(100):
                    tasks.add(tg.create_task(coro()))

                all_tasks = asyncio.all_tasks(loop)
                self.assertEqual(len(all_tasks), 101)

                for task in all_tasks:
                    self.assertEqual(task.get_loop(), loop)
                    self.assertFalse(task.done())

                current = asyncio.current_task()
                self.assertEqual(current.get_loop(), loop)
                self.assertSetEqual(all_tasks, tasks | {current})
                future.set_result(None)

        def runner():
            with asyncio.Runner() as runner:
                loop = runner.get_loop()
                loop.set_task_factory(self.factory)
                runner.run(main())

        threads = []

        for _ in range(10):
            thread = Thread(target=runner)
            threads.append(thread)

        with threading_helper.start_threads(threads):
            pass

    def test_all_tasks_different_thread(self) -> None:
        loop = None
        started = threading.Event()
        done = threading.Event() # used for main task not finishing early
        async def coro():
            await asyncio.Future()

        lock = threading.Lock()
        tasks = set()

        async def main():
            nonlocal tasks, loop
            loop = asyncio.get_running_loop()
            started.set()
            for i in range(1000):
                with lock:
                    asyncio.create_task(coro())
                    tasks = asyncio.all_tasks(loop)
            done.wait()

        runner = threading.Thread(target=lambda: asyncio.run(main()))

        def check():
            started.wait()
            with lock:
                self.assertSetEqual(tasks & asyncio.all_tasks(loop), tasks)

        threads = [threading.Thread(target=check) for _ in range(10)]
        runner.start()

        with threading_helper.start_threads(threads):
            pass

        done.set()
        runner.join()

    def test_task_different_thread_finalized(self) -> None:
        task = None
        async def func():
            nonlocal task
            task = asyncio.current_task()
        def runner():
            with asyncio.Runner() as runner:
                loop = runner.get_loop()
                loop.set_task_factory(self.factory)
                runner.run(func())
        thread = Thread(target=runner)
        thread.start()
        thread.join()
        wr = weakref.ref(task)
        del thread
        del task
        # task finalization in different thread shouldn't crash
        support.gc_collect()
        self.assertIsNone(wr())

    def test_unregister_lingering_tasks_of_exited_thread(self) -> None:
        # gh-159449: only the thread state that registered a task may
        # remove it from a task list without stopping the world.  When a
        # thread exits, its pending tasks linger on the interpreter's list,
        # and a new thread often reuses the exited thread's OS thread id and
        # thread state memory, so neither identifies the registering thread.
        #
        # Several threads remove lingering tasks at the same moment.  If any
        # of them wrongly skips stopping the world, the list gets corrupted
        # and the all_tasks() call at the end of the round crashes.
        class InertLoop:
            def get_debug(self):
                return False

            def is_running(self):
                return False

            def call_soon(self, *args, **kwargs):
                pass

        loop = InertLoop()
        nthreads = 4
        ntasks = 64
        timeout = support.SHORT_TIMEOUT

        async def coro():
            pass

        def new_task():
            c = coro()
            task = self.factory(loop, c)
            c.close()
            task._log_destroy_pending = False
            return task

        def run_round(paired):
            # Each creator registers its tasks, then the creators exit one
            # at a time, so the interpreter's list holds each creator's
            # tasks contiguously, in creator order.
            blocks = [None] * nthreads
            creator_of = {}
            exits = [threading.Event() for _ in range(nthreads)]
            ready = []
            stop_inspector = threading.Event()

            def creator(i):
                blocks[i] = [new_task() for _ in range(ntasks)]
                creator_of[threading.get_ident()] = i
                exits[i].wait(timeout)

            def remover(i=None):
                if i is None:
                    i = creator_of.get(threading.get_ident())
                # Spin instead of using a Barrier: wake-ups from a Barrier
                # are spread out more than the removals take, so the
                # removers would rarely overlap.
                ready.append(None)
                deadline = time.monotonic() + timeout
                while len(ready) < nthreads:
                    if time.monotonic() > deadline:
                        return
                if i is None:
                    return
                # Removers of neighbouring blocks 0 and 1 (and 2 and 3)
                # start at the boundary between their blocks.
                tasks = blocks[i] if i % 2 else reversed(blocks[i])
                for task in tasks:
                    # complete the task right away, unlike Task.cancel()
                    asyncio.Future.cancel(task)

            def inspector():
                while not stop_inspector.is_set():
                    asyncio.all_tasks(loop)

            # Also call all_tasks() while tasks are registered and while
            # exiting creators move their tasks to the interpreter's list.
            # Stop it before the removals start: it stops the world, which
            # would keep the removers from overlapping.
            inspector_thread = Thread(target=inspector)
            creators = [Thread(target=creator, args=(i,))
                        for i in range(nthreads)]
            removers = []
            try:
                inspector_thread.start()
                for thread in creators:
                    thread.start()
                for i, thread in enumerate(creators):
                    exits[i].set()
                    thread.join()
                    if paired:
                        if i == nthreads - 1:
                            stop_inspector.set()
                            inspector_thread.join()
                        # Started right after the creator exits, the
                        # remover typically reuses its thread state memory.
                        removers.append(Thread(target=remover, args=(i,)))
                        removers[-1].start()
                stop_inspector.set()
                inspector_thread.join()
                if not paired:
                    # Each remover completes the tasks of the creator whose
                    # OS thread id it reused.  threading.get_ident() is the
                    # id compared by the original bug on pthreads platforms,
                    # but not on Windows, where these rounds are weaker.
                    removers = [Thread(target=remover)
                                for _ in range(nthreads)]
                    for thread in removers:
                        thread.start()
            finally:
                stop_inspector.set()
                for event in exits:
                    event.set()
                for thread in [inspector_thread, *creators, *removers]:
                    if thread.ident is not None:
                        thread.join()

            # Complete the tasks of creators whose thread id was not reused.
            for tasks in blocks:
                for task in tasks:
                    if not task.done():
                        asyncio.Future.cancel(task)
            # Walking a corrupted list crashes.
            self.assertEqual(asyncio.all_tasks(loop), set())

        for paired in (False, True) * 3:
            run_round(paired)

    def test_run_coroutine_threadsafe(self) -> None:
        results = []

        def in_thread(loop: asyncio.AbstractEventLoop):
            coro = asyncio.sleep(0.1, result=42)
            fut = asyncio.run_coroutine_threadsafe(coro, loop)
            result = fut.result()
            self.assertEqual(result, 42)
            results.append(result)

        async def main():
            loop = asyncio.get_running_loop()
            async with asyncio.TaskGroup() as tg:
                for _ in range(10):
                    tg.create_task(asyncio.to_thread(in_thread, loop))
            self.assertEqual(results, [42] * 10)

        with asyncio.Runner() as r:
            loop = r.get_loop()
            loop.set_task_factory(self.factory)
            r.run(main())

    def test_run_coroutine_threadsafe_exception(self) -> None:
        async def coro():
            await asyncio.sleep(0)
            raise MyException("test")

        def in_thread(loop: asyncio.AbstractEventLoop):
            fut = asyncio.run_coroutine_threadsafe(coro(), loop)
            return fut.result()

        async def main():
            loop = asyncio.get_running_loop()
            tasks = []
            for _ in range(10):
                task = loop.create_task(asyncio.to_thread(in_thread, loop))
                tasks.append(task)
            results = await asyncio.gather(*tasks, return_exceptions=True)

            self.assertEqual(len(results), 10)
            for result in results:
                self.assertIsInstance(result, MyException)
                self.assertEqual(str(result), "test")

        with asyncio.Runner() as r:
            loop = r.get_loop()
            loop.set_task_factory(self.factory)
            r.run(main())

    def test_all_tasks_from_other_thread_includes_eager_tasks(self):
        # gh-152020: all_tasks() called from another thread used to drop
        # eager-started tasks on free-threaded builds.
        loop = asyncio.new_event_loop()

        async def wait_forever():
            await asyncio.Event().wait()

        def eager_factory(loop, coro, **kwargs):
            return self.factory(loop, coro, eager_start=True, **kwargs)

        async def setup():
            loop.set_task_factory(eager_factory)
            eager = loop.create_task(wait_forever(), name="EAGER")
            loop.set_task_factory(None)
            normal = loop.create_task(wait_forever(), name="NORMAL")
            return eager, normal

        async def teardown():
            tasks = [t for t in asyncio.all_tasks()
                     if t is not asyncio.current_task()]
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        thread = threading.Thread(target=loop.run_forever)
        thread.start()
        try:
            held = asyncio.run_coroutine_threadsafe(setup(), loop).result()
            names = {t.get_name() for t in asyncio.all_tasks(loop)}
            self.assertIn("NORMAL", names)
            self.assertIn("EAGER", names)
            del held
        finally:
            asyncio.run_coroutine_threadsafe(teardown(), loop).result()
            loop.call_soon_threadsafe(loop.stop)
            thread.join()
            loop.close()


class TestPyFreeThreading(TestFreeThreading, TestCase):

    def setUp(self):
        self._old_current_task = asyncio.current_task
        asyncio.current_task = asyncio.tasks.current_task = asyncio.tasks._py_current_task
        self._old_all_tasks = asyncio.all_tasks
        asyncio.all_tasks = asyncio.tasks.all_tasks = asyncio.tasks._py_all_tasks
        self._old_Task = asyncio.Task
        asyncio.Task = asyncio.tasks.Task = asyncio.tasks._PyTask
        self._old_Future = asyncio.Future
        asyncio.Future = asyncio.futures.Future = asyncio.futures._PyFuture
        return super().setUp()

    def tearDown(self):
        asyncio.current_task = asyncio.tasks.current_task = self._old_current_task
        asyncio.all_tasks = asyncio.tasks.all_tasks = self._old_all_tasks
        asyncio.Task = asyncio.tasks.Task = self._old_Task
        asyncio.Future = asyncio.tasks.Future = self._old_Future
        return super().tearDown()

    def factory(self, loop, coro, **kwargs):
        return asyncio.tasks._PyTask(coro, loop=loop, **kwargs)


@unittest.skipUnless(hasattr(asyncio.tasks, "_c_all_tasks"), "requires _asyncio")
class TestCFreeThreading(TestFreeThreading, TestCase):

    def setUp(self):
        self._old_current_task = asyncio.current_task
        asyncio.current_task = asyncio.tasks.current_task = asyncio.tasks._c_current_task
        self._old_all_tasks = asyncio.all_tasks
        asyncio.all_tasks = asyncio.tasks.all_tasks = asyncio.tasks._c_all_tasks
        self._old_Task = asyncio.Task
        asyncio.Task = asyncio.tasks.Task = asyncio.tasks._CTask
        self._old_Future = asyncio.Future
        asyncio.Future = asyncio.futures.Future = asyncio.futures._CFuture
        return super().setUp()

    def tearDown(self):
        asyncio.current_task = asyncio.tasks.current_task = self._old_current_task
        asyncio.all_tasks = asyncio.tasks.all_tasks = self._old_all_tasks
        asyncio.Task = asyncio.tasks.Task = self._old_Task
        asyncio.Future = asyncio.futures.Future = self._old_Future
        return super().tearDown()


    def factory(self, loop, coro, **kwargs):
        return asyncio.tasks._CTask(coro, loop=loop, **kwargs)


class TestEagerPyFreeThreading(TestPyFreeThreading):
    def factory(self, loop, coro, eager_start=True, **kwargs):
        return asyncio.tasks._PyTask(coro, loop=loop, **kwargs, eager_start=eager_start)


@unittest.skipUnless(hasattr(asyncio.tasks, "_c_all_tasks"), "requires _asyncio")
class TestEagerCFreeThreading(TestCFreeThreading, TestCase):
    def factory(self, loop, coro, eager_start=True, **kwargs):
        return asyncio.tasks._CTask(coro, loop=loop, **kwargs, eager_start=eager_start)

"""Memory watchdog: periodically print the memory usage of the given PID.

Typical: memory_watchdog.py is launched as a subprocess watching
until the parent closes stdin.

Darwin: Uses a subinterpreter since we want to use tas().
"""

import contextlib
import os
import select
import subprocess
import sys
from concurrent import interpreters
from test.support import get_pagesize


def _wait_select(timeout):
    return bool(select.select([sys.stdin], [], [], timeout)[0])


def _watch_loop(backend):
    max_size = 0
    while True:
        try:
            size = backend.get_size()
        except OSError:
            break
        if size > max_size:
            max_size = size
        print(f' ... process memory: {size / 1024**3:.1f}G', flush=True)
        if backend.wait_stop(1.0):
            break
    if max_size:
        print(f' ... max process memory: {max_size / 1024**3:.1f}G',
              flush=True)


class _DarwinBackend:
    def __init__(self, stop_q):
        self._stop_q = stop_q

    def get_size(self):
        from _testcapi import task_vm_phys_footprint
        return task_vm_phys_footprint()

    def wait_stop(self, timeout):
        import queue
        try:
            self._stop_q.get(timeout=timeout)
            return True
        except queue.Empty:
            return False


class _LinuxBackend:
    def __init__(self, pid):
        self._page_size = get_pagesize()
        self._statm = open(f'/proc/{pid}/statm')

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self._statm.close()

    def get_size(self):
        self._statm.seek(0)
        return int(self._statm.read().split()[5]) * self._page_size

    def wait_stop(self, timeout):
        return _wait_select(timeout)


class _WindowsBackend:
    def __init__(self, pid):
        import _winapi
        import msvcrt
        self._winapi = _winapi
        self._handle = _winapi.OpenProcess(
            _winapi.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        self._stdin_handle = msvcrt.get_osfhandle(sys.stdin.fileno())

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self._winapi.CloseHandle(self._handle)

    def get_size(self):
        return self._winapi.GetProcessMemoryInfo(self._handle)

    def wait_stop(self, timeout):
        result = self._winapi.WaitForSingleObject(
            self._stdin_handle, int(timeout * 1000))
        return result == self._winapi.WAIT_OBJECT_0


def _darwin_watch_loop(stop_q):
    print(' ... NOTE: memory carries between tests on Darwin', flush=True)
    _watch_loop(_DarwinBackend(stop_q))


class DarwinWatchdog(contextlib.AbstractContextManager):
    def __enter__(self):
        self._interp = interpreters.create()
        self._stop_q = interpreters.create_queue()
        self._thread = self._interp.call_in_thread(
            _darwin_watch_loop, self._stop_q)
        return self

    def __exit__(self, *_):
        self._stop_q.put(None)
        self._thread.join()
        self._interp.close()


class _SubprocessWatchdog(contextlib.AbstractContextManager):
    def __init__(self, backend_cls):
        self._backend_cls = backend_cls

    def __enter__(self):
        self._proc = subprocess.Popen(
            [sys.executable, __file__,
             str(os.getpid()), self._backend_cls.__name__],
            stdin=subprocess.PIPE,
        )
        assert self._proc.stdin is not None
        self._stdin = self._proc.stdin
        return self

    def __exit__(self, *_):
        self._stdin.close()
        self._proc.wait()


def get_watchdog():
    """Return the appropriate watchdog for the current platform, or None."""
    if sys.platform == 'darwin':
        return DarwinWatchdog()
    elif sys.platform == 'linux':
        return _SubprocessWatchdog(_LinuxBackend)
    elif sys.platform == 'win32':
        return _SubprocessWatchdog(_WindowsBackend)
    return None


if __name__ == '__main__':
    pid = int(sys.argv[1])
    backend_cls = globals()[sys.argv[2]]
    with backend_cls(pid) as backend:
        _watch_loop(backend)

# Measure buffered writes to (or reads from) one file from many threads at
# once.
#
# Usage: python Tools/nibblerbench/contention.py [options]
#
# Options:
#   --impl NAME      open() implementation: _nibbler (default) or _io.
#   --mode b|t       Binary (BufferedWriter, default) or text writes.
#   --op write|readline
#                    Write lines (default), or read them: every thread
#                    calls readline() on one shared file object.
#   --threads LIST   Comma separated thread counts (default: 1,2,4,16,32).
#   --lines N        Lines written in all, split between the threads
#                    (default: 1600000).
#   --gather N       Write in _gather() blocks of N lines each (writes
#                    only; 0, the default: no blocks).
#   --repeats N      Runs per thread count; the median is reported
#                    (default: 5).
#
# Each thread writes 27-byte lines with f.write() as fast as it can.  Small
# writes mostly go to the buffer without its lock; they contend on it when
# the buffer fills and is written out.  Reading, lines in the read-ahead are
# taken without the lock; threads contend on it when a fill is needed.
# Thread counts above 1 are only meaningful for `--disable-gil` builds.

import _io
import argparse
import os
import statistics
import tempfile
import threading
import time

LINE = b"0123456789abcdef0123456789\n"


def run(path, mode, nthreads, per_thread, gather=0):
    f = open(path, "wb" if mode == "b" else "w")
    line = LINE if mode == "b" else LINE.decode()
    barrier = threading.Barrier(nthreads + 1)

    def worker():
        write = f.write
        barrier.wait()
        if not gather:
            for _ in range(per_thread):
                write(line)
            return
        block = (f if mode == "b" else f.buffer)._gather
        for _ in range(per_thread // gather):
            with block():
                for _ in range(gather):
                    write(line)

    threads = [threading.Thread(target=worker) for _ in range(nthreads)]
    for t in threads:
        t.start()
    barrier.wait()
    start = time.perf_counter()
    for t in threads:
        t.join()
    f.flush()
    elapsed = time.perf_counter() - start
    f.close()
    if os.path.getsize(path) != nthreads * per_thread * len(LINE):
        raise RuntimeError("lost or duplicated writes")
    return elapsed


def run_readline(path, mode, nthreads, per_thread):
    with open(path, "wb") as f:
        f.write(LINE * (nthreads * per_thread))
    f = open(path, "rb" if mode == "b" else "r")
    barrier = threading.Barrier(nthreads + 1)
    counts = []

    def worker():
        readline = f.readline
        n = 0
        barrier.wait()
        while readline():
            n += 1
        counts.append(n)

    threads = [threading.Thread(target=worker) for _ in range(nthreads)]
    for t in threads:
        t.start()
    barrier.wait()
    start = time.perf_counter()
    for t in threads:
        t.join()
    elapsed = time.perf_counter() - start
    f.close()
    if sum(counts) != nthreads * per_thread:
        raise RuntimeError("lost or duplicated lines")
    return elapsed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--impl", default="_nibbler")
    parser.add_argument("--mode", choices=("b", "t"), default="b")
    parser.add_argument("--op", choices=("write", "readline"),
                        default="write")
    parser.add_argument("--threads", default="1,2,4,16,32")
    parser.add_argument("--lines", type=int, default=1_600_000)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--gather", type=int, default=0)
    args = parser.parse_args()

    _io._set_open_impl(args.impl)
    fd, path = tempfile.mkstemp()
    os.close(fd)
    try:
        for n in map(int, args.threads.split(",")):
            per_thread = args.lines // n
            if args.gather:
                per_thread -= per_thread % args.gather
            func = run if args.op == "write" else run_readline
            extra = (args.gather,) if args.gather else ()
            times = [func(path, args.mode, n, per_thread, *extra)
                     for _ in range(args.repeats)]
            med = statistics.median(times)
            g = f" gather={args.gather}" if args.gather else ""
            print(f"{args.impl} {args.op} {args.mode}{g} threads={n:3d}  "
                  f"{med * 1000:9.1f} ms  "
                  f"{n * per_thread / med / 1e6:6.2f} Mlines/s  "
                  f"(min {min(times) * 1000:.1f}, max {max(times) * 1000:.1f})")
    finally:
        os.unlink(path)


if __name__ == "__main__":
    main()

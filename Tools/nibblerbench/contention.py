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
#   --gather-life    Write in one _gather(direct=True) block per thread,
#                    for its whole life.
#   --direct         Blocks of --gather N with direct=True.
#   --line-flush     Blocks with line_flush=True.
#   --line-buffering No blocks, line buffered (binary: flush() per line).
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


def run(path, mode, nthreads, per_thread, gather=0, kw={}, lb=False):
    f = open(path, "wb" if mode == "b" else "w",
             buffering=1 if lb and mode == "t" else -1)
    line = LINE if mode == "b" else LINE.decode()
    barrier = threading.Barrier(nthreads + 1)

    def worker():
        write = f.write
        flush = f.flush
        barrier.wait()
        block = getattr(f if mode == "b" else f.buffer, "_gather", None)
        if gather < 0:
            with block(**kw):
                for _ in range(per_thread):
                    write(line)
        elif lb and mode == "b":
            for _ in range(per_thread):
                write(line)
                flush()
        elif not gather:
            for _ in range(per_thread):
                write(line)
        else:
            for _ in range(per_thread // gather):
                with block(**kw):
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
    parser.add_argument("--gather-life", action="store_true")
    parser.add_argument("--direct", action="store_true")
    parser.add_argument("--line-flush", action="store_true")
    parser.add_argument("--line-buffering", action="store_true")
    args = parser.parse_args()
    kw = {}
    if args.gather_life or args.direct:
        kw["direct"] = True
    if args.line_flush:
        kw["line_flush"] = True
    gather = -1 if args.gather_life else args.gather
    label = ("".join(f" {k}" for k in kw) + (" life" if gather < 0 else "")
             + (f" gather={gather}" if gather > 0 else "")
             + (" line-buffering" if args.line_buffering else ""))

    _io._set_open_impl(args.impl)
    fd, path = tempfile.mkstemp()
    os.close(fd)
    try:
        for n in map(int, args.threads.split(",")):
            per_thread = args.lines // n
            if gather > 0:
                per_thread -= per_thread % gather
            func = run if args.op == "write" else run_readline
            extra = ((gather, kw, args.line_buffering) if args.op == "write"
                     else ())
            times = [func(path, args.mode, n, per_thread, *extra)
                     for _ in range(args.repeats)]
            med = statistics.median(times)
            print(f"{args.impl} {args.op} {args.mode}{label} threads={n:3d}  "
                  f"{med * 1000:9.1f} ms  "
                  f"{n * per_thread / med / 1e6:6.2f} Mlines/s  "
                  f"(min {min(times) * 1000:.1f}, "
                  f"max {max(times) * 1000:.1f})")
    finally:
        os.unlink(path)


if __name__ == "__main__":
    main()

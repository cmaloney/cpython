# Measure block churn: reading and writing a large file in small pieces,
# which fills (reading) or rolls over (writing) a buffer-sized block every
# buffer's worth of data.
#
# Usage: python Tools/nibblerbench/churn.py [options]
#
# Options:
#   --impl NAME      open() implementation: _nibbler (default) or _io.
#   --ops LIST       Comma separated operations (default:
#                    read64,readline,write16): read(64) calls, iteration
#                    over lines, or write() of 16 bytes.
#   --mib N          MiB read or written per run (default: 64).
#   --threads N      Threads running the operation at once, each on a file
#                    of its own (default: 1).
#   --repeats N      Runs; the median is reported (default: 5).
#   --allocs         Instead of timing, count the blocks _io._nibbler
#                    allocates per MiB (nibbler_new_block() calls), by
#                    running each operation once under valgrind's
#                    callgrind (needs valgrind; slow).
#
# _io's buffered classes allocate their buffer once; _io._nibbler allocates
# a block when it can't reuse one, which on free-threaded builds needs no
# thread to be able to still read the block (see nibbler_fresh_block()).

import _io
import argparse
import os
import re
import statistics
import subprocess
import sys
import tempfile
import threading
import time

LINE = b"x" * 79 + b"\n"
CHUNK = b"x" * 15 + b"\n"


def make_input(path, mib):
    with open(path, "wb") as f:
        f.write(LINE * ((mib << 20) // len(LINE)))


def run_op(op, path, mib):
    """Read path (made by make_input() with mib MiB) or write mib MiB."""
    if mib == 0:
        open(path, "rb").close()
    elif op == "write16":
        with open(path, "wb") as f:
            write = f.write
            for _ in range((mib << 20) // len(CHUNK)):
                write(CHUNK)
    elif op == "readline":
        with open(path, "rb") as f:
            for _ in f:
                pass
    elif op == "read64":
        with open(path, "rb") as f:
            read = f.read
            while read(64):
                pass
    else:
        raise ValueError(op)


def timed(op, paths, mib):
    threads = [threading.Thread(target=run_op, args=(op, p, mib))
               for p in paths]
    start = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return time.perf_counter() - start


def callgrind_calls(code, func):
    """Run `python -c code` under callgrind; return the calls of func."""
    fd, out = tempfile.mkstemp(suffix=".callgrind")
    os.close(fd)
    try:
        subprocess.run(["valgrind", "--tool=callgrind",
                        f"--callgrind-out-file={out}", sys.executable,
                        "-c", code], check=True, capture_output=True)
        names = {}
        callee = None
        total = 0
        with open(out) as f:
            for line in f:
                m = re.match(r"(c?fn)=\((\d+)\)(?: (.*))?", line)
                if m:
                    if m.group(3):
                        names[m.group(2)] = m.group(3).strip()
                    if m.group(1) == "cfn":
                        callee = names.get(m.group(2))
                elif line.startswith("calls=") and callee == func:
                    total += int(line[6:].split()[0])
        return total
    finally:
        os.unlink(out)


def count_allocs(impl, op, path, mib):
    # Blocks per MiB: calls of nibbler_new_block() in a run of the operation,
    # minus those of a run that does nothing (opening the input aside).
    def calls(n):
        code = (f"import _io, sys; sys.path.insert(0, "
                f"{os.path.dirname(os.path.abspath(__file__))!r}); "
                f"_io._set_open_impl({impl!r}); import churn; "
                f"churn.run_op({op!r}, {path!r}, {n})")
        return callgrind_calls(code, "nibbler_new_block")
    return (calls(mib) - calls(0)) / mib


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--impl", default="_nibbler")
    parser.add_argument("--ops", default="read64,readline,write16")
    parser.add_argument("--mib", type=int, default=64)
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--allocs", action="store_true")
    args = parser.parse_args()

    _io._set_open_impl(args.impl)
    tmp = tempfile.mkdtemp()
    paths = [os.path.join(tmp, f"churn{i}.bin") for i in range(args.threads)]
    try:
        for p in paths:
            make_input(p, args.mib)
        for op in args.ops.split(","):
            if args.allocs:
                per = count_allocs(args.impl, op, paths[0], args.mib)
                print(f"{args.impl} {op:8s} {per:8.1f} blocks/MiB")
                continue
            times = [timed(op, paths, args.mib) for _ in range(args.repeats)]
            med = statistics.median(times)
            mib = args.mib * args.threads
            print(f"{args.impl} {op:8s} threads={args.threads:2d}  "
                  f"{med * 1000:8.1f} ms  {mib / med:8.1f} MiB/s  "
                  f"(min {min(times) * 1000:.1f}, "
                  f"max {max(times) * 1000:.1f})")
    finally:
        for p in paths:
            if os.path.exists(p):
                os.unlink(p)
        os.rmdir(tmp)


if __name__ == "__main__":
    main()

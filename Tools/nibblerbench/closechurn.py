# Measure small writes to a nibbler BufferedWriter over a raw stream other
# than FileIO while other threads open and close streams.
#
# Usage: python Tools/nibblerbench/closechurn.py [options]
#
# Options:
#   --raws LIST      Comma separated raw streams written to (default:
#                    sock,rec): a SocketIO over a socketpair, drained by a
#                    reader thread, or a Python RawIOBase subclass whose
#                    write() drops the data.
#   --churn LIST     Comma separated kinds of streams the other threads open
#                    and close in a loop (default: sock,rec): a socketpair
#                    with makefile('wb'), or a Python RawIOBase subclass.
#   --closers LIST   Comma separated counts of closing threads (default:
#                    0,1,4).
#   --writers N      Threads writing (default: 1), each to its own stream.
#   --seconds T      Time counted per run (default: 1.0), after a tenth
#                    of it to get going; writes of 16 bytes are counted
#                    in batches of 1000.
#   --repeats N      Runs; the median is reported (default: 5).
#
# Small writes to such a raw stream go without the lock and don't ask it
# whether it is closed.  This shows whether other threads closing unrelated
# streams slow them down (it is a guard against any per-close bookkeeping
# that lock-free writes would have to check).  Each configuration runs in
# a process of its own.

import argparse
import io
import socket
import statistics
import subprocess
import sys
import threading
import time

from _io import _nibbler

CHUNK = b"x" * 15 + b"\n"
# Writes between looks at the clock's flag.
BATCH = 1000


class Sink(io.RawIOBase):
    def writable(self):
        return True

    def write(self, b):
        return len(b)


def open_raw(kind, cleanup):
    if kind == "rec":
        return Sink()
    a, b = socket.socketpair()

    def drain():
        buf = bytearray(1 << 16)
        while True:
            try:
                if b.recv_into(buf) == 0:
                    return
            except OSError:
                return

    t = threading.Thread(target=drain, daemon=True)
    t.start()
    raw = socket.SocketIO(a, "wb")

    def close():
        raw.close()
        a.close()
        t.join()
        b.close()

    cleanup.append(close)
    return raw


def churn_once(kind):
    if kind == "rec":
        Sink().close()
    else:
        a, b = socket.socketpair()
        f = a.makefile("wb")
        f.close()
        a.close()
        b.close()


def one(raw_kind, churn_kind, nclosers, nwriters, seconds):
    cleanup = []
    files = [_nibbler.BufferedWriter(open_raw(raw_kind, cleanup), 8192)
             for _ in range(nwriters)]
    stop = threading.Event()
    closes = [0] * nclosers

    def closer(k):
        while not stop.is_set():
            churn_once(churn_kind)
            closes[k] += 1

    start = threading.Barrier(nwriters + 1)
    done = threading.Event()
    writes = [0] * nwriters

    def writer(k):
        write = files[k].write
        start.wait()
        while not done.is_set():
            for _ in range(BATCH):
                write(CHUNK)
            writes[k] += BATCH

    closers = [threading.Thread(target=closer, args=(k,))
               for k in range(nclosers)]
    for t in closers:
        t.start()
    writers = [threading.Thread(target=writer, args=(k,))
               for k in range(nwriters)]
    for t in writers:
        t.start()
    start.wait()
    # Let everything get going, then count what is done in `seconds`.
    time.sleep(seconds / 10)
    t0 = time.perf_counter()
    written0 = sum(writes)
    closed0 = sum(closes)
    time.sleep(seconds)
    elapsed = time.perf_counter() - t0
    written = sum(writes) - written0
    closed = sum(closes) - closed0
    done.set()
    for t in writers:
        t.join()
    stop.set()
    for t in closers:
        t.join()
    for f in files:
        f.flush()
    for c in cleanup:
        c()
    return written / elapsed, closed / elapsed


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--raws", default="sock,rec")
    p.add_argument("--churn", default="sock,rec")
    p.add_argument("--closers", default="0,1,4")
    p.add_argument("--writers", type=int, default=1)
    p.add_argument("--seconds", type=float, default=1.0)
    p.add_argument("--repeats", type=int, default=5)
    p.add_argument("--one", nargs=3, metavar=("RAW", "CHURN", "K"),
                   help=argparse.SUPPRESS)
    a = p.parse_args()
    if a.one:
        raw, churn, k = a.one[0], a.one[1], int(a.one[2])
        res = [one(raw, churn, k, a.writers, a.seconds)
               for _ in range(a.repeats)]
        w = statistics.median(r[0] for r in res)
        c = statistics.median(r[1] for r in res)
        print(f"{w:.0f} {c:.0f}")
        return
    for raw in a.raws.split(","):
        for churn in a.churn.split(","):
            for k in (int(x) for x in a.closers.split(",")):
                if k == 0 and churn != a.churn.split(",")[0]:
                    continue
                out = subprocess.run(
                    [sys.executable, __file__, "--one", raw, churn, str(k),
                     "--writers", str(a.writers), "--seconds", str(a.seconds),
                     "--repeats", str(a.repeats)],
                    capture_output=True, text=True, check=True)
                w, c = out.stdout.split()
                print(f"raw={raw:4} churn={churn if k else '-':4} "
                      f"closers={k} writers={a.writers} "
                      f"{float(w) / 1e6:8.3f} Mwrites/s "
                      f"{float(c):9.0f} closes/s", flush=True)


if __name__ == "__main__":
    main()

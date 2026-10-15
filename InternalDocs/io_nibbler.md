The `_io._nibbler` buffered classes
===================================

`Modules/_io/_nibbler` is a second implementation of `BufferedReader`,
`BufferedWriter`, `BufferedRandom` and `BufferedRWPair`.  Its point is
free threading: `_io`'s classes hold one lock across every raw call, so a
thread writing to a slow pipe blocks every other thread that prints.
The nibbler never holds its lock across a raw write: other threads keep
appending meanwhile.

It is opt-in and private: `_PYTHON_IO_DEFAULT_IMPL=_nibbler` makes the
nibbler classes `_io`'s (so `open()`, `io.*` and the standard streams use
them), and `_io._set_open_impl()` switches at run time (for tests).

This document is a map; the details are in the comments it points to.


Reading order
-------------

1. `nibbler.h`: the mutex (holder id, fork generation, takeover).
2. `bufferedio.c`: "Morsel lists", the comment before `typedef struct {
   ... } buffered`, "Locking", then "Writing" (`buffered_write()` →
   `buffered_write_slow()` → `buffered_write_out()`), then "Reading"
   (`buffered_fill()`, `buffered_readline()`, `buffered_seek()`).
3. `__init__()` (`buffered_init()`), `close()`, `detach()`, dealloc.
4. The `_iomodule.c` glue: `open()` (`buffering=None`),
   `_set_open_impl()` and `iomodule_exec()`.


Data structures
---------------

- **morsel**: a run of bytes inside a bytes object that keeps them alive.
  A **morsel list** is a queue of them with their total (`nbytes`);
  dropping from the front is amortized O(1).  It holds the pending writes
  (copies in the block, large exact bytes by reference) or, reading, the
  **stash** (data a raw read returned after the block's, kept after an
  error).
- **block**: a bytes object of `capacity` bytes (64 more for reads) that
  small writes are copied into and reads fill: `block[0:pos]` was returned
  (seek() moves back over it), `block[pos:end]` is the read-ahead,
  `block[dlo:dhi]` was written over in place by `BufferedRandom` and not
  written out yet.  A fresh fill reads `capacity` bytes from the first
  address congruent to the raw position modulo 64 (64-aligned when it is
  unknown), where the kernel copies fastest; `stop` records where it ends,
  and so where its data starts, below which seek() doesn't move back.
- **threshold**: pending bytes past which writes are written out
  (`capacity`, or `PY_SSIZE_T_MAX` for buffer size None).
- **raw position** (`raw_pos`, negative when unknown): kept only when
  `raw_regular` (an exact FileIO of a regular file it opened itself, not
  in append mode), so that `tell()` and `seek()` inside the read-ahead
  make no `lseek`, like `_io`'s `abs_pos`.  Pipes and character devices
  are left out because their position doesn't follow reads (GH-95782), a
  file descriptor FileIO was given because it may have `O_APPEND`.


Invariants
----------

- Data flows one way at a time: there are pending writes or read-ahead
  (and stash), never both.  `BufferedRandom` writes over a private
  read-ahead in place (written out before any other raw call), else hands
  it back (seeks) before writing, and writes out before reading.
- The logical position is the raw position plus the pending writes, or
  minus the unread read-ahead and the stash.
- A bytes object is never written to once something else can see it: a
  block is reused only while uniquely referenced; one a Python raw stream
  may still reach through a view is abandoned to it (gh-60198).
- `inflight` bytes (the front of the pending writes, given to a raw write
  made without the lock) belong to the I/O-role holder until the raw call
  returns: other threads only append meanwhile.


Locks and roles per operation
-----------------------------

There are two mutexes per object (`nibbler_mutex`, a `PyMutex` recording
its holder's thread state id, so that a reentrant call raises
`RuntimeError` instead of deadlocking): the **lock**, which guards every
field, and the **I/O role**, which gives one thread the raw stream (taken
before the lock).  Fast paths take the lock alone; anything needing raw
I/O releases it, takes the role, takes the lock again and looks again.

| Operation | I/O role | lock | Notes |
|---|---|---|---|
| `write()` that fits below the threshold | – | yes | an exact FileIO is checked by its fd; others see "Closing the raw stream alone" |
| other `write()`, `flush()` | yes | yes | the lock is released around the raw write (`buffered_write_spans()`) |
| `read(n)`, `read1()`, `readline()`, `peek()` hitting the read-ahead | – | yes | |
| other reads, `readinto()`, `peek()` that fills | yes | yes | raw reads are made with both held |
| `seek()` inside the read-ahead (known raw position) | – | yes | |
| other `seek()`, `tell()`, `truncate()` | yes | yes | raw calls with both held |
| `close()`, `detach()`, `__init__()` | yes | yes | flush with both held |
| `fileno()`, `isatty()`, `seekable()`, `name`, `mode`, `closed`, `raw` | – | – | a reference to raw, taken atomically |

Waits release the GIL (or detach) and a signal handler that raises
interrupts them, except the relock after a raw call, whose result must be
kept.  A signal handler writing to the stream during a raw write of its
own thread finds the role is its own and queues its data (gh-118143).

On free-threaded builds every field is used with the lock, but `raw`
(`_Py_XGetRef()` / atomic exchange), `dict`, `block` and `capacity`
(relaxed, for the getters and `__sizeof__()`); mutex holders and
generations are relaxed (a thread only compares with its own id).


Closing the raw stream alone
----------------------------

After `raw.close()` (rather than the buffered object's `close()`), writes
must not reach the raw stream.  What small writes see depends on the raw
stream:

- An exact `FileIO` is checked by every write (its `fd`): the next write
  raises.
- Other raw streams (`SocketIO`, Python `RawIOBase` subclasses,
  subclasses of `FileIO`) are asked through `closed` only by operations
  that take the I/O role.  A small write (under 512 bytes) that fits below
  the threshold trusts the last answer (`raw_open`), so after a direct
  `raw.close()` small writes are queued without an error until the
  pending writes reach the threshold, or until an operation that asks
  `closed` runs: `flush()`, a write that doesn't fit, a write of 512 bytes
  or more, `seek()`, reads.  That operation raises `ValueError` and clears
  `raw_open`, so every later write asks and raises too.
- Queued bytes never reach the closed raw stream: every write-out asks
  `closed` with the lock first.  `close()` of the buffered object then
  finds the raw stream closed and returns without writing them or
  warning (as `_io` does with bytes buffered before `raw.close()`); they
  are dropped with the object.

Why small writes don't ask: `closed` of a Python raw stream is an
attribute lookup and a Python call, about 1750 instructions for a
`RawIOBase` subclass and 1950 for a `SocketIO` (callgrind, -O3 GIL build),
more than a whole small write (about 1100).  Making small writes
notice sooner without asking was tried and rejected for its complexity
(branch `raw_closed`):

- a global count of closes bumped by `_io._IOBase.close()`, compared by
  each small write: under 0.6% per small write, but every close anywhere
  sends the next small write of every such buffered object to the lock,
  and with threads closing Python raw streams in a loop up to 18% of small
  writes took the lock and free-threaded writes/s fell by 20-43%
  (`Tools/nibblerbench/closechurn.py`);
- a count per raw stream, in a table of watched streams keyed by the
  stream with a mutex and 64 hashed counters: fixes that (about 25
  instructions per close), at about 100 more lines in `_iomodule.c`;
- a C `closed` flag in the `_io._IOBase` struct: covers only raw types with
  that layout, grows every Python IO object, and must mirror the
  `__IOBase_closed` attribute.

A raw stream whose `closed` says it is open after its file descriptor was
closed could write to a reused descriptor, with `_io` as here.


Fork and finalization
---------------------

A holder that can never release a mutex is not waited for (see
`nibbler.h`):

- **fork**: `PyOS_AfterFork_Child()` calls `_PyIO_AfterForkChild()`,
  which bumps a global fork generation.  Every acquisition records the
  generation; the first lock of a mutex in a newer one claims it, resets
  it if a thread gone in the fork held it, and tells the caller (which
  forgets `raw_pos`, or drops the bytes in flight).  No set of objects, no
  walk.
- **finalization**: every other thread is detached and hangs as soon as
  it attaches, so the finalizing thread takes over a mutex such a thread
  holds, dropping the bytes in flight.  If it takes the role over but the
  lock fails (a reentrant call, or a wait interrupted after a fork),
  `drop_inflight` (used only with the role) leaves that to the next
  holder of the role.


Buffer size 0 and None
----------------------

Buffer size 0 is unbuffered (gh-148773): writes go straight to the raw
stream, retrying partial writes; reads never ask for more than the caller
wants; `peek()` and `readline()` raise `UnsupportedOperation`.  Buffer
size None (writers only) buffers writes without limit: the threshold is
`PY_SSIZE_T_MAX` and only `flush()` and operations needing the position
write out.  `open(buffering=None)` gives that, and is only accepted when
`open()` uses the nibbler classes (it raises before opening the file
otherwise).


Differences from `_io`
----------------------

Each of these is a bug of `_io`'s classes, which the tests skip for them:

- `_io` holds its lock across raw writes; a signal handler writing to the
  stream raises "reentrant call" there, and is queued here.
- `_io` loses data read before a raw error (a socket timeout) and pending
  writes on `MemoryError`; here they stay buffered.
- `_io` reuses buffer memory a Python raw stream may still reach through a
  view (gh-60198); here such memory is abandoned to it.
- `_io`'s `__init__()` drops pending writes; here they are written to the
  old raw stream first (or, if it was closed meanwhile, dropped with a
  `ResourceWarning`).
- `_io` crashes in gh-143375.
- `_io`'s `readline()` copies a long partial line on each call; here it is
  kept in the read-ahead (up to the buffer size when the raw stream would
  block, then returned as it is).
- Buffer size 0 and None are only supported here.

And one of the nibbler: after a raw stream other than an exact FileIO is
closed by itself, small writes are queued
without an error until the block is full or an operation takes the lock
(see "Closing the raw stream alone"); `_io` asks `closed` on every write.

Two more, kept for speed:

- With data buffered, `tell()` uses the raw position kept (see "raw
  position") where `_io` asks the raw stream each time: it doesn't see the
  file descriptor moved behind its back (`os.lseek()`, `os.write()`,
  `raw.seek()`, another object over the same FileIO, the other side of a
  fork, the FileIO reopened by its `__init__()`): the answer means
  little then either way, and asking costs an `lseek` per `tell()`.
- The raw calls to an exact FileIO go to its C functions: an instance
  attribute overriding `readinto`, `write` or `readall` (as
  `mock.patch.object(f.raw, "write")` makes) is not called; overrides of
  `flush` and `close` are (patch the class, or use a subclass): a lookup
  per raw call would cost more than an unbuffered write's other work.

When the nibbler classes replace `_io`'s, the C fast paths keyed on
`_io`'s exact types (stock `TextIOWrapper`'s `read1()` shortcut, pickle's
`peek()`) don't apply to them.

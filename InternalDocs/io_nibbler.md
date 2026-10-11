The `_io._nibbler` buffered classes
===================================

`Modules/_io/_nibbler` is a second implementation of `BufferedReader`,
`BufferedWriter`, `BufferedRandom` and `BufferedRWPair` (and of
`TextIOWrapper`, see below).  Its point is free threading: `_io`'s classes
hold one lock across every raw call, so a thread writing to a slow pipe
blocks every other thread that prints.  The nibbler never holds its lock
across a raw write, and small writes and reads that hit the buffer take no
lock at all.

It is opt-in and private: `_PYTHON_IO_DEFAULT_IMPL=_nibbler` makes the
nibbler classes `_io`'s (so `open()`, `io.*` and the standard streams use
them), `_PYTHON_IO_UNBUFFERED_IMPL=_nibbler` makes `open(buffering=0)` wrap
the raw file in them with buffer size 0, and `_io._set_open_impl()` /
`_io._set_unbuffered_impl()` switch at run time (for tests).

This document is a map; the details are in the comments it points to.


Reading order
-------------

1. `nibbler.h`: the header comment, then "Morsel lists", "The open end"
   and "Locking".  This is the data structure and the concurrency
   protocol, without any I/O.
2. `bufferedio.c`: the comment before `typedef struct { ... } buffered`
   (directions, buffer size 0 and None), then `buffered_enter()` /
   `buffered_enter_locked()` / `buffered_enter_append()` ("Entering
   methods"), then the write path (`write()` → `buffered_write_lockfree()`
   → `buffered_write_data()` → `buffered_write_out()`), then the read path
   (`buffered_fill()`, `buffered_read_into()`, `buffered_readline()`).
3. Fork and finalization: "Locking" in `nibbler.h`,
   `nibbler_set_after_fork()`, `_PyIO_AfterForkChild()`.
4. `__init__()` (`buffered_init()`), `close()`, `detach()`, dealloc.
5. "Gathering" (`_gather()`).
6. The `_iomodule.c` glue: `open()` (`buffering=None`), the
   `_set_*_impl()` functions and `iomodule_exec()`.


Data structures
---------------

- **morsel** (`_PyIO_Morsel`): a run of bytes inside a bytes object that
  keeps them alive.  A **morsel list** is a queue of them with their total
  (`nbytes`); dropping from the front is amortized O(1).
- **nibbler**: the buffered data and the locking of one object: the morsel
  list (pending writes), the current **block** (a bytes object of
  `capacity` bytes that small writes are copied into and reads fill), the
  **threshold** (pending bytes past which writes are written out), the
  **open end**, the lock, the I/O role and `inflight`.
- **open end** (`nibbler_end`): one run `block[pos:limit]` that threads
  use without the lock, moving `pos` with a compare-and-swap.  A *writing*
  end is the room after the last morsel when it is in the block (appends
  reserve, copy, then add to `done`); a *reading* end holds the read-ahead
  (the bytes the last fill read: before `pos` returned, after it unread).
  Taking the lock *holds* the end (`pos` → `~pos`), releasing it opens it
  again.  An end that is replaced or dropped stays held and is freed once
  no thread can use it (QSBR on free-threaded builds).
- **buffered**: the object: `raw`, the nibbler, the **stash** (data a raw
  read returned that couldn't go into the read-ahead without a large
  allocation, read before the raw stream), flags fixed by `__init__()`
  (`raw_fileio`, `raw_vectored`, `raw_appending`, `ref_min`), and the list
  of `_gather()` records.


Invariants
----------

- Data flows one way at a time: there are pending writes or read-ahead
  (and stash), never both.  `BufferedRandom` hands read-ahead back (seeks)
  before writing and writes out before reading.
- The logical position is the raw position plus the pending writes, or
  minus the unread read-ahead and the stash.
- A bytes object is never written to once something else can see it: a
  block is reused only while uniquely referenced (and, free-threaded,
  after its QSBR goal); one a Python raw stream may still reach through a
  view is abandoned to it.
- Appends without the lock stay within the threshold and inside the
  block: `limit` only grows for a given `pos`.
- `inflight` bytes (the front of the pending writes, given to a raw write
  made without the lock) belong to the I/O-role holder until the raw call
  returns: other threads only append meanwhile.
- `raw` changes only with the lock held (or with no other users).
- While a stream has `_gather()` records, it has no writing end and its
  reading end stays held (`hold_reading`).


Locks and roles per operation
-----------------------------

There are two mutexes per object, each recording its holder's thread
state id (so a reentrant call raises `RuntimeError` instead of
deadlocking): the **lock**, which guards the state, and the **I/O role**,
which gives one thread the use of the data (taken before the lock; a
thread holding the lock never waits for the role).

| Operation | I/O role | lock | Notes |
|---|---|---|---|
| small `write()` (exact FileIO, room at the writing end) | – | – | reserve/commit at the end; the FileIO is checked after reserving |
| text write through `_PyIONibbler_reserve()`/`_commit()` | – | – | same, from `TextIOWrapper` |
| other `write()` | only to write out | yes | the lock is released around the raw write (`buffered_write_spans()`) |
| `read(n)`, `read1()`, `readline()`, `peek()` hitting the read-ahead | – | – | claim at the reading end |
| other reads, `readinto()`, `peek()` that fills | yes | yes | raw reads are made with both held |
| `flush()` | yes | yes | the write-out releases the lock |
| `seek()`, `tell()`, `truncate()`, `_discard_writes()` | yes | yes | raw calls with both held |
| `close()`, `detach()`, `__init__()` | yes | yes | flush with both held |
| `fileno()`, `isatty()`, `seekable()`, `readable()`, `writable()`, `name`, `mode`, `closed`, `raw` | – | – | a reference to raw, taken without the lock |
| `_gather()` enter / write in a block | – | yes | |
| `_gather()` exit | only to write out | yes (not interruptible) | |

Waits release the GIL (or detach) and a signal handler that raises
interrupts them, except the relock after a raw call, whose result must be
kept.


Free-threaded memory ordering
-----------------------------

Fields used with the lock need nothing more.  Those used without it:

- `nibbler.end`: release store, acquire load (`nibbler_end_get()`).
- `end->pos`: compare-and-swap; opened with a release store, loaded
  relaxed and re-checked by the CAS.
- `end->limit`, reading: release store after the bytes were written
  (`nibbler_extend()`), acquire load (`nibbler_end_limit()`).  Writing:
  relaxed, safe because it only grows for a given `pos`.
- `end->done`, writing: atomic add by each append, acquire load by the
  holder waiting for appends to finish (`nibbler_hold()`).
- `nibbler.block`, `nibbler.capacity`: relaxed (`__sizeof__()`, `read1()`).
- `buffered.raw`: `_Py_XGetRef()` / atomic exchange (`buffered_ref_raw()`,
  `buffered_swap_raw()`).
- `buffered.raw_fileio`, `buffered.dict`: relaxed.
- `buffered.ngather`: stored relaxed with the lock; read with it.
- mutex holders: relaxed (a thread only compares with its own id).
- Blocks and ends that threads without the lock may still read are freed
  or reused only after a QSBR goal (`block_goal`, `spare`,
  `_PyMem_FreeDelayed()`, `_PyObject_XDecRefDelayed()`).

Nothing that can wait or detach runs between reserving and committing at
the writing end, so a holder waiting for appends only waits for threads
running their copy.


Fork and finalization
---------------------

A holder that can never release a mutex is not waited for (see "Locking"
in `nibbler.h`):

- **fork**: `PyOS_AfterFork_Child()` calls `_PyIO_AfterForkChild()` before
  any Python after-fork hook.  For every initialized object (the module's
  `nibbler_set`) it resets the mutexes other threads held and, if the I/O
  role was held, drops the bytes in flight (the parent still writes them),
  holding the end meanwhile.  Read-ahead that a gone thread was filling
  is lost.
- **finalization**: every other thread is detached and hangs as soon as it
  attaches, so the finalizing thread takes over a mutex such a thread
  holds, dropping the bytes in flight.  If it takes the role over but the
  lock fails (a reentrant call), `drop_inflight` leaves that to the next
  holder of both.


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


`_gather()`
-----------

Private and experimental.  See "Gathering" in `bufferedio.c`: a block's
writes from the context that entered it are kept in a record and added in
one piece at its end (or at `limit`, or before an operation of that
context needs the position, or by `close()`/`detach()`/`__init__()`).


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
  old raw stream first.
- `_io` crashes in gh-143375.
- `_io`'s `readline()` copies a long partial line on each call; here it is
  kept in the read-ahead (up to the buffer size when the raw stream would
  block, then returned as it is).
- Buffer size 0 and None are only supported here.

When the nibbler classes replace `_io`'s, the C fast paths keyed on
`_io`'s exact types (stock `TextIOWrapper`'s `read1()` shortcut, pickle's
`peek()`) don't apply to them.


The text layer
--------------

<!-- Added with _io._nibbler.TextIOWrapper. -->

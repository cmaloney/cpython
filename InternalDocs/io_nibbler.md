The `_io._nibbler` buffered classes
===================================

`Modules/_io/_nibbler` is a second implementation of `BufferedReader`,
`BufferedWriter`, `BufferedRandom` and `BufferedRWPair` (and of
`TextIOWrapper`, see below).  Its point is free threading: `_io`'s classes
hold one lock across every raw call, so a thread writing to a slow pipe
blocks every other thread that prints.  The nibbler never holds its lock
across a raw write: other threads keep appending meanwhile.

It is opt-in and private: `_PYTHON_IO_DEFAULT_IMPL=_nibbler` makes the
nibbler classes `_io`'s (so `open()`, `io.*` and the standard streams use
them), `_PYTHON_IO_UNBUFFERED_IMPL=_nibbler` makes `open(buffering=0)` wrap
the raw file in them with buffer size 0, and `_io._set_open_impl()` /
`_io._set_unbuffered_impl()` switch at run time (for tests).

This document is a map; the details are in the comments it points to.


Reading order
-------------

1. `nibbler.h`: the mutex (holder id, fork generation, takeover).
2. `bufferedio.c`: "Morsel lists", the comment before `typedef struct {
   ... } buffered`, "Locking", then "Writing" (`buffered_write()` →
   `buffered_write_slow()` → `buffered_write_out()`), then "Reading"
   (`buffered_fill()`, `buffered_readline()`, `buffered_seek()`).
3. `__init__()` (`buffered_init()`), `close()`, `detach()`, dealloc.
4. "Gathering" (`_gather()`).
5. "Bytes for TextIOWrapper" and `textio.c` (see "The text layer").
6. The `_iomodule.c` glue: `open()` (`buffering=None`), the
   `_set_*_impl()` functions and `iomodule_exec()`.


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
  `raw_regular` (an exact FileIO of a regular file, not in append mode),
  so that `tell()` and `seek()` inside the read-ahead make no `lseek`, like
  `_io`'s `abs_pos`.  Pipes and character devices are left out because
  their position doesn't follow reads (GH-95782).


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
| `seek()` / `tell()` inside the read-ahead (known raw position) | – | yes | |
| other `seek()`, `tell()`, `truncate()` | yes | yes | raw calls with both held |
| `close()`, `detach()`, `__init__()` | yes | yes | flush with both held |
| `fileno()`, `isatty()`, `seekable()`, `name`, `mode`, `closed`, `raw` | – | – | a reference to raw, taken atomically |
| `_gather()` enter / write in a block | – | yes | |
| `_gather()` exit | yes | yes (not interruptible) | writes out when the pending writes don't fit |

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
- Text writes through the nibbler `TextIOWrapper` ask the buffered object
  whether it is closed on each write when the raw stream isn't an exact
  FileIO, so they raise at once.

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
While a stream has records (`ngather`), the fast paths that take the lock
alone go the way that takes the I/O role, where records are moved.


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

And one of the nibbler: after a raw stream other than an exact FileIO is
closed by itself, small writes are queued without an error until the
block is full or an operation takes the lock (see "Closing the raw stream
alone"); `_io` asks `closed` on every write.

When the nibbler classes replace `_io`'s, the C fast paths keyed on
`_io`'s exact types (stock `TextIOWrapper`'s `read1()` shortcut, pickle's
`peek()`) don't apply to them.



The text layer
--------------

`_io._nibbler.TextIOWrapper` (`Modules/_io/_nibbler/textio.c`) keeps no
bytes of its own.  The buffered object below it is the only queue in both
directions, so the buffer's position is the text position: `tell()` is the
buffer's position, and `write()` and `truncate()` after a read act there
(gh-82891, gh-70346).  Start with the comment at the top of `textio.c`.

### The store

Over an exact `_io._nibbler` buffered object, text uses the buffer's bytes
in place through the byte API ("Bytes for TextIOWrapper" in
`bufferedio.c`, declared in `_iomodule.h`): `_PyIONibbler_begin()` takes
the buffer's lock (and with `io` its role) and shows the unread bytes,
`_PyIONibbler_view()` takes some and shows the rest, `_PyIONibbler_fill()`
reads more after them (growing the block for a long line up to 64 blocks,
at least `DEFAULT_BUFFER_SIZE`, then `_PyIO_NIBBLER_FULL`),
`_PyIONibbler_unread()` puts bytes back in front (see "Failed reads"),
`_PyIONibbler_end()` releases.  `_PyIONibbler_take()` is the quick read's
one call: take bytes if they are still the next ones.

Over any other buffer, or once the buffer has an instance dict (its methods
may be overridden), the store is read-ahead kept in the text object
(`rbuf`), filled with `read1()`.

After the raw stream alone is closed, what the buffer read ahead is still
served, as by its own `read()`; anything needing the raw stream raises
`ValueError`.

### Decoding

UTF-8, Latin-1, ASCII and byte-to-character tables (cp1252 and others),
with errors `strict` or `surrogateescape` (and `replace` but for UTF-8),
are native: the bytes of any characters are known.  A chunk of the unread
bytes is decoded into a cache (`cache`, `cache_ci`, `cache_p`), valid while
the buffer's unread bytes still start at `cache_p`; the cache holds the
block, so the buffer never writes over those bytes in place.  A read finds
its text in the cache and takes the bytes of just that text, counted (the
"\n" byte of a UTF-8 line; a vectorized count for read(n)).  The usual
read (`text_read_quick()`) is a trylock of rlock, a memchr, a str and
`_PyIONibbler_take()`; the general one (`text_read_native()`,
`text_take()`) handles every newline mode, partial lines and refills.
`read()` with no size decodes the buffer's `read()` at once.

Other codecs go through the codec's incremental decoder, as `_io` does:
characters decoded ahead (`dchars`) with a snapshot (flags, bytes) for
`tell()`.  Their state is kept as flags (an `unsigned long long`, as
iso2022_kr's go past 32 bits; only `tell()`, whose cookie holds 32 bits,
raises `OverflowError`).

Invalid bytes with `strict` end the read before them (as at the end of the
stream); the next read takes them and raises, once, with either kind of
codec.

### Failed reads

A read that can't end with what the buffer holds (a line longer than the
buffer gathers, `read()` in pieces, a stream that would block) takes bytes
as it goes, and may fail after it took some: the raw stream raises (or is
closed, or raises `BlockingIOError` rather than returning `None`), or
`KeyboardInterrupt` comes while it waits.  Then, as the buffer does with
bytes (gh-51571), what the call took is given back and the exception is
raised; the next read returns it.  With a native codec the call keeps
copies of the bytes it takes and puts them back with
`_PyIONibbler_unread()` (or in front of `rbuf`).  With the decoder, text
longer than a chunk is taken in pieces as it is decoded (so the next
characters replace them, in linear time), joined at the end; a failed read
gives the pieces back as characters, but not their bytes (`dlost`):
`tell()` then names where they were decoded from and how many characters
to skip, and a write or `detach()` reads the bytes again first.

### Locking

- **rlock** (a nibbler mutex, reentrant through `rdepth` for calls nested
  from Python code it runs): held by reads, `seek()`, `tell()`,
  `truncate()`, `reconfigure()`, `detach()`, `close()` and `__init__()`,
  across buffer calls, so that a read is atomic (each line once, whole).
  The quick read takes it with a trylock; when anyone holds it the read
  goes the locked way.
- **wlock**: held only to look at or swap the settings, never across other
  code: `write()` and the getters take what they need under it.  With the
  GIL it is a no-op (holding the GIL is the same).  `write()` never takes
  rlock, so writing never waits for a blocking read (a socket's
  `makefile("rw")`); after a read it takes rlock to go back to the text
  position first.  (Critical sections were tried: daemon threads stopped
  at exit inside one hung the main thread's writes.)

### Differences from `_io.TextIOWrapper`

- Writes and `truncate()` after a read act at the text position.
- `tell()` is the buffer's position; with a native codec, a `"\r"`
  returned whose `"\n"` follows is noted as decoder flags 1, which
  `seek()` restores.  Other cookies `tell()` can't return raise
  (gh-91112).
- A partial line that would block is kept until it is longer than
  `_CHUNK_SIZE`, as `_io` and `_pyio` keep.
- Decode errors are raised once per run of invalid bytes, which are
  skipped; the text before them is returned first (by `read()` too).
- A read that raises keeps the text it took for the next read.
- `reconfigure(encoding=...)`, `close()` and `detach()` give the old
  encoder `final=True` (gh-79792).

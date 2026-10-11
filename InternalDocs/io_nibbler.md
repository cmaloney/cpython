## Text layer

`_io._nibbler.TextIOWrapper` (`Modules/_io/_nibbler/textio.c`) keeps no
bytes of its own.  The buffered object below it is the only queue in both
directions, so the buffer's position is the text position: `tell()` is the
buffer's position, and `write()` and `truncate()` after a read act there
(gh-82891, gh-70346).  Start with the comment at the top of `textio.c`, then
"Locking" and `tconf` there.

### The store

Over an exact `_io._nibbler` buffered object, text uses the buffer's bytes
in place through the byte API ("Bytes for TextIOWrapper" in
`bufferedio.c`, declared in `_iomodule.h`):

- `_PyIONibbler_peek()` shows the unread bytes without taking them, named
  by a key and an offset that always mean the same bytes.  To give a long
  line whole, it lets the block grow (as `buffered_fill()` does for a long
  binary line) up to 64 blocks, and at least `DEFAULT_BUFFER_SIZE`; past
  that it returns `_PyIO_NIBBLER_FULL` and the line is taken in parts.
- `_PyIONibbler_advance()` takes bytes only if they are still at the
  position (key and offset): that is how a call finds that another thread
  read first.
- `_PyIONibbler_write()`, and `_PyIONibbler_reserve()` plus
  `_PyIONibbler_commit()` for UTF-8 written straight into the buffer.

Over any other buffer, or once the buffer has an instance dict (its methods
may be overridden), the store is read-ahead kept in the text object
(`rbuf`), filled with `read1()`.  The byte API returns `_PyIO_NIBBLER_NO`
for a buffer with a dict, also after waiting for its lock, so that no call
takes bytes from the buffer once `rbuf` may hold bytes before them.

After the raw stream alone is closed, what the buffer read ahead is still
served, locked or not, as by its own `read()`; anything needing the raw
stream raises `ValueError`.

### Decoding

UTF-8, Latin-1, ASCII and byte-to-character tables (cp1252 and others),
with errors `strict` or `surrogateescape` (and `replace` but for UTF-8),
are native: the bytes of any characters are known, so a read takes just
the bytes of the text it returns.  The decoded characters are a cache
(`tcache`; on free-threaded builds a span published whole, `tspan`).

Other codecs go through the codec's incremental decoder.  Their state is
kept as flags (an `unsigned long long`, as iso2022_kr's go past 32 bits;
only `tell()`, whose cookie holds 32 bits, raises `OverflowError`).

Invalid bytes with `strict` end the read before them (as at the end of the
stream); the next read takes them and raises, once, with either kind of
codec.

### Locking

With a native codec over an exact nibbler buffer (`tconf.lockfree`),
reads, `write()`, `tell()`, `flush()` and the attributes run without the
critical section: the buffer takes bytes atomically, and each call works
on its own copy of the cache.  Everything else (the codec's decoder and
encoder, `rbuf`) keeps the critical section.

What calls run by (buffer, codec objects, errors, newline, the lockfree
flag) is one immutable, refcounted struct, `tconf`, published through one
pointer.  A call takes it once; `__init__()`, `reconfigure()`, `detach()`
and the switch to `rbuf` build a new one and swap it in.  Its memory is
freed with QSBR.  The quick read path (`text_quick()`) borrows it without a
reference, so lockfree settings are swapped out with a stop-the-world pass
(rare), after which their objects are released at once.

### Differences from `_io.TextIOWrapper`

- Writes and `truncate()` after a read act at the text position.
- `tell()` is the buffer's position; with a native codec, a `"\r"`
  returned whose `"\n"` follows is noted as decoder flags 1, which
  `seek()` restores.  Other cookies `tell()` can't return raise
  (gh-91112).
- A partial line that would block is kept until it is longer than
  `_CHUNK_SIZE`, as `_io` and `_pyio` keep.
- Decode errors are raised once per run of invalid bytes, which are
  skipped; the text before them is returned first.
- `reconfigure(encoding=...)`, `close()` and `detach()` give the old
  encoder `final=True` (gh-79792).

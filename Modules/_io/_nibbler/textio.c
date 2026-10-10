/*
    _io._nibbler.TextIOWrapper: text over a buffered object's bytes.

    The text layer only encodes and decodes, with the decoder's flags, and
    handles newlines.  The bytes stay in the buffered object until text is
    returned: a read takes from it only the bytes of the characters it
    returns, so a partial character, a "\r" that may begin a "\r\n", or a
    line that hasn't ended (when the stream would block) stays there for
    the next call.  So the buffer's position is the text position: tell()
    is the buffer's position (with the decoder's flags), and write() and
    truncate() after a read act there (gh-82891, gh-70346).  Written text
    goes straight into the buffer, which is the only queue.

    Over an exact _io._nibbler BufferedReader, BufferedWriter or
    BufferedRandom, the bytes are used in place through the functions in
    _iomodule.h ("the store").  Over any other buffer (or a raw stream),
    the store is a bytes object of read-ahead kept here (rbuf), filled with
    read1() (or read()), and written text goes to write() at once.

    Reading decodes a span of the unread bytes (a chunk of _CHUNK_SIZE
    bytes or more) into `chars`, and returns text from it.  How its
    characters map to bytes depends on the codec:

    - UTF-8, Latin-1, ASCII and byte-to-character tables (cp1252 and
      others), with errors "strict" or "surrogateescape" (and "replace"
      but for UTF-8): the bytes of any characters are known, so each call
      takes just those from the store.  `chars` is a cache, valid only
      while the store's unread bytes start where it says (key, koff);
      anything else that reads or moves the buffer makes it stale.

    - Other codecs, through the codec's incremental decoder: a span's bytes
      are taken when decoded (bar what the decoder holds: a partial
      character is left in the store), and `chars` keeps what wasn't
      returned yet.  tell() then gives the span's start, the decoder's flags
      there, and how many characters to skip; write() and truncate() first
      find the byte position of the text position by decoding again.

    Universal newlines are handled on the decoded characters, by
    text_take(), which also notes the kinds of newline seen.
*/

#include "Python.h"
#include "pycore_bytes_methods.h"       // _Py_bytes_isascii()
#include "pycore_call.h"                // _PyObject_CallMethod()
#include "pycore_codecs.h"              // _PyCodecInfo_GetIncrementalDecoder()
#include "pycore_fileutils.h"           // _Py_GetLocaleEncodingObject()
#include "pycore_interp.h"              // PyInterpreterState.unicode
#include "pycore_long.h"                // _PyLong_GetZero()
#include "pycore_object.h"              // _PyObject_GC_UNTRACK()
#include "pycore_pyerrors.h"            // _PyErr_ChainExceptions1()
#include "pycore_pystate.h"             // _PyInterpreterState_GET()
#include "pycore_runtime.h"             // _PyRuntime
#include "pycore_unicodeobject.h"       // _PyUnicode_AsUTF8String()
#include "pycore_weakref.h"             // FT_CLEAR_WEAKREFS()

#include "_iomodule.h"

/*[clinic input]
module _io
class _io.TextIOWrapper "textio *" "clinic_state()->PyTextIOWrapper_Type"
[clinic start generated code]*/
/*[clinic end generated code: output=da39a3ee5e6b4b0d input=a649d1250a227bde]*/

/* How characters map to bytes (see the top of the file). */
enum {
    CODEC_DECODER = 0,      /* through the codec's decoder */
    CODEC_UTF8,
    CODEC_LATIN1,
    CODEC_ASCII,
    CODEC_CHARMAP,          /* a byte-to-character table, `charmap` */
};

#define FLAGS_FRESH INT_MIN

/* Newlines seen, for the newlines attribute. */
enum { SEEN_CR = 1, SEEN_LF = 2, SEEN_CRLF = 4 };

/* A partial line that would block is kept for the next readline() until
   it is this many times _CHUNK_SIZE characters (or can't fit in the
   buffer): then it is returned as it is. */
#define READLINE_KEEP_MAX 64

/* The characters decoded at the position: chars[ci:].  With a native
   codec, while the buffer's unread bytes are those named by key at offset
   koff in their block, of which the first kbytes made them; with the
   decoder, always.  cr_at: the byte offset in chars' data of the first
   "\r" at or after ci (none: its end), if not below ci's.
   skip_lf: the "\n" at the position ends a "\r\n" already seen.  nl: the
   kinds of newline in chars[ci:] were noted (see text_note_newlines()).  With
   free threading, a call's copy, of the span sp (see tspan) at pos and of
   version ver; renew: chars are others now. */
typedef struct tspan tspan;
typedef struct {
    PyObject *chars;
    Py_ssize_t ci;
    Py_ssize_t cr_at;
    uint64_t key;
    Py_ssize_t koff;
    Py_ssize_t kbytes;
    uint64_t ver;
    uint8_t skip_lf;
    uint8_t nl;
    uint8_t renew;
    tspan *sp;
    uint64_t pos;
} tcache;

/* Native codecs decode at most this many bytes at a time. */
#define SPAN_MAX ((Py_ssize_t)1 << 30)

#ifdef Py_GIL_DISABLED
/* With free threading, the cache is a span, published whole: chars,
   decoded from the kbytes bytes at koff (as in tcache), and pos, the
   position in them: ci, skip_lf and (with a native codec, from which
   chars are at most SPAN_MAX bytes) how many of the bytes come before it,
   in one word that calls swap atomically.  The hints cr_at and nl may be
   changed by any call; the rest never.  ver tells spans apart. */
struct tspan {
    PyObject *chars;
    uint64_t key;
    uint64_t ver;
    uint64_t pos;
    Py_ssize_t koff;
    Py_ssize_t kbytes;
    Py_ssize_t cr_at;
    uint8_t nl;
    char wide;          /* the decoder's: ci alone in pos, key 0 */
};

#define SPAN_POS(ci, boff, skip_lf) \
    (((uint64_t)(boff) << 32) | ((uint64_t)(ci) << 1) | (uint64_t)(skip_lf))
#define SPAN_CI(sp, pos) \
    ((Py_ssize_t)(((pos) >> 1) & ((sp)->wide ? UINT64_MAX >> 1 : 0x7fffffff)))
#define SPAN_BOFF(sp, pos) ((sp)->wide ? 0 : (Py_ssize_t)((pos) >> 32))
#endif

typedef struct {
    PyObject_HEAD
    uint8_t ok;                 /* initialized? */
    uint8_t detached;
    char finalizing;
    uint8_t line_buffering;
    uint8_t write_through;
    char readable;
    char readuniversal;
    char readtranslate;
    char writetranslate;
    char seekable;
    char has_read1;             /* the buffer has read1() */
    char nib;                   /* the store is the buffer itself */
    char nib_ok;                /* the buffer can be the store */
    char codec;                 /* CODEC_* for reads */
    char escapes;               /* errors is "surrogateescape" */
    char enc;                   /* CODEC_* for writes (CHARMAP: ASCII only) */
    char encoding_start_of_stream;  /* the encoder may write a BOM */
    char encoder_used;          /* the encoder needs final=True at the end */
    uint8_t decoded;            /* read since the last seek or write */
    uint8_t seennl;             /* SEEN_* */
    /* Calls run without the critical section (see "Locking"). */
    uint8_t lockfree;
    Py_ssize_t chunk_size;
    PyObject *buffer;
    PyObject *encoding;
    PyObject *errors;
    PyObject *encoder;
    PyObject *decoder;          /* CODEC_DECODER only */
    PyObject *charmap;          /* CODEC_CHARMAP's decoding table */
    PyObject *readnl;
    const char *writenl;        /* ASCII; NULL stands for "\n" */

    /* What is known of the characters at the position (see tcache),
       shared by the calls that run without the critical section; with
       free threading, as a span (spans counts them). */
#ifdef Py_GIL_DISABLED
    tspan *span;
    uint64_t spans;
#else
    tcache cache;
#endif
    /* With the decoder, the characters came from the bytes taken last,
       dspan, which the decoder started on with flags dflags; at the
       store's position, the decoder holds nothing and has flags `flags`
       (FLAGS_FRESH: as after reset(), not asked yet).  Used only with the
       critical section. */
    PyObject *dspan;
    int dflags;
    int flags;

    /* The store over other buffers: rbuf[rpos:] is read-ahead (rgen tells
       its successive values apart). */
    PyObject *rbuf;
    Py_ssize_t rpos;
    uint64_t rgen;

    PyObject *weakreflist;
    PyObject *dict;
} textio;

#define textio_CAST(op) ((textio *)(op))

/* Free op once no thread can be using it without a reference (see
   "Locking"). */
#ifdef Py_GIL_DISABLED
static inline void
TEXT_DECREF_LATER(PyObject *op)
{
    if (op != NULL && !_Py_IsImmortal(op)) {
        _PyObject_XDecRefDelayed(op);
    }
}
#else
#  define TEXT_DECREF_LATER(op) Py_XDECREF(op)
#endif

static PyObject *
textio_unsupported(textio *self, const char *message)
{
    _PyIO_State *state = find_io_state_by_def(Py_TYPE(self));
    PyErr_SetString(state->unsupported_operation, message);
    return NULL;
}

/* Objects swapped while other threads may use them (see "Locking"): set
   *slot to obj (a new reference). */
static void
text_swap(PyObject **slot, PyObject *obj)
{
#ifdef Py_GIL_DISABLED
    if (obj != NULL) {
        /* Lets _Py_XGetRef() take references to it. */
        _PyObject_SetMaybeWeakref(obj);
    }
    TEXT_DECREF_LATER(_Py_atomic_exchange_ptr(slot, obj));
#else
    Py_XSETREF(*slot, obj);
#endif
}

static inline PyObject *
text_get(PyObject **slot)
{
#ifdef Py_GIL_DISABLED
    return _Py_XGetRef(slot);
#else
    return Py_XNewRef(*slot);
#endif
}

/* A new reference to the buffer, or NULL with ValueError. */
static PyObject *
textio_buffer(textio *self)
{
    PyObject *buffer = (FT_ATOMIC_LOAD_UINT8_RELAXED(self->ok)
                        ? text_get(&self->buffer) : NULL);
    if (buffer == NULL) {
        PyErr_SetString(PyExc_ValueError,
                        FT_ATOMIC_LOAD_UINT8_RELAXED(self->ok)
                        && FT_ATOMIC_LOAD_UINT8_RELAXED(self->detached)
                        ? "underlying buffer has been detached"
                        : "I/O operation on uninitialized object");
    }
    return buffer;
}

static PyObject *
textio_call(textio *self, PyObject *name, PyObject *arg)
{
    PyObject *buffer = textio_buffer(self);
    if (buffer == NULL) {
        return NULL;
    }
    PyObject *res = (arg == NULL ? PyObject_CallMethodNoArgs(buffer, name)
                     : PyObject_CallMethodOneArg(buffer, name, arg));
    Py_DECREF(buffer);
    return res;
}

static int
textio_call_bool(PyObject *obj, PyObject *name)
{
    PyObject *res = PyObject_CallMethodNoArgs(obj, name);
    if (res == NULL) {
        return -1;
    }
    int r = PyObject_IsTrue(res);
    Py_DECREF(res);
    return r;
}

/* Is self exactly a TextIOWrapper of ours (not a subclass)? */
static inline int
textio_exact(textio *self)
{
    return (((PyHeapTypeObject *)Py_TYPE(self))->ht_token
            == &_PyIONibbler_textiowrapper_spec);
}

/* Raise ValueError if the stream is closed.  A subclass may override
   closed. */
static int
textio_check_closed(textio *self, PyObject *buffer)
{
    if (!textio_exact(self)) {
        PyObject *res = _PyIOBase_check_closed((PyObject *)self, Py_True);
        Py_XDECREF(res);
        return res == NULL ? -1 : 0;
    }
    int r;
    if (self->nib_ok) {
        r = _PyIONibbler_closed(buffer);
    }
    else {
        PyObject *res = PyObject_GetAttr(buffer, &_Py_ID(closed));
        r = res == NULL ? -1 : PyObject_IsTrue(res);
        Py_XDECREF(res);
    }
    if (r > 0) {
        PyErr_SetString(PyExc_ValueError, "I/O operation on closed file.");
    }
    return r == 0 ? 0 : -1;
}

/* The buffer, attached and open, as a new reference. */
static PyObject *
textio_ready(textio *self)
{
    PyObject *buffer = textio_buffer(self);
    if (buffer != NULL && textio_check_closed(self, buffer) < 0) {
        Py_CLEAR(buffer);
    }
    return buffer;
}

/*
 * The store
 */

/* The store's unread bytes at the position (see _PyIONibbler_peek()). */
typedef struct {
    PyObject *buffer;
    _PyIO_Morsel m;
    uint64_t key;
    int status;         /* of the last peek: 0 or _PyIO_NIBBLER_* */
    char eof;           /* the stream ends after m */
    char at_end;        /* see text_more() */
    char peeked;        /* m is what the store had (else not looked) */
    char all;           /* read everything there is before decoding */
    char lockfree;      /* without the critical section */
    char retry;         /* error: do it with the critical section */
    Py_ssize_t held;    /* bytes of m the decoder held (it forgot them) */
    /* The cache as this call knows it: a copy (copy), with free threading
       (see "Locking"); with the GIL, the cache itself. */
    tcache *c;
#ifdef Py_GIL_DISABLED
    tcache copy;
#endif
} store;

/* rbuf's key: not one the buffer gives. */
#define STORE_KEY(gen) ((gen) | ((uint64_t)1 << 63))

static void
store_release(store *st)
{
    Py_CLEAR(st->m.obj);
    st->m = (_PyIO_Morsel){NULL, NULL, 0};
}

/* Forget what was seen of the store: another thread moved it. */
static void
store_forget(store *st)
{
    store_release(st);
    st->peeked = st->eof = st->status = 0;
    st->held = 0;
}

/*
 * Locking
 *
 * With a native codec over an exact _io._nibbler buffer (lockfree), reads,
 * write(), tell(), flush() and the attributes run without the object's
 * critical section: the bytes are the buffer's, which takes them
 * atomically (advance() by key and offset), and what each call knows of
 * the characters is its own copy of the cache, taken from a span and
 * published by swapping the span's position, or the span (see tspan).  A
 * copy that is no longer of the buffer's bytes is found out when its
 * bytes are taken, and decoded again.  The other
 * methods, and everything with other codecs or buffers (the codec's
 * decoder and encoder, and rbuf, aren't thread-safe), keep the critical
 * section.  The buffer is swapped atomically (detach()), and objects that
 * calls use without a reference are freed only once no thread can still
 * use them (delayed, on free-threaded builds).
 */

/* The cache as st's call knows it, st->c: with free threading, a copy,
   with a reference to its chars.  With the GIL, which other threads take
   only where calls wait for the buffer, the cache itself: what a call
   works on then changes only where a copy would turn out to be out of
   date, which the call checks (see text_read_impl()). */
static inline tcache *
cache_get(textio *self, tcache *copy)
{
#ifdef Py_GIL_DISABLED
    tspan *sp = _Py_atomic_load_ptr_acquire(&self->span);
    if (sp == NULL) {
        *copy = (tcache){.cr_at = -1,
                         .ver = _Py_atomic_load_uint64_relaxed(&self->spans)};
        return copy;
    }
    /* Alive: spans and their chars are freed only after a delay this
       thread is inside. */
    uint64_t pos = _Py_atomic_load_uint64_relaxed(&sp->pos);
    Py_ssize_t boff = SPAN_BOFF(sp, pos);
    *copy = (tcache){
        Py_NewRef(sp->chars),
        SPAN_CI(sp, pos),
        _Py_atomic_load_ssize_relaxed(&sp->cr_at),
        sp->key, sp->koff + boff, sp->kbytes - boff, sp->ver,
        (uint8_t)(pos & 1), _Py_atomic_load_uint8_relaxed(&sp->nl), 0,
        sp, pos,
    };
    return copy;
#else
    (void)copy;
    return &self->cache;
#endif
}

static inline void
cache_release(tcache *c)
{
#ifdef Py_GIL_DISABLED
    Py_CLEAR(c->chars);
#endif
}

/* With the critical section (and the decoder): the cache's chars
   (borrowed; NULL for none), and in *ci the position in them. */
static PyObject *
cache_chars(textio *self, Py_ssize_t *ci)
{
#ifdef Py_GIL_DISABLED
    tspan *sp = _Py_atomic_load_ptr_relaxed(&self->span);
    *ci = sp ? SPAN_CI(sp, _Py_atomic_load_uint64_relaxed(&sp->pos)) : 0;
    return sp ? sp->chars : NULL;
#else
    *ci = self->cache.ci;
    return self->cache.chars;
#endif
}

#ifdef Py_GIL_DISABLED
static void
span_free(tspan *sp)
{
    if (sp != NULL) {
        TEXT_DECREF_LATER(sp->chars);
        _PyMem_FreeDelayed(sp, sizeof(*sp));
    }
}
#endif

/* Make the copy c the cache, unless that changed since c was taken (then c
   is no more than this call's). */
static int
cache_put(textio *self, tcache *c)
{
#ifdef Py_GIL_DISABLED
    tspan *sp = _Py_atomic_load_ptr_acquire(&self->span);
    if (sp != c->sp
        || c->ver != (sp ? sp->ver : _Py_atomic_load_uint64(&self->spans)))
    {
        return 0;
    }
    if (!c->renew) {
        /* The same chars: the position and hints. */
        if (sp != NULL) {
            uint64_t old = c->pos;
            uint64_t pos = SPAN_POS(c->ci, sp->wide ? 0 : c->koff - sp->koff,
                                    c->skip_lf);
            if (pos != old
                && !_Py_atomic_compare_exchange_uint64(&sp->pos, &old, pos))
            {
                /* The hints are only from where c is. */
                return 0;
            }
            c->pos = pos;
            if (c->cr_at != _Py_atomic_load_ssize_relaxed(&sp->cr_at)) {
                _Py_atomic_store_ssize_relaxed(&sp->cr_at, c->cr_at);
            }
            if (c->nl && !_Py_atomic_load_uint8_relaxed(&sp->nl)) {
                _Py_atomic_store_uint8_relaxed(&sp->nl, 1);
            }
        }
        return 0;
    }
    /* Other chars (or none): another span. */
    tspan *n = NULL;
    if (c->chars != NULL) {
        n = PyMem_Malloc(sizeof(*n));
        if (n == NULL) {
            PyErr_NoMemory();
            return -1;
        }
        int wide = self->codec == CODEC_DECODER;
        assert(wide || c->ci == 0);
        *n = (tspan){Py_NewRef(c->chars), wide ? 0 : c->key,
                     _Py_atomic_add_uint64(&self->spans, 1) + 1,
                     SPAN_POS(c->ci, 0, c->skip_lf), c->koff, c->kbytes,
                     c->cr_at, c->nl, (char)wide};
    }
    c->renew = 0;
    /* (Once published, n->pos is other threads' too.) */
    uint64_t ver = n ? n->ver : 0, pos = n ? n->pos : 0;
    if (!_Py_atomic_compare_exchange_ptr(&self->span, &sp, n)) {
        span_free(n);
        return 0;
    }
    span_free(sp);
    c->sp = n;
    c->ver = n ? ver : _Py_atomic_load_uint64(&self->spans);
    c->pos = pos;
#else
    (void)self;
    (void)c;
#endif
    return 0;
}

#ifdef Py_GIL_DISABLED
#  define STORE_COPY(st) (&(st)->copy)
#else
#  define STORE_COPY(st) NULL
#endif

/* Drop the characters. */
static void
cache_clear(tcache *c)
{
    Py_CLEAR(c->chars);
    c->renew = 1;
    c->nl = 0;
    c->ci = 0;
    c->cr_at = -1;
    c->skip_lf = 0;
}

/* Drop the cache: the position moves. */
static void
textio_drop_chars(textio *self)
{
    tcache copy;
    tcache *c = cache_get(self, &copy);
    cache_clear(c);
    cache_put(self, c);
    cache_release(c);
    Py_CLEAR(self->dspan);
}

#ifdef Py_GIL_DISABLED
#  define SEENNL_ADD(self, seen) \
    _Py_atomic_or_uint8(&(self)->seennl, (uint8_t)(seen))
#else
#  define SEENNL_ADD(self, seen) ((self)->seennl |= (seen))
#endif

/* Use the buffer through its methods: for good (it got an instance dict),
   or while it can't hold the bytes needed (keeping read-ahead in rbuf). */
static void
store_use_methods(textio *self, store *st, int for_good)
{
    self->nib = 0;
    self->nib_ok &= !for_good;
    FT_ATOMIC_STORE_UINT8_RELAXED(self->lockfree, 0);
    if (self->codec != CODEC_DECODER) {
        cache_clear(st->c);
        cache_put(self, st->c);
    }
}

static int store_peek_methods(textio *self, store *st, Py_ssize_t need);

/* Peek at least need bytes (see _PyIONibbler_peek()); -1 on error. */
static inline int
store_peek(textio *self, store *st, Py_ssize_t need)
{
    if (!self->nib && self->nib_ok
        && (self->rbuf == NULL || self->rpos == PyBytes_GET_SIZE(self->rbuf)))
    {
        /* Nothing read ahead here any more: back to the buffer itself. */
        Py_CLEAR(self->rbuf);
        self->nib = 1;
    }
    if (self->nib) {
        Py_XDECREF(st->m.obj);
        int r = _PyIONibbler_peek(st->buffer, need, &st->m, &st->key);
        st->peeked = 1;
        if (r != _PyIO_NIBBLER_NO
            && (r != _PyIO_NIBBLER_FULL || st->lockfree))
        {
            st->status = r;
            st->eof = r == 0 && st->m.len < need;
            return r < 0 ? -1 : 0;
        }
        if (st->lockfree) {
            /* A dict on the buffer: the methods, with the critical
               section (see text_read()). */
            assert(r == _PyIO_NIBBLER_NO);
            FT_ATOMIC_STORE_UINT8_RELAXED(self->lockfree, 0);
            st->retry = 1;
            return -1;
        }
        store_use_methods(self, st, r == _PyIO_NIBBLER_NO);
    }
    return store_peek_methods(self, st, need);
}

/* store_peek() through the buffer's methods. */
Py_NO_INLINE static int
store_peek_methods(textio *self, store *st, Py_ssize_t need)
{
    store_release(st);
    st->eof = 0;
    st->peeked = 1;
    int r = 0;
    Py_ssize_t have = self->rbuf ? PyBytes_GET_SIZE(self->rbuf) - self->rpos
                                 : 0;
    while (have < need) {
        /* Growing geometrically, so that rbuf is copied O(1) times. */
        PyObject *size = PyLong_FromSsize_t(
            Py_MAX(FT_ATOMIC_LOAD_SSIZE_RELAXED(self->chunk_size),
                   Py_MAX(need - have, have)));
        if (size == NULL) {
            return -1;
        }
        PyObject *res = PyObject_CallMethodOneArg(
            st->buffer, self->has_read1 ? &_Py_ID(read1) : &_Py_ID(read),
            size);
        Py_DECREF(size);
        if (res == NULL) {
            if (_PyIO_trap_eintr()) {
                continue;
            }
            return -1;
        }
        if (res == Py_None) {
            Py_DECREF(res);
            r = _PyIO_NIBBLER_BLOCKED;
            break;
        }
        Py_buffer view;
        if (PyObject_GetBuffer(res, &view, PyBUF_SIMPLE) < 0) {
            PyErr_Format(PyExc_TypeError,
                         "underlying %s() should have returned a bytes-like "
                         "object, not '%.200s'",
                         self->has_read1 ? "read1": "read",
                         Py_TYPE(res)->tp_name);
            Py_DECREF(res);
            return -1;
        }
        PyObject *rbuf = PyBytes_FromStringAndSize(NULL, have + view.len);
        if (rbuf != NULL) {
            if (have) {
                memcpy(PyBytes_AS_STRING(rbuf),
                       PyBytes_AS_STRING(self->rbuf) + self->rpos, have);
            }
            memcpy(PyBytes_AS_STRING(rbuf) + have, view.buf, view.len);
        }
        Py_ssize_t got = view.len;
        PyBuffer_Release(&view);
        Py_DECREF(res);
        if (rbuf == NULL) {
            return -1;
        }
        Py_XSETREF(self->rbuf, rbuf);
        self->rpos = 0;
        self->rgen++;
        have += got;
        if (got == 0) {
            break;
        }
    }
    if (have > 0) {
        st->m = (_PyIO_Morsel){Py_NewRef(self->rbuf),
                               PyBytes_AS_STRING(self->rbuf) + self->rpos,
                               have};
    }
    st->key = STORE_KEY(self->rgen);
    st->status = r;
    st->eof = r == 0 && have < need;
    return 0;
}

static inline int store_advance(textio *self, store *st, uint64_t key,
                                Py_ssize_t off, Py_ssize_t n);

/* Take the first n bytes of st->m: 1, 0 if another thread took them, or
   -1. */
static int
store_take(textio *self, store *st, Py_ssize_t n)
{
    if (n == 0) {
        return 1;
    }
    return store_advance(self, st, st->key,
                         st->m.ptr - PyBytes_AS_STRING(st->m.obj), n);
}

/* Take n bytes from where key and off name: 1, 0 if the unread bytes
   don't start there any more, or -1. */
static inline int
store_advance(textio *self, store *st, uint64_t key, Py_ssize_t off,
              Py_ssize_t n)
{
    int r = 1;
    if (self->nib) {
        r = _PyIONibbler_advance(st->buffer, key, off, n);
    }
    else if (self->rbuf != NULL && key == STORE_KEY(self->rgen)
             && self->rpos == off
             && n <= PyBytes_GET_SIZE(self->rbuf) - off)
    {
        self->rpos += n;
    }
    else {
        r = 0;
    }
    if (r == 1 && n > 0) {
        if (st->m.obj != NULL) {
            st->m.ptr += n;
            st->m.len -= n;
        }
        if (self->enc == CODEC_DECODER && self->encoding_start_of_stream
            && self->encoder != NULL)
        {
            /* Not at the start any more: no BOM. */
            self->encoding_start_of_stream = 0;
            PyObject *res = PyObject_CallMethodOneArg(
                self->encoder, &_Py_ID(setstate), _PyLong_GetZero());
            Py_XDECREF(res);
            return res == NULL ? -1 : 1;
        }
    }
    return r;
}

/* Hand the read-ahead in rbuf back to the buffer, so that its position is
   the text position (the buffer as the store has none to hand back). */
static int
store_rewind(textio *self, PyObject *buffer)
{
    Py_ssize_t unread = self->rbuf ? PyBytes_GET_SIZE(self->rbuf) - self->rpos
                                   : 0;
    if (unread == 0 || !self->seekable) {
        /* Not seekable: reads and writes are separate streams. */
        return 0;
    }
    PyObject *res = _PyObject_CallMethod(buffer, &_Py_ID(seek), "ni",
                                         -unread, SEEK_CUR);
    if (res == NULL) {
        return -1;
    }
    Py_DECREF(res);
    Py_CLEAR(self->rbuf);
    self->rpos = 0;
    return 0;
}

/* The position of the store as an int (PyLong). */
static PyObject *
store_tell(textio *self, PyObject *buffer)
{
    PyObject *pos = PyObject_CallMethodNoArgs(buffer, &_Py_ID(tell));
    Py_ssize_t unread = self->rbuf ? PyBytes_GET_SIZE(self->rbuf) - self->rpos
                                   : 0;
    if (pos != NULL && unread > 0) {
        PyObject *k = PyLong_FromSsize_t(unread);
        Py_SETREF(pos, k == NULL ? NULL : PyNumber_Subtract(pos, k));
        Py_XDECREF(k);
    }
    return pos;
}

/* store_write() past its first case: rbuf handed back first, or through
   the buffer's write(). */
Py_NO_INLINE static int
store_write_methods(textio *self, PyObject *buffer, PyObject *obj,
                    const char *data, Py_ssize_t len)
{
    if (len == 0) {
        return 0;
    }
    if (self->rbuf != NULL && store_rewind(self, buffer) < 0) {
        return -1;
    }
    if (!self->nib && self->nib_ok && self->rbuf == NULL) {
        self->nib = 1;
    }
    if (self->nib) {
        int r = _PyIONibbler_write(buffer, obj, data, len);
        if (r != _PyIO_NIBBLER_NO) {
            return r;
        }
        self->nib = self->nib_ok = 0;
        FT_ATOMIC_STORE_UINT8_RELAXED(self->lockfree, 0);
    }
    PyObject *b = (PyBytes_CheckExact(obj) ? Py_NewRef(obj)
                   : PyBytes_FromStringAndSize(data, len));
    if (b == NULL) {
        return -1;
    }
    PyObject *res;
    do {
        res = PyObject_CallMethodOneArg(buffer, &_Py_ID(write), b);
    } while (res == NULL && _PyIO_trap_eintr());
    Py_DECREF(b);
    Py_XDECREF(res);
    return res == NULL ? -1 : 0;
}

static inline int
store_write(textio *self, PyObject *buffer, PyObject *obj, const char *data,
            Py_ssize_t len)
{
    if (self->nib && len > 0) {
        int r = _PyIONibbler_write(buffer, obj, data, len);
        if (r != _PyIO_NIBBLER_NO) {
            return r;
        }
    }
    return store_write_methods(self, buffer, obj, data, len);
}

/*
 * Decoding
 */

/* The UTF-8 bytes of chars[i:i+k] beyond one per character: those of
   characters from 0x80 on (and again from 0x800 on), counted a word, or a
   vector of 16 bytes where the compiler has them, at a time (summed by
   lanes, below their overflow). */
#if defined(__GNUC__) || defined(__clang__)
typedef uint16_t text_v16 __attribute__((vector_size(16)));
typedef int16_t text_vs16 __attribute__((vector_size(16)));
typedef int8_t text_v8 __attribute__((vector_size(16)));
#  define TEXT_VECTORS 1
#endif

static inline Py_ssize_t
utf8_extra_ucs1(const Py_UCS1 *p, Py_ssize_t k)
{
    /* The top bits, 4 words at a time (each byte of the sum is at most
       4), then the bytes of the sum by multiplying; the last bytes in the
       word ending with them (if there is one). */
    const uint64_t h = 0x8080808080808080ull;
    const uint64_t ones = 0x0101010101010101ull;
    Py_ssize_t n = 0, j = 0;
#ifdef TEXT_VECTORS
    if (k >= 16) {
        /* 15 vectors at most per sum (14 and the last), so that its
           lanes add up to a byte. */
        while (j + 16 <= k) {
            text_v8 acc = {0};
            Py_ssize_t stop = Py_MIN(k, j + 16 * 14);
            for (; j + 32 <= stop; j += 32) {
                text_v8 v[2];
                memcpy(v, p + j, 32);
                acc += (text_v8)(v[0] < 0) + (text_v8)(v[1] < 0);
            }
            if (j + 16 <= stop) {
                text_v8 v;
                memcpy(&v, p + j, 16);
                acc += (text_v8)(v < 0);
                j += 16;
            }
            if (j + 16 > k && j < k) {
                /* The last ones, in the 16 ending with them. */
                const text_v8 lane = {0, 1, 2, 3, 4, 5, 6, 7,
                                      8, 9, 10, 11, 12, 13, 14, 15};
                text_v8 v;
                memcpy(&v, p + k - 16, 16);
                acc += ((text_v8)(v < 0)
                        & (text_v8)(lane >= (int8_t)(16 - (k - j))));
                j = k;
            }
            acc = -acc;
            uint64_t w[2];
            memcpy(w, &acc, 16);
            n += (Py_ssize_t)(((w[0] + w[1]) * ones) >> 56);
        }
        return n;
    }
#endif
    for (; j + 32 <= k; j += 32) {
        uint64_t w[4];
        memcpy(w, p + j, 32);
        uint64_t sum = (((w[0] & h) >> 7) + ((w[1] & h) >> 7)
                        + ((w[2] & h) >> 7) + ((w[3] & h) >> 7));
        n += (Py_ssize_t)((sum * ones) >> 56);
    }
    for (; j + 8 <= k; j += 8) {
        uint64_t w;
        memcpy(&w, p + j, 8);
        n += (Py_ssize_t)((((w & h) >> 7) * ones) >> 56);
    }
    if (j < k && k >= 8) {
        uint64_t w;
        memcpy(&w, p + k - 8, 8);
#if PY_LITTLE_ENDIAN
        w >>= 8 * (8 - (k - j));
#else
        w <<= 8 * (8 - (k - j));
#endif
        return n + (Py_ssize_t)(((((w & h) >> 7)) * ones) >> 56);
    }
    for (; j < k; j++) {
        n += p[j] >> 7;
    }
    return n;
}

#ifdef TEXT_VECTORS
/* Per lane, minus the UTF-8 bytes beyond one of p[0:8], and in *wide
   whether it is from 0x100 on: compared as signed (as SSE2 can), biased by
   0x8000. */
static inline text_vs16
utf8_extra_lanes(const Py_UCS2 *p, text_vs16 *wide)
{
    text_v16 v;
    memcpy(&v, p, 16);
    text_vs16 u = (text_vs16)(v ^ 0x8000);
    *wide |= (text_vs16)(u > INT16_MIN + 0xff);
    return ((text_vs16)(u > INT16_MIN + 0x7f)
            + (text_vs16)(u > INT16_MIN + 0x7ff));
}

/* The sum of the lanes, each 0 to 4096. */
static inline Py_ssize_t
utf8_lanes_sum(text_vs16 acc)
{
    uint64_t w[2];
    memcpy(w, &acc, 16);
    return (Py_ssize_t)(((w[0] + w[1]) * 0x0001000100010001ull) >> 48);
}
#endif

/* The UTF-8 bytes of p[0:k] beyond one per character, and in *wide whether
   one is from 0x100 on (then a str of them has 2 byte characters). */
static inline Py_ssize_t
utf8_extra_ucs2(const Py_UCS2 *p, Py_ssize_t k, int *wide)
{
    Py_ssize_t n = 0, j = 0;
#ifdef TEXT_VECTORS
    text_vs16 w = {0};
    while (j + 8 <= k) {
        text_vs16 acc = {0};
        Py_ssize_t stop = Py_MIN(k, j + 8 * 2048);
        for (; j + 32 <= stop; j += 32) {
            acc += (utf8_extra_lanes(p + j, &w)
                    + utf8_extra_lanes(p + j + 8, &w)
                    + utf8_extra_lanes(p + j + 16, &w)
                    + utf8_extra_lanes(p + j + 24, &w));
        }
        for (; j + 8 <= stop; j += 8) {
            acc += utf8_extra_lanes(p + j, &w);
        }
        n += utf8_lanes_sum(-acc);
    }
    if (j < k && k >= 8) {
        /* The last ones, in the 8 ending with them. */
        const text_vs16 lane = {0, 1, 2, 3, 4, 5, 6, 7};
        text_vs16 c = (utf8_extra_lanes(p + k - 8, &w)
                       & (text_vs16)(lane >= (int16_t)(8 - (k - j))));
        n += utf8_lanes_sum(-c);
        j = k;
    }
    uint64_t x[2];
    memcpy(x, &w, 16);
    *wide = (x[0] | x[1]) != 0;
#else
    *wide = 0;
#endif
    for (; j < k; j++) {
        n += (p[j] >= 0x80) + (p[j] >= 0x800);
        *wide |= p[j] >= 0x100;
    }
    return n;
}

/* The UTF-8 bytes of chars[i:i+k].  Surrogates (with escapes) were bytes
   escaped with surrogateescape: one each. */
static inline Py_ssize_t
utf8_bytes(PyObject *chars, int escapes, Py_ssize_t i, Py_ssize_t k)
{
    if (PyUnicode_IS_ASCII(chars)) {
        return k;
    }
    const void *data = PyUnicode_DATA(chars);
    int kind = PyUnicode_KIND(chars);
    if (kind == PyUnicode_1BYTE_KIND) {
        return k + utf8_extra_ucs1((const Py_UCS1 *)data + i, k);
    }
    int wide;
    if (kind == PyUnicode_2BYTE_KIND && !escapes) {
        return k + utf8_extra_ucs2((const Py_UCS2 *)data + i, k, &wide);
    }
    Py_ssize_t n = k;
    for (Py_ssize_t j = i; j < i + k; j++) {
        Py_UCS4 c = PyUnicode_READ(kind, data, j);
        n += (c >= 0x80) + (c >= 0x800) + (c >= 0x10000)
             - 2 * Py_UNICODE_IS_SURROGATE(c);
    }
    return n;
}

/* The UTF-8 bytes of chars[i:i+k] (kbytes those of chars[i:]). */
static Py_ssize_t
text_bytes(textio *self, PyObject *chars, Py_ssize_t kbytes, Py_ssize_t i,
           Py_ssize_t k)
{
    return (i + k == PyUnicode_GET_LENGTH(chars) ? kbytes
            : utf8_bytes(chars, self->escapes, i, k));
}

/* A native codec's decoding of s[0:len] (but a partial character at the
   end, unless final): *used gets the bytes decoded. */
static PyObject *
native_decode(textio *self, const char *s, Py_ssize_t len, int final,
              Py_ssize_t *used)
{
    /* NULL is "strict", which the UTF-8 decoder does fastest. */
    const char *errors = (self->errors == &_Py_ID(strict) ? NULL
                          : PyUnicode_AsUTF8(self->errors));
    *used = len;
    switch (self->codec) {
    case CODEC_UTF8: {
        /* Not final, so as not to count the characters first (as the
           decoder does when final), which costs more than it saves; but
           bytes left at the end are an error then. */
        PyObject *chars = PyUnicode_DecodeUTF8Stateful(s, len, errors, used);
        if (chars != NULL && final && *used < len) {
            Py_SETREF(chars, PyUnicode_DecodeUTF8Stateful(s, len, errors,
                                                          NULL));
            *used = len;
        }
        return chars;
    }
    case CODEC_LATIN1:
        return PyUnicode_DecodeLatin1(s, len, errors);
    case CODEC_ASCII:
        return PyUnicode_DecodeASCII(s, len, errors);
    default:
        /* ASCII decodes as itself, faster. */
        if (_Py_bytes_isascii(s, len) == Py_True) {
            return PyUnicode_DecodeASCII(s, len, errors);
        }
        return PyUnicode_DecodeCharmap(s, len, self->charmap, errors);
    }
}

/* The decoder's flags. */
static int
decoder_flags(textio *self, int *flags, Py_ssize_t *held)
{
    PyObject *state = PyObject_CallMethodNoArgs(self->decoder,
                                                &_Py_ID(getstate));
    PyObject *buf;
    int ok = (state != NULL && PyTuple_Check(state)
              && PyArg_ParseTuple(state, "Oi;illegal decoder state", &buf,
                                  flags)
              && PyBytes_Check(buf));
    if (ok && held != NULL) {
        *held = PyBytes_GET_SIZE(buf);
    }
    if (!ok && state != NULL && !PyErr_Occurred()) {
        PyErr_SetString(PyExc_TypeError, "illegal decoder state");
    }
    Py_XDECREF(state);
    return ok ? 0 : -1;
}

/* Set the decoder to (b"", flags), or reset it (FLAGS_FRESH). */
static int
decoder_setstate(textio *self, int flags)
{
    PyObject *res = (flags == FLAGS_FRESH
                     ? PyObject_CallMethodNoArgs(self->decoder, &_Py_ID(reset))
                     : _PyObject_CallMethod(self->decoder, &_Py_ID(setstate),
                                            "((yi))", "", flags));
    Py_XDECREF(res);
    return res == NULL ? -1 : 0;
}

/* The decoder's decoding of s[0:len], from (b"", flags): *used gets the
   bytes it decoded (not those it holds, which it is made to forget),
   *flags its flags after them. */
static PyObject *
decoder_decode(textio *self, const char *s, Py_ssize_t len, int final,
               Py_ssize_t *used, int *flags)
{
    if (decoder_setstate(self, *flags) < 0) {
        return NULL;
    }
    PyObject *input = PyBytes_FromStringAndSize(s, len);
    if (input == NULL) {
        return NULL;
    }
    PyObject *chars = PyObject_CallMethodObjArgs(
        self->decoder, &_Py_ID(decode), input, final ? Py_True : Py_False,
        NULL);
    Py_DECREF(input);
    if (chars != NULL && !PyUnicode_Check(chars)) {
        PyErr_Format(PyExc_TypeError,
                     "decoder should return a string result, not '%.200s'",
                     Py_TYPE(chars)->tp_name);
        Py_CLEAR(chars);
    }
    Py_ssize_t held = 0;
    if (chars == NULL || decoder_flags(self, flags, &held) < 0
        || (held > 0 && decoder_setstate(self, *flags) < 0))
    {
        Py_XDECREF(chars);
        return NULL;
    }
    *used = len - held;
    return chars;
}

/* The decoder: where in dspan its first ci characters end, decoding it
   again from dflags (the fewest bytes giving at least that many): *off
   (from the end of dspan, which is at the store's position), with *flags
   its flags there.  Returns 1 if exactly there, 0 if past characters a
   byte decoded to as a group, or -1. */
static int
decoder_offset(textio *self, Py_ssize_t ci, Py_ssize_t *off, int *flags)
{
    /* The decoder runs Python code, which may use self. */
    PyObject *span = Py_NewRef(self->dspan);
    int dflags = self->dflags;
    Py_ssize_t lo = 0, hi = PyBytes_GET_SIZE(span), used = 0, n = 0;
    int r = -1;
    while (lo <= hi) {
        Py_ssize_t mid = lo + (hi - lo) / 2;
        *flags = dflags;
        PyObject *chars = decoder_decode(self, PyBytes_AS_STRING(span), mid,
                                         0, &used, flags);
        if (chars == NULL) {
            goto done;
        }
        n = PyUnicode_GET_LENGTH(chars);
        Py_DECREF(chars);
        if (lo == hi) {
            break;
        }
        if (n >= ci) {
            hi = mid;
        }
        else {
            lo = mid + 1;
        }
    }
    *off = lo - PyBytes_GET_SIZE(span);
    r = n == ci && used == lo;
done:
    Py_DECREF(span);
    return r;
}

/* Are chars[ci:] the characters at st's position?  (With the decoder,
   always.) */
static int
text_valid(textio *self, store *st)
{
    /* Not looked at the store yet: assumed (text_commit() finds out). */
    return (st->c->chars != NULL
            && (self->codec == CODEC_DECODER || !st->peeked
                || (st->m.obj != NULL && st->key == st->c->key
                    && st->m.ptr - PyBytes_AS_STRING(st->m.obj)
                       == st->c->koff)));
}

/* How many characters there are at the position, decoded. */
static Py_ssize_t
text_avail(textio *self, store *st)
{
    return (text_valid(self, st)
            ? PyUnicode_GET_LENGTH(st->c->chars) - st->c->ci : 0);
}

/* Where a UnicodeDecodeError found invalid bytes. */
static int
text_decode_error(Py_ssize_t *start, Py_ssize_t *end)
{
    PyObject *exc = PyErr_GetRaisedException();
    int r = (PyUnicodeDecodeError_GetStart(exc, start) < 0
             || PyUnicodeDecodeError_GetEnd(exc, end) < 0) ? -1 : 0;
    PyErr_Clear();
    PyErr_SetRaisedException(exc);
    return r;
}

/* Native codecs: decode more of the store's bytes (reading more when all
   that is there was).  Returns 1 if there may be more characters, 0 if
   not for now, or -1. */
static int
native_more(textio *self, store *st)
{
    if (!st->peeked) {
        /* What the store has, to see whether chars are of it. */
        if (store_peek(self, st, 1) < 0) {
            return -1;
        }
        return 1;
    }
    Py_ssize_t covered = text_valid(self, st) ? st->c->kbytes : 0;
    if (st->m.obj != NULL && covered < st->m.len) {
        /* A bigger span from the position: twice as much (and a whole
           character more), so that a long line is decoded O(1) times. */
        Py_ssize_t chunk = FT_ATOMIC_LOAD_SSIZE_RELAXED(self->chunk_size);
        Py_ssize_t span = Py_MIN(st->m.len,
                                 Py_MAX(chunk, 2 * covered + 4));
        span = Py_MIN(st->all ? st->m.len : span, SPAN_MAX);
        int final = st->eof && span == st->m.len;
        Py_ssize_t used;
        PyObject *chars = native_decode(self, st->m.ptr, span, final, &used);
        Py_ssize_t start, end;
        if (chars == NULL && PyErr_ExceptionMatches(PyExc_UnicodeDecodeError)
            && text_decode_error(&start, &end) == 0)
        {
            /* Decode what is valid; at invalid bytes, take them, so that
               the error is raised once (as _io's does). */
            if (start > 0) {
                PyErr_Clear();
                chars = native_decode(self, st->m.ptr, start, 0, &used);
            }
            else {
                PyObject *exc = PyErr_GetRaisedException();
                if (store_take(self, st, Py_MIN(end, st->m.len)) < 0) {
                    _PyErr_ChainExceptions1(exc);
                    return -1;
                }
                PyErr_SetRaisedException(exc);
            }
        }
        if (chars == NULL) {
            return -1;
        }
        Py_XSETREF(st->c->chars, chars);
        st->c->ci = 0;
        st->c->cr_at = -1;
        st->c->key = st->key;
        st->c->koff = st->m.ptr - PyBytes_AS_STRING(st->m.obj);
        st->c->kbytes = used;
        st->c->skip_lf = 0;
        st->c->nl = 0;
        st->c->renew = 1;
        if (cache_put(self, st->c) < 0) {
            return -1;
        }
        if (used > covered) {
            return 1;
        }
        /* Only part of a character more. */
    }
    if (st->peeked && (st->eof || st->status)) {
        return 0;
    }
    if (store_peek(self, st, st->m.len + 1) < 0) {
        return -1;
    }
    /* More bytes, or the same in another block (to decode again). */
    return (text_valid(self, st) ? st->c->kbytes : 0) < st->m.len;
}

/* The codec's decoder: decode the bytes after those it held (left in the
   store), reading more if there are none, and take them.  Returns 1 if
   there may be more characters, 0 if not for now, or -1. */
static int
decoder_more(textio *self, store *st)
{
    if (st->m.obj == NULL || st->m.len <= st->held) {
        if (st->peeked && (st->eof || st->status)) {
            return 0;
        }
        if (store_peek(self, st, st->held + 1) < 0) {
            return -1;
        }
        if (st->m.len <= st->held && !(st->eof && st->m.len > 0)) {
            return 0;
        }
    }
    /* As for native codecs, more than twice what the decoder held. */
    Py_ssize_t avail = text_avail(self, st);
    Py_ssize_t span = Py_MIN(st->m.len,
                             Py_MAX(Py_MAX(self->chunk_size,
                                           avail ? PyBytes_GET_SIZE(self->dspan)
                                                 : 0),
                                    2 * st->held + 4));
    span = st->all ? st->m.len : span;
    int final = st->eof && span == st->m.len;
    Py_ssize_t used;
    /* From the store's position (another thread may have used the decoder
       while this one waited): the flags there. */
    if (self->flags == FLAGS_FRESH
        && decoder_flags(self, &self->flags, NULL) < 0)
    {
        return -1;
    }
    int flags = self->flags;
    PyObject *chars = decoder_decode(self, st->m.ptr, span, final, &used,
                                     &flags);
    PyObject *bytes = chars ? PyBytes_FromStringAndSize(st->m.ptr, used)
                            : NULL;
    int r = bytes ? store_take(self, st, used) : -1;
    if (r <= 0) {
        /* Another thread took bytes: look again. */
        Py_XDECREF(chars);
        Py_XDECREF(bytes);
        store_forget(st);
        return r < 0 ? -1 : 1;
    }
    st->held = final ? 0 : span - used;
    /* The bytes are taken: their characters go after the cache's (which
       another thread may have changed while this one waited for the
       buffer). */
    cache_release(st->c);
    st->c = cache_get(self, STORE_COPY(st));
    if (st->c->chars == NULL || self->dspan == NULL
        || st->c->ci == PyUnicode_GET_LENGTH(st->c->chars))
    {
        Py_XSETREF(st->c->chars, chars);
        Py_XSETREF(self->dspan, bytes);
        st->c->ci = 0;
        self->dflags = self->flags;
        st->c->cr_at = -1;
    }
    else {
        PyUnicode_Append(&st->c->chars, chars);
        PyBytes_ConcatAndDel(&self->dspan, bytes);
        st->c->cr_at = -1;
        Py_DECREF(chars);
        if (st->c->chars == NULL || self->dspan == NULL) {
            cache_clear(st->c);
            textio_drop_chars(self);
            return -1;
        }
    }
    self->flags = flags;
    st->c->renew = 1;
    if (cache_put(self, st->c) < 0) {
        textio_drop_chars(self);
        return -1;
    }
    return 1;
}

/* Make chars[ci:] the characters at the position, more than `have` of
   them if the store has more now.  Returns how many, or -1.
   st->at_end tells whether none can ever follow them. */
static inline int
text_at_end(textio *self, store *st, Py_ssize_t avail)
{
    return st->eof && (self->codec == CODEC_DECODER ? st->m.len == 0
                       : avail == 0 || st->c->kbytes == st->m.len);
}

Py_NO_INLINE static Py_ssize_t
text_more(textio *self, store *st, Py_ssize_t have)
{
    while (st->all && !st->eof && !st->status) {
        /* Everything first, to decode it once. */
        if (store_peek(self, st, st->m.len + 1) < 0) {
            return -1;
        }
    }
    for (;;) {
        Py_ssize_t avail = text_avail(self, st);
        int r = 0;
        if (avail <= have) {
            r = (self->codec == CODEC_DECODER ? decoder_more(self, st)
                 : native_more(self, st));
            if (r < 0) {
                return -1;
            }
            avail = text_avail(self, st);
        }
        if (avail > have || r == 0) {
            st->at_end = text_at_end(self, st, avail);
            return avail;
        }
    }
}

/* Take k characters from chars[ci:], at the store's position: their bytes
   with a native codec.  Returns 1, 0 if another thread took bytes
   meanwhile (then nothing was taken), or -1. */
static int
text_commit(textio *self, store *st, Py_ssize_t k)
{
    Py_ssize_t ci = st->c->ci;
    if (self->codec != CODEC_DECODER) {
        Py_ssize_t b = (self->codec == CODEC_UTF8
                        ? text_bytes(self, st->c->chars, st->c->kbytes, ci, k)
                        : k);
#ifndef Py_GIL_DISABLED
        /* With the GIL, the cache is the call's own (see cache_get()), but
           other threads may decode while this one waits for the buffer. */
        PyObject *chars = st->c->chars;
        Py_ssize_t koff = st->c->koff;
#endif
        int r = store_advance(self, st, st->c->key, st->c->koff, b);
        if (r == 0) {
            /* Another thread took bytes: look at them afresh (not
               trusting the cache, which it may not have updated). */
            cache_release(st->c);
            st->c = cache_get(self, STORE_COPY(st));
            store_forget(st);
            if (store_peek(self, st, 1) < 0) {
                return -1;
            }
        }
        if (r <= 0) {
            return r;
        }
#ifndef Py_GIL_DISABLED
        if (st->c->chars != chars || st->c->koff != koff) {
            /* Now out of date (see text_read_impl()). */
            return 1;
        }
#endif
        st->c->koff += b;
        st->c->kbytes -= b;
    }
    st->c->ci = ci + k;
    cache_put(self, st->c);
    FT_ATOMIC_STORE_UINT8_RELAXED(self->decoded, 1);
    /* With room again, the buffer may take more. */
    st->status = 0;
    return 1;
}

/*
 * Newlines
 */

/* The first ch (a control character) in s[0:end) of a str's data (which
   ends with a NUL), or NULL. */
static const char *
find_char(int kind, const char *s, const char *end, Py_UCS4 ch)
{
    if (kind == PyUnicode_1BYTE_KIND) {
        return memchr(s, (char)ch, end - s);
    }
    /* Look for its low byte with memchr. */
#if PY_LITTLE_ENDIAN
    const int low = 0;
#else
    const int low = kind - 1;
#endif
    for (const char *p = s + low; p < end;) {
        p = memchr(p, (char)ch, end - p);
        if (p == NULL) {
            break;
        }
        const char *c = p - low;
        if ((c - s) % kind == 0 && PyUnicode_READ(kind, c, 0) == ch) {
            return c;
        }
        p++;
    }
    return NULL;
}

/* The first "\r" in s[0:end) of chars' data, or NULL, s being the
   position (or where a search for a line's end resumes, with none before
   it).  Where the next one is is kept in *cr_at (see tcache), so that
   "\r"-less text is looked at once. */
static Py_ALWAYS_INLINE const char *
find_cr(PyObject *chars, Py_ssize_t *cr_at, int kind, const char *s,
        const char *end)
{
    const char *base = PyUnicode_DATA(chars);
    Py_ssize_t at = FT_ATOMIC_LOAD_SSIZE_RELAXED(*cr_at);
    if (at < s - base) {
        Py_ssize_t len = PyUnicode_GET_LENGTH(chars) * kind;
        const char *cr = find_char(kind, s, base + len, '\r');
        FT_ATOMIC_STORE_SSIZE_RELAXED(*cr_at, at = cr ? cr - base : len);
    }
    return base + at < end ? base + at : NULL;
}

/* Note the kinds of newline in chars[ci:] (but a "\r" last, which the
   characters after it tell), as _io's decoder notes those of what it
   decodes, so that reads needn't.  (See find_cr() for cr_at.) */
Py_NO_INLINE static void
text_note_newlines(textio *self, PyObject *chars, Py_ssize_t ci,
                   int skip_lf, Py_ssize_t *cr_at)
{
    int kind = PyUnicode_KIND(chars);
    const void *data = PyUnicode_DATA(chars);
    Py_ssize_t j = ci, n = PyUnicode_GET_LENGTH(chars);
    /* How many "\r" and "\n", and "\r\n" (data[n] exists: the last "\r",
       or the NUL after the characters, neither a "\n"). */
    Py_ssize_t cr = 0, lf = 0, crlf = 0;
    j += skip_lf && j < n && PyUnicode_READ(kind, data, j) == '\n';
    if (find_cr(chars, cr_at, kind, (const char *)data + j * kind,
                (const char *)data + n * kind) == NULL)
    {
        /* No "\r": a "\n" tells. */
        lf = (!(FT_ATOMIC_LOAD_UINT8_RELAXED(self->seennl) & SEEN_LF)
              && find_char(kind, (const char *)data + j * kind,
                           (const char *)data + n * kind, '\n') != NULL);
        j = n;
    }
    n -= n > j && PyUnicode_READ(kind, data, n - 1) == '\r';
    /* The "\n"s counted are those after each character, and one first. */
    if (j < n) {
        lf = PyUnicode_READ(kind, data, j) == '\n';
    }
#ifdef TEXT_VECTORS
    if (kind == PyUnicode_1BYTE_KIND) {
        /* 15 vectors per sum at most, so that its lanes add up to a byte
           (see utf8_extra_ucs1()). */
        const Py_UCS1 *p = data;
        while (j + 16 <= n) {
            text_v8 vcr = {0}, vlf = {0}, vcrlf = {0};
            for (Py_ssize_t stop = Py_MIN(n, j + 16 * 15); j + 16 <= stop;
                 j += 16)
            {
                text_v8 a, b;
                memcpy(&a, p + j, 16);
                memcpy(&b, p + j + 1, 16);
                text_v8 r = (text_v8)(a == '\r');
                text_v8 l = (text_v8)(b == '\n');
                vcr += r;
                vlf += l;
                vcrlf += r & l;
            }
            uint64_t w[6];
            vcr = -vcr;
            vlf = -vlf;
            vcrlf = -vcrlf;
            memcpy(w, &vcr, 16);
            memcpy(w + 2, &vlf, 16);
            memcpy(w + 4, &vcrlf, 16);
            const uint64_t ones = 0x0101010101010101ull;
            cr += (Py_ssize_t)(((w[0] + w[1]) * ones) >> 56);
            lf += (Py_ssize_t)(((w[2] + w[3]) * ones) >> 56);
            crlf += (Py_ssize_t)(((w[4] + w[5]) * ones) >> 56);
        }
    }
#endif
    for (; j < n; j++) {
        int r = PyUnicode_READ(kind, data, j) == '\r';
        int l = PyUnicode_READ(kind, data, j + 1) == '\n';
        cr += r;
        lf += l;
        crlf += r & l;
    }
    int seen = ((crlf ? SEEN_CRLF : 0) | (cr != crlf ? SEEN_CR : 0)
                | (lf != crlf ? SEEN_LF : 0));
    if ((FT_ATOMIC_LOAD_UINT8_RELAXED(self->seennl) & seen) != seen) {
        SEENNL_ADD(self, seen);
    }
}

/* The length of the first line of s[0:end), with its newline, or -1 if
   none ends there (a "\r" at the end may begin a "\r\n"): then *resume
   is where to look on from. */
static Py_ssize_t
find_line(textio *self, tcache *c, int kind, const char *s, const char *end,
          Py_ssize_t *resume)
{
    if (self->readuniversal) {
        const char *lf = find_char(kind, s, end, '\n');
        const char *cr = find_cr(c->chars, &c->cr_at, kind, s, lf ? lf : end);
        if (cr == NULL && lf != NULL) {
            return (lf - s) / kind + 1;
        }
        if (cr != NULL && cr + kind < end) {
            return (cr - s) / kind + 1
                   + (PyUnicode_READ(kind, cr, 1) == '\n');
        }
        *resume = (cr ? cr - s : end - s) / kind;
        return -1;
    }
    /* "\n", "\r" or "\r\n" */
    Py_ssize_t e = _PyIO_find_line_ending(0, 0, self->readnl, kind, s, end,
                                          resume);
    return e;
}

/* res (stolen) with "\r\n" and "\r" made "\n": out characters. */
static PyObject *
text_translate(PyObject *res, Py_ssize_t out)
{
    if (res == NULL) {
        return NULL;
    }
    PyObject *t = PyUnicode_New(out, PyUnicode_MAX_CHAR_VALUE(res));
    if (t != NULL) {
        /* Runs between "\r"s copied whole (t has the kind of res). */
        int kind = PyUnicode_KIND(res);
        const char *r = PyUnicode_DATA(res);
        const char *rend = r + PyUnicode_GET_LENGTH(res) * kind;
        char *o = PyUnicode_DATA(t);
        assert(PyUnicode_KIND(t) == kind);
        while (r < rend) {
            const char *cr = find_char(kind, r, rend, '\r');
            const char *stop = cr ? cr : rend;
            memcpy(o, r, stop - r);
            o += stop - r;
            if (cr == NULL) {
                break;
            }
            PyUnicode_WRITE(kind, o, 0, '\n');
            o += kind;
            r = cr + kind;
            if (r < rend && PyUnicode_READ(kind, r, 0) == '\n') {
                r += kind;
            }
        }
        assert(o == (char *)PyUnicode_DATA(t) + out * kind);
    }
    Py_DECREF(res);
    return t;
}

/* The text of the characters at the position, chars[i:i+avail]: up to
   `want` characters of it (-1: no limit), or with `line` up to the end of
   the first line.  With universal newlines, a "\r" is taken only once what
   follows it is known (or at eof), and translated with readtranslate.
   *k gets how many characters are taken (0: nothing can be yet), and with
   `line`, *found whether the line (or want) ended; *scanned is where the
   search for its end goes on from.  Notes the newlines in the text. */
static PyObject *
text_take(textio *self, store *st, Py_ssize_t avail, Py_ssize_t want, int line,
          int eof, Py_ssize_t *scanned, Py_ssize_t *k, int *found)
{
    PyObject *chars = st->c->chars;
    Py_ssize_t i = st->c->ci;
    int kind = PyUnicode_KIND(chars);
    const char *s = (const char *)PyUnicode_DATA(chars) + i * kind;
    const char *end = s + avail * kind;
#define AT(j) PyUnicode_READ(kind, s, (j))
    int seen = 0, translate = 0, skip_lf = 0;
    Py_ssize_t n, out;
    *found = 0;
    if (line) {
        Py_ssize_t resume = 0;
        Py_ssize_t e = find_line(self, st->c, kind, s + *scanned * kind, end,
                                 &resume);
        if (e >= 0) {
            n = *scanned + e;
            *found = 1;
        }
        else {
            *scanned += resume;
            /* The rest ends at eof, or is limited by want (unless it ends
               with a "\r" that may be part of the line's end). */
            int cr_last = (self->readuniversal && !eof
                           && AT(avail - 1) == '\r');
            n = (want >= 0 && avail - cr_last >= want ? want
                 : eof ? avail : 0);
            *found = n > 0;
        }
        out = n;
        if (self->readuniversal && n > 0) {
            Py_UCS4 c = AT(n - 1);
            if (c == '\n') {
                seen = (n > 1 && AT(n - 2) == '\r') ? SEEN_CRLF
                       : (n == 1 && st->c->skip_lf) ? 0 : SEEN_LF;
                if (seen == SEEN_CRLF && self->readtranslate) {
                    out--;
                    translate = 1;
                }
            }
            else if (c == '\r') {
                seen = (n < avail && AT(n) == '\n') ? SEEN_CRLF : SEEN_CR;
                translate = self->readtranslate;
            }
        }
        if (want >= 0 && out > want) {
            /* Cut before the line's end (but between "\r" and "\n" if
               not translated). */
            n = out = want;
            translate = 0;
            seen = (n > 0 && self->readuniversal && AT(n - 1) == '\r')
                   ? SEEN_CRLF : 0;
            *found = 1;
        }
        skip_lf = seen == SEEN_CRLF && !translate && AT(n - 1) == '\r';
    }
    else {
        Py_ssize_t lim = want < 0 ? avail : Py_MIN(avail, want);
        const char *cr = (self->readuniversal
                          ? find_cr(st->c->chars, &st->c->cr_at, kind, s,
                                    s + lim * kind)
                          : NULL);
        n = out = cr ? (cr - s) / kind : lim;
        if (self->readuniversal
            && !(FT_ATOMIC_LOAD_UINT8_RELAXED(self->seennl) & SEEN_LF))
        {
            Py_ssize_t from = st->c->skip_lf && n > 0 && AT(0) == '\n';
            if (find_char(kind, s + from * kind, s + n * kind, '\n')) {
                seen |= SEEN_LF;
            }
        }
        /* Past a "\r": translate it with what follows, until want. */
        while (cr != NULL && (want < 0 || out < want)) {
            if (n + 1 == avail && !eof) {
                break;
            }
            int crlf = n + 1 < avail && AT(n + 1) == '\n';
            seen |= crlf ? SEEN_CRLF : SEEN_CR;
            translate |= self->readtranslate;
            if (self->readtranslate || (crlf && (want < 0 || out + 1 < want))) {
                n += 1 + crlf;
                out += 1 + (crlf && !self->readtranslate);
            }
            else {
                n++;
                out++;
                skip_lf = crlf;
            }
            Py_ssize_t left = want < 0 ? avail - n
                              : Py_MIN(avail - n, want - out);
            cr = find_char(kind, s + n * kind, s + (n + left) * kind, '\r');
            Py_ssize_t run = cr ? (cr - s) / kind - n : left;
            if (!(FT_ATOMIC_LOAD_UINT8_RELAXED(self->seennl) & SEEN_LF)
                && !(seen & SEEN_LF)
                && find_char(kind, s + n * kind, s + (n + run) * kind, '\n'))
            {
                seen |= SEEN_LF;
            }
            n += run;
            out += run;
        }
    }
    *k = n;
    if (n == 0) {
        return NULL;
    }
    SEENNL_ADD(self, seen);
    st->c->skip_lf = skip_lf;
    PyObject *res = PyUnicode_Substring(chars, i, i + n);
    if (res == NULL || !translate) {
        return res;
    }
    return text_translate(res, out);
#undef AT
}

/* A str of the k characters of a kind (1 or 2) at s, with one beyond the
   next smaller kind or not (known, so that they aren't looked at again;
   2 byte characters are the kind's only then). */
static PyObject *
text_new(const char *s, Py_ssize_t k, int kind, int high)
{
    if (!high || (k == 1 && kind == PyUnicode_1BYTE_KIND)) {
        return (k == 1 ? PyUnicode_FromOrdinal((Py_UCS1)s[0])
                : _PyUnicode_FromASCII(s, k));
    }
    PyObject *text = PyUnicode_New(k, kind == PyUnicode_1BYTE_KIND ? 0xff
                                                                    : 0xffff);
    if (text != NULL) {
        memcpy(PyUnicode_DATA(text), s, k * kind);
    }
    return text;
}

/* chars[i:i+k], a line ending with "\r\n", with "\n" for it. */
static PyObject *
text_crlf(PyObject *chars, Py_ssize_t i, Py_ssize_t k)
{
    Py_UCS4 max = (PyUnicode_IS_ASCII(chars) ? 127
                   : _PyUnicode_FindMaxChar(chars, i, i + k - 2));
    PyObject *text = PyUnicode_New(k - 1, Py_MAX(max, (Py_UCS4)127));
    if (text != NULL) {
        _PyUnicode_FastCopyCharacters(text, 0, chars, i, k - 2);
        PyUnicode_WRITE(PyUnicode_KIND(text), PyUnicode_DATA(text), k - 2,
                        '\n');
    }
    return text;
}

/* For text_quick(): how many of the avail characters at s (cr the first
   "\r") translate to n, or -1 if they don't tell (a "\r" last) or have
   more "\r"s than crs (where they go) holds. */
#define QUICK_CRS 16
static Py_ssize_t
text_quick_crs(PyObject *chars, Py_ssize_t *cr_at, int kind, const char *s,
               Py_ssize_t avail, Py_ssize_t n, const char *cr,
               Py_ssize_t crs[QUICK_CRS], int *ncr)
{
    int shift = kind >> 1;
    Py_ssize_t i = 0, out = 0, cr_at0 = *cr_at;
    *ncr = 0;
    for (;;) {
        /* Up to the next "\r" (kept in the cache for the next call, but
           if this one doesn't move the position past those before it), or
           the rest of n. */
        Py_ssize_t run = n - out;
        if (cr != NULL) {
            run = Py_MIN(run, ((cr - s) >> shift) - i);
        }
        else if (i + run > avail) {
            break;
        }
        i += run;
        out += run;
        if (out == n) {
            return i;
        }
        if (i + 1 >= avail || *ncr == QUICK_CRS) {
            break;
        }
        crs[(*ncr)++] = i;
        i += 1 + (PyUnicode_READ(kind, s, i + 1) == '\n');
        if (++out == n) {
            return i;
        }
        cr = find_cr(chars, cr_at, kind, s + (i << shift),
                     s + (avail << shift));
    }
    *cr_at = cr_at0;
    return -1;
}

/* chars[ci:ci+k] translated to n characters, with "\r"s at crs[:ncr]
   (relative to ci), of at most max. */
static Py_ALWAYS_INLINE PyObject *
text_quick_translate(PyObject *chars, Py_ssize_t ci, Py_ssize_t k,
                     Py_ssize_t n, const Py_ssize_t *crs, int ncr,
                     Py_UCS4 max)
{
    PyObject *t = PyUnicode_New(n, max);
    if (t == NULL) {
        return NULL;
    }
    int kind = PyUnicode_KIND(chars);
    if (PyUnicode_KIND(t) != kind) {
        /* Narrower: copied by characters. */
        Py_DECREF(t);
        return text_translate(PyUnicode_Substring(chars, ci, ci + k), n);
    }
    const char *r = (const char *)PyUnicode_DATA(chars) + ci * kind;
    char *o = PyUnicode_DATA(t);
    Py_ssize_t from = 0;
    for (int j = 0; j < ncr; j++) {
        memcpy(o, r + from * kind, (crs[j] - from) * kind);
        o += (crs[j] - from) * kind;
        PyUnicode_WRITE(kind, o, 0, '\n');
        o += kind;
        from = crs[j] + 1;
        from += from < k && PyUnicode_READ(kind, r, from) == '\n';
    }
    memcpy(o, r + from * kind, (k - from) * kind);
    assert(o + (k - from) * kind == (char *)PyUnicode_DATA(t) + n * kind);
    return t;
}

/* The first step of text_read_impl() in the usual case: the decoded
   characters have all of the text, and it has no "\r" (that newlines
   would translate, or wait for), so that nothing but noting a "\n" is left
   of text_take()'s work.  Returns the text, or NULL, with an exception set
   or not (then text_read_impl() goes on as if this wasn't tried). */
static inline PyObject *
text_quick(textio *self, PyObject *buffer, Py_ssize_t n, int line)
{
    /* What is known of the characters: with the GIL, the cache, which
       other threads may change while this one waits to take the bytes;
       with free threading, the span (chars borrowed: alive until this
       thread waits, which only taking the bytes may do, and text is made
       first), whose position is swapped once the bytes are taken.  (The
       decoder's span, which only a race with reconfigure() could find, has
       key 0: no bytes are taken.)  The hints are written in place: they
       are from the position or before it. */
#ifdef Py_GIL_DISABLED
    tspan *sp = _Py_atomic_load_ptr_acquire(&self->span);
    if (sp == NULL) {
        return NULL;
    }
    uint64_t pos = _Py_atomic_load_uint64_relaxed(&sp->pos), ver = sp->ver;
    Py_ssize_t boff = (Py_ssize_t)(pos >> 32);
    Py_ssize_t ci = (Py_ssize_t)((pos >> 1) & 0x7fffffff);
    int skip_lf = (int)(pos & 1);
#  define C sp
#  define KOFF (sp->koff + boff)
#  define KBYTES (sp->kbytes - boff)
#else
    tcache *c = &self->cache;
    Py_ssize_t ci = c->ci;
    int skip_lf = c->skip_lf;
#  define C c
#  define KOFF (c->koff)
#  define KBYTES (c->kbytes)
#endif
    PyObject *chars = C->chars;
    PyObject *text = NULL;
    if (chars == NULL) {
        goto done;
    }
    int kind = PyUnicode_KIND(chars);
    int shift = kind >> 1;      /* log2(kind) */
    const char *base = _PyUnicode_COMPACT_DATA(chars);
    Py_ssize_t len = PyUnicode_GET_LENGTH(chars);
    const char *s = base + (ci << shift);
    Py_ssize_t k;
    int seen = 0, crlf = 0, ncr = 0;
    Py_ssize_t crs[QUICK_CRS];
    /* The "\r" past the text, kept only once its bytes are taken. */
    Py_ssize_t cr_at = -1;
    if (line) {
        const char *lf, *cr;
        if (n >= 0 || !self->readuniversal
            || (lf = find_char(kind, s, base + (len << shift), '\n')) == NULL)
        {
            goto done;
        }
        k = ((lf - s) >> shift) + 1;
        if ((cr = find_cr(chars, &C->cr_at, kind, s, lf)) == NULL) {
            seen = k == 1 && skip_lf ? 0 : SEEN_LF;
        }
        else if (cr + kind == lf) {
            /* Ends with its only "\r", in "\r\n". */
            seen = SEEN_CRLF;
            crlf = self->readtranslate;
        }
        else {
            goto done;
        }
    }
    else {
        k = n;
        if (n <= 0 || len - ci < n) {
            goto done;
        }
        if (self->readuniversal && !FT_ATOMIC_LOAD_UINT8_RELAXED(C->nl)) {
            text_note_newlines(self, chars, ci, skip_lf, &C->cr_at);
            FT_ATOMIC_STORE_UINT8_RELAXED(C->nl, 1);
        }
        const char *cr = (self->readuniversal
                          ? find_cr(chars, &C->cr_at, kind, s,
                                    s + (k << shift))
                          : NULL);
        if (cr != NULL) {
            /* Translated, n characters from more. */
            cr_at = FT_ATOMIC_LOAD_SSIZE_RELAXED(C->cr_at);
            if (!self->readtranslate || skip_lf
                || (k = text_quick_crs(chars, &cr_at, kind, s, len - ci, n,
                                       cr, crs, &ncr)) < 0)
            {
                goto done;
            }
            crlf = 1;
        }
    }
    /* The bytes, and whether a character is beyond the next smaller kind
       (-1: not known), from counting those that need more UTF-8 bytes:
       then the str is made knowing its kind. */
    Py_ssize_t b = k;
    int high = PyUnicode_IS_ASCII(chars) ? 0 : -1;
    if (high < 0 && kind == PyUnicode_1BYTE_KIND) {
        /* (Counted for the str with any codec.) */
        Py_ssize_t extra = utf8_extra_ucs1((const Py_UCS1 *)s, k);
        b += self->codec == CODEC_UTF8 ? extra : 0;
        high = extra != 0;
    }
    else if (high < 0 && self->codec == CODEC_UTF8) {
        if (kind == PyUnicode_2BYTE_KIND && !self->escapes) {
            b += utf8_extra_ucs2((const Py_UCS2 *)s, k, &high);
        }
        else {
            b = text_bytes(self, chars, KBYTES, ci, k);
        }
    }
    int known = high > 0 || (high == 0 && kind == PyUnicode_1BYTE_KIND);
    text = (crlf ? (line ? text_crlf(chars, ci, k)
                    : text_quick_translate(
                        chars, ci, k, n, crs, ncr,
                        !known ? _PyUnicode_FindMaxChar(chars, ci, ci + k)
                        : kind == PyUnicode_2BYTE_KIND ? 0xffff
                        : high ? 255 : 127))
            : known ? text_new(s, k, kind, high)
            : PyUnicode_Substring(chars, ci, ci + k));
    if (text == NULL) {
        goto done;
    }
    /* Taking the bytes finds out whether the characters are theirs. */
    Py_ssize_t koff = KOFF;
    if (_PyIONibbler_advance(buffer, C->key, koff, b) != 1) {
        Py_CLEAR(text);
        goto done;
    }
#ifdef Py_GIL_DISABLED
    /* Unless the span changed meanwhile. */
    if (_Py_atomic_load_ptr_acquire(&self->span) == sp && sp->ver == ver
        && _Py_atomic_compare_exchange_uint64(&sp->pos, &pos,
                                              SPAN_POS(ci + k, boff + b, 0))
        && cr_at >= 0)
    {
        _Py_atomic_store_ssize_relaxed(&sp->cr_at, cr_at);
    }
#else
    /* Unless another thread decoded meanwhile. */
    if (c->chars == chars && c->koff == koff) {
        c->ci = ci + k;
        c->koff = koff + b;
        c->kbytes -= b;
        c->skip_lf = 0;
        if (cr_at >= 0) {
            c->cr_at = cr_at;
        }
    }
#endif
#undef C
#undef KOFF
#undef KBYTES
    FT_ATOMIC_STORE_UINT8_RELAXED(self->decoded, 1);
    if ((FT_ATOMIC_LOAD_UINT8_RELAXED(self->seennl) & seen) != seen) {
        SEENNL_ADD(self, seen);
    }
done:
    return text;
}

/* read() of everything, with a native codec: the buffer's read() (which
   needn't gather what it reads in a block, as peeking would), decoded at
   once.  The characters decoded but not taken yet came from bytes still
   in the buffer, so the cache is dropped. */
static PyObject *
text_read_all(textio *self, PyObject *buffer)
{
    PyObject *b = PyObject_CallMethodNoArgs(buffer, &_Py_ID(read));
    if (b == NULL) {
        return NULL;
    }
    if (b == Py_None) {
        Py_DECREF(b);
        _PyIO_set_read_blocking_error();
        return NULL;
    }
    if (!PyBytes_Check(b)) {
        PyErr_Format(PyExc_TypeError, "underlying read() should have "
                     "returned a bytes object, not '%.200s'",
                     Py_TYPE(b)->tp_name);
        Py_DECREF(b);
        return NULL;
    }
    tcache copy;
    tcache *c = cache_get(self, &copy);
    tcache t = {.cr_at = -1, .skip_lf = c->skip_lf};
    cache_clear(c);
    cache_put(self, c);
    cache_release(c);
    Py_ssize_t used;
    t.chars = native_decode(self, PyBytes_AS_STRING(b), PyBytes_GET_SIZE(b),
                            1, &used);
    Py_DECREF(b);
    if (t.chars == NULL) {
        return NULL;
    }
    store st = {.buffer = buffer, .c = &t};
    Py_ssize_t avail = PyUnicode_GET_LENGTH(t.chars), scanned = 0, k = 0;
    int found;
    PyObject *text = (avail == 0 ? NULL
                      : text_take(self, &st, avail, -1, 0, 1, &scanned, &k,
                                  &found));
    Py_DECREF(t.chars);
    if (text == NULL && !PyErr_Occurred()) {
        text = Py_GetConstant(Py_CONSTANT_EMPTY_STR);
    }
    return text;
}

/* read(n) (n < 0: all), or with line, readline(n); with lockfree, without
   the critical section (*retry: do it with it after all). */
static PyObject *
text_read_impl(textio *self, Py_ssize_t n, int line, int lockfree,
               int *retry)
{
    /* With native codecs the buffer checks that it is open when the bytes
       are looked at or taken. */
    int peeks = lockfree || (textio_exact(self) && self->nib_ok
                             && self->codec != CODEC_DECODER);
    PyObject *buffer = peeks ? textio_buffer(self) : textio_ready(self);
    if (buffer == NULL) {
        return NULL;
    }
    if (!lockfree && peeks && self->nib && self->codec != CODEC_DECODER
        && n != 0)
    {
        PyObject *text = text_quick(self, buffer, n, line);
        if (text != NULL || PyErr_Occurred()) {
            Py_DECREF(buffer);
            return text;
        }
    }
    store st = {.buffer = buffer, .all = n < 0 && !line,
                .lockfree = lockfree};
    if (!self->readable) {
        Py_DECREF(st.buffer);
        return textio_unsupported(self, "not readable");
    }
    if (peeks && n == 0) {
        /* No peek or commit to find whether it is closed. */
        Py_SETREF(st.buffer, textio_ready(self));
        if (st.buffer == NULL) {
            return NULL;
        }
    }
    if (st.all && peeks && self->codec != CODEC_DECODER
        && self->rbuf == NULL)
    {
        PyObject *text = text_read_all(self, st.buffer);
        Py_DECREF(st.buffer);
        return text;
    }
    st.c = cache_get(self, STORE_COPY(&st));
    /* The text so far: res, then in writer once there are two pieces. */
    PyObject *res = NULL;
    _PyUnicodeWriter writer;
    int pieces = 0;
    /* have: characters at the position looked at without a decision. */
    Py_ssize_t got = 0, have = 0, scanned = 0;
    int taken = 0;
    while (n != got) {
        Py_ssize_t avail = text_avail(self, &st);
        if (avail > have && !st.all) {
            st.at_end = text_at_end(self, &st, avail);
        }
        else {
            uint64_t key = st.c->key;
            Py_ssize_t koff = st.c->koff, ci = st.c->ci;
            if ((avail = text_more(self, &st, have)) < 0) {
                goto error;
            }
            if ((have || scanned)
                && (st.c->key != key || st.c->koff != koff || st.c->ci != ci))
            {
                /* Other characters (another thread read meanwhile, or
                   decoded again): look at them afresh. */
                have = scanned = 0;
                continue;
            }
        }
        Py_ssize_t k = 0;
        int found = 0;
        PyObject *text = NULL;
        if (avail > 0) {
            text = text_take(self, &st, avail, n < 0 ? -1 : n - got, line,
                             st.at_end, &scanned, &k, &found);
            if (text == NULL && PyErr_Occurred()) {
                goto error;
            }
        }
        if (k == 0 && avail > have) {
            /* Undecided ("\r" last, or no end of line yet): more. */
            have = avail;
            continue;
        }
        if (k == 0 && avail > 0 && line
            && (st.status == _PyIO_NIBBLER_FULL
                || (st.status == _PyIO_NIBBLER_BLOCKED
                    && (taken || avail >= READLINE_KEEP_MAX
                                          * FT_ATOMIC_LOAD_SSIZE_RELAXED(
                                              self->chunk_size)))))
        {
            /* The buffer can't hold more of the line, or it is too long to
               keep for the next call: take it so far, but a last "\r"
               (that may begin a "\r\n", universal or the newline: the
               buffer holds 8 bytes or more, so that there are others). */
            k = avail - ((self->readuniversal
                          || PyUnicode_GET_LENGTH(self->readnl) == 2)
                         && avail > 1
                         && PyUnicode_READ_CHAR(st.c->chars,
                                                st.c->ci + avail - 1) == '\r');
            text = PyUnicode_Substring(st.c->chars, st.c->ci, st.c->ci + k);
            if (text == NULL) {
                goto error;
            }
            found = st.status == _PyIO_NIBBLER_BLOCKED;
            taken = 1;
        }
        if (k == 0) {
            /* Nothing more for now: at the end, or it would block. */
            if (st.status == _PyIO_NIBBLER_BLOCKED && got == 0) {
                _PyIO_set_read_blocking_error();
                goto error;
            }
            break;
        }
        int r = text_commit(self, &st, k);
        if (r <= 0) {
            Py_DECREF(text);
            if (r < 0) {
                goto error;
            }
            /* Another thread read meanwhile: again from where it left. */
            have = scanned = 0;
            continue;
        }
        got += PyUnicode_GET_LENGTH(text);
        if (pieces++ == 0) {
            res = text;
        }
        else {
            if (pieces == 2) {
                _PyUnicodeWriter_Init(&writer);
                r = _PyUnicodeWriter_WriteStr(&writer, res);
                Py_CLEAR(res);
            }
            if (r >= 0) {
                r = _PyUnicodeWriter_WriteStr(&writer, text);
            }
            Py_DECREF(text);
            if (r < 0) {
                goto error;
            }
        }
        if (found) {
            break;
        }
        have = scanned = 0;
    }
    store_release(&st);
    Py_DECREF(st.buffer);
    cache_release(st.c);
    return (pieces > 1 ? _PyUnicodeWriter_Finish(&writer)
            : res ? res : Py_GetConstant(Py_CONSTANT_EMPTY_STR));

error:
    store_release(&st);
    Py_DECREF(st.buffer);
    cache_release(st.c);
    Py_XDECREF(res);
    if (pieces > 1) {
        _PyUnicodeWriter_Dealloc(&writer);
    }
    if (st.retry) {
        *retry = 1;
    }
    return NULL;
}

/* text_read() past text_quick(). */
Py_NO_INLINE static PyObject *
text_read_more(textio *self, Py_ssize_t n, int line, int lockfree)
{
    PyObject *res;
    if (lockfree) {
        int retry = 0;
        res = text_read_impl(self, n, line, 1, &retry);
        if (!retry) {
            return res;
        }
    }
    Py_BEGIN_CRITICAL_SECTION(self);
    res = text_read_impl(self, n, line, 0, NULL);
    Py_END_CRITICAL_SECTION();
    return res;
}

static inline PyObject *
text_read(textio *self, Py_ssize_t n, int line)
{
    int lockfree = FT_ATOMIC_LOAD_UINT8_RELAXED(self->lockfree);
    if (lockfree) {
        /* (Without it, text_read_impl() raises.)  Borrowed: nothing
           text_quick() does before it is done with the buffer lets other
           code run, or this thread wait (with free threading, a buffer
           swapped out is freed only once it has). */
        PyObject *buffer = (n != 0 && FT_ATOMIC_LOAD_UINT8_RELAXED(self->ok)
                            ? FT_ATOMIC_LOAD_PTR_ACQUIRE(self->buffer)
                            : NULL);
        if (buffer != NULL) {
            PyObject *res = text_quick(self, buffer, n, line);
            if (res != NULL || PyErr_Occurred()) {
                return res;
            }
        }
    }
    return text_read_more(self, n, line, lockfree);
}

/*
 * Writing
 */

/* UTF-8 text not ASCII, of 1 or 2 byte characters but no surrogates, into
   room reserved in the buffer, without a bytes object.  Returns 0, or
   _PyIO_NIBBLER_NO (nothing done). */
static int
utf8_write_direct(PyObject *buffer, PyObject *text)
{
    int kind = PyUnicode_KIND(text);
    const void *data = PyUnicode_DATA(text);
    Py_ssize_t n = PyUnicode_GET_LENGTH(text);
    if (kind == PyUnicode_4BYTE_KIND) {
        return _PyIO_NIBBLER_NO;
    }
    Py_ssize_t size = n;
    for (Py_ssize_t i = 0; i < n; i++) {
        Py_UCS4 c = PyUnicode_READ(kind, data, i);
        if (Py_UNICODE_IS_SURROGATE(c)) {
            return _PyIO_NIBBLER_NO;
        }
        size += (c >= 0x80) + (c >= 0x800);
    }
    void *end;
    char *p = _PyIONibbler_reserve(buffer, size, &end);
    if (p == NULL) {
        return _PyIO_NIBBLER_NO;
    }
    for (Py_ssize_t i = 0; i < n; i++) {
        Py_UCS4 c = PyUnicode_READ(kind, data, i);
        if (c < 0x80) {
            *p++ = (char)c;
        }
        else if (c < 0x800) {
            *p++ = (char)(0xc0 | (c >> 6));
            *p++ = (char)(0x80 | (c & 0x3f));
        }
        else {
            *p++ = (char)(0xe0 | (c >> 12));
            *p++ = (char)(0x80 | ((c >> 6) & 0x3f));
            *p++ = (char)(0x80 | (c & 0x3f));
        }
    }
    _PyIONibbler_commit(end, size);
    return 0;
}

/* Encode and store text.  The fast encoders hold no state; the codec's
   encoder must be given final=True at the end (gh-79792). */
static int
text_write(textio *self, PyObject *buffer, PyObject *text)
{
    PyObject *b;
    int enc = self->enc;
    if (enc != CODEC_DECODER
        && (PyUnicode_IS_ASCII(text)
            || (enc == CODEC_LATIN1
                && PyUnicode_KIND(text) == PyUnicode_1BYTE_KIND)))
    {
        /* The str's data is its encoding. */
        return store_write(self, buffer, text, PyUnicode_DATA(text),
                           PyUnicode_GET_LENGTH(text));
    }
    if (enc == CODEC_UTF8 && self->nib) {
        int r = utf8_write_direct(buffer, text);
        if (r != _PyIO_NIBBLER_NO) {
            return r;
        }
    }
    const char *errors = (enc == CODEC_DECODER || enc == CODEC_CHARMAP ? NULL
                          : PyUnicode_AsUTF8(self->errors));
    if (enc == CODEC_UTF8) {
        b = _PyUnicode_AsUTF8String(text, errors);
    }
    else if (enc == CODEC_LATIN1) {
        b = _PyUnicode_AsLatin1String(text, errors);
    }
    else if (enc == CODEC_ASCII) {
        b = _PyUnicode_AsASCIIString(text, errors);
    }
    else {
        self->encoding_start_of_stream = 0;
        b = PyObject_CallMethodOneArg(self->encoder, &_Py_ID(encode), text);
        if (b != NULL && !PyBytes_Check(b)) {
            PyErr_Format(PyExc_TypeError,
                         "encoder should return a bytes object, not '%.200s'",
                         Py_TYPE(b)->tp_name);
            Py_CLEAR(b);
        }
        self->encoder_used |= b != NULL;
    }
    if (b == NULL) {
        return -1;
    }
    int r = store_write(self, buffer, b, PyBytes_AS_STRING(b),
                        PyBytes_GET_SIZE(b));
    Py_DECREF(b);
    return r;
}

/* Give the codec's encoder the end of the text, and store what it still
   held (gh-79792). */
static int
text_finish_encoder(textio *self, PyObject *buffer)
{
    if (!self->encoder_used) {
        return 0;
    }
    self->encoder_used = 0;
    PyObject *b = PyObject_CallMethodObjArgs(
        self->encoder, &_Py_ID(encode), &_Py_STR(empty), Py_True, NULL);
    if (b != NULL && !PyBytes_Check(b)) {
        PyErr_Format(PyExc_TypeError,
                     "encoder should return a bytes object, not '%.200s'",
                     Py_TYPE(b)->tp_name);
        Py_CLEAR(b);
    }
    if (b == NULL) {
        return -1;
    }
    int r = store_write(self, buffer, b, PyBytes_AS_STRING(b),
                        PyBytes_GET_SIZE(b));
    Py_DECREF(b);
    return r;
}

/* The decoder's characters not returned yet came from bytes taken already:
   move the buffer back to the text position (past characters a byte
   decoded to as a group, if it is among them). */
static int
decoder_sync(textio *self, PyObject *buffer)
{
    Py_ssize_t off, ci;
    int flags;
    (void)cache_chars(self, &ci);
    if (!self->seekable || decoder_offset(self, ci, &off, &flags) < 0) {
        textio_drop_chars(self);
        return self->seekable ? -1 : 0;
    }
    PyObject *pos = store_tell(self, buffer);
    Py_off_t p = pos ? PyLong_AsOff_t(pos) : -1;
    Py_XDECREF(pos);
    if (p == -1 && PyErr_Occurred()) {
        return -1;
    }
    p += off;
    textio_drop_chars(self);
    Py_CLEAR(self->rbuf);
    PyObject *res = _PyObject_CallMethod(buffer, &_Py_ID(seek), "(O&)",
                                         PyLong_FromOff_t, p);
    Py_XDECREF(res);
    self->flags = flags;
    return res == NULL ? -1 : 0;
}

/* Before a write, truncate() or detach(): make the buffer's position the
   text position, dropping what was read ahead. */
static int
text_sync(textio *self, PyObject *buffer)
{
    FT_ATOMIC_STORE_UINT8_RELAXED(self->decoded, 0);
    Py_ssize_t ci;
    if (self->codec == CODEC_DECODER && cache_chars(self, &ci) != NULL) {
        if (decoder_sync(self, buffer) < 0) {
            return -1;
        }
    }
    else {
        textio_drop_chars(self);
    }
    return self->rbuf ? store_rewind(self, buffer) : 0;
}

static PyObject *
text_write_call(textio *self, PyObject *text)
{
    /* Over the buffer as the store, which checks that it is open when the
       bytes are stored, if any (and then there is nothing to sync but the
       cache: see text_sync()). */
    int stores = (self->nib && self->codec != CODEC_DECODER
                  && self->encoder != NULL && PyUnicode_GET_LENGTH(text) > 0
                  && textio_exact(self));
    PyObject *buffer = stores ? textio_buffer(self) : textio_ready(self);
    if (buffer == NULL) {
        return NULL;
    }
    if (self->encoder == NULL) {
        Py_DECREF(buffer);
        return textio_unsupported(self, "not writable");
    }
    Py_ssize_t textlen = PyUnicode_GET_LENGTH(text);
    int line_buffering = FT_ATOMIC_LOAD_UINT8_RELAXED(self->line_buffering);
    int haslf = ((self->writetranslate && self->writenl != NULL)
                 || line_buffering)
                && PyUnicode_FindChar(text, '\n', 0, textlen, 1) != -1;
    int needflush = line_buffering
                    && (haslf || PyUnicode_FindChar(text, '\r', 0, textlen,
                                                    1) != -1);
    Py_INCREF(text);
    if (haslf && self->writetranslate && self->writenl != NULL) {
        Py_SETREF(text, _PyObject_CallMethod(text, &_Py_ID(replace), "ss",
                                             "\n", self->writenl));
    }
    int r = (text == NULL || ((self->rbuf
                               || FT_ATOMIC_LOAD_UINT8_RELAXED(self->decoded))
                              && text_sync(self, buffer) < 0)
             ? -1 : text_write(self, buffer, text));
    Py_XDECREF(text);
    if (r == 0 && needflush) {
        r = _PyFile_Flush(buffer);
    }
    Py_DECREF(buffer);
    return r < 0 ? NULL : PyLong_FromSsize_t(textlen);
}

/*[clinic input]
_io.TextIOWrapper.write
    text: unicode
    /
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_write_impl(textio *self, PyObject *text)
/*[clinic end generated code: output=d2deb0d50771fcec input=fdf19153584a0e44]*/
{
    if (FT_ATOMIC_LOAD_UINT8_RELAXED(self->lockfree)) {
        return text_write_call(self, text);
    }
    PyObject *res;
    Py_BEGIN_CRITICAL_SECTION(self);
    res = text_write_call(self, text);
    Py_END_CRITICAL_SECTION();
    return res;
}

/*
 * Reading
 */

/*[clinic input]
_io.TextIOWrapper.read
    size as n: Py_ssize_t(accept={int, NoneType}) = -1
    /
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_read_impl(textio *self, Py_ssize_t n)
/*[clinic end generated code: output=7e651ce6cc6a25a6 input=123eecbfe214aeb8]*/
{
    return text_read(self, n < 0 ? -1 : n, 0);
}

/*[clinic input]
_io.TextIOWrapper.readline
    size: Py_ssize_t = -1
    /
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_readline_impl(textio *self, Py_ssize_t size)
/*[clinic end generated code: output=344afa98804e8b25 input=56c7172483b36db6]*/
{
    return text_read(self, size < 0 ? -1 : size, 1);
}

static PyObject *
textiowrapper_iternext(PyObject *op)
{
    textio *self = textio_CAST(op);
    PyObject *line;
    if (textio_exact(self)) {
        line = text_read(self, -1, 1);
    }
    else {
        line = PyObject_CallMethodNoArgs(op, &_Py_ID(readline));
        if (line != NULL && !PyUnicode_Check(line)) {
            PyErr_Format(PyExc_OSError,
                         "readline() should have returned a str object, "
                         "not '%.200s'", Py_TYPE(line)->tp_name);
            Py_CLEAR(line);
        }
    }
    if (line != NULL && PyUnicode_GET_LENGTH(line) == 0) {
        /* EOF */
        Py_CLEAR(line);
    }
    return line;
}

/*
 * Seek and tell
 */

/* A cookie: the position of the start of the decoder's characters (or of
   the text), the decoder's flags there and how many characters to skip.
   Laid out as _io's (bytes_to_feed and need_eof, unused, are 0). */
typedef struct {
    int64_t start_pos;
    int32_t dec_flags;
    int32_t bytes_to_feed;
    int32_t chars_to_skip;
    char need_eof;
} cookie_type;

#define COOKIE_BUF_LEN 21

static PyObject *
cookie_build(Py_off_t pos, int flags, Py_ssize_t skip)
{
    unsigned char b[COOKIE_BUF_LEN] = {0};
    uint64_t f[3] = {(uint64_t)pos, (uint32_t)flags, 0};
    for (int i = 0; i < 8; i++) {
        b[i] = (unsigned char)(f[0] >> (8 * i));
    }
    for (int i = 0; i < 4; i++) {
        b[8 + i] = (unsigned char)(f[1] >> (8 * i));
        b[16 + i] = (unsigned char)((uint32_t)skip >> (8 * i));
    }
    return _PyLong_FromByteArray(b, sizeof(b), 1, 0);
}

static int
cookie_parse(cookie_type *c, PyObject *cookie)
{
    unsigned char b[COOKIE_BUF_LEN];
    PyObject *v = PyNumber_Long(cookie);
    if (v == NULL) {
        return -1;
    }
    int r = _PyLong_AsByteArray((PyLongObject *)v, b, sizeof(b), 1, 0, 1);
    Py_DECREF(v);
    if (r < 0) {
        return -1;
    }
    uint64_t pos = 0;
    uint32_t f[3] = {0, 0, 0};
    for (int i = 0; i < 8; i++) {
        pos |= (uint64_t)b[i] << (8 * i);
    }
    for (int j = 0; j < 3; j++) {
        for (int i = 0; i < 4; i++) {
            f[j] |= (uint32_t)b[8 + 4 * j + i] << (8 * i);
        }
    }
    *c = (cookie_type){(int64_t)pos, (int32_t)f[0], (int32_t)f[1],
                       (int32_t)f[2], (char)b[20]};
    return 0;
}

static PyObject *text_tell(textio *self);

/*[clinic input]
_io.TextIOWrapper.tell

Return the stream position as an opaque number.

The return value of tell() can be given as input to seek(), to
restore a previous stream position.
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_tell_impl(textio *self)
/*[clinic end generated code: output=4f168c08bf34ad5f input=006277a23840acfc]*/
{
    /* With lockfree, the buffer's tell() is all there is to it. */
    if (FT_ATOMIC_LOAD_UINT8_RELAXED(self->lockfree)) {
        return text_tell(self);
    }
    PyObject *res;
    Py_BEGIN_CRITICAL_SECTION(self);
    res = text_tell(self);
    Py_END_CRITICAL_SECTION();
    return res;
}

static PyObject *
text_tell(textio *self)
{
    /* Over other buffers, flush first, as _io's does (their tell() might
       not count what they hold). */
    if (!self->nib_ok && FT_ATOMIC_LOAD_UINT8_RELAXED(self->ok)
        && FT_ATOMIC_LOAD_PTR_RELAXED(self->buffer) != NULL
        && _PyFile_Flush((PyObject *)self) < 0)
    {
        return NULL;
    }
    PyObject *buffer = textio_ready(self);
    if (buffer == NULL) {
        return NULL;
    }
    PyObject *pos = NULL;
    if (!self->seekable) {
        textio_unsupported(self, "underlying stream is not seekable");
        goto done;
    }
    pos = store_tell(self, buffer);
    if (pos == NULL || self->decoder == NULL) {
        goto done;
    }
    Py_off_t p = PyLong_AsOff_t(pos);
    if (p == -1 && PyErr_Occurred()) {
        Py_CLEAR(pos);
        goto done;
    }
    Py_ssize_t ci;
    PyObject *chars = cache_chars(self, &ci);
    int flags = self->flags;
    if (chars != NULL && PyUnicode_GET_LENGTH(chars) > ci) {
        /* The byte position of the text position, if there is one; else
           where the characters were decoded from, and how many to skip. */
        Py_ssize_t off, start = -PyBytes_GET_SIZE(self->dspan);
        int dflags = self->dflags;
        int r = decoder_offset(self, ci, &off, &flags);
        if (r < 0) {
            Py_CLEAR(pos);
            goto done;
        }
        Py_SETREF(pos, r > 0 ? cookie_build(p + off, flags, 0)
                             : cookie_build(p + start, dflags, ci));
    }
    else if (p != 0 && flags != FLAGS_FRESH && flags != 0) {
        Py_SETREF(pos, cookie_build(p, flags, 0));
    }
done:
    Py_DECREF(buffer);
    return pos;
}

/* Reset the encoder to the stream's start, or past it (no BOM). */
static int
text_encoder_reset(textio *self, int start)
{
    self->encoding_start_of_stream = start;
    if (self->encoder == NULL) {
        return 0;
    }
    PyObject *res = (start
                     ? PyObject_CallMethodNoArgs(self->encoder, &_Py_ID(reset))
                     : PyObject_CallMethodOneArg(self->encoder,
                                                 &_Py_ID(setstate),
                                                 _PyLong_GetZero()));
    Py_XDECREF(res);
    return res == NULL ? -1 : 0;
}

/* The decoder at a position: reset at the stream's start (pos and flags
   0), else with flags. */
static int
text_decoder_reset(textio *self, Py_off_t pos, int flags)
{
    if (self->decoder == NULL) {
        return 0;
    }
    self->flags = pos == 0 && flags == 0 ? FLAGS_FRESH : flags;
    return decoder_setstate(self, self->flags);
}

/* Drop what was read: the position moves. */
static void
text_drop_reads(textio *self)
{
    textio_drop_chars(self);
    Py_CLEAR(self->rbuf);
    self->rpos = 0;
    FT_ATOMIC_STORE_UINT8_RELAXED(self->decoded, 0);
}

/* Decode again the n characters that the decoder's flags at the position
   are followed by (before newlines are translated). */
static int
text_skip(textio *self, PyObject *buffer, Py_ssize_t n)
{
    store st = {.buffer = buffer};
    st.c = cache_get(self, STORE_COPY(&st));
    while (n > 0) {
        Py_ssize_t avail = text_more(self, &st, 0);
        if (avail <= 0) {
            if (avail == 0) {
                PyErr_SetString(PyExc_OSError,
                                "can't restore logical file position");
            }
            break;
        }
        int r = text_commit(self, &st, Py_MIN(n, avail));
        if (r < 0) {
            break;
        }
        n -= r ? Py_MIN(n, avail) : 0;
    }
    cache_release(st.c);
    store_release(&st);
    return n > 0 ? -1 : 0;
}

/*[clinic input]
@critical_section
_io.TextIOWrapper.seek
    cookie as cookieObj: object
      Zero or an opaque number returned by tell().
    whence: int(c_default='0') = os.SEEK_SET
      The relative position to seek from.
    /

Set the stream position, and return the new stream position.

Four operations are supported, given by the following argument
combinations:

- seek(0, SEEK_SET): Rewind to the start of the stream.
- seek(cookie, SEEK_SET): Restore a previous position;
  'cookie' must be a number returned by tell().
- seek(0, SEEK_END): Fast-forward to the end of the stream.
- seek(0, SEEK_CUR): Leave the current stream position unchanged.

Any other argument combinations are invalid,
and may raise exceptions.
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_seek_impl(textio *self, PyObject *cookieObj, int whence)
/*[clinic end generated code: output=0a15679764e2d04d input=4bea78698be23d7e]*/
{
    PyObject *buffer = textio_ready(self);
    if (buffer == NULL) {
        return NULL;
    }
    PyObject *res = NULL;
    Py_INCREF(cookieObj);
    if (!self->seekable) {
        textio_unsupported(self, "underlying stream is not seekable");
        goto done;
    }
    int zero = (whence == SEEK_CUR || whence == SEEK_END
                ? PyObject_RichCompareBool(cookieObj, _PyLong_GetZero(), Py_EQ)
                : 1);
    if (zero < 0) {
        goto done;
    }
    if (!zero) {
        textio_unsupported(self, whence == SEEK_CUR
                           ? "can't do nonzero cur-relative seeks"
                           : "can't do nonzero end-relative seeks");
        goto done;
    }
    if (whence == SEEK_CUR) {
        /* Sync the buffer with the current position. */
        Py_SETREF(cookieObj, text_tell(self));
        if (cookieObj == NULL) {
            goto done;
        }
    }
    else if (whence == SEEK_END) {
        if (_PyFile_Flush((PyObject *)self) < 0) {
            goto done;
        }
        text_drop_reads(self);
        res = _PyObject_CallMethod(buffer, &_Py_ID(seek), "ii", 0, 2);
        Py_off_t pos = res ? PyLong_AsOff_t(res) : -1;
        if (pos == -1 && PyErr_Occurred()) {
            Py_CLEAR(res);
        }
        else if (text_decoder_reset(self, 0, 0) < 0
                 || text_encoder_reset(self, pos == 0) < 0)
        {
            Py_CLEAR(res);
        }
        goto done;
    }
    else if (whence != SEEK_SET) {
        PyErr_Format(PyExc_ValueError,
                     "invalid whence (%d, should be %d, %d or %d)", whence,
                     SEEK_SET, SEEK_CUR, SEEK_END);
        goto done;
    }
    int neg = PyObject_RichCompareBool(cookieObj, _PyLong_GetZero(), Py_LT);
    if (neg) {
        if (neg > 0) {
            PyErr_Format(PyExc_ValueError, "negative seek position %R",
                         cookieObj);
        }
        goto done;
    }
    cookie_type c;
    if (cookie_parse(&c, cookieObj) < 0) {
        goto done;
    }
    /* gh-91112: a cookie tell() can't have returned is an error, not
       another position. */
    if (c.start_pos < 0 || c.chars_to_skip < 0 || c.bytes_to_feed < 0
        || (!self->readable && (c.dec_flags || c.bytes_to_feed
                                || c.chars_to_skip || c.need_eof)))
    {
        PyErr_SetString(PyExc_OSError, "can't restore logical file position");
        goto done;
    }
    if (_PyFile_Flush((PyObject *)self) < 0) {
        goto done;
    }
    text_drop_reads(self);
    res = _PyObject_CallMethod(buffer, &_Py_ID(seek), "(O&)",
                               PyLong_FromOff_t, (Py_off_t)c.start_pos);
    if (res == NULL) {
        goto done;
    }
    Py_CLEAR(res);
    int start = c.start_pos == 0 && c.dec_flags == 0;
    if (text_decoder_reset(self, c.start_pos, c.dec_flags) < 0
        || text_encoder_reset(self, start) < 0)
    {
        goto done;
    }
    if (c.chars_to_skip > 0 && text_skip(self, buffer, c.chars_to_skip) < 0) {
        goto done;
    }
    res = Py_NewRef(cookieObj);
done:
    Py_DECREF(cookieObj);
    Py_DECREF(buffer);
    return res;
}

/*[clinic input]
@critical_section
_io.TextIOWrapper.truncate
    pos: object = None
    /
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_truncate_impl(textio *self, PyObject *pos)
/*[clinic end generated code: output=90ec2afb9bb7745f input=8bddb320834c93ee]*/
{
    PyObject *buffer = textio_buffer(self);
    if (buffer == NULL) {
        return NULL;
    }
    /* At the text position (gh-70346): pos is a byte count, not a tell()
       cookie. */
    PyObject *res = NULL;
    if (text_sync(self, buffer) == 0
        && _PyFile_Flush((PyObject *)self) == 0)
    {
        res = PyObject_CallMethodOneArg(buffer, &_Py_ID(truncate), pos);
    }
    Py_DECREF(buffer);
    return res;
}

/*
 * Other methods
 */

/*[clinic input]
_io.TextIOWrapper.flush
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_flush_impl(textio *self)
/*[clinic end generated code: output=59de9165f9c2e4d2 input=928c60590694ab85]*/
{
    PyObject *buffer = textio_ready(self);
    if (buffer == NULL) {
        return NULL;
    }
    PyObject *res = PyObject_CallMethodNoArgs(buffer, &_Py_ID(flush));
    Py_DECREF(buffer);
    return res;
}

/* close() of the buffer would write out its pending data again after a
   flush that raised exc: drop it with the buffer's _discard_writes() if
   it has one, and warn that it was lost (gh-83973, gh-55589).  Steals exc
   and returns the exception to raise. */
static PyObject *
text_discard_writes(PyObject *buffer, PyObject *exc)
{
    PyObject *meth, *res = NULL;
    if (PyObject_GetOptionalAttrString(buffer, "_discard_writes", &meth) > 0) {
        res = PyObject_CallNoArgs(meth);
        Py_DECREF(meth);
    }
    Py_ssize_t n = res != NULL ? PyLong_AsSsize_t(res) : 0;
    Py_XDECREF(res);
    if (PyErr_Occurred()) {
        PyErr_Clear();
    }
    else if (n > 0) {
        int would_block = PyErr_GivenExceptionMatches(exc,
                                                      PyExc_BlockingIOError);
        PyErr_SetRaisedException(exc);
        _PyIO_warn_discarded(n, would_block);
        exc = PyErr_GetRaisedException();
    }
    return exc;
}

static PyObject *_io_TextIOWrapper_closed_get_impl(textio *self);

/*[clinic input]
@critical_section
_io.TextIOWrapper.close
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_close_impl(textio *self)
/*[clinic end generated code: output=056ccf8b4876e4f4 input=8e12d7079d5ac5c1]*/
{
    PyObject *buffer = textio_buffer(self);
    if (buffer == NULL) {
        return NULL;
    }
    PyObject *res = _io_TextIOWrapper_closed_get_impl(self);
    int r = res ? PyObject_IsTrue(res) : -1;
    Py_XDECREF(res);
    if (r != 0 || FT_ATOMIC_LOAD_PTR_RELAXED(self->buffer) == NULL) {
        Py_DECREF(buffer);
        return r < 0 ? NULL : Py_None;
    }
    if (self->finalizing) {
        res = PyObject_CallMethodOneArg(buffer, &_Py_ID(_dealloc_warn),
                                        (PyObject *)self);
        if (res == NULL) {
            PyErr_Clear();
        }
        Py_XDECREF(res);
    }
    PyObject *exc = NULL;
    if (text_finish_encoder(self, buffer) < 0) {
        exc = PyErr_GetRaisedException();
    }
    else if (_PyFile_Flush((PyObject *)self) < 0) {
        exc = text_discard_writes(buffer, PyErr_GetRaisedException());
    }
    text_drop_reads(self);
    res = PyObject_CallMethodNoArgs(buffer, &_Py_ID(close));
    Py_DECREF(buffer);
    if (exc != NULL) {
        _PyErr_ChainExceptions1(exc);
        Py_CLEAR(res);
    }
    return res;
}

/*[clinic input]
@critical_section
_io.TextIOWrapper.detach
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_detach_impl(textio *self)
/*[clinic end generated code: output=7ba3715cd032d5f2 input=c908a3b4ef203b0f]*/
{
    PyObject *buffer = textio_buffer(self);
    if (buffer == NULL) {
        return NULL;
    }
    if ((self->encoder_used && text_finish_encoder(self, buffer) < 0)
        || _PyFile_Flush((PyObject *)self) < 0
        || text_sync(self, buffer) < 0)
    {
        Py_DECREF(buffer);
        return NULL;
    }
    /* Something called meanwhile may have detached it. */
    if (FT_ATOMIC_LOAD_PTR_RELAXED(self->buffer) == NULL) {
        Py_DECREF(buffer);
        return textio_buffer(self);
    }
    text_drop_reads(self);
    FT_ATOMIC_STORE_UINT8_RELAXED(self->detached, 1);
    text_swap(&self->buffer, NULL);
    return buffer;
}

/*[clinic input]
_io.TextIOWrapper.fileno
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_fileno_impl(textio *self)
/*[clinic end generated code: output=21490a4c3da13e6c input=c488ca83d0069f9b]*/
{
    return textio_call(self, &_Py_ID(fileno), NULL);
}

/*[clinic input]
_io.TextIOWrapper.seekable
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_seekable_impl(textio *self)
/*[clinic end generated code: output=ab223dbbcffc0f00 input=8b005ca06e1fca13]*/
{
    return textio_call(self, &_Py_ID(seekable), NULL);
}

/*[clinic input]
_io.TextIOWrapper.readable
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_readable_impl(textio *self)
/*[clinic end generated code: output=72ff7ba289a8a91b input=0704ea7e01b0d3eb]*/
{
    return textio_call(self, &_Py_ID(readable), NULL);
}

/*[clinic input]
_io.TextIOWrapper.writable
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_writable_impl(textio *self)
/*[clinic end generated code: output=a728c71790d03200 input=c41740bc9d8636e8]*/
{
    return textio_call(self, &_Py_ID(writable), NULL);
}

/*[clinic input]
_io.TextIOWrapper.isatty
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_isatty_impl(textio *self)
/*[clinic end generated code: output=12be1a35bace882e input=fb68d9f2c99bbfff]*/
{
    return textio_call(self, &_Py_ID(isatty), NULL);
}

/*[clinic input]
@getter
_io.TextIOWrapper.name
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_name_get_impl(textio *self)
/*[clinic end generated code: output=8c2f1d6d8756af40 input=1459cfc515493c6b]*/
{
    PyObject *buffer = textio_buffer(self);
    PyObject *res = buffer ? PyObject_GetAttr(buffer, &_Py_ID(name)) : NULL;
    Py_XDECREF(buffer);
    return res;
}

/*[clinic input]
@getter
_io.TextIOWrapper.closed
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_closed_get_impl(textio *self)
/*[clinic end generated code: output=b49b68f443a85e3c input=3cfbb89d5815ed29]*/
{
    /* Partially constructed or deconstructed: closed (see _io's). */
    if (!FT_ATOMIC_LOAD_UINT8_RELAXED(self->ok)) {
        Py_RETURN_TRUE;
    }
    PyObject *buffer = textio_buffer(self);
    PyObject *res = buffer ? PyObject_GetAttr(buffer, &_Py_ID(closed)) : NULL;
    Py_XDECREF(buffer);
    return res;
}

/*[clinic input]
@getter
_io.TextIOWrapper.newlines
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_newlines_get_impl(textio *self)
/*[clinic end generated code: output=53aa03ac35573180 input=26b177526b166427]*/
{
    if (!FT_ATOMIC_LOAD_UINT8_RELAXED(self->ok)
        || FT_ATOMIC_LOAD_UINT8_RELAXED(self->detached))
    {
        Py_XDECREF(textio_buffer(self));
        return NULL;
    }
    if (!self->readuniversal || !self->readable) {
        Py_RETURN_NONE;
    }
    switch (FT_ATOMIC_LOAD_UINT8_RELAXED(self->seennl)) {
    case SEEN_CR: return PyUnicode_FromString("\r");
    case SEEN_LF: return PyUnicode_FromString("\n");
    case SEEN_CRLF: return PyUnicode_FromString("\r\n");
    case SEEN_CR | SEEN_LF: return Py_BuildValue("ss", "\r", "\n");
    case SEEN_CR | SEEN_CRLF: return Py_BuildValue("ss", "\r", "\r\n");
    case SEEN_LF | SEEN_CRLF: return Py_BuildValue("ss", "\n", "\r\n");
    case SEEN_CR | SEEN_LF | SEEN_CRLF:
        return Py_BuildValue("sss", "\r", "\n", "\r\n");
    default: Py_RETURN_NONE;
    }
}

/*[clinic input]
@getter
_io.TextIOWrapper.errors
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_errors_get_impl(textio *self)
/*[clinic end generated code: output=dca3a3ef21b09484 input=f5c39940cc10e47c]*/
{
    if (!FT_ATOMIC_LOAD_UINT8_RELAXED(self->ok)) {
        return textio_buffer(self);
    }
    return text_get(&self->errors);
}

static PyObject *
textio_encoding_get(PyObject *op, void *Py_UNUSED(closure))
{
    PyObject *encoding = text_get(&textio_CAST(op)->encoding);
    return encoding ? encoding : Py_NewRef(Py_None);
}

/*[clinic input]
@getter
_io.TextIOWrapper._CHUNK_SIZE -> Py_ssize_t
[clinic start generated code]*/

static Py_ssize_t
_io_TextIOWrapper__CHUNK_SIZE_get_impl(textio *self)
/*[clinic end generated code: output=3fe34b873b6b2c8c input=7e8abe69bf1cd463]*/
{
    PyObject *buffer = textio_buffer(self);
    if (buffer == NULL) {
        return -1;
    }
    Py_DECREF(buffer);
    return FT_ATOMIC_LOAD_SSIZE_RELAXED(self->chunk_size);
}

/*[clinic input]
@critical_section
@setter
_io.TextIOWrapper._CHUNK_SIZE
    value: Py_ssize_t
[clinic start generated code]*/

static int
_io_TextIOWrapper__CHUNK_SIZE_set_impl(textio *self, Py_ssize_t value)
/*[clinic end generated code: output=5170a93dd4d74917 input=ede7bae6145f941b]*/
{
    PyObject *buffer = textio_buffer(self);
    if (buffer == NULL) {
        return -1;
    }
    Py_DECREF(buffer);
    if (value <= 0) {
        PyErr_SetString(PyExc_ValueError,
                        "a strictly positive integer is required");
        return -1;
    }
    FT_ATOMIC_STORE_SSIZE_RELAXED(self->chunk_size, value);
    return 0;
}

/*[clinic input]
@getter
_io.TextIOWrapper.buffer
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_buffer_get_impl(textio *self)
/*[clinic end generated code: output=d265a34555aa5d4b input=1a1c8210c4ebb224]*/
{
    return textio_buffer(self);
}

static PyObject *
textiowrapper_repr(PyObject *op)
{
    textio *self = textio_CAST(op);
    const char *type_name = Py_TYPE(self)->tp_name;
    if (!FT_ATOMIC_LOAD_UINT8_RELAXED(self->ok)) {
        return textio_buffer(self);
    }
    int status = Py_ReprEnter(op);
    if (status != 0) {
        if (status > 0) {
            PyErr_Format(PyExc_RuntimeError,
                         "reentrant call inside %.100s.__repr__", type_name);
        }
        return NULL;
    }
    PyObject *res = PyUnicode_FromFormat("<%.100s", type_name);
    static const char *const names[] = {"name", "mode"};
    for (int i = 0; res != NULL && i < 2; i++) {
        PyObject *v;
        if (PyObject_GetOptionalAttrString(op, names[i], &v) < 0) {
            if (i == 1 || !PyErr_ExceptionMatches(PyExc_ValueError)) {
                Py_CLEAR(res);
                break;
            }
            /* The buffer was detached. */
            PyErr_Clear();
        }
        if (v != NULL) {
            PyObject *s = PyUnicode_FromFormat("%U %s=%R", res, names[i], v);
            Py_DECREF(v);
            Py_SETREF(res, s);
        }
    }
    if (res != NULL) {
        Py_SETREF(res, PyUnicode_FromFormat("%U encoding=%R>", res,
                                            self->encoding));
    }
    Py_ReprLeave(op);
    return res;
}

/*
 * Setting up
 */

static int
validate_newline(const char *newline)
{
    if (newline && newline[0] != '\0'
        && !(newline[0] == '\n' && newline[1] == '\0')
        && !(newline[0] == '\r' && newline[1] == '\0')
        && !(newline[0] == '\r' && newline[1] == '\n' && newline[2] == '\0')) {
        PyErr_Format(PyExc_ValueError,
                     "illegal newline value: %s", newline);
        return -1;
    }
    return 0;
}

static int
set_newline(textio *self, const char *newline)
{
    PyObject *readnl = newline ? PyUnicode_FromString(newline) : NULL;
    if (newline && readnl == NULL) {
        return -1;
    }
    text_swap(&self->readnl, readnl);
    self->readuniversal = (newline == NULL || newline[0] == '\0');
    self->readtranslate = (newline == NULL);
    self->writetranslate = (newline == NULL || newline[0] != '\0');
    self->writenl = NULL;
    if (!self->readuniversal && readnl != NULL) {
        self->writenl = (const char *)PyUnicode_1BYTE_DATA(readnl);
        if (strcmp(self->writenl, "\n") == 0) {
            self->writenl = NULL;
        }
    }
#ifdef MS_WINDOWS
    else {
        self->writenl = "\r\n";
    }
#endif
    return 0;
}

/* The decoding table of a codec of the encodings package that decodes byte
   by byte with one (cp1252, koi8-r and others), if it decodes ASCII as
   ASCII and other bytes as other characters (so that ASCII text is its
   own encoding too).  Returns a new reference, or NULL, with an exception
   set or not. */
static PyObject *
codec_charmap(PyObject *codec_info)
{
    PyObject *cls, *name = NULL, *module = NULL, *table = NULL;
    if (PyObject_GetOptionalAttrString(codec_info, "incrementaldecoder",
                                       &cls) <= 0)
    {
        return NULL;
    }
    const char *s;
    if (PyObject_GetOptionalAttr(cls, &_Py_ID(__module__), &name) <= 0
        || !PyUnicode_Check(name)
        || (s = PyUnicode_AsUTF8(name)) == NULL
        || strncmp(s, "encodings.", 10) != 0
        || (module = PyImport_GetModule(name)) == NULL
        || PyObject_GetOptionalAttrString(module, "decoding_table",
                                          &table) <= 0)
    {
        goto done;
    }
    int ok = PyUnicode_CheckExact(table) && PyUnicode_GET_LENGTH(table) == 256;
    for (Py_UCS4 i = 0; ok && i < 256; i++) {
        Py_UCS4 c = PyUnicode_READ_CHAR(table, i);
        ok = i < 128 ? c == i : c >= 128;
    }
    if (!ok) {
        Py_CLEAR(table);
    }
done:
    Py_DECREF(cls);
    Py_XDECREF(name);
    Py_XDECREF(module);
    return table;
}

/* Set up the codec: the decoder (if readable) and encoder (if writable),
   and how bytes map to characters. */
static int
text_set_codec(textio *self, PyObject *buffer, PyObject *codec_info,
               const char *errors)
{
    Py_CLEAR(self->decoder);
    Py_CLEAR(self->encoder);
    text_swap(&self->charmap, NULL);
    textio_drop_chars(self);
    self->encoder_used = 0;
    self->flags = FLAGS_FRESH;
    PyObject *name;
    if (PyObject_GetOptionalAttr(codec_info, &_Py_ID(name), &name) < 0) {
        return -1;
    }
    int codec = CODEC_DECODER;
    if (name != NULL && PyUnicode_Check(name)) {
        codec = (_PyUnicode_EqualToASCIIString(name, "utf-8") ? CODEC_UTF8
                 : _PyUnicode_EqualToASCIIString(name, "iso8859-1")
                   ? CODEC_LATIN1
                 : _PyUnicode_EqualToASCIIString(name, "ascii") ? CODEC_ASCII
                 : CODEC_DECODER);
    }
    Py_XDECREF(name);
    if (codec == CODEC_DECODER) {
        PyObject *charmap = codec_charmap(codec_info);
        if (charmap == NULL && PyErr_Occurred()) {
            return -1;
        }
        codec = charmap ? CODEC_CHARMAP : CODEC_DECODER;
        text_swap(&self->charmap, charmap);
    }
    self->enc = codec;
    /* Error handlers that keep one character per byte (or valid UTF-8
       sequence) keep the bytes of characters known. */
    int same = (PyUnicode_CompareWithASCIIString(self->errors, "strict") == 0
                || PyUnicode_CompareWithASCIIString(self->errors,
                                                    "surrogateescape") == 0
                || (codec != CODEC_UTF8
                    && PyUnicode_CompareWithASCIIString(self->errors,
                                                        "replace") == 0));
    self->codec = codec == CODEC_LATIN1 || same ? codec : CODEC_DECODER;
    self->escapes = PyUnicode_CompareWithASCIIString(self->errors,
                                                     "surrogateescape") == 0;

    int r = textio_call_bool(buffer, &_Py_ID(readable));
    self->readable = r > 0;
    if (r > 0 && self->codec == CODEC_DECODER) {
        self->decoder = _PyCodecInfo_GetIncrementalDecoder(codec_info, errors);
        if (self->decoder == NULL) {
            return -1;
        }
    }
    if (r >= 0) {
        r = textio_call_bool(buffer, &_Py_ID(writable));
    }
    if (r > 0) {
        self->encoder = _PyCodecInfo_GetIncrementalEncoder(codec_info, errors);
        if (self->encoder == NULL) {
            return -1;
        }
    }
    return r < 0 ? -1 : 0;
}

/* Can calls run without the critical section (see "Locking")?  Only over
   a buffer that can hold a few characters more than a "\r". */
static void
text_set_lockfree(textio *self, PyObject *buffer)
{
    FT_ATOMIC_STORE_UINT8_RELAXED(
        self->lockfree,
        textio_exact(self) && self->nib_ok && self->codec != CODEC_DECODER
        && _PyIONibbler_capacity(buffer) >= 8);
}

/* The encoder writes a BOM only at the start of the stream. */
static int
text_fix_encoder_state(textio *self, PyObject *buffer)
{
    self->encoding_start_of_stream = 0;
    if (!self->seekable || self->encoder == NULL) {
        return 0;
    }
    PyObject *pos = PyObject_CallMethodNoArgs(buffer, &_Py_ID(tell));
    int cmp = pos ? PyObject_RichCompareBool(pos, _PyLong_GetZero(), Py_EQ)
                  : -1;
    Py_XDECREF(pos);
    return cmp < 0 ? -1 : text_encoder_reset(self, cmp);
}

static int
io_check_errors(PyObject *errors)
{
    PyInterpreterState *interp = _PyInterpreterState_GET();
#ifndef Py_DEBUG
    /* In release mode, only check in development mode (-X dev) */
    if (!_PyInterpreterState_GetConfig(interp)->dev_mode) {
        return 0;
    }
#endif
    /* Not before the codec registry is ready. */
    if (!interp->unicode.fs_codec.encoding) {
        return 0;
    }
    const char *name = _PyUnicode_AsUTF8NoNUL(errors);
    if (name == NULL) {
        return -1;
    }
    PyObject *handler = PyCodec_LookupError(name);
    Py_XDECREF(handler);
    return handler == NULL ? -1 : 0;
}

/* The encoding to use: a new reference, or NULL. */
static PyObject *
text_encoding(const char *encoding)
{
    if (encoding == NULL && _PyRuntime.preconfig.utf8_mode) {
        _Py_DECLARE_STR(utf_8, "utf-8");
        return Py_NewRef(&_Py_STR(utf_8));
    }
    if (encoding == NULL || strcmp(encoding, "locale") == 0) {
        return _Py_GetLocaleEncodingObject();
    }
    return PyUnicode_FromString(encoding);
}

static int
textiowrapper_clear(PyObject *op)
{
    textio *self = textio_CAST(op);
    FT_ATOMIC_STORE_UINT8_RELAXED(self->ok, 0);
    Py_CLEAR(self->buffer);
    Py_CLEAR(self->encoding);
    Py_CLEAR(self->errors);
    Py_CLEAR(self->encoder);
    Py_CLEAR(self->decoder);
    Py_CLEAR(self->charmap);
    Py_CLEAR(self->readnl);
#ifdef Py_GIL_DISABLED
    span_free(_Py_atomic_exchange_ptr(&self->span, NULL));
#else
    Py_CLEAR(self->cache.chars);
#endif
    Py_CLEAR(self->dspan);
    Py_CLEAR(self->rbuf);
    Py_CLEAR(self->dict);
    return 0;
}

/*[clinic input]
@critical_section
_io.TextIOWrapper.__init__
    buffer: object
    encoding: str(accept={str, NoneType}) = None
    errors: object = None
    newline: str(accept={str, NoneType}) = None
    line_buffering: bool = False
    write_through: bool = False

Character and line based layer over a BufferedIOBase object, buffer.

encoding gives the name of the encoding that the stream will be
decoded or encoded with. It defaults to locale.getencoding().

errors determines the strictness of encoding and decoding (see
help(codecs.Codec) or the documentation for codecs.register) and
defaults to "strict".

newline controls how line endings are handled. It can be None, '',
'\n', '\r', and '\r\n'.  It works as follows:

* On input, if newline is None, universal newlines mode is
  enabled. Lines in the input can end in '\n', '\r', or '\r\n', and
  these are translated into '\n' before being returned to the
  caller. If it is '', universal newline mode is enabled, but line
  endings are returned to the caller untranslated. If it has any of
  the other legal values, input lines are only terminated by the given
  string, and the line ending is returned to the caller untranslated.

* On output, if newline is None, any '\n' characters written are
  translated to the system default line separator, os.linesep. If
  newline is '' or '\n', no translation takes place. If newline is any
  of the other legal values, any '\n' characters written are translated
  to the given string.

If line_buffering is True, a call to flush is implied when a call to
write contains a newline character.
[clinic start generated code]*/

static int
_io_TextIOWrapper___init___impl(textio *self, PyObject *buffer,
                                const char *encoding, PyObject *errors,
                                const char *newline, int line_buffering,
                                int write_through)
/*[clinic end generated code: output=72267c0c01032ed2 input=0f077220214c40a4]*/
{
    FT_ATOMIC_STORE_UINT8_RELAXED(self->ok, 0);
    FT_ATOMIC_STORE_UINT8_RELAXED(self->detached, 0);
    if (encoding == NULL) {
        PyInterpreterState *interp = _PyInterpreterState_GET();
        if (_PyInterpreterState_GetConfig(interp)->warn_default_encoding
            && PyErr_WarnEx(PyExc_EncodingWarning,
                            "'encoding' argument not specified", 1))
        {
            return -1;
        }
    }
    if (errors == Py_None) {
        errors = &_Py_ID(strict);
    }
    else if (!PyUnicode_Check(errors)) {
        PyErr_Format(
            PyExc_TypeError,
            "TextIOWrapper() argument 'errors' must be str or None, not %.50s",
            Py_TYPE(errors)->tp_name);
        return -1;
    }
    else if (io_check_errors(errors)) {
        return -1;
    }
    const char *errors_str = _PyUnicode_AsUTF8NoNUL(errors);
    if (errors_str == NULL || validate_newline(newline) < 0) {
        return -1;
    }

    (void)textiowrapper_clear((PyObject *)self);
    self->rpos = 0;
#ifdef Py_GIL_DISABLED
    /* Calls that took the cache before can't put it back. */
    (void)_Py_atomic_add_uint64(&self->spans, 1);
#else
    self->cache = (tcache){.cr_at = -1};
#endif
    self->seennl = self->decoded = 0;
    text_swap(&self->encoding, text_encoding(encoding));
    if (self->encoding == NULL) {
        return -1;
    }
    const char *enc = PyUnicode_AsUTF8(self->encoding);
    if (enc == NULL) {
        return -1;
    }
    /* Check we have been asked for a real text encoding */
    PyObject *codec_info = _PyCodec_LookupTextEncoding(enc, NULL);
    if (codec_info == NULL) {
        Py_CLEAR(self->encoding);
        return -1;
    }
    text_swap(&self->errors, Py_NewRef(errors));
    self->chunk_size = 8192;
    self->line_buffering = line_buffering;
    self->write_through = write_through;
    text_swap(&self->buffer, Py_NewRef(buffer));
    self->nib = self->nib_ok =
        (char)_PyIO_is_nibbler_buffered_type(Py_TYPE(buffer));
    int r = -1;
    if (set_newline(self, newline) < 0
        || text_set_codec(self, buffer, codec_info, errors_str) < 0)
    {
        goto done;
    }
    r = textio_call_bool(buffer, &_Py_ID(seekable));
    if (r < 0) {
        goto done;
    }
    self->seekable = (char)r;
    r = PyObject_HasAttrWithError(buffer, &_Py_ID(read1));
    if (r < 0) {
        goto done;
    }
    self->has_read1 = (char)r;
    r = text_fix_encoder_state(self, buffer);
    if (r == 0) {
        text_set_lockfree(self, buffer);
        FT_ATOMIC_STORE_UINT8_RELAXED(self->ok, 1);
    }
done:
    Py_DECREF(codec_info);
    return r;
}

/* Return default_value if obj is None, 0 if obj is false, 1 if obj is true,
   -1 on error. */
static int
convert_optional_bool(PyObject *obj, int default_value)
{
    if (obj == Py_None) {
        return default_value;
    }
    long v = PyLong_AsLong(obj);
    if (v == -1 && PyErr_Occurred()) {
        return -1;
    }
    return v != 0;
}

/*[clinic input]
@critical_section
_io.TextIOWrapper.reconfigure
    *
    encoding: object = None
    errors: object = None
    newline as newline_obj: object(c_default="NULL") = None
    line_buffering as line_buffering_obj: object = None
    write_through as write_through_obj: object = None

Reconfigure the text stream with new parameters.

This also does an implicit stream flush.

[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_reconfigure_impl(textio *self, PyObject *encoding,
                                   PyObject *errors, PyObject *newline_obj,
                                   PyObject *line_buffering_obj,
                                   PyObject *write_through_obj)
/*[clinic end generated code: output=52b812ff4b3d4b0f input=dc3bd35ebda702a7]*/
{
    static const char *const names[] = {"encoding", "errors", "newline"};
    PyObject *args[] = {encoding, errors, newline_obj};
    for (int i = 0; i < 3; i++) {
        if (args[i] != NULL && args[i] != Py_None
            && !PyUnicode_Check(args[i]))
        {
            PyErr_Format(PyExc_TypeError,
                         "reconfigure() argument '%s' must be str or None, "
                         "not %s", names[i], Py_TYPE(args[i])->tp_name);
            return NULL;
        }
    }
    int change = encoding != Py_None || errors != Py_None
                 || newline_obj != NULL;
    if (FT_ATOMIC_LOAD_UINT8_RELAXED(self->decoded) && change) {
        return textio_unsupported(self,
                                  "It is not possible to set the encoding "
                                  "or newline of stream after the first "
                                  "read");
    }
    const char *newline = NULL;
    if (newline_obj != NULL && newline_obj != Py_None) {
        newline = PyUnicode_AsUTF8(newline_obj);
        if (newline == NULL || validate_newline(newline) < 0) {
            return NULL;
        }
    }
    int line_buffering, write_through;
    if ((line_buffering = convert_optional_bool(line_buffering_obj,
                                                self->line_buffering)) < 0
        || (write_through = convert_optional_bool(write_through_obj,
                                                  self->write_through)) < 0
        || _PyFile_Flush((PyObject *)self) < 0)
    {
        return NULL;
    }
    PyObject *buffer = textio_buffer(self);
    if (buffer == NULL) {
        return NULL;
    }
    if (newline_obj != NULL && set_newline(self, newline) < 0) {
        goto error;
    }
    if (change) {
        /* Use the current settings where new ones are not given. */
        if (encoding == Py_None) {
            encoding = self->encoding;
            if (errors == Py_None) {
                errors = self->errors;
            }
            Py_INCREF(encoding);
        }
        else {
            encoding = (PyUnicode_CompareWithASCIIString(encoding, "locale")
                        == 0 ? _Py_GetLocaleEncodingObject()
                        : Py_NewRef(encoding));
            if (encoding == NULL) {
                goto error;
            }
            if (errors == Py_None) {
                errors = &_Py_ID(strict);
            }
        }
        const char *c_encoding = PyUnicode_AsUTF8(encoding);
        const char *c_errors = PyUnicode_AsUTF8(errors);
        PyObject *codec_info = (c_encoding && c_errors
                                ? _PyCodec_LookupTextEncoding(c_encoding, NULL)
                                : NULL);
        if (codec_info == NULL) {
            Py_DECREF(encoding);
            goto error;
        }
        text_swap(&self->encoding, encoding);
        text_swap(&self->errors, Py_NewRef(errors));
        int r = text_set_codec(self, buffer, codec_info, c_errors);
        Py_DECREF(codec_info);
        if (r < 0 || text_fix_encoder_state(self, buffer) < 0) {
            goto error;
        }
    }
    FT_ATOMIC_STORE_UINT8_RELAXED(self->line_buffering, line_buffering);
    FT_ATOMIC_STORE_UINT8_RELAXED(self->write_through, write_through);
    text_set_lockfree(self, buffer);
    Py_DECREF(buffer);
    Py_RETURN_NONE;

error:
    Py_DECREF(buffer);
    return NULL;
}

static void
textiowrapper_dealloc(PyObject *op)
{
    textio *self = textio_CAST(op);
    PyTypeObject *tp = Py_TYPE(self);
    self->finalizing = 1;
    if (_PyIOBase_finalize(op) < 0) {
        return;
    }
    self->ok = 0;
    _PyObject_GC_UNTRACK(self);
    FT_CLEAR_WEAKREFS(op, self->weakreflist);
    (void)textiowrapper_clear(op);
    tp->tp_free(self);
    Py_DECREF(tp);
}

static int
textiowrapper_traverse(PyObject *op, visitproc visit, void *arg)
{
    textio *self = textio_CAST(op);
    Py_VISIT(Py_TYPE(self));
    Py_VISIT(self->buffer);
    Py_VISIT(self->encoding);
    Py_VISIT(self->errors);
    Py_VISIT(self->encoder);
    Py_VISIT(self->decoder);
    Py_VISIT(self->charmap);
    Py_VISIT(self->readnl);
#ifdef Py_GIL_DISABLED
    tspan *sp = _Py_atomic_load_ptr_relaxed(&self->span);
    Py_VISIT(sp ? sp->chars : NULL);
#else
    Py_VISIT(self->cache.chars);
#endif
    Py_VISIT(self->dspan);
    Py_VISIT(self->rbuf);
    Py_VISIT(self->dict);
    return 0;
}

#define clinic_state() (find_io_state_by_def(Py_TYPE(self)))
#include "clinic/textio.c.h"
#undef clinic_state

static PyMethodDef textiowrapper_methods[] = {
    _IO_TEXTIOWRAPPER_DETACH_METHODDEF
    _IO_TEXTIOWRAPPER_RECONFIGURE_METHODDEF
    _IO_TEXTIOWRAPPER_WRITE_METHODDEF
    _IO_TEXTIOWRAPPER_READ_METHODDEF
    _IO_TEXTIOWRAPPER_READLINE_METHODDEF
    _IO_TEXTIOWRAPPER_FLUSH_METHODDEF
    _IO_TEXTIOWRAPPER_CLOSE_METHODDEF
    _IO_TEXTIOWRAPPER_FILENO_METHODDEF
    _IO_TEXTIOWRAPPER_SEEKABLE_METHODDEF
    _IO_TEXTIOWRAPPER_READABLE_METHODDEF
    _IO_TEXTIOWRAPPER_WRITABLE_METHODDEF
    _IO_TEXTIOWRAPPER_ISATTY_METHODDEF
    _IO_TEXTIOWRAPPER_SEEK_METHODDEF
    _IO_TEXTIOWRAPPER_TELL_METHODDEF
    _IO_TEXTIOWRAPPER_TRUNCATE_METHODDEF
    {"__getstate__", _PyIOBase_cannot_pickle, METH_NOARGS},
    {NULL, NULL}
};

static PyMemberDef textiowrapper_members[] = {
    {"line_buffering", Py_T_BOOL, offsetof(textio, line_buffering),
     Py_READONLY},
    {"write_through", Py_T_BOOL, offsetof(textio, write_through),
     Py_READONLY},
    {"_finalizing", Py_T_BOOL, offsetof(textio, finalizing), 0},
    {"__weaklistoffset__", Py_T_PYSSIZET, offsetof(textio, weakreflist),
     Py_READONLY},
    {"__dictoffset__", Py_T_PYSSIZET, offsetof(textio, dict), Py_READONLY},
    {NULL}
};

static PyGetSetDef textiowrapper_getset[] = {
    _IO_TEXTIOWRAPPER_NAME_GETSETDEF
    _IO_TEXTIOWRAPPER_CLOSED_GETSETDEF
    _IO_TEXTIOWRAPPER_NEWLINES_GETSETDEF
    _IO_TEXTIOWRAPPER_ERRORS_GETSETDEF
    _IO_TEXTIOWRAPPER__CHUNK_SIZE_GETSETDEF
    _IO_TEXTIOWRAPPER_BUFFER_GETSETDEF
    {"encoding", textio_encoding_get, NULL, NULL, NULL},
    {NULL}
};

static PyType_Slot textiowrapper_slots[] = {
    {Py_tp_dealloc, textiowrapper_dealloc},
    {Py_tp_repr, textiowrapper_repr},
    {Py_tp_doc, (void *)_io_TextIOWrapper___init____doc__},
    {Py_tp_traverse, textiowrapper_traverse},
    {Py_tp_clear, textiowrapper_clear},
    {Py_tp_iternext, textiowrapper_iternext},
    {Py_tp_methods, textiowrapper_methods},
    {Py_tp_members, textiowrapper_members},
    {Py_tp_getset, textiowrapper_getset},
    {Py_tp_init, _io_TextIOWrapper___init__},
    {Py_tp_token, &_PyIONibbler_textiowrapper_spec},
    {0, NULL},
};

PyType_Spec _PyIONibbler_textiowrapper_spec = {
    .name = "_io._nibbler.TextIOWrapper",
    .basicsize = sizeof(textio),
    .flags = (Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC |
              Py_TPFLAGS_IMMUTABLETYPE),
    .slots = textiowrapper_slots,
};

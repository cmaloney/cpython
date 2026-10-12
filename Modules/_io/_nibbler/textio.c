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
    _iomodule.h ("the store").  Over any other buffer (or a raw stream, or
    once the buffer has an instance dict, which may override its methods),
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

    Invalid bytes (errors="strict") end a read before them, as the end of
    the stream would; the next read takes them and raises, once.  A read
    that raises after taking some text gives it back for the next read
    (see "Keeping what a read took").

    Universal newlines are handled on the decoded characters, by
    text_take(), which also notes the kinds of newline seen.

    What calls run by is one immutable object, tconf; see "Locking" for
    which calls run without the critical section.  InternalDocs/io_nibbler.md
    ("Text layer") has an overview.
*/

#include "Python.h"
#include "pycore_bytes_methods.h"       // _Py_bytes_isascii()
#include "pycore_call.h"                // _PyObject_CallMethod()
#include "pycore_codecs.h"              // _PyCodecInfo_GetIncrementalDecoder()
#include "pycore_fileutils.h"           // _Py_GetLocaleEncodingObject()
#include "pycore_interp.h"              // PyInterpreterState.unicode
#include "pycore_lock.h"                // _PyRecursiveMutex
#include "pycore_long.h"                // _PyLong_GetZero()
#include "pycore_object.h"              // _PyObject_GC_UNTRACK()
#include "pycore_pyerrors.h"            // _PyErr_ChainExceptions1()
#include "pycore_pystate.h"             // _PyInterpreterState_GET()
#include "pycore_runtime.h"             // _PyRuntime
#include "pycore_unicodeobject.h"       // _PyUnicode_AsUTF8String()
#include "pycore_weakref.h"             // FT_CLEAR_WEAKREFS()

#include "../_iomodule.h"

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

/* The codec's decoder's flags (the second item of its state, which
   iso2022_kr's and others' go past 32 bits), or as after reset() (fresh:
   not asked yet). */
typedef struct {
    unsigned long long v;
    char fresh;
} dflags_t;

#define FLAGS_FRESH ((dflags_t){0, 1})

/* Newlines seen, for the newlines attribute. */
enum { SEEN_CR = 1, SEEN_LF = 2, SEEN_CRLF = 4 };


/* The characters decoded at the position: chars[ci:].  With a native
   codec, while the buffer's unread bytes are those named by key at offset
   koff in their block, of which the first kbytes made them; with the
   decoder, always.  cr_at: the byte offset in chars' data of the first
   "\r" at or after ci (none: its end), if not below ci's.
   skip_lf: the "\n" at the position ends a "\r\n" already seen.  nl: the
   kinds of newline in chars[ci:] were noted (see text_note_newlines()).  With
   free threading, a call's copy, of the span sp (see tspan) at pos and of
   version ver; renew: chars are others now; wide: the decoder's. */
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
    uint8_t wide;
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

/* The settings that calls run by: set by __init__() and reconfigure()
   (and detach(), and when the buffer can't be the store any more), and
   never changed once published, but replaced whole (see "Locking").  A
   call takes a reference to them once (textio_conf()), so that everything
   it reads of them agrees, and lives while it runs. */
typedef struct {
    Py_ssize_t refs;            /* the object's, and calls'; first */
    PyObject *buffer;           /* NULL once detached */
    PyObject *encoding;
    PyObject *errors;
    const char *errors_str;     /* errors, or NULL for "strict" */
    PyObject *encoder;          /* NULL if not writable */
    PyObject *decoder;          /* CODEC_DECODER only, if readable */
    PyObject *charmap;          /* CODEC_CHARMAP's decoding table */
    PyObject *readnl;
    const char *writenl;        /* ASCII; NULL stands for "\n" */
    char codec;                 /* CODEC_* for reads */
    char enc;                   /* CODEC_* for writes (CHARMAP: ASCII only) */
    char escapes;               /* errors is "surrogateescape" */
    char readable;
    char seekable;
    char has_read1;             /* the buffer has read1() */
    char readuniversal;
    char readtranslate;
    char writetranslate;
    char nibbler;               /* the buffer is an exact _io._nibbler one */
    char lockfree;              /* calls run without the critical section */
} tconf;

typedef struct {
    PyObject_HEAD
    tconf *conf;                /* NULL: not initialized */
    char finalizing;
    uint8_t line_buffering;
    uint8_t write_through;
    /* With the critical section only: the store is the buffer itself now
       (not rbuf); the buffer can be the store (it has no instance dict). */
    char nib;
    char nib_ok;
    /* Held while rbuf is filled (see store_peek_methods()). */
    _PyRecursiveMutex fill_lock;
    char encoding_start_of_stream;  /* the encoder may write a BOM */
    char encoder_used;          /* the encoder needs final=True at the end */
    uint8_t decoded;            /* read since the last seek or write */
    uint8_t seennl;             /* SEEN_* */
    Py_ssize_t chunk_size;

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
       (see dflags_t).  Used only with the
       critical section. */
    PyObject *dspan;
    dflags_t dflags;
    dflags_t flags;

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

/*
 * Settings
 */

/* New settings, with no references, or NULL with MemoryError. */
static tconf *
conf_new(void)
{
    tconf *cf = PyMem_Calloc(1, sizeof(*cf));
    if (cf == NULL) {
        PyErr_NoMemory();
        return NULL;
    }
    cf->refs = 1;
    return cf;
}

/* A copy of cf to change before it is published. */
static tconf *
conf_copy(const tconf *cf)
{
    tconf *n = conf_new();
    if (n != NULL) {
        /* All but refs, which other threads change meanwhile. */
        memcpy((char *)n + offsetof(tconf, buffer),
               (const char *)cf + offsetof(tconf, buffer),
               sizeof(tconf) - offsetof(tconf, buffer));
        Py_XINCREF(n->buffer);
        Py_XINCREF(n->encoding);
        Py_XINCREF(n->errors);
        Py_XINCREF(n->encoder);
        Py_XINCREF(n->decoder);
        Py_XINCREF(n->charmap);
        Py_XINCREF(n->readnl);
    }
    return n;
}

/* Drop a reference to cf.  The last one frees it: its memory once no
   thread can be in conf_get() with it (see conf_set() for text_quick(),
   which borrows the rest). */
static void
conf_put(tconf *cf)
{
    if (cf == NULL) {
        return;
    }
#ifdef Py_GIL_DISABLED
    if (_Py_atomic_add_ssize(&cf->refs, -1) != 1) {
        return;
    }
#else
    if (--cf->refs != 0) {
        return;
    }
#endif
    Py_XDECREF(cf->buffer);
    Py_XDECREF(cf->encoding);
    Py_XDECREF(cf->errors);
    Py_XDECREF(cf->encoder);
    Py_XDECREF(cf->decoder);
    Py_XDECREF(cf->charmap);
    Py_XDECREF(cf->readnl);
#ifdef Py_GIL_DISABLED
    _PyMem_FreeDelayed(cf, sizeof(*cf));
#else
    PyMem_Free(cf);
#endif
}

/* The settings, borrowed: alive until this thread waits or runs other
   code (see conf_put()). */
static inline tconf *
conf_peek(textio *self)
{
    return FT_ATOMIC_LOAD_PTR_ACQUIRE(self->conf);
}

/* A new reference to the settings, or NULL if there are none. */
static inline tconf *
conf_get(textio *self)
{
#ifdef Py_GIL_DISABLED
    for (;;) {
        tconf *cf = _Py_atomic_load_ptr_acquire(&self->conf);
        if (cf == NULL) {
            return NULL;
        }
        /* Freed only after a delay this thread is inside (see
           conf_put()): unless its last reference is gone. */
        Py_ssize_t refs = _Py_atomic_load_ssize_relaxed(&cf->refs);
        while (refs > 0) {
            if (_Py_atomic_compare_exchange_ssize(&cf->refs, &refs,
                                                  refs + 1))
            {
                return cf;
            }
        }
    }
#else
    tconf *cf = self->conf;
    if (cf != NULL) {
        cf->refs++;
    }
    return cf;
#endif
}

/* Publish cf (stolen; NULL: uninitialized), with the critical section.
   Settings with lockfree may be borrowed by text_quick() in other threads:
   with free threading, those swapped out are kept until every thread is
   past it (stopping the world: lockfree settings are rarely swapped out),
   but by tp_clear and dealloc, where no thread can be using self.  (The
   objects a borrower uses can't be freed later instead: the buffer's
   deallocator frees more later, which _PyMem_AbandonDelayed() can't take
   while it frees what a thread left.) */
static void
conf_set(textio *self, tconf *cf, int clearing)
{
#ifdef Py_GIL_DISABLED
    tconf *old = _Py_atomic_exchange_ptr(&self->conf, cf);
    if (old != NULL && old->lockfree && !clearing) {
        PyInterpreterState *interp = _PyInterpreterState_GET();
        _PyEval_StopTheWorld(interp);
        _PyEval_StartTheWorld(interp);
    }
    conf_put(old);
#else
    (void)clearing;
    tconf *old = self->conf;
    self->conf = cf;
    conf_put(old);
#endif
}

/* A new reference to the settings, with a buffer: else NULL with
   ValueError. */
static tconf *
textio_conf(textio *self)
{
    tconf *cf = conf_get(self);
    if (cf == NULL || cf->buffer == NULL) {
        PyErr_SetString(PyExc_ValueError,
                        cf ? "underlying buffer has been detached"
                           : "I/O operation on uninitialized object");
        conf_put(cf);
        return NULL;
    }
    return cf;
}

/* A new reference to the buffer, or NULL with ValueError. */
static PyObject *
textio_buffer_get(textio *self)
{
    tconf *cf = textio_conf(self);
    PyObject *buffer = cf ? Py_NewRef(cf->buffer) : NULL;
    conf_put(cf);
    return buffer;
}

static PyObject *
textio_call(textio *self, PyObject *name, PyObject *arg)
{
    tconf *cf = textio_conf(self);
    if (cf == NULL) {
        return NULL;
    }
    PyObject *res = (arg == NULL ? PyObject_CallMethodNoArgs(cf->buffer, name)
                     : PyObject_CallMethodOneArg(cf->buffer, name, arg));
    conf_put(cf);
    return res;
}

static PyObject *
textio_call_getattr(textio *self, PyObject *name)
{
    tconf *cf = textio_conf(self);
    if (cf == NULL) {
        return NULL;
    }
    PyObject *res = PyObject_GetAttr(cf->buffer, name);
    conf_put(cf);
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
textio_check_closed(textio *self, tconf *cf)
{
    if (!textio_exact(self)) {
        PyObject *res = _PyIOBase_check_closed((PyObject *)self, Py_True);
        Py_XDECREF(res);
        return res == NULL ? -1 : 0;
    }
    int r;
    if (cf->nibbler) {
        r = _PyIONibbler_closed(cf->buffer);
    }
    else {
        PyObject *res = PyObject_GetAttr(cf->buffer, &_Py_ID(closed));
        r = res == NULL ? -1 : PyObject_IsTrue(res);
        Py_XDECREF(res);
    }
    if (r > 0) {
        PyErr_SetString(PyExc_ValueError, "I/O operation on closed file.");
    }
    return r == 0 ? 0 : -1;
}

/* The settings, with the buffer attached and open, as a new reference. */
static tconf *
textio_ready(textio *self)
{
    tconf *cf = textio_conf(self);
    if (cf != NULL && textio_check_closed(self, cf) < 0) {
        conf_put(cf);
        cf = NULL;
    }
    return cf;
}

/*
 * The store
 */

/* The store's unread bytes at the position (see _PyIONibbler_peek()). */
typedef struct {
    tconf *cf;          /* the call's settings */
    PyObject *buffer;   /* cf's */
    _PyIO_Morsel m;
    uint64_t key;
    int status;         /* of the last peek: 0 or _PyIO_NIBBLER_* */
    char eof;           /* the stream ends after m */
    char at_end;        /* see text_more() */
    char peeked;        /* m is what the store had (else not looked) */
    char all;           /* read everything there is before decoding */
    char lockfree;      /* without the critical section */
    char retry;         /* error: do it with the critical section */
    char stop;          /* invalid bytes follow the characters */
    char again;         /* read everything in parts (see text_read_all()) */
    Py_ssize_t held;    /* bytes of m the decoder held (it forgot them) */
    /* What a read took so far, to give back if it fails (see "Keeping
       what a read took"): with keep, it notes it; taken: there is some;
       kskip: skip_lf where it started.  With a native codec, copies of the
       bytes, kbuf[0:klen] (kcap bytes of room); with the decoder, the
       characters chars[kci:kend] of the cache while its chars are kchars
       (NULL: they aren't any more). */
    char keep;
    char taken;
    uint8_t kskip;
    char *kbuf;
    Py_ssize_t klen;
    Py_ssize_t kcap;
    PyObject *kchars;
    Py_ssize_t kci;
    Py_ssize_t kend;
    /* The cache as this call knows it: a copy (copy), with free threading
       (see "Locking"); with the GIL, the cache itself. */
    tcache *c;
#ifdef Py_GIL_DISABLED
    tcache copy;
#endif
} store;

/* How many bytes of what a read took it copies to its own stack. */
#define KEEP_STACK 256

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
    st->peeked = st->eof = st->status = st->stop = 0;
    st->held = 0;
}

/*
 * Locking
 *
 * With a native codec over an exact _io._nibbler buffer (conf's lockfree),
 * reads, write(), tell(), flush() and the attributes run without the
 * object's critical section: the bytes are the buffer's, which takes them
 * atomically (advance() by key and offset), and what each call knows of
 * the characters is its own copy of the cache, taken from a span and
 * published by swapping the span's position, or the span (see tspan).  A
 * copy that is no longer of the buffer's bytes is found out when its
 * bytes are taken, and decoded again.  Such calls use the buffer as the
 * store, never rbuf.  The other methods, and everything with other codecs
 * or buffers (the codec's decoder and encoder, and rbuf, aren't
 * thread-safe), keep the critical section.
 *
 * What calls run by (the buffer, codec, newline and the lockfree flag) is
 * the settings, tconf, which are replaced whole: each call takes them once,
 * so that a reconfigure(), __init__() or detach() meanwhile changes nothing
 * under it.  Settings, spans and the objects in them that calls use without
 * a reference are freed only once no thread can still use them (delayed,
 * on free-threaded builds).
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
        (uint8_t)sp->wide, sp, pos,
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
        int wide = c->wide;
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

/* The buffer can't be the store any more (it got an instance dict): with
   the critical section, settings by which calls keep it.  Returns 0 or
   -1. */
static int
text_no_nib(textio *self)
{
    self->nib = self->nib_ok = 0;
    tconf *cf = conf_peek(self);
    if (cf != NULL && cf->lockfree) {
        tconf *n = conf_copy(cf);
        if (n == NULL) {
            return -1;
        }
        n->lockfree = 0;
        conf_set(self, n, 0);
    }
    return 0;
}

/* Use the buffer through its methods: for good (it got an instance dict),
   or while it can't hold the bytes needed (keeping read-ahead in rbuf). */
static int
store_use_methods(textio *self, store *st, int for_good)
{
    self->nib = 0;
    if (for_good && text_no_nib(self) < 0) {
        return -1;
    }
    if (st->cf->codec != CODEC_DECODER) {
        cache_clear(st->c);
        cache_put(self, st->c);
    }
    return 0;
}

static int store_peek_methods(textio *self, store *st, Py_ssize_t need);

/* Peek at least need bytes (see _PyIONibbler_peek()); -1 on error.
   Calls without the critical section (st->lockfree) use only the buffer:
   rbuf and nib are the critical section's. */
static inline int
store_peek(textio *self, store *st, Py_ssize_t need)
{
    if (!st->lockfree && !self->nib && self->nib_ok
        && (self->rbuf == NULL || self->rpos == PyBytes_GET_SIZE(self->rbuf)))
    {
        /* Nothing read ahead here any more: back to the buffer itself. */
        Py_CLEAR(self->rbuf);
        self->nib = 1;
    }
    if (st->lockfree || self->nib) {
        Py_XDECREF(st->m.obj);
        int r = _PyIONibbler_peek(st->buffer, need, &st->m, &st->key);
        st->peeked = 1;
        /* Nothing goes to rbuf while calls may run without the critical
           section: what doesn't fit the buffer is taken in parts. */
        if (r != _PyIO_NIBBLER_NO
            && (r != _PyIO_NIBBLER_FULL || st->cf->lockfree))
        {
            st->status = r;
            st->eof = r == 0 && st->m.len < need;
            return r < 0 ? -1 : 0;
        }
        if (st->lockfree) {
            /* A dict on the buffer: the methods, with the critical
               section (see text_read()). */
            assert(r == _PyIO_NIBBLER_NO);
            st->retry = 1;
            return -1;
        }
        if (store_use_methods(self, st, r == _PyIO_NIBBLER_NO) < 0) {
            return -1;
        }
    }
    return store_peek_methods(self, st, need);
}

#define RBUF_UNREAD(self) \
    ((self)->rbuf ? PyBytes_GET_SIZE((self)->rbuf) - (self)->rpos : 0)
#define FILL_END 3

/* For store_peek_methods(), with fill_lock: read more after rbuf.
   Returns 0 (*have: the bytes unread now), FILL_END if there are no more,
   _PyIO_NIBBLER_BLOCKED, or -1. */
static int
store_fill(textio *self, store *st, Py_ssize_t need, Py_ssize_t *have)
{
    /* Growing geometrically, so that rbuf is copied O(1) times. */
    PyObject *size = PyLong_FromSsize_t(
        Py_MAX(FT_ATOMIC_LOAD_SSIZE_RELAXED(self->chunk_size),
               Py_MAX(need - *have, *have)));
    if (size == NULL) {
        return -1;
    }
    PyObject *res = PyObject_CallMethodOneArg(
        st->buffer, st->cf->has_read1 ? &_Py_ID(read1) : &_Py_ID(read),
        size);
    Py_DECREF(size);
    if (res == NULL) {
        return -1;
    }
    if (res == Py_None) {
        Py_DECREF(res);
        return _PyIO_NIBBLER_BLOCKED;
    }
    Py_buffer view;
    if (PyObject_GetBuffer(res, &view, PyBUF_SIMPLE) < 0) {
        PyErr_Format(PyExc_TypeError,
                     "underlying %s() should have returned a bytes-like "
                     "object, not '%.200s'",
                     st->cf->has_read1 ? "read1": "read",
                     Py_TYPE(res)->tp_name);
        Py_DECREF(res);
        return -1;
    }
    /* read1() let other threads take bytes from rbuf (but not add any). */
    Py_ssize_t n = RBUF_UNREAD(self);
    PyObject *rbuf = PyBytes_FromStringAndSize(NULL, n + view.len);
    if (rbuf != NULL) {
        if (n) {
            memcpy(PyBytes_AS_STRING(rbuf),
                   PyBytes_AS_STRING(self->rbuf) + self->rpos, n);
        }
        memcpy(PyBytes_AS_STRING(rbuf) + n, view.buf, view.len);
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
    *have = n + got;
    return got == 0 ? FILL_END : 0;
}

/* store_peek() through the buffer's methods. */
Py_NO_INLINE static int
store_peek_methods(textio *self, store *st, Py_ssize_t need)
{
    store_release(st);
    st->eof = 0;
    st->peeked = 1;
    int r = 0;
    Py_ssize_t have = RBUF_UNREAD(self);
    while (have < need) {
        /* One thread at a time reads and appends, so that rbuf has the
           bytes in their order: read1() lets other threads in (and may
           call back into self: the lock is recursive). */
        _PyRecursiveMutex_Lock(&self->fill_lock);
        have = RBUF_UNREAD(self);
        if (have >= need) {
            _PyRecursiveMutex_Unlock(&self->fill_lock);
            break;
        }
        r = store_fill(self, st, need, &have);
        _PyRecursiveMutex_Unlock(&self->fill_lock);
        if (r != 0) {
            if (r < 0 && _PyIO_trap_eintr()) {
                r = 0;
                continue;
            }
            if (r < 0) {
                return -1;
            }
            break;
        }
    }
    if (r == FILL_END) {
        r = 0;
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
                                Py_ssize_t off, Py_ssize_t n, char *copy);

/* Take the first n bytes of st->m: 1, 0 if another thread took them, or
   -1. */
static int
store_take(textio *self, store *st, Py_ssize_t n)
{
    if (n == 0) {
        return 1;
    }
    return store_advance(self, st, st->key,
                         st->m.ptr - PyBytes_AS_STRING(st->m.obj), n, NULL);
}

/* Take n bytes from where key and off name (copying them to copy unless
   NULL): 1, 0 if the unread bytes don't start there any more, or -1. */
static inline int
store_advance(textio *self, store *st, uint64_t key, Py_ssize_t off,
              Py_ssize_t n, char *copy)
{
    int r = 1;
    if (st->lockfree || self->nib) {
        r = _PyIONibbler_take(st->buffer, key, off, n, copy);
        if (r == _PyIO_NIBBLER_NO) {
            /* A dict on the buffer: through its methods, with the critical
               section (see text_read()). */
            if (st->lockfree) {
                st->retry = 1;
                return -1;
            }
            return store_use_methods(self, st, 1) < 0 ? -1 : 0;
        }
    }
    else if (self->rbuf != NULL && key == STORE_KEY(self->rgen)
             && self->rpos == off
             && n <= PyBytes_GET_SIZE(self->rbuf) - off)
    {
        if (copy != NULL) {
            memcpy(copy, PyBytes_AS_STRING(self->rbuf) + off, n);
        }
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
        if (st->cf->enc == CODEC_DECODER && self->encoding_start_of_stream
            && st->cf->encoder != NULL)
        {
            /* Not at the start any more: no BOM.  (Not lockfree: the
               codec's decoder is used.) */
            self->encoding_start_of_stream = 0;
            PyObject *res = PyObject_CallMethodOneArg(
                st->cf->encoder, &_Py_ID(setstate), _PyLong_GetZero());
            Py_XDECREF(res);
            return res == NULL ? -1 : 1;
        }
    }
    return r;
}

/* Hand the read-ahead in rbuf back to the buffer, so that its position is
   the text position (the buffer as the store has none to hand back). */
static int
store_rewind(textio *self, tconf *cf)
{
    Py_ssize_t unread = self->rbuf ? PyBytes_GET_SIZE(self->rbuf) - self->rpos
                                   : 0;
    if (unread == 0 || !cf->seekable) {
        /* Not seekable: reads and writes are separate streams. */
        return 0;
    }
    PyObject *res = _PyObject_CallMethod(cf->buffer, &_Py_ID(seek), "ni",
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

/* store_write() past its first case, with the critical section: rbuf
   handed back first, or through the buffer's write(). */
Py_NO_INLINE static int
store_write_methods(textio *self, tconf *cf, PyObject *obj, const char *data,
                    Py_ssize_t len)
{
    if (len == 0) {
        return 0;
    }
    if (self->rbuf != NULL && store_rewind(self, cf) < 0) {
        return -1;
    }
    if (!self->nib && self->nib_ok && self->rbuf == NULL) {
        self->nib = 1;
    }
    if (self->nib) {
        int r = _PyIONibbler_write(cf->buffer, obj, data, len);
        if (r != _PyIO_NIBBLER_NO) {
            return r;
        }
        if (text_no_nib(self) < 0) {
            return -1;
        }
    }
    PyObject *b = (PyBytes_CheckExact(obj) ? Py_NewRef(obj)
                   : PyBytes_FromStringAndSize(data, len));
    if (b == NULL) {
        return -1;
    }
    PyObject *res;
    do {
        res = PyObject_CallMethodOneArg(cf->buffer, &_Py_ID(write), b);
    } while (res == NULL && _PyIO_trap_eintr());
    Py_DECREF(b);
    Py_XDECREF(res);
    return res == NULL ? -1 : 0;
}

/* Store data[0:len] (owned by obj).  Without the critical section
   (lockfree), only into the buffer itself: _PyIO_NIBBLER_NO if it has to
   be done with it. */
static Py_ALWAYS_INLINE int
store_write(textio *self, tconf *cf, int lockfree, PyObject *obj,
            const char *data, Py_ssize_t len)
{
    if ((lockfree || self->nib) && len > 0) {
        int r = _PyIONibbler_write(cf->buffer, obj, data, len);
        if (r != _PyIO_NIBBLER_NO || lockfree) {
            return r;
        }
    }
    return store_write_methods(self, cf, obj, data, len);
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
text_bytes(tconf *cf, PyObject *chars, Py_ssize_t kbytes, Py_ssize_t i,
           Py_ssize_t k)
{
    return (i + k == PyUnicode_GET_LENGTH(chars) ? kbytes
            : utf8_bytes(chars, cf->escapes, i, k));
}

/* A native codec's decoding of s[0:len] (but a partial character at the
   end, unless final): *used gets the bytes decoded. */
static PyObject *
native_decode(tconf *cf, const char *s, Py_ssize_t len, int final,
              Py_ssize_t *used)
{
    /* NULL is "strict", which the UTF-8 decoder does fastest. */
    const char *errors = cf->errors_str;
    *used = len;
    switch (cf->codec) {
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
        return PyUnicode_DecodeCharmap(s, len, cf->charmap, errors);
    }
}

/* The decoder's flags. */
static int
decoder_flags(PyObject *decoder, dflags_t *flags, Py_ssize_t *held)
{
    PyObject *state = PyObject_CallMethodNoArgs(decoder,
                                                &_Py_ID(getstate));
    PyObject *buf;
    int ok = (state != NULL && PyTuple_Check(state)
              && PyArg_ParseTuple(state, "OK;illegal decoder state", &buf,
                                  &flags->v)
              && PyBytes_Check(buf));
    flags->fresh = 0;
    if (ok && held != NULL) {
        *held = PyBytes_GET_SIZE(buf);
    }
    if (!ok && state != NULL && !PyErr_Occurred()) {
        PyErr_SetString(PyExc_TypeError, "illegal decoder state");
    }
    Py_XDECREF(state);
    return ok ? 0 : -1;
}

/* Set the decoder to (b"", flags), or reset it (fresh). */
static int
decoder_setstate(PyObject *decoder, dflags_t flags)
{
    PyObject *res = (flags.fresh
                     ? PyObject_CallMethodNoArgs(decoder, &_Py_ID(reset))
                     : _PyObject_CallMethod(decoder, &_Py_ID(setstate),
                                            "((yK))", "", flags.v));
    Py_XDECREF(res);
    return res == NULL ? -1 : 0;
}

/* The decoder's decoding of s[0:len], from (b"", flags): *used gets the
   bytes it decoded (not those it holds, which it is made to forget),
   *flags its flags after them. */
static PyObject *
decoder_decode(PyObject *decoder, const char *s, Py_ssize_t len, int final,
               Py_ssize_t *used, dflags_t *flags)
{
    if (decoder_setstate(decoder, *flags) < 0) {
        return NULL;
    }
    PyObject *input = PyBytes_FromStringAndSize(s, len);
    if (input == NULL) {
        return NULL;
    }
    PyObject *chars = PyObject_CallMethodObjArgs(
        decoder, &_Py_ID(decode), input, final ? Py_True : Py_False, NULL);
    Py_DECREF(input);
    if (chars != NULL && !PyUnicode_Check(chars)) {
        PyErr_Format(PyExc_TypeError,
                     "decoder should return a string result, not '%.200s'",
                     Py_TYPE(chars)->tp_name);
        Py_CLEAR(chars);
    }
    Py_ssize_t held = 0;
    if (chars == NULL || decoder_flags(decoder, flags, &held) < 0
        || (held > 0 && decoder_setstate(decoder, *flags) < 0))
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
decoder_offset(textio *self, PyObject *decoder, Py_ssize_t ci,
               Py_ssize_t *off, dflags_t *flags)
{
    /* The decoder runs Python code, which may use self. */
    PyObject *span = Py_NewRef(self->dspan);
    dflags_t dflags = self->dflags;
    Py_ssize_t lo = 0, hi = PyBytes_GET_SIZE(span), used = 0, n = 0;
    int r = -1;
    while (lo <= hi) {
        Py_ssize_t mid = lo + (hi - lo) / 2;
        *flags = dflags;
        PyObject *chars = decoder_decode(decoder, PyBytes_AS_STRING(span),
                                         mid, 0, &used, flags);
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
    (void)self;
    return (st->c->chars != NULL
            && (st->cf->codec == CODEC_DECODER || !st->peeked
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
        PyObject *chars = native_decode(st->cf, st->m.ptr, span, final,
                                        &used);
        Py_ssize_t start, end;
        if (chars == NULL && PyErr_ExceptionMatches(PyExc_UnicodeDecodeError)
            && text_decode_error(&start, &end) == 0)
        {
            /* Decode what is valid, which ends this call (as if at the
               end); at invalid bytes, take them, so that the error is
               raised once (as _io's does). */
            if (start > 0) {
                PyErr_Clear();
                chars = native_decode(st->cf, st->m.ptr, start, 0, &used);
                st->stop = 1;
            }
            else if (st->taken) {
                /* After text this call took: it ends there, and the next
                   read raises. */
                PyErr_Clear();
                st->stop = 1;
                return 0;
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
        /* Decoded again from the same position: the same "\r\n" seen. */
        int skip_lf = covered > 0 && st->c->ci == 0 && st->c->skip_lf;
        Py_XSETREF(st->c->chars, chars);
        st->c->ci = 0;
        st->c->cr_at = -1;
        st->c->key = st->key;
        st->c->koff = st->m.ptr - PyBytes_AS_STRING(st->m.obj);
        st->c->kbytes = used;
        st->c->skip_lf = skip_lf;
        st->c->nl = 0;
        st->c->renew = 1;
        st->c->wide = 0;
        if (cache_put(self, st->c) < 0) {
            return -1;
        }
        if (used > covered) {
            return 1;
        }
        /* Only part of a character more. */
    }
    if (st->stop || (st->peeked && (st->eof || st->status))) {
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
    if (st->stop) {
        return 0;
    }
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
    /* As for native codecs, more than twice what the decoder held.  (dspan
       is gone if reconfigure() ran while this call waited.) */
    Py_ssize_t avail = text_avail(self, st);
    Py_ssize_t dspan = (avail && self->dspan ? PyBytes_GET_SIZE(self->dspan)
                        : 0);
    Py_ssize_t span = Py_MIN(st->m.len,
                             Py_MAX(Py_MAX(FT_ATOMIC_LOAD_SSIZE_RELAXED(
                                               self->chunk_size), dspan),
                                    2 * st->held + 4));
    span = st->all ? st->m.len : span;
    int final = st->eof && span == st->m.len;
    Py_ssize_t used;
    /* From the store's position (another thread may have used the decoder
       while this one waited): the flags there. */
    PyObject *decoder = st->cf->decoder;
    if (self->flags.fresh
        && decoder_flags(decoder, &self->flags, NULL) < 0)
    {
        return -1;
    }
    dflags_t flags = self->flags;
    PyObject *chars = decoder_decode(decoder, st->m.ptr, span, final, &used,
                                     &flags);
    Py_ssize_t start, end;
    if (chars == NULL && PyErr_ExceptionMatches(PyExc_UnicodeDecodeError)
        && text_decode_error(&start, &end) == 0)
    {
        /* As native_more(): what is valid ends this call; invalid bytes
           are taken, so that the error is raised once. */
        if (start > 0 && start <= span) {
            PyErr_Clear();
            span = start;
            final = 0;
            flags = self->flags;
            chars = decoder_decode(decoder, st->m.ptr, span, 0, &used,
                                   &flags);
            st->stop = 1;
        }
        else if (st->taken) {
            /* As native_more(). */
            PyErr_Clear();
            st->stop = 1;
            return decoder_setstate(decoder, self->flags);
        }
        else {
            PyObject *exc = PyErr_GetRaisedException();
            int r = store_take(self, st, Py_MIN(Py_MAX(end, 1), st->m.len));
            if (r < 0 || decoder_setstate(decoder, self->flags) < 0) {
                _PyErr_ChainExceptions1(exc);
                return -1;
            }
            st->held = 0;
            PyErr_SetRaisedException(exc);
            return -1;
        }
    }
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
    if (st->kchars != NULL
        && (st->c->chars != st->kchars || st->c->ci != st->kend))
    {
        /* Another call read meanwhile (see text_give_back()). */
        Py_CLEAR(st->kchars);
    }
    if (st->c->chars == NULL || self->dspan == NULL
        || (st->c->ci == PyUnicode_GET_LENGTH(st->c->chars)
            && st->kchars == NULL))
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
        if (st->kchars != NULL) {
            /* The characters the call took are still there. */
            Py_SETREF(st->kchars, Py_NewRef(st->c->chars));
        }
    }
    self->flags = flags;
    st->c->renew = 1;
    st->c->wide = 1;
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
    (void)self;
    return st->stop
           || (st->eof && (st->cf->codec == CODEC_DECODER ? st->m.len == 0
                           : avail == 0 || st->c->kbytes == st->m.len));
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
            r = (st->cf->codec == CODEC_DECODER ? decoder_more(self, st)
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

/* Room for n more bytes in st->kbuf. */
static int
keep_room(store *st, Py_ssize_t n)
{
    if (n > PY_SSIZE_T_MAX / 2 - st->klen) {
        PyErr_NoMemory();
        return -1;
    }
    Py_ssize_t cap = Py_MAX(st->klen + n, 2 * st->kcap);
    char *p = st->kbuf;
    if (st->kcap <= KEEP_STACK) {
        /* From the caller's room (see text_read_impl()). */
        p = PyMem_Malloc(cap);
        if (p != NULL && st->klen > 0) {
            memcpy(p, st->kbuf, st->klen);
        }
    }
    else {
        p = PyMem_Realloc(p, cap);
    }
    if (p == NULL) {
        PyErr_NoMemory();
        return -1;
    }
    st->kbuf = p;
    st->kcap = cap;
    return 0;
}

/* Take k characters from chars[ci:], at the store's position: their bytes
   with a native codec.  Returns 1, 0 if another thread took bytes
   meanwhile (then nothing was taken), or -1. */
static int
text_commit(textio *self, store *st, Py_ssize_t k)
{
    Py_ssize_t ci = st->c->ci;
    if (st->cf->codec != CODEC_DECODER) {
        Py_ssize_t b = (st->cf->codec == CODEC_UTF8
                        ? text_bytes(st->cf, st->c->chars, st->c->kbytes, ci,
                                     k)
                        : k);
#ifndef Py_GIL_DISABLED
        /* With the GIL, the cache is the call's own (see cache_get()), but
           other threads may decode while this one waits for the buffer. */
        PyObject *chars = st->c->chars;
        Py_ssize_t koff = st->c->koff;
#endif
        char *copy = NULL;
        if (st->keep) {
            if (b > st->kcap - st->klen && keep_room(st, b) < 0) {
                return -1;
            }
            copy = st->kbuf + st->klen;
        }
        int r = store_advance(self, st, st->c->key, st->c->koff, b, copy);
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
        if (st->keep) {
            st->klen += b;
            st->taken = 1;
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
    else if (st->keep) {
        /* The characters stay in the cache: note where. */
        if (!st->taken) {
            st->taken = 1;
            st->kci = ci;
            st->kchars = Py_NewRef(st->c->chars);
        }
        else if (st->kchars != NULL
                 && (st->c->chars != st->kchars || ci != st->kend))
        {
            /* Another call read meanwhile (see text_give_back()). */
            Py_CLEAR(st->kchars);
        }
        st->kend = ci + k;
    }
    st->c->ci = ci + k;
    cache_put(self, st->c);
    FT_ATOMIC_STORE_UINT8_RELAXED(self->decoded, 1);
    /* With room again, the buffer may take more. */
    st->status = 0;
    return 1;
}

/*
 * Keeping what a read took
 *
 * A read takes the bytes of its text from the store piece by piece (as
 * text_commit() does), but may fail before it is done: the buffer's raw
 * stream raises, is closed, or would block when asked for more (an
 * exception, as opposed to a read returning None), or KeyboardInterrupt
 * comes.  Then, as the buffer does with bytes (gh-51571), what it took
 * is given back, so that the next read returns it, and the exception is
 * raised: with a native codec the bytes go back in front of the store's
 * unread bytes (the buffer's read-ahead, _PyIONibbler_unread(), or rbuf);
 * with the decoder, whose characters stay in the cache, the cache's
 * position goes back.  Either way the text position is where it was
 * before the call, so tell() and write() are right, and skip_lf is as it
 * was.  Not taking the bytes until the end instead would not do: a read
 * may need more than the buffer holds, and the buffer can't tell whether
 * the bytes at a position seen before are still unread once it gathered
 * them into another block.
 *
 * Invalid bytes after text the call took end it as the end of the stream
 * would (see native_more()); the next read raises.  read() of everything
 * (text_read_all()) gives the bytes back and reads them in parts.
 *
 * With free threading, other threads may read between the pieces: the
 * bytes then go back in front of what is unread now, and are read after
 * text that followed them, but neither lost nor read twice.  The
 * decoder's characters go back only if no other call read from the cache
 * meanwhile (or moved the position: seek(), write()); bytes go back only
 * while the buffer has no pending writes.  Without the critical section,
 * bytes that the buffer won't take back (it got an instance dict) are
 * handed to text_read_more(), which puts them in rbuf.
 */

/* Put data[0:len] back in front of the store's unread bytes.  Returns 1,
   0 if they can't be (see above), _PyIO_NIBBLER_NO without the critical
   section, or -1. */
static int
store_unread(textio *self, store *st, const char *data, Py_ssize_t len)
{
    if (st->lockfree || self->nib) {
        int r = _PyIONibbler_unread(st->buffer, data, len);
        if (r != _PyIO_NIBBLER_NO || st->lockfree) {
            return r;
        }
        if (store_use_methods(self, st, 1) < 0) {
            return -1;
        }
    }
    Py_ssize_t unread = RBUF_UNREAD(self);
    PyObject *rbuf = PyBytes_FromStringAndSize(NULL, len + unread);
    if (rbuf == NULL) {
        return -1;
    }
    memcpy(PyBytes_AS_STRING(rbuf), data, len);
    if (unread > 0) {
        memcpy(PyBytes_AS_STRING(rbuf) + len,
               PyBytes_AS_STRING(self->rbuf) + self->rpos, unread);
    }
    Py_XSETREF(self->rbuf, rbuf);
    self->rpos = 0;
    self->rgen++;
    return 1;
}

/* Bytes given back to the store: the "\n" there ends a "\r\n" seen before
   (as text_seek_skip_lf() does).  Without the critical section if
   lockfree. */
static int
text_unread_skip_lf(textio *self, tconf *cf, int lockfree)
{
    store st = {.cf = cf, .buffer = cf->buffer, .lockfree = lockfree};
    st.c = cache_get(self, STORE_COPY(&st));
    Py_ssize_t avail = text_more(self, &st, 0);
    if (avail > 0) {
        st.c->skip_lf = 1;
        cache_put(self, st.c);
    }
    cache_release(st.c);
    store_release(&st);
    return avail < 0 ? -1 : 0;
}

/* Bytes a read without the critical section couldn't give back. */
typedef struct {
    PyObject *bytes;
    uint8_t skip_lf;
} tkept;

enum { GIVEN = 1, HANDED = 2 };

/* The read of st failed (with an exception, unless retrying): give back
   what it took (see above).  Returns GIVEN, HANDED (to *out, without the
   critical section), or 0 if it is lost (the exception raised, if
   any, is kept, maybe as the context of another one). */
static int
text_give_back(textio *self, store *st, tkept *out)
{
    if (!st->taken) {
        return GIVEN;
    }
    PyObject *exc = PyErr_GetRaisedException();
    int r = 0;
    if (st->cf->codec == CODEC_DECODER) {
        /* The cache's position back, if it is where the call left it. */
        cache_release(st->c);
        st->c = cache_get(self, STORE_COPY(st));
        if (st->kchars != NULL && st->c->chars == st->kchars
            && st->c->ci == st->kend)
        {
            st->c->ci = st->kci;
            st->c->skip_lf = st->kskip;
            st->c->cr_at = -1;
            cache_put(self, st->c);
            r = GIVEN;
        }
    }
    else {
        r = store_unread(self, st, st->kbuf, st->klen);
        if (r == _PyIO_NIBBLER_NO) {
            assert(st->lockfree && out != NULL);
            out->bytes = PyBytes_FromStringAndSize(st->kbuf, st->klen);
            out->skip_lf = st->kskip;
            r = out->bytes != NULL ? HANDED : -1;
        }
        else if (r > 0 && st->kskip
                 && text_unread_skip_lf(self, st->cf, st->lockfree) < 0)
        {
            /* The bytes are back; only the newlines noted may differ. */
            PyErr_Clear();
        }
    }
    if (r < 0) {
        if (exc != NULL) {
            _PyErr_ChainExceptions1(exc);
            exc = NULL;
        }
        else {
            /* Retrying: nothing to raise but this. */
            return -1;
        }
        r = 0;
    }
    st->taken = 0;
    st->klen = 0;
    Py_CLEAR(st->kchars);
    if (exc != NULL) {
        PyErr_SetRaisedException(exc);
    }
    return r;
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
find_line(tconf *cf, tcache *c, int kind, const char *s, const char *end,
          Py_ssize_t *resume)
{
    if (cf->readuniversal) {
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
    Py_ssize_t e = _PyIO_find_line_ending(0, 0, cf->readnl, kind, s, end,
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
    tconf *cf = st->cf;
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
        Py_ssize_t e = find_line(cf, st->c, kind, s + *scanned * kind, end,
                                 &resume);
        if (e >= 0) {
            n = *scanned + e;
            *found = 1;
        }
        else {
            *scanned += resume;
            /* The rest ends at eof, or is limited by want (unless it ends
               with a "\r" that may be part of the line's end). */
            int cr_last = (cf->readuniversal && !eof
                           && AT(avail - 1) == '\r');
            n = (want >= 0 && avail - cr_last >= want ? want
                 : eof ? avail : 0);
            *found = n > 0;
        }
        out = n;
        if (cf->readuniversal && n > 0) {
            Py_UCS4 c = AT(n - 1);
            if (c == '\n') {
                seen = (n > 1 && AT(n - 2) == '\r') ? SEEN_CRLF
                       : (n == 1 && st->c->skip_lf) ? 0 : SEEN_LF;
                if (seen == SEEN_CRLF && cf->readtranslate) {
                    out--;
                    translate = 1;
                }
            }
            else if (c == '\r') {
                seen = (n < avail && AT(n) == '\n') ? SEEN_CRLF : SEEN_CR;
                translate = cf->readtranslate;
            }
        }
        if (want >= 0 && out > want) {
            /* Cut before the line's end (but between "\r" and "\n" if
               not translated). */
            n = out = want;
            translate = 0;
            seen = (n > 0 && cf->readuniversal && AT(n - 1) == '\r')
                   ? SEEN_CRLF : 0;
            *found = 1;
        }
        skip_lf = seen == SEEN_CRLF && !translate && AT(n - 1) == '\r';
    }
    else {
        Py_ssize_t lim = want < 0 ? avail : Py_MIN(avail, want);
        const char *cr = (cf->readuniversal
                          ? find_cr(st->c->chars, &st->c->cr_at, kind, s,
                                    s + lim * kind)
                          : NULL);
        n = out = cr ? (cr - s) / kind : lim;
        if (cf->readuniversal
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
            translate |= cf->readtranslate;
            if (cf->readtranslate || (crlf && (want < 0 || out + 1 < want))) {
                n += 1 + crlf;
                out += 1 + (crlf && !cf->readtranslate);
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
text_quick(textio *self, tconf *cf, Py_ssize_t n, int line)
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
        if (n >= 0 || !cf->readuniversal
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
            crlf = cf->readtranslate;
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
        if (cf->readuniversal && !FT_ATOMIC_LOAD_UINT8_RELAXED(C->nl)) {
            text_note_newlines(self, chars, ci, skip_lf, &C->cr_at);
            FT_ATOMIC_STORE_UINT8_RELAXED(C->nl, 1);
        }
        const char *cr = (cf->readuniversal
                          ? find_cr(chars, &C->cr_at, kind, s,
                                    s + (k << shift))
                          : NULL);
        if (cr != NULL) {
            /* Translated, n characters from more. */
            cr_at = FT_ATOMIC_LOAD_SSIZE_RELAXED(C->cr_at);
            if (!cf->readtranslate || skip_lf
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
        b += cf->codec == CODEC_UTF8 ? extra : 0;
        high = extra != 0;
    }
    else if (high < 0 && cf->codec == CODEC_UTF8) {
        if (kind == PyUnicode_2BYTE_KIND && !cf->escapes) {
            b += utf8_extra_ucs2((const Py_UCS2 *)s, k, &high);
        }
        else {
            b = text_bytes(cf, chars, KBYTES, ci, k);
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
    if (_PyIONibbler_take(cf->buffer, C->key, koff, b, NULL) != 1) {
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
   in the buffer, so the cache is dropped.  If decoding fails, the bytes
   are the call's to give back (see "Keeping what a read took"); invalid
   bytes are then read in parts instead (st->again), so that the text
   before them is returned first. */
static PyObject *
text_read_all(textio *self, store *st)
{
    tconf *cf = st->cf;
    PyObject *b = PyObject_CallMethodNoArgs(cf->buffer, &_Py_ID(read));
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
    Py_ssize_t used, len = PyBytes_GET_SIZE(b);
    t.chars = native_decode(cf, PyBytes_AS_STRING(b), len, 1, &used);
    if (t.chars == NULL) {
        if (len > st->kcap && keep_room(st, len) < 0) {
            Py_DECREF(b);
            return NULL;
        }
        memcpy(st->kbuf, PyBytes_AS_STRING(b), len);
        Py_DECREF(b);
        st->klen = len;
        st->taken = len > 0;
        st->kskip = t.skip_lf;
        st->again = PyErr_ExceptionMatches(PyExc_UnicodeDecodeError);
        return NULL;
    }
    Py_DECREF(b);
    store tst = {.cf = cf, .buffer = cf->buffer, .c = &t};
    Py_ssize_t avail = PyUnicode_GET_LENGTH(t.chars), scanned = 0, k = 0;
    int found;
    PyObject *text = (avail == 0 ? NULL
                      : text_take(self, &tst, avail, -1, 0, 1, &scanned, &k,
                                  &found));
    Py_DECREF(t.chars);
    if (text == NULL && !PyErr_Occurred()) {
        text = Py_GetConstant(Py_CONSTANT_EMPTY_STR);
    }
    return text;
}

/* read(n) (n < 0: all), or with line, readline(n); with lockfree, without
   the critical section (*retry: do it with it after all; *out: bytes taken
   to give back with it, see text_give_back()). */
static PyObject *
text_read_impl(textio *self, Py_ssize_t n, int line, int lockfree,
               int *retry, tkept *out)
{
    tconf *cf = textio_conf(self);
    if (cf == NULL) {
        return NULL;
    }
    if (lockfree && !cf->lockfree) {
        /* Not any more (see store_peek()). */
        conf_put(cf);
        *retry = 1;
        return NULL;
    }
    /* With native codecs the buffer checks that it is open when the bytes
       are looked at or taken. */
    int peeks = lockfree || (textio_exact(self) && self->nib_ok
                             && cf->codec != CODEC_DECODER);
    if (!peeks || n == 0) {
        /* (No peek or commit to find whether it is closed.) */
        if (textio_check_closed(self, cf) < 0) {
            conf_put(cf);
            return NULL;
        }
    }
    if (!lockfree && peeks && self->nib && n != 0) {
        PyObject *text = text_quick(self, cf, n, line);
        if (text != NULL || PyErr_Occurred()) {
            conf_put(cf);
            return text;
        }
    }
    /* The bytes taken are copied here first (see "Keeping what a read
       took"). */
    char kstack[KEEP_STACK];
    store st = {.cf = cf, .buffer = cf->buffer, .all = n < 0 && !line,
                .lockfree = lockfree, .keep = 1, .kbuf = kstack,
                .kcap = KEEP_STACK};
    /* The text so far: res, then in writer once there are two pieces. */
    PyObject *res = NULL;
    _PyUnicodeWriter writer;
    int pieces = 0;
    if (!cf->readable) {
        conf_put(cf);
        return textio_unsupported(self, "not readable");
    }
    if (st.all && peeks && (lockfree || self->rbuf == NULL)) {
        PyObject *text = text_read_all(self, &st);
        if (text != NULL || !st.taken) {
            if (st.kbuf != kstack) {
                PyMem_Free(st.kbuf);
            }
            conf_put(cf);
            return text;
        }
        st.c = cache_get(self, STORE_COPY(&st));
        if (!st.again) {
            goto error;
        }
        /* Invalid bytes: the text before them first. */
        st.again = 0;
        int r = text_give_back(self, &st, out);
        if (r == 0) {
            goto error;
        }
        PyErr_Clear();
        if (r == HANDED) {
            *retry = 1;
            goto error;
        }
    }
    else {
        st.c = cache_get(self, STORE_COPY(&st));
    }
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
        if (!st.taken) {
            /* Where the text taken would start. */
            st.kskip = st.c->skip_lf;
        }
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
                    && (taken || avail > FT_ATOMIC_LOAD_SSIZE_RELAXED(
                                             self->chunk_size)))))
        {
            /* The buffer can't hold more of the line, or it would block
               and is longer than _CHUNK_SIZE (the text layer's buffer
               size, as _io's and _pyio's keep), too long to keep for the
               next call: take it so far, but a last "\r"
               (that may begin a "\r\n", universal or the newline: the
               buffer holds 8 bytes or more, so that there are others). */
            k = avail - ((cf->readuniversal
                          || PyUnicode_GET_LENGTH(cf->readnl) == 2)
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
    /* Done: nothing to give back. */
    st.klen = 0;
    Py_CLEAR(st.kchars);
    if (st.kbuf != kstack) {
        PyMem_Free(st.kbuf);
    }
    store_release(&st);
    cache_release(st.c);
    conf_put(cf);
    return (pieces > 1 ? _PyUnicodeWriter_Finish(&writer)
            : res ? res : Py_GetConstant(Py_CONSTANT_EMPTY_STR));

error:
    if (st.retry) {
        /* All of it with the critical section, the text taken so far
           given back (see text_read_more()).  (An error found meanwhile,
           as of bytes that weren't next any more, will be found again.) */
        assert(lockfree);
        PyErr_Clear();
        *retry = 1;
    }
    if (st.taken && text_give_back(self, &st, out) < 0) {
        /* Retrying, but the bytes couldn't be handed over. */
        *retry = 0;
    }
    Py_CLEAR(st.kchars);
    if (st.kbuf != kstack) {
        PyMem_Free(st.kbuf);
    }
    store_release(&st);
    cache_release(st.c);
    conf_put(cf);
    Py_XDECREF(res);
    if (pieces > 1) {
        _PyUnicodeWriter_Dealloc(&writer);
    }
    return NULL;
}

/* With the critical section: bytes a read without it took and couldn't
   give back to the buffer (see text_give_back()) go in front of rbuf,
   from which reads take them first. */
static int
text_keep_handed(textio *self, tkept *kept)
{
    tconf *cf = textio_conf(self);
    if (cf == NULL) {
        return -1;
    }
    store st = {.cf = cf, .buffer = cf->buffer};
    st.c = cache_get(self, STORE_COPY(&st));
    int r = store_unread(self, &st, PyBytes_AS_STRING(kept->bytes),
                         PyBytes_GET_SIZE(kept->bytes));
    cache_release(st.c);
    if (r > 0 && kept->skip_lf && text_unread_skip_lf(self, cf, 0) < 0) {
        PyErr_Clear();
    }
    conf_put(cf);
    return r < 0 ? -1 : 0;
}

/* text_read() past text_quick(). */
Py_NO_INLINE static PyObject *
text_read_more(textio *self, Py_ssize_t n, int line, int lockfree)
{
    PyObject *res;
    if (lockfree) {
        int retry = 0;
        tkept kept = {NULL, 0};
        res = text_read_impl(self, n, line, 1, &retry, &kept);
        if (!retry && kept.bytes == NULL) {
            return res;
        }
        if (kept.bytes != NULL) {
            /* Unless retrying, an error is raised after they are kept. */
            PyObject *exc = PyErr_GetRaisedException();
            int r;
            Py_BEGIN_CRITICAL_SECTION(self);
            r = text_keep_handed(self, &kept);
            Py_END_CRITICAL_SECTION();
            Py_DECREF(kept.bytes);
            if (exc != NULL) {
                if (r < 0) {
                    _PyErr_ChainExceptions1(exc);
                }
                else {
                    PyErr_SetRaisedException(exc);
                }
                return NULL;
            }
            if (r < 0) {
                return NULL;
            }
        }
    }
    Py_BEGIN_CRITICAL_SECTION(self);
    res = text_read_impl(self, n, line, 0, NULL, NULL);
    Py_END_CRITICAL_SECTION();
    return res;
}

static inline PyObject *
text_read(textio *self, Py_ssize_t n, int line)
{
    /* The settings borrowed: text_quick() runs no other code, and is done
       with them once it may wait (in _PyIONibbler_take(), which keeps
       the buffer alive then); with free threading, lockfree settings are
       freed only once every thread is past such a call (see conf_set()).
       lockfree settings have a buffer; n == 0 is never quick. */
    tconf *cf = conf_peek(self);
    if (cf != NULL && cf->lockfree) {
        PyObject *res = text_quick(self, cf, n, line);
        if (res != NULL || PyErr_Occurred()) {
            return res;
        }
        return text_read_more(self, n, line, 1);
    }
    return text_read_more(self, n, line, 0);
}

/*
 * Writing
 */

/* UTF-8 text not ASCII, of 1 or 2 byte characters but no surrogates, into
   room reserved in the buffer, without a bytes object.  Returns 0, -1
   (closed: the bytes are stored, as by write()), or _PyIO_NIBBLER_NO
   (nothing done). */
static Py_ALWAYS_INLINE int
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
    int closed;
    char *p = _PyIONibbler_reserve(buffer, size, &end, &closed);
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
    if (closed) {
        PyErr_SetString(PyExc_ValueError, "I/O operation on closed file.");
        return -1;
    }
    return 0;
}

/* Encode and store text.  The fast encoders hold no state; the codec's
   encoder must be given final=True at the end (gh-79792).  Without the
   critical section (lockfree), _PyIO_NIBBLER_NO if it has to be done with
   it (nothing done). */
static int text_write_encoded(textio *self, tconf *cf, int lockfree,
                              PyObject *text);

static Py_ALWAYS_INLINE int
text_write(textio *self, tconf *cf, int lockfree, PyObject *text)
{
    int enc = cf->enc;
    if (enc != CODEC_DECODER
        && (PyUnicode_IS_ASCII(text)
            || (enc == CODEC_LATIN1
                && PyUnicode_KIND(text) == PyUnicode_1BYTE_KIND)))
    {
        /* The str's data is its encoding. */
        return store_write(self, cf, lockfree, text, PyUnicode_DATA(text),
                           PyUnicode_GET_LENGTH(text));
    }
    if (enc == CODEC_UTF8 && (lockfree || self->nib)) {
        int r = utf8_write_direct(cf->buffer, text);
        if (r != _PyIO_NIBBLER_NO) {
            return r;
        }
    }
    return text_write_encoded(self, cf, lockfree, text);
}

/* text_write() past its fast cases: encoded into a bytes object. */
Py_NO_INLINE static int
text_write_encoded(textio *self, tconf *cf, int lockfree, PyObject *text)
{
    PyObject *b;
    int enc = cf->enc;
    const char *errors = (enc == CODEC_DECODER || enc == CODEC_CHARMAP ? NULL
                          : cf->errors_str);
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
        /* The charmap encoder (lockfree too) holds no state: nothing to
           note of it. */
        if (enc == CODEC_DECODER) {
            self->encoding_start_of_stream = 0;
        }
        b = PyObject_CallMethodOneArg(cf->encoder, &_Py_ID(encode), text);
        if (b != NULL && !PyBytes_Check(b)) {
            PyErr_Format(PyExc_TypeError,
                         "encoder should return a bytes object, not '%.200s'",
                         Py_TYPE(b)->tp_name);
            Py_CLEAR(b);
        }
        if (enc == CODEC_DECODER && b != NULL) {
            self->encoder_used = 1;
        }
    }
    if (b == NULL) {
        return -1;
    }
    int r = store_write(self, cf, lockfree, b, PyBytes_AS_STRING(b),
                        PyBytes_GET_SIZE(b));
    Py_DECREF(b);
    return r;
}

/* Give the codec's encoder the end of the text, and store what it still
   held (gh-79792). */
static int
text_finish_encoder(textio *self, tconf *cf)
{
    if (!self->encoder_used) {
        return 0;
    }
    self->encoder_used = 0;
    PyObject *b = PyObject_CallMethodObjArgs(
        cf->encoder, &_Py_ID(encode), &_Py_STR(empty), Py_True, NULL);
    if (b != NULL && !PyBytes_Check(b)) {
        PyErr_Format(PyExc_TypeError,
                     "encoder should return a bytes object, not '%.200s'",
                     Py_TYPE(b)->tp_name);
        Py_CLEAR(b);
    }
    if (b == NULL) {
        return -1;
    }
    int r = store_write(self, cf, 0, b, PyBytes_AS_STRING(b),
                        PyBytes_GET_SIZE(b));
    Py_DECREF(b);
    return r;
}

/* The decoder's characters not returned yet came from bytes taken already:
   move the buffer back to the text position (past characters a byte
   decoded to as a group, if it is among them). */
static int
decoder_sync(textio *self, tconf *cf)
{
    Py_ssize_t off, ci;
    dflags_t flags;
    (void)cache_chars(self, &ci);
    if (!cf->seekable
        || decoder_offset(self, cf->decoder, ci, &off, &flags) < 0)
    {
        textio_drop_chars(self);
        return cf->seekable ? -1 : 0;
    }
    PyObject *pos = store_tell(self, cf->buffer);
    Py_off_t p = pos ? PyLong_AsOff_t(pos) : -1;
    Py_XDECREF(pos);
    if (p == -1 && PyErr_Occurred()) {
        return -1;
    }
    p += off;
    textio_drop_chars(self);
    Py_CLEAR(self->rbuf);
    PyObject *res = _PyObject_CallMethod(cf->buffer, &_Py_ID(seek), "(O&)",
                                         PyLong_FromOff_t, p);
    Py_XDECREF(res);
    self->flags = flags;
    return res == NULL ? -1 : 0;
}

/* Before a write, truncate() or detach(): make the buffer's position the
   text position, dropping what was read ahead.  (Without the critical
   section, only the cache is dropped: the codec is native and the buffer
   is the store.) */
static int
text_sync(textio *self, tconf *cf, int lockfree)
{
    FT_ATOMIC_STORE_UINT8_RELAXED(self->decoded, 0);
    Py_ssize_t ci;
    if (cf->codec == CODEC_DECODER && cf->decoder != NULL
        && cache_chars(self, &ci) != NULL)
    {
        if (decoder_sync(self, cf) < 0) {
            return -1;
        }
    }
    else {
        textio_drop_chars(self);
    }
    return !lockfree && self->rbuf ? store_rewind(self, cf) : 0;
}

/* What text_write_call() returns to have write() done with the critical
   section after all (nothing was done). */
#define TEXT_RETRY Py_NotImplemented

/* write(); with lockfree, without the critical section (or TEXT_RETRY). */
static Py_ALWAYS_INLINE PyObject *
text_write_call(textio *self, PyObject *text, int lockfree)
{
    tconf *cf = textio_conf(self);
    if (cf == NULL) {
        return NULL;
    }
    if (lockfree && !cf->lockfree) {
        conf_put(cf);
        return TEXT_RETRY;
    }
    /* Over the buffer as the store, which checks that it is open when the
       bytes are stored, if any (and then there is nothing to sync but the
       cache: see text_sync()). */
    int stores = ((lockfree || self->nib) && cf->codec != CODEC_DECODER
                  && cf->encoder != NULL && PyUnicode_GET_LENGTH(text) > 0
                  && textio_exact(self));
    if (!stores && textio_check_closed(self, cf) < 0) {
        conf_put(cf);
        return NULL;
    }
    if (cf->encoder == NULL) {
        conf_put(cf);
        return textio_unsupported(self, "not writable");
    }
    Py_ssize_t textlen = PyUnicode_GET_LENGTH(text);
    int line_buffering = FT_ATOMIC_LOAD_UINT8_RELAXED(self->line_buffering);
    const char *writenl = cf->writetranslate ? cf->writenl : NULL;
    int haslf = (writenl != NULL || line_buffering)
                && PyUnicode_FindChar(text, '\n', 0, textlen, 1) != -1;
    int needflush = line_buffering
                    && (haslf || PyUnicode_FindChar(text, '\r', 0, textlen,
                                                    1) != -1);
    Py_INCREF(text);
    if (haslf && writenl != NULL) {
        Py_SETREF(text, _PyObject_CallMethod(text, &_Py_ID(replace), "ss",
                                             "\n", writenl));
    }
    int r = (text == NULL
             || ((FT_ATOMIC_LOAD_UINT8_RELAXED(self->decoded)
                  || (!lockfree && self->rbuf))
                 && text_sync(self, cf, lockfree) < 0)
             ? -1 : text_write(self, cf, lockfree, text));
    Py_XDECREF(text);
    if (r == _PyIO_NIBBLER_NO) {
        assert(lockfree);
        conf_put(cf);
        return TEXT_RETRY;
    }
    if (r == 0 && needflush) {
        r = _PyFile_Flush(cf->buffer);
    }
    conf_put(cf);
    return r < 0 ? NULL : PyLong_FromSsize_t(textlen);
}

Py_NO_INLINE static PyObject *
text_write_locked(textio *self, PyObject *text)
{
    PyObject *res;
    Py_BEGIN_CRITICAL_SECTION(self);
    res = text_write_call(self, text, 0);
    Py_END_CRITICAL_SECTION();
    return res;
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
    tconf *cf = conf_peek(self);
    if (cf != NULL && cf->lockfree) {
        PyObject *res = text_write_call(self, text, 1);
        if (res != TEXT_RETRY) {
            return res;
        }
    }
    return text_write_locked(self, text);
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
cookie_build(Py_off_t pos, dflags_t flags, Py_ssize_t skip)
{
    if (!flags.fresh && flags.v > UINT32_MAX) {
        PyErr_SetString(PyExc_OverflowError,
                        "the decoder's state doesn't fit a tell() cookie");
        return NULL;
    }
    if (skip > INT32_MAX) {
        PyErr_SetString(PyExc_OverflowError,
                        "too many characters to skip for a tell() cookie");
        return NULL;
    }
    unsigned char b[COOKIE_BUF_LEN] = {0};
    uint64_t f[3] = {(uint64_t)pos, flags.fresh ? 0 : flags.v, 0};
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

static PyObject *text_tell(textio *self, tconf *cf);

/* Does a "\n" at the position end a "\r\n" whose "\r" was returned? */
static int
text_skip_lf(textio *self)
{
    tcache copy;
    tcache *c = cache_get(self, &copy);
    int r = c->chars != NULL && c->skip_lf;
    cache_release(c);
    return r;
}

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
    PyObject *res;
    tconf *cf = textio_conf(self);
    if (cf == NULL) {
        return NULL;
    }
    if (cf->lockfree) {
        /* The buffer's tell() is all there is to it. */
        res = text_tell(self, cf);
        conf_put(cf);
        return res;
    }
    conf_put(cf);
    Py_BEGIN_CRITICAL_SECTION(self);
    cf = textio_conf(self);
    res = cf ? text_tell(self, cf) : NULL;
    conf_put(cf);
    Py_END_CRITICAL_SECTION();
    return res;
}

static PyObject *
text_tell(textio *self, tconf *cf)
{
    /* Over other buffers, flush first, as _io's does (their tell() might
       not count what they hold). */
    if (!cf->lockfree && !self->nib_ok
        && _PyFile_Flush((PyObject *)self) < 0)
    {
        return NULL;
    }
    if (textio_check_closed(self, cf) < 0) {
        return NULL;
    }
    if (!cf->seekable) {
        return textio_unsupported(self, "underlying stream is not seekable");
    }
    PyObject *buffer = cf->buffer;
    if (cf->codec != CODEC_DECODER || cf->decoder == NULL) {
        /* The buffer's position, with a native codec and a "\r" just
           returned that a "\n" there ends, flags 1 (see tcache). */
        PyObject *pos = (cf->lockfree
                         ? PyObject_CallMethodNoArgs(buffer, &_Py_ID(tell))
                         : store_tell(self, buffer));
        if (pos != NULL && cf->readable && text_skip_lf(self)) {
            Py_off_t p = PyLong_AsOff_t(pos);
            Py_SETREF(pos, p == -1 && PyErr_Occurred() ? NULL
                           : cookie_build(p, (dflags_t){1, 0}, 0));
        }
        return pos;
    }
    PyObject *pos = store_tell(self, buffer);
    if (pos == NULL) {
        return NULL;
    }
    Py_off_t p = PyLong_AsOff_t(pos);
    if (p == -1 && PyErr_Occurred()) {
        Py_DECREF(pos);
        return NULL;
    }
    Py_ssize_t ci;
    PyObject *chars = cache_chars(self, &ci);
    dflags_t flags = self->flags;
    if (chars != NULL && PyUnicode_GET_LENGTH(chars) > ci) {
        /* The byte position of the text position, if there is one; else
           where the characters were decoded from, and how many to skip. */
        Py_ssize_t off, start = -PyBytes_GET_SIZE(self->dspan);
        dflags_t dflags = self->dflags;
        int r = decoder_offset(self, cf->decoder, ci, &off, &flags);
        if (r < 0) {
            Py_DECREF(pos);
            return NULL;
        }
        Py_SETREF(pos, r > 0 ? cookie_build(p + off, flags, 0)
                             : cookie_build(p + start, dflags, ci));
    }
    else if (p != 0 && !flags.fresh && flags.v != 0) {
        Py_SETREF(pos, cookie_build(p, flags, 0));
    }
    return pos;
}

/* Reset the encoder to the stream's start, or past it (no BOM). */
static int
text_encoder_reset(textio *self, tconf *cf, int start)
{
    self->encoding_start_of_stream = start;
    if (cf->encoder == NULL) {
        return 0;
    }
    PyObject *res = (start
                     ? PyObject_CallMethodNoArgs(cf->encoder, &_Py_ID(reset))
                     : PyObject_CallMethodOneArg(cf->encoder,
                                                 &_Py_ID(setstate),
                                                 _PyLong_GetZero()));
    Py_XDECREF(res);
    return res == NULL ? -1 : 0;
}

/* The decoder at a position: reset at the stream's start (pos and flags
   0), else with flags. */
static int
text_decoder_reset(textio *self, tconf *cf, Py_off_t pos, uint32_t flags)
{
    if (cf->decoder == NULL) {
        return 0;
    }
    self->flags = (pos == 0 && flags == 0 ? FLAGS_FRESH
                   : (dflags_t){flags, 0});
    return decoder_setstate(cf->decoder, self->flags);
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
text_skip(textio *self, tconf *cf, Py_ssize_t n)
{
    store st = {.cf = cf, .buffer = cf->buffer};
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

/* After seek() to a cookie of tell()'s with flags 1 and a native codec:
   the "\n" at the position ends a "\r\n" (see text_skip_lf()). */
static int
text_seek_skip_lf(textio *self, tconf *cf)
{
    store st = {.cf = cf, .buffer = cf->buffer};
    st.c = cache_get(self, STORE_COPY(&st));
    Py_ssize_t avail = text_more(self, &st, 0);
    if (avail > 0) {
        st.c->skip_lf = 1;
        cache_put(self, st.c);
    }
    cache_release(st.c);
    store_release(&st);
    return avail < 0 ? -1 : 0;
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
    tconf *cf = textio_ready(self);
    if (cf == NULL) {
        return NULL;
    }
    PyObject *buffer = cf->buffer;
    PyObject *res = NULL;
    Py_INCREF(cookieObj);
    if (!cf->seekable) {
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
        Py_SETREF(cookieObj, text_tell(self, cf));
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
        else if (text_decoder_reset(self, cf, 0, 0) < 0
                 || text_encoder_reset(self, cf, pos == 0) < 0)
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
        || (!cf->readable && (c.dec_flags || c.bytes_to_feed
                                || c.chars_to_skip || c.need_eof))
        || (cf->codec != CODEC_DECODER
            && ((uint32_t)c.dec_flags > 1 || c.chars_to_skip
                || c.bytes_to_feed || c.need_eof)))
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
    if (text_decoder_reset(self, cf, c.start_pos, (uint32_t)c.dec_flags) < 0
        || text_encoder_reset(self, cf, start) < 0)
    {
        goto done;
    }
    if (c.chars_to_skip > 0 && text_skip(self, cf, c.chars_to_skip) < 0) {
        goto done;
    }
    if (cf->codec != CODEC_DECODER && c.dec_flags == 1
        && text_seek_skip_lf(self, cf) < 0)
    {
        goto done;
    }
    res = Py_NewRef(cookieObj);
done:
    Py_DECREF(cookieObj);
    conf_put(cf);
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
    tconf *cf = textio_conf(self);
    if (cf == NULL) {
        return NULL;
    }
    /* At the text position (gh-70346): pos is a byte count, not a tell()
       cookie. */
    PyObject *res = NULL;
    if (text_sync(self, cf, 0) == 0
        && _PyFile_Flush((PyObject *)self) == 0)
    {
        res = PyObject_CallMethodOneArg(cf->buffer, &_Py_ID(truncate), pos);
    }
    conf_put(cf);
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
    tconf *cf = textio_ready(self);
    if (cf == NULL) {
        return NULL;
    }
    PyObject *res = PyObject_CallMethodNoArgs(cf->buffer, &_Py_ID(flush));
    conf_put(cf);
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
    tconf *cf = textio_conf(self);
    if (cf == NULL) {
        return NULL;
    }
    PyObject *res = _io_TextIOWrapper_closed_get_impl(self);
    int r = res ? PyObject_IsTrue(res) : -1;
    Py_XDECREF(res);
    if (r != 0 || conf_peek(self) != cf) {
        /* Closed, or detached or set up again meanwhile. */
        conf_put(cf);
        return r < 0 ? NULL : Py_NewRef(Py_None);
    }
    PyObject *buffer = cf->buffer;
    if (self->finalizing) {
        res = PyObject_CallMethodOneArg(buffer, &_Py_ID(_dealloc_warn),
                                        (PyObject *)self);
        if (res == NULL) {
            PyErr_Clear();
        }
        Py_XDECREF(res);
    }
    PyObject *exc = NULL;
    if (text_finish_encoder(self, cf) < 0) {
        exc = PyErr_GetRaisedException();
    }
    else if (_PyFile_Flush((PyObject *)self) < 0) {
        exc = text_discard_writes(buffer, PyErr_GetRaisedException());
    }
    text_drop_reads(self);
    res = PyObject_CallMethodNoArgs(buffer, &_Py_ID(close));
    conf_put(cf);
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
    tconf *cf = textio_conf(self);
    if (cf == NULL) {
        return NULL;
    }
    if ((self->encoder_used && text_finish_encoder(self, cf) < 0)
        || _PyFile_Flush((PyObject *)self) < 0
        || text_sync(self, cf, 0) < 0)
    {
        conf_put(cf);
        return NULL;
    }
    /* Something called meanwhile may have detached it, or set it up
       again. */
    if (conf_peek(self) != cf) {
        conf_put(cf);
        return textio_buffer_get(self);
    }
    /* The same settings without the buffer: the attributes stay. */
    tconf *n = conf_copy(cf);
    if (n == NULL) {
        conf_put(cf);
        return NULL;
    }
    PyObject *buffer = Py_NewRef(cf->buffer);
    conf_put(cf);
    Py_CLEAR(n->buffer);
    n->lockfree = 0;
    conf_set(self, n, 0);
    text_drop_reads(self);
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
    return textio_call_getattr(self, &_Py_ID(name));
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
    if (conf_peek(self) == NULL) {
        Py_RETURN_TRUE;
    }
    return textio_call_getattr(self, &_Py_ID(closed));
}

/*[clinic input]
@getter
_io.TextIOWrapper.newlines
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_newlines_get_impl(textio *self)
/*[clinic end generated code: output=53aa03ac35573180 input=26b177526b166427]*/
{
    tconf *cf = textio_conf(self);
    if (cf == NULL) {
        return NULL;
    }
    int universal = cf->readuniversal && cf->readable;
    conf_put(cf);
    if (!universal) {
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
    tconf *cf = conf_get(self);
    if (cf == NULL) {
        return textio_buffer_get(self);
    }
    PyObject *errors = Py_NewRef(cf->errors);
    conf_put(cf);
    return errors;
}

static PyObject *
textio_encoding_get(PyObject *op, void *Py_UNUSED(closure))
{
    tconf *cf = conf_get(textio_CAST(op));
    PyObject *encoding = Py_NewRef(cf ? cf->encoding : Py_None);
    conf_put(cf);
    return encoding;
}

/*[clinic input]
@getter
_io.TextIOWrapper._CHUNK_SIZE -> Py_ssize_t
[clinic start generated code]*/

static Py_ssize_t
_io_TextIOWrapper__CHUNK_SIZE_get_impl(textio *self)
/*[clinic end generated code: output=3fe34b873b6b2c8c input=7e8abe69bf1cd463]*/
{
    PyObject *buffer = textio_buffer_get(self);
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
    PyObject *buffer = textio_buffer_get(self);
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
    return textio_buffer_get(self);
}

static PyObject *textio_encoding_get(PyObject *op, void *closure);

static PyObject *
textiowrapper_repr(PyObject *op)
{
    textio *self = textio_CAST(op);
    const char *type_name = Py_TYPE(self)->tp_name;
    if (conf_peek(self) == NULL) {
        return textio_buffer_get(self);
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
        PyObject *encoding = textio_encoding_get(op, NULL);
        Py_SETREF(res, encoding == NULL ? NULL
                       : PyUnicode_FromFormat("%U encoding=%R>", res,
                                              encoding));
        Py_XDECREF(encoding);
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
        && !(newline[0] == '\r' && newline[1] == '\n' && newline[2] == '\0'))
    {
        PyErr_Format(PyExc_ValueError,
                     "illegal newline value: %s", newline);
        return -1;
    }
    return 0;
}

/* Set up cf (not published yet) for newline. */
static int
set_newline(tconf *cf, const char *newline)
{
    PyObject *readnl = newline ? PyUnicode_FromString(newline) : NULL;
    if (newline && readnl == NULL) {
        return -1;
    }
    Py_XSETREF(cf->readnl, readnl);
    cf->readuniversal = (newline == NULL || newline[0] == '\0');
    cf->readtranslate = (newline == NULL);
    cf->writetranslate = (newline == NULL || newline[0] != '\0');
    cf->writenl = NULL;
    if (!cf->readuniversal && readnl != NULL) {
        cf->writenl = (const char *)PyUnicode_1BYTE_DATA(readnl);
        if (strcmp(cf->writenl, "\n") == 0) {
            cf->writenl = NULL;
        }
    }
#ifdef MS_WINDOWS
    else {
        cf->writenl = "\r\n";
    }
#endif
    return 0;
}

/* Set cf's errors (not published yet). */
static int
set_errors(tconf *cf, PyObject *errors)
{
    const char *s = PyUnicode_AsUTF8(errors);
    if (s == NULL) {
        return -1;
    }
    Py_XSETREF(cf->errors, Py_NewRef(errors));
    /* NULL is "strict", which the UTF-8 codec does fastest. */
    cf->errors_str = strcmp(s, "strict") == 0 ? NULL : s;
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

/* Set up the codec in cf (not published yet), with cf's errors: the
   decoder (if readable) and encoder (if writable), and how bytes map to
   characters. */
static int
text_set_codec(tconf *cf, PyObject *buffer, PyObject *codec_info)
{
    Py_CLEAR(cf->decoder);
    Py_CLEAR(cf->encoder);
    Py_CLEAR(cf->charmap);
    const char *errors = PyUnicode_AsUTF8(cf->errors);
    if (errors == NULL) {
        return -1;
    }
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
        cf->charmap = codec_charmap(codec_info);
        if (cf->charmap == NULL && PyErr_Occurred()) {
            return -1;
        }
        codec = cf->charmap ? CODEC_CHARMAP : CODEC_DECODER;
    }
    cf->enc = codec;
    /* Error handlers that keep one character per byte (or valid UTF-8
       sequence) keep the bytes of characters known. */
    int same = (strcmp(errors, "strict") == 0
                || strcmp(errors, "surrogateescape") == 0
                || (codec != CODEC_UTF8 && strcmp(errors, "replace") == 0));
    cf->codec = codec == CODEC_LATIN1 || same ? codec : CODEC_DECODER;
    cf->escapes = strcmp(errors, "surrogateescape") == 0;

    int r = textio_call_bool(buffer, &_Py_ID(readable));
    cf->readable = r > 0;
    if (r > 0 && cf->codec == CODEC_DECODER) {
        cf->decoder = _PyCodecInfo_GetIncrementalDecoder(codec_info, errors);
        if (cf->decoder == NULL) {
            return -1;
        }
    }
    if (r >= 0) {
        r = textio_call_bool(buffer, &_Py_ID(writable));
    }
    if (r > 0) {
        cf->encoder = _PyCodecInfo_GetIncrementalEncoder(codec_info, errors);
        if (cf->encoder == NULL) {
            return -1;
        }
    }
    return r < 0 ? -1 : 0;
}

/* Can calls by cf run without the critical section (see "Locking")?  Only
   over a buffer that is the store (nothing in rbuf) and, for reads, can
   hold a few characters more than a "\r" (an unbuffered one can't). */
static void
text_set_lockfree(textio *self, tconf *cf)
{
    cf->lockfree = (textio_exact(self) && cf->nibbler && self->nib_ok
                    && self->nib && self->rbuf == NULL
                    && cf->codec != CODEC_DECODER
                    && (!cf->readable
                        || _PyIONibbler_capacity(cf->buffer) >= 8));
}

/* The encoder writes a BOM only at the start of the stream. */
static int
text_fix_encoder_state(textio *self, tconf *cf)
{
    self->encoding_start_of_stream = 0;
    if (!cf->seekable || cf->encoder == NULL) {
        return 0;
    }
    PyObject *pos = PyObject_CallMethodNoArgs(cf->buffer, &_Py_ID(tell));
    int cmp = pos ? PyObject_RichCompareBool(pos, _PyLong_GetZero(), Py_EQ)
                  : -1;
    Py_XDECREF(pos);
    return cmp < 0 ? -1 : text_encoder_reset(self, cf, cmp);
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

/* Forget the characters decoded, with the critical section: what calls in
   progress know of them too (see cache_put()). */
static void
text_drop_cache(textio *self)
{
#ifdef Py_GIL_DISABLED
    span_free(_Py_atomic_exchange_ptr(&self->span, NULL));
    (void)_Py_atomic_add_uint64(&self->spans, 1);
#else
    Py_CLEAR(self->cache.chars);
    self->cache = (tcache){.cr_at = -1};
#endif
    Py_CLEAR(self->dspan);
}

static int
textiowrapper_clear(PyObject *op)
{
    textio *self = textio_CAST(op);
    conf_set(self, NULL, 1);
    text_drop_cache(self);
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
    /* Not set up meanwhile (as _io's): calls in progress keep the settings
       they took. */
    conf_set(self, NULL, 0);
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
    if (_PyUnicode_AsUTF8NoNUL(errors) == NULL
        || validate_newline(newline) < 0)
    {
        return -1;
    }

    text_drop_cache(self);
    Py_CLEAR(self->rbuf);
    self->rpos = 0;
    self->flags = FLAGS_FRESH;
    self->encoder_used = 0;
    FT_ATOMIC_STORE_UINT8_RELAXED(self->seennl, 0);
    FT_ATOMIC_STORE_UINT8_RELAXED(self->decoded, 0);
    FT_ATOMIC_STORE_SSIZE_RELAXED(self->chunk_size, 8192);
    FT_ATOMIC_STORE_UINT8_RELAXED(self->line_buffering, line_buffering);
    FT_ATOMIC_STORE_UINT8_RELAXED(self->write_through, write_through);

    tconf *cf = conf_new();
    if (cf == NULL) {
        return -1;
    }
    PyObject *codec_info = NULL;
    int r = -1;
    cf->encoding = text_encoding(encoding);
    if (cf->encoding == NULL) {
        goto done;
    }
    const char *enc = PyUnicode_AsUTF8(cf->encoding);
    if (enc == NULL) {
        goto done;
    }
    /* Check we have been asked for a real text encoding */
    codec_info = _PyCodec_LookupTextEncoding(enc, NULL);
    if (codec_info == NULL) {
        goto done;
    }
    cf->buffer = Py_NewRef(buffer);
    cf->nibbler = (char)_PyIO_is_nibbler_buffered_type(Py_TYPE(buffer));
    self->nib = self->nib_ok = cf->nibbler;
    if (set_errors(cf, errors) < 0
        || set_newline(cf, newline) < 0
        || text_set_codec(cf, buffer, codec_info) < 0)
    {
        goto done;
    }
    r = textio_call_bool(buffer, &_Py_ID(seekable));
    if (r < 0) {
        goto done;
    }
    cf->seekable = (char)r;
    r = PyObject_HasAttrWithError(buffer, &_Py_ID(read1));
    if (r < 0) {
        goto done;
    }
    cf->has_read1 = (char)r;
    r = text_fix_encoder_state(self, cf);
    if (r == 0) {
        text_set_lockfree(self, cf);
        conf_set(self, cf, 0);
        cf = NULL;
    }
done:
    conf_put(cf);
    Py_XDECREF(codec_info);
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
    int codec_change = encoding != Py_None || errors != Py_None;
    int change = codec_change || newline_obj != NULL;
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
                                                  self->write_through)) < 0)
    {
        return NULL;
    }
    tconf *cf = textio_conf(self);
    if (cf == NULL) {
        return NULL;
    }
    /* The old encoder ends its text first (gh-79792). */
    if ((codec_change && text_finish_encoder(self, cf) < 0)
        || _PyFile_Flush((PyObject *)self) < 0)
    {
        conf_put(cf);
        return NULL;
    }
    /* New settings, published at once (see "Locking"): the codec is kept
       unless it changes. */
    tconf *n = conf_copy(cf);
    if (n == NULL
        || (newline_obj != NULL && set_newline(n, newline) < 0))
    {
        goto error;
    }
    if (codec_change) {
        /* Use the current settings where new ones are not given. */
        if (encoding == Py_None) {
            encoding = Py_NewRef(cf->encoding);
            if (errors == Py_None) {
                errors = cf->errors;
            }
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
        Py_SETREF(n->encoding, encoding);
        const char *c_encoding = PyUnicode_AsUTF8(encoding);
        PyObject *codec_info = (c_encoding && set_errors(n, errors) == 0
                                ? _PyCodec_LookupTextEncoding(c_encoding, NULL)
                                : NULL);
        if (codec_info == NULL) {
            goto error;
        }
        int r = text_set_codec(n, cf->buffer, codec_info);
        Py_DECREF(codec_info);
        if (r < 0 || text_fix_encoder_state(self, n) < 0) {
            goto error;
        }
    }
    FT_ATOMIC_STORE_UINT8_RELAXED(self->line_buffering, line_buffering);
    FT_ATOMIC_STORE_UINT8_RELAXED(self->write_through, write_through);
    if (change) {
        text_set_lockfree(self, n);
        conf_set(self, n, 0);
        n = NULL;
        if (codec_change) {
            self->encoder_used = 0;
            self->flags = FLAGS_FRESH;
        }
        text_drop_cache(self);
    }
    conf_put(n);
    conf_put(cf);
    Py_RETURN_NONE;

error:
    conf_put(n);
    conf_put(cf);
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
    /* The settings' references are the object's (calls' references to
       them are to the settings). */
    tconf *cf = FT_ATOMIC_LOAD_PTR_RELAXED(self->conf);
    if (cf != NULL) {
        Py_VISIT(cf->buffer);
        Py_VISIT(cf->encoding);
        Py_VISIT(cf->errors);
        Py_VISIT(cf->encoder);
        Py_VISIT(cf->decoder);
        Py_VISIT(cf->charmap);
        Py_VISIT(cf->readnl);
    }
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

/*
    _io._nibbler.TextIOWrapper: text over a buffered object's bytes.

    The text layer keeps no bytes of its own: over an exact _io._nibbler
    buffered object it decodes the buffer's read-ahead in place and takes
    only the bytes of the text it returns, so the buffer's position is the
    text position (tell() is the buffer's, and write() and truncate() after
    a read act there: gh-82891, gh-70346), and written text goes straight to
    the buffer.  A partial character, a "\r" that may begin a "\r\n" or a
    line that hasn't ended stay in the buffer for the next call.  Over any
    other buffer (or one with an instance dict, which may override its
    methods), the read-ahead is kept here in rbuf, filled with read1().

    Codecs whose characters' bytes are known (UTF-8, Latin-1, ASCII and
    byte tables such as cp1252, with errors strict or surrogateescape, and
    replace but for UTF-8) decode a chunk of the unread bytes into a cache
    and take the bytes of each text they return from it, counted.  Other
    codecs go through the codec's incremental decoder, keeping the
    characters decoded but not returned yet (dchars), as _io does.

    Reads, seek(), tell() and the changes of the settings hold rlock, so
    that a read is atomic (each line once, whole).  The settings are an
    immutable object (tconf), replaced whole: writes take a reference to
    them, without a lock, and take rlock only after a read of a seekable
    stream, so that they never wait for a blocking read.  See
    InternalDocs/io_nibbler.md.
*/

#include "Python.h"
#include "pycore_call.h"                // _PyObject_CallMethod()
#include "pycore_codecs.h"              // _PyCodecInfo_GetIncrementalDecoder()
#include "pycore_fileutils.h"           // _Py_GetLocaleEncodingObject()
#include "pycore_interp.h"              // PyInterpreterState.unicode
#include "pycore_long.h"                // _PyLong_GetZero()
#include "pycore_object.h"              // _PyObject_GC_UNTRACK()
#include "pycore_pyatomic_ft_wrappers.h" // FT_ATOMIC_LOAD_UINT8_RELAXED()
#include "pycore_pyerrors.h"            // _PyErr_ChainExceptions1()
#include "pycore_pystate.h"             // _PyInterpreterState_GET()
#include "pycore_runtime.h"             // _PyRuntime
#include "pycore_unicodeobject.h"       // _PyUnicode_AsUTF8String()
#include "pycore_weakref.h"             // FT_CLEAR_WEAKREFS()

#include "../_iomodule.h"
#include "nibbler.h"

/*[clinic input]
module _io
class _io.TextIOWrapper "textio *" "clinic_state()->PyTextIOWrapper_Type"
[clinic start generated code]*/
/*[clinic end generated code: output=da39a3ee5e6b4b0d input=a649d1250a227bde]*/

/* How characters map to bytes. */
enum {
    CODEC_DECODER = 0,      /* through the codec's decoder */
    CODEC_UTF8,
    CODEC_LATIN1,
    CODEC_ASCII,
    CODEC_CHARMAP,          /* a byte-to-character table, `charmap` */
};

/* Newlines seen, for the newlines attribute. */
enum { SEEN_CR = 1, SEEN_LF = 2, SEEN_CRLF = 4 };

/* The settings, made whole by __init__(), reconfigure() and detach() and
   never changed once published in self->conf (but nib), which only calls
   holding rlock do.  Those use self->conf as it is, looking again after
   running other code (a nested detach() replaces it: the buffer it hands
   out gets no more calls from them, see textio_buffer()); other calls
   take a reference with conf_get(), so that what they use of them agrees
   and lives while they run. */
typedef struct {
    Py_ssize_t refs;            /* self->conf's, and calls' */
    /* The buffer is an exact nibbler one, whose bytes are used in place:
       cleared (atomically) once it has an instance dict. */
    uint8_t nib;
    PyObject *buffer;           /* NULL once detached */
    PyObject *encoding;
    PyObject *errors;
    PyObject *encoder;          /* NULL if not writable */
    PyObject *decoder;          /* CODEC_DECODER only, if readable */
    PyObject *charmap;          /* CODEC_CHARMAP's decoding table */
    PyObject *readnl;
    const char *errors_str;     /* errors, or NULL for "strict" */
    const char *writenl;        /* ASCII; NULL stands for "\n" */
    char codec;                 /* CODEC_* for reads */
    char enc;                   /* CODEC_* for writes (CHARMAP: ASCII only) */
    char readable;
    char seekable;
    char has_read1;
    char readuniversal;
    char readtranslate;
    char writetranslate;
    char line_buffering;
    char write_through;
    char quick;                 /* reads may try text_read_quick() */
    char wquick;                /* write() may store text that is its
                                   encoding in the buffer at once */
} tconf;

#define CONF_OBJECTS(X) \
    X(buffer) X(encoding) X(errors) X(encoder) X(decoder) X(charmap) X(readnl)

typedef struct {
    PyObject_HEAD
    nibbler_mutex rlock;
    Py_ssize_t rdepth;          /* calls of the holder of rlock nested in it */
    char rbusy;                 /* its read state is used across Python code */
    /* Held across the use of the codec's encoder (CODEC_DECODER), which may
       hold state, and the store of its bytes, so that they reach the buffer
       in its order: only to write, flush the encoder or reset it. */
    nibbler_mutex elock;
    tconf *conf;                /* NULL: not initialized */
    char finalizing;
    char encoding_start_of_stream;  /* the encoder may write a BOM */
    char encoder_used;          /* the encoder needs final=True at the end */
    Py_ssize_t chunk_size;
    /* With rlock: the last character returned is a "\r" that the "\n"
       next ends (newline ""; tell()'s flags 1); newlines seen; something
       was read since the last seek or write. */
    uint8_t after_cr;
    uint8_t seennl;
    uint8_t decoded;
    /* Over other buffers, read-ahead: rbuf[rpos:]. */
    PyObject *rbuf;
    Py_ssize_t rpos;
    /* Native codecs: cache[cache_ci:] are the characters of the store's
       bytes cache_p[0:cache_end - cache_p] (in cache_block, whose bytes,
       held, don't change), while the store's position is cache_p;
       cache_stop: invalid bytes follow them; cache_all: they were all the
       store had then; cache_cr: where the next "\r" is, when not before
       cache_ci (the length: none). */
    PyObject *cache;
    Py_ssize_t cache_ci;
    PyObject *cache_block;
    const char *cache_p;
    const char *cache_end;
    Py_ssize_t cache_cr;
    char cache_stop;
    char cache_all;
    /* With the decoder: dchars[dpos:] are the characters decoded but not
       returned, from the bytes dbytes taken from the store, which the
       decoder started on with flags dflags (dlost bytes before dbytes, not
       kept: see text_read_decoder()); at the store's position, the
       decoder holds nothing and has flags `flags` (fresh: as reset, not
       asked yet). */
    PyObject *dchars;
    Py_ssize_t dpos;
    PyObject *dbytes;
    Py_ssize_t dlost;
    unsigned long long dflags;
    unsigned long long flags;
    char fresh;
    PyObject *weakreflist;
    PyObject *dict;
} textio;

#define textio_CAST(op) ((textio *)(op))

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

/* New settings (a copy of `from`'s if not NULL), or NULL with MemoryError. */
static tconf *
conf_new(tconf *from)
{
    tconf *cf = PyMem_Calloc(1, sizeof(*cf));
    if (cf == NULL) {
        PyErr_NoMemory();
        return NULL;
    }
    cf->refs = 1;
    if (from != NULL) {
        /* (Not refs and nib, which other threads change meanwhile.) */
        memcpy(&cf->buffer, &from->buffer,
               sizeof(*cf) - offsetof(tconf, buffer));
        cf->nib = FT_ATOMIC_LOAD_UINT8_RELAXED(from->nib);
#define CONF_INCREF(f) Py_XINCREF(cf->f);
        CONF_OBJECTS(CONF_INCREF)
#undef CONF_INCREF
    }
    return cf;
}

/* Drop a reference to cf.  The last frees it: its memory once no thread
   can be in conf_get() with it. */
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
    if (--cf->refs > 0) {
        return;
    }
#endif
#define CONF_DECREF(f) Py_XDECREF(cf->f);
    CONF_OBJECTS(CONF_DECREF)
#undef CONF_DECREF
#ifdef Py_GIL_DISABLED
    _PyMem_FreeDelayed(cf, sizeof(*cf));
#else
    PyMem_Free(cf);
#endif
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
        /* Unless its last reference is gone (replaced meanwhile), take
           one. */
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

/* Publish cf (stolen; NULL: not initialized), with rlock.  Returns the
   settings replaced, to drop (conf_put()) once rlock is released: their
   objects' finalizers may use self. */
static tconf *
conf_swap(textio *self, tconf *cf)
{
    tconf *old = self->conf;
    FT_ATOMIC_STORE_PTR_RELEASE(self->conf, cf);
    return old;
}

/* Raise ValueError unless cf has a buffer. */
static int
conf_attached(tconf *cf)
{
    if (cf != NULL && cf->buffer != NULL) {
        return 0;
    }
    PyErr_SetString(PyExc_ValueError,
                    cf ? "underlying buffer has been detached"
                       : "I/O operation on uninitialized object");
    return -1;
}

/* Is the buffer there?  Else ValueError.  (Looking at the settings
   without a reference: their memory lives while this thread can be
   here.) */
static int
textio_attached(textio *self)
{
    return conf_attached(FT_ATOMIC_LOAD_PTR_ACQUIRE(self->conf));
}

/* A new reference to the settings, with a buffer: else NULL with
   ValueError. */
static tconf *
textio_conf(textio *self)
{
    tconf *cf = conf_get(self);
    if (conf_attached(cf) < 0) {
        conf_put(cf);
        return NULL;
    }
    return cf;
}

/* With rlock, after running other code: a new reference to the buffer,
   else NULL with ValueError (a nested detach() took it; nested __init__()
   is refused, so there are settings). */
static PyObject *
textio_buffer(textio *self)
{
    PyObject *buffer = self->conf->buffer;
    if (buffer == NULL) {
        (void)conf_attached(self->conf);
        return NULL;
    }
    return Py_NewRef(buffer);
}

static inline int
textio_exact(textio *self)
{
    return (((PyHeapTypeObject *)Py_TYPE(self))->ht_token
            == &_PyIONibbler_textiowrapper_spec);
}

/* Raise ValueError if cf's buffer is closed (a subclass may override
   closed). */
static int
textio_check_closed(textio *self, tconf *cf)
{
    if (!textio_exact(self)) {
        PyObject *res = _PyIOBase_check_closed((PyObject *)self, Py_True);
        return res == NULL ? -1 : 0;
    }
    int r;
    PyObject *buffer = cf->buffer;
    if (FT_ATOMIC_LOAD_UINT8_RELAXED(cf->nib)) {
        /* (Which doesn't use it after its raw stream's closed.) */
        r = _PyIONibbler_closed(buffer);
    }
    else {
        /* (Held: a nested detach() may drop it meanwhile.) */
        Py_INCREF(buffer);
        PyObject *res = PyObject_GetAttr(buffer, &_Py_ID(closed));
        Py_DECREF(buffer);
        r = res == NULL ? -1 : PyObject_IsTrue(res);
        Py_XDECREF(res);
    }
    if (r > 0) {
        PyErr_SetString(PyExc_ValueError, "I/O operation on closed file.");
    }
    return r == 0 ? 0 : -1;
}

/* Take rlock, also in a call nested in one holding it (from Python code
   it runs: a decoder, a Python buffer, a subclass's flush()).  A nested
   call must not change what the outer one uses: see
   textio_refuse_nested().  Release with textio_leave(). */
static int
textio_lock(textio *self)
{
    if (nibbler_mutex_is_mine(&self->rlock)) {
        self->rdepth++;
        return 0;
    }
    int r = nibbler_mutex_lock(&self->rlock, (PyObject *)self, 1);
    if (r > 0) {
        /* Taken from a holder gone in a fork (or hung at exit). */
        self->rdepth = self->rbusy = 0;
    }
    return r < 0 ? -1 : 0;
}

/* RuntimeError for a call nested in one holding rlock that would change
   what that call uses: the settings (__init__(), reconfigure()) or the
   read state (reads); with busy, only while the outer call uses the read
   state across Python code (reads, going back to the text position,
   skipping characters after a seek): seek(), tell(), close(), and going
   back to the text position.  Other calls (detach(), writes, tell()
   from another seek()) may nest. */
static int
textio_refuse_nested(textio *self, int busy)
{
    if (self->rdepth > 0 && (!busy || self->rbusy)) {
        PyErr_Format(PyExc_RuntimeError, "reentrant call inside %R",
                     (PyObject *)self);
        return -1;
    }
    return 0;
}

static void
textio_leave(textio *self)
{
    if (self->rdepth > 0) {
        self->rdepth--;
    }
    else {
        nibbler_mutex_unlock(&self->rlock);
    }
}

static int
textio_enter(textio *self, int check_closed)
{
    if (textio_lock(self) < 0) {
        return -1;
    }
    if (textio_attached(self) < 0
        || (check_closed && textio_check_closed(self, self->conf) < 0))
    {
        textio_leave(self);
        return -1;
    }
    return 0;
}

/* Before cf is published: may reads try text_read_quick(), and write()
   store text that is its encoding at once?  (Whether the buffer's own
   bytes are used, nib, is checked apart.) */
static void
conf_set_quick(textio *self, tconf *cf)
{
    int exact = cf->buffer != NULL && textio_exact(self);
    cf->quick = exact && cf->readable && cf->codec != CODEC_DECODER;
    cf->wquick = (exact && cf->encoder != NULL && cf->enc != CODEC_DECODER
                  && !cf->line_buffering
                  && (!cf->writetranslate || cf->writenl == NULL));
}

/* What reads leave here (rbuf, dchars): writes go back to the text
   position first. */
static inline int
textio_holds(textio *self)
{
    return ((self->rbuf != NULL && self->rpos < PyBytes_GET_SIZE(self->rbuf))
            || (self->dchars != NULL
                && self->dpos < PyUnicode_GET_LENGTH(self->dchars)));
}

/* Forget the characters decoded and the read-ahead: the position moves. */
static void
textio_drop_reads(textio *self)
{
    Py_CLEAR(self->dchars);
    Py_CLEAR(self->dbytes);
    Py_CLEAR(self->rbuf);
    Py_CLEAR(self->cache);
    Py_CLEAR(self->cache_block);
    self->dpos = self->rpos = self->dlost = 0;
    self->after_cr = 0;
    FT_ATOMIC_STORE_UINT8_RELAXED(self->decoded, 0);
}

/*
 * The codec's incremental decoder, kept holding nothing: what it held is
 * left in the store, and its flags (an unsigned long long, as iso2022_kr's
 * go past 32 bits) kept with the position.
 */

static int
decoder_getflags(PyObject *decoder, unsigned long long *flags,
                 Py_ssize_t *held)
{
    PyObject *state = PyObject_CallMethodNoArgs(decoder, &_Py_ID(getstate));
    PyObject *buf;
    int ok = (state != NULL && PyTuple_Check(state)
              && PyArg_ParseTuple(state, "OK;illegal decoder state", &buf,
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

/* Set the decoder to (b"", flags), or reset it (fresh). */
static int
decoder_setstate(PyObject *decoder, unsigned long long flags, int fresh)
{
    PyObject *res = (fresh
                     ? PyObject_CallMethodNoArgs(decoder, &_Py_ID(reset))
                     : _PyObject_CallMethod(decoder, &_Py_ID(setstate),
                                            "((yK))", "", flags));
    Py_XDECREF(res);
    return res == NULL ? -1 : 0;
}

/* The decoding of s[0:len] by the decoder, holding nothing with flags
   *flags: *used gets the bytes decoded (not those it held, which it is
   made to forget), *flags its flags after them. */
static PyObject *
decoder_decode(PyObject *decoder, const char *s, Py_ssize_t len, int final,
               Py_ssize_t *used, unsigned long long *flags)
{
    PyObject *input = PyBytes_FromStringAndSize(s, len);
    PyObject *chars = input ? PyObject_CallMethodObjArgs(
        decoder, &_Py_ID(decode), input, final ? Py_True : Py_False, NULL)
        : NULL;
    Py_XDECREF(input);
    if (chars != NULL && !PyUnicode_Check(chars)) {
        PyErr_Format(PyExc_TypeError,
                     "decoder should return a string result, not '%.200s'",
                     Py_TYPE(chars)->tp_name);
        Py_CLEAR(chars);
    }
    Py_ssize_t held = 0;
    if (chars == NULL || decoder_getflags(decoder, flags, &held) < 0
        || (held > 0 && decoder_setstate(decoder, *flags, 0) < 0))
    {
        Py_XDECREF(chars);
        return NULL;
    }
    *used = len - held;
    return chars;
}

/* Where in dbytes the first ci characters of dchars end, decoding it again
   (the fewest bytes giving at least that many): *off, with *flags the
   decoder's there.  Returns 1 if exactly there, 0 if past characters a
   byte decoded to as a group, or -1. */
static int
decoder_offset(textio *self, Py_ssize_t ci, Py_ssize_t *off,
               unsigned long long *flags)
{
    /* The decoder runs Python code, which may use self. */
    PyObject *span = Py_NewRef(self->dbytes);
    Py_ssize_t lo = 0, hi = PyBytes_GET_SIZE(span), used = 0, n = 0;
    int r = -1;
    while (lo <= hi) {
        Py_ssize_t mid = lo + (hi - lo) / 2;
        *flags = self->dflags;
        PyObject *chars = NULL;
        if (decoder_setstate(self->conf->decoder, *flags, 0) == 0) {
            chars = decoder_decode(self->conf->decoder,
                                   PyBytes_AS_STRING(span), mid, 0, &used,
                                   flags);
        }
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
    *off = lo;
    r = n == ci && used == lo;
done:
    Py_DECREF(span);
    /* Back where reads left it. */
    if (r >= 0 && decoder_setstate(self->conf->decoder, self->flags, 0) < 0) {
        r = -1;
    }
    return r;
}

/* How many bytes p[0:len] starts with are ASCII (a word at a time). */
static Py_ssize_t
ascii_prefix(const char *p, Py_ssize_t len)
{
    Py_ssize_t i = 0;
    for (; i + 8 <= len; i += 8) {
        uint64_t w;
        memcpy(&w, p + i, 8);
        if (w & 0x8080808080808080ull) {
            break;
        }
    }
    while (i < len && !(p[i] & 0x80)) {
        i++;
    }
    return i;
}

/* A native codec's decoding of s[0:len] (but a partial character at the
   end, unless final): *used gets the bytes decoded. */
static PyObject *
native_decode(textio *self, const char *s, Py_ssize_t len, int final,
              Py_ssize_t *used)
{
    tconf *cf = self->conf;
    const char *errors = cf->errors_str;
    *used = len;
    switch (cf->codec) {
    case CODEC_UTF8: {
        /* (Stateful, which doesn't count the characters first.) */
        PyObject *res = PyUnicode_DecodeUTF8Stateful(s, len, errors, used);
        if (res != NULL && final && *used < len) {
            /* A partial character at the end: the error. */
            Py_SETREF(res, PyUnicode_DecodeUTF8(s, len, errors));
            *used = len;
        }
        return res;
    }
    case CODEC_LATIN1:
        return PyUnicode_DecodeLatin1(s, len, errors);
    case CODEC_ASCII:
        return PyUnicode_DecodeASCII(s, len, errors);
    default:
        /* ASCII decodes as itself, faster. */
        if (ascii_prefix(s, len) == len) {
            return PyUnicode_DecodeASCII(s, len, errors);
        }
        return PyUnicode_DecodeCharmap(s, len, cf->charmap, errors);
    }
}

/* The bytes of chars[i:i+k] (native codecs).  With UTF-8, surrogates were
   bytes escaped with surrogateescape: one each. */
static Py_ssize_t
native_bytes(textio *self, PyObject *chars, Py_ssize_t i, Py_ssize_t k)
{
    if (self->conf->codec != CODEC_UTF8 || PyUnicode_IS_ASCII(chars)) {
        return k;
    }
    Py_ssize_t n = k;
    if (PyUnicode_KIND(chars) == PyUnicode_1BYTE_KIND) {
        /* Two bytes for each of 0x80-0xff (in blocks counted in 8 bits,
           which vectorize). */
        const Py_UCS1 *d = PyUnicode_1BYTE_DATA(chars) + i;
        for (Py_ssize_t j = 0; j < k; j += 255) {
            uint8_t extra = 0;
            for (Py_ssize_t e = Py_MIN(k, j + 255), m = j; m < e; m++) {
                extra += d[m] >> 7;
            }
            n += extra;
        }
        return n;
    }
    if (PyUnicode_KIND(chars) == PyUnicode_2BYTE_KIND) {
        /* Up to two more each (in blocks counted in 16 bits, which
           vectorize). */
        const Py_UCS2 *d = PyUnicode_2BYTE_DATA(chars) + i;
        for (Py_ssize_t j = 0; j < k; j += 16384) {
            uint16_t extra = 0;
            for (Py_ssize_t e = Py_MIN(k, j + 16384), m = j; m < e; m++) {
                uint16_t c = d[m];
                extra += (uint16_t)((c > 0x7f) + (c > 0x7ff)
                                    - 2 * ((c & 0xf800) == 0xd800));
            }
            n += extra;
        }
        return n;
    }
    for (Py_ssize_t j = i; j < i + k; j++) {
        Py_UCS4 c = PyUnicode_READ_CHAR(chars, j);
        n += (c >= 0x80) + (c >= 0x800) + (c >= 0x10000)
             - 2 * Py_UNICODE_IS_SURROGATE(c);
    }
    return n;
}

/* The bytes of up to n characters at p[0:len] (native codecs; counting
   UTF-8 lead bytes, which decoding checks). */
static Py_ssize_t
native_span(textio *self, const char *p, Py_ssize_t len, Py_ssize_t n)
{
    if (n >= len || self->conf->codec != CODEC_UTF8) {
        return Py_MIN(n, len);
    }
    Py_ssize_t i = ascii_prefix(p, n);
    n -= i;
    while (i < len && n > 0) {
        i++;
        n--;
        while (i < len && (p[i] & 0xc0) == 0x80) {
            i++;
        }
    }
    return i;
}

/* Where a UnicodeDecodeError found invalid bytes. */
static int
decode_error(Py_ssize_t *start, Py_ssize_t *end)
{
    if (!PyErr_ExceptionMatches(PyExc_UnicodeDecodeError)) {
        return -1;
    }
    PyObject *exc = PyErr_GetRaisedException();
    int r = (PyUnicodeDecodeError_GetStart(exc, start) < 0
             || PyUnicodeDecodeError_GetEnd(exc, end) < 0) ? -1 : 0;
    PyErr_Clear();
    PyErr_SetRaisedException(exc);
    return r;
}

/*
 * The store: the unread bytes a read works on, in place.  Over an exact
 * nibbler buffer they are its read-ahead, used with its lock (and its I/O
 * role to read more, see _iomodule.h); else rbuf[rpos:], filled with
 * read1().  Reads hold rlock throughout.
 */

typedef struct {
    textio *self;
    PyObject *buffer;   /* the store's, kept while it is used */
    char nib;           /* the buffer's own bytes */
    char io;            /* with the buffer's I/O role */
    char eof;           /* nothing more after p[0:avail] */
    char blocked;       /* the stream would block after them */
    char full;          /* the store can't hold more of them */
    PyObject *block;    /* borrowed: holds p[0:avail] */
    const char *p;
    Py_ssize_t avail;
} tstore;

/* Take k of the unread bytes, and look at the rest. */
static void
store_skip(tstore *st, Py_ssize_t k)
{
    textio *self = st->self;
    if (st->nib) {
        st->avail = _PyIONibbler_view(st->buffer, k, &st->block, &st->p);
    }
    else {
        self->rpos += k;
        st->block = self->rbuf;
        st->avail = self->rbuf ? PyBytes_GET_SIZE(self->rbuf) - self->rpos : 0;
        st->p = self->rbuf ? PyBytes_AS_STRING(self->rbuf) + self->rpos : NULL;
    }
}

/* Start using the store (with io, able to read more).  Returns 0 or -1. */
static int
store_begin(tstore *st, int io)
{
    textio *self = st->self;
    if (st->buffer == NULL && (st->buffer = textio_buffer(self)) == NULL) {
        return -1;
    }
    st->nib = FT_ATOMIC_LOAD_UINT8_RELAXED(self->conf->nib);
    st->io = io;
    if (st->nib) {
        Py_ssize_t r = _PyIONibbler_begin(st->buffer, io, &st->block, &st->p);
        if (r == _PyIO_NIBBLER_NEEDIO) {
            st->io = 1;
            r = _PyIONibbler_begin(st->buffer, 1, &st->block, &st->p);
        }
        if (r >= 0) {
            st->avail = r;
            return 0;
        }
        if (r != _PyIO_NIBBLER_NO) {
            /* Nothing is held: store_end() has nothing to release. */
            st->nib = st->io = 0;
            return -1;
        }
        /* It got an instance dict: its methods from now on. */
        FT_ATOMIC_STORE_UINT8_RELAXED(self->conf->nib, 0);
        st->nib = 0;
    }
    store_skip(st, 0);
    return 0;
}

/* Stop using the store (with release, for good). */
static void
store_end(tstore *st, int release)
{
    if (st->nib) {
        _PyIONibbler_end(st->buffer, st->io);
        st->nib = 0;
    }
    if (release) {
        Py_CLEAR(st->buffer);
    }
}

/* Read more after the unread bytes (with io).  Sets eof, blocked or full
   instead when there are none; returns -1 on error. */
static int
store_fill(tstore *st)
{
    textio *self = st->self;
    Py_ssize_t chunk = FT_ATOMIC_LOAD_SSIZE_RELAXED(self->chunk_size);
    Py_ssize_t n;
    if (conf_attached(self->conf) < 0) {
        /* A nested detach() took it: no more calls on it. */
        return -1;
    }
    if (st->nib) {
        n = _PyIONibbler_fill(st->buffer, chunk);
    }
    else {
        /* Growing geometrically, so that rbuf is copied O(1) times. */
        PyObject *res = _PyObject_CallMethod(
            st->buffer, self->conf->has_read1 ? &_Py_ID(read1) : &_Py_ID(read),
            "n", Py_MAX(chunk, st->avail));
        if (res == NULL) {
            return -1;
        }
        n = res == Py_None ? _PyIO_NIBBLER_BLOCKED : 0;
        Py_buffer view;
        if (res != Py_None) {
            if (PyObject_GetBuffer(res, &view, PyBUF_SIMPLE) < 0) {
                PyErr_Format(PyExc_TypeError,
                             "underlying %s() should have returned a "
                             "bytes-like object, not '%.200s'",
                             self->conf->has_read1 ? "read1" : "read",
                             Py_TYPE(res)->tp_name);
                Py_DECREF(res);
                return -1;
            }
            PyObject *rbuf = PyBytes_FromStringAndSize(NULL,
                                                       st->avail + view.len);
            if (rbuf != NULL) {
                if (st->avail > 0) {
                    memcpy(PyBytes_AS_STRING(rbuf), st->p, st->avail);
                }
                memcpy(PyBytes_AS_STRING(rbuf) + st->avail, view.buf,
                       view.len);
                Py_XSETREF(self->rbuf, rbuf);
                self->rpos = 0;
                n = view.len;
            }
            PyBuffer_Release(&view);
            if (rbuf == NULL) {
                n = -1;
            }
        }
        Py_DECREF(res);
    }
    if (n == -1) {
        return -1;
    }
    st->eof |= n == 0;
    st->blocked |= n == _PyIO_NIBBLER_BLOCKED;
    st->full |= n == _PyIO_NIBBLER_FULL;
    store_skip(st, 0);
    return 0;
}

/* Put data[0:len] back in front of the unread bytes (a failed read). */
static int
store_unread(tstore *st, const char *data, Py_ssize_t len)
{
    textio *self = st->self;
    if (len == 0) {
        return 0;
    }
    if (st->nib) {
        return _PyIONibbler_unread(st->buffer, data, len);
    }
    PyObject *rbuf = PyBytes_FromStringAndSize(NULL, len + st->avail);
    if (rbuf == NULL) {
        return -1;
    }
    memcpy(PyBytes_AS_STRING(rbuf), data, len);
    if (st->avail > 0) {
        memcpy(PyBytes_AS_STRING(rbuf) + len, st->p, st->avail);
    }
    Py_XSETREF(self->rbuf, rbuf);
    self->rpos = 0;
    return 0;
}

/*
 * Newlines
 */

/* The first ch (a control character) in s[0:end) of a str's data, or
   NULL. */
static const char *
find_char(int kind, const char *s, const char *end, Py_UCS4 ch)
{
    if (kind == PyUnicode_1BYTE_KIND) {
        return memchr(s, (char)ch, end - s);
    }
    /* Its low byte, with memchr. */
#if PY_LITTLE_ENDIAN
    const int low = 0;
#else
    const int low = kind - 1;
#endif
    for (const char *p = s + low; p < end; p++) {
        p = memchr(p, (char)ch, end - p);
        if (p == NULL) {
            break;
        }
        const char *c = p - low;
        if ((c - s) % kind == 0 && PyUnicode_READ(kind, c, 0) == ch) {
            return c;
        }
    }
    return NULL;
}

/* Copy r[0:end) (characters of kind) to o (if not NULL) with "\r\n" and
   "\r" made "\n", adding the newlines met to *seen (SEEN_LF only if not
   there).  Returns the characters copied. */
static Py_ssize_t
translate_newlines(int kind, const char *r, const char *end, char *o,
                   int *seen)
{
    Py_ssize_t n = 0;
    for (;;) {
        const char *cr = find_char(kind, r, end, '\r');
        const char *stop = cr ? cr : end;
        if (!(*seen & SEEN_LF) && find_char(kind, r, stop, '\n') != NULL) {
            *seen |= SEEN_LF;
        }
        if (o != NULL) {
            memcpy(o + n * kind, r, stop - r);
        }
        n += (stop - r) / kind;
        if (cr == NULL) {
            return n;
        }
        if (o != NULL) {
            PyUnicode_WRITE(kind, o, n, '\n');
        }
        n++;
        r = cr + kind;
        int crlf = r < end && PyUnicode_READ(kind, r, 0) == '\n';
        *seen |= crlf ? SEEN_CRLF : SEEN_CR;
        r += crlf * kind;
    }
}

/* res (stolen) with "\r\n" and "\r" made "\n": out characters. */
static PyObject *
text_translate(PyObject *res, Py_ssize_t out)
{
    PyObject *t = res ? PyUnicode_New(out, PyUnicode_MAX_CHAR_VALUE(res))
                  : NULL;
    if (t != NULL) {
        int kind = PyUnicode_KIND(res), seen = SEEN_LF;
        const char *r = PyUnicode_DATA(res);
        Py_ssize_t n = translate_newlines(
            kind, r, r + PyUnicode_GET_LENGTH(res) * kind,
            PyUnicode_DATA(t), &seen);
        assert(n == out);
        (void)n;
    }
    Py_XDECREF(res);
    return t;
}

/* Note what text_take() found, once its text is taken: the newlines seen
   (bits 0-2) and after_cr (bit 3). */
static void
text_note(textio *self, int note)
{
    FT_ATOMIC_STORE_UINT8_RELAXED(self->seennl, self->seennl | (note & 7));
    self->after_cr = note >> 3;
}

/* Take text from chars[i:]: up to `want` characters (-1: no limit), or
   with line, to the end of the first line (also as far as it goes, with
   partial).  With universal newlines a "\r" is taken only once what
   follows it is known (final: nothing does), translated with
   readtranslate.  Returns the text and sets *k to the characters it takes,
   *found to whether the line or want ended, and *note (see text_note());
   NULL with *k 0 when nothing can be taken yet (or on error). */
static PyObject *
text_take(textio *self, PyObject *chars, Py_ssize_t i, Py_ssize_t want,
          int line, int final, int partial, Py_ssize_t *k, int *found,
          int *note)
{
    int kind = PyUnicode_KIND(chars);
    const char *s = (const char *)PyUnicode_DATA(chars) + i * kind;
    Py_ssize_t avail = PyUnicode_GET_LENGTH(chars) - i;
    const char *end = s + avail * kind;
#define AT(j) PyUnicode_READ(kind, s, (j))
    Py_ssize_t n = 0, out = 0;
    int seen = 0, translate = 0, after_cr = 0;
    *found = 0;
    /* A "\n" first ends the "\r\n" whose "\r" was taken already. */
    int lf_done = self->after_cr && avail > 0 && AT(0) == '\n';
    tconf *cf = self->conf;
    if (!cf->readuniversal && line) {
        Py_ssize_t safe;
        n = _PyIO_find_line_ending(0, 0, cf->readnl, kind, s, end, &safe);
        *found = n >= 0;
        if (n < 0) {
            n = final ? avail : partial ? safe : 0;
        }
        if (want >= 0 && (n > want || (!*found && avail >= want))) {
            n = want;
            *found = 1;
        }
        out = n;
    }
    else if (!cf->readuniversal) {
        n = out = want < 0 ? avail : Py_MIN(avail, want);
    }
    else {
        /* Runs between "\r"s (and with line, up to a "\n"). */
        for (;;) {
            Py_ssize_t lim = want < 0 ? avail - n : Py_MIN(avail - n,
                                                           want - out);
            const char *r = s + n * kind;
            const char *lf = line ? find_char(kind, r, r + lim * kind, '\n')
                             : NULL;
            const char *cr = find_char(kind, r, lf ? lf : r + lim * kind,
                                       '\r');
            Py_ssize_t run = ((cr ? cr : lf ? lf + kind : r + lim * kind)
                              - r) / kind;
            if (!(self->seennl & SEEN_LF) && !(seen & SEEN_LF)
                && (lf != NULL && cr == NULL
                    ? !(lf == s && lf_done)
                    : find_char(kind, r + (n == 0 && lf_done) * kind,
                                r + run * kind, '\n') != NULL))
            {
                seen |= SEEN_LF;
            }
            n += run;
            out += run;
            if (cr == NULL) {
                *found = lf != NULL;
                break;
            }
            if (n + 1 == avail && !final) {
                break;
            }
            int crlf = n + 1 < avail && AT(n + 1) == '\n';
            seen |= crlf ? SEEN_CRLF : SEEN_CR;
            if (cf->readtranslate) {
                translate = 1;
                n += 1 + crlf;
                out++;
            }
            else if (crlf && (want < 0 || out + 2 <= want)) {
                n += 2;
                out += 2;
            }
            else {
                n++;
                out++;
                after_cr = crlf;
            }
            if (line || (want >= 0 && out >= want)) {
                *found = 1;
                break;
            }
        }
        if (line && !*found) {
            /* No end of line yet: what can be taken of it, if partial. */
            if (want >= 0 && out >= want) {
                *found = 1;
            }
            else if (!final && !partial) {
                n = out = 0;
                seen = translate = after_cr = 0;
            }
        }
    }
    *found |= want >= 0 && out >= want;
    *k = n;
    *note = seen | (after_cr << 3);
    if (n == 0) {
        return NULL;
    }
    PyObject *res = (i == 0 && n == avail ? Py_NewRef(chars)
                     : PyUnicode_Substring(chars, i, i + n));
    return translate ? text_translate(res, out) : res;
#undef AT
}

/*
 * Reading (with rlock)
 */

/* The bytes a read took, to give back if it then fails, so that the next
   read returns them (as the buffer does with bytes, gh-51571): (bytes
   object, offset, length) of each piece, holding them (the store never
   writes into bytes held), len bytes in all. */
typedef struct {
    PyObject *list;
    Py_ssize_t len;
} tkeep;

static int
keep_add(tkeep *kp, PyObject *block, const char *p, Py_ssize_t n)
{
    PyObject *t = Py_BuildValue("(Onn)", block,
                                (Py_ssize_t)(p - PyBytes_AS_STRING(block)), n);
    if (t != NULL && kp->list == NULL) {
        kp->list = PyList_New(0);
    }
    int r = t != NULL && kp->list != NULL ? PyList_Append(kp->list, t) : -1;
    Py_XDECREF(t);
    kp->len += r == 0 ? n : 0;
    return r;
}

/* The text read so far: NULL, one str, or a list of them (stolen). */
static PyObject *
join_pieces(PyObject *pieces)
{
    if (pieces == NULL || PyUnicode_Check(pieces)) {
        return pieces ? pieces : Py_GetConstant(Py_CONSTANT_EMPTY_STR);
    }
    PyObject *res = PyUnicode_Join(&_Py_STR(empty), pieces);
    Py_DECREF(pieces);
    return res;
}

static int
add_piece(PyObject **pieces, PyObject *text)
{
    if (*pieces == NULL) {
        *pieces = text;
        return 0;
    }
    if (PyUnicode_Check(*pieces)) {
        PyObject *list = PyList_New(1);
        if (list == NULL) {
            Py_DECREF(text);
            return -1;
        }
        PyList_SET_ITEM(list, 0, *pieces);
        *pieces = list;
    }
    int r = PyList_Append(*pieces, text);
    Py_DECREF(text);
    return r;
}

/* Are the cache's characters those at the store's position? */
static inline int
cache_valid(textio *self, tstore *st)
{
    return (self->cache != NULL && st->p == self->cache_p
            && st->avail >= self->cache_end - self->cache_p
            && self->cache_ci < PyUnicode_GET_LENGTH(self->cache));
}

/* Decode the store's first span bytes into the cache (invalid bytes end
   it: cache_stop).  Invalid bytes first are taken, and raised (once),
   unless the call took text already (taken): then the cache is empty.
   Returns 0 or -1. */
static int
cache_fill(textio *self, tstore *st, Py_ssize_t span, int taken)
{
    Py_ssize_t used, start, end;
    span = Py_MIN(span, st->avail);
    int stop = 0;
    PyObject *chars = native_decode(self, st->p, span,
                                    st->eof && span == st->avail, &used);
    if (chars == NULL && decode_error(&start, &end) == 0) {
        if (start == 0 && !taken) {
            store_skip(st, Py_MIN(end, st->avail));
            return -1;
        }
        PyErr_Clear();
        chars = native_decode(self, st->p, start, 0, &used);
        stop = 1;
    }
    if (chars == NULL) {
        return -1;
    }
    Py_XSETREF(self->cache, chars);
    Py_XSETREF(self->cache_block, Py_XNewRef(st->block));
    self->cache_ci = 0;
    self->cache_cr = -1;
    self->cache_p = st->p;
    self->cache_end = st->p + used;
    self->cache_stop = (char)stop;
    self->cache_all = span == st->avail;
    return 0;
}

/* Where the first byte in p[from:len) that may end a line is, a "\n" or
   "\r" as the newline mode has them (ASCII in every native codec), or
   len. */
static Py_ssize_t
line_end_byte(textio *self, const char *p, Py_ssize_t from, Py_ssize_t len)
{
    if (from >= len) {
        return len;
    }
    const char *s = p + from, *end = p + len;
    tconf *cf = self->conf;
    int c = (cf->readuniversal ? '\n'
             : (int)PyUnicode_READ_CHAR(cf->readnl, 0));
    const char *e = memchr(s, c, end - s);
    if (cf->readuniversal) {
        const char *cr = memchr(s, '\r', (e ? e : end) - s);
        e = cr ? cr : e;
    }
    return e ? e - p : len;
}

/* The end of text_read_quick(): take the n bytes of text (the cache's k
   characters at cache_ci), which saw the newlines `seen`.  Returns text,
   or NULL (with an exception set or not) if the buffer's bytes moved. */
static inline PyObject *
quick_take(textio *self, PyObject *text, Py_ssize_t k, Py_ssize_t n,
           int seen)
{
    const char *p = self->cache_p;
    if (_PyIONibbler_take(self->conf->buffer, p, self->cache_end - p, n)
        <= 0)
    {
        Py_DECREF(text);
        return NULL;
    }
    self->cache_ci += k;
    self->cache_p += n;
    if (seen && (self->seennl & seen) != seen) {
        text_note(self, seen);
    }
    return text;
}

/* For text_read_quick(): read(want) translating newlines, from the
   cache's characters at cache_ci, with a "\r" at cache_cr.  Returns the
   text, or NULL (with an exception set or not) when a "\r" is the
   cache's last character, the text has many, or the bytes moved. */
#define QUICK_CRS 16
Py_NO_INLINE static PyObject *
quick_translate(textio *self, Py_ssize_t want)
{
    PyObject *chars = self->cache;
    int kind = PyUnicode_KIND(chars);
    const char *data = PyUnicode_DATA(chars);
    Py_ssize_t len = PyUnicode_GET_LENGTH(chars);
    Py_ssize_t ci = self->cache_ci, i = ci, out = 0, cr = self->cache_cr;
    Py_ssize_t crs[QUICK_CRS];
    int ncr = 0, seen = 0;
    for (;;) {
        /* A run to the next "\r" (whose "\n"s are alone). */
        Py_ssize_t run = Py_MIN(cr - i, want - out);
        if (!(self->seennl & SEEN_LF) && !(seen & SEEN_LF)
            && find_char(kind, data + i * kind, data + (i + run) * kind,
                         '\n') != NULL)
        {
            seen |= SEEN_LF;
        }
        i += run;
        out += run;
        if (out == want) {
            break;
        }
        if (i + 1 >= len || ncr == QUICK_CRS) {
            return NULL;
        }
        int lf = PyUnicode_READ(kind, data, i + 1) == '\n';
        seen |= lf ? SEEN_CRLF : SEEN_CR;
        crs[ncr++] = i;
        i += 1 + lf;
        if (++out == want) {
            break;
        }
        const char *p = find_char(kind, data + i * kind, data + len * kind,
                                  '\r');
        cr = p ? (p - data) / kind : len;
    }
    /* (Found again if it is before the position.) */
    self->cache_cr = cr;
    Py_ssize_t k = i - ci;
    Py_ssize_t n = (i == len ? self->cache_end - self->cache_p
                    : native_bytes(self, chars, ci, k));
    Py_UCS4 max = (PyUnicode_IS_ASCII(chars) ? 127
                   : _PyUnicode_FindMaxChar(chars, ci, i));
    PyObject *text = PyUnicode_New(want, max);
    if (text != NULL && PyUnicode_KIND(text) != kind) {
        /* Narrower: copied by characters. */
        Py_SETREF(text, text_translate(PyUnicode_Substring(chars, ci, i),
                                       want));
        return text ? quick_take(self, text, k, n, seen) : NULL;
    }
    if (text == NULL) {
        return NULL;
    }
    char *o = PyUnicode_DATA(text);
    Py_ssize_t from = ci;
    for (int j = 0; j < ncr; j++) {
        memcpy(o, data + from * kind, (crs[j] - from) * kind);
        o += (crs[j] - from) * kind;
        PyUnicode_WRITE(kind, o, 0, '\n');
        o += kind;
        from = crs[j] + 1;
        from += from < i && PyUnicode_READ(kind, data, from) == '\n';
    }
    memcpy(o, data + from * kind, (i - from) * kind);
    return quick_take(self, text, k, n, seen);
}

/* The usual native read, without text_take()'s work: the cache has all of
   the text, with no "\r" in it but in a "\r\n" ending a line (nor one
   before it, after_cr), and the buffer's unread bytes are still the
   cache's (taken in one locked step).  Returns the text, or
   NULL with an exception set or not (then the read is done the usual
   way). */
static PyObject *
text_read_quick(textio *self, Py_ssize_t want, int line)
{
    PyObject *chars = self->cache;
    tconf *cf = self->conf;
    if (chars == NULL || self->after_cr
        || (line && (want >= 0
                     /* (Lines end with writenl: "\n" is NULL.) */
                     || (!cf->readuniversal && cf->writenl != NULL))))
    {
        return NULL;
    }
    int kind = PyUnicode_KIND(chars);
    const char *data = PyUnicode_DATA(chars);
    Py_ssize_t ci = self->cache_ci, len = PyUnicode_GET_LENGTH(chars), k;
    const char *s = data + ci * kind;
    int seen = 0;
    if (line) {
        const char *lf = (kind == PyUnicode_1BYTE_KIND
                          ? memchr(s, '\n', len - ci)
                          : find_char(kind, s, data + len * kind, '\n'));
        if (lf == NULL) {
            return NULL;
        }
        k = ((lf - s) >> (kind >> 1)) + 1;    /* (kind: 1, 2 or 4) */
        seen = SEEN_LF;
    }
    else {
        if (want < 0 || want > len - ci) {
            return NULL;
        }
        k = want;
    }
    int crlf = 0;
    if (cf->readuniversal) {
        if (self->cache_cr < ci) {
            const char *cr = find_char(kind, s, data + len * kind, '\r');
            self->cache_cr = cr ? (cr - data) / kind : len;
        }
        crlf = line && self->cache_cr == ci + k - 2;
        if (self->cache_cr < ci + k && !crlf) {
            return (line || !cf->readtranslate ? NULL
                    : quick_translate(self, want));
        }
        else if (!line && !(self->seennl & SEEN_LF)) {
            seen = find_char(kind, s, s + k * kind, '\n') ? SEEN_LF : 0;
        }
        seen = crlf ? SEEN_CRLF : seen;
        crlf &= cf->readtranslate;
    }
    /* (A line's bytes end with the first "\n" byte, in UTF-8.) */
    const char *p = self->cache_p;
    Py_ssize_t avail = self->cache_end - p;
    Py_ssize_t n = (ci + k == len ? avail
                    : cf->codec != CODEC_UTF8 || PyUnicode_IS_ASCII(chars)
                    ? k
                    : line ? (const char *)memchr(p, '\n', avail) - p + 1
                    : native_bytes(self, chars, ci, k));
    /* "\r\n" made "\n" in a new str, or a "\n" alone. */
    Py_ssize_t out = k - crlf;
    PyObject *text;
    if (crlf && out == 1) {
        text = _PyUnicode_FromASCII("\n", 1);
    }
    else if (ci == 0 && out == len) {
        text = Py_NewRef(chars);
    }
    else if (PyUnicode_IS_ASCII(chars)) {
        text = _PyUnicode_FromASCII(s, out);
    }
    else if (cf->codec == CODEC_UTF8
             && PyUnicode_KIND(chars) == PyUnicode_1BYTE_KIND)
    {
        /* ASCII when they have as many bytes: no need to look for the
           widest. */
        text = (n == k ? _PyUnicode_FromASCII(s, out)
                : PyUnicode_New(out, 0xff));
        if (text != NULL && n > k) {
            memcpy(PyUnicode_1BYTE_DATA(text), s, out);
        }
    }
    else {
        text = PyUnicode_Substring(chars, ci, ci + out);
    }
    if (text == NULL) {
        return NULL;
    }
    if (crlf && out > 1) {
        assert(Py_REFCNT(text) == 1);
        PyUnicode_WRITE(PyUnicode_KIND(text), PyUnicode_DATA(text), out - 1,
                        '\n');
    }
    return quick_take(self, text, k, n, seen);
}

/* read(want) (-1: all), or with line, readline(want), with a native codec:
   text from the characters of the store's bytes at the position (decoded
   a chunk at a time, kept in the cache while the bytes stay there), whose
   bytes are taken.  A read that can't end with what the store holds (a
   line longer than the buffer gathers, read() of everything) takes it in
   pieces, keeping copies of the bytes to give back if it fails.  The
   first try only looks, without the buffer's I/O role. */
Py_NO_INLINE static PyObject *
text_read_native(textio *self, Py_ssize_t want, int line)
{
    tstore st = {.self = self};
    tkeep kp = {NULL, 0};
    PyObject *pieces = NULL;
    uint8_t after_cr = self->after_cr;
    Py_ssize_t chunk = FT_ATOMIC_LOAD_SSIZE_RELAXED(self->chunk_size);
    /* Once a line's end isn't in the decoded chunk, it is looked for in
       the bytes first (ASCII in every native codec): the store's first
       `noline` bytes have none. */
    Py_ssize_t span = 0, left = want, noline = 0;
    int io = 0, done = 0, bytes_first = 0;
again:
    if (store_begin(&st, io) < 0) {
        goto fail;
    }
    while (!done) {
        if (!cache_valid(self, &st)) {
            /* A chunk (or what want needs, or a line's bytes), or twice
               what didn't do. */
            span = Py_MAX(span, chunk);
            if (left >= 0 && !line) {
                Py_ssize_t more = left + (left < PY_SSIZE_T_MAX);
                span = Py_MAX(span, native_span(self, st.p, st.avail, more));
            }
            if (bytes_first) {
                noline = line_end_byte(self, st.p, noline, st.avail);
                span = Py_MAX(span, noline + 2);
            }
            if ((st.avail == 0 && !st.eof)
                || (bytes_first && noline == st.avail && !st.eof && !st.full
                    && !st.blocked))
            {
                /* Nothing, or no line's end yet: read more first. */
                Py_CLEAR(self->cache);
                self->cache_stop = 0;
            }
            else if (cache_fill(self, &st, span, pieces != NULL) < 0) {
                goto fail;
            }
        }
        PyObject *chars = self->cache;
        Py_ssize_t ci = self->cache_ci, k = 0;
        Py_ssize_t have = chars ? PyUnicode_GET_LENGTH(chars) - ci : 0;
        int whole = chars && self->cache_all;
        int found = 0, note = 0;
        if (have > 0) {
            int final = self->cache_stop || (st.eof && whole);
            int partial = st.full || (st.blocked && have > chunk);
            PyObject *text = text_take(self, chars, ci, left, line, final,
                                       partial, &k, &found, &note);
            if (text == NULL && k > 0) {
                goto fail;
            }
            if (k > 0) {
                Py_ssize_t n = (k == have ? self->cache_end - self->cache_p
                                : native_bytes(self, chars, ci, k));
                done = (found || st.blocked || (st.eof && n == st.avail)
                        || (k == have && self->cache_stop));
                if (!done && !io) {
                    Py_DECREF(text);
                    goto upgrade;
                }
                if ((!done && keep_add(&kp, st.block, st.p, n) < 0)
                    || add_piece(&pieces, text) < 0)
                {
                    goto fail;
                }
                left -= left >= 0 ? PyUnicode_GET_LENGTH(text) : 0;
                text_note(self, note);
                store_skip(&st, n);
                noline = 0;
                self->cache_ci += k;
                self->cache_p += n;
                st.full = 0;
                continue;
            }
        }
        if (self->cache_stop) {
            break;
        }
        if (line && want < 0 && chars != NULL) {
            /* (But the last byte, a "\r" a "\n" may follow.) */
            bytes_first = 1;
            noline = Py_MAX(noline, self->cache_end - self->cache_p - 1);
        }
        if (chars != NULL && !whole) {
            /* Decode more of what is there. */
            span = 2 * (self->cache_end - self->cache_p) + 8;
            Py_CLEAR(self->cache);
            continue;
        }
        if (st.eof || st.blocked) {
            break;
        }
        if (!io) {
            goto upgrade;
        }
        /* Let the buffer reuse its block. */
        Py_CLEAR(self->cache);
        Py_CLEAR(self->cache_block);
        if (store_fill(&st) < 0) {
            goto fail;
        }
    }
    store_end(&st, 1);
    Py_XDECREF(kp.list);
    if (pieces == NULL && st.blocked) {
        /* Nothing yet, which "" would say is the end. */
        _PyIO_set_read_blocking_error();
        return NULL;
    }
    return join_pieces(pieces);

upgrade:
    /* (Other code may take bytes meanwhile.) */
    store_end(&st, 0);
    io = 1;
    noline = 0;
    goto again;

fail:
    /* Give back what was taken (the exception is kept). */
    if (kp.len > 0) {
        PyObject *exc = PyErr_GetRaisedException();
        Py_CLEAR(self->cache);
        PyObject *b, *all = PyBytes_FromStringAndSize(NULL, kp.len);
        Py_ssize_t off, n, at = 0;
        for (Py_ssize_t i = 0; all && i < PyList_GET_SIZE(kp.list); i++) {
            (void)PyArg_ParseTuple(PyList_GET_ITEM(kp.list, i), "Onn", &b,
                                   &off, &n);
            memcpy(PyBytes_AS_STRING(all) + at, PyBytes_AS_STRING(b) + off, n);
            at += n;
        }
        if (all == NULL
            || store_unread(&st, PyBytes_AS_STRING(all), kp.len) < 0)
        {
            PyErr_Clear();
        }
        Py_XDECREF(all);
        PyErr_SetRaisedException(exc);
    }
    self->after_cr = after_cr;
    store_end(&st, 1);
    Py_XDECREF(kp.list);
    Py_XDECREF(pieces);
    return NULL;
}

/* All of chars (stolen), the end of the text, with "\r\n" and "\r" made
   "\n" (newline None), noting the newlines seen. */
static PyObject *
translate_all(textio *self, PyObject *chars)
{
    int kind = PyUnicode_KIND(chars), seen = self->seennl & SEEN_LF;
    Py_ssize_t len = PyUnicode_GET_LENGTH(chars);
    const char *r = PyUnicode_DATA(chars), *end = r + len * kind;
    PyObject *res = chars;
    if (find_char(kind, r, end, '\r') == NULL) {
        /* (Nothing to copy: whether there is a "\n".) */
        seen |= !seen && find_char(kind, r, end, '\n') ? SEEN_LF : 0;
    }
    else {
        res = PyUnicode_New(len, PyUnicode_MAX_CHAR_VALUE(chars));
        len = res ? translate_newlines(kind, r, end, PyUnicode_DATA(res),
                                       &seen) : 0;
        Py_DECREF(chars);
        if (res == NULL || PyUnicode_Resize(&res, len) < 0) {
            return NULL;
        }
    }
    text_note(self, seen);
    return res;
}

/* read() of everything with a native codec over the buffer's own bytes:
   its read() (the read-ahead and the rest at once), decoded at once.
   Returns NULL with no exception set if the bytes don't decode: they are
   given back, to be read in pieces (text_read_native()). */
Py_NO_INLINE static PyObject *
text_read_all(textio *self)
{
    PyObject *buffer = textio_buffer(self);
    if (buffer == NULL) {
        return NULL;
    }
    PyObject *b = PyObject_CallMethodNoArgs(buffer, &_Py_ID(read));
    PyObject *res = NULL;
    if (b == Py_None) {
        _PyIO_set_read_blocking_error();
    }
    else if (b != NULL && !PyBytes_Check(b)) {
        PyErr_Format(PyExc_TypeError, "underlying read() should have "
                     "returned a bytes object, not '%.200s'",
                     Py_TYPE(b)->tp_name);
    }
    if (b == NULL || PyErr_Occurred()) {
        goto end;
    }
    /* The bytes left the buffer: so did the cache's. */
    Py_CLEAR(self->cache);
    Py_CLEAR(self->cache_block);
    Py_ssize_t used, len = PyBytes_GET_SIZE(b);
    PyObject *chars = native_decode(self, PyBytes_AS_STRING(b), len, 1,
                                    &used);
    if (chars == NULL) {
        /* Given back (the exception is kept but for invalid bytes). */
        tstore st = {.self = self, .buffer = Py_NewRef(buffer)};
        PyObject *exc = PyErr_GetRaisedException();
        if (store_begin(&st, 1) == 0) {
            if (store_unread(&st, PyBytes_AS_STRING(b), len) < 0) {
                PyErr_Clear();
            }
            store_end(&st, 1);
        }
        else {
            PyErr_Clear();
            Py_CLEAR(st.buffer);
        }
        if (!PyErr_GivenExceptionMatches(exc, PyExc_UnicodeDecodeError)) {
            PyErr_SetRaisedException(exc);
        }
        else {
            Py_DECREF(exc);
        }
        goto end;
    }
    if (self->conf->readtranslate) {
        res = translate_all(self, chars);
    }
    else if (self->conf->readuniversal && PyUnicode_GET_LENGTH(chars) > 0) {
        Py_ssize_t k;
        int found, note;
        res = text_take(self, chars, 0, -1, 0, 1, 0, &k, &found, &note);
        if (res != NULL) {
            text_note(self, note);
        }
        Py_DECREF(chars);
    }
    else {
        res = chars;
    }
end:
    Py_XDECREF(b);
    Py_DECREF(buffer);
    return res;
}

/* With elock: reset encoder (if any) to the stream's start, or past it
   (no BOM). */
static int
encoder_reset_locked(textio *self, PyObject *encoder, int start)
{
    FT_ATOMIC_STORE_CHAR_RELAXED(self->encoding_start_of_stream, start);
    if (encoder == NULL) {
        return 0;
    }
    PyObject *res = (start
                     ? PyObject_CallMethodNoArgs(encoder, &_Py_ID(reset))
                     : PyObject_CallMethodOneArg(encoder, &_Py_ID(setstate),
                                                 _PyLong_GetZero()));
    Py_XDECREF(res);
    return res == NULL ? -1 : 0;
}

/* Decode the store's unread bytes with the codec's decoder, after dchars,
   and take them (but what the decoder holds, which stays).  Returns 1, 0
   if no more characters can come for now, or -1 (*stop: invalid bytes
   follow the characters; raised unless characters come first, or the call
   took text already, taken). */
static int
decoder_more(textio *self, tstore *st, int *stop, int taken)
{
    if (self->fresh && decoder_getflags(self->conf->decoder, &self->flags,
                                        NULL) < 0)
    {
        return -1;
    }
    self->fresh = 0;
    unsigned long long flags = self->flags;
    Py_ssize_t used, start, end, span = st->avail;
    int final = st->eof;
    PyObject *chars = decoder_decode(self->conf->decoder, st->p, span, final,
                                     &used, &flags);
    if (chars == NULL && decode_error(&start, &end) == 0) {
        /* As native reads: valid text first, then the bytes and the error,
           once. */
        int more = taken || (self->dchars != NULL && self->dpos
                             < PyUnicode_GET_LENGTH(self->dchars));
        if (start == 0 && !more) {
            PyObject *exc = PyErr_GetRaisedException();
            store_skip(st, Py_MIN(Py_MAX(end, 1), st->avail));
            if (decoder_setstate(self->conf->decoder, self->flags, 0) < 0) {
                _PyErr_ChainExceptions1(exc);
                return -1;
            }
            PyErr_SetRaisedException(exc);
            return -1;
        }
        PyErr_Clear();
        *stop = 1;
        flags = self->flags;
        chars = (start == 0 ? PyUnicode_New(0, 0)
                 : decoder_setstate(self->conf->decoder, flags, 0) < 0 ? NULL
                 : decoder_decode(self->conf->decoder, st->p, start, 0, &used,
                                  &flags));
        used = start > 0 ? used : 0;
    }
    if (chars == NULL) {
        return -1;
    }
    PyObject *bytes = PyBytes_FromStringAndSize(st->p, used);
    if (bytes == NULL) {
        Py_DECREF(chars);
        return -1;
    }
    if (self->dchars == NULL
        || self->dpos == PyUnicode_GET_LENGTH(self->dchars))
    {
        /* A new snapshot, where the decoder starts. */
        Py_XSETREF(self->dchars, chars);
        Py_XSETREF(self->dbytes, bytes);
        self->dpos = self->dlost = 0;
        self->dflags = self->flags;
    }
    else {
        PyUnicode_Append(&self->dchars, chars);
        PyBytes_ConcatAndDel(&self->dbytes, bytes);
        Py_DECREF(chars);
        if (self->dchars == NULL || self->dbytes == NULL) {
            textio_drop_reads(self);
            return -1;
        }
    }
    store_skip(st, used);
    self->flags = flags;
    if (used > 0 && FT_ATOMIC_LOAD_CHAR_RELAXED(self->encoding_start_of_stream)
        && self->conf->encoder != NULL && nibbler_mutex_trylock(&self->elock))
    {
        /* Not at the start any more: no BOM.  (Not waiting, with the
           buffer's locks, for a write, which holds elock while it waits for
           them: its encoder is past the start already.) */
        int r = encoder_reset_locked(self, self->conf->encoder, 0);
        nibbler_mutex_unlock(&self->elock);
        if (r < 0) {
            return -1;
        }
    }
    return used > 0 || st->eof;
}

/* read() and readline() through the codec's decoder: characters are
   decoded ahead into dchars, and taken from there once what is asked for
   is there, so that a read that fails loses nothing.  Longer text is taken
   in pieces as it is decoded (so that what the decoder makes next replaces
   them instead of being appended), joined at the end; a read that fails
   gives them back, joined, as characters decoded from where they started,
   kchars[0:kpos] before them, with flags kflags, from klost bytes not
   kept. */
Py_NO_INLINE static PyObject *
text_read_decoder(textio *self, Py_ssize_t want, int line)
{
    tstore st = {.self = self};
    if (store_begin(&st, 1) < 0) {
        return NULL;
    }
    PyObject *pieces = NULL, *kchars = NULL, *kraw = NULL;
    Py_ssize_t chunk = FT_ATOMIC_LOAD_SSIZE_RELAXED(self->chunk_size);
    Py_ssize_t kpos = 0, klost = 0;
    unsigned long long kflags = 0;
    uint8_t after_cr = self->after_cr;
    int stop = 0, look = 1, rounds = 0;
    for (;;) {
        Py_ssize_t have = (self->dchars == NULL ? 0
                           : PyUnicode_GET_LENGTH(self->dchars) - self->dpos);
        /* No text before the invalid bytes (an escape sequence alone):
           decoding them raises, rather than ending as at EOF. */
        stop &= have > 0 || pieces != NULL;
        int final = stop || (st.eof && st.avail == 0), more = have > chunk;
        if (have > 0 && (look || final || st.blocked || more
                         || (want >= 0 && have >= want)))
        {
            Py_ssize_t k;
            int found, note;
            PyObject *text = text_take(self, self->dchars, self->dpos, want,
                                       line, final, more, &k, &found, &note);
            int end = found || final || st.blocked;
            if (text == NULL && k > 0) {
                goto fail;
            }
            if (k > 0 && (end || more)) {
                if (!end && kchars == NULL) {
                    kchars = Py_NewRef(self->dchars);
                    kpos = self->dpos;
                    kflags = self->dflags;
                    klost = self->dlost + PyBytes_GET_SIZE(self->dbytes);
                }
                if (!end) {
                    /* As decoded ("\r\n" not made "\n"), to give back. */
                    PyObject *raw = (k == PyUnicode_GET_LENGTH(text)
                                     ? Py_NewRef(text)
                                     : PyUnicode_Substring(self->dchars,
                                                           self->dpos,
                                                           self->dpos + k));
                    if (raw == NULL || add_piece(&kraw, raw) < 0) {
                        Py_DECREF(text);
                        goto fail;
                    }
                }
                self->dpos += k;
                text_note(self, note);
                want -= want >= 0 ? PyUnicode_GET_LENGTH(text) : 0;
                if (add_piece(&pieces, text) < 0) {
                    goto fail;
                }
                if (end) {
                    break;
                }
                continue;
            }
            Py_XDECREF(text);
            if (PyErr_Occurred()) {
                goto fail;
            }
            look = 0;
        }
        if (final || st.blocked) {
            break;
        }
        /* Decode what the store has, as one raw read returned it (a stream
           that would block after a line still returns it first), reading
           more when there is none; after a round that wasn't enough,
           _CHUNK_SIZE bytes at least, so that long text isn't decoded in
           small pieces. */
        if ((st.avail == 0 && !st.eof)
            || (rounds > 0 && st.avail < chunk && !st.eof && !st.blocked
                && !st.full))
        {
            if (store_fill(&st) < 0) {
                goto fail;
            }
            continue;
        }
        rounds++;
        Py_ssize_t old = have, avail = st.avail;
        int r = decoder_more(self, &st, &stop, pieces != NULL);
        klost += avail - st.avail;
        if (r < 0 || (r == 0 && !st.eof && !stop && store_fill(&st) < 0)) {
            goto fail;
        }
        /* Look for a line's end in what is new only. */
        look = !line;
        if (line && self->dchars != NULL) {
            int kind = PyUnicode_KIND(self->dchars);
            const char *s = (const char *)PyUnicode_DATA(self->dchars)
                            + (self->dpos + old) * kind;
            const char *e = (const char *)PyUnicode_DATA(self->dchars)
                            + PyUnicode_GET_LENGTH(self->dchars) * kind;
            look = (find_char(kind, s, e, '\n') != NULL
                    || find_char(kind, s, e, '\r') != NULL);
        }
    }
    store_end(&st, 1);
    Py_XDECREF(kchars);
    Py_XDECREF(kraw);
    if (pieces == NULL && st.blocked) {
        _PyIO_set_read_blocking_error();
        return NULL;
    }
    return join_pieces(pieces);

fail:
    store_end(&st, 1);
    self->after_cr = after_cr;
    if (kchars != NULL && self->dchars != NULL) {
        /* Give back the pieces (the exception is kept). */
        PyObject *exc = PyErr_GetRaisedException();
        PyObject *taken = join_pieces(kraw);
        PyObject *parts = taken == NULL ? NULL : Py_BuildValue(
            "(NNN)", PyUnicode_Substring(kchars, 0, kpos), taken,
            PyUnicode_Substring(self->dchars, self->dpos, PY_SSIZE_T_MAX));
        PyObject *all = parts ? PyUnicode_Join(&_Py_STR(empty), parts) : NULL;
        Py_XDECREF(parts);
        kraw = NULL;
        if (all == NULL) {
            textio_drop_reads(self);
        }
        else {
            Py_XSETREF(self->dchars, all);
            Py_XSETREF(self->dbytes, Py_GetConstant(Py_CONSTANT_EMPTY_BYTES));
            self->dpos = kpos;
            self->dflags = kflags;
            self->dlost = klost;
        }
        PyErr_SetRaisedException(exc);
    }
    Py_XDECREF(kchars);
    Py_XDECREF(kraw);
    Py_XDECREF(pieces);
    return NULL;
}

/* read(n) (n < 0: all), or with line, readline(n). */
Py_NO_INLINE static PyObject *
text_read_locked(textio *self, Py_ssize_t n, int line)
{
    if (textio_lock(self) < 0) {
        return NULL;
    }
    PyObject *res = NULL;
    int nib = 0, read_ahead_after_close;
    if (textio_refuse_nested(self, 0) < 0 || textio_attached(self) < 0) {
        goto end;
    }
    nib = FT_ATOMIC_LOAD_UINT8_RELAXED(self->conf->nib);
    /* Over the buffer's own bytes with a native codec, what the buffer
       read ahead is read after its raw stream alone was closed (as the
       buffer's read() does): reading more checks. */
    read_ahead_after_close = (nib && textio_exact(self)
                              && self->conf->codec != CODEC_DECODER && n != 0);
    if (!read_ahead_after_close && textio_check_closed(self, self->conf) < 0) {
        goto end;
    }
    if (!self->conf->readable) {
        textio_unsupported(self, "not readable");
        goto end;
    }
    self->rbusy = 1;
    if (n == 0) {
        res = Py_GetConstant(Py_CONSTANT_EMPTY_STR);
    }
    else if (self->conf->codec == CODEC_DECODER) {
        res = text_read_decoder(self, n, line);
    }
    else {
        if (n < 0 && !line && nib) {
            res = text_read_all(self);
        }
        if (res == NULL && !PyErr_Occurred()) {
            res = text_read_native(self, n, line);
        }
    }
    if (res != NULL || textio_holds(self)) {
        /* (Also after a read that failed with characters decoded.) */
        FT_ATOMIC_STORE_UINT8_RELAXED(self->decoded, 1);
    }
    self->rbusy = 0;
end:
    textio_leave(self);
    return res;
}

/* read(n) (n < 0: all), or with line, readline(n): text_read_quick() if
   rlock is free and needs no checks, else text_read_locked(). */
static PyObject *
text_read(textio *self, Py_ssize_t n, int line)
{
    if (n != 0 && nibbler_mutex_trylock(&self->rlock)) {
        PyObject *res = NULL;
        tconf *cf = self->conf;
        if (cf != NULL && cf->quick && FT_ATOMIC_LOAD_UINT8_RELAXED(cf->nib)) {
            res = text_read_quick(self, n, line);
        }
        if (res != NULL && !self->decoded) {
            FT_ATOMIC_STORE_UINT8_RELAXED(self->decoded, 1);
        }
        nibbler_mutex_unlock(&self->rlock);
        if (res != NULL || PyErr_Occurred()) {
            return res;
        }
    }
    return text_read_locked(self, n, line);
}

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

/* A subclass's readline(). */
Py_NO_INLINE static PyObject *
text_readline_method(PyObject *op)
{
    PyObject *line = PyObject_CallMethodNoArgs(op, &_Py_ID(readline));
    if (line != NULL && !PyUnicode_Check(line)) {
        PyErr_Format(PyExc_OSError,
                     "readline() should have returned a str object, "
                     "not '%.200s'", Py_TYPE(line)->tp_name);
        Py_CLEAR(line);
    }
    return line;
}

static PyObject *
textiowrapper_iternext(PyObject *op)
{
    PyObject *line = (textio_exact(textio_CAST(op))
                      ? text_read(textio_CAST(op), -1, 1)
                      : text_readline_method(op));
    if (line != NULL && PyUnicode_GET_LENGTH(line) == 0) {
        /* EOF */
        Py_CLEAR(line);
    }
    return line;
}

/*
 * Writing
 */

/* The buffer's position as an int: minus what rbuf read ahead. */
static PyObject *
store_tell(textio *self)
{
    PyObject *buffer = textio_buffer(self);
    PyObject *pos = buffer ? PyObject_CallMethodNoArgs(buffer, &_Py_ID(tell))
                           : NULL;
    Py_XDECREF(buffer);
    Py_ssize_t unread = self->rbuf ? PyBytes_GET_SIZE(self->rbuf) - self->rpos
                                   : 0;
    if (pos != NULL && unread > 0) {
        PyObject *k = PyLong_FromSsize_t(unread);
        Py_SETREF(pos, k == NULL ? NULL : PyNumber_Subtract(pos, k));
        Py_XDECREF(k);
    }
    return pos;
}

/* The dlost bytes before dbytes weren't kept (see text_read_decoder()):
   read them again, from the buffer, before its position p (the store's),
   to which it then returns. */
static int
decoder_reread(textio *self, Py_off_t p)
{
    Py_ssize_t len = self->dlost + PyBytes_GET_SIZE(self->dbytes);
    Py_CLEAR(self->rbuf);
    self->rpos = 0;
    PyObject *b = NULL, *res = _PyObject_CallMethod(
        self->conf->buffer, &_Py_ID(seek), "(O&)", PyLong_FromOff_t, p - len);
    if (res != NULL) {
        b = _PyObject_CallMethod(self->conf->buffer, &_Py_ID(read), "n", len);
        Py_DECREF(res);
    }
    if (b != NULL && PyBytes_Check(b) && PyBytes_GET_SIZE(b) == len) {
        Py_SETREF(self->dbytes, b);
        self->dlost = 0;
        return 0;
    }
    if (b != NULL) {
        Py_DECREF(b);
        PyErr_SetString(PyExc_OSError, "could not read the text's bytes again");
    }
    PyObject *exc = PyErr_GetRaisedException();
    res = _PyObject_CallMethod(self->conf->buffer, &_Py_ID(seek), "(O&)",
                               PyLong_FromOff_t, p);
    if (res == NULL) {
        textio_drop_reads(self);
    }
    Py_XDECREF(res);
    _PyErr_ChainExceptions1(exc);
    return -1;
}

/* With rlock, before a write, truncate() or detach(): make the buffer's
   position the text position (rbuf's read-ahead handed back, or with the
   decoder, a seek to where the characters not returned start). */
static int
text_sync(textio *self)
{
    if (!self->conf->seekable) {
        /* Reads and writes are separate streams. */
        return 0;
    }
    if (textio_refuse_nested(self, 1) < 0) {
        return -1;
    }
    int r = -1;
    self->rbusy = 1;
    if (textio_holds(self)) {
        PyObject *pos = store_tell(self);
        Py_off_t p = pos ? PyLong_AsOff_t(pos) : -1, back = 0;
        Py_XDECREF(pos);
        if (p == -1 && PyErr_Occurred()) {
            goto end;
        }
        if (self->dchars != NULL
            && self->dpos < PyUnicode_GET_LENGTH(self->dchars))
        {
            Py_ssize_t off;
            unsigned long long flags;
            if ((self->dlost > 0 && decoder_reread(self, p) < 0)
                || decoder_offset(self, self->dpos, &off, &flags) < 0)
            {
                goto end;
            }
            back = PyBytes_GET_SIZE(self->dbytes) - off;
            self->flags = flags;
        }
        textio_drop_reads(self);
        PyObject *res = _PyObject_CallMethod(self->conf->buffer, &_Py_ID(seek),
                                             "(O&)", PyLong_FromOff_t,
                                             p - back);
        Py_XDECREF(res);
        if (res == NULL) {
            goto end;
        }
    }
    textio_drop_reads(self);
    r = 0;
end:
    self->rbusy = 0;
    return r;
}

/* Store data[0:len] (owned by obj) in cf's buffer. */
static int
text_store(tconf *cf, PyObject *obj, const char *data, Py_ssize_t len)
{
    if (FT_ATOMIC_LOAD_UINT8_RELAXED(cf->nib)) {
        int r = _PyIONibbler_write(cf->buffer, obj, data, len);
        if (r != _PyIO_NIBBLER_NO) {
            return r;
        }
        /* It got an instance dict: its methods from now on. */
        FT_ATOMIC_STORE_UINT8_RELAXED(cf->nib, 0);
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

/* The encoder's bytes for text, stored; with final, the end of the text,
   if the codec's encoder needs it.  Returns 0, -1, or -2 if storing them
   raised. */
static int
text_encoder_store(textio *self, tconf *cf, PyObject *text, int final)
{
    int stateful = cf->enc == CODEC_DECODER, r = 0;
    if (stateful
        && nibbler_mutex_lock(&self->elock, (PyObject *)self, 1) < 0)
    {
        return -1;
    }
    if (final) {
        r = FT_ATOMIC_LOAD_CHAR_RELAXED(self->encoder_used) ? 0 : 1;
        FT_ATOMIC_STORE_CHAR_RELAXED(self->encoder_used, 0);
    }
    PyObject *b = r ? NULL : PyObject_CallMethodObjArgs(
        cf->encoder, &_Py_ID(encode), text, final ? Py_True : Py_False, NULL);
    if (b != NULL && !PyBytes_Check(b)) {
        PyErr_Format(PyExc_TypeError,
                     "encoder should return a bytes object, not '%.200s'",
                     Py_TYPE(b)->tp_name);
        Py_CLEAR(b);
    }
    if (b != NULL) {
        if (stateful && !final) {
            FT_ATOMIC_STORE_CHAR_RELAXED(self->encoding_start_of_stream, 0);
            FT_ATOMIC_STORE_CHAR_RELAXED(self->encoder_used, 1);
        }
        r = text_store(cf, b, PyBytes_AS_STRING(b), PyBytes_GET_SIZE(b));
        r = r < 0 ? -2 : 0;
        Py_DECREF(b);
    }
    else {
        r = r ? 0 : -1;
    }
    if (stateful) {
        nibbler_mutex_unlock(&self->elock);
    }
    return r;
}

/* Encode text and store it: a str's data is its encoding when ASCII (and
   1 byte characters in Latin-1).  The charmap encoders hold no state; the
   codec's encoder must be given final=True at the end (gh-79792). */
static int
text_encode_store(textio *self, tconf *cf, PyObject *text)
{
    int enc = cf->enc;
    if (enc != CODEC_DECODER
        && (PyUnicode_IS_ASCII(text)
            || (enc == CODEC_LATIN1
                && PyUnicode_KIND(text) == PyUnicode_1BYTE_KIND)))
    {
        return text_store(cf, text, PyUnicode_DATA(text),
                          PyUnicode_GET_LENGTH(text));
    }
    PyObject *b;
    if (enc == CODEC_UTF8) {
        b = _PyUnicode_AsUTF8String(text, cf->errors_str);
    }
    else if (enc == CODEC_LATIN1) {
        b = _PyUnicode_AsLatin1String(text, cf->errors_str);
    }
    else if (enc == CODEC_ASCII) {
        b = _PyUnicode_AsASCIIString(text, cf->errors_str);
    }
    else {
        return text_encoder_store(self, cf, text, 0) < 0 ? -1 : 0;
    }
    if (b == NULL) {
        return -1;
    }
    int r = text_store(cf, b, PyBytes_AS_STRING(b), PyBytes_GET_SIZE(b));
    Py_DECREF(b);
    return r;
}

/* Give the codec's encoder the end of the text, and store what it held
   (gh-79792).  Returns 0, or with an exception set -2 if storing it
   raised, else -1. */
static int
text_finish_encoder(textio *self)
{
    if (!FT_ATOMIC_LOAD_CHAR_RELAXED(self->encoder_used)) {
        return 0;
    }
    /* (encoder_used is looked at again with elock.) */
    tconf *cf = conf_get(self);
    int r = (cf == NULL || cf->buffer == NULL ? 0
             : text_encoder_store(self, cf, &_Py_STR(empty), 1));
    conf_put(cf);
    return r;
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
    /* The usual write: text that is its encoding (or strict UTF-8), with
       no newline to translate, in the buffer's own bytes, with no read to
       go back from (none on a stream that isn't seekable: reads and writes
       are separate streams there; the buffer checks it is open). */
    Py_ssize_t textlen = PyUnicode_GET_LENGTH(text);
    tconf *cf = textio_conf(self);
    if (cf == NULL) {
        return NULL;
    }
    int r = -1;
    if (cf->wquick && FT_ATOMIC_LOAD_UINT8_RELAXED(cf->nib)
        && (!FT_ATOMIC_LOAD_UINT8_RELAXED(self->decoded) || !cf->seekable))
    {
        r = _PyIO_NIBBLER_NO;
        if (PyUnicode_IS_ASCII(text)
            || (cf->enc == CODEC_LATIN1
                && PyUnicode_KIND(text) == PyUnicode_1BYTE_KIND))
        {
            r = _PyIONibbler_write(cf->buffer, text, PyUnicode_DATA(text),
                                   textlen);
        }
        else if (cf->enc == CODEC_UTF8 && cf->errors_str == NULL) {
            PyObject *b = _PyUnicode_AsUTF8String(text, NULL);
            if (b != NULL) {
                r = _PyIONibbler_write(cf->buffer, b, PyBytes_AS_STRING(b),
                                       PyBytes_GET_SIZE(b));
                Py_DECREF(b);
            }
            else {
                /* Raised again below, after the usual checks. */
                PyErr_Clear();
            }
        }
        if (r != _PyIO_NIBBLER_NO) {
            goto end;
        }
        r = -1;
    }

    const char *writenl = cf->writetranslate ? cf->writenl : NULL;
    Py_INCREF(text);
    if (cf->encoder == NULL) {
        textio_unsupported(self, "not writable");
        goto done;
    }
    if (textio_check_closed(self, cf) < 0) {
        goto done;
    }
    if (cf->seekable && FT_ATOMIC_LOAD_UINT8_RELAXED(self->decoded)) {
        /* At the text position (gh-82891).  (Never on other streams, whose
           reads may wait for the other end, which waits for this write.) */
        if (textio_enter(self, 0) < 0) {
            goto done;
        }
        r = text_sync(self);
        textio_leave(self);
        if (r < 0) {
            goto done;
        }
    }
    int haslf = ((writenl != NULL || cf->line_buffering)
                 && PyUnicode_FindChar(text, '\n', 0, textlen, 1) != -1);
    int needflush = (cf->line_buffering
                     && (haslf || PyUnicode_FindChar(text, '\r', 0, textlen,
                                                     1) != -1));
    if (haslf && writenl != NULL) {
        Py_SETREF(text, _PyObject_CallMethod(text, &_Py_ID(replace), "ss",
                                             "\n", writenl));
    }
    r = text == NULL ? -1 : text_encode_store(self, cf, text);
    if (r == 0 && needflush) {
        r = _PyFile_Flush(cf->buffer);
    }
done:
    Py_XDECREF(text);
end:
    conf_put(cf);
    return r < 0 ? NULL : PyLong_FromSsize_t(textlen);
}

/*
 * Seek and tell
 */

/* A cookie: the position of the start of the decoder's characters (or of
   the text), the decoder's flags there and how many characters to skip,
   laid out as _io's (bytes_to_feed and need_eof are 0). */
typedef struct {
    int64_t start_pos;
    int32_t dec_flags;
    int32_t bytes_to_feed;
    int32_t chars_to_skip;
    char need_eof;
} cookie_type;

#define COOKIE_BUF_LEN 21

static PyObject *
cookie_build(Py_off_t pos, unsigned long long flags, Py_ssize_t skip)
{
    if (flags > UINT32_MAX || skip > INT32_MAX) {
        PyErr_SetString(PyExc_OverflowError,
                        "the decoder's state doesn't fit a tell() cookie");
        return NULL;
    }
    unsigned char b[COOKIE_BUF_LEN] = {0};
    for (int i = 0; i < 8; i++) {
        b[i] = (unsigned char)((uint64_t)pos >> (8 * i));
    }
    for (int i = 0; i < 4; i++) {
        b[8 + i] = (unsigned char)(flags >> (8 * i));
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

/* tell(), with rlock: the buffer's position; with a native codec and a
   "\r" just returned that a "\n" there ends, flags 1; with the decoder and
   characters not returned yet, the byte position of the text position if
   there is one, else where they were decoded from and how many to skip. */
static PyObject *
text_tell(textio *self)
{
    if (!self->conf->seekable) {
        return textio_unsupported(self, "underlying stream is not seekable");
    }
    /* Over other buffers, flush first, as _io's does (their tell() might
       not count what they hold). */
    if (!FT_ATOMIC_LOAD_UINT8_RELAXED(self->conf->nib)
        && (_PyFile_Flush((PyObject *)self) < 0 || textio_attached(self) < 0))
    {
        return NULL;
    }
    PyObject *pos = store_tell(self);
    Py_off_t p = pos ? PyLong_AsOff_t(pos) : -1;
    if (p == -1 && PyErr_Occurred()) {
        Py_XDECREF(pos);
        return NULL;
    }
    if (self->conf->codec != CODEC_DECODER) {
        return self->after_cr ? (Py_DECREF(pos), cookie_build(p, 1, 0)) : pos;
    }
    if (self->dchars != NULL
        && self->dpos < PyUnicode_GET_LENGTH(self->dchars))
    {
        Py_ssize_t off;
        unsigned long long flags;
        Py_off_t start = p - PyBytes_GET_SIZE(self->dbytes) - self->dlost;
        int r = self->dlost ? 0 : decoder_offset(self, self->dpos, &off,
                                                 &flags);
        Py_SETREF(pos, r < 0 ? NULL
                       : r > 0 ? cookie_build(start + off, flags, 0)
                       : cookie_build(start, self->dflags, self->dpos));
    }
    else if (p != 0 && !self->fresh && self->flags != 0) {
        Py_SETREF(pos, cookie_build(p, self->flags, 0));
    }
    return pos;
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
    if (textio_enter(self, 1) < 0) {
        return NULL;
    }
    PyObject *res = (textio_refuse_nested(self, 1) < 0 ? NULL
                     : text_tell(self));
    textio_leave(self);
    return res;
}

/* Reset encoder (if any) to the stream's start, or past it (no BOM). */
static int
text_encoder_reset(textio *self, PyObject *encoder, int start)
{
    if (encoder == NULL) {
        return encoder_reset_locked(self, NULL, start);
    }
    if (nibbler_mutex_lock(&self->elock, (PyObject *)self, 1) < 0) {
        return -1;
    }
    int r = encoder_reset_locked(self, encoder, start);
    nibbler_mutex_unlock(&self->elock);
    return r;
}

/* After moving the buffer to pos: the decoder (if any) there, with flags,
   reset at the stream's start; the encoder too. */
static int
text_moved(textio *self, Py_off_t pos, uint32_t flags)
{
    textio_drop_reads(self);
    self->fresh = pos == 0 && flags == 0;
    self->flags = flags;
    if ((self->conf->decoder != NULL
         && decoder_setstate(self->conf->decoder, flags, self->fresh) < 0)
        || text_encoder_reset(self, self->conf->encoder, self->fresh) < 0)
    {
        return -1;
    }
    return 0;
}

/* After seek() to a cookie with characters to skip: decode them again. */
static int
text_skip(textio *self, Py_ssize_t n)
{
    tstore st = {.self = self};
    if (store_begin(&st, 1) < 0) {
        return -1;
    }
    int stop = 0, r = 0, final = 0;
    self->rbusy = 1;
    while (self->dchars == NULL || PyUnicode_GET_LENGTH(self->dchars) < n) {
        if (stop || final) {
            r = -2;
            break;
        }
        if (st.avail == 0 && !st.eof) {
            if (store_fill(&st) < 0) {
                r = -1;
                break;
            }
            continue;
        }
        final = st.eof;
        r = decoder_more(self, &st, &stop, 0);
        if (r < 0 || (r == 0 && store_fill(&st) < 0)) {
            r = -1;
            break;
        }
    }
    store_end(&st, 1);
    self->rbusy = 0;
    if (r == -2) {
        PyErr_SetString(PyExc_OSError, "can't restore logical file position");
    }
    if (r >= 0) {
        self->dpos = n;
    }
    /* Writes go back to the text position. */
    FT_ATOMIC_STORE_UINT8_RELAXED(self->decoded, 1);
    return r < 0 ? -1 : 0;
}

/*[clinic input]
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
/*[clinic end generated code: output=0a15679764e2d04d input=0f68adcb02cf2823]*/
{
    if (textio_enter(self, 1) < 0) {
        return NULL;
    }
    PyObject *res = NULL;
    Py_INCREF(cookieObj);
    if (textio_refuse_nested(self, 1) < 0) {
        goto done;
    }
    if (!self->conf->seekable) {
        textio_unsupported(self, "underlying stream is not seekable");
        goto done;
    }
    if (whence == SEEK_CUR || whence == SEEK_END) {
        int zero = PyObject_RichCompareBool(cookieObj, _PyLong_GetZero(),
                                            Py_EQ);
        if (zero <= 0) {
            if (zero == 0) {
                textio_unsupported(self, whence == SEEK_CUR
                                   ? "can't do nonzero cur-relative seeks"
                                   : "can't do nonzero end-relative seeks");
            }
            goto done;
        }
    }
    if (whence == SEEK_CUR) {
        /* Sync the buffer with the current position. */
        Py_SETREF(cookieObj, text_tell(self));
        if (cookieObj == NULL) {
            goto done;
        }
    }
    else if (whence == SEEK_END) {
        if (_PyFile_Flush((PyObject *)self) < 0 || textio_attached(self) < 0) {
            goto done;
        }
        textio_drop_reads(self);
        res = _PyObject_CallMethod(self->conf->buffer, &_Py_ID(seek), "ii",
                                   0, 2);
        Py_off_t pos = res ? PyLong_AsOff_t(res) : -1;
        if ((pos == -1 && PyErr_Occurred()) || text_moved(self, pos, 0) < 0) {
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
    /* gh-91112: a cookie tell() can't have returned is an error. */
    if (c.start_pos < 0 || c.chars_to_skip < 0 || c.bytes_to_feed < 0
        || (!self->conf->readable && (c.dec_flags || c.bytes_to_feed
                                || c.chars_to_skip || c.need_eof))
        || (self->conf->codec != CODEC_DECODER
            && ((uint32_t)c.dec_flags > 1 || c.chars_to_skip
                || c.bytes_to_feed || c.need_eof)))
    {
        PyErr_SetString(PyExc_OSError, "can't restore logical file position");
        goto done;
    }
    if (_PyFile_Flush((PyObject *)self) < 0 || textio_attached(self) < 0) {
        goto done;
    }
    textio_drop_reads(self);
    res = _PyObject_CallMethod(self->conf->buffer, &_Py_ID(seek), "(O&)",
                               PyLong_FromOff_t, (Py_off_t)c.start_pos);
    if (res == NULL) {
        goto done;
    }
    Py_CLEAR(res);
    uint32_t flags = (self->conf->codec == CODEC_DECODER
                      ? (uint32_t)c.dec_flags : 0);
    if (text_moved(self, c.start_pos, flags) < 0
        || (c.chars_to_skip > 0 && text_skip(self, c.chars_to_skip) < 0))
    {
        goto done;
    }
    self->after_cr = self->conf->codec != CODEC_DECODER && c.dec_flags == 1;
    res = Py_NewRef(cookieObj);
done:
    Py_DECREF(cookieObj);
    textio_leave(self);
    return res;
}

/*[clinic input]
_io.TextIOWrapper.truncate
    pos: object = None
    /
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_truncate_impl(textio *self, PyObject *pos)
/*[clinic end generated code: output=90ec2afb9bb7745f input=56ec8baa65aea377]*/
{
    if (textio_enter(self, 0) < 0) {
        return NULL;
    }
    /* At the text position (gh-70346): pos is a byte count. */
    PyObject *res = NULL, *buffer;
    if (text_sync(self) == 0 && _PyFile_Flush((PyObject *)self) == 0
        && (buffer = textio_buffer(self)) != NULL)
    {
        res = PyObject_CallMethodOneArg(buffer, &_Py_ID(truncate), pos);
        Py_DECREF(buffer);
    }
    textio_leave(self);
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
    tconf *cf = textio_conf(self);
    if (cf == NULL) {
        return NULL;
    }
    PyObject *res = (textio_check_closed(self, cf) < 0 ? NULL
                     : PyObject_CallMethodNoArgs(cf->buffer, &_Py_ID(flush)));
    conf_put(cf);
    return res;
}

/* close() of the buffer would write its pending data again after a flush
   that raised exc: drop it with the buffer's _discard_writes() if it has
   one, and warn that it was lost (gh-83973).  Steals exc, returns the
   exception to raise. */
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

/*[clinic input]
_io.TextIOWrapper.close
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_close_impl(textio *self)
/*[clinic end generated code: output=056ccf8b4876e4f4 input=9c2114315eae1948]*/
{
    if (textio_enter(self, 0) < 0) {
        return NULL;
    }
    if (textio_refuse_nested(self, 1) < 0) {
        textio_leave(self);
        return NULL;
    }
    PyObject *buffer = Py_NewRef(self->conf->buffer);
    PyObject *res = PyObject_GetAttr(buffer, &_Py_ID(closed));
    int r = res ? PyObject_IsTrue(res) : -1;
    Py_XDECREF(res);
    res = NULL;
    if (r != 0 || self->conf->buffer == NULL) {
        /* Closed, or detached meanwhile (gh-142594). */
        res = r < 0 ? NULL : Py_NewRef(Py_None);
        goto end;
    }
    if (self->finalizing) {
        res = PyObject_CallMethodOneArg(buffer, &_Py_ID(_dealloc_warn),
                                        (PyObject *)self);
        if (res == NULL) {
            PyErr_Clear();
        }
        Py_CLEAR(res);
    }
    PyObject *exc = NULL;
    r = text_finish_encoder(self);
    if (r == 0 && _PyFile_Flush((PyObject *)self) < 0) {
        r = -2;
    }
    if (r < 0) {
        /* A write failed: close completely, without the buffer's close()
           writing the data again. */
        exc = PyErr_GetRaisedException();
        exc = r == -2 ? text_discard_writes(buffer, exc) : exc;
    }
    textio_drop_reads(self);
    res = PyObject_CallMethodNoArgs(buffer, &_Py_ID(close));
    if (exc != NULL) {
        _PyErr_ChainExceptions1(exc);
        Py_CLEAR(res);
    }
end:
    Py_DECREF(buffer);
    textio_leave(self);
    return res;
}

/*[clinic input]
_io.TextIOWrapper.detach
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_detach_impl(textio *self)
/*[clinic end generated code: output=7ba3715cd032d5f2 input=e5a71fbda9e1d9f9]*/
{
    if (textio_enter(self, 0) < 0) {
        return NULL;
    }
    PyObject *buffer = NULL;
    tconf *cf = NULL;
    if (text_finish_encoder(self) == 0 && _PyFile_Flush((PyObject *)self) == 0
        && textio_attached(self) == 0 && text_sync(self) == 0
        && (cf = conf_new(self->conf)) != NULL)
    {
        /* The settings stay, for the attributes. */
        buffer = cf->buffer;
        cf->buffer = NULL;
        conf_set_quick(self, cf);
        cf = conf_swap(self, cf);
    }
    textio_leave(self);
    conf_put(cf);
    return buffer;
}

/* Methods passed on to the buffer. */
static PyObject *
textio_buffer_call(PyObject *op, PyObject *name)
{
    tconf *cf = textio_conf(textio_CAST(op));
    PyObject *res = cf ? PyObject_CallMethodNoArgs(cf->buffer, name) : NULL;
    conf_put(cf);
    return res;
}

#define TEXTIO_BUFFER_METHOD(name)                                      \
    static PyObject *                                                   \
    textio_pass_##name(PyObject *op, PyObject *Py_UNUSED(dummy))        \
    {                                                                   \
        return textio_buffer_call(op, &_Py_ID(name));                   \
    }
TEXTIO_BUFFER_METHOD(fileno)
TEXTIO_BUFFER_METHOD(seekable)
TEXTIO_BUFFER_METHOD(readable)
TEXTIO_BUFFER_METHOD(writable)
TEXTIO_BUFFER_METHOD(isatty)
#undef TEXTIO_BUFFER_METHOD

#define BUFFER_METHODDEF(name) \
    {#name, textio_pass_##name, METH_NOARGS, #name "($self, /)\n--\n\n"},

/* The buffer's attribute name (closure). */
static PyObject *
textio_buffer_getattr(PyObject *op, void *name)
{
    textio *self = textio_CAST(op);
    if (name == &_Py_ID(closed)
        && FT_ATOMIC_LOAD_PTR_ACQUIRE(self->conf) == NULL)
    {
        /* Partially constructed: closed (as _io's). */
        Py_RETURN_TRUE;
    }
    tconf *cf = textio_conf(self);
    PyObject *res = (cf == NULL ? NULL : name == NULL ? Py_NewRef(cf->buffer)
                     : PyObject_GetAttr(cf->buffer, name));
    conf_put(cf);
    return res;
}

static PyObject *
textio_newlines_get(PyObject *op, void *Py_UNUSED(closure))
{
    /* (Looking at the settings without a reference, as
       textio_attached().) */
    textio *self = textio_CAST(op);
    tconf *cf = FT_ATOMIC_LOAD_PTR_ACQUIRE(self->conf);
    if (conf_attached(cf) < 0) {
        return NULL;
    }
    if (!cf->readuniversal || !cf->readable) {
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

/* The setting at offset in tconf (None before __init__()). */
static PyObject *
textio_setting_get(PyObject *op, void *offset)
{
    tconf *cf = conf_get(textio_CAST(op));
    if (cf == NULL) {
        Py_RETURN_NONE;
    }
    PyObject *res = Py_NewRef(*(PyObject **)((char *)cf + (Py_ssize_t)offset));
    conf_put(cf);
    return res;
}

/* The flag at offset in tconf (False before __init__()). */
static PyObject *
textio_flag_get(PyObject *op, void *offset)
{
    /* (Looking at the settings without a reference, as textio_attached().) */
    tconf *cf = FT_ATOMIC_LOAD_PTR_ACQUIRE(textio_CAST(op)->conf);
    return PyBool_FromLong(cf ? *((char *)cf + (Py_ssize_t)offset) : 0);
}

/*[clinic input]
@getter
_io.TextIOWrapper._CHUNK_SIZE -> Py_ssize_t
[clinic start generated code]*/

static Py_ssize_t
_io_TextIOWrapper__CHUNK_SIZE_get_impl(textio *self)
/*[clinic end generated code: output=3fe34b873b6b2c8c input=7e8abe69bf1cd463]*/
{
    return (textio_attached(self) < 0 ? -1
            : FT_ATOMIC_LOAD_SSIZE_RELAXED(self->chunk_size));
}

/*[clinic input]
@setter
_io.TextIOWrapper._CHUNK_SIZE
    value: Py_ssize_t
[clinic start generated code]*/

static int
_io_TextIOWrapper__CHUNK_SIZE_set_impl(textio *self, Py_ssize_t value)
/*[clinic end generated code: output=5170a93dd4d74917 input=4613131e37b7cf5c]*/
{
    if (textio_attached(self) < 0) {
        return -1;
    }
    if (value <= 0) {
        PyErr_SetString(PyExc_ValueError,
                        "a strictly positive integer is required");
        return -1;
    }
    FT_ATOMIC_STORE_SSIZE_RELAXED(self->chunk_size, value);
    return 0;
}

static PyObject *
textiowrapper_repr(PyObject *op)
{
    textio *self = textio_CAST(op);
    const char *type_name = Py_TYPE(self)->tp_name;
    if (FT_ATOMIC_LOAD_PTR_ACQUIRE(self->conf) == NULL) {
        (void)conf_attached(NULL);
        return NULL;
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
        PyObject *encoding = textio_setting_get(
            op, (void *)offsetof(tconf, encoding));
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
        PyErr_Format(PyExc_ValueError, "illegal newline value: %s", newline);
        return -1;
    }
    return 0;
}

static int
set_newline(tconf *t, const char *newline)
{
    PyObject *readnl = newline ? PyUnicode_FromString(newline) : NULL;
    if (newline && readnl == NULL) {
        return -1;
    }
    Py_XSETREF(t->readnl, readnl);
    t->readuniversal = (newline == NULL || newline[0] == '\0');
    t->readtranslate = (newline == NULL);
    t->writetranslate = (newline == NULL || newline[0] != '\0');
    t->writenl = NULL;
    if (!t->readuniversal && readnl != NULL) {
        t->writenl = (const char *)PyUnicode_1BYTE_DATA(readnl);
        if (strcmp(t->writenl, "\n") == 0) {
            t->writenl = NULL;
        }
    }
#ifdef MS_WINDOWS
    else {
        t->writenl = "\r\n";
    }
#endif
    return 0;
}

/* The decoding table of a codec of the encodings package that decodes byte
   by byte with one (cp1252 and others), if it decodes ASCII as ASCII and
   other bytes as other characters.  A new reference, or NULL. */
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

static int
call_bool(PyObject *obj, PyObject *name)
{
    PyObject *res = PyObject_CallMethodNoArgs(obj, name);
    int r = res ? PyObject_IsTrue(res) : -1;
    Py_XDECREF(res);
    return r;
}

/* Set up t for encoding (a str) and errors, over buffer: the decoder (if
   readable), the encoder (if writable), and how bytes map to
   characters. */
static int
set_codec(tconf *t, PyObject *buffer, PyObject *encoding,
          PyObject *errors)
{
    Py_XSETREF(t->encoding, Py_NewRef(encoding));
    Py_XSETREF(t->errors, Py_NewRef(errors));
    const char *enc = PyUnicode_AsUTF8(encoding);
    const char *err = PyUnicode_AsUTF8(errors);
    if (enc == NULL || err == NULL) {
        return -1;
    }
    /* NULL is "strict", which the UTF-8 decoder does fastest. */
    t->errors_str = strcmp(err, "strict") == 0 ? NULL : err;
    /* A real text encoding. */
    PyObject *info = _PyCodec_LookupTextEncoding(enc, NULL);
    if (info == NULL) {
        return -1;
    }
    PyObject *name;
    int r = PyObject_GetOptionalAttr(info, &_Py_ID(name), &name);
    int codec = CODEC_DECODER;
    if (name != NULL && PyUnicode_Check(name)) {
        codec = (_PyUnicode_EqualToASCIIString(name, "utf-8") ? CODEC_UTF8
                 : _PyUnicode_EqualToASCIIString(name, "iso8859-1")
                   ? CODEC_LATIN1
                 : _PyUnicode_EqualToASCIIString(name, "ascii") ? CODEC_ASCII
                 : CODEC_DECODER);
    }
    Py_XDECREF(name);
    Py_CLEAR(t->charmap);
    if (r >= 0 && codec == CODEC_DECODER) {
        t->charmap = codec_charmap(info);
        r = t->charmap == NULL && PyErr_Occurred() ? -1 : 0;
        codec = t->charmap ? CODEC_CHARMAP : CODEC_DECODER;
    }
    t->enc = (char)codec;
    /* Error handlers keeping one character per byte (or valid UTF-8
       sequence) keep the bytes of characters known. */
    int same = (t->errors_str == NULL || strcmp(err, "surrogateescape") == 0
                || (codec != CODEC_UTF8 && strcmp(err, "replace") == 0));
    t->codec = (char)(codec == CODEC_LATIN1 || same ? codec : CODEC_DECODER);
    Py_CLEAR(t->decoder);
    Py_CLEAR(t->encoder);
    r = r < 0 ? -1 : call_bool(buffer, &_Py_ID(readable));
    t->readable = r > 0;
    if (r > 0 && t->codec == CODEC_DECODER) {
        t->decoder = _PyCodecInfo_GetIncrementalDecoder(info, err);
        r = t->decoder ? r : -1;
    }
    r = r < 0 ? -1 : call_bool(buffer, &_Py_ID(writable));
    if (r > 0) {
        t->encoder = _PyCodecInfo_GetIncrementalEncoder(info, err);
        r = t->encoder ? r : -1;
    }
    Py_DECREF(info);
    return r < 0 ? -1 : 0;
}

/* Before cf (with a new encoder) is published: the encoder writes a BOM
   only at the start of the stream. */
static int
text_fix_encoder_state(textio *self, tconf *cf)
{
    FT_ATOMIC_STORE_CHAR_RELAXED(self->encoding_start_of_stream, 0);
    FT_ATOMIC_STORE_CHAR_RELAXED(self->encoder_used, 0);
    if (!cf->seekable || cf->encoder == NULL) {
        return 0;
    }
    PyObject *pos = PyObject_CallMethodNoArgs(cf->buffer, &_Py_ID(tell));
    int start = pos ? PyObject_RichCompareBool(pos, _PyLong_GetZero(), Py_EQ)
                    : -1;
    Py_XDECREF(pos);
    return start < 0 ? -1 : text_encoder_reset(self, cf->encoder, start);
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
    conf_put(conf_swap(self, NULL));
    textio_drop_reads(self);
    Py_CLEAR(self->dict);
    return 0;
}

/*[clinic input]
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
/*[clinic end generated code: output=72267c0c01032ed2 input=e6cfaaaf6059d4f5]*/
{
    /* Not set up meanwhile, nor after a failure, as _io's. */
    if (textio_lock(self) < 0) {
        return -1;
    }
    if (textio_refuse_nested(self, 0) < 0) {
        textio_leave(self);
        return -1;
    }
    /* (The old settings are dropped once rlock is released.) */
    tconf *old = conf_swap(self, NULL);
    int r = -1;
    tconf *cf = conf_new(NULL);
    if (cf == NULL) {
        goto end;
    }
    if (encoding == NULL) {
        PyInterpreterState *interp = _PyInterpreterState_GET();
        if (_PyInterpreterState_GetConfig(interp)->warn_default_encoding
            && PyErr_WarnEx(PyExc_EncodingWarning,
                            "'encoding' argument not specified", 1))
        {
            goto end;
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
        goto end;
    }
    else if (io_check_errors(errors)) {
        goto end;
    }
    if (_PyUnicode_AsUTF8NoNUL(errors) == NULL
        || validate_newline(newline) < 0)
    {
        goto end;
    }
    PyObject *enc = text_encoding(encoding);
    int seekable = -1, has_read1 = -1;
    if (enc != NULL && set_codec(cf, buffer, enc, errors) == 0
        && set_newline(cf, newline) == 0
        && (seekable = call_bool(buffer, &_Py_ID(seekable))) >= 0)
    {
        has_read1 = PyObject_HasAttrWithError(buffer, &_Py_ID(read1));
    }
    Py_XDECREF(enc);
    if (has_read1 >= 0) {
        cf->buffer = Py_NewRef(buffer);
        cf->seekable = (char)seekable;
        cf->has_read1 = (char)has_read1;
        cf->nib = _PyIO_is_nibbler_buffered_type(Py_TYPE(buffer));
        cf->line_buffering = (char)line_buffering;
        cf->write_through = (char)write_through;
        conf_set_quick(self, cf);
        textio_drop_reads(self);
        FT_ATOMIC_STORE_SSIZE_RELAXED(self->chunk_size, 8192);
        FT_ATOMIC_STORE_UINT8_RELAXED(self->seennl, 0);
        self->fresh = 1;
        r = text_fix_encoder_state(self, cf);
        if (r == 0) {
            /* (Nothing replaced: nested calls can't set it up.) */
            cf = conf_swap(self, cf);
        }
    }
end:
    textio_leave(self);
    conf_put(cf);
    conf_put(old);
    return r;
}

/* Return default_value if obj is None, 0 if obj is false, 1 if obj is
   true, -1 on error. */
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
/*[clinic end generated code: output=52b812ff4b3d4b0f input=671e82136e0f5822]*/
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
    const char *newline = NULL;
    if (newline_obj != NULL && newline_obj != Py_None) {
        newline = PyUnicode_AsUTF8(newline_obj);
        if (newline == NULL || validate_newline(newline) < 0) {
            return NULL;
        }
    }
    if (textio_enter(self, 0) < 0) {
        return NULL;
    }
    if (textio_refuse_nested(self, 0) < 0) {
        textio_leave(self);
        return NULL;
    }
    int codec_change = encoding != Py_None || errors != Py_None;
    if (self->decoded && (codec_change || newline_obj != NULL)) {
        textio_leave(self);
        return textio_unsupported(self, "It is not possible to set the "
                                  "encoding or newline of stream after the "
                                  "first read");
    }
    int line_buffering = convert_optional_bool(line_buffering_obj,
                                               self->conf->line_buffering);
    int write_through = line_buffering < 0 ? -1 : convert_optional_bool(
        write_through_obj, self->conf->write_through);
    tconf *cf = NULL;
    int r = line_buffering < 0 || write_through < 0 ? -1 : 0;
    if (r == 0 && codec_change) {
        /* The old encoder ends its text first (gh-79792). */
        r = text_finish_encoder(self);
    }
    r = (r < 0 || _PyFile_Flush((PyObject *)self) < 0
         || textio_attached(self) < 0
         || (cf = conf_new(self->conf)) == NULL) ? -1 : 0;
    if (r == 0 && newline_obj != NULL) {
        r = set_newline(cf, newline);
    }
    if (r == 0 && codec_change) {
        /* The current settings where new ones are not given. */
        if (encoding == Py_None) {
            encoding = Py_NewRef(cf->encoding);
            errors = errors == Py_None ? cf->errors : errors;
        }
        else {
            encoding = (PyUnicode_CompareWithASCIIString(encoding, "locale")
                        == 0 ? _Py_GetLocaleEncodingObject()
                        : Py_NewRef(encoding));
            errors = errors == Py_None ? &_Py_ID(strict) : errors;
        }
        Py_INCREF(errors);
        r = encoding ? set_codec(cf, cf->buffer, encoding, errors) : -1;
        Py_XDECREF(encoding);
        Py_DECREF(errors);
    }
    if (r == 0) {
        cf->line_buffering = (char)line_buffering;
        cf->write_through = (char)write_through;
        conf_set_quick(self, cf);
        if (codec_change) {
            self->fresh = 1;
            textio_drop_reads(self);
            r = text_fix_encoder_state(self, cf);
        }
    }
    if (r == 0) {
        cf = conf_swap(self, cf);
    }
    textio_leave(self);
    conf_put(cf);
    return r < 0 ? NULL : Py_NewRef(Py_None);
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
    tconf *cf = self->conf;
    Py_VISIT(Py_TYPE(self));
    if (cf != NULL) {
#define CONF_VISIT(f) Py_VISIT(cf->f);
        CONF_OBJECTS(CONF_VISIT)
#undef CONF_VISIT
    }
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
    BUFFER_METHODDEF(fileno)
    BUFFER_METHODDEF(seekable)
    BUFFER_METHODDEF(readable)
    BUFFER_METHODDEF(writable)
    BUFFER_METHODDEF(isatty)
    _IO_TEXTIOWRAPPER_SEEK_METHODDEF
    _IO_TEXTIOWRAPPER_TELL_METHODDEF
    _IO_TEXTIOWRAPPER_TRUNCATE_METHODDEF
    {"__getstate__", _PyIOBase_cannot_pickle, METH_NOARGS},
    {NULL, NULL}
};

static PyMemberDef textiowrapper_members[] = {
    {"_finalizing", Py_T_BOOL, offsetof(textio, finalizing), 0},
    {"__weaklistoffset__", Py_T_PYSSIZET, offsetof(textio, weakreflist),
     Py_READONLY},
    {"__dictoffset__", Py_T_PYSSIZET, offsetof(textio, dict), Py_READONLY},
    {NULL}
};

static PyGetSetDef textiowrapper_getset[] = {
    {"name", textio_buffer_getattr, NULL, NULL, &_Py_ID(name)},
    {"closed", textio_buffer_getattr, NULL, NULL, &_Py_ID(closed)},
    {"buffer", textio_buffer_getattr, NULL, NULL, NULL},
    {"newlines", textio_newlines_get, NULL, NULL, NULL},
    {"encoding", textio_setting_get, NULL, NULL,
     (void *)offsetof(tconf, encoding)},
    {"errors", textio_setting_get, NULL, NULL,
     (void *)offsetof(tconf, errors)},
    {"line_buffering", textio_flag_get, NULL, NULL,
     (void *)offsetof(tconf, line_buffering)},
    {"write_through", textio_flag_get, NULL, NULL,
     (void *)offsetof(tconf, write_through)},
    _IO_TEXTIOWRAPPER__CHUNK_SIZE_GETSETDEF
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

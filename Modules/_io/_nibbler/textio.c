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

typedef struct {
    PyObject_HEAD
    char ok;                    /* initialized? */
    char detached;
    char finalizing;
    char line_buffering;
    char write_through;
    char readable;
    char readuniversal;
    char readtranslate;
    char writetranslate;
    char seekable;
    char has_read1;             /* the buffer has read1() */
    char nib;                   /* the store is the buffer itself */
    char nib_ok;                /* the buffer can be the store */
    char codec;                 /* CODEC_* for reads */
    char enc;                   /* CODEC_* for writes (CHARMAP: ASCII only) */
    char encoding_start_of_stream;  /* the encoder may write a BOM */
    char encoder_used;          /* the encoder needs final=True at the end */
    char decoded;               /* read since the last seek or write */
    char seennl;                /* SEEN_* */
    char skip_lf;               /* the "\n" at the position ends a "\r\n"
                                   already seen */
    Py_ssize_t chunk_size;
    PyObject *buffer;
    PyObject *encoding;
    PyObject *errors;
    PyObject *encoder;
    PyObject *decoder;          /* CODEC_DECODER only */
    PyObject *charmap;          /* CODEC_CHARMAP's decoding table */
    PyObject *readnl;
    const char *writenl;        /* ASCII; NULL stands for "\n" */

    /* Decoded characters: chars[ci:] are those at the position.  With a
       native codec, while the store's unread bytes are those named by key
       at offset koff in their block, of which the first kbytes made them.
       With the decoder, they came from the bytes taken last, dspan, which
       the decoder started on with flags dflags; at the store's position,
       the decoder holds nothing and has flags `flags` (FLAGS_FRESH: as
       after reset(), not asked yet). */
    PyObject *chars;
    Py_ssize_t ci;
    char dwide;                 /* chars has some from U+0800 on */
    /* Where the first "\r" of chars at or after ci is (none: its length),
       if not below ci. */
    Py_ssize_t cr_at;
    uint64_t key;
    Py_ssize_t koff;
    Py_ssize_t kbytes;
    PyObject *dspan;
    int dflags;
    int flags;
    /* Counts the moves of the position: another thread may move it while
       this one waits for the buffer. */
    uint64_t moves;

    /* The store over other buffers: rbuf[rpos:] is read-ahead (rgen tells
       its successive values apart). */
    PyObject *rbuf;
    Py_ssize_t rpos;
    uint64_t rgen;

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

/* A new reference to the buffer, or NULL with ValueError. */
static PyObject *
textio_buffer(textio *self)
{
    if (self->ok <= 0 || self->buffer == NULL) {
        PyErr_SetString(PyExc_ValueError, self->ok > 0 && self->detached
                        ? "underlying buffer has been detached"
                        : "I/O operation on uninitialized object");
        return NULL;
    }
    return Py_NewRef(self->buffer);
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
    Py_ssize_t held;    /* bytes of m the decoder held (it forgot them) */
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

/* The cache is of the buffer as the store: no use with rbuf. */
static void
textio_drop_chars(textio *self)
{
    Py_CLEAR(self->chars);
    Py_CLEAR(self->dspan);
    self->ci = 0;
    self->cr_at = -1;
    self->moves++;
}

/* Use the buffer through its methods: for good (it got an instance dict),
   or while it can't hold the bytes needed (keeping read-ahead in rbuf). */
static void
store_use_methods(textio *self, int for_good)
{
    self->nib = 0;
    self->nib_ok &= !for_good;
    if (self->codec != CODEC_DECODER) {
        textio_drop_chars(self);
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
        if (r != _PyIO_NIBBLER_NO && r != _PyIO_NIBBLER_FULL) {
            st->status = r;
            st->eof = r == 0 && st->m.len < need;
            return r < 0 ? -1 : 0;
        }
        store_use_methods(self, r == _PyIO_NIBBLER_NO);
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
            Py_MAX(self->chunk_size, Py_MAX(need - have, have)));
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
        if (self->encoding_start_of_stream && self->encoder != NULL) {
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

static int
store_write(textio *self, PyObject *buffer, PyObject *obj, const char *data,
            Py_ssize_t len)
{
    if (len == 0) {
        return 0;
    }
    if (store_rewind(self, buffer) < 0) {
        return -1;
    }
    self->nib = self->nib_ok && self->rbuf == NULL;
    if (self->nib) {
        int r = _PyIONibbler_write(buffer, obj, data, len);
        if (r != _PyIO_NIBBLER_NO) {
            return r;
        }
        store_use_methods(self, 1);
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

/*
 * Decoding
 */

/* Characters at or above 0x800 in the UCS-2 data p[0:k]? */
static int
ucs2_has_wide(const Py_UCS2 *p, Py_ssize_t k)
{
    Py_UCS2 any = 0;
    for (Py_ssize_t j = 0; j < k; j++) {
        any |= p[j];
    }
    return any >= 0x800;
}

/* The UTF-8 bytes of chars[i:i+k] (surrogates were bytes escaped with
   surrogateescape: one each).  Unless wide (characters from U+0800 on in
   chars), characters above 0x7f take two bytes: count them (in 16-bit
   sums, which vectorize well). */
static Py_ssize_t
utf8_bytes(PyObject *chars, int wide, Py_ssize_t i, Py_ssize_t k)
{
    Py_ssize_t n = k;
    if (PyUnicode_IS_ASCII(chars)) {
        return n;
    }
    const void *data = PyUnicode_DATA(chars);
    int kind = PyUnicode_KIND(chars);
    if (kind == PyUnicode_1BYTE_KIND) {
        const Py_UCS1 *p = (const Py_UCS1 *)data + i;
        const uint64_t highs = 0x8080808080808080ull;
        Py_ssize_t j = 0;
        for (; j + 8 <= k; j += 8) {
            uint64_t w;
            memcpy(&w, p + j, 8);
            n += (((w & highs) >> 7) * 0x0101010101010101ull) >> 56;
        }
        for (; j < k; j++) {
            n += p[j] >> 7;
        }
    }
    else if (kind == PyUnicode_2BYTE_KIND && !wide) {
        const Py_UCS2 *p = (const Py_UCS2 *)data + i;
        for (Py_ssize_t j = 0; j < k; j += 0x4000) {
            Py_ssize_t m = Py_MIN(k - j, 0x4000);
            uint16_t sum = 0;
            for (Py_ssize_t q = 0; q < m; q++) {
                sum += p[j + q] >= 0x80;
            }
            n += sum;
        }
    }
    else {
        for (Py_ssize_t j = i; j < i + k; j++) {
            Py_UCS4 c = PyUnicode_READ(kind, data, j);
            n += (c >= 0x80) + (c >= 0x800) + (c >= 0x10000)
                 - 2 * Py_UNICODE_IS_SURROGATE(c);
        }
    }
    return n;
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
    case CODEC_UTF8:
        return PyUnicode_DecodeUTF8Stateful(s, len, errors,
                                            final ? NULL : used);
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
decoder_offset(textio *self, Py_ssize_t *off, int *flags)
{
    /* The decoder runs Python code, which may use self. */
    PyObject *span = Py_NewRef(self->dspan);
    Py_ssize_t ci = self->ci;
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
    return (self->chars != NULL
            && (self->codec == CODEC_DECODER || !st->peeked
                || (st->m.obj != NULL && st->key == self->key
                    && st->m.ptr - PyBytes_AS_STRING(st->m.obj)
                       == self->koff)));
}

/* How many characters there are at the position, decoded. */
static Py_ssize_t
text_avail(textio *self, store *st)
{
    return (text_valid(self, st)
            ? PyUnicode_GET_LENGTH(self->chars) - self->ci : 0);
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
    Py_ssize_t covered = text_valid(self, st) ? self->kbytes : 0;
    if (st->m.obj != NULL && covered < st->m.len) {
        /* A bigger span from the position: twice as much (and a whole
           character more), so that a long line is decoded O(1) times. */
        Py_ssize_t span = Py_MIN(st->m.len,
                                 Py_MAX(self->chunk_size, 2 * covered + 4));
        span = st->all ? st->m.len : span;
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
            else if (store_take(self, st, Py_MIN(end, st->m.len)) < 0) {
                return -1;
            }
        }
        if (chars == NULL) {
            return -1;
        }
        Py_XSETREF(self->chars, chars);
        self->ci = 0;
        self->cr_at = -1;
        self->dwide = (PyUnicode_KIND(chars) == PyUnicode_4BYTE_KIND
                       || (PyUnicode_KIND(chars) == PyUnicode_2BYTE_KIND
                           && ucs2_has_wide(PyUnicode_2BYTE_DATA(chars),
                                            PyUnicode_GET_LENGTH(chars))));
        self->key = st->key;
        self->koff = st->m.ptr - PyBytes_AS_STRING(st->m.obj);
        self->kbytes = used;
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
    return (text_valid(self, st) ? self->kbytes : 0) < st->m.len;
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
    if (self->chars == NULL || self->dspan == NULL
        || self->ci == PyUnicode_GET_LENGTH(self->chars))
    {
        Py_XSETREF(self->chars, chars);
        Py_XSETREF(self->dspan, bytes);
        self->ci = 0;
        self->dflags = self->flags;
        self->cr_at = -1;
    }
    else {
        PyUnicode_Append(&self->chars, chars);
        PyBytes_ConcatAndDel(&self->dspan, bytes);
        self->cr_at = -1;
        Py_DECREF(chars);
        if (self->chars == NULL || self->dspan == NULL) {
            textio_drop_chars(self);
            return -1;
        }
    }
    self->flags = flags;
    return 1;
}

/* Make chars[ci:] the characters at the position, more than `have` of
   them if the store has more now.  Returns how many, or -1.
   st->at_end tells whether none can ever follow them. */
static inline int
text_at_end(textio *self, store *st, Py_ssize_t avail)
{
    return st->eof && (self->codec == CODEC_DECODER ? st->m.len == 0
                       : avail == 0 || self->kbytes == st->m.len);
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
    Py_ssize_t ci = self->ci;
    if (self->codec != CODEC_DECODER) {
        Py_ssize_t b = (self->codec == CODEC_UTF8
                        ? utf8_bytes(self->chars, self->dwide, ci, k) : k);
        uint64_t moves = self->moves;
        int r = store_advance(self, st, self->key, self->koff, b);
        /* Waiting for the buffer's lock, other threads may have run. */
        if (r <= 0 || self->moves != moves) {
            textio_drop_chars(self);
            if (r == 0) {
                store_forget(st);
            }
            return r;
        }
        self->koff += b;
        self->kbytes -= b;
    }
    self->ci = ci + k;
    self->moves++;
    self->decoded = 1;
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

/* The first "\r" in s[0:end) of chars' data, or NULL.  Where the next one
   is is kept, so that "\r"-less text is looked at once. */
static const char *
find_cr(textio *self, int kind, const char *s, const char *end)
{
    const char *base = PyUnicode_DATA(self->chars);
    if (self->cr_at < (s - base) / kind) {
        Py_ssize_t len = PyUnicode_GET_LENGTH(self->chars);
        const char *cr = find_char(kind, s, base + len * kind, '\r');
        self->cr_at = cr ? (cr - base) / kind : len;
    }
    const char *cr = base + self->cr_at * kind;
    return cr < end ? cr : NULL;
}

/* The length of the first line of s[0:end), with its newline, or -1 if
   none ends there (a "\r" at the end may begin a "\r\n"): then *resume
   is where to look on from. */
static Py_ssize_t
find_line(textio *self, int kind, const char *s, const char *end,
          Py_ssize_t *resume)
{
    if (self->readuniversal) {
        const char *lf = find_char(kind, s, end, '\n');
        const char *cr = find_cr(self, kind, s, lf ? lf : end);
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

/* The text of the characters at the position, chars[i:i+avail]: up to
   `want` characters of it (-1: no limit), or with `line` up to the end of
   the first line.  With universal newlines, a "\r" is taken only once what
   follows it is known (or at eof), and translated with readtranslate.
   *k gets how many characters are taken (0: nothing can be yet), and with
   `line`, *found whether the line (or want) ended; *scanned is where the
   search for its end goes on from.  Notes the newlines in the text. */
static PyObject *
text_take(textio *self, Py_ssize_t avail, Py_ssize_t want, int line,
          int eof, Py_ssize_t *scanned, Py_ssize_t *k, int *found)
{
    PyObject *chars = self->chars;
    Py_ssize_t i = self->ci;
    int kind = PyUnicode_KIND(chars);
    const char *s = (const char *)PyUnicode_DATA(chars) + i * kind;
    const char *end = s + avail * kind;
#define AT(j) PyUnicode_READ(kind, s, (j))
    int seen = 0, translate = 0, skip_lf = 0;
    Py_ssize_t n, out;
    *found = 0;
    if (line) {
        Py_ssize_t resume = 0;
        Py_ssize_t e = find_line(self, kind, s + *scanned * kind, end,
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
                       : (n == 1 && self->skip_lf) ? 0 : SEEN_LF;
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
                          ? find_cr(self, kind, s, s + lim * kind) : NULL);
        n = out = cr ? (cr - s) / kind : lim;
        if (self->readuniversal && !(self->seennl & SEEN_LF)) {
            Py_ssize_t from = self->skip_lf && n > 0 && AT(0) == '\n';
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
            cr = find_cr(self, kind, s + n * kind, s + (n + left) * kind);
            Py_ssize_t run = cr ? (cr - s) / kind - n : left;
            if (!(self->seennl & SEEN_LF) && !(seen & SEEN_LF)
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
    self->seennl |= seen;
    self->skip_lf = skip_lf;
    PyObject *res = PyUnicode_Substring(chars, i, i + n);
    if (res == NULL || !translate) {
        return res;
    }
    /* Translated: "\r\n" and "\r" become "\n". */
    PyObject *t = PyUnicode_New(out, PyUnicode_MAX_CHAR_VALUE(res));
    if (t != NULL) {
        int tkind = PyUnicode_KIND(t);
        void *tdata = PyUnicode_DATA(t);
        Py_ssize_t o = 0;
        for (Py_ssize_t j = 0; j < n; j++) {
            Py_UCS4 c = AT(j);
            if (c == '\r') {
                c = '\n';
                j += j + 1 < n && AT(j + 1) == '\n';
            }
            PyUnicode_WRITE(tkind, tdata, o++, c);
        }
        assert(o == out);
    }
    Py_DECREF(res);
    return t;
#undef AT
}

/* read(n) (n < 0: all), or with line, readline(n). */
static PyObject *
text_read(textio *self, Py_ssize_t n, int line)
{
    /* With native codecs the buffer checks that it is open when the bytes
       are looked at or taken. */
    int peeks = textio_exact(self) && self->nib_ok
                && self->codec != CODEC_DECODER;
    store st = {.buffer = peeks ? textio_buffer(self) : textio_ready(self),
                .all = n < 0 && !line};
    if (st.buffer == NULL) {
        return NULL;
    }
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
    /* The text so far: res, then in writer once there are two pieces. */
    PyObject *res = NULL;
    _PyUnicodeWriter writer;
    int pieces = 0;
    /* have: characters at the position looked at without a decision. */
    Py_ssize_t got = 0, have = 0, scanned = 0;
    while (n != got) {
        uint64_t moves = self->moves;
        Py_ssize_t avail = text_avail(self, &st);
        if (avail > have && !st.all) {
            st.at_end = text_at_end(self, &st, avail);
        }
        else if ((avail = text_more(self, &st, have)) < 0) {
            goto error;
        }
        if (self->moves != moves && (have || scanned)) {
            /* What was looked at may be gone: look again. */
            have = scanned = 0;
            continue;
        }
        Py_ssize_t k = 0;
        int found = 0;
        PyObject *text = NULL;
        if (avail > 0) {
            text = text_take(self, avail, n < 0 ? -1 : n - got, line,
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
        if (k == 0 && avail > 0 && line && st.status == _PyIO_NIBBLER_BLOCKED
            && avail >= READLINE_KEEP_MAX * self->chunk_size)
        {
            /* Too long to keep for the next call: take it as it is, but a
               last "\r" (that may begin a "\r\n"). */
            k = avail - (self->readuniversal && avail > 1
                         && PyUnicode_READ_CHAR(self->chars,
                                                self->ci + avail - 1) == '\r');
            text = PyUnicode_Substring(self->chars, self->ci, self->ci + k);
            if (text == NULL) {
                goto error;
            }
            found = 1;
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
    return (pieces > 1 ? _PyUnicodeWriter_Finish(&writer)
            : res ? res : Py_GetConstant(Py_CONSTANT_EMPTY_STR));

error:
    store_release(&st);
    Py_DECREF(st.buffer);
    Py_XDECREF(res);
    if (pieces > 1) {
        _PyUnicodeWriter_Dealloc(&writer);
    }
    return NULL;
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
    const char *errors = (enc == CODEC_DECODER || enc == CODEC_CHARMAP ? NULL
                          : PyUnicode_AsUTF8(self->errors));
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
    Py_ssize_t off;
    int flags;
    if (!self->seekable || decoder_offset(self, &off, &flags) < 0) {
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
    self->skip_lf = 0;
    self->decoded = 0;
    if (self->codec == CODEC_DECODER) {
        if (self->chars != NULL && decoder_sync(self, buffer) < 0) {
            return -1;
        }
    }
    else if (self->chars != NULL) {
        textio_drop_chars(self);
    }
    return self->rbuf ? store_rewind(self, buffer) : 0;
}

/*[clinic input]
@critical_section
_io.TextIOWrapper.write
    text: unicode
    /
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_write_impl(textio *self, PyObject *text)
/*[clinic end generated code: output=d2deb0d50771fcec input=73ec95c5c4a3489c]*/
{
    PyObject *buffer = textio_ready(self);
    if (buffer == NULL) {
        return NULL;
    }
    if (self->encoder == NULL) {
        Py_DECREF(buffer);
        return textio_unsupported(self, "not writable");
    }
    Py_ssize_t textlen = PyUnicode_GET_LENGTH(text);
    int haslf = ((self->writetranslate && self->writenl != NULL)
                 || self->line_buffering)
                && PyUnicode_FindChar(text, '\n', 0, textlen, 1) != -1;
    int needflush = self->line_buffering
                    && (haslf || PyUnicode_FindChar(text, '\r', 0, textlen,
                                                    1) != -1);
    Py_INCREF(text);
    if (haslf && self->writetranslate && self->writenl != NULL) {
        Py_SETREF(text, _PyObject_CallMethod(text, &_Py_ID(replace), "ss",
                                             "\n", self->writenl));
    }
    int r = (text == NULL || ((self->chars || self->rbuf || self->decoded)
                              && text_sync(self, buffer) < 0)
             ? -1 : text_write(self, buffer, text));
    Py_XDECREF(text);
    self->encoding_start_of_stream = 0;
    if (r == 0 && needflush) {
        r = _PyFile_Flush(buffer);
    }
    Py_DECREF(buffer);
    return r < 0 ? NULL : PyLong_FromSsize_t(textlen);
}

/*
 * Reading
 */

/*[clinic input]
@critical_section
_io.TextIOWrapper.read
    size as n: Py_ssize_t(accept={int, NoneType}) = -1
    /
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_read_impl(textio *self, Py_ssize_t n)
/*[clinic end generated code: output=7e651ce6cc6a25a6 input=67d14c5661121377]*/
{
    return text_read(self, n < 0 ? -1 : n, 0);
}

/*[clinic input]
@critical_section
_io.TextIOWrapper.readline
    size: Py_ssize_t = -1
    /
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_readline_impl(textio *self, Py_ssize_t size)
/*[clinic end generated code: output=344afa98804e8b25 input=b65bab871dc3ddba]*/
{
    return text_read(self, size < 0 ? -1 : size, 1);
}

static PyObject *
textiowrapper_iternext(PyObject *op)
{
    textio *self = textio_CAST(op);
    PyObject *line;
    Py_BEGIN_CRITICAL_SECTION(op);
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
    Py_END_CRITICAL_SECTION();
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

/*[clinic input]
@critical_section
_io.TextIOWrapper.tell

Return the stream position as an opaque number.

The return value of tell() can be given as input to seek(), to
restore a previous stream position.
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_tell_impl(textio *self)
/*[clinic end generated code: output=4f168c08bf34ad5f input=aeece020f747fd92]*/
{
    /* Over other buffers, flush first, as _io's does (their tell() might
       not count what they hold). */
    if (!self->nib_ok && self->ok > 0 && self->buffer != NULL
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
    Py_ssize_t avail = self->chars ? PyUnicode_GET_LENGTH(self->chars)
                                     - self->ci : 0;
    int flags = self->flags;
    if (avail > 0) {
        /* The byte position of the text position, if there is one; else
           where the characters were decoded from, and how many to skip. */
        Py_ssize_t off, start = -PyBytes_GET_SIZE(self->dspan), ci = self->ci;
        int dflags = self->dflags;
        int r = decoder_offset(self, &off, &flags);
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
    self->skip_lf = 0;
    self->decoded = 0;
}

/* Decode again the n characters that the decoder's flags at the position
   are followed by (before newlines are translated). */
static int
text_skip(textio *self, PyObject *buffer, Py_ssize_t n)
{
    store st = {.buffer = buffer};
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
        Py_SETREF(cookieObj, _io_TextIOWrapper_tell_impl(self));
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
@critical_section
_io.TextIOWrapper.flush
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_flush_impl(textio *self)
/*[clinic end generated code: output=59de9165f9c2e4d2 input=3ac3bf521bfed59d]*/
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
    if (r != 0 || self->buffer == NULL) {
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
    if (self->buffer == NULL) {
        Py_DECREF(buffer);
        return textio_buffer(self);
    }
    text_drop_reads(self);
    Py_CLEAR(self->buffer);
    self->detached = 1;
    return buffer;
}

/*[clinic input]
@critical_section
_io.TextIOWrapper.fileno
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_fileno_impl(textio *self)
/*[clinic end generated code: output=21490a4c3da13e6c input=515e1196aceb97ab]*/
{
    return textio_call(self, &_Py_ID(fileno), NULL);
}

/*[clinic input]
@critical_section
_io.TextIOWrapper.seekable
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_seekable_impl(textio *self)
/*[clinic end generated code: output=ab223dbbcffc0f00 input=71c4c092736c549b]*/
{
    return textio_call(self, &_Py_ID(seekable), NULL);
}

/*[clinic input]
@critical_section
_io.TextIOWrapper.readable
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_readable_impl(textio *self)
/*[clinic end generated code: output=72ff7ba289a8a91b input=80438d1f01b0a89b]*/
{
    return textio_call(self, &_Py_ID(readable), NULL);
}

/*[clinic input]
@critical_section
_io.TextIOWrapper.writable
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_writable_impl(textio *self)
/*[clinic end generated code: output=a728c71790d03200 input=9d6c22befb0c340a]*/
{
    return textio_call(self, &_Py_ID(writable), NULL);
}

/*[clinic input]
@critical_section
_io.TextIOWrapper.isatty
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_isatty_impl(textio *self)
/*[clinic end generated code: output=12be1a35bace882e input=7f83ff04d4d1733d]*/
{
    return textio_call(self, &_Py_ID(isatty), NULL);
}

/*[clinic input]
@critical_section
@getter
_io.TextIOWrapper.name
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_name_get_impl(textio *self)
/*[clinic end generated code: output=8c2f1d6d8756af40 input=26ecec9b39e30e07]*/
{
    PyObject *buffer = textio_buffer(self);
    PyObject *res = buffer ? PyObject_GetAttr(buffer, &_Py_ID(name)) : NULL;
    Py_XDECREF(buffer);
    return res;
}

/*[clinic input]
@critical_section
@getter
_io.TextIOWrapper.closed
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_closed_get_impl(textio *self)
/*[clinic end generated code: output=b49b68f443a85e3c input=7dfcf43f63c7003d]*/
{
    /* Partially constructed or deconstructed: closed (see _io's). */
    if (self->ok <= 0) {
        Py_RETURN_TRUE;
    }
    PyObject *buffer = textio_buffer(self);
    PyObject *res = buffer ? PyObject_GetAttr(buffer, &_Py_ID(closed)) : NULL;
    Py_XDECREF(buffer);
    return res;
}

/*[clinic input]
@critical_section
@getter
_io.TextIOWrapper.newlines
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_newlines_get_impl(textio *self)
/*[clinic end generated code: output=53aa03ac35573180 input=610df647e514b3e8]*/
{
    if (self->ok <= 0 || self->detached) {
        Py_XDECREF(textio_buffer(self));
        return NULL;
    }
    if (!self->readuniversal || !self->readable) {
        Py_RETURN_NONE;
    }
    switch (self->seennl) {
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
@critical_section
@getter
_io.TextIOWrapper.errors
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_errors_get_impl(textio *self)
/*[clinic end generated code: output=dca3a3ef21b09484 input=b45f983e6d43c4d8]*/
{
    if (self->ok <= 0) {
        return textio_buffer(self);
    }
    return Py_NewRef(self->errors);
}

/*[clinic input]
@critical_section
@getter
_io.TextIOWrapper._CHUNK_SIZE -> Py_ssize_t
[clinic start generated code]*/

static Py_ssize_t
_io_TextIOWrapper__CHUNK_SIZE_get_impl(textio *self)
/*[clinic end generated code: output=3fe34b873b6b2c8c input=cae767b74b6b46bd]*/
{
    PyObject *buffer = textio_buffer(self);
    if (buffer == NULL) {
        return -1;
    }
    Py_DECREF(buffer);
    return self->chunk_size;
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
    self->chunk_size = value;
    return 0;
}

/*[clinic input]
@critical_section
@getter
_io.TextIOWrapper.buffer
[clinic start generated code]*/

static PyObject *
_io_TextIOWrapper_buffer_get_impl(textio *self)
/*[clinic end generated code: output=d265a34555aa5d4b input=5951cfa148f7350a]*/
{
    return textio_buffer(self);
}

static PyObject *
textiowrapper_repr(PyObject *op)
{
    textio *self = textio_CAST(op);
    const char *type_name = Py_TYPE(self)->tp_name;
    if (self->ok <= 0) {
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
    Py_XSETREF(self->readnl, readnl);
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
    Py_CLEAR(self->charmap);
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
        self->charmap = codec_charmap(codec_info);
        if (self->charmap == NULL && PyErr_Occurred()) {
            return -1;
        }
        codec = self->charmap ? CODEC_CHARMAP : CODEC_DECODER;
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
    self->ok = 0;
    Py_CLEAR(self->buffer);
    Py_CLEAR(self->encoding);
    Py_CLEAR(self->errors);
    Py_CLEAR(self->encoder);
    Py_CLEAR(self->decoder);
    Py_CLEAR(self->charmap);
    Py_CLEAR(self->readnl);
    Py_CLEAR(self->chars);
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
    self->ok = 0;
    self->detached = 0;
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
    self->rpos = self->ci = self->kbytes = 0;
    self->seennl = self->skip_lf = self->decoded = 0;
    self->encoding = text_encoding(encoding);
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
    self->errors = Py_NewRef(errors);
    self->chunk_size = 8192;
    self->line_buffering = line_buffering;
    self->write_through = write_through;
    self->buffer = Py_NewRef(buffer);
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
        self->ok = 1;
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
    if (self->decoded && change) {
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
        Py_SETREF(self->encoding, encoding);
        Py_SETREF(self->errors, Py_NewRef(errors));
        int r = text_set_codec(self, buffer, codec_info, c_errors);
        Py_DECREF(codec_info);
        if (r < 0 || text_fix_encoder_state(self, buffer) < 0) {
            goto error;
        }
    }
    self->line_buffering = line_buffering;
    self->write_through = write_through;
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
    Py_VISIT(self->chars);
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
    {"encoding", _Py_T_OBJECT, offsetof(textio, encoding), Py_READONLY},
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

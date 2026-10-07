/*
 * A nibbler: data queued as morsels, and the threads using it.
 *
 * Data to write is a list of morsels: runs of bytes inside bytes objects,
 * which keep them alive.  Data appended is either kept by reference (large
 * exact bytes objects) or copied into `block`, a bytes object of `capacity`
 * bytes filled in order.  Data read is a window over the block a read filled,
 * which readers take bytes from without the lock (see "The read window"
 * below).  A block is only written into while nothing else references it,
 * so a bytes object never changes once it was handed out.
 *
 * Threads coordinate with two things, both taken over (not waited for) when
 * their holder is gone, see nibbler_lock_wait():
 *
 * - The lock guards all of the state.  Its owner (the id of the holding
 *   thread state) detects reentrant calls, which raise instead of
 *   deadlocking.
 *
 * - The I/O role: the thread writing out the front of the queue with the
 *   lock released around its raw calls (io_owner, with the `inflight` bytes
 *   it was given).  Meanwhile other threads may only append; everything
 *   else waits for the role, parked in the parking lot (see
 *   nibbler_wait_io()).
 *
 * The owner (bufferedio.c) does the raw I/O and decides what the data
 * means; all nibbler functions except nibbler_lock() are called with the
 * lock held.  Included only by bufferedio.c.
 */

#ifndef Py_IO_NIBBLER_NIBBLER_H
#define Py_IO_NIBBLER_NIBBLER_H

#include "pycore_lock.h"                // PyMutex_LockFast()
#include "pycore_object.h"              // _PyObject_XDecRefDelayed()
#include "pycore_parking_lot.h"         // _PyParkingLot_Park()
#include "pycore_pyatomic_ft_wrappers.h" // FT_ATOMIC_LOAD_PTR_ACQUIRE()
#include "pycore_pymem.h"               // _PyMem_FreeDelayed()
#include "pycore_pylifecycle.h"         // _Py_IsInterpreterFinalizing()
#include "pycore_pystate.h"             // _Py_FOR_EACH_TSTATE_BEGIN()

enum {
    /* Exact bytes appended at least this large are kept by reference
       instead of being copied, when the owner asks for it. */
    NIBBLER_REF_MIN = 512,
};

/* A run of bytes inside the bytes object obj, which keeps them alive.  obj
   is NULL only for data borrowed for the duration of a call. */
typedef struct {
    PyObject *obj;
    const char *ptr;
    Py_ssize_t len;
} morsel;

/* Morsels in order, with their total length. */
typedef struct {
    morsel *items;
    Py_ssize_t count;
    Py_ssize_t capacity;
    Py_ssize_t nbytes;
} morsel_list;

typedef struct {
    PyMutex lock;
    uint64_t owner;
    /* See the I/O role above.  io_releases counts releases of the role:
       waiters park on it, as io_owner may be the same thread again by the
       time they park (ABA); io_waiters: threads are parked on it. */
    uint64_t io_owner;
    uint64_t io_releases;
    Py_ssize_t inflight;
    uint8_t io_waiters;

    Py_ssize_t capacity;
    morsel_list list;
    /* NULL until needed. */
    PyObject *block;
    /* What the last read filled; NULL for none.  See "The read window". */
    struct nibbler_window *window;
    /* The lock holder holds the window, at position `held`. */
    Py_ssize_t held;
    uint8_t holding;
} nibbler;


/*
 * Morsel lists
 */

static void
morsels_clear(morsel_list *list)
{
    for (Py_ssize_t i = 0; i < list->count; i++) {
        Py_DECREF(list->items[i].obj);
    }
    list->count = 0;
    list->nbytes = 0;
}

static void
morsels_free(morsel_list *list)
{
    morsels_clear(list);
    PyMem_Free(list->items);
    list->items = NULL;
    list->capacity = 0;
}

/* Append ptr[0:len], inside obj; extends the last morsel when contiguous. */
static int
morsels_push(morsel_list *list, PyObject *obj, const char *ptr,
             Py_ssize_t len)
{
    morsel *last = list->count > 0 ? &list->items[list->count - 1] : NULL;
    if (last != NULL && last->obj == obj && last->ptr + last->len == ptr) {
        last->len += len;
    }
    else {
        if (list->count == list->capacity) {
            Py_ssize_t capacity = list->capacity ? 2 * list->capacity : 8;
            morsel *items = PyMem_Realloc(list->items,
                                          capacity * sizeof(morsel));
            if (items == NULL) {
                PyErr_NoMemory();
                return -1;
            }
            list->items = items;
            list->capacity = capacity;
        }
        list->items[list->count++] = (morsel){Py_NewRef(obj), ptr, len};
    }
    list->nbytes += len;
    return 0;
}

/* Drop n bytes from the front.  Returns how many there were (up to n). */
static Py_ssize_t
morsels_consume(morsel_list *list, Py_ssize_t n)
{
    Py_ssize_t taken = 0;
    Py_ssize_t done = 0;
    for (; done < list->count; done++) {
        morsel *m = &list->items[done];
        Py_ssize_t k = Py_MIN(m->len, n - taken);
        m->ptr += k;
        m->len -= k;
        taken += k;
        if (m->len > 0) {
            break;
        }
        Py_DECREF(m->obj);
    }
    list->count -= done;
    memmove(list->items, list->items + done,
            (size_t)list->count * sizeof(morsel));
    list->nbytes -= taken;
    return taken;
}


/*
 * The read window
 *
 * A read fills a block and publishes a window over the bytes it read,
 * block[0:filled], which never change afterwards.  Readers take bytes by
 * advancing the window's cursor with a compare-and-swap, without the lock,
 * then copy them out (or take the whole block, without a copy).  Only reads
 * needing more than the window holds take the lock.
 *
 * Whoever holds the lock also holds the window: taking the lock swaps the
 * cursor for NIBBLER_HELD and keeps it in `held` (so the lock holder uses
 * plain loads and stores, and its operations are atomic with respect to
 * lock-free readers, which see no bytes and wait for the lock); releasing
 * the lock puts the cursor back.  A window is closed (NIBBLER_CLOSED) before
 * the raw position moves, and freed, with its reference to the block, once
 * no lock-free reader can still be using them: delayed with QSBR on
 * free-threaded builds; on GIL builds no reader is between loading the
 * window and using it while another thread runs, so plain loads and stores
 * do (the FT_ATOMIC convention).
 */

#define NIBBLER_CLOSED (-1)
#define NIBBLER_HELD (-2)

typedef struct nibbler_window {
    PyObject *block;
    Py_ssize_t filled;
    Py_ssize_t cursor;
} nibbler_window;

static inline int
nibbler_cursor_cas(nibbler_window *w, Py_ssize_t *expected,
                   Py_ssize_t desired)
{
#ifdef Py_GIL_DISABLED
    return _Py_atomic_compare_exchange_ssize(&w->cursor, expected, desired);
#else
    if (w->cursor != *expected) {
        *expected = w->cursor;
        return 0;
    }
    w->cursor = desired;
    return 1;
#endif
}

/* With the lock just taken: hold the window. */
static inline void
nibbler_hold(nibbler *n)
{
    nibbler_window *w = n->window;
    if (w != NULL && !n->holding) {
        Py_ssize_t c = FT_ATOMIC_LOAD_SSIZE_RELAXED(w->cursor);
        while (c >= 0 && !nibbler_cursor_cas(w, &c, NIBBLER_HELD)) {
        }
        assert(c >= 0);
        n->held = c;
        n->holding = 1;
    }
}

/* Before releasing the lock: let lock-free readers at the window again. */
static inline void
nibbler_open(nibbler *n)
{
    if (n->holding) {
        n->holding = 0;
        FT_ATOMIC_STORE_SSIZE_RELEASE(n->window->cursor, n->held);
    }
}


/*
 * Locking and the I/O role
 */

/* Is there no thread state with this id in the interpreter any more?  Its
   thread exited, or was removed by a fork or by finalization. */
static int
nibbler_thread_gone(PyInterpreterState *interp, uint64_t id)
{
    int found = 0;
    _Py_FOR_EACH_TSTATE_BEGIN(interp, t) {
        if (t->id == id) {
            found = 1;
            break;
        }
    }
    _Py_FOR_EACH_TSTATE_END(interp);
    return !found;
}

static void
nibbler_set_io_owner(nibbler *n, uint64_t id)
{
    _Py_atomic_store_uint64_relaxed(&n->io_owner, id);
    if (id == 0) {
        _Py_atomic_store_uint64(&n->io_releases, n->io_releases + 1);
        if (n->io_waiters) {
            n->io_waiters = 0;
            _PyParkingLot_UnparkAll(&n->io_releases);
        }
    }
}

/* Give up on the data a gone thread was writing out. */
static void
nibbler_abandon_io(nibbler *n)
{
    morsels_consume(&n->list, n->inflight);
    n->inflight = 0;
    nibbler_set_io_owner(n, 0);
}

static int
nibbler_reentrant(PyObject *obj)
{
    PyErr_Format(PyExc_RuntimeError, "reentrant call inside %R", obj);
    return -1;
}

/* Slow path of nibbler_lock(): another thread, or this one reentering,
   holds the lock.

   A holder that can never release the lock is taken over instead of
   waited for: after a fork, a thread that held it doesn't exist in the
   child; while finalizing, every other thread hangs as soon as it attaches
   again (before it can release the lock, perhaps having just taken it).
   Such a holder is in a raw call or has just taken the lock, when the state
   is consistent, and its raw call keeps references to the memory it uses.
   It may or may not have written the data it was given (the parent
   process still will, after a fork), so that is dropped.  A thread exits
   only after releasing the lock, so a gone thread still recorded as owner
   never released it. */
static int
nibbler_lock_wait(nibbler *n, PyObject *obj, PyThreadState *tstate,
                  int interruptible)
{
    for (;;) {
        uint64_t owner = _Py_atomic_load_uint64_relaxed(&n->owner);
        if (owner == tstate->id) {
            return nibbler_reentrant(obj);
        }
        if (!_Py_IsInterpreterFinalizing(tstate->interp)
            && (owner == 0 || !nibbler_thread_gone(tstate->interp, owner)))
        {
            _PyLockFlags flags = _PY_LOCK_DETACH;
            if (interruptible) {
                flags |= _PY_LOCK_HANDLE_SIGNALS;
            }
            PyLockStatus st = _PyMutex_LockTimed(&n->lock, -1, flags);
            return st == PY_LOCK_INTR ? -1 : 0;
        }
        /* Unlocked after all (PyMutex_LockFast() also fails while
           threads are parked)? */
        if (_PyMutex_LockTimed(&n->lock, 0, 0) == PY_LOCK_ACQUIRED) {
            return 0;
        }
        /* Take over, unless another thread just did. */
        if (_Py_atomic_compare_exchange_uint64(&n->owner, &owner,
                                               tstate->id))
        {
            if (owner != 0 && n->io_owner == owner) {
                nibbler_abandon_io(n);
            }
            return 0;
        }
    }
}

/* Lock; a signal handler raising interrupts the wait.  obj names the
   object in errors. */
static inline int
nibbler_lock(nibbler *n, PyObject *obj)
{
    PyThreadState *tstate = _PyThreadState_GET();
    if (!PyMutex_LockFast(&n->lock)
        && nibbler_lock_wait(n, obj, tstate, 1) < 0)
    {
        return -1;
    }
    _Py_atomic_store_uint64_relaxed(&n->owner, tstate->id);
    nibbler_hold(n);
    return 0;
}

/* Lock again after a raw call made without the lock: a signal must not
   interrupt this (its handler runs later). */
static void
nibbler_relock(nibbler *n, PyObject *obj)
{
    PyThreadState *tstate = _PyThreadState_GET();
    if (!PyMutex_LockFast(&n->lock)) {
        (void)nibbler_lock_wait(n, obj, tstate, 0);
    }
    _Py_atomic_store_uint64_relaxed(&n->owner, tstate->id);
    nibbler_hold(n);
}

static inline void
nibbler_unlock(nibbler *n)
{
    nibbler_open(n);
    _Py_atomic_store_uint64_relaxed(&n->owner, 0);
    PyMutex_Unlock(&n->lock);
}

/* Wait until no other thread has the I/O role, parked rather than holding
   the lock.  A gone holder is taken over the same way as a gone lock
   holder.  Returns 0 with the lock held, or -1 with it released. */
static int
nibbler_wait_io(nibbler *n, PyObject *obj)
{
    PyThreadState *tstate = _PyThreadState_GET();
    for (;;) {
        uint64_t io = n->io_owner;
        if (io == 0) {
            return 0;
        }
        if (io == tstate->id) {
            nibbler_unlock(n);
            return nibbler_reentrant(obj);
        }
        if (_Py_IsInterpreterFinalizing(tstate->interp)
            || nibbler_thread_gone(tstate->interp, io))
        {
            nibbler_abandon_io(n);
            return 0;
        }
        uint64_t seen = n->io_releases;
        n->io_waiters = 1;
        nibbler_unlock(n);
        int r = _PyParkingLot_Park(&n->io_releases, &seen, sizeof(seen), -1,
                                   NULL, 1);
        if (r == Py_PARK_INTR && PyErr_CheckSignals() < 0) {
            return -1;
        }
        if (nibbler_lock(n, obj) < 0) {
            return -1;
        }
    }
}

/* Is another thread writing out?  Then only appending is allowed. */
static inline int
nibbler_io_busy(nibbler *n)
{
    return n->io_owner != 0;
}

/* Take the I/O role, which must be free. */
static void
nibbler_begin_io(nibbler *n)
{
    assert(n->io_owner == 0);
    nibbler_set_io_owner(n, _PyThreadState_GET()->id);
}

static void
nibbler_end_io(nibbler *n)
{
    n->inflight = 0;
    nibbler_set_io_owner(n, 0);
}

/* Fill pieces with up to limit morsels from the front, avail bytes at
   most, for a raw write; they are in flight until nibbler_written().
   Returns how many, with their total length in *total. */
static Py_ssize_t
nibbler_pieces(nibbler *n, Py_ssize_t avail, morsel *pieces,
               Py_ssize_t limit, Py_ssize_t *total)
{
    Py_ssize_t cnt = 0;
    Py_ssize_t sum = 0;
    for (; cnt < limit && cnt < n->list.count && sum < avail; cnt++) {
        pieces[cnt] = n->list.items[cnt];
        pieces[cnt].len = Py_MIN(pieces[cnt].len, avail - sum);
        sum += pieces[cnt].len;
    }
    n->inflight = sum;
    *total = sum;
    return cnt;
}

/* A raw write took `written` bytes, starting with those in flight: drop
   those from the front.  Returns how many of them were in flight. */
static Py_ssize_t
nibbler_written(nibbler *n, Py_ssize_t written)
{
    Py_ssize_t k = morsels_consume(&n->list, Py_MIN(written, n->inflight));
    n->inflight = 0;
    return k;
}


/*
 * Data
 */

static void
nibbler_init(nibbler *n, Py_ssize_t capacity)
{
    n->capacity = capacity;
}

static Py_ssize_t nibbler_close_window(nibbler *n);

/* Discard all data and release the memory holding it. */
static void
nibbler_free(nibbler *n)
{
    (void)nibbler_close_window(n);
    morsels_free(&n->list);
    Py_CLEAR(n->block);
}

static inline Py_ssize_t
nibbler_nbytes(nibbler *n)
{
    return n->list.nbytes;
}

/* The block, when nothing but this nibbler references it (then all of it
   can be overwritten); else a new one. */
static PyObject *
nibbler_fresh_block(nibbler *n)
{
    if (n->block == NULL || !_PyObject_IsUniquelyReferenced(n->block)) {
        PyObject *block = PyBytes_FromStringAndSize(NULL, n->capacity);
        if (block == NULL) {
            return NULL;
        }
        Py_XSETREF(n->block, block);
    }
    return n->block;
}

/* Stop copying into the block, which Python code may now reach. */
static void
nibbler_drop_block(nibbler *n)
{
    Py_CLEAR(n->block);
}

/* Append data[0:len], owned by obj (or NULL), which must fit in capacity:
   by reference when by_ref allows it, else copied into the block. */
static int
nibbler_append(nibbler *n, PyObject *obj, const char *data, Py_ssize_t len,
               int by_ref)
{
    assert(n->list.nbytes + len <= n->capacity);
    if (len == 0) {
        return 0;
    }
    if (by_ref && len >= NIBBLER_REF_MIN && obj != NULL
        && PyBytes_CheckExact(obj))
    {
        return morsels_push(&n->list, obj, data, len);
    }

    /* Copy into the block after the last morsel in it, or into a fresh
       block. */
    Py_ssize_t used = -1;
    for (Py_ssize_t i = n->list.count - 1; i >= 0; i--) {
        morsel *m = &n->list.items[i];
        if (m->obj == n->block) {
            used = m->ptr + m->len - PyBytes_AS_STRING(n->block);
            break;
        }
    }
    if (used < 0 || n->capacity - used < len) {
        if (nibbler_fresh_block(n) == NULL) {
            return -1;
        }
        used = 0;
    }
    char *dst = PyBytes_AS_STRING(n->block) + used;
    memcpy(dst, data, len);
    return morsels_push(&n->list, n->block, dst, len);
}

/* A fresh block for a read to fill, with a new reference: the read holds
   its own while it uses the block (see nibbler_lock_wait()).  Publish what
   was read with nibbler_publish(). */
static PyObject *
nibbler_fill_block(nibbler *n)
{
    return Py_XNewRef(nibbler_fresh_block(n));
}


/*
 * Reading the window (see above)
 */

static inline nibbler_window *
nibbler_window_get(nibbler *n)
{
    return FT_ATOMIC_LOAD_PTR_ACQUIRE(n->window);
}

/* Without the lock: claim up to `want` bytes of w (with exact, exactly
   `want` or none).  Returns how many, starting at *start, or -1 (nothing
   claimed) when w is closed or held or, with exact, has fewer. */
static inline Py_ssize_t
nibbler_claim(nibbler_window *w, Py_ssize_t want, int exact,
              Py_ssize_t *start)
{
    Py_ssize_t c = FT_ATOMIC_LOAD_SSIZE_RELAXED(w->cursor);
    for (;;) {
        if (c < 0) {
            return -1;
        }
        Py_ssize_t k = Py_MIN(want, w->filled - c);
        if (exact && k < want) {
            return -1;
        }
        if (nibbler_cursor_cas(w, &c, c + k)) {
            *start = c;
            return k;
        }
    }
}

/* The length of the line at base[c:end], up to `limit` bytes unless that
   is -1, or -1 when it may go on past end. */
static inline Py_ssize_t
nibbler_line_length(const char *base, Py_ssize_t c, Py_ssize_t end,
                    Py_ssize_t limit)
{
    Py_ssize_t n = end - c;
    if (limit >= 0 && limit < n) {
        n = limit;
    }
    const char *nl = memchr(base + c, '\n', n);
    return nl != NULL ? nl - (base + c) + 1 : n == limit ? n : -1;
}

/* Without the lock: claim the line at the cursor of w, like
   nibbler_claim().  Returns its length, or -1 (nothing claimed) when it may
   go on past w, or w is closed or held. */
static inline Py_ssize_t
nibbler_claim_line(nibbler_window *w, Py_ssize_t limit, Py_ssize_t *start)
{
    const char *base = PyBytes_AS_STRING(w->block);
    Py_ssize_t c = FT_ATOMIC_LOAD_SSIZE_RELAXED(w->cursor);
    for (;;) {
        if (c < 0) {
            return -1;
        }
        Py_ssize_t k = nibbler_line_length(base, c, w->filled, limit);
        if (k < 0) {
            return -1;
        }
        if (nibbler_cursor_cas(w, &c, c + k)) {
            *start = c;
            return k;
        }
    }
}

/* w->block[start:start+k] as a bytes object: the block itself, without a
   copy, when that is all of it. */
static inline PyObject *
nibbler_window_bytes(nibbler_window *w, Py_ssize_t start, Py_ssize_t k)
{
    if (start == 0 && k == PyBytes_GET_SIZE(w->block)) {
        return Py_NewRef(w->block);
    }
    return PyBytes_FromStringAndSize(PyBytes_AS_STRING(w->block) + start, k);
}

/* Without the lock: the unread bytes of the window, without taking them
   (for peek()); b"" when there are none or the window is held. */
static PyObject *
nibbler_peek(nibbler *n)
{
    nibbler_window *w = nibbler_window_get(n);
    Py_ssize_t c = w == NULL ? -1 : FT_ATOMIC_LOAD_SSIZE_RELAXED(w->cursor);
    if (c < 0 || c == w->filled) {
        return Py_GetConstant(Py_CONSTANT_EMPTY_BYTES);
    }
    return nibbler_window_bytes(w, c, w->filled - c);
}

/* The functions below are called with the lock held. */

/* How many bytes of the window are unread. */
static inline Py_ssize_t
nibbler_unread(nibbler *n)
{
    return n->holding ? n->window->filled - n->held : 0;
}

/* Take up to `want` bytes of the window: how many, starting at *start (in
   n->window->block). */
static inline Py_ssize_t
nibbler_take(nibbler *n, Py_ssize_t want, Py_ssize_t *start)
{
    Py_ssize_t k = Py_MIN(want, nibbler_unread(n));
    *start = n->held;
    n->held += k;
    return k;
}

/* Take the line at the start of the window, like nibbler_claim_line(). */
static inline Py_ssize_t
nibbler_take_line(nibbler *n, Py_ssize_t limit, Py_ssize_t *start)
{
    if (!n->holding) {
        return -1;
    }
    nibbler_window *w = n->window;
    Py_ssize_t k = nibbler_line_length(PyBytes_AS_STRING(w->block), n->held,
                                       w->filled, limit);
    if (k >= 0) {
        *start = n->held;
        n->held += k;
    }
    return k;
}

/* Like nibbler_peek(). */
static PyObject *
nibbler_peek_held(nibbler *n)
{
    if (nibbler_unread(n) == 0) {
        return Py_GetConstant(Py_CONSTANT_EMPTY_BYTES);
    }
    return nibbler_window_bytes(n->window, n->held, nibbler_unread(n));
}

static void
nibbler_retire(nibbler_window *w)
{
    _PyObject_XDecRefDelayed(w->block);
    _PyMem_FreeDelayed(w, sizeof(*w));
}

/* Stop reads from the window and drop it.  Returns how many of its bytes
   were unread. */
static Py_ssize_t
nibbler_close_window(nibbler *n)
{
    nibbler_window *w = n->window;
    if (w == NULL) {
        return 0;
    }
    /* Not holding it only in dealloc, without the lock. */
    Py_ssize_t unread = nibbler_unread(n);
    n->holding = 0;
    FT_ATOMIC_STORE_SSIZE_RELEASE(w->cursor, NIBBLER_CLOSED);
    FT_ATOMIC_STORE_PTR_RELEASE(n->window, NULL);
    nibbler_retire(w);
    return unread;
}

/* Publish a window over block[0:filled], replacing any; it is held until
   the lock is released. */
static int
nibbler_publish(nibbler *n, PyObject *block, Py_ssize_t filled)
{
    nibbler_window *w = PyMem_Malloc(sizeof(*w));
    if (w == NULL) {
        PyErr_NoMemory();
        return -1;
    }
    w->block = Py_NewRef(block);
    w->filled = filled;
    w->cursor = NIBBLER_HELD;
    (void)nibbler_close_window(n);
    FT_ATOMIC_STORE_PTR_RELEASE(n->window, w);
    n->held = 0;
    n->holding = 1;
    return 0;
}

/* Move the position in the window by `offset` bytes, forward over unread
   bytes or back over read ones, if the result stays inside it.  Returns the
   number of bytes unread before the move, or -1 (unchanged) when it would
   leave the window, or there is none. */
static Py_ssize_t
nibbler_window_move(nibbler *n, Py_off_t offset)
{
    if (!n->holding || offset < -n->held
        || offset > n->window->filled - n->held)
    {
        return -1;
    }
    Py_ssize_t unread = nibbler_unread(n);
    n->held += (Py_ssize_t)offset;
    return unread;
}

#endif  // !Py_IO_NIBBLER_NIBBLER_H

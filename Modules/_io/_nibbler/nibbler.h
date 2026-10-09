/*
 * A nibbler: data queued as morsels, and the threads using it.
 *
 * Data is a list of morsels: runs of bytes inside bytes objects, which
 * keep them alive.  Writing, they are the pending writes: data appended is
 * either kept by reference (large exact bytes objects) or copied into
 * `block`, a bytes object of `capacity` bytes filled in order.  Reading,
 * they are the unread bytes a read filled into the block.  Readers take
 * from the front, and small appends that fit after the copies in the block
 * go at the back, without the lock (see "The open end" below).  A block is only written into
 * while nothing else references it, so a bytes object never changes once it
 * was handed out.
 *
 * Threads coordinate with two things, both taken over (not waited for) when
 * their holder is gone, see nibbler_lock_wait().  Threads waiting for either
 * hold nothing, so only a gone holder ever needs taking over:
 *
 * - The lock guards all of the state.  Its owner (the id of the holding
 *   thread state) detects reentrant calls, which raise instead of
 *   deadlocking.
 *
 * - The I/O role: the thread writing out the front of the queue with the
 *   lock released around its raw calls (`io`, with the `inflight` bytes it
 *   was given).  Meanwhile other threads may only append; everything else
 *   waits for the role, parked in the parking lot (see nibbler_wait_io()).
 *
 * The owner (bufferedio.c) does the raw I/O and decides what the data
 * means.  Functions are called with the lock held unless their section or
 * their comment says otherwise (locking itself, and the open end).
 * Included only by bufferedio.c.
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

/* Compare-and-swap in the style of pycore_pyatomic_ft_wrappers.h (which
   has none): atomic on free-threaded builds, a plain compare and store
   with the GIL. */
#ifdef Py_GIL_DISABLED
#  define FT_ATOMIC_COMPARE_EXCHANGE_SSIZE(value, expected, desired) \
    _Py_atomic_compare_exchange_ssize(&value, expected, desired)
#else
#  define FT_ATOMIC_COMPARE_EXCHANGE_SSIZE(value, expected, desired) \
    ((value) == *(expected) ? ((value) = (desired), 1)               \
                            : (*(expected) = (value), 0))
#endif

/* Exact bytes appended at least this large are kept by reference instead
   of being copied, when the owner asks for it. */
#define NIBBLER_REF_MIN 512

/* A run of bytes inside the bytes object obj, which keeps them alive (see
   _iomodule.h).  obj is NULL only for data borrowed for the duration of a
   call. */
typedef _PyIO_Morsel morsel;

/* Morsels in order, with their total length. */
typedef struct {
    morsel *items;
    Py_ssize_t count;
    Py_ssize_t capacity;
    Py_ssize_t nbytes;
} morsel_list;

/* Fields are used with the lock held, with plain loads and stores, unless
   noted. */
typedef struct {
    PyMutex lock;
    /* Part of the lock: read, and swapped when taken over, by threads
       without it, so always atomic like the mutex. */
    uint64_t owner;
    /* See the I/O role above.  `io` is 0 while nobody has the role, else
       the holder's thread state id shifted left by one, with
       NIBBLER_IO_PARKED set once a thread parked waiting for it.  Changed
       only with the lock held, but always atomically: the parking lot
       compares it without the lock (and without the GIL). */
    uint64_t io;
    Py_ssize_t inflight;

    /* Also read without the lock (FT_ATOMIC relaxed). */
    Py_ssize_t capacity;
    morsel_list list;
    /* NULL until needed.  Also read without the lock (FT_ATOMIC relaxed),
       so stored atomically. */
    PyObject *block;
    /* NULL for none.  Also read without the lock, see "The open end". */
    struct nibbler_end *end;
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

/* m->ptr[0:k] as a bytes object: m->obj itself, without a copy, when that
   is all of it. */
static inline PyObject *
morsel_bytes(const morsel *m, Py_ssize_t k)
{
    if (m->ptr == PyBytes_AS_STRING(m->obj) && k == PyBytes_GET_SIZE(m->obj)) {
        return Py_NewRef(m->obj);
    }
    return PyBytes_FromStringAndSize(m->ptr, k);
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
 * The open end
 *
 * Threads without the lock use the data through the open end: a run
 * block[pos:limit] of one block that they move `pos` over with a
 * compare-and-swap.  Reading, the end is the bytes the last read filled,
 * block[0:limit] (they never change afterwards), and readers take bytes at
 * `pos`, then copy them out (or take the whole block, without a copy).
 * Writing, the end is the room after the morsels when the last one is
 * copies in the block: appends reserve bytes at `pos`, copy their data
 * there, then add its length to `done`.  Reservation order is append order,
 * so each thread's appends stay in its order.  Only what the end can't do
 * takes the lock.
 *
 * Whoever holds the lock holds the end: taking the lock swaps `pos` for
 * ~pos (negative, so everything without the lock fails and takes the
 * lock).  Writing, it then waits until every append that reserved has
 * committed and adds what was appended to the last morsel; reading, it
 * drops what readers took from the front morsel.  So code holding the lock
 * sees plain morsels.  Releasing the lock opens the end again: reading, at
 * the front morsel (or `limit` when all was read); writing, after them if
 * they still end in its block, with `limit` keeping everything appended
 * within the capacity.  An end that is replaced or dropped stays held, so
 * lock-free users that loaded it fail; it is freed, with its reference to
 * the block, once none can still be using it: delayed with QSBR on
 * free-threaded builds.
 *
 * Nothing that waits (or lets the thread be stopped, or detached) comes
 * between reserving and committing, so a waiting holder only ever waits for
 * a thread that is running its copy: fork and finalization stop threads
 * only where they can detach.  With the GIL nobody is ever between loading
 * the end and using it while another thread runs, so plain loads and
 * stores do (the FT_ATOMIC convention).
 *
 * Writing, within one end `pos` (held or not) only grows, and `limit` only
 * grows for a given `pos`; so an append that loaded an outdated limit
 * before its compare-and-swap succeeded never goes past the current one.
 * The block is never written over from its start while it has an end: that
 * needs a fresh block, which drops the end.  Bytes past the morsels are
 * never handed out, so appends there never change memory anyone else uses.
 */

typedef struct nibbler_end {
    PyObject *block;
    Py_ssize_t pos;
    Py_ssize_t limit;
    /* Writing: bytes committed, up to pos. */
    Py_ssize_t done;
    int writing;
} nibbler_end;

/* Without the lock: the end, if it goes in the direction given. */
static inline nibbler_end *
nibbler_end_get(nibbler *n, int writing)
{
    nibbler_end *e = FT_ATOMIC_LOAD_PTR_ACQUIRE(n->end);
    return e != NULL && e->writing == writing ? e : NULL;
}

/* With the lock just taken: hold the end.  It is held already when it
   wasn't opened again, or the lock was taken over from a gone holder. */
static inline void
nibbler_hold(nibbler *n)
{
    nibbler_end *e = n->end;
    if (e == NULL) {
        return;
    }
    Py_ssize_t p = FT_ATOMIC_LOAD_SSIZE_RELAXED(e->pos);
    while (p >= 0 && !FT_ATOMIC_COMPARE_EXCHANGE_SSIZE(e->pos, &p, ~p)) {
        /* retry */
    }
    if (p < 0) {
        return;
    }
    if (!e->writing) {
        /* Readers took the bytes before p: drop them from the front. */
        Py_ssize_t k = (n->list.count == 0 ? 0 : p - (
            n->list.items[0].ptr - PyBytes_AS_STRING(e->block)));
        if (k > 0) {
            morsels_consume(&n->list, k);
        }
        return;
    }
#ifdef Py_GIL_DISABLED
    while (_Py_atomic_load_ssize_acquire(&e->done) != p) {
        _Py_yield();
    }
#else
    assert(e->done == p);
#endif
    /* Appends wrote up to p: add those bytes to the last morsel. */
    morsel *last = &n->list.items[n->list.count - 1];
    Py_ssize_t end = last->ptr + last->len - PyBytes_AS_STRING(e->block);
    assert(last->obj == e->block && p >= end);
    last->len += p - end;
    n->list.nbytes += p - end;
}

/* Before releasing the lock: open the end again (see above). */
static inline void
nibbler_open(nibbler *n)
{
    nibbler_end *e = n->end;
    if (e == NULL) {
        return;
    }
    const char *base = PyBytes_AS_STRING(e->block);
    Py_ssize_t p;
    if (!e->writing) {
        /* At the front morsel, the unread bytes. */
        p = n->list.count > 0 ? n->list.items[0].ptr - base : e->limit;
    }
    else {
        /* After the last morsel, if it is in the block. */
        morsel *last = (n->list.count > 0
                        ? &n->list.items[n->list.count - 1] : NULL);
        if (last == NULL || last->obj != e->block) {
            return;
        }
        p = last->ptr + last->len - base;
        FT_ATOMIC_STORE_SSIZE_RELAXED(e->done, p);
        FT_ATOMIC_STORE_SSIZE_RELAXED(
            e->limit, p + Py_MIN(n->capacity - n->list.nbytes,
                                 PyBytes_GET_SIZE(e->block) - p));
    }
    FT_ATOMIC_STORE_SSIZE_RELEASE(e->pos, p);
}

/* Drop the end (held, or without the lock in dealloc). */
static void
nibbler_drop_end(nibbler *n)
{
    nibbler_end *e = n->end;
    if (e != NULL) {
        FT_ATOMIC_STORE_PTR_RELEASE(n->end, NULL);
        _PyObject_XDecRefDelayed(e->block);
        _PyMem_FreeDelayed(e, sizeof(*e));
    }
}

/* Publish a new end over block, held at pos until the lock is released,
   replacing any. */
static int
nibbler_new_end(nibbler *n, PyObject *block, Py_ssize_t pos,
                Py_ssize_t limit, int writing)
{
    nibbler_end *e = PyMem_Malloc(sizeof(*e));
    if (e == NULL) {
        return -1;
    }
    *e = (nibbler_end){Py_NewRef(block), ~pos, limit, pos, writing};
    nibbler_drop_end(n);
    FT_ATOMIC_STORE_PTR_RELEASE(n->end, e);
    return 0;
}

/* Let appends go after the morsels without the lock from now on, if they
   end in the block.  Without memory for it, they just don't. */
static void
nibbler_start_appending(nibbler *n)
{
    if (n->end != NULL || n->list.count == 0
        || n->list.items[n->list.count - 1].obj != n->block)
    {
        return;
    }
    /* Opened, after the morsels, when the lock is released. */
    (void)nibbler_new_end(n, n->block, 0, 0, 1);
}

/* No more appends without the lock (dropping a writing end). */
static void
nibbler_stop_appending(nibbler *n)
{
    if (n->end != NULL && n->end->writing) {
        nibbler_drop_end(n);
    }
}

/* Without the lock: reserve len bytes of the writing end e.  Returns their
   offset in the block, or -1 when e is held or they don't fit.
   nibbler_commit() must follow, with nothing that can wait in between. */
static inline Py_ssize_t
nibbler_reserve(nibbler_end *e, Py_ssize_t len)
{
    Py_ssize_t r = FT_ATOMIC_LOAD_SSIZE_ACQUIRE(e->pos);
    for (;;) {
        if (r < 0 || len > FT_ATOMIC_LOAD_SSIZE_RELAXED(e->limit) - r) {
            return -1;
        }
        if (FT_ATOMIC_COMPARE_EXCHANGE_SSIZE(e->pos, &r, r + len)) {
            return r;
        }
    }
}

/* Copy data[0:len] to the bytes reserved at offset r. */
static inline void
nibbler_commit(nibbler_end *e, Py_ssize_t r, const char *data,
               Py_ssize_t len)
{
    memcpy(PyBytes_AS_STRING(e->block) + r, data, len);
    FT_ATOMIC_ADD_SSIZE(e->done, len);
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

/* Set in `io` by a thread parking until the role is released. */
#define NIBBLER_IO_PARKED 1

/* The thread state id of the I/O role holder, or 0. */
static inline uint64_t
nibbler_io_holder(nibbler *n)
{
    return n->io >> 1;
}

/* Is another thread writing out?  Then only appending is allowed. */
static inline int
nibbler_io_busy(nibbler *n)
{
    return n->io != 0;
}

/* Is this thread writing out? */
static inline int
nibbler_io_is_mine(nibbler *n)
{
    return nibbler_io_holder(n) == _PyThreadState_GET()->id;
}

/* Is the lock held by this thread? */
static inline int
nibbler_lock_is_mine(nibbler *n)
{
    return (_Py_atomic_load_uint64_relaxed(&n->owner)
            == _PyThreadState_GET()->id);
}

/* Take the I/O role, which must be free. */
static void
nibbler_begin_io(nibbler *n)
{
    uint64_t id = _PyThreadState_GET()->id;
    assert(nibbler_lock_is_mine(n));
    assert(n->io == 0);
    /* Shifting left loses no bit. */
    assert((id >> 63) == 0);
    /* Relaxed: see nibbler_wait_io(). */
    _Py_atomic_store_uint64_relaxed(&n->io, id << 1);
}

/* Release the I/O role, waking the threads parked waiting for it. */
static void
nibbler_end_io(nibbler *n)
{
    assert(nibbler_lock_is_mine(n));
    n->inflight = 0;
    if (_Py_atomic_exchange_uint64(&n->io, 0) & NIBBLER_IO_PARKED) {
        _PyParkingLot_UnparkAll(&n->io);
    }
}

/* Release the I/O role of a gone thread, giving up on the data it was
   writing out. */
static void
nibbler_abandon_io(nibbler *n)
{
    morsels_consume(&n->list, n->inflight);
    nibbler_end_io(n);
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
            if (owner != 0 && nibbler_io_holder(n) == owner) {
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
        /* Fails only on a reentrant call, which this thread just left. */
        int r = nibbler_lock_wait(n, obj, tstate, 0);
        assert(r == 0);
        (void)r;
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

/* Wait until the I/O role is free, parked rather than holding the lock.
   A gone holder is taken over the same way as a gone lock holder.  Returns
   0 with the lock held, or -1 with it released.

   Parking expects `io` to still be the value with NIBBLER_IO_PARKED set
   here.  Every release sets it to 0 and every take to a value without the
   bit, so any release after it was set either makes parking return at once
   or wakes the parked thread: none is missed, even when the same thread
   takes the role again.

   Stores to `io` need not be sequentially consistent: they are made with
   the lock held, which orders them for the next holder (so the releasing
   exchange sees NIBBLER_IO_PARKED), and the parking lot compares under the
   bucket lock that _PyParkingLot_UnparkAll() takes after that exchange. */
static int
nibbler_wait_io(nibbler *n, PyObject *obj)
{
    PyThreadState *tstate = _PyThreadState_GET();
    while (nibbler_io_busy(n)) {
        uint64_t holder = nibbler_io_holder(n);
        if (holder == tstate->id) {
            nibbler_unlock(n);
            return nibbler_reentrant(obj);
        }
        if (_Py_IsInterpreterFinalizing(tstate->interp)
            || nibbler_thread_gone(tstate->interp, holder))
        {
            nibbler_abandon_io(n);
            break;
        }
        /* `io` only changes with the lock held, which this thread has. */
        assert(nibbler_lock_is_mine(n));
        uint64_t io = n->io | NIBBLER_IO_PARKED;
        _Py_atomic_store_uint64_relaxed(&n->io, io);
        nibbler_unlock(n);
        int r = _PyParkingLot_Park(&n->io, &io, sizeof(io), -1, NULL, 1);
        if (r == Py_PARK_INTR && PyErr_CheckSignals() < 0) {
            return -1;
        }
        if (nibbler_lock(n, obj) < 0) {
            return -1;
        }
    }
    return 0;
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
 * Reading (see "The open end")
 */

/* Without the lock: claim up to `want` bytes of the reading end e (with
   exact, exactly `want` or none).  Returns how many, starting at *start, or
   -1 (nothing claimed) when e is held or, with exact, has fewer. */
static inline Py_ssize_t
nibbler_claim(nibbler_end *e, Py_ssize_t want, int exact, Py_ssize_t *start)
{
    Py_ssize_t c = FT_ATOMIC_LOAD_SSIZE_RELAXED(e->pos);
    for (;;) {
        if (c < 0) {
            return -1;
        }
        Py_ssize_t k = Py_MIN(want, e->limit - c);
        if (exact && k < want) {
            return -1;
        }
        if (FT_ATOMIC_COMPARE_EXCHANGE_SSIZE(e->pos, &c, c + k)) {
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
    if (nl != NULL) {
        return nl - (base + c) + 1;
    }
    if (n == limit) {
        return n;
    }
    return -1;
}

/* Without the lock: claim the line at the position of e, like
   nibbler_claim().  Returns its length, or -1 (nothing claimed) when it may
   go on past e, or e is held. */
static inline Py_ssize_t
nibbler_claim_line(nibbler_end *e, Py_ssize_t limit, Py_ssize_t *start)
{
    const char *base = PyBytes_AS_STRING(e->block);
    Py_ssize_t c = FT_ATOMIC_LOAD_SSIZE_RELAXED(e->pos);
    for (;;) {
        if (c < 0) {
            return -1;
        }
        Py_ssize_t k = nibbler_line_length(base, c, e->limit, limit);
        if (k < 0) {
            return -1;
        }
        if (FT_ATOMIC_COMPARE_EXCHANGE_SSIZE(e->pos, &c, c + k)) {
            *start = c;
            return k;
        }
    }
}

/* e->block[start:start+k] as a bytes object, like morsel_bytes(). */
static inline PyObject *
nibbler_end_bytes(nibbler_end *e, Py_ssize_t start, Py_ssize_t k)
{
    morsel m = {e->block, PyBytes_AS_STRING(e->block) + start, k};
    return morsel_bytes(&m, k);
}

/* Without the lock: the unread bytes, without taking them (for peek());
   b"" when there are none or the end is held. */
static PyObject *
nibbler_peek(nibbler *n)
{
    nibbler_end *e = nibbler_end_get(n, 0);
    Py_ssize_t c = e == NULL ? -1 : FT_ATOMIC_LOAD_SSIZE_RELAXED(e->pos);
    if (c < 0 || c == e->limit) {
        return Py_GetConstant(Py_CONSTANT_EMPTY_BYTES);
    }
    return nibbler_end_bytes(e, c, e->limit - c);
}

/* The functions below are called with the lock held.  While reading, the
   morsels are the unread bytes: one, at the end of the reading end's block
   (held, see "The open end"), or none. */

/* The reading end, or NULL. */
static inline nibbler_end *
nibbler_reading(nibbler *n)
{
    nibbler_end *e = n->end;
    return e != NULL && !e->writing ? e : NULL;
}

/* How many bytes are unread. */
static inline Py_ssize_t
nibbler_unread(nibbler *n)
{
    return nibbler_reading(n) != NULL ? n->list.nbytes : 0;
}

/* Take up to `want` unread bytes as a bytes object, like morsel_bytes();
   b"" when there is none. */
static inline PyObject *
nibbler_take_bytes(nibbler *n, Py_ssize_t want)
{
    if (nibbler_unread(n) == 0) {
        return Py_GetConstant(Py_CONSTANT_EMPTY_BYTES);
    }
    Py_ssize_t k = Py_MIN(want, n->list.items[0].len);
    PyObject *res = morsel_bytes(&n->list.items[0], k);
    morsels_consume(&n->list, k);
    return res;
}

/* Take up to len unread bytes, copying them to dst.  Returns how many. */
static inline Py_ssize_t
nibbler_take_into(nibbler *n, char *dst, Py_ssize_t len)
{
    if (nibbler_unread(n) == 0) {
        return 0;
    }
    Py_ssize_t k = Py_MIN(len, n->list.items[0].len);
    memcpy(dst, n->list.items[0].ptr, k);
    morsels_consume(&n->list, k);
    return k;
}

/* The length of the unread line, without taking it, like
   nibbler_claim_line(): -1 when it may go on past the unread bytes, or
   there are none. */
static inline Py_ssize_t
nibbler_line(nibbler *n, Py_ssize_t limit)
{
    if (nibbler_unread(n) == 0) {
        return -1;
    }
    const morsel *head = &n->list.items[0];
    return nibbler_line_length(head->ptr, 0, head->len, limit);
}

/* Like nibbler_peek(). */
static PyObject *
nibbler_peek_held(nibbler *n)
{
    Py_ssize_t unread = nibbler_unread(n);
    if (unread == 0) {
        return Py_GetConstant(Py_CONSTANT_EMPTY_BYTES);
    }
    return morsel_bytes(&n->list.items[0], unread);
}

/* Drop the unread bytes (and any writing end).  Returns how many there
   were. */
static Py_ssize_t
nibbler_drop_unread(nibbler *n)
{
    Py_ssize_t unread = nibbler_unread(n);
    if (nibbler_reading(n) != NULL) {
        morsels_clear(&n->list);
    }
    nibbler_drop_end(n);
    return unread;
}

/* Make block[0:filled] the unread bytes, replacing any. */
static int
nibbler_publish(nibbler *n, PyObject *block, Py_ssize_t filled)
{
    (void)nibbler_drop_unread(n);
    if (morsels_push(&n->list, block, PyBytes_AS_STRING(block), filled) < 0
        || nibbler_new_end(n, block, 0, filled, 0) < 0)
    {
        morsels_clear(&n->list);
        PyErr_NoMemory();
        return -1;
    }
    return 0;
}

/* Move the position in the reading end by `offset` bytes, forward over
   unread bytes or back over read ones, if the result stays inside it.
   Returns the number of bytes unread before the move, or -1 (unchanged)
   when it would leave the end, or there is none. */
static Py_ssize_t
nibbler_move(nibbler *n, Py_off_t offset)
{
    nibbler_end *e = nibbler_reading(n);
    if (e == NULL) {
        return -1;
    }
    Py_ssize_t unread = n->list.nbytes;
    Py_ssize_t pos = e->limit - unread;
    if (offset < -pos || offset > unread) {
        return -1;
    }
    pos += (Py_ssize_t)offset;
    morsels_clear(&n->list);
    if (pos < e->limit) {
        /* Never fails: nibbler_publish() made room for one morsel. */
        (void)morsels_push(&n->list, e->block,
                           PyBytes_AS_STRING(e->block) + pos, e->limit - pos);
    }
    return unread;
}

/*
 * Data
 */

/* Replace the block with block (a new reference, or NULL), releasing the
   old one.  __sizeof__() reads the pointer without the lock, so every
   store to it goes through here. */
static inline void
nibbler_set_block(nibbler *n, PyObject *block)
{
    PyObject *old = n->block;
    FT_ATOMIC_STORE_PTR_RELAXED(n->block, block);
    Py_XDECREF(old);
}

/* Discard all data and release the memory holding it. */
static void
nibbler_free(nibbler *n)
{
    nibbler_drop_end(n);
    morsels_free(&n->list);
    nibbler_set_block(n, NULL);
}

static inline Py_ssize_t
nibbler_nbytes(nibbler *n)
{
    return n->list.nbytes;
}

/* The block, when nothing but this nibbler references it (then all of it
   can be overwritten); else a new one.  Either way, the end is dropped. */
static PyObject *
nibbler_fresh_block(nibbler *n)
{
    assert(n->capacity > 0);
    nibbler_drop_end(n);
    if (n->block == NULL || !_PyObject_IsUniquelyReferenced(n->block)) {
        PyObject *block = PyBytes_FromStringAndSize(NULL, n->capacity);
        if (block == NULL) {
            return NULL;
        }
        nibbler_set_block(n, block);
    }
    return n->block;
}

/* The rest of nibbler_append(), out of line so that it stays small. */
Py_NO_INLINE static int
nibbler_append_slow(nibbler *n, PyObject *obj, const char *data,
                    Py_ssize_t len, int by_ref)
{
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

/* Append data[0:len], owned by obj (or NULL), which must fit in capacity:
   by reference when by_ref allows it, else copied into the block.  Small
   data that fits after the last morsel, when that is the copies in the
   block, just extends it. */
static inline int
nibbler_append(nibbler *n, PyObject *obj, const char *data, Py_ssize_t len,
               int by_ref)
{
    assert(n->list.nbytes + len <= n->capacity);
    if (len < NIBBLER_REF_MIN && n->list.count > 0) {
        morsel *last = &n->list.items[n->list.count - 1];
        if (last->obj == n->block) {
            Py_ssize_t used = (last->ptr + last->len
                               - PyBytes_AS_STRING(n->block));
            if (n->capacity - used >= len) {
                memcpy(PyBytes_AS_STRING(n->block) + used, data, len);
                last->len += len;
                n->list.nbytes += len;
                return 0;
            }
        }
    }
    return nibbler_append_slow(n, obj, data, len, by_ref);
}

/* Append a copy of data[0:len] in a bytes object of its own, past the
   capacity if need be. */
static int
nibbler_append_copy(nibbler *n, const char *data, Py_ssize_t len)
{
    PyObject *obj = PyBytes_FromStringAndSize(data, len);
    if (obj == NULL) {
        return -1;
    }
    int r = morsels_push(&n->list, obj, PyBytes_AS_STRING(obj), len);
    Py_DECREF(obj);
    return r;
}

#endif  // !Py_IO_NIBBLER_NIBBLER_H

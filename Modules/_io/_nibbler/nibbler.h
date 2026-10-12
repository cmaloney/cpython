/*
 * A nibbler: data queued as morsels, and the threads using it.
 *
 * Writing, data is a list of morsels: runs of bytes inside bytes objects,
 * which keep them alive.  They are the pending writes: data appended is
 * either kept by reference (large exact bytes objects) or copied into
 * `block`, a bytes object of `capacity` bytes filled in order.  Reading,
 * the unread bytes are what a read filled into the block, recorded by the
 * reading end alone (see "The open end" below).  Readers take from the
 * front, and small appends that fit after the copies in the block go at
 * the back, without the lock.  A block is only written into while nothing
 * else references it, so a bytes object never changes once it was handed
 * out.
 *
 * Threads coordinate with two mutexes (see "Locking" below):
 *
 * - The lock guards all of the state.
 *
 * - The I/O role gives a thread the use of the data to itself: every
 *   operation but appending holds it, taken before the lock.  Writing out
 *   holds it too, and releases the lock around its raw calls (with the
 *   `inflight` bytes it gave them), so that other threads can append
 *   meanwhile.
 *
 * The caller (bufferedio.c) does the raw I/O and decides what the data
 * means.  Functions are called with the lock held unless their section or
 * their comment says otherwise (locking itself, and the open end).
 * Included only by bufferedio.c.
 */

#ifndef Py_IO_NIBBLER_NIBBLER_H
#define Py_IO_NIBBLER_NIBBLER_H

#include "pycore_lock.h"                // PyMutex_LockFast()
#include "pycore_object.h"              // _PyObject_XDecRefDelayed()
#include "pycore_pyatomic_ft_wrappers.h" // FT_ATOMIC_COMPARE_EXCHANGE_SSIZE()
#include "pycore_pymem.h"               // _PyMem_FreeDelayed()
#include "pycore_pylifecycle.h"         // _Py_IsInterpreterFinalizing()
#include "pycore_pystate.h"             // _PyThreadState_GET()
#include "pycore_qsbr.h"                // _Py_qsbr_advance()
#include "pycore_tstate.h"              // _PyThreadStateImpl

/* Exact bytes appended at least this large can be kept by reference
   instead of being copied (the caller may ask for a larger minimum, see
   nibbler_append()). */
#define NIBBLER_REF_MIN 512

/* A run of bytes inside the bytes object obj, which keeps them alive (see
   _iomodule.h).  obj is NULL only for data borrowed for the duration of a
   call. */
typedef _PyIO_Morsel morsel;

/* Morsels in order, with their total length: items[0:count], with room
   for `capacity` from items on.  Dropping morsels from the front moves
   items forward over `dropped` slots, which are taken back once there are
   as many as morsels left: writing out a long list a few morsels at a
   time then takes linear time. */
typedef struct {
    morsel *items;
    Py_ssize_t count;
    Py_ssize_t capacity;
    Py_ssize_t nbytes;
    Py_ssize_t dropped;
} morsel_list;

/* A PyMutex, and the id of the thread state holding it (see "Locking"). */
typedef struct {
    PyMutex mutex;
    uint64_t holder;
} nibbler_mutex;

/* nibbler.raw_pos when unknown: so far below 0 that adding what is read
   and written leaves it negative, so that it can be advanced without a
   test. */
#define NIBBLER_POS_UNKNOWN (-((Py_off_t)1 << (8 * sizeof(Py_off_t) - 2)))

/* Fields are used with the lock held, with plain loads and stores, unless
   noted. */
typedef struct nibbler {
    nibbler_mutex lock;
    /* The I/O role (see above); with it, while writing out, the bytes at
       the front given to a raw call. */
    nibbler_mutex io;
    Py_ssize_t inflight;
    /* Set, with the I/O role, when it was taken over (see "Locking") but
       the lock could not be had to drop the bytes in flight: the next
       holder of both drops them. */
    uint8_t drop_inflight;
    /* The raw stream's position as the caller last knew it, kept with the
       I/O role; negative when unknown (see NIBBLER_POS_UNKNOWN).  It
       becomes unknown when the role is taken over or the data dropped (a
       raw call may have been under way, or nothing is known any more), and
       in the child of a fork. */
    Py_off_t raw_pos;

    /* The block size, which reads fill and small appends are copied into.
       Also read without the lock (FT_ATOMIC relaxed). */
    Py_ssize_t capacity;
    /* Pending writes past this many bytes are written out by the caller:
       appends without the lock stay within it.  Set by the caller. */
    Py_ssize_t threshold;
    morsel_list list;
    /* NULL until needed.  Also read without the lock (FT_ATOMIC relaxed),
       so stored atomically. */
    PyObject *block;
#ifdef Py_GIL_DISABLED
    /* Threads without the lock may read the block through an end until
       this QSBR goal (0: none), and the block used before it, kept to be
       used again, with its own goal (see nibbler_fresh_block()). */
    uint64_t block_goal;
    PyObject *spare;
    uint64_t spare_goal;
#endif
    /* NULL for none.  Also read without the lock, see "The open end". */
    struct nibbler_end *end;
    /* Set by the caller: keep the reading end held when the lock is
       released, so that reads go through the lock. */
    uint8_t hold_reading;
    /* How many ends were made (see nibbler_end.id). */
    uint64_t ends;
    /* The nibbler_set it is in (NULL for none); in it, the next one and
       the pointer to it.  Changed with the set's mutex held. */
    struct nibbler_set *set;
    struct nibbler *next;
    struct nibbler **pprev;
} nibbler;

/*
 * Morsel lists
 */

/* The start of the memory holding the morsels. */
static inline morsel *
morsels_base(morsel_list *list)
{
    return list->dropped > 0 ? list->items - list->dropped : list->items;
}

/* Move the morsels to the start of their memory. */
static void
morsels_compact(morsel_list *list)
{
    morsel *base = morsels_base(list);
    if (base != list->items) {
        memmove(base, list->items, (size_t)list->count * sizeof(morsel));
        list->items = base;
        list->capacity += list->dropped;
        list->dropped = 0;
    }
}

static void
morsels_clear(morsel_list *list)
{
    for (Py_ssize_t i = 0; i < list->count; i++) {
        Py_DECREF(list->items[i].obj);
    }
    list->count = 0;
    list->nbytes = 0;
    morsels_compact(list);
}

static void
morsels_free(morsel_list *list)
{
    morsels_clear(list);
    PyMem_Free(list->items);
    list->items = NULL;
    list->capacity = 0;
}

/* Make room for `need` morsels in all. */
static int
morsels_grow(morsel_list *list, Py_ssize_t need)
{
    Py_ssize_t capacity = Py_MAX(Py_MAX(2 * list->capacity, need), 8);
    morsel *base = PyMem_Realloc(morsels_base(list),
                                 (list->dropped + capacity) * sizeof(morsel));
    if (base == NULL) {
        PyErr_NoMemory();
        return -1;
    }
    list->items = base + list->dropped;
    list->capacity = capacity;
    return 0;
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
        if (list->count == list->capacity
            && morsels_grow(list, list->count + 1) < 0)
        {
            return -1;
        }
        list->items[list->count++] = (morsel){Py_NewRef(obj), ptr, len};
    }
    list->nbytes += len;
    return 0;
}

/* Move all of src's morsels, with their references, to the end of dst,
   leaving src empty. */
static int
morsels_splice(morsel_list *dst, morsel_list *src)
{
    if (dst->count + src->count > dst->capacity
        && morsels_grow(dst, dst->count + src->count) < 0)
    {
        return -1;
    }
    if (src->count > 0) {
        memcpy(dst->items + dst->count, src->items,
               (size_t)src->count * sizeof(morsel));
    }
    dst->count += src->count;
    dst->nbytes += src->nbytes;
    src->count = 0;
    src->nbytes = 0;
    morsels_compact(src);
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
    list->nbytes -= taken;
    if (done > 0) {
        list->items += done;
        list->count -= done;
        list->capacity -= done;
        list->dropped += done;
        if (list->dropped >= list->count) {
            morsels_compact(list);
        }
    }
    return taken;
}

/*
 * The open end
 *
 * Threads without the lock use the data through the open end: a run
 * block[pos:limit] of one block that they move `pos` over with a
 * compare-and-swap.  Reading, the end is the bytes the last read filled,
 * block[0:limit] (they never change afterwards; a read can add bytes after
 * them, which grows `limit`, see nibbler_extend()), and readers take bytes
 * at `pos`, then copy them out (or take the whole block, without a copy).
 * Writing, the end is the room after the morsels when the last one is
 * copies in the block: appends reserve bytes at `pos`, copy their data
 * there, then add its length to `done`.  Reservation order is append order,
 * so each thread's appends stay in its order.  Only what the end can't do
 * takes the lock.
 *
 * Whoever holds the lock holds the end: taking the lock swaps `pos` for
 * ~pos (negative, so everything without the lock fails and takes the
 * lock).  Writing, it then waits until every append that reserved has
 * committed and adds what was appended to the last morsel, so code holding
 * the lock sees plain morsels; reading, the position (~pos) is where the
 * unread bytes start.  Releasing the lock opens the end again: reading, at
 * that position; writing, after the morsels if they still end in its
 * block, with `limit` keeping everything appended within the block and
 * the threshold.  An end that is replaced or dropped stays held, so
 * lock-free users that loaded it fail; it is freed, with its reference to
 * the block, once none can still be using it: delayed with QSBR on
 * free-threaded builds (see also nibbler_fresh_block()).
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
    /* Writing: bytes committed, up to pos.  Reading: block[pos:done] has
       no end of line (see nibbler_noline()); used with the lock only. */
    Py_ssize_t done;
    int writing;
    /* Tells this end from the nibbler's others (never reused, as the
       nibbler's ends count only grows), so that, reading, it and an
       offset in the block always name the same bytes. */
    uint64_t id;
} nibbler_end;

/* Without the lock: the end, if it goes in the direction given. */
static inline nibbler_end *
nibbler_end_get(nibbler *n, int writing)
{
    nibbler_end *e = FT_ATOMIC_LOAD_PTR_ACQUIRE(n->end);
    return e != NULL && e->writing == writing ? e : NULL;
}

/* With the lock just taken: hold the end.  It is held already when it
   wasn't opened again, as when a holder that could never release the lock
   held it (see "Locking"). */
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
    if (p < 0 || !e->writing) {
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
    Py_ssize_t p;
    if (!e->writing) {
        /* At the unread bytes. */
        p = ~FT_ATOMIC_LOAD_SSIZE_RELAXED(e->pos);
        if (e->done > p || n->hold_reading) {
            /* A readline() found no end of line in the unread bytes (see
               nibbler_noline()): stay held, so that reads without the lock
               fail (lines would be looked for in those bytes again), and
               go through the lock until they are taken.  Also while the
               caller wants that. */
            return;
        }
    }
    else {
        /* After the last morsel, if it is in the block. */
        morsel *last = (n->list.count > 0
                        ? &n->list.items[n->list.count - 1] : NULL);
        if (last == NULL || last->obj != e->block) {
            return;
        }
        p = last->ptr + last->len - PyBytes_AS_STRING(e->block);
        FT_ATOMIC_STORE_SSIZE_RELAXED(e->done, p);
        FT_ATOMIC_STORE_SSIZE_RELAXED(
            e->limit, p + Py_MIN(n->threshold - n->list.nbytes,
                                 PyBytes_GET_SIZE(e->block) - p));
    }
    FT_ATOMIC_STORE_SSIZE_RELEASE(e->pos, p);
}

/* Drop the end (held, or without the lock in dealloc). */
static void
nibbler_drop_end(nibbler *n)
{
    nibbler_end *e = n->end;
    if (e == NULL) {
        return;
    }
    FT_ATOMIC_STORE_PTR_RELEASE(n->end, NULL);
#ifdef Py_GIL_DISABLED
    if (e->block == n->block) {
        /* The nibbler keeps it alive, but must not write over it until
           no thread can still be reading it through e. */
        n->block_goal = _Py_qsbr_advance(
            ((_PyThreadStateImpl *)_PyThreadState_GET())->qsbr->shared);
        Py_DECREF(e->block);
    }
    else
#endif
    {
        _PyObject_XDecRefDelayed(e->block);
    }
    _PyMem_FreeDelayed(e, sizeof(*e));
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
    *e = (nibbler_end){Py_NewRef(block), ~pos, limit, writing ? pos : 0,
                       writing, ++n->ends};
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

/* Without the lock: give back the len bytes reserved at offset r, instead
   of committing them, if nothing was reserved after them.  Returns 1 if
   so, else 0 (then nibbler_commit() must follow). */
static inline int
nibbler_unreserve(nibbler_end *e, Py_ssize_t r, Py_ssize_t len)
{
    Py_ssize_t expected = r + len;
    return FT_ATOMIC_COMPARE_EXCHANGE_SSIZE(e->pos, &expected, r);
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
 * Locking
 *
 * The lock and the I/O role are PyMutexes that record the id of the thread
 * state holding them: a thread trying to take one it holds raises (a
 * reentrant call, from a signal handler or a raw stream calling back)
 * instead of deadlocking.  (_PyRecursiveMutex records its holder too, but
 * lets it in again, and finds the thread with calls that would cost an
 * unbuffered write a few percent.)  The holder is 0 while a mutex is free,
 * and for a moment after a thread took it.
 *
 * A thread holding the lock never waits for the I/O role: it releases the
 * lock first (see nibbler_take_io()).  Waits detach (release the GIL), and a
 * signal handler raising interrupts them, except where a raw call returned
 * and its result must be kept.
 *
 * A holder that can never release a mutex is not waited for:
 *
 * - In the child of a fork only the forking thread is left: the mutexes
 *   other threads held are reset, see nibbler_set_after_fork().
 *
 * - While finalizing, every other thread was detached when finalizing
 *   began and hangs as soon as it attaches again: the finalizing thread
 *   takes a mutex such a thread holds over.
 *
 * Such a holder is in a raw call, or about to attach after taking a mutex,
 * when the state is consistent; its raw call keeps references to the
 * memory it uses.  It may or may not have written the data it was given
 * (the parent process still will, after a fork), so that is dropped (see
 * nibbler_drop_inflight()).
 */

static int
nibbler_reentrant(PyObject *obj)
{
    PyErr_Format(PyExc_RuntimeError, "reentrant call inside %R", obj);
    return -1;
}

/* Does this thread hold m?  Also without m: only this thread can have
   stored its own id. */
static inline int
nibbler_mutex_is_mine(nibbler_mutex *m, PyThreadState *tstate)
{
    return _Py_atomic_load_uint64_relaxed(&m->holder) == tstate->id;
}

/* Take m if that needs no wait. */
static inline int
nibbler_mutex_trylock(nibbler_mutex *m, PyThreadState *tstate)
{
    if (!PyMutex_LockFast(&m->mutex)) {
        return 0;
    }
    _Py_atomic_store_uint64_relaxed(&m->holder, tstate->id);
    return 1;
}

/* Slow path of nibbler_mutex_lock(): m is held, or threads wait for it.
   Returns 1 when it was taken over. */
Py_NO_INLINE static int
nibbler_mutex_wait(nibbler_mutex *m, PyObject *obj, PyThreadState *tstate,
                   int interruptible)
{
    if (nibbler_mutex_is_mine(m, tstate)) {
        return nibbler_reentrant(obj);
    }
    int taken_over = 0;
    if (_Py_IsInterpreterFinalizing(tstate->interp)) {
        /* Take it, or take it over from a holder that can never release
           it (see "Locking"). */
        taken_over = _PyMutex_LockTimed(&m->mutex, 0, 0) != PY_LOCK_ACQUIRED;
    }
    else {
        _PyLockFlags flags = _PY_LOCK_DETACH;
        if (interruptible) {
            flags |= _PY_LOCK_HANDLE_SIGNALS;
        }
        if (_PyMutex_LockTimed(&m->mutex, -1, flags) != PY_LOCK_ACQUIRED) {
            return -1;
        }
    }
    _Py_atomic_store_uint64_relaxed(&m->holder, tstate->id);
    return taken_over;
}

/* Take m.  With interruptible, a signal handler raising interrupts the
   wait.  obj names the object in errors.  Returns 0, 1 when m was taken
   over (see "Locking"), or -1. */
static inline int
nibbler_mutex_lock(nibbler_mutex *m, PyObject *obj, int interruptible)
{
    PyThreadState *tstate = _PyThreadState_GET();
    if (nibbler_mutex_trylock(m, tstate)) {
        return 0;
    }
    return nibbler_mutex_wait(m, obj, tstate, interruptible);
}

static inline void
nibbler_mutex_unlock(nibbler_mutex *m)
{
    _Py_atomic_store_uint64_relaxed(&m->holder, 0);
    PyMutex_Unlock(&m->mutex);
}

/* Lock; a signal handler raising interrupts the wait.  obj names the
   object in errors. */
static inline int
nibbler_lock(nibbler *n, PyObject *obj)
{
    if (nibbler_mutex_lock(&n->lock, obj, 1) < 0) {
        return -1;
    }
    nibbler_hold(n);
    return 0;
}

/* Lock again after a raw call made without the lock: a signal must not
   interrupt this (its handler runs later). */
static void
nibbler_relock(nibbler *n, PyObject *obj)
{
    /* Takes the lock, or takes it over while finalizing (from a thread
       that was handed it meanwhile).  Fails only on a reentrant call,
       which this thread just left. */
    int r = nibbler_mutex_lock(&n->lock, obj, 0);
    assert(r >= 0);
    (void)r;
    nibbler_hold(n);
}

static inline void
nibbler_unlock(nibbler *n)
{
    nibbler_open(n);
    nibbler_mutex_unlock(&n->lock);
}

/* Does this thread hold the I/O role? */
static inline int
nibbler_io_is_mine(nibbler *n)
{
    return nibbler_mutex_is_mine(&n->io, _PyThreadState_GET());
}

/* The I/O role was taken from a holder that will never return from its raw
   call: drop what it had given it (see "Locking").  A holder releases the
   role only once its raw calls returned, so otherwise nothing is in
   flight. */
static void
nibbler_drop_inflight(nibbler *n)
{
    (void)morsels_consume(&n->list, n->inflight);
    n->inflight = 0;
    n->drop_inflight = 0;
    n->raw_pos = NIBBLER_POS_UNKNOWN;
}

/* Take the I/O role, then the lock; a signal handler raising interrupts
   the waits.  obj names the object in errors. */
static Py_ALWAYS_INLINE int
nibbler_lock_io(nibbler *n, PyObject *obj)
{
    int taken_over = nibbler_mutex_lock(&n->io, obj, 1);
    if (taken_over < 0) {
        return -1;
    }
    if (nibbler_lock(n, obj) < 0) {
        /* Only a reentrant call fails while finalizing: this thread holds
           the lock further up its stack, in the middle of something. */
        if (taken_over) {
            n->drop_inflight = 1;
        }
        nibbler_mutex_unlock(&n->io);
        return -1;
    }
    if (taken_over || n->drop_inflight) {
        nibbler_drop_inflight(n);
    }
    return 0;
}

/* Release the I/O role (keeping the lock, if held). */
static inline void
nibbler_end_io(nibbler *n)
{
    assert(n->inflight == 0);
    nibbler_mutex_unlock(&n->io);
}

/* Release the I/O role and the lock. */
static inline void
nibbler_unlock_io(nibbler *n)
{
    nibbler_end_io(n);
    nibbler_unlock(n);
}

/* What nibbler_take_io() did (or -1 on error, with nothing held). */
enum {
    /* Took the I/O role. */
    NIBBLER_IO_TAKEN,
    /* Took it after waiting, with the lock released meanwhile (anything may
       have changed).  Keeping it, rather than waiting only until it is
       free, makes progress: a release hands it to a waiting thread, so
       waiters that let it go and retried could each find it taken by the
       next one, forever. */
    NIBBLER_IO_WAITED,
    /* This thread has it: it is writing out further up its stack (as when
       a signal handler writes). */
    NIBBLER_IO_MINE,
};

/* Slow path of nibbler_take_io(). */
Py_NO_INLINE static int
nibbler_take_io_wait(nibbler *n, PyObject *obj, PyThreadState *tstate)
{
    if (nibbler_mutex_is_mine(&n->io, tstate)) {
        return NIBBLER_IO_MINE;
    }
    nibbler_unlock(n);
    if (nibbler_lock_io(n, obj) < 0) {
        return -1;
    }
    return NIBBLER_IO_WAITED;
}

/* With the lock held, to write out: take the I/O role too, waiting for it
   if need be (a signal handler raising interrupts the wait). */
static inline int
nibbler_take_io(nibbler *n, PyObject *obj)
{
    PyThreadState *tstate = _PyThreadState_GET();
    if (nibbler_mutex_trylock(&n->io, tstate)) {
        if (n->drop_inflight) {
            nibbler_drop_inflight(n);
        }
        return NIBBLER_IO_TAKEN;
    }
    return nibbler_take_io_wait(n, obj, tstate);
}

/* A raw write took `written` bytes, starting with those in flight: drop
   those from the front.  Returns how many of them were in flight. */
static inline Py_ssize_t
nibbler_written(nibbler *n, Py_ssize_t written)
{
    if (n->inflight == 0) {
        return 0;
    }
    Py_ssize_t k = morsels_consume(&n->list, Py_MIN(written, n->inflight));
    n->inflight = 0;
    return k;
}

/*
 * Reading (see "The open end")
 */

/* Without the lock: the limit of the reading end e.  It only grows, after
   the bytes before it were written (see nibbler_extend()), so they are
   complete once it is loaded. */
static inline Py_ssize_t
nibbler_end_limit(nibbler_end *e)
{
    return FT_ATOMIC_LOAD_SSIZE_ACQUIRE(e->limit);
}

/* block[start:start+k] as a bytes object: block itself, without a copy,
   when that is all of it. */
static inline PyObject *
block_bytes(PyObject *block, Py_ssize_t start, Py_ssize_t k)
{
    if (start == 0 && k == PyBytes_GET_SIZE(block)) {
        return Py_NewRef(block);
    }
    return PyBytes_FromStringAndSize(PyBytes_AS_STRING(block) + start, k);
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

/* What nibbler_claim() takes. */
enum {
    CLAIM_UPTO,     /* up to `want` bytes, at least one unless want is 0 */
    CLAIM_EXACT,    /* exactly `want` */
    CLAIM_LINE,     /* the line, up to `want` bytes unless that is -1 */
};

/* Without the lock: take bytes at the position of the reading end, as a
   bytes object.  Returns NULL, with no exception set, when there is no
   reading end, it is held, or it hasn't what `how` asks for: then the
   lock is needed. */
static inline PyObject *
nibbler_claim(nibbler *n, Py_ssize_t want, int how)
{
    nibbler_end *e = nibbler_end_get(n, 0);
    if (e == NULL) {
        return NULL;
    }
    Py_ssize_t c = FT_ATOMIC_LOAD_SSIZE_RELAXED(e->pos);
    for (;;) {
        if (c < 0) {
            return NULL;
        }
        Py_ssize_t end = nibbler_end_limit(e);
        Py_ssize_t k = (how == CLAIM_LINE
                        ? nibbler_line_length(PyBytes_AS_STRING(e->block), c,
                                              end, want)
                        : Py_MIN(want, end - c));
        if (k < 0 || (how == CLAIM_EXACT ? k < want : k == 0 && want != 0)) {
            return NULL;
        }
        if (FT_ATOMIC_COMPARE_EXCHANGE_SSIZE(e->pos, &c, c + k)) {
            return block_bytes(e->block, c, k);
        }
    }
}

/* Without the lock: the unread bytes, without taking them (for peek());
   b"" when there are none or the end is held. */
static PyObject *
nibbler_peek(nibbler *n)
{
    nibbler_end *e = nibbler_end_get(n, 0);
    Py_ssize_t c = e == NULL ? -1 : FT_ATOMIC_LOAD_SSIZE_RELAXED(e->pos);
    Py_ssize_t limit = c < 0 ? 0 : nibbler_end_limit(e);
    if (c < 0 || limit == c) {
        return Py_GetConstant(Py_CONSTANT_EMPTY_BYTES);
    }
    return block_bytes(e->block, c, limit - c);
}

/* The functions below are called with the lock held.  While reading, the
   reading end alone records the read-ahead: held (see "The open end"), it
   keeps its position as ~pos, and block[pos:limit] are the unread bytes. */

/* The reading end, or NULL. */
static inline nibbler_end *
nibbler_reading(nibbler *n)
{
    nibbler_end *e = n->end;
    return e != NULL && !e->writing ? e : NULL;
}

/* The position of the reading end e.  (Threads without the lock load it
   too, see it is held, and fail.) */
static inline Py_ssize_t
nibbler_reading_pos(nibbler_end *e)
{
    Py_ssize_t pos = FT_ATOMIC_LOAD_SSIZE_RELAXED(e->pos);
    assert(pos < 0);
    return ~pos;
}

/* How many bytes are unread. */
static inline Py_ssize_t
nibbler_unread(nibbler *n)
{
    nibbler_end *e = nibbler_reading(n);
    return e != NULL ? e->limit - nibbler_reading_pos(e) : 0;
}

/* The first unread byte (there must be a reading end). */
static inline const char *
nibbler_unread_ptr(nibbler *n)
{
    nibbler_end *e = nibbler_reading(n);
    return PyBytes_AS_STRING(e->block) + nibbler_reading_pos(e);
}

/* Take k of the unread bytes (without returning them). */
static inline void
nibbler_skip(nibbler *n, Py_ssize_t k)
{
    nibbler_end *e = nibbler_reading(n);
    assert(k <= nibbler_unread(n));
    FT_ATOMIC_STORE_SSIZE_RELAXED(e->pos, ~(nibbler_reading_pos(e) + k));
}

/* Take up to `want` unread bytes as a bytes object (see block_bytes()). */
static inline PyObject *
nibbler_take_bytes(nibbler *n, Py_ssize_t want)
{
    Py_ssize_t k = Py_MIN(want, nibbler_unread(n));
    nibbler_end *e = nibbler_reading(n);
    if (k == 0) {
        return Py_GetConstant(Py_CONSTANT_EMPTY_BYTES);
    }
    Py_ssize_t pos = nibbler_reading_pos(e);
    nibbler_skip(n, k);
    return block_bytes(e->block, pos, k);
}
/* Take up to len unread bytes, copying them to dst.  Returns how many. */
static inline Py_ssize_t
nibbler_take_into(nibbler *n, char *dst, Py_ssize_t len)
{
    Py_ssize_t k = Py_MIN(len, nibbler_unread(n));
    if (k > 0) {
        memcpy(dst, nibbler_unread_ptr(n), k);
        nibbler_skip(n, k);
    }
    return k;
}

/* How many of the unread bytes are known to have no end of line: a
   readline() that returned without one looked at them (and, since bytes
   before the limit never change, that stays true while they are unread).
   Meanwhile the end stays held (see nibbler_open()). */
static inline Py_ssize_t
nibbler_noline(nibbler *n)
{
    nibbler_end *e = nibbler_reading(n);
    return e == NULL ? 0 : Py_MAX(0, e->done - nibbler_reading_pos(e));
}

/* Record that the first `k` unread bytes have no end of line, for later
   readline() calls. */
static inline void
nibbler_set_noline(nibbler *n, Py_ssize_t k)
{
    nibbler_end *e = nibbler_reading(n);
    if (e != NULL) {
        e->done = nibbler_reading_pos(e) + k;
    }
}

/* The unread bytes grew by k bytes, read into the reading end's block
   right after them (where nothing was handed out).  The limit is stored
   after the bytes were written, see nibbler_end_limit(). */
static inline void
nibbler_extend(nibbler *n, Py_ssize_t k)
{
    nibbler_end *e = nibbler_reading(n);
    assert(e != NULL && e->limit + k <= PyBytes_GET_SIZE(e->block));
    FT_ATOMIC_STORE_SSIZE_RELEASE(e->limit, e->limit + k);
}

/* The unread bytes as a bytes object, without taking them (see
   block_bytes()). */
static PyObject *
nibbler_peek_held(nibbler *n)
{
    nibbler_end *e = nibbler_reading(n);
    if (e == NULL || nibbler_unread(n) == 0) {
        return Py_GetConstant(Py_CONSTANT_EMPTY_BYTES);
    }
    return block_bytes(e->block, nibbler_reading_pos(e), nibbler_unread(n));
}

/* Drop the unread bytes (and any writing end).  Returns how many there
   were. */
static Py_ssize_t
nibbler_drop_unread(nibbler *n)
{
    Py_ssize_t unread = nibbler_unread(n);
    nibbler_drop_end(n);
    return unread;
}

/* Make block[0:filled] the unread bytes, replacing any. */
static int
nibbler_publish(nibbler *n, PyObject *block, Py_ssize_t filled)
{
    (void)nibbler_drop_unread(n);
    if (nibbler_new_end(n, block, 0, filled, 0) < 0) {
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
    Py_ssize_t pos = nibbler_reading_pos(e);
    Py_ssize_t unread = e->limit - pos;
    if (offset < -pos || offset > unread) {
        return -1;
    }
    if (offset < 0) {
        /* The end of line hint (see nibbler_noline()) was for bytes after
           pos. */
        e->done = 0;
    }
    FT_ATOMIC_STORE_SSIZE_RELAXED(e->pos, ~(pos + (Py_ssize_t)offset));
    return unread;
}

/*
 * Data
 */

/* Replace the block with block (a new reference, or NULL), releasing the
   old one, which is not used again.  (__sizeof__() reads the pointer
   without the lock: every store to it is atomic.) */
static inline void
nibbler_set_block(nibbler *n, PyObject *block)
{
    PyObject *old = n->block;
    FT_ATOMIC_STORE_PTR_RELAXED(n->block, block);
#ifdef Py_GIL_DISABLED
    if (n->block_goal != 0) {
        /* Threads may still be reading it (see nibbler_drop_end()). */
        n->block_goal = 0;
        _PyObject_XDecRefDelayed(old);
        return;
    }
#endif
    Py_XDECREF(old);
}

/* Discard all data and release the memory holding it. */
static void
nibbler_free(nibbler *n)
{
    nibbler_drop_end(n);
    morsels_free(&n->list);
    nibbler_set_block(n, NULL);
#ifdef Py_GIL_DISABLED
    _PyObject_XDecRefDelayed(n->spare);
    n->spare = NULL;
#endif
    n->raw_pos = NIBBLER_POS_UNKNOWN;
}

static inline Py_ssize_t
nibbler_nbytes(nibbler *n)
{
    return n->list.nbytes;
}

/* A new block.  Out of line: it is needed once per block at most, and
   Tools/nibblerbench/churn.py counts the calls. */
Py_NO_INLINE static PyObject *
nibbler_new_block(nibbler *n)
{
    return PyBytes_FromStringAndSize(NULL, n->capacity);
}

/* Can block, whose readers without the lock have the given QSBR goal (see
   nibbler_drop_end()), be written over: does nothing else reference it,
   and can no thread still read it? */
static inline int
nibbler_block_free(PyObject *block, uint64_t goal)
{
    if (!_PyObject_IsUniquelyReferenced(block)) {
        return 0;
    }
#ifdef Py_GIL_DISABLED
    if (goal != 0 && !_Py_qsbr_poll(
            ((_PyThreadStateImpl *)_PyThreadState_GET())->qsbr, goal))
    {
        return 0;
    }
#endif
    return 1;
}

/* A block that all of can be written over: the block, when it can be
   (see nibbler_block_free()), else a new one.  Either way, the end is
   dropped.

   With the GIL, dropping the end releases its reference at once, so the
   block is used again unless the bytes were handed out.  On free-threaded
   builds, threads without the lock may still be reading the block of the
   end just dropped: the block used before it is kept as a spare, and used
   again once none can (the next time, as a rule: raw calls detach, which
   is a quiescent state). */
static PyObject *
nibbler_fresh_block(nibbler *n)
{
    assert(n->capacity > 0);
    nibbler_drop_end(n);
#ifdef Py_GIL_DISABLED
    if (n->block != NULL && nibbler_block_free(n->block, n->block_goal)) {
        n->block_goal = 0;
        return n->block;
    }
    PyObject *block = n->spare;
    if (block == NULL || !nibbler_block_free(block, n->spare_goal)) {
        block = nibbler_new_block(n);
        if (block == NULL) {
            return NULL;
        }
        /* The spare it replaces may still be read. */
        _PyObject_XDecRefDelayed(n->spare);
    }
    /* The block becomes the spare. */
    n->spare = n->block;
    n->spare_goal = n->block_goal;
    FT_ATOMIC_STORE_PTR_RELAXED(n->block, block);
    n->block_goal = 0;
    return block;
#else
    if (n->block == NULL || !nibbler_block_free(n->block, 0)) {
        PyObject *block = nibbler_new_block(n);
        if (block == NULL) {
            return NULL;
        }
        nibbler_set_block(n, block);
    }
    return n->block;
#endif
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

/* Is data of len bytes inside obj (or NULL) kept by reference rather than
   copied: exact bytes, at least NIBBLER_REF_MIN bytes, and at least ref_min
   bytes or larger than a block? */
static inline int
nibbler_by_ref(nibbler *n, PyObject *obj, Py_ssize_t len, Py_ssize_t ref_min)
{
    return ((len >= ref_min || len > n->capacity) && len >= NIBBLER_REF_MIN
            && obj != NULL && PyBytes_CheckExact(obj));
}

/* Append data[0:len], inside obj (or NULL): by reference (see
   nibbler_by_ref()), else copied into the block, or into a bytes object of
   its own when larger. */
static int
nibbler_append(nibbler *n, PyObject *obj, const char *data, Py_ssize_t len,
               Py_ssize_t ref_min)
{
    if (len == 0) {
        return 0;
    }
    if (nibbler_by_ref(n, obj, len, ref_min)) {
        return morsels_push(&n->list, obj, data, len);
    }
    /* Data larger than a block (the caller may let pending writes pass the
       block size) is never copied into one. */
    if (len > n->capacity) {
        return nibbler_append_copy(n, data, len);
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

/*
 * Fork
 */

/* Nibblers whose mutexes the child of a fork releases: a list, with a
   mutex held only for a few pointer updates.  Never across a detach, so
   never across a fork either. */
typedef struct nibbler_set {
    PyMutex mutex;
    nibbler *first;
} nibbler_set;

/* Add n to s, unless it is in it already. */
static void
nibbler_set_add(nibbler_set *s, nibbler *n)
{
    PyMutex_LockFlags(&s->mutex, _Py_LOCK_DONT_DETACH);
    if (n->set == NULL) {
        n->set = s;
        n->next = s->first;
        if (n->next != NULL) {
            n->next->pprev = &n->next;
        }
        s->first = n;
        n->pprev = &s->first;
    }
    PyMutex_Unlock(&s->mutex);
}

/* Remove n from its set, if it is in one.  Only for n's last user. */
static void
nibbler_set_remove(nibbler *n)
{
    nibbler_set *s = n->set;
    if (s == NULL) {
        return;
    }
    PyMutex_LockFlags(&s->mutex, _Py_LOCK_DONT_DETACH);
    *n->pprev = n->next;
    if (n->next != NULL) {
        n->next->pprev = n->pprev;
    }
    n->set = NULL;
    n->next = NULL;
    n->pprev = NULL;
    PyMutex_Unlock(&s->mutex);
}

/* Release m if a thread other than this one held it.  Returns 1 if so. */
static int
nibbler_mutex_after_fork(nibbler_mutex *m, PyThreadState *tstate)
{
    if (nibbler_mutex_is_mine(m, tstate)) {
        return 0;
    }
    _PyMutex_at_fork_reinit(&m->mutex);
    m->holder = 0;
    return 1;
}

/* In the child of a fork, where only this thread is left: release the
   mutexes that other threads held, dropping what a gone holder of the I/O
   role was writing out (see "Locking").

   Dropping morsels needs the end held: a gone thread writing out without
   the lock left it open, and a lock-free append in the child would
   otherwise go after morsels that are gone.  Unless this thread holds the
   lock (then the end is held already), the lock is taken here, in effect:
   hold the end, drop, and open it again as releasing the lock does. */
static void
nibbler_set_after_fork(nibbler_set *s)
{
    PyThreadState *tstate = _PyThreadState_GET();
    for (nibbler *n = s->first; n != NULL; n = n->next) {
        int locked = !nibbler_mutex_after_fork(&n->lock, tstate);
        if (!locked) {
            nibbler_hold(n);
        }
        if (nibbler_mutex_after_fork(&n->io, tstate)) {
            nibbler_drop_inflight(n);
        }
        /* The parent shares the file position. */
        n->raw_pos = NIBBLER_POS_UNKNOWN;
        if (!locked) {
            nibbler_open(n);
        }
    }
}

#endif  // !Py_IO_NIBBLER_NIBBLER_H

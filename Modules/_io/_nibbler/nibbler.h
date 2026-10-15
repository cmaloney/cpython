/*
 * The mutexes of the _io._nibbler objects (see InternalDocs/io_nibbler.md).
 *
 * A PyMutex that records the id of the thread state holding it, so that a
 * reentrant call (a signal handler, or a raw stream calling back) raises
 * RuntimeError instead of deadlocking, and a holder that can never release
 * it is recognized:
 *
 * - In the child of a fork, only the forking thread is left.  Every
 *   acquisition records the fork generation, which _PyIO_AfterForkChild()
 *   bumps: the first lock of a mutex in a new generation releases it from
 *   a holder gone in the fork, under a claim that makes the other threads
 *   of the child wait meanwhile.
 *
 * - While finalizing, every other thread is detached and hangs as soon as
 *   it attaches again: a mutex such a thread holds is taken over, without
 *   its bit (a lock with no wait fails), so that the hung holder and the
 *   finalizing thread both hold it.  That is safe because the hung holder
 *   never runs again, and what it can still reach stays alive through the
 *   references on its stack (the block a fill reads into, the objects a
 *   write-out gives the raw stream).  A thread parked in the wait, woken
 *   when the finalizing thread releases the mutex, hangs as it attaches
 *   again, before it stores itself as the holder.
 *
 * Holders keep the data consistent wherever they can be stopped (in a raw
 * call, or detached waiting), so taking a mutex over is safe; what a gone
 * holder of the I/O role was writing is dropped by the caller.
 */

#ifndef Py_IO_NIBBLER_NIBBLER_H
#define Py_IO_NIBBLER_NIBBLER_H

#include "pycore_lock.h"                // PyMutex_LockFast()
#include "pycore_pylifecycle.h"         // _Py_IsInterpreterFinalizing()
#include "pycore_pystate.h"             // _PyThreadState_GET()

typedef struct {
    PyMutex mutex;
    uint64_t holder;    /* thread state id; 0 when free or just handed on */
    uint64_t gen;       /* fork generation of the last holder */
} nibbler_mutex;

/* Bumped in the child of a fork, with the forking thread's id. */
extern uint64_t _PyIO_nibbler_fork_gen;
extern uint64_t _PyIO_nibbler_fork_holder;

#define NIBBLER_GEN_CLAIMED UINT64_MAX

static inline int
nibbler_mutex_is_mine(nibbler_mutex *m)
{
    return (_Py_atomic_load_uint64_relaxed(&m->holder)
            == _PyThreadState_GET()->id);
}

/* The first lock of m in the child of a fork: release it from a holder
   gone in the fork.  Returns 1 if this thread did that check (the first
   in the child). */
Py_NO_INLINE static int
nibbler_mutex_after_fork(nibbler_mutex *m, uint64_t gen)
{
    uint64_t old = _Py_atomic_load_uint64(&m->gen);
    while (old != gen) {
        if (old != NIBBLER_GEN_CLAIMED
            && _Py_atomic_compare_exchange_uint64(&m->gen, &old,
                                                  NIBBLER_GEN_CLAIMED))
        {
            int gone = (PyMutex_IsLocked(&m->mutex)
                        && _Py_atomic_load_uint64_relaxed(&m->holder)
                           != _PyIO_nibbler_fork_holder);
            if (gone) {
                _PyMutex_at_fork_reinit(&m->mutex);
                _Py_atomic_store_uint64_relaxed(&m->holder, 0);
            }
            _Py_atomic_store_uint64(&m->gen, gen);
            return 1;
        }
        _Py_yield();
        old = _Py_atomic_load_uint64(&m->gen);
    }
    return 0;
}

/* Slow path of nibbler_mutex_lock(). */
Py_NO_INLINE static int
nibbler_mutex_wait(nibbler_mutex *m, PyObject *obj, int interruptible,
                   int taken_over)
{
    PyThreadState *tstate = _PyThreadState_GET();
    if (nibbler_mutex_is_mine(m)) {
        /* (By the type's name when repr() fails, as for an object not set
           up yet.) */
        PyObject *repr = PyObject_Repr(obj);
        PyErr_Clear();
        PyErr_Format(PyExc_RuntimeError, repr ? "reentrant call inside %U"
                                              : "reentrant call inside %T",
                     repr ? repr : obj);
        Py_XDECREF(repr);
        return -1;
    }
    if (_Py_IsInterpreterFinalizing(tstate->interp)) {
        /* Take it, or take it over. */
        taken_over |= _PyMutex_LockTimed(&m->mutex, 0, 0) != PY_LOCK_ACQUIRED;
    }
    else if (_PyMutex_LockTimed(&m->mutex, -1, _PY_LOCK_DETACH
                                | (interruptible ? _PY_LOCK_HANDLE_SIGNALS
                                                 : 0))
             != PY_LOCK_ACQUIRED)
    {
        return -1;
    }
    _Py_atomic_store_uint64_relaxed(&m->holder, tstate->id);
    _Py_atomic_store_uint64_relaxed(&m->gen, _PyIO_nibbler_fork_gen);
    return taken_over;
}

/* Take m; with interruptible, a signal handler raising interrupts the
   wait.  obj names the object in errors.  Returns 0, 1 when m was taken
   from a holder that can never release it or first taken in the child of
   a fork, or -1. */
static inline int
nibbler_mutex_lock(nibbler_mutex *m, PyObject *obj, int interruptible)
{
    uint64_t gen = _PyIO_nibbler_fork_gen;
    int taken_over = 0;
    if (_Py_atomic_load_uint64_relaxed(&m->gen) != gen) {
        taken_over = nibbler_mutex_after_fork(m, gen);
    }
    if (!PyMutex_LockFast(&m->mutex)) {
        return nibbler_mutex_wait(m, obj, interruptible, taken_over);
    }
    _Py_atomic_store_uint64_relaxed(&m->holder, _PyThreadState_GET()->id);
    _Py_atomic_store_uint64_relaxed(&m->gen, gen);
    return taken_over;
}

/* Take m if that needs no wait (and no release from a fork). */
static inline int
nibbler_mutex_trylock(nibbler_mutex *m)
{
    if (_Py_atomic_load_uint64_relaxed(&m->gen) != _PyIO_nibbler_fork_gen
        || !PyMutex_LockFast(&m->mutex))
    {
        return 0;
    }
    _Py_atomic_store_uint64_relaxed(&m->holder, _PyThreadState_GET()->id);
    return 1;
}

static inline void
nibbler_mutex_unlock(nibbler_mutex *m)
{
    if (_Py_atomic_load_uint64_relaxed(&m->gen) != _PyIO_nibbler_fork_gen) {
        /* The forking thread releasing in the child what it held at the
           fork: the check of the first lock first (it finds this thread
           holding m), or a lock meanwhile could take m, holder 0 below, for
           one left locked by a thread gone in the fork. */
        (void)nibbler_mutex_after_fork(m, _PyIO_nibbler_fork_gen);
    }
    _Py_atomic_store_uint64_relaxed(&m->holder, 0);
    PyMutex_Unlock(&m->mutex);
}

#endif  // !Py_IO_NIBBLER_NIBBLER_H

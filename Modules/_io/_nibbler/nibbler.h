/*
 * The roles of the _io._nibbler objects (see InternalDocs/io_nibbler.md).
 *
 * Data is guarded by critical sections (nibbler_begin()), which a
 * detached thread never holds.  What must not interleave across a raw
 * call, or other Python code, takes a role: a _PyRecursiveMutex held
 * across it, so that a reentrant call (a signal handler, or a raw stream
 * calling back) finds it is the holder.  Only such a holder can be
 * stopped for good, and isn't waited for:
 *
 * - In the child of a fork, a holder that was another thread is gone.
 *   Each role records the fork generation it was taken in, which
 *   _PyIO_AfterForkChild() bumps: a role of an older one whose holder
 *   (if recorded yet: a handed-off mutex has none) has no thread state
 *   left is free.
 * - While finalizing, every other thread is detached and hangs as soon as
 *   it attaches again, maybe owning a mutex it was handed while it waited:
 *   the finalizing thread takes no critical section, and takes roles over.
 *
 * A role taken over tells the caller, as when a role is first taken in
 * the child of a fork (which shares raw positions with the parent): what
 * its holder had in flight is lost, but the data is consistent (it was
 * detached).
 */

#ifndef Py_IO_NIBBLER_NIBBLER_H
#define Py_IO_NIBBLER_NIBBLER_H

#include "pycore_critical_section.h" // _PyCriticalSection_Begin()
#include "pycore_lock.h"            // _PyRecursiveMutex
#include "pycore_pylifecycle.h"     // _Py_IsInterpreterFinalizing()
#include "pycore_pystate.h"         // _Py_FOR_EACH_TSTATE_BEGIN()

/* Bumped in the child of a fork. */
extern uint64_t _PyIO_nibbler_fork_gen;

/* Begin obj's critical section in cs, and return cs; but not in the
   finalizing thread (NULL): every other thread hangs as soon as it
   attaches, and one may own the mutex for good, handed it while it
   waited.  Late Python runs unsynchronized. */
static inline PyCriticalSection *
nibbler_begin(PyObject *obj, PyCriticalSection *cs)
{
#ifdef Py_GIL_DISABLED
    PyThreadState *tstate = _PyThreadState_GET();
    if (!_Py_IsInterpreterFinalizing(tstate->interp)) {
        _PyCriticalSection_Begin(tstate, cs, obj);
        return cs;
    }
#endif
    return NULL;
}

/* Does another thread hold obj's critical section now?  (For code with a
   way around waiting for it.) */
static inline int
nibbler_busy(PyObject *obj)
{
#ifdef Py_GIL_DISABLED
    return PyMutex_IsLocked(&obj->ob_mutex);
#else
    return 0;
#endif
}

static inline void
nibbler_end(PyCriticalSection *cs)
{
#ifdef Py_GIL_DISABLED
    if (cs != NULL) {
        _PyCriticalSection_End(_PyThreadState_GET(), cs);
    }
#endif
}

/* Is m, held by another thread, held by one that can never release it? */
static int
nibbler_role_gone(_PyRecursiveMutex *m, uint64_t gen)
{
    PyInterpreterState *interp = _PyInterpreterState_GET();
    if (_Py_IsInterpreterFinalizing(interp)) {
        return 1;
    }
    if (gen == _PyIO_nibbler_fork_gen) {
        return 0;
    }
    PyThread_ident_t holder = _Py_atomic_load_ullong_relaxed(&m->thread);
    int found = 0;
    _Py_FOR_EACH_TSTATE_BEGIN(interp, t) {
        found |= holder != 0 && t->thread_id == holder;
    }
    _Py_FOR_EACH_TSTATE_END(interp);
    return !found;
}

/* Inline fast paths of _PyRecursiveMutex, which I/O takes per call: the
   holder it records is the thread state's thread_id (the same
   PyThread_get_thread_ident_ex()). */
static inline int
nibbler_role_mine(_PyRecursiveMutex *m)
{
    return (_Py_atomic_load_ullong_relaxed(&m->thread)
            == _PyThreadState_GET()->thread_id);
}

static inline int
nibbler_role_lockfast(_PyRecursiveMutex *m)
{
    if (!PyMutex_LockFast(&m->mutex)) {
        return 0;
    }
    _Py_atomic_store_ullong_relaxed(&m->thread,
                                    _PyThreadState_GET()->thread_id);
    return 1;
}

static inline void
nibbler_role_unlock(_PyRecursiveMutex *m)
{
    if (m->level > 0) {
        m->level--;
        return;
    }
    _Py_atomic_store_ullong_relaxed(&m->thread, 0);
    PyMutex_Unlock(&m->mutex);
}

/* With m just taken: record the fork generation.  Returns 1 if it is a
   newer one. */
static inline int
nibbler_role_taken(uint64_t *gen)
{
    if (_Py_atomic_load_uint64_relaxed(gen) == _PyIO_nibbler_fork_gen) {
        return 0;
    }
    _Py_atomic_store_uint64_relaxed(gen, _PyIO_nibbler_fork_gen);
    return 1;
}

/* Slow path of nibbler_role_lock(). */
Py_NO_INLINE static int
nibbler_role_wait(_PyRecursiveMutex *m, uint64_t *gen, PyObject *obj,
                  int interruptible)
{
    if (nibbler_role_mine(m)) {
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
    /* In obj's critical section: one takeover at a time. */
    int taken_over = 0;
    PyCriticalSection cs, *held = nibbler_begin(obj, &cs);
    if (PyMutex_IsLocked(&m->mutex)
        && nibbler_role_gone(m, _Py_atomic_load_uint64_relaxed(gen)))
    {
        _PyMutex_at_fork_reinit(&m->mutex);
        m->level = 0;
        /* A thread taking it now isn't found gone before it records; the
           taker below is told by taken_over. */
        _Py_atomic_store_uint64_relaxed(gen, _PyIO_nibbler_fork_gen);
        taken_over = 1;
    }
    nibbler_end(held);
    if (_PyRecursiveMutex_LockTimed(m, -1, _PY_LOCK_DETACH
                                    | (interruptible ? _PY_LOCK_HANDLE_SIGNALS
                                                     : 0))
        != PY_LOCK_ACQUIRED)
    {
        return -1;
    }
    return nibbler_role_taken(gen) | taken_over;
}

/* Take the role m of obj, whose fork generation is *gen; with
   interruptible, a signal handler raising interrupts the wait.  Returns
   0, 1 when it was taken over or first taken in the child of a fork (see
   above), or -1 (RuntimeError for a reentrant call). */
static inline int
nibbler_role_lock(_PyRecursiveMutex *m, uint64_t *gen, PyObject *obj,
                  int interruptible)
{
    if (nibbler_role_lockfast(m)) {
        return nibbler_role_taken(gen);
    }
    return nibbler_role_wait(m, gen, obj, interruptible);
}

/* Take m if that needs no wait.  Returns 0 if not, else 1 + what
   nibbler_role_lock() returns. */
static inline int
nibbler_role_trylock(_PyRecursiveMutex *m, uint64_t *gen)
{
    return nibbler_role_lockfast(m) ? 1 + nibbler_role_taken(gen) : 0;
}

#endif  // !Py_IO_NIBBLER_NIBBLER_H

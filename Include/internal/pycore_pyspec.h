#ifndef Py_INTERNAL_PYSPEC_H
#define Py_INTERNAL_PYSPEC_H
#ifdef __cplusplus
extern "C" {
#endif

#ifndef Py_BUILD_CORE
#  error "this header requires Py_BUILD_CORE define"
#endif

/* Call tables generated from pyspec files (Objects/pyspec/<file>.py) by
 * Argument Clinic (Tools/clinic/libclinic/pyspec/call_table.py, run by
 * "make clinic").  For a builtin type whose __new__ is
 * implemented by a spec, the table lists direct C entry points for calls
 * of the type with positional, object-typed arguments only, and facts
 * about their results derived from the spec code.  The tier-2 optimizer
 * uses them to replace _CALL_BUILTIN_CLASS by a direct call and to type
 * or fold the result.  The data is static: no startup cost. */

/* The call may execute arbitrary Python code (__bytes__, __index__,
 * iterators, codecs, ...). */
#define _PySpec_MAY_RUN_PYTHON  (1 << 0)
/* The call always raises: it never returns a result. */
#define _PySpec_ALWAYS_RAISES   (1 << 1)

typedef PyObject *(*_PySpecFunc0)(void);
typedef PyObject *(*_PySpecFunc1)(PyObject *);

typedef struct {
    /* Number of positional arguments, all PyObject *. */
    uint8_t nargs;
    /* _PySpec_* flags. */
    uint8_t flags;
    /* Py_CONSTANT_* the call always returns, without side effects and
       without raising; -1 if none. */
    int8_t result_const;
    /* For nargs == 1: the exact type of the argument this entry is
       specialized for, or NULL for any argument. */
    PyTypeObject *arg_type;
    /* The exact type of every result, or NULL when unknown (e.g. a
       subclass instance may be returned). */
    PyTypeObject *result_type;
    /* Returns a new reference, or NULL with an exception set. */
    union {
        _PySpecFunc0 f0;
        _PySpecFunc1 f1;
    } func;
} _PySpecCall;

typedef struct {
    PyTypeObject *type;
    Py_ssize_t ncalls;
    const _PySpecCall *calls;
} _PySpecCallTable;

/* Generated into Objects/clinic/bytesobject_pyspec.c.h. */
extern const _PySpecCallTable _PySpec_bytes_calls;

/* The call table of type tp, or NULL.  Add a line per type with a spec. */
static inline const _PySpecCallTable *
_PySpec_GetCallTable(PyTypeObject *tp)
{
    if (tp == &PyBytes_Type) {
        return &_PySpec_bytes_calls;
    }
    return NULL;
}

/* The table entry for tp(arg, ...) with nargs positional arguments.
 * arg_type is the exact type of the single argument when known, or NULL;
 * an entry specialized for it is preferred over the generic one. */
static inline const _PySpecCall *
_PySpec_FindCall(PyTypeObject *tp, int nargs, PyTypeObject *arg_type)
{
    const _PySpecCallTable *table = _PySpec_GetCallTable(tp);
    if (table == NULL) {
        return NULL;
    }
    const _PySpecCall *generic = NULL;
    for (Py_ssize_t i = 0; i < table->ncalls; i++) {
        const _PySpecCall *call = &table->calls[i];
        if (call->nargs != nargs) {
            continue;
        }
        if (call->arg_type == NULL) {
            generic = call;
        }
        else if (call->arg_type == arg_type) {
            return call;
        }
    }
    return generic;
}

#ifdef __cplusplus
}
#endif
#endif /* !Py_INTERNAL_PYSPEC_H */

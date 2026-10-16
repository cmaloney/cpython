#ifndef Py_INTERNAL_PYBUFFER_H
#define Py_INTERNAL_PYBUFFER_H
#ifdef __cplusplus
extern "C" {
#endif

#ifndef Py_BUILD_CORE
#  error "this header requires Py_BUILD_CORE define"
#endif


// Exported for the _interpchannels module.
PyAPI_FUNC(int) _PyBuffer_ReleaseInInterpreter(
        PyInterpreterState *interp, Py_buffer *view);
PyAPI_FUNC(int) _PyBuffer_ReleaseInInterpreterAndRawFree(
        PyInterpreterState *interp, Py_buffer *view);

/* Buffer protocol backed sequence operations with optimized comparisons.

   Implements optimized comparison when possible for integers while falling back
   to generic Python richcompare.

   Implemented in memoryobject.c. */
PyAPI_FUNC(Py_ssize_t) _PyBuffer_FindItem(
        PyObject *obj, PyObject *value,
        Py_ssize_t start, Py_ssize_t stop);
PyAPI_FUNC(Py_ssize_t) _PyBuffer_CountItem(PyObject *obj, PyObject *value);

#ifdef __cplusplus
}
#endif
#endif /* !Py_INTERNAL_PYBUFFER_H */

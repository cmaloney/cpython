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

/* Search the aligned, contiguous items of itemsize bytes in the native
   struct format format for value, without calling Python code.
   _PyBuffer_FindItem() returns the index of the first item equal to value
   in [start, stop), or -1 if there is none. _PyBuffer_CountItem() returns
   the number of items equal to value in the first n items. Both return -2,
   without setting an exception, if the items have to be compared with value
   as objects.
   Exported for the array module. */
PyAPI_FUNC(Py_ssize_t) _PyBuffer_FindItem(
        const void *buf, Py_ssize_t itemsize, const char *format,
        PyObject *value, Py_ssize_t start, Py_ssize_t stop);
PyAPI_FUNC(Py_ssize_t) _PyBuffer_CountItem(
        const void *buf, Py_ssize_t itemsize, const char *format,
        PyObject *value, Py_ssize_t n);

#ifdef __cplusplus
}
#endif
#endif /* !Py_INTERNAL_PYBUFFER_H */

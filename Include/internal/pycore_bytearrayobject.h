#ifndef Py_INTERNAL_BYTEARRAYOBJECT_H
#define Py_INTERNAL_BYTEARRAYOBJECT_H
#ifdef __cplusplus
extern "C" {
#endif

#ifndef Py_BUILD_CORE
#  error "this header requires Py_BUILD_CORE define"
#endif

/* Hand the bytearray's buffer over as a bytes object, leaving the bytearray
   empty; what bytearray.take_bytes() does with no argument.

   Stores the bytes object in *result and returns 1 on success, returns 0 if
   the buffer cannot be handed over because the bytearray has buffer exports
   (the caller should copy instead), or returns -1 with an exception set.

   Only call this on a bytearray nothing else can observe, such as a unique
   temporary argument: the bytearray is left empty. */
extern int _PyByteArray_TryTakeBytes(PyObject *op, PyObject **result);

#ifdef __cplusplus
}
#endif
#endif /* !Py_INTERNAL_BYTEARRAYOBJECT_H */

#ifndef Py_INTERNAL_DESCROBJECT_H
#define Py_INTERNAL_DESCROBJECT_H
#ifdef __cplusplus
extern "C" {
#endif

#ifndef Py_BUILD_CORE
#  error "this header requires Py_BUILD_CORE define"
#endif

typedef struct {
    PyObject_HEAD
    PyObject *prop_get;
    PyObject *prop_set;
    PyObject *prop_del;
    PyObject *prop_doc;
    PyObject *prop_name;
    int getter_doc;
} propertyobject;

typedef propertyobject _PyPropertyObject;

extern PyTypeObject _PyMethodWrapper_Type;

// A wrapperfunc taking its arguments (without self) as an array
typedef PyObject *(*_Py_wrapperfunc_fast)(PyObject *self,
                                          PyObject *const *args,
                                          Py_ssize_t nargs, void *wrapped);

extern vectorcallfunc _PyType_GetWrapperVectorcall(wrapperfunc wrapper,
                                                   void *wrapped);

// The vectorcall function of a wrapper descriptor, given the array variant
// of its wrapperfunc
extern PyObject* _PyWrapperDescr_Vectorcall(PyObject *descr,
                                            PyObject *const *args,
                                            size_t nargsf, PyObject *kwnames,
                                            _Py_wrapperfunc_fast fast);

// The vectorcall function of a "__call__" wrapper descriptor whose slot is
// PyVectorcall_Call()
extern PyObject* _PyWrapperDescr_VectorcallCall(PyObject *descr,
                                                PyObject *const *args,
                                                size_t nargsf,
                                                PyObject *kwnames);

extern void *_PyMember_GetOffset(PyObject *, PyMemberDef *);

#ifdef __cplusplus
}
#endif
#endif   /* !Py_INTERNAL_DESCROBJECT_H */

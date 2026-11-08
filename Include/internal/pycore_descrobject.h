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

/* A wrapper_descriptor (slot wrapper), as allocated by PyDescr_NewWrapper().

   The public PyWrapperDescrObject calls the wrapped slot function
   (d_wrapped, e.g. tp_init) through a wrapperfunc, which for slots taking
   keyword arguments (tp_init, tp_call) means building an argument tuple and
   a keyword dict.  A core type can also give the slot a "vectorcall
   always" implementation, d_fast, which the descriptor (and the
   method-wrappers bound from it) calls instead with the arguments as a C
   array and keyword names, like a METH_FASTCALL|METH_KEYWORDS method.

   d_wrapped is unchanged and is still what subclasses inherit as their slot
   (see update_one_slot() in typeobject.c), so d_fast must behave exactly
   like calling d_wrapped (and returning None for tp_init). */
typedef struct {
    PyWrapperDescrObject base;
    PyCFunctionFastWithKeywords d_fast;
} _PyWrapperDescrObject;

/* Flag for a tp_methods entry which is not a method, but gives the
   METH_FASTCALL|METH_KEYWORDS implementation (d_fast) of the slot wrapper
   of the same name that the type defines, e.g. "__init__" for tp_init.  It
   must be combined with METH_FASTCALL|METH_KEYWORDS. */
#define _Py_METH_SLOT_FAST 0x4000

extern int _PyDescr_SetWrapperFast(PyObject *descr, PyTypeObject *type,
                                   PyMethodDef *meth);

extern void *_PyMember_GetOffset(PyObject *, PyMemberDef *);

#ifdef __cplusplus
}
#endif
#endif   /* !Py_INTERNAL_DESCROBJECT_H */

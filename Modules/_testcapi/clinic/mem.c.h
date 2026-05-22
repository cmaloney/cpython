/*[clinic input]
preserve
[clinic start generated code]*/

#if (defined(__APPLE__) && defined(TARGET_OS_OSX) && TARGET_OS_OSX)

PyDoc_STRVAR(_testcapi_task_vm_phys_footprint__doc__,
"task_vm_phys_footprint($module, /)\n"
"--\n"
"\n"
"Return the physical memory footprint of the current process in bytes, via\n"
"task_info(mach_task_self(), TASK_VM_INFO).");

#define _TESTCAPI_TASK_VM_PHYS_FOOTPRINT_METHODDEF    \
    {"task_vm_phys_footprint", (PyCFunction)_testcapi_task_vm_phys_footprint, METH_NOARGS, _testcapi_task_vm_phys_footprint__doc__},

static PyObject *
_testcapi_task_vm_phys_footprint_impl(PyObject *module);

static PyObject *
_testcapi_task_vm_phys_footprint(PyObject *module, PyObject *Py_UNUSED(ignored))
{
    return _testcapi_task_vm_phys_footprint_impl(module);
}

#endif /* (defined(__APPLE__) && defined(TARGET_OS_OSX) && TARGET_OS_OSX) */

#ifndef _TESTCAPI_TASK_VM_PHYS_FOOTPRINT_METHODDEF
    #define _TESTCAPI_TASK_VM_PHYS_FOOTPRINT_METHODDEF
#endif /* !defined(_TESTCAPI_TASK_VM_PHYS_FOOTPRINT_METHODDEF) */
/*[clinic end generated code: output=af9e1b2b5841bf03 input=a9049054013a1b77]*/

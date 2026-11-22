/*[clinic input]
preserve
[clinic start generated code]*/

#if defined(Py_BUILD_CORE) && !defined(Py_BUILD_CORE_MODULE)
#  include "pycore_gc.h"          // PyGC_Head
#  include "pycore_runtime.h"     // _Py_ID()
#endif
#include "pycore_critical_section.h"// Py_BEGIN_CRITICAL_SECTION()
#include "pycore_modsupport.h"    // _PyArg_UnpackKeywords()

PyDoc_STRVAR(keyobject_call__doc__,
"KeyWrapper($self, /, obj)\n"
"--\n"
"\n");

#define KEYOBJECT_CALL_METHODDEF    \
    {"KeyWrapper", _PyCFunction_CAST(keyobject_call), METH_VARARGS|METH_KEYWORDS, keyobject_call__doc__},

static PyObject *
keyobject_call_impl(PyObject *self, PyObject *object);

static PyObject *
keyobject_call(PyObject *self, PyObject *args, PyObject *kwargs)
{
    PyObject *return_value = NULL;
    #if defined(Py_BUILD_CORE) && !defined(Py_BUILD_CORE_MODULE)

    #define NUM_KEYWORDS 1
    static struct {
        PyGC_Head _this_is_not_used;
        PyObject_VAR_HEAD
        Py_hash_t ob_hash;
        PyObject *ob_item[NUM_KEYWORDS];
    } _kwtuple = {
        .ob_base = PyVarObject_HEAD_INIT(&PyTuple_Type, NUM_KEYWORDS)
        .ob_hash = -1,
        .ob_item = { &_Py_ID(obj), },
    };
    #undef NUM_KEYWORDS
    #define KWTUPLE (&_kwtuple.ob_base.ob_base)

    #else  // !Py_BUILD_CORE
    #  define KWTUPLE NULL
    #endif  // !Py_BUILD_CORE

    static const char * const _keywords[] = {"obj", NULL};
    static _PyArg_Parser _parser = {
        .keywords = _keywords,
        .fname = "KeyWrapper",
        .kwtuple = KWTUPLE,
    };
    #undef KWTUPLE
    PyObject *argsbuf[1];
    PyObject * const *fastargs;
    Py_ssize_t nargs = PyTuple_GET_SIZE(args);
    PyObject *object;

    fastargs = _PyArg_UnpackKeywords(_PyTuple_CAST(args)->ob_item, nargs, kwargs, NULL, &_parser,
            /*minpos*/ 1, /*maxpos*/ 1, /*minkw*/ 0, /*varpos*/ 0, argsbuf);
    if (!fastargs) {
        goto exit;
    }
    object = fastargs[0];
    return_value = keyobject_call_impl(self, object);

exit:
    return return_value;
}

PyDoc_STRVAR(_functools_cmp_to_key__doc__,
"cmp_to_key($module, /, mycmp)\n"
"--\n"
"\n"
"Convert a cmp= function into a key= function.\n"
"\n"
"  mycmp\n"
"    Function that compares two objects.");

#define _FUNCTOOLS_CMP_TO_KEY_METHODDEF    \
    {"cmp_to_key", _PyCFunction_CAST(_functools_cmp_to_key), METH_FASTCALL|METH_KEYWORDS, _functools_cmp_to_key__doc__},

static PyObject *
_functools_cmp_to_key_impl(PyObject *module, PyObject *mycmp);

static PyObject *
_functools_cmp_to_key(PyObject *module, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    PyObject *return_value = NULL;
    #if defined(Py_BUILD_CORE) && !defined(Py_BUILD_CORE_MODULE)

    #define NUM_KEYWORDS 1
    static struct {
        PyGC_Head _this_is_not_used;
        PyObject_VAR_HEAD
        Py_hash_t ob_hash;
        PyObject *ob_item[NUM_KEYWORDS];
    } _kwtuple = {
        .ob_base = PyVarObject_HEAD_INIT(&PyTuple_Type, NUM_KEYWORDS)
        .ob_hash = -1,
        .ob_item = { &_Py_ID(mycmp), },
    };
    #undef NUM_KEYWORDS
    #define KWTUPLE (&_kwtuple.ob_base.ob_base)

    #else  // !Py_BUILD_CORE
    #  define KWTUPLE NULL
    #endif  // !Py_BUILD_CORE

    static const char * const _keywords[] = {"mycmp", NULL};
    static _PyArg_Parser _parser = {
        .keywords = _keywords,
        .fname = "cmp_to_key",
        .kwtuple = KWTUPLE,
    };
    #undef KWTUPLE
    PyObject *argsbuf[1];
    PyObject *mycmp;

    args = _PyArg_UnpackKeywords(args, nargs, NULL, kwnames, &_parser,
            /*minpos*/ 1, /*maxpos*/ 1, /*minkw*/ 0, /*varpos*/ 0, argsbuf);
    if (!args) {
        goto exit;
    }
    mycmp = args[0];
    return_value = _functools_cmp_to_key_impl(module, mycmp);

exit:
    return return_value;
}

PyDoc_STRVAR(_functools_reduce__doc__,
"reduce($module, function, iterable, /,\n"
"       initial=functools._initial_missing)\n"
"--\n"
"\n"
"Apply a function of two arguments cumulatively to the items of an iterable, from left to right.\n"
"\n"
"This effectively reduces the iterable to a single value.  If initial is\n"
"present, it is placed before the items of the iterable in the\n"
"calculation, and serves as a default when the iterable is empty.\n"
"\n"
"For example, reduce(lambda x, y: x+y, [1, 2, 3, 4, 5])\n"
"calculates ((((1 + 2) + 3) + 4) + 5).");

#define _FUNCTOOLS_REDUCE_METHODDEF    \
    {"reduce", _PyCFunction_CAST(_functools_reduce), METH_FASTCALL|METH_KEYWORDS, _functools_reduce__doc__},

static PyObject *
_functools_reduce_impl(PyObject *module, PyObject *func, PyObject *seq,
                       PyObject *result);

static PyObject *
_functools_reduce(PyObject *module, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    PyObject *return_value = NULL;
    #if defined(Py_BUILD_CORE) && !defined(Py_BUILD_CORE_MODULE)

    #define NUM_KEYWORDS 1
    static struct {
        PyGC_Head _this_is_not_used;
        PyObject_VAR_HEAD
        Py_hash_t ob_hash;
        PyObject *ob_item[NUM_KEYWORDS];
    } _kwtuple = {
        .ob_base = PyVarObject_HEAD_INIT(&PyTuple_Type, NUM_KEYWORDS)
        .ob_hash = -1,
        .ob_item = { &_Py_ID(initial), },
    };
    #undef NUM_KEYWORDS
    #define KWTUPLE (&_kwtuple.ob_base.ob_base)

    #else  // !Py_BUILD_CORE
    #  define KWTUPLE NULL
    #endif  // !Py_BUILD_CORE

    static const char * const _keywords[] = {"", "", "initial", NULL};
    static _PyArg_Parser _parser = {
        .keywords = _keywords,
        .fname = "reduce",
        .kwtuple = KWTUPLE,
    };
    #undef KWTUPLE
    PyObject *argsbuf[3];
    Py_ssize_t noptargs = nargs + (kwnames ? PyTuple_GET_SIZE(kwnames) : 0) - 2;
    PyObject *func;
    PyObject *seq;
    PyObject *result = NULL;

    args = _PyArg_UnpackKeywords(args, nargs, NULL, kwnames, &_parser,
            /*minpos*/ 2, /*maxpos*/ 3, /*minkw*/ 0, /*varpos*/ 0, argsbuf);
    if (!args) {
        goto exit;
    }
    func = args[0];
    seq = args[1];
    if (!noptargs) {
        goto skip_optional_pos;
    }
    result = args[2];
skip_optional_pos:
    return_value = _functools_reduce_impl(module, func, seq, result);

exit:
    return return_value;
}

PyDoc_STRVAR(lru_cache_new__doc__,
"_lru_cache_wrapper(user_function, maxsize, typed, cache_info_type)\n"
"--\n"
"\n"
"Create a cached callable that wraps another function.\n"
"\n"
"user_function:      the function being cached\n"
"\n"
"maxsize:  0         for no caching\n"
"          None      for unlimited cache size\n"
"          n         for a bounded cache\n"
"\n"
"typed:    False     cache f(3) and f(3.0) as identical calls\n"
"          True      cache f(3) and f(3.0) as distinct calls\n"
"\n"
"cache_info_type:    namedtuple class with the fields:\n"
"                        hits misses currsize maxsize");

static PyObject *
lru_cache_new_impl(PyTypeObject *type, PyObject *func, PyObject *maxsize_O,
                   int typed, PyObject *cache_info_type);

static PyObject *
lru_cache_new_helper(PyTypeObject *type, PyObject *const *args,
    Py_ssize_t nargs, Py_ssize_t nkw, PyObject *kwargs, PyObject *kwnames)
{
    PyObject *return_value = NULL;
    #if defined(Py_BUILD_CORE) && !defined(Py_BUILD_CORE_MODULE)

    #define NUM_KEYWORDS 4
    static struct {
        PyGC_Head _this_is_not_used;
        PyObject_VAR_HEAD
        Py_hash_t ob_hash;
        PyObject *ob_item[NUM_KEYWORDS];
    } _kwtuple = {
        .ob_base = PyVarObject_HEAD_INIT(&PyTuple_Type, NUM_KEYWORDS)
        .ob_hash = -1,
        .ob_item = { &_Py_ID(user_function), &_Py_ID(maxsize), &_Py_ID(typed), &_Py_ID(cache_info_type), },
    };
    #undef NUM_KEYWORDS
    #define KWTUPLE (&_kwtuple.ob_base.ob_base)

    #else  // !Py_BUILD_CORE
    #  define KWTUPLE NULL
    #endif  // !Py_BUILD_CORE

    static const char * const _keywords[] = {"user_function", "maxsize", "typed", "cache_info_type", NULL};
    static _PyArg_Parser _parser = {
        .keywords = _keywords,
        .fname = "_lru_cache_wrapper",
        .kwtuple = KWTUPLE,
    };
    #undef KWTUPLE
    PyObject *argsbuf[4];
    PyObject * const *fastargs;
    PyObject *func;
    PyObject *maxsize_O;
    int typed;
    PyObject *cache_info_type;

    fastargs = _PyArg_UnpackKeywords(args, nargs, kwargs, kwnames, &_parser,
            /*minpos*/ 4, /*maxpos*/ 4, /*minkw*/ 0, /*varpos*/ 0, argsbuf);
    if (!fastargs) {
        goto exit;
    }
    func = fastargs[0];
    maxsize_O = fastargs[1];
    typed = PyObject_IsTrue(fastargs[2]);
    if (typed < 0) {
        goto exit;
    }
    cache_info_type = fastargs[3];
    return_value = lru_cache_new_impl(type, func, maxsize_O, typed, cache_info_type);

exit:
    return return_value;
}

static PyObject *
lru_cache_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    return lru_cache_new_helper(type, _PyTuple_CAST(args)->ob_item,
        PyTuple_GET_SIZE(args),
        kwargs ? PyDict_GET_SIZE(kwargs) : 0,
        kwargs, NULL);
}

static PyObject *
lru_cache_vectorcall(PyObject *type, PyObject *const *args,
    size_t nargsf, PyObject *kwnames)
{
    PyObject *return_value = NULL;
    Py_ssize_t nargs = PyVectorcall_NARGS(nargsf);
    PyObject *func;
    PyObject *maxsize_O;
    int typed;
    PyObject *cache_info_type;

    assert(_PyType_CAST(type)->tp_new == lru_cache_new);
    /* Make sure the type object is immutable: the generated
     * vectorcall doesn't deal e.g. with users reassigning __init__. */
    assert(PyType_HasFeature(_PyType_CAST(type), Py_TPFLAGS_IMMUTABLETYPE));
    if (kwnames != NULL || nargs < 4 || nargs > 4) {
        return lru_cache_new_helper(_PyType_CAST(type), args, nargs,
            kwnames ? PyTuple_GET_SIZE(kwnames) : 0,
            NULL, kwnames);
    }
    func = args[0];
    maxsize_O = args[1];
    typed = PyObject_IsTrue(args[2]);
    if (typed < 0) {
        goto exit;
    }
    cache_info_type = args[3];
    return_value = lru_cache_new_impl(_PyType_CAST(type), func, maxsize_O, typed, cache_info_type);

exit:
    return return_value;
}

PyDoc_STRVAR(_functools__lru_cache_wrapper_cache_info__doc__,
"cache_info($self, /)\n"
"--\n"
"\n"
"Report cache statistics");

#define _FUNCTOOLS__LRU_CACHE_WRAPPER_CACHE_INFO_METHODDEF    \
    {"cache_info", (PyCFunction)_functools__lru_cache_wrapper_cache_info, METH_NOARGS, _functools__lru_cache_wrapper_cache_info__doc__},

static PyObject *
_functools__lru_cache_wrapper_cache_info_impl(PyObject *self);

static PyObject *
_functools__lru_cache_wrapper_cache_info(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    PyObject *return_value = NULL;

    Py_BEGIN_CRITICAL_SECTION(self);
    return_value = _functools__lru_cache_wrapper_cache_info_impl(self);
    Py_END_CRITICAL_SECTION();

    return return_value;
}

PyDoc_STRVAR(_functools__lru_cache_wrapper_cache_clear__doc__,
"cache_clear($self, /)\n"
"--\n"
"\n"
"Clear the cache and cache statistics");

#define _FUNCTOOLS__LRU_CACHE_WRAPPER_CACHE_CLEAR_METHODDEF    \
    {"cache_clear", (PyCFunction)_functools__lru_cache_wrapper_cache_clear, METH_NOARGS, _functools__lru_cache_wrapper_cache_clear__doc__},

static PyObject *
_functools__lru_cache_wrapper_cache_clear_impl(PyObject *self);

static PyObject *
_functools__lru_cache_wrapper_cache_clear(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    PyObject *return_value = NULL;

    Py_BEGIN_CRITICAL_SECTION(self);
    return_value = _functools__lru_cache_wrapper_cache_clear_impl(self);
    Py_END_CRITICAL_SECTION();

    return return_value;
}

PyDoc_STRVAR(_functools__lru_cache_wrapper___copy____doc__,
"__copy__($self, /)\n"
"--\n"
"\n"
"Return a copy of the wrapper, which is the wrapper itself.");

#define _FUNCTOOLS__LRU_CACHE_WRAPPER___COPY___METHODDEF    \
    {"__copy__", (PyCFunction)_functools__lru_cache_wrapper___copy__, METH_NOARGS, _functools__lru_cache_wrapper___copy____doc__},

static PyObject *
_functools__lru_cache_wrapper___copy___impl(PyObject *self);

static PyObject *
_functools__lru_cache_wrapper___copy__(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return _functools__lru_cache_wrapper___copy___impl(self);
}

PyDoc_STRVAR(_functools__lru_cache_wrapper___deepcopy____doc__,
"__deepcopy__($self, memo, /)\n"
"--\n"
"\n"
"Return a deep copy of the wrapper, which is the wrapper itself.");

#define _FUNCTOOLS__LRU_CACHE_WRAPPER___DEEPCOPY___METHODDEF    \
    {"__deepcopy__", (PyCFunction)_functools__lru_cache_wrapper___deepcopy__, METH_O, _functools__lru_cache_wrapper___deepcopy____doc__},
/*[clinic end generated code: output=65d5b63bd3584c37 input=a9049054013a1b77]*/

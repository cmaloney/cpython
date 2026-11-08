from test.support import import_helper, Py_GIL_DISABLED, refleak_helper
import unittest

_testcapi = import_helper.import_module('_testcapi')
_testlimitedcapi = import_helper.import_module('_testlimitedcapi')

NULL = None


class BuiltinStaticTypesTests(unittest.TestCase):

    TYPES = [
        object,
        type,
        int,
        str,
        dict,
        type(None),
        bool,
        BaseException,
        Exception,
        Warning,
        DeprecationWarning,  # Warning subclass
    ]

    def test_tp_bases_is_set(self):
        # PyTypeObject.tp_bases is documented as public API.
        # See https://github.com/python/cpython/issues/105020.
        for typeobj in self.TYPES:
            with self.subTest(typeobj):
                bases = _testcapi.type_get_tp_bases(typeobj)
                self.assertIsNot(bases, None)

    def test_tp_mro_is_set(self):
        # PyTypeObject.tp_bases is documented as public API.
        # See https://github.com/python/cpython/issues/105020.
        for typeobj in self.TYPES:
            with self.subTest(typeobj):
                mro = _testcapi.type_get_tp_mro(typeobj)
                self.assertIsNot(mro, None)


class TypeTests(unittest.TestCase):
    def test_get_type_name(self):
        # Test PyType_GetName(), PyType_GetQualName(),
        # PyType_GetFullyQualifiedName() and PyType_GetModuleName().

        class MyType:
            pass

        from _testlimitedcapi import (
            get_type_name, get_type_qualname,
            get_type_fullyqualname, get_type_module_name)

        from collections import OrderedDict
        ht = _testlimitedcapi.get_heaptype_for_name()
        for cls, fullname, modname, qualname, name in (
            (int,
             'int',
             'builtins',
             'int',
             'int'),
            (OrderedDict,
             'collections.OrderedDict',
             'collections',
             'OrderedDict',
             'OrderedDict'),
            (ht,
             '_testcapi.HeapTypeNameType',
             '_testcapi',
             'HeapTypeNameType',
             'HeapTypeNameType'),
            (MyType,
             f'{__name__}.TypeTests.test_get_type_name.<locals>.MyType',
             __name__,
             'TypeTests.test_get_type_name.<locals>.MyType',
             'MyType'),
        ):
            with self.subTest(cls=repr(cls)):
                self.assertEqual(get_type_fullyqualname(cls), fullname)
                self.assertEqual(get_type_module_name(cls), modname)
                self.assertEqual(get_type_qualname(cls), qualname)
                self.assertEqual(get_type_name(cls), name)

        # override __module__
        ht.__module__ = 'test_module'
        self.assertEqual(get_type_fullyqualname(ht), 'test_module.HeapTypeNameType')
        self.assertEqual(get_type_module_name(ht), 'test_module')
        self.assertEqual(get_type_qualname(ht), 'HeapTypeNameType')
        self.assertEqual(get_type_name(ht), 'HeapTypeNameType')

        # override __name__ and __qualname__
        MyType.__name__ = 'my_name'
        MyType.__qualname__ = 'my_qualname'
        self.assertEqual(get_type_fullyqualname(MyType), f'{__name__}.my_qualname')
        self.assertEqual(get_type_module_name(MyType), __name__)
        self.assertEqual(get_type_qualname(MyType), 'my_qualname')
        self.assertEqual(get_type_name(MyType), 'my_name')

        # override also __module__
        MyType.__module__ = 'my_module'
        self.assertEqual(get_type_fullyqualname(MyType), 'my_module.my_qualname')
        self.assertEqual(get_type_module_name(MyType), 'my_module')
        self.assertEqual(get_type_qualname(MyType), 'my_qualname')
        self.assertEqual(get_type_name(MyType), 'my_name')

        # PyType_GetFullyQualifiedName() ignores the module if it's "builtins"
        # or "__main__" of it is not a string
        MyType.__module__ = 'builtins'
        self.assertEqual(get_type_fullyqualname(MyType), 'my_qualname')
        MyType.__module__ = '__main__'
        self.assertEqual(get_type_fullyqualname(MyType), 'my_qualname')
        MyType.__module__ = 123
        self.assertEqual(get_type_fullyqualname(MyType), 'my_qualname')

        # CRASHES get_type_name(NULL)
        # CRASHES get_type_qualname(NULL)
        # CRASHES get_type_fullyqualname(NULL)
        # CRASHES get_type_module_name(NULL)
        # CRASHES get_type_name(object()): argument must be a type
        # CRASHES get_type_qualname(object()): argument must be a type
        # CRASHES get_type_fullyqualname(object()): argument must be a type
        # CRASHES get_type_module_name(object()): argument must be a type

    def test_get_base_by_token(self):
        def get_base_by_token(src, key, comparable=True):
            def run(use_mro):
                find_first = _testcapi.pytype_getbasebytoken
                ret1, result = find_first(src, key, use_mro, True)
                ret2, no_result = find_first(src, key, use_mro, False)
                self.assertIn(ret1, (0, 1))
                self.assertEqual(ret1, result is not None)
                self.assertEqual(ret1, ret2)
                self.assertIsNone(no_result)
                return result

            found_in_mro = run(True)
            found_in_bases = run(False)
            if comparable:
                self.assertIs(found_in_mro, found_in_bases)
                return found_in_mro
            return found_in_mro, found_in_bases

        create_type = _testcapi.create_type_with_token
        get_token = _testcapi.get_tp_token

        Py_TP_USE_SPEC = _testcapi.Py_TP_USE_SPEC
        self.assertEqual(Py_TP_USE_SPEC, 0)

        A1 = create_type('_testcapi.A1', Py_TP_USE_SPEC)
        self.assertTrue(get_token(A1) != Py_TP_USE_SPEC)

        B1 = create_type('_testcapi.B1', id(self))
        self.assertTrue(get_token(B1) == id(self))

        tokenA1 = get_token(A1)
        # find A1 from A1
        found = get_base_by_token(A1, tokenA1)
        self.assertIs(found, A1)

        # no token in static types
        STATIC = type(1)
        self.assertEqual(get_token(STATIC), 0)
        found = get_base_by_token(STATIC, tokenA1)
        self.assertIs(found, None)

        # no token in pure subtypes
        class A2(A1): pass
        self.assertEqual(get_token(A2), 0)
        # find A1
        class Z(STATIC, B1, A2): pass
        found = get_base_by_token(Z, tokenA1)
        self.assertIs(found, A1)

        # searching for NULL token is an error
        with self.assertRaises(SystemError):
            get_base_by_token(Z, 0)
        with self.assertRaises(SystemError):
            get_base_by_token(STATIC, 0)

        # share the token with A1
        C1 = create_type('_testcapi.C1', tokenA1)
        self.assertTrue(get_token(C1) == tokenA1)

        # find C1 first by shared token
        class Z(C1, A2): pass
        found = get_base_by_token(Z, tokenA1)
        self.assertIs(found, C1)
        # B1 not found
        found = get_base_by_token(Z, get_token(B1))
        self.assertIs(found, None)

        with self.assertRaises(TypeError):
            _testcapi.pytype_getbasebytoken(
                'not a type', id(self), True, False)

    def test_get_module_by_def(self):
        heaptype = _testcapi.create_type_with_token('_testcapi.H', 0)
        mod = _testcapi.pytype_getmodulebydef(heaptype)
        self.assertIs(mod, _testcapi)

        class H1(heaptype): pass
        mod = _testcapi.pytype_getmodulebydef(H1)
        self.assertIs(mod, _testcapi)

        with self.assertRaises(TypeError):
            _testcapi.pytype_getmodulebydef(int)

        class H2(int): pass
        with self.assertRaises(TypeError):
            _testcapi.pytype_getmodulebydef(H2)

    def test_get_module_by_token(self):
        token = _testcapi.pymodule_get_token(_testcapi)

        heaptype = _testcapi.create_type_with_token('_testcapi.H', 0)
        mod = _testcapi.pytype_getmodulebytoken(heaptype, token)
        self.assertIs(mod, _testcapi)

        class H1(heaptype): pass
        mod = _testcapi.pytype_getmodulebytoken(H1, token)
        self.assertIs(mod, _testcapi)

        with self.assertRaises(TypeError):
            _testcapi.pytype_getmodulebytoken(int, token)

        class H2(int): pass
        with self.assertRaises(TypeError):
            _testcapi.pytype_getmodulebytoken(H2, token)

    def test_freeze(self):
        # test PyType_Freeze()
        type_freeze = _testlimitedcapi.type_freeze

        # simple case, no inherante
        class MyType:
            pass
        MyType.attr = "mutable"

        type_freeze(MyType)
        err_msg = "cannot set 'attr' attribute of immutable type 'MyType'"
        with self.assertRaisesRegex(TypeError, err_msg):
            # the class is now immutable
            MyType.attr = "immutable"

        # test MRO: PyType_Freeze() requires base classes to be immutable
        class A: pass
        class B: pass
        class C(B): pass
        class D(A, C): pass

        self.assertEqual(D.mro(), [D, A, C, B, object])
        with self.assertRaises(TypeError):
            type_freeze(D)

        type_freeze(A)
        type_freeze(B)
        type_freeze(C)
        # all parent classes are now immutable, so D can be made immutable
        # as well
        type_freeze(D)

        # CRASHES type_freeze(NULL)
        # CRASHES type_freeze(object()): argument must be a type

    @unittest.skipIf(
        Py_GIL_DISABLED and refleak_helper.hunting_for_refleaks(),
        "Specialization failure triggers gh-127773")
    def test_freeze_meta(self):
        """test PyType_Freeze() with overridden MRO"""
        type_freeze = _testlimitedcapi.type_freeze

        class Base:
            value = 1

        class Meta(type):
            def mro(cls):
                return (cls, Base, object)

        class FreezeThis(metaclass=Meta):
            """This has `Base` in the MRO, but not tp_bases"""

        self.assertEqual(FreezeThis.value, 1)

        with self.assertRaises(TypeError):
            type_freeze(FreezeThis)

        Base.value = 2
        self.assertEqual(FreezeThis.value, 2)

        type_freeze(Base)
        with self.assertRaises(TypeError):
            Base.value = 3
        type_freeze(FreezeThis)
        self.assertEqual(FreezeThis.value, 2)

    def test_manual_heap_type(self):
        # gh-128923: test that a manually allocated and initailized heap type
        # works correctly
        ManualHeapType = _testcapi.ManualHeapType
        for i in range(100):
            self.assertIsInstance(ManualHeapType(), ManualHeapType)

    def test_extension_managed_dict_type(self):
        ManagedDictType = _testcapi.ManagedDictType
        obj = ManagedDictType()
        obj.foo = 42
        self.assertEqual(obj.foo, 42)
        self.assertEqual(obj.__dict__, {'foo': 42})
        obj.__dict__ = {'bar': 3}
        self.assertEqual(obj.__dict__, {'bar': 3})
        self.assertEqual(obj.bar, 3)

    def test_extension_managed_weakref_nogc_type(self):
        msg = ("type _testcapi.ManagedWeakrefNoGCType "
               "has the Py_TPFLAGS_MANAGED_WEAKREF "
               "flag but not Py_TPFLAGS_HAVE_GC flag")
        with self.assertRaisesRegex(SystemError, msg):
            _testcapi.create_managed_weakref_nogc_type()

    def test_type_ready(self):
        # Test PyType_Ready(): calling it on initialized types
        # must not raise an exception.
        type_ready = _testlimitedcapi.type_ready

        class HeapType:
            pass

        type_ready(int)
        type_ready(dict)
        type_ready(HeapType)

        # CRASHES type_ready(NULL)
        # CRASHES type_ready(123): argument must be a type

    def test_type_clearcache(self):
        # Test PyType_ClearCache()
        type_clearcache = _testlimitedcapi.type_clearcache
        version_tag = type_clearcache()
        self.assertEqual(type(version_tag), int)
        self.assertGreaterEqual(version_tag, 0)

    def test_type_getflags(self):
        # Test PyType_GetFlags()
        type_getflags = _testlimitedcapi.type_getflags

        from _testlimitedcapi import (
            Py_TPFLAGS_HEAPTYPE,
            Py_TPFLAGS_HAVE_GC,
            Py_TPFLAGS_HAVE_FINALIZE,
            Py_TPFLAGS_HAVE_VERSION_TAG,
            Py_TPFLAGS_VALID_VERSION_TAG,
            Py_TPFLAGS_HAVE_VECTORCALL,
            Py_TPFLAGS_DISALLOW_INSTANTIATION,
            Py_TPFLAGS_IMMUTABLETYPE,
            Py_TPFLAGS_READY,
            Py_TPFLAGS_READYING,
            Py_TPFLAGS_LONG_SUBCLASS,
            Py_TPFLAGS_LIST_SUBCLASS,
            Py_TPFLAGS_TUPLE_SUBCLASS,
            Py_TPFLAGS_BYTES_SUBCLASS,
            Py_TPFLAGS_UNICODE_SUBCLASS,
            Py_TPFLAGS_DICT_SUBCLASS,
            Py_TPFLAGS_BASE_EXC_SUBCLASS,
            Py_TPFLAGS_TYPE_SUBCLASS,
            Py_TPFLAGS_IS_ABSTRACT,
            Py_TPFLAGS_BASETYPE,
            _Py_TPFLAGS_MATCH_SELF,
            Py_TPFLAGS_ITEMS_AT_END,
            Py_TPFLAGS_METHOD_DESCRIPTOR,
        )
        from _testcapi import (
            _Py_TPFLAGS_STATIC_BUILTIN,
            Py_TPFLAGS_SEQUENCE,
            Py_TPFLAGS_MAPPING,
            Py_TPFLAGS_INLINE_VALUES,
            Py_TPFLAGS_MANAGED_WEAKREF,
            Py_TPFLAGS_MANAGED_DICT,
        )

        def check_flag(flags, flag, expected):
            self.assertEqual(bool(flags & flag), expected)

        def check_subclasses(test_type, flags):
            for flag, base_type in (
                (Py_TPFLAGS_LONG_SUBCLASS, int),
                (Py_TPFLAGS_LIST_SUBCLASS, list),
                (Py_TPFLAGS_TUPLE_SUBCLASS, tuple),
                (Py_TPFLAGS_BYTES_SUBCLASS, bytes),
                (Py_TPFLAGS_UNICODE_SUBCLASS, str),
                (Py_TPFLAGS_DICT_SUBCLASS, dict),
                (Py_TPFLAGS_BASE_EXC_SUBCLASS, BaseException),
                (Py_TPFLAGS_TYPE_SUBCLASS, type),
            ):
                with self.subTest(test_type=test_type, flag=flag, base_type=base_type):
                    check_flag(flags, flag, issubclass(test_type, base_type))

        def check_type(test_type, static_type, have_gc=False, have_vectorcall=False,
                       is_base_type=True, sequence=False, mapping=False,
                       match_self=True, items_at_end=False):
            heap_type = not static_type

            flags = type_getflags(test_type)
            check_flag(flags, _Py_TPFLAGS_STATIC_BUILTIN, static_type)
            check_flag(flags, Py_TPFLAGS_HEAPTYPE, heap_type)
            check_flag(flags, Py_TPFLAGS_HAVE_GC, have_gc)
            check_subclasses(test_type, flags)
            check_flag(flags, Py_TPFLAGS_HAVE_VECTORCALL, have_vectorcall)
            check_flag(flags, Py_TPFLAGS_DISALLOW_INSTANTIATION, False)
            check_flag(flags, Py_TPFLAGS_IMMUTABLETYPE, static_type)
            check_flag(flags, Py_TPFLAGS_READY, True)
            check_flag(flags, Py_TPFLAGS_READYING, False)
            check_flag(flags, Py_TPFLAGS_IS_ABSTRACT, False)
            check_flag(flags, Py_TPFLAGS_BASETYPE, is_base_type)
            check_flag(flags, Py_TPFLAGS_SEQUENCE, sequence)
            check_flag(flags, Py_TPFLAGS_MAPPING, mapping)

            check_flag(flags, Py_TPFLAGS_INLINE_VALUES, heap_type)
            check_flag(flags, Py_TPFLAGS_MANAGED_WEAKREF, heap_type)
            check_flag(flags, Py_TPFLAGS_MANAGED_DICT, heap_type)
            check_flag(flags, Py_TPFLAGS_ITEMS_AT_END, items_at_end)
            check_flag(flags, Py_TPFLAGS_METHOD_DESCRIPTOR, False)

            check_flag(flags, _Py_TPFLAGS_MATCH_SELF, match_self)

            # Flags kept for backward compatibility
            check_flag(flags, Py_TPFLAGS_HAVE_FINALIZE, False)
            check_flag(flags, Py_TPFLAGS_HAVE_VERSION_TAG, False)
            check_flag(flags, Py_TPFLAGS_VALID_VERSION_TAG, False)

        # Scalar types
        check_type(int, static_type=True)
        check_type(bool, static_type=True,
                   is_base_type=False)
        check_type(float, static_type=True)
        check_type(complex, static_type=True,
                   match_self=False)
        check_type(bytes, static_type=True)
        check_type(bytearray, static_type=True)
        check_type(str, static_type=True)

        # Collection types
        check_type(tuple, static_type=True, have_gc=True,
                   sequence=True)
        check_type(list, static_type=True, have_gc=True,
                   sequence=True)
        check_type(dict, static_type=True, have_gc=True,
                   mapping=True)
        check_type(frozendict, static_type=True, have_gc=True,
                   mapping=True)
        check_type(set, static_type=True, have_gc=True)
        check_type(frozenset, static_type=True, have_gc=True)

        # Other types
        check_type(BaseException, static_type=True, have_gc=True,
                   match_self=False)
        check_type(type, static_type=True, have_gc=True,
                   have_vectorcall=True,
                   match_self=False,
                   items_at_end=True)

        # Heap type
        class HeapType:
            pass
        check_type(HeapType, static_type=False, have_gc=True, match_self=False)

        # CRASHES type_getflags(NULL)

    def test_type_issubtype(self):
        # Test PyType_IsSubtype()
        _type_issubtype = _testlimitedcapi.type_issubtype

        def type_issubtype(type1, type2):
            res = _type_issubtype(type1, type2)
            self.assertIn(res, (0, 1))
            return bool(res)

        class MyList(list):
            pass

        self.assertTrue(type_issubtype(bool, int))
        self.assertTrue(type_issubtype(MyList, list))

        self.assertFalse(type_issubtype(int, type))
        self.assertFalse(type_issubtype(frozendict, dict))
        self.assertFalse(type_issubtype(MyList, tuple))

    def test_subclass_type_with_dict_subclass_tp_dict(self):
        # gh-132042: MyListDictSubclass initializes tp_dict with a dict
        # subclass before PyType_Ready(), as extensions may do.  Creating a
        # subclass must still find the special methods in that dict.
        class Sub(_testcapi.MyListDictSubclass):
            pass
        self.assertEqual(len(Sub([1, 2, 3])), 3)

        class Sub2(_testcapi.MyListDictSubclass):
            def __len__(self):
                return 5
        self.assertEqual(len(Sub2([1, 2, 3])), 5)

    def test_type_modified(self):
        # Test PyType_Modified()
        type_modified = _testlimitedcapi.type_modified

        class MyType:
            pass
        type_modified(MyType)

        # CRASHES type_modified(NULL)
        # CRASHES type_modified({}): argument must be a type


class FastSlotsTests(unittest.TestCase):
    # Heap types with the provisional "vectorcall always" __init__ and
    # __new__ slots (Py_tp_init_fast, Py_tp_new_fast).  The test types record
    # which implementation ran ('via': "fast" or "tuple") and its arguments.

    def check(self, obj, via, args, kwargs):
        self.assertEqual(obj.via, via)
        self.assertEqual(obj.args, args)
        self.assertEqual(obj.kwargs, kwargs)

    def test_init_slots(self):
        get_fast_slots = _testcapi.get_fast_slots
        for name, has_fast, direct_via in [
            ('FastInitOnly', True, 'fast'),  # tp_init is an adaptor
            ('FastInitBoth', True, 'tuple'),
            ('FastNeither', False, 'tuple'),
        ]:
            with self.subTest(name):
                C = getattr(_testcapi, name)
                via = 'fast' if has_fast else 'tuple'
                self.assertEqual(get_fast_slots(C), (has_fast, False, has_fast))
                self.check(C(), via, (), {})
                self.check(C(1, 2, a=3), via, (1, 2), {'a': 3})
                o = C()
                C.__init__(o, 4, b=5)
                self.check(o, via, (4,), {'b': 5})
                o.__init__(6)
                self.check(o, via, (6,), {})
                # Calling tp_init directly, as C code does
                _testcapi.call_tp_init(C, o, (7,), {'c': 8})
                self.check(o, direct_via, (7,), {'c': 8})
                _testcapi.call_tp_init(C, o, (9,))
                self.check(o, direct_via, (9,), {})
                with self.assertRaisesRegex(ValueError, 'fail'):
                    C(fail=1)
                with self.assertRaisesRegex(ValueError, 'fail'):
                    C.__init__(o, fail=1)
                with self.assertRaisesRegex(ValueError, 'fail'):
                    _testcapi.call_tp_init(C, o, (), {'fail': 1})

    def test_new_slots(self):
        get_fast_slots = _testcapi.get_fast_slots
        for name, direct_via in [
            ('FastNewOnly', 'fast'),  # tp_new is an adaptor
            ('FastNewBoth', 'tuple'),
        ]:
            with self.subTest(name):
                C = getattr(_testcapi, name)
                self.assertEqual(get_fast_slots(C), (False, True, True))
                self.check(C(), 'fast', (), {})
                self.check(C(1, 2, a=3), 'fast', (1, 2), {'a': 3})
                self.check(C.__new__(C, 4, b=5), 'fast', (4,), {'b': 5})
                o = _testcapi.call_tp_new(C, C, (6,), {'c': 7})
                self.check(o, direct_via, (6,), {'c': 7})
                class S(C):
                    pass
                o = _testcapi.call_tp_new(C, S, (8,))
                self.assertIs(type(o), S)
                self.check(o, direct_via, (8,), {})
                with self.assertRaisesRegex(ValueError, 'fail'):
                    C(fail=1)
                with self.assertRaisesRegex(ValueError, 'fail'):
                    C.__new__(C, fail=1)
                with self.assertRaisesRegex(ValueError, 'fail'):
                    _testcapi.call_tp_new(C, C, (), {'fail': 1})
                # object.__init__() is skipped, like type_call() does
                self.check(C(1), 'fast', (1,), {})
                with self.assertRaisesRegex(TypeError, 'is not safe'):
                    object.__new__(S)

    def test_python_subclass(self):
        get_fast_slots = _testcapi.get_fast_slots
        for name in 'FastInitOnly', 'FastInitBoth':
            with self.subTest(name):
                C = getattr(_testcapi, name)

                class Inherit(C):
                    pass
                self.assertEqual(get_fast_slots(Inherit), (True, False, True))
                self.check(Inherit(1, a=2), 'fast', (1,), {'a': 2})

                class Super(C):
                    def __init__(self, *args, **kwargs):
                        super().__init__(*args, **kwargs)
                self.assertEqual(get_fast_slots(Super), (False, False, False))
                self.check(Super(1, a=2), 'fast', (1,), {'a': 2})

                class Explicit(C):
                    def __init__(self, *args, **kwargs):
                        C.__init__(self, *args, **kwargs)
                self.check(Explicit(3, b=4), 'fast', (3,), {'b': 4})

                class Grandchild(Inherit):
                    pass
                self.assertEqual(get_fast_slots(Grandchild), (True, False, True))
                self.check(Grandchild(5), 'fast', (5,), {})

        C = _testcapi.FastNewOnly

        class NewSuper(C):
            def __new__(cls, *args, **kwargs):
                return super().__new__(cls, *args, **kwargs)
        self.assertEqual(get_fast_slots(NewSuper), (False, False, False))
        o = NewSuper(1, a=2)
        self.assertIs(type(o), NewSuper)
        self.check(o, 'fast', (1,), {'a': 2})

    def test_assign_init(self):
        get_fast_slots = _testcapi.get_fast_slots
        for name in 'FastInitOnly', 'FastInitBoth':
            with self.subTest(name):
                C = getattr(_testcapi, name)

                class S(C):
                    pass
                class T(S):
                    pass
                self.assertEqual(get_fast_slots(T), (True, False, True))
                calls = []
                def init(self, *args, **kwargs):
                    calls.append(args)
                    C.__init__(self, *args, **kwargs)
                S.__init__ = init
                self.assertEqual(get_fast_slots(S)[0], False)
                self.assertEqual(get_fast_slots(T)[0], False)
                self.check(S(1), 'fast', (1,), {})
                self.check(T(2), 'fast', (2,), {})
                self.assertEqual(calls, [(1,), (2,)])
                del S.__init__
                self.assertEqual(get_fast_slots(S), (True, False, True))
                self.assertEqual(get_fast_slots(T), (True, False, True))
                self.check(S(3), 'fast', (3,), {})
                self.check(T(4), 'fast', (4,), {})
                self.assertEqual(calls, [(1,), (2,)])
                # The slot wrapper of another type
                S.__init__ = _testcapi.FastNeither.__init__
                with self.assertRaisesRegex(TypeError, 'requires'):
                    S()

    def test_assign_init_on_heap_type(self):
        # The test types are mutable: assigning __init__ to the type giving
        # the fast slots doesn't lose them for its slot wrapper.
        class Base:
            pass
        C = _testcapi.FastInitOnly
        S = type('S', (C,), {})
        saved = C.__init__
        try:
            C.__init__ = lambda self, *args: saved(self, 'patched', *args)
            self.check(C(1), 'fast', ('patched', 1), {})
            self.check(S(2), 'fast', ('patched', 2), {})
            o = C.__new__(C)
            saved(o, 3)
            self.check(o, 'fast', (3,), {})
            _testcapi.call_tp_init(_testcapi.FastInitOnly, o, (4,))
        finally:
            C.__init__ = saved
        self.assertEqual(_testcapi.get_fast_slots(S), (True, False, True))
        self.check(S(5), 'fast', (5,), {})

    def test_multiple_inheritance(self):
        get_fast_slots = _testcapi.get_fast_slots
        C = _testcapi.FastInitBoth

        class Mixin:
            def __init__(self, *args, **kwargs):
                self.mixin = args
                super().__init__(*args, **kwargs)

        class MixinFirst(Mixin, C):
            pass
        self.assertEqual(get_fast_slots(MixinFirst), (False, False, False))
        o = MixinFirst(1, a=2)
        self.assertEqual(o.mixin, (1,))
        self.check(o, 'fast', (1,), {'a': 2})

        class Plain:
            pass

        class FastFirst(C, Plain):
            pass
        self.assertEqual(get_fast_slots(FastFirst), (True, False, True))
        self.check(FastFirst(3), 'fast', (3,), {})

    def test_change_bases(self):
        get_fast_slots = _testcapi.get_fast_slots
        C = _testcapi.FastInitBoth

        class WithInit:
            def __init__(self, *args, **kwargs):
                self.with_init = True
                super().__init__(*args, **kwargs)
        class NoInit:
            pass
        class U(WithInit, C):
            pass
        class V(U):
            pass
        self.assertEqual(get_fast_slots(V)[0], False)
        o = V(1)
        self.assertTrue(o.with_init)
        self.check(o, 'fast', (1,), {})
        U.__bases__ = (NoInit, C)
        self.assertEqual(get_fast_slots(U)[0], True)
        self.assertEqual(get_fast_slots(V)[0], True)
        o = V(2)
        self.assertNotHasAttr(o, 'with_init')
        self.check(o, 'fast', (2,), {})
        U.__bases__ = (WithInit, C)
        self.assertEqual(get_fast_slots(V)[0], False)
        o = V(3)
        self.assertTrue(o.with_init)
        self.check(o, 'fast', (3,), {})

    def test_reentrancy_and_gc(self):
        # Errors from the fast slots propagate, and objects are freed.
        import gc
        C = _testcapi.FastInitOnly
        for i in range(100):
            with self.assertRaises(ValueError):
                C(i, fail=True)
        gc.collect()

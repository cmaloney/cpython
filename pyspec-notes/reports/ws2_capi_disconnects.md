# C API catalog disconnects: Objects/pyspec/bytesobject.py

Catalog: 39 functions from `Objects/pyspec/bytesobject.py`, compared with `Objects/bytesobject.c`, `Include/bytesobject.h`, `Include/cpython/bytesobject.h`, `Include/internal/pycore_bytesobject.h`, `Doc/c-api/bytes.rst`, `Doc/data/refcounts.dat`, `Misc/stable_abi.toml`, `Doc/data/stable_abi.dat`.

42 disconnects.

## Catalog completeness

None found.

## Headers

- `PyBytesWriter_Grow` param-names: size (catalog: grow) (`Objects/pyspec/bytesobject.py:583`, `Include/cpython/bytesobject.h:79`)
  - note: header says "size", C definition and docs say "grow"
- `PyBytes_AsStringAndSize` param-names: s (catalog: buffer), len (catalog: length) (`Objects/pyspec/bytesobject.py:271`, `Include/bytesobject.h:51`)
  - note: header and C say (s, len), docs say (buffer, length)
- `_PyBytes_CheckOverflow` param-names: op (catalog: self) (`Objects/pyspec/bytesobject.py:383`, `Include/internal/pycore_bytesobject.h:85`)
  - note: header says "op", C definition says "self"
- `_PyBytes_IsMutable` param-names: obj (catalog: self) (`Objects/pyspec/bytesobject.py:420`, `Include/internal/pycore_bytesobject.h:81`)
  - note: header says "obj", C definition says "self"
- `_Py_bytes_repr` declared-elsewhere: declared in Include/internal/pycore_bytes_methods.h, not in Include/bytesobject.h, Include/cpython/bytesobject.h, Include/internal/pycore_bytesobject.h (`Objects/pyspec/bytesobject.py:338`, `Include/internal/pycore_bytes_methods.h:51`)
  - note: defined in bytesobject.c, declared in pycore_bytes_methods.h

## C definitions

- `PyBytesWriter_Resize` param-names: new_size (catalog: size) (`Objects/pyspec/bytesobject.py:564`, `Objects/bytesobject.c:3893`)
  - note: C says "new_size", header and docs say "size"
- `PyBytes_AsString` param-names: op (catalog: o) (`Objects/pyspec/bytesobject.py:258`, `Objects/bytesobject.c:1343`)
  - note: C "op", docs "o"
- `PyBytes_AsStringAndSize` param-names: s (catalog: buffer), len (catalog: length) (`Objects/pyspec/bytesobject.py:271`, `Objects/bytesobject.c:1354`)
  - note: C (s, len), docs (buffer, length)
- `PyBytes_Concat` param-names: pv (catalog: bytes), w (catalog: newpart) (`Objects/pyspec/bytesobject.py:391`, `Objects/bytesobject.c:3146`)
  - note: C (pv, w), docs (bytes, newpart)
- `PyBytes_ConcatAndDel` param-names: pv (catalog: bytes), w (catalog: newpart) (`Objects/pyspec/bytesobject.py:407`, `Objects/bytesobject.c:3195`)
  - note: C (pv, w), docs (bytes, newpart)
- `PyBytes_FromString` param-names: str (catalog: v) (`Objects/pyspec/bytesobject.py:130`, `Objects/bytesobject.c:163`)
  - note: C "str", docs "v"
- `PyBytes_FromStringAndSize` param-names: str (catalog: v), size (catalog: len) (`Objects/pyspec/bytesobject.py:118`, `Objects/bytesobject.c:135`)
  - note: C (str, size), docs (v, len)
- `PyBytes_Repr` param-names: obj (catalog: bytes) (`Objects/pyspec/bytesobject.py:318`, `Objects/bytesobject.c:1436`)
  - note: C "obj", docs "bytes"
- `PyBytes_Size` param-names: op (catalog: o) (`Objects/pyspec/bytesobject.py:252`, `Objects/bytesobject.c:1332`)
  - note: C "op", docs "o"
- `_PyBytes_Resize` param-names: pv (catalog: bytes) (`Objects/pyspec/bytesobject.py:431`, `Objects/bytesobject.c:3330`)
  - note: C "pv", docs "bytes"

## Docs (Doc/c-api)

- `PyBytesWriter_FinishWithSize` error-unstated: returns NULL on error; docs do not say so (`Doc/c-api/bytes.rst:342`)
  - note: "Similar to PyBytesWriter_Finish" only; NULL on error not stated
- `PyBytes_FromFormat` error-unstated: returns NULL on error; docs do not say so (`Doc/c-api/bytes.rst:62`)
  - note: does not say it returns NULL on error
- `PyBytes_FromFormatV` error-unstated: returns NULL on error; docs do not say so (`Doc/c-api/bytes.rst:126`)
  - note: does not say it returns NULL on error
- `PyBytes_FromObject` param-names: o (catalog: x) (`Objects/pyspec/bytesobject.py:59`, `Doc/c-api/bytes.rst:132`)
  - note: spec body parameter is "x", docs say "o"
- `PyBytes_FromObject` error-unstated: returns NULL on error; docs do not say so (`Doc/c-api/bytes.rst:132`)
  - note: does not say it returns NULL on error
- `PyBytes_Size` error-unstated: returns -1 on error; docs do not say so (`Doc/c-api/bytes.rst:142`)
  - note: does not say it returns -1 (TypeError) for a non-bytes object

## Doc/data/refcounts.dat

- `PyBytesWriter_Create` missing: documented, but no entry in refcounts.dat (`Doc/c-api/bytes.rst:318`)
  - note: PyBytesWriter API (3.15)
- `PyBytesWriter_Discard` missing: documented, but no entry in refcounts.dat (`Doc/c-api/bytes.rst:360`)
  - note: PyBytesWriter API (3.15)
- `PyBytesWriter_Finish` missing: documented, but no entry in refcounts.dat (`Doc/c-api/bytes.rst:331`)
  - note: PyBytesWriter API: returns a new reference, not annotated
- `PyBytesWriter_FinishWithPointer` missing: documented, but no entry in refcounts.dat (`Doc/c-api/bytes.rst:347`)
  - note: PyBytesWriter API: returns a new reference, not annotated
- `PyBytesWriter_FinishWithSize` missing: documented, but no entry in refcounts.dat (`Doc/c-api/bytes.rst:342`)
  - note: PyBytesWriter API: returns a new reference, not annotated
- `PyBytesWriter_Format` missing: documented, but no entry in refcounts.dat (`Doc/c-api/bytes.rst:384`)
  - note: PyBytesWriter API (3.15)
- `PyBytesWriter_GetData` missing: documented, but no entry in refcounts.dat (`Doc/c-api/bytes.rst:406`)
  - note: PyBytesWriter API (3.15)
- `PyBytesWriter_GetSize` missing: documented, but no entry in refcounts.dat (`Doc/c-api/bytes.rst:397`)
  - note: PyBytesWriter API (3.15)
- `PyBytesWriter_Grow` missing: documented, but no entry in refcounts.dat (`Doc/c-api/bytes.rst:434`)
  - note: PyBytesWriter API (3.15)
- `PyBytesWriter_GrowAndUpdatePointer` missing: documented, but no entry in refcounts.dat (`Doc/c-api/bytes.rst:447`)
  - note: PyBytesWriter API (3.15)
- `PyBytesWriter_Resize` missing: documented, but no entry in refcounts.dat (`Doc/c-api/bytes.rst:420`)
  - note: PyBytesWriter API (3.15)
- `PyBytesWriter_WriteBytes` missing: documented, but no entry in refcounts.dat (`Doc/c-api/bytes.rst:372`)
  - note: PyBytesWriter API (3.15)
- `PyBytes_DecodeEscape` missing: documented, but no entry in refcounts.dat (`Doc/c-api/bytes.rst:278`)
  - note: stable ABI function returning a new reference, not annotated
- `PyBytes_FromObject` params: 'PyBytes_FromObject:PyObject*:o:0:' vs 'PyBytes_FromObject:PyObject*:x:0:' (refcounts.dat vs catalog) (`Objects/pyspec/bytesobject.py:59`, `Doc/data/refcounts.dat:147`)
  - note: refcounts.dat names the parameter "o", the spec body "x"
- `PyBytes_Join` missing: documented, but no entry in refcounts.dat (`Doc/c-api/bytes.rst:215`)
  - note: added in 3.14 without a refcounts.dat entry
- `PyBytes_Repr` missing: documented, but no entry in refcounts.dat (`Doc/c-api/bytes.rst:259`)
  - note: stable ABI function returning a new reference, not annotated

## Stable ABI (Misc/stable_abi.toml, Doc/data/stable_abi.dat)

None found.

Checked: 12 catalog functions are in the stable ABI (`PyBytes_AsString`, `PyBytes_AsStringAndSize`, `PyBytes_Concat`, `PyBytes_ConcatAndDel`, `PyBytes_DecodeEscape`, `PyBytes_FromFormat`, `PyBytes_FromFormatV`, `PyBytes_FromObject`, `PyBytes_FromString`, `PyBytes_FromStringAndSize`, `PyBytes_Repr`, `PyBytes_Size`); each is declared in Include/bytesobject.h, listed in `Doc/data/stable_abi.dat` with the same version, not abi_only, and no other catalog function is declared in the limited header.

## Behavior (spec body) vs doc prose

- `PyBytes_FromObject` identity-unstated: returned unchanged (same object, new reference) (bytes); the docs do not mention it (`Objects/pyspec/bytesobject.py:59`, `Doc/c-api/bytes.rst:132`)
  - note: an exact bytes object is returned itself (new reference)
- `PyBytes_FromObject` sequence-unstated: list/tuple fast path (items: ints in range(256)) (list, tuple); the docs do not mention it (`Objects/pyspec/bytesobject.py:59`, `Doc/c-api/bytes.rst:132`)
  - note: lists and tuples of ints are accepted; docs only mention buffers
- `PyBytes_FromObject` iterable-unstated: iterated; each item converted with __index__, must be in range(256) (dict, set, range, generator, list_iterator); the docs do not mention it (`Objects/pyspec/bytesobject.py:59`, `Doc/c-api/bytes.rst:132`)
  - note: any iterable of ints (except str) is accepted
- `PyBytes_FromObject` null-unstated: NULL argument: SystemError (PyErr_BadInternalCall); docs do not say (`Objects/pyspec/bytesobject.py:59`, `Doc/c-api/bytes.rst:132`)
  - note: NULL raises SystemError (PyErr_BadInternalCall)
- `PyBytes_FromObject` runs-python-unstated: may run Python code via C._PyBytes_FromBuffer(x), C._PyBytes_FromIterator(it, x), iter(x) (`Objects/pyspec/bytesobject.py:59`, `Doc/c-api/bytes.rst:132`)
  - note: calls __buffer__, __iter__/__next__ and __index__

## Catalog overview

| function | facts | C definition | header | docs | refcounts.dat | stable ABI |
|---|---|---|---|---|---|---|
| `PyBytesWriter_Create` | PyBytesWriter *; errors: NULL | Objects/bytesobject.c:3749 | Include/cpython/bytesobject.h:49 | Doc/c-api/bytes.rst:318 | - | - |
| `PyBytesWriter_Discard` | void; errors: none; steals writer | Objects/bytesobject.c:3762 | Include/cpython/bytesobject.h:51 | Doc/c-api/bytes.rst:360 | - | - |
| `PyBytesWriter_Finish` | new; errors: NULL; steals writer | Objects/bytesobject.c:3860 | Include/cpython/bytesobject.h:53 | Doc/c-api/bytes.rst:331 | - | - |
| `PyBytesWriter_FinishWithPointer` | new; errors: NULL; steals writer | Objects/bytesobject.c:3867 | Include/cpython/bytesobject.h:58 | Doc/c-api/bytes.rst:347 | - | - |
| `PyBytesWriter_FinishWithSize` | new; errors: NULL; steals writer | Objects/bytesobject.c:3781 | Include/cpython/bytesobject.h:55 | Doc/c-api/bytes.rst:342 | - | - |
| `PyBytesWriter_Format` | int; errors: -1 | Objects/bytesobject.c:4007 | Include/cpython/bytesobject.h:71 | Doc/c-api/bytes.rst:384 | - | - |
| `PyBytesWriter_GetData` | void *; errors: none | Objects/bytesobject.c:3875 | Include/cpython/bytesobject.h:62 | Doc/c-api/bytes.rst:406 | - | - |
| `PyBytesWriter_GetSize` | Py_ssize_t; errors: none | Objects/bytesobject.c:3884 | Include/cpython/bytesobject.h:64 | Doc/c-api/bytes.rst:397 | - | - |
| `PyBytesWriter_Grow` | int; errors: -1 | Objects/bytesobject.c:3931 | Include/cpython/bytesobject.h:79 | Doc/c-api/bytes.rst:434 | - | - |
| `PyBytesWriter_GrowAndUpdatePointer` | void *; errors: NULL | Objects/bytesobject.c:3970 | Include/cpython/bytesobject.h:82 | Doc/c-api/bytes.rst:447 | - | - |
| `PyBytesWriter_Resize` | int; errors: -1 | Objects/bytesobject.c:3893 | Include/cpython/bytesobject.h:76 | Doc/c-api/bytes.rst:420 | - | - |
| `PyBytesWriter_WriteBytes` | int; errors: -1 | Objects/bytesobject.c:3982 | Include/cpython/bytesobject.h:67 | Doc/c-api/bytes.rst:372 | - | - |
| `PyBytes_AsString` | char *; errors: NULL | Objects/bytesobject.c:1343 | Include/bytesobject.h:39 | Doc/c-api/bytes.rst:152 | Doc/data/refcounts.dat:110 | 3.2 |
| `PyBytes_AsStringAndSize` | int; errors: -1 | Objects/bytesobject.c:1354 | Include/bytesobject.h:51 | Doc/c-api/bytes.rst:169 | Doc/data/refcounts.dat:113 | 3.2 |
| `PyBytes_Concat` | void; errors: NullIn('bytes'); runs Python | Objects/bytesobject.c:3146 | Include/bytesobject.h:41 | Doc/c-api/bytes.rst:191 | Doc/data/refcounts.dat:124 | 3.2 |
| `PyBytes_ConcatAndDel` | void; errors: NullIn('bytes'); steals newpart; runs Python | Objects/bytesobject.c:3195 | Include/bytesobject.h:42 | Doc/c-api/bytes.rst:204 | Doc/data/refcounts.dat:128 | 3.2 |
| `PyBytes_DecodeEscape` | new; errors: NULL; runs Python | Objects/bytesobject.c:1291 | Include/bytesobject.h:43 | Doc/c-api/bytes.rst:278 | - | 3.2 |
| `PyBytes_FromFormat` | new; errors: NULL | Objects/bytesobject.c:395 | Include/bytesobject.h:36 | Doc/c-api/bytes.rst:62 | Doc/data/refcounts.dat:139 | 3.2 |
| `PyBytes_FromFormatV` | new; errors: NULL | Objects/bytesobject.c:376 | Include/bytesobject.h:34 | Doc/c-api/bytes.rst:126 | Doc/data/refcounts.dat:143 | 3.2 |
| `PyBytes_FromObject` | new; errors: NULL; runs Python; spec body | Objects/clinic/bytesobject_pyspec.c.h:97 | Include/bytesobject.h:33 | Doc/c-api/bytes.rst:132 | Doc/data/refcounts.dat:147 | 3.2 |
| `PyBytes_FromString` | new; errors: NULL | Objects/bytesobject.c:163 | Include/bytesobject.h:32 | Doc/c-api/bytes.rst:44 | Doc/data/refcounts.dat:132 | 3.2 |
| `PyBytes_FromStringAndSize` | new; errors: NULL | Objects/bytesobject.c:135 | Include/bytesobject.h:31 | Doc/c-api/bytes.rst:51 | Doc/data/refcounts.dat:135 | 3.2 |
| `PyBytes_Join` | new; errors: NULL; runs Python | Objects/bytesobject.c:2002 | Include/cpython/bytesobject.h:35 | Doc/c-api/bytes.rst:215 | - | - |
| `PyBytes_Repr` | new; errors: NULL | Objects/bytesobject.c:1436 | Include/bytesobject.h:40 | Doc/c-api/bytes.rst:259 | - | 3.2 |
| `PyBytes_Size` | Py_ssize_t; errors: -1 | Objects/bytesobject.c:1332 | Include/bytesobject.h:38 | Doc/c-api/bytes.rst:142 | Doc/data/refcounts.dat:153 | 3.2 |
| `_PyBytesWriter_CreateByteArray` | PyBytesWriter *; errors: NULL | Objects/bytesobject.c:3755 | Include/internal/pycore_bytesobject.h:102 | - | - | - |
| `_PyBytes_CheckOverflow` | void; errors: none | Objects/bytesobject.c:3070 | Include/internal/pycore_bytesobject.h:85 | - | - | - |
| `_PyBytes_Concat` | new; errors: NULL; runs Python | Objects/bytesobject.c:1543 | Include/internal/pycore_bytesobject.h:20 | - | - | - |
| `_PyBytes_DecodeEscape2` | new; errors: NULL | Objects/bytesobject.c:1177 | Include/internal/pycore_bytesobject.h:28 | - | - | - |
| `_PyBytes_Find` | Py_ssize_t; errors: none | Objects/bytesobject.c:1401 | Include/internal/pycore_bytesobject.h:42 | - | - | - |
| `_PyBytes_FormatEx` | new; errors: NULL; runs Python | Objects/bytesobject.c:629 | Include/internal/pycore_bytesobject.h:11 | - | - | - |
| `_PyBytes_FromHex` | new; errors: NULL; runs Python | Objects/bytesobject.c:2636 | Include/internal/pycore_bytesobject.h:22 | - | - | - |
| `_PyBytes_IsMutable` | int; errors: none | Objects/bytesobject.c:3207 | Include/internal/pycore_bytesobject.h:81 | - | - | - |
| `_PyBytes_Repeat` | new; errors: NULL | Objects/bytesobject.c:1587 | Include/internal/pycore_bytesobject.h:68 | - | - | - |
| `_PyBytes_RepeatBuffer` | void; errors: none | Objects/bytesobject.c:3501 | Include/internal/pycore_bytesobject.h:65 | - | - | - |
| `_PyBytes_Resize` | int; errors: -1, NullIn('bytes') | Objects/bytesobject.c:3330 | Include/cpython/bytesobject.h:17 | Doc/c-api/bytes.rst:236 | Doc/data/refcounts.dat:3097 | - |
| `_PyBytes_ResizeKeepOnError` | int; errors: -1 | Objects/bytesobject.c:3243 | Include/internal/pycore_bytesobject.h:78 | - | - | - |
| `_PyBytes_ReverseFind` | Py_ssize_t; errors: none | Objects/bytesobject.c:1427 | Include/internal/pycore_bytesobject.h:49 | - | - | - |
| `_Py_bytes_repr` | new; errors: NULL | Objects/bytesobject.c:1443 | Include/internal/pycore_bytes_methods.h:51 | - | - | - |

## Behavior derived from spec bodies

### PyBytes_FromObject (`Objects/pyspec/bytesobject.py:59`)

Derived facts: returns, ownership, errors, runs_python, borrowed parameters: returns `PyObject *` new reference, NULL on error, runs Python: True.

| exact argument type | outcome |
|---|---|
| `bytes` | returned unchanged (same object, new reference) |
| `bytes subclass` | copied through the buffer protocol |
| `bytearray` | copied through the buffer protocol |
| `memoryview` | copied through the buffer protocol |
| `array.array` | copied through the buffer protocol |
| `list` | list/tuple fast path (items: ints in range(256)) |
| `tuple` | list/tuple fast path (items: ints in range(256)) |
| `str` | rejected: TypeError |
| `int` | rejected: TypeError |
| `bool` | rejected: TypeError |
| `float` | rejected: TypeError |
| `dict` | iterated; each item converted with __index__, must be in range(256) |
| `set` | iterated; each item converted with __index__, must be in range(256) |
| `range` | iterated; each item converted with __index__, must be in range(256) |
| `generator` | iterated; each item converted with __index__, must be in range(256) |
| `list_iterator` | iterated; each item converted with __index__, must be in range(256) |
| `NoneType` | rejected: TypeError |
| `object` | rejected: TypeError |

NULL argument: SystemError (PyErr_BadInternalCall).

Calls that may run Python code: `C._PyBytes_FromBuffer(x)`, `iter(x)`, `C._PyBytes_FromIterator(it, x)`

Doc prose (`Doc/c-api/bytes.rst:132`):

> Return the bytes representation of object *o* that implements the buffer
> protocol.
> 
> .. note::
>    If the object implements the buffer protocol, then the buffer
>    must not be mutated while the bytes object is being created.

## Documented, not in the catalog

Macros or static inline functions in headers (not defined in `Objects/bytesobject.c`): `PyBytes_AS_STRING`, `PyBytes_Check`, `PyBytes_CheckExact`, `PyBytes_GET_SIZE`

## refcounts.dat implied by the catalog

Diff from the current file to the lines the catalog implies (documented functions and those already listed):

```diff
--- Doc/data/refcounts.dat
+++ catalog
@@ -1 +1,47 @@
+PyBytesWriter_Create:PyBytesWriter*:::
+PyBytesWriter_Create:Py_ssize_t:size::
+
+PyBytesWriter_Discard:void:::
+PyBytesWriter_Discard:PyBytesWriter*:writer::
+
+PyBytesWriter_Finish:PyObject*::+1:
+PyBytesWriter_Finish:PyBytesWriter*:writer::
+
+PyBytesWriter_FinishWithPointer:PyObject*::+1:
+PyBytesWriter_FinishWithPointer:PyBytesWriter*:writer::
+PyBytesWriter_FinishWithPointer:void*:buf::
+
+PyBytesWriter_FinishWithSize:PyObject*::+1:
+PyBytesWriter_FinishWithSize:PyBytesWriter*:writer::
+PyBytesWriter_FinishWithSize:Py_ssize_t:size::
+
+PyBytesWriter_Format:int:::
+PyBytesWriter_Format:PyBytesWriter*:writer::
+PyBytesWriter_Format:const char*:format::
+PyBytesWriter_Format::...::
+
+PyBytesWriter_GetData:void*:::
+PyBytesWriter_GetData:PyBytesWriter*:writer::
+
+PyBytesWriter_GetSize:Py_ssize_t:::
+PyBytesWriter_GetSize:PyBytesWriter*:writer::
+
+PyBytesWriter_Grow:int:::
+PyBytesWriter_Grow:PyBytesWriter*:writer::
+PyBytesWriter_Grow:Py_ssize_t:grow::
+
+PyBytesWriter_GrowAndUpdatePointer:void*:::
+PyBytesWriter_GrowAndUpdatePointer:PyBytesWriter*:writer::
+PyBytesWriter_GrowAndUpdatePointer:Py_ssize_t:size::
+PyBytesWriter_GrowAndUpdatePointer:void*:buf::
+
+PyBytesWriter_Resize:int:::
+PyBytesWriter_Resize:PyBytesWriter*:writer::
+PyBytesWriter_Resize:Py_ssize_t:size::
+
+PyBytesWriter_WriteBytes:int:::
+PyBytesWriter_WriteBytes:PyBytesWriter*:writer::
+PyBytesWriter_WriteBytes:const void*:bytes::
+PyBytesWriter_WriteBytes:Py_ssize_t:size::
+
 PyBytes_AsString:char*:::
@@ -16,2 +62,9 @@
 
+PyBytes_DecodeEscape:PyObject*::+1:
+PyBytes_DecodeEscape:const char*:s::
+PyBytes_DecodeEscape:Py_ssize_t:len::
+PyBytes_DecodeEscape:const char*:errors::
+PyBytes_DecodeEscape:Py_ssize_t:unicode::
+PyBytes_DecodeEscape:const char*:recode_encoding::
+
 PyBytes_FromFormat:PyObject*::+1:
@@ -25,3 +78,3 @@
 PyBytes_FromObject:PyObject*::+1:
-PyBytes_FromObject:PyObject*:o:0:
+PyBytes_FromObject:PyObject*:x:0:
 
@@ -34,2 +87,10 @@
 
+PyBytes_Join:PyObject*::+1:
+PyBytes_Join:PyObject*:sep:0:
+PyBytes_Join:PyObject*:iterable:0:
+
+PyBytes_Repr:PyObject*::+1:
+PyBytes_Repr:PyObject*:bytes:0:
+PyBytes_Repr:int:smartquotes::
+
 PyBytes_Size:Py_ssize_t:::
```

## Other findings (found while building the catalog; not automated checks)

- **Bug: `PyBytesWriter_Format` ignores a formatting error.**
  `Objects/bytesobject.c:4016-4020`: when `bytes_fromformat()` fails it
  returns NULL. `PyBytesWriter_Format` does not check for that. It computes
  `buf - byteswriter_data(writer)` with `buf == NULL` (undefined behavior),
  then passes the negative size to `PyBytesWriter_Resize`, which replaces the
  real exception. I checked this on the debug build with ctypes:
  `PyBytesWriter_Format(w, "%c", 1000)` raises `ValueError: size must be >= 0`,
  while `PyBytes_FromFormat("%c", 1000)` raises
  `OverflowError: ... %c format expects an integer in range [0; 255]`.
  I have not fixed it.
- **Headers omit parameter names.** Every prototype in `Include/bytesobject.h:31-45`
  omits them except `PyBytes_AsStringAndSize`. So do
  `Include/cpython/bytesobject.h:17` (`_PyBytes_Resize`),
  `Include/internal/pycore_bytesobject.h:28` (`_PyBytes_DecodeEscape2`) and
  `Include/internal/pycore_bytes_methods.h:51` (`_Py_bytes_repr`). Because of
  this, the parameter names of those functions can only be compared between
  the catalog, the C definitions and the docs.
- **refcounts.dat cannot express in/out references.**
  `Doc/data/refcounts.dat:125` and `:129` give `PyBytes_Concat*` and
  `bytes` the value `0`, and `:3098` does the same for `_PyBytes_Resize`.
  In all three the old `*bytes` is released (stolen) and replaced by a new
  reference, or set to NULL on error. The catalog records this as
  `InOut[object]` plus `NullIn('bytes')`. The implied refcounts lines keep
  `0` because the file format has no way to say it (see the XXX note at
  `Doc/data/refcounts.dat:24`).
- **Some functions only exist in some builds.** `_PyBytes_IsMutable` is
  compiled only `#ifndef NDEBUG`, and `_PyBytes_CheckOverflow` only
  `#ifdef Py_DEBUG` (`Include/internal/pycore_bytesobject.h:80-89`). The
  catalog vocabulary cannot express conditional compilation, so their entries
  are unconditional.
- **Not in the catalog on purpose.** These static helpers are defined in
  `Objects/bytesobject.c`: `_PyBytes_FromSize`, `_PyBytes_FromBuffer`,
  `_PyBytes_FromSequence_lock_held`, `_PyBytes_FromIterator`,
  `_PyBytesWriter_ResizeAndUpdatePointer` and
  `_PyBytesWriter_ResizeToAllocated`. The completeness check covers only
  non-static `Py*`/`_Py*` definitions. The spec uses some of these helpers
  through `pyspec_runtime` escapes.

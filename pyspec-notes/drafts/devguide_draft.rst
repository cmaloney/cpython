.. Draft of a new section for the devguide's Argument Clinic page
   (development-tools/clinic/).  Not in the devguide repository.

.. _clinic-spec-files:

Declaring a type in a spec file
===============================

A C file can keep the Python side of its Argument Clinic functions in a
*spec file*: ``Objects/pyspec/bytesobject.py`` for
``Objects/bytesobject.c``.  A spec is ordinary Python, written like a
typeshed stub.  Argument Clinic reads it while processing the C file, so
``make clinic`` is still the only generator, and ``test_clinic`` the only
test to run.

A spec gives three things:

* the **signatures and docstrings** of the clinic functions, in Python
  syntax instead of the clinic DSL;
* optionally, the **type object**: clinic generates the static
  ``PyTypeObject``, its method table and its slot tables;
* optionally, **bodies**: a method written in (a subset of) Python is
  compiled to C, and the interpreter gets facts about it (for example that
  ``bytes(b)`` returns ``b`` for an exact ``bytes``).

Everything else stays C, exactly as with plain Argument Clinic.


A clinic function in a spec
---------------------------

Compare a plain clinic block with its spec form.  Plain Argument Clinic,
in ``bytesobject.c``::

   /*[clinic input]
   @permit_long_summary
   bytes.split

       sep: object = None
           The delimiter according which to split the bytes.
       maxsplit: Py_ssize_t = -1
           Maximum number of splits to do.

   Return a list of the sections in the bytes, using sep as the delimiter.
   [clinic start generated code]*/

With a spec, ``Objects/pyspec/bytesobject.py`` holds::

   class bytes:
       @permit_long_summary
       def split(self, sep: object = None, maxsplit: Py_ssize_t = -1):
           """Return a list of the sections in the bytes, using sep as the delimiter.

             sep
               The delimiter according which to split the bytes.
             maxsplit
               Maximum number of splits to do.
           """
           ...

and ``bytesobject.c`` keeps a one-line block above the impl::

   /*[clinic input]
   bytes.split
   [clinic start generated code]*/

   static PyObject *
   bytes_split_impl(PyBytesObject *self, PyObject *sep, Py_ssize_t maxsplit)
   /*[clinic end generated code: output=52126b5844c1d8ef input=...]*/
   {
       ...
   }

The rules are the clinic rules, spelled in Python:

* The **converter** is the annotation, with its arguments
  (``slice_index(accept={int, NoneType}, c_default='0')``); the default
  is the Python default, ``NULL`` included.
* ``/`` and ``*`` are Python's.  An unannotated first parameter is
  clinic's implicit ``self`` (or ``cls``).
* The **docstring** is the one ``help()`` shows after the signature: the
  summary line, then the parameter section (``  name`` and its text
  indented by 4, in signature order), then the rest.
* **Decorators**: ``@classmethod`` and ``@staticmethod`` are Python's;
  every clinic decorator (``@permit_long_summary``,
  ``@text_signature("...")``, ``@critical_section``, ``@vectorcall``...)
  is written as a Python decorator with the same arguments.
* **C names**: the C basename is clinic's default; ``@c_name("x")`` gives
  another, like ``as x`` in a block.  In a converter, ``c_param='x'`` names
  the C parameter (clinic's ``name as x``).
* **No clones**: Python has none, so ``count`` is a full ``def`` with the
  same signature as ``find``.  Clinic generates the same code as for a
  clone.
* A body of ``...`` means "implemented in C by hand".

Clinic writes the impl head into the one-line block and the argument
parsing into ``Objects/clinic/bytesobject.c.h``, byte for byte what the
full block would give.  A spec method without a block in the C file is an
error that shows the block to add.


The type object
---------------

A class decorated with ``@static_type`` is a whole type::

   @static_type(tp_basicsize="PyBytesObject_SIZE", tp_itemsize="sizeof(char)",
                tp_dealloc="bytes_dealloc", tp_flags="Py_TPFLAGS_BYTES_SUBCLASS")
   class bytes:
       """bytes(iterable_of_ints) -> bytes ..."""

       def __repr__(self, /): ...

       @c_name(mp_length="bytes_length", sq_length="bytes_length")
       def __len__(self, /): ...

       @c_name(METH_NOARGS="bytes_getnewargs")
       def __getnewargs__(self, /): ...

       center = transmogrify.B.center

* The ``class bytes "PyBytesObject *" "&PyBytes_Type"`` directive in the C
  file names the C type and the type object.
* The class docstring is ``tp_doc``; the order of the class body is the
  order of the method table, hence of ``bytes.__dict__``.
* A dunder that has a slot (``slotdefs[]`` in ``Objects/typeobject.c``) is a
  slot: its C function has the slot's typedef and is named
  ``<class>_<slot>`` unless ``@c_name`` says otherwise.  It has no
  docstring, and a slot shared by several dunders (``tp_richcompare``)
  needs all of them declared.
* ``@c_name(METH_O="f")`` or ``METH_NOARGS`` declares a hand-written
  PyCFunction (``@classmethod`` adds ``METH_CLASS``).
* ``center = transmogrify.B.center`` shares a method declared once in
  ``Objects/stringlib/pyspec/transmogrify.py``.
* ``@static_type(...)`` takes the members that cannot be derived, as C
  expressions; ``@final`` means not subclassable.

The type is generated at the end of ``Objects/clinic/bytesobject_pyspec.c.h``,
which the C file includes as its last line.


Bodies
------

A method or a top-level function with a real body is compiled to C.  The
accepted subset is small: ``if``/``else``, ``return``, ``raise E("...")``,
assignments of calls, ``try``/``except E``/``else``, ``for`` loops; tests
on ``NULL``, exact types, ``isinstance()`` and integers; calls of C
functions (``C.<escape>(...)``) and of other spec functions.  Anything else
is an error pointing at ``Objects/pyspec/README.rst``.

Add cases for a new body to ``Objects/pyspec/<stem>_cases.py``:
``test_clinic`` runs the spec as Python on each case and compares the
outcome with the built interpreter.


Common tasks
------------

``Objects/pyspec/README.rst`` has a one-page table of the common tasks:
add a parameter, a C method, a spec-body method, a slot, a hand-written
PyCFunction or a shared stringlib method, declare a type, regenerate and
test.

After changing a spec, run ``make clinic`` (or
``./python Tools/clinic/clinic.py Objects/bytesobject.c``), rebuild, and
run ``./python -m test test_clinic``.  Clinic reports errors as
``path:line: error: message``, at the line of the spec when the mistake is
in the spec, and writes nothing when anything fails.

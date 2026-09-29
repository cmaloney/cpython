.. Draft of a new section for the devguide's Argument Clinic page
   (development-tools/clinic/).  Not in the devguide repository.

.. _clinic-spec-files:

Declaring a type in a spec file
===============================

A C file can keep the Python side of its Argument Clinic functions in a
*spec file*: ``Objects/pyspec/bytesobject.py`` for
``Objects/bytesobject.c``.  A spec is ordinary Python, written like a
typeshed stub.  Argument Clinic reads it while processing the C file, so
``make clinic`` is still the only generator.  Each spec has a companion
test-data file, ``Objects/pyspec/bytesobject_cases.py``, which names the
Python type of each class of the spec (``TYPES``) and holds the cases
of its tests.

A spec gives three things:

* the **signatures and docstrings** of the clinic functions, in Python
  syntax instead of the clinic DSL;
* optionally, the **method and slot tables** of a type: clinic generates
  its ``PyMethodDef`` array, its ``tp_as_*`` sub-tables and its
  docstring; the ``PyTypeObject`` itself stays hand-written in C;
* optionally, **bodies**: a method written in (a subset of) Python is
  generated as C, and the interpreter gets facts about it (for example
  that ``bytes(b)`` returns ``b`` for an exact ``bytes``); a C function
  written by hand can carry a Python *reference* body (``@native``),
  never compiled, from which clinic derives the facts of its calls.

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


Method and slot tables
----------------------

A class that declares a slot (a dunder) gets its tables generated::

   @c_name("striter")
   class bytes_iterator:
       @c_name("PyObject_SelfIter")
       def __iter__(self, /): ...

       @c_name(METH_NOARGS="striter_len")
       def __length_hint__(self, /):
           """Private method returning an estimate of len(list(it))."""
           ...

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

Clinic writes ``<prefix>_doc``, ``<prefix>_methods[]`` and
``<prefix>_as_number`` (and the other sub-tables) into
``Objects/clinic/bytesobject_pyspec.c.h``; the C file includes it and
then defines its ``PyTypeObject`` structs, which name them as before.
A class that declares no slot gets no tables: its C method table stays.


Bodies
------

A method or a top-level function with a real body is generated as C.
Only a subset is lowered: ``if``/``else``, ``return``, ``raise``,
assignments of calls, ``try``/``except``/``else``/``finally``, ``for``
loops; tests on ``NULL``, exact types, ``isinstance()`` and integers;
calls of C functions by name and of other spec functions.  Any other
Python is accepted by the spec language, and reported as "expressible,
but not lowered to C yet" where clinic would have to generate it.  A C
function a body calls is declared in the spec of its own C file with
``@native``: its body is a Python reference of the C, never compiled,
read for facts (the exact result type, whether it can raise, whether it
may run Python code).

Add cases for a new body to ``Objects/pyspec/<stem>_cases.py``:
``test_clinic`` runs the spec as Python on each case and compares the
outcome with the built interpreter.


Common tasks
------------

``Objects/pyspec/README.rst`` has a one-page table of the common tasks:
add a parameter, a C method, a spec-body method, a slot, a hand-written
PyCFunction or a shared stringlib method, declare a type, regenerate,
test and validate (``Tools/clinic/pyspec_review.py``).

To move a C file to a spec: write ``Objects/pyspec/foo.py``, add
``Objects/pyspec/foo_cases.py`` with the class in ``TYPES`` (and its
parity data, ``PARITY``, if the type needs samples), record the type's
behaviour with ``./python Tools/clinic/pyspec_parity.py check --update``
*before* the change, then shrink the clinic blocks.
``Objects/pyspec/MIGRATING.rst`` has the steps and checklists per level.

After changing a spec, run ``make clinic`` (or
``./python Tools/clinic/clinic.py Objects/bytesobject.c``), rebuild, and
run ``./python -m test test_clinic test_pyspec_facts test_pyspec_catalog
test_tools.test_pyspec_parity``.  ``./python
Tools/clinic/pyspec_review.py`` runs the first three and the parity
check, and says what changed against main.  Clinic reports errors as
``path:line: error: message``, at the line of the spec when the mistake is
in the spec.

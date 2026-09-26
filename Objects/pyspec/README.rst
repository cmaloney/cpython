Specs: C types declared in Python
=================================

``Objects/pyspec/foo.py`` is the *spec* of ``Objects/foo.c``: its types
written as ordinary Python, in the style of a typeshed stub.  Argument
Clinic reads it when it processes ``foo.c``.  A method of ``class bytes``
is the clinic function ``bytes.meth``.  A body of ``...`` means the C impl
is written by hand, as with plain Argument Clinic; a real body is
generated as C.  ``Objects/stringlib/pyspec/`` holds the specs of the
templates that bytes and bytearray share.

Files
-----

=====================================  ====================================
``Objects/pyspec/foo.py``              the spec: signatures, docstrings,
                                       decorators, bodies, type objects
``Objects/pyspec/foo_cases.py``        test data: ``CASES`` and ``TYPES``
``Objects/foo.c``                      one-line clinic block per spec
                                       method (``bytes.split``) above its
                                       impl, as with plain Argument Clinic
``Objects/clinic/foo.c.h``             generated: argument parsing
``Objects/clinic/foo_pyspec.c.h``      generated: the spec bodies, the
                                       tier-2 call table, the type
                                       objects; ``foo.c`` includes it last
=====================================  ====================================

To do X, edit Y
---------------

==========================  ===============================================
Task                        What to edit
==========================  ===============================================
Add a parameter             The method's signature in the spec (converter
                            as annotation) and its ``  name`` docstring
                            section; run clinic, which rewrites the impl
                            head in ``foo.c``; use the parameter in C.
Add a C method              A ``def`` with body ``...`` in the spec, at its
                            place in the method table (the class body order
                            is ``T.__dict__`` order); in ``foo.c``, a block
                            ``/*[clinic input]`` ``bytes.meth``
                            ``[clinic start generated code]*/`` above the
                            impl.  Clinic writes the head and the table.
Add a spec-body method      The same ``def`` with a body in the subset
                            below, the same one-line block (no C body);
                            add cases to ``foo_cases.py``.
Add or rename a slot        ``def __len__(self, /): ...`` in the class,
                            no docstring, with ``@c_name(...)`` if the C
                            function is not ``<class>_<slot>``; write the C
                            function with the slot's typedef.
Add a hand-written          ``@c_name(METH_O="f")`` (or ``METH_NOARGS``,
PyCFunction                 plus ``@classmethod`` for ``METH_CLASS``);
                            the docstring is ``__doc__`` as is.
Share a stringlib method    ``from stringlib.pyspec import transmogrify``,
                            then ``center = transmogrify.B.center`` in the
                            class; the method is declared once, in
                            ``Objects/stringlib/pyspec/transmogrify.py``.
Declare a new type          ``@static_type(...)`` on its class, a
                            ``class T "CType *" "&T_Type"`` directive in
                            ``foo.c``, and the type in ``TYPES`` of
                            ``foo_cases.py``.
Regenerate                  ``make clinic``, or
                            ``./python Tools/clinic/clinic.py Objects/foo.c``
Test                        ``./python -m test test_clinic`` (after
                            rebuilding Python if the spec changed)
==========================  ===============================================

Decorators
----------

* ``@classmethod``, ``@staticmethod``: Python's.  ``__new__`` is implicitly
  a class method.
* Clinic decorators, written as Python decorators with the same name and
  arguments: ``@permit_long_summary``, ``@text_signature("(...)")``,
  ``@critical_section``, ``@vectorcall``, ``@disable(...)``...  They do
  nothing when the spec runs as Python.
* ``@c_name("x")``: the C basename (clinic's ``as x``).  The default is
  clinic's: ``T_meth``, ``T`` for ``T.__new__``, ``T___init__``.
* ``@c_name(slot="f", ...)``: the slots of a dunder that several slots can
  implement (``@c_name(mp_length="f", sq_length="f")``).
* ``@c_name(METH_NOARGS="f")``, ``@c_name(METH_O="f")``: a hand-written
  PyCFunction entry.
* ``@static_type(member="C expression", ...)`` on a class: clinic generates
  its static ``PyTypeObject``; ``@final``: not subclassable.

In a converter, ``c_param='x'`` names the C parameter (clinic's
``name as x``).

What a spec may contain
-----------------------

* A class body holds a docstring, ``def``\ s, shared methods
  (``x = module.Class.x``) and ``pass``.  Two methods with the same
  signature are two full ``def``\ s: Python has no clones.
  ``@getter``/``@setter`` are not supported in a ``@static_type`` class yet.
* A C implementation is a body of ``...``, or only a docstring (not
  ``pass``).
* A spec body may use: ``if``/``else``, ``return``, ``raise E("...")``,
  ``x = call(...)``, ``try``/``except E``/``else``, ``for item in it``;
  conditions ``x is [not] NULL``, ``type(x) is K``, ``isinstance(x, K)``,
  ``hasattr(type(x), "__dunder__")``, integer comparisons, ``and``/``or``/
  ``not``; calls of ``C.<escape>(...)``, other spec functions and
  ``T.meth(...)``.  See ``Tools/clinic/libclinic/pyspec/emit.py``.

Clinic reports every error as ``path:line: error: message``, at the line
of the spec when the error is in the spec.  The implementation is in
``Tools/clinic/libclinic/pyspec/``.

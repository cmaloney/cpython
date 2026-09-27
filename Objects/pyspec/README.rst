Specs: C types declared in Python
=================================

``Objects/pyspec/foo.py`` is the *spec* of ``Objects/foo.c``: its types
written as ordinary Python, in the style of a typeshed stub.  Argument
Clinic reads it when it processes ``foo.c``.  A method of ``class bytes``
is the clinic function ``bytes.meth``.  A body of ``...`` means the C impl
is written by hand, as with plain Argument Clinic; a real body is
generated as C.  ``Objects/stringlib/pyspec/`` holds the specs of the
templates that bytes and bytearray share.  A spec body calls C functions
by name; each one it calls is declared in the spec of its own file
(``Objects/pyspec/abstract.py`` for ``Objects/abstract.c``,
``Python/pyspec/errors.py``, ``Include/cpython/pyspec/longintrepr.py``),
with its Python reference (below).

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
Call a C function from a    Call it by name.  Declare it, if no spec does
spec body                   yet, in the spec of its C file, with
                            ``@c_implemented`` and its Python reference
                            (below), and import it (``from pyspec.abstract
                            import PyObject_LengthHint``); add it to
                            ``HelperTest`` of ``test_pyspec_facts``.
Add or rename a slot        ``def __len__(self, /): ...`` in the class,
                            no docstring, with ``@c_name(...)`` if the C
                            function is not ``<class>_<slot>`` without the
                            slot's prefix (``bytes_repr``); write the C
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
Test                        ``./python -m test test_clinic
                            test_pyspec_facts test_pyspec_catalog`` (after
                            rebuilding Python if the spec changed)
Change a C function a spec  Keep its Python reference in step: what it
calls                       returns and raises, and which Python code it
                            may run (``calls()``, ``runs_python()``).
                            ``test_pyspec_catalog`` reads the C and fails
                            on a call that may run Python code the
                            reference does not account for.
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
  ``pass``): nothing is known about it, and a call of it may do anything.
* A spec body may use: ``if``/``else``, ``return``, ``raise E("...")``,
  ``x = call(...)``, ``try``/``except E``/``else``, ``try``/``finally``,
  ``for item in it``; conditions ``x is [not] NULL``, ``type(x) is K``,
  ``isinstance(x, K)``, ``hasattr(type(x), "__dunder__")``, integer
  comparisons, ``and``/``or``/``not``; calls of C functions, other spec
  functions and ``T.meth(...)``.  See
  ``Tools/clinic/libclinic/pyspec/emit.py``.

C functions: ``@c_implemented``
-------------------------------

A C function written by hand that spec bodies call is a function of the
spec of its file, decorated ``@c_implemented``: the C is the authority, and
the body is its *Python reference*.  The reference runs when a spec runs
as Python (the difftest), and Argument Clinic reads it for the facts of
each call: the exact type of the result, whether it can raise, and whether
it may run Python code, for the arguments the call knows about.  It is
never compiled.  Its annotations are its C types (``object``, ``str``,
``int``, ``Py_ssize_t``, ``None``, or the C type as a string,
``'PyTypeObject *'``)::

    @c_implemented
    def _PyBytes_FromBuffer(x: object):
        """A copy of the buffer of x (in C order)."""
        calls(x, "__buffer__")
        calls(x, "__release_buffer__")
        return exact(bytes, memoryview(x).tobytes())

What plain Python cannot say, a few primitives say where it happens:

=========================  ===============================================
``exact(T, value)``        value is a new object of exactly type T
``unknown(value)``         value is a new object of a type not known
                           exactly
``calls(x, "__name__")``   here the C invokes the special method of
                           ``type(x)``: Python code runs only if that is
                           Python code (for builtin types, the audited
                           table of ``builtin_types.py`` says)
``runs_python()``          here the C may run any Python code
``return NULL``            an absent result, not an error
=========================  ===============================================

The rest of the reference is the model of the values the C computes: it
has no other effects.  ``raise`` says what the C raises; ``exact()`` and
``unknown()`` may fail with MemoryError, ``calls()`` and
``runs_python()`` may raise anything.  The error check of a call follows:
none if it cannot raise; else NULL for an object (NULL with an exception
set if it may also return NULL), -1 with an exception set for a
``Py_ssize_t``, negative for an ``int``.  Ownership is C's: a returned
object is a new reference, arguments are borrowed.

A leading ``if <test>: return <value>`` of a reference is a *fast path*:
where a call knows the test holds (``type(o) is int`` for an exact int),
the value is written instead of the call; a call on a loop item is split
into both.  A C struct kept in a local, such as the ``bytes_appender`` of
``bytesobject.c``, is the result of a function whose return annotation
is the struct: it initializes the local in place, and the body releases
it in a ``finally`` clause.

Two checks keep a reference true: ``test_pyspec_catalog`` reads the C of
the function (and the static functions it calls) and fails on a call that
may run Python code the reference does not account for (a call of the
same function, a ``calls()`` of the special method, or ``runs_python()``);
``HelperTest`` of ``test_pyspec_facts`` calls the C directly, compares it
with the reference, and checks the derived facts, with debug builds
aborting when Python code runs where the facts say none does.

Clinic reports every error as ``path:line: error: message``, at the line
of the spec when the error is in the spec.  The implementation is in
``Tools/clinic/libclinic/pyspec/``.

To migrate a C file to a spec, and to decide whether a function is
worth a spec body, see `MIGRATING.rst <MIGRATING.rst>`_.

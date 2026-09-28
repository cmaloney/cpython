Specs: C types declared in Python
=================================

``Objects/pyspec/foo.py`` is the *spec* of ``Objects/foo.c``: its types
written as ordinary Python, in the style of a typeshed stub.  Argument
Clinic reads it when it processes ``foo.c``.  A method of ``class bytes``
is the clinic function ``bytes.meth``.  A body of ``...`` means the C impl
is written by hand, as with plain Argument Clinic; a real body is
generated as C (if it is in the lowered subset, below).
``Objects/stringlib/pyspec/`` holds the specs of the
templates that bytes and bytearray share.  A spec body calls C functions
by name; each one it calls is declared in the spec of its own file
(``Objects/pyspec/abstract.py`` for ``Objects/abstract.c``,
``Python/pyspec/errors.py``, ``Include/cpython/pyspec/longintrepr.py``),
with its Python reference (below).

Files
-----

=====================================  ====================================
``Objects/pyspec/foo.py``              the spec: signatures, docstrings,
                                       decorators, bodies, the methods
                                       and slots of its types
``Objects/pyspec/foo_cases.py``        test data: ``CASES``, ``TYPES``
                                       and the names described in
                                       ``bytesobject_cases.py``
``Objects/foo.c``                      one-line clinic block per spec
                                       method (``bytes.split``) above its
                                       impl, as with plain Argument Clinic
``Objects/clinic/foo.c.h``             generated: argument parsing
``Objects/clinic/foo_pyspec.c.h``      generated: the spec bodies, the
                                       tier-2 call table, the docstring,
                                       method and slot tables of the
                                       types; ``foo.c`` includes it last,
                                       then defines the ``PyTypeObject``\ s
                                       naming them
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
Add a spec-body method      The same ``def`` with a body in the lowered
                            subset (below), the same one-line block (no C
                            body); add cases to ``foo_cases.py``.
Keep a method's C, with     ``@c_implemented`` on the ``def``: any
its Python reference        signature, any Python body; clinic output is
                            that of ``...``.
Add an accessor             ``@getter def attr(self) -> conv:`` (its
                            docstring) and ``@setter def attr(self,
                            value: object):``; in ``foo.c`` the blocks
                            ``@getter`` ``T.attr`` and ``@setter``
                            ``T.attr``.  ``tp_getset`` stays in C.
Call a C function from a    Call it by name.  Declare it, if no spec does
spec body                   yet, in the spec of its C file, with
                            ``@c_implemented`` and its Python reference
                            (below), and import it (``from pyspec.abstract
                            import PyObject_LengthHint``); add its inputs
                            to ``HELPERS`` of the ``_cases.py`` of its
                            spec (``HelperTest`` of ``test_pyspec_facts``).
Add or rename a slot        ``def __len__(self, /): ...`` in the class,
                            no docstring, with ``@c_name(...)`` if the C
                            function is not ``<class>_<slot>`` without the
                            slot's prefix (``bytes_repr``); write the C
                            function with the slot's typedef.
Give the optimizer the      ``@c_implemented`` on the slot, with its Python
facts of a slot             reference (``bytes.__getitem__``); add inputs
                            to ``HELPERS`` in ``foo_cases.py``.  Clinic
                            puts its facts in the call table of the class;
                            a uop that does what the slot does takes its
                            result facts from ``_PySpec_FindSlot()`` with
                            ``_PySpec_SLOT(<member>)`` (see
                            ``_BINARY_OP_SUBSCR_BYTES_INT``) and is listed
                            in ``SLOT_USES`` of ``foo_cases.py``.
Add a hand-written          ``@c_name(METH_O="f")``, or ``METH_NOARGS``,
PyCFunction                 ``METH_VARARGS``, ``METH_FASTCALL``: the
                            parameters say which (``(self, /)``,
                            ``(self, arg, /)``, ``(self, /, *args)``;
                            ``**kwargs`` adds ``METH_KEYWORDS``);
                            ``@classmethod``, ``@staticmethod``,
                            ``@coexist`` add ``METH_CLASS``,
                            ``METH_STATIC``, ``METH_COEXIST``.  The
                            docstring is ``__doc__`` as is, after the
                            signature of ``@text_signature``.  A slot
                            with a method entry too (list's
                            ``__getitem__``): its slots and
                            ``METH_O="f"`` in ``@c_name``, and
                            ``@coexist``.
Share a stringlib method    ``from stringlib.pyspec import transmogrify``,
                            then ``center = transmogrify.B.center`` in the
                            class; the method is declared once, in
                            ``Objects/stringlib/pyspec/transmogrify.py``.
                            ``critical_section(transmogrify.B.center)``:
                            clinic generates ``<class>_center()``, which
                            calls it in a critical section on self.
Declare a method like       ``strip = bytesobject.bytes.strip`` (after
another type's              ``from pyspec import bytesobject``) and the
                            block ``bytearray.strip`` in ``foo.c``: a
                            clinic function of this class with the other's
                            parameters, docstring and decorators; wrap it
                            (``critical_section(...)``) to add
                            ``@critical_section``.  A hand-written
                            PyCFunction with another's docstring:
                            ``m = c_name(METH_NOARGS="f")(T.m)``.
Declare a new type          A class in the spec (its docstring, methods
                            and dunders), a ``class T "CType *"
                            "&T_Type"`` directive in ``foo.c``, and the
                            type in ``TYPES`` of ``foo_cases.py``; write
                            its ``PyTypeObject`` in C after the include of
                            ``clinic/foo_pyspec.c.h``, naming
                            ``T_doc``, ``T_methods``, ``T_as_number``...
                            (``@c_name("prefix")`` on the class changes
                            ``T``).  ``test_clinic`` checks that the slots
                            it fills are the dunders of the class.
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
* ``@c_name(METH_NOARGS="f")``, ``@c_name(METH_O="f")``,
  ``METH_VARARGS``, ``METH_FASTCALL``: a hand-written PyCFunction entry
  (``Spec.pycfunction()`` in ``frontend.py``).
* ``@c_implemented``: the C is written by hand and the body is its Python
  reference (below); on a clinic method, clinic generates what it does
  for ``...``.
* ``@getter``, ``@setter`` (and ``@deleter`` after ``@setter``): an
  accessor; its block in the C file starts with the same decorator.
* ``@c_name("prefix")`` on a class: the prefix of its generated tables
  (``striter_methods``); the default is the class name.

In a converter, ``c_param='x'`` names the C parameter (clinic's
``name as x``).

The spec language
-----------------

A spec is Python, and may say anything a type needs.  Clinic reads it
with the ``ast`` module; the tests run it.

* A class body holds a docstring, ``def``\ s, shared methods
  (``x = module.Class.x``, or ``Class.x`` of the same spec, possibly
  wrapped in ``critical_section(...)`` or ``c_name(...)(...)``) and
  ``pass``.  Two methods with the same signature are two full ``def``\ s:
  Python has no clones.
* A signature is any signature clinic can state: positional-only,
  positional-or-keyword and keyword-only parameters, ``*args``,
  ``**kwargs``, any converter (the annotation, with its options:
  ``object(c_default="NULL")``, ``str(accept={str, NoneType})``,
  ``c_param='x'`` for clinic's ``name as x``), any default (``()``,
  ``10``, ``None``, ``NULL``), ``self: self(type="...")``, ``cls:
  defining_class``, a return converter (``-> Py_ssize_t``),
  ``@classmethod``, ``@staticmethod``, ``__new__``, ``__init__``,
  accessors (``@getter``, ``@setter``) and every clinic decorator.
  Clinic's output for it is plain clinic's, byte for byte.  Not
  expressible yet: optional groups (``[ ]``), the ``[from X.Y]``
  deprecation markers, and module-level clinic functions: keep those in
  plain clinic.
* A body is any Python.  ``...`` (or only a docstring, not ``pass``) is
  a C implementation about which nothing is known: a call of it may do
  anything.  With ``@c_implemented`` the body is the Python reference of
  C written by hand (below).  Any other body is generated as C, and must
  be in the lowered subset.

The lowered subset
------------------

What clinic generates as C, and what the facts follow, is one explicit
part of the language, checked by ``Tools/clinic/libclinic/pyspec/subset.py``
before anything else.  Outside it, clinic says where and what:
``foo.py:12: error: bytes.__new__(): while loop '...' is expressible, but
not lowered to C yet``.  Keep the C by hand then: ``...``, or
``@c_implemented`` with the body as its Python reference.

========================  ================================================
Signature                 a top-level function, ``__new__`` (of a type
                          with a row in ``builtin_types.py``), a method
                          or a ``@classmethod``; positional parameters
                          with converter ``object`` or ``str``, default
                          ``NULL``; no ``@critical_section``
Statements                ``if``/``else``; ``x = call(...)``;
                          ``f(...)`` for a C function ``f``; ``return
                          x``, ``return call(...)``, ``return
                          <constant>``; ``raise f(...)`` (a C function
                          setting the exception), ``raise E("...")``,
                          ``raise E(f"...{fqname(type(x))}...")`` (also
                          ``tp_name``); ``try: x = call(...)`` ``except
                          E:`` ... ``else:`` ...; ``try:`` ...
                          ``finally:`` <calls of C functions>; ``for
                          item in it:`` (no ``else``); ``pass``
Conditions                ``x is [not] NULL``, ``(v := call(...)) is
                          [not] NULL``, ``type(x) is [not] K``, ``cls
                          is [not] K``, ``isinstance(x, K)``,
                          ``hasattr(type(x), "__index__")`` (or
                          ``"__buffer__"``), a call of a C function
                          that cannot fail, integer comparisons,
                          ``and``/``or``/``not``; ``K`` a type of
                          ``builtin_types.py``
Values                    names, ``NULL``, types, exception classes,
                          ``bool`` and ``int`` constants; a ``str``
                          constant as the argument of a C function
Calls                     C functions by name (``@c_implemented``, or
                          ``...``), other spec functions (``f(...)``,
                          ``T.meth(...)``), ``iter(x)``, ``len(x)`` of
                          an exact list or tuple, a local object or
                          type with at most one argument (``f()``,
                          ``cls(x)``)
========================  ================================================

In a Python reference (``@c_implemented``), the facts follow the same
control flow; any other code is the model of a value and must have no
effect (no primitive, no call of a C or spec function, no ``return`` or
``raise``) where they cannot see it, e.g. in a ``while`` loop or in the
argument of a call.  A reference that does has the worst facts: any
result, may raise anything, may run Python code.  So does a function
about which nothing is known.

Extending the lowered subset
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Adding a construct is a local change:

1. accept it in ``subset.py``, in the method of ``Lowered`` for its kind
   of node (``signature()``, ``statement()``, ``condition()``,
   ``value()``, ``call()``; ``Analysed`` for references);
2. lower it in ``emit.py`` (and evaluate it in ``partial_eval.py`` if
   the facts of a call site decide it);
3. give its effects in ``facts.py`` if it has any (anything it does not
   know is the worst case);
4. add its row to the table above, and a test to ``PyspecLanguageTest``
   of ``Lib/test/test_clinic.py`` (its message moves from the
   "not lowered" cases to a generated-C case).

Conditional compilation
-----------------------

A spec has no ``#if``: as with plain Argument Clinic, the condition of a
method is where its block is in the C file.

* A method compiled under ``#if``: put its one-line block inside the
  ``#if``.  Clinic wraps its generated code (and a spec body in
  ``foo_pyspec.c.h``) in the condition, and defines an empty
  ``*_METHODDEF`` when it is false, so a method table lists it
  unconditionally.
* A signature that depends on ``#if`` (the same method defined twice):
  keep its full clinic blocks in the C file.  In the spec it is only
  ``def meth(self): ...``, its place in a generated method table, or
  absent.  Declaring it in both is an error.
* A slot compiled under ``#if`` stays in a hand-written C sub-table and
  is not declared in the spec.
* The tests skip a method whose block is under an ``#if`` false in this
  build.

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
of the spec when the error is in the spec (in the spec it was written
in, for code copied from another).  A spec error has a kind
(``SpecErrorKind`` in ``Tools/clinic/libclinic/errors.py``): not valid
in the spec language; expressible, but not lowered yet; in the lowered
subset, but a use the emitter cannot lower (a local that changes type);
or a disagreement between the spec and the blocks of the C file.  The
implementation is in ``Tools/clinic/libclinic/pyspec/``.

To migrate a C file to a spec, and to decide whether a function is
worth a spec body, see `MIGRATING.rst <MIGRATING.rst>`_.

Specs: C types declared in Python
=================================

``Objects/pyspec/foo.py`` is the *spec* of ``Objects/foo.c``: its types
written as ordinary Python, in the style of a typeshed stub.  Argument
Clinic reads it when it processes ``foo.c``.  A method of ``class T``
is the clinic function ``T.meth``.  A body of ``...`` means the C impl
is written by hand, as with plain Argument Clinic; a real body is
generated as C (if it is in the lowered subset, below).  The same holds
in every directory: ``<dir>/pyspec/<stem>.py`` is the spec of
``<dir>/<stem>.c`` (or of the header ``<dir>/<stem>.h``:
``Objects/stringlib/pyspec/`` holds the specs of the templates that
bytes and bytearray share), found by one glob
(``Tools/clinic/libclinic/pyspec/specfiles.py``).  A spec body calls C
functions by name; each one it calls is declared in the spec of its own
file (``Objects/pyspec/abstract.py`` for ``Objects/abstract.c``,
``Python/pyspec/errors.py``, ``Include/cpython/pyspec/longintrepr.py``),
``@native``, with its Python reference (below).  Every piece of code
that runs has one source: native code (C written by hand) that a
reference only describes, or a spec body that clinic generates.

``Objects/pyspec/bytesobject.py`` is the complete example: every kind
of declaration below appears in it.  This file is the reference ("to do
X, edit Y"); how to move a C file to a spec, step by step, and how to
validate a change is in `MIGRATING.rst <MIGRATING.rst>`_.

Files
-----

=====================================  ====================================
``Objects/pyspec/foo.py``              the spec: signatures, docstrings,
                                       decorators, bodies, the methods
                                       and slots of its types
``Objects/pyspec/foo_cases.py``        test data: ``TYPES``, ``CASES``
                                       and the other names described in
                                       the docstring of
                                       ``bytesobject_cases.py``
``Objects/foo.c``                      one-line clinic block per spec
                                       method (``T.meth``) above its
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
                            ``/*[clinic input]`` ``T.meth``
                            ``[clinic start generated code]*/`` above the
                            impl.  Clinic writes the head and the table.
Add a spec-body method      The same ``def`` with a body in the lowered
                            subset (below), the same one-line block (no C
                            body); add cases to ``foo_cases.py``.
Keep a method's C, with     ``@native`` on the ``def``: any
its Python reference        signature, any Python body; clinic output is
                            that of ``...``.
Give a C method its pure    ``@native(facts=False)`` on the ``def`` and
Python                      the Python as its body ("Pure Python",
                            below); clinic output is that of ``...``;
                            check it with ``./python
                            Tools/clinic/pyspec_parity.py model``.
Add an accessor            ``@getter def attr(self) -> conv:`` (its
                            docstring) and ``@setter def attr(self,
                            value: object):``; in ``foo.c`` the blocks
                            ``@getter`` ``T.attr`` and ``@setter``
                            ``T.attr``.  ``tp_getset`` stays in C.
Call a C function from a    Call it by name.  Declare it, if no spec does
spec body                   yet, in the spec of its C file, with
                            ``@native`` and its Python reference
                            (below), and import it by the path of the
                            spec from the source root (``from
                            Objects.pyspec.abstract import
                            PyObject_LengthHint``); add its inputs to
                            ``HELPERS`` of the ``_cases.py`` of its spec
                            (``HelperTest`` of ``test_pyspec_facts``).
Give a C function a fast    An ``@inline`` function next to it in its
path in generated code      spec: ``if <test>: return <value>``, then
                            ``return f(...)``; spec bodies call it instead
                            of ``f`` (``PyNumber_AsSsize_t_fast``, below).
                            Never in the reference of ``f``.
Add or rename a slot        ``def __len__(self, /): ...`` in the class,
                            no docstring, with ``@c_name(...)`` if the C
                            function is not ``<class>_<slot>`` without the
                            slot's prefix (``bytes_repr``); write the C
                            function with the slot's typedef.
Give the optimizer the      ``@native`` on the slot, with its Python
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
Share a stringlib method    ``from Objects.stringlib.pyspec import
                            transmogrify``, then ``center =
                            transmogrify.B.center`` in the
                            class; the method is declared once, in
                            ``Objects/stringlib/pyspec/transmogrify.py``.
                            ``critical_section(transmogrify.B.center)``:
                            clinic generates ``<class>_center()``, which
                            calls it in a critical section on self.
Declare a method like       ``strip = bytesobject.bytes.strip`` (after
another type's              ``from Objects.pyspec import bytesobject``)
                            and the block ``bytearray.strip`` in the C
                            file: a
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
                            (the latter in a checkout that holds other
                            worktrees: ``make clinic`` would regenerate
                            theirs too); with ``--dry-run``, clinic only
                            says what is out of date
Test                        ``./python -m test test_clinic
                            test_pyspec_facts test_pyspec_catalog`` (after
                            rebuilding Python if the spec changed)
Validate a change for       ``./python Tools/clinic/pyspec_review.py``
review                      (MIGRATING.rst, "Validating a change")
Change a C function a spec  Keep its Python reference in step: what it
calls                       returns and raises, which Python code it may
                            run (``calls()``, ``runs_python()``) and which
                            native functions it calls.
                            ``test_pyspec_catalog`` reads the C and fails
                            on a call that may run Python code the
                            reference does not account for, or on a call
                            the reference makes that the C does not.
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
* ``@native``: the function is implemented natively (C written by
  hand) and the body is its Python reference, which describes it and is
  never compiled (below); on a clinic method, clinic generates what it
  does for ``...``.
* ``@native(facts=False)``: implemented natively too, and the body is
  its pure-Python implementation, which only the model runs ("Pure
  Python", below).  Clinic, the facts, the checker and ``HelperTest``
  read the function as ``...``; a Python reference may call it as part
  of the model of a value.
* ``@inline``:a top-level function whose body clinic generates into
  each caller, never as a C function of its own: a fast path (below).
* ``@getter``, ``@setter`` (and ``@deleter`` after ``@setter``): an
  accessor; its block in the C file starts with the same decorator.
* ``@c_name("prefix")`` on a class: the prefix of its generated tables
  (``striter_methods``); the default is the class name.

The spec language
-----------------

A spec is Python, and may say anything a type needs.  Clinic reads it
with the ``ast`` module; the tests run it.

* A class body holds a docstring, ``def``\ s, shared methods
  (``x = module.Class.x``, or ``Class.x`` of the same spec, possibly
  wrapped in ``critical_section(...)`` or ``c_name(...)(...)``), the
  fields of its C struct (``it_index: Py_ssize_t``, ``ob_sval:
  'char[]'`` for the bytes an object holds: the struct stays C, the
  model allocates them, "Pure Python") and ``pass``.  Two methods with
  the same signature are two full ``def``\ s: Python has no clones.
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
  anything.  With ``@native`` the body is the Python reference of
  native code (below), never compiled.  Any other body is generated as
  C (with ``@inline``, into each caller), and must be in the lowered
  subset.
* A spec imports the functions of another spec, and the specs whose
  methods it shares, by the path of that spec from the source root:
  ``from Objects.pyspec.abstract import PyNumber_AsSsize_t``, ``from
  Objects.stringlib.pyspec import transmogrify``.  It imports the names
  of ``Tools/clinic/libclinic/pyspec/runtime.py`` it uses from there
  (``from libclinic.pyspec.runtime import NULL, isinstance``);
  ``isinstance()`` and ``iter()`` have their C meaning only when
  imported, and a spec that uses them without the import fails to load
  as Python.

The lowered subset
------------------

What clinic generates as C, and what the facts follow, is one explicit
part of the language, checked by ``Tools/clinic/libclinic/pyspec/subset.py``
before anything else.  Outside it, clinic says where and what:
``foo.py:12: error: bytes.__new__(): while loop '...' is expressible, but
not lowered to C yet``.  Keep the C by hand then: ``...``, or
``@native`` with the body as its Python reference.

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
                          E:`` (or ``except (E1, E2):``) ... ``else:``
                          ...; ``try:`` ...
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
Calls                     C functions by name (``@native``, or
                          ``...``), ``@inline`` functions, other spec
                          functions (``f(...)``, ``T.meth(...)``),
                          ``iter(x)``, ``len(x)`` of an exact list or
                          tuple, a local object or type with at most one
                          argument (``f()``, ``cls(x)``)
``@inline`` body          ``if <condition>: return <value>`` (any
                          number), then ``return <value>``: conditions
                          and values (a call, or a value) as above; its
                          parameters and result of any C type
========================  ================================================

In a Python reference (``@native``), the facts follow the same
control flow; any other code is the model of a value and must have no
effect (no primitive, no call of a C or spec function, no ``return`` or
``raise``) where they cannot see it, e.g. in a ``while`` loop or in the
argument of a call.  A reference that does has the worst facts: any
result, may raise anything, may run Python code.  So does a function
about which nothing is known.

Extending the lowered subset
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Adding a construct is a local change, in
``Tools/clinic/libclinic/pyspec/``:

1. accept it in ``subset.py``, in the method of ``Lowered`` for its kind
   of node (``signature()``, a statement method, ``condition()``,
   ``value()``, ``call()``; ``Analysed`` for references).  The kinds of
   statements are ``subset.Kind``; every pass over statements is a
   ``subset.Walker``, with a method per kind.  A new kind of statement
   is a new ``Kind`` and a method
   in each walker: ``facts.Analyzer``,
   ``partial_eval.Evaluator`` and ``emit.FunctionLowering`` (a kind
   without a method goes to ``other()``: the worst facts, and an error
   in the emitter);
2. give its effects in ``facts.py`` if it has any (anything it does not
   know is the worst case);
3. evaluate it in ``partial_eval.py`` if the facts of a call site decide
   it; what the evaluator decides for the emitter is a typed mark on the
   node (``marks.py``);
4. lower it in ``emit.py`` to the nodes of ``ir.py``; an operation that
   each language writes its own way is a new node, written by
   ``c_backend.py``;
5. add its row to the table above, and a test to ``PyspecLanguageTest``
   of ``Lib/test/test_clinic.py`` (its message moves from the
   "not lowered" cases to a generated-C case).

The generated C and other languages
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The C of a spec body is made in passes that share one
``context.Context``: the body is checked (``subset.py``), partially
evaluated for the facts of each entry (``partial_eval.py``, with the
facts of ``facts.py``), lowered (``emit.py``) to a small typed form
(``ir.py``), and written out by ``c_backend.CBackend``.  The lowered
form has made every decision that does not depend on the language: the
C types of the locals, which references are owned and where each is
released (``Release``, NULL or not), the error check of each call
(``Failed`` and its ``Convention``), how a loop iterates (``ForIndex``
over a tuple, a list, or a list in its critical section; ``ForIter``).
Calls name functions of the C API.

Each group of lines of the spec is named in the C before its code,
``/* Objects/pyspec/bytesobject.py:90 */``, and the clinic block of a
spec method says where its impl is generated.

Another language plugs in at two places, neither of which has an
implementation yet: a backend, for spec bodies generated in that
language (here), and a checker, for native functions written in it
("Checking a reference against its native code", below).  A backend
for another language (Rust, say) would implement the methods
of ``CBackend`` for it: ``function()`` (an ``extern "C"`` function with
the C signature of the entry, which clinic's C parsing code calls),
``prototype()``, ``comment()``, ``guard()`` (``#if``), the statements
and expressions of ``ir.py`` -- in particular those the C API has only
as macros or inline functions: ``TypeCheck`` (``PyBytes_CheckExact()``),
``HasSlot``, ``NewRef``/``Release`` (reference counts), the loops of
``ForIndex`` (``PyTuple_GET_ITEM()``, ``_PyList_ITEMS()``), ``Locked``
(the critical section), ``TypeName`` -- and write to its own output
file.  The partial evaluation, the facts, the lowering and the call
tables of the tier-2 optimizer (C data of the interpreter, from
``call_table.py``) stay as they are.

Pure Python
-----------

A spec is *Python which is lowered* when running its Python would
behave exactly as the C does: the C is the same program, lowered (by
hand, or by clinic) for speed.  For a type that means:

1. every method and slot of the class, and every function its bodies
   call, has a Python body: generated (lowered by clinic), ``@native``
   (a reference the facts read) or ``@native(facts=False)`` (a
   pure-Python implementation only the model runs); no ``...`` is left;
2. the bodies are *non-circular*: they compute with the host types no
   spec describes (``int``, ``str``, ``tuple``, ``list``, ``slice``, the
   exceptions), call other spec functions, and name a type a spec
   describes (``bytearray``) or ``memoryview`` only as a type, never
   calling it or reading its attributes; the classes of the spec stand
   for themselves, so ``bytes(...)`` in a body is the model's;
3. what Python cannot say is a *machine primitive*
   (``Tools/clinic/libclinic/pyspec/machine.py``): ``ob_alloc(tp,
   items)`` and ``ob_items(o)`` (the object and the bytes it holds),
   ``ob_new(tp)`` (an object with its fields), ``buffer_items(o)`` and
   ``buffer_export(o, flags)`` (the buffer protocol), ``hash_secret()``,
   ``has_slot(tp, slot)`` (what abstract.c's dispatch looks at) and
   ``from_host(tp, v)`` (a value from host code the model does not
   describe, a codec).  Each has a Python meaning and stands for C; on
   the host (the tests of the references) a primitive reads the builtin;
4. the fields of the C struct are declared in the class (``it_index:
   Py_ssize_t``; ``ob_sval: 'char[]'``: the bytes, ``ob_items()``);
5. the C types the template files are compiled for are parameters: a
   method of ``Objects/stringlib/pyspec/`` runs with ``B`` and
   ``STRINGLIB_NEW`` of the spec that shares it (``STRINGLIB_NEW =
   new_bytes`` in bytesobject.py).

The *model* (``Tools/clinic/libclinic/pyspec/model.py``) runs a spec so:
Python classes built from it, named like the builtins, whose methods
run the bodies through clinic's argument parsing (from the signature and
the converters) and models of the descriptors and slot wrappers of
``descrobject.c`` and ``typeobject.c``.  A method still ``...`` calls
the C (it is *delegated*, and circular).  Nothing of this is compiled:
clinic's output, the facts and the call tables do not change.

``./python Tools/clinic/pyspec_parity.py model`` compares the model
with the C type, line by line, with the parity tool's probes (the host
objects of the pool become model objects), and says which lines differ.
Left out: the type object (flags, sizes, ``help()``, the C layout),
``sys.getsizeof()``, and pickle and copy, which find the builtin by
identity.  Reported apart, the limits of a Python class: ``__mul__`` is
both the operator and ``sq_repeat``'s slot wrapper; a heap type always
has ``tp_as_sequence``; ``bytearray % b`` tests ``PyBytes_Check()``.
``ModelTest`` of ``test_tools.test_pyspec_parity`` fails when a method
with a Python body diverges, and when a body is circular
(``model.check_circular()``).

bytes and its iterator are the example: every method and slot but
``__mod__``/``__rmod__`` has a Python body (with
``Objects/pyspec/bytes_methods.py``, ``longobject.py``, and
``Python/pyspec/pyhash.py``, SipHash-1-3, and ``pystrhex.py``).  The
design, the numbers and how this relates to PEP 399's pure-Python
modules are in ``pyspec-notes/reports/phase5_pure_python.md`` and
``pyspec-notes/drafts/CONCEPT.md`` section 7.3.

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

Native functions: ``@native``
-----------------------------

A function implemented natively that spec bodies call, C written by
hand today (another language, Rust say, later), is a function of the
spec of its file, decorated ``@native``: the native code is the
authority, and the body is its *Python reference*, which describes it.
The reference runs when a spec runs as Python (the difftest), and
Argument Clinic reads it for the facts of each call: the exact type of
the result, whether it can raise, and whether it may run Python code,
for the arguments the call knows about.  It is never compiled, not even
in part.  Its annotations are the C types of its interface, the one
generated code calls it through (``object``, ``str``, ``int``,
``Py_ssize_t``, ``None``, or the C type as a string,
``'PyTypeObject *'``)::

    @native
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
object is a new reference, arguments are borrowed.  A model uses the
parameters of the interpreter it runs in (``sys.int_info.bits_per_digit``
in ``_PyLong_IsCompact()``), not a constant of one build.

A C struct kept in a local, such as the ``bytes_appender`` of
``bytesobject.c``, is the result of a function whose return annotation
is the struct: it initializes the local in place, and the body releases
it in a ``finally`` clause.

Fast paths: ``@inline``
~~~~~~~~~~~~~~~~~~~~~~~

Where generated code has a cheaper way to the result of a native
function for some arguments (a compact int read inline instead of a call
of ``PyNumber_AsSsize_t()``), the fast path is generated code of its
own, written once as an ``@inline`` function in the spec of the native
function, which spec bodies call instead of it::

    @inline
    def PyNumber_AsSsize_t_fast(o: object, exc: object) -> Py_ssize_t:
        """PyNumber_AsSsize_t(o, exc), read inline for a compact int."""
        if (type(o) is int or type(o) is bool) and _PyLong_IsCompact(o):
            return _PyLong_CompactValue(o)
        return PyNumber_AsSsize_t(o, exc)

Its body is fast paths, ``if <test>: return <value>``, then ``return
<value>`` (the lowered subset); its annotations are C types, as for
``@native``.  Clinic generates it into every statement that calls it and
never as a C function of its own: a test the facts of the call decide
selects or drops its path (for an exact int, only
``_PyLong_IsCompact(o)`` is left), and one they do not is tested at run
time.  The generated code never assumes that the native function has
the fast path, and the reference of the native function describes only
the native code, so the two cannot disagree.  In a loop over a tuple (or
a list, in its critical section) that writes to a buffer sized for every
item, the first path of the ``@inline`` call writing the buffer is taken
without its test (``bytes_appender_append_fast()``; "Capacity" in
``Tools/clinic/libclinic/pyspec/partial_eval.py``).

Native code that needs the logic of a fast path calls the same code
instead of repeating it: the pieces are native functions that both use
(``bytes_appender_append()`` is ``bytes_appender_has_room()`` and
``bytes_appender_append_unchecked()`` in C, as its fast path is in the
spec).  Logic that exists only as a spec body would be generated as a
``static inline`` function of a header the native code includes; no
native code needs one yet.

Checking a reference against its native code
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* ``HelperTest`` of ``test_pyspec_facts`` calls the native function
  directly with the ``HELPERS`` of the ``_cases.py`` of its spec,
  compares it with the reference, and checks the derived facts, with
  debug builds aborting when Python code runs where the facts say none
  does.
* The checker of the language of the native file reads the native code
  (``NATIVE_CHECKERS`` in
  ``Tools/clinic/libclinic/pyspec/disconnects.py``, by extension): every
  call that may run Python code is accounted for by the reference (a
  call of the same function, a ``calls()`` of the special method it
  invokes, or ``runs_python()``); a reference that cannot fail has
  native code that calls nothing that can; and the native code calls
  every native function the reference calls.  The C checker,
  ``CChecker``, uses the lexer and the escape analysis of the cases
  generator (``Tools/cases_generator/``); ``test_pyspec_catalog`` holds
  its disconnects to a ratchet (``c_calls``).

A native file in another language needs only a checker of its own: a
subclass of ``NativeChecker`` registered in ``NATIVE_CHECKERS`` for its
extension (``.rs``), with ``function(name)``, the code of a function of
the file; ``calls(code)``, the functions that code calls;
``escaping_calls(code)``, those that may run Python code;
``runs_no_python(name)``, the calls audited to run none; and
``special_method(name)``, the special method whose Python code a call
runs (``PyObject_GetIter()`` runs ``__iter__``), and a ratchet
dimension of its own next to ``c_calls``.  The spec, the reference, the
facts, the fast paths and ``HelperTest`` stay as they are: the reference
describes the function whatever its language, and generated code calls
it through its C interface.  No checker for another language exists
yet.

Errors
------

Clinic reports every error as ``path:line: error: message``, at the line
of the spec when the error is in the spec (in the spec it was written
in, for code copied from another).  A spec error has a kind
(``SpecErrorKind`` in ``Tools/clinic/libclinic/errors.py``): not valid
in the spec language; expressible, but not lowered yet; in the lowered
subset, but a use the emitter cannot lower (a local that changes type);
or a disagreement between the spec and the blocks of the C file.  The common messages and
what to do about each are in "Troubleshooting" of `MIGRATING.rst
<MIGRATING.rst>`_.  The implementation is in
``Tools/clinic/libclinic/pyspec/`` (its ``__init__.py`` lists the
modules).

To migrate a C file to a spec, and to decide whether a function is
worth a spec body, see `MIGRATING.rst <MIGRATING.rst>`_.

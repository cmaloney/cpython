Specs: C types declared in Python
=================================

``Objects/pyspec/foo.py`` is the *spec* of ``Objects/foo.c``: its types
written as ordinary Python, in the style of a typeshed stub.  Argument
Clinic reads it when it processes ``foo.c``.  A method of ``class T``
is the clinic function ``T.meth``.  What clinic outputs is opt-in, by
decorator: ``@ac.stub`` means the C impl is written by hand, as with
plain Argument Clinic; ``@ac.generate`` means the body is generated as C
(if it is in the lowered subset, below); a def or class without one
outputs nothing.  The same holds in every directory:
``<dir>/pyspec/<stem>.py`` is the spec of ``<dir>/<stem>.c`` (or of the
header ``<dir>/<stem>.h``: ``Objects/stringlib/pyspec/`` holds the
models of the C functions of the templates that bytes and bytearray
share), found by one glob
(``Tools/clinic/libclinic/pyspec/specfiles.py``).  A spec body calls the
C functions of other files by their module
(``abstract.PyNumber_AsSsize_t(...)``); each one it calls is declared in
the spec of its own file (``Objects/pyspec/abstract.py`` for
``Objects/abstract.c``, ``Python/pyspec/errors.py``,
``Include/cpython/pyspec/longintrepr.py``,
``Objects/pyspec/bytes_methods.py``...), ``@ac.stub(optimizer_info=True)``,
with its Python reference (below).  Every piece of code that runs has
one source: native code (C written by hand) that a reference only
describes, or a spec body that clinic generates.

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
                                       impl, as with plain Argument
                                       Clinic; clinic inserts a missing
                                       one
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
Add a C method              A ``def`` with ``@ac.stub`` and body ``...``
                            in the spec, at its place in the method table
                            (the class body order is ``T.__dict__``
                            order); run clinic.  It inserts the block
                            ``/*[clinic input]`` ``T.meth``
                            ``[clinic start generated code]*/`` in
                            ``foo.c`` after that of the method before it,
                            with a placeholder impl that raises
                            ``NotImplementedError``: write the impl there.
                            Clinic writes the head and the table; for a
                            method table written in C (a class without
                            ``@ac.generate``, or with ``methods=False``)
                            it warns to add ``T_METH_METHODDEF`` to it.
Add a spec-body method      The same ``def`` with ``@ac.generate`` and a
                            body in the lowered subset (below); clinic
                            inserts the same one-line block (no C body);
                            add cases to ``foo_cases.py``.
Keep a method's C, with     ``@ac.stub(optimizer_info=True)`` on the ``def``:
its Python reference        any signature, any Python body; clinic output
                            is that of ``...``.
Give a C method its pure    ``@ac.stub`` on the ``def`` and the Python as
Python                      its body ("Pure Python", below); clinic
                            output is that of ``...``; check it with
                            ``./python Tools/clinic/pyspec_parity.py
                            model``.
Add an accessor             ``@ac.stub @ac.getter def attr(self) ->
                            ac.conv:`` (its docstring) and ``@ac.stub
                            @ac.setter def attr(self, value:
                            ac.object):``; clinic inserts the blocks
                            ``@getter`` ``T.attr`` and ``@setter``
                            ``T.attr`` in ``foo.c``, with placeholder
                            impls.  ``tp_getset`` stays in C: clinic warns
                            to add ``T_ATTR_GETSETDEF`` to it.
Call a C function from a    Call it by its module, ``abstract.f(...)``
spec body                   (a function of the same spec: by name).
                            Declare it, if no spec does yet, in the spec
                            of its C file, with
                            ``@ac.stub(optimizer_info=True)`` and its Python
                            reference (below), and import that spec by
                            its path from the source root (``from
                            Objects.pyspec import abstract``); add its
                            inputs to ``HELPERS`` of the ``_cases.py`` of
                            its spec (``HelperTest`` of
                            ``test_pyspec_facts``).
Give a C function a fast    An ``@ac.inline`` function next to it in its
path in generated code      spec: ``if <test>: return <value>``, then
                            ``return f(...)``; spec bodies call it instead
                            of ``f`` (``PyNumber_AsSsize_t_fast``, below).
                            Never in the reference of ``f``.
Add or rename a slot        ``@ac.stub def __len__(self, /): ...`` in the
                            class, no docstring; the C function is
                            ``<prefix>_<slot>`` without the slot's prefix
                            (``bytes_repr`` for ``tp_repr``), else give
                            it: ``@ac.stub("f")``; a dunder of several
                            slots names them, ``@ac.stub(slots=
                            ["mp_length", "sq_length"])``, or with their
                            C names, ``@ac.stub(mp_length="f")``; write
                            the C function with the slot's typedef.
Give the optimizer the      ``@ac.stub(optimizer_info=True)`` on the slot,
facts of a slot             with its Python reference
                            (``bytes.__getitem__``); add inputs to
                            ``HELPERS`` in ``foo_cases.py``.  Clinic puts
                            its facts in the call table of the class
                            (whether or not the class generates its
                            tables); a uop that does what the slot does
                            takes its result facts from
                            ``_PySpec_FindSlot()`` with
                            ``_PySpec_SLOT(<member>)`` (see
                            ``_BINARY_OP_SUBSCR_BYTES_INT``) and is listed
                            in ``SLOT_USES`` of ``foo_cases.py``.
Add a hand-written          ``@ac.stub(METH_O="f")``, or ``METH_NOARGS``,
PyCFunction                 ``METH_VARARGS``, ``METH_FASTCALL``: the
                            parameters say which (``(self, /)``,
                            ``(self, arg, /)``, ``(self, /, *args)``;
                            ``**kwargs`` adds ``METH_KEYWORDS``);
                            ``@classmethod``, ``@staticmethod``,
                            ``@ac.coexist`` add ``METH_CLASS``,
                            ``METH_STATIC``, ``METH_COEXIST``.  The
                            docstring is ``__doc__`` as is, after the
                            signature of ``@ac.text_signature``.  A slot
                            with a method entry too (list's
                            ``__getitem__``): its slots and
                            ``METH_O="f"`` in ``@ac.stub``, and
                            ``@ac.coexist``.
Share a stringlib method    ``center = ac.stub("stringlib_center")`` in
                            the class: the method is that C function of
                            a header the C file ``#include``\ s.  Clinic
                            reads the rest from the C: a clinic function
                            of the header (``B.center as
                            stringlib_center``, its parameters and
                            docstring, in ``transmogrify.h``) gives its
                            ``*_METHODDEF``; a PyCFunction written by
                            hand (``ctype.h``) its calling convention,
                            from its parameters (``PyObject
                            *Py_UNUSED(ignored)``: ``METH_NOARGS``;
                            where they do not say, ``(PyObject *self,
                            PyObject *arg)``, write
                            ``ac.stub(METH_O="f")``), and its docstring
                            is that of its model.  ``ac.stub(
                            "stringlib_center", critical_section=True)``:
                            clinic generates ``<class>_center()``, which
                            calls it in a critical section on self.
                            The model of the function is the def of its
                            name in the spec of the header
                            (``Objects/stringlib/pyspec/transmogrify.py``,
                            ``@ac.stub def stringlib_center(self, width,
                            fillchar=b' ', /)``), with the parameters of
                            the C (clinic checks them) and a pure-Python
                            body.
Declare a method like       ``strip = bytesobject.bytes.strip`` (after
another type's              ``from Objects.pyspec import bytesobject``)
                            and the block ``bytearray.strip`` in the C
                            file: a
                            clinic function of this class with the other's
                            parameters, docstring and decorators; wrap it
                            (``ac.critical_section(...)``) to add
                            ``@critical_section``.  A hand-written
                            PyCFunction with another's docstring:
                            ``m = ac.stub(METH_NOARGS="f")(T.m)``.
                            (Not ``ac.stub("bytes_strip")``: that names
                            a C function that is the method, where this
                            declares a new clinic function, with its
                            own impl.)
Declare a new type          A class in the spec (its docstring, methods
                            and dunders) with ``@ac.generate``, a
                            ``class T "CType *" "&T_Type"`` directive in
                            ``foo.c``, and the type in ``TYPES`` of
                            ``foo_cases.py``; write its ``PyTypeObject``
                            in C after the include of
                            ``clinic/foo_pyspec.c.h``, naming ``T_doc``,
                            ``T_methods``, ``T_as_number``...
                            (``@ac.generate(prefix="x")`` changes ``T``).
                            ``test_clinic`` checks that the slots it
                            fills are the dunders of the class.
Move part of a type         A class without ``@ac.generate``, with only
                            the defs that move (``@ac.generate def
                            __new__``, a slot with its reference): no
                            table is generated, the C keeps its
                            ``PyTypeObject`` and tables, and its other
                            methods stay plain Argument Clinic blocks;
                            ``test_clinic`` checks that the class's
                            methods and slots are the type's.
Regenerate                  ``make clinic``, or
                            ``./python Tools/clinic/clinic.py Objects/foo.c``
                            (the latter in a checkout that holds other
                            worktrees: ``make clinic`` would regenerate
                            theirs too); with ``--dry-run``, clinic only
                            says what is out of date
Test                        ``./python -m test test_clinic
                            test_pyspec_facts test_pyspec_catalog
                            test_tools.test_pyspec_parity`` (after
                            rebuilding Python if the spec changed; the
                            last runs the parity record and the model)
Validate a change for       ``./python Tools/clinic/pyspec_review.py``
review                      (MIGRATING.rst, "Validating a change")
Change a C function a spec  Keep its Python reference in step: what it
calls                       returns and raises, which Python code it may
                            run (``rt.calls()``, ``rt.runs_python()``) and
                            which native functions it calls.
                            ``test_pyspec_catalog`` reads the C and fails
                            on a call that may run Python code the
                            reference does not account for, or on a call
                            the reference makes that the C does not.
==========================  ===============================================

Decorators
----------

What clinic outputs for a def or class is opt-in: a def without
``@ac.generate``, ``@ac.stub`` or ``@ac.inline`` outputs nothing.  The
decorators are Argument Clinic's, from the group ``ac`` ("The spec
language", below); ``@classmethod`` and ``@staticmethod`` are Python's.

* ``@ac.generate``: clinic generates the C from the body (the lowered
  subset, below): a clinic method's impl, or a top-level C function of
  the name of the function.  ``@ac.generate("x")``: the C basename of a
  method (clinic's ``as x``); the default is clinic's, ``T_meth``, ``T``
  for ``T.__new__``, ``T___init__``.
* ``@ac.stub``: the clinic parts (signature, converters, docstring,
  clinic decorators) of C written by hand.  The body is ``...``
  (nothing is known of the C: a call of it may do anything), or its
  pure-Python implementation, which only the model runs ("Pure Python",
  below): clinic, the facts, the checker and ``HelperTest`` read it as
  ``...``, and a Python reference may call it as part of the model of a
  value.  Its options:

  * ``@ac.stub("x")``: the C name, when it is not the default: clinic's
    for a method (as for ``@ac.generate``); for a slot, the class prefix
    and the slot without its ``tp_``, ``nb_``, ``sq_``, ``mp_``, ``am_``
    or ``bf_`` (``bytes_repr`` for ``tp_repr``, ``bytes_length`` for
    ``mp_length``).  A top-level function has its name as its C name.
  * ``@ac.stub(slots=["mp_length", "sq_length"])``: the slots of a
    dunder that several slots can implement, each with its default name;
    ``@ac.stub(mp_subscript="f", sq_item="g")``, with their C names (the
    two forms combine).  A dunder that shares its slot with another
    (``__rmod__`` with ``__mod__``) names none.
  * ``@ac.stub(METH_NOARGS="f")``, ``METH_O``, ``METH_VARARGS``,
    ``METH_FASTCALL``: a hand-written PyCFunction entry
    (``Spec.pycfunction()`` in ``frontend.py``).
  * In a class body, ``meth = ac.stub("f")``: the C function f of a
    header the C file includes is the method; clinic reads its
    signature, calling convention and docstring from the C, and its
    model is the def f of the spec of the header ("Share a stringlib
    method", above; ``Tools/clinic/libclinic/pyspec/cfunctions.py``).
    ``critical_section=True`` calls it in a critical section on self;
    ``ac.stub(METH_O="f")`` gives the calling convention of a
    PyCFunction written by hand whose parameters do not.
  * ``@ac.stub(optimizer_info=True)``: the body is information for the
    optimizer: the Python reference of the C, never compiled ("Native
    functions", below).  The facts read from it what the C returns (its
    exact type), what it raises, whether it may fail, and which Python
    code it may run (``rt.calls()``, ``rt.runs_python()``); generated
    callers and the call table rely on them, so the C checker,
    ``test_pyspec_catalog`` and ``HelperTest`` check it against the C.
    Without it, a body is only the model's.  On a clinic method, clinic
    generates what it does for ``...``.

* ``@ac.inline``: a top-level function whose body clinic generates into
  each caller, never as a C function of its own: a fast path (below).
* The clinic decorators, written with the same name and arguments:
  ``@ac.permit_long_summary``, ``@ac.text_signature("(...)")``,
  ``@ac.critical_section``, ``@ac.vectorcall``, ``@ac.disable(...)``...
  They do nothing when the spec runs as Python.
* ``@ac.getter``, ``@ac.setter`` (and ``@ac.deleter`` after
  ``@ac.setter``), with ``@ac.stub``: an accessor; its block in the C
  file starts with the same decorator.
* A top-level def without a decorator is Python only: a helper that the
  model and the Python references may call, and a generated body may
  not.  A method without ``@ac.stub`` or ``@ac.generate`` is an error.
* On a class, ``@ac.generate`` generates its tables into
  ``foo_pyspec.c.h``: its docstring (``<prefix>_doc``), its method table
  (``<prefix>_methods``) and its slot sub-tables (``<prefix>_as_number``,
  ...).  ``@ac.generate(prefix="striter", doc=True, methods=True,
  slots=True)`` gives the prefix (the default is the class name) and
  which tables (all by default).  A class without it declares what it
  has (the clinic input of its methods, the facts of its slots) and the
  C keeps its own tables: part of a type can move to the spec while the
  rest stays plain Argument Clinic.

The spec language
-----------------

A spec is Python, and may say anything a type needs.  Clinic reads it
with the ``ast`` module; the tests run it.

* A spec names what it takes from the tooling by group, ``from
  libclinic.pyspec import ac, rt, machine``:

  * ``ac``, Argument Clinic: every converter and return converter
    (``ac.object``, ``ac.Py_ssize_t``, ``ac.str(c_default="NULL")``,
    ``ac.slice_index(accept={int, ac.NoneType}, c_default='0')``, a
    converter of the ``[python input]`` block of the C file such as
    ``ac.bytesvalue``), the names clinic evaluates their options with
    (``ac.NoneType``, ``ac.robuffer``...), and the decorators (above).
    Run as Python, a converter checks the names of its options as
    clinic does, and raises ``TypeError`` on a typo
    (``Tools/clinic/libclinic/pyspec/ac.py``);
  * ``rt``, the primitives with a C meaning
    (``Tools/clinic/libclinic/pyspec/rt.py``): ``rt.NULL``,
    ``rt.PY_SSIZE_T_MAX``, ``rt.isinstance`` (the real type),
    ``rt.iter`` (``PyObject_GetIter()``), ``rt.tp_name`` and
    ``rt.fqname`` (type names in messages), and the primitives of a
    Python reference, ``rt.exact``, ``rt.unknown``, ``rt.calls`` and
    ``rt.runs_python`` ("Native functions", below).  A bare
    ``isinstance()`` or ``iter()`` is Python's, not the C's: clinic
    rejects it, and so does the spec run as Python;
  * ``machine``, the object memory of pure-Python bodies
    (``machine.ob_items(x)``; "Pure Python", below).

* A spec imports the specs whose functions it calls, and whose methods
  it declares like its own, by their path from the source root: ``from
  Objects.pyspec import abstract``, ``from Python.pyspec import errors
  as pyerrors`` (``as`` when the name is taken, here by a parameter).
  It calls a function of another spec by its module,
  ``abstract.PyNumber_AsSsize_t(o, exc)`` (and so names a constant,
  ``bytes_methods.SPACE``), and a function of its own by name.
* A class body holds a docstring, ``def``\ s, the C functions of headers
  that are methods (``x = ac.stub("f")``, options ``critical_section=
  True`` and ``METH_O="f"`` in place of the name), methods declared like
  another's (``x = module.Class.x``, or ``Class.x`` of the same spec,
  possibly wrapped in ``ac.critical_section(...)`` or
  ``ac.stub(...)(...)``), the
  fields of its C struct (``it_index: ac.Py_ssize_t``, ``ob_sval:
  'char[]'`` for the bytes an object holds: the struct stays C, the
  model allocates them, "Pure Python") and ``pass``.  Two methods with
  the same signature are two full ``def``\ s: Python has no clones.
* A signature is any signature clinic can state: positional-only,
  positional-or-keyword and keyword-only parameters, ``*args``,
  ``**kwargs``, any converter (the annotation, ``ac.<converter>``, with
  its options: ``ac.object(c_default="NULL")``, ``ac.str(accept={str,
  ac.NoneType})``, ``c_param='x'`` for clinic's ``name as x``), any
  default (``()``, ``10``, ``None``, ``rt.NULL``), ``self:
  ac.self(type="...")``, ``cls: ac.defining_class``, a return converter
  (``-> ac.Py_ssize_t``), ``@classmethod``, ``@staticmethod``,
  ``__new__``, ``__init__``, accessors (``@ac.getter``, ``@ac.setter``)
  and every clinic decorator.  Clinic reads the converters and defaults
  as written, less ``ac.`` and ``rt.``: its output is plain clinic's,
  byte for byte.  Not expressible yet: optional groups (``[ ]``), the
  ``[from X.Y]`` deprecation markers, and module-level clinic functions:
  keep those in plain clinic.
* The annotations of a top-level function are the C types of its
  interface: ``ac.object``, ``ac.str``, ``ac.int``, ``ac.Py_ssize_t``,
  ``None``, or the C type as a string (``'PyTypeObject *'``).
* A body is any Python; its decorator says what it is (above).  With
  ``@ac.generate`` (and ``@ac.inline``, into each caller) it is
  generated as C, and must be in the lowered subset.

The lowered subset
------------------

What clinic generates as C, and what the facts follow, is one explicit
part of the language, checked by ``Tools/clinic/libclinic/pyspec/subset.py``
before anything else.  Outside it, clinic says where and what:
``foo.py:12: error: bytes.__new__(): while loop '...' is expressible, but
not lowered to C yet``.  Keep the C by hand then: ``@ac.stub``, with
``...``, its pure Python, or (``optimizer_info=True``) the body as its Python
reference.

========================  ================================================
Signature                 a top-level function, ``__new__`` (of a type
                          with a row in ``builtin_types.py``), a method
                          or a ``@classmethod``; positional parameters
                          with converter ``ac.object`` or ``ac.str``,
                          default ``rt.NULL``; no
                          ``@ac.critical_section``
Statements                ``if``/``else``; ``x = call(...)``;
                          ``f(...)`` for a C function ``f``; ``return
                          x``, ``return call(...)``, ``return
                          <constant>``; ``raise f(...)`` (a C function
                          setting the exception), ``raise E("...")``,
                          ``raise E(f"...{rt.fqname(type(x))}...")``
                          (also ``rt.tp_name``); ``try: x =
                          call(...)`` ``except E:`` (or ``except (E1,
                          E2):``) ... ``else:`` ...; ``try:`` ...
                          ``finally:`` <calls of C functions>; ``for
                          item in it:`` (no ``else``); ``pass``
Conditions                ``x is [not] rt.NULL``, ``(v := call(...))
                          is [not] rt.NULL``, ``type(x) is [not] K``,
                          ``cls is [not] K``, ``rt.isinstance(x, K)``,
                          ``hasattr(type(x), "__index__")`` (or
                          ``"__buffer__"``), a call of a C function
                          that cannot fail, integer comparisons,
                          ``and``/``or``/``not``; ``K`` a type of
                          ``builtin_types.py``
Values                    names, ``rt.NULL``, types, exception classes,
                          ``bool`` and ``int`` constants; a ``str``
                          constant as the argument of a C function
Calls                     C functions (``@ac.stub``: ``f(...)``, or
                          ``module.f(...)`` of another spec),
                          ``@ac.inline`` functions, other generated
                          spec functions (``f(...)``, ``T.meth(...)``),
                          ``rt.iter(x)``, ``len(x)`` of an exact list or
                          tuple, a local object or type with at most one
                          argument (``f()``, ``cls(x)``)
``@ac.inline`` body       ``if <condition>: return <value>`` (any
                          number), then ``return <value>``: conditions
                          and values (a call, or a value) as above; its
                          parameters and result of any C type
========================  ================================================

In a Python reference (``@ac.stub(optimizer_info=True)``), the facts follow
the same control flow; any other code is the model of a value and must
have no effect (no primitive, no call of a C or spec function, no
``return`` or ``raise``) where they cannot see it, e.g. in a ``while``
loop or in the argument of a call.  A reference that does has the worst
facts: any result, may raise anything, may run Python code.  So does a
function about which nothing is known.

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
   call, has a Python body: generated (``@ac.generate``, lowered by
   clinic), a reference the facts read (``@ac.stub(optimizer_info=True)``) or
   a pure-Python implementation only the model runs (``@ac.stub``); no
   ``...`` is left;
2. the bodies are *non-circular*: they compute with the host types no
   spec describes (``int``, ``str``, ``tuple``, ``list``, ``slice``, the
   exceptions), call other spec functions, and name a type a spec
   describes (``bytearray``) or ``memoryview`` only as a type, never
   calling it or reading its attributes; the classes of the spec stand
   for themselves, so ``bytes(...)`` in a body is the model's;
3. what Python cannot say is a *machine primitive*
   (``Tools/clinic/libclinic/pyspec/machine.py``, the group
   ``machine``): ``machine.ob_alloc(tp, items)`` and
   ``machine.ob_items(o)`` (the object and the bytes it holds),
   ``machine.ob_new(tp)`` (an object with its fields),
   ``machine.buffer_items(o)`` and ``machine.buffer_export(o, flags)``
   (the buffer protocol), ``machine.hash_secret()``,
   ``machine.has_slot(tp, slot)`` (what abstract.c's dispatch looks at)
   and ``machine.from_host(tp, v)`` (a value from host code the model
   does not describe, a codec).  Each has a Python meaning and stands for C; on
   the host (the tests of the references) a primitive reads the builtin;
4. the fields of the C struct are declared in the class (``it_index:
   ac.Py_ssize_t``; ``ob_sval: 'char[]'``: the bytes,
   ``machine.ob_items()``);
5. the C types the template files are compiled for are parameters: a
   function of ``Objects/stringlib/pyspec/`` runs with ``B`` the class
   that names it (``center = ac.stub("stringlib_center")``) and
   ``STRINGLIB_NEW`` of its spec (``STRINGLIB_NEW = new_bytes`` in
   bytesobject.py).

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
with a Python body diverges, and when a body is circular: by its names
(``model.check_circular()``, and ``check_circular_spec()`` for the
bodies of every spec, also one whose model cannot be built yet), and by
what it calls while the probes run (``model.circular_calls()``: a call
of the builtin of a described type from the frame of a spec, under any
name).

bytes and its iterator are the example: 67 of their 69 members, every
method and slot but ``__mod__``/``__rmod__``, have a Python body (with
``Objects/pyspec/bytes_methods.py``, ``longobject.py``, and
``Python/pyspec/pyhash.py``, SipHash-1-3, and ``pystrhex.py``).  On a
debug build ``pyspec_parity.py model`` finds 36,086 of 36,189 compared
lines identical (99.7 %); the 103 others are the limits of a Python
class above, and 889 lines are left out.  Running the model is slow (a
parity run takes about three times as long as for the C; single calls
are 100 to 900 times slower): it is a check and a reference, not a
replacement.  It is also what makes the spec language-neutral: an
implementation in another language, or a pure-Python module paired
with an accelerator in the spirit of PEP 399, would be checked against
the same bodies by the same comparison.  Not yet done: ``%`` (the
parity samples have no format strings), ``bytearray`` (it needs a
mutable-storage primitive, and bodies of its own for the methods it
shares with bytes) and ``mmap`` (protocol logic over an OS primitive,
mapped memory).  ``@critical_section`` does nothing in the model: the
model states single-threaded behaviour, and what free threading
guarantees is a property of the C, checked by the C tests.

Conditional compilation
-----------------------

A spec has no ``#if``: as with plain Argument Clinic, the condition of a
method is where its block is in the C file.

* A method compiled under ``#if``: put its one-line block inside the
  ``#if`` (clinic inserts a missing block under the ``#if`` of the
  ``class`` directive only: move it).  Clinic wraps its generated code (and a spec body in
  ``foo_pyspec.c.h``) in the condition, and defines an empty
  ``*_METHODDEF`` when it is false, so a method table lists it
  unconditionally.
* A signature that depends on ``#if`` (the same method defined twice):
  keep its full clinic blocks in the C file.  In the spec it is only
  ``@ac.stub def meth(self): ...``, its place in a generated method
  table, or absent.  Declaring it in both is an error.
* A slot compiled under ``#if`` stays in a hand-written C sub-table and
  is not declared in the spec.
* The tests skip a method whose block is under an ``#if`` false in this
  build.

Native functions: ``@ac.stub(optimizer_info=True)``
----------------------------------------------

A function implemented natively that spec bodies call, C written by hand
today (another language, Rust say, later), is a function of the spec of
its file, decorated ``@ac.stub(optimizer_info=True)``: the native code is the
authority, and the body is its *Python reference*, which describes it.
The reference runs when a spec runs as Python (the difftest), and
Argument Clinic reads it for the facts of each call: the exact type of
the result, whether it can raise, and whether it may run Python code,
for the arguments the call knows about.  It is never compiled, not even
in part.  Its annotations are the C types of its interface, the one
generated code calls it through (``ac.object``, ``ac.str``, ``ac.int``,
``ac.Py_ssize_t``, ``None``, or the C type as a string,
``'PyTypeObject *'``)::

    @ac.stub(optimizer_info=True)
    def _PyBytes_FromBuffer(x: ac.object):
        """A copy of the buffer of x (in C order)."""
        rt.calls(x, "__buffer__")
        rt.calls(x, "__release_buffer__")
        return rt.exact(bytes, memoryview(x).tobytes())

What plain Python cannot say, a few primitives of ``rt`` say where it
happens:

============================  ============================================
``rt.exact(T, value)``        value is a new object of exactly type T
``rt.unknown(value)``         value is a new object of a type not known
                              exactly
``rt.calls(x, "__name__")``   here the C invokes the special method of
                              ``type(x)``: Python code runs only if that
                              is Python code (for builtin types, the
                              audited table of ``builtin_types.py`` says)
``rt.runs_python()``          here the C may run any Python code
``return rt.NULL``            an absent result, not an error
============================  ============================================

The rest of the reference is the model of the values the C computes: it
has no other effects.  ``raise`` says what the C raises; ``rt.exact()``
and ``rt.unknown()`` may fail with MemoryError, ``rt.calls()`` and
``rt.runs_python()`` may raise anything.  The error check of a call follows:
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

Fast paths: ``@ac.inline``
~~~~~~~~~~~~~~~~~~~~~~~~~~

Where generated code has a cheaper way to the result of a native
function for some arguments (a compact int read inline instead of a call
of ``PyNumber_AsSsize_t()``), the fast path is generated code of its
own, written once as an ``@ac.inline`` function in the spec of the
native function, which spec bodies call instead of it::

    @ac.inline
    def PyNumber_AsSsize_t_fast(o: ac.object, exc: ac.object
                                ) -> ac.Py_ssize_t:
        """PyNumber_AsSsize_t(o, exc), read inline for a compact int."""
        if ((type(o) is int or type(o) is bool)
                and longintrepr._PyLong_IsCompact(o)):
            return longintrepr._PyLong_CompactValue(o)
        return PyNumber_AsSsize_t(o, exc)

Its body is fast paths, ``if <test>: return <value>``, then ``return
<value>`` (the lowered subset); its annotations are C types, as for
``@ac.stub``.  Clinic generates it into every statement that calls it and
never as a C function of its own: a test the facts of the call decide
selects or drops its path (for an exact int, only
``_PyLong_IsCompact(o)`` is left), and one they do not is tested at run
time.  The generated code never assumes that the native function has
the fast path, and the reference of the native function describes only
the native code, so the two cannot disagree.  In a loop over a tuple (or
a list, in its critical section) that writes to a buffer sized for every
item, the first path of the ``@ac.inline`` call writing the buffer is taken
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
  ``Tools/clinic/libclinic/pyspec/native_check.py``, by extension):
  every call that may run Python code is accounted for by the reference
  (a call of the same function, an ``rt.calls()`` of the special method
  it invokes, or ``rt.runs_python()``, which accounts for every call); a
  reference that cannot fail has native code that calls nothing that
  can; and every definition of the native code (each ``#if`` variant)
  calls every native function the reference calls.  The C checker,
  ``CChecker``, uses the lexer and the escape analysis of the cases
  generator (``Tools/cases_generator/``), and counts calls through
  pointers, the macros of the file and the calls in ``assert()``; the
  docstring of ``native_check.py`` says exactly what counts, and what
  it assumes of the release of a reference.  ``test_pyspec_catalog``
  holds its disconnects to a ratchet (``c_calls``).

A native file in another language needs only a checker of its own: a
subclass of ``NativeChecker`` registered in ``NATIVE_CHECKERS`` for its
extension (``.rs``), with ``functions(name)``, the code of each
definition of a function of the file; ``calls(code)``, the functions that code calls;
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

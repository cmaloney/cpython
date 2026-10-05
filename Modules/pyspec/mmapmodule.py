"""The mmap type, written as Python: the spec of Modules/mmapmodule.c.

Argument Clinic reads this file while processing mmapmodule.c (see
Objects/pyspec/README.rst).  Each method of ``class mmap`` is a clinic
function; mmapmodule.c has a one-line block for it (``mmap.mmap.read``)
above its impl, which is written in C by hand (``@ac.stub``).  The class
has no ``@ac.generate``: the method table and the type stay in C.

The spec has no #if.  resize(), __sizeof__(), _protect() and madvise()
exist only on some platforms: their one-line blocks are inside the #if in
mmapmodule.c, which clinic reads as for any block, and the method table
of mmapmodule.c lists their *_METHODDEF unconditionally.
"""

from libclinic.pyspec import ac


class mmap:
    @ac.stub
    @ac.critical_section
    def close(self):
        ...

    @ac.stub
    @ac.critical_section
    def find(self, view: ac.Py_buffer, start: ac.object = None,
             end: ac.object = None, /):
        ...

    @ac.stub
    @ac.critical_section
    def rfind(self, view: ac.Py_buffer, start: ac.object = None,
              end: ac.object = None, /):
        ...

    @ac.stub
    @ac.critical_section
    def flush(self, offset: ac.Py_ssize_t = 0, size: ac.Py_ssize_t = -1, /, *,
              flags: ac.int = 0):
        ...

    @ac.stub
    @ac.critical_section
    def madvise(self, option: ac.int, start: ac.Py_ssize_t = 0,
                length: ac.object(c_param='length_obj') = None, /):
        ...

    @ac.stub
    @ac.critical_section
    def move(self, dest: ac.Py_ssize_t, src: ac.Py_ssize_t,
             count: ac.Py_ssize_t(c_param='cnt'), /):
        ...

    @ac.stub
    @ac.critical_section
    def read(self,
             n: ac.object(converter='_Py_convert_optional_to_ssize_t',
                       type='Py_ssize_t', c_default='PY_SSIZE_T_MAX',
                       c_param='num_bytes') = None,
             /):
        ...

    @ac.stub
    @ac.critical_section
    def read_byte(self):
        ...

    @ac.stub
    @ac.critical_section
    def readline(self):
        ...

    @ac.stub
    @ac.critical_section
    def resize(self, newsize: ac.Py_ssize_t(c_param='new_size'), /):
        ...

    @ac.stub
    @ac.critical_section
    def seek(self, pos: ac.Py_ssize_t(c_param='dist'),
             whence: ac.int(c_param='how') = 0, /):
        ...

    @ac.stub
    def seekable(self):
        ...

    @ac.stub
    @ac.critical_section
    def set_name(self, name: ac.str, /):
        ...

    @ac.stub
    @ac.critical_section
    def size(self):
        ...

    @ac.stub
    @ac.critical_section
    def tell(self):
        ...

    @ac.stub
    @ac.critical_section
    def write(self, bytes: ac.Py_buffer(c_param='data'), /):
        ...

    @ac.stub
    @ac.critical_section
    def write_byte(self, byte: ac.unsigned_char(c_param='value'), /):
        ...

    @ac.stub
    @ac.critical_section
    def __enter__(self):
        ...

    @ac.stub
    @ac.critical_section
    def __exit__(self, exc_type: ac.object, exc_value: ac.object,
                 traceback: ac.object, /):
        ...

    @ac.stub
    @ac.critical_section
    def __sizeof__(self):
        ...

    @ac.stub
    @ac.critical_section
    def _protect(self, flNewProtect: ac.unsigned_int(bitwise=True),
                 start: ac.Py_ssize_t, length: ac.Py_ssize_t, /):
        ...

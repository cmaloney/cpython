"""The mmap type, written as Python: the spec of Modules/mmapmodule.c.

Argument Clinic reads this file while processing mmapmodule.c (see
Objects/pyspec/README.rst).  Each method of ``class mmap`` is a clinic
function; mmapmodule.c has a one-line block for it (``mmap.mmap.read``)
above its impl, which is written in C by hand.

The spec has no #if.  resize(), __sizeof__(), _protect() and madvise()
exist only on some platforms: their one-line blocks are inside the #if in
mmapmodule.c, which clinic reads as for any block, and the method table
of mmapmodule.c lists their *_METHODDEF unconditionally.
"""

from libclinic.pyspec.runtime import critical_section


class mmap:
    @critical_section
    def close(self):
        ...

    @critical_section
    def find(self, view: Py_buffer, start: object = None,
             end: object = None, /):
        ...

    @critical_section
    def rfind(self, view: Py_buffer, start: object = None,
              end: object = None, /):
        ...

    @critical_section
    def flush(self, offset: Py_ssize_t = 0, size: Py_ssize_t = -1, /, *,
              flags: int = 0):
        ...

    @critical_section
    def madvise(self, option: int, start: Py_ssize_t = 0,
                length: object(c_param='length_obj') = None, /):
        ...

    @critical_section
    def move(self, dest: Py_ssize_t, src: Py_ssize_t,
             count: Py_ssize_t(c_param='cnt'), /):
        ...

    @critical_section
    def read(self,
             n: object(converter='_Py_convert_optional_to_ssize_t',
                       type='Py_ssize_t', c_default='PY_SSIZE_T_MAX',
                       c_param='num_bytes') = None,
             /):
        ...

    @critical_section
    def read_byte(self):
        ...

    @critical_section
    def readline(self):
        ...

    @critical_section
    def resize(self, newsize: Py_ssize_t(c_param='new_size'), /):
        ...

    @critical_section
    def seek(self, pos: Py_ssize_t(c_param='dist'),
             whence: int(c_param='how') = 0, /):
        ...

    def seekable(self):
        ...

    @critical_section
    def set_name(self, name: str, /):
        ...

    @critical_section
    def size(self):
        ...

    @critical_section
    def tell(self):
        ...

    @critical_section
    def write(self, bytes: Py_buffer(c_param='data'), /):
        ...

    @critical_section
    def write_byte(self, byte: unsigned_char(c_param='value'), /):
        ...

    @critical_section
    def __enter__(self):
        ...

    @critical_section
    def __exit__(self, exc_type: object, exc_value: object,
                 traceback: object, /):
        ...

    @critical_section
    def __sizeof__(self):
        ...

    @critical_section
    def _protect(self, flNewProtect: unsigned_int(bitwise=True),
                 start: Py_ssize_t, length: Py_ssize_t, /):
        ...

"""Write tree/Objects/pyspec/bytesobject.py: the real spec with bytes.__new__
and PyBytes_FromObject replaced by the OVERLOADS section of
bytes_new_overloads.py (text splice, so clinic reads it as a file)."""
import ast, os

HERE = os.path.dirname(os.path.abspath(__file__))
REAL = '/home/firebird347/projects/python/cpython/Objects/pyspec/bytesobject.py'
OUT = os.path.join(HERE, 'tree/Objects/pyspec/bytesobject.py')

draft_src = open(os.path.join(HERE, 'bytes_new_overloads.py')).read()
draft_lines = draft_src.splitlines(keepends=True)
draft = ast.parse(draft_src)
classes = [n for n in draft.body if isinstance(n, ast.ClassDef)]
overload_class = classes[1]
# The class body (without the "class bytes:" line) and everything after it.
new_body = ''.join(draft_lines[overload_class.lineno:overload_class.end_lineno])
new_funcs = ''.join(draft_lines[overload_class.end_lineno:]).lstrip('\n')

src = open(REAL).read()
lines = src.splitlines(keepends=True)
tree = ast.parse(src)
cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'bytes')
new = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == '__new__')
fro = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'PyBytes_FromObject')
start_new = min(d.lineno for d in new.decorator_list) - 1
start_fro = fro.lineno - 1
out = (lines[:start_new] + [new_body.lstrip('\n')] + lines[new.end_lineno:start_fro]
       + [new_funcs] + lines[fro.end_lineno:])
text = ''.join(out)
anchor = 'from libclinic.pyspec.runtime import c_name\n'
text = text.replace(anchor, anchor + (
    '\n# Overload sets (see libclinic/pyspec/overloads.py).\n'
    'from collections.abc import Buffer\n'
    'from typing import SupportsIndex, overload\n'
    'from libclinic.pyspec.overloads import Exact\n'), 1)
open(OUT, 'w').write(text)
print('wrote', OUT)

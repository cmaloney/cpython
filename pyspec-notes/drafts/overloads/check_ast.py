"""Desugar the OVERLOADS section of bytes_new_overloads.py and compare
the resulting bodies with the CURRENT section, as ASTs."""
import ast, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import overloads

HERE = os.path.dirname(os.path.abspath(__file__))
tree = ast.parse(open(os.path.join(HERE, 'bytes_new_overloads.py')).read())
classes = [n for n in tree.body if isinstance(n, ast.ClassDef)]
funcs = [n for n in tree.body if isinstance(n, ast.FunctionDef)]
current = {'bytes.__new__': classes[0].body[0], 'PyBytes_FromObject': funcs[0]}
mod = overloads.desugar_module(
    ast.Module(body=[classes[1]] + funcs[1:], type_ignores=[]), 'draft')
desugared = {'bytes.__new__': mod.body[0].body[0],
             'PyBytes_FromObject': mod.body[1]}
ok = True
for name in current:
    a, b = current[name], desugared[name]
    same = ast.dump(ast.Module(a.body, [])) == ast.dump(ast.Module(b.body, []))
    same_sig = ast.dump(a.args) == ast.dump(b.args)
    ok &= same and same_sig
    print(f'{name}: body {"IDENTICAL" if same else "DIFFERENT"}, '
          f'signature {"IDENTICAL" if same_sig else "DIFFERENT"}')
    if '-v' in sys.argv or not same:
        print(ast.unparse(b), end='\n\n')
sys.exit(0 if ok else 1)

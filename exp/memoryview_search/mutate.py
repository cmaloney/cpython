"""Plant bugs in the C implementation one at a time and check that the
adversarial suite and the regression tests catch each one.

Usage: python3 mutate.py BUILD_DIR

BUILD_DIR is a configured (debug) build directory of this source tree; it is
rebuilt with "make" for every mutation. Each source file is restored after
its mutation is tested.
"""
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
SRC = HERE.parent.parent
BUILD = pathlib.Path(sys.argv[1]).resolve()

MO = 'Objects/memoryobject.c'
AR = 'Modules/arraymodule.c'

MUTATIONS = {
    'no alignment check': (MO,
        '        || !_Py_IS_ALIGNED(buf, itemsize))',
        '        )'),
    'no exact-int check': (MO,
        '        || !PyLong_CheckExact(value)\n',
        '        || !PyLong_Check(value)\n'),
    'no size==itemsize check': (MO,
        'if (get_native_fmtchar(&fmt, format) != itemsize',
        'if (get_native_fmtchar(&fmt, format) < 0'),
    'memoryview: no contiguity check (index)': (MO,
        '''        if (PyBuffer_IsContiguous(view, 'C')) {
            found = _PyBuffer_FindItem(''',
        '''        if (1) {
            found = _PyBuffer_FindItem('''),
    'compact path off by one': (MO,
        'if (x >= limit || x < (is_signed ? -limit : 0)) {',
        'if (x > limit || x < (is_signed ? -limit : 0)) {'),
    'signedness flipped': (MO,
        'int is_signed = Py_ISLOWER(fmt[0]);',
        'int is_signed = Py_ISUPPER(fmt[0]);'),
    'missing UNSIGNED_BUFFER flag': (MO,
        '        flags |= Py_ASNATIVEBYTES_UNSIGNED_BUFFER;\n    }\n    Py_ssize_t needed',
        '        flags |= 0;\n    }\n    Py_ssize_t needed'),
    'find returns relative index': (MO,
        'return res < 0 ? -1 : start + res;',
        'return res < 0 ? -1 : res;'),
    'array: stop not clamped to size': (AR,
        'start, Py_MIN(stop, Py_SIZE(self)));',
        'start, stop == PY_SSIZE_T_MAX ? Py_SIZE(self) : stop);'),
    'pack_single: no range error': (MO,
        '        if (size < 0)\n            goto err_range;\n        memcpy(ptr, buf, size);',
        '        if (size < 0)\n            size = 1;\n        memcpy(ptr, buf, size);'),
}


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def main():
    results = []
    for name, (path, old, new) in MUTATIONS.items():
        f = SRC / path
        orig = f.read_text()
        assert orig.count(old) == 1, (name, orig.count(old))
        try:
            f.write_text(orig.replace(old, new))
            b = run(['make', '-j12'], cwd=BUILD)
            if b.returncode:
                results.append((name, 'BUILD FAILED', b.stderr[-300:]))
                continue
            adv = run([str(BUILD / 'python.exe'), str(HERE / 'adversarial.py')],
                      timeout=600)
            last = (adv.stdout.strip().splitlines() or ['crash'])
            summary = next((l for l in last if 'checks' in l),
                           f'CRASHED rc={adv.returncode}')
            reg = run([str(BUILD / 'python.exe'), '-m', 'test', 'test_array',
                       'test_memoryview', 'test_buffer', '-q'], timeout=600)
            reg_ok = 'Result: SUCCESS' in reg.stdout
            results.append((name, summary,
                            'regression tests PASS (missed!)' if reg_ok
                            else 'regression tests FAIL (caught)'))
        finally:
            f.write_text(orig)
        print(results[-1], flush=True)
    run(['make', '-j12'], cwd=BUILD)


main()

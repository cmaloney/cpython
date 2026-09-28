"""Test data for Modules/pyspec/mmapmodule.py (see test_clinic's
PyspecFilesTest).

TYPES maps each class of the spec to the type it describes; the spec
has no bodies, hence no CASES.  Methods compiled out on this platform
(e.g. __sizeof__ outside Windows) are skipped by the test.
"""

import mmap
import tempfile

TYPES = {
    'mmap': mmap.mmap,
}

CASES = {}


def _mmap(size=16, data=b'ab cd\x00ef'):
    with tempfile.TemporaryFile() as f:
        f.write(data.ljust(size, b'\x00'))
        f.flush()
        return mmap.mmap(f.fileno(), size)


# For Tools/clinic/pyspec_parity.py: see Objects/pyspec/bytesobject_cases.py.
PARITY = {
    'mmap': {
        'samples': {'mmap(16)': _mmap},
    },
}

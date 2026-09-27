"""Test data for Modules/pyspec/mmapmodule.py (see test_clinic's
PyspecFilesTest).

TYPES maps each class of the spec to the type it describes; the spec
has no bodies, hence no CASES.  Methods compiled out on this platform
(e.g. __sizeof__ outside Windows) are skipped by the test.
"""

import mmap

TYPES = {
    'mmap': mmap.mmap,
}

CASES = {}

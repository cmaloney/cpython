"""Test data for Objects/pyspec/typeobject.py (see the docstring of
Objects/pyspec/bytesobject_cases.py for the names)."""


class HasBytes:
    def __bytes__(self):
        return b'hb'


HELPERS = {
    '_PyObject_LookupSpecial': [
        (b'x', '__bytes__'), (bytearray(), '__bytes__'),
        (range(3), '__length_hint__'), (iter([]), '__length_hint__'),
        (HasBytes(), '__bytes__'), (5, '__index__')],
}

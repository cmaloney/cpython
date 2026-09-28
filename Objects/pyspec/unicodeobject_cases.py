"""Test data for Objects/pyspec/unicodeobject.py (see the docstring of
Objects/pyspec/bytesobject_cases.py for the names)."""

import codecs


class NULL:
    """C NULL: an argument, or a fact about a parameter."""


class BytesSubclass(bytes):
    pass


def subclass_codec():
    """The name of a codec whose encoder returns a bytes subclass,
    registered on first use."""
    name = 'pyspec_cases_unicode_subclass'
    if not _CODECS:
        def search(wanted):
            if wanted != name:
                return None
            return codecs.CodecInfo(
                name=name,
                encode=lambda s, errors='strict': (BytesSubclass(s.encode()),
                                                   len(s)),
                decode=lambda b, errors='strict': (bytes(b).decode(),
                                                   len(b)))
        codecs.register(search)
        _CODECS.append(search)
    return name


_CODECS = []

HELPERS = {
    'PyUnicode_AsEncodedString': [
        ('abc', 'ascii', NULL), ('\xe9', 'ascii', NULL),
        ('\xe9', 'ascii', 'replace'), ('x', 'utf-8', NULL),
        # F6: the result may be of a bytes subclass.
        lambda: ('x', subclass_codec(), NULL)],
}

# F6: so no exact type is claimed for the result.
FACTS = [
    dict(expr='PyUnicode_AsEncodedString(x, "utf-8", NULL)',
         env={'x': str}, result_type=None),
]

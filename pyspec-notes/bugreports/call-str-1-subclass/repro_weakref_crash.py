import weakref
from _testinternalcapi import TIER2_THRESHOLD

class S(str):
    pass

refs = []

class C:
    def __str__(self):
        s = S("x")
        refs.append(weakref.ref(s))
        return s

def f(n):
    c = C()
    for _ in range(n):
        str(c)

f(TIER2_THRESHOLD * 4)
alive = [r for r in refs if r() is not None]
print(f"{len(alive)} of {len(refs)} weakrefs still return an object; expected 0")
print("first:", type(alive[0]()) if alive else None)

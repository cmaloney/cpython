import gc, sys
from _testinternalcapi import TIER2_THRESHOLD

class S(str):
    pass

class C:
    def __str__(self):
        return S("x")

def f(n):
    c = C()
    for _ in range(n):
        str(c)

print("S instances GC-tracked:", gc.is_tracked(S("x")))
before = sys.getrefcount(S)
n = TIER2_THRESHOLD * 4
f(n)
print("refcount(S) grew by", sys.getrefcount(S) - before, "(expected 0)")
for i in range(20):
    [S("y") for _ in range(10000)]
    gc.collect()
print("survived gc stress")

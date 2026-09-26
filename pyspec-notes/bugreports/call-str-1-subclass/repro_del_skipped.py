import gc
from _testinternalcapi import TIER2_THRESHOLD

dels = 0

class S(str):
    def __del__(self):
        global dels
        dels += 1

class C:
    def __str__(self):
        return S("x")

def f(n):
    c = C()
    for _ in range(n):
        str(c)          # result discarded -> POP_TOP

n = TIER2_THRESHOLD * 4
f(n)
gc.collect()
print(f"S.__del__ ran {dels} times; expected {n}")

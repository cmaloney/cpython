from _testinternalcapi import TIER2_THRESHOLD


class S(str):
    pass


class C:
    def __str__(self):
        return S("x")


def f(n):
    c = C()
    hits = 0
    for _ in range(n):
        if type(str(c)) is str:
            hits += 1
    return hits


print("type(str(c)) is str counted", f(TIER2_THRESHOLD * 4), "times; expected 0")

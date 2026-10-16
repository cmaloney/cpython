"""Search an array while another thread frees and reallocates its buffer.

Usage: python race.py {fast,generic}

Meant for a free-threaded build, ideally with AddressSanitizer. 'fast' uses an
exact int (raw search), 'generic' an int subclass (object comparisons).
Both modes crash, because the array module is not thread-safe
(gh-128942).
"""
import array, sys, threading, time
class I(int):
    # Overriding __eq__ forces the generic path.
    def __eq__(self, other):
        return int.__eq__(self, other)
    __hash__ = int.__hash__
N = 1 << 18
mode = sys.argv[1]
b = array.array('i', range(N))
a = array.array('i', b)
value = N - 1 if mode == 'fast' else I(N - 1)
done = False
counts = {'mut': 0, 'search': 0}
def mutator():
    while not done:
        del a[:]          # size 0: PyMem_Free(ob_item)
        a.extend(b)       # fresh allocation
        counts['mut'] += 1
def searcher():
    while not done:
        try:
            a.count(value)
        except Exception:
            pass
        counts['search'] += 1
ts = [threading.Thread(target=mutator)] + [threading.Thread(target=searcher) for _ in range(3)]
for t in ts: t.start()
time.sleep(4); done = True
for t in ts: t.join()
print("finished", counts)

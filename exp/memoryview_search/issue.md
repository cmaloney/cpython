# Speed up searching integer `array.array` and `memoryview` objects

# Feature or enhancement

### Proposal:

`array.array.index()`, `count()`, `remove()` and `__contains__`, and `memoryview.index()` and `count()` (new in 3.14), compare every item with the value by creating a Python object for it and calling `PyObject_RichCompareBool()`. For integer data this is hundreds of times slower than the equivalent `bytes` search, as reported on Discourse:

```python
data = memoryview(bytearray(64 * 1024))
data[-1] = 10
data.index(10, 100)   # ~860x slower than bytes(data).index(10, 100)
```

It is not specific to memoryview or to bytes. On main (macOS, M3, release build):

| | main | `bytes`/`bytearray` |
|---|---|---|
| `memoryview(bytearray(64 * 1024)).index(10, 100)` | 525 µs | 1.1 µs |
| `array('i', range(16384)).index(16383)` | 210 µs | — |
| `array('q', range(8192)).index(8191)` | 85 µs | — |
| `array('i', range(16384)).count(5)` | 207 µs | — |

When the items are native integers (struct formats `bBhHiIlLqQnN`) and the value is an exact `int` or a `bool`, an item is equal to the value exactly when its bytes are equal to the value packed in that format: each integer has a single representation. So the search can be done on the raw memory, with no objects created and no Python code called, using stringlib's single-character search instantiated for 1-, 2-, 4- and 8-byte items (`memchr()` for 1-byte items).

This does not hold for other formats, which keep the generic comparison: `0.0 == -0.0` and `NaN != NaN` for floats, and any nonzero byte is `True` for `'?'`. Nor does it hold for other types of value, such as `int` subclasses like `IntEnum` (which may override `__eq__`) or `1.0`, nor for non-contiguous or misaligned buffers. Results are unchanged in every case.

With the change:

| | main | patched |
|---|---|---|
| `memoryview(bytearray(64 * 1024)).index(10, 100)` | 525 µs | 1.14 µs |
| `array('i', range(16384)).index(16383)` | 210 µs | 1.5 µs |
| `array('q', range(8192)).index(8191)` | 85 µs | 1.5 µs |
| `array('i', range(16384)).count(5)` | 207 µs | 1.9 µs |
| `array('i', [1, 2, 3]).index(3)` | 28 ns | 19 ns |
| `array('d', range(1000)).index(999.0)` (unchanged path) | 9.5 µs | 9.1 µs |

The value is packed by a helper shared with memoryview's item assignment (`mv[i] = value`), which reports out-of-range values without raising, so `array('B').count(300)` is also fast.

### Has this already been discussed elsewhere?

I have already discussed this feature proposal on Discourse

### Links to previous discussion of this feature:

- https://discuss.python.org/t/memoryview-index-860x-slower-than-bytes-index/104973
- gh-125420: addition of `memoryview.index()` and `count()`

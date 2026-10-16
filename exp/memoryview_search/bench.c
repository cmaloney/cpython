// Microbenchmark: searching for one fixed-size item in an aligned array.
// Typed stringlib instantiations (what memoryobject.c uses) vs byte-level
// alternatives that need an alignment check on every hit.
//
// Build from this directory, with BUILD a configured build directory:
//   cc -O3 -I../../Include -I../../Objects -I$BUILD -o bench bench.c
#include "Python.h"
#include <string.h>
#include <time.h>

#define FASTSEARCH bytes_fastsearch
#define STRINGLIB(F) bytes_##F
#define STRINGLIB_CHAR char
#define STRINGLIB_SIZEOF_CHAR 1
#define STRINGLIB_FAST_MEMCHR memchr
#include "stringlib/fastsearch.h"
#include "stringlib/undef.h"

#define FASTSEARCH item1_fastsearch
#define STRINGLIB(F) item1_##F
#define STRINGLIB_CHAR uint8_t
#define STRINGLIB_SIZEOF_CHAR 1
#define STRINGLIB_FAST_MEMCHR memchr
#include "stringlib/fastsearch.h"
#include "stringlib/undef.h"
#define FASTSEARCH item2_fastsearch
#define STRINGLIB(F) item2_##F
#define STRINGLIB_CHAR uint16_t
#define STRINGLIB_SIZEOF_CHAR 2
#include "stringlib/fastsearch.h"
#include "stringlib/undef.h"
#define FASTSEARCH item4_fastsearch
#define STRINGLIB(F) item4_##F
#define STRINGLIB_CHAR uint32_t
#define STRINGLIB_SIZEOF_CHAR 4
#include "stringlib/fastsearch.h"
#include "stringlib/undef.h"
#define FASTSEARCH item8_fastsearch
#define STRINGLIB(F) item8_##F
#define STRINGLIB_CHAR uint64_t
#define STRINGLIB_SIZEOF_CHAR 8
#include "stringlib/fastsearch.h"
#include "stringlib/undef.h"

typedef Py_ssize_t (*findfn)(const void *, Py_ssize_t, Py_ssize_t, const void *);

// --- typed (current implementation) ---
static Py_ssize_t
typed_find(const void *buf, Py_ssize_t n, Py_ssize_t size, const void *needle)
{
    switch (size) {
    case 1: return item1_fastsearch(buf, n, needle, 1, PY_SSIZE_T_MAX, FAST_SEARCH);
    case 2: return item2_fastsearch(buf, n, needle, 1, PY_SSIZE_T_MAX, FAST_SEARCH);
    case 4: return item4_fastsearch(buf, n, needle, 1, PY_SSIZE_T_MAX, FAST_SEARCH);
    case 8: return item8_fastsearch(buf, n, needle, 1, PY_SSIZE_T_MAX, FAST_SEARCH);
    }
    abort();
}
static Py_ssize_t
typed_count(const void *buf, Py_ssize_t n, Py_ssize_t size, const void *needle)
{
    switch (size) {
    case 1: return item1_fastsearch(buf, n, needle, 1, PY_SSIZE_T_MAX, FAST_COUNT);
    case 2: return item2_fastsearch(buf, n, needle, 1, PY_SSIZE_T_MAX, FAST_COUNT);
    case 4: return item4_fastsearch(buf, n, needle, 1, PY_SSIZE_T_MAX, FAST_COUNT);
    case 8: return item8_fastsearch(buf, n, needle, 1, PY_SSIZE_T_MAX, FAST_COUNT);
    }
    abort();
}

// --- byte level: stringlib bytes search for an itemsize-byte needle ---
static Py_ssize_t
bytes_find(const void *buf, Py_ssize_t n, Py_ssize_t size, const void *needle)
{
    const char *s = buf;
    Py_ssize_t len = n * size, pos = 0;
    while (pos <= len - size) {
        Py_ssize_t r = bytes_fastsearch(s + pos, len - pos, needle, size,
                                        PY_SSIZE_T_MAX, FAST_SEARCH);
        if (r < 0) return -1;
        pos += r;
        if (pos % size == 0) return pos / size;
        pos += 1;
    }
    return -1;
}

// --- byte level: memmem ---
static Py_ssize_t
memmem_find(const void *buf, Py_ssize_t n, Py_ssize_t size, const void *needle)
{
    const char *s = buf;
    Py_ssize_t len = n * size, pos = 0;
    while (pos <= len - size) {
        const char *p = memmem(s + pos, len - pos, needle, size);
        if (p == NULL) return -1;
        pos = p - s;
        if (pos % size == 0) return pos / size;
        pos += 1;
    }
    return -1;
}

// --- byte level: memchr on the first byte, then memcmp ---
static Py_ssize_t
memchr_find(const void *buf, Py_ssize_t n, Py_ssize_t size, const void *needle)
{
    const char *s = buf, *e = s + n * size;
    const char *p = s;
    unsigned char c = *(const unsigned char *)needle;
    while (p < e) {
        p = memchr(p, c, e - p);
        if (p == NULL) return -1;
        Py_ssize_t off = p - s;
        if (off % size == 0 && memcmp(p, needle, size) == 0) return off / size;
        p++;
    }
    return -1;
}

// --- plain typed loop (let the compiler vectorize) ---
#define LOOP(T) { const T *a = buf; T v; memcpy(&v, needle, sizeof v); \
    for (Py_ssize_t i = 0; i < n; i++) if (a[i] == v) return i; return -1; }
static Py_ssize_t
loop_find(const void *buf, Py_ssize_t n, Py_ssize_t size, const void *needle)
{
    switch (size) {
    case 1: LOOP(uint8_t) case 2: LOOP(uint16_t)
    case 4: LOOP(uint32_t) case 8: LOOP(uint64_t)
    }
    abort();
}

// count via repeated byte-level find
static Py_ssize_t
bytes_count(const void *buf, Py_ssize_t n, Py_ssize_t size, const void *needle)
{
    Py_ssize_t count = 0, start = 0;
    for (;;) {
        Py_ssize_t i = memchr_find((const char *)buf + start * size,
                                   n - start, size, needle);
        if (i < 0) return count;
        count++;
        start += i + 1;
    }
}

static double
now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static volatile Py_ssize_t sink;

static double
bench(findfn f, const void *buf, Py_ssize_t n, Py_ssize_t size,
      const void *needle, Py_ssize_t expected)
{
    if (f(buf, n, size, needle) != expected) {
        printf("WRONG RESULT\n");
        exit(1);
    }
    double best = 1e9;
    for (int rep = 0; rep < 7; rep++) {
        int iters = 2000;
        double t0 = now();
        for (int i = 0; i < iters; i++) sink = f(buf, n, size, needle);
        double t = (now() - t0) / iters;
        if (t < best) best = t;
    }
    return best * 1e6;
}

#define N_BYTES (64 * 1024)

static void
fill(void *buf, Py_ssize_t n, Py_ssize_t size, int scenario)
{
    for (Py_ssize_t i = 0; i < n; i++) {
        uint64_t v;
        switch (scenario) {
        case 0: v = i; break;                          // range(n)
        case 1: v = 0; break;                          // zeros
        case 2: v = 0x0101010101010101ULL; break;      // every byte 0x01
        default: v = (i * 2654435761u) | 1; break;     // pseudo-random
        }
        memcpy((char *)buf + i * size, &v, size);      // little endian
    }
}

int
main(void)
{
    static const char *names[] = {
        "range, find last", "zeros, find 1 at end",
        "all 0x01 bytes, find 1 at end", "random-ish, find 0x100 at end",
    };
    static uint64_t storage[N_BYTES / 8 + 1];
    void *buf = storage;
    struct { const char *name; findfn f; } fns[] = {
        {"typed stringlib", typed_find},
        {"plain typed loop", loop_find},
        {"bytes stringlib", bytes_find},
        {"memmem", memmem_find},
        {"memchr+memcmp", memchr_find},
    };
    for (Py_ssize_t size = 1; size <= 8; size *= 2) {
        Py_ssize_t n = N_BYTES / size;
        printf("\n== itemsize %zd, %zd items (64 KiB) ==\n", size, n);
        printf("%-34s", "scenario (find)");
        for (size_t k = 0; k < sizeof(fns) / sizeof(fns[0]); k++)
            printf("%18s", fns[k].name);
        printf("\n");
        for (int sc = 0; sc < 4; sc++) {
            fill(buf, n, size, sc);
            uint64_t needle;
            switch (sc) {
            case 0: needle = n - 1; break;
            case 1: case 2: needle = 1; break;
            default: needle = 0x100 & (size == 1 ? 0xff : ~0ULL); break;
            }
            if (size == 1 && sc == 3) needle = 0x80;  // even values absent
            {
                // make sure the needle appears only at the end
                for (Py_ssize_t i = 0; i < n - 1; i++)
                    if (memcmp((char *)buf + i * size, &needle, size) == 0)
                        memset((char *)buf + i * size, 0x55, size);
            }
            memcpy((char *)buf + (n - 1) * size, &needle, size);
            printf("%-34s", names[sc]);
            for (size_t k = 0; k < sizeof(fns) / sizeof(fns[0]); k++)
                printf("%15.2f us", bench(fns[k].f, buf, n, size, &needle, n - 1));
            printf("\n");
        }
        // count
        fill(buf, n, size, 0);
        uint64_t needle = 5;
        Py_ssize_t expected = typed_count(buf, n, size, &needle);
        printf("%-34s%15.2f us%15s%15s%15s%15.2f us  (typed vs memchr loop)\n",
               "range, count 5",
               bench(typed_count, buf, n, size, &needle, expected), "", "", "",
               bench(bytes_count, buf, n, size, &needle, expected));
    }
    return 0;
}

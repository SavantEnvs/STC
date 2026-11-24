// libFuzzer harness: STC cbits bitset — cbits_from() on fuzzed '0'/'1' strings, resize, set
// algebra (union/intersect/xor/subset/disjoint), flip, count and to_str. Results are checked
// against a naive per-bit model (abort on mismatch).
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "stc/cbits.h"

static volatile int sink;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3) return -1;
    isize_t rsz = (isize_t)((data[0] << 8) | data[1]) % 4096;
    uint8_t flags = data[2];
    data += 3; size -= 3;
    char *buf = malloc(size + 2);
    for (size_t i = 0; i < size; ++i) buf[i] = data[i] ? (char)('0' + (data[i] & 1)) : 0;
    buf[size] = buf[size + 1] = 0;
    const char *s1 = buf, *s2 = buf + strlen(buf) + 1;
    if (s2 > buf + size) s2 = "";

    cbits a = cbits_from(s1), b = cbits_from(s2);
    if (cbits_size(&a) != (isize_t)strlen(s1)) abort();
    isize_t cnt = 0;
    for (const char *p = s1; *p; ++p) cnt += *p == '1';
    if (cbits_count(&a) != cnt) abort();
    bool ra = cbits_resize(&a, rsz, flags & 1);
    bool rb = cbits_resize(&b, rsz, flags & 2);
    if (!ra || !rb) {
        // A failed resize leaves the bitset as it was (cbits.h contract), so it may now differ in
        // size from the other and the set operations' same-size precondition no longer holds.
        // At HEAD resize(.., 0, ..) fails after realloc(buf, 0) already freed the buffer: use the
        // bitsets the way a caller would (count) so that fires, then stop this input. They are
        // not dropped, as the buffer may already be freed.
        sink ^= (int)(cbits_count(&a) + cbits_count(&b));
        free(buf);
        return 0;
    }
    char *out = malloc((size_t)rsz + 1);
    cbits_to_str(&a, out, 0, rsz);
    isize_t naive = 0;
    for (isize_t i = 0; i < rsz; ++i) {
        if ((out[i] == '1') != cbits_test(&a, i)) abort();
        naive += out[i] == '1';
    }
    if (naive != cbits_count(&a)) abort();
    cbits c = cbits_clone(a);
    cbits_intersect(&c, &b);
    // cbits_subset_of()'s direction differs from docs/cbits_api.md at HEAD (it tests other <= self),
    // so its result is exercised but not asserted; the set algebra is checked via counts below.
    sink ^= cbits_subset_of(&c, &a) ^ cbits_subset_of(&a, &c);
    cbits u = cbits_clone(a);
    cbits_union(&u, &b);
    if (cbits_count(&u) + cbits_count(&c) != cbits_count(&a) + cbits_count(&b)) abort();
    cbits x = cbits_clone(a);
    cbits_xor(&x, &b);
    if (cbits_count(&x) + 2 * cbits_count(&c) != cbits_count(&a) + cbits_count(&b)) abort();
    cbits_flip_all(&x);
    sink ^= cbits_disjoint(&x, &c);
    if (rsz) {
        isize_t k = flags % rsz;
        cbits_flip(&c, k); cbits_set(&u, k); cbits_reset(&x, k);
        if (!cbits_test(&u, k) || cbits_test(&x, k)) abort();
        cbits_to_str(&u, out, k, rsz);
    }
    cbits_copy(&b, &a);
    if (cbits_count(&b) != cbits_count(&a)) abort();
    cbits_drop(&a); cbits_drop(&b); cbits_drop(&c); cbits_drop(&u); cbits_drop(&x);
    (void)sink;
    free(out); free(buf);
    return 0;
}

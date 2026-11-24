// libFuzzer harness: STC csview/zsview string-view API — subview/slice/tail clamping, trimming,
// UTF-8 iteration/subviews, case-insensitive compare, split/tokenize and find.
// Input: 6 header bytes = positions/lengths, rest = text (split on first NUL into text, needle).
// Byte positions obey the documented c_assert preconditions (pos <= size, len >= 0);
// lengths past the end are allowed since the API clamps them.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "stc/csview.h"
#include "stc/zsview.h"
#include "stc/utf8.h"

static isize_t pick(uint8_t b, isize_t n) { return n ? (isize_t)(b % (n + 1)) : 0; }
static volatile char sink;
static void touch(csview v) { for (isize_t i = 0; i < v.size; ++i) sink ^= v.buf[i]; }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 7) return -1;
    const uint8_t *h = data; data += 6; size -= 6;
    char *buf = malloc(size + 2);
    memcpy(buf, data, size); buf[size] = buf[size + 1] = 0;
    const char *needle = buf + strlen(buf) + 1;
    if (needle > buf + size) needle = "";

    csview all = csview_from_n(buf, (isize_t)size);
    csview sv = csview_from(buf);
    isize_t n = sv.size;
    isize_t p1 = pick(h[0], n);
    touch(csview_subview(sv, p1, h[1]));
    touch(csview_slice(sv, p1, p1 + h[2]));
    touch(csview_tail(sv, pick(h[3], n)));
    touch(csview_trim(all));
    touch(csview_trim_start(sv)); touch(csview_trim_end(sv));
    sink ^= (char)csview_find(sv, needle) ^ (char)csview_contains(sv, needle);
    sink ^= (char)csview_starts_with(sv, needle) ^ (char)csview_ends_with(sv, needle);
    sink ^= (char)csview_istarts_with(sv, needle) ^ (char)csview_iends_with(sv, needle);
    csview nv = csview_from(needle);
    sink ^= (char)csview_icmp(&sv, &nv) ^ (char)csview_iequals_sv(sv, nv) ^ (char)csview_cmp(&sv, &nv);
    sink ^= (char)csview_hash(&sv);
    sink ^= (char)csview_u8_valid(all);
    for (c_each(i, csview, all)) sink ^= (char)csview_codepoint(&i);
    if (*needle) {
        int k = 0;
        for (c_each_split_sv(t, needle, sv)) { touch(t.token); if (++k > 512) break; }
        k = 0;
        for (c_each_strtok_sv(t, needle, sv)) { touch(t.token); if (++k > 512) break; }
    }
    if (cutf8_valid(buf)) {
        isize_t u = csview_u8_size(sv);
        isize_t up = pick(h[4], u), ul = pick(h[5], u - up);
        touch(csview_u8_from(buf, up, ul));
        touch(cutf8_subview(buf, up, ul));
        zsview z = zsview_from(buf);
        zsview zt = zsview_u8_tail(z, h[5]);
        touch(csview_from_n(zt.str, zt.size));
        touch(zsview_u8_subview(z, up, ul));
        zsview zz = zsview_tail(z, pick(h[3], n));
        touch(csview_from_n(zz.str, zz.size));
        sink ^= (char)zsview_u8_valid(z);
    }
    (void)sink;
    free(buf);
    return 0;
}

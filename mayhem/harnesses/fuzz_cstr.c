// libFuzzer harness: STC cstr string API on fuzzed bytes — SSO/heap string management, UTF-8
// sub-views/replace/insert/erase, case conversion, search/replace, iteration and getline.
// Input: 8 header bytes choose UTF-8 positions/lengths; the rest is split on NUL into
// text, search and replacement. Byte-index positions are kept in range (c_assert contract);
// UTF-8 positions are kept within the UTF-8 length of valid UTF-8 text (cutf8_at contract).
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stc/cstr.h"

static isize_t pick(uint8_t b, isize_t n) { return n ? (isize_t)(b % (n + 1)) : 0; }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 9) return -1;
    const uint8_t *h = data; data += 8; size -= 8;
    char *buf = malloc(size + 3);
    memcpy(buf, data, size); buf[size] = buf[size + 1] = buf[size + 2] = 0;
    const char *text = buf;
    const char *search = text + strlen(text) + 1;
    if (search > buf + size) search = "";
    const char *repl = search + strlen(search) + 1;
    if (repl > buf + size) repl = "";
    volatile char sink = 0;

    cstr s = cstr_from_n(buf, (isize_t)size);   // includes embedded NULs
    cstr t = cstr_from(text);
    isize_t n = cstr_size(&t);
    csview sv = cstr_subview(&t, pick(h[0], n), h[1]);
    for (isize_t i = 0; i < sv.size; ++i) sink ^= sv.buf[i];
    csviewz tz = cstr_tail(&t, h[2]);
    for (isize_t i = 0; i < tz.size; ++i) sink ^= tz.str[i];

    if (cstr_u8_valid(&t)) {
        isize_t u = cstr_u8_size(&t);
        isize_t p = pick(h[3], u), l = pick(h[4], u - p);
        csview us = cstr_u8_subview(&t, p, l);
        for (isize_t i = 0; i < us.size; ++i) sink ^= us.buf[i];
        csviewz ut = cstr_u8_tail(&t, h[5]);
        for (isize_t i = 0; i < ut.size; ++i) sink ^= ut.str[i];
        cstr_iter it = cstr_u8_at(&t, p);
        if (it.ref) sink ^= *it.ref;
        cstr c = cstr_u8_from(cstr_str(&t), p, l);
        if (cutf8_valid(repl)) cstr_u8_replace(&c, 0, cstr_u8_size(&c) ? 1 : 0, repl);
        if (cstr_u8_valid(&c)) cstr_u8_insert(&c, pick(h[6], cstr_u8_size(&c)), search);
        if (cstr_u8_valid(&c)) {
            isize_t cu = cstr_u8_size(&c), cp = pick(h[7], cu);
            cstr_u8_erase(&c, cp, pick(h[6], cu - cp));
        }
        cstr_drop(&c);
        for (c_each(i, cstr, t)) sink ^= (char)cstr_codepoint(&i);
        cstr lo = cstr_tolower(cstr_str(&t)), up = cstr_toupper(cstr_str(&t));
        cstr cf = cstr_casefold_sv(cstr_sv(&t));
        sink ^= (char)cstr_icmp(&lo, &up);
        sink ^= (char)cstr_iequals(&cf, cstr_str(&lo));
        sink ^= (char)cstr_istarts_with(&t, search) ^ (char)cstr_iends_with(&t, search);
        cstr_uppercase(&lo);
        cstr_drop(&lo); cstr_drop(&up); cstr_drop(&cf);
    }

    sink ^= (char)cstr_find(&t, search);
    sink ^= (char)cstr_contains(&t, search) ^ (char)cstr_starts_with(&t, search) ^ (char)cstr_ends_with(&t, search);
    if (*search) {
        cstr r = cstr_clone(t);
        cstr_replace(&r, search, repl);
        cstr_replace_nfirst(&r, repl, search, h[0] & 7);
        cstr_drop(&r);
    }
    n = cstr_size(&t);
    isize_t pos = pick(h[1], n);
    cstr_insert(&t, pos, repl);
    n = cstr_size(&t); pos = pick(h[2], n);
    cstr_replace_at(&t, pos, pick(h[3], n - pos), search);
    n = cstr_size(&t); pos = pick(h[4], n);
    cstr_erase(&t, pos, h[5]);
    cstr_append(&t, search);
    cstr_append_s(&t, s);
    cstr_push(&t, repl);
    if (cstr_size(&t)) cstr_pop(&t);
    cstr_reserve(&t, cstr_size(&t) + h[6]);
    cstr_shrink_to_fit(&t);
    sink ^= cstr_str(&t)[0];

    FILE *fp = fmemopen(buf, size, "r");
    if (fp) {
        cstr line = {0};
        int k = 0;
        while (k++ < 64 && cstr_getdelim(&line, (char)h[7], fp)) sink ^= cstr_str(&line)[0];
        cstr_drop(&line);
        fclose(fp);
    }
    (void)sink;
    cstr_drop(&t); cstr_drop(&s);
    free(buf);
    return 0;
}

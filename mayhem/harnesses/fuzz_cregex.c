// libFuzzer harness: STC regex engine (cregex.h) — compile a fuzzed pattern, match it against a
// fuzzed input, iterate all matches, and run regex replace with a fuzzed replacement string.
// Input layout: byte0 = compile/match flags; rest split on NUL into pattern, input, replacement.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "stc/cstr.h"
#include "stc/cregex.h"
#include "stc/csview.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return -1;
    int cflags = data[0] & (CREG_DOTALL | CREG_ICASE | CREG_MULTILINE);
    int mflags = data[0] & (CREG_FULLMATCH | CREG_STRIP);
    char *buf = malloc(size + 2);            // +2 NULs: guarantees three C strings
    memcpy(buf, data + 1, size - 1);
    buf[size - 1] = 0; buf[size] = 0; buf[size + 1] = 0;
    const char *pat = buf;
    const char *input = pat + strlen(pat) + 1;
    const char *repl = input + strlen(input) + 1;
    if (repl > buf + size) repl = "";

    cregex re = {0};
    int rc = cregex_compile(&re, pat, cflags);
    if (rc == CREG_OK) {
        csview m[CREG_MAX_CAPTURES];
        int ncap = cregex_captures(&re);
        if (cregex_match(&re, input, m, mflags & CREG_FULLMATCH) == CREG_OK) {
            volatile char sink = 0;
            for (int i = 0; i <= ncap && i < CREG_MAX_CAPTURES; ++i)
                for (isize_t j = 0; j < m[i].size; ++j) sink ^= m[i].buf[j];
            (void)sink;
        }
        csview sv = csview_from(input);
        (void)cregex_match_sv(&re, sv, m);
        int n = 0;
        for (c_each_match(it, &re, input)) {
            if (++n > 256) break;
            if (it.match[0].size == 0 && *(it.match[0].buf) == 0) break;
        }
        // .count bounds the loop: cregex_replace_opt never advances past an empty match, so an unbounded
        // replace with a pattern like "a*" never terminates (upstream bug, reported in the PR).
        cstr r = cregex_replace(&re, input, repl, .count = 256, .flags = mflags & CREG_STRIP);
        cstr_drop(&r);
        cstr r2 = cregex_replace_sv(&re, sv, repl, .count = 3);
        cstr_drop(&r2);
    }
    cregex_drop(&re);
    free(buf);
    return 0;
}

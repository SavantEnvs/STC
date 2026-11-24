// libFuzzer harness: STC fmt.h ({}-style formatted printing) with a fuzzed format string, into
// a fmt_stream (_fmt_sprint) AND a char[] buffer (sprintf): _fmt_init buffer sizing, _fmt_parse
// '{}'/'{:MODS}' -> printf translation (types, '<'/'>' alignment, left-align of strings), plus
// fmt_time (strftime) on the same text.
//
// Input: byte 0 = control (bit 0: stream overwrite mode, bit 1: argument type set), rest = format.
//
// Preconditions, all from fmt.h's own contract:
// - the format's "{}" count must equal the number of arguments (0..6 here; the macro asserts it);
// - "{:MODS}" content is copied into the printf spec verbatim ("MODS can be regular printf()
//   format modifiers"), and the argument's conversion is appended only when MODS do not end in
//   one. So MODS are limited to [flags][width][.precision] (flags '<' '>' '-' '+' ' ' '#' '0')
//   with each number at most 3 digits; a conversion letter or '*' would let the format
//   pick the vararg type, which the caller must guarantee. Other text, including '%' (documented
//   to print '%'), passes through. Inputs violating that are rejected with -1.
// - a char* destination must be large enough: the buffer is sized from the format length plus
//   the widest a 3-digit width/precision can make each argument.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>
#include "stc/c11/fmt.h"

#define MAXARGS 6

// Returns the number of "{}" fields, or -1 if the format is outside the contract above.
static int count_fields(const char *f) {
    int n = 0;
    for (size_t i = 0; f[i]; ++i) {
        if (f[i] == '}') {
            if (f[i + 1] != '}') return -1;
            ++i; continue;
        }
        if (f[i] != '{') continue;
        if (f[i + 1] == '{') { ++i; continue; }
        size_t j = i + 1;
        if (f[j] == ':') {               // [flags][width][.precision], numbers <= 3 digits
            ++j;
            while (f[j] && strchr("<>-+ #0", f[j])) ++j;
            for (int d = 0; f[j] >= '0' && f[j] <= '9'; ++j) if (++d > 3) return -1;
            if (f[j] == '.') {
                ++j;
                for (int d = 0; f[j] >= '0' && f[j] <= '9'; ++j) if (++d > 3) return -1;
            }
        }
        if (f[j] != '}') return -1;
        i = j;
        if (++n > MAXARGS) return -1;
    }
    return n;
}

// Every argument printed with a <=3-digit width/precision stays under this many bytes.
#define PER_ARG 1100

#define EMIT(...) do { \
        fmt_printd(ss, __VA_ARGS__); \
        fmt_printd(obuf, __VA_ARGS__); \
    } while (0)

static void print_all(fmt_stream *ss, char *obuf, const char *f, int nargs, int set) {
    const wchar_t *ws = L"wide";
    void *ptr = (void *)ss;
    switch (nargs * 2 + set) {
    case 0: case 1: EMIT(f); break;
    case 2:  EMIT(f, 42); break;
    case 3:  EMIT(f, "str"); break;
    case 4:  EMIT(f, "str", 3.5); break;
    case 5:  EMIT(f, 'c', 2.5f); break;
    case 6:  EMIT(f, 'c', -7L, "xyz"); break;
    case 7:  EMIT(f, (unsigned char)200, (short)-3, (unsigned short)65535); break;
    case 8:  EMIT(f, 1u, 2.5f, "ab", (long long)-9); break;
    case 9:  EMIT(f, (_Bool)1, 18446744073709551615ull, ws, (unsigned long)7); break;
    case 10: EMIT(f, -1, "s", 0.125, 'z', 99ul); break;
    case 11: EMIT(f, ptr, (signed char)-5, 1e300, (long double)1.5L, ""); break;
    case 12: EMIT(f, 1, 2, 3, "four", 5.0, (long long)6); break;
    case 13: EMIT(f, ws, -0.0f, (short)1, 'q', 4294967295u, (unsigned char)0); break;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 || size > 65536) return -1;
    uint8_t ctl = data[0];
    ++data; --size;
    char *f = malloc(size + 1);
    memcpy(f, data, size); f[size] = 0;
    int nargs = count_fields(f);
    // fmt_printd_2 (no arguments) hands the raw format to printf, so '%' is only safe with args.
    if (strlen(f) != size || nargs < 0 || (nargs == 0 && strchr(f, '%'))) { free(f); return -1; }

    fmt_stream ss = {0};
    ss.overwrite = ctl & 1;
    char *obuf = malloc(size + (size_t)MAXARGS * PER_ARG + 64);
    // The fuzzed text as an argument, first: at HEAD, an empty first write into a fresh stream
    // computes NULL + 0 in _fmt_sprint (fmt.h:249), which would halt every empty-output format.
    fmt_printd(&ss, "{}{}", f, (int)size);
    print_all(&ss, obuf, f, nargs, (ctl >> 1) & 1);
    fmt_printd(obuf, "{:.40}|{:>8}", f, ss.len);
    struct tm tm = {.tm_year = 126, .tm_mon = 10, .tm_mday = 24, .tm_hour = 13, .tm_min = 5,
                    .tm_sec = 9, .tm_wday = 2, .tm_yday = 327};
    (void)fmt_time(f, &tm, 127);
    fmt_close(&ss);
    free(obuf);
    free(f);
    return 0;
}

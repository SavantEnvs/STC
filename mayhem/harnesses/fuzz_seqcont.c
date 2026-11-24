// libFuzzer harness: STC sequence containers (vec, stack, deque, queue, list) driven by a fuzzed
// opcode stream, with int and cstr elements. Every vec<int> op is mirrored in a plain model
// array and the two are compared after each step (abort on divergence). Clone/copy of empty,
// reserved and shrunk containers is exercised. Only valid indices are used (c_assert contract).
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stc/cstr.h"

#define T IVec, int, (c_use_compare)
#include "stc/vec.h"
#define T SVec, cstr, (c_pro_key)
#include "stc/vec.h"
#define T IStack, int
#include "stc/stack.h"
#define T SStack, cstr, (c_pro_key)
#include "stc/stack.h"
#define T IDeq, int, (c_use_eq)
#include "stc/deque.h"
#define T IQue, int, (c_use_eq)
#include "stc/queue.h"
#define T IList, int, (c_use_compare)
#include "stc/list.h"
#define T SList, cstr, (c_pro_key)
#include "stc/list.h"

#define MAXN 4096
static int model[MAXN];
static isize_t msize;
static int icmp(const void *x, const void *y) { int a = *(const int*)x, b = *(const int*)y; return (a > b) - (a < b); }

static void check(const IVec *v) {
    if (IVec_size(v) != msize) abort();
    for (isize_t i = 0; i < msize; ++i) if (*IVec_at(v, i) != model[i]) abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    IVec v = {0}; SVec sv = {0}; IStack st = {0}; SStack sst = {0};
    IDeq dq = {0}; IQue q = {0}; IList l = {0}; SList sl = {0};
    msize = 0;
    char str[16];
    size_t i = 0;
    while (i + 2 < size) {
        uint8_t op = data[i], a = data[i + 1], b = data[i + 2];
        i += 3;
        int val = (int)((a << 8) | b) - 32768;
        snprintf(str, sizeof str, "%d", val);
        switch (op % 24) {
        case 0: if (msize < MAXN) { IVec_push(&v, val); model[msize++] = val; } break;
        case 1: if (msize) { IVec_pop(&v); --msize; } break;
        case 2: if (msize < MAXN) { isize_t p = a % (msize + 1);
                IVec_insert_n(&v, p, &val, 1);
                memmove(model + p + 1, model + p, (size_t)(msize - p) * sizeof(int));
                model[p] = val; ++msize; } break;
        case 3: if (msize) { isize_t p = a % msize, k = b % (msize - p + 1);
                IVec_erase_n(&v, p, k);
                memmove(model + p, model + p + k, (size_t)(msize - p - k) * sizeof(int));
                msize -= k; } break;
        case 4: { isize_t n = b % 64; IVec_resize(&v, n, val);
                for (isize_t j = msize; j < n; ++j) model[j] = val; msize = n; } break;
        case 5: IVec_reserve(&v, a); break;
        case 6: IVec_shrink_to_fit(&v); break;
        case 7: { IVec c = IVec_clone(v); if (!IVec_eq(&c, &v)) abort();
                IVec d = {0}; IVec_copy(&d, &c); if (!IVec_eq(&d, &v)) abort();
                IVec_drop(&c); IVec_drop(&d); } break;
        case 8: IVec_sort(&v); qsort(model, (size_t)msize, sizeof(int), icmp); break;
        case 9: { IVec_iter it = IVec_find(&v, val); int found = 0;
                for (isize_t j = 0; j < msize; ++j) if (model[j] == val) { found = 1; break; }
                if ((it.ref != NULL) != found) abort(); } break;
        case 10: SVec_emplace(&sv, str); break;
        case 11: if (SVec_size(&sv)) SVec_erase_n(&sv, a % SVec_size(&sv), 1); break;
        case 12: { SVec c = SVec_clone(sv); SVec_copy(&sv, &c); SVec_drop(&c);
                 if (a & 1) SVec_shrink_to_fit(&sv); else SVec_reserve(&sv, b); } break;
        case 13: IStack_push(&st, val); SStack_emplace(&sst, str); break;
        case 14: if (IStack_size(&st)) IStack_pop(&st);
                 if (SStack_size(&sst)) SStack_pop(&sst); break;
        case 15: { IStack c = IStack_clone(st); SStack c2 = SStack_clone(sst);
                 if (IStack_size(&c) != IStack_size(&st) || SStack_size(&c2) != SStack_size(&sst)) abort();
                 IStack_drop(&c); SStack_drop(&c2);
                 if (a & 1) { IStack_shrink_to_fit(&st); SStack_shrink_to_fit(&sst); }
                 else { IStack_reserve(&st, b); SStack_reserve(&sst, b); } } break;
        case 16: if (a & 1) IDeq_push_front(&dq, val); else IDeq_push_back(&dq, val); break;
        case 17: if (IDeq_size(&dq)) { if (a & 1) IDeq_pop_front(&dq); else IDeq_pop_back(&dq); } break;
        case 18: { isize_t n = IDeq_size(&dq); IDeq_insert_n(&dq, a % (n + 1), &val, 1);
                 n = IDeq_size(&dq); isize_t p = b % n; IDeq_erase_n(&dq, p, (a % (n - p + 1)));
                 IDeq c = IDeq_clone(dq); if (!IDeq_eq(&c, &dq)) abort(); IDeq_drop(&c);
                 IDeq_shrink_to_fit(&dq); } break;
        case 19: IQue_push(&q, val); if ((a & 3) == 0 && IQue_size(&q)) IQue_pop(&q);
                 { IQue c = IQue_clone(q); if (!IQue_eq(&c, &q)) abort(); IQue_drop(&c); } break;
        case 20: if (a & 1) IList_push_front(&l, val); else IList_push_back(&l, val);
                 SList_emplace_back(&sl, str); break;
        case 21: if (!IList_is_empty(&l)) IList_pop_front(&l);
                 if (!SList_is_empty(&sl)) SList_pop_front(&sl); break;
        case 22: IList_sort(&l); IList_reverse(&l); IList_remove(&l, val);
                 { IList c = IList_clone(l); if (!IList_eq(&c, &l)) abort(); IList_drop(&c); } break;
        case 23: { SList c = SList_clone(sl); SList_splice(&sl, SList_begin(&sl), &c);
                 SList_drop(&c); } break;
        }
        check(&v);
    }
    IVec_drop(&v); SVec_drop(&sv); IStack_drop(&st); SStack_drop(&sst);
    IDeq_drop(&dq); IQue_drop(&q); IList_drop(&l); SList_drop(&sl);
    return 0;
}

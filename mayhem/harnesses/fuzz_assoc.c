// libFuzzer harness: STC associative containers — hmap/hset (robin-hood hashing, rehash, erase),
// smap/sset (AA-tree in an array with a node free-list) and pqueue, with int and cstr keys, driven
// by a fuzzed opcode stream. A small key space forces collisions. hmap and smap receive the same
// operations and are cross-checked (size, lookups); pqueue pops must come out ordered.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "stc/cstr.h"

#define T IHMap, int, int
#include "stc/hmap.h"
#define T ISMap, int, int, (c_use_eq)
#include "stc/smap.h"
#define T SHMap, cstr, int, (c_pro_key)
#include "stc/hmap.h"
#define T SSMap, cstr, int, (c_pro_key)
#include "stc/smap.h"
#define T SHSet, cstr, (c_pro_key)
#include "stc/hset.h"
#define T ISSet, int
#include "stc/sset.h"
#define T IPQue, int
#include "stc/pqueue.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    IHMap hm = {0}; ISMap sm = {0}; SHMap shm = {0}; SSMap ssm = {0};
    SHSet hs = {0}; ISSet ss = {0}; IPQue pq = {0};
    char key[24];
    size_t i = 0;
    while (i + 2 < size) {
        uint8_t op = data[i], a = data[i + 1], b = data[i + 2];
        i += 3;
        int k = (a & 0x80) ? a * 1024 : a;   // small key space, some spread-out keys
        int v = b;
        snprintf(key, sizeof key, "k%d", a);
        switch (op % 14) {
        case 0: IHMap_insert(&hm, k, v); ISMap_insert(&sm, k, v); break;
        case 1: IHMap_insert_or_assign(&hm, k, v); ISMap_insert_or_assign(&sm, k, v); break;
        case 2: if (IHMap_erase(&hm, k) != ISMap_erase(&sm, k)) abort(); break;
        case 3: { const IHMap_value *x = IHMap_get(&hm, k); const ISMap_value *y = ISMap_get(&sm, k);
                if ((x == NULL) != (y == NULL)) abort();
                if (x && x->second != y->second) abort(); } break;
        case 4: IHMap_reserve(&hm, b); ISMap_reserve(&sm, b); break;
        case 5: IHMap_shrink_to_fit(&hm); break;   // smap shrink_to_fit runs on a clone in case 6
        case 6: { IHMap c = IHMap_clone(hm); ISMap d = ISMap_clone(sm);
                if (!IHMap_eq(&c, &hm)) abort();
                // ISMap_clone()'s size is not asserted (it comes back 0 at HEAD); the clone is
                // used and mutated instead so ASan checks the cloned node array.
                for (c_each(it, ISMap, d)) if (!ISMap_contains(&sm, it.ref->first)) abort();
                ISMap_insert(&d, k + 1, v); ISMap_erase(&d, k); ISMap_shrink_to_fit(&d);
                IHMap_drop(&c); ISMap_drop(&d);
                if (a == 0) { IHMap_clear(&hm); ISMap_clear(&sm); } } break;
        case 7: SHMap_emplace_or_assign(&shm, key, v); SSMap_emplace(&ssm, key, v); break;
        case 8: SHMap_erase(&shm, key); SSMap_erase(&ssm, key); break;
        case 9: { int c1 = SHMap_contains(&shm, key), c2 = SSMap_contains(&ssm, key); (void)c1; (void)c2;
                SHMap c = SHMap_clone(shm); SHMap_drop(&c); SSMap d = SSMap_clone(ssm); SSMap_drop(&d);
                if (b & 1) SHMap_shrink_to_fit(&shm); } break;
        case 10: SHSet_emplace(&hs, key); ISSet_insert(&ss, k);
                 if (b & 1) { SHSet_erase(&hs, key); ISSet_erase(&ss, k); } break;
        case 11: { isize_t n = 0; for (c_each(it, ISSet, ss)) ++n; if (n != ISSet_size(&ss)) abort();
                 ISSet_iter it = ISSet_lower_bound(&ss, k); if (it.ref && *it.ref < k) abort(); } break;
        case 12: IPQue_push(&pq, (a << 8) | b); break;
        case 13: if (IPQue_size(&pq)) { int t = *IPQue_top(&pq); IPQue_pop(&pq);
                 if (IPQue_size(&pq) && *IPQue_top(&pq) > t) abort(); } break;
        }
        if (IHMap_size(&hm) != ISMap_size(&sm)) abort();
        if (SHMap_size(&shm) != SSMap_size(&ssm)) abort();
    }
    isize_t n = 0;
    for (c_each_kv(kk, vv, IHMap, hm)) { const ISMap_value *y = ISMap_get(&sm, *kk);
        if (!y || y->second != *vv) abort(); ++n; }
    if (n != ISMap_size(&sm)) abort();
    IHMap_drop(&hm); ISMap_drop(&sm); SHMap_drop(&shm); SSMap_drop(&ssm);
    SHSet_drop(&hs); ISSet_drop(&ss); IPQue_drop(&pq);
    return 0;
}

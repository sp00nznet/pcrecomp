/*
 * storage_selftest.c - structured storage round trip: a compound file with a
 * small stream (the mini stream) and a big one (regular sectors) inside a
 * sub-storage, written, released, opened again and read back. Headless.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "win32hle.h"

const recomp_dispatch_entry_t recomp_dispatch_table[] = { { 0, 0 } };
const uint32_t recomp_dispatch_count = 0;

static int fails;
static void ok(const char *w, int c) { if (!c) { printf("FAIL %s\n", w); fails++; } }

static uint32_t call(const char *name, int n, const uint32_t *a) { return hle_call_guest(hle_resolve(name), n, a); }
static uint32_t vcall(uint32_t obj, int slot, int n, const uint32_t *args) {
    uint32_t a[8] = { obj };
    for (int i = 0; i < n; i++) a[1 + i] = args[i];
    return hle_call_guest(MEM32(MEM32(obj) + 4u * (uint32_t)slot), n + 1, a);
}
#define P(x) ((uint32_t)(uintptr_t)(x))
static void wide(uint16_t *w, const char *s) { while ((*w++ = (uint8_t)*s++)) {} }

int main(void) {
    win32hle_register(win32hle_kernel32);
    win32hle_register(win32hle_ole32);
    win32hle_register(win32hle_storage);
    hle_set_drive('Z', "/");
    mach_enter();

    static uint16_t file[64], sub[16], small[16], big[16];
    wide(file, "Z:\\tmp\\win32hle_storage.sav");
    wide(sub, "Scenario"), wide(small, "Header"), wide(big, "Data");
    static uint8_t bigdata[10000];
    for (int i = 0; i < (int)sizeof bigdata; i++) bigdata[i] = (uint8_t)(i * 7);
    static const char hello[] = "Tiberian Sun save";

    uint32_t stg = 0, s2 = 0, stm = 0, n = 0;
    uint32_t a[6] = { P(file), 0x1012u /* CREATE | READWRITE | SHARE_EXCLUSIVE */, 0, P(&stg) };
    ok("StgCreateDocfile", call("StgCreateDocfile", 4, a) == 0 && stg);
    uint32_t cs[5] = { P(sub), 0x12u, 0, 0, P(&s2) };
    ok("CreateStorage", vcall(stg, 5, 5, cs) == 0 && s2);
    uint32_t c1[5] = { P(small), 0x12u, 0, 0, P(&stm) };
    ok("CreateStream small", vcall(s2, 3, 5, c1) == 0 && stm);
    uint32_t w1[3] = { P(hello), sizeof hello, P(&n) };
    ok("Write small", vcall(stm, 4, 3, w1) == 0 && n == sizeof hello);
    vcall(stm, 2, 0, NULL);
    uint32_t c2[5] = { P(big), 0x12u, 0, 0, P(&stm) };
    ok("CreateStream big", vcall(s2, 3, 5, c2) == 0 && stm);
    uint32_t w2[3] = { P(bigdata), sizeof bigdata, P(&n) };
    ok("Write big", vcall(stm, 4, 3, w2) == 0 && n == sizeof bigdata);
    vcall(stm, 2, 0, NULL);
    vcall(s2, 2, 0, NULL);
    vcall(stg, 2, 0, NULL);                              /* the last release writes the file */

    uint32_t o[6] = { P(file), 0, 0x10u /* READ | SHARE_EXCLUSIVE */, 0, 0, P(&stg) };
    ok("StgOpenStorage", call("StgOpenStorage", 6, o) == 0 && stg);
    uint32_t os[6] = { P(sub), 0, 0x10u, 0, 0, P(&s2) };
    ok("OpenStorage", vcall(stg, 6, 6, os) == 0 && s2);
    static uint8_t back[sizeof bigdata];
    uint32_t r1[5] = { P(small), 0, 0x10u, 0, P(&stm) };
    ok("OpenStream small", vcall(s2, 4, 5, r1) == 0 && stm);
    uint32_t rd[3] = { P(back), sizeof back, P(&n) };
    vcall(stm, 3, 3, rd);
    ok("small read back", n == sizeof hello && !memcmp(back, hello, sizeof hello));
    vcall(stm, 2, 0, NULL);
    uint32_t r2[5] = { P(big), 0, 0x10u, 0, P(&stm) };
    ok("OpenStream big", vcall(s2, 4, 5, r2) == 0 && stm);
    vcall(stm, 3, 3, rd);
    ok("big read back", n == sizeof bigdata && !memcmp(back, bigdata, sizeof bigdata));
    vcall(stm, 2, 0, NULL);
    vcall(s2, 2, 0, NULL);
    vcall(stg, 2, 0, NULL);

    mach_leave();
    if (fails == 0) printf("storage_selftest: all checks passed\n");
    return fails != 0;
}

/*
 * native32 selftest: the bridge's purge measurement and st(0) transfer,
 * without a game. Build from an x86 prompt (vcvarsall x86):
 *
 *   cl /nologo /I. /I..\recomp32 native32_selftest.c native32.c ..\recomp32\image_loader.c ..\recomp32\recomp_trace.c
 *   native32_selftest.exe
 */
#include <stdio.h>
#include <string.h>
#include "native32.h"

const recomp_dispatch_entry_t recomp_dispatch_table[1];
const uint32_t recomp_dispatch_count = 0;
recomp_func_t recomp_lookup_manual(uint32_t va) { (void)va; return NULL; }

static int __stdcall add3(int a, int b, int c) { return a + b * 10 + c * 100; }
static int __cdecl sub2(int a, int b) { return a - b; }
static int __fastcall this_plus(int self, int unused, int x) { (void)unused; return self + x; }
static double __cdecl half(int a) { return a / 2.0; }

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } } while (0)

/* What a lifted `push args...; call [slot]` does: args, dummy ret, ICALL. */
static uint32_t call(void* fn, int n, const uint32_t* args, uint32_t* esp_after) {
    for (int i = n - 1; i >= 0; i--) PUSH32(g_esp, args[i]);
    recomp_func_t f = recomp_lookup_import((uint32_t)(uintptr_t)fn);   /* RECOMP_ICALL, by hand */
    CHECK(f != NULL);
    PUSH32(g_esp, RECOMP_RETADDR);
    f();
    *esp_after = g_esp;
    return g_eax;
}

int main(void) {
    native32_init();
    mach_enter();                       /* a guest stack and TIB for this thread */
    uint32_t esp0 = g_esp, after, eax = 0;

    uint32_t a3[] = {1, 2, 3};
    eax = call(add3, 3, a3, &after);
    CHECK(eax == 321);
    CHECK(after == esp0);               /* stdcall: callee popped 12 */

    g_esp = esp0;
    uint32_t a2[] = {9, 4};
    eax = call(sub2, 2, a2, &after);
    CHECK(eax == 5);
    CHECK(after == esp0 - 8);           /* cdecl: the lifted caller pops its args */

    g_esp = esp0;
    g_ecx = 40; g_edx = 0;              /* fastcall stands in for thiscall's ecx */
    uint32_t a1[] = {2};
    eax = call(this_plus, 1, a1, &after);
    CHECK(eax == 42);
    CHECK(after == esp0);

    g_esp = esp0;
    int top = g_fp_top;
    uint32_t h[] = {7};
    call(half, 1, h, &after);
    CHECK(g_fp_top == top + 1);          /* one value pushed on the lifted x87 */
    CHECK(g_st[0] == 3.5);

    mach_leave();
    printf("native32 selftest: %s\n", fails ? "FAILED" : "ok");
    return fails != 0;
}

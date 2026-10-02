/*
 * pump_selftest.c - proves the message-pump hook drives a guest's own
 * GetMessage loop, SDL-free. A stub hook stands in for the SDL present layer:
 * it posts one WM_KEYDOWN, then WM_QUIT. A synthetic lifted loop calls
 * GetMessageA until it returns 0, and we check it saw exactly one key and then
 * exited — i.e. an empty queue pumped the hook instead of ending the loop.
 *
 * This is the integration the SDL present layer relies on (hle_present_enable
 * sets exactly this hook); here the hook is plain C so the check needs no
 * display. Build -m32.
 */
#define RECOMP_GENERATED_CODE
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include "win32hle.h"

#define WM_QUIT    0x0012u
#define WM_KEYDOWN 0x0100u
#define ENTRY_VA   0x00401000u

static int fails;
static void ok(const char *w, int c) { if (!c) { printf("FAIL %s\n", w); fails++; } }

#define GUEST_PROLOGUE(va) \
    uint32_t _cf = 0; uint32_t _flag_k = FK_NONE; uint32_t _flag_a = 0, _flag_b = 0; RECOMP_ENTER(va)

static uint8_t  g_msg[28];
static uint32_t VA_GetMessageA;
static int      g_keydowns;

/* The stub "present": first empty-queue pump posts a key, the next posts quit. */
static int g_pump_calls;
static void stub_pump(void) {
    g_pump_calls++;
    if (g_pump_calls == 1) hle_post_message(0, WM_KEYDOWN, 0x41 /* 'A' */, 0);
    else                   hle_post_message(0, WM_QUIT, 0, 0);
}

/* The lifted message loop: while (GetMessage(&msg)) count key-downs. */
static void guest_msgloop(void) {
    GUEST_PROLOGUE(ENTRY_VA);
    for (;;) {
        PUSH32(esp, 0); PUSH32(esp, 0); PUSH32(esp, 0); PUSH32(esp, (uint32_t)(uintptr_t)g_msg);
        RECOMP_ICALL(VA_GetMessageA);
        if (eax == 0) break;
        if (MEM32((uint32_t)(uintptr_t)g_msg + 4) == WM_KEYDOWN) g_keydowns++;
    }
    eax = 0;
}

const recomp_dispatch_entry_t recomp_dispatch_table[] = { { ENTRY_VA, guest_msgloop } };
const uint32_t recomp_dispatch_count = 1;

int main(void) {
    win32hle_register(win32hle_user32);
    VA_GetMessageA = hle_resolve("GetMessageA");
    ok("GetMessageA resolves", VA_GetMessageA != 0);

    hle_set_pump_hook(stub_pump);

    mach_enter();
    guest_msgloop();
    mach_leave();

    ok("loop pumped the hook until messages arrived", g_pump_calls == 2);
    ok("loop saw exactly one WM_KEYDOWN", g_keydowns == 1);

    if (fails == 0) printf("pump_selftest: all checks passed\n");
    return fails != 0;
}

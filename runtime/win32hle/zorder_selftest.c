/*
 * zorder_selftest.c - sibling z-order: creation order, first on top, until
 * SetWindowPos or BringWindowToTop moves a window. Red Alert 2 raises each
 * dialog it opens with SetWindowPos(HWND_TOP) and then asks GetWindow for the
 * windows above; a raise that did nothing left its mode-change box under the
 * Options screen (redalert2-recomp#24).
 */
#define RECOMP_GENERATED_CODE
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include "win32hle.h"

#define ENTRY_VA 0x00401000u
#define WS_CHILD 0x40000000u
#define GW_HWNDNEXT 2u
#define GW_HWNDPREV 3u
#define GW_CHILD 5u
#define SWP_NOSIZE_NOMOVE 3u
#define SWP_NOZORDER 4u

static int fails;
static void ok(const char *w, int c) { if (!c) { printf("FAIL %s\n", w); fails++; } }

#define GUEST_PROLOGUE(va) \
    uint32_t _cf = 0; uint32_t _flag_k = FK_NONE; uint32_t _flag_a = 0, _flag_b = 0; RECOMP_ENTER(va)

static uint32_t VA_CreateWindowExA, VA_GetWindow, VA_SetWindowPos, VA_BringWindowToTop;
static uint32_t g_args[12], g_nargs, g_fn, g_ret, g_static;   /* g_static: "Static" in guest memory */

/* One stdcall into a shim with g_args, as the lifted code makes it. */
static void guest_call(void) {
    GUEST_PROLOGUE(ENTRY_VA);
    for (int i = (int)g_nargs - 1; i >= 0; i--) PUSH32(esp, g_args[i]);
    RECOMP_ICALL(g_fn);
    g_ret = eax;
}
const recomp_dispatch_entry_t recomp_dispatch_table[] = { { ENTRY_VA, guest_call } };
const uint32_t recomp_dispatch_count = 1;

static uint32_t call(uint32_t fn, int n, const uint32_t *a) {
    for (int i = 0; i < n; i++) g_args[i] = a[i];
    g_fn = fn, g_nargs = (uint32_t)n;
    mach_enter();
    guest_call();
    mach_leave();
    return g_ret;
}
static uint32_t get_window(uint32_t h, uint32_t cmd) { return call(VA_GetWindow, 2, (uint32_t[]){ h, cmd }); }
static void set_window_pos(uint32_t h, uint32_t after, uint32_t flags) {
    call(VA_SetWindowPos, 7, (uint32_t[]){ h, after, 0, 0, 0, 0, flags });
}
static uint32_t create(uint32_t style, uint32_t parent, uint32_t id) {
    return call(VA_CreateWindowExA, 12, (uint32_t[]){ 0, g_static, 0, style, 0, 0, 100, 100, parent, id, 0, 0 });
}

int main(void) {
    win32hle_register(win32hle_user32);
    VA_CreateWindowExA = hle_resolve("CreateWindowExA");
    VA_GetWindow = hle_resolve("GetWindow");
    VA_SetWindowPos = hle_resolve("SetWindowPos");
    VA_BringWindowToTop = hle_resolve("BringWindowToTop");
    ok("the shims resolve", VA_CreateWindowExA && VA_GetWindow && VA_SetWindowPos && VA_BringWindowToTop);
    char *s = hle_alloc(8);
    snprintf(s, 8, "Static");
    g_static = hle_va(s);

    uint32_t main_w = create(0, 0, 0);
    uint32_t a = create(WS_CHILD, main_w, 1), b = create(WS_CHILD, main_w, 2), c = create(WS_CHILD, main_w, 3);
    ok("windows created", main_w && a && b && c);

    ok("first created is the top child", get_window(main_w, GW_CHILD) == a);
    ok("b is below a", get_window(a, GW_HWNDNEXT) == b && get_window(b, GW_HWNDPREV) == a);

    set_window_pos(c, 0 /* HWND_TOP */, SWP_NOSIZE_NOMOVE);
    ok("HWND_TOP raises c", get_window(main_w, GW_CHILD) == c && get_window(c, GW_HWNDPREV) == 0);
    ok("a is now below c", get_window(c, GW_HWNDNEXT) == a);

    set_window_pos(a, 0, SWP_NOSIZE_NOMOVE | SWP_NOZORDER);
    ok("SWP_NOZORDER leaves the order", get_window(main_w, GW_CHILD) == c);

    set_window_pos(c, 1 /* HWND_BOTTOM */, SWP_NOSIZE_NOMOVE);
    ok("HWND_BOTTOM lowers c", get_window(b, GW_HWNDNEXT) == c && get_window(c, GW_HWNDNEXT) == 0);

    set_window_pos(c, a, SWP_NOSIZE_NOMOVE);
    ok("after a puts c between a and b", get_window(a, GW_HWNDNEXT) == c && get_window(c, GW_HWNDNEXT) == b);

    call(VA_BringWindowToTop, 1, (uint32_t[]){ b });
    ok("BringWindowToTop raises b", get_window(main_w, GW_CHILD) == b && get_window(b, GW_HWNDNEXT) == a);

    if (fails == 0) printf("zorder_selftest: all checks passed\n");
    return fails != 0;
}

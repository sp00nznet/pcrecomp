/*
 * win32hle_selftest.c - exercises the host spine and the shim ABI with a
 * hand-written synthetic "guest" in the global-register lifted style, so the
 * whole guest<->native<->guest path is proven with no game binary and no
 * display. This is the win32hle CI green signal (build -m32, run).
 *
 * The guest functions below are what the lifter emits by hand: they drive g_esp
 * and g_eax directly, push stdcall arguments, and call imports through
 * RECOMP_ICALL against a synthetic shim VA. A real lift produces thousands of
 * these; three are enough to check the contract.
 */
#define RECOMP_GENERATED_CODE   /* make eax/esp/... alias the g_* register file */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "win32hle.h"

static int fails;
static void ok(const char *what, int cond) {
    if (!cond) { printf("FAIL %s\n", what); fails++; }
}

/* The per-function prologue the lifter emits (lift32.py): the flag locals the
 * RECOMP_FLAGS_IN/OUT in RECOMP_ENTER/RECOMP_ICALL read and write, then
 * RECOMP_ENTER to publish g_cur_func and import the caller's flags. */
#define GUEST_PROLOGUE(va)              \
    uint32_t _cf = 0;                   \
    uint32_t _flag_k = FK_NONE;         \
    uint32_t _flag_a = 0, _flag_b = 0;  \
    RECOMP_ENTER(va)

/* Resolved shim VAs, filled in main() before any guest runs. */
static uint32_t VA_HeapAlloc, VA_lstrlenA, VA_GetTickCount;
static uint32_t VA_CreateDIBSection, VA_StretchDIBits;
#define VA_ADD 0x00401000u   /* guest_add's dispatch VA (callback target) */

/* host framebuffer the DIB blits land on, and the guest's drawing scratch */
#define FB_W 8
#define FB_H 8
static uint32_t g_fb[FB_W * FB_H];
void hle_gdi_set_target(uint32_t *pixels, int w, int h);

static uint8_t  g_bmi[40];       /* BITMAPINFOHEADER: 4x4, top-down, 32bpp */
static uint32_t g_dibbits_slot;  /* CreateDIBSection writes the pixel ptr here */
static uint32_t src_pixel(int x, int y) { return 0xFF000000u | (uint32_t)((x << 4) | y); }

/* guest: p = HeapAlloc(heap, 0, 64); for (i<16) p[i]=i*i; return p;
 * stdcall args pushed right-to-left, then RECOMP_ICALL pushes the ret addr. */
static void guest_alloc_and_fill(void) {
    GUEST_PROLOGUE(0x00402000u);
    uint32_t heap = 1;
    PUSH32(esp, 64);            /* size  (arg2) */
    PUSH32(esp, 0);             /* flags (arg1) */
    PUSH32(esp, heap);          /* hHeap (arg0) */
    RECOMP_ICALL(VA_HeapAlloc);
    uint32_t p = eax;
    for (uint32_t i = 0; i < 16; i++) MEM32(p + 4 * i) = i * i;
    eax = p;                    /* return the pointer */
}

/* guest: return lstrlenA(str), str passed in esi by the caller. */
static void guest_strlen(void) {
    GUEST_PROLOGUE(0x00402100u);
    PUSH32(esp, esi);           /* lpString (arg0) */
    RECOMP_ICALL(VA_lstrlenA);
    /* eax already holds the length */
}

/* guest: build a 4x4 top-down 32bpp DIB, draw a pattern into it, and
 * StretchDIBits it 2x into the 8x8 framebuffer. Mirrors a software renderer's
 * frame: draw into DIB bits, blit to the device. */
static void guest_draw(void) {
    GUEST_PROLOGUE(0x00402200u);
    /* CreateDIBSection(hdc=0, &bmi, usage=0, &bits_slot, hSection=0, offset=0) */
    PUSH32(esp, 0);                                   /* offset   */
    PUSH32(esp, 0);                                   /* hSection */
    PUSH32(esp, (uint32_t)(uintptr_t)&g_dibbits_slot);/* ppvBits  */
    PUSH32(esp, 0);                                   /* usage    */
    PUSH32(esp, (uint32_t)(uintptr_t)g_bmi);          /* pbmi     */
    PUSH32(esp, 0);                                   /* hdc      */
    RECOMP_ICALL(VA_CreateDIBSection);
    uint32_t bits = g_dibbits_slot;
    for (uint32_t y = 0; y < 4; y++)
        for (uint32_t x = 0; x < 4; x++)
            MEM32(bits + 4 * (y * 4 + x)) = src_pixel((int)x, (int)y);

    /* StretchDIBits(hdc,0,0,8,8, 0,0,4,4, bits, &bmi, 0, SRCCOPY=0xCC0020) */
    PUSH32(esp, 0x00CC0020u);                         /* rop     */
    PUSH32(esp, 0);                                   /* usage   */
    PUSH32(esp, (uint32_t)(uintptr_t)g_bmi);          /* bmi     */
    PUSH32(esp, bits);                                /* bits    */
    PUSH32(esp, 4); PUSH32(esp, 4);                   /* hS, wS  (pushed hS then wS) */
    PUSH32(esp, 0); PUSH32(esp, 0);                   /* yS, xS  */
    PUSH32(esp, 8); PUSH32(esp, 8);                   /* hD, wD  */
    PUSH32(esp, 0); PUSH32(esp, 0);                   /* yD, xD  */
    PUSH32(esp, 0);                                   /* hdc     */
    RECOMP_ICALL(VA_StretchDIBits);
}

/* guest callback: int add(int a, int b) in stdcall. Reads its two args off the
 * stack (ret addr at esp), returns a+b, and pops them (ret 8). */
static void guest_add(void) {
    GUEST_PROLOGUE(VA_ADD);
    uint32_t a = MEM32(esp + 4), b = MEM32(esp + 8);
    eax = a + b;
    esp += 4 + 8;               /* pop ret addr + 2 args (callee cleans: stdcall) */
}

/* Dispatch table the host searches (sorted by address). guest_add is reachable
 * as a callback through hle_call_guest. */
const recomp_dispatch_entry_t recomp_dispatch_table[] = {
    { VA_ADD, guest_add },
};
const uint32_t recomp_dispatch_count = 1;

int main(void) {
    win32hle_register(win32hle_kernel32);
    win32hle_register(win32hle_gdi32);
    VA_HeapAlloc       = hle_resolve("HeapAlloc");
    VA_lstrlenA        = hle_resolve("lstrlenA");
    VA_GetTickCount    = hle_resolve("GetTickCount");
    VA_CreateDIBSection= hle_resolve("CreateDIBSection");
    VA_StretchDIBits   = hle_resolve("StretchDIBits");
    ok("HeapAlloc resolves",    VA_HeapAlloc != 0);
    ok("lstrlenA resolves",     VA_lstrlenA != 0);
    ok("GetTickCount resolves", VA_GetTickCount != 0);
    ok("gdi32 resolves",        VA_CreateDIBSection != 0 && VA_StretchDIBits != 0);
    ok("unknown import is 0",   hle_resolve("NoSuchApi") == 0);
    ok("hle_name round-trips",  hle_name(VA_HeapAlloc) && !strcmp(hle_name(VA_HeapAlloc), "HeapAlloc"));

    /* BITMAPINFOHEADER: 4x4, top-down (negative height), 32bpp BI_RGB. */
    g_bmi[0]=40;                                 /* biSize */
    g_bmi[4]=4;                                  /* biWidth = 4 */
    { int32_t h=-4; memcpy(g_bmi+8,&h,4); }      /* biHeight = -4 (top-down) */
    g_bmi[12]=1;                                 /* biPlanes */
    g_bmi[14]=32;                                /* biBitCount */
    hle_gdi_set_target(g_fb, FB_W, FB_H);

    mach_enter();   /* claim the register file / establish this thread's stack+TIB */

    /* 1. guest -> shim: HeapAlloc + fill, check eax and memory. */
    guest_alloc_and_fill();
    uint32_t p = eax;
    ok("HeapAlloc returned memory", p != 0);
    int mem_ok = 1;
    for (uint32_t i = 0; i < 16; i++) if (MEM32(p + 4 * i) != i * i) mem_ok = 0;
    ok("guest wrote through the heap block", mem_ok);

    /* 2. guest -> shim with a pointer arg: lstrlenA. */
    static const char msg[] = "win32hle";
    esi = (uint32_t)(uintptr_t)msg;
    guest_strlen();
    ok("lstrlenA counted the string", eax == strlen(msg));

    /* 3. the register file is serialised and fs: points at a TIB. */
    ok("TIB self at fs:[0x18]", MEM32(FS_BASE + 0x18) == FS_BASE && FS_BASE != 0);

    /* 4. the renderer seam: guest draws a DIB and StretchDIBits-blits it 2x into
     * the framebuffer. Each source pixel (x,y) must land in the 2x2 block at
     * (2x,2y) (top-down, nearest-neighbour). */
    guest_draw();
    int blit_ok = 1;
    for (int fy = 0; fy < FB_H; fy++)
        for (int fx = 0; fx < FB_W; fx++)
            if (g_fb[fy * FB_W + fx] != src_pixel(fx / 2, fy / 2)) blit_ok = 0;
    ok("StretchDIBits scaled the DIB into the framebuffer", blit_ok);

    mach_leave();

    /* 5. native -> guest: call guest_add(40, 2) through the explicit path. */
    uint32_t args[2] = { 40, 2 };
    ok("hle_call_guest ran the callback", hle_call_guest(VA_ADD, 2, args) == 42);

    if (fails == 0) printf("win32hle_selftest: all checks passed\n");
    return fails != 0;
}

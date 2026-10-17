/*
 * gdi_selftest.c - a GDI game's drawing path and a RIFF read, through the
 * shims as a guest calls them (hle_call_guest on their import VAs):
 *
 *   - a 16-bit 5-5-5 bottom-up DIB section, selected into a memory DC and
 *     BitBlt to a window DC, lands in the window surface the right way up
 *     and converted to 32-bit, and a clip region keeps a column out;
 *   - mmioDescend finds a RIFF form and a chunk in it, mmioRead reads it.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "win32hle.h"
#include "host.h"

static int fails;
static void ok(const char *what, int cond) { if (!cond) { printf("FAIL %s\n", what); fails++; } }
static uint32_t call(const char *name, int n, const uint32_t *a) { return hle_call_guest(hle_resolve(name), n, a); }
#define A(p) ((uint32_t)(uintptr_t)(p))

const recomp_dispatch_entry_t recomp_dispatch_table[1];
const uint32_t recomp_dispatch_count = 0;

int main(void) {
    recomp_host_init();

    /* the screen: 4x2, 32-bit */
    static uint32_t screen[4 * 2];
    hle_gdi_window_surface((uint8_t *)screen, 4, 2, 16, 32);

    /* a 2x2 BI_RGB 16bpp DIB: bottom-up, so its first row in memory is the bottom one */
    static uint8_t bmi[40];
    bmi[0] = 40, bmi[4] = 2, bmi[8] = 2, bmi[12] = 1, bmi[14] = 16;
    static uint32_t bits;
    uint32_t a1[6] = { 0, A(bmi), 0, A(&bits), 0, 0 };
    uint32_t dib = call("CreateDIBSection", 6, a1);
    ok("CreateDIBSection", dib && bits);
    uint16_t *px = (uint16_t *)(uintptr_t)bits;          /* rows are 4 bytes: 2 pixels */
    px[0] = 0x7C00, px[1] = 0x03E0;                       /* bottom row: red, green */
    px[2] = 0x001F, px[3] = 0x7FFF;                       /* top row: blue, white */

    uint32_t z = 0;
    uint32_t mem = call("CreateCompatibleDC", 1, &z);
    uint32_t a2[2] = { mem, dib };
    call("SelectObject", 2, a2);
    uint32_t win = call("GetDC", 1, &z);
    uint32_t a3[9] = { win, 1, 0, 2, 2, mem, 0, 0, 0x00CC0020u };   /* SRCCOPY to (1,0) */
    call("BitBlt", 9, a3);
    ok("top row blue", screen[1] == 0x0000FF);
    ok("top row white", screen[2] == 0xFFFFFF);
    ok("bottom row red", screen[4 + 1] == 0xFF0000);
    ok("bottom row green", screen[4 + 2] == 0x00FF00);
    ok("left of the blit untouched", screen[0] == 0 && screen[4] == 0);

    /* clip to x < 2: the second column stays */
    memset(screen, 0, sizeof screen);
    static uint32_t rc[4] = { 0, 0, 2, 2 };
    uint32_t rgn = call("CreateRectRgnIndirect", 1, (uint32_t[]){ A(rc) });
    call("SelectClipRgn", 2, (uint32_t[]){ win, rgn });
    call("BitBlt", 9, a3);
    ok("clipped: inside", screen[1] == 0x0000FF);
    ok("clipped: outside", screen[2] == 0);

    /* RIFF: "RIFF" n "WAVE" "fmt " 4 [1 2 3 4] "data" 2 [9 9] */
    static const uint8_t riff[] = { 'R','I','F','F', 26,0,0,0, 'W','A','V','E', 'f','m','t',' ', 4,0,0,0, 1,2,3,4,
                                    'd','a','t','a', 2,0,0,0, 9,9 };
    FILE *f = fopen("/tmp/hle_selftest.wav", "wb");
    fwrite(riff, 1, sizeof riff, f);
    fclose(f);
    hle_set_drive('Z', "/");
    uint32_t h = call("mmioOpenA", 3, (uint32_t[]){ A("Z:\\tmp\\hle_selftest.wav"), 0, 0 });
    ok("mmioOpenA", h != 0);
    static uint32_t form[5], ck[5];
    form[2] = 0x45564157u;                               /* 'WAVE' */
    ok("descend RIFF WAVE", call("mmioDescend", 4, (uint32_t[]){ h, A(form), 0, 0x20 }) == 0);
    ck[0] = 0x61746164u;                                 /* 'data': past 'fmt ' */
    ok("find data", call("mmioDescend", 4, (uint32_t[]){ h, A(ck), A(form), 0x10 }) == 0 && ck[1] == 2);
    static uint8_t got[4];
    ok("read data", call("mmioRead", 3, (uint32_t[]){ h, A(got), 4 }) == 2 && got[0] == 9 && got[1] == 9);
    call("mmioClose", 2, (uint32_t[]){ h, 0 });

    printf("%s: %d failure(s)\n", fails ? "FAIL" : "ok", fails);
    return fails != 0;
}

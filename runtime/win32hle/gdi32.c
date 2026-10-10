/*
 * gdi32.c - win32hle GDI subset: the DIB-and-blit path a software-rendered
 * Win32 game draws through (Fury3: CreateDIBSection + StretchBlt; many others:
 * StretchDIBits). It is pure pixel work against a host framebuffer, so it needs
 * no SDL and runs headless; presenting that framebuffer in a window is the
 * user32/SDL layer's job (deferred until 32-bit SDL2 is in).
 *
 * Supports 32bpp BI_RGB DIBs, top-down or bottom-up, scaled with
 * nearest-neighbour. 8/16/24bpp and palettes come with the palette layer.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "win32hle.h"

/* The destination the game's blits land on: a host-owned ARGB8888 framebuffer.
 * The host (or the selftest) sets it; user32's present copies it to a texture. */
static uint32_t *g_fb;
static int g_fb_w, g_fb_h;
void hle_gdi_set_target(uint32_t *pixels, int w, int h) { g_fb = pixels; g_fb_w = w; g_fb_h = h; }

/* The present layer reads the framebuffer to show it. */
const uint32_t *hle_gdi_framebuffer(int *w, int *h) {
    if (w) *w = g_fb_w;
    if (h) *h = g_fb_h;
    return g_fb;
}

/* BITMAPINFOHEADER is 40 bytes of little-endian fields; read by offset so no
 * windows.h struct is needed. Negative height means a top-down DIB. */
static int32_t  bi_w(const uint8_t *b)   { return (int32_t)(b[4] | b[5]<<8 | b[6]<<16 | (uint32_t)b[7]<<24); }
static int32_t  bi_h(const uint8_t *b)   { return (int32_t)(b[8] | b[9]<<8 | b[10]<<16 | (uint32_t)b[11]<<24); }
static uint16_t bi_bpp(const uint8_t *b) { return (uint16_t)(b[14] | b[15]<<8); }

/* A CreateDIBSection handle: the pixel buffer and its geometry. */
#define MAX_DIBS 256
static struct { uint32_t h; uint32_t *bits; int w, h_abs, topdown; } g_dibs[MAX_DIBS];
static int g_dib_n;
static uint32_t g_next_handle = 0xD1B00001u;

/* CreateDIBSection(hdc, pbmi, usage, ppvBits, hSection, offset): allocate the
 * pixel array, hand the guest its pointer through *ppvBits, return an HBITMAP. */
static void g_CreateDIBSection(void) {
    const uint8_t *bmi = (const uint8_t *)APTR(1);
    uint32_t *ppv = (uint32_t *)APTR(3);
    int w = bi_w(bmi), h = bi_h(bmi), bpp = bi_bpp(bmi);
    int hab = h < 0 ? -h : h;
    /* any depth gets its pixels (rows are DWORD-aligned); only 32bpp blits */
    uint32_t *bits = (uint32_t *)calloc((size_t)((w * bpp + 31) / 32) * hab + 1, 4);
    if (g_dib_n < MAX_DIBS) {
        g_dibs[g_dib_n].h = g_next_handle;
        g_dibs[g_dib_n].bits = bits; g_dibs[g_dib_n].w = w;
        g_dibs[g_dib_n].h_abs = hab; g_dibs[g_dib_n].topdown = h < 0;
        g_dib_n++;
    }
    if (ppv) *ppv = (uint32_t)(uintptr_t)bits;   /* the guest draws straight into this */
    RET(g_next_handle++, 6);
}

/* Nearest-neighbour blit of a wSrc x hSrc ARGB block into the framebuffer at
 * (xDst,yDst), scaled to wDst x hDst, clipped to the framebuffer. `src` is the
 * DIB's top row for a top-down DIB, else its bottom row. */
static void blit_scaled(const uint32_t *src, int sw, int sh, int topdown,
                        int xd, int yd, int wd, int hd) {
    if (!g_fb || wd <= 0 || hd <= 0 || sw <= 0 || sh <= 0) return;
    for (int dy = 0; dy < hd; dy++) {
        int fy = yd + dy; if (fy < 0 || fy >= g_fb_h) continue;
        int sy = dy * sh / hd; if (!topdown) sy = sh - 1 - sy;
        const uint32_t *srow = src + (size_t)sy * sw;
        uint32_t *drow = g_fb + (size_t)fy * g_fb_w;
        for (int dx = 0; dx < wd; dx++) {
            int fx = xd + dx; if (fx < 0 || fx >= g_fb_w) continue;
            drow[fx] = srow[dx * sw / wd];
        }
    }
}

/* StretchDIBits(hdc, xD,yD,wD,hD, xS,yS,wS,hS, bits, bmi, usage, rop) - 13 args.
 * The common case games use: whole-DIB source, scaled to a destination rect. */
static void g_StretchDIBits(void) {
    int xd=A32(1), yd=A32(2), wd=A32(3), hd=A32(4);
    int ws=A32(7), hs=A32(8);
    const uint32_t *bits = (const uint32_t *)APTR(9);
    const uint8_t  *bmi  = (const uint8_t  *)APTR(10);
    int topdown = bi_h(bmi) < 0;
    int hab = hs < 0 ? -hs : hs;
    blit_scaled(bits, ws, hab, topdown, xd, yd, wd, hd);
    RET((uint32_t)hab, 13);
}

/* CreateCompatibleDC/DeleteDC: handle bookkeeping; the DCs that draw text
 * are gdidc.c's. DeleteObject is gdidc.c's too, and hands DIBs back here. */
static void g_CreateCompatibleDC(void){ RET(0x0DC00002u, 1); }
static void g_DeleteDC(void)          { RET(1, 1); }
int hle_gdi_dib_delete(uint32_t h) {
    for (int i = 0; i < g_dib_n; i++) if (g_dibs[i].h == h && g_dibs[i].bits) { free(g_dibs[i].bits); g_dibs[i].bits = NULL; return 1; }
    return 0;
}

/* GetDeviceCaps(hdc, index): report a plain 32bpp desktop the size of the
 * framebuffer. A software renderer reads these to size its backbuffer and to
 * decide it is NOT a palette device (so it takes the truecolour path). */
static void g_GetDeviceCaps(void) {
    int w, h; (void)hle_gdi_framebuffer(&w, &h);
    uint32_t v;
    switch (A32(1)) {
        case 8:  v = (uint32_t)(w > 0 ? w : 640); break;  /* HORZRES   */
        case 10: v = (uint32_t)(h > 0 ? h : 480); break;  /* VERTRES   */
        case 12: v = 32; break;                           /* BITSPIXEL */
        case 14: v = 1;  break;                           /* PLANES    */
        case 104: v = 0; break;                           /* SIZEPALETTE: not a palette device */
        case 38: v = 0;  break;                           /* RASTERCAPS: no RC_PALETTE */
        default: v = 0;  break;
    }
    RET(v, 2);
}

const win32hle_shim win32hle_gdi32[] = {
    { "GetDeviceCaps",      g_GetDeviceCaps },
    { "CreateDIBSection",   g_CreateDIBSection },
    { "StretchDIBits",      g_StretchDIBits },
    { "CreateCompatibleDC", g_CreateCompatibleDC },
    { "DeleteDC",           g_DeleteDC },
    { 0, 0 }
};

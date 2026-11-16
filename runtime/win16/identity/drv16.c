/* drv16.c - the Win16 drivers KRNL386's own LoadModule loads (SYSTEM.DRV,
 * KEYBOARD.DRV, MOUSE.DRV, DISPLAY.DRV), as stand-ins this file writes at
 * run time into the guest's WINDOWS\SYSTEM. Each is a small NE of our own:
 * one code segment whose bytes are a tag ("PCRD", the driver's index) and a
 * `retf` per entry; no Microsoft bytes. KRNL386 loads it like any library
 * (header, segment, entry table, its LibEntry), and a far call into the
 * segment (dispatch_far: no lifted function there) lands in drv_far, which
 * runs the entry's host function by ordinal. An entry with no host function
 * stops the run with its driver and ordinal. Nothing touches hardware. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "cpu.h"

uint32_t recomp_sel_base(uint32_t selector);
void w16_drv_stop(const char *what, unsigned a, unsigned b);

#define E_LIBENTRY 0x08     /* the NE's cs:ip */
#define E_FIRST    0x10     /* entry n (ordinal) at E_FIRST + 2 * (n - 1) */
#define NORD       140      /* ordinals 1..NORD exported (KEYBOARD goes to 136) */

typedef void (*drv_fn)(CPU *c);
typedef struct { const char *name; drv_fn fn[NORD + 1]; } drv_t;

static uint16_t arg16(CPU *c, int i) { return mem_read16(c, c->ss, (uint16_t)(c->sp + 4 + 2 * i)); }
static void ret_far(CPU *c, int argbytes) { c->sp = (uint16_t)(c->sp + 4 + argbytes); }
static void libentry(CPU *c) { c->ax = 1; ret_far(c, 0); }   /* LibEntry: success, nothing to set up */

static uint32_t argfar(CPU *c, int i) { return (uint32_t)arg16(c, i + 1) << 16 | arg16(c, i); }
static char *farptr(uint32_t p) { return (char *)(uintptr_t)(recomp_sel_base(p >> 16) + (p & 0xFFFF)); }

/* Code-page conversion between the guest's ANSI (1252) and OEM (437) sets: Win98 SE US.
 * ponytail: both fixed; read them off system.ini [boot.description]/the keyboard's tables if another locale turns up. */
static void cp_convert(const char *src, char *dst, int n, UINT from, UINT to) {
    WCHAR w[1024];
    while (n > 0) {
        int k = n > 1024 ? 1024 : n;
        MultiByteToWideChar(from, 0, src, k, w, k);
        WideCharToMultiByte(to, 0, w, k, dst, k, NULL, NULL);
        src += k; dst += k; n -= k;
    }
}
/* KEYBOARD.5 AnsiToOem(LPCSTR src, LPSTR dst) / .6 OemToAnsi: KRNL386 seg1 A5C2 (OpenFile's path)
 * calls them through DGROUP:1250 once the keyboard is loaded; pascal, TRUE back. */
static void kb_xlat(CPU *c, UINT from, UINT to) {
    char *dst = farptr(argfar(c, 0)), *src = farptr(argfar(c, 2));
    cp_convert(src, dst, (int)strlen(src) + 1, from, to);
    c->ax = 0xFFFF; ret_far(c, 8);
}
static void kb_ansi_to_oem(CPU *c) { kb_xlat(c, 1252, 437); }
static void kb_oem_to_ansi(CPU *c) { kb_xlat(c, 437, 1252); }

/* ---- DISPLAY.DRV: a 16-bit DIB framebuffer (pcrecomp's own, no hardware) ----
 * Entries are the Win 3.1 DDK display ordinals, named from GDI.EXE's call
 * sites as each is reached. ponytail: 800x600x16 (5-6-5), no palette (RC_PALETTE
 * off, so no SetPalette/translate traffic); a host window shows g_fb later. */
#define FB_W 800
#define FB_H 600
static uint16_t g_fb[FB_W * FB_H];
static void fb_window(void);
static void put16(char *p, int off, int v) { *(uint16_t *)(p + off) = (uint16_t)v; }
/* DISPLAY.5 Enable(lpDevice, style, lpDestDevType, lpOutputFile, lpData): GDI seg005_26A4 asks
 * with style 1 for GDIINFO into a 7Eh-byte block (it keeps its own words from 78h), then
 * seg005_289F with style 0 for the PDEVICE (dpDEVICEsize bytes it GlobalAllocs). */
#define PDEV_SIZE 0x20
static void disp_enable(CPU *c) {
    char *dev = farptr(argfar(c, 7));
    uint16_t style = arg16(c, 6);
    if (style & 1) {
        memset(dev, 0, 0x6E);
        put16(dev, 0x00, 0x030A);      /* dpVersion 3.10 */
        put16(dev, 0x02, 1);           /* DT_RASDISPLAY */
        put16(dev, 0x04, 208); put16(dev, 0x06, 156);       /* mm */
        put16(dev, 0x08, FB_W); put16(dev, 0x0A, FB_H);
        put16(dev, 0x0C, 16); put16(dev, 0x0E, 1);          /* bits/pixel, planes */
        put16(dev, 0x10, -1); put16(dev, 0x12, 100);         /* brushes, pens */
        put16(dev, 0x16, 0); put16(dev, 0x18, -1);           /* device fonts, colors (more than 256) */
        put16(dev, 0x1A, PDEV_SIZE);
        put16(dev, 0x1C, 0);           /* dpCurves: GDI draws them */
        put16(dev, 0x1E, 0x0002);      /* dpLines: LC_POLYLINE */
        put16(dev, 0x20, 0x0008);      /* dpPolygonals: PC_SCANLINE */
        put16(dev, 0x22, 0x2000);      /* dpText: TC_RA_ABLE (GDI's raster fonts, StrBlt/ExtTextOut) */
        put16(dev, 0x24, 0x0001);      /* dpClip: CP_RECTANGLE */
        put16(dev, 0x26, 0x0699);      /* dpRaster: BITBLT|BITMAP64|GDI20_OUTPUT|DI_BITMAP|DIBTODEV|BIGFONT */
        put16(dev, 0x28, 36); put16(dev, 0x2A, 36); put16(dev, 0x2C, 51); put16(dev, 0x2E, 72);   /* aspect, style len */
        static const int16_t map[20] = { 2080, 1560, 800, -600,  20800, 15600, 800, -600,   /* MM_LOMETRIC, HIMETRIC */
                                         819, 614, 800, -600,  8189, 6142, 800, -600,       /* LOENGLISH, HIENGLISH */
                                         11792, 8844, 800, -600 };                           /* TWIPS */
        memcpy(dev + 0x30, map, sizeof map);
        put16(dev, 0x58, 96); put16(dev, 0x5A, 96);          /* LOGPIXELS */
        put16(dev, 0x5C, 4);           /* dpDCManage: DC_IGNOREDFNP */
        c->ax = 0x6E;
    } else {
        memset(dev, 0, PDEV_SIZE);     /* a BITMAP header, bmType nonzero: the screen */
        put16(dev, 0x00, 0x2000); put16(dev, 0x02, FB_W); put16(dev, 0x04, FB_H); put16(dev, 0x06, FB_W * 2);
        dev[0x08] = 1; dev[0x09] = 16;
        c->ax = 1;
        fb_window();
    }
    if (getenv("W16_TRACE")) fprintf(stderr, "[drv] DISPLAY.Enable style %u -> %04X\n", style, c->ax);
    ret_far(c, 18);
}

/* DISPLAY.3 Control(lpDevice, wFunction, lpInData, lpOutData): escapes (GDI seg005_2AB6
 * right after Enable). ponytail: none supported, 0 for all (QUERYESCSUPPORT included). */
static void disp_control(CPU *c) {
    if (getenv("W16_TRACE")) fprintf(stderr, "[drv] DISPLAY.Control %u -> 0\n", arg16(c, 4));
    c->ax = 0; c->dx = 0; ret_far(c, 14);
}

/* DISPLAY.2 ColorInfo(lpDevice, DWORD color, LPDWORD lpPhys) -> dx:ax RGB (GDI seg005_1B99):
 * with lpPhys, RGB -> the 5-6-5 physical color stored there, and the RGB that shows;
 * without, physical -> RGB. */
static uint16_t rgb565(uint32_t rgb) { return (uint16_t)(((rgb & 0xF8) << 8) | ((rgb >> 5) & 0x7E0) | ((rgb >> 19) & 0x1F)); }
static uint32_t rgb_of(uint16_t p) {
    uint32_t r = (p >> 11) & 31, g = (p >> 5) & 63, b = p & 31;
    return (r << 3 | r >> 2) | (g << 2 | g >> 4) << 8 | (b << 3 | b >> 2) << 16;
}
static void disp_colorinfo(CPU *c) {
    uint32_t col = argfar(c, 2), lp = argfar(c, 0), rgb;
    if (lp) { uint16_t p = rgb565(col); *(uint32_t *)farptr(lp) = p; rgb = rgb_of(p); }
    else rgb = rgb_of((uint16_t)col);
    c->ax = (uint16_t)rgb; c->dx = (uint16_t)(rgb >> 16); ret_far(c, 12);
}

/* DISPLAY.10 RealizeObject(lpDevice, style, lpIn, lpOut, lpTextXForm) (GDI seg005_5263):
 * lpOut 0 asks the physical size. Pens: {style, width, color}; brushes: {style, hatch,
 * color, bk, 8x8 pattern}; style < 0 deletes (nothing to free); fonts 0: GDI realizes its
 * own raster fonts (dpNumFonts 0). ponytail: hatched and pattern brushes fill solid in their color. */
typedef struct { uint16_t style, width, color, pad; } ppen_t;
typedef struct { uint16_t style, hatch, color, bk; uint16_t pat[64]; } pbrush_t;
static void disp_realize(CPU *c) {
    int16_t style = (int16_t)arg16(c, 6);
    uint32_t in = argfar(c, 4), out = argfar(c, 2);
    int sz = style == 1 ? (int)sizeof(ppen_t) : style == 2 ? (int)sizeof(pbrush_t) : 0;
    if (style > 0 && out && sz) {
        const uint8_t *li = (const uint8_t *)farptr(in);
        if (style == 1) {
            ppen_t *p = (ppen_t *)farptr(out);
            p->style = *(const uint16_t *)li; p->width = *(const uint16_t *)(li + 2);
            p->color = rgb565(*(const uint32_t *)(li + 6)); p->pad = 0;
        } else {
            pbrush_t *b = (pbrush_t *)farptr(out);
            b->style = *(const uint16_t *)li; b->color = rgb565(*(const uint32_t *)(li + 2));
            b->hatch = *(const uint16_t *)(li + 6); b->bk = 0xFFFF;
            for (int i = 0; i < 64; i++) b->pat[i] = b->color;
            if (b->style > 1 && getenv("W16_TRACE")) fprintf(stderr, "[drv] DISPLAY brush style %u: solid\n", b->style);
        }
    }
    c->ax = (uint16_t)(style > 0 ? sz : 1); c->dx = 0;
    ret_far(c, 18);
}

/* A destination: the screen's PDEVICE (bmType nonzero) or a GDI memory bitmap (a PBITMAP:
 * type, width, height, widthbytes, planes, bitspixel, bits far ptr at 0Ah). 1 and 16 bpp.
 * ponytail: no huge (>64K, segmented) bitmaps. */
typedef struct { uint8_t *bits; int w, h, pitch, bpp; } surf_t;
static int surf_of(uint32_t lp, surf_t *s) {
    const uint8_t *b = (const uint8_t *)farptr(lp);
    if (*(const uint16_t *)b) { s->bits = (uint8_t *)g_fb; s->w = FB_W; s->h = FB_H; s->pitch = FB_W * 2; s->bpp = 16; return 1; }
    s->w = *(const int16_t *)(b + 2); s->h = *(const int16_t *)(b + 4); s->pitch = *(const uint16_t *)(b + 6);
    s->bpp = b[9] * b[8]; s->bits = (uint8_t *)farptr(*(const uint32_t *)(b + 10));
    return s->bpp == 16 || s->bpp == 1;
}
/* A pixel in a 1-bpp bitmap is 1 where the color is white (the background), as GDI's mono rule. */
static void surf_put(surf_t *s, int x, int y, uint16_t col) {
    if (x < 0 || y < 0 || x >= s->w || y >= s->h) return;
    if (s->bpp == 16) { *(uint16_t *)(s->bits + y * s->pitch + x * 2) = col; return; }
    uint8_t *p = s->bits + y * s->pitch + (x >> 3), m = (uint8_t)(0x80 >> (x & 7));
    if (col == 0xFFFF) *p |= m; else *p &= (uint8_t)~m;
}
static uint16_t surf_get(surf_t *s, int x, int y) {
    if (x < 0 || y < 0 || x >= s->w || y >= s->h) return 0;
    if (s->bpp == 16) return *(uint16_t *)(s->bits + y * s->pitch + x * 2);
    return (s->bits[y * s->pitch + (x >> 3)] & (0x80 >> (x & 7))) ? 0xFFFF : 0;
}
typedef struct { int16_t l, t, r, b; } rect16;
static void surf_fill(surf_t *s, int l, int t, int r, int b, uint16_t col) {
    for (int y = t; y < b; y++) for (int x = l; x < r; x++) surf_put(s, x, y, col);
}

/* DISPLAY.14 ExtTextOut(lpDestDev, x, y, lpClipRect, lpString, count, lpFontInfo, lpDrawMode,
 * lpTextXForm, lpCharWidths, lpOpaqueRect, options), GDI seg005_5FB0: count < 0 asks the
 * extent only; dx:ax = height:width. Raster fonts as GDI hands them (FONTINFO = the .FNT
 * header from dfType on; 2.0 char table of {width, offset} words at 34h, 3.0 {width, dword
 * offset} at 52h; glyphs column-major bytes, offsets from the file's start, 66 bytes before
 * FONTINFO). DRAWMODE: bkMode at 2 (2 opaque), bkColor 4, TextColor 8 (physical). */
static void disp_exttextout(CPU *c) {
    uint16_t opts = arg16(c, 0);
    uint32_t lpopaque = argfar(c, 1), lpwidths = argfar(c, 3), lpdm = argfar(c, 7), lpfont = argfar(c, 9);
    int16_t count = (int16_t)arg16(c, 11);
    uint32_t lpstr = argfar(c, 12), lpclip = argfar(c, 14);
    int16_t y0 = (int16_t)arg16(c, 16), x0 = (int16_t)arg16(c, 17);
    uint32_t lpdev = argfar(c, 18);
    const uint8_t *fi = (const uint8_t *)farptr(lpfont);
    int h = *(const uint16_t *)(fi + 22), first = fi[29], last = fi[30], dflt = fi[31];
    int v3 = (*(const uint32_t *)(fi + 52) & 0x0F) != 0;   /* dfFlags DFF_FIXED/PROPORTIONAL/... */
    const uint8_t *base = fi - 66;
    int n = count < 0 ? -count : count, width = 0;
    const uint8_t *str = (const uint8_t *)farptr(lpstr);
    surf_t s; int draw = count > 0 && surf_of(lpdev, &s);
    rect16 clip = { 0, 0, 0x7FFF, 0x7FFF };
    if (lpclip) clip = *(const rect16 *)farptr(lpclip);
    const uint8_t *dm = lpdm ? (const uint8_t *)farptr(lpdm) : NULL;
    uint16_t fg = dm ? *(const uint16_t *)(dm + 8) : 0, bg = dm ? *(const uint16_t *)(dm + 4) : 0xFFFF;
    int opaque = dm && *(const uint16_t *)(dm + 2) == 2;
    if (draw && lpopaque && (opts & 2)) {   /* ETO_OPAQUE */
        rect16 r = *(const rect16 *)farptr(lpopaque);
        surf_fill(&s, max(r.l, clip.l), max(r.t, clip.t), min(r.r, clip.r), min(r.b, clip.b), bg);
    }
    for (int i = 0; i < n; i++) {
        int ch = str[i];
        if (ch < first || ch > last) ch = dflt + first;
        int k = ch - first, cw; uint32_t off;
        if (v3) { const uint8_t *e = fi + 82 + 6 * k; cw = *(const uint16_t *)e; off = *(const uint32_t *)(e + 2); }
        else { const uint8_t *e = fi + 52 + 4 * k; cw = *(const uint16_t *)e; off = *(const uint16_t *)(e + 2); }
        int adv = lpwidths ? ((const int16_t *)farptr(lpwidths))[i] : cw;
        if (draw) {
            const uint8_t *g = base + off;
            for (int x = 0; x < cw; x++) for (int y = 0; y < h; y++) {
                int px = x0 + width + x, py = y0 + y;
                if (px < clip.l || px >= clip.r || py < clip.t || py >= clip.b) continue;
                int on = g[(x >> 3) * h + y] & (0x80 >> (x & 7));
                if (on) surf_put(&s, px, py, fg); else if (opaque) surf_put(&s, px, py, bg);
            }
        }
        width += adv;
    }
    if (getenv("W16_TRACE")) fprintf(stderr, "[drv] DISPLAY.ExtTextOut %d,%d n %d \"%.*s\" -> %dx%d v%d\n", x0, y0, count, n, str, width, h, v3 ? 3 : 2);
    c->ax = (uint16_t)width; c->dx = (uint16_t)h; ret_far(c, 40);
}

/* Raster ops, bitwise over 16-bit pixels (a mono surface holds 0/FFFF per pixel):
 * ROP2 code r (1..16) gives bit (P<<1|D) of r-1; ROP3 byte c gives bit (P<<2|S<<1|D). */
static uint16_t rop2(int r, uint16_t p, uint16_t d) {
    unsigned c = (unsigned)(r - 1) & 15; uint16_t v = 0;
    for (int i = 0; i < 4; i++) if (c >> i & 1) v |= (uint16_t)(((i & 2) ? p : ~p) & ((i & 1) ? d : ~d));
    return v;
}
static uint16_t rop3(unsigned c, uint16_t p, uint16_t s, uint16_t d) {
    uint16_t v = 0;
    for (int i = 0; i < 8; i++) if (c >> i & 1) v |= (uint16_t)(((i & 4) ? p : ~p) & ((i & 2) ? s : ~s) & ((i & 1) ? d : ~d));
    return v;
}
/* A brush's color at a pixel (8x8 pattern), or 0 for none; pens {style, width, color}. */
static uint16_t brush_at(const pbrush_t *b, int x, int y) { return b ? b->pat[(y & 7) * 8 + (x & 7)] : 0; }
/* A color for a surface: on a mono one, white is 1 (FFFF), anything else 0. */
static uint16_t for_surf(const surf_t *s, uint16_t col) { return s->bpp == 1 ? (col == 0xFFFF ? 0xFFFF : 0) : col; }

/* DISPLAY.1 BitBlt(lpDestDev, dx, dy, lpSrcDev, sx, sy, w, h, rop3, lpPBrush, lpDrawMode)
 * (GDI seg005_5FB0). Mono source into color: 1 -> the DRAWMODE background, 0 -> text
 * color; color into mono: background color -> 1. Overlap goes through a copy. */
static void disp_bitblt(CPU *c) {
    uint32_t lpdm = argfar(c, 0), lpbr = argfar(c, 2), rop = argfar(c, 4);
    int h = (int16_t)arg16(c, 6), w = (int16_t)arg16(c, 7), sy = (int16_t)arg16(c, 8), sx = (int16_t)arg16(c, 9);
    uint32_t lpsrc = argfar(c, 10);
    int dy = (int16_t)arg16(c, 12), dx = (int16_t)arg16(c, 13);
    uint32_t lpdst = argfar(c, 14);
    unsigned code = (rop >> 16) & 0xFF;
    surf_t d, s; int hs = 0;
    const pbrush_t *br = lpbr ? (const pbrush_t *)farptr(lpbr) : NULL;
    const uint8_t *dm = lpdm ? (const uint8_t *)farptr(lpdm) : NULL;
    uint16_t bk = dm ? *(const uint16_t *)(dm + 4) : 0xFFFF, fg = dm ? *(const uint16_t *)(dm + 8) : 0;
    if (!surf_of(lpdst, &d)) { c->ax = 0; ret_far(c, 32); return; }
    if (lpsrc && ((code >> 2) ^ code) & 0x33) hs = surf_of(lpsrc, &s);   /* the rop reads S */
    uint16_t *tmp = NULL;
    if (hs) {   /* the source block, as destination-format pixels */
        tmp = (uint16_t *)malloc((size_t)(w > 0 ? w : 1) * (h > 0 ? h : 1) * 2);
        for (int y = 0; y < h; y++) for (int x = 0; x < w; x++) {
            uint16_t v = surf_get(&s, sx + x, sy + y);
            if (s.bpp == 1 && d.bpp == 16) v = v ? bk : fg;
            else if (s.bpp == 16 && d.bpp == 1) v = v == bk ? 0xFFFF : 0;
            tmp[y * w + x] = v;
        }
    }
    for (int y = 0; y < h; y++) for (int x = 0; x < w; x++) {
        int px = dx + x, py = dy + y;
        uint16_t sv = tmp ? tmp[y * w + x] : 0;
        surf_put(&d, px, py, rop3(code, for_surf(&d, brush_at(br, px, py)), sv, surf_get(&d, px, py)));
    }
    free(tmp);
    if (getenv("W16_TRACE")) fprintf(stderr, "[drv] DISPLAY.BitBlt %d,%d %dx%d rop %02X src %s %s\n", dx, dy, w, h, code, hs ? "yes" : "no",
                                         d.bits == (uint8_t *)g_fb ? "screen" : d.bpp == 1 ? "mono" : "bitmap");
    c->ax = 1; ret_far(c, 32);
}

/* DISPLAY.8 Output(lpDestDev, style, count, lpPoints, lpPPen, lpPBrush, lpDrawMode, lpClipRect):
 * what dpLines/dpPolygonals ask for, OS_POLYLINE 18 (the pen, ROP2) and OS_SCANLINES 4
 * (points[0].y the row, then {x1, x2} pairs filled with the brush, or the pen if no brush).
 * ponytail: 1-pixel pens, no styles (dashes draw solid); others answer -1 (GDI simulates). */
static void line_px(surf_t *s, const rect16 *cl, int x, int y, int r2, uint16_t col) {
    if (cl && (x < cl->l || x >= cl->r || y < cl->t || y >= cl->b)) return;
    surf_put(s, x, y, rop2(r2, col, surf_get(s, x, y)));
}
static void disp_output(CPU *c) {
    uint32_t lpclip = argfar(c, 0), lpdm = argfar(c, 2), lpbr = argfar(c, 4), lppen = argfar(c, 6), lppts = argfar(c, 8);
    int count = (int16_t)arg16(c, 10), style = arg16(c, 11);
    surf_t s;
    const uint8_t *dm = lpdm ? (const uint8_t *)farptr(lpdm) : NULL;
    int r2 = dm ? *(const uint16_t *)dm : 13;
    rect16 clip, *cl = NULL;
    if (lpclip) { clip = *(const rect16 *)farptr(lpclip); cl = &clip; }
    const int16_t *pt = (const int16_t *)farptr(lppts);
    const ppen_t *pen = lppen ? (const ppen_t *)farptr(lppen) : NULL;
    const pbrush_t *br = lpbr ? (const pbrush_t *)farptr(lpbr) : NULL;
    int ok = surf_of(argfar(c, 12), &s);
    if (ok && style == 18 && pen && pen->style != 5) {   /* OS_POLYLINE; PS_NULL draws nothing */
        uint16_t col = for_surf(&s, pen->color);
        for (int i = 0; i + 1 < count; i++) {   /* Bresenham, the last point left off */
            int x0 = pt[2 * i], y0 = pt[2 * i + 1], x1 = pt[2 * i + 2], y1 = pt[2 * i + 3];
            int ddx = abs(x1 - x0), ddy = -abs(y1 - y0), sx = x0 < x1 ? 1 : -1, sy = y0 < y1 ? 1 : -1, e = ddx + ddy;
            while (x0 != x1 || y0 != y1) {
                line_px(&s, cl, x0, y0, r2, col);
                int e2 = 2 * e;
                if (e2 >= ddy) { e += ddy; x0 += sx; }
                if (e2 <= ddx) { e += ddx; y0 += sy; }
            }
        }
    } else if (ok && style == 4 && count > 1) {   /* OS_SCANLINES */
        int y = pt[1];
        for (int i = 1; i < count; i++)
            for (int x = pt[2 * i]; x < pt[2 * i + 1]; x++)
                line_px(&s, cl, x, y, r2, for_surf(&s, br ? brush_at(br, x, y) : pen ? pen->color : 0));
    } else ok = 0;
    if (getenv("W16_TRACE")) fprintf(stderr, "[drv] DISPLAY.Output style %d n %d -> %d\n", style, count, ok ? 1 : -1);
    c->ax = ok ? 1 : 0xFFFF; ret_far(c, 28);
}

/* DISPLAY.9 Pixel(lpDestDev, x, y, color, lpDrawMode): no DRAWMODE reads the physical color
 * back (dx:ax); with one, sets it under the ROP2. */
static void disp_pixel(CPU *c) {
    uint32_t lpdm = argfar(c, 0), col = argfar(c, 2);
    int y = (int16_t)arg16(c, 4), x = (int16_t)arg16(c, 5);
    surf_t s; uint16_t v = 0;
    if (surf_of(argfar(c, 6), &s)) {
        if (!lpdm) v = surf_get(&s, x, y);
        else { surf_put(&s, x, y, rop2(*(const uint16_t *)farptr(lpdm), for_surf(&s, (uint16_t)col), surf_get(&s, x, y))); v = 1; }
    }
    c->ax = v; c->dx = 0; ret_far(c, 16);
}

/* ---- the host window: g_fb shown 1:1, repainted on a timer; no input yet ---- */
static LRESULT CALLBACK fb_wndproc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_TIMER) { InvalidateRect(h, NULL, FALSE); return 0; }
    if (m == WM_PAINT || m == WM_PRINTCLIENT) {
        PAINTSTRUCT ps; HDC dc = m == WM_PAINT ? BeginPaint(h, &ps) : (HDC)w;
        struct { BITMAPINFOHEADER h; DWORD mask[3]; } bi = { { sizeof(BITMAPINFOHEADER), FB_W, -FB_H, 1, 16, BI_BITFIELDS }, { 0xF800, 0x07E0, 0x001F } };
        SetDIBitsToDevice(dc, 0, 0, FB_W, FB_H, 0, 0, 0, FB_H, g_fb, (BITMAPINFO *)&bi, DIB_RGB_COLORS);
        if (m == WM_PAINT) EndPaint(h, &ps);
        return 0;
    }
    if (m == WM_CLOSE) return 0;   /* the guest owns its lifetime */
    return DefWindowProcA(h, m, w, l);
}
static DWORD WINAPI fb_thread(LPVOID unused) {
    (void)unused;
    WNDCLASSA wc = { 0 };
    wc.lpfnWndProc = fb_wndproc; wc.hInstance = GetModuleHandleA(NULL); wc.lpszClassName = "pcrecomp_w16_display";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassA(&wc);
    RECT r = { 0, 0, FB_W, FB_H };
    AdjustWindowRect(&r, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, FALSE);
    HWND h = CreateWindowA(wc.lpszClassName, "DISPLAY.DRV (pcrecomp)", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                           0, 0, r.right - r.left, r.bottom - r.top, NULL, NULL, wc.hInstance, NULL);
    SetTimer(h, 1, 100, NULL);
    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0) > 0) DispatchMessageA(&msg);
    return 0;
}
/* ponytail: a window only when asked (W16_WINDOW), so check_w16 and plain runs stay headless */
static void fb_window(void) {
    static int up;
    if (!up && getenv("W16_WINDOW")) { up = 1; CloseHandle(CreateThread(NULL, 0, fb_thread, NULL, 0, NULL)); }
}

/* Cursor entries (USER): 101 Inquire(lpCursorInfo) -> its size, {dpXRate, dpYRate} (seg072_3714 wants 4);
 * 102 SetCursor(lpShape), 103 MoveCursor(x, y), 104 CheckCursor(). ponytail: the shape and
 * position are kept, not drawn (the host window shows the host's arrow). */
static int16_t g_cur_x, g_cur_y;
static void disp_inquire(CPU *c) { put16(farptr(argfar(c, 0)), 0, 1); put16(farptr(argfar(c, 0)), 2, 1); c->ax = 4; ret_far(c, 4); }
static void disp_setcursor(CPU *c) { c->ax = 1; ret_far(c, 4); }
static void disp_movecursor(CPU *c) { g_cur_y = (int16_t)arg16(c, 0); g_cur_x = (int16_t)arg16(c, 1); ret_far(c, 4); }
static void disp_checkcursor(CPU *c) { ret_far(c, 0); }

/* DISPLAY.19 DeviceBitmapBits(lpBitmap, fGet, iStart, cScans, lpDIBits, lpBitmapInfo,
 * lpDrawMode, lpConversionInfo) (GDI seg005_5F05: Set/GetDIBits on a device bitmap):
 * scans copied. A DIB is bottom-up, BITMAPINFOHEADER then its color table; 1/4/8/16/24/32 bpp
 * (16 as 5-5-5). ponytail: BI_RGB only; Get writes 1 bpp or 24 bpp as asked, others skipped. */
static uint16_t dib_px(const uint8_t *row, int x, int bpp, const uint8_t *pal) {
    const uint8_t *q;
    switch (bpp) {
    case 1: q = pal + 4 * ((row[x >> 3] >> (7 - (x & 7))) & 1); break;
    case 4: q = pal + 4 * ((row[x >> 1] >> ((x & 1) ? 0 : 4)) & 15); break;
    case 8: q = pal + 4 * row[x]; break;
    case 16: { uint16_t v = ((const uint16_t *)row)[x]; return (uint16_t)(((v & 0x7FE0) << 1) | (v & 0x1F) | ((v >> 4) & 0x20)); }
    case 24: q = row + 3 * x; break;
    default: q = row + 4 * x; break;
    }
    return rgb565((uint32_t)q[2] | (uint32_t)q[1] << 8 | (uint32_t)q[0] << 16);
}
static void disp_dibbits(CPU *c) {
    uint32_t lpbi = argfar(c, 4), lpbits = argfar(c, 6), lpbm = argfar(c, 11);
    int scans = arg16(c, 8), start = arg16(c, 9), get = arg16(c, 10);
    const uint8_t *bi = (const uint8_t *)farptr(lpbi);
    int w = *(const int32_t *)(bi + 4), h = *(const int32_t *)(bi + 8), bpp = *(const uint16_t *)(bi + 14);
    int ncol = *(const uint32_t *)(bi + 32); if (!ncol && bpp <= 8) ncol = 1 << bpp;
    const uint8_t *pal = bi + *(const uint32_t *)bi;
    int stride = ((w * bpp + 31) / 32) * 4, hh = h < 0 ? -h : h;
    uint8_t *bits = (uint8_t *)farptr(lpbits);
    surf_t s; int done = 0;
    if (surf_of(lpbm, &s))
        for (int i = 0; i < scans && start + i < hh; i++) {
            int y = h < 0 ? start + i : hh - 1 - (start + i);   /* the bitmap row this scan is */
            uint8_t *row = bits + (size_t)i * stride;
            for (int x = 0; x < w && x < s.w; x++) {
                if (!get) { surf_put(&s, x, y, dib_px(row, x, bpp, pal)); continue; }
                uint32_t rgb = rgb_of(surf_get(&s, x, y));
                if (bpp == 24) { row[3 * x] = (uint8_t)(rgb >> 16); row[3 * x + 1] = (uint8_t)(rgb >> 8); row[3 * x + 2] = (uint8_t)rgb; }
                else if (bpp == 1) { uint8_t m = (uint8_t)(0x80 >> (x & 7)); if ((rgb & 0xFFFFFF) == 0xFFFFFF) row[x >> 3] |= m; else row[x >> 3] &= (uint8_t)~m; }
            }
            done++;
        }
    (void)ncol;
    if (getenv("W16_TRACE")) fprintf(stderr, "[drv] DISPLAY.DeviceBitmapBits %s %dx%d %dbpp scans %d+%d -> %d\n", get ? "get" : "set", w, h, bpp, start, scans, done);
    c->ax = (uint16_t)done; ret_far(c, 26);
}

static drv_t g_drv[] = {
    { "SYSTEM",   { 0 } },
    { "KEYBOARD", { [5] = kb_ansi_to_oem, [6] = kb_oem_to_ansi } },
    { "MOUSE",    { 0 } },
    { "DISPLAY",  { [1] = disp_bitblt, [8] = disp_output, [9] = disp_pixel, [2] = disp_colorinfo, [3] = disp_control, [5] = disp_enable, [10] = disp_realize, [14] = disp_exttextout, [19] = disp_dibbits,
                    [101] = disp_inquire, [102] = disp_setcursor, [103] = disp_movecursor, [104] = disp_checkcursor } },
    { "MMSOUND",  { 0 } },   /* SlowBoot: sound.drv= default; makes no sound */
    { "COMM",     { 0 } },   /* comm.drv=: no ports */
};
#define NDRV (int)(sizeof g_drv / sizeof *g_drv)

/* ---- the NE file ---- */
static uint8_t g_ne[0x800];
static size_t ne_build(int idx) {
    const char *name = g_drv[idx].name;
    uint8_t *f = g_ne;
    memset(f, 0, sizeof g_ne);
    f[0] = 'M'; f[1] = 'Z'; *(uint16_t *)(f + 2) = 0x40; *(uint16_t *)(f + 4) = 1; *(uint16_t *)(f + 8) = 4;
    *(uint16_t *)(f + 0x18) = 0x40; *(uint32_t *)(f + 0x3C) = 0x40;
    uint8_t *ne = f + 0x40, *p = ne + 0x40;
    ne[0] = 'N'; ne[1] = 'E'; ne[2] = 5; ne[3] = 10;
    *(uint16_t *)(ne + 0x0C) = 0x8000;            /* library, no automatic data segment */
    *(uint16_t *)(ne + 0x14) = E_LIBENTRY; *(uint16_t *)(ne + 0x16) = 1;   /* cs:ip = 1:LibEntry */
    *(uint16_t *)(ne + 0x1C) = 1;                 /* one segment */
    *(uint16_t *)(ne + 0x32) = 4;                 /* alignment shift: 16-byte sectors */
    ne[0x36] = 2;                                 /* Windows */
    *(uint16_t *)(ne + 0x3E) = 0x030A;
    /* segment table */
    *(uint16_t *)(ne + 0x22) = (uint16_t)(p - ne);
    uint8_t *seg = p; p += 8;
    /* resource table: none (offset = resident names) */
    *(uint16_t *)(ne + 0x24) = (uint16_t)(p - ne);
    *(uint16_t *)(ne + 0x26) = (uint16_t)(p - ne);
    size_t n = strlen(name);
    *p++ = (uint8_t)n; memcpy(p, name, n); p += n; *p++ = 0; *p++ = 0;   /* module name, ordinal 0 */
    *p++ = 0;
    *(uint16_t *)(ne + 0x28) = (uint16_t)(p - ne);   /* module references: none */
    *(uint16_t *)(ne + 0x2A) = (uint16_t)(p - ne);   /* imported names: one empty byte */
    *p++ = 0;
    /* entry table: one bundle of NORD fixed entries in segment 1, exported */
    *(uint16_t *)(ne + 0x04) = (uint16_t)(p - ne);
    uint8_t *et = p;
    *p++ = NORD; *p++ = 1;
    for (int i = 0; i < NORD; i++) { *p++ = 1; *(uint16_t *)p = (uint16_t)(E_FIRST + 2 * i); p += 2; }
    *p++ = 0;
    *(uint16_t *)(ne + 0x06) = (uint16_t)(p - et);
    /* nonresident names: the description */
    static const char desc[] = "pcrecomp host driver";
    *(uint32_t *)(ne + 0x2C) = (uint32_t)(p - f);
    uint8_t *nr = p;
    *p++ = sizeof desc - 1; memcpy(p, desc, sizeof desc - 1); p += sizeof desc - 1; *p++ = 0; *p++ = 0;
    *p++ = 0;
    *(uint16_t *)(ne + 0x20) = (uint16_t)(p - nr);
    /* the code segment, on a sector boundary */
    size_t at = ((size_t)(p - f) + 15) & ~(size_t)15;
    uint8_t *cs = f + at;
    uint16_t len = E_FIRST + 2 * NORD;
    memcpy(cs, "PCRD", 4); cs[4] = (uint8_t)idx;
    cs[E_LIBENTRY] = 0xCB;                        /* retf: never run, drv_far answers */
    for (int i = 0; i < NORD; i++) cs[E_FIRST + 2 * i] = 0xCB;
    *(uint16_t *)(seg + 0) = (uint16_t)(at >> 4);
    *(uint16_t *)(seg + 2) = len;
    *(uint16_t *)(seg + 4) = 0x0070;              /* code: moveable, pure, preload */
    *(uint16_t *)(seg + 6) = len;
    return at + len;
}

/* Write each stand-in to <sysdir>\<NAME>.DRV (the guest's own tree). */
void w16_drv_write(const char *sysdir) {
    for (int i = 0; i < NDRV; i++) {
        char path[512];
        snprintf(path, sizeof path, "%s\\%s.DRV", sysdir, g_drv[i].name);
        size_t n = ne_build(i);
        FILE *f = fopen(path, "wb");
        if (!f) { fprintf(stderr, "[drv] cannot write %s\n", path); continue; }
        fwrite(g_ne, 1, n, f);
        fclose(f);
    }
}

/* A far call into a segment that holds no lifted code: ours if tagged. */
int w16_drv_far(CPU *c, uint16_t sel, uint16_t off) {
    const uint8_t *b = (const uint8_t *)(uintptr_t)recomp_sel_base(sel);
    if (!(sel & 4) || !b || memcmp(b, "PCRD", 4) || b[4] >= NDRV) return 0;
    drv_t *d = &g_drv[b[4]];
    if (getenv("W16_TRACE")) fprintf(stderr, "[drv] %s %04X:%04X\n", d->name, sel, off);
    if (off == E_LIBENTRY) { libentry(c); return 1; }
    unsigned ord = off >= E_FIRST ? (off - E_FIRST) / 2u + 1 : 0;
    if (!ord || ord > NORD || (off - E_FIRST) % 2) w16_drv_stop("driver offset with no entry, idx:off", b[4], off);
    if (!d->fn[ord]) { fprintf(stderr, "\n[drv] %s.%u has no host function\n", d->name, ord); w16_drv_stop("driver entry not named yet, idx:ordinal", b[4], ord); }
    d->fn[ord](c);
    return 1;
}

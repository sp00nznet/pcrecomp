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

static drv_t g_drv[] = {
    { "SYSTEM",   { 0 } },
    { "KEYBOARD", { [5] = kb_ansi_to_oem, [6] = kb_oem_to_ansi } },
    { "MOUSE",    { 0 } },
    { "DISPLAY",  { [2] = disp_colorinfo, [3] = disp_control, [5] = disp_enable, [10] = disp_realize } },
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

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
uint8_t *native32_w9x_desc(uint16_t sel);
void w16_drv_stop(const char *what, unsigned a, unsigned b);

#define E_LIBENTRY 0x08     /* the NE's cs:ip */
#define E_FIRST    0x10     /* entry n (ordinal) at E_FIRST + 2 * (n - 1) */
#define NORD       410      /* ordinals 1..NORD exported (KEYBOARD goes to 136, DIBENG to 408) */

typedef void (*drv_fn)(CPU *c);
typedef struct { const char *name; drv_fn fn[NORD + 1]; } drv_t;

static uint16_t arg16(CPU *c, int i) { return mem_read16(c, c->ss, (uint16_t)(c->sp + 4 + 2 * i)); }
static void ret_far(CPU *c, int argbytes) { c->ret_ip = mem_read16(c, c->ss, c->sp); c->sp = (uint16_t)(c->sp + 4 + argbytes); }   /* ret_ip: what a far return pops (w16_retf_call) */
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
/* 134 AnsiToOemBuff(lpSrc, lpDst, nLength) / 135 OemToAnsiBuff: the same over n bytes. */
static void kb_xlat_buf(CPU *c, UINT from, UINT to) {
    int n = arg16(c, 0);
    cp_convert(farptr(argfar(c, 3)), farptr(argfar(c, 1)), n ? n : 65536, from, to);
    ret_far(c, 10);
}
static void kb_ansi_to_oem_buf(CPU *c) { kb_xlat_buf(c, 1252, 437); }
static void kb_oem_to_ansi_buf(CPU *c) { kb_xlat_buf(c, 437, 1252); }
/* 132 GetKBCodePage() -> the OEM code page (437, as cp_convert); 136 EnableKBSysReq(f) -> 0
 * (ponytail: the previous state is never kept; no SysReq key here). */
static void kb_codepage(CPU *c) { c->ax = 437; ret_far(c, 0); }
static void kb_sysreq(CPU *c) { c->ax = 0; ret_far(c, 2); }

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
#define PDEV_SIZE 0x40   /* also every DIB section's PDEVICE (GDI CreateDIBSection, seg007_0052): a DIBENGINE is 30h */
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

/* DISPLAY.4 Disable(lpDestDev): the device goes away (USER's shutdown path, after KRNL386
 * fails to start its first program). The framebuffer is left as it was, so a
 * W16_HOLD shot still shows the last frame. */
static void disp_disable(CPU *c) {
    if (getenv("W16_TRACE")) fprintf(stderr, "[drv] DISPLAY.Disable\n");
    c->ax = 1; ret_far(c, 4);
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
/* Marlett, the one TrueType face Win98's USER needs (caption buttons, scroll arrows,
 * check marks: DrawFrameControl selects it and draws "0" "1" "2" "r" "6"...). GDI realizes
 * TrueType through its rasterizer only with dpNumFonts/TC_RA_ABLE TrueType support, which
 * this display stand-in lacks, so RealizeObject answers a LOGFONT whose face is Marlett
 * with a device font: Win98's own marlett.ttf (the host copies it to SYSTEM\MARLETT.TT_) (font data, not code)
 * rasterized at that height by a process-private host GDI font (AddFontMemResourceEx), laid
 * out as a FNT 3.0 FONTINFO that ExtTextOut and GetCharWidth already read.
 * ponytail: Marlett only, chars 20h..7Fh, mono, no other TrueType face. */
static char g_fontdir[512];
static HANDLE g_marlett;
static int marlett_build(int lfh, uint8_t *fi) {
    if (!g_marlett) {
        char p[600]; snprintf(p, sizeof p, "%s\\MARLETT.TT_", g_fontdir);
        FILE *f = fopen(p, "rb"); if (!f) return 0;
        static uint8_t ttf[64 * 1024]; DWORD n = (DWORD)fread(ttf, 1, sizeof ttf, f), cnt = 0; fclose(f);
        g_marlett = AddFontMemResourceEx(ttf, n, NULL, &cnt);   /* private to this process */
        if (!g_marlett) return 0;
    }
    HDC dc = CreateCompatibleDC(NULL);
    HFONT hf = CreateFontA(lfh, 0, 0, 0, FW_NORMAL, 0, 0, 0, SYMBOL_CHARSET, 0, 0, NONANTIALIASED_QUALITY, 0, "Marlett");
    HGDIOBJ of = SelectObject(dc, hf);
    TEXTMETRICA tm; GetTextMetricsA(dc, &tm);
    int h = tm.tmHeight, first = 0x20, last = 0x7F, nch = last - first + 1, maxw = 1;
    INT w[96]; GetCharWidth32A(dc, first, last, w);
    for (int i = 0; i < nch; i++) if (w[i] > maxw) maxw = w[i];
    /* the block: FONTINFO (file offset 66 on) + table of nch+1 {width, dword offset} + face + glyphs;
     * offsets count from 66 bytes before FONTINFO, as in a .FNT file */
    int tab = 82, face = tab + 6 * (nch + 1), bits = face + 8, size = bits;
    for (int i = 0; i < nch; i++) size += ((w[i] + 7) / 8) * h;
    if (fi) {
        memset(fi, 0, (size_t)size);
        put16((char *)fi, 0, 0x80);              /* dfType: device-realized */
        put16((char *)fi, 2, (uint16_t)(h * 72 / 96)); put16((char *)fi, 4, 96); put16((char *)fi, 6, 96);
        put16((char *)fi, 8, (uint16_t)tm.tmAscent); put16((char *)fi, 10, (uint16_t)tm.tmInternalLeading);
        put16((char *)fi, 17, FW_NORMAL); fi[19] = SYMBOL_CHARSET;
        put16((char *)fi, 22, (uint16_t)h); fi[24] = 0x02 | FF_DECORATIVE;   /* variable pitch */
        put16((char *)fi, 25, (uint16_t)tm.tmAveCharWidth); put16((char *)fi, 27, (uint16_t)maxw);
        fi[29] = (uint8_t)first; fi[30] = (uint8_t)last; fi[31] = 0; fi[32] = 0;
        *(uint32_t *)(fi + 39) = 66 + face;     /* dfFace */
        *(uint32_t *)(fi + 47) = 66 + bits;     /* dfBitsOffset */
        *(uint32_t *)(fi + 52) = 0x02;          /* dfFlags: DFF_PROPORTIONAL (marks 3.0 here) */
        memcpy(fi + face, "Marlett", 8);
        BITMAPINFO bi = { { sizeof(BITMAPINFOHEADER), maxw, -h, 1, 32 } };
        uint32_t *px; HBITMAP bm = CreateDIBSection(dc, &bi, DIB_RGB_COLORS, (void **)&px, NULL, 0);
        HGDIOBJ ob = SelectObject(dc, bm);
        SetTextColor(dc, RGB(255, 255, 255)); SetBkColor(dc, 0); SetBkMode(dc, OPAQUE);
        int off = bits;
        for (int i = 0; i < nch; i++) {
            uint8_t *e = fi + tab + 6 * i;
            put16((char *)e, 0, (uint16_t)w[i]); *(uint32_t *)(e + 2) = 66 + off;
            RECT r = { 0, 0, maxw, h }; char ch = (char)(first + i);
            ExtTextOutA(dc, 0, 0, ETO_OPAQUE, &r, &ch, 1, NULL); GdiFlush();
            for (int x = 0; x < w[i]; x++) for (int y = 0; y < h; y++)
                if (px[y * maxw + x] & 0xFF) fi[off + (x >> 3) * h + y] |= (uint8_t)(0x80 >> (x & 7));
            off += ((w[i] + 7) / 8) * h;
        }
        put16((char *)(fi + tab + 6 * nch), 0, 0);
        SelectObject(dc, ob); DeleteObject(bm);
    }
    SelectObject(dc, of); DeleteObject(hf); DeleteDC(dc);
    return size;
}

typedef struct { uint8_t *bits; int w, h, pitch, bpp; const uint16_t *pal; } surf_t;
static int surf_of(uint32_t lp, surf_t *s);
static uint16_t surf_get(surf_t *s, int x, int y);
typedef struct { uint16_t style, width, color, pad; } ppen_t;
typedef struct { uint16_t style, hatch, color, bk; uint16_t pat[64]; } pbrush_t;
static void disp_realize(CPU *c) {
    int16_t style = (int16_t)arg16(c, 6);
    uint32_t in = argfar(c, 4), out = argfar(c, 2);
    int sz = style == 1 ? (int)sizeof(ppen_t) : style == 2 ? (int)sizeof(pbrush_t) : 0;
    if (style == 3 && getenv("W16_TRACE")) { const uint8_t *lf = (const uint8_t *)farptr(in); fprintf(stderr, "[drv] DISPLAY.RealizeObject font h %d \"%.32s\" out %08X\n", *(const int16_t *)lf, lf + 18, out); }
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
            if (b->style == 3) {   /* BS_PATTERN: GDI passes a far pointer to the bitmap's PBITMAP where the
                                    * colour would be (notepad's scroll bars); its top-left 8x8 is the pattern.
                                    * A mono one (bk 0) takes the DRAWMODE's colours in BitBlt, 1 -> background. */
                surf_t ps;
                if (surf_of(*(const uint32_t *)(li + 2), &ps)) {
                    for (int i = 0; i < 64; i++) b->pat[i] = surf_get(&ps, i & 7, i >> 3);
                    if (ps.bpp == 1) b->bk = 0;
                }
            }
            if (b->style > 1 && getenv("W16_TRACE")) fprintf(stderr, "[drv] DISPLAY brush style %u: solid (color %08X hatch %04X)\n", b->style, *(const uint32_t *)(li + 2), b->hatch);
        }
    }
    if (style == 3 && !_stricmp((const char *)farptr(in) + 18, "Marlett")) {   /* a device font (above) */
        int lfh = *(const int16_t *)farptr(in);
        sz = marlett_build(lfh, out ? (uint8_t *)farptr(out) : NULL);
        if (getenv("W16_TRACE")) fprintf(stderr, "[drv] DISPLAY Marlett h %d: device font, %d bytes%s\n", lfh, sz, out ? " written" : "");
    }
    c->ax = (uint16_t)(style > 0 ? sz : 1); c->dx = 0;
    ret_far(c, 18);
}

/* A destination: the screen's PDEVICE (bmType nonzero) or a GDI memory bitmap (a PBITMAP:
 * type, width, height, widthbytes, planes, bitspixel, bits far ptr at 0Ah). 1 and 16 bpp.
 * ponytail: no huge (>64K, segmented) bitmaps. */
/* surf_t (above), pal: a palettized DIB's colors (5-6-5) */
/* A DIB section's PDEVICE (DIBENG.CreateDIBPDevice, below): the DIB engine's DIBENGINE
 * header, deType 'RP', deDeltaScan (signed) at 0Eh, deBits 16:32 at 16h (offset) and 1Ah
 * (selector): the buffer's start (GDI writes its own there after CreateDIBPDevice), so a
 * negative deDeltaScan (bottom-up) starts at its last row. 1/4/8 bpp through the color
 * table (a host copy, found by the PDEVICE's address), 16 (5-5-5), 24 and 32 bpp. */
/* Each PDEVICE address has a slot (GDI reuses the addresses): the color table as 5-6-5 and
 * the BITMAPINFO copy deBitmapInfo points at (GDI's CreateCompatibleBitmap on a DIB-section DC,
 * seg010_0DB3, clones it; the caller's own block is gone by then).
 * ponytail: 256 PDEVICE addresses, one selector each, never freed */
static struct { uint32_t dev; int npal; uint16_t sel; uint16_t pal[256]; uint8_t bi[40 + 1024]; } g_dibpal[256];
/* Found by the PDEVICE's deBitmapInfo selector (each slot's own), not its address: GDI moves
 * the block (shell32's image list DIB section, once the list grows), and an address lookup then
 * found nothing, so every blit into that list was dropped (My Computer's icon black). */
static uint16_t *dib_pal(const uint8_t *b) {
    uint16_t sel = (uint16_t)(*(const uint32_t *)(b + 0x20) >> 16);
    for (int i = 0; i < 256 && g_dibpal[i].dev; i++)
        if (sel && g_dibpal[i].sel == sel) {
            g_dibpal[i].dev = (uint32_t)(uintptr_t)b;   /* where it is now: a new PDEVICE at the old address gets its own slot */
            return g_dibpal[i].npal ? g_dibpal[i].pal : NULL;
        }
    return NULL;
}
#define DE_TYPE 0x5250
uint32_t recomp_sel_base(uint32_t selector);
static int surf_of(uint32_t lp, surf_t *s) {
    const uint8_t *b = (const uint8_t *)farptr(lp);
    if (*(const uint16_t *)b == DE_TYPE) {
        s->w = *(const int16_t *)(b + 2); s->h = *(const int16_t *)(b + 4); s->pitch = *(const int32_t *)(b + 0x0E);
        s->bpp = b[9] == 16 ? 15 : b[9];   /* 15: a DIB's 5-5-5 */
        {   /* GDI's own bits are flat (the 32-bit caller writes them): an offset past 64 KB is
             * the address, whatever the selector word holds. ponytail: read from one case */
            uint32_t off = *(const uint32_t *)(b + 0x16);
            s->bits = (uint8_t *)(uintptr_t)(off > 0xFFFF ? off : recomp_sel_base(*(const uint16_t *)(b + 0x1A)) + off);
        }
        if (s->pitch < 0) s->bits -= s->pitch * (s->h - 1);
        s->pal = dib_pal(b);
        if (getenv("W16_DIBDBG")) fprintf(stderr, "[dib] surf %08X: %dx%d bpp %d bits %04X:%08X delta %d own %08X base %08X lim %08X\n", lp, s->w, s->h, s->bpp, *(const uint16_t *)(b + 0x1A), *(const uint32_t *)(b + 0x16), s->pitch, *(const uint32_t *)(b + 0x2C), recomp_sel_base(*(const uint16_t *)(b + 0x1A)), *(const uint32_t *)native32_w9x_desc(*(const uint16_t *)(b + 0x1A)), *(const uint32_t *)(b + 0x0A), *(const uint32_t *)(b + 0x48), *(const uint32_t *)(b + 0x50), *(const uint32_t *)(b + 0x54), *(const uint32_t *)(b + 0x58));
        return s->bits && (s->bpp == 15 || s->bpp == 24 || s->bpp == 32 || (s->pal && (s->bpp == 1 || s->bpp == 4 || s->bpp == 8)));
    }
    s->pal = NULL;
    if (*(const uint16_t *)b) { s->bits = (uint8_t *)g_fb; s->w = FB_W; s->h = FB_H; s->pitch = FB_W * 2; s->bpp = 16; return 1; }
    s->w = *(const int16_t *)(b + 2); s->h = *(const int16_t *)(b + 4); s->pitch = *(const uint16_t *)(b + 6);
    s->bpp = b[9] * b[8]; s->bits = (uint8_t *)farptr(*(const uint32_t *)(b + 10));
    return s->bpp == 16 || s->bpp == 1;
}
/* A pixel in a 1-bpp bitmap is 1 where the color is white (the background), as GDI's mono rule. */
static void surf_put(surf_t *s, int x, int y, uint16_t col) {
    if (x < 0 || y < 0 || x >= s->w || y >= s->h) return;
    if (s->bpp == 16) { *(uint16_t *)(s->bits + y * s->pitch + x * 2) = col; return; }
    if (s->pal) {   /* a palettized DIB: the nearest entry. ponytail: a linear search per pixel */
        uint32_t c = rgb_of(col), best = 0, bd = 0xFFFFFFFFu;
        for (uint32_t i = 0; i < (1u << s->bpp); i++) {
            uint32_t e = rgb_of(s->pal[i]);
            int dr = (int)(c & 0xFF) - (int)(e & 0xFF), dg = (int)(c >> 8 & 0xFF) - (int)(e >> 8 & 0xFF), db = (int)(c >> 16 & 0xFF) - (int)(e >> 16 & 0xFF);
            uint32_t d = (uint32_t)(dr * dr + dg * dg + db * db);
            if (d < bd) { bd = d; best = i; if (!d) break; }
        }
        uint8_t *q = s->bits + y * s->pitch + (x * s->bpp >> 3);
        int sh = 8 - s->bpp - (x * s->bpp & 7);
        *q = (uint8_t)((*q & ~(((1 << s->bpp) - 1) << sh)) | best << sh);
        return;
    }
    if (s->bpp > 16) {   /* a DIB section: 5-6-5 to 5-5-5 or B,G,R */
        uint32_t c = rgb_of(col);
        uint8_t *q = s->bits + y * s->pitch + x * (s->bpp == 15 ? 2 : s->bpp / 8);
        if (s->bpp == 15) *(uint16_t *)q = (uint16_t)((c & 0xF8) << 7 | (c >> 6 & 0x3E0) | (c >> 19 & 0x1F));
        else { q[0] = (uint8_t)(c >> 16); q[1] = (uint8_t)(c >> 8); q[2] = (uint8_t)c; if (s->bpp == 32) q[3] = 0; }
        return;
    }
    uint8_t *p = s->bits + y * s->pitch + (x >> 3), m = (uint8_t)(0x80 >> (x & 7));
    if (col == 0xFFFF) *p |= m; else *p &= (uint8_t)~m;
}
static uint16_t surf_get(surf_t *s, int x, int y) {
    if (x < 0 || y < 0 || x >= s->w || y >= s->h) return 0;
    if (s->bpp == 16) return *(uint16_t *)(s->bits + y * s->pitch + x * 2);
    if (s->pal) {
        const uint8_t *q = s->bits + y * s->pitch + (x * s->bpp >> 3);
        return s->pal[*q >> (8 - s->bpp - (x * s->bpp & 7)) & ((1 << s->bpp) - 1)];
    }
    if (s->bpp > 16) {
        const uint8_t *q = s->bits + y * s->pitch + x * (s->bpp == 15 ? 2 : s->bpp / 8);
        if (s->bpp == 15) { uint16_t v = *(const uint16_t *)q; return rgb565((uint32_t)(v >> 7 & 0xF8) | (uint32_t)(v >> 2 & 0xF8) << 8 | (uint32_t)(v << 3 & 0xF8) << 16); }
        return rgb565((uint32_t)q[2] | (uint32_t)q[1] << 8 | (uint32_t)q[0] << 16);
    }
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
    surf_t s; int draw = count >= 0 && surf_of(lpdev, &s);   /* count 0: ETO_OPAQUE alone, a fill (comctl32 PatB) */
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
    if (getenv("W16_TRACE")) fprintf(stderr, "[drv] DISPLAY.ExtTextOut %d,%d n %d \"%.*s\" -> %dx%d v%d fg %04X bg %04X%s\n", x0, y0, count, n, str, width, h, v3 ? 3 : 2, fg, bg, opaque ? " opaque" : "");
    c->ax = (uint16_t)width; c->dx = (uint16_t)h; ret_far(c, 40);
}

/* DISPLAY.15 GetCharWidth(lpDestDev, lpBuffer, wFirst, wLast, lpFontInfo, lpDrawMode,
 * lpTextXForm): the raster font's widths, one int16 per char (as ExtTextOut reads them). */
static void disp_charwidth(CPU *c) {
    const uint8_t *fi = (const uint8_t *)farptr(argfar(c, 4));
    int last = arg16(c, 6), first = arg16(c, 7);
    int16_t *out = (int16_t *)farptr(argfar(c, 8));
    int f0 = fi[29], f1 = fi[30], dflt = fi[31];
    int v3 = (*(const uint32_t *)(fi + 52) & 0x0F) != 0;
    for (int ch = first; ch <= last; ch++) {
        int k = (ch < f0 || ch > f1 ? dflt + f0 : ch) - f0;
        *out++ = *(const int16_t *)(fi + (v3 ? 82 + 6 * k : 52 + 4 * k));
    }
    c->ax = 1; ret_far(c, 24);
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
    if (hs && getenv("W16_DUMPSRC")) {   /* debug: W16_DUMPSRC=WxH writes each such source surface as dumpNNN.ppm */
        static int n; char want[32], fn[64]; snprintf(want, sizeof want, "%dx%d", s.w, s.h);
        if (!strcmp(want, getenv("W16_DUMPSRC")) && n < 50 && (!getenv("W16_DUMPSCR") || code == 0xE2 || d.bits == (uint8_t *)g_fb)) {
            snprintf(fn, sizeof fn, "work/s34dump/d%03d.ppm", n++);
            FILE *f = fopen(fn, "wb");
            if (f) { fprintf(f, "P6 %d %d 255\n", s.w, s.h); for (int y = 0; y < s.h; y++) for (int x = 0; x < s.w; x++) { uint32_t v = rgb_of(surf_get(&s, x, y)); fputc((int)(v & 255), f); fputc((int)(v >> 8 & 255), f); fputc((int)(v >> 16 & 255), f); } fclose(f); }
            fprintf(stderr, "[drv] dumped %s (bpp %d pitch %d) for blit %d,%d<-%d,%d %dx%d rop %02X\n", fn, s.bpp, s.pitch, dx, dy, sx, sy, w, h, code);
        }
    }
    if (hs) {   /* the source block, as destination-format pixels */
        tmp = (uint16_t *)malloc((size_t)(w > 0 ? w : 1) * (h > 0 ? h : 1) * 2);
        for (int y = 0; y < h; y++) for (int x = 0; x < w; x++) {
            uint16_t v = surf_get(&s, sx + x, sy + y);
            if (s.bpp == 1 && d.bpp != 1) v = v ? bk : fg;   /* any color surface: screen, bitmap or DIB */
            else if (s.bpp != 1 && d.bpp == 1) v = v == bk ? 0xFFFF : 0;
            tmp[y * w + x] = v;
        }
    }
    for (int y = 0; y < h; y++) for (int x = 0; x < w; x++) {
        int px = dx + x, py = dy + y;
        uint16_t sv = tmp ? tmp[y * w + x] : 0;
        uint16_t pv = brush_at(br, px, py);
        if (br && br->style == 3 && !br->bk && d.bpp != 1) pv = pv ? bk : fg;   /* a mono pattern */
        surf_put(&d, px, py, rop3(code, for_surf(&d, pv), sv, surf_get(&d, px, py)));
    }
    free(tmp);
    if (getenv("W16_TRACE")) fprintf(stderr, "[drv] DISPLAY.BitBlt %d,%d %dx%d rop %02X pat %04X src %s %s\n", dx, dy, w, h, code, brush_at(br, dx, dy), hs ? "yes" : "no",
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
 * (16 as 5-5-5). A 4/8 bpp get from a DIB of that depth copies its indices and color table
 * (comctl32 ImageList_Draw goes through one), else the nearest entry of the given table.
 * BI_RLE4/8 sets are unpacked first (dib_unrle). */
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
/* BI_RLE8 (1) / BI_RLE4 (2) bits unpacked to plain bottom-up rows of the same depth (calloc'd,
 * the caller frees; NULL for BI_RGB). Explorer's Start-menu banner (bitmap 157) is RLE4. */
static uint8_t *dib_unrle(const uint8_t *bi, const uint8_t *src, int w, int hh, int bpp, int stride) {
    uint32_t comp = *(const uint32_t *)(bi + 16), n = *(const uint32_t *)(bi + 20);
    if ((comp != 1 && comp != 2) || bpp != (comp == 1 ? 8 : 4)) return NULL;
    uint8_t *out = (uint8_t *)calloc((size_t)hh, (size_t)stride);
    const uint8_t *p = src, *e = src + (n ? n : (uint32_t)(hh * stride * 2));
    int x = 0, y = 0;
#define PUT(v) do { if (x < w && y < hh) { uint8_t *r_ = out + (size_t)y * stride;         if (bpp == 8) r_[x] = (uint8_t)(v); else r_[x >> 1] |= (uint8_t)(((v) & 15) << ((x & 1) ? 0 : 4)); } x++; } while (0)
    while (p + 1 < e && y < hh) {
        int a = p[0], b = p[1]; p += 2;
        if (a) { for (int k = 0; k < a; k++) PUT(bpp == 8 ? b : (k & 1) ? b & 15 : b >> 4); continue; }
        if (b == 0) { x = 0; y++; continue; }               /* end of line */
        if (b == 1) break;                                   /* end of bitmap */
        if (b == 2) { if (p + 1 >= e) break; x += p[0]; y += p[1]; p += 2; continue; }   /* delta */
        for (int k = 0; k < b; k++) PUT(bpp == 8 ? p[k] : (k & 1) ? p[k >> 1] & 15 : p[k >> 1] >> 4);   /* absolute run */
        p += bpp == 8 ? (b + 1) & ~1 : ((b + 3) / 4) * 2;
    }
#undef PUT
    return out;
}
static void disp_dibbits(CPU *c) {
    uint32_t lpbi = argfar(c, 4), lpbits = argfar(c, 6), lpbm = argfar(c, 11);
    int scans = arg16(c, 8), start = arg16(c, 9), get = arg16(c, 10);
    const uint8_t *bi = (const uint8_t *)farptr(lpbi);
    int w = *(const int32_t *)(bi + 4), h = *(const int32_t *)(bi + 8), bpp = *(const uint16_t *)(bi + 14);
    int ncol = *(const uint32_t *)(bi + 32); if (!ncol && bpp <= 8) ncol = 1 << bpp;
    const uint8_t *pal = bi + *(const uint32_t *)bi;
    int stride = ((w * bpp + 31) / 32) * 4, hh = h < 0 ? -h : h;
    uint8_t *bits = (uint8_t *)farptr(lpbits), *unrle = get ? NULL : dib_unrle(bi, bits, w, hh, bpp, stride);
    if (unrle) bits = unrle + (size_t)start * stride;
    surf_t s; int done = 0;
    int same = 0;   /* a get from a palettized DIB of this depth: its indices and color table as they are */
    if (surf_of(lpbm, &s) && get && bpp <= 8 && bpp > 1) {
        same = s.pal && s.bpp == bpp;
        uint8_t *q = (uint8_t *)pal;
        if (same) for (int k = 0; k < (1 << bpp); k++) { uint32_t v = rgb_of(s.pal[k]); q[4 * k] = (uint8_t)(v >> 16); q[4 * k + 1] = (uint8_t)(v >> 8); q[4 * k + 2] = (uint8_t)v; q[4 * k + 3] = 0; }
        if (same) *(uint32_t *)(bi + 32) = 0;
    }
    if (surf_of(lpbm, &s))
        for (int i = 0; i < scans && start + i < hh; i++) {
            int y = h < 0 ? start + i : hh - 1 - (start + i);   /* the bitmap row this scan is */
            uint8_t *row = bits + (size_t)i * stride;
            for (int x = 0; x < w && x < s.w; x++) {
                if (!get) { surf_put(&s, x, y, dib_px(row, x, bpp, pal)); continue; }
                if (bpp == 4 || bpp == 8) {   /* an index: the surface's own, or the nearest in the given table */
                    unsigned k = 0;
                    if (same) { const uint8_t *sq = s.bits + y * s.pitch + (x * bpp >> 3); k = *sq >> (8 - bpp - (x * bpp & 7)) & ((1u << bpp) - 1); }
                    else {
                        uint32_t v = rgb_of(surf_get(&s, x, y)), bd = 0xFFFFFFFFu;
                        for (int e = 0; e < ncol; e++) {
                            int dr = (int)(v & 255) - pal[4 * e + 2], dg = (int)(v >> 8 & 255) - pal[4 * e + 1], db = (int)(v >> 16 & 255) - pal[4 * e];
                            uint32_t dd = (uint32_t)(dr * dr + dg * dg + db * db);
                            if (dd < bd) { bd = dd; k = (unsigned)e; }
                        }
                    }
                    if (bpp == 8) row[x] = (uint8_t)k;
                    else row[x >> 1] = (uint8_t)((x & 1) ? (row[x >> 1] & 0xF0) | k : (row[x >> 1] & 0x0F) | k << 4);
                    continue;
                }
                uint32_t rgb = rgb_of(surf_get(&s, x, y));
                if (bpp == 32) { row[4 * x] = (uint8_t)(rgb >> 16); row[4 * x + 1] = (uint8_t)(rgb >> 8); row[4 * x + 2] = (uint8_t)rgb; row[4 * x + 3] = 0; continue; }
                if (bpp == 16) { ((uint16_t *)row)[x] = (uint16_t)((rgb & 0xF8) << 7 | (rgb >> 6 & 0x3E0) | (rgb >> 19 & 0x1F)); continue; }
                if (bpp == 24) { row[3 * x] = (uint8_t)(rgb >> 16); row[3 * x + 1] = (uint8_t)(rgb >> 8); row[3 * x + 2] = (uint8_t)rgb; }
                else if (bpp == 1) { uint8_t m = (uint8_t)(0x80 >> (x & 7)); if ((rgb & 0xFFFFFF) == 0xFFFFFF) row[x >> 3] |= m; else row[x >> 3] &= (uint8_t)~m; }
            }
            done++;
        }
    (void)ncol;
    free(unrle);
    if (getenv("W16_TRACE")) fprintf(stderr, "[drv] DISPLAY.DeviceBitmapBits %s %dx%d %dbpp scans %d+%d -> %d (bi %08X bits %08X: %08X %08X, table %08X %08X same %d)\n", get ? "get" : "set", w, h, bpp, start, scans, done,
                                         lpbi, lpbits, *(const uint32_t *)(bits + 8 * stride), *(const uint32_t *)(bits + 8 * stride + 4), *(const uint32_t *)(pal + 4), *(const uint32_t *)(pal + 36), same);
    c->ax = (uint16_t)done; ret_far(c, 26);
}

/* DISPLAY.21 DIBtoDevice(lpPDevice, X, Y, iStart, cScans, lpClipRect, lpDrawMode, lpDIBits,
 * lpBitmapInfo, lpTranslate) -> scans drawn: SetDIBitsToDevice straight onto the device (winmine's
 * tiles). X,Y is the DIB's top-left; the buffer holds scans iStart.. (bottom-up DIBs count from the
 * bottom); only what lies in the clip rect is drawn.
 * ponytail: no lpTranslate (no palette device), X,Y read as the whole DIB's top-left */
static void disp_dibtodev(CPU *c) {
    int x0 = (int16_t)arg16(c, 13), y0 = (int16_t)arg16(c, 12), start = arg16(c, 11), scans = arg16(c, 10);
    const rect16 *cr = argfar(c, 8) ? (const rect16 *)farptr(argfar(c, 8)) : NULL;
    const uint8_t *bi = (const uint8_t *)farptr(argfar(c, 2));
    uint8_t *bits = (uint8_t *)farptr(argfar(c, 4));
    int w = *(const int32_t *)(bi + 4), h = *(const int32_t *)(bi + 8), bpp = *(const uint16_t *)(bi + 14);
    const uint8_t *pal = bi + *(const uint32_t *)bi;
    int stride = ((w * bpp + 31) / 32) * 4, hh = h < 0 ? -h : h, done = 0;
    uint8_t *unrle = dib_unrle(bi, bits, w, hh, bpp, stride);
    if (unrle) bits = unrle + (size_t)start * stride;
    surf_t s;
    if (surf_of(argfar(c, 14), &s))
        for (int i = 0; i < scans && start + i < hh; i++, done++) {
            int y = y0 + (h < 0 ? start + i : hh - 1 - (start + i));
            if (cr && (y < cr->t || y >= cr->b)) continue;
            uint8_t *row = bits + (size_t)i * stride;
            for (int x = 0; x < w; x++)
                if (!cr || (x0 + x >= cr->l && x0 + x < cr->r)) surf_put(&s, x0 + x, y, dib_px(row, x, bpp, pal));
        }
    free(unrle);
    if (getenv("W16_TRACE")) fprintf(stderr, "[drv] DISPLAY.DIBtoDevice %d,%d %dx%d %dbpp scans %d+%d -> %d\n", x0, y0, w, h, bpp, start, scans, done);
    c->ax = (uint16_t)done; ret_far(c, 32);
}

/* SYSTEM.7 Get80x87SaveSize() -> the FNSAVE size; 8 Save80x87(lpBuf) / 9 Restore80x87(lpBuf).
 * ponytail: lifted code keeps no x87 state in guest memory, so save/restore do nothing. */
static void sys_fpu_size(CPU *c) { c->ax = 94; ret_far(c, 0); }
static void sys_fpu_save(CPU *c) { ret_far(c, 4); }

/* KEYBOARD.1 Inquire(lpKBINFO) -> its size: no DBCS lead ranges (FFh..FEh), no state, 12 F-keys;
 * 2 Enable(lpEventProc, lpKeyState), 3 Disable(), 7 SetSpeed(rate) -> -1 (not settable).
 * MOUSE.1 Inquire(lpMOUSEINFO): present, absolute, 2 buttons, 100 Hz; 2 Enable(lpEventProc), 3 Disable.
 * SYSTEM.1 InquireSystem(wReq, wDrive) dx:ax; 2 CreateSystemTimer(rate, lpProc) -> 1;
 * 3 KillSystemTimer(h); 4/5 Enable/DisableSystemTimers; 6 GetSystemMSecCount -> dx:ax.
 * Timers run from the tick thread (below); W16_INPUT drives the mouse and keyboard procs. */
static void kb_inquire(CPU *c) {
    uint8_t *k = (uint8_t *)farptr(argfar(c, 0));
    int native32_w9x_is_win95(void);
    k[0] = 0xFF; k[1] = 0xFE; k[2] = 0xFF; k[3] = 0xFE; put16((char *)k, 4, 0);
    /* Windows 95's KBINFO stops at StateSize: USER keeps its global hook table right
     * after it (USER ds:0CC6 + 6 = 0CCC, WH_MSGFILTER's slot), so a NumFuncKeys
     * there is a hook at 000C (its menu loop called 0100:0000) */
    if (native32_w9x_is_win95()) { c->ax = 6; ret_far(c, 4); return; }
    put16((char *)k, 6, 12);
    c->ax = 8; ret_far(c, 4);
}
static uint32_t g_kb_proc;
static void kb_enable(CPU *c) { g_kb_proc = argfar(c, 2); c->ax = 1; ret_far(c, 8); }   /* (lpEventProc, lpKeyState): the proc is the first pushed */
/* KEYBOARD.4 ToAscii(vk, scan, lpKeyState, lpChar, flags) -> chars written; 131 MapVirtualKey(code, type).
 * Through the host's own (pure) translation with the guest's key state.
 * ponytail: the host's layout stands in for KEYBOARD.DRV's tables (US here). */
static void kb_toascii(CPU *c) {
    WORD ch = 0;
    int n = ToAscii(arg16(c, 6), arg16(c, 5), (const BYTE *)farptr(argfar(c, 3)), &ch, arg16(c, 0));
    if (n > 0) put16(farptr(argfar(c, 1)), 0, ch);
    c->ax = (uint16_t)n; ret_far(c, 14);
}
static void kb_mapvk(CPU *c) { c->ax = (uint16_t)MapVirtualKeyA(arg16(c, 1), arg16(c, 0)); ret_far(c, 4); }
static void drv_disable(CPU *c) { c->ax = 1; ret_far(c, 0); }
static void kb_setspeed(CPU *c) { c->ax = 0xFFFF; ret_far(c, 2); }
static void ms_inquire(CPU *c) {
    char *m = farptr(argfar(c, 0));
    memset(m, 0, 14); m[0] = 1; put16(m, 2, 2); put16(m, 4, 100); put16(m, 6, 0); put16(m, 8, 0);
    put16(m, 10, FB_W); put16(m, 12, FB_H);
    c->ax = 14; ret_far(c, 4);
}
/* Scripted input, W16_INPUT="click X,Y@T;click X,Y@T;...": at T seconds a left
 * press and release at screen X,Y, through the event proc USER gave MOUSE.Enable,
 * the way MOUSE.DRV's interrupt handler calls it: ax = status (8000h absolute,
 * 1 moved, 2 left down, 4 left up), bx/cx = x/y scaled to 0..FFFFh, dx = buttons.
 * A host thread takes the machine for each call, as an interrupt would.
 * "key C@T": C pressed and released through KEYBOARD.Enable's proc (al vk, ah 80h up, bl scan).
 * "text STR@T": each character, shifted ones between a Shift press and release.
 * "drag X,Y,X2,Y2@T": press at X,Y, eight moves to X2,Y2, release there.
 * "mem N:OFF@T": print 16 words of global segment N at OFF (debug).
 * ponytail: left clicks and Shift-only keys, on a private 8 KB 16-bit stack. */
static uint32_t g_ms_proc;
int w16_call(CPU *r);
void mach_enter(void);
void mach_leave(void);
uint16_t native32_w9x_alloc_sel(uint32_t base, uint32_t limit);
static DWORD WINAPI input_thread(LPVOID unused) {
    (void)unused;
    DWORD t0 = GetTickCount();
    uint16_t ss = native32_w9x_alloc_sel((uint32_t)(uintptr_t)VirtualAlloc(NULL, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE), 0x1FFF);
    for (const char *s = getenv("W16_INPUT"); s && *s; s = strchr(s, ';') ? strchr(s, ';') + 1 : "") {
        int x, y; double t; char k;
        extern int g_fncount;
        if (getenv("W16_FN_INPUT") || getenv("W16_ARGS")) g_fncount = 1;   /* W16_FN's function trace from the first event on */
        char txt[128] = "";
        if (sscanf(s, " key %c@%lf", &k, &t) == 2) txt[0] = k, txt[1] = 0;
        else if (sscanf(s, " text %127[^@]@%lf", txt, &t) != 2) txt[0] = 0;
        if (txt[0]) {   /* "key C@T" one key, "text STR@T" each character; shifted ones under a Shift press */
            while (GetTickCount() - t0 < (DWORD)(t * 1000)) Sleep(20);
            for (const char *p = txt; *p; p++) {
                k = *p;
                SHORT sc = VkKeyScanA(k);
                UINT vk = k == '+' && !p[1] && p == txt ? VK_ADD : k == '*' && p == txt && !p[1] ? VK_MULTIPLY
                        : k == '-' && p == txt && !p[1] ? VK_SUBTRACT : k == '/' && p == txt && !p[1] ? VK_DIVIDE : LOBYTE(sc);
                int shift = vk == LOBYTE(sc) && (HIBYTE(sc) & 1);   /* ponytail: Shift only, no Ctrl/Alt combinations */
                uint16_t ev[4], n = 0;
                if (shift) ev[n++] = VK_SHIFT;
                ev[n++] = (uint16_t)vk; ev[n++] = (uint16_t)(vk | 0x8000);
                if (shift) ev[n++] = VK_SHIFT | 0x8000;
                for (int i = 0; i < n && g_kb_proc; i++) {
                    mach_enter();
                    CPU r; cpu_init(&r);
                    r.ax = ev[i]; r.bx = (uint16_t)MapVirtualKeyA(ev[i] & 0xFF, 0);   /* al vk, ah 80h on release; bl scan */
                    r.cs = (uint16_t)(g_kb_proc >> 16); r.ip = (uint16_t)g_kb_proc; r.ss = r.ds = r.es = ss; r.sp = 0x1FF0;
                    fprintf(stderr, "[drv] key event %04X (%c) to %04X:%04X\n", r.ax, k, r.cs, r.ip);
                    if (!w16_call(&r)) fprintf(stderr, "[drv] keyboard proc %04X:%04X is no lifted function\n", r.cs, r.ip);
                    mach_leave();
                    Sleep(60);
                }
            }
            continue;
        }
        unsigned ms, mo;
        if (sscanf(s, " mem %u:%x@%lf", &ms, &mo, &t) == 3) {   /* "mem N:OFF@T": 16 words of global segment N at OFF */
            while (GetTickCount() - t0 < (DWORD)(t * 1000)) Sleep(20);
            extern uint16_t g_w16_segsel[];
            const uint8_t *u = (const uint8_t *)(uintptr_t)recomp_sel_base(g_w16_segsel[ms]);
            fprintf(stderr, "[drv] mem %u:%04X:", ms, mo);
            for (int i = 0; u && i < 16; i++) fprintf(stderr, " %04X", *(const uint16_t *)(u + mo + 2 * i));
            fprintf(stderr, "\n");
            continue;
        }
        if (sscanf(s, " wnd %u:%x@%lf", &ms, &mo, &t) == 3) {   /* "wnd N:HWND@T": USER's WND (N its DGROUP), via the table at 10000h */
            while (GetTickCount() - t0 < (DWORD)(t * 1000)) Sleep(20);
            extern uint16_t g_w16_segsel[];
            const uint8_t *u = (const uint8_t *)(uintptr_t)recomp_sel_base(g_w16_segsel[ms]);
            uint32_t pw = u ? *(const uint32_t *)(u + 0x10000 + mo) : 0;
            fprintf(stderr, "[drv] wnd %04X @%08X:", mo, pw);
            for (int i = 0; pw >= 0x10000 && i < 40; i++) fprintf(stderr, " %04X", *(const uint16_t *)(u + pw + 2 * i));
            fprintf(stderr, "\n");
            continue;
        }
        int x2, y2, drag = sscanf(s, " drag %d,%d,%d,%d@%lf", &x, &y, &x2, &y2, &t) == 5;
        if (!drag && sscanf(s, " click %d,%d@%lf", &x, &y, &t) != 3) { fprintf(stderr, "[drv] W16_INPUT: cannot read \"%s\"\n", s); break; }
        if (!drag) x2 = x, y2 = y;
        while (GetTickCount() - t0 < (DWORD)(t * 1000)) Sleep(20);
        /* move, then press, then (a drag: moves in 8 steps to X2,Y2) release: USER's proc queues the
         * button messages before it takes a move in the same call, so a press with the move bit
         * lands where the cursor was */
        for (int i = 0; i < (drag ? 11 : 3); i++) {
            int last = i == (drag ? 10 : 2), step = drag && i >= 2 && !last ? i - 1 : last ? 8 : 0;
            int px = x + (x2 - x) * step / 8, py = y + (y2 - y) * step / 8;
            mach_enter();
            CPU r; cpu_init(&r);
            r.ax = i == 0 ? 0x8001 : i == 1 ? 0x8002 : last ? 0x8004 : 0x8001;
            r.bx = (uint16_t)(px * 0xFFFF / (FB_W - 1)); r.cx = (uint16_t)(py * 0xFFFF / (FB_H - 1)); r.dx = 2;
            r.cs = (uint16_t)(g_ms_proc >> 16); r.ip = (uint16_t)g_ms_proc; r.ss = r.ds = r.es = ss; r.sp = 0x1FF0;
            fprintf(stderr, "[drv] mouse event %04X at %d,%d to %04X:%04X\n", r.ax, px, py, r.cs, r.ip);
            if (!w16_call(&r)) fprintf(stderr, "[drv] mouse proc %04X:%04X is no lifted function\n", r.cs, r.ip);
            mach_leave();
            Sleep(60);
        }
    }
    return 0;
}
static void ms_enable(CPU *c) {
    g_ms_proc = argfar(c, 0);
    if (getenv("W16_INPUT")) fprintf(stderr, "[drv] MOUSE.Enable %08X\n", g_ms_proc);
    if (g_ms_proc && getenv("W16_INPUT")) CloseHandle(CreateThread(NULL, 0, input_thread, NULL, 0, NULL));
    c->ax = 1; ret_far(c, 4);
}
/* USER imports MOUSE statically, so its lifted calls name these (not the
 * stand-in module's segment, which KRNL386-loaded callers reach).
 * ponytail: MOUSE only; USER's static KEYBOARD and SYSTEM imports still take
 * the generated "unimplemented" stubs (keys and timers have no consumer yet). */
void MOUSE_Ord1(CPU *c) { ms_inquire(c); }
void MOUSE_Ord2(CPU *c) { ms_enable(c); }
void MOUSE_Ord3(CPU *c) { drv_disable(c); }
static void sys_inquire(CPU *c) {
    uint16_t req = arg16(c, 1);
    c->ax = 0; c->dx = 0;
    if (req == 0) { c->ax = 1000; c->dx = 0; }    /* timer resolution in microseconds */
    else if (req == 1) c->dx = 3;                 /* drive type: fixed */
    ret_far(c, 4);
}
/* The tick source. VTDAPI (VxD 442h) ax=9 hands back a selector whose dword
 * at 0 is the system time in ms: USER keeps 0:sel at DGROUP:0 (seg72 1EEB, its
 * GetTickCount 1:110C and every hardware event's time read it), KRNL386 at
 * DGROUP:1A88. A host thread keeps that dword at GetTickCount and runs the
 * SYSTEM.DRV timers (CreateSystemTimer's procs), taking the machine for each
 * call as the timer interrupt would. No hardware: the host's clock only.
 * ponytail: one thread, Sleep-paced (host ~15 ms granularity); 8 timers. */
static volatile DWORD *g_tick;
static uint16_t g_tick_sel;
static struct { uint32_t proc; DWORD rate, next; } g_tmr[8];
static DWORD WINAPI tick_thread(LPVOID unused) {
    (void)unused;
    uint16_t ss = native32_w9x_alloc_sel((uint32_t)(uintptr_t)VirtualAlloc(NULL, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE), 0x1FFF);
    for (;;) {
        DWORD now = GetTickCount();
        *g_tick = now;
        for (int i = 0; i < 8; i++) {
            if (!g_tmr[i].proc || (int)(now - g_tmr[i].next) < 0) continue;
            g_tmr[i].next = now + g_tmr[i].rate;
            mach_enter();
            if (g_tmr[i].proc) {
                CPU r; cpu_init(&r);
                r.cs = (uint16_t)(g_tmr[i].proc >> 16); r.ip = (uint16_t)g_tmr[i].proc; r.ss = r.ds = r.es = ss; r.sp = 0x1FF0;
                if (!w16_call(&r)) { fprintf(stderr, "[drv] system timer %04X:%04X is no lifted function\n", r.cs, r.ip); g_tmr[i].proc = 0; }
            }
            mach_leave();
        }
        Sleep(5);
    }
}
uint16_t drv16_tick_sel(void) {
    if (!g_tick_sel) {
        g_tick = (volatile DWORD *)VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        *g_tick = GetTickCount();
        g_tick_sel = native32_w9x_alloc_sel((uint32_t)(uintptr_t)g_tick, 0xFFF);
        CloseHandle(CreateThread(NULL, 0, tick_thread, NULL, 0, NULL));
    }
    return g_tick_sel;
}
/* SYSTEM.2 CreateSystemTimer(wRate ms, lpProc) -> a handle (index + 1), 0 if full; 3 KillSystemTimer(h) -> 0 */
static void sys_createtimer(CPU *c) {
    uint32_t proc = argfar(c, 0); DWORD rate = arg16(c, 2);
    drv16_tick_sel();
    c->ax = 0;
    for (int i = 0; i < 8; i++)
        if (!g_tmr[i].proc) { g_tmr[i].rate = rate ? rate : 1; g_tmr[i].next = GetTickCount() + g_tmr[i].rate; g_tmr[i].proc = proc; c->ax = (uint16_t)(i + 1); break; }
    if (getenv("W16_TRACE")) fprintf(stderr, "[drv] SYSTEM.CreateSystemTimer(%u ms, %08X) -> %u\n", (unsigned)rate, proc, c->ax);
    ret_far(c, 6);
}
static void sys_killtimer(CPU *c) { unsigned h = arg16(c, 0); if (h >= 1 && h <= 8) g_tmr[h - 1].proc = 0; c->ax = 0; ret_far(c, 2); }
static void sys_timers(CPU *c) { ret_far(c, 0); }
static void sys_msec(CPU *c) { DWORD t = GetTickCount(); c->ax = (uint16_t)t; c->dx = (uint16_t)(t >> 16); ret_far(c, 0); }
/* USER's static SYSTEM and KEYBOARD imports, as MOUSE_Ord* above (pop counts from USER's call sites:
 * KEYBOARD.1 pushes 4, .4 14, .131 4; the generated stubs had 8, 18, 8). 128/129/133 stay generated. */
void SYSTEM_Ord1(CPU *c) { sys_inquire(c); }
void SYSTEM_Ord2(CPU *c) { sys_createtimer(c); }
void SYSTEM_Ord3(CPU *c) { sys_killtimer(c); }
void SYSTEM_Ord4(CPU *c) { sys_timers(c); }
void SYSTEM_Ord5(CPU *c) { sys_timers(c); }
void SYSTEM_Ord6(CPU *c) { sys_msec(c); }
void KEYBOARD_Ord1(CPU *c) { kb_inquire(c); }
void KEYBOARD_Ord2(CPU *c) { kb_enable(c); }
void KEYBOARD_Ord3(CPU *c) { drv_disable(c); }
void KEYBOARD_Ord4(CPU *c) { kb_toascii(c); }
void KEYBOARD_Ord5(CPU *c) { kb_ansi_to_oem(c); }
void KEYBOARD_Ord6(CPU *c) { kb_oem_to_ansi(c); }
void KEYBOARD_Ord7(CPU *c) { kb_setspeed(c); }
void KEYBOARD_Ord131(CPU *c) { kb_mapvk(c); }
void KEYBOARD_Ord132(CPU *c) { kb_codepage(c); }
void KEYBOARD_Ord134(CPU *c) { kb_ansi_to_oem_buf(c); }
void KEYBOARD_Ord135(CPU *c) { kb_oem_to_ansi_buf(c); }

/* SOUND.DRV (winmine imports 1 OpenSound, 2 CloseSound, 4 SetVoiceNote(4 words), 5 SetVoiceAccent(5 words),
 * 9 StartSound, 10 StopSound): no audio device, so OpenSound answers S_SERDVNA (-1, in use/not there)
 * and the rest do nothing. */
static void snd_open(CPU *c) { c->ax = 0xFFFF; ret_far(c, 0); }
static void snd_zero(CPU *c) { c->ax = 0; ret_far(c, 0); }
static void snd_note(CPU *c) { c->ax = 0; ret_far(c, 8); }
static void snd_accent(CPU *c) { c->ax = 0; ret_far(c, 10); }

/* DIBENG.300 CreateDIBPDevice(lpbi, lpDevice, lpBits, wFlags) (GDI.EXE's CreateDIBSection,
 * comctl32's image lists, 4 bpp by default): the DIBENGINE header. No lpBits: the bits are
 * ours, flat memory under a flat selector (GDI hands deBits to the 32-bit caller).
 * ponytail: the answer is the header's size; the bits and the color table copy are never
 * freed, and a later SetDIBColorTable is not seen. */
uint16_t native32_w9x_alloc_sel(uint32_t base, uint32_t limit);
uint8_t *native32_w9x_desc(uint16_t sel);
static void dib_createpdevice(CPU *c) {
    uint16_t flags = arg16(c, 0);
    uint32_t bits = argfar(c, 1), dev = argfar(c, 3), lpbi = argfar(c, 5);
    const uint8_t *bi = (const uint8_t *)farptr(lpbi);
    int32_t w = *(const int32_t *)(bi + 4), h = *(const int32_t *)(bi + 8);
    uint16_t bpp = *(const uint16_t *)(bi + 14);
    if (getenv("W16_TRACE")) fprintf(stderr, "[drv] DIBENG.CreateDIBPDevice(bi %08X %dx%d %u bpp, dev %08X, bits %08X, flags %04X) hdr %u comp %u clr %u: %08X %08X %08X %08X\n", lpbi, w, h, bpp, dev, bits, flags,
                                         *(const uint32_t *)bi, *(const uint32_t *)(bi + 16), *(const uint32_t *)(bi + 32), *(const uint32_t *)(bi + 40), *(const uint32_t *)(bi + 44), *(const uint32_t *)(bi + 48), *(const uint32_t *)(bi + 52));
    int32_t stride = ((w * bpp + 31) / 32) * 4, ah = h < 0 ? -h : h;
    if (dev) {
        uint8_t *d = (uint8_t *)farptr(dev);
        memset(d, 0, 0x40);
        *(uint16_t *)d = DE_TYPE; *(int16_t *)(d + 2) = (int16_t)w; *(int16_t *)(d + 4) = (int16_t)ah;
        *(uint16_t *)(d + 6) = (uint16_t)stride; d[8] = 1; d[9] = (uint8_t)bpp;
        *(int32_t *)(d + 0x0E) = h < 0 ? stride : -stride;   /* bottom-up unless the height is negative */
        *(uint32_t *)(d + 0x12) = dev;                     /* delpPDevice: itself */
        *(uint32_t *)(d + 0x16) = bits & 0xFFFF;          /* no lpBits: GDI allocates the bits (shared ones from a section) and writes deBits after */
        *(uint16_t *)(d + 0x1A) = (uint16_t)(bits >> 16);
        {   /* the slot: color table as 5-6-5, the BITMAPINFO copy (header and table or masks) */
            int i = 0;
            while (i < 255 && g_dibpal[i].dev && g_dibpal[i].dev != (uint32_t)(uintptr_t)d) i++;
            g_dibpal[i].dev = (uint32_t)(uintptr_t)d; g_dibpal[i].npal = 0;
            uint32_t n = *(const uint32_t *)(bi + 32), hs = *(const uint32_t *)bi, comp = *(const uint32_t *)(bi + 16);
            if (bpp <= 8 && (!n || n > (1u << bpp))) n = 1u << bpp;
            const uint8_t *q = bi + hs;
            if (bpp <= 8) {
                for (uint32_t k = 0; k < n; k++) g_dibpal[i].pal[k] = rgb565((uint32_t)q[4 * k + 2] | (uint32_t)q[4 * k + 1] << 8 | (uint32_t)q[4 * k] << 16);
                g_dibpal[i].npal = (int)n;
            }
            uint32_t tab = bpp <= 8 ? 4 * n : comp == 3 ? 12 : 0;
            if (hs > 40) hs = 40;
            memcpy(g_dibpal[i].bi, bi, hs); memcpy(g_dibpal[i].bi + hs, q, tab);
            *(uint32_t *)g_dibpal[i].bi = hs;
            uint32_t base = (uint32_t)(uintptr_t)g_dibpal[i].bi;
            if (!g_dibpal[i].sel) g_dibpal[i].sel = native32_w9x_alloc_sel(base, sizeof g_dibpal[i].bi - 1);
            *(uint32_t *)(d + 0x20) = (uint32_t)g_dibpal[i].sel << 16;   /* deBitmapInfo */
        }
    }
    { uint32_t sz = (uint32_t)stride * (uint32_t)ah; c->eax = sz; c->dx = (uint16_t)(sz >> 16); }   /* the image size: GDI stores it as biSizeImage */
    ret_far(c, 14);
}

/* DIBENG.30 BitmapBits(lpDevice, fFlags, dwCount, lpBits): 2 (DBB_GET) copies the bitmap's
 * bytes out, 1 (DBB_SET) in, as they lie (a DIB's own row order). ponytail: no conversion,
 * the count clipped to the bits. */
static void dib_bitmapbits(CPU *c) {
    uint32_t lpbits = argfar(c, 0), count = argfar(c, 2), flags = argfar(c, 4), dev = argfar(c, 6);
    surf_t s;
    uint32_t done = 0;
    if (surf_of(dev, &s) && lpbits) {
        int stride = s.pitch < 0 ? -s.pitch : s.pitch;
        uint8_t *start = s.pitch < 0 ? s.bits + s.pitch * (s.h - 1) : s.bits;
        done = count < (uint32_t)(stride * s.h) ? count : (uint32_t)(stride * s.h);
        if (flags & 2) memcpy(farptr(lpbits), start, done); else if (flags & 1) memcpy(start, farptr(lpbits), done); else done = 0;
    }
    if (getenv("W16_TRACE")) fprintf(stderr, "[drv] DIBENG.BitmapBits(%08X, flags %X, %u) -> %u\n", dev, flags, count, done);
    c->ax = (uint16_t)done; c->dx = (uint16_t)(done >> 16);
    ret_far(c, 16);
}
#define DISPLAY_FNS [1] = disp_bitblt, [8] = disp_output, [9] = disp_pixel, [2] = disp_colorinfo, [3] = disp_control, [4] = disp_disable, [5] = disp_enable, [10] = disp_realize, [14] = disp_exttextout, [15] = disp_charwidth, [19] = disp_dibbits, [21] = disp_dibtodev
static drv_t g_drv[] = {
    { "SYSTEM",   { [1] = sys_inquire, [2] = sys_createtimer, [3] = sys_killtimer, [4] = sys_timers, [5] = sys_timers, [6] = sys_msec, [7] = sys_fpu_size, [8] = sys_fpu_save, [9] = sys_fpu_save } },
    { "KEYBOARD", { [5] = kb_ansi_to_oem, [6] = kb_oem_to_ansi, [1] = kb_inquire, [2] = kb_enable, [3] = drv_disable, [7] = kb_setspeed, [4] = kb_toascii, [131] = kb_mapvk, [132] = kb_codepage, [134] = kb_ansi_to_oem_buf, [135] = kb_oem_to_ansi_buf, [136] = kb_sysreq } },
    { "MOUSE",    { [1] = ms_inquire, [2] = ms_enable, [3] = drv_disable } },
    { "DISPLAY",  { DISPLAY_FNS,
                    [101] = disp_inquire, [102] = disp_setcursor, [103] = disp_movecursor, [104] = disp_checkcursor } },
    { "COMM",     { 0 } },   /* comm.drv=: no ports */
    /* GDI.EXE's DIB sections: the DIB engine's entries are the display driver's ordinals,
     * drawing into a DIBENGINE surface (surf_of) */
    { "DIBENG",   { DISPLAY_FNS, [30] = dib_bitmapbits, [300] = dib_createpdevice } },
    { "SOUND",    { [1] = snd_open, [2] = snd_zero, [4] = snd_note, [5] = snd_accent, [9] = snd_zero, [10] = snd_zero } },
};
#define NDRV (int)(sizeof g_drv / sizeof *g_drv)

/* ---- the NE file ---- */
static uint8_t g_ne[0x1000];
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
    for (int i = 0; i < NORD; ) {   /* bundles of at most 255 */
        int k = NORD - i < 255 ? NORD - i : 255;
        *p++ = (uint8_t)k; *p++ = 1;
        for (int e = 0; e < k; e++, i++) { *p++ = 1; *(uint16_t *)p = (uint16_t)(E_FIRST + 2 * i); p += 2; }
    }
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
    snprintf(g_fontdir, sizeof g_fontdir, "%s", sysdir);
    for (int i = 0; i < NDRV; i++) {
        char path[512];
        snprintf(path, sizeof path, "%s\\%s.%s", sysdir, g_drv[i].name, strcmp(g_drv[i].name, "DIBENG") ? "DRV" : "DLL");
        size_t n = ne_build(i);
        FILE *f = fopen(path, "wb");
        if (!f) { fprintf(stderr, "[drv] cannot write %s\n", path); continue; }
        fwrite(g_ne, 1, n, f);
        fclose(f);
    }
}

/* A far call into a segment that holds no lifted code: ours if tagged. */
int w16_drv_far(CPU *c, uint16_t sel, uint16_t off) {
    extern uint8_t *native32_w9x_desc(uint16_t);
    if (!(sel & 4) || !(native32_w9x_desc(sel)[5] & 0x80)) return 0;   /* ours are present; a not-present base is no address */
    const uint8_t *b = (const uint8_t *)(uintptr_t)recomp_sel_base(sel);
    if (!b || memcmp(b, "PCRD", 4) || b[4] >= NDRV) return 0;
    drv_t *d = &g_drv[b[4]];
    if (getenv("W16_TRACE")) fprintf(stderr, "[drv] %s %04X:%04X\n", d->name, sel, off);
    if (off == E_LIBENTRY) { libentry(c); return 1; }
    unsigned ord = off >= E_FIRST ? (off - E_FIRST) / 2u + 1 : 0;
    if (!ord || ord > NORD || (off - E_FIRST) % 2) w16_drv_stop("driver offset with no entry, idx:off", b[4], off);
    if (!d->fn[ord]) { fprintf(stderr, "\n[drv] %s.%u has no host function\n", d->name, ord); w16_drv_stop("driver entry not named yet, idx:ordinal", b[4], ord); }
    d->fn[ord](c);
    return 1;
}

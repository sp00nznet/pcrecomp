/*
 * gdidc.c - GDI device contexts, fonts and text, on SDL2_ttf.
 *
 * A DC is a small state record (font, colours, background mode, alignment,
 * origins) that may be bound to pixels: a DirectDraw surface's, through its
 * GetDC (ddraw.c calls hle_gdi_surface_dc). TextOutA renders into those
 * pixels; on a DC with none (a window's: nothing here draws windows) it
 * draws nothing, and the measuring calls answer either way.
 *
 * Fonts are CreateFont's requests matched to TrueType files the way a
 * desktop's font substitution would: Arial and MS Sans Serif to Liberation
 * Sans (Arial's metrics), Times to Liberation Serif, Courier to Liberation
 * Mono, else DejaVu, found by fontconfig (fc-match) or in the usual places.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <SDL2/SDL.h>
#include <SDL2/SDL_ttf.h>
#include "win32hle.h"

#define TRANSPARENT 1
#define OPAQUE      2

typedef struct {
    int used;
    uint8_t *px; int w, h, pitch, bpp;
    uint32_t font, text, bk, brush, pen, pal;
    int bkmode, align, wox, woy, vox, voy, cpx, cpy;
} dc_t;
#define MAX_DC 64
static dc_t g_dc[MAX_DC], g_saved[MAX_DC];
#define DC_BASE 0x0DC10000u

typedef struct { int used; int height, weight, italic, quality; char face[32]; TTF_Font *ttf; } font_t;
#define MAX_FONTS 64
static font_t g_font[MAX_FONTS];
#define FONT_BASE 0x0DF10000u
#define SYSTEM_FONT (FONT_BASE + MAX_FONTS)              /* the stock font: 13 px MS Sans Serif */

static dc_t *DC(uint32_t h) {
    uint32_t i = h - DC_BASE;
    return h >= DC_BASE && i < MAX_DC && g_dc[i].used ? &g_dc[i] : NULL;
}
static uint32_t new_dc(void) {
    for (int i = 0; i < MAX_DC; i++)
        if (!g_dc[i].used) {
            memset(&g_dc[i], 0, sizeof g_dc[i]);
            g_dc[i].used = 1, g_dc[i].font = SYSTEM_FONT, g_dc[i].bk = 0xFFFFFFu, g_dc[i].bkmode = OPAQUE;
            return DC_BASE + (uint32_t)i;
        }
    return 0;
}
uint32_t hle_gdi_surface_dc(uint8_t *px, int w, int h, int pitch, int bpp) {
    uint32_t d = new_dc();
    dc_t *x = DC(d);
    if (x) x->px = px, x->w = w, x->h = h, x->pitch = pitch, x->bpp = bpp;
    return d;
}
void hle_gdi_release_dc(uint32_t h) { dc_t *x = DC(h); if (x) x->used = 0; }

/* ---- fonts ---- */
static const char *font_file(const char *face, int bold, int italic) {
    static char path[512];
    const char *family = "Liberation Sans", *style = bold && italic ? "Bold Italic" : bold ? "Bold" : italic ? "Italic" : "Regular";
    if (!strncasecmp(face, "Times", 5) || !strcasecmp(face, "MS Serif") || !strcasecmp(face, "Georgia")) family = "Liberation Serif";
    else if (!strncasecmp(face, "Courier", 7) || !strcasecmp(face, "Fixedsys") || !strcasecmp(face, "Terminal")) family = "Liberation Mono";
    char cmd[256];
    snprintf(cmd, sizeof cmd, "fc-match -f '%%{file}' '%s:style=%s' 2>/dev/null", family, style);
    FILE *p = popen(cmd, "r");
    if (p) {
        size_t n = fread(path, 1, sizeof path - 1, p);
        pclose(p);
        path[n] = 0;
        if (n && access(path, R_OK) == 0) return path;
    }
    static const char *const dirs[] = { "/usr/share/fonts/truetype/liberation/", "/usr/share/fonts/truetype/liberation2/",
                                        "/usr/share/fonts/liberation/", "/usr/share/fonts/liberation-sans/",
                                        "/usr/share/fonts/TTF/", "/usr/share/fonts/truetype/dejavu/" };
    char file[64];
    snprintf(file, sizeof file, "%s-%s.ttf", strstr(family, "Serif") ? "LiberationSerif" : strstr(family, "Mono") ? "LiberationMono" : "LiberationSans",
             bold && italic ? "BoldItalic" : bold ? "Bold" : italic ? "Italic" : "Regular");
    for (size_t i = 0; i < sizeof dirs / sizeof *dirs; i++) {
        snprintf(path, sizeof path, "%s%s", dirs[i], file);
        if (access(path, R_OK) == 0) return path;
    }
    for (size_t i = 0; i < sizeof dirs / sizeof *dirs; i++) {
        snprintf(path, sizeof path, "%s%s", dirs[i], bold ? "DejaVuSans-Bold.ttf" : "DejaVuSans.ttf");
        if (access(path, R_OK) == 0) return path;
    }
    /* macOS has the faces Liberation stands in for */
    const char *mac = strstr(family, "Serif") ? "Times New Roman" : strstr(family, "Mono") ? "Courier New" : "Arial";
    snprintf(path, sizeof path, "/System/Library/Fonts/Supplemental/%s%s.ttf", mac,
             bold && italic ? " Bold Italic" : bold ? " Bold" : italic ? " Italic" : "");
    if (access(path, R_OK) == 0) return path;
    return NULL;
}
static font_t *FONT(uint32_t h) {
    if (h == SYSTEM_FONT || h < FONT_BASE || h - FONT_BASE >= MAX_FONTS || !g_font[h - FONT_BASE].used) {
        static font_t sys = { 1, -11, 400, 0, 0, "MS Sans Serif", NULL };   /* 8 pt at 96 dpi: 11 px em, 13 px cell */
        return &sys;
    }
    return &g_font[h - FONT_BASE];
}
static TTF_Font *ttf_of(font_t *f) {
    if (f->ttf) return f->ttf;
    if (!TTF_WasInit() && TTF_Init() != 0) return NULL;
    const char *file = font_file(f->face, f->weight >= 600, f->italic);
    if (!file) { fprintf(stderr, "[gdi] no TrueType font for \"%s\": text is not drawn\n", f->face); return NULL; }
    /* A negative height is the em in pixels; a positive one the cell (ascent
     * plus descent), which for these faces is about 1.15 em. */
    int em = f->height < 0 ? -f->height : f->height > 0 ? f->height * 87 / 100 : 11;
    f->ttf = TTF_OpenFont(file, em > 0 ? em : 11);
    if (f->ttf && f->quality != 3 /* NONANTIALIASED */) TTF_SetFontHinting(f->ttf, TTF_HINTING_NORMAL);
    return f->ttf;
}

static void g_CreateFontA(void) {                        /* (h, w, esc, orient, weight, italic, underline, strike, charset, out, clip, quality, pitch, face) */
    for (int i = 0; i < MAX_FONTS; i++)
        if (!g_font[i].used) {
            font_t *f = &g_font[i];
            memset(f, 0, sizeof *f);
            f->used = 1, f->height = (int)A32(0), f->weight = (int)A32(4), f->italic = A32(5) != 0, f->quality = (int)A32(11);
            snprintf(f->face, sizeof f->face, "%s", ASTR(13) ? ASTR(13) : "Arial");
            RET(FONT_BASE + (uint32_t)i, 14);
        }
    RET(SYSTEM_FONT, 14);
}
static void g_CreateFontIndirectA(void) {                /* LOGFONTA: height, width, esc, orient, weight, italic(byte)..., face at +28 */
    uint32_t lf = A32(0);
    for (int i = 0; i < MAX_FONTS; i++)
        if (!g_font[i].used) {
            font_t *f = &g_font[i];
            memset(f, 0, sizeof *f);
            f->used = 1, f->height = (int)MEM32(lf), f->weight = (int)MEM32(lf + 16), f->italic = MEM8(lf + 20) != 0, f->quality = MEM8(lf + 26);
            snprintf(f->face, sizeof f->face, "%s", (const char *)hle_ptr(lf + 28));
            RET(FONT_BASE + (uint32_t)i, 1);
        }
    RET(SYSTEM_FONT, 1);
}

/* ---- GDI objects: brushes, pens, bitmaps ----
 * One handle space (0x0DB1....). A brush/pen carry a COLORREF; a bitmap carries
 * its own pixels so it can be selected into a memory DC and blitted. */
enum { GO_BRUSH = 1, GO_PEN, GO_BITMAP, GO_PALETTE };
#define PS_NULL 5
#define HS_HOLLOW 5
typedef struct {
    int used, type;
    uint32_t color; int style, width;
    uint8_t *px; int w, h, pitch, bpp, owns;             /* bitmap */
    uint32_t *pal; int paln;                             /* palette: paln COLORREFs */
} gobj_t;
#define MAX_GOBJ 1024
static gobj_t g_obj[MAX_GOBJ];
#define GOBJ_BASE 0x0DB10000u
static gobj_t *GOBJ(uint32_t h) { uint32_t i = h - GOBJ_BASE; return h >= GOBJ_BASE && i < MAX_GOBJ && g_obj[i].used ? &g_obj[i] : NULL; }
static uint32_t new_obj(int type) {
    for (int i = 0; i < MAX_GOBJ; i++) if (!g_obj[i].used) {
        memset(&g_obj[i], 0, sizeof g_obj[i]); g_obj[i].used = 1; g_obj[i].type = type;
        return GOBJ_BASE + (uint32_t)i;
    }
    return 0;
}
static uint32_t make_brush(uint32_t color, int hatch) { uint32_t h = new_obj(GO_BRUSH); gobj_t *o = GOBJ(h); if (o) o->color = color, o->style = hatch; return h; }
static uint32_t make_pen(int style, int width, uint32_t color) { uint32_t h = new_obj(GO_PEN); gobj_t *o = GOBJ(h); if (o) o->color = color, o->style = style, o->width = width; return h; }

static uint32_t g_stock[20];
static uint32_t stock(int i) {
    if (i == 13 || i == 17 || i == 12 || i == 10) return SYSTEM_FONT;       /* font stocks: one font */
    if (i < 0 || i >= 20) return 0;
    if (!g_stock[i]) switch (i) {
        case 0: g_stock[i] = make_brush(0xFFFFFF, 0); break;               /* WHITE_BRUSH */
        case 1: g_stock[i] = make_brush(0xC0C0C0, 0); break;               /* LTGRAY_BRUSH */
        case 2: g_stock[i] = make_brush(0x808080, 0); break;               /* GRAY_BRUSH */
        case 3: g_stock[i] = make_brush(0x404040, 0); break;               /* DKGRAY_BRUSH */
        case 4: g_stock[i] = make_brush(0x000000, 0); break;               /* BLACK_BRUSH */
        case 5: g_stock[i] = make_brush(0, HS_HOLLOW); break;              /* NULL_BRUSH (hollow) */
        case 6: g_stock[i] = make_pen(0, 1, 0xFFFFFF); break;              /* WHITE_PEN */
        case 7: g_stock[i] = make_pen(0, 1, 0x000000); break;              /* BLACK_PEN */
        case 8: g_stock[i] = make_pen(PS_NULL, 1, 0); break;               /* NULL_PEN */
        default: g_stock[i] = make_brush(0xC0C0C0, 0); break;              /* DC_BRUSH etc.: a plausible one */
    }
    return g_stock[i];
}
/* The COLORREF a DC fills/strokes with (default: white brush, black pen). */
static uint32_t brush_color(const dc_t *d, int *hollow) {
    gobj_t *o = GOBJ(d->brush); if (hollow) *hollow = o ? o->style == HS_HOLLOW : 0;
    return o ? o->color : 0xFFFFFF;
}
static uint32_t pen_color(const dc_t *d, int *null) {
    gobj_t *o = GOBJ(d->pen); if (null) *null = o ? o->style == PS_NULL : 0;
    return o ? o->color : 0x000000;
}

static void g_CreateSolidBrush(void)    { RET(make_brush(A32(0), 0), 1); }
static void g_CreateHatchBrush(void)    { RET(make_brush(A32(1), 0), 2); }     /* hatch drawn as solid */
static void g_CreatePen(void)           { RET(make_pen((int)A32(0), (int)A32(1), A32(2)), 3); }
static void g_CreateBrushIndirect(void) { uint32_t lb = A32(0); RET(make_brush(lb ? MEM32(lb + 4) : 0, lb && MEM32(lb) == 1 ? HS_HOLLOW : 0), 1); } /* LOGBRUSH: style, color */
static void g_CreatePenIndirect(void)   { uint32_t lp = A32(0); RET(make_pen(lp ? (int)MEM32(lp) : 0, lp ? (int)MEM32(lp + 4) : 1, lp ? MEM32(lp + 8) : 0), 1); }

/* ---- palettes ----
 * A palette is up to 256 COLORREFs. SimCity 2000 builds one from its master
 * palette bitmap and animates it; with a 32bpp device we don't drive real
 * hardware, but an 8bpp DIB blits through the DC's selected palette (see the
 * blit path), and AnimatePalette changing an entry recolours the next blit. */
static void g_CreatePalette(void) {                      /* LOGPALETTE: version, count, PALETTEENTRY[] */
    uint32_t lp = A32(0);
    int n = lp ? (int)MEM16(lp + 2) : 0;
    if (n > 256) n = 256;
    if (n < 0) n = 0;
    uint32_t h = new_obj(GO_PALETTE); gobj_t *o = GOBJ(h);
    if (o) {
        o->pal = (uint32_t *)calloc(256, 4); o->paln = n;
        for (int i = 0; i < n; i++) { uint32_t e = lp + 4 + 4u * (uint32_t)i; o->pal[i] = MEM8(e) | (MEM8(e + 1) << 8) | (MEM8(e + 2) << 16); }
    }
    RET(h, 1);
}
static void g_GetPaletteEntries(void) {                  /* (hpal, start, count, lpentries) */
    gobj_t *o = GOBJ(A32(0)); uint32_t start = A32(1), count = A32(2), lp = A32(3), got = 0;
    if (!o || !o->pal) RET(0, 4);
    for (uint32_t i = 0; i < count && start + i < 256; i++, got++) {
        uint32_t c = o->pal[start + i];
        if (lp) { MEM8(lp + 4 * i) = c & 0xFF; MEM8(lp + 4 * i + 1) = (c >> 8) & 0xFF; MEM8(lp + 4 * i + 2) = (c >> 16) & 0xFF; MEM8(lp + 4 * i + 3) = 0; }
    }
    RET(got, 4);
}
static void g_SetPaletteEntries(void) {                  /* (hpal, start, count, lpentries) */
    gobj_t *o = GOBJ(A32(0)); uint32_t start = A32(1), count = A32(2), lp = A32(3), set = 0;
    if (!o || !o->pal) RET(0, 4);
    for (uint32_t i = 0; i < count && start + i < 256; i++, set++)
        if (lp) o->pal[start + i] = MEM8(lp + 4 * i) | (MEM8(lp + 4 * i + 1) << 8) | (MEM8(lp + 4 * i + 2) << 16);
    if ((int)(start + count) > o->paln) o->paln = (start + count) > 256 ? 256 : (int)(start + count);
    RET(set, 4);
}
static void g_AnimatePalette(void) { g_SetPaletteEntries(); }    /* same store; the next blit recolours */
static void g_GetNearestPaletteIndex(void) {             /* (hpal, color) */
    gobj_t *o = GOBJ(A32(0)); uint32_t c = A32(1); int best = 0; long bd = -1;
    int r = c & 0xFF, g = (c >> 8) & 0xFF, b = (c >> 16) & 0xFF;
    if (o && o->pal) for (int i = 0; i < o->paln; i++) {
        uint32_t p = o->pal[i]; int dr = r - (int)(p & 0xFF), dg = g - (int)((p >> 8) & 0xFF), db = b - (int)((p >> 16) & 0xFF);
        long d = (long)dr * dr + dg * dg + db * db;
        if (bd < 0 || d < bd) bd = d, best = i;
    }
    RET((uint32_t)best, 2);
}
static void g_SelectPalette(void) { dc_t *d = DC(A32(0)); uint32_t old = d ? d->pal : 0; if (d) d->pal = A32(1); RET(old, 3); }
static void g_RealizePalette(void) { dc_t *d = DC(A32(0)); gobj_t *o = d ? GOBJ(d->pal) : NULL; RET(o ? (uint32_t)o->paln : 0u, 1); }
static void g_ResizePalette(void) { gobj_t *o = GOBJ(A32(0)); if (o) o->paln = (int)A32(1) > 256 ? 256 : (int)A32(1); RET(1, 2); }
static void g_GetSystemPaletteEntries(void) { RET(0, 4); }       /* truecolour device: no system palette */
static void g_SetSystemPaletteUse(void) { RET(1, 2); }           /* SYSPAL_STATIC */
static void g_GetSystemPaletteUse(void) { RET(1, 1); }
static void g_UpdateColors(void) { RET(1, 1); }

/* ---- objects ---- */
int hle_gdi_dib_delete(uint32_t h);                      /* gdi32.c */
static void g_DeleteObject(void) {
    uint32_t h = A32(0);
    if (h >= FONT_BASE && h - FONT_BASE < MAX_FONTS && g_font[h - FONT_BASE].used) {
        font_t *f = &g_font[h - FONT_BASE];
        if (f->ttf) TTF_CloseFont(f->ttf);
        f->used = 0, f->ttf = NULL;
        RET(1, 1);
    }
    gobj_t *o = GOBJ(h);
    if (o) { if (o->owns) free(o->px); free(o->pal); o->used = 0; RET(1, 1); }
    RET(hle_gdi_dib_delete(h) || 1, 1);
}
static void g_GetStockObject(void) { RET(stock((int)A32(0)), 1); }
static void g_SelectObject(void) {                       /* (hdc, obj) -> the previous of its kind */
    dc_t *d = DC(A32(0));
    uint32_t o = A32(1), old;
    if (o >= FONT_BASE && o <= SYSTEM_FONT) {
        if (!d) RET(SYSTEM_FONT, 2);
        old = d->font, d->font = o; RET(old, 2);
    }
    gobj_t *g = GOBJ(o);
    if (d && g && g->type == GO_BRUSH) { old = d->brush ? d->brush : stock(0); d->brush = o; RET(old, 2); }
    if (d && g && g->type == GO_PEN)   { old = d->pen ? d->pen : stock(7);   d->pen = o;   RET(old, 2); }
    if (d && g && g->type == GO_BITMAP) {                /* select a bitmap into a memory DC */
        d->px = g->px, d->w = g->w, d->h = g->h, d->pitch = g->pitch, d->bpp = g->bpp;
        RET(stock(0), 2);
    }
    RET(stock(0), 2);
}

/* make a selectable bitmap object with its own pixels (CreateCompatibleBitmap
 * / CreateBitmap). gdi32.c's CreateDIBSection registers its DIB this way too. */
uint32_t hle_gdi_make_bitmap(int w, int h, int bpp, uint8_t *px, int owns) {
    uint32_t handle = new_obj(GO_BITMAP); gobj_t *o = GOBJ(handle);
    if (o) { o->w = w, o->h = h, o->bpp = bpp, o->pitch = w * (bpp / 8); o->px = px; o->owns = owns; }
    return handle;
}
static void g_CreateCompatibleBitmap(void) {             /* (hdc, w, h) -> 32bpp bitmap */
    int w = (int)A32(1), h = (int)A32(2); if (w < 1) w = 1; if (h < 1) h = 1;
    RET(hle_gdi_make_bitmap(w, h, 32, (uint8_t *)calloc((size_t)w * h, 4), 1), 3);
}
static void g_CreateBitmap(void) {                       /* (w, h, planes, bpp, bits) */
    int w = (int)A32(0), h = (int)A32(1), bpp = (int)A32(3); if (bpp < 8) bpp = 8;
    RET(hle_gdi_make_bitmap(w, h, bpp == 24 ? 32 : bpp, (uint8_t *)calloc((size_t)w * h, bpp / 8 ? bpp / 8 : 1), 1), 5);
}

/* ---- DCs ---- */
static void g_GetDC(void)     { RET(new_dc(), 1); }      /* a window's: state only */
static void g_ReleaseDC(void) { hle_gdi_release_dc(A32(1)); RET(1, 2); }
static void g_SaveDC(void)    { dc_t *d = DC(A32(0)); if (d) g_saved[d - g_dc] = *d; RET(d ? 1u : 0u, 1); }
static void g_RestoreDC(void) { dc_t *d = DC(A32(0)); if (d && g_saved[d - g_dc].used) *d = g_saved[d - g_dc]; RET(d ? 1u : 0u, 2); }
#define SETTER(name, field, def, argc) \
    static void g_##name(void) { dc_t *d = DC(A32(0)); uint32_t old = d ? (uint32_t)d->field : def; if (d) d->field = A32(1); RET(old, argc); }
#define GETTER(name, field, def) \
    static void g_##name(void) { dc_t *d = DC(A32(0)); RET(d ? (uint32_t)d->field : def, 1); }
SETTER(SetTextColor, text, 0u, 2)
SETTER(SetBkColor, bk, 0xFFFFFFu, 2)
SETTER(SetBkMode, bkmode, OPAQUE, 2)
SETTER(SetTextAlign, align, 0u, 2)
GETTER(GetTextColor, text, 0u)
GETTER(GetBkColor, bk, 0xFFFFFFu)
GETTER(GetBkMode, bkmode, OPAQUE)
static void g_SetViewportOrgEx(void) {                   /* (hdc, x, y, &old) */
    dc_t *d = DC(A32(0));
    if (A32(3)) MEM32(A32(3)) = d ? (uint32_t)d->vox : 0, MEM32(A32(3) + 4) = d ? (uint32_t)d->voy : 0;
    if (d) d->vox = (int)A32(1), d->voy = (int)A32(2);
    RET(1, 4);
}
static void g_SetWindowOrgEx(void) {
    dc_t *d = DC(A32(0));
    if (A32(3)) MEM32(A32(3)) = d ? (uint32_t)d->wox : 0, MEM32(A32(3) + 4) = d ? (uint32_t)d->woy : 0;
    if (d) d->wox = (int)A32(1), d->woy = (int)A32(2);
    RET(1, 4);
}
static void g_DPtoLP(void) {                             /* (hdc, pts, n) */
    dc_t *d = DC(A32(0));
    for (uint32_t i = 0; d && i < A32(2); i++)
        MEM32(A32(1) + 8 * i) += (uint32_t)(d->wox - d->vox), MEM32(A32(1) + 8 * i + 4) += (uint32_t)(d->woy - d->voy);
    RET(1, 3);
}
static void g_SetGraphicsMode(void) { RET(1u, 2); }
static void g_ModifyWorldTransform(void) { RET(1, 3); }

/* ---- text ---- */
static void g_GetTextExtentPoint32A(void) {              /* (hdc, text, n, &SIZE) */
    dc_t *d = DC(A32(0));
    font_t *f = FONT(d ? d->font : SYSTEM_FONT);
    TTF_Font *t = ttf_of(f);
    int n = (int)A32(2), w = 6 * n, h = 13;
    if (t && n > 0) {
        char buf[1024];
        if (n >= (int)sizeof buf) n = sizeof buf - 1;
        memcpy(buf, APTR(1), (size_t)n), buf[n] = 0;
        TTF_SizeText(t, buf, &w, &h);
    } else if (t) {
        w = 0, h = TTF_FontHeight(t);
    }
    if (A32(3)) MEM32(A32(3)) = (uint32_t)w, MEM32(A32(3) + 4) = (uint32_t)h;
    RET(1, 4);
}
static void g_GetTextMetricsA(void) {                    /* TEXTMETRICA */
    dc_t *d = DC(A32(0));
    TTF_Font *t = ttf_of(FONT(d ? d->font : SYSTEM_FONT));
    uint32_t m = A32(1);
    if (!m) RET(0, 2);
    memset(hle_ptr(m), 0, 56);
    int asc = t ? TTF_FontAscent(t) : 10, desc = t ? -TTF_FontDescent(t) : 3, ave = 6, max = 12;
    if (t) { int w; TTF_SizeText(t, "x", &ave, &w); TTF_SizeText(t, "W", &max, &w); }
    MEM32(m) = (uint32_t)(asc + desc), MEM32(m + 4) = (uint32_t)asc, MEM32(m + 8) = (uint32_t)desc;
    MEM32(m + 20) = (uint32_t)ave, MEM32(m + 24) = (uint32_t)max, MEM32(m + 28) = 400;
    MEM8(m + 45) = 0x20, MEM8(m + 46) = 0xFF, MEM8(m + 47) = 0x1F, MEM8(m + 48) = 0x20;
    MEM8(m + 51) = 0x26;                                 /* TMPF_VARIABLE_PITCH | VECTOR | TRUETYPE */
    RET(1, 2);
}

static uint32_t pack(const dc_t *d, uint32_t cr) {       /* COLORREF 0x00BBGGRR -> the surface's pixel */
    uint32_t r = cr & 0xFF, g = (cr >> 8) & 0xFF, b = (cr >> 16) & 0xFF;
    if (d->bpp == 16) return (r >> 3) << 11 | (g >> 2) << 5 | (b >> 3);
    return r << 16 | g << 8 | b;
}
static void put(dc_t *d, int x, int y, uint32_t v) {
    uint8_t *p = d->px + (size_t)y * d->pitch + (size_t)x * (size_t)(d->bpp / 8);
    if (d->bpp == 16) *(uint16_t *)p = (uint16_t)v;
    else if (d->bpp == 32) *(uint32_t *)p = v;
}
static uint32_t get(dc_t *d, int x, int y) {
    const uint8_t *p = d->px + (size_t)y * d->pitch + (size_t)x * (size_t)(d->bpp / 8);
    return d->bpp == 16 ? *(const uint16_t *)p : *(const uint32_t *)p;
}
static uint32_t mix(const dc_t *d, uint32_t under, uint32_t over, int a) {
    if (a >= 255) return over;
    if (d->bpp == 16) {
        int r = ((under >> 11) * (255 - a) + (over >> 11) * a) / 255;
        int g = (((under >> 5) & 63) * (255 - a) + ((over >> 5) & 63) * a) / 255;
        int b = ((under & 31) * (255 - a) + (over & 31) * a) / 255;
        return (uint32_t)(r << 11 | g << 5 | b);
    }
    uint32_t out = 0;
    for (int s = 0; s < 24; s += 8)
        out |= (uint32_t)((((under >> s) & 255) * (255 - a) + ((over >> s) & 255) * a) / 255) << s;
    return out;
}

static void g_TextOutA(void) {                           /* (hdc, x, y, text, n) */
    dc_t *d = DC(A32(0));
    int n = (int)A32(4);
    if (!d || !d->px || n <= 0 || (d->bpp != 16 && d->bpp != 32)) RET(1, 5);
    font_t *f = FONT(d->font);
    TTF_Font *t = ttf_of(f);
    if (!t) RET(1, 5);
    char buf[1024];
    if (n >= (int)sizeof buf) n = sizeof buf - 1;
    memcpy(buf, APTR(3), (size_t)n), buf[n] = 0;
    SDL_Color white = { 255, 255, 255, 255 };
    SDL_Surface *s = f->quality == 3 ? TTF_RenderText_Solid(t, buf, white) : TTF_RenderText_Blended(t, buf, white);
    if (!s) RET(1, 5);
    int x = (int)A32(1) - d->wox + d->vox, y = (int)A32(2) - d->woy + d->voy;
    if ((d->align & 6) == 6) x -= s->w / 2;              /* TA_CENTER */
    else if (d->align & 2) x -= s->w;                    /* TA_RIGHT */
    if ((d->align & 24) == 24) y -= TTF_FontAscent(t);   /* TA_BASELINE */
    else if (d->align & 8) y -= s->h;                    /* TA_BOTTOM */
    uint32_t fg = pack(d, d->text), bg = pack(d, d->bk);
    SDL_LockSurface(s);
    for (int j = 0; j < s->h; j++) {
        int py = y + j;
        if (py < 0 || py >= d->h) continue;
        for (int i = 0; i < s->w; i++) {
            int px = x + i;
            if (px < 0 || px >= d->w) continue;
            int a;
            if (s->format->BytesPerPixel == 1) a = ((const uint8_t *)s->pixels)[j * s->pitch + i] ? 255 : 0;
            else a = (int)(((const uint32_t *)((const uint8_t *)s->pixels + j * s->pitch))[i] >> 24);
            if (d->bkmode == OPAQUE) put(d, px, py, mix(d, bg, fg, a));
            else if (a) put(d, px, py, mix(d, get(d, px, py), fg, a));
        }
    }
    SDL_UnlockSurface(s);
    SDL_FreeSurface(s);
    RET(1, 5);
}

/* ---- drawing ---- */
static void rectfill(dc_t *d, int l, int t, int r, int b, uint32_t cr) {
    if (!d || !d->px) return;
    int ox = d->wox - d->vox, oy = d->woy - d->voy;
    l -= ox; r -= ox; t -= oy; b -= oy;
    if (l > r) { int x = l; l = r; r = x; }
    if (t > b) { int y = t; t = b; b = y; }
    if (l < 0) l = 0;
    if (t < 0) t = 0;
    if (r > d->w) r = d->w;
    if (b > d->h) b = d->h;
    uint32_t v = pack(d, cr);
    for (int y = t; y < b; y++) for (int x = l; x < r; x++) put(d, x, y, v);
}
static void g_FillRect(void) {                           /* (hdc, &RECT, hbrush) */
    dc_t *d = DC(A32(0)); uint32_t rc = A32(1); gobj_t *b = GOBJ(A32(2));
    if (d && rc && b && b->style != HS_HOLLOW)
        rectfill(d, (int)MEM32(rc), (int)MEM32(rc + 4), (int)MEM32(rc + 8), (int)MEM32(rc + 12), b->color);
    RET(1, 3);
}
static void g_FrameRect(void) {                          /* (hdc, &RECT, hbrush): 1px border */
    dc_t *d = DC(A32(0)); uint32_t rc = A32(1); gobj_t *b = GOBJ(A32(2));
    if (d && rc && b) {
        int l = (int)MEM32(rc), t = (int)MEM32(rc + 4), r = (int)MEM32(rc + 8), bo = (int)MEM32(rc + 12);
        rectfill(d, l, t, r, t + 1, b->color); rectfill(d, l, bo - 1, r, bo, b->color);
        rectfill(d, l, t, l + 1, bo, b->color); rectfill(d, r - 1, t, r, bo, b->color);
    }
    RET(1, 3);
}
static void g_Rectangle(void) {                          /* (hdc, l, t, r, b): brush fill + pen frame */
    dc_t *d = DC(A32(0)); if (!d) RET(1, 5);
    int l = (int)A32(1), t = (int)A32(2), r = (int)A32(3), b = (int)A32(4), hollow = 0, pnull = 0;
    uint32_t bc = brush_color(d, &hollow), pc = pen_color(d, &pnull);
    if (!hollow) rectfill(d, l + 1, t + 1, r - 1, b - 1, bc);
    if (!pnull) { rectfill(d, l, t, r, t + 1, pc); rectfill(d, l, b - 1, r, b, pc); rectfill(d, l, t, l + 1, b, pc); rectfill(d, r - 1, t, r, b, pc); }
    RET(1, 5);
}
static void g_PatBlt(void) {                             /* (hdc,x,y,w,h,rop): BLACKNESS/WHITENESS/PATCOPY */
    dc_t *d = DC(A32(0)); int x = (int)A32(1), y = (int)A32(2), w = (int)A32(3), h = (int)A32(4); uint32_t rop = A32(5), hollow = 0;
    uint32_t cr = rop == 0x42u ? 0x000000u : rop == 0x00FF0062u ? 0xFFFFFFu : brush_color(d, (int *)&hollow);
    if (d) rectfill(d, x, y, x + w, y + h, cr);
    RET(1, 6);
}
static void g_SetPixel(void) { dc_t *d = DC(A32(0)); if (d && d->px) { int x = (int)A32(1) - d->wox + d->vox, y = (int)A32(2) - d->woy + d->voy; if (x >= 0 && y >= 0 && x < d->w && y < d->h) put(d, x, y, pack(d, A32(3))); } RET(A32(3), 4); }
static void g_GetPixel(void) { dc_t *d = DC(A32(0)); int x = (int)A32(1), y = (int)A32(2); RET(d && d->px && x >= 0 && y >= 0 && x < d->w && y < d->h ? get(d, x, y) : 0xFFFFFFFFu, 3); }
static void g_MoveToEx(void) { dc_t *d = DC(A32(0)); if (A32(3) && d) { MEM32(A32(3)) = (uint32_t)d->cpx; MEM32(A32(3) + 4) = (uint32_t)d->cpy; } if (d) { d->cpx = (int)A32(1); d->cpy = (int)A32(2); } RET(1, 4); }
static void g_LineTo(void) {                             /* Bresenham cp -> (x,y) in pen colour */
    dc_t *d = DC(A32(0)); int x1 = (int)A32(1), y1 = (int)A32(2);
    if (d && d->px) {
        int pn = 0; uint32_t v = pack(d, pen_color(d, &pn)); int x0 = d->cpx, y0 = d->cpy;
        if (!pn) {
            int dx = abs(x1 - x0), dy = -abs(y1 - y0), sx = x0 < x1 ? 1 : -1, sy = y0 < y1 ? 1 : -1, e = dx + dy;
            for (;;) {
                int px = x0 - d->wox + d->vox, py = y0 - d->woy + d->voy;
                if (px >= 0 && py >= 0 && px < d->w && py < d->h) put(d, px, py, v);
                if (x0 == x1 && y0 == y1) break;
                int e2 = 2 * e;
                if (e2 >= dy) { e += dy; x0 += sx; }
                if (e2 <= dx) { e += dx; y0 += sy; }
            }
        }
    }
    if (d) { d->cpx = x1; d->cpy = y1; } RET(1, 3);
}
/* ---- blits (DC -> DC); like-for-like bpp, which is what a game's own
 * back-buffer-to-window blit is ---- */
static void blt(dc_t *dst, int dx, int dy, int w, int h, dc_t *src, int sx, int sy, int sw, int sh) {
    if (!dst || !dst->px || !src || !src->px || w <= 0 || h <= 0) return;
    for (int j = 0; j < h; j++) {
        int py = dy + j; if (py < 0 || py >= dst->h) continue;
        int sj = sy + (sh == h ? j : j * sh / h); if (sj < 0 || sj >= src->h) continue;
        for (int i = 0; i < w; i++) {
            int px = dx + i; if (px < 0 || px >= dst->w) continue;
            int si = sx + (sw == w ? i : i * sw / w); if (si < 0 || si >= src->w) continue;
            put(dst, px, py, get(src, si, sj));
        }
    }
}
static void g_BitBlt(void)     { dc_t *d = DC(A32(0)), *s = DC(A32(5)); blt(d,(int)A32(1),(int)A32(2),(int)A32(3),(int)A32(4),s,(int)A32(6),(int)A32(7),(int)A32(3),(int)A32(4)); RET(1, 9); }
static void g_StretchBlt(void) { dc_t *d = DC(A32(0)), *s = DC(A32(5)); blt(d,(int)A32(1),(int)A32(2),(int)A32(3),(int)A32(4),s,(int)A32(6),(int)A32(7),(int)A32(8),(int)A32(9)); RET(1, 11); }
static void g_CreateCompatibleDC(void) { RET(new_dc(), 1); }   /* a memory DC; a bitmap is selected into it */
static void g_DeleteDC(void) { hle_gdi_release_dc(A32(0)); RET(1, 1); }

const win32hle_shim win32hle_gdidc[] = {
    { "CreateSolidBrush", g_CreateSolidBrush }, { "CreateHatchBrush", g_CreateHatchBrush },
    { "CreateBrushIndirect", g_CreateBrushIndirect }, { "CreatePen", g_CreatePen }, { "CreatePenIndirect", g_CreatePenIndirect },
    { "CreateCompatibleBitmap", g_CreateCompatibleBitmap }, { "CreateBitmap", g_CreateBitmap },
    { "CreateCompatibleDC", g_CreateCompatibleDC }, { "DeleteDC", g_DeleteDC },
    { "CreatePalette", g_CreatePalette }, { "GetPaletteEntries", g_GetPaletteEntries },
    { "SetPaletteEntries", g_SetPaletteEntries }, { "AnimatePalette", g_AnimatePalette },
    { "GetNearestPaletteIndex", g_GetNearestPaletteIndex }, { "SelectPalette", g_SelectPalette },
    { "RealizePalette", g_RealizePalette }, { "ResizePalette", g_ResizePalette },
    { "GetSystemPaletteEntries", g_GetSystemPaletteEntries }, { "SetSystemPaletteUse", g_SetSystemPaletteUse },
    { "GetSystemPaletteUse", g_GetSystemPaletteUse }, { "UpdateColors", g_UpdateColors },
    { "FillRect", g_FillRect }, { "FrameRect", g_FrameRect }, { "Rectangle", g_Rectangle }, { "PatBlt", g_PatBlt },
    { "SetPixel", g_SetPixel }, { "SetPixelV", g_SetPixel }, { "GetPixel", g_GetPixel },
    { "MoveToEx", g_MoveToEx }, { "LineTo", g_LineTo }, { "BitBlt", g_BitBlt }, { "StretchBlt", g_StretchBlt },
    { "CreateFontA", g_CreateFontA }, { "CreateFontIndirectA", g_CreateFontIndirectA },
    { "DeleteObject", g_DeleteObject }, { "GetStockObject", g_GetStockObject }, { "SelectObject", g_SelectObject },
    { "GetDC", g_GetDC }, { "ReleaseDC", g_ReleaseDC }, { "SaveDC", g_SaveDC }, { "RestoreDC", g_RestoreDC },
    { "SetTextColor", g_SetTextColor }, { "SetBkColor", g_SetBkColor }, { "SetBkMode", g_SetBkMode },
    { "SetTextAlign", g_SetTextAlign }, { "GetTextColor", g_GetTextColor }, { "GetBkColor", g_GetBkColor },
    { "GetBkMode", g_GetBkMode }, { "SetViewportOrgEx", g_SetViewportOrgEx }, { "SetWindowOrgEx", g_SetWindowOrgEx },
    { "DPtoLP", g_DPtoLP }, { "SetGraphicsMode", g_SetGraphicsMode }, { "ModifyWorldTransform", g_ModifyWorldTransform },
    { "GetTextExtentPoint32A", g_GetTextExtentPoint32A }, { "GetTextExtentPointA", g_GetTextExtentPoint32A },
    { "GetTextMetricsA", g_GetTextMetricsA }, { "TextOutA", g_TextOutA },
    { 0, 0 }
};

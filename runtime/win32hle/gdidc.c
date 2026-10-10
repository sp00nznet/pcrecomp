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
    uint32_t font, text, bk, brush;
    int bkmode, align, wox, woy, vox, voy;
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
            snprintf(f->face, sizeof f->face, "%s", (const char *)(uintptr_t)(lf + 28));
            RET(FONT_BASE + (uint32_t)i, 1);
        }
    RET(SYSTEM_FONT, 1);
}

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
    RET(hle_gdi_dib_delete(h) || 1, 1);
}
static void g_GetStockObject(void) {
    uint32_t i = A32(0);
    RET(i == 13 || i == 17 || i == 12 || i == 10 ? SYSTEM_FONT : 0x0DB00001u + i, 1);   /* the font stocks: one font */
}
static void g_SelectObject(void) {                       /* (hdc, obj) -> the previous of its kind */
    dc_t *d = DC(A32(0));
    uint32_t o = A32(1), old;
    if ((o >= FONT_BASE && o <= SYSTEM_FONT)) {
        if (!d) RET(SYSTEM_FONT, 2);
        old = d->font, d->font = o;
        RET(old, 2);
    }
    if (d && (o >> 16) == 0x0DB1u) { old = d->brush ? d->brush : 0x0DB00001u; d->brush = o; RET(old, 2); }
    RET(0x0DB00001u, 2);                                 /* a stock object of that kind */
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
    memset((void *)(uintptr_t)m, 0, 56);
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

const win32hle_shim win32hle_gdidc[] = {
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

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
    int win, is555;                                      /* draws into the window surface; 16bpp is 5-5-5 */
    const uint32_t *ctab;                                /* an 8bpp DIB's colour table, 0x00RRGGBB */
    uint32_t bmp;                                        /* the bitmap selected into it */
    int clip, cl, ct, cr, cb;                            /* SelectClipRgn's rectangle, in pixels */
} dc_t;
#define MAX_DC 4096                      /* Civilization III's jgl keeps one per surface */
static dc_t g_dc[MAX_DC], g_saved[MAX_DC];
#define DC_BASE 0x0DC10000u

typedef struct { int used; int height, weight, italic, quality; char face[32]; TTF_Font *ttf; int crisp, synth_bold, underline; } font_t;
#define MAX_FONTS 1024                    /* Civilization III: 37 sizes in each of 8 styles */
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

/* The window surface: the pixels a GDI game's window DCs (GetDC, BeginPaint)
 * draw into, set by the host at the display mode's size. There is one, for
 * every window: a game that draws its whole screen into one top-level window
 * is what it serves. Off (no surface), a window DC is state only. */
static uint8_t *g_win_px;
static int g_win_w, g_win_h, g_win_pitch, g_win_bpp;
static volatile unsigned g_win_seq;
void hle_gdi_window_surface(uint8_t *px, int w, int h, int pitch, int bpp) {
    g_win_px = px, g_win_w = w, g_win_h = h, g_win_pitch = pitch, g_win_bpp = bpp;
    g_win_seq++;
    /* A window DC the game keeps (Civilization III's jgl holds its own)
     * follows a mode change: it had been drawing into the old pixels. */
    for (int i = 0; i < MAX_DC; i++)
        if (g_dc[i].used && g_dc[i].win) g_dc[i].px = px, g_dc[i].w = w, g_dc[i].h = h, g_dc[i].pitch = pitch, g_dc[i].bpp = bpp;
}
uint32_t hle_gdi_window_dc(void) {
    uint32_t d = new_dc();
    dc_t *x = DC(d);
    if (x && g_win_px) x->px = g_win_px, x->w = g_win_w, x->h = g_win_h, x->pitch = g_win_pitch, x->bpp = g_win_bpp, x->win = 1;
    return d;
}
void (*hle_gdi_window_hook)(void);                     /* the presenter: a blit reached the window */
void hle_gdi_window_touched(void) { g_win_seq++; if (hle_gdi_window_hook) hle_gdi_window_hook(); }   /* a host drew into it directly */
int hle_gdi_window_frame(const uint8_t **px, int *w, int *h, int *pitch, int *bpp, unsigned *seq) {
    if (!g_win_px) return 0;
    *px = g_win_px, *w = g_win_w, *h = g_win_h, *pitch = g_win_pitch, *bpp = g_win_bpp;
    if (seq) *seq = g_win_seq;
    return 1;
}

/* ---- fonts ---- */
/* A font file through our own read, not SDL's: a 32-bit SDL's stat fails
 * with EOVERFLOW on a disk with 64-bit inode numbers (XFS, Btrfs, WSL's
 * /mnt), and calls the game's own font "not a regular file". Each file is
 * read once and kept: an open font reads from it. */
static struct { char path[512]; void *data; long n; } g_font_files[32];
static int font_data(const char *path) {                 /* its slot, read on first use; -1 if not */
    int i = 0;
    while (i < 32 && g_font_files[i].data && strcmp(g_font_files[i].path, path)) i++;
    if (i == 32) return -1;
    if (!g_font_files[i].data) {
        FILE *f = fopen(path, "rb");
        if (!f) return -1;
        fseek(f, 0, SEEK_END);
        long n = ftell(f);
        void *data = n > 0 ? malloc((size_t)n) : NULL;
        rewind(f);
        if (!data || fread(data, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(data); return -1; }
        fclose(f);
        snprintf(g_font_files[i].path, sizeof g_font_files[i].path, "%s", path);
        g_font_files[i].data = data, g_font_files[i].n = n;
    }
    return i;
}
static TTF_Font *open_font(const char *path, int size) {
    int i = font_data(path);
    if (i < 0) return TTF_OpenFont(path, size);
    return TTF_OpenFontRW(SDL_RWFromConstMem(g_font_files[i].data, (int)g_font_files[i].n), 1, size);
}
/* Whether Windows smooths this face at this size: its 'gasp' table says,
 * range by range (GASP_DOGRAY); with none, it does. Civilization III's
 * Lucida Sans says no from 9 to 22 px, and its menus are drawn crisp. */
static int gasp_gray(const char *path, int ppem) {
    int i = font_data(path);
    if (i < 0) return 1;
    const uint8_t *p = (const uint8_t *)g_font_files[i].data;
    long n = g_font_files[i].n;
#define BE16(o) ((uint32_t)p[o] << 8 | p[(o) + 1])
#define BE32(o) (BE16(o) << 16 | BE16((o) + 2))
    if (n < 12) return 1;
    for (uint32_t t = 0, nt = BE16(4); t < nt && 12 + 16 * (long)t + 16 <= n; t++) {
        uint32_t e = 12 + 16 * t;
        if (memcmp(p + e, "gasp", 4)) continue;
        uint32_t o = BE32(e + 8);
        if ((long)o + 4 > n) return 1;
        for (uint32_t r = 0, nr = BE16(o + 2); r < nr && (long)(o + 4 + 4 * r + 4) <= n; r++)
            if ((uint32_t)ppem <= BE16(o + 4 + 4 * r)) return (BE16(o + 6 + 4 * r) & 2) != 0;
        return 1;
    }
    return 1;
#undef BE16
#undef BE32
}

/* Fonts the guest added from its own files (AddFontResourceA, through a .fot
 * CreateScalableFontResourceA made): face name and TrueType file. A game
 * that ships its face (Civilization III's Lucida Sans) gets it by name. */
#define MAX_ADDED 16
static struct { char family[64], path[512]; } g_added[MAX_ADDED];
static int g_nadded;
static struct { char fot[260], ttf[512]; } g_fot[MAX_ADDED];
static int g_nfot;
static void g_CreateScalableFontResourceA(void) {        /* (hidden, fot, ttf, path) */
    const char *fot = ASTR(1), *ttf = ASTR(2), *dir = ASTR(3);
    char guest[600];
    if (win32hle_trace) fprintf(stderr, "[gdi] CreateScalableFontResourceA(%u, \"%s\", \"%s\", \"%s\")\n", A32(0), fot ? fot : "", ttf ? ttf : "", dir ? dir : "");
    if (!fot || !ttf) RET(0, 4);
    for (int i = 0; i < g_nfot; i++)                     /* made already: Windows says the file exists */
        if (!strcasecmp(g_fot[i].fot, fot)) { hle_set_last_error(80); RET(0, 4); }   /* ERROR_FILE_EXISTS */
    if (g_nfot >= MAX_ADDED) RET(0, 4);
    int in_dir = dir && *dir && !strchr(ttf, '\\');        /* a bare file name is in path */
    snprintf(guest, sizeof guest, "%s%s%s", in_dir ? dir : "", in_dir ? "\\" : "", ttf);
    if (!hle_host_path(guest, g_fot[g_nfot].ttf, sizeof g_fot[g_nfot].ttf) &&
        !hle_host_path(ttf, g_fot[g_nfot].ttf, sizeof g_fot[g_nfot].ttf)) {
        fprintf(stderr, "[gdi] CreateScalableFontResourceA(\"%s\", \"%s\", \"%s\"): no such file\n", fot, ttf, dir ? dir : "");
        RET(0, 4);
    }
    snprintf(g_fot[g_nfot++].fot, sizeof g_fot[0].fot, "%s", fot);
    RET(1, 4);
}
static void g_AddFontResourceA(void) {
    const char *name = ASTR(0), *path = NULL;
    char host[512];
    if (!name) RET(0, 1);
    for (int i = 0; i < g_nfot; i++) if (!strcasecmp(g_fot[i].fot, name)) path = g_fot[i].ttf;
    if (!path && hle_host_path(name, host, sizeof host)) path = host;
    for (int i = 0; path && i < g_nadded; i++) if (!strcmp(g_added[i].path, path)) RET(1, 1);   /* added already */
    if (!path || (!TTF_WasInit() && TTF_Init() != 0)) {
        fprintf(stderr, "[gdi] AddFontResourceA(\"%s\"): no such file\n", name);
        RET(0, 1);
    }
    TTF_Font *f = open_font(path, 12);
    const char *family = f ? TTF_FontFaceFamilyName(f) : NULL;
    if (family && g_nadded < MAX_ADDED) {
        snprintf(g_added[g_nadded].family, sizeof g_added[0].family, "%s", family);
        snprintf(g_added[g_nadded++].path, sizeof g_added[0].path, "%s", path);
        fprintf(stderr, "[gdi] font \"%s\" from %s\n", family, path);
    }
    if (f) TTF_CloseFont(f);
    if (!family) fprintf(stderr, "[gdi] AddFontResourceA(\"%s\"): no font in %s (%s)\n", name, path, TTF_GetError());
    RET(family ? 1u : 0u, 1);
}
static void g_RemoveFontResourceA(void) { RET(1, 1); }

static const char *font_file(const char *face, int bold, int italic) {
    static char path[512];
    for (int i = 0; i < g_nadded; i++) if (!strcasecmp(g_added[i].family, face)) return g_added[i].path;   /* ponytail: one file per face, its style whatever bold asks */
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
    f->ttf = open_font(file, em > 0 ? em : 11);
    f->crisp = f->quality == 3 || (f->quality != 4 && f->quality != 5 && !gasp_gray(file, em));   /* not ANTIALIASED, CLEARTYPE */
    if (!f->ttf) return NULL;
    /* Crisp text is hinted fully, as GDI hints it, advances included: what
     * FreeType does only for monochrome. */
    TTF_SetFontHinting(f->ttf, f->crisp ? TTF_HINTING_MONO : TTF_HINTING_NORMAL);
    TTF_SetFontKerning(f->ttf, 0);                       /* GDI's TextOut does not kern */
    int one_face = 0;                                    /* a game's own font, one file for every style */
    for (int i = 0; i < g_nadded; i++) one_face |= file == g_added[i].path;
    f->synth_bold = one_face && f->weight >= 600;        /* bold and italic as Windows makes them */
    TTF_SetFontStyle(f->ttf, (one_face && f->italic ? TTF_STYLE_ITALIC : 0) | (f->underline ? TTF_STYLE_UNDERLINE : 0));
    return f->ttf;
}

static void g_CreateFontA(void) {                        /* (h, w, esc, orient, weight, italic, underline, strike, charset, out, clip, quality, pitch, face) */
    for (int i = 0; i < MAX_FONTS; i++)
        if (!g_font[i].used) {
            font_t *f = &g_font[i];
            memset(f, 0, sizeof *f);
            f->used = 1, f->height = (int)A32(0), f->weight = (int)A32(4), f->italic = A32(5) != 0, f->quality = (int)A32(11);
            f->underline = A32(6) != 0;
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
            f->underline = MEM8(lf + 21) != 0;
            snprintf(f->face, sizeof f->face, "%s", (const char *)(uintptr_t)(lf + 28));
            if (win32hle_trace) fprintf(stderr, "[gdi] CreateFontIndirectA(\"%s\", height %d, width %d, weight %d, italic %d, underline %d, quality %d)\n",
                                        f->face, f->height, (int)MEM32(lf + 4), f->weight, f->italic, MEM8(lf + 21), f->quality);
            RET(FONT_BASE + (uint32_t)i, 1);
        }
    RET(SYSTEM_FONT, 1);
}

/* ---- GDI objects: brushes, pens, bitmaps ----
 * One handle space (0x0DB1....). A brush/pen carry a COLORREF; a bitmap carries
 * its own pixels so it can be selected into a memory DC and blitted. */
enum { GO_BRUSH = 1, GO_PEN, GO_BITMAP, GO_PALETTE, GO_REGION };
#define PS_NULL 5
#define HS_HOLLOW 5
typedef struct {
    int used, type;
    uint32_t color; int style, width;
    uint8_t *px; int w, h, pitch, bpp, owns;             /* bitmap */
    uint32_t *pal; int paln;                             /* palette: paln COLORREFs; a DIB's colour table, 0x00RRGGBB */
    int is555;                                           /* a 16bpp DIB in 5-5-5 (BI_RGB) */
} gobj_t;
#define MAX_GOBJ 8192
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
    if (o) { if (o->owns) free(o->px); else hle_gdi_dib_delete(h); free(o->pal); o->used = 0; RET(1, 1); }
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
        old = d->bmp ? d->bmp : stock(0);
        d->px = g->px, d->w = g->w, d->h = g->h, d->pitch = g->pitch, d->bpp = g->bpp;
        d->is555 = g->is555, d->ctab = g->pal, d->bmp = o, d->win = 0;
        RET(old, 2);
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
/* A DIB section's bitmap object: rows DWORD-aligned, a bottom-up one with
 * its last row first and a negative pitch, so a DC reads it top-down. */
uint32_t hle_gdi_make_dib(int w, int h, int bpp, uint8_t *bits, int topdown, const uint32_t *ctab, int ncolors, int is555) {
    uint32_t handle = new_obj(GO_BITMAP); gobj_t *o = GOBJ(handle);
    if (!o) return 0;
    int pitch = (w * bpp + 31) / 32 * 4;
    o->w = w, o->h = h, o->bpp = bpp, o->is555 = bpp == 16 && is555;
    o->px = topdown ? bits : bits + (size_t)(h - 1) * pitch, o->pitch = topdown ? pitch : -pitch;
    if (bpp <= 8) {
        o->pal = (uint32_t *)calloc(256, 4), o->paln = 256;
        if (ctab) memcpy(o->pal, ctab, (size_t)(ncolors > 256 ? 256 : ncolors) * 4);
    }
    return handle;
}
/* Regions are rectangles, which is what a game clipping its blits makes:
 * left, top in style and width, right, bottom in w and h. */
static uint32_t make_region(int l, int t, int r, int b) {
    uint32_t h = new_obj(GO_REGION); gobj_t *o = GOBJ(h);
    if (o) o->style = l, o->width = t, o->w = r, o->h = b;
    return h;
}
static void g_CreateRectRgn(void) { RET(make_region((int)A32(0), (int)A32(1), (int)A32(2), (int)A32(3)), 4); }
static void g_CreateRectRgnIndirect(void) {
    uint32_t rc = A32(0);
    RET(rc ? make_region((int)MEM32(rc), (int)MEM32(rc + 4), (int)MEM32(rc + 8), (int)MEM32(rc + 12)) : 0, 1);
}
static void g_SelectClipRgn(void) {                      /* (hdc, hrgn): NULL takes the clip away */
    dc_t *d = DC(A32(0)); gobj_t *g = GOBJ(A32(1));
    if (!d) RET(0, 2);                                   /* ERROR */
    d->clip = g && g->type == GO_REGION;
    if (d->clip) d->cl = g->style, d->ct = g->width, d->cr = g->w, d->cb = g->h;
    RET(d->clip && (d->cl >= d->cr || d->ct >= d->cb) ? 1u : 2u, 2);   /* NULLREGION, SIMPLEREGION */
}
/* SetDIBColorTable(hdc, start, n, RGBQUAD[]): the selected 8bpp DIB's colours. */
static void g_SetDIBColorTable(void) {
    dc_t *d = DC(A32(0));
    gobj_t *g = d ? GOBJ(d->bmp) : NULL;
    uint32_t start = A32(1), n = A32(2), q = A32(3);
    if (!g || !g->pal || start >= 256) RET(0, 4);
    if (start + n > 256) n = 256 - start;
    for (uint32_t i = 0; i < n; i++) g->pal[start + i] = MEM32(q + 4 * i) & 0xFFFFFFu;
    RET(n, 4);
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
static void g_GetDC(void)     { RET(hle_gdi_window_dc(), 1); }   /* a window's: the window surface, if the host set one */
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
        if (f->synth_bold) w += n;                       /* a pixel more per character */
    } else if (t) {
        w = 0, h = TTF_FontHeight(t);
    }
    if (A32(3)) MEM32(A32(3)) = (uint32_t)w, MEM32(A32(3) + 4) = (uint32_t)h;
    RET(1, 4);
}
static void g_GetTextMetricsA(void) {                    /* TEXTMETRICA */
    dc_t *d = DC(A32(0));
    font_t *f = FONT(d ? d->font : SYSTEM_FONT);
    TTF_Font *t = ttf_of(f);
    uint32_t m = A32(1);
    if (!m) RET(0, 2);
    memset((void *)(uintptr_t)m, 0, 56);
    int asc = t ? TTF_FontAscent(t) : 10, desc = t ? -TTF_FontDescent(t) : 3, ave = 6, max = 12;
    if (t) { int w; TTF_SizeText(t, "x", &ave, &w); TTF_SizeText(t, "W", &max, &w); }
    int em = f->height < 0 ? -f->height : f->height > 0 ? f->height * 87 / 100 : 11, bold = f->synth_bold;
    MEM32(m) = (uint32_t)(asc + desc), MEM32(m + 4) = (uint32_t)asc, MEM32(m + 8) = (uint32_t)desc;
    MEM32(m + 12) = (uint32_t)(asc + desc > em ? asc + desc - em : 0);   /* tmInternalLeading: the cell above the em */
    MEM32(m + 20) = (uint32_t)(ave + bold), MEM32(m + 24) = (uint32_t)(max + bold);
    MEM32(m + 28) = (uint32_t)(f->weight ? f->weight : 400), MEM32(m + 32) = (uint32_t)bold;   /* tmWeight, tmOverhang */
    MEM32(m + 36) = 96, MEM32(m + 40) = 96;              /* tmDigitizedAspectX, Y */
    MEM8(m + 44) = 0x20, MEM8(m + 45) = 0xFF, MEM8(m + 46) = 0x1F, MEM8(m + 47) = 0x20;   /* first, last, default, break */
    MEM8(m + 48) = (uint8_t)(f->italic != 0), MEM8(m + 49) = (uint8_t)(f->underline != 0);   /* tmItalic, tmUnderlined */
    MEM8(m + 51) = 0x27;                                 /* FF_SWISS | TRUETYPE | VECTOR | TMPF_FIXED_PITCH, which means variable pitch */
    RET(1, 2);
}

static uint32_t pack(const dc_t *d, uint32_t cr) {       /* COLORREF 0x00BBGGRR -> the surface's pixel */
    uint32_t r = cr & 0xFF, g = (cr >> 8) & 0xFF, b = (cr >> 16) & 0xFF;
    if (d->bpp == 16) return d->is555 ? (r >> 3) << 10 | (g >> 3) << 5 | (b >> 3) : (r >> 3) << 11 | (g >> 2) << 5 | (b >> 3);
    return r << 16 | g << 8 | b;
}
static void put(dc_t *d, int x, int y, uint32_t v) {
    if (d->clip && (x < d->cl || x >= d->cr || y < d->ct || y >= d->cb)) return;
    uint8_t *p = d->px + (ptrdiff_t)y * d->pitch + (size_t)x * (size_t)(d->bpp / 8);
    if (d->bpp == 16) *(uint16_t *)p = (uint16_t)v;
    else if (d->bpp == 32) *(uint32_t *)p = v;
    else if (d->bpp == 8) *p = (uint8_t)v;
}
static uint32_t get(dc_t *d, int x, int y) {
    const uint8_t *p = d->px + (ptrdiff_t)y * d->pitch + (size_t)x * (size_t)(d->bpp / 8);
    return d->bpp == 16 ? *(const uint16_t *)p : d->bpp == 8 ? *p : *(const uint32_t *)p;
}
/* A pixel as 0x00RRGGBB, and back: what a blit between depths goes through. */
static uint32_t to_rgb(const dc_t *d, uint32_t v) {
    if (d->bpp == 8) return d->ctab ? d->ctab[v & 0xFF] : v * 0x010101u;
    if (d->bpp == 16) {
        uint32_t r = d->is555 ? v >> 10 & 31 : v >> 11, g = d->is555 ? (v >> 5 & 31) << 1 | (v >> 9 & 1) : v >> 5 & 63, b = v & 31;
        return (r << 3 | r >> 2) << 16 | (g << 2 | g >> 4) << 8 | (b << 3 | b >> 2);
    }
    return v & 0xFFFFFFu;
}
static uint32_t from_rgb(const dc_t *d, uint32_t c) {
    uint32_t r = c >> 16 & 0xFF, g = c >> 8 & 0xFF, b = c & 0xFF;
    if (d->bpp == 16) return d->is555 ? (r >> 3) << 10 | (g >> 3) << 5 | (b >> 3) : (r >> 3) << 11 | (g >> 2) << 5 | (b >> 3);
    if (d->bpp == 8) return (r * 77 + g * 151 + b * 28) >> 8;      /* ponytail: grey; nothing blits into an 8bpp DIB yet */
    return c;
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

/* The text's coverage, 0..255 a pixel, the width GetTextExtentPoint32
 * gives it. Crisp text is FreeType's monochrome rendering. Synthetic bold
 * (a face with no bold file) is Windows': every glyph drawn twice, a pixel
 * apart, and every advance a pixel wider. */
static void ink_from(uint8_t *ink, int iw, int ih, int x0, SDL_Surface *s) {
    SDL_LockSurface(s);
    for (int j = 0; j < s->h && j < ih; j++)
        for (int i = 0; i < s->w; i++) {
            int x = x0 + i, a;
            if (x < 0 || x >= iw) continue;
            if (s->format->BytesPerPixel == 1) a = ((const uint8_t *)s->pixels)[j * s->pitch + i] ? 255 : 0;
            else a = (int)(((const uint32_t *)((const uint8_t *)s->pixels + j * s->pitch))[i] >> 24);
            if (a > ink[j * iw + x]) ink[j * iw + x] = (uint8_t)a;
        }
    SDL_UnlockSurface(s);
}
static SDL_Surface *render(const font_t *f, TTF_Font *t, const char *s) {
    SDL_Color white = { 255, 255, 255, 255 };
    return f->crisp ? TTF_RenderText_Solid(t, s, white) : TTF_RenderText_Blended(t, s, white);
}
static uint8_t *text_ink(const font_t *f, TTF_Font *t, const char *buf, int n, int *iw, int *ih) {
    int w, h;
    if (TTF_SizeText(t, buf, &w, &h) != 0) return NULL;
    *iw = w + (f->synth_bold ? n + 1 : 0), *ih = h;
    uint8_t *ink = (uint8_t *)calloc((size_t)*iw * *ih + 1, 1);
    if (!f->synth_bold) {
        SDL_Surface *s = render(f, t, buf);
        if (s) ink_from(ink, *iw, *ih, 0, s), SDL_FreeSurface(s);
        return ink;
    }
    for (int k = 0, x = 0; k < n; k++) {
        char one[2] = { buf[k], 0 };
        int adv = 0;
        if (TTF_GlyphMetrics(t, (uint8_t)buf[k], NULL, NULL, NULL, NULL, &adv) != 0) TTF_SizeText(t, one, &adv, NULL);
        SDL_Surface *s = render(f, t, one);
        if (s) ink_from(ink, *iw, *ih, x, s), ink_from(ink, *iw, *ih, x + 1, s), SDL_FreeSurface(s);
        x += adv + 1;
    }
    return ink;
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
    int iw, ih;
    uint8_t *ink = text_ink(f, t, buf, n, &iw, &ih);
    if (!ink) RET(1, 5);
    int x = (int)A32(1) - d->wox + d->vox, y = (int)A32(2) - d->woy + d->voy;
    if ((d->align & 6) == 6) x -= iw / 2;                /* TA_CENTER */
    else if (d->align & 2) x -= iw;                      /* TA_RIGHT */
    if ((d->align & 24) == 24) y -= TTF_FontAscent(t);   /* TA_BASELINE */
    else if (d->align & 8) y -= ih;                      /* TA_BOTTOM */
    uint32_t fg = pack(d, d->text), bg = pack(d, d->bk);
    for (int j = 0; j < ih; j++) {
        int py = y + j;
        if (py < 0 || py >= d->h) continue;
        for (int i = 0; i < iw; i++) {
            int px = x + i, a = ink[j * iw + i];
            if (px < 0 || px >= d->w) continue;
            if (d->bkmode == OPAQUE) put(d, px, py, mix(d, bg, fg, a));
            else if (a) put(d, px, py, mix(d, get(d, px, py), fg, a));
        }
    }
    free(ink);
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
    if (d->win) g_win_seq++;
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
    int same = src->bpp == dst->bpp && src->is555 == dst->is555 && src->bpp != 8;
    if (dst->win) g_win_seq++;
    for (int j = 0; j < h; j++) {
        int py = dy + j; if (py < 0 || py >= dst->h) continue;
        int sj = sy + (sh == h ? j : j * sh / h); if (sj < 0 || sj >= src->h) continue;
        for (int i = 0; i < w; i++) {
            int px = dx + i; if (px < 0 || px >= dst->w) continue;
            int si = sx + (sw == w ? i : i * sw / w); if (si < 0 || si >= src->w) continue;
            uint32_t v = get(src, si, sj);
            put(dst, px, py, same ? v : from_rgb(dst, to_rgb(src, v)));
        }
    }
    if (dst->win && hle_gdi_window_hook) hle_gdi_window_hook();
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
    { "SetDIBColorTable", g_SetDIBColorTable },
    { "CreateScalableFontResourceA", g_CreateScalableFontResourceA }, { "AddFontResourceA", g_AddFontResourceA },
    { "RemoveFontResourceA", g_RemoveFontResourceA },
    { "CreateRectRgn", g_CreateRectRgn }, { "CreateRectRgnIndirect", g_CreateRectRgnIndirect },
    { "SelectClipRgn", g_SelectClipRgn },
    { "GetDC", g_GetDC }, { "ReleaseDC", g_ReleaseDC }, { "SaveDC", g_SaveDC }, { "RestoreDC", g_RestoreDC },
    { "SetTextColor", g_SetTextColor }, { "SetBkColor", g_SetBkColor }, { "SetBkMode", g_SetBkMode },
    { "SetTextAlign", g_SetTextAlign }, { "GetTextColor", g_GetTextColor }, { "GetBkColor", g_GetBkColor },
    { "GetBkMode", g_GetBkMode }, { "SetViewportOrgEx", g_SetViewportOrgEx }, { "SetWindowOrgEx", g_SetWindowOrgEx },
    { "DPtoLP", g_DPtoLP }, { "SetGraphicsMode", g_SetGraphicsMode }, { "ModifyWorldTransform", g_ModifyWorldTransform },
    { "GetTextExtentPoint32A", g_GetTextExtentPoint32A }, { "GetTextExtentPointA", g_GetTextExtentPoint32A },
    { "GetTextMetricsA", g_GetTextMetricsA }, { "TextOutA", g_TextOutA },
    { 0, 0 }
};

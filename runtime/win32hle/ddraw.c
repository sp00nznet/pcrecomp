/*
 * ddraw.c - DirectDraw in software: IDirectDraw (and IDirectDraw2), surfaces
 * (IDirectDrawSurface 1-3), palettes and clippers.
 *
 * Every surface is system memory the game Locks and draws into, or blits
 * between; Blt and BltFast do the copy, colour fill, source colour key and
 * stretch in C. The display is virtual: SetDisplayMode records the mode, and
 * the primary surface's pixels are what a presenter (screen.c) shows,
 * through hle_dd_frame. Nothing is exclusive and nothing touches a real
 * display mode.
 *
 * Each surface gets a 64 KB tail behind its last row: a 1990s blitter that
 * checks only where a block starts runs past the bottom (Tiberian Sun's movie
 * decoder does, by up to 4.6 KB), into slack Windows happens to leave.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "win32hle.h"

#define DD_OK                   0u
#define DDERR_INVALIDPARAMS     0x80070057u
#define DDERR_UNSUPPORTED       0x80004001u
#define DDERR_NOTFOUND          0x887600FFu
#define DDERR_NOPALETTEATTACHED 0x8876023Cu
#define DDERR_NOCLIPPERATTACHED 0x88760082u
#define DDERR_NOCOLORKEY        0x887600D7u
#define DDERR_NOTLOCKED         0x887602ACu
#define DDERR_GENERIC           0x80004005u
#define DDERR_SURFACEBUSY       0x887601B6u

#define DDSD_CAPS        0x00000001u
#define DDSD_HEIGHT      0x00000002u
#define DDSD_WIDTH       0x00000004u
#define DDSD_PITCH       0x00000008u
#define DDSD_BACKBUFFERCOUNT 0x00000020u
#define DDSD_LPSURFACE   0x00000800u
#define DDSD_PIXELFORMAT 0x00001000u
#define DDSD_CKSRCBLT    0x00010000u
#define DDSD_REFRESHRATE 0x00040000u
#define DDSCAPS_BACKBUFFER     0x00000004u
#define DDSCAPS_COMPLEX        0x00000008u
#define DDSCAPS_FLIP           0x00000010u
#define DDSCAPS_FRONTBUFFER    0x00000020u
#define DDSCAPS_OFFSCREENPLAIN 0x00000040u
#define DDSCAPS_PRIMARYSURFACE 0x00000200u
#define DDSCAPS_SYSTEMMEMORY   0x00000800u
#define DDSCAPS_VIDEOMEMORY    0x00004000u
#define DDSCAPS_VISIBLE        0x00008000u
#define DDSCAPS_LOCALVIDMEM    0x10000000u
#define DDPF_PALETTEINDEXED8   0x00000020u
#define DDPF_RGB               0x00000040u
#define DDBLT_COLORFILL        0x00000400u
#define DDBLT_KEYSRC           0x00008000u
#define DDBLT_KEYSRCOVERRIDE   0x00010000u
#define DDBLTFAST_SRCCOLORKEY  0x00000001u
#define DDCKEY_SRCBLT          0x00000008u
#define SURF_TAIL              (64u << 10)

/* ---- the display ---- */
static int g_mode_w = 640, g_mode_h = 480, g_mode_bpp = 16, g_mode_set;
static int g_trace = -1;
static int trace(void) { if (g_trace < 0) g_trace = getenv("HLE_DDTRACE") != NULL; return g_trace; }

typedef struct surf {
    uint32_t self;
    int w, h, bpp, pitch;
    uint8_t *px;
    uint32_t caps;
    int primary, locks;
    struct surf *back;                   /* the flip chain's next */
    uint32_t palette, clipper;
    int ck_src; uint32_t ck_lo, ck_hi;
    uint32_t rmask, gmask, bmask;
} surf_t;

typedef struct { uint32_t entries[256]; int refs; } pal_t;   /* PALETTEENTRY: r, g, b, flags */

static surf_t *g_primary;
static uint32_t g_vt_dd, g_vt_dd2, g_vt_surf, g_vt_pal, g_vt_clip;
static uint32_t g_dd, g_dd2;                             /* the one DirectDraw object, both faces */
static volatile unsigned g_frame_seq;                    /* bumped when the primary may have changed */

#define S(self) ((surf_t *)(uintptr_t)MEM32((self) + 8))
#define P(self) ((pal_t *)(uintptr_t)MEM32((self) + 8))

/* What the presenter shows: the primary's pixels and their format. 0 if
 * there is no primary yet. */
int hle_dd_frame(const uint8_t **px, int *w, int *h, int *pitch, int *bpp, const uint32_t **palette, unsigned *seq) {
    surf_t *s = g_primary;
    if (!s) return 0;
    *px = s->px, *w = s->w, *h = s->h, *pitch = s->pitch, *bpp = s->bpp;
    *palette = s->palette ? P(s->palette)->entries : NULL;
    if (seq) *seq = g_frame_seq;
    return 1;
}
void hle_dd_mode(int *w, int *h, int *bpp) { *w = g_mode_w, *h = g_mode_h, *bpp = g_mode_bpp; }

static void masks(int bpp, uint32_t *r, uint32_t *g, uint32_t *b) {
    if (bpp == 16) *r = 0xF800, *g = 0x07E0, *b = 0x001F;
    else if (bpp >= 24) *r = 0xFF0000, *g = 0x00FF00, *b = 0x0000FF;
    else *r = *g = *b = 0;
}
static void put_pf(uint32_t pf, int bpp) {
    uint32_t r, g, b;
    masks(bpp, &r, &g, &b);
    memset((void *)(uintptr_t)pf, 0, 32);
    MEM32(pf) = 32;
    MEM32(pf + 4) = bpp == 8 ? DDPF_RGB | DDPF_PALETTEINDEXED8 : DDPF_RGB;
    MEM32(pf + 12) = (uint32_t)bpp, MEM32(pf + 16) = r, MEM32(pf + 20) = g, MEM32(pf + 24) = b;
}
static void put_desc(uint32_t d, surf_t *s) {
    uint32_t size = MEM32(d) >= 108 ? MEM32(d) : 108;
    memset((void *)(uintptr_t)(d + 4), 0, size - 4);
    MEM32(d + 4) = DDSD_CAPS | DDSD_HEIGHT | DDSD_WIDTH | DDSD_PITCH | DDSD_PIXELFORMAT | DDSD_LPSURFACE;
    MEM32(d + 8) = (uint32_t)s->h, MEM32(d + 12) = (uint32_t)s->w, MEM32(d + 16) = (uint32_t)s->pitch;
    MEM32(d + 36) = (uint32_t)(uintptr_t)s->px;
    if (s->ck_src) MEM32(d + 4) |= DDSD_CKSRCBLT, MEM32(d + 64) = s->ck_lo, MEM32(d + 68) = s->ck_hi;
    put_pf(d + 72, s->bpp);
    MEM32(d + 104) = s->caps;
}

static uint32_t new_surface(int w, int h, int bpp, uint32_t caps, int primary) {
    surf_t *s = (surf_t *)calloc(1, sizeof *s);
    s->w = w, s->h = h, s->bpp = bpp, s->caps = caps, s->primary = primary;
    s->pitch = ((w * (bpp / 8)) + 3) & ~3;
    s->px = (uint8_t *)calloc(1, (size_t)s->pitch * (size_t)h + SURF_TAIL);
    masks(bpp, &s->rmask, &s->gmask, &s->bmask);
    uint32_t o = hle_com_new(g_vt_surf, 12);
    MEM32(o + 8) = (uint32_t)(uintptr_t)s;
    s->self = o;
    return o;
}
static void free_surface(surf_t *s) {
    if (g_primary == s) g_primary = NULL, g_frame_seq++;
    if (s->palette) { uint32_t p = s->palette; if (--MEM32(p + 4) == 0) { free(P(p)); free((void *)(uintptr_t)p); } }
    free(s->px);
    free(s);
}

/* ---- IDirectDraw ---- */
static void dd_QueryInterface(void) {                    /* (this, iid, &out) */
    const uint8_t *iid = (const uint8_t *)APTR(1);
    uint32_t d1 = *(const uint32_t *)iid;
    char s[40];
    hle_guid_string(iid, s);
    if (trace()) fprintf(stderr, "[ddraw] IDirectDraw::QueryInterface %s\n", s);
    if (d1 == 0x6C14DB80u || d1 == 0x00000000u) { MEM32(A32(2)) = g_dd, MEM32(g_dd + 4)++; RET(DD_OK, 3); }    /* IDirectDraw, IUnknown */
    if (d1 == 0xB3A6F3E0u) { MEM32(A32(2)) = g_dd2, MEM32(g_dd2 + 4)++; RET(DD_OK, 3); }                       /* IDirectDraw2 */
    fprintf(stderr, "[ddraw] QueryInterface(%s): not served\n", s);
    MEM32(A32(2)) = 0;
    RET(0x80004002u, 3);
}
static void dd_Release(void) { uint32_t n = MEM32(A32(0) + 4) ? --MEM32(A32(0) + 4) : 0; RET(n, 1); }   /* the object lives on */
static void dd_Compact(void) { RET(DD_OK, 1); }
static void dd_CreateClipper(void) {                     /* (this, flags, &out, outer) */
    uint32_t o = hle_com_new(g_vt_clip, 12);
    MEM32(A32(2)) = o;
    RET(DD_OK, 4);
}
static void dd_CreatePalette(void) {                     /* (this, flags, entries, &out, outer) */
    pal_t *p = (pal_t *)calloc(1, sizeof *p);
    if (A32(2)) memcpy(p->entries, APTR(2), 256 * 4);
    uint32_t o = hle_com_new(g_vt_pal, 12);
    MEM32(o + 8) = (uint32_t)(uintptr_t)p;
    MEM32(A32(3)) = o;
    RET(DD_OK, 5);
}
static void dd_CreateSurface(void) {                     /* (this, &DDSURFACEDESC, &out, outer) */
    uint32_t d = A32(1), fl = MEM32(d + 4), caps = fl & DDSD_CAPS ? MEM32(d + 104) : 0;
    int primary = (caps & DDSCAPS_PRIMARYSURFACE) != 0;
    int w = primary ? g_mode_w : (int)MEM32(d + 12), h = primary ? g_mode_h : (int)MEM32(d + 8);
    int bpp = !primary && (fl & DDSD_PIXELFORMAT) ? (int)MEM32(d + 72 + 12) : g_mode_bpp;
    if (w <= 0 || h <= 0 || w > 8192 || h > 8192) { fprintf(stderr, "[ddraw] CreateSurface %dx%d: no\n", w, h); RET(DDERR_INVALIDPARAMS, 4); }
    caps = (caps & ~(DDSCAPS_VIDEOMEMORY | DDSCAPS_LOCALVIDMEM)) | DDSCAPS_SYSTEMMEMORY;
    if (!primary && !(caps & 0x1000u)) caps |= DDSCAPS_OFFSCREENPLAIN;
    uint32_t o = new_surface(w, h, bpp, primary ? caps | DDSCAPS_VISIBLE | DDSCAPS_FRONTBUFFER : caps, primary);
    surf_t *s = S(o);
    if (fl & DDSD_CKSRCBLT) s->ck_src = 1, s->ck_lo = MEM32(d + 64), s->ck_hi = MEM32(d + 68);
    if (fl & DDSD_LPSURFACE && MEM32(d + 36)) {           /* the game's own memory */
        free(s->px);
        s->px = (uint8_t *)(uintptr_t)MEM32(d + 36);
        if (fl & DDSD_PITCH) s->pitch = (int)MEM32(d + 16);
    }
    if (primary) {
        g_primary = s, g_frame_seq++;
        if ((fl & DDSD_BACKBUFFERCOUNT) && MEM32(d + 20)) {   /* a flip chain: one back buffer is all anyone uses */
            uint32_t b = new_surface(w, h, bpp, DDSCAPS_BACKBUFFER | DDSCAPS_SYSTEMMEMORY | (caps & (DDSCAPS_FLIP | DDSCAPS_COMPLEX)), 0);
            s->back = S(b);
            S(b)->back = s;
        }
    }
    if (trace() || primary)
        fprintf(stderr, "[ddraw] CreateSurface %dx%d %d bpp caps 0x%X%s -> %p\n", w, h, bpp, caps, primary ? " primary" : "", (void *)(uintptr_t)o);
    MEM32(A32(2)) = o;
    RET(DD_OK, 4);
}
static void dd_DuplicateSurface(void) { RET(DDERR_UNSUPPORTED, 3); }

static const int g_modes[][2] = { { 640, 480 }, { 800, 600 }, { 1024, 768 }, { 1152, 864 }, { 1280, 720 }, { 1280, 768 },
                                  { 1280, 800 }, { 1280, 960 }, { 1280, 1024 }, { 1360, 768 }, { 1366, 768 }, { 1440, 900 },
                                  { 1600, 900 }, { 1600, 1200 }, { 1680, 1050 }, { 1920, 1080 }, { 1920, 1200 } };
static void dd_EnumDisplayModes(void) {                  /* (this, flags, desc filter, ctx, callback) */
    uint32_t cb = A32(4), filter = A32(2);
    static uint32_t d[27];
    for (int bpp = 8; bpp <= 32; bpp += 8) {
        if (bpp == 24) continue;
        for (size_t i = 0; i < sizeof g_modes / sizeof *g_modes; i++) {
            if (filter && (MEM32(filter + 4) & DDSD_WIDTH) && MEM32(filter + 12) != (uint32_t)g_modes[i][0]) continue;
            if (filter && (MEM32(filter + 4) & DDSD_HEIGHT) && MEM32(filter + 8) != (uint32_t)g_modes[i][1]) continue;
            if (filter && (MEM32(filter + 4) & DDSD_PIXELFORMAT) && MEM32(filter + 84) != (uint32_t)bpp) continue;
            memset(d, 0, sizeof d);
            d[0] = 108;
            d[1] = DDSD_HEIGHT | DDSD_WIDTH | DDSD_PITCH | DDSD_PIXELFORMAT | DDSD_REFRESHRATE;
            d[2] = (uint32_t)g_modes[i][1], d[3] = (uint32_t)g_modes[i][0], d[4] = (uint32_t)(g_modes[i][0] * bpp / 8);
            d[6] = 60;
            put_pf((uint32_t)(uintptr_t)&d[18], bpp);
            uint32_t a[2] = { (uint32_t)(uintptr_t)d, A32(3) };
            if (!hle_call_guest(cb, 2, a)) RET(DD_OK, 5);   /* DDENUMRET_CANCEL */
        }
    }
    RET(DD_OK, 5);
}
static void dd_EnumSurfaces(void) { RET(DD_OK, 5); }
static void dd_FlipToGDISurface(void) { RET(DD_OK, 1); }
static void dd_GetCaps(void) {                           /* (this, &driver, &hel) */
    for (int k = 1; k <= 2; k++) {
        uint32_t c = A32(k);
        if (!c) continue;
        uint32_t size = MEM32(c) ? MEM32(c) : 316;
        memset((void *)(uintptr_t)(c + 4), 0, size - 4);
        MEM32(c + 4) = 0x00000040u | 0x00000200u | 0x00400000u | 0x04000000u;   /* BLT, BLTSTRETCH, COLORKEY, BLTCOLORFILL */
        MEM32(c + 12) = 0x00000200u;                     /* DDCKEYCAPS_SRCBLT */
        MEM32(c + 24) = 0x00000004u | 0x00000040u;       /* DDPCAPS_8BIT, PRIMARYSURFACE */
        MEM32(c + 60) = 256u << 20, MEM32(c + 64) = 192u << 20;   /* video memory: 256 MB, 192 free */
        if (size >= 108) MEM32(c + 104) = DDSCAPS_PRIMARYSURFACE | DDSCAPS_OFFSCREENPLAIN | DDSCAPS_FLIP | DDSCAPS_SYSTEMMEMORY | DDSCAPS_VIDEOMEMORY;
    }
    RET(DD_OK, 3);
}
static void dd_GetDisplayMode(void) {                    /* (this, &desc) */
    uint32_t d = A32(1);
    uint32_t size = MEM32(d) >= 108 ? MEM32(d) : 108;
    memset((void *)(uintptr_t)(d + 4), 0, size - 4);
    MEM32(d + 4) = DDSD_HEIGHT | DDSD_WIDTH | DDSD_PITCH | DDSD_PIXELFORMAT | DDSD_REFRESHRATE;
    MEM32(d + 8) = (uint32_t)g_mode_h, MEM32(d + 12) = (uint32_t)g_mode_w, MEM32(d + 16) = (uint32_t)(g_mode_w * g_mode_bpp / 8);
    MEM32(d + 24) = 60;
    put_pf(d + 72, g_mode_bpp);
    RET(DD_OK, 2);
}
static void dd_GetFourCCCodes(void) { if (A32(1)) MEM32(A32(1)) = 0; RET(DD_OK, 3); }
static void dd_GetGDISurface(void) { if (!g_primary) RET(DDERR_NOTFOUND, 2); MEM32(A32(1)) = g_primary->self; MEM32(g_primary->self + 4)++; RET(DD_OK, 2); }
static void dd_GetMonitorFrequency(void) { if (A32(1)) MEM32(A32(1)) = 60; RET(DD_OK, 2); }
static void dd_GetScanLine(void) { if (A32(1)) MEM32(A32(1)) = (hle_ticks_ms() * 29) % (uint32_t)g_mode_h; RET(DD_OK, 2); }
static void dd_GetVerticalBlankStatus(void) { if (A32(1)) MEM32(A32(1)) = (hle_ticks_ms() % 16) == 0; RET(DD_OK, 2); }
static void dd_Initialize(void) { RET(DD_OK, 2); }
static void dd_RestoreDisplayMode(void) { RET(DD_OK, 1); }
static void dd_SetCooperativeLevel(void) { if (trace()) fprintf(stderr, "[ddraw] SetCooperativeLevel(0x%X)\n", A32(2)); RET(DD_OK, 3); }
static void set_mode(int w, int h, int bpp) {
    g_mode_w = w, g_mode_h = h, g_mode_bpp = bpp, g_mode_set = 1;
    hle_set_screen_size(w, h);
    fprintf(stderr, "[ddraw] SetDisplayMode(%dx%dx%d)\n", w, h, bpp);
}
static void dd_SetDisplayMode(void)  { set_mode((int)A32(1), (int)A32(2), (int)A32(3)); RET(DD_OK, 4); }
static void dd2_SetDisplayMode(void) { set_mode((int)A32(1), (int)A32(2), (int)A32(3)); RET(DD_OK, 6); }
static void dd_WaitForVerticalBlank(void) {              /* (this, flags, event): the next 60 Hz tick */
    uint32_t now = hle_ticks_ms(), wait = 16 - now % 16;
    hle_block_begin();
    struct timespec ts = { 0, (long)wait * 1000000L };
    nanosleep(&ts, NULL);
    hle_block_end();
    RET(DD_OK, 3);
}
static void dd2_GetAvailableVidMem(void) {               /* (this, &caps, &total, &free) */
    if (A32(2)) MEM32(A32(2)) = 256u << 20;
    if (A32(3)) MEM32(A32(3)) = 192u << 20;
    RET(DD_OK, 4);
}

/* ---- IDirectDrawSurface ---- */
static void sf_QueryInterface(void) {
    const uint8_t *iid = (const uint8_t *)APTR(1);
    uint32_t d1 = *(const uint32_t *)iid;
    /* IUnknown, Surface, Surface2, Surface3: the same object (one vtable is all three) */
    if (d1 == 0 || d1 == 0x6C14DB81u || d1 == 0x57805885u || d1 == 0xDA044E00u) { MEM32(A32(2)) = A32(0); MEM32(A32(0) + 4)++; RET(DD_OK, 3); }
    char s[40];
    hle_guid_string(iid, s);
    fprintf(stderr, "[ddraw] Surface::QueryInterface(%s): not served\n", s);
    MEM32(A32(2)) = 0;
    RET(0x80004002u, 3);
}
static void sf_Release(void) {
    uint32_t self = A32(0), n = --MEM32(self + 4);
    if (!n) {
        surf_t *s = S(self);
        if (s->back && s->back->back == s && s->primary) {  /* the chain goes with its front */
            surf_t *b = s->back;
            uint32_t bo = b->self;
            b->back = NULL;
            free_surface(b);
            free((void *)(uintptr_t)bo);
        }
        free_surface(s);
        free((void *)(uintptr_t)self);
    }
    RET(n, 1);
}
static void sf_AddAttachedSurface(void) {
    surf_t *s = S(A32(0)), *b = A32(1) ? S(A32(1)) : NULL;
    if (b) s->back = b, MEM32(A32(1) + 4)++;
    RET(DD_OK, 2);
}
static void sf_AddOverlayDirtyRect(void) { RET(DDERR_UNSUPPORTED, 2); }

static inline uint32_t get_px(const surf_t *s, int x, int y) {
    const uint8_t *p = s->px + (size_t)y * (size_t)s->pitch + (size_t)x * (size_t)(s->bpp / 8);
    return s->bpp == 16 ? *(const uint16_t *)p : s->bpp == 8 ? *p : s->bpp == 32 ? *(const uint32_t *)p : (uint32_t)(p[0] | p[1] << 8 | p[2] << 16);
}
static inline void put_px(surf_t *s, int x, int y, uint32_t v) {
    uint8_t *p = s->px + (size_t)y * (size_t)s->pitch + (size_t)x * (size_t)(s->bpp / 8);
    if (s->bpp == 16) *(uint16_t *)p = (uint16_t)v;
    else if (s->bpp == 8) *p = (uint8_t)v;
    else if (s->bpp == 32) *(uint32_t *)p = v;
    else p[0] = (uint8_t)v, p[1] = (uint8_t)(v >> 8), p[2] = (uint8_t)(v >> 16);
}
static void get_rect(uint32_t r, const surf_t *s, int *l, int *t, int *rr, int *b) {
    if (r) *l = (int)MEM32(r), *t = (int)MEM32(r + 4), *rr = (int)MEM32(r + 8), *b = (int)MEM32(r + 12);
    else *l = 0, *t = 0, *rr = s->w, *b = s->h;
}
static void mark(surf_t *d) { if (d == g_primary) g_frame_seq++; }

/* The copy: same format at both ends (DirectDraw does not convert either),
 * clipped to both surfaces, stretched nearest-neighbour when the sizes
 * differ, and keyed when a source colour key applies. */
static void blit(surf_t *d, int dl, int dt, int dr, int db, surf_t *s, int sl, int st, int sr, int sb, int keyed, uint32_t klo, uint32_t khi) {
    int dw = dr - dl, dh = db - dt, sw = sr - sl, sh = sb - st;
    if (dw <= 0 || dh <= 0 || sw <= 0 || sh <= 0) return;
    int bpp = d->bpp / 8;
    uint8_t *tmp = NULL;
    const uint8_t *spx = s->px;
    if (s == d) {                                        /* overlapping: copy the source out first */
        tmp = (uint8_t *)malloc((size_t)s->pitch * (size_t)s->h);
        memcpy(tmp, s->px, (size_t)s->pitch * (size_t)s->h);
        spx = tmp;
    }
    if (dw == sw && dh == sh && !keyed && s->bpp == d->bpp) {
        int x0 = dl < 0 ? -dl : 0, y0 = dt < 0 ? -dt : 0;
        if (sl + x0 < 0) x0 = -sl;
        if (st + y0 < 0) y0 = -st;
        int x1 = dw, y1 = dh;
        if (dl + x1 > d->w) x1 = d->w - dl;
        if (dt + y1 > d->h) y1 = d->h - dt;
        if (sl + x1 > s->w) x1 = s->w - sl;
        if (st + y1 > s->h) y1 = s->h - st;
        for (int y = y0; y < y1 && x1 > x0; y++)
            memcpy(d->px + (size_t)(dt + y) * (size_t)d->pitch + (size_t)(dl + x0) * (size_t)bpp,
                   spx + (size_t)(st + y) * (size_t)s->pitch + (size_t)(sl + x0) * (size_t)bpp, (size_t)(x1 - x0) * (size_t)bpp);
    } else {
        surf_t src = *s;
        src.px = (uint8_t *)spx;
        for (int y = 0; y < dh; y++) {
            int ty = dt + y, sy = st + y * sh / dh;
            if (ty < 0 || ty >= d->h || sy < 0 || sy >= s->h) continue;
            for (int x = 0; x < dw; x++) {
                int tx = dl + x, sx = sl + x * sw / dw;
                if (tx < 0 || tx >= d->w || sx < 0 || sx >= s->w) continue;
                uint32_t v = get_px(&src, sx, sy);
                if (keyed && v >= klo && v <= khi) continue;
                put_px(d, tx, ty, v);
            }
        }
    }
    free(tmp);
    mark(d);
}
static void fill(surf_t *d, int l, int t, int r, int b, uint32_t c) {
    if (l < 0) l = 0;
    if (t < 0) t = 0;
    if (r > d->w) r = d->w;
    if (b > d->h) b = d->h;
    for (int y = t; y < b; y++) {
        if (d->bpp == 16) { uint16_t *p = (uint16_t *)(d->px + (size_t)y * (size_t)d->pitch) + l; for (int x = l; x < r; x++) *p++ = (uint16_t)c; }
        else if (d->bpp == 8) memset(d->px + (size_t)y * (size_t)d->pitch + l, (int)(c & 0xFF), (size_t)(r > l ? r - l : 0));
        else for (int x = l; x < r; x++) put_px(d, x, y, c);
    }
    mark(d);
}
static void sf_Blt(void) {                               /* (this, dstRect, src, srcRect, flags, fx) */
    surf_t *d = S(A32(0)), *s = A32(2) ? S(A32(2)) : NULL;
    uint32_t fl = A32(4), fx = A32(5);
    int dl, dt, dr, db;
    get_rect(A32(1), d, &dl, &dt, &dr, &db);
    if (fl & DDBLT_COLORFILL) {
        fill(d, dl, dt, dr, db, fx ? MEM32(fx + 80) : 0);
        RET(DD_OK, 6);
    }
    if (!s) RET(DD_OK, 6);                               /* a raster op with no source: nothing to do here */
    int sl, st, sr, sb;
    get_rect(A32(3), s, &sl, &st, &sr, &sb);
    int keyed = 0;
    uint32_t lo = 0, hi = 0;
    if ((fl & DDBLT_KEYSRCOVERRIDE) && fx) keyed = 1, lo = MEM32(fx + 92), hi = MEM32(fx + 96);
    else if ((fl & DDBLT_KEYSRC) && s->ck_src) keyed = 1, lo = s->ck_lo, hi = s->ck_hi;
    if (hi < lo) hi = lo;
    blit(d, dl, dt, dr, db, s, sl, st, sr, sb, keyed, lo, hi);
    RET(DD_OK, 6);
}
static void sf_BltBatch(void) { RET(DDERR_UNSUPPORTED, 4); }
static void sf_BltFast(void) {                           /* (this, x, y, src, srcRect, trans) */
    surf_t *d = S(A32(0)), *s = A32(3) ? S(A32(3)) : NULL;
    if (!s) RET(DDERR_INVALIDPARAMS, 6);
    int sl, st, sr, sb, x = (int)A32(1), y = (int)A32(2);
    get_rect(A32(4), s, &sl, &st, &sr, &sb);
    int keyed = (A32(5) & DDBLTFAST_SRCCOLORKEY) && s->ck_src;
    uint32_t hi = s->ck_hi < s->ck_lo ? s->ck_lo : s->ck_hi;
    blit(d, x, y, x + (sr - sl), y + (sb - st), s, sl, st, sr, sb, keyed, s->ck_lo, hi);
    RET(DD_OK, 6);
}
static void sf_DeleteAttachedSurface(void) { surf_t *s = S(A32(0)); s->back = NULL; RET(DD_OK, 3); }
static void sf_EnumAttachedSurfaces(void) {              /* (this, ctx, callback) */
    surf_t *s = S(A32(0));
    if (s->back) {
        static uint32_t d[27];
        memset(d, 0, sizeof d);
        d[0] = 108;
        put_desc((uint32_t)(uintptr_t)d, s->back);
        MEM32(s->back->self + 4)++;
        uint32_t a[3] = { s->back->self, (uint32_t)(uintptr_t)d, A32(1) };
        hle_call_guest(A32(2), 3, a);
    }
    RET(DD_OK, 3);
}
static void sf_EnumOverlayZOrders(void) { RET(DD_OK, 4); }
static void sf_Flip(void) {                              /* (this, target, flags): swap front and back pixels */
    surf_t *s = S(A32(0));
    if (s->back) {
        uint8_t *t = s->px;
        s->px = s->back->px, s->back->px = t;
        mark(s);
    }
    RET(DD_OK, 3);
}
static void sf_GetAttachedSurface(void) {                /* (this, &caps, &out) */
    surf_t *s = S(A32(0));
    if (!s->back) { MEM32(A32(2)) = 0; RET(DDERR_NOTFOUND, 3); }
    MEM32(A32(2)) = s->back->self;
    MEM32(s->back->self + 4)++;
    RET(DD_OK, 3);
}
static void sf_ok_2(void) { RET(DD_OK, 2); }
static void sf_ok_1(void) { RET(DD_OK, 1); }
static void sf_GetCaps(void) { if (A32(1)) MEM32(A32(1)) = S(A32(0))->caps; RET(DD_OK, 2); }
static void sf_GetClipper(void) {
    surf_t *s = S(A32(0));
    if (!s->clipper) RET(DDERR_NOCLIPPERATTACHED, 2);
    MEM32(A32(1)) = s->clipper, MEM32(s->clipper + 4)++;
    RET(DD_OK, 2);
}
static void sf_GetColorKey(void) {                       /* (this, flags, &key) */
    surf_t *s = S(A32(0));
    if (!(A32(1) & DDCKEY_SRCBLT) || !s->ck_src) RET(DDERR_NOCOLORKEY, 3);
    MEM32(A32(2)) = s->ck_lo, MEM32(A32(2) + 4) = s->ck_hi;
    RET(DD_OK, 3);
}
/* A DC on a surface: GDI text drawn into its pixels (gdidc.c). */
static void sf_GetDC(void) {
    surf_t *s = S(A32(0));
    if (A32(1)) MEM32(A32(1)) = hle_gdi_surface_dc(s->px, s->w, s->h, s->pitch, s->bpp);
    RET(DD_OK, 2);
}
static void sf_GetOverlayPosition(void) { RET(DDERR_UNSUPPORTED, 3); }
static void sf_GetPalette(void) {
    surf_t *s = S(A32(0));
    if (!s->palette) RET(DDERR_NOPALETTEATTACHED, 2);
    MEM32(A32(1)) = s->palette, MEM32(s->palette + 4)++;
    RET(DD_OK, 2);
}
static void sf_GetPixelFormat(void) { put_pf(A32(1), S(A32(0))->bpp); RET(DD_OK, 2); }
static void sf_GetSurfaceDesc(void) { put_desc(A32(1), S(A32(0))); RET(DD_OK, 2); }
static void sf_Initialize(void) { RET(DD_OK, 3); }
static void sf_Lock(void) {                              /* (this, rect, &desc, flags, event) */
    surf_t *s = S(A32(0));
    uint32_t d = A32(2);
    if (!d) RET(DDERR_INVALIDPARAMS, 5);
    put_desc(d, s);
    if (A32(1)) {
        int l = (int)MEM32(A32(1)), t = (int)MEM32(A32(1) + 4);
        MEM32(d + 36) = (uint32_t)(uintptr_t)(s->px + (size_t)t * (size_t)s->pitch + (size_t)l * (size_t)(s->bpp / 8));
    }
    s->locks++;
    RET(DD_OK, 5);
}
static void sf_ReleaseDC(void) { hle_gdi_release_dc(A32(1)); mark(S(A32(0))); RET(DD_OK, 2); }
static void sf_SetClipper(void) {
    surf_t *s = S(A32(0));
    if (A32(1)) MEM32(A32(1) + 4)++;
    s->clipper = A32(1);
    RET(DD_OK, 2);
}
static void sf_SetColorKey(void) {                       /* (this, flags, &key) */
    surf_t *s = S(A32(0));
    if (A32(1) & DDCKEY_SRCBLT) {
        if (A32(2)) s->ck_src = 1, s->ck_lo = MEM32(A32(2)), s->ck_hi = MEM32(A32(2) + 4);
        else s->ck_src = 0;
    }
    RET(DD_OK, 3);
}
static void sf_SetOverlayPosition(void) { RET(DDERR_UNSUPPORTED, 3); }
static void sf_SetPalette(void) {
    surf_t *s = S(A32(0));
    if (A32(1)) MEM32(A32(1) + 4)++;
    s->palette = A32(1);
    mark(s);
    RET(DD_OK, 2);
}
static void sf_Unlock(void) {
    surf_t *s = S(A32(0));
    if (s->locks) s->locks--;
    mark(s);
    RET(DD_OK, 2);
}
static void sf_UpdateOverlay(void) { RET(DDERR_UNSUPPORTED, 6); }
static void sf_UpdateOverlayDisplay(void) { RET(DDERR_UNSUPPORTED, 2); }
static void sf_UpdateOverlayZOrder(void) { RET(DDERR_UNSUPPORTED, 3); }
static void sf_GetDDInterface(void) { MEM32(A32(1)) = g_dd; RET(DD_OK, 2); }
static void sf_PageLock(void) { RET(DD_OK, 2); }
static void sf_PageUnlock(void) { RET(DD_OK, 2); }
static void sf_SetSurfaceDesc(void) {                    /* (this, &desc, flags): the game's own memory */
    surf_t *s = S(A32(0));
    uint32_t d = A32(1), fl = MEM32(d + 4);
    if ((fl & DDSD_LPSURFACE) && MEM32(d + 36)) s->px = (uint8_t *)(uintptr_t)MEM32(d + 36);   /* ponytail: the old pixels leak */
    if (fl & DDSD_PITCH) s->pitch = (int)MEM32(d + 16);
    if (fl & DDSD_WIDTH) s->w = (int)MEM32(d + 12);
    if (fl & DDSD_HEIGHT) s->h = (int)MEM32(d + 8);
    RET(DD_OK, 3);
}

/* ---- IDirectDrawPalette, IDirectDrawClipper ---- */
static void pl_Release(void) {
    uint32_t self = A32(0), n = --MEM32(self + 4);
    if (!n) { free(P(self)); free((void *)(uintptr_t)self); }
    RET(n, 1);
}
static void pl_GetCaps(void) { if (A32(1)) MEM32(A32(1)) = 0x4u; RET(DD_OK, 2); }   /* DDPCAPS_8BIT */
static void pl_GetEntries(void) {                        /* (this, flags, start, count, entries) */
    pal_t *p = P(A32(0));
    uint32_t start = A32(2), n = A32(3);
    if (start + n > 256) RET(DDERR_INVALIDPARAMS, 5);
    memcpy(APTR(4), p->entries + start, n * 4);
    RET(DD_OK, 5);
}
static void pl_SetEntries(void) {
    pal_t *p = P(A32(0));
    uint32_t start = A32(2), n = A32(3);
    if (start + n > 256) RET(DDERR_INVALIDPARAMS, 5);
    memcpy(p->entries + start, APTR(4), n * 4);
    g_frame_seq++;
    RET(DD_OK, 5);
}
static void pl_Initialize(void) { RET(DD_OK, 4); }
static void cl_Release(void) { uint32_t self = A32(0), n = --MEM32(self + 4); if (!n) free((void *)(uintptr_t)self); RET(n, 1); }
static void cl_GetClipList(void) { if (A32(3)) MEM32(A32(3)) = 0; RET(DDERR_UNSUPPORTED, 4); }
static void cl_GetHWnd(void) { MEM32(A32(1)) = MEM32(A32(0) + 8); RET(DD_OK, 2); }
static void cl_IsClipListChanged(void) { if (A32(1)) MEM32(A32(1)) = 0; RET(DD_OK, 2); }
static void cl_SetClipList(void) { RET(DD_OK, 3); }
static void cl_SetHWnd(void) { MEM32(A32(0) + 8) = A32(2); RET(DD_OK, 3); }
static void cl_Initialize(void) { RET(DD_OK, 3); }

static void vtables(void) {
    if (g_vt_dd) return;
#define DD_COMMON(I) \
        { I "QueryInterface", dd_QueryInterface }, { I "AddRef", hle_com_AddRef }, { I "Release", dd_Release }, \
        { I "Compact", dd_Compact }, { I "CreateClipper", dd_CreateClipper }, { I "CreatePalette", dd_CreatePalette }, \
        { I "CreateSurface", dd_CreateSurface }, { I "DuplicateSurface", dd_DuplicateSurface }, \
        { I "EnumDisplayModes", dd_EnumDisplayModes }, { I "EnumSurfaces", dd_EnumSurfaces }, \
        { I "FlipToGDISurface", dd_FlipToGDISurface }, { I "GetCaps", dd_GetCaps }, { I "GetDisplayMode", dd_GetDisplayMode }, \
        { I "GetFourCCCodes", dd_GetFourCCCodes }, { I "GetGDISurface", dd_GetGDISurface }, \
        { I "GetMonitorFrequency", dd_GetMonitorFrequency }, { I "GetScanLine", dd_GetScanLine }, \
        { I "GetVerticalBlankStatus", dd_GetVerticalBlankStatus }, { I "Initialize", dd_Initialize }, \
        { I "RestoreDisplayMode", dd_RestoreDisplayMode }, { I "SetCooperativeLevel", dd_SetCooperativeLevel }
    static const win32hle_shim dd[] = { DD_COMMON("IDirectDraw::"), { "IDirectDraw::SetDisplayMode", dd_SetDisplayMode },
        { "IDirectDraw::WaitForVerticalBlank", dd_WaitForVerticalBlank }, { 0, 0 } };
    static const win32hle_shim dd2[] = { DD_COMMON("IDirectDraw2::"), { "IDirectDraw2::SetDisplayMode", dd2_SetDisplayMode },
        { "IDirectDraw2::WaitForVerticalBlank", dd_WaitForVerticalBlank },
        { "IDirectDraw2::GetAvailableVidMem", dd2_GetAvailableVidMem }, { 0, 0 } };
    static const win32hle_shim sf[] = {
        { "IDirectDrawSurface::QueryInterface", sf_QueryInterface }, { "IDirectDrawSurface::AddRef", hle_com_AddRef },
        { "IDirectDrawSurface::Release", sf_Release }, { "IDirectDrawSurface::AddAttachedSurface", sf_AddAttachedSurface },
        { "IDirectDrawSurface::AddOverlayDirtyRect", sf_AddOverlayDirtyRect }, { "IDirectDrawSurface::Blt", sf_Blt },
        { "IDirectDrawSurface::BltBatch", sf_BltBatch }, { "IDirectDrawSurface::BltFast", sf_BltFast },
        { "IDirectDrawSurface::DeleteAttachedSurface", sf_DeleteAttachedSurface },
        { "IDirectDrawSurface::EnumAttachedSurfaces", sf_EnumAttachedSurfaces },
        { "IDirectDrawSurface::EnumOverlayZOrders", sf_EnumOverlayZOrders }, { "IDirectDrawSurface::Flip", sf_Flip },
        { "IDirectDrawSurface::GetAttachedSurface", sf_GetAttachedSurface }, { "IDirectDrawSurface::GetBltStatus", sf_ok_2 },
        { "IDirectDrawSurface::GetCaps", sf_GetCaps }, { "IDirectDrawSurface::GetClipper", sf_GetClipper },
        { "IDirectDrawSurface::GetColorKey", sf_GetColorKey }, { "IDirectDrawSurface::GetDC", sf_GetDC },
        { "IDirectDrawSurface::GetFlipStatus", sf_ok_2 }, { "IDirectDrawSurface::GetOverlayPosition", sf_GetOverlayPosition },
        { "IDirectDrawSurface::GetPalette", sf_GetPalette }, { "IDirectDrawSurface::GetPixelFormat", sf_GetPixelFormat },
        { "IDirectDrawSurface::GetSurfaceDesc", sf_GetSurfaceDesc }, { "IDirectDrawSurface::Initialize", sf_Initialize },
        { "IDirectDrawSurface::IsLost", sf_ok_1 }, { "IDirectDrawSurface::Lock", sf_Lock },
        { "IDirectDrawSurface::ReleaseDC", sf_ReleaseDC }, { "IDirectDrawSurface::Restore", sf_ok_1 },
        { "IDirectDrawSurface::SetClipper", sf_SetClipper }, { "IDirectDrawSurface::SetColorKey", sf_SetColorKey },
        { "IDirectDrawSurface::SetOverlayPosition", sf_SetOverlayPosition }, { "IDirectDrawSurface::SetPalette", sf_SetPalette },
        { "IDirectDrawSurface::Unlock", sf_Unlock }, { "IDirectDrawSurface::UpdateOverlay", sf_UpdateOverlay },
        { "IDirectDrawSurface::UpdateOverlayDisplay", sf_UpdateOverlayDisplay },
        { "IDirectDrawSurface::UpdateOverlayZOrder", sf_UpdateOverlayZOrder },
        { "IDirectDrawSurface2::GetDDInterface", sf_GetDDInterface }, { "IDirectDrawSurface2::PageLock", sf_PageLock },
        { "IDirectDrawSurface2::PageUnlock", sf_PageUnlock }, { "IDirectDrawSurface3::SetSurfaceDesc", sf_SetSurfaceDesc },
        { 0, 0 } };
    static const win32hle_shim pl[] = {
        { "IDirectDrawPalette::QueryInterface", hle_com_QueryInterface }, { "IDirectDrawPalette::AddRef", hle_com_AddRef },
        { "IDirectDrawPalette::Release", pl_Release }, { "IDirectDrawPalette::GetCaps", pl_GetCaps },
        { "IDirectDrawPalette::GetEntries", pl_GetEntries }, { "IDirectDrawPalette::Initialize", pl_Initialize },
        { "IDirectDrawPalette::SetEntries", pl_SetEntries }, { 0, 0 } };
    static const win32hle_shim cl[] = {
        { "IDirectDrawClipper::QueryInterface", hle_com_QueryInterface }, { "IDirectDrawClipper::AddRef", hle_com_AddRef },
        { "IDirectDrawClipper::Release", cl_Release }, { "IDirectDrawClipper::GetClipList", cl_GetClipList },
        { "IDirectDrawClipper::GetHWnd", cl_GetHWnd }, { "IDirectDrawClipper::Initialize", cl_Initialize },
        { "IDirectDrawClipper::IsClipListChanged", cl_IsClipListChanged }, { "IDirectDrawClipper::SetClipList", cl_SetClipList },
        { "IDirectDrawClipper::SetHWnd", cl_SetHWnd }, { 0, 0 } };
    g_vt_dd = hle_com_vtable(dd);
    g_vt_dd2 = hle_com_vtable(dd2);
    g_vt_surf = hle_com_vtable(sf);
    g_vt_pal = hle_com_vtable(pl);
    g_vt_clip = hle_com_vtable(cl);
    g_dd = hle_com_new(g_vt_dd, 12);
    g_dd2 = hle_com_new(g_vt_dd2, 12);
}

static void x_DirectDrawCreate(void) {                   /* (guid, &out, outer) */
    vtables();
    MEM32(g_dd + 4)++;
    MEM32(A32(1)) = g_dd;
    RET(DD_OK, 3);
}
static void x_DirectDrawEnumerateA(void) {               /* (callback, ctx): the primary display */
    static char desc[] = "Primary Display Driver", name[] = "display";
    uint32_t a[4] = { 0, (uint32_t)(uintptr_t)desc, (uint32_t)(uintptr_t)name, A32(1) };
    if (A32(0)) hle_call_guest(A32(0), 4, a);
    RET(DD_OK, 2);
}

const win32hle_shim win32hle_ddraw[] = {
    { "DirectDrawCreate", x_DirectDrawCreate }, { "DirectDrawEnumerateA", x_DirectDrawEnumerateA },
    { 0, 0 }
};

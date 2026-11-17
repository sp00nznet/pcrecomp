/*
 * w32kposix: win32k for a lifted Windows 2000 user32 + gdi32 on POSIX.
 *
 * user32 and gdi32 are Windows 2000's own, lifted; they call win32k through
 * int 2Eh (services from 0x1000, ntposix.c) and read its state client-side
 * in the layouts of w32klayout.h. This file is that win32k, small and in
 * software:
 *
 *   windows    WNDs in a desktop heap in guest memory, kept in step with our
 *              own records (rectangles, styles, links, text); classes; a
 *              posted-message queue, WM_PAINT from update state, timers on
 *              the virtual clock. A window procedure is called the way
 *              win32k calls it: KiUserCallbackDispatcher into user32's
 *              __fnDWORD / __fnINLPCREATESTRUCT, DispatchClientMessage.
 *   DefWindowProc's server half (NtUserMessageCall FNID_DEFWINDOWPROC):
 *              frames, captions and the menu bar in Windows 2000's classic
 *              look, WM_NCCALCSIZE by its metrics, erasing, text.
 *   GDI        DCs (memory and display), bitmaps (32-bit, or monochrome),
 *              brushes, pens, ROP3 blits, StretchBlt, DIBs in and out,
 *              lines, pixels, text from Windows 2000's own .fon files
 *              (parsed here), the TEB batch.
 *   screen     one 32-bit framebuffer; windows draw into it where they are,
 *              in creation order (no overlap clipping). A shot is a PNG of
 *              the visible top-level windows' box, and of the main window's
 *              client area.
 *   input      scripted (w2kx_script_arg): messages posted to the main or
 *              top window at times on the virtual clock, which advances only
 *              when the guest waits for a message.
 *
 * ponytail: one thread; rectangular clipping only (no regions beyond a
 * rectangle); MM_TEXT only; no z-order clipping between windows; menus
 * drop down only through the script (SC_KEYMENU), not tracked; ANSI window
 * procedures get Unicode text.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include <ctype.h>
#include "ntposix.h"
#include "w32klayout.h"
#include "w32kposix.h"

static int g_trace;
static uint32_t g_cbt;                        /* the WH_CBT hook procedure (s_sethook) */
#define TRACE(...) do { if (g_trace) fprintf(stderr, __VA_ARGS__); } while (0)

typedef struct { int l, t, r, b; } rc_t;
static int rc_empty(const rc_t* r) { return r->r <= r->l || r->b <= r->t; }
static rc_t rc_and(rc_t a, rc_t b) {
    rc_t r = { a.l > b.l ? a.l : b.l, a.t > b.t ? a.t : b.t, a.r < b.r ? a.r : b.r, a.b < b.b ? a.b : b.b };
    return r;
}
static rc_t rc_or(rc_t a, rc_t b) {
    if (rc_empty(&a)) return b;
    if (rc_empty(&b)) return a;
    rc_t r = { a.l < b.l ? a.l : b.l, a.t < b.t ? a.t : b.t, a.r > b.r ? a.r : b.r, a.b > b.b ? a.b : b.b };
    return r;
}
static rc_t rc_get(uint32_t p) { rc_t r = { (int)MEM32(p), (int)MEM32(p + 4), (int)MEM32(p + 8), (int)MEM32(p + 12) }; return r; }
static void rc_put(uint32_t p, rc_t r) { MEM32(p) = (uint32_t)r.l, MEM32(p + 4) = (uint32_t)r.t, MEM32(p + 8) = (uint32_t)r.r, MEM32(p + 12) = (uint32_t)r.b; }

/* ======================================================================
 * The framebuffer, colours (COLORREF 0x00BBGGRR throughout), PNG
 * ====================================================================== */
typedef struct { int w, h, mono; uint32_t* px; uint32_t dc; } bmp_t;
static bmp_t g_screen;
static int g_cx = 1024, g_cy = 768;
#define CLR(c) ((c) & 0xFFFFFFu)
static uint32_t lum_mono(uint32_t c) {     /* the nearest of black and white */
    return ((c & 0xFF) + ((c >> 8) & 0xFF) + ((c >> 16) & 0xFF)) >= 3 * 128 ? 0xFFFFFF : 0;
}

static uint32_t crc_tab[256];
static uint32_t crc32_(uint32_t c, const uint8_t* p, size_t n) {
    if (!crc_tab[1]) for (uint32_t i = 0; i < 256; i++) { uint32_t k = i; for (int j = 0; j < 8; j++) k = k & 1 ? 0xEDB88320u ^ (k >> 1) : k >> 1; crc_tab[i] = k; }
    c = ~c;
    while (n--) c = crc_tab[(c ^ *p++) & 0xFF] ^ (c >> 8);
    return ~c;
}
static void be32(uint8_t* p, uint32_t v) { p[0] = (uint8_t)(v >> 24), p[1] = (uint8_t)(v >> 16), p[2] = (uint8_t)(v >> 8), p[3] = (uint8_t)v; }
static void png_chunk(FILE* f, const char* type, const uint8_t* d, uint32_t n) {
    uint8_t h[8];
    be32(h, n), memcpy(h + 4, type, 4);
    fwrite(h, 1, 8, f);
    if (n) fwrite(d, 1, n, f);
    uint32_t c = crc32_(crc32_(0, (const uint8_t*)type, 4), d, n);
    be32(h, c);
    fwrite(h, 1, 4, f);
}
/* An RGB PNG of r (screen coordinates), deflate's stored blocks: no zlib */
static int png_write(const char* path, const bmp_t* b, rc_t r) {
    r = rc_and(r, (rc_t){ 0, 0, b->w, b->h });
    if (rc_empty(&r)) return 0;
    int w = r.r - r.l, h = r.b - r.t;
    size_t raw = (size_t)(3 * w + 1) * h, nblk = (raw + 65534) / 65535, z = 2 + raw + 5 * nblk + 4;
    uint8_t* img = malloc(raw), *zb = malloc(z);
    for (int y = 0; y < h; y++) {
        uint8_t* o = img + (size_t)y * (3 * w + 1);
        *o++ = 0;
        for (int x = 0; x < w; x++) {
            uint32_t c = b->px[(size_t)(r.t + y) * b->w + r.l + x];
            *o++ = (uint8_t)c, *o++ = (uint8_t)(c >> 8), *o++ = (uint8_t)(c >> 16);
        }
    }
    uint8_t* q = zb;
    *q++ = 0x78, *q++ = 0x01;
    uint32_t a1 = 1, a2 = 0;
    for (size_t i = 0; i < raw; i++) a1 = (a1 + img[i]) % 65521, a2 = (a2 + a1) % 65521;
    for (size_t off = 0; off < raw || !off; ) {
        size_t n = raw - off > 65535 ? 65535 : raw - off;
        *q++ = off + n >= raw;
        *q++ = (uint8_t)n, *q++ = (uint8_t)(n >> 8), *q++ = (uint8_t)~n, *q++ = (uint8_t)(~n >> 8);
        memcpy(q, img + off, n), q += n, off += n;
        if (!n) break;
    }
    be32(q, a2 << 16 | a1), q += 4;
    FILE* f = fopen(path, "wb");
    if (!f) { free(img), free(zb); return 0; }
    static const uint8_t sig[8] = { 0x89, 'P', 'N', 'G', 13, 10, 26, 10 };
    uint8_t ih[13];
    fwrite(sig, 1, 8, f);
    be32(ih, (uint32_t)w), be32(ih + 4, (uint32_t)h);
    ih[8] = 8, ih[9] = 2, ih[10] = ih[11] = ih[12] = 0;
    png_chunk(f, "IHDR", ih, 13);
    png_chunk(f, "IDAT", zb, (uint32_t)(q - zb));
    png_chunk(f, "IEND", NULL, 0);
    fclose(f);
    free(img), free(zb);
    return 1;
}

/* ======================================================================
 * Fonts: Windows 2000's .fon files (NE images of FNT 2.0/3.0 resources)
 * ====================================================================== */
typedef struct {
    char face[32];
    int points, h, ascent, ilead, elead, avgw, maxw, weight, first, last, defch, brk, charset, pitch;
    uint16_t w[256];
    uint32_t off[256];
    const uint8_t* raw;
} fnt_t;
#define MAX_FNT 64
static fnt_t g_fnt[MAX_FNT];
static int g_nfnt;
static uint16_t rd16(const uint8_t* p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t rd32(const uint8_t* p) { return (uint32_t)(p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24); }

static void fon_load(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "[w32k] font %s: missing (no text)\n", path); return; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    uint8_t* d = malloc(n);
    fseek(f, 0, SEEK_SET);
    if (fread(d, 1, n, f) != (size_t)n) { fclose(f); free(d); return; }
    fclose(f);
    uint32_t ne = rd32(d + 0x3C);
    if (ne + 0x40 > (uint32_t)n || d[ne] != 'N' || d[ne + 1] != 'E') { free(d); return; }
    const uint8_t* rt = d + ne + rd16(d + ne + 0x24);
    int shift = rd16(rt);
    for (const uint8_t* t = rt + 2; rd16(t); t += 8 + 12 * rd16(t + 2)) {
        if (rd16(t) != 0x8008) continue;                     /* RT_FONT */
        for (int i = 0; i < rd16(t + 2) && g_nfnt < MAX_FNT; i++) {
            const uint8_t* ni = t + 8 + 12 * i, *h = d + ((uint32_t)rd16(ni) << shift);
            fnt_t* F = &g_fnt[g_nfnt];
            int ver = rd16(h), first = h[95], last = h[96];
            if (ver != 0x200 && ver != 0x300) continue;
            const uint8_t* ct = h + (ver == 0x300 ? 148 : 118);
            F->raw = h;
            F->points = rd16(h + 68), F->ascent = rd16(h + 74), F->ilead = rd16(h + 76), F->elead = rd16(h + 78);
            F->weight = rd16(h + 83), F->charset = h[85], F->h = rd16(h + 88), F->pitch = h[90];
            F->avgw = rd16(h + 91), F->maxw = rd16(h + 93), F->first = first, F->last = last;
            F->defch = h[97] + first, F->brk = h[98] + first;
            snprintf(F->face, sizeof F->face, "%s", (const char*)(h + rd32(h + 105)));
            for (int c = first; c <= last; c++) {
                const uint8_t* e = ct + (c - first) * (ver == 0x300 ? 6 : 4);
                F->w[c] = rd16(e);
                F->off[c] = ver == 0x300 ? rd32(e + 2) : rd16(e + 2);
            }
            TRACE("[w32k] font %s %dpt %dpx (%s)\n", F->face, F->points, F->h, path);
            g_nfnt++;
        }
    }
}
/* ======================================================================
 * TrueType: Windows 2000's own .ttf files (lucon.ttf, tahoma.ttf, ...),
 * read and scan-converted here, each size turned into an fnt_t so the
 * bitmap text path draws it. Monochrome, as Windows 2000 draws without
 * font smoothing: a pixel is on when its centre is inside the outline
 * (non-zero winding).
 * ponytail: no hinting (no bytecode interpreter), so stems can land a pixel
 * off the hinted output Windows draws; cp1252 only; composites keep offsets,
 * not scale; glyphs are cut at their advance.
 * ====================================================================== */
typedef struct { char fam[32]; const uint8_t* d; uint32_t glyf, loca, hmtx, cmap4; int upem, longloca, nhm, asc, desc, avgw, maxw, weight, fixed; } ttf_t;
static ttf_t g_ttf[8];
static int g_nttf;
static uint16_t rbe16(const uint8_t* p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint32_t rbe32(const uint8_t* p) { return (uint32_t)p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]; }
static void ttf_load(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f || g_nttf >= 8) { if (f) fclose(f); return; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    uint8_t* d = malloc(n);
    fseek(f, 0, SEEK_SET);
    if (n < 12 || fread(d, 1, n, f) != (size_t)n) { fclose(f); free(d); return; }
    fclose(f);
    ttf_t* T = &g_ttf[g_nttf];
    memset(T, 0, sizeof *T);
    T->d = d;
    uint32_t head = 0, hhea = 0, os2 = 0, name = 0, cmap = 0, post = 0;
    for (int i = 0; i < rbe16(d + 4); i++) {
        const uint8_t* e = d + 12 + 16 * i;
        uint32_t o = rbe32(e + 8);
        if (!memcmp(e, "head", 4)) head = o; else if (!memcmp(e, "hhea", 4)) hhea = o;
        else if (!memcmp(e, "OS/2", 4)) os2 = o; else if (!memcmp(e, "name", 4)) name = o;
        else if (!memcmp(e, "cmap", 4)) cmap = o; else if (!memcmp(e, "post", 4)) post = o;
        else if (!memcmp(e, "glyf", 4)) T->glyf = o; else if (!memcmp(e, "loca", 4)) T->loca = o;
        else if (!memcmp(e, "hmtx", 4)) T->hmtx = o;
    }
    if (!head || !hhea || !os2 || !name || !cmap || !T->glyf || !T->loca || !T->hmtx) { free(d); return; }
    T->upem = rbe16(d + head + 18), T->longloca = (int16_t)rbe16(d + head + 50);
    T->nhm = rbe16(d + hhea + 34), T->maxw = rbe16(d + hhea + 10);
    T->avgw = (int16_t)rbe16(d + os2 + 2), T->weight = rbe16(d + os2 + 4);
    T->asc = rbe16(d + os2 + 74), T->desc = rbe16(d + os2 + 76);
    T->fixed = post ? rbe32(d + post + 12) != 0 : 0;
    for (int i = 0; i < rbe16(d + cmap + 2); i++) {                /* (3,1) format 4 */
        const uint8_t* e = d + cmap + 4 + 8 * i;
        if (rbe16(e) == 3 && rbe16(e + 2) == 1 && rbe16(d + cmap + rbe32(e + 4)) == 4) T->cmap4 = cmap + rbe32(e + 4);
    }
    const uint8_t* nt = d + name;
    for (int i = 0; i < rbe16(nt + 2); i++) {                      /* the family name (1), Windows Unicode */
        const uint8_t* r = nt + 6 + 12 * i;
        if (rbe16(r) != 3 || rbe16(r + 6) != 1 || (rbe16(r + 4) & 0x3FF) != 9) continue;
        const uint8_t* s = nt + rbe16(nt + 4) + rbe16(r + 10);
        int k = 0;
        for (int j = 0; j + 1 < rbe16(r + 8) && k < 31; j += 2) T->fam[k++] = (char)s[j + 1];
        T->fam[k] = 0;
        break;
    }
    if (!T->cmap4 || !T->fam[0]) { free(d); return; }
    TRACE("[w32k] TrueType %s (%s)\n", T->fam, path);
    g_nttf++;
}
static int ttf_glyph(const ttf_t* T, uint32_t u) {
    const uint8_t* c = T->d + T->cmap4;
    int n = rbe16(c + 6) / 2;
    for (int i = 0; i < n; i++) {
        uint32_t end = rbe16(c + 14 + 2 * i), start = rbe16(c + 16 + 2 * n + 2 * i);
        if (u > end) continue;
        if (u < start) return 0;
        uint16_t delta = rbe16(c + 16 + 4 * n + 2 * i);
        uint32_t ro = 16 + 6 * n + 2 * i, r = rbe16(c + ro);
        if (!r) return (uint16_t)(u + delta);
        uint16_t g = rbe16(c + ro + r + 2 * (u - start));
        return g ? (uint16_t)(g + delta) : 0;
    }
    return 0;
}
/* a glyph's outline as line segments in font units (quadratics flattened) */
typedef struct { float x0, y0, x1, y1; } seg_t;
typedef struct { seg_t* s; int n, cap; } segs_t;
static void seg_add(segs_t* S, float x0, float y0, float x1, float y1) {
    if (S->n == S->cap) S->cap = S->cap ? 2 * S->cap : 256, S->s = realloc(S->s, S->cap * sizeof *S->s);
    S->s[S->n++] = (seg_t){ x0, y0, x1, y1 };
}
static void seg_quad(segs_t* S, float x0, float y0, float cx, float cy, float x1, float y1) {
    float px = x0, py = y0;
    for (int i = 1; i <= 8; i++) {
        float t = i / 8.f, u = 1 - t;
        float x = u * u * x0 + 2 * u * t * cx + t * t * x1, y = u * u * y0 + 2 * u * t * cy + t * t * y1;
        seg_add(S, px, py, x, y);
        px = x, py = y;
    }
}
static void ttf_outline(const ttf_t* T, int g, float dx, float dy, segs_t* S, int depth) {
    const uint8_t* d = T->d;
    uint32_t o0 = T->longloca ? rbe32(d + T->loca + 4 * g) : 2u * rbe16(d + T->loca + 2 * g);
    uint32_t o1 = T->longloca ? rbe32(d + T->loca + 4 * g + 4) : 2u * rbe16(d + T->loca + 2 * g + 2);
    if (o1 <= o0 || depth > 4) return;
    const uint8_t* p = d + T->glyf + o0;
    int nc = (int16_t)rbe16(p);
    if (nc < 0) {                                                 /* a composite: its parts at their offsets */
        const uint8_t* q = p + 10;
        for (;;) {
            int fl = rbe16(q), sub = rbe16(q + 2);
            float ox, oy;
            q += 4;
            if (fl & 1) ox = (int16_t)rbe16(q), oy = (int16_t)rbe16(q + 2), q += 4;
            else ox = (int8_t)q[0], oy = (int8_t)q[1], q += 2;
            if (!(fl & 2)) ox = oy = 0;                           /* point matching: not done */
            q += fl & 8 ? 2 : fl & 0x40 ? 4 : fl & 0x80 ? 8 : 0;
            ttf_outline(T, sub, dx + ox, dy + oy, S, depth + 1);
            if (!(fl & 0x20)) break;
        }
        return;
    }
    const uint8_t* ends = p + 10;
    int np = nc ? rbe16(ends + 2 * (nc - 1)) + 1 : 0;
    const uint8_t* ip = ends + 2 * nc;
    const uint8_t* fp = ip + 2 + rbe16(ip);
    uint8_t* fl = malloc(np + 1);
    float* xs = malloc(sizeof(float) * (np + 1)), *ys = malloc(sizeof(float) * (np + 1));
    for (int i = 0; i < np; ) {
        uint8_t f = *fp++;
        int r = f & 8 ? *fp++ : 0;
        for (int k = 0; k <= r && i < np; k++) fl[i++] = f;
    }
    int v = 0;
    for (int i = 0; i < np; i++) {
        if (fl[i] & 2) v += fl[i] & 0x10 ? *fp : -*fp, fp++;
        else if (!(fl[i] & 0x10)) v += (int16_t)rbe16(fp), fp += 2;
        xs[i] = (float)v + dx;
    }
    v = 0;
    for (int i = 0; i < np; i++) {
        if (fl[i] & 4) v += fl[i] & 0x20 ? *fp : -*fp, fp++;
        else if (!(fl[i] & 0x20)) v += (int16_t)rbe16(fp), fp += 2;
        ys[i] = (float)v + dy;
    }
    for (int c = 0, s = 0; c < nc; c++) {
        int e = rbe16(ends + 2 * c), m = e - s + 1;
        if (m < 2) { s = e + 1; continue; }
        int k0 = s;                                               /* start on an on-curve point (or a midpoint) */
        while (k0 <= e && !(fl[k0] & 1)) k0++;
        float sx, sy;
        int mid = k0 > e;
        if (mid) sx = (xs[s] + xs[e]) / 2, sy = (ys[s] + ys[e]) / 2, k0 = e;
        else sx = xs[k0], sy = ys[k0];
        float px = sx, py = sy, cx = 0, cy = 0;
        int hasc = 0;
        for (int j = 1; j <= m; j++) {
            int k = s + (k0 - s + j) % m;
            if (j == m && !mid) break;                            /* back at the start point */
            float x = xs[k], y = ys[k];
            if (fl[k] & 1) {
                if (hasc) seg_quad(S, px, py, cx, cy, x, y); else seg_add(S, px, py, x, y);
                px = x, py = y, hasc = 0;
            } else {
                if (hasc) { float mx = (cx + x) / 2, my = (cy + y) / 2; seg_quad(S, px, py, cx, cy, mx, my); px = mx, py = my; }
                cx = x, cy = y, hasc = 1;
            }
        }
        if (hasc) seg_quad(S, px, py, cx, cy, sx, sy);
        else if (px != sx || py != sy) seg_add(S, px, py, sx, sy);
        s = e + 1;
    }
    free(fl), free(xs), free(ys);
}
/* a TrueType face at a LOGFONT height, as a new fnt_t (cached by face and ppem) */
static int ttf_pick(const char* face, int height) {
    static const uint16_t cp1252[32] = { 0x20AC, 0, 0x201A, 0x192, 0x201E, 0x2026, 0x2020, 0x2021, 0x2C6, 0x2030, 0x160, 0x2039, 0x152, 0, 0x17D, 0,
        0, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x2DC, 0x2122, 0x161, 0x203A, 0x153, 0, 0x17E, 0x178 };
    ttf_t* T = NULL;
    for (int i = 0; i < g_nttf; i++) if (!strcasecmp(g_ttf[i].fam, face)) T = &g_ttf[i];
    if (!T) return -1;
    int ppem = height < 0 ? -height : height ? (height * T->upem + (T->asc + T->desc) / 2) / (T->asc + T->desc) : 13;
    for (int i = 0; i < g_nfnt; i++) if (g_fnt[i].points == -ppem && !strcmp(g_fnt[i].face, T->fam)) return i;
    if (g_nfnt >= MAX_FNT) return -1;
    float sc = (float)ppem / T->upem;
    fnt_t* F = &g_fnt[g_nfnt];
    memset(F, 0, sizeof *F);
    snprintf(F->face, sizeof F->face, "%s", T->fam);
    F->points = -ppem;                                            /* (marks a TrueType size; the cache key) */
    F->ascent = (int)(T->asc * sc + .5f), F->h = F->ascent + (int)(T->desc * sc + .5f), F->ilead = F->h - ppem;
    F->avgw = (int)(T->avgw * sc + .5f), F->maxw = (int)(T->maxw * sc + .5f), F->weight = T->weight;
    F->first = 0, F->last = 255, F->defch = '?', F->brk = ' ', F->pitch = (T->fixed ? 0 : 1) | 4;
    size_t tot = 0;
    int gl[256];
    for (int c = 0; c < 256; c++) {
        uint32_t u = c >= 0x80 && c < 0xA0 ? cp1252[c - 0x80] : (uint32_t)c;
        int g = gl[c] = u ? ttf_glyph(T, u) : 0;
        int adv = rbe16(T->d + T->hmtx + 4 * (g < T->nhm ? g : T->nhm - 1));
        F->w[c] = (uint16_t)(int)(adv * sc + .5f), F->off[c] = (uint32_t)tot;
        tot += (size_t)((F->w[c] + 7) / 8) * F->h;
    }
    uint8_t* raw = calloc(tot ? tot : 1, 1);
    segs_t S = { 0 };
    enum { MAXX = 512 };
    float xs[MAXX];
    int dir[MAXX];
    for (int c = 0; c < 256; c++) {
        S.n = 0;
        ttf_outline(T, gl[c], 0, 0, &S, 0);
        for (int y = 0; y < F->h; y++) {                          /* a row at its pixel centres: the crossings, by winding */
            float fy = (F->ascent - (y + .5f)) / sc;
            int nx = 0;
            for (int i = 0; i < S.n && nx < MAXX; i++) {
                seg_t* e = &S.s[i];
                if ((e->y0 <= fy) == (e->y1 <= fy)) continue;
                float x = e->x0 + (fy - e->y0) * (e->x1 - e->x0) / (e->y1 - e->y0);
                int k = nx++;                                     /* (insertion sort: few crossings) */
                for (; k > 0 && xs[k - 1] > x * sc; k--) xs[k] = xs[k - 1], dir[k] = dir[k - 1];
                xs[k] = x * sc, dir[k] = e->y1 > e->y0 ? 1 : -1;
            }
            int wind = 0;
            for (int i = 0; i + 1 < nx; i++) {
                wind += dir[i];
                if (!wind) continue;
                for (int x = (int)ceilf(xs[i] - .5f); x + .5f < xs[i + 1] && x < F->w[c]; x++)
                    if (x >= 0) raw[F->off[c] + (size_t)(x >> 3) * F->h + y] |= (uint8_t)(0x80 >> (x & 7));
            }
        }
    }
    free(S.s);
    F->raw = raw;
    TRACE("[w32k] TrueType %s at %d ppem: %d high\n", F->face, ppem, F->h);
    return g_nfnt++;
}
/* the font for a LOGFONT: the face if we have it (MS Sans Serif otherwise),
 * the nearest cell height. ponytail: bitmap faces only; bold is overstruck */
static int fnt_pick(const char* face, int height) {
    int best = -1, bd = 1 << 30;
    for (int i = 0; i < g_nfnt; i++) if (g_fnt[i].points > 0 && !strcasecmp(g_fnt[i].face, face)) goto bitmap;
    if ((best = ttf_pick(face, height)) >= 0) return best;
bitmap:
    for (int pass = 0; pass < 2 && best < 0; pass++)
        for (int i = 0; i < g_nfnt; i++) {
            if (g_fnt[i].points <= 0) continue;           /* (TrueType sizes are made on demand) */
            if (pass == 0 && strcasecmp(g_fnt[i].face, face)) continue;
            if (pass == 1 && strcasecmp(g_fnt[i].face, "MS Sans Serif")) continue;
            int ch = height < 0 ? g_fnt[i].h - g_fnt[i].ilead : g_fnt[i].h;
            int dd = height ? abs(ch - abs(height)) : abs(g_fnt[i].h - 13);
            if (dd < bd) bd = dd, best = i;
        }
    return best < 0 && g_nfnt ? 0 : best;
}
static int fnt_cw(const fnt_t* F, int c) {
    if (c < F->first || c > F->last) c = F->defch;
    return F->w[c];
}

/* ======================================================================
 * GDI objects
 * ====================================================================== */
typedef struct gobj {
    uint32_t h;
    uint8_t type, stock;
    bmp_t bm;                                 /* a bitmap */
    uint32_t color; int style, width;         /* a brush, a pen */
    bmp_t* pat;                               /* a pattern brush's bitmap (copied) */
    int font, bold, italic, underline, height;/* a font */
    rc_t rgn;                                 /* a region: a rectangle */
    /* a DC */
    int display;
    uint32_t hbm;                             /* a memory DC's bitmap */
    uint32_t hwnd;
    int ox, oy;                               /* the device origin in its bitmap */
    rc_t vis, clip;                           /* in its bitmap's coordinates; clip within vis */
    uint32_t attr;
    struct { uint8_t a[DCA_SIZE]; rc_t clip; uint32_t hbm; } *saved;
    int nsaved;
    struct dibsec* ds;                        /* a DIB section: its bits in guest memory */
} gobj_t;
static gobj_t* g_g[GDI_ENTRIES];
static uint8_t g_guniq[GDI_ENTRIES];
static uint32_t g_gdit;                       /* the shared handle table */
static uint32_t g_stock[20], g_stockbm;
static uint32_t g_sysbrush[0x1D];
static int g_gnext = 1;

static uint32_t guest_pid(void) { return MEM32(MEM32(g_fs_base + 0x18) + 0x20); }
static gobj_t* G(uint32_t h, int type) {
    uint32_t i = h & 0xFFFF;
    if (!h || i >= GDI_ENTRIES || !g_g[i] || g_g[i]->h != h) {
        /* gdi32 may hand back a handle with the stock bit set or cleared */
        if (h && i < GDI_ENTRIES && g_g[i] && (g_g[i]->h & 0xFF7FFFFFu) == (h & 0xFF7FFFFFu)) goto ok;
        return NULL;
    }
ok:
    if (type && (g_g[i]->type & 0x1F) != (type & 0x1F)) return NULL;
    return g_g[i];
}
static gobj_t* gnew(int type, int stock) {
    int i = 0;
    for (int k = 0; k < GDI_ENTRIES - 1; k++) {
        int j = g_gnext + k;
        if (j >= GDI_ENTRIES) j -= GDI_ENTRIES - 1;
        if (!g_g[j]) { i = j; break; }
    }
    if (!i) { fprintf(stderr, "[gdi] handle table full\n"); return NULL; }
    g_gnext = i + 1 >= GDI_ENTRIES ? 1 : i + 1;
    gobj_t* o = calloc(1, sizeof *o);
    if (++g_guniq[i] == 0) g_guniq[i] = 1;
    o->type = (uint8_t)type, o->stock = (uint8_t)stock;
    o->h = (uint32_t)i | ((uint32_t)((g_guniq[i] & 0x7F) << 8 | type | (stock ? GDI_STOCK : 0)) << 16);
    g_g[i] = o;
    uint32_t attr = 0;
    if (type == GDI_DC || type == GDI_RGN) attr = o->attr = ntp_alloc(DCA_SIZE);
    w2k_gdi_entry(g_gdit, o->h, guest_pid(), attr);
    return o;
}
static void gfree(gobj_t* o) {
    uint32_t i = o->h & 0xFFFF;
    w2k_gdi_clear(g_gdit, o->h);
    if (o->type == GDI_BMP) free(o->bm.px);
    if (o->ds) free(o->ds);
    if (o->pat) free(o->pat->px), free(o->pat);
    free(o->saved);
    g_g[i] = NULL;
    free(o);                       /* ponytail: a DC's DC_ATTR page is not given back */
}
static void ds_sync(gobj_t* o);
static bmp_t* bm_of(uint32_t h) { gobj_t* o = G(h, GDI_BMP); if (o && o->ds) ds_sync(o); return o ? &o->bm : NULL; }
static void bm_init(bmp_t* b, int w, int h, int mono) {
    b->w = w > 0 ? w : 1, b->h = h > 0 ? h : 1, b->mono = mono;
    b->px = calloc((size_t)b->w * b->h, 4);
}
static gobj_t* bitmap_new(int w, int h, int mono) {
    gobj_t* o = gnew(GDI_BMP, 0);
    if (o) bm_init(&o->bm, w, h, mono);
    return o;
}

/* ---- DCs ------------------------------------------------------------------ */
#define AT(dc, off) MEM32((dc)->attr + (off))
static gobj_t* dc_new(int display) {
    gobj_t* d = gnew(GDI_DC, 0);
    if (!d) return NULL;
    d->display = display;
    AT(d, DCA_BRUSH) = g_stock[0];           /* WHITE_BRUSH */
    AT(d, DCA_PEN) = g_stock[7];             /* BLACK_PEN */
    AT(d, 0x10) = AT(d, DCA_BKCOLOR) = 0xFFFFFF;
    AT(d, 0x18) = AT(d, DCA_TEXTCOLOR) = 0;
    MEM8(d->attr + DCA_ROP2) = 13;           /* R2_COPYPEN */
    MEM8(d->attr + DCA_BKMODE) = 2;          /* OPAQUE */
    AT(d, DCA_FONT) = g_stock[13];           /* SYSTEM_FONT */
    AT(d, DCA_MAPMODE) = 1;
    AT(d, DCA_WINEXT) = AT(d, DCA_WINEXT + 4) = AT(d, DCA_VPEXT) = AT(d, DCA_VPEXT + 4) = 1;
    if (display) {
        d->vis = d->clip = (rc_t){ 0, 0, g_cx, g_cy };
    } else {
        d->hbm = g_stockbm;
        d->vis = d->clip = (rc_t){ 0, 0, 1, 1 };
    }
    return d;
}
static bmp_t* dc_bm(gobj_t* d) {
    if (d->display) return &g_screen;
    bmp_t* b = bm_of(d->hbm);
    return b ? b : &g_screen;
}
static gobj_t* DCH(uint32_t h) { return G(h, GDI_DC); }
/* logical -> the DC's bitmap */
static void lp2dp(gobj_t* d, int* x, int* y) {
    *x = *x - (int)AT(d, DCA_WINORG) + (int)AT(d, DCA_VPORG) + d->ox;
    *y = *y - (int)AT(d, DCA_WINORG + 4) + (int)AT(d, DCA_VPORG + 4) + d->oy;
}
static rc_t dc_rect(gobj_t* d, int l, int t, int r, int b) {
    lp2dp(d, &l, &t), lp2dp(d, &r, &b);
    rc_t o = { l < r ? l : r, t < b ? t : b, l < r ? r : l, t < b ? b : t };
    return o;
}
static uint32_t dc_bk(gobj_t* d) { return CLR(AT(d, DCA_BKCOLOR)); }
static uint32_t dc_fg(gobj_t* d) { return CLR(AT(d, DCA_TEXTCOLOR)); }
/* a colour drawn into this DC (a monochrome bitmap takes black or white) */
static uint32_t dc_color(gobj_t* d, uint32_t c) { return dc_bm(d)->mono ? lum_mono(CLR(c)) : CLR(c); }

/* ---- raster operations ---------------------------------------------------- */
static uint32_t rop3(uint8_t code, uint32_t p, uint32_t s, uint32_t d) {
    uint32_t r = 0;
    for (int k = 0; k < 8; k++)
        if (code >> k & 1) r |= (k & 4 ? p : ~p) & (k & 2 ? s : ~s) & (k & 1 ? d : ~d);
    return r & 0xFFFFFF;
}
static uint32_t rop2(int r, uint32_t p, uint32_t d) {
    switch (r) {
    case 1: return 0; case 2: return ~(p | d) & 0xFFFFFF; case 3: return ~p & d; case 4: return ~p & 0xFFFFFF;
    case 5: return p & ~d; case 6: return ~d & 0xFFFFFF; case 7: return p ^ d; case 8: return ~(p & d) & 0xFFFFFF;
    case 9: return p & d; case 10: return ~(p ^ d) & 0xFFFFFF; case 11: return d; case 12: return (~p | d) & 0xFFFFFF;
    case 14: return (p | ~d) & 0xFFFFFF; case 15: return p | d; case 16: return 0xFFFFFF;
    default: return p;
    }
}
/* a brush's colour at a pixel of the DC's bitmap (-1: a hollow brush) */
static int64_t brush_at(gobj_t* d, gobj_t* br, int x, int y) {
    if (!br || br->style == 1) return -1;                     /* BS_NULL */
    if (br->pat) {
        int ox = (int)AT(d, DCA_BRUSHORG), oy = (int)AT(d, DCA_BRUSHORG + 4);
        int px = ((x - d->ox - ox) % br->pat->w + br->pat->w) % br->pat->w, py = ((y - d->oy - oy) % br->pat->h + br->pat->h) % br->pat->h;
        uint32_t c = br->pat->px[py * br->pat->w + px];
        if (br->pat->mono) c = c ? dc_bk(d) : dc_fg(d);
        return dc_color(d, c);
    }
    return dc_color(d, br->color);
}
static int rop_uses_src(uint32_t rop) { uint8_t c = (uint8_t)(rop >> 16); return ((c >> 2) ^ c) & 0x33; }
static int rop_uses_pat(uint32_t rop) { uint8_t c = (uint8_t)(rop >> 16); return ((c >> 4) ^ c) & 0x0F; }

static void patblt(gobj_t* d, rc_t r, uint32_t rop, uint32_t hbr) {
    bmp_t* b = dc_bm(d);
    gobj_t* br = G(hbr ? hbr : AT(d, DCA_BRUSH), GDI_BRUSH);
    uint8_t code = (uint8_t)(rop >> 16);
    r = rc_and(r, d->clip);
    for (int y = r.t; y < r.b; y++)
        for (int x = r.l; x < r.r; x++) {
            uint32_t* px = &b->px[(size_t)y * b->w + x];
            int64_t p = rop_uses_pat(rop) ? brush_at(d, br, x, y) : 0;
            if (p < 0) continue;
            *px = rop3(code, (uint32_t)p, 0, *px);
        }
}

/* BitBlt / StretchBlt: source pixels through the colour rules (monochrome
 * to colour: 0 the destination's text colour, 1 its background; colour to
 * monochrome: the source's background colour is 1) and the ROP */
static void stretchblt(gobj_t* d, int x, int y, int w, int h, gobj_t* s, int sx, int sy, int sw, int sh, uint32_t rop) {
    if (!s || !rop_uses_src(rop)) { patblt(d, dc_rect(d, x, y, x + w, y + h), rop, 0); return; }
    bmp_t* db = dc_bm(d), *sb = dc_bm(s);
    lp2dp(d, &x, &y), lp2dp(s, &sx, &sy);
    if (!w || !h || !sw || !sh) return;
    int fx = (w < 0) != (sw < 0), fy = (h < 0) != (sh < 0);
    if (w < 0) x += w, w = -w;
    if (h < 0) y += h, h = -h;
    if (sw < 0) sx += sw, sw = -sw;
    if (sh < 0) sy += sh, sh = -sh;
    /* a copy of the source first: it may be the destination */
    uint32_t* tmp = malloc((size_t)sw * sh * 4);
    rc_t sv = s->vis;
    for (int j = 0; j < sh; j++)
        for (int i = 0; i < sw; i++) {
            int X = sx + i, Y = sy + j;
            uint32_t c = X >= sv.l && X < sv.r && Y >= sv.t && Y < sv.b ? sb->px[(size_t)Y * sb->w + X] : 0;
            if (sb->mono && !db->mono) c = c ? dc_bk(d) : dc_fg(d);
            else if (!sb->mono && db->mono) c = c == dc_bk(s) ? 0xFFFFFF : 0;
            tmp[(size_t)j * sw + i] = c;
        }
    gobj_t* br = G(AT(d, DCA_BRUSH), GDI_BRUSH);
    uint8_t code = (uint8_t)(rop >> 16);
    rc_t r = rc_and((rc_t){ x, y, x + w, y + h }, d->clip);
    for (int Y = r.t; Y < r.b; Y++)
        for (int X = r.l; X < r.r; X++) {
            int i = (int)((int64_t)(X - x) * sw / w), j = (int)((int64_t)(Y - y) * sh / h);
            if (fx) i = sw - 1 - i;
            if (fy) j = sh - 1 - j;
            uint32_t sp = tmp[(size_t)j * sw + i], *dp = &db->px[(size_t)Y * db->w + X];
            if (code == 0xCC) { *dp = sp; continue; }
            int64_t p = rop_uses_pat(rop) ? brush_at(d, br, X, Y) : 0;
            *dp = rop3(code, p < 0 ? 0 : (uint32_t)p, sp, *dp);
        }
    free(tmp);
}

static void setpx(gobj_t* d, int x, int y, uint32_t c, int r2) {
    bmp_t* b = dc_bm(d);
    if (x < d->clip.l || x >= d->clip.r || y < d->clip.t || y >= d->clip.b) return;
    uint32_t* p = &b->px[(size_t)y * b->w + x];
    *p = rop2(r2, dc_color(d, c), *p);
}
/* a pen line from the current position (logical), the last pixel left out */
static void line(gobj_t* d, int x0, int y0, int x1, int y1) {
    gobj_t* pen = G(AT(d, DCA_PEN), GDI_PEN);
    if (!pen || pen->style == 5) return;                      /* PS_NULL */
    int r2 = MEM8(d->attr + DCA_ROP2), w = pen->width > 1 ? pen->width : 1;
    lp2dp(d, &x0, &y0), lp2dp(d, &x1, &y1);
    int dx = abs(x1 - x0), sx = x0 < x1 ? 1 : -1, dy = -abs(y1 - y0), sy = y0 < y1 ? 1 : -1, e = dx + dy;
    while (x0 != x1 || y0 != y1) {
        for (int j = 0; j < w; j++) for (int i = 0; i < w; i++) setpx(d, x0 + i - w / 2, y0 + j - w / 2, pen->color, r2);
        int e2 = 2 * e;
        if (e2 >= dy) e += dy, x0 += sx;
        if (e2 <= dx) e += dx, y0 += sy;
    }
}

/* ---- DIBs ------------------------------------------------------------------
 * BITMAPINFOHEADER (or BITMAPCOREHEADER), colours, bits: one pixel as a
 * COLORREF; DIB_PAL_COLORS indexes are taken as the index's grey. */
typedef struct { int w, h, bpp, topdown, stride, ncol; uint32_t comp, mask[3]; uint32_t pal[256]; } dib_t;
struct dibsec { dib_t D; uint32_t bits; int touched; uint8_t shadow[]; };
static int dib_parse(uint32_t bmi, uint32_t usage, dib_t* o) {
    if (!bmi) return 0;
    uint32_t hs = MEM32(bmi);
    memset(o, 0, sizeof *o);
    if (hs == 12) o->w = MEM16(bmi + 4), o->h = (int16_t)MEM16(bmi + 6), o->bpp = MEM16(bmi + 10);
    else o->w = (int)MEM32(bmi + 4), o->h = (int)MEM32(bmi + 8), o->bpp = MEM16(bmi + 14), o->comp = MEM32(bmi + 16);
    if (o->h < 0) o->topdown = 1, o->h = -o->h;
    o->stride = ((o->w * o->bpp + 31) / 32) * 4;
    uint32_t c = bmi + hs;
    if (o->comp == 3) {                                       /* BI_BITFIELDS */
        o->mask[0] = MEM32(c), o->mask[1] = MEM32(c + 4), o->mask[2] = MEM32(c + 8);
    } else if (o->bpp == 16) o->mask[0] = 0x7C00, o->mask[1] = 0x3E0, o->mask[2] = 0x1F;
    else if (o->bpp == 32) o->mask[0] = 0xFF0000, o->mask[1] = 0xFF00, o->mask[2] = 0xFF;
    if (o->bpp <= 8) {
        o->ncol = hs != 12 && MEM32(bmi + 32) ? (int)MEM32(bmi + 32) : 1 << o->bpp;
        if (o->ncol > 256) o->ncol = 256;
        for (int i = 0; i < o->ncol; i++) {
            if (usage == 1) { uint32_t g = (MEM16(c + 2 * i) & 0xFF); o->pal[i] = g | g << 8 | g << 16; continue; }
            uint32_t q = hs == 12 ? (uint32_t)(MEM8(c + 3 * i) | MEM8(c + 3 * i + 1) << 8 | MEM8(c + 3 * i + 2) << 16) : MEM32(c + 4 * i);
            o->pal[i] = (q >> 16 & 0xFF) | (q & 0xFF00) | (q & 0xFF) << 16;   /* RGBQUAD -> COLORREF */
        }
    }
    return o->w > 0 && o->h > 0;
}
/* BI_RLE8 (1) / BI_RLE4 (2) bits unpacked to plain bottom-up rows (one
 * buffer, reused); other bits as they are */
static uint32_t dib_plain(const dib_t* d, uint32_t bits) {
    static uint8_t* buf;
    static size_t cap;
    if (d->comp != 1 && d->comp != 2) return bits;
    size_t n = (size_t)d->stride * d->h;
    if (n > cap) free(buf), buf = malloc(n), cap = n;
    memset(buf, 0, n);
    const uint8_t* p = (const uint8_t*)(uintptr_t)bits;
    int x = 0, y = 0, four = d->comp == 2;
#define PUT(v) do { if (x < d->w && y < d->h) { uint8_t* q = buf + (size_t)y * d->stride; \
        if (four) q[x >> 1] |= (uint8_t)(((v) & 0xF) << (x & 1 ? 0 : 4)); else q[x] = (uint8_t)(v); } x++; } while (0)
    while (y < d->h) {
        int c = *p++, v = *p++;
        if (c) { for (int i = 0; i < c; i++) PUT(four ? (i & 1 ? v : v >> 4) : v); continue; }
        if (v == 0) { x = 0, y++; continue; }
        if (v == 1) break;
        if (v == 2) { x += p[0], y += p[1], p += 2; continue; }
        int nb = four ? (v + 1) / 2 : v;
        for (int i = 0; i < v; i++) PUT(four ? (i & 1 ? p[i >> 1] : p[i >> 1] >> 4) : p[i]);
        p += (nb + 1) & ~1;
    }
#undef PUT
    return (uint32_t)(uintptr_t)buf;
}
static uint32_t field(uint32_t v, uint32_t m) {
    if (!m) return 0;
    int s = 0, n = 0;
    while (!(m >> s & 1)) s++;
    while (m >> (s + n) & 1) n++;
    v = (v & m) >> s;
    return n >= 8 ? v >> (n - 8) : (v << (8 - n)) | (v >> (2 * n - 8 > 0 ? 2 * n - 8 : 0));
}
/* the pixel at (x, row) of a DIB's bits, row counted in memory order */
static uint32_t dib_px(const dib_t* d, const uint8_t* bits, int x, int row) {
    const uint8_t* r = bits + (size_t)row * d->stride;
    switch (d->bpp) {
    case 1: return d->pal[(r[x >> 3] >> (7 - (x & 7))) & 1];
    case 4: return d->pal[(r[x >> 1] >> (x & 1 ? 0 : 4)) & 0xF];
    case 8: return d->pal[r[x]];
    case 16: { uint32_t v = rd16(r + 2 * x); return field(v, d->mask[0]) | field(v, d->mask[1]) << 8 | field(v, d->mask[2]) << 16; }
    case 24: return r[3 * x + 2] | r[3 * x + 1] << 8 | (uint32_t)r[3 * x] << 16;
    case 32: { uint32_t v = rd32(r + 4 * x); return field(v, d->mask[0]) | field(v, d->mask[1]) << 8 | field(v, d->mask[2]) << 16; }
    }
    return 0;
}
/* Draw DIB rows into the DC: dst (x, y, w, h) <- src (sx, sy, sw, sh) in
 * DIB coordinates (bottom-up: sy from the bottom), the bits holding scans
 * start..start+num (in DIB order) */
static void dib_draw(gobj_t* d, int x, int y, int w, int h, int sx, int sy, int sw, int sh,
                     uint32_t bits, uint32_t bmi, uint32_t usage, int start, int num, uint32_t rop) {
    dib_t D;
    if (!bits || !dib_parse(bmi, usage, &D)) return;
    bits = dib_plain(&D, bits);
    if (num <= 0) num = D.h;
    bmp_t tmpb;
    bm_init(&tmpb, sw, sh, 0);
    for (int j = 0; j < sh; j++) {
        int top = D.topdown ? sy + j : D.h - sy - sh + j;            /* row from the top */
        int scan = D.topdown ? top : D.h - 1 - top;                  /* in DIB order */
        if (scan < start || scan >= start + num) continue;
        for (int i = 0; i < sw; i++) {
            int X = sx + i;
            if (X < 0 || X >= D.w) continue;
            tmpb.px[(size_t)j * sw + i] = dib_px(&D, (const uint8_t*)(uintptr_t)bits, X, scan - start);
        }
    }
    {
        bmp_t* db = dc_bm(d);
        int X0 = x, Y0 = y;
        lp2dp(d, &X0, &Y0);
        rc_t r = rc_and((rc_t){ X0, Y0, X0 + (w < 0 ? -w : w), Y0 + (h < 0 ? -h : h) }, d->clip);
        gobj_t* br = G(AT(d, DCA_BRUSH), GDI_BRUSH);
        uint8_t code = (uint8_t)(rop >> 16);
        for (int Y = r.t; Y < r.b; Y++)
            for (int X = r.l; X < r.r; X++) {
                int i = (int)((int64_t)(X - X0) * sw / (w < 0 ? -w : w)), j = (int)((int64_t)(Y - Y0) * sh / (h < 0 ? -h : h));
                if (w < 0) i = sw - 1 - i;
                if (h < 0) j = sh - 1 - j;
                uint32_t sp = tmpb.px[(size_t)j * sw + i], *dp = &db->px[(size_t)Y * db->w + X];
                if (db->mono) sp = lum_mono(sp);
                if (code == 0xCC) { *dp = sp; continue; }
                int64_t p = rop_uses_pat(rop) ? brush_at(d, br, X, Y) : 0;
                *dp = rop3(code, p < 0 ? 0 : (uint32_t)p, sp, *dp);
            }
    }
    free(tmpb.px);
}
/* bits of a bitmap out as a DIB (GetDIBits): 1, 24 or 32 bpp; header only
 * when bits is 0 */
static int dib_get(bmp_t* b, int start, int num, uint32_t bits, uint32_t bmi) {
    uint32_t hs = MEM32(bmi);
    if (hs < 40) return 0;
    int bpp = MEM16(bmi + 14);
    if (!bpp || !bits) {
        MEM32(bmi + 4) = (uint32_t)b->w, MEM32(bmi + 8) = (uint32_t)b->h;
        MEM16(bmi + 12) = 1, MEM16(bmi + 14) = (uint16_t)(b->mono ? 1 : 32);
        MEM32(bmi + 16) = 0;
        MEM32(bmi + 20) = (uint32_t)(((b->w * MEM16(bmi + 14) + 31) / 32) * 4 * b->h);
        return b->h;
    }
    int h = (int)MEM32(bmi + 8), td = h < 0, stride = ((b->w * bpp + 31) / 32) * 4;
    if (h < 0) h = -h;
    if (bpp == 1) { MEM32(bmi + hs) = 0; MEM32(bmi + hs + 4) = 0xFFFFFF; }
    for (int s = start; s < start + num && s < b->h; s++) {
        int top = td ? s : b->h - 1 - s;
        uint8_t* r = (uint8_t*)(uintptr_t)(bits + (uint32_t)((s - start) * stride));
        if (bpp == 1) memset(r, 0, stride);
        for (int x = 0; x < b->w; x++) {
            uint32_t c = b->px[(size_t)top * b->w + x];
            if (bpp == 32) r[4 * x] = (uint8_t)(c >> 16), r[4 * x + 1] = (uint8_t)(c >> 8), r[4 * x + 2] = (uint8_t)c, r[4 * x + 3] = 0;
            else if (bpp == 24) r[3 * x] = (uint8_t)(c >> 16), r[3 * x + 1] = (uint8_t)(c >> 8), r[3 * x + 2] = (uint8_t)c;
            else if (bpp == 1 && lum_mono(c)) r[x >> 3] |= (uint8_t)(0x80 >> (x & 7));
        }
    }
    return num;
}

/* ---- text ------------------------------------------------------------------ */
static fnt_t* dc_font(gobj_t* d, gobj_t** fo) {
    gobj_t* f = G(AT(d, DCA_FONT), GDI_FONT);
    if (fo) *fo = f;
    if (!g_nfnt) return NULL;
    return &g_fnt[f && f->font >= 0 ? f->font : 0];
}
static int text_width(fnt_t* F, gobj_t* fo, const uint16_t* s, int n) {
    int w = 0;
    for (int i = 0; i < n; i++) w += fnt_cw(F, s[i] < 256 ? s[i] : '?') + (fo && fo->bold ? 1 : 0);
    return w;
}
/* ExtTextOut: x, y logical; the cell's background when opaque; dx: widths */
static void textout(gobj_t* d, int x, int y, uint32_t opts, uint32_t prc, const uint16_t* s, int n, uint32_t dx) {
    gobj_t* fo;
    fnt_t* F = dc_font(d, &fo);
    uint32_t align = AT(d, DCA_TEXTALIGN);
    if (align & 1) x = (int)AT(d, DCA_CURX), y = (int)AT(d, DCA_CURY);      /* TA_UPDATECP */
    rc_t clip = d->clip;
    if (prc) {
        rc_t r = rc_get(prc);
        r = dc_rect(d, r.l, r.t, r.r, r.b);
        if (opts & 2) {                                                     /* ETO_OPAQUE */
            bmp_t* b = dc_bm(d);
            rc_t o = rc_and(r, d->clip);
            uint32_t c = dc_color(d, dc_bk(d));
            for (int Y = o.t; Y < o.b; Y++) for (int X = o.l; X < o.r; X++) b->px[(size_t)Y * b->w + X] = c;
        }
        if (opts & 4) clip = rc_and(clip, r);                               /* ETO_CLIPPED */
    }
    if (!F || !n) return;
    int w = 0;
    for (int i = 0; i < n; i++) w += dx ? (int)MEM32(dx + 4 * i) : fnt_cw(F, s[i] < 256 ? s[i] : '?') + (fo && fo->bold);
    if ((align & 6) == 6) x -= w / 2;                                       /* TA_CENTER */
    else if (align & 2) x -= w;                                             /* TA_RIGHT */
    if ((align & 24) == 24) y -= F->ascent;                                 /* TA_BASELINE */
    else if (align & 8) y -= F->h;                                          /* TA_BOTTOM */
    int X = x, Y = y;
    lp2dp(d, &X, &Y);
    bmp_t* b = dc_bm(d);
    uint32_t fg = dc_color(d, dc_fg(d)), bk = dc_color(d, dc_bk(d));
    int opaque = MEM8(d->attr + DCA_BKMODE) == 2;
    for (int i = 0; i < n; i++) {
        int c = s[i] < 256 ? s[i] : '?';
        if (c < F->first || c > F->last) c = F->defch;
        int cw = F->w[c], adv = dx ? (int)MEM32(dx + 4 * i) : cw + (fo && fo->bold);
        const uint8_t* g = F->raw + F->off[c];
        for (int yy = 0; yy < F->h; yy++)
            for (int xx = 0; xx < adv; xx++) {
                int PX = X + xx, PY = Y + yy;
                if (PX < clip.l || PX >= clip.r || PY < clip.t || PY >= clip.b) continue;
                int on = xx < cw && (g[(xx >> 3) * F->h + yy] >> (7 - (xx & 7)) & 1);
                if (fo && fo->bold && !on && xx > 0 && xx - 1 < cw) on = g[((xx - 1) >> 3) * F->h + yy] >> (7 - ((xx - 1) & 7)) & 1;
                if (fo && fo->underline && yy == F->ascent + 1) on = 1;
                if (on) b->px[(size_t)PY * b->w + PX] = fg;
                else if (opaque) b->px[(size_t)PY * b->w + PX] = bk;
            }
        X += adv;
    }
    if (align & 1) AT(d, DCA_CURX) += (uint32_t)w;
}

/* ======================================================================
 * GDI services (Windows 2000 argument lists)
 * ====================================================================== */
static int devcaps(int i) {
    switch (i) {
    case 0: return 0x4000; case 2: return 1; case 4: return 320; case 6: return 240;
    case 8: return g_cx; case 10: return g_cy; case 12: return 32; case 14: return 1;
    case 16: case 18: case 24: return -1; case 20: return 0; case 22: return 0;
    case 26: return 0; case 28: return 0xFF; case 30: return 0xFE; case 32: return 0xFF; case 34: return 0x7807;
    case 36: return 1; case 38: return 0x7E99; case 40: case 42: return 36; case 44: return 51;
    case 88: case 90: return 96; case 104: return 0; case 106: return 20; case 108: return 24;
    case 116: return 60; case 117: return g_cy; case 118: return g_cx; case 119: return 0;
    }
    return 0;
}
static uint32_t s_gdi_init(uint32_t* a) {
    (void)a;
    if (g_gdit) return 1;
    g_gdit = ntp_alloc(GDI_TABLE_SIZE);
    MEM32(ntp_peb() + PEB_GDITABLE) = g_gdit;
    w2k_gdi_devcaps(g_gdit, devcaps);
    /* the stock objects */
    static const uint32_t bc[] = { 0xFFFFFF, 0xC0C0C0, 0x808080, 0x404040, 0 };
    for (int i = 0; i <= 4; i++) { gobj_t* o = gnew(GDI_BRUSH, 1); o->color = bc[i]; g_stock[i] = o->h; }
    { gobj_t* o = gnew(GDI_BRUSH, 1); o->style = 1; g_stock[5] = o->h; }
    static const uint32_t pc[] = { 0xFFFFFF, 0, 0 };
    for (int i = 0; i < 3; i++) { gobj_t* o = gnew(GDI_PEN, 1); o->color = pc[i]; o->style = i == 2 ? 5 : 0; o->width = 1; g_stock[6 + i] = o->h; }
    for (int i = 10; i <= 17; i++) {
        if (i == 15) { gobj_t* o = gnew(GDI_PAL, 1); g_stock[i] = o->h; continue; }
        gobj_t* o = gnew(GDI_FONT, 1);
        o->font = i == 13 || i == 16 ? fnt_pick("System", 16) : i == 10 || i == 11 ? fnt_pick("Terminal", 12) : fnt_pick("MS Sans Serif", 13);
        o->height = o->font >= 0 ? g_fnt[o->font].h : 13;
        g_stock[i] = o->h;
    }
    { gobj_t* o = gnew(GDI_BRUSH, 1); o->color = 0xFFFFFF; g_stock[18] = o->h; }
    { gobj_t* o = gnew(GDI_PEN, 1); o->width = 1; g_stock[19] = o->h; }
    { gobj_t* o = gnew(GDI_BMP, 1); bm_init(&o->bm, 1, 1, 1); g_stockbm = o->h; }
    for (int i = 0; i < 0x1D; i++) { gobj_t* o = gnew(GDI_BRUSH, 1); o->color = w2k_colors_2000[i]; g_sysbrush[i] = o->h; }
    return 1;
}
static uint32_t s_zero(uint32_t* a) { (void)a; return 0; }
static uint32_t s_one(uint32_t* a) { (void)a; return 1; }
static uint32_t s_stock(uint32_t* a) { return a[0] < 20 ? g_stock[a[0]] : 0; }
static uint32_t s_compat_dc(uint32_t* a) { (void)a; gobj_t* d = dc_new(0); return d ? d->h : 0; }
static uint32_t s_compat_bitmap(uint32_t* a) {
    gobj_t* d = DCH(a[0]);
    int mono = d && !d->display && dc_bm(d)->mono;
    gobj_t* o = bitmap_new((int)a[1], (int)a[2], mono);
    return o ? o->h : 0;
}
/* NtGdiCreateBitmap(cx, cy, planes, bpp, bits) */
static uint32_t s_bitmap(uint32_t* a) {
    int w = (int)a[0], h = (int)a[1], bpp = (int)(a[2] * a[3]);
    gobj_t* o = bitmap_new(w, h, bpp == 1);
    if (!o || !a[4]) return o ? o->h : 0;
    const uint8_t* p = (const uint8_t*)(uintptr_t)a[4];
    int stride = ((w * bpp + 15) / 16) * 2;                   /* DDB rows: WORD aligned */
    for (int y = 0; y < h; y++)
        for (int x = 0; x < w; x++) {
            const uint8_t* r = p + (size_t)y * stride;
            uint32_t c = 0;
            if (bpp == 1) c = r[x >> 3] >> (7 - (x & 7)) & 1 ? 0xFFFFFF : 0;
            else if (bpp == 32) c = r[4 * x + 2] | r[4 * x + 1] << 8 | (uint32_t)r[4 * x] << 16;
            else if (bpp == 24) c = r[3 * x + 2] | r[3 * x + 1] << 8 | (uint32_t)r[3 * x] << 16;
            else if (bpp == 16) { uint32_t v = rd16(r + 2 * x); c = field(v, 0x7C00) | field(v, 0x3E0) << 8 | field(v, 0x1F) << 16; }
            o->bm.px[(size_t)y * w + x] = c;
        }
    return o->h;
}
static uint32_t s_pen(uint32_t* a) {             /* NtGdiCreatePen(style, width, color, hbr) */
    gobj_t* o = gnew(GDI_PEN, 0);
    if (!o) return 0;
    o->style = (int)(a[0] & 0xF), o->width = (int)a[1], o->color = CLR(a[2]);
    return o->h;
}
static uint32_t s_brush(uint32_t* a) {           /* NtGdiCreateSolidBrush(color, hbr) */
    gobj_t* o = gnew(GDI_BRUSH, 0);
    if (!o) return 0;
    o->color = CLR(a[0]);
    return o->h;
}
static uint32_t s_hatch(uint32_t* a) {           /* NtGdiCreateHatchBrushInternal(style, color, pen) */
    gobj_t* o = gnew(GDI_BRUSH, 0);
    if (o) o->color = CLR(a[1]);
    return o ? o->h : 0;
}
static uint32_t s_patbrush(uint32_t* a) {        /* NtGdiCreatePatternBrushInternal(hbm, bPen, b8x8) */
    bmp_t* b = bm_of(a[0]);
    gobj_t* o = gnew(GDI_BRUSH, 0);
    if (!o || !b) return o ? o->h : 0;
    o->pat = calloc(1, sizeof *o->pat);
    bm_init(o->pat, b->w, b->h, b->mono);
    memcpy(o->pat->px, b->px, (size_t)b->w * b->h * 4);
    return o->h;
}
/* a region's rectangle: gdi32's SetRectRgn writes the RGN_ATTR (+0 flags,
 * 0x20 dirty; +4 complexity; +8 the rect) without a call */
static rc_t* rgn_get(gobj_t* o) {
    if (o->attr && (MEM32(o->attr) & 0x20)) o->rgn = rc_get(o->attr + 8), MEM32(o->attr) &= ~0x20u;
    return &o->rgn;
}
static uint32_t rgn_set(gobj_t* o, rc_t r, uint32_t cplx) {
    if (rc_empty(&r)) r = (rc_t){ 0, 0, 0, 0 }, cplx = 1;
    o->rgn = r;
    if (o->attr) rc_put(o->attr + 8, r), MEM32(o->attr + 4) = cplx;
    return cplx;
}
static uint32_t s_rectrgn(uint32_t* a) {
    gobj_t* o = gnew(GDI_RGN, 0);
    if (o) rgn_set(o, (rc_t){ (int)a[0], (int)a[1], (int)a[2], (int)a[3] }, 2);
    return o ? o->h : 0;
}
/* NtGdiCombineRgn(dst, a, b, mode): AND, OR, XOR, DIFF, COPY on rectangles.
 * ponytail: a result that is not a rectangle is kept as its bounding box
 * (COMPLEXREGION returned); real regions when something draws through one */
static uint32_t s_combinergn(uint32_t* a) {
    gobj_t* d = G(a[0], GDI_RGN), *x = G(a[1], GDI_RGN), *y = G(a[2], GDI_RGN);
    if (!d || !x || (a[3] != 5 && !y)) return 0;
    rc_t p = *rgn_get(x), q = y ? *rgn_get(y) : p, i = rc_and(p, q);
    switch (a[3]) {
    case 1: return rgn_set(d, i, 2);
    case 2: case 3: return rgn_set(d, rc_empty(&p) ? q : rc_empty(&q) ? p : rc_or(p, q), 3);
    case 4:
        if (rc_empty(&i)) return rgn_set(d, p, 2);
        if (i.l <= p.l && i.r >= p.r) {                                  /* a band across the full width */
            if (i.t <= p.t) p.t = i.b < p.b ? i.b : p.b;
            else if (i.b >= p.b) p.b = i.t;
            else return rgn_set(d, p, 3);
            return rgn_set(d, p, 2);
        }
        if (i.t <= p.t && i.b >= p.b) {
            if (i.l <= p.l) p.l = i.r < p.r ? i.r : p.r;
            else if (i.r >= p.r) p.r = i.l;
            else return rgn_set(d, p, 3);
            return rgn_set(d, p, 2);
        }
        return rgn_set(d, p, 3);
    default: return rgn_set(d, p, 2);
    }
}
static uint32_t s_select_bitmap(uint32_t* a) {
    gobj_t* d = DCH(a[0]), *b = G(a[1], GDI_BMP);
    if (!d || !b || d->display) return 0;
    if (b->bm.dc && b->bm.dc != d->h && b->h != g_stockbm) return 0;   /* in another DC */
    uint32_t old = d->hbm;
    gobj_t* ob = G(old, GDI_BMP);
    if (ob) ob->bm.dc = 0;
    d->hbm = b->h;
    if (b->h != g_stockbm) b->bm.dc = d->h;
    d->vis = d->clip = (rc_t){ 0, 0, b->bm.w, b->bm.h };
    return old;
}
static uint32_t s_dcforbitmap(uint32_t* a) { gobj_t* b = G(a[0], GDI_BMP); return b ? b->bm.dc : 0; }
static uint32_t s_delete(uint32_t* a) {
    gobj_t* o = G(a[0], 0);
    if (!o) return 0;
    if (o->stock) return 1;
    if (o->type == GDI_BMP && o->bm.dc) { gobj_t* d = DCH(o->bm.dc); if (d && d->hbm == o->h) return 0; }
    if (o->type == GDI_DC) { gobj_t* b = G(o->hbm, GDI_BMP); if (b && b->bm.dc == o->h) b->bm.dc = 0; }
    gfree(o);
    return 1;
}
static uint32_t s_bitblt(uint32_t* a) {          /* NtGdiBitBlt(dst, x, y, cx, cy, src, xs, ys, rop, crBack, fl) */
    gobj_t* d = DCH(a[0]);
    if (!d) return 0;
    stretchblt(d, (int)a[1], (int)a[2], (int)a[3], (int)a[4], DCH(a[5]), (int)a[6], (int)a[7], (int)a[3], (int)a[4], a[8]);
    return 1;
}
static uint32_t s_stretchblt(uint32_t* a) {      /* (dst, x, y, cx, cy, src, xs, ys, cxs, cys, rop, crBack) */
    gobj_t* d = DCH(a[0]);
    if (!d) return 0;
    stretchblt(d, (int)a[1], (int)a[2], (int)a[3], (int)a[4], DCH(a[5]), (int)a[6], (int)a[7], (int)a[8], (int)a[9], a[10]);
    return 1;
}
static uint32_t s_patblt(uint32_t* a) {          /* NtGdiPatBlt(hdc, x, y, cx, cy, rop) */
    gobj_t* d = DCH(a[0]);
    if (!d) return 0;
    patblt(d, dc_rect(d, (int)a[1], (int)a[2], (int)a[1] + (int)a[3], (int)a[2] + (int)a[4]), a[5], 0);
    return 1;
}
static uint32_t s_lineto(uint32_t* a) {
    gobj_t* d = DCH(a[0]);
    if (!d) return 0;
    line(d, (int)AT(d, DCA_CURX), (int)AT(d, DCA_CURY), (int)a[1], (int)a[2]);
    AT(d, DCA_CURX) = a[1], AT(d, DCA_CURY) = a[2];
    return 1;
}
static uint32_t s_moveto(uint32_t* a) {          /* NtGdiMoveTo(hdc, x, y, POINT* old) */
    gobj_t* d = DCH(a[0]);
    if (!d) return 0;
    if (a[3]) MEM32(a[3]) = AT(d, DCA_CURX), MEM32(a[3] + 4) = AT(d, DCA_CURY);
    AT(d, DCA_CURX) = a[1], AT(d, DCA_CURY) = a[2];
    return 1;
}
static uint32_t s_rectangle(uint32_t* a) {       /* NtGdiRectangle(hdc, l, t, r, b) */
    gobj_t* d = DCH(a[0]);
    if (!d) return 0;
    int l = (int)a[1], t = (int)a[2], r = (int)a[3], b = (int)a[4];
    gobj_t* pen = G(AT(d, DCA_PEN), GDI_PEN);
    int pw = pen && pen->style != 5 ? 1 : 0;
    patblt(d, dc_rect(d, l + pw, t + pw, r - pw, b - pw), 0xF00021, 0);
    if (pw) { line(d, l, t, r - 1, t); line(d, r - 1, t, r - 1, b - 1); line(d, r - 1, b - 1, l, b - 1); line(d, l, b - 1, l, t); }
    return 1;
}
static uint32_t s_setpixel(uint32_t* a) {
    gobj_t* d = DCH(a[0]);
    if (!d) return (uint32_t)-1;
    int x = (int)a[1], y = (int)a[2];
    lp2dp(d, &x, &y);
    setpx(d, x, y, a[3], 13);
    return CLR(a[3]);
}
static uint32_t s_getpixel(uint32_t* a) {
    gobj_t* d = DCH(a[0]);
    if (!d) return (uint32_t)-1;
    int x = (int)a[1], y = (int)a[2];
    lp2dp(d, &x, &y);
    if (x < d->vis.l || x >= d->vis.r || y < d->vis.t || y >= d->vis.b) return (uint32_t)-1;
    bmp_t* b = dc_bm(d);
    return b->px[(size_t)y * b->w + x];
}
static uint32_t s_devcaps(uint32_t* a) { (void)a; return (uint32_t)devcaps((int)a[1]); }
/* NtGdiSetDIBitsToDeviceInternal(hdc, xDst, yDst, cx, cy, xSrc, ySrc, iStartScan,
 * cNumScan, pInitBits, pbmi, iUsage, cjMaxBits, cjMaxInfo, bTransform, hcmXform) */
static uint32_t s_setdibits(uint32_t* a) {
    gobj_t* d = DCH(a[0]);
    if (!d) return 0;
    int cx = (int)a[3], cy = (int)a[4];
    dib_draw(d, (int)a[1], (int)a[2], cx, cy, (int)a[5], (int)a[6], cx, cy, a[9], a[10], a[11], (int)a[7], (int)a[8], 0xCC0020);
    return a[8];
}
/* NtGdiStretchDIBitsInternal(hdc, xDst, yDst, cxDst, cyDst, xSrc, ySrc, cxSrc,
 * cySrc, pjInit, pbmi, iUsage, rop, cjMaxInfo, cjMaxBits, hcmXform) */
static uint32_t s_stretchdib(uint32_t* a) {
    gobj_t* d = DCH(a[0]);
    if (!d) return 0;
    dib_t D;
    if (!dib_parse(a[10], a[11], &D)) return 0;
    dib_draw(d, (int)a[1], (int)a[2], (int)a[3], (int)a[4], (int)a[5], (int)a[6], (int)a[7], (int)a[8], a[9], a[10], a[11], 0, D.h, a[12]);
    return (uint32_t)D.h;
}
/* a DIB into a bitmap (CreateDIBitmap's CBM_INIT, SetDIBits) */
static void dib_into(bmp_t* b, int start, int num, uint32_t bits, uint32_t bmi, uint32_t usage) {
    dib_t D;
    if (!bits || !dib_parse(bmi, usage, &D)) return;
    bits = dib_plain(&D, bits);
    if (num <= 0) num = D.h;
    for (int s = start; s < start + num && s < D.h; s++) {
        int top = D.topdown ? s : D.h - 1 - s;
        if (top >= b->h) continue;
        for (int x = 0; x < D.w && x < b->w; x++) {
            uint32_t c = dib_px(&D, (const uint8_t*)(uintptr_t)bits, x, s - start);
            b->px[(size_t)top * b->w + x] = b->mono ? lum_mono(c) : c;
        }
    }
}
/* NtGdiCreateDIBitmapInternal(hdc, cx, cy, fInit, pjInit, pbmi, iUsage,
 * cjMaxInitInfo, cjMaxBits, fl, hcmXform): a device bitmap; monochrome when
 * the DC's is, or the DIB is 1 bpp in black and white */
static uint32_t s_dibitmap(uint32_t* a) {
    gobj_t* d = DCH(a[0]);
    dib_t D;
    int mono = d && !d->display && dc_bm(d)->mono;
    if (a[5] && dib_parse(a[5], a[6], &D) && D.bpp == 1 && D.pal[0] == 0 && D.pal[1] == 0xFFFFFF) mono = 1;
    gobj_t* o = bitmap_new((int)a[1], (int)a[2], mono);
    if (o && (a[3] & 4)) dib_into(&o->bm, 0, 0, a[4], a[5], a[6]);
    return o ? o->h : 0;
}
/* NtGdiSetDIBits? gdi32 draws SetDIBits through the bitmap's DC; GetDIBits:
 * NtGdiGetDIBitsInternal(hdc, hbm, start, num, bits, bmi, usage, cjMaxBits, cjMaxInfo) */
static uint32_t s_getdibits(uint32_t* a) {
    bmp_t* b = bm_of(a[1]);
    return b && a[5] ? (uint32_t)dib_get(b, (int)a[2], (int)a[3], a[4], a[5]) : 0;
}
/* NtGdiCreateDIBSection(hdc, hSection, offset, BITMAPINFO*, usage, cjHeader,
 * fl, colorspace, void** bits): a device bitmap with its bits beside it */
static uint32_t s_dibsection(uint32_t* a) {
    dib_t D;
    if (!dib_parse(a[3], a[4], &D)) return 0;
    gobj_t* o = bitmap_new(D.w, D.h, D.bpp == 1);
    if (!o) return 0;
    uint32_t bits = ntp_alloc((uint32_t)(D.stride * D.h));
    if (a[8]) MEM32(a[8]) = bits;
    if (bits && D.comp != 1 && D.comp != 2 && (o->ds = malloc(sizeof *o->ds + (size_t)D.stride * D.h))) {
        o->ds->D = D, o->ds->bits = bits;
        memset(o->ds->shadow, 0xFF, (size_t)D.stride * D.h);   /* (differs: the first use loads them) */
    }
    return o->h;
}
/* the program writes a DIB section's bits itself: before GDI uses the bitmap, bits that changed
 * since the last look are loaded into its pixels. ponytail: one way only; GDI's own drawing is
 * not written back to the bits (a program reading its bits after drawing on them sees the old
 * ones), and the compare is a whole-buffer memcmp per use */
static void ds_sync(gobj_t* o) {
    struct dibsec* s = o->ds;
    size_t n = (size_t)s->D.stride * s->D.h;
    const uint8_t* bits = (const uint8_t*)(uintptr_t)s->bits;
    s->touched = 1;                                         /* (GDI may draw on it now) */
    if (!memcmp(s->shadow, bits, n)) return;
    bmp_t* b = &o->bm;
    int bpp = s->D.bpp;
    for (int r = 0; r < s->D.h && r < b->h; r++) {         /* only the pixels whose bytes changed */
        size_t ro = (size_t)r * s->D.stride;
        if (!memcmp(s->shadow + ro, bits + ro, (size_t)s->D.stride)) continue;
        int top = s->D.topdown ? r : s->D.h - 1 - r;
        for (int x = 0; x < s->D.w && x < b->w; x++) {
            size_t b0 = ro + (size_t)x * bpp / 8, b1 = ro + ((size_t)x * bpp + bpp - 1) / 8;
            if (!memcmp(s->shadow + b0, bits + b0, b1 - b0 + 1)) continue;
            uint32_t c = dib_px(&s->D, bits, x, r);
            b->px[(size_t)top * b->w + x] = b->mono ? lum_mono(c) : c;
        }
    }
    memcpy(s->shadow, bits, n);
}
/* a COLORREF into a DIB's mask field (field()'s inverse) */
static uint32_t unfield(uint32_t c8, uint32_t m) {
    if (!m) return 0;
    int s = 0, n = 0;
    while (!(m >> s & 1)) s++;
    while (m >> (s + n) & 1) n++;
    return ((n >= 8 ? c8 << (n - 8) : c8 >> (8 - n)) << s) & m;
}
/* GdiFlush (NtGdiFlush): what GDI drew on a DIB section is in its bits afterwards (the program
 * reads them then: comctl32's image lists). Only the sections GDI touched since the last flush */
static uint32_t s_gdiflush(uint32_t* a) {
    (void)a;
    for (int i = 0; i < GDI_ENTRIES; i++) {
        gobj_t* o = g_g[i];
        if (!o || !o->ds || !o->ds->touched) continue;
        ds_sync(o);                                         /* (the program's own writes first) */
        struct dibsec* s = o->ds;
        const dib_t* D = &s->D;
        uint8_t* bits = (uint8_t*)(uintptr_t)s->bits;
        for (int r = 0; r < D->h && r < o->bm.h; r++) {
            int top = D->topdown ? r : D->h - 1 - r;
            uint8_t* row = bits + (size_t)r * D->stride;
            for (int x = 0; x < D->w && x < o->bm.w; x++) {
                uint32_t c = o->bm.px[(size_t)top * o->bm.w + x] & 0xFFFFFF;
                if (dib_px(D, bits, x, r) == c) continue;
                uint32_t R = c & 0xFF, G = c >> 8 & 0xFF, B = c >> 16 & 0xFF;
                if (D->bpp <= 8) {                          /* the nearest palette entry */
                    int best = 0, bd = 1 << 30;
                    for (int k = 0; k < D->ncol; k++) {
                        uint32_t q = D->pal[k];
                        int d = abs((int)(q & 0xFF) - (int)R) + abs((int)(q >> 8 & 0xFF) - (int)G) + abs((int)(q >> 16 & 0xFF) - (int)B);
                        if (d < bd) bd = d, best = k;
                    }
                    int sh = D->bpp == 1 ? 7 - (x & 7) : D->bpp == 4 ? (x & 1 ? 0 : 4) : 0;
                    uint8_t mk = (uint8_t)(((1 << D->bpp) - 1) << sh);
                    uint8_t* q = &row[(size_t)x * D->bpp / 8];
                    *q = (uint8_t)((*q & ~mk) | ((best << sh) & mk));
                } else if (D->bpp == 24) row[3 * x] = (uint8_t)B, row[3 * x + 1] = (uint8_t)G, row[3 * x + 2] = (uint8_t)R;
                else {
                    uint32_t v = unfield(R, D->mask[0]) | unfield(G, D->mask[1]) | unfield(B, D->mask[2]);
                    if (D->bpp == 16) row[2 * x] = (uint8_t)v, row[2 * x + 1] = (uint8_t)(v >> 8);
                    else memcpy(row + 4 * x, &v, 4);
                }
            }
        }
        memcpy(s->shadow, bits, (size_t)D->stride * D->h);
        s->touched = 0;
    }
    return 1;
}
/* NtGdiExtGetObjectW(h, count, buffer) */
static uint32_t s_getobject(uint32_t* a) {
    gobj_t* o = G(a[0], 0);
    if (!o) return 0;
    uint32_t p = a[2];
    if (o->type == GDI_PEN) {
        if (!p) return 16;
        MEM32(p) = (uint32_t)o->style, MEM32(p + 4) = (uint32_t)o->width, MEM32(p + 8) = 0, MEM32(p + 12) = o->color;
        return 16;
    }
    switch (o->type & 0x1F) {
    case GDI_BMP:
        if (!p) return 24;
        MEM32(p) = 0, MEM32(p + 4) = (uint32_t)o->bm.w, MEM32(p + 8) = (uint32_t)o->bm.h;
        MEM32(p + 12) = (uint32_t)(o->bm.mono ? ((o->bm.w + 15) / 16) * 2 : o->bm.w * 4);
        MEM16(p + 16) = 1, MEM16(p + 18) = (uint16_t)(o->bm.mono ? 1 : 32), MEM32(p + 20) = 0;
        return 24;
    case GDI_BRUSH:
        if (!p) return 12;
        MEM32(p) = o->pat ? 3 : (uint32_t)o->style, MEM32(p + 4) = o->color, MEM32(p + 8) = 0;
        return 12;
    case GDI_FONT: {
        if (!p) return 92;
        fnt_t* F = o->font >= 0 && g_nfnt ? &g_fnt[o->font] : NULL;
        memset((void*)(uintptr_t)p, 0, a[1] < 92 ? a[1] : 92);
        if (a[1] < 92) return a[1];
        MEM32(p) = (uint32_t)(F ? -(F->h - F->ilead) : -11);
        MEM32(p + 16) = o->bold ? 700 : 400;
        if (F) for (int i = 0; F->face[i] && i < 31; i++) MEM16(p + 28 + 2 * i) = (uint8_t)F->face[i];
        return 92;
    }
    }
    return 0;
}
static uint32_t s_textmetrics(uint32_t* a) {     /* NtGdiGetTextMetricsW(hdc, TMW_INTERNAL*, cj) */
    gobj_t* d = DCH(a[0]), *fo = NULL;
    fnt_t* F = d ? dc_font(d, &fo) : NULL;
    uint32_t t = a[1];
    if (!F || !t) return 0;
    memset((void*)(uintptr_t)t, 0, a[2]);
    MEM32(t + 0) = (uint32_t)F->h, MEM32(t + 4) = (uint32_t)F->ascent, MEM32(t + 8) = (uint32_t)(F->h - F->ascent);
    MEM32(t + 12) = (uint32_t)F->ilead, MEM32(t + 16) = (uint32_t)F->elead;
    MEM32(t + 20) = (uint32_t)F->avgw + (fo && fo->bold), MEM32(t + 24) = (uint32_t)F->maxw + (fo && fo->bold);
    MEM32(t + 28) = fo && fo->bold ? 700 : (uint32_t)F->weight;
    MEM32(t + 32) = 0, MEM32(t + 36) = 96, MEM32(t + 40) = 96;
    MEM16(t + 44) = (uint16_t)F->first, MEM16(t + 46) = (uint16_t)F->last, MEM16(t + 48) = (uint16_t)F->defch, MEM16(t + 50) = (uint16_t)F->brk;
    MEM8(t + 52) = 0, MEM8(t + 53) = (uint8_t)(fo && fo->underline), MEM8(t + 54) = 0;
    MEM8(t + 55) = (uint8_t)F->pitch, MEM8(t + 56) = (uint8_t)F->charset;
    return 1;
}
/* NtGdiGetTextExtent(hdc, str, count, SIZE*, flags) and ...ExW(hdc, str,
 * count, maxExtent, *fit, *dx, SIZE*, flags) */
static uint32_t s_textextent(uint32_t* a) {
    gobj_t* d = DCH(a[0]), *fo = NULL;
    fnt_t* F = d ? dc_font(d, &fo) : NULL;
    if (!F || !a[3]) return 0;
    MEM32(a[3]) = (uint32_t)text_width(F, fo, (const uint16_t*)(uintptr_t)a[1], (int)a[2]);
    MEM32(a[3] + 4) = (uint32_t)F->h;
    return 1;
}
static uint32_t s_textextentex(uint32_t* a) {
    gobj_t* d = DCH(a[0]), *fo = NULL;
    fnt_t* F = d ? dc_font(d, &fo) : NULL;
    const uint16_t* s = (const uint16_t*)(uintptr_t)a[1];
    if (!F || !a[6]) return 0;
    int w = 0, n = (int)a[2], fit = 0;
    for (int i = 0; i < n; i++) {
        w += fnt_cw(F, s[i] < 256 ? s[i] : '?') + (fo && fo->bold);
        if (a[5]) MEM32(a[5] + 4 * i) = (uint32_t)w;
        if (w <= (int)a[3]) fit = i + 1;
    }
    if (a[4]) MEM32(a[4]) = (uint32_t)fit;
    MEM32(a[6]) = (uint32_t)w, MEM32(a[6] + 4) = (uint32_t)F->h;
    return 1;
}
/* NtGdiGetCharWidthW(hdc, first, count, WCHAR* chars, fl, buffer) */
static uint32_t s_charwidth(uint32_t* a) {
    gobj_t* d = DCH(a[0]), *fo = NULL;
    fnt_t* F = d ? dc_font(d, &fo) : NULL;
    if (!F || !a[5]) return 0;
    for (uint32_t i = 0; i < a[2]; i++) {
        uint32_t c = a[3] ? MEM16(a[3] + 2 * i) : a[1] + i;
        MEM32(a[5] + 4 * i) = (uint32_t)(fnt_cw(F, c < 256 ? (int)c : '?') + (fo && fo->bold));
    }
    return 1;
}
/* NtGdiHfontCreate(ENUMLOGFONTEXDVW*, cj, lft, fl, pvCliData): its LOGFONTW leads */
static uint32_t s_font(uint32_t* a) {
    uint32_t l = a[0];
    char face[33] = "";
    for (int i = 0; i < 32 && MEM16(l + 28 + 2 * i); i++) face[i] = (char)MEM16(l + 28 + 2 * i), face[i + 1] = 0;
    gobj_t* o = gnew(GDI_FONT, 0);
    if (!o) return 0;
    if (!strcasecmp(face, "MS Shell Dlg") || !strcasecmp(face, "Tahoma") || !strcasecmp(face, "Microsoft Sans Serif") || !face[0])
        strcpy(face, "MS Sans Serif");
    o->height = (int)MEM32(l);
    o->font = fnt_pick(face, o->height);
    o->bold = (int)MEM32(l + 16) >= 600 && (o->font < 0 || g_fnt[o->font].weight < 600);
    o->italic = MEM8(l + 20), o->underline = MEM8(l + 21);
    TRACE("[gdi] font %s %d weight %d -> %d\n", face, o->height, (int)MEM32(l + 16), o->font);
    return o->h;
}
/* NtGdiExtTextOutW(hdc, x, y, flOpts, prcl, pwsz, cwc, pdx, dwCodePage) */
static uint32_t s_textout(uint32_t* a) {
    gobj_t* d = DCH(a[0]);
    if (!d) return 0;
    textout(d, (int)a[1], (int)a[2], a[3], a[4], (const uint16_t*)(uintptr_t)a[5], (int)a[6], a[7]);
    return 1;
}
static uint32_t s_select(uint32_t* a) {          /* NtGdiSelectBrush/Pen/Font: the DC_ATTR's (gdi32 sets it too) */
    gobj_t* d = DCH(a[0]), *o = G(a[1], 0);
    if (!d || !o) return 0;
    uint32_t off = (o->type & 0x1F) == GDI_FONT ? DCA_FONT : o->type == GDI_PEN ? DCA_PEN : DCA_BRUSH, old = AT(d, off);
    AT(d, off) = a[1];
    return old;
}
/* NtGdiGetDCObject(hdc, type << 16) */
static uint32_t s_dcobject(uint32_t* a) {
    gobj_t* d = DCH(a[0]);
    if (!d) return 0;
    switch (a[1] >> 16) {
    case GDI_BMP: return d->display ? g_stockbm : d->hbm;
    case GDI_FONT: return AT(d, DCA_FONT);
    case GDI_BRUSH: return AT(d, DCA_BRUSH);
    case GDI_PEN: return AT(d, DCA_PEN);
    case GDI_PAL: return g_stock[15];
    }
    return 0;
}
/* clipping: one rectangle, in the DC's bitmap */
static uint32_t s_intersectclip(uint32_t* a) {
    gobj_t* d = DCH(a[0]);
    if (!d) return 0;
    d->clip = rc_and(d->clip, dc_rect(d, (int)a[1], (int)a[2], (int)a[3], (int)a[4]));
    return rc_empty(&d->clip) ? 1 : 2;                      /* NULLREGION / SIMPLEREGION */
}
static uint32_t s_excludeclip(uint32_t* a) { (void)a; return 2; }   /* ponytail: not excluded */
static uint32_t s_selectcliprgn(uint32_t* a) {   /* NtGdiExtSelectClipRgn(hdc, hrgn, mode) */
    gobj_t* d = DCH(a[0]), *r = G(a[1], GDI_RGN);
    if (!d) return 0;
    if (r) rgn_get(r);
    if (!r) d->clip = d->vis;
    else {
        rc_t rr = { r->rgn.l + d->ox, r->rgn.t + d->oy, r->rgn.r + d->ox, r->rgn.b + d->oy };
        d->clip = a[2] == 1 ? rc_and(d->clip, rr) : rc_and(d->vis, rr);   /* RGN_AND, else RGN_COPY */
    }
    return 2;
}
static uint32_t s_savedc(uint32_t* a) {
    gobj_t* d = DCH(a[0]);
    if (!d) return 0;
    d->saved = realloc(d->saved, sizeof *d->saved * (d->nsaved + 1));
    memcpy(d->saved[d->nsaved].a, (void*)(uintptr_t)d->attr, DCA_SIZE);
    d->saved[d->nsaved].clip = d->clip, d->saved[d->nsaved].hbm = d->hbm;
    return (uint32_t)++d->nsaved;
}
static uint32_t s_restoredc(uint32_t* a) {
    gobj_t* d = DCH(a[0]);
    int lv = (int)a[1];
    if (!d || !d->nsaved) return 0;
    if (lv < 0) lv = d->nsaved + lv + 1;
    if (lv < 1 || lv > d->nsaved) return 0;
    memcpy((void*)(uintptr_t)d->attr, d->saved[lv - 1].a, DCA_SIZE);
    d->clip = d->saved[lv - 1].clip;
    d->nsaved = lv - 1;
    return 1;
}
static uint32_t s_getcharset(uint32_t* a) { (void)a; return 1252u << 16; }   /* ANSI_CHARSET, cp 1252 */
static uint32_t s_nearest(uint32_t* a) { return a[1] & 0xFFFFFF; }   /* NtGdiGetNearestColor: true colour, itself */
static uint32_t s_charsetinfo(uint32_t* a) {     /* NtGdiGetTextCharsetInfo(hdc, FONTSIGNATURE*, flags): ANSI_CHARSET */
    if (a[1]) { for (int i = 0; i < 24; i += 4) MEM32(a[1] + i) = 0; MEM32(a[1] + 16) = 1; }   /* fsCsb[0]: Latin 1 */
    return 0;
}
/* NtGdiGetTextFaceW(hdc, cChar, out, fAlias): the face that renders (a .fon's), with its length counting the NUL */
static uint32_t s_textface(uint32_t* a) {
    gobj_t* d = DCH(a[0]);
    fnt_t* F = d ? dc_font(d, NULL) : NULL;
    if (!F) return 0;
    uint32_t n = (uint32_t)strlen(F->face) + 1;
    if (!a[2]) return n;
    if (n > a[1]) n = a[1];
    if (!n) return 0;
    for (uint32_t i = 0; i + 1 < n; i++) MEM16(a[2] + 2 * i) = (uint8_t)F->face[i];
    MEM16(a[2] + 2 * (n - 1)) = 0;
    return n;
}
/* Font enumeration: NtGdiEnumFontOpen(hdc, type, flWin31Compat, cwchMax, face, charset, &cb)
 * gives an id and the size of the list; NtGdiEnumFontChunk(hdc, id, cb, &cbGot, buf) copies
 * it. One ENUMFONTDATAW per face, as gdi32 walks it: +0 its size, +4 dpNtmi (the
 * NEWTEXTMETRICEXW is at +8+dpNtmi), +8 the font type, +0xC ENUMLOGFONTEXDVW.
 * The faces are the .fon faces w32kposix renders; a named face is answered as itself
 * (any face renders, through fnt_pick), Western. ponytail: one enumeration at a time. */
#define EFD_LF 0xC
#define EFD_NTM 0x1B8                             /* after ENUMLOGFONTEXDVW (420 bytes) */
#define EFD_SIZE (EFD_NTM + 100 + 72)
static uint8_t* g_efd;
static uint32_t g_efd_cb;
static void a2u(uint16_t* d, const char* s, int cap) { int i = 0; for (; s[i] && i < cap - 1; i++) d[i] = (uint8_t)s[i]; d[i] = 0; }
static void efd_put(uint8_t* e, const char* face, const fnt_t* F) {
    uint32_t p = (uint32_t)(uintptr_t)e, lf = p + EFD_LF, tm = p + EFD_NTM;
    memset(e, 0, EFD_SIZE);
    MEM32(p) = EFD_SIZE, MEM32(p + 4) = EFD_NTM - 8, MEM32(p + 8) = 1;              /* RASTER_FONTTYPE */
    MEM32(lf) = (uint32_t)(F ? F->h : 13), MEM32(lf + 4) = (uint32_t)(F ? F->avgw : 6);
    MEM32(lf + 16) = F ? (uint32_t)F->weight : 400;
    MEM8(lf + 23) = 0, MEM8(lf + 27) = (uint8_t)(F ? F->pitch : 0x22);              /* ANSI_CHARSET */
    for (int i = 0; face[i] && i < 31; i++) MEM16(lf + 28 + 2 * i) = (uint8_t)face[i], MEM16(lf + 92 + 2 * i) = (uint8_t)face[i];
    a2u((uint16_t*)(uintptr_t)(lf + 220), "Regular", 32);
    a2u((uint16_t*)(uintptr_t)(lf + 284), "Western", 32);
    if (F) {
        MEM32(tm) = (uint32_t)F->h, MEM32(tm + 4) = (uint32_t)F->ascent, MEM32(tm + 8) = (uint32_t)(F->h - F->ascent);
        MEM32(tm + 12) = (uint32_t)F->ilead, MEM32(tm + 16) = (uint32_t)F->elead;
        MEM32(tm + 20) = (uint32_t)F->avgw, MEM32(tm + 24) = (uint32_t)F->maxw, MEM32(tm + 28) = (uint32_t)F->weight;
        MEM16(tm + 44) = (uint16_t)F->first, MEM16(tm + 46) = (uint16_t)F->last;
        MEM16(tm + 48) = (uint16_t)F->defch, MEM16(tm + 50) = (uint16_t)F->brk;
        MEM8(tm + 55) = (uint8_t)F->pitch;
    }
    MEM32(tm + 36) = 96, MEM32(tm + 40) = 96, MEM32(tm + 92) = 1;                  /* fsCsb[0]: Latin 1 */
}
static uint32_t s_enumfont_open(uint32_t* a) {
    char face[33] = "";
    for (uint32_t i = 0; a[4] && i < 32 && MEM16(a[4] + 2 * i); i++) face[i] = (char)MEM16(a[4] + 2 * i), face[i + 1] = 0;
    free(g_efd);
    g_efd = calloc((size_t)(g_nfnt + 1), EFD_SIZE), g_efd_cb = 0;
    if (face[0]) {
        int k = fnt_pick(face, 0);
        efd_put(g_efd, face, k >= 0 && g_nfnt ? &g_fnt[k] : NULL), g_efd_cb = EFD_SIZE;
    } else
        for (int i = 0; i < g_nfnt; i++) {
            int dup = 0;
            for (int j = 0; j < i; j++) dup |= !strcmp(g_fnt[j].face, g_fnt[i].face);
            if (!dup) efd_put(g_efd + g_efd_cb, g_fnt[i].face, &g_fnt[i]), g_efd_cb += EFD_SIZE;
        }
    if (a[6]) MEM32(a[6]) = g_efd_cb;
    return 0x4E554D45u;                           /* any non-zero id */
}
static uint32_t s_enumfont_chunk(uint32_t* a) {
    uint32_t n = a[2] < g_efd_cb ? a[2] : g_efd_cb;
    if (!g_efd || !a[4]) return 0;
    memcpy((void*)(uintptr_t)a[4], g_efd, n);
    if (a[3]) MEM32(a[3]) = n;
    return 1;
}
static rc_t* rgn_get(gobj_t* o);
static uint32_t rgn_set(gobj_t* o, rc_t r, uint32_t cplx);
static uint32_t s_randomrgn(uint32_t* a) {       /* NtGdiGetRandomRgn(hdc, hrgn, SYSRGN 4): the visible region, screen coordinates */
    gobj_t* d = DCH(a[0]), *r = G(a[1], GDI_RGN);
    if (!d || !r) return (uint32_t)-1;
    rgn_set(r, d->vis, 2);
    return 1;
}
static uint32_t s_dcpoint(uint32_t* a) {         /* NtGdiGetDCPoint(hdc, 6 the origin, POINTL*) */
    gobj_t* d = DCH(a[0]);
    if (!d || a[1] != 6 || !a[2]) return 0;
    MEM32(a[2]) = (uint32_t)d->ox, MEM32(a[2] + 4) = (uint32_t)d->oy;
    return 1;
}
/* NtGdiGetDCDword(hdc, index, DWORD*): 7 a memory DC's type (GetObjectType) */
static uint32_t s_getdword(uint32_t* a) {
    gobj_t* d = DCH(a[0]);
    if (!d || !a[2]) return 0;
    if (a[1] == 7) { MEM32(a[2]) = d->display ? 1 : 2; return 1; }
    MEM32(a[2]) = 0;
    return 1;
}
static uint32_t s_getsetdword(uint32_t* a) {     /* NtGdiGetAndSetDCDword(hdc, index, value, DWORD* old) */
    gobj_t* d = DCH(a[0]);
    if (!d) return 0;
    if (a[1] == 8) { if (a[3]) MEM32(a[3]) = AT(d, DCA_MAPMODE); AT(d, DCA_MAPMODE) = a[2]; return 1; }
    if (a[3]) MEM32(a[3]) = 0;
    return 1;
}
static uint32_t s_opendc(uint32_t* a) { (void)a; gobj_t* d = dc_new(1); return d ? d->h : 0; }
static uint32_t s_getrgnbox(uint32_t* a) {       /* NtGdiGetRgnBox(hrgn, RECT*) */
    gobj_t* r = G(a[0], GDI_RGN);
    if (!r || !a[1]) return 0;
    rc_put(a[1], *rgn_get(r));
    return rc_empty(&r->rgn) ? 1 : 2;
}
static uint32_t s_cliprect(uint32_t* a) {        /* NtGdiGetAppClipBox(hdc, RECT*) */
    gobj_t* d = DCH(a[0]);
    if (!d || !a[1]) return 0;
    rc_t c = d->clip;
    c.l -= d->ox, c.r -= d->ox, c.t -= d->oy, c.b -= d->oy;
    rc_put(a[1], c);
    return 2;
}

/* the TEB batch */
static void batch_cmd(uint32_t hdc, uint32_t cmd, uint32_t e, uint32_t len) {
    gobj_t* d = DCH(hdc);
    switch (cmd) {
    case W2K_B_PATBLT:
        if (d) patblt(d, dc_rect(d, (int)MEM32(e + 4), (int)MEM32(e + 8), (int)MEM32(e + 4) + (int)MEM32(e + 0xC), (int)MEM32(e + 8) + (int)MEM32(e + 0x10)),
                      MEM32(e + 0x18), MEM32(e + 0x14));
        break;
    case W2K_B_POLYPATBLT:
        for (uint32_t k = 0, n = MEM32(e + 0xC); d && k < n && 0x24 + 0x14 * (k + 1) <= len; k++) {
            uint32_t r = e + 0x24 + 0x14 * k;
            patblt(d, dc_rect(d, (int)MEM32(r), (int)MEM32(r + 4), (int)MEM32(r) + (int)MEM32(r + 8), (int)MEM32(r + 4) + (int)MEM32(r + 0xC)),
                   MEM32(e + 4), MEM32(r + 0x10));
        }
        break;
    case W2K_B_TEXTOUT:
        if (d) {
            uint32_t save[4] = { AT(d, DCA_TEXTCOLOR), AT(d, DCA_BKCOLOR), MEM8(d->attr + DCA_BKMODE), AT(d, DCA_FONT) };
            uint32_t sal = AT(d, DCA_TEXTALIGN), o = MEM32(e + 0x18);
            AT(d, DCA_TEXTCOLOR) = MEM32(e + 4), AT(d, DCA_BKCOLOR) = MEM32(e + 8), MEM8(d->attr + DCA_BKMODE) = (uint8_t)MEM32(e + 0xC);
            if (MEM32(e + 0x38)) AT(d, DCA_FONT) = MEM32(e + 0x38);
            AT(d, DCA_TEXTALIGN) = MEM32(e + 0x3C);
            textout(d, (int)MEM32(e + 0x10), (int)MEM32(e + 0x14), o & 0x7FFFFFFFu, (o & 0x80000000u) ? 0 : e + 0x1C,
                    (const uint16_t*)(uintptr_t)(e + 0x48), (int)MEM32(e + 0x30), 0);
            AT(d, DCA_TEXTCOLOR) = save[0], AT(d, DCA_BKCOLOR) = save[1], MEM8(d->attr + DCA_BKMODE) = (uint8_t)save[2], AT(d, DCA_FONT) = save[3];
            AT(d, DCA_TEXTALIGN) = sal;
        }
        break;
    case W2K_B_EXTTEXTOUT:
        if (d) {
            uint32_t sv = AT(d, DCA_BKCOLOR);
            AT(d, DCA_BKCOLOR) = MEM32(e + 4);
            textout(d, 0, 0, MEM32(e + 8), e + 0xC, NULL, 0, 0);
            AT(d, DCA_BKCOLOR) = sv;
        }
        break;
    case W2K_B_BRUSHORG: if (d) AT(d, DCA_BRUSHORG) = MEM32(e + 4), AT(d, DCA_BRUSHORG + 4) = MEM32(e + 8); break;
    case W2K_B_CLIPRGN:
        if (d) {
            uint32_t m = MEM32(e + 4);
            if (m & 0x80000000u) d->clip = d->vis;
            else {
                rc_t r = { (int)MEM32(e + 8) + d->ox, (int)MEM32(e + 0xC) + d->oy, (int)MEM32(e + 0x10) + d->ox, (int)MEM32(e + 0x14) + d->oy };
                d->clip = (m & 0xFF) == 1 ? rc_and(d->clip, r) : rc_and(d->vis, r);
            }
        }
        break;
    case W2K_B_FONT: if (d) AT(d, DCA_FONT) = MEM32(e + 4); break;
    case W2K_B_DELETE: s_delete((uint32_t*)(uintptr_t)(e + 4)); break;
    default: fprintf(stderr, "[gdi] batch command %u (%u bytes) dropped\n", cmd, len);
    }
}
static uint32_t s_flushbatch(uint32_t* a) { (void)a; w2k_gdi_batch(MEM32(g_fs_base + 0x18), batch_cmd); return 0; }

/* ======================================================================
 * USER: objects, windows, classes
 * ====================================================================== */
#define MAXU 0x2000
typedef struct { uint32_t type, state, id, sub, data, bmp; uint16_t text[64]; int x, w; } item_t;
typedef struct uobj {
    uint8_t type;
    uint32_t h, obj;                              /* the handle; the object in the desktop heap */
    /* a window */
    int cls;
    uint32_t style, ex, parent, owner, menu, id, inst;
    rc_t wrel;                                    /* the window rect in the parent's client coordinates */
    rc_t cin;                                     /* the client rect within the window rect */
    rc_t wr, cr;                                  /* both on the screen */
    int dirty, ncdirty, erase;
    int ansi;                                     /* an ANSI window procedure (win32k's WFANSIPROC) */
    int sizemove;                                 /* WM_SIZE and WM_MOVE still to send, at the first show (as win32k's WFSENDSIZEMOVE) */
    int sb[2][4];                                 /* WS_HSCROLL / WS_VSCROLL: min, max, page, pos */
    uint16_t text[128];
    /* a menu */
    item_t* items;
    int nitems;
    /* a cursor / icon */
    uint32_t mask, color;
    int icx, icy;
} uobj_t;
static uobj_t g_u[MAXU];
static uint16_t g_uuniq[MAXU];
static uint32_t g_psi, g_ahe, g_disp, g_mon, g_desk, g_deskinfo, g_threadinfo, g_desk_top, g_defmsgs;
#define DESK_SIZE (8u << 20)
static uint32_t g_desktop;                        /* the desktop window's handle */
static uint32_t g_focus, g_capture, g_active, g_main;

static uint32_t desk_alloc(uint32_t n) {
    uint32_t p = g_desk + g_desk_top;
    g_desk_top += (n + 15) & ~15u;
    if (g_desk_top > DESK_SIZE) { fprintf(stderr, "[user] desktop heap full\n"); exit(3); }
    memset((void*)(uintptr_t)p, 0, n);
    return p;
}
static uobj_t* U(uint32_t h, int type) {
    uint32_t i = h & 0xFFFF;
    if (!h || i >= MAXU || g_u[i].h != h || g_u[i].type != type) return NULL;
    return &g_u[i];
}
static uobj_t* W(uint32_t h) { return U(h, W2K_TYPE_WINDOW); }
static uobj_t* unew(int type, uint32_t size) {
    for (int i = 2; i < MAXU; i++)
        if (!g_u[i].type) {
            uobj_t* u = &g_u[i];
            memset(u, 0, sizeof *u);
            if (++g_uuniq[i] == 0) g_uuniq[i] = 1;
            u->type = (uint8_t)type, u->h = (uint32_t)i | (uint32_t)g_uuniq[i] << 16;
            u->obj = desk_alloc(size);
            MEM32(u->obj) = u->h;
            w2k_ahe_set(g_ahe, u->h, u->obj, (uint8_t)type, g_threadinfo);
            return u;
        }
    fprintf(stderr, "[user] handle table full\n");
    return NULL;
}
static void ufree(uobj_t* u) { w2k_ahe_clear(g_ahe, u->h); free(u->items); u->type = 0, u->h = 0; }

typedef struct {
    uint16_t name[64];
    uint16_t atom, fnid;
    int ansi;                                     /* CSF_ANSIPROC (2): RegisterClassA */
    uint32_t proc, style, extra, inst, bg, icon, iconsm, menu, cls;
} cls_t;
#define MAXC 64
static cls_t g_cls[MAXC];
static int g_ncls;
static uint16_t g_atom = 0xC000;
static int u16icmp(const uint16_t* a, const uint16_t* b) {
    for (;; a++, b++) {
        int x = *a < 128 ? tolower(*a) : *a, y = *b < 128 ? tolower(*b) : *b;
        if (x != y || !x) return x - y;
    }
}
static void u16cpy(uint16_t* d, const uint16_t* s, int cap) { int i = 0; for (; s && s[i] && i < cap - 1; i++) d[i] = s[i]; d[i] = 0; }
static int u16len_(const uint16_t* s) { int n = 0; while (s && s[n]) n++; return n; }
/* a class by atom (a value below 0x10000) or name */
static int cls_find(uint32_t name) {
    for (int i = 0; i < g_ncls; i++)
        if (name < 0x10000 ? g_cls[i].atom == name : !u16icmp(g_cls[i].name, (const uint16_t*)(uintptr_t)name)) return i;
    return -1;
}
/* LARGE_STRING (CreateWindowEx: buffer at +8, bAnsi bit 31 of +4) or an atom */
static uint32_t lstr(uint32_t ls, uint16_t* tmp, int cap) {
    if (ls < 0x10000) return ls;
    uint32_t b = MEM32(ls + 8);
    if (b < 0x10000) return b;
    if (MEM32(ls + 4) & 0x80000000u) {
        int n = (int)MEM32(ls);
        for (int i = 0; i < n && i < cap - 1; i++) tmp[i] = MEM8(b + i), tmp[i + 1] = 0;
        if (!n) tmp[0] = 0;
        return (uint32_t)(uintptr_t)tmp;
    }
    int n = (int)MEM32(ls) / 2;
    for (int i = 0; i < n && i < cap - 1; i++) tmp[i] = MEM16(b + 2 * i), tmp[i + 1] = 0;
    if (!n) tmp[0] = 0;
    return (uint32_t)(uintptr_t)tmp;
}

/* ---- metrics -------------------------------------------------------------- */
static int32_t g_met[0x53];
#define SM(i) g_met[i]
#define WS_CHILD 0x40000000u
#define WS_VISIBLE 0x10000000u
#define WS_CAPTION 0x00C00000u
#define WS_BORDER 0x00800000u
#define WS_DLGFRAME 0x00400000u
#define WS_SYSMENU 0x00080000u
#define WS_THICKFRAME 0x00040000u
#define WS_VSCROLL 0x00200000u
#define WS_HSCROLL 0x00100000u
#define WS_MINIMIZEBOX 0x00020000u
#define WS_MAXIMIZEBOX 0x00010000u
#define WS_EX_DLGMODALFRAME 0x1u
#define WS_EX_TOOLWINDOW 0x80u
#define WS_EX_WINDOWEDGE 0x100u
#define WS_EX_CLIENTEDGE 0x200u
#define WS_EX_STATICEDGE 0x20000u
/* GetWindowBorders, as Windows 2000's AdjustWindowRectEx counts them */
static int borders(uint32_t st, uint32_t ex) {
    int b = ex & WS_EX_WINDOWEDGE ? 2 : ex & WS_EX_STATICEDGE ? 1 : 0;
    if ((st & WS_CAPTION) || (ex & WS_EX_DLGMODALFRAME)) b++;
    if (st & WS_THICKFRAME) b++;
    if (ex & WS_EX_CLIENTEDGE) b += 2;
    return b;
}
static int caption_h(uint32_t st, uint32_t ex) {
    if ((st & WS_CAPTION) != WS_CAPTION) return 0;
    return ex & WS_EX_TOOLWINDOW ? SM(51) : SM(4);
}
static int menubar_h(uobj_t* u) { return u->menu && !(u->style & WS_CHILD) ? SM(15) : 0; }

/* ---- the WND, kept in step ------------------------------------------------ */
static void place(uobj_t* u) {                   /* screen rects from the relative ones */
    uobj_t* p = W(u->parent);
    int ox = p ? p->cr.l : 0, oy = p ? p->cr.t : 0;
    if (u->h == g_desktop) ox = oy = 0;
    u->wr = (rc_t){ u->wrel.l + ox, u->wrel.t + oy, u->wrel.r + ox, u->wrel.b + oy };
    u->cr = (rc_t){ u->wr.l + u->cin.l, u->wr.t + u->cin.t, u->wr.l + u->cin.r, u->wr.t + u->cin.b };
}
static void wnd_sync(uobj_t* u) {
    uint32_t w = u->obj;
    place(u);
    MEM32(w + WND_PSELF) = w;
    MEM32(w + WND_EXSTYLE) = u->ex, MEM32(w + WND_STYLE) = u->style, MEM32(w + WND_HMODULE) = u->inst;
    rc_put(w + WND_RCWINDOW, u->wr), rc_put(w + WND_RCCLIENT, u->cr);
    uobj_t* p = W(u->parent), *o = W(u->owner);
    MEM32(w + WND_PARENT) = p ? p->obj : 0;
    MEM32(w + WND_OWNER) = o ? o->obj : 0;
    if (u->style & WS_CHILD) MEM32(w + WND_MENU) = u->id;
    else { uobj_t* m = U(u->menu, W2K_TYPE_MENU); MEM32(w + WND_MENU) = m ? m->obj : 0; }
    /* children and siblings, in creation order */
    uint32_t first = 0, next = 0;
    for (int i = (int)(u->h & 0xFFFF) + 1; i < MAXU && !next; i++)
        if (g_u[i].type == W2K_TYPE_WINDOW && g_u[i].parent == u->parent) next = g_u[i].obj;
    for (int i = 2; i < MAXU && !first; i++)
        if (g_u[i].type == W2K_TYPE_WINDOW && g_u[i].parent == u->h && g_u[i].h != u->h) first = g_u[i].obj;
    MEM32(w + WND_CHILD) = first;
    MEM32(w + WND_NEXT) = u->h == g_desktop ? 0 : next;
    /* the text, a LARGE_UNICODE_STRING in the heap */
    int n = u16len_(u->text);
    if (!MEM32(w + WND_STRNAME + 8)) MEM32(w + WND_STRNAME + 8) = desk_alloc(256);
    memcpy((void*)(uintptr_t)MEM32(w + WND_STRNAME + 8), u->text, 2 * n + 2);
    MEM32(w + WND_STRNAME) = (uint32_t)(2 * n), MEM32(w + WND_STRNAME + 4) = 256;
}
static void sync_all(void) {
    for (int i = 1; i < MAXU; i++) if (g_u[i].type == W2K_TYPE_WINDOW) wnd_sync(&g_u[i]);
}
static int visible(uobj_t* u) {
    for (; u; u = W(u->parent)) if (!(u->style & WS_VISIBLE)) return 0;
    return 1;
}

/* ---- sending: win32k's callbacks into user32 ------------------------------ */
static uint32_t g_dcm;                            /* user32's DispatchClientMessage */
static uint32_t find_dcm(void) {
    /* in no export; PFNCLIENT (apfnClientA / apfnClientW, user32's data)
     * holds it at +0x24 from pfnDialogWndProc, the same in both */
    uint32_t u = ntp_module("user32.dll");
    if (!u) return 0;
    uint32_t da = ntp_export(u, "DefDlgProcA"), dw = ntp_export(u, "DefDlgProcW");
    uint32_t size = MEM32(u + MEM32(u + 0x3C) + 0x50);
    for (uint32_t o = 0x1000; o + 0x28 < size; o += 4)
        if (MEM32(u + o) == dw)
            for (uint32_t p = 0x1000; p + 0x28 < size; p += 4)
                if (MEM32(u + p) == da && MEM32(u + p + 0x24) == MEM32(u + o + 0x24)) return MEM32(u + o + 0x24);
    return 0;
}
static uint32_t defproc(uobj_t* u, uint32_t m, uint32_t w, uint32_t l);
static void batch_flush(void) { w2k_gdi_batch(MEM32(g_fs_base + 0x18), batch_cmd); }
static uint32_t call_proc(uobj_t* u, uint32_t pfn, uint32_t m, uint32_t w, uint32_t l) {
    uint32_t teb = MEM32(g_fs_base + 0x18), oh = MEM32(teb + TEB_CBWND), op = MEM32(teb + TEB_CBWND + 4), r = 0, o = 0, olen = 0, st;
    sync_all();
    MEM32(teb + TEB_CBWND) = u->h, MEM32(teb + TEB_CBWND + 4) = u->obj;
    if ((m == 1 || m == 0x81) && l) {           /* WM_CREATE / WM_NCCREATE: __fnINLPCREATESTRUCT */
        uint32_t msg[0x18] = { 0 };
        msg[0] = sizeof msg;
        msg[6] = u->obj, msg[7] = m, msg[8] = w, msg[9] = 1;
        memcpy(&msg[0x0A], (void*)(uintptr_t)l, 0x30);
        msg[0x16] = pfn, msg[0x17] = g_dcm;
        st = ntp_callback(W2K_CB_INLPCREATESTRUCT, (uint32_t)(uintptr_t)msg, sizeof msg, &o, &olen);
    } else {
        uint32_t msg[6] = { u->obj, m, w, l, pfn, g_dcm };
        st = ntp_callback(W2K_CB_DWORD, (uint32_t)(uintptr_t)msg, sizeof msg, &o, &olen);
    }
    if (st == 0 && o && olen >= 4) r = MEM32(o);
    else if (st) fprintf(stderr, "[user] callback for message 0x%X: status %08X\n", m, st);
    MEM32(teb + TEB_CBWND) = oh, MEM32(teb + TEB_CBWND + 4) = op;
    batch_flush();                                /* (as win32k's callback return does) */
    return r;
}
static uint32_t send(uint32_t h, uint32_t m, uint32_t w, uint32_t l) {
    uobj_t* u = W(h);
    if (!u) return 0;
    if (!g_dcm) g_dcm = find_dcm();
    uint32_t pfn = MEM32(u->obj + WND_PROC);
    TRACE("[user] send %08X msg %04X %08X %08X (proc %08X)\n", h, m, w, l, pfn);
    if (!pfn || !g_dcm) return defproc(u, m, w, l);
    return call_proc(u, pfn, m, w, l);
}
/* HWND_BROADCAST: the top-level windows, which here are all the guest's own (another
 * process's windows are in another runner) */
static void broadcast(uint32_t m, uint32_t w, uint32_t l, int posted);

/* ---- the queue, timers ---------------------------------------------------- */
typedef struct { uint32_t h, m, w, l, t; } qmsg_t;
#define QN 1024
static qmsg_t g_q[QN];
static int g_qh, g_qt, g_quit, g_quitcode;
static void post(uint32_t h, uint32_t m, uint32_t w, uint32_t l) {
    if ((g_qt + 1) % QN == g_qh) { fprintf(stderr, "[user] queue full\n"); return; }
    g_q[g_qt] = (qmsg_t){ h, m, w, l, ntp_clock_ms() };
    g_qt = (g_qt + 1) % QN;
}
typedef struct { uint32_t h, id, elapse, due, proc; int on; } timer_t_;
#define MAXT 32
static timer_t_ g_tm[MAXT];

/* ---- DCs for windows ------------------------------------------------------ */
/* z-order, the one case there is: a topmost window (SetWindowPos HWND_TOPMOST: the taskbar) stays
 * above the rest, so the others' DCs leave out the band it covers along an edge.
 * ponytail: one rectangle per DC, so only a topmost window spanning a whole edge is cut out;
 * real visible regions when overlapping windows have to clip each other */
static rc_t band_cut(rc_t r, rc_t z) {
    if (z.l <= r.l && z.r >= r.r) {
        if (z.t <= r.t && z.b > r.t) r.t = z.b;
        else if (z.b >= r.b && z.t < r.b) r.b = z.t;
    } else if (z.t <= r.t && z.b >= r.b) {
        if (z.l <= r.l && z.r > r.l) r.l = z.r;
        else if (z.r >= r.r && z.l < r.r) r.r = z.l;
    }
    return r;
}
static rc_t zclip(uobj_t* u, rc_t r) {
    /* WS_CLIPCHILDREN: a visible child spanning a whole edge of it (a status bar, a toolbar) is
     * left out, so the parent painting after the child (UpdateWindow painted the child first)
     * does not cover it. ponytail: the same one-rectangle band rule as the topmost case */
    if (u->style & 0x02000000u)
        for (int i = 2; i < MAXU; i++)
            if (g_u[i].type == W2K_TYPE_WINDOW && g_u[i].parent == u->h && visible(&g_u[i])) r = band_cut(r, g_u[i].wr);
    uobj_t* t = u;
    while (t && t->parent != g_desktop && W(t->parent)) t = W(t->parent);
    if (!t || (t->ex & 8)) return r;
    for (int i = 2; i < MAXU; i++) {
        uobj_t* w = &g_u[i];
        if (w->type != W2K_TYPE_WINDOW || w == t || w->parent != g_desktop || !(w->ex & 8) || !visible(w)) continue;
        r = band_cut(r, w->wr);
    }
    return r;
}
static gobj_t* window_dc(uobj_t* u, int whole) {
    gobj_t* d = dc_new(1);
    if (!d) return NULL;
    rc_t r = u ? (whole ? u->wr : u->cr) : (rc_t){ 0, 0, g_cx, g_cy };
    d->ox = r.l, d->oy = r.t;
    d->vis = d->clip = rc_and(u ? zclip(u, r) : r, (rc_t){ 0, 0, g_cx, g_cy });
    d->hwnd = u ? u->h : 0;
    return d;
}
static void dc_release(uint32_t h) { gobj_t* d = DCH(h); if (d && d->display) gfree(d); }

/* ---- drawing the non-client area (classic) -------------------------------- */
static void fill(gobj_t* d, rc_t r, uint32_t c) {
    bmp_t* b = dc_bm(d);
    r = rc_and(r, d->clip);
    for (int y = r.t; y < r.b; y++) for (int x = r.l; x < r.r; x++) b->px[(size_t)y * b->w + x] = c;
}
/* DrawEdge's raised edge: outer light/dark shadow, inner highlight/shadow */
static void edge(gobj_t* d, rc_t r, uint32_t tl1, uint32_t br1, uint32_t tl2, uint32_t br2) {
    fill(d, (rc_t){ r.l, r.t, r.r - 1, r.t + 1 }, tl1), fill(d, (rc_t){ r.l, r.t, r.l + 1, r.b - 1 }, tl1);
    fill(d, (rc_t){ r.l, r.b - 1, r.r, r.b }, br1), fill(d, (rc_t){ r.r - 1, r.t, r.r, r.b }, br1);
    r = (rc_t){ r.l + 1, r.t + 1, r.r - 1, r.b - 1 };
    fill(d, (rc_t){ r.l, r.t, r.r - 1, r.t + 1 }, tl2), fill(d, (rc_t){ r.l, r.t, r.l + 1, r.b - 1 }, tl2);
    fill(d, (rc_t){ r.l, r.b - 1, r.r, r.b }, br2), fill(d, (rc_t){ r.r - 1, r.t, r.r, r.b }, br2);
}
static const uint32_t* C = w2k_colors_2000;
static void draw_text(gobj_t* d, int x, int y, const uint16_t* s, uint32_t color, int bold, int amp) {
    fnt_t* F = g_nfnt ? &g_fnt[fnt_pick("MS Sans Serif", 13)] : NULL;
    if (!F) return;
    bmp_t* b = dc_bm(d);
    int ul = 0;
    for (; *s; s++) {
        int c = *s < 256 ? *s : '?';
        if (amp && c == '&' && s[1] != '&') { ul = 1; continue; }
        if (c < F->first || c > F->last) c = F->defch;
        const uint8_t* g = F->raw + F->off[c];
        int cw = F->w[c];
        for (int yy = 0; yy < F->h; yy++)
            for (int xx = 0; xx < cw + bold; xx++) {
                int on = xx < cw && (g[(xx >> 3) * F->h + yy] >> (7 - (xx & 7)) & 1);
                if (bold && !on && xx > 0) on = g[((xx - 1) >> 3) * F->h + yy] >> (7 - ((xx - 1) & 7)) & 1;
                if (ul && yy == F->ascent + 1 && xx < cw) on = 1;
                int X = x + xx, Y = y + yy;
                if (on && X >= d->clip.l && X < d->clip.r && Y >= d->clip.t && Y < d->clip.b) b->px[(size_t)Y * b->w + X] = color;
            }
        x += cw + bold;
        ul = 0;
    }
}
static int str_w(const uint16_t* s, int bold, int amp) {
    fnt_t* F = g_nfnt ? &g_fnt[fnt_pick("MS Sans Serif", 13)] : NULL;
    int w = 0;
    for (; F && *s; s++) { if (amp && *s == '&' && s[1] != '&') continue; w += fnt_cw(F, *s < 256 ? *s : '?') + bold; }
    return w;
}
/* the menu bar's items, laid out from the window's left (window coordinates) */
static void menubar_layout(uobj_t* u) {
    uobj_t* m = U(u->menu, W2K_TYPE_MENU);
    if (!m) return;
    int x = borders(u->style, u->ex);
    for (int i = 0; i < m->nitems; i++) {
        m->items[i].x = x;
        m->items[i].w = str_w(m->items[i].text, 0, 1) + 12;
        x += m->items[i].w;
    }
}
static void draw_icon(gobj_t* d, uobj_t* ic, int x, int y, int cx, int cy, uint32_t fl);
/* a scroll bar, Windows 2000's way: two arrow buttons, the track in the
 * 3D-highlight/face dither, the thumb when the range is more than a page
 * (arrows greyed when it is not) */
static void scrollbar(gobj_t* d, uobj_t* u, int v) {
    rc_t r = v ? (rc_t){ u->cr.r, u->cr.t, u->cr.r + SM(2), u->cr.b } : (rc_t){ u->cr.l, u->cr.b, u->cr.r, u->cr.b + SM(3) };
    int* i = u->sb[v], len = v ? r.b - r.t : r.r - r.l, a = v ? SM(2) : SM(3), range = i[1] - i[0] + 1;
    int on = range > (i[2] ? i[2] : 1) && i[1] > i[0];
    if (2 * a > len) a = len / 2;
    for (int y = r.t; y < r.b; y++)
        for (int x = r.l; x < r.r; x++) fill(d, (rc_t){ x, y, x + 1, y + 1 }, (x + y) & 1 ? C[15] : C[20]);
    for (int k = 0; k < 2; k++) {                 /* the arrows: up/left, down/right */
        rc_t b = v ? (rc_t){ r.l, k ? r.b - a : r.t, r.r, k ? r.b : r.t + a } : (rc_t){ k ? r.r - a : r.l, r.t, k ? r.r : r.l + a, r.b };
        fill(d, b, C[15]);
        edge(d, b, C[15], C[21], C[20], C[16]);
        int cx = (b.l + b.r) / 2, cy = (b.t + b.b) / 2;
        for (int g = on ? 0 : 1; g >= 0; g--)     /* (greyed: a white one under, one right and down) */
            for (int j = 0; j < 4; j++) {
                uint32_t c = on ? 0 : g ? C[20] : C[16];
                int o = g, w = 7 - 2 * j, t = k ? j : 3 - j;   /* rows of 7, 5, 3, 1 from the base */
                if (v) fill(d, (rc_t){ cx - 3 + j + o, cy - 2 + t + o, cx - 3 + j + w + o, cy - 1 + t + o }, c);
                else fill(d, (rc_t){ cx - 2 + t + o, cy - 3 + j + o, cx - 1 + t + o, cy - 3 + j + w + o }, c);
            }
    }
    if (!on) return;
    int track = len - 2 * a, page = i[2] ? i[2] : 1, th = track * page / range;
    if (th < 8) th = 8;
    if (th > track) return;
    int span = range - page, pos = span > 0 ? (i[3] - i[0]) * (track - th) / span : 0;
    rc_t t = v ? (rc_t){ r.l, r.t + a + pos, r.r, r.t + a + pos + th } : (rc_t){ r.l + a + pos, r.t, r.l + a + pos + th, r.b };
    fill(d, t, C[15]);
    edge(d, t, C[15], C[21], C[20], C[16]);
}
static void ncpaint(uobj_t* u) {
    if (!visible(u)) return;
    gobj_t* d = window_dc(u, 1);
    rc_t r = u->wr;
    int b = borders(u->style, u->ex), cap = caption_h(u->style, u->ex);
    if (u->ex & WS_EX_WINDOWEDGE) {
        edge(d, r, C[22], C[21], C[20], C[16]);
        for (int k = 2; k < b - (u->ex & WS_EX_CLIENTEDGE ? 2 : 0); k++) {   /* one ring per k (edge() draws two: */
            rc_t q = { r.l + k, r.t + k, r.r - k, r.b - k };                   /*  the last one fell in the client) */
            fill(d, (rc_t){ q.l, q.t, q.r, q.t + 1 }, C[15]), fill(d, (rc_t){ q.l, q.b - 1, q.r, q.b }, C[15]);
            fill(d, (rc_t){ q.l, q.t, q.l + 1, q.b }, C[15]), fill(d, (rc_t){ q.r - 1, q.t, q.r, q.b }, C[15]);
        }
    } else if (u->style & WS_BORDER) edge(d, r, C[6], C[6], C[6], C[6]);   /* (one pixel: only the outer ring is seen) */
    rc_t sc = u->cr;                              /* the client with its scroll bars */
    if (u->style & WS_VSCROLL) sc.r += SM(2);
    if (u->style & WS_HSCROLL) sc.b += SM(3);
    for (int v = 0; v < 2; v++) if (u->style & (v ? WS_VSCROLL : WS_HSCROLL)) scrollbar(d, u, v);
    if ((u->style & WS_VSCROLL) && (u->style & WS_HSCROLL)) fill(d, (rc_t){ u->cr.r, u->cr.b, sc.r, sc.b }, C[15]);
    if (u->ex & WS_EX_CLIENTEDGE) {
        rc_t c = sc;
        edge(d, (rc_t){ c.l - 2, c.t - 2, c.r + 2, c.b + 2 }, C[16], C[20], C[21], C[22]);
    }
    if (cap) {
        int act = u->h == g_active || !g_active;
        rc_t cr = { r.l + b, r.t + b, r.r - b, r.t + b + cap - 1 };
        uint32_t c1 = act ? C[2] : C[3], c2 = act ? C[27] : C[28];
        for (int x = cr.l; x < cr.r; x++) {
            int t = cr.r - cr.l > 1 ? (x - cr.l) * 256 / (cr.r - cr.l - 1) : 0;
            uint32_t c = 0;
            for (int k = 0; k < 24; k += 8) c |= (uint32_t)((((c1 >> k) & 0xFF) * (256 - t) + ((c2 >> k) & 0xFF) * t) >> 8) << k;
            fill(d, (rc_t){ x, cr.t, x + 1, cr.b }, c);
        }
        fill(d, (rc_t){ cr.l, cr.b, cr.r, cr.b + 1 }, C[15]);
        int tx = cr.l + 2;
        if (u->style & WS_SYSMENU) {
            cls_t* c = u->cls >= 0 ? &g_cls[u->cls] : NULL;
            uobj_t* ic = c ? U(c->iconsm ? c->iconsm : c->icon, W2K_TYPE_CURSOR) : NULL;
            if (ic) draw_icon(d, ic, cr.l + 2, cr.t + 1, 16, 16, 3);
            tx += 18;
        }
        draw_text(d, tx, cr.t + 2, u->text, act ? C[9] : C[19], 1, 0);
        if (u->style & WS_SYSMENU) {
            int bw = SM(30) - 2, bh = SM(31) - 4, x = cr.r - 2 - bw, y = cr.t + 2;
            for (int k = 0; k < 3; k++) {
                if (k == 1 && !(u->style & (WS_MINIMIZEBOX | WS_MAXIMIZEBOX))) break;
                rc_t br = { x, y, x + bw, y + bh };
                fill(d, br, C[15]);
                edge(d, br, C[22], C[21], C[20], C[16]);
                int cx = x + bw / 2, cy = y + bh / 2;
                uint32_t g = (k == 1 && !(u->style & WS_MAXIMIZEBOX)) || (k == 2 && !(u->style & WS_MINIMIZEBOX)) ? C[16] : 0;
                if (k == 0)
                    for (int i = 0; i < 7; i++)
                        fill(d, (rc_t){ cx - 4 + i, cy - 4 + i, cx - 2 + i, cy - 3 + i }, 0), fill(d, (rc_t){ cx + 2 - i, cy - 4 + i, cx + 4 - i, cy - 3 + i }, 0);
                else if (k == 1) {
                    if (g) fill(d, (rc_t){ cx - 3, cy - 3, cx + 6, cy + 5 }, C[20]);
                    fill(d, (rc_t){ cx - 4, cy - 4, cx + 5, cy - 2 }, g), fill(d, (rc_t){ cx - 4, cy - 4, cx - 3, cy + 4 }, g);
                    fill(d, (rc_t){ cx + 4, cy - 4, cx + 5, cy + 4 }, g), fill(d, (rc_t){ cx - 4, cy + 3, cx + 5, cy + 4 }, g);
                } else fill(d, (rc_t){ cx - 4, cy + 2, cx + 2, cy + 4 }, g);
                x -= bw + (k == 0 ? 2 : 0);
            }
        }
    }
    uobj_t* m = U(u->menu, W2K_TYPE_MENU);
    if (m && !(u->style & WS_CHILD)) {
        menubar_layout(u);
        int y = r.t + b + cap;
        fill(d, (rc_t){ r.l + b, y, r.r - b, y + SM(15) }, C[4]);
        for (int i = 0; i < m->nitems; i++)
            draw_text(d, r.l + m->items[i].x + 6, y + 3, m->items[i].text, m->items[i].state & 3 ? C[17] : C[7], 0, 1);
    }
    gfree(d);
}

/* A menu bar item's popup, dropped down (SC_KEYMENU): WM_INITMENU and
 * WM_INITMENUPOPUP first, then drawn on the screen below the item, the
 * item pushed in. ponytail: not tracked; it stays until the next click or
 * key, which closes it and repaints the window */
static rc_t g_popup;
static uint32_t g_popup_owner, g_popup_menu;      /* the window and the drop-down menu shown (for a live click in it) */
static int g_popup_bar, g_popup_sel = -1;         /* its bar item; the highlighted item (arrows, the mouse) */
static int g_popup_next = -1;                     /* left/right: the bar item to drop down once the old one is painted over */
static void invalidate(uobj_t* u, int erase);
static void popup_draw(uobj_t* u, int k) {
    uobj_t* m = U(u->menu, W2K_TYPE_MENU), *p;
    if (!m || k < 0 || k >= m->nitems || !(p = U(m->items[k].sub, W2K_TYPE_MENU))) return;
    if (rc_empty(&g_popup) || g_popup_owner != u->h || g_popup_bar != k) {
        send(u->h, 0x116, m->h, 0);                                   /* WM_INITMENU */
        send(u->h, 0x117, p->h, (uint32_t)k);                         /* WM_INITMENUPOPUP */
        if (g_popup_bar != k || g_popup_owner != u->h) g_popup_sel = -1;
    }
    menubar_layout(u);
    gobj_t* d = window_dc(NULL, 0);
    int bx = u->wr.l + m->items[k].x, by = u->wr.t + borders(u->style, u->ex) + caption_h(u->style, u->ex);
    /* the bar item, pushed */
    edge(d, (rc_t){ bx, by + 1, bx + m->items[k].w, by + SM(15) - 1 }, C[16], C[20], C[4], C[4]);
    /* the popup: items 17 high (separators 9), text after the check column, accelerators right */
    int w = 0, h = 6, tabw = 0;
    for (int i = 0; i < p->nitems; i++) {
        uint16_t t[64], *tab;
        u16cpy(t, p->items[i].text, 64);
        for (tab = t; *tab && *tab != 9; tab++) ;
        int has = *tab == 9;
        *tab = 0;
        if (str_w(t, 0, 1) > w) w = str_w(t, 0, 1);
        if (has && str_w(tab + 1, 0, 1) > tabw) tabw = str_w(tab + 1, 0, 1);
        h += p->items[i].type & 0x800 ? 9 : 17;                       /* MFT_SEPARATOR */
    }
    w += 6 + 17 + 17 + (tabw ? tabw + 12 : 0);
    rc_t r = { bx, by + SM(15), bx + w, by + SM(15) + h };
    fill(d, r, C[4]);
    edge(d, r, C[22], C[21], C[20], C[16]);
    int y = r.t + 3;
    for (int i = 0; i < p->nitems; i++) {
        item_t* it = &p->items[i];
        if (it->type & 0x800) { fill(d, (rc_t){ r.l + 3, y + 3, r.r - 3, y + 4 }, C[16]); fill(d, (rc_t){ r.l + 3, y + 4, r.r - 3, y + 5 }, C[20]); y += 9; continue; }
        uint16_t t[64], *tab;
        u16cpy(t, it->text, 64);
        for (tab = t; *tab && *tab != 9; tab++) ;
        int has = *tab == 9;
        *tab = 0;
        uint32_t col = it->state & 3 ? C[17] : C[7];
        if (i == g_popup_sel) {                                       /* highlighted: COLOR_HIGHLIGHT, its text */
            fill(d, (rc_t){ r.l + 3, y, r.r - 3, y + 17 }, C[13]);
            if (!(it->state & 3)) col = C[14];
        }
        if (it->state & 8)                                            /* MFS_CHECKED: a check mark */
            for (int j = 0; j < 7; j++) {
                int cx = r.l + 7 + j, cy = y + 9 + (j < 3 ? j : 4 - j) - 1;
                fill(d, (rc_t){ cx, cy - 1, cx + 1, cy + 2 }, col);
            }
        draw_text(d, r.l + 3 + 17, y + 2, t, col, 0, 1);
        if (has) draw_text(d, r.r - 3 - 17 - str_w(tab + 1, 0, 1), y + 2, tab + 1, col, 0, 1);
        y += 17;
    }
    gfree(d);
    g_popup = r, g_popup_owner = u->h, g_popup_menu = p->h, g_popup_bar = k;
}
/* the keys while a menu is down: arrows move, Enter chooses, Esc closes (1: taken) */
static void popup_close(void);
static int popup_key(uint32_t vk) {
    uobj_t* u = W(g_popup_owner), *p = U(g_popup_menu, W2K_TYPE_MENU), *m = u ? U(u->menu, W2K_TYPE_MENU) : NULL;
    if (!u || !p || !m) return 0;
    if (vk == 37 || vk == 39) {                                       /* left, right: the next bar item's menu */
        int k = (g_popup_bar + (vk == 39 ? 1 : m->nitems - 1)) % m->nitems;
        popup_close(), g_popup_next = k;
        return 1;
    }
    if (vk == 38 || vk == 40) {                                       /* up, down: skipping separators */
        for (int n = 0, i = g_popup_sel; n < p->nitems; n++) {
            i = vk == 40 ? (i + 1) % p->nitems : (i <= 0 ? p->nitems : i) - 1;
            if (!(p->items[i].type & 0x800)) { g_popup_sel = i; break; }
        }
        popup_draw(u, g_popup_bar);
        return 1;
    }
    if (vk == 13) {
        item_t* it = g_popup_sel >= 0 && g_popup_sel < p->nitems ? &p->items[g_popup_sel] : NULL;
        uint32_t owner = g_popup_owner;
        popup_close();
        if (it && !(it->state & 3) && !it->sub) post(owner, 0x111, it->id, 0);
        return 1;
    }
    if (vk == 27) { popup_close(); return 1; }
    for (int i = 0; i < p->nitems; i++)                               /* a mnemonic in the menu */
        for (uint16_t* t = p->items[i].text; *t && !(p->items[i].state & 3); t++)
            if (*t == '&' && t[1] && (t[1] | 0x20) == (vk | 0x20) && vk >= 'A' && vk <= 'Z') {
                uint32_t owner = g_popup_owner, id = p->items[i].id;
                popup_close();
                if (!p->items[i].sub) post(owner, 0x111, id, 0);
                return 1;
            }
    return 1;                                                         /* (other keys: swallowed while the menu is down) */
}
static void popup_close(void) {
    if (rc_empty(&g_popup)) return;
    g_popup = (rc_t){ 0, 0, 0, 0 }, g_popup_sel = -1;
    for (int i = 2; i < MAXU; i++) if (g_u[i].type == W2K_TYPE_WINDOW && visible(&g_u[i])) invalidate(&g_u[i], 1);
}
static void keymenu(uobj_t* u, uint32_t ch) {
    uobj_t* m = U(u->menu, W2K_TYPE_MENU);
    if (!m) return;
    for (int i = 0; i < m->nitems; i++)
        for (uint16_t* t = m->items[i].text; *t; t++)
            if (*t == '&' && t[1] && (t[1] | 0x20) == (ch | 0x20)) { popup_draw(u, i); return; }
    if (!ch) popup_draw(u, 0);
}

/* ---- window operations ---------------------------------------------------- */
/* WND +0x64, hrgnUpdate: user32's GetUpdateRect/GetUpdateRgn answer "nothing to paint"
 * client-side when it is NULL (comctl32's list view then skips its WM_PAINT). A dirty window
 * holds win32k's HRGN_FULL (1), the whole window */
#define WND_HRGNUPDATE 0x64
static void set_dirty(uobj_t* u, int d) { u->dirty = d; MEM32(u->obj + WND_HRGNUPDATE) = d ? 1u : 0u; }
static void invalidate(uobj_t* u, int erase) {
    set_dirty(u, 1), u->ncdirty = 1;
    u->erase |= erase;
    for (int i = 2; i < MAXU; i++)
        if (g_u[i].type == W2K_TYPE_WINDOW && g_u[i].parent == u->h) invalidate(&g_u[i], erase);
}
static void calcsize(uobj_t* u) {                /* WM_NCCALCSIZE(FALSE, the window rect) */
    uint32_t rr[4];
    rc_t w = u->wrel;
    rr[0] = (uint32_t)w.l, rr[1] = (uint32_t)w.t, rr[2] = (uint32_t)w.r, rr[3] = (uint32_t)w.b;
    send(u->h, 0x83, 0, (uint32_t)(uintptr_t)rr);
    rc_t c = rc_get((uint32_t)(uintptr_t)rr);
    if (c.r < c.l) c.r = c.l;
    if (c.b < c.t) c.b = c.t;
    u->cin = (rc_t){ c.l - w.l, c.t - w.t, c.r - w.l, c.b - w.t };
}
#define SWP_NOSIZE 1
#define SWP_NOMOVE 2
#define SWP_NOREDRAW 8
#define SWP_FRAMECHANGED 0x20
#define SWP_SHOWWINDOW 0x40
#define SWP_HIDEWINDOW 0x80
static int setpos(uobj_t* u, int x, int y, int cx, int cy, uint32_t fl) {
    uint32_t wp[7] = { u->h, 0, (uint32_t)x, (uint32_t)y, (uint32_t)cx, (uint32_t)cy, fl };
    if (fl & SWP_NOMOVE) wp[2] = (uint32_t)u->wrel.l, wp[3] = (uint32_t)u->wrel.t;
    if (fl & SWP_NOSIZE) wp[4] = (uint32_t)(u->wrel.r - u->wrel.l), wp[5] = (uint32_t)(u->wrel.b - u->wrel.t);
    send(u->h, 0x46, 0, (uint32_t)(uintptr_t)wp);                     /* WM_WINDOWPOSCHANGING */
    rc_t old = u->wrel;
    u->wrel = (rc_t){ (int)wp[2], (int)wp[3], (int)wp[2] + (int)wp[4], (int)wp[3] + (int)wp[5] };
    int moved = old.l != u->wrel.l || old.t != u->wrel.t, sized = old.r - old.l != u->wrel.r - u->wrel.l || old.b - old.t != u->wrel.b - u->wrel.t;
    if (fl & SWP_SHOWWINDOW) u->style |= WS_VISIBLE;
    if ((fl & SWP_SHOWWINDOW) && u->parent == g_desktop && W(g_main) && !(W(g_main)->style & WS_VISIBLE)) g_main = u->h;
    if (fl & SWP_HIDEWINDOW) u->style &= ~WS_VISIBLE;
    if (sized || moved || (fl & SWP_FRAMECHANGED)) calcsize(u);
    wnd_sync(u);
    if (!(fl & SWP_NOREDRAW) && (sized || moved || (fl & (SWP_FRAMECHANGED | SWP_SHOWWINDOW)))) invalidate(u, 1);
    if (!moved) wp[6] |= SWP_NOMOVE;
    if (!sized) wp[6] |= SWP_NOSIZE;
    send(u->h, 0x47, 0, (uint32_t)(uintptr_t)wp);                     /* WM_WINDOWPOSCHANGED */
    return 1;
}
static void activate(uobj_t* u) {
    if (g_active == u->h) return;
    uint32_t old = g_active;
    g_active = u->h;
    TRACE("[user] activate %08X (style %08X), was %08X\n", u->h, u->style, old);
    if (W(old)) { send(old, 0x86, 0, 0); send(old, 6, 0, u->h); }
    send(u->h, 0x86, 1, 0);                                           /* WM_NCACTIVATE */
    send(u->h, 6, 1, old);                                            /* WM_ACTIVATE WA_ACTIVE */
    if (g_active == u->h && (!g_focus || !W(g_focus))) {
        g_focus = u->h;
        send(u->h, 7, 0, 0);                                          /* WM_SETFOCUS */
    }
}
static uint32_t show(uobj_t* u, int cmd) {
    int was = (u->style & WS_VISIBLE) != 0;
    if (!cmd) {
        if (!was) return 0;
        send(u->h, 0x18, 0, 0);                                       /* WM_SHOWWINDOW FALSE */
        setpos(u, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_HIDEWINDOW);
        return 1;
    }
    if (!was) {
        send(u->h, 0x18, 1, 0);
        setpos(u, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
        if (u->sizemove && W(u->h)) {
            u->sizemove = 0;
            send(u->h, 5, 0, (uint32_t)((u->cr.b - u->cr.t) << 16 | ((u->cr.r - u->cr.l) & 0xFFFF)));   /* WM_SIZE */
            send(u->h, 3, 0, (uint32_t)((u->cin.t + u->wrel.t) << 16 | ((u->cin.l + u->wrel.l) & 0xFFFF)));   /* WM_MOVE */
        }
    }
    if (!(u->style & WS_CHILD) && cmd != 4 && cmd != 7 && cmd != 8) activate(u);
    return (uint32_t)was;
}
static void destroy(uobj_t* u) {
    uint32_t h = u->h;
    send(h, 2, 0, 0);                                                 /* WM_DESTROY */
    for (int i = 2; i < MAXU; i++)
        if (g_u[i].type == W2K_TYPE_WINDOW && (g_u[i].parent == h || g_u[i].owner == h)) destroy(&g_u[i]);
    if (!W(h)) return;
    send(h, 0x82, 0, 0);                                              /* WM_NCDESTROY */
    if (g_focus == h) g_focus = 0;
    if (g_capture == h) g_capture = 0;
    if (g_active == h) g_active = 0;
    for (int i = 0; i < MAXT; i++) if (g_tm[i].h == h) g_tm[i].on = 0;
    ufree(u);
    sync_all();
}

/* ---- DefWindowProc's server half ------------------------------------------ */
static uint32_t erase_bk(uobj_t* u, uint32_t hdc) {
    gobj_t* d = DCH(hdc);
    cls_t* c = u->cls >= 0 ? &g_cls[u->cls] : NULL;
    if (!d || !c || !c->bg) return 0;
    uint32_t br = c->bg <= 0x1D ? g_sysbrush[c->bg - 1] : c->bg;
    if (!G(br, GDI_BRUSH)) return 0;
    rc_t r = u->cr;
    r.r -= r.l, r.b -= r.t, r.l = r.t = 0;
    patblt(d, dc_rect(d, r.l, r.t, r.r, r.b), 0xF00021, br);
    return 1;
}
static uint32_t paint_dc(uobj_t* u, uint32_t ps);
static uint32_t defproc(uobj_t* u, uint32_t m, uint32_t w, uint32_t l) {
    switch (m) {
    case 0x81:                                                       /* WM_NCCREATE */
        if (l && MEM32(l + 0x24)) {
            uint32_t s = MEM32(l + 0x24);
            if (s >= 0x10000) u16cpy(u->text, (const uint16_t*)(uintptr_t)s, 128);
        }
        return 1;
    case 0x83: {                                                     /* WM_NCCALCSIZE */
        rc_t r = rc_get(l);
        int b = borders(u->style, u->ex), cap = caption_h(u->style, u->ex), mb = menubar_h(u);
        r.l += b, r.t += b + cap + mb, r.r -= b, r.b -= b;
        if (u->style & WS_VSCROLL) r.r -= SM(2);
        if (u->style & WS_HSCROLL) r.b -= SM(3);
        rc_put(l, r);
        return 0;
    }
    case 0x85: ncpaint(u); return 0;                                 /* WM_NCPAINT */
    case 0x86: u->ncdirty = 1; return 1;                             /* WM_NCACTIVATE */
    case 0x14: return erase_bk(u, w);                                /* WM_ERASEBKGND */
    case 0x0F: {                                                     /* WM_PAINT */
        uint32_t ps[16];
        uint32_t dc = paint_dc(u, (uint32_t)(uintptr_t)ps);
        dc_release(dc);
        return 0;
    }
    case 0x0C:                                                       /* WM_SETTEXT */
        if (l) u16cpy(u->text, (const uint16_t*)(uintptr_t)l, 128); else u->text[0] = 0;
        wnd_sync(u);
        u->ncdirty = 1;
        return 1;
    case 0x0D: {                                                     /* WM_GETTEXT */
        int n = u16len_(u->text);
        if (!w || !l) return 0;
        if (n > (int)w - 1) n = (int)w - 1;
        memcpy((void*)(uintptr_t)l, u->text, 2 * n);
        MEM16(l + 2 * n) = 0;
        return (uint32_t)n;
    }
    case 0x0E: return (uint32_t)u16len_(u->text);                    /* WM_GETTEXTLENGTH */
    case 0x47: {                                                     /* WM_WINDOWPOSCHANGED */
        /* a window still owing its first WM_SIZE/WM_MOVE (win32k's WFSENDSIZEMOVE) gets them
         * here once it is visible, even from a SWP_NOSIZE|SWP_NOMOVE show (SetWindowPos
         * SWP_SHOWWINDOW: the desktop's DefView, whose WM_SIZE sizes its list view) */
        uint32_t fl = MEM32(l + 24);
        if (u->sizemove && (u->style & WS_VISIBLE)) u->sizemove = 0, fl &= ~(uint32_t)(SWP_NOSIZE | SWP_NOMOVE);
        if (!(fl & SWP_NOMOVE)) send(u->h, 3, 0, (uint32_t)((u->cr.t - (W(u->parent) ? W(u->parent)->cr.t : 0)) << 16 |
                                                           ((u->cr.l - (W(u->parent) ? W(u->parent)->cr.l : 0)) & 0xFFFF)));
        if (!(fl & (SWP_NOSIZE | SWP_NOMOVE))) u->sizemove = 0;
        if (!(fl & SWP_NOSIZE)) send(u->h, 5, 0, (uint32_t)((u->cr.b - u->cr.t) << 16 | ((u->cr.r - u->cr.l) & 0xFFFF)));
        return 0;
    }
    case 0x55: return l == 3 ? (u->ansi ? 1u : 2u) : 0;             /* WM_NOTIFYFORMAT NF_QUERY: NFR_ANSI / NFR_UNICODE */
    case 0x10: destroy(u); return 0;                                 /* WM_CLOSE */
    case 0x112:                                                      /* WM_SYSCOMMAND */
        if ((w & 0xFFF0) == 0xF060) send(u->h, 0x10, 0, 0);          /* SC_CLOSE */
        if ((w & 0xFFF0) == 0xF100) keymenu(u, l);                   /* SC_KEYMENU: the menu of that letter */
        return 0;
    case 0x84: {                                                     /* WM_NCHITTEST */
        int x = (int16_t)(l & 0xFFFF), y = (int16_t)(l >> 16);
        if (x >= u->cr.l && x < u->cr.r && y >= u->cr.t && y < u->cr.b) return 1;   /* HTCLIENT */
        if (y >= u->cr.t - menubar_h(u) && y < u->cr.t) return 5;    /* HTMENU */
        if (y >= u->wr.t && y < u->cr.t) return 2;                   /* HTCAPTION */
        return 0;
    }
    case 0x21: return 1;                                             /* WM_MOUSEACTIVATE: MA_ACTIVATE */
    case 0x20: return 0;                                             /* WM_SETCURSOR */
    case 0x06: if (w & 0xFFFF) { g_focus = u->h; } return 0;         /* WM_ACTIVATE */
    case 0x31: return g_stock[17];                                   /* WM_GETFONT: none set, DEFAULT_GUI_FONT */
    case 0x132: case 0x133: case 0x134: case 0x135: case 0x136: case 0x137: case 0x138: {   /* WM_CTLCOLOR* */
        gobj_t* d = DCH(w);
        int win = m == 0x133 || m == 0x134;                          /* edit, list box: COLOR_WINDOW */
        if (d) AT(d, DCA_TEXTCOLOR) = AT(d, 0x18) = C[win ? 8 : 18], AT(d, DCA_BKCOLOR) = AT(d, 0x10) = C[win ? 5 : 15];
        return g_sysbrush[win ? 5 : 15];
    }
    }
    return 0;
}

static uint32_t paint_dc(uobj_t* u, uint32_t ps) {
    if (u->ncdirty) { u->ncdirty = 0; send(u->h, 0x85, 1, 0); }    /* WM_NCPAINT */
    gobj_t* d = window_dc(u, 0);
    if (!d) return 0;
    int erased = 0;
    if (u->erase) { u->erase = 0; erased = send(u->h, 0x14, d->h, 0) != 0; }
    set_dirty(u, 0);
    if (ps) {
        memset((void*)(uintptr_t)ps, 0, 64);
        MEM32(ps) = d->h, MEM32(ps + 4) = !erased;
        rc_put(ps + 8, (rc_t){ 0, 0, u->cr.r - u->cr.l, u->cr.b - u->cr.t });
    }
    return d->h;
}

/* ---- menus ------------------------------------------------------------------ */
static void menu_sync(uobj_t* m) {
    uint32_t o = m->obj;
    /* the 64 ITEMs, then each one's text (ITEM +0x18 lpstr, +0x1C cch: user32's GetMenuItemInfo and
     * GetMenuString read them client-side; the Start menu's band takes its items so) */
    if (!MEM32(o + MENU_RGITEMS)) MEM32(o + MENU_RGITEMS) = desk_alloc(64 * (ITEM_SIZE + 128));
    MEM32(o + MENU_PSELF) = o;
    MEM32(o + MENU_CITEMS) = (uint32_t)m->nitems;
    for (int i = 0; i < m->nitems && i < 64; i++) {
        uint32_t it = MEM32(o + MENU_RGITEMS) + i * ITEM_SIZE;
        uobj_t* s = U(m->items[i].sub, W2K_TYPE_MENU);
        memset((void*)(uintptr_t)it, 0, ITEM_SIZE);
        MEM32(it) = m->items[i].type, MEM32(it + 4) = m->items[i].state, MEM32(it + 8) = m->items[i].id;
        MEM32(it + 0xC) = s ? s->obj : 0;
        uint32_t t = MEM32(o + MENU_RGITEMS) + 64 * ITEM_SIZE + i * 128;
        int n = u16len_(m->items[i].text);
        memcpy((void*)(uintptr_t)t, m->items[i].text, 2 * n + 2);
        if (n) MEM32(it + 0x18) = t, MEM32(it + 0x1C) = (uint32_t)n;
        MEM32(it + 0x20) = m->items[i].data, MEM32(it + 0x40) = m->items[i].bmp;
    }
}
static item_t* menu_item(uobj_t* m, uint32_t item, int bypos, uobj_t** owner) {
    if (!m) return NULL;
    if (bypos) { if (owner) *owner = m; return item < (uint32_t)m->nitems ? &m->items[item] : NULL; }
    for (int i = 0; i < m->nitems; i++) {
        if (m->items[i].id == item && !m->items[i].sub) { if (owner) *owner = m; return &m->items[i]; }
        item_t* r = menu_item(U(m->items[i].sub, W2K_TYPE_MENU), item, 0, owner);
        if (r) return r;
    }
    return NULL;
}

/* ---- icons ------------------------------------------------------------------ */
/* DrawIconEx's DI_MASK (1): the AND mask copied; DI_IMAGE (2): the image copied; DI_NORMAL (3):
 * the two combined (comctl32's image lists take an icon's mask and image apart so) */
static void draw_icon(gobj_t* d, uobj_t* ic, int x, int y, int cx, int cy, uint32_t fl) {
    bmp_t* m = bm_of(ic->mask), *c = bm_of(ic->color), *b = dc_bm(d);
    if (!m) return;
    /* NT keeps the mask twice the icon's height for a colour icon too (the AND mask on top) */
    int iw = c ? c->w : m->w, ih = c ? (m->h >= 2 * c->h ? c->h : m->h) : m->h / 2;
    if (!cx) cx = iw;
    if (!cy) cy = ih;
    for (int j = 0; j < cy; j++)
        for (int i = 0; i < cx; i++) {
            int X = x + i, Y = y + j, sx = i * iw / cx, sy = j * ih / cy;
            if (X < d->clip.l || X >= d->clip.r || Y < d->clip.t || Y >= d->clip.b) continue;
            /* each read inside its own bitmap (a colour bitmap smaller than the mask, a DC clip
             * larger than the DC's bitmap: the live-mode fault read past a pixel buffer) */
            if (X < 0 || Y < 0 || X >= b->w || Y >= b->h || sx >= m->w || (c ? sy >= m->h || sx >= c->w || sy >= c->h : sy + ih >= m->h)) continue;
            uint32_t* p = &b->px[(size_t)Y * b->w + X];
            uint32_t a = m->px[(size_t)sy * m->w + sx], xo = c ? c->px[(size_t)sy * c->w + sx] : m->px[(size_t)(sy + ih) * m->w + sx];
            uint32_t v = fl == 1 ? a : fl == 2 ? xo : (*p & a) ^ xo;
            *p = (b->mono ? lum_mono(v) : v) & 0xFFFFFF;
        }
}

/* ======================================================================
 * USER services
 * ====================================================================== */
#define UNI(p) ((const uint16_t*)(uintptr_t)(p))
/* NtUserRegisterClassExWOW(WNDCLASSEXW*, UNICODE_STRING* class, CLSMENUNAME*, fnid, flags, wow*) */
static uint32_t s_register_class(uint32_t* a) {
    uint32_t wc = a[0], name = MEM32(a[1] + 4);
    if (g_ncls >= MAXC) return 0;
    if (name >= 0x10000 && MEM16(a[1]) == 0) name = 0;
    int i = name ? cls_find(name) : -1;
    if (i >= 0 && g_cls[i].inst == MEM32(wc + 0x14)) { TRACE("[user] class registered twice\n"); return 0; }
    cls_t* c = &g_cls[g_ncls];
    memset(c, 0, sizeof *c);
    if (name < 0x10000) c->atom = (uint16_t)name;
    else { u16cpy(c->name, UNI(name), 64); c->atom = g_atom++; }
    c->ansi = (a[4] & 2) != 0;
    c->fnid = (uint16_t)a[3], c->style = MEM32(wc + 4), c->proc = MEM32(wc + 8), c->extra = MEM32(wc + 0x10);
    c->inst = MEM32(wc + 0x14), c->icon = MEM32(wc + 0x18), c->bg = MEM32(wc + 0x20), c->iconsm = MEM32(wc + 0x2C);
    c->menu = a[2] ? MEM32(a[2] + 4) : 0;
    c->cls = desk_alloc(0x80);
    /* a window procedure the lifter never saw (only data points at it): said
     * the way a missed indirect call is, for seed_from_log.py */
    if (c->proc && !recomp_lookup(c->proc) && !recomp_lookup_manual(c->proc))
        fprintf(stderr, "ICALL: unresolved VA 0x%08X from 0x%08X (a class's window procedure)\n", c->proc, MEM32(g_esp));
    static const char* sys[] = { "Button", "Edit", "Static", "ListBox", "ScrollBar", "ComboBox", "MDIClient", "ComboLBox" };   /* ICLS_ order */
    for (int k = 0; k < 8; k++) {
        uint16_t s[16];
        a2u(s, sys[k], 16);
        if (name >= 0x10000 && !u16icmp(c->name, s)) MEM16(g_psi + SI_ATOMSYSCLASS + 2 * k) = c->atom;
    }
    g_ncls++;
    return c->atom;
}
/* NtUserGetClassInfo(hInstance, UNICODE_STRING* class, WNDCLASSEXW*, LPWSTR* menu, bAnsi) */
static uint32_t s_classinfo(uint32_t* a) {
    uint32_t name = MEM32(a[1] + 4);
    int i = cls_find(name);
    if (i < 0) return 0;
    cls_t* c = &g_cls[i];
    uint32_t w = a[2];
    MEM32(w + 4) = c->style, MEM32(w + 8) = c->proc, MEM32(w + 0xC) = 0, MEM32(w + 0x10) = c->extra;
    MEM32(w + 0x14) = c->inst, MEM32(w + 0x18) = c->icon, MEM32(w + 0x1C) = 0, MEM32(w + 0x20) = c->bg;
    MEM32(w + 0x24) = c->menu, MEM32(w + 0x2C) = c->iconsm;
    if (a[3]) MEM32(a[3]) = c->menu;
    return c->atom;
}

/* NtUserCreateWindowEx(exstyle, LARGE_STRING* class, LARGE_STRING* name,
 * style, x, y, cx, cy, parent, menu, hInstance, lpParam, flags) */
#define CW_USEDEFAULT 0x80000000u
static uint32_t s_create_window(uint32_t* a) {
    uint16_t cn[64], wn[128];
    uint32_t cname = lstr(a[1], cn, 64), wname = a[2] ? lstr(a[2], wn, 128) : 0;
    int ci = cls_find(cname);
    if (g_trace) {
        char b[64] = "#atom";
        if (cname >= 0x10000) { int i = 0; for (const uint16_t* p = UNI(cname); i < 63 && p[i]; i++) b[i] = (char)p[i]; b[i] = 0; }
        else snprintf(b, sizeof b, "#%X", cname);
        char t[80] = ""; int i = 0;
        if (wname >= 0x10000) for (const uint16_t* p = UNI(wname); i < 79 && p[i]; i++) t[i] = p[i] < 0x80 ? (char)p[i] : '?';
        t[i] = 0;
        fprintf(stderr, "[user] CreateWindowEx %s \"%s\" style %08X ex %08X at %d,%d %dx%d parent %X menu %X\n", b, t, a[3], a[0],
                (int)a[4], (int)a[5], (int)a[6], (int)a[7], a[8], a[9]);
    }
    if (ci < 0) {
        fprintf(stderr, "[user] CreateWindowEx: no class %s\n", cname < 0x10000 ? "(atom)" : "(name)");
        return 0;
    }
    uint32_t st = a[3], ex = a[0] & ~0x80000000u;              /* (WS_EX_ANSICREATOR is CreateWindowExA's mark) */
    if ((ex & WS_EX_DLGMODALFRAME) || (!(ex & WS_EX_STATICEDGE) && (st & (WS_DLGFRAME | WS_THICKFRAME)))) ex |= WS_EX_WINDOWEDGE;
    else ex &= ~WS_EX_WINDOWEDGE;
    uobj_t* parent = W(a[8]);
    if ((st & WS_CHILD) && !parent) { fprintf(stderr, "[user] CreateWindowEx: a child with no parent\n"); return 0; }
    uobj_t* u = unew(W2K_TYPE_WINDOW, WND_SIZE);
    if (!u) return 0;
    cls_t* c = &g_cls[ci];
    u->cls = ci, u->style = st & ~WS_VISIBLE, u->ex = ex, u->inst = a[10];
    if (st & WS_CHILD) u->parent = parent->h, u->id = a[9];
    else {
        u->parent = g_desktop, u->owner = parent ? parent->h : 0, u->menu = a[9];
        if (!u->menu && c->menu) {                             /* the class menu: __ClientLoadMenu(hinst, name) */
            uint32_t msg[9] = { sizeof msg, 0, 0, 0, 0, 0, a[10] ? a[10] : c->inst, 0, c->menu }, o = 0, olen = 0;
            if (!ntp_callback(W2K_CB_LOADMENU, (uint32_t)(uintptr_t)msg, sizeof msg, &o, &olen) && o && olen >= 4) u->menu = MEM32(o);
        }
    }
    if (wname >= 0x10000) u16cpy(u->text, UNI(wname), 128);
    int x = (int)a[4], y = (int)a[5], cx = (int)a[6], cy = (int)a[7];
    if (!(st & WS_CHILD)) {
        static int k;
        if ((uint32_t)x == CW_USEDEFAULT && !y) st &= ~WS_VISIBLE, u->style &= ~WS_VISIBLE;   /* y is the show command: SW_HIDE */
        if ((uint32_t)x == CW_USEDEFAULT || x == 0x8000) { x = y = 22 * (k % 8) + 22; k++; }   /* (0x8000: win32k's CW2_USEDEFAULT, dialogs') */
        if ((uint32_t)cx == CW_USEDEFAULT) cx = g_cx * 3 / 4, cy = g_cy * 3 / 4;
    } else {
        if ((uint32_t)x == CW_USEDEFAULT) x = y = 0;
        if ((uint32_t)cx == CW_USEDEFAULT) cx = cy = 0;
    }
    u->wrel = (rc_t){ x, y, x + cx, y + cy };
    MEM32(u->obj + WND_PROC) = c->proc;
    u->ansi = c->ansi;
    MEM32(u->obj + WND_PCLS) = c->cls;
    MEM32(u->obj + WND_CBEXTRA) = c->extra;
    if (c->fnid) MEM16(u->obj + WND_FNID) = 0;                  /* (user32 sets it with NtUserSetWindowFNID) */
    if (!(st & WS_CHILD) && (!W(g_main) || !(W(g_main)->style & WS_VISIBLE))) g_main = u->h;   /* the first top-level window shown */
    wnd_sync(u);
    /* CREATESTRUCTW */
    uint32_t cs[12] = { a[11], a[10], a[9], a[8], (uint32_t)cy, (uint32_t)cx, (uint32_t)y, (uint32_t)x, st, wname, cname, ex };
    if ((st & WS_THICKFRAME) || !(st & (WS_CHILD | 0x80000000u))) {   /* WM_GETMINMAXINFO */
        uint32_t mm[10] = { 0, 0, (uint32_t)SM(61), (uint32_t)SM(62), (uint32_t)-SM(32), (uint32_t)-SM(33), (uint32_t)SM(34), (uint32_t)SM(35),
                            (uint32_t)SM(59), (uint32_t)SM(60) };
        send(u->h, 0x24, 0, (uint32_t)(uintptr_t)mm);
    }
    uint32_t h = u->h;
    if (g_cbt) {                                  /* HCBT_CREATEWND(hwnd, CBT_CREATEWND { lpcs, hwndInsertAfter }) */
        uint32_t cbt[2] = { (uint32_t)(uintptr_t)cs, 0 }, ha[3] = { 3, h, (uint32_t)(uintptr_t)cbt };
        /* CallNextHookEx reads CLIENTINFO's phkCurrent (TEB +0x6EC, less the
         * client delta at +0x6E8): a HOOK with no next (+0x14) and flag 1 (+0x20)
         * makes it return 0 */
        static uint32_t hk;
        if (!hk) hk = ntp_alloc(0x40), MEM8(hk + 0x20) = 1;
        uint32_t teb = MEM32(g_fs_base + 0x18), svk = MEM32(teb + 0x6EC), svc = MEM32(teb + 0x6FC);
        MEM32(teb + 0x6EC) = hk + MEM32(teb + 0x6E8), MEM32(teb + 0x6FC) = 5u << 16;
        uint32_t r = ntp_guest(g_cbt, 3, ha);
        MEM32(teb + 0x6EC) = svk, MEM32(teb + 0x6FC) = svc;
        if (r) { if (W(h)) destroy(W(h)); return 0; }
        if (!W(h)) return 0;
    }
    if (!send(h, 0x81, 0, (uint32_t)(uintptr_t)cs)) { TRACE("[user] WM_NCCREATE refused\n"); if (W(h)) destroy(W(h)); return 0; }
    if (!W(h)) return 0;
    calcsize(u);
    wnd_sync(u);
    if (send(h, 1, 0, (uint32_t)(uintptr_t)cs) == (uint32_t)-1) { if (W(h)) destroy(W(h)); return 0; }
    if (!W(h)) return 0;
    u->sizemove = 1;                              /* (WM_SIZE, WM_MOVE: when it is first shown) */
    if (st & WS_VISIBLE) show(u, 1);
    TRACE("[user]   -> %X %d,%d-%d,%d style %08X\n", h, u->wrel.l, u->wrel.t, u->wrel.r, u->wrel.b, u->style);
    return h;
}
static uint32_t s_destroy(uint32_t* a) { uobj_t* u = W(a[0]); if (!u) return 0; destroy(u); return 1; }
static uint32_t s_show(uint32_t* a) { uobj_t* u = W(a[0]); TRACE("[user] ShowWindow %X %d\n", a[0], (int)a[1]); return u ? show(u, (int)a[1]) : 0; }
static uint32_t s_move(uint32_t* a) {            /* NtUserMoveWindow(hwnd, x, y, cx, cy, repaint) */
    uobj_t* u = W(a[0]);
    return u ? (uint32_t)setpos(u, (int)a[1], (int)a[2], (int)a[3], (int)a[4], a[5] ? 0 : SWP_NOREDRAW) : 0;
}
static uint32_t s_setpos(uint32_t* a) {          /* NtUserSetWindowPos(hwnd, after, x, y, cx, cy, flags) */
    uobj_t* u = W(a[0]);
    if (!u) return 0;
    if (a[1] == 0xFFFFFFFFu && !(u->style & WS_CHILD)) u->ex |= 8;         /* HWND_TOPMOST: WS_EX_TOPMOST */
    if (a[1] == 0xFFFFFFFEu && !(u->style & WS_CHILD)) u->ex &= ~8u;       /* HWND_NOTOPMOST */
    setpos(u, (int)a[2], (int)a[3], (int)a[4], (int)a[5], a[6]);
    if ((a[6] & SWP_SHOWWINDOW) && !(a[6] & 0x10) && !(u->style & WS_CHILD)) activate(u);
    return 1;
}
/* NtUserDeferWindowPos(hdwp, hwnd, after, x, y, cx, cy, flags): done at once,
 * so NtUserEndDeferWindowPosEx has nothing left. ponytail: not batched */
static uint32_t s_deferpos(uint32_t* a) { s_setpos(a + 1); return a[0]; }
/* NtUserSetParent(hwnd, parent): the old parent */
static void invalidate(uobj_t* u, int erase);
static uint32_t s_setparent(uint32_t* a) {
    uobj_t* u = W(a[0]), *p = a[1] ? W(a[1]) : NULL;
    if (!u) return 0;
    uint32_t old = u->parent;
    u->parent = p ? p->h : g_desktop;
    wnd_sync(u);
    invalidate(u, 1);
    return old;
}
static uint32_t s_invalidate(uint32_t* a) {      /* NtUserInvalidateRect(hwnd, RECT*, erase) */
    uobj_t* u = W(a[0]);
    if (!a[0]) { for (int i = 2; i < MAXU; i++) if (g_u[i].type == W2K_TYPE_WINDOW) invalidate(&g_u[i], (int)a[2]); return 1; }
    if (!u) return 0;
    invalidate(u, a[2] != 0);                     /* the rect is not kept, so the whole window, children too (painted over otherwise) */
    return 1;
}
/* NtUserRedrawWindow(hwnd, RECT*, hrgn, flags): RDW_INVALIDATE 1, RDW_ERASE 4, RDW_FRAME 0x400, RDW_UPDATENOW 0x100 */
static void update(uobj_t* u);
static uint32_t s_redraw(uint32_t* a) {
    uobj_t* u = a[0] ? W(a[0]) : NULL;
    if (!u) return a[0] == 0;
    if (a[3] & 1) set_dirty(u, 1), u->erase |= (a[3] & 4) != 0;
    if (a[3] & 0x400) u->ncdirty = 1;
    if (a[3] & 0x100) update(u);
    return 1;
}
static void update(uobj_t* u) {                   /* UpdateWindow: WM_PAINT now, if it needs one */
    if (!visible(u)) return;
    if (u->dirty || u->ncdirty) send(u->h, 0x0F, 0, 0);
    for (int i = 2; i < MAXU; i++)
        if (g_u[i].type == W2K_TYPE_WINDOW && g_u[i].parent == u->h) update(&g_u[i]);
}
static uint32_t s_beginpaint(uint32_t* a) { uobj_t* u = W(a[0]); return u ? paint_dc(u, a[1]) : 0; }
static uint32_t s_endpaint(uint32_t* a) { if (a[1]) dc_release(MEM32(a[1])); return 1; }
static uint32_t s_getdc(uint32_t* a) {
    uobj_t* u = W(a[0]);
    gobj_t* d = window_dc(u, 0);
    return d ? d->h : 0;
}
static uint32_t s_getwindowdc(uint32_t* a) { uobj_t* u = W(a[0]); gobj_t* d = window_dc(u, 1); return d ? d->h : 0; }
static uint32_t s_getdcex(uint32_t* a) {         /* NtUserGetDCEx(hwnd, hrgn, flags): DCX_WINDOW 1 */
    uobj_t* u = W(a[0]);
    gobj_t* d = window_dc(u, (a[2] & 1) != 0);
    return d ? d->h : 0;
}
static uint32_t s_setmenu(uint32_t* a) {         /* NtUserSetMenu(hwnd, hmenu, repaint) */
    uobj_t* u = W(a[0]);
    if (!u || (u->style & WS_CHILD)) return 0;
    u->menu = a[1];
    setpos(u, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_FRAMECHANGED);
    return 1;
}

/* messages */
static void broadcast(uint32_t m, uint32_t w, uint32_t l, int posted) {
    for (int i = 2; i < MAXU; i++)
        if (g_u[i].type == W2K_TYPE_WINDOW && g_u[i].parent == g_desktop) {
            if (posted) post(g_u[i].h, m, w, l);
            else send(g_u[i].h, m, w, l);
        }
}
static uint32_t s_post(uint32_t* a) {
    if (a[0] == 0xFFFF) { broadcast(a[1], a[2], a[3], 1); return 1; }
    post(a[0], a[1], a[2], a[3]);
    return 1;
}
static uint32_t s_message_call(uint32_t* a) {    /* NtUserMessageCall(hwnd, msg, w, l, xParam, fnid, bAnsi) */
    uobj_t* u = W(a[0]);
    if (a[5] == FNID_DEFWINDOWPROC) return u ? defproc(u, a[1], a[2], a[3]) : 0;
    if (a[5] >= FNID_SENDMESSAGE && a[5] <= FNID_SENDMESSAGE + 4) {
        if (a[0] == 0xFFFF) { broadcast(a[1], a[2], a[3], 0); return 1; }
        return send(a[0], a[1], a[2], a[3]);
    }
    static uint32_t seen[8];
    int k;
    for (k = 0; k < 8 && seen[k] && seen[k] != a[5]; k++) ;
    if (k < 8 && !seen[k]) { seen[k] = a[5]; fprintf(stderr, "[user] NtUserMessageCall fnid 0x%X (msg 0x%X): DefWindowProc's\n", a[5], a[1]); }
    return u ? defproc(u, a[1], a[2], a[3]) : 0;
}
/* NtUserGetUpdateRect(hwnd, RECT*, erase): the client area while it is dirty */
static uint32_t s_update_rect(uint32_t* a) {
    uobj_t* u = W(a[0]);
    int d = u && u->dirty;
    if (a[1]) rc_put(a[1], d ? (rc_t){ 0, 0, u->cr.r - u->cr.l, u->cr.b - u->cr.t } : (rc_t){ 0, 0, 0, 0 });
    return (uint32_t)d;
}
/* NtUserSendNotifyMessage(hwnd, msg, w, l): one thread here, so it is a send */
static uint32_t s_send_notify(uint32_t* a) {
    if (a[0] == 0xFFFF) broadcast(a[1], a[2], a[3], 0);
    else send(a[0], a[1], a[2], a[3]);
    return 1;
}
static int script_idle(void);
static int child_of(uint32_t c, uint32_t p) { for (uobj_t* u = W(c); u; u = W(u->parent)) if (u->h == p) return 1; return 0; }
/* the next message for MSG* (hwnd filter, range), or 0; WM_PAINT and
 * WM_TIMER made when nothing is posted */
static int next_msg(uint32_t msg, uint32_t hw, uint32_t lo, uint32_t hi, int remove) {
    for (int i = g_qh; i != g_qt; i = (i + 1) % QN) {
        qmsg_t* q = &g_q[i];
        if (hw && q->h != hw && !child_of(q->h, hw)) continue;
        if ((lo || hi) && (q->m < lo || q->m > hi)) continue;
        MEM32(msg) = q->h, MEM32(msg + 4) = q->m, MEM32(msg + 8) = q->w, MEM32(msg + 12) = q->l;
        MEM32(msg + 16) = q->t, MEM32(msg + 20) = (uint32_t)(int16_t)(q->l & 0xFFFF), MEM32(msg + 24) = (uint32_t)(int16_t)(q->l >> 16);
        if (remove) {                                          /* out of the ring, order kept */
            for (int j = i; j != g_qh; ) { int p = (j - 1 + QN) % QN; g_q[j] = g_q[p]; j = p; }
            g_qh = (g_qh + 1) % QN;
        }
        return 1;
    }
    if (g_quit) {
        MEM32(msg) = 0, MEM32(msg + 4) = 0x12, MEM32(msg + 8) = (uint32_t)g_quitcode, MEM32(msg + 12) = 0;
        if (remove) g_quit = 0;
        return 1;
    }
    if (!lo || (lo <= 0x0F && hi >= 0x0F))
        for (int i = 2; i < MAXU; i++) {
            uobj_t* u = &g_u[i];
            if (u->type != W2K_TYPE_WINDOW || !(u->dirty || u->ncdirty) || !visible(u)) continue;
            /* an empty window has an empty update region: no WM_PAINT (comctl32's toolbar paints
             * nothing at zero width and never calls BeginPaint, so its WM_PAINT came forever) */
            if (rc_empty(&u->cr)) set_dirty(u, 0);
            if (rc_empty(&u->wr)) u->ncdirty = 0;
            if (!(u->dirty || u->ncdirty)) continue;
            if (hw && u->h != hw && !child_of(u->h, hw)) continue;
            MEM32(msg) = u->h, MEM32(msg + 4) = 0x0F, MEM32(msg + 8) = 0, MEM32(msg + 12) = 0, MEM32(msg + 16) = ntp_clock_ms();
            return 1;
        }
    if (!lo || (lo <= 0x113 && hi >= 0x113))
        for (int i = 0; i < MAXT; i++) {
            timer_t_* t = &g_tm[i];
            if (!t->on || ntp_clock_ms() < t->due) continue;
            if (hw && t->h != hw) continue;
            MEM32(msg) = t->h, MEM32(msg + 4) = 0x113, MEM32(msg + 8) = t->id, MEM32(msg + 12) = t->proc, MEM32(msg + 16) = ntp_clock_ms();
            if (remove) t->due = ntp_clock_ms() + t->elapse;
            return 1;
        }
    return 0;
}
static uint32_t s_getmessage(uint32_t* a) {      /* NtUserGetMessage(MSG*, hwnd, min, max) */
    while (!next_msg(a[0], a[1], a[2], a[3], 1)) script_idle();
    return MEM32(a[0] + 4) != 0x12;
}
static uint32_t s_peekmessage(uint32_t* a) {     /* NtUserPeekMessage(MSG*, hwnd, min, max, flags) */
    if (next_msg(a[0], a[1], a[2], a[3], a[4] & 1)) return 1;
    script_idle();                                /* (a program polling must still see time pass) */
    return 0;
}
static uint32_t s_waitmessage(uint32_t* a) {
    (void)a;
    uint32_t m[7];
    while (!next_msg((uint32_t)(uintptr_t)m, 0, 0, 0, 0)) script_idle();
    return 1;
}
static uint32_t s_dispatch(uint32_t* a) {        /* NtUserDispatchMessage(MSG*) */
    uint32_t m = a[0];
    if (MEM32(m + 4) == 0x0F && W(MEM32(m))) {
        uobj_t* u = W(MEM32(m));
        uint32_t r = send(u->h, 0x0F, 0, 0);
        if (W(MEM32(m))) set_dirty(u, 0), u->ncdirty = 0;      /* (a WM_PAINT that never called BeginPaint) */
        return r;
    }
    return send(MEM32(m), MEM32(m + 4), MEM32(m + 8), MEM32(m + 12));
}
/* the caret: kept apart from the framebuffer and inverted over it when the
 * live window is presented, so painting never has to hide it first.
 * ponytail: shots leave it out (the Windows build's shots do too); one caret, as win32k has per queue. */
static uint32_t host_ms(void);
static struct { uint32_t hwnd; int x, y, w, h, shown; uint32_t t0; } g_caret;
static uint32_t s_createcaret(uint32_t* a) {     /* NtUserCreateCaret(hwnd, hbitmap, cx, cy) */
    g_caret.hwnd = a[0], g_caret.w = (int)a[2] ? (int)a[2] : 1, g_caret.h = (int)a[3] ? (int)a[3] : 1;
    g_caret.x = g_caret.y = g_caret.shown = 0, g_caret.t0 = host_ms();
    return 1;
}
static uint32_t s_showcaret(uint32_t* a) { if (!a[0] || a[0] == g_caret.hwnd) g_caret.shown++, g_caret.t0 = host_ms(); return 1; }
static uint32_t s_hidecaret(uint32_t* a) { if (!a[0] || a[0] == g_caret.hwnd) g_caret.shown--; return 1; }
static void caret_overlay(uint32_t* o) {          /* o: the presented copy of the screen */
    uobj_t* u = W(g_caret.hwnd);
    if (!u || g_caret.shown <= 0 || (host_ms() - g_caret.t0) / 530 % 2) return;   /* GetCaretBlinkTime: 530 */
    rc_t r = rc_and((rc_t){ u->cr.l + g_caret.x, u->cr.t + g_caret.y, u->cr.l + g_caret.x + g_caret.w, u->cr.t + g_caret.y + g_caret.h }, u->cr);
    for (int y = r.t; y < r.b; y++) for (int x = r.l; x < r.r; x++) o[(size_t)y * g_cx + x] ^= 0xFFFFFF;
}
/* accelerators: the ACCEL table copied at create, matched at TranslateAccelerator */
typedef struct { uint8_t virt; uint16_t key, cmd; } accel_t;
static accel_t* g_acc[MAXU];
static int g_nacc[MAXU];
static uint8_t g_keys[256];                       /* live: keys down (VK), and the character each one typed */
static uint16_t g_keychar[256];
static uint32_t s_translate(uint32_t* a) {       /* NtUserTranslateMessage(MSG*, flags): WM_KEYDOWN -> WM_CHAR */
    uint32_t m = a[0], k = MEM32(m + 8);
    if (MEM32(m + 4) != 0x100) return 0;
    if (k < 256 && g_keychar[k]) { post(MEM32(m), 0x102, g_keychar[k], MEM32(m + 12)); return 1; }
    if ((k >= '0' && k <= '9') || k == ' ' || k == 13 || k == 8 || k == 27) post(MEM32(m), 0x102, k, MEM32(m + 12));
    else if (k >= 'A' && k <= 'Z') post(MEM32(m), 0x102, k + 32, MEM32(m + 12));
    return 1;
}
static uint32_t s_settimer(uint32_t* a) {        /* NtUserSetTimer(hwnd, id, elapse, proc) */
    static uint32_t next = 0x7FF0;
    uint32_t id = a[0] ? a[1] : next++;
    int f = -1;
    for (int i = 0; i < MAXT; i++) if (g_tm[i].on && g_tm[i].h == a[0] && g_tm[i].id == id) f = i;
    for (int i = 0; i < MAXT && f < 0; i++) if (!g_tm[i].on) f = i;
    if (f < 0) return 0;
    g_tm[f] = (timer_t_){ a[0], id, a[2] ? a[2] : 1, ntp_clock_ms() + (a[2] ? a[2] : 1), a[3], 1 };
    return id;
}
static uint32_t s_killtimer(uint32_t* a) {
    for (int i = 0; i < MAXT; i++) if (g_tm[i].on && g_tm[i].h == a[0] && g_tm[i].id == a[1]) { g_tm[i].on = 0; return 1; }
    return 0;
}

/* menus */
static uint32_t menu_new(int popup) {
    uobj_t* m = unew(W2K_TYPE_MENU, 0x100);
    if (!m) return 0;
    m->items = calloc(64, sizeof *m->items);
    (void)popup;
    menu_sync(m);
    return m->h;
}
/* NtUserThunkedMenuItemInfo(hmenu, item, fByPosition, fInsert, MENUITEMINFOW*, UNICODE_STRING* text) */
static uint32_t s_menu_item(uint32_t* a) {
    uobj_t* m = U(a[0], W2K_TYPE_MENU), *own = m;
    uint32_t mi = a[4], mask = MEM32(mi + 4);
    if (!m) return 0;
    item_t* it;
    if (a[3]) {
        if (m->nitems >= 64) return 0;
        int pos = m->nitems;
        if (a[2] && a[1] < (uint32_t)m->nitems) pos = (int)a[1];
        else if (!a[2]) for (int i = 0; i < m->nitems; i++) if (m->items[i].id == a[1]) pos = i;
        memmove(&m->items[pos + 1], &m->items[pos], sizeof *it * (m->nitems - pos));
        it = &m->items[pos];
        memset(it, 0, sizeof *it);
        m->nitems++;
    } else if (!(it = menu_item(m, a[1], (int)a[2], &own))) return 0;
    if (mask & 0x10) it->type = MEM32(mi + 8);                      /* MIIM_TYPE */
    if (mask & 0x100) it->type = MEM32(mi + 8);                     /* MIIM_FTYPE */
    if (mask & 1) it->state = MEM32(mi + 0xC);                      /* MIIM_STATE */
    if (mask & 2) it->id = MEM32(mi + 0x10);                        /* MIIM_ID */
    if (mask & 4) it->sub = MEM32(mi + 0x14);                       /* MIIM_SUBMENU */
    if (mask & 0x20) it->data = MEM32(mi + 0x20);                   /* MIIM_DATA */
    if (mask & 0x80) it->bmp = MEM32(mi + 0x2C);                    /* MIIM_BITMAP */
    if ((mask & 0x50) && a[5] && MEM32(a[5] + 4)) {                 /* MIIM_TYPE / MIIM_STRING */
        int n = MEM16(a[5]) / 2;
        for (int i = 0; i < n && i < 63; i++) it->text[i] = MEM16(MEM32(a[5] + 4) + 2 * i), it->text[i + 1] = 0;
    }
    if ((mask & 0x110) && !(it->type & 0x904) && !it->text[0] && !it->sub) it->type |= 0x800;   /* (MFT_STRING, no string: win32k makes it a separator) */
    menu_sync(own);
    return 1;
}
static uint32_t s_check_menu(uint32_t* a) {      /* NtUserCheckMenuItem(hmenu, id, flags): the old state */
    uobj_t* m = U(a[0], W2K_TYPE_MENU), *own = m;
    item_t* it = menu_item(m, a[1], (a[2] & 0x400) != 0, &own);
    if (!it) return (uint32_t)-1;
    uint32_t old = it->state & 8;
    it->state = (it->state & ~8u) | (a[2] & 8);
    menu_sync(own);
    return old;
}
static uint32_t s_enable_menu(uint32_t* a) {     /* NtUserEnableMenuItem(hmenu, id, flags) */
    uobj_t* m = U(a[0], W2K_TYPE_MENU), *own = m;
    item_t* it = menu_item(m, a[1], (a[2] & 0x400) != 0, &own);
    if (!it) return (uint32_t)-1;
    uint32_t old = it->state & 3;
    it->state = (it->state & ~3u) | (a[2] & 3);
    menu_sync(own);
    return old;
}
/* NtUserRemoveMenu / NtUserDeleteMenu(hmenu, item, flags): MF_BYPOSITION 0x400, else by command.
 * ponytail: DeleteMenu leaves a submenu alive (no one holds it after) */
static uint32_t s_remove_menu(uint32_t* a) {
    uobj_t* m = U(a[0], W2K_TYPE_MENU), *own = m;
    item_t* it = menu_item(m, a[1], (a[2] & 0x400) != 0, &own);
    if (!it) return 0;
    int i = (int)(it - own->items);
    memmove(it, it + 1, sizeof *it * (own->nitems - i - 1));
    own->nitems--;
    menu_sync(own);
    return 1;
}
static uint32_t s_destroy_menu(uint32_t* a) { uobj_t* m = U(a[0], W2K_TYPE_MENU); if (m) ufree(m); return m != NULL; }
/* NtUserGetMenuItemRect(hwnd, hmenu, item, RECT*): a menu bar item on the screen */
static uint32_t s_menu_rect(uint32_t* a) {
    uobj_t* u = W(a[0]), *m = U(a[1], W2K_TYPE_MENU);
    if (!u || !m || a[2] >= (uint32_t)m->nitems || !a[3]) return 0;
    menubar_layout(u);
    int y = u->wr.t + borders(u->style, u->ex) + caption_h(u->style, u->ex);
    rc_put(a[3], (rc_t){ u->wr.l + m->items[a[2]].x, y, u->wr.l + m->items[a[2]].x + m->items[a[2]].w, y + SM(15) });
    return 1;
}
static uint32_t s_sysmenu(uint32_t* a) { (void)a; static uint32_t m; if (!m) m = menu_new(1); return m; }

/* cursors and icons: CreateIconIndirect asks for an empty object (CallOneParam
 * 0x19), SetCursorIconData fills it: CURSORDATA +8 rt, +0x14 hbmMask,
 * +0x18 hbmColor, +0x34 cx, +0x38 cy (doubled) */
static uint32_t s_set_cursor_data(uint32_t* a) {
    uobj_t* c = U(a[0], W2K_TYPE_CURSOR);
    uint32_t cd = a[3];
    if (!c || !cd) return 0;
    c->mask = MEM32(cd + 0x14), c->color = MEM32(cd + 0x18);
    c->icx = (int)MEM32(cd + 0x34), c->icy = (int)MEM32(cd + 0x38) / 2;
    return 1;
}
/* NtUserFindExistingCursorIcon(module, resource, info): the system cursors
 * and icons (LoadCursor(NULL, IDC_WAIT) and the like) exist from the start
 * in win32k; here each is an empty object made the first time it is asked
 * for. ponytail: never drawn (no cursor on the framebuffer); an icon drawn
 * from one draws nothing */
static uint32_t s_find_cursor(uint32_t* a) {
    static uint32_t sys[256];
    uint32_t id = a[1] ? MEM32(a[1] + 4) : 0;
    if (id < 32512 || id >= 32512 + 256) return 0;
    if (!sys[id - 32512]) { uobj_t* c = unew(W2K_TYPE_CURSOR, 0x80); sys[id - 32512] = c ? c->h : 0; }
    return sys[id - 32512];
}
/* NtUserDrawIconEx(hdc, x, y, hicon, cx, cy, step, hbr, flags, bMeta, cursordata) */
static uint32_t s_drawicon(uint32_t* a) {
    gobj_t* d = DCH(a[0]);
    uobj_t* c = U(a[3], W2K_TYPE_CURSOR);
    if (!d || !c) return 0;
    int x = (int)a[1], y = (int)a[2];
    lp2dp(d, &x, &y);
    draw_icon(d, c, x, y, (int)a[4] ? (int)a[4] : c->icx, (int)a[5] ? (int)a[5] : c->icy, a[8] & 3 ? a[8] & 3 : 3);
    return 1;
}

/* the CallXxx families: the index decides (Windows 2000's numbering, read
 * off the user32 exports that call them) */
static uint32_t s_call_noparam(uint32_t* a) {
    switch (a[0]) {
    case 0: return menu_new(0);                  /* CreateMenu */
    case 1: return menu_new(1);                  /* CreatePopupMenu */
    case 2: g_caret.hwnd = 0; return 1;          /* DestroyCaret */
    case 5: return 0;                            /* GetMessagePos */
    case 8: g_capture = 0; return 1;             /* ReleaseCapture */
    case 0x12: return 0;                         /* ClientThreadSetup asks: a new thread */
    case 0x15: return 0;                         /* MsgWaitForMultipleObjectsEx: clear the wake mask (none kept) */
    }
    fprintf(stderr, "[user] NtUserCallNoParam %u not answered\n", a[0]);
    return 0;
}
static uint32_t s_call_oneparam(uint32_t* a) {
    switch (a[1]) {
    case 0x19: { uobj_t* c = unew(W2K_TYPE_CURSOR, 0x80); return c ? c->h : 0; }
    case 0x24: return 1;                         /* MessageBeep: no sound here */
    case 0x25: return 1;                         /* PlayEventSound (SoftModalMessageBox's): no sound either */
    case 0x26: g_quit = 1, g_quitcode = (int)a[0]; return 1;   /* PostQuitMessage */
    case 0x29: dc_release(a[0]); return 1;       /* ReleaseDC */
    case 0x2D: return 1;                         /* ShowCursor */
    case 0x1E: return 0x04090409;                /* GetKeyboardLayout */
    case 0x33: if (a[0]) MEM32(a[0]) = 0; return 1;   /* GetProcessDefaultLayout */
    case 0x16: return 1;                         /* BeginDeferWindowPos */
    case 0x18: return 1;                         /* AllowSetForegroundWindow: the guest's own */
    /* 0x1D GetInputEvent(wake mask): MsgWaitForMultipleObjects waits on it with its handles.
     * ponytail: always signalled (the caller then peeks; every peek lets time pass), so a
     * message wait never sleeps; a real per-queue event when idle CPU matters */
    case 0x1D: { static uint32_t ev; if (!ev) ev = ntp_event(1, 1); return ev; }
    case 0x21: return 1;                         /* LockSetForegroundWindow */
    }
    fprintf(stderr, "[user] NtUserCallOneParam(%08X, 0x%X) not answered\n", a[0], a[1]);
    return 0;
}
static uint32_t s_call_twoparam(uint32_t* a) {
    if (a[2] == 0x5E) { g_caret.x = (int)a[0], g_caret.y = (int)a[1], g_caret.t0 = host_ms(); return 1; }   /* SetCaretPos */
    fprintf(stderr, "[user] NtUserCallTwoParam(%08X, %08X, 0x%X) not answered\n", a[0], a[1], a[2]);
    return 0;
}
static uint32_t s_call_hwnd(uint32_t* a) {       /* NtUserCallHwnd(hwnd, index) */
    if (a[1] == 0x3D) return 1;                   /* SetMsgBox: the dialog is a message box (win32k only marks it) */
    if (a[1] == 0x3C || a[1] == 0x39) return 1;   /* Register/DeregisterShellHookWindow. ponytail: no HSHELL_* sent yet */
    fprintf(stderr, "[user] NtUserCallHwnd index 0x%X not answered\n", a[1]);
    return 0;
}
/* NtUserGetCursorFrameInfo(hcur, step, &jiffies, &frames): one frame, not animated */
static uint32_t s_cursorframe(uint32_t* a) {
    if (a[2]) MEM32(a[2]) = 0;
    if (a[3]) MEM32(a[3]) = 1;
    return a[0];
}
static uint32_t s_hwnd_lock(uint32_t* a) {       /* NtUserCallHwndLock(hwnd, index) */
    uobj_t* u = W(a[0]);
    if (!u) return 0;
    if (a[1] == 0x50) { update(u); return 1; }  /* UpdateWindow */
    if (a[1] == 0x48) { u->ncdirty = 1; return 1; }   /* DrawMenuBar */
    if (a[1] == 0x4C || a[1] == 0x4D) { activate(u); return 1; }   /* (SetForegroundWindow's) */
    fprintf(stderr, "[user] NtUserCallHwndLock index 0x%X not answered\n", a[1]);
    return 0;
}
static uint32_t s_hwnd_param(uint32_t* a) {      /* NtUserCallHwndParam(hwnd, param, index) */
    uobj_t* u = W(a[0]);
    if (!u) return 0;
    if (a[2] == 0x43) { MEM32(u->obj + 0x9C) = a[1]; MEM8(u->obj + 0x16) |= 1; return 1; }   /* a dialog's DIALOG */
    if (a[2] == 0x46 && (a[1] >> 8) < 8) { MEM8(u->obj + 0x14 + (a[1] >> 8)) |= (uint8_t)a[1]; return 1; }   /* SetWindowState */
    if (a[2] == 0x41 && (a[1] >> 8) < 8) { MEM8(u->obj + 0x14 + (a[1] >> 8)) &= (uint8_t)~a[1]; return 1; }  /* ClearWindowState */
    if ((a[2] == 0x41 || a[2] == 0x46) && (a[1] >> 8) < 0x10) {   /* the same on ExStyle (8..B) and style (C..F), kept in u */
        uint32_t* f = (a[1] >> 8) < 0xC ? &u->ex : &u->style, m = (a[1] & 0xFFu) << (8 * ((a[1] >> 8) & 3));
        if (a[2] == 0x46) *f |= m; else *f &= ~m;
        wnd_sync(u);
        return 1;
    }
    fprintf(stderr, "[user] NtUserCallHwndParam(%08X, %08X) index 0x%X not answered\n", a[0], a[1], a[2]);
    return 0;
}
static uint32_t s_hwnd_param_lock(uint32_t* a) { /* 0x53 EnableWindow */
    uobj_t* u = W(a[0]);
    if (!u) return 0;
    if (a[2] == 0x53) {
        int was = !(u->style & 0x08000000u);
        if (a[1]) u->style &= ~0x08000000u; else u->style |= 0x08000000u;
        wnd_sync(u);
        return (uint32_t)!was;
    }
    fprintf(stderr, "[user] NtUserCallHwndParamLock index 0x%X not answered\n", a[2]);
    return 0;
}
/* NtUserScrollWindowEx(hwnd, dx, dy, prcScroll, prcClip, hrgnUpdate, prcUpdate, flags):
 * ponytail: no bits moved, the whole client is repainted (the update rect is all of it);
 * children not moved (SW_SCROLLCHILDREN) */
static uint32_t s_scrollwindow(uint32_t* a) {
    uobj_t* u = W(a[0]);
    if (!u) return 0;
    invalidate(u, 1);
    if (a[6]) { rc_t r = { 0, 0, u->cr.r - u->cr.l, u->cr.b - u->cr.t }; rc_put(a[6], r); }
    return 2;                                     /* SIMPLEREGION */
}
/* NtUserGetClassName(hwnd, bReal, UNICODE_STRING* out): the length copied, without the NUL */
static uint32_t s_classname(uint32_t* a) {
    uobj_t* u = W(a[0]);
    uint32_t s = a[2];
    if (!u || u->cls < 0 || !s) return 0;
    const uint16_t* n = g_cls[u->cls].name;
    uint32_t cap = MEM16(s + 2) / 2, b = MEM32(s + 4), i = 0;
    if (!cap || !b) return 0;
    for (; n[i] && i + 1 < cap; i++) MEM16(b + 2 * i) = n[i];
    MEM16(b + 2 * i) = 0;
    return i;
}
/* NtUserFindWindowEx(parent, after, UNICODE_STRING* class, UNICODE_STRING* name, type):
 * class by atom (Buffer below 0x10000) or name, name exact; either may be absent */
static uint32_t s_findwindow(uint32_t* a) {
    uint32_t parent = a[0] ? a[0] : g_desktop, cb = a[2] ? MEM32(a[2] + 4) : 0, nb = a[3] ? MEM32(a[3] + 4) : 0;
    int ci = -2, past = !a[1];
    if (cb) { ci = cls_find(cb); if (ci < 0) return 0; }
    uint16_t name[128] = { 0 };
    if (nb) for (uint32_t i = 0; i < MEM16(a[3]) / 2u && i < 127; i++) name[i] = MEM16(nb + 2 * i);
    for (int i = 2; i < MAXU; i++) {
        uobj_t* u = &g_u[i];
        if (u->type != W2K_TYPE_WINDOW || u->parent != parent) continue;
        if (!past) { past = u->h == a[1]; continue; }
        if ((ci == -2 || u->cls == ci) && (!nb || !u16icmp(u->text, name))) return u->h;
    }
    return 0;
}
/* NtUserUnregisterClass(UNICODE_STRING* name, hInstance, CLSMENUNAME* out): the
 * class is forgotten (its windows keep their procedure); no menu names to hand back */
static uint32_t s_unregister_class(uint32_t* a) {
    int i = cls_find(MEM32(a[0] + 4));
    if (i < 0) return 0;
    g_cls[i].atom = 0, g_cls[i].name[0] = 0;
    if (a[2]) MEM32(a[2]) = MEM32(a[2] + 4) = MEM32(a[2] + 8) = 0;
    return 1;
}
static uint32_t s_set_fnid(uint32_t* a) { uobj_t* u = W(a[0]); if (u) MEM16(u->obj + WND_FNID) = (uint16_t)a[1]; return u != NULL; }
static uint32_t s_query_window(uint32_t* a) {
    uint32_t teb = MEM32(g_fs_base + 0x18);
    if (a[1] == 0) return MEM32(teb + 0x20);
    if (a[1] == 1) return MEM32(teb + 0x24);
    return 0;
}
/* NtUserSetWindowLong(hwnd, index, value, bAnsi) */
static uint32_t s_setlong(uint32_t* a) {
    uobj_t* u = W(a[0]);
    int i = (int)a[1];
    uint32_t old = 0;
    if (!u) return 0;
    switch (i) {
    case -4: old = MEM32(u->obj + WND_PROC); MEM32(u->obj + WND_PROC) = a[2]; u->ansi = a[3] != 0; return old;   /* GWL_WNDPROC */
    case -16: old = u->style; u->style = (a[2] & ~WS_VISIBLE) | (u->style & WS_VISIBLE) | (a[2] & WS_VISIBLE); wnd_sync(u); return old;
    case -20: old = u->ex; u->ex = a[2]; wnd_sync(u); return old;
    case -12: old = u->id; u->id = a[2]; wnd_sync(u); return old;            /* GWL_ID */
    case -6: old = u->inst; u->inst = a[2]; wnd_sync(u); return old;         /* GWL_HINSTANCE */
    case -21: old = MEM32(u->obj + WND_USERDATA); MEM32(u->obj + WND_USERDATA) = a[2]; return old;
    }
    if (i >= 0 && !(MEM8(u->obj + 0x16) & 1) && (uint32_t)i + 4 <= MEM32(u->obj + WND_CBEXTRA) && i + 4 <= WND_SIZE - WND_EXTRA) {
        old = MEM32(u->obj + WND_EXTRA + i);
        MEM32(u->obj + WND_EXTRA + i) = a[2];
        return old;
    }
    return 0;
}
static uint32_t s_setfocus(uint32_t* a) {
    uint32_t old = g_focus;
    if (a[0] == old) return old;
    if (W(old)) send(old, 8, a[0], 0);           /* WM_KILLFOCUS */
    g_focus = a[0];
    if (W(a[0])) send(a[0], 7, old, 0);          /* WM_SETFOCUS */
    return old;
}
static uint32_t s_setcapture(uint32_t* a) { uint32_t o = g_capture; g_capture = a[0]; return o; }
static uint32_t s_setactive(uint32_t* a) {       /* a child is not activated (mspaint asks for its view's) */
    uint32_t o = g_active;
    uobj_t* u = W(a[0]);
    if (u && (u->style & (WS_CHILD | 0x80000000u)) == WS_CHILD) return 0;
    if (u) activate(u);
    return o;
}
static uint32_t s_foreground(uint32_t* a) { (void)a; return g_active; }
static uint32_t s_threaddesk(uint32_t* a) { (void)a; return 0x128; }
static uint32_t s_one_u(uint32_t* a) { (void)a; return 1; }
static uint32_t s_selpal(uint32_t* a) { (void)a; return g_stock[15]; }   /* NtUserSelectPalette: the default palette stays */
static uint32_t s_zero_u(uint32_t* a) { (void)a; return 0; }
/* NtGdiCreateHalftonePalette(hdc): a true-colour screen has no palette to build; the default
 * one (DeleteObject on a stock object succeeds and does nothing) */
static uint32_t s_halftone(uint32_t* a) { (void)a; return g_stock[15]; }
/* NtGdiCreatePaletteInternal(LOGPALETTE*, count): an object to select; nothing here is palettised.
 * NtGdiDoPalette(hpal, start, count, entries, func, inbound): no entries to give or take.
 * ponytail: entries not kept; add when a guest reads back what it set */
static uint32_t s_create_palette(uint32_t* a) { (void)a; gobj_t* o = gnew(GDI_PAL, 0); return o ? o->h : 0; }
/* NtGdiGetBitmapBits(hbm, cb, bits): the DDB's rows, WORD aligned: 1 bpp for a mono bitmap, else 32 */
static uint32_t s_getbitmapbits(uint32_t* a) {
    bmp_t* b = bm_of(a[0]);
    if (!b) return 0;
    uint32_t stride = b->mono ? (uint32_t)((b->w + 15) / 16 * 2) : (uint32_t)b->w * 4, n = stride * (uint32_t)b->h;
    if (!a[2]) return n;
    if (n > a[1]) n = a[1];
    uint8_t* p = (uint8_t*)(uintptr_t)a[2];
    memset(p, 0, n);
    for (uint32_t y = 0; y < (uint32_t)b->h; y++)
        for (uint32_t x = 0; x < (uint32_t)b->w; x++) {
            uint32_t c = b->px[(size_t)y * b->w + x], o = y * stride + (b->mono ? x >> 3 : 4 * x);
            if (o >= n) continue;
            if (b->mono) { if (c & 0xFFFFFF) p[o] |= (uint8_t)(0x80 >> (x & 7)); }
            else if (o + 3 < n) p[o] = (uint8_t)(c >> 16), p[o + 1] = (uint8_t)(c >> 8), p[o + 2] = (uint8_t)c, p[o + 3] = 0;
        }
    return n;
}
static uint32_t s_deftext(uint32_t* a) {        /* NtUserDefSetText(hwnd, LARGE_STRING*): DefWindowProc's WM_SETTEXT */
    uobj_t* u = W(a[0]);
    if (!u) return 0;
    uint32_t s = a[1], n = s ? MEM32(s) : 0, b = s ? MEM32(s + 8) : 0, ansi = s ? MEM32(s + 4) >> 31 : 0, i;
    if (!b) n = 0;
    n = ansi ? n : n / 2;
    for (i = 0; i < n && i < 127; i++) u->text[i] = ansi ? MEM8(b + i) : MEM16(b + 2 * i);
    u->text[i] = 0;
    wnd_sync(u);
    u->ncdirty = 1;
    return 1;
}
static uint32_t s_setscroll(uint32_t* a) {      /* NtUserSetScrollInfo(hwnd, SB_HORZ/VERT, SCROLLINFO*, redraw) -> pos */
    uobj_t* u = W(a[0]);
    uint32_t si = a[2];
    if (!u || a[1] > 1 || !si) return 0;
    int* i = u->sb[a[1]], m = (int)MEM32(si + 4);
    if (m & 1) i[0] = (int)MEM32(si + 8), i[1] = (int)MEM32(si + 12);
    if (m & 2) i[2] = (int)MEM32(si + 16);
    if (m & 4) i[3] = (int)MEM32(si + 20);
    if (i[3] > i[1] - (i[2] ? i[2] - 1 : 0)) i[3] = i[1] - (i[2] ? i[2] - 1 : 0);
    if (i[3] < i[0]) i[3] = i[0];
    if (a[3]) u->ncdirty = 1;
    return (uint32_t)i[3];
}
/* NtUserGetThreadState(index): 0 focus, 1 active, 2 capture (Windows 2000's numbering) */
static uint32_t s_threadstate(uint32_t* a) { return a[0] == 0 ? g_focus : a[0] == 1 ? g_active : a[0] == 2 ? g_capture : 0; }
/* NtUserGetIconSize(hicon, step, cx*, cy*): cy is both masks' height */
static uint32_t s_iconsize(uint32_t* a) {
    uobj_t* c = U(a[0], W2K_TYPE_CURSOR);
    if (!c) return 0;
    if (a[2]) MEM32(a[2]) = (uint32_t)(c->icx ? c->icx : 32);
    if (a[3]) MEM32(a[3]) = (uint32_t)(2 * (c->icy ? c->icy : 32));
    return 1;
}
/* NtUserGetIconInfo(hicon, ICONINFO*, module*, resource*, DWORD* bpp, internal): copies of the
 * mask and colour (the caller deletes them, as win32k's are copies). ponytail: no names */
static uint32_t bm_copy(uint32_t h) {
    bmp_t* s = bm_of(h);
    gobj_t* o = s ? bitmap_new(s->w, s->h, s->mono) : NULL;
    if (!o) return 0;
    memcpy(o->bm.px, s->px, (size_t)s->w * s->h * 4);
    return o->h;
}
static uint32_t s_iconinfo(uint32_t* a) {
    uobj_t* c = U(a[0], W2K_TYPE_CURSOR);
    if (!c || !a[1] || !bm_of(c->mask)) return 0;
    MEM32(a[1]) = 1, MEM32(a[1] + 4) = (uint32_t)c->icx / 2, MEM32(a[1] + 8) = (uint32_t)c->icy / 2;
    MEM32(a[1] + 12) = bm_copy(c->mask), MEM32(a[1] + 16) = c->color ? bm_copy(c->color) : 0;
    if (a[4]) MEM32(a[4]) = c->color && !bm_of(c->color)->mono ? 32 : 1;
    return 1;
}
/* NtUserDrawCaptionTemp(hwnd, hdc, RECT*, hfont, hicon, UNICODE_STRING* text, flags): a caption
 * drawn into any DC. explorer's Start button bitmap is DC_INBUTTON|DC_ICON|DC_TEXT: the face
 * colour, the small icon, the text in bold. A string with no buffer is the window's own title.
 * ponytail: the system font, bold; no gradient for DC_GRADIENT */
static uint32_t s_drawcaptiontemp(uint32_t* a) {
    gobj_t* d = DCH(a[1]);
    if (!d || !a[2]) return 0;
    rc_t r = rc_get(a[2]);
    r = dc_rect(d, r.l, r.t, r.r, r.b);
    uint32_t fl = a[6], act = fl & 1;
    uint32_t bg = fl & 0x10 ? C[15] : act ? C[2] : C[3], fg = fl & 0x10 ? C[18] : act ? C[9] : C[19];
    fill(d, r, bg);
    int x = r.l + 2;
    uobj_t* ic = a[4] ? U(a[4], W2K_TYPE_CURSOR) : NULL;
    if (!ic && a[0] && W(a[0]) && W(a[0])->cls >= 0) { cls_t* k = &g_cls[W(a[0])->cls]; ic = U(k->iconsm ? k->iconsm : k->icon, W2K_TYPE_CURSOR); }
    if ((fl & 4) && ic) { draw_icon(d, ic, x, r.t + (r.b - r.t - 16) / 2, 16, 16, 3); x += 18; }
    if (fl & 8) {
        uint16_t t[128] = { 0 };
        if (a[5] && MEM32(a[5] + 4)) { int n = MEM16(a[5]) / 2; for (int i = 0; i < n && i < 127; i++) t[i] = MEM16(MEM32(a[5] + 4) + 2 * i); }
        else if (a[0] && W(a[0])) u16cpy(t, W(a[0])->text, 128);
        draw_text(d, x, r.t + (r.b - r.t - 13) / 2, t, fg, 1, 0);
    }
    return 1;
}
static uint32_t s_keystate(uint32_t* a) { return a[0] < 256 && g_keys[a[0]] ? 0xFF80u : 0; }
static uint32_t s_dblclick(uint32_t* a) { (void)a; return 500; }
static uint32_t s_register_msg(uint32_t* a) { (void)a; static uint32_t n = 0xC100; return n++; }
static uint32_t s_accel(uint32_t* a) {           /* NtUserCreateAcceleratorTable(ACCEL*, n): 6-byte entries */
    uobj_t* c = unew(W2K_TYPE_ACCEL, 0x20);
    if (!c) return 0;
    int i = (int)(c->h & 0xFFFF), n = (int)a[1];
    free(g_acc[i]), g_acc[i] = calloc((size_t)(n > 0 ? n : 1), sizeof(accel_t)), g_nacc[i] = n;
    for (int k = 0; k < n; k++)
        g_acc[i][k] = (accel_t){ MEM8(a[0] + 6 * k), MEM16(a[0] + 6 * k + 2), MEM16(a[0] + 6 * k + 4) };
    return c->h;
}
/* NtUserTranslateAccelerator(hwnd, haccel, MSG*): FVIRTKEY 1, FSHIFT 4, FCONTROL 8, FALT 0x10 */
static uint32_t s_translate_accel(uint32_t* a) {
    uobj_t* c = U(a[1], W2K_TYPE_ACCEL);
    uint32_t m = a[2], msg = MEM32(m + 4), k = MEM32(m + 8);
    if (!c || !W(a[0])) return 0;
    int i = (int)(c->h & 0xFFFF), sys = msg == 0x104 || msg == 0x106;
    if (msg != 0x100 && msg != 0x104 && msg != 0x102 && msg != 0x106) return 0;
    for (int n = 0; n < g_nacc[i]; n++) {
        accel_t* e = &g_acc[i][n];
        if (e->virt & 1) {
            if ((msg != 0x100 && msg != 0x104) || e->key != k) continue;
            if (!!(e->virt & 4) != !!g_keys[16] || !!(e->virt & 8) != !!g_keys[17] || !!(e->virt & 0x10) != sys) continue;
        } else if ((msg != 0x102 && msg != 0x106) || e->key != k || !!(e->virt & 0x10) != sys) continue;
        send(a[0], 0x111, 0x10000u | e->cmd, 0);   /* WM_COMMAND, HIWORD 1: from an accelerator */
        return 1;
    }
    return 0;
}
/* NtUserSetWindowsHookEx(hmod, lib, thread, id, proc, ansi). Only WH_CBT's
 * HCBT_CREATEWND is called (MFC subclasses its windows there), straight into
 * the hook procedure. ponytail: one CBT hook, no chain, no other hooks or codes */

static uint32_t s_sethook(uint32_t* a) {
    if (a[3] == 5) { g_cbt = a[4]; return 0x00010001u + 0x105; }
    return 0x00010001u + 0x100;
}
static uint32_t s_unhook(uint32_t* a) { if (a[0] == 0x00010001u + 0x105) g_cbt = 0; return 1; }
/* NtUserEnumDisplayMonitors(hdc, clip, MONITORENUMPROC, data): the one monitor, to the guest's
 * proc (as w32kuser.c). ponytail: hdc and the clip ignored */
static uint32_t s_enum_monitors(uint32_t* a) {
    static uint32_t rc;
    if (!a[2]) return 0;
    if (!rc) rc = ntp_alloc(16);
    memcpy((void*)(uintptr_t)rc, (void*)(uintptr_t)(g_mon + 0x10), 16);
    uint32_t args[4] = { MEM32(g_mon), a[0], rc, a[3] };
    ntp_guest(a[2], 4, args);
    return 1;
}
/* NtUserEnumDisplaySettings(device, mode, DEVMODEW*, flags): the screen, 32 bpp, 60 Hz, for the
 * current and registry modes; mode n >= 0: the same one only (nothing to switch to here) */
static uint32_t s_enum_settings(uint32_t* a) {
    uint32_t d = a[2];
    if (!d || ((int)a[1] >= 1)) return 0xC0000001u;
    MEM32(d + 0x48) = 0x40000 | 0x80000 | 0x100000 | 0x200000 | 0x400000;   /* BITSPERPEL PELSWIDTH PELSHEIGHT DISPLAYFLAGS DISPLAYFREQUENCY */
    MEM32(d + 0x4C) = MEM32(d + 0x50) = 0;
    MEM32(d + 0xA8) = 32, MEM32(d + 0xAC) = (uint32_t)g_cx, MEM32(d + 0xB0) = (uint32_t)g_cy;
    MEM32(d + 0xB4) = 0, MEM32(d + 0xB8) = 60;
    return 0;
}
/* NtUserBuildHwndList(hdesk, hwnd, fChildren, tid, cMax, HWND* list, ULONG* cNeeded): the top-level
 * windows (or hwnd's children), Windows 2000's way: the list ends with HWND 1, counted.
 * ponytail: tid and hdesk not filtered (one desktop, one process) */
static uint32_t s_hwndlist(uint32_t* a) {
    uint32_t parent = a[2] && a[1] ? a[1] : g_desktop, n = 0;
    for (int i = 2; i < MAXU; i++)
        if (g_u[i].type == W2K_TYPE_WINDOW && g_u[i].parent == parent && g_u[i].h != g_desktop) {
            if (n < a[4] && a[5]) MEM32(a[5] + 4 * n) = g_u[i].h;
            n++;
        }
    if (n < a[4] && a[5]) MEM32(a[5] + 4 * n) = 1;
    n++;
    if (a[6]) MEM32(a[6]) = n;
    return n > a[4] ? 0xC0000023u : 0;
}
static uint32_t s_winsta(uint32_t* a) { (void)a; return 0x10; }   /* NtUserGetProcessWindowStation: the one there is */
/* NtUserGetObjectInformation(h, index, buf, len, needed*): UOI_NAME (2) of the window station */
static uint32_t s_objinfo(uint32_t* a) {
    static const char n[] = "WinSta0";
    if (a[1] != 2) return 0;
    if (a[4]) MEM32(a[4]) = 2 * sizeof n;
    if (a[3] < 2 * sizeof n) return 0;
    for (unsigned i = 0; i < sizeof n; i++) MEM16(a[2] + 2 * i) = (uint8_t)n[i];
    return 1;
}
/* NtUserPaintDesktop(hdc): the desktop's colour (COLOR_BACKGROUND) over the DC's clip.
 * ponytail: no wallpaper (none is set in the box) */
static uint32_t s_paintdesktop(uint32_t* a) {
    gobj_t* d = DCH(a[0]);
    if (!d) return 0;
    fill(d, d->clip, C[1]);
    return 1;
}
static uint32_t s_fill_window(uint32_t* a) {     /* NtUserFillWindow(hwndBrush, hwnd, hdc, hbr) */
    uobj_t* u = W(a[1]);
    gobj_t* d = DCH(a[2]);
    uint32_t br = a[3];
    if (!u || !d) return 0;
    if (br <= 6) br = send(a[0] ? a[0] : a[1], 0x132 + br, a[2], a[1]);
    patblt(d, dc_rect(d, 0, 0, u->cr.r - u->cr.l, u->cr.b - u->cr.t), 0xF00021, br);
    return 1;
}
/* NtUserGetControlBrush(hwnd, hdc, msg) / NtUserGetControlColor(hwndParent,
 * hwnd, hdc, msg): a control's WM_CTLCOLOR* to its parent; none there, the
 * default's (DefWindowProc's colours on the DC) */
static uint32_t ctlcolor(uint32_t parent, uint32_t hwnd, uint32_t hdc, uint32_t msg) {
    uint32_t r = W(parent) ? send(parent, msg, hdc, hwnd) : 0;
    uobj_t* u = W(hwnd);
    return r ? r : u ? defproc(u, msg, hdc, hwnd) : 0;
}
static uint32_t s_ctlbrush(uint32_t* a) { uobj_t* u = W(a[0]); return u ? ctlcolor(u->parent, a[0], a[1], a[2]) : 0; }
static uint32_t s_ctlcolor(uint32_t* a) { return ctlcolor(a[0], a[1], a[2], a[3]); }
static uint32_t s_frompoint(uint32_t* a) {       /* NtUserWindowFromPoint(x, y) */
    uint32_t r = g_desktop;
    int rtop = 0;
    for (int i = 2; i < MAXU; i++) {
        uobj_t* u = &g_u[i];
        if (u->type == W2K_TYPE_WINDOW && visible(u) && (int)a[0] >= u->wr.l && (int)a[0] < u->wr.r && (int)a[1] >= u->wr.t && (int)a[1] < u->wr.b) {
            uobj_t* t = u;                                /* a topmost tree (the taskbar) is above the others */
            while (W(t->parent) && t->parent != g_desktop) t = W(t->parent);
            int top = (t->ex & 8) != 0;
            if (top >= rtop) r = u->h, rtop = top;
        }
    }
    return r;
}
static uint32_t s_getplacement(uint32_t* a) {    /* NtUserGetWindowPlacement(hwnd, WINDOWPLACEMENT*) */
    uobj_t* u = W(a[0]);
    if (!u || !a[1]) return 0;
    MEM32(a[1] + 8) = 1;
    rc_put(a[1] + 28, u->wrel);
    return 1;
}
/* NtUserSetWindowPlacement(hwnd, WINDOWPLACEMENT*): the normal rectangle (+28) is where the window
 * goes; the taskbar places itself this way. ponytail: showCmd (+8) and the min/max points ignored */
static uint32_t s_setplacement(uint32_t* a) {
    uobj_t* u = W(a[0]);
    if (!u || !a[1]) return 0;
    rc_t r = rc_get(a[1] + 28);
    TRACE("[user] SetWindowPlacement %08X flags %u show %u normal %d,%d,%d,%d\n", a[0], MEM32(a[1] + 4), MEM32(a[1] + 8), r.l, r.t, r.r, r.b);
    /* an empty rectangle keeps the window where it is: wordpad, with no saved placement, hands
     * 0,0,0,0 (on Windows the frame's minimum tracking size would apply) */
    if (rc_empty(&r) || r.l == (int)0x80000000 || r.t == (int)0x80000000) return 1;   /* (mspaint hands back a CW_USEDEFAULT rect) */
    setpos(u, r.l, r.t, r.r - r.l, r.b - r.t, 0x0004 | 0x0010);   /* SWP_NOZORDER | SWP_NOACTIVATE */
    return 1;
}
/* NtUserSystemParametersInfo(action, uiParam, pvParam, fWinIni): queries
 * answered with Windows 2000's defaults; a set is kept nowhere */
static void logfont(uint32_t p, int h, int weight) {
    memset((void*)(uintptr_t)p, 0, 92);
    MEM32(p) = (uint32_t)h, MEM32(p + 16) = (uint32_t)weight;
    static const char f[] = "MS Sans Serif";
    for (int i = 0; f[i]; i++) MEM16(p + 28 + 2 * i) = (uint8_t)f[i];
}
static uint32_t s_spi(uint32_t* a) {
    uint32_t p = a[2];
    switch (a[0]) {
    case 0x30: if (p) memcpy((void*)(uintptr_t)p, (void*)(uintptr_t)(g_mon + 0x20), 16); return 1;   /* SPI_GETWORKAREA */
    case 0x2F:                                   /* SPI_SETWORKAREA: the taskbar docking; SPIF_SENDCHANGE tells the windows */
        if (p) memcpy((void*)(uintptr_t)(g_mon + 0x20), (void*)(uintptr_t)p, 16);
        else w2k_monitor(g_disp, g_mon, g_cx, g_cy, g_cy);
        if (a[3] & 2) broadcast(0x1A, 0x2F, 0, 0);                              /* WM_SETTINGCHANGE */
        return 1;
    case 0x2B:                                   /* SPI_GETMINIMIZEDMETRICS: width 160, no gaps, ARW_BOTTOMLEFT */
        if (p) MEM32(p + 4) = 160, MEM32(p + 8) = 0, MEM32(p + 12) = 0, MEM32(p + 16) = 0;
        return 1;
    case 0x62: case 0x64: if (p) MEM32(p) = 4; return 1;                        /* mouse hover width, height */
    case 0x66: if (p) MEM32(p) = 400; return 1;                                 /* SPI_GETMOUSEHOVERTIME */
    case 0x29:                                                                  /* SPI_GETNONCLIENTMETRICS */
        if (!p) return 0;
        memset((void*)(uintptr_t)(p + 4), 0, 0x1F0);
        MEM32(p + 4) = 1, MEM32(p + 8) = 16, MEM32(p + 12) = 16, MEM32(p + 16) = 18, MEM32(p + 20) = 18;
        logfont(p + 24, -11, 700);
        MEM32(p + 116) = 12, MEM32(p + 120) = 14;
        logfont(p + 124, -11, 700);
        MEM32(p + 216) = 18, MEM32(p + 220) = 18;
        logfont(p + 224, -11, 400), logfont(p + 316, -11, 400), logfont(p + 408, -11, 400);
        return 1;
    case 0x1F: if (p) logfont(p, -11, 400); return 1;                            /* SPI_GETICONTITLELOGFONT */
    case 0x26: case 0x1016: case 0x1012: case 0x100A: case 0x1018: case 0x1004: case 0x1002: case 0x1006: case 0x100C:
    case 0x101A: case 0x103E: case 0x1022: case 0x1024:
        if (p) MEM32(p) = 0;                                                    /* (effects and animations: off) */
        return 1;
    case 0x0E: case 0x10: case 0x0A: case 0x16: case 0x1B: case 0x3A: case 0x5E: case 0x5F:
        if (p) MEM32(p) = a[0] == 0x16 ? 500 : a[0] == 0x0A ? 3 : 0;            /* (keyboard speed and the like) */
        return 1;
    case 0x0D: case 0x18: if (p) MEM32(p) = 75; return 1;                        /* icon spacing */
    case 0x68: case 0x6A: if (p) MEM32(p) = 3; return 1;                         /* wheel lines, menu show delay */
    case 0x2D: if (p) MEM32(p) = 0; return 1;                                    /* SPI_GETSHOWSOUNDS */
    }
    if (!(a[0] & 1) || a[0] < 0x1000) TRACE("[user] SystemParametersInfo 0x%X: not answered\n", a[0]);
    if (p && a[0] < 0x2000) MEM32(p) = 0;
    return a[0] >= 0x1000 && !(a[0] & 1);
}

/* ======================================================================
 * csrss usersrv, the thread, the install
 * ====================================================================== */
static void user_connect(uint32_t index, uint32_t ci, uint32_t len) {
    if (index != 3 || len < 0x104) return;
    if (!g_psi) {
        g_psi = ntp_alloc(SI_SIZE);
        g_ahe = ntp_alloc(MAXU * W2K_AHE_SIZE);
        g_disp = ntp_alloc(0x1000);
        g_mon = ntp_alloc(0x100);
        g_defmsgs = ntp_alloc(0x80);
        memset((void*)(uintptr_t)g_defmsgs, 0xFF, 0x80);
        g_desk = ntp_alloc(DESK_SIZE);
        g_deskinfo = ntp_alloc(0x200);
        g_threadinfo = ntp_alloc(0x400);
        MEM32(g_deskinfo) = g_desk, MEM32(g_deskinfo + 4) = g_desk + DESK_SIZE;
        g_desk_top = 0x100;
        MEM32(g_psi + SI_CHANDLES) = MAXU;
        w2k_metrics_2000(g_met, g_cx, g_cy);
        memcpy((void*)(uintptr_t)(g_psi + SI_METRICS), g_met, sizeof g_met);
        memcpy((void*)(uintptr_t)(g_psi + SI_COLORS), w2k_colors_2000, sizeof w2k_colors_2000);
        if (!g_gdit) s_gdi_init(NULL);
        for (int i = 0; i < 0x1D; i++) MEM32(g_psi + SI_BRUSHES + 4 * i) = g_sysbrush[i];
        MEM16(g_psi + SI_CXSYSFONT) = 8, MEM16(g_psi + SI_CYSYSFONT) = 16;
        MEM16(g_psi + SI_LOGPIXELS) = 96;
        MEM32(g_psi + SI_PREFMASK) = 0;
        MEM32(g_psi + SI_GCLBORDER) = 1;               /* the sizing border setting (AdjustWindowRect: 4-pixel thick frames) */
        w2k_monitor(g_disp, g_mon, g_cx, g_cy, g_cy);   /* (the work area: the screen, until the taskbar sets it) */
        /* the desktop window */
        uobj_t* d = unew(W2K_TYPE_WINDOW, WND_SIZE);
        d->style = WS_VISIBLE | 0x02000000u, d->cls = -1;
        d->wrel = d->cin = (rc_t){ 0, 0, g_cx, g_cy };
        g_desktop = d->h;
        MEM16(d->obj + WND_FNID) = FNID_DESKTOP;
        /* its class (#32769): GetClassLong(GetDesktopWindow()) reads through WND_PCLS (shell32 at
         * startup). ponytail: an empty CLS, every field 0; fill when a caller wants one */
        MEM32(d->obj + WND_PCLS) = desk_alloc(0x80);
        wnd_sync(d);
        MEM32(g_deskinfo + 8) = d->obj;
        /* the monitor's handle (TYPE_MONITOR, 12): user32's GetMonitorInfo/MonitorFromRect validate
         * it in the handle table; with none, the taskbar placed itself on a 0x0 monitor */
        uobj_t* mo = unew(12, 4);
        if (mo) MEM32(g_mon) = mo->h, w2k_ahe_set(g_ahe, mo->h, g_mon, 12, g_threadinfo);
    }
    w2k_user_connect(ci, g_psi, g_ahe, g_disp, g_defmsgs);
}
static void pre(void) {                           /* before every win32k service */
    if (g_psi) w2k_client_info(MEM32(g_fs_base + 0x18), g_threadinfo, g_deskinfo);
    if (g_gdit) batch_flush();
}
void w2kx_start(void) {
    uint32_t o = 0, olen = 0;
    pre();
    ntp_callback(W2K_CB_THREADSETUP, 0, 0, &o, &olen);
}

/* ======================================================================
 * The script, shots
 * ====================================================================== */
enum { EV_SHOT, EV_CLICK, EV_COMMAND, EV_POST, EV_DLGCMD, EV_TYPE, EV_SCLICK };   /* (run_event names each one) */
typedef struct { uint32_t ms; int kind; char arg[256]; } ev_t;
#define MAXEV 64
static ev_t g_ev[MAXEV];
static int g_nev, g_iev;
static char g_out[512] = "shot";
static uint32_t g_secs_ms;
static int g_live;                                /* --live: an X11 window, real input (W2K_X11) */
static int ev_cmp(const void* a, const void* b) {
    const ev_t* x = a, *y = b;
    if (x->ms != y->ms) return x->ms < y->ms ? -1 : 1;
    if ((x->kind == EV_SHOT) != (y->kind == EV_SHOT)) return x->kind == EV_SHOT ? 1 : -1;   /* shots last */
    return x < y ? -1 : 1;
}
int w2kx_script_arg(int argc, char** argv, int i) {
    static const char* k[] = { "--shot", "--click", "--command", "--post", "--dlgcommand", "--type", "--sclick" };
    if (!strcmp(argv[i], "--live")) { g_live = 1; return 1; }
    if (i + 1 >= argc) return 0;
    if (!strcmp(argv[i], "--out")) { snprintf(g_out, sizeof g_out, "%s", argv[i + 1]); return 2; }
    if (!strcmp(argv[i], "--secs")) { g_secs_ms = (uint32_t)(atof(argv[i + 1]) * 1000); return 2; }
    for (int n = 0; n < 7; n++)
        if (!strcmp(argv[i], k[n]) && g_nev < MAXEV) {
            ev_t* e = &g_ev[g_nev++];
            const char* at = n == EV_SHOT ? argv[i + 1] : strrchr(argv[i + 1], '@');
            e->kind = n;
            e->ms = at ? (uint32_t)(atof(at + (n != EV_SHOT)) * 1000 + 0.5) : 0;
            snprintf(e->arg, sizeof e->arg, "%.*s", n == EV_SHOT || !at ? 255 : (int)(at - argv[i + 1]), argv[i + 1]);
            qsort(g_ev, g_nev, sizeof *g_ev, ev_cmp);
            return 2;
        }
    return 0;
}
static uint32_t top_window(void) {                /* the newest visible top-level window */
    for (int i = MAXU - 1; i >= 2; i--)
        if (g_u[i].type == W2K_TYPE_WINDOW && g_u[i].parent == g_desktop && (g_u[i].style & WS_VISIBLE)) return g_u[i].h;
    return g_main;
}
static void shot(uint32_t ms) {
    char p[600];
    rc_t box = { 0, 0, 0, 0 };
    for (int i = 2; i < MAXU; i++)
        if (g_u[i].type == W2K_TYPE_WINDOW && g_u[i].parent == g_desktop && (g_u[i].style & WS_VISIBLE)) box = rc_or(box, g_u[i].wr);
    box = rc_or(box, g_popup);
    for (int i = 2; g_trace && i < MAXU; i++)   /* the windows, for a trace (where is what) */
        if (g_u[i].type == W2K_TYPE_WINDOW) {
            uobj_t* u = &g_u[i];
            char cn[64] = "?";
            if (u->cls >= 0) { int k = 0; for (; k < 63 && g_cls[u->cls].name[k]; k++) cn[k] = (char)g_cls[u->cls].name[k]; cn[k] = 0; }
            fprintf(stderr, "[shot]   %08X parent %08X style %08X ex %08X %s (%d,%d)-(%d,%d) %s\n", u->h, u->parent, u->style, u->ex,
                    visible(u) ? "shown " : "hidden", u->wr.l, u->wr.t, u->wr.r, u->wr.b, cn);
        }
    snprintf(p, sizeof p, "%s_%u.png", g_out, ms / 1000);
    if (!rc_empty(&box) && png_write(p, &g_screen, box)) fprintf(stderr, "[shot] %u ms: %s (%dx%d)\n", ms, p, box.r - box.l, box.b - box.t);
    uobj_t* m = W(g_main);
    if (m) {
        snprintf(p, sizeof p, "%s_%u_client.png", g_out, ms / 1000);
        png_write(p, &g_screen, m->cr);
    }
    if (!g_nev || rc_empty(&box)) {
        snprintf(p, sizeof p, "%s_%u_screen.png", g_out, ms / 1000);
        png_write(p, &g_screen, (rc_t){ 0, 0, g_cx, g_cy });
    }
}
static uint32_t find_child(uint32_t parent, uint32_t id) {
    for (int i = 2; i < MAXU; i++) if (g_u[i].type == W2K_TYPE_WINDOW && g_u[i].parent == parent && g_u[i].id == id) return g_u[i].h;
    return 0;
}
static void run_event(ev_t* e) {
    uint32_t main = g_main, top = top_window();
    fprintf(stderr, "[script] %u ms: %s %s\n", e->ms, (const char*[]){ "shot", "click", "command", "post", "dlgcommand", "type", "sclick" }[e->kind], e->arg);
    if (e->kind != EV_SHOT) popup_close();
    switch (e->kind) {
    case EV_SHOT: shot(e->ms); break;
    case EV_CLICK: {
        int x = 0, y = 0;
        sscanf(e->arg, "%d,%d", &x, &y);
        uint32_t lp = (uint32_t)(y << 16 | (x & 0xFFFF));
        post(main, 0x201, 1, lp), post(main, 0x202, 0, lp);
        break;
    }
    case EV_SCLICK: {                                   /* --sclick X,Y: a screen point, to the window under it (the taskbar's Start) */
        int x = 0, y = 0;
        sscanf(e->arg, "%d,%d", &x, &y);
        uint32_t pt[2] = { (uint32_t)x, (uint32_t)y };
        uobj_t* u = W(s_frompoint(pt));
        if (!u || u->h == g_desktop) break;
        uint32_t cl = (uint32_t)((y - u->cr.t) << 16 | ((x - u->cr.l) & 0xFFFF));
        post(u->h, 0x201, 1, cl), post(u->h, 0x202, 0, cl);
        break;
    }
    case EV_COMMAND: post(main, 0x111, (uint32_t)strtoul(e->arg, NULL, 0), 0); break;
    case EV_DLGCMD: post(top, 0x111, (uint32_t)strtoul(e->arg, NULL, 0), 0); break;
    case EV_POST: {
        char* s = e->arg;
        uint32_t m = (uint32_t)strtoul(s, &s, 0), w = (uint32_t)strtoul(s + (*s == ','), &s, 0), l = (uint32_t)strtoul(s + (*s == ','), &s, 0);
        post(main, m, w, l);
        break;
    }
    case EV_TYPE: {
        char* eq = strchr(e->arg, '=');
        if (!eq) break;
        uint32_t c = find_child(top, (uint32_t)strtoul(e->arg, NULL, 0));
        if (!c) { fprintf(stderr, "[script] no control %s in the top window\n", e->arg); break; }
        post(c, 0xB1, 0, (uint32_t)-1);                       /* EM_SETSEL all */
        for (const char* t = eq + 1; *t; t++) post(c, 0x102, (uint8_t)*t, 1);
        break;
    }
    }
}
/* nothing to deliver: the next scripted event, or the virtual clock on to
 * the next timer; with neither, the run is over */
static int live_idle(uint32_t now, uint32_t next);
static int script_idle(void) {
    ntp_yield();                                  /* (another guest thread may have work) */
    uint32_t now = ntp_clock_ms(), next = UINT32_MAX;
    if (g_popup_next >= 0) {                      /* (the queue is empty: the windows have repainted) */
        int k = g_popup_next;
        g_popup_next = -1;
        if (W(g_popup_owner)) popup_draw(W(g_popup_owner), k);
        return 1;
    }
    if (g_iev < g_nev && g_ev[g_iev].ms <= now) { run_event(&g_ev[g_iev++]); return 1; }
    if (g_iev < g_nev) next = g_ev[g_iev].ms;
    for (int i = 0; i < MAXT; i++) if (g_tm[i].on && g_tm[i].due < next) next = g_tm[i].due;
    if (live_idle(now, next)) return 1;
    uint32_t end = g_secs_ms ? g_secs_ms : g_nev ? g_ev[g_nev - 1].ms + 1000 : 0;
    if (next == UINT32_MAX || (end && next > end)) {
        if (!g_nev) shot(now);
        fprintf(stderr, "[script] %u ms: the run is over\n", now);
        fflush(NULL);
        exit(0);
    }
    /* in steps of at most 100 ms: another guest thread (explorer's tray, its desktop) is still
     * starting while this one idles, and a jump straight to the next event left it no time */
    if (next > now) ntp_clock_advance(next - now < 100 ? next - now : 100);
    return 1;
}

/* ======================================================================
 * Live: an X11 window over the same framebuffer, with the real mouse and
 * keyboard (--live; built with -DW2K_X11 -lX11). The virtual clock follows
 * the real one while it waits for input; scripted events and shots still
 * run on it, so a live run can also be driven (xdotool) and shot.
 * ====================================================================== */
#ifdef W2K_X11
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>
#include <sys/select.h>
#include <time.h>
static Display* g_xd;
static Window g_xw;
static XImage* g_xi;
static GC g_xgc;
static Atom g_xdel;
static uint32_t g_xlast, g_xshown, g_xdown_ms, g_xdown_h;
static int g_xdown_x, g_xdown_y;
static uint32_t host_ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (uint32_t)(t.tv_sec * 1000 + t.tv_nsec / 1000000); }
static void x_open(void) {
    if (!(g_xd = XOpenDisplay(NULL))) { fprintf(stderr, "[live] no X display (DISPLAY=%s)\n", getenv("DISPLAY") ? getenv("DISPLAY") : ""); exit(1); }
    int sc = DefaultScreen(g_xd);
    g_xw = XCreateSimpleWindow(g_xd, RootWindow(g_xd, sc), 0, 0, (unsigned)g_cx, (unsigned)g_cy, 0, 0, 0);
    XStoreName(g_xd, g_xw, "Windows 2000");
    XSelectInput(g_xd, g_xw, ExposureMask | KeyPressMask | KeyReleaseMask | ButtonPressMask | ButtonReleaseMask | PointerMotionMask);
    g_xdel = XInternAtom(g_xd, "WM_DELETE_WINDOW", False);
    XSetWMProtocols(g_xd, g_xw, &g_xdel, 1);
    XMapWindow(g_xd, g_xw);
    g_xgc = DefaultGC(g_xd, sc);
    g_xi = XCreateImage(g_xd, DefaultVisual(g_xd, sc), 24, ZPixmap, 0, malloc((size_t)g_cx * g_cy * 4), (unsigned)g_cx, (unsigned)g_cy, 32, 0);
    g_xlast = host_ms();
    fprintf(stderr, "[live] X11 window 0x%lx, %dx%d\n", (unsigned long)g_xw, g_cx, g_cy);
}
static void x_present(void) {                    /* COLORREF (0x00BBGGRR) to the visual's 0x00RRGGBB */
    uint32_t* o = (uint32_t*)g_xi->data;
    for (int i = 0; i < g_cx * g_cy; i++) { uint32_t c = g_screen.px[i]; o[i] = (c & 0xFF) << 16 | (c & 0xFF00) | (c >> 16 & 0xFF); }
    caret_overlay(o);
    XPutImage(g_xd, g_xw, g_xgc, g_xi, 0, 0, 0, 0, (unsigned)g_cx, (unsigned)g_cy);
    XFlush(g_xd);
    g_xshown = host_ms();
}
static uint32_t x_vk(KeySym k) {
    if (k >= XK_a && k <= XK_z) return (uint32_t)(k - XK_a + 'A');
    if (k >= XK_0 && k <= XK_9) return (uint32_t)k;
    if (k >= XK_F1 && k <= XK_F12) return (uint32_t)(0x70 + k - XK_F1);
    if (k >= XK_KP_0 && k <= XK_KP_9) return (uint32_t)(0x60 + k - XK_KP_0);
    static const struct { KeySym k; uint8_t vk; } t[] = {
        { XK_Return, 13 }, { XK_KP_Enter, 13 }, { XK_BackSpace, 8 }, { XK_Tab, 9 }, { XK_Escape, 27 }, { XK_space, 32 },
        { XK_Left, 37 }, { XK_Up, 38 }, { XK_Right, 39 }, { XK_Down, 40 }, { XK_Home, 36 }, { XK_End, 35 }, { XK_Prior, 33 },
        { XK_Next, 34 }, { XK_Insert, 45 }, { XK_Delete, 46 }, { XK_Shift_L, 16 }, { XK_Shift_R, 16 }, { XK_Control_L, 17 },
        { XK_Control_R, 17 }, { XK_Alt_L, 18 }, { XK_Alt_R, 18 }, { XK_KP_Add, 0x6B }, { XK_KP_Subtract, 0x6D },
        { XK_KP_Multiply, 0x6A }, { XK_KP_Divide, 0x6F }, { XK_KP_Decimal, 0x6E }, { XK_semicolon, 0xBA }, { XK_equal, 0xBB },
        { XK_comma, 0xBC }, { XK_minus, 0xBD }, { XK_period, 0xBE }, { XK_slash, 0xBF }, { XK_grave, 0xC0 },
        { XK_bracketleft, 0xDB }, { XK_backslash, 0xDC }, { XK_bracketright, 0xDD }, { XK_apostrophe, 0xDE },
    };
    for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) if (t[i].k == k) return t[i].vk;
    return 0;
}
static uint32_t top_of(uint32_t h) { uobj_t* u = W(h); while (u && W(u->parent) && u->parent != g_desktop) u = W(u->parent); return u ? u->h : 0; }
/* a click in the dropped-down menu: its item's WM_COMMAND to the owner */
static void x_popup_click(int x, int y) {
    uobj_t* p = U(g_popup_menu, W2K_TYPE_MENU);
    uint32_t owner = g_popup_owner, id = 0;
    for (int i = 0, iy = g_popup.t + 3; p && i < p->nitems; i++) {
        int h = p->items[i].type & 0x800 ? 9 : 17;
        if (y >= iy && y < iy + h && !(p->items[i].type & 0x800) && !(p->items[i].state & 3) && !p->items[i].sub) id = p->items[i].id;
        iy += h;
    }
    (void)x;
    popup_close();
    if (id) post(owner, 0x111, id, 0);
}
static void x_mouse(int type, int x, int y, unsigned button, unsigned state) {
    uint32_t mk = (state & Button1Mask ? 1 : 0) | (state & Button3Mask ? 2 : 0) | (state & ShiftMask ? 4 : 0) | (state & ControlMask ? 8 : 0);
    if (type != MotionNotify && button > 3) return;          /* the wheel */
    if (type == MotionNotify && !rc_empty(&g_popup) && x >= g_popup.l && x < g_popup.r && y >= g_popup.t && y < g_popup.b) {
        uobj_t* p = U(g_popup_menu, W2K_TYPE_MENU);                 /* hot-tracking */
        int sel = -1;
        for (int i = 0, iy = g_popup.t + 3; p && i < p->nitems; i++) {
            int ih = p->items[i].type & 0x800 ? 9 : 17;
            if (y >= iy && y < iy + ih && !(p->items[i].type & 0x800)) sel = i;
            iy += ih;
        }
        if (sel != g_popup_sel && W(g_popup_owner)) g_popup_sel = sel, popup_draw(W(g_popup_owner), g_popup_bar);
        return;
    }
    if (type == ButtonPress && !rc_empty(&g_popup)) {
        if (x >= g_popup.l && x < g_popup.r && y >= g_popup.t && y < g_popup.b) { x_popup_click(x, y); return; }
        popup_close();
    }
    uint32_t pt[2] = { (uint32_t)x, (uint32_t)y }, h = g_capture ? g_capture : s_frompoint(pt);
    uobj_t* u = W(h);
    if (!u || h == g_desktop) return;
    uint32_t sl = (uint32_t)(y << 16 | (x & 0xFFFF));
    int client = g_capture || (x >= u->cr.l && x < u->cr.r && y >= u->cr.t && y < u->cr.b);
    if (type == ButtonPress) {
        uobj_t* t = W(top_of(h));
        if (t && t->h != g_active) activate(t);
    }
    if (!client) {
        if (type != ButtonPress || button != 1) return;
        uint32_t ht = send(h, 0x84, 0, sl);                 /* WM_NCHITTEST */
        uobj_t* m = ht == 5 ? U(u->menu, W2K_TYPE_MENU) : NULL;
        if (m) {
            menubar_layout(u);
            for (int k = 0; k < m->nitems; k++)
                if (x >= u->wr.l + m->items[k].x && x < u->wr.l + m->items[k].x + m->items[k].w) { popup_draw(u, k); return; }
        }
        post(h, 0xA1, ht, sl);                               /* WM_NCLBUTTONDOWN */
        return;
    }
    uint32_t cl = (uint32_t)((y - u->cr.t) << 16 | ((x - u->cr.l) & 0xFFFF)), m = 0x200;   /* WM_MOUSEMOVE */
    if (type == ButtonPress || type == ButtonRelease) {
        uint32_t b = button == 3 ? 3 : button == 2 ? 6 : 0;  /* WM_LBUTTON*, WM_RBUTTON*, WM_MBUTTON* */
        uint32_t bit = button == 1 ? 1 : button == 3 ? 2 : 0x10;
        m = 0x201 + b + (type == ButtonRelease);
        mk = type == ButtonPress ? mk | bit : mk & ~bit;
        if (type == ButtonPress) {
            uint32_t now = host_ms();
            cls_t* c = u->cls >= 0 ? &g_cls[u->cls] : NULL;
            if (c && (c->style & 8) && h == g_xdown_h && now - g_xdown_ms < 500 && abs(x - g_xdown_x) < 4 && abs(y - g_xdown_y) < 4)
                m = 0x203 + b, now = 0;                       /* CS_DBLCLKS: the second click is a double click */
            g_xdown_ms = now, g_xdown_h = h, g_xdown_x = x, g_xdown_y = y;
        }
    }
    post(h, m, mk, cl);
}
static void x_key(XKeyEvent* e, int down) {
    KeySym k = XLookupKeysym(e, 0), dummy;
    char ch[8] = "";
    int n = down ? XLookupString(e, ch, sizeof ch, &dummy, NULL) : 0;
    uint32_t vk = x_vk(k), alt = (e->state & Mod1Mask) != 0;
    if (!vk) return;
    g_keys[vk] = (uint8_t)down;
    if (down) g_keychar[vk] = n == 1 && !(e->state & ControlMask) ? (uint8_t)ch[0] : 0;
    uint32_t lp = 1 | (uint32_t)(e->keycode - 8) << 16 | (down ? 0 : 0xC0000000u);
    uint32_t to = W(g_focus) ? g_focus : g_active ? g_active : g_main;
    if (!rc_empty(&g_popup) && vk != 16 && vk != 17 && vk != 18) { if (down) popup_key(vk); return; }
    if (down && (vk == 0x79 || (alt && vk >= 'A' && vk <= 'Z'))) {   /* F10, Alt+letter: the menu */
        post(top_of(to) ? top_of(to) : g_main, 0x112, 0xF100, vk == 0x79 ? 0 : vk + 32);
        return;
    }
    if (vk == 18) return;
    post(to, down ? 0x100 : 0x101, vk, lp);
}
static int live_idle(uint32_t now, uint32_t next) {
    if (!g_live) return 0;
    if (!g_xd) x_open();
    if (host_ms() - g_xshown >= 15) x_present();
    int wait = next == UINT32_MAX || next - now > 15 ? 15 : (int)(next - now);
    if (!XPending(g_xd)) {
        fd_set f;
        FD_ZERO(&f);
        FD_SET(ConnectionNumber(g_xd), &f);
        struct timeval tv = { 0, wait * 1000 };
        select(ConnectionNumber(g_xd) + 1, &f, NULL, NULL, &tv);
    }
    while (XPending(g_xd)) {
        XEvent e;
        XNextEvent(g_xd, &e);
        switch (e.type) {
        case Expose: g_xshown = 0; break;
        case ButtonPress: case ButtonRelease: x_mouse(e.type, e.xbutton.x, e.xbutton.y, e.xbutton.button, e.xbutton.state); break;
        case MotionNotify: x_mouse(e.type, e.xmotion.x, e.xmotion.y, 0, e.xmotion.state); break;
        case KeyPress: case KeyRelease: x_key(&e.xkey, e.type == KeyPress); break;
        case ClientMessage: if ((Atom)e.xclient.data.l[0] == g_xdel) { if (W(g_main)) post(g_main, 0x10, 0, 0); else exit(0); } break;
        }
    }
    uint32_t t = host_ms(), d = t - g_xlast;
    g_xlast = t;
    if (d) ntp_clock_advance(d);
    return 1;
}
#else
static int live_idle(uint32_t now, uint32_t next) {
    (void)now, (void)next;
    if (g_live) { fprintf(stderr, "[live] built without X11 (-DW2K_X11 -lX11)\n"); exit(1); }
    return 0;
}
#endif

void w2kx_install(int cx, int cy, const char* fontdir) {
    char p[1024];
    g_trace = getenv("NATIVE32_SYSCALLS") != NULL;
    g_cx = cx, g_cy = cy;
    bm_init(&g_screen, cx, cy, 0);
    for (int i = 0; i < cx * cy; i++) g_screen.px[i] = w2k_colors_2000[1];   /* COLOR_BACKGROUND */
    snprintf(p, sizeof p, "%s/sserife.fon", fontdir), fon_load(p);
    snprintf(p, sizeof p, "%s/vgasys.fon", fontdir), fon_load(p);
    static const char* const ttfs[] = { "lucon.ttf", "tahoma.ttf", "tahomabd.ttf", "arial.ttf", "times.ttf", "cour.ttf" };
    for (unsigned i = 0; i < sizeof ttfs / sizeof ttfs[0]; i++) snprintf(p, sizeof p, "%s/%s", fontdir, ttfs[i]), ttf_load(p);
    ntp_csr_connect = user_connect;
    ntp_win32k_pre = pre;
    static const struct { const char* name; uint32_t (*fn)(uint32_t*); } svc[] = {
        /* GDI */
        { "NtGdiInit", s_gdi_init }, { "NtGdiQueryFontAssocInfo", s_zero }, { "NtGdiGetStockObject", s_stock },
        { "NtGdiCreateCompatibleDC", s_compat_dc }, { "NtGdiCreateCompatibleBitmap", s_compat_bitmap }, { "NtGdiCreateBitmap", s_bitmap },
        { "NtGdiCreatePen", s_pen }, { "NtGdiCreateSolidBrush", s_brush }, { "NtGdiCreateHatchBrushInternal", s_hatch },
        { "NtGdiCreatePatternBrushInternal", s_patbrush }, { "NtGdiCreateRectRgn", s_rectrgn }, { "NtGdiCombineRgn", s_combinergn }, { "NtGdiCreateDIBitmapInternal", s_dibitmap },
        { "NtGdiCreateDIBSection", s_dibsection }, { "NtGdiGetDIBitsInternal", s_getdibits },
        { "NtGdiSelectBitmap", s_select_bitmap }, { "NtGdiSelectBrush", s_select }, { "NtGdiSelectPen", s_select }, { "NtGdiSelectFont", s_select },
        { "NtGdiGetDCforBitmap", s_dcforbitmap }, { "NtGdiDeleteObjectApp", s_delete }, { "NtGdiBitBlt", s_bitblt }, { "NtGdiStretchBlt", s_stretchblt },
        { "NtGdiPatBlt", s_patblt }, { "NtGdiLineTo", s_lineto }, { "NtGdiMoveTo", s_moveto }, { "NtGdiRectangle", s_rectangle },
        { "NtGdiSetPixel", s_setpixel }, { "NtGdiGetPixel", s_getpixel }, { "NtGdiGetDeviceCaps", s_devcaps },
        { "NtGdiSetDIBitsToDeviceInternal", s_setdibits }, { "NtGdiStretchDIBitsInternal", s_stretchdib },
        { "NtGdiExtGetObjectW", s_getobject }, { "NtGdiGetTextMetricsW", s_textmetrics }, { "NtGdiGetTextExtent", s_textextent },
        { "NtGdiGetTextExtentExW", s_textextentex }, { "NtGdiGetCharWidthW", s_charwidth }, { "NtGdiHfontCreate", s_font },
        { "NtGdiExtTextOutW", s_textout }, { "NtGdiGetDCObject", s_dcobject }, { "NtGdiIntersectClipRect", s_intersectclip },
        { "NtGdiExcludeClipRect", s_excludeclip }, { "NtGdiExtSelectClipRgn", s_selectcliprgn }, { "NtGdiSaveDC", s_savedc },
        { "NtGdiRestoreDC", s_restoredc }, { "NtGdiGetCharSet", s_getcharset }, { "NtGdiGetDCPoint", s_dcpoint },
        { "NtGdiGetDCDword", s_getdword }, { "NtGdiGetAndSetDCDword", s_getsetdword }, { "NtGdiOpenDCW", s_opendc },
        { "NtGdiGetRgnBox", s_getrgnbox }, { "NtGdiGetAppClipBox", s_cliprect }, { "NtGdiFlushUserBatch", s_flushbatch },
        { "NtGdiFlush", s_gdiflush }, { "NtGdiComputeXformCoefficients", s_one }, { "NtGdiSetLayout", s_zero }, { "NtGdiGetLayout", s_zero },
        { "NtGdiEnumFontClose", s_one }, { "NtGdiGetTextCharsetInfo", s_charsetinfo }, { "NtGdiGetRandomRgn", s_randomrgn }, { "NtGdiRectVisible", s_one }, { "NtGdiGetNearestColor", s_nearest },
        { "NtGdiGetTextFaceW", s_textface }, { "NtGdiEnumFontOpen", s_enumfont_open }, { "NtGdiEnumFontChunk", s_enumfont_chunk },
        /* USER */
        { "NtUserRegisterClassExWOW", s_register_class }, { "NtUserGetClassInfo", s_classinfo },
        { "NtUserCreateWindowEx", s_create_window }, { "NtUserDestroyWindow", s_destroy }, { "NtUserShowWindow", s_show },
        { "NtUserMoveWindow", s_move }, { "NtUserDeferWindowPos", s_deferpos }, { "NtUserEndDeferWindowPosEx", s_one_u },
        { "NtUserSetParent", s_setparent }, { "NtUserSelectPalette", s_selpal }, { "NtUserSetWindowPos", s_setpos }, { "NtUserInvalidateRect", s_invalidate },
        { "NtUserRedrawWindow", s_redraw }, { "NtUserBeginPaint", s_beginpaint }, { "NtUserEndPaint", s_endpaint },
        { "NtUserGetDC", s_getdc }, { "NtUserGetDCEx", s_getdcex }, { "NtUserGetWindowDC", s_getwindowdc }, { "NtUserSetMenu", s_setmenu },
        { "NtUserPostMessage", s_post }, { "NtUserMessageCall", s_message_call }, { "NtUserGetMessage", s_getmessage },
        { "NtUserPeekMessage", s_peekmessage }, { "NtUserWaitMessage", s_waitmessage }, { "NtUserDispatchMessage", s_dispatch },
        { "NtUserTranslateMessage", s_translate }, { "NtUserSetTimer", s_settimer }, { "NtUserKillTimer", s_killtimer },
        { "NtUserValidateTimerCallback", s_one_u }, { "NtUserThunkedMenuItemInfo", s_menu_item }, { "NtUserRemoveMenu", s_remove_menu }, { "NtUserDeleteMenu", s_remove_menu }, { "NtUserCheckMenuItem", s_check_menu },
        { "NtUserEnableMenuItem", s_enable_menu }, { "NtUserDestroyMenu", s_destroy_menu }, { "NtUserGetMenuItemRect", s_menu_rect },
        { "NtUserGetSystemMenu", s_sysmenu }, { "NtUserFindExistingCursorIcon", s_find_cursor }, { "NtUserSetCursorIconData", s_set_cursor_data },
        { "NtUserDrawIconEx", s_drawicon }, { "NtUserDestroyCursor", s_one_u }, { "NtUserSetCursor", s_zero_u },
        { "NtUserCallNoParam", s_call_noparam }, { "NtUserCallOneParam", s_call_oneparam }, { "NtUserCallTwoParam", s_call_twoparam },
        { "NtUserCallHwndLock", s_hwnd_lock }, { "NtUserCallHwnd", s_call_hwnd }, { "NtUserGetCursorFrameInfo", s_cursorframe }, { "NtUserCallHwndParam", s_hwnd_param }, { "NtUserCallHwndParamLock", s_hwnd_param_lock },
        { "NtUserSetWindowFNID", s_set_fnid }, { "NtUserSendNotifyMessage", s_send_notify }, { "NtUserGetUpdateRect", s_update_rect }, { "NtUserDefSetText", s_deftext }, { "NtUserSetScrollInfo", s_setscroll }, { "NtUserQueryWindow", s_query_window }, { "NtUserSetWindowLong", s_setlong },
        { "NtUserSetFocus", s_setfocus }, { "NtUserSetCapture", s_setcapture }, { "NtUserSetActiveWindow", s_setactive },
        { "NtUserGetForegroundWindow", s_foreground }, { "NtUserGetThreadState", s_threadstate }, { "NtUserGetIconSize", s_iconsize }, { "NtUserGetThreadDesktop", s_threaddesk },
        { "NtUserModifyUserStartupInfoFlags", s_one_u }, { "NtUserGetDoubleClickTime", s_dblclick },
        { "NtUserRegisterWindowMessage", s_register_msg }, { "NtUserCreateAcceleratorTable", s_accel },
        { "NtUserTranslateAccelerator", s_translate_accel }, { "NtUserSetWindowsHookEx", s_sethook }, { "NtUserUnhookWindowsHookEx", s_unhook },
        { "NtUserCallNextHookEx", s_zero_u }, { "NtUserSetProp", s_one_u }, { "NtUserRemoveProp", s_zero_u },
        { "NtUserFillWindow", s_fill_window }, { "NtUserWindowFromPoint", s_frompoint }, { "NtUserGetWindowPlacement", s_getplacement },
        { "NtUserSetWindowPlacement", s_setplacement }, { "NtUserSystemParametersInfo", s_spi }, { "NtUserGetKeyState", s_keystate },
        { "NtUserGetAsyncKeyState", s_keystate }, { "NtUserShowCaret", s_showcaret }, { "NtUserHideCaret", s_hidecaret },
        { "NtUserCreateCaret", s_createcaret }, { "NtUserGetKeyboardLayoutList", s_zero_u },
        { "NtUserGetControlBrush", s_ctlbrush }, { "NtUserGetClassName", s_classname }, { "NtUserFindWindowEx", s_findwindow }, { "NtUserScrollWindowEx", s_scrollwindow },
        { "NtUserUnregisterClass", s_unregister_class }, { "NtUserCountClipboardFormats", s_zero_u }, { "NtUserGetControlColor", s_ctlcolor },
        { "NtUserGetIconInfo", s_iconinfo }, { "NtUserDrawCaptionTemp", s_drawcaptiontemp },
        { "NtUserRegisterHotKey", s_one_u }, { "NtUserUnregisterHotKey", s_one_u },   /* no system-wide hotkeys here */
        { "NtGdiCreateHalftonePalette", s_halftone }, { "NtUserPaintDesktop", s_paintdesktop },
        { "NtUserSetShellWindowEx", s_one_u }, { "NtUserEnumDisplayMonitors", s_enum_monitors },
        { "NtUserEnumDisplaySettings", s_enum_settings }, { "NtUserBuildHwndList", s_hwndlist },
        { "NtUserGetProcessWindowStation", s_winsta }, { "NtUserGetObjectInformation", s_objinfo }, { "NtUserCallHwndOpt", s_one_u },   /* Set{Progman,Taskman}Window */
        { "NtGdiCreatePaletteInternal", s_create_palette }, { "NtGdiDoPalette", s_zero_u }, { "NtGdiGetBitmapBits", s_getbitmapbits },
    };
    for (unsigned i = 0; i < sizeof svc / sizeof svc[0]; i++) ntp_win32k_override(svc[i].name, svc[i].fn);
}

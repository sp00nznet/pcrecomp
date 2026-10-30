/*
 * d3d_raster.c - Direct3D's triangles in software: half-space rasterisation
 * over the bounding box, perspective-correct attributes (each times 1/w, then
 * divided back), a 16-bit z-buffer, texturing (nearest or bilinear, wrap or
 * clamp, colour key), DirectX 6's texture-stage colour and alpha operations
 * for stage 0, alpha test, vertex fog, specular, and alpha blending, into a
 * surface in whatever 16 or 32-bit format it has.
 */
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "win32hle.h"
#include "d3d_raster.h"

/* ---- pixel formats ---- */
static int shift_of(uint32_t m) { int s = 0; if (!m) return 0; while (!(m & 1u)) m >>= 1, s++; return s; }
static int bits_of(uint32_t m) { int n = 0; while (m) n += (int)(m & 1u), m >>= 1; return n; }
static inline float chan(uint32_t v, uint32_t m) {
    if (!m) return 1.0f;
    uint32_t x = (v & m) >> shift_of(m), max = m >> shift_of(m);
    return (float)x / (float)max;
}
static inline uint32_t unchan(float f, uint32_t m) {
    if (!m) return 0;
    uint32_t max = m >> shift_of(m);
    if (f < 0) f = 0;
    if (f > 1) f = 1;
    return ((uint32_t)(f * (float)max + 0.5f) << shift_of(m)) & m;
}
static void masks_of(const surf_t *s, uint32_t *r, uint32_t *g, uint32_t *b, uint32_t *a) {
    if (s->pf_flags || s->rmask) { *r = s->rmask, *g = s->gmask, *b = s->bmask, *a = s->amask; return; }
    if (s->bpp == 16) *r = 0xF800, *g = 0x07E0, *b = 0x001F, *a = 0;
    else *r = 0xFF0000, *g = 0xFF00, *b = 0xFF, *a = 0;
}
static inline uint32_t raw(const surf_t *s, int x, int y) {
    const uint8_t *p = s->px + (size_t)y * (size_t)s->pitch;
    switch (s->bpp) {
    case 8: return p[x];
    case 16: return ((const uint16_t *)p)[x];
    case 32: return ((const uint32_t *)p)[x];
    default: p += x * 3; return (uint32_t)(p[0] | p[1] << 8 | p[2] << 16);
    }
}
static inline void put_raw(surf_t *s, int x, int y, uint32_t v) {
    uint8_t *p = s->px + (size_t)y * (size_t)s->pitch;
    switch (s->bpp) {
    case 16: ((uint16_t *)p)[x] = (uint16_t)v; break;
    case 32: ((uint32_t *)p)[x] = v; break;
    case 8: p[x] = (uint8_t)v; break;
    default: p += x * 3; p[0] = (uint8_t)v, p[1] = (uint8_t)(v >> 8), p[2] = (uint8_t)(v >> 16);
    }
}
static void unpack(const surf_t *s, uint32_t v, float out[4]) {
    uint32_t r, g, b, a;
    if (s->bpp == 8) {                                   /* through the palette */
        uint32_t e = s->palette ? MEM32(MEM32(s->palette + 8) + 4u * v) : v * 0x010101u;
        out[0] = (float)(e & 0xFF) / 255.f, out[1] = (float)((e >> 8) & 0xFF) / 255.f;
        out[2] = (float)((e >> 16) & 0xFF) / 255.f, out[3] = 1.f;
        return;
    }
    masks_of(s, &r, &g, &b, &a);
    out[0] = chan(v, r), out[1] = chan(v, g), out[2] = chan(v, b), out[3] = a ? chan(v, a) : 1.f;
}
uint32_t d3d_pack(const surf_t *s, float r, float g, float b, float a) {
    uint32_t rm, gm, bm, am;
    masks_of(s, &rm, &gm, &bm, &am);
    return unchan(r, rm) | unchan(g, gm) | unchan(b, bm) | unchan(a, am);
}
static void fmt_of(const surf_t *s, rfmt_t *f) {
    uint32_t m[4];
    masks_of(s, &m[0], &m[1], &m[2], &m[3]);
    for (int i = 0; i < 4; i++) f->mask[i] = m[i], f->sh[i] = shift_of(m[i]), f->bits[i] = bits_of(m[i]);
}
static inline uint32_t fmt_pack(const rfmt_t *f, const float c[4]) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        if (!f->bits[i]) continue;
        float x = c[i] < 0 ? 0 : c[i] > 1 ? 1 : c[i];
        v |= (uint32_t)(x * (float)((1u << f->bits[i]) - 1) + 0.5f) << f->sh[i];
    }
    return v;
}
static inline void fmt_unpack(const rfmt_t *f, uint32_t v, float c[4]) {
    for (int i = 0; i < 4; i++)
        c[i] = f->bits[i] ? (float)((v & f->mask[i]) >> f->sh[i]) / (float)((1u << f->bits[i]) - 1) : 1.0f;
}
/* The texture as ARGB8888, remade when its pixels or key have changed. */
static void tex_cache(surf_t *t) {
    if (t->argb && t->argb_gen == t->gen && t->argb_w == t->w && t->argb_h == t->h) return;
    size_t n = (size_t)t->w * (size_t)t->h;
    if (t->argb && (t->argb_w != t->w || t->argb_h != t->h)) {   /* resized (SetSurfaceDesc): a new cache */
        free(t->argb), free(t->keyed);
        t->argb = NULL, t->keyed = NULL;
    }
    if (!t->argb) {
        t->argb = (uint32_t *)malloc(n * 4), t->keyed = (uint8_t *)malloc(n);
        if (!t->argb || !t->keyed) hle_fatal("no memory for a %dx%d texture's cache", t->w, t->h);
        t->argb_w = t->w, t->argb_h = t->h;
    }
    for (int y = 0; y < t->h; y++)
        for (int x = 0; x < t->w; x++) {
            float c[4];
            int k;
            d3d_texel(t, x, y, c, &k);
            t->argb[(size_t)y * (size_t)t->w + (size_t)x] = (uint32_t)(c[3] * 255.f + .5f) << 24 | (uint32_t)(c[0] * 255.f + .5f) << 16 |
                                                            (uint32_t)(c[1] * 255.f + .5f) << 8 | (uint32_t)(c[2] * 255.f + .5f);
            t->keyed[(size_t)y * (size_t)t->w + (size_t)x] = (uint8_t)k;
        }
    t->argb_gen = t->gen;
}
void d3d_raster_prepare(rstate_t *st) {
    if (st->target) fmt_of(st->target, &st->tfmt);
    if (st->tex) tex_cache(st->tex);
}

void d3d_texel(const surf_t *s, int x, int y, float out[4], int *keyed) {
    uint32_t v = raw(s, x, y);
    if (keyed) *keyed = s->ck_src && v >= s->ck_lo && v <= (s->ck_hi < s->ck_lo ? s->ck_lo : s->ck_hi);
    unpack(s, v, out);
}

/* ---- per pixel ---- */
static inline int cmp(int func, float a, float b) {
    switch (func) {
    case 1: return 0;                                    /* NEVER */
    case 2: return a < b;  case 3: return a == b; case 4: return a <= b;
    case 5: return a > b;  case 6: return a != b; case 7: return a >= b;
    default: return 1;                                   /* ALWAYS */
    }
}
static inline void factor(int f, const float s[4], const float d[4], float out[4]) {
    float sa = s[3], da = d[3];
    switch (f) {
    case 1: out[0] = out[1] = out[2] = out[3] = 0; break;                     /* ZERO */
    case 3: memcpy(out, s, 16); break;                                        /* SRCCOLOR */
    case 4: for (int i = 0; i < 4; i++) out[i] = 1 - s[i]; break;             /* INVSRCCOLOR */
    case 5: case 12: out[0] = out[1] = out[2] = out[3] = sa; break;           /* SRCALPHA, BOTHSRCALPHA */
    case 6: case 13: out[0] = out[1] = out[2] = out[3] = 1 - sa; break;       /* INVSRCALPHA, BOTHINV */
    case 7: out[0] = out[1] = out[2] = out[3] = da; break;
    case 8: out[0] = out[1] = out[2] = out[3] = 1 - da; break;
    case 9: memcpy(out, d, 16); break;                                        /* DESTCOLOR */
    case 10: for (int i = 0; i < 4; i++) out[i] = 1 - d[i]; break;
    case 11: { float f2 = sa < 1 - da ? sa : 1 - da; out[0] = out[1] = out[2] = f2; out[3] = 1; } break;
    default: out[0] = out[1] = out[2] = out[3] = 1; break;                    /* ONE */
    }
}
static inline void sample(const rstate_t *st, float u, float v, float out[4], int *keyed) {
    const surf_t *t = st->tex;
    int w = t->w, h = t->h;
    const uint32_t *px = t->argb;
    const uint8_t *kk = t->keyed;
    if (!st->bilinear) {
        int ix = (int)floorf(u * (float)w), iy = (int)floorf(v * (float)h);
        if (st->wrap_u) { ix %= w; if (ix < 0) ix += w; } else ix = ix < 0 ? 0 : ix >= w ? w - 1 : ix;
        if (st->wrap_v) { iy %= h; if (iy < 0) iy += h; } else iy = iy < 0 ? 0 : iy >= h ? h - 1 : iy;
        size_t i = (size_t)iy * (size_t)w + (size_t)ix;
        uint32_t c = px[i];
        out[0] = (float)((c >> 16) & 0xFF) * (1 / 255.f), out[1] = (float)((c >> 8) & 0xFF) * (1 / 255.f);
        out[2] = (float)(c & 0xFF) * (1 / 255.f), out[3] = (float)(c >> 24) * (1 / 255.f);
        *keyed = kk[i];
        return;
    }
    float x = u * (float)w - 0.5f, y = v * (float)h - 0.5f;
    int x0 = (int)floorf(x), y0 = (int)floorf(y);
    int fx = (int)((x - (float)x0) * 256.f), fy = (int)((y - (float)y0) * 256.f);
    int xs[2] = { x0, x0 + 1 }, ys[2] = { y0, y0 + 1 };
    for (int i = 0; i < 2; i++) {
        if (st->wrap_u) { xs[i] %= w; if (xs[i] < 0) xs[i] += w; } else xs[i] = xs[i] < 0 ? 0 : xs[i] >= w ? w - 1 : xs[i];
        if (st->wrap_v) { ys[i] %= h; if (ys[i] < 0) ys[i] += h; } else ys[i] = ys[i] < 0 ? 0 : ys[i] >= h ? h - 1 : ys[i];
    }
    size_t i0 = (size_t)ys[0] * (size_t)w, i1 = (size_t)ys[1] * (size_t)w;
    size_t id[4] = { i0 + (size_t)xs[0], i0 + (size_t)xs[1], i1 + (size_t)xs[0], i1 + (size_t)xs[1] };
    int wgt[4] = { (256 - fx) * (256 - fy), fx * (256 - fy), (256 - fx) * fy, fx * fy };
    /* A keyed texel counts as transparent black, so edges fade instead of fringing. */
    int acc[4] = { 0, 0, 0, 0 }, kw = 0;
    for (int k = 0; k < 4; k++) {
        if (kk[id[k]] && st->colorkey) { kw += wgt[k]; continue; }
        uint32_t c = px[id[k]];
        acc[0] += (int)((c >> 16) & 0xFF) * wgt[k], acc[1] += (int)((c >> 8) & 0xFF) * wgt[k];
        acc[2] += (int)(c & 0xFF) * wgt[k], acc[3] += (int)(c >> 24) * wgt[k];
    }
    const float sc = 1.0f / (255.f * 65536.f);
    for (int k = 0; k < 4; k++) out[k] = (float)acc[k] * sc;
    *keyed = kw > 32768;
}
/* Texture-stage arguments: 0 diffuse, 1 current, 2 texture, 3 tfactor; the
 * flags 0x10 complement and 0x20 alpha replicate. */
static inline void arg(int a, const float tex[4], const float dif[4], const float tf[4], float out[4]) {
    const float *src = (a & 0xF) == 2 ? tex : (a & 0xF) == 3 ? tf : dif;
    memcpy(out, src, 16);
    if (a & 0x20) out[0] = out[1] = out[2] = out[3];
    if (a & 0x10) for (int i = 0; i < 4; i++) out[i] = 1 - out[i];
}
static inline float op1(int op, float a, float b) {
    switch (op) {
    case 2: return a;                                    /* SELECTARG1 */
    case 3: return b;                                    /* SELECTARG2 */
    case 4: return a * b;                                /* MODULATE */
    case 5: { float r = a * b * 2; return r > 1 ? 1 : r; }
    case 6: { float r = a * b * 4; return r > 1 ? 1 : r; }
    case 7: { float r = a + b; return r > 1 ? 1 : r; }   /* ADD */
    case 8: { float r = a + b - 0.5f; return r < 0 ? 0 : r > 1 ? 1 : r; }
    case 10: return a - b < 0 ? 0 : a - b;               /* SUBTRACT */
    case 11: { float r = a + b - a * b; return r > 1 ? 1 : r; }   /* ADDSMOOTH */
    default: return b;                                   /* DISABLE: the current colour */
    }
}

static void shade(const rstate_t *st, int x, int y, float z, const float att[12]) {
    surf_t *t = st->target;
    /* depth */
    uint16_t *zp = NULL;
    if (st->zbuf && st->zenable) {
        zp = (uint16_t *)(st->zbuf->px + (size_t)y * (size_t)st->zbuf->pitch) + x;
        float zv = z < 0 ? 0 : z > 1 ? 1 : z;
        uint16_t zi = (uint16_t)(zv * 65535.f);
        if (!cmp(st->zfunc, (float)zi, (float)*zp)) return;
        if (!st->zwrite) zp = NULL;
        else z = (float)zi;
    }
    float dif[4] = { att[0], att[1], att[2], att[3] }, tex[4] = { 1, 1, 1, 1 }, col[4];
    int keyed = 0;
    if (st->tex) {
        sample(st, att[8], att[9], tex, &keyed);
        if (keyed && st->colorkey) return;
    }
    float a1[4], a2[4];
    if (st->tex && st->colorop != 1) {
        arg(st->colorarg1, tex, dif, st->tfactor, a1);
        arg(st->colorarg2, tex, dif, st->tfactor, a2);
        for (int i = 0; i < 3; i++) col[i] = op1(st->colorop, a1[i], a2[i]);
    } else {
        memcpy(col, dif, 12);
    }
    if (st->tex && st->alphaop != 1) {
        arg(st->alphaarg1, tex, dif, st->tfactor, a1);
        arg(st->alphaarg2, tex, dif, st->tfactor, a2);
        col[3] = op1(st->alphaop, a1[3], a2[3]);
    } else {
        col[3] = dif[3];
    }
    if (st->alphatest && !cmp(st->alphafunc, col[3] * 255.f, st->alpharef)) return;
    if (st->specular) for (int i = 0; i < 3; i++) { col[i] += att[4 + i]; if (col[i] > 1) col[i] = 1; }
    if (st->fog) {
        float f = att[7] < 0 ? 0 : att[7] > 1 ? 1 : att[7];
        col[0] = col[0] * f + st->fog_r * (1 - f);
        col[1] = col[1] * f + st->fog_g * (1 - f);
        col[2] = col[2] * f + st->fog_b * (1 - f);
    }
    if (st->blend) {
        float d[4], sf[4], df[4];
        fmt_unpack(&st->tfmt, raw(t, x, y), d);
        factor(st->srcblend, col, d, sf);
        factor(st->dstblend, col, d, df);
        if (st->srcblend == 12) for (int i = 0; i < 4; i++) df[i] = 1 - col[3];   /* BOTHSRCALPHA */
        if (st->srcblend == 13) for (int i = 0; i < 4; i++) df[i] = col[3];
        for (int i = 0; i < 4; i++) { col[i] = col[i] * sf[i] + d[i] * df[i]; if (col[i] > 1) col[i] = 1; }
    }
    put_raw(t, x, y, fmt_pack(&st->tfmt, col));
    if (zp) *zp = (uint16_t)z;
}

static inline float edge(float ax, float ay, float bx, float by, float px, float py) {
    return (bx - ax) * (py - ay) - (by - ay) * (px - ax);
}

void d3d_raster_triangle(const rstate_t *st, const rvert_t *a, const rvert_t *b, const rvert_t *c) {
    float area = edge(a->x, a->y, b->x, b->y, c->x, c->y);
    if (area == 0 || !isfinite(area)) return;
    /* Screen y runs down: a clockwise triangle has a positive area here. */
    if (st->cull == 2 && area > 0) return;
    if (st->cull == 3 && area < 0) return;
    if (area < 0) { const rvert_t *t = b; b = c; c = t; area = -area; }
    float minx = fminf(a->x, fminf(b->x, c->x)), maxx = fmaxf(a->x, fmaxf(b->x, c->x));
    float miny = fminf(a->y, fminf(b->y, c->y)), maxy = fmaxf(a->y, fmaxf(b->y, c->y));
    int x0 = (int)ceilf(minx - 0.5f), x1 = (int)ceilf(maxx - 0.5f);
    int y0 = (int)ceilf(miny - 0.5f), y1 = (int)ceilf(maxy - 0.5f);
    if (x0 < st->clip_l) x0 = st->clip_l;
    if (y0 < st->clip_t) y0 = st->clip_t;
    if (x1 > st->clip_r) x1 = st->clip_r;
    if (y1 > st->clip_b) y1 = st->clip_b;
    if (x0 >= x1 || y0 >= y1) return;
    /* What is interpolated, each divided by w (times rhw) so it is linear in
     * screen space; z is linear in screen space as it is. */
    const rvert_t *v[3] = { a, b, c };
    float att[3][12], rhw[3];
    for (int i = 0; i < 3; i++) {
        float q = v[i]->rhw > 0 && isfinite(v[i]->rhw) ? v[i]->rhw : 1.0f;
        const rvert_t *s = st->flat ? a : v[i];
        rhw[i] = q;
        float in[12] = { s->r, s->g, s->b, s->a, s->sr, s->sg, s->sb, v[i]->fog, v[i]->u, v[i]->v, 0, 0 };
        for (int k = 0; k < 10; k++) att[i][k] = in[k] * q;
    }
    float inv = 1.0f / area;
    /* Top-left fill rule: an edge's own pixels belong to it when it is a top
     * or a left edge; elsewhere a pixel exactly on it is skipped. */
    float bias[3];
    const rvert_t *e0[3] = { b, c, a }, *e1[3] = { c, a, b };
    for (int i = 0; i < 3; i++) {
        float dx = e1[i]->x - e0[i]->x, dy = e1[i]->y - e0[i]->y;
        int topleft = (dy < 0) || (dy == 0 && dx > 0);
        bias[i] = topleft ? 0 : -1e-6f;
    }
    /* Each edge function is linear in x: step it along the row. */
    float e0dx = -(c->y - b->y), e1dx = -(a->y - c->y), e2dx = -(b->y - a->y);
    for (int y = y0; y < y1; y++) {
        float py = (float)y + 0.5f, px = (float)x0 + 0.5f;
        float w0 = edge(b->x, b->y, c->x, c->y, px, py);
        float w1 = edge(c->x, c->y, a->x, a->y, px, py);
        float w2 = edge(a->x, a->y, b->x, b->y, px, py);
        for (int x = x0; x < x1; x++, w0 += e0dx, w1 += e1dx, w2 += e2dx) {
            if (w0 + bias[0] < 0 || w1 + bias[1] < 0 || w2 + bias[2] < 0) continue;
            float b0 = w0 * inv, b1 = w1 * inv, b2 = w2 * inv;
            float q = b0 * rhw[0] + b1 * rhw[1] + b2 * rhw[2];
            float rq = q != 0 ? 1.0f / q : 0, out[12];
            for (int k = 0; k < 10; k++) out[k] = (b0 * att[0][k] + b1 * att[1][k] + b2 * att[2][k]) * rq;
            shade(st, x, y, b0 * a->z + b1 * b->z + b2 * c->z, out);
        }
    }
}

void d3d_raster_line(const rstate_t *st, const rvert_t *a, const rvert_t *b) {
    float dx = b->x - a->x, dy = b->y - a->y;
    int n = (int)fmaxf(fabsf(dx), fabsf(dy));
    if (n <= 0 || n > 8192) return;
    for (int i = 0; i <= n; i++) {
        float t = (float)i / (float)n;
        int x = (int)(a->x + dx * t), y = (int)(a->y + dy * t);
        if (x < st->clip_l || x >= st->clip_r || y < st->clip_t || y >= st->clip_b) continue;
        float att[12] = { a->r + (b->r - a->r) * t, a->g + (b->g - a->g) * t, a->b + (b->b - a->b) * t,
                          a->a + (b->a - a->a) * t, a->sr, a->sg, a->sb, a->fog + (b->fog - a->fog) * t,
                          a->u + (b->u - a->u) * t, a->v + (b->v - a->v) * t, 0, 0 };
        shade(st, x, y, a->z + (b->z - a->z) * t, att);
    }
}

/* ---- deferred, banded, on every core ----
 * Triangles are recorded with their state, then drawn at a flush by a pool
 * of threads, each owning a horizontal band of the target and drawing every
 * triangle in order, clipped to its band: the result is the same as drawing
 * them one at a time, and each band's pixels have one writer. */
#include <pthread.h>
#include <unistd.h>

typedef struct { int state, line; rvert_t v[3]; } rcmd_t;
static rcmd_t *g_cmd;
static rstate_t *g_states;
static int g_ncmd, g_cap_cmd, g_nstate, g_cap_state;

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_go = PTHREAD_COND_INITIALIZER, g_done = PTHREAD_COND_INITIALIZER;
static int g_nthreads, g_job, g_pending, g_top, g_height;

static void run_band(int band) {
    int bands = g_nthreads + 1;
    int y0 = g_top + g_height * band / bands, y1 = g_top + g_height * (band + 1) / bands;
    rstate_t st;
    int last = -1;
    for (int i = 0; i < g_ncmd; i++) {
        const rcmd_t *c = &g_cmd[i];
        if (c->state != last) {
            st = g_states[c->state];
            if (st.clip_t < y0) st.clip_t = y0;
            if (st.clip_b > y1) st.clip_b = y1;
            last = c->state;
        }
        if (st.clip_t >= st.clip_b) continue;
        if (c->line) d3d_raster_line(&st, &c->v[0], &c->v[1]);
        else d3d_raster_triangle(&st, &c->v[0], &c->v[1], &c->v[2]);
    }
}
static void *worker(void *arg) {
    int band = (int)(intptr_t)arg, seen = 0;
    for (;;) {
        pthread_mutex_lock(&g_mu);
        while (g_job == seen) pthread_cond_wait(&g_go, &g_mu);
        seen = g_job;
        pthread_mutex_unlock(&g_mu);
        run_band(band);
        pthread_mutex_lock(&g_mu);
        if (--g_pending == 0) pthread_cond_signal(&g_done);
        pthread_mutex_unlock(&g_mu);
    }
    return NULL;
}
static void pool(void) {
    if (g_nthreads) return;
#ifdef __EMSCRIPTEN__
    long n = 1;                                          /* a browser's worker pool is fixed at load: draw here */
#else
    long n = sysconf(_SC_NPROCESSORS_ONLN);
#endif
    const char *e = getenv("HLE_D3DTHREADS");
    if (e) n = atol(e);
    if (n < 1) n = 1;
    if (n > 16) n = 16;
    g_nthreads = (int)n - 1;                             /* the caller draws a band too */
    for (int i = 0; i < g_nthreads; i++) {
        pthread_t t;
        pthread_create(&t, NULL, worker, (void *)(intptr_t)(i + 1));
        pthread_detach(t);
    }
}

static int push_state(const rstate_t *st) {
    if (g_nstate && !memcmp(&g_states[g_nstate - 1], st, sizeof *st)) return g_nstate - 1;
    if (g_nstate == g_cap_state) {
        g_cap_state = g_cap_state ? g_cap_state * 2 : 256;
        g_states = (rstate_t *)realloc(g_states, sizeof *g_states * (size_t)g_cap_state);
    }
    g_states[g_nstate] = *st;
    return g_nstate++;
}
static rcmd_t *push_cmd(const rstate_t *st, int line) {
    if (g_ncmd == g_cap_cmd) {
        g_cap_cmd = g_cap_cmd ? g_cap_cmd * 2 : 4096;
        g_cmd = (rcmd_t *)realloc(g_cmd, sizeof *g_cmd * (size_t)g_cap_cmd);
    }
    rcmd_t *c = &g_cmd[g_ncmd++];
    c->state = push_state(st), c->line = line;
    return c;
}
void d3d_raster_submit_triangle(const rstate_t *st, const rvert_t *a, const rvert_t *b, const rvert_t *c) {
    rcmd_t *k = push_cmd(st, 0);
    k->v[0] = *a, k->v[1] = *b, k->v[2] = *c;
}
void d3d_raster_submit_line(const rstate_t *st, const rvert_t *a, const rvert_t *b) {
    rcmd_t *k = push_cmd(st, 1);
    k->v[0] = *a, k->v[1] = *b;
}
void d3d_raster_flush(void) {
    if (!g_ncmd) return;
    pool();
    int top = 1 << 30, bottom = 0;
    for (int i = 0; i < g_nstate; i++) {
        if (g_states[i].clip_t < top) top = g_states[i].clip_t;
        if (g_states[i].clip_b > bottom) bottom = g_states[i].clip_b;
    }
    g_top = top, g_height = bottom > top ? bottom - top : 0;
    if (g_nthreads && g_height >= 64) {
        pthread_mutex_lock(&g_mu);
        g_pending = g_nthreads;
        g_job++;
        pthread_cond_broadcast(&g_go);
        pthread_mutex_unlock(&g_mu);
        run_band(0);
        pthread_mutex_lock(&g_mu);
        while (g_pending) pthread_cond_wait(&g_done, &g_mu);
        pthread_mutex_unlock(&g_mu);
    } else {
        int keep = g_nthreads;
        g_nthreads = 0;                                  /* one band: all of it */
        run_band(0);
        g_nthreads = keep;
    }
    g_ncmd = 0, g_nstate = 0;
}

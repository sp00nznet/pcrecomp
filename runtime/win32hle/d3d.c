/*
 * d3d.c - Direct3D as DirectX 6 has it (IDirect3D3, IDirect3DDevice3 and
 * their viewports, materials, textures and vertex buffers), drawn in
 * software by d3d_raster.c into the DirectDraw surfaces of ddraw.c.
 *
 * One device is offered, a "HAL" with hardware rasterisation as a 1999 game
 * expects to find, and texture formats 565, 1555, 4444 and 8888. Vertices
 * come pre-transformed (D3DFVF_XYZRHW) or not (D3DFVF_XYZ: world, view and
 * projection applied here, without lighting); triangles go to the
 * rasteriser in screen space.
 *
 * HLE_D3DTRACE=1 prints every call.
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "win32hle.h"
#include "ddraw_int.h"
#include "d3d_raster.h"
#include "d3d_gpu.h"

#define D3D_OK              0u
#define DDERR_INVALIDPARAMS 0x80070057u
#define E_NOINTERFACE       0x80004002u
#define D3DERR_NOTFOUND     0x887602A0u   /* DDERR_NOTFOUND */

static int g_trace = -1;
static int trace(void) { if (g_trace < 0) g_trace = getenv("HLE_D3DTRACE") != NULL; return g_trace; }
#define T(...) do { if (trace()) fprintf(stderr, "[d3d] " __VA_ARGS__); } while (0)

static uint32_t g_vt_d3d, g_vt_dev, g_vt_vp, g_vt_tex, g_vt_mat, g_vt_vb, g_vt_light;
static uint32_t g_d3d;                                   /* the one IDirect3D3 */

/* The renderer: a GPU's (d3d_gpu.h), else the software rasteriser. */
const d3d_gpu_t *hle_d3d_gpu;
static void flush(void) { if (hle_d3d_gpu) hle_d3d_gpu->sync(); else d3d_raster_flush(); }
static void tri(const rstate_t *st, const rvert_t *a, const rvert_t *b, const rvert_t *c) {
    if (hle_d3d_gpu) hle_d3d_gpu->triangle(st, a, b, c); else d3d_raster_submit_triangle(st, a, b, c);
}
static void line(const rstate_t *st, const rvert_t *a, const rvert_t *b) {
    if (hle_d3d_gpu) hle_d3d_gpu->line(st, a, b); else d3d_raster_submit_line(st, a, b);
}

/* ---- the device ---- */
#define NRS 256
#define NTSS 32
typedef struct {
    uint32_t self, target;                               /* the render target's surface object */
    uint32_t rs[NRS];
    uint32_t tss[2][NTSS];
    uint32_t tex[2];                                     /* IDirect3DTexture2 objects */
    uint32_t viewport;                                   /* current IDirect3DViewport3 */
    float world[16], view[16], proj[16];
    int scene;
    uint32_t prims, tris;
} d3ddev_t;
typedef struct {
    uint32_t self, device;
    int x, y, w, h;
    float cx, cy, cw, ch, minz, maxz;                    /* the clip volume (D3DVIEWPORT2) */
    uint32_t background;                                 /* a material handle */
} vp_t;
typedef struct { uint32_t self, surface; } tex_t;
typedef struct { uint32_t self; float diffuse[4]; } mat_t;
typedef struct { uint32_t self, fvf, count, size; uint8_t *data; } vb_t;

#define DEV(o) ((d3ddev_t *)hle_ptr(MEM32((o) + 8)))
#define VP(o)  ((vp_t *)hle_ptr(MEM32((o) + 8)))
#define TEX(o) ((tex_t *)hle_ptr(MEM32((o) + 8)))
#define MAT(o) ((mat_t *)hle_ptr(MEM32((o) + 8)))
#define VB(o)  ((vb_t *)hle_ptr(MEM32((o) + 8)))

static uint32_t new_obj(uint32_t vt, uint32_t state) {
    uint32_t o = hle_com_new(vt, 12);
    MEM32(o + 8) = state;
    return o;
}
static void identity(float *m) { memset(m, 0, 64); m[0] = m[5] = m[10] = m[15] = 1; }
static float fl(uint32_t v) { float f; memcpy(&f, &v, 4); return f; }

/* ---- the device description: a HAL with hardware rasterisation ---- */
static void put_primcaps(uint32_t p) {
    MEM32(p) = 56;
    MEM32(p + 4) = 0x00000002u | 0x00000004u | 0x00000008u | 0x00000010u;   /* MASKZ, LINEPATTERNREP, CULLNONE/CW/CCW */
    MEM32(p + 8) = 0x00000001u | 0x00000010u | 0x00000020u | 0x00000080u | 0x00000100u | 0x00002000u
                 | 0x00004000u | 0x00100000u | 0x00200000u;               /* DITHER ZTEST SUBPIXEL FOGVERTEX FOGTABLE LODBIAS ZBIAS WFOG ZFOG */
    MEM32(p + 12) = 0xFF;                                                     /* every z compare */
    MEM32(p + 16) = 0x1FFF, MEM32(p + 20) = 0x1FFF;                          /* every blend */
    MEM32(p + 24) = 0xFF;                                                     /* every alpha compare */
    MEM32(p + 28) = 0x00000008u | 0x00000200u | 0x00004000u | 0x00080000u;  /* gouraud RGB, specular, alpha, fog */
    MEM32(p + 32) = 0x00000001u | 0x00000002u | 0x00000004u | 0x00000008u | 0x00000040u;   /* PERSPECTIVE POW2 ALPHA TRANSPARENCY SQUAREONLY */
    MEM32(p + 36) = 0x0303033Fu;                                             /* nearest, linear, mipmaps */
    MEM32(p + 40) = 0xFF;                                                     /* every legacy texture blend */
    MEM32(p + 44) = 0x0F;                                                     /* wrap, mirror, clamp, border */
}
static void put_devdesc(uint32_t d, int hal) {
    uint32_t size = MEM32(d) ? MEM32(d) : 252;
    if (size > 252) size = 252;
    memset(hle_ptr(d + 4), 0, size - 4);
    if (!hal) return;                                    /* the HEL: nothing in software, the HAL does it all */
    MEM32(d + 4) = 0x7FF;                                /* every field valid */
    MEM32(d + 8) = 2;                                    /* D3DCOLOR_RGB */
    MEM32(d + 12) = 0x00000001u | 0x00000010u | 0x00000040u | 0x00000100u | 0x00000200u | 0x00000400u
                  | 0x00000800u | 0x00002000u | 0x00080000u;                 /* float TL, system/video memory, drawprimitive(2), HW raster */
    MEM32(d + 16) = 8, MEM32(d + 20) = 1;               /* transform caps: clip */
    MEM32(d + 24) = 1;                                   /* bClipping */
    MEM32(d + 28) = 16, MEM32(d + 32) = 7, MEM32(d + 36) = 2, MEM32(d + 40) = 8;   /* lighting caps */
    put_primcaps(d + 44);
    put_primcaps(d + 100);
    MEM32(d + 156) = 0x00000400u | 0x00000100u;          /* DDBD_16, DDBD_32 */
    MEM32(d + 160) = 0x00000400u;                        /* a 16-bit z-buffer */
    MEM32(d + 164) = 0, MEM32(d + 168) = 65535;
    if (size >= 252) {
        MEM32(d + 172) = 1, MEM32(d + 176) = 1, MEM32(d + 180) = 2048, MEM32(d + 184) = 2048;
        MEM32(d + 204) = 2048, MEM32(d + 208) = 2048, MEM32(d + 212) = 1;
        float gb[4] = { -2048, -2048, 2048, 2048 };
        memcpy(hle_ptr(d + 216), gb, 16);
        MEM32(d + 240) = 0x00080001u;                    /* FVF: one texture coordinate set, do not strip elements */
        MEM32(d + 244) = 0x0001FFFFu;                    /* the common texture ops */
        MEM16(d + 248) = 2, MEM16(d + 250) = 1;          /* blend stages, simultaneous textures */
    }
}

/* ---- pixel formats offered ---- */
static void put_pixfmt(uint32_t pf, uint32_t flags, int bits, uint32_t r, uint32_t g, uint32_t b, uint32_t a) {
    memset(hle_ptr(pf), 0, 32);
    MEM32(pf) = 32, MEM32(pf + 4) = flags, MEM32(pf + 12) = (uint32_t)bits;
    MEM32(pf + 16) = r, MEM32(pf + 20) = g, MEM32(pf + 24) = b, MEM32(pf + 28) = a;
}

/* ---- IDirect3D3 ---- */
static void d3_QueryInterface(void) {
    uint32_t d1 = MEM32(A32(1));
    if (d1 == 0 || d1 == 0xBB223240u) { MEM32(A32(2)) = A32(0); MEM32(A32(0) + 4)++; RET(D3D_OK, 3); }
    char s[40];
    hle_guid_string((const uint8_t *)APTR(1), s);
    T("IDirect3D3::QueryInterface %s: not served\n", s);
    MEM32(A32(2)) = 0;
    RET(E_NOINTERFACE, 3);
}
static void d3_Release(void) { uint32_t n = MEM32(A32(0) + 4) ? --MEM32(A32(0) + 4) : 0; RET(n, 1); }
static const uint8_t IID_HAL[16] = { 0xE0, 0x3D, 0xE6, 0x84, 0xAA, 0x46, 0xCF, 0x11, 0x81, 0x6F, 0x00, 0x00, 0xC0, 0x20, 0x15, 0x6E };
static void d3_EnumDevices(void) {                       /* (this, callback, ctx) */
    static uint32_t guid, desc, name;
    if (!guid) {
        guid = hle_va(hle_alloc(16)), memcpy(hle_ptr(guid), IID_HAL, 16);
        desc = hle_guest_strdup("Direct3D HAL"), name = hle_guest_strdup("Direct3D HAL");
    }
    uint32_t mark = hle_scratch_mark(), hal = hle_scratch(252), hel = hle_scratch(252);
    MEM32(hal) = MEM32(hel) = 252;
    put_devdesc(hal, 1);
    put_devdesc(hel, 0);
    uint32_t a[6] = { guid, desc, name, hal, hel, A32(2) };
    T("EnumDevices -> 0x%08X\n", A32(1));
    hle_call_guest(A32(1), 6, a);
    hle_scratch_release(mark);
    RET(D3D_OK, 3);
}
static void d3_FindDevice(void) {                        /* (this, search, result) */
    uint32_t r = A32(2);
    if (!r) RET(DDERR_INVALIDPARAMS, 3);
    memcpy(hle_ptr(r + 4), IID_HAL, 16);
    MEM32(r + 20) = 252, put_devdesc(r + 20, 1);
    MEM32(r + 20 + 252) = 252, put_devdesc(r + 20 + 252, 0);
    RET(D3D_OK, 3);
}
static void dev_reset(d3ddev_t *d) {
    memset(d->rs, 0, sizeof d->rs);
    memset(d->tss, 0, sizeof d->tss);
    d->rs[7] = 1;                                        /* ZENABLE: on with a z-buffer */
    d->rs[8] = 3, d->rs[9] = 2;                          /* FILLMODE solid, SHADEMODE gouraud */
    d->rs[14] = 1;                                       /* ZWRITEENABLE */
    d->rs[17] = 1, d->rs[18] = 1;                        /* TEXTUREMAG, TEXTUREMIN: nearest */
    d->rs[19] = 2, d->rs[20] = 1;                        /* SRCBLEND one, DESTBLEND zero */
    d->rs[22] = 3;                                       /* CULLMODE ccw */
    d->rs[23] = 4;                                       /* ZFUNC lessequal */
    d->rs[25] = 8;                                       /* ALPHAFUNC always */
    d->rs[44] = d->rs[45] = 1;                           /* TEXTUREADDRESSU/V wrap */
    d->rs[137] = 1;                                      /* LIGHTING */
    for (int s = 0; s < 2; s++) {
        d->tss[s][1] = s == 0 ? 4 : 1;                   /* COLOROP: modulate, then disable */
        d->tss[s][2] = 2, d->tss[s][3] = 1;              /* COLORARG1 texture, COLORARG2 current */
        d->tss[s][4] = s == 0 ? 2 : 1;                   /* ALPHAOP: select arg1 */
        d->tss[s][5] = 2, d->tss[s][6] = 1;
        d->tss[s][13] = d->tss[s][14] = 1;               /* ADDRESSU/V wrap */
        d->tss[s][16] = d->tss[s][17] = d->tss[s][18] = 1;   /* MAG/MIN point, MIP none */
    }
    identity(d->world), identity(d->view), identity(d->proj);
}
static void d3_CreateDevice(void) {                      /* (this, guid, surface, &device, outer) */
    d3ddev_t *d = (d3ddev_t *)hle_alloc(sizeof *d);
    dev_reset(d);
    d->target = A32(2);
    if (A32(2)) MEM32(A32(2) + 4)++;
    surf_t *t = hle_dd_surf(A32(2));
    if (t && !t->zbuf) d->rs[7] = 0;
    uint32_t o = new_obj(g_vt_dev, hle_va(d));
    d->self = o;
    if (!hle_d3d_gpu) hle_dd_access_hook = d3d_raster_flush;   /* DirectDraw touching any surface: draw what is queued first */
    T("CreateDevice on 0x%08X (%dx%d, z-buffer %s) -> 0x%08X\n", A32(2), t ? t->w : 0, t ? t->h : 0,
      t && t->zbuf ? "yes" : "no", o);
    fprintf(stderr, "[d3d] CreateDevice %dx%d%s\n", t ? t->w : 0, t ? t->h : 0, t && t->zbuf ? " with a z-buffer" : "");
    MEM32(A32(3)) = o;
    RET(D3D_OK, 5);
}
static void d3_CreateViewport(void) {                    /* (this, &vp, outer) */
    vp_t *v = (vp_t *)hle_alloc(sizeof *v);
    v->cx = -1, v->cy = 1, v->cw = 2, v->ch = 2, v->maxz = 1;
    uint32_t o = new_obj(g_vt_vp, hle_va(v));
    v->self = o;
    MEM32(A32(1)) = o;
    RET(D3D_OK, 3);
}
static void d3_CreateMaterial(void) {
    mat_t *m = (mat_t *)hle_alloc(sizeof *m);
    uint32_t o = new_obj(g_vt_mat, hle_va(m));
    m->self = o;
    MEM32(A32(1)) = o;
    RET(D3D_OK, 3);
}
static void d3_CreateLight(void) { MEM32(A32(1)) = new_obj(g_vt_light, 0); RET(D3D_OK, 3); }
static uint32_t fvf_size(uint32_t fvf) {
    uint32_t n = 0;
    switch (fvf & 0x00E) {
    case 0x002: n = 12; break;                           /* XYZ */
    case 0x004: n = 16; break;                           /* XYZRHW */
    case 0x006: n = 16; break; case 0x008: n = 20; break; case 0x00A: n = 24; break;
    case 0x00C: n = 28; break; case 0x00E: n = 32; break;
    }
    if (fvf & 0x010) n += 12;                            /* NORMAL */
    if (fvf & 0x020) n += 4;                             /* RESERVED1 */
    if (fvf & 0x040) n += 4;                             /* DIFFUSE */
    if (fvf & 0x080) n += 4;                             /* SPECULAR */
    n += 8u * ((fvf >> 8) & 0xF);                        /* two floats a texture coordinate set */
    return n;
}
static void d3_CreateVertexBuffer(void) {                /* (this, &desc, &vb, flags, outer) */
    uint32_t desc = A32(1);
    vb_t *v = (vb_t *)hle_alloc(sizeof *v);
    v->fvf = MEM32(desc + 8), v->count = MEM32(desc + 12);
    v->size = fvf_size(v->fvf) * v->count;
    v->data = (uint8_t *)hle_alloc(v->size + 16);
    uint32_t o = new_obj(g_vt_vb, hle_va(v));
    v->self = o;
    MEM32(A32(2)) = o;
    RET(D3D_OK, 5);
}
static void d3_EnumZBufferFormats(void) {                /* (this, guid, callback, ctx) */
    uint32_t mark = hle_scratch_mark(), pf = hle_scratch(32);
    put_pixfmt(pf, 0x400, 16, 0, 0xFFFF, 0, 0);          /* DDPF_ZBUFFER, 16 bits */
    uint32_t a[2] = { pf, A32(3) };
    hle_call_guest(A32(2), 2, a);
    hle_scratch_release(mark);
    RET(D3D_OK, 4);
}
static void d3_EvictManagedTextures(void) { RET(D3D_OK, 1); }

/* ---- textures: a surface's other face ---- */
#define MAX_TEX 4096
static uint32_t g_tex_surf[MAX_TEX], g_tex_obj[MAX_TEX];
static int g_ntex;
static uint32_t texture_for(uint32_t surface) {
    for (int i = 0; i < g_ntex; i++) if (g_tex_surf[i] == surface) { MEM32(g_tex_obj[i] + 4)++; return g_tex_obj[i]; }
    tex_t *t = (tex_t *)hle_alloc(sizeof *t);
    t->surface = surface;
    uint32_t o = new_obj(g_vt_tex, hle_va(t));
    t->self = o;
    MEM32(surface + 4)++;                                /* the texture holds its surface */
    if (g_ntex < MAX_TEX) g_tex_surf[g_ntex] = surface, g_tex_obj[g_ntex++] = o;
    return o;
}
static void tx_Release(void) {
    uint32_t self = A32(0), n = --MEM32(self + 4);
    if (!n) {
        tex_t *t = TEX(self);
        for (int i = 0; i < g_ntex; i++) if (g_tex_obj[i] == self) { g_tex_obj[i] = g_tex_obj[--g_ntex]; g_tex_surf[i] = g_tex_surf[g_ntex]; break; }
        uint32_t s = t->surface;
        hle_free(t);
        hle_com_free(self);
        if (MEM32(s + 4) > 1) MEM32(s + 4)--;            /* the hold on the surface; the game's own Release frees it */
    }
    RET(n, 1);
}
static void tx_QueryInterface(void) {                    /* the texture, or the surface it is */
    tex_t *t = TEX(A32(0));
    uint32_t d1 = MEM32(A32(1));
    if (d1 == 0x93281502u) { MEM32(A32(2)) = A32(0); MEM32(A32(0) + 4)++; RET(D3D_OK, 3); }
    if (d1 == 0 || d1 == 0x6C14DB81u || d1 == 0x57805885u || d1 == 0xDA044E00u || d1 == 0x0B2B8630u) {
        MEM32(A32(2)) = t->surface; MEM32(t->surface + 4)++; RET(D3D_OK, 3);
    }
    MEM32(A32(2)) = 0;
    RET(E_NOINTERFACE, 3);
}
static void tx_GetHandle(void) { if (A32(2)) MEM32(A32(2)) = A32(0); RET(D3D_OK, 3); }   /* the handle is the object */
static void tx_PaletteChanged(void) { RET(D3D_OK, 3); }
static void tx_Load(void) {                              /* (this, source texture): copy its pixels, every level */
    flush();
    surf_t *d = hle_dd_surf(TEX(A32(0))->surface), *s = A32(1) ? hle_dd_surf(TEX(A32(1))->surface) : NULL;
    for (; d && s; d = d->mip, s = s->mip) {
        int rows = d->h < s->h ? d->h : s->h, bytes = (d->w < s->w ? d->w : s->w) * (d->bpp / 8);
        for (int y = 0; y < rows; y++)
            memcpy(d->px + (size_t)y * (size_t)d->pitch, s->px + (size_t)y * (size_t)s->pitch, (size_t)bytes);
        d->ck_src = s->ck_src, d->ck_lo = s->ck_lo, d->ck_hi = s->ck_hi;
        d->gen++;
        if (s->palette && !d->palette) d->palette = s->palette, MEM32(s->palette + 4)++;
    }
    RET(D3D_OK, 2);
}
/* IDirectDrawSurface::QueryInterface's answer for IID_IDirect3DTexture2,
 * and IDirectDraw's for IID_IDirect3D3 (ddraw.c). */
uint32_t hle_d3d_surface_query(uint32_t surface, const uint8_t *iid);
uint32_t hle_d3d_query(const uint8_t *iid);

/* ---- materials and lights ---- */
static void mt_Release(void) {
    uint32_t self = A32(0), n = --MEM32(self + 4);
    if (!n) { hle_free(MAT(self)); hle_com_free(self); }
    RET(n, 1);
}
static void mt_SetMaterial(void) {                       /* D3DMATERIAL: size, then diffuse r, g, b, a */
    mat_t *m = MAT(A32(0));
    for (int i = 0; i < 4; i++) m->diffuse[i] = fl(MEM32(A32(1) + 4 + 4 * (uint32_t)i));
    RET(D3D_OK, 2);
}
static void mt_GetMaterial(void) {
    mat_t *m = MAT(A32(0));
    for (int i = 0; i < 4; i++) memcpy(hle_ptr(A32(1) + 4 + 4 * (uint32_t)i), &m->diffuse[i], 4);
    RET(D3D_OK, 2);
}
static void mt_GetHandle(void) { if (A32(2)) MEM32(A32(2)) = A32(0); RET(D3D_OK, 3); }
static void lt_Release(void) { uint32_t self = A32(0), n = --MEM32(self + 4); if (!n) hle_com_free(self); RET(n, 1); }
static void ok1(void) { RET(D3D_OK, 1); }
static void ok2(void) { RET(D3D_OK, 2); }
static void ok3(void) { RET(D3D_OK, 3); }
static void ok4(void) { RET(D3D_OK, 4); }
static void ok5(void) { RET(D3D_OK, 5); }

/* ---- viewports ---- */
static void vp_Release(void) {
    uint32_t self = A32(0), n = --MEM32(self + 4);
    if (!n) { hle_free(VP(self)); hle_com_free(self); }
    RET(n, 1);
}
static void vp_GetViewport2(void) {                      /* D3DVIEWPORT2 */
    vp_t *v = VP(A32(0));
    uint32_t p = A32(1);
    MEM32(p + 4) = (uint32_t)v->x, MEM32(p + 8) = (uint32_t)v->y, MEM32(p + 12) = (uint32_t)v->w, MEM32(p + 16) = (uint32_t)v->h;
    float f[6] = { v->cx, v->cy, v->cw, v->ch, v->minz, v->maxz };
    memcpy(hle_ptr(p + 20), f, 24);
    RET(D3D_OK, 2);
}
static void vp_SetViewport2(void) {
    vp_t *v = VP(A32(0));
    uint32_t p = A32(1);
    v->x = (int)MEM32(p + 4), v->y = (int)MEM32(p + 8), v->w = (int)MEM32(p + 12), v->h = (int)MEM32(p + 16);
    v->cx = fl(MEM32(p + 20)), v->cy = fl(MEM32(p + 24)), v->cw = fl(MEM32(p + 28)), v->ch = fl(MEM32(p + 32));
    v->minz = fl(MEM32(p + 36)), v->maxz = fl(MEM32(p + 40));
    if (v->maxz <= v->minz) v->minz = 0, v->maxz = 1;
    T("SetViewport2 %d,%d %dx%d z %.2f..%.2f\n", v->x, v->y, v->w, v->h, v->minz, v->maxz);
    RET(D3D_OK, 2);
}
static void vp_SetViewport(void) {                       /* D3DVIEWPORT: the old one, scale-based */
    vp_t *v = VP(A32(0));
    uint32_t p = A32(1);
    v->x = (int)MEM32(p + 4), v->y = (int)MEM32(p + 8), v->w = (int)MEM32(p + 12), v->h = (int)MEM32(p + 16);
    v->cx = -1, v->cy = 1, v->cw = 2, v->ch = 2;
    v->minz = fl(MEM32(p + 36)), v->maxz = fl(MEM32(p + 40));
    if (v->maxz <= v->minz) v->minz = 0, v->maxz = 1;
    RET(D3D_OK, 2);
}
static void vp_GetViewport(void) { vp_GetViewport2(); }
static void vp_SetBackground(void) { VP(A32(0))->background = A32(1); RET(D3D_OK, 2); }
static void vp_GetBackground(void) { if (A32(1)) MEM32(A32(1)) = VP(A32(0))->background; if (A32(2)) MEM32(A32(2)) = 1; RET(D3D_OK, 3); }
static void vp_GetBackgroundDepth(void) { if (A32(1)) MEM32(A32(1)) = 0; if (A32(2)) MEM32(A32(2)) = 0; RET(D3D_OK, 3); }
static void clear(vp_t *v, uint32_t nrects, uint32_t rects, uint32_t flags, uint32_t argb, float z) {
    if (!hle_d3d_gpu) flush();
    d3ddev_t *d = v->device ? DEV(v->device) : NULL;
    surf_t *t = d ? hle_dd_surf(d->target) : NULL;
    if (!t) return;
    for (uint32_t i = 0; i < (nrects ? nrects : 1); i++) {
        int l = v->x, tp = v->y, r = v->x + v->w, b = v->y + v->h;
        if (nrects && rects) l = (int)MEM32(rects + 16 * i), tp = (int)MEM32(rects + 16 * i + 4),
                             r = (int)MEM32(rects + 16 * i + 8), b = (int)MEM32(rects + 16 * i + 12);
        if (l < 0) l = 0;
        if (tp < 0) tp = 0;
        if (r > t->w) r = t->w;
        if (b > t->h) b = t->h;
        if (hle_d3d_gpu) {
            if (l < r && tp < b) hle_d3d_gpu->clear(t, l, tp, r, b, flags & 3, argb, z);
            continue;
        }
        if (flags & 1) {                                 /* D3DCLEAR_TARGET */
            uint32_t c = d3d_pack(t, (float)((argb >> 16) & 0xFF) / 255.f, (float)((argb >> 8) & 0xFF) / 255.f,
                                  (float)(argb & 0xFF) / 255.f, (float)(argb >> 24) / 255.f);
            for (int y = tp; y < b; y++)
                for (int x = l; x < r; x++) {
                    uint8_t *p = t->px + (size_t)y * (size_t)t->pitch;
                    if (t->bpp == 16) ((uint16_t *)p)[x] = (uint16_t)c; else if (t->bpp == 32) ((uint32_t *)p)[x] = c;
                }
        }
        if ((flags & 2) && t->zbuf) {                    /* D3DCLEAR_ZBUFFER */
            surf_t *zb = t->zbuf;
            uint16_t zv = (uint16_t)((z < 0 ? 0 : z > 1 ? 1 : z) * 65535.f);
            for (int y = tp; y < b && y < zb->h; y++)
                for (int x = l; x < r && x < zb->w; x++) ((uint16_t *)(zb->px + (size_t)y * (size_t)zb->pitch))[x] = zv;
        }
    }
    if (!hle_d3d_gpu) hle_dd_mark(t);
}
static void vp_Clear(void) {                             /* (this, count, rects, flags): the background material */
    vp_t *v = VP(A32(0));
    uint32_t argb = 0;
    if (v->background) {
        mat_t *m = MAT(v->background);
        argb = (uint32_t)(m->diffuse[3] * 255) << 24 | (uint32_t)(m->diffuse[0] * 255) << 16 |
               (uint32_t)(m->diffuse[1] * 255) << 8 | (uint32_t)(m->diffuse[2] * 255);
    }
    clear(v, A32(1), A32(2), A32(3), argb, 1.0f);
    RET(D3D_OK, 4);
}
static void vp_Clear2(void) {                            /* (this, count, rects, flags, color, z, stencil) */
    clear(VP(A32(0)), A32(1), A32(2), A32(3), A32(4), fl(A32(5)));
    RET(D3D_OK, 7);
}
static void vp_NextLight(void) { if (A32(2)) MEM32(A32(2)) = 0; RET(D3DERR_NOTFOUND, 4); }

/* ---- the device's methods ---- */
static void dv_QueryInterface(void) {
    uint32_t d1 = MEM32(A32(1));
    if (d1 == 0 || d1 == 0xB0AB3B60u) { MEM32(A32(2)) = A32(0); MEM32(A32(0) + 4)++; RET(D3D_OK, 3); }
    MEM32(A32(2)) = 0;
    RET(E_NOINTERFACE, 3);
}
static void dv_Release(void) {
    uint32_t self = A32(0), n = --MEM32(self + 4);
    if (!n) { hle_free(DEV(self)); hle_com_free(self); }
    RET(n, 1);
}
static void dv_GetCaps(void) { if (A32(1)) put_devdesc(A32(1), 1); if (A32(2)) put_devdesc(A32(2), 0); RET(D3D_OK, 3); }
static void dv_GetStats(void) { RET(D3D_OK, 2); }
static void dv_AddViewport(void) {
    vp_t *v = VP(A32(1));
    v->device = A32(0);
    MEM32(A32(1) + 4)++;
    if (!DEV(A32(0))->viewport) DEV(A32(0))->viewport = A32(1);
    RET(D3D_OK, 2);
}
static void dv_DeleteViewport(void) { if (DEV(A32(0))->viewport == A32(1)) DEV(A32(0))->viewport = 0; RET(D3D_OK, 2); }
static void dv_NextViewport(void) { if (A32(2)) MEM32(A32(2)) = 0; RET(D3DERR_NOTFOUND, 4); }
static void dv_EnumTextureFormats(void) {                /* (this, callback, ctx) */
    static const uint32_t f[][6] = {
        { 0x40, 16, 0xF800, 0x07E0, 0x001F, 0 },                         /* RGB 565 */
        { 0x41, 16, 0x7C00, 0x03E0, 0x001F, 0x8000 },                   /* ARGB 1555 */
        { 0x41, 16, 0x0F00, 0x00F0, 0x000F, 0xF000 },                   /* ARGB 4444 */
        { 0x41, 32, 0xFF0000, 0xFF00, 0xFF, 0xFF000000u },              /* ARGB 8888 */
    };
    uint32_t mark = hle_scratch_mark(), pf = hle_scratch(32);
    for (int i = 0; i < 4; i++) {
        put_pixfmt(pf, f[i][0], (int)f[i][1], f[i][2], f[i][3], f[i][4], f[i][5]);
        uint32_t a[2] = { pf, A32(2) };
        if (!hle_call_guest(A32(1), 2, a)) break;        /* D3DENUMRET_CANCEL */
    }
    hle_scratch_release(mark);
    RET(D3D_OK, 3);
}
static void dv_BeginScene(void) { DEV(A32(0))->scene = 1; RET(D3D_OK, 1); }
static void dv_EndScene(void) {
    d3ddev_t *d = DEV(A32(0));
    d->scene = 0;
    if (hle_d3d_gpu) hle_d3d_gpu->end_scene(hle_dd_surf(d->target)); else d3d_raster_flush();
    static int fps = -1;
    static uint32_t t0, frames, tris0;
    if (fps < 0) fps = getenv("HLE_D3DFPS") != NULL;
    if (fps) {                                           /* HLE_D3DFPS: scenes a second, every five */
        uint32_t now = hle_ticks_ms();
        frames++;
        if (!t0) t0 = now, tris0 = d->tris;
        else if (now - t0 >= 5000) {
            fprintf(stderr, "[d3d] %.1f scenes/s, %u triangles a scene\n", frames * 1000.0 / (now - t0),
                    frames ? (d->tris - tris0) / frames : 0);
            t0 = now, frames = 0, tris0 = d->tris;
        }
    }
    surf_t *t = hle_dd_surf(d->target);
    if (t && !hle_d3d_gpu) hle_dd_mark(t);
    RET(D3D_OK, 1);
}
static void dv_GetDirect3D(void) { MEM32(A32(1)) = g_d3d; MEM32(g_d3d + 4)++; RET(D3D_OK, 2); }
static void dv_SetCurrentViewport(void) { DEV(A32(0))->viewport = A32(1); if (A32(1)) VP(A32(1))->device = A32(0); RET(D3D_OK, 2); }
static void dv_GetCurrentViewport(void) {
    uint32_t v = DEV(A32(0))->viewport;
    MEM32(A32(1)) = v;
    if (v) MEM32(v + 4)++;
    RET(v ? D3D_OK : D3DERR_NOTFOUND, 2);
}
static void dv_SetRenderTarget(void) {
    d3ddev_t *d = DEV(A32(0));
    flush();
    if (A32(1)) MEM32(A32(1) + 4)++;
    d->target = A32(1);
    RET(D3D_OK, 3);
}
static void dv_GetRenderTarget(void) { uint32_t t = DEV(A32(0))->target; MEM32(A32(1)) = t; if (t) MEM32(t + 4)++; RET(D3D_OK, 2); }
static void dv_GetRenderState(void) { uint32_t s = A32(1); MEM32(A32(2)) = s < NRS ? DEV(A32(0))->rs[s] : 0; RET(D3D_OK, 3); }
static void dv_SetRenderState(void) {
    d3ddev_t *d = DEV(A32(0));
    uint32_t s = A32(1), v = A32(2);
    if (s < NRS) d->rs[s] = v;
    if (s == 1) d->tex[0] = v;                           /* TEXTUREHANDLE: the texture object */
    if (s == 21) {                                       /* TEXTUREMAPBLEND, as stage 0's operations */
        uint32_t *t = d->tss[0];
        switch (v) {
        case 1: case 7: t[1] = 2, t[2] = 2, t[4] = 2, t[5] = 2; break;          /* DECAL, COPY */
        case 2: t[1] = 4, t[2] = 2, t[3] = 0, t[4] = 2, t[5] = 2; break;       /* MODULATE */
        case 3: t[1] = 13, t[2] = 2, t[3] = 0, t[4] = 3, t[6] = 0; break;      /* DECALALPHA */
        case 4: t[1] = 4, t[2] = 2, t[3] = 0, t[4] = 4, t[5] = 2, t[6] = 0; break;   /* MODULATEALPHA */
        case 8: t[1] = 7, t[2] = 2, t[3] = 0, t[4] = 3, t[6] = 0; break;       /* ADD */
        }
    }
    RET(D3D_OK, 3);
}
static void dv_GetLightState(void) { MEM32(A32(2)) = 0; RET(D3D_OK, 3); }
static float *transform(d3ddev_t *d, uint32_t type) {
    return type == 1 ? d->world : type == 2 ? d->view : type == 3 ? d->proj : NULL;
}
static void dv_SetTransform(void) {
    float *m = transform(DEV(A32(0)), A32(1));
    if (m) memcpy(m, APTR(2), 64);
    RET(D3D_OK, 3);
}
static void dv_GetTransform(void) {
    float *m = transform(DEV(A32(0)), A32(1));
    if (m) memcpy(APTR(2), m, 64);
    RET(D3D_OK, 3);
}
static void mul(const float *a, const float *b, float *out) {
    float r[16];
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            r[i * 4 + j] = a[i * 4] * b[j] + a[i * 4 + 1] * b[4 + j] + a[i * 4 + 2] * b[8 + j] + a[i * 4 + 3] * b[12 + j];
    memcpy(out, r, 64);
}
static void dv_MultiplyTransform(void) {
    float *m = transform(DEV(A32(0)), A32(1));
    if (m) mul((const float *)APTR(2), m, m);
    RET(D3D_OK, 3);
}
static void dv_GetTexture(void) {
    uint32_t t = A32(1) < 2 ? DEV(A32(0))->tex[A32(1)] : 0;
    MEM32(A32(2)) = t;
    if (t) MEM32(t + 4)++;
    RET(D3D_OK, 3);
}
static void dv_SetTexture(void) {
    if (A32(1) < 2) DEV(A32(0))->tex[A32(1)] = A32(2);
    RET(D3D_OK, 3);
}
static void dv_GetTextureStageState(void) {
    uint32_t st = A32(1), ty = A32(2);
    MEM32(A32(3)) = st < 2 && ty < NTSS ? DEV(A32(0))->tss[st][ty] : 0;
    RET(D3D_OK, 4);
}
static void dv_SetTextureStageState(void) {
    uint32_t st = A32(1), ty = A32(2);
    if (st < 2 && ty < NTSS) DEV(A32(0))->tss[st][ty] = A32(3);
    RET(D3D_OK, 4);
}
static void dv_ValidateDevice(void) { if (A32(1)) MEM32(A32(1)) = 1; RET(D3D_OK, 2); }
static void dv_ComputeSphereVisibility(void) {
    uint32_t n = A32(3), out = A32(5);
    for (uint32_t i = 0; i < n; i++) MEM32(out + 4 * i) = 0;          /* everything visible */
    RET(D3D_OK, 6);
}

/* ---- drawing ---- */
static void state_of(d3ddev_t *d, rstate_t *st) {
    memset(st, 0, sizeof *st);
    surf_t *t = hle_dd_surf(d->target);
    st->target = t;
    st->zbuf = t ? t->zbuf : NULL;
    vp_t *v = d->viewport ? VP(d->viewport) : NULL;
    st->clip_l = v ? v->x : 0, st->clip_t = v ? v->y : 0;
    st->clip_r = v ? v->x + v->w : (t ? t->w : 0), st->clip_b = v ? v->y + v->h : (t ? t->h : 0);
    if (st->clip_l < 0) st->clip_l = 0;
    if (st->clip_t < 0) st->clip_t = 0;
    if (t && st->clip_r > t->w) st->clip_r = t->w;
    if (t && st->clip_b > t->h) st->clip_b = t->h;
    if (st->clip_r <= st->clip_l || st->clip_b <= st->clip_t) st->clip_l = st->clip_t = 0, st->clip_r = t ? t->w : 0, st->clip_b = t ? t->h : 0;
    uint32_t *rs = d->rs, *ts = d->tss[0];
    st->zenable = rs[7] != 0, st->zwrite = rs[14] != 0, st->zfunc = (int)rs[23];
    st->alphatest = rs[15] != 0, st->alphafunc = (int)rs[25], st->alpharef = (float)(rs[24] & 0xFF);
    st->blend = rs[27] != 0, st->srcblend = (int)rs[19], st->dstblend = (int)rs[20];
    st->colorkey = rs[41] != 0;
    st->fog = rs[28] != 0;
    st->fog_r = (float)((rs[34] >> 16) & 0xFF) / 255.f, st->fog_g = (float)((rs[34] >> 8) & 0xFF) / 255.f;
    st->fog_b = (float)(rs[34] & 0xFF) / 255.f;
    st->specular = rs[29] != 0;
    st->flat = rs[9] == 1;
    st->cull = (int)rs[22];
    st->bilinear = ts[16] == 2 || ts[16] == 3 || rs[17] == 2;
    st->wrap_u = ts[13] == 1, st->wrap_v = ts[14] == 1;
    st->colorop = (int)ts[1], st->colorarg1 = (int)ts[2], st->colorarg2 = (int)ts[3];
    st->alphaop = (int)ts[4], st->alphaarg1 = (int)ts[5], st->alphaarg2 = (int)ts[6];
    uint32_t tf = rs[60];                                /* TEXTUREFACTOR */
    st->tfactor[0] = (float)((tf >> 16) & 0xFF) / 255.f, st->tfactor[1] = (float)((tf >> 8) & 0xFF) / 255.f;
    st->tfactor[2] = (float)(tf & 0xFF) / 255.f, st->tfactor[3] = (float)(tf >> 24) / 255.f;
    uint32_t tex = d->tex[0];
    st->tex = tex ? hle_dd_surf(TEX(tex)->surface) : NULL;
    if (st->tex && (st->tex->w <= 0 || st->tex->h <= 0 || !st->tex->px)) st->tex = NULL;
    d3d_raster_prepare(st);
}
/* One vertex of any FVF to screen space. 0 if it is behind the eye. */
static int vertex(d3ddev_t *d, const float *mvp, uint32_t fvf, const uint8_t *p, rvert_t *o) {
    float x, y, z, rhw;
    const float *f = (const float *)(const void *)p;
    uint32_t off;
    if ((fvf & 0x00E) == 0x004) {                        /* XYZRHW: screen space already */
        x = f[0], y = f[1], z = f[2], rhw = f[3], off = 16;
    } else {
        float in[4] = { f[0], f[1], f[2], 1 }, c[4];
        for (int j = 0; j < 4; j++) c[j] = in[0] * mvp[j] + in[1] * mvp[4 + j] + in[2] * mvp[8 + j] + in[3] * mvp[12 + j];
        if (c[3] <= 1e-6f) return 0;
        vp_t *v = d->viewport ? VP(d->viewport) : NULL;
        float vx = v ? (float)v->x : 0, vy = v ? (float)v->y : 0, vw = v ? (float)v->w : 640, vh = v ? (float)v->h : 480;
        float cx = v ? v->cx : -1, cy = v ? v->cy : 1, cw = v ? v->cw : 2, ch = v ? v->ch : 2;
        float minz = v ? v->minz : 0, maxz = v ? v->maxz : 1;
        rhw = 1.0f / c[3];
        float nx = c[0] * rhw, ny = c[1] * rhw, nz = c[2] * rhw;
        x = vx + (nx - cx) / cw * vw;
        y = vy + (cy - ny) / ch * vh;
        z = minz + nz * (maxz - minz);
        off = fvf_size(fvf & 0x00E);
    }
    if (fvf & 0x010) off += 12;
    if (fvf & 0x020) off += 4;
    uint32_t dif = 0xFFFFFFFFu, spec = 0xFF000000u;
    if (fvf & 0x040) memcpy(&dif, p + off, 4), off += 4;
    if (fvf & 0x080) memcpy(&spec, p + off, 4), off += 4;
    float u = 0, vv = 0;
    if ((fvf >> 8) & 0xF) memcpy(&u, p + off, 4), memcpy(&vv, p + off + 4, 4);
    o->x = x, o->y = y, o->z = z, o->rhw = rhw;
    o->r = (float)((dif >> 16) & 0xFF) / 255.f, o->g = (float)((dif >> 8) & 0xFF) / 255.f;
    o->b = (float)(dif & 0xFF) / 255.f, o->a = (float)(dif >> 24) / 255.f;
    o->sr = (float)((spec >> 16) & 0xFF) / 255.f, o->sg = (float)((spec >> 8) & 0xFF) / 255.f;
    o->sb = (float)(spec & 0xFF) / 255.f, o->fog = (float)(spec >> 24) / 255.f;
    o->u = u, o->v = vv;
    return 1;
}
/* Draw `count` vertices (or `nidx` of them through 16-bit indices) as a
 * primitive type: 1 points, 2 lines, 3 a strip of lines, 4 triangles, 5 a
 * strip, 6 a fan. */
static void draw(d3ddev_t *d, uint32_t type, uint32_t fvf, const uint8_t *verts, uint32_t nverts,
                 const uint16_t *idx, uint32_t nidx) {
    rstate_t st;
    state_of(d, &st);
    if (!st.target || !verts) return;
    uint32_t stride = fvf_size(fvf), n = idx ? nidx : nverts;
    if (!stride || n > 1u << 20) return;
    float vm[16], mvp[16];
    mul(d->world, d->view, vm);
    mul(vm, d->proj, mvp);
    d->prims++;
#define V(i, out) vertex(d, mvp, fvf, verts + (size_t)stride * (size_t)(idx ? idx[i] : (i)), out)
    rvert_t a, b, c;
    switch (type) {
    case 4:
        for (uint32_t i = 0; i + 2 < n; i += 3)
            if (V(i, &a) && V(i + 1, &b) && V(i + 2, &c)) tri(&st, &a, &b, &c), d->tris++;
        break;
    case 5:
        for (uint32_t i = 0; i + 2 < n; i++)
            if (V(i, &a) && V(i + 1, &b) && V(i + 2, &c)) {
                if (i & 1) tri(&st, &b, &a, &c); else tri(&st, &a, &b, &c);
                d->tris++;
            }
        break;
    case 6:
        if (n >= 3 && V(0, &a))
            for (uint32_t i = 1; i + 1 < n; i++)
                if (V(i, &b) && V(i + 1, &c)) tri(&st, &a, &b, &c), d->tris++;
        break;
    case 2:
        for (uint32_t i = 0; i + 1 < n; i += 2) if (V(i, &a) && V(i + 1, &b)) line(&st, &a, &b);
        break;
    case 3:
        for (uint32_t i = 0; i + 1 < n; i++) if (V(i, &a) && V(i + 1, &b)) line(&st, &a, &b);
        break;
    case 1:
        for (uint32_t i = 0; i < n; i++) if (V(i, &a)) line(&st, &a, &a);
        break;
    }
#undef V
    if (!hle_d3d_gpu) hle_dd_mark(st.target);
}
static void dv_DrawPrimitive(void) {                     /* (this, type, fvf, verts, count, flags) */
    draw(DEV(A32(0)), A32(1), A32(2), (const uint8_t *)APTR(3), A32(4), NULL, 0);
    RET(D3D_OK, 6);
}
static void dv_DrawIndexedPrimitive(void) {              /* (this, type, fvf, verts, nverts, idx, nidx, flags) */
    draw(DEV(A32(0)), A32(1), A32(2), (const uint8_t *)APTR(3), A32(4), (const uint16_t *)APTR(5), A32(6));
    RET(D3D_OK, 8);
}
static void dv_DrawPrimitiveVB(void) {                   /* (this, type, vb, start, count, flags) */
    vb_t *v = VB(A32(2));
    draw(DEV(A32(0)), A32(1), v->fvf, v->data + (size_t)fvf_size(v->fvf) * A32(3), A32(4), NULL, 0);
    RET(D3D_OK, 6);
}
static void dv_DrawIndexedPrimitiveVB(void) {            /* (this, type, vb, idx, nidx, flags) */
    vb_t *v = VB(A32(2));
    draw(DEV(A32(0)), A32(1), v->fvf, v->data, v->count, (const uint16_t *)APTR(3), A32(4));
    RET(D3D_OK, 6);
}
static void dv_unsupported6(void) { T("a strided draw: not drawn\n"); RET(D3D_OK, 6); }
static void dv_unsupported8(void) { T("a strided indexed draw: not drawn\n"); RET(D3D_OK, 8); }
/* Begin/Vertex/End: the vertices gathered, then drawn as one primitive. */
static uint8_t g_imm[65536];
static uint32_t g_imm_n, g_imm_type, g_imm_fvf;
static void dv_Begin(void) { g_imm_type = A32(1), g_imm_fvf = A32(2), g_imm_n = 0; RET(D3D_OK, 4); }
static void dv_BeginIndexed(void) { RET(D3D_OK, 6); }
static void dv_Vertex(void) {
    uint32_t sz = fvf_size(g_imm_fvf);
    if ((g_imm_n + 1) * sz <= sizeof g_imm) memcpy(g_imm + g_imm_n++ * sz, APTR(1), sz);
    RET(D3D_OK, 2);
}
static void dv_End(void) { draw(DEV(A32(0)), g_imm_type, g_imm_fvf, g_imm, g_imm_n, NULL, 0); RET(D3D_OK, 2); }

/* ---- vertex buffers ---- */
static void vb_Release(void) {
    uint32_t self = A32(0), n = --MEM32(self + 4);
    if (!n) { vb_t *v = VB(self); hle_free(v->data); hle_free(v); hle_com_free(self); }
    RET(n, 1);
}
static void vb_Lock(void) {                              /* (this, flags, &ptr, &size) */
    vb_t *v = VB(A32(0));
    if (A32(2)) MEM32(A32(2)) = hle_va(v->data);
    if (A32(3)) MEM32(A32(3)) = v->size;
    RET(D3D_OK, 4);
}
static void vb_GetVertexBufferDesc(void) {
    vb_t *v = VB(A32(0));
    uint32_t p = A32(1);
    MEM32(p + 4) = 0, MEM32(p + 8) = v->fvf, MEM32(p + 12) = v->count;
    RET(D3D_OK, 2);
}

/* ---- the vtables ---- */
static void vtables(void) {
    if (g_vt_d3d) return;
    static const win32hle_shim d3[] = {
        { "IDirect3D3::QueryInterface", d3_QueryInterface }, { "IDirect3D3::AddRef", hle_com_AddRef },
        { "IDirect3D3::Release", d3_Release }, { "IDirect3D3::EnumDevices", d3_EnumDevices },
        { "IDirect3D3::CreateLight", d3_CreateLight }, { "IDirect3D3::CreateMaterial", d3_CreateMaterial },
        { "IDirect3D3::CreateViewport", d3_CreateViewport }, { "IDirect3D3::FindDevice", d3_FindDevice },
        { "IDirect3D3::CreateDevice", d3_CreateDevice }, { "IDirect3D3::CreateVertexBuffer", d3_CreateVertexBuffer },
        { "IDirect3D3::EnumZBufferFormats", d3_EnumZBufferFormats },
        { "IDirect3D3::EvictManagedTextures", d3_EvictManagedTextures }, { 0, 0 } };
    static const win32hle_shim dv[] = {
        { "IDirect3DDevice3::QueryInterface", dv_QueryInterface }, { "IDirect3DDevice3::AddRef", hle_com_AddRef },
        { "IDirect3DDevice3::Release", dv_Release }, { "IDirect3DDevice3::GetCaps", dv_GetCaps },
        { "IDirect3DDevice3::GetStats", dv_GetStats }, { "IDirect3DDevice3::AddViewport", dv_AddViewport },
        { "IDirect3DDevice3::DeleteViewport", dv_DeleteViewport }, { "IDirect3DDevice3::NextViewport", dv_NextViewport },
        { "IDirect3DDevice3::EnumTextureFormats", dv_EnumTextureFormats },
        { "IDirect3DDevice3::BeginScene", dv_BeginScene }, { "IDirect3DDevice3::EndScene", dv_EndScene },
        { "IDirect3DDevice3::GetDirect3D", dv_GetDirect3D },
        { "IDirect3DDevice3::SetCurrentViewport", dv_SetCurrentViewport },
        { "IDirect3DDevice3::GetCurrentViewport", dv_GetCurrentViewport },
        { "IDirect3DDevice3::SetRenderTarget", dv_SetRenderTarget },
        { "IDirect3DDevice3::GetRenderTarget", dv_GetRenderTarget },
        { "IDirect3DDevice3::Begin", dv_Begin }, { "IDirect3DDevice3::BeginIndexed", dv_BeginIndexed },
        { "IDirect3DDevice3::Vertex", dv_Vertex }, { "IDirect3DDevice3::Index", ok2 },
        { "IDirect3DDevice3::End", dv_End },
        { "IDirect3DDevice3::GetRenderState", dv_GetRenderState }, { "IDirect3DDevice3::SetRenderState", dv_SetRenderState },
        { "IDirect3DDevice3::GetLightState", dv_GetLightState }, { "IDirect3DDevice3::SetLightState", ok3 },
        { "IDirect3DDevice3::SetTransform", dv_SetTransform }, { "IDirect3DDevice3::GetTransform", dv_GetTransform },
        { "IDirect3DDevice3::MultiplyTransform", dv_MultiplyTransform },
        { "IDirect3DDevice3::DrawPrimitive", dv_DrawPrimitive },
        { "IDirect3DDevice3::DrawIndexedPrimitive", dv_DrawIndexedPrimitive },
        { "IDirect3DDevice3::SetClipStatus", ok2 }, { "IDirect3DDevice3::GetClipStatus", ok2 },
        { "IDirect3DDevice3::DrawPrimitiveStrided", dv_unsupported6 },
        { "IDirect3DDevice3::DrawIndexedPrimitiveStrided", dv_unsupported8 },
        { "IDirect3DDevice3::DrawPrimitiveVB", dv_DrawPrimitiveVB },
        { "IDirect3DDevice3::DrawIndexedPrimitiveVB", dv_DrawIndexedPrimitiveVB },
        { "IDirect3DDevice3::ComputeSphereVisibility", dv_ComputeSphereVisibility },
        { "IDirect3DDevice3::GetTexture", dv_GetTexture }, { "IDirect3DDevice3::SetTexture", dv_SetTexture },
        { "IDirect3DDevice3::GetTextureStageState", dv_GetTextureStageState },
        { "IDirect3DDevice3::SetTextureStageState", dv_SetTextureStageState },
        { "IDirect3DDevice3::ValidateDevice", dv_ValidateDevice }, { 0, 0 } };
    static const win32hle_shim vp[] = {
        { "IDirect3DViewport3::QueryInterface", hle_com_QueryInterface }, { "IDirect3DViewport3::AddRef", hle_com_AddRef },
        { "IDirect3DViewport3::Release", vp_Release }, { "IDirect3DViewport3::Initialize", ok2 },
        { "IDirect3DViewport3::GetViewport", vp_GetViewport }, { "IDirect3DViewport3::SetViewport", vp_SetViewport },
        { "IDirect3DViewport3::TransformVertices", ok5 }, { "IDirect3DViewport3::LightElements", ok3 },
        { "IDirect3DViewport3::SetBackground", vp_SetBackground }, { "IDirect3DViewport3::GetBackground", vp_GetBackground },
        { "IDirect3DViewport3::SetBackgroundDepth", ok2 },
        { "IDirect3DViewport3::GetBackgroundDepth", vp_GetBackgroundDepth },
        { "IDirect3DViewport3::Clear", vp_Clear }, { "IDirect3DViewport3::AddLight", ok2 },
        { "IDirect3DViewport3::DeleteLight", ok2 }, { "IDirect3DViewport3::NextLight", vp_NextLight },
        { "IDirect3DViewport3::GetViewport2", vp_GetViewport2 }, { "IDirect3DViewport3::SetViewport2", vp_SetViewport2 },
        { "IDirect3DViewport3::SetBackgroundDepth2", ok2 },
        { "IDirect3DViewport3::GetBackgroundDepth2", vp_GetBackgroundDepth },
        { "IDirect3DViewport3::Clear2", vp_Clear2 }, { 0, 0 } };
    static const win32hle_shim tx[] = {
        { "IDirect3DTexture2::QueryInterface", tx_QueryInterface }, { "IDirect3DTexture2::AddRef", hle_com_AddRef },
        { "IDirect3DTexture2::Release", tx_Release }, { "IDirect3DTexture2::GetHandle", tx_GetHandle },
        { "IDirect3DTexture2::PaletteChanged", tx_PaletteChanged }, { "IDirect3DTexture2::Load", tx_Load }, { 0, 0 } };
    static const win32hle_shim mt[] = {
        { "IDirect3DMaterial3::QueryInterface", hle_com_QueryInterface }, { "IDirect3DMaterial3::AddRef", hle_com_AddRef },
        { "IDirect3DMaterial3::Release", mt_Release }, { "IDirect3DMaterial3::SetMaterial", mt_SetMaterial },
        { "IDirect3DMaterial3::GetMaterial", mt_GetMaterial }, { "IDirect3DMaterial3::GetHandle", mt_GetHandle }, { 0, 0 } };
    static const win32hle_shim lt[] = {
        { "IDirect3DLight::QueryInterface", hle_com_QueryInterface }, { "IDirect3DLight::AddRef", hle_com_AddRef },
        { "IDirect3DLight::Release", lt_Release }, { "IDirect3DLight::Initialize", ok2 },
        { "IDirect3DLight::SetLight", ok2 }, { "IDirect3DLight::GetLight", ok2 }, { 0, 0 } };
    static const win32hle_shim vb[] = {
        { "IDirect3DVertexBuffer::QueryInterface", hle_com_QueryInterface }, { "IDirect3DVertexBuffer::AddRef", hle_com_AddRef },
        { "IDirect3DVertexBuffer::Release", vb_Release }, { "IDirect3DVertexBuffer::Lock", vb_Lock },
        { "IDirect3DVertexBuffer::Unlock", ok1 }, { "IDirect3DVertexBuffer::ProcessVertices", ok1 },
        { "IDirect3DVertexBuffer::GetVertexBufferDesc", vb_GetVertexBufferDesc },
        { "IDirect3DVertexBuffer::Optimize", ok3 }, { 0, 0 } };
    g_vt_d3d = hle_com_vtable(d3);
    g_vt_dev = hle_com_vtable(dv);
    g_vt_vp = hle_com_vtable(vp);
    g_vt_tex = hle_com_vtable(tx);
    g_vt_mat = hle_com_vtable(mt);
    g_vt_light = hle_com_vtable(lt);
    g_vt_vb = hle_com_vtable(vb);
    g_d3d = hle_com_new(g_vt_d3d, 12);
    MEM32(g_d3d + 4) = 0;
}

uint32_t hle_d3d_query(const uint8_t *iid) {
    uint32_t d1;
    memcpy(&d1, iid, 4);
    if (d1 != 0xBB223240u) return 0;                     /* IDirect3D3 only */
    vtables();
    MEM32(g_d3d + 4)++;
    T("IDirect3D3 -> 0x%08X\n", g_d3d);
    return g_d3d;
}
uint32_t hle_d3d_surface_query(uint32_t surface, const uint8_t *iid) {
    uint32_t d1;
    memcpy(&d1, iid, 4);
    if (d1 != 0x93281502u) return 0;                     /* IDirect3DTexture2 */
    vtables();
    return texture_for(surface);
}

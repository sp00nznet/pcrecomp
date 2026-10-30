/*
 * ddraw_selftest.c - DirectDraw 4's surfaces, through the shims as a guest
 * calls them (hle_call_guest on their import VAs):
 *
 *   - each surface has its own uniqueness value: changing one, or locking
 *     it, leaves another's alone;
 *   - an attached z-buffer is let go of: DeleteAttachedSurface returns the
 *     reference AddAttachedSurface took, and so does a render target that
 *     goes (freeing the z-buffer when that was the last);
 *   - Direct3D's texture cache follows the surface: SetSurfaceDesc to a
 *     larger size gives a cache of the new size with the new pixels.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "win32hle.h"
#include "host.h"
#include "d3d_raster.h"

static int fails;
static void ok(const char *what, int cond) { if (!cond) { printf("FAIL %s\n", what); fails++; } }
static uint32_t call(const char *name, int n, const uint32_t *a) { return hle_call_guest(hle_resolve(name), n, a); }
#define A(p) hle_va(p)

const recomp_dispatch_entry_t recomp_dispatch_table[1];
const uint32_t recomp_dispatch_count = 0;

static uint32_t g_dd4;

/* A DDSURFACEDESC2 for an offscreen 16-bit surface, or a 16-bit z-buffer. */
static uint32_t surface(int w, int h, int zbuffer) {
    uint8_t *d = (uint8_t *)hle_alloc(124);
    uint32_t *u = (uint32_t *)d;
    u[0] = 124;
    u[1] = 0x1 | 0x2 | 0x4 | 0x1000;                      /* CAPS HEIGHT WIDTH PIXELFORMAT */
    u[2] = (uint32_t)h, u[3] = (uint32_t)w;
    u[18] = 32;                                          /* the pixel format, at 72 */
    if (zbuffer) u[19] = 0x400, u[21] = 16, u[23] = 0xFFFF, u[26] = 0x20000;   /* ZBUFFER; DDSCAPS_ZBUFFER */
    else u[19] = 0x40, u[21] = 16, u[22] = 0xF800, u[23] = 0x07E0, u[24] = 0x001F, u[26] = 0x40 | 0x1000;
    uint32_t *out = (uint32_t *)hle_alloc(4);
    uint32_t a[4] = { g_dd4, A(d), A(out), 0 };
    ok("CreateSurface", call("IDirectDraw4::CreateSurface", 4, a) == 0 && *out);
    return *out;
}
static uint32_t uniqueness(uint32_t s) {
    uint32_t *v = (uint32_t *)hle_alloc(4);
    uint32_t a[2] = { s, A(v) };
    call("IDirectDrawSurface4::GetUniquenessValue", 2, a);
    return *v;
}
static uint32_t refs(uint32_t obj) { return MEM32(obj + 4); }

int main(void) {
    recomp_host_init();
    uint32_t *out = (uint32_t *)hle_alloc(4);
    uint32_t a0[3] = { 0, A(out), 0 };
    call("DirectDrawCreate", 3, a0);
    uint8_t *iid = (uint8_t *)hle_alloc(16);             /* IID_IDirectDraw4 */
    const uint8_t dd4[16] = { 0x9A, 0x50, 0x59, 0x9C, 0xBD, 0x39, 0xD1, 0x11, 0x8C, 0x4A, 0x00, 0xC0, 0x4F, 0xD9, 0x30, 0xC5 };
    memcpy(iid, dd4, 16);
    uint32_t a1[3] = { *out, A(iid), A(out) };
    ok("IDirectDraw4", call("IDirectDraw::QueryInterface", 3, a1) == 0 && *out);
    g_dd4 = *out;

    /* uniqueness values are each surface's own */
    uint32_t s1 = surface(2, 2, 0), s2 = surface(2, 2, 0);
    uint32_t u1 = uniqueness(s1), u2 = uniqueness(s2);
    call("IDirectDrawSurface4::ChangeUniquenessValue", 1, &s1);
    ok("ChangeUniquenessValue moves its own surface's", uniqueness(s1) != u1);
    ok("...and not another's", uniqueness(s2) == u2);
    uint8_t *desc = (uint8_t *)hle_alloc(124);
    ((uint32_t *)desc)[0] = 124;
    uint32_t lk[5] = { s2, 0, A(desc), 0, 0 }, un[2] = { s2, 0 };
    u1 = uniqueness(s1);
    call("IDirectDrawSurface::Lock", 5, lk);
    call("IDirectDrawSurface::Unlock", 2, un);
    ok("a Lock moves the locked surface's", uniqueness(s2) != u2);
    ok("...and not another's", uniqueness(s1) == u1);

    /* an attached z-buffer: DeleteAttachedSurface gives its reference back */
    uint32_t target = surface(4, 4, 0), z = surface(4, 4, 1);
    uint32_t at[2] = { target, z };
    call("IDirectDrawSurface::AddAttachedSurface", 2, at);
    ok("AddAttachedSurface holds the z-buffer", refs(z) == 2);
    uint32_t de[3] = { target, 0, z };
    call("IDirectDrawSurface::DeleteAttachedSurface", 3, de);
    ok("DeleteAttachedSurface lets it go", refs(z) == 1);

    /* ...and a render target that goes gives its reference back too (the
     * game's own reference is kept, so the z-buffer is still there to look at) */
    call("IDirectDrawSurface::AddAttachedSurface", 2, at);
    ok("attached again", refs(z) == 2);
    call("IDirectDrawSurface::Release", 1, &target);
    ok("the target's reference goes with it", refs(z) == 1);
    call("IDirectDrawSurface::Release", 1, &z);

    /* Direct3D's texture cache follows SetSurfaceDesc to a larger size */
    uint32_t tex = surface(2, 2, 0);
    rstate_t st;
    memset(&st, 0, sizeof st);
    st.tex = hle_dd_surf(tex);
    ok("hle_dd_surf", st.tex != NULL);
    d3d_raster_prepare(&st);
    ok("a 2x2 cache", st.tex->argb && st.tex->argb_w == 2 && st.tex->argb_h == 2);
    uint16_t *px = (uint16_t *)hle_alloc(4 * 4 * 2);
    for (int i = 0; i < 16; i++) px[i] = 0x001F;         /* blue */
    px[15] = 0xF800;                                     /* the last pixel red */
    uint32_t *sd = (uint32_t *)hle_alloc(124);
    sd[0] = 124, sd[1] = 0x2 | 0x4 | 0x8 | 0x800;        /* HEIGHT WIDTH PITCH LPSURFACE */
    sd[2] = 4, sd[3] = 4, sd[4] = 8, sd[9] = A(px);
    uint32_t ss[3] = { tex, A(sd), 0 };
    call("IDirectDrawSurface3::SetSurfaceDesc", 3, ss);
    d3d_raster_prepare(&st);
    ok("a 4x4 cache after SetSurfaceDesc", st.tex->argb_w == 4 && st.tex->argb_h == 4);
    ok("its last texel is the new red", st.tex->argb[15] == 0xFFFF0000u);
    ok("its first the new blue", st.tex->argb[0] == 0xFF0000FFu);

    if (!fails) printf("ok\n");
    return fails != 0;
}

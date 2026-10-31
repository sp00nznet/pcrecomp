/*
 * d3d_gpu.h - a renderer on the host's GPU in place of d3d_raster.c: d3d.c
 * hands it the same screen-space triangles, lines and clears, with the same
 * state, and it draws them into textures of its own.
 *
 * A surface Direct3D draws into then lives on the GPU. DirectDraw reads and
 * writes the pixels in memory, so the renderer hears from ddraw.c of each
 * surface it is about to touch (hle_dd_sync_hook) and brings that one into
 * memory first; it may do a blit itself, on the GPU, when an end of it is
 * there (hle_dd_blit_hook); and a surface whose pixels changed in memory goes
 * up again before the GPU draws into it. sync() brings every surface into
 * memory, for d3d.c's own reads (a texture Load, a new render target).
 */
#ifndef WIN32HLE_D3D_GPU_H
#define WIN32HLE_D3D_GPU_H
#include "d3d_raster.h"

typedef struct {
    const char *name;
    void (*triangle)(const rstate_t *st, const rvert_t *a, const rvert_t *b, const rvert_t *c);
    void (*line)(const rstate_t *st, const rvert_t *a, const rvert_t *b);
    /* flags: 1 the colour, 2 the depth (D3DCLEAR_TARGET, D3DCLEAR_ZBUFFER) */
    void (*clear)(surf_t *target, int l, int t, int r, int b, uint32_t flags, uint32_t argb, float z);
    void (*end_scene)(surf_t *target);
    void (*sync)(void);
} d3d_gpu_t;

/* The renderer in use: NULL, d3d_raster.c's software. */
extern const d3d_gpu_t *hle_d3d_gpu;

/* Metal (d3d_metal.m, macOS): 0 and in use, or -1 with no Metal device. */
int hle_d3d_metal_enable(void);

#endif

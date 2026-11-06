/*
 * ddraw_int.h - a DirectDraw surface as win32hle keeps it, for the code that
 * draws into surfaces besides ddraw.c itself (d3d.c, Direct3D's rasteriser).
 */
#ifndef WIN32HLE_DDRAW_INT_H
#define WIN32HLE_DDRAW_INT_H
#include <stdint.h>

typedef struct surf {
    uint32_t self;
    int w, h, bpp, pitch;
    uint8_t *px;
    uint8_t *own_px;                     /* the pixels allocated here (px may be the game's, or swapped by Flip) */
    uint32_t caps;
    int primary, locks;
    struct surf *back;                   /* the flip chain's next */
    uint32_t palette, clipper;
    int ck_src; uint32_t ck_lo, ck_hi;
    uint32_t rmask, gmask, bmask, amask;
    uint32_t pf_flags;                   /* DDPIXELFORMAT.dwFlags it was created with; 0: the display's */
    struct surf *zbuf;                   /* an attached z-buffer */
    struct surf *mip;                    /* the next mipmap level */
    int mip_count;                       /* levels from this one down */
    uint32_t gen;                        /* bumped whenever the pixels or the colour key change */
    uint32_t *argb;                      /* d3d_raster.c's cache: the pixels as ARGB (host memory) */
    uint8_t *keyed;                      /* ...and which of them are the colour key */
    uint32_t argb_gen;                   /* the gen it was made at; 0: none */
    int argb_w, argb_h;                  /* the size it was made at (SetSurfaceDesc can change the surface's) */
} surf_t;

/* The surface behind a DirectDraw surface object, or NULL if obj is not one. */
surf_t *hle_dd_surf(uint32_t obj);
/* Called before a surface is read or written through DirectDraw (Lock, Blt,
 * BltFast, Flip, GetDC, Release): Direct3D's queued drawing goes first. */
extern void (*hle_dd_access_hook)(void);
/* Tell the presenter a surface changed (it shows the primary). */
void hle_dd_mark(surf_t *s);

#endif

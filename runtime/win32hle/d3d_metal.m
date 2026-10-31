/*
 * d3d_metal.m - Direct3D's drawing on the GPU, through Metal (macOS): the
 * renderer d3d_gpu.h describes, in place of d3d_raster.c.
 *
 * Every surface Direct3D draws into gets a texture (BGRA8, whatever the
 * surface's own format), and its z-buffer a depth texture. Triangles go in
 * batches: consecutive ones with the same state are one draw. The fragment
 * shader is d3d_raster.c's shade() - stage 0's colour and alpha operations,
 * colour key, alpha test, specular and fog - with the texture read texel by
 * texel as it reads it, so both renderers draw alike; blending and the depth
 * test are the GPU's own.
 *
 * Pixels go between memory and the GPU through a shared buffer, packed and
 * unpacked by two compute kernels into the surface's own format. Down when
 * DirectDraw is about to touch a surface; up when a surface changed in
 * memory since the GPU last had it, before the GPU draws into it, unless the
 * first thing drawn is a clear of all of it. A blit with either end on the
 * GPU is drawn there (a game's cursor, saved from and drawn onto the back
 * buffer each frame, never comes down); and a flip starts the new front
 * down without waiting, for the presenter to show when it is there
 * (hle_dd_frame_hook). So the game does not wait for the GPU in a frame.
 *
 * Built without ARC: what this file makes it releases.
 */
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "win32hle.h"
#include "d3d_gpu.h"

/* ---- the shaders ---- */
static const char *g_src =
"#include <metal_stdlib>\n"
"using namespace metal;\n"
"struct GV { packed_float4 p; packed_float4 dif; packed_float4 spec; packed_float2 uv; };\n"
"struct VO { float4 pos [[position]]; float4 dif; float4 spec; float2 uv; float psize [[point_size]]; };\n"
"vertex VO vs(uint vid [[vertex_id]], const device GV *v [[buffer(0)]], constant float2 &size [[buffer(1)]]) {\n"
"    GV g = v[vid];\n"
"    float rhw = g.p[3];\n"
"    float w = rhw > 0 && isfinite(rhw) ? 1.0f / rhw : 1.0f;\n"
"    float nx = g.p[0] / size.x * 2 - 1, ny = 1 - g.p[1] / size.y * 2;\n"
"    VO o;\n"
"    o.pos = float4(nx * w, ny * w, g.p[2] * w, w);\n"
"    o.dif = float4(g.dif), o.spec = float4(g.spec), o.uv = float2(g.uv), o.psize = 1;\n"
"    return o;\n"
"}\n"
/* What a draw is shaded with: rstate_t's per-pixel part. */
"struct U { int4 a; int4 b; int4 c; int4 d; float4 tf; float4 fogc; };\n"
/* a: tex, colorkey, bilinear, wrap_u; b: wrap_v, colorop, colorarg1, colorarg2;
 * c: alphaop, alphaarg1, alphaarg2, alphatest; d: alphafunc, specular, fog, 0;
 * fogc.w: alpharef */
"static bool cmp(int f, float a, float b) {\n"
"    switch (f) { case 1: return false; case 2: return a < b; case 3: return a == b; case 4: return a <= b;\n"
"    case 5: return a > b; case 6: return a != b; case 7: return a >= b; default: return true; }\n"
"}\n"
"static float4 arg(int a, float4 tex, float4 dif, float4 tf) {\n"
"    float4 o = (a & 0xF) == 2 ? tex : (a & 0xF) == 3 ? tf : dif;\n"
"    if (a & 0x20) o = float4(o.w);\n"
"    if (a & 0x10) o = 1 - o;\n"
"    return o;\n"
"}\n"
"static float4 op(int op, float4 a, float4 b) {\n"
"    switch (op) {\n"
"    case 2: return a; case 3: return b; case 4: return a * b;\n"
"    case 5: return min(a * b * 2, float4(1)); case 6: return min(a * b * 4, float4(1));\n"
"    case 7: return min(a + b, float4(1)); case 8: return clamp(a + b - 0.5f, float4(0), float4(1));\n"
"    case 10: return max(a - b, float4(0)); case 11: return min(a + b - a * b, float4(1));\n"
"    default: return b;\n"
"    }\n"
"}\n"
"static int wrap(int i, int n, bool w) { if (w) { i %= n; return i < 0 ? i + n : i; } return clamp(i, 0, n - 1); }\n"
"fragment float4 fs(VO in [[stage_in]], constant U &u [[buffer(0)]],\n"
"                   texture2d<float, access::read> tx [[texture(0)]], texture2d<uint, access::read> kt [[texture(1)]]) {\n"
"    float4 dif = in.dif, tex = float4(1), col;\n"
"    bool has = u.a.x != 0, ck = u.a.y != 0;\n"
"    if (has) {\n"
"        int w = int(tx.get_width()), h = int(tx.get_height());\n"
"        bool wu = u.a.w != 0, wv = u.b.x != 0;\n"
"        if (u.a.z == 0) {\n"
"            uint2 p = uint2(wrap(int(floor(in.uv.x * w)), w, wu), wrap(int(floor(in.uv.y * h)), h, wv));\n"
"            tex = tx.read(p);\n"
"            if (ck && kt.read(p).x != 0) discard_fragment();\n"
"        } else {\n"
"            float x = in.uv.x * w - 0.5f, y = in.uv.y * h - 0.5f;\n"
"            float x0 = floor(x), y0 = floor(y), fx = x - x0, fy = y - y0;\n"
"            int xs[2] = { wrap(int(x0), w, wu), wrap(int(x0) + 1, w, wu) };\n"
"            int ys[2] = { wrap(int(y0), h, wv), wrap(int(y0) + 1, h, wv) };\n"
"            float wt[4] = { (1 - fx) * (1 - fy), fx * (1 - fy), (1 - fx) * fy, fx * fy };\n"
/* A keyed texel counts as transparent black, so edges fade instead of fringing. */
"            float4 acc = 0; float kw = 0;\n"
"            for (int k = 0; k < 4; k++) {\n"
"                uint2 p = uint2(xs[k & 1], ys[k >> 1]);\n"
"                if (ck && kt.read(p).x != 0) { kw += wt[k]; continue; }\n"
"                acc += tx.read(p) * wt[k];\n"
"            }\n"
"            if (ck && kw > 0.5f) discard_fragment();\n"
"            tex = acc;\n"
"        }\n"
"    }\n"
"    col.xyz = has && u.b.y != 1 ? op(u.b.y, arg(u.b.z, tex, dif, u.tf), arg(u.b.w, tex, dif, u.tf)).xyz : dif.xyz;\n"
"    col.w = has && u.c.x != 1 ? op(u.c.x, arg(u.c.y, tex, dif, u.tf), arg(u.c.z, tex, dif, u.tf)).w : dif.w;\n"
"    if (u.c.w != 0 && !cmp(u.d.x, col.w * 255, u.fogc.w)) discard_fragment();\n"
"    if (u.d.y != 0) col.xyz = min(col.xyz + in.spec.xyz, float3(1));\n"
"    if (u.d.z != 0) { float f = clamp(in.spec.w, 0.0f, 1.0f); col.xyz = col.xyz * f + u.fogc.xyz * (1 - f); }\n"
"    return col;\n"
"}\n"
"fragment float4 fs_clear(VO in [[stage_in]]) { return in.dif; }\n"
/* DirectDraw's blit (ddraw.c's blit()): each pixel of the destination
 * rectangle from source pixel (sl + x * sw / dw, st + y * sh / dh), none
 * outside the source, none whose value in the source's own format is in
 * the colour key's range. */
"struct BU { int4 d; int4 s; uint4 key; uint4 sh; uint4 bits; };\n"
"fragment float4 fs_blit(VO in [[stage_in]], constant BU &u [[buffer(0)]], texture2d<float, access::read> src [[texture(0)]]) {\n"
"    int x = int(in.pos.x) - u.d.x, y = int(in.pos.y) - u.d.y;\n"
"    if (x < 0 || y < 0 || x >= u.d.z || y >= u.d.w) discard_fragment();\n"
"    int sx = u.s.x + x * u.s.z / u.d.z, sy = u.s.y + y * u.s.w / u.d.w;\n"
"    if (sx < 0 || sy < 0 || sx >= int(src.get_width()) || sy >= int(src.get_height())) discard_fragment();\n"
"    float4 c = src.read(uint2(sx, sy));\n"
"    if (u.key.x != 0) {\n"
"        uint v = 0;\n"
"        for (int i = 0; i < 4; i++) if (u.bits[i]) v |= uint(clamp(c[i], 0.0f, 1.0f) * float((1u << u.bits[i]) - 1) + 0.5f) << u.sh[i];\n"
"        if (v >= u.key.y && v <= u.key.z) discard_fragment();\n"
"    }\n"
"    return c;\n"
"}\n"
/* Between a texture and a surface's pixels, in its own format: each
 * channel's shift and width; bpp 16 or 32; rows `pitch` bytes apart. */
"struct PK { uint4 dim; uint4 sh; uint4 bits; };\n"
"kernel void pack(texture2d<float, access::read> t [[texture(0)]], device uchar *buf [[buffer(0)]],\n"
"                 constant PK &k [[buffer(1)]], uint2 g [[thread_position_in_grid]]) {\n"
"    if (g.x >= k.dim.x || g.y >= k.dim.y) return;\n"
"    float4 c = t.read(g);\n"
"    uint v = 0;\n"
"    for (int i = 0; i < 4; i++) if (k.bits[i]) v |= uint(clamp(c[i], 0.0f, 1.0f) * float((1u << k.bits[i]) - 1) + 0.5f) << k.sh[i];\n"
"    device uchar *row = buf + g.y * k.dim.z;\n"
"    if (k.dim.w == 16) ((device ushort *)row)[g.x] = ushort(v); else ((device uint *)row)[g.x] = v;\n"
"}\n"
"kernel void unpack(texture2d<float, access::write> t [[texture(0)]], const device uchar *buf [[buffer(0)]],\n"
"                   constant PK &k [[buffer(1)]], uint2 g [[thread_position_in_grid]]) {\n"
"    if (g.x >= k.dim.x || g.y >= k.dim.y) return;\n"
"    const device uchar *row = buf + g.y * k.dim.z;\n"
"    uint v = k.dim.w == 16 ? uint(((const device ushort *)row)[g.x]) : ((const device uint *)row)[g.x];\n"
"    float4 c;\n"
"    for (int i = 0; i < 4; i++) c[i] = k.bits[i] ? float((v >> k.sh[i]) & ((1u << k.bits[i]) - 1)) / float((1u << k.bits[i]) - 1) : 1.0f;\n"
"    t.write(c, g);\n"
"}\n";

/* ---- what this side keeps ---- */
typedef struct { float p[4], dif[4], spec[4], uv[2]; } gv_t;            /* the shaders' GV */
typedef struct { int32_t a[4], b[4], c[4], d[4]; float tf[4], fogc[4]; } gu_t;   /* ...and U */
typedef struct { uint32_t dim[4], sh[4], bits[4]; } gpk_t;               /* ...and PK */
typedef struct { int32_t d[4], s[4]; uint32_t key[4], sh[4], bits[4]; } gbu_t;   /* ...and BU */

/* A surface on the GPU: as a render target (colour), a z-buffer (depth), or
 * a texture (tex and its colour key). */
typedef struct {
    surf_t *s;
    id<MTLTexture> color, depth, tex, key;
    id<MTLBuffer> xfer;                  /* the pixels on their way, in the surface's format */
    uint32_t gen;                        /* s->gen when memory and colour last agreed */
    int stale;                           /* memory has the newer pixels, whatever gen says */
    int dirty;                           /* the GPU has the newer pixels */
    uint32_t tex_gen;                    /* the argb cache's gen that tex holds */
    int depth_new;                       /* depth texture never cleared yet */
    uint32_t epoch;                      /* passes begun on it */
    id<MTLCommandBuffer> pending;        /* a download under way, of the colour as it was at epoch... */
    uint32_t pending_epoch;              /* ...this */
} grec_t;

static id<MTLDevice> g_dev;
static id<MTLCommandQueue> g_q;
static id<MTLRenderPipelineState> g_clear_pipe[2][2][2];          /* [depth?][colour?][alpha?] */
static id<MTLComputePipelineState> g_pack, g_unpack;
static id<MTLFunction> g_vs, g_fs, g_fs_clear, g_fs_blit;
static id<MTLRenderPipelineState> g_blit_pipe[2][2];              /* [depth?][alpha?] */
static id<MTLDepthStencilState> g_ds[2][2][9];                    /* [enabled][write][func] */
static id<MTLTexture> g_blank, g_blank_key;                       /* bound when a draw has no texture */
static NSMutableDictionary *g_pipes;                              /* blend key -> pipeline */

static id<MTLCommandBuffer> g_cb;                                 /* being filled */
static id<MTLCommandBuffer> g_last;                               /* the last committed */
static id<MTLRenderCommandEncoder> g_enc;
static surf_t *g_ts, *g_zs;                                       /* the pass's target and z-buffer */

static grec_t **g_dirty;
static int g_ndirty, g_cap_dirty;

/* Vertex memory: shared buffers, back in the pool when the GPU is done. */
#define VCHUNK (4u << 20)
static pthread_mutex_t g_pool_mu = PTHREAD_MUTEX_INITIALIZER;
static id<MTLBuffer> g_pool[64];
static int g_npool;
static id<MTLBuffer> g_used[256];
static int g_nused;
static id<MTLBuffer> g_vb;
static uint32_t g_voff;

/* The batch being gathered: one state, one kind of primitive. */
static rstate_t g_bst;
static int g_bkind = -1;                                          /* 0 triangles, 1 lines, 2 points */
static uint32_t g_bstart, g_bcount;

static int g_trace = -1;
static int trace(void) { if (g_trace < 0) g_trace = getenv("HLE_METALTRACE") != NULL; return g_trace; }

/* ---- records ---- */
static grec_t *rec(surf_t *s) {
    if (!s->gpu) {
        grec_t *r = (grec_t *)calloc(1, sizeof *r);
        r->s = s, r->stale = 1;
        s->gpu = r;
    }
    return (grec_t *)s->gpu;
}
static void rec_free(grec_t *r) {
    [r->pending release];
    [r->color release], [r->depth release], [r->tex release], [r->key release], [r->xfer release];
    free(r);
}
static void add_dirty(grec_t *r) {
    if (r->dirty) return;
    r->dirty = 1;
    if (g_ndirty == g_cap_dirty) {
        g_cap_dirty = g_cap_dirty ? g_cap_dirty * 2 : 16;
        g_dirty = (grec_t **)realloc(g_dirty, sizeof *g_dirty * (size_t)g_cap_dirty);
    }
    g_dirty[g_ndirty++] = r;
}
static void forget_dirty(grec_t *r) {
    for (int i = 0; i < g_ndirty; i++) if (g_dirty[i] == r) { g_dirty[i] = g_dirty[--g_ndirty]; break; }
}

/* A surface's format for the kernels. 0 if they cannot carry it. */
static int fmt_of(const surf_t *s, gpk_t *k) {
    if (s->bpp != 16 && s->bpp != 32) return 0;
    uint32_t m[4] = { s->rmask, s->gmask, s->bmask, s->amask };
    if (!s->pf_flags && !s->rmask) {
        if (s->bpp == 16) m[0] = 0xF800, m[1] = 0x07E0, m[2] = 0x001F, m[3] = 0;
        else m[0] = 0xFF0000, m[1] = 0xFF00, m[2] = 0xFF, m[3] = 0;
    }
    memset(k, 0, sizeof *k);
    k->dim[0] = (uint32_t)s->w, k->dim[1] = (uint32_t)s->h, k->dim[2] = (uint32_t)s->pitch, k->dim[3] = (uint32_t)s->bpp;
    for (int i = 0; i < 4; i++) {
        uint32_t v = m[i];
        int sh = 0, n = 0;
        if (v) { while (!(v & 1u)) v >>= 1, sh++; while (v & 1u) v >>= 1, n++; }
        k->sh[i] = (uint32_t)sh, k->bits[i] = (uint32_t)n;
    }
    return 1;
}
static int has_alpha(const surf_t *s) { gpk_t k; return fmt_of(s, &k) && k.bits[3]; }

/* ---- command buffers ---- */
static void end_pass(void);
static id<MTLCommandBuffer> cb(void) {
    if (!g_cb) g_cb = [[g_q commandBuffer] retain];
    return g_cb;
}
static void commit(int wait) {
    end_pass();
    g_vb = nil;                                          /* it goes back to the pool with this command buffer */
    if (!g_cb) { if (wait && g_last) [g_last waitUntilCompleted]; return; }
    if (g_nused) {                                       /* the vertex buffers go back when the GPU is done */
        int n = g_nused;
        id<MTLBuffer> *back = (id<MTLBuffer> *)malloc(sizeof *back * (size_t)n);
        memcpy(back, g_used, sizeof *back * (size_t)n);
        g_nused = 0;
        [g_cb addCompletedHandler:^(id<MTLCommandBuffer> done) {
            (void)done;
            pthread_mutex_lock(&g_pool_mu);
            for (int i = 0; i < n; i++) {
                if (g_npool < 64) g_pool[g_npool++] = back[i]; else [back[i] release];
            }
            pthread_mutex_unlock(&g_pool_mu);
            free(back);
        }];
    }
    [g_cb commit];
    [g_last release];
    g_last = g_cb, g_cb = nil;
    if (wait) [g_last waitUntilCompleted];
}

/* ---- textures ---- */
static id<MTLTexture> new_tex(MTLPixelFormat f, int w, int h, MTLTextureUsage use, MTLStorageMode m) {
    MTLTextureDescriptor *d = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:f width:(NSUInteger)w
                                                                                  height:(NSUInteger)h mipmapped:NO];
    d.usage = use, d.storageMode = m;
    return [g_dev newTextureWithDescriptor:d];
}
static void ensure_xfer(grec_t *r) {
    NSUInteger n = (NSUInteger)r->s->pitch * (NSUInteger)r->s->h;
    if (r->xfer && r->xfer.length >= n) return;
    [r->xfer release];
    r->xfer = [g_dev newBufferWithLength:n options:MTLResourceStorageModeShared];
}
static void dispatch(id<MTLComputePipelineState> p, id<MTLTexture> t, id<MTLBuffer> b, const gpk_t *k) {
    id<MTLComputeCommandEncoder> e = [cb() computeCommandEncoder];
    [e setComputePipelineState:p];
    [e setTexture:t atIndex:0];
    [e setBuffer:b offset:0 atIndex:0];
    [e setBytes:k length:sizeof *k atIndex:1];
    [e dispatchThreads:MTLSizeMake(k->dim[0], k->dim[1], 1) threadsPerThreadgroup:MTLSizeMake(16, 16, 1)];
    [e endEncoding];
}
/* The render target's colour texture, made or remade to its size. */
static grec_t *target(surf_t *s) {
    grec_t *r = rec(s);
    if (!r->color || (int)r->color.width != s->w || (int)r->color.height != s->h) {
        [r->color release];
        r->color = new_tex(MTLPixelFormatBGRA8Unorm, s->w, s->h,
                           MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead | MTLTextureUsageShaderWrite,
                           MTLStorageModePrivate);
        r->stale = 1;
    }
    return r;
}
static grec_t *zbuffer(surf_t *z) {
    grec_t *r = rec(z);
    if (!r->depth || (int)r->depth.width != z->w || (int)r->depth.height != z->h) {
        [r->depth release];
        r->depth = new_tex(MTLPixelFormatDepth32Float, z->w, z->h, MTLTextureUsageRenderTarget, MTLStorageModePrivate);
        r->depth_new = 1;
    }
    return r;
}
/* The pixels in memory up to the GPU (outside any pass). */
static void upload(grec_t *r) {
    gpk_t k;
    if (fmt_of(r->s, &k)) {
        ensure_xfer(r);
        memcpy(r->xfer.contents, r->s->px, (size_t)r->s->pitch * (size_t)r->s->h);
        dispatch(g_unpack, r->color, r->xfer, &k);
    }
    r->gen = r->s->gen, r->stale = 0;
}
/* A texture's pixels as d3d_raster_prepare left them (argb, keyed). */
static grec_t *texture(surf_t *s) {
    grec_t *r = rec(s);
    if (!s->argb) return NULL;
    if (!r->tex || (int)r->tex.width != s->w || (int)r->tex.height != s->h) {
        [r->tex release], [r->key release];
        r->tex = new_tex(MTLPixelFormatBGRA8Unorm, s->w, s->h, MTLTextureUsageShaderRead, MTLStorageModeShared);
        r->key = new_tex(MTLPixelFormatR8Uint, s->w, s->h, MTLTextureUsageShaderRead, MTLStorageModeShared);
        r->tex_gen = 0;
    }
    if (r->tex_gen != s->argb_gen || !r->tex_gen) {
        if (r->tex_gen) {                                /* draws queued on the old pixels keep them */
            [r->tex release], [r->key release];
            r->tex = new_tex(MTLPixelFormatBGRA8Unorm, s->w, s->h, MTLTextureUsageShaderRead, MTLStorageModeShared);
            r->key = new_tex(MTLPixelFormatR8Uint, s->w, s->h, MTLTextureUsageShaderRead, MTLStorageModeShared);
        }
        MTLRegion all = MTLRegionMake2D(0, 0, (NSUInteger)s->w, (NSUInteger)s->h);
        [r->tex replaceRegion:all mipmapLevel:0 withBytes:s->argb bytesPerRow:(NSUInteger)s->w * 4];
        [r->key replaceRegion:all mipmapLevel:0 withBytes:s->keyed bytesPerRow:(NSUInteger)s->w];
        r->tex_gen = s->argb_gen;
    }
    return r;
}

/* ---- passes ---- */
static void flush_batch(void);
static void end_pass(void) {
    if (!g_enc) return;
    [g_enc endEncoding];
    [g_enc release];
    g_enc = nil, g_ts = g_zs = NULL;
}
/* A pass drawing into t (and its z-buffer): its pixels go up first if
 * memory has newer ones, unless `whole` - all of it is about to be cleared. */
static void begin_pass(surf_t *t, int whole) {
    surf_t *z = t->zbuf;
    if (g_enc && g_ts == t && g_zs == z) return;
    end_pass();
    grec_t *r = target(t);
    if (whole) r->gen = t->gen, r->stale = 0;
    else if (!r->dirty && (r->stale || r->gen != t->gen)) upload(r);
    MTLRenderPassDescriptor *pd = [MTLRenderPassDescriptor renderPassDescriptor];
    pd.colorAttachments[0].texture = r->color;
    pd.colorAttachments[0].loadAction = MTLLoadActionLoad;
    pd.colorAttachments[0].storeAction = MTLStoreActionStore;
    if (z) {
        grec_t *zr = zbuffer(z);
        pd.depthAttachment.texture = zr->depth;
        pd.depthAttachment.loadAction = zr->depth_new ? MTLLoadActionClear : MTLLoadActionLoad;
        pd.depthAttachment.clearDepth = 1.0;
        pd.depthAttachment.storeAction = MTLStoreActionStore;
        zr->depth_new = 0;
    }
    g_enc = [[cb() renderCommandEncoderWithDescriptor:pd] retain];
    r->epoch++;
    [g_enc setDepthClipMode:MTLDepthClipModeClamp];
    float size[2] = { (float)t->w, (float)t->h };
    [g_enc setVertexBytes:size length:sizeof size atIndex:1];
    g_ts = t, g_zs = z;
    add_dirty(r);
}

/* ---- pipelines ---- */
static MTLBlendFactor factor(int f) {
    switch (f) {
    case 1: return MTLBlendFactorZero;
    case 3: return MTLBlendFactorSourceColor;
    case 4: return MTLBlendFactorOneMinusSourceColor;
    case 5: return MTLBlendFactorSourceAlpha;
    case 6: return MTLBlendFactorOneMinusSourceAlpha;
    case 7: return MTLBlendFactorDestinationAlpha;
    case 8: return MTLBlendFactorOneMinusDestinationAlpha;
    case 9: return MTLBlendFactorDestinationColor;
    case 10: return MTLBlendFactorOneMinusDestinationColor;
    case 11: return MTLBlendFactorSourceAlphaSaturated;
    default: return MTLBlendFactorOne;
    }
}
static id<MTLRenderPipelineState> make_pipe(id<MTLFunction> fs, int depth, int blend, int src, int dst, int write, int alpha) {
    MTLRenderPipelineDescriptor *d = [[MTLRenderPipelineDescriptor alloc] init];
    d.vertexFunction = g_vs, d.fragmentFunction = fs;
    d.colorAttachments[0].pixelFormat = MTLPixelFormatBGRA8Unorm;
    d.colorAttachments[0].writeMask = !write ? MTLColorWriteMaskNone
                                    : alpha ? MTLColorWriteMaskAll : MTLColorWriteMaskRed | MTLColorWriteMaskGreen | MTLColorWriteMaskBlue;
    if (blend) {
        MTLBlendFactor s = factor(src), t = factor(dst);
        if (src == 12) s = MTLBlendFactorSourceAlpha, t = MTLBlendFactorOneMinusSourceAlpha;           /* BOTHSRCALPHA */
        if (src == 13) s = MTLBlendFactorOneMinusSourceAlpha, t = MTLBlendFactorSourceAlpha;           /* BOTHINVSRCALPHA */
        d.colorAttachments[0].blendingEnabled = YES;
        d.colorAttachments[0].sourceRGBBlendFactor = d.colorAttachments[0].sourceAlphaBlendFactor = s;
        d.colorAttachments[0].destinationRGBBlendFactor = d.colorAttachments[0].destinationAlphaBlendFactor = t;
    }
    if (depth) d.depthAttachmentPixelFormat = MTLPixelFormatDepth32Float;
    NSError *err = nil;
    id<MTLRenderPipelineState> p = [g_dev newRenderPipelineStateWithDescriptor:d error:&err];
    [d release];
    if (!p) fprintf(stderr, "[metal] a pipeline: %s\n", err ? err.localizedDescription.UTF8String : "?");
    return p;
}
static id<MTLRenderPipelineState> pipe_for(const rstate_t *st) {
    int depth = st->target->zbuf != NULL, alpha = has_alpha(st->target);
    int blend = st->blend, src = blend ? st->srcblend : 0, dst = blend ? st->dstblend : 0;
    NSNumber *key = @(depth | alpha << 1 | blend << 2 | src << 3 | dst << 8);
    id<MTLRenderPipelineState> p = g_pipes[key];
    if (!p) {
        p = make_pipe(g_fs, depth, blend, src, dst, 1, alpha);
        if (!p) return nil;
        g_pipes[key] = p;
        [p release];
    }
    return p;
}
static id<MTLDepthStencilState> make_ds(int enabled, int write, int func) {
    static const MTLCompareFunction f[9] = { MTLCompareFunctionAlways, MTLCompareFunctionNever, MTLCompareFunctionLess,
        MTLCompareFunctionEqual, MTLCompareFunctionLessEqual, MTLCompareFunctionGreater, MTLCompareFunctionNotEqual,
        MTLCompareFunctionGreaterEqual, MTLCompareFunctionAlways };
    MTLDepthStencilDescriptor *d = [[MTLDepthStencilDescriptor alloc] init];
    d.depthCompareFunction = enabled ? f[func] : MTLCompareFunctionAlways;
    d.depthWriteEnabled = enabled && write;
    id<MTLDepthStencilState> s = [g_dev newDepthStencilStateWithDescriptor:d];
    [d release];
    return s;
}

/* ---- vertices ---- */
static gv_t *vspace(uint32_t n) {
    uint32_t need = n * (uint32_t)sizeof(gv_t);
    if (!g_vb || g_voff + need > VCHUNK) {
        flush_batch();
        if (g_nused == 256) commit(0);
        id<MTLBuffer> b = nil;
        pthread_mutex_lock(&g_pool_mu);
        if (g_npool) b = g_pool[--g_npool];
        pthread_mutex_unlock(&g_pool_mu);
        if (!b) b = [g_dev newBufferWithLength:VCHUNK options:MTLResourceStorageModeShared | MTLResourceCPUCacheModeWriteCombined];
        g_used[g_nused++] = b;
        g_vb = b, g_voff = 0;
    }
    gv_t *p = (gv_t *)((uint8_t *)g_vb.contents + g_voff);
    g_voff += need;
    return p;
}
static void put(gv_t *o, const rvert_t *v, const rvert_t *col) {
    o->p[0] = v->x, o->p[1] = v->y, o->p[2] = v->z, o->p[3] = v->rhw;
    o->dif[0] = col->r, o->dif[1] = col->g, o->dif[2] = col->b, o->dif[3] = col->a;
    o->spec[0] = col->sr, o->spec[1] = col->sg, o->spec[2] = col->sb, o->spec[3] = v->fog;
    o->uv[0] = v->u, o->uv[1] = v->v;
}

static void flush_batch(void) {
    if (g_bkind < 0 || !g_bcount) { g_bkind = -1; return; }
    const rstate_t *st = &g_bst;
    int kind = g_bkind;
    uint32_t start = g_bstart, count = g_bcount;
    g_bkind = -1, g_bcount = 0;
    surf_t *t = st->target;
    id<MTLRenderPipelineState> p = pipe_for(st);
    if (!p) return;
    begin_pass(t, 0);
    [g_enc setRenderPipelineState:p];
    int zon = st->zenable && t->zbuf, zf = st->zfunc >= 1 && st->zfunc <= 8 ? st->zfunc : 8;
    [g_enc setDepthStencilState:g_ds[zon][st->zwrite != 0][zf]];
    MTLScissorRect sr = { (NSUInteger)st->clip_l, (NSUInteger)st->clip_t,
                          (NSUInteger)(st->clip_r - st->clip_l), (NSUInteger)(st->clip_b - st->clip_t) };
    [g_enc setScissorRect:sr];
    gu_t u;
    memset(&u, 0, sizeof u);
    grec_t *tr = st->tex ? texture(st->tex) : NULL;
    u.a[0] = tr != NULL, u.a[1] = st->colorkey, u.a[2] = st->bilinear, u.a[3] = st->wrap_u;
    u.b[0] = st->wrap_v, u.b[1] = st->colorop, u.b[2] = st->colorarg1, u.b[3] = st->colorarg2;
    u.c[0] = st->alphaop, u.c[1] = st->alphaarg1, u.c[2] = st->alphaarg2, u.c[3] = st->alphatest;
    u.d[0] = st->alphafunc, u.d[1] = st->specular, u.d[2] = st->fog;
    memcpy(u.tf, st->tfactor, sizeof u.tf);
    u.fogc[0] = st->fog_r, u.fogc[1] = st->fog_g, u.fogc[2] = st->fog_b, u.fogc[3] = st->alpharef;
    [g_enc setFragmentBytes:&u length:sizeof u atIndex:0];
    [g_enc setFragmentTexture:tr ? tr->tex : g_blank atIndex:0];
    [g_enc setFragmentTexture:tr ? tr->key : g_blank_key atIndex:1];
    [g_enc setVertexBuffer:g_vb offset:0 atIndex:0];
    MTLPrimitiveType pt = kind == 0 ? MTLPrimitiveTypeTriangle : kind == 1 ? MTLPrimitiveTypeLine : MTLPrimitiveTypePoint;
    [g_enc drawPrimitives:pt vertexStart:start vertexCount:count];
}
/* Room for n more vertices of a kind in the batch, which st may end. */
static gv_t *batch(const rstate_t *st, int kind, uint32_t n) {
    if (g_bkind != kind || memcmp(&g_bst, st, sizeof *st)) flush_batch();
    gv_t *p = vspace(n);                                 /* a new buffer ends the batch too */
    if (g_bkind < 0) {
        g_bst = *st, g_bkind = kind, g_bcount = 0;
        g_bstart = (uint32_t)(((uint8_t *)p - (uint8_t *)g_vb.contents) / sizeof(gv_t));
    }
    g_bcount += n;
    return p;
}

/* ---- the renderer ---- */
static void m_triangle(const rstate_t *st, const rvert_t *a, const rvert_t *b, const rvert_t *c) {
    if (!st->target) return;
    float area = (b->x - a->x) * (c->y - a->y) - (b->y - a->y) * (c->x - a->x);
    if (area == 0 || !isfinite(area)) return;
    /* Screen y runs down: a clockwise triangle has a positive area here. */
    if (st->cull == 2 && area > 0) return;
    if (st->cull == 3 && area < 0) return;
    @autoreleasepool {
        gv_t *o = batch(st, 0, 3);
        put(&o[0], a, a), put(&o[1], b, st->flat ? a : b), put(&o[2], c, st->flat ? a : c);
    }
}
static void m_line(const rstate_t *st, const rvert_t *a, const rvert_t *b) {
    if (!st->target) return;
    @autoreleasepool {
        if (a == b || (a->x == b->x && a->y == b->y)) {
            gv_t *o = batch(st, 2, 1);
            put(&o[0], a, a);
        } else {
            gv_t *o = batch(st, 1, 2);
            put(&o[0], a, a), put(&o[1], b, b);
        }
    }
}
static void m_clear(surf_t *t, int l, int tp, int r, int b, uint32_t flags, uint32_t argb, float z) {
    if (!flags) return;
    @autoreleasepool {
        flush_batch();
        int depth = t->zbuf != NULL, colour = (flags & 1) != 0;
        if ((flags & 2) && !depth && !colour) return;
        begin_pass(t, colour && l == 0 && tp == 0 && r == t->w && b == t->h);
        int alpha = has_alpha(t);
        id<MTLRenderPipelineState> p = g_clear_pipe[depth][colour][1];   /* all four: no alpha keeps 1 */
        [g_enc setRenderPipelineState:p];
        [g_enc setDepthStencilState:g_ds[depth && (flags & 2)][depth && (flags & 2)][8]];
        MTLScissorRect sr = { (NSUInteger)l, (NSUInteger)tp, (NSUInteger)(r - l), (NSUInteger)(b - tp) };
        [g_enc setScissorRect:sr];
        rvert_t v[4];
        memset(v, 0, sizeof v);
        float zz = z < 0 ? 0 : z > 1 ? 1 : z;
        float xs[4] = { (float)l, (float)r, (float)l, (float)r }, ys[4] = { (float)tp, (float)tp, (float)b, (float)b };
        for (int i = 0; i < 4; i++) {
            v[i].x = xs[i], v[i].y = ys[i], v[i].z = zz, v[i].rhw = 1;
            v[i].r = (float)((argb >> 16) & 0xFF) / 255.f, v[i].g = (float)((argb >> 8) & 0xFF) / 255.f;
            v[i].b = (float)(argb & 0xFF) / 255.f, v[i].a = alpha ? (float)(argb >> 24) / 255.f : 1.f;
        }
        gv_t *o = vspace(6);
        uint32_t start = (uint32_t)(((uint8_t *)o - (uint8_t *)g_vb.contents) / sizeof(gv_t));
        put(&o[0], &v[0], &v[0]), put(&o[1], &v[1], &v[1]), put(&o[2], &v[2], &v[2]);
        put(&o[3], &v[1], &v[1]), put(&o[4], &v[3], &v[3]), put(&o[5], &v[2], &v[2]);
        [g_enc setVertexBuffer:g_vb offset:0 atIndex:0];
        [g_enc drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:start vertexCount:6];
    }
}
/* ---- down to memory ----
 * A download packs the colour into the record's buffer; when it is done the
 * buffer goes to the pixels in memory, and the record is clean unless a pass
 * began on it since. */
static void start_download(grec_t *r) {
    gpk_t k;
    if (r->pending || !fmt_of(r->s, &k)) return;
    end_pass();
    ensure_xfer(r);
    dispatch(g_pack, r->color, r->xfer, &k);
    r->pending = [cb() retain], r->pending_epoch = r->epoch;
}
static void finish_download(grec_t *r) {
    [r->pending release];
    r->pending = nil;
    memcpy(r->s->px, r->xfer.contents, (size_t)r->s->pitch * (size_t)r->s->h);
    if (r->pending_epoch == r->epoch) r->dirty = 0, forget_dirty(r);
    hle_dd_mark(r->s);
    r->gen = r->s->gen, r->stale = 0;
}
/* One surface's pixels into memory, now: DirectDraw is about to touch it. */
static void m_touch(surf_t *s) {
    @autoreleasepool {
        if (g_bkind >= 0 && (g_bst.tex == s || g_bst.target == s)) flush_batch();
        grec_t *r = (grec_t *)s->gpu;
        if (!r || !r->dirty) return;
        flush_batch();
        if (r->pending && r->pending_epoch != r->epoch) {    /* an older picture: it can wait */
            [r->pending waitUntilCompleted];
            finish_download(r);
        }
        if (!r->pending) { start_download(r); commit(0); }
        [r->pending waitUntilCompleted];
        finish_download(r);
    }
}
/* Every surface the GPU holds newer pixels of, into memory. */
static void m_sync(void) {
    @autoreleasepool {
        flush_batch();
        end_pass();
        for (int i = 0; i < g_ndirty; i++)
            if (g_dirty[i]->pending && g_dirty[i]->pending_epoch != g_dirty[i]->epoch) {
                [g_dirty[i]->pending waitUntilCompleted];
                finish_download(g_dirty[i--]);           /* it may have left the list */
            }
        for (int i = 0; i < g_ndirty; i++) start_download(g_dirty[i]);
        commit(1);
        while (g_ndirty) {
            grec_t *r = g_dirty[0];
            if (r->pending) finish_download(r);
            else r->dirty = 0, forget_dirty(r);         /* a format the kernels cannot carry: as it is */
        }
    }
}
/* Downloads that are done, into memory, waiting for none: the presenter is
 * about to show the primary. */
static void m_frame(void) {
    static int busy;
    if (busy) return;
    busy = 1;
    for (int i = 0; i < g_ndirty; i++) {
        grec_t *r = g_dirty[i];
        if (r->pending && r->pending.status >= MTLCommandBufferStatusCompleted) {
            finish_download(r);
            i = -1;                                      /* the list may have changed */
        }
    }
    busy = 0;
}
static void m_end_scene(surf_t *t) {
    @autoreleasepool {
        flush_batch();
        grec_t *r = t ? (grec_t *)t->gpu : NULL;
        if (t && t->primary && r && r->dirty) start_download(r);   /* drawn straight to the screen: show it */
        commit(0);
    }
}

/* ---- DirectDraw's side ---- */
static void m_free(surf_t *s) {
    @autoreleasepool { flush_batch(); }                  /* a batch may draw with it */
    grec_t *r = (grec_t *)s->gpu;
    if (!r) return;
    forget_dirty(r);
    s->gpu = NULL;
    @autoreleasepool {
        if (g_ts == s || g_zs == s) end_pass();
        commit(1);                                       /* nothing in flight may still read it */
    }
    rec_free(r);
}
/* The pixels changed places: the records follow them, each still as far
 * ahead of or behind its pixels as it was. The new front's picture starts
 * down to memory for the presenter, without waiting. */
static void m_flip(surf_t *front, surf_t *back) {
    grec_t *f = (grec_t *)front->gpu, *b = (grec_t *)back->gpu;
    /* Flip marked the front (gen + 1) before calling here. */
    int f_ok = f && !f->stale && f->gen == front->gen - 1, b_ok = b && !b->stale && b->gen == back->gen;
    @autoreleasepool { flush_batch(); end_pass(); }
    front->gpu = b, back->gpu = f;
    /* Newer on the GPU is never also newer in memory. */
    if (b) b->s = front, b->gen = front->gen, b->stale = !b_ok && !b->dirty;
    if (f) f->s = back, f->gen = back->gen, f->stale = !f_ok && !f->dirty;
    if (b && b->dirty) @autoreleasepool { start_download(b); commit(0); }
}
/* A blit on the GPU, when either end has newer pixels there: the
 * destination becomes the GPU's. Not for a surface onto itself, nor
 * between formats the kernels cannot carry. */
static int m_blit(surf_t *d, int dl, int dt, int dr, int db, surf_t *s, int sl, int st, int sr, int sb,
                  int keyed, uint32_t klo, uint32_t khi) {
    grec_t *rd = (grec_t *)d->gpu, *rs = (grec_t *)s->gpu;
    gpk_t kd, ks;
    if (s == d || !((rd && rd->dirty) || (rs && rs->dirty))) return 0;
    if (!fmt_of(d, &kd) || !fmt_of(s, &ks) || d->bpp != s->bpp) return 0;
    if (dr - dl <= 0 || db - dt <= 0 || sr - sl <= 0 || sb - st <= 0) return 1;
    @autoreleasepool {
        flush_batch();
        if (!(rs && rs->dirty)) {                        /* the source's pixels up, if they are not there */
            end_pass();
            rs = target(s);
            if (rs->stale || rs->gen != s->gen) upload(rs);
        }
        /* An empty destination is no pass at all: nothing changes. */
        if ((dl > d->w || dt > d->h || dr < 0 || db < 0)) return 1;
        begin_pass(d, 0);
        [g_enc setRenderPipelineState:g_blit_pipe[d->zbuf != NULL][has_alpha(d)]];
        [g_enc setDepthStencilState:g_ds[0][0][8]];
        int l = dl < 0 ? 0 : dl, t = dt < 0 ? 0 : dt, r = dr > d->w ? d->w : dr, b = db > d->h ? d->h : db;
        if (l >= r || t >= b) return 1;
        MTLScissorRect sc = { (NSUInteger)l, (NSUInteger)t, (NSUInteger)(r - l), (NSUInteger)(b - t) };
        [g_enc setScissorRect:sc];
        gbu_t u;
        memset(&u, 0, sizeof u);
        u.d[0] = dl, u.d[1] = dt, u.d[2] = dr - dl, u.d[3] = db - dt;
        u.s[0] = sl, u.s[1] = st, u.s[2] = sr - sl, u.s[3] = sb - st;
        u.key[0] = (uint32_t)keyed, u.key[1] = klo, u.key[2] = khi;
        memcpy(u.sh, ks.sh, sizeof u.sh), memcpy(u.bits, ks.bits, sizeof u.bits);
        [g_enc setFragmentBytes:&u length:sizeof u atIndex:0];
        [g_enc setFragmentTexture:rs->color atIndex:0];
        rvert_t v[4];
        memset(v, 0, sizeof v);
        float xs[4] = { (float)l, (float)r, (float)l, (float)r }, ys[4] = { (float)t, (float)t, (float)b, (float)b };
        for (int i = 0; i < 4; i++) v[i].x = xs[i], v[i].y = ys[i], v[i].rhw = 1;
        gv_t *o = vspace(6);
        uint32_t start = (uint32_t)(((uint8_t *)o - (uint8_t *)g_vb.contents) / sizeof(gv_t));
        put(&o[0], &v[0], &v[0]), put(&o[1], &v[1], &v[1]), put(&o[2], &v[2], &v[2]);
        put(&o[3], &v[1], &v[1]), put(&o[4], &v[3], &v[3]), put(&o[5], &v[2], &v[2]);
        [g_enc setVertexBuffer:g_vb offset:0 atIndex:0];
        [g_enc drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:start vertexCount:6];
    }
    return 1;
}

static const d3d_gpu_t g_metal = { "metal", m_triangle, m_line, m_clear, m_end_scene, m_sync };

int hle_d3d_metal_enable(void) {
    @autoreleasepool {
        g_dev = MTLCreateSystemDefaultDevice();
        if (!g_dev) { fprintf(stderr, "[metal] no Metal device: software rendering\n"); return -1; }
        g_q = [g_dev newCommandQueue];
        NSError *err = nil;
        id<MTLLibrary> lib = [g_dev newLibraryWithSource:[NSString stringWithUTF8String:g_src] options:nil error:&err];
        if (!lib) {
            fprintf(stderr, "[metal] the shaders: %s\n", err ? err.localizedDescription.UTF8String : "?");
            return -1;
        }
        g_vs = [lib newFunctionWithName:@"vs"], g_fs = [lib newFunctionWithName:@"fs"];
        g_fs_clear = [lib newFunctionWithName:@"fs_clear"];
        g_fs_blit = [lib newFunctionWithName:@"fs_blit"];
        id<MTLFunction> pk = [lib newFunctionWithName:@"pack"], up = [lib newFunctionWithName:@"unpack"];
        g_pack = [g_dev newComputePipelineStateWithFunction:pk error:&err];
        g_unpack = [g_dev newComputePipelineStateWithFunction:up error:&err];
        [pk release], [up release], [lib release];
        if (!g_pack || !g_unpack) { fprintf(stderr, "[metal] the kernels failed\n"); return -1; }
        for (int d = 0; d < 2; d++)
            for (int c = 0; c < 2; c++)
                for (int a = 0; a < 2; a++) g_clear_pipe[d][c][a] = make_pipe(g_fs_clear, d, 0, 0, 0, c, a);
        for (int d = 0; d < 2; d++)
            for (int a = 0; a < 2; a++) g_blit_pipe[d][a] = make_pipe(g_fs_blit, d, 0, 0, 0, 1, a);
        for (int e = 0; e < 2; e++)
            for (int w = 0; w < 2; w++)
                for (int f = 0; f < 9; f++) g_ds[e][w][f] = make_ds(e, w, f);
        g_pipes = [[NSMutableDictionary alloc] init];
        g_blank = new_tex(MTLPixelFormatBGRA8Unorm, 1, 1, MTLTextureUsageShaderRead, MTLStorageModeShared);
        g_blank_key = new_tex(MTLPixelFormatR8Uint, 1, 1, MTLTextureUsageShaderRead, MTLStorageModeShared);
        uint32_t white = 0xFFFFFFFFu;
        uint8_t zero = 0;
        [g_blank replaceRegion:MTLRegionMake2D(0, 0, 1, 1) mipmapLevel:0 withBytes:&white bytesPerRow:4];
        [g_blank_key replaceRegion:MTLRegionMake2D(0, 0, 1, 1) mipmapLevel:0 withBytes:&zero bytesPerRow:1];
        hle_dd_free_hook = m_free;
        hle_dd_flip_hook = m_flip;
        hle_dd_sync_hook = m_touch;
        hle_dd_blit_hook = m_blit;
        hle_dd_frame_hook = m_frame;
        hle_d3d_gpu = &g_metal;
        fprintf(stderr, "[metal] drawing on %s\n", g_dev.name.UTF8String);
        if (trace()) fprintf(stderr, "[metal] HLE_METALTRACE on\n");
    }
    return 0;
}

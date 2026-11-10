/*
 * d3d_vulkan.c - Direct3D's drawing on the GPU, through Vulkan (Linux): the
 * renderer d3d_gpu.h describes, in place of d3d_raster.c, made as
 * d3d_metal.m is on a Mac, part for part.
 *
 * Every surface Direct3D draws into gets a colour image (RGBA8, whatever the
 * surface's own format) and its z-buffer a depth image. Triangles go in
 * batches: consecutive ones with the same state are one draw. The fragment
 * shader (vulkan/d3d.frag) is d3d_raster.c's shade(), the texture read texel
 * by texel as it reads it, so all three renderers draw alike; blending and
 * the depth test are the GPU's own.
 *
 * Pixels go between memory and the GPU through a host-visible buffer, packed
 * and unpacked by two compute shaders into the surface's own format. Down
 * when DirectDraw is about to touch a surface; up when a surface changed in
 * memory since the GPU last had it, before the GPU draws into it, unless the
 * first thing drawn is a clear of all of it. A blit with either end on the
 * GPU is drawn there, and a flip starts the new front down without waiting,
 * for the presenter to show when it is there (hle_dd_frame_hook): so the game
 * does not wait for the GPU in a frame, and there is no swapchain - the
 * presenter shows the frame as it shows any other.
 *
 * Vulkan 1.3 (dynamic rendering), headless, the loader opened at run time
 * (libvulkan.so.1): a computer without it, or without a GPU, keeps the
 * software renderer. Images stay in the GENERAL layout, and one memory
 * barrier comes between a write and whatever follows it. The shaders are
 * SPIR-V, built from vulkan/ by vulkan/spv.sh into d3d_vulkan_spv.h.
 *
 * HLE_VULKAN_DEBUG=1 turns on the validation layer, if installed;
 * HLE_VULKAN_ANY=1 lets a software Vulkan (llvmpipe) draw; HLE_VULKAN_STATS=1
 * prints the flips a second.
 */
#include <stdio.h>
#include "win32hle.h"
#include "d3d_gpu.h"

#if !defined(__APPLE__) && defined(__has_include)
#if __has_include(<vulkan/vulkan.h>)
#define HLE_HAVE_VULKAN 1
#endif
#endif

#ifndef HLE_HAVE_VULKAN
int hle_d3d_vulkan_enable(void) {
    fprintf(stderr, "[vulkan] not built in (no Vulkan headers): software rendering\n");
    return -1;
}
#else

#define VK_NO_PROTOTYPES
#include <vulkan/vulkan.h>
#include <dlfcn.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include "d3d_vulkan_spv.h"

/* ---- the entry points, from the loader ---- */
#define VK_GLOBAL(X) X(vkCreateInstance) X(vkEnumerateInstanceVersion) X(vkEnumerateInstanceLayerProperties)
#define VK_INSTANCE(X) X(vkDestroyInstance) X(vkEnumeratePhysicalDevices) X(vkGetPhysicalDeviceProperties) \
    X(vkGetPhysicalDeviceQueueFamilyProperties) X(vkGetPhysicalDeviceMemoryProperties) X(vkGetPhysicalDeviceFeatures) \
    X(vkGetPhysicalDeviceFeatures2) X(vkCreateDevice) X(vkGetDeviceProcAddr)
#define VK_DEVICE(X) X(vkGetDeviceQueue) X(vkQueueSubmit) X(vkCreateCommandPool) X(vkAllocateCommandBuffers) \
    X(vkBeginCommandBuffer) X(vkEndCommandBuffer) X(vkResetCommandBuffer) X(vkCreateFence) X(vkWaitForFences) \
    X(vkResetFences) X(vkGetFenceStatus) X(vkCreateBuffer) X(vkDestroyBuffer) X(vkGetBufferMemoryRequirements) \
    X(vkBindBufferMemory) X(vkAllocateMemory) X(vkFreeMemory) X(vkMapMemory) X(vkCreateImage) X(vkDestroyImage) \
    X(vkGetImageMemoryRequirements) X(vkBindImageMemory) X(vkCreateImageView) X(vkDestroyImageView) \
    X(vkCreateSampler) X(vkCreateShaderModule) X(vkCreateDescriptorSetLayout) X(vkCreatePipelineLayout) \
    X(vkCreateDescriptorPool) X(vkResetDescriptorPool) X(vkAllocateDescriptorSets) X(vkUpdateDescriptorSets) \
    X(vkCreateGraphicsPipelines) X(vkCreateComputePipelines) X(vkCmdBindPipeline) X(vkCmdBindDescriptorSets) \
    X(vkCmdPushConstants) X(vkCmdBindVertexBuffers) X(vkCmdDraw) X(vkCmdSetViewport) X(vkCmdSetScissor) \
    X(vkCmdDispatch) X(vkCmdPipelineBarrier) X(vkCmdCopyBufferToImage)
#define DECL(f) static PFN_##f f;
VK_GLOBAL(DECL) VK_INSTANCE(DECL) VK_DEVICE(DECL)
static PFN_vkGetInstanceProcAddr gipa;
static PFN_vkCmdBeginRendering vkCmdBeginRendering_;
static PFN_vkCmdEndRendering vkCmdEndRendering_;

/* ---- what this side keeps ---- */
typedef struct { float p[4], dif[4], spec[4], uv[2]; } gv_t;                      /* d3d.vert's inputs */
typedef struct { int32_t a[4], b[4], c[4], d[4]; float tf[4], fogc[4]; } gu_t;    /* d3d.frag's U */
typedef struct { uint32_t dim[4], sh[4], bits[4], words, row; } gpk_t;            /* pack/unpack's PK */
typedef struct { int32_t d[4], s[4]; uint32_t key[4], sh[4], bits[4]; } gbu_t;    /* blit.frag's BU */

typedef struct { VkBuffer b; VkDeviceMemory m; uint8_t *map; VkDeviceSize size; } buf_t;
typedef struct { VkImage i; VkDeviceMemory m; VkImageView v; int w, h; } img_t;

/* A surface on the GPU: as a render target (colour), a z-buffer (depth), or
 * a texture (tex and its colour key). */
typedef struct {
    surf_t *s;
    img_t color, depth, tex, key;
    buf_t xfer;                          /* the pixels on their way, in the surface's format */
    uint32_t gen;                        /* s->gen when memory and colour last agreed */
    int stale;                           /* memory has the newer pixels, whatever gen says */
    int dirty;                           /* the GPU has the newer pixels */
    uint32_t tex_gen;                    /* the argb cache's gen that tex holds */
    int depth_new;                       /* depth image never cleared yet */
    uint32_t epoch;                      /* passes begun on it */
    uint64_t pending;                    /* a download under way (its submission), of the colour as it was at epoch... */
    uint32_t pending_epoch;              /* ...this */
} grec_t;

static void *g_lib;
static VkInstance g_inst;
static VkPhysicalDevice g_pd;
static VkDevice g_dev;
static VkQueue g_q;
static uint32_t g_qfam;
static VkPhysicalDeviceMemoryProperties g_mem;
static VkBool32 g_depth_clamp;
static VkCommandPool g_cpool;
static VkShaderModule g_vs, g_fs, g_fs_clear, g_fs_blit, g_cs_pack, g_cs_unpack;
static VkDescriptorSetLayout g_gfx_dsl, g_cmp_dsl;
static VkPipelineLayout g_gfx_pl, g_cmp_pl;
static VkPipeline g_pack, g_unpack;
static VkSampler g_sampler;
static img_t g_blank, g_blank_key;                                /* bound when a draw has no texture */

/* ---- submissions: a command buffer, its fence, and what goes when done ---- */
#define NSUB 16
#define VCHUNK (4u << 20)
typedef struct { int kind; buf_t b; img_t i; } junk_t;           /* kind 0 buffer, 1 image */
typedef struct {
    VkCommandBuffer cb;
    VkFence fence;
    VkDescriptorPool dp;
    uint64_t serial;
    int busy;                            /* submitted, not yet retired */
    junk_t *junk; int njunk, capjunk;
    buf_t *chunks; int nchunks, capchunks;   /* vertex memory it used, back to the pool when done */
} sub_t;
static sub_t g_sub[NSUB];
static int g_cur = -1;                                            /* being recorded */
static int g_next;                                                /* the slot after the last used */
static uint64_t g_serial, g_last;                                 /* the last begun, the last submitted */

static buf_t g_pool[64];
static int g_npool;
static buf_t g_vb;                                                /* the vertex chunk being filled */
static uint32_t g_voff;

static int g_rendering;                                           /* a dynamic-rendering pass is open */
static surf_t *g_ts, *g_zs;                                       /* the pass's target and z-buffer */
static int g_need_barrier;                                        /* something wrote since the last barrier */

static grec_t **g_dirty;
static int g_ndirty, g_cap_dirty;

/* The batch being gathered: one state, one kind of primitive. */
static rstate_t g_bst;
static int g_bkind = -1;                                          /* 0 triangles, 1 lines, 2 points */
static uint32_t g_bstart, g_bcount;

static int g_failed;
static void vk_fail(const char *what, VkResult r) {
    if (!g_failed++) fprintf(stderr, "[vulkan] %s failed (%d)\n", what, (int)r);
}
#define VKC(call) do { VkResult r_ = (call); if (r_ != VK_SUCCESS) vk_fail(#call, r_); } while (0)

/* ---- memory, buffers, images ---- */
static int mem_type(uint32_t bits, VkMemoryPropertyFlags want, VkMemoryPropertyFlags prefer) {
    for (int pass = 0; pass < 2; pass++)
        for (uint32_t i = 0; i < g_mem.memoryTypeCount; i++) {
            VkMemoryPropertyFlags f = g_mem.memoryTypes[i].propertyFlags;
            if (!(bits & (1u << i)) || (f & want) != want) continue;
            if (pass == 0 && (f & prefer) != prefer) continue;
            return (int)i;
        }
    return -1;
}
/* A buffer the CPU writes (readback 0) or reads (readback 1), mapped. */
static buf_t buf_new(VkDeviceSize size, VkBufferUsageFlags use, int readback) {
    buf_t o;
    memset(&o, 0, sizeof o);
    VkBufferCreateInfo bi = { VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO };
    bi.size = size, bi.usage = use, bi.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    VKC(vkCreateBuffer(g_dev, &bi, NULL, &o.b));
    VkMemoryRequirements mr;
    vkGetBufferMemoryRequirements(g_dev, o.b, &mr);
    VkMemoryAllocateInfo ai = { VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO };
    ai.allocationSize = mr.size;
    int t = mem_type(mr.memoryTypeBits, VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
                     readback ? VK_MEMORY_PROPERTY_HOST_CACHED_BIT : 0);
    ai.memoryTypeIndex = (uint32_t)(t < 0 ? 0 : t);
    VKC(vkAllocateMemory(g_dev, &ai, NULL, &o.m));
    VKC(vkBindBufferMemory(g_dev, o.b, o.m, 0));
    void *p = NULL;
    VKC(vkMapMemory(g_dev, o.m, 0, VK_WHOLE_SIZE, 0, &p));
    o.map = (uint8_t *)p, o.size = size;
    return o;
}
static void buf_free(buf_t *o) {
    if (o->b) vkDestroyBuffer(g_dev, o->b, NULL);
    if (o->m) vkFreeMemory(g_dev, o->m, NULL);
    memset(o, 0, sizeof *o);
}
static img_t img_new(VkFormat f, int w, int h, VkImageUsageFlags use, VkImageAspectFlags aspect) {
    img_t o;
    memset(&o, 0, sizeof o);
    VkImageCreateInfo ii = { VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO };
    ii.imageType = VK_IMAGE_TYPE_2D, ii.format = f;
    ii.extent.width = (uint32_t)w, ii.extent.height = (uint32_t)h, ii.extent.depth = 1;
    ii.mipLevels = 1, ii.arrayLayers = 1, ii.samples = VK_SAMPLE_COUNT_1_BIT;
    ii.tiling = VK_IMAGE_TILING_OPTIMAL, ii.usage = use, ii.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    ii.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    VKC(vkCreateImage(g_dev, &ii, NULL, &o.i));
    VkMemoryRequirements mr;
    vkGetImageMemoryRequirements(g_dev, o.i, &mr);
    VkMemoryAllocateInfo ai = { VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO };
    ai.allocationSize = mr.size;
    int t = mem_type(mr.memoryTypeBits, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, 0);
    if (t < 0) t = mem_type(mr.memoryTypeBits, 0, 0);
    ai.memoryTypeIndex = (uint32_t)(t < 0 ? 0 : t);
    VKC(vkAllocateMemory(g_dev, &ai, NULL, &o.m));
    VKC(vkBindImageMemory(g_dev, o.i, o.m, 0));
    VkImageViewCreateInfo vi = { VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO };
    vi.image = o.i, vi.viewType = VK_IMAGE_VIEW_TYPE_2D, vi.format = f;
    vi.subresourceRange.aspectMask = aspect, vi.subresourceRange.levelCount = 1, vi.subresourceRange.layerCount = 1;
    VKC(vkCreateImageView(g_dev, &vi, NULL, &o.v));
    o.w = w, o.h = h;
    return o;
}
static void img_free(img_t *o) {
    if (o->v) vkDestroyImageView(g_dev, o->v, NULL);
    if (o->i) vkDestroyImage(g_dev, o->i, NULL);
    if (o->m) vkFreeMemory(g_dev, o->m, NULL);
    memset(o, 0, sizeof *o);
}

/* ---- submissions ---- */
static void retire(sub_t *s) {
    for (int i = 0; i < s->njunk; i++) {
        if (s->junk[i].kind == 0) buf_free(&s->junk[i].b); else img_free(&s->junk[i].i);
    }
    s->njunk = 0;
    for (int i = 0; i < s->nchunks; i++) {
        if (g_npool < 64) g_pool[g_npool++] = s->chunks[i]; else buf_free(&s->chunks[i]);
    }
    s->nchunks = 0;
    vkResetDescriptorPool(g_dev, s->dp, 0);
    s->busy = 0;
}
static void sub_wait(sub_t *s) {
    if (!s->busy) return;
    VKC(vkWaitForFences(g_dev, 1, &s->fence, VK_TRUE, UINT64_MAX));
    retire(s);
}
static VkCommandBuffer cb(void) {
    if (g_cur >= 0) return g_sub[g_cur].cb;
    sub_t *s = &g_sub[g_next];
    sub_wait(s);                                         /* the oldest: long done, as a rule */
    VKC(vkResetFences(g_dev, 1, &s->fence));
    VKC(vkResetCommandBuffer(s->cb, 0));
    VkCommandBufferBeginInfo bi = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    VKC(vkBeginCommandBuffer(s->cb, &bi));
    s->serial = ++g_serial;
    g_cur = g_next, g_next = (g_next + 1) % NSUB;
    g_need_barrier = 1;                                  /* submissions on one queue may overlap */
    return s->cb;
}
static sub_t *sub_of(uint64_t serial) {
    for (int i = 0; i < NSUB; i++) if (g_sub[i].serial == serial) return &g_sub[i];
    return NULL;
}
/* Whether a submission is done (or long gone). */
static int done(uint64_t serial) {
    sub_t *s = sub_of(serial);
    if (!s || (s - g_sub) == g_cur) return s == NULL;
    if (!s->busy) return 1;
    if (vkGetFenceStatus(g_dev, s->fence) != VK_SUCCESS) return 0;
    retire(s);
    return 1;
}
static void end_pass(void);
static void commit(int wait) {
    end_pass();
    g_vb.b = VK_NULL_HANDLE;                             /* it goes back to the pool with this submission */
    if (g_cur < 0) { if (wait && g_last) { sub_t *s = sub_of(g_last); if (s) sub_wait(s); } return; }
    sub_t *s = &g_sub[g_cur];
    VKC(vkEndCommandBuffer(s->cb));
    VkSubmitInfo si = { VK_STRUCTURE_TYPE_SUBMIT_INFO };
    si.commandBufferCount = 1, si.pCommandBuffers = &s->cb;
    VKC(vkQueueSubmit(g_q, 1, &si, s->fence));
    s->busy = 1, g_last = s->serial, g_cur = -1;
    if (wait) sub_wait(s);
}
/* A submission's end, waited for: committed first if it is still being recorded. */
static void wait_serial(uint64_t serial) {
    if (g_cur >= 0 && g_sub[g_cur].serial == serial) commit(0);
    sub_t *s = sub_of(serial);
    if (s) sub_wait(s);
}
/* Freed when nothing in flight may use it any more. */
static sub_t *latest(void) {
    if (g_cur >= 0) return &g_sub[g_cur];
    sub_t *s = g_last ? sub_of(g_last) : NULL;
    return s && s->busy ? s : NULL;
}
static void junk(int kind, buf_t *b, img_t *i) {
    sub_t *s = latest();
    if (!s) { if (kind == 0) buf_free(b); else img_free(i); return; }
    if (s->njunk == s->capjunk) {
        s->capjunk = s->capjunk ? s->capjunk * 2 : 16;
        s->junk = (junk_t *)realloc(s->junk, sizeof *s->junk * (size_t)s->capjunk);
    }
    junk_t *j = &s->junk[s->njunk++];
    j->kind = kind;
    if (kind == 0) j->b = *b; else j->i = *i;
    if (b) memset(b, 0, sizeof *b);
    if (i) memset(i, 0, sizeof *i);
}
static void junk_buf(buf_t *b) { if (b->b) junk(0, b, NULL); }
static void junk_img(img_t *i) { if (i->i) junk(1, NULL, i); }

/* One barrier between whatever wrote and whatever comes next (outside a pass). */
static void barrier(void) {
    if (!g_need_barrier) return;
    VkMemoryBarrier mb = { VK_STRUCTURE_TYPE_MEMORY_BARRIER };
    mb.srcAccessMask = VK_ACCESS_MEMORY_WRITE_BIT;
    mb.dstAccessMask = VK_ACCESS_MEMORY_READ_BIT | VK_ACCESS_MEMORY_WRITE_BIT;
    vkCmdPipelineBarrier(cb(), VK_PIPELINE_STAGE_ALL_COMMANDS_BIT, VK_PIPELINE_STAGE_ALL_COMMANDS_BIT, 0,
                         1, &mb, 0, NULL, 0, NULL);
    g_need_barrier = 0;
}
/* A new image into the layout it keeps (outside a pass). */
static void layout(img_t *i, VkImageAspectFlags aspect, VkImageLayout to) {
    end_pass();
    VkImageMemoryBarrier ib = { VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER };
    ib.srcAccessMask = 0, ib.dstAccessMask = VK_ACCESS_MEMORY_READ_BIT | VK_ACCESS_MEMORY_WRITE_BIT;
    ib.oldLayout = VK_IMAGE_LAYOUT_UNDEFINED, ib.newLayout = to;
    ib.srcQueueFamilyIndex = ib.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    ib.image = i->i;
    ib.subresourceRange.aspectMask = aspect, ib.subresourceRange.levelCount = 1, ib.subresourceRange.layerCount = 1;
    vkCmdPipelineBarrier(cb(), VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, VK_PIPELINE_STAGE_ALL_COMMANDS_BIT, 0,
                         0, NULL, 0, NULL, 1, &ib);
}

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
    img_free(&r->color), img_free(&r->depth), img_free(&r->tex), img_free(&r->key), buf_free(&r->xfer);
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

/* A surface's format for the compute shaders. 0 if they cannot carry it. */
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
static VkDeviceSize xfer_size(const surf_t *s) { return ((VkDeviceSize)s->pitch * (VkDeviceSize)s->h + 3) & ~(VkDeviceSize)3; }

/* ---- descriptors ---- */
static VkDescriptorSet dset(VkDescriptorSetLayout l) {
    for (int tries = 0; tries < 2; tries++) {
        cb();
        VkDescriptorSetAllocateInfo ai = { VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO };
        ai.descriptorPool = g_sub[g_cur].dp, ai.descriptorSetCount = 1, ai.pSetLayouts = &l;
        VkDescriptorSet s;
        if (vkAllocateDescriptorSets(g_dev, &ai, &s) == VK_SUCCESS) return s;
        commit(0);                                       /* the pool is spent: a new submission has another */
    }
    vk_fail("vkAllocateDescriptorSets", VK_ERROR_OUT_OF_POOL_MEMORY);
    return VK_NULL_HANDLE;
}
static VkDescriptorSet gfx_set(VkImageView a, VkImageView b) {
    VkDescriptorSet s = dset(g_gfx_dsl);
    VkDescriptorImageInfo ii[2] = { { g_sampler, a, VK_IMAGE_LAYOUT_GENERAL }, { g_sampler, b, VK_IMAGE_LAYOUT_GENERAL } };
    VkWriteDescriptorSet w = { VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET };
    w.dstSet = s, w.dstBinding = 0, w.descriptorCount = 2, w.descriptorType = VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER;
    w.pImageInfo = ii;
    vkUpdateDescriptorSets(g_dev, 1, &w, 0, NULL);
    return s;
}

/* ---- the compute shaders: pack and unpack ---- */
static void dispatch(int pack, img_t *t, buf_t *b, gpk_t *k) {
    end_pass();
    VkDescriptorSet s = dset(g_cmp_dsl);
    VkDescriptorImageInfo ii = { VK_NULL_HANDLE, t->v, VK_IMAGE_LAYOUT_GENERAL };
    VkDescriptorBufferInfo bi = { b->b, 0, VK_WHOLE_SIZE };
    VkWriteDescriptorSet w[2] = { { VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET }, { VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET } };
    w[0].dstSet = s, w[0].dstBinding = 0, w[0].descriptorCount = 1, w[0].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_IMAGE;
    w[0].pImageInfo = &ii;
    w[1].dstSet = s, w[1].dstBinding = 1, w[1].descriptorCount = 1, w[1].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    w[1].pBufferInfo = &bi;
    vkUpdateDescriptorSets(g_dev, 2, w, 0, NULL);
    VkCommandBuffer c = cb();
    barrier();
    vkCmdBindPipeline(c, VK_PIPELINE_BIND_POINT_COMPUTE, pack ? g_pack : g_unpack);
    vkCmdBindDescriptorSets(c, VK_PIPELINE_BIND_POINT_COMPUTE, g_cmp_pl, 0, 1, &s, 0, NULL);
    uint32_t gx, gy;
    if (pack) {
        k->words = (k->dim[2] * k->dim[1] + 3) / 4;      /* the buffer's 32-bit words, padding and all */
        uint32_t groups = (k->words + 63) / 64;
        gx = groups < 32768 ? groups : 32768, gy = (groups + gx - 1) / gx;
        k->row = gx * 64;
    } else {
        gx = (k->dim[0] + 7) / 8, gy = (k->dim[1] + 7) / 8;
    }
    vkCmdPushConstants(c, g_cmp_pl, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof *k, k);
    vkCmdDispatch(c, gx ? gx : 1, gy ? gy : 1, 1);
    g_need_barrier = 1;
}

/* ---- images ---- */
#define COLOR_FMT VK_FORMAT_R8G8B8A8_UNORM
#define DEPTH_FMT VK_FORMAT_D32_SFLOAT
static void ensure_xfer(grec_t *r) {
    VkDeviceSize n = xfer_size(r->s);
    if (r->xfer.b && r->xfer.size >= n) return;
    junk_buf(&r->xfer);
    r->xfer = buf_new(n, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT, 1);
}
/* The render target's colour image, made or remade to its size. */
static grec_t *target(surf_t *s) {
    grec_t *r = rec(s);
    if (!r->color.i || r->color.w != s->w || r->color.h != s->h) {
        junk_img(&r->color);
        r->color = img_new(COLOR_FMT, s->w, s->h, VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT | VK_IMAGE_USAGE_SAMPLED_BIT |
                           VK_IMAGE_USAGE_STORAGE_BIT, VK_IMAGE_ASPECT_COLOR_BIT);
        layout(&r->color, VK_IMAGE_ASPECT_COLOR_BIT, VK_IMAGE_LAYOUT_GENERAL);
        r->stale = 1;
    }
    return r;
}
static grec_t *zbuffer(surf_t *z) {
    grec_t *r = rec(z);
    if (!r->depth.i || r->depth.w != z->w || r->depth.h != z->h) {
        junk_img(&r->depth);
        r->depth = img_new(DEPTH_FMT, z->w, z->h, VK_IMAGE_USAGE_DEPTH_STENCIL_ATTACHMENT_BIT, VK_IMAGE_ASPECT_DEPTH_BIT);
        layout(&r->depth, VK_IMAGE_ASPECT_DEPTH_BIT, VK_IMAGE_LAYOUT_DEPTH_ATTACHMENT_OPTIMAL);
        r->depth_new = 1;
    }
    return r;
}
/* The pixels in memory up to the GPU (outside any pass). */
static void upload(grec_t *r) {
    gpk_t k;
    if (fmt_of(r->s, &k)) {
        ensure_xfer(r);
        memcpy(r->xfer.map, r->s->px, (size_t)r->s->pitch * (size_t)r->s->h);
        dispatch(0, &r->color, &r->xfer, &k);
    }
    r->gen = r->s->gen, r->stale = 0;
}
/* Bytes into an image, through a buffer that goes when the copy is done
 * (outside any pass). Draws recorded before it read what was there before. */
static void copy_in(img_t *i, const void *px, size_t n, VkImageAspectFlags aspect) {
    end_pass();
    buf_t st = buf_new(n, VK_BUFFER_USAGE_TRANSFER_SRC_BIT, 0);
    memcpy(st.map, px, n);
    VkCommandBuffer c = cb();
    barrier();
    VkBufferImageCopy bc;
    memset(&bc, 0, sizeof bc);
    bc.imageSubresource.aspectMask = aspect, bc.imageSubresource.layerCount = 1;
    bc.imageExtent.width = (uint32_t)i->w, bc.imageExtent.height = (uint32_t)i->h, bc.imageExtent.depth = 1;
    vkCmdCopyBufferToImage(c, st.b, i->i, VK_IMAGE_LAYOUT_GENERAL, 1, &bc);
    g_need_barrier = 1;
    junk_buf(&st);
}
/* A texture's pixels as d3d_raster_prepare left them (argb, keyed). */
static grec_t *texture(surf_t *s) {
    grec_t *r = rec(s);
    if (!s->argb) return NULL;
    if (!r->tex.i || r->tex.w != s->w || r->tex.h != s->h) {
        junk_img(&r->tex), junk_img(&r->key);
        r->tex = img_new(VK_FORMAT_B8G8R8A8_UNORM, s->w, s->h, VK_IMAGE_USAGE_SAMPLED_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT,
                         VK_IMAGE_ASPECT_COLOR_BIT);
        r->key = img_new(VK_FORMAT_R8_UINT, s->w, s->h, VK_IMAGE_USAGE_SAMPLED_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT,
                         VK_IMAGE_ASPECT_COLOR_BIT);
        layout(&r->tex, VK_IMAGE_ASPECT_COLOR_BIT, VK_IMAGE_LAYOUT_GENERAL);
        layout(&r->key, VK_IMAGE_ASPECT_COLOR_BIT, VK_IMAGE_LAYOUT_GENERAL);
        r->tex_gen = 0;
    }
    if (r->tex_gen != s->argb_gen || !r->tex_gen) {
        copy_in(&r->tex, s->argb, (size_t)s->w * (size_t)s->h * 4, VK_IMAGE_ASPECT_COLOR_BIT);
        copy_in(&r->key, s->keyed, (size_t)s->w * (size_t)s->h, VK_IMAGE_ASPECT_COLOR_BIT);
        r->tex_gen = s->argb_gen;
    }
    return r;
}

/* ---- passes ---- */
static void flush_batch(void);
static void end_pass(void) {
    if (!g_rendering) return;
    vkCmdEndRendering_(g_sub[g_cur].cb);
    g_rendering = 0, g_ts = g_zs = NULL;
    g_need_barrier = 1;
}
/* A pass drawing into t (and its z-buffer): its pixels go up first if
 * memory has newer ones, unless `whole` - all of it is about to be cleared. */
static void begin_pass(surf_t *t, int whole) {
    surf_t *z = t->zbuf;
    if (g_rendering && g_ts == t && g_zs == z) return;
    end_pass();
    grec_t *r = target(t);
    if (whole) r->gen = t->gen, r->stale = 0;
    else if (!r->dirty && (r->stale || r->gen != t->gen)) upload(r);
    grec_t *zr = z ? zbuffer(z) : NULL;
    VkCommandBuffer c = cb();
    barrier();
    VkRenderingAttachmentInfo ca = { VK_STRUCTURE_TYPE_RENDERING_ATTACHMENT_INFO };
    ca.imageView = r->color.v, ca.imageLayout = VK_IMAGE_LAYOUT_GENERAL;
    ca.loadOp = VK_ATTACHMENT_LOAD_OP_LOAD, ca.storeOp = VK_ATTACHMENT_STORE_OP_STORE;
    VkRenderingAttachmentInfo da = { VK_STRUCTURE_TYPE_RENDERING_ATTACHMENT_INFO };
    if (zr) {
        da.imageView = zr->depth.v, da.imageLayout = VK_IMAGE_LAYOUT_DEPTH_ATTACHMENT_OPTIMAL;
        da.loadOp = zr->depth_new ? VK_ATTACHMENT_LOAD_OP_CLEAR : VK_ATTACHMENT_LOAD_OP_LOAD;
        da.storeOp = VK_ATTACHMENT_STORE_OP_STORE;
        da.clearValue.depthStencil.depth = 1.0f;
        zr->depth_new = 0;
    }
    VkRenderingInfo ri = { VK_STRUCTURE_TYPE_RENDERING_INFO };
    ri.renderArea.extent.width = (uint32_t)t->w, ri.renderArea.extent.height = (uint32_t)t->h;
    ri.layerCount = 1, ri.colorAttachmentCount = 1, ri.pColorAttachments = &ca;
    ri.pDepthAttachment = zr ? &da : NULL;
    vkCmdBeginRendering_(c, &ri);
    g_rendering = 1;
    r->epoch++;
    VkViewport vp = { 0, 0, (float)t->w, (float)t->h, 0, 1 };
    vkCmdSetViewport(c, 0, 1, &vp);
    float size[4] = { (float)t->w, (float)t->h, 0, 0 };
    vkCmdPushConstants(c, g_gfx_pl, VK_SHADER_STAGE_VERTEX_BIT, 0, sizeof size, size);
    g_ts = t, g_zs = z;
    add_dirty(r);
}
static int scissor(int l, int t, int r, int b) {
    if (l < 0) l = 0;
    if (t < 0) t = 0;
    if (r <= l || b <= t) return 0;
    VkRect2D sc = { { l, t }, { (uint32_t)(r - l), (uint32_t)(b - t) } };
    vkCmdSetScissor(g_sub[g_cur].cb, 0, 1, &sc);
    return 1;
}

/* ---- pipelines ---- */
static VkBlendFactor factor(int f) {
    switch (f) {
    case 1: return VK_BLEND_FACTOR_ZERO;
    case 3: return VK_BLEND_FACTOR_SRC_COLOR;
    case 4: return VK_BLEND_FACTOR_ONE_MINUS_SRC_COLOR;
    case 5: return VK_BLEND_FACTOR_SRC_ALPHA;
    case 6: return VK_BLEND_FACTOR_ONE_MINUS_SRC_ALPHA;
    case 7: return VK_BLEND_FACTOR_DST_ALPHA;
    case 8: return VK_BLEND_FACTOR_ONE_MINUS_DST_ALPHA;
    case 9: return VK_BLEND_FACTOR_DST_COLOR;
    case 10: return VK_BLEND_FACTOR_ONE_MINUS_DST_COLOR;
    case 11: return VK_BLEND_FACTOR_SRC_ALPHA_SATURATE;
    default: return VK_BLEND_FACTOR_ONE;
    }
}
/* A pipeline's key: which fragment shader (0 the draw's, 1 clear, 2 blit),
 * the primitive, the attachments, the colour writes, blending and depth. */
#define PKEY(fs, prim, depth, alpha, write, blend, src, dst, zon, zw, zf) \
    ((uint32_t)(fs) | (uint32_t)(prim) << 2 | (uint32_t)(depth) << 4 | (uint32_t)(alpha) << 5 | (uint32_t)(write) << 6 | \
     (uint32_t)(blend) << 7 | (uint32_t)(src) << 8 | (uint32_t)(dst) << 12 | (uint32_t)(zon) << 16 | (uint32_t)(zw) << 17 | \
     (uint32_t)(zf) << 18 | 1u << 31)
#define NPIPES 1024
static struct { uint32_t key; VkPipeline p; } g_pipes[NPIPES];
static VkPipeline make_pipe(uint32_t key) {
    int fs = key & 3, prim = key >> 2 & 3, depth = key >> 4 & 1, alpha = key >> 5 & 1, write = key >> 6 & 1;
    int blend = key >> 7 & 1, src = key >> 8 & 15, dst = key >> 12 & 15, zon = key >> 16 & 1, zw = key >> 17 & 1;
    int zf = key >> 18 & 15;
    VkPipelineShaderStageCreateInfo st[2] = { { VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO },
                                              { VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO } };
    st[0].stage = VK_SHADER_STAGE_VERTEX_BIT, st[0].module = g_vs, st[0].pName = "main";
    st[1].stage = VK_SHADER_STAGE_FRAGMENT_BIT, st[1].module = fs == 1 ? g_fs_clear : fs == 2 ? g_fs_blit : g_fs;
    st[1].pName = "main";
    VkVertexInputBindingDescription vb = { 0, sizeof(gv_t), VK_VERTEX_INPUT_RATE_VERTEX };
    VkVertexInputAttributeDescription va[4] = {
        { 0, 0, VK_FORMAT_R32G32B32A32_SFLOAT, 0 }, { 1, 0, VK_FORMAT_R32G32B32A32_SFLOAT, 16 },
        { 2, 0, VK_FORMAT_R32G32B32A32_SFLOAT, 32 }, { 3, 0, VK_FORMAT_R32G32_SFLOAT, 48 } };
    VkPipelineVertexInputStateCreateInfo vi = { VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO };
    vi.vertexBindingDescriptionCount = 1, vi.pVertexBindingDescriptions = &vb;
    vi.vertexAttributeDescriptionCount = 4, vi.pVertexAttributeDescriptions = va;
    VkPipelineInputAssemblyStateCreateInfo ia = { VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO };
    ia.topology = prim == 1 ? VK_PRIMITIVE_TOPOLOGY_LINE_LIST : prim == 2 ? VK_PRIMITIVE_TOPOLOGY_POINT_LIST
                                                                          : VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST;
    VkPipelineViewportStateCreateInfo vp = { VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO };
    vp.viewportCount = 1, vp.scissorCount = 1;
    VkPipelineRasterizationStateCreateInfo rs = { VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO };
    rs.depthClampEnable = g_depth_clamp, rs.polygonMode = VK_POLYGON_MODE_FILL, rs.cullMode = VK_CULL_MODE_NONE;
    rs.frontFace = VK_FRONT_FACE_COUNTER_CLOCKWISE, rs.lineWidth = 1.0f;
    VkPipelineMultisampleStateCreateInfo ms = { VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO };
    ms.rasterizationSamples = VK_SAMPLE_COUNT_1_BIT;
    static const VkCompareOp cmp[9] = { VK_COMPARE_OP_ALWAYS, VK_COMPARE_OP_NEVER, VK_COMPARE_OP_LESS, VK_COMPARE_OP_EQUAL,
        VK_COMPARE_OP_LESS_OR_EQUAL, VK_COMPARE_OP_GREATER, VK_COMPARE_OP_NOT_EQUAL, VK_COMPARE_OP_GREATER_OR_EQUAL,
        VK_COMPARE_OP_ALWAYS };
    VkPipelineDepthStencilStateCreateInfo ds = { VK_STRUCTURE_TYPE_PIPELINE_DEPTH_STENCIL_STATE_CREATE_INFO };
    ds.depthTestEnable = depth && zon, ds.depthWriteEnable = depth && zon && zw;
    ds.depthCompareOp = cmp[zf <= 8 ? zf : 8];
    VkPipelineColorBlendAttachmentState ba;
    memset(&ba, 0, sizeof ba);
    ba.colorWriteMask = !write ? 0 : VK_COLOR_COMPONENT_R_BIT | VK_COLOR_COMPONENT_G_BIT | VK_COLOR_COMPONENT_B_BIT |
                                     (alpha ? VK_COLOR_COMPONENT_A_BIT : 0);
    if (blend) {
        VkBlendFactor s = factor(src), d = factor(dst);
        if (src == 12) s = VK_BLEND_FACTOR_SRC_ALPHA, d = VK_BLEND_FACTOR_ONE_MINUS_SRC_ALPHA;    /* BOTHSRCALPHA */
        if (src == 13) s = VK_BLEND_FACTOR_ONE_MINUS_SRC_ALPHA, d = VK_BLEND_FACTOR_SRC_ALPHA;    /* BOTHINVSRCALPHA */
        ba.blendEnable = VK_TRUE;
        ba.srcColorBlendFactor = ba.srcAlphaBlendFactor = s;
        ba.dstColorBlendFactor = ba.dstAlphaBlendFactor = d;
        ba.colorBlendOp = ba.alphaBlendOp = VK_BLEND_OP_ADD;
    }
    VkPipelineColorBlendStateCreateInfo cbs = { VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO };
    cbs.attachmentCount = 1, cbs.pAttachments = &ba;
    VkDynamicState dyn[2] = { VK_DYNAMIC_STATE_VIEWPORT, VK_DYNAMIC_STATE_SCISSOR };
    VkPipelineDynamicStateCreateInfo dy = { VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO };
    dy.dynamicStateCount = 2, dy.pDynamicStates = dyn;
    VkFormat cf = COLOR_FMT;
    VkPipelineRenderingCreateInfo pr = { VK_STRUCTURE_TYPE_PIPELINE_RENDERING_CREATE_INFO };
    pr.colorAttachmentCount = 1, pr.pColorAttachmentFormats = &cf;
    pr.depthAttachmentFormat = depth ? DEPTH_FMT : VK_FORMAT_UNDEFINED;
    VkGraphicsPipelineCreateInfo gi = { VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO };
    gi.pNext = &pr;
    gi.stageCount = 2, gi.pStages = st, gi.pVertexInputState = &vi, gi.pInputAssemblyState = &ia;
    gi.pViewportState = &vp, gi.pRasterizationState = &rs, gi.pMultisampleState = &ms;
    gi.pDepthStencilState = &ds, gi.pColorBlendState = &cbs, gi.pDynamicState = &dy, gi.layout = g_gfx_pl;
    VkPipeline p = VK_NULL_HANDLE;
    VkResult r = vkCreateGraphicsPipelines(g_dev, VK_NULL_HANDLE, 1, &gi, NULL, &p);
    if (r != VK_SUCCESS) { vk_fail("a pipeline", r); return VK_NULL_HANDLE; }
    return p;
}
static VkPipeline pipe(uint32_t key) {
    uint32_t h = (key * 2654435761u) >> 22;                  /* 10 bits: NPIPES */
    for (int n = 0; n < NPIPES; n++, h = (h + 1) & (NPIPES - 1)) {
        if (g_pipes[h].key == key) return g_pipes[h].p;
        if (!g_pipes[h].key) {
            VkPipeline p = make_pipe(key);
            if (!p) return VK_NULL_HANDLE;
            g_pipes[h].key = key, g_pipes[h].p = p;
            return p;
        }
    }
    return VK_NULL_HANDLE;
}
static VkPipeline pipe_for(const rstate_t *st, int kind) {
    int depth = st->target->zbuf != NULL, alpha = has_alpha(st->target);
    int blend = st->blend != 0, src = blend ? st->srcblend & 15 : 0, dst = blend ? st->dstblend & 15 : 0;
    int zon = st->zenable && depth, zf = st->zfunc >= 1 && st->zfunc <= 8 ? st->zfunc : 8;
    return pipe(PKEY(0, kind, depth, alpha, 1, blend, src, dst, zon, st->zwrite != 0, zf));
}

/* ---- vertices ---- */
static gv_t *vspace(uint32_t n) {
    uint32_t need = n * (uint32_t)sizeof(gv_t);
    if (!g_vb.b || g_voff + need > VCHUNK) {
        flush_batch();
        cb();
        sub_t *s = &g_sub[g_cur];
        if (s->nchunks == 256) { commit(0); cb(); s = &g_sub[g_cur]; }
        buf_t b = g_npool ? g_pool[--g_npool] : buf_new(VCHUNK, VK_BUFFER_USAGE_VERTEX_BUFFER_BIT, 0);
        if (s->nchunks == s->capchunks) {
            s->capchunks = s->capchunks ? s->capchunks * 2 : 8;
            s->chunks = (buf_t *)realloc(s->chunks, sizeof *s->chunks * (size_t)s->capchunks);
        }
        s->chunks[s->nchunks++] = b;
        g_vb = b, g_voff = 0;
    }
    gv_t *p = (gv_t *)(g_vb.map + g_voff);
    g_voff += need;
    return p;
}
static uint32_t vindex(const gv_t *p) { return (uint32_t)(((const uint8_t *)p - g_vb.map) / sizeof(gv_t)); }
static void put(gv_t *o, const rvert_t *v, const rvert_t *col) {
    o->p[0] = v->x, o->p[1] = v->y, o->p[2] = v->z, o->p[3] = v->rhw;
    o->dif[0] = col->r, o->dif[1] = col->g, o->dif[2] = col->b, o->dif[3] = col->a;
    o->spec[0] = col->sr, o->spec[1] = col->sg, o->spec[2] = col->sb, o->spec[3] = v->fog;
    o->uv[0] = v->u, o->uv[1] = v->v;
}
static void bind_vb(VkCommandBuffer c) {
    VkDeviceSize off = 0;
    vkCmdBindVertexBuffers(c, 0, 1, &g_vb.b, &off);
}

static void flush_batch(void) {
    if (g_bkind < 0 || !g_bcount) { g_bkind = -1; return; }
    const rstate_t *st = &g_bst;
    int kind = g_bkind;
    uint32_t start = g_bstart, count = g_bcount;
    VkBuffer vbuf = g_vb.b;
    g_bkind = -1, g_bcount = 0;
    surf_t *t = st->target;
    VkPipeline p = pipe_for(st, kind);
    if (!p) return;
    grec_t *tr = st->tex ? texture(st->tex) : NULL;         /* its pixels up first: no copies in a pass */
    VkDescriptorSet set = gfx_set(tr ? tr->tex.v : g_blank.v, tr ? tr->key.v : g_blank_key.v);
    begin_pass(t, 0);
    VkCommandBuffer c = g_sub[g_cur].cb;
    if (!scissor(st->clip_l, st->clip_t, st->clip_r, st->clip_b)) return;
    vkCmdBindPipeline(c, VK_PIPELINE_BIND_POINT_GRAPHICS, p);
    gu_t u;
    memset(&u, 0, sizeof u);
    u.a[0] = tr != NULL, u.a[1] = st->colorkey, u.a[2] = st->bilinear, u.a[3] = st->wrap_u;
    u.b[0] = st->wrap_v, u.b[1] = st->colorop, u.b[2] = st->colorarg1, u.b[3] = st->colorarg2;
    u.c[0] = st->alphaop, u.c[1] = st->alphaarg1, u.c[2] = st->alphaarg2, u.c[3] = st->alphatest;
    u.d[0] = st->alphafunc, u.d[1] = st->specular, u.d[2] = st->fog;
    memcpy(u.tf, st->tfactor, sizeof u.tf);
    u.fogc[0] = st->fog_r, u.fogc[1] = st->fog_g, u.fogc[2] = st->fog_b, u.fogc[3] = st->alpharef;
    vkCmdPushConstants(c, g_gfx_pl, VK_SHADER_STAGE_FRAGMENT_BIT, 16, sizeof u, &u);
    vkCmdBindDescriptorSets(c, VK_PIPELINE_BIND_POINT_GRAPHICS, g_gfx_pl, 0, 1, &set, 0, NULL);
    VkDeviceSize off = 0;
    vkCmdBindVertexBuffers(c, 0, 1, &vbuf, &off);
    vkCmdDraw(c, count, 1, start, 0);
}
/* Room for n more vertices of a kind in the batch, which st may end. */
static gv_t *batch(const rstate_t *st, int kind, uint32_t n) {
    if (g_bkind != kind || memcmp(&g_bst, st, sizeof *st)) flush_batch();
    gv_t *p = vspace(n);                                 /* a new chunk ends the batch too */
    if (g_bkind < 0) {
        g_bst = *st, g_bkind = kind, g_bcount = 0;
        g_bstart = vindex(p);
    }
    g_bcount += n;
    return p;
}
/* A quad (two triangles) of the pass's own, outside any batch. */
static void quad(VkCommandBuffer c, int l, int t, int r, int b, float z, const float rgba[4]) {
    rvert_t v[4];
    memset(v, 0, sizeof v);
    float xs[4] = { (float)l, (float)r, (float)l, (float)r }, ys[4] = { (float)t, (float)t, (float)b, (float)b };
    for (int i = 0; i < 4; i++) {
        v[i].x = xs[i], v[i].y = ys[i], v[i].z = z, v[i].rhw = 1;
        if (rgba) v[i].r = rgba[0], v[i].g = rgba[1], v[i].b = rgba[2], v[i].a = rgba[3];
    }
    gv_t *o = vspace(6);
    uint32_t start = vindex(o);
    put(&o[0], &v[0], &v[0]), put(&o[1], &v[1], &v[1]), put(&o[2], &v[2], &v[2]);
    put(&o[3], &v[1], &v[1]), put(&o[4], &v[3], &v[3]), put(&o[5], &v[2], &v[2]);
    bind_vb(c);
    vkCmdDraw(c, 6, 1, start, 0);
}

/* ---- the renderer ---- */
static void v_triangle(const rstate_t *st, const rvert_t *a, const rvert_t *b, const rvert_t *c) {
    if (!st->target) return;
    float area = (b->x - a->x) * (c->y - a->y) - (b->y - a->y) * (c->x - a->x);
    if (area == 0 || !isfinite(area)) return;
    /* Screen y runs down: a clockwise triangle has a positive area here. */
    if (st->cull == 2 && area > 0) return;
    if (st->cull == 3 && area < 0) return;
    gv_t *o = batch(st, 0, 3);
    put(&o[0], a, a), put(&o[1], b, st->flat ? a : b), put(&o[2], c, st->flat ? a : c);
}
static void v_line(const rstate_t *st, const rvert_t *a, const rvert_t *b) {
    if (!st->target) return;
    if (a == b || (a->x == b->x && a->y == b->y)) {
        gv_t *o = batch(st, 2, 1);
        put(&o[0], a, a);
    } else {
        gv_t *o = batch(st, 1, 2);
        put(&o[0], a, a), put(&o[1], b, b);
    }
}
static void v_clear(surf_t *t, int l, int tp, int r, int b, uint32_t flags, uint32_t argb, float z) {
    if (!flags) return;
    flush_batch();
    int depth = t->zbuf != NULL, colour = (flags & 1) != 0, zclear = depth && (flags & 2);
    if (!zclear && !colour) return;
    VkPipeline p = pipe(PKEY(1, 0, depth, 1, colour, 0, 0, 0, zclear, zclear, 8));   /* all four: no alpha keeps 1 */
    if (!p) return;
    begin_pass(t, colour && l == 0 && tp == 0 && r == t->w && b == t->h);
    VkCommandBuffer c = g_sub[g_cur].cb;
    if (!scissor(l, tp, r, b)) return;
    vkCmdBindPipeline(c, VK_PIPELINE_BIND_POINT_GRAPHICS, p);
    float rgba[4] = { (float)((argb >> 16) & 0xFF) / 255.f, (float)((argb >> 8) & 0xFF) / 255.f,
                      (float)(argb & 0xFF) / 255.f, has_alpha(t) ? (float)(argb >> 24) / 255.f : 1.f };
    quad(c, l, tp, r, b, z < 0 ? 0 : z > 1 ? 1 : z, rgba);
}

/* ---- down to memory ----
 * A download packs the colour into the record's buffer; when it is done the
 * buffer goes to the pixels in memory, and the record is clean unless a pass
 * began on it since. */
static void start_download(grec_t *r) {
    gpk_t k;
    if (r->pending || !fmt_of(r->s, &k) || !r->color.i) return;
    ensure_xfer(r);
    dispatch(1, &r->color, &r->xfer, &k);
    r->pending = g_sub[g_cur].serial, r->pending_epoch = r->epoch;
}
static void finish_download(grec_t *r) {
    r->pending = 0;
    memcpy(r->s->px, r->xfer.map, (size_t)r->s->pitch * (size_t)r->s->h);
    if (r->pending_epoch == r->epoch) r->dirty = 0, forget_dirty(r);
    hle_dd_mark(r->s);
    r->gen = r->s->gen, r->stale = 0;
}
/* One surface's pixels into memory, now: DirectDraw is about to touch it. */
static void v_touch(surf_t *s) {
    if (g_bkind >= 0 && (g_bst.tex == s || g_bst.target == s)) flush_batch();
    grec_t *r = (grec_t *)s->gpu;
    if (!r || !r->dirty) return;
    flush_batch();
    if (r->pending && r->pending_epoch != r->epoch) {    /* an older picture: it can wait */
        wait_serial(r->pending);
        finish_download(r);
    }
    if (!r->pending) start_download(r);
    if (r->pending) {
        wait_serial(r->pending);
        finish_download(r);
    }
}
/* Every surface the GPU holds newer pixels of, into memory. */
static void v_sync(void) {
    flush_batch();
    end_pass();
    for (int i = 0; i < g_ndirty; i++)
        if (g_dirty[i]->pending && g_dirty[i]->pending_epoch != g_dirty[i]->epoch) {
            wait_serial(g_dirty[i]->pending);
            finish_download(g_dirty[i--]);               /* it may have left the list */
        }
    for (int i = 0; i < g_ndirty; i++) start_download(g_dirty[i]);
    commit(1);
    while (g_ndirty) {
        grec_t *r = g_dirty[0];
        if (r->pending) { wait_serial(r->pending); finish_download(r); }
        else r->dirty = 0, forget_dirty(r);              /* a format the shaders cannot carry: as it is */
    }
}

/* ---- what the presenter shows ----
 * Each flip starts the new front's picture down into one of three buffers,
 * and the presenter shows the one the flip before started, which is there by
 * then: every frame shown once, in step with the flips, and the game never
 * waits for the GPU. With none on its way (the first flip, or one after a
 * flip of pixels from memory), the flip waits for its own. The front stays
 * newer on the GPU than in memory until DirectDraw touches it. */
#define RING 3
static buf_t g_ring[RING];
static uint64_t g_ring_serial[RING];
static int g_show = -1, g_coming = -1;                            /* ring entries: shown, on its way */
static int g_show_new;                                            /* not yet seen by the presenter */
static uint32_t g_show_gen, g_flip_ms;
static surf_t *g_show_s;                                          /* the primary they are of */
static void show_none(void) { g_show = g_coming = -1, g_show_s = NULL; }

/* The frame to show for the primary, or NULL for its own pixels. Also
 * finishes downloads that are done, waiting for none. */
static const uint8_t *v_frame(surf_t *p) {
    static int busy;
    if (busy) return NULL;
    busy = 1;
    for (int i = 0; i < g_ndirty; i++) {
        grec_t *r = g_dirty[i];
        if (r->pending && done(r->pending)) {
            finish_download(r);
            i = -1;                                      /* the list may have changed */
        }
    }
    busy = 0;
    if (g_show < 0 || p != g_show_s) return NULL;
    if (g_show_new) g_show_new = 0, g_show_gen = p->gen;  /* the flip's own mark: from here, any other is a change */
    else if (p->gen != g_show_gen) { show_none(); return NULL; }   /* written since, in memory */
    /* The game has stopped flipping: its last frame, once it is down. */
    if (g_coming >= 0 && g_coming != g_show && hle_ticks_ms() - g_flip_ms > 100 && done(g_ring_serial[g_coming]))
        g_show = g_coming;
    return g_ring[g_show].map;
}
static void show_flip(grec_t *r) {
    gpk_t k;
    if (!fmt_of(r->s, &k)) { show_none(); return; }
    if (g_coming >= 0) {
        wait_serial(g_ring_serial[g_coming]);            /* started a frame ago: done by now */
        g_show = g_coming, g_show_s = r->s;
    }
    g_show_new = 1;                                      /* this flip's mark is not a change */
    int i = 0;
    while (i == g_show) i++;
    VkDeviceSize n = xfer_size(r->s);
    if (!g_ring[i].b || g_ring[i].size < n) {
        junk_buf(&g_ring[i]);
        g_ring[i] = buf_new(n, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT, 1);
    }
    dispatch(1, &r->color, &g_ring[i], &k);
    g_ring_serial[i] = g_sub[g_cur].serial;
    commit(0);
    g_flip_ms = hle_ticks_ms();
    if (g_show < 0 || g_show_s != r->s) {               /* nothing to show yet (memory's pixels are older): this one, now */
        wait_serial(g_ring_serial[i]);
        g_show = i, g_show_s = r->s, g_coming = -1;
        return;
    }
    g_coming = i;
}
static void v_end_scene(surf_t *t) {
    flush_batch();
    grec_t *r = t ? (grec_t *)t->gpu : NULL;
    if (t && t->primary && r && r->dirty) start_download(r);   /* drawn straight to the screen: show it */
    commit(0);
}

/* ---- DirectDraw's side ---- */
static void v_free(surf_t *s) {
    flush_batch();                                       /* a batch may draw with it */
    if (s == g_show_s) show_none();
    grec_t *r = (grec_t *)s->gpu;
    if (!r) return;
    forget_dirty(r);
    s->gpu = NULL;
    if (g_ts == s || g_zs == s) end_pass();
    commit(1);                                           /* nothing in flight may still use it */
    rec_free(r);
}
/* The pixels changed places: the records follow them, each still as far
 * ahead of or behind its pixels as it was. The new front's picture starts
 * down for the presenter. */
static void stats(void) {
    static int on = -1;
    static uint32_t since, flips;
    if (on < 0) on = getenv("HLE_VULKAN_STATS") != NULL;
    if (!on) return;
    uint32_t now = hle_ticks_ms();
    if (!since) since = now;
    flips++;
    if (now - since >= 5000) {
        fprintf(stderr, "[vulkan] %.1f flips a second\n", flips * 1000.0 / (now - since));
        since = now, flips = 0;
    }
}
static void v_flip(surf_t *front, surf_t *back) {
    grec_t *f = (grec_t *)front->gpu, *b = (grec_t *)back->gpu;
    stats();
    int f_ok = f && !f->stale && f->gen == front->gen, b_ok = b && !b->stale && b->gen == back->gen;
    flush_batch();
    end_pass();
    front->gpu = b, back->gpu = f;
    /* Newer on the GPU is never also newer in memory. Flip marks the front
     * (gen + 1) after this. */
    if (b) b->s = front, b->gen = front->gen + 1, b->stale = !b_ok && !b->dirty;
    if (f) f->s = back, f->gen = back->gen, f->stale = !f_ok && !f->dirty;
    if (b && b->dirty) show_flip(b);
    else show_none();
}
/* A blit on the GPU, when either end has newer pixels there: the
 * destination becomes the GPU's. Not for a surface onto itself, nor
 * between formats the shaders cannot carry. */
static int v_blit(surf_t *d, int dl, int dt, int dr, int db, surf_t *s, int sl, int st, int sr, int sb,
                  int keyed, uint32_t klo, uint32_t khi) {
    grec_t *rd = (grec_t *)d->gpu, *rs = (grec_t *)s->gpu;
    gpk_t kd, ks;
    if (s == d || !((rd && rd->dirty) || (rs && rs->dirty))) return 0;
    if (!fmt_of(d, &kd) || !fmt_of(s, &ks) || d->bpp != s->bpp) return 0;
    if (dr - dl <= 0 || db - dt <= 0 || sr - sl <= 0 || sb - st <= 0) return 1;
    flush_batch();
    if (!(rs && rs->dirty)) {                            /* the source's pixels up, if they are not there */
        end_pass();
        rs = target(s);
        if (rs->stale || rs->gen != s->gen) upload(rs);
    }
    /* An empty destination is no pass at all: nothing changes. */
    if (dl > d->w || dt > d->h || dr < 0 || db < 0) return 1;
    int l = dl < 0 ? 0 : dl, t = dt < 0 ? 0 : dt, r = dr > d->w ? d->w : dr, b = db > d->h ? d->h : db;
    if (l >= r || t >= b) return 1;
    VkPipeline p = pipe(PKEY(2, 0, d->zbuf != NULL, has_alpha(d), 1, 0, 0, 0, 0, 0, 8));
    if (!p) return 1;
    VkDescriptorSet set = gfx_set(rs->color.v, g_blank_key.v);
    begin_pass(d, 0);
    VkCommandBuffer c = g_sub[g_cur].cb;
    if (!scissor(l, t, r, b)) return 1;
    vkCmdBindPipeline(c, VK_PIPELINE_BIND_POINT_GRAPHICS, p);
    gbu_t u;
    memset(&u, 0, sizeof u);
    u.d[0] = dl, u.d[1] = dt, u.d[2] = dr - dl, u.d[3] = db - dt;
    u.s[0] = sl, u.s[1] = st, u.s[2] = sr - sl, u.s[3] = sb - st;
    u.key[0] = (uint32_t)keyed, u.key[1] = klo, u.key[2] = khi;
    memcpy(u.sh, ks.sh, sizeof u.sh), memcpy(u.bits, ks.bits, sizeof u.bits);
    vkCmdPushConstants(c, g_gfx_pl, VK_SHADER_STAGE_FRAGMENT_BIT, 16, sizeof u, &u);
    vkCmdBindDescriptorSets(c, VK_PIPELINE_BIND_POINT_GRAPHICS, g_gfx_pl, 0, 1, &set, 0, NULL);
    quad(c, l, t, r, b, 0, NULL);
    return 1;
}

static const d3d_gpu_t g_vulkan = { "vulkan", v_triangle, v_line, v_clear, v_end_scene, v_sync };

/* ---- start ---- */
static VkShaderModule shader(const uint32_t *code, size_t n) {
    VkShaderModuleCreateInfo si = { VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO };
    si.codeSize = n, si.pCode = code;
    VkShaderModule m = VK_NULL_HANDLE;
    VKC(vkCreateShaderModule(g_dev, &si, NULL, &m));
    return m;
}
static int has_layer(const char *name) {
    uint32_t n = 0;
    if (!vkEnumerateInstanceLayerProperties || vkEnumerateInstanceLayerProperties(&n, NULL) != VK_SUCCESS || !n) return 0;
    VkLayerProperties *lp = (VkLayerProperties *)calloc(n, sizeof *lp);
    vkEnumerateInstanceLayerProperties(&n, lp);
    int found = 0;
    for (uint32_t i = 0; i < n; i++) if (!strcmp(lp[i].layerName, name)) found = 1;
    free(lp);
    return found;
}
/* The GPU to draw on: one with Vulkan 1.3, dynamic rendering and demotion
 * (what glslang makes of discard for 1.3; every 1.3 device has both), and a
 * queue for drawing and computing; a real one before a software one. */
static int pick_device(void) {
    uint32_t n = 0;
    if (vkEnumeratePhysicalDevices(g_inst, &n, NULL) != VK_SUCCESS || !n) return -1;
    VkPhysicalDevice *pds = (VkPhysicalDevice *)calloc(n, sizeof *pds);
    vkEnumeratePhysicalDevices(g_inst, &n, pds);
    int best = -1, best_score = 0;
    uint32_t best_q = 0;
    int any = getenv("HLE_VULKAN_ANY") != NULL;
    for (uint32_t i = 0; i < n; i++) {
        VkPhysicalDeviceProperties pp;
        vkGetPhysicalDeviceProperties(pds[i], &pp);
        if (pp.apiVersion < VK_API_VERSION_1_3) continue;
        VkPhysicalDeviceVulkan13Features f13 = { VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_3_FEATURES };
        VkPhysicalDeviceFeatures2 f2 = { VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2 };
        f2.pNext = &f13;
        vkGetPhysicalDeviceFeatures2(pds[i], &f2);
        if (!f13.dynamicRendering || !f13.shaderDemoteToHelperInvocation) continue;   /* discard, in SPIR-V 1.6 */
        uint32_t nq = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(pds[i], &nq, NULL);
        VkQueueFamilyProperties *qp = (VkQueueFamilyProperties *)calloc(nq, sizeof *qp);
        vkGetPhysicalDeviceQueueFamilyProperties(pds[i], &nq, qp);
        int q = -1;
        for (uint32_t j = 0; j < nq && q < 0; j++)
            if ((qp[j].queueFlags & (VK_QUEUE_GRAPHICS_BIT | VK_QUEUE_COMPUTE_BIT)) == (VK_QUEUE_GRAPHICS_BIT | VK_QUEUE_COMPUTE_BIT))
                q = (int)j;
        free(qp);
        if (q < 0) continue;
        int score = pp.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU ? 4
                  : pp.deviceType == VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU ? 3
                  : pp.deviceType == VK_PHYSICAL_DEVICE_TYPE_VIRTUAL_GPU ? 2
                  : pp.deviceType == VK_PHYSICAL_DEVICE_TYPE_CPU ? (any ? 1 : 0) : 1;
        if (score > best_score) best = (int)i, best_score = score, best_q = (uint32_t)q;
    }
    if (best >= 0) g_pd = pds[best], g_qfam = best_q;
    free(pds);
    return best;
}
static int start(void) {
    g_lib = dlopen("libvulkan.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!g_lib) g_lib = dlopen("libvulkan.so", RTLD_NOW | RTLD_LOCAL);
    if (!g_lib) { fprintf(stderr, "[vulkan] no Vulkan loader (libvulkan.so.1): software rendering\n"); return -1; }
    gipa = (PFN_vkGetInstanceProcAddr)dlsym(g_lib, "vkGetInstanceProcAddr");
    if (!gipa) return -1;
#define LOAD_G(f) f = (PFN_##f)gipa(VK_NULL_HANDLE, #f);
    VK_GLOBAL(LOAD_G)
    uint32_t ver = VK_API_VERSION_1_0;
    if (vkEnumerateInstanceVersion) vkEnumerateInstanceVersion(&ver);
    if (!vkCreateInstance || ver < VK_API_VERSION_1_3) {
        fprintf(stderr, "[vulkan] Vulkan 1.3 needed (the loader has %u.%u): software rendering\n",
                VK_API_VERSION_MAJOR(ver), VK_API_VERSION_MINOR(ver));
        return -1;
    }
    VkApplicationInfo app = { VK_STRUCTURE_TYPE_APPLICATION_INFO };
    app.pApplicationName = "win32hle", app.pEngineName = "pcrecomp", app.apiVersion = VK_API_VERSION_1_3;
    VkInstanceCreateInfo ii = { VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO };
    ii.pApplicationInfo = &app;
    const char *layer = "VK_LAYER_KHRONOS_validation";
    if (getenv("HLE_VULKAN_DEBUG")) {
        if (has_layer(layer)) ii.enabledLayerCount = 1, ii.ppEnabledLayerNames = &layer;
        else fprintf(stderr, "[vulkan] HLE_VULKAN_DEBUG: no validation layer installed\n");
    }
    VkResult r = vkCreateInstance(&ii, NULL, &g_inst);
    if (r != VK_SUCCESS) { fprintf(stderr, "[vulkan] no instance (%d): software rendering\n", (int)r); return -1; }
#define LOAD_I(f) f = (PFN_##f)gipa(g_inst, #f);
    VK_INSTANCE(LOAD_I)
    if (pick_device() < 0) { fprintf(stderr, "[vulkan] no GPU with Vulkan 1.3: software rendering\n"); return -1; }
    VkPhysicalDeviceFeatures have;
    vkGetPhysicalDeviceFeatures(g_pd, &have);
    g_depth_clamp = have.depthClamp;
    float prio = 1;
    VkDeviceQueueCreateInfo qi = { VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO };
    qi.queueFamilyIndex = g_qfam, qi.queueCount = 1, qi.pQueuePriorities = &prio;
    VkPhysicalDeviceVulkan13Features f13 = { VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_3_FEATURES };
    f13.dynamicRendering = VK_TRUE, f13.shaderDemoteToHelperInvocation = VK_TRUE;
    VkPhysicalDeviceFeatures2 f2 = { VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2 };
    f2.pNext = &f13, f2.features.depthClamp = g_depth_clamp;
    VkDeviceCreateInfo di = { VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO };
    di.pNext = &f2, di.queueCreateInfoCount = 1, di.pQueueCreateInfos = &qi;
    r = vkCreateDevice(g_pd, &di, NULL, &g_dev);
    if (r != VK_SUCCESS) { fprintf(stderr, "[vulkan] no device (%d): software rendering\n", (int)r); return -1; }
#define LOAD_D(f) f = (PFN_##f)vkGetDeviceProcAddr(g_dev, #f); if (!f) { fprintf(stderr, "[vulkan] no %s\n", #f); return -1; }
    VK_DEVICE(LOAD_D)
    vkCmdBeginRendering_ = (PFN_vkCmdBeginRendering)vkGetDeviceProcAddr(g_dev, "vkCmdBeginRendering");
    vkCmdEndRendering_ = (PFN_vkCmdEndRendering)vkGetDeviceProcAddr(g_dev, "vkCmdEndRendering");
    if (!vkCmdBeginRendering_ || !vkCmdEndRendering_) { fprintf(stderr, "[vulkan] no dynamic rendering\n"); return -1; }
    vkGetDeviceQueue(g_dev, g_qfam, 0, &g_q);
    vkGetPhysicalDeviceMemoryProperties(g_pd, &g_mem);

    VkCommandPoolCreateInfo pi = { VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO };
    pi.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT, pi.queueFamilyIndex = g_qfam;
    VKC(vkCreateCommandPool(g_dev, &pi, NULL, &g_cpool));
    VkDescriptorPoolSize ps[3] = { { VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER, 8192 },
                                   { VK_DESCRIPTOR_TYPE_STORAGE_IMAGE, 512 }, { VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 512 } };
    for (int i = 0; i < NSUB; i++) {
        VkCommandBufferAllocateInfo ai = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO };
        ai.commandPool = g_cpool, ai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY, ai.commandBufferCount = 1;
        VKC(vkAllocateCommandBuffers(g_dev, &ai, &g_sub[i].cb));
        VkFenceCreateInfo fi = { VK_STRUCTURE_TYPE_FENCE_CREATE_INFO };
        VKC(vkCreateFence(g_dev, &fi, NULL, &g_sub[i].fence));
        VkDescriptorPoolCreateInfo dpi = { VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO };
        dpi.maxSets = 4096 + 512, dpi.poolSizeCount = 3, dpi.pPoolSizes = ps;
        VKC(vkCreateDescriptorPool(g_dev, &dpi, NULL, &g_sub[i].dp));
    }

    g_vs = shader(spv_d3d_vert, sizeof spv_d3d_vert), g_fs = shader(spv_d3d_frag, sizeof spv_d3d_frag);
    g_fs_clear = shader(spv_clear_frag, sizeof spv_clear_frag), g_fs_blit = shader(spv_blit_frag, sizeof spv_blit_frag);
    g_cs_pack = shader(spv_pack_comp, sizeof spv_pack_comp), g_cs_unpack = shader(spv_unpack_comp, sizeof spv_unpack_comp);

    VkDescriptorSetLayoutBinding gb[2] = {
        { 0, VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER, 1, VK_SHADER_STAGE_FRAGMENT_BIT, NULL },
        { 1, VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER, 1, VK_SHADER_STAGE_FRAGMENT_BIT, NULL } };
    VkDescriptorSetLayoutCreateInfo li = { VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO };
    li.bindingCount = 2, li.pBindings = gb;
    VKC(vkCreateDescriptorSetLayout(g_dev, &li, NULL, &g_gfx_dsl));
    VkDescriptorSetLayoutBinding cbd[2] = {
        { 0, VK_DESCRIPTOR_TYPE_STORAGE_IMAGE, 1, VK_SHADER_STAGE_COMPUTE_BIT, NULL },
        { 1, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1, VK_SHADER_STAGE_COMPUTE_BIT, NULL } };
    li.pBindings = cbd;
    VKC(vkCreateDescriptorSetLayout(g_dev, &li, NULL, &g_cmp_dsl));
    VkPushConstantRange pr[2] = { { VK_SHADER_STAGE_VERTEX_BIT, 0, 16 }, { VK_SHADER_STAGE_FRAGMENT_BIT, 16, sizeof(gu_t) } };
    VkPipelineLayoutCreateInfo pli = { VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO };
    pli.setLayoutCount = 1, pli.pSetLayouts = &g_gfx_dsl, pli.pushConstantRangeCount = 2, pli.pPushConstantRanges = pr;
    VKC(vkCreatePipelineLayout(g_dev, &pli, NULL, &g_gfx_pl));
    VkPushConstantRange cpr = { VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(gpk_t) };
    pli.pSetLayouts = &g_cmp_dsl, pli.pushConstantRangeCount = 1, pli.pPushConstantRanges = &cpr;
    VKC(vkCreatePipelineLayout(g_dev, &pli, NULL, &g_cmp_pl));
    VkComputePipelineCreateInfo ci = { VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO };
    ci.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    ci.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT, ci.stage.pName = "main", ci.layout = g_cmp_pl;
    ci.stage.module = g_cs_pack;
    VKC(vkCreateComputePipelines(g_dev, VK_NULL_HANDLE, 1, &ci, NULL, &g_pack));
    ci.stage.module = g_cs_unpack;
    VKC(vkCreateComputePipelines(g_dev, VK_NULL_HANDLE, 1, &ci, NULL, &g_unpack));
    VkSamplerCreateInfo smi = { VK_STRUCTURE_TYPE_SAMPLER_CREATE_INFO };
    smi.magFilter = smi.minFilter = VK_FILTER_NEAREST;
    smi.addressModeU = smi.addressModeV = smi.addressModeW = VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE;
    VKC(vkCreateSampler(g_dev, &smi, NULL, &g_sampler));

    g_blank = img_new(VK_FORMAT_B8G8R8A8_UNORM, 1, 1, VK_IMAGE_USAGE_SAMPLED_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT,
                      VK_IMAGE_ASPECT_COLOR_BIT);
    g_blank_key = img_new(VK_FORMAT_R8_UINT, 1, 1, VK_IMAGE_USAGE_SAMPLED_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT,
                          VK_IMAGE_ASPECT_COLOR_BIT);
    layout(&g_blank, VK_IMAGE_ASPECT_COLOR_BIT, VK_IMAGE_LAYOUT_GENERAL);
    layout(&g_blank_key, VK_IMAGE_ASPECT_COLOR_BIT, VK_IMAGE_LAYOUT_GENERAL);
    uint32_t white = 0xFFFFFFFFu;
    uint8_t zero = 0;
    copy_in(&g_blank, &white, 4, VK_IMAGE_ASPECT_COLOR_BIT);
    copy_in(&g_blank_key, &zero, 1, VK_IMAGE_ASPECT_COLOR_BIT);
    commit(1);
    if (g_failed) { fprintf(stderr, "[vulkan] could not start: software rendering\n"); return -1; }

    VkPhysicalDeviceProperties pp;
    vkGetPhysicalDeviceProperties(g_pd, &pp);
    fprintf(stderr, "[vulkan] drawing on %s (Vulkan %u.%u)\n", pp.deviceName,
            VK_API_VERSION_MAJOR(pp.apiVersion), VK_API_VERSION_MINOR(pp.apiVersion));
    return 0;
}

int hle_d3d_vulkan_enable(void) {
    if (start() != 0) return -1;
    hle_dd_free_hook = v_free;
    hle_dd_flip_hook = v_flip;
    hle_dd_sync_hook = v_touch;
    hle_dd_blit_hook = v_blit;
    hle_dd_frame_hook = v_frame;
    hle_d3d_gpu = &g_vulkan;
    return 0;
}

#endif /* HLE_HAVE_VULKAN */

/*
 * sdl2lite: the software SDL2 slice behind src/sdl2lite/SDL.h.
 * Everything renders into one 0x00RRGGBB framebuffer the backend shows.
 * Textures are kept as native ARGB8888; surfaces as 8-bit indexed or 32-bit.
 */
#include "SDL.h"

size_t SDL_strlcpy(char *dst, const char *src, size_t maxlen) {
    size_t n = strlen(src);
    if (maxlen) { size_t c = n < maxlen - 1 ? n : maxlen - 1; memcpy(dst, src, c); dst[c] = 0; }
    return n;
}

int SDL_Init(Uint32 flags) { (void)flags; return 0; }
const char *SDL_GetError(void) { return "sdl2lite"; }
Uint32 SDL_GetTicks(void) { return lite_ticks(); }
void SDL_Delay(Uint32 ms) { lite_sleep(ms); }
int SDL_ShowSimpleMessageBox(Uint32 flags, const char *title, const char *msg, SDL_Window *w) {
    (void)flags; (void)w;
    printf("[%s] %s\n", title, msg);
    return 0;
}

/* ---- pixel formats ---- */

static int ctz(Uint32 m) { int s = 0; if (!m) return 0; while (!(m & 1)) { m >>= 1; s++; } return s; }

static SDL_PixelFormat *alloc_format(int bpp, Uint32 R, Uint32 G, Uint32 B, Uint32 A) {
    SDL_PixelFormat *f = calloc(1, sizeof(*f));
    f->BitsPerPixel = (Uint8)bpp;
    f->BytesPerPixel = (Uint8)(bpp / 8);
    if (bpp == 8) {
        f->format = SDL_PIXELFORMAT_INDEX8;
        f->palette = calloc(1, sizeof(SDL_Palette));
        f->palette->ncolors = 256;
        f->palette->colors = calloc(256, sizeof(SDL_Color));
        return f;
    }
    f->Rmask = R; f->Gmask = G; f->Bmask = B; f->Amask = A;
    f->Rshift = ctz(R); f->Gshift = ctz(G); f->Bshift = ctz(B); f->Ashift = ctz(A);
    return f;
}

Uint32 SDL_MapRGBA(const SDL_PixelFormat *f, Uint8 r, Uint8 g, Uint8 b, Uint8 a) {
    if (f->BitsPerPixel == 8) return 0;   /* ponytail: the game never maps into an indexed surface */
    return ((Uint32)r << f->Rshift) | ((Uint32)g << f->Gshift) | ((Uint32)b << f->Bshift) |
           (f->Amask ? (Uint32)a << f->Ashift : 0);
}
Uint32 SDL_MapRGB(const SDL_PixelFormat *f, Uint8 r, Uint8 g, Uint8 b) { return SDL_MapRGBA(f, r, g, b, 255); }

/* raw pixel at (x, y) */
static Uint32 get_raw(const SDL_Surface *s, int x, int y) {
    const Uint8 *row = (const Uint8 *)s->pixels + y * s->pitch;
    return s->format->BitsPerPixel == 8 ? row[x] : ((const Uint32 *)row)[x];
}

/* raw pixel to native ARGB8888 */
static Uint32 raw_to_argb(const SDL_PixelFormat *f, Uint32 p) {
    Uint32 r, g, b, a;
    if (f->BitsPerPixel == 8) {
        const SDL_Color *c = &f->palette->colors[p & 0xff];
        return 0xff000000u | (Uint32)c->r << 16 | (Uint32)c->g << 8 | c->b;
    }
    r = (p & f->Rmask) >> f->Rshift;
    g = (p & f->Gmask) >> f->Gshift;
    b = (p & f->Bmask) >> f->Bshift;
    a = f->Amask ? (p & f->Amask) >> f->Ashift : 255;
    return a << 24 | r << 16 | g << 8 | b;
}

static Uint32 blend_argb(Uint32 s, Uint32 d) {   /* src over dst, alpha out */
    Uint32 a = s >> 24, ia = 255 - a, da = d >> 24;
    Uint32 r = (((s >> 16) & 255) * a + ((d >> 16) & 255) * ia) / 255;
    Uint32 g = (((s >> 8) & 255) * a + ((d >> 8) & 255) * ia) / 255;
    Uint32 b = ((s & 255) * a + (d & 255) * ia) / 255;
    return (a + da * ia / 255) << 24 | r << 16 | g << 8 | b;
}

/* clip a w*h copy at (dx,dy) into W*H; adjusts source offset too */
static int clip(int *sx, int *sy, int *dx, int *dy, int *w, int *h, int W, int H) {
    if (*dx < 0) { *sx -= *dx; *w += *dx; *dx = 0; }
    if (*dy < 0) { *sy -= *dy; *h += *dy; *dy = 0; }
    if (*dx + *w > W) *w = W - *dx;
    if (*dy + *h > H) *h = H - *dy;
    return *w > 0 && *h > 0;
}

/* ---- surfaces ---- */

static SDL_Surface *new_surface(int w, int h, SDL_PixelFormat *f) {
    SDL_Surface *s = calloc(1, sizeof(*s));
    s->format = f;
    s->w = w; s->h = h;
    s->pitch = (w * f->BytesPerPixel + 3) & ~3;
    s->pixels = calloc((size_t)s->pitch * (h ? h : 1), 1);
    s->blend = f->Amask ? SDL_BLENDMODE_BLEND : SDL_BLENDMODE_NONE;   /* as SDL2 */
    return s;
}

SDL_Surface *SDL_CreateRGBSurface(Uint32 flags, int w, int h, int depth, Uint32 R, Uint32 G, Uint32 B, Uint32 A) {
    (void)flags;
    return new_surface(w, h, alloc_format(depth, R, G, B, A));
}

static void format_masks(Uint32 fmt, Uint32 *R, Uint32 *G, Uint32 *B, Uint32 *A) {
    switch (fmt) {
    case SDL_PIXELFORMAT_RGBA8888: *R = 0xff000000u; *G = 0xff0000; *B = 0xff00; *A = 0xff; break;
    case SDL_PIXELFORMAT_ABGR8888: *R = 0xff; *G = 0xff00; *B = 0xff0000; *A = 0xff000000u; break;
    default: /* ARGB8888 */        *R = 0xff0000; *G = 0xff00; *B = 0xff; *A = 0xff000000u; break;
    }
}

SDL_Surface *SDL_CreateRGBSurfaceWithFormat(Uint32 flags, int w, int h, int depth, Uint32 format) {
    Uint32 R, G, B, A;
    (void)flags; (void)depth;
    format_masks(format, &R, &G, &B, &A);
    return new_surface(w, h, alloc_format(32, R, G, B, A));
}

/* a surface over someone else's pixels (flags = 1: not ours to free) */
SDL_Surface *SDL_CreateRGBSurfaceWithFormatFrom(void *pixels, int w, int h, int depth, int pitch, Uint32 format) {
    SDL_Surface *s = SDL_CreateRGBSurfaceWithFormat(0, 0, 0, depth, format);
    free(s->pixels);
    s->pixels = pixels; s->w = w; s->h = h; s->pitch = pitch; s->flags = 1;
    return s;
}

void SDL_FreeSurface(SDL_Surface *s) {
    if (!s) return;
    if (s->format->palette) { free(s->format->palette->colors); free(s->format->palette); }
    free(s->format);
    if (!s->flags) free(s->pixels);
    free(s);
}

int SDL_FillRect(SDL_Surface *s, const SDL_Rect *r, Uint32 color) {
    int x0 = 0, y0 = 0, w = s->w, h = s->h, sx = 0, sy = 0, x, y;
    if (r) { x0 = r->x; y0 = r->y; w = r->w; h = r->h; }
    if (!clip(&sx, &sy, &x0, &y0, &w, &h, s->w, s->h)) return 0;
    for (y = y0; y < y0 + h; y++) {
        Uint8 *row = (Uint8 *)s->pixels + y * s->pitch;
        if (s->format->BitsPerPixel == 8) memset(row + x0, (int)color, (size_t)w);
        else for (x = x0; x < x0 + w; x++) ((Uint32 *)row)[x] = color;
    }
    return 0;
}

int SDL_SetColorKey(SDL_Surface *s, int flag, Uint32 key) { s->has_key = flag; s->key = key; return 0; }
int SDL_SetSurfaceBlendMode(SDL_Surface *s, SDL_BlendMode mode) { s->blend = mode; return 0; }

/* Converting blit, 1:1. Color key skips; BLEND mixes by source alpha. */
int SDL_BlitSurface(SDL_Surface *src, const SDL_Rect *srcrect, SDL_Surface *dst, SDL_Rect *dstrect) {
    int sx = 0, sy = 0, w = src->w, h = src->h, dx = 0, dy = 0, x, y;
    const SDL_PixelFormat *df = dst->format;
    if (srcrect) { sx = srcrect->x; sy = srcrect->y; w = srcrect->w; h = srcrect->h; }
    if (dstrect) { dx = dstrect->x; dy = dstrect->y; }
    if (!clip(&sx, &sy, &dx, &dy, &w, &h, dst->w, dst->h)) return 0;
    for (y = 0; y < h; y++) {
        Uint32 *drow = (Uint32 *)((Uint8 *)dst->pixels + (dy + y) * dst->pitch) + dx;
        for (x = 0; x < w; x++) {
            Uint32 raw = get_raw(src, sx + x, sy + y), c;
            if (src->has_key && raw == src->key) continue;
            c = raw_to_argb(src->format, raw);
            if (src->blend == SDL_BLENDMODE_BLEND && (c >> 24) != 255) {
                if (!(c >> 24)) continue;
                c = blend_argb(c, raw_to_argb(df, drow[x]));
            }
            drow[x] = SDL_MapRGBA(df, (Uint8)(c >> 16), (Uint8)(c >> 8), (Uint8)c, (Uint8)(c >> 24));
        }
    }
    if (dstrect) { dstrect->x = dx; dstrect->y = dy; dstrect->w = w; dstrect->h = h; }
    return 0;
}

/* ---- RWops and BMP ---- */

SDL_RWops *SDL_RWFromConstMem(const void *mem, int size) {
    SDL_RWops *rw = calloc(1, sizeof(*rw));
    rw->base = mem; rw->size = (size_t)size;
    return rw;
}
int SDL_RWclose(SDL_RWops *rw) { free(rw); return 0; }

static Uint32 le32(const Uint8 *p) { return p[0] | p[1] << 8 | p[2] << 16 | (Uint32)p[3] << 24; }
static Uint16 le16(const Uint8 *p) { return (Uint16)(p[0] | p[1] << 8); }

/* Uncompressed 1/4/8-bit BMPs, to an 8-bit indexed surface (as SDL2 does) */
SDL_Surface *SDL_LoadBMP_RW(SDL_RWops *rw, int freesrc) {
    const Uint8 *d = rw->base;
    SDL_Surface *s = NULL;
    if (rw->size > 54 && d[0] == 'B' && d[1] == 'M') {
        Uint32 off = le32(d + 10), hs = le32(d + 14), ncol = le32(d + 46);
        int w = (int)le32(d + 18), h = (int)le32(d + 22), bpp = le16(d + 28);
        int up = h > 0, stride, x, y, i;
        if (!up) h = -h;
        if ((bpp == 1 || bpp == 4 || bpp == 8) && le32(d + 30) == 0) {
            stride = ((w * bpp + 31) / 32) * 4;
            if (!ncol) ncol = 1u << bpp;
            s = new_surface(w, h, alloc_format(8, 0, 0, 0, 0));
            for (i = 0; i < (int)ncol && i < 256; i++) {
                const Uint8 *c = d + 14 + hs + i * 4;   /* B G R x */
                s->format->palette->colors[i] = (SDL_Color){ c[2], c[1], c[0], 255 };
            }
            for (y = 0; y < h; y++) {
                const Uint8 *src = d + off + (size_t)(up ? h - 1 - y : y) * stride;
                Uint8 *dst = (Uint8 *)s->pixels + y * s->pitch;
                for (x = 0; x < w; x++) {
                    int bit = x * bpp;
                    dst[x] = (Uint8)((src[bit >> 3] >> (8 - bpp - (bit & 7))) & ((1 << bpp) - 1));
                }
            }
        }
    }
    if (freesrc) SDL_RWclose(rw);
    return s;
}

/* ---- window, renderer, textures ---- */

struct SDL_Texture {
    int w, h;
    Uint32 *px;              /* native ARGB8888 */
    SDL_BlendMode blend;
    Uint8 mr, mg, mb;
    SDL_Surface *lock;       /* streaming textures: a copy in their own format */
};
struct SDL_Window { int w, h; };
struct SDL_Renderer {
    Uint32 *fb; int w, h;         /* what the game draws into: the logical size */
    Uint32 *out; int ow, oh;      /* the screen, when a logical size scales up to it */
    Uint8 r, g, b, a; SDL_BlendMode blend;
};

static SDL_Window the_window;
static SDL_Renderer the_renderer;

SDL_Window *SDL_CreateWindow(const char *title, int x, int y, int w, int h, Uint32 flags) {
    (void)title; (void)x; (void)y; (void)flags;
    if (the_window.w) return NULL;   /* one screen: no second window (the asset viewer) */
    the_window.w = w; the_window.h = h;
    if (lite_video_init(&the_window.w, &the_window.h) != 0) return NULL;
    {   /* as a real window does: it shows with focus, which starts the game timer */
        SDL_Event e;
        memset(&e, 0, sizeof e);
        e.type = SDL_WINDOWEVENT;
        e.window.windowID = 1;
        e.window.event = SDL_WINDOWEVENT_FOCUS_GAINED;
        lite_push_event(&e);
    }
    return &the_window;
}
void SDL_DestroyWindow(SDL_Window *w) { (void)w; }
Uint32 SDL_GetWindowID(SDL_Window *w) { return w ? 1 : 0; }
void SDL_SetWindowTitle(SDL_Window *w, const char *t) { (void)w; (void)t; }
void SDL_MinimizeWindow(SDL_Window *w) { (void)w; }

SDL_Renderer *SDL_CreateRenderer(SDL_Window *w, int index, Uint32 flags) {
    (void)index; (void)flags;
    if (!w) return NULL;
    the_renderer.w = the_renderer.ow = w->w;
    the_renderer.h = the_renderer.oh = w->h;
    the_renderer.fb = calloc((size_t)w->w * w->h, 4);
    the_renderer.a = 255;
    return &the_renderer;
}
void SDL_DestroyRenderer(SDL_Renderer *r) { (void)r; }
int SDL_GetRendererInfo(SDL_Renderer *r, SDL_RendererInfo *info) { (void)r; info->name = "sdl2lite"; info->flags = 0; return 0; }
int SDL_GetRendererOutputSize(SDL_Renderer *r, int *w, int *h) { *w = r->ow; *h = r->oh; return 0; }
int SDL_RenderSetLogicalSize(SDL_Renderer *r, int w, int h) {
    if (w <= 0 || h <= 0 || w > r->ow || h > r->oh) return -1;
    free(r->fb);
    r->w = w; r->h = h;
    r->fb = calloc((size_t)w * h, 4);
    if (!r->out) r->out = calloc((size_t)r->ow * r->oh, 4);
    return 0;
}
int SDL_SetRenderDrawColor(SDL_Renderer *r, Uint8 red, Uint8 g, Uint8 b, Uint8 a) { r->r = red; r->g = g; r->b = b; r->a = a; return 0; }
int SDL_SetRenderDrawBlendMode(SDL_Renderer *r, SDL_BlendMode m) { r->blend = m; return 0; }

static void fill(SDL_Renderer *r, int x0, int y0, int w, int h) {
    int sx = 0, sy = 0, x, y;
    Uint32 c = 0xff000000u | (Uint32)r->r << 16 | (Uint32)r->g << 8 | r->b;
    int mix = r->blend == SDL_BLENDMODE_BLEND && r->a != 255;
    if (mix) c = (c & 0xffffff) | (Uint32)r->a << 24;
    if (!clip(&sx, &sy, &x0, &y0, &w, &h, r->w, r->h)) return;
    for (y = y0; y < y0 + h; y++) {
        Uint32 *row = r->fb + y * r->w;
        for (x = x0; x < x0 + w; x++) row[x] = mix ? blend_argb(c, row[x]) & 0xffffff : c & 0xffffff;
    }
}
int SDL_RenderClear(SDL_Renderer *r) {
    SDL_BlendMode b = r->blend; Uint8 a = r->a;
    r->blend = SDL_BLENDMODE_NONE; r->a = 255;
    fill(r, 0, 0, r->w, r->h);
    r->blend = b; r->a = a;
    return 0;
}
int SDL_RenderFillRect(SDL_Renderer *r, const SDL_Rect *rc) {
    if (rc) fill(r, rc->x, rc->y, rc->w, rc->h); else fill(r, 0, 0, r->w, r->h);
    return 0;
}
int SDL_RenderDrawRect(SDL_Renderer *r, const SDL_Rect *rc) {
    fill(r, rc->x, rc->y, rc->w, 1);
    fill(r, rc->x, rc->y + rc->h - 1, rc->w, 1);
    fill(r, rc->x, rc->y, 1, rc->h);
    fill(r, rc->x + rc->w - 1, rc->y, 1, rc->h);
    return 0;
}
void SDL_RenderPresent(SDL_Renderer *r) {
    int x, y;
    if (r->w == r->ow && r->h == r->oh) { lite_video_present(r->fb, r->w, r->h); return; }
    for (y = 0; y < r->oh; y++) {   /* nearest-neighbour stretch of the logical size */
        const Uint32 *src = r->fb + (y * r->h / r->oh) * r->w;
        for (x = 0; x < r->ow; x++) r->out[y * r->ow + x] = src[x * r->w / r->ow];
    }
    lite_video_present(r->out, r->ow, r->oh);
}

SDL_Texture *SDL_CreateTexture(SDL_Renderer *r, Uint32 format, int access, int w, int h) {
    SDL_Texture *t = calloc(1, sizeof(*t));
    (void)r;
    t->w = w; t->h = h;
    t->px = calloc((size_t)w * h, 4);
    t->mr = t->mg = t->mb = 255;
    if (access == SDL_TEXTUREACCESS_STREAMING) t->lock = SDL_CreateRGBSurfaceWithFormat(0, w, h, 32, format);
    return t;
}

static void surface_to_texture(SDL_Surface *s, SDL_Texture *t) {
    int x, y;
    for (y = 0; y < s->h; y++)
        for (x = 0; x < s->w; x++) {
            Uint32 raw = get_raw(s, x, y);
            t->px[y * t->w + x] = s->has_key && raw == s->key ? 0 : raw_to_argb(s->format, raw);
        }
}

SDL_Texture *SDL_CreateTextureFromSurface(SDL_Renderer *r, SDL_Surface *s) {
    SDL_Texture *t = SDL_CreateTexture(r, SDL_PIXELFORMAT_ARGB8888, SDL_TEXTUREACCESS_STATIC, s->w, s->h);
    surface_to_texture(s, t);
    if (s->has_key || s->format->Amask) t->blend = SDL_BLENDMODE_BLEND;   /* as SDL2 */
    return t;
}

/* whole-texture updates of a streaming texture, in its own format */
int SDL_UpdateTexture(SDL_Texture *t, const SDL_Rect *rect, const void *pixels, int pitch) {
    int y;
    (void)rect;
    if (!t->lock) return -1;
    for (y = 0; y < t->h; y++)
        memcpy((Uint8 *)t->lock->pixels + y * t->lock->pitch, (const Uint8 *)pixels + y * pitch, (size_t)t->w * 4);
    surface_to_texture(t->lock, t);
    return 0;
}
int SDL_SetTextureColorMod(SDL_Texture *t, Uint8 r, Uint8 g, Uint8 b) { t->mr = r; t->mg = g; t->mb = b; return 0; }

/* nearest-neighbour scaled copy with color mod and blend */
int SDL_RenderCopy(SDL_Renderer *r, SDL_Texture *t, const SDL_Rect *src, const SDL_Rect *dst) {
    SDL_Rect s = { 0, 0, t->w, t->h }, d = { 0, 0, r->w, r->h };
    int x, y, mod = t->mr != 255 || t->mg != 255 || t->mb != 255;
    if (src) s = *src;
    if (dst) d = *dst;
    if (s.w <= 0 || s.h <= 0 || d.w <= 0 || d.h <= 0) return 0;
    for (y = d.y < 0 ? -d.y : 0; y < d.h && d.y + y < r->h; y++) {
        int ty = s.y + y * s.h / d.h;
        Uint32 *row = r->fb + (d.y + y) * r->w;
        if (ty < 0 || ty >= t->h) continue;
        for (x = d.x < 0 ? -d.x : 0; x < d.w && d.x + x < r->w; x++) {
            int tx = s.x + x * s.w / d.w;
            Uint32 c;
            if (tx < 0 || tx >= t->w) continue;
            c = t->px[ty * t->w + tx];
            if (mod)
                c = (c & 0xff000000u) | (((c >> 16) & 255) * t->mr / 255) << 16 |
                    (((c >> 8) & 255) * t->mg / 255) << 8 | ((c & 255) * t->mb / 255);
            if (t->blend == SDL_BLENDMODE_BLEND) {
                Uint32 a = c >> 24;
                if (!a) continue;
                if (a != 255) c = blend_argb(c, row[d.x + x]);
            }
            row[d.x + x] = c & 0xffffff;
        }
    }
    return 0;
}

/* ---- audio ---- */

static SDL_AudioSpec audio_spec;
static int audio_paused = 1;

SDL_AudioSpec *SDL_LoadWAV_RW(SDL_RWops *rw, int freesrc, SDL_AudioSpec *spec, Uint8 **buf, Uint32 *len) {
    const Uint8 *d = rw->base;
    size_t i = 12, n = rw->size;
    SDL_AudioSpec *ok = NULL;
    int have_fmt = 0;
    if (n >= 12 && !memcmp(d, "RIFF", 4) && !memcmp(d + 8, "WAVE", 4)) {
        while (i + 8 <= n) {
            Uint32 sz = le32(d + i + 4);
            if (!memcmp(d + i, "fmt ", 4) && le16(d + i + 8) == 1) {
                memset(spec, 0, sizeof(*spec));
                spec->channels = (Uint8)le16(d + i + 10);
                spec->freq = (int)le32(d + i + 12);
                spec->format = le16(d + i + 22) == 8 ? AUDIO_U8 : AUDIO_S16LSB;
                have_fmt = 1;
            } else if (!memcmp(d + i, "data", 4) && have_fmt) {
                if (sz > n - i - 8) sz = (Uint32)(n - i - 8);
                *buf = malloc(sz ? sz : 1);
                memcpy(*buf, d + i + 8, sz);
                *len = sz;
                ok = spec;
                break;
            }
            i += 8 + sz + (sz & 1);
        }
    }
    if (freesrc) SDL_RWclose(rw);
    return ok;
}
void SDL_FreeWAV(Uint8 *buf) { free(buf); }

static int frame_bytes(SDL_AudioFormat f, int ch) { return (f & 0xff) / 8 * ch; }

int SDL_BuildAudioCVT(SDL_AudioCVT *cvt, SDL_AudioFormat sf, Uint8 sc, int sr, SDL_AudioFormat df, Uint8 dc, int dr) {
    int sb = frame_bytes(sf, sc), db = frame_bytes(df, dc);
    memset(cvt, 0, sizeof(*cvt));
    if (!sb || !db || sr <= 0 || dr <= 0 || (df & 0xff) != 16) return -1;
    cvt->src_format = sf; cvt->dst_format = df;
    cvt->src_channels = sc; cvt->dst_channels = dc;
    cvt->src_rate = sr; cvt->dst_rate = dr;
    cvt->len_mult = (db * ((dr + sr - 1) / sr) + sb - 1) / sb + 1;
    cvt->needed = 1;
    return 1;
}

static Sint16 read_sample(const Uint8 *p, SDL_AudioFormat f) {
    switch (f) {
    case AUDIO_U8: return (Sint16)((p[0] - 128) << 8);
    case AUDIO_S8: return (Sint16)((Sint8)p[0] << 8);
    case AUDIO_S16MSB: return (Sint16)(p[0] << 8 | p[1]);
    default: return (Sint16)(p[0] | p[1] << 8);
    }
}

/* to 16-bit at the destination rate (nearest sample) and channel count */
int SDL_ConvertAudio(SDL_AudioCVT *cvt) {
    int sb = frame_bytes(cvt->src_format, cvt->src_channels), ss = sb / cvt->src_channels;
    int in = cvt->len / sb, out = (int)((long long)in * cvt->dst_rate / cvt->src_rate), i, c;
    Sint16 *tmp = malloc((size_t)(out ? out : 1) * cvt->dst_channels * 2);
    for (i = 0; i < out; i++) {
        const Uint8 *f = cvt->buf + (size_t)((long long)i * cvt->src_rate / cvt->dst_rate) * sb;
        for (c = 0; c < cvt->dst_channels; c++) {
            int sc = c < cvt->src_channels ? c : cvt->src_channels - 1;
            tmp[i * cvt->dst_channels + c] = read_sample(f + sc * ss, cvt->src_format);
        }
    }
    cvt->len_cvt = out * cvt->dst_channels * 2;
    memcpy(cvt->buf, tmp, (size_t)cvt->len_cvt);   /* native 16-bit: AUDIO_S16SYS */
    free(tmp);
    return 0;
}

SDL_AudioDeviceID SDL_OpenAudioDevice(const char *dev, int iscapture, const SDL_AudioSpec *want, SDL_AudioSpec *have, int allowed) {
    (void)dev; (void)iscapture; (void)allowed;
    if (want->freq != 44100 || want->channels != 2 || want->format != AUDIO_S16SYS) return 0;
    audio_spec = *want;
    if (have) *have = *want;
    if (lite_audio_start() != 0) return 0;
    return 1;
}
void SDL_CloseAudioDevice(SDL_AudioDeviceID dev) { (void)dev; audio_paused = 1; }
void SDL_PauseAudioDevice(SDL_AudioDeviceID dev, int pause) { (void)dev; audio_paused = pause; }

void lite_audio_mix(Sint16 *out, int frames) {
    if (audio_paused || !audio_spec.callback) memset(out, 0, (size_t)frames * 4);
    else audio_spec.callback(audio_spec.userdata, (Uint8 *)out, frames * 4);
}

/* ---- events and the pad ---- */

#define QLEN 64
static SDL_Event queue[QLEN];
static int qhead, qtail;

void lite_push_event(const SDL_Event *e) {
    int n = (qtail + 1) % QLEN;
    if (n == qhead) return;   /* full: drop */
    queue[qtail] = *e;
    qtail = n;
}

int SDL_PollEvent(SDL_Event *e) {
    if (qhead == qtail) lite_poll();
    if (qhead == qtail) return 0;
    *e = queue[qhead];
    qhead = (qhead + 1) % QLEN;
    return 1;
}

void lite_pad(Uint32 buttons, Sint16 lx, Sint16 ly) {
    static Uint32 prev;
    static Sint16 px, py;
    SDL_Event e;
    int b;
    for (b = 0; b < SDL_CONTROLLER_BUTTON_MAX; b++) {
        Uint32 m = 1u << b;
        if ((buttons ^ prev) & m) {
            memset(&e, 0, sizeof(e));
            e.type = buttons & m ? SDL_CONTROLLERBUTTONDOWN : SDL_CONTROLLERBUTTONUP;
            e.cbutton.button = (Uint8)b;
            e.cbutton.state = (buttons & m) != 0;
            lite_push_event(&e);
        }
    }
    prev = buttons;
    if (lx != px || ly != py) {
        memset(&e, 0, sizeof(e));
        e.type = SDL_CONTROLLERAXISMOTION;
        if (lx != px) { e.caxis.axis = SDL_CONTROLLER_AXIS_LEFTX; e.caxis.value = lx; lite_push_event(&e); }
        if (ly != py) { e.caxis.axis = SDL_CONTROLLER_AXIS_LEFTY; e.caxis.value = ly; lite_push_event(&e); }
        px = lx; py = ly;
    }
}

int SDL_NumJoysticks(void) { return 1; }
SDL_bool SDL_IsGameController(int i) { return i == 0 ? SDL_TRUE : SDL_FALSE; }
SDL_GameController *SDL_GameControllerOpen(int i) { static int pad; (void)i; return (SDL_GameController *)&pad; }
void SDL_GameControllerClose(SDL_GameController *c) { (void)c; }
const char *SDL_GameControllerName(SDL_GameController *c) { (void)c; return "Console pad"; }

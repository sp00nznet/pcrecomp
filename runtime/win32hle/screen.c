/*
 * screen.c - the display and input for a DirectDraw game on win32hle: an SDL2
 * window showing the primary surface (ddraw.c), scaled to the window with its
 * aspect kept, and SDL's mouse and keyboard turned into the window messages
 * a game's windows get (user32.c's hle_input_*).
 *
 * It runs as user32's pump hook, on the thread that runs the game (SDL wants
 * its video calls on one thread, and the game's thread is the one that pumps
 * messages). A frame is shown when the primary has changed, at most 60 times
 * a second: from the pump, and as the game draws into the primary (ddraw.c's
 * hle_dd_primary_hook), since on Windows the primary is the screen. A game
 * that draws without pumping (a loading screen, a menu's transition) is seen
 * as it draws, as on Windows.
 *
 * Headless (hle_screen_open(..., headless)), there is no window: the pump
 * only paces, and input comes from a host's script.
 */
#define _GNU_SOURCE
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <SDL2/SDL.h>
#include <SDL2/SDL_ttf.h>
#include "win32hle.h"
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#endif

#define WM_MOUSEMOVE   0x0200u
#define WM_LBUTTONDOWN 0x0201u
#define WM_LBUTTONUP   0x0202u
#define WM_RBUTTONDOWN 0x0204u
#define WM_RBUTTONUP   0x0205u
#define WM_MBUTTONDOWN 0x0207u
#define WM_MBUTTONUP   0x0208u
#define WM_CLOSE       0x0010u

static SDL_Window *g_win;
static SDL_Renderer *g_ren;
static SDL_Texture *g_tex;
static int g_tex_w, g_tex_h, g_tex_fmt;
static unsigned g_shown_seq = ~0u;
static uint32_t g_last_present;
static int g_headless, g_fullscreen;
static SDL_Rect g_dst;                                   /* where the picture is in the window */
static pthread_t g_video_thread;                         /* SDL's video calls stay on the thread that opened it */
static SDL_Texture *g_pre, *g_small;                     /* sharp's integer prescale; the bars' blur */
static int g_pre_w, g_pre_h;

/* How the picture is scaled, as the Windows presenter offers (F12 cycles):
 * sharp-bilinear (an integer prescale, nearest, then the rest bilinear),
 * smooth (bilinear), crt (sharp with scanlines), nearest, integer (whole
 * multiples only). The bars beside a letterboxed picture are a dark blur of
 * it, or black. */
static const char *const k_modes[] = { "sharp", "smooth", "crt", "nearest", "integer" };
static int g_mode, g_bars = 1;
void (*hle_screen_settings_hook)(const char *scale, int bars, int fullscreen);   /* to remember them */
int hle_screen_scale(const char *name) {
    for (int i = 0; i < 5; i++) if (name && !strcmp(name, k_modes[i])) return g_mode = i, 1;
    return 0;
}
void hle_screen_bars(int blur) { g_bars = blur != 0; }
static void settings_changed(void) {
    g_shown_seq = ~0u;
    if (hle_screen_settings_hook) hle_screen_settings_hook(k_modes[g_mode], g_bars, g_fullscreen);
}
static void menu_draw(void);
static int g_menu_depth;                                 /* hle_screen_menu's levels open; 0: closed */
static void set_fullscreen(int on) {
    g_fullscreen = on, g_menu_depth = 0;
#ifdef __EMSCRIPTEN__
    (void)on;                                              /* the page does it, on the key itself (a gesture) */
#else
    if (g_win) SDL_SetWindowFullscreen(g_win, on ? SDL_WINDOW_FULLSCREEN_DESKTOP : 0);
#endif
    settings_changed();
}
void hle_screen_fullscreen(int on) { set_fullscreen(on != 0); }
const char *hle_screen_settings(int *bars, int *fullscreen) {
    if (bars) *bars = g_bars;
    if (fullscreen) *fullscreen = g_fullscreen;
    return k_modes[g_mode];
}
static uint32_t *g_conv;                                 /* 8-bit frames converted */
static size_t g_conv_n;
void (*hle_screen_frame_hook)(const uint8_t *px, int w, int h, int pitch, int bpp);   /* a recorder, a checksum */
/* A host's own picture at twice the size (an HD layer): fills out with 2w x
 * 2h XRGB from the 16-bit frame and returns 1, or returns 0 for the 1x. */
int (*hle_screen_compose_hook)(const uint8_t *px16, int pitch, int w, int h, uint32_t *out);
static uint32_t *g_hd;
static size_t g_hd_n;
/* The HD overlay (hle_screen_overlay_hook): a 2x ARGB layer blended over the
 * scaled 1x picture, so the CPU does not upscale the whole frame. */
int (*hle_screen_overlay_hook)(const uint8_t *px16, int pitch, int w, int h,
                               uint32_t *ov, int *dx, int *dy, int *dw, int *dh);
static uint32_t *g_ov;
static size_t g_ov_n;
static SDL_Texture *g_ov_tex;
static int g_ov_tw, g_ov_th;

static int vk_of(SDL_Scancode s) {
    if (s >= SDL_SCANCODE_A && s <= SDL_SCANCODE_Z) return 'A' + (s - SDL_SCANCODE_A);
    if (s >= SDL_SCANCODE_1 && s <= SDL_SCANCODE_9) return '1' + (s - SDL_SCANCODE_1);
    if (s >= SDL_SCANCODE_F1 && s <= SDL_SCANCODE_F12) return 0x70 + (s - SDL_SCANCODE_F1);
    if (s >= SDL_SCANCODE_KP_1 && s <= SDL_SCANCODE_KP_9) return 0x61 + (s - SDL_SCANCODE_KP_1);
    switch (s) {
    case SDL_SCANCODE_0: return '0';
    case SDL_SCANCODE_KP_0: return 0x60;
    case SDL_SCANCODE_RETURN: case SDL_SCANCODE_KP_ENTER: return 0x0D;
    case SDL_SCANCODE_ESCAPE: return 0x1B;
    case SDL_SCANCODE_BACKSPACE: return 0x08;
    case SDL_SCANCODE_TAB: return 0x09;
    case SDL_SCANCODE_SPACE: return 0x20;
    case SDL_SCANCODE_LSHIFT: case SDL_SCANCODE_RSHIFT: return 0x10;
    case SDL_SCANCODE_LCTRL: case SDL_SCANCODE_RCTRL: return 0x11;
    case SDL_SCANCODE_LALT: case SDL_SCANCODE_RALT: return 0x12;
    case SDL_SCANCODE_PAUSE: return 0x13;
    case SDL_SCANCODE_CAPSLOCK: return 0x14;
    case SDL_SCANCODE_PAGEUP: return 0x21;
    case SDL_SCANCODE_PAGEDOWN: return 0x22;
    case SDL_SCANCODE_END: return 0x23;
    case SDL_SCANCODE_HOME: return 0x24;
    case SDL_SCANCODE_LEFT: return 0x25;
    case SDL_SCANCODE_UP: return 0x26;
    case SDL_SCANCODE_RIGHT: return 0x27;
    case SDL_SCANCODE_DOWN: return 0x28;
    case SDL_SCANCODE_INSERT: return 0x2D;
    case SDL_SCANCODE_DELETE: return 0x2E;
    case SDL_SCANCODE_KP_MULTIPLY: return 0x6A;
    case SDL_SCANCODE_KP_PLUS: return 0x6B;
    case SDL_SCANCODE_KP_MINUS: return 0x6D;
    case SDL_SCANCODE_KP_PERIOD: return 0x6E;
    case SDL_SCANCODE_KP_DIVIDE: return 0x6F;
    case SDL_SCANCODE_SEMICOLON: return 0xBA;
    case SDL_SCANCODE_EQUALS: return 0xBB;
    case SDL_SCANCODE_COMMA: return 0xBC;
    case SDL_SCANCODE_MINUS: return 0xBD;
    case SDL_SCANCODE_PERIOD: return 0xBE;
    case SDL_SCANCODE_SLASH: return 0xBF;
    case SDL_SCANCODE_GRAVE: return 0xC0;
    case SDL_SCANCODE_LEFTBRACKET: return 0xDB;
    case SDL_SCANCODE_BACKSLASH: return 0xDC;
    case SDL_SCANCODE_RIGHTBRACKET: return 0xDD;
    case SDL_SCANCODE_APOSTROPHE: return 0xDE;
    default: return 0;
    }
}
/* the PC/AT set-1 scan code, which lParam carries */
static uint32_t scan_of(SDL_Scancode s) {
    static const uint8_t t[SDL_NUM_SCANCODES] = {
        [SDL_SCANCODE_ESCAPE] = 0x01, [SDL_SCANCODE_1] = 2, [SDL_SCANCODE_2] = 3, [SDL_SCANCODE_3] = 4, [SDL_SCANCODE_4] = 5,
        [SDL_SCANCODE_5] = 6, [SDL_SCANCODE_6] = 7, [SDL_SCANCODE_7] = 8, [SDL_SCANCODE_8] = 9, [SDL_SCANCODE_9] = 10,
        [SDL_SCANCODE_0] = 11, [SDL_SCANCODE_MINUS] = 12, [SDL_SCANCODE_EQUALS] = 13, [SDL_SCANCODE_BACKSPACE] = 14,
        [SDL_SCANCODE_TAB] = 15, [SDL_SCANCODE_Q] = 16, [SDL_SCANCODE_W] = 17, [SDL_SCANCODE_E] = 18, [SDL_SCANCODE_R] = 19,
        [SDL_SCANCODE_T] = 20, [SDL_SCANCODE_Y] = 21, [SDL_SCANCODE_U] = 22, [SDL_SCANCODE_I] = 23, [SDL_SCANCODE_O] = 24,
        [SDL_SCANCODE_P] = 25, [SDL_SCANCODE_LEFTBRACKET] = 26, [SDL_SCANCODE_RIGHTBRACKET] = 27, [SDL_SCANCODE_RETURN] = 28,
        [SDL_SCANCODE_LCTRL] = 29, [SDL_SCANCODE_A] = 30, [SDL_SCANCODE_S] = 31, [SDL_SCANCODE_D] = 32, [SDL_SCANCODE_F] = 33,
        [SDL_SCANCODE_G] = 34, [SDL_SCANCODE_H] = 35, [SDL_SCANCODE_J] = 36, [SDL_SCANCODE_K] = 37, [SDL_SCANCODE_L] = 38,
        [SDL_SCANCODE_SEMICOLON] = 39, [SDL_SCANCODE_APOSTROPHE] = 40, [SDL_SCANCODE_GRAVE] = 41, [SDL_SCANCODE_LSHIFT] = 42,
        [SDL_SCANCODE_BACKSLASH] = 43, [SDL_SCANCODE_Z] = 44, [SDL_SCANCODE_X] = 45, [SDL_SCANCODE_C] = 46, [SDL_SCANCODE_V] = 47,
        [SDL_SCANCODE_B] = 48, [SDL_SCANCODE_N] = 49, [SDL_SCANCODE_M] = 50, [SDL_SCANCODE_COMMA] = 51, [SDL_SCANCODE_PERIOD] = 52,
        [SDL_SCANCODE_SLASH] = 53, [SDL_SCANCODE_RSHIFT] = 54, [SDL_SCANCODE_LALT] = 56, [SDL_SCANCODE_SPACE] = 57,
        [SDL_SCANCODE_CAPSLOCK] = 58, [SDL_SCANCODE_F1] = 59, [SDL_SCANCODE_F2] = 60, [SDL_SCANCODE_F3] = 61, [SDL_SCANCODE_F4] = 62,
        [SDL_SCANCODE_F5] = 63, [SDL_SCANCODE_F6] = 64, [SDL_SCANCODE_F7] = 65, [SDL_SCANCODE_F8] = 66, [SDL_SCANCODE_F9] = 67,
        [SDL_SCANCODE_F10] = 68, [SDL_SCANCODE_F11] = 87, [SDL_SCANCODE_F12] = 88, [SDL_SCANCODE_HOME] = 71, [SDL_SCANCODE_UP] = 72,
        [SDL_SCANCODE_PAGEUP] = 73, [SDL_SCANCODE_LEFT] = 75, [SDL_SCANCODE_RIGHT] = 77, [SDL_SCANCODE_END] = 79,
        [SDL_SCANCODE_DOWN] = 80, [SDL_SCANCODE_PAGEDOWN] = 81, [SDL_SCANCODE_INSERT] = 82, [SDL_SCANCODE_DELETE] = 83 };
    return (unsigned)s < SDL_NUM_SCANCODES ? t[s] : 0;
}

/* window points -> game pixels, clamped to the picture */
static int g_src_w, g_src_h;                            /* the picture last shown: what the window maps to */
static void to_game(int x, int y, int *gx, int *gy) {
    int w = g_src_w, h = g_src_h, bpp, pw, ph, ww, wh;
    if (w <= 0 || h <= 0) hle_dd_mode(&w, &h, &bpp);
    if (g_ren && g_win) {                                /* HiDPI: the renderer counts pixels, events points */
        SDL_GetRendererOutputSize(g_ren, &pw, &ph);
        SDL_GetWindowSize(g_win, &ww, &wh);
        if (ww > 0 && wh > 0) x = x * pw / ww, y = y * ph / wh;
    }
    if (g_dst.w <= 0 || g_dst.h <= 0) { *gx = x, *gy = y; return; }
    *gx = (int)((long long)(x - g_dst.x) * w / g_dst.w);
    *gy = (int)((long long)(y - g_dst.y) * h / g_dst.h);
    if (*gx < 0) *gx = 0;
    if (*gy < 0) *gy = 0;
    if (*gx >= w) *gx = w - 1;
    if (*gy >= h) *gy = h - 1;
}

#ifdef __EMSCRIPTEN__
static void web_present(const uint16_t *fb, int w, int h, int dx, int dy, int dw, int dh, int mode, int cw, int ch) {
    MAIN_THREAD_ASYNC_EM_ASM({ if (Module['ra2Present']) Module['ra2Present']($0, $1, $2, $3, $4, $5, $6, $7, $8, $9); },
                             fb, w, h, dx, dy, dw, dh, mode, cw, ch);
}
static void web_menu(int open) {
    static int was = -1;
    if (open == was) return;
    was = open;
    MAIN_THREAD_ASYNC_EM_ASM({ if (Module['ra2Menu']) Module['ra2Menu']($0); }, open);
}
#endif
/* Frame pacing, for flips: each frame stays on screen for the same number of
 * the display's refreshes. A game making 70 frames a second on a 175 Hz
 * display would otherwise show them for 2 or 3 refreshes in turn, which
 * judders; held to 3 it moves evenly at 58.3. The number is the fewest the
 * game's own time a frame fits in (10% over is let go, as an occasional
 * late frame; gaps of a tenth of a second and more are loads, not frames),
 * taken up at once and down only after a second of fitting, and never more
 * than a twentieth of a second.
 * The wait gives the machine up, so the game's other threads run. */
static uint64_t g_paced_back;                              /* when the last paced frame went out */
static int g_pace_k = 1, g_pace_hz;                         /* each frame held for k of the display's hz */
static void pace(void) {
    static uint64_t last_call;
    static double ema;
    static int lower;
    int k = g_pace_k;
    SDL_DisplayMode dm;
    int hz = SDL_GetCurrentDisplayMode(SDL_GetWindowDisplayIndex(g_win), &dm) == 0 && dm.refresh_rate > 0 ? dm.refresh_rate : 60;
    double freq = (double)SDL_GetPerformanceFrequency(), period = 1.0 / hz;
    uint64_t now = SDL_GetPerformanceCounter();
    if (g_paced_back) {
        double work = (double)(now - g_paced_back) / freq;  /* the game's time since the last frame went out */
        if (work < 0.1) ema = ema > 0 ? 0.9 * ema + 0.1 * work : work;   /* longer: a load, not a frame */
        int want = (int)ceil(ema / period - 0.1), most = hz / 20 > 1 ? hz / 20 : 1;   /* never under 20 a second */
        if (want < 1) want = 1;
        if (want > most) want = most;
        if (want > k) k = want, lower = 0;
        else if (want < k && ++lower * k >= hz) k = want, lower = 0;  /* a second of frames that fit */
        else if (want >= k) lower = 0;
        uint64_t due = last_call + (uint64_t)(k * period * freq);
        if (now < due && due - now < (uint64_t)freq) {
            hle_block_begin();
            uint64_t spin = (uint64_t)(0.001 * freq);    /* sleep to a millisecond short, then spin: sleeps overshoot */
            if (due - now > spin) SDL_Delay((Uint32)((double)(due - now - spin) * 1000.0 / freq));
            while (SDL_GetPerformanceCounter() < due) {}
            hle_block_end();
            now = due;
        }
    }
    last_call = now;
    g_pace_k = k, g_pace_hz = hz;
}
/* flip: the game flipped, and this frame is shown, paced (pace). */
static void present(int flip) {
    const uint8_t *px;
    const uint32_t *pal;
    int w, h, pitch, bpp;
    unsigned seq;
    pal = NULL;
    if (!hle_dd_frame(&px, &w, &h, &pitch, &bpp, &pal, &seq) && !hle_gdi_window_frame(&px, &w, &h, &pitch, &bpp, &seq)) return;
    uint32_t now = hle_ticks_ms();
    g_src_w = w, g_src_h = h;
    if (!flip && seq == g_shown_seq && now - g_last_present < 250) return;
    if (!flip && now - g_last_present < 15) return;
    g_shown_seq = seq, g_last_present = now;
    if (hle_screen_frame_hook) hle_screen_frame_hook(px, w, h, pitch, bpp);
    if (!g_ren) return;
#ifdef __EMSCRIPTEN__
    /* The page draws the frame with WebGL on its own thread (index.html's
     * ra2Present): SDL's software renderer scaled it on this thread and
     * handed the whole window's pixels over, which took longer than the
     * game's frame, so the game never went idle. The frame goes as RGB565
     * in one of two buffers (the page reads it later); the place in the
     * window is this thread's, so the mouse maps the same way. SDL still
     * draws the host's menu (F10), over which the page's canvas hides. */
    if (bpp == 16) {
        int ww, wh;
        SDL_GetRendererOutputSize(g_ren, &ww, &wh);
        if ((long long)ww * h > (long long)wh * w) g_dst.h = wh, g_dst.w = (int)((long long)wh * w / h);
        else g_dst.w = ww, g_dst.h = (int)((long long)ww * h / w);
        if (g_mode == 4) {
            int k = ww / w < wh / h ? ww / w : wh / h;
            if (k < 1) k = 1;
            g_dst.w = w * k, g_dst.h = h * k;
        }
        g_dst.x = (ww - g_dst.w) / 2, g_dst.y = (wh - g_dst.h) / 2;
        if (g_menu_depth) {                              /* SDL's picture and menu: the page's canvas steps aside */
            web_menu(1);
        } else {
            static uint16_t *fb[2];
            static size_t fbn;
            static int which;
            if (fbn < (size_t)w * h) {
                free(fb[0]); free(fb[1]);
                fbn = (size_t)w * h;
                fb[0] = (uint16_t *)malloc(fbn * 2), fb[1] = (uint16_t *)malloc(fbn * 2);
            }
            which ^= 1;
            uint16_t *dst = fb[which];
            if (dst) {
                for (int y = 0; y < h; y++) memcpy(dst + (size_t)y * w, px + (size_t)y * pitch, (size_t)w * 2);
                web_menu(0);
                web_present(dst, w, h, g_dst.x, g_dst.y, g_dst.w, g_dst.h, g_mode, ww, wh);
            }
            return;
        }
    }
#endif
    int hd = 0, ov = 0, ovx = 0, ovy = 0, ovw = 0, ovh = 0;
    if (bpp == 16 && hle_screen_overlay_hook) {        /* 1x base scaled on the GPU + an Nx overlay */
        if (g_ov_n < (size_t)w * h * 9) {              /* sized for the largest scale (3x) */
            free(g_ov); g_ov_n = (size_t)w * h * 9; g_ov = (uint32_t *)calloc(g_ov_n, 4);
            if (g_ov_tex) { SDL_DestroyTexture(g_ov_tex); g_ov_tex = NULL; }
        }
        ov = g_ov ? hle_screen_overlay_hook(px, pitch, w, h, g_ov, &ovx, &ovy, &ovw, &ovh) : 0;
    }
    if (!ov && bpp == 16 && hle_screen_compose_hook) { /* the old full 2x compose (other titles) */
        if (g_hd_n < (size_t)w * h * 4) { free(g_hd); g_hd_n = (size_t)w * h * 4; g_hd = (uint32_t *)malloc(g_hd_n * 4); }
        hd = g_hd && hle_screen_compose_hook(px, pitch, w, h, g_hd);
    }
    int fmt = bpp == 16 && !hd ? SDL_PIXELFORMAT_RGB565 : SDL_PIXELFORMAT_RGB888;
    int tw = hd ? 2 * w : w, th = hd ? 2 * h : h;
    if (!g_tex || g_tex_w != tw || g_tex_h != th || g_tex_fmt != fmt) {
        if (g_tex) SDL_DestroyTexture(g_tex);
        g_tex = SDL_CreateTexture(g_ren, (Uint32)fmt, SDL_TEXTUREACCESS_STREAMING, tw, th);
        g_tex_w = tw, g_tex_h = th, g_tex_fmt = fmt;
    }
    if (hd) {
        SDL_UpdateTexture(g_tex, NULL, g_hd, tw * 4);
    } else if (bpp == 8) {
        if (g_conv_n < (size_t)w * h) { free(g_conv); g_conv_n = (size_t)w * h; g_conv = (uint32_t *)malloc(g_conv_n * 4); }
        for (int y = 0; y < h; y++)
            for (int x = 0; x < w; x++) {
                uint32_t e = pal ? pal[px[(size_t)y * pitch + x]] : 0;   /* PALETTEENTRY r, g, b */
                g_conv[(size_t)y * w + x] = 0xFF000000u | (e & 0xFF) << 16 | (e & 0xFF00) | (e >> 16 & 0xFF);
            }
        SDL_UpdateTexture(g_tex, NULL, g_conv, w * 4);
    } else {
        SDL_UpdateTexture(g_tex, NULL, px, pitch);
    }
    int ww, wh;
    SDL_GetRendererOutputSize(g_ren, &ww, &wh);
    if ((long long)ww * h > (long long)wh * w) g_dst.h = wh, g_dst.w = (int)((long long)wh * w / h);
    else g_dst.w = ww, g_dst.h = (int)((long long)ww * h / w);
    if (g_mode == 4) {                                   /* integer: whole multiples of the game's size */
        int k = ww / w < wh / h ? ww / w : wh / h;
        if (k < 1) k = 1;
        g_dst.w = w * k, g_dst.h = h * k;
    }
    g_dst.x = (ww - g_dst.w) / 2, g_dst.y = (wh - g_dst.h) / 2;
    SDL_SetRenderDrawColor(g_ren, 0, 0, 0, 255);
    SDL_RenderClear(g_ren);
    if (g_bars && (g_dst.w < ww || g_dst.h < wh)) {     /* the bars: the picture, tiny then stretched, dark */
        if (!g_small) g_small = SDL_CreateTexture(g_ren, SDL_PIXELFORMAT_RGB888, SDL_TEXTUREACCESS_TARGET, 24, 15);
        if (g_small) {
            SDL_SetTextureScaleMode(g_tex, SDL_ScaleModeLinear);
            SDL_SetRenderTarget(g_ren, g_small);
            SDL_RenderCopy(g_ren, g_tex, NULL, NULL);
            SDL_SetRenderTarget(g_ren, NULL);
            SDL_SetTextureScaleMode(g_small, SDL_ScaleModeLinear);
            SDL_SetTextureColorMod(g_small, 90, 90, 90);
            SDL_RenderCopy(g_ren, g_small, NULL, NULL);
        }
    }
    int sharp = g_mode == 0 || g_mode == 2;
    int k = g_dst.w / tw < g_dst.h / th ? g_dst.w / tw : g_dst.h / th;
    if (sharp && k >= 1 && (tw * k != g_dst.w || th * k != g_dst.h)) {
        if (!g_pre || g_pre_w != tw * k || g_pre_h != th * k) {
            if (g_pre) SDL_DestroyTexture(g_pre);
            g_pre = SDL_CreateTexture(g_ren, SDL_PIXELFORMAT_RGB888, SDL_TEXTUREACCESS_TARGET, tw * k, th * k);
            g_pre_w = tw * k, g_pre_h = th * k;
        }
    }
    if (sharp && k >= 1 && g_pre && (tw * k != g_dst.w || th * k != g_dst.h)) {
        SDL_SetTextureScaleMode(g_tex, SDL_ScaleModeNearest);
        SDL_SetRenderTarget(g_ren, g_pre);
        SDL_RenderCopy(g_ren, g_tex, NULL, NULL);
        SDL_SetRenderTarget(g_ren, NULL);
        SDL_SetTextureScaleMode(g_pre, SDL_ScaleModeLinear);
        SDL_RenderCopy(g_ren, g_pre, NULL, &g_dst);
    } else {
        SDL_SetTextureScaleMode(g_tex, g_mode == 1 ? SDL_ScaleModeLinear : SDL_ScaleModeNearest);
        SDL_RenderCopy(g_ren, g_tex, NULL, &g_dst);
    }
    if (ov) {                                            /* the Nx HD overlay (ov = N), over the scaled 1x picture */
        int ow = ov * w, oh = ov * h;
        if (!g_ov_tex || g_ov_tw != ow || g_ov_th != oh) {
            if (g_ov_tex) SDL_DestroyTexture(g_ov_tex);
            g_ov_tex = SDL_CreateTexture(g_ren, SDL_PIXELFORMAT_ARGB8888, SDL_TEXTUREACCESS_STREAMING, ow, oh);
            g_ov_tw = ow, g_ov_th = oh;
            if (g_ov_tex) SDL_SetTextureBlendMode(g_ov_tex, SDL_BLENDMODE_BLEND);
            ovx = 0, ovy = 0, ovw = ow, ovh = oh;        /* a new texture: upload all of it */
        }
        if (g_ov_tex && ovw > 0 && ovh > 0) {
            SDL_Rect ur = { ovx, ovy, ovw, ovh };
            SDL_UpdateTexture(g_ov_tex, &ur, g_ov + (size_t)ovy * ow + ovx, ow * 4);
        }
        if (g_ov_tex) {
            SDL_SetTextureScaleMode(g_ov_tex, SDL_ScaleModeNearest);
            SDL_RenderCopy(g_ren, g_ov_tex, NULL, &g_dst);
        }
    }
    if (g_mode == 2 && g_dst.h >= 2 * h) {                /* crt: the lower third of every game row darker */
        SDL_SetRenderDrawBlendMode(g_ren, SDL_BLENDMODE_BLEND);
        SDL_SetRenderDrawColor(g_ren, 0, 0, 0, 96);
        for (int y = 0; y < h; y++) {
            int y0 = g_dst.y + (int)((long long)(3 * y + 2) * g_dst.h / (3 * h)), y1 = g_dst.y + (int)((long long)(y + 1) * g_dst.h / h);
            SDL_Rect r = { g_dst.x, y0, g_dst.w, y1 > y0 ? y1 - y0 : 1 };
            SDL_RenderFillRect(g_ren, &r);
        }
        SDL_SetRenderDrawBlendMode(g_ren, SDL_BLENDMODE_NONE);
    }
    if (g_menu_depth) menu_draw();
    if (flip) pace();
    SDL_RenderPresent(g_ren);
    if (flip) g_paced_back = SDL_GetPerformanceCounter();
    static int trace = -1;
    static uint32_t t0, prev, shown, flips, worst, late;
    if (trace < 0) trace = getenv("HLE_PRESENTTRACE") != NULL;
    if (trace) {                                         /* HLE_PRESENTTRACE: frames shown a second, and the longest wait */
        uint32_t t = hle_ticks_ms();
        if (prev && t - prev > worst) worst = t - prev;
        if (prev && flip && g_pace_hz && (t - prev) * (uint32_t)g_pace_hz > 1500u * (uint32_t)g_pace_k) late++;   /* held a refresh or more too long */
        prev = t, shown++, flips += flip != 0;
        if (!t0) t0 = t;
        else if (t - t0 >= 5000) {
            fprintf(stderr, "[screen] %.1f frames shown/s (%u of them flips), longest gap %u ms; flips held %d of %d Hz, %u late\n",
                    shown * 1000.0 / (t - t0), flips, worst, g_pace_k, g_pace_hz, late);
            t0 = t, shown = flips = worst = late = 0;
        }
    }
}

/* Who shows the cursor. A DirectDraw game draws its own into the picture, so
 * by default the window has none. A game whose menus are Win32 dialogs (Red
 * Alert 2) uses the Windows cursor there: its host's hook says when, and the
 * window shows the cursor the game set, built from its resources. */
int (*hle_screen_cursor_hook)(void);
int (*hle_screen_key_hook)(int sdl_scancode, int down);

/* The window's title, for a host that shows what is playing (a mod). */
void hle_screen_title(const char *title) { if (g_win) SDL_SetWindowTitle(g_win, title); }

static SDL_Cursor *sdl_cursor_from(const hle_cursor_image_t *img) {
    /* Windows' AND/XOR masks to SDL's mask/data: AND 0 is opaque (XOR 0 black,
     * 1 white); AND 1 is transparent (XOR 1 inverts). */
    uint8_t data[128], mask[128];
    for (int i = 0; i < 128; i++) {
        mask[i] = (uint8_t)~img->and_mask[i];
        data[i] = (uint8_t)((~img->xor_mask[i] & mask[i]) | (img->xor_mask[i] & img->and_mask[i]));
    }
    return SDL_CreateCursor(data, mask, 32, 32, img->hot_x, img->hot_y);
}

static void update_cursor(void) {
    static int was_shown = 0;
    static uint32_t was_handle;
    static SDL_Cursor *made;
    int show = g_menu_depth || (hle_screen_cursor_hook && hle_screen_cursor_hook());
    uint32_t handle = g_menu_depth ? 0 : hle_current_cursor();   /* over a menu, the system arrow */
    if (show == was_shown && (!show || handle == was_handle)) return;
    if (show && handle != was_handle) {
        const hle_cursor_image_t *img = hle_cursor_image(handle);
        SDL_Cursor *c = img ? sdl_cursor_from(img) : NULL;
        SDL_SetCursor(c ? c : SDL_GetDefaultCursor());
        if (made) SDL_FreeCursor(made);
        made = c;
        was_handle = handle;
    }
    if (show != was_shown) SDL_ShowCursor(show ? SDL_ENABLE : SDL_DISABLE);
    fprintf(stderr, "[screen] cursor: %s\n", !show ? "drawn by the game" : made ? "the game's, from its resources" : "the system arrow");
    was_shown = show;
}

/* ---- the popup menu (hle_screen_menu) ----
 * Drawn over the picture in the renderer's pixels, in a desktop menu's look:
 * light rows, a blue highlight, a check mark, a submenu's arrow. */
#define MENU_LEVELS 4
static struct { const hle_menu_item_t *items; int n, x, y, w, h, sel; } g_menu[MENU_LEVELS];
static void (*g_menu_chosen)(int id);
static TTF_Font *g_menu_font;
static int g_menu_scale, g_menu_eat_up;                  /* renderer pixels per window point; the closing click's release */

static int menu_ok(const hle_menu_item_t *it) { return it->label && (it->sub || it->id); }
static int menu_item_h(const hle_menu_item_t *it) {
    return it->label ? TTF_FontHeight(g_menu_font) + 8 * g_menu_scale : 7 * g_menu_scale;
}
static int menu_text_w(const char *s) {
    int w = 0, h;
    if (s && *s) TTF_SizeUTF8(g_menu_font, s, &w, &h);
    return w;
}
static void menu_dirty(void) { g_shown_seq = ~0u; }
static void menu_close(void) { g_menu_depth = 0; menu_dirty(); }

/* Level l at (x, y), kept inside the window: a submenu that would leave it
 * on the right opens to its parent's left instead. */
static void menu_place(int l, int x, int y) {
    int pw, ph, s = g_menu_scale, w = 0, h = 2 * s;
    SDL_GetRendererOutputSize(g_ren, &pw, &ph);
    for (int i = 0; i < g_menu[l].n; i++) {
        const hle_menu_item_t *it = &g_menu[l].items[i];
        int iw = menu_text_w(it->label) + (it->hint ? menu_text_w(it->hint) + 32 * s : 0);
        if (iw > w) w = iw;
        h += menu_item_h(it);
    }
    w += 2 * 26 * s;                                     /* the check's column and the arrow's */
    if (x + w > pw) x = l ? g_menu[l - 1].x - w : pw - w;
    if (y + h > ph) y = ph - h;
    g_menu[l].x = x < 0 ? 0 : x, g_menu[l].y = y < 0 ? 0 : y, g_menu[l].w = w, g_menu[l].h = h, g_menu[l].sel = -1;
}
static int menu_row_y(int l, int row) {
    int y = g_menu[l].y + g_menu_scale;
    for (int i = 0; i < row; i++) y += menu_item_h(&g_menu[l].items[i]);
    return y;
}
static int menu_first(int l, int from, int step) {      /* the next item that can be chosen, or -1 */
    for (int k = 0, i = from; k < g_menu[l].n; k++) {
        i = (i + step + g_menu[l].n) % g_menu[l].n;
        if (menu_ok(&g_menu[l].items[i])) return i;
    }
    return -1;
}
/* Row `row` of level l is highlighted: its submenu opens, any deeper closes. */
static void menu_select(int l, int row) {
    const hle_menu_item_t *it = &g_menu[l].items[row];
    g_menu[l].sel = row, g_menu_depth = l + 1;
    if (it->sub && it->nsub > 0 && l + 1 < MENU_LEVELS) {
        g_menu[l + 1].items = it->sub, g_menu[l + 1].n = it->nsub;
        menu_place(l + 1, g_menu[l].x + g_menu[l].w - 2 * g_menu_scale, menu_row_y(l, row) - g_menu_scale);
        g_menu_depth = l + 2;
    }
    menu_dirty();
}
static void menu_choose(int l, int row) {
    const hle_menu_item_t *it = &g_menu[l].items[row];
    if (!menu_ok(it)) return;
    if (it->sub) {                                       /* into the submenu, its first item */
        menu_select(l, row);
        if (g_menu_depth == l + 2) g_menu[l + 1].sel = menu_first(l + 1, -1, 1);
        return;
    }
    void (*chosen)(int) = g_menu_chosen;
    menu_close();
    fprintf(stderr, "[screen] menu: %s\n", it->label);
    if (chosen) chosen(it->id);
}
static int menu_hit(int x, int y, int *row) {           /* the deepest level under (x, y), or -1 */
    for (int l = g_menu_depth - 1; l >= 0; l--) {
        if (x < g_menu[l].x || x >= g_menu[l].x + g_menu[l].w || y < g_menu[l].y || y >= g_menu[l].y + g_menu[l].h) continue;
        int ry = g_menu[l].y + g_menu_scale;
        *row = -1;
        for (int i = 0; i < g_menu[l].n && *row < 0; i++) {
            ry += menu_item_h(&g_menu[l].items[i]);
            if (y < ry) *row = i;
        }
        return l;
    }
    return -1;
}
static void menu_key(SDL_Scancode sc) {
    int l = g_menu_depth - 1, sel = g_menu[l].sel;
    if (sc == SDL_SCANCODE_ESCAPE) { if (l) g_menu_depth = l, menu_dirty(); else menu_close(); }
    else if (sc == SDL_SCANCODE_F10) menu_close();
    else if (sc == SDL_SCANCODE_UP || sc == SDL_SCANCODE_DOWN) {
        int to = menu_first(l, sel < 0 && sc == SDL_SCANCODE_UP ? 0 : sel, sc == SDL_SCANCODE_UP ? -1 : 1);
        if (to >= 0) g_menu[l].sel = to, g_menu_depth = l + 1, menu_dirty();
    }
    else if (sc == SDL_SCANCODE_LEFT && l) g_menu_depth = l, menu_dirty();
    else if (sel >= 0 && ((sc == SDL_SCANCODE_RIGHT && g_menu[l].items[sel].sub) ||
                          sc == SDL_SCANCODE_RETURN || sc == SDL_SCANCODE_KP_ENTER || sc == SDL_SCANCODE_SPACE))
        menu_choose(l, sel);
}
/* An event while the menu is open: the menu's, never the game's. */
static int menu_event(const SDL_Event *e) {
    int x, y, row = -1, l, pw, ph, ww, wh;
    switch (e->type) {
    case SDL_MOUSEMOTION: case SDL_MOUSEBUTTONDOWN: case SDL_MOUSEBUTTONUP:
        x = e->type == SDL_MOUSEMOTION ? e->motion.x : e->button.x;
        y = e->type == SDL_MOUSEMOTION ? e->motion.y : e->button.y;
        SDL_GetRendererOutputSize(g_ren, &pw, &ph);
        SDL_GetWindowSize(g_win, &ww, &wh);
        if (ww > 0 && wh > 0) x = x * pw / ww, y = y * ph / wh;
        l = menu_hit(x, y, &row);
        if (e->type == SDL_MOUSEMOTION) { if (l >= 0 && row >= 0 && g_menu[l].sel != row) menu_select(l, row); }
        else if (e->type == SDL_MOUSEBUTTONDOWN) {
            g_menu_eat_up = 1;                           /* a click that closes the menu: its release isn't the game's */
            if (l < 0) menu_close(); else if (row >= 0) menu_choose(l, row);
        } else g_menu_eat_up = 0;
        return 1;
    case SDL_KEYDOWN: menu_key(e->key.keysym.scancode); return 1;
    case SDL_KEYUP: case SDL_TEXTINPUT: case SDL_MOUSEWHEEL: return 1;
    default: return 0;
    }
}

static void menu_text(const char *s, int x, int y, SDL_Color c) {
    SDL_Surface *t = s && *s ? TTF_RenderUTF8_Blended(g_menu_font, s, c) : NULL;
    if (!t) return;
    SDL_Texture *tx = SDL_CreateTextureFromSurface(g_ren, t);   /* ponytail: made each frame; a cache if a menu ever grows long */
    SDL_Rect r = { x, y, t->w, t->h };
    if (tx) SDL_RenderCopy(g_ren, tx, NULL, &r), SDL_DestroyTexture(tx);
    SDL_FreeSurface(t);
}
static void menu_lines(const int *pts, int n, int dx, int dy) {   /* a stroke two pixels wide per scale */
    for (int t = 0; t < 2 * g_menu_scale; t++)
        for (int i = 0; i + 3 < 2 * n; i += 2)
            SDL_RenderDrawLine(g_ren, dx + pts[i] * g_menu_scale, dy + pts[i + 1] * g_menu_scale + t,
                               dx + pts[i + 2] * g_menu_scale, dy + pts[i + 3] * g_menu_scale + t);
}
static void menu_draw(void) {
    int s = g_menu_scale, fh = TTF_FontHeight(g_menu_font);
    for (int l = 0; l < g_menu_depth; l++) {
        SDL_Rect box = { g_menu[l].x, g_menu[l].y, g_menu[l].w, g_menu[l].h };
        SDL_SetRenderDrawColor(g_ren, 242, 242, 242, 255);
        SDL_RenderFillRect(g_ren, &box);
        SDL_SetRenderDrawColor(g_ren, 150, 150, 150, 255);
        SDL_RenderDrawRect(g_ren, &box);
        int y = g_menu[l].y + s;
        for (int i = 0; i < g_menu[l].n; i++) {
            const hle_menu_item_t *it = &g_menu[l].items[i];
            int h = menu_item_h(it), x = g_menu[l].x;
            if (!it->label) {
                SDL_SetRenderDrawColor(g_ren, 200, 200, 200, 255);
                SDL_Rect sep = { x + 8 * s, y + h / 2, g_menu[l].w - 16 * s, s };
                SDL_RenderFillRect(g_ren, &sep);
                y += h;
                continue;
            }
            int lit = i == g_menu[l].sel && menu_ok(it);
            SDL_Color c = lit ? (SDL_Color){ 255, 255, 255, 255 } : menu_ok(it) ? (SDL_Color){ 20, 20, 20, 255 }
                                                                               : (SDL_Color){ 150, 150, 150, 255 };
            if (lit) {
                SDL_Rect r = { x + 2 * s, y, g_menu[l].w - 4 * s, h };
                SDL_SetRenderDrawColor(g_ren, 0, 103, 192, 255);
                SDL_RenderFillRect(g_ren, &r);
            }
            SDL_SetRenderDrawColor(g_ren, c.r, c.g, c.b, 255);
            int mid = y + h / 2;
            if (it->checked) { static const int tick[] = { 9, 0, 12, 3, 18, -4 }; menu_lines(tick, 3, x, mid - s); }
            if (it->sub) { static const int arrow[] = { 0, -4, 4, 0, 0, 4 }; menu_lines(arrow, 3, x + g_menu[l].w - 16 * s, mid - s); }
            menu_text(it->label, x + 26 * s, y + (h - fh) / 2, c);
            if (it->hint) menu_text(it->hint, x + g_menu[l].w - 26 * s - menu_text_w(it->hint), y + (h - fh) / 2, c);
            y += h;
        }
    }
}

#ifndef __EMSCRIPTEN__
int hle_screen_menu_open(void) { return g_menu_depth > 0; }
#endif

/* The size of the display the window is on (the first, before it opens):
 * SDL's desktop mode, in points, so a Retina Mac's logical size. */
int hle_screen_desktop(int *w, int *h) {
    SDL_DisplayMode m;
    int i = g_win ? SDL_GetWindowDisplayIndex(g_win) : 0;
    if (!SDL_WasInit(SDL_INIT_VIDEO) || SDL_GetDesktopDisplayMode(i < 0 ? 0 : i, &m) != 0) return 0;
    *w = m.w, *h = m.h;
    return 1;
}
#ifdef __EMSCRIPTEN__
/* In a browser the page draws the menu (index.html's ra2PopupMenu), as HTML
 * at the mouse: SDL's own, drawn with its software renderer, took longer
 * than a frame to show, and the game then never went idle to read a key.
 * The items go over as JSON; the page writes the choice (0: none yet, -1:
 * closed) into g_web_choice, and the pump calls chosen() on this thread. */
static volatile int g_web_choice;
static void (*g_web_chosen)(int id);
static char g_web_menu_json[16384];
static size_t json_item(char *out, size_t n, const hle_menu_item_t *it) {
    size_t k = 0;
    if (!it->label) return (size_t)snprintf(out, n, "null");
    k += (size_t)snprintf(out + k, n - k, "{\"label\":\"");
    for (const char *p = it->label; *p && k + 8 < n; p++) {
        if (*p == '"' || *p == '\\') out[k++] = '\\';
        out[k++] = *p;
    }
    k += (size_t)snprintf(out + k, n - k, "\",\"hint\":\"%s\",\"id\":%d,\"checked\":%d", it->hint ? it->hint : "", it->id, it->checked ? 1 : 0);
    if (it->sub && it->nsub > 0) {
        k += (size_t)snprintf(out + k, n - k, ",\"sub\":[");
        for (int i = 0; i < it->nsub && k + 64 < n; i++) {
            if (i) out[k++] = ',';
            k += json_item(out + k, n - k, &it->sub[i]);
        }
        k += (size_t)snprintf(out + k, n - k, "]");
    }
    k += (size_t)snprintf(out + k, n - k, "}");
    return k;
}
void hle_screen_menu(const hle_menu_item_t *items, int n, void (*chosen)(int id)) {
    if (!items || n <= 0) return;
    size_t k = 0;
    g_web_menu_json[k++] = '[';
    for (int i = 0; i < n && k + 64 < sizeof g_web_menu_json; i++) {
        if (i) g_web_menu_json[k++] = ',';
        k += json_item(g_web_menu_json + k, sizeof g_web_menu_json - k, &items[i]);
    }
    g_web_menu_json[k++] = ']';
    g_web_menu_json[k] = 0;
    g_web_choice = 0, g_web_chosen = chosen;
    MAIN_THREAD_ASYNC_EM_ASM({ if (Module['ra2PopupMenu']) Module['ra2PopupMenu'](UTF8ToString($0), $1); else HEAP32[$1 >> 2] = -1; },
                             g_web_menu_json, &g_web_choice);
}
int hle_screen_menu_open(void) { return g_web_chosen != NULL; }
static void web_menu_poll(void) {
    if (!g_web_chosen || !g_web_choice) return;
    int id = g_web_choice;
    void (*cb)(int) = g_web_chosen;
    g_web_choice = 0, g_web_chosen = NULL;
    if (id > 0) cb(id);
}
#endif
#ifndef __EMSCRIPTEN__
void hle_screen_menu(const hle_menu_item_t *items, int n, void (*chosen)(int id)) {
    int pw, ph, ww, wh, mx, my;
    if (!g_ren || !items || n <= 0) return;
    SDL_GetRendererOutputSize(g_ren, &pw, &ph);
    SDL_GetWindowSize(g_win, &ww, &wh);
    int scale = ww > 0 && pw >= 2 * ww ? 2 : 1;          /* ponytail: 1x or 2x; a fractional HiDPI scale gets 1x */
    if (!g_menu_font || scale != g_menu_scale) {
        const char *path = TTF_WasInit() || TTF_Init() == 0 ? hle_font_file("MS Sans Serif", 0, 0) : NULL;
        if (g_menu_font) TTF_CloseFont(g_menu_font);
        g_menu_font = path ? TTF_OpenFont(path, 16 * scale) : NULL;
        g_menu_scale = scale;
        if (!g_menu_font) { fprintf(stderr, "[screen] no font for the menu: install fonts-liberation\n"); return; }
    }
    SDL_GetMouseState(&mx, &my);
    if (ww > 0 && wh > 0) mx = mx * pw / ww, my = my * ph / wh;
    g_menu[0].items = items, g_menu[0].n = n;
    menu_place(0, mx, my);
    g_menu_depth = 1, g_menu_chosen = chosen, g_menu_eat_up = 0;
    menu_dirty();
}
#endif

#ifdef __EMSCRIPTEN__
#include <emscripten/threading.h>
#endif
int g_input_trace;                                         /* a host's --inputtrace */
void hle_screen_pump(void) {
#ifdef __EMSCRIPTEN__
    /* the browser's main thread queues this thread's input callbacks */
    emscripten_current_thread_process_queued_calls();
    web_menu_poll();
#endif
    SDL_Event e;
    if (g_win) update_cursor();
    while (g_win && SDL_PollEvent(&e)) {
#ifdef __EMSCRIPTEN__
        if (getenv("RA2_INPUT_TRACE") || g_input_trace) {
            if (e.type == SDL_KEYDOWN || e.type == SDL_KEYUP) fprintf(stderr, "[input] key %s scancode %d repeat %d\n", e.type == SDL_KEYDOWN ? "down" : "up", e.key.keysym.scancode, e.key.repeat);
            else if (e.type == SDL_MOUSEBUTTONDOWN || e.type == SDL_MOUSEBUTTONUP) fprintf(stderr, "[input] button %d %s at %d,%d\n", e.button.button, e.type == SDL_MOUSEBUTTONDOWN ? "down" : "up", e.button.x, e.button.y);
        }
#endif
        if (g_menu_depth && menu_event(&e)) continue;
        if (g_menu_eat_up && e.type == SDL_MOUSEBUTTONUP) { g_menu_eat_up = 0; continue; }
        switch (e.type) {
        case SDL_QUIT: {
            uint32_t h = hle_first_hwnd();
            if (h) hle_post_message(h, WM_CLOSE, 0, 0); else hle_exit(0);
            break;
        }
        case SDL_KEYDOWN: case SDL_KEYUP: {
            SDL_Scancode sc = e.key.keysym.scancode;
            /* a key the host keeps for itself (a mod switch): the game never sees it */
            if (hle_screen_key_hook && hle_screen_key_hook((int)sc, e.type == SDL_KEYDOWN)) break;
            /* the presenter's keys, the Windows build's: they do not reach the game */
            if ((sc == SDL_SCANCODE_RETURN && (e.key.keysym.mod & KMOD_ALT)) || sc == SDL_SCANCODE_F11) {
                if (e.type == SDL_KEYDOWN) set_fullscreen(!g_fullscreen);
                break;
            }
            if (sc == SDL_SCANCODE_F12) {
                if (e.type == SDL_KEYDOWN) {
                    g_mode = (g_mode + 1) % 5;
                    fprintf(stderr, "[screen] scaling: %s\n", k_modes[g_mode]);
                    settings_changed();
                }
                break;
            }
            int vk = vk_of(e.key.keysym.scancode);
            if (vk) hle_input_key(e.type == SDL_KEYDOWN, (uint32_t)vk, scan_of(e.key.keysym.scancode));
            break;
        }
        case SDL_MOUSEMOTION: {
            int gx, gy;
            to_game(e.motion.x, e.motion.y, &gx, &gy);
            hle_input_mouse(WM_MOUSEMOVE, gx, gy);
            break;
        }
        case SDL_MOUSEBUTTONDOWN: case SDL_MOUSEBUTTONUP: {
            int gx, gy, down = e.type == SDL_MOUSEBUTTONDOWN;
            to_game(e.button.x, e.button.y, &gx, &gy);
            uint32_t m = e.button.button == SDL_BUTTON_RIGHT ? (down ? WM_RBUTTONDOWN : WM_RBUTTONUP)
                       : e.button.button == SDL_BUTTON_MIDDLE ? (down ? WM_MBUTTONDOWN : WM_MBUTTONUP)
                       : (down ? WM_LBUTTONDOWN : WM_LBUTTONUP);
            hle_input_mouse(m, gx, gy);
            break;
        }
        case SDL_WINDOWEVENT:
            if (e.window.event == SDL_WINDOWEVENT_SIZE_CHANGED) g_menu_depth = 0;   /* placed for the old size */
            if (e.window.event == SDL_WINDOWEVENT_SIZE_CHANGED || e.window.event == SDL_WINDOWEVENT_EXPOSED) g_shown_seq = ~0u;
            break;
        default: break;
        }
    }
    present(0);
}

static void present_gdi(void) { present(0); }

/* The guest moved the cursor (SetCursorPos): move the real one with it. */
static void warp(int x, int y) {
    int w, h, bpp;
    hle_dd_mode(&w, &h, &bpp);
    if (!g_win || g_dst.w <= 0 || w <= 0 || h <= 0) return;
    SDL_WarpMouseInWindow(g_win, g_dst.x + x * g_dst.w / w, g_dst.y + y * g_dst.h / h);
}

/* The game drew into the primary. On the window's thread, show it (present
 * keeps to 60 a second, except a flip, which is always shown), and keep the
 * window's own events moving: a load
 * that does not pump for seconds would otherwise look hung to the desktop
 * (macOS's spinning cursor). The events wait in SDL's queue for the pump. */
static void primary_changed(void) {
    static uint32_t last_events;
    if (!g_ren || !pthread_equal(pthread_self(), g_video_thread)) return;
    uint32_t now = hle_ticks_ms();
    int flip = hle_dd_flipping();
    if (!flip && now - g_last_present < 15) return;
    if (now - last_events >= 100) SDL_PumpEvents(), last_events = now;
    present(flip);
}

int hle_screen_open(const char *title, int fullscreen, int headless) {
    g_headless = headless, g_fullscreen = fullscreen;
    hle_set_pump_hook(hle_screen_pump);
    hle_gdi_window_hook = present_gdi;                   /* a GDI game's blit shows, pumping or not (a loading bar) */
    if (headless) return 0;
    SDL_SetHint(SDL_HINT_NO_SIGNAL_HANDLERS, "1");      /* SIGINT and SIGTERM end the process: SDL would make them a close the game can refuse */
    if (SDL_InitSubSystem(SDL_INIT_VIDEO) != 0) { fprintf(stderr, "[screen] SDL: %s\n", SDL_GetError()); return -1; }
    g_win = SDL_CreateWindow(title, SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, 1280, 960,
                             SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI | (fullscreen ? SDL_WINDOW_FULLSCREEN_DESKTOP : 0));
    if (!g_win) { fprintf(stderr, "[screen] window: %s\n", SDL_GetError()); return -1; }
#ifdef __EMSCRIPTEN__
    /* In a browser the game runs on a worker thread and the canvas belongs
     * to the page's: SDL's GL renderer would need the WebGL context made
     * current on this thread, which its EGL path (proxied to the page's
     * thread) does not do. The software renderer draws into the window's
     * framebuffer, which SDL hands to the canvas from the page's thread. */
    g_ren = SDL_CreateRenderer(g_win, -1, SDL_RENDERER_SOFTWARE);
#else
    g_ren = SDL_CreateRenderer(g_win, -1, SDL_RENDERER_PRESENTVSYNC);
    if (!g_ren) g_ren = SDL_CreateRenderer(g_win, -1, SDL_RENDERER_SOFTWARE);
#endif
    if (!g_ren) { fprintf(stderr, "[screen] renderer: %s\n", SDL_GetError()); return -1; }
    SDL_SetHint(SDL_HINT_RENDER_SCALE_QUALITY, "0");
    SDL_ShowCursor(SDL_DISABLE);                         /* the game draws its own */
    hle_cursor_hook = warp;
    SDL_RendererInfo ri;
    SDL_GetRendererInfo(g_ren, &ri);
    g_video_thread = pthread_self();
    hle_dd_primary_hook = primary_changed;
    fprintf(stderr, "[screen] %s, renderer %s, scaling %s (F12), fullscreen F11\n", SDL_GetCurrentVideoDriver(), ri.name, k_modes[g_mode]);
    return 0;
}

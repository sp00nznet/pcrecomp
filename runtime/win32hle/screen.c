/*
 * screen.c - the display and input for a DirectDraw game on win32hle: an SDL2
 * window showing the primary surface (ddraw.c), scaled to the window with its
 * aspect kept, and SDL's mouse and keyboard turned into the window messages
 * a game's windows get (user32.c's hle_input_*).
 *
 * It runs as user32's pump hook, on the thread that runs the game (SDL wants
 * its video calls on one thread, and the game's thread is the one that pumps
 * messages). A frame is shown when the primary has changed, at most 60 times
 * a second; a game that draws without pumping (a loading screen) shows the
 * frame it last pumped on.
 *
 * Headless (hle_screen_open(..., headless)), there is no window: the pump
 * only paces, and input comes from a host's script.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <SDL2/SDL.h>
#include "win32hle.h"

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
static uint32_t *g_conv;                                 /* 8-bit frames converted */
static size_t g_conv_n;
void (*hle_screen_frame_hook)(const uint8_t *px, int w, int h, int pitch, int bpp);   /* a recorder, a checksum */
/* A host's own picture at twice the size (an HD layer): fills out with 2w x
 * 2h XRGB from the 16-bit frame and returns 1, or returns 0 for the 1x. */
int (*hle_screen_compose_hook)(const uint8_t *px16, int pitch, int w, int h, uint32_t *out);
static uint32_t *g_hd;
static size_t g_hd_n;

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
static void to_game(int x, int y, int *gx, int *gy) {
    int w, h, bpp, pw, ph, ww, wh;
    hle_dd_mode(&w, &h, &bpp);
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

static void present(void) {
    const uint8_t *px;
    const uint32_t *pal;
    int w, h, pitch, bpp;
    unsigned seq;
    if (!hle_dd_frame(&px, &w, &h, &pitch, &bpp, &pal, &seq)) return;
    uint32_t now = hle_ticks_ms();
    if (seq == g_shown_seq && now - g_last_present < 250) return;
    if (now - g_last_present < 15) return;
    g_shown_seq = seq, g_last_present = now;
    if (hle_screen_frame_hook) hle_screen_frame_hook(px, w, h, pitch, bpp);
    if (!g_ren) return;
    int hd = 0;
    if (bpp == 16 && hle_screen_compose_hook) {
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
    SDL_RenderPresent(g_ren);
}

/* Who shows the cursor. A DirectDraw game draws its own into the picture, so
 * by default the window has none. A game whose menus are Win32 dialogs (Red
 * Alert 2) uses the Windows cursor there: its host's hook says when, and the
 * window shows the cursor the game set, built from its resources. */
int (*hle_screen_cursor_hook)(void);

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
    int show = hle_screen_cursor_hook && hle_screen_cursor_hook();
    uint32_t handle = hle_current_cursor();
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

void hle_screen_pump(void) {
    SDL_Event e;
    if (g_win) update_cursor();
    while (g_win && SDL_PollEvent(&e)) {
        switch (e.type) {
        case SDL_QUIT: {
            uint32_t h = hle_first_hwnd();
            if (h) hle_post_message(h, WM_CLOSE, 0, 0); else hle_exit(0);
            break;
        }
        case SDL_KEYDOWN: case SDL_KEYUP: {
            SDL_Scancode sc = e.key.keysym.scancode;
            /* the presenter's keys, the Windows build's: they do not reach the game */
            if ((sc == SDL_SCANCODE_RETURN && (e.key.keysym.mod & KMOD_ALT)) || sc == SDL_SCANCODE_F11) {
                if (e.type == SDL_KEYDOWN) {
                    g_fullscreen = !g_fullscreen;
                    SDL_SetWindowFullscreen(g_win, g_fullscreen ? SDL_WINDOW_FULLSCREEN_DESKTOP : 0);
                    settings_changed();
                }
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
            if (e.window.event == SDL_WINDOWEVENT_SIZE_CHANGED || e.window.event == SDL_WINDOWEVENT_EXPOSED) g_shown_seq = ~0u;
            break;
        default: break;
        }
    }
    present();
}

/* The guest moved the cursor (SetCursorPos): move the real one with it. */
static void warp(int x, int y) {
    int w, h, bpp;
    hle_dd_mode(&w, &h, &bpp);
    if (!g_win || g_dst.w <= 0 || w <= 0 || h <= 0) return;
    SDL_WarpMouseInWindow(g_win, g_dst.x + x * g_dst.w / w, g_dst.y + y * g_dst.h / h);
}

int hle_screen_open(const char *title, int fullscreen, int headless) {
    g_headless = headless, g_fullscreen = fullscreen;
    hle_set_pump_hook(hle_screen_pump);
    if (headless) return 0;
    SDL_SetHint(SDL_HINT_NO_SIGNAL_HANDLERS, "1");      /* SIGINT and SIGTERM end the process: SDL would make them a close the game can refuse */
    if (SDL_InitSubSystem(SDL_INIT_VIDEO) != 0) { fprintf(stderr, "[screen] SDL: %s\n", SDL_GetError()); return -1; }
    g_win = SDL_CreateWindow(title, SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, 1280, 960,
                             SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI | (fullscreen ? SDL_WINDOW_FULLSCREEN_DESKTOP : 0));
    if (!g_win) { fprintf(stderr, "[screen] window: %s\n", SDL_GetError()); return -1; }
    g_ren = SDL_CreateRenderer(g_win, -1, SDL_RENDERER_PRESENTVSYNC);
    if (!g_ren) g_ren = SDL_CreateRenderer(g_win, -1, SDL_RENDERER_SOFTWARE);
    if (!g_ren) { fprintf(stderr, "[screen] renderer: %s\n", SDL_GetError()); return -1; }
    SDL_SetHint(SDL_HINT_RENDER_SCALE_QUALITY, "0");
    SDL_ShowCursor(SDL_DISABLE);                         /* the game draws its own */
    hle_cursor_hook = warp;
    SDL_RendererInfo ri;
    SDL_GetRendererInfo(g_ren, &ri);
    fprintf(stderr, "[screen] %s, renderer %s, scaling %s (F12), fullscreen F11\n", SDL_GetCurrentVideoDriver(), ri.name, k_modes[g_mode]);
    return 0;
}

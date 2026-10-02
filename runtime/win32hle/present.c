/*
 * present.c - the optional SDL2 present/input layer for win32hle. It shows the
 * gdi32 framebuffer in a window and turns SDL input into WM_* messages posted
 * to the user32 queue. This is the ONE piece of win32hle that needs a display;
 * everything else is headless, which is why it lives on its own and user32 does
 * not depend on SDL. Link it when you want a visible window; leave it out for
 * headless/CI (--headless uses the SDL "dummy" video driver, which this still
 * drives without a screen).
 *
 * The framebuffer is drawn with the window surface (not a GL/renderer texture)
 * so the exact same path works under the dummy driver as on a real display.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <SDL2/SDL.h>
#include "win32hle.h"

/* A subset of the Win32 message ids SDL events map to. */
#define WM_QUIT         0x0012u
#define WM_KEYDOWN      0x0100u
#define WM_KEYUP        0x0101u
#define WM_MOUSEMOVE    0x0200u
#define WM_LBUTTONDOWN  0x0201u
#define WM_LBUTTONUP    0x0202u
#define WM_RBUTTONDOWN  0x0204u
#define WM_RBUTTONUP    0x0205u

static SDL_Window  *g_win;
static SDL_Surface *g_winsurf;
static int          g_w, g_h;

int hle_present_open(const char *title, int w, int h) {
    if (SDL_Init(SDL_INIT_VIDEO) != 0) { fprintf(stderr, "[present] SDL_Init: %s\n", SDL_GetError()); return -1; }
    g_win = SDL_CreateWindow(title ? title : "win32hle",
                             SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                             w, h, SDL_WINDOW_SHOWN);
    if (!g_win) { fprintf(stderr, "[present] CreateWindow: %s\n", SDL_GetError()); return -1; }
    g_winsurf = SDL_GetWindowSurface(g_win);   /* NULL under some drivers; frame copes */
    g_w = w; g_h = h;
    return 0;
}

/* Blit a w*h ARGB8888 framebuffer to the window, scaled to the window size. */
void hle_present_frame(const uint32_t *fb) {
    if (!g_win || !fb) return;
    if (!g_winsurf) g_winsurf = SDL_GetWindowSurface(g_win);
    if (!g_winsurf) return;
    SDL_Surface *src = SDL_CreateRGBSurfaceWithFormatFrom((void *)fb, g_w, g_h, 32, g_w * 4,
                                                          SDL_PIXELFORMAT_ARGB8888);
    if (src) { SDL_BlitScaled(src, NULL, g_winsurf, NULL); SDL_FreeSurface(src); }
    SDL_UpdateWindowSurface(g_win);
}

static uint32_t mouse_lparam(int x, int y) { return ((uint32_t)(y & 0xFFFF) << 16) | (uint32_t)(x & 0xFFFF); }

/* Drain SDL's event queue, posting each as a WM_* message to the focused
 * window (the first one, for now). Call once per frame / message-loop turn. */
void hle_present_pump(void) {
    uint32_t hwnd = hle_first_hwnd();
    SDL_Event e;
    while (SDL_PollEvent(&e)) {
        switch (e.type) {
        case SDL_QUIT:
            hle_post_message(0, WM_QUIT, 0, 0);
            break;
        case SDL_KEYDOWN:
            hle_post_message(hwnd, WM_KEYDOWN, (uint32_t)e.key.keysym.sym, 0);
            break;
        case SDL_KEYUP:
            hle_post_message(hwnd, WM_KEYUP, (uint32_t)e.key.keysym.sym, 0);
            break;
        case SDL_MOUSEMOTION:
            hle_post_message(hwnd, WM_MOUSEMOVE, 0, mouse_lparam(e.motion.x, e.motion.y));
            break;
        case SDL_MOUSEBUTTONDOWN:
        case SDL_MOUSEBUTTONUP: {
            int down = e.type == SDL_MOUSEBUTTONDOWN;
            uint32_t msg = e.button.button == SDL_BUTTON_RIGHT
                         ? (down ? WM_RBUTTONDOWN : WM_RBUTTONUP)
                         : (down ? WM_LBUTTONDOWN : WM_LBUTTONUP);
            hle_post_message(hwnd, msg, 0, mouse_lparam(e.button.x, e.button.y));
            break;
        }
        default: break;
        }
    }
}

/* One turn of a guest message loop: collect input, show the current gdi32
 * frame, and yield briefly so an idle loop does not spin a core. Wired as
 * user32's pump hook by hle_present_enable, so a guest's own GetMessage/
 * PeekMessage loop drives the window with no change to the guest. */
void hle_present_step(void) {
    hle_present_pump();
    int w, h;
    const uint32_t *fb = hle_gdi_framebuffer(&w, &h);
    if (fb && w == g_w && h == g_h) hle_present_frame(fb);
    SDL_Delay(1);
}
void hle_present_enable(void) { hle_set_pump_hook(hle_present_step); }

void hle_present_close(void) {
    hle_set_pump_hook(0);
    if (g_win) { SDL_DestroyWindow(g_win); g_win = NULL; g_winsurf = NULL; }
    SDL_Quit();
}

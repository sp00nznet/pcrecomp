/*
 * present_selftest.c - exercises the SDL2 present/input layer headless, under
 * the SDL "dummy" video driver (no screen needed, works over RDP / in CI). It
 * opens a window, presents a framebuffer, pushes SDL input events, pumps them,
 * and checks each turned into the right WM_* message in the user32 queue.
 *
 * Build -m32 against 32-bit SDL2. Forces SDL_VIDEODRIVER=dummy itself so the
 * check is deterministic without a display.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <SDL2/SDL.h>
#include "win32hle.h"

/* host_lite's recomp_lookup wants the dispatch table the lifted program would
 * define; no guest runs here, so an empty one satisfies the link. */
const recomp_dispatch_entry_t recomp_dispatch_table[] = { { 0, 0 } };
const uint32_t recomp_dispatch_count = 0;

#define WM_QUIT      0x0012u
#define WM_KEYDOWN   0x0100u
#define WM_MOUSEMOVE 0x0200u

static int fails;
static void ok(const char *w, int c) { if (!c) { printf("FAIL %s\n", w); fails++; } }

int main(void) {
    setenv("SDL_VIDEODRIVER", "dummy", 1);     /* headless: no screen required */

    ok("present opens", hle_present_open("win32hle test", 8, 8) == 0);

    /* present a known frame — under dummy this still exercises the blit path */
    static uint32_t fb[8 * 8];
    for (int i = 0; i < 64; i++) fb[i] = 0xFF000000u | (uint32_t)i;
    hle_present_frame(fb);                      /* must not crash */

    /* push input and pump: a key, a mouse move, then quit */
    SDL_Event e;
    SDL_zero(e); e.type = SDL_KEYDOWN; e.key.keysym.sym = SDLK_a;              SDL_PushEvent(&e);
    SDL_zero(e); e.type = SDL_MOUSEMOTION; e.motion.x = 3; e.motion.y = 5;     SDL_PushEvent(&e);
    SDL_zero(e); e.type = SDL_QUIT;                                           SDL_PushEvent(&e);
    hle_present_pump();

    uint32_t msg, wp, lp;
    ok("key -> WM_KEYDOWN(a)", hle_msg_pop(&msg, &wp, &lp) && msg == WM_KEYDOWN && wp == (uint32_t)SDLK_a);
    ok("motion -> WM_MOUSEMOVE(3,5)", hle_msg_pop(&msg, &wp, &lp) && msg == WM_MOUSEMOVE && lp == ((5u << 16) | 3u));
    ok("quit -> WM_QUIT", hle_msg_pop(&msg, &wp, &lp) && msg == WM_QUIT);
    ok("queue now empty", hle_msg_pop(&msg, &wp, &lp) == 0);

    hle_present_close();
    if (fails == 0) printf("present_selftest: all checks passed\n");
    return fails != 0;
}

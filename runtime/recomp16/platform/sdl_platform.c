/*
 * sdl_platform.c - SDL2 Platform Layer Implementation
 *
 * Creates a scaled window for the 320x200 VGA framebuffer, handles
 * SDL events for keyboard/mouse input, and renders the VGA output
 * with proper palette conversion.
 *
 * Part of the Civ Recomp project (sp00nznet/civ)
 */

#include "platform/sdl_platform.h"
#include "font8x8.h"

#include <SDL2/SDL.h>
#include <stdio.h>
#include <string.h>

/* Text mode constants */
#define TEXT_MODE_BASE  0xB8000
#define TEXT_COLS       80
#define TEXT_ROWS       25
#define CHAR_W          4   /* pixels per character width  (80*4 = 320) */
#define CHAR_H          8   /* pixels per character height (25*8 = 200) */

int platform_init(Platform *plat, int scale)
{
    memset(plat, 0, sizeof(*plat));
    plat->scale = scale > 0 ? scale : WINDOW_SCALE;
    plat->running = 1;

    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO | SDL_INIT_TIMER) < 0) {
        fprintf(stderr, "[SDL] Init failed: %s\n", SDL_GetError());
        return -1;
    }

    int w = VGA_WIDTH * plat->scale;
    int h = VGA_HEIGHT * plat->scale;

    SDL_Window *win = SDL_CreateWindow(
        "Sid Meier's Civilization - Recomp",
        SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
        w, h,
        SDL_WINDOW_SHOWN | SDL_WINDOW_RESIZABLE);
    if (!win) {
        fprintf(stderr, "[SDL] Window creation failed: %s\n", SDL_GetError());
        return -1;
    }
    plat->window = win;

    SDL_Renderer *ren = SDL_CreateRenderer(win, -1,
        SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (!ren) {
        fprintf(stderr, "[SDL] Renderer creation failed: %s\n", SDL_GetError());
        return -1;
    }
    plat->renderer = ren;

    /* Create VGA mode 13h texture (320x200) */
    SDL_Texture *tex_vga = SDL_CreateTexture(ren,
        SDL_PIXELFORMAT_ABGR8888, SDL_TEXTUREACCESS_STREAMING,
        VGA_WIDTH, VGA_HEIGHT);
    if (!tex_vga) {
        fprintf(stderr, "[SDL] VGA texture creation failed: %s\n", SDL_GetError());
        return -1;
    }
    plat->tex_vga = tex_vga;

    /* Create text mode texture (640x200 for 80x25 with 8x8 font) */
    SDL_Texture *tex_text = SDL_CreateTexture(ren,
        SDL_PIXELFORMAT_ABGR8888, SDL_TEXTUREACCESS_STREAMING,
        TEXT_COLS * 8, TEXT_ROWS * CHAR_H);
    if (!tex_text) {
        fprintf(stderr, "[SDL] Text texture creation failed: %s\n", SDL_GetError());
        return -1;
    }
    plat->tex_text = tex_text;
    plat->last_mode = -1;

    SDL_ShowCursor(SDL_DISABLE);

    printf("[SDL] Initialized: %dx%d (scale %dx)\n", w, h, plat->scale);
    return 0;
}

void platform_shutdown(Platform *plat)
{
    if (plat->tex_vga)  SDL_DestroyTexture((SDL_Texture *)plat->tex_vga);
    if (plat->tex_text) SDL_DestroyTexture((SDL_Texture *)plat->tex_text);
    if (plat->renderer) SDL_DestroyRenderer((SDL_Renderer *)plat->renderer);
    if (plat->window)   SDL_DestroyWindow((SDL_Window *)plat->window);
    SDL_Quit();
    printf("[SDL] Shutdown complete\n");
}

/* ─── Scancode translation (SDL -> DOS) ─── */

static uint8_t sdl_to_dos_scancode(SDL_Scancode sc)
{
    /* Map common keys to DOS scancodes */
    static const struct { SDL_Scancode sdl; uint8_t dos; } map[] = {
        {SDL_SCANCODE_ESCAPE, 0x01}, {SDL_SCANCODE_1, 0x02},
        {SDL_SCANCODE_2, 0x03}, {SDL_SCANCODE_3, 0x04},
        {SDL_SCANCODE_4, 0x05}, {SDL_SCANCODE_5, 0x06},
        {SDL_SCANCODE_6, 0x07}, {SDL_SCANCODE_7, 0x08},
        {SDL_SCANCODE_8, 0x09}, {SDL_SCANCODE_9, 0x0A},
        {SDL_SCANCODE_0, 0x0B}, {SDL_SCANCODE_MINUS, 0x0C},
        {SDL_SCANCODE_EQUALS, 0x0D}, {SDL_SCANCODE_BACKSPACE, 0x0E},
        {SDL_SCANCODE_TAB, 0x0F},
        {SDL_SCANCODE_Q, 0x10}, {SDL_SCANCODE_W, 0x11},
        {SDL_SCANCODE_E, 0x12}, {SDL_SCANCODE_R, 0x13},
        {SDL_SCANCODE_T, 0x14}, {SDL_SCANCODE_Y, 0x15},
        {SDL_SCANCODE_U, 0x16}, {SDL_SCANCODE_I, 0x17},
        {SDL_SCANCODE_O, 0x18}, {SDL_SCANCODE_P, 0x19},
        {SDL_SCANCODE_RETURN, 0x1C}, {SDL_SCANCODE_LCTRL, 0x1D},
        {SDL_SCANCODE_A, 0x1E}, {SDL_SCANCODE_S, 0x1F},
        {SDL_SCANCODE_D, 0x20}, {SDL_SCANCODE_F, 0x21},
        {SDL_SCANCODE_G, 0x22}, {SDL_SCANCODE_H, 0x23},
        {SDL_SCANCODE_J, 0x24}, {SDL_SCANCODE_K, 0x25},
        {SDL_SCANCODE_L, 0x26}, {SDL_SCANCODE_LSHIFT, 0x2A},
        {SDL_SCANCODE_Z, 0x2C}, {SDL_SCANCODE_X, 0x2D},
        {SDL_SCANCODE_C, 0x2E}, {SDL_SCANCODE_V, 0x2F},
        {SDL_SCANCODE_B, 0x30}, {SDL_SCANCODE_N, 0x31},
        {SDL_SCANCODE_M, 0x32}, {SDL_SCANCODE_RSHIFT, 0x36},
        {SDL_SCANCODE_LALT, 0x38}, {SDL_SCANCODE_SPACE, 0x39},
        {SDL_SCANCODE_F1, 0x3B}, {SDL_SCANCODE_F2, 0x3C},
        {SDL_SCANCODE_F3, 0x3D}, {SDL_SCANCODE_F4, 0x3E},
        {SDL_SCANCODE_F5, 0x3F}, {SDL_SCANCODE_F6, 0x40},
        {SDL_SCANCODE_F7, 0x41}, {SDL_SCANCODE_F8, 0x42},
        {SDL_SCANCODE_F9, 0x43}, {SDL_SCANCODE_F10, 0x44},
        {SDL_SCANCODE_UP, 0x48}, {SDL_SCANCODE_LEFT, 0x4B},
        {SDL_SCANCODE_RIGHT, 0x4D}, {SDL_SCANCODE_DOWN, 0x50},
    };

    for (int i = 0; i < (int)(sizeof(map)/sizeof(map[0])); i++) {
        if (map[i].sdl == sc) return map[i].dos;
    }
    return 0;
}

void platform_poll_events(Platform *plat, DosState *dos)
{
    SDL_Event e;
    while (SDL_PollEvent(&e)) {
        switch (e.type) {
        case SDL_QUIT:
            plat->running = 0;
            break;

        case SDL_KEYDOWN: {
            if (e.key.repeat) break;

            /* Alt+Enter = toggle fullscreen */
            if (e.key.keysym.sym == SDLK_RETURN &&
                (e.key.keysym.mod & KMOD_ALT)) {
                plat->fullscreen = !plat->fullscreen;
                SDL_SetWindowFullscreen((SDL_Window *)plat->window,
                    plat->fullscreen ? SDL_WINDOW_FULLSCREEN_DESKTOP : 0);
                break;
            }

            uint8_t sc = sdl_to_dos_scancode(e.key.keysym.scancode);
            uint8_t ascii = 0;
            if (e.key.keysym.sym >= 32 && e.key.keysym.sym < 127)
                ascii = (uint8_t)e.key.keysym.sym;
            else if (e.key.keysym.sym == SDLK_RETURN)
                ascii = 13;
            else if (e.key.keysym.sym == SDLK_ESCAPE)
                ascii = 27;
            else if (e.key.keysym.sym == SDLK_BACKSPACE)
                ascii = 8;

            if (sc || ascii)
                keyboard_push(&dos->keyboard, sc, ascii);
            break;
        }

        case SDL_MOUSEMOTION: {
            float fx, fy;
            SDL_RenderWindowToLogical((SDL_Renderer *)plat->renderer,
                e.motion.x, e.motion.y, &fx, &fy);
            mouse_update(&dos->mouse, (int)fx, (int)fy, dos->mouse.buttons);
            break;
        }

        case SDL_MOUSEBUTTONDOWN:
        case SDL_MOUSEBUTTONUP: {
            uint16_t btn = dos->mouse.buttons;
            uint16_t mask = 0;
            if (e.button.button == SDL_BUTTON_LEFT)   mask = 0x01;
            if (e.button.button == SDL_BUTTON_RIGHT)  mask = 0x02;
            if (e.button.button == SDL_BUTTON_MIDDLE) mask = 0x04;
            if (e.type == SDL_MOUSEBUTTONDOWN)
                btn |= mask;
            else
                btn &= ~mask;
            dos->mouse.buttons = btn;
            break;
        }
        }
    }
}

/* Render text mode (80x25 chars from 0xB8000) into 640x200 pixels.
 * Each character cell is 8 pixels wide × 8 pixels tall using the CP437 font. */
static void render_text_mode(const CPU *cpu, uint32_t *pixels, int pitch)
{
    const uint8_t *textbuf = cpu->mem + TEXT_MODE_BASE;

    for (int row = 0; row < TEXT_ROWS; row++) {
        for (int col = 0; col < TEXT_COLS; col++) {
            int cell = (row * TEXT_COLS + col) * 2;
            uint8_t ch   = textbuf[cell];
            uint8_t attr = textbuf[cell + 1];

            uint32_t fg = text_colors[attr & 0x0F];
            uint32_t bg = text_colors[(attr >> 4) & 0x07]; /* high bit = blink, ignore */

            const uint8_t *glyph = font8x8_cp437[ch];

            for (int gy = 0; gy < CHAR_H; gy++) {
                int py = row * CHAR_H + gy;
                uint32_t *prow = (uint32_t *)((uint8_t *)pixels + py * pitch);
                uint8_t bits = glyph[gy];
                for (int gx = 0; gx < 8; gx++) {
                    int px = col * 8 + gx;
                    prow[px] = (bits & (0x80 >> gx)) ? fg : bg;
                }
            }
        }
    }
}

void platform_render(Platform *plat, const CPU *cpu, const DosState *dos)
{
    SDL_Renderer *ren = (SDL_Renderer *)plat->renderer;

    /* Check video mode from BIOS data area */
    uint8_t vmode = cpu->mem[0x449]; /* 0040:0049 */
    int is_gfx = (vmode == 0x13);

    /* Switch logical size when mode changes */
    int mode_id = is_gfx ? 1 : 0;
    if (mode_id != plat->last_mode) {
        plat->last_mode = mode_id;
        if (is_gfx) {
            SDL_RenderSetLogicalSize(ren, VGA_WIDTH, VGA_HEIGHT);
        } else {
            SDL_RenderSetLogicalSize(ren, TEXT_COLS * 8, TEXT_ROWS * CHAR_H);
        }
    }

    SDL_Texture *tex;
    uint32_t *pixels;
    int pitch;

    if (is_gfx) {
        /* Mode 13h: 320x200x256 VGA */
        tex = (SDL_Texture *)plat->tex_vga;
        SDL_LockTexture(tex, NULL, (void **)&pixels, &pitch);

        uint32_t rgba[256];
        video_get_rgba_palette(&dos->video, rgba);

        const uint8_t *fb = cpu->mem + VGA_FB_ADDR;
        for (int y = 0; y < VGA_HEIGHT; y++) {
            uint32_t *row = (uint32_t *)((uint8_t *)pixels + y * pitch);
            for (int x = 0; x < VGA_WIDTH; x++) {
                row[x] = rgba[fb[y * VGA_WIDTH + x]];
            }
        }
    } else {
        /* Text mode (mode 3 or default): render from 0xB8000 */
        tex = (SDL_Texture *)plat->tex_text;
        SDL_LockTexture(tex, NULL, (void **)&pixels, &pitch);
        render_text_mode(cpu, pixels, pitch);
    }

    SDL_UnlockTexture(tex);

    SDL_RenderClear(ren);
    SDL_RenderCopy(ren, tex, NULL, NULL);
    SDL_RenderPresent(ren);
}

uint64_t platform_get_ticks(void)
{
    return SDL_GetTicks64();
}

void platform_delay(uint32_t ms)
{
    SDL_Delay(ms);
}

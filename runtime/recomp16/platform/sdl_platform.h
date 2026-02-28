/*
 * sdl_platform.h - SDL2 Platform Layer
 *
 * Provides the window, rendering, input polling, and audio output
 * that connects the HAL to the actual display/input hardware.
 *
 * Part of the Civ Recomp project (sp00nznet/civ)
 */

#ifndef CIV_SDL_PLATFORM_H
#define CIV_SDL_PLATFORM_H

#include "recomp/cpu.h"
#include "recomp/dos_compat.h"

#define WINDOW_SCALE 3  /* 320x200 * 3 = 960x600 */

typedef struct {
    void *window;       /* SDL_Window* */
    void *renderer;     /* SDL_Renderer* */
    void *tex_vga;      /* SDL_Texture* for VGA mode 13h (320x200) */
    void *tex_text;     /* SDL_Texture* for text mode (640x200) */
    int   scale;
    int   running;
    int   fullscreen;
    int   last_mode;    /* Track mode changes for texture switching */
} Platform;

/* Initialize SDL2 window and renderer */
int platform_init(Platform *plat, int scale);

/* Shut down SDL2 */
void platform_shutdown(Platform *plat);

/* Process SDL events (keyboard, mouse, window) */
void platform_poll_events(Platform *plat, DosState *dos);

/* Render VGA framebuffer to screen */
void platform_render(Platform *plat, const CPU *cpu, const DosState *dos);

/* Get current time in milliseconds */
uint64_t platform_get_ticks(void);

/* Delay for ms milliseconds */
void platform_delay(uint32_t ms);

#endif /* CIV_SDL_PLATFORM_H */

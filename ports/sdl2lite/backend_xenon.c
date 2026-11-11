/*
 * sdl2lite backend: Xbox 360 (libxenon). Writes the Xenos framebuffer
 * directly (32x32-tiled, the layout libxenon's console_pset uses, pixel
 * 0xBBGGRR00), at most 60 times a second. Sound: 48 kHz little-endian S16
 * stereo, resampled from the 44.1 kHz mixer on the main thread. Pad 1 over
 * USB: A jump, Start pause, Back restart, RB turbo; the Guide button quits.
 * Untested: there is no emulator for libxenon homebrew.
 */
#include "SDL.h"
#include <xetypes.h>
#include <xenos/xenos.h>
#include <xenon_sound/sound.h>
#include <input/input.h>
#include <usb/usbmain.h>
#include <ppc/timebase.h>
#include <ppc/cache.h>
#include <time/time.h>

struct ati_info { uint32_t unknown1[4]; uint32_t base; uint32_t unknown2[8]; uint32_t width, height; } __attribute__((__packed__));

static uint32_t *fb;
static int fbw, fbh, tiled_w;   /* tiled_w: width rounded up to 32 */

Uint32 lite_ticks(void) { return (Uint32)(mftb() / (PPC_TIMEBASE_FREQ / 1000)); }

int lite_video_init(int *w, int *h) {
    struct ati_info *ai = (struct ati_info *)0xec806100ULL;
    xenos_init(VIDEO_MODE_AUTO);
    fb = (uint32_t *)(long)(ai->base | 0x80000000);
    fbw = (int)ai->width; fbh = (int)ai->height;
    tiled_w = ((fbw + 31) >> 5) << 5;
    usb_init();
    *w = fbw; *h = fbh;
    return 0;
}

void lite_video_present(const Uint32 *px, int w, int h) {
    static Uint32 last;
    int x, y;
    if (lite_ticks() - last < 16 || w != fbw || h != fbh) return;
    last = lite_ticks();
    for (y = 0; y < h; y++) {
        const Uint32 *row = px + y * w;
        Uint32 ybase = (Uint32)((y >> 5) * 32 * tiled_w + ((y & 1) << 2) + (((y & 31) >> 1) << 6));
        for (x = 0; x < w; x++) {
            Uint32 p = row[x];
            Uint32 i = (ybase + ((x >> 5) << 10) + (x & 3) + (((x & 31) >> 2) << 3)) ^ ((y & 8) << 2);
            fb[i] = (p & 0xff) << 24 | (p & 0xff00) << 8 | (p & 0xff0000) >> 8;
        }
    }
    memdcbst(fb, tiled_w * (((fbh + 31) >> 5) << 5) * 4);
}

static int audio_ok;
static Uint64 made;   /* 48 kHz frames submitted */

int lite_audio_start(void) { xenon_sound_init(); audio_ok = 1; return 0; }

static void audio_pump(void) {
    static Sint16 in[2 * 260];
    static Uint16 out[2 * 256];
    if (!audio_ok) return;
    while (xenon_sound_get_free() >= (int)sizeof out) {
        Uint64 from = made * 44100 / 48000, to = (made + 256) * 44100 / 48000;
        int n = (int)(to - from), i;
        lite_audio_mix(in, n);
        for (i = 0; i < 256; i++) {
            int s = (int)((made + i) * 44100 / 48000 - from);
            if (s >= n) s = n - 1;
            out[i * 2] = __builtin_bswap16((Uint16)in[s * 2]);
            out[i * 2 + 1] = __builtin_bswap16((Uint16)in[s * 2 + 1]);
        }
        xenon_sound_submit(out, sizeof out);
        made += 256;
    }
}

void lite_sleep(Uint32 ms) { audio_pump(); mdelay(ms); }

void lite_poll(void) {
    struct controller_data_s pad;
    usb_do_poll();
    audio_pump();
    if (!get_controller_data(&pad, 0)) return;
    if (pad.logo) {
        SDL_Event e;
        memset(&e, 0, sizeof e);
        e.type = SDL_QUIT;
        lite_push_event(&e);
        return;
    }
    lite_pad((pad.a ? 1u << SDL_CONTROLLER_BUTTON_A : 0) |
             (pad.b ? 1u << SDL_CONTROLLER_BUTTON_B : 0) |
             (pad.x ? 1u << SDL_CONTROLLER_BUTTON_X : 0) |
             (pad.y ? 1u << SDL_CONTROLLER_BUTTON_Y : 0) |
             (pad.back ? 1u << SDL_CONTROLLER_BUTTON_BACK : 0) |
             (pad.start ? 1u << SDL_CONTROLLER_BUTTON_START : 0) |
             (pad.lb ? 1u << SDL_CONTROLLER_BUTTON_LEFTSHOULDER : 0) |
             (pad.rb ? 1u << SDL_CONTROLLER_BUTTON_RIGHTSHOULDER : 0) |
             (pad.up ? 1u << SDL_CONTROLLER_BUTTON_DPAD_UP : 0) |
             (pad.down ? 1u << SDL_CONTROLLER_BUTTON_DPAD_DOWN : 0) |
             (pad.left ? 1u << SDL_CONTROLLER_BUTTON_DPAD_LEFT : 0) |
             (pad.right ? 1u << SDL_CONTROLLER_BUTTON_DPAD_RIGHT : 0),
             pad.s1_x, (Sint16)(pad.s1_y == -32768 ? 32767 : -pad.s1_y));   /* XInput's y is up; SDL's is down */
}

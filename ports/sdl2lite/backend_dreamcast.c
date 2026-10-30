/*
 * sdl2lite backend: Sega Dreamcast (KallistiOS). 640x480 RGB565 framebuffer,
 * maple controller on port A, snd_stream at 44.1 kHz stereo (its callback runs
 * inside snd_stream_poll, on the main thread).
 * Pad: A jump, Start pause, Y restart, right trigger turbo; A+B+X+Y+Start quits.
 */
#include "SDL.h"
#include <kos.h>

KOS_INIT_FLAGS(INIT_DEFAULT);

static snd_stream_hnd_t snd = SND_STREAM_INVALID;
static Sint16 sndbuf[SND_STREAM_BUFFER_MAX / 2] __attribute__((aligned(32)));

Uint32 lite_ticks(void) { return (Uint32)timer_ms_gettime64(); }
void lite_sleep(Uint32 ms) {
    if (snd != SND_STREAM_INVALID) snd_stream_poll(snd);
    thd_sleep(ms);
}

int lite_video_init(int *w, int *h) {
    vid_set_mode(DM_640x480, PM_RGB565);
    *w = 640; *h = 480;
    return 0;
}

void lite_video_present(const Uint32 *px, int w, int h) {
    int i, n = w * h;
    vid_waitvbl();
    for (i = 0; i < n; i++) {
        Uint32 p = px[i];
        vram_s[i] = (Uint16)((p >> 8 & 0xf800) | (p >> 5 & 0x07e0) | (p >> 3 & 0x001f));
    }
}

static void *audio_cb(snd_stream_hnd_t hnd, int req, int *recv) {
    int frames = req / 4;
    (void)hnd;
    if (frames > SND_STREAM_BUFFER_MAX / 4) frames = SND_STREAM_BUFFER_MAX / 4;
    lite_audio_mix(sndbuf, frames);
    *recv = frames * 4;
    return sndbuf;
}

int lite_audio_start(void) {
    if (snd_stream_init() != 0) return -1;
    snd = snd_stream_alloc(audio_cb, SND_STREAM_BUFFER_MAX);
    if (snd == SND_STREAM_INVALID) return -1;
    snd_stream_start(snd, 44100, 1);
    return 0;
}

void lite_poll(void) {
    maple_device_t *dev = maple_enum_type(0, MAPLE_FUNC_CONTROLLER);
    cont_state_t *st = dev ? (cont_state_t *)maple_dev_status(dev) : NULL;
    if (snd != SND_STREAM_INVALID) snd_stream_poll(snd);
    if (!st) return;
    if ((st->buttons & CONT_RESET_BUTTONS) == CONT_RESET_BUTTONS) {
        SDL_Event e;
        memset(&e, 0, sizeof e);
        e.type = SDL_QUIT;
        lite_push_event(&e);
        return;
    }
    lite_pad((st->buttons & CONT_A ? 1u << SDL_CONTROLLER_BUTTON_A : 0) |
             (st->buttons & CONT_B ? 1u << SDL_CONTROLLER_BUTTON_B : 0) |
             (st->buttons & CONT_X ? 1u << SDL_CONTROLLER_BUTTON_X : 0) |
             (st->buttons & CONT_Y ? 1u << SDL_CONTROLLER_BUTTON_BACK : 0) |
             (st->buttons & CONT_START ? 1u << SDL_CONTROLLER_BUTTON_START : 0) |
             (st->buttons & CONT_DPAD_UP ? 1u << SDL_CONTROLLER_BUTTON_DPAD_UP : 0) |
             (st->buttons & CONT_DPAD_DOWN ? 1u << SDL_CONTROLLER_BUTTON_DPAD_DOWN : 0) |
             (st->buttons & CONT_DPAD_LEFT ? 1u << SDL_CONTROLLER_BUTTON_DPAD_LEFT : 0) |
             (st->buttons & CONT_DPAD_RIGHT ? 1u << SDL_CONTROLLER_BUTTON_DPAD_RIGHT : 0) |
             (st->rtrig > 128 ? 1u << SDL_CONTROLLER_BUTTON_RIGHTSHOULDER : 0),
             (Sint16)(st->joyx * 256), (Sint16)(st->joyy * 256));
}

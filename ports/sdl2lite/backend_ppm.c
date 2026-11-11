/*
 * sdl2lite test backend for a desktop (Linux): no window. Frames go to PPM
 * files at the times in $LITE_SHOTS (ms, comma-separated), a scripted pad
 * skis down and jumps, and the game quits at $LITE_QUIT ms (default 6000).
 * Screen size from $LITE_W/$LITE_H (default 640x480).
 */
#include "SDL.h"
#include <time.h>
#include <unistd.h>

static Uint32 t0;
static const char *shots;
static FILE *wav;

Uint32 lite_ticks(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (Uint32)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000) - t0;
}
void lite_sleep(Uint32 ms) { usleep(ms * 1000); }

int lite_video_init(int *w, int *h) {
    t0 = 0; t0 = lite_ticks();
    if (getenv("LITE_W")) *w = atoi(getenv("LITE_W"));
    if (getenv("LITE_H")) *h = atoi(getenv("LITE_H"));
    shots = getenv("LITE_SHOTS");
    return 0;
}

void lite_video_present(const Uint32 *px, int w, int h) {
    char name[64];
    FILE *f;
    int i, next;
    if (!shots || !*shots || lite_ticks() < (Uint32)(next = atoi(shots))) return;
    snprintf(name, sizeof name, "shot_%d.ppm", next);
    shots = strchr(shots, ',') ? strchr(shots, ',') + 1 : "";
    f = fopen(name, "wb");
    fprintf(f, "P6\n%d %d\n255\n", w, h);
    for (i = 0; i < w * h; i++) { fputc(px[i] >> 16 & 255, f); fputc(px[i] >> 8 & 255, f); fputc(px[i] & 255, f); }
    fclose(f);
    printf("[ppm] %s\n", name);
}

int lite_audio_start(void) { wav = fopen("audio.raw", "wb"); return 0; }   /* 44100 S16 stereo */

void lite_poll(void) {
    static Uint32 played;
    Uint32 t = lite_ticks(), quit = getenv("LITE_QUIT") ? (Uint32)atoi(getenv("LITE_QUIT")) : 6000;
    if (wav) {   /* mix in step with real time */
        Sint16 buf[2 * 512];
        while (played * 1000ull / 44100 < t) { lite_audio_mix(buf, 512); fwrite(buf, 4, 512, wav); played += 512; }
    }
    /* stick down from 1.5 s; A (jump) at 3 s */
    lite_pad(t >= 3000 && t < 3100 ? 1u << SDL_CONTROLLER_BUTTON_A : 0, 0, t >= 1500 ? 20000 : 0);
    if (t >= quit && wav) {   /* once */
        SDL_Event e;
        memset(&e, 0, sizeof e);
        e.type = SDL_QUIT;
        lite_push_event(&e);
        fclose(wav);
        wav = NULL;
    }
}

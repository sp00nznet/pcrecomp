/*
 * mss.c - the Miles Sound System's digital sound (AIL 3.x, DOS), answered by the host.
 *
 * A game links Miles in and Miles loads a card driver (SB16.DIG...) into real-mode memory and
 * calls it through int 66h: none of that runs here. So the AIL_API_ functions a game uses are
 * taken over (each game's run_lift.py OVERRIDES maps its addresses to the names below) and
 * the samples play on audio.c's mixer, straight out of guest memory. Above that line it is the
 * game's own code: which sound, when, how loud.
 *
 *   drivers   install_DIG_INI / _driver_file: one driver, always there
 *   samples   handles, address / type / rate / volume / pan / loop, start / stop / resume /
 *             end, status; file samples (WAV, VOC) parsed here
 *   streams   the double buffer: buffer_ready / load_sample_buffer, a voice's queued buffer
 *   callbacks EOS (end of sample) and EOF (a file sample's end), called on the guest thread
 *             from dos32_on_poll when a voice runs out, and at once by end_sample, as Miles does
 *
 * All AIL_API_ functions are cdecl. Handles are small blocks of guest memory (the program
 * holds and compares them); the state is here, with the status mirrored at +4 as Miles keeps it.
 */
#include "compat.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "recomp_types.h"
#include "dos32.h"
#include "audio.h"

#define M8(a)  (*(uint8_t*)dos32_mem(a))
#define M16(a) (*(uint16_t*)dos32_mem(a))
#define M32(a) (*(uint32_t*)dos32_mem(a))
#define ARG(n) M32(g_esp + 4 + 4 * (n))      /* cdecl: the return address is at esp */
static void ret(uint32_t v) { g_eax = v; g_esp += 4; }

enum { SMP_FREE = 1, SMP_DONE = 2, SMP_PLAYING = 4, SMP_STOPPED = 8 };
enum { F_16 = 1, F_STEREO = 2 };              /* DIG_F_ format bits */
enum { PCM_SIGN = 1 };                        /* DIG_PCM_SIGN */
#define NSMP 32

typedef struct {
    uint32_t va;                 /* the handle */
    int status;
    uint32_t addr, len;
    int format, flags, rate, vol, pan, loops;
    uint32_t eos, eob, eof;      /* guest callbacks */
    int file;                    /* a file sample: released at its end */
    uint32_t user[8];
    int voice;
    int stream, fifo[2], nfifo, last;   /* double buffer: the buffers queued, in play order */
    int ended;                   /* the voice ran out: callbacks due */
} smp_t;

static smp_t smp[NSMP];
static uint32_t dig_va;
uint32_t mss_default_volume_va;   /* the game's DIG_DEFAULT_VOLUME preference, if known */
int mss_log;

static smp_t* S_of(uint32_t va) {
    for (int i = 0; i < NSMP; i++) if (smp[i].va == va && va) return &smp[i];
    return NULL;
}
static void set_status(smp_t* s, int st) { s->status = st; M32(s->va + 4) = (uint32_t)st; }

static uint32_t the_driver(void) {
    if (!dig_va) {
        dig_va = dos32_heap_alloc(0x100);
        if (dig_va) memset(dos32_mem(dig_va), 0, 0x100);
    }
    return dig_va;
}

/* ---- drivers -------------------------------------------------------------------------- */

static void poll_samples(void);

/* AIL_install_DIG_INI(HDIGDRIVER *dig): AIL_INIT_SUCCESS. */
void mss_install_dig_ini(void (*lifted)(void)) {
    (void)lifted;
    uint32_t p = ARG(0), d = the_driver();
    if (p) M32(p) = d;
    audio_master(127);
    dos32_on_poll = poll_samples;
    fprintf(stderr, "[mss] digital driver installed (host mixer)\n");
    ret(d ? 0 : 2);
}

/* AIL_install_DIG_driver_file(name, IO_PARMS *): the driver. */
void mss_install_dig_file(void (*lifted)(void)) {
    (void)lifted;
    dos32_on_poll = poll_samples;
    ret(the_driver());
}

void mss_nop(void (*lifted)(void)) { (void)lifted; ret(0); }

/* ---- sample handles --------------------------------------------------------------------- */

static void reset(smp_t* s) {
    uint32_t va = s->va;
    if (s->voice) audio_stop(s->voice);
    memset(s, 0, sizeof *s);
    s->va = va;
    s->rate = 11025; s->pan = 64; s->loops = 1;
    s->vol = mss_default_volume_va ? (int)M32(mss_default_volume_va) : 100;
    s->last = 1;
    set_status(s, SMP_DONE);
}

static smp_t* alloc_sample(void) {
    smp_t* s = NULL;
    for (int i = 0; i < NSMP && !s; i++) if (smp[i].va && smp[i].status == SMP_FREE) s = &smp[i];
    for (int i = 0; i < NSMP && !s; i++) if (!smp[i].va) {
        smp[i].va = dos32_heap_alloc(0x40);
        if (!smp[i].va) return NULL;
        memset(dos32_mem(smp[i].va), 0, 0x40);
        M32(smp[i].va) = the_driver();
        s = &smp[i];
    }
    if (!s) { fprintf(stderr, "[mss] out of sample handles\n"); return NULL; }
    reset(s);
    return s;
}

void mss_allocate_sample(void (*lifted)(void)) { (void)lifted; smp_t* s = alloc_sample(); ret(s ? s->va : 0); }

void mss_release_sample(void (*lifted)(void)) {
    (void)lifted;
    smp_t* s = S_of(ARG(0));
    if (s) { if (s->voice) audio_stop(s->voice); s->voice = 0; s->ended = 0; set_status(s, SMP_FREE); }
    ret(0);
}

void mss_init_sample(void (*lifted)(void)) { (void)lifted; smp_t* s = S_of(ARG(0)); if (s) reset(s); ret(0); }

void mss_set_address(void (*lifted)(void)) {
    (void)lifted;
    smp_t* s = S_of(ARG(0));
    if (s) { s->addr = ARG(1); s->len = ARG(2); }
    ret(0);
}

void mss_set_type(void (*lifted)(void)) {
    (void)lifted;
    smp_t* s = S_of(ARG(0));
    if (s) { s->format = (int)ARG(1); s->flags = (int)ARG(2); }
    ret(0);
}

void mss_set_rate(void (*lifted)(void)) {
    (void)lifted;
    smp_t* s = S_of(ARG(0));
    if (s) { s->rate = (int)ARG(1); if (s->voice) audio_set(s->voice, -1, -1, s->rate); }
    ret(0);
}

void mss_set_volume(void (*lifted)(void)) {
    (void)lifted;
    smp_t* s = S_of(ARG(0));
    if (s) { s->vol = (int)ARG(1); if (s->voice) audio_set(s->voice, s->vol, -1, 0); }
    ret(0);
}

void mss_volume(void (*lifted)(void)) { (void)lifted; smp_t* s = S_of(ARG(0)); ret(s ? (uint32_t)s->vol : 0); }

void mss_set_pan(void (*lifted)(void)) {
    (void)lifted;
    smp_t* s = S_of(ARG(0));
    if (s) { s->pan = (int)ARG(1); if (s->voice) audio_set(s->voice, -1, s->pan, 0); }
    ret(0);
}

/* Miles' loop count: 0 for ever, n plays in all. */
static int repeats(int loops) { return loops == 0 ? -1 : loops - 1; }

void mss_set_loop_count(void (*lifted)(void)) {
    (void)lifted;
    smp_t* s = S_of(ARG(0));
    if (s) { s->loops = (int)ARG(1); if (s->voice) audio_loop(s->voice, repeats(s->loops)); }
    ret(0);
}

void mss_status(void (*lifted)(void)) { (void)lifted; smp_t* s = S_of(ARG(0)); ret(s ? (uint32_t)s->status : 0); }

void mss_active_count(void (*lifted)(void)) {
    (void)lifted;
    int n = 0;
    for (int i = 0; i < NSMP; i++) if (smp[i].va && smp[i].status == SMP_PLAYING) n++;
    ret((uint32_t)n);
}

static int play(smp_t* s, uint32_t addr, uint32_t len, int loops) {
    if (!addr || !len) return 0;
    return audio_play_ch(dos32_mem(addr), len, (s->format & F_16) ? 16 : 8,
                         (s->format & F_16) || (s->flags & PCM_SIGN), (s->format & F_STEREO) ? 2 : 1,
                         s->rate, s->vol, s->pan, loops);
}

void mss_start(void (*lifted)(void)) {
    (void)lifted;
    smp_t* s = S_of(ARG(0));
    if (s && s->status != SMP_FREE && !s->stream && s->addr && s->len) {   /* a stream starts as it loads */
        if (s->voice) audio_stop(s->voice);
        s->voice = play(s, s->addr, s->len, repeats(s->loops));
        s->ended = 0;
        set_status(s, SMP_PLAYING);
        if (mss_log) fprintf(stderr, "[mss] start %08X: %u bytes fmt %d rate %d vol %d -> voice %d\n",
                             s->va, s->len, s->format, s->rate, s->vol, s->voice);
        if (!s->voice) s->ended = 1;
    }
    ret(0);
}

void mss_stop(void (*lifted)(void)) {
    (void)lifted;
    smp_t* s = S_of(ARG(0));
    if (s && s->status == SMP_PLAYING) { if (s->voice) audio_pause(s->voice, 1); set_status(s, SMP_STOPPED); }
    ret(0);
}

void mss_resume(void (*lifted)(void)) {
    (void)lifted;
    smp_t* s = S_of(ARG(0));
    if (s && s->status == SMP_STOPPED) { if (s->voice) audio_pause(s->voice, 0); set_status(s, SMP_PLAYING); }
    ret(0);
}

/* The end: DONE, then the EOB and EOS callbacks, then a file sample's EOF and its release
 * (Miles' own end_sample and file-sample handler, in that order). */
static void finish(smp_t* s) {
    uint32_t va = s->va, a[1] = { va };
    if (s->voice) audio_stop(s->voice);
    s->voice = 0; s->ended = 0; s->nfifo = 0;
    set_status(s, SMP_DONE);
    if (s->eob) dos32_call(s->eob, 1, a);
    if (s->eos) dos32_call(s->eos, 1, a);
    if (s->file && s->status != SMP_FREE) {
        if (s->eof) dos32_call(s->eof, 1, a);
        set_status(s, SMP_FREE);
    }
}

void mss_end(void (*lifted)(void)) {
    (void)lifted;
    smp_t* s = S_of(ARG(0));
    if (s && s->status != SMP_FREE && s->status != SMP_DONE) finish(s);
    ret(0);
}

/* On the guest thread, where an interrupt could be taken: voices that ran out end now. */
static void poll_samples(void) {
    for (int i = 0; i < NSMP; i++) {
        smp_t* s = &smp[i];
        if (!s->va || s->status != SMP_PLAYING) continue;
        if (s->stream) continue;                       /* a stream ends when its loader stops */
        if (s->ended || !audio_playing(s->voice)) finish(s);
    }
}

/* ---- callbacks and user data ------------------------------------------------------------ */

static void set_cb(uint32_t* slot) { uint32_t old = *slot; *slot = ARG(1); ret(old); }
void mss_register_sob(void (*lifted)(void)) { (void)lifted; ret(0); }
void mss_register_eob(void (*lifted)(void)) { (void)lifted; smp_t* s = S_of(ARG(0)); if (s) set_cb(&s->eob); else ret(0); }
void mss_register_eos(void (*lifted)(void)) { (void)lifted; smp_t* s = S_of(ARG(0)); if (s) set_cb(&s->eos); else ret(0); }
void mss_register_eof(void (*lifted)(void)) { (void)lifted; smp_t* s = S_of(ARG(0)); if (s) set_cb(&s->eof); else ret(0); }

void mss_set_user_data(void (*lifted)(void)) {
    (void)lifted;
    smp_t* s = S_of(ARG(0));
    if (s && ARG(1) < 8) s->user[ARG(1)] = ARG(2);
    ret(0);
}

void mss_user_data(void (*lifted)(void)) {
    (void)lifted;
    smp_t* s = S_of(ARG(0));
    ret(s && ARG(1) < 8 ? s->user[ARG(1)] : 0);
}

/* ---- the double buffer ------------------------------------------------------------------- */

/* AIL_minimum_sample_buffer_size(dig, rate, format): 1/10 s, in whole kilobytes. */
void mss_min_buffer_size(void (*lifted)(void)) {
    (void)lifted;
    int rate = (int)ARG(1), fmt = (int)ARG(2);
    int bytes = rate / 10 * ((fmt & F_16) ? 2 : 1) * ((fmt & F_STEREO) ? 2 : 1);
    ret((uint32_t)((bytes + 1023) & ~1023));
}

/* Drop the buffers the voice has played through (all of them, once it has stopped). */
static void sync_fifo(smp_t* s) {
    if (!s->voice || !audio_playing(s->voice)) s->nfifo = 0;
    else if (s->nfifo == 2 && !audio_queued(s->voice)) { s->fifo[0] = s->fifo[1]; s->nfifo = 1; }
}

/* AIL_sample_buffer_ready(S): a buffer number to load, or -1 while both are queued. */
void mss_buffer_ready(void (*lifted)(void)) {
    (void)lifted;
    smp_t* s = S_of(ARG(0));
    int r = -1;
    if (s) {
        sync_fifo(s);
        if (s->nfifo < 2) r = s->nfifo ? s->fifo[0] ^ 1 : s->last ^ 1;
    }
    ret((uint32_t)r);
}

/* AIL_load_sample_buffer(S, n, buffer, len): queued after what plays; len 0 is the end. */
void mss_load_buffer(void (*lifted)(void)) {
    (void)lifted;
    smp_t* s = S_of(ARG(0));
    int n = (int)ARG(1) & 1;
    uint32_t buf = ARG(2), len = ARG(3);
    if (!s) { ret(0); return; }
    s->stream = 1;
    sync_fifo(s);
    if (!len) {                                   /* the stream's end: done when it has played */
        if (!s->nfifo) finish(s);
        else s->stream = 0, s->ended = 0;          /* poll_samples ends it with the voice */
        ret(0);
        return;
    }
    if (!s->nfifo) {
        s->voice = play(s, buf, len, 0);
        set_status(s, SMP_PLAYING);
    } else if (!audio_queue(s->voice, dos32_mem(buf), len)) {
        ret(0);                                    /* both queued: the program asked too soon */
        return;
    }
    s->fifo[s->nfifo++] = n;
    s->last = n;
    ret(0);
}

/* ---- file samples ------------------------------------------------------------------------ */

/* A .WAV or .VOC image in memory: its PCM, format and rate. 0 if it is neither. */
static int parse_file(smp_t* s, uint32_t img) {
    if (!memcmp(dos32_mem(img), "RIFF", 4) && !memcmp(dos32_mem(img + 8), "WAVE", 4)) {
        uint32_t end = img + 8 + M32(img + 4), p = img + 12;
        int ch = 1, bits = 8;
        while (p + 8 <= end) {
            uint32_t id = p, n = M32(p + 4);
            if (!memcmp(dos32_mem(id), "fmt ", 4)) {
                ch = M16(p + 10); s->rate = (int)M32(p + 12); bits = M16(p + 22);
            } else if (!memcmp(dos32_mem(id), "data", 4)) {
                s->addr = p + 8; s->len = n;
                s->format = (bits == 16 ? F_16 : 0) | (ch == 2 ? F_STEREO : 0);
                s->flags = bits == 16 ? PCM_SIGN : 0;
                return 1;
            }
            p += 8 + ((n + 1) & ~1u);
        }
        return 0;
    }
    if (!memcmp(dos32_mem(img), "Creative Voice File", 19)) {
        uint32_t p = img + M16(img + 0x14);
        for (int k = 0; k < 64 && M8(p); k++) {
            uint32_t n = M32(p + 1) & 0xFFFFFF;
            if (M8(p) == 1) {                      /* sound data: rate byte, codec 0 (8-bit) */
                s->rate = 1000000 / (256 - M8(p + 4));
                s->addr = p + 6; s->len = n - 2; s->format = 0; s->flags = 0;
                return 1;
            }
            if (M8(p) == 9) {                      /* new format: rate, bits, channels */
                s->rate = (int)M32(p + 4);
                s->format = (M8(p + 8) == 16 ? F_16 : 0) | (M8(p + 9) == 2 ? F_STEREO : 0);
                s->flags = M8(p + 8) == 16 ? PCM_SIGN : 0;
                s->addr = p + 16; s->len = n - 12;
                return 1;
            }
            p += 4 + n;                            /* ponytail: one data block; the rest skipped */
        }
    }
    return 0;
}

/* AIL_allocate_file_sample(dig, file_image, block): a handle set up to play it, released at
 * its end. */
void mss_allocate_file_sample(void (*lifted)(void)) {
    (void)lifted;
    uint32_t img = ARG(1);
    smp_t* s = alloc_sample();
    if (s && !parse_file(s, img)) {
        fprintf(stderr, "[mss] not a WAV or VOC image at %08X\n", img);
        set_status(s, SMP_FREE);
        s = NULL;
    }
    if (s) s->file = 1;
    ret(s ? s->va : 0);
}

/*
 * audio.c - the host's sound: a software mixer on waveOut, the 3DS's DSP or SDL audio.
 * Theme Park's (themepark-recomp/src/runtime/audio.c), with a queued next buffer per
 * voice for streams, pause, and the loop count set while playing.
 *
 * Voices play PCM straight out of guest memory, resampled to the output rate with linear
 * interpolation, with the game's volume and pan. The mix runs on the device's thread (a
 * waveOut feeder, the DSP's callback, SDL's audio thread); the game thread only flips voice
 * fields under a lock.
 *
 * ponytail: waveOut, not WASAPI: ~60 ms of latency, which these games do not notice.
 */
#include "compat.h"
#ifdef _WIN32
#include <mmsystem.h>
#elif defined(__3DS__)
#include <3ds.h>
#else
#include <SDL.h>
#endif
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "audio.h"

#define RATE    44100
#define BLOCK   1024              /* frames per block: 23 ms */
#define NBLOCK  4
#define NVOICE  32

typedef struct {
    const uint8_t* data;
    uint32_t len;                 /* in sample frames */
    const uint8_t* next;          /* queued: played when this one ends */
    uint32_t next_len;
    uint64_t pos_fx;              /* 48.16 */
    uint32_t step_fx;             /* 16.16 per output frame */
    int bits, is_signed, loop;    /* loop: repeats left, -1 forever */
    int ch;                       /* 1, or 2: interleaved stereo */
    int vol, pan;                 /* 0..127, 0..127 (64 = centre) */
    int paused;
    int id;                       /* 0 = free */
    void (*gen)(int16_t*, int, void*);   /* a synthesizer's voice: its frames, made as mixed */
    void* user;
} voice_t;

static voice_t voices[NVOICE];
static CRITICAL_SECTION lock;
static int next_id = 1;
static int master = 127;
static int live;                  /* a device is open and pulling the mix */
int audio_live(void) { return live; }

static int sample(const voice_t* v, uint32_t i) {
    if (v->bits == 16) return ((const int16_t*)v->data)[i];   /* i counts samples: frame * ch + channel */
    int s = v->data[i];
    return (v->is_signed ? (int8_t)s : s - 128) << 8;
}

static void mix(int16_t* out, int frames) {
    static int32_t acc[BLOCK * 2];
    memset(acc, 0, sizeof acc);
    EnterCriticalSection(&lock);
    for (int k = 0; k < NVOICE; k++) {
        voice_t* v = &voices[k];
        if (!v->id || v->paused) continue;
        if (v->gen) {
            static int16_t g[BLOCK * 2];
            v->gen(g, frames, v->user);
            for (int i = 0; i < frames * 2; i++) acc[i] += g[i] * v->vol / 127;
            continue;
        }
        int gl = v->vol * (127 - v->pan) / 64, gr = v->vol * v->pan / 64;   /* 0..254 each */
        if (gl > 127) gl = 127;
        if (gr > 127) gr = 127;
        for (int f = 0; f < frames; f++) {
            uint32_t i = (uint32_t)(v->pos_fx >> 16);
            if (i >= v->len) {
                if (v->next) {                       /* a stream's next buffer */
                    v->pos_fx -= (uint64_t)v->len << 16;
                    v->data = v->next; v->len = v->next_len; v->next = NULL;
                } else if (!v->loop) { v->id = 0; break; }
                else {
                    if (v->loop > 0) v->loop--;      /* -1 loops forever */
                    v->pos_fx -= (uint64_t)v->len << 16;
                }
                i = (uint32_t)(v->pos_fx >> 16);
                if (i >= v->len) { v->id = 0; break; }
            }
            int fr = (int)(v->pos_fx & 0xFFFF);
            for (int c = 0; c < v->ch; c++) {
                int a = sample(v, i * v->ch + c), b = i + 1 < v->len ? sample(v, (i + 1) * v->ch + c) : a;
                int s = a + (int)(((int64_t)(b - a) * fr) >> 16);
                if (v->ch == 1) { acc[f * 2] += s * gl / 127; acc[f * 2 + 1] += s * gr / 127; }
                else acc[f * 2 + c] += s * v->vol / 127;
            }
            v->pos_fx += v->step_fx;
        }
    }
    LeaveCriticalSection(&lock);
    for (int i = 0; i < frames * 2; i++) {
        int32_t s = acc[i] * master / 127;
        out[i] = (int16_t)(s > 32767 ? 32767 : s < -32768 ? -32768 : s);
    }
}

#ifdef _WIN32
static HWAVEOUT wo;
static WAVEHDR hdr[NBLOCK];
static int16_t buf[NBLOCK][BLOCK * 2];
static HANDLE ev;

static DWORD WINAPI feeder(LPVOID p) {
    (void)p;
    for (;;) {
        WaitForSingleObject(ev, INFINITE);
        for (int b = 0; b < NBLOCK; b++) {
            if (!(hdr[b].dwFlags & WHDR_DONE)) continue;
            mix(buf[b], BLOCK);
            hdr[b].dwFlags &= ~WHDR_DONE;
            waveOutWrite(wo, &hdr[b], sizeof hdr[b]);
        }
    }
    return 0;
}

int audio_init(int silent) {
    InitializeCriticalSection(&lock);
    if (silent) return 0;
    WAVEFORMATEX f = { WAVE_FORMAT_PCM, 2, RATE, RATE * 4, 4, 16, 0 };
    ev = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (waveOutOpen(&wo, WAVE_MAPPER, &f, (DWORD_PTR)ev, 0, CALLBACK_EVENT) != MMSYSERR_NOERROR) {
        fprintf(stderr, "[audio] no audio device: running silent\n");
        return 0;
    }
    for (int b = 0; b < NBLOCK; b++) {
        hdr[b].lpData = (LPSTR)buf[b];
        hdr[b].dwBufferLength = sizeof buf[b];
        waveOutPrepareHeader(wo, &hdr[b], sizeof hdr[b]);
        hdr[b].dwFlags |= WHDR_DONE;
    }
    CloseHandle(CreateThread(NULL, 0, feeder, NULL, 0, NULL));
    SetEvent(ev);
    return live = 1;
}
#elif defined(__3DS__)
/* The DSP plays NBLOCK buffers in turn on channel 0; its callback refills the ones done. */
static ndspWaveBuf wb[NBLOCK];
static int16_t* abuf;

static void refill(void* u) {
    (void)u;
    for (int b = 0; b < NBLOCK; b++) {
        if (wb[b].status != NDSP_WBUF_DONE && wb[b].status != NDSP_WBUF_FREE) continue;
        mix(wb[b].data_pcm16, BLOCK);
        DSP_FlushDataCache(wb[b].data_pcm16, BLOCK * 4);
        ndspChnWaveBufAdd(0, &wb[b]);
    }
}

int audio_init(int silent) {
    InitializeCriticalSection(&lock);
    if (silent) return 0;
    if (R_FAILED(ndspInit()) || !(abuf = linearAlloc(NBLOCK * BLOCK * 4))) {
        fprintf(stderr, "[audio] no DSP (dspfirm.cdc dumped?): running silent\n");
        return 0;
    }
    ndspSetOutputMode(NDSP_OUTPUT_STEREO);
    ndspChnSetInterp(0, NDSP_INTERP_LINEAR);
    ndspChnSetRate(0, RATE);
    ndspChnSetFormat(0, NDSP_FORMAT_STEREO_PCM16);
    memset(wb, 0, sizeof wb);
    for (int b = 0; b < NBLOCK; b++) { wb[b].data_pcm16 = abuf + b * BLOCK * 2; wb[b].nsamples = BLOCK; }
    ndspSetCallback(refill, NULL);
    refill(NULL);
    return live = 1;
}
#else
static void SDLCALL pull(void* u, Uint8* out, int bytes) {
    (void)u;
    audio_render((int16_t*)out, bytes / 4);
}

int audio_init(int silent) {
    InitializeCriticalSection(&lock);
    if (silent) return 0;
    SDL_AudioSpec want = { 0 }, got;
    want.freq = RATE; want.format = AUDIO_S16SYS; want.channels = 2; want.samples = BLOCK; want.callback = pull;
    SDL_AudioDeviceID dev;
    if (SDL_InitSubSystem(SDL_INIT_AUDIO) || !(dev = SDL_OpenAudioDevice(NULL, 0, &want, &got, 0))) {
        fprintf(stderr, "[audio] no audio device (%s): running silent\n", SDL_GetError());
        return 0;
    }
    SDL_PauseAudioDevice(dev, 0);
    return live = 1;
}
#endif

/* Silent runs mix on demand: the host pulls the time that has passed. */
void audio_render(int16_t* stereo, int frames) {
    while (frames > 0) {
        int n = frames > BLOCK ? BLOCK : frames;
        mix(stereo, n);
        stereo += n * 2;
        frames -= n;
    }
}

int audio_rate(void) { return RATE; }

int audio_play_ch(const void* data, uint32_t bytes, int bits, int is_signed, int ch, int rate,
                  int vol, int pan, int loop) {
    if (!data || !bytes || rate <= 0 || ch < 1 || ch > 2) return 0;
    EnterCriticalSection(&lock);
    int k = 0;
    for (; k < NVOICE && voices[k].id; k++) {}
    if (k == NVOICE) {   /* all busy: take the oldest sound (never a synthesizer) */
        int oldest = -1;
        for (int j = 0; j < NVOICE; j++)
            if (!voices[j].gen && (oldest < 0 || voices[j].id < voices[oldest].id)) oldest = j;
        k = oldest;
    }
    voice_t* v = &voices[k];
    memset(v, 0, sizeof *v);
    v->data = data;
    v->bits = bits;
    v->ch = ch;
    v->len = bytes / (bits == 16 ? 2 : 1) / ch;
    v->step_fx = (uint32_t)(((uint64_t)rate << 16) / RATE);
    v->is_signed = is_signed; v->loop = loop;
    v->vol = vol < 0 ? 0 : vol > 127 ? 127 : vol;
    v->pan = pan < 0 ? 0 : pan > 127 ? 127 : pan;
    v->id = next_id++;
    if (next_id <= 0) next_id = 1;
    int id = v->id;
    LeaveCriticalSection(&lock);
    return id;
}

int audio_play_gen(void (*gen)(int16_t* stereo, int frames, void* user), void* user, int vol) {
    if (!gen) return 0;
    EnterCriticalSection(&lock);
    int k = 0;
    for (; k < NVOICE && voices[k].id; k++) {}
    if (k == NVOICE) { LeaveCriticalSection(&lock); return 0; }   /* never in place of a sound */
    voice_t* v = &voices[k];
    memset(v, 0, sizeof *v);
    v->gen = gen; v->user = user;
    v->vol = vol < 0 ? 0 : vol > 127 ? 127 : vol;
    v->id = next_id++;
    if (next_id <= 0) next_id = 1;
    int id = v->id;
    LeaveCriticalSection(&lock);
    return id;
}

static voice_t* find(int id) {
    for (int k = 0; k < NVOICE; k++) if (voices[k].id == id && id) return &voices[k];
    return NULL;
}

int audio_queue(int id, const void* data, uint32_t bytes) {
    EnterCriticalSection(&lock);
    voice_t* v = find(id);
    int ok = v && !v->next;
    if (ok) { v->next = data; v->next_len = bytes / (v->bits == 16 ? 2 : 1) / v->ch; }
    LeaveCriticalSection(&lock);
    return ok;
}

int audio_queued(int id) {
    EnterCriticalSection(&lock);
    voice_t* v = find(id);
    int r = v && v->next;
    LeaveCriticalSection(&lock);
    return r;
}

void audio_stop(int id) {
    EnterCriticalSection(&lock);
    voice_t* v = find(id);
    if (v) v->id = 0;
    LeaveCriticalSection(&lock);
}

int audio_playing(int id) {
    EnterCriticalSection(&lock);
    int r = find(id) != NULL;
    LeaveCriticalSection(&lock);
    return r;
}

void audio_set(int id, int vol, int pan, int rate) {
    EnterCriticalSection(&lock);
    voice_t* v = find(id);
    if (v) {
        if (vol >= 0) v->vol = vol > 127 ? 127 : vol;
        if (pan >= 0) v->pan = pan > 127 ? 127 : pan;
        if (rate > 0) v->step_fx = (uint32_t)(((uint64_t)rate << 16) / RATE);
    }
    LeaveCriticalSection(&lock);
}

void audio_loop(int id, int loop) {
    EnterCriticalSection(&lock);
    voice_t* v = find(id);
    if (v) v->loop = loop;
    LeaveCriticalSection(&lock);
}

void audio_pause(int id, int paused) {
    EnterCriticalSection(&lock);
    voice_t* v = find(id);
    if (v) v->paused = paused;
    LeaveCriticalSection(&lock);
}

void audio_stop_all(void) {
    EnterCriticalSection(&lock);
    for (int k = 0; k < NVOICE; k++) voices[k].id = 0;
    LeaveCriticalSection(&lock);
}

void audio_master(int vol) { master = vol < 0 ? 0 : vol > 127 ? 127 : vol; }

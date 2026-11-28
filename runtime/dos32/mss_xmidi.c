/*
 * mss_xmidi.c - the Miles Sound System's music (AIL 3.x, DOS): XMIDI sequences, answered by the
 * host and played on an emulated OPL3.
 *
 * mss.c answers Miles' digital sound; this is its other half, the MDI drivers. A game with MIDI
 * music has Miles load one (ADLIB.MDI, SBPRO2.MDI, MPU401.MDI...) into real-mode memory, and
 * Miles' XMIDI sequencer runs on Miles' timer and sends it MIDI: none of that runs here. The
 * AIL_API_ functions the game calls are taken over instead (each game's run_lift.py OVERRIDES
 * maps its addresses to the names below) and the music is made here:
 *
 *   driver     install_MDI_driver_file / _INI: one driver, always there, whichever the game
 *              asked for. Its timbres are the game's Global Timbre Library, the file Miles
 *              loads for an FM card: AIL_set_GTL_filename_prefix's name (SAMPLE by default)
 *              with .AD, else .OPL
 *   sequences  handles; init (an XMIDI image's sequence n: its EVNT chunk, copied), start,
 *              stop, resume, end, status, volume (with Miles' fade over ms), loop count,
 *              the XMIDI master volume
 *   the music  XMIDI's 120 ticks a second: note durations, FOR/NEXT loops (controllers 116
 *              and 117), patch banks (114); MIDI on 18 two-operator OPL3 voices with the
 *              library's timbres (bank 127 is the drums, on channel 10, each at its own key)
 *
 * One mixer voice (audio_play_gen) makes the music as it is mixed, so a sequence runs in step
 * with what is heard and ends when it is heard to. Built with MSS_XMIDI_SILENT (no OPL3, so no
 * C++: the 3DS), sequences still run and end on time, with no sound.
 *
 * Not here yet: the sequence callbacks (EOS, trigger, beat, prefix), tempo, branches (RBRN),
 * channel locks and mapping, and the MIDI a game sends a driver itself.
 *
 * All AIL_API_ functions are cdecl. Handles are small blocks of guest memory (the program holds
 * and compares them); the state is here, with the status mirrored at +4 as Miles keeps it.
 */
#include "compat.h"
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "recomp_types.h"
#include "dos32.h"
#include "audio.h"
#ifndef MSS_XMIDI_SILENT
#include "opl3.h"
#endif

#define M8(a)  (*(uint8_t*)dos32_mem(a))
#define M32(a) (*(uint32_t*)dos32_mem(a))
#define ARG(n) M32(g_esp + 4 + 4 * (n))      /* cdecl: the return address is at esp */
static void ret(uint32_t v) { g_eax = v; g_esp += 4; }

enum { SEQ_FREE = 1, SEQ_DONE = 2, SEQ_PLAYING = 4, SEQ_STOPPED = 8 };
#define NSEQ   8
#define NVOICE 18
#define TICKS  120                            /* XMIDI's intervals: 1/120 s */

uint32_t mss_mdi_volume_va;                  /* the game's MDI_DEFAULT_VOLUME preference, if known */
extern int mss_log;                          /* mss.c */

/* ---- timbres: the Global Timbre Library --------------------------------------------------- */

/* A two-operator timbre as the GTL keeps it: the modulator's registers 20h 40h 60h 80h E0h,
 * C0h (feedback, connection), the carrier's 20h..E0h; and a transpose, which for a drum (bank
 * 127) is the key it sounds at. */
typedef struct { uint8_t m20, m40, m60, m80, me0, c0, c20, c40, c60, c80, ce0; int8_t transpose; } timbre_t;
static timbre_t* timbres;
static int16_t tix[128][128];                /* [bank][patch]: index + 1, 0 none */
static char gtl_prefix[128] = "SAMPLE";

/* The GTL: (patch, bank, offset) entries up to bank 0xFF, each timbre a length (14), the
 * transpose and the eleven register bytes. Four-operator timbres (length 25) are skipped. */
static int load_gtl(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t* d = malloc((size_t)n);
    if (!d || fread(d, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(d); return 0; }
    fclose(f);
    int count = 0;
    for (long i = 0; i + 6 <= n && d[i + 1] != 0xFF; i += 6) count++;
    timbres = calloc((size_t)count + 1, sizeof *timbres);
    memset(tix, 0, sizeof tix);
    int k = 0;
    for (long i = 0; i + 6 <= n && d[i + 1] != 0xFF && timbres; i += 6) {
        uint8_t patch = d[i], bank = d[i + 1];
        uint32_t off = d[i + 2] | d[i + 3] << 8 | (uint32_t)d[i + 4] << 16 | (uint32_t)d[i + 5] << 24;
        if (off + 14 > (uint32_t)n || (d[off] | d[off + 1] << 8) != 14 || patch > 127 || bank > 127) continue;
        const uint8_t* t = d + off + 2;
        timbre_t* x = &timbres[k];
        x->transpose = (int8_t)t[0];
        x->m20 = t[1]; x->m40 = t[2]; x->m60 = t[3]; x->m80 = t[4]; x->me0 = t[5]; x->c0 = t[6];
        x->c20 = t[7]; x->c40 = t[8]; x->c60 = t[9]; x->c80 = t[10]; x->ce0 = t[11];
        tix[bank][patch] = (int16_t)++k;
    }
    free(d);
    fprintf(stderr, "[mss] %d timbres from %s\n", k, path);
    return k;
}

/* With no library: one plain sustained tone for every melodic patch, and no drums. */
static const timbre_t plain = { 0x21, 0x1A, 0xF2, 0x24, 0, 0x0A, 0x21, 0x00, 0xF2, 0x26, 0, 0 };

static const timbre_t* timbre(int bank, int patch) {
    if (bank < 0 || bank > 127 || patch < 0 || patch > 127) return NULL;
    if (tix[bank][patch]) return &timbres[tix[bank][patch] - 1];
    if (bank != 127 && tix[0][patch]) return &timbres[tix[0][patch] - 1];   /* a bank's missing patch: bank 0's */
    return bank == 127 || timbres ? NULL : &plain;
}

/* ---- the sequences ---------------------------------------------------------------------------- */

typedef struct {
    uint32_t va;                 /* the handle */
    int status;
    uint8_t* evnt;               /* the sequence's events (its EVNT chunk, copied) */
    uint32_t len, pos;
    int32_t wait;                /* ticks until the event at pos */
    int loops, plays;            /* Miles' loop count (0 for ever, n plays in all), plays so far */
    struct { uint32_t pos; int count; } fors[4];
    int nfor;
    double vol, vol_to, vol_step;   /* 0..127, and a fade's target and step per tick */
    uint8_t prog[16], bank[16], next_bank[16], chv[16], expr[16], pan[16], sus[16], rpn[16][2], range[16];
    int bend[16];                /* -8192..8191 */
} seq_t;

static seq_t seqs[NSEQ];
static CRITICAL_SECTION lock;    /* the sequences and voices: the guest's calls and the mixer's thread */
static uint32_t mdi_va;
static int master = 127, gen_voice;

static seq_t* S_of(uint32_t va) {
    for (int i = 0; i < NSEQ; i++) if (seqs[i].va == va && va) return &seqs[i];
    return NULL;
}
static void set_status(seq_t* s, int st) { s->status = st; M32(s->va + 4) = (uint32_t)st; }

/* ---- the OPL3's voices ------------------------------------------------------------------------- */

#ifdef MSS_XMIDI_SILENT
#define opl3_write(r, v) ((void)0)
#endif

typedef struct {
    int on;                      /* the key is down */
    seq_t* s;                    /* whose note: the sequence, its channel and the note as sent */
    int ch, note, vel, key;      /* key: what sounds (after the timbre's transpose) */
    const timbre_t* t;
    int32_t off_in;              /* ticks to its note-off (XMIDI gives each note its length) */
    int held;                    /* off, but held by the sustain pedal */
    uint32_t stamp;              /* when it last went on or off */
    int b0;                      /* its last B0h: the block and high F-number bits */
} voice_t;

static voice_t vc[NVOICE];
static uint32_t now_tick;
static int chip_rate = 49716;
static uint8_t att[128];         /* 0..127 as an attenuation in the OPL's 0.75 dB steps */
static const uint8_t opoff[9] = { 0, 1, 2, 8, 9, 10, 16, 17, 18 };

static int base(int v) { return v >= 9 ? 0x100 : 0; }

/* The level: velocity, channel volume and expression, the sequence's and the master volume,
 * each as MIDI's 40 log10(x/127) dB, taken off the carrier's level (and the modulator's too
 * when both are heard, connection 1). */
static void voice_level(int v) {
    voice_t* x = &vc[v];
    seq_t* s = x->s;
    int c = v % 9, b = base(v), add = att[x->vel] + att[s->chv[x->ch]] + att[s->expr[x->ch]] +
        att[(int)(s->vol + 0.5)] + att[master];
    int car = (x->t->c40 & 63) + add, mod = (x->t->m40 & 63) + ((x->t->c0 & 1) ? add : 0);
    opl3_write(b + 0x43 + opoff[c], (x->t->c40 & 0xC0) | (car > 63 ? 63 : car));
    opl3_write(b + 0x40 + opoff[c], (x->t->m40 & 0xC0) | (mod > 63 ? 63 : mod));
}

/* The key plus the channel's bend, as an F-number and block: f = fnum * rate / 2^(20 - block). */
static void voice_pitch(int v, int keyon) {
    voice_t* x = &vc[v];
    seq_t* s = x->s;
    double semis = x->key - 69 + s->bend[x->ch] / 8192.0 * s->range[x->ch];
    double fn = 440.0 * pow(2.0, semis / 12.0) * 1048576.0 / chip_rate;
    int block = 0;
    while (fn >= 1023.5 && block < 7) { fn /= 2; block++; }
    int fnum = fn > 1023 ? 1023 : (int)(fn + 0.5);
    x->b0 = block << 2 | fnum >> 8;
    opl3_write(base(v) + 0xA0 + v % 9, fnum & 0xFF);
    opl3_write(base(v) + 0xB0 + v % 9, (keyon ? 0x20 : 0) | x->b0);
}

static void voice_off(int v) {
    if (!vc[v].on) return;
    vc[v].on = 0; vc[v].held = 0; vc[v].stamp = now_tick;
    opl3_write(base(v) + 0xB0 + v % 9, vc[v].b0);
}

/* A free voice, the one let go of longest ago; else the oldest note, cut short. */
static int alloc_voice(void) {
    int best = -1;
    for (int v = 0; v < NVOICE; v++)
        if (!vc[v].on && (best < 0 || vc[v].stamp < vc[best].stamp)) best = v;
    if (best >= 0) return best;
    for (int v = 0; v < NVOICE; v++) if (best < 0 || vc[v].stamp < vc[best].stamp) best = v;
    voice_off(best);
    return best;
}

static void note_on(seq_t* s, int ch, int note, int vel, uint32_t dur) {
    const timbre_t* t = ch == 9 ? timbre(127, note) : timbre(s->bank[ch], s->prog[ch]);
    if (!t) return;                           /* no timbre: Miles plays nothing */
    int v = alloc_voice(), b = base(v), c = v % 9, m = opoff[c];
    int pan = s->pan[ch] < 32 ? 0x10 : s->pan[ch] > 96 ? 0x20 : 0x30;   /* the OPL3's left, right or both */
    voice_t* x = &vc[v];
    x->on = 1; x->held = 0; x->s = s; x->ch = ch; x->note = note; x->vel = vel; x->t = t;
    x->key = ch == 9 ? t->transpose : note + t->transpose;
    x->off_in = dur ? (int32_t)dur : 1;
    x->stamp = now_tick;
    opl3_write(b + 0x20 + m, t->m20); opl3_write(b + 0x60 + m, t->m60);
    opl3_write(b + 0x80 + m, t->m80); opl3_write(b + 0xE0 + m, t->me0 & 7);
    opl3_write(b + 0x23 + m, t->c20); opl3_write(b + 0x63 + m, t->c60);
    opl3_write(b + 0x83 + m, t->c80); opl3_write(b + 0xE3 + m, t->ce0 & 7);
    opl3_write(b + 0xC0 + c, (t->c0 & 0x0F) | pan);
    voice_level(v);
    voice_pitch(v, 1);
}

static void notes_off(seq_t* s, int ch) {     /* ch -1: all of the sequence's */
    for (int v = 0; v < NVOICE; v++) if (vc[v].on && vc[v].s == s && (ch < 0 || vc[v].ch == ch)) voice_off(v);
}

static void channel_levels(seq_t* s, int ch) {
    for (int v = 0; v < NVOICE; v++) if (vc[v].on && vc[v].s == s && (ch < 0 || vc[v].ch == ch)) voice_level(v);
}

/* ---- the events ------------------------------------------------------------------------------ */

static uint8_t rd(seq_t* s) { return s->pos < s->len ? s->evnt[s->pos++] : 0; }
static uint32_t vlq(seq_t* s) {
    uint32_t v = 0;
    for (int i = 0; i < 4 && s->pos < s->len; i++) {
        uint8_t b = s->evnt[s->pos++];
        v = v << 7 | (b & 0x7F);
        if (!(b & 0x80)) break;
    }
    return v;
}

static void reset_channels(seq_t* s) {
    for (int ch = 0; ch < 16; ch++) {
        s->prog[ch] = 0; s->bank[ch] = s->next_bank[ch] = 0; s->chv[ch] = 100; s->expr[ch] = 127;
        s->pan[ch] = 64; s->sus[ch] = 0; s->bend[ch] = 0; s->range[ch] = 2;
        s->rpn[ch][0] = s->rpn[ch][1] = 127;
    }
}

static void controller(seq_t* s, int ch, int c, int v) {
    switch (c) {
    case 7: s->chv[ch] = (uint8_t)v; channel_levels(s, ch); break;
    case 11: s->expr[ch] = (uint8_t)v; channel_levels(s, ch); break;
    case 10: s->pan[ch] = (uint8_t)v; break;
    case 64:
        s->sus[ch] = v >= 64;
        if (!s->sus[ch]) for (int k = 0; k < NVOICE; k++) if (vc[k].on && vc[k].held && vc[k].s == s && vc[k].ch == ch) voice_off(k);
        break;
    case 100: case 101: s->rpn[ch][c - 100] = (uint8_t)v; break;
    case 6: if (!s->rpn[ch][0] && !s->rpn[ch][1]) s->range[ch] = (uint8_t)v; break;   /* RPN 0: the bend range */
    case 114: s->next_bank[ch] = (uint8_t)v; break;      /* XMIDI: the bank of the next patch */
    case 116:                                            /* FOR: the loop's start, its count (0: for ever) */
        if (s->nfor < 4) { s->fors[s->nfor].pos = s->pos; s->fors[s->nfor].count = v; s->nfor++; }
        break;
    case 117:                                            /* NEXT (64 and up) or BREAK */
        if (!s->nfor) break;
        if (v < 64) { s->nfor--; break; }
        if (s->fors[s->nfor - 1].count == 0 || --s->fors[s->nfor - 1].count > 0) s->pos = s->fors[s->nfor - 1].pos;
        else s->nfor--;
        break;
    case 121: s->chv[ch] = 100; s->expr[ch] = 127; s->sus[ch] = 0; s->bend[ch] = 0; break;
    case 120: case 123: notes_off(s, ch); break;
    }
}

static void restart(seq_t* s) { s->pos = 0; s->wait = 0; s->nfor = 0; }

/* The end of the events: another play when the loop count says so, else done. */
static void sequence_end(seq_t* s) {
    notes_off(s, -1);
    if (s->loops == 0 || ++s->plays < s->loops) { restart(s); return; }
    s->status = SEQ_DONE;                    /* mirrored at +4 on the guest's next call */
}

static void event(seq_t* s, uint8_t st) {
    int ch = st & 15;
    switch (st >> 4) {
    case 0x8: { int n = rd(s); rd(s);
        for (int v = 0; v < NVOICE; v++) if (vc[v].on && vc[v].s == s && vc[v].ch == ch && vc[v].note == n) vc[v].off_in = 0;
        break; }
    case 0x9: { int n = rd(s), vel = rd(s); uint32_t d = vlq(s); if (vel) note_on(s, ch, n & 127, vel & 127, d); break; }
    case 0xA: rd(s); rd(s); break;
    case 0xB: { int c = rd(s); controller(s, ch, c, rd(s) & 127); break; }
    case 0xC: s->prog[ch] = rd(s) & 127; s->bank[ch] = s->next_bank[ch]; break;
    case 0xD: rd(s); break;
    case 0xE: { int lo = rd(s), hi = rd(s); s->bend[ch] = ((hi & 127) << 7 | (lo & 127)) - 8192;
        for (int v = 0; v < NVOICE; v++) if (vc[v].on && vc[v].s == s && vc[v].ch == ch) voice_pitch(v, 1);
        break; }
    default:
        if (st == 0xFF) {                    /* meta: 2Fh is the end */
            int type = rd(s);
            uint32_t n = vlq(s);
            if (type == 0x2F) { s->pos = s->len; break; }
            s->pos = s->pos + n < s->len ? s->pos + n : s->len;
        } else if (st == 0xF0 || st == 0xF7) { uint32_t n = vlq(s); s->pos = s->pos + n < s->len ? s->pos + n : s->len; }
        break;
    }
}

/* One tick of a playing sequence: its fade, then what is due. An interval is a run of bytes
 * under 80h, added up. */
static void sequence_tick(seq_t* s) {
    if (s->vol_step != 0) {
        s->vol += s->vol_step;
        if ((s->vol_step > 0) == (s->vol >= s->vol_to)) { s->vol = s->vol_to; s->vol_step = 0; }
        channel_levels(s, -1);
    }
    if (s->wait > 0) s->wait--;
    for (int guard = 0; s->wait <= 0 && s->status == SEQ_PLAYING && guard < 4096; guard++) {
        if (s->pos >= s->len) { sequence_end(s); if (s->status != SEQ_PLAYING || s->len == 0) break; continue; }
        uint8_t b = s->evnt[s->pos];
        if (b < 0x80) { while (s->pos < s->len && s->evnt[s->pos] < 0x80) s->wait += s->evnt[s->pos++]; continue; }
        s->pos++;
        event(s, b);
    }
}

static void tick(void) {
    now_tick++;
    for (int v = 0; v < NVOICE; v++)          /* the notes whose time is up */
        if (vc[v].on && !vc[v].held && vc[v].s->status == SEQ_PLAYING && --vc[v].off_in <= 0) {
            if (vc[v].s->sus[vc[v].ch]) vc[v].held = 1;
            else voice_off(v);
        }
    for (int i = 0; i < NSEQ; i++) if (seqs[i].va && seqs[i].status == SEQ_PLAYING) sequence_tick(&seqs[i]);
}

/* The mixer's voice: ticks at 120 a second of output, the chip at its own rate, taken to the
 * output's by linear interpolation. */
static void render(int16_t* out, int frames, void* user) {
    static uint32_t tick_acc, phase;
    static int a[2], b[2];
    int rate = audio_rate();
    (void)user;
    EnterCriticalSection(&lock);
    for (int f = 0; f < frames; f++) {
        if ((tick_acc += TICKS) >= (uint32_t)rate) { tick_acc -= rate; tick(); }
#ifdef MSS_XMIDI_SILENT
        out[f * 2] = out[f * 2 + 1] = 0;
        (void)phase; (void)a; (void)b;
#else
        for (phase += chip_rate; phase >= (uint32_t)rate; phase -= rate) {
            a[0] = b[0]; a[1] = b[1];
            opl3_frame(&b[0], &b[1]);
        }
        for (int c = 0; c < 2; c++) {
            int s = a[c] + (int)((int64_t)(b[c] - a[c]) * phase / rate);
            out[f * 2 + c] = (int16_t)(s > 32767 ? 32767 : s < -32768 ? -32768 : s);
        }
#endif
    }
    LeaveCriticalSection(&lock);
}

/* ---- the driver -------------------------------------------------------------------------- */

static uint32_t install(void) {
    if (mdi_va) return mdi_va;
    mdi_va = dos32_heap_alloc(0x100);
    if (!mdi_va) return 0;
    memset(dos32_mem(mdi_va), 0, 0x100);
    InitializeCriticalSection(&lock);
    for (int i = 0; i < 128; i++) {
        double d = i ? -40.0 * log10(i / 127.0) / 0.75 : 63;
        att[i] = (uint8_t)(d > 63 ? 63 : d + 0.5);
    }
    char dos[160], path[MAX_PATH];
    snprintf(dos, sizeof dos, "%s.AD", gtl_prefix);
    dos32_host_path(dos, path, sizeof path);
    if (!load_gtl(path)) {
        snprintf(dos, sizeof dos, "%s.OPL", gtl_prefix);
        dos32_host_path(dos, path, sizeof path);
        if (!load_gtl(path)) fprintf(stderr, "[mss] no timbre library %s.AD or .OPL: a plain tone for every patch\n", gtl_prefix);
    }
#ifndef MSS_XMIDI_SILENT
    chip_rate = opl3_init();
    opl3_write(0x105, 0x01);                  /* OPL3 */
    opl3_write(0x104, 0x00);                  /* every channel two-operator */
    opl3_write(0x001, 0x20);
    opl3_write(0x0BD, 0x00);                  /* melodic, no rhythm section */
#endif
    gen_voice = audio_play_gen(render, NULL, 127);
    fprintf(stderr, "[mss] MIDI driver installed (XMIDI on an OPL3%s)\n",
#ifdef MSS_XMIDI_SILENT
            ", silent"
#else
            ""
#endif
    );
    return mdi_va;
}

/* AIL_install_MDI_driver_file(name, IO_PARMS*), AIL_install_MDI_INI(MDI_DRIVER**): whichever
 * card was named, the host's. */
void mss_install_mdi_file(void (*lifted)(void)) { (void)lifted; ret(install()); }
void mss_install_mdi_ini(void (*lifted)(void)) {
    (void)lifted;
    uint32_t p = ARG(0), d = install();
    if (p) M32(p) = d;
    ret(d ? 0 : 2);                           /* AIL_INIT_SUCCESS, else AIL_NO_INI_FILE */
}

/* AIL_set_GTL_filename_prefix(name): where install looks for the timbres. */
void mss_set_gtl_prefix(void (*lifted)(void)) {
    (void)lifted;
    uint32_t p = ARG(0);
    size_t i = 0;
    for (; p && i + 1 < sizeof gtl_prefix && M8(p + i); i++) gtl_prefix[i] = (char)M8(p + i);
    if (p) gtl_prefix[i] = 0;
    ret(0);
}

/* AIL_set_XMIDI_master_volume(mdi, volume) */
void mss_set_xmidi_master_volume(void (*lifted)(void)) {
    (void)lifted;
    if (!mdi_va) { ret(0); return; }
    EnterCriticalSection(&lock);
    master = (int)ARG(1) < 0 ? 0 : (int)ARG(1) > 127 ? 127 : (int)ARG(1);
    for (int i = 0; i < NSEQ; i++) if (seqs[i].va) channel_levels(&seqs[i], -1);
    LeaveCriticalSection(&lock);
    ret(0);
}

/* ---- sequence handles -------------------------------------------------------------------- */

/* AIL_allocate_sequence_handle(mdi): a handle, once a driver is installed (the lock is its). */
void mss_allocate_sequence(void (*lifted)(void)) {
    (void)lifted;
    seq_t* s = NULL;
    if (!mdi_va) { ret(0); return; }
    for (int i = 0; i < NSEQ && !s; i++) if (seqs[i].va && seqs[i].status == SEQ_FREE) s = &seqs[i];
    for (int i = 0; i < NSEQ && !s; i++) if (!seqs[i].va && (seqs[i].va = dos32_heap_alloc(0x100))) {
        memset(dos32_mem(seqs[i].va), 0, 0x100);
        M32(seqs[i].va) = mdi_va;
        s = &seqs[i];
    }
    if (s) set_status(s, SEQ_DONE);
    else fprintf(stderr, "[mss] out of sequence handles\n");
    ret(s ? s->va : 0);
}

void mss_release_sequence(void (*lifted)(void)) {
    (void)lifted;
    seq_t* s = S_of(ARG(0));
    if (s) { EnterCriticalSection(&lock); notes_off(s, -1); set_status(s, SEQ_FREE); LeaveCriticalSection(&lock); }
    ret(0);
}

static const uint8_t* chunk(const uint8_t* p, const uint8_t* end, const char* id, uint32_t* n) {
    while (p + 8 <= end) {
        uint32_t len = (uint32_t)p[4] << 24 | p[5] << 16 | p[6] << 8 | p[7];
        if (!memcmp(p, id, 4)) { *n = len; return p + 8; }
        p += 8 + ((len + 1) & ~1u);
    }
    return NULL;
}

/* AIL_init_sequence(S, start, sequence_num): sequence n of the XMIDI image at start (a FORM
 * XDIR and a CAT of FORM XMIDs, or one FORM XMID), ready to start. 1, or 0 if it has none. */
void mss_init_sequence(void (*lifted)(void)) {
    (void)lifted;
    seq_t* s = S_of(ARG(0));
    const uint8_t* p = ARG(1) ? dos32_mem(ARG(1)) : NULL;
    int n = (int)ARG(2);
    if (!s || !p) { ret(0); return; }
    uint32_t len;
    const uint8_t *form = NULL, *end;
    if (!memcmp(p, "FORM", 4) && !memcmp(p + 8, "XDIR", 4))
        p += 8 + ((((uint32_t)p[4] << 24 | p[5] << 16 | p[6] << 8 | p[7]) + 1) & ~1u);
    if (!memcmp(p, "CAT ", 4) && !memcmp(p + 8, "XMID", 4)) {
        end = p + 8 + ((uint32_t)p[4] << 24 | p[5] << 16 | p[6] << 8 | p[7]);
        for (p += 12; p + 12 <= end; p += 8 + ((len + 1) & ~1u)) {
            len = (uint32_t)p[4] << 24 | p[5] << 16 | p[6] << 8 | p[7];
            if (!memcmp(p, "FORM", 4) && !memcmp(p + 8, "XMID", 4) && n-- == 0) { form = p; break; }
        }
    } else if (!memcmp(p, "FORM", 4) && !memcmp(p + 8, "XMID", 4) && n == 0) form = p;
    const uint8_t* ev = NULL;
    if (form) {
        len = (uint32_t)form[4] << 24 | form[5] << 16 | form[6] << 8 | form[7];
        ev = chunk(form + 12, form + 8 + len, "EVNT", &len);
    }
    if (!ev) { fprintf(stderr, "[mss] no sequence %d in the XMIDI at %08X\n", (int)ARG(2), ARG(1)); ret(0); return; }
    uint8_t* copy = malloc(len ? len : 1);
    if (!copy) { ret(0); return; }
    memcpy(copy, ev, len);
    EnterCriticalSection(&lock);
    notes_off(s, -1);
    free(s->evnt);
    s->evnt = copy; s->len = len;
    restart(s);
    reset_channels(s);
    s->loops = 1; s->plays = 0;
    s->vol = s->vol_to = mss_mdi_volume_va ? (int)M32(mss_mdi_volume_va) : 127;
    s->vol_step = 0;
    set_status(s, SEQ_DONE);                  /* ready to start, as Miles leaves it */
    LeaveCriticalSection(&lock);
    if (mss_log) fprintf(stderr, "[mss] sequence %08X: %u bytes of events, volume %d\n", s->va, len, (int)s->vol);
    ret(1);
}

/* ---- playing ------------------------------------------------------------------------------ */

void mss_start_sequence(void (*lifted)(void)) {
    (void)lifted;
    seq_t* s = S_of(ARG(0));
    if (s && s->evnt && s->status != SEQ_FREE) {
        EnterCriticalSection(&lock);
        notes_off(s, -1);
        restart(s);
        s->plays = 0;
        set_status(s, SEQ_PLAYING);
        LeaveCriticalSection(&lock);
    }
    ret(0);
}

void mss_stop_sequence(void (*lifted)(void)) {
    (void)lifted;
    seq_t* s = S_of(ARG(0));
    if (s && s->status == SEQ_PLAYING) {
        EnterCriticalSection(&lock); notes_off(s, -1); set_status(s, SEQ_STOPPED); LeaveCriticalSection(&lock);
    }
    ret(0);
}

void mss_resume_sequence(void (*lifted)(void)) {
    (void)lifted;
    seq_t* s = S_of(ARG(0));
    if (s && s->status == SEQ_STOPPED && s->evnt) { EnterCriticalSection(&lock); set_status(s, SEQ_PLAYING); LeaveCriticalSection(&lock); }
    ret(0);
}

void mss_end_sequence(void (*lifted)(void)) {
    (void)lifted;
    seq_t* s = S_of(ARG(0));
    if (s && s->status != SEQ_FREE) {
        EnterCriticalSection(&lock); notes_off(s, -1); set_status(s, SEQ_DONE); LeaveCriticalSection(&lock);
    }
    ret(0);
}

void mss_sequence_status(void (*lifted)(void)) {
    (void)lifted;
    seq_t* s = S_of(ARG(0));
    if (s) set_status(s, s->status);          /* a sequence that ended while mixed: +4 catches up */
    ret(s ? (uint32_t)s->status : 0);
}

/* AIL_set_sequence_volume(S, volume, ms): there in ms (a fade), at once for 0. */
void mss_set_sequence_volume(void (*lifted)(void)) {
    (void)lifted;
    seq_t* s = S_of(ARG(0));
    int v = (int)ARG(1), ms = (int)ARG(2);
    if (s) {
        v = v < 0 ? 0 : v > 127 ? 127 : v;
        EnterCriticalSection(&lock);
        s->vol_to = v;
        s->vol_step = ms > 0 ? (v - s->vol) * 1000.0 / ((double)ms * TICKS) : 0;
        if (s->vol_step == 0) { s->vol = v; channel_levels(s, -1); }
        LeaveCriticalSection(&lock);
    }
    ret(0);
}

void mss_sequence_volume(void (*lifted)(void)) { (void)lifted; seq_t* s = S_of(ARG(0)); ret(s ? (uint32_t)(s->vol + 0.5) : 0); }

/* AIL_set_sequence_loop_count(S, n): 0 for ever, n plays in all. */
void mss_set_sequence_loop_count(void (*lifted)(void)) {
    (void)lifted;
    seq_t* s = S_of(ARG(0));
    if (s) { EnterCriticalSection(&lock); s->loops = (int)ARG(1); LeaveCriticalSection(&lock); }
    ret(0);
}

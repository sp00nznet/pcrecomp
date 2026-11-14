/* mmsystem.c - MMSYSTEM.DLL for a game that loads it at run time.
 *
 * Win 3.0 had no multimedia; a game that wanted it on 3.1 checked for
 * MMSYSTEM.DLL, loaded it with LoadLibrary and took each entry point with
 * GetProcAddress. SimAnt does exactly that (_CheckMMWave, _myBeginSong). Such a
 * module was never lifted, so this file is it: LoadLibrary("MMSYSTEM") hands
 * out RECOMP_MMSYSTEM_HINST, and GetProcAddress on that handle answers with
 * host thunks for the entry points below.
 *
 * Music: MCI (sequencer + .MID file), forwarded to Win32 MCI. Sound effects:
 * waveOutGetNumDevs says one device, and waveOutOpen says it is busy, so the
 * game takes its own fallback -- it wraps the sample in a RIFF header and calls
 * sndPlaySound(SND_MEMORY), which the shim plays.
 *
 * ponytail: no real waveOut. Add it (CALLBACK_WINDOW, MM_WOM_DONE) when a game
 * has no sndPlaySound fallback or needs overlapping voices.
 */
#include "cpu.h"
#include "runtime_api.h"
#include "recomp_game.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <mmsystem.h>

int  recomp_map_guest_path(const char *g, char *host, int hostsz);   /* win16_impl.c */
HWND recomp_real_hwnd(uint16_t guest_hwnd);                           /* win32_backend.c */
void MMSYSTEM_SNDPLAYSOUND(CPU *cpu);                                  /* win16_impl.c */

static inline uint16_t a16(CPU *cpu, int off) {
    return mem_read16(cpu, cpu->ss, (uint16_t)(cpu->sp + 4 + off));
}
static inline uint32_t a32(CPU *cpu, int off) {
    return (uint32_t)a16(cpu, off) | ((uint32_t)a16(cpu, off + 2) << 16);
}
static inline void ret(CPU *cpu, int purge) { cpu->sp += 4 + purge; }
static uint32_t rd32(CPU *cpu, uint16_t s, uint16_t o) {
    return (uint32_t)mem_read16(cpu, s, o) | ((uint32_t)mem_read16(cpu, s, (uint16_t)(o + 2)) << 16);
}
static void wr32(CPU *cpu, uint16_t s, uint16_t o, uint32_t v) {
    mem_write16(cpu, s, o, (uint16_t)v);
    mem_write16(cpu, s, (uint16_t)(o + 2), (uint16_t)(v >> 16));
}
static void rd_str(CPU *cpu, uint32_t fp, char *out, int max) {
    int i = 0;
    for (; i < max - 1; i++) {
        char c = (char)mem_read8(cpu, (uint16_t)(fp >> 16), (uint16_t)(fp + i));
        if (!c) break;
        out[i] = c;
    }
    out[i] = 0;
}

static void ret32(CPU *cpu, uint32_t v, int purge) {
    cpu->ax = (uint16_t)v; cpu->dx = (uint16_t)(v >> 16);
    ret(cpu, purge);
}

static void wave_numdevs(CPU *cpu) { cpu->ax = 1; ret(cpu, 0); }
static void midi_numdevs(CPU *cpu) { cpu->ax = (uint16_t)midiOutGetNumDevs(); ret(cpu, 0); }
/* (lphwo@18, uDeviceID@16, lpFormat@12, dwCallback@8, dwInstance@4, dwFlags@0) */
static void wave_open(CPU *cpu)    { cpu->ax = MMSYSERR_ALLOCATED; ret(cpu, 22); }
/* Never reached once open fails; answer like a bad handle. */
static void wave_hdr(CPU *cpu)     { cpu->ax = MMSYSERR_INVALHANDLE; ret(cpu, 8); }  /* (hwo, lpHdr, cb) */
static void wave_h(CPU *cpu)       { cpu->ax = MMSYSERR_INVALHANDLE; ret(cpu, 2); }  /* (hwo) */

/* PCRECOMP_MUTE: MCI is the one Win16 audio path that reaches a real device
 * (the MIDI sequencer plays through the GS synth, which the per-app mixer
 * cannot mute). A muted PLAY on a sound-only device (sequencer, CD audio,
 * wave) is not sent; with MCI_NOTIFY the guest is told it finished, so a game
 * waiting for the end goes on. Video devices still play, with their audio
 * switched off first. Returns 1 when the PLAY was swallowed. */
static int mci_muted_play(UINT dev, DWORD fl, DWORD_PTR cb)
{
    if (!getenv("PCRECOMP_MUTE")) return 0;
    MCI_GETDEVCAPS_PARMS dc = { 0, 0, MCI_GETDEVCAPS_DEVICE_TYPE };
    DWORD type = mciSendCommandA(dev, MCI_GETDEVCAPS, MCI_GETDEVCAPS_ITEM, (DWORD_PTR)&dc) ? 0 : dc.dwReturn;
    if (type == MCI_DEVTYPE_SEQUENCER) {
        /* Played to no MIDI port: silent, but it still takes the song's
           length and notifies at its end, which a title screen may wait for. */
        MCI_SEQ_SET_PARMS sq = { 0 };
        sq.dwPort = MCI_SEQ_NONE;
        MCIERROR e = mciSendCommandA(dev, MCI_SET, MCI_SEQ_SET_PORT, (DWORD_PTR)&sq);
        fprintf(stderr, "[mci] muted: sequencer %u to no port -> %lu\n", dev, (unsigned long)e);
        if (!e) return 0;
    }
    if (type == MCI_DEVTYPE_SEQUENCER || type == MCI_DEVTYPE_CD_AUDIO || type == MCI_DEVTYPE_WAVEFORM_AUDIO) {
        fprintf(stderr, "[mci] muted: play on device %u (type %lu) not sent\n", dev, (unsigned long)type);
        if ((fl & MCI_NOTIFY) && cb) PostMessageA((HWND)cb, MM_MCINOTIFY, MCI_NOTIFY_SUCCESSFUL, dev);
        return 1;
    }
    MCI_SET_PARMS sp = { 0 };             /* dwAudio = MCI_SET_AUDIO_ALL */
    MCIERROR e = mciSendCommandA(dev, MCI_SET, MCI_SET_AUDIO | MCI_SET_OFF, (DWORD_PTR)&sp);
    fprintf(stderr, "[mci] muted: device %u (type %lu) audio off -> %lu\n", dev, (unsigned long)type, (unsigned long)e);
    return 0;
}

/* mciSendCommand(wDeviceID@10, wMessage@8, dwParam1@4, dwParam2@0) -> DWORD.
 * The Win16 parameter blocks are a DWORD callback (low word: the HWND to
 * notify) followed by fields that are DWORDs here but pointer-sized on Win64,
 * so each command is rebuilt field by field. */
static void mci_send(CPU *cpu) {
    UINT dev = a16(cpu, 10), msg = a16(cpu, 8);
    DWORD fl = a32(cpu, 4);
    uint32_t pp = a32(cpu, 0);
    uint16_t ps = (uint16_t)(pp >> 16), po = (uint16_t)pp;
    DWORD_PTR cb = ps ? (DWORD_PTR)recomp_real_hwnd((uint16_t)rd32(cpu, ps, po)) : 0;
    MCIERROR e;
    switch (msg) {
    case MCI_OPEN: {
        MCI_OPEN_PARMSA p = { cb };
        char type[64] = "", elem[260] = "", host[320] = "", alias[64] = "";
        uint32_t t = rd32(cpu, ps, (uint16_t)(po + 8));
        if (fl & MCI_OPEN_TYPE)
            p.lpstrDeviceType = (fl & MCI_OPEN_TYPE_ID) ? (LPCSTR)(uintptr_t)(t & 0xFFFF)
                                                        : (rd_str(cpu, t, type, sizeof type), type);
        if (fl & MCI_OPEN_ELEMENT) {
            rd_str(cpu, rd32(cpu, ps, (uint16_t)(po + 12)), elem, sizeof elem);
            p.lpstrElementName = recomp_map_guest_path(elem, host, sizeof host) ? host : elem;
        }
        if (fl & MCI_OPEN_ALIAS) {
            rd_str(cpu, rd32(cpu, ps, (uint16_t)(po + 16)), alias, sizeof alias);
            p.lpstrAlias = alias;
        }
        e = mciSendCommandA(0, msg, fl, (DWORD_PTR)&p);
        if (!e) mem_write16(cpu, ps, (uint16_t)(po + 4), (uint16_t)p.wDeviceID);
        fprintf(stderr, "[mci] open %s -> %lu (device %u)\n",
                p.lpstrElementName ? p.lpstrElementName : type, (unsigned long)e, p.wDeviceID);
        break;
    }
    case MCI_PLAY: {
        MCI_PLAY_PARMS p = { cb, rd32(cpu, ps, (uint16_t)(po + 4)), rd32(cpu, ps, (uint16_t)(po + 8)) };
        e = mci_muted_play(dev, fl, cb) ? 0 : mciSendCommandA(dev, msg, fl, (DWORD_PTR)&p);
        break;
    }
    case MCI_SEEK: {
        MCI_SEEK_PARMS p = { cb, rd32(cpu, ps, (uint16_t)(po + 4)) };
        e = mciSendCommandA(dev, msg, fl, (DWORD_PTR)&p);
        break;
    }
    case MCI_SET: {                       /* MCI_SEQ_SET_PARMS: 7 DWORDs after the callback */
        MCI_SEQ_SET_PARMS p = { cb };
        DWORD *f = &p.dwTimeFormat;
        for (int i = 0; i < 7; i++) f[i] = rd32(cpu, ps, (uint16_t)(po + 4 + 4 * i));
        e = mciSendCommandA(dev, msg, fl, (DWORD_PTR)&p);
        break;
    }
    case MCI_STATUS: {                    /* cb, dwReturn, dwItem, dwTrack */
        MCI_STATUS_PARMS p = { cb, 0, rd32(cpu, ps, (uint16_t)(po + 8)), rd32(cpu, ps, (uint16_t)(po + 12)) };
        e = mciSendCommandA(dev, msg, fl, (DWORD_PTR)&p);
        if (!e) wr32(cpu, ps, (uint16_t)(po + 4), (uint32_t)p.dwReturn);
        break;
    }
    case MCI_CLOSE: case MCI_STOP: case MCI_PAUSE: case MCI_RESUME: {
        MCI_GENERIC_PARMS p = { cb };
        e = mciSendCommandA(dev, msg, fl, (DWORD_PTR)&p);
        break;
    }
    default:
        fprintf(stderr, "[mci] *** command %04X not translated\n", msg);
        e = MCIERR_UNRECOGNIZED_COMMAND;
    }
    if (msg != MCI_OPEN && getenv("RECOMP_LOG_MCI"))
        fprintf(stderr, "[mci] dev %u msg %04X flags %08lX -> %lu\n", dev, msg, (unsigned long)fl, (unsigned long)e);
    ret32(cpu, e, 12);
}

/* ---- the multimedia timer ------------------------------------------------
 * timeSetEvent's callback runs at interrupt time on Windows 3.1, so a game may
 * busy-wait for what its callback sets without ever pumping messages (CivNet's
 * movie player). Here a due callback runs from recomp_mmtimer_poll(), which a
 * game built with RECOMP_IRQ calls from its recomp_tick (at lifted function
 * entries and loop back-edges), and which a Win32 thread timer also calls from
 * the message loop. Both are on the thread that owns the guest CPU. CivNet's
 * PCTIMER.CPP gives up (ERR_TIMERSETFAILED) without timeSetEvent. */
uint16_t recomp_call_guest(uint16_t pseg, uint16_t poff, const uint16_t *argw, int n);  /* win32_backend.c */

#define MAX_MMTIMERS 16
static struct { int on; uint16_t seg, off, flags; uint32_t user, period, due; } g_mmt[MAX_MMTIMERS];
static UINT_PTR g_mm_pump;
static int g_mm_busy;

void recomp_mmtimer_poll(void) {
    if (g_mm_busy) return;                  /* a callback is running */
    g_mm_busy = 1;
    DWORD now = timeGetTime();
    for (int i = 0; i < MAX_MMTIMERS; i++) {
        if (!g_mmt[i].on || (int)(now - g_mmt[i].due) < 0) continue;
        if (g_mmt[i].flags & TIME_PERIODIC) {
            g_mmt[i].due += g_mmt[i].period;
            if ((int)(now - g_mmt[i].due) > (int)(8 * g_mmt[i].period)) g_mmt[i].due = now + g_mmt[i].period;
        } else {
            g_mmt[i].on = 0;
        }
        /* TimeProc(uID, uMsg, dwUser, dw1, dw2): PASCAL, DWORDs high word first. */
        uint16_t a[8] = { (uint16_t)(i + 1), 0, (uint16_t)(g_mmt[i].user >> 16), (uint16_t)g_mmt[i].user,
                          0, 0, 0, 0 };
        static int fired;
        if (fired++ < 3 || getenv("RECOMP_LOG_MMTIMER"))
            fprintf(stderr, "[mm] timer %d fires %04X:%04X\n", i + 1, g_mmt[i].seg, g_mmt[i].off);
        recomp_call_guest(g_mmt[i].seg, g_mmt[i].off, a, 8);
    }
    g_mm_busy = 0;
}

static void CALLBACK mm_pump(HWND h, UINT m, UINT_PTR id, DWORD t) {
    (void)h; (void)m; (void)id; (void)t;
    recomp_mmtimer_poll();
}

/* timeSetEvent(uDelay@12, uResolution@10, lpFunction@6, dwUser@2, uFlags@0) */
void MMSYSTEM_TIMESETEVENT(CPU *cpu) {
    UINT delay = a16(cpu, 12);
    uint32_t fn = a32(cpu, 6), user = a32(cpu, 2);
    uint16_t flags = a16(cpu, 0);
    int i = 0;
    while (i < MAX_MMTIMERS && g_mmt[i].on) i++;
    cpu->ax = 0;
    if (i < MAX_MMTIMERS && fn) {
        g_mmt[i].seg = (uint16_t)(fn >> 16); g_mmt[i].off = (uint16_t)fn;
        g_mmt[i].user = user; g_mmt[i].flags = flags;
        g_mmt[i].period = delay ? delay : 1;
        g_mmt[i].due = timeGetTime() + g_mmt[i].period;
        g_mmt[i].on = 1;
        if (!g_mm_pump) g_mm_pump = SetTimer(NULL, 0, 10, mm_pump);
        cpu->ax = (uint16_t)(i + 1);
    }
    fprintf(stderr, "[mm] timeSetEvent(%u ms, %04X:%04X, %s) -> %u\n", delay, (unsigned)(fn >> 16),
            (unsigned)(fn & 0xFFFF), flags & TIME_PERIODIC ? "periodic" : "once", cpu->ax);
    ret(cpu, 14);
}

void MMSYSTEM_TIMEKILLEVENT(CPU *cpu) {
    UINT id = a16(cpu, 0);
    cpu->ax = MMSYSERR_INVALPARAM;
    if (id >= 1 && id <= MAX_MMTIMERS && g_mmt[id - 1].on) {
        g_mmt[id - 1].on = 0;
        cpu->ax = 0;
    }
    ret(cpu, 2);
}

void MMSYSTEM_TIMEBEGINPERIOD(CPU *cpu) { cpu->ax = 0; ret(cpu, 2); }
void MMSYSTEM_TIMEENDPERIOD(CPU *cpu) { cpu->ax = 0; ret(cpu, 2); }

void MMSYSTEM_TIMEGETDEVCAPS(CPU *cpu);   /* win32_backend.c */

/* The calls above, imported rather than looked up. */
void MMSYSTEM_MCISENDCOMMAND(CPU *cpu) { mci_send(cpu); }

/* mciSendString(lpstrCommand@8, lpstrReturn@4, uReturnLength@2, hwndCallback@0).
 * Forwarded to Win32 MCI after two rewrites: the word after "open" is a guest
 * path, and the number after "parent" or "handle" is a guest HWND. Bermuda
 * Syndrome plays its intro this way ("open ..\data\intro.avi alias movie style
 * child parent %d", then "play movie notify") and waits for MM_MCINOTIFY. */
void MMSYSTEM_MCISENDSTRING(CPU *cpu) {
    char in[512], out[768] = "", ret_buf[256] = "";
    rd_str(cpu, a32(cpu, 8), in, sizeof in);
    uint32_t rp = a32(cpu, 4);
    UINT rlen = a16(cpu, 2);
    HWND cb = recomp_real_hwnd(a16(cpu, 0));
    char prev[64] = "";
    for (char *t = strtok(in, " "); t; t = strtok(NULL, " ")) {
        char tok[400];
        snprintf(tok, sizeof tok, "%s", t);
        if (!_stricmp(prev, "open") && strchr(t, '.')) {
            char host[320];
            if (recomp_map_guest_path(t, host, sizeof host)) snprintf(tok, sizeof tok, "\"%s\"", host);
        } else if (!_stricmp(prev, "parent") || !_stricmp(prev, "handle")) {
            snprintf(tok, sizeof tok, "%llu", (unsigned long long)(uintptr_t)recomp_real_hwnd((uint16_t)atoi(t)));
        }
        if (*out) strncat(out, " ", sizeof out - strlen(out) - 1);
        strncat(out, tok, sizeof out - strlen(out) - 1);
        snprintf(prev, sizeof prev, "%s", t);
    }
    MCIERROR e = 0;
    char verb[16] = "", name[128] = "";
    sscanf(out, "%15s %127s", verb, name);
    if (!_stricmp(verb, "play") && mci_muted_play(mciGetDeviceIDA(name), strstr(out, " notify") ? MCI_NOTIFY : 0, (DWORD_PTR)cb))
        ;   /* swallowed; the notify is already posted */
    else
        e = mciSendStringA(out, ret_buf, sizeof ret_buf, cb);
    for (UINT i = 0; rp && i < rlen; i++) {
        mem_write8(cpu, (uint16_t)(rp >> 16), (uint16_t)(rp + i), (uint8_t)ret_buf[i]);
        if (!ret_buf[i]) break;
    }
    if (e || getenv("RECOMP_LOG_MCI")) {
        char msg[128] = "";
        if (e) mciGetErrorStringA(e, msg, sizeof msg);
        fprintf(stderr, "[mci] \"%s\" -> %lu %s\n", out, (unsigned long)e, msg);
    }
    ret32(cpu, e, 12);
}

static const struct { const char *name; void (*fn)(CPU *); } g_mm[] = {
    { "timeSetEvent",           MMSYSTEM_TIMESETEVENT },
    { "timeKillEvent",          MMSYSTEM_TIMEKILLEVENT },
    { "timeBeginPeriod",        MMSYSTEM_TIMEBEGINPERIOD },
    { "timeEndPeriod",          MMSYSTEM_TIMEENDPERIOD },
    { "timeGetDevCaps",         MMSYSTEM_TIMEGETDEVCAPS },
    { "waveOutGetNumDevs",      wave_numdevs },
    { "midiOutGetNumDevs",      midi_numdevs },
    { "waveOutOpen",            wave_open },
    { "waveOutPrepareHeader",   wave_hdr },
    { "waveOutUnprepareHeader", wave_hdr },
    { "waveOutWrite",           wave_hdr },
    { "waveOutGetPosition",     wave_hdr },
    { "waveOutReset",           wave_h },
    { "waveOutClose",           wave_h },
    { "mciSendCommand",         mci_send },
    { "sndPlaySound",           MMSYSTEM_SNDPLAYSOUND },
};

static void mm_thunk(CPU *cpu, uint16_t i) { g_mm[i].fn(cpu); }

int recomp_mmsystem_proc(const char *name, uint16_t *seg, uint16_t *off) {
    for (uint16_t i = 0; name && i < sizeof g_mm / sizeof g_mm[0]; i++)
        if (!_stricmp(name, g_mm[i].name)) {
            uint32_t fp = recomp_host_thunk(mm_thunk, i);
            *seg = (uint16_t)(fp >> 16); *off = (uint16_t)fp;
            return fp != 0;
        }
    return 0;
}

/* "MMSYSTEM", "MMSYSTEM.DLL" or any path ending in one. */
int recomp_is_mmsystem(const char *path) {
    const char *leaf = path;
    for (const char *q = path; *q; q++) if (*q == '\\' || *q == '/' || *q == ':') leaf = q + 1;
    return !_stricmp(leaf, "MMSYSTEM") || !_stricmp(leaf, "MMSYSTEM.DLL");
}

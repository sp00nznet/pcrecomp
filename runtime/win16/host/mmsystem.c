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
        e = mciSendCommandA(dev, msg, fl, (DWORD_PTR)&p);
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

static const struct { const char *name; void (*fn)(CPU *); } g_mm[] = {
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

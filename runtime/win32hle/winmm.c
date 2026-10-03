/*
 * winmm.c - win32hle WINMM: multimedia timers, joystick, waveOut audio, MCI.
 * On libc for timing; audio is "accept and retire" (a silent device that
 * completes every buffer immediately, so a game's double-buffered mixer thread
 * keeps cycling without a real sound card); no joystick; MCI stubbed. Real SDL
 * audio can replace the waveOut path later without touching callers.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <time.h>
#include "win32hle.h"

#define MMSYSERR_NOERROR  0u
#define MMSYSERR_ERROR    1u
#define JOYERR_UNPLUGGED  167u
#define WHDR_DONE         0x00000001u
#define WHDR_INQUEUE      0x00000010u

/* --- multimedia timer --- */
static void m_timeGetTime(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    RET((uint32_t)(ts.tv_sec * 1000u + ts.tv_nsec / 1000000u), 0);
}
static void m_timeBeginPeriod(void) { RET(MMSYSERR_NOERROR, 1); }
static void m_timeEndPeriod(void)   { RET(MMSYSERR_NOERROR, 1); }

/* --- joystick: none present, so the game takes its keyboard/mouse path --- */
static void m_joyGetNumDevs(void)   { RET(0, 0); }
static void m_joyGetDevCapsA(void)  { RET(JOYERR_UNPLUGGED, 3); }
static void m_joyGetPos(void)       { RET(JOYERR_UNPLUGGED, 2); }
static void m_joyGetPosEx(void)     { RET(JOYERR_UNPLUGGED, 2); }

/* --- waveOut: a silent device that retires every buffer at once ---
 * waveOutOpen succeeds with a fake handle; waveOutWrite marks the WAVEHDR done
 * and not-in-queue, so a mixer that waits for buffers to drain keeps going. */
static void m_waveOutOpen(void) {              /* (&hwo, devID, &fmt, cb, inst, flags) */
    uint32_t ph = A32(0);
    if (ph) MEM32(ph) = 0x5A5E0001u;           /* a nonzero HWAVEOUT */
    RET(MMSYSERR_NOERROR, 6);
}
static void m_waveOutWrite(void) {             /* (hwo, lpWaveHdr, cbwh) */
    uint32_t wh = A32(1);
    if (wh) { MEM32(wh + 16) = (MEM32(wh + 16) | WHDR_DONE) & ~WHDR_INQUEUE; }
    RET(MMSYSERR_NOERROR, 3);
}
static void m_waveOutPrepareHeader(void)   { uint32_t wh=A32(1); if(wh) MEM32(wh+16)|=0x00000002u/*WHDR_PREPARED*/; RET(MMSYSERR_NOERROR, 3); }
static void m_waveOutUnprepareHeader(void) { uint32_t wh=A32(1); if(wh) MEM32(wh+16)&=~0x00000002u; RET(MMSYSERR_NOERROR, 3); }
static void m_waveOutReset(void)       { RET(MMSYSERR_NOERROR, 1); }
static void m_waveOutClose(void)       { RET(MMSYSERR_NOERROR, 1); }
static void m_waveOutGetNumDevs(void)  { RET(1, 0); }          /* one (silent) device */
static void m_waveOutGetDevCapsA(void) { RET(MMSYSERR_NOERROR, 3); }

/* --- MCI (CD audio / command strings): not available --- */
static void m_mciSendStringA(void)     { RET(MMSYSERR_ERROR, 4); }
static void m_mciGetErrorStringA(void) { RET(0, 3); }          /* FALSE: no string */

const win32hle_shim win32hle_winmm[] = {
    { "timeGetTime",            m_timeGetTime },
    { "timeBeginPeriod",        m_timeBeginPeriod },
    { "timeEndPeriod",          m_timeEndPeriod },
    { "joyGetNumDevs",          m_joyGetNumDevs },
    { "joyGetDevCapsA",         m_joyGetDevCapsA },
    { "joyGetPos",              m_joyGetPos },
    { "joyGetPosEx",            m_joyGetPosEx },
    { "waveOutOpen",            m_waveOutOpen },
    { "waveOutWrite",           m_waveOutWrite },
    { "waveOutPrepareHeader",   m_waveOutPrepareHeader },
    { "waveOutUnprepareHeader", m_waveOutUnprepareHeader },
    { "waveOutReset",           m_waveOutReset },
    { "waveOutClose",           m_waveOutClose },
    { "waveOutGetNumDevs",      m_waveOutGetNumDevs },
    { "waveOutGetDevCapsA",     m_waveOutGetDevCapsA },
    { "mciSendStringA",         m_mciSendStringA },
    { "mciGetErrorStringA",     m_mciGetErrorStringA },
    { 0, 0 }
};

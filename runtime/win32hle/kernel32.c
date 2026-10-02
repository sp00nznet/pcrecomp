/*
 * kernel32.c - win32hle KERNEL32 subset on libc / POSIX. See win32hle.h for the
 * shim ABI (args via A32/APTR/ASTR, return via RET/RETP/RETV which pops stdcall
 * args). Each function is what a Win32-era game touches at startup and in its
 * file/heap/time paths; the comments name the POSIX primitive underneath.
 */
#define _GNU_SOURCE   /* clock_gettime, usleep */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include "win32hle.h"

#define HEAP_ZERO_MEMORY 0x00000008u

/* --- process / module --- */
static const char g_cmdline[] = "game.exe";

static void k_GetProcessHeap(void)    { RET(0x00000001u, 0); }          /* a nonzero handle */
static void k_GetModuleHandleA(void)  { RET(0x00400000u, 1); }          /* the image base */
static void k_GetCommandLineA(void)   { RETP(g_cmdline, 0); }
static void k_GetCurrentProcess(void) { RET(0xFFFFFFFFu, 0); }          /* pseudo-handle */
static void k_GetCurrentThreadId(void){ RET((uint32_t)(uintptr_t)pthread_self(), 0); }
static void k_ExitProcess(void)       { exit((int)A32(0)); }

/* GetVersion: Win2000 (5.0, build 2195, NT). LOWORD = major|minor<<8,
 * HIWORD = build (NT clears the top bit). */
static void k_GetVersion(void)        { RET(5u | (0u<<8) | (2195u<<16), 0); }

/* --- heap --- */
static void k_HeapAlloc(void) {                                         /* (hHeap, flags, size) */
    uint32_t flags = A32(1), size = A32(2);
    void *p = (flags & HEAP_ZERO_MEMORY) ? calloc(1, size) : malloc(size);
    RETP(p, 3);
}
static void k_HeapFree(void)   { free(APTR(2)); RET(1, 3); }            /* (hHeap, flags, ptr) */
static void k_HeapReAlloc(void){ RETP(realloc(APTR(2), A32(3)), 4); }   /* (hHeap, flags, ptr, size) */
static void k_HeapSize(void)   { RET(0xFFFFFFFFu, 3); }                 /* unknown; callers rarely trust it */
static void k_LocalAlloc(void) { uint32_t flags=A32(0), n=A32(1); RETP(flags&0x40?calloc(1,n):malloc(n), 2); }
static void k_LocalFree(void)  { free(APTR(0)); RET(0, 1); }

/* VirtualAlloc(addr, size, type, protect): MEM_RESERVE/COMMIT -> a plain
 * allocation. If the guest asked for a fixed address we honour it (it is a
 * host pointer on a 32-bit host); otherwise hand back fresh memory. */
static void k_VirtualAlloc(void) {
    uint32_t addr = A32(0), size = A32(1);
    RETP(addr ? (void *)(uintptr_t)addr : calloc(1, size), 4);
}
static void k_VirtualFree(void) { RET(1, 3); }

/* --- time --- */
static uint32_t ticks_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000u + ts.tv_nsec / 1000000u);
}
static void k_GetTickCount(void) { RET(ticks_ms(), 0); }
static void k_Sleep(void)        { uint32_t ms = A32(0); if (ms) usleep(ms * 1000u); RETV(1); }

/* --- error / debug --- */
static __thread uint32_t g_last_error;
static void k_GetLastError(void)      { RET(g_last_error, 0); }
static void k_SetLastError(void)      { g_last_error = A32(0); RETV(1); }
static void k_OutputDebugStringA(void){ fprintf(stderr, "[guest] %s", ASTR(0)); RETV(1); }

/* --- strings (KERNEL32's lstr*; CRT handles the rest) --- */
static void k_lstrlenA(void) { char *s = ASTR(0); RET(s ? (uint32_t)strlen(s) : 0u, 1); }
static void k_lstrcpyA(void) { char *d = ASTR(0), *s = ASTR(1); if (d && s) strcpy(d, s); RETP(d, 2); }
static void k_lstrcatA(void) { char *d = ASTR(0), *s = ASTR(1); if (d && s) strcat(d, s); RETP(d, 2); }
static void k_lstrcmpA(void) { RET((uint32_t)strcmp(ASTR(0), ASTR(1)), 2); }

/* STARTUPINFOA is 68 bytes; the CRT reads it early. Zero it and move on. */
static void k_GetStartupInfoA(void) { void *si = APTR(0); if (si) memset(si, 0, 68); RETV(1); }

const win32hle_shim win32hle_kernel32[] = {
    { "GetProcessHeap",     k_GetProcessHeap },
    { "GetModuleHandleA",   k_GetModuleHandleA },
    { "GetCommandLineA",    k_GetCommandLineA },
    { "GetCurrentProcess",  k_GetCurrentProcess },
    { "GetCurrentThreadId", k_GetCurrentThreadId },
    { "ExitProcess",        k_ExitProcess },
    { "GetVersion",         k_GetVersion },
    { "HeapAlloc",          k_HeapAlloc },
    { "HeapFree",           k_HeapFree },
    { "HeapReAlloc",        k_HeapReAlloc },
    { "HeapSize",           k_HeapSize },
    { "LocalAlloc",         k_LocalAlloc },
    { "LocalFree",          k_LocalFree },
    { "VirtualAlloc",       k_VirtualAlloc },
    { "VirtualFree",        k_VirtualFree },
    { "GetTickCount",       k_GetTickCount },
    { "Sleep",              k_Sleep },
    { "GetLastError",       k_GetLastError },
    { "SetLastError",       k_SetLastError },
    { "OutputDebugStringA", k_OutputDebugStringA },
    { "lstrlenA",           k_lstrlenA },
    { "lstrcpyA",           k_lstrcpyA },
    { "lstrcatA",           k_lstrcatA },
    { "lstrcmpA",           k_lstrcmpA },
    { "GetStartupInfoA",    k_GetStartupInfoA },
    { 0, 0 }
};

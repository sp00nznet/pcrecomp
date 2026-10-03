/*
 * kernel32_crt.c - the KERNEL32 imports an MSVC C runtime calls on its way from
 * the PE entry point to WinMain: std handles, file-type/console probes, the ANSI
 * codepage/locale queries, the environment block, and the SEH/error hooks. Most
 * are "answer plausibly and move on" — the CRT only needs them to not fail. On
 * libc/POSIX. Surfaced by running a real title under the permissive host and
 * implementing each import it reached (Fury³ was the first).
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "win32hle.h"

/* --- threads ---
 * A guest thread runs lifted code, so it enters through hle_call_guest, which
 * takes the machine lock and gives the thread its own guest stack + TIB. The
 * lifted start routine is stdcall with one argument (lpParameter). Guest
 * threads interleave cooperatively: a thread holds the machine lock while
 * running lifted code and only yields it in a blocking shim (Sleep,
 * WaitForSingleObject), which is enough for a game-loop/mixer thread. */
struct thread_arg { uint32_t start, param; };
static void *thread_trampoline(void *p) {
    struct thread_arg a = *(struct thread_arg *)p; free(p);
    uint32_t args[1] = { a.param };
    hle_call_guest(a.start, 1, args);
    return NULL;
}
static void k_CreateThread(void) {             /* (sa, stack, start, param, flags, &tid) */
    struct thread_arg *a = (struct thread_arg *)malloc(sizeof *a);
    a->start = A32(2); a->param = A32(3);
    pthread_t t;
    if (pthread_create(&t, NULL, thread_trampoline, a) != 0) { free(a); RET(0, 6); }
    pthread_detach(t);
    uint32_t tid = (uint32_t)(uintptr_t)t;
    uint32_t ptid = A32(5); if (ptid) MEM32(ptid) = tid;
    RET(0x7D000000u | (tid & 0x00FFFFFFu), 6);    /* a nonzero pseudo-handle */
}
static void k_SetThreadPriority(void) { RET(1, 2); }
static void k_GetCurrentThread(void)  { RET(0xFFFFFFFEu, 0); }
/* WaitForSingleObject: yield the machine lock so another guest thread can run,
 * wait briefly, then report signalled. A real object wait comes later. */
static void k_WaitForSingleObject(void) {
    mach_leave(); usleep(1000); mach_enter();
    RET(0u, 2);                                   /* WAIT_OBJECT_0 */
}

/* --- standard handles / file type --- */
static void k_GetStdHandle(void) {                 /* (nStdHandle) -10..-12 */
    uint32_t n = A32(0);
    RET(n == 0xFFFFFFF6u ? 0x13u : n == 0xFFFFFFF5u ? 0x12u : 0x11u, 1); /* ERR/OUT/IN */
}
static void k_SetStdHandle(void) { RET(1, 2); }
static void k_GetFileType(void)  { RET(2u, 1); }   /* FILE_TYPE_CHAR (a console) */
static void k_SetHandleCount(void){ RET(A32(0), 1); }

/* --- codepage / locale (the CRT's __setargv / _setmbcp path) --- */
static void k_GetACP(void)  { RET(1252u, 0); }     /* Windows-1252 */
static void k_GetOEMCP(void){ RET(437u, 0); }
static void k_GetCPInfo(void) {                    /* (cp, &CPINFO) */
    uint8_t *ci = (uint8_t *)APTR(1);
    if (ci) { memset(ci, 0, 20); *(uint32_t *)ci = 1; ci[4] = (uint8_t)'?'; } /* MaxCharSize=1, DefaultChar='?' */
    RET(1, 2);
}
/* GetStringTypeA/W and the LCMapString family: the CRT uses them for locale
 * classification; returning success with no-op output is enough for ASCII. */
static void k_GetStringTypeA(void) { RET(1, 5); }
static void k_GetStringTypeW(void) { RET(1, 4); }

/* --- environment block: an empty, double-NUL-terminated block --- */
static char g_envblock[2] = { 0, 0 };
static void k_GetEnvironmentStrings(void)   { RETP(g_envblock, 0); }
static void k_GetEnvironmentStringsW(void)  { RETP(g_envblock, 0); }
static void k_FreeEnvironmentStringsA(void) { RET(1, 1); }
static void k_FreeEnvironmentStringsW(void) { RET(1, 1); }
static void k_GetEnvironmentVariableA(void) { RET(0, 3); }   /* not found */

/* --- module/path ---
 * The host records the real image path (hle_set_module_path), stored in
 * backslash form so the guest's own path logic (which splits on '\\' to find
 * the install directory) works; CreateFileA flips '\\' back to '/'. This is how
 * a game finds its data (.POD, etc.) relative to the executable. */
static char g_modpath[512] = "C:\\GAME\\GAME.EXE";
void hle_set_module_path(const char *real) {
    size_t i = 0;
    if (real) for (; real[i] && i + 1 < sizeof g_modpath; i++) g_modpath[i] = real[i] == '/' ? '\\' : real[i];
    g_modpath[i] = 0;
}
static void k_GetModuleFileNameA(void) {           /* (hModule, buf, size) */
    char *buf = ASTR(1); uint32_t size = A32(2);
    if (buf && size) { strncpy(buf, g_modpath, size - 1); buf[size - 1] = 0; }
    RET(buf ? (uint32_t)strlen(buf) : 0u, 3);
}
static void k_GetCurrentDirectoryA(void) {         /* (size, buf) -> install dir */
    uint32_t size = A32(0); char *buf = ASTR(1);
    char dir[512]; strncpy(dir, g_modpath, sizeof dir - 1); dir[sizeof dir - 1] = 0;
    char *bs = strrchr(dir, '\\'); if (bs) *bs = 0;      /* strip the exe name */
    if (buf && size) { strncpy(buf, dir, size - 1); buf[size - 1] = 0; }
    RET(buf ? (uint32_t)strlen(buf) : 0u, 2);
}
static void k_SetCurrentDirectoryA(void) { RET(1, 1); }
static void k_GetDriveTypeA(void)  { RET(3u, 1); } /* DRIVE_FIXED */
static void k_GetLogicalDrives(void){ RET(0x4u, 0); } /* C: present */

/* --- unicode conversion (ASCII 1:1, enough for the CRT's startup) --- */
static void k_MultiByteToWideChar(void) {          /* (cp,fl,src,srcN,dst,dstN) */
    const char *src = ASTR(2); int srcN = (int)A32(3);
    uint16_t *dst = (uint16_t *)APTR(4); int dstN = (int)A32(5);
    if (!src) RET(0, 6);
    int n = srcN < 0 ? (int)strlen(src) + 1 : srcN;
    if (dst && dstN) { for (int i = 0; i < n && i < dstN; i++) dst[i] = (uint8_t)src[i]; }
    RET((uint32_t)n, 6);
}
static void k_WideCharToMultiByte(void) {          /* (cp,fl,src,srcN,dst,dstN,dc,uu) */
    const uint16_t *src = (const uint16_t *)APTR(2); int srcN = (int)A32(3);
    char *dst = ASTR(4); int dstN = (int)A32(5);
    if (!src) RET(0, 8);
    int n = 0; if (srcN < 0) { while (src[n]) n++; n++; } else n = srcN;
    if (dst && dstN) { for (int i = 0; i < n && i < dstN; i++) dst[i] = (char)src[i]; }
    RET((uint32_t)n, 8);
}

/* --- system info / time zone --- */
static void k_GlobalMemoryStatus(void) {           /* (&MEMORYSTATUS) 32 bytes */
    uint8_t *m = (uint8_t *)APTR(0);
    if (m) { memset(m, 0, 32); *(uint32_t *)m = 32; m[4] = 50;          /* dwLength, dwMemoryLoad */
             *(uint32_t *)(m + 8)  = 0x20000000u;                       /* dwTotalPhys = 512 MB */
             *(uint32_t *)(m + 12) = 0x10000000u; }                     /* dwAvailPhys = 256 MB */
    RETV(1);
}
static void k_GetTimeZoneInformation(void) { RET(0u, 1); } /* TIME_ZONE_ID_UNKNOWN */

/* --- SEH / error hooks: the startup installs these; stub to not fail --- */
static void k_SetUnhandledExceptionFilter(void) { RET(0, 1); }
static void k_UnhandledExceptionFilter(void)    { RET(0, 1); }  /* EXCEPTION_CONTINUE_SEARCH */
static void k_RtlUnwind(void)      { RETV(4); }                 /* no guest SEH unwinding yet */
static void k_RaiseException(void) { hle_fatal("RaiseException (guest SEH/C++ throw) not handled yet"); }

/* --- module loading: no dynamic libraries for first-light --- */
static void k_LoadLibraryA(void)  { RET(0x100000u, 1); }        /* a fake, nonzero HMODULE */
static void k_FreeLibrary(void)   { RET(1, 1); }
static void k_GetProcAddress(void){ RET(0, 2); }                /* "not found" -> caller falls back */
static void k_LoadModule(void)    { RET(32u, 2); }              /* >31 == success */

const win32hle_shim win32hle_kernel32_crt[] = {
    { "GetStdHandle",                 k_GetStdHandle },
    { "SetStdHandle",                 k_SetStdHandle },
    { "GetFileType",                  k_GetFileType },
    { "SetHandleCount",               k_SetHandleCount },
    { "GetACP",                       k_GetACP },
    { "GetOEMCP",                     k_GetOEMCP },
    { "GetCPInfo",                    k_GetCPInfo },
    { "GetStringTypeA",               k_GetStringTypeA },
    { "GetStringTypeW",               k_GetStringTypeW },
    { "GetEnvironmentStrings",        k_GetEnvironmentStrings },
    { "GetEnvironmentStringsW",       k_GetEnvironmentStringsW },
    { "FreeEnvironmentStringsA",      k_FreeEnvironmentStringsA },
    { "FreeEnvironmentStringsW",      k_FreeEnvironmentStringsW },
    { "GetEnvironmentVariableA",      k_GetEnvironmentVariableA },
    { "GetModuleFileNameA",           k_GetModuleFileNameA },
    { "GetCurrentDirectoryA",         k_GetCurrentDirectoryA },
    { "SetCurrentDirectoryA",         k_SetCurrentDirectoryA },
    { "GetDriveTypeA",                k_GetDriveTypeA },
    { "GetLogicalDrives",             k_GetLogicalDrives },
    { "MultiByteToWideChar",          k_MultiByteToWideChar },
    { "WideCharToMultiByte",          k_WideCharToMultiByte },
    { "GlobalMemoryStatus",           k_GlobalMemoryStatus },
    { "GetTimeZoneInformation",       k_GetTimeZoneInformation },
    { "SetUnhandledExceptionFilter",  k_SetUnhandledExceptionFilter },
    { "UnhandledExceptionFilter",     k_UnhandledExceptionFilter },
    { "RtlUnwind",                    k_RtlUnwind },
    { "RaiseException",               k_RaiseException },
    { "LoadLibraryA",                 k_LoadLibraryA },
    { "FreeLibrary",                  k_FreeLibrary },
    { "GetProcAddress",               k_GetProcAddress },
    { "LoadModule",                   k_LoadModule },
    { "CreateThread",                 k_CreateThread },
    { "SetThreadPriority",            k_SetThreadPriority },
    { "GetCurrentThread",             k_GetCurrentThread },
    { "WaitForSingleObject",          k_WaitForSingleObject },
    { 0, 0 }
};

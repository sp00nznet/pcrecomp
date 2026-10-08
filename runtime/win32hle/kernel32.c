/*
 * kernel32.c - win32hle KERNEL32 core on libc / POSIX: process, heap and
 * virtual memory, time, errors, lstr*, synchronisation (critical sections,
 * events, mutexes, waits, Interlocked*), thread-local storage, and the
 * console/serial/process calls a game links but has no use for on a host.
 * See win32hle.h for the shim ABI (A32/APTR/ASTR in, RET/RETP/RETV out).
 *
 * Guest threads run one at a time (the machine lock), so the guest-side state
 * here (a CRITICAL_SECTION's fields, an event's flag) needs no lock of its own:
 * a wait gives the machine up (hle_block_begin/end) and looks again.
 */
#define _GNU_SOURCE   /* clock_gettime, usleep, MAP_ANONYMOUS */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include "win32hle.h"

#define HEAP_ZERO_MEMORY            0x00000008u
#define HEAP_REALLOC_IN_PLACE_ONLY  0x00000010u
#define ERROR_INVALID_HANDLE        6u
#define ERROR_NOT_ENOUGH_MEMORY     8u
#define ERROR_INVALID_PARAMETER    87u
#define ERROR_CALL_NOT_IMPLEMENTED 120u
#define ERROR_ALREADY_EXISTS      183u
#define WAIT_OBJECT_0               0u
#define WAIT_TIMEOUT              258u
#define WAIT_FAILED       0xFFFFFFFFu
#define INFINITE          0xFFFFFFFFu

/* --- error --- */
static __thread uint32_t g_last_error;
void hle_set_last_error(uint32_t code) { g_last_error = code; }
uint32_t hle_get_last_error(void) { return g_last_error; }
static void k_GetLastError(void)      { RET(g_last_error, 0); }
static void k_SetLastError(void)      { g_last_error = A32(0); RETV(1); }
static void k_OutputDebugStringA(void){ fprintf(stderr, "[guest] %s", ASTR(0) ? ASTR(0) : ""); RETV(1); }

/* --- process --- */
static const char g_default_cmdline[] = "game.exe";
static const char *g_cmdline = g_default_cmdline;
void hle_set_command_line(const char *cmdline) { g_cmdline = cmdline; }

/* A host may want to close a recording or a window before the process goes. */
void (*hle_on_exit)(int code);
void hle_exit(int code) {
    static volatile int once;
    if (__sync_lock_test_and_set(&once, 1)) _exit(code);
    if (hle_on_exit) hle_on_exit(code);
    fflush(stdout);
    fflush(stderr);
    _exit(code);
}

static void k_GetProcessHeap(void)      { RET(0x00000001u, 0); }        /* every heap is the one heap */
static void k_GetCommandLineA(void)     { RETP(g_cmdline, 0); }
static void k_GetCurrentProcess(void)   { RET(0xFFFFFFFFu, 0); }        /* pseudo-handle */
static void k_GetCurrentProcessId(void) { RET((uint32_t)getpid(), 0); }
static void k_ExitProcess(void)         { fprintf(stderr, "[win32hle] ExitProcess(%u)\n", A32(0)); hle_exit((int)A32(0)); }
static void k_TerminateProcess(void) {
    if (A32(0) == 0xFFFFFFFFu) { fprintf(stderr, "[win32hle] TerminateProcess(self, %u)\n", A32(1)); hle_exit((int)A32(1)); }
    g_last_error = ERROR_INVALID_HANDLE;
    RET(0, 2);
}
static void k_FatalAppExitA(void) { fprintf(stderr, "[win32hle] FatalAppExitA: %s\n", ASTR(1) ? ASTR(1) : ""); hle_exit(1); }
static void k_CreateProcessA(void) {
    fprintf(stderr, "[win32hle] CreateProcessA(%s, %s): not on this host\n", ASTR(0) ? ASTR(0) : "", ASTR(1) ? ASTR(1) : "");
    g_last_error = 2;
    RET(0, 10);
}
static void k_GetExitCodeProcess(void) { if (A32(1)) MEM32(A32(1)) = 0; RET(1, 2); }

/* Thread ids: small and stable per host thread (pthread_self is a pointer). */
static __thread uint32_t g_tid;
static volatile uint32_t g_next_tid = 0x100;
uint32_t hle_thread_id(void) {
    if (!g_tid) g_tid = __sync_add_and_fetch(&g_next_tid, 4);
    return g_tid;
}
static void k_GetCurrentThreadId(void) { RET(hle_thread_id(), 0); }

/* GetVersion: Windows XP (5.1, build 2600, NT). LOWORD = major|minor<<8,
 * HIWORD = build (NT clears the top bit). */
static void k_GetVersion(void) { RET(5u | (1u << 8) | (2600u << 16), 0); }
static void k_GetVersionExA(void) {                      /* OSVERSIONINFOA: size, major, minor, build, platform, csd[128] */
    uint32_t v = A32(0);
    if (!v) RET(0, 1);
    MEM32(v + 4) = 5, MEM32(v + 8) = 1, MEM32(v + 12) = 2600, MEM32(v + 16) = 2;
    snprintf((char *)(uintptr_t)(v + 20), 128, "Service Pack 3");
    RET(1, 1);
}

/* --- heap ---
 * One heap. Each block carries its size in front (HeapSize and _msize answer
 * from it, and a Local/Global block is the same kind of block). */
#define HDR 16u
static void *blk_alloc(uint32_t n, int zero) {
    uint8_t *p = (uint8_t *)(zero ? calloc(1, (size_t)n + HDR) : malloc((size_t)n + HDR));
    if (!p) return NULL;
    *(uint32_t *)p = n;
    *(uint32_t *)(p + 4) = 0x48454150u;                  /* 'HEAP' */
    return p + HDR;
}
static int blk_ok(void *u) { return u && *(uint32_t *)((uint8_t *)u - HDR + 4) == 0x48454150u; }
static uint32_t blk_size(void *u) { return blk_ok(u) ? *(uint32_t *)((uint8_t *)u - HDR) : 0; }
static void blk_free(void *u) {
    if (!u) return;
    if (!blk_ok(u)) { fprintf(stderr, "[win32hle] free of a block this heap did not hand out: %p\n", u); return; }
    *(uint32_t *)((uint8_t *)u - HDR + 4) = 0;
    free((uint8_t *)u - HDR);
}
static void *blk_realloc(void *u, uint32_t n, int zero) {
    if (!u) return blk_alloc(n, zero);
    uint32_t old = blk_size(u);
    uint8_t *p = (uint8_t *)realloc((uint8_t *)u - HDR, (size_t)n + HDR);
    if (!p) return NULL;
    *(uint32_t *)p = n;
    if (zero && n > old) memset(p + HDR + old, 0, n - old);
    return p + HDR;
}
void *hle_alloc(uint32_t n) { return blk_alloc(n, 1); }
void  hle_free(void *p) { blk_free(p); }

static void k_HeapCreate(void)  { RET(0x00000001u, 3); }
static void k_HeapDestroy(void) { RET(1, 1); }
static void k_HeapAlloc(void) {                          /* (hHeap, flags, size) */
    void *p = blk_alloc(A32(2), (A32(1) & HEAP_ZERO_MEMORY) != 0);
    if (!p) g_last_error = ERROR_NOT_ENOUGH_MEMORY;
    RETP(p, 3);
}
static void k_HeapFree(void) { blk_free(APTR(2)); RET(1, 3); }   /* (hHeap, flags, ptr) */
static void k_HeapReAlloc(void) {                        /* (hHeap, flags, ptr, size) */
    uint32_t fl = A32(1), n = A32(3);
    void *u = APTR(2);
    if (fl & HEAP_REALLOC_IN_PLACE_ONLY) {
        if (!blk_ok(u) || n > blk_size(u)) { g_last_error = ERROR_NOT_ENOUGH_MEMORY; RET(0, 4); }
        *(uint32_t *)((uint8_t *)u - HDR) = n;
        RETP(u, 4);
    }
    RETP(blk_realloc(u, n, (fl & HEAP_ZERO_MEMORY) != 0), 4);
}
static void k_HeapSize(void)   { void *u = APTR(2); RET(blk_ok(u) ? blk_size(u) : 0xFFFFFFFFu, 3); }
static void k_HeapValidate(void) { RET(1, 3); }
static void k_LocalAlloc(void) { RETP(blk_alloc(A32(1), (A32(0) & 0x40u) != 0), 2); }
static void k_LocalFree(void)  { blk_free(APTR(0)); RET(0, 1); }
static void k_LocalReAlloc(void) { RETP(blk_realloc(APTR(0), A32(1), (A32(2) & 0x40u) != 0), 3); }
static void k_LocalLock(void)  { RETP(APTR(0), 1); }
static void k_LocalUnlock(void){ RET(1, 1); }
static void k_LocalSize(void)  { RET(blk_size(APTR(0)), 1); }
static void k_GlobalAlloc(void) { RETP(blk_alloc(A32(1), (A32(0) & 0x40u) != 0), 2); }
static void k_GlobalFree(void)  { blk_free(APTR(0)); RET(0, 1); }
static void k_GlobalReAlloc(void){ RETP(blk_realloc(APTR(0), A32(1), (A32(2) & 0x40u) != 0), 3); }
static void k_GlobalLock(void)  { RETP(APTR(0), 1); }        /* GMEM_FIXED: the handle is the pointer */
static void k_GlobalUnlock(void){ RET(1, 1); }
static void k_GlobalSize(void)  { RET(blk_size(APTR(0)), 1); }
static void k_GlobalHandle(void){ RET(A32(0), 1); }

/* --- virtual memory ---
 * A reservation is an mmap of the whole range, read-write (pages cost nothing
 * until touched); commit within it hands back the address; decommit drops the
 * pages (they read as zero when committed again); release unmaps the
 * reservation, whose size is remembered here. */
#define MEM_COMMIT   0x1000u
#define MEM_RESERVE  0x2000u
#define MEM_DECOMMIT 0x4000u
#define MEM_RELEASE  0x8000u
#define MAX_REGIONS 1024
static struct { uint32_t base, size; } g_region[MAX_REGIONS];

static int region_of(uint32_t a) {
    for (int i = 0; i < MAX_REGIONS; i++)
        if (g_region[i].size && a >= g_region[i].base && a - g_region[i].base < g_region[i].size) return i;
    return -1;
}

static void k_VirtualAlloc(void) {                       /* (addr, size, type, protect) */
    uint32_t addr = A32(0), size = (A32(1) + 0xFFFu) & ~0xFFFu, type = A32(2);
    if (addr && region_of(addr) >= 0) {                  /* commit inside a reservation */
        RET(addr & ~0xFFFu, 4);
    }
    if (!size) { g_last_error = ERROR_INVALID_PARAMETER; RET(0, 4); }
    void *p = mmap(addr ? (void *)(uintptr_t)(addr & ~0xFFFFu) : NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | (addr ? 0x100000 /* MAP_FIXED_NOREPLACE */ : 0), -1, 0);
    if (p == MAP_FAILED || (addr && (uint32_t)(uintptr_t)p != (addr & ~0xFFFFu))) {
        if (p != MAP_FAILED) munmap(p, size);
        g_last_error = ERROR_NOT_ENOUGH_MEMORY;
        RET(0, 4);
    }
    for (int i = 0; i < MAX_REGIONS; i++)
        if (!g_region[i].size) { g_region[i].base = (uint32_t)(uintptr_t)p, g_region[i].size = size; break; }
    (void)type;
    RETP(p, 4);
}
static void k_VirtualFree(void) {                        /* (addr, size, type) */
    uint32_t addr = A32(0), size = A32(1), type = A32(2);
    int i = region_of(addr);
    if (i < 0) { g_last_error = ERROR_INVALID_PARAMETER; RET(0, 3); }
    if (type & MEM_RELEASE) {
        munmap((void *)(uintptr_t)g_region[i].base, g_region[i].size);
        g_region[i].size = 0;
    } else if (type & MEM_DECOMMIT) {
        uint32_t a = addr & ~0xFFFu, end = size ? (addr + size + 0xFFFu) & ~0xFFFu : g_region[i].base + g_region[i].size;
        madvise((void *)(uintptr_t)a, end - a, MADV_DONTNEED);
    }
    RET(1, 3);
}
static void k_VirtualProtect(void) { if (A32(3)) MEM32(A32(3)) = 0x04u; RET(1, 4); }   /* PAGE_READWRITE before */
static void k_VirtualQuery(void) {                       /* (addr, &MEMORY_BASIC_INFORMATION, len) */
    uint32_t a = A32(0), m = A32(1);
    int i = region_of(a);
    if (!m || A32(2) < 28) RET(0, 3);
    MEM32(m) = a & ~0xFFFu;
    MEM32(m + 4) = i >= 0 ? g_region[i].base : a & ~0xFFFFu;
    MEM32(m + 8) = 0x04u;
    MEM32(m + 12) = i >= 0 ? g_region[i].base + g_region[i].size - (a & ~0xFFFu) : 0x1000u;
    MEM32(m + 16) = MEM_COMMIT, MEM32(m + 20) = 0x04u, MEM32(m + 24) = 0x20000u;
    RET(28, 3);
}
/* Bad pointers: nothing below 64 KB is mapped on either OS; above it the
 * host would have to probe, and a game asks only to be careful. */
static void k_IsBadReadPtr(void)  { RET(A32(0) < 0x10000u && A32(1) ? 1u : 0u, 2); }
static void k_IsBadWritePtr(void) { RET(A32(0) < 0x10000u && A32(1) ? 1u : 0u, 2); }
static void k_IsBadCodePtr(void)  { RET(A32(0) < 0x10000u ? 1u : 0u, 1); }
static void k_FlushInstructionCache(void) { RET(1, 3); }
/* The CRT asks which instruction sets it may use; the lifted code is the
 * same either way, so the oldest paths. */
static void k_IsProcessorFeaturePresent(void) { RET(0, 1); }

/* --- time --- */
static uint32_t ticks_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)((uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u);
}
uint32_t hle_ticks_ms(void) { return ticks_ms(); }
static void k_GetTickCount(void) { RET(ticks_ms(), 0); }
static void k_QueryPerformanceFrequency(void) { if (A32(0)) MEM32(A32(0)) = 1000000u, MEM32(A32(0) + 4) = 0; RET(1, 1); }
static void k_QueryPerformanceCounter(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t us = (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
    if (A32(0)) MEM32(A32(0)) = (uint32_t)us, MEM32(A32(0) + 4) = (uint32_t)(us >> 32);
    RET(1, 1);
}
/* Sleep gives the machine up for the wait, so another guest thread (a mixer,
 * a timer callback) runs meanwhile. Sleep(0) is a yield. */
static void k_Sleep(void) {
    uint32_t ms = A32(0);
    hle_block_begin();
    if (ms) usleep(ms * 1000u); else sched_yield();
    hle_block_end();
    RETV(1);
}
static void k_SleepEx(void) { uint32_t ms = A32(0); hle_block_begin(); if (ms) usleep(ms * 1000u); else sched_yield(); hle_block_end(); RET(0, 2); }

/* --- strings (KERNEL32's lstr*; the CRT has the rest) --- */
static void k_lstrlenA(void) { char *s = ASTR(0); RET(s ? (uint32_t)strlen(s) : 0u, 1); }
static void k_lstrlenW(void) { const uint16_t *s = (const uint16_t *)APTR(0); uint32_t n = 0; if (s) while (s[n]) n++; RET(n, 1); }
static void k_lstrcpyA(void) { char *d = ASTR(0), *s = ASTR(1); if (d && s) memmove(d, s, strlen(s) + 1); RETP(d, 2); }
static void k_lstrcpynA(void) { char *d = ASTR(0), *s = ASTR(1); int n = (int)A32(2); if (d && s && n > 0) { strncpy(d, s, (size_t)n - 1); d[n - 1] = 0; } RETP(d, 3); }
static void k_lstrcatA(void) { char *d = ASTR(0), *s = ASTR(1); if (d && s) strcat(d, s); RETP(d, 2); }
static void k_lstrcmpA(void) { RET((uint32_t)strcmp(ASTR(0) ? ASTR(0) : "", ASTR(1) ? ASTR(1) : ""), 2); }
static void k_lstrcmpiA(void) { RET((uint32_t)strcasecmp(ASTR(0) ? ASTR(0) : "", ASTR(1) ? ASTR(1) : ""), 2); }

/* STARTUPINFOA is 68 bytes; the CRT reads it early. */
static void k_GetStartupInfoA(void) { uint32_t si = A32(0); if (si) { memset((void *)(uintptr_t)si, 0, 68); MEM32(si) = 68; } RETV(1); }

/* --- critical sections ---
 * CRITICAL_SECTION: DebugInfo, LockCount, RecursionCount, OwningThread,
 * LockSemaphore, SpinCount. The guest's own struct holds the state. */
#define CS_REC(cs)   MEM32((cs) + 8)
#define CS_OWNER(cs) MEM32((cs) + 12)
static void k_InitializeCriticalSection(void) { uint32_t cs = A32(0); if (cs) memset((void *)(uintptr_t)cs, 0, 24), MEM32(cs + 4) = 0xFFFFFFFFu; RETV(1); }
static void k_DeleteCriticalSection(void) { RETV(1); }
void hle_enter_cs(uint32_t cs) {
    uint32_t me = hle_thread_id();
    while (CS_OWNER(cs) && CS_OWNER(cs) != me) {
        hle_block_begin();
        sched_yield();
        usleep(50);
        hle_block_end();
    }
    CS_OWNER(cs) = me;
    CS_REC(cs)++;
    MEM32(cs + 4)++;
}
void hle_leave_cs(uint32_t cs) {
    if (CS_OWNER(cs) != hle_thread_id() || !CS_REC(cs)) return;
    MEM32(cs + 4)--;
    if (--CS_REC(cs) == 0) CS_OWNER(cs) = 0;
}
static void k_EnterCriticalSection(void) { hle_enter_cs(A32(0)); RETV(1); }
static void k_LeaveCriticalSection(void) { hle_leave_cs(A32(0)); RETV(1); }
static void k_TryEnterCriticalSection(void) {
    uint32_t cs = A32(0), me = hle_thread_id();
    if (CS_OWNER(cs) && CS_OWNER(cs) != me) RET(0, 1);
    CS_OWNER(cs) = me, CS_REC(cs)++, MEM32(cs + 4)++;
    RET(1, 1);
}

/* --- Interlocked (on guest memory) --- */
static void k_InterlockedIncrement(void) { RET(__sync_add_and_fetch((volatile uint32_t *)APTR(0), 1u), 1); }
static void k_InterlockedDecrement(void) { RET(__sync_sub_and_fetch((volatile uint32_t *)APTR(0), 1u), 1); }
static void k_InterlockedExchange(void)  { RET(__sync_lock_test_and_set((volatile uint32_t *)APTR(0), A32(1)), 2); }
static void k_InterlockedExchangeAdd(void) { RET(__sync_fetch_and_add((volatile uint32_t *)APTR(0), A32(1)), 2); }
static void k_InterlockedCompareExchange(void) { RET(__sync_val_compare_and_swap((volatile uint32_t *)APTR(0), A32(2), A32(1)), 3); }

/* --- events, mutexes, semaphores, waits --- */
typedef struct { int manual, signaled; } hevent;
typedef struct { uint32_t owner, count; } hmutex;
typedef struct { int32_t count, max; } hsem;
typedef struct { char name[128]; uint32_t h; } named_t;
static named_t g_named[64];

static uint32_t named_find(const char *name) {
    for (int i = 0; name && i < 64; i++) if (g_named[i].h && !strcmp(g_named[i].name, name)) return g_named[i].h;
    return 0;
}
static void named_add(const char *name, uint32_t h) {
    for (int i = 0; name && i < 64; i++) if (!g_named[i].h) { snprintf(g_named[i].name, sizeof g_named[i].name, "%s", name); g_named[i].h = h; return; }
}
static void free_obj(void *o) { free(o); }

static void k_CreateEventA(void) {                       /* (sa, manual, initial, name) */
    static int closer;
    if (!closer) hle_handle_set_closer(HLE_H_EVENT, free_obj), closer = 1;
    uint32_t h = named_find(ASTR(3));
    if (h) { g_last_error = ERROR_ALREADY_EXISTS; RET(h, 4); }
    hevent *e = (hevent *)calloc(1, sizeof *e);
    e->manual = A32(1) != 0, e->signaled = A32(2) != 0;
    h = hle_handle_alloc(HLE_H_EVENT, e);
    named_add(ASTR(3), h);
    g_last_error = 0;
    RET(h, 4);
}
void hle_set_event(uint32_t h) { hevent *e = (hevent *)hle_handle_obj(h, HLE_H_EVENT); if (e) e->signaled = 1; }
static void k_SetEvent(void)   { hevent *e = (hevent *)hle_handle_obj(A32(0), HLE_H_EVENT); if (e) e->signaled = 1; RET(e ? 1u : 0u, 1); }
static void k_ResetEvent(void) { hevent *e = (hevent *)hle_handle_obj(A32(0), HLE_H_EVENT); if (e) e->signaled = 0; RET(e ? 1u : 0u, 1); }
static void k_PulseEvent(void) { hevent *e = (hevent *)hle_handle_obj(A32(0), HLE_H_EVENT); if (e) e->signaled = 0; RET(e ? 1u : 0u, 1); }

static void k_CreateMutexA(void) {                       /* (sa, initialOwner, name) */
    static int closer;
    if (!closer) hle_handle_set_closer(HLE_H_MUTEX, free_obj), closer = 1;
    uint32_t h = named_find(ASTR(2));
    if (h) { g_last_error = ERROR_ALREADY_EXISTS; RET(h, 3); }
    hmutex *m = (hmutex *)calloc(1, sizeof *m);
    if (A32(1)) m->owner = hle_thread_id(), m->count = 1;
    h = hle_handle_alloc(HLE_H_MUTEX, m);
    named_add(ASTR(2), h);
    g_last_error = 0;
    RET(h, 3);
}
static void k_OpenMutexA(void) {                         /* (access, inherit, name) */
    uint32_t h = named_find(ASTR(2));
    if (!h) g_last_error = 2;
    RET(h, 3);
}
static void k_ReleaseMutex(void) {
    hmutex *m = (hmutex *)hle_handle_obj(A32(0), HLE_H_MUTEX);
    if (!m || m->owner != hle_thread_id()) { g_last_error = 288u; RET(0, 1); }   /* ERROR_NOT_OWNER */
    if (--m->count == 0) m->owner = 0;
    RET(1, 1);
}
static void k_CreateSemaphoreA(void) {                   /* (sa, initial, max, name) */
    hsem *s = (hsem *)calloc(1, sizeof *s);
    s->count = (int32_t)A32(1), s->max = (int32_t)A32(2);
    RET(hle_handle_alloc(HLE_H_SEMAPHORE, s), 4);
}
static void k_ReleaseSemaphore(void) {
    hsem *s = (hsem *)hle_handle_obj(A32(0), HLE_H_SEMAPHORE);
    if (!s) RET(0, 3);
    if (A32(2)) MEM32(A32(2)) = (uint32_t)s->count;
    s->count += (int32_t)A32(1);
    if (s->count > s->max) s->count = s->max;
    RET(1, 3);
}

/* Try to take one object: 1 if it is signalled (and consumed, as its type
 * says), 0 if not, -1 if it is not a waitable handle. */
int (*hle_wait_hook)(uint32_t h);        /* a host's own objects (threads, sockets) */
static int try_take(uint32_t h) {
    if (hle_wait_hook) { int r = hle_wait_hook(h); if (r >= 0) return r; }
    switch (hle_handle_type(h)) {
    case HLE_H_EVENT: {
        hevent *e = (hevent *)hle_handle_obj(h, HLE_H_EVENT);
        if (!e->signaled) return 0;
        if (!e->manual) e->signaled = 0;
        return 1;
    }
    case HLE_H_MUTEX: {
        hmutex *m = (hmutex *)hle_handle_obj(h, HLE_H_MUTEX);
        if (m->owner && m->owner != hle_thread_id()) return 0;
        m->owner = hle_thread_id(), m->count++;
        return 1;
    }
    case HLE_H_SEMAPHORE: {
        hsem *s = (hsem *)hle_handle_obj(h, HLE_H_SEMAPHORE);
        if (s->count <= 0) return 0;
        s->count--;
        return 1;
    }
    case HLE_H_THREAD:
        return 0;                                        /* threads end only at exit */
    default:
        return h == 0xFFFFFFFFu || h == 0xFFFFFFFEu ? 0 : -1;   /* this process/thread: never */
    }
}

uint32_t hle_wait(int n, const uint32_t *h, int all, uint32_t timeout) {
    uint32_t start = ticks_ms();
    for (;;) {
        if (all) {
            int ready = 1;
            for (int i = 0; i < n; i++) { int r = try_take(h[i]); if (r < 0) return WAIT_FAILED; if (!r) { ready = 0; break; } }
            if (ready) return WAIT_OBJECT_0;           /* ponytail: takes as it checks; a partial take is not undone */
        } else {
            for (int i = 0; i < n; i++) {
                int r = try_take(h[i]);
                if (r < 0) { g_last_error = ERROR_INVALID_HANDLE; return WAIT_FAILED; }
                if (r) return WAIT_OBJECT_0 + (uint32_t)i;
            }
        }
        if (timeout != INFINITE && ticks_ms() - start >= timeout) return WAIT_TIMEOUT;
        hle_block_begin();
        usleep(timeout == 0 ? 0 : 200);
        hle_block_end();
        if (timeout == 0) return WAIT_TIMEOUT;
    }
}
static void k_WaitForSingleObject(void) { uint32_t h = A32(0); RET(hle_wait(1, &h, 0, A32(1)), 2); }
static void k_WaitForSingleObjectEx(void) { uint32_t h = A32(0); RET(hle_wait(1, &h, 0, A32(1)), 3); }
static void k_WaitForMultipleObjects(void) {             /* (n, handles, all, timeout) */
    uint32_t n = A32(0), hs[64];
    if (n > 64) n = 64;
    for (uint32_t i = 0; i < n; i++) hs[i] = MEM32(A32(1) + 4 * i);
    RET(hle_wait((int)n, hs, A32(2) != 0, A32(3)), 4);
}

/* --- thread-local storage: per host thread --- */
#define TLS_SLOTS 64
static __thread uint32_t g_tls[TLS_SLOTS];
static uint8_t g_tls_used[TLS_SLOTS];
static void k_TlsAlloc(void) {
    for (int i = 0; i < TLS_SLOTS; i++) if (!g_tls_used[i]) { g_tls_used[i] = 1; RET((uint32_t)i, 0); }
    RET(0xFFFFFFFFu, 0);
}
static void k_TlsFree(void) { uint32_t i = A32(0); if (i < TLS_SLOTS) g_tls_used[i] = 0; RET(1, 1); }
static void k_TlsGetValue(void) { uint32_t i = A32(0); g_last_error = 0; RET(i < TLS_SLOTS ? g_tls[i] : 0u, 1); }
static void k_TlsSetValue(void) { uint32_t i = A32(0); if (i < TLS_SLOTS) g_tls[i] = A32(1); RET(i < TLS_SLOTS ? 1u : 0u, 2); }

/* --- the console, serial ports, devices: a game links them, a host has none --- */
static void k_ret1_0(void) { RET(1, 0); }
static void k_ret1_1(void) { RET(1, 1); }
static void k_ret1_2(void) { RET(1, 2); }
static void k_fail_1(void) { g_last_error = ERROR_INVALID_HANDLE; RET(0, 1); }
static void k_fail_2(void) { g_last_error = ERROR_INVALID_HANDLE; RET(0, 2); }
static void k_fail_3(void) { g_last_error = ERROR_INVALID_HANDLE; RET(0, 3); }
static void k_fail_4(void) { g_last_error = ERROR_INVALID_HANDLE; RET(0, 4); }
static void k_fail_8(void) { g_last_error = ERROR_INVALID_HANDLE; RET(0, 8); }
static void k_GetConsoleMode(void) { if (A32(1)) MEM32(A32(1)) = 0; RET(0, 2); }
static void k_GetNumberOfConsoleInputEvents(void) { if (A32(1)) MEM32(A32(1)) = 0; RET(0, 2); }
static void k_WriteConsoleA(void) {                      /* (h, buf, n, &written, reserved) */
    fwrite(APTR(1), 1, A32(2), stderr);
    if (A32(3)) MEM32(A32(3)) = A32(2);
    RET(1, 5);
}

const win32hle_shim win32hle_kernel32[] = {
    { "GetProcessHeap",     k_GetProcessHeap },
    { "GetCommandLineA",    k_GetCommandLineA },
    { "GetCurrentProcess",  k_GetCurrentProcess },
    { "GetCurrentProcessId",k_GetCurrentProcessId },
    { "GetCurrentThreadId", k_GetCurrentThreadId },
    { "ExitProcess",        k_ExitProcess },
    { "TerminateProcess",   k_TerminateProcess },
    { "FatalAppExitA",      k_FatalAppExitA },
    { "CreateProcessA",     k_CreateProcessA },
    { "GetExitCodeProcess", k_GetExitCodeProcess },
    { "GetVersion",         k_GetVersion },
    { "GetVersionExA",      k_GetVersionExA },
    { "HeapCreate",         k_HeapCreate },
    { "HeapDestroy",        k_HeapDestroy },
    { "HeapAlloc",          k_HeapAlloc },
    { "HeapFree",           k_HeapFree },
    { "HeapReAlloc",        k_HeapReAlloc },
    { "HeapSize",           k_HeapSize },
    { "HeapValidate",       k_HeapValidate },
    { "LocalAlloc",         k_LocalAlloc },
    { "LocalFree",          k_LocalFree },
    { "LocalReAlloc",       k_LocalReAlloc },
    { "LocalLock",          k_LocalLock },
    { "LocalUnlock",        k_LocalUnlock },
    { "LocalSize",          k_LocalSize },
    { "GlobalAlloc",        k_GlobalAlloc },
    { "GlobalFree",         k_GlobalFree },
    { "GlobalReAlloc",      k_GlobalReAlloc },
    { "GlobalLock",         k_GlobalLock },
    { "GlobalUnlock",       k_GlobalUnlock },
    { "GlobalSize",         k_GlobalSize },
    { "GlobalHandle",       k_GlobalHandle },
    { "VirtualAlloc",       k_VirtualAlloc },
    { "VirtualFree",        k_VirtualFree },
    { "VirtualProtect",     k_VirtualProtect },
    { "VirtualQuery",       k_VirtualQuery },
    { "IsBadReadPtr",       k_IsBadReadPtr },
    { "IsBadWritePtr",      k_IsBadWritePtr },
    { "IsBadCodePtr",       k_IsBadCodePtr },
    { "FlushInstructionCache", k_FlushInstructionCache },
    { "IsProcessorFeaturePresent", k_IsProcessorFeaturePresent },
    { "GetTickCount",       k_GetTickCount },
    { "QueryPerformanceFrequency", k_QueryPerformanceFrequency },
    { "QueryPerformanceCounter",   k_QueryPerformanceCounter },
    { "Sleep",              k_Sleep },
    { "SleepEx",            k_SleepEx },
    { "GetLastError",       k_GetLastError },
    { "SetLastError",       k_SetLastError },
    { "OutputDebugStringA", k_OutputDebugStringA },
    { "lstrlenA",           k_lstrlenA },
    { "lstrlenW",           k_lstrlenW },
    { "lstrcpyA",           k_lstrcpyA },
    { "lstrcpynA",          k_lstrcpynA },
    { "lstrcatA",           k_lstrcatA },
    { "lstrcmpA",           k_lstrcmpA },
    { "lstrcmpiA",          k_lstrcmpiA },
    { "GetStartupInfoA",    k_GetStartupInfoA },
    { "InitializeCriticalSection", k_InitializeCriticalSection },
    { "DeleteCriticalSection",     k_DeleteCriticalSection },
    { "EnterCriticalSection",      k_EnterCriticalSection },
    { "LeaveCriticalSection",      k_LeaveCriticalSection },
    { "TryEnterCriticalSection",   k_TryEnterCriticalSection },
    { "InterlockedIncrement",      k_InterlockedIncrement },
    { "InterlockedDecrement",      k_InterlockedDecrement },
    { "InterlockedExchange",       k_InterlockedExchange },
    { "InterlockedExchangeAdd",    k_InterlockedExchangeAdd },
    { "InterlockedCompareExchange",k_InterlockedCompareExchange },
    { "CreateEventA",       k_CreateEventA },
    { "SetEvent",           k_SetEvent },
    { "ResetEvent",         k_ResetEvent },
    { "PulseEvent",         k_PulseEvent },
    { "CreateMutexA",       k_CreateMutexA },
    { "OpenMutexA",         k_OpenMutexA },
    { "ReleaseMutex",       k_ReleaseMutex },
    { "CreateSemaphoreA",   k_CreateSemaphoreA },
    { "ReleaseSemaphore",   k_ReleaseSemaphore },
    { "WaitForSingleObject",   k_WaitForSingleObject },
    { "WaitForSingleObjectEx", k_WaitForSingleObjectEx },
    { "WaitForMultipleObjects", k_WaitForMultipleObjects },
    { "TlsAlloc",           k_TlsAlloc },
    { "TlsFree",            k_TlsFree },
    { "TlsGetValue",        k_TlsGetValue },
    { "TlsSetValue",        k_TlsSetValue },
    { "AllocConsole",       k_ret1_0 },
    { "FreeConsole",        k_ret1_0 },
    { "GetConsoleMode",     k_GetConsoleMode },
    { "SetConsoleMode",     k_ret1_2 },
    { "SetConsoleCtrlHandler", k_ret1_2 },
    { "GetNumberOfConsoleInputEvents", k_GetNumberOfConsoleInputEvents },
    { "PeekConsoleInputA",  k_fail_4 },
    { "ReadConsoleInputA",  k_fail_4 },
    { "WriteConsoleA",      k_WriteConsoleA },
    { "SetupComm",          k_fail_3 },
    { "PurgeComm",          k_fail_2 },
    { "ClearCommBreak",     k_fail_1 },
    { "SetCommBreak",       k_fail_1 },
    { "ClearCommError",     k_fail_3 },
    { "EscapeCommFunction", k_fail_2 },
    { "GetCommMask",        k_fail_2 },
    { "GetCommModemStatus", k_fail_2 },
    { "GetCommState",       k_fail_2 },
    { "SetCommState",       k_fail_2 },
    { "SetCommTimeouts",    k_fail_2 },
    { "DeviceIoControl",    k_fail_8 },
    { "GetOverlappedResult",k_fail_4 },
    { "SetPriorityClass",   k_ret1_2 },
    { "SetErrorMode",       k_ret1_1 },
    { 0, 0 }
};

/*
 * kernel32_ext.c - the KERNEL32 file-I/O, Global*, and .ini profile shims a
 * Win32 game touches at startup and while loading/saving. Split from kernel32.c
 * to keep each file readable; registered as its own table. All on libc/POSIX.
 *
 * This batch was chosen because it is both reusable across every Win32 title
 * and testable headless (the selftest round-trips a file, a Global block, and
 * an .ini key). The rest of a given title's import surface (audio, dialogs,
 * the CRT's locale queries) is filled in as a lift actually calls it.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "win32hle.h"

#define INVALID_HANDLE  0xFFFFFFFFu

/* ---- file handles: a small table mapping a HANDLE to a FILE* ---- */
#define MAXF 64
static FILE *g_files[MAXF];
#define FH_BASE 0x00F11E00u
static uint32_t file_open(FILE *f) {
    for (int i = 0; i < MAXF; i++) if (!g_files[i]) { g_files[i] = f; return FH_BASE + (uint32_t)i; }
    fclose(f); return INVALID_HANDLE;
}
static FILE *file_of(uint32_t h) {
    uint32_t i = h - FH_BASE;
    return (h >= FH_BASE && i < MAXF) ? g_files[i] : NULL;
}
static int file_close(uint32_t h) {
    uint32_t i = h - FH_BASE;
    if (h >= FH_BASE && i < MAXF && g_files[i]) { fclose(g_files[i]); g_files[i] = NULL; return 1; }
    return 0;
}

/* CreateFileA(name,access,share,sa,disp,flags,template). access GENERIC_READ
 * 0x80000000, GENERIC_WRITE 0x40000000; disp CREATE_NEW 1, CREATE_ALWAYS 2,
 * OPEN_EXISTING 3, OPEN_ALWAYS 4, TRUNCATE_EXISTING 5. */
static void k_CreateFileA(void) {
    const char *name = ASTR(0);
    uint32_t access = A32(1), disp = A32(4);
    int wr = (access & 0x40000000u) != 0;
    const char *mode;
    switch (disp) {
        case 1: case 2: mode = "wb+"; break;             /* create / create-always */
        case 5:         mode = "wb+"; break;             /* truncate-existing */
        case 4:         mode = wr ? "rb+" : "rb"; break; /* open-always (fallback below) */
        default:        mode = wr ? "rb+" : "rb"; break; /* open-existing */
    }
    FILE *f = name ? fopen(name, mode) : NULL;
    if (!f && disp == 4 && name) f = fopen(name, "wb+");  /* open-always: make it */
    RET(f ? file_open(f) : INVALID_HANDLE, 7);
}

static void k_ReadFile(void) {                           /* (h,buf,n,&read,ovl) */
    FILE *f = file_of(A32(0)); void *buf = APTR(1); uint32_t n = A32(2); uint32_t *pr = (uint32_t *)APTR(3);
    size_t got = f ? fread(buf, 1, n, f) : 0;
    if (pr) *pr = (uint32_t)got;
    RET(f ? 1u : 0u, 5);
}
static void k_WriteFile(void) {                          /* (h,buf,n,&written,ovl) */
    FILE *f = file_of(A32(0)); const void *buf = APTR(1); uint32_t n = A32(2); uint32_t *pw = (uint32_t *)APTR(3);
    size_t put = f ? fwrite(buf, 1, n, f) : 0;
    if (pw) *pw = (uint32_t)put;
    RET(f && put == n ? 1u : 0u, 5);
}
static void k_SetFilePointer(void) {                     /* (h,dist,&distHigh,method) -> new pos */
    FILE *f = file_of(A32(0)); int32_t dist = (int32_t)A32(1); uint32_t method = A32(3);
    int whence = method == 1 ? SEEK_CUR : method == 2 ? SEEK_END : SEEK_SET;
    if (f && fseek(f, dist, whence) == 0) RET((uint32_t)ftell(f), 4);
    RET(INVALID_HANDLE, 4);
}
static void k_SetEndOfFile(void)    { FILE *f = file_of(A32(0)); RET(f ? 1u : 0u, 1); } /* pos already grown by writes */
static void k_FlushFileBuffers(void){ FILE *f = file_of(A32(0)); if (f) fflush(f); RET(f ? 1u : 0u, 1); }
static void k_GetFileSize(void) {                        /* (h,&high) -> low */
    FILE *f = file_of(A32(0)); uint32_t *hi = (uint32_t *)APTR(1);
    long cur, end = 0;
    if (f) { cur = ftell(f); fseek(f, 0, SEEK_END); end = ftell(f); fseek(f, cur, SEEK_SET); }
    if (hi) *hi = 0;
    RET((uint32_t)end, 2);
}
/* CloseHandle also closes non-file handles no-op (heaps, pseudo-handles). */
static void k_CloseHandle(void) { file_close(A32(0)); RET(1, 1); }

/* ---- Global* (we use GMEM_FIXED semantics: HGLOBAL == the pointer) ---- */
#define GMEM_ZEROINIT 0x0040u
static void k_GlobalAlloc(void) { uint32_t fl = A32(0), n = A32(1); RETP(fl & GMEM_ZEROINIT ? calloc(1, n) : malloc(n), 2); }
static void k_GlobalFree(void)  { free(APTR(0)); RET(0, 1); }
static void k_GlobalLock(void)  { RETP(APTR(0), 1); }          /* already a pointer */
static void k_GlobalUnlock(void){ RET(1, 1); }
static void k_GlobalReAlloc(void){ RETP(realloc(APTR(0), A32(1)), 3); }
static void k_GlobalSize(void)  { RET(0, 1); }                 /* unknown; callers rarely trust it */

/* ---- .ini profile: a minimal reader/writer over a flat key=value file ----
 * Enough for a game remembering settings; sections are honoured on read. */
static int ini_find_section(FILE *f, const char *section) {
    char line[512]; char want[256];
    snprintf(want, sizeof want, "[%s]", section);
    rewind(f);
    while (fgets(line, sizeof line, f))
        if (line[0] == '[' && !strncasecmp(line, want, strlen(want))) return 1;
    return 0;
}
static void k_GetPrivateProfileStringA(void) {           /* (sec,key,def,buf,size,file) */
    const char *sec = ASTR(0), *key = ASTR(1), *def = ASTR(2);
    char *buf = ASTR(3); uint32_t size = A32(4); const char *file = ASTR(5);
    const char *val = def ? def : "";
    char line[512];
    FILE *f = file ? fopen(file, "r") : NULL;
    if (f && sec && key && ini_find_section(f, sec)) {
        size_t kl = strlen(key);
        while (fgets(line, sizeof line, f)) {
            if (line[0] == '[') break;                   /* next section */
            if (!strncasecmp(line, key, kl) && line[kl] == '=') {
                char *v = line + kl + 1, *nl = strpbrk(v, "\r\n"); if (nl) *nl = 0;
                static char out[512]; strncpy(out, v, sizeof out - 1); val = out; break;
            }
        }
    }
    if (f) fclose(f);
    if (buf && size) { strncpy(buf, val, size - 1); buf[size - 1] = 0; }
    RET(buf ? (uint32_t)strlen(buf) : 0u, 6);
}
static void k_GetPrivateProfileIntA(void) {              /* (sec,key,def,file) */
    char buf[64] = "", def[16];
    snprintf(def, sizeof def, "%d", (int)A32(2));
    /* reuse the string reader by hand: */
    const char *sec = ASTR(0), *key = ASTR(1), *file = ASTR(3);
    FILE *f = file ? fopen(file, "r") : NULL; char line[512]; int got = 0;
    if (f && sec && key && ini_find_section(f, sec)) {
        size_t kl = strlen(key);
        while (fgets(line, sizeof line, f)) {
            if (line[0] == '[') break;
            if (!strncasecmp(line, key, kl) && line[kl] == '=') { strncpy(buf, line + kl + 1, 63); got = 1; break; }
        }
    }
    if (f) fclose(f);
    RET((uint32_t)atoi(got ? buf : def), 4);
}
/* WritePrivateProfileStringA: simplest correct thing — append the key under a
 * (possibly new) section. A real profile rewrites in place; a game that only
 * ever writes then reads its own keys is served, and the reader takes the first
 * match. Good enough for first-light; a title that rewrites keys gets the
 * in-place version when it needs it. */
static void k_WritePrivateProfileStringA(void) {         /* (sec,key,val,file) */
    const char *sec = ASTR(0), *key = ASTR(1), *val = ASTR(2), *file = ASTR(3);
    if (file && sec && key) {
        FILE *f = fopen(file, "a");
        if (f) { fprintf(f, "[%s]\n%s=%s\n", sec, key, val ? val : ""); fclose(f); }
    }
    RET(1, 4);
}

const win32hle_shim win32hle_kernel32_ext[] = {
    { "CreateFileA",                k_CreateFileA },
    { "ReadFile",                   k_ReadFile },
    { "WriteFile",                  k_WriteFile },
    { "SetFilePointer",             k_SetFilePointer },
    { "SetEndOfFile",               k_SetEndOfFile },
    { "FlushFileBuffers",           k_FlushFileBuffers },
    { "GetFileSize",                k_GetFileSize },
    { "CloseHandle",                k_CloseHandle },
    { "GlobalAlloc",                k_GlobalAlloc },
    { "GlobalFree",                 k_GlobalFree },
    { "GlobalLock",                 k_GlobalLock },
    { "GlobalUnlock",               k_GlobalUnlock },
    { "GlobalReAlloc",              k_GlobalReAlloc },
    { "GlobalSize",                 k_GlobalSize },
    { "GetPrivateProfileStringA",   k_GetPrivateProfileStringA },
    { "GetPrivateProfileIntA",      k_GetPrivateProfileIntA },
    { "WritePrivateProfileStringA", k_WritePrivateProfileStringA },
    { 0, 0 }
};

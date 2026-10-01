/*
 * ns_libc.c - libsys_s (NeXTSTEP's libc) as host shims.
 *
 * Guest pointers are 32-bit VAs: a string argument is GSTR(ARG(n)). stdio
 * FILEs are guest structures (the app's getc/putc macros read _cnt/_ptr
 * directly), so a guest FILE is a 20-byte block whose _cnt stays 0 -- every
 * getc falls through to _filbuf -- mapped to a host FILE by address.
 * Part of the pcrecomp toolbox.
 */
#include "ns_runtime.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <windows.h>
#define chdir _chdir
#else
#include <sys/time.h>
#include <unistd.h>
#define O_BINARY 0
#endif

#define NS_FILE_SIZE 20            /* struct _iobuf on NeXTSTEP 3.x */
static uint32_t g_iob;             /* _iob in libsys: stdin, stdout, stderr */

/* ---- errno --------------------------------------------------------------- */
static void set_errno(int e) {
    static uint32_t va;
    if (!va) va = ns_sym("_errno");
    if (va) MEM32(va) = (uint32_t)e;
}

/* ---- guest FILE <-> host FILE -------------------------------------------- */
#define MAX_FILES 64
static struct { uint32_t va; FILE *f; } g_files[MAX_FILES];

static FILE *host_file(uint32_t va) {
    if (va == g_iob) return stdin;
    if (va == g_iob + NS_FILE_SIZE) return stdout;
    if (va == g_iob + 2 * NS_FILE_SIZE) return stderr;
    for (int i = 0; i < MAX_FILES; i++)
        if (g_files[i].va == va) return g_files[i].f;
    return NULL;
}

/* feof()/ferror() are macros over the guest FILE's _flag (a short at 16):
 * _IOEOF 0x10, _IOERR 0x20. Mirror the host stream into it after each read. */
static void sync_flags(uint32_t va, FILE *f) {
    uint16_t fl = MEM16(va + 16) & ~0x30;
    if (f && feof(f)) fl |= 0x10;
    if (f && ferror(f)) fl |= 0x20;
    MEM16(va + 16) = fl;
}

static uint32_t guest_file(FILE *f) {
    for (int i = 0; i < MAX_FILES; i++)
        if (!g_files[i].va) {
            g_files[i].va = ns_calloc(NS_FILE_SIZE);
            g_files[i].f = f;
            return g_files[i].va;
        }
    fclose(f);
    return 0;
}

/* ---- printf with guest varargs ------------------------------------------- *
 * Walk the format; each conversion pulls its argument from guest memory at
 * `ap` (4 bytes, or 8 for a double or %ll) and is rendered by the host
 * snprintf, one spec at a time. %s takes a guest pointer. */
static int gformat(char *out, size_t cap, const char *fmt, uint32_t ap) {
    size_t n = 0;
#define PUT(s, l) do { size_t _l = (l); if (n + _l < cap) memcpy(out + n, s, _l); n += _l; } while (0)
    while (*fmt) {
        if (*fmt != '%') { PUT(fmt, 1); fmt++; continue; }
        if (fmt[1] == '%') { PUT("%", 1); fmt += 2; continue; }
        char spec[32], tmp[512];
        int k = 0, longs = 0;
        spec[k++] = *fmt++;
        while (*fmt && strchr("-+ #0123456789.*hlLqjzt", *fmt) && k < 28) {
            if (*fmt == '*') {                           /* width/precision from args */
                k += snprintf(spec + k, sizeof spec - k, "%d", (int)MEM32(ap));
                ap += 4; fmt++; continue;
            }
            if (*fmt == 'l' || *fmt == 'q') longs++;
            if (*fmt != 'l' && *fmt != 'q' && *fmt != 'h' && *fmt != 'L')
                spec[k++] = *fmt;
            fmt++;
        }
        char c = *fmt ? *fmt++ : 0;
        int w;
        switch (c) {
        case 'd': case 'i': case 'u': case 'x': case 'X': case 'o': case 'c':
            if (longs >= 2) {
                spec[k++] = 'l'; spec[k++] = 'l'; spec[k++] = c; spec[k] = 0;
                w = snprintf(tmp, sizeof tmp, spec, (long long)MEM64(ap)); ap += 8;
            } else {
                spec[k++] = c; spec[k] = 0;
                w = snprintf(tmp, sizeof tmp, spec, (int)MEM32(ap)); ap += 4;
            }
            break;
        case 'p':
            w = snprintf(tmp, sizeof tmp, "0x%x", MEM32(ap)); ap += 4;
            break;
        case 's': {
            uint32_t s = MEM32(ap); ap += 4;
            spec[k++] = 's'; spec[k] = 0;
            w = snprintf(tmp, sizeof tmp, spec, s ? GSTR(s) : "(null)");
            break;
        }
        case 'f': case 'e': case 'E': case 'g': case 'G':
            spec[k++] = c; spec[k] = 0;
            w = snprintf(tmp, sizeof tmp, spec, MEMD(ap)); ap += 8;
            break;
        case 'n':
            MEM32(MEM32(ap)) = (uint32_t)n; ap += 4;
            continue;
        default:
            continue;
        }
        if (w > (int)sizeof tmp - 1) w = sizeof tmp - 1;
        if (w > 0) PUT(tmp, (size_t)w);
    }
    if (cap) out[n < cap ? n : cap - 1] = 0;
    return (int)n;
#undef PUT
}

static char g_fmtbuf[65536];

static void sh_printf(void)   { int n = gformat(g_fmtbuf, sizeof g_fmtbuf, GSTR(ARG(0)), g_esp + 8);
                                fwrite(g_fmtbuf, 1, n, stdout); NS_RET(n); }
static void sh_fprintf(void)  { FILE *f = host_file(ARG(0));
                                int n = gformat(g_fmtbuf, sizeof g_fmtbuf, GSTR(ARG(1)), g_esp + 12);
                                if (f) fwrite(g_fmtbuf, 1, n, f); NS_RET(n); }
static void sh_sprintf(void)  { int n = gformat(g_fmtbuf, sizeof g_fmtbuf, GSTR(ARG(1)), g_esp + 12);
                                memcpy(GSTR(ARG(0)), g_fmtbuf, n + 1); NS_RET(n); }
static void sh_vsprintf(void) { int n = gformat(g_fmtbuf, sizeof g_fmtbuf, GSTR(ARG(1)), ARG(2));
                                memcpy(GSTR(ARG(0)), g_fmtbuf, n + 1); NS_RET(n); }

/* ---- scanf: host vsscanf with each guest pointer translated -------------- */
static int gscan(const char *src, const char *fmt, uint32_t ap, int *consumed) {
    void *p[16];
    char hfmt[512];
    int np = 0, k = 0;
    for (const char *f = fmt; *f && k < 500; f++) {
        hfmt[k++] = *f;
        if (*f != '%') continue;
        if (f[1] == '%') { hfmt[k++] = *++f; continue; }
        int suppress = f[1] == '*';
        while (f[1] && !isalpha((unsigned char)f[1]) && f[1] != '[') hfmt[k++] = *++f;
        while (f[1] == 'l' || f[1] == 'h') hfmt[k++] = *++f;
        if (f[1] == '[') { do hfmt[k++] = *++f; while (f[1] && f[1] != ']'); if (f[1]) hfmt[k++] = *++f; }
        else if (f[1]) hfmt[k++] = *++f;
        if (!suppress && np < 16) { p[np++] = GUEST(MEM32(ap)); ap += 4; }
    }
    hfmt[k++] = '%'; hfmt[k++] = 'n'; hfmt[k] = 0;
    int used = 0;
    void *q[16] = {0};
    for (int i = 0; i < np; i++) q[i] = p[i];
    q[np] = &used;
    int r = sscanf(src, hfmt, q[0], q[1], q[2], q[3], q[4], q[5], q[6], q[7],
                   q[8], q[9], q[10], q[11], q[12], q[13], q[14], q[15]);
    if (consumed) *consumed = used;
    return r;
}

static void sh_sscanf(void) { NS_RET(gscan(GSTR(ARG(0)), GSTR(ARG(1)), g_esp + 12, NULL)); }

/* ponytail: fscanf reads one line and scans it; a format spanning lines would
 * need the unread tail pushed back. Doom's config reader is one item a line. */
static void sh_fscanf(void) {
    FILE *f = host_file(ARG(0));
    char line[4096];
    long at = f ? ftell(f) : 0;
    if (!f || !fgets(line, sizeof line, f)) { sync_flags(ARG(0), f); NS_RET(-1); return; }
    int used = 0, r = gscan(line, GSTR(ARG(1)), g_esp + 12, &used);
    fseek(f, at + used, SEEK_SET);
    if (fgetc(f) != EOF) fseek(f, -1, SEEK_CUR);         /* sets EOF if nothing is left */
    sync_flags(ARG(0), f);
    NS_RET(r);
}

/* ---- stdio --------------------------------------------------------------- */
static void sh_fopen(void) {
    const char *mode = GSTR(ARG(1));
    char m[8];
    snprintf(m, sizeof m, "%s%s", mode, strchr(mode, 'b') ? "" : "b");
    FILE *f = fopen(ns_host_path(GSTR(ARG(0))), m);
    if (!f) set_errno(errno);
    NS_RET(f ? guest_file(f) : 0);
}
static void sh_fclose(void) {
    uint32_t va = ARG(0);
    for (int i = 0; i < MAX_FILES; i++)
        if (g_files[i].va == va) { fclose(g_files[i].f); g_files[i].va = 0; NS_RET(0); return; }
    NS_RET(-1);
}
static void sh_filbuf(void) {
    uint32_t va = ARG(0);
    FILE *f = host_file(va);
    MEM32(va) = 0;                                       /* _cnt: next getc lands here again */
    int c = f ? fgetc(f) : -1;
    sync_flags(va, f);
    NS_RET(c);
}
static void sh_setbuf(void) { NS_RET(0); }

/* ---- fds ------------------------------------------------------------------ */
static int host_oflags(uint32_t f) {                     /* NeXT (4.3BSD) values */
    int o = O_BINARY | (f & 3);
    if (f & 0x008) o |= O_APPEND;
    if (f & 0x200) o |= O_CREAT;
    if (f & 0x400) o |= O_TRUNC;
    if (f & 0x800) o |= O_EXCL;
    return o;
}
static void sh_open(void)  { int r = open(ns_host_path(GSTR(ARG(0))), host_oflags(ARG(1)), 0666);
                             if (r < 0) set_errno(errno); NS_RET(r); }
static void sh_close(void) { NS_RET(close((int)ARG(0))); }
static void sh_read(void)  { NS_RET(read((int)ARG(0), GUEST(ARG(1)), ARG(2))); }
static void sh_write(void) { NS_RET(write((int)ARG(0), GUEST(ARG(1)), ARG(2))); }
static void sh_lseek(void) { NS_RET(lseek((int)ARG(0), (long)ARG(1), (int)ARG(2))); }
static void sh_access(void){ NS_RET(access(ns_host_path(GSTR(ARG(0))), (int)ARG(1) & 6)); }
static void sh_chdir(void) { NS_RET(chdir(ns_host_path(GSTR(ARG(0))))); }

/* struct stat on NeXTSTEP 3.x: st_mode is a short at 8, st_size a long at 20. */
static void sh_fstat(void) {
    struct stat st;
    int r = fstat((int)ARG(0), &st);
    uint8_t *g = GUEST(ARG(1));
    memset(g, 0, 64);
    if (!r) {
        *(uint16_t *)(g + 8) = (uint16_t)st.st_mode;
        *(uint32_t *)(g + 20) = (uint32_t)st.st_size;
        *(uint32_t *)(g + 24) = (uint32_t)st.st_mtime;
    }
    NS_RET(r);
}

/* ---- memory and strings -------------------------------------------------- */
static void sh_malloc(void)  { NS_RET(ns_malloc(ARG(0))); }
static void sh_valloc(void)  { uint32_t va = ns_malloc(ARG(0) + 4096);
                               NS_RET((va + 4095) & ~4095u); }
static void sh_free(void)    { NS_RET(0); }
static void sh_realloc(void) { NS_RET(ns_realloc(ARG(0), ARG(1))); }
static void sh_memset(void)  { memset(GUEST(ARG(0)), (int)ARG(1), ARG(2)); NS_RET(ARG(0)); }
static void sh_memcpy(void)  { memmove(GUEST(ARG(0)), GUEST(ARG(1)), ARG(2)); NS_RET(ARG(0)); }
static void sh_strcpy(void)  { strcpy(GSTR(ARG(0)), GSTR(ARG(1))); NS_RET(ARG(0)); }
static void sh_strncpy(void) { strncpy(GSTR(ARG(0)), GSTR(ARG(1)), ARG(2)); NS_RET(ARG(0)); }
static void sh_strcat(void)  { strcat(GSTR(ARG(0)), GSTR(ARG(1))); NS_RET(ARG(0)); }
static void sh_strcmp(void)  { NS_RET(strcmp(GSTR(ARG(0)), GSTR(ARG(1)))); }
static void sh_strncmp(void) { NS_RET(strncmp(GSTR(ARG(0)), GSTR(ARG(1)), ARG(2))); }
static int ci_cmp(const char *a, const char *b, size_t n) {
    for (; n; n--, a++, b++) {
        int d = tolower((unsigned char)*a) - tolower((unsigned char)*b);
        if (d || !*a) return d;
    }
    return 0;
}
static void sh_strcasecmp(void)  { NS_RET(ci_cmp(GSTR(ARG(0)), GSTR(ARG(1)), (size_t)-1)); }
static void sh_strncasecmp(void) { NS_RET(ci_cmp(GSTR(ARG(0)), GSTR(ARG(1)), ARG(2))); }
static void sh_strlen(void)  { NS_RET(strlen(GSTR(ARG(0)))); }
static void sh_atoi(void)    { NS_RET(atoi(GSTR(ARG(0)))); }
static void sh_strerror(void) {
    static uint32_t buf;
    if (!buf) buf = ns_malloc(256);
    snprintf(GSTR(buf), 256, "%s", strerror((int)ARG(0)));
    NS_RET(buf);
}

/* ---- process and time ---------------------------------------------------- */
static void sh_exit(void) { fflush(NULL); exit((int)ARG(0)); }
static void sh_gettimeofday(void) {
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    uint64_t t = (((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime) / 10 - 11644473600000000ull;
    if (ARG(0)) { MEM32(ARG(0)) = (uint32_t)(t / 1000000); MEM32(ARG(0) + 4) = (uint32_t)(t % 1000000); }
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    if (ARG(0)) { MEM32(ARG(0)) = (uint32_t)tv.tv_sec; MEM32(ARG(0) + 4) = (uint32_t)tv.tv_usec; }
#endif
    NS_RET(0);
}
static void sh_usleep(void) {
#ifdef _WIN32
    Sleep(ARG(0) / 1000);
#else
    usleep(ARG(0));
#endif
    NS_RET(0);
}

/* ---- sockets: no network yet ---------------------------------------------- *
 * ponytail: every call fails, which Doom reads as "no netgame". Map to host
 * sockets when multiplayer matters. */
static void sh_fail(void) { set_errno(EINVAL); NS_RET(-1); }
static void sh_null(void) { NS_RET(0); }

static const ns_shim_t libc_shims[] = {
    { "_printf", sh_printf },       { "_fprintf", sh_fprintf },
    { "_sprintf", sh_sprintf },     { "_vsprintf", sh_vsprintf },
    { "_sscanf", sh_sscanf },       { "_fscanf", sh_fscanf },
    { "_fopen", sh_fopen },         { "_fclose", sh_fclose },
    { "__filbuf", sh_filbuf },      { "_setbuf", sh_setbuf },
    { "_open", sh_open },           { "_close", sh_close },
    { "_read", sh_read },           { "_write", sh_write },
    { "_lseek", sh_lseek },         { "_fstat", sh_fstat },
    { "_access", sh_access },       { "_chdir", sh_chdir },
    { "_malloc", sh_malloc },       { "_valloc", sh_valloc },
    { "_free", sh_free },           { "_vfree", sh_free },
    { "_realloc", sh_realloc },
    { "_memset", sh_memset },       { "_memcpy", sh_memcpy },
    { "_bcopy", sh_memcpy },
    { "_strcpy", sh_strcpy },       { "_strncpy", sh_strncpy },
    { "_strcat", sh_strcat },       { "_strcmp", sh_strcmp },
    { "_strncmp", sh_strncmp },     { "_strcasecmp", sh_strcasecmp },
    { "_strncasecmp", sh_strncasecmp },
    { "_strlen", sh_strlen },       { "_atoi", sh_atoi },
    { "_strerror", sh_strerror },
    { "_exit", sh_exit },           { "_gettimeofday", sh_gettimeofday },
    { "_usleep", sh_usleep },
    { "_socket", sh_fail },         { "_bind", sh_fail },
    { "_sendto", sh_fail },         { "_recvfrom", sh_fail },
    { "_ioctl", sh_fail },          { "_gethostbyname", sh_null },
    { "_inet_addr", sh_fail },
    { NULL, NULL }
};

void ns_libc_init(void) {
    g_iob = ns_sym("__iob");
    ns_register(libc_shims);
}

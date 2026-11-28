/* host.c - the Win16 identity runtime's portable host (RECOMP_W16_BASED): what native32 and
 * vxd32 give identity.c and drv16.c on Windows, in plain C, for a host with no Windows under
 * it (the 3DS; and a PC build of the same, which is how it is tested).
 *
 *   memory   one arena; guest linear L is host g_w16_mem + L (cpu.h W16_P / W16_A). L 0 to
 *            110000h is the first megabyte a DOS box has (identity.c w16_real_base); DPMI
 *            blocks come from the top down, as they lie above a DOS-loaded KRNL386.
 *   LDT      vxd32's, unchanged: a 64 KB descriptor table the guest also writes itself.
 *   DOS      int 21h's file services on the host's files, every path boxed under a root
 *            directory that is the guest's C:\ (w16_host_init).
 *   tasks    identity.c runs each Win16 task on a fiber: Windows' on a PC, a small ARM
 *            context switch on the 3DS.
 *   idle     the guest idles (int 28h, int 2Fh 1689h): drv16_poll delivers the tick, timers
 *            and input, then the platform's w16_platform_idle shows the screen.
 * Win98's paths (kernel32, VWIN32, the registry) are not here: identity.c leaves them out. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include "cpu.h"
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <io.h>
#include <direct.h>
#define open _open
#define close _close
#define read _read
#define write _write
#define lseek _lseek
#define strcasecmp _stricmp
#define mkdir(p, m) _mkdir(p)
#define rmdir _rmdir
static int ftrunc(int fd, long n) { return _chsize(fd, n); }
#else
#include <unistd.h>
#include <dirent.h>
#include <strings.h>
static int ftrunc(int fd, long n) { return ftruncate(fd, n); }
#ifndef O_BINARY
#define O_BINARY 0
#endif
#endif
#ifdef __3DS__
#include <3ds.h>
#endif

#define MEM8(a)  (*(uint8_t *)W16_P(a))
#define MEM16(a) (*(uint16_t *)W16_P(a))
#define MEM32(a) (*(uint32_t *)W16_P(a))
#define SET16(r, v) ((r) = ((r) & 0xFFFF0000u) | (uint16_t)(v))
#define SET8L(r, v) ((r) = ((r) & 0xFFFFFF00u) | (uint8_t)(v))

void drv16_poll(void);
void w16_platform_idle(void);   /* the platform: show the screen, read input, give the CPU up a moment */

/* ---- the 32-bit register file identity.c's int 21h path passes through (native32's) ---- */
uint32_t g_eax, g_ecx, g_edx, g_ebx, g_esp, g_ebp, g_esi, g_edi;
uint32_t g_ss_base, g_ds_base, g_es_base, g_cs_base, g_fs_base, g_gs_base;
uint16_t g_seg_cs, g_seg_ss, g_seg_ds, g_seg_es, g_seg_fs, g_seg_gs;
static int g_cf;
void recomp_set_seg(int sreg, uint32_t sel) {
    sel &= 0xFFFF;
    if (sreg == 0) { g_seg_es = (uint16_t)sel; g_es_base = recomp_sel_base(sel); }
    if (sreg == 2) { g_seg_ss = (uint16_t)sel; g_ss_base = recomp_sel_base(sel); }
    if (sreg == 3) { g_seg_ds = (uint16_t)sel; g_ds_base = recomp_sel_base(sel); }
    if (sreg == 4) { g_seg_fs = (uint16_t)sel; g_fs_base = recomp_sel_base(sel); }
    if (sreg == 5) { g_seg_gs = (uint16_t)sel; g_gs_base = recomp_sel_base(sel); }
}
/* No 32-bit code is lifted: nothing to find. */
typedef void (*w16_fn32)(void);
w16_fn32 recomp_lookup(uint32_t va) { (void)va; return NULL; }

static void host_stop(const char *what, unsigned a) {
    fprintf(stderr, "\n[host] %s %X\n", what, a);
    fflush(stderr);
    exit(5);
}

/* ---- the arena ---- */
uint8_t *g_w16_mem;
static uint32_t g_arena_size, g_arena_top, g_arena_low;   /* blocks from the top down to g_arena_low */
#define REALMODE_END 0x110000u
static void *g_arena_block;

/* Milliseconds since the host started (the guest's tick count starts near 0, as after a boot). */
static uint32_t host_ms_raw(void) {
#if defined(__3DS__)
    return (uint32_t)osGetTime();
#elif defined(_WIN32)
    return GetTickCount();
#else
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint32_t)(t.tv_sec * 1000 + t.tv_nsec / 1000000);
#endif
}
uint32_t w16_host_ms(void) {
    static uint32_t t0;
    if (!t0) t0 = host_ms_raw() - 1;
    return host_ms_raw() - t0;
}

/* A block of n bytes, zeroed, 16-byte aligned; its guest linear address. ponytail: a bump
 * allocator from the top; a free gives back only the most recent block (KRNL386 allocates
 * its heap once and keeps it). */
static uint32_t g_last_block, g_last_size;
uint32_t w16_host_alloc(uint32_t n) {
    uint32_t sz = (n + 0xFFFu) & ~0xFFFu;
    if (!sz || g_arena_top - g_arena_low < sz) {
        fprintf(stderr, "[host] arena: no %u bytes (%u left)\n", n, g_arena_top - g_arena_low);
        return 0;
    }
    g_arena_top -= sz;
    memset(W16_P(g_arena_top), 0, sz);
    g_last_block = g_arena_top; g_last_size = sz;
    if (getenv("W16_TRACE")) fprintf(stderr, "[host] alloc %u at %08X\n", n, g_arena_top);
    return g_arena_top;
}
void w16_host_free(uint32_t a) {
    if (a && a == g_last_block) { g_arena_top += g_last_size; g_last_block = 0; }
}
/* The largest block the guest may still have, less room for the host's own later blocks. */
uint32_t w16_host_free_bytes(void) {
    uint32_t f = g_arena_top - g_arena_low;
    return f > (4u << 20) ? f - (4u << 20) : 0;
}
int w16_host_mapped(uint32_t a, uint32_t n) { return a < g_arena_size && n <= g_arena_size - a; }

/* ---- the LDT (vxd32.c's, unchanged in substance) ---- */
static uint8_t g_ldt[0x10000];
static uint16_t g_ldt_alias;
static uint16_t g_next_sel = 0x0087;
#define HOST_POOL 0xF800u
static uint16_t g_pool_next = HOST_POOL;

void native32_w9x_ldt(uint16_t alias_sel, uint32_t *ldt_base) {
    g_ldt_alias = alias_sel & ~7; *ldt_base = W16_A(g_ldt);
    uint8_t *d = g_ldt + g_ldt_alias; uint32_t b = *ldt_base;
    d[0] = d[1] = 0xFF; d[2] = (uint8_t)b; d[3] = (uint8_t)(b >> 8); d[4] = (uint8_t)(b >> 16); d[7] = (uint8_t)(b >> 24);
    d[5] = 0xF2; d[6] = 0x40;
    for (unsigned i = HOST_POOL; i < 0x10000; i += 8) { g_ldt[i + 5] = 0xF2; g_ldt[i + 6] = 0x40; }
}
uint32_t (*g_w9x_np_hook)(uint16_t sel);
uint32_t recomp_sel_base(uint32_t sel) {
    sel &= 0xFFFF;
    if ((sel & ~7u) == g_ldt_alias) return W16_A(g_ldt);
    if (!(sel & 4)) return 0;
    const uint8_t *d = g_ldt + (sel & ~7u);
    return d[2] | d[3] << 8 | d[4] << 16 | (uint32_t)d[7] << 24;
}
uint32_t recomp_sel_access_base(uint32_t sel) {
    const uint8_t *d = g_ldt + (sel & 0xFFF8u);
    uint32_t b;
    if ((sel & 4) && !(d[5] & 0x80) && (d[5] & 0x10) && g_w9x_np_hook && (sel & 0xFFF8u) != g_ldt_alias && (b = g_w9x_np_hook((uint16_t)sel)))
        return b;
    return recomp_sel_base(sel);
}
static void put_desc(uint8_t *d, uint32_t base, uint32_t limit) {
    d[0] = (uint8_t)limit; d[1] = (uint8_t)(limit >> 8);
    d[2] = (uint8_t)base; d[3] = (uint8_t)(base >> 8); d[4] = (uint8_t)(base >> 16); d[7] = (uint8_t)(base >> 24);
}
uint16_t native32_w9x_alloc_sel(uint32_t base, uint32_t limit) {
    while (g_next_sel > 7 && g_next_sel < HOST_POOL && (*(uint32_t *)(g_ldt + (g_next_sel & ~7u)) || *(uint32_t *)(g_ldt + (g_next_sel & ~7u) + 4)))
        g_next_sel += 8;
    if (g_next_sel <= 7 || g_next_sel >= HOST_POOL) {
        if (!g_pool_next) host_stop("host selector pool empty", 0);
        uint16_t ps = (uint16_t)(g_pool_next | 7);
        g_pool_next = (uint16_t)(g_pool_next + 8);
        uint8_t *pd = g_ldt + (ps & ~7u);
        put_desc(pd, base, limit);
        pd[5] = 0xF2; pd[6] = (uint8_t)((limit >> 16) & 0x0F) | 0x40;
        return ps;
    }
    uint16_t sel = g_next_sel;
    uint8_t *d = g_ldt + (sel & ~7u);
    g_next_sel += 8;
    put_desc(d, base, limit);
    d[5] = 0xF2; d[6] = (uint8_t)((limit >> 16) & 0x0F) | 0x40;
    return sel;
}
void native32_w9x_set_sel(uint16_t sel, uint32_t base, uint32_t limit, int code) {
    uint8_t *d = g_ldt + (sel & ~7u);
    put_desc(d, base, limit);
    d[5] = code ? 0xFA : 0xF2;
    d[6] = (uint8_t)((limit >> 16) & 0x0F);
    if ((uint16_t)((sel | 7) + 8) > g_next_sel) g_next_sel = (uint16_t)((sel | 7) + 8);
}
uint8_t *native32_w9x_desc(uint16_t sel) { return g_ldt + (sel & ~7u); }
uint16_t native32_w9x_next_sel(void) { return g_next_sel; }
uint16_t native32_w9x_ldt_alias(void) { return (uint16_t)(g_ldt_alias | 7); }
static const uint8_t *ldt_desc_any(uint16_t sel) {
    if (!(sel & 4) || (sel & ~7u) == g_ldt_alias) return NULL;
    const uint8_t *d = g_ldt + (sel & ~7u);
    if (!(d[5] & 0x10)) return NULL;
    return ((d[5] >> 5 & 3) == 3 || (d[5] & 0x0C) == 0x0C) ? d : NULL;
}
int recomp_lsl32(uint16_t sel, uint32_t *limit) {
    if ((sel & ~7u) == g_ldt_alias) { *limit = sizeof g_ldt - 1; return 1; }
    const uint8_t *d = ldt_desc_any(sel);
    if (!d) return 0;
    uint32_t l = d[0] | d[1] << 8 | (uint32_t)(d[6] & 0x0F) << 16;
    *limit = (d[6] & 0x80) ? (l << 12) | 0xFFF : l;
    return 1;
}
int recomp_lar32(uint16_t sel, uint32_t *rights) {
    if ((sel & ~7u) == g_ldt_alias) { *rights = 0x00C0F200u; return 1; }
    const uint8_t *d = ldt_desc_any(sel);
    if (!d) return 0;
    *rights = ((uint32_t)d[5] << 8 | (uint32_t)(d[6] & 0xF0) << 16);
    return 1;
}

/* ---- idle: the guest has nothing to do (int 28h, int 2Fh 1689h) ---- */
void native32_w9x_yield(void) {
    drv16_poll();
    w16_platform_idle();
}

/* ---- fibers ---- */
#ifdef _WIN32
typedef struct { void (*fn)(void *); void *arg; } fstart;
static void CALLBACK fiber_main(void *p) { fstart s = *(fstart *)p; free(p); s.fn(s.arg); }
void *w16_fiber_self(void) { if (!IsThreadAFiber()) ConvertThreadToFiber(NULL); return GetCurrentFiber(); }
void *w16_fiber_new(void (*fn)(void *), void *arg) {
    fstart *s = malloc(sizeof *s); s->fn = fn; s->arg = arg;
    return CreateFiberEx(0x10000, 16u << 20, FIBER_FLAG_FLOAT_SWITCH, fiber_main, s);
}
void w16_fiber_switch(void *to) { SwitchToFiber(to); }
#elif defined(__arm__)
/* r4-r11, sp, lr and d8-d15: what the AAPCS has a callee keep. */
typedef struct { uint32_t r[10]; double d[8]; } w16_ctx;
void w16_ctx_swap(w16_ctx *from, w16_ctx *to);
__asm__(
    ".text\n.align 2\n.global w16_ctx_swap\n.type w16_ctx_swap, %function\n"
    "w16_ctx_swap:\n"
    "  stmia r0!, {r4-r11}\n  mov r2, sp\n  stmia r0!, {r2, lr}\n  vstmia r0, {d8-d15}\n"
    "  ldmia r1!, {r4-r11}\n  ldmia r1!, {r2, lr}\n  mov sp, r2\n  vldmia r1, {d8-d15}\n  bx lr\n"
    ".global w16_ctx_start\n.type w16_ctx_start, %function\n"
    "w16_ctx_start:\n  mov r0, r5\n  blx r4\n  bl abort\n");
void w16_ctx_start(void);
typedef struct { w16_ctx c; uint8_t *stack; } w16_fiber;
static w16_fiber g_main_fiber, *g_cur_fiber;
/* Each task's C stack: lifted loops that span functions recurse on it (identity.c). */
#ifndef W16_FIBER_STACK
#define W16_FIBER_STACK (1u << 20)
#endif
void *w16_fiber_self(void) { if (!g_cur_fiber) g_cur_fiber = &g_main_fiber; return g_cur_fiber; }
void *w16_fiber_new(void (*fn)(void *), void *arg) {
    w16_fiber *f = calloc(1, sizeof *f);
    f->stack = malloc(W16_FIBER_STACK);
    if (!f->stack) host_stop("no memory for a task's stack", W16_FIBER_STACK);
    f->c.r[0] = (uint32_t)(uintptr_t)fn; f->c.r[1] = (uint32_t)(uintptr_t)arg;   /* r4, r5 */
    f->c.r[8] = (uint32_t)(uintptr_t)(f->stack + W16_FIBER_STACK - 16);         /* sp */
    f->c.r[9] = (uint32_t)(uintptr_t)w16_ctx_start;                             /* lr */
    return f;
}
void w16_fiber_switch(void *to) {
    w16_fiber *from = w16_fiber_self();
    g_cur_fiber = to;
    w16_ctx_swap(&from->c, &((w16_fiber *)to)->c);
}
#else
#error "no fibers for this host"
#endif

/* ---- DOS ---- */
static char g_root[512];      /* the host directory that is C:\ */
static char g_cwd[260];       /* guest, no drive, no leading '\' */
static uint16_t g_cur_psp;
static uint16_t g_dos_err;
const char *native32_w9x_cwd(void) { return g_cwd; }
void native32_w9x_set_psp(uint16_t sel) { g_cur_psp = sel; }
static void dos_fail(uint16_t err) { SET16(g_eax, err); g_cf = 1; g_dos_err = err; }

/* guest path (flat) -> host path under g_root, '.' and '..' resolved; 0 if it leaves C:\ */
static int g_path_err = 3;
static int host_path(uint32_t guest, char *out, size_t outn) {
    char g[260], *p = g;
    size_t i = 0;
    for (; i + 1 < sizeof g && MEM8(guest + i); i++) g[i] = (char)MEM8(guest + i);
    g[i] = 0;
    g_path_err = 3;
    if (p[0] && p[1] == ':') {
        if ((p[0] | 0x20) != 'c') { g_path_err = 15; return 0; }
        p += 2;
    }
    char full[600];
    if (*p == '\\' || *p == '/') snprintf(full, sizeof full, "%s", p + 1);
    else snprintf(full, sizeof full, "%s%s%s", g_cwd, g_cwd[0] ? "\\" : "", p);
    /* components: split on either slash, resolve . and .. */
    char *comp[64]; int n = 0;
    for (char *t = strtok(full, "\\/"); t; t = strtok(NULL, "\\/")) {
        if (!strcmp(t, ".")) continue;
        if (!strcmp(t, "..")) { if (!n) return 0; n--; continue; }
        if (n == 64) return 0;
        comp[n++] = t;
    }
    size_t o = (size_t)snprintf(out, outn, "%s", g_root);
    for (int k = 0; k < n && o < outn; k++) o += (size_t)snprintf(out + o, outn - o, "/%s", comp[k]);
    if (getenv("W16_TRACE")) fprintf(stderr, "[int21]   \"%s\" -> %s\n", g, out);
    return o < outn;
}
static int dos_device(uint32_t guest) {
    char g[300], *b = g;
    size_t i = 0;
    for (; i + 1 < sizeof g && MEM8(guest + i); i++) g[i] = (char)MEM8(guest + i);
    g[i] = 0;
    for (char *q = g; *q; q++) if (*q == '\\' || *q == ':' || *q == '/') b = q + 1;
    char *dot = strchr(b, '.');
    if (dot) *dot = 0;
    static const char *const dev[] = { "CON", "NUL", "AUX", "PRN", "COM1", "COM2", "COM3", "COM4", "LPT1", "LPT2", "LPT3" };
    for (unsigned k = 0; k < sizeof dev / sizeof *dev; k++) if (!strcasecmp(b, dev[k])) return 1;
    return 0;
}
static void guest_put(uint32_t va, const char *s, size_t max) {
    size_t i = 0;
    for (; s[i] && i + 1 < max; i++) MEM8(va + i) = (uint8_t)s[i];
    MEM8(va + i) = 0;
}

/* DOS handles: 0-4 the standard devices, 5 on host files (fd) or the null device (-2). */
#define NHANDLES 256
static int g_fd[NHANDLES];
static int new_handle(int fd) {
    for (int i = 5; i < NHANDLES; i++) if (!g_fd[i]) { g_fd[i] = fd; return i; }
    if (fd >= 0) close(fd);
    return -1;
}
static int fd_of(uint16_t h) { return h < NHANDLES && h > 4 ? g_fd[h] : 0; }
static uint16_t errno_dos(void) {
    switch (errno) { case 2: return 2; case 13: return 5; case 24: return 4; case 17: return 80; default: return 5; }
}
static void dos_time(time_t t, uint16_t *date, uint16_t *tim) {
    struct tm *l = localtime(&t);
    if (!l || l->tm_year < 80) { *date = (0 << 9) | (1 << 5) | 1; *tim = 0; return; }
    *date = (uint16_t)((l->tm_year - 80) << 9 | (l->tm_mon + 1) << 5 | l->tm_mday);
    *tim = (uint16_t)(l->tm_hour << 11 | l->tm_min << 5 | l->tm_sec / 2);
}

static uint8_t g_dta_default[128];
static uint32_t g_dta;

/* Find first/next: one directory listing per search, matched against an 8.3 spec. */
#define NFINDS 32
static struct { char dir[512]; char spec[16]; uint16_t attr; int pos, root, used; } g_find[NFINDS];
static int wild_match(const char *pat, const char *s) {   /* DOS: * and ?, no case */
    if (!*pat) return !*s;
    if (*pat == '*') { for (;;) { if (wild_match(pat + 1, s)) return 1; if (!*s) return 0; s++; } }
    if (!*s) return !strcmp(pat, ".") || !strcmp(pat, "*");
    if (*pat == '?' || toupper((unsigned char)*pat) == toupper((unsigned char)*s)) return wild_match(pat + 1, s + 1);
    if (*pat == '.' && !strchr(s, '.')) return wild_match(pat + 1, s);   /* "NAME." / "*.*" match "NAME" */
    return 0;
}
/* the nth name in dir (0, 1, ...): 1 with *name/*st filled, 0 past the end */
static int list_nth(const char *dir, int n, char *name, size_t nn) {
#ifdef _WIN32
    char p[600]; snprintf(p, sizeof p, "%s/*", dir);
    WIN32_FIND_DATAA fd; HANDLE h = FindFirstFileA(p, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    for (int i = 0; ; i++) {
        if (i == n) { snprintf(name, nn, "%s", fd.cFileName); FindClose(h); return 1; }
        if (!FindNextFileA(h, &fd)) { FindClose(h); return 0; }
    }
#else
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *e; int i = 0;
    while ((e = readdir(d))) if (i++ == n) { snprintf(name, nn, "%s", e->d_name); closedir(d); return 1; }
    closedir(d);
    return 0;
#endif
}
static int find_step(int h) {   /* the next match into the DTA; 0 when none is left */
    uint32_t dta = g_dta;
    char name[260], p[800];
    while (list_nth(g_find[h].dir, g_find[h].pos++, name, sizeof name)) {
        if (g_find[h].root && (!strcmp(name, ".") || !strcmp(name, ".."))) continue;
        if (!wild_match(g_find[h].spec, name) || strlen(name) > 12) continue;
        snprintf(p, sizeof p, "%s/%s", g_find[h].dir, name);
        struct stat st;
        if (stat(p, &st)) continue;
        uint16_t at = (st.st_mode & S_IFDIR) ? 0x10 : 0x20;
        uint16_t may = (g_find[h].attr & 0xFF) | 0x21;
        if (at & ~may & 0x16) continue;
        uint16_t d, t; dos_time(st.st_mtime, &d, &t);
        MEM8(dta + 0x15) = (uint8_t)at;
        MEM16(dta + 0x16) = t; MEM16(dta + 0x18) = d; MEM32(dta + 0x1A) = (uint32_t)st.st_size;
        char n83[13]; int i = 0;
        for (; name[i] && i < 12; i++) n83[i] = (char)toupper((unsigned char)name[i]);
        n83[i] = 0;
        guest_put(dta + 0x1E, n83, 13);
        return 1;
    }
    return 0;
}
static int is_dir(const char *p) { struct stat st; return !stat(p, &st) && (st.st_mode & S_IFDIR); }

static void int21_unknown(uint16_t ax) {
    fprintf(stderr, "\n[host] int 21h: unknown AX=%04X (ebx=%08X ecx=%08X edx=%08X)\n", ax, g_ebx, g_ecx, g_edx);
    fflush(stderr);
    exit(5);
}

/* identity.c dos_int21 has put flat pointers in the globals (ds:dx -> g_edx, ds:si -> g_esi,
 * es:di -> g_edi). Returns CF. */
int native32_w9x_int21(uint32_t eax, uint32_t ecx) {
    char path[600], path2[600];
    (void)ecx;
    if (!g_dta) g_dta = W16_A(g_dta_default);
    g_eax = eax; g_cf = 0;
    uint8_t ah = (uint8_t)(eax >> 8), al = (uint8_t)eax;
    if (getenv("W16_TRACE")) fprintf(stderr, "[int21] AX=%04X ebx=%08X ecx=%08X edx=%08X\n", (uint16_t)eax, g_ebx, g_ecx, g_edx);
    switch (ah) {
    case 0x0D: return 0;
    case 0x0E: SET8L(g_eax, 26); return 0;
    case 0x19: SET8L(g_eax, 2); return 0;
    case 0x1A: g_dta = g_edx; return 0;
    case 0x2F: g_ebx = g_dta; return 0;
    case 0x30: SET16(g_eax, 0x0A07); SET16(g_ebx, 0xFF00); return 0;   /* DOS 7.10 */
    case 0x4B:   /* DOS exec (not a Windows module): no DOS VM */
        if (al == 0) { struct stat st; dos_fail(host_path(g_edx, path, sizeof path) && !stat(path, &st) ? 5 : 2); return 1; }
        break;
    case 0x1C: {   /* drive allocation: a fixed 2 GB drive */
        static uint8_t media = 0xF8;
        uint8_t d = (uint8_t)g_edx;
        if (d != 0 && d != 3) { SET8L(g_eax, 0xFF); return 0; }
        SET8L(g_eax, 64); SET16(g_ecx, 512); SET16(g_edx, 0xFFFF); g_ebx = W16_A(&media);
        return 0;
    }
    case 0x36: {   /* free space: half of that drive */
        uint8_t d = (uint8_t)g_edx;
        if (d != 0 && d != 3) { SET16(g_eax, 0xFFFF); return 0; }
        SET16(g_eax, 64); SET16(g_ecx, 512); SET16(g_ebx, 0x7FFF); SET16(g_edx, 0xFFFE);
        return 0;
    }
    case 0x2A: case 0x2C: {
        time_t now = time(NULL); struct tm *l = localtime(&now);
        if (ah == 0x2A) { SET16(g_ecx, l->tm_year + 1900); SET16(g_edx, (l->tm_mon + 1) << 8 | l->tm_mday); SET8L(g_eax, l->tm_wday); }
        else { SET16(g_ecx, l->tm_hour << 8 | l->tm_min); SET16(g_edx, l->tm_sec << 8 | (w16_host_ms() % 1000) / 10); }
        return 0;
    }
    case 0x59: SET16(g_eax, g_dos_err); SET16(g_ebx, 0x0D01); g_ecx = (g_ecx & 0xFFFF00FFu) | 0x0200; return 0;
    case 0x56: {   /* rename DS:DX -> ES:DI */
        if (!host_path(g_edx, path, sizeof path) || !host_path(g_edi, path2, sizeof path2)) { dos_fail((uint16_t)g_path_err); return 1; }
        if (rename(path, path2)) { dos_fail(errno_dos()); return 1; }
        return 0;
    }
    case 0x41:
        if (!host_path(g_edx, path, sizeof path)) { dos_fail((uint16_t)g_path_err); return 1; }
        if (remove(path)) { dos_fail(2); return 1; }
        return 0;
    case 0x39: case 0x3A:
        if (!host_path(g_edx, path, sizeof path)) { dos_fail((uint16_t)g_path_err); return 1; }
        if (ah == 0x39 ? mkdir(path, 0777) : rmdir(path)) { dos_fail(5); return 1; }
        return 0;
    case 0x50: g_cur_psp = (uint16_t)g_ebx; return 0;
    case 0x51: case 0x62: SET16(g_ebx, g_cur_psp); return 0;
    case 0x55: {   /* child PSP at DX: a copy of the current one */
        uint32_t np = recomp_sel_base((uint16_t)g_edx), op = recomp_sel_base(g_cur_psp);
        if (!np) { dos_fail(8); return 1; }
        if (op) memmove(W16_P(np), W16_P(op), 0x100);
        MEM16(np + 2) = (uint16_t)g_esi; MEM16(np + 0x16) = g_cur_psp;
        g_cur_psp = (uint16_t)g_edx;
        return 0;
    }
    case 0x69:
        if (al == 0) {
            uint8_t d = (uint8_t)g_ebx;
            if (d != 0 && d != 3) { dos_fail(15); return 1; }
            MEM16(g_edx) = 0; MEM32(g_edx + 2) = 0x19930401u;
            memcpy(W16_P(g_edx + 6), "NO NAME    FAT16   ", 19);
            return 0;
        }
        break;
    case 0x60: {   /* truename DS:SI -> ES:DI */
        if (!host_path(g_esi, path, sizeof path)) { dos_fail((uint16_t)g_path_err); return 1; }
        const char *rel = path + strlen(g_root);
        snprintf(path2, sizeof path2, "C:\\%s", *rel == '/' ? rel + 1 : rel);
        for (char *q = path2; *q; q++) { if (*q == '/') *q = '\\'; *q = (char)toupper((unsigned char)*q); }
        path2[127] = 0;
        guest_put(g_edi, path2, 128);
        return 0;
    }
    case 0x43:
        if (!host_path(g_edx, path, sizeof path)) { dos_fail((uint16_t)g_path_err); return 1; }
        if (al == 0) {
            struct stat st;
            if (stat(path, &st)) { dos_fail(2); return 1; }
            SET16(g_ecx, (st.st_mode & S_IFDIR) ? 0x10 : 0x20);
            return 0;
        }
        if (al == 1) return 0;   /* ponytail: attributes are not kept */
        break;
    case 0x3C: case 0x3D: case 0x5B: {   /* create / open / create new: DS:DX -> AX handle */
        int mk = ah == 0x3C || ah == 0x5B, fd;
        if (dos_device(g_edx)) fd = -2;
        else {
            if (!host_path(g_edx, path, sizeof path)) { dos_fail((uint16_t)g_path_err); return 1; }
            if (!mk && is_dir(path)) { dos_fail(5); return 1; }
            int fl = O_BINARY | (mk ? O_RDWR | O_CREAT | (ah == 0x5B ? O_EXCL : O_TRUNC) : (al & 3) == 0 ? O_RDONLY : (al & 3) == 1 ? O_WRONLY : O_RDWR);
            fd = open(path, fl, 0666);
            if (fd < 0) { dos_fail(errno_dos()); return 1; }
        }
        int h = new_handle(fd);
        if (h < 0) { dos_fail(4); return 1; }
        SET16(g_eax, h);
        return 0;
    }
    case 0x3E: {
        uint16_t h = (uint16_t)g_ebx;
        if (h <= 4) return 0;
        if (h >= NHANDLES || !g_fd[h]) { dos_fail(6); return 1; }
        if (g_fd[h] >= 0) close(g_fd[h]);
        g_fd[h] = 0;
        return 0;
    }
    case 0x3F: case 0x40: {
        uint16_t h = (uint16_t)g_ebx;
        if (h <= 4) {   /* the standard devices: reads find nothing, writes go to the log */
            if (ah == 0x40 && (h == 1 || h == 2)) fwrite(W16_P(g_edx), 1, g_ecx & 0xFFFF, stderr);
            g_eax = ah == 0x40 ? (g_ecx & 0xFFFF) : 0; return 0;
        }
        int fd = fd_of(h);
        if (!fd) { dos_fail(6); return 1; }
        if (fd == -2) { g_eax = ah == 0x40 ? g_ecx : 0; return 0; }
        long n;
        if (ah == 0x3F) n = read(fd, W16_P(g_edx), g_ecx);
        else if (g_ecx) n = write(fd, W16_P(g_edx), g_ecx);
        else { long at = lseek(fd, 0, SEEK_CUR); n = ftrunc(fd, at) ? -1 : 0; }
        if (n < 0) { dos_fail(5); return 1; }
        g_eax = (uint32_t)n;
        return 0;
    }
    case 0x42: {
        int fd = fd_of((uint16_t)g_ebx);
        if (!fd) { dos_fail(6); return 1; }
        long at = 0;
        if (fd != -2 && (at = lseek(fd, (int32_t)((uint32_t)(uint16_t)g_ecx << 16 | (uint16_t)g_edx), al)) < 0) { dos_fail(25); return 1; }
        SET16(g_eax, (uint32_t)at); SET16(g_edx, (uint32_t)at >> 16);
        return 0;
    }
    case 0x44:
        if (al == 0x00) {   /* device info: a file, or a character device for 0-4 and NUL */
            uint16_t h = (uint16_t)g_ebx;
            int fd = fd_of(h);
            if (h > 4 && !fd) { dos_fail(6); return 1; }
            SET16(g_edx, h <= 4 || fd == -2 ? 0x80D3 : 0x0002);
            return 0;
        }
        if (al == 0x08 || al == 0x09) {
            uint8_t d = (uint8_t)g_ebx;
            if (d != 0 && d != 3) { dos_fail(15); return 1; }
            if (al == 0x08) SET16(g_eax, 1); else SET16(g_edx, 0);
            return 0;
        }
        if (al == 0x0D || al == 0x0E || al == 0x0F) { dos_fail(al == 0x0D ? 1 : 15); return 1; }
        break;
    case 0x57: {
        int fd = fd_of((uint16_t)g_ebx);
        if (!fd) { dos_fail(6); return 1; }
        if (al == 0) {
            struct stat st; uint16_t d = 0x21, t = 0;
            if (fd != -2 && !fstat(fd, &st)) dos_time(st.st_mtime, &d, &t);
            SET16(g_ecx, t); SET16(g_edx, d);
            return 0;
        }
        if (al == 1) return 0;   /* ponytail: file times are not set */
        break;
    }
    case 0x3B:   /* chdir */
        if (!host_path(g_edx, path, sizeof path) || !is_dir(path)) { dos_fail((uint16_t)g_path_err); return 1; }
        {
            const char *rel = path + strlen(g_root);
            snprintf(g_cwd, sizeof g_cwd, "%s", *rel == '/' ? rel + 1 : rel);
            for (char *q = g_cwd; *q; q++) if (*q == '/') *q = '\\';
        }
        return 0;
    case 0x4E: case 0x4F: {   /* find first (CX attrs, DS:DX spec) / next, into the DTA */
        int h;
        if (ah == 0x4E) {
            if (!host_path(g_edx, path, sizeof path)) { dos_fail((uint16_t)g_path_err); return 1; }
            for (h = 0; h < NFINDS && g_find[h].used; h++) ;
            if (h == NFINDS) { h = 0; }   /* ponytail: searches are never closed in DOS; the oldest is reused */
            char *sl = strrchr(path, '/');
            *sl = 0;
            snprintf(g_find[h].dir, sizeof g_find[h].dir, "%s", path);
            snprintf(g_find[h].spec, sizeof g_find[h].spec, "%s", sl + 1);
            g_find[h].attr = (uint16_t)g_ecx; g_find[h].pos = 0; g_find[h].used = 1;
            g_find[h].root = !strcmp(path, g_root);
            MEM16(g_dta) = 0xF1D0; MEM16(g_dta + 2) = (uint16_t)h;
        } else {
            h = MEM16(g_dta) == 0xF1D0 ? MEM16(g_dta + 2) : -1;
            if (h < 0 || h >= NFINDS || !g_find[h].used) { dos_fail(18); return 1; }
        }
        if (!find_step(h)) { g_find[h].used = 0; dos_fail(18); return 1; }
        return 0;
    }
    }
    int21_unknown((uint16_t)eax);
    return 1;
}

/* ---- set up: the arena (size bytes) and C:\ (root, a host directory) ---- */
void w16_host_init(uint32_t size, const char *root) {
    g_arena_block = malloc(size + 0x10000);
    if (!g_arena_block) host_stop("no arena of", size);
    g_w16_mem = (uint8_t *)(((uintptr_t)g_arena_block + 0xFFFF) & ~(uintptr_t)0xFFFF);
    g_arena_size = size;
    g_arena_top = size;
    g_arena_low = REALMODE_END;
    memset(g_w16_mem, 0, REALMODE_END);
    snprintf(g_root, sizeof g_root, "%s", root);
    fprintf(stderr, "[host] arena %u MB at %p, C:\\ is %s\n", size >> 20, (void *)g_w16_mem, g_root);
}

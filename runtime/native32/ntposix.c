/*
 * ntposix: a lifted Windows NT userland on a POSIX host (Linux), no Wine.
 *
 * The guest's own ntdll is lifted like any module; lift32 turns its system
 * call gate (int 2Eh: eax = service, edx -> arguments) into recomp_syscall().
 * On Windows, syscall32.c answers a service with the host ntdll's export of
 * the same name. Here every service the guest uses is answered on POSIX:
 *
 *   memory    a page map over the 4 GB guest space (state, protection,
 *             allocation base per 4 KB page); reservations are
 *             mmap(PROT_NONE) at addresses the map hands out, below
 *             0x7FFE0000 as on Windows; commits are mprotect.
 *   objects   one handle table: files (an fd and the guest path), events,
 *             sections, mutants, the CSR port, directory objects.
 *   files     NT paths (\??\C:\x\y) through a mount table (guest prefix ->
 *             host directory, longest first), components matched without
 *             case. NUL is /dev/null.
 *   sections  a file's: mmap MAP_PRIVATE of it; a pagefile one: a memfd,
 *             MAP_SHARED, so two views alias. Image sections are the lifted
 *             modules' own mappings, or a proxy (ntp_proxy): a PE export
 *             table whose functions are host C stubs. Anything else is
 *             refused: an EXE that is not lifted never runs (the guard).
 *   csrss     \Windows\ApiPort answered in process, as csr32.c does on
 *             Windows; the console is stdin/stdout/stderr as plain files.
 *   time      KUSER_SHARED_DATA at 0x7FFE0000, kept current by a host
 *             thread (GetTickCount and GetSystemTimeAsFileTime read it).
 *
 * The service table is the guest ntdll's own, read from its NtXxx stubs, so
 * each NT build brings its own numbering (as syscall32.c).
 *
 * Built with gcc -m32 and RECOMP_FLAT_MEMORY: a guest address is a host
 * address. One guest thread. See win2000's docs/linux.md.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <pthread.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <signal.h>
#include <ucontext.h>
#include <execinfo.h>
#include "ntposix.h"

#if !defined(__i386__)
#error "ntposix is flat: build it with gcc -m32 (docs/linux.md)"
#endif
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

/* ------------------------------------------------------------ register file */
uint32_t  g_eax, g_ecx, g_edx, g_esp, g_ebx, g_esi, g_edi, g_ebp;
double    g_st[8];
int       g_fp_top;
uint16_t  g_fpu_cw = 0x027F;
uint16_t  g_seg_cs, g_seg_ds, g_seg_es, g_seg_fs, g_seg_gs, g_seg_ss;
uint64_t  g_mm[8];
xmm_t     g_xmm[8];
uint32_t  g_mxcsr = 0x1F80;
uint32_t  g_fs_base, g_gs_base, g_es_base, g_cs_base;
ptrdiff_t g_mem_base = 0;
uint32_t  g_cur_func;
uint32_t  g_icall_trace[ICALL_TRACE_SIZE], g_icall_from[ICALL_TRACE_SIZE];
uint32_t  g_icall_trace_idx, g_icall_count;
#ifdef RECOMP_X87_RING
double   g_stbuf[X87_RING], *g_stp = g_stbuf + X87_RING / 2;
int64_t  g_sti64buf[X87_RING], *g_sti64p = g_sti64buf + X87_RING / 2;
void recomp_x87_recentre(void) {
    double v[8];
    int64_t w[8];
    memcpy(v, g_stp, sizeof v), memcpy(w, g_sti64p, sizeof w);
    g_stp = g_stbuf + X87_RING / 2, g_sti64p = g_sti64buf + X87_RING / 2;
    memcpy(g_stp, v, sizeof v), memcpy(g_sti64p, w, sizeof w);
}
#endif

#define ST_OK                 0x00000000u
#define ST_TIMEOUT            0x00000102u
#define ST_BUFFER_OVERFLOW    0x80000005u
#define ST_NO_MORE_FILES      0x80000006u
#define ST_NO_MORE_ENTRIES    0x8000001Au
#define ST_NOT_IMPLEMENTED    0xC0000002u
#define ST_INVALID_INFO_CLASS 0xC0000003u
#define ST_INFO_LENGTH        0xC0000004u
#define ST_INVALID_HANDLE     0xC0000008u
#define ST_INVALID_PARAMETER  0xC000000Du
#define ST_NO_SUCH_FILE       0xC000000Fu
#define ST_INVALID_DEVICE_REQ 0xC0000010u
#define ST_END_OF_FILE        0xC0000011u
#define ST_NO_MEMORY          0xC0000017u
#define ST_CONFLICTING_ADDR   0xC0000018u
#define ST_ACCESS_DENIED      0xC0000022u
#define ST_BUFFER_TOO_SMALL   0xC0000023u
#define ST_NAME_INVALID       0xC0000033u
#define ST_NAME_NOT_FOUND     0xC0000034u
#define ST_NAME_COLLISION     0xC0000035u
#define ST_PATH_NOT_FOUND     0xC000003Au
#define ST_NO_TOKEN           0xC000007Cu
#define ST_IS_DIRECTORY       0xC00000BAu
#define ST_NOT_A_DIRECTORY    0xC0000103u
#define ST_DIR_NOT_EMPTY      0xC0000101u

static int g_trace = -1;

/* ------------------------------------------------------------- utilities */
static int u16len(const uint16_t* s) { int n = 0; while (s[n]) n++; return n; }

/* UTF-16 (n units, or to the NUL when n < 0) -> UTF-8 */
static void u16_to_u8(const uint16_t* s, int n, char* out, int cap) {
    int o = 0;
    if (n < 0) n = u16len(s);
    for (int i = 0; i < n && o < cap - 4; i++) {
        uint32_t c = s[i];
        if (c >= 0xD800 && c < 0xDC00 && i + 1 < n) c = 0x10000 + ((c - 0xD800) << 10) + (s[++i] - 0xDC00);
        if (c < 0x80) out[o++] = (char)c;
        else if (c < 0x800) out[o++] = (char)(0xC0 | c >> 6), out[o++] = (char)(0x80 | (c & 0x3F));
        else if (c < 0x10000) out[o++] = (char)(0xE0 | c >> 12), out[o++] = (char)(0x80 | ((c >> 6) & 0x3F)), out[o++] = (char)(0x80 | (c & 0x3F));
        else out[o++] = (char)(0xF0 | c >> 18), out[o++] = (char)(0x80 | ((c >> 12) & 0x3F)),
             out[o++] = (char)(0x80 | ((c >> 6) & 0x3F)), out[o++] = (char)(0x80 | (c & 0x3F));
    }
    out[o] = 0;
}

/* UTF-8 -> UTF-16, NUL-terminated; returns units written (without the NUL) */
static int u8_to_u16(const char* s, uint16_t* out, int cap) {
    const unsigned char* p = (const unsigned char*)s;
    int o = 0;
    while (*p && o < cap - 2) {
        uint32_t c = *p++;
        if (c >= 0xF0 && p[0] && p[1] && p[2]) c = ((c & 7) << 18) | ((p[0] & 0x3F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F), p += 3;
        else if (c >= 0xE0 && p[0] && p[1]) c = ((c & 0xF) << 12) | ((p[0] & 0x3F) << 6) | (p[1] & 0x3F), p += 2;
        else if (c >= 0xC0 && p[0]) c = ((c & 0x1F) << 6) | (p[0] & 0x3F), p += 1;
        if (c >= 0x10000) { c -= 0x10000; out[o++] = (uint16_t)(0xD800 + (c >> 10)); out[o++] = (uint16_t)(0xDC00 + (c & 0x3FF)); }
        else out[o++] = (uint16_t)c;
    }
    out[o] = 0;
    return o;
}

/* a UNICODE_STRING in guest memory -> UTF-8 */
static void us_to_u8(uint32_t us, char* out, int cap) {
    if (!us || !MEM32(us + 4)) { out[0] = 0; return; }
    u16_to_u8((const uint16_t*)(uintptr_t)MEM32(us + 4), MEM16(us) / 2, out, cap);
}

static uint64_t filetime(time_t s, long ns) { return ((uint64_t)s + 11644473600ull) * 10000000ull + (uint64_t)ns / 100; }
static uint64_t now_ft(void) { struct timespec t; clock_gettime(CLOCK_REALTIME, &t); return filetime(t.tv_sec, t.tv_nsec); }
static uint64_t mono_ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000; }
static int64_t tz_bias(void) { time_t t = time(NULL); struct tm lt; localtime_r(&t, &lt); return -(int64_t)lt.tm_gmtoff * 10000000; }

/* ------------------------------------------------------------- dispatch */
static recomp_dispatch_entry_t* g_disp;
static uint32_t g_ndisp;
static int cmp_disp(const void* a, const void* b) {
    uint32_t x = ((const recomp_dispatch_entry_t*)a)->address, y = ((const recomp_dispatch_entry_t*)b)->address;
    return x < y ? -1 : x > y;
}

recomp_func_t recomp_lookup(uint32_t va) {
    uint32_t lo = 0, hi = g_ndisp;
    while (lo < hi) {
        uint32_t m = (lo + hi) / 2;
        if (g_disp[m].address == va) return g_disp[m].func;
        if (g_disp[m].address < va) lo = m + 1; else hi = m;
    }
    return NULL;
}

#define MAX_REPL 256
static struct { uint32_t va; recomp_func_t fn; } g_repl[MAX_REPL];
static int g_nrepl;
void ntp_replace(uint32_t va, recomp_func_t fn) { if (va && g_nrepl < MAX_REPL) g_repl[g_nrepl].va = va, g_repl[g_nrepl++].fn = fn; }
recomp_func_t recomp_lookup_manual(uint32_t va) {
    for (int i = 0; i < g_nrepl; i++) if (g_repl[i].va == va) return g_repl[i].fn;
    return NULL;
}

/* proxies: their export slots are 16 bytes apart in the proxy image */
#define MAX_PROXY 16
static struct { char name[64]; const ntp_stub_t* s; int n; uint32_t base, size, lo; } g_proxy[MAX_PROXY];
static int g_nproxy;
recomp_func_t recomp_lookup_import(uint32_t va) {
    for (int i = 0; i < g_nproxy; i++)
        if (g_proxy[i].lo && va >= g_proxy[i].lo && va < g_proxy[i].lo + 16u * g_proxy[i].n && !((va - g_proxy[i].lo) & 15))
            return g_proxy[i].s[(va - g_proxy[i].lo) / 16].fn;
    return NULL;
}

/* the hardware's other gates: not used by an NT userland */
void recomp_int(int n) {
    if (n == 0x2D && g_eax == 1 && g_ecx) {                 /* DbgPrint: ecx the text, edx its length */
        fprintf(stderr, "[dbgprint] %.*s", (int)(g_edx & 0xFFFF), (const char*)(uintptr_t)g_ecx);
        return;
    }
    fprintf(stderr, "[ntposix] int %02Xh in sub_%08X\n", n, g_cur_func);
}

void ntp_call(uint32_t va, int nargs, const uint32_t* args) {
    recomp_func_t f = recomp_lookup_manual(va);
    if (!f) f = recomp_lookup(va);
    if (!f) { fprintf(stderr, "[ntposix] no lifted function at 0x%08X\n", va); exit(3); }
    for (int i = nargs - 1; i >= 0; i--) PUSH32(g_esp, args[i]);
    PUSH32(g_esp, RECOMP_RETADDR);
    f();
}

/* ------------------------------------------------------------- landing pads
 * (eh32.c's portable half: a guest handler continuing inside a lifted body
 * longjmps into that body's RECOMP_EH_FRAME) */
static recomp_ehframe_t* t_frames;
void recomp_eh_push(recomp_ehframe_t* f) { f->prev = t_frames; t_frames = f; }
void recomp_eh_pop(recomp_ehframe_t* f) {
    for (recomp_ehframe_t* p = t_frames; p; p = p->prev)
        if (p == f) { t_frames = f->prev; return; }
}
recomp_ehframe_t* recomp_eh_owner(uint32_t esp) {
    for (recomp_ehframe_t* f = t_frames; f; f = f->prev) if (f->entry_esp > esp) return f;
    return NULL;
}
void recomp_eh_resume(recomp_ehframe_t* f, uint32_t resume) {
    t_frames = f;
    f->resume = resume;
    g_cur_func = f->func;
    longjmp(f->jb, 1);
}
static int eh_jump(uint32_t va) {
    for (recomp_ehframe_t* f = t_frames; f; f = f->prev) {
        if (!f->resume_at || f->entry_esp != g_ebp + f->off) continue;
        for (const uint32_t* r = f->resume_at; *r; r++)
            if (*r == va) recomp_eh_resume(f, va);
    }
    return 0;
}

/* ------------------------------------------------------------- memory
 * One entry per 4 KB guest page. */
#define NPAGES   (1u << 20)
#define GUEST_LO 0x00100000u
#define GUEST_HI 0x7FFE0000u      /* KUSER_SHARED_DATA and up: not handed out */
enum { PG_FREE, PG_RESERVED, PG_COMMITTED };
enum { PT_PRIVATE, PT_MAPPED, PT_IMAGE };
static uint8_t  pg_state[NPAGES], pg_type[NPAGES];
static uint16_t pg_prot[NPAGES], pg_aprot[NPAGES];
static uint32_t pg_base[NPAGES];

static int host_prot(uint32_t p) { return (p & 0xFF) == 0x01 ? PROT_NONE : PROT_READ | PROT_WRITE; }

static int pages_free(uint32_t a, uint32_t size) {
    for (uint32_t p = a >> 12; p < (a + size) >> 12; p++) if (pg_state[p] != PG_FREE) return 0;
    return 1;
}

static void mark(uint32_t a, uint32_t size, int state, int type, uint32_t prot, uint32_t base) {
    for (uint32_t p = a >> 12; p < (uint32_t)(((uint64_t)a + size) >> 12); p++) {
        pg_state[p] = (uint8_t)state;
        if (state == PG_FREE) { pg_base[p] = 0; pg_prot[p] = pg_aprot[p] = 0; continue; }
        pg_type[p] = (uint8_t)type;
        pg_prot[p] = (uint16_t)prot;
        if (base) pg_base[p] = base, pg_aprot[p] = (uint16_t)prot;
    }
}

/* reserve [a, a+size) (a = 0: anywhere, 64 KB aligned; top: from the top) */
static uint32_t vm_reserve(uint32_t a, uint32_t size, int type, int top) {
    size = (size + 0xFFF) & ~0xFFFu;
    if (a) {
        if (a < 0x10000 || (uint64_t)a + size > GUEST_HI + 0x10000ull || !pages_free(a, size)) return 0;
        void* p = mmap((void*)(uintptr_t)a, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE, -1, 0);
        if (p == MAP_FAILED) return 0;
        if ((uintptr_t)p != a) { munmap(p, size); return 0; }
    } else {
        uint32_t span = (size + 0xFFFF) & ~0xFFFFu;
        for (uint32_t c = top ? GUEST_HI - span : GUEST_LO; c >= GUEST_LO && c + span <= GUEST_HI; c = top ? c - 0x10000 : c + 0x10000) {
            if (!pages_free(c, span)) continue;
            void* p = mmap((void*)(uintptr_t)c, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE, -1, 0);
            if (p == MAP_FAILED) continue;
            if ((uintptr_t)p != c) { munmap(p, size); continue; }
            a = c;
            break;
        }
        if (!a) return 0;
    }
    mark(a, size, PG_RESERVED, type, 0x01, a);
    return a;
}

static int vm_commit(uint32_t a, uint32_t size, uint32_t prot) {
    uint32_t lo = a & ~0xFFFu, hi = (a + size + 0xFFF) & ~0xFFFu;
    for (uint32_t p = lo >> 12; p < hi >> 12; p++) if (pg_state[p] == PG_FREE) return 0;
    if (mprotect((void*)(uintptr_t)lo, hi - lo, host_prot(prot))) return 0;
    for (uint32_t p = lo >> 12; p < hi >> 12; p++) pg_state[p] = PG_COMMITTED, pg_prot[p] = (uint16_t)prot;
    return 1;
}

uint32_t ntp_alloc(uint32_t size) {
    uint32_t a = vm_reserve(0, size, PT_PRIVATE, 0);
    if (!a || !vm_commit(a, size, 0x04)) { fprintf(stderr, "[ntposix] out of guest memory (%u bytes)\n", size); exit(3); }
    return a;
}

/* the extent of the allocation that holds page a */
static uint32_t alloc_extent(uint32_t base) {
    uint32_t p = base >> 12;
    while (p < NPAGES && pg_state[p] != PG_FREE && pg_base[p] == base) p++;
    return (p << 12) - base;
}

/* NtAllocateVirtualMemory(Process, Base*, ZeroBits, Size*, Type, Protect) */
static uint32_t s_alloc_vm(uint32_t* a) {
    uint32_t base = MEM32(a[1]), size = MEM32(a[3]), type = a[4], prot = a[5];
    if (a[0] != 0xFFFFFFFFu) return ST_INVALID_HANDLE;
    if (!size) return ST_INVALID_PARAMETER;
    if (type & 0x2000) {                                   /* MEM_RESERVE */
        uint32_t lo = base & ~0xFFFFu, hi = (base + size + 0xFFF) & ~0xFFFu;
        uint32_t r = vm_reserve(lo, hi - lo, PT_PRIVATE, (type & 0x100000) != 0);
        if (!r) return base ? ST_CONFLICTING_ADDR : ST_NO_MEMORY;
        base = r, size = hi - lo;
        for (uint32_t p = base >> 12; p < (base + size) >> 12; p++) pg_aprot[p] = (uint16_t)prot;
        if (type & 0x1000 && !vm_commit(base, size, prot)) return ST_NO_MEMORY;
    } else if (type & 0x1000) {                            /* MEM_COMMIT */
        uint32_t lo = base & ~0xFFFu, hi = (base + size + 0xFFF) & ~0xFFFu;
        if (!base || !vm_commit(lo, hi - lo, prot)) return ST_CONFLICTING_ADDR;
        base = lo, size = hi - lo;
    } else return ST_INVALID_PARAMETER;
    MEM32(a[1]) = base;
    MEM32(a[3]) = size;
    return 0;
}

/* NtFreeVirtualMemory(Process, Base*, Size*, FreeType) */
static uint32_t s_free_vm(uint32_t* a) {
    uint32_t base = MEM32(a[1]) & ~0xFFFu, size = MEM32(a[2]);
    if (base >= GUEST_HI + 0x10000u || pg_state[base >> 12] == PG_FREE) return 0xC000009Fu;   /* MEMORY_NOT_ALLOCATED */
    if (a[3] & 0x8000) {                                   /* MEM_RELEASE: the whole allocation */
        base = pg_base[base >> 12];
        size = alloc_extent(base);
        munmap((void*)(uintptr_t)base, size);
        mark(base, size, PG_FREE, 0, 0, 0);
    } else {                                               /* MEM_DECOMMIT */
        size = (size + (MEM32(a[1]) & 0xFFF) + 0xFFF) & ~0xFFFu;
        if (!MEM32(a[2])) size = alloc_extent(pg_base[base >> 12]) - (base - pg_base[base >> 12]);
        mmap((void*)(uintptr_t)base, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_NORESERVE, -1, 0);
        for (uint32_t p = base >> 12; p < (base + size) >> 12; p++) pg_state[p] = PG_RESERVED, pg_prot[p] = 0x01;
    }
    MEM32(a[1]) = base;
    MEM32(a[2]) = size;
    return 0;
}

/* NtProtectVirtualMemory(Process, Base*, Size*, NewProtect, OldProtect*) */
static uint32_t s_protect_vm(uint32_t* a) {
    uint32_t base = MEM32(a[1]), lo = base & ~0xFFFu, hi = (base + MEM32(a[2]) + 0xFFF) & ~0xFFFu;
    if (pg_state[lo >> 12] != PG_COMMITTED) return 0xC000002Du;   /* NOT_COMMITTED */
    MEM32(a[4]) = pg_prot[lo >> 12];
    if (!vm_commit(lo, hi - lo, a[3])) return 0xC000002Du;
    MEM32(a[1]) = lo;
    MEM32(a[2]) = hi - lo;
    return 0;
}

/* NtQueryVirtualMemory(Process, Base, Class, Buffer, Length, ReturnLength*):
 * MEMORY_BASIC_INFORMATION */
static uint32_t s_query_vm(uint32_t* a) {
    uint32_t va = a[1] & ~0xFFFu, o = a[3];
    if (a[2] != 0) return ST_INVALID_INFO_CLASS;
    if (a[4] < 28) return ST_INFO_LENGTH;
    if (va >= 0x7FFF0000u) return ST_INVALID_PARAMETER;
    uint32_t p = va >> 12, e = p;
    while (e < 0x7FFF0u && pg_state[e] == pg_state[p] && pg_base[e] == pg_base[p] &&
           (pg_state[p] != PG_COMMITTED || pg_prot[e] == pg_prot[p])) e++;
    static const uint32_t st[] = { 0x10000, 0x2000, 0x1000 }, ty[] = { 0x20000, 0x40000, 0x1000000 };
    MEM32(o + 0) = va;
    MEM32(o + 4) = pg_base[p];
    MEM32(o + 8) = pg_state[p] == PG_FREE ? 0 : pg_aprot[p];
    MEM32(o + 12) = (e - p) << 12;
    MEM32(o + 16) = st[pg_state[p]];
    MEM32(o + 20) = pg_state[p] == PG_COMMITTED ? pg_prot[p] : pg_state[p] == PG_FREE ? 0x01 : 0;
    MEM32(o + 24) = pg_state[p] == PG_FREE ? 0 : ty[pg_type[p]];
    if (a[5]) MEM32(a[5]) = 28;
    return 0;
}

/* ------------------------------------------------------------- modules */
#define MAX_MODS 32
static struct { char name[64]; uint32_t base, size; uint8_t* snap; int gone; } g_mod[MAX_MODS];
static int g_nmod;

static uint32_t image_size(uint32_t base) { return MEM32(base + MEM32(base + 0x3C) + 0x50); }

uint32_t ntp_map(const char* path, uint32_t base, const char* name) {
    FILE* f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "[load] %s: missing\n", path); return 0; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    uint8_t* raw = malloc(n);
    fseek(f, 0, SEEK_SET);
    if (fread(raw, 1, n, f) != (size_t)n) { fclose(f); free(raw); return 0; }
    fclose(f);
    uint32_t pe = *(uint32_t*)(raw + 0x3C), size = *(uint32_t*)(raw + pe + 0x50), hdrs = *(uint32_t*)(raw + pe + 0x54);
    uint16_t nsec = *(uint16_t*)(raw + pe + 6), opt = *(uint16_t*)(raw + pe + 0x14);
    if (*(uint32_t*)(raw + pe + 0x34) != base) fprintf(stderr, "[load] %s: based at 0x%08X, not 0x%08X (rebase it)\n", path, *(uint32_t*)(raw + pe + 0x34), base);
    if (vm_reserve(base, size, PT_IMAGE, 0) != base || !vm_commit(base, size, 0x40)) {
        fprintf(stderr, "[load] %s: 0x%08X..0x%08X is taken\n", path, base, base + size);
        free(raw);
        return 0;
    }
    for (uint32_t p = base >> 12; p < (base + size) >> 12; p++) pg_aprot[p] = 0x80;   /* EXECUTE_WRITECOPY */
    memcpy((void*)(uintptr_t)base, raw, hdrs);
    for (int i = 0; i < nsec; i++) {
        uint8_t* s = raw + pe + 0x18 + opt + 40 * i;
        uint32_t va = *(uint32_t*)(s + 12), rawsz = *(uint32_t*)(s + 16), ptr = *(uint32_t*)(s + 20);
        if (rawsz && ptr) memcpy((void*)(uintptr_t)(base + va), raw + ptr, rawsz);
    }
    free(raw);
    if (g_nmod < MAX_MODS) {
        snprintf(g_mod[g_nmod].name, sizeof g_mod[0].name, "%s", name);
        g_mod[g_nmod].base = base, g_mod[g_nmod++].size = size;
    }
    return base;
}

uint32_t ntp_export(uint32_t base, const char* name) {
    uint32_t nt = base + MEM32(base + 0x3C), dir = MEM32(nt + 0x78);
    if (!dir) return 0;
    uint32_t ed = base + dir, names = base + MEM32(ed + 0x20), ords = base + MEM32(ed + 0x24), funcs = base + MEM32(ed + 0x1C);
    for (uint32_t i = 0; i < MEM32(ed + 0x18); i++)
        if (!strcmp((const char*)(uintptr_t)(base + MEM32(names + 4 * i)), name))
            return base + MEM32(funcs + 4 * MEM16(ords + 2 * i));
    return 0;
}

static int module_by_name(const char* n) {
    for (int i = 0; i < g_nmod; i++) if (!strcasecmp(g_mod[i].name, n)) return i;
    return -1;
}
uint32_t ntp_module(const char* name) { int i = module_by_name(name); return i < 0 ? 0 : g_mod[i].base; }

void ntp_proxy(const char* dll, const ntp_stub_t* stubs, int n) {
    if (g_nproxy >= MAX_PROXY) return;
    snprintf(g_proxy[g_nproxy].name, sizeof g_proxy[0].name, "%s", dll);
    g_proxy[g_nproxy].s = stubs, g_proxy[g_nproxy++].n = n;
}

static int proxy_by_name(const char* n) {
    for (int i = 0; i < g_nproxy; i++) if (!strcasecmp(g_proxy[i].name, n)) return i;
    return -1;
}

/* A PE image whose export table names the proxy's stubs, by name; export i
 * is at lo + 16 i (recomp_lookup_import). No entry point, no imports. */
static uint32_t proxy_image(int k) {
    if (g_proxy[k].base) return g_proxy[k].base;
    int n = g_proxy[k].n;
    uint32_t strs = 64;
    for (int i = 0; i < n; i++) strs += (uint32_t)strlen(g_proxy[k].s[i].name) + 1;
    uint32_t dir = 0x1000, funcs = dir + 40, names = funcs + 4 * n, ords = names + 4 * n, pool = ords + 2 * n;
    uint32_t code = (pool + strs + 0xFFF) & ~0xFFFu, size = (code + 16 * n + 0xFFF) & ~0xFFFu;
    uint32_t b = vm_reserve(0, size, PT_IMAGE, 0);
    vm_commit(b, size, 0x20);
    uint8_t* p = (uint8_t*)(uintptr_t)b;
    uint8_t* nt = p + 0x40;
    *(uint16_t*)p = 0x5A4D;
    *(uint32_t*)(p + 0x3C) = 0x40;
    *(uint32_t*)nt = 0x4550;
    *(uint16_t*)(nt + 4) = 0x14C;
    *(uint16_t*)(nt + 0x14) = 0xE0;
    *(uint16_t*)(nt + 0x16) = 0x2102;                       /* DLL | 32BIT | EXECUTABLE */
    *(uint16_t*)(nt + 0x18) = 0x10B;
    *(uint32_t*)(nt + 0x34) = b;
    *(uint32_t*)(nt + 0x38) = 0x1000;
    *(uint32_t*)(nt + 0x3C) = 0x200;
    *(uint16_t*)(nt + 0x40) = 4;
    *(uint16_t*)(nt + 0x48) = 4;
    *(uint32_t*)(nt + 0x50) = size;
    *(uint32_t*)(nt + 0x54) = 0x1000;
    *(uint16_t*)(nt + 0x5C) = 3;                            /* CUI */
    *(uint32_t*)(nt + 0x74) = 16;
    *(uint32_t*)(nt + 0x78) = dir;
    *(uint32_t*)(nt + 0x7C) = pool + strs - dir;
    uint8_t* e = p + dir;
    *(uint32_t*)(e + 0x10) = 1;                             /* Base */
    *(uint32_t*)(e + 0x14) = n;
    *(uint32_t*)(e + 0x18) = n;
    *(uint32_t*)(e + 0x1C) = funcs;
    *(uint32_t*)(e + 0x20) = names;
    *(uint32_t*)(e + 0x24) = ords;
    /* names sorted, as the loader's binary search wants */
    int idx[256];
    for (int i = 0; i < n && i < 256; i++) idx[i] = i;
    for (int i = 1; i < n && i < 256; i++)
        for (int j = i; j > 0 && strcmp(g_proxy[k].s[idx[j - 1]].name, g_proxy[k].s[idx[j]].name) > 0; j--) {
            int t = idx[j]; idx[j] = idx[j - 1]; idx[j - 1] = t;
        }
    for (int i = 0; i < n && i < 256; i++) {
        int s = idx[i];
        ((uint32_t*)(p + funcs))[s] = code + 16 * s;
        strcpy((char*)p + pool, g_proxy[k].s[s].name);
        ((uint32_t*)(p + names))[i] = pool;
        ((uint16_t*)(p + ords))[i] = (uint16_t)s;
        pool += (uint32_t)strlen(g_proxy[k].s[s].name) + 1;
    }
    *(uint32_t*)(e + 0x0C) = pool;
    strcpy((char*)p + pool, g_proxy[k].name);
    g_proxy[k].base = b, g_proxy[k].size = size, g_proxy[k].lo = b + code;
    return b;
}

/* ------------------------------------------------------------- objects */
enum { O_FILE = 1, O_EVENT, O_SECTION, O_IMAGE, O_PORT, O_DIROBJ, O_MUTANT, O_SEM, O_TOKEN, O_KEY, O_THREAD, O_IOCOMP };
typedef struct obj {
    int type, refs;
    int fd, keepfd;              /* keepfd: stdin/out/err, never closed */
    char* guest;                 /* C:\x\y */
    char* host;                  /* /root/x/y */
    char** names;                /* a directory's entries, sorted as NTFS returns them */
    int nnames, pos, listed;
    char pat[256];
    int first, del;
    int signaled, manual;        /* events */
    uint32_t size, base;         /* sections: size; images: base */
    int image;
    uint32_t ctx[9], teb, tid;   /* a thread: edi esi ebx edx ecx eax ebp eip esp; its TEB, its id */
    int suspended;
    uint32_t* q;                 /* an I/O completion port: packets of 4 (key, apc, status, information) */
    int qn, qcap;
} obj_t;

#define MAXH 4096
#define HBASE 0x100u
static obj_t* g_h[MAXH];

static obj_t* obj_new(int type) {
    obj_t* o = calloc(1, sizeof *o);
    o->type = type, o->refs = 1, o->fd = -1;
    return o;
}
static uint32_t h_put(obj_t* o) {
    for (int i = 0; i < MAXH; i++) if (!g_h[i]) { g_h[i] = o; return HBASE + 4u * i; }
    return 0;
}
static obj_t* h_get(uint32_t h) {
    uint32_t i = (h - HBASE) / 4;
    return h >= HBASE && !(h & 3) && i < MAXH ? g_h[i] : NULL;
}
static void obj_release(obj_t* o) {
    if (--o->refs) return;
    for (int i = 0; i < o->nnames; i++) free(o->names[i]);
    free(o->names);
    if (o->fd >= 0 && !o->keepfd) close(o->fd);
    if (o->del && o->host) { if (remove(o->host)) rmdir(o->host); }
    free(o->q);
    free(o->guest);
    free(o->host);
    free(o);
}

static uint32_t g_std[3];      /* the guest's handles for fd 0, 1, 2 */

/* ------------------------------------------------------------- paths */
#define MAX_MNT 16
static struct { char g[260], h[1024]; } g_mnt[MAX_MNT];
static int g_nmnt;
void ntp_mount(const char* guest, const char* host) {
    if (g_nmnt < MAX_MNT) {
        snprintf(g_mnt[g_nmnt].g, sizeof g_mnt[0].g, "%s", guest);
        snprintf(g_mnt[g_nmnt++].h, sizeof g_mnt[0].h, "%s", host);
    }
}

/* C:\x\..\Y -> the host path, each component matched without case; the last
 * may not exist (the caller creates it). 0: not under a mount. */
static int to_host(const char* guest, char* out, int cap) {
    int best = -1;
    size_t bl = 0;
    for (int i = 0; i < g_nmnt; i++) {
        size_t n = strlen(g_mnt[i].g);
        if (n > bl && !strncasecmp(guest, g_mnt[i].g, n) && (guest[n] == '\\' || !guest[n])) best = i, bl = n;
    }
    if (best < 0) return 0;
    snprintf(out, cap, "%s", g_mnt[best].h);
    size_t root = strlen(out);
    char comp[256];
    const char* s = guest + bl;
    while (*s) {
        while (*s == '\\') s++;
        if (!*s) break;
        size_t k = 0;
        while (*s && *s != '\\' && k < sizeof comp - 1) comp[k++] = *s++;
        comp[k] = 0;
        if (!strcmp(comp, ".")) continue;
        if (!strcmp(comp, "..")) {
            char* sl = strrchr(out, '/');
            if (sl && (size_t)(sl - out) >= root) *sl = 0;
            continue;
        }
        size_t L = strlen(out);
        snprintf(out + L, cap - L, "/%s", comp);
        struct stat st;
        if (!lstat(out, &st)) {
            if (S_ISLNK(st.st_mode)) return 0;      /* the drive sandbox: a link never leads out of a mount */
            continue;
        }
        out[L] = 0;
        DIR* d = opendir(L ? out : "/");
        struct dirent* de;
        int found = 0;
        while (d && (de = readdir(d)))
            if (!strcasecmp(de->d_name, comp)) { snprintf(out + L, cap - L, "/%s", de->d_name); found = 1; break; }
        if (d) closedir(d);
        if (!found) snprintf(out + L, cap - L, "/%s", comp);
        else if (!lstat(out, &st) && S_ISLNK(st.st_mode)) return 0;
    }
    return 1;
}

/* OBJECT_ATTRIBUTES -> a guest DOS path (C:\x), with RootDirectory applied */
static int oa_path(uint32_t oa, char* g, int cap) {
    char name[1024];
    if (!oa) return 0;
    us_to_u8(MEM32(oa + 8), name, sizeof name);
    obj_t* root = MEM32(oa + 4) ? h_get(MEM32(oa + 4)) : NULL;
    if (root && root->guest) snprintf(g, cap, "%s\\%s", root->guest, name);
    else if (!strncmp(name, "\\??\\", 4)) snprintf(g, cap, "%s", name + 4);
    else if (!strncasecmp(name, "\\DosDevices\\", 12)) snprintf(g, cap, "%s", name + 12);
    else snprintf(g, cap, "%s", name);
    for (char* p = g; *p; p++) if (*p == '/') *p = '\\';
    size_t n = strlen(g);
    while (n > 3 && g[n - 1] == '\\') g[--n] = 0;
    return 1;
}

static const char* base_name(const char* p) {
    const char* b = p;
    for (; *p; p++) if (*p == '\\' || *p == '/' || *p == ':') b = p + 1;
    return b;
}

static uint32_t attrs_of(const struct stat* st) {
    uint32_t a = S_ISDIR(st->st_mode) ? 0x10 : 0x20;
    if (!(st->st_mode & S_IWUSR)) a |= 0x01;
    return a;
}

/* FILE_BASIC_INFORMATION (40 bytes) */
static void put_basic(uint32_t o, const struct stat* st) {
    *(uint64_t*)(uintptr_t)(o + 0) = filetime(st->st_mtim.tv_sec, st->st_mtim.tv_nsec);
    *(uint64_t*)(uintptr_t)(o + 8) = filetime(st->st_atim.tv_sec, st->st_atim.tv_nsec);
    *(uint64_t*)(uintptr_t)(o + 16) = filetime(st->st_mtim.tv_sec, st->st_mtim.tv_nsec);
    *(uint64_t*)(uintptr_t)(o + 24) = filetime(st->st_ctim.tv_sec, st->st_ctim.tv_nsec);
    MEM32(o + 32) = attrs_of(st);
    MEM32(o + 36) = 0;
}

static uint32_t missing_status(const char* host) {
    char parent[2048];
    struct stat st;
    snprintf(parent, sizeof parent, "%s", host);
    char* sl = strrchr(parent, '/');
    if (sl) *sl = 0;
    return !stat(parent, &st) && S_ISDIR(st.st_mode) ? ST_NAME_NOT_FOUND : ST_PATH_NOT_FOUND;
}

/* a proxy DLL's file: there is none, but the loader looks for it */
static int virtual_file(const char* guest) { return proxy_by_name(base_name(guest)) >= 0; }

static int is_nul(const char* g) { return !strcasecmp(base_name(g), "NUL") || !strcasecmp(g, "\\Device\\Null"); }

static uint32_t do_open(uint32_t ph, uint32_t access, uint32_t oa, uint32_t iosb, uint32_t disp, uint32_t opts) {
    char g[1024], hp[2048];
    struct stat st;
    if (!oa_path(oa, g, sizeof g)) return ST_NAME_INVALID;
    if (is_nul(g)) snprintf(hp, sizeof hp, "/dev/null");
    else if (!to_host(g, hp, sizeof hp)) return ST_PATH_NOT_FOUND;
    int ex = !stat(hp, &st), info = 1;
    obj_t* o = obj_new(O_FILE);
    if (!ex && virtual_file(g) && disp == 1) {
        o->guest = strdup(g), o->host = strdup(hp);
        MEM32(ph) = h_put(o);
        if (iosb) MEM32(iosb) = 0, MEM32(iosb + 4) = 1;
        return 0;
    }
    if (!ex && (disp == 1 || disp == 4)) { free(o); return missing_status(hp); }
    if (ex && disp == 2) { free(o); return ST_NAME_COLLISION; }
    if (!ex && opts & 1) {                                 /* create a directory */
        if (mkdir(hp, 0777)) { free(o); return missing_status(hp); }
        ex = !stat(hp, &st), info = 2;
    }
    if (ex && S_ISDIR(st.st_mode)) {
        if (opts & 0x40) { free(o); return ST_IS_DIRECTORY; }
        o->fd = open(hp, O_RDONLY | O_DIRECTORY);
    } else {
        if (ex && opts & 1) { free(o); return ST_NOT_A_DIRECTORY; }
        int wr = (access & (0x40000000u | 0x10000000u | 0x02000000u | 2 | 4)) != 0, fl = wr ? O_RDWR : O_RDONLY;
        if (!ex) fl |= O_CREAT, info = 2;
        else if (disp == 0 || disp == 4 || disp == 5) fl |= O_TRUNC, info = disp ? 3 : 0;
        o->fd = open(hp, fl, 0666);
        if (o->fd < 0 && wr && (access & 0x02000000u)) o->fd = open(hp, O_RDONLY);   /* MAXIMUM_ALLOWED */
    }
    if (o->fd < 0) { int e = errno; free(o); return e == EACCES ? ST_ACCESS_DENIED : missing_status(hp); }
    o->guest = strdup(g), o->host = strdup(hp);
    o->del = (opts & 0x1000) != 0;
    MEM32(ph) = h_put(o);
    if (iosb) MEM32(iosb) = 0, MEM32(iosb + 4) = info;
    return 0;
}

/* NtCreateFile(Handle*, Access, OA, Iosb, AllocSize*, Attributes, Share, Disposition, Options, Ea, EaLength) */
static uint32_t s_create_file(uint32_t* a) { return do_open(a[0], a[1], a[2], a[3], a[7], a[8]); }
/* NtOpenFile(Handle*, Access, OA, Iosb, Share, Options) */
static uint32_t s_open_file(uint32_t* a) { return do_open(a[0], a[1], a[2], a[3], 1, a[5]); }

static int stat_oa(uint32_t oa, struct stat* st, uint32_t* status, int* virt) {
    char g[1024], hp[2048];
    *virt = 0;
    if (!oa_path(oa, g, sizeof g)) { *status = ST_NAME_INVALID; return 0; }
    if (!to_host(g, hp, sizeof hp)) { *status = ST_PATH_NOT_FOUND; return 0; }
    if (!stat(hp, st)) return 1;
    if (virtual_file(g)) { memset(st, 0, sizeof *st); st->st_mode = S_IFREG | 0444; *virt = 1; return 1; }
    *status = missing_status(hp);
    return 0;
}

/* NtQueryAttributesFile(OA, FILE_BASIC_INFORMATION*) */
static uint32_t s_query_attributes(uint32_t* a) {
    struct stat st;
    uint32_t s;
    int v;
    if (!stat_oa(a[0], &st, &s, &v)) return s;
    put_basic(a[1], &st);
    return 0;
}

/* FILE_NETWORK_OPEN_INFORMATION (0x38) */
static void put_netopen(uint32_t o, const struct stat* st) {
    put_basic(o, st);
    *(uint64_t*)(uintptr_t)(o + 32) = (uint64_t)st->st_blocks * 512;
    *(uint64_t*)(uintptr_t)(o + 40) = S_ISDIR(st->st_mode) ? 0 : (uint64_t)st->st_size;
    MEM32(o + 48) = attrs_of(st);
    MEM32(o + 52) = 0;
}

/* NtQueryFullAttributesFile(OA, FILE_NETWORK_OPEN_INFORMATION*) */
static uint32_t s_query_full_attributes(uint32_t* a) {
    struct stat st;
    uint32_t s;
    int v;
    if (!stat_oa(a[0], &st, &s, &v)) return s;
    put_netopen(a[1], &st);
    return 0;
}

static void iosb_set(uint32_t iosb, uint32_t st, uint32_t info) { if (iosb) MEM32(iosb) = st, MEM32(iosb + 4) = info; }
static void event_set(uint32_t h) { obj_t* e = h_get(h); if (e && e->type == O_EVENT) e->signaled = 1; }

/* NtReadFile(Handle, Event, Apc, ApcCtx, Iosb, Buffer, Length, ByteOffset*, Key) */
static uint32_t s_read_file(uint32_t* a) {
    obj_t* o = h_get(a[0]);
    if (!o || o->type != O_FILE || o->fd < 0) return ST_INVALID_HANDLE;
    ssize_t n;
    uint32_t off = a[7];
    if (off && MEM32(off + 4) != 0xFFFFFFFFu) n = pread(o->fd, (void*)(uintptr_t)a[5], a[6], (off_t)*(int64_t*)(uintptr_t)off);
    else n = read(o->fd, (void*)(uintptr_t)a[5], a[6]);
    if (n < 0) { iosb_set(a[4], ST_ACCESS_DENIED, 0); return ST_ACCESS_DENIED; }
    event_set(a[1]);
    if (n == 0 && a[6]) { iosb_set(a[4], ST_END_OF_FILE, 0); return ST_END_OF_FILE; }
    iosb_set(a[4], 0, (uint32_t)n);
    return 0;
}

/* NtWriteFile(Handle, Event, Apc, ApcCtx, Iosb, Buffer, Length, ByteOffset*, Key) */
static uint32_t s_write_file(uint32_t* a) {
    obj_t* o = h_get(a[0]);
    if (!o || o->type != O_FILE || o->fd < 0) return ST_INVALID_HANDLE;
    ssize_t n;
    uint32_t off = a[7];
    if (off && MEM32(off + 4) == 0xFFFFFFFFu && MEM32(off) == 0xFFFFFFFFu) {   /* FILE_WRITE_TO_END_OF_FILE */
        lseek(o->fd, 0, SEEK_END);
        n = write(o->fd, (void*)(uintptr_t)a[5], a[6]);
    } else if (off && MEM32(off + 4) != 0xFFFFFFFFu)
        n = pwrite(o->fd, (void*)(uintptr_t)a[5], a[6], (off_t)*(int64_t*)(uintptr_t)off);
    else n = write(o->fd, (void*)(uintptr_t)a[5], a[6]);
    if (n < 0) { iosb_set(a[4], ST_ACCESS_DENIED, 0); return ST_ACCESS_DENIED; }
    event_set(a[1]);
    iosb_set(a[4], 0, (uint32_t)n);
    return 0;
}

/* NtQueryInformationFile(Handle, Iosb, Info, Length, Class) */
static uint32_t s_query_info_file(uint32_t* a) {
    obj_t* o = h_get(a[0]);
    uint32_t b = a[2], len = a[3], cls = a[4], n = 0;
    struct stat st;
    if (!o || o->type != O_FILE) return ST_INVALID_HANDLE;
    if (o->fd < 0) { memset(&st, 0, sizeof st); st.st_mode = S_IFREG | 0444; }
    else if (fstat(o->fd, &st)) return ST_INVALID_HANDLE;
    memset((void*)(uintptr_t)b, 0, len);
    switch (cls) {
    case 4: if (len < 40) return ST_INFO_LENGTH; put_basic(b, &st); n = 40; break;          /* Basic */
    case 5:                                                                               /* Standard */
        if (len < 24) return ST_INFO_LENGTH;
        *(uint64_t*)(uintptr_t)b = (uint64_t)st.st_blocks * 512;
        *(uint64_t*)(uintptr_t)(b + 8) = S_ISDIR(st.st_mode) ? 0 : (uint64_t)st.st_size;
        MEM32(b + 16) = (uint32_t)st.st_nlink;
        MEM8(b + 20) = (uint8_t)o->del;
        MEM8(b + 21) = S_ISDIR(st.st_mode);
        n = 24;
        break;
    case 9: {                                                                             /* Name: from the volume root */
        uint16_t w[1024];
        const char* g = o->guest ? o->guest : "";
        if (g[0] && g[1] == ':') g += 2;
        int k = u8_to_u16(g, w, 1024);
        MEM32(b) = 2u * k;
        if (len < 4 + 2u * k) { memcpy((void*)(uintptr_t)(b + 4), w, len - 4); iosb_set(a[1], ST_BUFFER_OVERFLOW, len); return ST_BUFFER_OVERFLOW; }
        memcpy((void*)(uintptr_t)(b + 4), w, 2u * k);
        n = 4 + 2u * k;
        break;
    }
    case 0xE:                                                                             /* Position */
        *(int64_t*)(uintptr_t)b = o->fd >= 0 ? (int64_t)lseek(o->fd, 0, SEEK_CUR) : 0;
        n = 8;
        break;
    case 0x22: put_netopen(b, &st); n = 0x38; break;                                      /* NetworkOpen */
    case 0x11: MEM32(b) = 0; n = 4; break;                                                /* EaInformation */
    case 0x10: MEM32(b) = 0x0000FFFFu; n = 4; break;                                     /* Mode */
    case 6: *(uint64_t*)(uintptr_t)b = (uint64_t)st.st_ino; n = 8; break;               /* Internal */
    case 0x23: {                                                                          /* AttributeTag: attributes, no reparse tag */
        uint8_t t[40];
        if (len < 8) return ST_INFO_LENGTH;
        put_basic((uint32_t)(uintptr_t)t, &st);
        MEM32(b) = *(uint32_t*)(t + 32), MEM32(b + 4) = 0, n = 8;
        break;
    }
    case 0x12: {                                                                          /* All (GetFileInformationByHandle) */
        if (len < 0x60) return ST_INFO_LENGTH;
        uint32_t q[5] = { a[0], a[1], b + 40, 24, 5 }, r[5] = { a[0], a[1], b + 64, 8, 6 }, p[5] = { a[0], a[1], b + 80, 8, 0xE };
        put_basic(b, &st);                                                                /* Basic, Standard, Internal, Ea 0, Access, Position, Mode, Alignment, Name */
        s_query_info_file(q), s_query_info_file(r), s_query_info_file(p);
        MEM32(b + 76) = 0x001F01FFu;
        uint32_t nq[5] = { a[0], a[1], b + 96, len - 96, 9 };
        uint32_t st9 = s_query_info_file(nq);
        n = len - 96 >= 4 + MEM32(b + 96) ? 100 + MEM32(b + 96) : len;
        iosb_set(a[1], st9, n);
        return st9;
    }
    default:
        fprintf(stderr, "[ntposix] NtQueryInformationFile class %u\n", cls);
        return ST_INVALID_INFO_CLASS;
    }
    iosb_set(a[1], 0, n);
    return 0;
}

/* NtSetInformationFile(Handle, Iosb, Info, Length, Class) */
static uint32_t s_set_info_file(uint32_t* a) {
    obj_t* o = h_get(a[0]);
    uint32_t b = a[2], cls = a[4];
    if (!o || o->type != O_FILE) return ST_INVALID_HANDLE;
    switch (cls) {
    case 0xE: if (o->fd >= 0) lseek(o->fd, (off_t)*(int64_t*)(uintptr_t)b, SEEK_SET); break;   /* Position */
    case 0xD: o->del = MEM8(b) != 0; break;                                                   /* Disposition */
    case 0x14: case 0x13: if (o->fd >= 0 && ftruncate(o->fd, (off_t)*(int64_t*)(uintptr_t)b)) return ST_ACCESS_DENIED; break;   /* EndOfFile, Allocation */
    case 4: break;                                                                            /* Basic: times kept */
    case 0xA: {                                                                               /* Rename */
        char name[1024], g[1024], hp[2048];
        u16_to_u8((const uint16_t*)(uintptr_t)(b + 12), MEM32(b + 8) / 2, name, sizeof name);
        snprintf(g, sizeof g, "%s", !strncmp(name, "\\??\\", 4) ? name + 4 : name);
        if (!to_host(g, hp, sizeof hp) || rename(o->host, hp)) return ST_ACCESS_DENIED;
        free(o->host); free(o->guest);
        o->host = strdup(hp), o->guest = strdup(g);
        break;
    }
    default:
        fprintf(stderr, "[ntposix] NtSetInformationFile class %u\n", cls);
        return ST_INVALID_INFO_CLASS;
    }
    iosb_set(a[1], 0, 0);
    return 0;
}

/* NtQueryVolumeInformationFile(Handle, Iosb, Info, Length, Class) */
static uint32_t s_query_volume(uint32_t* a) {
    obj_t* o = h_get(a[0]);
    uint32_t b = a[2], len = a[3], n = 0;
    struct stat st;
    struct statvfs vf;
    if (!o || o->type != O_FILE) return ST_INVALID_HANDLE;
    memset((void*)(uintptr_t)b, 0, len);
    switch (a[4]) {
    case 4: {                                                                  /* Device: what GetFileType reads */
        uint32_t t = 7;                                                        /* DISK */
        if (o->fd >= 0 && !fstat(o->fd, &st)) {
            if (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode)) t = 0x11;       /* NAMED_PIPE */
            else if (S_ISCHR(st.st_mode)) t = 0x15;                            /* NULL: a character device */
        }
        MEM32(b) = t;
        MEM32(b + 4) = 0;
        n = 8;
        break;
    }
    case 1:                                                                    /* Volume: no label */
        if (len < 18) return ST_INFO_LENGTH;
        *(uint64_t*)(uintptr_t)b = 0;
        MEM32(b + 8) = 0x20000502u;                                            /* the serial number dir prints */
        n = 18;
        break;
    case 5: {                                                                  /* Attribute */
        static const uint16_t fs[] = { 'N', 'T', 'F', 'S' };
        if (len < 12 + 8) return ST_INFO_LENGTH;
        MEM32(b) = 0x00000003u;                                                /* case sensitive search, case preserved */
        MEM32(b + 4) = 255;
        MEM32(b + 8) = 8;
        memcpy((void*)(uintptr_t)(b + 12), fs, 8);
        n = 20;
        break;
    }
    case 3: case 7:                                                            /* Size, FullSize */
        if (o->fd < 0 || fstatvfs(o->fd, &vf)) memset(&vf, 0, sizeof vf), vf.f_frsize = 4096;
        *(uint64_t*)(uintptr_t)b = vf.f_blocks;
        *(uint64_t*)(uintptr_t)(b + 8) = vf.f_bavail;
        if (a[4] == 7) {
            *(uint64_t*)(uintptr_t)(b + 16) = vf.f_bfree;
            MEM32(b + 24) = (uint32_t)(vf.f_frsize / 512), MEM32(b + 28) = 512;
            n = 32;
        } else MEM32(b + 16) = (uint32_t)(vf.f_frsize / 512), MEM32(b + 20) = 512, n = 24;
        break;
    default:
        fprintf(stderr, "[ntposix] NtQueryVolumeInformationFile class %u\n", a[4]);
        return ST_INVALID_INFO_CLASS;
    }
    iosb_set(a[1], 0, n);
    return 0;
}

/* DOS wildcards as kernel32 hands them down: * ?, < (DOS_STAR), > (DOS_QM,
 * also matches nothing at a dot or the end), " (DOS_DOT, a dot or the end).
 * Without case. */
static int wmatch(const char* p, const char* s) {
    for (;; p++, s++) {
        char c = *p;
        if (c == '*' || c == '<') {
            while (*p == '*' || *p == '<') p++;
            if (!*p) return 1;
            for (; *s; s++) if (wmatch(p, s)) return 1;
            return wmatch(p, s);
        }
        if (!c) return !*s;
        if (c == '?') { if (!*s) return 0; continue; }
        if (c == '>') { if (!*s || *s == '.') s--; continue; }
        if (c == '"') { if (!*s) { s--; continue; } if (*s != '.') return 0; continue; }
        if (tolower((unsigned char)c) != tolower((unsigned char)*s)) return 0;
    }
}

/* NTFS's order: names compared as upper case, ordinal */
static int cmp_upper(const void* a, const void* b) {
    const unsigned char *x = *(const unsigned char* const*)a, *y = *(const unsigned char* const*)b;
    while (*x && toupper(*x) == toupper(*y)) x++, y++;
    return toupper(*x) - toupper(*y);
}

/* NtQueryDirectoryFile(Handle, Event, Apc, ApcCtx, Iosb, Info, Length, Class, ReturnSingleEntry, FileName*, RestartScan) */
static uint32_t s_query_dir(uint32_t* a) {
    obj_t* o = h_get(a[0]);
    uint32_t b = a[5], len = a[6], cls = a[7], used = 0, prev = 0, nameoff;
    if (!o || o->type != O_FILE || o->fd < 0) return ST_INVALID_HANDLE;
    switch (cls) {
    case 1: nameoff = 0x40; break;     /* FileDirectoryInformation */
    case 2: nameoff = 0x44; break;     /* FileFullDirectoryInformation */
    case 3: nameoff = 0x5E; break;     /* FileBothDirectoryInformation */
    case 12: nameoff = 0x0C; break;    /* FileNamesInformation */
    default: return ST_INVALID_INFO_CLASS;
    }
    if (!o->listed) {
        int d = dup(o->fd), cap = 64;
        DIR* dir = fdopendir(d);
        struct dirent* de;
        if (!dir) { close(d); return ST_INVALID_HANDLE; }
        o->names = malloc(sizeof(char*) * cap);
        while ((de = readdir(dir))) {
            if (o->nnames == cap) o->names = realloc(o->names, sizeof(char*) * (cap *= 2));
            o->names[o->nnames++] = strdup(de->d_name);
        }
        closedir(dir);
        qsort(o->names, o->nnames, sizeof(char*), cmp_upper);
        o->listed = o->first = 1;
        strcpy(o->pat, "*");
    }
    if (a[9] && (o->first || a[10])) us_to_u8(a[9], o->pat, sizeof o->pat);
    if (a[10]) o->pos = 0, o->first = 1;
    for (; o->pos < o->nnames; o->pos++) {
        const char* dn = o->names[o->pos];
        struct stat st;
        uint16_t w[512];
        if (!wmatch(o->pat, dn)) continue;
        if (fstatat(o->fd, dn, &st, 0)) memset(&st, 0, sizeof st);
        int k = u8_to_u16(dn, w, 512);
        uint32_t esz = (nameoff + 2u * k + 7) & ~7u;
        if (used + nameoff + 2u * k > len) {
            if (!used) { iosb_set(a[4], ST_BUFFER_OVERFLOW, 0); return ST_BUFFER_OVERFLOW; }
            break;
        }
        uint32_t e = b + used;
        memset((void*)(uintptr_t)e, 0, nameoff);
        if (prev) MEM32(prev) = e - prev;
        if (cls == 12) MEM32(e + 8) = 2u * k;
        else {
            put_basic(e + 8, &st);                     /* the four times at +8, then +0x28 sizes */
            *(uint64_t*)(uintptr_t)(e + 0x28) = S_ISDIR(st.st_mode) ? 0 : (uint64_t)st.st_size;
            *(uint64_t*)(uintptr_t)(e + 0x30) = (uint64_t)st.st_blocks * 512;
            MEM32(e + 0x38) = attrs_of(&st);
            MEM32(e + 0x3C) = 2u * k;
        }
        memcpy((void*)(uintptr_t)(e + nameoff), w, 2u * k);
        prev = e;
        used += esz;
        if (a[8]) { o->pos++; break; }
    }
    int first = o->first;
    o->first = 0;
    event_set(a[1]);
    if (!used) {
        uint32_t s = first ? ST_NO_SUCH_FILE : ST_NO_MORE_FILES;
        iosb_set(a[4], s, 0);
        return s;
    }
    iosb_set(a[4], 0, used > len ? len : used);
    return 0;
}

static uint32_t s_fs_control(uint32_t* a) {
    if (a[5] == 0x90028u) { iosb_set(a[4], 0, 0); return 0; }     /* FSCTL_IS_VOLUME_MOUNTED */
    return ST_INVALID_DEVICE_REQ;
}
static uint32_t s_device_io(uint32_t* a) { (void)a; return ST_INVALID_DEVICE_REQ; }
static uint32_t s_flush_file(uint32_t* a) { iosb_set(a[1], 0, 0); return 0; }

/* ------------------------------------------------------------- handles */
static uint32_t s_close(uint32_t* a) {
    obj_t* o = h_get(a[0]);
    if (!o) return a[0] >= 0xFFFFFFFEu ? 0 : ST_INVALID_HANDLE;
    g_h[(a[0] - HBASE) / 4] = NULL;
    obj_release(o);
    return 0;
}

/* NtDuplicateObject(SourceProcess, Source, TargetProcess, Target*, Access, Attributes, Options) */
static uint32_t s_duplicate(uint32_t* a) {
    obj_t* o = h_get(a[1]);
    if (!o) {
        if (a[1] < 0xFFFFFFFEu) return ST_INVALID_HANDLE;
        if (a[3]) MEM32(a[3]) = a[1];
        return 0;
    }
    o->refs++;
    uint32_t h = h_put(o);
    if (a[3]) MEM32(a[3]) = h;
    if (a[6] & 1) { g_h[(a[1] - HBASE) / 4] = NULL; obj_release(o); }   /* DUPLICATE_CLOSE_SOURCE */
    return 0;
}

static uint32_t s_query_object(uint32_t* a) {
    if (a[1] == 4 && a[3] >= 2) { MEM16(a[2]) = 0; if (a[4]) MEM32(a[4]) = 2; return 0; }   /* HandleFlags */
    return ST_INVALID_INFO_CLASS;
}
static uint32_t s_ok(uint32_t* a) { (void)a; return 0; }

/* ------------------------------------------------------------- events, waits */
static uint32_t new_handle(uint32_t ph, int type, int signaled, int manual) {
    obj_t* o = obj_new(type);
    o->signaled = signaled, o->manual = manual;
    MEM32(ph) = h_put(o);
    return 0;
}
uint32_t ntp_event(int signaled, int manual) {
    obj_t* o = obj_new(O_EVENT);
    o->signaled = signaled, o->manual = manual;
    return h_put(o);
}
/* NtCreateEvent(Handle*, Access, OA, Type, InitialState): type 0 manual reset */
/* named events, in this process: CreateEvent of a name that exists opens it (STATUS_OBJECT_NAME_EXISTS),
 * NtOpenEvent finds it. The tray's "MSShellRunDlgReady", set by shell32's Run dialog, was never found and
 * the tray waited its 10 s. ponytail: one process's names (no cross-process objects), kept for its life */
static struct { char n[128]; obj_t* o; } g_named[64];
static obj_t* named_event(uint32_t oa, obj_t* add) {
    char n[128];
    us_to_u8(oa ? MEM32(oa + 8) : 0, n, sizeof n);
    if (!n[0]) return NULL;
    for (int i = 0; i < 64; i++) if (g_named[i].o && !strcasecmp(g_named[i].n, n)) return g_named[i].o;
    for (int i = 0; add && i < 64; i++) if (!g_named[i].o) { snprintf(g_named[i].n, sizeof g_named[i].n, "%s", n); g_named[i].o = add, add->refs++; break; }
    return NULL;
}
static uint32_t s_create_event(uint32_t* a) {
    obj_t* o = named_event(a[2], NULL);
    if (o && o->type == O_EVENT) { o->refs++, MEM32(a[0]) = h_put(o); return 0x40000000u; }   /* STATUS_OBJECT_NAME_EXISTS */
    uint32_t r = new_handle(a[0], O_EVENT, a[4] != 0, a[3] == 0);
    named_event(a[2], h_get(MEM32(a[0])));
    return r;
}
static uint32_t s_open_event(uint32_t* a) {     /* NtOpenEvent(Handle*, Access, OA) */
    obj_t* o = named_event(a[2], NULL);
    if (!o || o->type != O_EVENT) return ST_NAME_NOT_FOUND;
    o->refs++, MEM32(a[0]) = h_put(o);
    return 0;
}
static uint32_t s_set_event(uint32_t* a) {
    obj_t* o = h_get(a[0]);
    if (!o || o->type != O_EVENT) return ST_INVALID_HANDLE;
    if (a[1]) MEM32(a[1]) = (uint32_t)o->signaled;
    o->signaled = 1;
    return 0;
}
static uint32_t s_reset_event(uint32_t* a) {
    obj_t* o = h_get(a[0]);
    if (!o || o->type != O_EVENT) return ST_INVALID_HANDLE;
    if (a[1] && a[1] < 0xFFFFFFFEu && h_get(a[0])) { /* NtResetEvent's PreviousState */ }
    o->signaled = 0;
    return 0;
}
static uint32_t s_create_mutant(uint32_t* a) { return new_handle(a[0], O_MUTANT, 1, 1); }
static uint32_t s_create_semaphore(uint32_t* a) { return new_handle(a[0], O_SEM, a[3] != 0, 1); }
static uint32_t s_release(uint32_t* a) { (void)a; return 0; }
static uint32_t s_not_found(uint32_t* a) { (void)a; return ST_NAME_NOT_FOUND; }

/* NtOpenMutant: build 2163's kernel32 opens csrss's NlsCacheMutant */
static uint32_t s_open_mutant(uint32_t* a) {
    char n[512];
    us_to_u8(a[2] ? MEM32(a[2] + 8) : 0, n, sizeof n);
    size_t k = strlen(n);
    if (k >= 14 && !strcasecmp(n + k - 14, "NlsCacheMutant")) return new_handle(a[0], O_MUTANT, 1, 1);
    return ST_NAME_NOT_FOUND;
}

/* ------------------------------------------------------------- threads
 * Guest threads on host threads under one big lock: the thread holding it
 * runs guest code; a wait hands it over. The register file is global, so
 * whoever gives the lock up keeps its registers on its own host stack.
 * ponytail: waits poll (1 ms) instead of being woken; MMX/SSE and the x87
 * ring are not switched (a syscall is not reached mid-expression). */
static pthread_mutex_t g_big = PTHREAD_MUTEX_INITIALIZER;
static int g_nthreads = 1;
static __thread obj_t* t_self;                     /* this host thread's guest thread (NULL: the first) */
typedef struct { uint32_t r[8], fs, cur; double st[8]; int top; uint16_t cw; } regs_t;
static void regs_save(regs_t* r) {
    uint32_t v[8] = { g_eax, g_ecx, g_edx, g_ebx, g_esp, g_ebp, g_esi, g_edi };
    memcpy(r->r, v, sizeof v), r->fs = g_fs_base, r->cur = g_cur_func;
    memcpy(r->st, g_st, sizeof g_st), r->top = g_fp_top, r->cw = g_fpu_cw;
}
static void regs_load(const regs_t* r) {
    g_eax = r->r[0], g_ecx = r->r[1], g_edx = r->r[2], g_ebx = r->r[3], g_esp = r->r[4], g_ebp = r->r[5], g_esi = r->r[6], g_edi = r->r[7];
    g_fs_base = r->fs, g_cur_func = r->cur, memcpy(g_st, r->st, sizeof g_st), g_fp_top = r->top, g_fpu_cw = r->cw;
}
/* let the other guest threads run for a while (a wait, an idle message loop) */
void ntp_yield(void) {
    if (g_nthreads < 2) return;
    regs_t r;
    regs_save(&r);
    pthread_mutex_unlock(&g_big);
    struct timespec d = { 0, 1000000 };
    nanosleep(&d, NULL);
    pthread_mutex_lock(&g_big);
    regs_load(&r);
}
static void* thread_main(void* arg) {
    obj_t* t = arg;
    pthread_mutex_lock(&g_big);
    t_self = t;
    g_edi = t->ctx[0], g_esi = t->ctx[1], g_ebx = t->ctx[2], g_edx = t->ctx[3], g_ecx = t->ctx[4], g_eax = t->ctx[5], g_ebp = t->ctx[6];
    g_esp = t->ctx[8], g_fs_base = t->teb, g_fp_top = 0, g_fpu_cw = 0x027F;
    recomp_func_t f = recomp_lookup(t->ctx[7]);
    if (f) f();                                    /* BaseThreadStartThunk: it ends in NtTerminateThread */
    else fprintf(stderr, "[nt] thread start %08X is not lifted\n", t->ctx[7]);
    t->signaled = 1, g_nthreads--;
    pthread_mutex_unlock(&g_big);
    return NULL;
}
static uint32_t g_teb, g_pid, g_tid;
/* NtResumeThread(Handle, PreviousCount*) */
static uint32_t s_resume_thread(uint32_t* a) {
    obj_t* t = h_get(a[0]);
    if (a[1]) MEM32(a[1]) = t && t->type == O_THREAD ? (uint32_t)t->suspended : 0;
    if (!t || t->type != O_THREAD || !t->suspended) return 0;
    t->suspended = 0;
    if (g_nthreads == 1) pthread_mutex_trylock(&g_big);   /* (the first thread takes the lock now) */
    g_nthreads++;
    pthread_t p;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setstacksize(&at, 8u << 20);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&p, &at, thread_main, t)) { g_nthreads--; return 0xC0000001u; }
    t->refs++;                                     /* (the running thread keeps its object) */
    fprintf(stderr, "[nt] thread %X starts at %08X (eax %08X), on a host thread\n", t->tid, t->ctx[7], t->ctx[5]);
    return 0;
}
/* NtCreateThread(Handle*, Access, OA, Process, ClientId*, CONTEXT*, INITIAL_TEB*, CreateSuspended) */
static uint32_t s_create_thread(uint32_t* a) {
    static uint32_t next;
    obj_t* t = obj_new(O_THREAD);
    uint32_t c = a[5];
    for (int i = 0; i < 8; i++) t->ctx[i] = MEM32(c + 0x9C + 4 * i);
    t->ctx[8] = MEM32(c + 0xC4);
    t->teb = ntp_alloc(0x2000);
    memcpy((void*)(uintptr_t)t->teb, (void*)(uintptr_t)g_teb, 0x2000);   /* (the first thread's, USER's thread info with it) */
    memset((void*)(uintptr_t)(t->teb + 0xE10), 0, 64 * 4);              /* but its own TlsSlots, empty (MFC keeps each thread's state there) */
    /* and none of the first thread's per-thread pointers: ReservedForOle (ole32's SOleTlsData:
     * shared, CoSetState on one thread released another's oleaut32 state), ReservedForNtRpc (rpcrt4's
     * thread object: a thread's exit freed the first thread's, a fault after shell32's execute thread),
     * WinSockData and TlsExpansionSlots */
    MEM32(t->teb + 0xF80) = 0, MEM32(t->teb + 0xF1C) = 0, MEM32(t->teb + 0xF6C) = 0, MEM32(t->teb + 0xF94) = 0;
    t->tid = g_tid + 4 * ++next;
    MEM32(t->teb + 0x00) = 0xFFFFFFFFu;
    MEM32(t->teb + 0x04) = MEM32(a[6] + 8), MEM32(t->teb + 0x08) = MEM32(a[6] + 12);
    MEM32(t->teb + 0x18) = t->teb, MEM32(t->teb + 0x24) = t->tid;
    MEM32(t->teb + 0xBFC) = t->teb + 0xC00, MEM32(t->teb + 0xE0C) = MEM32(a[6] + 16);
    t->suspended = 1;
    MEM32(a[0]) = h_put(t);
    if (a[4]) MEM32(a[4]) = g_pid, MEM32(a[4] + 4) = t->tid;
    if (!a[7]) { uint32_t r[2] = { MEM32(a[0]), 0 }; s_resume_thread(r); }
    return 0;
}

static int signaled(uint32_t h, int consume) {
    obj_t* o = h_get(h);
    if (!o) return 0;                              /* this process / thread: alive */
    if (o->type == O_THREAD) return o->signaled;
    if (o->type != O_EVENT) return 1;
    int s = o->signaled;
    if (s && consume && !o->manual) o->signaled = 0;
    return s;
}

static int g_virtual;                              /* the virtual clock (ntp_clock_virtual) */
static uint64_t g_vms;
void ntp_clock_advance(uint32_t ms);
static uint32_t wait_timeout(uint32_t to, const char* what) {
    if (!to) {
        fprintf(stderr, "[ntposix] %s waits forever with one guest thread: returning a timeout (from sub_%08X)\n", what, g_cur_func);
        return ST_TIMEOUT;
    }
    int64_t t = *(int64_t*)(uintptr_t)to;
    if (t < 0) {
        int64_t ns = -t * 100;
        if (ns > 2000000000ll) ns = 2000000000ll;
        if (g_virtual) { ntp_clock_advance((uint32_t)(ns / 1000000)); return ST_TIMEOUT; }
        struct timespec d = { (time_t)(ns / 1000000000), (long)(ns % 1000000000) };
        nanosleep(&d, NULL);
    }
    return ST_TIMEOUT;
}

/* NtWaitForSingleObject(Handle, Alertable, Timeout*) */
static uint64_t real_ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (uint64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000; }
/* with other threads, a wait polls them (to: the timeout's address, 0 forever); 0 when it is over */
static int wait_more(uint32_t to, uint64_t* end) {
    if (g_nthreads < 2) return 0;
    if (!*end) {
        int64_t t = to ? *(int64_t*)(uintptr_t)to : 0;
        *end = !to ? UINT64_MAX : t < 0 ? real_ms() + (uint64_t)(-t / 10000) : real_ms();
    }
    if (real_ms() >= *end) return 0;
    ntp_yield();
    return 1;
}
static uint32_t s_wait1(uint32_t* a) {
    for (uint64_t end = 0;;) {
        if (signaled(a[0], 1)) return 0;
        if (!wait_more(a[2], &end)) return end ? ST_TIMEOUT : wait_timeout(a[2], "NtWaitForSingleObject");
    }
}

/* NtWaitForMultipleObjects(Count, Handles*, WaitType(0 all, 1 any), Alertable, Timeout*) */
static uint32_t s_waitn(uint32_t* a) {
    uint32_t n = a[0], hs = a[1];
    for (uint64_t end = 0;;) {
    if (a[2] == 1) {
        for (uint32_t i = 0; i < n; i++) if (signaled(MEM32(hs + 4 * i), 1)) return i;
    } else {
        uint32_t i;
        for (i = 0; i < n && signaled(MEM32(hs + 4 * i), 0); i++) ;
        if (i == n) { for (i = 0; i < n; i++) signaled(MEM32(hs + 4 * i), 1); return 0; }
    }
    if (!wait_more(a[4], &end)) return end ? ST_TIMEOUT : wait_timeout(a[4], "NtWaitForMultipleObjects");
    }
}

/* I/O completion ports (the thread pool's): a queue of packets nobody but the guest fills */
static uint32_t s_create_iocomp(uint32_t* a) {
    obj_t* o = obj_new(O_IOCOMP);
    MEM32(a[0]) = h_put(o);
    return 0;
}
/* NtSetIoCompletion(Port, KeyContext, ApcContext, Status, Information) */
static uint32_t s_set_iocomp(uint32_t* a) {
    obj_t* o = h_get(a[0]);
    if (!o || o->type != O_IOCOMP) return ST_INVALID_HANDLE;
    if (o->qn == o->qcap) o->q = realloc(o->q, (o->qcap = o->qcap * 2 + 16) * 16);
    memcpy(o->q + 4 * o->qn++, a + 1, 16);
    return 0;
}
/* NtRemoveIoCompletion(Port, KeyContext*, ApcContext*, IoStatusBlock*, Timeout*) */
static uint32_t s_remove_iocomp(uint32_t* a) {
    for (uint64_t end = 0;;) {
        obj_t* o = h_get(a[0]);
        if (!o || o->type != O_IOCOMP) return ST_INVALID_HANDLE;
        if (o->qn) {
            uint32_t* p = o->q;
            MEM32(a[1]) = p[0], MEM32(a[2]) = p[1], MEM32(a[3]) = p[2], MEM32(a[3] + 4) = p[3];
            memmove(p, p + 4, (size_t)--o->qn * 16);
            return 0;
        }
        if (!wait_more(a[4], &end)) return end ? ST_TIMEOUT : wait_timeout(a[4], "NtRemoveIoCompletion");
    }
}

/* the global atom table (GlobalAddAtom): NtAddAtom/NtFindAtom(Name, Length in bytes, Atom*), NtDeleteAtom(Atom) */
static char* g_atom[0x1000];
static uint32_t g_atomref[0x1000];               /* (NT counts references: GlobalDeleteAtom drops one) */
static uint32_t atom_op(uint32_t* a, int add) {
    char n[512];
    uint32_t len = a[1] / 2 > 255 ? 255 : a[1] / 2;
    u16_to_u8((const uint16_t*)(uintptr_t)a[0], len, n, sizeof n);
    if (n[0] == '#') { if (a[2]) MEM16(a[2]) = (uint16_t)atoi(n + 1); return 0; }
    int i, fr = -1;
    for (i = 0; i < 0x1000; i++) {
        if (g_atom[i] && !strcasecmp(g_atom[i], n)) break;
        if (!g_atom[i] && fr < 0) fr = i;
    }
    if (i == 0x1000) {
        if (!add) return ST_NAME_NOT_FOUND;
        if (fr < 0) return ST_NO_MEMORY;
        g_atom[i = fr] = strdup(n);
    }
    if (add) g_atomref[i]++;
    if (a[2]) MEM16(a[2]) = (uint16_t)(0xC000 + i);
    return 0;
}
static uint32_t s_add_atom(uint32_t* a) { return atom_op(a, 1); }
static uint32_t s_find_atom(uint32_t* a) { return atom_op(a, 0); }
static uint32_t s_delete_atom(uint32_t* a) {
    uint32_t i = (a[0] & 0xFFFF) - 0xC000;
    if (i < 0x1000 && g_atom[i] && !--g_atomref[i]) { free(g_atom[i]); g_atom[i] = NULL; }
    return 0;
}

/* NtDelayExecution(Alertable, Interval*) */
static uint32_t s_delay(uint32_t* a) {
    uint64_t end = 0;
    while (wait_more(a[1], &end)) ;
    if (!end) wait_timeout(a[1], "NtDelayExecution");
    return 0;
}

/* ------------------------------------------------------------- sections */
#define MAX_NLS 32
static struct { char name[96], file[1024]; } g_nls[MAX_NLS];
static int g_nnls;
void ntp_section_file(const char* name, const char* file) {
    if (g_nnls < MAX_NLS) {
        snprintf(g_nls[g_nnls].name, sizeof g_nls[0].name, "%s", name);
        snprintf(g_nls[g_nnls++].file, sizeof g_nls[0].file, "%s", file);
    }
}

#define MAX_VIEWS 256
static struct { uint32_t base, span; } g_view[MAX_VIEWS];

static uint32_t map_view(obj_t* s, uint32_t want, uint32_t off, uint32_t size) {
    if (!size) size = s->size - off;
    uint32_t span = (size + 0xFFFF) & ~0xFFFFu;
    uint32_t a = vm_reserve(want & ~0xFFFFu, span, PT_MAPPED, 0);
    if (!a) return 0;
    int shared = s->fd >= 0 && s->image == 2;     /* a memfd: views alias */
    uint32_t psz = (size + 0xFFF) & ~0xFFFu;
    if (s->fd >= 0) {
        if (mmap((void*)(uintptr_t)a, psz, PROT_READ | PROT_WRITE, MAP_FIXED | (shared ? MAP_SHARED : MAP_PRIVATE), s->fd, off) == MAP_FAILED) {
            munmap((void*)(uintptr_t)a, span);
            mark(a, span, PG_FREE, 0, 0, 0);
            return 0;
        }
    } else mprotect((void*)(uintptr_t)a, psz, PROT_READ | PROT_WRITE);
    for (uint32_t p = a >> 12; p < (a + psz) >> 12; p++) pg_state[p] = PG_COMMITTED, pg_prot[p] = 0x04, pg_aprot[p] = 0x04;
    for (int i = 0; i < MAX_VIEWS; i++) if (!g_view[i].base) { g_view[i].base = a, g_view[i].span = span; break; }
    return a;
}

static obj_t* file_section(const char* path) {
    int fd = open(path, O_RDONLY);
    struct stat st;
    if (fd < 0 || fstat(fd, &st)) { if (fd >= 0) close(fd); return NULL; }
    obj_t* s = obj_new(O_SECTION);
    s->fd = fd, s->size = (uint32_t)st.st_size;
    return s;
}

/* NtOpenSection(Handle*, Access, OA): csrss's \NLS\NlsSection* from files */
static uint32_t s_open_section(uint32_t* a) {
    char n[512];
    us_to_u8(a[2] ? MEM32(a[2] + 8) : 0, n, sizeof n);
    for (int i = 0; i < g_nnls; i++)
        if (!strcasecmp(g_nls[i].name, n)) {
            obj_t* s = file_section(g_nls[i].file);
            if (!s) break;
            MEM32(a[0]) = h_put(s);
            return 0;
        }
    fprintf(stderr, "[ntposix] NtOpenSection %s: not found\n", n);
    return ST_NAME_NOT_FOUND;
}

/* NtCreateSection(Handle*, Access, OA, MaximumSize*, Protect, Attributes, File) */
/* A lifted image is never really unmapped (its code is in the host), so a DLL the loader unloads
 * and loads again would keep the data its DllMain left at PROCESS_DETACH (oleaut32's CRT heap,
 * after clbcatq's failed load). NT maps a fresh copy: the writable sections are saved at the
 * first map and put back on a map after an unmap (syscall32.c's img_writable). */
static void img_writable(int m, int restore) {
    uint32_t b = g_mod[m].base, nt = b + MEM32(b + 0x3C), sh = nt + 0x18 + MEM16(nt + 0x14), n = 0, o = 0;
    for (int pass = 0; pass < 2; pass++)
        for (uint32_t k = 0; k < MEM16(nt + 6); k++) {
            uint32_t h = sh + 40 * k, v = MEM32(h + 8);
            if (!(MEM32(h + 36) & 0x80000000u)) continue;          /* IMAGE_SCN_MEM_WRITE */
            if (!pass) { n += v; continue; }
            void* at = (void*)(uintptr_t)(b + MEM32(h + 12));
            if (restore) memcpy(at, g_mod[m].snap + o, v); else memcpy(g_mod[m].snap + o, at, v);
            o += v;
        }
    (void)n;
}
static void img_mapped(int m) {
    if (m < 0) return;
    if (!g_mod[m].snap) {
        uint32_t b = g_mod[m].base, nt = b + MEM32(b + 0x3C), sh = nt + 0x18 + MEM16(nt + 0x14), n = 0;
        for (uint32_t k = 0; k < MEM16(nt + 6); k++) if (MEM32(sh + 40 * k + 36) & 0x80000000u) n += MEM32(sh + 40 * k + 8);
        g_mod[m].snap = malloc(n ? n : 1);
        img_writable(m, 0);
    } else if (g_mod[m].gone) {
        img_writable(m, 1);
        fprintf(stderr, "[nt] %s mapped again: its writable sections as at its first map\n", g_mod[m].name);
    }
    g_mod[m].gone = 0;
}

static uint32_t s_create_section(uint32_t* a) {
    obj_t* f = a[6] ? h_get(a[6]) : NULL;
    if (a[5] & 0x01000000u) {                                          /* SEC_IMAGE */
        if (!f || f->type != O_FILE) return ST_INVALID_HANDLE;
        const char* name = base_name(f->guest);
        size_t n = strlen(name);
        int m = module_by_name(name), p = proxy_by_name(name);
        uint32_t base = 0;
        int exe = n > 4 && (!strcasecmp(name + n - 4, ".exe") || !strcasecmp(name + n - 4, ".com") || !strcasecmp(name + n - 4, ".scr"));
        if (m >= 0) base = g_mod[m].base, img_mapped(m);
        else if (exe) {
            fprintf(stderr, "[guard] %s: a program that is not lifted: not run\n", f->guest);
            return ST_ACCESS_DENIED;
        } else if (p >= 0) {
            base = proxy_image(p);
            fprintf(stderr, "[nt] %s: host stubs, through a proxy image at 0x%08X\n", f->guest, base);
        } else {
            fprintf(stderr, "[guard] %s is neither lifted nor provided: not mapped\n", f->guest);
            return ST_ACCESS_DENIED;
        }
        obj_t* s = obj_new(O_IMAGE);
        s->base = base, s->size = image_size(base);
        MEM32(a[0]) = h_put(s);
        return 0;
    }
    obj_t* s = obj_new(O_SECTION);
    uint32_t size = a[3] ? MEM32(a[3]) : 0;
    if (f && f->type == O_FILE && f->fd >= 0) {
        struct stat st;
        fstat(f->fd, &st);
        s->fd = dup(f->fd);
        s->size = size ? size : (uint32_t)st.st_size;
    } else {
        s->fd = memfd_create("ntsection", 0);
        s->image = 2;
        s->size = size;
        if (s->fd < 0 || ftruncate(s->fd, size)) { obj_release(s); return ST_NO_MEMORY; }
    }
    MEM32(a[0]) = h_put(s);
    return 0;
}

/* NtMapViewOfSection(Section, Process, Base*, ZeroBits, Commit, Offset*, ViewSize*, Inherit, AllocType, Protect) */
static uint32_t s_map_view(uint32_t* a) {
    obj_t* s = h_get(a[0]);
    if (!s) return ST_INVALID_HANDLE;
    if (s->type == O_IMAGE) {
        MEM32(a[2]) = s->base;
        MEM32(a[6]) = s->size;
        return 0;
    }
    if (s->type != O_SECTION) return ST_INVALID_HANDLE;
    uint32_t off = a[5] ? MEM32(a[5]) : 0;
    uint32_t v = map_view(s, MEM32(a[2]), off & ~0xFFFu, MEM32(a[6]) ? MEM32(a[6]) + (off & 0xFFF) : 0);
    if (!v) return MEM32(a[2]) ? ST_CONFLICTING_ADDR : ST_NO_MEMORY;
    MEM32(a[2]) = v + (off & 0xFFF);
    MEM32(a[6]) = ((MEM32(a[6]) ? MEM32(a[6]) : s->size - off) + 0xFFF) & ~0xFFFu;
    return 0;
}

/* NtUnmapViewOfSection(Process, Base) */
static uint32_t s_unmap_view(uint32_t* a) {
    for (int i = 0; i < MAX_VIEWS; i++)
        if (g_view[i].base && a[1] >= g_view[i].base && a[1] < g_view[i].base + g_view[i].span) {
            munmap((void*)(uintptr_t)g_view[i].base, g_view[i].span);
            mark(g_view[i].base, g_view[i].span, PG_FREE, 0, 0, 0);
            g_view[i].base = 0;
            return 0;
        }
    for (int i = 0; i < g_nmod; i++) if (g_mod[i].base == a[1]) g_mod[i].gone = 1;
    return 0;      /* an image: stays (its data is put back if it is mapped again) */
}

/* NtQuerySection(Section, Class, Buffer, Length, ReturnLength*) */
static uint32_t s_query_section(uint32_t* a) {
    obj_t* s = h_get(a[0]);
    uint32_t o = a[2];
    if (!s) return ST_INVALID_HANDLE;
    if (a[1] == 0 && a[3] >= 16) {                       /* SectionBasicInformation */
        MEM32(o) = s->type == O_IMAGE ? s->base : 0;
        MEM32(o + 4) = s->type == O_IMAGE ? 0x01000000u : 0x08000000u;
        *(uint64_t*)(uintptr_t)(o + 8) = s->size;
        if (a[4]) MEM32(a[4]) = 16;
        return 0;
    }
    if (a[1] != 1 || s->type != O_IMAGE || a[3] < 0x30) return ST_INVALID_INFO_CLASS;
    uint32_t nt = s->base + MEM32(s->base + 0x3C);
    memset((void*)(uintptr_t)o, 0, 0x30);
    MEM32(o + 0x00) = MEM32(nt + 0x28) ? s->base + MEM32(nt + 0x28) : 0;
    MEM32(o + 0x08) = MEM32(nt + 0x60);                  /* stack reserve */
    MEM32(o + 0x0C) = MEM32(nt + 0x64);                  /* stack commit */
    MEM32(o + 0x10) = MEM16(nt + 0x5C);                  /* subsystem */
    MEM16(o + 0x14) = MEM16(nt + 0x4A);
    MEM16(o + 0x16) = MEM16(nt + 0x48);
    MEM16(o + 0x1C) = MEM16(nt + 0x16);
    MEM16(o + 0x1E) = MEM16(nt + 0x5E);
    MEM16(o + 0x20) = MEM16(nt + 0x04);
    MEM8(o + 0x22) = 1;
    if (a[4]) MEM32(a[4]) = 0x30;
    return 0;
}

/* ------------------------------------------------------------- system info */
static uint32_t g_peb, g_harderror;

static void basic_info(uint32_t o) {
    memset((void*)(uintptr_t)o, 0, 0x2C);
    long pages = sysconf(_SC_PHYS_PAGES);
    MEM32(o + 4) = 156250;
    MEM32(o + 8) = 0x1000;
    MEM32(o + 12) = (uint32_t)(pages > 0x3FFFF ? 0x3FFFF : pages);   /* reported as 1 GB at most */
    MEM32(o + 16) = 1;
    MEM32(o + 20) = MEM32(o + 12);
    MEM32(o + 24) = 0x10000;
    MEM32(o + 28) = 0x10000;
    MEM32(o + 32) = 0x7FFEFFFF;
    MEM32(o + 36) = 1;
    MEM8(o + 40) = 1;
}
static void timeofday(uint32_t o) {
    memset((void*)(uintptr_t)o, 0, 0x30);
    struct timespec up;
    clock_gettime(CLOCK_MONOTONIC, &up);
    uint64_t now = now_ft();
    *(uint64_t*)(uintptr_t)o = now - ((uint64_t)up.tv_sec * 10000000ull);
    *(uint64_t*)(uintptr_t)(o + 8) = now;
    *(int64_t*)(uintptr_t)(o + 16) = tz_bias();
}

/* NtQuerySystemInformation(Class, Buffer, Length, ReturnLength*) */
static uint32_t s_query_system(uint32_t* a) {
    uint32_t o = a[1], n;
    switch (a[0]) {
    case 0: if (a[2] < 0x2C) return ST_INFO_LENGTH; basic_info(o); n = 0x2C; break;
    case 1:                                              /* Processor: i686 */
        if (a[2] < 12) return ST_INFO_LENGTH;
        memset((void*)(uintptr_t)o, 0, 12);
        MEM16(o + 2) = 6;
        MEM16(o + 4) = 0x0801;
        MEM32(o + 8) = 0x2FFF;
        n = 12;
        break;
    case 3: if (a[2] < 0x30) return ST_INFO_LENGTH; timeofday(o); n = 0x30; break;
    case 50: if (a[2] < 4) return ST_INFO_LENGTH; MEM32(o) = 0x80000000u; n = 4; break;   /* SystemRangeStart */
    default:
        fprintf(stderr, "[ntposix] NtQuerySystemInformation class %u\n", a[0]);
        return ST_INVALID_INFO_CLASS;
    }
    if (a[3]) MEM32(a[3]) = n;
    return 0;
}

static uint32_t s_query_system_time(uint32_t* a) { *(uint64_t*)(uintptr_t)a[0] = now_ft(); return 0; }
static uint32_t s_query_perf(uint32_t* a) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    *(uint64_t*)(uintptr_t)a[0] = (uint64_t)t.tv_sec * 10000000ull + (uint64_t)t.tv_nsec / 100;
    if (a[1]) *(uint64_t*)(uintptr_t)a[1] = 10000000ull;
    return 0;
}
static uint32_t s_tick(uint32_t* a) { (void)a; return (uint32_t)mono_ms(); }
static uint32_t s_luid(uint32_t* a) { static uint32_t n = 0x1000; MEM32(a[0]) = n++; MEM32(a[0] + 4) = 0; return 0; }
static uint32_t s_default_locale(uint32_t* a) { MEM32(a[1]) = 0x409; return 0; }
static uint32_t s_ui_language(uint32_t* a) { MEM16(a[0]) = 0x409; return 0; }

/* NtQueryInformationProcess(Process, Class, Buffer, Length, ReturnLength*) */
static uint32_t s_query_process(uint32_t* a) {
    uint32_t o = a[2], n;
    switch (a[1]) {
    case 0:                                              /* Basic */
        if (a[3] < 24) return ST_INFO_LENGTH;
        memset((void*)(uintptr_t)o, 0, 24);
        MEM32(o + 0) = 0x103;                            /* STILL_ACTIVE */
        MEM32(o + 4) = g_peb;
        MEM32(o + 8) = 1;
        MEM32(o + 12) = 8;
        MEM32(o + 16) = g_pid;
        n = 24;
        break;
    case 0xC: MEM32(o) = g_harderror; n = 4; break;      /* DefaultHardErrorMode */
    case 0x1A: MEM32(o) = 0; n = 4; break;               /* Wow64Information: none */
    case 0x18: MEM32(o) = 0; n = 4; break;               /* SessionInformation: session 0 */
    default:
        fprintf(stderr, "[ntposix] NtQueryInformationProcess class %u\n", a[1]);
        return ST_INVALID_INFO_CLASS;
    }
    if (a[4]) MEM32(a[4]) = n;
    return 0;
}
/* NtOpenProcess(Handle*, Access, OA, CLIENT_ID*): only the guest's own process, as the current-process
 * handle (explorer asks for its own session). Any other process does not exist here. */
static uint32_t s_open_process(uint32_t* a) {
    if (!a[3] || MEM32(a[3]) != g_pid) return 0xC000000Bu;   /* STATUS_INVALID_CID */
    MEM32(a[0]) = 0xFFFFFFFFu;
    return 0;
}
/* NtQuerySecurityObject(Handle, SecurityInformation, SD*, Length, LengthNeeded*): a self-relative
 * descriptor with a NULL DACL (everyone may): the only user is the guest itself.
 * ponytail: no owner/group SIDs; add when a caller reads them */
static uint32_t s_query_security(uint32_t* a) {
    if (a[4]) MEM32(a[4]) = 20;
    if (a[3] < 20) return ST_BUFFER_TOO_SMALL;
    memset((void*)(uintptr_t)a[2], 0, 20);
    MEM8(a[2]) = 1;                                      /* SECURITY_DESCRIPTOR_REVISION */
    MEM16(a[2] + 2) = 0x8004;                            /* SE_SELF_RELATIVE | SE_DACL_PRESENT, Dacl 0: NULL DACL */
    return 0;
}
static uint32_t s_set_process(uint32_t* a) { if (a[1] == 0xC) g_harderror = MEM32(a[2]); return 0; }

/* NtQueryInformationThread(Thread, Class, Buffer, Length, ReturnLength*) */
static uint32_t s_query_thread(uint32_t* a) {
    uint32_t o = a[2];
    if (a[1] != 0 || a[3] < 28) return ST_INVALID_INFO_CLASS;
    memset((void*)(uintptr_t)o, 0, 28);
    MEM32(o + 0) = 0x103;
    MEM32(o + 4) = g_teb;
    MEM32(o + 8) = g_pid;
    MEM32(o + 12) = g_tid;
    MEM32(o + 16) = 1;
    MEM32(o + 20) = 8;
    if (a[4]) MEM32(a[4]) = 28;
    return 0;
}

static uint32_t s_terminate_process(uint32_t* a) {
    if (a[0] == 0) return 0;                             /* the other threads: there are none */
    fflush(NULL);
    _exit((int)a[1]);
}
static uint32_t s_terminate_thread(uint32_t* a) {
    if (t_self && (!a[0] || a[0] == 0xFFFFFFFEu || h_get(a[0]) == t_self)) {   /* a second thread ends */
        t_self->signaled = 1, g_nthreads--;
        pthread_mutex_unlock(&g_big);
        pthread_exit(NULL);
    }
    if (a[0] && a[0] != 0xFFFFFFFEu) return ST_INVALID_HANDLE;
    fflush(NULL);
    _exit((int)a[1]);
}

/* NtRaiseHardError(Status, N, UnicodeStringMask, Parameters*, ResponseOption, Response*) */
static uint32_t s_hard_error(uint32_t* a) {
    fprintf(stderr, "[nt] hard error %08X", a[0]);
    for (uint32_t i = 0; i < a[1] && i < 4 && a[3]; i++) {
        uint32_t p = MEM32(a[3] + 4 * i);
        char s[512];
        if (a[2] & (1u << i)) { us_to_u8(p, s, sizeof s); fprintf(stderr, " \"%s\"", s); }
        else fprintf(stderr, " %08X", p);
    }
    fprintf(stderr, "\n");
    if (a[5]) MEM32(a[5]) = 1;
    return 0;
}

static uint32_t s_no_process(uint32_t* a) {
    (void)a;
    fprintf(stderr, "[guard] the guest tried to create a process: refused\n");
    return ST_ACCESS_DENIED;
}

/* NtOpenDirectoryObject: \KnownDlls must not exist (the loader then searches the DLL path) */
static uint32_t s_open_dirobj(uint32_t* a) {
    char n[512];
    us_to_u8(a[2] ? MEM32(a[2] + 8) : 0, n, sizeof n);
    if (!strncasecmp(n, "\\KnownDlls", 10)) return ST_NAME_NOT_FOUND;
    return new_handle(a[0], O_DIROBJ, 1, 1);
}
static uint32_t s_query_dirobj(uint32_t* a) { (void)a; return ST_NO_MORE_ENTRIES; }

/* The user: one SID, S-1-5-21-1-2-3-1000, whose HKCU is USER_KEY (below) */
static uint32_t s_open_token(uint32_t* a) { return new_handle(a[2], O_TOKEN, 1, 1); }
/* NtQueryInformationToken(Token, Class, Buffer, Length, ReturnLength*) */
static uint32_t s_query_token(uint32_t* a) {
    obj_t* o = h_get(a[0]);
    uint32_t b = a[2], need;
    if (!o || o->type != O_TOKEN) return ST_INVALID_HANDLE;
    switch (a[1]) {
    case 1:                                              /* TokenUser: SID_AND_ATTRIBUTES, then the SID */
        need = 8 + 28;
        if (a[4]) MEM32(a[4]) = need;
        if (a[3] < need) return ST_BUFFER_TOO_SMALL;
        MEM32(b) = b + 8, MEM32(b + 4) = 0;
        MEM8(b + 8) = 1, MEM8(b + 9) = 5;                /* revision, 5 sub-authorities */
        memset((void*)(uintptr_t)(b + 10), 0, 6), MEM8(b + 15) = 5;   /* NT authority */
        MEM32(b + 16) = 21, MEM32(b + 20) = 1, MEM32(b + 24) = 2, MEM32(b + 28) = 3, MEM32(b + 32) = 1000;
        return 0;
    case 10:                                             /* TokenStatistics */
        need = 56;
        if (a[4]) MEM32(a[4]) = need;
        if (a[3] < need) return ST_BUFFER_TOO_SMALL;
        memset((void*)(uintptr_t)b, 0, need);
        MEM32(b) = 0x1001, MEM32(b + 8) = 0x3E7;         /* TokenId, AuthenticationId */
        MEM32(b + 24) = 1;                               /* TokenPrimary */
        return 0;
    default:
        fprintf(stderr, "[ntposix] NtQueryInformationToken class %u\n", a[1]);
        return ST_INVALID_INFO_CLASS;
    }
}
static uint32_t s_open_thread_token(uint32_t* a) { (void)a; return ST_NO_TOKEN; }
/* The registry box: one tree of keys and values in memory, seeded with what
 * the guest's NLS code checks (IsValidLocale: the locale's key and its
 * language group; the user's International values), then loaded from the
 * box file (ntp_regbox) and saved to it after every write. There is no host
 * registry here: the guest sees the seed and the file, nothing else. The file
 * is text, one "[\Registry\...]" line per key and one "name"=hex(T):xx,xx
 * line per value (@ for the default value).
 * ponytail: a flat array scanned linearly, the whole file rewritten per
 * write; a hash and a flush at idle if a guest writes a lot. */
#define USER_KEY "\\REGISTRY\\USER\\S-1-5-21-1-2-3-1000"
static const struct { const char* key; const char* name; const char* sz; } g_reg[] = {
    { "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\Locale", "00000409", "1" },
    { "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\Locale\\Alternate Sorts", NULL, NULL },
    { "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\Language Groups", "1", "1" },
    { USER_KEY, NULL, NULL },
    /* what Windows 2000 setup writes for US English */
#define INTL USER_KEY "\\Control Panel\\International"
    { INTL, "Locale", "00000409" }, { INTL, "sLanguage", "ENU" }, { INTL, "sCountry", "United States" },
    { INTL, "iCountry", "1" }, { INTL, "sList", "," }, { INTL, "iMeasure", "1" }, { INTL, "iPaperSize", "1" },
    { INTL, "sDecimal", "." }, { INTL, "sThousand", "," }, { INTL, "sGrouping", "3;0" }, { INTL, "iDigits", "2" },
    { INTL, "iLZero", "1" }, { INTL, "iNegNumber", "1" }, { INTL, "sNegativeSign", "-" }, { INTL, "sPositiveSign", "" },
    { INTL, "sNativeDigits", "0123456789" }, { INTL, "NumShape", "1" },
    { INTL, "sCurrency", "$" }, { INTL, "iCurrDigits", "2" }, { INTL, "iCurrency", "0" }, { INTL, "iNegCurr", "0" },
    { INTL, "sMonDecimalSep", "." }, { INTL, "sMonThousandSep", "," }, { INTL, "sMonGrouping", "3;0" },
    { INTL, "sDate", "/" }, { INTL, "iDate", "0" }, { INTL, "sShortDate", "M/d/yyyy" },
    { INTL, "sLongDate", "dddd, MMMM dd, yyyy" }, { INTL, "sTime", ":" }, { INTL, "iTime", "0" },
    { INTL, "iTLZero", "0" }, { INTL, "iTimePrefix", "0" }, { INTL, "sTimeFormat", "h:mm:ss tt" },
    { INTL, "s1159", "AM" }, { INTL, "s2359", "PM" }, { INTL, "iCalendarType", "1" },
    { INTL, "iFirstDayOfWeek", "6" }, { INTL, "iFirstWeekOfYear", "0" },
};
#define NREG ((int)(sizeof g_reg / sizeof g_reg[0]))

typedef struct rval { char* name; uint32_t type, len; uint8_t* data; struct rval* next; } rval_t;
typedef struct { char* path; int parent, dead; rval_t* vals, *last; } rkey_t;
static rkey_t* g_rk;
static int g_nrk, g_rkinit;
static char g_regfile[1024];
static pthread_mutex_t g_regmu = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

static int rk_find(const char* p) {
    for (int i = 0; i < g_nrk; i++) if (!g_rk[i].dead && !strcasecmp(g_rk[i].path, p)) return i;
    return -1;
}
static int rk_make(const char* p) {
    int k = rk_find(p);
    if (k >= 0) return k;
    char par[1024];
    snprintf(par, sizeof par, "%s", p);
    char* sl = strrchr(par, '\\');
    int pi = -1;
    if (sl && sl != par) { *sl = 0; pi = rk_make(par); }
    if (!(g_nrk & 255)) g_rk = realloc(g_rk, (g_nrk + 256) * sizeof *g_rk);
    g_rk[g_nrk] = (rkey_t){ strdup(p), pi, 0, NULL, NULL };
    return g_nrk++;
}
static rval_t* rv_find(int k, const char* n) {
    for (rval_t* v = g_rk[k].vals; v; v = v->next) if (!strcasecmp(v->name, n)) return v;
    return NULL;
}
static void rv_set(int k, const char* n, uint32_t type, const void* d, uint32_t len) {
    rval_t* v = rv_find(k, n);
    if (!v) {                                    /* appended: values enumerate in the order they were set */
        v = calloc(1, sizeof *v);
        v->name = strdup(n);
        if (g_rk[k].last) g_rk[k].last->next = v; else g_rk[k].vals = v;
        g_rk[k].last = v;
    }
    free(v->data);
    v->type = type, v->len = len, v->data = malloc(len ? len : 1);
    memcpy(v->data, d, len);
}
static void reg_save(void) {
    if (!g_regfile[0]) return;
    char tmp[1100];
    snprintf(tmp, sizeof tmp, "%s.new", g_regfile);
    FILE* f = fopen(tmp, "w");
    if (!f) return;
    for (int i = 0; i < g_nrk; i++) {
        if (g_rk[i].dead) continue;
        fprintf(f, "[%s]\n", g_rk[i].path);
        for (rval_t* v = g_rk[i].vals; v; v = v->next) {
            if (!v->name[0]) fputc('@', f);
            else {
                fputc('"', f);
                for (const char* c = v->name; *c; c++) { if (*c == '"' || *c == '\\') fputc('\\', f); fputc(*c, f); }
                fputc('"', f);
            }
            fprintf(f, "=hex(%x):", v->type);
            for (uint32_t j = 0; j < v->len; j++) fprintf(f, j ? ",%02x" : "%02x", v->data[j]);
            fputc('\n', f);
        }
    }
    fclose(f);
    rename(tmp, g_regfile);
}
static void reg_load(const char* file) {
    FILE* f = fopen(file, "r");
    if (!f) return;
    static char l[1 << 20];
    static uint8_t d[1 << 18];
    int k = -1;
    while (fgets(l, sizeof l, f)) {
        l[strcspn(l, "\r\n")] = 0;
        if (l[0] == '[') { char* e = strrchr(l, ']'); if (e) { *e = 0; k = rk_make(l + 1); } continue; }
        if (k < 0 || (l[0] != '"' && l[0] != '@')) continue;
        char n[1024];
        size_t o = 0;
        const char* c = l + 1;
        if (l[0] == '"') {
            while (*c && *c != '"' && o < sizeof n - 1) { if (*c == '\\' && c[1]) c++; n[o++] = *c++; }
            if (*c) c++;
        }
        n[o] = 0;
        unsigned type;
        if (sscanf(c, "=hex(%x):", &type) != 1 || !(c = strchr(c, ':'))) continue;
        uint32_t len = 0;
        for (c++; *c && len < sizeof d; ) {
            d[len++] = (uint8_t)strtoul(c, (char**)&c, 16);
            if (*c != ',') break;
            c++;
        }
        rv_set(k, n, type, d, len);
    }
    fclose(f);
}
static void reg_init(void) {
    if (g_rkinit) return;
    g_rkinit = 1;
    rk_make("\\Registry\\Machine\\Software\\Classes");
    for (int i = 0; i < NREG; i++) {
        int k = rk_make(g_reg[i].key);
        if (!g_reg[i].name) continue;
        uint16_t w[256];
        rv_set(k, g_reg[i].name, 1, w, 2u * (u8_to_u16(g_reg[i].sz, w, 256) + 1));
    }
    if (g_regfile[0]) reg_load(g_regfile);
}
void ntp_regbox(const char* file) { snprintf(g_regfile, sizeof g_regfile, "%s", file); }

/* OBJECT_ATTRIBUTES -> the key's full path */
static int key_path(uint32_t oa, char* full, int cap) {
    char n[512];
    obj_t* root = oa && MEM32(oa + 4) ? h_get(MEM32(oa + 4)) : NULL;
    us_to_u8(oa ? MEM32(oa + 8) : 0, n, sizeof n);
    size_t L = strlen(n);
    while (L && n[L - 1] == '\\') n[--L] = 0;
    if (root && root->type == O_KEY && root->guest) snprintf(full, cap, L ? "%s\\%s" : "%s", root->guest, n);
    else if (root) return 0;
    else snprintf(full, cap, "%s", n);
    return 1;
}
static int key_of(uint32_t h) {
    obj_t* o = h_get(h);
    return o && o->type == O_KEY && o->guest ? rk_find(o->guest) : -1;
}
static uint32_t key_handle(uint32_t at, int k) {
    obj_t* o = obj_new(O_KEY);
    o->guest = strdup(g_rk[k].path);
    MEM32(at) = h_put(o);
    return 0;
}
/* an information block: a fixed part, then a tail at off; NT's rules for a short buffer */
static uint32_t reg_out(uint32_t buf, uint32_t cap, uint32_t res, const void* hdr, uint32_t nh, const void* tail, uint32_t nt, uint32_t off) {
    uint32_t need = off + nt;
    if (res) MEM32(res) = need;
    if (cap < nh) return ST_BUFFER_TOO_SMALL;
    memcpy((void*)(uintptr_t)buf, hdr, nh);
    if (cap < need) return ST_BUFFER_OVERFLOW;
    if (nt) memcpy((void*)(uintptr_t)(buf + off), tail, nt);
    return 0;
}
static const char* leaf(const char* p) { const char* s = strrchr(p, '\\'); return s ? s + 1 : p; }

/* NtOpenKey(Handle*, Access, OA) */
static uint32_t s_registry(uint32_t* a) {
    char full[1024];
    pthread_mutex_lock(&g_regmu);
    reg_init();
    int k = key_path(a[2], full, sizeof full) ? rk_find(full) : -1;
    uint32_t r = k < 0 ? ST_NAME_NOT_FOUND : key_handle(a[0], k);
    pthread_mutex_unlock(&g_regmu);
    return r;
}
/* NtCreateKey(Handle*, Access, OA, TitleIndex, Class, Options, Disposition*) */
static uint32_t s_create_key(uint32_t* a) {
    char full[1024];
    pthread_mutex_lock(&g_regmu);
    reg_init();
    uint32_t r = ST_NAME_NOT_FOUND;
    if (key_path(a[2], full, sizeof full) && !strncasecmp(full, "\\Registry\\", 10)) {
        int had = rk_find(full) >= 0, k = rk_make(full);
        if (a[6]) MEM32(a[6]) = had ? 2 : 1;      /* REG_OPENED_EXISTING_KEY : REG_CREATED_NEW_KEY */
        if (!had) reg_save();
        r = key_handle(a[0], k);
    }
    pthread_mutex_unlock(&g_regmu);
    return r;
}

/* KEY_VALUE_{BASIC,FULL,PARTIAL}_INFORMATION */
static uint32_t value_info(rval_t* v, uint32_t cls, uint32_t buf, uint32_t cap, uint32_t res) {
    uint16_t wn[512];
    uint32_t nl = 2u * u8_to_u16(v->name, wn, 512), h[5];
    if (cls == 0) { h[0] = 0, h[1] = v->type, h[2] = nl; return reg_out(buf, cap, res, h, 12, wn, nl, 12); }
    if (cls == 2) { h[0] = 0, h[1] = v->type, h[2] = v->len; return reg_out(buf, cap, res, h, 12, v->data, v->len, 12); }
    if (cls != 1) return ST_INVALID_INFO_CLASS;
    uint32_t off = (20 + nl + 3) & ~3u, need = off + v->len;
    h[0] = 0, h[1] = v->type, h[2] = off, h[3] = v->len, h[4] = nl;
    if (res) MEM32(res) = need;
    if (cap < 20) return ST_BUFFER_TOO_SMALL;
    memcpy((void*)(uintptr_t)buf, h, 20);
    if (cap < need) return ST_BUFFER_OVERFLOW;
    memcpy((void*)(uintptr_t)(buf + 20), wn, nl);
    memcpy((void*)(uintptr_t)(buf + off), v->data, v->len);
    return 0;
}
/* NtQueryValueKey(Key, ValueName*, Class, Buffer, Length, ResultLength*) */
static uint32_t s_query_value(uint32_t* a) {
    char n[1024];
    pthread_mutex_lock(&g_regmu);
    int k = key_of(a[0]);
    us_to_u8(a[1], n, sizeof n);
    rval_t* v = k >= 0 ? rv_find(k, n) : NULL;
    uint32_t r = k < 0 ? ST_INVALID_HANDLE : !v ? ST_NAME_NOT_FOUND : value_info(v, a[2], a[3], a[4], a[5]);
    pthread_mutex_unlock(&g_regmu);
    return r;
}
/* NtEnumerateValueKey(Key, Index, Class, Buffer, Length, ResultLength*) */
static uint32_t s_enum_value(uint32_t* a) {
    pthread_mutex_lock(&g_regmu);
    int k = key_of(a[0]);
    rval_t* v = k >= 0 ? g_rk[k].vals : NULL;
    for (uint32_t i = 0; v && i < a[1]; i++) v = v->next;
    uint32_t r = k < 0 ? ST_INVALID_HANDLE : !v ? ST_NO_MORE_ENTRIES : value_info(v, a[2], a[3], a[4], a[5]);
    pthread_mutex_unlock(&g_regmu);
    return r;
}
/* NtSetValueKey(Key, ValueName*, TitleIndex, Type, Data, DataSize) */
static uint32_t s_set_value(uint32_t* a) {
    char n[1024];
    pthread_mutex_lock(&g_regmu);
    int k = key_of(a[0]);
    us_to_u8(a[1], n, sizeof n);
    if (k >= 0) { rv_set(k, n, a[3], (const void*)(uintptr_t)a[4], a[5]); reg_save(); }
    pthread_mutex_unlock(&g_regmu);
    return k < 0 ? ST_INVALID_HANDLE : 0;
}
/* NtDeleteValueKey(Key, ValueName*) */
static uint32_t s_delete_value(uint32_t* a) {
    char n[1024];
    pthread_mutex_lock(&g_regmu);
    int k = key_of(a[0]);
    uint32_t r = k < 0 ? ST_INVALID_HANDLE : ST_NAME_NOT_FOUND;
    us_to_u8(a[1], n, sizeof n);
    if (k >= 0) {
        rval_t* prev = NULL;
        for (rval_t* v = g_rk[k].vals; v; prev = v, v = v->next) {
            if (strcasecmp(v->name, n)) continue;
            if (prev) prev->next = v->next; else g_rk[k].vals = v->next;
            if (g_rk[k].last == v) g_rk[k].last = prev;
            free(v->name), free(v->data), free(v);
            reg_save();
            r = 0;
            break;
        }
    }
    pthread_mutex_unlock(&g_regmu);
    return r;
}
/* NtDeleteKey(Key): only a key with no subkeys, as NT */
static uint32_t s_delete_key(uint32_t* a) {
    pthread_mutex_lock(&g_regmu);
    int k = key_of(a[0]);
    uint32_t r = k < 0 ? ST_INVALID_HANDLE : 0;
    for (int i = 0; k >= 0 && i < g_nrk; i++) if (!g_rk[i].dead && g_rk[i].parent == k) r = ST_ACCESS_DENIED;
    if (!r) { g_rk[k].dead = 1; reg_save(); }
    pthread_mutex_unlock(&g_regmu);
    return r;
}
/* KEY_BASIC / KEY_NODE / KEY_FULL_INFORMATION of key k */
static uint32_t key_info(int k, uint32_t cls, uint32_t buf, uint32_t cap, uint32_t res) {
    uint16_t wn[512];
    uint32_t nl = 2u * u8_to_u16(leaf(g_rk[k].path), wn, 512), h[11] = { 0 };
    if (cls == 0) { h[3] = nl; return reg_out(buf, cap, res, h, 16, wn, nl, 16); }
    if (cls == 1) { h[3] = 0xFFFFFFFFu, h[5] = nl; return reg_out(buf, cap, res, h, 24, wn, nl, 24); }
    if (cls != 2) return ST_INVALID_INFO_CLASS;
    h[3] = 44;                                           /* ClassOffset */
    for (int i = 0; i < g_nrk; i++) {
        if (g_rk[i].dead || g_rk[i].parent != k) continue;
        uint32_t l = 2u * (uint32_t)strlen(leaf(g_rk[i].path));
        h[5]++;
        if (l > h[6]) h[6] = l;
    }
    for (rval_t* v = g_rk[k].vals; v; v = v->next) {
        uint32_t l = 2u * (uint32_t)strlen(v->name);
        h[8]++;
        if (l > h[9]) h[9] = l;
        if (v->len > h[10]) h[10] = v->len;
    }
    return reg_out(buf, cap, res, h, 44, NULL, 0, 44);
}
/* NtQueryKey(Key, Class, Buffer, Length, ResultLength*) */
static uint32_t s_query_key(uint32_t* a) {
    pthread_mutex_lock(&g_regmu);
    int k = key_of(a[0]);
    uint32_t r = k < 0 ? ST_INVALID_HANDLE : key_info(k, a[1], a[2], a[3], a[4]);
    pthread_mutex_unlock(&g_regmu);
    return r;
}
/* NtEnumerateKey(Key, Index, Class, Buffer, Length, ResultLength*) */
static uint32_t s_enum_key(uint32_t* a) {
    pthread_mutex_lock(&g_regmu);
    int k = key_of(a[0]), c = -1;
    for (int i = 0, n = 0; k >= 0 && i < g_nrk; i++)
        if (!g_rk[i].dead && g_rk[i].parent == k && (uint32_t)n++ == a[1]) { c = i; break; }
    uint32_t r = k < 0 ? ST_INVALID_HANDLE : c < 0 ? ST_NO_MORE_ENTRIES : key_info(c, a[2], a[3], a[4], a[5]);
    pthread_mutex_unlock(&g_regmu);
    return r;
}
/* NtNotifyChangeKey: nothing else writes the box, so no change ever comes */
static uint32_t s_notify_key(uint32_t* a) { (void)a; return 0x103; }      /* STATUS_PENDING */

/* ------------------------------------------------------------- the RPC client call guard
 * (native32.c's): Windows 2000's ole32 calls rpcss with no __except around its stubs, since rpcss
 * is always there. Here no RPC server is, so an RPC status (0x6A4..0x7FF, or its HRESULT) that no
 * guest frame takes inside NdrClientCall2/NdrClientCall ends that call: the handlers it entered
 * unwind, and the stub returns the status. */
typedef struct rpcg {
    struct rpcg* prev;
    jmp_buf jb;
    uint32_t chain, esp, ebx, esi, edi, ebp, func, status;
    recomp_ehframe_t* frames;
} rpcg_t;
static __thread rpcg_t* t_rpcg;
static recomp_func_t g_rpc_orig[2];
static void rpc_guarded(int k) {
    rpcg_t g;
    g.prev = t_rpcg, g.chain = MEM32(g_fs_base), g.frames = t_frames;
    g.esp = g_esp, g.ebx = g_ebx, g.esi = g_esi, g.edi = g_edi, g.ebp = g_ebp, g.func = g_cur_func;
    t_rpcg = &g;
    if (!setjmp(g.jb)) g_rpc_orig[k]();
    else {
        MEM32(g_fs_base) = g.chain;
        t_frames = g.frames;
        g_esp = g.esp + 4, g_ebx = g.ebx, g_esi = g.esi, g_edi = g.edi, g_ebp = g.ebp, g_cur_func = g.func;
        g_eax = g.status, g_edx = 0;
        fprintf(stderr, "[rpc] client call failed with %08X: returned to the stub, not raised\n", g.status);
    }
    t_rpcg = g.prev;
}
static void shim_rpc_call2(void) { rpc_guarded(0); }
static void shim_rpc_call(void) { rpc_guarded(1); }
static void rpc_guard_install(void) {
    uint32_t rpc = ntp_module("rpcrt4.dll"), va;
    if (!rpc) return;
    if ((va = ntp_export(rpc, "NdrClientCall2")) && (g_rpc_orig[0] = recomp_lookup(va))) ntp_replace(va, shim_rpc_call2);
    if ((va = ntp_export(rpc, "NdrClientCall")) && (g_rpc_orig[1] = recomp_lookup(va))) ntp_replace(va, shim_rpc_call);
}
static void rpc_fail(uint32_t er, uint32_t ctx) {
    rpcg_t* g = t_rpcg;
    uint32_t code = er ? MEM32(er) : 0, c = (code & 0xFFFF0000u) == 0x80070000u ? code & 0xFFFF : code;
    if (!g || c < 0x6A4 || c > 0x7FF) return;
    MEM32(er + 4) |= 2u;                                     /* EXCEPTION_UNWINDING */
    for (uint32_t reg = MEM32(g_fs_base); reg && reg != 0xFFFFFFFFu && reg != g->chain; ) {
        uint32_t args[4] = { er, reg, ctx, 0 };
        if (recomp_lookup(MEM32(reg + 4))) ntp_guest(MEM32(reg + 4), 4, args);
        reg = MEM32(reg);
        MEM32(g_fs_base) = reg;
    }
    g->status = c;
    longjmp(g->jb, 1);
}

/* ------------------------------------------------------------- exceptions */
static uint32_t s_raise_exception(uint32_t* a) {
    uint32_t rec = a[0], ctx = a[1];
    static int depth;
    uint32_t ntdll = module_by_name("ntdll.dll") >= 0 ? g_mod[module_by_name("ntdll.dll")].base : 0;
    uint32_t kued = ntdll ? ntp_export(ntdll, "KiUserExceptionDispatcher") : 0;
    recomp_func_t f = kued ? recomp_lookup(kued) : NULL;
    if (a[2] && f && depth < 8) {                        /* first chance: the guest's own dispatcher */
        uint32_t sp = g_esp;
        g_esp -= 0x400;
        PUSH32(g_esp, ctx);
        PUSH32(g_esp, rec);
        depth++;
        f();
        depth--;
        g_esp = sp;
    }
    rpc_fail(rec, ctx);                                  /* in a guarded RPC client call: that call fails instead */
    fprintf(stderr, "\n[nt] unhandled guest exception %08X at %08X (first chance %u), eip %08X esp %08X\n",
            rec ? MEM32(rec) : 0, rec ? MEM32(rec + 12) : 0, a[2], ctx ? MEM32(ctx + 0xB8) : 0, ctx ? MEM32(ctx + 0xC4) : 0);
    fflush(NULL);
    _exit(rec ? (int)MEM32(rec) : 1);
}
/* NtContinue: back to the raiser (the context was captured there) */
static uint32_t s_continue(uint32_t* a) { g_eax = MEM32(a[0] + 0xB0); return MEM32(a[0] + 0xB0); }

/* ------------------------------------------------------------- csrss */
static uint32_t g_port;

static void ustr_u8(uint32_t at, const char* s) {
    uint16_t* w = (uint16_t*)(uintptr_t)ntp_alloc(0x1000);
    int n = u8_to_u16(s, w, 0x7FF);
    MEM16(at) = (uint16_t)(2 * n);
    MEM16(at + 2) = (uint16_t)(2 * n + 2);
    MEM32(at + 4) = (uint32_t)(uintptr_t)w;
}

/* BASE_STATIC_SERVER_DATA, NT 5.0 (csr32.c) */
static uint32_t base_static_server_data(void) {
    uint32_t d = ntp_alloc(0x2000);
    ustr_u8(d + 0x00, "C:\\WINNT");
    ustr_u8(d + 0x08, "C:\\WINNT\\system32");
    ustr_u8(d + 0x10, "\\BaseNamedObjects");
    MEM16(d + 0x18) = (uint16_t)MEM32(g_peb + 0xA4);
    MEM16(d + 0x1A) = (uint16_t)MEM32(g_peb + 0xA8);
    MEM16(d + 0x1C) = MEM16(g_peb + 0xAC);
    MEM16(d + 0x1E) = MEM16(g_peb + 0xAE);
    if (MEM16(g_peb + 0xAE) >> 8) {
        char sp[32];
        snprintf(sp, sizeof sp, "Service Pack %u", MEM16(g_peb + 0xAE) >> 8);
        u8_to_u16(sp, (uint16_t*)(uintptr_t)(d + 0x22), 128);
    }
    basic_info(d + 0x124);
    timeofday(d + 0x150);
    MEM32(d + 0x180) = ntp_alloc(0x1000);                /* IniFileMapping: empty */
    if (MEM16(g_peb + 0xAC) < 2195) MEM32(d + 0x184 + 0x1860) = 0x409;
    return d;
}

typedef uint32_t (*csr_fn)(uint32_t data);
/* csrsrv 0 ClientConnect: consrv's CONSOLE_INFO names our std handles */
void (*ntp_csr_connect)(uint32_t index, uint32_t info, uint32_t len);
static uint32_t csr_client_connect(uint32_t data) {
    uint32_t index = MEM32(data), ci = MEM32(data + 4);
    if (g_trace) fprintf(stderr, "[csr] client connect, server %u, info %08X len %u\n", index, ci, MEM32(data + 8));
    if (index != 2 && ntp_csr_connect && ci) ntp_csr_connect(index, ci, MEM32(data + 8));
    if (index == 2 && ci) {
        uint32_t e;
        MEM32(ci + 0x00) = 0x0C0Eu;
        new_handle((uint32_t)(uintptr_t)&e, O_EVENT, 0, 1); MEM32(ci + 0x04) = e;
        MEM32(ci + 0x08) = g_std[0];
        MEM32(ci + 0x0C) = g_std[1];
        MEM32(ci + 0x10) = g_std[2];
        new_handle((uint32_t)(uintptr_t)&e, O_EVENT, 1, 1); MEM32(ci + 0x14) = e;
        new_handle((uint32_t)(uintptr_t)&e, O_EVENT, 0, 1); MEM32(ci + 0x18) = e;
    }
    return 0;
}
/* basesrv 26 NlsGetUserInfo: UserLocaleId (+0x1860) */
static uint32_t csr_nls_user_info(uint32_t data) {
    uint32_t info = MEM32(data), len = MEM32(data + 4);
    if (!info || len < 0x1870) return ST_INVALID_PARAMETER;
    memset((void*)(uintptr_t)info, 0, len);
    MEM32(info + 0x1860) = 0x409;
    return 0;
}

static uint32_t lpc_connect(uint32_t* a, int secure) {
    char n[512];
    uint32_t cv = a[3], sv = a[secure ? 5 : 4], len = a[secure ? 6 : 5], info = a[secure ? 7 : 6];
    us_to_u8(a[1], n, sizeof n);
    size_t k = strlen(n);
    if (k < 8 || strcasecmp(n + k - 8, "\\ApiPort")) return ST_NAME_NOT_FOUND;
    if (cv && MEM32(cv + 4)) {                           /* the client's port memory, mapped "on both sides" */
        obj_t* s = h_get(MEM32(cv + 4));
        uint32_t v = s && s->type == O_SECTION ? map_view(s, 0, MEM32(cv + 8), MEM32(cv + 12)) : 0;
        if (!v) return ST_NO_MEMORY;
        MEM32(cv + 16) = MEM32(cv + 20) = v;
        if (sv) MEM32(sv + 4) = MEM32(cv + 12), MEM32(sv + 8) = v;
    }
    if (info) {
        static uint32_t srv, shared;
        if (!srv) {
            srv = ntp_alloc(64);
            shared = ntp_alloc(0x10000);
            MEM32(srv + 4) = base_static_server_data();
        }
        MEM32(info + 0x08) = g_pid;
        MEM32(info + 0x0C) = shared;
        MEM32(info + 0x10) = srv;
        MEM32(info + 0x14) = shared;
    }
    if (len) MEM32(len) = 0x148;
    if (!g_port) { obj_t* p = obj_new(O_PORT); g_port = h_put(p); }
    MEM32(a[0]) = g_port;
    return 0;
}
static uint32_t s_secure_connect(uint32_t* a) { return lpc_connect(a, 1); }
static uint32_t s_connect(uint32_t* a) { return lpc_connect(a, 0); }

/* NtRequestWaitReplyPort(Port, Request, Reply): CSR_API_MSG, api at +0x1C, data at +0x28 */
static uint32_t s_request_wait_reply(uint32_t* a) {
    if (!g_port || a[0] != g_port) return ST_INVALID_HANDLE;
    uint32_t m = a[1], api = MEM32(m + 0x1C), r = 0;
    csr_fn fn = api == 0 ? csr_client_connect : api == 0x1001A ? csr_nls_user_info : NULL;
    if (fn) r = fn(m + 0x28);
    else if (api == 0x10001 || api == 0x1000C || api == 0x30405) {
        /* basesrv CreateThread (csrss notes a thread), SetProcessShutdownParam, usersrv
         * GetThreadConsoleDesktop (none): success, nothing to keep */
        uint16_t total = MEM16(m + 2);
        if (api == 0x30405 && total > 0x28 && total < 0x1000) memset((void*)(uintptr_t)(m + 0x28), 0, total - 0x28);
    } else {
        uint16_t total = MEM16(m + 2);
        if (total > 0x28 && total < 0x1000) memset((void*)(uintptr_t)(m + 0x28), 0, total - 0x28);
        if (g_trace) fprintf(stderr, "[csr] api %u:%u not answered, from sub_%08X\n", api >> 16, api & 0xFFFF, g_cur_func);
    }
    MEM32(m + 0x20) = r;
    if (a[2] && a[2] != m) memcpy((void*)(uintptr_t)a[2], (void*)(uintptr_t)m, MEM16(m) + 0x18);
    return 0;
}

/* ------------------------------------------------------------- win32k
 * user32 and gdi32 call win32k through the same gate, services from
 * 0x1000; numbers and argument counts from their stubs, names from a
 * "0xNNNN Name" file (win2000's tools/w32k_names.py), as syscall32.c. A
 * window manager answers them by name (w32kposix.c). */
#define W32K_MAX 0x400
static struct { char name[64]; uint8_t argc, seen; uint32_t (*fn)(uint32_t*); } g_w32k[W32K_MAX];
void (*ntp_win32k_pre)(void);

int ntp_win32k(const uint32_t* bases, int nbases, const char* names_file) {
    int stubs = 0, named = 0;
    for (int m = 0; m < nbases; m++) {
        uint32_t base = bases[m], size = image_size(base);
        for (uint32_t p = base + 0x1000; p + 16 < base + size; p++) {
            const uint8_t* b = (const uint8_t*)(uintptr_t)p;
            if (b[0] != 0xB8 || b[5] != 0x8D || b[6] != 0x54 || b[7] != 0x24 || b[8] != 0x04 || b[9] != 0xCD || b[10] != 0x2E) continue;
            uint32_t svc = *(const uint32_t*)(b + 1);
            if (svc < 0x1000 || svc >= 0x1000 + W32K_MAX) continue;
            g_w32k[svc - 0x1000].argc = b[11] == 0xC2 ? (uint8_t)(*(const uint16_t*)(b + 12) / 4) : 0;
            stubs++;
        }
    }
    FILE* f = names_file ? fopen(names_file, "r") : NULL;
    if (f) {
        char line[128], name[64];
        unsigned num;
        while (fgets(line, sizeof line, f))
            if (sscanf(line, "%x %63s", &num, name) == 2 && num >= 0x1000 && num < 0x1000 + W32K_MAX) {
                strcpy(g_w32k[num - 0x1000].name, name);
                named++;
            }
        fclose(f);
    } else fprintf(stderr, "[win32k] %s: missing (services unnamed)\n", names_file ? names_file : "(none)");
    fprintf(stderr, "[win32k] %d stubs in the guest's user32/gdi32, %d names\n", stubs, named);
    return stubs;
}

void ntp_win32k_override(const char* name, uint32_t (*fn)(uint32_t*)) {
    for (int i = 0; i < W32K_MAX; i++)
        if (!strcmp(g_w32k[i].name, name)) { g_w32k[i].fn = fn; return; }
    fprintf(stderr, "[win32k] no service named %s\n", name);
}

static uint32_t win32k_call(uint32_t svc, uint32_t* args) {
    int i = (int)(svc - 0x1000);
    if (ntp_win32k_pre) ntp_win32k_pre();
    if (i < 0 || i >= W32K_MAX) return 0xC000001Cu;                       /* STATUS_INVALID_SYSTEM_SERVICE */
    uint32_t r = g_w32k[i].fn ? g_w32k[i].fn(args) : 0;
    if (g_trace || (!g_w32k[i].fn && !g_w32k[i].seen)) {
        fprintf(stderr, "[win32k] %-34s(", g_w32k[i].name[0] ? g_w32k[i].name : "?");
        for (int k = 0; k < g_w32k[i].argc && k < 16; k++) fprintf(stderr, k ? " %08X" : "%08X", args[k]);
        fprintf(stderr, ") -> %08X%s  0x%X from sub_%08X\n", r, g_w32k[i].fn ? "" : "  NOT ANSWERED", svc, g_cur_func);
    }
    g_w32k[i].seen = 1;
    return r;
}

/* win32k's calls back into user32 (a window procedure, a hook):
 * KiUserCallbackDispatcher(ApiNumber, Input, Length) runs
 * Peb->KernelCallbackTable[ApiNumber](Input, Length), which ends in
 * NtCallbackReturn(Output, Length, Status) or returns into the dispatcher's
 * int 2Bh. Neither unwinds: the result is kept, the routine returns, and the
 * dispatcher's trailing int3 (lifted as a return) comes back here. The
 * caller's registers are kept across it (only eax is the service's). */
#define CB_DEPTH 64
static struct { uint32_t out, outlen, status, done; } g_cb[CB_DEPTH];
static int g_cbn;
static void callback_return(uint32_t out, uint32_t outlen, uint32_t status) {
    if (g_cbn <= 0 || g_cb[g_cbn - 1].done) return;
    g_cb[g_cbn - 1].out = out, g_cb[g_cbn - 1].outlen = outlen, g_cb[g_cbn - 1].status = status;
    g_cb[g_cbn - 1].done = 1;
}
static uint32_t s_callback_return(uint32_t* a) {
    if (g_cbn <= 0) return 0xC0000258u;                                    /* STATUS_NO_CALLBACK_ACTIVE */
    callback_return(a[0], a[1], a[2]);
    return 0;
}
uint32_t ntp_callback(uint32_t api, uint32_t in, uint32_t len, uint32_t* out, uint32_t* outlen) {
    static uint32_t kucd;
    if (!kucd) kucd = ntp_export(ntp_module("ntdll.dll"), "KiUserCallbackDispatcher");
    if (!kucd || g_cbn >= CB_DEPTH) return 0xC0000258u;
    uint32_t args[3] = { api, in, len };
    uint32_t sv[8] = { g_ebx, g_ecx, g_edx, g_esi, g_edi, g_ebp, g_esp, g_cur_func };
    g_cb[g_cbn].done = 0;
    g_cbn++;
    g_esp -= 16;
    ntp_call(kucd, 3, args);
    g_cbn--;
    if (!g_cb[g_cbn].done) g_cb[g_cbn].status = g_eax, g_cb[g_cbn].out = 0, g_cb[g_cbn].outlen = 0;
    g_ebx = sv[0], g_ecx = sv[1], g_edx = sv[2], g_esi = sv[3], g_edi = sv[4], g_ebp = sv[5], g_esp = sv[6], g_cur_func = sv[7];
    if (out) *out = g_cb[g_cbn].out;
    if (outlen) *outlen = g_cb[g_cbn].outlen;
    return g_cb[g_cbn].status;
}
/* a guest stdcall function called from a service (a hook procedure), the
 * caller's registers kept */
uint32_t ntp_guest(uint32_t va, int nargs, const uint32_t* args) {
    uint32_t sv[8] = { g_ebx, g_ecx, g_edx, g_esi, g_edi, g_ebp, g_esp, g_cur_func };
    g_esp -= 16;
    ntp_call(va, nargs, args);
    uint32_t r = g_eax;
    g_ebx = sv[0], g_ecx = sv[1], g_edx = sv[2], g_esi = sv[3], g_edi = sv[4], g_ebp = sv[5], g_esp = sv[6], g_cur_func = sv[7];
    return r;
}
uint32_t ntp_peb(void) { return g_peb; }

/* RtlUnwind(TargetFrame, TargetIp, ExceptionRecord, ReturnValue), stdcall: the guest's own ends in
 * NtContinue to its caller, which a lift cannot do. This one (seh32.c's, on the guest's fs:[0]
 * chain) calls each handler above the target with the unwinding flag, unlinks it, and returns:
 * TargetIp is where the caller goes on anyway (its __except block, through the landing pads).
 * ponytail: no ExecuteHandler2 frame around the handler (C++Builder's stub reads one). */
static void shim_rtl_unwind(void) {
    uint32_t target = MEM32(g_esp + 4), er = MEM32(g_esp + 12), ret = MEM32(g_esp + 16), esp = g_esp;
    g_esp = (g_esp - 0x400) & ~15u;                          /* a record and a context below the caller */
    uint32_t mine = g_esp, ctx = g_esp + 0x80;
    memset((void*)(uintptr_t)mine, 0, 0x80 + 0x2CC);
    MEM32(mine) = 0xC0000027u;                               /* STATUS_UNWIND */
    if (!er) er = mine;
    MEM32(er + 4) |= 2u | (target ? 0 : 4u);                 /* EXCEPTION_UNWINDING, EXIT_UNWIND */
    for (uint32_t reg = MEM32(g_fs_base); reg && reg != 0xFFFFFFFFu && reg != target; ) {
        uint32_t args[4] = { er, reg, ctx, 0 };
        if (recomp_lookup(MEM32(reg + 4))) ntp_guest(MEM32(reg + 4), 4, args);
        else fprintf(stderr, "[seh] handler %08X of frame %08X is not lifted\n", MEM32(reg + 4), reg);
        reg = MEM32(reg);
        MEM32(g_fs_base) = reg;
    }
    g_esp = esp + 4 + 16;
    g_eax = ret;
}

/* ------------------------------------------------------------- the table */
static const struct { const char* name; uint32_t (*fn)(uint32_t*); } g_impl[] = {
    { "NtAllocateVirtualMemory", s_alloc_vm }, { "NtFreeVirtualMemory", s_free_vm },
    { "NtProtectVirtualMemory", s_protect_vm }, { "NtQueryVirtualMemory", s_query_vm },
    { "NtFlushInstructionCache", s_ok }, { "NtFlushVirtualMemory", s_ok },
    { "NtCreateFile", s_create_file }, { "NtOpenFile", s_open_file },
    { "NtReadFile", s_read_file }, { "NtWriteFile", s_write_file },
    { "NtQueryAttributesFile", s_query_attributes }, { "NtQueryFullAttributesFile", s_query_full_attributes },
    { "NtQueryInformationFile", s_query_info_file }, { "NtSetInformationFile", s_set_info_file },
    { "NtQueryVolumeInformationFile", s_query_volume }, { "NtQueryDirectoryFile", s_query_dir },
    { "NtFsControlFile", s_fs_control }, { "NtDeviceIoControlFile", s_device_io },
    { "NtFlushBuffersFile", s_flush_file }, { "NtCancelIoFile", s_flush_file },
    { "NtLockFile", s_ok }, { "NtUnlockFile", s_ok },
    { "NtClose", s_close }, { "NtDuplicateObject", s_duplicate },
    { "NtQueryObject", s_query_object }, { "NtSetInformationObject", s_ok },
    { "NtCreateEvent", s_create_event }, { "NtOpenEvent", s_open_event },
    { "NtSetEvent", s_set_event }, { "NtResetEvent", s_reset_event }, { "NtClearEvent", s_reset_event },
    { "NtPulseEvent", s_reset_event },
    { "NtCreateMutant", s_create_mutant }, { "NtOpenMutant", s_open_mutant }, { "NtReleaseMutant", s_release },
    { "NtCreateSemaphore", s_create_semaphore }, { "NtReleaseSemaphore", s_release },
    { "NtWaitForSingleObject", s_wait1 }, { "NtWaitForMultipleObjects", s_waitn },
    { "NtDelayExecution", s_delay }, { "NtYieldExecution", s_ok }, { "NtTestAlert", s_ok },
    { "NtOpenSection", s_open_section }, { "NtCreateSection", s_create_section },
    { "NtMapViewOfSection", s_map_view }, { "NtUnmapViewOfSection", s_unmap_view },
    { "NtQuerySection", s_query_section },
    { "NtQuerySystemInformation", s_query_system }, { "NtQuerySystemTime", s_query_system_time },
    { "NtQueryPerformanceCounter", s_query_perf }, { "NtGetTickCount", s_tick },
    { "NtAllocateLocallyUniqueId", s_luid },
    { "NtQueryDefaultLocale", s_default_locale }, { "NtSetDefaultLocale", s_ok },
    { "NtQueryDefaultUILanguage", s_ui_language }, { "NtQueryInstallUILanguage", s_ui_language },
    { "NtQueryInformationProcess", s_query_process }, { "NtSetInformationProcess", s_set_process },
    { "NtQueryInformationThread", s_query_thread }, { "NtSetInformationThread", s_ok },
    { "NtCreateThread", s_create_thread }, { "NtResumeThread", s_resume_thread },
    { "NtTerminateProcess", s_terminate_process }, { "NtTerminateThread", s_terminate_thread },
    { "NtRaiseHardError", s_hard_error },
    { "NtCreateProcess", s_no_process }, { "NtCreateProcessEx", s_no_process },
    { "NtOpenDirectoryObject", s_open_dirobj }, { "NtCreateDirectoryObject", s_open_dirobj },
    { "NtQueryDirectoryObject", s_query_dirobj }, { "NtOpenSymbolicLinkObject", s_not_found },
    { "NtOpenProcess", s_open_process }, { "NtQuerySecurityObject", s_query_security },
    { "NtOpenProcessToken", s_open_token }, { "NtQueryInformationToken", s_query_token }, { "NtOpenThreadToken", s_open_thread_token },
    { "NtOpenKey", s_registry }, { "NtQueryValueKey", s_query_value }, { "NtCreateKey", s_create_key },
    { "NtEnumerateValueKey", s_enum_value }, { "NtSetValueKey", s_set_value }, { "NtDeleteValueKey", s_delete_value },
    { "NtDeleteKey", s_delete_key }, { "NtQueryKey", s_query_key }, { "NtEnumerateKey", s_enum_key },
    { "NtFlushKey", s_ok }, { "NtNotifyChangeKey", s_notify_key },
    { "NtCreateIoCompletion", s_create_iocomp }, { "NtSetIoCompletion", s_set_iocomp },
    { "NtRemoveIoCompletion", s_remove_iocomp },
    { "NtAddAtom", s_add_atom }, { "NtFindAtom", s_find_atom }, { "NtDeleteAtom", s_delete_atom },
    { "NtRaiseException", s_raise_exception }, { "NtContinue", s_continue },
    { "NtSecureConnectPort", s_secure_connect }, { "NtConnectPort", s_connect },
    { "NtRequestWaitReplyPort", s_request_wait_reply }, { "NtRequestPort", s_ok },
    { "NtRegisterThreadTerminatePort", s_ok }, { "NtCallbackReturn", s_callback_return },
};

#define MAX_SVC 0x400
static struct { const char* name; uint8_t argc, warned; uint32_t (*fn)(uint32_t*); } g_svc[MAX_SVC];

int ntp_syscalls(uint32_t base) {
    uint32_t nt = base + MEM32(base + 0x3C), ed = base + MEM32(nt + 0x78);
    uint32_t names = base + MEM32(ed + 0x20), ords = base + MEM32(ed + 0x24), funcs = base + MEM32(ed + 0x1C);
    int n = 0, impl = 0;
    for (uint32_t i = 0; i < MEM32(ed + 0x18); i++) {
        const char* name = (const char*)(uintptr_t)(base + MEM32(names + 4 * i));
        const uint8_t* p = (const uint8_t*)(uintptr_t)(base + MEM32(funcs + 4 * MEM16(ords + 2 * i)));
        if (name[0] != 'N' || name[1] != 't') continue;
        if (p[0] != 0xB8 || p[5] != 0x8D || p[6] != 0x54 || p[7] != 0x24 || p[8] != 0x04 || p[9] != 0xCD || p[10] != 0x2E) continue;
        uint32_t svc = *(const uint32_t*)(p + 1);
        if (svc >= MAX_SVC) continue;
        g_svc[svc].name = name;
        g_svc[svc].argc = p[11] == 0xC2 ? (uint8_t)(*(const uint16_t*)(p + 12) / 4) : 0;
        for (size_t k = 0; k < sizeof g_impl / sizeof g_impl[0]; k++)
            if (!strcmp(g_impl[k].name, name)) { g_svc[svc].fn = g_impl[k].fn; impl++; }
        n++;
    }
    fprintf(stderr, "[syscall] %d services from the guest ntdll, %d answered on POSIX\n", n, impl);
    return n;
}

/* ------------------------------------------------------------- KUSER_SHARED_DATA */
#define KUSER 0x7FFE0000u
static void ksystime(uint32_t at, uint64_t v) {      /* KSYSTEM_TIME: High2, Low, High1 */
    MEM32(at + 8) = (uint32_t)(v >> 32);
    MEM32(at) = (uint32_t)v;
    MEM32(at + 4) = (uint32_t)(v >> 32);
}
static uint64_t g_vft;                              /* the virtual clock's start, as a FILETIME */
static void kuser_update(void) {
    static uint64_t t0;
    uint64_t ms = mono_ms();
    if (!t0) t0 = ms;
    uint64_t up = g_virtual ? g_vms : ms - t0;
    MEM32(KUSER + 0x00) = (uint32_t)(up + 60000);       /* TickCountLow (ms; the multiplier is 1.0) */
    ksystime(KUSER + 0x08, (up + 60000) * 10000);
    ksystime(KUSER + 0x14, g_virtual ? g_vft + up * 10000 : now_ft());
}
/* The virtual clock: from here on the guest's time (tick count, system
 * time, its sleeps) moves only when the host says so, so a scripted run
 * (w32kposix.c) is the same every time. */
void ntp_clock_virtual(void) { g_vft = now_ft(); g_vms = 0; g_virtual = 1; kuser_update(); }
void ntp_clock_advance(uint32_t ms) { g_vms += ms; kuser_update(); }
uint32_t ntp_clock_ms(void) { return (uint32_t)g_vms; }
static void* kuser_thread(void* unused) {
    (void)unused;
    for (;;) {
        struct timespec d = { 0, 10000000 };
        nanosleep(&d, NULL);
        if (!g_virtual) kuser_update();
    }
    return NULL;
}
static void kuser_init(void) {
    if (vm_reserve(KUSER, 0x1000, PT_PRIVATE, 0) != KUSER || !vm_commit(KUSER, 0x1000, 0x02)) {
        fprintf(stderr, "[ntposix] 0x7FFE0000 (KUSER_SHARED_DATA) is taken\n");
        exit(3);
    }
    MEM32(KUSER + 0x04) = 1u << 24;                      /* TickCountMultiplier */
    ksystime(KUSER + 0x20, (uint64_t)tz_bias());
    MEM16(KUSER + 0x2C) = 0x14C, MEM16(KUSER + 0x2E) = 0x14C;
    u8_to_u16("C:\\WINNT", (uint16_t*)(uintptr_t)(KUSER + 0x30), 260);
    MEM32(KUSER + 0x264) = 1;                            /* NtProductType: WinNt */
    MEM8(KUSER + 0x268) = 1;
    MEM32(KUSER + 0x26C) = 5;
    MEM32(KUSER + 0x270) = 0;
    kuser_update();
    pthread_t t;
    pthread_create(&t, NULL, kuser_thread, NULL);
}

/* ------------------------------------------------------------- the gate */
void recomp_syscall(int vector) {
    uint32_t svc = g_eax, *args = (uint32_t*)(uintptr_t)g_edx, r;
    if (vector == 0x2B) { callback_return(g_ecx, g_edx, g_eax); return; }   /* the callback dispatcher's own return */
    if (vector == 0x2E && svc >= 0x1000) { g_eax = win32k_call(svc, args); return; }
    if (vector != 0x2E || svc >= MAX_SVC || !g_svc[svc].name) {
        fprintf(stderr, "[syscall] int %02Xh service 0x%X: not in the table (from sub_%08X)\n", vector, svc, g_cur_func);
        g_eax = ST_NOT_IMPLEMENTED;
        return;
    }
    if (g_svc[svc].fn) r = g_svc[svc].fn(args);
    else {
        if (!g_svc[svc].warned++) fprintf(stderr, "[syscall] %s: not implemented on POSIX (from sub_%08X)\n", g_svc[svc].name, g_cur_func);
        r = ST_NOT_IMPLEMENTED;
    }
    if (g_trace) {
        fprintf(stderr, "[syscall] %-32s(", g_svc[svc].name);
        for (int i = 0; i < g_svc[svc].argc && i < 11; i++) fprintf(stderr, i ? " %08X" : "%08X", args[i]);
        fprintf(stderr, ") -> %08X  from sub_%08X", r, g_cur_func);
        if (g_svc[svc].argc >= 3 && args[2] >= 0x10000 && args[2] < 0x80000000u && pg_state[args[2] >> 12] == PG_COMMITTED &&
            MEM32(args[2]) == 0x18 && MEM32(args[2] + 8)) {
            char n[512];
            us_to_u8(MEM32(args[2] + 8), n, sizeof n);
            fprintf(stderr, "  %s", n);
        }
        fprintf(stderr, "\n");
    }
    g_eax = r;
}

/* ------------------------------------------------------------- process start */
/* A host fault (a lifted function's stray access): where, the guest
 * function, its last indirect calls and the host frames (addr2line them) */
static void crash(int sig, siginfo_t* si, void* uc) {
    /* a stack growing down: a reserved page right below a committed one (the guard page, which NT
     * moves down on the first touch) is committed and the access goes on */
    uint32_t fa = (uint32_t)(uintptr_t)si->si_addr, fp = fa >> 12;
    if (sig == SIGSEGV && fa >= GUEST_LO && fa < GUEST_HI && pg_state[fp] == PG_RESERVED &&
        pg_state[fp + 1] == PG_COMMITTED && pg_base[fp] == pg_base[fp + 1] && vm_commit(fp << 12, 0x1000, 0x04))
        return;
    void* bt[32];
    int n = backtrace(bt, 32);
    fprintf(stderr, "\n[ntposix] signal %d at %p (host eip %08X) in sub_%08X, esp %08X\n", sig, si->si_addr,
            (unsigned)((ucontext_t*)uc)->uc_mcontext.gregs[REG_EIP], g_cur_func, g_esp);
    for (uint32_t i = 0; i < 8 && i < g_icall_count; i++) {
        uint32_t k = (g_icall_trace_idx - 1 - i) & (ICALL_TRACE_SIZE - 1);
        fprintf(stderr, "  icall 0x%08X from 0x%08X\n", g_icall_trace[k], g_icall_from[k]);
    }
    for (int i = 0; i < n; i++) fprintf(stderr, "  host %p\n", bt[i]);
    fflush(NULL);
    _exit(128 + sig);
}

/* SIGUSR1 turns the syscall trace on and off in a running process (a live run traced only around one click) */
volatile int ntp_tracing;
static void on_usr1(int sig) { (void)sig; ntp_tracing = g_trace = !g_trace; }
void ntp_init(void) {
    ntp_tracing = g_trace = getenv("NATIVE32_SYSCALLS") != NULL;
    signal(SIGUSR1, on_usr1);
    {
        struct sigaction sa;
        static uint8_t alt[64 << 10];
        stack_t st = { alt, 0, sizeof alt };
        sigaltstack(&st, NULL);
        memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = crash;
        sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGBUS, &sa, NULL);
        sigaction(SIGILL, &sa, NULL);
    }
    g_ndisp = recomp_dispatch_count;
    g_disp = malloc(sizeof *g_disp * g_ndisp);
    memcpy(g_disp, recomp_dispatch_table, sizeof *g_disp * g_ndisp);
    qsort(g_disp, g_ndisp, sizeof *g_disp, cmp_disp);
    recomp_eh_jump_hook = eh_jump;
    for (int i = 0; i < 3; i++) {
        obj_t* o = obj_new(O_FILE);
        o->fd = i, o->keepfd = 1, o->refs = 1 << 30;
        o->guest = strdup(i ? "CONOUT$" : "CONIN$");
        g_std[i] = h_put(o);
    }
    kuser_init();
}

/* a UNICODE_STRING at `at`, its buffer from the pool */
static void ustr_pool(uint32_t at, const char* s, uint32_t* pool, uint32_t extra) {
    int n = u8_to_u16(s, (uint16_t*)(uintptr_t)*pool, 0x4000);
    MEM16(at) = (uint16_t)(2 * n);
    MEM16(at + 2) = (uint16_t)(2 * n + 2 + extra);
    MEM32(at + 4) = *pool;
    *pool += (2u * n + 2 + extra + 3) & ~3u;
}

static uint32_t load_nls(const char* dir, const char* name) {
    char p[2048];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    FILE* f = fopen(p, "rb");
    if (!f) { fprintf(stderr, "[nt] %s: missing\n", p); return 0; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint32_t a = ntp_alloc((uint32_t)n);
    size_t got = fread((void*)(uintptr_t)a, 1, n, f);
    fclose(f);
    return got == (size_t)n ? a : 0;
}

/* the guest's environment: a Windows 2000 one, not the host's */
static uint32_t environment(void) {
    static const char* env[] = {
        "ComSpec=C:\\WINNT\\system32\\cmd.exe", "OS=Windows_NT", "Path=C:\\WINNT\\system32;C:\\WINNT",
        "PATHEXT=.COM;.EXE;.BAT;.CMD", "PROCESSOR_ARCHITECTURE=x86", "PROMPT=$P$G", "SystemDrive=C:",
        "SystemRoot=C:\\WINNT", "TEMP=C:\\TEMP", "TMP=C:\\TEMP", "USERNAME=user", "COMPUTERNAME=W2K",
        "windir=C:\\WINNT", "NUMBER_OF_PROCESSORS=1",
        /* the profile: a shell finds its folders through these (all under the C: mount) */
        "ALLUSERSPROFILE=C:\\Documents and Settings\\all", "APPDATA=C:\\Documents and Settings\\user\\Application Data",
        "CommonProgramFiles=C:\\Program Files\\Common Files", "HOMEDRIVE=C:", "HOMEPATH=\\Documents and Settings\\user",
        "ProgramFiles=C:\\Program Files", "USERPROFILE=C:\\Documents and Settings\\user",
    };
    uint32_t e = ntp_alloc(0x4000), o = e;
    for (size_t i = 0; i < sizeof env / sizeof env[0]; i++)
        o += 2u * (u8_to_u16(env[i], (uint16_t*)(uintptr_t)o, 0x1000) + 1);
    MEM16(o) = 0;
    return e;
}

static void ntdll_version(uint32_t ntdll, uint32_t* major, uint32_t* minor, uint32_t* build) {
    uint32_t size = image_size(ntdll);
    *major = 5, *minor = 0, *build = 2195;
    for (uint32_t p = ntdll; p + 52 < ntdll + size; p += 4)
        if (MEM32(p) == 0xFEEF04BDu) { *major = MEM32(p + 8) >> 16, *minor = MEM32(p + 8) & 0xFFFF, *build = MEM32(p + 12) >> 16; return; }
}

int ntp_boot(uint32_t ntdll, uint32_t exe, const char* image, const char* cmdline,
             const char* dllpath, const char* curdir, const char* nls_dir, uint16_t csd) {
    uint32_t peb = ntp_alloc(0x10000), pp = peb + 0x1000, pool = peb + 0x2000;
    uint32_t major, minor, build, ent = exe + MEM32(exe + 0x3C);
    g_peb = peb;
    g_pid = ((uint32_t)getpid() & 0x3FFF) * 4 + 0x100;
    g_tid = g_pid + 4;

    /* the thread: a guest stack and a TEB (NT 5 offsets) */
    uint32_t stack = vm_reserve(0, 0x100000, PT_PRIVATE, 0);
    vm_commit(stack, 0x100000, 0x04);
    g_teb = ntp_alloc(0x2000);
    MEM32(g_teb + 0x00) = 0xFFFFFFFFu;
    MEM32(g_teb + 0x04) = stack + 0x100000;
    MEM32(g_teb + 0x08) = stack;
    MEM32(g_teb + 0x18) = g_teb;
    MEM32(g_teb + 0x20) = g_pid;
    MEM32(g_teb + 0x24) = g_tid;
    MEM32(g_teb + 0x30) = peb;
    MEM32(g_teb + 0xBF8) = 0x020A0000u;
    MEM32(g_teb + 0xBFC) = g_teb + 0xC00;
    MEM32(g_teb + 0xE0C) = stack;
    g_fs_base = g_teb;
    g_esp = stack + 0x100000 - 0x100;

    ntdll_version(ntdll, &major, &minor, &build);
    MEM32(peb + 0x08) = exe;
    MEM32(peb + 0x10) = pp;
    MEM32(peb + 0x64) = 1;                                   /* NumberOfProcessors */
    if (getenv("NTP_GLOBALFLAG")) MEM32(peb + 0x68) = (uint32_t)strtoul(getenv("NTP_GLOBALFLAG"), NULL, 0);  /* e.g. 0x470: ntdll's heap checks */
    *(int64_t*)(uintptr_t)(peb + 0x70) = -(int64_t)2592000 * 10000000;
    MEM32(peb + 0x78) = 0x100000;
    MEM32(peb + 0x7C) = 0x2000;
    MEM32(peb + 0x80) = 0x10000;
    MEM32(peb + 0x84) = 0x1000;
    MEM32(peb + 0xA4) = major;
    MEM32(peb + 0xA8) = minor;
    MEM16(peb + 0xAC) = (uint16_t)build;
    MEM16(peb + 0xAE) = csd;
    MEM32(peb + 0xB0) = 2;
    MEM32(peb + 0xB4) = MEM16(ent + 0x5C);
    MEM32(peb + 0xB8) = MEM16(ent + 0x48);
    MEM32(peb + 0xBC) = MEM16(ent + 0x4A);

    /* process parameters, normalized */
    char cur[1024];
    snprintf(cur, sizeof cur, "%s%s", curdir, curdir[strlen(curdir) - 1] == '\\' ? "" : "\\");
    MEM32(pp + 0x00) = 0x1000;
    MEM32(pp + 0x04) = 0x2A0;
    MEM32(pp + 0x08) = 1;
    MEM32(pp + 0x18) = g_std[0];
    MEM32(pp + 0x1C) = g_std[1];
    MEM32(pp + 0x20) = g_std[2];
    ustr_pool(pp + 0x24, cur, &pool, 0);
    MEM16(pp + 0x26) = 260 * 2;                              /* a MAX_PATH buffer: RtlSetCurrentDirectory_U writes in place */
    pool += 260 * 2;
    {
        uint32_t oa[6] = { 0x18, 0, 0, 0x40, 0, 0 }, us[2], iosb[2], h = 0;
        uint16_t w[1024];
        char nt[1100];
        snprintf(nt, sizeof nt, "\\??\\%s", cur);
        int n = u8_to_u16(nt, w, 1024);
        us[0] = (uint32_t)(2 * n) | (uint32_t)(2 * n + 2) << 16, us[1] = (uint32_t)(uintptr_t)w;
        oa[2] = (uint32_t)(uintptr_t)us;
        if (do_open((uint32_t)(uintptr_t)&h, 0x100001, (uint32_t)(uintptr_t)oa, (uint32_t)(uintptr_t)iosb, 1, 0x21))
            fprintf(stderr, "[nt] current directory %s: not found\n", cur);
        MEM32(pp + 0x2C) = h;
    }
    ustr_pool(pp + 0x30, dllpath, &pool, 0);
    ustr_pool(pp + 0x38, image, &pool, 0);
    ustr_pool(pp + 0x40, cmdline, &pool, 0);
    MEM32(pp + 0x48) = environment();
    ustr_pool(pp + 0x70, image, &pool, 0);
    ustr_pool(pp + 0x78, "WinSta0\\Default", &pool, 0);
    ustr_pool(pp + 0x80, "", &pool, 0);
    ustr_pool(pp + 0x88, "", &pool, 0);

    /* the NLS tables the kernel maps into every process: the guest's own */
    uint32_t ansi = load_nls(nls_dir, "c_1252.nls"), oem = load_nls(nls_dir, "c_437.nls"), casetab = load_nls(nls_dir, "l_intl.nls");
    if (!ansi || !oem || !casetab) return 0;
    MEM32(peb + 0x58) = ansi;
    MEM32(peb + 0x5C) = oem;
    MEM32(peb + 0x60) = casetab;

    /* LdrInitializeThunk(Context, ntdll base, 0) with the initial CONTEXT after it */
    if (ntp_export(ntdll, "RtlUnwind")) ntp_replace(ntp_export(ntdll, "RtlUnwind"), shim_rtl_unwind);
    rpc_guard_install();
    uint32_t thunk = ntp_export(ntdll, "LdrInitializeThunk");
    if (!thunk) { fprintf(stderr, "[nt] ntdll has no LdrInitializeThunk\n"); return 0; }
    uint32_t args[3 + 0x2CC / 4] = { 0, ntdll, 0 };
    uint32_t* ctx = args + 3;
    ctx[0] = 0x10007;
    ctx[0xB0 / 4] = exe + MEM32(ent + 0x28);
    ctx[0xB8 / 4] = exe + MEM32(ent + 0x28);
    uint32_t sp = g_esp;
    ntp_call(thunk, (int)(sizeof args / 4), args);
    g_esp = sp;
    fprintf(stderr, "[nt] guest PEB %08X, process heap %08X: the guest's loader is done\n", peb, MEM32(peb + 0x18));
    return MEM32(peb + 0x18) != 0;
}

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
void recomp_int(int n) { fprintf(stderr, "[ntposix] int %02Xh in sub_%08X\n", n, g_cur_func); }

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
static struct { char name[64]; uint32_t base, size; } g_mod[MAX_MODS];
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
enum { O_FILE = 1, O_EVENT, O_SECTION, O_IMAGE, O_PORT, O_DIROBJ, O_MUTANT, O_SEM, O_TOKEN, O_KEY };
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
        if (!lstat(out, &st)) continue;
        out[L] = 0;
        DIR* d = opendir(L ? out : "/");
        struct dirent* de;
        int found = 0;
        while (d && (de = readdir(d)))
            if (!strcasecmp(de->d_name, comp)) { snprintf(out + L, cap - L, "/%s", de->d_name); found = 1; break; }
        if (d) closedir(d);
        if (!found) snprintf(out + L, cap - L, "/%s", comp);
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
/* NtCreateEvent(Handle*, Access, OA, Type, InitialState): type 0 manual reset */
static uint32_t s_create_event(uint32_t* a) { return new_handle(a[0], O_EVENT, a[4] != 0, a[3] == 0); }
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

static int signaled(uint32_t h, int consume) {
    obj_t* o = h_get(h);
    if (!o) return 0;                              /* this process / thread: alive */
    if (o->type != O_EVENT) return 1;
    int s = o->signaled;
    if (s && consume && !o->manual) o->signaled = 0;
    return s;
}

static uint32_t wait_timeout(uint32_t to, const char* what) {
    if (!to) {
        fprintf(stderr, "[ntposix] %s waits forever with one guest thread: returning a timeout (from sub_%08X)\n", what, g_cur_func);
        return ST_TIMEOUT;
    }
    int64_t t = *(int64_t*)(uintptr_t)to;
    if (t < 0) {
        int64_t ns = -t * 100;
        if (ns > 2000000000ll) ns = 2000000000ll;
        struct timespec d = { (time_t)(ns / 1000000000), (long)(ns % 1000000000) };
        nanosleep(&d, NULL);
    }
    return ST_TIMEOUT;
}

/* NtWaitForSingleObject(Handle, Alertable, Timeout*) */
static uint32_t s_wait1(uint32_t* a) { return signaled(a[0], 1) ? 0 : wait_timeout(a[2], "NtWaitForSingleObject"); }

/* NtWaitForMultipleObjects(Count, Handles*, WaitType(0 all, 1 any), Alertable, Timeout*) */
static uint32_t s_waitn(uint32_t* a) {
    uint32_t n = a[0], hs = a[1];
    if (a[2] == 1) {
        for (uint32_t i = 0; i < n; i++) if (signaled(MEM32(hs + 4 * i), 1)) return i;
    } else {
        uint32_t i;
        for (i = 0; i < n && signaled(MEM32(hs + 4 * i), 0); i++) ;
        if (i == n) { for (i = 0; i < n; i++) signaled(MEM32(hs + 4 * i), 1); return 0; }
    }
    return wait_timeout(a[4], "NtWaitForMultipleObjects");
}

/* NtDelayExecution(Alertable, Interval*) */
static uint32_t s_delay(uint32_t* a) { wait_timeout(a[1], "NtDelayExecution"); return 0; }

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
static uint32_t s_create_section(uint32_t* a) {
    obj_t* f = a[6] ? h_get(a[6]) : NULL;
    if (a[5] & 0x01000000u) {                                          /* SEC_IMAGE */
        if (!f || f->type != O_FILE) return ST_INVALID_HANDLE;
        const char* name = base_name(f->guest);
        size_t n = strlen(name);
        int m = module_by_name(name), p = proxy_by_name(name);
        uint32_t base = 0;
        int exe = n > 4 && (!strcasecmp(name + n - 4, ".exe") || !strcasecmp(name + n - 4, ".com") || !strcasecmp(name + n - 4, ".scr"));
        if (m >= 0) base = g_mod[m].base;
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
    return 0;      /* an image: stays */
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
static uint32_t g_peb, g_teb, g_pid, g_tid, g_harderror;

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
    default:
        fprintf(stderr, "[ntposix] NtQueryInformationProcess class %u\n", a[1]);
        return ST_INVALID_INFO_CLASS;
    }
    if (a[4]) MEM32(a[4]) = n;
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
/* The registry: read only, and only what the guest's NLS code checks
 * (IsValidLocale: the locale's key and its language group). Everything else
 * is not found, and cmd, kernel32 and msvcrt keep their defaults.
 * ponytail: a table, not a hive; a writable private hive (regbox32's on
 * Windows) when a program needs to keep settings. */
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

/* NtOpenKey(Handle*, Access, OA) */
static uint32_t s_registry(uint32_t* a) {
    char n[512], full[1024];
    obj_t* root = a[2] && MEM32(a[2] + 4) ? h_get(MEM32(a[2] + 4)) : NULL;
    us_to_u8(a[2] ? MEM32(a[2] + 8) : 0, n, sizeof n);
    if (root && root->type == O_KEY && root->guest) snprintf(full, sizeof full, "%s\\%s", root->guest, n);
    else if (root) return ST_NAME_NOT_FOUND;
    else snprintf(full, sizeof full, "%s", n);
    for (int i = 0; i < NREG; i++)
        if (!strcasecmp(g_reg[i].key, full)) {
            obj_t* o = obj_new(O_KEY);
            o->guest = strdup(g_reg[i].key);
            MEM32(a[0]) = h_put(o);
            return 0;
        }
    return ST_NAME_NOT_FOUND;
}

/* NtQueryValueKey(Key, ValueName*, Class, Buffer, Length, ResultLength*) */
static uint32_t s_query_value(uint32_t* a) {
    obj_t* o = h_get(a[0]);
    char n[256];
    if (!o || o->type != O_KEY || !o->guest) return ST_INVALID_HANDLE;
    us_to_u8(a[1], n, sizeof n);
    for (int i = 0; i < NREG; i++) {
        if (strcasecmp(g_reg[i].key, o->guest) || !g_reg[i].name || strcasecmp(g_reg[i].name, n)) continue;
        uint16_t w[256];
        uint32_t dl = 2u * (u8_to_u16(g_reg[i].sz, w, 256) + 1), b = a[3], need;
        if (a[2] == 2) {                                        /* KeyValuePartialInformation */
            need = 12 + dl;
            if (a[5]) MEM32(a[5]) = need;
            if (a[4] < need) return a[4] < 12 ? ST_BUFFER_TOO_SMALL : ST_BUFFER_OVERFLOW;
            MEM32(b) = 0, MEM32(b + 4) = 1, MEM32(b + 8) = dl;  /* REG_SZ */
            memcpy((void*)(uintptr_t)(b + 12), w, dl);
            return 0;
        }
        if (a[2] == 1) {                                        /* KeyValueFullInformation */
            uint16_t wn[256];
            uint32_t nl = 2u * u8_to_u16(g_reg[i].name, wn, 256), off = (20 + nl + 3) & ~3u;
            need = off + dl;
            if (a[5]) MEM32(a[5]) = need;
            if (a[4] < need) return a[4] < 20 ? ST_BUFFER_TOO_SMALL : ST_BUFFER_OVERFLOW;
            MEM32(b) = 0, MEM32(b + 4) = 1, MEM32(b + 8) = off, MEM32(b + 12) = dl, MEM32(b + 16) = nl;
            memcpy((void*)(uintptr_t)(b + 20), wn, nl);
            memcpy((void*)(uintptr_t)(b + off), w, dl);
            return 0;
        }
        return ST_INVALID_INFO_CLASS;
    }
    return ST_NAME_NOT_FOUND;
}
static uint32_t s_create_key(uint32_t* a) { (void)a; return ST_ACCESS_DENIED; }

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
static uint32_t csr_client_connect(uint32_t data) {
    uint32_t index = MEM32(data), ci = MEM32(data + 4);
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
    else {
        uint16_t total = MEM16(m + 2);
        if (total > 0x28 && total < 0x1000) memset((void*)(uintptr_t)(m + 0x28), 0, total - 0x28);
        if (g_trace) fprintf(stderr, "[csr] api %u:%u not answered, from sub_%08X\n", api >> 16, api & 0xFFFF, g_cur_func);
    }
    MEM32(m + 0x20) = r;
    if (a[2] && a[2] != m) memcpy((void*)(uintptr_t)a[2], (void*)(uintptr_t)m, MEM16(m) + 0x18);
    return 0;
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
    { "NtCreateEvent", s_create_event }, { "NtOpenEvent", s_not_found },
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
    { "NtTerminateProcess", s_terminate_process }, { "NtTerminateThread", s_terminate_thread },
    { "NtRaiseHardError", s_hard_error },
    { "NtCreateProcess", s_no_process }, { "NtCreateProcessEx", s_no_process },
    { "NtOpenDirectoryObject", s_open_dirobj }, { "NtCreateDirectoryObject", s_open_dirobj },
    { "NtQueryDirectoryObject", s_query_dirobj }, { "NtOpenSymbolicLinkObject", s_not_found },
    { "NtOpenProcessToken", s_open_token }, { "NtQueryInformationToken", s_query_token }, { "NtOpenThreadToken", s_open_thread_token },
    { "NtOpenKey", s_registry }, { "NtQueryValueKey", s_query_value }, { "NtCreateKey", s_create_key },
    { "NtRaiseException", s_raise_exception }, { "NtContinue", s_continue },
    { "NtSecureConnectPort", s_secure_connect }, { "NtConnectPort", s_connect },
    { "NtRequestWaitReplyPort", s_request_wait_reply }, { "NtRequestPort", s_ok },
    { "NtRegisterThreadTerminatePort", s_ok },
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
static void kuser_update(void) {
    static uint64_t t0;
    uint64_t ms = mono_ms();
    if (!t0) t0 = ms;
    MEM32(KUSER + 0x00) = (uint32_t)(ms - t0 + 60000);  /* TickCountLow (ms; the multiplier is 1.0) */
    ksystime(KUSER + 0x08, (ms - t0 + 60000) * 10000);
    ksystime(KUSER + 0x14, now_ft());
}
static void* kuser_thread(void* unused) {
    (void)unused;
    for (;;) {
        struct timespec d = { 0, 10000000 };
        nanosleep(&d, NULL);
        kuser_update();
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
    if (vector == 0x2B) return;                          /* NtCallbackReturn's gate: no callbacks yet */
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
void ntp_init(void) {
    g_trace = getenv("NATIVE32_SYSCALLS") != NULL;
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

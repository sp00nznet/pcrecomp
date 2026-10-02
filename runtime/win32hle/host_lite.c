/*
 * host_lite.c - the portable spine of a win32hle host (see win32hle.h).
 *
 * Owns the recomp32 register file, the machine lock, each thread's simulated
 * TIB (g_fs_base), the dispatch lookups, the shim registry, and the explicit
 * native -> guest call. No inline asm and no OS exception handling: every
 * import is a C shim, so the guest -> native and native -> guest paths are both
 * ordinary C calls. Builds under gcc/clang -m32 and MSVC x86 alike.
 *
 * "lite" because it is the spine without a PE loader: enough to drive lifted
 * code and the shim layer (the selftest does exactly that). A full game host
 * adds image mapping and IAT binding on top; those are separate.
 */
#define _GNU_SOURCE   /* PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include "win32hle.h"

/* ------------------------------------------------------------ register file
 * recomp_types.h declares these extern; exactly one translation unit defines
 * them, and for a win32hle host that is here. (Mirrors native32.c.) */
uint32_t  g_eax, g_ecx, g_edx, g_esp, g_ebx, g_esi, g_edi, g_ebp;
double    g_st[8];
int       g_fp_top;
uint16_t  g_fpu_cw = 0x027F;
uint16_t  g_seg_cs, g_seg_ds, g_seg_es, g_seg_fs, g_seg_gs, g_seg_ss;
uint64_t  g_mm[8];
uint32_t  g_fs_base, g_gs_base;
ptrdiff_t g_mem_base = 0;
uint32_t  g_cur_func;
const char *g_cur_import;
uint32_t  g_icall_trace[ICALL_TRACE_SIZE], g_icall_from[ICALL_TRACE_SIZE];
uint32_t  g_icall_trace_idx, g_icall_count;

int win32hle_trace;

void hle_fatal(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fprintf(stderr, "[win32hle] FATAL: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    abort();
}

/* --------------------------------------------------------------- the lock
 * One recursive mutex serialises the (global) register file. A thread holds it
 * while running lifted code and across hle_call_guest; a shim that calls back
 * into the guest nests the claim. */
static pthread_mutex_t g_mach = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

typedef struct {
    uint32_t eax, ecx, edx, esp, ebx, esi, edi, ebp, fs, cur;
    double   st[8];
    int      fp_top;
    uint16_t fpu_cw;
    uint64_t mm[8];
} regs_t;

static void regs_save(regs_t *r) {
    r->eax=g_eax; r->ecx=g_ecx; r->edx=g_edx; r->esp=g_esp;
    r->ebx=g_ebx; r->esi=g_esi; r->edi=g_edi; r->ebp=g_ebp;
    r->fs=g_fs_base; r->cur=g_cur_func;
    memcpy(r->st, g_st, sizeof g_st); r->fp_top=g_fp_top; r->fpu_cw=g_fpu_cw;
    memcpy(r->mm, g_mm, sizeof g_mm);
}
static void regs_load(const regs_t *r) {
    g_eax=r->eax; g_ecx=r->ecx; g_edx=r->edx; g_esp=r->esp;
    g_ebx=r->ebx; g_esi=r->esi; g_edi=r->edi; g_ebp=r->ebp;
    g_fs_base=r->fs; g_cur_func=r->cur;
    memcpy(g_st, r->st, sizeof g_st); g_fp_top=r->fp_top; g_fpu_cw=r->fpu_cw;
    memcpy(g_mm, r->mm, sizeof g_mm);
}

/* A guest thread's stack and simulated TIB. Lifted code reads fs:[n] as
 * MEM32(g_fs_base + n); the host's own TLS stays separate, so a guest SEH frame
 * never lands on a chain the host walks. */
#define GUEST_STACK (4u << 20)

static uint32_t make_tib(uint32_t lo, uint32_t hi) {
    uint32_t *t = (uint32_t *)calloc(1, 0x1000);
    t[0]        = 0xFFFFFFFFu;                 /* ExceptionList: end of chain */
    t[1]        = hi;                          /* StackBase                   */
    t[2]        = lo;                          /* StackLimit                  */
    t[0x18/4]   = (uint32_t)(uintptr_t)t;      /* Self (fs:[0x18])            */
    return (uint32_t)(uintptr_t)t;
}

typedef struct { regs_t r; int depth, inited; } mstate;
static __thread mstate g_ms;

void mach_enter(void) {
    pthread_mutex_lock(&g_mach);
    if (!g_ms.inited) {
        uint32_t lo = (uint32_t)(uintptr_t)calloc(1, GUEST_STACK);
        g_ms.r.esp    = lo + GUEST_STACK - 64;
        g_ms.r.fs     = make_tib(lo, lo + GUEST_STACK);
        g_ms.r.fpu_cw = 0x027F;
        g_ms.inited   = 1;
    }
    if (g_ms.depth++ == 0) regs_load(&g_ms.r);
}
void mach_leave(void) {
    if (--g_ms.depth == 0) regs_save(&g_ms.r);
    pthread_mutex_unlock(&g_mach);
}

/* ------------------------------------------------------------- dispatch
 * recomp_lookup searches the generated dispatch table (declared extern in
 * recomp_types.h; defined by the lifted program, or the selftest). */
recomp_func_t recomp_lookup(uint32_t va) {
    uint32_t lo = 0, hi = recomp_dispatch_count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2, m = recomp_dispatch_table[mid].address;
        if (m == va) return recomp_dispatch_table[mid].func;
        if (m < va) lo = mid + 1; else hi = mid;
    }
    return NULL;
}
recomp_func_t recomp_lookup_manual(uint32_t va) { (void)va; return NULL; }

/* --------------------------------------------------------- shim registry
 * Each shim gets a synthetic VA in a reserved range that no real image uses. */
#define SHIM_BASE  0x7F000000u
#define SHIM_STEP  16u
#define MAX_SHIMS  2048
static struct { const char *name; recomp_func_t fn; uint32_t va; } g_shim[MAX_SHIMS];
static int g_shim_n;

int win32hle_register(const win32hle_shim *shims) {
    int added = 0;
    for (; shims->name; shims++) {
        if (g_shim_n >= MAX_SHIMS) hle_fatal("too many shims");
        g_shim[g_shim_n].name = shims->name;
        g_shim[g_shim_n].fn   = shims->fn;
        g_shim[g_shim_n].va   = SHIM_BASE + SHIM_STEP * (uint32_t)g_shim_n;
        g_shim_n++; added++;
    }
    return added;
}
uint32_t hle_resolve(const char *name) {
    for (int i = 0; i < g_shim_n; i++)
        if (!strcmp(g_shim[i].name, name)) return g_shim[i].va;
    return 0;
}
const char *hle_name(uint32_t va) {
    for (int i = 0; i < g_shim_n; i++) if (g_shim[i].va == va) return g_shim[i].name;
    return NULL;
}

/* An import VA that is one of our synthetic shim VAs resolves to its shim. */
recomp_func_t recomp_lookup_import(uint32_t va) {
    if (va < SHIM_BASE || va >= SHIM_BASE + SHIM_STEP * (uint32_t)g_shim_n) return NULL;
    uint32_t i = (va - SHIM_BASE) / SHIM_STEP;
    if (i < (uint32_t)g_shim_n && g_shim[i].va == va) {
        if (win32hle_trace) fprintf(stderr, "[hle] %s\n", g_shim[i].name);
        return g_shim[i].fn;
    }
    return NULL;
}

/* ------------------------------------------------------- native -> guest */
uint32_t hle_call_guest(uint32_t va, int nargs, const uint32_t *args) {
    recomp_func_t f = recomp_lookup(va);
    if (!f) f = recomp_lookup_import(va);
    if (!f) hle_fatal("no lifted function at 0x%08X", va);
    mach_enter();
    regs_t saved; regs_save(&saved);
    for (int i = nargs - 1; i >= 0; i--) PUSH32(g_esp, args[i]);
    PUSH32(g_esp, RECOMP_RETADDR);
    f();
    uint32_t eax = g_eax;
    regs_load(&saved);
    mach_leave();
    return eax;
}

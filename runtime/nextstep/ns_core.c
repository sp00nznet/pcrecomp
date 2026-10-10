/*
 * ns_core.c - guest address space, Mach-O loader, name binding, guest heap.
 * See ns_runtime.h. Part of the pcrecomp toolbox.
 */
#include "ns_runtime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

/* ---- register file, as recomp_types.h expects ---------------------------- */
uint32_t g_eax, g_ecx, g_edx, g_esp, g_ebx, g_esi, g_edi, g_ebp;
uint16_t g_seg_cs, g_seg_ds, g_seg_es, g_seg_fs, g_seg_gs, g_seg_ss;
uint32_t g_fs_base, g_gs_base;
double   g_st[8];
int      g_fp_top;
uint16_t g_fpu_cw = 0x037F;
uint64_t g_mm[8];
xmm_t    g_xmm[8];
uint32_t g_mxcsr = 0x1F80;
ptrdiff_t g_mem_base;
uint32_t g_cur_func;
uint32_t g_icall_trace[ICALL_TRACE_SIZE], g_icall_from[ICALL_TRACE_SIZE];
uint32_t g_icall_trace_idx, g_icall_count;
#ifdef RECOMP_TRACE
uint32_t g_enter_trace[RECOMP_ENTER_SIZE], g_enter_idx;
void recomp_trace_enter(uint32_t va) { g_enter_trace[g_enter_idx++ & (RECOMP_ENTER_SIZE - 1)] = va; }
#endif
void recomp_dump_trace(const char *why) { (void)why; }

/* ---- guest address space ------------------------------------------------- *
 * One reservation covers every VA a NeXTSTEP 3.3 app and its shlibs use
 * (app from 0x2000, shlib data at 0x04xxxxxx, text up to ~0x0Axxxxxx), plus
 * the stack and heap placed above them. */
#define GUEST_SPAN   0x20000000u
#define STACK_HI     0x0F000000u
#define HEAP_LO      0x10000000u
#define HEAP_HI      GUEST_SPAN

static void map_guest(void) {
#ifdef _WIN32
    uint8_t *p = VirtualAlloc(NULL, GUEST_SPAN, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    DWORD old;
    if (p) VirtualProtect(p, 0x2000, PAGE_NOACCESS, &old);   /* __PAGEZERO: catch null */
#else
    uint8_t *p = mmap(NULL, GUEST_SPAN, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) p = NULL;
    else mprotect(p, 0x2000, PROT_NONE);
#endif
    if (!p) { fprintf(stderr, "ns: cannot map %u MB of guest space\n", GUEST_SPAN >> 20); exit(1); }
    g_mem_base = (ptrdiff_t)p;
}

/* ---- guest heap ---------------------------------------------------------- *
 * ponytail: bump allocator with a size header; free is a no-op. Doom takes one
 * big zone at startup. Add a free list when an app churns the heap. */
static uint32_t g_brk = HEAP_LO;

uint32_t ns_malloc(uint32_t n) {
    uint32_t va = (g_brk + 16 + 15) & ~15u;
    if (va + n > HEAP_HI) { fprintf(stderr, "ns: guest heap exhausted (%u bytes)\n", n); exit(1); }
    MEM32(va - 4) = n;
    g_brk = va + n;
    return va;
}
uint32_t ns_calloc(uint32_t n) { uint32_t va = ns_malloc(n); memset(GUEST(va), 0, n); return va; }
void ns_free(uint32_t va) { (void)va; }
uint32_t ns_realloc(uint32_t va, uint32_t n) {
    if (!va) return ns_malloc(n);
    uint32_t old = MEM32(va - 4);
    if (n <= old) { MEM32(va - 4) = n; return va; }
    uint32_t nv = ns_malloc(n);
    memcpy(GUEST(nv), GUEST(va), old);
    return nv;
}
uint32_t ns_strdup(const char *s) {
    uint32_t va = ns_malloc((uint32_t)strlen(s) + 1);
    strcpy(GSTR(va), s);
    return va;
}

/* ---- symbols ------------------------------------------------------------- */
typedef struct { uint32_t va; const char *name; } sym_t;
static sym_t *g_syms;
static int g_nsyms, g_capsyms;

static int sym_cmp(const void *a, const void *b) {
    uint32_t x = ((const sym_t *)a)->va, y = ((const sym_t *)b)->va;
    return x < y ? -1 : x > y;
}
const char *ns_sym_at(uint32_t va) {
    int lo = 0, hi = g_nsyms;
    while (lo < hi) {
        int mid = (lo + hi) / 2;
        if (g_syms[mid].va < va) lo = mid + 1; else hi = mid;
    }
    /* several names can share an address: prefer one that is not a slot label */
    for (int i = lo; i < g_nsyms && g_syms[i].va == va; i++)
        if (strncmp(g_syms[i].name, ".branch_table_slot", 18)) return g_syms[i].name;
    return lo < g_nsyms && g_syms[lo].va == va ? g_syms[lo].name : NULL;
}
uint32_t ns_sym(const char *name) {
    for (int i = 0; i < g_nsyms; i++)
        if (!strcmp(g_syms[i].name, name)) return g_syms[i].va;
    return 0;
}

/* ---- Mach-O loader ------------------------------------------------------- */
#define RD32(p) (*(const uint32_t *)(p))
#define BE32(p) (((uint32_t)(p)[0] << 24) | ((uint32_t)(p)[1] << 16) | ((uint32_t)(p)[2] << 8) | (p)[3])

static char g_shlib_dir[1024], g_root[1024], g_bundle[1024];

const char *ns_bundle_dir(void) { return g_bundle; }

#define MAX_SECTIONS 512
static struct { char seg[17], sect[17]; uint32_t addr, size; } g_sect[MAX_SECTIONS];
static int g_nsect;

int ns_sections(const char *seg, const char *sect, uint32_t *addr, uint32_t *size, int max) {
    int n = 0;
    for (int i = 0; i < g_nsect && n < max; i++)
        if (!strcmp(g_sect[i].seg, seg) && !strcmp(g_sect[i].sect, sect)) {
            addr[n] = g_sect[i].addr;
            size[n++] = g_sect[i].size;
        }
    return n;
}
static uint32_t g_entry;

static uint8_t *slurp(const char *path, long *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); *len = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(*len);
    if (fread(b, 1, *len, f) != (size_t)*len) { free(b); b = NULL; }
    fclose(f);
    return b;
}

static void load_macho(const char *path, int is_app) {
    long len;
    uint8_t *file = slurp(path, &len), *m = file;
    if (!file) { fprintf(stderr, "ns: cannot read %s\n", path); exit(1); }
    if (BE32(file) == 0xCAFEBABE) {                    /* fat: take the i386 slice */
        uint32_t n = BE32(file + 4);
        m = NULL;
        for (uint32_t i = 0; i < n; i++)
            if (BE32(file + 8 + 20 * i) == 7) m = file + BE32(file + 8 + 20 * i + 8);
        if (!m) { fprintf(stderr, "ns: %s has no i386 slice\n", path); exit(1); }
    }
    if (RD32(m) != 0xFEEDFACE) { fprintf(stderr, "ns: %s is not a little-endian Mach-O\n", path); exit(1); }
    uint32_t ncmds = RD32(m + 16);
    const uint8_t *lc = m + 28;
    for (uint32_t c = 0; c < ncmds; c++, lc += RD32(lc + 4)) {
        uint32_t cmd = RD32(lc);
        if (cmd == 1) {                                  /* LC_SEGMENT */
            if (!strncmp((const char *)lc + 8, "__LINKEDIT", 16) || !strncmp((const char *)lc + 8, "__PAGEZERO", 16))
                continue;
            uint32_t vm = RD32(lc + 24), fileoff = RD32(lc + 32), filesize = RD32(lc + 36);
            memcpy(GUEST(vm), m + fileoff, filesize);    /* the rest of vmsize is already zero */
            for (uint32_t k = 0, ns = RD32(lc + 48); k < ns && g_nsect < MAX_SECTIONS; k++) {
                const uint8_t *sc = lc + 56 + 68 * k;
                memcpy(g_sect[g_nsect].sect, sc, 16);
                memcpy(g_sect[g_nsect].seg, sc + 16, 16);
                g_sect[g_nsect].addr = RD32(sc + 32);
                g_sect[g_nsect].size = RD32(sc + 36);
                g_nsect++;
            }
        } else if (cmd == 2 && !is_app) {                /* LC_SYMTAB: shlib names */
            uint32_t symoff = RD32(lc + 8), nsyms = RD32(lc + 12), stroff = RD32(lc + 16);
            for (uint32_t i = 0; i < nsyms; i++) {
                const uint8_t *s = m + symoff + 12 * i;
                if ((s[4] & 0x0e) != 0x0e) continue;     /* N_SECT only */
                if (g_nsyms == g_capsyms) {
                    g_capsyms = g_capsyms ? g_capsyms * 2 : 16384;
                    g_syms = realloc(g_syms, g_capsyms * sizeof(sym_t));
                }
                g_syms[g_nsyms].va = RD32(s + 8);
                g_syms[g_nsyms].name = (const char *)m + stroff + RD32(s);  /* file stays loaded */
                g_nsyms++;
            }
        } else if (cmd == 6 && is_app) {                 /* LC_LOADFVMLIB */
            const char *name = (const char *)lc + RD32(lc + 8);
            const char *base = strrchr(name, '/');
            char p[2048];
            snprintf(p, sizeof p, "%s/%s", g_shlib_dir, base ? base + 1 : name);
            load_macho(p, 0);
        } else if (cmd == 5 && is_app) {                 /* LC_UNIXTHREAD: i386 eip */
            g_entry = RD32(lc + 16 + 4 * 10);
        }
    }
    if (is_app) { (void)len; free(file); }
}

/* ---- name binding -------------------------------------------------------- */
#define MAX_SHIMS 2048
static ns_shim_t g_shims[MAX_SHIMS];
static int g_nshims;

void ns_register(const ns_shim_t *s) {
    for (; s->name; s++) {
        if (g_nshims == MAX_SHIMS) { fprintf(stderr, "ns: shim table full\n"); exit(1); }
        g_shims[g_nshims++] = *s;
    }
}

static recomp_func_t shim_named(const char *name) {
    for (int i = g_nshims - 1; i >= 0; i--)
        if (!strcmp(g_shims[i].name, name)) return g_shims[i].fn;
    return NULL;
}

int g_ns_trace;   /* NS_TRACE=1: log every import and message */

/* The import being entered; the generic stub reports it. */
static const char *g_cur_import = "(none)";

/* Anything without a shim. Methods named init* hand back self, so an
 * unimplemented initializer does not nil out the object being built. */
static void unimplemented(void) {
    static const char *seen[1024];
    static int nseen;
    const char *n = g_cur_import;
    int known = 0;
    for (int i = 0; i < nseen; i++) known |= seen[i] == n;
    if (!known) {
        fprintf(stderr, "ns: unimplemented %s (from 0x%08X)\n", n, g_cur_func);
        if (nseen < 1024) seen[nseen++] = n;
    }
    int is_init = (n[0] == '-' || n[0] == '+') && strstr(n, " init");
    NS_RET(is_init ? ARG(0) : 0);
}

/* va -> binding cache. Open addressing; a NeXT app touches a few hundred. */
#define BIND_SLOTS 8192
static struct { uint32_t va; recomp_func_t fn; const char *name; } g_bind[BIND_SLOTS];

recomp_func_t recomp_lookup_import(uint32_t va) {
    uint32_t h = (va * 2654435761u) & (BIND_SLOTS - 1);
    while (g_bind[h].va && g_bind[h].va != va) h = (h + 1) & (BIND_SLOTS - 1);
    if (!g_bind[h].va) {
        const char *name = ns_sym_at(va);
        if ((!name || !strncmp(name, ".branch_table_slot", 18)) && MEM8(va) == 0xE9) {
            uint32_t t = va + 5 + MEM32(va + 1);        /* follow the slot's jmp */
            name = ns_sym_at(t);
        }
        if (!name) return NULL;                          /* not a shlib address: ICALL reports it */
        recomp_func_t fn = shim_named(name);
        g_bind[h].va = va;
        g_bind[h].fn = fn ? fn : unimplemented;
        g_bind[h].name = name;
    }
    g_cur_import = g_bind[h].name;
    if (g_ns_trace) fprintf(stderr, "ns: -> %s (from 0x%08X)\n", g_cur_import, g_cur_func);
    return g_bind[h].fn;
}

recomp_func_t recomp_lookup_manual(uint32_t va) { (void)va; return NULL; }

recomp_func_t recomp_lookup(uint32_t va) {
    uint32_t lo = 0, hi = recomp_dispatch_count;
    while (lo < hi) {
        uint32_t mid = (lo + hi) / 2;
        if (recomp_dispatch_table[mid].address < va) lo = mid + 1; else hi = mid;
    }
    return lo < recomp_dispatch_count && recomp_dispatch_table[lo].address == va
         ? recomp_dispatch_table[lo].func : NULL;
}

uint32_t ns_call(uint32_t va, int n, const uint32_t *args) {
    for (int i = n - 1; i >= 0; i--) PUSH32(g_esp, args[i]);
    recomp_func_t fn = recomp_lookup(va);
    if (!fn) fn = recomp_lookup_import(va);
    if (!fn) { fprintf(stderr, "ns: call to unknown VA 0x%08X\n", va); exit(1); }
    uint32_t caller = g_cur_func;
    PUSH32(g_esp, RECOMP_RETADDR);
    fn();                                                /* its ret pops RETADDR */
    g_cur_func = caller;
    g_esp += 4 * n;
    return g_eax;
}

/* ---- paths --------------------------------------------------------------- */
const char *ns_host_path(const char *guest) {
    static char buf[4096];
    if (guest[0] == '/') snprintf(buf, sizeof buf, "%s%s", g_root, guest);
    else snprintf(buf, sizeof buf, "%s", guest);
    return buf;
}

/* ---- entry --------------------------------------------------------------- */

static uint32_t push_str(uint32_t *sp, const char *s) {
    uint32_t n = (uint32_t)strlen(s) + 1;
    *sp = (*sp - n) & ~3u;
    memcpy(GUEST(*sp), s, n);
    return *sp;
}

void ns_run(const char *app, const char *shlib_dir, const char *root, int argc, char **argv) {
    snprintf(g_shlib_dir, sizeof g_shlib_dir, "%s", shlib_dir);
    snprintf(g_root, sizeof g_root, "%s", root);
    {   /* bundle = the app's directory, as a guest path under root */
        size_t rl = strlen(root);
        const char *rel = strncmp(app, root, rl) ? app : app + rl;
        snprintf(g_bundle, sizeof g_bundle, "%s%s", rel[0] == '/' || rel[0] == '\\' ? "" : "/", rel);
        for (char *c = g_bundle; *c; c++) if (*c == '\\') *c = '/';
        char *slash = strrchr(g_bundle, '/');
        if (slash && slash != g_bundle) *slash = 0; else strcpy(g_bundle, "/");
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    g_ns_trace = getenv("NS_TRACE") != NULL;
    map_guest();
    load_macho(app, 1);
    qsort(g_syms, g_nsyms, sizeof(sym_t), sym_cmp);
    fprintf(stderr, "ns: mapped %s, %d shlib symbols, entry 0x%08X\n", app, g_nsyms, g_entry);

    ns_libc_init();
    ns_objc_init();
    ns_appkit_init();

    /* The stack as the kernel leaves it: argc, argv[], 0, envp[], 0, strings. */
    uint32_t sp = STACK_HI - 16, gargv[64];
    int n = argc < 63 ? argc : 63;
    for (int i = 0; i < n; i++) gargv[i] = push_str(&sp, argv[i]);
    sp &= ~15u;
    PUSH32(sp, 0);                  /* envp terminator: no environment */
    PUSH32(sp, 0);                  /* argv terminator */
    for (int i = n - 1; i >= 0; i--) PUSH32(sp, gargv[i]);
    PUSH32(sp, n);
    g_esp = sp;                     /* crt0 reads argc at [esp]: no return address */

    recomp_func_t start = recomp_lookup(g_entry);
    if (!start) { fprintf(stderr, "ns: entry 0x%08X was not lifted\n", g_entry); exit(1); }
    start();
    fprintf(stderr, "ns: crt0 returned\n");
    exit(0);
}

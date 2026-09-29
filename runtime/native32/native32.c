/*
 * native32: see native32.h for the model. Extracted from gunman's
 * src/runtime/runtime.c, which is where each of the non-obvious details below
 * was found the hard way; the comments say which.
 */
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "native32.h"
#include "image_loader.h"
#include "recomp_trace.h"

#if !defined(_MSC_VER) || !defined(_M_IX86)
#error "native32 is MSVC x86 only: the bridge and the callback trampoline are inline asm"
#endif

/* ------------------------------------------------------------ register file */

uint32_t  g_eax, g_ecx, g_edx, g_esp, g_ebx, g_esi, g_edi, g_ebp;
double    g_st[8];
int       g_fp_top;
uint16_t  g_fpu_cw = 0x027F;
uint16_t  g_seg_cs, g_seg_ds, g_seg_es, g_seg_fs, g_seg_gs, g_seg_ss;
uint64_t  g_mm[8];
uint32_t  g_fs_base, g_gs_base;
ptrdiff_t g_mem_base = 0;
uint32_t  g_cur_func;
uint32_t  g_icall_trace[ICALL_TRACE_SIZE], g_icall_from[ICALL_TRACE_SIZE];
uint32_t  g_icall_trace_idx, g_icall_count;

int native32_trace_native, native32_trace_callbacks;

typedef struct {
    uint32_t eax, ecx, edx, esp, ebx, esi, edi, ebp, fs, cur;
    double   st[8];
    int      fp_top;
    uint16_t fpu_cw;
    uint64_t mm[8];
} regs_t;

static void regs_save(regs_t* r) {
    r->eax = g_eax; r->ecx = g_ecx; r->edx = g_edx; r->esp = g_esp;
    r->ebx = g_ebx; r->esi = g_esi; r->edi = g_edi; r->ebp = g_ebp;
    r->fs = g_fs_base; r->cur = g_cur_func;
    memcpy(r->st, g_st, sizeof g_st); r->fp_top = g_fp_top; r->fpu_cw = g_fpu_cw;
    memcpy(r->mm, g_mm, sizeof g_mm);
}

static void regs_load(const regs_t* r) {
    g_eax = r->eax; g_ecx = r->ecx; g_edx = r->edx; g_esp = r->esp;
    g_ebx = r->ebx; g_esi = r->esi; g_edi = r->edi; g_ebp = r->ebp;
    g_fs_base = r->fs; g_cur_func = r->cur;
    memcpy(g_st, r->st, sizeof g_st); g_fp_top = r->fp_top; g_fpu_cw = r->fpu_cw;
    memcpy(g_mm, r->mm, sizeof g_mm);
}

/* ------------------------------------------------------------- machine lock */

static CRITICAL_SECTION g_mach;
static DWORD g_mach_tls = TLS_OUT_OF_INDEXES;

#define GUEST_STACK (4u << 20)

/* A guest thread's TIB. Lifted code reads fs:[n] as MEM32(g_fs_base + n); the
 * real TEB stays the host's, so a guest SEH frame never lands on a chain
 * Windows walks. The PEB is the real one: code that reads fs:[30h] wants it. */
static uint32_t make_tib(uint32_t lo, uint32_t hi) {
    uint32_t* t = (uint32_t*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    t[0] = 0xFFFFFFFFu;                          /* ExceptionList: end of chain */
    t[1] = hi;                                   /* StackBase                   */
    t[2] = lo;                                   /* StackLimit                  */
    t[0x18 / 4] = (uint32_t)(uintptr_t)t;        /* Self                        */
    t[0x24 / 4] = GetCurrentThreadId();
    t[0x30 / 4] = __readfsdword(0x30);
    return (uint32_t)(uintptr_t)t;
}

typedef struct { regs_t r; int depth; } mstate;

/* Nests: a callback that arrives while this thread is inside a native call
 * claims again, and only the outermost claim loads the saved state. */
void mach_enter(void) {
    EnterCriticalSection(&g_mach);
    mstate* m = (mstate*)TlsGetValue(g_mach_tls);
    if (!m) {
        /* Stack left for a fault handler after an overflow: without it the
         * report itself overflows and the process just vanishes. */
        ULONG guarantee = 64 * 1024;
        SetThreadStackGuarantee(&guarantee);
        m = (mstate*)calloc(1, sizeof *m);
        uint32_t lo = (uint32_t)(uintptr_t)VirtualAlloc(NULL, GUEST_STACK,
                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        m->r.esp = lo + GUEST_STACK - 64;
        m->r.fs = make_tib(lo, lo + GUEST_STACK);
        m->r.fpu_cw = 0x027F;
        TlsSetValue(g_mach_tls, m);
    }
    if (m->depth++ == 0) regs_load(&m->r);
}

void mach_leave(void) {
    mstate* m = (mstate*)TlsGetValue(g_mach_tls);
    if (--m->depth == 0) regs_save(&m->r);
    LeaveCriticalSection(&g_mach);
}

/* ---------------------------------------------------------------- modules */

#define MAX_MODULES 32
static struct { uint32_t base, span; } g_mods[MAX_MODULES];
static int g_mod_n;

int native32_in_guest(uint32_t va) {
    for (int i = 0; i < g_mod_n; i++)
        if (va >= g_mods[i].base && va < g_mods[i].base + g_mods[i].span) return 1;
    return 0;
}

uint32_t native32_map(const char* path, uint32_t base) {
    uint32_t span = recomp_load_image(path, base);
    if (!span || g_mod_n == MAX_MODULES) return 0;
    g_mods[g_mod_n].base = base;
    g_mods[g_mod_n++].span = span;
    IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(uintptr_t)(base + ((IMAGE_DOS_HEADER*)(uintptr_t)base)->e_lfanew);
    IMAGE_SECTION_HEADER* s = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, s++) {
        DWORD old;
        if (s->Characteristics & IMAGE_SCN_MEM_EXECUTE)
            VirtualProtect((void*)(uintptr_t)(base + s->VirtualAddress), s->Misc.VirtualSize,
                           PAGE_READWRITE, &old);
    }
    return span;
}

/* ---------------------------------------------------------------- names */

#define MAX_NAMES 4096
static struct { uint32_t va; char name[60]; } g_names[MAX_NAMES];
static int g_name_n;

const char* native32_name(uint32_t va) {
    for (int i = 0; i < g_name_n; i++)
        if (g_names[i].va == va) return g_names[i].name;
    return NULL;
}

static void add_name(uint32_t va, const char* dll, const char* fn) {
    if (g_name_n < MAX_NAMES && !native32_name(va)) {
        _snprintf(g_names[g_name_n].name, sizeof g_names[0].name - 1, "%s!%s", dll, fn);
        g_names[g_name_n++].va = va;
    }
}

/* ------------------------------------------------------- guest -> Windows */

/* Argument slots copied per call. Reading past a callee's real arguments is
 * harmless; CreateFontA (14) is the widest common Win32 call. */
#define BRIDGE_SLOTS 24

static uint32_t g_native_target;

/* Synthetic VAs for hand shims: a reserved, never-committed range, so no real
 * code or data can share an address with one. */
static uint32_t g_shim_page;
static native32_shim_t* g_shims;
static int g_nshims;
#define IS_SHIM_VA(va) (g_shim_page && (va) >= g_shim_page && (va) < g_shim_page + 0x10000u)

static void native_bridge(void) {
    uint32_t fn = g_native_target;
    uint32_t* src = (uint32_t*)(uintptr_t)(g_esp + 4);   /* past the dummy ret */
    uint32_t this_ecx = g_ecx, r_eax, r_edx, purge;
    uint16_t sw0, sw1;
    double r_st = 0;
    const char* saved_import = g_cur_import;
    if (native32_trace_native) {
        const char* n = native32_name(fn);
        fprintf(stderr, "[native] %-32s (%08X %08X %08X %08X) from sub_%08X",
                n ? n : "?", src[0], src[1], src[2], src[3], g_cur_func);
        if (!n) fprintf(stderr, " @%08X", fn);
        for (int k = 0; k < 4; k++) {       /* arguments that are strings (gunman) */
            MEMORY_BASIC_INFORMATION mbi;
            const char* p = (const char*)(uintptr_t)src[k];
            if (src[k] < 0x10000 || !VirtualQuery(p, &mbi, sizeof mbi) ||
                mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
                continue;
            size_t room = (size_t)((const char*)mbi.BaseAddress + mbi.RegionSize - p), len = 0;
            while (len < room && len < 96 && p[len] >= 0x20 && p[len] < 0x7F) len++;
            if (len >= 3 && (len == room || len == 96 || !p[len]))
                fprintf(stderr, " a%d=\"%.*s\"", k, (int)len, p);
        }
    }
    g_cur_import = native32_name(fn);
    if (!g_cur_import) g_cur_import = "(native)";
    mach_leave();
    __asm {
        mov  esi, src
        sub  esp, BRIDGE_SLOTS * 4
        mov  edi, esp
        mov  ecx, BRIDGE_SLOTS
        cld
        rep  movsd
        mov  ebx, esp            ; callee-saved: survives the call
        fnstsw ax
        mov  sw0, ax             ; x87 TOP before
        mov  ecx, this_ecx       ; thiscall / COM 'this'
        call fn
        mov  r_eax, eax
        mov  r_edx, edx
        mov  eax, esp
        sub  eax, ebx            ; bytes the callee popped
        mov  purge, eax
        lea  esp, [ebx + BRIDGE_SLOTS * 4]
        fxam                     ; C3..C0 classify st(0)
        fnstsw ax
        mov  sw1, ax             ; x87 TOP after
    }
    /* A float result comes back in st(0): TOP moved down by exactly one and
     * st(0) is not empty. A native fninit/_fpreset also moves TOP; without the
     * fxam check that read as a returned float and pushed junk onto the lifted
     * stack (gunman: every later frame rendered NaNs). */
    int st_ret = (((sw0 >> 11) - (sw1 >> 11)) & 7) == 1 && (sw1 & 0x4100) != 0x4100;
    if (st_ret) __asm fstp r_st
    mach_enter();
    if (st_ret) fp_push_impl(g_st, &g_fp_top, r_st);
    g_cur_import = saved_import;
    g_eax = r_eax;
    g_edx = r_edx;
    g_esp += 4 + purge;
    if (native32_trace_native) fprintf(stderr, " -> %08X\n", r_eax);
}

recomp_func_t recomp_lookup(uint32_t va) {
    uint32_t lo = 0, hi = recomp_dispatch_count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2, m = recomp_dispatch_table[mid].address;
        if (m == va) return recomp_dispatch_table[mid].func;
        if (m < va) lo = mid + 1; else hi = mid;
    }
    return NULL;
}

/* Anything that is neither a shim nor inside a guest module is native: an
 * import, a GetProcAddress result, a COM method. */
recomp_func_t recomp_lookup_import(uint32_t va) {
    if (IS_SHIM_VA(va)) {
        for (int i = 0; i < g_nshims; i++)
            if (g_shims[i].va == va) return g_shims[i].fn;
        return NULL;
    }
    if (va < 0x10000u || native32_in_guest(va)) return NULL;
    g_native_target = va;
    return native_bridge;
}

/* Built-in shims every host gets, ahead of its own.
 *
 * CreateThread: the thread runs LIFTED code on its native stack, and a lifted
 * function's frame is several times the original's (register locals, flag
 * state, the C compiler's own spills), so the size the original asked for is
 * far too small. The Movies' worker threads overflowed theirs, and with no
 * stack left even the fault report died. Reserve 16 MB (committed on demand). */
#define GUEST_THREAD_STACK (16u << 20)
static void shim_CreateThread(void) {
    uint32_t* a = (uint32_t*)(uintptr_t)(g_esp + 4);
    SIZE_T size = a[1] > GUEST_THREAD_STACK ? a[1] : GUEST_THREAD_STACK;
    HANDLE h = CreateThread((LPSECURITY_ATTRIBUTES)(uintptr_t)a[0], size,
                            (LPTHREAD_START_ROUTINE)(uintptr_t)a[2], (LPVOID)(uintptr_t)a[3],
                            a[4] | STACK_SIZE_PARAM_IS_A_RESERVATION, (LPDWORD)(uintptr_t)a[5]);
    g_eax = (uint32_t)(uintptr_t)h;
    g_esp += 4 + 6 * 4;
}

static native32_shim_t g_builtin[] = {
    { "CreateThread", shim_CreateThread },
};

int native32_bind(uint32_t base, native32_shim_t* shims, int nshims) {
    uint8_t* b = (uint8_t*)(uintptr_t)base;
    IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(b + ((IMAGE_DOS_HEADER*)b)->e_lfanew);
    IMAGE_DATA_DIRECTORY dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_IMPORT_DESCRIPTOR* d = (IMAGE_IMPORT_DESCRIPTOR*)(b + dd.VirtualAddress);
    int native = 0, shimmed = 0, missing = 0;
    /* The host's shims, then every built-in the host did not replace. */
    int nb = (int)(sizeof g_builtin / sizeof g_builtin[0]);
    native32_shim_t* all = (native32_shim_t*)calloc(nshims + nb, sizeof *all);
    int n = 0;
    for (int i = 0; i < nshims; i++) all[n++] = shims[i];
    for (int i = 0; i < nb; i++) {
        int dup = 0;
        for (int k = 0; k < nshims; k++) dup |= !strcmp(shims[k].name, g_builtin[i].name);
        if (!dup) all[n++] = g_builtin[i];
    }
    shims = all;
    nshims = n;
    g_shims = shims;
    g_nshims = nshims;
    for (; dd.VirtualAddress && d->Name; d++) {
        const char* dll = (const char*)(b + d->Name);
        HMODULE h = LoadLibraryA(dll);
        uint32_t* ilt = (uint32_t*)(b + (d->OriginalFirstThunk ? d->OriginalFirstThunk : d->FirstThunk));
        uint32_t* iat = (uint32_t*)(b + d->FirstThunk);
        for (; *ilt; ilt++, iat++) {
            int by_ord = (*ilt & 0x80000000u) != 0;
            const char* nm = by_ord ? (const char*)(uintptr_t)(*ilt & 0xFFFF) : (const char*)(b + *ilt + 2);
            uint32_t va = 0;
            for (int i = 0; !by_ord && i < nshims; i++)
                if (!strcmp(shims[i].name, nm)) {
                    shims[i].va = g_shim_page + 16 * i;
                    va = shims[i].va;
                    shimmed++;
                }
            if (!va) {
                va = h ? (uint32_t)(uintptr_t)GetProcAddress(h, nm) : 0;
                if (va) native++;
                else {
                    fprintf(stderr, "[bind] %s!%s%s unresolved\n", dll, by_ord ? "#" : "",
                            by_ord ? "" : nm);
                    missing++;
                }
            }
            if (va && !by_ord) add_name(va, dll, nm);
            *iat = va;
        }
    }
    fprintf(stderr, "[bind] 0x%08X: %d native, %d shimmed, %d unresolved\n",
            base, native, shimmed, missing);
    return missing;
}

/* ------------------------------------------------------- Windows -> guest */

/* Runs a lifted function for a native caller. `sp` points at the native
 * caller's [ret][args...]. Returns eax in the low half and the bytes the
 * callee popped in the high half, for cb_tramp's variable `ret n`. */
static uint64_t __cdecl cb_run(uint32_t va, uint32_t* sp, uint32_t ecx) {
    recomp_func_t f = IS_SHIM_VA(va) ? recomp_lookup_import(va) : recomp_lookup(va);
    if (native32_trace_callbacks)
        fprintf(stderr, "[callback] sub_%08X (%08X %08X %08X %08X)\n", va, sp[1], sp[2], sp[3], sp[4]);
    mach_enter();
    regs_t saved;
    regs_save(&saved);
    g_esp -= BRIDGE_SLOTS * 4;
    memcpy((void*)(uintptr_t)g_esp, sp + 1, BRIDGE_SLOTS * 4);
    PUSH32(g_esp, RECOMP_RETADDR);
    uint32_t before = g_esp;
    g_ecx = ecx;
    f();
    uint32_t eax = g_eax, purge = g_esp - before - 4;
    /* The other half of the st(0) transfer: a lifted function returning a
     * float leaves it on the LIFTED x87 stack, and the native caller is about
     * to fstp its own. */
    int st_ret = g_fp_top == saved.fp_top + 1;
    double cb_st = g_st[0];
    regs_load(&saved);
    mach_leave();
    if (st_ret) __asm fld cb_st
    return ((uint64_t)purge << 32) | eax;
}

static __declspec(naked) void cb_tramp(void) {
    __asm {
        mov  edx, esp            ; [ret][args]
        push ecx
        push edx
        push eax                 ; the guest VA, planted by the VEH
        call cb_run
        add  esp, 12
        pop  ecx                 ; native return address
        add  esp, edx            ; pop what the guest callee popped
        jmp  ecx
    }
}

static LONG CALLBACK native32_veh(EXCEPTION_POINTERS* ep) {
    EXCEPTION_RECORD* er = ep->ExceptionRecord;
    uint32_t pc = (uint32_t)(uintptr_t)er->ExceptionAddress;
    if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->ExceptionInformation[0] == 8 &&
        (native32_in_guest(pc) || IS_SHIM_VA(pc))) {
        if (recomp_lookup(pc) || IS_SHIM_VA(pc)) {
            ep->ContextRecord->Eax = pc;
            ep->ContextRecord->Eip = (DWORD)(uintptr_t)cb_tramp;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        fprintf(stderr, "[callback] Windows called guest 0x%08X, which is not lifted\n", pc);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* ---------------------------------------------------------------- setup */

void native32_init(void) {
    InitializeCriticalSection(&g_mach);
    g_mach_tls = TlsAlloc();
    g_shim_page = (uint32_t)(uintptr_t)VirtualAlloc(NULL, 0x10000, MEM_RESERVE, PAGE_NOACCESS);
    AddVectoredExceptionHandler(1, native32_veh);
}

void native32_call_guest(uint32_t va, int nargs, const uint32_t* args) {
    recomp_func_t f = recomp_lookup(va);
    if (!f) { fprintf(stderr, "[native32] no lifted function at 0x%08X\n", va); exit(3); }
    mach_enter();
    for (int i = nargs - 1; i >= 0; i--) PUSH32(g_esp, args[i]);
    PUSH32(g_esp, RECOMP_RETADDR);
    f();
    mach_leave();
}

void native32_dump_icalls(int n) {
    fprintf(stderr, "last indirect calls (newest first):\n");
    for (int i = 1; i <= n && i <= (int)g_icall_trace_idx; i++) {
        uint32_t k = (g_icall_trace_idx - i) & (ICALL_TRACE_SIZE - 1);
        const char* nm = native32_name(g_icall_trace[k]);
        fprintf(stderr, "  0x%08X  from 0x%08X  %s\n", g_icall_trace[k], g_icall_from[k], nm ? nm : "");
    }
}

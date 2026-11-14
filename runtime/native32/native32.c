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
xmm_t     g_xmm[8];
uint32_t  g_mxcsr = 0x1F80;
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
    xmm_t    xmm[8];
    uint32_t mxcsr;
} regs_t;

static void regs_save(regs_t* r) {
    r->eax = g_eax; r->ecx = g_ecx; r->edx = g_edx; r->esp = g_esp;
    r->ebx = g_ebx; r->esi = g_esi; r->edi = g_edi; r->ebp = g_ebp;
    r->fs = g_fs_base; r->cur = g_cur_func;
    memcpy(r->st, g_st, sizeof g_st); r->fp_top = g_fp_top; r->fpu_cw = g_fpu_cw;
    memcpy(r->mm, g_mm, sizeof g_mm);
    memcpy(r->xmm, g_xmm, sizeof g_xmm); r->mxcsr = g_mxcsr;
}

static void regs_load(const regs_t* r) {
    g_eax = r->eax; g_ecx = r->ecx; g_edx = r->edx; g_esp = r->esp;
    g_ebx = r->ebx; g_esi = r->esi; g_edi = r->edi; g_ebp = r->ebp;
    g_fs_base = r->fs; g_cur_func = r->cur;
    memcpy(g_st, r->st, sizeof g_st); g_fp_top = r->fp_top; g_fpu_cw = r->fpu_cw;
    memcpy(g_mm, r->mm, sizeof g_mm);
    memcpy(g_xmm, r->xmm, sizeof g_xmm); g_mxcsr = r->mxcsr;
}

/* ------------------------------------------------------------- machine lock */

static CRITICAL_SECTION g_mach;
static DWORD g_mach_tls = TLS_OUT_OF_INDEXES;

/* Argument slots copied per call. Reading past a callee's real arguments is
 * harmless while those words are mapped (mach_enter leaves room); CreateFontA
 * (14) is the widest common Win32 call. */
#define BRIDGE_SLOTS 24

#define GUEST_STACK (4u << 20)

/* Static TLS (__declspec(thread), Borland's threadvars): the guest reads its
 * block as fs:[2Ch][index]. Windows sets that up only for modules its loader
 * loaded, and the guest TIB is ours, so a guest module with a TLS directory
 * (native32_map) gets a slot here, and each guest thread a copy of the
 * template in make_tib. ponytail: TLS callbacks are not run; no title has had
 * one. */
#define MAX_TLS 8
static struct { uint32_t start, end, zero; } g_tls[MAX_TLS];
static int g_tls_n;

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
    if (g_tls_n) {
        uint32_t* slots = (uint32_t*)calloc(MAX_TLS, 4);
        for (int i = 0; i < g_tls_n; i++) {
            uint32_t n = g_tls[i].end - g_tls[i].start;
            uint8_t* blk = (uint8_t*)calloc(1, n + g_tls[i].zero + 16);
            memcpy(blk, (void*)(uintptr_t)g_tls[i].start, n);
            slots[i] = (uint32_t)(uintptr_t)blk;
        }
        t[0x2C / 4] = (uint32_t)(uintptr_t)slots;
    }
    return (uint32_t)(uintptr_t)t;
}

typedef struct { regs_t r; int depth; } mstate;

/* TerminateThread and the machine lock. A thread killed while it waits for
 * the lock leaves its wait block linked into the lock, on a stack that no
 * longer exists, and the next thread to wait on the lock faults inside ntdll
 * (Star Wars Rebellion: its movie player kills its worker thread, and the
 * sound thread started next died on its first mach_enter). So every guest
 * thread says, in a table any thread can read, whether it is waiting for the
 * lock; a doomed one exits by itself at the lock (shim_TerminateThread). The
 * order is what makes it safe: a thread marks itself waiting BEFORE it looks
 * at its doom, and the killer dooms it BEFORE it looks at that mark, so a
 * thread the killer sees as not waiting can never start waiting. */
#define MAX_GTHREADS 64
enum { T_FREE, T_NATIVE, T_WAITING };
static volatile LONG g_tid[MAX_GTHREADS], g_tstate[MAX_GTHREADS], g_tdoom[MAX_GTHREADS];
static volatile LONG g_tcode[MAX_GTHREADS];
static DWORD g_tslot_fls = FLS_OUT_OF_INDEXES;  /* frees a slot when its thread ends */

static int tslot(DWORD tid, int add) {
    for (int i = 0; i < MAX_GTHREADS; i++)
        if ((DWORD)g_tid[i] == tid) return i;
    for (int i = 0; add && i < MAX_GTHREADS; i++)
        if (InterlockedCompareExchange(&g_tid[i], (LONG)tid, 0) == 0) return i;
    return -1;
}

static void tslot_exit(int k, int holding) {
    DWORD code = (DWORD)g_tcode[k];
    g_tdoom[k] = 0;
    InterlockedExchange(&g_tstate[k], T_FREE);
    InterlockedExchange(&g_tid[k], 0);
    if (g_tslot_fls != FLS_OUT_OF_INDEXES) FlsSetValue(g_tslot_fls, NULL);   /* freed already */
    if (holding) LeaveCriticalSection(&g_mach);
    if (getenv("NATIVE32_LOG_THREADS"))
        fprintf(stderr, "[thread] %lu exits at the lock (holding %d)\n", GetCurrentThreadId(), holding);
    ExitThread(code);
}

static __declspec(thread) int t_slot;          /* this thread's slot + 1; 0: not looked up */

/* A thread that ends any other way (returns, ExitThread) frees its slot here:
 * an FLS destructor runs as the thread exits. */
static void WINAPI tslot_free(void* v) {
    int k = (int)(intptr_t)v - 1;
    if (k < 0) return;
    g_tdoom[k] = 0;
    InterlockedExchange(&g_tstate[k], T_FREE);
    InterlockedExchange(&g_tid[k], 0);
}

void mach_enter(void) {
    if (!t_slot) {
        t_slot = tslot(GetCurrentThreadId(), 1) + 1;
        if (t_slot && g_tslot_fls != FLS_OUT_OF_INDEXES) FlsSetValue(g_tslot_fls, (void*)(intptr_t)t_slot);
    }
    int k = t_slot - 1;
    if (k >= 0) {
        InterlockedExchange(&g_tstate[k], T_WAITING);
        if (InterlockedCompareExchange(&g_tdoom[k], 0, 0)) tslot_exit(k, 0);
    }
    EnterCriticalSection(&g_mach);
    if (k >= 0) {
        InterlockedExchange(&g_tstate[k], T_NATIVE);   /* not waiting; the lock says it runs */
        if (g_tdoom[k]) tslot_exit(k, 1);
    }
    mstate* m = (mstate*)TlsGetValue(g_mach_tls);
    if (!m) {
        /* Stack left for a fault handler after an overflow: without it the
         * report itself overflows and the process just vanishes. */
        ULONG guarantee = 64 * 1024;
        SetThreadStackGuarantee(&guarantee);
        m = (mstate*)calloc(1, sizeof *m);
        uint32_t lo = (uint32_t)(uintptr_t)VirtualAlloc(NULL, GUEST_STACK,
                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        /* The bridge copies BRIDGE_SLOTS words up from esp whatever the
         * callee takes, so the first call made from an empty stack must not
         * read off the end of it. With 64 bytes of headroom it did, and faulted
         * whenever ASLR left the next page unmapped: the selftest crashed on
         * about two runs in three. */
        m->r.esp = lo + GUEST_STACK - BRIDGE_SLOTS * 4 - 64;
        m->r.fs = make_tib(lo, lo + GUEST_STACK);
        m->r.fpu_cw = 0x027F;
        m->r.mxcsr = 0x1F80;              /* exceptions masked, round to nearest */
        TlsSetValue(g_mach_tls, m);
    }
    if (m->depth++ == 0) regs_load(&m->r);
}

void mach_leave(void) {
    mstate* m = (mstate*)TlsGetValue(g_mach_tls);
    if (--m->depth == 0) regs_save(&m->r);
    LeaveCriticalSection(&g_mach);
}

/* RECOMP_BACKEDGE's hand-over: let another guest thread take the machine.
 * Only the outermost claim can give it up; inside a callback the lock is
 * still held further out, and the loop simply runs on. */
static void native32_yield(void) {
    mstate* m = (mstate*)TlsGetValue(g_mach_tls);
    if (!m || m->depth != 1) return;
    mach_leave();
    SwitchToThread();
    mach_enter();
}

/* ---------------------------------------------------------------- modules */

#define MAX_MODULES 32
static struct { uint32_t base, span; int native; char name[MAX_PATH]; } g_mods[MAX_MODULES];
static int g_mod_n;

static recomp_func_t dispatch_find(uint32_t va);

/* Functions inside a native module that still run lifted
 * (native32_lift_in_native), sorted for bsearch. */
static uint32_t* g_lin;
static int g_lin_n;

static int lifted_in_native(uint32_t va) {
    int lo = 0, hi = g_lin_n;
    while (lo < hi) {
        int mid = (lo + hi) / 2;
        if (g_lin[mid] == va) return 1;
        if (g_lin[mid] < va) lo = mid + 1; else hi = mid;
    }
    return 0;
}

/* A module running its original machine code (native32_set_native). */
static int native_module_at(uint32_t va) {
    for (int i = 0; i < g_mod_n; i++)
        if (g_mods[i].native && va >= g_mods[i].base && va < g_mods[i].base + g_mods[i].span)
            return !lifted_in_native(va);
    return 0;
}

/* A call into a guest module outside its code sections: code kept in a data
 * section, where old hand-written asm patches its own constants. UT's Fire.dll
 * runs its procedural-texture loops from .data. No static lift can hold code
 * that rewrites itself, and it was written for this CPU, so it runs natively:
 * the section is made executable the first time it is called into. Its calls
 * back into lifted code fault on non-executable pages and take the callback
 * trampoline. */
/* A section's size in memory. Watcom's linker leaves VirtualSize 0 on every
 * section and puts the memory size in SizeOfRawData (POD's PODMMX.EXE, and
 * image_loader.c's note on Nocturne), so a section sized by VirtualSize alone
 * is empty: its code was never made non-executable, and a Windows callback
 * into it ran the original machine code instead of the lift. */
static uint32_t sec_size(const IMAGE_SECTION_HEADER* s) {
    return s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;
}

static int data_section_code(uint32_t va) {
    for (int i = 0; i < g_mod_n; i++) {
        uint32_t base = g_mods[i].base;
        if (va < base || va >= base + g_mods[i].span) continue;
        IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(uintptr_t)(base + ((IMAGE_DOS_HEADER*)(uintptr_t)base)->e_lfanew);
        IMAGE_SECTION_HEADER* s = IMAGE_FIRST_SECTION(nt);
        for (int k = 0; k < nt->FileHeader.NumberOfSections; k++, s++) {
            uint32_t lo = base + s->VirtualAddress, hi = lo + sec_size(s);
            if (va < lo || va >= hi) continue;
            if (s->Characteristics & IMAGE_SCN_MEM_EXECUTE) return 0;   /* lifted code */
            MEMORY_BASIC_INFORMATION mbi;
            DWORD old;
            VirtualQuery((void*)(uintptr_t)va, &mbi, sizeof mbi);
            if (mbi.Protect != PAGE_EXECUTE_READWRITE) {
                VirtualProtect((void*)(uintptr_t)lo, hi - lo, PAGE_EXECUTE_READWRITE, &old);
                fprintf(stderr, "[native32] %s: code in data section %.8s (0x%08X) runs natively\n",
                        g_mods[i].name, (const char*)s->Name, va);
            }
            return 1;
        }
        return 0;
    }
    return 0;
}

static int cmp_u32(const void* a, const void* b) {
    uint32_t x = *(const uint32_t*)a, y = *(const uint32_t*)b;
    return x < y ? -1 : x > y;
}

int native32_lift_in_native(const uint32_t* vas, int n) {
    int done = 0;
    g_lin = (uint32_t*)realloc(g_lin, (g_lin_n + n) * sizeof *g_lin);
    for (int i = 0; i < n; i++) {
        if (!dispatch_find(vas[i])) continue;           /* not a lifted entry */
        uint8_t* p = (uint8_t*)(uintptr_t)vas[i];
        p[0] = 0x0F, p[1] = 0x0B;                      /* ud2: the trap is the trampoline */
        g_lin[g_lin_n++] = vas[i];
        done++;
    }
    qsort(g_lin, g_lin_n, sizeof *g_lin, cmp_u32);
    FlushInstructionCache(GetCurrentProcess(), NULL, 0);
    return done;
}

int native32_set_native(uint32_t base) {
    for (int i = 0; i < g_mod_n; i++) {
        if (g_mods[i].base != base) continue;
        IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(uintptr_t)(base + ((IMAGE_DOS_HEADER*)(uintptr_t)base)->e_lfanew);
        IMAGE_SECTION_HEADER* s = IMAGE_FIRST_SECTION(nt);
        for (int k = 0; k < nt->FileHeader.NumberOfSections; k++, s++) {
            DWORD old;
            /* writable too: old code patches itself (software rasterisers) */
            if (s->Characteristics & IMAGE_SCN_MEM_EXECUTE)
                VirtualProtect((void*)(uintptr_t)(base + s->VirtualAddress), sec_size(s),
                               PAGE_EXECUTE_READWRITE, &old);
        }
        g_mods[i].native = 1;
        return 1;
    }
    return 0;
}

int native32_in_guest(uint32_t va) {
    for (int i = 0; i < g_mod_n; i++)
        if (va >= g_mods[i].base && va < g_mods[i].base + g_mods[i].span) return 1;
    return 0;
}

/* native32_hold_image: see the header. The child is marked by an environment
 * variable, so it never launches again; the standard handles are passed on
 * explicitly, so a harness reading a pipe sees the child's output. */
#define NATIVE32_HELD_ENV "NATIVE32_HELD"

int native32_hold_image(const char* path, uint32_t base) {
    char flag[16], me[MAX_PATH];
    if (GetEnvironmentVariableA(NATIVE32_HELD_ENV, flag, sizeof flag)) {
        SetEnvironmentVariableA(NATIVE32_HELD_ENV, NULL);  /* not passed on to what the guest starts */
        return 1;
    }
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS32 nt;
    FILE* f = fopen(path, "rb");
    int ok = f && fread(&dos, sizeof dos, 1, f) == 1 && fseek(f, dos.e_lfanew, SEEK_SET) == 0 &&
             fread(&nt, sizeof nt, 1, f) == 1 && nt.Signature == IMAGE_NT_SIGNATURE;
    if (f) fclose(f);
    if (!ok) return 0;
    uint32_t span = nt.OptionalHeader.SizeOfImage;

    STARTUPINFOA si = { sizeof si };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    HANDLE std[3] = { si.hStdInput, si.hStdOutput, si.hStdError };
    for (int i = 0; i < 3; i++)
        if (std[i] && std[i] != INVALID_HANDLE_VALUE) SetHandleInformation(std[i], HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    GetModuleFileNameA(NULL, me, MAX_PATH);
    SetEnvironmentVariableA(NATIVE32_HELD_ENV, "1");
    BOOL made = CreateProcessA(me, GetCommandLineA(), NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    SetEnvironmentVariableA(NATIVE32_HELD_ENV, NULL);
    if (!made) {
        fprintf(stderr, "[native32] cannot start the host again (error %lu)\n", GetLastError());
        return 0;
    }
    if (!VirtualAllocEx(pi.hProcess, (void*)(uintptr_t)base, span, MEM_RESERVE, PAGE_NOACCESS)) {
        fprintf(stderr, "[native32] 0x%08X+0x%X is taken at process start (error %lu): link the host "
                "with a small /STACK and run the lifted code on a thread with a large one\n",
                base, span, GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 0;
    }
    HANDLE job = CreateJobObjectA(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION lim = { 0 };
    lim.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (job) {
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &lim, sizeof lim);
        AssignProcessToJobObject(job, pi.hProcess);
    }
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    ExitProcess(code);
}

uint32_t native32_map(const char* path, uint32_t base) {
    uint32_t span = recomp_load_image(path, base);
    if (!span || g_mod_n == MAX_MODULES) return 0;
    const char* file = strrchr(path, '\\');
    g_mods[g_mod_n].base = base;
    g_mods[g_mod_n].span = span;
    strncpy(g_mods[g_mod_n++].name, file ? file + 1 : path, MAX_PATH - 1);
    IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(uintptr_t)(base + ((IMAGE_DOS_HEADER*)(uintptr_t)base)->e_lfanew);
    IMAGE_DATA_DIRECTORY td = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    IMAGE_TLS_DIRECTORY32* tl = td.VirtualAddress ? (IMAGE_TLS_DIRECTORY32*)(uintptr_t)(base + td.VirtualAddress) : NULL;
    /* Only an image whose TLS directory names its own memory: a copy mapped
     * away from its base with no relocations still names the original's
     * (the selftest maps a copy of itself, whose index is the host's own). */
    if (tl && g_tls_n < MAX_TLS && tl->AddressOfIndex - base < span && tl->StartAddressOfRawData - base < span) {
        /* Its index, as the loader would write it. A thread whose TIB was
         * made before this map has no block: map before running guest code. */
        IMAGE_TLS_DIRECTORY32* t = tl;
        g_tls[g_tls_n].start = t->StartAddressOfRawData;
        g_tls[g_tls_n].end = t->EndAddressOfRawData;
        g_tls[g_tls_n].zero = t->SizeOfZeroFill;
        if (t->AddressOfIndex) *(uint32_t*)(uintptr_t)t->AddressOfIndex = (uint32_t)g_tls_n;
        g_tls_n++;
    }
    IMAGE_SECTION_HEADER* s = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, s++) {
        DWORD old;
        if (s->Characteristics & IMAGE_SCN_MEM_EXECUTE)
            VirtualProtect((void*)(uintptr_t)(base + s->VirtualAddress), sec_size(s),
                           PAGE_READWRITE, &old);
    }
    return span;
}

uint32_t native32_module(const char* name) {
    const char* file = strrchr(name, '\\');
    file = file ? file + 1 : name;
    for (int i = 0; i < g_mod_n; i++)
        if (!_stricmp(g_mods[i].name, file)) return g_mods[i].base;
    return 0;
}

/* GetProcAddress over a mapped guest image: a name, or an ordinal below
 * 0x10000. Forwarders are not followed; no guest module has needed one. */
uint32_t native32_export(uint32_t base, const char* name) {
    uint8_t* b = (uint8_t*)(uintptr_t)base;
    IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(b + ((IMAGE_DOS_HEADER*)b)->e_lfanew);
    IMAGE_DATA_DIRECTORY dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dd.VirtualAddress) return 0;
    IMAGE_EXPORT_DIRECTORY* e = (IMAGE_EXPORT_DIRECTORY*)(b + dd.VirtualAddress);
    uint32_t* funcs = (uint32_t*)(b + e->AddressOfFunctions);
    uint32_t* names = (uint32_t*)(b + e->AddressOfNames);
    uint16_t* ords = (uint16_t*)(b + e->AddressOfNameOrdinals);
    uint32_t idx = 0xFFFFFFFFu;
    if ((uintptr_t)name < 0x10000) idx = (uint32_t)(uintptr_t)name - e->Base;
    else
        for (uint32_t i = 0; i < e->NumberOfNames; i++)
            if (!strcmp((const char*)(b + names[i]), name)) { idx = ords[i]; break; }
    return idx < e->NumberOfFunctions && funcs[idx] ? base + funcs[idx] : 0;
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

static uint32_t g_native_target;

/* Synthetic VAs for hand shims: a reserved, never-committed range, so no real
 * code or data can share an address with one. */
static uint32_t g_shim_page;
static native32_shim_t* g_shims;
static int g_nshims;
#define IS_SHIM_VA(va) (g_shim_page && (va) >= g_shim_page && (va) < g_shim_page + 0x10000u)

static void native_bridge(void) {
    /* The guest's last error, as the previous native call left it: the trace
     * below and mach_leave's TlsGetValue would reset it before this call. */
    DWORD guest_error = GetLastError();
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
    SetLastError(guest_error);
    /* The locals are reached through whatever base register the compiler
     * chose, and the asm must leave it alone. MSVC uses ebp; clang-cl uses
     * esi (its x86 base pointer, for a frame it realigns), so the old
     * `mov esi, src` for rep movsd cut the frame off and the next local read
     * was garbage: the first native call jumped to 0 (KotOR, clang-cl). So:
     * no esi or ebp, every input in a register before esp moves, and the
     * arguments copied by pushes, highest slot first.
     *
     * Nor does the callee have to keep the C ABI. It is usually Windows, but
     * it can be the guest's own hand-written asm, run natively because no lift
     * can hold it (code in a data section, a native module), and that was
     * only ever called from inline asm that saved everything: UT's Fire.dll
     * returns with ebx and ebp changed. So ebp, esi and ebx are saved on the
     * stack, and the esp anchor is kept in this thread's TEB
     * (ArbitraryUserPointer, fs:[0x14], its old value saved and put back, so a
     * nested bridge through a callback unwinds in order). */
    __asm {
        fnstsw ax
        mov  sw0, ax             ; x87 TOP before
        mov  edx, src
        mov  eax, fn
        mov  edi, this_ecx
        push ebp
        push esi
        push ebx
        push dword ptr fs:[0x14]
        mov  ecx, BRIDGE_SLOTS
    copy_args:
        push dword ptr [edx + ecx * 4 - 4]
        dec  ecx
        jnz  copy_args
        mov  fs:[0x14], esp      ; the anchor: survives any callee
        mov  ecx, edi            ; thiscall / COM 'this'
        call eax
        mov  ecx, esp
        mov  esp, fs:[0x14]
        sub  ecx, esp            ; bytes the callee popped
        add  esp, BRIDGE_SLOTS * 4
        pop  dword ptr fs:[0x14]
        pop  ebx
        pop  esi
        pop  ebp                 ; the frame is reachable again
        mov  r_eax, eax
        mov  r_edx, edx
        mov  purge, ecx
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
    /* The callee's last error belongs to the guest, but mach_enter's
     * TlsGetValue resets it to 0 (TlsGetValue always does), and so does
     * stdio. A guest that loops on FindNextFileA until GetLastError() says
     * ERROR_NO_MORE_FILES then never stopped (KotOR's resource scan): the
     * value has to survive both ways across the bridge, into GetLastError
     * itself and back out of FindNextFileA. */
    DWORD last_error = GetLastError();
    mach_enter();
    if (st_ret) fp_push_impl(g_st, &g_fp_top, r_st);
    g_cur_import = saved_import;
    g_eax = r_eax;
    g_edx = r_edx;
    g_esp += 4 + purge;
    if (native32_trace_native) fprintf(stderr, " -> %08X\n", r_eax);
    SetLastError(last_error);
}

static recomp_func_t dispatch_find(uint32_t va) {
    uint32_t lo = 0, hi = recomp_dispatch_count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2, m = recomp_dispatch_table[mid].address;
        if (m == va) return recomp_dispatch_table[mid].func;
        if (m < va) lo = mid + 1; else hi = mid;
    }
    return NULL;
}

recomp_func_t recomp_lookup(uint32_t va) {
    if (native_module_at(va)) return NULL;    /* its original code runs: recomp_lookup_import */
    return dispatch_find(va);
}

/* ------------------------------------------------ code the guest generates
 *
 * A guest that writes machine code at run time (SimCity 4's software
 * renderer compiles its span loops into a VirtualAlloc'd PAGE_EXECUTE_READWRITE
 * buffer, 0x008EC050) cannot have it lifted. It runs natively, but not
 * through native_bridge: that one is for the C ABI (stack arguments, ecx),
 * and generated code takes its inputs wherever the generator put them --
 * esi/edi/ebp pointers and MMX registers set up by the hand-written caller
 * (0x008DD8B0). Through native_bridge it read 0 for each. So these calls get
 * the whole register file, on the guest's stack, the way the original call
 * instruction would have left it. */
/* gen_bridge calls in flight with the TEB's stack bounds widened (cb_tramp). */
static volatile LONG g_teb_widened;

#define MAX_GEN 64
static struct { uint32_t lo, hi; int x87; } g_gen[MAX_GEN];
static volatile LONG g_gen_n;

/* 1: generated (MMX registers carried), 2: an x87 range, 0: neither. */
static int gen_kind(uint32_t va) {
    LONG n = g_gen_n < MAX_GEN ? g_gen_n : MAX_GEN;
    for (LONG i = 0; i < n; i++)
        if (va >= g_gen[i].lo && va < g_gen[i].hi) return g_gen[i].x87 ? 2 : 1;
    return 0;
}

int native32_is_generated(uint32_t va) { return gen_kind(va) != 0; }

static void add_generated(uint32_t lo, uint32_t size, int x87);
void native32_add_generated(uint32_t lo, uint32_t size) { add_generated(lo, size, 0); }
void native32_add_guest_abi(uint32_t lo, uint32_t size) { add_generated(lo, size, 1); }

static void add_generated(uint32_t lo, uint32_t size, int x87) {
    if (!size || (native32_is_generated(lo) && native32_is_generated(lo + size - 1))) return;
    LONG i = InterlockedIncrement(&g_gen_n) - 1;
    if (i >= MAX_GEN) {
        InterlockedDecrement(&g_gen_n);
        fprintf(stderr, "[native32] more than %d generated-code ranges: 0x%08X+0x%X not added\n", MAX_GEN, lo, size);
        return;
    }
    g_gen[i].hi = lo + size;
    g_gen[i].x87 = x87;
    g_gen[i].lo = lo;
    if (getenv("NATIVE32_LOG_THREADS") || native32_trace_native)
        fprintf(stderr, "[native32] generated code at 0x%08X+0x%X runs natively\n", lo, size);
}

/* Field offsets are used by the asm below: fn, in[8], mm, out[8], sw[2]. */
typedef struct {
    uint32_t fn;
    uint32_t in[8];     /* eax ecx edx ebx esp ebp esi edi; esp already past the dummy ret */
    uint32_t mm;        /* &g_mm, or 0 for an x87 range (native32_add_guest_abi) */
    uint32_t out[8];
    uint32_t sw[2];     /* x87 range: the status word before the call and after it */
    uint32_t lim[2];    /* x87 range: the TEB's StackBase and StackLimit, put back after */
    uint32_t fl;        /* EFLAGS as the callee left them */
} gen_ctx_t;

/* Entered by `call` on the guest's stack with edi = the context: loads the
 * guest registers and returns into the target, so the target finds its
 * return address at [esp], exactly where the original call put it. */
static __declspec(naked) void gen_enter(void) {
    __asm {
        push dword ptr [edi]
        mov  eax, [edi + 4]
        mov  ecx, [edi + 8]
        mov  edx, [edi + 12]
        mov  ebx, [edi + 16]
        mov  ebp, [edi + 24]
        mov  esi, [edi + 28]
        mov  edi, [edi + 32]
        ret
    }
}

static void gen_bridge(void) {
    gen_ctx_t c;
    gen_ctx_t* cp = &c;
    const char* saved_import = g_cur_import;
    c.fn = g_native_target;
    c.in[0] = g_eax; c.in[1] = g_ecx; c.in[2] = g_edx; c.in[3] = g_ebx;
    c.in[4] = g_esp + 4; c.in[5] = g_ebp; c.in[6] = g_esi; c.in[7] = g_edi;
    /* An x87 range is a compiled runtime (CA-Visual Objects' CAVORT20) that
     * computes on the real x87 and returns doubles in st(0), like any C
     * function: loading the MMX registers set every x87 tag valid, so its
     * first fld overflowed the stack and VO's FLOAT conversion raised
     * NUMERIC OVERFLOW on -1.#I. Its MMX state is not carried, and an st(0)
     * result is moved onto the lifted FPU stack, as native_bridge does. */
    int x87 = gen_kind(c.fn) == 2;
    double r_st = 0;
    /* Its exception handling runs on the guest stack too: a compiled runtime
     * calls Windows, and Windows' own __try frames (RPC inside the print
     * spooler raising 0x6BA, Retail Plus Lite's startup) are then on the
     * guest stack, outside the TEB's StackBase..StackLimit, and the
     * dispatcher calls such a chain invalid and ends the process. So for the
     * call the TEB's bounds cover the guest stack as well. cb_tramp tells
     * the guest stack apart by the guest TIB, not by these. */
    NT_TIB* tib = (NT_TIB*)NtCurrentTeb();
    c.lim[0] = (uint32_t)(uintptr_t)tib->StackBase;
    c.lim[1] = (uint32_t)(uintptr_t)tib->StackLimit;
    int widened = x87 && g_fs_base;
    if (widened) {
        uint32_t gb = MEM32(g_fs_base + 4), gl = MEM32(g_fs_base + 8);
        g_teb_widened++;
        if (gb > c.lim[0]) tib->StackBase = (PVOID)(uintptr_t)gb;
        if (gl && gl < c.lim[1]) tib->StackLimit = (PVOID)(uintptr_t)gl;
    }
    c.mm = x87 ? 0 : (uint32_t)(uintptr_t)g_mm;
    if (native32_trace_native)
        fprintf(stderr, "[native] generated code @%08X from sub_%08X (esi %08X edi %08X ebp %08X)\n",
                c.fn, g_cur_func, g_esi, g_edi, g_ebp);
    g_cur_import = "(generated code)";
    /* As in native_bridge: the context pointer is in a register before esp
     * moves, every host register the compiler may rely on is saved, and the
     * anchor back to this frame is the TEB's ArbitraryUserPointer. The machine
     * lock stays held: this is guest code. */
    __asm {
        mov  eax, cp
        push edi
        push ebp
        push esi
        push ebx
        push eax                     ; the context, for after the call
        push dword ptr fs:[0x14]
        mov  fs:[0x14], esp
        mov  edi, eax
        mov  eax, [edi + 36]
        test eax, eax
        jnz  load_mm
        fnstsw ax
        mov  [edi + 72], eax         ; x87 TOP before
        jmp  gen_go
    load_mm:
        movq mm0, qword ptr [eax]
        movq mm1, qword ptr [eax + 8]
        movq mm2, qword ptr [eax + 16]
        movq mm3, qword ptr [eax + 24]
        movq mm4, qword ptr [eax + 32]
        movq mm5, qword ptr [eax + 40]
        movq mm6, qword ptr [eax + 48]
        movq mm7, qword ptr [eax + 56]
    gen_go:
        mov  esp, [edi + 20]         ; the guest's stack
        call gen_enter
        push eax
        mov  eax, fs:[0x14]
        mov  eax, [eax + 4]          ; the context
        pushfd                       ; nothing above wrote the flags
        pop  dword ptr [eax + 88]
        mov  [eax + 44], ecx
        mov  [eax + 48], edx
        mov  [eax + 52], ebx
        mov  [eax + 60], ebp
        mov  [eax + 64], esi
        mov  [eax + 68], edi
        pop  ecx
        mov  [eax + 40], ecx
        mov  [eax + 56], esp
        mov  ecx, [eax + 36]
        test ecx, ecx
        jnz  save_mm
        mov  ecx, eax
        fxam                         ; C3..C0 classify st(0)
        fnstsw ax
        mov  [ecx + 76], eax         ; x87 TOP after
        jmp  gen_done
    save_mm:
        movq qword ptr [ecx], mm0
        movq qword ptr [ecx + 8], mm1
        movq qword ptr [ecx + 16], mm2
        movq qword ptr [ecx + 24], mm3
        movq qword ptr [ecx + 32], mm4
        movq qword ptr [ecx + 40], mm5
        movq qword ptr [ecx + 48], mm6
        movq qword ptr [ecx + 56], mm7
        emms                         ; the host's x87 is usable again
    gen_done:
        mov  esp, fs:[0x14]
        pop  dword ptr fs:[0x14]
        add  esp, 4
        pop  ebx
        pop  esi
        pop  ebp
        pop  edi
    }
    tib->StackBase = (PVOID)(uintptr_t)c.lim[0];
    tib->StackLimit = (PVOID)(uintptr_t)c.lim[1];
    if (widened) g_teb_widened--;
    /* A runtime helper can answer in the flags: VO's string compare _CPSE is
     * `call _CPSE; jne ...`, and the lifted caller reads the flags back after
     * the call (RECOMP_FLAGS_IN). Left stale, Retail Plus Lite's ".DBF"
     * extension check failed and every inventory was "not a DBF file". */
    if (x87) {
        g_flag_k = FK_EFLAGS;
        g_flag_a = c.fl;
    }
    if (x87) {
        uint16_t sw0 = (uint16_t)c.sw[0], sw1 = (uint16_t)c.sw[1];
        if ((((sw0 >> 11) - (sw1 >> 11)) & 7) == 1 && (sw1 & 0x4100) != 0x4100) {
            __asm fstp r_st
            fp_push_impl(g_st, &g_fp_top, r_st);
        }
    }
    g_eax = c.out[0]; g_ecx = c.out[1]; g_edx = c.out[2]; g_ebx = c.out[3];
    g_esp = c.out[4]; g_ebp = c.out[5]; g_esi = c.out[6]; g_edi = c.out[7];
    if (native32_trace_native) fprintf(stderr, "[native]   -> eax %08X edx %08X esp %08X\n", g_eax, g_edx, g_esp);
    g_cur_import = saved_import;
}

/* Anything that is neither a shim nor inside a guest module is native: an
 * import, a GetProcAddress result, a COM method. */
recomp_func_t recomp_lookup_import(uint32_t va) {
    if (IS_SHIM_VA(va)) {
        for (int i = 0; i < g_nshims; i++)
            if (g_shims[i].va == va) return g_shims[i].fn;
        return NULL;
    }
    if (va < 0x10000u) return NULL;
    if (native32_in_guest(va) && !native_module_at(va) && !data_section_code(va)) return NULL;
    g_native_target = va;
    return native32_is_generated(va) ? gen_bridge : native_bridge;
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
    if (getenv("NATIVE32_LOG_THREADS"))
        fprintf(stderr, "[thread] %lu creates %lu at 0x%08X\n", GetCurrentThreadId(), GetThreadId(h), a[2]);
    g_esp += 4 + 6 * 4;
}

/* TerminateThread on a guest thread (see g_doomed). The caller holds the
 * machine lock, so the target is not running lifted code: it is waiting for
 * the lock, or inside a native call. Mark it, give up the lock for a moment,
 * and it exits by itself as soon as it reaches the lock. Only a thread still
 * inside a native call after that is terminated for real -- it is not waiting
 * on the lock, and anything that reaches mach_enter from now on exits there. */
static void shim_TerminateThread(void) {
    uint32_t* a = (uint32_t*)(uintptr_t)(g_esp + 4);
    HANDLE h = (HANDLE)(uintptr_t)a[0];
    DWORD code = a[1], tid = GetThreadId(h);
    g_esp += 4 + 2 * 4;
    if (tid == GetCurrentThreadId()) { mach_leave(); ExitThread(code); }
    int k = tid ? tslot(tid, 0) : -1;
    if (k >= 0) {
        g_tcode[k] = (LONG)code;
        InterlockedExchange(&g_tdoom[k], 1);
        if (InterlockedCompareExchange(&g_tstate[k], 0, 0) == T_WAITING) {
            /* It gets the lock when we give it up, and exits there. Give up
             * every claim: a TerminateThread inside a window procedure (the
             * movie player's, on WM_DESTROY) holds the lock twice, and
             * releasing it once left the waiter waiting forever. */
            mstate* m = (mstate*)TlsGetValue(g_mach_tls);
            int d = m->depth;
            m->depth = 1;
            mach_leave();
            for (int i = 1; i < d; i++) LeaveCriticalSection(&g_mach);
            WaitForSingleObject(h, INFINITE);
            mach_enter();
            for (int i = 1; i < d; i++) EnterCriticalSection(&g_mach);
            m->depth = d;
            if (getenv("NATIVE32_LOG_THREADS"))
                fprintf(stderr, "[thread] %lu exited at the lock\n", tid);
            g_eax = 1;
            return;
        }
    }
    /* In native code, not waiting, and it can no longer start to. */
    if (getenv("NATIVE32_LOG_THREADS"))
        fprintf(stderr, "[thread] %lu terminated in native code\n", tid);
    g_eax = (uint32_t)TerminateThread(h, code);
    if (k >= 0) {
        g_tdoom[k] = 0;
        InterlockedExchange(&g_tstate[k], T_FREE);
        InterlockedExchange(&g_tid[k], 0);
    }
}

/* RaiseException(0x406D1388): MSVC's SetThreadName, which only an attached
 * debugger is meant to see. The guest wraps it in
 *     __try { RaiseException(0x406D1388, ...); } __except (EXCEPTION_EXECUTE_HANDLER) {}
 * but its __try frame is on the guest's SEH chain, which Windows never walks
 * (eh32.c handles C++ frames only), so the exception went unhandled and ended
 * the process with that code: Tiberium Wars, naming its first worker thread.
 * Returning is what the empty __except does. Any other code is raised for real. */
/* VirtualProtect: a guest may make its own code writable, never executable.
 * Old self-modifying code asks for PAGE_EXECUTE_READWRITE on its code
 * section before patching it (POD's blitter, at start). Granted as asked,
 * that undoes native32_map, and the next time Windows calls into the guest
 * (a thread start, a window procedure) the original machine code runs
 * natively instead of the lift. So on a lifted module's code the execute
 * bit is dropped; the old protection reported back is what was really
 * there. Modules set native (native32_set_native) get what they ask for. */
static void shim_VirtualProtect(void) {
    uint32_t* a = (uint32_t*)(uintptr_t)(g_esp + 4);
    uint32_t lo = a[0], hi = a[0] + a[1];
    DWORD prot = a[2];
    for (int i = 0; i < g_mod_n; i++) {
        uint32_t base = g_mods[i].base;
        if (g_mods[i].native || hi <= base || lo >= base + g_mods[i].span) continue;
        IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(uintptr_t)(base + ((IMAGE_DOS_HEADER*)(uintptr_t)base)->e_lfanew);
        IMAGE_SECTION_HEADER* s = IMAGE_FIRST_SECTION(nt);
        for (int k = 0; k < nt->FileHeader.NumberOfSections; k++, s++) {
            uint32_t slo = base + s->VirtualAddress, shi = slo + sec_size(s);
            if (!(s->Characteristics & IMAGE_SCN_MEM_EXECUTE) || hi <= slo || lo >= shi) continue;
            DWORD was = prot;
            prot = prot == PAGE_EXECUTE_READWRITE ? PAGE_READWRITE :
                   prot == PAGE_EXECUTE_WRITECOPY ? PAGE_WRITECOPY :
                   prot == PAGE_EXECUTE_READ || prot == PAGE_EXECUTE ? PAGE_READONLY : prot;
            if (prot != was && getenv("NATIVE32_LOG_THREADS"))
                fprintf(stderr, "[native32] VirtualProtect(0x%08X, 0x%X, %08lX) on lifted code: %08lX\n",
                        a[0], a[1], was, prot);
        }
    }
    g_eax = VirtualProtect((void*)(uintptr_t)a[0], a[1], prot, (PDWORD)(uintptr_t)a[3]);
    if (g_eax && (prot & 0xF0) && !native32_in_guest(lo))   /* PAGE_EXECUTE*: code it wrote */
        native32_add_generated(lo, a[1]);
    g_esp += 4 + 4 * 4;
}

/* VirtualAlloc with an execute protection outside the guest's modules is a
 * buffer for code the guest is about to write: calls into it run natively,
 * with the guest's registers (gen_bridge). */
static void shim_VirtualAlloc(void) {
    uint32_t* a = (uint32_t*)(uintptr_t)(g_esp + 4);
    g_eax = (uint32_t)(uintptr_t)VirtualAlloc((void*)(uintptr_t)a[0], a[1], a[2], a[3]);
    if (g_eax && (a[3] & 0xF0)) native32_add_generated(g_eax, a[1]);
    g_esp += 4 + 4 * 4;
}

/* VirtualQuery on a lifted module reports what Windows would for a loaded
 * image: MEM_IMAGE, allocated at the module's base. native32_map commits the
 * image as private memory, and VC8+ CRTs check before they trust an
 * exception registration: _ValidateEH3RN only runs a __try's scope table
 * when VirtualQuery says the table is in an image, and otherwise declines
 * the exception, so every __except was skipped. */
static void shim_VirtualQuery(void) {
    uint32_t* a = (uint32_t*)(uintptr_t)(g_esp + 4);
    MEMORY_BASIC_INFORMATION* m = (MEMORY_BASIC_INFORMATION*)(uintptr_t)a[1];
    g_eax = (uint32_t)VirtualQuery((void*)(uintptr_t)a[0], m, a[2]);
    for (int i = 0; g_eax >= sizeof *m && i < g_mod_n; i++)
        if (!g_mods[i].native && a[0] - g_mods[i].base < g_mods[i].span) {
            m->AllocationBase = (void*)(uintptr_t)g_mods[i].base;
            m->Type = MEM_IMAGE;
        }
    g_esp += 4 + 3 * 4;
}

/* With native32_guest_seh, any other code goes to the guest's own SEH chain
 * first (seh32.c), and is raised for real only if no guest frame takes it. */
#include "seh32.c"

/* A C++ throw from a statically linked CRT goes to eh32's dispatch first
 * (native32_cxx_raise returns only if nothing in the guest catches it). */
int native32_cxx_raise(uint32_t n, uint32_t args);

static void shim_RaiseException(void) {
    uint32_t* a = (uint32_t*)(uintptr_t)(g_esp + 4);
    if (a[0] == 0xE06D7363u) native32_cxx_raise(a[2], a[3]);
    if (a[0] != 0x406D1388u && !(native32_guest_seh && seh_dispatch(a[0], a[1], a[2], a[3])))
        RaiseException(a[0], a[1], a[2], (const ULONG_PTR*)(uintptr_t)a[3]);
    g_esp += 4 + 4 * 4;
}

/* DirectInputCreateA/W/Ex and DirectInput8Create check that their HINSTANCE
 * is a module Windows loaded; a mapped guest image is not one, and they fail
 * with E_INVALIDARG (KotOR, Messiah, Shogo). The host's own instance stands
 * in for a guest one. Stack arguments: (hinst, version, ...) up to 5 dwords. */
/* IDirectInput(A/W)::EnumDevices for every device type (0) also walks the
 * "other" HID devices (DIDEVTYPE_DEVICE, 1), and on Windows 11 with some
 * vendor-defined HID collections (RGB keyboards, headsets) that walk
 * corrupts the process heap inside dinput.dll: a plain C program dies the
 * same way, so no game gets past it. The mouse, keyboard and joystick walks
 * are fine. So an all-types request becomes those three, in that order, and
 * the "other" devices (nothing a 1990s game drives) are left out. KISS Psycho
 * Circus (LithTech 2) enumerates everything at start-up.
 * ponytail: the interface DirectInputCreate returned only; an IDirectInput2/7
 * from QueryInterface has its own vtable and is not wrapped. */
typedef HRESULT (WINAPI *di_enum_t)(void*, DWORD, void*, void*, DWORD);
typedef BOOL (WINAPI *di_cb_t)(const void*, void*);
static di_enum_t g_di_enum[2];        /* the real EnumDevices, A and W */
typedef struct { di_cb_t cb; void* ref; int stop; } di_split_t;
static BOOL WINAPI di_split_cb(const void* ddi, void* ctx) {
    di_split_t* s = (di_split_t*)ctx;
    BOOL r = s->cb(ddi, s->ref);      /* a guest callback: runs lifted, through the trampoline */
    if (!r) s->stop = 1;
    return r;
}
static HRESULT di_enum_split(int w, void* self, DWORD type, void* cb, void* ref, DWORD flags) {
    if (type & 0xFF) return g_di_enum[w](self, type, cb, ref, flags);
    di_split_t s = { (di_cb_t)cb, ref, 0 };
    static const DWORD types[3] = { 2, 3, 4 };   /* DIDEVTYPE_MOUSE, _KEYBOARD, _JOYSTICK */
    HRESULT hr = 0;
    for (int i = 0; i < 3 && !s.stop && hr >= 0; i++)
        hr = g_di_enum[w](self, types[i] | (type & ~0xFFu), (void*)di_split_cb, &s, flags);
    return hr;
}
static HRESULT WINAPI di_enum_a(void* self, DWORD t, void* cb, void* ref, DWORD f) { return di_enum_split(0, self, t, cb, ref, f); }
static HRESULT WINAPI di_enum_w(void* self, DWORD t, void* cb, void* ref, DWORD f) { return di_enum_split(1, self, t, cb, ref, f); }
/* The slot is patched in dinput's own vtable, not swapped for a copy in the
 * object: dinput tells its interfaces apart by their vtable pointer, and an
 * object with a copied one crashed in its own Release. */
static void di_wrap(void*** obj, int w) {
    void* mine = (void*)(w ? di_enum_w : di_enum_a);
    DWORD old;
    if (!obj || !*obj || (*obj)[4] == mine) return;
    if (!g_di_enum[w]) g_di_enum[w] = (di_enum_t)(*obj)[4];
    if ((*obj)[4] != (void*)g_di_enum[w]) return;     /* another vtable: not ours to patch */
    if (VirtualProtect(&(*obj)[4], sizeof(void*), PAGE_READWRITE, &old)) {
        (*obj)[4] = mine;
        VirtualProtect(&(*obj)[4], sizeof(void*), old, &old);
    }
}

static void di_wrap_devices(void*** di, int w);   /* dinput32.c */
static void dinput_create(const char* name, int nargs) {
    static FARPROC real[4];
    static const char* names[4] = { "DirectInputCreateA", "DirectInputCreateW", "DirectInputCreateEx",
                                    "DirectInput8Create" };
    uint32_t* a = (uint32_t*)(uintptr_t)(g_esp + 4);
    int k = 0;
    while (strcmp(names[k], name)) k++;
    if (!real[k]) real[k] = GetProcAddress(LoadLibraryA(k == 3 ? "dinput8.dll" : "dinput.dll"), name);
    uint32_t h = native32_in_guest(a[0]) ? (uint32_t)(uintptr_t)GetModuleHandleA(NULL) : a[0];
    typedef uint32_t (WINAPI *f4_t)(uint32_t, uint32_t, uint32_t, uint32_t);
    typedef uint32_t (WINAPI *f5_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
    g_eax = !real[k] ? 0x80004005u : nargs == 4 ? ((f4_t)real[k])(h, a[1], a[2], a[3])
                                                : ((f5_t)real[k])(h, a[1], a[2], a[3], a[4]);
    if (k < 2 && g_eax == 0 && a[2]) {
        di_wrap((void***)(uintptr_t)MEM32(a[2]), k);
        di_wrap_devices((void***)(uintptr_t)MEM32(a[2]), k);
    }
    g_esp += 4 + 4 * nargs;
}
static void shim_DirectInputCreateA(void) { dinput_create("DirectInputCreateA", 4); }
static void shim_DirectInputCreateW(void) { dinput_create("DirectInputCreateW", 4); }
static void shim_DirectInputCreateEx(void) { dinput_create("DirectInputCreateEx", 5); }
static void shim_DirectInput8Create(void) { dinput_create("DirectInput8Create", 5); }

/* DirectDraw as a 1999 game expects it, on a Windows that differs:
 *
 * - IDirectDraw4/7::GetDeviceIdentifier(DDGDI_GETHOSTIDENTIFIER) answers
 *   DDERR_NOTFOUND on Windows 10/11, and on native32_headless's private
 *   desktop it fails without the flag too. Sim Theme Park takes that as "no
 *   DirectDraw" and quits. A failed host query is asked again without the
 *   flag, and if that fails as well the guest gets an identifier with no
 *   vendor, which games treat as an unknown card.
 * - On a desktop with no display driver behind it (native32_headless) there
 *   is no HAL, so a surface asked for in video memory fails with
 *   DDERR_NOHAL / DDERR_NODIRECTDRAWHW. It is made again in system memory,
 *   where DirectDraw's emulation and Direct3D's software rasterisers work.
 *
 * Patched in ddraw's own vtables, as di_wrap does (interfaces are told apart
 * by vtable pointer), the first time the guest creates DirectDraw. */
typedef HRESULT (WINAPI *dd_ident_t)(void*, void*, DWORD);
typedef HRESULT (WINAPI *dd_create_t)(void*, void*, void**, void*);
static dd_ident_t g_dd_ident[4];
static dd_create_t g_dd_surf[4];
static HRESULT WINAPI dd_ident(int k, void* self, void* out, DWORD flags) {
    HRESULT hr = g_dd_ident[k](self, out, flags);
    if (hr < 0 && (flags & 1)) hr = g_dd_ident[k](self, out, flags & ~1u);
    if (hr == (HRESULT)0x887600FFu && out) {
        /* DDDEVICEIDENTIFIER: 1024 bytes of names, then 8 + 4*4 + 16; the 7
         * version adds a DWORD. */
        memset(out, 0, 1024 + 8 + 16 + 16 + (k == 3 ? 4 : 0));
        strcpy((char*)out, "display");
        strcpy((char*)out + 512, "Display adapter");
        hr = 0;
    }
    return hr;
}
typedef HRESULT (WINAPI *dd_blt_t)(void*, RECT*, void*, RECT*, DWORD, void*);
typedef HRESULT (WINAPI *dd_flip_t)(void*, void*, DWORD);
static dd_blt_t g_dd_blt[4];
static dd_flip_t g_dd_flip[4];
static void* g_dd_primary[4];
static void* g_dd_blt_mine[4];
static void* g_dd_flip_mine[4];
static void dd_patch(void** slot, void* mine, void** real);
static HRESULT WINAPI dd_surf(int k, void* self, void* desc, void** out, void* outer) {
    HRESULT hr = g_dd_surf[k](self, desc, out, outer);
    DWORD* caps = desc ? (DWORD*)((uint8_t*)desc + 0x68) : NULL;   /* ddsCaps, both desc sizes */
    if ((hr == (HRESULT)0x88760233u || hr == (HRESULT)0x887600FAu) && caps && (*caps & 0x4000)) {
        DWORD was = *caps;
        *caps = (was & ~(0x4000u | 0x10000000u | 0x08000000u)) | 0x800;   /* VIDEOMEMORY -> SYSTEMMEMORY */
        hr = g_dd_surf[k](self, desc, out, outer);
        *caps = was;
    }
    if (hr >= 0 && caps && (*caps & 0x200) && out && *out) {      /* DDSCAPS_PRIMARYSURFACE */
        g_dd_primary[k] = *out;
        dd_patch(&(*(void***)*out)[5], g_dd_blt_mine[k], (void**)&g_dd_blt[k]);    /* Blt */
        dd_patch(&(*(void***)*out)[11], g_dd_flip_mine[k], (void**)&g_dd_flip[k]); /* Flip */
    }
    return hr;
}

/* native32_on_present: the guest's frames as it shows them. A blit to the
 * primary surface (a windowed game) hands the callback its source, a Flip
 * the primary after the flip. A host saves screenshots and recordings from
 * there: on native32_headless's private desktop a GDI copy of the window
 * is black. */
static void (*g_present_cb)(void* surface, int version);
void native32_on_present(void (*cb)(void* surface, int version)) { g_present_cb = cb; }
static const int g_dd_surf_ver[4] = { 1, 1, 4, 7 };
static HRESULT WINAPI dd_blt(int k, void* self, RECT* dr, void* src, RECT* sr, DWORD f, void* fx) {
    if (g_present_cb && src && self == g_dd_primary[k]) g_present_cb(src, g_dd_surf_ver[k]);
    return g_dd_blt[k](self, dr, src, sr, f, fx);
}
static HRESULT WINAPI dd_flip(int k, void* self, void* to, DWORD f) {
    HRESULT hr = g_dd_flip[k](self, to, f);
    if (g_present_cb && hr >= 0 && self == g_dd_primary[k]) g_present_cb(self, g_dd_surf_ver[k]);
    return hr;
}
#define DD_SURF_HOOKS(n, k) \
    static HRESULT WINAPI dd_blt##n(void* s, RECT* d, void* o, RECT* r, DWORD f, void* x) { return dd_blt(k, s, d, o, r, f, x); } \
    static HRESULT WINAPI dd_flip##n(void* s, void* t, DWORD f) { return dd_flip(k, s, t, f); }
DD_SURF_HOOKS(1, 0) DD_SURF_HOOKS(2, 1) DD_SURF_HOOKS(4, 2) DD_SURF_HOOKS(7, 3)
static void* g_dd_blt_mine[4] = { (void*)dd_blt1, (void*)dd_blt2, (void*)dd_blt4, (void*)dd_blt7 };
static void* g_dd_flip_mine[4] = { (void*)dd_flip1, (void*)dd_flip2, (void*)dd_flip4, (void*)dd_flip7 };
static HRESULT WINAPI dd_ident4(void* s, void* o, DWORD f) { return dd_ident(2, s, o, f); }
static HRESULT WINAPI dd_ident7(void* s, void* o, DWORD f) { return dd_ident(3, s, o, f); }
static HRESULT WINAPI dd_surf1(void* s, void* d, void** o, void* u) { return dd_surf(0, s, d, o, u); }
static HRESULT WINAPI dd_surf2(void* s, void* d, void** o, void* u) { return dd_surf(1, s, d, o, u); }
static HRESULT WINAPI dd_surf4(void* s, void* d, void** o, void* u) { return dd_surf(2, s, d, o, u); }
static HRESULT WINAPI dd_surf7(void* s, void* d, void** o, void* u) { return dd_surf(3, s, d, o, u); }

static void dd_patch(void** slot, void* mine, void** real) {
    DWORD old;
    if (*slot == mine || (*real && *slot != *real)) return;   /* done, or a vtable not ours */
    if (VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &old)) {
        *real = *slot;
        *slot = mine;
        VirtualProtect(slot, sizeof(void*), old, &old);
    }
}

static const GUID g_dd_iid[4] = {
    { 0x6c14db80, 0xa733, 0x11ce, { 0xa5, 0x21, 0x00, 0x20, 0xaf, 0x0b, 0xe5, 0x60 } },   /* IDirectDraw */
    { 0xb3a6f3e0, 0x2b43, 0x11cf, { 0xa2, 0xde, 0x00, 0xaa, 0x00, 0xb9, 0x33, 0x56 } },   /* IDirectDraw2 */
    { 0x9c59509a, 0x39bd, 0x11d1, { 0x8c, 0x4a, 0x00, 0xc0, 0x4f, 0xd9, 0x30, 0xc5 } },   /* IDirectDraw4 */
    { 0x15e65ec0, 0x3b9c, 0x11d2, { 0xb9, 0x2f, 0x00, 0x60, 0x97, 0x97, 0xea, 0x5b } },   /* IDirectDraw7 */
};
typedef HRESULT (WINAPI *dd_qi_t)(void*, const GUID*, void**);
static dd_qi_t g_dd_qi[4];
static void dd_fix(void*** obj, int k);
/* Windows' own DirectDraw compatibility shims hook CreateSurface again on
 * every QueryInterface, over a patch made before it; so each QI for a
 * DirectDraw interface re-applies ours to what it returns. */
static HRESULT WINAPI dd_qi(int k, void* self, const GUID* riid, void** out) {
    HRESULT hr = g_dd_qi[k](self, riid, out);
    for (int j = 0; hr >= 0 && out && *out && j < 4; j++)
        if (!memcmp(riid, &g_dd_iid[j], sizeof(GUID))) dd_fix((void***)*out, j);
    return hr;
}
static HRESULT WINAPI dd_qi1(void* s, const GUID* r, void** o) { return dd_qi(0, s, r, o); }
static HRESULT WINAPI dd_qi2(void* s, const GUID* r, void** o) { return dd_qi(1, s, r, o); }
static HRESULT WINAPI dd_qi4(void* s, const GUID* r, void** o) { return dd_qi(2, s, r, o); }
static HRESULT WINAPI dd_qi7(void* s, const GUID* r, void** o) { return dd_qi(3, s, r, o); }

static void dd_fix(void*** obj, int k) {
    void* qi[4] = { (void*)dd_qi1, (void*)dd_qi2, (void*)dd_qi4, (void*)dd_qi7 };
    void* surf[4] = { (void*)dd_surf1, (void*)dd_surf2, (void*)dd_surf4, (void*)dd_surf7 };
    void* ident[4] = { NULL, NULL, (void*)dd_ident4, (void*)dd_ident7 };
    dd_patch(&(*obj)[0], qi[k], (void**)&g_dd_qi[k]);                      /* QueryInterface */
    dd_patch(&(*obj)[6], surf[k], (void**)&g_dd_surf[k]);                  /* CreateSurface */
    if (ident[k]) dd_patch(&(*obj)[27], ident[k], (void**)&g_dd_ident[k]); /* GetDeviceIdentifier */
}

static void ddraw_create(const char* name, int nargs) {
    static FARPROC real[2];
    uint32_t* a = (uint32_t*)(uintptr_t)(g_esp + 4);
    int k = nargs == 4;                                 /* DirectDrawCreateEx */
    if (!real[k]) real[k] = GetProcAddress(LoadLibraryA("ddraw.dll"), name);
    typedef uint32_t (WINAPI *f3_t)(uint32_t, uint32_t, uint32_t);
    typedef uint32_t (WINAPI *f4_t)(uint32_t, uint32_t, uint32_t, uint32_t);
    g_eax = !real[k] ? 0x80004005u : k ? ((f4_t)real[k])(a[0], a[1], a[2], a[3])
                                       : ((f3_t)real[k])(a[0], a[1], a[2]);
    if (g_eax == 0 && a[1] && MEM32(a[1])) dd_fix((void***)(uintptr_t)MEM32(a[1]), k ? 3 : 0);
    g_esp += 4 + 4 * nargs;
}
/* GetForegroundWindow: on native32_headless's private desktop nothing is in
 * the foreground (the foreground belongs to the user's desktop), so it
 * answers NULL, and a game that hands that to DirectSound's
 * SetCooperativeLevel gets E_INVALIDARG (Sim Theme Park then dereferences
 * the DirectSound it released). There the answer is this process's own
 * visible top-level window, which is what the game would be in front with. */
static BOOL CALLBACK fg_find(HWND w, LPARAM out) {
    DWORD pid;
    GetWindowThreadProcessId(w, &pid);
    if (pid == GetCurrentProcessId() && IsWindowVisible(w) && !GetWindow(w, GW_OWNER)) {
        *(HWND*)out = w;
        return FALSE;
    }
    return TRUE;
}
static void shim_GetForegroundWindow(void) {
    HWND w = GetForegroundWindow();
    if (!w && GetEnvironmentVariableA("NATIVE32_HEADLESS", NULL, 0)) EnumWindows(fg_find, (LPARAM)&w);
    g_eax = (uint32_t)(uintptr_t)w;
    g_esp += 4;
}

/* native32_input_*: synthetic DirectInput for a harness (dinput32.c). */
#include "dinput32.c"

static void shim_DirectDrawCreate(void) { ddraw_create("DirectDrawCreate", 3); }
static void shim_DirectDrawCreateEx(void) { ddraw_create("DirectDrawCreateEx", 4); }

/* _CxxThrowException: a guest throw is dispatched over the guest's own
 * frames (eh32.c), so the guest's catch blocks run. */
void native32_shim_CxxThrowException(void);

/* msvcrt helpers that take their arguments on the x87 stack (x87crt.c): the
 * bridge passes stack arguments only, and the lifted FPU stack is g_st. */
#define X87CRT(n) void native32_shim_##n(void);
X87CRT(ftol) X87CRT(CIsqrt) X87CRT(CIsin) X87CRT(CIcos) X87CRT(CItan) X87CRT(CIasin)
X87CRT(CIacos) X87CRT(CIatan) X87CRT(CIexp) X87CRT(CIlog) X87CRT(CIlog10) X87CRT(CIsinh)
X87CRT(CIcosh) X87CRT(CItanh) X87CRT(CIpow) X87CRT(CIfmod) X87CRT(CIatan2)
X87CRT(controlfp) X87CRT(control87)

/* native32_set_codepage: the guest's ANSI code page (codepage.c). */
#include "codepage.c"

/* native32_registry: the guest's own registry subtrees, from a .reg file. */
#include "reg32.c"

static native32_shim_t g_builtin[] = {
    { "CreateThread", shim_CreateThread },
    { "RaiseException", shim_RaiseException },
    { "RtlUnwind", shim_RtlUnwind },
    { "TerminateThread", shim_TerminateThread },
    { "VirtualProtect", shim_VirtualProtect },
    { "VirtualAlloc", shim_VirtualAlloc },
    { "DirectInputCreateA", shim_DirectInputCreateA }, { "DirectInputCreateW", shim_DirectInputCreateW },
    { "DirectInputCreateEx", shim_DirectInputCreateEx }, { "DirectInput8Create", shim_DirectInput8Create },
 { "DirectDrawCreate", shim_DirectDrawCreate },
    { "DirectDrawCreateEx", shim_DirectDrawCreateEx },
    { "GetForegroundWindow", shim_GetForegroundWindow },
    { "_CxxThrowException", native32_shim_CxxThrowException },
    { "_ftol", native32_shim_ftol },
    { "_CIsqrt", native32_shim_CIsqrt }, { "_CIsin", native32_shim_CIsin },
    { "_CIcos", native32_shim_CIcos }, { "_CItan", native32_shim_CItan },
    { "_CIasin", native32_shim_CIasin }, { "_CIacos", native32_shim_CIacos },
    { "_CIatan", native32_shim_CIatan }, { "_CIexp", native32_shim_CIexp },
    { "_CIlog", native32_shim_CIlog }, { "_CIlog10", native32_shim_CIlog10 },
    { "_CIsinh", native32_shim_CIsinh }, { "_CIcosh", native32_shim_CIcosh },
    { "_CItanh", native32_shim_CItanh }, { "_CIpow", native32_shim_CIpow },
    { "_CIfmod", native32_shim_CIfmod }, { "_CIatan2", native32_shim_CIatan2 },
    { "_controlfp", native32_shim_controlfp }, { "_control87", native32_shim_control87 },
};

int native32_bind(uint32_t base, native32_shim_t* shims, int nshims) {
    uint8_t* b = (uint8_t*)(uintptr_t)base;
    IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(b + ((IMAGE_DOS_HEADER*)b)->e_lfanew);
    IMAGE_DATA_DIRECTORY dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_IMPORT_DESCRIPTOR* d = (IMAGE_IMPORT_DESCRIPTOR*)(b + dd.VirtualAddress);
    int native = 0, shimmed = 0, guested = 0, missing = 0;
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
    /* Every entry gets its VA now, not only the ones this module imports: a
     * host binding several guest modules calls this once per module, each
     * call builds a new array and it replaces g_shims, so a VA set only on
     * the first module's copy was lost to the second, and the first module's
     * shimmed imports stopped resolving. Same array in, same VAs out. */
    for (int i = 0; i < n; i++) all[i].va = g_shim_page + 16 * i;
    shims = all;
    nshims = n;
    g_shims = shims;
    g_nshims = nshims;
    for (; dd.VirtualAddress && d->Name; d++) {
        const char* dll = (const char*)(b + d->Name);
        /* A guest module importing from another one (a game DLL calling back
         * into its engine EXE) binds to the guest's own exports: those VAs are
         * in the dispatch table. LoadLibrary would load the original binary as
         * native code, or fail. */
        uint32_t guest = native32_module(dll);
        /* Loaded at its first import the host did not shim: a DLL every one
         * of whose imports is shimmed (a host that stubs a whole library out)
         * is never loaded, so its DllMain never runs. */
        HMODULE h = NULL;
        uint32_t* ilt = (uint32_t*)(b + (d->OriginalFirstThunk ? d->OriginalFirstThunk : d->FirstThunk));
        uint32_t* iat = (uint32_t*)(b + d->FirstThunk);
        for (; *ilt; ilt++, iat++) {
            int by_ord = (*ilt & 0x80000000u) != 0;
            const char* nm = by_ord ? (const char*)(uintptr_t)(*ilt & 0xFFFF) : (const char*)(b + *ilt + 2);
            /* An import by ordinal is shimmed by "<dll>#<ordinal>", the DLL
             * named as the import table names it, in any case: there is no
             * name to match, and the same ordinal means different functions
             * in different DLLs. */
            char ordname[MAX_PATH + 8];
            if (by_ord) _snprintf(ordname, sizeof ordname, "%s#%u", dll, *ilt & 0xFFFF);
            uint32_t va = 0;
            for (int i = 0; !guest && !va && i < nshims; i++)
                if (by_ord ? !_stricmp(shims[i].name, ordname) : !strcmp(shims[i].name, nm)) {
                    va = shims[i].va;
                    shimmed++;
                }
            if (!va && !guest && !by_ord && (va = codepage_func(nm)) != 0) shimmed++;
            if (!va) {
                if (!guest && !h) h = LoadLibraryA(dll);
                va = guest ? native32_export(guest, nm)
                   : h ? (uint32_t)(uintptr_t)GetProcAddress(h, nm) : 0;
                if (va && guest) guested++;
                else if (va) native++;
                else {
                    fprintf(stderr, "[bind] %s!%s unresolved\n", dll,
                            by_ord ? strrchr(ordname, '#') : nm);
                    missing++;
                }
            }
            if (va) add_name(va, dll, by_ord ? strrchr(ordname, '#') : nm);
            *iat = va;
        }
    }
    fprintf(stderr, "[bind] 0x%08X: %d native, %d guest, %d shimmed, %d unresolved\n",
            base, native, guested, shimmed, missing);
    return missing;
}

/* ------------------------------------------------------- Windows -> guest */

/* Runs a lifted function for a native caller. `sp` points at the native
 * caller's [ret][args...]. Returns eax in the low half and edx in the high
 * half (a 64-bit result), and the bytes the callee popped in *purge, for
 * cb_tramp's variable `ret n`. edx used to carry the purge, so a callback's
 * edx never reached its caller: CA-Visual Objects returns a USUAL in
 * eax:edx (edx the type), and every method the runtime sent came back NIL
 * (Retail Plus Lite: DATA TYPE ERROR, NIL =>LOGIC, at APP:START). */
/* A callback from an x87 range (native32_add_guest_abi) takes the caller's
 * registers with it, as a call does: CA-Visual Objects' runtime calls
 * compiled code with values in eax/edx and the frame in ebp. The VEH stashes
 * them here (cb_tramp has only ecx free); cb_run loads them. */
static __declspec(thread) struct { int on; uint32_t r[6]; } t_cb_regs;

static uint64_t __cdecl cb_run(uint32_t va, uint32_t* sp, uint32_t ecx, uint32_t* purge_out) {
    recomp_func_t f = IS_SHIM_VA(va) ? recomp_lookup_import(va) : recomp_lookup(va);
    if (native32_trace_callbacks)
        fprintf(stderr, "[callback] sub_%08X (%08X %08X %08X %08X)\n", va, sp[1], sp[2], sp[3], sp[4]);
    mach_enter();
    regs_t saved;
    regs_save(&saved);
    /* Called from guest code run natively on the guest stack: below it. */
    uint32_t at = (uint32_t)(uintptr_t)sp;
    if (at >= MEM32(g_fs_base + 8) && at < MEM32(g_fs_base + 4) && at < g_esp)   /* guest TIB's stack */
        g_esp = (at - 64) & ~15u;
    g_esp -= BRIDGE_SLOTS * 4;
    memcpy((void*)(uintptr_t)g_esp, sp + 1, BRIDGE_SLOTS * 4);
    PUSH32(g_esp, RECOMP_RETADDR);
    uint32_t before = g_esp;
    g_ecx = ecx;
    if (t_cb_regs.on) {
        t_cb_regs.on = 0;
        g_eax = t_cb_regs.r[0]; g_edx = t_cb_regs.r[1]; g_ebx = t_cb_regs.r[2];
        g_esi = t_cb_regs.r[3]; g_edi = t_cb_regs.r[4]; g_ebp = t_cb_regs.r[5];
    }
    f();
    uint32_t eax = g_eax, edx = g_edx, purge = g_esp - before - 4;
    /* The other half of the st(0) transfer: a lifted function returning a
     * float leaves it on the LIFTED x87 stack, and the native caller is about
     * to fstp its own. */
    int st_ret = g_fp_top == saved.fp_top + 1;
    double cb_st = g_st[0];
    regs_load(&saved);
    mach_leave();
    if (st_ret) __asm fld cb_st
    *purge_out = purge;
    return ((uint64_t)edx << 32) | eax;
}

/* Native code that is guest code run natively (gen_bridge: VCL's window
 * procedure thunks) runs on the GUEST stack, and calls back into lifted code
 * from there (the thunk jumps to StdWndProc). Run on that stack, the
 * callback's host frames and the lifted function's guest frames grew down
 * through the same memory, and the thunk's window procedure returned into
 * garbage. So off the thread's own stack (TEB StackLimit..StackBase) the
 * callback moves to the host stack below gen_bridge's anchor (fs:[14h]),
 * which nothing uses while the native code runs, and cb_run puts the guest
 * stack below the native caller's arguments. */
static __declspec(naked) void cb_tramp(void) {
    __asm {
        mov  edx, esp            ; [ret][args]
        cmp  g_teb_widened, 0
        je   teb_only
        push eax
        mov  eax, g_fs_base      ; on the guest TIB's stack: off it, whatever
        test eax, eax            ; the TEB says (gen_bridge widens the TEB's
        jz   by_teb              ; bounds over the guest stack for an x87
        cmp  edx, [eax + 8]      ; range)
        jb   by_teb
        cmp  edx, [eax + 4]
        jae  by_teb
        pop  eax
        jmp  off_stack
    by_teb:
        pop  eax
    teb_only:
        cmp  esp, fs:[8]
        jb   off_stack
        cmp  esp, fs:[4]
        jb   on_stack
    off_stack:
        mov  esp, fs:[0x14]
        sub  esp, 16
    on_stack:
        push edx                 ; the native caller's esp
        sub  esp, 4              ; cb_run's purge goes here
        push esp                 ; ...this address
        push ecx
        push edx
        push eax                 ; the guest VA, planted by the VEH
        call cb_run              ; eax:edx the result
        add  esp, 16
        pop  ecx                 ; the bytes the guest callee popped
        pop  esp                 ; back on the caller's stack: [ret][args]
        push dword ptr [esp]     ; the native return address moves up past
        pop  dword ptr [esp + ecx] ; the popped arguments (pop's address is
        add  esp, ecx            ; computed after esp moves back), and only
        ret                      ; ecx is spent: eax and edx are the result
    }
}

/* Native code reaching a function of a native module that runs lifted
 * (native32_lift_in_native). cb_tramp is the Windows -> guest path: stack
 * arguments and ecx in, eax out, everything else put back, which is the C ABI
 * and right for a callback. A function inside the module owes the C ABI to
 * nobody: hand-written asm and register conventions (Watcom) take arguments
 * in any register and return them in any register. Bisecting with such a
 * function in the lifted set reported it wrong whatever its lift did. So this
 * path hands over all eight registers and the arithmetic flags, both ways:
 * they go in from the trap's pushfd/pushad, and the lifted body's final values
 * come back out through them (asm returns status in CF as often as in eax). */
static __declspec(thread) uint32_t t_lin_va;

static uint32_t __cdecl lin_run(uint32_t* blk) {
    /* blk: pushad's edi esi ebp esp ebx edx ecx eax, pushfd's eflags, then
     * [ret][args] */
    recomp_func_t f = recomp_lookup(t_lin_va);
    mach_enter();
    regs_t saved;
    regs_save(&saved);
    g_esp -= BRIDGE_SLOTS * 4;
    memcpy((void*)(uintptr_t)g_esp, blk + 10, BRIDGE_SLOTS * 4);
    PUSH32(g_esp, RECOMP_RETADDR);
    uint32_t before = g_esp;
    g_edi = blk[0]; g_esi = blk[1]; g_ebp = blk[2]; g_ebx = blk[4];
    g_edx = blk[5]; g_ecx = blk[6]; g_eax = blk[7];
    f();
    uint32_t purge = g_esp - before - 4;
    blk[0] = g_edi; blk[1] = g_esi; blk[2] = g_ebp; blk[4] = g_ebx;
    blk[5] = g_edx; blk[6] = g_ecx; blk[7] = g_eax;
    blk[8] = (blk[8] & ~0x8D5u) |       /* CF PF AF ZF SF OF, from the lift */
             (recomp_eflags(g_flag_k, g_flag_a, g_flag_b, g_flag_cf, (blk[8] >> 10) & 1) & 0x8D5u);
    regs_load(&saved);
    mach_leave();
    /* A callee that pops its arguments (ret n): move the saved registers and
     * the return address up over them, so the trampoline's popad, popfd and
     * ret leave esp where the native caller expects it. */
    if (purge) memmove((char*)blk + purge, blk, 10 * 4);
    return purge;
}

static __declspec(naked) void lin_tramp(void) {
    __asm {
        pushfd
        pushad                   ; every register, as the native caller left them
        push esp                 ; the block
        call lin_run             ; -> bytes the callee popped
        add  esp, 4
        add  esp, eax            ; the block moved up by that much
        popad                    ; the lifted body's registers
        popfd                    ; and flags
        ret
    }
}

static int g_heap_code;

static LONG CALLBACK native32_veh(EXCEPTION_POINTERS* ep) {
    EXCEPTION_RECORD* er = ep->ExceptionRecord;
    uint32_t pc = (uint32_t)(uintptr_t)er->ExceptionAddress;
    if (er->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION && lifted_in_native(pc)) {
        t_lin_va = pc;                          /* native code reached a lifted one */
        ep->ContextRecord->Eip = (DWORD)(uintptr_t)lin_tramp;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    /* An instruction fetch: Windows says so (8, execute). Wine on Apple
     * Silicon (CrossOver, 32-bit code under Rosetta) reports it as a read,
     * but a read of the faulting instruction's own address is a fetch too:
     * Wine calling a window procedure in the shim page came through as
     * "read of 0x032D0170" at 0x032D0170, and the game died creating its
     * window. */
    int fetch = er->NumberParameters >= 2 &&
                (er->ExceptionInformation[0] == 8 || (uint32_t)er->ExceptionInformation[1] == pc);
    if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && fetch &&
        (native32_in_guest(pc) || IS_SHIM_VA(pc))) {
        if (recomp_lookup(pc) || IS_SHIM_VA(pc)) {
            CONTEXT* cx = ep->ContextRecord;
            if (gen_kind(MEM32(cx->Esp)) == 2) {     /* called from an x87 range */
                t_cb_regs.on = 1;
                t_cb_regs.r[0] = cx->Eax; t_cb_regs.r[1] = cx->Edx; t_cb_regs.r[2] = cx->Ebx;
                t_cb_regs.r[3] = cx->Esi; t_cb_regs.r[4] = cx->Edi; t_cb_regs.r[5] = cx->Ebp;
            }
            ep->ContextRecord->Eax = pc;
            ep->ContextRecord->Eip = (DWORD)(uintptr_t)cb_tramp;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        fprintf(stderr, "[callback] Windows called guest 0x%08X, which is not lifted\n", pc);
    }
    /* native32_allow_heap_code: Windows' own code run from the heap. */
    MEMORY_BASIC_INFORMATION mbi;
    DWORD old;
    if (g_heap_code && er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2 &&
        er->ExceptionInformation[0] == 8 && !native32_in_guest((uint32_t)er->ExceptionInformation[1]) &&
        VirtualQuery((void*)er->ExceptionInformation[1], &mbi, sizeof mbi) && mbi.Type == MEM_PRIVATE &&
        mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE &&
        VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &old))
        return EXCEPTION_CONTINUE_EXECUTION;
    return EXCEPTION_CONTINUE_SEARCH;
}

void native32_allow_heap_code(void) { g_heap_code = 1; }

/* ---------------------------------------------------------------- setup */

int native32_require_color_depth(int bpp) {
    char layer[512] = "";
    const char* want = bpp == 16 ? "16BITCOLOR" : bpp == 8 ? "256COLOR" : NULL;
    STARTUPINFOA si = { sizeof si };
    PROCESS_INFORMATION pi;
    DWORD rc = 1;
    if (!want || GetEnvironmentVariableA("PCRECOMP_COLOR_CHILD", NULL, 0)) return -1;
    SetEnvironmentVariableA("PCRECOMP_COLOR_CHILD", want);   /* set before the child exists */
    GetEnvironmentVariableA("__COMPAT_LAYER", layer, sizeof layer - 16);
    if (layer[0]) strcat_s(layer, sizeof layer, " ");
    strcat_s(layer, sizeof layer, want);
    SetEnvironmentVariableA("__COMPAT_LAYER", layer);
    fprintf(stderr, "[native32] relaunching under __COMPAT_LAYER=%s for %d-bit DirectDraw modes\n", layer, bpp);
    if (!CreateProcessA(NULL, GetCommandLineA(), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "[native32] relaunch failed (%lu); running at the desktop's depth\n", GetLastError());
        return -1;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &rc);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (int)rc;
}
static void eh32_init(void);

/* PCRECOMP_MUTE=1: the process's audio session at volume 0. On Vista and
 * later the legacy wave volume is the session's, which DirectSound, waveOut
 * and every mixer DLL in the process share; set before the guest makes a
 * sound, so test runs are silent without touching the game's audio code. */
#include <mmsystem.h>
#pragma comment(lib, "winmm.lib")
static void native32_mute(void) {
    char v[8] = "";
    GetEnvironmentVariableA("PCRECOMP_MUTE", v, sizeof v);
    if (v[0] && v[0] != '0') {
        waveOutSetVolume(NULL, 0);
        fprintf(stderr, "[native32] PCRECOMP_MUTE: audio session muted\n");
    } else if (v[0] == '0') {
        /* Windows remembers an app's session volume, so a muted test run
         * would leave the next real one silent: PCRECOMP_MUTE=0 undoes it. */
        waveOutSetVolume(NULL, 0xFFFFFFFFu);
    }
}

void native32_init(void) {
    native32_mute();
    eh32_init();
    /* Every Windows -> guest call relies on the guest's code faulting when it
     * is fetched. Windows enforces that for a /NXCOMPAT exe; Wine does not
     * unless DEP is asked for, and otherwise answers the first fetch by making
     * the page executable and running the shipping machine code. */
    SetProcessDEPPolicy(PROCESS_DEP_ENABLE);
    InitializeCriticalSection(&g_mach);
    recomp_yield_hook = native32_yield;
    g_mach_tls = TlsAlloc();
    g_tslot_fls = FlsAlloc(tslot_free);
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

/* Built-in bodies kept in their own files, compiled as part of this one so a
 * host's build needs no change when one is added. */
#include "eh32.c"
#include "x87crt.c"

/* native32_headless: see the header. */
int native32_headless(void) {
    char name[64];
    if (GetEnvironmentVariableA("NATIVE32_HEADLESS", NULL, 0)) return -1;   /* the child */
    _snprintf(name, sizeof name - 1, "native32-headless-%lu", GetCurrentProcessId());
    name[sizeof name - 1] = 0;
    HDESK desk = CreateDesktopA(name, NULL, NULL, 0, GENERIC_ALL, NULL);
    if (!desk) { fprintf(stderr, "[headless] CreateDesktop failed (%lu)\n", GetLastError()); return -1; }
    SetEnvironmentVariableA("NATIVE32_HEADLESS", name);
    STARTUPINFOA si = { sizeof si };
    PROCESS_INFORMATION pi;
    DWORD rc = 1;
    si.lpDesktop = name;
    if (!CreateProcessA(NULL, GetCommandLineA(), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "[headless] CreateProcess failed (%lu)\n", GetLastError());
        CloseDesktop(desk);
        return -1;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &rc);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseDesktop(desk);
    return (int)rc;
}

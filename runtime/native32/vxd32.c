/*
 * vxd32: the Windows 9x kernel boundary, for lifted Windows 98 kernel32.
 *
 * Windows 98's kernel32 imports nothing. It leaves ring 3 by one far call
 * through a call gate to VMM (kernel32's VxDCall0..8, ordinals 1-9:
 * `mov eax,[esp+4]; pop [esp]; call fword cs:[gate]`). lift32 turns that
 * `call m16:32` into recomp_farcall32(); this file answers it by service id
 * (VxD id << 16 | service), the way VWIN32 and VMM's Win32 services would,
 * with the host underneath.
 *
 * At the gate the stack is: [esp] the VxDCall caller's return address, then
 * the service's arguments. The gate returns straight to that caller and pops
 * the arguments, so a handler names its argument count.
 *
 * NATIVE32_VXD=1 traces every call. An unknown service stops the process
 * (exit 5) with its id and arguments: nothing is guessed.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "native32.h"
void recomp_trace_flush(void);   /* recomp_trace.c: --calltrace before we end */

static int g_trace = -1;          /* NATIVE32_VXD */
static uint16_t g_cur_psp;         /* the current PSP selector (a TDBX points at it) */
static char g_cwd[MAX_PATH];       /* the guest's current directory: no drive, no leading backslash */
uint16_t native32_w9x_alloc_sel(uint32_t base, uint32_t limit);
static uint32_t g_cur[3];          /* VWIN32's current thread, process, TDBX (0xBFFC9CE0 points here) */
typedef struct { uint32_t id; int nargs; uint32_t (*fn)(const uint32_t* a); const char* name; } vxd_service_t;

/* VWIN32 3: kernel32's boot hands VWIN32 its code and data selectors (args
 * 1, 2) before reading the boot block; nothing for a flat host to keep. */
static uint32_t vwin32_boot_sels(const uint32_t* a) { (void)a; return 0; }

/* VWIN32 4A (crit, level): the kernel side of a critical section kernel32
 * just initialised (its type-4 object). Returns VWIN32's own object for it;
 * kernel32 keeps it in the section. A zeroed block of our own stands in. */
/* The object's first dword is read as a pointer to a list head: kernel32
 * walks [[obj]] up to a zero dword (0xBFF7D61A, 0xBFF89796, for the heap's
 * section that _INIT keeps at 0xBFFC9230). An empty list here.
 * ponytail: what the entries are (12 at most, {?, value} pairs copied into
 * a new thread at +DC) is open until one is needed. */
static uint32_t vwin32_crst_create(const uint32_t* a) {
    uint32_t* o = calloc(1, 0x40);
    (void)a;
    o[0] = (uint32_t)(uintptr_t)&o[1];
    o[1] = (uint32_t)(uintptr_t)&o[2];
    return (uint32_t)(uintptr_t)o;
}

/* VMM's Win32 memory services (DDK _PageReserve/_PageCommit/_PageDecommit),
 * in pages. page: a page number, or PR_PRIVATE 0x80000400 / PR_SHARED
 * 0x80060000 / PR_SYSTEM 0x80080000 for "anywhere in that arena".
 * ponytail: every arena is "anywhere" in the host; place PR_SHARED above 2 GB
 * if kernel32 turns out to test addresses for sharedness. */
#define PR_ANY(p) (((p) & 0xFFF00000u) == 0x80000000u)
/* Win9x commits a reserved page on first touch (a thread's stack grows that
 * way: kernel32 commits its top 2 pages and the program probes below). A
 * first-chance handler does the same for regions reserved here.
 * ponytail: a fixed table of 4096 regions, never pruned on PageFree. */
static struct { uintptr_t base, size; } g_resv[4096];
static volatile LONG g_nresv;
/* Win9x maps the first 64 KB (the V86 IVT and BIOS data) readable and
 * writable from ring 3, and kernel32 relies on it: a thread whose context
 * was just released (+58 = 0) is read as [0+38h] during its own process's
 * teardown (0xBFF7D65E). Win11 maps nothing there, so a lifted access to
 * the low 64 KB is emulated: the host instruction (32-bit, compiled C) is
 * decoded, a load gives 0, a store is dropped.
 * ponytail: mov/movzx/movsx loads and mov stores only; any other form still
 * faults and the report names it. */
static int low_emulate(CONTEXT* c) {
    uint8_t* p = (uint8_t*)(uintptr_t)c->Eip;
    int o16 = 0, n = 0;
    if (p[n] == 0x66) { o16 = 1; n++; }
    uint8_t op = p[n++], op2 = 0;
    if (op == 0x0F) op2 = p[n++];
    int load = op == 0x8B || op == 0x8A || (op == 0x0F && (op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF));
    int store = op == 0x89 || op == 0x88 || op == 0xC7 || op == 0xC6;
    if (!load && !store) return 0;
    uint8_t m = p[n++], mod = m >> 6, reg = (m >> 3) & 7, rm = m & 7;
    if (mod == 3) return 0;
    if (rm == 4) { uint8_t sib = p[n++]; if (mod == 0 && (sib & 7) == 5) n += 4; }
    else if (mod == 0 && rm == 5) n += 4;
    n += mod == 1 ? 1 : mod == 2 ? 4 : 0;
    if (op == 0xC7) n += o16 ? 2 : 4;
    if (op == 0xC6) n += 1;
    if (load) {
        DWORD* r[8] = { &c->Eax, &c->Ecx, &c->Edx, &c->Ebx, &c->Esp, &c->Ebp, &c->Esi, &c->Edi };
        if (op == 0x8A) { if (reg < 4) *r[reg] &= ~0xFFu; else *r[reg - 4] &= ~0xFF00u; }
        else if (o16 && op == 0x8B) *r[reg] &= ~0xFFFFu;
        else *r[reg] = 0;
    }
    c->Eip += n;
    return 1;
}
static LONG CALLBACK resv_fault(EXCEPTION_POINTERS* e) {
    if (e->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;
    uintptr_t at = e->ExceptionRecord->ExceptionInformation[1];
    MEMORY_BASIC_INFORMATION mb;
    if (at < 0x10000 && low_emulate(e->ContextRecord)) {
        if (g_trace > 0) fprintf(stderr, "[vxd] low-memory %s %04X (Win9x's first 64 KB) emulated (in sub_%08X)\n",
                                 e->ExceptionRecord->ExceptionInformation[0] ? "write" : "read", (unsigned)at, g_cur_func);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    for (LONG i = 0; i < g_nresv; i++)
        if (at - g_resv[i].base < g_resv[i].size) {
            if (!VirtualQuery((void*)at, &mb, sizeof mb) || mb.State != MEM_RESERVE) break;
            if (!VirtualAlloc((void*)(at & ~(uintptr_t)0xFFF), 0x1000, MEM_COMMIT, PAGE_READWRITE)) break;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    return EXCEPTION_CONTINUE_SEARCH;
}
/* VWIN32 40 (r0, addr, &mbi, cb): VirtualQuery(Ex) (0xBFFA1E2A, 0xBFF85301
 * with cb 1Ch); the bytes written. One address space: the host's answer. */
static uint32_t vwin32_virtual_query(const uint32_t* a) {
    if (a[3] < sizeof(MEMORY_BASIC_INFORMATION)) return 0;
    return (uint32_t)VirtualQuery((void*)(uintptr_t)a[1], (MEMORY_BASIC_INFORMATION*)(uintptr_t)a[2], sizeof(MEMORY_BASIC_INFORMATION));
}
/* VWIN32 41 (value, ctx): ExitProcess (0xBFF89786) passes PDB+38 + 60h and
 * then each of a list's +4 with the process's +58 (its context) and keeps
 * the results to restore later: a value translated into a context. The
 * host has one context, so the value comes back as it went in. */
static uint32_t vwin32_in_context(const uint32_t* a) { return a[0]; }
static uint32_t vmm_page_reserve(const uint32_t* a) {
    void* want = PR_ANY(a[0]) ? NULL : (void*)(uintptr_t)(a[0] << 12);
    void* p = VirtualAlloc(want, a[1] << 12, MEM_RESERVE, PAGE_READWRITE);
    if (p) {
        if (!g_nresv) AddVectoredExceptionHandler(1, resv_fault);
        LONG i = InterlockedIncrement(&g_nresv) - 1;
        if (i < 4096) { g_resv[i].base = (uintptr_t)p; g_resv[i].size = (uintptr_t)a[1] << 12; } else g_nresv = 4096;
    }
    MEMORY_BASIC_INFORMATION mb;
    /* kernel32's loader reserving a module at its own base, where native32
     * already holds that image (the lifted code is for that address): the
     * region is the guest's already, and the pager fills it with the same
     * bytes. Anywhere else would be a relocated copy nothing lifted runs. */
    if (!p && want && VirtualQuery(want, &mb, sizeof mb) && mb.AllocationBase == want && mb.State != MEM_FREE) {
        if (g_trace > 0) fprintf(stderr, "[vxd] PageReserve %08X: the image native32 holds there\n", (uint32_t)(uintptr_t)want);
        return (uint32_t)(uintptr_t)want;
    }
    return p ? (uint32_t)(uintptr_t)p : 0xFFFFFFFFu;
}
/* VMM's registry (Windows 9x keeps it in ring 0). Named from kernel32's
 * call sites: 11 (hkey, sub, &hk) open, 12 the same create, 13 (hk) close,
 * 16 (hk, sub) delete key, 18 (hk, i, buf, cch) enum key, 19 (hk, i, name,
 * &cch, 0, &type, data, &cb) enum value, 1A (hk, name, 0, &type, data, &cb)
 * query value, 1B (hk, name, 0, type, data, cb) set value. Return codes
 * are Win32's. Every call goes through pcrecomp's registry box (regbox32):
 * the guest never writes the real registry. */
static void* reg_fn(const char* name) { void* f = native32_registry_sandbox_fn(name); return f ? f : (void*)GetProcAddress(GetModuleHandleA("advapi32.dll"), name); }
#define REG(name, type) ((type)reg_fn(name))
#define P(i) ((void*)(uintptr_t)a[i])
static uint32_t vmm_reg_open(const uint32_t* a) {
    return (uint32_t)REG("RegOpenKeyExA", LONG(WINAPI*)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY))((HKEY)P(0), P(1), 0, KEY_ALL_ACCESS, P(2));
}
static uint32_t vmm_reg_create(const uint32_t* a) {
    return (uint32_t)REG("RegCreateKeyA", LONG(WINAPI*)(HKEY, LPCSTR, PHKEY))((HKEY)P(0), P(1), P(2));
}
static uint32_t vmm_reg_close(const uint32_t* a) { return (uint32_t)RegCloseKey((HKEY)P(0)); }
static uint32_t vmm_reg_delete_key(const uint32_t* a) {
    return (uint32_t)REG("RegDeleteKeyA", LONG(WINAPI*)(HKEY, LPCSTR))((HKEY)P(0), P(1));
}
static uint32_t vmm_reg_enum_key(const uint32_t* a) {
    return (uint32_t)REG("RegEnumKeyA", LONG(WINAPI*)(HKEY, DWORD, LPSTR, DWORD))((HKEY)P(0), a[1], P(2), a[3]);
}
static uint32_t vmm_reg_enum_value(const uint32_t* a) {
    return (uint32_t)REG("RegEnumValueA", LONG(WINAPI*)(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD))(
        (HKEY)P(0), a[1], P(2), P(3), NULL, P(5), P(6), P(7));
}
static uint32_t vmm_reg_query_value(const uint32_t* a) {
    return (uint32_t)REG("RegQueryValueExA", LONG(WINAPI*)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD))((HKEY)P(0), P(1), NULL, P(3), P(4), P(5));
}
/* 1D (hk, &subkeys, &maxsubkey, &values, &maxvaluename, &maxvalue): advapi32's
 * RegQueryInfoKeyA (0xBFE81C2B); 15 (hk, sub, type, data, cb): RegSetValueA. */
static uint32_t vmm_reg_query_info(const uint32_t* a) {
    return (uint32_t)REG("RegQueryInfoKeyA", LONG(WINAPI*)(HKEY, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME))(
        (HKEY)P(0), NULL, NULL, NULL, P(1), P(2), NULL, P(3), P(4), P(5), NULL, NULL);
}
static uint32_t vmm_reg_set_value_sub(const uint32_t* a) {
    return (uint32_t)REG("RegSetValueA", LONG(WINAPI*)(HKEY, LPCSTR, DWORD, LPCSTR, DWORD))((HKEY)P(0), P(1), a[2], P(3), a[4]);
}
static uint32_t vmm_reg_set_value(const uint32_t* a) {
    return (uint32_t)REG("RegSetValueExA", LONG(WINAPI*)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD))((HKEY)P(0), P(1), 0, a[3], P(4), a[5]);
}
/* VMM 100h+, KRNL386's 16-bit registry (seg2 6B0C..), told apart by each
 * entry's retf: a[] is the arguments in declaration order, far pointers
 * already flat. Win16's HKEY_CLASSES_ROOT is 1. Everything goes through
 * regbox32, like the 32-bit services; REG.DAT is never opened. The
 * hive-file services (10C RegLoadKey, 10D RegUnLoadKey, 10E RegSaveKey)
 * answer ERROR_ACCESS_DENIED: no guest file becomes a hive. */
uint32_t native32_w9x_reg16(uint16_t svc, uint32_t* a) {
    if (a[0] == 1) a[0] = (uint32_t)(uintptr_t)HKEY_CLASSES_ROOT;
    switch (svc) {
    case 0x100: return vmm_reg_open(a);
    case 0x101: return vmm_reg_create(a);
    case 0x102: return vmm_reg_close(a);
    case 0x103: return vmm_reg_delete_key(a);
    case 0x104: return vmm_reg_set_value_sub(a);   /* (hk, sub, type, data, cb) */
    case 0x105: return (uint32_t)REG("RegQueryValueA", LONG(WINAPI*)(HKEY, LPCSTR, LPSTR, PLONG))((HKEY)P(0), P(1), P(2), P(3));
    case 0x106: return vmm_reg_enum_key(a);
    case 0x107: return (uint32_t)REG("RegDeleteValueA", LONG(WINAPI*)(HKEY, LPCSTR))((HKEY)P(0), P(1));
    case 0x108: return vmm_reg_enum_value(a);
    case 0x109: return vmm_reg_query_value(a);
    case 0x10A: return vmm_reg_set_value(a);
    case 0x10B: return 0;                          /* RegFlushKey: nothing buffered */
    default: return ERROR_ACCESS_DENIED;
    }
}

/* VWIN32 1 (p0..p9): VWIN32 hands kernel32 its ring-0 file entry points,
 * which kernel32 then calls directly (cdecl) for module images and their
 * pager, plus two data pointers; the return value is one more entry
 * (-> 0xBFFC9510, the pager's read). Each entry is a tagged address
 * (0xFEEF0000 + 4 * n) that native32's dispatcher resolves through
 * native32_w9x_lookup; one not answered yet stops the run with its slot.
 *   n  kernel32 slot  used at
 *   0  9500           0xBFFAB95F (3 args)
 *   1  9508           0xBFF7D83F (1)
 *   2  953C           0xBFFAB694 (1)
 *   3  9544           0xBFFAB679 (1)
 *   4  9550           0xBFFAB68A (1)
 *   5  950C           0xBFFAB75D (1)
 *   6  9514           0xBFFABC2F (4, result in ax)
 *   7  9540           0xBFFAB707 (3)
 *   8  9338  data, read at 0xBFFC72EE
 *   9  9334  data, a pointer to a table pointer (0xBFF81D3A)
 *  10  9510  (return value) the pager's read: (h, offset, buf, n, sel, sel, 13Fh) */
#define R0F_TAG 0xFEEF0000u
static const uint32_t g_r0f_slot[] = { 0x9500, 0x9508, 0x953C, 0x9544, 0x9550, 0x950C, 0x9514, 0x9540, 0, 0, 0x9510 };
static uint32_t g_r0_data8[0x40], g_r0_table9[0x400], *g_r0_data9 = g_r0_table9;
static uint32_t vwin32_r0_file_entries(const uint32_t* a) {
    for (int i = 0; i < 8; i++) MEM32(a[i]) = R0F_TAG + 4u * i;
    MEM32(a[8]) = (uint32_t)(uintptr_t)g_r0_data8;
    MEM32(a[9]) = (uint32_t)(uintptr_t)&g_r0_data9;
    return R0F_TAG + 4u * 10;
}
/* 2 (mutex) / 3 (mutex): enter and leave a ring-0 mutex (0xBFFC9560 guards
 * kernel32's mapped-file table: 0xBFFABA34 enters, and the exit leaves
 * through 3 or, from ring 3, LeaveCriticalSection). One host lock for all.
 * ponytail: one global lock; key it by mutex if two ever nest across threads. */
static CRITICAL_SECTION g_r0_mutex;
static int host_path(uint32_t guest, char* out);   /* the int 21h section below */
static HANDLE dos_handle(uint16_t h);
static int new_handle(HANDLE fh);
static int dos_close(uint16_t h);
static void r0f_call(uint32_t n) {
    uint32_t a0 = MEM32(g_esp + 4);
    static int init;
    if (!init) { InitializeCriticalSection(&g_r0_mutex); init = 1; }
    switch (n) {
    case 2: EnterCriticalSection(&g_r0_mutex); g_esp += 4; if (g_trace > 0) fprintf(stderr, "[vxd] r0 enter mutex %08X\n", a0); return;
    case 3: LeaveCriticalSection(&g_r0_mutex); g_esp += 4; if (g_trace > 0) fprintf(stderr, "[vxd] r0 leave mutex %08X\n", a0); return;
    /* 0 (event, -1, 0) waits on and 1 (event) signals kernel32's paging
     * event (0xBFFC952C); 4 (rec) and 5 (rec) bracket a mapped-file record
     * (0xBFFAB68A, 0xBFFAB75D). With one guest thread doing its own paging
     * nothing ever waits. ponytail: no-ops until a second guest thread pages. */
    case 0: case 1: case 4: case 5: g_esp += 4; g_eax = 0; return;
    case 6: {   /* (name, mode, sel, sel) open for paging (0xBFFABC2F): ax = handle, high word -1 on failure */
        char path[MAX_PATH];
        uint16_t mode = (uint16_t)MEM32(g_esp + 8);
        HANDLE fh = INVALID_HANDLE_VALUE;
        if (host_path(a0, path))
            fh = CreateFileA(path, (mode & 3) ? GENERIC_READ | GENERIC_WRITE : GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        int h = fh == INVALID_HANDLE_VALUE ? -1 : new_handle(fh);
        g_eax = h < 0 ? 0xFFFF0002u : (uint32_t)h;
        if (g_trace > 0) fprintf(stderr, "[vxd] r0 open %s -> %08X\n", path, g_eax);
        g_esp += 4; return; }
    case 7: {   /* (handle, sel, sel) close (0xBFFAB707) */
        dos_close((uint16_t)a0);
        g_eax = 0; g_esp += 4; return; }
    case 10: {  /* (handle, offset, buf, n, sel, sel, 13Fh) the pager's read (0xBFF7D8E6): eax = bytes read */
        HANDLE fh = dos_handle((uint16_t)a0);
        LARGE_INTEGER at; DWORD got = 0;
        at.QuadPart = MEM32(g_esp + 8);
        if (fh && SetFilePointerEx(fh, at, NULL, FILE_BEGIN)) ReadFile(fh, (void*)(uintptr_t)MEM32(g_esp + 12), MEM32(g_esp + 16), &got, NULL);
        if (g_trace > 0) fprintf(stderr, "[vxd] r0 read h%u @%08X %u -> %u\n", (unsigned)(uint16_t)a0, MEM32(g_esp + 8), MEM32(g_esp + 16), (unsigned)got);
        g_eax = got; g_esp += 4; return; }
    }
    fprintf(stderr, "\n[vxd] VWIN32 ring-0 file entry %u (kernel32 slot 0xBFFC%04X) from sub_%08X: args %08X %08X %08X %08X %08X %08X %08X\n",
            n, g_r0f_slot[n], g_cur_func, MEM32(g_esp + 4), MEM32(g_esp + 8), MEM32(g_esp + 12), MEM32(g_esp + 16),
            MEM32(g_esp + 20), MEM32(g_esp + 24), MEM32(g_esp + 28));
    native32_dump_icalls(8);
    fflush(stderr);
    recomp_trace_flush();
    TerminateProcess(GetCurrentProcess(), 5);
}
#define R0F(n) static void r0f_##n(void) { r0f_call(n); }
R0F(0) R0F(1) R0F(2) R0F(3) R0F(4) R0F(5) R0F(6) R0F(7) R0F(10)
static void (*const g_r0f[11])(void) = { r0f_0, r0f_1, r0f_2, r0f_3, r0f_4, r0f_5, r0f_6, r0f_7, NULL, NULL, r0f_10 };

/* KRNL386, the 16-bit half of kernel32's flat thunks. Each thunked call is
 * a stub `mov cl, N; jmp common`, and common (`push ebp; mov ebp, esp; push
 * ecx; sub esp, 3Ch; push 16-bit args...; call [slot]`) reaches QT_Thunk
 * through the slot. The host points the slot at K386_TAG, so the call lands
 * here with N at [ebp-4] and the Pascal-order arguments on the stack (the
 * last one at esp+4). The answer is dx:ax; the stub's `leave` drops the
 * arguments. Named from the 32-bit callers; an N not answered stops the run.
 *   12h (lpBuf:16:16, cb:16) GetSystemDirectory: 0xBFF8DBFE opens
 *       <it>\unicode.nls */
#define K386_TAG 0xFEEE8000u
static void guest_put(uint32_t va, const char* s, size_t max);
const char* g_w9x_sysdir = "C:\\WINDOWS\\SYSTEM", *g_w9x_windir = "C:\\WINDOWS";
static uint32_t lin16(uint32_t p1616) { return recomp_sel_base(p1616 >> 16) + (p1616 & 0xFFFF); }
static void krnl386_thunk(void) {
    uint8_t n = MEM8(g_ebp - 4);
    uint32_t sp = g_esp + 4;          /* past the return address the call pushed */
    switch (n) {
    case 0x12: case 0x13: {   /* 13h (lpBuf, cb) GetWindowsDirectory: 0xBFF968EC appends \APPLOG */
        uint16_t cb = MEM16(sp);
        uint32_t buf = lin16(MEM32(sp + 2));
        const char* dir = n == 0x12 ? g_w9x_sysdir : g_w9x_windir;
        size_t len = strlen(dir);
        if (len < cb) guest_put(buf, dir, cb);
        g_eax = (uint32_t)len; g_edx = 0;
        if (g_trace > 0) fprintf(stderr, "[krnl386] thunk %02X Get%sDirectory(%08X, %u) = %u\n", n, n == 0x12 ? "System" : "Windows", buf, cb, (unsigned)len);
        break; }
    case 0x30:   /* (hTask:16, lpszName:16:16): _INIT passes the boot task and
                  * "KERNEL32.DLL" (0xBFFC6F68), CreateProcess a new process's
                  * task (PDB+38) and its module name (0xBFF8B4BF). The task's
                  * name for KRNL386. ponytail: not kept; nothing on the host
                  * reads Win16 task names yet. */
        if (g_trace > 0) fprintf(stderr, "[krnl386] thunk 30 task %04X name \"%s\"\n", MEM16(sp + 4), (const char*)(uintptr_t)lin16(MEM32(sp)));
        g_eax = 0; g_edx = 0;
        break;
    case 0x32: { /* (psp:16, thread:32, tibsel:16): the new process's Win16 task
                  * (CreateProcess, 0xBFF92F8F); the selector lands in PDB+38
                  * and thread+14. A TDB like the boot task's (k32host): +16
                  * flags (10h, a Win32 task), +60 its PSP, +66 the drive with
                  * bit 7 (+100 holds the directory), 'TD' at +FA. */
        uint8_t* tdb = calloc(1, 0x200);
        tdb[0x16] = 0x10;
        *(uint16_t*)(tdb + 0x60) = MEM16(sp + 6);
        tdb[0x66] = 0x80 | 2;
        tdb[0xFA] = 'T'; tdb[0xFB] = 'D';
        _snprintf((char*)tdb + 0x100, 0x100, "\\%s", g_cwd);
        g_eax = native32_w9x_alloc_sel((uint32_t)(uintptr_t)tdb, 0x1FF); g_edx = 0;
        if (g_trace > 0) fprintf(stderr, "[krnl386] thunk 32 new task %04X (psp %04X, thread %08X)\n", g_eax, MEM16(sp + 6), MEM32(sp + 2));
        break; }
    case 0x2A: { /* (lpCmdLine:16:16, nCmdShow:16, ?:16) WinExec. A console
                  * program's first thread starts the console agent
                  * (0xBFFA205C: "<sysdir>\CONAGENT.EXE /new ..."), the DOS
                  * box that runs a Win9x console. The host's console is that
                  * console: say it started (an hInstance above 31). Anything
                  * else would be a real 16-bit program: stop. */
        const char* cmd = (const char*)(uintptr_t)lin16(MEM32(sp + 4));
        if (g_trace > 0) fprintf(stderr, "[krnl386] thunk 2A WinExec(\"%s\", %u)\n", cmd, MEM16(sp + 2));
        if (strstr(cmd, "CONAGENT") || strstr(cmd, "conagent")) { g_eax = 0x40; g_edx = 0; break; }
        fprintf(stderr, "\n[krnl386] WinExec(\"%s\"): no 16-bit programs here\n", cmd);
        fflush(stderr); recomp_trace_flush(); TerminateProcess(GetCurrentProcess(), 5);
        break; }
    case 0x33:   /* () under crst 0xBFFC9470, from a new process's first thread
                  * (0xBFF8B493, before its task name, thunk 30): 0 sends the
                  * process to ExitProcess(-1). Nothing for KRNL386 to set up. */
        g_eax = 1; g_edx = 0;
        break;
    case 0x34:   /* (sel:16) FreeSelector: 0xBFF7202B returns TRUE when this
                  * gives 0 (ExitProcess frees the process's selectors). The
                  * host LDT only grows. ponytail: never reused. */
        g_eax = 0; g_edx = 0;
        break;
    case 0x31:   /* (task:16) the Win16 task thunk 32 made, deleted with its
                  * process (0xBFF92FA4). ponytail: the TDB block stays. */
        if (g_trace > 0) fprintf(stderr, "[krnl386] thunk 31 delete task %04X\n", MEM16(sp));
        g_eax = 0; g_edx = 0;
        break;
    case 0x55:   /* (sel:16) a dying thread's selector, right after USER's
                  * signal 1 for it (0xBFF89083); then the selector is
                  * freed. Nothing kept per selector. */
        g_eax = 0; g_edx = 0;
        break;
    case 0x43:   /* (pdb:32) the process teardown (0xBFF8CDE8) tells KRNL386 a
                  * Win32 process is gone; its result is not read. */
        if (g_trace > 0) fprintf(stderr, "[krnl386] thunk 43 process %08X gone\n", MEM32(sp));
        g_eax = 0; g_edx = 0;
        break;
    case 0x0D:   /* (drive:16, 0 = A:) GetDriveType: GetDriveTypeA (0xBFF74D33)
                  * asks for a drive it found real. Only C: (fixed, 3). */
        g_eax = MEM16(sp) == 2 ? 3 : 0; g_edx = 0;
        break;
    case 0x2D:   /* () GetWinFlags: _INIT (0xBFFC702E) picks the CPU it describes
                  * from it (2000h, else 4 = 386 checks). Protected mode,
                  * enhanced, an x87, a 486 and 2000h (the Pentium class). */
        g_eax = 0x2000 | 0x400 | 0x20 | 0x8 | 0x1; g_edx = 0;
        break;
    default:
        fprintf(stderr, "\n[krnl386] unknown thunk %02Xh from sub_%08X: 16-bit args at esp %04X %04X %04X %04X %04X %04X\n",
                n, g_cur_func, MEM16(sp), MEM16(sp + 2), MEM16(sp + 4), MEM16(sp + 6), MEM16(sp + 8), MEM16(sp + 10));
        native32_dump_icalls(8);
        fflush(stderr);
        recomp_trace_flush();
        TerminateProcess(GetCurrentProcess(), 5);
    }
    g_esp += 4;                        /* the dummy return address */
}
uint32_t native32_w9x_krnl386_thunk(void) { return K386_TAG; }

/* USER32!UserSignalProc(signal, id, flags, hTask16), stdcall: kernel32 tells
 * USER of every process and thread event (0xBFF815FB) through 0xBFFC95C0,
 * which it fills when USER32 loads; Windows 98 always has USER32 loaded, so
 * it never checks. Until a GUI guest brings its own user32, the host stands
 * in: a console program has no windows to tidy. */
#define USIG_TAG 0xFEEE9000u
static void user_signal_proc(void) {
    if (g_trace > 0) fprintf(stderr, "[user32] UserSignalProc(%08X, %08X, %08X, %04X)\n", MEM32(g_esp + 4), MEM32(g_esp + 8), MEM32(g_esp + 12), MEM16(g_esp + 16));
    g_eax = 0;
    g_esp += 4 + 16;
}
uint32_t native32_w9x_user_signal_proc(void) { return USIG_TAG; }

/* Guest hard errors. Win98's kernel32 shows them with USER32!MessageBoxA,
 * bound lazily through its own table (0xBFFCB2C4: FatalAppExit 0xBFF94E8A,
 * a process's load and teardown failures 0xBFFA96F1 and others), and the
 * guest's USER32 is a proxy onto the host's. The proxy's MessageBoxA is
 * this instead: the message is logged, nothing is shown on the host, and
 * the answer is the one that ends the operation (OK, Cancel, Abort, No). */
#define MBOX_TAG (USIG_TAG + 0x10)
static void guest_message_box(void) {
    const char* text = (const char*)(uintptr_t)MEM32(g_esp + 8);
    const char* cap = (const char*)(uintptr_t)MEM32(g_esp + 12);
    uint32_t type = MEM32(g_esp + 16);
    static const uint32_t answer[8] = { 1, 2, 3, 2, 7, 2, 2, 1 };   /* MB_OK .. MB_CANCELTRYCONTINUE */
    fprintf(stderr, "[hard error] \"%s\": \"%s\" (type %X) -> %u\n", cap ? cap : "", text ? text : "", type, answer[type & 7]);
    g_eax = answer[type & 7];
    g_esp += 4 + 16;
}
uint32_t native32_w9x_message_box(void) { return MBOX_TAG; }

/* A flat thunk's 32->16 stub in a DLL's .data (kernel32 0xBFFC9ED0 for its
 * own 32->16 slot 0xBFF9AD46, user32 0xBFF5D400 for its thunks into
 * USER.EXE): `jmp +20h` to `call $+5; pop eax; sub eax, 25h; mov edx, -4;
 * push patcher; ret`, and the patcher (kernel32 0xBFF7273F) rewrites it on
 * first call into `xor ecx,ecx; mov cl,[ebp-4]; mov edx,[ecx*4+table];
 * mov eax,0xBFF727D9; jmp eax`, table = the dword at stub+edx. Static code
 * can't run the rewritten bytes, so this is that stub, for any DLL's: the
 * lookup recognizes the bytes and keeps the stub's address for the call it
 * is about to make (the thread's last lookup of one).
 * ponytail: the 0xBFF727D9 target (Win98 SE kernel32's) is hardcoded; read it off the patcher if another build shows up */
static __declspec(thread) uint32_t t_qt_stub;
static int is_qt_stub(uint32_t va) {
    static const uint8_t tail[] = { 0xE8, 0, 0, 0, 0, 0x58, 0x2D, 0x25, 0, 0, 0, 0xBA };
    return va >= 0x10000 && !IsBadReadPtr((void *)(uintptr_t)va, 0x31) && MEM8(va) == 0xEB && MEM8(va + 1) == 0x1E &&
           !memcmp((const void *)(uintptr_t)(va + 0x20), tail, sizeof tail);
}
static void qt_stub(void) {
    uint32_t va = t_qt_stub;
    g_ecx = MEM8(g_ebp - 4);
    g_edx = MEM32(MEM32(va + MEM32(va + 0x2C)) + g_ecx * 4);
    if (g_trace > 0 || getenv("W16_TRACE")) fprintf(stderr, "[qt] thunk %02X -> %04X:%04X (stub %08X ss %04X@%08X esp %08X fs %04X)\n", g_ecx, g_edx >> 16, g_edx & 0xFFFF, va, g_seg_ss, g_ss_base, g_esp, g_seg_fs);
    g_eax = 0xBFF727D9u;
    recomp_lookup(0xBFF727D9u)();
}

/* The host's recomp_lookup_manual forwards here: VWIN32's entries above. */
recomp_func_t native32_w9x_lookup(uint32_t va) {
    if (va == K386_TAG) return krnl386_thunk;
    if (va == USIG_TAG) return user_signal_proc;
    if (va == MBOX_TAG) return guest_message_box;
    if (is_qt_stub(va)) { t_qt_stub = va; return qt_stub; }
    if ((va & 0xFFFF0000u) == R0F_TAG && (va & 0xFFFF) < 4 * 11 && !(va & 3)) return g_r0f[(va & 0xFFFF) / 4];
    return NULL;
}

/* VMM pagers. kernel32 asks for a stock pager's descriptor (service 4,
 * (hpd, &pd)), puts its own page-in in it (0xBFF7D84B: module images,
 * read from the file through VWIN32) and registers the copy (service 3,
 * (&pd) -> hpd). pd: +00 virgin page-in, +04 tainted page-in, +08 clean
 * out, +0C dirty out, +10/+14 frees, +18 dirty, +1C type. The stock pagers
 * (1, 2) are plain zero-fill memory here. */
#define NPAGERS 16
static uint32_t g_pd[NPAGERS][8];
static int g_npd = 3;                      /* 1, 2: VMM's own; ours from 3 */
static uint32_t vmm_pager_query(const uint32_t* a) {
    uint32_t* pd = (uint32_t*)(uintptr_t)a[1];
    if (a[0] == 0 || a[0] >= (uint32_t)g_npd) return 0;
    memcpy(pd, g_pd[a[0]], 32);
    if (a[0] < 3) pd[7] = a[0];
    return 1;
}
static uint32_t vmm_pager_register(const uint32_t* a) {
    if (g_npd == NPAGERS) return 0;
    memcpy(g_pd[g_npd], (void*)(uintptr_t)a[0], 32);
    return (uint32_t)g_npd++;
}

/* (page, npages, hpd, pagerdata, flags). A host has no page faults to page
 * in on, so a pager with a page-in has it run for every page now:
 * pagein(&pagerdata, page address, 0), cdecl, pagerdata + i for page i. */
static uint32_t vmm_page_commit(const uint32_t* a) {
    uint32_t page = a[0], n = a[1], hpd = a[2], data = a[3];
    if (!VirtualAlloc((void*)(uintptr_t)(page << 12), n << 12, MEM_COMMIT, PAGE_READWRITE)) return 0;
    if (hpd >= 3 && hpd < (uint32_t)g_npd && g_pd[hpd][0]) {
        uint32_t saved[8] = { g_eax, g_ecx, g_edx, g_ebx, g_esp, g_ebp, g_esi, g_edi };
        for (uint32_t i = 0; i < n; i++) {
            uint32_t d = data + i;   /* per page: the file-mapping pager (0xBFF813F9) keeps the page index in the low 18 bits */
            uint32_t args[3] = { (uint32_t)(uintptr_t)&d, (page + i) << 12, 0 };
            if (g_trace > 0) fprintf(stderr, "[vxd]   page-in %08X (pager %u, data %08X)\n", (page + i) << 12, hpd, d);
            native32_call_guest(g_pd[hpd][0], 3, args);
        }
        g_eax = saved[0]; g_ecx = saved[1]; g_edx = saved[2]; g_ebx = saved[3];
        g_esp = saved[4]; g_ebp = saved[5]; g_esi = saved[6]; g_edi = saved[7];
    }
    return 1;
}
/* (page, npages, flags) */
static uint32_t vmm_page_decommit(const uint32_t* a) {
    return VirtualFree((void*)(uintptr_t)(a[0] << 12), a[1] << 12, MEM_DECOMMIT);
}

/* VMM 28, through two inline gate calls (0xBFF9CA9A, 0xBFF9CAB9) that
 * bracket it with pushal/popal and drop the result. The one reached, at a
 * new process's start (0xBFF8B1AA), leaves a word under the return address
 * (-1) that its own `pop eax` takes back: so no arguments. Nothing on the
 * host. ponytail: named when a caller looks at what it did. */
static uint32_t vmm_28(const uint32_t* a) { (void)a; return 0; }

/* VMM 0D (page, n, and, or): _PageModifyPermissions, the old permissions
 * back (-1 fails). kernel32 reads them with (and 0, or 20060000h) and puts
 * them back with or 20000000h, the writable bit (0xBFF85ACB, copy-on-write).
 * Every host page stays read/write/execute: report them writable, user. */
static uint32_t vmm_page_modify(const uint32_t* a) { (void)a; return 0x20060000u; }

/* VMM 0A (base, flags): release a whole reservation. VirtualFree's
 * MEM_RELEASE path calls it with (base, 0) (0xBFF84200); kernel32's module
 * and heap teardown with flags 10h. */
static uint32_t vmm_page_free(const uint32_t* a) {
    return VirtualFree((void*)(uintptr_t)a[0], 0, MEM_RELEASE);
}

/* VWIN32 6 (data, entry1, entry2): kernel32 registers where VWIN32 calls
 * back into it (two code entries and a block). Kept for when a callback
 * has to be delivered (APCs, exceptions). */
uint32_t g_vwin32_callbacks[3];
static uint32_t vwin32_set_callbacks(const uint32_t* a) {
    for (int i = 0; i < 3; i++) g_vwin32_callbacks[i] = a[i];
    return 1;
}

/* VWIN32 47 (env): kernel32 tells VWIN32 where the first process's
 * environment now lives (it copied it out of the DOS VM). Nothing to keep. */
static uint32_t vwin32_set_env(const uint32_t* a) { (void)a; return 0; }

/* VMM service 5: the ring-0 heap's _HeapAllocate(nbytes, flags), flags bit 0
 * = HEAPZEROINIT. (Service 6 is NOT _HeapFree: see vmm_context_create.) */
static HANDLE vmm_heap(void) { static HANDLE h; if (!h) h = HeapCreate(0, 0, 0); return h; }
static uint32_t vmm_heap_alloc(const uint32_t* a) {
    return (uint32_t)(uintptr_t)HeapAlloc(vmm_heap(), (a[1] & 1) ? HEAP_ZERO_MEMORY : 0, a[0] ? a[0] : 1);
}
/* VMM service 10h (block, flags): _HeapFree of a service-5 block
 * (0xBFF7CF3B frees kernel32's ring-0 allocations through it). */
static uint32_t vmm_heap_free(const uint32_t* a) { return a[0] ? HeapFree(vmm_heap(), 0, (void*)(uintptr_t)a[0]) : 1; }
/* VMM service 0Ch (block, nbytes, flags): _HeapReAllocate of a service-5 block
 * (a process's handle table at PDB+44h grows through it, 0xBFF7D7B0). */
static uint32_t vmm_heap_realloc(const uint32_t* a) {
    if (!a[0]) return vmm_heap_alloc(a + 1);
    return (uint32_t)(uintptr_t)HeapReAlloc(vmm_heap(), (a[2] & 1) ? HEAP_ZERO_MEMORY : 0, (void*)(uintptr_t)a[0], a[1] ? a[1] : 1);
}

/* VMM service 6, no arguments: a new memory context, kept in the process
 * database at +1C (beside +24, the PSP's linear address). Every guest
 * process shares the host's one address space: a nonzero cookie. */
static uint32_t vmm_context_create(const uint32_t* a) { static uint32_t n; (void)a; return 0xC0DE0000u + ++n; }
/* VMM 7 (ctx): a dead process's memory context (PDB+1C, 0xBFF8D3CA and
 * 0xBFF8D9B4) destroyed. A cookie: nothing to free. */
static uint32_t vmm_context_destroy(const uint32_t* a) { (void)a; return 1; }
/* VMM 8 (page, ctx, srcpage, n): _PageAttach, a module's pages mapped into a
 * new process's context (kernel32 attaches MPR.DLL's for MPREXE). One address
 * space: already there. */
static uint32_t vmm_page_attach(const uint32_t* a) { (void)a; return 1; }

/* VWIN32 4F (fn, handle, 0, 0): 33h registers a kernel32 object (a process) with
 * VWIN32's ring-0 side, 34h drops it. The host keeps no ring-0 twin. */
static uint32_t vwin32_obj_fn(const uint32_t* a) { return a[0] == 0x33 || a[0] == 0x34; }

/* VWIN32 32 (obj): kernel32 releases an object's ring-0 part just before it
 * clears the object. Nothing on the host side. */
static uint32_t vwin32_obj_release(const uint32_t* a) { (void)a; return 0; }

/* VWIN32 64 (pairs, n): after a process's priority class changes
 * (PDB+A0: 4/8/0Dh/18h), kernel32 hands VWIN32 n {ring-0 thread
 * (thread+54), priority} pairs to reschedule (0xBFF8F69D). The host's
 * threads keep their own priority. */
static uint32_t vwin32_set_priorities(const uint32_t* a) { (void)a; return 0; }

/* VWIN32 8 (thread, process, ctx, flags, sel, entry, sel, esp, &tdbx): a
 * new thread's ring-0 twin (0xBFF86828; the result -> thread+54, and the
 * TDBX goes to *a[8] = thread+58). kernel32 has built the thread's first
 * frame at esp for entry 0xBFF72170: ds es fs gs, popad, popfd, VWIN32
 * 9(-1), then ret to 0xBFF868EC with the start address and parameter.
 * The twin keeps entry and esp (R0T_ENTRY/ESP) for when it is run.
 * It runs on a host thread from VWIN32 36 (below). */
#define R0T_ENTRY 0x20
#define R0T_ESP   0x24
#define R0T_THREAD 0x28
#define R0T_PROCESS 0x38
#define R0T_TDBX   0x3C
#define R0T_SS     0x54      /* the stack selector of esp (a[6]) */
static void track_thread(uint32_t r0);
static void note_tid(uint32_t r0);
/* A TDBX: +0 its thread, +4 its process (ExitProcess reads it, 0xBFF89768),
 * +50 -> the current PSP selector. */
static uint32_t new_tdbx(uint32_t thread, uint32_t process) {
    uint8_t* tdbx = calloc(1, 0x100);
    *(uint32_t*)(tdbx + 0x00) = thread;
    *(uint32_t*)(tdbx + 0x04) = process;
    *(uint32_t*)(tdbx + 0x50) = (uint32_t)(uintptr_t)&g_cur_psp;
    return (uint32_t)(uintptr_t)tdbx;
}
static uint32_t vwin32_create_thread(const uint32_t* a) {
    uint8_t* r0 = calloc(1, 0x100);
    track_thread((uint32_t)(uintptr_t)r0);
    *(uint32_t*)(r0 + R0T_ENTRY) = a[5];
    *(uint32_t*)(r0 + R0T_ESP) = a[7];
    *(uint32_t*)(r0 + R0T_SS) = a[6];
    *(uint32_t*)(r0 + R0T_THREAD) = a[0];
    MEM32(a[8]) = new_tdbx(a[0], a[1]);
    *(uint32_t*)(r0 + R0T_PROCESS) = a[1];
    *(uint32_t*)(r0 + R0T_TDBX) = MEM32(a[8]);
    if (g_trace > 0) fprintf(stderr, "[vxd] new thread %08X: entry %04X:%08X esp %04X:%08X\n", a[0], a[4], a[5], a[6], a[7]);
    return (uint32_t)(uintptr_t)r0;
}

/* Guest threads. Each runs on a host thread under native32's machine lock;
 * a guest thread that blocks in a service (w9x_wait) gives the machine up.
 * VWIN32 A (r0thread, 0) makes a created thread runnable (0xBFF72151,
 * right after CreateThread / CreateProcess build one); it starts on the
 * first VWIN32 36 (r0thread), with which the creator lets it run until it
 * blocks (_INIT does that for its service thread, 0xBFFC7014).
 * The thread's first frame (VWIN32 8) is popped by 0xBFF72170, whose `ret`
 * returns here (lifted code returns in C): the frame's next word is where
 * it was going (0xBFF868EC), entered as a jump. */
#define R0T_READY  0x2C
#define R0T_PARKED 0x30      /* host event: the thread blocked or ended */
#define R0T_WAKE   0x34
#define R0T_KILL   0x50      /* a termination block queued by VWIN32 B */      /* host event: what a blocked thread sleeps on */
static uint32_t g_boot_r0;          /* the first thread's twin (VWIN32 0C) */
static __declspec(thread) uint32_t t_r0;   /* this host thread's guest r0 twin, 0 for the boot thread */

/* A thread's termination, on the thread: VWIN32 first calls the routine
 * _INIT gave VWIN32 0C at +24 (0xBFF89912: DLL_THREAD_DETACH, USER's
 * signal 20h, thread exit, which frees the thread's queue; process exit
 * when it is the last), then blk's own (+8, 0xBFF89302: the thread object's
 * teardown, which frees its TIB selector). ponytail: the order and the
 * "always" are read off what each needs (89912 runs on the live TIB). */
static uint32_t g_k32_thread_term;   /* 0C's +24 */
static void run_termination(uint32_t blk) {
    uint32_t arg[1] = { blk };
    if (g_k32_thread_term) native32_call_guest(g_k32_thread_term, 0, NULL);
    native32_call_guest(MEM32(blk + 8), 1, arg);
}

static DWORD w9x_wait(HANDLE h, DWORD ms) {
    uint16_t sds = g_seg_ds, ses = g_seg_es, sfs = g_seg_fs, sgs = g_seg_gs;
    uint32_t bds = g_ds_base, bes = g_es_base, bgs = g_gs_base;
    uint32_t cur[3] = { g_cur[0], g_cur[1], g_cur[2] };
    if (t_r0) SetEvent((HANDLE)(uintptr_t)MEM32(t_r0 + R0T_PARKED));
    DWORD rc = native32_wait(h, ms);
    g_seg_ds = sds; g_seg_es = ses; g_seg_fs = sfs; g_seg_gs = sgs;
    g_ds_base = bds; g_es_base = bes; g_gs_base = bgs;
    g_cur[0] = cur[0]; g_cur[1] = cur[1]; g_cur[2] = cur[2];   /* this thread is VWIN32's current one again */
    if (t_r0 && MEM32(t_r0 + R0T_KILL)) {    /* VWIN32 B from another thread: run the teardown here (it ends in 2B) */
        uint32_t blk = MEM32(t_r0 + R0T_KILL);
        MEM32(t_r0 + R0T_KILL) = 0;
        if (g_trace > 0) fprintf(stderr, "[vxd] thread %08X (r0 %08X): its termination runs\n", g_cur[0], t_r0);
        run_termination(blk);
    }
    return rc;
}

/* A blocking wait from 16-bit code (VWIN32_EventWait): the machine is given up meanwhile. */
uint32_t native32_w9x_wait(void* h, uint32_t ms) { return w9x_wait((HANDLE)h, ms); }

/* Whichever guest thread takes the machine (a back-edge hand-over as much as
 * a wait coming back) is VWIN32's current one. */
static void w9x_on_enter(void) {
    uint32_t r0 = t_r0 ? t_r0 : g_boot_r0;
    if (!r0 || !MEM32(r0 + R0T_THREAD)) return;
    g_cur[0] = MEM32(r0 + R0T_THREAD); g_cur[1] = MEM32(r0 + R0T_PROCESS); g_cur[2] = MEM32(r0 + R0T_TDBX);
}
static DWORD WINAPI guest_thread(LPVOID p) {
    t_r0 = (uint32_t)(uintptr_t)p;
    note_tid(t_r0);
    mach_enter();
    g_cur[0] = MEM32(t_r0 + R0T_THREAD); g_cur[1] = MEM32(t_r0 + R0T_PROCESS); g_cur[2] = MEM32(t_r0 + R0T_TDBX);
    g_esp = MEM32(t_r0 + R0T_ESP);
    recomp_set_seg(2, MEM32(t_r0 + R0T_SS));   /* a host thread starts with ss 0: 16-bit code would take esp as a 16-bit sp */
    recomp_func_t f = recomp_lookup(MEM32(t_r0 + R0T_ENTRY));
    if (f) {
        f();
        uint32_t next = MEM32(g_esp - 4);
        if (g_trace > 0) fprintf(stderr, "[vxd] thread %08X: on to %08X\n", MEM32(t_r0 + R0T_THREAD), next);
        if ((f = recomp_lookup(next)) != NULL) f();
    }
    if (g_trace > 0) fprintf(stderr, "[vxd] thread %08X ended\n", MEM32(t_r0 + R0T_THREAD));
    mach_leave();
    SetEvent((HANDLE)(uintptr_t)MEM32(t_r0 + R0T_PARKED));
    return 0;
}

static void start_thread(uint32_t r0) {
    if (MEM32(r0 + R0T_PARKED)) return;
    native32_on_enter = w9x_on_enter;
    MEM32(r0 + R0T_PARKED) = (uint32_t)(uintptr_t)CreateEventA(NULL, FALSE, FALSE, NULL);
    /* 16 MB reserved: lifted loops that cross function blocks recurse (GDI seg 5 2DBE/2DE9
     * walks a 1024-slot table as a call per empty slot) */
    CloseHandle(CreateThread(NULL, 16u << 20, guest_thread, (LPVOID)(uintptr_t)r0, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL));
}

/* A ready thread starts on its host thread at once; it waits for the
 * machine until the running thread blocks. */
static uint32_t vwin32_ready_thread(const uint32_t* a) {
    if (!a[0]) return 0;
    MEM32(a[0] + R0T_READY) = 1;
    if (g_trace > 0) fprintf(stderr, "[vxd] thread %08X ready\n", MEM32(a[0] + R0T_THREAD));
    start_thread(a[0]);
    return 0;
}

static uint32_t vwin32_run_thread(const uint32_t* a) {
    uint32_t r0 = a[0];
    if (!r0 || !MEM32(r0 + R0T_READY)) return 0;
    start_thread(r0);
    w9x_wait((HANDLE)(uintptr_t)MEM32(r0 + R0T_PARKED), INFINITE);
    return 0;
}

/* VWIN32 5D (n, objs, ms, all, alertable): block on n of kernel32's wait
 * blocks (WaitForMultipleObjects' ring-0 half, 0xBFF99AE7; kernel32 has
 * already found none signaled). The thread sleeps on its wake event until
 * another thread wakes one of the blocks (see vxd_wake) or the time runs
 * out: the result is the woken block's index, 102h on timeout, C0h for an
 * APC. Waits are kept per thread (R0T_WAITS).
 * ponytail: wait-all is treated as wait-any; kernel32 re-checks. */
#define R0T_WAITN  0x40
#define R0T_WAITS  0x44
#define R0T_WOKEN  0x48
#define MAXTHREADS 64
static uint32_t g_threads[MAXTHREADS];     /* every r0 twin, for vxd_wake */
static int g_nthreads;
static HANDLE thread_wake(void);
static void track_thread(uint32_t r0) { if (g_nthreads < MAXTHREADS) g_threads[g_nthreads++] = r0; }
static DWORD g_tids[MAXTHREADS];           /* the host thread each runs on, for the dump */
static void note_tid(uint32_t r0) { for (int t = 0; t < g_nthreads; t++) if (g_threads[t] == r0) g_tids[t] = GetCurrentThreadId(); }
static uint32_t g_console_obj;   /* VCOND 2's object: its input is the host's stdin */
/* Mutexes (kernel32 type 3, 0xBFF8CAA2: 18h bytes, +4 0, +8 1): Win98's
 * WaitForSingleObject goes straight to ring 0 (0xBFF99B28), which owns
 * them; CreateMutex(TRUE) is a 5C with 0 ms, ReleaseMutex is 5F (0xBFF92DC1).
 * Owner and recursion are kept here, by object. ponytail: 64 mutexes, no
 * abandonment when an owner dies, wait-all still wait-any. */
#define MAXMUTEX 64
static struct { uint32_t obj, owner, n; } g_mutex[MAXMUTEX];
static int mutex_slot(uint32_t obj) {
    int f = -1;
    for (int i = 0; i < MAXMUTEX; i++) { if (g_mutex[i].obj == obj) return i; if (f < 0 && !g_mutex[i].obj) f = i; }
    if (f >= 0) { g_mutex[f].obj = obj; g_mutex[f].owner = 0; g_mutex[f].n = 0; }
    return f;
}
static int is_mutex(uint32_t obj) { return obj && MEM8(obj) == 3; }
static uint32_t vwin32_release_mutex(const uint32_t* a) {
    int m = is_mutex(a[0]) ? mutex_slot(a[0]) : -1;
    if (m < 0 || g_mutex[m].owner != g_cur[0] || !g_mutex[m].n) return 0;
    if (--g_mutex[m].n) return 1;
    g_mutex[m].owner = 0;
    for (int t = 0; t < g_nthreads; t++) {   /* hand it to one waiter */
        uint32_t r0 = g_threads[t], n = MEM32(r0 + R0T_WAITN);
        for (uint32_t i = 0; i < n; i++)
            if (MEM32(MEM32(r0 + R0T_WAITS) + 4 * i) == a[0]) {
                g_mutex[m].owner = MEM32(r0 + R0T_THREAD); g_mutex[m].n = 1;
                MEM32(r0 + R0T_WOKEN) = i; MEM32(r0 + R0T_WAITN) = 0;
                SetEvent((HANDLE)(uintptr_t)MEM32(r0 + R0T_WAKE));
                return 1;
            }
    }
    return 1;
}
/* Semaphores (kernel32 type 1, 0xBFF8F49D: 14h bytes, +8 the count, +10h
 * the maximum): ReleaseSemaphore is VWIN32 5E (sem, n, &prev), 0xBFF92D4D.
 * A wait takes one at once while the count is above 0; a release hands one
 * to each waiter it can. FALSE past the maximum. */
static int is_sem(uint32_t obj) { return obj && MEM8(obj) == 1; }
static uint32_t vwin32_release_sem(const uint32_t* a) {
    uint32_t s = a[0];
    if (!is_sem(s) || MEM32(s + 8) + a[1] > MEM32(s + 0x10)) return 0;
    if (a[2]) MEM32(a[2]) = MEM32(s + 8);
    MEM32(s + 8) += a[1];
    for (int t = 0; t < g_nthreads && MEM32(s + 8); t++) {
        uint32_t r0 = g_threads[t], n = MEM32(r0 + R0T_WAITN);
        for (uint32_t i = 0; i < n; i++)
            if (MEM32(MEM32(r0 + R0T_WAITS) + 4 * i) == s) {
                MEM32(s + 8)--;
                MEM32(r0 + R0T_WOKEN) = i; MEM32(r0 + R0T_WAITN) = 0;
                SetEvent((HANDLE)(uintptr_t)MEM32(r0 + R0T_WAKE));
                break;
            }
    }
    return 1;
}
/* For a watchdog: every ring-0 twin's thread, host thread and wait list, and
 * each held mutex. */
void native32_w9x_dump_threads(void) {
    for (int t = 0; t < g_nthreads; t++) {
        uint32_t r0 = g_threads[t], n = MEM32(r0 + R0T_WAITN);
        fprintf(stderr, "  r0 %08X thread %08X process %08X host %lu waits", r0, MEM32(r0 + R0T_THREAD), MEM32(r0 + R0T_PROCESS), g_tids[t]);
        for (uint32_t i = 0; i < n && i < 8; i++) fprintf(stderr, " %08X", MEM32(MEM32(r0 + R0T_WAITS) + 4 * i));
        fprintf(stderr, "\n");
    }
    for (int m = 0; m < MAXMUTEX; m++)
        if (g_mutex[m].obj && g_mutex[m].owner) fprintf(stderr, "  mutex %08X owner %08X x%u\n", g_mutex[m].obj, g_mutex[m].owner, g_mutex[m].n);
}
static uint32_t vwin32_wait_multiple(const uint32_t* a) {
    /* A wait on the console (ReadFile on a console handle, 0xBFF774E4)
     * waits for input: always ready, the read itself blocks on stdin. */
    for (uint32_t i = 0; g_console_obj && i < a[0]; i++)
        if (MEM32(a[1] + 4 * i) == g_console_obj) return i;
    for (uint32_t i = 0; i < a[0]; i++) {   /* a free (or our own) mutex is taken at once */
        uint32_t o = MEM32(a[1] + 4 * i);
        int m = is_mutex(o) ? mutex_slot(o) : -1;
        if (m >= 0 && (!g_mutex[m].owner || g_mutex[m].owner == g_cur[0])) { g_mutex[m].owner = g_cur[0]; g_mutex[m].n++; return i; }
    }
    for (uint32_t i = 0; i < a[0]; i++) {   /* already signalled (an event set before the wait: MPREXE's for MPR) */
        uint32_t o = MEM32(a[1] + 4 * i), w;
        if (!o || is_mutex(o)) continue;
        if (is_sem(o)) { if (MEM32(o + 8)) { MEM32(o + 8)--; return i; } continue; }
        w = MEM32(o + 4) > 0xFFFFu ? MEM32(o + 4) : o;   /* an object's +4 is its wait block; a block's +4 its count */
        if (MEM32(w + 4)) { if (!MEM32(w + 8)) MEM32(w + 4) = 0; return i; }
    }
    uint32_t r0 = t_r0 ? t_r0 : g_boot_r0;
    MEM32(r0 + R0T_WAITN) = a[0];
    MEM32(r0 + R0T_WAITS) = a[1];
    MEM32(r0 + R0T_WOKEN) = 0xFFFFFFFFu;
    if (g_trace > 0) fprintf(stderr, "[vxd] thread %08X waits on %u blocks (%d ms), first %08X\n", g_cur[0], a[0], (int)a[2], MEM32(a[1]));
    DWORD rc = w9x_wait(thread_wake(), a[2]);
    MEM32(r0 + R0T_WAITN) = 0;
    if (rc == WAIT_TIMEOUT) return 0x102;
    return MEM32(r0 + R0T_WOKEN) == 0xFFFFFFFFu ? 0xC0 : MEM32(r0 + R0T_WOKEN);
}

/* VWIN32 5C (blk, ms, alertable): 5D for one block (WaitForSingleObject's
 * ring-0 half, 0xBFF99B28): 0, 102h or C0h. */
static uint32_t vwin32_wait_single(const uint32_t* a) {
    uint32_t objs[1] = { a[0] };
    uint32_t m[5] = { 1, (uint32_t)(uintptr_t)objs, a[1], 0, a[2] };
    return vwin32_wait_multiple(m);
}

/* VWIN32 2D (ms, alertable): block this thread (SleepEx, 0xBFF88BB0):
 * C0h when woken for an APC, 102h on timeout. The thread gives up the
 * machine meanwhile, on its wake event (R0T_WAKE). */
static HANDLE thread_wake(void) {
    uint32_t r0 = t_r0 ? t_r0 : g_boot_r0;
    if (!MEM32(r0 + R0T_WAKE)) MEM32(r0 + R0T_WAKE) = (uint32_t)(uintptr_t)CreateEventA(NULL, FALSE, FALSE, NULL);
    return (HANDLE)(uintptr_t)MEM32(r0 + R0T_WAKE);
}
static uint32_t vwin32_block(const uint32_t* a) {
    if (g_trace > 0) fprintf(stderr, "[vxd] thread %08X blocks (%d ms)\n", g_cur[0], (int)a[0]);
    DWORD rc = w9x_wait(thread_wake(), a[0]);
    return rc == WAIT_TIMEOUT ? 0x102 : 0xC0;
}

/* VWIN32 26 (r0thread, r0other): ties a thread's ring-0 twin to another
 * thread's of the same process: a starting thread to its process's first
 * (0xBFF8697A), a new thread to the boot thread (0xBFF89B55). Host threads
 * share everything already. */
static uint32_t vwin32_link_thread(const uint32_t* a) { (void)a; return 0; }

/* VWIN32's 16-bit API 01 (ebx = r0 thread, ecx): KRNL386's task switch
 * (seg1 73BA, from Reschedule 5F54 and the boot thread's idle loop 7404):
 * after leaving the Win16 lock it hands the CPU to the next task's thread
 * and sleeps until a switch comes back to it. A thread not yet run (a new
 * task's, created suspended by kernel32) starts here.
 * ponytail: ecx (0 or F01h) is not read; every switch blocks the caller
 * until woken, which the callers' loops re-check. */
void native32_w9x_switch_to(uint32_t r0) {
    if (g_trace > 0) fprintf(stderr, "[vxd] switch from %08X to r0 %08X (thread %08X; this r0 %08X)\n", g_cur[0], r0, r0 ? MEM32(r0 + R0T_THREAD) : 0, t_r0 ? t_r0 : g_boot_r0);
    if (!r0 || r0 == (t_r0 ? t_r0 : g_boot_r0)) return;   /* to itself: nothing to switch */
    {
        if (!MEM32(r0 + R0T_PARKED)) { MEM32(r0 + R0T_READY) = 1; start_thread(r0); }
        else {
            if (!MEM32(r0 + R0T_WAKE)) MEM32(r0 + R0T_WAKE) = (uint32_t)(uintptr_t)CreateEventA(NULL, FALSE, FALSE, NULL);
            SetEvent((HANDLE)(uintptr_t)MEM32(r0 + R0T_WAKE));
        }
    }
    w9x_wait(thread_wake(), INFINITE);
}

/* VCOND (VxD 38h), the console. 23 (6, &info, sysdir): kernel32's service
 * thread (0xBFF91450) introduces itself once, with the system directory
 * (where CONAGENT.EXE lives); nothing reads the info block (0xBFFC9D30)
 * back. The host's console needs no agent. */
static uint32_t vcond_init(const uint32_t* a) { (void)a; return 0; }

/* VCOND 1F (): right after the console agent is started (0xBFFA2092), the
 * new console's object, which kernel32 flags at +10 (|= 20h). On Win98 the
 * agent builds it by calling back into kernel32 (16-bit entry 0xBFF941D9 ->
 * 0xBFF8E9E1 (info, word)): a 0x470-byte object with its crst at +20, two
 * buffers at +40/+44, +150 the VCOND handle (from VCOND 2), +46C an event.
 * The host has no agent, so it runs that constructor itself, on the
 * creating thread, and puts back the process's +B0 the constructor sets
 * (the agent's, on Win98). */
static uint32_t vcond_new_console(const uint32_t* a) {
    static uint8_t info[0x100];
    uint32_t pdb = g_cur[1], b0 = MEM32(pdb + 0xB0);
    uint32_t saved[8] = { g_eax, g_ecx, g_edx, g_ebx, g_esp, g_ebp, g_esi, g_edi };
    uint32_t args[2] = { (uint32_t)(uintptr_t)info, 0 };
    (void)a;
    native32_call_guest(0xBFF8E9E1, 2, args);
    uint32_t c = g_eax;
    g_eax = saved[0]; g_ecx = saved[1]; g_edx = saved[2]; g_ebx = saved[3];
    g_esp = saved[4]; g_ebp = saved[5]; g_esi = saved[6]; g_edi = saved[7];
    MEM32(pdb + 0xB0) = b0;
    if (g_trace > 0) fprintf(stderr, "[vcond] console object %08X\n", c);
    return c;
}

/* VCOND 1 (h, buf, n): text for the console's teletype, the DOS box's
 * screen (WriteConsole's output path, 0xBFFA367E; single bytes from
 * 0xBFFCADA8/0xBFFCADB0 for line ends). The host console is stdout. */
static uint32_t vcond_write(const uint32_t* a) {
    DWORD n = 0;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), (void*)(uintptr_t)a[1], a[2], &n, NULL);
    return 0;
}

/* VCOND 2 (info, obj): the constructor registers the object; the result is
 * its handle (+150; -1 fails). The object itself serves. */
static uint32_t vcond_register(const uint32_t* a) { return g_console_obj = a[1]; }

/* VCOND services the attach (0xBFFA2100) and the console set-up call on the
 * console handle (+150) that need nothing from a host console: 18 (h) and
 * 1E (h, x) leave a value at +1C, 0E (h, 17h), 13 (h) once the process owns
 * it, 14 (h, exit code low byte / -1 / 8) when a process lets it go
 * (0xBFF9090A, 0xBFF90E7A). All answer 0. */
static uint32_t vcond_zero(const uint32_t* a) { (void)a; return 0; }

/* VCOND F (h): the input mode ReadConsole (0xBFFA5F98) and GetConsoleMode
 * (0xBFFA27B4) see: 1 processed, 2 line input, 4 echo (the console's
 * default, 7). kernel32 does the line editing and the echo itself, reading
 * one byte at a time with VCOND 10 (h, buf, n, 1) -> bytes read
 * (0xBFFA5CC1). The host's stdin serves (scripted input); a bare LF is
 * taken as CR, which is what a console's Enter gives. At EOF, CR then ^Z.
 * ponytail: the read blocks under the machine lock; fine for one console
 * thread, a reader thread + w9x_wait if a GUI ever shares it. */
static uint32_t vcond_input_mode(const uint32_t* a) { (void)a; return 7; }
static uint32_t vcond_read(const uint32_t* a) {
    static int eof;
    uint8_t* p = (uint8_t*)(uintptr_t)a[1];
    DWORD n = 0;
    if (!a[2]) return 0;
    if (eof || !ReadFile(GetStdHandle(STD_INPUT_HANDLE), p, 1, &n, NULL) || !n) {
        *p = eof++ ? 0x1A : '\r';
        return 1;
    }
    if (*p == '\n') *p = '\r';
    else if (*p == '\r') {   /* CRLF: drop the LF that follows */
        static uint8_t skip; DWORD m = 0;
        PeekNamedPipe(GetStdHandle(STD_INPUT_HANDLE), &skip, 1, &m, NULL, NULL);
        if (m && skip == '\n') ReadFile(GetStdHandle(STD_INPUT_HANDLE), &skip, 1, &m, NULL);
    }
    return 1;
}

/* VWIN32 1D (crst) / 1E (crst): a critical section's contention. kernel32's
 * EnterCriticalSection (0xBFF741B4) calls 1D when another thread owns it
 * and then returns as the owner, so the hand-over happens here: 1E, from
 * LeaveCriticalSection when the count says someone waits (0xBFF74268),
 * makes the first waiter the owner (+08 its TDBX, +04 recursion 1) and
 * wakes it. A crst is {+04 recursion, +08 owner TDBX, +10 lock count}. */
#define R0T_CRST 0x4C
static uint32_t vwin32_crst_wait(const uint32_t* a) {
    uint32_t r0 = t_r0 ? t_r0 : g_boot_r0;
    MEM32(r0 + R0T_CRST) = a[0];
    if (g_trace > 0) fprintf(stderr, "[vxd] thread %08X waits for crst %08X (owner %08X)\n", g_cur[0], a[0], MEM32(a[0] + 8));
    while (MEM32(r0 + R0T_CRST)) w9x_wait(thread_wake(), INFINITE);
    return 0;
}
static uint32_t vwin32_crst_wake(const uint32_t* a) {
    for (int t = 0; t < g_nthreads; t++) {
        uint32_t r0 = g_threads[t];
        if (MEM32(r0 + R0T_CRST) != a[0]) continue;
        MEM32(r0 + R0T_CRST) = 0;
        MEM32(a[0] + 8) = MEM32(r0 + R0T_TDBX);
        MEM32(a[0] + 4) = 1;
        if (!MEM32(r0 + R0T_WAKE)) MEM32(r0 + R0T_WAKE) = (uint32_t)(uintptr_t)CreateEventA(NULL, FALSE, FALSE, NULL);
        SetEvent((HANDLE)(uintptr_t)MEM32(r0 + R0T_WAKE));
        return 0;
    }
    return 0;
}

/* Wake every thread waiting on wait block obj; returns how many. A wait
 * lists wait blocks or kernel32 objects (a process, a thread), whose +4 is
 * their wait block (the process at 0xBFF8CDxx signals PDB+4). */
static int vxd_wake(uint32_t obj) {
    int woke = 0;
    for (int t = 0; t < g_nthreads; t++) {
        uint32_t r0 = g_threads[t], n = MEM32(r0 + R0T_WAITN);
        for (uint32_t i = 0; i < n; i++)
            if (MEM32(MEM32(r0 + R0T_WAITS) + 4 * i) == obj || MEM32(MEM32(MEM32(r0 + R0T_WAITS) + 4 * i) + 4) == obj) {
                MEM32(r0 + R0T_WOKEN) = i;
                MEM32(r0 + R0T_WAITN) = 0;
                SetEvent((HANDLE)(uintptr_t)MEM32(r0 + R0T_WAKE));
                woke++;
                break;
            }
    }
    return woke;
}

/* VWIN32 B (r0thread, blk): a thread's termination (ExitProcess,
 * 0xBFF89628, for any thread but the boot one, 0xBFFC9CF8). blk is the
 * thread's +1F4: {+0 thread, +8 0xBFF89302, the routine that tears it
 * down}. On Win98 the thread runs blk's routine itself; for the calling
 * thread that is a call, here. Another thread's would have to be delivered
 * to it: not needed yet, so it stops the run. */
static uint32_t vwin32_terminate_thread(const uint32_t* a) {
    uint32_t r0 = t_r0 ? t_r0 : g_boot_r0;
    if (a[0] != r0) {   /* delivered at the thread's next wake (w9x_wait) */
        if (g_trace > 0) fprintf(stderr, "[vxd] thread %08X: termination queued\n", MEM32(a[0] + R0T_THREAD));
        MEM32(a[0] + R0T_KILL) = a[1];
        if (!MEM32(a[0] + R0T_WAKE)) MEM32(a[0] + R0T_WAKE) = (uint32_t)(uintptr_t)CreateEventA(NULL, FALSE, FALSE, NULL);
        SetEvent((HANDLE)(uintptr_t)MEM32(a[0] + R0T_WAKE));
        return 0;
    }
    run_termination(a[1]);
    return 0;
}

/* VWIN32 D (fn, arg, r0thread): queue fn(arg) (stdcall) to a thread, always
 * kernel32's service thread (0xBFFC9D0C) at the call sites: a dying
 * thread's cleanup (0xBFF894A4, fn 0xBFF996CD), ExitProcess (0xBFF89714),
 * the console's teardown (0xBFF908D6). ponytail: run now, on the caller,
 * under the machine lock; deliver it to the service thread if a fn ever
 * needs to be on it. */
static uint32_t vwin32_queue_to_thread(const uint32_t* a) {
    uint32_t saved[8] = { g_eax, g_ecx, g_edx, g_ebx, g_esp, g_ebp, g_esi, g_edi };
    uint32_t arg[1] = { a[1] };
    native32_call_guest(a[0], 1, arg);
    g_eax = saved[0]; g_ecx = saved[1]; g_edx = saved[2]; g_ebx = saved[3];
    g_esp = saved[4]; g_ebp = saved[5]; g_esi = saved[6]; g_edi = saved[7];
    return 1;
}

/* VWIN32 58 (x): a dying thread's +58 handed back (0xBFF89C97, then
 * cleared; the result unread). Nothing on the host holds it. */
static uint32_t vwin32_release_58(const uint32_t* a) { (void)a; return 0; }

/* VWIN32 2C (ebx at entry): the end of 0C's +24 thread-termination routine
 * (0xBFF89A4E), handing ring 0 back the ebx it was entered with. Here the
 * routine is a plain call (run_termination), so there is nothing to resume. */
static uint32_t vwin32_term_done(const uint32_t* a) { (void)a; return 0; }

/* VMM 20 (blk): a block of kernel32's handed to ring 0 for the last time:
 * a mapped-file record on close (0xBFFAB776, outside the 4/5 bracket) and
 * a dying process's block (0xBFFA972A). Results unread; the host holds
 * nothing. ponytail: name it when a caller reads the result. */
static uint32_t vmm_20_release(const uint32_t* a) { (void)a; return 0; }

/* VMM 1F (r0 thread, 35h): kernel32's service thread (proc 0xBFF91AC5),
 * once per turn of its loop (0xBFF91B94, after its work in 0xBFF8502C),
 * on itself: it sleeps there until there is more work. ponytail: blocks on
 * the thread's wake event (nothing sets it; the loop's work, Ctrl+Alt+Del
 * and process clean-up, has no host source yet); 35h not read. */
static HANDLE thread_wake(void);
static uint32_t vmm_1f_sleep(const uint32_t* a) { (void)a; w9x_wait(thread_wake(), INFINITE); return 0; }

/* VWIN32 2B (): the calling thread is done (the end of ExitThread/
 * ExitProcess, 0xBFF89EBE, looping if it ever came back). Its host thread
 * gives the machine up for good. ponytail: it stays parked, not ended, so
 * nothing unwinds through lifted frames; ExitThread if threads pile up. */
static uint32_t vwin32_thread_done(const uint32_t* a) {
    uint32_t r0 = t_r0 ? t_r0 : g_boot_r0;
    (void)a;
    if (g_trace > 0) fprintf(stderr, "[vxd] thread %08X ended (VWIN32 2B)\n", g_cur[0]);
    if (MEM32(r0 + R0T_PARKED)) SetEvent((HANDLE)(uintptr_t)MEM32(r0 + R0T_PARKED));
    HANDLE never = CreateEventA(NULL, TRUE, FALSE, NULL);
    for (;;) native32_wait(never, INFINITE);
}

/* VWIN32 9 (-1): a new thread's first call, from its start frame
 * (0xBFF72178) before it goes to its start routine. Nothing to wait for. */
static uint32_t vwin32_thread_starting(const uint32_t* a) { (void)a; return 0; }

/* VWIN32 21 (r0thread, priority): set a thread's priority in its ring-0
 * twin and return the field's offset there: CreateThread keeps r0thread +
 * the result as the TIB's pCurrentPriority (thread+2C, 0xBFF86850). */
#define R0T_PRIORITY 0x10
/* VWIN32 13 (r0 thread, 1000h): kernel32 0xBFF91A8E, right after it creates
 * its own service thread (proc 0xBFF91AC5, 4 KB stack) for the first Win16
 * task; the result is not read. ponytail: unknown meaning (a stack/commit
 * size for the thread?); answered 0 and nothing kept. */
static uint32_t vwin32_13(const uint32_t* a) { (void)a; return 0; }

/* REBOOT (VxD 9) 0 (proc 0xBFFAA127, r0 thread): kernel32's service thread
 * (0xBFF91B3D) hands it its Ctrl+Alt+Del ("close program") callback. The
 * host has no such key path: ponytail: kept nowhere, 0. */
static uint32_t reboot_0(const uint32_t* a) { (void)a; return 0; }
/* REBOOT 1 (0, 0): right after 0, before the thread's own loop (0xBFF91B44);
 * the result is not read. ponytail: no-op (no Ctrl+Alt+Del path to arm). */

static uint32_t vwin32_set_thread_priority(const uint32_t* a) {
    if (a[0]) MEM32(a[0] + R0T_PRIORITY) = a[1];
    return R0T_PRIORITY;
}

/* VWIN32 60/61/62 (waitblk): SetEvent (0xBFF92BAE), PulseEvent (0xBFF92BE6)
 * and ResetEvent (0xBFF92C1E) go through these wrappers (0xBFF92D66..88),
 * as do a fresh file object (0xBFF80215), a dying thread (0xBFF8CC9F) and
 * ExitProcess (0xBFF89610). A wait block (0xBFF7E4BA, 10h bytes) has +4 its
 * signal count and +8 manual-reset. 60 signals it and wakes its waiters (an
 * auto-reset one goes back to 0 once it has woken one), 61 wakes them and
 * leaves it reset, 62 resets it. TRUE. */
static uint32_t vwin32_set_event(const uint32_t* a) {
    MEM32(a[0] + 4) = 1;
    if (vxd_wake(a[0]) && !MEM32(a[0] + 8)) MEM32(a[0] + 4) = 0;
    return 1;
}
static uint32_t vwin32_pulse_event(const uint32_t* a) { vxd_wake(a[0]); MEM32(a[0] + 4) = 0; return 1; }
static uint32_t vwin32_reset_event(const uint32_t* a) { MEM32(a[0] + 4) = 0; return 1; }

/* VWIN32 30 (waitblk, 1): the first step of kernel32's wait-block destroy
 * (0xBFF92D19: then it frees +0C and, for type 3, more), e.g. when a file
 * handle closes. No ring-0 wait state on the host: nothing to release. */
static uint32_t vwin32_wait_block_destroy(const uint32_t* a) { (void)a; return 0; }

/* VWIN32 20 (&type) -> ax: the coprocessor. _INIT (0xBFFC70DF) keeps the
 * type at 0xBFFC9CF0; 0 (none) and 2 skip, anything else gets
 * HKLM\HARDWARE\...\FloatingPointProcessor\0 (boxed).
 * The host's x87: 3, a 387-class unit; ax its reset control word. */
static uint32_t vwin32_fpu_info(const uint32_t* a) { MEM32(a[0]) = 3; return 0x037F; }

/* VMM service 0B (context): switch to a memory context. One address space. */
static uint32_t vmm_context_switch(const uint32_t* a) { (void)a; return 0; }

/* VWIN32 0C (blk): the first thread's ring-0 twin. kernel32's _INIT has
 * already built the thread object (TIB at +08, its fs selector at +4C) and
 * loaded fs with it; blk (on its stack, read at 0xBFFC69DE) carries
 *   +00 thread, +04 process, +08 memory context, +20/+22 selectors,
 *   +28 the Win16 mutex, +4C kernel32's callback table, +54 an entry;
 * and VWIN32 answers in
 *   +0C the ring-0 thread (-> thread+54),
 *   +10 VWIN32's "current" triple {thread, process, TDBX}: kernel32 keeps it
 *       at 0xBFFC9CE0/4/8 and reads the current thread/process through it
 *       (TDBX -> thread+58; TDBX+50 -> a word, the current PSP selector,
 *       compared before every int 21h AH=50h),
 *   +1C/+1E selectors (-> 0xBFFC933E/933C: 933E is a PSP selector,
 *       passed to the "set PSP" helper at 0xBFF76555),
 *   +44 -> 0xBFFC9D1C (the NLS tables: lodsw lookups at +4/+14/+18),
 *   +50 -> 0xBFFC94F0 (an offset added to a selector's base).
 * ponytail: 933C and +50 left 0 until a call site needs them. */
/* VWIN32's NLS block (0C's +44, kept at 0xBFFC9D1C and in boot block +68).
 * Read off its two users in kernel32:
 *  +04 Unicode -> ANSI (0xBFF76B96): a range tree of 12-byte nodes {u16
 *      left, u16 right, u16 lo, u16 hi, u32 t}, offsets from the tree; a
 *      char in [lo, hi] maps through the table at tree + t/2, bytes if t
 *      is odd (else big-endian DBCS words); a miss writes '_'.
 *  +14/+18 case folding up to U+0586 (0xBFF76C11, the compare): +18 is a
 *      byte per char, a byte offset into +14's words, the delta to subtract.
 * Built here from the host's code page 1252 and its upper-casing. */
static uint32_t nls_block(void) {
    uint8_t* b = calloc(1, 0x20);
    uint8_t* tree = calloc(1, 12 + 0x10000);
    uint8_t* idx = calloc(1, 0x588);
    uint16_t* delta = calloc(128, 2);
    int nd = 1;
    *(uint16_t*)(tree + 6) = 0xFFFF;
    *(uint32_t*)(tree + 8) = (12u << 1) | 1;
    for (uint32_t c = 0; c < 0x10000; c++) {
        WCHAR w = (WCHAR)c; char a; BOOL def = FALSE;
        int n = WideCharToMultiByte(1252, WC_NO_BEST_FIT_CHARS, &w, 1, &a, 1, NULL, &def);
        tree[12 + c] = (n == 1 && !def) ? (uint8_t)a : '_';
    }
    for (uint32_t c = 0; c <= 0x586; c++) {
        uint16_t d = (uint16_t)(c - (uint16_t)(uintptr_t)CharUpperW((LPWSTR)(uintptr_t)c));
        int k = 0;
        while (k < nd && delta[k] != d) k++;
        if (k == nd && nd < 128) delta[nd++] = d;
        idx[c] = (uint8_t)(2 * (k < nd ? k : 0));
    }
    *(uint32_t*)(b + 0x04) = (uint32_t)(uintptr_t)tree;
    *(uint32_t*)(b + 0x14) = (uint32_t)(uintptr_t)delta;
    *(uint32_t*)(b + 0x18) = (uint32_t)(uintptr_t)idx;
    return (uint32_t)(uintptr_t)b;
}

uint16_t g_w9x_psp_sel;            /* the host's boot PSP (k32host sets it) */
void native32_w9x_set_psp(uint16_t sel) { g_cur_psp = sel; }   /* int 21h 50h from 16-bit code */
static uint32_t vwin32_first_thread(const uint32_t* a) {
    uint32_t* blk = (uint32_t*)(uintptr_t)a[0];
    g_cur[0] = blk[0]; g_cur[1] = blk[1]; g_cur[2] = new_tdbx(blk[0], blk[1]);
    g_cur_psp = g_w9x_psp_sel;
    g_k32_thread_term = blk[0x24 / 4];
    blk[0x0C / 4] = g_boot_r0 = (uint32_t)(uintptr_t)calloc(1, 0x100);   /* its ring-0 twin */
    MEM32(g_boot_r0 + R0T_THREAD) = blk[0];
    MEM32(g_boot_r0 + R0T_PROCESS) = blk[1];
    MEM32(g_boot_r0 + R0T_TDBX) = g_cur[2];
    track_thread(g_boot_r0);
    {   /* The boot process has no handle table (PDB+44): _INIT makes the
         * process with 0xBFF89CEB, which leaves it 0, and then at once opens
         * a handle to itself (0xBFFC6A72 -> 0xBFF7D747 reads [PDB+44] without
         * a check). Every other process gets one from 0xBFF89CCD: 84h bytes
         * off the VMM heap, zeroed, +0 = 10h slots. Built the same way here.
         * ponytail: whether VWIN32 does this in 0Ch or elsewhere is unread
         * (VWIN32's Win32 services live inside the compressed VMM32.VXD). */
        uint32_t pdb = blk[1];
        if (!MEM32(pdb + 0x44)) {
            uint32_t* ht = HeapAlloc(vmm_heap(), HEAP_ZERO_MEMORY, 0x84);
            ht[0] = 0x10;
            MEM32(pdb + 0x44) = (uint32_t)(uintptr_t)ht;
        }
    }
    blk[0x10 / 4] = (uint32_t)(uintptr_t)g_cur;
    ((uint16_t*)blk)[0x1C / 2] = g_w9x_psp_sel;
    ((uint16_t*)blk)[0x1E / 2] = 0;
    blk[0x44 / 4] = nls_block();
    return 0;
}

/* ---- VWIN32 10: Int21Dispatch -------------------------------------------
 * kernel32's only way to DOS (0xBFF712B9: push ecx; push eax; push 2A0010h).
 * a[0] is eax, a[1] ecx; ebx/edx/esi/edi are live in the globals and the
 * answer comes back in registers and CF. Pointers are flat (kernel32 calls
 * it from flat code). Modelled on pcrecomp dos32's int 21h, but on host
 * handles, and every path is boxed under the sandbox root (C:\ is
 * NATIVE32_W9X_ROOT). An AH (or AX for 71xx) we do not know stops the run. */
#define SET16(f, v) ((f) = ((f) & 0xFFFF0000u) | (uint16_t)(v))
#define SET8L(f, v) ((f) = ((f) & 0xFFFFFF00u) | (uint8_t)(v))
static int g_cf;                  /* the service's CF */
static void set_cf(int cf) { g_cf = cf; }
static uint16_t g_dos_err;
static void dos_fail(uint16_t err) { SET16(g_eax, err); set_cf(1); g_dos_err = err; }

/* The sandbox: guest C:\ is this host directory, and no guest path may
 * leave it (".." is resolved first, then the prefix is checked). */
static char g_root[MAX_PATH];   /* g_cwd: guest, no drive, no leading '\' */
static int host_path(uint32_t guest, char* out) {
    char g[MAX_PATH], full[2 * MAX_PATH], *p = g;
    size_t i = 0;
    if (!g_root[0]) {
        const char* r = getenv("NATIVE32_W9X_ROOT");
        GetFullPathNameA(r ? r : "root", MAX_PATH, g_root, NULL);
        CreateDirectoryA(g_root, NULL);
    }
    for (; i + 1 < sizeof g && MEM8(guest + i); i++) g[i] = (char)MEM8(guest + i);
    g[i] = 0;
    if (p[0] && p[1] == ':') {
        if ((p[0] | 0x20) != 'c') return 0;                    /* only C: exists */
        p += 2;
    }
    if (*p == '\\' || *p == '/') _snprintf(full, sizeof full, "%s%s", g_root, p);
    else _snprintf(full, sizeof full, "%s\\%s\\%s", g_root, g_cwd, p);
    full[sizeof full - 1] = 0;
    if (!GetFullPathNameA(full, MAX_PATH, out, NULL)) return 0;
    if (g_trace > 0) fprintf(stderr, "[int21]   \"%s\" -> %s\n", g, out);
    size_t n = strlen(g_root);
    if (_strnicmp(out, g_root, n) || (out[n] && out[n] != '\\')) return 0;
    return 1;
}
static void guest_put(uint32_t va, const char* s, size_t max) {
    size_t i = 0;
    for (; s[i] && i + 1 < max; i++) MEM8(va + i) = (uint8_t)s[i];
    MEM8(va + i) = 0;
}

/* DOS handles: 0-4 the std devices, the rest host handles. */
#define NHANDLES 256
static HANDLE g_fh[NHANDLES];
static HANDLE dos_handle(uint16_t h) {
    if (h <= 2) return GetStdHandle(h == 0 ? STD_INPUT_HANDLE : h == 1 ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
    return h < NHANDLES ? g_fh[h] : NULL;
}
static int dos_close(uint16_t h) {
    if (h <= 4 || h >= NHANDLES || !g_fh[h]) return h <= 4;
    CloseHandle(g_fh[h]); g_fh[h] = NULL;
    return 1;
}
static int new_handle(HANDLE fh) {
    for (int i = 5; i < NHANDLES; i++) if (!g_fh[i]) { g_fh[i] = fh; return i; }
    CloseHandle(fh);
    return -1;
}
static uint16_t host_err(void) {
    DWORD e = GetLastError();
    return e < 0x100 ? (uint16_t)e : 5;     /* Win32 errors 1-255 are DOS's own numbers */
}

/* Win32 find data, the 71h form: attrs, 3 times, size hi/lo, 8 reserved,
 * name[260], short name[14]. SI = 1: DOS date/time instead of FILETIMEs. */
static void put_find(uint32_t p, const WIN32_FIND_DATAA* fd, int dos_times) {
    const FILETIME* t[3] = { &fd->ftCreationTime, &fd->ftLastAccessTime, &fd->ftLastWriteTime };
    MEM32(p) = fd->dwFileAttributes & 0x3F;
    for (int i = 0; i < 3; i++) {
        if (dos_times) {
            FILETIME l; WORD d = 0, tm = 0;
            FileTimeToLocalFileTime(t[i], &l); FileTimeToDosDateTime(&l, &d, &tm);
            MEM32(p + 4 + 8 * i) = (uint32_t)d << 16 | tm; MEM32(p + 8 + 8 * i) = 0;
        } else { MEM32(p + 4 + 8 * i) = t[i]->dwLowDateTime; MEM32(p + 8 + 8 * i) = t[i]->dwHighDateTime; }
    }
    MEM32(p + 0x1C) = fd->nFileSizeHigh; MEM32(p + 0x20) = fd->nFileSizeLow;
    MEM32(p + 0x24) = 0; MEM32(p + 0x28) = 0;
    guest_put(p + 0x2C, fd->cFileName, 260);
    guest_put(p + 0x130, fd->cAlternateFileName, 14);
}
static uint8_t g_dta_default[128];
static uint32_t g_dta = (uint32_t)(uintptr_t)g_dta_default;   /* Int21 1Ah; DOS's default is PSP:80 */
#define NFINDS 64
static HANDLE g_find[NFINDS];
static uint16_t g_find_attr[NFINDS];
static int g_find_root[NFINDS];
/* DOS's attribute filter: CL may-have (hidden, system, directory need it), CH must-have */
static int find_ok(const WIN32_FIND_DATAA* fd, uint16_t cx) {
    uint32_t at = fd->dwFileAttributes & 0x37, may = (cx & 0xFF) | 0x21, must = cx >> 8;
    return !(at & ~may & 0x16) && (at & must) == must;
}

static void int21_unknown(uint16_t ax) {
    fprintf(stderr, "\n[vxd] Int21Dispatch: unknown AX=%04X (ebx=%08X ecx=%08X edx=%08X esi=%08X edi=%08X) from sub_%08X\n",
            ax, g_ebx, g_ecx, g_edx, g_esi, g_edi, g_cur_func);
    native32_dump_icalls(8);
    fflush(stderr);
    recomp_trace_flush();
    TerminateProcess(GetCurrentProcess(), 5);
}

static uint32_t vwin32_int21(const uint32_t* a) {
    char path[MAX_PATH], path2[MAX_PATH];
    g_eax = a[0];
    g_cf = 0;
    uint8_t ah = (uint8_t)(g_eax >> 8), al = (uint8_t)g_eax;
    uint16_t ax = (uint16_t)g_eax;
    if (g_trace > 0) fprintf(stderr, "[int21] AX=%04X ebx=%08X ecx=%08X edx=%08X esi=%08X edi=%08X\n", ax, g_ebx, g_ecx, g_edx, g_esi, g_edi);
    switch (ah) {
    case 0xEA:                                                 /* AX=EA00, kernel32 _INIT (0xBFFC6F47): BX -> 0xBFFC9CCC, */
        if (al == 0) { SET16(g_ebx, 0); return g_eax; }        /* tested before a 'NETQ' check (0xBFF7FC9B): no network */
        break;
    case 0x0D: return g_eax;                                   /* disk reset (KRNL386 at boot): nothing cached */
    case 0x0E: SET8L(g_eax, 26); return g_eax;                 /* select drive: 26 letters */
    case 0x19: SET8L(g_eax, 2); return g_eax;                  /* current drive: C: */
    case 0x1C: {   /* DL drive's allocation: AL sectors/cluster, CX bytes/sector, DX clusters, DS:BX media byte
                    * (KRNL386's GetPrivateProfileSection path through kernel32, from USER's LibEntry).
                    * ponytail: a fixed 2 GB FAT drive, nothing of the host's; AL FFh for any drive but C:. */
        static uint8_t media = 0xF8;
        uint8_t d = (uint8_t)g_edx;
        if (d != 0 && d != 3) { SET8L(g_eax, 0xFF); return g_eax; }
        SET8L(g_eax, 64); SET16(g_ecx, 512); SET16(g_edx, 0xFFFF); g_ebx = (uint32_t)(uintptr_t)&media;
        return g_eax;
    }
    case 0x2A: { SYSTEMTIME t; GetLocalTime(&t);
        SET16(g_ecx, t.wYear); SET16(g_edx, t.wMonth << 8 | t.wDay); SET8L(g_eax, t.wDayOfWeek); return g_eax; }
    case 0x2C: { SYSTEMTIME t; GetLocalTime(&t);
        SET16(g_ecx, t.wHour << 8 | t.wMinute); SET16(g_edx, t.wSecond << 8 | t.wMilliseconds / 10); return g_eax; }
    case 0x59:                                                 /* extended error: AX code, BH class, BL action, CH locus */
        SET16(g_eax, g_dos_err); SET16(g_ebx, 0x0D01); g_ecx = (g_ecx & 0xFFFF00FFu) | 0x0200; return g_eax;
    case 0x30: SET16(g_eax, 0x0A07); SET16(g_ebx, 0xFF00); return g_eax;   /* DOS 7.10 */
    case 0x41:   /* delete DS:DX (boxed) */
        if (!host_path(g_edx, path)) { dos_fail(3); return g_eax; }
        if (getenv("W16_TRACE")) fprintf(stderr, "[int21] delete %s\n", path);
        if (!DeleteFileA(path)) dos_fail(host_err());
        return g_eax;
    case 0x50: g_cur_psp = (uint16_t)g_ebx; return g_eax;      /* set PSP (kernel32 walking 16-bit modules, MSGSRV32's WNet thunk) */
    case 0x51: case 0x62: SET16(g_ebx, g_cur_psp); return g_eax;
    case 0x55: {   /* create child PSP at DX (KRNL386's LoadModule of a task, MSGSRV32): a copy of
                    * the current one, SI its memory top, parent = current; it becomes current.
                    * ponytail: the job file table is shared, not duplicated (no inheritance counts). */
        uint32_t np = recomp_sel_base((uint16_t)g_edx), op = recomp_sel_base(g_cur_psp);
        if (!np) { dos_fail(8); return g_eax; }
        if (op) memmove((void*)(uintptr_t)np, (void*)(uintptr_t)op, 0x100);
        MEM16(np + 2) = (uint16_t)g_esi; MEM16(np + 0x16) = g_cur_psp;
        if (g_trace > 0) fprintf(stderr, "[int21] child PSP %04X of %04X\n", (uint16_t)g_edx, g_cur_psp);
        g_cur_psp = (uint16_t)g_edx;
        return g_eax;
    }
    case 0x69:   /* AL 0: BL drive -> DS:DX {+0 level, +2 serial, +6 label[11], +11h fs[8]} (GetVolumeInformationA) */
        if (al == 0) {
            uint8_t d = (uint8_t)g_ebx;
            if (d != 0 && d != 3) { dos_fail(15); return g_eax; }
            MEM16(g_edx) = 0; MEM32(g_edx + 2) = 0x19980505u;   /* a fixed serial: nothing of the host's */
            memcpy((void*)(uintptr_t)(g_edx + 6), "NO NAME    FAT32   ", 19);
            return g_eax;
        }
        break;
    case 0x60: {   /* truename DS:SI -> ES:DI (128 bytes), the 8.3 form of 7160 (MSGSRV32's
                    * WinExec of the shell, after 716C did not find it) */
        if (!host_path(g_esi, path)) { dos_fail(3); return g_eax; }
        const char* rel = path + strlen(g_root);
        _snprintf(path2, sizeof path2, "C:\\%s", *rel == '\\' ? rel + 1 : rel);
        path2[127] = 0;
        _strupr(path2);
        guest_put(g_edi, path2, 128);
        return g_eax; }
    case 0x1A: g_dta = g_edx; return g_eax;                    /* set DTA (DS:DX) */
    case 0x2F: g_ebx = g_dta; return g_eax;                    /* get DTA -> ES:BX */
    case 0x3C: case 0x3D: {   /* create (CX attrs) / open (AL mode): DS:DX name -> AX handle */
        DWORD acc = ah == 0x3C || (al & 3) == 2 ? GENERIC_READ | GENERIC_WRITE : (al & 3) == 1 ? GENERIC_WRITE : GENERIC_READ;
        DWORD share = ah == 0x3C ? FILE_SHARE_READ | FILE_SHARE_WRITE : (al & 0x70) == 0x10 ? 0 : (al & 0x70) == 0x20 ? FILE_SHARE_READ
                    : (al & 0x70) == 0x30 ? FILE_SHARE_WRITE : FILE_SHARE_READ | FILE_SHARE_WRITE;
        if (!host_path(g_edx, path)) { dos_fail(3); return g_eax; }
        HANDLE fh = CreateFileA(path, acc, share, NULL, ah == 0x3C ? CREATE_ALWAYS : OPEN_EXISTING,
                                ah == 0x3C && ((uint16_t)g_ecx & 0x27) ? ((uint16_t)g_ecx & 0x27) : FILE_ATTRIBUTE_NORMAL, NULL);
        if (fh == INVALID_HANDLE_VALUE) { dos_fail(host_err()); return g_eax; }
        int h = new_handle(fh);
        if (h < 0) { dos_fail(4); return g_eax; }
        SET16(g_eax, h);
        return g_eax; }
    case 0x4E: case 0x4F: {   /* 8.3 find first (CX attrs, DS:DX spec) / next, into the DTA */
        WIN32_FIND_DATAA fd;
        int h;
        if (ah == 0x4E) {
            if (!host_path(g_edx, path)) { dos_fail(3); return g_eax; }
            for (h = 0; h < NFINDS && g_find[h]; h++) ;
            if (h == NFINDS) { dos_fail(4); return g_eax; }
            HANDLE f = FindFirstFileA(path, &fd);
            if (f == INVALID_HANDLE_VALUE) { dos_fail(GetLastError() == ERROR_FILE_NOT_FOUND ? 18 : host_err()); return g_eax; }
            g_find[h] = f; g_find_attr[h] = (uint16_t)g_ecx;
            { char* sl = strrchr(path, '\\'); g_find_root[h] = sl && (size_t)(sl - path) == strlen(g_root); }
            MEM16(g_dta) = 0xF1D0; MEM16(g_dta + 2) = (uint16_t)h;   /* the DTA's reserved bytes carry the search */
        } else {
            h = MEM16(g_dta) == 0xF1D0 ? MEM16(g_dta + 2) : -1;
            if (h < 0 || h >= NFINDS || !g_find[h] || !FindNextFileA(g_find[h], &fd)) { dos_fail(18); return g_eax; }
        }
        while (!find_ok(&fd, g_find_attr[h]) || (g_find_root[h] && (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, ".."))))
            if (!FindNextFileA(g_find[h], &fd)) { FindClose(g_find[h]); g_find[h] = NULL; dos_fail(18); return g_eax; }
        {   FILETIME l; WORD d = 0, t = 0;
            FileTimeToLocalFileTime(&fd.ftLastWriteTime, &l); FileTimeToDosDateTime(&l, &d, &t);
            MEM8(g_dta + 0x15) = (uint8_t)(fd.dwFileAttributes & 0x3F);
            MEM16(g_dta + 0x16) = t; MEM16(g_dta + 0x18) = d; MEM32(g_dta + 0x1A) = fd.nFileSizeLow;
            const char* sn = fd.cAlternateFileName[0] ? fd.cAlternateFileName : fd.cFileName;
            char n83[13]; int i = 0;
            for (; sn[i] && i < 12; i++) n83[i] = (char)toupper((unsigned char)sn[i]);
            n83[i] = 0;
            guest_put(g_dta + 0x1E, n83, 13); }
        return g_eax; }
    case 0x3E: if (!dos_close((uint16_t)g_ebx)) dos_fail(6); return g_eax;
    case 0x3F: case 0x40: { HANDLE fh = dos_handle((uint16_t)g_ebx); DWORD n = 0;
        if (!fh || fh == INVALID_HANDLE_VALUE) { dos_fail(6); return g_eax; }
        BOOL ok = ah == 0x3F ? ReadFile(fh, (void*)(uintptr_t)g_edx, g_ecx, &n, NULL)
                             : (g_ecx ? WriteFile(fh, (void*)(uintptr_t)g_edx, g_ecx, &n, NULL) : SetEndOfFile(fh));
        if (!ok && GetLastError() != ERROR_BROKEN_PIPE) dos_fail(host_err()); else g_eax = n;
        return g_eax; }
    case 0x42: { HANDLE fh = dos_handle((uint16_t)g_ebx); LARGE_INTEGER d, at;
        d.QuadPart = (int32_t)((uint32_t)(uint16_t)g_ecx << 16 | (uint16_t)g_edx);
        if (!fh || !SetFilePointerEx(fh, d, &at, al)) { dos_fail(fh ? host_err() : 6); return g_eax; }
        SET16(g_eax, at.LowPart); SET16(g_edx, at.LowPart >> 16); return g_eax; }
    case 0x44:
        if (al == 0x00) {                                      /* device info */
            HANDLE fh = dos_handle((uint16_t)g_ebx);
            if (!fh) { dos_fail(6); return g_eax; }
            SET16(g_edx, GetFileType(fh) == FILE_TYPE_CHAR ? 0x80D3 : 0x0002);
            return g_eax;
        }
        if (al == 0x08 || al == 0x09) {                        /* BL drive (0 current): removable? / remote? */
            uint8_t d = (uint8_t)g_ebx;
            if (d != 0 && d != 3) { dos_fail(15); return g_eax; }   /* only C: exists */
            if (al == 0x08) SET16(g_eax, 1); else SET16(g_edx, 0);  /* fixed, local */
            return g_eax;
        }
        break;
    case 0x57: { HANDLE fh = dos_handle((uint16_t)g_ebx); FILETIME ft, l; WORD d, t;
        if (!fh) { dos_fail(6); return g_eax; }
        if (al == 0) { GetFileTime(fh, NULL, NULL, &ft); FileTimeToLocalFileTime(&ft, &l); FileTimeToDosDateTime(&l, &d, &t);
                       SET16(g_ecx, t); SET16(g_edx, d); return g_eax; }
        if (al == 1) { DosDateTimeToFileTime((WORD)g_edx, (WORD)g_ecx, &l); LocalFileTimeToFileTime(&l, &ft);
                       if (!SetFileTime(fh, NULL, NULL, &ft)) dos_fail(host_err()); return g_eax; }
        break; }
    case 0x71:
        switch (al) {
        case 0x47:                                             /* LFN cwd: DL drive (0 = current), DS:ESI */
            if ((uint8_t)g_edx != 0 && (uint8_t)g_edx != 3) { dos_fail(15); return g_eax; }
            guest_put(g_esi, g_cwd, 260); SET16(g_eax, 0x0100); return g_eax;
        case 0x3B: {                                           /* LFN chdir */
            DWORD at;
            if (!host_path(g_edx, path) || (at = GetFileAttributesA(path)) == INVALID_FILE_ATTRIBUTES || !(at & FILE_ATTRIBUTE_DIRECTORY)) { dos_fail(3); return g_eax; }
            strcpy(g_cwd, path + strlen(g_root) + (path[strlen(g_root)] == '\\'));
            return g_eax; }
        case 0x39: case 0x3A: case 0x41:                       /* LFN mkdir, rmdir, delete */
            if (!host_path(g_edx, path)) { dos_fail(3); return g_eax; }
            if (!(al == 0x39 ? CreateDirectoryA(path, NULL) : al == 0x3A ? RemoveDirectoryA(path) : DeleteFileA(path))) dos_fail(host_err());
            return g_eax;
        case 0x43:                                             /* LFN attributes: BL 0 get, 1 set */
            if (!host_path(g_edx, path)) { dos_fail(3); return g_eax; }
            if ((uint8_t)g_ebx == 0) {
                DWORD at = GetFileAttributesA(path);
                if (at == INVALID_FILE_ATTRIBUTES) dos_fail(host_err()); else SET16(g_ecx, at & 0x3F);
                return g_eax;
            }
            if ((uint8_t)g_ebx == 1) { if (!SetFileAttributesA(path, (uint16_t)g_ecx ? (uint16_t)g_ecx : FILE_ATTRIBUTE_NORMAL)) dos_fail(host_err()); return g_eax; }
            break;
        case 0x56:                                             /* LFN rename DS:EDX -> ES:EDI */
            if (!host_path(g_edx, path) || !host_path(g_edi, path2)) { dos_fail(3); return g_eax; }
            if (!MoveFileA(path, path2)) dos_fail(host_err());
            return g_eax;
        case 0x6C: {   /* LFN extended open: BX mode, CX attrs, DX action, DS:ESI name -> AX handle, CX action taken */
            uint16_t mode = (uint16_t)g_ebx, act = (uint16_t)g_edx;
            DWORD acc = (mode & 3) == 0 ? GENERIC_READ : (mode & 3) == 1 ? GENERIC_WRITE : GENERIC_READ | GENERIC_WRITE;
            DWORD share = (mode & 0x70) == 0x10 ? 0 : (mode & 0x70) == 0x20 ? FILE_SHARE_READ : (mode & 0x70) == 0x30 ? FILE_SHARE_WRITE : FILE_SHARE_READ | FILE_SHARE_WRITE;
            DWORD disp = (act & 0x10) ? ((act & 3) == 1 ? OPEN_ALWAYS : (act & 3) == 2 ? CREATE_ALWAYS : CREATE_NEW)
                                      : ((act & 3) == 2 ? TRUNCATE_EXISTING : OPEN_EXISTING);
            if (!host_path(g_esi, path)) { dos_fail(3); return g_eax; }
            DWORD pre = GetFileAttributesA(path);
            HANDLE fh = CreateFileA(path, acc, share, NULL, disp, ((uint16_t)g_ecx & 0x27) ? ((uint16_t)g_ecx & 0x27) : FILE_ATTRIBUTE_NORMAL, NULL);
            if (fh == INVALID_HANDLE_VALUE) { dos_fail(host_err()); return g_eax; }
            int h = new_handle(fh);
            if (h < 0) { dos_fail(4); return g_eax; }
            SET16(g_eax, h);
            SET16(g_ecx, pre == INVALID_FILE_ATTRIBUTES ? 2 : (disp == CREATE_ALWAYS || disp == TRUNCATE_EXISTING) ? 3 : 1);
            return g_eax; }
        case 0x4E: case 0x4F: {   /* LFN find first (CX attrs, SI date form, DS:EDX spec) / next (BX); ES:EDI result */
            WIN32_FIND_DATAA fd;
            int h;
            if (al == 0x4E) {
                if (!host_path(g_edx, path)) { dos_fail(3); return g_eax; }
                for (h = 0; h < NFINDS && g_find[h]; h++) ;
                if (h == NFINDS) { dos_fail(4); return g_eax; }
                HANDLE f = FindFirstFileA(path, &fd);
                if (f == INVALID_HANDLE_VALUE) { dos_fail(GetLastError() == ERROR_FILE_NOT_FOUND ? 18 : host_err()); return g_eax; }
                g_find[h] = f; g_find_attr[h] = (uint16_t)g_ecx;
                { char* sl = strrchr(path, '\\'); g_find_root[h] = sl && (size_t)(sl - path) == strlen(g_root); }
            } else {
                h = (uint16_t)g_ebx - 1;
                if (h < 0 || h >= NFINDS || !g_find[h] || !FindNextFileA(g_find[h], &fd)) { dos_fail(18); return g_eax; }
            }
            /* a drive's root has no "." or "..": the sandbox root is a host subdirectory */
            while (!find_ok(&fd, g_find_attr[h]) || (g_find_root[h] && (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, ".."))))
                if (!FindNextFileA(g_find[h], &fd)) { if (al == 0x4E) { FindClose(g_find[h]); g_find[h] = NULL; } dos_fail(18); return g_eax; }
            put_find(g_edi, &fd, (uint16_t)g_esi == 1);
            if (al == 0x4E) SET16(g_eax, h + 1);
            SET16(g_ecx, 0);
            return g_eax; }
        case 0xA7: {   /* time conversion, no time zone: BL 0 FILETIME DS:ESI -> CX time, DX date, BH 10 ms;
                        * BL 1 CX time, DX date, BH 10 ms -> FILETIME ES:EDI */
            FILETIME ft; WORD d, t;
            if ((uint8_t)g_ebx == 0) {
                ft.dwLowDateTime = MEM32(g_esi); ft.dwHighDateTime = MEM32(g_esi + 4);
                if (!FileTimeToDosDateTime(&ft, &d, &t)) { dos_fail(1); return g_eax; }
                SET16(g_ecx, t); SET16(g_edx, d); g_ebx &= 0xFFFF00FFu;
                return g_eax;
            }
            if ((uint8_t)g_ebx == 1) {
                if (!DosDateTimeToFileTime((WORD)g_edx, (WORD)g_ecx, &ft)) { dos_fail(1); return g_eax; }
                uint64_t v = ((uint64_t)ft.dwHighDateTime << 32 | ft.dwLowDateTime) + (uint64_t)((g_ebx >> 8) & 0xFF) * 100000u;
                MEM32(g_edi) = (uint32_t)v; MEM32(g_edi + 4) = (uint32_t)(v >> 32);
                return g_eax;
            }
            break; }
        case 0xA1: { int h = (uint16_t)g_ebx - 1;              /* LFN find close */
            if (h >= 0 && h < NFINDS && g_find[h]) { FindClose(g_find[h]); g_find[h] = NULL; }
            return g_eax; }
        case 0x60: {                                           /* LFN truename: DS:ESI -> ES:EDI */
            if (!host_path(g_esi, path)) { dos_fail(3); return g_eax; }
            const char* rel = path + strlen(g_root);
            _snprintf(path2, sizeof path2, "C:\\%s", *rel == '\\' ? rel + 1 : rel);
            path2[sizeof path2 - 1] = 0;
            guest_put(g_edi, path2, 261);
            return g_eax; }
        case 0xA0:     /* LFN volume info: DS:EDX root, ES:EDI fs name (CX bytes) -> BX flags, CX max name, DX max path */
            guest_put(g_edi, "FAT", (uint16_t)g_ecx ? (uint16_t)g_ecx : 4);
            SET16(g_ebx, 0x4006); SET16(g_ecx, 255); SET16(g_edx, 260);
            return g_eax;
        }
        break;
    }
    int21_unknown(ax);
    return 0;
}

/* The same table for lifted 16-bit code (identity.c dos_int21): the caller
 * has put flat pointers in the globals (ds:dx -> g_edx, ...). Returns CF. */
int native32_w9x_int21(uint32_t eax, uint32_t ecx) {
    uint32_t a[2] = { eax, ecx };
    g_eax = vwin32_int21(a);
    return g_cf;
}

static const vxd_service_t g_services[] = {
    { 0x002A0010, 2, vwin32_int21, "VWIN32_Int21Dispatch" },
    { 0x002A000C, 1, vwin32_first_thread, "VWIN32_CreateFirstThread" },
    { 0x0001000B, 1, vmm_context_switch, "VMM_ContextSwitch" },
    { 0x002A0008, 9, vwin32_create_thread, "VWIN32_CreateThread" },
    { 0x002A000A, 2, vwin32_ready_thread, "VWIN32_ReadyThread" },
    { 0x002A0036, 1, vwin32_run_thread, "VWIN32_RunThreadUntilBlocked" },
    { 0x002A0009, 1, vwin32_thread_starting, "VWIN32_ThreadStarting" },
    { 0x002A0026, 2, vwin32_link_thread, "VWIN32_LinkThread" },
    { 0x00380023, 3, vcond_init, "VCOND_Init" },
    { 0x0038001F, 0, vcond_new_console, "VCOND_NewConsole" },
    { 0x00380001, 3, vcond_write, "VCOND_Write" },
    { 0x00380002, 2, vcond_register, "VCOND_Register" },
    { 0x00380017, 3, vcond_zero, "VCOND_17_PostAgent" },
    { 0x0038000A, 1, vcond_zero, "VCOND_0A" },
    { 0x0038000D, 2, vcond_zero, "VCOND_0D_SetMode" },
    { 0x0038000C, 2, vcond_zero, "VCOND_0C_Set" },
    { 0x0038001B, 2, vcond_zero, "VCOND_1B_Set" },
    { 0x002A0040, 4, vwin32_virtual_query, "VWIN32_VirtualQuery" },
    { 0x002A0041, 2, vwin32_in_context, "VWIN32_InContext" },
    { 0x002A000B, 2, vwin32_terminate_thread, "VWIN32_TerminateThread" },
    { 0x002A002B, 0, vwin32_thread_done, "VWIN32_ThreadDone" },
    { 0x002A000D, 3, vwin32_queue_to_thread, "VWIN32_QueueToThread" },
    { 0x002A0058, 1, vwin32_release_58, "VWIN32_58_Release" },
    { 0x002A002C, 1, vwin32_term_done, "VWIN32_TermDone" },
    { 0x00010020, 1, vmm_20_release, "VMM_20_Release" },
    { 0x0001001F, 2, vmm_1f_sleep, "VMM_1F_Sleep" },
    { 0x00380014, 2, vcond_zero, "VCOND_14_Detach" },
    { 0x00380018, 1, vcond_zero, "VCOND_18_Get" },
    { 0x0038001E, 2, vcond_zero, "VCOND_1E_Set" },
    { 0x0038000E, 2, vcond_zero, "VCOND_0E" },
    { 0x00380013, 1, vcond_zero, "VCOND_13_Attached" },
    { 0x0038000F, 1, vcond_input_mode, "VCOND_0F_InputMode" },
    { 0x00380010, 4, vcond_read, "VCOND_10_Read" },
    { 0x002A002D, 2, vwin32_block, "VWIN32_BlockThread" },
    { 0x002A005C, 3, vwin32_wait_single, "VWIN32_WaitSingle" },
    { 0x002A005D, 5, vwin32_wait_multiple, "VWIN32_WaitMultiple" },
    { 0x002A001D, 1, vwin32_crst_wait, "VWIN32_WaitCrst" },
    { 0x002A001E, 1, vwin32_crst_wake, "VWIN32_WakeCrst" },
    { 0x002A0020, 1, vwin32_fpu_info, "VWIN32_GetCoprocessor" },
    { 0x002A0021, 2, vwin32_set_thread_priority, "VWIN32_SetThreadPriority" },
    { 0x002A0013, 2, vwin32_13, "VWIN32_13" },
    { 0x00090000, 2, reboot_0, "REBOOT_0" },
    { 0x00090001, 2, reboot_0, "REBOOT_1" },
    { 0x002A0030, 2, vwin32_wait_block_destroy, "VWIN32_DestroyWaitBlock" },
    { 0x002A005F, 1, vwin32_release_mutex, "VWIN32_ReleaseMutex" },
    { 0x002A005E, 3, vwin32_release_sem, "VWIN32_ReleaseSemaphore" },
    { 0x002A0060, 1, vwin32_set_event, "VWIN32_SetEvent" },
    { 0x002A0061, 1, vwin32_pulse_event, "VWIN32_PulseEvent" },
    { 0x002A0062, 1, vwin32_reset_event, "VWIN32_ResetEvent" },
    { 0x002A0064, 2, vwin32_set_priorities, "VWIN32_SetThreadPriorities" },
    { 0x002A0032, 1, vwin32_obj_release, "VWIN32_ReleaseObject" },
    { 0x002A004F, 4, vwin32_obj_fn, "VWIN32_ObjectFn" },
    { 0x00010005, 2, vmm_heap_alloc, "VMM_HeapAllocate" },
    { 0x00010006, 0, vmm_context_create, "VMM_ContextCreate" },
    { 0x00010007, 1, vmm_context_destroy, "VMM_ContextDestroy" },
    { 0x00010008, 4, vmm_page_attach, "VMM_PageAttach" },
    /* VxD 4B service 0: its Get_Version, which kernel32 compares with 100h
     * before using it (DeviceIoControl/CreateFile on \\.\ names). Absent. */
    { 0x004B0000, 0, vmm_28, "VxD4B_Get_Version (absent)" },
    /* VxD 2B service 15 (name past "\\.\"): is it a device (0xBFF7FF9F, from
     * CreateFileA)? No devices in the sandbox (MPRSERV asks for IFSMGR). */
    { 0x002B0015, 1, vmm_28, "VxD2B_15_DeviceName (none)" },
    /* VWIN32 1F (0, 0xBFF9CEEE, name, ...): CreateFileA on \\.\<vxd> opens a
     * VxD (0xBFF7F7F9). 0 is ERROR_FILE_NOT_FOUND: no VxDs, no hardware. */
    { 0x002A001F, 11, vmm_28, "VWIN32_OpenVxD (none)" },
    { 0x00010010, 2, vmm_heap_free, "VMM_HeapFree" },
    { 0x0001000C, 3, vmm_heap_realloc, "VMM_HeapReAllocate" },
    { 0x002A0047, 1, vwin32_set_env, "VWIN32_SetEnvironment" },
    { 0x002A0006, 3, vwin32_set_callbacks, "VWIN32_SetCallbacks" },
    { 0x00010000, 3, vmm_page_reserve, "VMM_PageReserve" },
    { 0x00010001, 5, vmm_page_commit, "VMM_PageCommit" },
    { 0x00010002, 3, vmm_page_decommit, "VMM_PageDecommit" },
    { 0x0001000A, 2, vmm_page_free, "VMM_PageFree" },
    { 0x0001000D, 4, vmm_page_modify, "VMM_PageModifyPermissions" },
    { 0x00010028, 0, vmm_28, "VMM_28" },
    { 0x00010003, 1, vmm_pager_register, "VMM_PagerRegister" },
    { 0x002A0001, 10, vwin32_r0_file_entries, "VWIN32_GetRing0FileEntries" },
    { 0x00010011, 3, vmm_reg_open, "VMM_RegOpenKey" },
    { 0x00010012, 3, vmm_reg_create, "VMM_RegCreateKey" },
    { 0x00010013, 1, vmm_reg_close, "VMM_RegCloseKey" },
    { 0x00010016, 2, vmm_reg_delete_key, "VMM_RegDeleteKey" },
    { 0x00010018, 4, vmm_reg_enum_key, "VMM_RegEnumKey" },
    { 0x00010019, 8, vmm_reg_enum_value, "VMM_RegEnumValue" },
    { 0x0001001A, 6, vmm_reg_query_value, "VMM_RegQueryValueEx" },
    { 0x0001001B, 6, vmm_reg_set_value, "VMM_RegSetValueEx" },
    { 0x0001001D, 6, vmm_reg_query_info, "VMM_RegQueryInfoKey" },
    { 0x00010015, 5, vmm_reg_set_value_sub, "VMM_RegSetValue" },
    { 0x00010004, 2, vmm_pager_query, "VMM_PagerQuery" },
    { 0x002A004A, 2, vwin32_crst_create, "VWIN32_CreateCrst" },
    { 0x002A0003, 8, vwin32_boot_sels, "VWIN32_BootSelectors" },
    { 0, 0, NULL, NULL },
};


/* VWIN32's ring-0 entry table: the KEXP header's second dword is where
 * VWIN32 stores its address; kernel32 enters an entry by a retf (lifted as
 * recomp_retf32). Entries are tagged 0xFEED0000 + their offset. */
#define R0_TAG 0xFEED0000u
static uint32_t g_r0_table[0x40];
static uint16_t g_next_sel = 0x0087;   /* LDT, RPL 3: what a flat host hands out */

uint32_t native32_vwin32_r0_table(void) {
    for (int i = 0; i < 0x40; i++) g_r0_table[i] = R0_TAG + 4u * i;
    return (uint32_t)(uintptr_t)g_r0_table;
}

/* The LDT. kernel32 writes descriptors itself, through an alias selector
 * whose base is the LDT (the boot block's +10h); the host owns the array and
 * every LDT selector's base is read from what kernel32 wrote there. GDT
 * selectors (the host's own flat ones) are base 0. */
static uint8_t g_ldt[0x10000];
static uint16_t g_ldt_alias;
extern uint32_t g_es_base, g_cs_base, g_ds_base, g_ss_base;   /* native32.c (per-thread state) */

/* The alias's own descriptor is in the LDT too, as on Win9x: KRNL386 reads
 * the LDT's base from it (seg001_4E8C on cs:[6]) for kernel32's boot block
 * +14, which MapSL then indexes. */
void native32_w9x_ldt(uint16_t alias_sel, uint32_t* ldt_base) {
    g_ldt_alias = alias_sel & ~7; *ldt_base = (uint32_t)(uintptr_t)g_ldt;
    uint8_t* d = g_ldt + g_ldt_alias; uint32_t b = *ldt_base;
    d[0] = d[1] = 0xFF; d[2] = (uint8_t)b; d[3] = (uint8_t)(b >> 8); d[4] = (uint8_t)(b >> 16); d[7] = (uint8_t)(b >> 24);
    d[5] = 0xF2; d[6] = 0x40;
}

uint32_t recomp_sel_base(uint32_t sel) {
    sel &= 0xFFFF;
    if ((sel & ~7u) == g_ldt_alias) return (uint32_t)(uintptr_t)g_ldt;
    if (!(sel & 4)) return 0;
    const uint8_t* d = g_ldt + (sel & ~7u);
    return d[2] | d[3] << 8 | d[4] << 16 | (uint32_t)d[7] << 24;
}

/* A data selector on [base, base+limit] in the host's LDT: what VWIN32 or
 * KRNL386 would have allocated. */
uint16_t native32_w9x_alloc_sel(uint32_t base, uint32_t limit) {
    /* KRNL386 writes the LDT itself (its alias from int 2Fh 168Ah): skip
     * descriptors it holds, including its free chain (nonzero bytes) */
    while (g_next_sel > 7 && (*(uint32_t*)(g_ldt + (g_next_sel & ~7u)) || *(uint32_t*)(g_ldt + (g_next_sel & ~7u) + 4)))
        g_next_sel += 8;
    uint16_t sel = g_next_sel;
    uint8_t* d = g_ldt + (sel & ~7u);
    g_next_sel += 8;
    d[0] = (uint8_t)limit; d[1] = (uint8_t)(limit >> 8);
    d[2] = (uint8_t)base; d[3] = (uint8_t)(base >> 8); d[4] = (uint8_t)(base >> 16); d[7] = (uint8_t)(base >> 24);
    d[5] = 0xF2;                            /* present, DPL 3, data, writable */
    d[6] = (uint8_t)((limit >> 16) & 0x0F) | 0x40;
    return sel;
}

/* A fixed selector for a lifted 16-bit segment (Win16 identity mode: ne_link
 * NE_IDENTITY_SEL=1 gives segment n the selector (n << 3) | 7): code
 * (execute/read) or data, 16-bit, DPL 3. The allocator above moves past
 * it, so kernel32's own selectors never land on a lifted segment. */
void native32_w9x_set_sel(uint16_t sel, uint32_t base, uint32_t limit, int code) {
    uint8_t* d = g_ldt + (sel & ~7u);
    d[0] = (uint8_t)limit; d[1] = (uint8_t)(limit >> 8);
    d[2] = (uint8_t)base; d[3] = (uint8_t)(base >> 8); d[4] = (uint8_t)(base >> 16); d[7] = (uint8_t)(base >> 24);
    d[5] = code ? 0xFA : 0xF2;
    d[6] = (uint8_t)((limit >> 16) & 0x0F);
    if ((uint16_t)((sel | 7) + 8) > g_next_sel) g_next_sel = (uint16_t)((sel | 7) + 8);
}

/* The raw 8-byte descriptor, for 16-bit DPMI (int 31h 0B/0C) in identity mode. */
uint8_t* native32_w9x_desc(uint16_t sel) { return g_ldt + (sel & ~7u); }
uint16_t native32_w9x_next_sel(void) { return g_next_sel; }
uint16_t native32_w9x_ldt_alias(void) { return (uint16_t)(g_ldt_alias | 7); }

static const uint8_t* ldt_desc(uint16_t sel) {
    if (!(sel & 4) || (sel & ~7u) == g_ldt_alias) return NULL;
    const uint8_t* d = g_ldt + (sel & ~7u);
    return (d[5] & 0x80) ? d : NULL;           /* present */
}

/* lar/lsl accept a not-present descriptor, as the CPU does (KRNL386 reads a
 * discarded segment's handle with lar before reloading it): a code or data
 * descriptor at DPL 3, or conforming code. */
static const uint8_t* ldt_desc_any(uint16_t sel) {
    if (!(sel & 4) || (sel & ~7u) == g_ldt_alias) return NULL;
    const uint8_t* d = g_ldt + (sel & ~7u);
    if (!(d[5] & 0x10)) return NULL;
    return ((d[5] >> 5 & 3) == 3 || (d[5] & 0x0C) == 0x0C) ? d : NULL;
}

int recomp_lsl32(uint16_t sel, uint32_t* limit) {
    if ((sel & ~7u) == g_ldt_alias) { *limit = sizeof g_ldt - 1; return 1; }
    const uint8_t* d = ldt_desc_any(sel);
    if (!d) return 0;
    uint32_t l = d[0] | d[1] << 8 | (uint32_t)(d[6] & 0x0F) << 16;
    *limit = (d[6] & 0x80) ? (l << 12) | 0xFFF : l;
    return 1;
}

int recomp_lar32(uint16_t sel, uint32_t* rights) {
    if ((sel & ~7u) == g_ldt_alias) { *rights = 0x00C0F200u; return 1; }
    const uint8_t* d = ldt_desc_any(sel);
    if (!d) return 0;
    *rights = ((uint32_t)d[5] << 8 | (uint32_t)(d[6] & 0xF0) << 16);
    return 1;
}

/* ss is a 32-bit (B=1) stack: `mov sp, r16` keeps the top of esp only then (lift32 W9X). */
int recomp_ss_big(void) {
    uint32_t r;
    return !recomp_lar32(g_seg_ss, &r) || (r & 0x00400000u);
}

void recomp_set_seg(int sreg, uint32_t sel) {
    /* A register reloaded with the selector it holds, whose descriptor has
     * been freed since (not present): the cached base stays. A dying
     * thread's teardown (0xBFF893E9) frees its own TIB selector, fs, through
     * QT_Thunk, whose tail reloads fs (0xBFF72881) and whose next call (the
     * thread's 16-bit stack, 0xBFF893FB) reads fs:[18h]. ponytail: real x86
     * would #GP on that load; what Win98 does with the fault is not known,
     * this keeps the descriptor cache as it was. */
    uint16_t* cur[6] = { &g_seg_es, NULL, &g_seg_ss, &g_seg_ds, &g_seg_fs, &g_seg_gs };
    sel &= 0xFFFF;
    if (sreg >= 0 && sreg < 6 && cur[sreg] && *cur[sreg] == sel && (sel & 4) && (sel & ~7u) != g_ldt_alias
        && !(g_ldt[(sel & ~7u) + 5] & 0x80))
        return;
    if (sreg == 0) { g_seg_es = (uint16_t)sel; g_es_base = recomp_sel_base(sel); }
    if (sreg == 5) { g_seg_gs = (uint16_t)sel; g_gs_base = recomp_sel_base(sel); }
    if (sreg == 4) {   /* a thread's TIB (Win9x layout: fs:[1Ch] flags, fs:[1Eh] Win16 mutex count) */
        g_seg_fs = (uint16_t)sel; g_fs_base = recomp_sel_base(sel);
        if (g_trace < 0) g_trace = getenv("NATIVE32_VXD") != NULL;
        if (g_trace) fprintf(stderr, "[vxd] fs=%04X base %08X (from sub_%08X)\n", sel & 0xFFFF, g_fs_base, g_cur_func);
    }
    if (sreg == 3) { g_seg_ds = (uint16_t)sel; g_ds_base = recomp_sel_base(sel); }
    if (sreg == 2) { g_seg_ss = (uint16_t)sel; g_ss_base = recomp_sel_base(sel); }
}

/* A far jump into a lifted 16-bit code selector (QT_Thunk's o16 retf):
 * the Win16 identity bridge (runtime/win16/identity/identity.c w16_enter), when the
 * host links one. */
int (*native32_w16_enter)(uint32_t target);

int recomp_retf32(uint32_t target) {
    if (native32_w16_enter && (target >> 16) & 4) {
        uint32_t r;
        if (recomp_lar32((uint16_t)(target >> 16), &r) && (r & 0x0800)) return native32_w16_enter(target);
    }
    if ((target & 0xFFFF0000u) != R0_TAG) { if (getenv("W16_TRACE")) fprintf(stderr, "[retf32] flat %08X ss %04X@%08X esp %08X ebp %08X ebx %08X in sub_%08X\n", target, g_seg_ss, g_ss_base, g_esp, g_ebp, g_ebx, g_cur_func); return 0; }
    uint32_t off = target & 0xFFFF;
    if (g_trace < 0) g_trace = getenv("NATIVE32_VXD") != NULL;
    switch (off) {
    case 0x28:   /* allocate ecx LDT selectors: ax = the first. ponytail: a counter; no descriptors yet */
        g_eax = (g_eax & 0xFFFF0000u) | g_next_sel;
        g_next_sel += (uint16_t)(8 * (g_ecx ? g_ecx : 1));
        break;
    default:
        fprintf(stderr, "\n[vwin32-r0] unknown ring-0 entry +%02X from sub_%08X: eax=%08X ecx=%08X edx=%08X ebx=%08X\n",
                off, g_cur_func, g_eax, g_ecx, g_edx, g_ebx);
        fflush(stderr);
        recomp_trace_flush();
        TerminateProcess(GetCurrentProcess(), 5);
    }
    if (g_trace) fprintf(stderr, "[vwin32-r0] +%02X -> eax=%08X (from sub_%08X)\n", off, g_eax, g_cur_func);
    return 1;
}

int recomp_farcall32(uint32_t ptr) {
    uint32_t id = g_eax, *a = (uint32_t*)(uintptr_t)(g_esp + 4);
    (void)ptr;
    if (g_trace < 0) g_trace = getenv("NATIVE32_VXD") != NULL;
    for (const vxd_service_t* s = g_services; s->fn; s++) {
        if (s->id != id) continue;
        g_cf = 0;
        uint32_t r = s->fn(a);
        /* the service's CF, as a cmp the caller's jb/jc reads (ZF clear) */
        g_flag_k = FK_CMP; g_flag_a = g_cf ? 0 : 1; g_flag_b = g_cf ? 1 : 0; g_flag_cf = (uint32_t)g_cf;
        if (g_trace)
            fprintf(stderr, "[vxd] %08X %s(%08X %08X %08X %08X) = %08X  (from sub_%08X, esp %08X esi %08X)\n",
                    id, s->name, a[0], a[1], a[2], a[3], r, g_cur_func, g_esp, g_esi);
        g_eax = r;
        g_esp += 4 + 4u * s->nargs;
        return 1;
    }
    fprintf(stderr, "\n[vxd] unknown service %08X (VxD %04X, service %04X) from sub_%08X\n"
                    "      stack: ret %08X, args %08X %08X %08X %08X %08X %08X\n",
            id, id >> 16, id & 0xFFFF, g_cur_func, MEM32(g_esp), a[0], a[1], a[2], a[3], a[4], a[5]);
    native32_dump_icalls(8);
    fflush(stderr);
    recomp_trace_flush();
    TerminateProcess(GetCurrentProcess(), 5);
    return 1;
}

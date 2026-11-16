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

#include "native32.h"
void recomp_trace_flush(void);   /* recomp_trace.c: --calltrace before we end */

static int g_trace = -1;          /* NATIVE32_VXD */
static uint16_t g_cur_psp;         /* the current PSP selector (a TDBX points at it) */
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
static uint32_t vmm_page_reserve(const uint32_t* a) {
    void* want = PR_ANY(a[0]) ? NULL : (void*)(uintptr_t)(a[0] << 12);
    void* p = VirtualAlloc(want, a[1] << 12, MEM_RESERVE, PAGE_EXECUTE_READWRITE);
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
static uint32_t vmm_reg_set_value(const uint32_t* a) {
    return (uint32_t)REG("RegSetValueExA", LONG(WINAPI*)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD))((HKEY)P(0), P(1), 0, a[3], P(4), a[5]);
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
const char* g_w9x_sysdir = "C:\\WINDOWS\\SYSTEM";
static uint32_t lin16(uint32_t p1616) { return recomp_sel_base(p1616 >> 16) + (p1616 & 0xFFFF); }
static void krnl386_thunk(void) {
    uint8_t n = MEM8(g_ebp - 4);
    uint32_t sp = g_esp + 4;          /* past the return address the call pushed */
    switch (n) {
    case 0x12: {
        uint16_t cb = MEM16(sp);
        uint32_t buf = lin16(MEM32(sp + 2));
        size_t len = strlen(g_w9x_sysdir);
        if (len < cb) guest_put(buf, g_w9x_sysdir, cb);
        g_eax = (uint32_t)len; g_edx = 0;
        if (g_trace > 0) fprintf(stderr, "[krnl386] thunk %02X GetSystemDirectory(%08X, %u) = %u\n", n, buf, cb, (unsigned)len);
        break; }
    case 0x30:   /* (hTask:16, lpszName:16:16): _INIT passes the boot task and
                  * "KERNEL32.DLL" (0xBFFC6F68), CreateProcess a new process's
                  * task (PDB+38) and its module name (0xBFF8B4BF). The task's
                  * name for KRNL386. ponytail: not kept; nothing on the host
                  * reads Win16 task names yet. */
        if (g_trace > 0) fprintf(stderr, "[krnl386] thunk 30 task %04X name \"%s\"\n", MEM16(sp + 4), (const char*)(uintptr_t)lin16(MEM32(sp)));
        g_eax = 0; g_edx = 0;
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

/* The host's recomp_lookup_manual forwards here: VWIN32's entries above. */
recomp_func_t native32_w9x_lookup(uint32_t va) {
    if (va == K386_TAG) return krnl386_thunk;
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
    if (!VirtualAlloc((void*)(uintptr_t)(page << 12), n << 12, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) return 0;
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

/* VMM service 6, no arguments: a new memory context, kept in the process
 * database at +1C (beside +24, the PSP's linear address). Every guest
 * process shares the host's one address space: a nonzero cookie. */
static uint32_t vmm_context_create(const uint32_t* a) { static uint32_t n; (void)a; return 0xC0DE0000u + ++n; }

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
static uint32_t new_tdbx(void) {
    uint8_t* tdbx = calloc(1, 0x100);
    *(uint32_t*)(tdbx + 0x50) = (uint32_t)(uintptr_t)&g_cur_psp;
    return (uint32_t)(uintptr_t)tdbx;
}
static uint32_t vwin32_create_thread(const uint32_t* a) {
    uint8_t* r0 = calloc(1, 0x100);
    *(uint32_t*)(r0 + R0T_ENTRY) = a[5];
    *(uint32_t*)(r0 + R0T_ESP) = a[7];
    *(uint32_t*)(r0 + R0T_THREAD) = a[0];
    MEM32(a[8]) = new_tdbx();
    *(uint32_t*)(r0 + R0T_PROCESS) = a[1];
    *(uint32_t*)(r0 + R0T_TDBX) = MEM32(a[8]);
    if (g_trace > 0) fprintf(stderr, "[vxd] new thread %08X: entry %08X esp %08X\n", a[0], a[5], a[7]);
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
static __declspec(thread) uint32_t t_r0;   /* this host thread's guest r0 twin, 0 for the boot thread */

static DWORD w9x_wait(HANDLE h, DWORD ms) {
    uint16_t sds = g_seg_ds, ses = g_seg_es, sfs = g_seg_fs, sgs = g_seg_gs;
    uint32_t bds = g_ds_base, bes = g_es_base, bgs = g_gs_base;
    uint32_t cur[3] = { g_cur[0], g_cur[1], g_cur[2] };
    if (t_r0) SetEvent((HANDLE)(uintptr_t)MEM32(t_r0 + R0T_PARKED));
    DWORD rc = native32_wait(h, ms);
    g_seg_ds = sds; g_seg_es = ses; g_seg_fs = sfs; g_seg_gs = sgs;
    g_ds_base = bds; g_es_base = bes; g_gs_base = bgs;
    g_cur[0] = cur[0]; g_cur[1] = cur[1]; g_cur[2] = cur[2];   /* this thread is VWIN32's current one again */
    return rc;
}

static DWORD WINAPI guest_thread(LPVOID p) {
    t_r0 = (uint32_t)(uintptr_t)p;
    mach_enter();
    g_cur[0] = MEM32(t_r0 + R0T_THREAD); g_cur[1] = MEM32(t_r0 + R0T_PROCESS); g_cur[2] = MEM32(t_r0 + R0T_TDBX);
    g_esp = MEM32(t_r0 + R0T_ESP);
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

static uint32_t vwin32_ready_thread(const uint32_t* a) {
    if (a[0]) MEM32(a[0] + R0T_READY) = 1;
    if (g_trace > 0) fprintf(stderr, "[vxd] thread %08X ready\n", a[0] ? MEM32(a[0] + R0T_THREAD) : 0);
    return 0;
}

static uint32_t vwin32_run_thread(const uint32_t* a) {
    uint32_t r0 = a[0];
    if (!r0 || !MEM32(r0 + R0T_READY)) return 0;
    HANDLE parked = (HANDLE)(uintptr_t)MEM32(r0 + R0T_PARKED);
    if (!parked) {
        parked = CreateEventA(NULL, FALSE, FALSE, NULL);
        MEM32(r0 + R0T_PARKED) = (uint32_t)(uintptr_t)parked;
        CloseHandle(CreateThread(NULL, 1u << 20, guest_thread, (LPVOID)(uintptr_t)r0, 0, NULL));
    }
    w9x_wait(parked, INFINITE);
    return 0;
}

/* VWIN32 26 (r0thread, r0other): ties a thread's ring-0 twin to another
 * thread's of the same process: a starting thread to its process's first
 * (0xBFF8697A), a new thread to the boot thread (0xBFF89B55). Host threads
 * share everything already. */
static uint32_t vwin32_link_thread(const uint32_t* a) { (void)a; return 0; }

/* ---- VCOND (VxD 38h), the console ----------------------------------------
 * 23 (6, &info, sysdir): kernel32's service thread (0xBFF91450) introduces
 * itself to VCOND once, with the system directory (where CONAGENT.EXE
 * lives); nothing reads the info block (0xBFFC9D30) back. The host's
 * console needs no agent. */
static uint32_t vcond_init(const uint32_t* a) { (void)a; return 0; }

/* VWIN32 2D (ms, alertable): block this thread (SleepEx, 0xBFF88BB0):
 * C0h when woken for an APC, 102h on timeout. The thread gives up the
 * machine meanwhile; its wake event (R0T_WAKE, the boot thread's own) is
 * what a queued APC will set. */
#define R0T_WAKE 0x34
static HANDLE thread_wake(void) {
    static HANDLE boot;
    if (!t_r0) { if (!boot) boot = CreateEventA(NULL, FALSE, FALSE, NULL); return boot; }
    if (!MEM32(t_r0 + R0T_WAKE)) MEM32(t_r0 + R0T_WAKE) = (uint32_t)(uintptr_t)CreateEventA(NULL, FALSE, FALSE, NULL);
    return (HANDLE)(uintptr_t)MEM32(t_r0 + R0T_WAKE);
}
static uint32_t vwin32_block(const uint32_t* a) {
    if (g_trace > 0) fprintf(stderr, "[vxd] thread %08X blocks (%d ms)\n", g_cur[0], (int)a[0]);
    DWORD rc = w9x_wait(thread_wake(), a[0]);
    return rc == WAIT_TIMEOUT ? 0x102 : 0xC0;
}

/* VWIN32 9 (-1): a new thread's first call, from its start frame
 * (0xBFF72178) before it goes to its start routine. Nothing to wait for. */
static uint32_t vwin32_thread_starting(const uint32_t* a) { (void)a; return 0; }

/* VWIN32 21 (r0thread, priority): set a thread's priority in its ring-0
 * twin and return the field's offset there: CreateThread keeps r0thread +
 * the result as the TIB's pCurrentPriority (thread+2C, 0xBFF86850). */
#define R0T_PRIORITY 0x10
static uint32_t vwin32_set_thread_priority(const uint32_t* a) {
    if (a[0]) MEM32(a[0] + R0T_PRIORITY) = a[1];
    return R0T_PRIORITY;
}

/* VWIN32 60 (waitblk): called on a fresh file object's wait block (made by
 * 0xBFF7E4BA, 10h bytes, +4 count, +8 manual-reset) at 0xBFF80215, and on a
 * thread's in its teardown (0xBFF8CC9F). Its neighbours 5E (3 args) and 61
 * (1) are wrapped the same way (0xBFF92D4D..77). The host keeps no ring-0
 * wait state: nothing to do, and kernel32 ignores the result.
 * ponytail: the name is still open; give it one when a caller needs a result. */
static uint32_t vwin32_wait_block_60(const uint32_t* a) { (void)a; return 0; }

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
static uint32_t vwin32_first_thread(const uint32_t* a) {
    uint32_t* blk = (uint32_t*)(uintptr_t)a[0];
    uint8_t* tdbx = calloc(1, 0x100);
    g_cur[0] = blk[0]; g_cur[1] = blk[1]; g_cur[2] = (uint32_t)(uintptr_t)tdbx;
    g_cur_psp = g_w9x_psp_sel;
    *(uint32_t*)(tdbx + 0x50) = (uint32_t)(uintptr_t)&g_cur_psp;
    blk[0x0C / 4] = (uint32_t)(uintptr_t)calloc(1, 0x100);   /* ring-0 thread: nothing reads into it yet */
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
static char g_root[MAX_PATH], g_cwd[MAX_PATH];   /* g_cwd: guest, no drive, no leading '\' */
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
    case 0x0E: SET8L(g_eax, 26); return g_eax;                 /* select drive: 26 letters */
    case 0x19: SET8L(g_eax, 2); return g_eax;                  /* current drive: C: */
    case 0x2A: { SYSTEMTIME t; GetLocalTime(&t);
        SET16(g_ecx, t.wYear); SET16(g_edx, t.wMonth << 8 | t.wDay); SET8L(g_eax, t.wDayOfWeek); return g_eax; }
    case 0x2C: { SYSTEMTIME t; GetLocalTime(&t);
        SET16(g_ecx, t.wHour << 8 | t.wMinute); SET16(g_edx, t.wSecond << 8 | t.wMilliseconds / 10); return g_eax; }
    case 0x59:                                                 /* extended error: AX code, BH class, BL action, CH locus */
        SET16(g_eax, g_dos_err); SET16(g_ebx, 0x0D01); g_ecx = (g_ecx & 0xFFFF00FFu) | 0x0200; return g_eax;
    case 0x30: SET16(g_eax, 0x0A07); SET16(g_ebx, 0xFF00); return g_eax;   /* DOS 7.10 */
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
    { 0x002A002D, 2, vwin32_block, "VWIN32_BlockThread" },
    { 0x002A0020, 1, vwin32_fpu_info, "VWIN32_GetCoprocessor" },
    { 0x002A0021, 2, vwin32_set_thread_priority, "VWIN32_SetThreadPriority" },
    { 0x002A0030, 2, vwin32_wait_block_destroy, "VWIN32_DestroyWaitBlock" },
    { 0x002A0060, 1, vwin32_wait_block_60, "VWIN32_60_WaitBlock" },
    { 0x002A0064, 2, vwin32_set_priorities, "VWIN32_SetThreadPriorities" },
    { 0x002A0032, 1, vwin32_obj_release, "VWIN32_ReleaseObject" },
    { 0x002A004F, 4, vwin32_obj_fn, "VWIN32_ObjectFn" },
    { 0x00010005, 2, vmm_heap_alloc, "VMM_HeapAllocate" },
    { 0x00010006, 0, vmm_context_create, "VMM_ContextCreate" },
    { 0x00010010, 2, vmm_heap_free, "VMM_HeapFree" },
    { 0x002A0047, 1, vwin32_set_env, "VWIN32_SetEnvironment" },
    { 0x002A0006, 3, vwin32_set_callbacks, "VWIN32_SetCallbacks" },
    { 0x00010000, 3, vmm_page_reserve, "VMM_PageReserve" },
    { 0x00010001, 5, vmm_page_commit, "VMM_PageCommit" },
    { 0x00010002, 3, vmm_page_decommit, "VMM_PageDecommit" },
    { 0x0001000A, 2, vmm_page_free, "VMM_PageFree" },
    { 0x0001000D, 4, vmm_page_modify, "VMM_PageModifyPermissions" },
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
uint32_t g_es_base, g_cs_base, g_ds_base;

void native32_w9x_ldt(uint16_t alias_sel, uint32_t* ldt_base) { g_ldt_alias = alias_sel & ~7; *ldt_base = (uint32_t)(uintptr_t)g_ldt; }

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
    uint16_t sel = g_next_sel;
    uint8_t* d = g_ldt + (sel & ~7u);
    g_next_sel += 8;
    d[0] = (uint8_t)limit; d[1] = (uint8_t)(limit >> 8);
    d[2] = (uint8_t)base; d[3] = (uint8_t)(base >> 8); d[4] = (uint8_t)(base >> 16); d[7] = (uint8_t)(base >> 24);
    d[5] = 0xF2;                            /* present, DPL 3, data, writable */
    d[6] = (uint8_t)((limit >> 16) & 0x0F) | 0x40;
    return sel;
}

static const uint8_t* ldt_desc(uint16_t sel) {
    if (!(sel & 4) || (sel & ~7u) == g_ldt_alias) return NULL;
    const uint8_t* d = g_ldt + (sel & ~7u);
    return (d[5] & 0x80) ? d : NULL;           /* present */
}

int recomp_lsl32(uint16_t sel, uint32_t* limit) {
    if ((sel & ~7u) == g_ldt_alias) { *limit = sizeof g_ldt - 1; return 1; }
    const uint8_t* d = ldt_desc(sel);
    if (!d) return 0;
    uint32_t l = d[0] | d[1] << 8 | (uint32_t)(d[6] & 0x0F) << 16;
    *limit = (d[6] & 0x80) ? (l << 12) | 0xFFF : l;
    return 1;
}

int recomp_lar32(uint16_t sel, uint32_t* rights) {
    if ((sel & ~7u) == g_ldt_alias) { *rights = 0x00C0F200u; return 1; }
    const uint8_t* d = ldt_desc(sel);
    if (!d) return 0;
    *rights = ((uint32_t)d[5] << 8 | (uint32_t)(d[6] & 0xF0) << 16);
    return 1;
}

void recomp_set_seg(int sreg, uint32_t sel) {
    if (sreg == 0) { g_seg_es = (uint16_t)sel; g_es_base = recomp_sel_base(sel); }
    if (sreg == 5) { g_seg_gs = (uint16_t)sel; g_gs_base = recomp_sel_base(sel); }
    if (sreg == 4) {   /* a thread's TIB (Win9x layout: fs:[1Ch] flags, fs:[1Eh] Win16 mutex count) */
        g_seg_fs = (uint16_t)sel; g_fs_base = recomp_sel_base(sel);
        if (g_trace < 0) g_trace = getenv("NATIVE32_VXD") != NULL;
        if (g_trace) fprintf(stderr, "[vxd] fs=%04X base %08X (from sub_%08X)\n", sel & 0xFFFF, g_fs_base, g_cur_func);
    }
    if (sreg == 3) { g_seg_ds = (uint16_t)sel; g_ds_base = recomp_sel_base(sel); }
}

int recomp_retf32(uint32_t target) {
    if ((target & 0xFFFF0000u) != R0_TAG) return 0;
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

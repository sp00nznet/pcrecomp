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
typedef struct { uint32_t id; int nargs; uint32_t (*fn)(const uint32_t* a); const char* name; } vxd_service_t;

/* VWIN32 3: kernel32's boot hands VWIN32 its code and data selectors (args
 * 1, 2) before reading the boot block; nothing for a flat host to keep. */
static uint32_t vwin32_boot_sels(const uint32_t* a) { (void)a; return 0; }

/* VWIN32 4A (crit, level): the kernel side of a critical section kernel32
 * just initialised (its type-4 object). Returns VWIN32's own object for it;
 * kernel32 keeps it in the section. A zeroed block of our own stands in. */
static uint32_t vwin32_crst_create(const uint32_t* a) { (void)a; return (uint32_t)(uintptr_t)calloc(1, 0x40); }

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
/* (page, npages, hpd, pagerdata, flags) */
static uint32_t vmm_page_commit(const uint32_t* a) {
    return VirtualAlloc((void*)(uintptr_t)(a[0] << 12), a[1] << 12, MEM_COMMIT, PAGE_EXECUTE_READWRITE) != NULL;
}
/* (page, npages, flags) */
static uint32_t vmm_page_decommit(const uint32_t* a) {
    return VirtualFree((void*)(uintptr_t)(a[0] << 12), a[1] << 12, MEM_DECOMMIT);
}

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
/* VMM service 6, no arguments: a new memory context, kept in the process
 * database at +1C (beside +24, the PSP's linear address). Every guest
 * process shares the host's one address space: a nonzero cookie. */
static uint32_t vmm_context_create(const uint32_t* a) { static uint32_t n; (void)a; return 0xC0DE0000u + ++n; }

/* VWIN32 4F (fn, handle): 33h registers a kernel32 object (a process) with
 * VWIN32's ring-0 side, 34h drops it. The host keeps no ring-0 twin. */
static uint32_t vwin32_obj_fn(const uint32_t* a) { return a[0] == 0x33 || a[0] == 0x34; }

/* VWIN32 32 (obj): kernel32 releases an object's ring-0 part just before it
 * clears the object. Nothing on the host side. */
static uint32_t vwin32_obj_release(const uint32_t* a) { (void)a; return 0; }

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

static uint32_t g_cur[3];          /* VWIN32's current thread, process, TDBX */
static uint16_t g_cur_psp;
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
static void dos_fail(uint16_t err) { SET16(g_eax, err); set_cf(1); }

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
    case 0x0E: SET8L(g_eax, 26); return g_eax;                 /* select drive: 26 letters */
    case 0x19: SET8L(g_eax, 2); return g_eax;                  /* current drive: C: */
    case 0x2A: { SYSTEMTIME t; GetLocalTime(&t);
        SET16(g_ecx, t.wYear); SET16(g_edx, t.wMonth << 8 | t.wDay); SET8L(g_eax, t.wDayOfWeek); return g_eax; }
    case 0x2C: { SYSTEMTIME t; GetLocalTime(&t);
        SET16(g_ecx, t.wHour << 8 | t.wMinute); SET16(g_edx, t.wSecond << 8 | t.wMilliseconds / 10); return g_eax; }
    case 0x30: SET16(g_eax, 0x0A07); SET16(g_ebx, 0xFF00); return g_eax;   /* DOS 7.10 */
    case 0x3E: { uint16_t h = (uint16_t)g_ebx;
        if (h > 4 && h < NHANDLES && g_fh[h]) { CloseHandle(g_fh[h]); g_fh[h] = NULL; }
        else if (h > 4) dos_fail(6);
        return g_eax; }
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
    { 0x002A0032, 1, vwin32_obj_release, "VWIN32_ReleaseObject" },
    { 0x002A004F, 2, vwin32_obj_fn, "VWIN32_ObjectFn" },
    { 0x00010005, 2, vmm_heap_alloc, "VMM_HeapAllocate" },
    { 0x00010006, 0, vmm_context_create, "VMM_ContextCreate" },
    { 0x002A0047, 1, vwin32_set_env, "VWIN32_SetEnvironment" },
    { 0x002A0006, 3, vwin32_set_callbacks, "VWIN32_SetCallbacks" },
    { 0x00010000, 3, vmm_page_reserve, "VMM_PageReserve" },
    { 0x00010001, 5, vmm_page_commit, "VMM_PageCommit" },
    { 0x00010002, 3, vmm_page_decommit, "VMM_PageDecommit" },
    { 0x0001000A, 2, vmm_page_free, "VMM_PageFree" },
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
            fprintf(stderr, "[vxd] %08X %s(%08X %08X %08X %08X) = %08X  (from sub_%08X)\n",
                    id, s->name, a[0], a[1], a[2], a[3], r, g_cur_func);
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

/*
 * syscall32: a lifted Windows NT userland on the host's kernel.
 *
 * The guest's own ntdll.dll is lifted like any module, and lift32 turns its
 * system call gate (int 2Eh: eax = service, edx -> arguments) into
 * recomp_syscall(). That is the only boundary: kernel32, msvcrt and the
 * program above it are the guest's own code all the way down.
 *
 *   table    The service numbers are the guest ntdll's, read from its NtXxx
 *            export stubs (mov eax, N / lea edx, [esp+4] / int 2Eh / ret 4n),
 *            which also give each service's argument count. No symbols, and
 *            any NT build's ntdll brings its own numbering.
 *   backend  A service is answered by NAME. On Windows the default is the
 *            host ntdll's export of the same name, called with the same
 *            arguments: the NT native API has kept its signatures since NT 4
 *            for nearly everything a userland calls. A host overrides by
 *            name where the guest's era differs (native32_nt_override). A
 *            Linux backend replaces backend_resolve() and the overrides; the
 *            table and the dispatch stay.
 *
 * native32_nt_process() does what the kernel and LdrpInitializeProcess do
 * before the first instruction: an NT 5 PEB with process parameters, the
 * NLS tables (the guest's own .nls files) and the process heap, made by the
 * guest's own RtlCreateHeap. The host's loader work (mapping, binding,
 * DllMain) is modules32's.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "native32.h"

#define MAX_SVC 0x400
static struct { const char* name; uint8_t argc; native32_syscall_fn fn; void* host; } g_svc[MAX_SVC];
static int g_trace = -1;

#define MAX_OVR 64
static struct { const char* name; native32_syscall_fn fn; } g_ovr[MAX_OVR];
static int g_novr;

void native32_nt_override(const char* name, native32_syscall_fn fn) {
    if (g_novr < MAX_OVR) g_ovr[g_novr].name = name, g_ovr[g_novr++].fn = fn;
    for (int i = 0; i < MAX_SVC; i++)
        if (g_svc[i].name && !strcmp(g_svc[i].name, name)) g_svc[i].fn = fn;
}

/* ---- backend: Windows ---------------------------------------------------- */
static void* backend_resolve(const char* name) {
    return (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), name);
}

/* stdcall with n arguments: the callee pops them. */
static uint32_t call_std(void* fn, const uint32_t* a, int n) {
    uint32_t r;
    __asm {
        mov  edi, esp
        mov  ecx, n
        mov  edx, a
    next:
        test ecx, ecx
        jz   go
        dec  ecx
        push dword ptr [edx + ecx * 4]
        jmp  next
    go:
        call fn
        mov  esp, edi
        mov  r, eax
    }
    return r;
}

static int svc_by_name(const char* name) {
    for (int i = 0; i < MAX_SVC; i++)
        if (g_svc[i].name && !strcmp(g_svc[i].name, name)) return i;
    return -1;
}

uint32_t native32_nt_forward(const char* name, uint32_t* args) {
    int i = svc_by_name(name);
    if (i < 0 || !g_svc[i].host) return 0xC0000002u;              /* STATUS_NOT_IMPLEMENTED */
    return call_std(g_svc[i].host, args, g_svc[i].argc);
}

/* ---- the table, from the guest ntdll's own stubs ------------------------- */
int native32_nt_syscalls(uint32_t base) {
    uint8_t* b = (uint8_t*)(uintptr_t)base;
    IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(b + ((IMAGE_DOS_HEADER*)b)->e_lfanew);
    IMAGE_DATA_DIRECTORY dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY* ed = (IMAGE_EXPORT_DIRECTORY*)(b + dd.VirtualAddress);
    uint32_t* names = (uint32_t*)(b + ed->AddressOfNames);
    uint16_t* ords = (uint16_t*)(b + ed->AddressOfNameOrdinals);
    uint32_t* funcs = (uint32_t*)(b + ed->AddressOfFunctions);
    int n = 0, missing = 0;
    for (uint32_t i = 0; i < ed->NumberOfNames; i++) {
        const char* name = (const char*)(b + names[i]);
        const uint8_t* p = b + funcs[ords[i]];
        if (name[0] != 'N' || name[1] != 't') continue;            /* Zw* are the same stubs */
        if (p[0] != 0xB8 || p[5] != 0x8D || p[6] != 0x54 || p[7] != 0x24 || p[8] != 0x04 ||
            p[9] != 0xCD || p[10] != 0x2E) continue;
        uint32_t svc = *(uint32_t*)(p + 1);
        if (svc >= MAX_SVC) continue;
        g_svc[svc].name = name;
        g_svc[svc].argc = p[11] == 0xC2 ? (uint8_t)(*(uint16_t*)(p + 12) / 4) : 0;
        g_svc[svc].host = backend_resolve(name);
        for (int k = 0; k < g_novr; k++)
            if (!strcmp(g_ovr[k].name, name)) g_svc[svc].fn = g_ovr[k].fn;
        missing += !g_svc[svc].host && !g_svc[svc].fn;
        n++;
    }
    fprintf(stderr, "[syscall] %d services from the guest ntdll, %d with no host counterpart\n", n, missing);
    return n;
}

/* ---- the gate ------------------------------------------------------------ */
void recomp_syscall(int vector) {
    uint32_t svc = g_eax, *args = (uint32_t*)(uintptr_t)g_edx, r;
    if (g_trace < 0) g_trace = getenv("NATIVE32_SYSCALLS") != NULL;
    if (vector != 0x2E || svc >= MAX_SVC || !g_svc[svc].name) {
        fprintf(stderr, "[syscall] int %02Xh service 0x%X: not in the table\n", vector, svc);
        g_eax = 0xC0000002u;
        return;
    }
    if (g_svc[svc].fn) r = g_svc[svc].fn(args);
    else if (g_svc[svc].host) {
        mach_leave();                                 /* a wait must not hold the machine */
        r = call_std(g_svc[svc].host, args, g_svc[svc].argc);
        mach_enter();
    } else {
        fprintf(stderr, "[syscall] %s: no host counterpart\n", g_svc[svc].name);
        r = 0xC0000002u;
    }
    if (g_trace) {
        fprintf(stderr, "[syscall] %-32s(", g_svc[svc].name);
        for (int i = 0; i < g_svc[svc].argc && i < 6; i++) fprintf(stderr, i ? " %08X" : "%08X", args[i]);
        fprintf(stderr, ") -> %08X  from sub_%08X\n", r, g_cur_func);
    }
    g_eax = r;
}

/* NtQueryInformationProcess(ProcessBasicInformation) on this process names
 * the HOST's PEB; the guest wants its own. */
static uint32_t ovr_query_process(uint32_t* a) {
    uint32_t r = native32_nt_forward("NtQueryInformationProcess", a);
    if (!r && a[1] == 0 && (a[0] == 0xFFFFFFFFu || GetProcessId((HANDLE)(uintptr_t)a[0]) == GetCurrentProcessId()))
        MEM32(a[2] + 4) = native32_guest_peb;
    return r;
}

/* ---- named sections the guest's servers would have made --------------
 * csrss creates \NLS\NlsSection* (the NLS files) for kernel32 to open; on
 * the host they do not exist under those names. A host maps a name to a
 * file: NtOpenSection on it makes a read-only section of that file. */
#define MAX_SECTIONS 32
static struct { const wchar_t* name; wchar_t file[MAX_PATH]; } g_sec[MAX_SECTIONS];
static int g_nsec;

void native32_nt_section_file(const wchar_t* name, const wchar_t* file) {
    if (g_nsec < MAX_SECTIONS) {
        g_sec[g_nsec].name = name;
        wcsncpy(g_sec[g_nsec++].file, file, MAX_PATH - 1);
    }
}

static const wchar_t* oa_name(uint32_t oa, int* len) {
    uint32_t us = oa ? MEM32(oa + 8) : 0;
    *len = us ? MEM16(us) / 2 : 0;
    return us ? (const wchar_t*)(uintptr_t)MEM32(us + 4) : L"";
}

/* NtOpenSection(SectionHandle, DesiredAccess, ObjectAttributes) */
static uint32_t ovr_open_section(uint32_t* a) {
    int n;
    const wchar_t* name = oa_name(a[2], &n);
    for (int i = 0; i < g_nsec; i++)
        if ((int)wcslen(g_sec[i].name) == n && !_wcsnicmp(g_sec[i].name, name, n)) {
            HANDLE f = CreateFileW(g_sec[i].file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (f == INVALID_HANDLE_VALUE) break;
            HANDLE s = CreateFileMappingW(f, NULL, PAGE_READONLY, 0, 0, NULL);
            CloseHandle(f);
            if (!s) break;
            MEM32(a[0]) = (uint32_t)(uintptr_t)s;
            return 0;
        }
    uint32_t r = native32_nt_forward("NtOpenSection", a);
    if (r) fprintf(stderr, "[syscall] NtOpenSection %.*ls -> %08X\n", n, name, r);
    return r;
}

/* ---- process start: what the kernel and LdrpInitializeProcess did ------- */
static void* load_file(const char* dir, const char* name) {
    char path[MAX_PATH];
    _snprintf(path, MAX_PATH - 1, "%s\\%s", dir, name);
    path[MAX_PATH - 1] = 0;
    FILE* f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "[nt] %s: missing\n", path); return NULL; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    void* p = VirtualAlloc(NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    fread(p, 1, n, f);
    fclose(f);
    return p;
}

static void ustr(uint8_t* at, const wchar_t* s, uint8_t** pool) {
    size_t n = wcslen(s) * 2;
    memcpy(*pool, s, n + 2);
    *(uint16_t*)at = (uint16_t)n;
    *(uint16_t*)(at + 2) = (uint16_t)(n + 2);
    *(uint32_t*)(at + 4) = (uint32_t)(uintptr_t)*pool;
    *pool += (n + 2 + 3) & ~3u;
}

static uint32_t guest(uint32_t ntdll, const char* fn, int n, const uint32_t* a) {
    uint32_t va = native32_export(ntdll, fn);
    if (!va) { fprintf(stderr, "[nt] ntdll has no %s\n", fn); return 0; }
    native32_call_guest(va, n, a);
    return g_eax;
}

static uint32_t g_preinit[8];
static int g_npreinit;
void native32_nt_preinit(uint32_t va) { if (g_npreinit < 8) g_preinit[g_npreinit++] = va; }

uint32_t native32_nt_process(uint32_t ntdll, uint32_t image_base, const wchar_t* image_path,
                             const wchar_t* cmdline, const char* nls_dir) {
    uint8_t* peb = (uint8_t*)VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    uint8_t* pp = peb + 0x1000;                       /* RTL_USER_PROCESS_PARAMETERS */
    uint8_t* pool = peb + 0x2000;                     /* its strings */
    uint32_t* heaps = (uint32_t*)(peb + 0x800);
    uint8_t* lock = peb + 0x900;                      /* FastPebLock, LoaderLock (24 bytes each) */
    wchar_t cur[MAX_PATH], sysdir[MAX_PATH];
    native32_guest_peb = (uint32_t)(uintptr_t)peb;
    native32_nt_override("NtQueryInformationProcess", ovr_query_process);
    native32_nt_override("NtOpenSection", ovr_open_section);

    /* PEB, NT 5.0 offsets */
    *(uint32_t*)(peb + 0x08) = image_base;
    *(uint32_t*)(peb + 0x10) = (uint32_t)(uintptr_t)pp;
    *(uint32_t*)(peb + 0x1C) = (uint32_t)(uintptr_t)lock;
    *(uint32_t*)(peb + 0x20) = native32_export(ntdll, "RtlEnterCriticalSection");
    *(uint32_t*)(peb + 0x24) = native32_export(ntdll, "RtlLeaveCriticalSection");
    *(uint32_t*)(peb + 0x40) = (uint32_t)(uintptr_t)(peb + 0x600);   /* TlsBitmap -> RTL_BITMAP */
    *(uint32_t*)(peb + 0x600) = 64;
    *(uint32_t*)(peb + 0x604) = (uint32_t)(uintptr_t)(peb + 0x44);
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    *(uint32_t*)(peb + 0x64) = si.dwNumberOfProcessors;
    *(int64_t*)(peb + 0x70) = -(int64_t)2592000 * 10000000;          /* CriticalSectionTimeout: 30 days */
    *(uint32_t*)(peb + 0x78) = 0x100000;                              /* HeapSegmentReserve */
    *(uint32_t*)(peb + 0x7C) = 0x2000;                                /* HeapSegmentCommit */
    *(uint32_t*)(peb + 0x80) = 0x10000;
    *(uint32_t*)(peb + 0x84) = 0x1000;
    *(uint32_t*)(peb + 0x8C) = 16;                                    /* MaximumNumberOfHeaps */
    *(uint32_t*)(peb + 0x90) = (uint32_t)(uintptr_t)heaps;
    *(uint32_t*)(peb + 0xA0) = (uint32_t)(uintptr_t)(lock + 0x20);    /* LoaderLock */
    *(uint32_t*)(peb + 0xA4) = 5;                                     /* Windows 2000: 5.0.2195 */
    *(uint32_t*)(peb + 0xA8) = 0;
    *(uint16_t*)(peb + 0xAC) = 2195;
    *(uint16_t*)(peb + 0xAE) = 0x0400;                                /* SP4 */
    *(uint32_t*)(peb + 0xB0) = 2;                                     /* VER_PLATFORM_WIN32_NT */
    *(uint32_t*)(peb + 0xB4) = 3;                                     /* ImageSubsystem: console */
    *(uint32_t*)(peb + 0xB8) = 4;

    /* Process parameters, normalized (absolute pointers) */
    GetCurrentDirectoryW(MAX_PATH - 1, cur);
    if (cur[wcslen(cur) - 1] != L'\\') wcscat(cur, L"\\");
    GetSystemDirectoryW(sysdir, MAX_PATH);
    *(uint32_t*)(pp + 0x00) = 0x1000;
    *(uint32_t*)(pp + 0x04) = 0x2A0;
    *(uint32_t*)(pp + 0x08) = 1;                                      /* RTL_USER_PROC_PARAMS_NORMALIZED */
    *(uint32_t*)(pp + 0x18) = (uint32_t)(uintptr_t)GetStdHandle(STD_INPUT_HANDLE);
    *(uint32_t*)(pp + 0x1C) = (uint32_t)(uintptr_t)GetStdHandle(STD_OUTPUT_HANDLE);
    *(uint32_t*)(pp + 0x20) = (uint32_t)(uintptr_t)GetStdHandle(STD_ERROR_HANDLE);
    ustr(pp + 0x24, cur, &pool);
    ustr(pp + 0x30, sysdir, &pool);
    ustr(pp + 0x38, image_path, &pool);
    ustr(pp + 0x40, cmdline, &pool);
    {
        wchar_t* e = GetEnvironmentStringsW();
        size_t n = 0;
        while (e[n] || e[n + 1]) n++;
        void* copy = VirtualAlloc(NULL, (n + 2) * 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        memcpy(copy, e, (n + 2) * 2);
        FreeEnvironmentStringsW(e);
        *(uint32_t*)(pp + 0x48) = (uint32_t)(uintptr_t)copy;
    }
    ustr(pp + 0x70, image_path, &pool);                               /* WindowTitle */
    ustr(pp + 0x78, L"WinSta0\\Default", &pool);                      /* DesktopInfo */
    ustr(pp + 0x80, L"", &pool);
    ustr(pp + 0x88, L"", &pool);

    /* NLS: the guest's own code page and case tables */
    void* ansi = load_file(nls_dir, "c_1252.nls");
    void* oem = load_file(nls_dir, "c_437.nls");
    void* casetab = load_file(nls_dir, "l_intl.nls");
    if (!ansi || !oem || !casetab) return 0;
    *(uint32_t*)(peb + 0x58) = (uint32_t)(uintptr_t)ansi;
    *(uint32_t*)(peb + 0x5C) = (uint32_t)(uintptr_t)oem;
    *(uint32_t*)(peb + 0x60) = (uint32_t)(uintptr_t)casetab;
    {
        static uint8_t info[0x80];                                    /* NLSTABLEINFO */
        uint32_t a[4] = { (uint32_t)(uintptr_t)ansi, (uint32_t)(uintptr_t)oem, (uint32_t)(uintptr_t)casetab,
                          (uint32_t)(uintptr_t)info };
        guest(ntdll, "RtlInitNlsTables", 4, a);
        a[0] = (uint32_t)(uintptr_t)info;
        guest(ntdll, "RtlResetRtlTranslations", 1, a);
    }
    /* LdrpInitializeProcess's own unexported steps before the heap, by
     * address (the host finds them; NT 5.0: RtlpInitDeferedCriticalSection,
     * which seeds the critical sections' debug-info pool). */
    for (int i = 0; i < g_npreinit; i++) native32_call_guest(g_preinit[i], 0, NULL);
    {
        uint32_t a[6] = { 0x00000002u /* HEAP_GROWABLE */, 0, 0, 0, 0, 0 };
        uint32_t h = guest(ntdll, "RtlCreateHeap", 6, a);
        *(uint32_t*)(peb + 0x18) = h;
        fprintf(stderr, "[nt] guest PEB %p, process heap %08X\n", peb, h);
        if (!h) return 0;
    }
    /* after the heap: a critical section's debug info comes from it */
    {
        uint32_t a[1] = { (uint32_t)(uintptr_t)lock };
        guest(ntdll, "RtlInitializeCriticalSection", 1, a);
        a[0] = (uint32_t)(uintptr_t)(lock + 0x20);
        guest(ntdll, "RtlInitializeCriticalSection", 1, a);
    }
    return (uint32_t)(uintptr_t)peb;
}

/* ---- loader data: the modules the host mapped, as ntdll's loader keeps them
 * PEB_LDR_DATA (NT 5): 0x0C InLoadOrder, 0x14 InMemoryOrder, 0x1C InInitializationOrder.
 * LDR_DATA_TABLE_ENTRY: links at 0x00/0x08/0x10, DllBase 0x18, EntryPoint
 * 0x1C, SizeOfImage 0x20, FullDllName 0x24, BaseDllName 0x2C, Flags 0x34,
 * LoadCount 0x38, HashLinks 0x3C, TimeDateStamp 0x44. */
static void list_init(uint8_t* head) { MEM32((uint32_t)(uintptr_t)head) = MEM32((uint32_t)(uintptr_t)head + 4) = (uint32_t)(uintptr_t)head; }

static void list_tail(uint8_t* head, uint8_t* e) {
    uint32_t h = (uint32_t)(uintptr_t)head, x = (uint32_t)(uintptr_t)e, last = MEM32(h + 4);
    MEM32(x) = h;
    MEM32(x + 4) = last;
    MEM32(last) = x;
    MEM32(h + 4) = x;
}

static uint32_t g_insert_fn;
void native32_nt_loader(uint32_t hash_table, uint32_t insert_fn) {
    for (int i = 0; i < 32; i++) list_init((uint8_t*)(uintptr_t)(hash_table + 8 * i));
    g_insert_fn = insert_fn;
}

void native32_nt_module(uint32_t base, const wchar_t* path) {
    uint8_t* peb = (uint8_t*)(uintptr_t)native32_guest_peb;
    uint8_t* ldr = (uint8_t*)(uintptr_t)MEM32(native32_guest_peb + 0x0C);
    if (!ldr) {
        ldr = (uint8_t*)calloc(1, 0x30);
        *(uint32_t*)ldr = 0x28;
        ldr[4] = 1;
        list_init(ldr + 0x0C); list_init(ldr + 0x14); list_init(ldr + 0x1C);
        *(uint32_t*)(peb + 0x0C) = (uint32_t)(uintptr_t)ldr;
    }
    uint8_t* b = (uint8_t*)(uintptr_t)base;
    IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(b + ((IMAGE_DOS_HEADER*)b)->e_lfanew);
    int dll = (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
    uint8_t* e = (uint8_t*)calloc(1, 0x50);
    uint8_t* pool = (uint8_t*)calloc(1, (wcslen(path) + 1) * 2 + 8);
    const wchar_t* name = wcsrchr(path, L'\\');
    name = name ? name + 1 : path;
    *(uint32_t*)(e + 0x18) = base;
    *(uint32_t*)(e + 0x1C) = nt->OptionalHeader.AddressOfEntryPoint ? base + nt->OptionalHeader.AddressOfEntryPoint : 0;
    *(uint32_t*)(e + 0x20) = nt->OptionalHeader.SizeOfImage;
    ustr(e + 0x24, path, &pool);
    *(uint16_t*)(e + 0x2C) = (uint16_t)(wcslen(name) * 2);           /* BaseDllName: the tail of FullDllName */
    *(uint16_t*)(e + 0x2E) = (uint16_t)(wcslen(name) * 2 + 2);
    *(uint32_t*)(e + 0x30) = *(uint32_t*)(e + 0x28) + (uint32_t)((name - path) * 2);
    *(uint32_t*)(e + 0x34) = (dll ? 0x4u : 0) | 0x4000u | 0x80000u;   /* IMAGE_DLL, ENTRY_PROCESSED, PROCESS_ATTACH_CALLED */
    *(uint16_t*)(e + 0x38) = 0xFFFF;                                  /* static: never unloaded */
    list_init(e + 0x3C);
    *(uint32_t*)(e + 0x44) = nt->FileHeader.TimeDateStamp;
    if (g_insert_fn) {           /* the guest's own: hash table, load and memory order */
        uint32_t a = (uint32_t)(uintptr_t)e;
        native32_call_guest(g_insert_fn, 1, &a);
    } else {
        list_tail(ldr + 0x0C, e);
        list_tail(ldr + 0x14, e + 0x08);
    }
    if (dll) list_tail(ldr + 0x1C, e + 0x10);
}

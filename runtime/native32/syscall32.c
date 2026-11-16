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

#define MAX_OVR 128
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
static uint32_t win32k_call(uint32_t svc, uint32_t* args);
static void callback_return(uint32_t out, uint32_t outlen, uint32_t status);

void recomp_syscall(int vector) {
    uint32_t svc = g_eax, *args = (uint32_t*)(uintptr_t)g_edx, r;
    if (g_trace < 0) g_trace = getenv("NATIVE32_SYSCALLS") != NULL;
    if (g_trace < 0) g_trace = getenv("NATIVE32_SYSCALLS") != NULL;
    if (vector == 0x2B) {                 /* the callback dispatcher's own NtCallbackReturn */
        callback_return(g_ecx, g_edx, g_eax);
        return;
    }
    if (vector == 0x2E && svc >= 0x1000) {
        g_eax = win32k_call(svc, args);
        return;
    }
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
        for (int i = 0; i < g_svc[svc].argc && i < 10; i++) fprintf(stderr, i ? " %08X" : "%08X", args[i]);
        fprintf(stderr, ") -> %08X  from sub_%08X", r, g_cur_func);
        /* The object's name, for an Open/Create whose third argument is
         * OBJECT_ATTRIBUTES (Length 0x18) */
        if (g_svc[svc].argc >= 3 && args[2] > 0x10000 && !IsBadReadPtr((void*)(uintptr_t)args[2], 0x18) &&
            MEM32(args[2]) == 0x18 && MEM32(args[2] + 8) && !IsBadReadPtr((void*)(uintptr_t)MEM32(args[2] + 8), 8)) {
            uint32_t us = MEM32(args[2] + 8);
            fprintf(stderr, "  %.*ls", MEM16(us) / 2, (wchar_t*)(uintptr_t)MEM32(us + 4));
        }
        fprintf(stderr, "\n");
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


/* ---- images: the kernel's half of the guest's own loader ---------------
 * The guest ntdll loads DLLs itself (LdrpMapDll): it opens the file, makes an
 * image section (NtCreateSection, SEC_IMAGE) and maps a view of it. Here:
 *   - a guest module the host already mapped (modules32's table, by file
 *     name): the view is that mapping, so its lifted code is what runs;
 *   - a host DLL (in the host's system directory): a proxy image, a PE
 *     header and export directory whose exports are the host DLL's functions
 *     (GetProcAddress, forwarders and API sets resolved by the host), with
 *     no entry point and no imports: the guest's loader snaps them like any
 *     DLL's and the lifted callers reach the host functions by the bridge;
 *   - anything else is refused: an image that is neither lifted nor the
 *     host's never runs (the guard: no original Windows 2000 binary is ever
 *     started natively). Process creation is refused the same way. */
#define MAX_IMAGES 64
static struct { HANDLE h; uint32_t base, size; } g_img[MAX_IMAGES];
static int g_nimg;

static int img_by_handle(uint32_t h) {
    for (int i = g_nimg - 1; i >= 0; i--)        /* newest first: handle values are reused */
        if (g_img[i].h && (uint32_t)(uintptr_t)g_img[i].h == h) return i;
    return -1;
}

static uint32_t image_size(uint32_t base) {
    IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(uintptr_t)(base + MEM32(base + 0x3C));
    return nt->OptionalHeader.SizeOfImage;
}

/* The guard's other half: a host DLL can start processes itself (cmd.exe
 * fell back to shell32's ShellExecuteEx when its own CreateProcess was
 * refused, and the host ran the program). Through a proxy, these exports are
 * refusals with the same signatures. */
static BOOL WINAPI deny_cp10(void* a, void* b, void* c, void* d, BOOL e, DWORD f, void* g, void* h, void* i, void* j) {
    (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; (void)g; (void)h; (void)i; (void)j;
    fprintf(stderr, "[guard] host CreateProcess from the guest: refused\n");
    SetLastError(ERROR_ACCESS_DENIED);
    return FALSE;
}
static BOOL WINAPI deny_cp11(void* t, void* a, void* b, void* c, void* d, BOOL e, DWORD f, void* g, void* h, void* i, void* j) {
    (void)t;
    return deny_cp10(a, b, c, d, e, f, g, h, i, j);
}
static BOOL WINAPI deny_cp9(void* t, DWORD l, void* a, void* b, DWORD f, void* g, void* h, void* i, void* j) {
    (void)t; (void)l; (void)a; (void)b; (void)f; (void)g; (void)h; (void)i; (void)j;
    return deny_cp10(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}
static BOOL WINAPI deny_sex(void* info) {
    (void)info;
    fprintf(stderr, "[guard] host ShellExecuteEx from the guest: refused\n");
    SetLastError(ERROR_ACCESS_DENIED);
    return FALSE;
}
static void* WINAPI deny_se(void* a, void* b, void* c, void* d, void* e, int f) {
    (void)a; (void)b; (void)c; (void)d; (void)e; (void)f;
    fprintf(stderr, "[guard] host ShellExecute from the guest: refused\n");
    return (void*)(uintptr_t)5;                                   /* SE_ERR_ACCESSDENIED */
}
static UINT WINAPI deny_winexec(const char* a, UINT b) {
    (void)a; (void)b;
    fprintf(stderr, "[guard] host WinExec from the guest: refused\n");
    return 0;
}
static const struct { const char* name; void* fn; } g_deny[] = {
    { "CreateProcessA", deny_cp10 }, { "CreateProcessW", deny_cp10 },
    { "CreateProcessAsUserA", deny_cp11 }, { "CreateProcessAsUserW", deny_cp11 },
    { "CreateProcessWithLogonW", deny_cp11 }, { "CreateProcessWithTokenW", deny_cp9 },
    { "ShellExecuteExA", deny_sex }, { "ShellExecuteExW", deny_sex },
    { "ShellExecuteA", deny_se }, { "ShellExecuteW", deny_se }, { "WinExec", deny_winexec },
};

/* Host functions a host puts in place of a proxied export (native32_nt_proxy_hook):
 * the same signature, usually calling the real one and noting its result
 * (w32kgdi.c registers the HDC host user32's BeginPaint returns). */
#define MAX_HOOKS 224
static struct { const char* name; void* fn; } g_hook[MAX_HOOKS];
static int g_nhook;
void native32_nt_proxy_hook(const char* name, void* fn) {
    if (g_nhook < MAX_HOOKS) g_hook[g_nhook].name = name, g_hook[g_nhook++].fn = fn;
}

static void* denied(const char* name) {
    for (int i = 0; i < g_nhook; i++)
        if (!strcmp(g_hook[i].name, name)) return g_hook[i].fn;
    for (int i = 0; i < (int)(sizeof g_deny / sizeof g_deny[0]); i++)
        if (!strcmp(g_deny[i].name, name)) return g_deny[i].fn;
    return NULL;
}

/* Windows 2000 exports a modern host DLL no longer has: the guest's loader
 * fails the whole image over one (ole32's advapi32 imports, the Safer/site
 * SID calls of IE5). Each answers "none", in its own signature. Sorted by
 * name within a DLL: the proxy's name table is binary-searched. */
static void* WINAPI gone_site_sid(void* token) { (void)token; return NULL; }
static long WINAPI gone_mangled_sid(void* sid, unsigned long n, void* out) {
    (void)sid; (void)n;
    if (out) *(void**)out = NULL;
    return (long)0x80004005;                                     /* E_FAIL */
}
static BOOL WINAPI gone_restricted(void) { return FALSE; }
static const struct { const char* dll, *name; void* fn; } g_gone[] = {
    { "advapi32.dll", "GetMangledSiteSid", gone_mangled_sid },
    { "advapi32.dll", "GetSiteSidFromToken", gone_site_sid },
    { "advapi32.dll", "IsProcessRestricted", gone_restricted },
};

/* A PE image in memory whose export table is a host DLL's, by ordinal and
 * name; each export's RVA is (host function - proxy base), modulo 2^32.
 * Names in g_gone the host lacks are added after its functions. */
static uint32_t proxy_image(const wchar_t* path) {
    HMODULE h = LoadLibraryW(path);
    if (!h) return 0;
    uint8_t* hb = (uint8_t*)h;
    IMAGE_NT_HEADERS* hnt = (IMAGE_NT_HEADERS*)(hb + ((IMAGE_DOS_HEADER*)hb)->e_lfanew);
    IMAGE_DATA_DIRECTORY hd = hnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!hd.VirtualAddress) return 0;
    IMAGE_EXPORT_DIRECTORY* he = (IMAGE_EXPORT_DIRECTORY*)(hb + hd.VirtualAddress);
    uint32_t nf = he->NumberOfFunctions, nn = he->NumberOfNames, strs = 0, hnf, hnn;
    uint32_t* hnames = (uint32_t*)(hb + he->AddressOfNames);
    uint16_t* hords = (uint16_t*)(hb + he->AddressOfNameOrdinals);
    const wchar_t* file = wcsrchr(path, L'\\') ? wcsrchr(path, L'\\') + 1 : path;
    int gone[sizeof g_gone / sizeof g_gone[0]], ngone = 0;
    for (int i = 0; i < (int)(sizeof g_gone / sizeof g_gone[0]); i++) {
        wchar_t w[32];
        MultiByteToWideChar(CP_ACP, 0, g_gone[i].dll, -1, w, 32);
        if (!_wcsicmp(w, file) && !GetProcAddress(h, g_gone[i].name)) gone[ngone++] = i;
    }
    for (uint32_t i = 0; i < nn; i++) strs += (uint32_t)strlen((char*)hb + hnames[i]) + 1;
    for (int i = 0; i < ngone; i++) strs += (uint32_t)strlen(g_gone[gone[i]].name) + 1;
    hnf = nf, hnn = nn;
    nf += ngone, nn += ngone;
    uint32_t dir = 0x1000, funcs = dir + 40, names = funcs + 4 * nf, ords = names + 4 * nn, pool = ords + 2 * nn;
    uint32_t size = (pool + strs + 64 + 0xFFF) & ~0xFFFu;
    uint8_t* p = (uint8_t*)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    uint32_t base = (uint32_t)(uintptr_t)p;
    IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(p + 0x40);
    ((IMAGE_DOS_HEADER*)p)->e_magic = IMAGE_DOS_SIGNATURE;
    ((IMAGE_DOS_HEADER*)p)->e_lfanew = 0x40;
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
    nt->FileHeader.Characteristics = IMAGE_FILE_DLL | IMAGE_FILE_32BIT_MACHINE | IMAGE_FILE_EXECUTABLE_IMAGE;
    nt->FileHeader.TimeDateStamp = hnt->FileHeader.TimeDateStamp;
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    nt->OptionalHeader.ImageBase = base;
    nt->OptionalHeader.SectionAlignment = 0x1000;
    nt->OptionalHeader.FileAlignment = 0x200;
    nt->OptionalHeader.MajorOperatingSystemVersion = 4;
    nt->OptionalHeader.MajorSubsystemVersion = 4;
    nt->OptionalHeader.SizeOfImage = size;
    nt->OptionalHeader.SizeOfHeaders = 0x1000;
    nt->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
    nt->OptionalHeader.NumberOfRvaAndSizes = 16;
    nt->OptionalHeader.DataDirectory[0].VirtualAddress = dir;
    nt->OptionalHeader.DataDirectory[0].Size = pool + strs - dir;
    IMAGE_EXPORT_DIRECTORY* e = (IMAGE_EXPORT_DIRECTORY*)(p + dir);
    e->Base = he->Base;
    e->NumberOfFunctions = nf;
    e->NumberOfNames = nn;
    e->AddressOfFunctions = funcs;
    e->AddressOfNames = names;
    e->AddressOfNameOrdinals = ords;
    for (uint32_t i = 0; i < hnf; i++) {
        FARPROC f = GetProcAddress(h, (LPCSTR)(uintptr_t)(he->Base + i));
        ((uint32_t*)(p + funcs))[i] = f ? (uint32_t)(uintptr_t)f - base : 0;
    }
    for (uint32_t i = 0, j = 0, k = 0; i < nn; i++) {   /* the host's names and g_gone's, merged in order */
        int extra = k < (uint32_t)ngone && (j >= hnn || strcmp(g_gone[gone[k]].name, (const char*)hb + hnames[j]) < 0);
        const char* s = extra ? g_gone[gone[k]].name : (const char*)hb + hnames[j];
        uint16_t o = extra ? (uint16_t)(hnf + k) : hords[j];
        if (extra) ((uint32_t*)(p + funcs))[o] = (uint32_t)(uintptr_t)g_gone[gone[k]].fn - base, k++;
        else j++;
        strcpy((char*)p + pool, s);
        ((uint32_t*)(p + names))[i] = pool;
        ((uint16_t*)(p + ords))[i] = o;
        if (denied(s)) ((uint32_t*)(p + funcs))[o] = (uint32_t)(uintptr_t)denied(s) - base;
        pool += (uint32_t)strlen(s) + 1;
    }
    e->Name = pool;
    WideCharToMultiByte(CP_ACP, 0, wcsrchr(path, L'\\') ? wcsrchr(path, L'\\') + 1 : path, -1,
                        (char*)p + pool, 60, NULL, NULL);
    return base;
}

static int under(const wchar_t* path, const wchar_t* dir) {
    size_t n = wcslen(dir);
    return !_wcsnicmp(path, dir, n) && (path[n] == L'\\' || !path[n]);
}

/* NtCreateSection(Handle*, Access, ObjectAttributes, MaximumSize*, Protect, Attributes, File) */
static uint32_t ovr_create_section(uint32_t* a) {
    if (!(a[5] & 0x01000000u) || !a[6] || g_nimg >= MAX_IMAGES)   /* SEC_IMAGE */
        return native32_nt_forward("NtCreateSection", a);
    wchar_t raw[MAX_PATH + 8], sys[MAX_PATH], win[MAX_PATH];
    char name[MAX_PATH];
    if (!GetFinalPathNameByHandleW((HANDLE)(uintptr_t)a[6], raw, MAX_PATH, 0)) return 0xC0000008u;
    const wchar_t* path = !wcsncmp(raw, L"\\\\?\\", 4) ? raw + 4 : raw;
    WideCharToMultiByte(CP_ACP, 0, path, -1, name, MAX_PATH, NULL, NULL);
    uint32_t base = native32_module(name), size;
    GetSystemDirectoryW(sys, MAX_PATH);
    GetWindowsDirectoryW(win, MAX_PATH);
    {
        /* The guard: a program image is either lifted or not run. A host DLL
         * is served as a proxy; a host or original EXE never is. */
        size_t n = wcslen(path);
        int exe = n > 4 && (!_wcsicmp(path + n - 4, L".exe") || !_wcsicmp(path + n - 4, L".com") ||
                            !_wcsicmp(path + n - 4, L".scr"));
        if (exe && !base) {
            fprintf(stderr, "[guard] %ls: a program that is not lifted: not run\n", path);
            return 0xC0000022u;                                              /* STATUS_ACCESS_DENIED */
        }
    }
    if (base) size = image_size(base);
    else if (under(path, sys) || under(path, win)) {
        if (!(base = proxy_image(path))) return 0xC000007Bu;                 /* STATUS_INVALID_IMAGE_FORMAT */
        size = image_size(base);
        fprintf(stderr, "[nt] %ls: the host's, through a proxy image at 0x%08X\n", path, base);
    } else {
        fprintf(stderr, "[guard] %ls is neither lifted nor the host's: not mapped\n", path);
        return 0xC0000022u;                                                  /* STATUS_ACCESS_DENIED */
    }
    g_img[g_nimg].h = CreateEventA(NULL, FALSE, FALSE, NULL);
    g_img[g_nimg].base = base;
    g_img[g_nimg].size = size;
    MEM32(a[0]) = (uint32_t)(uintptr_t)g_img[g_nimg++].h;
    return 0;
}

/* NtMapViewOfSection(Section, Process, Base*, ZeroBits, Commit, Offset*, ViewSize*, ...) */
static uint32_t ovr_map_view(uint32_t* a) {
    int i = img_by_handle(a[0]);
    if (i < 0) return native32_nt_forward("NtMapViewOfSection", a);
    MEM32(a[2]) = g_img[i].base;
    MEM32(a[6]) = g_img[i].size;
    return 0;
}

/* NtClose on an image section handle: the loader closes it right after
 * mapping, and the host hands the same value to the next object. */
static uint32_t ovr_close(uint32_t* a) {
    int i = img_by_handle(a[0]);
    if (i >= 0) g_img[i].h = NULL;
    return native32_nt_forward("NtClose", a);
}

/* NtUnmapViewOfSection(Process, Base): a guest image or proxy stays mapped. */
static uint32_t ovr_unmap_view(uint32_t* a) {
    for (int i = 0; i < g_nimg; i++)
        if (g_img[i].base == a[1]) return 0;
    return native32_nt_forward("NtUnmapViewOfSection", a);
}

/* NtQuerySection(Section, Class, Buffer, Length, ReturnLength*) for an image:
 * SectionImageInformation (1) from its headers. */
static uint32_t ovr_query_section(uint32_t* a) {
    int i = img_by_handle(a[0]);
    if (i < 0) return native32_nt_forward("NtQuerySection", a);
    if (a[1] != 1 || a[3] < 0x30) return 0xC0000003u;                         /* STATUS_INVALID_INFO_CLASS */
    IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(uintptr_t)(g_img[i].base + MEM32(g_img[i].base + 0x3C));
    uint8_t* o = (uint8_t*)(uintptr_t)a[2];
    memset(o, 0, 0x30);
    *(uint32_t*)(o + 0x00) = nt->OptionalHeader.AddressOfEntryPoint ? g_img[i].base + nt->OptionalHeader.AddressOfEntryPoint : 0;
    *(uint32_t*)(o + 0x08) = nt->OptionalHeader.SizeOfStackReserve;
    *(uint32_t*)(o + 0x0C) = nt->OptionalHeader.SizeOfStackCommit;
    *(uint32_t*)(o + 0x10) = nt->OptionalHeader.Subsystem;
    *(uint16_t*)(o + 0x14) = nt->OptionalHeader.MinorSubsystemVersion;
    *(uint16_t*)(o + 0x16) = nt->OptionalHeader.MajorSubsystemVersion;
    *(uint16_t*)(o + 0x1C) = nt->FileHeader.Characteristics;
    *(uint16_t*)(o + 0x1E) = nt->OptionalHeader.DllCharacteristics;
    *(uint16_t*)(o + 0x20) = nt->FileHeader.Machine;
    o[0x22] = 1;
    if (a[4]) MEM32(a[4]) = 0x30;
    return 0;
}

/* \KnownDlls is the host's: its sections are the host's own system DLLs as
 * images, which the guest must not map. Without it the loader searches the
 * DLL path, which ends at the host system directory (proxies, above). */
static uint32_t ovr_open_directory(uint32_t* a) {
    int n;
    const wchar_t* name = oa_name(a[2], &n);
    if (n >= 10 && !_wcsnicmp(name, L"\\KnownDlls", 10)) return 0xC0000034u;     /* NAME_NOT_FOUND */
    return native32_nt_forward("NtOpenDirectoryObject", a);
}

/* NtRaiseHardError(Status, NumberOfParameters, UnicodeStringMask, Parameters*,
 * ResponseOption, Response*): the message box csrss would show, printed. */
static uint32_t ovr_hard_error(uint32_t* a) {
    fprintf(stderr, "[nt] hard error %08X", a[0]);
    for (uint32_t i = 0; i < a[1] && i < 4 && a[3]; i++) {
        uint32_t p = MEM32(a[3] + 4 * i);
        if (a[2] & (1u << i)) fprintf(stderr, " \"%.*ls\"", MEM16(p) / 2, (wchar_t*)(uintptr_t)MEM32(p + 4));
        else fprintf(stderr, " %08X", p);
    }
    fprintf(stderr, "\n");
    if (a[5]) MEM32(a[5]) = 1;                        /* ResponseReturnToCaller */
    return 0;
}

/* ---- threads ------------------------------------------------------------
 * NtCreateThread(Handle*, Access, ObjectAttributes, Process, ClientId*,
 * Context*, InitialTeb*, CreateSuspended): the guest's kernel32 has made the
 * stack and a CONTEXT that starts at BaseThreadStartThunk (eax = the start
 * routine, ebx = its parameter). A host thread runs it: it enters the machine
 * (its own guest TEB, made by mach_enter), takes the guest's stack and
 * registers from the CONTEXT and calls the lifted Eip. ponytail: the loader's
 * per-thread start (LdrInitializeThunk: DLL_THREAD_ATTACH) is not run; no DLL
 * here has needed it. Only threads of this process. */
typedef struct { uint8_t ctx[0x2CC]; uint32_t base, limit; } nt_thread_t;
static DWORD WINAPI nt_thread(LPVOID p) {
    nt_thread_t t = *(nt_thread_t*)p;
    free(p);
    recomp_func_t f = recomp_lookup(*(uint32_t*)(t.ctx + 0xB8));
    if (t.base) {
        /* The stack the guest made: reserved, its top committed, a guard
         * page below. Its growth is the kernel's for a thread's own stack
         * only; this host thread's is another, so the guard page faulted
         * (a fatal STATUS_GUARD_PAGE_VIOLATION). All of it committed. */
        MEMORY_BASIC_INFORMATION mb;
        DWORD old;
        if (VirtualQuery((void*)(uintptr_t)(t.base - 1), &mb, sizeof mb)) {
            SIZE_T n = t.base - (uint32_t)(uintptr_t)mb.AllocationBase;
            VirtualAlloc(mb.AllocationBase, n, MEM_COMMIT, PAGE_READWRITE);
            VirtualProtect(mb.AllocationBase, n, PAGE_READWRITE, &old);
            t.limit = (uint32_t)(uintptr_t)mb.AllocationBase;
        }
    }
    mach_enter();
    if (t.base) MEM32(g_fs_base + 4) = t.base, MEM32(g_fs_base + 8) = t.limit;
    g_edi = *(uint32_t*)(t.ctx + 0x9C); g_esi = *(uint32_t*)(t.ctx + 0xA0);
    g_ebx = *(uint32_t*)(t.ctx + 0xA4); g_edx = *(uint32_t*)(t.ctx + 0xA8);
    g_ecx = *(uint32_t*)(t.ctx + 0xAC); g_eax = *(uint32_t*)(t.ctx + 0xB0);
    g_ebp = *(uint32_t*)(t.ctx + 0xB4); g_esp = *(uint32_t*)(t.ctx + 0xC4);
    if (f) f();
    else fprintf(stderr, "[nt] thread start 0x%08X is not lifted\n", *(uint32_t*)(t.ctx + 0xB8));
    mach_leave();
    return 0;
}
static uint32_t ovr_create_thread(uint32_t* a) {
    if (a[3] != 0xFFFFFFFFu && GetProcessId((HANDLE)(uintptr_t)a[3]) != GetCurrentProcessId()) {
        fprintf(stderr, "[guard] a thread in another process: refused\n");
        return 0xC0000022u;
    }
    nt_thread_t* t = (nt_thread_t*)calloc(1, sizeof *t);
    DWORD tid;
    memcpy(t->ctx, (void*)(uintptr_t)a[5], sizeof t->ctx);
    if (a[6]) t->base = MEM32(a[6] + 8), t->limit = MEM32(a[6] + 12);    /* INITIAL_TEB StackBase, StackLimit */
    HANDLE h = CreateThread(NULL, 16u << 20, nt_thread, t, STACK_SIZE_PARAM_IS_A_RESERVATION | (a[7] ? CREATE_SUSPENDED : 0), &tid);
    if (!h) { free(t); return 0xC0000017u; }
    MEM32(a[0]) = (uint32_t)(uintptr_t)h;
    if (a[4]) MEM32(a[4]) = GetCurrentProcessId(), MEM32(a[4] + 4) = tid;
    return 0;
}
/* NtTerminateThread(Thread, Status) on the calling thread: give up the
 * machine first, or every other guest thread waits for it forever. */
static uint32_t ovr_terminate_thread(uint32_t* a) {
    if (!a[0] || a[0] == 0xFFFFFFFEu || GetThreadId((HANDLE)(uintptr_t)a[0]) == GetCurrentThreadId()) {
        mach_leave();
        ExitThread(a[1]);
    }
    return native32_nt_forward("NtTerminateThread", a);
}

static uint32_t ovr_no_process(uint32_t* a) {
    (void)a;
    fprintf(stderr, "[guard] the guest tried to create a process: refused\n");
    return 0xC0000022u;
}

/* ---- win32k: the window manager's and GDI's system calls (0x1000..) -----
 * user32 and gdi32 call win32k.sys through the same gate, with service
 * numbers from 0x1000. The numbers and argument counts are the guest's own,
 * read from its user32/gdi32 stubs (most are not exported, so the stubs are
 * found by their shape); the names come from a "0xNNNN Name" file
 * (tools/w32k_names.py). A host answers a service by name
 * (native32_nt_win32k_override); an unanswered one is logged once and
 * returns 0. */
#define W32K_MAX 0x400
static struct { char name[64]; uint8_t argc, seen; native32_syscall_fn fn; } g_w32k[W32K_MAX];

int native32_nt_win32k(const uint32_t* bases, int nbases, const char* names_file) {
    int stubs = 0, named = 0;
    for (int m = 0; m < nbases; m++) {
        uint32_t base = bases[m], size = image_size(base);
        for (uint32_t p = base + 0x1000; p + 16 < base + size; p++) {
            const uint8_t* b = (const uint8_t*)(uintptr_t)p;
            if (b[0] != 0xB8 || b[5] != 0x8D || b[6] != 0x54 || b[7] != 0x24 || b[8] != 0x04 ||
                b[9] != 0xCD || b[10] != 0x2E) continue;
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
    }
    fprintf(stderr, "[win32k] %d stubs in the guest's user32/gdi32, %d names\n", stubs, named);
    return stubs;
}

void native32_nt_win32k_override(const char* name, native32_syscall_fn fn) {
    for (int i = 0; i < W32K_MAX; i++)
        if (!strcmp(g_w32k[i].name, name)) { g_w32k[i].fn = fn; return; }
    fprintf(stderr, "[win32k] no service named %s\n", name);
}

int native32_guest_loaded;             /* the guest's loader is done (native32_nt_boot) */
void (*native32_win32k_pre)(void);   /* before every win32k service (GDI's TEB batch) */

static uint32_t win32k_call(uint32_t svc, uint32_t* args) {
    int i = (int)(svc - 0x1000);
    if (native32_win32k_pre) native32_win32k_pre();
    if (i < 0 || i >= W32K_MAX) return 0xC000001Cu;                       /* STATUS_INVALID_SYSTEM_SERVICE */
    uint32_t r = g_w32k[i].fn ? g_w32k[i].fn(args) : 0;
    if (g_trace || (!g_w32k[i].fn && !g_w32k[i].seen)) {
        fprintf(stderr, "[win32k] %-34s(", g_w32k[i].name[0] ? g_w32k[i].name : "?");
        for (int k = 0; k < g_w32k[i].argc && k < 16; k++) fprintf(stderr, k ? " %08X" : "%08X", args[k]);
        fprintf(stderr, ") -> %08X%s  0x%X from sub_%08X\n", r, g_w32k[i].fn ? "" : "  NOT SHIMMED", svc, g_cur_func);
    }
    g_w32k[i].seen = 1;
    return r;
}

/* ---- user-mode callbacks ---------------------------------------------------
 * win32k calls user32 back (a window procedure, a hook, a client-side
 * allocation) through KiUserCallbackDispatcher(ApiNumber, Input, Length),
 * which calls Peb->KernelCallbackTable[ApiNumber](Input, Length). The routine
 * ends in NtCallbackReturn(Output, Length, Status), or returns and the
 * dispatcher's `int 2Bh` does it. Neither unwinds here: they record the
 * result, the routine returns, and the dispatcher's trailing int3 (lifted as
 * a return) comes back to native32_nt_callback. */
#define CB_DEPTH 32
static struct { uint32_t out, outlen, status, done; } g_cb[CB_DEPTH];
static int g_cbn;

static void callback_return(uint32_t out, uint32_t outlen, uint32_t status) {
    if (g_cbn <= 0 || g_cb[g_cbn - 1].done) return;
    g_cb[g_cbn - 1].out = out, g_cb[g_cbn - 1].outlen = outlen, g_cb[g_cbn - 1].status = status;
    g_cb[g_cbn - 1].done = 1;
}

/* NtCallbackReturn(Output, OutputLength, Status) */
static uint32_t ovr_callback_return(uint32_t* a) {
    if (g_cbn <= 0) return 0xC0000258u;                                    /* STATUS_NO_CALLBACK_ACTIVE */
    callback_return(a[0], a[1], a[2]);
    return 0;
}

uint32_t native32_nt_callback(uint32_t api, uint32_t in, uint32_t len, uint32_t* out, uint32_t* outlen) {
    uint32_t kucd = native32_export(native32_module("ntdll.dll"), "KiUserCallbackDispatcher");
    if (!kucd || g_cbn >= CB_DEPTH) return 0xC0000258u;
    uint32_t args[3] = { api, in, len };
    mach_enter();
    uint32_t sp = g_esp;
    g_cb[g_cbn].done = 0;
    g_cbn++;
    native32_call_guest(kucd, 3, args);
    g_cbn--;
    if (!g_cb[g_cbn].done) g_cb[g_cbn].status = g_eax, g_cb[g_cbn].out = 0, g_cb[g_cbn].outlen = 0;
    g_esp = sp;
    mach_leave();
    if (out) *out = g_cb[g_cbn].out;
    if (outlen) *outlen = g_cb[g_cbn].outlen;
    return g_cb[g_cbn].status;
}

/* ---- exceptions ------------------------------------------------------------
 * RtlRaiseException is the guest's own (lifted ntdll): it dispatches over the
 * guest's fs:[0] chain itself, and a handler's jump into its __except block
 * goes through native32's landing pads (eh32). Only what reaches the kernel
 * is answered here: NtRaiseException, the second chance (no guest handler),
 * ends the process like Windows 2000's would, with a report;
 * NtContinue(Context, TestAlert), ExceptionContinueExecution, resumes at the
 * caller of RtlRaiseException with the context's registers when the context
 * says so (the common case: the context was captured there). */
static uint32_t ovr_raise_exception(uint32_t* a) {
    uint32_t rec = a[0], ctx = a[1];
    /* First chance (x86 RtlRaiseException asks the kernel first): back to
     * user mode through the guest's KiUserExceptionDispatcher(Record,
     * Context), which runs RtlDispatchException over the guest's frames. A
     * handler that takes it jumps into its __except block through native32's
     * landing pads (eh32) and never comes back here; the machine lock is not
     * taken again, so that jump leaves nothing held. */
    static int depth;
    uint32_t kued = native32_export(native32_module("ntdll.dll"), "KiUserExceptionDispatcher");
    recomp_func_t f = kued ? recomp_lookup(kued) : NULL;
    if (a[2] && f && depth < 8) {
        uint32_t sp = g_esp;
        g_esp -= 0x400;                                /* below the raiser's frame */
        PUSH32(g_esp, ctx);
        PUSH32(g_esp, rec);
        depth++;
        f();
        depth--;
        g_esp = sp;                                    /* it came back: not handled */
    }
    fprintf(stderr, "\n[nt] unhandled guest exception %08X at %08X (first chance %u), eip %08X esp %08X\n",
            rec ? MEM32(rec) : 0, rec ? MEM32(rec + 12) : 0, a[2], ctx ? MEM32(ctx + 0xB8) : 0, ctx ? MEM32(ctx + 0xC4) : 0);
    fflush(NULL);
    TerminateProcess(GetCurrentProcess(), rec ? MEM32(rec) : 1);
    return 0;
}

static uint32_t ovr_continue(uint32_t* a) {
    uint32_t ctx = a[0];
    if (getenv("NATIVE32_SYSCALLS"))
        fprintf(stderr, "[nt] NtContinue to eip %08X esp %08X: returning to the raiser\n", MEM32(ctx + 0xB8), MEM32(ctx + 0xC4));
    g_eax = MEM32(ctx + 0xB0);
    return MEM32(ctx + 0xB0);
}

/* ---- process start ------------------------------------------------------ */
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

/* The OS version from the guest ntdll's VS_FIXEDFILEINFO: 5.0.2195 for
 * Windows 2000 whatever its service pack. */
static void ntdll_version(uint32_t ntdll, uint32_t* major, uint32_t* minor, uint32_t* build) {
    uint32_t size = image_size(ntdll);
    *major = 5, *minor = 0, *build = 2195;
    for (uint32_t p = ntdll; p + 52 < ntdll + size; p += 4)
        if (MEM32(p) == 0xFEEF04BDu) {
            *major = MEM32(p + 8) >> 16, *minor = MEM32(p + 8) & 0xFFFF, *build = MEM32(p + 12) >> 16;
            return;
        }
}

void csr32_install(void);   /* csr32.c */

/* What the kernel hands a new process, then the guest's own process start:
 * ntdll's LdrInitializeThunk does what LdrpInitializeProcess does on NT
 * (heap, NLS, loader lists, the EXE's imports, every DllMain), and returns. */
int native32_nt_boot(uint32_t ntdll, uint32_t exe, const wchar_t* image_path, const wchar_t* cmdline,
                     const wchar_t* dll_path, const char* nls_dir, uint16_t csd) {
    uint8_t* peb = (uint8_t*)VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    uint8_t* pp = peb + 0x1000;                       /* RTL_USER_PROCESS_PARAMETERS */
    uint8_t* pool = peb + 0x2000;                     /* its strings */
    wchar_t cur[MAX_PATH];
    uint32_t major, minor, build;
    IMAGE_NT_HEADERS32* ent = (IMAGE_NT_HEADERS32*)(uintptr_t)(exe + MEM32(exe + 0x3C));
    native32_guest_peb = (uint32_t)(uintptr_t)peb;
    native32_nt_override("NtQueryInformationProcess", ovr_query_process);
    native32_nt_override("NtOpenSection", ovr_open_section);
    native32_nt_override("NtCreateSection", ovr_create_section);
    native32_nt_override("NtMapViewOfSection", ovr_map_view);
    native32_nt_override("NtUnmapViewOfSection", ovr_unmap_view);
    native32_nt_override("NtClose", ovr_close);
    native32_nt_override("NtQuerySection", ovr_query_section);
    native32_nt_override("NtOpenDirectoryObject", ovr_open_directory);
    native32_nt_override("NtRaiseHardError", ovr_hard_error);
    native32_nt_override("NtCallbackReturn", ovr_callback_return);
    native32_nt_override("NtRaiseException", ovr_raise_exception);
    native32_nt_override("NtContinue", ovr_continue);
    native32_nt_override("NtCreateProcess", ovr_no_process);
    native32_nt_override("NtCreateThread", ovr_create_thread);
    native32_nt_override("NtTerminateThread", ovr_terminate_thread);
    native32_nt_override("NtCreateProcessEx", ovr_no_process);
    csr32_install();
    /* RtlUnwind ends in NtContinue to its caller, which a lift cannot do:
     * native32's own (seh32.c) unwinds the guest's frames and returns. */
    if (native32_export(ntdll, "RtlUnwind") && native32_shim("RtlUnwind"))
        native32_replace(native32_export(ntdll, "RtlUnwind"), native32_shim("RtlUnwind"));
    /* ...over the guest's chain (fs:[0] of the guest's TEB): the host's
     * RtlUnwind walked the host's, found no target and ended the process with
     * STATUS_UNWIND (ole32's RPC __except when epmapper is refused) */
    native32_guest_seh = 1;

    /* PEB: the fields the kernel sets (NT 5 offsets). Ldr, the heap, the
     * locks and the TLS bitmap are the guest ntdll's to make. */
    ntdll_version(ntdll, &major, &minor, &build);
    *(uint32_t*)(peb + 0x08) = exe;
    *(uint32_t*)(peb + 0x10) = (uint32_t)(uintptr_t)pp;
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    *(uint32_t*)(peb + 0x64) = si.dwNumberOfProcessors;
    *(int64_t*)(peb + 0x70) = -(int64_t)2592000 * 10000000;          /* CriticalSectionTimeout: 30 days */
    *(uint32_t*)(peb + 0x78) = 0x100000;                              /* HeapSegmentReserve */
    *(uint32_t*)(peb + 0x7C) = 0x2000;                                /* HeapSegmentCommit */
    *(uint32_t*)(peb + 0x80) = 0x10000;
    *(uint32_t*)(peb + 0x84) = 0x1000;
    *(uint32_t*)(peb + 0xA4) = major;
    *(uint32_t*)(peb + 0xA8) = minor;
    *(uint16_t*)(peb + 0xAC) = (uint16_t)build;
    *(uint16_t*)(peb + 0xAE) = csd;
    *(uint32_t*)(peb + 0xB0) = 2;                                     /* VER_PLATFORM_WIN32_NT */
    *(uint32_t*)(peb + 0xB4) = ent->OptionalHeader.Subsystem;
    *(uint32_t*)(peb + 0xB8) = ent->OptionalHeader.MajorSubsystemVersion;
    *(uint32_t*)(peb + 0xBC) = ent->OptionalHeader.MinorSubsystemVersion;
    {
        DWORD session = 0;
        ProcessIdToSessionId(GetCurrentProcessId(), &session);
        *(uint32_t*)(peb + 0x1D4) = session;
    }

    /* Process parameters, normalized, with the current directory's handle
     * open the way the creating process leaves it. */
    GetCurrentDirectoryW(MAX_PATH - 1, cur);
    if (cur[wcslen(cur) - 1] != L'\\') wcscat(cur, L"\\");
    *(uint32_t*)(pp + 0x00) = 0x1000;
    *(uint32_t*)(pp + 0x04) = 0x2A0;
    *(uint32_t*)(pp + 0x08) = 1;                                      /* RTL_USER_PROC_PARAMS_NORMALIZED */
    *(uint32_t*)(pp + 0x18) = (uint32_t)(uintptr_t)GetStdHandle(STD_INPUT_HANDLE);
    *(uint32_t*)(pp + 0x1C) = (uint32_t)(uintptr_t)GetStdHandle(STD_OUTPUT_HANDLE);
    *(uint32_t*)(pp + 0x20) = (uint32_t)(uintptr_t)GetStdHandle(STD_ERROR_HANDLE);
    /* CurrentDirectory.DosPath: a MAX_PATH buffer, as RtlCreateProcessParameters
     * makes it. RtlSetCurrentDirectory_U writes the new path into it in place;
     * sized to the first path, every longer one (`cd work`) failed with
     * ERROR_INVALID_NAME and `cd ..` worked. */
    ustr(pp + 0x24, cur, &pool);
    *(uint16_t*)(pp + 0x26) = MAX_PATH * 2;
    pool += MAX_PATH * 2;
    *(uint32_t*)(pp + 0x2C) = (uint32_t)(uintptr_t)CreateFileW(cur, FILE_TRAVERSE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    ustr(pp + 0x30, dll_path, &pool);
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

    /* The NLS tables the kernel maps into every process: the guest's own. */
    void* ansi = load_file(nls_dir, "c_1252.nls");
    void* oem = load_file(nls_dir, "c_437.nls");
    void* casetab = load_file(nls_dir, "l_intl.nls");
    if (!ansi || !oem || !casetab) return 0;
    *(uint32_t*)(peb + 0x58) = (uint32_t)(uintptr_t)ansi;
    *(uint32_t*)(peb + 0x5C) = (uint32_t)(uintptr_t)oem;
    *(uint32_t*)(peb + 0x60) = (uint32_t)(uintptr_t)casetab;

    /* LdrInitializeThunk(NormalContext, SystemArgument1 = ntdll's base,
     * SystemArgument2) with the thread's initial CONTEXT right after, as
     * KiUserApcDispatcher calls it; NT 5 takes the context at esp + 0x10. */
    uint32_t thunk = native32_export(ntdll, "LdrInitializeThunk");
    if (!thunk) { fprintf(stderr, "[nt] ntdll has no LdrInitializeThunk\n"); return 0; }
    uint32_t args[3 + 0x2CC / 4] = { 0, ntdll, 0 };
    uint32_t* ctx = args + 3;
    ctx[0] = 0x10007;                                                 /* CONTEXT_FULL */
    ctx[0xB0 / 4] = exe + ent->OptionalHeader.AddressOfEntryPoint;    /* Eax: the image's entry */
    ctx[0xB8 / 4] = exe + ent->OptionalHeader.AddressOfEntryPoint;    /* Eip */
    mach_enter();
    uint32_t sp = g_esp;
    native32_call_guest(thunk, (int)(sizeof args / 4), args);
    g_esp = sp;
    mach_leave();
    native32_guest_loaded = 1;
    fprintf(stderr, "[nt] guest PEB %p, process heap %08X: the guest's loader is done\n", peb, MEM32(native32_guest_peb + 0x18));
    return MEM32(native32_guest_peb + 0x18) != 0;
}

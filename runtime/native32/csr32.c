/*
 * csr32: csrss, for a lifted NT userland (syscall32.c).
 *
 * On Windows NT the Win32 subsystem server, csrss.exe, is another process:
 * ntdll connects to its LPC port, \Windows\ApiPort, and kernel32 asks it for
 * consoles, process and thread bookkeeping and more, one LPC message each.
 * The host's own csrss speaks its own, newer protocol, so the guest's port is
 * answered here, at the system calls (NtSecureConnectPort,
 * NtRequestWaitReplyPort): the guest's ntdll runs its own CSR client code.
 *
 *   connect  maps the client's port memory, gives the connect info what
 *            basesrv publishes (BASE_STATIC_SERVER_DATA in the static server
 *            data's slot 1), and a port handle of ours;
 *   call     api numbers are (server << 16) | api: csrsrv 0 ClientConnect
 *            (consrv: the host's console), basesrv 26 NlsGetUserInfo; others
 *            are logged and succeed with an empty reply.
 *
 * Layouts are NT 5.0's, from the offsets the lifted ntdll and kernel32 read.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "native32.h"

extern uint32_t g_cur_func;

static void ustr(uint8_t* at, const wchar_t* s) {
    size_t n = wcslen(s) * 2;
    wchar_t* copy = (wchar_t*)calloc(1, n + 2);
    memcpy(copy, s, n);
    *(uint16_t*)at = (uint16_t)n;
    *(uint16_t*)(at + 2) = (uint16_t)(n + 2);
    *(uint32_t*)(at + 4) = (uint32_t)(uintptr_t)copy;
}

/* BASE_STATIC_SERVER_DATA, NT 5.0:
 *   0x000 WindowsDirectory, 0x008 WindowsSystemDirectory, 0x010 NamedObjectDirectory
 *   0x018 major, minor, build, CSD number, RC number (USHORT); 0x022 CSDVersion[128]
 *   0x124 SYSTEM_BASIC_INFORMATION; 0x150 SYSTEM_TIMEOFDAY_INFORMATION
 *   0x170.. IniFileMapping, NlsUserInfo, flags: left zero. */
static uint32_t base_static_server_data(void) {
    typedef LONG (WINAPI *qsi_t)(ULONG, PVOID, ULONG, PULONG);
    qsi_t qsi = (qsi_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    uint8_t* d = (uint8_t*)VirtualAlloc(NULL, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    wchar_t win[MAX_PATH], sys[MAX_PATH], obj[64];
    DWORD session = 0;
    GetWindowsDirectoryW(win, MAX_PATH);
    GetSystemDirectoryW(sys, MAX_PATH);   /* SysWOW64 for a 32-bit host: the 32-bit DLLs */
    ProcessIdToSessionId(GetCurrentProcessId(), &session);
    _snwprintf(obj, 63, L"\\Sessions\\%lu\\BaseNamedObjects", session);
    ustr(d + 0x00, win);
    ustr(d + 0x08, sys);
    ustr(d + 0x10, obj);
    *(uint16_t*)(d + 0x18) = (uint16_t)MEM32(native32_guest_peb + 0xA4);   /* the PEB's OS version */
    *(uint16_t*)(d + 0x1A) = (uint16_t)MEM32(native32_guest_peb + 0xA8);
    *(uint16_t*)(d + 0x1C) = MEM16(native32_guest_peb + 0xAC);
    *(uint16_t*)(d + 0x1E) = MEM16(native32_guest_peb + 0xAE);
    if (MEM16(native32_guest_peb + 0xAE) >> 8)
        _snwprintf((wchar_t*)(d + 0x22), 127, L"Service Pack %u", MEM16(native32_guest_peb + 0xAE) >> 8);
    qsi(0, d + 0x124, 0x2C, NULL);        /* SystemBasicInformation */
    qsi(3, d + 0x150, 0x30, NULL);        /* SystemTimeOfDayInformation */
    /* IniFileMapping (0x180, after a 0x30-byte time of day): basesrv's map of .ini sections to registry
     * keys. Empty: the profile APIs (calc's GetProfileIntW) use the files. */
    *(uint32_t*)(d + 0x180) = (uint32_t)(uintptr_t)calloc(1, 0x40);
    /* Before build 2195 (2163, a release candidate) kernel32 reads the user's
     * NLS settings from an NLS_USER_INFO inside this data, at 0x184;
     * UserLocaleId is its +0x1860. 2195 asks basesrv instead (api 26). */
    if (MEM16(native32_guest_peb + 0xAC) < 2195) MEM32((uint32_t)(uintptr_t)d + 0x184 + 0x1860) = GetUserDefaultLCID();
    return (uint32_t)(uintptr_t)d;
}


/* SERVERINFO and the USER handle table the user server's connect hands out
 * (w32kuser.c fills them in) */
uint8_t* native32_user_psi;
uint8_t* native32_user_ahe;
uint8_t* native32_user_disp;

/* ---- the api handlers ---------------------------------------------------- */
static native32_csr_api_fn g_api[8][1024];

void native32_csr_api(uint32_t number, native32_csr_api_fn fn) {
    if ((number >> 16) < 8 && (number & 0xFFFF) < 1024) g_api[number >> 16][number & 0xFFFF] = fn;
}

/* csrsrv 0, ClientConnect { ServerDllIndex; ConnectionInformation*; Length }:
 * ntdll's CsrClientConnectToServer, once per server DLL. consrv (2) fills
 * CONSOLE_INFO at the start of its connect info: the console is the host's,
 * with its real std handles (a lifted kernel32 sends ReadFile/WriteFile on
 * them down to NtReadFile/NtWriteFile), a pseudo console handle for the
 * console api, and the two init events ConDllInitialize waits on, the first
 * ("succeeded") signaled. */
static uint32_t client_connect(uint32_t data, uint32_t capture) {
    uint32_t index = MEM32(data), ci = MEM32(data + 4);
    (void)capture;
    if (getenv("NATIVE32_SYSCALLS"))
        fprintf(stderr, "[csr] client connect, server %u, info %08X len %u\n", index, ci, MEM32(data + 8));
    if (index == 3 && ci && MEM32(data + 8) >= 0x104) {
        /* usersrv: USERCONNECT { ulVersion, ulCurrentVersion, dwDispatchCount,
         * SHAREDINFO siClient { psi, aheList, pDispInfo, ulSharedDelta, ... } }.
         * SERVERINFO, the handle table (w32kuser.c keeps both) and the
         * display info (zeroed). */
        uint8_t *psi = native32_user_psi, *ahe = native32_user_ahe;
        uint8_t* disp = native32_user_disp;
        if (!psi) {
            psi = native32_user_psi = (uint8_t*)VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            /* 0x10000 HANDLEENTRYs of 12 bytes: a host HWND's own index fits */
            ahe = native32_user_ahe = (uint8_t*)VirtualAlloc(NULL, 0xC0000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            disp = native32_user_disp = (uint8_t*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            *(uint32_t*)(psi + 8) = 0x10000;                  /* cHandleEntries */
        }
        MEM32(ci + 0x04) = MEM32(ci + 0x00);
        MEM32(ci + 0x0C) = (uint32_t)(uintptr_t)psi;
        MEM32(ci + 0x10) = (uint32_t)(uintptr_t)ahe;
        MEM32(ci + 0x14) = (uint32_t)(uintptr_t)disp;
        /* ulSharedDelta: user32 subtracts it from every kernel pointer in the
         * shared section (pDispInfo->pMonitorPrimary, ...). The section is
         * ours, so 0; left unset it was the caller's stack (0xCCCC...) */
        MEM32(ci + 0x18) = 0;
        {
            /* SHAREDINFO +0xE8 DefWindowMsgs { maxMsgs, abMsgs }: the messages
             * DefWindowProc hands to win32k. All of them: the host's
             * DefWindowProc answers (w32kuser.c). +0xF0 DefWindowSpecMsgs,
             * the ones user32 answers itself from the WND: none. */
            static uint8_t all[0x80];
            memset(all, 0xFF, sizeof all);
            MEM32(ci + 0x0C + 0xE8) = 0x3FF;
            MEM32(ci + 0x0C + 0xEC) = (uint32_t)(uintptr_t)all;
        }
    }
    if (index == 2 && ci) {
        MEM32(ci + 0x00) = 0x0C0Eu;
        MEM32(ci + 0x04) = (uint32_t)(uintptr_t)CreateEventA(NULL, TRUE, FALSE, NULL);
        MEM32(ci + 0x08) = (uint32_t)(uintptr_t)GetStdHandle(STD_INPUT_HANDLE);
        MEM32(ci + 0x0C) = (uint32_t)(uintptr_t)GetStdHandle(STD_OUTPUT_HANDLE);
        MEM32(ci + 0x10) = (uint32_t)(uintptr_t)GetStdHandle(STD_ERROR_HANDLE);
        MEM32(ci + 0x14) = (uint32_t)(uintptr_t)CreateEventA(NULL, TRUE, TRUE, NULL);
        MEM32(ci + 0x18) = (uint32_t)(uintptr_t)CreateEventA(NULL, TRUE, FALSE, NULL);
    }
    return 0;
}

/* basesrv 26 (NT 5.0), NlsGetUserInfo { NLS_USER_INFO* info; ULONG length }:
 * the user's locale settings. kernel32 resolves LCID 0 and
 * LOCALE_USER_DEFAULT through UserLocaleId (+0x1860); left 0, every
 * LCMapStringW(0, ...) failed and msvcrt's locale-aware case mapping with it
 * (cmd matched no built-in command typed in lower case). The per-field
 * override strings stay empty. */
static uint32_t nls_get_user_info(uint32_t data, uint32_t capture) {
    uint32_t info = MEM32(data), len = MEM32(data + 4);
    (void)capture;
    if (!info || len < 0x1870) return 0xC000000Du;       /* STATUS_INVALID_PARAMETER */
    memset((void*)(uintptr_t)info, 0, len);
    MEM32(info + 0x1860) = GetUserDefaultLCID();
    return 0;
}

/* ---- the port ------------------------------------------------------------ */
static HANDLE g_port;     /* the guest's handle to \Windows\ApiPort: an event of ours */

/* NtSecureConnectPort(Port*, Name, Qos, ClientView, Sid, ServerView, MaxLen*, Info, InfoLen*)
 * and NtConnectPort (the same without Sid). The client's port memory view is
 * mapped here, at the same address on "both sides" (no remote delta); the
 * connect info (NT 5: CSR_API_CONNECTINFO) names the shared section, the
 * static server data array (basesrv's slot 1) and the shared heap, which
 * ntdll copies into the PEB. */
static uint32_t lpc_connect(uint32_t* a, int secure) {
    uint32_t name = a[1], cv = a[3], sv = a[secure ? 5 : 4], len = a[secure ? 6 : 5];
    uint32_t info = a[secure ? 7 : 6];
    int n = name ? MEM16(name) / 2 : 0;
    const wchar_t* s = name ? (const wchar_t*)(uintptr_t)MEM32(name + 4) : L"";
    if (n < 8 || _wcsnicmp(s + n - 8, L"\\ApiPort", 8)) {
        /* Any other port is a host service (RPCSS's epmapper, lsass, the
         * services): a guest never talks to one. As if it were not running. */
        fprintf(stderr, "[guard] LPC connect to %.*ls: refused\n", n, s);
        return 0xC0000034u;                                 /* STATUS_OBJECT_NAME_NOT_FOUND */
    }
    if (cv && MEM32(cv + 4)) {
        void* v = MapViewOfFile((HANDLE)(uintptr_t)MEM32(cv + 4), FILE_MAP_ALL_ACCESS, 0, MEM32(cv + 8), MEM32(cv + 12));
        if (!v) return 0xC0000017u;                       /* STATUS_NO_MEMORY */
        MEM32(cv + 16) = MEM32(cv + 20) = (uint32_t)(uintptr_t)v;
        if (sv) MEM32(sv + 4) = MEM32(cv + 12), MEM32(sv + 8) = (uint32_t)(uintptr_t)v;
    }
    if (info) {
        static uint32_t srv[16];
        static uint8_t* shared;
        if (!shared) shared = (uint8_t*)VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!srv[1]) srv[1] = base_static_server_data();
        MEM32(info + 0x08) = GetCurrentProcessId();
        MEM32(info + 0x0C) = (uint32_t)(uintptr_t)shared;   /* SharedSectionBase */
        MEM32(info + 0x10) = (uint32_t)(uintptr_t)srv;      /* SharedStaticServerData */
        MEM32(info + 0x14) = (uint32_t)(uintptr_t)shared;   /* SharedSectionHeap */
    }
    if (len) MEM32(len) = 0x148;
    if (!g_port) g_port = CreateEventA(NULL, FALSE, FALSE, NULL);
    MEM32(a[0]) = (uint32_t)(uintptr_t)g_port;
    if (getenv("NATIVE32_SYSCALLS")) fprintf(stderr, "[csr] connected to %.*ls\n", n, s);
    return 0;
}

static uint32_t ovr_secure_connect(uint32_t* a) { return lpc_connect(a, 1); }
static uint32_t ovr_connect(uint32_t* a) { return lpc_connect(a, 0); }

static int is_port(uint32_t h) { return g_port && (HANDLE)(uintptr_t)h == g_port; }

/* NtRequestWaitReplyPort(Port, Request, Reply): one CSR_API_MSG, a
 * PORT_MESSAGE (0x18) + CaptureBuffer, ApiNumber, ReturnValue (0x20),
 * Reserved, then the api's data (0x28). */
static uint32_t ovr_request_wait_reply(uint32_t* a) {
    if (!is_port(a[0])) return native32_nt_forward("NtRequestWaitReplyPort", a);
    uint32_t m = a[1], api = MEM32(m + 0x1C), r = 0;
    native32_csr_api_fn fn = (api >> 16) < 8 && (api & 0xFFFF) < 1024 ? g_api[api >> 16][api & 0xFFFF] : NULL;
    if (fn) r = fn(m + 0x28, MEM32(m + 0x18));
    else {
        /* An empty reply, not the request's stack bytes: build 2163's
         * GetConsoleOutputCP read its code page from here, got garbage, and
         * every WideCharToMultiByte cmd wrote failed. 0 is CP_ACP. */
        uint16_t total = MEM16(m + 2);
        if (total > 0x28 && total < 0x1000) memset((void*)(uintptr_t)(m + 0x28), 0, total - 0x28);
        if (getenv("NATIVE32_SYSCALLS"))
            fprintf(stderr, "[csr] api %u:%u not answered, from sub_%08X\n", api >> 16, api & 0xFFFF, g_cur_func);
    }
    MEM32(m + 0x20) = r;
    if (a[2] && a[2] != m) memcpy((void*)(uintptr_t)a[2], (void*)(uintptr_t)m, MEM16(m) + 0x18);
    return 0;
}

static uint32_t ovr_request_port(uint32_t* a) {
    return is_port(a[0]) ? 0 : native32_nt_forward("NtRequestPort", a);
}

static uint32_t ovr_terminate_port(uint32_t* a) {
    return is_port(a[0]) ? 0 : native32_nt_forward("NtRegisterThreadTerminatePort", a);
}

/* Named objects csrss creates at its start, which the guest only opens:
 * build 2163's kernel32 opens \Sessions\N\NlsCacheMutant and fails its
 * DllMain without it. A process of our own needs no sharing, so the open
 * returns a new unnamed one. NtOpenMutant(Handle*, Access, ObjectAttributes) */
static uint32_t ovr_open_mutant(uint32_t* a) {
    uint32_t r = native32_nt_forward("NtOpenMutant", a), us = a[2] ? MEM32(a[2] + 8) : 0;
    int n = us ? MEM16(us) / 2 : 0;
    const wchar_t* s = us ? (const wchar_t*)(uintptr_t)MEM32(us + 4) : L"";
    if (r == 0xC0000034u && n >= 14 && !_wcsnicmp(s + n - 14, L"NlsCacheMutant", 14)) {
        static HANDLE m;
        if (!m) m = CreateMutexW(NULL, FALSE, NULL);
        HANDLE d;
        if (!DuplicateHandle(GetCurrentProcess(), m, GetCurrentProcess(), &d, 0, FALSE, DUPLICATE_SAME_ACCESS)) return r;
        MEM32(a[0]) = (uint32_t)(uintptr_t)d;
        return 0;
    }
    return r;
}

void csr32_install(void) {
    native32_nt_override("NtOpenMutant", ovr_open_mutant);
    native32_csr_api(0x00000, client_connect);
    if (!g_api[1][26]) native32_csr_api(0x1001A, nls_get_user_info);
    native32_nt_override("NtSecureConnectPort", ovr_secure_connect);
    native32_nt_override("NtConnectPort", ovr_connect);
    native32_nt_override("NtRequestWaitReplyPort", ovr_request_wait_reply);
    native32_nt_override("NtRequestPort", ovr_request_port);
    native32_nt_override("NtRegisterThreadTerminatePort", ovr_terminate_port);
}

/*
 * csr64.c: csrss for a lifted 64-bit NT userland (native64.c).
 *
 * The guest's ntdll connects to \Windows\ApiPort and kernel32 asks csrss
 * (basesrv, consrv) for process bookkeeping, one LPC message each. The host's
 * csrss speaks its own protocol, so the port is answered here, at the system
 * calls: the guest's ntdll runs its own CSR client code (csr32.c's model).
 * Layouts are NT 5.2 x64's, read off the guest ntdll's CsrpConnectToServer:
 *
 *   PORT_VIEW        Length, SectionHandle +8, SectionOffset +0x10, ViewSize +0x18,
 *                    ViewBase +0x20, ViewRemoteBase +0x28
 *   CSR connect info ObjectDirectory, SharedSectionBase +8, SharedStaticServerData +0x10,
 *                    SharedSectionHeap +0x18, DebugFlags +0x20, ..., ServerProcessId +0x30
 *   CSR_API_MSG      PORT_MESSAGE (0x28), CaptureBuffer +0x28, ApiNumber +0x30,
 *                    ReturnValue +0x34, Reserved +0x38, data +0x40
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>
#include "native64.h"

#define CSR_PORT ((uint64_t)0x4E363450u)   /* our port handle */

static void ustr(uint8_t* at, const wchar_t* s) {
    size_t n = wcslen(s) * 2;
    wchar_t* copy = (wchar_t*)calloc(1, n + 2);
    memcpy(copy, s, n);
    *(uint16_t*)at = (uint16_t)n;
    *(uint16_t*)(at + 2) = (uint16_t)(n + 2);
    *(uint64_t*)(at + 8) = (uint64_t)(uintptr_t)copy;
}

/* What basesrv publishes in the static server data's slot 1. */
static uint64_t base_static_server_data(void) {
    typedef LONG (WINAPI *qsi_t)(ULONG, PVOID, ULONG, PULONG);
    qsi_t qsi = (qsi_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    uint8_t* d = (uint8_t*)VirtualAlloc(NULL, 0x4000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    uint8_t* peb = (uint8_t*)(uintptr_t)native64_peb;
    wchar_t sys[MAX_PATH], win[MAX_PATH], obj[64];
    DWORD session = 0;
    /* the guest's own directories: its system folder is where its modules are */
    const wchar_t* dll = (const wchar_t*)(uintptr_t)*(uint64_t*)(uintptr_t)(*(uint64_t*)(peb + 0x20) + 0x58);
    wcsncpy(sys, dll, MAX_PATH - 1), sys[MAX_PATH - 1] = 0;
    wcscpy(win, sys);
    if (wcsrchr(win, L'\\')) *wcsrchr(win, L'\\') = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &session);
    _snwprintf(obj, 63, L"\\Sessions\\%lu\\BaseNamedObjects", session);
    ustr(d + 0x00, win);
    ustr(d + 0x10, sys);
    ustr(d + 0x20, obj);
    *(uint16_t*)(d + 0x30) = (uint16_t)*(uint32_t*)(peb + 0x118);
    *(uint16_t*)(d + 0x32) = (uint16_t)*(uint32_t*)(peb + 0x11C);
    *(uint16_t*)(d + 0x34) = *(uint16_t*)(peb + 0x120);
    *(uint16_t*)(d + 0x36) = *(uint16_t*)(peb + 0x122);
    if (*(uint16_t*)(peb + 0x122) >> 8)
        _snwprintf((wchar_t*)(d + 0x3A), 127, L"Service Pack %u", *(uint16_t*)(peb + 0x122) >> 8);
    qsi(0, d + 0x140, 0x40, NULL);        /* SystemBasicInformation */
    qsi(3, d + 0x180, 0x30, NULL);        /* SystemTimeOfDayInformation */
    *(uint64_t*)(d + 0x1B0) = (uint64_t)(uintptr_t)calloc(1, 0x80);   /* IniFileMapping: empty */
    return (uint64_t)(uintptr_t)d;
}

static uint64_t g_static[16];   /* SharedStaticServerData: one pointer per server DLL */

/* NtSecureConnectPort(h*, name, qos, ClientView*, sid, ServerView*, maxlen*, info*, infolen*)
 * NtConnectPort      (h*, name, qos, ClientView*,      ServerView*, maxlen*, info*, infolen*) */
static uint64_t connect(uint64_t* a, int secure, const char* svc) {
    UNICODE_STRING* n = (UNICODE_STRING*)(uintptr_t)a[1];
    uint64_t cv = a[3], sv = a[4 + secure], ml = a[5 + secure], ci = a[6 + secure];
    if (!n || n->Length < 16 || _wcsnicmp(n->Buffer + n->Length / 2 - 7, L"ApiPort", 7) ||
        (n->Length >= 18 && n->Buffer[n->Length / 2 - 8] != L'\\'))
        return native64_forward(svc, a);
    if (cv) {   /* the client's port memory: map its section here, at one address for both sides */
        typedef LONG (NTAPI *map_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
        map_t map = (map_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");
        PVOID base = NULL;
        SIZE_T size = *(uint64_t*)(uintptr_t)(cv + 0x18);
        LONG st = map((HANDLE)(uintptr_t)*(uint64_t*)(uintptr_t)(cv + 8), GetCurrentProcess(), &base, 0, 0, NULL, &size, 2, 0, PAGE_READWRITE);
        if (st < 0) { fprintf(stderr, "[csr] port memory: map %08lX\n", st); return (uint64_t)(uint32_t)st; }
        *(uint64_t*)(uintptr_t)(cv + 0x18) = size;
        *(uint64_t*)(uintptr_t)(cv + 0x20) = (uint64_t)(uintptr_t)base;
        *(uint64_t*)(uintptr_t)(cv + 0x28) = (uint64_t)(uintptr_t)base;
    }
    if (sv) *(uint64_t*)(uintptr_t)(sv + 8) = 0, *(uint64_t*)(uintptr_t)(sv + 0x10) = 0;
    if (ml) *(uint32_t*)(uintptr_t)ml = 0x148;
    if (ci) {
        uint8_t* c = (uint8_t*)(uintptr_t)ci;
        if (!g_static[1]) g_static[1] = base_static_server_data();
        uint8_t* shared = (uint8_t*)VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        *(uint64_t*)(c + 0x08) = (uint64_t)(uintptr_t)shared;             /* SharedSectionBase */
        *(uint64_t*)(c + 0x10) = (uint64_t)(uintptr_t)g_static;           /* SharedStaticServerData */
        *(uint64_t*)(c + 0x18) = (uint64_t)(uintptr_t)shared;             /* SharedSectionHeap */
        *(uint64_t*)(c + 0x30) = GetCurrentProcessId();                    /* ServerProcessId */
    }
    *(uint64_t*)(uintptr_t)a[0] = CSR_PORT;
    if (native64_trace) fprintf(stderr, "[csr] connected\n");
    return 0;
}
static uint64_t ovr_secure_connect(uint64_t* a) { return connect(a, 1, "NtSecureConnectPort"); }
static uint64_t ovr_connect(uint64_t* a) { return connect(a, 0, "NtConnectPort"); }

/* NtRequestWaitReplyPort(port, request, reply): one CSR api */
static uint64_t ovr_request(uint64_t* a) {
    if (a[0] != CSR_PORT) return native64_forward("NtRequestWaitReplyPort", a);
    uint8_t* m = (uint8_t*)(uintptr_t)a[1];
    uint32_t api = *(uint32_t*)(m + 0x30), st = 0;
    uint8_t* d = m + 0x40;
    switch (api) {
    case 0x00000000:   /* csrsrv ClientConnect { ServerDllIndex; ConnectionInfo*; Length } */
        if (native64_trace) fprintf(stderr, "[csr] client connect, server %u, info %llX len %u\n",
                                    *(uint32_t*)d, *(uint64_t*)(d + 8), *(uint32_t*)(d + 0x10));
        break;
    case 0x2023F:      /* consrv GetConsoleCP { ConsoleHandle; CodePage +8; Output +0xC } */
        *(uint32_t*)(d + 8) = 437;   /* ponytail: XP's OEM page, whatever the host console's */
        break;
    default:
        fprintf(stderr, "[csr] api %X (server %u, api %u): answered empty\n", api, api >> 16, api & 0xFFFF);
        break;
    }
    *(uint32_t*)(m + 0x34) = st;
    if (a[2] && a[2] != a[1]) memcpy((void*)(uintptr_t)a[2], m, 0x28 + (*(uint16_t*)m & 0xFFFF));
    return 0;
}

void csr64_install(void) {
    native64_override("NtSecureConnectPort", ovr_secure_connect);
    native64_override("NtConnectPort", ovr_connect);
    native64_override("NtRequestWaitReplyPort", ovr_request);
}

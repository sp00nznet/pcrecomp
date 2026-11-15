/*
 * csr32: csrss, for a lifted NT 5 userland (syscall32.c).
 *
 * On Windows NT the Win32 subsystem server, csrss.exe, is another process:
 * kernel32 connects to it at start (CsrClientConnectToServer) and asks it for
 * consoles, process and thread bookkeeping, and more (CsrClientCallServer, an
 * LPC message). The host's own csrss speaks its own, newer protocol, so the
 * guest ntdll's two CsrClient* exports are replaced here (as
 * "ntdll.dll!CsrClient..." shims, which win over a guest module's export):
 *
 *   connect  answers every server DLL; for basesrv (1) it fills in what
 *            basesrv maps into each process, BASE_STATIC_SERVER_DATA, and
 *            points Peb->ReadOnlyStaticServerData at it.
 *   call     api numbers are (server << 16) | api; unknown ones are logged
 *            and succeed with a zero reply, which most callers take.
 *
 * Layouts are NT 5.0's, from the offsets the lifted kernel32 reads.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "native32.h"

#define ARG(n) MEM32(g_esp + 4 + 4 * (n))
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
    *(uint16_t*)(d + 0x18) = 5;           /* 5.0.2195 Service Pack 4 */
    *(uint16_t*)(d + 0x1A) = 0;
    *(uint16_t*)(d + 0x1C) = 2195;
    *(uint16_t*)(d + 0x1E) = 0x0400;
    wcscpy((wchar_t*)(d + 0x22), L"Service Pack 4");
    qsi(0, d + 0x124, 0x2C, NULL);        /* SystemBasicInformation */
    qsi(3, d + 0x150, 0x20, NULL);        /* SystemTimeOfDayInformation */
    return (uint32_t)(uintptr_t)d;
}

/* CsrClientConnectToServer(ObjectDirectory, ServerDllIndex, CallbackInfo,
 *                          ConnectionInformation, ConnectionInformationLength,
 *                          CalledFromServer) */
static void csr_connect(void) {
    if (getenv("NATIVE32_SYSCALLS"))
        fprintf(stderr, "[csr] connect %ls server %u info %08X len %u\n", (wchar_t*)(uintptr_t)ARG(0), ARG(1),
                ARG(3), ARG(4) ? MEM32(ARG(4)) : 0);
    if (!MEM32(native32_guest_peb + 0x54)) {
        uint32_t* srv = (uint32_t*)calloc(16, 4);   /* one slot per server DLL */
        srv[1] = base_static_server_data();
        MEM32(native32_guest_peb + 0x54) = (uint32_t)(uintptr_t)srv;
    }
    if (ARG(1) == 2 && ARG(3)) {
        /* consrv: CONSOLE_INFO at the start of the connect info. The console
         * is the host's: its real std handles (a lifted kernel32 sends
         * ReadFile/WriteFile on them down to NtReadFile/NtWriteFile), a
         * pseudo console handle for the CSR console api, and the init events
         * ConDllInitialize waits on, the first ("succeeded") signaled. */
        uint32_t ci = ARG(3);
        MEM32(ci + 0x00) = 0x0C0Eu;
        MEM32(ci + 0x04) = (uint32_t)(uintptr_t)CreateEventA(NULL, TRUE, FALSE, NULL);
        MEM32(ci + 0x08) = (uint32_t)(uintptr_t)GetStdHandle(STD_INPUT_HANDLE);
        MEM32(ci + 0x0C) = (uint32_t)(uintptr_t)GetStdHandle(STD_OUTPUT_HANDLE);
        MEM32(ci + 0x10) = (uint32_t)(uintptr_t)GetStdHandle(STD_ERROR_HANDLE);
        MEM32(ci + 0x14) = (uint32_t)(uintptr_t)CreateEventA(NULL, TRUE, TRUE, NULL);
        MEM32(ci + 0x18) = (uint32_t)(uintptr_t)CreateEventA(NULL, TRUE, FALSE, NULL);
    }
    if (ARG(5)) *(uint8_t*)(uintptr_t)ARG(5) = 0;
    g_eax = 0;
    g_esp += 4 + 4 * 6;
}

/* CsrClientCallServer(ApiMessage, CaptureBuffer, ApiNumber, ArgLength):
 * CSR_API_MSG is a PORT_MESSAGE (0x18) + CaptureBuffer, ApiNumber,
 * ReturnValue (0x20), Reserved, then the api's own data (0x28). */
static native32_csr_api_fn g_api[8][1024];

void native32_csr_api(uint32_t number, native32_csr_api_fn fn) {
    if ((number >> 16) < 8 && (number & 0xFFFF) < 1024) g_api[number >> 16][number & 0xFFFF] = fn;
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

static void csr_call(void) {
    uint32_t m = ARG(0), api = ARG(2), r = 0;
    native32_csr_api_fn fn = (api >> 16) < 8 && (api & 0xFFFF) < 1024 ? g_api[api >> 16][api & 0xFFFF] : NULL;
    if (!fn && api == 0x1001A) fn = nls_get_user_info;
    MEM32(m + 0x1C) = api;
    if (fn) r = fn(m + 0x28, ARG(1));
    else fprintf(stderr, "[csr] api %u:%u (len %u) not answered, from sub_%08X\n", api >> 16, api & 0xFFFF,
                 ARG(3), g_cur_func);
    MEM32(m + 0x20) = r;
    g_eax = r;
    g_esp += 4 + 4 * 4;
}

native32_shim_t native32_csr_shims[2] = {
    { "ntdll.dll!CsrClientConnectToServer", csr_connect },
    { "ntdll.dll!CsrClientCallServer", csr_call },
};

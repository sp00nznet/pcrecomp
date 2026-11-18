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
 *            (consrv: the host's console), basesrv 26 (XP: 30) NlsGetUserInfo; others
 *            are logged and succeed with an empty reply.
 *
 * Layouts are NT 5.0's, from the offsets the lifted ntdll and kernel32 read.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wctype.h>
#include "native32.h"
#include "ntguest.h"

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
            *(uint32_t*)(psi + nt_si(native32_guest_peb, 0x864)) = 1;                    /* cCaptures: never 0, so GetCapture asks NtUserGetThreadState(2) */
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
            uint32_t dm = ci + 0x0C + nt_shared_defmsgs(native32_guest_peb);   /* (XP: +0x108) */
            MEM32(dm) = 0x3FF;
            MEM32(dm + 4) = (uint32_t)(uintptr_t)all;
            /* (DefWindowSpecMsgs said so; left as the buffer had it, XP's explorer
             * read 0x020A0000 messages from a NULL bitmap) */
            MEM32(dm + 8) = 0, MEM32(dm + 12) = 0;
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

/* ---- SxS: activation contexts (XP) ----------------------------------------
 * XP's csrss builds an activation context from a manifest: basesrv 27,
 * BaseSrvSxsCreateActivationContext, and the process default one at process
 * creation. The result is ACTIVATION_CONTEXT_DATA, the binary form XP's ntdll
 * searches (RtlFindActivationContextSectionString): its loader for DLL
 * redirection (comctl32.dll -> version 6), user32 for window class
 * redirection (Button -> "6.0.2600.5512!Button"). Layouts read off XP's
 * ntdll (winxp-recomp docs/survey.md):
 *   ACTIVATION_CONTEXT_DATA { 'Actx', HeaderSize 0x20, FormatVersion 1,
 *     TotalSize, DefaultTocOffset, ExtendedTocOffset, AssemblyRosterOffset, Flags }
 *   TOC { HeaderSize 0x10, EntryCount, FirstEntryOffset, Flags (2 sorted) },
 *     entries { Id, Offset, Length, Format (1 string section) } sorted by Id
 *   roster { HeaderSize 0x14, HashAlgorithm, EntryCount, FirstEntryOffset, .. },
 *     entries of 0x18, entry 0 unused
 *   string section { 'SsHd', HeaderSize 0x2C, FormatVersion 1, DataFormatVersion 1,
 *     Flags (1 case-insensitive, 2 sorted), ElementCount, ElementListOffset,
 *     HashAlgorithm (1: x65599), SearchStructureOffset 0, UserDataOffset, UserDataSize },
 *     entries { PseudoKey, KeyOffset, KeyLength, Offset, Length, RosterIndex }
 *     sorted by PseudoKey, offsets from the section's start
 *   DLL redirection { Size 0x14, Flags (1 path includes the name, 2 no assembly
 *     root), TotalPathLength, PathSegmentCount, PathSegmentOffset } + { Length, Offset }
 *   window class redirection { Size 0x18, Flags, VersionSpecificClassNameLength,
 *     its Offset (from this structure), DllNameLength, DllNameOffset (from the section) }
 * The store: PCRECOMP_SXS\<assembly name>\<assembly name>.manifest and its
 * files beside it (a host lifts them there). ponytail: no publisher policy
 * (the manifest's own version is the one used), no COM/typelib sections. */
#define SXS_MAX 64
typedef struct { wchar_t key[64]; uint8_t* data; uint32_t len, roster; } sxs_ent;
typedef struct { sxs_ent e[SXS_MAX]; int n; } sxs_sec;

static uint32_t sxs_hash(const wchar_t* s) {        /* RtlHashUnicodeString, upcased, x65599 */
    uint32_t h = 0;
    for (; *s; s++) h = h * 65599u + (uint32_t)towupper(*s);
    return h;
}
/* the value of attribute a inside the tag starting at t, as wide text */
static int xml_attr(const char* t, const char* a, wchar_t* out, int max) {
    const char* end = strchr(t, '>'), *p = t;
    size_t n = strlen(a);
    while ((p = strstr(p, a)) && (!end || p < end)) {
        if ((p[-1] == ' ' || p[-1] == '\t' || p[-1] == '\n' || p[-1] == '\r') && p[n] == '=' && (p[n + 1] == '"' || p[n + 1] == '\'')) {
            const char* v = p + n + 2, *q = strchr(v, p[n + 1]);
            int k = q ? (int)(q - v) : 0;
            if (k >= max) k = max - 1;
            for (int i = 0; i < k; i++) out[i] = (unsigned char)v[i];
            out[k] = 0;
            return 1;
        }
        p += n;
    }
    return 0;
}
static uint8_t* sxs_blob_add(sxs_sec* s, const wchar_t* key, uint32_t len, uint32_t roster) {
    if (s->n >= SXS_MAX) return NULL;
    sxs_ent* e = &s->e[s->n++];
    wcsncpy(e->key, key, 63);
    e->data = (uint8_t*)calloc(1, len);
    e->len = len, e->roster = roster;
    return e->data;
}
/* one dependency from the store: its files (DLL redirection) and their window
 * classes (window class redirection) */
static void sxs_dependency(const wchar_t* name, sxs_sec* dll, sxs_sec* wc, uint32_t roster) {
    wchar_t store[MAX_PATH], dir[MAX_PATH], man[MAX_PATH], ver[64] = L"";
    if (!GetEnvironmentVariableW(L"PCRECOMP_SXS", store, MAX_PATH)) return;
    _snwprintf(dir, MAX_PATH - 1, L"%ls\\%ls", store, name);
    _snwprintf(man, MAX_PATH - 1, L"%ls\\%ls.manifest", dir, name);
    FILE* f = _wfopen(man, L"rb");
    if (!f) { fprintf(stderr, "[sxs] %ls: not in the store (%ls)\n", name, man); return; }
    static char x[0x10000];
    size_t n = fread(x, 1, sizeof x - 1, f);
    fclose(f);
    x[n] = 0;
    const char* id = strstr(x, "<assemblyIdentity");
    if (id) xml_attr(id, "version", ver, 64);
    for (const char* fl = strstr(x, "<file"); fl; fl = strstr(fl + 5, "<file")) {
        wchar_t file[MAX_PATH], path[MAX_PATH];
        if (!xml_attr(fl, "name", file, MAX_PATH)) continue;
        /* the DLL: one absolute path segment (flag 2 would put the assembly's storage root before it) */
        int pl = _snwprintf(path, MAX_PATH - 1, L"%ls\\%ls", dir, file);
        uint8_t* d = sxs_blob_add(dll, file, 0x1C + 2 * (pl + 1), roster);
        if (d) {
            MEM32((uint32_t)(uintptr_t)d + 0x00) = 0x14;
            MEM32((uint32_t)(uintptr_t)d + 0x04) = 1;   /* the path includes the name; no 2: it is absolute, no assembly root before it */
            MEM32((uint32_t)(uintptr_t)d + 0x08) = 2 * pl;
            MEM32((uint32_t)(uintptr_t)d + 0x0C) = 1;
            /* PathSegmentOffset and the segment's Offset are fixed up when the
             * section is laid out (from the section's start): marked relative */
            MEM32((uint32_t)(uintptr_t)d + 0x10) = 0x14;     /* (from this entry's data) */
            MEM32((uint32_t)(uintptr_t)d + 0x14) = 2 * pl;
            MEM32((uint32_t)(uintptr_t)d + 0x18) = 0x1C;     /* (from this entry's data) */
            memcpy(d + 0x1C, path, 2 * (pl + 1));
        }
        const char* fend = strstr(fl, "</file>");
        for (const char* w = strstr(fl, "<windowClass>"); w && (!fend || w < fend); w = strstr(w + 13, "<windowClass>")) {
            wchar_t cls[64], vcls[160];
            const char* v = w + 13, *q = strchr(v, '<');
            int k = q ? (int)(q - v) : 0, vl;
            if (k <= 0 || k > 63) continue;
            for (int i = 0; i < k; i++) cls[i] = (unsigned char)v[i];
            cls[k] = 0;
            vl = _snwprintf(vcls, 159, L"%ls!%ls", ver, cls);
            int fl2 = (int)wcslen(file);
            uint8_t* c = sxs_blob_add(wc, cls, 0x18 + 2 * (vl + 1) + 2 * (fl2 + 1), roster);
            if (!c) continue;
            MEM32((uint32_t)(uintptr_t)c + 0x00) = 0x18;
            MEM32((uint32_t)(uintptr_t)c + 0x08) = 2 * vl;
            MEM32((uint32_t)(uintptr_t)c + 0x0C) = 0x18;          /* from this structure */
            MEM32((uint32_t)(uintptr_t)c + 0x10) = 2 * fl2;
            MEM32((uint32_t)(uintptr_t)c + 0x14) = 0x18 + 2 * (vl + 1);   /* (fixed up: from the section) */
            memcpy(c + 0x18, vcls, 2 * (vl + 1));
            memcpy(c + 0x18 + 2 * (vl + 1), file, 2 * (fl2 + 1));
        }
    }
    fprintf(stderr, "[sxs] %ls %ls from the store\n", name, ver);
}
static int sxs_cmp(const void* a, const void* b) {
    uint32_t x = sxs_hash(((const sxs_ent*)a)->key), y = sxs_hash(((const sxs_ent*)b)->key);
    return x < y ? -1 : x > y;
}
/* a string section at out (NULL: its size) */
static uint32_t sxs_section(sxs_sec* s, uint8_t* out, int id) {
    uint32_t o = 0x2C + 0x18 * s->n;
    qsort(s->e, s->n, sizeof s->e[0], sxs_cmp);
    for (int i = 0; i < s->n; i++) {
        uint32_t kl = 2 * (uint32_t)wcslen(s->e[i].key), ko = o, dof;
        o += (kl + 2 + 3) & ~3u;
        dof = o;
        o += (s->e[i].len + 3) & ~3u;
        if (!out) continue;
        uint32_t e = (uint32_t)(uintptr_t)out + 0x2C + 0x18 * i;
        MEM32(e) = sxs_hash(s->e[i].key), MEM32(e + 4) = ko, MEM32(e + 8) = kl;
        MEM32(e + 0xC) = dof, MEM32(e + 0x10) = s->e[i].len, MEM32(e + 0x14) = s->e[i].roster;
        memcpy(out + ko, s->e[i].key, kl + 2);
        memcpy(out + dof, s->e[i].data, s->e[i].len);
        uint32_t d = (uint32_t)(uintptr_t)out + dof;
        if (id == 2) MEM32(d + 0x10) += dof, MEM32(d + 0x18) += dof;     /* DLL: path segment offsets from the section */
        if (id == 3) MEM32(d + 0x14) += dof;                             /* window class: the DLL name from the section */
    }
    if (out) {
        uint32_t h = (uint32_t)(uintptr_t)out;
        MEM32(h) = 0x64487353u, MEM32(h + 4) = 0x2C, MEM32(h + 8) = 1, MEM32(h + 0xC) = 1;
        MEM32(h + 0x10) = 3, MEM32(h + 0x14) = s->n, MEM32(h + 0x18) = 0x2C, MEM32(h + 0x1C) = 1;
        MEM32(h + 0x20) = 0, MEM32(h + 0x24) = 0, MEM32(h + 0x28) = 0;
    }
    return o;
}
/* ACTIVATION_CONTEXT_DATA for a manifest's text (its dependencies resolved
 * from the store), in memory the guest can read; 0 when it has none */
uint32_t csr32_sxs_blob(const char* m, size_t len) {
    static sxs_sec dll, wc;
    char* x = (char*)malloc(len + 1);
    int deps = 0;
    if (!x) return 0;
    memcpy(x, m, len);
    x[len] = 0;
    memset(&dll, 0, sizeof dll), memset(&wc, 0, sizeof wc);
    for (const char* d = strstr(x, "<dependentAssembly"); d; d = strstr(d + 18, "<dependentAssembly")) {
        const char* id = strstr(d, "<assemblyIdentity");
        wchar_t name[128];
        if (id && xml_attr(id, "name", name, 128)) sxs_dependency(name, &dll, &wc, (uint32_t)++deps + 1);
    }
    free(x);
    /* header, TOC (2 entries), roster (deps + 2 entries: 0 unused, 1 the manifest's own), sections */
    uint32_t toc = 0x20, roster = toc + 0x10 + 2 * 0x10, nr = (uint32_t)deps + 2;
    uint32_t s2 = roster + 0x14 + 0x18 * nr, l2 = sxs_section(&dll, NULL, 2), s3 = (s2 + l2 + 3) & ~3u, l3 = sxs_section(&wc, NULL, 3);
    uint32_t total = s3 + l3;
    uint8_t* b = (uint8_t*)VirtualAlloc(NULL, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!b) return 0;
    uint32_t h = (uint32_t)(uintptr_t)b;
    MEM32(h) = 0x78746341u, MEM32(h + 4) = 0x20, MEM32(h + 8) = 1, MEM32(h + 0xC) = total;
    MEM32(h + 0x10) = toc, MEM32(h + 0x14) = 0, MEM32(h + 0x18) = roster, MEM32(h + 0x1C) = 0;
    MEM32(h + toc) = 0x10, MEM32(h + toc + 4) = 2, MEM32(h + toc + 8) = toc + 0x10, MEM32(h + toc + 0xC) = 2;
    MEM32(h + toc + 0x10) = 2, MEM32(h + toc + 0x14) = s2, MEM32(h + toc + 0x18) = l2, MEM32(h + toc + 0x1C) = 1;
    MEM32(h + toc + 0x20) = 3, MEM32(h + toc + 0x24) = s3, MEM32(h + toc + 0x28) = l3, MEM32(h + toc + 0x2C) = 1;
    MEM32(h + roster) = 0x14, MEM32(h + roster + 4) = 1, MEM32(h + roster + 8) = nr, MEM32(h + roster + 0xC) = roster + 0x14;
    for (uint32_t i = 1; i < nr; i++) MEM32(h + roster + 0x14 + 0x18 * i) = 1;   /* Flags: a valid entry */
    sxs_section(&dll, b + s2, 2);
    sxs_section(&wc, b + s3, 3);
    for (int i = 0; i < dll.n; i++) free(dll.e[i].data);
    for (int i = 0; i < wc.n; i++) free(wc.e[i].data);
    return h;
}

/* basesrv 27 on XP, BaseSrvSxsCreateActivationContext { Flags, ProcessorArchitecture,
 * LangId, Manifest { FileType, PathType, HandleType, Path, FileHandle, Handle,
 * Offset (8), Size } at +8, Policy at +0x30, AssemblyDirectory +0x58,
 * TextualAssemblyIdentity +0x60; out: *ActivationContextData +0x68 }. The
 * manifest is read through the section (+0x18) or file (+0x14) handle the
 * caller made (a DLL's resource: the file mapped, its Offset and Size). */
static uint32_t sxs_create_actctx(uint32_t data, uint32_t capture) {
    (void)capture;
    HANDLE sec = (HANDLE)(uintptr_t)MEM32(data + 0x18), file = (HANDLE)(uintptr_t)MEM32(data + 0x14);
    uint32_t off = MEM32(data + 0x20), size = MEM32(data + 0x28), r = 0;
    char* m = NULL;
    if (sec == (HANDLE)(intptr_t)-1) {           /* NtCurrentProcess: a loaded module's resource, at Offset */
        if ((m = (char*)malloc(size + 1)) != NULL) memcpy(m, (void*)(uintptr_t)off, size);
    } else if (sec) {
        uint8_t* v = (uint8_t*)MapViewOfFile(sec, FILE_MAP_READ, 0, 0, 0);
        if (v) { m = (char*)malloc(size + 1); if (m) memcpy(m, v + off, size); UnmapViewOfFile(v); }
    } else if (file && (m = (char*)malloc(size + 1)) != NULL) {
        DWORD got = 0;
        OVERLAPPED ov = { 0 };
        ov.Offset = off;
        if (!ReadFile(file, m, size, &got, &ov) || got != size) free(m), m = NULL;
    }
    if (!m) { fprintf(stderr, "[sxs] create: no manifest (section %p file %p)\n", sec, file); return 0xC0000034u; }
    r = csr32_sxs_blob(m, size);
    free(m);
    /* +0x68 is where the client wants it (PVOID*: csrss writes the view's address
     * into the caller's variable), not the address itself */
    if (r && MEM32(data + 0x68)) MEM32(MEM32(data + 0x68)) = r;
    return r ? 0 : 0xC0000017u;                          /* STATUS_NO_MEMORY */
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
    /* NlsGetUserInfo is basesrv 26 on NT 5.0 and 30 on NT 5.1 (Windows XP),
     * where 26 is another api: the guest's build (its PEB, set by now) says */
    {
        uint32_t nls = MEM16(native32_guest_peb + 0xAC) >= 2600 ? 30 : 26;
        if (!g_api[1][nls]) native32_csr_api(0x10000 | nls, nls_get_user_info);
        if (nls == 30 && !g_api[1][27]) native32_csr_api(0x1001B, sxs_create_actctx);
    }
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
    native32_nt_override("NtSecureConnectPort", ovr_secure_connect);
    native32_nt_override("NtConnectPort", ovr_connect);
    native32_nt_override("NtRequestWaitReplyPort", ovr_request_wait_reply);
    native32_nt_override("NtRequestPort", ovr_request_port);
    native32_nt_override("NtRegisterThreadTerminatePort", ovr_terminate_port);
}

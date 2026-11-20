/*
 * regbox32.c - a registry of the guest's own, per instance.
 *
 * native32_registry_sandbox(name) gives the guest, and only the guest, a
 * private hive under
 *
 *     HKCU\Software\pcrecomp\sandbox\<name>       (a name with a backslash,
 *     HKCU\Software\pcrecomp\<name>               "w2k\wordpad", is used as is)
 *
 * with HKCU, HKLM and NT (any other \REGISTRY path) under it, and INI for the
 * win.ini-style profile calls. The rule: the guest can never change the real
 * registry.
 *
 *   create      always in the sandbox (the real path mapped under it)
 *   open        the sandbox's key if it has one, else the real key READ-ONLY
 *               (write access bits stripped): Windows' own settings still read
 *   set/delete  on whichever key the handle is, mapped to the sandbox by its
 *               path (NtQueryKey); a real handle is never written
 *   query       a value: the sandbox first, then the real key
 *   the rest    RegSaveKey/RestoreKey/LoadKey/ReplaceKey/SetKeySecurity/
 *               OverridePredefKey/ConnectRegistry/DeleteTree/...: refused
 *
 * Covered: the guest's advapi32 imports, A and W (native32_redirect, so a
 * stage-1 host advapi32 and a run-time GetProcAddress), the profile calls of
 * kernel32 (WriteProfileString lands in INI\win.ini\<section>), and with
 * native32_registry_sandbox_nt() the NtXxxKey system calls of a lifted ntdll
 * and the proxied host advapi32 of a lifted process.
 *
 * ponytail: RegEnumKey/RegEnumValue see one side only (the handle's), and a
 * delete of a value that is only in the real key is a no-op (no tombstones).
 * Host DLLs in the process (comdlg32, shell32, shlwapi) are boxed through
 * their import slots (box_host_dlls), not their GetProcAddress lookups.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "native32.h"
#include "ntguest.h"

#pragma comment(lib, "advapi32.lib")

#define KP 1024
#define WRITE_BITS (KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK | DELETE | WRITE_DAC | WRITE_OWNER | \
                    MAXIMUM_ALLOWED | GENERIC_WRITE | GENERIC_ALL | ACCESS_SYSTEM_SECURITY)

typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } US;
typedef struct { ULONG Length; HANDLE Root; US* Name; ULONG Attributes; PVOID Sd, Qos; } OA;
static LONG (WINAPI* p_NtQueryKey)(HANDLE, int, void*, ULONG, ULONG*);
static LONG (WINAPI* p_NtOpenKey)(HANDLE*, ACCESS_MASK, OA*);
static ULONG (WINAPI* p_RtlNtStatusToDosError)(LONG);

static wchar_t g_cu_nt[256];      /* \REGISTRY\USER\S-1-5-21-... */
static wchar_t g_root_nt[512];    /* g_cu_nt\Software\pcrecomp\sandbox\<name> */
static wchar_t g_root_rel[300];   /* the same, relative to HKCU */
static int g_on;

static int prefix(const wchar_t* s, const wchar_t* p) {
    size_t n = wcslen(p);
    return !_wcsnicmp(s, p, n) && (s[n] == L'\\' || !s[n]);
}

/* the NT path of a key handle (or a predefined key), 0 if it has none */
static int key_path(HKEY k, wchar_t* out) {
    const wchar_t* fixed = k == HKEY_LOCAL_MACHINE ? L"\\REGISTRY\\MACHINE"
        : k == HKEY_CURRENT_USER ? g_cu_nt
        : k == HKEY_CLASSES_ROOT ? L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes"   /* ponytail: not the per-user merge */
        : k == HKEY_USERS ? L"\\REGISTRY\\USER"
        : k == HKEY_CURRENT_CONFIG ? L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current"
        : NULL;
    if (fixed) { wcscpy(out, fixed); return 1; }
    if ((ULONG_PTR)k >= 0x80000000u && (ULONG_PTR)k < 0x80000100u) return 0;   /* HKEY_PERFORMANCE_DATA... */
    union { ULONG len; BYTE b[KP * 2 + 8]; } u;
    ULONG got;
    if (p_NtQueryKey((HANDLE)k, 3 /* KeyNameInformation */, &u, sizeof u - 2, &got) < 0) return 0;
    ULONG n = u.len / 2;
    if (n >= KP) return 0;
    memcpy(out, u.b + 4, n * 2);
    out[n] = 0;
    return 1;
}
static void join(wchar_t* full, const wchar_t* sub) {
    if (sub && *sub) {
        size_t n = wcslen(full);
        _snwprintf(full + n, KP - n - 1, L"\\%ls", sub);
        full[KP - 1] = 0;
    }
}
static int in_box(const wchar_t* nt) { return prefix(nt, g_root_nt); }

/* real NT path -> the sandbox's, relative to HKCU */
static void to_box(const wchar_t* nt, wchar_t* rel) {
    size_t cu = wcslen(g_cu_nt);
    if (in_box(nt)) _snwprintf(rel, KP - 1, L"%ls%ls", g_root_rel, nt + wcslen(g_root_nt));
    /* the per-user classes (HKCR's other half): one merged HKCR in the box */
    else if (!_wcsnicmp(nt, g_cu_nt, cu) && prefix(nt + cu, L"_Classes"))
        _snwprintf(rel, KP - 1, L"%ls\\HKLM\\SOFTWARE\\Classes%ls", g_root_rel, nt + cu + 8);
    else if (prefix(nt, g_cu_nt)) _snwprintf(rel, KP - 1, L"%ls\\HKCU%ls", g_root_rel, nt + wcslen(g_cu_nt));
    else if (prefix(nt, L"\\REGISTRY\\MACHINE")) _snwprintf(rel, KP - 1, L"%ls\\HKLM%ls", g_root_rel, nt + 17);
    else _snwprintf(rel, KP - 1, L"%ls\\NT%ls", g_root_rel, nt);
    rel[KP - 1] = 0;
}
/* a sandbox NT path -> the real one; 0 for the sandbox's own top keys */
static int from_box(const wchar_t* nt, wchar_t* real) {
    const wchar_t* r = nt + wcslen(g_root_nt);
    if (prefix(r, L"\\HKCU")) _snwprintf(real, KP - 1, L"%ls%ls", g_cu_nt, r + 5);
    else if (prefix(r, L"\\HKLM")) _snwprintf(real, KP - 1, L"\\REGISTRY\\MACHINE%ls", r + 5);
    else if (prefix(r, L"\\NT") && r[3]) _snwprintf(real, KP - 1, L"%ls", r + 3);
    else return 0;
    real[KP - 1] = 0;
    return 1;
}
/* With a lifted ntdll (Windows 2000's own ole32), the host's COM class
 * registrations are not the guest's: Windows 11's HKCR\CLSID names its own
 * DLLs (explorerframe.dll for browseui's classes). Under any Classes\CLSID
 * or Classes\AppID only the box answers, seeded from Windows 2000's own
 * registration INFs (win2000 tools/reginst.py).
 * Any other class the box has is answered by the box alone too.
 * ponytail: Interface/TypeLib and classes only the host has still read the host's. */
static int g_guest_classes;
/* Keys the guest's OS owns: never the host's, whether or not the box has them
 * (the host's Shell Folders name C:\Users\<user>\OneDrive\..., its Environment
 * and ProfileList the host's user). The box's seed answers them (win2000
 * tools/profile.py); a key the box lacks is simply absent. */
static int os_owned_key(const wchar_t* nt) {
    static const wchar_t* cu[] = { L"\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER",
        L"\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\POLICIES", L"\\ENVIRONMENT", L"\\VOLATILE ENVIRONMENT" };
    static const wchar_t* lm[] = { L"\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\SHELL FOLDERS",
        L"\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\USER SHELL FOLDERS",
        L"\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\POLICIES", L"\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\PROFILELIST" };
    wchar_t u[KP];
    const wchar_t* r;
    size_t cn = wcslen(g_cu_nt), n;
    wcsncpy(u, nt, KP - 1), u[KP - 1] = 0, _wcsupr(u);
    if (!_wcsnicmp(nt, g_cu_nt, cn) && (!nt[cn] || nt[cn] == L'\\')) {
        for (int i = 0; i < 4; i++)
            if (n = wcslen(cu[i]), !wcsncmp(u + cn, cu[i], n) && (!u[cn + n] || u[cn + n] == L'\\')) return 1;
        /* NT 4.0's explorer starts what Run names: never the host's (its VMware tray...) */
        if (nt_guest_nt4(native32_guest_peb) && !wcsncmp(u + cn, L"\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN", 46)) return 1;
        return 0;
    }
    if (!wcsncmp(u, L"\\REGISTRY\\MACHINE\\SYSTEM\\", 25) && (r = wcsstr(u, L"\\CONTROL\\SESSION MANAGER\\ENVIRONMENT")))
        return !r[36] || r[36] == L'\\';
    if (wcsncmp(u, L"\\REGISTRY\\MACHINE\\SOFTWARE", 26)) return 0;
    r = u + 26;
    if (!wcsncmp(r, L"\\WOW6432NODE", 12)) r += 12;
    for (int i = 0; i < 4; i++)
        if (n = wcslen(lm[i]), !wcsncmp(r, lm[i], n) && (!r[n] || r[n] == L'\\')) return 1;
    if (nt_guest_nt4(native32_guest_peb) && !wcsncmp(r, L"\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN", 37)) return 1;   /* Run, RunOnce, RunServices: never the host's */
    /* and NT 4.0's Explorer key whole (its setup hive's): the host's desktop NameSpace (OneDrive...)
     * names classes NT 4.0 lacks, nameless folders on its desktop */
    if (nt_guest_nt4(native32_guest_peb) && !wcsncmp(r, L"\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER", 42) && (!r[42] || r[42] == L'\\')) return 1;
    /* XP's COM+ catalog (clbcatq): the host's COM3 names Windows 11's REGDB files, which
     * XP's catalog cannot read; without the key it reads the classes from the registry */
    if (nt_guest_xp(native32_guest_peb) && !wcsncmp(r, L"\\MICROSOFT\\COM3", 15) && (!r[15] || r[15] == L'\\')) return 1;
    /* and the taskbar's default bands (Explorer\Streams\Desktop): Windows 11's streams are not XP's */
    if (nt_guest_xp(native32_guest_peb) && !wcsncmp(r, L"\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\STREAMS", 50)) return 1;
    return 0;
}
static int host_class_key(const wchar_t* nt) {
    wchar_t u[KP];
    if (os_owned_key(nt)) {
        if (getenv("PCRECOMP_REGTRACE")) fprintf(stderr, "[regbox] %ls: the guest OS's key, not the host's\n", nt);
        return 1;
    }
    /* Keys a box that has them answers whole, never merged with the host's:
     * the time zones (Windows 11's Display values are @tzres.dll MUI strings)
     * and Control Panel's namespace (Windows 11's items were nameless folders) */
    {
        static const wchar_t* whole[] = { L"\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\TIME ZONES",
                                          L"\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\CONTROLPANEL\\NAMESPACE" };
        static const wchar_t* rels[] = { L"Microsoft\\Windows NT\\CurrentVersion\\Time Zones",
                                         L"Microsoft\\Windows\\CurrentVersion\\Explorer\\ControlPanel\\NameSpace" };
        wcsncpy(u, nt, KP - 1), u[KP - 1] = 0, _wcsupr(u);
        for (int i = 0; i < 2; i++)
            /* (the per-user Control Panel namespace too: Windows 11 has items there) */
            if ((!wcsncmp(u, L"\\REGISTRY\\MACHINE\\SOFTWARE", 26) || !wcsncmp(u, L"\\REGISTRY\\USER\\", 15)) && wcsstr(u, whole[i])) {
                wchar_t rel[KP];
                HKEY h;
                _snwprintf(rel, KP - 1, L"%ls\\HKLM\\SOFTWARE\\%ls", g_root_rel, rels[i]);
                rel[KP - 1] = 0;
                if (RegOpenKeyExW(HKEY_CURRENT_USER, rel, 0, KEY_READ, &h)) return 0;
                RegCloseKey(h);
                return 1;
            }
    }
    if (g_guest_classes < 0 && native32_module("ole32.dll")) g_guest_classes = 1;   /* Windows 2000's own COM, lifted (asked until the guest's modules are mapped) */
    /* NT 4.0's shell32 reads its classes' InProcServer32 itself (no ole32 lifted): the host's name windows.storage.dll */
    if (g_guest_classes < 0 && nt_guest_nt4(native32_guest_peb) && native32_module("shell32.dll")) g_guest_classes = 1;
    if (g_guest_classes <= 0) return 0;
    wcsncpy(u, nt, KP - 1), u[KP - 1] = 0, _wcsupr(u);
    if (!wcsstr(u, L"CLASSES\\CLSID\\") && !wcsstr(u, L"CLASSES\\WOW6432NODE\\CLSID\\") && !wcsstr(u, L"CLASSES\\APPID\\") &&
        !wcsstr(u, L"\\CURRENTVERSION\\EXPLORER\\CLSID\\")) {   /* the per-user overrides (Recycle Bin's imageres icons) */
        /* any other class the box has (Windows 2000's .txt, txtfile, Folder, Drive...):
         * the box answers it whole, so the host's newer values and subkeys under it
         * (imageres.dll icons, Win11 verbs) are not seen. A class only the host has
         * still reads through. */
        const wchar_t* c = wcsstr(u, L"CLASSES\\");
        wchar_t rel[KP];
        HKEY h;
        size_t n;
        if (!c) return 0;
        c += 8;
        if (!wcsncmp(c, L"WOW6432NODE\\", 12)) c += 12;
        n = wcscspn(c, L"\\");
        if (!n) return 0;
        _snwprintf(rel, KP - 1, L"%ls\\HKLM\\SOFTWARE\\Classes\\%.*ls", g_root_rel, (int)n, nt + (c - u));
        rel[KP - 1] = 0;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, rel, 0, KEY_READ, &h)) return 0;
        RegCloseKey(h);
    }
    if (getenv("PCRECOMP_REGTRACE")) fprintf(stderr, "[regbox] %ls: the host's class, not the guest's\n", nt);
    return 1;
}
static LONG real_open(const wchar_t* nt, REGSAM sam, HKEY* out) {
    if (host_class_key(nt)) return ERROR_FILE_NOT_FOUND;
    if (getenv("PCRECOMP_REGTRACE")) fprintf(stderr, "[regbox] host key read: %ls\n", nt);
    US us = { (USHORT)(wcslen(nt) * 2), (USHORT)(wcslen(nt) * 2), (PWSTR)nt };
    OA oa = { sizeof oa, NULL, &us, 0x40 /* OBJ_CASE_INSENSITIVE */, NULL, NULL };
    LONG st = p_NtOpenKey((HANDLE*)out, (sam & ~WRITE_BITS) | KEY_READ, &oa);
    return st < 0 ? (LONG)p_RtlNtStatusToDosError(st) : 0;
}

static int box_whole(HKEY bk);
/* The policy, by NT path: create in the box; open the box's, else the real one read-only. */
static LONG sb_open(const wchar_t* full, REGSAM sam, int create, DWORD opts, HKEY* out, DWORD* disp) {
    wchar_t rel[KP], real[KP];
    to_box(full, rel);
    LONG r = RegOpenKeyExW(HKEY_CURRENT_USER, rel, 0, sam, out);
    { const char* t = getenv("PCRECOMP_REGTRACE"); if (t && *t == '2') fprintf(stderr, "[regbox] open %ls -> %ld\n", full, r); }
    if (!r) { if (disp) *disp = REG_OPENED_EXISTING_KEY; return 0; }
    if (create) return RegCreateKeyExW(HKEY_CURRENT_USER, rel, 0, NULL, opts & ~REG_OPTION_BACKUP_RESTORE, sam, NULL, out, disp);
    if (in_box(full)) { if (!from_box(full, real)) return r; full = real; }
    /* a whole key's subtree is whole too: the nearest box ancestor that exists decides
     * (Win98's Explorer key: the host's MenuOrder\Favorites, MyComputer\NameSpace stay out) */
    for (wchar_t* sl; (sl = wcsrchr(rel, L'\\')) && (size_t)(sl - rel) > wcslen(g_root_rel); ) {
        HKEY a;
        *sl = 0;
        if (!RegOpenKeyExW(HKEY_CURRENT_USER, rel, 0, KEY_READ, &a)) {
            int w = box_whole(a);
            RegCloseKey(a);
            if (w) return ERROR_FILE_NOT_FOUND;
            break;
        }
    }
    return real_open(full, sam, out);
}

/* The key a write on handle k lands in: k itself when it is the box's, else
 * the box's copy of k's path (made, and closed by the caller through *tmp). */
static HKEY write_key(HKEY k, HKEY* tmp) {
    wchar_t nt[KP], rel[KP];
    *tmp = NULL;
    if (!key_path(k, nt)) return NULL;
    if (in_box(nt)) return k;
    to_box(nt, rel);
    if (RegCreateKeyExW(HKEY_CURRENT_USER, rel, 0, NULL, 0, KEY_ALL_ACCESS, NULL, tmp, NULL)) return NULL;
    return *tmp;
}
/* The box's copy of k (opened, if it exists) and the real key behind a box handle. */
static HKEY box_of(HKEY k, int* is_box) {
    wchar_t nt[KP], rel[KP];
    HKEY h;
    *is_box = 0;
    if (!key_path(k, nt)) return NULL;
    if (in_box(nt)) {
        *is_box = 1;
        return from_box(nt, rel) && !real_open(rel, KEY_READ, &h) ? h : NULL;
    }
    to_box(nt, rel);
    return RegOpenKeyExW(HKEY_CURRENT_USER, rel, 0, KEY_READ, &h) ? NULL : h;
}
/* A box key holding a value named "pcrecomp:whole" is the guest's whole: a value it lacks
 * is not looked up in the real key (Win98 USER's Control Panel\Colors: missing means its
 * own defaults, and the host's are Windows 11's). ponytail: the marker shows in an
 * enumeration of the key. */
static int box_whole(HKEY bk) { return !RegQueryValueExW(bk, L"pcrecomp:whole", NULL, NULL, NULL, NULL); }
#define done(x) do { if (tmp) RegCloseKey(tmp); return (x); } while (0)

static wchar_t* wide(const char* s, wchar_t* buf) {
    if (!s) return NULL;
    MultiByteToWideChar(CP_ACP, 0, s, -1, buf, KP);
    buf[KP - 1] = 0;
    return buf;
}

/* ---- advapi32 ------------------------------------------------------------ */
static LONG WINAPI g_RegCreateKeyExW(HKEY k, LPCWSTR sub, DWORD res, LPWSTR cls, DWORD opt, REGSAM sam,
                                     LPSECURITY_ATTRIBUTES sa, PHKEY out, LPDWORD disp) {
    wchar_t full[KP];
    (void)res; (void)cls; (void)sa;
    if (!key_path(k, full)) return ERROR_ACCESS_DENIED;
    join(full, sub);
    return sb_open(full, sam, 1, opt, out, disp);
}
static LONG WINAPI g_RegOpenKeyExW(HKEY k, LPCWSTR sub, DWORD opt, REGSAM sam, PHKEY out) {
    wchar_t full[KP];
    if (!key_path(k, full)) return RegOpenKeyExW(k, sub, opt, (sam & ~WRITE_BITS) | KEY_READ, out);
    join(full, sub);
    if (!in_box(full)) {
        /* the box's, else the real key opened from k itself: a 32-bit process's
         * HKLM\Software is WOW64-redirected and HKCR is merged per user, which
         * an absolute NT path would miss (the Open dialog's COM classes) */
        wchar_t rel[KP];
        to_box(full, rel);
        { LONG r = RegOpenKeyExW(HKEY_CURRENT_USER, rel, 0, sam, out); const char* t = getenv("PCRECOMP_REGTRACE");
          if (t && *t == '2') fprintf(stderr, "[regbox] Open %ls -> %ld\n", full, r);
          if (!r) return 0; }
        if (host_class_key(full)) return ERROR_FILE_NOT_FOUND;
        if (getenv("PCRECOMP_REGTRACE")) fprintf(stderr, "[regbox] host key read: %ls\n", full);
        return RegOpenKeyExW(k, sub, opt, (sam & ~WRITE_BITS) | KEY_READ, out);
    }
    return sb_open(full, sam, 0, 0, out, NULL);
}
static LONG WINAPI g_RegCreateKeyExA(HKEY k, LPCSTR sub, DWORD res, LPSTR cls, DWORD opt, REGSAM sam,
                                     LPSECURITY_ATTRIBUTES sa, PHKEY out, LPDWORD disp) {
    wchar_t s[KP];
    (void)cls;
    return g_RegCreateKeyExW(k, wide(sub, s), res, NULL, opt, sam, sa, out, disp);
}
static LONG WINAPI g_RegOpenKeyExA(HKEY k, LPCSTR sub, DWORD opt, REGSAM sam, PHKEY out) {
    wchar_t s[KP];
    return g_RegOpenKeyExW(k, wide(sub, s), opt, sam, out);
}
static LONG WINAPI g_RegCreateKeyW(HKEY k, LPCWSTR sub, PHKEY out) {
    return g_RegCreateKeyExW(k, sub, 0, NULL, 0, KEY_ALL_ACCESS, NULL, out, NULL);
}
static LONG WINAPI g_RegCreateKeyA(HKEY k, LPCSTR sub, PHKEY out) {
    return g_RegCreateKeyExA(k, sub, 0, NULL, 0, KEY_ALL_ACCESS, NULL, out, NULL);
}
static LONG WINAPI g_RegOpenKeyW(HKEY k, LPCWSTR sub, PHKEY out) { return g_RegOpenKeyExW(k, sub, 0, MAXIMUM_ALLOWED, out); }
static LONG WINAPI g_RegOpenKeyA(HKEY k, LPCSTR sub, PHKEY out) { return g_RegOpenKeyExA(k, sub, 0, MAXIMUM_ALLOWED, out); }
static LONG WINAPI g_RegOpenCurrentUser(REGSAM sam, PHKEY out) { return real_open(g_cu_nt, sam, out); }

static LONG WINAPI g_RegSetValueExW(HKEY k, LPCWSTR v, DWORD r, DWORD t, const BYTE* d, DWORD n) {
    HKEY tmp, h = write_key(k, &tmp);
    if (!h) return ERROR_ACCESS_DENIED;
    done(RegSetValueExW(h, v, r, t, d, n));
}
static LONG WINAPI g_RegSetValueExA(HKEY k, LPCSTR v, DWORD r, DWORD t, const BYTE* d, DWORD n) {
    HKEY tmp, h = write_key(k, &tmp);
    if (!h) return ERROR_ACCESS_DENIED;
    done(RegSetValueExA(h, v, r, t, d, n));
}
static LONG WINAPI g_RegSetValueW(HKEY k, LPCWSTR sub, DWORD t, LPCWSTR d, DWORD n) {
    HKEY h;
    LONG r = g_RegCreateKeyW(k, sub, &h);
    (void)n;
    if (r) return r;
    r = t == REG_SZ && d ? RegSetValueExW(h, NULL, 0, REG_SZ, (const BYTE*)d, (DWORD)(wcslen(d) + 1) * 2)
                         : ERROR_INVALID_PARAMETER;
    RegCloseKey(h);
    return r;
}
static LONG WINAPI g_RegSetValueA(HKEY k, LPCSTR sub, DWORD t, LPCSTR d, DWORD n) {
    HKEY h;
    LONG r = g_RegCreateKeyA(k, sub, &h);
    (void)n;
    if (r) return r;
    r = t == REG_SZ && d ? RegSetValueExA(h, NULL, 0, REG_SZ, (const BYTE*)d, (DWORD)strlen(d) + 1)
                         : ERROR_INVALID_PARAMETER;
    RegCloseKey(h);
    return r;
}
static LONG WINAPI g_RegDeleteValueW(HKEY k, LPCWSTR v) {
    int b;
    HKEY h = box_of(k, &b);
    LONG r;
    if (b) { if (h) RegCloseKey(h); return RegDeleteValueW(k, v); }
    if (!h) return ERROR_FILE_NOT_FOUND;
    RegCloseKey(h);
    HKEY tmp; h = write_key(k, &tmp);
    r = h ? RegDeleteValueW(h, v) : ERROR_ACCESS_DENIED;
    done(r);
}
static LONG WINAPI g_RegDeleteValueA(HKEY k, LPCSTR v) {
    wchar_t s[KP];
    return g_RegDeleteValueW(k, wide(v, s));
}
static LONG WINAPI g_RegDeleteKeyW(HKEY k, LPCWSTR sub) {
    wchar_t full[KP], rel[KP];
    if (!sub || !*sub || !key_path(k, full)) return ERROR_ACCESS_DENIED;
    join(full, sub);
    to_box(full, rel);
    return RegDeleteKeyW(HKEY_CURRENT_USER, rel);      /* only ever the box's */
}
static LONG WINAPI g_RegDeleteKeyA(HKEY k, LPCSTR sub) {
    wchar_t s[KP];
    return g_RegDeleteKeyW(k, wide(sub, s));
}

/* A value: the box's first, then the real key's. */
static LONG WINAPI g_RegQueryValueExW(HKEY k, LPCWSTR v, LPDWORD r, LPDWORD t, LPBYTE d, LPDWORD n) {
    int b;
    HKEY o = box_of(k, &b);
    LONG e;
    if (!o) return RegQueryValueExW(k, v, r, t, d, n);
    e = RegQueryValueExW(b ? k : o, v, r, t, d, n);
    if (e == ERROR_FILE_NOT_FOUND && !box_whole(b ? k : o)) e = RegQueryValueExW(b ? o : k, v, r, t, d, n);
    RegCloseKey(o);
    return e;
}
static LONG WINAPI g_RegQueryValueExA(HKEY k, LPCSTR v, LPDWORD r, LPDWORD t, LPBYTE d, LPDWORD n) {
    int b;
    HKEY o = box_of(k, &b);
    LONG e;
    if (!o) return RegQueryValueExA(k, v, r, t, d, n);
    e = RegQueryValueExA(b ? k : o, v, r, t, d, n);
    if (e == ERROR_FILE_NOT_FOUND && !box_whole(b ? k : o)) e = RegQueryValueExA(b ? o : k, v, r, t, d, n);
    RegCloseKey(o);
    return e;
}
static LONG WINAPI g_RegQueryValueW(HKEY k, LPCWSTR sub, LPWSTR d, PLONG n) {
    HKEY h = k;
    LONG r = sub && *sub ? g_RegOpenKeyExW(k, sub, 0, KEY_READ, &h) : 0;
    if (r) return r;
    r = g_RegQueryValueExW(h, NULL, NULL, NULL, (LPBYTE)d, (LPDWORD)n);
    if (h != k) RegCloseKey(h);
    return r;
}
static LONG WINAPI g_RegQueryValueA(HKEY k, LPCSTR sub, LPSTR d, PLONG n) {
    HKEY h = k;
    LONG r = sub && *sub ? g_RegOpenKeyExA(k, sub, 0, KEY_READ, &h) : 0;
    if (r) return r;
    r = g_RegQueryValueExA(h, NULL, NULL, NULL, (LPBYTE)d, (LPDWORD)n);
    if (h != k) RegCloseKey(h);
    return r;
}
/* RegGetValue (kernelbase's own open, not boxed otherwise: the host's shell32
 * read Shell Folders through it): opened through the box, the box's value first */
static LONG get_value(HKEY k, const void* sub, const void* v, DWORD f, LPDWORD t, PVOID d, LPDWORD n, int w) {
    HKEY h = k, o;
    int b;
    LONG r = 0;
    DWORD n0 = n ? *n : 0;
    if (sub && (w ? *(const wchar_t*)sub : *(const char*)sub))
        r = w ? g_RegOpenKeyExW(k, sub, 0, KEY_READ, &h) : g_RegOpenKeyExA(k, sub, 0, KEY_READ, &h);
    if (r) return r;
#define GV(x) (w ? RegGetValueW(x, NULL, v, f, t, d, n) : RegGetValueA(x, NULL, v, f, t, d, n))
    o = box_of(h, &b);
    if (!o) r = GV(h);
    else {
        r = GV(b ? h : o);
        if (r == ERROR_FILE_NOT_FOUND) { if (n) *n = n0; r = GV(b ? o : h); }
        RegCloseKey(o);
    }
#undef GV
    if (h != k) RegCloseKey(h);
    return r;
}
static LONG WINAPI g_RegGetValueW(HKEY k, LPCWSTR sub, LPCWSTR v, DWORD f, LPDWORD t, PVOID d, LPDWORD n) { return get_value(k, sub, v, f, t, d, n, 1); }
static LONG WINAPI g_RegGetValueA(HKEY k, LPCSTR sub, LPCSTR v, DWORD f, LPDWORD t, PVOID d, LPDWORD n) { return get_value(k, sub, v, f, t, d, n, 0); }

/* Refused outright: whole-hive and security operations. */
#define DENY(n, ...) static LONG WINAPI deny##n(__VA_ARGS__) { fprintf(stderr, "[regbox] refused a registry write\n"); return ERROR_ACCESS_DENIED; }
DENY(2, void* a, void* b) DENY(3, void* a, void* b, void* c) DENY(4, void* a, void* b, void* c, void* d)
DENY(5, void* a, void* b, void* c, void* d, void* e) DENY(6, void* a, void* b, void* c, void* d, void* e, void* f)
DENY(7, void* a, void* b, void* c, void* d, void* e, void* f, void* g)
DENY(11, void* a, void* b, void* c, void* d, void* e, void* f, void* g, void* h, void* i, void* j, void* l)
static BOOL WINAPI deny_prof2(void* a, void* b) { (void)a; (void)b; return FALSE; }
static BOOL WINAPI deny_prof3(void* a, void* b, void* c) { (void)a; (void)b; (void)c; return FALSE; }
static BOOL WINAPI deny_prof5(void* a, void* b, void* c, void* d, void* e) { (void)a; (void)b; (void)c; (void)d; (void)e; return FALSE; }

/* ---- kernel32 profiles: INI\<file>\<section>, value = key ----------------- */
static int ini_name(LPCWSTR file, wchar_t* out) {   /* win.ini, or a bare/Windows-directory .ini */
    wchar_t win[MAX_PATH];
    const wchar_t* base;
    if (!file) { wcscpy(out, L"win.ini"); return 1; }
    base = wcsrchr(file, L'\\');
    if (!base) base = wcsrchr(file, L'/');
    GetWindowsDirectoryW(win, MAX_PATH);
    if (base && !(prefix(file, win) && (size_t)(base - file) == wcslen(win))) return 0;   /* the program's own file */
    wcsncpy(out, base ? base + 1 : file, MAX_PATH - 1);
    out[MAX_PATH - 1] = 0;
    return 1;
}
static LONG ini_key(LPCWSTR file, LPCWSTR sec, int create, HKEY* h) {
    wchar_t rel[KP], ini[MAX_PATH];
    if (!ini_name(file, ini) || !sec) return ERROR_INVALID_PARAMETER;
    _snwprintf(rel, KP - 1, L"%ls\\INI\\%ls\\%ls", g_root_rel, ini, sec);
    rel[KP - 1] = 0;
    return create ? RegCreateKeyExW(HKEY_CURRENT_USER, rel, 0, NULL, 0, KEY_ALL_ACCESS, NULL, h, NULL)
                  : RegOpenKeyExW(HKEY_CURRENT_USER, rel, 0, KEY_READ, h);
}
static BOOL WINAPI g_WritePrivateProfileStringW(LPCWSTR sec, LPCWSTR key, LPCWSTR val, LPCWSTR file) {
    wchar_t ini[MAX_PATH];
    HKEY h;
    LONG r;
    if (file && !ini_name(file, ini)) return WritePrivateProfileStringW(sec, key, val, file);
    if (!sec) return TRUE;                                  /* flush */
    if (!key) {                                             /* delete the section (the box's) */
        if (ini_key(file, L"", 0, &h)) return TRUE;
        RegDeleteKeyW(h, sec);
        RegCloseKey(h);
        return TRUE;
    }
    if (ini_key(file, sec, 1, &h)) return FALSE;
    r = val ? RegSetValueExW(h, key, 0, REG_SZ, (const BYTE*)val, (DWORD)(wcslen(val) + 1) * 2) : RegDeleteValueW(h, key);
    RegCloseKey(h);
    return !r || !val;
}
static BOOL WINAPI g_WriteProfileStringW(LPCWSTR sec, LPCWSTR key, LPCWSTR val) {
    return g_WritePrivateProfileStringW(sec, key, val, NULL);
}
static BOOL WINAPI g_WritePrivateProfileStringA(LPCSTR sec, LPCSTR key, LPCSTR val, LPCSTR file) {
    static wchar_t a[KP], b[KP], c[KP], d[KP];   /* ponytail: not reentrant across threads */
    return g_WritePrivateProfileStringW(wide(sec, a), wide(key, b), wide(val, c), wide(file, d));
}
static BOOL WINAPI g_WriteProfileStringA(LPCSTR sec, LPCSTR key, LPCSTR val) {
    return g_WritePrivateProfileStringA(sec, key, val, NULL);
}
/* the box's string for sec/key, or 0 */
static int ini_get(LPCWSTR file, LPCWSTR sec, LPCWSTR key, wchar_t* out, DWORD cch) {
    HKEY h;
    DWORD t, n = cch * 2;
    LONG r;
    if (!sec || !key || (file && !ini_name(file, out)) || ini_key(file, sec, 0, &h)) return 0;
    r = RegQueryValueExW(h, key, NULL, &t, (LPBYTE)out, &n);
    RegCloseKey(h);
    if (r || t != REG_SZ) return 0;
    out[cch - 1] = 0;
    return 1;
}
static DWORD WINAPI g_GetPrivateProfileStringW(LPCWSTR sec, LPCWSTR key, LPCWSTR def, LPWSTR out, DWORD n, LPCWSTR file) {
    wchar_t v[KP];
    if (n && ini_get(file, sec, key, v, KP)) {
        wcsncpy(out, v, n - 1);
        out[n - 1] = 0;
        return (DWORD)wcslen(out);
    }
    return file ? GetPrivateProfileStringW(sec, key, def, out, n, file) : GetProfileStringW(sec, key, def, out, n);
}
static DWORD WINAPI g_GetProfileStringW(LPCWSTR sec, LPCWSTR key, LPCWSTR def, LPWSTR out, DWORD n) {
    return g_GetPrivateProfileStringW(sec, key, def, out, n, NULL);
}
static UINT WINAPI g_GetPrivateProfileIntW(LPCWSTR sec, LPCWSTR key, INT def, LPCWSTR file) {
    wchar_t v[KP];
    if (ini_get(file, sec, key, v, KP)) return (UINT)_wtoi(v);
    return file ? GetPrivateProfileIntW(sec, key, def, file) : GetProfileIntW(sec, key, def);
}
static UINT WINAPI g_GetProfileIntW(LPCWSTR sec, LPCWSTR key, INT def) { return g_GetPrivateProfileIntW(sec, key, def, NULL); }

/* SystemParametersInfo from a host DLL in the process (a proxied desk.cpl
 * rewrote HKCU\Control Panel\Desktop\WindowMetrics): queries only, as the
 * guest's own (w32kuser.c s_spi). GETs below 0x62 by name; from there and in
 * the 0x1000/0x2000 ranges they are even. */
static int spi_is_get(UINT a, void* pv) {
    static const UINT get[] = { 1, 3, 5, 0xA, 0xE, 0x10, 0x12, 0x16, 0x19, 0x1B, 0x1F, 0x23, 0x26, 0x29, 0x2B, 0x2D,
        0x30, 0x32, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E, 0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4F, 0x50, 0x53, 0x54,
        0x59, 0x5E, 0x5F, 0x73 };
    if (a == 0xD || a == 0x18) return pv != NULL;
    if (a >= 0x62) return !(a & 1) || a == 0x73;
    for (unsigned i = 0; i < sizeof get / sizeof get[0]; i++) if (get[i] == a) return 1;
    return 0;
}
static BOOL WINAPI g_SystemParametersInfoW(UINT a, UINT u, void* pv, UINT w) {
    if (!spi_is_get(a, pv)) { fprintf(stderr, "[regbox] host SystemParametersInfo 0x%X (a SET) refused\n", a); (void)w; return FALSE; }
    return SystemParametersInfoW(a, u, pv, 0);
}
static BOOL WINAPI g_SystemParametersInfoA(UINT a, UINT u, void* pv, UINT w) {
    if (!spi_is_get(a, pv)) { fprintf(stderr, "[regbox] host SystemParametersInfo 0x%X (a SET) refused\n", a); (void)w; return FALSE; }
    return SystemParametersInfoA(a, u, pv, 0);
}

/* ---- the guest's identity -------------------------------------------------
 * The guest never learns the host's account or machine: it is user "User" on
 * computer "PCRECOMP". The host's names are read here only to be recognized
 * (never printed): a proxied advapi32 answer naming one is rewritten, a host
 * registry value holding one reads as absent, and the guest's environment
 * drops every entry holding one (syscall32.c). */
#define GUEST_USER L"User"
#define GUEST_MACHINE L"PCRECOMP"
static wchar_t g_hid[6][260];      /* user, display name, profile folder | computer, DNS host, domain */
static int g_nhid = -1;
static void host_ids(void) {
    DWORD n;
    HANDLE t;
    wchar_t* s;
    BOOLEAN (WINAPI* ex)(int, wchar_t*, ULONG*) = (void*)GetProcAddress(LoadLibraryA("secur32.dll"), "GetUserNameExW");
    BOOL (WINAPI* prof)(HANDLE, wchar_t*, DWORD*) = (void*)GetProcAddress(LoadLibraryA("userenv.dll"), "GetUserProfileDirectoryW");
    if (g_nhid >= 0) return;
    memset(g_hid, 0, sizeof g_hid);
    n = 260, GetUserNameW(g_hid[0], &n);
    n = 260; if (ex) ex(3 /* NameDisplay */, g_hid[1], &n);
    n = 260;
    if (prof && OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) {
        if (prof(t, g_hid[2], &n) && (s = wcsrchr(g_hid[2], L'\\'))) memmove(g_hid[2], s + 1, (wcslen(s + 1) + 1) * 2);
        else g_hid[2][0] = 0;
        CloseHandle(t);
    }
    n = 260, GetComputerNameW(g_hid[3], &n);
    n = 260, GetComputerNameExW(ComputerNameDnsHostname, g_hid[4], &n);
    GetEnvironmentVariableW(L"USERDOMAIN", g_hid[5], 260);
    for (int i = 0; i < 6; i++) if (wcslen(g_hid[i]) < 3) g_hid[i][0] = 0;   /* too short to tell from other text */
    g_nhid = 6;
}
/* s (n characters) is exactly a host name: the guest's name for it */
static const wchar_t* id_map(const wchar_t* s, size_t n) {
    host_ids();
    for (int i = 0; s && i < 6; i++)
        if (g_hid[i][0] && wcslen(g_hid[i]) == n && !_wcsnicmp(s, g_hid[i], n)) return i < 3 ? GUEST_USER : GUEST_MACHINE;
    return NULL;
}
/* s (n characters) holds a host name anywhere, as a whole word (a 3-letter machine
 * name is not found inside "AppliedDPI") */
int native32_host_identity_in(const wchar_t* s, size_t n) {
    host_ids();
    for (int i = 0; i < 6; i++) {
        size_t k = wcslen(g_hid[i]);
        for (size_t j = 0; k && j + k <= n; j++)
            if (!_wcsnicmp(s + j, g_hid[i], k) && (!j || !iswalnum(s[j - 1])) && (j + k == n || !iswalnum(s[j + k]))) return 1;
    }
    return 0;
}
static void us_fix(US* u) {
    const wchar_t* m = u && u->Buffer ? id_map(u->Buffer, u->Length / 2) : NULL;
    USHORT n;
    if (!m) return;
    n = (USHORT)(wcslen(m) * 2);
    /* ponytail: a buffer too small for the guest's name points at a constant (LSA frees the block, not the string) */
    if (n <= u->MaximumLength) memcpy(u->Buffer, m, n); else u->Buffer = (PWSTR)m, u->MaximumLength = n;
    u->Length = n;
}
/* the A/W "name, count" out-parameter rule: the count without the NUL on success, with it when too small */
static BOOL id_put(const wchar_t* v, void* buf, DWORD* cnt, int ansi) {
    DWORD need = (DWORD)wcslen(v) + 1;
    if (!cnt || !buf || *cnt < need) { if (cnt) *cnt = need; SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    if (ansi) WideCharToMultiByte(CP_ACP, 0, v, -1, (char*)buf, (int)*cnt, NULL, NULL); else wcscpy((wchar_t*)buf, v);
    *cnt = need;
    return TRUE;
}
static BOOL WINAPI g_GetUserNameW(wchar_t* b, DWORD* n) { return id_put(GUEST_USER, b, n, 0); }   /* (the count with the NUL) */
static BOOL WINAPI g_GetUserNameA(char* b, DWORD* n) { return id_put(GUEST_USER, b, n, 1); }
static BOOLEAN WINAPI g_GetUserNameExW(int f, wchar_t* b, ULONG* n) {
    const wchar_t* v = f == 2 ? GUEST_MACHINE L"\\" GUEST_USER : f == 3 ? GUEST_USER : NULL;   /* SamCompatible, Display */
    if (!v) { SetLastError(ERROR_NONE_MAPPED); return FALSE; }
    if (!id_put(v, b, n, 0)) { SetLastError(ERROR_MORE_DATA); return FALSE; }
    --*n;
    return TRUE;
}
static BOOL lookup_sid(const wchar_t* sys, PSID sid, void* nm, DWORD* cn, void* dm, DWORD* cd, SID_NAME_USE* use, int ansi) {
    wchar_t n[260], d[260];
    const wchar_t* N, *D;
    DWORD a = 260, b = 260, nn, dn;
    SID_NAME_USE u;
    if (!LookupAccountSidW(sys, sid, n, &a, d, &b, &u)) return FALSE;
    N = id_map(n, wcslen(n)), D = id_map(d, wcslen(d));
    if (!N) N = n;
    if (!D) D = d;
    nn = (DWORD)wcslen(N) + 1, dn = (DWORD)wcslen(D) + 1;
    if (!cn || !cd || *cn < nn || *cd < dn || !nm || !dm) {
        if (cn) *cn = nn;
        if (cd) *cd = dn;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    id_put(N, nm, cn, ansi), id_put(D, dm, cd, ansi);
    --*cn, --*cd;
    if (use) *use = u;
    return TRUE;
}
static BOOL WINAPI g_LookupAccountSidW(const wchar_t* s, PSID p, wchar_t* n, DWORD* cn, wchar_t* d, DWORD* cd, SID_NAME_USE* u) {
    return lookup_sid(s, p, n, cn, d, cd, u, 0);
}
static BOOL WINAPI g_LookupAccountSidA(const char* s, PSID p, char* n, DWORD* cn, char* d, DWORD* cd, SID_NAME_USE* u) {
    wchar_t w[260];
    if (s) MultiByteToWideChar(CP_ACP, 0, s, -1, w, 260);
    return lookup_sid(s ? w : NULL, p, n, cn, d, cd, u, 1);
}
static BOOL WINAPI g_LookupAccountSidLocalW(PSID p, wchar_t* n, DWORD* cn, wchar_t* d, DWORD* cd, SID_NAME_USE* u) {
    return lookup_sid(NULL, p, n, cn, d, cd, u, 0);
}
static BOOL WINAPI g_LookupAccountSidLocalA(PSID p, char* n, DWORD* cn, char* d, DWORD* cd, SID_NAME_USE* u) {
    return lookup_sid(NULL, p, n, cn, d, cd, u, 1);
}
/* LSA: the host's answer, its names rewritten in place */
typedef struct { ULONG Entries; struct { US Name; PSID Sid; }* Domains; } LSA_DOMS;
static LONG lsa_names(LONG r, ULONG count, LSA_DOMS* dom, BYTE* names, size_t stride) {
    if (r < 0) return r;
    for (ULONG i = 0; names && i < count; i++) us_fix((US*)(names + i * stride + 4));   /* {Use; Name; DomainIndex[; Flags]} */
    for (ULONG i = 0; dom && i < dom->Entries; i++) us_fix(&dom->Domains[i].Name);
    return r;
}
static LONG WINAPI g_LsaLookupSids(HANDLE h, ULONG c, PSID* s, LSA_DOMS** d, BYTE** n) {
    static LONG (WINAPI* f)(HANDLE, ULONG, PSID*, LSA_DOMS**, BYTE**);
    if (!f) f = (void*)GetProcAddress(GetModuleHandleA("advapi32.dll"), "LsaLookupSids");
    LONG r = f(h, c, s, d, n);
    return lsa_names(r, c, r < 0 ? NULL : *d, r < 0 ? NULL : *n, 16);
}
static LONG WINAPI g_LsaLookupSids2(HANDLE h, ULONG fl, ULONG c, PSID* s, LSA_DOMS** d, BYTE** n) {
    static LONG (WINAPI* f)(HANDLE, ULONG, ULONG, PSID*, LSA_DOMS**, BYTE**);
    if (!f) f = (void*)GetProcAddress(GetModuleHandleA("advapi32.dll"), "LsaLookupSids2");
    LONG r = f(h, fl, c, s, d, n);
    return lsa_names(r, c, r < 0 ? NULL : *d, r < 0 ? NULL : *n, 20);
}
static LONG WINAPI g_LsaGetUserName(US** u, US** d) {
    static LONG (WINAPI* f)(US**, US**);
    if (!f) f = (void*)GetProcAddress(GetModuleHandleA("advapi32.dll"), "LsaGetUserName");
    LONG r = f(u, d);
    if (r >= 0) { if (u) us_fix(*u); if (d) us_fix(*d); }
    return r;
}
static LONG WINAPI g_LsaQueryInformationPolicy(HANDLE h, int c, void** b) {
    LONG r = ((LONG (WINAPI*)(HANDLE, int, void**))GetProcAddress(GetModuleHandleA("advapi32.dll"), "LsaQueryInformationPolicy"))(h, c, b);
    if (r >= 0 && b && *b && (c == 3 || c == 5 || c == 12)) {   /* Primary/AccountDomain {Name, Sid}; DnsDomain {Name, DnsDomainName, DnsForestName, ...} */
        US* u = (US*)*b;
        for (int i = 0; i < (c == 12 ? 3 : 1); i++) us_fix(u + i);
    }
    return r;
}
static DWORD WINAPI g_NetWkstaGetInfo(void* srv, DWORD level, void** out) {
    (void)srv; (void)level;
    if (out) *out = NULL;
    return ERROR_ACCESS_DENIED;                                   /* no workstation service to ask */
}
static const struct { const char* name; void* fn; } g_ids[] = {
    { "GetUserNameW", g_GetUserNameW }, { "GetUserNameA", g_GetUserNameA }, { "GetUserNameExW", g_GetUserNameExW },
    { "LookupAccountSidW", g_LookupAccountSidW }, { "LookupAccountSidA", g_LookupAccountSidA },
    { "LookupAccountSidLocalW", g_LookupAccountSidLocalW }, { "LookupAccountSidLocalA", g_LookupAccountSidLocalA },
    { "LsaLookupSids", g_LsaLookupSids }, { "LsaLookupSids2", g_LsaLookupSids2 }, { "LsaGetUserName", g_LsaGetUserName },
    { "LsaQueryInformationPolicy", g_LsaQueryInformationPolicy }, { "NetWkstaGetInfo", g_NetWkstaGetInfo },
};
/* the guest's own answers for the registry values that name the machine or its user (the box answers first) */
static void seed_ids(void) {
    static const wchar_t* v[][3] = {
        { L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName", L"ComputerName", GUEST_MACHINE },
        { L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName", L"ComputerName", GUEST_MACHINE },
        { L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", L"Hostname", GUEST_MACHINE },
        { L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", L"NV Hostname", GUEST_MACHINE },
        { L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"DefaultUserName", GUEST_USER },
        { L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"DefaultDomainName", GUEST_MACHINE },
        { L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"RegisteredOwner", GUEST_USER },
        { L"HKCU\\Volatile Environment", L"USERNAME", GUEST_USER },
        { L"HKCU\\Volatile Environment", L"USERDOMAIN", GUEST_MACHINE },
        { L"HKCU\\Volatile Environment", L"LOGONSERVER", L"\\\\" GUEST_MACHINE },
    };
    for (int i = 0; i < (int)(sizeof v / sizeof v[0]); i++) {
        wchar_t rel[KP];
        _snwprintf(rel, KP - 1, L"%ls\\%ls", g_root_rel, v[i][0]), rel[KP - 1] = 0;
        RegSetKeyValueW(HKEY_CURRENT_USER, rel, v[i][1], REG_SZ, v[i][2], (DWORD)(wcslen(v[i][2]) + 1) * 2);
    }
}

static const struct { const char* name; void* fn; } g_fns[] = {
    { "SystemParametersInfoW", g_SystemParametersInfoW }, { "SystemParametersInfoA", g_SystemParametersInfoA },
    { "RegCreateKeyExW", g_RegCreateKeyExW }, { "RegCreateKeyExA", g_RegCreateKeyExA },
    { "RegCreateKeyW", g_RegCreateKeyW }, { "RegCreateKeyA", g_RegCreateKeyA },
    { "RegOpenKeyExW", g_RegOpenKeyExW }, { "RegOpenKeyExA", g_RegOpenKeyExA },
    { "RegOpenKeyW", g_RegOpenKeyW }, { "RegOpenKeyA", g_RegOpenKeyA }, { "RegOpenCurrentUser", g_RegOpenCurrentUser },
    { "RegSetValueExW", g_RegSetValueExW }, { "RegSetValueExA", g_RegSetValueExA },
    { "RegSetValueW", g_RegSetValueW }, { "RegSetValueA", g_RegSetValueA },
    { "RegDeleteValueW", g_RegDeleteValueW }, { "RegDeleteValueA", g_RegDeleteValueA },
    { "RegDeleteKeyW", g_RegDeleteKeyW }, { "RegDeleteKeyA", g_RegDeleteKeyA },
    { "RegQueryValueExW", g_RegQueryValueExW }, { "RegQueryValueExA", g_RegQueryValueExA },
    { "RegQueryValueW", g_RegQueryValueW }, { "RegQueryValueA", g_RegQueryValueA },
    { "RegGetValueW", g_RegGetValueW }, { "RegGetValueA", g_RegGetValueA },
    { "RegUnLoadKeyW", deny2 }, { "RegUnLoadKeyA", deny2 }, { "RegOverridePredefKey", deny2 },
    { "RegDeleteTreeW", deny2 }, { "RegDeleteTreeA", deny2 },
    { "RegLoadKeyW", deny3 }, { "RegLoadKeyA", deny3 }, { "RegRestoreKeyW", deny3 }, { "RegRestoreKeyA", deny3 },
    { "RegSaveKeyW", deny3 }, { "RegSaveKeyA", deny3 }, { "RegSetKeySecurity", deny3 },
    { "RegConnectRegistryW", deny3 }, { "RegConnectRegistryA", deny3 }, { "RegCopyTreeW", deny3 }, { "RegCopyTreeA", deny3 },
    { "RegRenameKey", deny3 }, { "RegDeleteKeyValueW", deny3 }, { "RegDeleteKeyValueA", deny3 },
    { "RegReplaceKeyW", deny4 }, { "RegReplaceKeyA", deny4 }, { "RegSaveKeyExW", deny4 }, { "RegSaveKeyExA", deny4 },
    { "RegDeleteKeyExW", deny4 }, { "RegDeleteKeyExA", deny4 }, { "RegLoadAppKeyW", deny5 }, { "RegLoadAppKeyA", deny5 },
    { "RegSetKeyValueW", deny6 }, { "RegSetKeyValueA", deny6 }, { "RegDeleteKeyTransactedW", deny6 },
    { "RegDeleteKeyTransactedA", deny6 }, { "RegOpenKeyTransactedW", deny7 }, { "RegOpenKeyTransactedA", deny7 },
    { "RegCreateKeyTransactedW", deny11 }, { "RegCreateKeyTransactedA", deny11 },
    { "WriteProfileStringW", g_WriteProfileStringW }, { "WriteProfileStringA", g_WriteProfileStringA },
    { "WritePrivateProfileStringW", g_WritePrivateProfileStringW }, { "WritePrivateProfileStringA", g_WritePrivateProfileStringA },
    { "GetProfileStringW", g_GetProfileStringW }, { "GetPrivateProfileStringW", g_GetPrivateProfileStringW },
    { "GetProfileIntW", g_GetProfileIntW }, { "GetPrivateProfileIntW", g_GetPrivateProfileIntW },
    { "WriteProfileSectionW", deny_prof2 }, { "WriteProfileSectionA", deny_prof2 },
    { "WritePrivateProfileSectionW", deny_prof3 }, { "WritePrivateProfileSectionA", deny_prof3 },
    { "WritePrivateProfileStructW", deny_prof5 }, { "WritePrivateProfileStructA", deny_prof5 },
};
#define NFNS ((int)(sizeof g_fns / sizeof g_fns[0]))

/* ---- host DLLs in the process (comdlg32, shell32, shlwapi...) --------------
 * Their imports of the same functions, through advapi32, kernel32 or the
 * api-ms-win-core-registry sets, all resolve to a few host addresses: every
 * import slot (and delay-load slot) holding one of them, in every module but
 * the host exe and the core DLLs that implement the registry, is pointed at the
 * sandbox's function. Modules loaded later are patched as they load
 * (LdrRegisterDllNotification). ponytail: a host DLL that finds these with
 * GetProcAddress is not covered. */
static void* g_orig[96][4];
static void patch_slot(void** slot, int delay_unbound, const char* name) {
    DWORD old;
    for (int i = 0; i < NFNS; i++) {
        if (!g_fns[i].fn) continue;
        int hit = delay_unbound ? name && !strcmp(name, g_fns[i].name) : 0;
        for (int j = 0; !hit && j < 4; j++) hit = g_orig[i][j] && *slot == g_orig[i][j];
        if (!hit) continue;
        if (VirtualProtect(slot, 4, PAGE_READWRITE, &old)) { *slot = g_fns[i].fn; VirtualProtect(slot, 4, old, &old); }
        return;
    }
}
static void patch_module(HMODULE m) {
    static const char* skip[] = { "ntdll.dll", "kernel32.dll", "kernelbase.dll", "advapi32.dll", "sechost.dll" };
    char path[MAX_PATH];
    const char* base;
    BYTE* b = (BYTE*)m;
    if (!m || m == GetModuleHandleA(NULL) || !GetModuleFileNameA(m, path, MAX_PATH)) return;
    base = strrchr(path, '\\') ? strrchr(path, '\\') + 1 : path;
    for (int i = 0; i < (int)(sizeof skip / sizeof skip[0]); i++) if (!_stricmp(base, skip[i])) return;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(b + ((IMAGE_DOS_HEADER*)b)->e_lfanew);
    IMAGE_DATA_DIRECTORY* dd = nt->OptionalHeader.DataDirectory;
    if (dd[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
        for (IMAGE_IMPORT_DESCRIPTOR* d = (void*)(b + dd[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress); d->Name; d++)
            for (void** s = (void**)(b + d->FirstThunk); *s; s++) patch_slot(s, 0, NULL);
    if (dd[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress)
        for (IMAGE_DELAYLOAD_DESCRIPTOR* d = (void*)(b + dd[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress); d->DllNameRVA; d++) {
            void** s = (void**)(b + d->ImportAddressTableRVA);
            IMAGE_THUNK_DATA32* n = (IMAGE_THUNK_DATA32*)(b + d->ImportNameTableRVA);
            for (; n->u1.AddressOfData; s++, n++) {
                const char* nm = n->u1.Ordinal & IMAGE_ORDINAL_FLAG32 ? NULL : ((IMAGE_IMPORT_BY_NAME*)(b + n->u1.AddressOfData))->Name;
                int unbound = (BYTE*)*s >= b && (BYTE*)*s < b + nt->OptionalHeader.SizeOfImage;
                patch_slot(s, unbound, nm);
            }
        }
}
typedef struct { ULONG Flags; void* FullName; void* BaseName; PVOID DllBase; ULONG SizeOfImage; } DLL_NOTE;
static VOID CALLBACK on_dll(ULONG reason, DLL_NOTE* d, PVOID ctx) {
    (void)ctx;
    if (reason == 1 /* loaded */) patch_module((HMODULE)d->DllBase);
}
static void box_host_dlls(void) {
    const char* dlls[4] = { "advapi32.dll", "kernelbase.dll", "kernel32.dll", "user32.dll" };
    HMODULE ms[512];
    DWORD got;
    PVOID cookie;
    LONG (WINAPI* reg)(ULONG, void*, PVOID, PVOID*) =
        (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrRegisterDllNotification");
    for (int i = 0; i < NFNS && i < 96; i++)
        for (int j = 0; j < 4; j++) {
            HMODULE h = GetModuleHandleA(dlls[j]);
            g_orig[i][j] = h ? (void*)GetProcAddress(h, g_fns[i].name) : NULL;
        }
    if (reg) reg(0, (void*)on_dll, NULL, &cookie);
    BOOL (WINAPI* en)(HANDLE, HMODULE*, DWORD, DWORD*) =
        (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "K32EnumProcessModules");
    if (en && en(GetCurrentProcess(), ms, sizeof ms, &got))
        for (DWORD i = 0; i < got / sizeof ms[0] && i < 512; i++) patch_module(ms[i]);
}

void* native32_registry_sandbox_fn(const char* name) {
    for (int i = 0; g_on && i < NFNS; i++)
        if (g_fns[i].fn && !strcmp(g_fns[i].name, name)) return g_fns[i].fn;
    return NULL;
}

int native32_registry_box_sz(const wchar_t* sub, const wchar_t* value, wchar_t* out, DWORD cch) {
    wchar_t key[KP];
    DWORD n = cch * sizeof(wchar_t);
    if (!g_on) return 0;
    _snwprintf(key, KP - 1, L"%ls\\HKCU\\%ls", g_root_rel, sub);
    key[KP - 1] = 0;
    return !RegGetValueW(HKEY_CURRENT_USER, key, value, RRF_RT_REG_SZ, NULL, out, &n);
}

int native32_registry_sandbox(const char* name) {
    char path[300];
    HKEY cu, root;
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    p_NtQueryKey = (void*)GetProcAddress(nt, "NtQueryKey");
    p_NtOpenKey = (void*)GetProcAddress(nt, "NtOpenKey");
    p_RtlNtStatusToDosError = (void*)GetProcAddress(nt, "RtlNtStatusToDosError");
    if (RegOpenCurrentUser(KEY_READ, &cu)) return 0;
    if (!key_path(cu, g_cu_nt)) return 0;
    RegCloseKey(cu);
    _snprintf(path, sizeof path - 1, strchr(name, '\\') ? "Software\\pcrecomp\\%s" : "Software\\pcrecomp\\sandbox\\%s", name);
    path[sizeof path - 1] = 0;
    MultiByteToWideChar(CP_ACP, 0, path, -1, g_root_rel, 300);
    if (RegCreateKeyExW(HKEY_CURRENT_USER, g_root_rel, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &root, NULL)) return 0;
    RegCloseKey(root);
    _snwprintf(g_root_nt, 511, L"%ls\\%ls", g_cu_nt, g_root_rel);
    g_on = 1;
    seed_ids();
    for (int i = 0; i < NFNS; i++)
        if (g_fns[i].fn) native32_redirect(g_fns[i].name, g_fns[i].fn);
    for (int i = 0; i < (int)(sizeof g_ids / sizeof g_ids[0]); i++) native32_redirect(g_ids[i].name, g_ids[i].fn);
    box_host_dlls();
    return 1;
}

/* ---- NtXxxKey of a lifted ntdll (syscall32's argument arrays) ------------- */
#define ST_DENIED 0xC0000022u
#define ST_NOT_FOUND 0xC0000034u
static uint32_t (*nt_fwd)(const char*, uint32_t*);
static uint32_t st_of(LONG e) { return !e ? 0 : e == ERROR_FILE_NOT_FOUND ? ST_NOT_FOUND : e == ERROR_ACCESS_DENIED ? ST_DENIED
                                    : e == ERROR_PATH_NOT_FOUND ? 0xC000003Au : 0xC0000001u; }
static int oa_path(OA* oa, wchar_t* full) {
    if (oa->Root) { if (!key_path((HKEY)oa->Root, full)) return 0; }
    else full[0] = 0;
    if (oa->Name && oa->Name->Length) {
        size_t n = wcslen(full), m = oa->Name->Length / 2;
        if (n + m + 2 >= KP) return 0;
        if (n) full[n++] = L'\\';
        memcpy(full + n, oa->Name->Buffer, m * 2);
        full[n + m] = 0;
    }
    return full[0] == L'\\';
}
/* NtCreateKey(PHANDLE, ACCESS, OA*, TitleIndex, Class, Options, Disposition*) */
static uint32_t nt_create_key(uint32_t* a) {
    wchar_t full[KP];
    if (!oa_path((OA*)(uintptr_t)a[2], full)) return ST_DENIED;
    return st_of(sb_open(full, a[1], 1, a[5], (HKEY*)(uintptr_t)a[0], (DWORD*)(uintptr_t)a[6]));
}
/* NtOpenKey(PHANDLE, ACCESS, OA*) */
static uint32_t nt_open_key(uint32_t* a) {
    wchar_t full[KP];
    if (!oa_path((OA*)(uintptr_t)a[2], full)) { a[1] = (a[1] & ~WRITE_BITS) | KEY_READ; return nt_fwd("NtOpenKey", a); }
    return st_of(sb_open(full, a[1], 0, 0, (HKEY*)(uintptr_t)a[0], NULL));
}
/* NtSetValueKey(H, US*, TitleIndex, Type, Data, Size) */
static uint32_t nt_set_value(uint32_t* a) {
    HKEY tmp, h = write_key((HKEY)(uintptr_t)a[0], &tmp);
    uint32_t r, k = a[0];
    if (!h) return ST_DENIED;
    a[0] = (uint32_t)(uintptr_t)h;
    r = nt_fwd("NtSetValueKey", a);
    a[0] = k;
    if (tmp) RegCloseKey(tmp);
    return r;
}
/* NtDeleteValueKey(H, US*) */
static uint32_t nt_delete_value(uint32_t* a) {
    int b;
    HKEY o = box_of((HKEY)(uintptr_t)a[0], &b);
    uint32_t r, k = a[0];
    if (b) { if (o) RegCloseKey(o); return nt_fwd("NtDeleteValueKey", a); }
    if (!o) return ST_NOT_FOUND;
    RegCloseKey(o);
    HKEY tmp, h = write_key((HKEY)(uintptr_t)k, &tmp);
    if (!h) return ST_DENIED;
    a[0] = (uint32_t)(uintptr_t)h;
    r = nt_fwd("NtDeleteValueKey", a);
    a[0] = k;
    if (tmp) RegCloseKey(tmp);
    return r;
}
/* NtDeleteKey(H): the box's only */
static uint32_t nt_delete_key(uint32_t* a) {
    wchar_t nt[KP];
    return key_path((HKEY)(uintptr_t)a[0], nt) && in_box(nt) ? nt_fwd("NtDeleteKey", a) : ST_DENIED;
}
/* NtQueryValueKey(H, US*, class, buf, len, ret*): the box's, then the real one */
static uint32_t nt_query_value(uint32_t* a) {
    int b;
    HKEY o = box_of((HKEY)(uintptr_t)a[0], &b);
    uint32_t r, k = a[0];
    if (!o) return nt_fwd("NtQueryValueKey", a);
    if (!b) a[0] = (uint32_t)(uintptr_t)o;
    r = nt_fwd("NtQueryValueKey", a);
    if (r == ST_NOT_FOUND) { a[0] = b ? (uint32_t)(uintptr_t)o : k; r = nt_fwd("NtQueryValueKey", a); }
    a[0] = k;
    /* a value naming the host's user or machine (a path under C:\Users\<name>, ...) is absent for the guest */
    if (!r && a[3] && native32_host_identity_in((const wchar_t*)(uintptr_t)a[3], (a[5] ? *(uint32_t*)(uintptr_t)a[5] : a[4]) / 2)) r = ST_NOT_FOUND;
    RegCloseKey(o);
    return r;
}
static uint32_t nt_deny(uint32_t* a) { (void)a; fprintf(stderr, "[regbox] refused an NT registry write\n"); return ST_DENIED; }

void native32_registry_sandbox_nt(void (*ovr)(const char*, native32_syscall_fn),
                                  uint32_t (*fwd)(const char*, uint32_t*), void (*hook)(const char*, void*)) {
    static const char* deny[] = { "NtSetInformationKey", "NtSaveKey", "NtSaveMergedKeys", "NtRestoreKey", "NtLoadKey",
        "NtLoadKey2", "NtReplaceKey", "NtUnloadKey", "NtInitializeRegistry", "NtSaveKeyEx", "NtLoadKeyEx", "NtRenameKey" };
    if (!g_on) return;
    nt_fwd = fwd;
    g_guest_classes = -1;   /* asked once the guest's modules are mapped */
    ovr("NtCreateKey", nt_create_key);
    ovr("NtOpenKey", nt_open_key);
    ovr("NtSetValueKey", nt_set_value);
    ovr("NtDeleteValueKey", nt_delete_value);
    ovr("NtDeleteKey", nt_delete_key);
    ovr("NtQueryValueKey", nt_query_value);
    for (int i = 0; i < (int)(sizeof deny / sizeof deny[0]); i++) ovr(deny[i], nt_deny);
    for (int i = 0; hook && i < NFNS; i++)                  /* the proxied host advapi32 */
        if (g_fns[i].fn && !strncmp(g_fns[i].name, "Reg", 3)) hook(g_fns[i].name, g_fns[i].fn);
    for (int i = 0; hook && i < (int)(sizeof g_ids / sizeof g_ids[0]); i++) hook(g_ids[i].name, g_ids[i].fn);
}

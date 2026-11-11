/*
 * reg32.c - a registry of the guest's own, per instance.
 *
 * native32_registry_sandbox(name) redirects the guest's Reg*A imports so that
 * HKEY_LOCAL_MACHINE and HKEY_CURRENT_USER are, for the guest only,
 *
 *     HKCU\Software\pcrecomp\sandbox\<name>\HKLM   and   ...\<name>\HKCU
 *
 * Keys it creates and values it writes land there. A key it only opens, and
 * that the sandbox does not have yet, is opened read-only in the real
 * registry (KEY_READ), so the guest still sees what Windows set up (shell
 * folders, Internet settings). Nothing outside the guest is affected: Windows'
 * own code in the process (Winsock providers, COM, the shell) reads the real
 * registry, which RegOverridePredefKey would not leave alone.
 *
 * What it is for: two instances of one program side by side (two clients of
 * a network test, each its own user), a program that writes HKLM without
 * admin rights, and a test run that leaves the real registry as it was.
 * Delete the key to start from a clean install. Call before native32_bind.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "native32.h"

static HKEY g_lm, g_cu;

static HKEY box(HKEY k) {
    return k == HKEY_LOCAL_MACHINE ? g_lm : k == HKEY_CURRENT_USER ? g_cu : k;
}

#define WRITE_BITS (KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK | DELETE | WRITE_DAC | WRITE_OWNER)

static LONG WINAPI g_RegOpenKeyExA(HKEY k, LPCSTR sub, DWORD opt, REGSAM sam, PHKEY out) {
    LONG r = RegOpenKeyExA(box(k), sub, opt, sam, out);
    if (r == ERROR_FILE_NOT_FOUND && box(k) != k)          /* not in the sandbox: the real one, read-only */
        r = RegOpenKeyExA(k, sub, opt, (sam & ~WRITE_BITS) | KEY_READ, out);
    return r;
}
static LONG WINAPI g_RegOpenKeyA(HKEY k, LPCSTR sub, PHKEY out) {
    return g_RegOpenKeyExA(k, sub, 0, MAXIMUM_ALLOWED, out);
}
static LONG WINAPI g_RegCreateKeyExA(HKEY k, LPCSTR sub, DWORD res, LPSTR cls, DWORD opt, REGSAM sam,
                                     LPSECURITY_ATTRIBUTES sa, PHKEY out, LPDWORD disp) {
    return RegCreateKeyExA(box(k), sub, res, cls, opt, sam, sa, out, disp);
}
static LONG WINAPI g_RegCreateKeyA(HKEY k, LPCSTR sub, PHKEY out) { return RegCreateKeyA(box(k), sub, out); }
static LONG WINAPI g_RegDeleteKeyA(HKEY k, LPCSTR sub) { return RegDeleteKeyA(box(k), sub); }
static LONG WINAPI g_RegDeleteValueA(HKEY k, LPCSTR v) { return RegDeleteValueA(box(k), v); }
static LONG WINAPI g_RegSetValueExA(HKEY k, LPCSTR v, DWORD r, DWORD t, const BYTE* d, DWORD n) {
    return RegSetValueExA(box(k), v, r, t, d, n);
}
static LONG WINAPI g_RegQueryValueExA(HKEY k, LPCSTR v, LPDWORD r, LPDWORD t, LPBYTE d, LPDWORD n) {
    return RegQueryValueExA(box(k), v, r, t, d, n);
}

int native32_registry_sandbox(const char* name) {
    char path[512];
    _snprintf(path, sizeof path - 1, "Software\\pcrecomp\\sandbox\\%s\\HKLM", name);
    path[sizeof path - 1] = 0;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, path, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &g_lm, NULL)) return 0;
    strcpy(path + strlen(path) - 4, "HKCU");
    if (RegCreateKeyExA(HKEY_CURRENT_USER, path, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &g_cu, NULL)) return 0;
    native32_redirect("RegOpenKeyExA", (void*)g_RegOpenKeyExA);
    native32_redirect("RegOpenKeyA", (void*)g_RegOpenKeyA);
    native32_redirect("RegCreateKeyExA", (void*)g_RegCreateKeyExA);
    native32_redirect("RegCreateKeyA", (void*)g_RegCreateKeyA);
    native32_redirect("RegDeleteKeyA", (void*)g_RegDeleteKeyA);
    native32_redirect("RegDeleteValueA", (void*)g_RegDeleteValueA);
    native32_redirect("RegSetValueExA", (void*)g_RegSetValueExA);
    native32_redirect("RegQueryValueExA", (void*)g_RegQueryValueExA);
    return 1;
}

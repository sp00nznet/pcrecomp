/*
 * modules32: the Windows loader's part for a program made of several lifted
 * modules (an EXE and its DLLs), on native32.
 *
 * Every multi-module host had its own copy of this (gunman, ut99, kf, tw,
 * shogo, ...): map each rebased module at its fixed base, bind them all with
 * one shim array, run each DLL's DllMain once, after the guest modules it
 * imports, and answer LoadLibrary / GetProcAddress / GetModuleHandle /
 * GetModuleFileName for guest modules from the table instead of loading the
 * original binaries. Sambar Server, the first application recomp with
 * plug-in DLLs, made it shared.
 *
 *   static native32_module_t mods[] = { {"server.exe", 0x00400000}, {"core.dll", 0x10400000} };
 *   native32_modules_map("work\\rebased", "C:\\app\\bin", mods, 2);
 *   native32_modules_bind(host_shims, n);     // host shims win over the loader's
 *   native32_attach_imports(0x00400000);      // DllMains the EXE's imports need
 *   native32_call_guest(entry, 0, NULL);
 *
 * A DLL that is not in the table loads natively, as before. DLL_THREAD_ATTACH
 * and DLL_PROCESS_DETACH are not sent. ponytail: add them when a guest DLL
 * keeps per-thread state in DllMain or flushes in DETACH.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "native32.h"

#define ARG(n) MEM32(g_esp + 4 + 4 * (n))

static native32_module_t* g_m;
static int g_n;
static char g_dir[MAX_PATH];     /* what GetModuleFileName reports */
static uint32_t g_exe;           /* GetModuleHandle(NULL) */

/* "core", "core.dll", "C:\x\core.dll", "../x/CORE.DLL": the file part, with
 * or without its extension, any case, like the loader. */
native32_module_t* native32_module_by_name(const char* path) {
    const char* p = path;
    for (const char* s = path; *s; s++)
        if (*s == '\\' || *s == '/' || *s == ':') p = s + 1;
    size_t n = strlen(p);
    for (int i = 0; i < g_n; i++) {
        const char* m = g_m[i].name;
        const char* dot = strrchr(m, '.');
        size_t k = dot ? (size_t)(dot - m) : strlen(m);
        if (!_stricmp(p, m) || (n == k && !_strnicmp(p, m, k))) return &g_m[i];
    }
    return NULL;
}

native32_module_t* native32_module_by_base(uint32_t base) {
    for (int i = 0; i < g_n; i++)
        if (g_m[i].base == base) return &g_m[i];
    return NULL;
}

static native32_module_t* by_name_w(const WCHAR* path) {
    char a[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, path, -1, a, sizeof a, NULL, NULL);
    return native32_module_by_name(a);
}

int native32_modules_map(const char* map_dir, const char* report_dir, native32_module_t* m, int n) {
    g_m = m;
    g_n = n;
    strncpy(g_dir, report_dir, MAX_PATH - 1);
    for (int i = 0; i < n; i++) {
        char path[MAX_PATH];
        _snprintf(path, MAX_PATH - 1, "%s\\%s", map_dir, m[i].name);
        path[MAX_PATH - 1] = 0;
        if (!native32_map(path, m[i].base)) {
            fprintf(stderr, "[load] %s: cannot map at 0x%08X\n", path, m[i].base);
            return 0;
        }
        uint8_t* b = (uint8_t*)(uintptr_t)m[i].base;
        IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(b + ((IMAGE_DOS_HEADER*)b)->e_lfanew);
        if (!(nt->FileHeader.Characteristics & IMAGE_FILE_DLL) && !g_exe) g_exe = m[i].base;
    }
    return 1;
}

int native32_attach(uint32_t base) {
    native32_module_t* m = native32_module_by_base(base);
    if (!m) return 0;
    if (m->attached) return 1;
    m->attached = 1;
    uint8_t* b = (uint8_t*)(uintptr_t)base;
    IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(b + ((IMAGE_DOS_HEADER*)b)->e_lfanew);
    if (!native32_attach_imports(base)) return 0;
    if (nt->FileHeader.Characteristics & IMAGE_FILE_DLL && nt->OptionalHeader.AddressOfEntryPoint) {
        uint32_t args[3] = { base, DLL_PROCESS_ATTACH, 0 };
        fprintf(stderr, "[load] %s: DllMain\n", m->name);
        native32_call_guest(base + nt->OptionalHeader.AddressOfEntryPoint, 3, args);
        if (!g_eax) {
            fprintf(stderr, "[load] %s: DllMain failed\n", m->name);
            return 0;
        }
    }
    return 1;
}

int native32_attach_imports(uint32_t base) {
    uint8_t* b = (uint8_t*)(uintptr_t)base;
    IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(b + ((IMAGE_DOS_HEADER*)b)->e_lfanew);
    IMAGE_DATA_DIRECTORY dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    for (IMAGE_IMPORT_DESCRIPTOR* d = (IMAGE_IMPORT_DESCRIPTOR*)(b + dd.VirtualAddress);
         dd.VirtualAddress && d->Name; d++) {
        native32_module_t* dep = native32_module_by_name((const char*)(b + d->Name));
        if (dep && !native32_attach(dep->base)) return 0;
    }
    return 1;
}

/* ---- the loader's shims: stdcall, inside the lifted model --------------- */

static uint32_t load(native32_module_t* m, uint32_t native) {
    if (!m) return native;
    return native32_attach(m->base) ? m->base : 0;
}
/* A DLL that is not a guest module loads natively, but searched for the way
 * Windows would for the guest: its own folder first (the one GetModuleFileName
 * reports), not the host's. Windows looks in the folder of the process's EXE,
 * which here is the host's build folder. Napster's file-type plug-ins
 * (LoadLibrary("VMP3.NVM"), next to napster.exe) were not found, and every
 * file it was asked to share was rejected. */
static HMODULE load_native(const char* nm, DWORD flags) {
    if (!strpbrk(nm, "\\/:") && g_dir[0]) {
        char path[MAX_PATH];
        _snprintf(path, MAX_PATH - 1, "%s\\%s", g_dir, nm);
        path[MAX_PATH - 1] = 0;
        if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) {
            HMODULE h = LoadLibraryExA(path, NULL, flags | LOAD_WITH_ALTERED_SEARCH_PATH);
            if (h) return h;
        }
    }
    HMODULE h = LoadLibraryExA(nm, NULL, flags);
    if (!h) fprintf(stderr, "[load] %s: not found (error %lu)\n", nm, GetLastError());
    else if (native32_trace_native) fprintf(stderr, "[load] %s: native\n", nm);
    return h;
}
static void shim_LoadLibraryA(void) {
    const char* nm = (const char*)(uintptr_t)ARG(0);
    native32_module_t* m = native32_module_by_name(nm);
    g_eax = m ? load(m, 0) : (uint32_t)(uintptr_t)load_native(nm, 0);
    g_esp += 8;
}
static void shim_LoadLibraryW(void) {
    const WCHAR* nm = (const WCHAR*)(uintptr_t)ARG(0);
    native32_module_t* m = by_name_w(nm);
    char a[MAX_PATH];
    if (!m && WideCharToMultiByte(CP_ACP, 0, nm, -1, a, sizeof a, NULL, NULL))
        g_eax = (uint32_t)(uintptr_t)load_native(a, 0);
    else
        g_eax = m ? load(m, 0) : (uint32_t)(uintptr_t)LoadLibraryW(nm);
    g_esp += 8;
}
static void shim_LoadLibraryExA(void) {
    const char* nm = (const char*)(uintptr_t)ARG(0);
    native32_module_t* m = native32_module_by_name(nm);
    g_eax = m ? load(m, 0) : (uint32_t)(uintptr_t)load_native(nm, ARG(2));
    g_esp += 16;
}
static void shim_FreeLibrary(void) {
    g_eax = native32_module_by_base(ARG(0)) ? TRUE : FreeLibrary((HMODULE)(uintptr_t)ARG(0));
    g_esp += 8;
}
static void shim_GetProcAddress(void) {
    uint32_t h = ARG(0);
    const char* nm = (const char*)(uintptr_t)ARG(1);
    g_eax = native32_module_by_base(h) ? native32_export(h, nm)
                                       : (uint32_t)(uintptr_t)GetProcAddress((HMODULE)(uintptr_t)h, nm);
    if (!g_eax) SetLastError(ERROR_PROC_NOT_FOUND);
    g_esp += 12;
}
static void shim_GetModuleHandleA(void) {
    const char* nm = (const char*)(uintptr_t)ARG(0);
    native32_module_t* m = nm ? native32_module_by_name(nm) : NULL;
    g_eax = !nm ? g_exe : m ? m->base : (uint32_t)(uintptr_t)GetModuleHandleA(nm);
    g_esp += 8;
}
static void shim_GetModuleHandleW(void) {
    const WCHAR* nm = (const WCHAR*)(uintptr_t)ARG(0);
    native32_module_t* m = nm ? by_name_w(nm) : NULL;
    g_eax = !nm ? g_exe : m ? m->base : (uint32_t)(uintptr_t)GetModuleHandleW(nm);
    g_esp += 8;
}
/* report_dir\<name>: programs find their config and data from here. Same
 * truncation rule as Windows: size-1 characters, NUL, returns size. */
static int guest_path(uint32_t h, char* out) {
    native32_module_t* m = native32_module_by_base(h ? h : g_exe);
    if (!m) return 0;
    _snprintf(out, MAX_PATH - 1, "%s\\%s", g_dir, m->name);
    out[MAX_PATH - 1] = 0;
    return 1;
}
static void shim_GetModuleFileNameA(void) {
    char path[MAX_PATH];
    char* out = (char*)(uintptr_t)ARG(1);
    uint32_t size = ARG(2);
    if (guest_path(ARG(0), path)) {
        uint32_t len = (uint32_t)strlen(path);
        if (size) {
            uint32_t k = len < size ? len : size - 1;
            memcpy(out, path, k);
            out[k] = 0;
            g_eax = len < size ? len : size;
        } else g_eax = 0;
    } else g_eax = GetModuleFileNameA((HMODULE)(uintptr_t)ARG(0), out, size);
    g_esp += 16;
}
static void shim_GetModuleFileNameW(void) {
    char path[MAX_PATH];
    WCHAR* out = (WCHAR*)(uintptr_t)ARG(1);
    uint32_t size = ARG(2);
    if (guest_path(ARG(0), path)) {
        WCHAR w[MAX_PATH];
        uint32_t len = (uint32_t)MultiByteToWideChar(CP_ACP, 0, path, -1, w, MAX_PATH) - 1;
        if (size) {
            uint32_t k = len < size ? len : size - 1;
            memcpy(out, w, k * sizeof(WCHAR));
            out[k] = 0;
            g_eax = len < size ? len : size;
        } else g_eax = 0;
    } else g_eax = GetModuleFileNameW((HMODULE)(uintptr_t)ARG(0), out, size);
    g_esp += 16;
}

static const native32_shim_t g_loader[] = {
    { "LoadLibraryA", shim_LoadLibraryA },     { "LoadLibraryW", shim_LoadLibraryW },
    { "LoadLibraryExA", shim_LoadLibraryExA }, { "FreeLibrary", shim_FreeLibrary },
    { "GetProcAddress", shim_GetProcAddress },
    { "GetModuleHandleA", shim_GetModuleHandleA }, { "GetModuleHandleW", shim_GetModuleHandleW },
    { "GetModuleFileNameA", shim_GetModuleFileNameA }, { "GetModuleFileNameW", shim_GetModuleFileNameW },
};
#define NLOADER ((int)(sizeof g_loader / sizeof g_loader[0]))

int native32_modules_bind(const native32_shim_t* host, int nhost) {
    /* One array for every module (native32_bind's rule): host shims first,
     * so a host can still override one of the loader's. */
    static native32_shim_t* all;
    int n = 0, missing = 0;
    all = (native32_shim_t*)calloc(nhost + NLOADER, sizeof *all);
    for (int i = 0; i < nhost; i++) all[n++] = host[i];
    for (int i = 0; i < NLOADER; i++) {
        int dup = 0;
        for (int k = 0; k < nhost; k++) dup |= !strcmp(host[k].name, g_loader[i].name);
        if (!dup) all[n++] = g_loader[i];
    }
    for (int i = 0; i < g_n; i++) missing += native32_bind(g_m[i].base, all, n);
    return missing;
}

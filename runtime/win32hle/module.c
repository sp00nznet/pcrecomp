/*
 * module.c - modules and their resources: LoadLibraryA, GetModuleHandleA,
 * GetModuleFileNameA, GetProcAddress, FindResourceA and friends, LoadStringA,
 * and the current directory.
 *
 * Three kinds of module:
 *   - the main image, mapped by the host at its base (hle_module_add);
 *   - a DLL file the guest loads, mapped wherever there is room and
 *     relocated (resource DLLs: its code, if any, is not lifted and is never
 *     run);
 *   - a system DLL (kernel32, ddraw, ...), which has no image: its handle is a
 *     pseudo-module whose GetProcAddress answers from the shim registry.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include "win32hle.h"
#include "pe_loader.h"

#define ERROR_MOD_NOT_FOUND       126u
#define ERROR_PROC_NOT_FOUND      127u
#define ERROR_RESOURCE_NOT_FOUND 1814u

#define MAX_MODULES 32
static struct {
    char     guest[260];          /* full guest path, C:\...\name.dll */
    char     base_name[64];       /* lower case, for matching */
    uint32_t base, rsrc, rsrc_size;
    int      system, refs;
} g_mod[MAX_MODULES];
static int g_nmod;
static int g_main = -1;

static const char *const g_system[] = {
    "kernel32", "user32", "gdi32", "advapi32", "shell32", "ole32", "oleaut32", "winmm",
    "wsock32", "ws2_32", "ddraw", "dsound", "dinput", "version", "comctl32", "comdlg32",
    "ntdll", "msvcrt", "imm32", "mpr", "rpcrt4", "uuid", "dplayx", "d3dim",
};

static void base_of(const char *path, char *out, size_t n) {
    const char *b = path + strlen(path);
    while (b > path && b[-1] != '\\' && b[-1] != '/' && b[-1] != ':') b--;
    size_t k = 0;
    for (; b[k] && k + 1 < n; k++) out[k] = (char)(b[k] >= 'A' && b[k] <= 'Z' ? b[k] + 32 : b[k]);
    out[k] = 0;
    if (!strchr(out, '.') && k + 4 < n) strcat(out, ".dll");
}

static int find_mod(uint32_t h) {
    if (!h && g_main >= 0) return g_main;
    for (int i = 0; i < g_nmod; i++) if (g_mod[i].base == h) return i;
    return -1;
}
static int find_by_name(const char *name) {
    char b[64];
    base_of(name, b, sizeof b);
    for (int i = 0; i < g_nmod; i++) if (!strcmp(g_mod[i].base_name, b)) return i;
    return -1;
}

int hle_module_add(const char *guest_path, uint32_t base, uint32_t rsrc_rva, uint32_t rsrc_size, int main_image) {
    if (g_nmod >= MAX_MODULES) return -1;
    int i = g_nmod++;
    snprintf(g_mod[i].guest, sizeof g_mod[i].guest, "%s", guest_path);
    base_of(guest_path, g_mod[i].base_name, sizeof g_mod[i].base_name);
    g_mod[i].base = base, g_mod[i].rsrc = rsrc_rva, g_mod[i].rsrc_size = rsrc_size, g_mod[i].refs = 1;
    if (main_image) g_main = i;
    return i;
}

/* Older hosts set only the main image's path. */
void hle_set_module_path(const char *real) {
    char g[260];
    hle_guest_path(real, g, sizeof g);
    if (g_main >= 0) snprintf(g_mod[g_main].guest, sizeof g_mod[g_main].guest, "%s", g);
    else hle_module_add(g, 0x00400000u, 0, 0, 1);
}

static uint32_t system_module(const char *name) {
    char b[64];
    base_of(name, b, sizeof b);
    char *dot = strrchr(b, '.');
    if (dot && strcmp(dot, ".dll")) return 0;
    if (dot) *dot = 0;
    for (size_t k = 0; k < sizeof g_system / sizeof *g_system; k++)
        if (!strcmp(b, g_system[k])) {
            int i = find_by_name(name);
            if (i < 0) {
                i = hle_module_add(name, 0x7E000000u + 0x10000u * (uint32_t)k, 0, 0, 0);
                if (i < 0) return 0;
                g_mod[i].system = 1;
            }
            return g_mod[i].base;
        }
    return 0;
}

static void k_GetModuleHandleA(void) {
    const char *name = ASTR(0);
    if (!name) RET(g_main >= 0 ? g_mod[g_main].base : 0x00400000u, 1);
    int i = find_by_name(name);
    if (i >= 0) RET(g_mod[i].base, 1);
    uint32_t s = system_module(name);
    if (!s) hle_set_last_error(ERROR_MOD_NOT_FOUND);
    RET(s, 1);
}

static void k_GetModuleFileNameA(void) {                 /* (hModule, buf, size) */
    int i = find_mod(A32(0));
    char *buf = ASTR(1);
    uint32_t size = A32(2);
    char sys[300];
    const char *p = i < 0 ? NULL : g_mod[i].system ? (snprintf(sys, sizeof sys, "C:\\WINDOWS\\SYSTEM32\\%s", g_mod[i].base_name), sys)
                                                   : g_mod[i].guest;
    if (!p) { hle_set_last_error(ERROR_MOD_NOT_FOUND); RET(0, 3); }
    uint32_t n = (uint32_t)strlen(p);
    if (!buf || !size) RET(0, 3);
    if (n >= size) n = size - 1;
    memcpy(buf, p, n), buf[n] = 0;
    RET(n, 3);
}

static void k_LoadLibraryA(void) {
    const char *name = ASTR(0);
    if (!name) { hle_set_last_error(ERROR_MOD_NOT_FOUND); RET(0, 1); }
    int i = find_by_name(name);
    if (i >= 0) { g_mod[i].refs++; RET(g_mod[i].base, 1); }
    uint32_t s = system_module(name);
    if (s) RET(s, 1);
    char host[1024];
    int found = hle_host_path(name, host, sizeof host);
    if (!found && g_main >= 0) {                         /* the exe's own directory */
        char g[600];
        const char *bs = strrchr(g_mod[g_main].guest, '\\');
        snprintf(g, sizeof g, "%.*s\\%s", bs ? (int)(bs - g_mod[g_main].guest) : 0, g_mod[g_main].guest, name);
        found = hle_host_path(g, host, sizeof host);
    }
    pe_image img;
    if (!found || recomp_pe_map_any(host, &img) != 0) {
        fprintf(stderr, "[module] LoadLibraryA(\"%s\"): not found\n", name);
        hle_set_last_error(ERROR_MOD_NOT_FOUND);
        RET(0, 1);
    }
    char g[600];
    hle_guest_path(host, g, sizeof g);
    hle_module_add(g, img.base, img.resource_rva, img.resource_size, 0);
    fprintf(stderr, "[module] LoadLibraryA(\"%s\") -> 0x%08X (its code is not run)\n", name, img.base);
    RET(img.base, 1);
}
static void k_FreeLibrary(void) { int i = find_mod(A32(0)); if (i >= 0 && g_mod[i].refs > 1) g_mod[i].refs--; RET(1, 1); }

static void k_GetProcAddress(void) {                     /* (hModule, name or ordinal) */
    int i = find_mod(A32(0));
    uint32_t n = A32(1), va = 0;
    if (i >= 0 && g_mod[i].system) {
        if (n < 0x10000u) {
            char nm[96];
            snprintf(nm, sizeof nm, "%s#%u", g_mod[i].base_name, n);
            va = hle_resolve(nm);
        } else {
            va = hle_resolve((const char *)(uintptr_t)n);
        }
    }
    if (!va) {
        fprintf(stderr, "[module] GetProcAddress(%s, %s%s): not answered\n", i >= 0 ? g_mod[i].base_name : "?",
                n < 0x10000u ? "#" : "", n < 0x10000u ? "" : (const char *)(uintptr_t)n);
        hle_set_last_error(ERROR_PROC_NOT_FOUND);
    }
    RET(va, 2);
}

/* ---- resources ----
 * The resource directory is a three-level tree (type, name, language) of
 * IMAGE_RESOURCE_DIRECTORY {.., u16 named, u16 ids} + {u32 name, u32 off}
 * entries; an offset with the top bit set is a subdirectory, else an
 * IMAGE_RESOURCE_DATA_ENTRY {rva, size, codepage, 0}. An HRSRC is the data
 * entry's address. */
static int name_matches(uint32_t root, uint32_t entry_name, uint32_t want) {
    if (want < 0x10000u) return !(entry_name & 0x80000000u) && entry_name == want;
    const char *w = (const char *)(uintptr_t)want;
    if (w[0] == '#') return !(entry_name & 0x80000000u) && entry_name == (uint32_t)atoi(w + 1);
    if (!(entry_name & 0x80000000u)) return 0;
    uint32_t s = root + (entry_name & 0x7FFFFFFFu);
    uint16_t len = MEM16(s);
    if (strlen(w) != len) return 0;
    for (uint16_t k = 0; k < len; k++) {
        uint16_t c = MEM16(s + 2 + 2u * k);
        if ((c < 128 ? (c | 0x20) : c) != (uint16_t)((uint8_t)w[k] | 0x20)) return 0;
    }
    return 1;
}
/* Find `want` in the directory at dir; 0 for any (the first). Returns the
 * entry's offset word. */
static uint32_t dir_lookup(uint32_t root, uint32_t dir, uint32_t want, int any) {
    uint32_t n = (uint32_t)MEM16(dir + 12) + MEM16(dir + 14);
    for (uint32_t k = 0; k < n; k++) {
        uint32_t e = dir + 16 + 8 * k;
        if (any || name_matches(root, MEM32(e), want)) return MEM32(e + 4);
    }
    return 0xFFFFFFFFu;
}
static uint32_t find_resource(int m, uint32_t name, uint32_t type) {
    if (m < 0 || !g_mod[m].rsrc) return 0;
    uint32_t root = g_mod[m].base + g_mod[m].rsrc;
    uint32_t t = dir_lookup(root, root, type, 0);
    if (t == 0xFFFFFFFFu || !(t & 0x80000000u)) return 0;
    uint32_t nm = dir_lookup(root, root + (t & 0x7FFFFFFFu), name, 0);
    if (nm == 0xFFFFFFFFu || !(nm & 0x80000000u)) return 0;
    uint32_t lang = dir_lookup(root, root + (nm & 0x7FFFFFFFu), 0, 1);
    if (lang == 0xFFFFFFFFu || (lang & 0x80000000u)) return 0;
    return root + lang;
}

uint32_t hle_find_resource(uint32_t hmod, uint32_t name, uint32_t type) {
    return find_resource(find_mod(hmod), name, type);
}
uint32_t hle_resource_data(uint32_t hmod, uint32_t hrsrc, uint32_t *size) {
    int m = find_mod(hmod);
    if (!hrsrc) return 0;
    if (m < 0) {                                          /* a NULL/odd module: find the owner */
        for (int i = 0; i < g_nmod && m < 0; i++)
            if (g_mod[i].rsrc && hrsrc >= g_mod[i].base + g_mod[i].rsrc && hrsrc < g_mod[i].base + g_mod[i].rsrc + g_mod[i].rsrc_size) m = i;
        if (m < 0) return 0;
    }
    if (size) *size = MEM32(hrsrc + 4);
    return g_mod[m].base + MEM32(hrsrc);
}

/* The last dialog template looked up, so a dialog made from its bytes
 * (CreateDialogIndirectParamA) can still be named by its resource ID. A game
 * may copy the template first (to edit its styles), so this is the last one
 * found, not one at the template's address. */
static uint32_t g_last_dialog_id, g_last_dialog_rsrc;
uint32_t hle_dialog_resource_id(uint32_t tmpl) {
    (void)tmpl;
    return g_last_dialog_rsrc ? g_last_dialog_id : 0;
}
static void k_FindResourceA(void) {                      /* (hModule, name, type) */
    uint32_t r = hle_find_resource(A32(0), A32(1), A32(2));
    if (r && A32(2) == 5 && A32(1) < 0x10000u) g_last_dialog_id = A32(1), g_last_dialog_rsrc = r;
    if (!r) hle_set_last_error(ERROR_RESOURCE_NOT_FOUND);
    RET(r, 3);
}
static void k_LoadResource(void)   { RET(hle_resource_data(A32(0), A32(1), NULL), 2); }
static void k_LockResource(void)   { RET(A32(0), 1); }
static void k_FreeResource(void)   { RET(0, 1); }
static void k_SizeofResource(void) { uint32_t n = 0; hle_resource_data(A32(0), A32(1), &n); RET(n, 2); }

/* LoadStringA(hInstance, id, buf, n): string tables are blocks of 16 counted
 * UTF-16 strings, block id/16 + 1. */
int hle_load_string(uint32_t hmod, uint32_t id, char *buf, int n) {
    uint32_t r = hle_find_resource(hmod, id / 16 + 1, 6);
    uint32_t size = 0, p = r ? hle_resource_data(hmod, r, &size) : 0;
    if (!p || !buf || n <= 0) { if (buf && n > 0) buf[0] = 0; return 0; }
    for (uint32_t k = 0; k < id % 16; k++) p += 2 + 2u * MEM16(p);
    int len = MEM16(p), k = 0;
    for (; k < len && k < n - 1; k++) {
        uint16_t c = MEM16(p + 2 + 2u * (uint32_t)k);
        buf[k] = (char)(c < 256 ? c : '?');
    }
    buf[k] = 0;
    return k;
}
static void k_LoadStringA(void) { RET((uint32_t)hle_load_string(A32(0), A32(1), ASTR(2), (int)A32(3)), 4); }

/* ---- the current directory, as the guest sees it ---- */
static void k_GetCurrentDirectoryA(void) {               /* (size, buf) */
    char cwd[1024], g[1024];
    if (!getcwd(cwd, sizeof cwd)) cwd[0] = 0;
    hle_guest_path(cwd, g, sizeof g);
    uint32_t n = (uint32_t)strlen(g), size = A32(0);
    char *buf = ASTR(1);
    if (!buf || n + 1 > size) RET(n + 1, 2);
    memcpy(buf, g, n + 1);
    RET(n, 2);
}
static void k_SetCurrentDirectoryA(void) {
    char host[1024];
    if (hle_host_path(ASTR(0), host, sizeof host) && chdir(host) == 0) RET(1, 1);
    hle_set_last_error(3u);                               /* ERROR_PATH_NOT_FOUND */
    RET(0, 1);
}

const win32hle_shim win32hle_module[] = {
    { "GetModuleHandleA",     k_GetModuleHandleA },
    { "GetModuleFileNameA",   k_GetModuleFileNameA },
    { "LoadLibraryA",         k_LoadLibraryA },
    { "FreeLibrary",          k_FreeLibrary },
    { "GetProcAddress",       k_GetProcAddress },
    { "FindResourceA",        k_FindResourceA },
    { "LoadResource",         k_LoadResource },
    { "LockResource",         k_LockResource },
    { "FreeResource",         k_FreeResource },
    { "SizeofResource",       k_SizeofResource },
    { "LoadStringA",          k_LoadStringA },
    { "GetCurrentDirectoryA", k_GetCurrentDirectoryA },
    { "SetCurrentDirectoryA", k_SetCurrentDirectoryA },
    { 0, 0 }
};

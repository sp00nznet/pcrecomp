/*
 * advapi32.c - the registry, and the small system DLLs a game links for one
 * or two calls each: COMCTL32 (its version and InitCommonControls),
 * VERSION (file version resources) and SHELL32.
 *
 * The registry is in memory: a tree of keys, each with named values. A host
 * seeds what the game expects an installer to have written
 * (hle_reg_set_string/_dword), and may give it a file to persist to
 * (hle_reg_load/hle_reg_save: one "key\name=type:value" per line).
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "win32hle.h"

#define ERROR_SUCCESS        0u
#define ERROR_FILE_NOT_FOUND 2u
#define ERROR_MORE_DATA    234u
#define ERROR_NO_MORE_ITEMS 259u
#define REG_SZ     1u
#define REG_BINARY 3u
#define REG_DWORD  4u

typedef struct value { char name[128]; uint32_t type, size; uint8_t *data; struct value *next; } value_t;
typedef struct key { char name[128]; struct key *parent, *child, *next; value_t *values; } rkey_t;
static rkey_t g_roots[6];                         /* HKCR HKCU HKLM HKU HKPD HKCC */
static const char *const g_root_names[6] = { "HKEY_CLASSES_ROOT", "HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE",
                                             "HKEY_USERS", "HKEY_PERFORMANCE_DATA", "HKEY_CURRENT_CONFIG" };
static const char *g_reg_file;

static rkey_t *root_of(uint32_t h) {
    if (h >= 0x80000000u && h <= 0x80000005u) return &g_roots[h - 0x80000000u];
    return (rkey_t *)hle_handle_obj(h, HLE_H_REGKEY);
}
static rkey_t *subkey(rkey_t *k, const char *path, int create) {
    char part[128];
    while (k && path && *path) {
        size_t n = strcspn(path, "\\");
        if (n >= sizeof part) n = sizeof part - 1;
        memcpy(part, path, n), part[n] = 0;
        path += n;
        while (*path == '\\') path++;
        if (!part[0]) continue;
        rkey_t *c = k->child;
        while (c && strcasecmp(c->name, part)) c = c->next;
        if (!c && create) {
            c = (rkey_t *)calloc(1, sizeof *c);
            snprintf(c->name, sizeof c->name, "%s", part);
            c->parent = k, c->next = k->child, k->child = c;
        }
        k = c;
    }
    return k;
}
static value_t *find_value(rkey_t *k, const char *name, int create) {
    value_t *v = k->values;
    if (!name) name = "";
    while (v && strcasecmp(v->name, name)) v = v->next;
    if (!v && create) {
        v = (value_t *)calloc(1, sizeof *v);
        snprintf(v->name, sizeof v->name, "%s", name);
        v->next = k->values, k->values = v;
    }
    return v;
}
static void set_value(rkey_t *k, const char *name, uint32_t type, const void *data, uint32_t size) {
    value_t *v = find_value(k, name, 1);
    free(v->data);
    v->data = (uint8_t *)malloc(size + 2);
    memcpy(v->data, data, size);
    v->data[size] = v->data[size + 1] = 0;
    v->type = type, v->size = size;
}

static int root_index(const char *name) {
    for (int i = 0; i < 6; i++) if (!strcasecmp(name, g_root_names[i])) return i;
    if (!strcasecmp(name, "HKLM")) return 2;
    if (!strcasecmp(name, "HKCU")) return 1;
    return -1;
}
void hle_reg_set_string(uint32_t root, const char *path, const char *name, const char *s) {
    set_value(subkey(root_of(root), path, 1), name, REG_SZ, s, (uint32_t)strlen(s) + 1);
}
void hle_reg_set_dword(uint32_t root, const char *path, const char *name, uint32_t v) {
    set_value(subkey(root_of(root), path, 1), name, REG_DWORD, &v, 4);
}

/* the file: HKEY_LOCAL_MACHINE\SOFTWARE\x\name=sz:text | dword:0x1 | hex:0a0b */
void hle_reg_load(const char *file) {
    FILE *f = fopen(file, "r");
    char line[2048];
    g_reg_file = file;
    while (f && fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = 0;
        char *eq = strchr(line, '='), *colon = eq ? strchr(eq, ':') : NULL;
        if (!eq || !colon) continue;
        *eq = 0, *colon = 0;
        char *bs = strchr(line, '\\'), *name = strrchr(line, '\\');
        if (!bs || !name) continue;
        *bs = 0, *name++ = 0;
        int r = root_index(line);
        if (r < 0) continue;
        rkey_t *k = subkey(&g_roots[r], name == bs + 1 ? "" : bs + 1, 1);
        if (!strcmp(eq + 1, "sz")) set_value(k, name, REG_SZ, colon + 1, (uint32_t)strlen(colon + 1) + 1);
        else if (!strcmp(eq + 1, "dword")) { uint32_t v = (uint32_t)strtoul(colon + 1, NULL, 0); set_value(k, name, REG_DWORD, &v, 4); }
        else {
            uint8_t buf[1024];
            uint32_t n = 0;
            for (const char *p = colon + 1; p[0] && p[1] && n < sizeof buf; p += 2) { unsigned b; sscanf(p, "%2x", &b); buf[n++] = (uint8_t)b; }
            set_value(k, name, REG_BINARY, buf, n);
        }
    }
    if (f) fclose(f);
}
static void save_key(FILE *f, rkey_t *k, const char *path) {
    for (value_t *v = k->values; v; v = v->next) {
        fprintf(f, "%s\\%s=", path, v->name);
        if (v->type == REG_SZ) fprintf(f, "sz:%s\n", (const char *)v->data);
        else if (v->type == REG_DWORD && v->size == 4) fprintf(f, "dword:0x%X\n", *(uint32_t *)v->data);
        else { fprintf(f, "hex:"); for (uint32_t i = 0; i < v->size; i++) fprintf(f, "%02x", v->data[i]); fprintf(f, "\n"); }
    }
    for (rkey_t *c = k->child; c; c = c->next) {
        char p[1024];
        snprintf(p, sizeof p, "%s\\%s", path, c->name);
        save_key(f, c, p);
    }
}
static void reg_save(void) {
    if (!g_reg_file) return;
    FILE *f = fopen(g_reg_file, "w");
    if (!f) return;
    for (int i = 0; i < 6; i++) save_key(f, &g_roots[i], g_root_names[i]);
    fclose(f);
}

static uint32_t open_key(uint32_t parent, const char *path, uint32_t out, int create) {
    rkey_t *p = root_of(parent);
    if (!p) return 6u;                                   /* ERROR_INVALID_HANDLE */
    rkey_t *k = subkey(p, path, create);
    if (!k) { if (out) MEM32(out) = 0; return ERROR_FILE_NOT_FOUND; }
    if (out) MEM32(out) = hle_handle_alloc(HLE_H_REGKEY, k);
    return ERROR_SUCCESS;
}
static void r_RegOpenKeyExA(void)   { RET(open_key(A32(0), ASTR(1), A32(4), 0), 5); }   /* (key, sub, opts, sam, &out) */
static void r_RegOpenKeyA(void)     { RET(open_key(A32(0), ASTR(1), A32(2), 0), 3); }
static void r_RegCreateKeyA(void)   { RET(open_key(A32(0), ASTR(1), A32(2), 1), 3); }
static void r_RegCreateKeyExA(void) {                    /* (key, sub, 0, class, opts, sam, sa, &out, &disp) */
    rkey_t *p = root_of(A32(0));
    int existed = p && subkey(p, ASTR(1), 0) != NULL;
    uint32_t r = open_key(A32(0), ASTR(1), A32(7), 1);
    if (A32(8)) MEM32(A32(8)) = existed ? 2u : 1u;       /* REG_OPENED_EXISTING_KEY / CREATED_NEW_KEY */
    RET(r, 9);
}
static void r_RegCloseKey(void) { hle_handle_close(A32(0)); RET(ERROR_SUCCESS, 1); }
static void r_RegQueryValueExA(void) {                   /* (key, name, 0, &type, data, &size) */
    rkey_t *k = root_of(A32(0));
    value_t *v = k ? find_value(k, ASTR(1), 0) : NULL;
    if (!v) RET(ERROR_FILE_NOT_FOUND, 6);
    if (A32(3)) MEM32(A32(3)) = v->type;
    uint32_t have = A32(5) ? MEM32(A32(5)) : 0;
    if (A32(5)) MEM32(A32(5)) = v->size;
    if (!A32(4)) RET(ERROR_SUCCESS, 6);
    if (have < v->size) RET(ERROR_MORE_DATA, 6);
    memcpy(APTR(4), v->data, v->size);
    RET(ERROR_SUCCESS, 6);
}
static void r_RegSetValueExA(void) {                     /* (key, name, 0, type, data, size) */
    rkey_t *k = root_of(A32(0));
    if (!k) RET(6u, 6);
    set_value(k, ASTR(1), A32(3), APTR(4), A32(5));
    reg_save();
    RET(ERROR_SUCCESS, 6);
}
static void r_RegDeleteValueA(void) {
    rkey_t *k = root_of(A32(0));
    for (value_t **v = k ? &k->values : NULL; v && *v; v = &(*v)->next)
        if (!strcasecmp((*v)->name, ASTR(1) ? ASTR(1) : "")) { value_t *d = *v; *v = d->next; free(d->data); free(d); reg_save(); RET(0, 2); }
    RET(ERROR_FILE_NOT_FOUND, 2);
}
static void r_RegDeleteKeyA(void) {                      /* (key, sub): a key without subkeys */
    rkey_t *k = root_of(A32(0)), *d = k ? subkey(k, ASTR(1), 0) : NULL;
    if (!d || d->child || !d->parent) RET(ERROR_FILE_NOT_FOUND, 2);
    for (rkey_t **c = &d->parent->child; *c; c = &(*c)->next) if (*c == d) { *c = d->next; break; }
    reg_save();
    RET(ERROR_SUCCESS, 2);
}
static void r_RegEnumKeyExA(void) {                      /* (key, index, name, &nameN, 0, class, &classN, &time) */
    rkey_t *k = root_of(A32(0)), *c = k ? k->child : NULL;
    for (uint32_t i = 0; c && i < A32(1); i++) c = c->next;
    if (!c) RET(ERROR_NO_MORE_ITEMS, 8);
    uint32_t n = (uint32_t)strlen(c->name);
    if (MEM32(A32(3)) <= n) RET(ERROR_MORE_DATA, 8);
    memcpy(ASTR(2), c->name, n + 1);
    MEM32(A32(3)) = n;
    RET(ERROR_SUCCESS, 8);
}
static void r_RegEnumKeyA(void) {                        /* (key, index, name, n) */
    rkey_t *k = root_of(A32(0)), *c = k ? k->child : NULL;
    for (uint32_t i = 0; c && i < A32(1); i++) c = c->next;
    if (!c) RET(ERROR_NO_MORE_ITEMS, 4);
    snprintf(ASTR(2), A32(3), "%s", c->name);
    RET(ERROR_SUCCESS, 4);
}
static void r_RegQueryInfoKeyA(void) {                   /* (key, class, &classN, 0, &subkeys, &maxSub, &maxClass, &values, &maxName, &maxData, &sec, &time) */
    rkey_t *k = root_of(A32(0));
    if (!k) RET(6u, 12);
    uint32_t nsub = 0, maxsub = 0, nval = 0, maxname = 0, maxdata = 0;
    for (rkey_t *c = k->child; c; c = c->next) { nsub++; if (strlen(c->name) > maxsub) maxsub = (uint32_t)strlen(c->name); }
    for (value_t *v = k->values; v; v = v->next) { nval++; if (strlen(v->name) > maxname) maxname = (uint32_t)strlen(v->name); if (v->size > maxdata) maxdata = v->size; }
    if (A32(2)) MEM32(A32(2)) = 0;
    if (A32(4)) MEM32(A32(4)) = nsub;
    if (A32(5)) MEM32(A32(5)) = maxsub;
    if (A32(6)) MEM32(A32(6)) = 0;
    if (A32(7)) MEM32(A32(7)) = nval;
    if (A32(8)) MEM32(A32(8)) = maxname;
    if (A32(9)) MEM32(A32(9)) = maxdata;
    if (A32(10)) MEM32(A32(10)) = 0;
    if (A32(11)) MEM32(A32(11)) = 0, MEM32(A32(11) + 4) = 0;
    RET(ERROR_SUCCESS, 12);
}
static void r_GetUserNameA(void) { if (A32(1) && MEM32(A32(1)) > 6) { strcpy(ASTR(0), "player"); MEM32(A32(1)) = 7; RET(1, 2); } RET(0, 2); }

/* ---- COMCTL32 ---- */
static void c_InitCommonControls(void) { RETV(0); }
static void c_InitCommonControlsEx(void) { RET(1, 1); }
static void c_DllGetVersion(void) {                      /* (&DLLVERSIONINFO): cbSize, major, minor, build, platform */
    uint32_t d = A32(0);
    if (d) MEM32(d + 4) = 5, MEM32(d + 8) = 81, MEM32(d + 12) = 4704, MEM32(d + 16) = 1;
    RET(0, 1);
}
static void c_ret0_0(void) { RET(0, 0); }
static void c_ret0_1(void) { RET(0, 1); }
static void c_ret0_2(void) { RET(0, 2); }
static void c_ret0_3(void) { RET(0, 3); }
static void c_ret0_4(void) { RET(0, 4); }

/* ---- VERSION: no version resources here ---- */
static void v_GetFileVersionInfoSizeA(void) { if (A32(1)) MEM32(A32(1)) = 0; hle_set_last_error(1813u); RET(0, 2); }
static void v_GetFileVersionInfoA(void) { hle_set_last_error(1813u); RET(0, 4); }
static void v_VerQueryValueA(void) { if (A32(3)) MEM32(A32(3)) = 0; RET(0, 4); }

/* ---- SHELL32 ---- */
static void s_FindExecutableA(void) { if (A32(2)) MEM8(A32(2)) = 0; RET(31u, 3); }   /* SE_ERR_NOASSOC */
static void s_ShellExecuteA(void) { fprintf(stderr, "[shell32] ShellExecuteA(%s): not on this host\n", ASTR(2) ? ASTR(2) : ""); RET(31u, 6); }

const win32hle_shim win32hle_advapi32[] = {
    { "RegOpenKeyExA", r_RegOpenKeyExA }, { "RegOpenKeyA", r_RegOpenKeyA }, { "RegCreateKeyA", r_RegCreateKeyA },
    { "RegCreateKeyExA", r_RegCreateKeyExA }, { "RegCloseKey", r_RegCloseKey },
    { "RegQueryValueExA", r_RegQueryValueExA }, { "RegSetValueExA", r_RegSetValueExA },
    { "RegDeleteValueA", r_RegDeleteValueA }, { "RegDeleteKeyA", r_RegDeleteKeyA },
    { "RegEnumKeyExA", r_RegEnumKeyExA }, { "RegEnumKeyA", r_RegEnumKeyA }, { "RegQueryInfoKeyA", r_RegQueryInfoKeyA },
    { "GetUserNameA", r_GetUserNameA },
    { "comctl32.dll#17", c_InitCommonControls }, { "InitCommonControls", c_InitCommonControls },
    { "InitCommonControlsEx", c_InitCommonControlsEx }, { "DllGetVersion", c_DllGetVersion },
    { "ImageList_BeginDrag", c_ret0_4 }, { "ImageList_Destroy", c_ret0_1 }, { "ImageList_DragEnter", c_ret0_3 },
    { "ImageList_DragMove", c_ret0_2 }, { "ImageList_DragShowNolock", c_ret0_1 }, { "ImageList_EndDrag", c_ret0_0 },
    { "GetFileVersionInfoSizeA", v_GetFileVersionInfoSizeA }, { "GetFileVersionInfoA", v_GetFileVersionInfoA },
    { "VerQueryValueA", v_VerQueryValueA },
    { "FindExecutableA", s_FindExecutableA }, { "ShellExecuteA", s_ShellExecuteA },
    { 0, 0 }
};

/*
 * reg32.c - a private registry for the guest (native32_registry), included by
 * native32.c.
 *
 * A Win9x game reads its install path, language and settings from
 * HKLM\Software\<publisher>\<game>, which its installer wrote. A recompiled
 * game is never installed, and writing HKLM needs administrator rights (or
 * lands in the VirtualStore). So the subtrees a .reg file names are served
 * from that file instead: the guest's Reg*A calls on keys inside them read and
 * write an in-memory copy, saved back to the file on every change. Keys
 * outside those subtrees go to the real registry, unchanged.
 *
 * The file is a regedit 4 subset: [HKEY_LOCAL_MACHINE\Software\X] sections,
 * "name"="string", "name"=dword:0000000a and "name"=hex:01,02 lines (@ is the
 * default value). Every section names a private subtree, even an empty one.
 *
 * ponytail: no RegEnumKey/RegEnumValue, and the W functions go to the real
 * registry; add them when a game needs them.
 */
#pragma comment(lib, "advapi32.lib")

typedef struct { int key; char name[128]; DWORD type, size; uint8_t* data; } reg_value_t;
static char (*g_reg_keys)[MAX_PATH];     /* lower-case full paths: "hkey_local_machine\software\x" */
static int g_reg_nkeys;
static reg_value_t* g_reg_vals;
static int g_reg_nvals;
static char g_reg_file[MAX_PATH];
static char (*g_reg_roots)[MAX_PATH];    /* the private subtrees (the file's sections) */
static int g_reg_nroots;
#define REG_HANDLE0 0x7E000000u           /* a private key's handle: REG_HANDLE0 + key index */
static CRITICAL_SECTION g_reg_lock;

static const char* reg_root_name(uint32_t h) {
    switch (h) {
    case 0x80000000u: return "hkey_classes_root";
    case 0x80000001u: return "hkey_current_user";
    case 0x80000002u: return "hkey_local_machine";
    case 0x80000003u: return "hkey_users";
    }
    return NULL;
}

static void reg_lower(char* s) { for (; *s; s++) if (*s >= 'A' && *s <= 'Z') *s += 32; }

static int reg_key(const char* path, int create) {
    for (int i = 0; i < g_reg_nkeys; i++) if (!strcmp(g_reg_keys[i], path)) return i;
    if (!create) return -1;
    g_reg_keys = realloc(g_reg_keys, (g_reg_nkeys + 1) * sizeof *g_reg_keys);
    strcpy_s(g_reg_keys[g_reg_nkeys], MAX_PATH, path);
    return g_reg_nkeys++;
}

/* 1: inside a private subtree; 2: above one (a game opens
 * "Software\Publisher", then "Game" under that handle): an empty key of ours,
 * so a path opened a step at a time still arrives, and never saved. */
static int reg_private(const char* path) {
    size_t p = strlen(path);
    for (int i = 0; i < g_reg_nroots; i++) {
        size_t n = strlen(g_reg_roots[i]);
        if (!strncmp(path, g_reg_roots[i], n) && (path[n] == 0 || path[n] == '\\')) return 1;
    }
    for (int i = 0; i < g_reg_nroots; i++)
        if (p < strlen(g_reg_roots[i]) && !strncmp(path, g_reg_roots[i], p) && g_reg_roots[i][p] == '\\') return 2;
    return 0;
}

/* The full path of (parent, sub), or 0 when it is not a private one. */
static int reg_path(uint32_t parent, const char* sub, char* out) {
    const char* root = reg_root_name(parent);
    if (root) strcpy_s(out, MAX_PATH, root);
    else if (parent - REG_HANDLE0 < (uint32_t)g_reg_nkeys) strcpy_s(out, MAX_PATH, g_reg_keys[parent - REG_HANDLE0]);
    else return 0;
    if (sub && *sub) {
        while (*sub == '\\') sub++;
        strcat_s(out, MAX_PATH, "\\");
        strcat_s(out, MAX_PATH, sub);
    }
    size_t n = strlen(out);
    while (n && out[n - 1] == '\\') out[--n] = 0;
    reg_lower(out);
    return reg_private(out);
}

static reg_value_t* reg_value(int key, const char* name, int create) {
    if (!name) name = "";
    for (int i = 0; i < g_reg_nvals; i++)
        if (g_reg_vals[i].key == key && !_stricmp(g_reg_vals[i].name, name)) return &g_reg_vals[i];
    if (!create) return NULL;
    g_reg_vals = realloc(g_reg_vals, (g_reg_nvals + 1) * sizeof *g_reg_vals);
    reg_value_t* v = &g_reg_vals[g_reg_nvals++];
    memset(v, 0, sizeof *v);
    v->key = key;
    strncpy_s(v->name, sizeof v->name, name, _TRUNCATE);
    return v;
}

static void reg_save(void) {
    FILE* f = fopen(g_reg_file, "w");
    if (!f) return;
    fprintf(f, "REGEDIT4\n");
    for (int k = 0; k < g_reg_nkeys; k++) {
        if (reg_private(g_reg_keys[k]) != 1) continue;
        fprintf(f, "\n[%s]\n", g_reg_keys[k]);
        for (int i = 0; i < g_reg_nvals; i++) {
            reg_value_t* v = &g_reg_vals[i];
            if (v->key != k) continue;
            if (v->name[0]) fprintf(f, "\"%s\"=", v->name); else fprintf(f, "@=");
            if (v->type == REG_SZ) {
                fputc('"', f);
                for (DWORD j = 0; j + 1 < v->size && v->data[j]; j++) {
                    if (v->data[j] == '"' || v->data[j] == '\\') fputc('\\', f);
                    fputc(v->data[j], f);
                }
                fprintf(f, "\"\n");
            } else if (v->type == REG_DWORD && v->size == 4) {
                fprintf(f, "dword:%08x\n", *(DWORD*)v->data);
            } else {
                fprintf(f, v->type == REG_BINARY ? "hex:" : "hex(%lx):", v->type);
                for (DWORD j = 0; j < v->size; j++) fprintf(f, j ? ",%02x" : "%02x", v->data[j]);
                fprintf(f, "\n");
            }
        }
    }
    fclose(f);
}

static void reg_put(reg_value_t* v, DWORD type, const void* data, DWORD size) {
    free(v->data);
    v->type = type;
    v->size = size;
    v->data = malloc(size + 1);
    memcpy(v->data, data, size);
    v->data[size] = 0;
}

static LONG WINAPI reg_OpenKeyA(HKEY, LPCSTR, PHKEY);
static LONG WINAPI reg_OpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
static LONG WINAPI reg_CreateKeyA(HKEY, LPCSTR, PHKEY);
static LONG WINAPI reg_CreateKeyExA(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, const LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
static LONG WINAPI reg_QueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
static LONG WINAPI reg_SetValueExA(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
static LONG WINAPI reg_DeleteValueA(HKEY, LPCSTR);
static LONG WINAPI reg_CloseKey(HKEY);

int native32_registry(const char* file) {
    char line[4096];
    int key = -1;
    InitializeCriticalSection(&g_reg_lock);
    GetFullPathNameA(file, MAX_PATH, g_reg_file, NULL);
    FILE* f = fopen(g_reg_file, "r");
    if (!f) { fprintf(stderr, "[native32] registry %s: cannot open\n", file); return 0; }
    while (fgets(line, sizeof line, f)) {
        char* e = line + strlen(line);
        while (e > line && (e[-1] == '\n' || e[-1] == '\r')) *--e = 0;
        if (line[0] == '[' && e > line + 1 && e[-1] == ']') {
            e[-1] = 0;
            reg_lower(line + 1);
            key = reg_key(line + 1, 1);
            g_reg_roots = realloc(g_reg_roots, (g_reg_nroots + 1) * sizeof *g_reg_roots);
            strcpy_s(g_reg_roots[g_reg_nroots++], MAX_PATH, line + 1);
            continue;
        }
        if (key < 0 || (line[0] != '"' && line[0] != '@')) continue;
        char name[128] = "", *p = line;
        if (*p == '"') {
            char* q = strchr(p + 1, '"');
            if (!q) continue;
            *q = 0;
            strncpy_s(name, sizeof name, p + 1, _TRUNCATE);
            p = q + 1;
        } else {
            p++;
        }
        if (*p++ != '=') continue;
        reg_value_t* v = reg_value(key, name, 1);
        if (*p == '"') {
            char s[4096];
            int n = 0;
            for (p++; *p && *p != '"' && n < (int)sizeof s - 1; p++) s[n++] = *p == '\\' && p[1] ? *++p : *p;
            s[n++] = 0;
            reg_put(v, REG_SZ, s, n);
        } else if (!strncmp(p, "dword:", 6)) {
            DWORD d = strtoul(p + 6, NULL, 16);
            reg_put(v, REG_DWORD, &d, 4);
        } else if (!strncmp(p, "hex", 3)) {
            DWORD type = REG_BINARY, n = 0;
            uint8_t b[2048];
            if (p[3] == '(') type = strtoul(p + 4, NULL, 16);
            p = strchr(p, ':');
            for (p = p ? p + 1 : ""; *p && n < sizeof b; ) {
                b[n++] = (uint8_t)strtoul(p, &p, 16);
                while (*p == ',' || *p == ' ' || *p == '\\') p++;
            }
            reg_put(v, type, b, n);
        }
    }
    fclose(f);
    if (!g_reg_nroots) return 0;
    static const struct { const char* name; void* fn; } funcs[] = {
        { "RegOpenKeyA", reg_OpenKeyA }, { "RegOpenKeyExA", reg_OpenKeyExA },
        { "RegCreateKeyA", reg_CreateKeyA }, { "RegCreateKeyExA", reg_CreateKeyExA },
        { "RegQueryValueExA", reg_QueryValueExA }, { "RegSetValueExA", reg_SetValueExA },
        { "RegDeleteValueA", reg_DeleteValueA }, { "RegCloseKey", reg_CloseKey },
    };
    for (int i = 0; i < (int)(sizeof funcs / sizeof funcs[0]); i++) native32_redirect(funcs[i].name, funcs[i].fn);
    fprintf(stderr, "[native32] registry %s: %d private subtrees, %d values\n", file, g_reg_nroots, g_reg_nvals);
    return g_reg_nroots;
}

static LONG reg_open(HKEY parent, const char* sub, HKEY* out, int create, DWORD* disp) {
    char path[MAX_PATH];
    if (!reg_path((uint32_t)(uintptr_t)parent, sub, path)) return -1;    /* not ours */
    EnterCriticalSection(&g_reg_lock);
    int had = reg_key(path, 0) >= 0, k = reg_key(path, create || reg_private(path) == 2);
    if (create && !had) reg_save();
    LeaveCriticalSection(&g_reg_lock);
    if (disp) *disp = had ? REG_OPENED_EXISTING_KEY : REG_CREATED_NEW_KEY;
    if (k < 0) return ERROR_FILE_NOT_FOUND;
    *out = (HKEY)(uintptr_t)(REG_HANDLE0 + k);
    return ERROR_SUCCESS;
}

static LONG WINAPI reg_OpenKeyA(HKEY h, LPCSTR sub, PHKEY out) {
    LONG r = reg_open(h, sub, out, 0, NULL);
    return r != -1 ? r : RegOpenKeyA(h, sub, out);
}
static LONG WINAPI reg_OpenKeyExA(HKEY h, LPCSTR sub, DWORD opt, REGSAM sam, PHKEY out) {
    LONG r = reg_open(h, sub, out, 0, NULL);
    return r != -1 ? r : RegOpenKeyExA(h, sub, opt, sam, out);
}
static LONG WINAPI reg_CreateKeyA(HKEY h, LPCSTR sub, PHKEY out) {
    LONG r = reg_open(h, sub, out, 1, NULL);
    return r != -1 ? r : RegCreateKeyA(h, sub, out);
}
static LONG WINAPI reg_CreateKeyExA(HKEY h, LPCSTR sub, DWORD res, LPSTR cls, DWORD opt, REGSAM sam,
                                    const LPSECURITY_ATTRIBUTES sa, PHKEY out, LPDWORD disp) {
    LONG r = reg_open(h, sub, out, 1, disp);
    return r != -1 ? r : RegCreateKeyExA(h, sub, res, cls, opt, sam, sa, out, disp);
}

static int reg_mine(HKEY h) { return (uint32_t)(uintptr_t)h - REG_HANDLE0 < (uint32_t)g_reg_nkeys; }

static LONG WINAPI reg_QueryValueExA(HKEY h, LPCSTR name, LPDWORD res, LPDWORD type, LPBYTE data, LPDWORD size) {
    if (!reg_mine(h)) return RegQueryValueExA(h, name, res, type, data, size);
    LONG r = ERROR_SUCCESS;
    EnterCriticalSection(&g_reg_lock);
    reg_value_t* v = reg_value((int)((uint32_t)(uintptr_t)h - REG_HANDLE0), name, 0);
    if (!v) {
        r = ERROR_FILE_NOT_FOUND;
        fprintf(stderr, "[native32] registry: no %s\\%s\n", g_reg_keys[(uint32_t)(uintptr_t)h - REG_HANDLE0], name ? name : "@");
    } else {
        if (type) *type = v->type;
        if (data && size && *size < v->size) r = ERROR_MORE_DATA;
        else if (data) memcpy(data, v->data, v->size);
        if (size) *size = v->size;
    }
    LeaveCriticalSection(&g_reg_lock);
    return r;
}

static LONG WINAPI reg_SetValueExA(HKEY h, LPCSTR name, DWORD res, DWORD type, const BYTE* data, DWORD size) {
    if (!reg_mine(h)) return RegSetValueExA(h, name, res, type, data, size);
    EnterCriticalSection(&g_reg_lock);
    reg_put(reg_value((int)((uint32_t)(uintptr_t)h - REG_HANDLE0), name, 1), type, data, size);
    reg_save();
    LeaveCriticalSection(&g_reg_lock);
    return ERROR_SUCCESS;
}

static LONG WINAPI reg_DeleteValueA(HKEY h, LPCSTR name) {
    if (!reg_mine(h)) return RegDeleteValueA(h, name);
    EnterCriticalSection(&g_reg_lock);
    reg_value_t* v = reg_value((int)((uint32_t)(uintptr_t)h - REG_HANDLE0), name, 0);
    if (v) { free(v->data); *v = g_reg_vals[--g_reg_nvals]; reg_save(); }
    LeaveCriticalSection(&g_reg_lock);
    return v ? ERROR_SUCCESS : ERROR_FILE_NOT_FOUND;
}

static LONG WINAPI reg_CloseKey(HKEY h) { return reg_mine(h) ? ERROR_SUCCESS : RegCloseKey(h); }

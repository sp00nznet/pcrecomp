/* ne_resources.c - parse the original NE binaries' resource directory + string
 * tables so the Win16 shims can serve real LoadString/FindResource/LoadResource.
 * See ne_resources.h. Pure host-side parsing; no guest CPU/memory access here. */
#include "ne_resources.h"
#include "recomp_game.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef RECOMP_GAME_DIR
#define RECOMP_GAME_DIR "game"
#endif

typedef struct {
    uint16_t type_raw;      /* raw NE rtTypeID (0x8000|n int, else name offset)  */
    int      type_int;      /* resolved int type, or -1 if named                 */
    char     type_name[32];
    uint16_t name_raw;      /* raw NE rnID                                        */
    int      name_int;      /* resolved int id, or -1 if named                   */
    char     name_str[64];
    uint32_t off;           /* absolute file offset of the resource bytes        */
    uint32_t len;           /* length in bytes                                    */
} Res;

typedef struct {
    char      path[512];    /* host file it was read from (AccessResource)          */
    char      name[64];     /* upper; no extension, or the file name if loaded by path */
    uint16_t  hinst;        /* assigned instance handle                          */
    uint8_t  *data;
    long      size;
    uint32_t  ne;           /* offset of NE header                               */
    uint32_t  res_base;     /* absolute offset of the resource table             */
    Res      *res;
    int       nres;
} Mod;

static Mod g_mods[48];     /* lifted modules + LoadLibrary'd resource DLLs (Oddballz: 8 + 14 eggs) */
static int g_nmods;

static struct { Mod *m; Res *r; } g_found[8192];
static int g_nfound;

/* Petz tag table: maps a 4-char resource tag + id to the real NE integer type.
 * CATZDLL embeds records [tag(4)][00 00][0C 00][type 0xFF0x][id]; the engine asks
 * FindResource by (tag string, id) but resources are stored under the int type. */
typedef struct { char tag[5]; uint16_t id; uint16_t type; const void *mod; } TagMap;
static TagMap g_tagmap[8192];
static int g_ntag;

static int g_inited;

static int ieq(const char *a, const char *b);   /* case-insensitive equal */

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }

/* Resolve a raw NE type/name value (rtTypeID or rnID): high bit set => integer,
 * else an offset (from the resource table base) to a length-prefixed name. */
static void resolve_id(Mod *m, uint16_t val, int *out_int, char *out_str, int outsz) {
    out_str[0] = 0;
    if (val & 0x8000) { *out_int = val & 0x7FFF; return; }
    *out_int = -1;
    uint32_t o = m->res_base + val;
    if (o < (uint32_t)m->size) {
        int n = m->data[o];
        int i = 0;
        for (; i < n && i < outsz - 1 && (o + 1 + i) < (uint32_t)m->size; i++)
            out_str[i] = (char)m->data[o + 1 + i];
        out_str[i] = 0;
    }
}

static int parse_ne(Mod *m) {
    if (m->size < 0x40) return 0;
    uint32_t e = rd16(m->data + 0x3C);
    if (e + 64 > (uint32_t)m->size || m->data[e] != 'N' || m->data[e + 1] != 'E') return 0;
    m->ne = e;
    const uint8_t *nh = m->data + e;
    uint32_t res_off = rd16(nh + 36);
    if (res_off == 0) return 1;                 /* no resource table */
    m->res_base = e + res_off;
    if (m->res_base + 2 > (uint32_t)m->size) return 0;
    uint16_t align = rd16(m->data + m->res_base);
    uint32_t p = m->res_base + 2;

    /* first pass: count */
    int total = 0;
    uint32_t q = p;
    while (q + 8 <= (uint32_t)m->size) {
        uint16_t tid = rd16(m->data + q);
        if (tid == 0) break;
        uint16_t cnt = rd16(m->data + q + 2);
        q += 8 + (uint32_t)cnt * 12;
        total += cnt;
    }
    m->res = (Res *)calloc(total ? total : 1, sizeof(Res));
    m->nres = 0;

    while (p + 8 <= (uint32_t)m->size) {
        uint16_t tid = rd16(m->data + p);
        if (tid == 0) break;
        uint16_t cnt = rd16(m->data + p + 2);
        p += 8;
        for (int i = 0; i < cnt && p + 12 <= (uint32_t)m->size; i++, p += 12) {
            Res *r = &m->res[m->nres++];
            r->type_raw = tid;
            resolve_id(m, tid, &r->type_int, r->type_name, sizeof r->type_name);
            r->name_raw = rd16(m->data + p + 6);
            resolve_id(m, r->name_raw, &r->name_int, r->name_str, sizeof r->name_str);
            r->off = (uint32_t)rd16(m->data + p + 0) << align;
            r->len = (uint32_t)rd16(m->data + p + 2) << align;
        }
    }
    return 1;
}

static Mod *register_mod(const char *base, uint16_t hinst, const char *file) {
    /* `file` is the exact name when the caller knows it (a lifted module, from
       RECOMP_MODULES). LoadLibrary only has a base name, so probe extensions:
       a host is as likely to be a .WAD or .EXE as a library is a .DLL. Probing
       for a module we DO know picked ODDBALLZ.EXE, the launcher, over
       ODDBALLZ.WAD, the game. */
    static const char *const EXTS[] = { "DLL", "EXE", "WAD", "DRV" };
    char path[512];
    FILE *f = NULL;
    if (file) {                         /* absolute host path, or relative to the game */
        int abs = file[0] == '/' || file[0] == '\\' || (file[0] && file[1] == ':');
        if (abs) snprintf(path, sizeof path, "%s", file);
        else     snprintf(path, sizeof path, "%s/%s", RECOMP_GAME_DIR, file);
        f = fopen(path, "rb");
    }
    for (unsigned k = 0; !f && !file && k < sizeof EXTS / sizeof EXTS[0]; k++) {
        snprintf(path, sizeof path, "%s/%s.%s", RECOMP_GAME_DIR, base, EXTS[k]);
        f = fopen(path, "rb");
    }
    if (!f) { fprintf(stderr, "[ne] cannot open %s\n", base); return NULL; }
    Mod *m = &g_mods[g_nmods];
    fseek(f, 0, SEEK_END); m->size = ftell(f); fseek(f, 0, SEEK_SET);
    m->data = (uint8_t *)malloc(m->size);
    if (fread(m->data, 1, m->size, f) != (size_t)m->size) { fclose(f); free(m->data); return NULL; }
    fclose(f);
    snprintf(m->name, sizeof m->name, "%s", base);
    snprintf(m->path, sizeof m->path, "%s", path);
    m->hinst = hinst;
    if (!parse_ne(m)) { fprintf(stderr, "[ne] %s: NE parse failed\n", base); free(m->data); return NULL; }
    fprintf(stderr, "[ne] loaded %s (hinst=%04X, %d resources)\n", base, hinst, m->nres);
    g_nmods++;
    return m;
}

/* Scan a module's raw image for Petz tag records and build the tag+id->type map. */
static void scan_tagmap(Mod *m) {
    const uint8_t *d = m->data;
    long n = m->size;
    for (long i = 0; i + 12 <= n; i++) {
        int ok = 1;
        for (int k = 0; k < 4; k++) { uint8_t c = d[i + k]; if (c < 0x20 || c > 0x7E) { ok = 0; break; } }
        if (!ok) continue;
        if (d[i + 4] || d[i + 5]) continue;
        if (d[i + 6] != 0x0C || d[i + 7] != 0x00) continue;
        uint16_t type = (uint16_t)(d[i + 8] | (d[i + 9] << 8));
        if (type < 0xFF00 || type > 0xFF20) continue;      /* Petz custom types */
        if (g_ntag >= (int)(sizeof g_tagmap / sizeof g_tagmap[0])) break;
        memcpy(g_tagmap[g_ntag].tag, d + i, 4); g_tagmap[g_ntag].tag[4] = 0;
        g_tagmap[g_ntag].id   = (uint16_t)(d[i + 10] | (d[i + 11] << 8));
        g_tagmap[g_ntag].type = (uint16_t)(type & 0x7FFF);
        g_tagmap[g_ntag].mod  = m;
        g_ntag++;
    }
}

/* The (tag,id) records are the ones CATZDLL's data segment happens to mention
 * literally, NOT the full set of resources: type 0x7F04 holds names 1000, 2000,
 * 3000 and 4000, but only 2000/3000/4000 have a record. Requiring an exact pair
 * therefore left STBL/1000 unresolvable, FindResource returned 0, and the engine
 * threw. A tag names the resource *type* and the id names the resource, so fall
 * back to the tag alone -- but only when it is unambiguous: PALT appears under
 * both 0x7F03 and 0x7F04, and for that one the exact records are what
 * discriminate. */
/* `in`: a module's own records first. CivNet's nine data DLLs each number
 * their types from 0x7F01, so STRG is 0x7F01 in one and SPRT in another, and
 * only the module being searched can say which. NULL: every module, as the
 * single-DLL PF Magic games always did. */
static int tag_to_type_in(const char *tag, int id, const void *in) {
    if (id < 0 || !tag) return -1;
    for (int i = 0; i < g_ntag; i++)
        if ((!in || g_tagmap[i].mod == in) && g_tagmap[i].id == (uint16_t)id && ieq(g_tagmap[i].tag, tag))
            return g_tagmap[i].type;
    int found = -1;
    for (int i = 0; i < g_ntag; i++) {
        if ((in && g_tagmap[i].mod != in) || !ieq(g_tagmap[i].tag, tag)) continue;
        if (found >= 0 && found != (int)g_tagmap[i].type) return -1;   /* ambiguous */
        found = (int)g_tagmap[i].type;
    }
    return found;
}

void ne_init(void) {
    if (g_inited) return;
    g_inited = 1;
    /* Every lifted module serves its own resources; hInstance == its DGROUP
       selector, the handle the runtime hands out for it everywhere else. */
    for (int i = 0; i < RECOMP_NUM_MODULES; i++) {
        char base[32];
        snprintf(base, sizeof base, "%s", RECOMP_MODULES[i].file);
        char *dot = strrchr(base, '.');
        if (dot) *dot = 0;
        Mod *m = register_mod(base, RECOMP_MODULES[i].dgroup, RECOMP_MODULES[i].file);
        if (m && recomp_game.resource_tags) scan_tagmap(m);
    }
    fprintf(stderr, "[ne] tag map: %d (tag,id)->type records\n", g_ntag);
}

static Mod *mod_by_hinst(uint16_t hinst) {
    hinst = recomp_hinst_unalias(hinst);
    for (int i = 0; i < g_nmods; i++) if (g_mods[i].hinst == hinst) return &g_mods[i];
    return NULL;
}

/* normalize "C:\\PATH\\CATZREZX.DLL" -> "CATZREZX" (upper, no path/ext) */
static void normalize(const char *in, char *out, int outsz) {
    const char *p = in, *slash = in;
    for (; *p; p++) if (*p == '\\' || *p == '/' || *p == ':') slash = p + 1;
    int i = 0;
    for (p = slash; *p && *p != '.' && i < outsz - 1; p++, i++) {
        char c = *p;
        if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
        out[i] = c;
    }
    out[i] = 0;
}

uint16_t ne_loadlib(const char *name, const char *hostpath) {
    ne_init();
    char base[64];
    normalize(name, base, sizeof base);
    if (base[0] == 0) return 0;
    if (hostpath) {
        /* A module loaded by path is known by its file name WITH extension:
           Oddballz ships DYNAROO.ODD and DYNAROO.ODX side by side, and by base
           name alone the second load would hand back the first. */
        const char *leaf = hostpath;
        for (const char *q = hostpath; *q; q++) if (*q == '/' || *q == '\\') leaf = q + 1;
        int i = 0;
        for (; leaf[i] && i < (int)sizeof base - 1; i++)
            base[i] = (char)((leaf[i] >= 'a' && leaf[i] <= 'z') ? leaf[i] - 32 : leaf[i]);
        base[i] = 0;
    }
    for (int i = 0; i < g_nmods; i++)
        if (strcmp(g_mods[i].name, base) == 0) return recomp_hinst_alias(g_mods[i].hinst);
    /* Only serve modules that actually ship as game NE files we can parse. */
    if (g_nmods < (int)(sizeof g_mods / sizeof g_mods[0])) {
        uint16_t hinst = (uint16_t)(0xF000 + g_nmods);
        Mod *m = register_mod(base, hinst, hostpath);
        /* A DLL loaded at run time can carry the tag map too: CivNet's is in
           CIVENG0.DLL, which it LoadLibrary's. */
        if (m && recomp_game.resource_tags) {
            int before = g_ntag;
            scan_tagmap(m);
            if (g_ntag != before)
                fprintf(stderr, "[ne] tag map: %d records from %s\n", g_ntag - before, base);
        }
        if (m) return m->hinst;
    }
    return 0;
}

static int load_string_from(Mod *m, uint16_t id, char *out, int max) {
    uint16_t block = (uint16_t)((id >> 4) + 1);   /* RT_STRING block id */
    uint16_t sub   = (uint16_t)(id & 0x0F);
    for (int i = 0; i < m->nres; i++) {
        Res *r = &m->res[i];
        if (r->type_int != 6) continue;           /* RT_STRING */
        if (r->name_int != block) continue;
        uint32_t q = r->off, end = r->off + r->len;
        for (uint16_t s = 0; s <= sub; s++) {
            if (q >= end || q >= (uint32_t)m->size) return 0;
            int n = m->data[q++];
            if (s == sub) {
                int k = 0;
                for (; k < n && k < max - 1 && q + k < (uint32_t)m->size; k++)
                    out[k] = (char)m->data[q + k];
                out[k] = 0;
                return k;
            }
            q += n;
        }
    }
    return 0;
}

/* On Windows a module answers LoadString/FindResource only for itself. Catz's
 * engine passes the wrong module's handle for some lookups, so a game can opt
 * into searching the lifted modules when its own misses
 * (recomp_game.resource_fallback). Never for a DLL LoadLibrary'd at run time
 * (handles 0xF000 up), and never by default: on Oddballz, falling back handed
 * its eggs other modules' strings ("Exit", "Fear") as bitmap names. */
static int no_fallback(const Mod *m) {
    return !recomp_game.resource_fallback || (m && m->hinst >= 0xF000);
}

int ne_load_string(uint16_t hinst, uint16_t id, char *out, int max) {
    ne_init();
    Mod *m = mod_by_hinst(hinst);
    int n = m ? load_string_from(m, id, out, max) : 0;
    if (n || no_fallback(m)) return n;
    /* Fall back to any module: the engine sometimes passes the app (WAD)
     * instance for strings that actually live in CATZDLL, and vice-versa. */
    for (int i = 0; i < g_nmods; i++) {
        if (&g_mods[i] == m) continue;
        n = load_string_from(&g_mods[i], id, out, max);
        if (n) return n;
    }
    return 0;
}

static int res_matches(Res *r, int type_int, const char *type_str,
                       int name_int, const char *name_str) {
    int tmatch = (type_int >= 0)
        ? (r->type_int == type_int)
        : (r->type_int < 0 && type_str && ieq(r->type_name, type_str));
    if (!tmatch) return 0;
    return (name_int >= 0) ? (r->name_int == name_int)
                           : (r->name_int < 0 && name_str && ieq(r->name_str, name_str));
}

/* One HRSRC per resource, as Windows gives: CivNet looks resources up
 * thousands of times, and with a new handle each time the table filled at 512
 * and every later FindResource failed. */
static uint16_t register_found(Mod *m, Res *r) {
    if (getenv("RECOMP_RES_DEDUPE"))
        for (int i = 0; i < g_nfound; i++)
            if (g_found[i].m == m && g_found[i].r == r) return (uint16_t)(i + 1);
    if (g_nfound >= (int)(sizeof g_found / sizeof g_found[0])) {
        fprintf(stderr, "[ne] *** resource handle table full\n");
        return 0;
    }
    g_found[g_nfound].m = m; g_found[g_nfound].r = r;
    return (uint16_t)(++g_nfound);                /* HRSRC = index+1 */
}

/* RT_NAMETABLE (type 15): Windows 3.0's map from string names to the integer
 * type/id a resource was compiled under. Entries are
 *     WORD cb; WORD type; WORD id; char type_name[]; char name[];
 * with 0x8000 set on an ordinal type/id, and cb == 0 ending the table.
 * FindResource(h, "DI", "TAG") on an Oddballz egg means type 0xFF0A id 1 by
 * way of exactly this. Returns 1 and rewrites the query when an entry matches. */
static int nametable(Mod *m, int *ti, const char **ts, int *ni, const char **ns) {
    for (int i = 0; i < m->nres; i++) {
        Res *r = &m->res[i];
        if (r->type_int != 15) continue;
        uint32_t p = r->off, end = r->off + r->len;
        while (p + 6 < end && p + 6 < (uint32_t)m->size) {
            uint16_t cb = rd16(m->data + p);
            if (cb < 6 || p + cb > end) break;
            uint16_t et = rd16(m->data + p + 2), ei = rd16(m->data + p + 4);
            const char *etn = (const char *)m->data + p + 6;
            const char *enm = etn + strnlen(etn, cb - 6) + 1;
            int tok = *ts ? ieq(etn, *ts) : (*ti == (et & 0x7FFF));
            int nok = *ns ? ((const uint8_t *)enm < m->data + p + cb && ieq(enm, *ns))
                          : (*ni == (ei & 0x7FFF));
            if (tok && nok) {
                *ti = et & 0x7FFF; *ts = NULL;
                *ni = ei & 0x7FFF; *ns = NULL;
                return 1;
            }
            p += cb;
        }
    }
    return 0;
}

/* A resource of this module by the query as given, else by its name table. */
static uint16_t find_in(Mod *m, int ti, const char *ts, int ni, const char *ns) {
    for (int i = 0; i < m->nres; i++)
        if (res_matches(&m->res[i], ti, ts, ni, ns))
            return register_found(m, &m->res[i]);
    if ((ts || ns) && nametable(m, &ti, &ts, &ni, &ns))
        for (int i = 0; i < m->nres; i++)
            if (res_matches(&m->res[i], ti, ts, ni, ns))
                return register_found(m, &m->res[i]);
    return 0;
}

/* find_in, with a 4-char tag type resolved to the int type the resources are
 * stored under: this module's tag records first, then everyone's. */
static uint16_t find_tagged(Mod *m, int type_int, const char *type_str, int name_int, const char *name_str) {
    if (type_int < 0 && type_str && name_int >= 0 && g_ntag) {
        /* A module with records of its own answers only from them (a CivNet
           data DLL without a STRN record has no STRN, even if another DLL's
           STRN type number exists in it); one without any uses everyone's. */
        int own = 0;
        for (int i = 0; i < g_ntag && !own; i++) own = g_tagmap[i].mod == m;
        int t = tag_to_type_in(type_str, name_int, own ? m : NULL);
        if (getenv("RECOMP_LOG_TAGS")) fprintf(stderr, "[tag] %s/%d in %s -> type %d\n", type_str, name_int, m->name, t);
        if (t >= 0) return find_in(m, t, NULL, name_int, name_str);
    }
    return find_in(m, type_int, type_str, name_int, name_str);
}

uint16_t ne_find_resource(uint16_t hinst, int type_int, const char *type_str,
                          int name_int, const char *name_str) {
    ne_init();
    /* "#123" is how Win16 spells integer ID 123 as a string (the RC compiler
       and MAKEINTRESOURCE both produce it); Dogz asks for type "#123". */
    if (type_int < 0 && type_str && type_str[0] == '#') { type_int = atoi(type_str + 1); type_str = NULL; }
    if (name_int < 0 && name_str && name_str[0] == '#') { name_int = atoi(name_str + 1); name_str = NULL; }
    /* Resolve a Petz 4-char tag ("APTF","PALT",...) to its real NE int type via
     * the (tag,id) table, since resources are stored under int types not the tag. */
    Mod *m = mod_by_hinst(hinst);
    uint16_t h = m ? find_tagged(m, type_int, type_str, name_int, name_str) : 0;
    /* The engine sometimes passes hInst=0 / the wrong module's handle (the real
     * resource handle does not always propagate cross-module yet). Fall back to
     * searching every loaded module. */
    for (int j = 0; !h && !no_fallback(m) && j < g_nmods; j++)
        if (&g_mods[j] != m)
            h = find_tagged(&g_mods[j], type_int, type_str, name_int, name_str);
    return h;
}

int ne_resource_file(uint16_t hrsrc, char *path, int pathsz, uint32_t *off) {
    if (hrsrc == 0 || hrsrc > g_nfound) return 0;
    snprintf(path, pathsz, "%s", g_found[hrsrc - 1].m->path);
    *off = g_found[hrsrc - 1].r->off;
    return 1;
}

const uint8_t *ne_resource_bytes(uint16_t hrsrc, uint32_t *out_len) {
    if (hrsrc == 0 || hrsrc > g_nfound) return NULL;
    Mod *m = g_found[hrsrc - 1].m;
    Res *r = g_found[hrsrc - 1].r;
    if (r->off + r->len > (uint32_t)m->size) return NULL;
    if (out_len) *out_len = r->len;
    return m->data + r->off;
}

/* GetProcAddress for a module that was lifted into this image. The entry table
 * gives (segment, offset) in the module's own numbering; the lifted code calls
 * it at (first_seg - 1 + segment, offset), which is the far pointer the guest
 * must get back. Oddballz LoadLibrary's its intro DLL and calls through the
 * pointers this returns -- 0 sent it through a null far pointer into abort. */
int ne_proc_address(uint16_t hinst, const char *name, int ordinal,
                    uint16_t *seg, uint16_t *off) {
    ne_init();
    Mod *m = mod_by_hinst(hinst);
    const RecompModule *rm = recomp_module_of_hinst(hinst);
    if (!m || !rm) return 0;
    const uint8_t *d = m->data;
    if (name) {                                 /* name -> ordinal: resident, then non-resident */
        uint32_t tabs[2] = { m->ne + rd16(d + m->ne + 0x26), 0 };
        uint32_t nonres = (uint32_t)(d[m->ne + 0x2C] | d[m->ne + 0x2D] << 8 |
                                     d[m->ne + 0x2E] << 16 | (uint32_t)d[m->ne + 0x2F] << 24);
        tabs[1] = nonres;
        for (int t = 0; t < 2 && ordinal <= 0; t++) {
            uint32_t p = tabs[t];
            if (!p) continue;
            p += 1u + d[p] + 2u;                /* skip the module-name entry */
            while (p < (uint32_t)m->size && d[p]) {
                char nm[128]; int n = d[p];
                if (n > 127) n = 127;
                memcpy(nm, d + p + 1, n); nm[n] = 0;
                if (ieq(nm, name)) { ordinal = rd16(d + p + 1 + d[p]); break; }
                p += 1u + d[p] + 2u;
            }
        }
    }
    if (ordinal <= 0) return 0;
    uint32_t p = m->ne + rd16(d + m->ne + 0x04), end = p + rd16(d + m->ne + 0x06);
    int ord = 1;
    while (p < end && d[p]) {
        int count = d[p], type = d[p + 1];
        p += 2;
        if (type == 0) { ord += count; continue; }          /* unused ordinals */
        for (int i = 0; i < count; i++, ord++) {
            int s; uint16_t o;
            if (type == 0xFF) { s = d[p + 3]; o = rd16(d + p + 4); p += 6; }   /* moveable */
            else              { s = type;     o = rd16(d + p + 1); p += 3; }   /* fixed */
            if (ord == ordinal) {
                if (s == 0 || s >= 0xFE) return 0;          /* constant, not code */
                *seg = (uint16_t)(rm->first_seg - 1 + s);
                *off = o;
                return 1;
            }
        }
    }
    return 0;
}

/* tiny case-insensitive compare returning 1 on equal (avoid platform strcasecmp) */
static int ieq(const char *a, const char *b) {
    for (; *a && *b; a++, b++) {
        char ca = *a, cb = *b;
        if (ca >= 'a' && ca <= 'z') ca = (char)(ca - 32);
        if (cb >= 'a' && cb <= 'z') cb = (char)(cb - 32);
        if (ca != cb) return 0;
    }
    return *a == *b;
}

/*
 * storage.c - OLE structured storage: StgCreateDocfile/StgOpenStorage,
 * IStorage and IStream, and OleSaveToStream/OleLoadFromStream.
 *
 * A storage is held in memory while it is open, a tree of storages and
 * streams, and is a compound file on disk: read whole when opened, written
 * whole when committed or released. The file is the format Windows writes
 * (MS-CFB version 3: 512-byte sectors, small streams in the mini stream), so
 * a game's save written here loads on Windows and the other way round.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "win32hle.h"

#define S_OK              0u
#define S_FALSE           1u
#define E_NOTIMPL         0x80004001u
#define E_NOINTERFACE     0x80004002u
#define E_FAIL            0x80004005u
#define STG_E_FILENOTFOUND     0x80030002u
#define STG_E_ACCESSDENIED     0x80030005u
#define STG_E_INVALIDPOINTER   0x80030009u
#define STG_E_FILEALREADYEXISTS 0x80030050u
#define STG_E_INVALIDHEADER    0x800300FBu
#define STG_E_READFAULT        0x8003001Eu
#define STG_E_WRITEFAULT       0x8003001Du
#define STGM_WRITE      0x1u
#define STGM_READWRITE  0x2u
#define STGM_CREATE     0x1000u

#define FREESECT   0xFFFFFFFFu
#define ENDOFCHAIN 0xFFFFFFFEu
#define FATSECT    0xFFFFFFFDu
#define NOSTREAM   0xFFFFFFFFu

/* ---- the tree ---- */
typedef struct node {
    uint16_t name[32];
    int type;                            /* 1 storage, 2 stream, 5 root */
    uint8_t clsid[16];
    uint8_t *data;
    uint32_t size, cap;
    struct node *child, *next, *parent;
    int refs;                            /* objects open on it */
} node_t;

typedef struct { node_t *root; char path[1024]; int writable, dirty, refs; } file_t;

static int wlen(const uint16_t *w) { int n = 0; while (w && w[n]) n++; return n; }
static int wcmp_upper(const uint16_t *a, const uint16_t *b) {   /* the CFB order: length, then upper case */
    int la = wlen(a), lb = wlen(b);
    if (la != lb) return la < lb ? -1 : 1;
    for (int i = 0; i < la; i++) {
        uint16_t x = a[i] >= 'a' && a[i] <= 'z' ? a[i] - 32 : a[i], y = b[i] >= 'a' && b[i] <= 'z' ? b[i] - 32 : b[i];
        if (x != y) return x < y ? -1 : 1;
    }
    return 0;
}
static node_t *find_child(node_t *p, const uint16_t *name) {
    for (node_t *c = p->child; c; c = c->next) if (!wcmp_upper(c->name, name)) return c;
    return NULL;
}
static node_t *add_child(node_t *p, const uint16_t *name, int type) {
    node_t *c = (node_t *)calloc(1, sizeof *c);
    int n = wlen(name);
    if (n > 31) n = 31;
    memcpy(c->name, name, (size_t)n * 2);
    c->type = type, c->parent = p, c->next = p->child, p->child = c;
    return c;
}
static void free_tree(node_t *n) {
    while (n) { node_t *nx = n->next; free_tree(n->child); free(n->data); free(n); n = nx; }
}
static void unlink_child(node_t *c) {
    for (node_t **p = &c->parent->child; *p; p = &(*p)->next) if (*p == c) { *p = c->next; break; }
    c->next = NULL;
    free_tree(c);
}

/* ---- reading a compound file ---- */
typedef struct { const uint8_t *f; size_t n; uint32_t ss; uint32_t *fat; uint32_t nfat; uint32_t *minifat; uint32_t nmini; uint8_t *ministream; uint32_t ministream_n; } rd_t;
static const uint8_t *sector(rd_t *r, uint32_t s) {
    size_t at = ((size_t)s + 1) * r->ss;
    return at + r->ss <= r->n ? r->f + at : NULL;
}
static uint8_t *chain(rd_t *r, uint32_t start, uint32_t *len) {   /* a FAT chain's bytes */
    uint8_t *out = NULL;
    uint32_t n = 0, steps = 0;
    for (uint32_t s = start; s != ENDOFCHAIN && s < r->nfat && steps < 1u << 20; s = r->fat[s], steps++) {
        const uint8_t *p = sector(r, s);
        if (!p) break;
        out = (uint8_t *)realloc(out, n + r->ss);
        memcpy(out + n, p, r->ss);
        n += r->ss;
    }
    *len = n;
    return out;
}
static int read_cfb(const uint8_t *f, size_t n, node_t **out) {
    static const uint8_t sig[8] = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
    if (n < 512 || memcmp(f, sig, 8)) return 0;
    rd_t r;
    memset(&r, 0, sizeof r);
    r.f = f, r.n = n, r.ss = 1u << *(const uint16_t *)(f + 30);
    if (r.ss != 512 && r.ss != 4096) return 0;
    uint32_t nfatsec = *(const uint32_t *)(f + 44), dir0 = *(const uint32_t *)(f + 48);
    uint32_t cutoff = *(const uint32_t *)(f + 56), mini0 = *(const uint32_t *)(f + 60);
    uint32_t difat0 = *(const uint32_t *)(f + 68), ndifat = *(const uint32_t *)(f + 72);
    /* the FAT's sectors: 109 in the header, the rest through the DIFAT chain */
    uint32_t *fs = (uint32_t *)calloc(nfatsec + 1, 4), k = 0;
    for (uint32_t i = 0; i < 109 && k < nfatsec; i++) fs[k++] = *(const uint32_t *)(f + 76 + 4 * i);
    for (uint32_t d = difat0, j = 0; j < ndifat && d != ENDOFCHAIN && k < nfatsec; j++) {
        const uint8_t *p = sector(&r, d);
        if (!p) break;
        for (uint32_t i = 0; i < r.ss / 4 - 1 && k < nfatsec; i++) fs[k++] = ((const uint32_t *)p)[i];
        d = ((const uint32_t *)p)[r.ss / 4 - 1];
    }
    r.nfat = k * (r.ss / 4);
    r.fat = (uint32_t *)calloc(r.nfat ? r.nfat : 1, 4);
    for (uint32_t i = 0; i < k; i++) { const uint8_t *p = sector(&r, fs[i]); if (p) memcpy(r.fat + i * (r.ss / 4), p, r.ss); }
    free(fs);
    uint32_t dlen;
    uint8_t *dir = chain(&r, dir0, &dlen);
    uint32_t mlen;
    r.minifat = (uint32_t *)chain(&r, mini0, &mlen);
    r.nmini = mlen / 4;
    uint32_t ndir = dlen / 128;
    if (!ndir) { free(dir); free(r.fat); free(r.minifat); return 0; }
    /* the root's chain is the mini stream */
    r.ministream = chain(&r, *(const uint32_t *)(dir + 116), &r.ministream_n);
    node_t **nodes = (node_t **)calloc(ndir, sizeof *nodes);
    for (uint32_t i = 0; i < ndir; i++) {
        const uint8_t *e = dir + 128 * i;
        int type = e[66];
        if (type != 1 && type != 2 && type != 5) continue;
        node_t *x = (node_t *)calloc(1, sizeof *x);
        int nl = *(const uint16_t *)(e + 64) / 2 - 1;
        if (nl > 31) nl = 31;
        if (nl > 0) memcpy(x->name, e, (size_t)nl * 2);
        x->type = type;
        memcpy(x->clsid, e + 80, 16);
        if (type == 2) {
            uint32_t start = *(const uint32_t *)(e + 116), size = *(const uint32_t *)(e + 120);
            x->size = x->cap = size;
            x->data = (uint8_t *)calloc(1, size ? size : 1);
            if (size < cutoff) {                     /* in the mini stream, 64-byte sectors */
                uint32_t got = 0, steps = 0;
                for (uint32_t s = start; s != ENDOFCHAIN && s < r.nmini && got < size && steps < 1u << 20; s = r.minifat[s], steps++) {
                    uint32_t take = size - got < 64 ? size - got : 64;
                    if ((size_t)s * 64 + take <= r.ministream_n) memcpy(x->data + got, r.ministream + (size_t)s * 64, take);
                    got += take;
                }
            } else {
                uint32_t cl;
                uint8_t *c = chain(&r, start, &cl);
                memcpy(x->data, c, cl < size ? cl : size);
                free(c);
            }
        }
        nodes[i] = x;
    }
    /* each storage's children are the tree under its child id: in-order */
    node_t *root = nodes[0];
    int ok = root && root->type == 5;
    for (uint32_t i = 0; ok && i < ndir; i++) {
        if (!nodes[i] || nodes[i]->type == 2) continue;
        uint32_t stack[256], sp = 0, c = *(const uint32_t *)(dir + 128 * i + 76);
        if (c != NOSTREAM) stack[sp++] = c;
        while (sp) {
            uint32_t id = stack[--sp];
            if (id >= ndir || !nodes[id] || nodes[id]->parent || id == 0) continue;
            nodes[id]->parent = nodes[i];
            nodes[id]->next = nodes[i]->child, nodes[i]->child = nodes[id];
            uint32_t l = *(const uint32_t *)(dir + 128 * id + 68), rr = *(const uint32_t *)(dir + 128 * id + 72);
            if (l != NOSTREAM && sp < 255) stack[sp++] = l;
            if (rr != NOSTREAM && sp < 255) stack[sp++] = rr;
        }
    }
    for (uint32_t i = 1; i < ndir; i++) if (nodes[i] && !nodes[i]->parent) free_tree(nodes[i]);   /* unreachable */
    free(nodes), free(dir), free(r.fat), free(r.minifat), free(r.ministream);
    if (!ok) { if (root) free(root); return 0; }
    *out = root;
    return 1;
}

/* ---- writing one ---- */
typedef struct { uint8_t *b; size_t n, cap; } buf_t;
static void put(buf_t *b, const void *p, size_t n) {
    if (b->n + n > b->cap) { b->cap = (b->n + n) * 2 + 4096; b->b = (uint8_t *)realloc(b->b, b->cap); }
    memcpy(b->b + b->n, p, n);
    b->n += n;
}
typedef struct { node_t *n; uint32_t left, right, child, start, size; } ent_t;
static ent_t *g_ents;
static uint32_t g_nents;

static uint32_t number(node_t *n) {                      /* every node, root first */
    uint32_t id = g_nents++;
    g_ents = (ent_t *)realloc(g_ents, sizeof *g_ents * g_nents);
    memset(&g_ents[id], 0, sizeof *g_ents);
    g_ents[id].n = n, g_ents[id].left = g_ents[id].right = g_ents[id].child = NOSTREAM;
    for (node_t *c = n->child; c; c = c->next) number(c);
    return id;
}
static int cmp_ent(const void *a, const void *b) { return wcmp_upper(g_ents[*(const uint32_t *)a].n->name, g_ents[*(const uint32_t *)b].n->name); }
static uint32_t balance(uint32_t *ids, int lo, int hi) {   /* a balanced BST of the sorted siblings */
    if (lo > hi) return NOSTREAM;
    int mid = (lo + hi) / 2;
    g_ents[ids[mid]].left = balance(ids, lo, mid - 1);
    g_ents[ids[mid]].right = balance(ids, mid + 1, hi);
    return ids[mid];
}
static uint32_t id_of(node_t *n) { for (uint32_t i = 0; i < g_nents; i++) if (g_ents[i].n == n) return i; return NOSTREAM; }

static int write_cfb(const char *path, node_t *root) {
    g_ents = NULL, g_nents = 0;
    number(root);
    for (uint32_t i = 0; i < g_nents; i++) {
        node_t *n = g_ents[i].n;
        uint32_t ids[1024];
        int k = 0;
        for (node_t *c = n->child; c && k < 1024; c = c->next) ids[k++] = id_of(c);
        qsort(ids, (size_t)k, 4, cmp_ent);
        g_ents[i].child = balance(ids, 0, k - 1);
    }
    /* small streams into the mini stream (64-byte sectors), big ones into regular sectors */
    buf_t mini = { 0 }, big = { 0 };
    uint32_t *minifat = NULL, nminifat = 0;
    uint32_t nbigsec = 0;
    uint32_t *bigfat = NULL;                             /* chains among the data sectors, relative */
    for (uint32_t i = 0; i < g_nents; i++) {
        node_t *n = g_ents[i].n;
        g_ents[i].start = ENDOFCHAIN, g_ents[i].size = n->type == 2 ? n->size : 0;
        if (n->type != 2 || !n->size) continue;
        if (n->size < 4096) {
            uint32_t secs = (n->size + 63) / 64;
            g_ents[i].start = nminifat;
            minifat = (uint32_t *)realloc(minifat, 4 * (nminifat + secs));
            for (uint32_t s = 0; s < secs; s++) minifat[nminifat + s] = s + 1 < secs ? nminifat + s + 1 : ENDOFCHAIN;
            nminifat += secs;
            put(&mini, n->data, n->size);
            static const uint8_t z[64];
            if (n->size % 64) put(&mini, z, 64 - n->size % 64);
        } else {
            uint32_t secs = (n->size + 511) / 512;
            g_ents[i].start = nbigsec;                   /* relative, fixed up below */
            bigfat = (uint32_t *)realloc(bigfat, 4 * (nbigsec + secs));
            for (uint32_t s = 0; s < secs; s++) bigfat[nbigsec + s] = s + 1 < secs ? nbigsec + s + 1 : ENDOFCHAIN;
            nbigsec += secs;
            put(&big, n->data, n->size);
            static const uint8_t z[512];
            if (n->size % 512) put(&big, z, 512 - n->size % 512);
        }
    }
    /* layout: [data][mini stream][minifat][directory][FAT] */
    uint32_t mini_secs = (uint32_t)((mini.n + 511) / 512), minifat_secs = (nminifat * 4 + 511) / 512;
    uint32_t dir_secs = (g_nents * 128 + 511) / 512;
    uint32_t used = nbigsec + mini_secs + minifat_secs + dir_secs, fat_secs = 1;
    while (fat_secs * 128 < used + fat_secs) fat_secs++;
    if (fat_secs > 109) { free(mini.b), free(big.b), free(minifat), free(bigfat), free(g_ents); return 0; }   /* ponytail: no DIFAT; a 7 MB save is far off */
    uint32_t total = used + fat_secs, a_mini = nbigsec, a_minifat = a_mini + mini_secs, a_dir = a_minifat + minifat_secs, a_fat = a_dir + dir_secs;
    uint32_t *fat = (uint32_t *)malloc(4u * fat_secs * 128);
    for (uint32_t i = 0; i < fat_secs * 128; i++) fat[i] = FREESECT;
    for (uint32_t i = 0; i < nbigsec; i++) fat[i] = bigfat[i];
    for (uint32_t i = 0; i < mini_secs; i++) fat[a_mini + i] = i + 1 < mini_secs ? a_mini + i + 1 : ENDOFCHAIN;
    for (uint32_t i = 0; i < minifat_secs; i++) fat[a_minifat + i] = i + 1 < minifat_secs ? a_minifat + i + 1 : ENDOFCHAIN;
    for (uint32_t i = 0; i < dir_secs; i++) fat[a_dir + i] = i + 1 < dir_secs ? a_dir + i + 1 : ENDOFCHAIN;
    for (uint32_t i = 0; i < fat_secs; i++) fat[a_fat + i] = FATSECT;
    (void)total;
    buf_t out = { 0 };
    uint8_t h[512];
    memset(h, 0, sizeof h);
    static const uint8_t sig[8] = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
    memcpy(h, sig, 8);
    *(uint16_t *)(h + 24) = 0x3E, *(uint16_t *)(h + 26) = 3, *(uint16_t *)(h + 28) = 0xFFFE;
    *(uint16_t *)(h + 30) = 9, *(uint16_t *)(h + 32) = 6;
    *(uint32_t *)(h + 44) = fat_secs, *(uint32_t *)(h + 48) = a_dir, *(uint32_t *)(h + 56) = 4096;
    *(uint32_t *)(h + 60) = minifat_secs ? a_minifat : ENDOFCHAIN, *(uint32_t *)(h + 64) = minifat_secs;
    *(uint32_t *)(h + 68) = ENDOFCHAIN, *(uint32_t *)(h + 72) = 0;
    for (int i = 0; i < 109; i++) *(uint32_t *)(h + 76 + 4 * i) = (uint32_t)i < fat_secs ? a_fat + (uint32_t)i : FREESECT;
    put(&out, h, 512);
    put(&out, big.b, big.n);
    { static const uint8_t z[512]; put(&out, mini.b, mini.n); if (mini.n % 512) put(&out, z, 512 - mini.n % 512); }
    {
        uint32_t *mf = (uint32_t *)malloc((size_t)minifat_secs * 512 + 4);
        for (uint32_t i = 0; i < minifat_secs * 128; i++) mf[i] = i < nminifat ? minifat[i] : FREESECT;
        put(&out, mf, (size_t)minifat_secs * 512);
        free(mf);
    }
    for (uint32_t i = 0; i < dir_secs * 4; i++) {
        uint8_t e[128];
        memset(e, 0, sizeof e);
        if (i < g_nents) {
            ent_t *x = &g_ents[i];
            node_t *n = x->n;
            int nl = wlen(n->name);
            if (i == 0) {
                static const uint16_t rootname[] = { 'R', 'o', 'o', 't', ' ', 'E', 'n', 't', 'r', 'y', 0 };
                memcpy(e, rootname, sizeof rootname), nl = 10;
            } else {
                memcpy(e, n->name, (size_t)nl * 2);
            }
            *(uint16_t *)(e + 64) = (uint16_t)((nl + 1) * 2);
            e[66] = (uint8_t)(i == 0 ? 5 : n->type), e[67] = 1;   /* black */
            *(uint32_t *)(e + 68) = x->left, *(uint32_t *)(e + 72) = x->right, *(uint32_t *)(e + 76) = x->child;
            memcpy(e + 80, n->clsid, 16);
            if (i == 0) {
                *(uint32_t *)(e + 116) = mini.n ? a_mini : ENDOFCHAIN, *(uint32_t *)(e + 120) = (uint32_t)mini.n;
            } else if (n->type == 2) {
                uint32_t st = x->start;
                *(uint32_t *)(e + 116) = n->size ? st : ENDOFCHAIN, *(uint32_t *)(e + 120) = n->size;
            }
        } else {
            *(uint32_t *)(e + 68) = *(uint32_t *)(e + 72) = *(uint32_t *)(e + 76) = NOSTREAM;
        }
        put(&out, e, 128);
    }
    put(&out, fat, (size_t)fat_secs * 512);
    FILE *f = fopen(path, "wb");
    int ok = f && fwrite(out.b, 1, out.n, f) == out.n;
    if (f) fclose(f);
    free(out.b), free(mini.b), free(big.b), free(minifat), free(bigfat), free(fat), free(g_ents);
    g_ents = NULL;
    return ok;
}

/* ---- the objects ---- */
static uint32_t g_vt_stg, g_vt_stm;
typedef struct { file_t *file; node_t *node; uint32_t pos; } obj_t;   /* at +8 of the COM object */
#define OBJ(self) ((obj_t *)(uintptr_t)MEM32((self) + 8))

static void vtables(void);
static uint32_t new_obj(uint32_t vt, file_t *f, node_t *n) {
    obj_t *o = (obj_t *)calloc(1, sizeof *o);
    o->file = f, o->node = n;
    f->refs++, n->refs++;
    uint32_t c = hle_com_new(vt, 12);
    MEM32(c + 8) = (uint32_t)(uintptr_t)o;
    return c;
}
static void commit(file_t *f) {
    if (f->writable && f->dirty) {
        if (!write_cfb(f->path, f->root)) fprintf(stderr, "[storage] cannot write %s\n", f->path);
        f->dirty = 0;
    }
}
static void obj_release(uint32_t self) {
    obj_t *o = OBJ(self);
    o->node->refs--;
    if (--o->file->refs == 0) {
        commit(o->file);
        free_tree(o->file->root);
        free(o->file);
    }
    free(o);
    free((void *)(uintptr_t)self);
}
static void x_Release(void) {
    uint32_t self = A32(0), n = --MEM32(self + 4);
    if (!n) obj_release(self);
    RET(n, 1);
}

/* QueryInterface: IUnknown and the object's own interface only (a game asks
 * a storage for IPropertySetStorage, and goes another way when it is not
 * there). */
static void qi(uint32_t want) {
    const uint8_t *iid = (const uint8_t *)APTR(1);
    static const uint8_t tail[8] = { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 };
    uint32_t d1 = *(const uint32_t *)iid;
    if (!memcmp(iid + 8, tail, 8) && !*(const uint32_t *)(iid + 4) && (d1 == 0 || d1 == want)) {
        MEM32(A32(2)) = A32(0);
        MEM32(A32(0) + 4)++;
        RET(S_OK, 3);
    }
    if (A32(2)) MEM32(A32(2)) = 0;
    RET(E_NOINTERFACE, 3);
}
static void sm_QueryInterface(void) { qi(0x0Cu); }   /* IStream {0000000C-...} */
static void st_QueryInterface(void) { qi(0x0Bu); }   /* IStorage {0000000B-...} */

/* IStream */
static void sm_Read(void) {                              /* (this, pv, cb, &read) */
    obj_t *o = OBJ(A32(0));
    uint32_t cb = A32(2), have = o->pos < o->node->size ? o->node->size - o->pos : 0, n = cb < have ? cb : have;
    memcpy(APTR(1), o->node->data + o->pos, n);
    o->pos += n;
    if (A32(3)) MEM32(A32(3)) = n;
    RET(n < cb ? S_FALSE : S_OK, 4);
}
static void grow(node_t *n, uint32_t size) {
    if (size > n->cap) { n->cap = size * 2 + 256; n->data = (uint8_t *)realloc(n->data, n->cap); }
    if (size > n->size) memset(n->data + n->size, 0, size - n->size);
    n->size = size;
}
static void sm_Write(void) {                             /* (this, pv, cb, &written) */
    obj_t *o = OBJ(A32(0));
    uint32_t cb = A32(2);
    if (!o->file->writable) RET(STG_E_ACCESSDENIED, 4);
    if (o->pos + cb > o->node->size) grow(o->node, o->pos + cb);
    memcpy(o->node->data + o->pos, APTR(1), cb);
    o->pos += cb;
    o->file->dirty = 1;
    if (A32(3)) MEM32(A32(3)) = cb;
    RET(S_OK, 4);
}
static void sm_Seek(void) {                              /* (this, LARGE move (2 dwords), origin, &newpos) */
    obj_t *o = OBJ(A32(0));
    int64_t move = (int64_t)((uint64_t)A32(2) << 32 | A32(1));
    int64_t base = A32(3) == 1 ? o->pos : A32(3) == 2 ? o->node->size : 0, p = base + move;
    if (p < 0) RET(0x80030019u /* STG_E_INVALIDFUNCTION */, 5);
    o->pos = (uint32_t)p;
    if (A32(4)) MEM32(A32(4)) = o->pos, MEM32(A32(4) + 4) = 0;
    RET(S_OK, 5);
}
static void sm_SetSize(void) { obj_t *o = OBJ(A32(0)); grow(o->node, A32(1)); o->node->size = A32(1); o->file->dirty = 1; RET(S_OK, 3); }
static void sm_CopyTo(void) {                            /* (this, stm, ULARGE cb, &read, &written) */
    obj_t *o = OBJ(A32(0)), *d = OBJ(A32(1));
    uint32_t have = o->pos < o->node->size ? o->node->size - o->pos : 0, n = A32(2) < have || A32(3) ? (A32(3) ? have : A32(2)) : have;
    if (d->pos + n > d->node->size) grow(d->node, d->pos + n);
    memcpy(d->node->data + d->pos, o->node->data + o->pos, n);
    o->pos += n, d->pos += n, d->file->dirty = 1;
    if (A32(4)) MEM32(A32(4)) = n, MEM32(A32(4) + 4) = 0;
    if (A32(5)) MEM32(A32(5)) = n, MEM32(A32(5) + 4) = 0;
    RET(S_OK, 6);
}
static void sm_Commit(void) { commit(OBJ(A32(0))->file); RET(S_OK, 2); }
static void sm_Revert(void) { RET(S_OK, 1); }
static void sm_LockRegion(void) { RET(S_OK, 6); }
static void stat_of(uint32_t st, node_t *n, int noname) {   /* STATSTG: name, type, size, 3 times, mode, locks, clsid, state, reserved */
    memset((void *)(uintptr_t)st, 0, 72);
    if (!noname) {
        uint16_t *w = (uint16_t *)hle_alloc(64);
        memcpy(w, n->name, 62);
        MEM32(st) = (uint32_t)(uintptr_t)w;
    }
    MEM32(st + 4) = n->type == 5 ? 1u : (uint32_t)n->type;
    MEM32(st + 8) = n->type == 2 ? n->size : 0;
    memcpy((void *)(uintptr_t)(st + 0x38), n->clsid, 16);
}
static void sm_Stat(void) { stat_of(A32(1), OBJ(A32(0))->node, A32(2) & 1); RET(S_OK, 3); }
static void sm_Clone(void) {
    obj_t *o = OBJ(A32(0));
    uint32_t c = new_obj(g_vt_stm, o->file, o->node);
    OBJ(c)->pos = o->pos;
    MEM32(A32(1)) = c;
    RET(S_OK, 2);
}

/* IStorage */
static node_t *named(uint32_t self, uint32_t wname, int type, int create, uint32_t *hr) {
    obj_t *o = OBJ(self);
    const uint16_t *name = (const uint16_t *)(uintptr_t)wname;
    node_t *c = find_child(o->node, name);
    *hr = S_OK;
    if (create) {
        if (!o->file->writable) { *hr = STG_E_ACCESSDENIED; return NULL; }
        if (c) unlink_child(c);
        o->file->dirty = 1;
        return add_child(o->node, name, type);
    }
    if (!c || c->type != type) { *hr = STG_E_FILENOTFOUND; return NULL; }
    return c;
}
static void st_CreateStream(void) {                      /* (this, name, mode, r1, r2, &stm) */
    uint32_t hr;
    node_t *n = named(A32(0), A32(1), 2, 1, &hr);
    if (!n) RET(hr, 6);
    MEM32(A32(5)) = new_obj(g_vt_stm, OBJ(A32(0))->file, n);
    RET(S_OK, 6);
}
static void st_OpenStream(void) {                        /* (this, name, r1, mode, r2, &stm) */
    uint32_t hr;
    node_t *n = named(A32(0), A32(1), 2, 0, &hr);
    if (A32(5)) MEM32(A32(5)) = n ? new_obj(g_vt_stm, OBJ(A32(0))->file, n) : 0;
    RET(hr, 6);
}
static void st_CreateStorage(void) {                     /* (this, name, mode, r1, r2, &stg) */
    uint32_t hr;
    node_t *n = named(A32(0), A32(1), 1, 1, &hr);
    if (!n) RET(hr, 6);
    MEM32(A32(5)) = new_obj(g_vt_stg, OBJ(A32(0))->file, n);
    RET(S_OK, 6);
}
static void st_OpenStorage(void) {                       /* (this, name, priority, mode, exclude, r, &stg) */
    uint32_t hr;
    node_t *n = named(A32(0), A32(1), 1, 0, &hr);
    if (A32(6)) MEM32(A32(6)) = n ? new_obj(g_vt_stg, OBJ(A32(0))->file, n) : 0;
    RET(hr, 7);
}
static void st_Commit(void) { commit(OBJ(A32(0))->file); RET(S_OK, 2); }
static void st_DestroyElement(void) {
    obj_t *o = OBJ(A32(0));
    node_t *c = find_child(o->node, (const uint16_t *)APTR(1));
    if (!c) RET(STG_E_FILENOTFOUND, 2);
    unlink_child(c);
    o->file->dirty = 1;
    RET(S_OK, 2);
}
static void st_SetClass(void) { obj_t *o = OBJ(A32(0)); memcpy(o->node->clsid, APTR(1), 16); o->file->dirty = 1; RET(S_OK, 2); }
static void st_Stat(void) { stat_of(A32(1), OBJ(A32(0))->node, A32(2) & 1); RET(S_OK, 3); }
static void x_notimpl_2(void) { RET(E_NOTIMPL, 2); }
static void x_notimpl_4(void) { RET(E_NOTIMPL, 4); }
static void x_notimpl_5(void) { RET(E_NOTIMPL, 5); }
static void x_notimpl_3(void) { RET(E_NOTIMPL, 3); }
static void x_ok_1(void) { RET(S_OK, 1); }
static void x_ok_3(void) { RET(S_OK, 3); }

static void vtables(void) {
    if (g_vt_stg) return;
    static const win32hle_shim stm[] = {
        { "IStream::QueryInterface", sm_QueryInterface }, { "IStream::AddRef", hle_com_AddRef },
        { "IStream::Release", x_Release }, { "IStream::Read", sm_Read }, { "IStream::Write", sm_Write },
        { "IStream::Seek", sm_Seek }, { "IStream::SetSize", sm_SetSize }, { "IStream::CopyTo", sm_CopyTo },
        { "IStream::Commit", sm_Commit }, { "IStream::Revert", sm_Revert }, { "IStream::LockRegion", sm_LockRegion },
        { "IStream::UnlockRegion", sm_LockRegion }, { "IStream::Stat", sm_Stat }, { "IStream::Clone", sm_Clone }, { 0, 0 } };
    static const win32hle_shim stg[] = {
        { "IStorage::QueryInterface", st_QueryInterface }, { "IStorage::AddRef", hle_com_AddRef },
        { "IStorage::Release", x_Release }, { "IStorage::CreateStream", st_CreateStream },
        { "IStorage::OpenStream", st_OpenStream }, { "IStorage::CreateStorage", st_CreateStorage },
        { "IStorage::OpenStorage", st_OpenStorage }, { "IStorage::CopyTo", x_notimpl_5 },
        { "IStorage::MoveElementTo", x_notimpl_5 }, { "IStorage::Commit", st_Commit }, { "IStorage::Revert", x_ok_1 },
        { "IStorage::EnumElements", x_notimpl_5 }, { "IStorage::DestroyElement", st_DestroyElement },
        { "IStorage::RenameElement", x_notimpl_3 }, { "IStorage::SetElementTimes", x_notimpl_5 },
        { "IStorage::SetClass", st_SetClass }, { "IStorage::SetStateBits", x_ok_3 }, { "IStorage::Stat", st_Stat }, { 0, 0 } };
    g_vt_stm = hle_com_vtable(stm);
    g_vt_stg = hle_com_vtable(stg);
    (void)x_notimpl_2, (void)x_notimpl_4;
}

static void wide_path(uint32_t w, char *out, size_t n) {
    char g[1024];
    const uint16_t *s = (const uint16_t *)(uintptr_t)w;
    size_t k = 0;
    for (; s && s[k] && k + 1 < sizeof g; k++) g[k] = (char)(s[k] < 256 ? s[k] : '_');
    g[k] = 0;
    hle_host_path(g, out, n);
}

static void s_StgCreateDocfile(void) {                   /* (name, mode, reserved, &stg) */
    vtables();
    char path[1024];
    if (!A32(0) || !A32(3)) RET(STG_E_INVALIDPOINTER, 4);
    wide_path(A32(0), path, sizeof path);
    FILE *t = fopen(path, "rb");
    if (t && !(A32(1) & STGM_CREATE)) { fclose(t); RET(STG_E_FILEALREADYEXISTS, 4); }
    if (t) fclose(t);
    file_t *f = (file_t *)calloc(1, sizeof *f);
    snprintf(f->path, sizeof f->path, "%s", path);
    f->root = (node_t *)calloc(1, sizeof(node_t));
    f->root->type = 5, f->writable = 1, f->dirty = 1;
    MEM32(A32(3)) = new_obj(g_vt_stg, f, f->root);
    if (!write_cfb(path, f->root)) { fprintf(stderr, "[storage] cannot create %s\n", path); }
    RET(S_OK, 4);
}
static void s_StgOpenStorage(void) {                     /* (name, priority, mode, exclude, reserved, &stg) */
    vtables();
    char path[1024];
    if (!A32(0) || !A32(5)) RET(STG_E_INVALIDPOINTER, 6);
    wide_path(A32(0), path, sizeof path);
    FILE *fp = fopen(path, "rb");
    if (!fp) RET(STG_E_FILENOTFOUND, 6);
    fseek(fp, 0, SEEK_END);
    long n = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint8_t *b = (uint8_t *)malloc((size_t)n + 1);
    size_t got = fread(b, 1, (size_t)n, fp);
    fclose(fp);
    node_t *root;
    int ok = got == (size_t)n && read_cfb(b, (size_t)n, &root);
    free(b);
    if (!ok) RET(STG_E_INVALIDHEADER, 6);
    file_t *f = (file_t *)calloc(1, sizeof *f);
    snprintf(f->path, sizeof f->path, "%s", path);
    f->root = root, f->writable = (A32(2) & 3u) != 0;
    MEM32(A32(5)) = new_obj(g_vt_stg, f, root);
    RET(S_OK, 6);
}

/* OleSaveToStream / OleLoadFromStream: the class ID, then the object's own
 * IPersistStream::Save / Load (vtable 6 / 5; GetClassID is 3). */
static uint32_t vcall(uint32_t obj, int slot, int nargs, const uint32_t *args) {
    uint32_t a[8] = { obj };
    for (int i = 0; i < nargs; i++) a[1 + i] = args[i];
    return hle_call_guest(MEM32(MEM32(obj) + 4u * (uint32_t)slot), nargs + 1, a);
}
static void s_OleSaveToStream(void) {                    /* (persist stream, stream) */
    uint32_t ps = A32(0), stm = A32(1);
    uint8_t clsid[16];                                   /* locals: Save may save objects of its own */
    if (!ps) {                                           /* a null object: a null class ID */
        memset(clsid, 0, 16);
        uint32_t w[3] = { (uint32_t)(uintptr_t)clsid, 16, 0 };
        RET(vcall(stm, 4, 3, w), 2);
    }
    uint32_t a[1] = { (uint32_t)(uintptr_t)clsid };
    uint32_t hr = vcall(ps, 3, 1, a);
    if (hr) RET(hr, 2);
    uint32_t w[3] = { (uint32_t)(uintptr_t)clsid, 16, 0 };
    if ((hr = vcall(stm, 4, 3, w))) RET(hr, 2);
    uint32_t s[2] = { stm, 1 };
    RET(vcall(ps, 6, 2, s), 2);
}
static void s_OleLoadFromStream(void) {                  /* (stream, iid, &obj) */
    uint32_t stm = A32(0), out = A32(2);
    uint8_t clsid[16];
    static const uint8_t IID_IPersistStream[16] = { 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0, 0, 0, 0, 0, 0, 0x46 };
    uint32_t got = 0, r[3] = { (uint32_t)(uintptr_t)clsid, 16, (uint32_t)(uintptr_t)&got };
    if (out) MEM32(out) = 0;
    uint32_t hr = vcall(stm, 3, 3, r);
    if (hr || got != 16) RET(hr ? hr : STG_E_READFAULT, 3);
    /* CoCreateInstance(clsid, NULL, CLSCTX_INPROC_SERVER, iid, out), through the shim */
    uint32_t cc[5] = { (uint32_t)(uintptr_t)clsid, 0, 1, A32(1), out };
    hr = hle_call_guest(hle_resolve("CoCreateInstance"), 5, cc);
    if (hr) RET(hr, 3);
    uint32_t ps = 0;
    uint32_t q[2] = { (uint32_t)(uintptr_t)IID_IPersistStream, (uint32_t)(uintptr_t)&ps };
    if ((hr = vcall(MEM32(out), 0, 2, q))) RET(hr, 3);
    uint32_t l[1] = { stm };
    hr = vcall(ps, 5, 1, l);
    vcall(ps, 2, 0, NULL);
    RET(hr, 3);
}

const win32hle_shim win32hle_storage[] = {
    { "StgCreateDocfile", s_StgCreateDocfile }, { "StgOpenStorage", s_StgOpenStorage },
    { "OleSaveToStream", s_OleSaveToStream }, { "OleLoadFromStream", s_OleLoadFromStream },
    { 0, 0 }
};

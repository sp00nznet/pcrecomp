/*
 * ole32.c - OLE32 and OLEAUT32: COM's bookkeeping, and a way for a host to
 * serve COM objects of its own.
 *
 * A COM object a guest holds is guest memory whose first dword points at a
 * vtable of method addresses; on win32hle those are shim VAs, so a guest's
 * `call [eax+0Ch]` dispatches to C (hle_com_vtable builds one from a shim
 * table). CoCreateInstance asks the classes a host registered
 * (hle_com_register_class), and otherwise answers REGDB_E_CLASSNOTREG, as for
 * a COM server that is not installed.
 *
 * Structured storage, OLE embedding and type libraries are not here: they
 * fail with E_NOTIMPL.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "win32hle.h"

#define S_OK                 0u
#define E_NOTIMPL            0x80004001u
#define E_NOINTERFACE        0x80004002u
#define E_FAIL               0x80004005u
#define REGDB_E_CLASSNOTREG  0x80040154u
#define CO_E_CLASSSTRING     0x800401F3u

/* ---- GUIDs ---- */
void hle_guid_string(const uint8_t *g, char *out) {      /* {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} */
    sprintf(out, "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", *(const uint32_t *)g,
            *(const uint16_t *)(g + 4), *(const uint16_t *)(g + 6), g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
}
static int parse_guid(const char *s, uint8_t *g) {
    unsigned a, b, c, d[8];
    if (sscanf(s, "{%8x-%4x-%4x-%2x%2x-%2x%2x%2x%2x%2x%2x}", &a, &b, &c, &d[0], &d[1], &d[2], &d[3], &d[4], &d[5], &d[6], &d[7]) != 11)
        return 0;
    *(uint32_t *)g = a, *(uint16_t *)(g + 4) = (uint16_t)b, *(uint16_t *)(g + 6) = (uint16_t)c;
    for (int i = 0; i < 8; i++) g[8 + i] = (uint8_t)d[i];
    return 1;
}

/* ---- host-served classes ---- */
#define MAX_CLASSES 16
static struct { uint8_t clsid[16]; uint32_t (*create)(const uint8_t *iid, uint32_t *out); } g_class[MAX_CLASSES];
static int g_nclass;
void hle_com_register_class(const uint8_t *clsid, uint32_t (*create)(const uint8_t *iid, uint32_t *out)) {
    if (g_nclass < MAX_CLASSES) memcpy(g_class[g_nclass].clsid, clsid, 16), g_class[g_nclass++].create = create;
}

/* A vtable of shim VAs, in guest-readable memory (it lives for the run). */
uint32_t hle_com_vtable(const win32hle_shim *methods) {
    int n = 0;
    while (methods[n].name) n++;
    uint32_t *vt = (uint32_t *)calloc((size_t)n + 1, 4);
    win32hle_register(methods);
    for (int i = 0; i < n; i++) vt[i] = hle_resolve(methods[i].name);
    return (uint32_t)(uintptr_t)vt;
}
/* An object: the vtable pointer, a reference count, then `size` - 8 bytes of
 * the host's own state. */
uint32_t hle_com_new(uint32_t vtable, uint32_t size) {
    uint32_t *o = (uint32_t *)calloc(1, size < 8 ? 8 : size);
    o[0] = vtable, o[1] = 1;
    return (uint32_t)(uintptr_t)o;
}
/* IUnknown for such objects: any interface is this one (a host serves one
 * interface per object), counted at +4, freed at zero. */
void hle_com_QueryInterface(void) {                      /* (this, iid, &out) */
    uint32_t self = A32(0);
    if (A32(2)) MEM32(A32(2)) = self;
    MEM32(self + 4)++;
    RET(S_OK, 3);
}
void hle_com_AddRef(void) { RET(++MEM32(A32(0) + 4), 1); }
void hle_com_Release(void) {
    uint32_t self = A32(0), n = --MEM32(self + 4);
    if (!n) free((void *)(uintptr_t)self);
    RET(n, 1);
}

/* Class objects the guest registered itself (CoRegisterClassObject): a game
 * that serves its own classes in process (Tiberian Sun's locomotors) creates
 * them through COM, so CoCreateInstance has to find its factories. */
#define MAX_GUEST_CLASSES 64
static struct { uint8_t clsid[16]; uint32_t unk, cookie; } g_guest_class[MAX_GUEST_CLASSES];
static uint32_t g_next_cookie = 0x100;
static const uint8_t IID_IClassFactory[16] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                               0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 };
static uint32_t vcall(uint32_t obj, int slot, int nargs, const uint32_t *args) {
    uint32_t a[8] = { obj };
    for (int i = 0; i < nargs; i++) a[1 + i] = args[i];
    return hle_call_guest(MEM32(MEM32(obj) + 4u * (uint32_t)slot), nargs + 1, a);
}

static void o_CoCreateInstance(void) {                   /* (clsid, outer, ctx, iid, &out) */
    const uint8_t *clsid = (const uint8_t *)APTR(0);
    char s[40];
    if (A32(4)) MEM32(A32(4)) = 0;
    for (int i = 0; clsid && i < g_nclass; i++)
        if (!memcmp(g_class[i].clsid, clsid, 16)) RET(g_class[i].create((const uint8_t *)APTR(3), (uint32_t *)APTR(4)), 5);
    for (int i = 0; clsid && i < MAX_GUEST_CLASSES; i++)
        if (g_guest_class[i].unk && !memcmp(g_guest_class[i].clsid, clsid, 16)) {
            static uint32_t cf;                          /* (re-entrant enough: read before the next call) */
            uint32_t qi[2] = { (uint32_t)(uintptr_t)IID_IClassFactory, (uint32_t)(uintptr_t)&cf };
            uint32_t hr = vcall(g_guest_class[i].unk, 0, 2, qi);           /* QueryInterface */
            if (hr) RET(hr, 5);
            uint32_t f = cf, ci[3] = { A32(1), A32(3), A32(4) };
            hr = vcall(f, 3, 3, ci);                                        /* IClassFactory::CreateInstance */
            vcall(f, 2, 0, NULL);                                           /* Release */
            RET(hr, 5);
        }
    if (clsid) hle_guid_string(clsid, s);
    fprintf(stderr, "[ole32] CoCreateInstance(%s): no such class on this host\n", clsid ? s : "(null)");
    RET(REGDB_E_CLASSNOTREG, 5);
}
static void o_OleInitialize(void)   { RET(S_OK, 1); }
static void o_OleUninitialize(void) { RETV(0); }
static void o_CoInitialize(void)    { RET(S_OK, 1); }
static void o_CoUninitialize(void)  { RETV(0); }
static void o_CoRegisterClassObject(void) {              /* (clsid, unk, ctx, flags, &cookie) */
    for (int i = 0; i < MAX_GUEST_CLASSES; i++)
        if (!g_guest_class[i].unk) {
            memcpy(g_guest_class[i].clsid, APTR(0), 16);
            g_guest_class[i].unk = A32(1), g_guest_class[i].cookie = g_next_cookie++;
            vcall(A32(1), 1, 0, NULL);                   /* AddRef: COM holds it */
            if (A32(4)) MEM32(A32(4)) = g_guest_class[i].cookie;
            RET(S_OK, 5);
        }
    RET(E_FAIL, 5);
}
static void o_CoRevokeClassObject(void) {
    for (int i = 0; i < MAX_GUEST_CLASSES; i++)
        if (g_guest_class[i].unk && g_guest_class[i].cookie == A32(0)) {
            uint32_t u = g_guest_class[i].unk;
            g_guest_class[i].unk = 0;
            vcall(u, 2, 0, NULL);                        /* Release */
            RET(S_OK, 1);
        }
    RET(0x80040011u /* CO_E_OBJNOTREG */, 1);
}
static void o_CoDisconnectObject(void)    { RET(S_OK, 2); }
static void o_CoFileTimeNow(void) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t ft = ((uint64_t)ts.tv_sec + 11644473600ull) * 10000000ull + (uint64_t)ts.tv_nsec / 100u;
    if (A32(0)) MEM32(A32(0)) = (uint32_t)ft, MEM32(A32(0) + 4) = (uint32_t)(ft >> 32);
    RET(S_OK, 1);
}
static void o_CLSIDFromString(void) {                    /* (wide string, &clsid) */
    const uint16_t *w = (const uint16_t *)APTR(0);
    char s[64];
    int k = 0;
    for (; w && w[k] && k < 63; k++) s[k] = (char)w[k];
    s[k] = 0;
    RET(parse_guid(s, (uint8_t *)APTR(1)) ? S_OK : CO_E_CLASSSTRING, 2);
}
static void o_StringFromGUID2(void) {                    /* (guid, wide buf, n) -> chars incl. NUL */
    char s[40];
    uint16_t *w = (uint16_t *)APTR(1);
    hle_guid_string((const uint8_t *)APTR(0), s);
    if ((int)A32(2) < 39) RET(0, 3);
    for (int i = 0; i < 39; i++) w[i] = (uint8_t)s[i];
    RET(39, 3);
}
static void o_StringFromCLSID(void) {                    /* (clsid, &wide string) */
    char s[40];
    uint16_t *w = (uint16_t *)hle_alloc(80);
    hle_guid_string((const uint8_t *)APTR(0), s);
    for (int i = 0; i < 39; i++) w[i] = (uint8_t)s[i];
    if (A32(1)) MEM32(A32(1)) = (uint32_t)(uintptr_t)w;
    RET(S_OK, 2);
}
/* OleRun: an object a host serves is in process, so always running. */
static void o_OleRun(void) { RET(A32(0) ? S_OK : E_FAIL, 1); }
static void o_notimpl_1(void) { RET(E_NOTIMPL, 1); }
static void o_notimpl_2(void) { RET(E_NOTIMPL, 2); }
static void o_notimpl_4(void) { RET(E_NOTIMPL, 4); }

/* ---- OLEAUT32: BSTRs (length-prefixed wide strings) and VARIANTs ---- */
static void a_SysAllocString(void) {
    const uint16_t *w = (const uint16_t *)APTR(0);
    uint32_t n = 0;
    if (!w) RET(0, 1);
    while (w[n]) n++;
    uint8_t *b = (uint8_t *)hle_alloc(4 + 2 * n + 2);
    *(uint32_t *)b = 2 * n;
    memcpy(b + 4, w, 2 * n);
    RETP(b + 4, 1);
}
static void a_SysFreeString(void) { if (A32(0)) hle_free((uint8_t *)APTR(0) - 4); RETV(1); }
static void a_VariantInit(void)   { if (A32(0)) memset(APTR(0), 0, 16); RETV(1); }
static void a_VariantClear(void)  { if (A32(0)) memset(APTR(0), 0, 16); RET(S_OK, 1); }
static void a_VariantChangeType(void) { RET(E_NOTIMPL, 4); }
static void a_GetErrorInfo(void)  { if (A32(1)) MEM32(A32(1)) = 0; RET(1u /* S_FALSE */, 2); }

const win32hle_shim win32hle_ole32[] = {
    { "CoCreateInstance",      o_CoCreateInstance },
    { "OleInitialize",         o_OleInitialize },
    { "OleUninitialize",       o_OleUninitialize },
    { "CoInitialize",          o_CoInitialize },
    { "CoUninitialize",        o_CoUninitialize },
    { "CoRegisterClassObject", o_CoRegisterClassObject },
    { "CoRevokeClassObject",   o_CoRevokeClassObject },
    { "CoDisconnectObject",    o_CoDisconnectObject },
    { "CoFileTimeNow",         o_CoFileTimeNow },
    { "CLSIDFromString",       o_CLSIDFromString },
    { "StringFromGUID2",       o_StringFromGUID2 },
    { "StringFromCLSID",       o_StringFromCLSID },
    { "OleRun",                o_OleRun },
#define AUT(ord, name, fn) { "oleaut32.dll#" #ord, fn }, { name, fn }
    AUT(2, "SysAllocString",        a_SysAllocString),
    AUT(6, "SysFreeString",         a_SysFreeString),
    AUT(8, "VariantInit",           a_VariantInit),
    AUT(9, "VariantClear",          a_VariantClear),
    AUT(12, "VariantChangeType",    a_VariantChangeType),
    AUT(200, "GetErrorInfo",        a_GetErrorInfo),
    AUT(201, "SetErrorInfo",        o_notimpl_2),
    AUT(202, "CreateErrorInfo",     o_notimpl_1),
    AUT(161, "LoadTypeLib",         o_notimpl_2),
    AUT(33, "RegisterActiveObject", o_notimpl_4),
    AUT(34, "RevokeActiveObject",   o_notimpl_2),
    { 0, 0 }
};

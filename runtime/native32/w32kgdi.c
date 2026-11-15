/*
 * w32kgdi: GDI's half of win32k, for a lifted Windows 2000 gdi32 on the
 * host's GDI (syscall32.c's win32k table).
 *
 * gdi32 is a client of state win32k shares with it, read directly:
 *
 *   handle table  Peb->GdiSharedHandleTable, 0x4000 GDI_TABLE_ENTRYs of 16
 *                 bytes. gdi32 validates a handle h against entry
 *                 [h & 0xFFFF] (an index of 0x4000 or more is invalid): +0x08
 *                 the handle's high word, +0x0A its type (h >> 16 & 0x1F; 1 a
 *                 DC), +0x04 the owning process (pid, low bits clear), +0x0C
 *                 the object's user-mode attributes.
 *   DC_ATTR       a DC's attributes, which gdi32 changes in user mode and
 *                 win32k reads when it draws: +0x04 dirty flags, +0x08 the
 *                 selected brush, +0x0C the selected pen (gdi32's
 *                 SelectObject sets them, no system call), +0x38 the ROP2,
 *                 +0x3C/+0x40 the current position (Windows 2000 SP4
 *                 offsets, from the lifted gdi32).
 *
 * Here the table is ours, in that layout, over the host's GDI objects. The
 * guest never sees a host handle: a host's index runs to 0xFFFF, which
 * Windows 2000's gdi32 rejects. Each host object gets a guest handle, the
 * host's high word (the type codes are the same) with an index of ours below
 * 0x4000; the NtGdi* services translate both ways, and so do the hooks on
 * host user32's DC functions in its proxy image (BeginPaint, GetDC, ...,
 * EndPaint, ReleaseDC). Before a draw the DC's attributes go onto the host
 * DC.
 *
 * The table, the translation and DC_ATTR are what a full win32k (user32
 * lifted too) will share: native32_gdi_handle, native32_gdi_host and
 * native32_gdi_attr are its entry points; the services and hooks are this
 * host-user32 configuration's.
 *
 * ponytail: the attributes synced are the ones these services read (brush,
 * pen, ROP2, current position); add fields (colours, brush origin, text) with the
 * services that need them. The host->guest lookup is a linear scan over the
 * live entries; a hash when a program keeps thousands of objects.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "native32.h"

#define GDI_ENTRIES 0x4000
#define ATTR_SIZE 0x400

static uint8_t* g_table;                 /* the shared section: entries, then gdi32's shared data */
static uint32_t g_host[GDI_ENTRIES];     /* guest index -> host handle */
static int g_top = 1;                    /* index 0 is never used */

static uint32_t ea(int i) { return (uint32_t)(uintptr_t)(g_table + 16 * i); }

/* The host object behind a guest handle (0 for none or a stale handle). */
uint32_t native32_gdi_host(uint32_t g) {
    int i = (int)(g & 0xFFFF);
    if (!g || !g_table || i >= GDI_ENTRIES || !g_host[i] || MEM16(ea(i) + 8) != (g >> 16)) return g ? 0 : 0;
    return g_host[i];
}

uint8_t* native32_gdi_attr(uint32_t g) {
    return native32_gdi_host(g) ? (uint8_t*)(uintptr_t)MEM32(ea((int)(g & 0xFFFF)) + 12) : NULL;
}

/* The guest handle for a host GDI object, entered in the table the first
 * time it is seen. */
uint32_t native32_gdi_handle(uint32_t h) {
    if (!h || !g_table) return h;
    int i, free_i = 0;
    for (i = 1; i < g_top; i++) {
        if (g_host[i] == h) return (h & 0xFFFF0000u) | (uint32_t)i;
        if (!free_i && !g_host[i]) free_i = i;
    }
    i = free_i ? free_i : g_top < GDI_ENTRIES ? g_top++ : 0;
    if (!i) { fprintf(stderr, "[gdi] guest handle table full\n"); return 0; }
    uint32_t type = (h >> 16) & 0x1F, e = ea(i);
    uint8_t* attr = (uint8_t*)(uintptr_t)MEM32(e + 12);
    if (type == 1) {                                                   /* a DC: its attributes */
        POINT p;
        if (!attr) attr = (uint8_t*)calloc(1, ATTR_SIZE);
        else memset(attr, 0, ATTR_SIZE);
        attr[0x38] = (uint8_t)GetROP2((HDC)(uintptr_t)h);
        *(uint32_t*)(attr + 0x08) = 0;                     /* set below, once this DC has its index */
        *(uint32_t*)(attr + 0x0C) = 0;
        GetCurrentPositionEx((HDC)(uintptr_t)h, &p);
        *(int32_t*)(attr + 0x3C) = p.x;
        *(int32_t*)(attr + 0x40) = p.y;
    }
    g_host[i] = h;
    MEM32(e) = 0x80000000u | (uint32_t)i;                              /* "kernel object": nonzero */
    MEM32(e + 4) = GetCurrentProcessId() & ~3u;
    MEM16(e + 8) = (uint16_t)(h >> 16);
    MEM8(e + 10) = (uint8_t)type;
    MEM32(e + 12) = type == 1 ? (uint32_t)(uintptr_t)attr : 0;
    if (type == 1) {                                        /* the brush and pen it starts with */
        *(uint32_t*)(attr + 0x08) = native32_gdi_handle((uint32_t)(uintptr_t)GetCurrentObject((HDC)(uintptr_t)h, OBJ_BRUSH));
        *(uint32_t*)(attr + 0x0C) = native32_gdi_handle((uint32_t)(uintptr_t)GetCurrentObject((HDC)(uintptr_t)h, OBJ_PEN));
    }
    return (h & 0xFFFF0000u) | (uint32_t)i;
}

static void forget(uint32_t g) {
    int i = (int)(g & 0xFFFF);
    if (native32_gdi_host(g)) g_host[i] = 0, MEM32(ea(i)) = 0, MEM16(ea(i) + 8) = 0;
}

#define HOST(x) native32_gdi_host((uint32_t)(x))
#define GUEST(x) native32_gdi_handle((uint32_t)(uintptr_t)(x))

/* A guest DC as the host's, with its user-mode attributes applied. */
static HDC dc(uint32_t g) {
    HDC h = (HDC)(uintptr_t)HOST(g);
    uint8_t* a = native32_gdi_attr(g);
    if (h && a) {
        uint32_t br = HOST(*(uint32_t*)(a + 0x08)), pen = HOST(*(uint32_t*)(a + 0x0C));
        if (br) SelectObject(h, (HGDIOBJ)(uintptr_t)br);
        if (pen) SelectObject(h, (HGDIOBJ)(uintptr_t)pen);
        SetROP2(h, a[0x38] ? a[0x38] : R2_COPYPEN);
        MoveToEx(h, *(int32_t*)(a + 0x3C), *(int32_t*)(a + 0x40), NULL);
    }
    return h;
}

static void dc_back(uint32_t g) {          /* after a draw that moves the pen */
    uint8_t* a = native32_gdi_attr(g);
    POINT p;
    if (a && GetCurrentPositionEx((HDC)(uintptr_t)HOST(g), &p)) *(int32_t*)(a + 0x3C) = p.x, *(int32_t*)(a + 0x40) = p.y;
}

/* ---- the services (Windows 2000 argument lists) -------------------------- */
static uint32_t s_init(uint32_t* a) {
    (void)a;
    if (!g_table) {
        /* the handle table and the shared data after it (gdi32 reads +0x40094) */
        g_table = (uint8_t*)VirtualAlloc(NULL, 0x80000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        MEM32(native32_guest_peb + 0x94) = (uint32_t)(uintptr_t)g_table;
    }
    return 1;
}
static uint32_t s_zero(uint32_t* a) { (void)a; return 0; }
static uint32_t s_one(uint32_t* a) { (void)a; return 1; }
static uint32_t s_stock(uint32_t* a) { return GUEST(GetStockObject((int)a[0])); }
static uint32_t s_compat_dc(uint32_t* a) { return GUEST(CreateCompatibleDC((HDC)(uintptr_t)HOST(a[0]))); }
static uint32_t s_compat_bitmap(uint32_t* a) {
    return GUEST(CreateCompatibleBitmap((HDC)(uintptr_t)HOST(a[0]), a[1], a[2]));
}
static uint32_t s_pen(uint32_t* a) { return GUEST(CreatePen((int)a[0], (int)a[1], a[2])); }
static uint32_t s_brush(uint32_t* a) { return GUEST(CreateSolidBrush(a[0])); }
static uint32_t s_select(uint32_t* a) {
    return GUEST(SelectObject((HDC)(uintptr_t)HOST(a[0]), (HGDIOBJ)(uintptr_t)HOST(a[1])));
}
static uint32_t s_delete(uint32_t* a) {
    uint32_t h = HOST(a[0]);
    BOOL r = !h ? FALSE : ((h >> 16) & 0x1F) == 1 ? DeleteDC((HDC)(uintptr_t)h) : DeleteObject((HGDIOBJ)(uintptr_t)h);
    if (r) forget(a[0]);
    return r;
}
static uint32_t s_bitblt(uint32_t* a) {
    return BitBlt(dc(a[0]), a[1], a[2], a[3], a[4], a[5] ? dc(a[5]) : NULL, a[6], a[7], a[8]);
}
static uint32_t s_lineto(uint32_t* a) {
    BOOL r = LineTo(dc(a[0]), (int)a[1], (int)a[2]);
    dc_back(a[0]);
    return r;
}
static uint32_t s_moveto(uint32_t* a) {        /* NtGdiMoveTo(hdc, x, y, POINT* old) */
    BOOL r = MoveToEx(dc(a[0]), (int)a[1], (int)a[2], (POINT*)(uintptr_t)a[3]);
    dc_back(a[0]);
    return r;
}
static uint32_t s_setpixel(uint32_t* a) { return SetPixel(dc(a[0]), a[1], a[2], a[3]); }
static uint32_t s_devcaps(uint32_t* a) { return GetDeviceCaps((HDC)(uintptr_t)HOST(a[0]), (int)a[1]); }
static uint32_t s_setlayout(uint32_t* a) { return SetLayout((HDC)(uintptr_t)HOST(a[0]), a[2]); }
/* NtGdiSetDIBitsToDeviceInternal(hdc, xDst, yDst, cx, cy, xSrc, ySrc, iStartScan,
 * cNumScan, pInitBits, pbmi, iUsage, cjMaxBits, cjMaxInfo, bTransform, hcmXform) */
static uint32_t s_setdibits(uint32_t* a) {
    return SetDIBitsToDevice(dc(a[0]), a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8],
                             (void*)(uintptr_t)a[9], (BITMAPINFO*)(uintptr_t)a[10], a[11]);
}

/* ---- host user32's DCs, translated where the guest sees them ------------- */
static HDC WINAPI hk_BeginPaint(HWND w, PAINTSTRUCT* ps) {
    HDC h = BeginPaint(w, ps);
    if (ps) ps->hdc = (HDC)(uintptr_t)GUEST(ps->hdc);
    return (HDC)(uintptr_t)GUEST(h);
}
static BOOL WINAPI hk_EndPaint(HWND w, PAINTSTRUCT* ps) {
    uint32_t g = ps ? (uint32_t)(uintptr_t)ps->hdc : 0;
    if (ps) ps->hdc = (HDC)(uintptr_t)HOST(g);
    BOOL r = EndPaint(w, ps);
    if (ps) forget(g), ps->hdc = (HDC)(uintptr_t)g;
    return r;
}
static HDC WINAPI hk_GetDC(HWND w) { return (HDC)(uintptr_t)GUEST(GetDC(w)); }
static HDC WINAPI hk_GetWindowDC(HWND w) { return (HDC)(uintptr_t)GUEST(GetWindowDC(w)); }
static HDC WINAPI hk_GetDCEx(HWND w, HRGN r, DWORD f) { return (HDC)(uintptr_t)GUEST(GetDCEx(w, r, f)); }
static int WINAPI hk_ReleaseDC(HWND w, HDC g) {
    int r = ReleaseDC(w, (HDC)(uintptr_t)HOST((uint32_t)(uintptr_t)g));
    forget((uint32_t)(uintptr_t)g);
    return r;
}

/* A class's background brush crosses into host user32 (winmine's
 * GetStockObject(LTGRAY_BRUSH)); a COLOR_* + 1 value is no handle and passes. */
#define BRUSH_IN(b) ((uint32_t)(uintptr_t)(b) > 0x40 && HOST((uint32_t)(uintptr_t)(b)) ? \
                     (HBRUSH)(uintptr_t)HOST((uint32_t)(uintptr_t)(b)) : (b))
static ATOM WINAPI hk_RegisterClassW(const WNDCLASSW* c) {
    WNDCLASSW w = *c;
    w.hbrBackground = BRUSH_IN(w.hbrBackground);
    return RegisterClassW(&w);
}
static ATOM WINAPI hk_RegisterClassA(const WNDCLASSA* c) {
    WNDCLASSA w = *c;
    w.hbrBackground = BRUSH_IN(w.hbrBackground);
    return RegisterClassA(&w);
}
static ATOM WINAPI hk_RegisterClassExW(const WNDCLASSEXW* c) {
    WNDCLASSEXW w = *c;
    w.hbrBackground = BRUSH_IN(w.hbrBackground);
    return RegisterClassExW(&w);
}
static ATOM WINAPI hk_RegisterClassExA(const WNDCLASSEXA* c) {
    WNDCLASSEXA w = *c;
    w.hbrBackground = BRUSH_IN(w.hbrBackground);
    return RegisterClassExA(&w);
}

void native32_gdi_install(void) {
    native32_nt_proxy_hook("RegisterClassW", (void*)hk_RegisterClassW);
    native32_nt_proxy_hook("RegisterClassA", (void*)hk_RegisterClassA);
    native32_nt_proxy_hook("RegisterClassExW", (void*)hk_RegisterClassExW);
    native32_nt_proxy_hook("RegisterClassExA", (void*)hk_RegisterClassExA);
    static const struct { const char* name; native32_syscall_fn fn; } svc[] = {
        { "NtGdiInit", s_init }, { "NtGdiQueryFontAssocInfo", s_zero }, { "NtGdiGetStockObject", s_stock },
        { "NtGdiCreateCompatibleDC", s_compat_dc }, { "NtGdiCreateCompatibleBitmap", s_compat_bitmap },
        { "NtGdiCreatePen", s_pen }, { "NtGdiCreateSolidBrush", s_brush },
        { "NtGdiSelectBitmap", s_select }, { "NtGdiSelectBrush", s_select }, { "NtGdiSelectPen", s_select },
        { "NtGdiSelectFont", s_select }, { "NtGdiDeleteObjectApp", s_delete }, { "NtGdiBitBlt", s_bitblt },
        { "NtGdiLineTo", s_lineto }, { "NtGdiMoveTo", s_moveto }, { "NtGdiSetPixel", s_setpixel },
        { "NtGdiGetDeviceCaps", s_devcaps }, { "NtGdiSetLayout", s_setlayout },
        { "NtGdiSetDIBitsToDeviceInternal", s_setdibits }, { "NtGdiFlush", s_one },
    };
    for (int i = 0; i < (int)(sizeof svc / sizeof svc[0]); i++) native32_nt_win32k_override(svc[i].name, svc[i].fn);
    native32_nt_proxy_hook("BeginPaint", (void*)hk_BeginPaint);
    native32_nt_proxy_hook("EndPaint", (void*)hk_EndPaint);
    native32_nt_proxy_hook("GetDC", (void*)hk_GetDC);
    native32_nt_proxy_hook("GetWindowDC", (void*)hk_GetWindowDC);
    native32_nt_proxy_hook("GetDCEx", (void*)hk_GetDCEx);
    native32_nt_proxy_hook("ReleaseDC", (void*)hk_ReleaseDC);
}

/* Windows 2000's gdi32 has no entry point: user32's DllMain calls its
 * GdiDllInitialize. With the host's user32 nobody would; call after the
 * guest's loader is done (native32_nt_boot). 0 if gdi32 has no such export. */
int native32_gdi_start(uint32_t gdi32) {
    uint32_t init = native32_export(gdi32, "GdiDllInitialize");
    if (!init) return 0;
    uint32_t a[3] = { gdi32, DLL_PROCESS_ATTACH, 0 };
    mach_enter();
    uint32_t sp = g_esp;
    native32_call_guest(init, 3, a);
    g_esp = sp;
    mach_leave();
    return 1;
}

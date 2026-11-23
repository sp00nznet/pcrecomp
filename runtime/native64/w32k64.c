/*
 * w32k64.c: win32k for a lifted 64-bit user32/gdi32 (native64.c) over the
 * host's windows and GDI: the x64 counterpart of native32's w32kuser.c and
 * w32kgdi.c (same design, XP x64's layouts).
 *
 * USER. XP x64's user32 reads win32k's shared state directly, as Windows
 * 2000's does: SERVERINFO, the handle table (24-byte HANDLEENTRYs), each
 * window's WND, the thread's CLIENTINFO (TEB+0x800). Real host windows sit
 * underneath; this layer keeps those structures, in XP x64's layout (read
 * off its user32; most fields where Windows 7 x64 has them), for what
 * user32 reads. A class the guest registers is a host class with wnd_thunk
 * as its procedure, which sends each message as win32k does: through the
 * guest's KernelCallbackTable (__fnDWORD), in the x64 message layouts. The
 * guest user32's own control classes (Button, Edit, Static, ...) are the
 * host's, which draw themselves.
 *
 * GDI. Guest handles ARE host handles: XP x64's gdi32 validates a handle
 * against entry [LOWORD(h)] of a 65,536-entry table, and a host handle's
 * index fits it, so each host object met is entered at its own index (the
 * host's high word, the type, this process) with no translation either way.
 * A DC's entry carries a DC_ATTR in XP x64's layout (gdi32 writes colours,
 * modes and selected objects there in user mode); before a draw it is
 * applied to the host DC. gdi32's TEB batch (PatBlt, font selects) runs at
 * each service and callback return.
 *
 * The guest's screen is its own: XP64_SHOT/XP64_KEYS (w32k64_script) type
 * into the guest's window and write its picture from inside the process.
 *
 * ponytail: one GUI thread (calc, notepad, winmine), ANSI window procedures
 * get no text conversion, no menus/cursors of the guest's making; each is
 * added with the program that needs it.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "native64.h"

extern uint8_t* native64_user_psi, *native64_user_ahe, *native64_user_disp;

#define Q(p, o) (*(uint64_t*)((uint8_t*)(uintptr_t)(p) + (o)))
#define D(p, o) (*(uint32_t*)((uint8_t*)(uintptr_t)(p) + (o)))
#define W(p, o) (*(uint16_t*)((uint8_t*)(uintptr_t)(p) + (o)))
#define B(p, o) (*(uint8_t*)((uint8_t*)(uintptr_t)(p) + (o)))
#define TEB ((uint8_t*)(uintptr_t)g_guest_gs)
#define HW(x) ((HWND)(uintptr_t)(x))
#define HH(x) ((HANDLE)(intptr_t)(int32_t)(x))       /* a 32-bit handle value, sign-extended */
#define TRACE (native64_trace)

/* ---- XP x64 layouts (read off its user32 and gdi32) ----------------------
 * WND: +0 hwnd, +0x10 pti, +0x20 pSelf, +0x28 state (byte +0x2A: bit 0 a
 * dialog, bit 2 a server-side procedure), +0x30 ExStyle, +0x34 style,
 * +0x38 hModule, +0x42 fnid, +0x48 spwndNext, +0x58 spwndParent, +0x60
 * spwndChild, +0x68 spwndOwner, +0x70 rcWindow, +0x80 rcClient (screen),
 * +0x90 lpfnWndProc, +0x98 pcls, +0xA0 hrgnUpdate, +0xC0 spmenu (a child's
 * ID), +0xD0 strName { Length, MaximumLength, Buffer }, +0xE0 cbwndExtra,
 * +0xF8 dwUserData, +0x108 the extra bytes (a dialog's DIALOG* at +0x118). */
#define WND_STATE2A 0x2A
#define WND_EXSTYLE 0x30
#define WND_STYLE   0x34
#define WND_FNID    0x42
#define WND_NEXT    0x48
#define WND_PARENT  0x58
#define WND_CHILD   0x60
#define WND_OWNER   0x68
#define WND_RCWND   0x70
#define WND_RCCLI   0x80
#define WND_PROC    0x90
#define WND_PCLS    0x98
#define WND_UPDATE  0xA0
#define WND_MENU    0xC0
/* SERVERINFO: +0x8 cHandleEntries, +0x738 aiSysMet, +0x91C argbSystem[31],
 * +0x998 ahbrSystem[31], +0xAC4/+0xAC8 cxSysFontChar/cySysFontChar */
/* Vista x64 (NT 6.0, read off its user32: InternalGetWindowText, GetWindowLongPtr,
 * RealGetSystemMetrics, GetSysColor(Brush), GetDialogBaseUnits, IsHelpParent):
 * WND strName 0xD8, cbwndExtra 0xE8, extra bytes 0x128; SERVERINFO aiSysMet
 * 0x758, atomSysClass 0x354, argbSystem 0xABC, ahbrSystem 0xB38, cxSysFontChar
 * 0xC6C. Set by w32k64_install from the guest's build. */
static uint32_t WND_NAME = 0xD0, WND_CBEXTRA = 0xE0, WND_EXTRA = 0x108;
static uint32_t SI_METRICS = 0x738, SI_COLORS = 0x91C, SI_BRUSHES = 0x998, SI_CXSYSFONT = 0xAC4, SI_ATOMSYSCLASS = 0x334;

/* FNIDs are XP x64's here; Vista's are one higher from FNID_MDICLIENT on
 * (0x2A9; one more constant before it, as on Vista x86) */
static uint32_t fnid_in(uint32_t f) { return NATIVE64_NT6 && f >= 0x2AA && f < 0x2C2 ? f - 1 : f; }
static uint32_t fnid_out(uint32_t f) { return NATIVE64_NT6 && f >= 0x2A9 && f < 0x2C1 ? f + 1 : f; }

/* NtUserCall* routine numbers (SFI_*) are XP x64's here; a Vista guest's are
 * mapped to them first. Read off both user32s by export (vista64-recomp's
 * tools/sfimap.py: CreatePopupMenu, MessageBeep, UpdateWindow, ...); the ones
 * no export carries are between two that do, at the same distance. */
static const uint8_t g_sfi_vista[][2] = {   /* { XP x64, Vista x64 } */
    { 0x00, 0x00 }, { 0x01, 0x01 }, { 0x04, 0x02 }, { 0x05, 0x05 }, { 0x02, 0x06 }, { 0x08, 0x09 }, { 0x09, 0x0A },
    { 0x0D, 0x10 }, { 0x18, 0x1B }, { 0x1C, 0x20 },
    { 0x1E, 0x21 }, { 0x1F, 0x23 }, { 0x20, 0x24 }, { 0x21, 0x25 }, { 0x25, 0x28 }, { 0x26, 0x29 }, { 0x28, 0x2A },
    { 0x2A, 0x2C }, { 0x2B, 0x2D }, { 0x2C, 0x2E }, { 0x2E, 0x2F }, { 0x2F, 0x30 }, { 0x31, 0x32 }, { 0x33, 0x34 },
    { 0x35, 0x35 }, { 0x39, 0x3A }, { 0x3A, 0x3C }, { 0x3B, 0x3D }, { 0x3C, 0x3E }, { 0x3E, 0x3F }, { 0x3F, 0x40 },
    { 0x40, 0x42 }, { 0x41, 0x43 }, { 0x42, 0x44 },
    { 0x45, 0x46 }, { 0x47, 0x48 }, { 0x48, 0x49 }, { 0x4A, 0x4B }, { 0x4B, 0x4C }, { 0x4D, 0x4E }, { 0x4E, 0x4F },
    { 0x4F, 0x50 }, { 0x51, 0x52 }, { 0x52, 0x53 }, { 0x54, 0x55 }, { 0x55, 0x56 }, { 0x5B, 0x5C }, { 0x5E, 0x5F },
    { 0x60, 0x61 }, { 0x62, 0x63 }, { 0x63, 0x64 }, { 0x65, 0x66 },
    { 0x69, 0x6D }, { 0x6E, 0x72 }, { 0x6F, 0x73 }, { 0x70, 0x75 } };
static uint64_t sfi(uint64_t x) {
    if (!NATIVE64_NT6) return x;
    for (size_t i = 0; i < sizeof g_sfi_vista / sizeof g_sfi_vista[0]; i++)
        if (g_sfi_vista[i][1] == x) return g_sfi_vista[i][0];
    return 0x1000 + x;   /* not mapped: no case matches, "not answered" names it */
}
/* KernelCallbackTable (PEB+0x58) */
#define CB_DWORD       2     /* __fnDWORD { pwnd, msg, w, l, xParam, xpfn } (no capture header) */
#define CB_THREADSETUP 76    /* __ClientThreadSetup */

/* ---- KeUserModeCallback --------------------------------------------------
 * The guest's KernelCallbackTable[api](msg, len), and its NtCallbackReturn
 * (result, length, status) taken as the reply: the routine returns after it
 * (the kernel would switch stacks back; here the call just returns). */
static __declspec(thread) struct { uint8_t buf[0x800]; uint32_t len, st; int got; } t_cbr;
static uint64_t ovr_callback_return(uint64_t* a) {
    t_cbr.len = (uint32_t)(a[1] < sizeof t_cbr.buf ? a[1] : sizeof t_cbr.buf);
    if (a[0] && t_cbr.len) memcpy(t_cbr.buf, (void*)(uintptr_t)a[0], t_cbr.len);
    t_cbr.st = (uint32_t)a[2], t_cbr.got = 1;
    return 0;
}
static void gdi_flush(void);
/* the first reply's qword (an LRESULT), 0 when the routine gave none */
static uint64_t callback(int api, void* msg, uint32_t len) {
    uint64_t kct = Q(native64_peb, 0x58), args[2] = { (uint64_t)(uintptr_t)msg, len };
    if (!kct) return 0;
    t_cbr.got = 0;
    native64_call(Q(kct, 8 * api), 2, args);
    gdi_flush();                /* (a callback's return runs the TEB batch, as win32k's does) */
    if (!t_cbr.got) { fprintf(stderr, "[user] callback %d: no NtCallbackReturn\n", api); return 0; }
    if (t_cbr.st && TRACE) fprintf(stderr, "[user] callback %d: status %08X\n", api, t_cbr.st);
    return t_cbr.len >= 8 ? Q(t_cbr.buf, 0) : 0;
}

/* ---- GDI: the table, DC_ATTR ---------------------------------------------
 * GDICELL (24 bytes): +0 pKernelAddress (nonzero), +8 pid (low bit ignored),
 * +0xC the handle's high word, +0xE type (1 DC, 4 region, 5 bitmap, 8
 * palette, 0xA font, 0x10 brush, 0x30 pen), +0x10 pUser (a DC's DC_ATTR).
 * DC_ATTR: +0x08 ulDirty (bit 14: a DIB-section DC), +0x10
 * hbrush, +0x18 hpen, +0x20/+0x24 background colour, +0x28/+0x2C text
 * colour, +0x48 ROP2, +0x49 bk mode, +0x4C current position, +0x5C lBkMode,
 * +0x98/+0x9C text align, +0xB0 font, +0x134 map mode, +0x140 window org,
 * +0x148 window ext, +0x150 viewport org, +0x158 viewport ext, +0x17C brush
 * org. */
#define GDI_ENTRIES 0x10000
#define ATTR_SIZE 0x400
#define DA_DIRTY 0x08
#define DA_BRUSH 0x10
#define DA_PEN 0x18
#define DA_BK 0x24
#define DA_TEXT 0x2C
#define DA_ROP2 0x48
#define DA_BKMODE 0x49
#define DA_CURPOS 0x4C
#define DA_LBKMODE 0x5C
#define DA_ALIGN 0x9C
#define DA_FONT 0xB0
#define DA_MAPMODE 0x134
#define DA_WINORG 0x140
#define DA_VPORG 0x150
#define DA_BRUSHORG 0x17C
static uint8_t* g_gt;
static uint8_t* g_attr[GDI_ENTRIES];

static uint8_t* gcell(uint64_t h) { return g_gt ? g_gt + 24 * (h & 0xFFFF) : NULL; }
static uint8_t* gattr(uint64_t h) {
    uint8_t* e = gcell(h);
    return e && W(e, 0xC) == (uint16_t)(h >> 16) ? (uint8_t*)(uintptr_t)Q(e, 0x10) : NULL;
}
static uint64_t G(HANDLE hv);
static void attr_from_dc(uint8_t* at, HDC d) {
    POINT p;
    memset(at, 0, ATTR_SIZE);
    D(at, DA_DIRTY) = 0;
    Q(at, DA_BRUSH) = G(GetCurrentObject(d, OBJ_BRUSH));
    Q(at, DA_PEN) = G(GetCurrentObject(d, OBJ_PEN));
    Q(at, DA_FONT) = G(GetCurrentObject(d, OBJ_FONT));
    D(at, 0x20) = D(at, DA_BK) = GetBkColor(d);
    D(at, 0x28) = D(at, DA_TEXT) = GetTextColor(d);
    B(at, DA_ROP2) = (uint8_t)GetROP2(d);
    B(at, DA_BKMODE) = (uint8_t)GetBkMode(d);
    D(at, DA_LBKMODE) = (uint32_t)GetBkMode(d);
    D(at, 0x60) = (uint32_t)GetPolyFillMode(d);
    D(at, 0x64) = (uint32_t)GetStretchBltMode(d);
    GetCurrentPositionEx(d, &p);
    D(at, DA_CURPOS) = (uint32_t)p.x, D(at, DA_CURPOS + 4) = (uint32_t)p.y;
    D(at, 0x98) = D(at, DA_ALIGN) = GetTextAlign(d);
    D(at, DA_MAPMODE) = (uint32_t)GetMapMode(d);
    D(at, DA_WINORG + 8) = D(at, DA_WINORG + 0xC) = 1;   /* extents 1,1 (MM_TEXT) */
    D(at, DA_VPORG + 8) = D(at, DA_VPORG + 0xC) = 1;
    GetBrushOrgEx(d, &p);
    D(at, DA_BRUSHORG) = (uint32_t)p.x, D(at, DA_BRUSHORG + 4) = (uint32_t)p.y;
}
/* Enter a host GDI object in the guest's table; fresh: a DC just handed out
 * (its attributes read from the host DC again) */
static uint64_t gdi_enter(HANDLE hv, int fresh) {
    uint64_t h = (uint64_t)(uintptr_t)hv;
    uint8_t* e = gcell(h);
    if (!h || !e) return h;
    uint8_t type = (uint8_t)((h >> 16) & 0x7F);
    int same = Q(e, 0) && W(e, 0xC) == (uint16_t)(h >> 16);
    if (same && !fresh) return h;
    Q(e, 0) = 0xFFFFF90000000000ull | (h & 0xFFFF) << 4;
    D(e, 8) = GetCurrentProcessId();
    W(e, 0xC) = (uint16_t)(h >> 16);
    B(e, 0xE) = type & 0x1F;
    Q(e, 0x10) = 0;
    if ((type & 0x1F) == 1 || (type & 0x1F) == 4) {
        uint32_t i = (uint32_t)(h & 0xFFFF);
        if (!g_attr[i]) g_attr[i] = (uint8_t*)calloc(1, ATTR_SIZE);
        Q(e, 0x10) = (uint64_t)(uintptr_t)g_attr[i];
        if ((type & 0x1F) == 1) {
            Q(e, 0x10) = 0;                         /* (G() inside reads the cell: no stale attr) */
            attr_from_dc(g_attr[i], (HDC)hv);
            Q(e, 0x10) = (uint64_t)(uintptr_t)g_attr[i];
        } else memset(g_attr[i], 0, ATTR_SIZE);
    }
    return h;
}
static uint64_t G(HANDLE hv) { return gdi_enter(hv, 0); }
static void gdi_forget(uint64_t h) { uint8_t* e = gcell(h); if (e && W(e, 0xC) == (uint16_t)(h >> 16)) memset(e, 0, 24); }

/* A guest DC as the host's, with its user-mode attributes applied */
static HDC dc(uint64_t g) {
    HDC h = (HDC)HH(g);
    uint8_t* a = gattr(g);
    gdi_flush();
    if (!a) return h;
    if (Q(a, DA_BRUSH)) SelectObject(h, HH(Q(a, DA_BRUSH)));
    if (Q(a, DA_PEN)) SelectObject(h, HH(Q(a, DA_PEN)));
    if (Q(a, DA_FONT)) SelectObject(h, HH(Q(a, DA_FONT)));
    SetBkColor(h, D(a, DA_BK));
    SetTextColor(h, D(a, DA_TEXT));
    SetROP2(h, B(a, DA_ROP2) ? B(a, DA_ROP2) : R2_COPYPEN);
    SetBkMode(h, B(a, DA_BKMODE) ? B(a, DA_BKMODE) : OPAQUE);
    SetTextAlign(h, D(a, DA_ALIGN));
    MoveToEx(h, (int)D(a, DA_CURPOS), (int)D(a, DA_CURPOS + 4), NULL);
    SetBrushOrgEx(h, (int)D(a, DA_BRUSHORG), (int)D(a, DA_BRUSHORG + 4), NULL);
    SetWindowOrgEx(h, (int)D(a, DA_WINORG), (int)D(a, DA_WINORG + 4), NULL);
    SetViewportOrgEx(h, (int)D(a, DA_VPORG), (int)D(a, DA_VPORG + 4), NULL);
    return h;
}
static void dc_back(uint64_t g) {          /* after a draw that moves the pen */
    uint8_t* a = gattr(g);
    POINT p;
    if (a && GetCurrentPositionEx((HDC)HH(g), &p)) D(a, DA_CURPOS) = (uint32_t)p.x, D(a, DA_CURPOS + 4) = (uint32_t)p.y;
}

/* The TEB batch (TEB+0x2F0 bytes used, +0x2F8 the DC, +0x300 entries
 * { USHORT length, USHORT command, data }, +0x1740 their count). PatBlt (0):
 * x +4, y +8, cx +0xC, cy +0x10, brush +0x18, rop +0x20. */
static void gdi_flush(void) {
    uint8_t* t = TEB;
    uint32_t used = t ? D(t, 0x2F0) : 0;
    if (!used) return;
    uint64_t hdc = Q(t, 0x2F8);
    D(t, 0x2F0) = 0, Q(t, 0x2F8) = 0, D(t, 0x1740) = 0;
    for (uint32_t off = 0; off + 4 <= used && off < 0x4D8;) {
        uint8_t* e = t + 0x300 + off;
        uint32_t len = W(e, 0), cmd = W(e, 2);
        if (cmd == 0) {
            HDC h = dc(hdc);
            HGDIOBJ old = Q(e, 0x18) ? SelectObject(h, HH(Q(e, 0x18))) : NULL;
            PatBlt(h, (int)D(e, 4), (int)D(e, 8), (int)D(e, 0xC), (int)D(e, 0x10), D(e, 0x20));
            if (old) SelectObject(h, old);
        } else if (cmd == 6) {          /* select a font { font at +8 }: DC_ATTR's is current */
            uint8_t* at = gattr(hdc);
            if (at) Q(at, DA_FONT) = Q(e, 8);
        } else fprintf(stderr, "[gdi] batch command %u (%u bytes) dropped\n", cmd, len);
        if (len < 4) break;
        off += (len + 7) & ~7u;
    }
}

/* ---- USER: the desktop heap, CLIENTINFO, the handle table ---------------- */
#define DESK_SIZE (16u << 20)
static uint8_t* g_desk, *g_deskinfo, *g_threadinfo, *g_cls, *g_deskwnd;
static uint32_t g_desk_top;
static uint8_t* desk_alloc(uint32_t n) {
    uint32_t k = (n + 15) & ~15u;
    if (g_desk_top + k > DESK_SIZE) return NULL;
    uint8_t* p = g_desk + g_desk_top;
    g_desk_top += k;
    memset(p, 0, k);
    return p;
}
/* TEB+0x78 Win32ThreadInfo (nonzero: a GUI thread); CLIENTINFO (TEB+0x800):
 * +0x10 dwExpWinVer, +0x20 pDeskInfo -> DESKTOPINFO { pvDesktopBase,
 * pvDesktopLimit, spwnd }, +0x28 ulClientDelta, +0x40 CallbackWnd { hwnd, pwnd } */
static void thread_setup(void) {
    uint8_t* t = TEB;
    if (!g_desk) {
        g_desk = (uint8_t*)VirtualAlloc(NULL, DESK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        g_desk_top = 0x100;
        g_deskinfo = desk_alloc(0x200);
        Q(g_deskinfo, 0) = (uint64_t)(uintptr_t)g_desk;
        Q(g_deskinfo, 8) = (uint64_t)(uintptr_t)g_desk + DESK_SIZE;
        g_threadinfo = (uint8_t*)calloc(1, 0x800);
        g_cls = desk_alloc(0x100);
        /* the desktop: what a top-level window's spwndParent is (IsWindowVisible stops at fnid 0x29D) */
        g_deskwnd = desk_alloc(WND_EXTRA + 0x40);
        Q(g_deskwnd, 0) = (uint64_t)(uintptr_t)GetDesktopWindow();
        Q(g_deskwnd, 0x20) = (uint64_t)(uintptr_t)g_deskwnd;
        D(g_deskwnd, WND_STYLE) = WS_VISIBLE | WS_POPUP | WS_CLIPCHILDREN;
        W(g_deskwnd, WND_FNID) = (uint16_t)fnid_out(0x29D);
        Q(g_deskwnd, WND_PCLS) = (uint64_t)(uintptr_t)g_cls;
        Q(g_deskinfo, 0x10) = (uint64_t)(uintptr_t)g_deskwnd;
    }
    if (!t) return;
    if (!Q(t, 0x78)) Q(t, 0x78) = (uint64_t)(uintptr_t)g_threadinfo;
    if (Q(t, 0x820) != (uint64_t)(uintptr_t)g_deskinfo) {
        Q(t, 0x820) = (uint64_t)(uintptr_t)g_deskinfo;
        Q(t, 0x828) = 0;
        D(t, 0x810) = 0x502;
    }
}

/* the guest's procedure of each class it registered (the host's is wnd_thunk) */
#define MAX_CLASSES 256
static struct { ATOM atom; uint64_t proc; HINSTANCE inst; } g_cl[MAX_CLASSES];
static int g_ncl;
static LRESULT CALLBACK wnd_thunk(HWND h, UINT m, WPARAM w, LPARAM l);
static uint64_t class_proc(HWND h) {
    ATOM a = (ATOM)GetClassWord(h, GCW_ATOM);
    for (int i = 0; i < g_ncl; i++) if (g_cl[i].atom == a) return g_cl[i].proc;
    return 0;
}
static uint8_t* ahe(HWND h) { return native64_user_ahe + 24 * ((uintptr_t)h & 0xFFFF); }

static DWORD g_gui_tid;          /* the guest's GUI thread */
#define MAX_WNDS 1024
static HWND g_wnds[MAX_WNDS];
static int g_nwnds;
static uint8_t* user_wnd(HWND h);
static uint64_t wnd_of(HWND h) { return h && h != GetDesktopWindow() ? (uint64_t)(uintptr_t)user_wnd(h) : (uint64_t)(uintptr_t)g_deskwnd; }
static void wnd_sync(HWND h, uint8_t* w) {
    RECT r;
    POINT o = { 0, 0 };
    HWND p = GetAncestor(h, GA_PARENT), own = GetWindow(h, GW_OWNER), c = GetWindow(h, GW_CHILD);
    uint32_t style = (uint32_t)GetWindowLongW(h, GWL_STYLE);
    D(w, WND_EXSTYLE) = (uint32_t)GetWindowLongW(h, GWL_EXSTYLE);
    D(w, WND_STYLE) = style;
    GetWindowRect(h, &r);
    memcpy(w + WND_RCWND, &r, sizeof r);
    GetClientRect(h, &r);
    ClientToScreen(h, &o);
    OffsetRect(&r, o.x, o.y);
    memcpy(w + WND_RCCLI, &r, sizeof r);
    Q(w, WND_PARENT) = wnd_of(p);
    Q(w, WND_OWNER) = own ? wnd_of(own) : 0;
    Q(w, WND_CHILD) = c ? wnd_of(c) : 0;
    Q(w, WND_UPDATE) = GetUpdateRect(h, NULL, FALSE) ? 1 : 0;
    if (style & WS_CHILD) {
        HWND n = GetWindow(h, GW_HWNDNEXT);
        Q(w, WND_NEXT) = n ? wnd_of(n) : 0;
        Q(w, WND_MENU) = (uint64_t)GetDlgCtrlID(h);
    }
    {   /* strName: DefWindowProc's WM_GETTEXT and GetWindowTextLength read it client-side */
        wchar_t* buf = (wchar_t*)(uintptr_t)Q(w, WND_NAME + 8);
        int n = InternalGetWindowText(h, buf, 255);
        D(w, WND_NAME) = (uint32_t)(n > 0 ? n : 0) * 2;
        D(w, WND_NAME + 4) = 256 * 2;
    }
}
/* The WND for a host window, made the first time the guest meets it */
static uint8_t* user_wnd(HWND h) {
    if (!h || !native64_user_ahe) return NULL;
    thread_setup();
    uint8_t* e = ahe(h);
    if (Q(e, 0) && W(e, 0x12) == (uint16_t)((uintptr_t)h >> 16)) return (uint8_t*)(uintptr_t)Q(e, 0);
    uint32_t extra = (uint32_t)GetClassLongW(h, GCL_CBWNDEXTRA);
    uint8_t* w = desk_alloc(WND_EXTRA + extra + 0x10);
    if (!w) return NULL;
    Q(w, 0) = (uint64_t)(uintptr_t)h;
    Q(w, 0x10) = (uint64_t)(uintptr_t)g_threadinfo;
    Q(w, 0x20) = (uint64_t)(uintptr_t)w;
    Q(w, 0x38) = (uint64_t)GetWindowLongPtrW(h, GWLP_HINSTANCE);
    Q(w, WND_PCLS) = (uint64_t)(uintptr_t)g_cls;
    D(w, WND_CBEXTRA) = extra;
    Q(w, WND_NAME + 8) = (uint64_t)(uintptr_t)desk_alloc(512);
    /* lpfnWndProc: the guest's own for its classes, called client-side; a host
     * class's procedure is not guest code, so its window is marked as having a
     * server-side one (DispatchMessage and SendMessage go through win32k) */
    uint64_t pfn = class_proc(h);
    if (pfn && (WNDPROC)GetWindowLongPtrW(h, GWLP_WNDPROC) == wnd_thunk) Q(w, WND_PROC) = pfn;
    else { Q(w, WND_PROC) = (uint64_t)GetWindowLongPtrW(h, GWLP_WNDPROC); B(w, WND_STATE2A) |= 4; }
    Q(e, 0) = (uint64_t)(uintptr_t)w;
    Q(e, 8) = (uint64_t)(uintptr_t)g_threadinfo;
    B(e, 0x10) = 1;                                 /* TYPE_WINDOW */
    B(e, 0x11) = 0;
    W(e, 0x12) = (uint16_t)((uintptr_t)h >> 16);
    if (g_nwnds < MAX_WNDS) g_wnds[g_nwnds++] = h;
    wnd_sync(h, w);
    return w;
}
static void wnd_sync_all(void) {
    for (int i = 0; i < g_nwnds; i++) {
        if (!IsWindow(g_wnds[i])) { memset(ahe(g_wnds[i]), 0, 24); g_wnds[i--] = g_wnds[--g_nwnds]; continue; }
        uint8_t* e = ahe(g_wnds[i]);
        if (Q(e, 0)) wnd_sync(g_wnds[i], (uint8_t*)(uintptr_t)Q(e, 0));
    }
}

/* SERVERINFO from the host's metrics, colours and brushes, and the system font's size */
static void server_info(void) {
    static int done;
    uint8_t* si = native64_user_psi;
    if (done || !si) return;
    done = 1;
    Q(si, 8) = 0x10000;                             /* cHandleEntries */
    for (int i = 0; i < 0x5A; i++) D(si, SI_METRICS + 4 * i) = (uint32_t)GetSystemMetrics(i);
    for (int i = 0; i < 31; i++) {
        D(si, SI_COLORS + 4 * i) = GetSysColor(i);
        Q(si, SI_BRUSHES + 8 * i) = G(GetSysColorBrush(i));
    }
    {   /* +0x334 atomSysClass: a dialog template's class ordinals (0x80 Button ...) */
        static const wchar_t* sc[] = { L"Button", L"Edit", L"Static", L"ListBox", L"ScrollBar", L"ComboBox", L"MDIClient", L"ComboLBox" };
        for (int i = 0; i < 8; i++) {
            WNDCLASSEXW wc = { sizeof wc };
            W(si, SI_ATOMSYSCLASS + 2 * i) = (uint16_t)GetClassInfoExW(NULL, sc[i], &wc);
        }
    }
    {   /* DISPLAYINFO: +0x50 cMonitors, +0x58 pMonitorPrimary, +0x60 pMonitorFirst; MONITOR:
         * +0 handle, +0x18 dwMONFlags (1 visible), +0x1C rcMonitor, +0x2C rcWork */
        uint8_t* d = native64_user_disp, *mon = (uint8_t*)calloc(1, 0x100);
        RECT r = { 0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN) }, wk;
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &wk, 0);
        Q(mon, 0) = (uint64_t)(uintptr_t)MonitorFromPoint((POINT){ 0, 0 }, MONITOR_DEFAULTTOPRIMARY);
        D(mon, 0x18) = 1;
        memcpy(mon + 0x1C, &r, sizeof r), memcpy(mon + 0x2C, &wk, sizeof wk);
        D(d, 0x50) = 1, Q(d, 0x58) = Q(d, 0x60) = (uint64_t)(uintptr_t)mon;
    }
    {
        HDC s = GetDC(NULL);
        TEXTMETRICW tm;
        HGDIOBJ o = SelectObject(s, GetStockObject(SYSTEM_FONT));
        GetTextMetricsW(s, &tm);
        SelectObject(s, o);
        ReleaseDC(NULL, s);
        W(si, SI_CXSYSFONT) = (uint16_t)tm.tmAveCharWidth;
        W(si, SI_CXSYSFONT + 4) = (uint16_t)tm.tmHeight;
    }
}

static void user_pre(void) {          /* before each USER service */
    server_info();
    thread_setup();
    wnd_sync_all();
    /* win32k calls a new GUI thread back at __ClientThreadSetup: user32 makes
     * its drawing DCs there. ponytail: once per process (one GUI thread) */
    static int setup;
    if (!setup && Q(native64_peb, 0x58)) {
        uint64_t z[4] = { 0 };
        setup = 1;
        callback(CB_THREADSETUP, z, sizeof z);
    }
}

/* ---- messages: win32k's callback ------------------------------------------
 * A host message for a guest window reaches its procedure the way win32k
 * delivers it: __fnDWORD (KernelCallbackTable[2]) { pwnd, msg, wParam,
 * lParam, xParam = the procedure, xpfnProc = DispatchClientMessage }, which
 * calls xpfnProc(pwnd, msg, w, l, xParam). DispatchClientMessage takes the
 * HWND from CLIENTINFO's CallbackWnd (TEB+0x840, the WND at +0x848), set
 * first. Strings and structures are passed as pointers: one address space.
 * GDI handles in a message (a DC to draw on, a font) are entered first. */
static uint64_t g_dcm;                 /* user32's DispatchClientMessage */
static uint64_t find_dcm(void) {
    /* in no export: PFNCLIENT (apfnClientA/W, user32's data) holds it, a
     * fixed distance after pfnDialogWndProc; found as the slot where the A
     * and W tables (DefDlgProcA/W at the same slot) agree */
    uint64_t u = native64_module("user32.dll");
    if (!u) return 0;
    uint64_t da = native64_export(u, "DefDlgProcA"), dw = native64_export(u, "DefDlgProcW");
    uint32_t size = D(u + D(u, 0x3C), 0x50);
    for (uint32_t o = 0x1000; o + 0x80 < size; o += 8)
        if (Q(u, o) == dw)
            for (uint32_t p = 0x1000; p + 0x80 < size; p += 8)
                if (Q(u, p) == da)
                    for (uint32_t k = 0x30; k <= 0x60; k += 8)
                        if (Q(u, o + k) == Q(u, p + k) && Q(u, o + k) > u && Q(u, o + k) < u + size)
                            return Q(u, o + k);
    return 0;
}
static void msg_gdi_in(UINT m, WPARAM w, LPARAM l) {
    if (w && (m == WM_ERASEBKGND || m == WM_PRINTCLIENT || m == WM_PRINT || (m >= WM_CTLCOLORMSGBOX && m <= WM_CTLCOLORSTATIC)))
        gdi_enter((HANDLE)w, 1);
    if (m == WM_SETFONT && w) G((HANDLE)w);
    if (m == WM_DRAWITEM && l) gdi_enter(((DRAWITEMSTRUCT*)l)->hDC, 1);
}
static LRESULT CALLBACK wnd_thunk(HWND h, UINT m, WPARAM w, LPARAM l) {
    uint8_t* pw = user_wnd(h);
    uint64_t pfn = pw ? Q(pw, WND_PROC) : 0;
    if (!g_dcm && (g_dcm = find_dcm()) != 0 && TRACE) fprintf(stderr, "[user] DispatchClientMessage %llX\n", g_dcm);
    if (!pw || !pfn || !g_dcm || !TEB) return DefWindowProcW(h, m, w, l);
    wnd_sync_all();
    msg_gdi_in(m, w, l);
    uint8_t* t = TEB;
    uint64_t oh = Q(t, 0x840), op = Q(t, 0x848);
    Q(t, 0x840) = (uint64_t)(uintptr_t)h, Q(t, 0x848) = (uint64_t)(uintptr_t)pw;
    uint64_t msg[6] = { (uint64_t)(uintptr_t)pw, m, w, (uint64_t)l, pfn, g_dcm };
    uint64_t r = callback(CB_DWORD, msg, sizeof msg);
    Q(t, 0x840) = oh, Q(t, 0x848) = op;
    if (TRACE) fprintf(stderr, "[user] msg %p %04X %llX %llX -> %llX\n", (void*)h, m, (uint64_t)w, (uint64_t)l, r);
    if (r && m >= WM_CTLCOLORMSGBOX && m <= WM_CTLCOLORSTATIC) r = (uint64_t)(uintptr_t)HH(r);
    return (LRESULT)r;
}

/* ---- USER services --------------------------------------------------------
 * UNICODE_STRING x64 { USHORT Length, MaximumLength; PWSTR Buffer (+8) };
 * LARGE_STRING { ULONG Length, MaximumLength:31 | bAnsi:1; PVOID Buffer (+8) } */
static const wchar_t* ustr(uint64_t us) { return us ? (const wchar_t*)(uintptr_t)Q(us, 8) : NULL; }
static const wchar_t* lstr(uint64_t ls) {
    static wchar_t buf[2][512];
    static int k;
    if (ls < 0x10000) return (const wchar_t*)(uintptr_t)ls;
    if (!(D(ls, 4) & 0x80000000u) || !Q(ls, 8)) return (const wchar_t*)(uintptr_t)Q(ls, 8);
    wchar_t* o = buf[k ^= 1];
    int n = MultiByteToWideChar(CP_ACP, 0, (const char*)(uintptr_t)Q(ls, 8), (int)D(ls, 0), o, 511);
    o[n > 0 ? n : 0] = 0;
    return o;
}
static const wchar_t* ustr_or_atom(uint64_t us) { return us < 0x10000 ? (const wchar_t*)(uintptr_t)us : ustr(us); }

/* the guest user32's own control classes stand for the host's of that name */
static int host_control(const wchar_t* n) {
    static const wchar_t* sys[] = { L"Button", L"Edit", L"Static", L"ListBox", L"ScrollBar", L"ComboBox",
                                    L"ComboLBox", L"MDIClient", L"#32770", L"#32768", L"#32769", L"#32771", L"#32772",
                                    L"Message", L"IME", L"DDEMLEvent", L"DDEMLMom", L"DMGClass",
                                    L"DDEMLAnsiClient", L"DDEMLUnicodeClient", L"DDEMLAnsiServer", L"DDEMLUnicodeServer", NULL };
    if ((uintptr_t)n < 0x10000) return 0;
    for (int i = 0; sys[i]; i++) if (!_wcsicmp(n, sys[i])) return 1;
    return 0;
}
/* NtUserRegisterClassExWOW(WNDCLASSEXW*, UNICODE_STRING* name, UNICODE_STRING*
 * version, CLSMENUNAME* { ansi +0, unicode +8, us +0x10 }, fnid, flags, wow*) */
static uint64_t s_register_class(uint64_t* a) {
    WNDCLASSEXW wc = *(WNDCLASSEXW*)(uintptr_t)a[0];
    if (TRACE) fprintf(stderr, "[user] RegisterClassExWOW name %llX/%llX ver %llX/%llX fnid %llX\n", a[1], a[1] ? Q(a[1], 8) : 0, a[2], a[2] ? Q(a[2], 8) : 0, a[4]);
    wc.cbSize = sizeof wc;
    wc.lpszClassName = ustr_or_atom(a[1]);
    if ((uintptr_t)wc.lpszClassName < 0x10000 || host_control(wc.lpszClassName)) {
        WNDCLASSEXW hc = { sizeof hc };
        return (uint64_t)GetClassInfoExW(NULL, wc.lpszClassName, &hc);
    }
    if (a[3]) wc.lpszMenuName = (LPCWSTR)(uintptr_t)Q(a[3], 8);
    uint64_t proc = (uint64_t)(uintptr_t)wc.lpfnWndProc;
    wc.lpfnWndProc = wnd_thunk;
    ATOM r = RegisterClassExW(&wc);
    if (r && g_ncl < MAX_CLASSES) g_cl[g_ncl].atom = r, g_cl[g_ncl].inst = wc.hInstance, g_cl[g_ncl++].proc = proc;
    if (TRACE || !r) fprintf(stderr, "[user] class %ls: atom %X (%lu)\n", (uintptr_t)wc.lpszClassName < 0x10000 ? L"(atom)" : wc.lpszClassName, r, r ? 0 : GetLastError());
    return r;
}
/* NtUserCreateWindowEx(exstyle, LARGE_STRING* class, LARGE_STRING* version,
 * LARGE_STRING* name, style, x, y, cx, cy, parent, menu, hInstance, lpParam,
 * flags, acbiBuffer): a guest class is found under any instance it was
 * registered with (a DLL's global class) */
static uint64_t s_create_window(uint64_t* a) {
    const wchar_t* cls = lstr(a[1]);
    HINSTANCE inst = (HINSTANCE)(uintptr_t)a[11];
    WNDCLASSEXW wc = { sizeof wc };
    if (!GetClassInfoExW(inst, cls, &wc))
        for (int i = 0; i < g_ncl; i++)
            if (GetClassInfoExW(g_cl[i].inst, cls, &wc)) { inst = g_cl[i].inst; break; }
    HWND h = CreateWindowExW((DWORD)a[0] & ~0x80000000u, cls, lstr(a[3]), (DWORD)a[4], (int)a[5], (int)a[6], (int)a[7], (int)a[8],
                             HW(a[9]), (HMENU)(uintptr_t)a[10], inst, (void*)(uintptr_t)a[12]);
    if (!h) {
        DWORD e = GetLastError();
        D(TEB, 0x68) = e;                           /* the thread's LastErrorValue */
        fprintf(stderr, "[user] CreateWindowExW %ls failed: %lu (style %llX parent %llX)\n",
                (uintptr_t)cls < 0x10000 ? L"(atom)" : cls, e, a[4], a[9]);
        return 0;
    }
    user_wnd(h);
    g_gui_tid = GetCurrentThreadId();
    if (TRACE) fprintf(stderr, "[user] window %p %ls\n", (void*)h, (uintptr_t)cls < 0x10000 ? L"(atom)" : cls);
    return (uint64_t)(uintptr_t)h;
}

/* NtUserMessageCall(hwnd, msg, wParam, lParam, xParam, fnid, bAnsi): 0x29E
 * DefWindowProc and the SendMessage family go to the host */
static uint64_t s_message_call(uint64_t* a) {
    HWND h = HW(a[0]);
    UINT m = (UINT)a[1];
    WPARAM w = (WPARAM)a[2];
    if (w && (m == WM_ERASEBKGND || m == WM_PRINTCLIENT || (m >= WM_CTLCOLORMSGBOX && m <= WM_CTLCOLORSTATIC))) gdi_flush();
    uint32_t fnid = fnid_in((uint32_t)a[5]);
    LRESULT r;
    int ansi = (uint32_t)a[6] != 0;   /* a BOOL: the high half is not the caller's (Vista x64's user32 leaves it) */
    if (TRACE) fprintf(stderr, "[user] MessageCall %p %04X fnid %X%s\n", (void*)h, m, fnid, ansi ? " (ANSI)" : "");
    if (fnid == 0x29E) r = ansi ? DefWindowProcA(h, m, w, (LPARAM)a[3]) : DefWindowProcW(h, m, w, (LPARAM)a[3]);
    else if (fnid == 0x2B0 || fnid == 0x2AE || fnid == 0x2B1) r = ansi ? SendMessageA(h, m, w, (LPARAM)a[3]) : SendMessageW(h, m, w, (LPARAM)a[3]);
    else {
        static int said[0x400];
        if (fnid < 0x400 ? !said[fnid]++ : 1) fprintf(stderr, "[user] NtUserMessageCall fnid 0x%X (msg 0x%X) as SendMessage\n", fnid, m);
        r = SendMessageW(h, m, w, (LPARAM)a[3]);
    }
    if (r && (m == WM_GETFONT || (m >= WM_CTLCOLORMSGBOX && m <= WM_CTLCOLORSTATIC))) G((HANDLE)r);
    return (uint64_t)r;
}

static uint64_t s_thread_state(uint64_t* a) {
    switch (a[0]) {
    case 0: return (uint64_t)(uintptr_t)GetFocus();
    case 1: return (uint64_t)(uintptr_t)GetActiveWindow();
    case 2: return (uint64_t)(uintptr_t)GetCapture();
    }
    if (TRACE) fprintf(stderr, "[user] NtUserGetThreadState %llu: 0\n", a[0]);
    return 0;
}
/* Any USER object a guest handle should validate as: menus (bType 2) get an
 * entry and a zeroed object in the desktop heap, like windows (1).
 * ponytail: the MENU's items are not mirrored (user32's client-side item
 * lookups see none); add with the program that reads them */
static uint64_t user_object(HANDLE hv, uint8_t type, uint32_t size) {
    uint64_t h = (uint64_t)(uintptr_t)hv;
    uint8_t* e = native64_user_ahe + 24 * (h & 0xFFFF);
    if (!h || (Q(e, 0) && W(e, 0x12) == (uint16_t)(h >> 16))) return h;
    thread_setup();
    uint8_t* o = desk_alloc(size);
    if (!o) return h;
    Q(o, 0) = h, Q(o, 0x20) = (uint64_t)(uintptr_t)o;
    Q(e, 0) = (uint64_t)(uintptr_t)o, Q(e, 8) = (uint64_t)(uintptr_t)g_threadinfo;
    B(e, 0x10) = type, B(e, 0x11) = 0, W(e, 0x12) = (uint16_t)(h >> 16);
    return h;
}
#define MENU(m) user_object((HANDLE)(m), 2, 0x100)
/* NtUserThunkedMenuItemInfo(hmenu, item, fByPosition, fInsert, MENUITEMINFOW*, UNICODE_STRING* text) */
static uint64_t s_menu_item(uint64_t* a) {
    MENUITEMINFOW mi = *(MENUITEMINFOW*)(uintptr_t)a[4];
    mi.cbSize = sizeof mi;
    if (a[5] && Q(a[5], 8)) mi.dwTypeData = (LPWSTR)(uintptr_t)Q(a[5], 8), mi.cch = W(a[5], 0) / 2;
    if ((mi.fMask & MIIM_TYPE) && (mi.fMask & (MIIM_FTYPE | MIIM_STRING | MIIM_BITMAP))) mi.fMask &= ~MIIM_TYPE;
    if ((mi.fMask & MIIM_SUBMENU) && mi.hSubMenu) MENU(mi.hSubMenu);
    BOOL r = a[3] ? InsertMenuItemW((HMENU)(uintptr_t)a[0], (UINT)a[1], (BOOL)a[2], &mi)
                  : SetMenuItemInfoW((HMENU)(uintptr_t)a[0], (UINT)a[1], (BOOL)a[2], &mi);
    if (!r) fprintf(stderr, "[user] %sMenuItem failed: %lu\n", a[3] ? "Insert" : "Set", GetLastError());
    return r;
}
static uint64_t s_destroy_menu(uint64_t* a) { return DestroyMenu((HMENU)(uintptr_t)a[0]); }
static uint64_t s_check_menu(uint64_t* a) { return CheckMenuItem((HMENU)(uintptr_t)a[0], (UINT)a[1], (UINT)a[2]); }
static uint64_t s_enable_menu(uint64_t* a) { return (uint64_t)(int64_t)EnableMenuItem((HMENU)(uintptr_t)a[0], (UINT)a[1], (UINT)a[2]); }
static uint64_t s_remove_menu(uint64_t* a) { return RemoveMenu((HMENU)(uintptr_t)a[0], (UINT)a[1], (UINT)a[2]); }
static uint64_t s_delete_menu(uint64_t* a) { return DeleteMenu((HMENU)(uintptr_t)a[0], (UINT)a[1], (UINT)a[2]); }
static uint64_t s_menu_default(uint64_t* a) { return SetMenuDefaultItem((HMENU)(uintptr_t)a[0], (UINT)a[1], (UINT)a[2]); }
static uint64_t s_menu_rect(uint64_t* a) { return GetMenuItemRect(HW(a[0]), (HMENU)(uintptr_t)a[1], (UINT)a[2], (RECT*)(uintptr_t)a[3]); }
static uint64_t s_getsysmenu(uint64_t* a) { return MENU(GetSystemMenu(HW(a[0]), (BOOL)a[1])); }

/* NtUserFindExistingCursorIcon(UNICODE_STRING* module, UNICODE_STRING* resource,
 * CURSORFIND*): user32 asks win32k's cache before building an icon or cursor
 * from the resource itself. Answered with the host's own load of the same
 * resource (user32's are the system's; a guest module's resources are read
 * from its image, mapped at its base), entered as a cursor/icon (type 3). */
static uint64_t s_find_icon(uint64_t* a) {
    const wchar_t* mod = a[0] ? ustr(a[0]) : NULL;
    uint64_t res = a[1] ? Q(a[1], 8) : 0;
    uint8_t* f = (uint8_t*)(uintptr_t)a[2];
    if (TRACE && f) fprintf(stderr, "[user] cursorfind %ls %llX: %08X %08X %08X %08X %08X %08X\n", mod ? mod : L"-", res,
                            D(f, 0), D(f, 4), D(f, 8), D(f, 12), D(f, 16), D(f, 20));
    HINSTANCE h = NULL;
    if (mod && !wcsstr(mod, L"USER32") && !wcsstr(mod, L"user32")) {
        char n[MAX_PATH];
        const wchar_t* b = wcsrchr(mod, L'\\');
        WideCharToMultiByte(CP_ACP, 0, b ? b + 1 : mod, -1, n, MAX_PATH, NULL, NULL);
        h = (HINSTANCE)(uintptr_t)native64_module(n);
        if (!h) return 0;
    }
    /* CURSORFIND { hcur? (8), rt (+8: 1 RT_CURSOR, 3 RT_ICON), cx, cy, bpp }:
     * ponytail: read as the 32-bit one shifted by 4 until a dump says otherwise */
    UINT type = f && D(f, 8) == 1 ? IMAGE_CURSOR : IMAGE_ICON;
    int cx = f ? (int)D(f, 0xC) : 0, cy = f ? (int)D(f, 0x10) : 0;
    if (cx < 0 || cx > 256 || cy < 0 || cy > 256) cx = cy = 0;
    HANDLE r = LoadImageW(h, (LPCWSTR)(uintptr_t)res, type, cx, cy, LR_SHARED | (cx ? 0 : LR_DEFAULTSIZE));
    if (!r && !h) r = LoadImageW(NULL, (LPCWSTR)(uintptr_t)res, type == IMAGE_ICON ? IMAGE_CURSOR : IMAGE_ICON, 0, 0, LR_SHARED | LR_DEFAULTSIZE);
    if (r) user_object(r, 3, 0x80);
    return (uint64_t)(uintptr_t)r;
}

/* the SFI_ routine numbers are XP x64's (read off user32's callers) */
static uint64_t s_call_noparam(uint64_t* a) {
    switch (sfi(a[0])) {
    case 0: return MENU(CreateMenu());
    case 1: return MENU(CreatePopupMenu());
    case 5: return DestroyCaret();
    case 9: return GetMessagePos();
    case 0xD: return ReleaseCapture();
    case 0x18: return 0;            /* ClientThreadSetup's: a new thread (do the client-side setup) */
    }
    fprintf(stderr, "[user] NtUserCallNoParam 0x%llX not answered\n", a[0]);
    return 0;
}
static uint64_t s_call_oneparam(uint64_t* a) {
    switch (sfi(a[1])) {
    case 0x20: case 0x2E: return 1;   /* (Lock)SetForegroundWindow permissions: the guest's own */
    case 0x1E: return (uint64_t)(uintptr_t)BeginDeferWindowPos((int)a[0]);
    case 0x26: {
        POINT p;
        if (!GetCursorPos(&p)) return 0;
        D(a[0], 0) = (uint32_t)p.x, D(a[0], 4) = (uint32_t)p.y;
        return 1;
    }
    case 0x28: return (uint64_t)(uintptr_t)GetKeyboardLayout(0);
    case 0x2A: { DWORD l = 0; GetProcessDefaultLayout(&l); if (a[0]) D(a[0], 0) = l; return 1; }
    case 0x2B: return GetQueueStatus((UINT)a[0]);
    case 0x31: return getenv("PCRECOMP_MUTE") ? 1 : MessageBeep((UINT)a[0]);
    case 0x33: PostQuitMessage((int)a[0]); return 1;
    case 0x39: return ReleaseDC(NULL, (HDC)HH(a[0]));
    case 0x40: return (uint64_t)(int64_t)ShowCursor((BOOL)a[0]);
    }
    fprintf(stderr, "[user] NtUserCallOneParam(%llX, 0x%llX) not answered\n", a[0], a[1]);
    return 0;
}
static uint64_t s_call_twoparam(uint64_t* a) {
    switch (sfi(a[2])) {
    case 0x6E: return SetCaretPos((int)a[0], (int)a[1]);
    }
    fprintf(stderr, "[user] NtUserCallTwoParam(%llX, %llX, 0x%llX) not answered\n", a[0], a[1], a[2]);
    return 0;
}
static uint64_t s_call_hwnd(uint64_t* a) {
    fprintf(stderr, "[user] NtUserCallHwnd(%llX, 0x%llX) not answered\n", a[0], a[1]);
    return 0;
}
static uint64_t s_call_hwndopt(uint64_t* a) {
    fprintf(stderr, "[user] NtUserCallHwndOpt(%llX, 0x%llX) not answered\n", a[0], a[1]);
    return 0;
}
static uint64_t s_call_hwndlock(uint64_t* a) {
    HWND h = HW(a[0]);
    switch (sfi(a[1])) {
    case 0x55: return DrawMenuBar(h);
    case 0x5B: return SetForegroundWindow(h);
    case 0x5E: return UpdateWindow(h);
    }
    fprintf(stderr, "[user] NtUserCallHwndLock(%llX, 0x%llX) not answered\n", a[0], a[1]);
    return 0;
}
static uint64_t s_call_hwndparam(uint64_t* a) {
    uint8_t* w = user_wnd(HW(a[0]));
    uint64_t k = sfi(a[2]);
    switch (k) {
    case 0x4F:      /* SetDialogPointer: the DIALOG at the extra bytes' +8, state bit "a dialog" */
        if (!w) return 0;
        Q(w, WND_EXTRA + 8) = a[1];
        B(w, WND_STATE2A) |= 1;
        return 1;
    case 0x4D:      /* ClearWindowState / SetWindowState: (byte from +0x28) << 8 | mask */
    case 0x52:
        if (!w || (a[1] >> 8) >= 8) return 0;
        if (k == 0x52) B(w, 0x28 + (a[1] >> 8)) |= (uint8_t)a[1];
        else B(w, 0x28 + (a[1] >> 8)) &= (uint8_t)~a[1];
        return 1;
    case 0x4E: return KillTimer(HW(a[0]), (UINT_PTR)a[1]);
    case 0x51: return SetWindowContextHelpId(HW(a[0]), (DWORD)a[1]);
    }
    fprintf(stderr, "[user] NtUserCallHwndParam(%llX, %llX, 0x%llX) not answered\n", a[0], a[1], a[2]);
    return 0;
}
static uint64_t s_call_hwndparamlock(uint64_t* a) {
    HWND h = HW(a[0]);
    switch (sfi(a[2])) {
    case 0x60: return EnableWindow(h, (BOOL)a[1]);
    case 0x62: return ShowOwnedPopups(h, (BOOL)a[1]);
    case 0x65: return ValidateRgn(h, (HRGN)HH(a[1]));
    }
    fprintf(stderr, "[user] NtUserCallHwndParamLock(%llX, %llX, 0x%llX) not answered\n", a[0], a[1], a[2]);
    return 0;
}

static uint64_t s_show(uint64_t* a) { return ShowWindow(HW(a[0]), (int)a[1]); }
static uint64_t s_getmessage(uint64_t* a) { return (uint64_t)(int64_t)GetMessageW((MSG*)(uintptr_t)a[0], HW(a[1]), (UINT)a[2], (UINT)a[3]); }
static uint64_t s_peekmessage(uint64_t* a) { return PeekMessageW((MSG*)(uintptr_t)a[0], HW(a[1]), (UINT)a[2], (UINT)a[3], (UINT)a[4]); }
static uint64_t s_translate(uint64_t* a) { return TranslateMessage((MSG*)(uintptr_t)a[0]); }
static uint64_t s_dispatch(uint64_t* a) { return (uint64_t)DispatchMessageW((MSG*)(uintptr_t)a[0]); }
static uint64_t s_waitmessage(uint64_t* a) { (void)a; return WaitMessage(); }
static uint64_t s_post(uint64_t* a) { return PostMessageW(HW(a[0]), (UINT)a[1], (WPARAM)a[2], (LPARAM)a[3]); }
static uint64_t s_post_thread(uint64_t* a) { return PostThreadMessageW((DWORD)a[0], (UINT)a[1], (WPARAM)a[2], (LPARAM)a[3]); }
static uint64_t s_beginpaint(uint64_t* a) {
    PAINTSTRUCT* ps = (PAINTSTRUCT*)(uintptr_t)a[1];
    HDC h = BeginPaint(HW(a[0]), ps);
    return gdi_enter(h, 1);
}
static uint64_t s_endpaint(uint64_t* a) { gdi_flush(); return EndPaint(HW(a[0]), (PAINTSTRUCT*)(uintptr_t)a[1]); }
static uint64_t s_getdc(uint64_t* a) { return gdi_enter(GetDC(HW(a[0])), 1); }
static uint64_t s_getwindowdc(uint64_t* a) { return gdi_enter(GetWindowDC(HW(a[0])), 1); }
static uint64_t s_getdcex(uint64_t* a) { return gdi_enter(GetDCEx(HW(a[0]), (HRGN)HH(a[1]), (DWORD)a[2]), 1); }
static uint64_t s_invalidate(uint64_t* a) { return InvalidateRect(HW(a[0]), (RECT*)(uintptr_t)a[1], (BOOL)a[2]); }
static uint64_t s_redraw(uint64_t* a) { return RedrawWindow(HW(a[0]), (RECT*)(uintptr_t)a[1], (HRGN)HH(a[2]), (UINT)a[3]); }
static uint64_t s_getupdaterect(uint64_t* a) { return GetUpdateRect(HW(a[0]), (RECT*)(uintptr_t)a[1], (BOOL)a[2]); }
/* A top-level frame: the guest sizes it with its own borders (one border per
 * WS_EX_WINDOWEDGE side and a caption, GetWindowBorders); the host's is
 * thicker (padded borders), so the difference goes on each side and the
 * client area is what the guest meant (winmine sizes itself from its board) */
static int frame_pad_top;            /* the caption's share, after frame_pad */
static int frame_pad(HWND h) {
    frame_pad_top = 0;
    uint32_t style = (uint32_t)GetWindowLongW(h, GWL_STYLE), ex = (uint32_t)GetWindowLongW(h, GWL_EXSTYLE);
    RECT r = { 0, 0, 0, 0 };
    if ((style & WS_CHILD) || (style & WS_CAPTION) != WS_CAPTION) return 0;
    int b = (ex & WS_EX_WINDOWEDGE) ? 2 : (ex & WS_EX_STATICEDGE) ? 1 : 0;
    b++;
    if (style & WS_THICKFRAME) { UINT g = 1; SystemParametersInfoW(SPI_GETBORDER, 0, &g, 0); b += (int)g; }
    if (ex & WS_EX_CLIENTEDGE) b += 2;
    b *= GetSystemMetrics(SM_CXBORDER);
    AdjustWindowRectEx(&r, style, FALSE, ex);
    int top = -r.top - b - GetSystemMetrics(SM_CYCAPTION), p = -r.left > b ? -r.left - b : 0;
    frame_pad_top = top > p ? top - p : 0;
    return p;
}
static uint64_t s_move(uint64_t* a) {
    int p = frame_pad(HW(a[0]));
    return MoveWindow(HW(a[0]), (int)a[1], (int)a[2], (int)a[3] + 2 * p, (int)a[4] + 2 * p + frame_pad_top, (BOOL)a[5]);
}
/* ponytail: SetWindowPos keeps the guest's size (calc resizes from its own GetWindowRect: a pad there grew it each time) */
static uint64_t s_setpos(uint64_t* a) { return SetWindowPos(HW(a[0]), HW(a[1]), (int)a[2], (int)a[3], (int)a[4], (int)a[5], (UINT)a[6]); }
static uint64_t s_destroy(uint64_t* a) { return DestroyWindow(HW(a[0])); }
static uint64_t s_setfocus(uint64_t* a) { return (uint64_t)(uintptr_t)SetFocus(HW(a[0])); }
static uint64_t s_setactive(uint64_t* a) { return (uint64_t)(uintptr_t)SetActiveWindow(HW(a[0])); }
static uint64_t s_setcapture(uint64_t* a) { return (uint64_t)(uintptr_t)SetCapture(HW(a[0])); }
static uint64_t s_foreground(uint64_t* a) { (void)a; return (uint64_t)(uintptr_t)GetForegroundWindow(); }
static uint64_t s_settimer(uint64_t* a) { return SetTimer(HW(a[0]), (UINT_PTR)a[1], (UINT)a[2], (TIMERPROC)(uintptr_t)a[3]); }
static uint64_t s_killtimer(uint64_t* a) { return KillTimer(HW(a[0]), (UINT_PTR)a[1]); }
static uint64_t s_validate_timer(uint64_t* a) { (void)a; return 1; }
static uint64_t s_register_msg(uint64_t* a) { return RegisterWindowMessageW(ustr(a[0])); }
static uint64_t s_one(uint64_t* a) { (void)a; return 1; }
static uint64_t s_zero(uint64_t* a) { (void)a; return 0; }
static uint64_t s_setmenu(uint64_t* a) { return SetMenu(HW(a[0]), (HMENU)(uintptr_t)a[1]); }
static uint64_t s_keystate(uint64_t* a) { return (uint16_t)GetKeyState((int)a[0]); }
static uint64_t s_asynckeystate(uint64_t* a) { return (uint16_t)GetAsyncKeyState((int)a[0]); }
static uint64_t s_getkeyboardstate(uint64_t* a) { return GetKeyboardState((BYTE*)(uintptr_t)a[0]); }
static uint64_t s_setcursor(uint64_t* a) { return (uint64_t)(uintptr_t)SetCursor((HCURSOR)(uintptr_t)a[0]); }
static uint64_t s_showcaret(uint64_t* a) { return ShowCaret(HW(a[0])); }
static uint64_t s_hidecaret(uint64_t* a) { return HideCaret(HW(a[0])); }
static uint64_t s_createcaret(uint64_t* a) { return CreateCaret(HW(a[0]), (HBITMAP)HH(a[1]), (int)a[2], (int)a[3]); }
static uint64_t s_findwindow(uint64_t* a) {
    return (uint64_t)(uintptr_t)FindWindowExW(HW(a[0]), HW(a[1]), a[2] ? ustr(a[2]) : NULL, a[3] ? ustr(a[3]) : NULL);
}
/* NtUserSetWindowLong(Ptr)(hwnd, index, value, bAnsi): the host's, and the
 * WND's copy (GetWindowLong is client-side); GWLP_WNDPROC of a guest window
 * is its WND's procedure (the host's stays the thunk) */
static uint64_t s_setlong(uint64_t* a) {
    HWND h = HW(a[0]);
    int i = (int)a[1];
    uint8_t* w = user_wnd(h);
    if (i == GWLP_WNDPROC && w) {
        uint64_t old = Q(w, WND_PROC);
        if ((WNDPROC)GetWindowLongPtrW(h, GWLP_WNDPROC) != wnd_thunk) SetWindowLongPtrW(h, GWLP_WNDPROC, (LONG_PTR)wnd_thunk);
        Q(w, WND_PROC) = a[2];
        B(w, WND_STATE2A) &= ~4;
        return old;
    }
    uint64_t r = (uint64_t)SetWindowLongPtrW(h, i, (LONG_PTR)a[2]);
    if (w && i >= 0 && (uint32_t)i + 8 <= D(w, WND_CBEXTRA) + 4) {
        if ((uint32_t)i + 8 <= D(w, WND_CBEXTRA)) Q(w, WND_EXTRA + i) = a[2];
        else D(w, WND_EXTRA + i) = (uint32_t)a[2];
    }
    if (w && i == GWLP_USERDATA) Q(w, 0xF8) = a[2];
    if (w && i == GWLP_ID) Q(w, WND_MENU) = a[2];
    if (w) wnd_sync(h, w);
    return r;
}
/* NtUserSetWindowFNID(hwnd, fnid) */
static uint64_t s_set_fnid(uint64_t* a) {
    uint8_t* w = user_wnd(HW(a[0]));
    if (w) W(w, WND_FNID) = (uint16_t)a[1];
    return w != NULL;
}
/* NtUserQueryWindow(hwnd, what): 0 the process, 1 the thread */
static uint64_t s_query_window(uint64_t* a) {
    DWORD pid = 0, tid = GetWindowThreadProcessId(HW(a[0]), &pid);
    if (a[1] == 0) return pid;
    if (a[1] == 1) return tid;
    fprintf(stderr, "[user] NtUserQueryWindow %llu not answered\n", a[1]);
    return 0;
}
static uint64_t s_internal_text(uint64_t* a) { return (uint64_t)InternalGetWindowText(HW(a[0]), (LPWSTR)(uintptr_t)a[1], (int)a[2]); }
/* NtUserDefSetText(hwnd, LARGE_STRING*): DefWindowProc's WM_SETTEXT/WM_NCCREATE */
static uint64_t s_defsettext(uint64_t* a) {
    const wchar_t* t = a[1] ? lstr(a[1]) : L"";
    BOOL r = DefWindowProcW(HW(a[0]), WM_SETTEXT, 0, (LPARAM)(t ? t : L""));
    uint8_t* w = user_wnd(HW(a[0]));
    if (w) wnd_sync(HW(a[0]), w);
    return r;
}
static uint64_t s_getclassname(uint64_t* a) {
    /* NtUserGetClassName(hwnd, bReal, UNICODE_STRING* out) */
    uint64_t us = a[2];
    int n = GetClassNameW(HW(a[0]), (LPWSTR)(uintptr_t)Q(us, 8), W(us, 2) / 2);
    return (uint64_t)(n > 0 ? n : 0);
}
/* NtUserGetAtomName(atom, UNICODE_STRING* out): the user atom table (class
 * names and clipboard formats share it, so GetClipboardFormatName reads it) */
static uint64_t s_atom_name(uint64_t* a) {
    uint64_t us = a[1];
    int n = GetClipboardFormatNameW((UINT)a[0], (LPWSTR)(uintptr_t)Q(us, 8), W(us, 2) / 2);
    if (n > 0) W(us, 0) = (uint16_t)(n * 2);
    return (uint64_t)(n > 0 ? n : 0);
}
static uint64_t s_getancestor(uint64_t* a) { return (uint64_t)(uintptr_t)GetAncestor(HW(a[0]), (UINT)a[1]); }
static uint64_t s_redrawframe(uint64_t* a) { (void)a; return 1; }
static uint64_t s_scrollwindow(uint64_t* a) {
    return (uint64_t)ScrollWindowEx(HW(a[0]), (int)a[1], (int)a[2], (RECT*)(uintptr_t)a[3], (RECT*)(uintptr_t)a[4],
                                    (HRGN)HH(a[5]), (RECT*)(uintptr_t)a[6], (UINT)a[7]);
}
static uint64_t s_setscrollinfo(uint64_t* a) { return (uint64_t)SetScrollInfo(HW(a[0]), (int)a[1], (SCROLLINFO*)(uintptr_t)a[2], (BOOL)a[3]); }
static uint64_t s_showscrollbar(uint64_t* a) { return ShowScrollBar(HW(a[0]), (int)a[1], (BOOL)a[2]); }
static uint64_t s_translate_accel(uint64_t* a) { return TranslateAcceleratorW(HW(a[0]), (HACCEL)(uintptr_t)a[1], (MSG*)(uintptr_t)a[2]); }
static uint64_t s_create_accel(uint64_t* a) { return (uint64_t)(uintptr_t)CreateAcceleratorTableW((ACCEL*)(uintptr_t)a[0], (int)a[1]); }
static uint64_t s_get_placement(uint64_t* a) { return GetWindowPlacement(HW(a[0]), (WINDOWPLACEMENT*)(uintptr_t)a[1]); }
static uint64_t s_set_placement(uint64_t* a) { return SetWindowPlacement(HW(a[0]), (WINDOWPLACEMENT*)(uintptr_t)a[1]); }
/* NtUserSystemParametersInfo(action, uParam, pvParam, fWinIni): read only */
static uint64_t s_spi(uint64_t* a) {
    UINT act = (UINT)a[0];
    if (act & 1 && act != SPI_GETNONCLIENTMETRICS && act != SPI_GETICONTITLELOGFONT) {
        /* a SPI_SET*: never the host's settings (the GETs are the even numbers, mostly) */
        if (act > 0x1000 ? (act & 1) : (act == SPI_SETDESKWALLPAPER || act == SPI_SETWORKAREA)) return 1;
    }
    return SystemParametersInfoW(act, (UINT)a[1], (void*)(uintptr_t)a[2], 0);
}
static uint64_t s_getobjinfo(uint64_t* a) { return GetUserObjectInformationW(HH(a[0]), (int)a[1], (void*)(uintptr_t)a[2], (DWORD)a[3], (DWORD*)(uintptr_t)a[4]); }
static uint64_t s_threaddesk(uint64_t* a) { (void)a; return (uint64_t)(uintptr_t)GetThreadDesktop(GetCurrentThreadId()); }
static uint64_t s_winsta(uint64_t* a) { (void)a; return (uint64_t)(uintptr_t)GetProcessWindowStation(); }
static uint64_t s_getcaretblink(uint64_t* a) { (void)a; return GetCaretBlinkTime(); }
static uint64_t s_dblclick(uint64_t* a) { (void)a; return GetDoubleClickTime(); }
static uint64_t s_setprop(uint64_t* a) { return SetPropW(HW(a[0]), (LPCWSTR)(uintptr_t)(uint16_t)a[1], HH(a[2])); }
static uint64_t s_removeprop(uint64_t* a) { return (uint64_t)(uintptr_t)RemovePropW(HW(a[0]), (LPCWSTR)(uintptr_t)(uint16_t)a[1]); }
static uint64_t s_getcpd(uint64_t* a) { (void)a; return 0; }
/* NtUserFillWindow(hwndBrush, hwnd, hdc, hbr): a CTLCOLOR_* index in hbr asks for the brush */
static uint64_t s_fill_window(uint64_t* a) {
    HWND hb = HW(a[0]), h = HW(a[1]);
    HDC d = dc(a[2]);
    uint64_t br = a[3];
    RECT r;
    if (br <= 6) br = (uint64_t)SendMessageW(hb ? hb : h, WM_CTLCOLORMSGBOX + (UINT)br, (WPARAM)d, (LPARAM)h);
    if (!br) return 0;
    GetClientRect(h, &r);
    return FillRect(d, &r, (HBRUSH)HH(br));
}
/* NtUserGetClassInfo(Ex)(hinst, UNICODE_STRING* name, WNDCLASSEXW*, PWSTR* menu, bAnsi) */
static uint64_t s_classinfo(uint64_t* a) {
    WNDCLASSEXW* wc = (WNDCLASSEXW*)(uintptr_t)a[2];
    const wchar_t* n = ustr_or_atom(a[1]);
    wc->cbSize = sizeof *wc;
    ATOM r = (ATOM)GetClassInfoExW((HINSTANCE)(uintptr_t)a[0], n, wc);
    if (!r) for (int i = 0; i < g_ncl && !r; i++) r = (ATOM)GetClassInfoExW(g_cl[i].inst, n, wc);
    if (r && wc->lpfnWndProc == wnd_thunk)
        for (int i = 0; i < g_ncl; i++) if (g_cl[i].atom == r) wc->lpfnWndProc = (WNDPROC)(uintptr_t)g_cl[i].proc;
    if (a[3]) Q(a[3], 0) = 0;
    return r;
}
/* NtUserGetWindowPlacement etc. are above; NtUserGetControlBrush/Color: the host's CTLCOLOR */
static uint64_t s_getcontrolbrush(uint64_t* a) {
    uint64_t r = (uint64_t)SendMessageW(GetParent(HW(a[0])), (UINT)a[2], (WPARAM)HH(a[1]), (LPARAM)HW(a[0]));
    return r ? G((HANDLE)(uintptr_t)r) : G(GetSysColorBrush(COLOR_WINDOW));
}
static uint64_t s_drawcaptiontemp(uint64_t* a) { (void)a; return 1; }
static uint64_t s_hwndlist(uint64_t* a) {
    /* NtUserBuildHwndList(hdesk, hwndParent, bChildren, threadId, cHwndMax, phwnd, pcHwnd) */
    /* ponytail: no list (no caller here needs one yet) */
    if (a[6]) D(a[6], 0) = 0;
    return 0;
}

/* ---- GDI services ---------------------------------------------------------- */
static uint64_t g_init(uint64_t* a) {
    (void)a;
    uint8_t* peb = (uint8_t*)(uintptr_t)native64_peb;
    if (!g_gt) {
        g_gt = (uint8_t*)VirtualAlloc(NULL, GDI_ENTRIES * 24 + 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        Q(peb, 0xF8) = (uint64_t)(uintptr_t)g_gt;
    }
    return 1;
}
static uint64_t g_stock(uint64_t* a) { return G(GetStockObject((int)a[0])); }
static uint64_t g_compat_dc(uint64_t* a) { return gdi_enter(CreateCompatibleDC(a[0] ? dc(a[0]) : NULL), 1); }
static uint64_t g_compat_bitmap(uint64_t* a) { return G(CreateCompatibleBitmap(dc(a[0]), (int)a[1], (int)a[2])); }
static uint64_t g_pen(uint64_t* a) { return G(CreatePen((int)a[0], (int)a[1], (COLORREF)a[2])); }
static uint64_t g_brush(uint64_t* a) { return G(CreateSolidBrush((COLORREF)a[0])); }
static uint64_t g_hatchbrush(uint64_t* a) { return G(CreateHatchBrush((int)a[0], (COLORREF)a[1])); }
static uint64_t g_patbrush(uint64_t* a) { return G(CreatePatternBrush((HBITMAP)HH(a[0]))); }
static uint64_t g_rectrgn(uint64_t* a) { return G(CreateRectRgn((int)a[0], (int)a[1], (int)a[2], (int)a[3])); }
static uint64_t g_select_bitmap(uint64_t* a) { return G(SelectObject(dc(a[0]), HH(a[1]))); }
static uint64_t g_select(uint64_t* a) { return G(SelectObject(dc(a[0]), HH(a[1]))); }
static uint64_t g_delete(uint64_t* a) {
    HANDLE h = HH(a[0]);
    for (int i = 0; i <= DC_PEN; i++) if (GetStockObject(i) == h) return 1;
    BOOL r = ((a[0] >> 16) & 0x1F) == 1 ? DeleteDC((HDC)h) : DeleteObject(h);
    if (r) gdi_forget(a[0]);
    return r;
}
static uint64_t g_bitblt(uint64_t* a) {
    return BitBlt(dc(a[0]), (int)a[1], (int)a[2], (int)a[3], (int)a[4], a[5] ? dc(a[5]) : NULL, (int)a[6], (int)a[7], (DWORD)a[8]);
}
static uint64_t g_stretchblt(uint64_t* a) {
    return StretchBlt(dc(a[0]), (int)a[1], (int)a[2], (int)a[3], (int)a[4], a[5] ? dc(a[5]) : NULL, (int)a[6], (int)a[7], (int)a[8], (int)a[9], (DWORD)a[10]);
}
static uint64_t g_patblt(uint64_t* a) { return PatBlt(dc(a[0]), (int)a[1], (int)a[2], (int)a[3], (int)a[4], (DWORD)a[5]); }
/* NtGdiPolyPatBlt(hdc, rop, POLYPATBLT* { x, y, cx, cy, brush (8) } x n, n, mode) */
static uint64_t g_polypatblt(uint64_t* a) {
    HDC h = dc(a[0]);
    uint8_t* p = (uint8_t*)(uintptr_t)a[2];
    for (uint64_t i = 0; i < a[3]; i++, p += 0x18) {
        HGDIOBJ old = Q(p, 0x10) ? SelectObject(h, HH(Q(p, 0x10))) : NULL;
        PatBlt(h, (int)D(p, 0), (int)D(p, 4), (int)D(p, 8), (int)D(p, 0xC), (DWORD)a[1]);
        if (old) SelectObject(h, old);
    }
    return 1;
}
static uint64_t g_lineto(uint64_t* a) { BOOL r = LineTo(dc(a[0]), (int)a[1], (int)a[2]); dc_back(a[0]); return r; }
static uint64_t g_rectangle(uint64_t* a) { return Rectangle(dc(a[0]), (int)a[1], (int)a[2], (int)a[3], (int)a[4]); }
static uint64_t g_ellipse(uint64_t* a) { return Ellipse(dc(a[0]), (int)a[1], (int)a[2], (int)a[3], (int)a[4]); }
static uint64_t g_roundrect(uint64_t* a) { return RoundRect(dc(a[0]), (int)a[1], (int)a[2], (int)a[3], (int)a[4], (int)a[5], (int)a[6]); }
static uint64_t g_fillrgn(uint64_t* a) { return FillRgn(dc(a[0]), (HRGN)HH(a[1]), (HBRUSH)HH(a[2])); }
static uint64_t g_framergn(uint64_t* a) { return FrameRgn(dc(a[0]), (HRGN)HH(a[1]), (HBRUSH)HH(a[2]), (int)a[3], (int)a[4]); }
static uint64_t g_setpixel(uint64_t* a) { return SetPixel(dc(a[0]), (int)a[1], (int)a[2], (COLORREF)a[3]); }
static uint64_t g_getpixel(uint64_t* a) { return GetPixel(dc(a[0]), (int)a[1], (int)a[2]); }
static uint64_t g_devcaps(uint64_t* a) { return (uint64_t)GetDeviceCaps(a[0] ? dc(a[0]) : NULL, (int)a[1]); }
static uint64_t g_intersectclip(uint64_t* a) { return (uint64_t)IntersectClipRect(dc(a[0]), (int)a[1], (int)a[2], (int)a[3], (int)a[4]); }
static uint64_t g_excludeclip(uint64_t* a) { return (uint64_t)ExcludeClipRect(dc(a[0]), (int)a[1], (int)a[2], (int)a[3], (int)a[4]); }
static uint64_t g_selectcliprgn(uint64_t* a) { return (uint64_t)ExtSelectClipRgn(dc(a[0]), (HRGN)HH(a[1]), (int)a[2]); }
static uint64_t g_appclipbox(uint64_t* a) { return (uint64_t)GetClipBox(dc(a[0]), (RECT*)(uintptr_t)a[1]); }
static uint64_t g_randomrgn(uint64_t* a) { return (uint64_t)GetRandomRgn(dc(a[0]), (HRGN)HH(a[1]), (INT)a[2]); }
static uint64_t g_combinergn(uint64_t* a) { return (uint64_t)CombineRgn((HRGN)HH(a[0]), (HRGN)HH(a[1]), (HRGN)HH(a[2]), (int)a[3]); }
static uint64_t g_offsetrgn(uint64_t* a) { return (uint64_t)OffsetRgn((HRGN)HH(a[0]), (int)a[1], (int)a[2]); }
static uint64_t g_rgnbox(uint64_t* a) { return (uint64_t)GetRgnBox((HRGN)HH(a[0]), (RECT*)(uintptr_t)a[1]); }
static uint64_t g_savedc(uint64_t* a) { return (uint64_t)SaveDC(dc(a[0])); }
static uint64_t g_restoredc(uint64_t* a) { return RestoreDC(dc(a[0]), (int)a[1]); }
static uint64_t g_bitmap(uint64_t* a) { return G(CreateBitmap((int)a[0], (int)a[1], (UINT)a[2], (UINT)a[3], (void*)(uintptr_t)a[4])); }
/* NtGdiExtGetObjectW(h, count, buffer). A window DC's bitmap (the screen's
 * surface) has no BITMAP on the host; XP answered the screen's size and depth
 * (winmine reads its colour depth so) */
static uint64_t g_getobject(uint64_t* a) {
    int r = GetObjectW(HH(a[0]), (int)a[1], (void*)(uintptr_t)a[2]);
    if (!r && ((a[0] >> 16) & 0x1F) == 5 && a[2] && a[1] >= sizeof(BITMAP)) {
        BITMAP* b = (BITMAP*)(uintptr_t)a[2];
        HDC s = GetDC(NULL);
        memset(b, 0, sizeof *b);
        b->bmWidth = GetDeviceCaps(s, HORZRES), b->bmHeight = GetDeviceCaps(s, VERTRES);
        b->bmPlanes = 1, b->bmBitsPixel = (WORD)GetDeviceCaps(s, BITSPIXEL);
        b->bmWidthBytes = ((b->bmWidth * b->bmBitsPixel + 15) / 16) * 2;
        ReleaseDC(NULL, s);
        r = sizeof(BITMAP);
    }
    return (uint64_t)r;
}
static uint64_t g_font(uint64_t* a) { return G(CreateFontIndirectW((LOGFONTW*)(uintptr_t)a[0])); }
static uint64_t g_textout(uint64_t* a) {
    return ExtTextOutW(dc(a[0]), (int)a[1], (int)a[2], (UINT)a[3], (RECT*)(uintptr_t)a[4], (LPCWSTR)(uintptr_t)a[5], (UINT)a[6], (const INT*)(uintptr_t)a[7]);
}
static uint64_t g_flush(uint64_t* a) { (void)a; gdi_flush(); return 0; }
static uint64_t g_textmetrics(uint64_t* a) {
    TEXTMETRICW tm;
    if (!GetTextMetricsW(dc(a[0]), &tm)) return 0;
    memset((void*)(uintptr_t)a[1], 0, (size_t)a[2]);
    memcpy((void*)(uintptr_t)a[1], &tm, a[2] < sizeof tm ? (size_t)a[2] : sizeof tm);
    return 1;
}
/* NtGdiGetTextExtentExW(hdc, pwsz, cwc, dxMax, *nFit, pdxOut, SIZE*, fl) */
static uint64_t g_textextentex(uint64_t* a) {
    return GetTextExtentExPointW(dc(a[0]), (LPCWSTR)(uintptr_t)a[1], (int)a[2], (int)a[3], (INT*)(uintptr_t)a[4], (INT*)(uintptr_t)a[5], (SIZE*)(uintptr_t)a[6]);
}
/* NtGdiGetTextExtent(hdc, pwsz, cwc, SIZE*, fl) */
static uint64_t g_textextent(uint64_t* a) { return GetTextExtentPoint32W(dc(a[0]), (LPCWSTR)(uintptr_t)a[1], (int)a[2], (SIZE*)(uintptr_t)a[3]); }
static uint64_t g_textface(uint64_t* a) { return (uint64_t)GetTextFaceW(dc(a[0]), (int)a[1], (LPWSTR)(uintptr_t)a[2]); }
static uint64_t g_charset(uint64_t* a) { return (uint64_t)GetTextCharsetInfo(dc(a[0]), (FONTSIGNATURE*)(uintptr_t)a[1], (DWORD)a[2]); }
static uint64_t g_getcharset(uint64_t* a) {
    CHARSETINFO ci = { 0 };
    int cs = GetTextCharset(dc(a[0]));
    TranslateCharsetInfo((DWORD*)(uintptr_t)cs, &ci, TCI_SRCCHARSET);
    return ci.ciACP << 16 | (cs & 0xFFFF);
}
static uint64_t g_charwidth(uint64_t* a) {
    HDC h = dc(a[0]);
    const WCHAR* l = (const WCHAR*)(uintptr_t)a[3];
    for (uint64_t i = 0; i < a[2]; i++) {
        UINT c = l ? l[i] : (UINT)(a[1] + i);
        void* out = (void*)(uintptr_t)(a[5] + 4 * i);
        if (!(a[4] & 2 ? GetCharWidth32W(h, c, c, out) : GetCharWidthFloatW(h, c, c, out))) return 0;
    }
    return 1;
}
static uint64_t g_dibsection(uint64_t* a) {
    void* bits = NULL;
    HBITMAP b = CreateDIBSection(a[0] ? dc(a[0]) : NULL, (BITMAPINFO*)(uintptr_t)a[3], (UINT)a[4], &bits, NULL, 0);
    if (a[8]) Q(a[8], 0) = (uint64_t)(uintptr_t)bits;
    return G(b);
}
static uint64_t g_dibitmap(uint64_t* a) {
    BITMAPINFO* bi = (BITMAPINFO*)(uintptr_t)a[5];
    static HDC screen;
    HDC h = a[0] ? dc(a[0]) : NULL;
    if (!screen) screen = GetDC(NULL);
    if (!bi) return G(CreateCompatibleBitmap(h ? h : screen, (int)a[1], (int)a[2]));
    if ((a[3] & 2) && bi->bmiHeader.biBitCount > 1) h = screen;
    return G(CreateDIBitmap(h ? h : screen, &bi->bmiHeader, (DWORD)(a[3] & CBM_INIT), (void*)(uintptr_t)a[4], bi, (UINT)a[6]));
}
static uint64_t g_getdibits(uint64_t* a) {
    static HDC screen;
    if (!screen) screen = GetDC(NULL);
    return (uint64_t)GetDIBits(a[0] ? dc(a[0]) : screen, (HBITMAP)HH(a[1]), (UINT)a[2], (UINT)a[3], (void*)(uintptr_t)a[4], (BITMAPINFO*)(uintptr_t)a[5], (UINT)a[6]);
}
static uint64_t g_setdibits(uint64_t* a) {
    return (uint64_t)SetDIBitsToDevice(dc(a[0]), (int)a[1], (int)a[2], (DWORD)a[3], (DWORD)a[4], (int)a[5], (int)a[6], (UINT)a[7], (UINT)a[8],
                                       (void*)(uintptr_t)a[9], (BITMAPINFO*)(uintptr_t)a[10], (UINT)a[11]);
}
static uint64_t g_stretchdib(uint64_t* a) {
    return (uint64_t)StretchDIBits(dc(a[0]), (int)a[1], (int)a[2], (int)a[3], (int)a[4], (int)a[5], (int)a[6], (int)a[7], (int)a[8],
                                   (void*)(uintptr_t)a[9], (BITMAPINFO*)(uintptr_t)a[10], (UINT)a[11], (DWORD)a[12]);
}
static uint64_t g_dcobject(uint64_t* a) {
    UINT t = 0;
    switch ((a[1] >> 16) & 0x7F) { case 5: t = OBJ_BITMAP; break; case 8: t = OBJ_PAL; break; case 0xA: t = OBJ_FONT; break;
                                   case 0x10: t = OBJ_BRUSH; break; case 0x30: t = OBJ_PEN; break; }
    return t ? G(GetCurrentObject(dc(a[0]), t)) : 0;
}
static uint64_t g_dcpoint(uint64_t* a) {
    if (a[1] == 6) return GetDCOrgEx(dc(a[0]), (POINT*)(uintptr_t)a[2]);
    fprintf(stderr, "[gdi] NtGdiGetDCPoint %llu not answered\n", a[1]);
    return 0;
}
static uint64_t g_getdword(uint64_t* a) {
    HDC h = dc(a[0]);
    uint32_t v;
    if (a[1] == 7) v = GetObjectType(h) == OBJ_MEMDC;
    else if (a[1] == 6) v = GetFontLanguageInfo(h);
    else if (a[1] == 4) v = (uint32_t)GetArcDirection(h);
    else { fprintf(stderr, "[gdi] NtGdiGetDCDword index %llu not answered\n", a[1]); return 0; }
    if (a[2]) D(a[2], 0) = v;
    return 1;
}
static uint64_t g_getsetdword(uint64_t* a) {
    if (a[1] == 8) {
        int o = SetMapMode(dc(a[0]), (int)a[2]);
        uint8_t* at = gattr(a[0]);
        if (at && o) D(at, DA_MAPMODE) = (uint32_t)a[2];
        if (a[3]) D(a[3], 0) = (uint32_t)o;
        return o != 0;
    }
    fprintf(stderr, "[gdi] NtGdiGetAndSetDCDword index %llu not answered\n", a[1]);
    return 0;
}
static uint64_t g_opendc(uint64_t* a) {
    const wchar_t* d = a[0] ? ustr(a[0]) : L"DISPLAY";
    return gdi_enter(a[3] == 2 ? CreateICW(d, NULL, NULL, (DEVMODEW*)(uintptr_t)a[1]) : CreateDCW(d, NULL, NULL, (DEVMODEW*)(uintptr_t)a[1]), 1);
}
static uint64_t g_setlayout(uint64_t* a) { return SetLayout(dc(a[0]), (DWORD)a[2]); }
static uint64_t g_rectvisible(uint64_t* a) { return RectVisible(dc(a[0]), (RECT*)(uintptr_t)a[1]); }
static uint64_t g_ptvisible(uint64_t* a) { return PtVisible(dc(a[0]), (int)a[1], (int)a[2]); }
static uint64_t g_bitmapbits(uint64_t* a) { return (uint64_t)GetBitmapBits((HBITMAP)HH(a[0]), (LONG)a[1], (void*)(uintptr_t)a[2]); }
static uint64_t g_nearestcolor(uint64_t* a) { return GetNearestColor(dc(a[0]), (COLORREF)a[1]); }
static uint64_t g_otm(uint64_t* a) {
    HDC h = dc(a[0]);
    if (a[3]) memset((void*)(uintptr_t)a[3], 0, 8), D(a[3], 0) = GetOutlineTextMetricsA(h, 0, NULL);
    return GetOutlineTextMetricsW(h, (UINT)a[1], (OUTLINETEXTMETRICW*)(uintptr_t)a[2]);
}
static uint64_t g_polypolydraw(uint64_t* a) {
    HDC h = a[4] == 6 ? NULL : dc(a[0]);
    const POINT* p = (const POINT*)(uintptr_t)a[1];
    const DWORD* c = (const DWORD*)(uintptr_t)a[2];
    INT n[64];
    uint32_t k = (uint32_t)(a[3] < 64 ? a[3] : 64);
    for (uint32_t i = 0; i < k; i++) n[i] = (INT)c[i];
    switch (a[4]) {
    case 1: return PolyPolygon(h, p, n, (int)k);
    case 2: return PolyPolyline(h, p, c, k);
    case 3: return PolyBezier(h, p, c[0]);
    case 4: { BOOL r = PolylineTo(h, p, c[0]); dc_back(a[0]); return r; }
    case 5: { BOOL r = PolyBezierTo(h, p, c[0]); dc_back(a[0]); return r; }
    case 6: return G(CreatePolyPolygonRgn(p, n, (int)k, (int)a[0]));
    }
    return 0;
}
static uint64_t g_moveto(uint64_t* a) { BOOL r = MoveToEx(dc(a[0]), (int)a[1], (int)a[2], (POINT*)(uintptr_t)a[3]); dc_back(a[0]); return r; }
static uint64_t g_fontassoc(uint64_t* a) { (void)a; return 0; }
static uint64_t g_bitmap_attrs(uint64_t* a) { return a[0]; }
static uint64_t g_dcforbitmap(uint64_t* a) { (void)a; return 0; }
static uint64_t g_extcreatepen(uint64_t* a) {
    /* NtGdiExtCreatePen(style, width, brushstyle, color, hatch, bmp?, cstyle, pstyle, cjDIB, bOldStyle, hbrush) */
    LOGBRUSH lb = { (UINT)a[2], (COLORREF)a[3], (ULONG_PTR)a[4] };
    return G(ExtCreatePen((DWORD)a[0], (DWORD)a[1], &lb, (DWORD)a[6], (const DWORD*)(uintptr_t)a[7]));
}

/* ---- the guest's screen from inside: XP64_KEYS / XP64_SHOT ----------------
 * XP64_KEYS=T:text (\n Enter) types text into the guest's focused window T
 * seconds in; XP64_SHOT=T:file.bmp writes the guest's top-level window as a
 * 24-bit BMP (PrintWindow of its own window, from this process). Several of
 * each, separated by ';'. */
static HWND top_window(void) {
    for (int i = 0; i < g_nwnds; i++)
        if (IsWindow(g_wnds[i]) && IsWindowVisible(g_wnds[i]) && !(GetWindowLongW(g_wnds[i], GWL_STYLE) & WS_CHILD) &&
            !GetWindow(g_wnds[i], GW_OWNER))
            return g_wnds[i];
    return NULL;
}
static void write_bmp(HWND h, const char* path) {
    RECT r;
    GetWindowRect(h, &r);
    int w = r.right - r.left, ht = r.bottom - r.top;
    HDC s = GetDC(NULL), m = CreateCompatibleDC(s);
    BITMAPINFO bi = { { sizeof(BITMAPINFOHEADER), w, ht, 1, 24, BI_RGB } };
    void* bits;
    HBITMAP b = CreateDIBSection(s, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
    HGDIOBJ o = SelectObject(m, b);
    PatBlt(m, 0, 0, w, ht, WHITENESS);
    BOOL ok = PrintWindow(h, m, 0);
    fprintf(stderr, "[shot] PrintWindow %d\n", ok);
    if (TRACE)   /* each child's text: what the picture should show */
        for (HWND c = GetWindow(h, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT)) {
            wchar_t t[128] = L"";
            RECT r;
            GetWindowTextW(c, t, 127), GetWindowRect(c, &r);
            if (t[0]) fprintf(stderr, "[shot]  %p (%ld,%ld %ldx%ld) \"%ls\"\n", (void*)c, r.left, r.top, r.right - r.left, r.bottom - r.top, t);
        }
    GdiFlush();
    FILE* f = fopen(path, "wb");
    if (f) {
        uint32_t stride = ((uint32_t)w * 3 + 3) & ~3u, size = stride * (uint32_t)ht;
        BITMAPFILEHEADER fh = { 0x4D42, sizeof fh + sizeof bi.bmiHeader + size, 0, 0, sizeof fh + sizeof bi.bmiHeader };
        fwrite(&fh, sizeof fh, 1, f), fwrite(&bi.bmiHeader, sizeof bi.bmiHeader, 1, f), fwrite(bits, size, 1, f);
        fclose(f);
        fprintf(stderr, "[shot] %s: %dx%d\n", path, w, ht);
    }
    SelectObject(m, o), DeleteObject(b), DeleteDC(m), ReleaseDC(NULL, s);
}
static DWORD WINAPI script_thread(LPVOID p) {
    char* s = _strdup((const char*)p);
    DWORD t0 = GetTickCount();
    for (char* item = strtok(s, ";"); item; item = strtok(NULL, ";")) {
        double t = atof(item + 1);
        char* arg = strchr(item, ':');
        if (!arg) continue;
        arg++;
        while (GetTickCount() - t0 < (DWORD)(t * 1000)) Sleep(50);
        HWND top = top_window();
        if (item[0] == 'S' && top) write_bmp(top, arg);
        else if (item[0] == 'K' && top) {
            GUITHREADINFO gi = { sizeof gi };
            /* the focused window when it takes text (notepad's Edit), else the top window (calc reads WM_CHAR itself) */
            wchar_t cn[32] = L"";
            HWND to = GetGUIThreadInfo(g_gui_tid, &gi) && gi.hwndFocus ? gi.hwndFocus : top;
            GetClassNameW(to, cn, 32);
            if (_wcsicmp(cn, L"Edit")) to = top;
            for (char* c = arg; *c; c++) {
                WPARAM ch = (WPARAM)(unsigned char)*c;
                if (*c == '\\' && c[1] == 'n') ch = '\r', c++;
                PostMessageW(to, WM_CHAR, ch, 1);
                Sleep(60);
            }
        }
    }
    return 0;
}
/* "K2:12+3=;S4:out.bmp" from XP64_KEYS="2:12+3=" XP64_SHOT="4:out.bmp" */
static void script_start(void) {
    static char plan[2048];
    const char* k = getenv("XP64_KEYS"), *sh = getenv("XP64_SHOT");
    struct { double t; char kind; char arg[256]; } it[16];
    int n = 0;
    for (int pass = 0; pass < 2; pass++) {
        const char* v = pass ? sh : k;
        char buf[1024];
        if (!v) continue;
        strncpy(buf, v, sizeof buf - 1), buf[sizeof buf - 1] = 0;
        for (char* x = strtok(buf, ";"); x && n < 16; x = strtok(NULL, ";")) {
            char* c = strchr(x, ':');
            if (!c) continue;
            it[n].t = atof(x), it[n].kind = pass ? 'S' : 'K';
            strncpy(it[n].arg, c + 1, 255), it[n].arg[255] = 0;
            n++;
        }
    }
    if (!n) return;
    for (int i = 0; i < n; i++)          /* by time */
        for (int j = i + 1; j < n; j++)
            if (it[j].t < it[i].t) { char tmp[sizeof it[0]]; memcpy(tmp, &it[i], sizeof tmp); memcpy(&it[i], &it[j], sizeof tmp); memcpy(&it[j], tmp, sizeof tmp); }
    for (int i = 0; i < n; i++) {
        char one[300];
        _snprintf(one, sizeof one, "%c%g:%s;", it[i].kind, it[i].t, it[i].arg);
        strncat(plan, one, sizeof plan - strlen(plan) - 1);
    }
    CreateThread(NULL, 0, script_thread, plan, 0, NULL);
}

/* every win32k service is preceded by the shared state's refresh */
typedef struct { const char* name; native64_syscall_fn fn; } svc_t;
static const svc_t g_user[] = {
    { "NtUserRegisterClassExWOW", s_register_class }, { "NtUserCreateWindowEx", s_create_window },
    { "NtUserMessageCall", s_message_call }, { "NtUserGetThreadState", s_thread_state },
    { "NtUserCallNoParam", s_call_noparam }, { "NtUserCallOneParam", s_call_oneparam }, { "NtUserCallTwoParam", s_call_twoparam },
    { "NtUserCallHwnd", s_call_hwnd }, { "NtUserCallHwndOpt", s_call_hwndopt }, { "NtUserCallHwndLock", s_call_hwndlock },
    { "NtUserCallHwndParam", s_call_hwndparam }, { "NtUserCallHwndParamLock", s_call_hwndparamlock },
    { "NtUserShowWindow", s_show }, { "NtUserGetMessage", s_getmessage }, { "NtUserPeekMessage", s_peekmessage },
    { "NtUserTranslateMessage", s_translate }, { "NtUserDispatchMessage", s_dispatch }, { "NtUserWaitMessage", s_waitmessage },
    { "NtUserPostMessage", s_post }, { "NtUserPostThreadMessage", s_post_thread },
    { "NtUserBeginPaint", s_beginpaint }, { "NtUserEndPaint", s_endpaint }, { "NtUserGetDC", s_getdc },
    { "NtUserGetWindowDC", s_getwindowdc }, { "NtUserGetDCEx", s_getdcex }, { "NtUserInvalidateRect", s_invalidate },
    { "NtUserRedrawWindow", s_redraw }, { "NtUserGetUpdateRect", s_getupdaterect }, { "NtUserMoveWindow", s_move },
    { "NtUserSetWindowPos", s_setpos }, { "NtUserDestroyWindow", s_destroy }, { "NtUserSetFocus", s_setfocus },
    { "NtUserSetActiveWindow", s_setactive }, { "NtUserSetCapture", s_setcapture }, { "NtUserGetForegroundWindow", s_foreground },
    { "NtUserSetTimer", s_settimer }, { "NtUserKillTimer", s_killtimer }, { "NtUserValidateTimerCallback", s_validate_timer },
    { "NtUserRegisterWindowMessage", s_register_msg }, { "NtUserSetMenu", s_setmenu }, { "NtUserGetKeyState", s_keystate },
    { "NtUserGetAsyncKeyState", s_asynckeystate }, { "NtUserGetKeyboardState", s_getkeyboardstate }, { "NtUserSetCursor", s_setcursor },
    { "NtUserShowCaret", s_showcaret }, { "NtUserHideCaret", s_hidecaret }, { "NtUserCreateCaret", s_createcaret },
    { "NtUserFindWindowEx", s_findwindow }, { "NtUserSetWindowLong", s_setlong }, { "NtUserSetWindowLongPtr", s_setlong },
    { "NtUserSetWindowFNID", s_set_fnid }, { "NtUserQueryWindow", s_query_window }, { "NtUserInternalGetWindowText", s_internal_text },
    { "NtUserDefSetText", s_defsettext }, { "NtUserGetClassName", s_getclassname }, { "NtUserGetAncestor", s_getancestor }, { "NtUserFindExistingCursorIcon", s_find_icon }, { "NtUserGetAtomName", s_atom_name },
    { "NtUserRedrawFrame", s_redrawframe }, { "NtUserScrollWindowEx", s_scrollwindow }, { "NtUserSetScrollInfo", s_setscrollinfo },
    { "NtUserShowScrollBar", s_showscrollbar }, { "NtUserTranslateAccelerator", s_translate_accel },
    { "NtUserCreateAcceleratorTable", s_create_accel }, { "NtUserGetWindowPlacement", s_get_placement },
    { "NtUserSetWindowPlacement", s_set_placement }, { "NtUserSystemParametersInfo", s_spi },
    { "NtUserGetObjectInformation", s_getobjinfo }, { "NtUserGetThreadDesktop", s_threaddesk },
    { "NtUserGetProcessWindowStation", s_winsta }, { "NtUserGetCaretBlinkTime", s_getcaretblink },
    { "NtUserGetDoubleClickTime", s_dblclick }, { "NtUserSetProp", s_setprop }, { "NtUserRemoveProp", s_removeprop },
    { "NtUserGetCPD", s_getcpd }, { "NtUserFillWindow", s_fill_window }, { "NtUserGetClassInfo", s_classinfo },
    { "NtUserGetClassInfoEx", s_classinfo }, { "NtUserGetControlBrush", s_getcontrolbrush }, { "NtUserDrawCaptionTemp", s_drawcaptiontemp },
    { "NtUserBuildHwndList", s_hwndlist }, { "NtUserModifyUserStartupInfoFlags", s_one }, { "NtUserNotifyProcessCreate", s_one },
    { "NtUserSetThreadState", s_zero }, { "NtUserThunkedMenuItemInfo", s_menu_item }, { "NtUserDestroyMenu", s_destroy_menu },
    { "NtUserCheckMenuItem", s_check_menu }, { "NtUserEnableMenuItem", s_enable_menu }, { "NtUserRemoveMenu", s_remove_menu },
    { "NtUserDeleteMenu", s_delete_menu }, { "NtUserSetMenuDefaultItem", s_menu_default }, { "NtUserGetSystemMenu", s_getsysmenu }, { "NtUserGetMenuItemRect", s_menu_rect }, { "NtUserUpdateInputContext", s_zero }, { "NtUserGetImeInfoEx", s_zero },
};
static const svc_t g_gdi[] = {
    { "NtGdiInit", g_init }, { "NtGdiGetStockObject", g_stock }, { "NtGdiCreateCompatibleDC", g_compat_dc },
    { "NtGdiCreateCompatibleBitmap", g_compat_bitmap }, { "NtGdiCreatePen", g_pen }, { "NtGdiCreateSolidBrush", g_brush },
    { "NtGdiCreateHatchBrushInternal", g_hatchbrush }, { "NtGdiCreatePatternBrushInternal", g_patbrush },
    { "NtGdiCreateRectRgn", g_rectrgn }, { "NtGdiSelectBitmap", g_select_bitmap }, { "NtGdiSelectBrush", g_select },
    { "NtGdiSelectPen", g_select }, { "NtGdiSelectFont", g_select }, { "NtGdiDeleteObjectApp", g_delete },
    { "NtGdiBitBlt", g_bitblt }, { "NtGdiStretchBlt", g_stretchblt }, { "NtGdiPatBlt", g_patblt }, { "NtGdiPolyPatBlt", g_polypatblt },
    { "NtGdiLineTo", g_lineto }, { "NtGdiRectangle", g_rectangle }, { "NtGdiEllipse", g_ellipse }, { "NtGdiRoundRect", g_roundrect },
    { "NtGdiFillRgn", g_fillrgn }, { "NtGdiFrameRgn", g_framergn }, { "NtGdiSetPixel", g_setpixel }, { "NtGdiGetPixel", g_getpixel },
    { "NtGdiGetDeviceCaps", g_devcaps }, { "NtGdiIntersectClipRect", g_intersectclip }, { "NtGdiExcludeClipRect", g_excludeclip },
    { "NtGdiExtSelectClipRgn", g_selectcliprgn }, { "NtGdiGetAppClipBox", g_appclipbox }, { "NtGdiGetRandomRgn", g_randomrgn },
    { "NtGdiCombineRgn", g_combinergn }, { "NtGdiOffsetRgn", g_offsetrgn }, { "NtGdiGetRgnBox", g_rgnbox },
    { "NtGdiSaveDC", g_savedc }, { "NtGdiRestoreDC", g_restoredc }, { "NtGdiCreateBitmap", g_bitmap },
    { "NtGdiExtGetObjectW", g_getobject }, { "NtGdiHfontCreate", g_font }, { "NtGdiExtTextOutW", g_textout },
    { "NtGdiFlushUserBatch", g_flush }, { "NtGdiFlush", g_flush }, { "NtGdiGetTextMetricsW", g_textmetrics },
    { "NtGdiGetTextExtentExW", g_textextentex }, { "NtGdiGetTextExtent", g_textextent }, { "NtGdiGetTextFaceW", g_textface },
    { "NtGdiGetTextCharsetInfo", g_charset }, { "NtGdiGetCharSet", g_getcharset }, { "NtGdiGetCharWidthW", g_charwidth },
    { "NtGdiCreateDIBSection", g_dibsection }, { "NtGdiCreateDIBitmapInternal", g_dibitmap }, { "NtGdiGetDIBitsInternal", g_getdibits },
    { "NtGdiSetDIBitsToDeviceInternal", g_setdibits }, { "NtGdiStretchDIBitsInternal", g_stretchdib },
    { "NtGdiGetDCObject", g_dcobject }, { "NtGdiGetDCPoint", g_dcpoint }, { "NtGdiGetDCDword", g_getdword },
    { "NtGdiGetAndSetDCDword", g_getsetdword }, { "NtGdiOpenDCW", g_opendc }, { "NtGdiSetLayout", g_setlayout },
    { "NtGdiRectVisible", g_rectvisible }, { "NtGdiPtVisible", g_ptvisible }, { "NtGdiGetBitmapBits", g_bitmapbits },
    { "NtGdiGetNearestColor", g_nearestcolor }, { "NtGdiGetOutlineTextMetricsInternalW", g_otm },
    { "NtGdiPolyPolyDraw", g_polypolydraw }, { "NtGdiMoveTo", g_moveto }, { "NtGdiQueryFontAssocInfo", g_fontassoc },
    { "NtGdiSetBitmapAttributes", g_bitmap_attrs }, { "NtGdiGetDCforBitmap", g_dcforbitmap }, { "NtGdiExtCreatePen", g_extcreatepen },
};
static void pre(const char* name) { if (!strncmp(name, "NtUser", 6)) user_pre(); gdi_flush(); }
/* NT 6: NtUserProcessConnect(hProcess, USERCONNECT* { ulVersion, ulCurrentVersion,
 * SHAREDINFO (+8) }) replaces usersrv's csrss connect (csr64.c fills both) */
static uint64_t s_process_connect(uint64_t* a) {
    if (!a[1]) return 0xC000000Du;
    csr64_user_connect((uint8_t*)(uintptr_t)a[1] + 8);
    return 0;
}

void w32k64_install(void) {
    if (NATIVE64_NT6) {
        WND_NAME = 0xD8, WND_CBEXTRA = 0xE8, WND_EXTRA = 0x128;
        SI_METRICS = 0x758, SI_COLORS = 0xABC, SI_BRUSHES = 0xB38, SI_CXSYSFONT = 0xC6C, SI_ATOMSYSCLASS = 0x354;
        native64_w32k("NtUserProcessConnect", s_process_connect);
    }
    native64_override("NtCallbackReturn", ovr_callback_return);
    for (size_t i = 0; i < sizeof g_user / sizeof g_user[0]; i++) native64_w32k(g_user[i].name, g_user[i].fn);
    for (size_t i = 0; i < sizeof g_gdi / sizeof g_gdi[0]; i++) native64_w32k(g_gdi[i].name, g_gdi[i].fn);
    native64_win32k_pre = pre;
    script_start();
}

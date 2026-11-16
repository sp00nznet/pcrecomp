/*
 * w32kuser: USER's half of win32k, for a lifted Windows 2000 user32 (with
 * its gdi32 on w32kgdi.c) over the host's windows.
 *
 * Windows 2000's user32 is a client of state win32k keeps and maps into the
 * process: SERVERINFO (system metrics, colours, ...), the handle table every
 * HWND is validated against, the WND of each window, the thread's
 * CLIENTINFO. This layer answers the NtUser* services with real host
 * windows underneath and keeps those structures, in Windows 2000's layout,
 * for what user32 reads (docs/findings.md in win2000-recomp has the offsets
 * and where each came from).
 *
 * Messages: a guest class is registered with the host with wnd_thunk as
 * its procedure, which sends each message the way win32k does, through the
 * guest ntdll's KiUserCallbackDispatcher into user32's __fn* routines.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "native32.h"

/* UNICODE_STRING (buffer at +4) / LARGE_STRING (buffer at +8): a name, or an
 * atom in its place */
static const wchar_t* ustr_name(uint32_t us) { return us ? (const wchar_t*)(uintptr_t)MEM32(us + 4) : NULL; }
/* (a class may come as an atom instead: #32770 is 0x8002, the same on the host) */
/* LARGE_STRING { Length, MaximumLength:31 | bAnsi:1, Buffer }: CreateWindowExA
 * passes its window name ANSI (bAnsi). ponytail: two rotating buffers of
 * 512, enough for one call's class and name */
static const wchar_t* lstr_name(uint32_t ls) {
    static wchar_t buf[2][512];
    static int k;
    if (ls < 0x10000) return (const wchar_t*)(uintptr_t)ls;
    if (!(MEM32(ls + 4) & 0x80000000u) || !MEM32(ls + 8)) return (const wchar_t*)(uintptr_t)MEM32(ls + 8);
    wchar_t* w = buf[k ^= 1];
    int n = MultiByteToWideChar(CP_ACP, 0, (const char*)(uintptr_t)MEM32(ls + 8), (int)MEM32(ls), w, 511);
    w[n > 0 ? n : 0] = 0;
    return w;
}

/* ---- the desktop heap, CLIENTINFO and the handle table -------------------
 * user32's ValidateHwnd: index = LOWORD(h) < psi->cHandleEntries (+8);
 * aheList entry (12 bytes) { phead, pOwner, bType (+8, 1 a window), bFlags
 * (+9, bit 0 destroyed), wUniq (+0xA) = HIWORD(h) }; then phead must lie in
 * the thread's desktop (CLIENTINFO at TEB+0x6CC: +0x18 pDeskInfo -> { base,
 * limit }) and the WND user32 reads is phead - CLIENTINFO+0x1C (the client
 * delta, 0 here: the heap is ours). A host HWND's own index and uniq are
 * used as they are. WND, Windows 2000 SP4: +0x00 hwnd (THRDESKHEAD.h),
 * +0x10 pSelf, +0x16 state bits, +0x5C lpfnWndProc. */
#define DESK_SIZE (16u << 20)
static uint8_t* g_desk, *g_deskinfo;
static uint32_t g_desk_top;

static void thread_setup(void) {
    uint32_t teb = MEM32(g_fs_base + 0x18), ci = teb + 0x6CC;
    static uint8_t* threadinfo;
    /* TEB+0x40 Win32ThreadInfo: nonzero is a GUI thread (GetSystemMetrics
     * otherwise asks NtUserGetThreadState to convert it first) */
    if (!threadinfo) threadinfo = (uint8_t*)calloc(1, 0x400);
    if (!MEM32(teb + 0x40)) MEM32(teb + 0x40) = (uint32_t)(uintptr_t)threadinfo;
    if (!g_desk) {
        g_desk = (uint8_t*)VirtualAlloc(NULL, DESK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        g_deskinfo = (uint8_t*)calloc(1, 0x200);
        *(uint32_t*)(g_deskinfo + 0) = (uint32_t)(uintptr_t)g_desk;               /* pvDesktopBase */
        *(uint32_t*)(g_deskinfo + 4) = (uint32_t)(uintptr_t)g_desk + DESK_SIZE;   /* pvDesktopLimit */
        g_desk_top = 0x100;
    }
    if (MEM32(ci + 0x18) != (uint32_t)(uintptr_t)g_deskinfo) {
        MEM32(ci + 0x18) = (uint32_t)(uintptr_t)g_deskinfo;
        MEM32(ci + 0x1C) = 0;                                                   /* ulClientDelta */
        /* +0x08 dwExpWinVer (GETAPPVER): >= 4.0 gives dialogs DS_3DLOOK and
         * a normal-weight font. ponytail: 5.0 for every program, read the
         * image's subsystem version if a 3.x one ever runs */
        MEM32(ci + 0x08) = 0x500;
    }
}

static uint8_t* desk_alloc(uint32_t n) {
    uint8_t* p = g_desk + g_desk_top;
    g_desk_top += (n + 15) & ~15u;
    return g_desk_top <= DESK_SIZE ? p : NULL;
}

/* WND fields kept from the host window: +0x1C ExStyle, +0x20 style, +0x30
 * spwndParent (top-level: none), +0x38 spwndOwner, +0x3C rcWindow, +0x4C
 * rcClient, both in screen coordinates. A dialog places itself at the
 * owner's rcClient (ClientToScreen is client-side). */
#define MAX_WNDS 512
static HWND g_wnds[MAX_WNDS];
static int g_nwnds;
uint8_t* native32_user_wnd(void* hv);
static LRESULT CALLBACK wnd_thunk(HWND h, UINT m, WPARAM w, LPARAM l);
/* the guest's window procedure of each class registered (the host class has
 * wnd_thunk in its place) */
#define MAX_CLASSES 256
static struct { ATOM atom; uint32_t proc; int ansi; HINSTANCE inst; } g_cls[MAX_CLASSES];
static int g_ncls;
static int class_index(HWND h) {
    ATOM a = (ATOM)GetClassWord(h, GCW_ATOM);
    for (int i = 0; i < g_ncls; i++) if (g_cls[i].atom == a) return i;
    return -1;
}
static uint32_t class_proc(HWND h) { int i = class_index(h); return i < 0 ? 0 : g_cls[i].proc; }
/* registered by RegisterClass(Ex)A: its procedure takes ANSI text */
static int class_ansi(HWND h) { int i = class_index(h); return i >= 0 && g_cls[i].ansi; }
/* ---- the virtual screen (W2K_SCREEN=WxH) ----------------------------------
 * One host window is Windows 2000's screen and desktop window: WS_POPUP at
 * host (0,0), so its coordinates are the host's and nothing is translated.
 * Guest top-level windows are SetParent'ed into it (still popups to the
 * host: menus stay) and PrintWindow of it is the whole screen. A runner
 * started by a guest in it gets W2K_SCREEN_HWND and joins the same one. */
static COLORREF sys_color(int i);
static HWND g_screen;
static int g_scx, g_scy;
static RECT g_work;
static void screen_init(void) {
    const char* e = getenv("W2K_SCREEN_HWND"), *s = getenv("W2K_SCREEN");
    RECT r;
    if (e && IsWindow((HWND)(uintptr_t)strtoul(e, NULL, 16))) g_screen = (HWND)(uintptr_t)strtoul(e, NULL, 16);
    else if (s && sscanf(s, "%dx%d", &g_scx, &g_scy) == 2 && g_scx > 0 && g_scy > 0) {
        WNDCLASSW wc = { 0 };
        wc.lpfnWndProc = DefWindowProcW;
        wc.hInstance = GetModuleHandleW(NULL);
        wc.hbrBackground = CreateSolidBrush(sys_color(COLOR_BACKGROUND));
        wc.lpszClassName = L"pcrecomp.screen";
        RegisterClassW(&wc);
        g_screen = CreateWindowExW(0, wc.lpszClassName, L"Windows 2000", WS_POPUP | WS_CLIPCHILDREN | WS_VISIBLE,
                                   0, 0, g_scx, g_scy, NULL, NULL, wc.hInstance, NULL);
    }
    if (!g_screen) return;
    GetClientRect(g_screen, &r);
    g_scx = r.right, g_scy = r.bottom;
    SetRect(&g_work, 0, 0, g_scx, g_scy);
    {
        char v[16];
        _snprintf(v, sizeof v, "%lx", (unsigned long)(uintptr_t)g_screen);
        v[15] = 0;
        SetEnvironmentVariableA("W2K_SCREEN_HWND", v);
    }
    fprintf(stderr, "[user] virtual screen %dx%d: host window %p\n", g_scx, g_scy, (void*)g_screen);
}
HWND native32_user_screen(void) { return g_screen; }

/* A top-level window's parent is the desktop: IsWindowVisible walks
 * spwndParent up to a visible WND whose fnid (+0x2A) is 0x29D. Only those
 * two fields; the desktop's own children are not entered. */
static uint32_t desktop_wnd(void) {
    static uint8_t* d;
    if (g_screen) return (uint32_t)(uintptr_t)native32_user_wnd(g_screen);
    if (!d && (d = desk_alloc(0x100)) != NULL) {
        memset(d, 0, 0x100);
        *(uint32_t*)(d + 0x20) = WS_VISIBLE;
        *(uint16_t*)(d + 0x2A) = 0x29D;
    }
    return (uint32_t)(uintptr_t)d;
}
static void wnd_sync(HWND h, uint8_t* w) {
    RECT r;
    POINT o = { 0, 0 };
    HWND p = GetAncestor(h, GA_PARENT), own = GetWindow(h, GW_OWNER);
    *(uint32_t*)(w + 0x1C) = (uint32_t)GetWindowLongW(h, GWL_EXSTYLE);
    *(uint32_t*)(w + 0x20) = (uint32_t)GetWindowLongW(h, GWL_STYLE);
    GetWindowRect(h, &r);
    memcpy(w + 0x3C, &r, sizeof r);
    GetClientRect(h, &r);
    ClientToScreen(h, &o);
    OffsetRect(&r, o.x, o.y);
    memcpy(w + 0x4C, &r, sizeof r);
    *(uint32_t*)(w + 0x30) = p && p != GetDesktopWindow() ? (uint32_t)(uintptr_t)native32_user_wnd(p) : desktop_wnd();
    if (h == g_screen) {            /* the desktop: no parent, the desktop's fnid */
        *(uint32_t*)(w + 0x30) = 0;
        *(uint16_t*)(w + 0x2A) = 0x29D;
    }
    *(uint32_t*)(w + 0x38) = own ? (uint32_t)(uintptr_t)native32_user_wnd(own) : 0;
    /* +0x64 hrgnUpdate: user32's GetUpdateRect answers FALSE client-side
     * when it is 0 (the listview then never painted: WM_PAINT forever, no
     * icons or labels). HRGN_FULL (1) when the host window has one; the
     * rectangle itself comes from NtUserGetUpdateRect. */
    *(uint32_t*)(w + 0x64) = GetUpdateRect(h, NULL, FALSE) ? 1 : 0;
    /* +0x34 spwndChild, and for a child +0x2C spwndNext and +0x74 its ID
     * (spmenu's place): GetDlgItem walks them client-side. A top-level
     * window's spwndNext stays 0 (the next is anyone's window) and its spmenu
     * is a menu, not kept here. */
    {
        HWND c = GetWindow(h, GW_CHILD);
        *(uint32_t*)(w + 0x34) = c ? (uint32_t)(uintptr_t)native32_user_wnd(c) : 0;
        if (GetWindowLongW(h, GWL_STYLE) & WS_CHILD) {
            HWND n = GetWindow(h, GW_HWNDNEXT);
            *(uint32_t*)(w + 0x2C) = n ? (uint32_t)(uintptr_t)native32_user_wnd(n) : 0;
            *(uint32_t*)(w + 0x74) = (uint32_t)GetDlgCtrlID(h);
        }
    }
}

/* The WND for a host window, made the first time the guest meets it */
uint8_t* native32_user_wnd(void* hv) {
    HWND h = (HWND)hv;
    uint32_t i = (uint32_t)(uintptr_t)h & 0xFFFF, e;
    if (!native32_user_ahe || !h) return NULL;
    thread_setup();
    e = (uint32_t)(uintptr_t)native32_user_ahe + 12 * i;
    if (MEM32(e) && MEM16(e + 0xA) == (uint16_t)((uint32_t)(uintptr_t)h >> 16)) return (uint8_t*)(uintptr_t)MEM32(e);
    uint8_t* w = desk_alloc(0x200);
    if (!w) return NULL;
    memset(w, 0, 0x200);
    *(uint32_t*)(w + 0x00) = (uint32_t)(uintptr_t)h;
    *(uint32_t*)(w + 0x10) = (uint32_t)(uintptr_t)w;
    /* +0x5C lpfnWndProc: DispatchMessage calls it client-side (unless +0x16
     * bit 4, a server-side procedure, sends it to NtUserDispatchMessage).
     * The guest's own for its classes; a host procedure is called through the
     * bridge like any host function. */
    *(uint32_t*)(w + 0x5C) = (uint32_t)GetWindowLongPtrW(h, GWLP_WNDPROC);
    if (*(uint32_t*)(w + 0x5C) == (uint32_t)(uintptr_t)wnd_thunk) *(uint32_t*)(w + 0x5C) = class_proc(h);
    /* +0x88 cbwndExtra (a dialog's must be DLGWINDOWEXTRA); the extra bytes
     * follow the WND at +0x98 (a dialog keeps its DIALOG pointer at +0x9C) */
    *(uint32_t*)(w + 0x88) = (uint32_t)GetClassLongW(h, GCL_CBWNDEXTRA);
    /* +0x60 pcls: GetWindowLong(GWL_WNDPROC) reads the class's fnid (+6)
     * to map a server-side procedure back; a zeroed CLS has none. ponytail:
     * one shared CLS, the class's own fields when something reads them */
    {
        static uint8_t* cls;
        if (!cls && (cls = desk_alloc(0x80)) != NULL) memset(cls, 0, 0x80);
        *(uint32_t*)(w + 0x60) = (uint32_t)(uintptr_t)cls;
    }
    MEM32(e) = (uint32_t)(uintptr_t)w;
    /* +4 pOwner, the window's THREADINFO: 0 made GetWindowThreadProcessId
     * answer 0, and comctl32 sends WM_NOTIFY only to a parent of its own
     * process (no LVN_GETDISPINFO: the desktop listview's items had no text
     * or icon). Never the threads' shared one (user32 would take every
     * window for the caller's own): a stand-in, so it asks
     * NtUserQueryWindow, which answers from the host. */
    {
        static uint8_t* other;
        if (!other) other = (uint8_t*)calloc(1, 0x400);
        MEM32(e + 4) = (uint32_t)(uintptr_t)other;
    }
    MEM8(e + 8) = 1;                                                            /* TYPE_WINDOW */
    MEM8(e + 9) = 0;
    MEM16(e + 0xA) = (uint16_t)((uint32_t)(uintptr_t)h >> 16);
    if (g_nwnds < MAX_WNDS) g_wnds[g_nwnds++] = h;
    wnd_sync(h, w);
    return w;
}

/* Every WND's fields from its host window, before each win32k service and
 * callback (user32 reads them with no call between). ponytail: a linear
 * pass over every window met, an event hook if there are ever hundreds */
static void wnd_sync_all(void) {
    for (int i = 0; i < g_nwnds; i++) {
        if (!IsWindow(g_wnds[i])) { g_wnds[i--] = g_wnds[--g_nwnds]; continue; }
        uint32_t e = (uint32_t)(uintptr_t)native32_user_ahe + 12 * ((uint32_t)(uintptr_t)g_wnds[i] & 0xFFFF);
        if (MEM32(e)) wnd_sync(g_wnds[i], (uint8_t*)(uintptr_t)MEM32(e));
    }
}

/* SERVERINFO, once: +0x59C aiSysMet[0x53] (GetSystemMetrics), +0x6E8
 * argbSystem[0x1D] (GetSysColor), from the host's */
static uint8_t* g_mon;      /* the primary MONITOR, for the work area */
/* COLOR_* i: the guest's box's Control Panel\Colors (what win32k reads at
 * logon: a Windows 2000 profile's 58 110 165 desktop), else the host's */
static uint32_t g_boxcolor;  /* bit i: colour i came from the box */
static COLORREF sys_color(int i) {
    static const wchar_t* names[0x1D] = {
        L"Scrollbar", L"Background", L"ActiveTitle", L"InactiveTitle", L"Menu", L"Window", L"WindowFrame",
        L"MenuText", L"WindowText", L"TitleText", L"ActiveBorder", L"InactiveBorder", L"AppWorkspace",
        L"Hilight", L"HilightText", L"ButtonFace", L"ButtonShadow", L"GrayText", L"ButtonText",
        L"InactiveTitleText", L"ButtonHilight", L"ButtonDkShadow", L"ButtonLight", L"InfoText", L"InfoWindow",
        L"ButtonAlternateFace", L"HotTrackingColor", L"GradientActiveTitle", L"GradientInactiveTitle" };
    wchar_t v[64];
    int r, g, b;
    if (native32_registry_box_sz(L"Control Panel\\Colors", names[i], v, 64) && swscanf(v, L"%d %d %d", &r, &g, &b) == 3) {
        g_boxcolor |= 1u << i;
        return RGB(r, g, b);
    }
    return GetSysColor(i);
}
static void server_info(void) {
    static int done;
    uint8_t* psi = native32_user_psi;
    if (done || !psi) return;
    done = 1;
    for (int i = 0; i < 0x53; i++) *(int32_t*)(psi + 0x59C + 4 * i) = GetSystemMetrics(i);
    if (g_screen) {                 /* the virtual screen's size, not the host's */
        int32_t* m = (int32_t*)(psi + 0x59C);
        int dx = m[SM_CXMAXIMIZED] - m[SM_CXSCREEN], dy = m[SM_CYMAXIMIZED] - m[SM_CYSCREEN];
        m[SM_CXSCREEN] = m[SM_CXVIRTUALSCREEN] = g_scx;
        m[SM_CYSCREEN] = m[SM_CYVIRTUALSCREEN] = g_scy;
        m[SM_XVIRTUALSCREEN] = m[SM_YVIRTUALSCREEN] = 0;
        m[SM_CXFULLSCREEN] = g_scx;
        m[SM_CYFULLSCREEN] = g_scy - m[SM_CYCAPTION];
        m[SM_CXMAXIMIZED] = g_scx + (dx > 0 ? dx : 0);
        m[SM_CYMAXIMIZED] = g_scy + (dy > 0 ? dy : 0);
        m[SM_CXMAXTRACK] = m[SM_CXMAXIMIZED] + 4 * GetSystemMetrics(SM_CXFRAME);
        m[SM_CYMAXTRACK] = m[SM_CYMAXIMIZED] + 4 * GetSystemMetrics(SM_CYFRAME);
    }
    for (int i = 0; i < 0x1D; i++) *(uint32_t*)(psi + 0x6E8 + 4 * i) = sys_color(i);
    /* +0x800 / +0x804 the system font's character size (GetDialogBaseUnits) */
    *(uint16_t*)(psi + 0x800) = (uint16_t)LOWORD(GetDialogBaseUnits());
    *(uint16_t*)(psi + 0x804) = (uint16_t)HIWORD(GetDialogBaseUnits());
    /* +0xE50 the UserPreferencesMask: 0x80000000 UI effects, 0x20 keyboard
     * cues always shown. A dialog hides its underlines and focus rectangle
     * (WM_CHANGEUISTATE UIS_INITIALIZE) when effects are on and cues are
     * not. ponytail: only these two bits, the host's; the rest (menu and
     * combo animations, ...) stay off */
    {
        BOOL fx = FALSE, cues = FALSE;
        SystemParametersInfoW(SPI_GETUIEFFECTS, 0, &fx, 0);
        SystemParametersInfoW(SPI_GETKEYBOARDCUES, 0, &cues, 0);
        *(uint32_t*)(psi + 0xE50) = (fx ? 0x80000000u : 0) | (cues ? 0x20u : 0);
    }
    /* +0xE4A dmLogPixels: a dialog font's height is -MulDiv(points, it, 72).
     * +0xE48 BitCount (planes * bits), +0xE4C Planes, +0xE4D BitsPixel: the
     * display depth an icon's image is chosen by (LookupIconIdFromDirectoryEx);
     * left 0, user32 took the 16-colour image where the host takes 256 */
    {
        HDC s = GetDC(NULL);
        int pl = GetDeviceCaps(s, PLANES), bp = GetDeviceCaps(s, BITSPIXEL);
        *(uint16_t*)(psi + 0xE48) = (uint16_t)(pl * bp);
        *(uint8_t*)(psi + 0xE4C) = (uint8_t)pl;
        *(uint8_t*)(psi + 0xE4D) = (uint8_t)bp;
        *(uint16_t*)(psi + 0xE4A) = (uint16_t)GetDeviceCaps(s, LOGPIXELSY);
        ReleaseDC(NULL, s);
    }
    /* +0x1A0 the system classes' atoms, by dialog-template ordinal & 0x7F
     * (0x80 Button .. 0x85 ComboBox): the host's */
    {
        static const wchar_t* cls[] = { L"Button", L"Edit", L"Static", L"ListBox", L"ScrollBar", L"ComboBox" };
        for (int i = 0; i < 6; i++) {
            WNDCLASSEXW wc = { sizeof wc };
            *(uint16_t*)(psi + 0x1A0 + 2 * i) = (uint16_t)GetClassInfoExW(NULL, cls[i], &wc);
        }
    }
    /* DISPLAYINFO (SHAREDINFO's pDispInfo): +0x2C cMonitors, +0x30
     * pMonitorPrimary, +0x34 pMonitorFirst. MONITOR: +0x0C flags (bit 0
     * attached), +0x10 rcMonitor, +0x20 rcWork. Dialogs place themselves by it
     * (MonitorFromRect). */
    if (native32_user_disp) {
        static uint8_t mon[0x80];
        MONITORINFO mi = { sizeof mi };
        POINT o = { 0, 0 };
        GetMonitorInfoW(MonitorFromPoint(o, MONITOR_DEFAULTTOPRIMARY), &mi);
        *(uint32_t*)(mon + 0x0C) = 1;
        if (g_screen) SetRect(&mi.rcMonitor, 0, 0, g_scx, g_scy), mi.rcWork = g_work;
        g_mon = mon;
        memcpy(mon + 0x10, &mi.rcMonitor, sizeof(RECT));
        memcpy(mon + 0x20, &mi.rcWork, sizeof(RECT));
        *(uint32_t*)(native32_user_disp + 0x2C) = 1;
        *(uint32_t*)(native32_user_disp + 0x30) = (uint32_t)(uintptr_t)mon;
        *(uint32_t*)(native32_user_disp + 0x34) = (uint32_t)(uintptr_t)mon;
        /* +0 HEAD.h: MonitorFromRect answers PtoH(pMonitor) and GetMonitorInfo
         * validates it (TYPE_MONITOR 12). Handle 0 failed both: explorer's tray
         * sized itself to an empty monitor (4x0 at -2,2). ponytail: the table's
         * last slot, which a host window of index 0xFFFF would take over */
        if (native32_user_ahe) {
            uint32_t e = (uint32_t)(uintptr_t)native32_user_ahe + 12 * 0xFFFF;
            *(uint32_t*)mon = 0x1FFFF;
            MEM32(e) = (uint32_t)(uintptr_t)mon;
            MEM8(e + 8) = 12;
            MEM16(e + 0xA) = 1;
        }
    }
}

/* SERVERINFO +0x75C ahbrSystem[0x1D] (GetSysColorBrush; DrawEdge reads
 * them directly), as guest handles of the host's: once the GDI table is up */
static void sys_brushes(void) {
    uint8_t* psi = native32_user_psi;
    if (!psi || *(uint32_t*)(psi + 0x75C)) return;
    {   /* (no table yet) */
        uint32_t s = (uint32_t)(uintptr_t)GetSysColorBrush(0);
        if (native32_gdi_handle(s) == s) return;
    }
    for (int i = 0; i < 0x1D; i++) {
        /* a box colour gets its own brush (ponytail: never deleted, like the system's) */
        uint32_t h = (uint32_t)(uintptr_t)(g_boxcolor & (1u << i) ? CreateSolidBrush(*(uint32_t*)(psi + 0x6E8 + 4 * i))
                                                                   : GetSysColorBrush(i)), g = native32_gdi_handle(h);
        if (g == h) { *(uint32_t*)(psi + 0x75C) = 0; return; }       /* (no table yet) */
        *(uint32_t*)(psi + 0x75C + 4 * i) = g;
    }
}

static void (*g_prev_pre)(void);
static void user_pre(void) {        /* before every win32k service */
    server_info();
    sys_brushes();
    if (native32_user_ahe) {
        thread_setup();
        /* DESKTOPINFO +8 spwnd: user32's GetDesktopWindow reads it */
        if (g_screen && !*(uint32_t*)(g_deskinfo + 8)) *(uint32_t*)(g_deskinfo + 8) = desktop_wnd();
        wnd_sync_all();
    }
    if (g_prev_pre) g_prev_pre();
    /* win32k calls a thread back at __ClientThreadSetup (KernelCallbackTable
     * 74) when it becomes a GUI thread: user32's ClientThreadSetup makes its
     * drawing DCs there (ghdcBits2: LoadBitmap's DIB-to-DDB copy blits from
     * it, a mono bitmap came out black without). ponytail: once per process,
     * not per thread; per-thread when a guest starts a second GUI thread */
    static int setup;
    if (!setup && native32_guest_loaded && native32_user_ahe) {
        uint32_t o = 0, olen = 0;
        setup = 1;
        native32_nt_callback(74, 0, 0, &o, &olen);
    }
}

static void (*g_prev_cb_in)(uint32_t* args);
static void cb_in(uint32_t* a) {             /* a window the guest is about to hear from */
    if (IsWindow((HWND)(uintptr_t)a[0])) native32_user_wnd((HWND)(uintptr_t)a[0]);
    if (native32_user_ahe) wnd_sync_all();
    if (g_prev_cb_in) g_prev_cb_in(a);
}

/* A class the guest registered (its procedure is the thunk), found under inst */
static int guest_class(HINSTANCE inst, const wchar_t* name, WNDCLASSEXW* wc) {
    wc->cbSize = sizeof *wc;
    return GetClassInfoExW(inst, name, wc) && wc->lpfnWndProc == wnd_thunk;
}
/* A class a host DLL registered globally (not the host user32's system
 * classes, which stand in for the guest user32's own; their procedures are
 * user32's, or ntdll's stubs in a WOW64 process) */
static int host_dll_class(const wchar_t* name) {
    WNDCLASSEXW wc = { sizeof wc };
    HMODULE owner = NULL;
    return GetClassInfoExW(NULL, name, &wc) &&
           GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                              (LPCWSTR)(void*)wc.lpfnWndProc, &owner) &&
           owner != GetModuleHandleW(L"user32.dll") && owner != GetModuleHandleW(L"ntdll.dll");
}
/* NtUserRegisterClassExWOW(WNDCLASSEXW*, PUNICODE_STRING class, CLSMENUNAME*,
 * WORD fnid, DWORD flags, DWORD* wow): the host class, with the guest's
 * window procedure and the host's background brush. */
static uint32_t cur_host(uint32_t h);
static uint32_t s_register_class(uint32_t* a) {
    WNDCLASSEXW w = *(WNDCLASSEXW*)(uintptr_t)a[0];
    w.cbSize = sizeof w;
    w.lpszClassName = ustr_name(a[1]);
    if (a[2]) w.lpszMenuName = (LPCWSTR)(uintptr_t)MEM32(a[2] + 4);   /* pwszClientUnicodeMenuName */
    if ((uintptr_t)w.hbrBackground > 0x40 && native32_gdi_host((uint32_t)(uintptr_t)w.hbrBackground))
        w.hbrBackground = (HBRUSH)(uintptr_t)native32_gdi_host((uint32_t)(uintptr_t)w.hbrBackground);
    w.hIcon = (HICON)(uintptr_t)cur_host((uint32_t)(uintptr_t)w.hIcon);
    w.hIconSm = (HICON)(uintptr_t)cur_host((uint32_t)(uintptr_t)w.hIconSm);
    w.hCursor = (HCURSOR)(uintptr_t)cur_host((uint32_t)(uintptr_t)w.hCursor);
    if (getenv("NATIVE32_SYSCALLS"))
        fprintf(stderr, "[user] class background %p (guest %08X)\n", w.hbrBackground, ((WNDCLASSEXW*)(uintptr_t)a[0])->hbrBackground);
    uint32_t guest_proc = (uint32_t)(uintptr_t)w.lpfnWndProc;
    w.lpfnWndProc = wnd_thunk;
    ATOM r = RegisterClassExW(&w);
    /* a host DLL in the process (Win11's language bar loads the host comctl32)
     * holds the global name: the guest's class is then its DLL's local one */
    if (!r && GetLastError() == ERROR_CLASS_ALREADY_EXISTS && (w.style & CS_GLOBALCLASS) && host_dll_class(w.lpszClassName)) {
        w.style &= ~CS_GLOBALCLASS;
        r = RegisterClassExW(&w);
    }
    /* flags (a[4]) bit 1 is CSF_ANSIPROC: RegisterClassExA passes 2 (0x82
     * past 3.10), the W form 0 (0x80) */
    if (r && g_ncls < MAX_CLASSES)
        g_cls[g_ncls].atom = r, g_cls[g_ncls].inst = w.hInstance, g_cls[g_ncls].ansi = (a[4] & 2) != 0, g_cls[g_ncls++].proc = guest_proc;
    if (!r) fprintf(stderr, "[user] RegisterClassExW %ls failed: %lu\n",
                    (uintptr_t)w.lpszClassName < 0x10000 ? L"(atom)" : w.lpszClassName, GetLastError());
    return r;
}

/* NtUserUnregisterClass(UNICODE_STRING* name or atom, hInstance, CLSMENUNAME*):
 * the host's (ole32 unregisters OleMainThreadWndClass at CoUninitialize and
 * registers it again at the next CoInitialize) */
static uint32_t s_unregister_class(uint32_t* a) {
    const wchar_t* n = a[0] < 0x10000 ? (const wchar_t*)(uintptr_t)a[0] : ustr_name(a[0]);
    ATOM at = 0;
    WNDCLASSEXW wc = { sizeof wc };
    if (n) at = (ATOM)GetClassInfoExW((HINSTANCE)(uintptr_t)a[1], n, &wc);
    if (!n || !UnregisterClassW(n, (HINSTANCE)(uintptr_t)a[1])) return 0;
    for (int i = 0; i < g_ncls; i++)
        if (g_cls[i].atom == at) { g_cls[i] = g_cls[--g_ncls]; break; }
    return 1;
}

/* ---- messages: win32k's callback ------------------------------------------
 * A message the host sends a guest window reaches its procedure the way
 * Windows 2000's win32k delivers it: KeUserModeCallback(__fnDWORD, FNDWORDMSG
 * { pwnd, msg, wParam, lParam, xParam = the procedure, xpfnProc =
 * DispatchClientMessage }) through the guest ntdll's KiUserCallbackDispatcher
 * and user32's own __fnDWORD (KernelCallbackTable[2]), which returns the
 * result with NtCallbackReturn. DispatchClientMessage(pwnd, msg, w, l, pfn)
 * takes the HWND from CLIENTINFO's CallbackWnd (TEB+0x6F4), set first.
 * Text messages go through their own routines (msg_call, below). */
static uint32_t g_dcm;        /* user32's DispatchClientMessage */
static uint32_t find_dcm(void) {
    /* It is in no export and no code names it: only PFNCLIENT (apfnClientA /
     * apfnClientW, user32's data, handed to win32k by csrss) holds it, at
     * +0x24 from pfnDialogWndProc, the same in both. */
    uint32_t u = native32_module("user32.dll"), da, dw;
    if (!u) return 0;
    da = native32_export(u, "DefDlgProcA"), dw = native32_export(u, "DefDlgProcW");
    uint32_t size = MEM32(u + MEM32(u + 0x3C) + 0x50);
    for (uint32_t o = 0x1000; o + 0x28 < size; o += 4)
        if (MEM32(u + o) == dw)
            for (uint32_t p = 0x1000; p + 0x28 < size; p += 4)
                if (MEM32(u + p) == da && MEM32(u + p + 0x24) == MEM32(u + o + 0x24)) return MEM32(u + o + 0x24);
    return 0;
}
/* win32k's per-message callbacks (KernelCallbackTable index, read off
 * user32's routines). The copying ones start with a capture-buffer header
 * (0x18 bytes: +0 size, +8 pointers to fix up, none here, since the guest
 * shares the host's address space) and take { pwnd, msg, wParam } at +0x18:
 *   2  __fnDWORD             { pwnd, msg, w, l, xParam, xpfn }
 *   7  __fnINCNTOUTSTRING    +0x24 xParam, +0x28 xpfn, +0x2C buffer, +0x30
 *      its size in bytes; the reply is { result, size, the buffer written }
 *      (user32's own stack buffer up to 0x800 bytes), copied from by win32k
 *   9  __fnINLPCREATESTRUCT  +0x24 lParam != 0, +0x28 the CREATESTRUCT
 *      itself (0x30 bytes), +0x58 xParam, +0x5C xpfn
 *   25 __fnINSTRING          +0x24 xParam, +0x28 xpfn, +0x2C the string
 * An ANSI class (class_ansi) gets its text converted here, as win32k does.
 * ponytail: WM_CREATE/NCCREATE, WM_SETTEXT and WM_GETTEXT; every other
 * message is __fnDWORD (WM_CHAR is not converted for an ANSI class) */
static uint32_t msg_call(uint32_t api, uint32_t* msg, uint32_t len, uint32_t m, uint32_t* out) {
    uint32_t o = 0, olen = 0, st;
    msg[0] = len;
    st = native32_nt_callback(api, (uint32_t)(uintptr_t)msg, len, &o, &olen);
    if (st) { fprintf(stderr, "[user] callback for message 0x%X: status %08X\n", m, st); return 0; }
    if (o && olen >= 4) memcpy(out, (void*)(uintptr_t)o, olen < 12 ? olen : 12);
    return o && olen >= 4;
}
static LRESULT CALLBACK wnd_thunk(HWND h, UINT m, WPARAM w, LPARAM l) {
    uint8_t* pw = native32_user_wnd(h);
    uint32_t pfn = pw ? *(uint32_t*)(pw + 0x5C) : 0, args[4] = { (uint32_t)(uintptr_t)h, m, (uint32_t)w, (uint32_t)l };
    uint32_t teb, oh, op, rep[3] = { 0, 0, 0 };
    int ansi;
    if (!g_dcm && (g_dcm = find_dcm()) != 0 && getenv("NATIVE32_SYSCALLS"))
        fprintf(stderr, "[user] messages through KiUserCallbackDispatcher, DispatchClientMessage %08X\n", g_dcm);
    if (!pfn || !g_dcm) return DefWindowProcW(h, m, w, l);
    if (native32_cb_in) native32_cb_in(args);   /* (as the bridge would: the WND, GDI handles) */
    ansi = class_ansi(h);
    teb = MEM32(g_fs_base + 0x18), oh = MEM32(teb + 0x6F4), op = MEM32(teb + 0x6F8);
    MEM32(teb + 0x6F4) = args[0], MEM32(teb + 0x6F8) = (uint32_t)(uintptr_t)pw;
    if ((m == WM_CREATE || m == WM_NCCREATE) && l) {
        uint32_t msg[0x18] = { 0 };
        char an[256], ac[256];
        CREATESTRUCTW* cs = (CREATESTRUCTW*)&msg[0x0A];
        msg[6] = (uint32_t)(uintptr_t)pw, msg[7] = m, msg[8] = args[2], msg[9] = 1;
        *cs = *(CREATESTRUCTW*)l;
        if (ansi && (uintptr_t)cs->lpszName >= 0x10000) {
            WideCharToMultiByte(CP_ACP, 0, cs->lpszName, -1, an, sizeof an, NULL, NULL);
            cs->lpszName = (LPCWSTR)an;
        }
        if (ansi && (uintptr_t)cs->lpszClass >= 0x10000) {
            WideCharToMultiByte(CP_ACP, 0, cs->lpszClass, -1, ac, sizeof ac, NULL, NULL);
            cs->lpszClass = (LPCWSTR)ac;
        }
        msg[0x16] = pfn, msg[0x17] = g_dcm;
        msg_call(9, msg, sizeof msg, m, rep);
    } else if (m == WM_SETTEXT) {
        uint32_t msg[0x0C] = { 0 };
        char* a = NULL;
        msg[6] = (uint32_t)(uintptr_t)pw, msg[7] = m, msg[8] = args[2], msg[9] = pfn, msg[10] = g_dcm, msg[11] = args[3];
        if (ansi && l) {
            int n = WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)l, -1, NULL, 0, NULL, NULL);
            if ((a = (char*)malloc(n)) != NULL) WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)l, -1, a, n, NULL, NULL);
            msg[11] = (uint32_t)(uintptr_t)a;
        }
        msg_call(25, msg, sizeof msg, m, rep);
        free(a);
    } else if (m == WM_GETTEXT && l && w) {
        uint32_t msg[0x0D] = { 0 };
        char* a = ansi ? (char*)malloc(w * 2) : NULL;
        msg[6] = (uint32_t)(uintptr_t)pw, msg[7] = m, msg[8] = args[2], msg[9] = pfn, msg[10] = g_dcm;
        msg[11] = a ? (uint32_t)(uintptr_t)a : args[3], msg[12] = (uint32_t)w * 2;
        if (msg_call(7, msg, sizeof msg, m, rep) && rep[2]) {
            if (ansi) {
                int n = MultiByteToWideChar(CP_ACP, 0, (char*)(uintptr_t)rep[2], (int)rep[0], (LPWSTR)l, (int)w - 1);
                ((LPWSTR)l)[n] = 0;
                rep[0] = (uint32_t)n;
            } else if (rep[2] != args[3]) {
                uint32_t n = rep[0] < w ? rep[0] : (uint32_t)w - 1;
                memcpy((void*)l, (void*)(uintptr_t)rep[2], n * 2);
                ((LPWSTR)l)[n] = 0;
            }
        }
        free(a);
    } else {
        uint32_t msg[6] = { (uint32_t)(uintptr_t)pw, args[1], args[2], args[3], pfn, g_dcm };
        uint32_t o = 0, olen = 0, st = native32_nt_callback(2, (uint32_t)(uintptr_t)msg, sizeof msg, &o, &olen);
        if (st == 0 && o && olen >= 4) rep[0] = MEM32(o);
        else if (st) fprintf(stderr, "[user] callback for message 0x%X: status %08X\n", m, st);
    }
    MEM32(teb + 0x6F4) = oh, MEM32(teb + 0x6F8) = op;
    /* the callback's return flushes the TEB's GDI batch, as win32k's does
     * (calc's owner-drawn buttons: DrawEdge's PatBlts are batched) */
    if (native32_win32k_pre) native32_win32k_pre();
    if (native32_cb_out) native32_cb_out(args, &rep[0]);
    return (LRESULT)rep[0];
}

/* NtUserCreateWindowEx(exstyle, LARGE_STRING* class, LARGE_STRING* name, style,
 * x, y, cx, cy, parent, menu, hInstance, lpParam, flags) */
static uint32_t s_create_window(uint32_t* a) {
    /* A top-level frame: Windows 2000 sized it with its own borders (one
     * SM_CXBORDER each for WS_EX_WINDOWEDGE x2 and a caption or modal frame,
     * GetWindowBorders); the host's frame is thicker (padded borders). The
     * client area is what the guest meant, so the difference goes on. */
    int cx = (int)a[6], cy = (int)a[7];
    if (a[4] != CW_USEDEFAULT && !(a[3] & WS_CHILD) && cx > 0 && cy > 0 && cx != CW_USEDEFAULT) {
        int b = (a[0] & WS_EX_WINDOWEDGE) ? 2 : (a[0] & WS_EX_STATICEDGE) ? 1 : 0;
        RECT r = { 0, 0, 0, 0 };
        if ((a[3] & WS_CAPTION) || (a[0] & WS_EX_DLGMODALFRAME)) b++;
        if (a[3] & WS_THICKFRAME) { UINT g = 1; SystemParametersInfoW(SPI_GETBORDER, 0, &g, 0); b += g; }
        if (a[0] & WS_EX_CLIENTEDGE) b += 2;
        b *= GetSystemMetrics(SM_CXBORDER);
        AdjustWindowRectEx(&r, a[3], FALSE, a[0]);
        if (-r.left > b) { cx += 2 * (-r.left - b); cy += 2 * (-r.left - b); }
    }
    /* The guest's own class, under the instance it was registered with: win32k
     * finds a DLL's local class with no instance (ole32's OleMainThreadWndClass)
     * and a guest DLL's global class from any instance (comctl32's controls,
     * made local when a host DLL holds the global name: s_register_class); the
     * host only under that instance. Host system classes stay as they are. */
    {
        WNDCLASSEXW wc = { sizeof wc };
        int mine = a[10] && guest_class((HINSTANCE)(uintptr_t)a[10], lstr_name(a[1]), &wc);
        for (int i = 0; i < g_ncls && !mine; i++)
            if (g_cls[i].inst && guest_class(g_cls[i].inst, lstr_name(a[1]), &wc)) {
                a[10] = (uint32_t)(uintptr_t)g_cls[i].inst;
                break;
            }
    }
    /* 0x80000000 WS_EX_ANSICREATOR: CreateWindowExA's mark for win32k, not the host's */
    HWND h = CreateWindowExW(a[0] & ~0x80000000u, lstr_name(a[1]), lstr_name(a[2]), a[3], (int)a[4], (int)a[5], cx, cy,
                             (HWND)(uintptr_t)a[8], (HMENU)(uintptr_t)a[9], (HINSTANCE)(uintptr_t)a[10],
                             (void*)(uintptr_t)a[11]);
    if (!h) fprintf(stderr, "[user] CreateWindowExW %08X %ls failed: %lu (style %08X ex %08X parent %08X menu %08X inst %08X)\n", a[1], (uintptr_t)lstr_name(a[1]) < 0x10000 ? L"(atom)" : lstr_name(a[1]), GetLastError(), a[3], a[0], a[8], a[9], a[10]);
    if (h && g_screen && !(a[3] & WS_CHILD)) SetParent(h, g_screen);   /* a top-level window: on the screen */
    /* a window of a host class (a dialog's #32770) never calls the guest
     * while it is made, so its WND is entered here */
    if (h) native32_user_wnd(h);
    return (uint32_t)(uintptr_t)h;
}
/* NtUserPostMessage(hwnd, msg, wParam, lParam); NtUserValidateTimerCallback
 * (hwnd, wParam, lParam): a WM_TIMER's TIMERPROC is the guest's own, valid */
static uint32_t s_post(uint32_t* a) { return PostMessageW((HWND)(uintptr_t)a[0], a[1], a[2], a[3]); }
static uint32_t s_validate_timer(uint32_t* a) { (void)a; return 1; }
/* NtUserFindWindowEx(parent, after, UNICODE_STRING* class, UNICODE_STRING* name,
 * type): the host's (an absent class or name is a NULL pointer) */
static uint32_t s_findwindow(uint32_t* a) {
    return (uint32_t)(uintptr_t)FindWindowExW((HWND)(uintptr_t)a[0], (HWND)(uintptr_t)a[1],
                                              a[2] ? ustr_name(a[2]) : NULL, a[3] ? ustr_name(a[3]) : NULL);
}
/* NtUserModifyUserStartupInfoFlags(set, clear): STARTF_* bits win32k keeps
 * for the first window; nothing to keep here */
static uint32_t s_one_u(uint32_t* a) { (void)a; return 1; }
/* The shell's system-wide calls (RegisterHotKey, SetShellWindowEx) are
 * answered here, never the host's: a guest explorer must not take Win+E from
 * the real shell or name itself the host's shell window */
static int own_window(uint32_t h) {
    DWORD pid = 0;
    GetWindowThreadProcessId((HWND)(uintptr_t)h, &pid);
    return pid == GetCurrentProcessId();
}
/* SetShellWindowEx: win32k keeps the shell window (explorer's desktop) under
 * every other; inside the virtual screen that is its bottom child, here and
 * whenever it is shown (else it covered the taskbar) */
static HWND g_shellwnd;
static void shell_bottom(HWND h) {
    if (h && h == g_shellwnd) SetWindowPos(h, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
}
static uint32_t s_set_shell(uint32_t* a) {
    if (!own_window(a[0])) return 0;
    shell_bottom(g_shellwnd = (HWND)(uintptr_t)a[0]);
    return 1;
}
/* a broadcast stays in the guest (ponytail: dropped, not sent to the guest's
 * own top-level windows; send it to them when something waits for one) */
static uint32_t s_send_notify(uint32_t* a) {
    return own_window(a[0]) ? SendNotifyMessageW((HWND)(uintptr_t)a[0], a[1], a[2], a[3]) : 1;
}
static uint32_t s_post_thread(uint32_t* a) {
    HANDLE t = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, a[0]);
    DWORD pid = t ? GetProcessIdOfThread(t) : 0;
    if (t) CloseHandle(t);
    return pid == GetCurrentProcessId() ? PostThreadMessageW(a[0], a[1], a[2], a[3]) : 0;
}
/* SetWindowRgn: the system owns the region it is given, so the host gets a copy */
static uint32_t s_setrgn(uint32_t* a) {
    HRGN g = (HRGN)(uintptr_t)native32_gdi_rgn(a[1]), c = NULL;
    if (!own_window(a[0])) return 0;
    if (g && (c = CreateRectRgn(0, 0, 0, 0)) != NULL) CombineRgn(c, g, NULL, RGN_COPY);
    return SetWindowRgn((HWND)(uintptr_t)a[0], c, (BOOL)a[2]);
}
/* (hdc, lprcClip, proc, lParam): the one monitor, server_info's, to the
 * guest's MONITORENUMPROC. ponytail: hdc and the clip rectangle ignored */
static uint32_t s_enum_monitors(uint32_t* a) {
    static RECT rc;
    if (!g_mon || !a[2]) return 0;
    memcpy(&rc, g_mon + 0x10, sizeof rc);
    uint32_t args[4] = { MEM32((uint32_t)(uintptr_t)g_mon), a[0], (uint32_t)(uintptr_t)&rc, a[3] };
    native32_call_guest(a[2], 4, args);
    return 1;
}
/* RichEdit's (wordpad): read-only queries and its caret */
static uint32_t s_dblclick(uint32_t* a) { (void)a; return GetDoubleClickTime(); }
static uint32_t s_kblist(uint32_t* a) { return (uint32_t)GetKeyboardLayoutList((int)a[0], (HKL*)(uintptr_t)a[1]); }
static uint32_t s_showcaret(uint32_t* a) { return ShowCaret((HWND)(uintptr_t)a[0]); }
static uint32_t s_hidecaret(uint32_t* a) { return HideCaret((HWND)(uintptr_t)a[0]); }
/* NtUserGetThreadDesktop(tid, hdeskConsole): this thread's (the guest tid is not the host's) */
static uint32_t s_threaddesk(uint32_t* a) { (void)a; return (uint32_t)(uintptr_t)GetThreadDesktop(GetCurrentThreadId()); }
static uint32_t s_showsb(uint32_t* a) { return ShowScrollBar((HWND)(uintptr_t)a[0], (int)a[1], a[2]); }
static uint32_t s_keystate(uint32_t* a) { return (uint32_t)(uint16_t)GetKeyState((int)a[0]); }
static uint32_t s_nclipfmt(uint32_t* a) { (void)a; return (uint32_t)CountClipboardFormats(); }
/* NtUserCreateCaret(hwnd, hbm (0, 1 grey or a bitmap), cx, cy) */
static uint32_t s_createcaret(uint32_t* a) {
    uint32_t b = a[1] > 1 && native32_gdi_host(a[1]) ? native32_gdi_host(a[1]) : a[1];
    return CreateCaret((HWND)(uintptr_t)a[0], (HBITMAP)(uintptr_t)b, (int)a[2], (int)a[3]);
}
/* NtUserCallTwoParam(p1, p2, index): 0x5E SetCaretPos (read off the export) */
static uint32_t s_call_twoparam(uint32_t* a) {
    if (a[2] == 0x5E) return SetCaretPos((int)a[0], (int)a[1]);
    fprintf(stderr, "[user] NtUserCallTwoParam(%08X, %08X, 0x%X) not answered\n", a[0], a[1], a[2]);
    return 0;
}
/* NtUserEnableScrollBar(hwnd, wSBflags, wArrows): the host's */
static uint32_t s_enable_sb(uint32_t* a) { return EnableScrollBar((HWND)(uintptr_t)a[0], a[1], a[2]); }
/* NtUserSystemParametersInfo(action, uiParam, pvParam, fWinIni): the host's */
/* Only queries reach the host: a guest must never change the user's live
 * settings. GET actions below 0x62 by name (winuser.h); from 0x62, and in
 * the 0x1000/0x2000 ranges, GETs are even. ICON{HORIZONTAL,VERTICAL}SPACING
 * (0xD, 0x18) query when given a buffer. SETs are refused (0) and logged. */
static int spi_get(uint32_t act, uint32_t pv) {
    static const uint8_t get[] = { 1, 3, 5, 0xA, 0xE, 0x10, 0x12, 0x16, 0x19, 0x1B, 0x1F, 0x23, 0x26, 0x29, 0x2B, 0x2D,
        0x30, 0x32, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E, 0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4F, 0x50, 0x53, 0x54,
        0x59, 0x5E, 0x5F, 0x73 };
    if (act == 0xD || act == 0x18) return pv != 0;
    if (act >= 0x1000) return !(act & 1);
    if (act >= 0x62) return !(act & 1) || act == 0x73;
    for (unsigned i = 0; i < sizeof get; i++) if (get[i] == act) return 1;
    return 0;
}
static uint32_t s_spi(uint32_t* a) {
    /* the virtual screen's work area: the taskbar sets it, kept here only */
    if (g_screen && a[0] == SPI_GETWORKAREA && a[2]) { memcpy((void*)(uintptr_t)a[2], &g_work, sizeof g_work); return 1; }
    if (g_screen && a[0] == SPI_SETWORKAREA) {
        if (a[2]) memcpy(&g_work, (void*)(uintptr_t)a[2], sizeof g_work);
        else SetRect(&g_work, 0, 0, g_scx, g_scy);
        if (g_mon) memcpy(g_mon + 0x20, &g_work, sizeof g_work);
        return 1;
    }
    if (!spi_get(a[0], a[2])) {
        fprintf(stderr, "[user] SystemParametersInfo 0x%X (a SET) refused\n", a[0]);
        return 0;
    }
    return SystemParametersInfoW(a[0], a[1], (void*)(uintptr_t)a[2], 0);
}
/* NtUserGetDCEx(hwnd, hrgnClip, flags), NtUserGetWindowDC(hwnd) */
static uint32_t s_getdcex(uint32_t* a) {
    return native32_gdi_handle((uint32_t)(uintptr_t)GetDCEx((HWND)(uintptr_t)a[0], (HRGN)(uintptr_t)native32_gdi_host(a[1]), a[2]));
}
static uint32_t s_getwindowdc(uint32_t* a) { return native32_gdi_handle((uint32_t)(uintptr_t)GetWindowDC((HWND)(uintptr_t)a[0])); }
static uint32_t s_getdc(uint32_t* a) { return native32_gdi_handle((uint32_t)(uintptr_t)GetDC((HWND)(uintptr_t)a[0])); }
/* NtUserCreateAcceleratorTable(ACCEL*, count) */
/* NtUserTranslateAccelerator(hwnd, haccel, MSG*): the table is the host's (s_accel) */
static uint32_t s_translate_accel(uint32_t* a) {
    return (uint32_t)TranslateAcceleratorW((HWND)(uintptr_t)a[0], (HACCEL)(uintptr_t)a[1], (MSG*)(uintptr_t)a[2]);
}
/* NtUserScrollWindowEx(hwnd, dx, dy, prcScroll, prcClip, hrgnUpdate, prcUpdate, flags) */
static uint32_t s_scrollwindow(uint32_t* a) {
    uint32_t r = a[5] && native32_gdi_host(a[5]) ? native32_gdi_host(a[5]) : a[5];
    return (uint32_t)ScrollWindowEx((HWND)(uintptr_t)a[0], (int)a[1], (int)a[2], (RECT*)(uintptr_t)a[3], (RECT*)(uintptr_t)a[4],
                                    (HRGN)(uintptr_t)r, (RECT*)(uintptr_t)a[6], a[7]);
}
static uint32_t s_clipfmt_avail(uint32_t* a) { return IsClipboardFormatAvailable(a[0]); }
static uint32_t s_accel(uint32_t* a) { return (uint32_t)(uintptr_t)CreateAcceleratorTableW((ACCEL*)(uintptr_t)a[0], (int)a[1]); }

/* NtUserMessageCall(hwnd, msg, wParam, lParam, xParam, fnid, bAnsi): the
 * kernel half of a message function, by fnid. 0x29E (FNID_DEFWINDOWPROC) is
 * DefWindowProc's: the host's. */
static uint32_t s_message_call(uint32_t* a) {
    HWND h = (HWND)(uintptr_t)a[0];
    /* a DC the guest got in the message (WM_ERASEBKGND, WM_CTLCOLOR*, ...)
     * goes back to the host as the host's */
    if (a[2] && ((a[2] >> 16) & 0x1F) == 1 && native32_gdi_host(a[2])) a[2] = native32_gdi_host(a[2]);
    /* a GDI object in wParam (WM_SETFONT's font) goes to the host as the host's */
    if (a[2] && native32_gdi_host(a[2])) a[2] = native32_gdi_host(a[2]);
    if (a[5] == 0x2AE) {                   /* SendMessage */
        LRESULT r = a[6] ? SendMessageA(h, a[1], a[2], a[3]) : SendMessageW(h, a[1], a[2], a[3]);
        return (uint32_t)(a[1] == WM_GETFONT && r ? native32_gdi_handle((uint32_t)r) : r);
    }
    if (a[5] == 0x29E) {
        LRESULT r = a[6] ? DefWindowProcA(h, a[1], a[2], a[3]) : DefWindowProcW(h, a[1], a[2], a[3]);
        /* WM_CTLCOLOR*: the brush goes back to the guest's gdi32 as its own */
        if (a[1] >= WM_CTLCOLORMSGBOX && a[1] <= WM_CTLCOLORSTATIC && r) return native32_gdi_handle((uint32_t)r);
        return (uint32_t)r;
    }
    fprintf(stderr, "[user] NtUserMessageCall fnid 0x%X (msg 0x%X) not answered\n", a[5], a[1]);
    return 0;
}

/* Any USER object a guest handle should validate as: menus (bType 2) get an
 * entry and a zeroed object in the desktop heap, like windows (1). */
static void user_object(uint32_t h, uint8_t type, uint32_t size) {
    uint32_t e = (uint32_t)(uintptr_t)native32_user_ahe + 12 * (h & 0xFFFF);
    if (!native32_user_ahe || !h || (MEM32(e) && MEM16(e + 0xA) == (uint16_t)(h >> 16))) return;
    thread_setup();
    uint8_t* o = desk_alloc(size);
    if (!o) return;
    memset(o, 0, size);
    *(uint32_t*)o = h;
    MEM32(e) = (uint32_t)(uintptr_t)o;
    MEM8(e + 8) = type;
    MEM16(e + 0xA) = (uint16_t)(h >> 16);
}
static uint32_t menu(HMENU m) { user_object((uint32_t)(uintptr_t)m, 2, 0x100); return (uint32_t)(uintptr_t)m; }

/* The MENU's items, from the host menu, for what user32 looks up client-side
 * (CheckMenuItem calls win32k only when the state changes): MENU +0x10 pSelf,
 * +0x20 cItems, +0x34 rgItems; ITEM (0x4C bytes) +0 fType, +4 fState, +8
 * wID, +0xC spSubMenu. Kept after every call that changes a menu.
 * ponytail: up to 64 items a menu */
#define MENU_ITEMS 64
static void menu_sync(HMENU m) {
    uint32_t h = (uint32_t)(uintptr_t)m, e = (uint32_t)(uintptr_t)native32_user_ahe + 12 * (h & 0xFFFF);
    uint8_t* o;
    int n = GetMenuItemCount(m);
    if (!native32_user_ahe || n < 0 || !MEM32(e) || MEM8(e + 8) != 2) return;
    o = (uint8_t*)(uintptr_t)MEM32(e);
    if (!*(uint32_t*)(o + 0x34)) *(uint32_t*)(o + 0x34) = (uint32_t)(uintptr_t)desk_alloc(MENU_ITEMS * 0x4C);
    if (!*(uint32_t*)(o + 0x34)) return;
    if (n > MENU_ITEMS) n = MENU_ITEMS;
    *(uint32_t*)(o + 0x10) = (uint32_t)(uintptr_t)o;
    *(uint32_t*)(o + 0x20) = (uint32_t)n;
    for (int i = 0; i < n; i++) {
        uint8_t* it = (uint8_t*)(uintptr_t)*(uint32_t*)(o + 0x34) + i * 0x4C;
        MENUITEMINFOW mi = { sizeof mi, MIIM_FTYPE | MIIM_STATE | MIIM_ID | MIIM_SUBMENU };
        memset(it, 0, 0x4C);
        if (!GetMenuItemInfoW(m, i, TRUE, &mi)) continue;
        *(uint32_t*)(it + 0) = mi.fType;
        *(uint32_t*)(it + 4) = mi.fState;
        *(uint32_t*)(it + 8) = mi.wID;
        if (mi.hSubMenu) {
            uint32_t se = (uint32_t)(uintptr_t)native32_user_ahe + 12 * ((uint32_t)(uintptr_t)mi.hSubMenu & 0xFFFF);
            menu(mi.hSubMenu);
            menu_sync(mi.hSubMenu);       /* (a by-command lookup goes down into it) */
            *(uint32_t*)(it + 0xC) = MEM32(se);
        }
    }
}

/* NtUserCallNoParam(index): 0 CreateMenu, 1 CreatePopupMenu, 8 ReleaseCapture (Windows 2000's
 * order, from what user32 does with the result) */
static uint32_t s_call_noparam(uint32_t* a) {
    if (a[0] == 0) return menu(CreateMenu());
    if (a[0] == 1) return menu(CreatePopupMenu());
    if (a[0] == 8) return ReleaseCapture();
    if (a[0] == 5) return GetMessagePos();
    if (a[0] == 2) return DestroyCaret();
    /* 0x12: asked by user32's ClientThreadSetup; 1 skips its client-side
     * setup (ghdcBits2, the cursors), so 0: this thread is new */
    if (a[0] == 0x12) return 0;
    fprintf(stderr, "[user] NtUserCallNoParam %u not answered\n", a[0]);
    return 0;
}
/* Cursors built client-side: NtUserCallOneParam 0x19 (CreateIcon,
 * CreateIconIndirect, LookupIconIdFromDirectoryEx, LoadCursorFromFile) asks for
 * an empty cursor object, NtUserSetCursorIconData then fills it. The host
 * cannot fill an HICON after the fact, so the empty object is a placeholder
 * host icon (a real, unique handle) and the filled host icon is kept beside
 * it; cur_host() turns one into the other where a cursor reaches the host.
 * ponytail: 1024 built cursors (explorer makes over 100), a growing table if a program makes more */
#define MAX_CURS 1024
static uint32_t g_cur[MAX_CURS][2];
static int g_ncur;
static uint32_t cur_host(uint32_t h) {
    for (int i = 0; i < g_ncur; i++) if (g_cur[i][0] == h && g_cur[i][1]) return g_cur[i][1];
    return h;
}
static uint32_t cur_new(void) {
    static const BYTE and1[4] = { 0xFF, 0xFF, 0xFF, 0xFF }, xor1[4] = { 0 };
    HICON p = CreateIcon(NULL, 1, 1, 1, 1, and1, xor1);
    if (!p || g_ncur >= MAX_CURS) return (uint32_t)(uintptr_t)p;
    g_cur[g_ncur][0] = (uint32_t)(uintptr_t)p, g_cur[g_ncur++][1] = 0;
    user_object((uint32_t)(uintptr_t)p, 3, 0x80);
    return (uint32_t)(uintptr_t)p;
}
/* NtUserSetCursorIconData(hcur, UNICODE_STRING* module, UNICODE_STRING*
 * resource, CURSORDATA*). CURSORDATA (0x54 bytes, read off CreateIconIndirect):
 * +0 lpName, +4 lpModName, +8 rt (WORD: 3 icon, 1 cursor), +0x10/+0x12 the
 * hotspot (SHORTs), +0x14 hbmMask (the mask, cy doubled when there is no
 * colour), +0x18 hbmColor, +0x30 bpp, +0x34 cx, +0x38 cy * 2 */
static uint32_t s_set_cursor_data(uint32_t* a) {
    uint32_t cd = a[3], m = MEM32(cd + 0x14), c = MEM32(cd + 0x18);
    ICONINFO ii = { MEM16(cd + 8) != 1, (int16_t)MEM16(cd + 0x10), (int16_t)MEM16(cd + 0x12),
                    (HBITMAP)(uintptr_t)(native32_gdi_host(m) ? native32_gdi_host(m) : m),
                    (HBITMAP)(uintptr_t)(c && native32_gdi_host(c) ? native32_gdi_host(c) : c) };
    /* Windows 2000's user32 hands a double-height mask (AND mask on top) even
     * with a colour bitmap (explorer's icons); the host wants the AND mask
     * alone, the colour bitmap's height (else ERROR_INVALID_PARAMETER). Tried
     * second, when the host refuses (notepad's icon takes this path too). */
    BITMAP bm, bc;
    HBITMAP half = NULL;
    HICON h = CreateIconIndirect(&ii);
    if (!h && ii.hbmColor && GetObjectW(ii.hbmMask, sizeof bm, &bm) && GetObjectW(ii.hbmColor, sizeof bc, &bc) &&
        bm.bmHeight == 2 * bc.bmHeight) {
        HDC s = CreateCompatibleDC(NULL), d = CreateCompatibleDC(NULL);
        half = CreateBitmap(bm.bmWidth, bc.bmHeight, 1, 1, NULL);
        HGDIOBJ os = SelectObject(s, ii.hbmMask), od = SelectObject(d, half);
        BitBlt(d, 0, 0, bm.bmWidth, bc.bmHeight, s, 0, 0, SRCCOPY);
        SelectObject(s, os), SelectObject(d, od), DeleteDC(s), DeleteDC(d);
        ii.hbmMask = half;
        h = CreateIconIndirect(&ii);
    }
    if (half) DeleteObject(half);
    if (getenv("NATIVE32_SYSCALLS") && !h) {
        BITMAP bm = { 0 }, bc = { 0 };
        int gm = GetObjectW(ii.hbmMask, sizeof bm, &bm), gc = ii.hbmColor ? GetObjectW(ii.hbmColor, sizeof bc, &bc) : -1;
        fprintf(stderr, "[user]   mask %d: %dx%d %dbpp; color %d: %dx%d %dbpp\n", gm, bm.bmWidth, bm.bmHeight, bm.bmBitsPixel,
                gc, bc.bmWidth, bc.bmHeight, bc.bmBitsPixel);
    }
    if (getenv("NATIVE32_SYSCALLS"))
        fprintf(stderr, "[user] SetCursorIconData %08X rt %u mask %08X color %08X (host %08X %08X) -> %p err %lu\n", a[0], MEM16(cd + 8), m, c,
                (uint32_t)(uintptr_t)ii.hbmMask, (uint32_t)(uintptr_t)ii.hbmColor, h, h ? 0 : GetLastError());
    for (int i = 0; i < g_ncur; i++) if (g_cur[i][0] == a[0]) g_cur[i][1] = (uint32_t)(uintptr_t)h;
    return h != NULL;
}

/* NtUserCallOneParam(param, index): 0x29 ReleaseDC; the rest read off the
 * user32 exports that call them */
static uint32_t s_call_oneparam(uint32_t* a) {
    if (a[1] == 0x19) return cur_new();
    if (a[1] == 0x16) return (uint32_t)(uintptr_t)BeginDeferWindowPos((int)a[0]);
    /* 0x24 MessageBeep, 0x26 PostQuitMessage, 0x2D ShowCursor, 0x33
     * GetProcessDefaultLayout (param: the DWORD* it fills) */
    if (a[1] == 0x24) return getenv("PCRECOMP_MUTE") ? 1 : MessageBeep(a[0]);   /* (muted runs stay silent) */
    if (a[1] == 0x26) { PostQuitMessage((int)a[0]); return 1; }
    if (a[1] == 0x2D) return (uint32_t)ShowCursor(a[0]);
    if (a[1] == 0x1E) return (uint32_t)(uintptr_t)GetKeyboardLayout(0);   /* (a guest tid: this thread's) */
    if (a[1] == 0x33) { DWORD l = 0; GetProcessDefaultLayout(&l); if (a[0]) MEM32(a[0]) = l; return 1; }
    if (a[1] == 0x29) {
        uint32_t h = native32_gdi_host(a[0]);
        return ReleaseDC(NULL, (HDC)(uintptr_t)(h ? h : a[0]));
    }
    fprintf(stderr, "[user] NtUserCallOneParam(%08X, 0x%X) not answered\n", a[0], a[1]);
    return 0;
}

/* NtUserThunkedMenuItemInfo(hmenu, item, fByPosition, fInsert, MENUITEMINFOW*,
 * UNICODE_STRING* text) */
static uint32_t s_menu_item(uint32_t* a) {
    MENUITEMINFOW mi = *(MENUITEMINFOW*)(uintptr_t)a[4];
    mi.cbSize = sizeof mi;
    if (a[5] && MEM32(a[5] + 4)) mi.dwTypeData = (LPWSTR)(uintptr_t)MEM32(a[5] + 4), mi.cch = MEM16(a[5]) / 2;
    BOOL r = a[3] ? InsertMenuItemW((HMENU)(uintptr_t)a[0], a[1], a[2], &mi)
                  : SetMenuItemInfoW((HMENU)(uintptr_t)a[0], a[1], a[2], &mi);
    menu_sync((HMENU)(uintptr_t)a[0]);
    return r;
}
/* NtUserCheckMenuItem(hmenu, id, flags) / NtUserEnableMenuItem: the previous state */
static uint32_t s_check_menu(uint32_t* a) {
    DWORD r = CheckMenuItem((HMENU)(uintptr_t)a[0], a[1], a[2]);
    menu_sync((HMENU)(uintptr_t)a[0]);
    return r;
}
static uint32_t s_enable_menu(uint32_t* a) {
    BOOL r = EnableMenuItem((HMENU)(uintptr_t)a[0], a[1], a[2]);
    menu_sync((HMENU)(uintptr_t)a[0]);
    return (uint32_t)r;
}
static uint32_t s_destroy_menu(uint32_t* a) { return DestroyMenu((HMENU)(uintptr_t)a[0]); }

/* NtUserGetMenuItemRect(hwnd, hmenu, item, RECT*) */
static uint32_t s_menu_rect(uint32_t* a) {
    return GetMenuItemRect((HWND)(uintptr_t)a[0], (HMENU)(uintptr_t)a[1], a[2], (RECT*)(uintptr_t)a[3]);
}
/* NtUserFindExistingCursorIcon(UNICODE_STRING* module, UNICODE_STRING* resource,
 * ...): Windows 2000 asks win32k's cache before building an icon or cursor
 * from the resource itself. Answered with the host's own load of the same
 * resource (a guest module's resources are mapped where the host can read
 * them; user32's are the system's), entered as a cursor/icon (type 3). */
static uint32_t s_find_icon(uint32_t* a) {
    const wchar_t* mod = a[0] ? (const wchar_t*)(uintptr_t)MEM32(a[0] + 4) : NULL;
    uint32_t res = a[1] ? MEM32(a[1] + 4) : 0;
    if (getenv("NATIVE32_SYSCALLS") && a[2])
        fprintf(stderr, "[user] cursorfind %08X %08X %08X %08X %08X %08X\n", MEM32(a[2]), MEM32(a[2] + 4),
                MEM32(a[2] + 8), MEM32(a[2] + 12), MEM32(a[2] + 16), MEM32(a[2] + 20));
    HINSTANCE h = NULL;
    if (mod && !wcsstr(mod, L"USER32") && !wcsstr(mod, L"user32")) {
        char n[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, mod, -1, n, MAX_PATH, NULL, NULL);
        h = (HINSTANCE)(uintptr_t)native32_module(n);
    }
    /* the third argument: { ?, resource type (+4: 3 RT_ICON, 1 RT_CURSOR), cx,
     * cy, bpp }. Shared, as LoadIcon's are: the title bar's small icon is then
     * the resource's own 16x16 image, not the large one scaled. */
    UINT type = a[2] && MEM32(a[2] + 4) == 1 ? IMAGE_CURSOR : IMAGE_ICON;
    int cx = a[2] ? (int)MEM32(a[2] + 8) : 0, cy = a[2] ? (int)MEM32(a[2] + 12) : 0;
    HANDLE r = LoadImageW(h, (LPCWSTR)(uintptr_t)res, type, cx, cy, LR_SHARED | (cx ? 0 : LR_DEFAULTSIZE));
    if (r) user_object((uint32_t)(uintptr_t)r, 3, 0x80);
    return (uint32_t)(uintptr_t)r;
}

/* NtUserSetCursor(hcursor) */
static uint32_t s_setcursor(uint32_t* a) { return (uint32_t)(uintptr_t)SetCursor((HCURSOR)(uintptr_t)cur_host(a[0])); }

/* NtUserSetTimer(hwnd, id, elapse, TIMERPROC) / NtUserKillTimer(hwnd, id):
 * the host's (a TIMERPROC is guest code: the host calls it through the
 * trampoline) */
static uint32_t s_settimer(uint32_t* a) {
    return (uint32_t)SetTimer((HWND)(uintptr_t)a[0], a[1], a[2], (TIMERPROC)(uintptr_t)a[3]);
}
static uint32_t s_killtimer(uint32_t* a) { return KillTimer((HWND)(uintptr_t)a[0], a[1]); }
/* NtUserCallHwndParamLock(hwnd, param, index): 0x53 EnableWindow (the
 * dialog manager re-enables its owner with it) */
static uint32_t s_hwnd_param_lock(uint32_t* a) {
    if (a[2] == 0x53) return EnableWindow((HWND)(uintptr_t)a[0], a[1]);
    fprintf(stderr, "[user] NtUserCallHwndParamLock index 0x%X not answered\n", a[2]);
    return 0;
}

/* NtUserCallHwndParam(hwnd, param, index): 0x43 attaches a dialog's DIALOG
 * structure: WND+0x9C, and WND+0x16 bit 0 says it is there */
static uint32_t s_hwnd_param(uint32_t* a) {
    uint8_t* w = native32_user_wnd((void*)(uintptr_t)a[0]);
    if (a[2] == 0x43 && w) {
        /* the window procedure becomes Windows 2000's own DefDlgProcW (its
         * apfnClientW dialog procedure): it keeps the dialog in that DIALOG
         * and calls the guest's dialog procedure, which the host's
         * DefDlgProc knows nothing of */
        static uint32_t ddp;
        if (!ddp) ddp = native32_export(native32_module("user32.dll"), "DefDlgProcW");
        *(uint32_t*)(w + 0x9C) = a[1];
        w[0x16] |= 1;
        /* (a dialog of the guest's own class, calc's SciCalc, keeps its
         * procedure: that calls DefDlgProc itself) */
        if (ddp && !class_proc((HWND)(uintptr_t)a[0])) {
            SetWindowLongPtrW((HWND)(uintptr_t)a[0], GWLP_WNDPROC, (LONG_PTR)wnd_thunk);
            *(uint32_t*)(w + 0x5C) = ddp;
        }
        return 1;
    }
    /* 0x46 SetWindowState: param is a WND state bit as (byte offset from
     * +0x14) << 8 | mask (user32 tests it client-side first; a dialog sets
     * 0x502 at each WM_CTLCOLOR) */
    if (a[2] == 0x46 && w && (a[1] >> 8) < 8) {
        w[0x14 + (a[1] >> 8)] |= (uint8_t)a[1];
        return 1;
    }
    /* 0x41 ClearWindowState, its mirror (user32 calls it only when the bit is set) */
    if (a[2] == 0x41 && w && (a[1] >> 8) < 8) {
        w[0x14 + (a[1] >> 8)] &= (uint8_t)~a[1];
        return 1;
    }
    fprintf(stderr, "[user] NtUserCallHwndParam index 0x%X not answered\n", a[2]);
    return 0;
}

/* NtUserSetWindowFNID(hwnd, fnid): WND+0x2A (a dialog's 0x2A2) */
static uint32_t s_set_fnid(uint32_t* a) {
    uint8_t* w = native32_user_wnd((void*)(uintptr_t)a[0]);
    if (w) *(uint16_t*)(w + 0x2A) = (uint16_t)a[1];
    return w != NULL;
}
/* NtUserQueryWindow(hwnd, what): 0 the process, 1 the thread; for the
 * guest's own windows its TEB's ClientId (SetWindowText sends WM_SETTEXT
 * only to a window of its own process) */
static uint32_t s_query_window(uint32_t* a) {
    DWORD pid = 0, tid = GetWindowThreadProcessId((HWND)(uintptr_t)a[0], &pid);
    uint32_t teb = MEM32(g_fs_base + 0x18);
    int own = pid == GetCurrentProcessId();
    if (a[1] == 0) return own ? MEM32(teb + 0x20) : pid;
    if (a[1] == 1) return own ? MEM32(teb + 0x24) : tid;
    fprintf(stderr, "[user] NtUserQueryWindow %u not answered\n", a[1]);
    return 0;
}
/* NtUserFillWindow(hwndBrush, hwnd, hdc, hbr): a CTLCOLOR_* index in hbr
 * asks hwndBrush for the brush (WM_CTLCOLORMSGBOX + index) */
static uint32_t s_fill_window(uint32_t* a) {
    HWND hb = (HWND)(uintptr_t)a[0], h = (HWND)(uintptr_t)a[1];
    HDC dc = (HDC)(uintptr_t)native32_gdi_host(a[2]);
    uint32_t br = a[3];
    RECT r;
    if (br <= 6) br = (uint32_t)SendMessageW(hb ? hb : h, WM_CTLCOLORMSGBOX + br, (WPARAM)a[2], (LPARAM)h);
    if (native32_gdi_host(br)) br = native32_gdi_host(br);
    if (!dc || !br) return 0;
    GetClientRect(h, &r);
    return FillRect(dc, &r, (HBRUSH)(uintptr_t)br);
}
static uint32_t s_setfocus(uint32_t* a) { return (uint32_t)(uintptr_t)SetFocus((HWND)(uintptr_t)a[0]); }
static uint32_t s_destroy(uint32_t* a) { return DestroyWindow((HWND)(uintptr_t)a[0]); }
static uint32_t s_setcapture(uint32_t* a) { return (uint32_t)(uintptr_t)SetCapture((HWND)(uintptr_t)a[0]); }

/* NtUserRegisterWindowMessage(UNICODE_STRING*) */
static uint32_t s_register_msg(uint32_t* a) { return RegisterWindowMessageW(ustr_name(a[0])); }
/* NtUserSetWindowPos(hwnd, after, x, y, cx, cy, flags) */
static uint32_t s_setpos(uint32_t* a) {
    return SetWindowPos((HWND)(uintptr_t)a[0], (HWND)(uintptr_t)a[1], (int)a[2], (int)a[3], (int)a[4], (int)a[5], a[6]);
}
static uint32_t s_foreground(uint32_t* a) { (void)a; return (uint32_t)(uintptr_t)GetForegroundWindow(); }
/* NtUserGetSystemMenu(hwnd, bRevert) */
static uint32_t s_sysmenu(uint32_t* a) { return menu(GetSystemMenu((HWND)(uintptr_t)a[0], a[1])); }
/* NtUserSetWindowLong(hwnd, index, value, bAnsi). GWL_WNDPROC subclasses:
 * the guest's procedure goes in WND+0x5C (DispatchMessage calls it
 * client-side) and the host window gets wnd_thunk, so sent messages reach it
 * too; the old one comes back (a host control's own procedure, called
 * through the bridge by the guest's CallWindowProc). ponytail: the class's
 * ANSI-ness is kept for the new procedure, whatever bAnsi says */
static uint32_t s_setlong(uint32_t* a) {
    HWND h = (HWND)(uintptr_t)a[0];
    if ((int)a[1] == GWLP_WNDPROC) {
        uint8_t* w = native32_user_wnd(h);
        uint32_t old;
        if (!w) return 0;
        old = *(uint32_t*)(w + 0x5C);
        if ((LONG_PTR)GetWindowLongPtrW(h, GWLP_WNDPROC) != (LONG_PTR)wnd_thunk)
            SetWindowLongPtrW(h, GWLP_WNDPROC, (LONG_PTR)wnd_thunk);
        *(uint32_t*)(w + 0x5C) = a[2];
        return old;
    }
    /* Styles are the host window's: MFC's ModifyStyleEx drops WS_EX_CLIENTEDGE
     * from a frame and its view, and the client edge moving is what sends
     * WM_MOVE/WM_SIZE (wordpad sized its frame from them) */
    if ((int)a[1] == GWL_STYLE || (int)a[1] == GWL_EXSTYLE) {
        uint8_t* w = native32_user_wnd(h);
        uint32_t v = a[2], old;
        /* WS_VISIBLE stays the host's: the guest's value is read-modify-write
         * from the WND, which can predate ShowWindow (RichEdit's view, made
         * visible by CreateWindowEx after WM_CREATE, was hidden again). A
         * value that sets WS_VISIBLE the WND does not have is a show, and
         * passes. ponytail: a hide through the style is not answered */
        if ((int)a[1] == GWL_STYLE) {
            uint32_t show = w && (v & WS_VISIBLE) && !(*(uint32_t*)(w + 0x20) & WS_VISIBLE) ? WS_VISIBLE : 0;
            v = (v & ~WS_VISIBLE) | ((uint32_t)GetWindowLongW(h, GWL_STYLE) & WS_VISIBLE) | show;
        }
        old = (uint32_t)SetWindowLongW(h, (int)a[1], (LONG)v);
        if (w) *(uint32_t*)(w + ((int)a[1] == GWL_STYLE ? 0x20 : 0x1C)) = (uint32_t)GetWindowLongW(h, (int)a[1]);
        return old;
    }
    /* The window's extra bytes (index >= 0) are the WND's from +0x98, where
     * the guest's GetWindowLong reads them: RichEdit keeps its object at 0,
     * and without it every message it gets returns 0 (wordpad) */
    if ((int)a[1] >= 0) {
        uint8_t* w = native32_user_wnd(h);
        uint32_t old;
        if (!w || (w[0x16] & 1) || a[1] + 4 > *(uint32_t*)(w + 0x88) || a[1] + 4 > 0x200 - 0x98) return 0;
        old = *(uint32_t*)(w + 0x98 + a[1]);
        *(uint32_t*)(w + 0x98 + a[1]) = a[2];
        return old;
    }
    /* ponytail: other indexes unanswered (0), as before: forwarded to the
     * host they broke winmine's Custom dialog (a guest dialog's DWL_* live in
     * its own DIALOG, not the host window) */
    return 0;
}
/* NtUserCallHwndLock(hwnd, index): 0x48 DrawMenuBar, 0x50 UpdateWindow */
static uint32_t s_hwnd_lock(uint32_t* a) {
    if (a[1] == 0x48) return DrawMenuBar((HWND)(uintptr_t)a[0]);
    if (a[1] == 0x50) return UpdateWindow((HWND)(uintptr_t)a[0]);
    fprintf(stderr, "[user] NtUserCallHwndLock index 0x%X not answered\n", a[1]);
    return 0;
}
/* NtUserSetWindowsHookEx(hmod, UNICODE_STRING* dll, tid, idHook, proc, bAnsi):
 * a host hook on the guest's procedure (MFC's WH_CBT, which subclasses each
 * window as it is made, and WH_MSGFILTER). The host calls it like any other
 * guest callback. ponytail: thread hooks only; a global one (tid 0, a dll)
 * would need the dll in every process */
/* WH_CBT goes through cbt_thunk: HCBT_CREATEWND (3) comes before any message,
 * so the window has no WND yet and MFC's hook, which subclasses it there
 * (SetWindowLong GWL_WNDPROC), would fail ValidateHwnd. ponytail: one CBT
 * hook procedure per process (MFC's) */
static uint32_t g_cbt;
static LRESULT CALLBACK cbt_thunk(int c, WPARAM w, LPARAM l) {
    if (c == HCBT_CREATEWND) native32_user_wnd((void*)w);
    return ((HOOKPROC)(uintptr_t)g_cbt)(c, w, l);
}
static uint32_t s_sethook(uint32_t* a) {
    (void)a[2];   /* the guest TEB's thread id, not the host's: this thread */
    if ((int)a[3] == WH_CBT) g_cbt = a[4];
    return (uint32_t)(uintptr_t)SetWindowsHookExW((int)a[3], (int)a[3] == WH_CBT ? cbt_thunk : (HOOKPROC)(uintptr_t)a[4],
                                                  NULL, GetCurrentThreadId());
}
/* NtUserCallNextHookEx(nCode, wParam, lParam, bAnsi) */
static uint32_t s_nexthook(uint32_t* a) { return (uint32_t)CallNextHookEx(NULL, (int)a[0], a[1], a[2]); }
static uint32_t s_unhook(uint32_t* a) { return UnhookWindowsHookEx((HHOOK)(uintptr_t)a[0]); }
/* NtUserDestroyCursor(hcur, force) */
static uint32_t s_destroy_cursor(uint32_t* a) { (void)a; return 1; }   /* ponytail: shared host icons are never freed */
/* NtUserGetIconSize(hicon, step, LONG* cx, LONG* cy): cy is the doubled
 * height, as win32k keeps it (CURSORDATA +0x38); user32 halves it. shell32's
 * icon extraction got 0 here. */
static uint32_t s_get_icon_size(uint32_t* a) {
    ICONINFO ii;
    BITMAP bm;
    if (!GetIconInfo((HICON)(uintptr_t)cur_host(a[0]), &ii)) return 0;
    int ok = GetObjectW(ii.hbmColor ? ii.hbmColor : ii.hbmMask, sizeof bm, &bm) != 0;
    if (ok) {
        MEM32(a[2]) = (uint32_t)bm.bmWidth;
        MEM32(a[3]) = (uint32_t)(ii.hbmColor ? 2 * bm.bmHeight : bm.bmHeight);   /* a mono mask is already doubled */
    }
    if (ii.hbmColor) DeleteObject(ii.hbmColor);
    DeleteObject(ii.hbmMask);
    return ok;
}
/* NtUserGetIconInfo(hicon, ICONINFO*, UNICODE_STRING* module, UNICODE_STRING*
 * resource, DWORD* bpp, BOOL internal): the host's copies of the bitmaps, as
 * guest handles. ImageList_ReplaceIcon reads them; unanswered, shell32's icon
 * cache never filled and its lookup recursed until the stack ran out
 * (sub_20A13F31). ponytail: no module/resource names (only CopyImage's
 * LR_COPYFROMRESOURCE wants them) */
static uint32_t s_get_icon_info(uint32_t* a) {
    ICONINFO ii;
    if (!a[1] || !GetIconInfo((HICON)(uintptr_t)cur_host(a[0]), &ii)) return 0;
    MEM32(a[1]) = (uint32_t)ii.fIcon;
    MEM32(a[1] + 4) = ii.xHotspot;
    MEM32(a[1] + 8) = ii.yHotspot;
    MEM32(a[1] + 12) = native32_gdi_handle((uint32_t)(uintptr_t)ii.hbmMask);
    MEM32(a[1] + 16) = ii.hbmColor ? native32_gdi_handle((uint32_t)(uintptr_t)ii.hbmColor) : 0;
    if (a[4]) {
        BITMAP bm = { 0 };
        GetObjectW(ii.hbmColor ? ii.hbmColor : ii.hbmMask, sizeof bm, &bm);
        MEM32(a[4]) = bm.bmBitsPixel;
    }
    return 1;
}
/* NtUserDrawIconEx(hdc, x, y, hicon, cx, cy, step, hbrFlicker, flags, fMeta,
 * DRAWICONEXDATA*): the host draws its icon into the host DC. Unanswered,
 * ImageList_ReplaceIcon left the image list empty (no desktop icons).
 * ponytail: fMeta (a metafile DC) ignored */
static uint32_t s_drawiconex(uint32_t* a) {
    uint32_t dc = native32_gdi_host(a[0]) ? native32_gdi_host(a[0]) : a[0];
    uint32_t br = a[7] && native32_gdi_host(a[7]) ? native32_gdi_host(a[7]) : a[7];
    return DrawIconEx((HDC)(uintptr_t)dc, (int)a[1], (int)a[2], (HICON)(uintptr_t)cur_host(a[3]), (int)a[4], (int)a[5],
                      a[6], (HBRUSH)(uintptr_t)br, a[8]);
}
/* NtUserGetClassInfo(hInstance, UNICODE_STRING* class, WNDCLASSEXW*, LPWSTR* menu, bAnsi):
 * the atom, as GetClassInfoEx's result */
static uint32_t s_classinfo(uint32_t* a) {
    WNDCLASSEXW* w = (WNDCLASSEXW*)(uintptr_t)a[2];
    w->cbSize = sizeof *w;
    ATOM r = (ATOM)GetClassInfoExW((HINSTANCE)(uintptr_t)a[0], ustr_name(a[1]), w);
    if (!r) r = (ATOM)GetClassInfoExW(NULL, ustr_name(a[1]), w);
    if (r) {
        /* a host DLL's global class (the host comctl32's SysListView32) is
         * not the guest's: its comctl32 would skip registering its own and
         * get the host's controls, which take none of its handles (the
         * desktop listview's image lists). Only the host user32's system
         * classes stand in for the guest's. */
        int mine = w->lpfnWndProc == wnd_thunk;
        for (int i = 0; i < g_ncls && !mine; i++)       /* a guest DLL's class made local */
            if (g_cls[i].inst && guest_class(g_cls[i].inst, ustr_name(a[1]), w)) mine = 1;
        if (!mine && host_dll_class(ustr_name(a[1]))) return 0;
        for (int i = 0; i < g_ncls && mine; i++) if (g_cls[i].atom == r) w->lpfnWndProc = (WNDPROC)(uintptr_t)g_cls[i].proc;
        if (a[3]) MEM32(a[3]) = (uint32_t)(uintptr_t)w->lpszMenuName;
    }
    return r;
}
static uint32_t s_setplacement(uint32_t* a) {
    WINDOWPLACEMENT* p = (WINDOWPLACEMENT*)(uintptr_t)a[1];
    if (getenv("NATIVE32_SYSCALLS"))
        fprintf(stderr, "[user] SetWindowPlacement len %u flags %u show %u normal %ld,%ld,%ld,%ld\n", p->length, p->flags, p->showCmd,
                p->rcNormalPosition.left, p->rcNormalPosition.top, p->rcNormalPosition.right, p->rcNormalPosition.bottom);
    return SetWindowPlacement((HWND)(uintptr_t)a[0], p);
}
static uint32_t s_getplacement(uint32_t* a) {
    WINDOWPLACEMENT* p = (WINDOWPLACEMENT*)(uintptr_t)a[1];
    BOOL r = GetWindowPlacement((HWND)(uintptr_t)a[0], p);
    if (getenv("NATIVE32_SYSCALLS"))
        fprintf(stderr, "[user] GetWindowPlacement -> %d show %u normal %ld,%ld,%ld,%ld\n", r, p->showCmd,
                p->rcNormalPosition.left, p->rcNormalPosition.top, p->rcNormalPosition.right, p->rcNormalPosition.bottom);
    return r;
}
/* NtUserDeferWindowPos(hdwp, hwnd, after, x, y, cx, cy, flags) /
 * NtUserEndDeferWindowPosEx(hdwp, async) */
static uint32_t s_deferpos(uint32_t* a) {
    return (uint32_t)(uintptr_t)DeferWindowPos((HDWP)(uintptr_t)a[0], (HWND)(uintptr_t)a[1], (HWND)(uintptr_t)a[2],
                                               (int)a[3], (int)a[4], (int)a[5], (int)a[6], a[7]);
}
static uint32_t s_enddeferpos(uint32_t* a) { return EndDeferWindowPos((HDWP)(uintptr_t)a[0]); }
/* NtUserSetProp(hwnd, atom, data) / NtUserRemoveProp(hwnd, atom): the host's
 * (the guest's GetProp, which reads the WND's list, is answered by the host's
 * GetProp in the program's host) */
static uint32_t s_setprop(uint32_t* a) { return SetPropW((HWND)(uintptr_t)a[0], MAKEINTATOM(a[1]), (HANDLE)(uintptr_t)a[2]); }
static uint32_t s_removeprop(uint32_t* a) { return (uint32_t)(uintptr_t)RemovePropW((HWND)(uintptr_t)a[0], MAKEINTATOM(a[1])); }
/* NtUserSelectPalette(hdc, hpal, bForceBackground) */
static uint32_t s_selectpal(uint32_t* a) {
    uint32_t d = native32_gdi_host(a[0]), p = native32_gdi_host(a[1]);
    return native32_gdi_handle((uint32_t)(uintptr_t)SelectPalette((HDC)(uintptr_t)(d ? d : a[0]), (HPALETTE)(uintptr_t)(p ? p : a[1]), a[2]));
}
static uint32_t s_setparent(uint32_t* a) { return (uint32_t)(uintptr_t)SetParent((HWND)(uintptr_t)a[0], (HWND)(uintptr_t)a[1]); }
/* NtUserSetScrollInfo(hwnd, bar, SCROLLINFO*, redraw); the guest's
 * GetScrollInfo and friends read the WND's SBINFO, answered by the host's */
static uint32_t s_setscroll(uint32_t* a) { return (uint32_t)SetScrollInfo((HWND)(uintptr_t)a[0], (int)a[1], (SCROLLINFO*)(uintptr_t)a[2], a[3]); }
/* NtUserWindowFromPoint(POINT by value) / NtUserSetActiveWindow(hwnd) */
static uint32_t s_frompoint(uint32_t* a) { POINT p = { (LONG)a[0], (LONG)a[1] }; return (uint32_t)(uintptr_t)WindowFromPoint(p); }
static uint32_t s_setactive(uint32_t* a) { return (uint32_t)(uintptr_t)SetActiveWindow((HWND)(uintptr_t)a[0]); }
static uint32_t s_waitmessage(uint32_t* a) { (void)a; return WaitMessage(); }

#define HW(x) ((HWND)(uintptr_t)(x))
static uint32_t s_thread_state(uint32_t* a) { return a[0] == 0x11 ? 1 : 0; }
static uint32_t s_move(uint32_t* a) { return MoveWindow(HW(a[0]), (int)a[1], (int)a[2], (int)a[3], (int)a[4], a[5]); }
static uint32_t s_setmenu(uint32_t* a) { return SetMenu(HW(a[0]), (HMENU)(uintptr_t)a[1]); }
static uint32_t s_invalidate(uint32_t* a) { return InvalidateRect(HW(a[0]), (RECT*)(uintptr_t)a[1], a[2]); }
/* NtUserRedrawWindow(hwnd, rect*, hrgn, flags): explorer's desktop asks
 * for its first paint this way. No window is the guest's desktop: the
 * virtual screen, never the host's desktop. */
static uint32_t s_redraw(uint32_t* a) {
    HWND h = a[0] ? HW(a[0]) : g_screen;
    if (!h) return 0;
    return RedrawWindow(h, (RECT*)(uintptr_t)a[1], (HRGN)(uintptr_t)(a[2] ? native32_gdi_host(a[2]) : 0), a[3]);
}
static uint32_t s_show(uint32_t* a) {
    uint32_t r = ShowWindow(HW(a[0]), (int)a[1]);
    RECT rc;
    shell_bottom(HW(a[0]));
    if (getenv("NATIVE32_SYSCALLS") && GetWindowRect(HW(a[0]), &rc))
        fprintf(stderr, "[user] ShowWindow %08X %u: %ld,%ld %ldx%ld visible %d\n", a[0], a[1], rc.left, rc.top,
                rc.right - rc.left, rc.bottom - rc.top, IsWindowVisible(HW(a[0])));
    return r;
}
static uint32_t s_update(uint32_t* a) { return UpdateWindow(HW(a[0])); }
/* NtUserGetMessage(MSG*, hwnd, min, max) / NtUserPeekMessage(MSG*, hwnd, min, max, remove) */
static uint32_t s_getmessage(uint32_t* a) { return GetMessageW((MSG*)(uintptr_t)a[0], HW(a[1]), a[2], a[3]); }
static uint32_t s_peekmessage(uint32_t* a) { return PeekMessageW((MSG*)(uintptr_t)a[0], HW(a[1]), a[2], a[3], a[4]); }
static uint32_t s_translate(uint32_t* a) { return TranslateMessage((MSG*)(uintptr_t)a[0]); }
static uint32_t s_dispatch(uint32_t* a) { return (uint32_t)DispatchMessageW((MSG*)(uintptr_t)a[0]); }
/* NtUserBeginPaint(hwnd, PAINTSTRUCT*) / NtUserEndPaint: the DC as the guest's */
static uint32_t s_beginpaint(uint32_t* a) {
    PAINTSTRUCT* ps = (PAINTSTRUCT*)(uintptr_t)a[1];
    HDC h = BeginPaint(HW(a[0]), ps);
    ps->hdc = (HDC)(uintptr_t)native32_gdi_handle((uint32_t)(uintptr_t)ps->hdc);
    return native32_gdi_handle((uint32_t)(uintptr_t)h);
}
/* NtUserGetUpdateRect(hwnd, RECT*, bErase) */
static uint32_t s_getupdaterect(uint32_t* a) { return GetUpdateRect(HW(a[0]), (RECT*)(uintptr_t)a[1], (BOOL)a[2]); }
static uint32_t s_endpaint(uint32_t* a) {
    PAINTSTRUCT* ps = (PAINTSTRUCT*)(uintptr_t)a[1];
    HDC g = ps->hdc;
    if (native32_gdi_host((uint32_t)(uintptr_t)g)) ps->hdc = (HDC)(uintptr_t)native32_gdi_host((uint32_t)(uintptr_t)g);
    BOOL r = EndPaint(HW(a[0]), ps);
    ps->hdc = g;
    return r;
}

void native32_user_install(void) {
    static const struct { const char* name; native32_syscall_fn fn; } svc[] = {
        { "NtUserGetThreadState", s_thread_state }, { "NtUserMoveWindow", s_move }, { "NtUserSetMenu", s_setmenu },
        { "NtUserInvalidateRect", s_invalidate }, { "NtUserShowWindow", s_show }, { "NtUserRedrawWindow", s_redraw },
        { "NtUserGetMessage", s_getmessage }, { "NtUserPeekMessage", s_peekmessage },
        { "NtUserTranslateMessage", s_translate }, { "NtUserDispatchMessage", s_dispatch },
        { "NtUserBeginPaint", s_beginpaint }, { "NtUserGetUpdateRect", s_getupdaterect }, { "NtUserEndPaint", s_endpaint },
        { "NtUserThunkedMenuItemInfo", s_menu_item }, { "NtUserDestroyMenu", s_destroy_menu },
        { "NtUserCheckMenuItem", s_check_menu }, { "NtUserEnableMenuItem", s_enable_menu },
        { "NtUserGetMenuItemRect", s_menu_rect }, { "NtUserFindExistingCursorIcon", s_find_icon }, { "NtUserSetCursorIconData", s_set_cursor_data },
        { "NtUserSetWindowsHookEx", s_sethook }, { "NtUserCallNextHookEx", s_nexthook }, { "NtUserUnhookWindowsHookEx", s_unhook },
        { "NtUserDestroyCursor", s_destroy_cursor }, { "NtUserGetIconSize", s_get_icon_size }, { "NtUserGetIconInfo", s_get_icon_info }, { "NtUserDrawIconEx", s_drawiconex }, { "NtUserDeferWindowPos", s_deferpos }, { "NtUserEndDeferWindowPosEx", s_enddeferpos },
        { "NtUserSetProp", s_setprop }, { "NtUserSelectPalette", s_selectpal }, { "NtUserSetParent", s_setparent }, { "NtUserSetScrollInfo", s_setscroll },
        { "NtUserWindowFromPoint", s_frompoint }, { "NtUserSetActiveWindow", s_setactive }, { "NtUserRemoveProp", s_removeprop }, { "NtUserSetWindowPlacement", s_setplacement }, { "NtUserGetWindowPlacement", s_getplacement }, { "NtUserGetClassInfo", s_classinfo },
        { "NtUserSetCursor", s_setcursor }, { "NtUserSetTimer", s_settimer }, { "NtUserKillTimer", s_killtimer },
        { "NtUserCallHwndParamLock", s_hwnd_param_lock }, { "NtUserCallHwndParam", s_hwnd_param },
        { "NtUserDestroyWindow", s_destroy }, { "NtUserSetWindowFNID", s_set_fnid }, { "NtUserSetFocus", s_setfocus },
        { "NtUserQueryWindow", s_query_window }, { "NtUserFillWindow", s_fill_window }, { "NtUserSetCapture", s_setcapture },
        { "NtUserWaitMessage", s_waitmessage }, { "NtUserRegisterWindowMessage", s_register_msg }, { "NtUserCallHwndLock", s_hwnd_lock }, { "NtUserSetWindowLong", s_setlong },
        { "NtUserSetWindowPos", s_setpos }, { "NtUserGetForegroundWindow", s_foreground }, { "NtUserGetSystemMenu", s_sysmenu }, { "NtUserCallNoParam", s_call_noparam }, { "NtUserCallOneParam", s_call_oneparam },
    };
    for (int i = 0; i < (int)(sizeof svc / sizeof svc[0]); i++) native32_nt_win32k_override(svc[i].name, svc[i].fn);
    (void)s_update;
    screen_init();
    g_prev_pre = native32_win32k_pre;
    native32_win32k_pre = user_pre;
    native32_nt_win32k_override("NtUserMessageCall", s_message_call);
    g_prev_cb_in = native32_cb_in;
    native32_cb_in = cb_in;
    native32_nt_win32k_override("NtUserCreateWindowEx", s_create_window);
    native32_nt_win32k_override("NtUserGetDC", s_getdc);
    native32_nt_win32k_override("NtUserGetDCEx", s_getdcex);
    native32_nt_win32k_override("NtUserGetWindowDC", s_getwindowdc);
    native32_nt_win32k_override("NtUserSystemParametersInfo", s_spi);
    native32_nt_win32k_override("NtUserPostMessage", s_post);
    native32_nt_win32k_override("NtUserValidateTimerCallback", s_validate_timer);
    native32_nt_win32k_override("NtUserEnableScrollBar", s_enable_sb);
    native32_nt_win32k_override("NtUserFindWindowEx", s_findwindow);
    native32_nt_win32k_override("NtUserModifyUserStartupInfoFlags", s_one_u);
    native32_nt_win32k_override("NtUserRegisterHotKey", s_one_u);
    native32_nt_win32k_override("NtUserUnregisterHotKey", s_one_u);
    native32_nt_win32k_override("NtUserSetShellWindowEx", s_set_shell);
    native32_nt_win32k_override("NtUserSendNotifyMessage", s_send_notify);
    native32_nt_win32k_override("NtUserPostThreadMessage", s_post_thread);
    native32_nt_win32k_override("NtUserSetWindowRgn", s_setrgn);
    native32_nt_win32k_override("NtUserEnumDisplayMonitors", s_enum_monitors);
    native32_nt_win32k_override("NtUserGetDoubleClickTime", s_dblclick);
    native32_nt_win32k_override("NtUserGetKeyboardLayoutList", s_kblist);
    native32_nt_win32k_override("NtUserShowCaret", s_showcaret);
    native32_nt_win32k_override("NtUserHideCaret", s_hidecaret);
    native32_nt_win32k_override("NtUserGetThreadDesktop", s_threaddesk);
    native32_nt_win32k_override("NtUserShowScrollBar", s_showsb);
    native32_nt_win32k_override("NtUserGetKeyState", s_keystate);
    native32_nt_win32k_override("NtUserCountClipboardFormats", s_nclipfmt);
    native32_nt_win32k_override("NtUserCreateCaret", s_createcaret);
    native32_nt_win32k_override("NtUserCallTwoParam", s_call_twoparam);
    native32_nt_win32k_override("NtUserCreateAcceleratorTable", s_accel);
    native32_nt_win32k_override("NtUserTranslateAccelerator", s_translate_accel);
    native32_nt_win32k_override("NtUserScrollWindowEx", s_scrollwindow);
    native32_nt_win32k_override("NtUserIsClipboardFormatAvailable", s_clipfmt_avail);
    native32_nt_win32k_override("NtUserRegisterClassExWOW", s_register_class);
    native32_nt_win32k_override("NtUserUnregisterClass", s_unregister_class);
}

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
#include "ntguest.h"

/* Windows 2000's offsets below, the guest's through these (ntguest.h: XP's
 * WND, SERVERINFO, callback and routine numbers are shifts of 2000's) */
#define WO(o) nt_wnd(native32_guest_peb, (o))
#define SO(o) nt_si(native32_guest_peb, (o))
#define CB(i) nt_cb(native32_guest_peb, (i))

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
    /* atomic: explorer's threads make windows at once, and two WNDs at one address
     * (one's handle over the other's) gave GetWindowLong(hwnd, 0) another window's data */
    uint32_t k = (n + 15) & ~15u, o = (uint32_t)InterlockedExchangeAdd((volatile LONG*)&g_desk_top, (LONG)k);
    return o + k <= DESK_SIZE ? g_desk + o : NULL;
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
static LRESULT CALLBACK screen_proc(HWND h, UINT m, WPARAM w, LPARAM l);
static HWND g_screen;
static int g_scx, g_scy;
static RECT g_work;
static void screen_init(void) {
    const char* e = getenv("W2K_SCREEN_HWND"), *s = getenv("W2K_SCREEN");
    RECT r;
    if (e && IsWindow((HWND)(uintptr_t)strtoul(e, NULL, 16))) g_screen = (HWND)(uintptr_t)strtoul(e, NULL, 16);
    else if (s && sscanf(s, "%dx%d", &g_scx, &g_scy) == 2 && g_scx > 0 && g_scy > 0) {
        WNDCLASSW wc = { 0 };
        wc.lpfnWndProc = screen_proc;
        wc.hInstance = GetModuleHandleW(NULL);
        wc.hbrBackground = CreateSolidBrush(sys_color(COLOR_BACKGROUND));
        wc.lpszClassName = L"pcrecomp.screen";
        RegisterClassW(&wc);
        g_screen = CreateWindowExW(0, wc.lpszClassName, L"Windows 2000", WS_POPUP | WS_CLIPCHILDREN | WS_VISIBLE,
                                   0, 0, g_scx, g_scy, NULL, NULL, wc.hInstance, NULL);
    }
    if (!g_screen) return;
    if (!e) SetTimer(g_screen, 1, 250, NULL);   /* the screen's owner: shell_poll */
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
    *(uint32_t*)(w + WO(0x1C)) = (uint32_t)GetWindowLongW(h, GWL_EXSTYLE);
    *(uint32_t*)(w + WO(0x20)) = (uint32_t)GetWindowLongW(h, GWL_STYLE);
    GetWindowRect(h, &r);
    memcpy(w + WO(0x3C), &r, sizeof r);
    GetClientRect(h, &r);
    ClientToScreen(h, &o);
    OffsetRect(&r, o.x, o.y);
    memcpy(w + WO(0x4C), &r, sizeof r);
    *(uint32_t*)(w + WO(0x30)) = p && p != GetDesktopWindow() ? (uint32_t)(uintptr_t)native32_user_wnd(p) : desktop_wnd();
    if (h == g_screen) {            /* the desktop: no parent, the desktop's fnid */
        *(uint32_t*)(w + WO(0x30)) = 0;
        *(uint16_t*)(w + WO(0x2A)) = 0x29D;
    }
    *(uint32_t*)(w + WO(0x38)) = own ? (uint32_t)(uintptr_t)native32_user_wnd(own) : 0;
    /* +0x14 state bit 0x40 WFFRAMEON (an active frame): XP's uxtheme paints the
     * caption by it. The screen's topmost captioned window, as screen_caption */
    if (native32_themed && g_screen && p == g_screen) {
        HWND top = GetWindow(g_screen, GW_CHILD);
        while (top && (!IsWindowVisible(top) || (GetWindowLongW(top, GWL_STYLE) & WS_CAPTION) != WS_CAPTION)) top = GetWindow(top, GW_HWNDNEXT);
        if (top == h) *(uint32_t*)(w + WO(0x14)) |= 0x40;
        else *(uint32_t*)(w + WO(0x14)) &= ~0x40u;
    }
    /* +0x64 hrgnUpdate: user32's GetUpdateRect answers FALSE client-side
     * when it is 0 (the listview then never painted: WM_PAINT forever, no
     * icons or labels). HRGN_FULL (1) when the host window has one; the
     * rectangle itself comes from NtUserGetUpdateRect. */
    *(uint32_t*)(w + WO(0x64)) = GetUpdateRect(h, NULL, FALSE) ? 1 : 0;
    /* +0x34 spwndChild, and for a child +0x2C spwndNext and +0x74 its ID
     * (spmenu's place): GetDlgItem walks them client-side. A top-level
     * window's spwndNext stays 0 (the next is anyone's window) and its spmenu
     * is a menu, not kept here. */
    {
        HWND c = GetWindow(h, GW_CHILD);
        *(uint32_t*)(w + WO(0x34)) = c ? (uint32_t)(uintptr_t)native32_user_wnd(c) : 0;
        if (GetWindowLongW(h, GWL_STYLE) & WS_CHILD) {
            HWND n = GetWindow(h, GW_HWNDNEXT);
            *(uint32_t*)(w + WO(0x2C)) = n ? (uint32_t)(uintptr_t)native32_user_wnd(n) : 0;
            *(uint32_t*)(w + WO(0x74)) = (uint32_t)GetDlgCtrlID(h);
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
    *(uint32_t*)(w + WO(0x00)) = (uint32_t)(uintptr_t)h;
    *(uint32_t*)(w + WO(0x10)) = (uint32_t)(uintptr_t)w;
    /* +0x5C lpfnWndProc: DispatchMessage calls it client-side (unless +0x16
     * bit 4, a server-side procedure, sends it to NtUserDispatchMessage).
     * The guest's own for its classes; a host procedure is called through the
     * bridge like any host function. */
    *(uint32_t*)(w + WO(0x5C)) = (uint32_t)GetWindowLongPtrW(h, GWLP_WNDPROC);
    if (*(uint32_t*)(w + WO(0x5C)) == (uint32_t)(uintptr_t)wnd_thunk) *(uint32_t*)(w + WO(0x5C)) = class_proc(h);
    /* +0x88 cbwndExtra (a dialog's must be DLGWINDOWEXTRA); the extra bytes
     * follow the WND at +0x98 (a dialog keeps its DIALOG pointer at +0x9C) */
    *(uint32_t*)(w + WO(0x88)) = (uint32_t)GetClassLongW(h, GCL_CBWNDEXTRA);
    /* +0x60 pcls: GetWindowLong(GWL_WNDPROC) reads the class's fnid (+6)
     * to map a server-side procedure back; a zeroed CLS has none. ponytail:
     * one shared CLS, the class's own fields when something reads them */
    {
        static uint8_t* cls;
        if (!cls && (cls = desk_alloc(0x80)) != NULL) memset(cls, 0, 0x80);
        *(uint32_t*)(w + WO(0x60)) = (uint32_t)(uintptr_t)cls;
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
    static const wchar_t* names[0x1F] = {
        L"Scrollbar", L"Background", L"ActiveTitle", L"InactiveTitle", L"Menu", L"Window", L"WindowFrame",
        L"MenuText", L"WindowText", L"TitleText", L"ActiveBorder", L"InactiveBorder", L"AppWorkspace",
        L"Hilight", L"HilightText", L"ButtonFace", L"ButtonShadow", L"GrayText", L"ButtonText",
        L"InactiveTitleText", L"ButtonHilight", L"ButtonDkShadow", L"ButtonLight", L"InfoText", L"InfoWindow",
        L"ButtonAlternateFace", L"HotTrackingColor", L"GradientActiveTitle", L"GradientInactiveTitle",
        L"MenuHilight", L"MenuBar" };   /* (the last two: XP's) */
    wchar_t v[64];
    int r, g, b;
    if (native32_registry_box_sz(L"Control Panel\\Colors", names[i], v, 64) && swscanf(v, L"%d %d %d", &r, &g, &b) == 3) {
        g_boxcolor |= 1u << i;
        return RGB(r, g, b);
    }
    return GetSysColor(i);
}
/* The frame metrics of the box's Control Panel\Desktop\WindowMetrics (negative
 * twips, as XP writes them when a visual style is applied: Luna's 25 px
 * caption, 19 px menu, 1 px border), over the host's in aiSysMet: XP's user32
 * and uxtheme lay frames out by them, and so does xp_ncrect. Only a box that
 * has them (an XP profile with Luna: tools/profile.py) */
static void box_metrics(int32_t* m) {
    static const struct { const wchar_t* name; int add, idx[2]; } k[] = {
        { L"CaptionHeight", 1, { SM_CYCAPTION, -1 } }, { L"SmCaptionHeight", 1, { SM_CYSMCAPTION, -1 } },
        { L"MenuHeight", 1, { SM_CYMENU, -1 } }, { L"BorderWidth", 3, { SM_CXFRAME, SM_CYFRAME } },
        { L"ScrollWidth", 0, { SM_CXVSCROLL, SM_CXHSCROLL } }, { L"ScrollHeight", 0, { SM_CYHSCROLL, SM_CYVSCROLL } },
        { L"CaptionWidth", 0, { SM_CXSIZE, -1 } }, { L"SmCaptionWidth", 0, { SM_CXSMSIZE, -1 } } };
    wchar_t v[32];
    if (!nt_guest_xp(native32_guest_peb)) return;
    for (unsigned i = 0; i < sizeof k / sizeof k[0]; i++)
        if (native32_registry_box_sz(L"Control Panel\\Desktop\\WindowMetrics", k[i].name, v, 32) && _wtoi(v) < 0)
            for (int j = 0; j < 2 && k[i].idx[j] >= 0; j++) m[k[i].idx[j]] = -_wtoi(v) / 15 + k[i].add;
    if (native32_registry_box_sz(L"Control Panel\\Desktop\\WindowMetrics", L"CaptionHeight", v, 32) && _wtoi(v) < 0)
        m[SM_CYSIZE] = -_wtoi(v) / 15, m[SM_CXDLGFRAME] = m[SM_CYDLGFRAME] = 3, m[SM_CXEDGE] = m[SM_CYEDGE] = 2;
}
/* A themed top-level frame's client area, as XP's win32k computes it from those
 * metrics (the host's frame is another size: XP's uxtheme paints the frame it
 * lays out, so the host's client edge would leave a gap) */
static void xp_ncrect(HWND h, RECT* r) {
    int32_t* m = (int32_t*)(native32_user_psi + SO(0x59C));
    uint32_t st = (uint32_t)GetWindowLongW(h, GWL_STYLE), ex = (uint32_t)GetWindowLongW(h, GWL_EXSTYLE);
    int t = (st & WS_THICKFRAME) ? 0 : ((st & WS_DLGFRAME) || (ex & WS_EX_DLGMODALFRAME)) ? 1 : (st & WS_BORDER) ? 2 : 3;
    int bx[4] = { m[SM_CXFRAME], m[SM_CXDLGFRAME], m[SM_CXBORDER], 0 }, by[4] = { m[SM_CYFRAME], m[SM_CYDLGFRAME], m[SM_CYBORDER], 0 };
    InflateRect(r, -bx[t], -by[t]);
    if ((st & WS_CAPTION) == WS_CAPTION) r->top += (ex & WS_EX_TOOLWINDOW) ? m[SM_CYSMCAPTION] : m[SM_CYCAPTION];
    if (GetMenu(h)) r->top += m[SM_CYMENU];
    if (ex & WS_EX_CLIENTEDGE) InflateRect(r, -m[SM_CXEDGE], -m[SM_CYEDGE]);
    if (r->bottom < r->top) r->bottom = r->top;
    if (r->right < r->left) r->right = r->left;
}
static HFONT g_capfont, g_msgfont;   /* +0x854 / +0x858, given guest handles once gdi32's table exists */
static void msg_fonts(void) {
    uint8_t* psi = native32_user_psi;
    if (!psi || !g_msgfont || *(uint32_t*)(psi + SO(0x858))) return;
    uint32_t c = native32_gdi_handle((uint32_t)(uintptr_t)g_capfont), m = native32_gdi_handle((uint32_t)(uintptr_t)g_msgfont);
    if (m == (uint32_t)(uintptr_t)g_msgfont) return;             /* (no table yet) */
    *(uint32_t*)(psi + SO(0x854)) = c;
    *(uint32_t*)(psi + SO(0x858)) = m;
}
static void server_info(void) {
    static int done;
    uint8_t* psi = native32_user_psi;
    if (done || !psi) return;
    done = 1;
    for (int i = 0; i < 0x53; i++) *(int32_t*)(psi + SO(0x59C) + 4 * i) = GetSystemMetrics(i);
    if (g_screen) {                 /* the virtual screen's size, not the host's */
        int32_t* m = (int32_t*)(psi + SO(0x59C));
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
    box_metrics((int32_t*)(psi + SO(0x59C)));
    for (int i = 0; i < nt_ncolors(native32_guest_peb); i++) *(uint32_t*)(psi + SO(0x6E8) + 4 * i) = sys_color(i);
    /* +0x800 / +0x804 the system font's character size (GetDialogBaseUnits) */
    *(uint16_t*)(psi + SO(0x800)) = (uint16_t)LOWORD(GetDialogBaseUnits());
    *(uint16_t*)(psi + SO(0x804)) = (uint16_t)HIWORD(GetDialogBaseUnits());
    /* +0x808 / +0x80C cxMsgFontChar / cyMsgFontChar, +0x854 hCaptionFont,
     * +0x858 hMsgFont (msg_fonts): SoftModalMessageBox sizes its text and buttons by
     * them (all 0: every message box laid out at 16x39). The host's
     * NONCLIENTMETRICS fonts, as the guest's SPI query answers;
     * character size as win32k's GetCharDimensions */
    {
        NONCLIENTMETRICSW nm = { sizeof nm };
        if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof nm, &nm, 0)) {
            HFONT msg = CreateFontIndirectW(&nm.lfMessageFont);
            g_capfont = CreateFontIndirectW(&nm.lfCaptionFont), g_msgfont = msg;
            HDC s = GetDC(NULL);
            HGDIOBJ o = SelectObject(s, msg);
            TEXTMETRICW tm;
            SIZE z = { 0, 0 };
            GetTextMetricsW(s, &tm);
            GetTextExtentPoint32W(s, L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 52, &z);
            SelectObject(s, o);
            ReleaseDC(NULL, s);
            *(int32_t*)(psi + SO(0x808)) = (tm.tmPitchAndFamily & TMPF_FIXED_PITCH) ? (z.cx / 26 + 1) / 2 : tm.tmAveCharWidth;
            *(int32_t*)(psi + SO(0x80C)) = tm.tmHeight;
            /* +0x1D8 wMaxBtnSize: a message box button's width. ponytail:
             * 50 dialog units (75 pixels at 6), not widened for a long
             * localized button string */
            *(int32_t*)(psi + SO(0x1D8)) = 50 * *(int32_t*)(psi + SO(0x808)) / 4;
        }
    }
    /* +0x1DC MBStrings[11] { WCHAR szName[16]; UINT uID; UINT uStr; }: a
     * message box's button texts and ids, OK .. Continue (empty: blank
     * buttons). ponytail: Windows 2000's English strings; uStr unused */
    {
        static const wchar_t* mb[11] = { L"OK", L"Cancel", L"&Abort", L"&Retry", L"&Ignore", L"&Yes", L"&No",
                                         L"&Close", L"Help", L"&Try Again", L"&Continue" };
        for (int i = 0; i < 11; i++) {
            wcsncpy((wchar_t*)(psi + SO(0x1DC) + 0x28 * i), mb[i], 15);
            *(uint32_t*)(psi + SO(0x1DC) + 0x28 * i + 0x20) = (uint32_t)i + 1;
        }
    }
    /* +0xE50 the UserPreferencesMask: 0x80000000 UI effects, 0x20 keyboard
     * cues always shown. A dialog hides its underlines and focus rectangle
     * (WM_CHANGEUISTATE UIS_INITIALIZE) when effects are on and cues are
     * not. ponytail: only these two bits, the host's; the rest (menu and
     * combo animations, ...) stay off */
    {
        BOOL fx = FALSE, cues = FALSE;
        SystemParametersInfoW(SPI_GETUIEFFECTS, 0, &fx, 0);
        SystemParametersInfoW(SPI_GETKEYBOARDCUES, 0, &cues, 0);
        *(uint32_t*)(psi + SO(0xE50)) = (fx ? 0x80000000u : 0) | (cues ? 0x20u : 0);
    }
    /* +0xE4A dmLogPixels: a dialog font's height is -MulDiv(points, it, 72).
     * +0xE48 BitCount (planes * bits), +0xE4C Planes, +0xE4D BitsPixel: the
     * display depth an icon's image is chosen by (LookupIconIdFromDirectoryEx);
     * left 0, user32 took the 16-colour image where the host takes 256 */
    {
        HDC s = GetDC(NULL);
        int pl = GetDeviceCaps(s, PLANES), bp = GetDeviceCaps(s, BITSPIXEL);
        *(uint16_t*)(psi + SO(0xE48)) = (uint16_t)(pl * bp);
        *(uint8_t*)(psi + SO(0xE4C)) = (uint8_t)pl;
        *(uint8_t*)(psi + SO(0xE4D)) = (uint8_t)bp;
        *(uint16_t*)(psi + SO(0xE4A)) = (uint16_t)GetDeviceCaps(s, LOGPIXELSY);
        ReleaseDC(NULL, s);
    }
    /* +0x1A0 the system classes' atoms, by dialog-template ordinal & 0x7F
     * (0x80 Button .. 0x85 ComboBox): the host's */
    {
        static const wchar_t* cls[] = { L"Button", L"Edit", L"Static", L"ListBox", L"ScrollBar", L"ComboBox" };
        for (int i = 0; i < 6; i++) {
            WNDCLASSEXW wc = { sizeof wc };
            *(uint16_t*)(psi + SO(0x1A0) + 2 * i) = (uint16_t)GetClassInfoExW(NULL, cls[i], &wc);
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
    if (!psi || *(uint32_t*)(psi + SO(0x75C))) return;
    {   /* (no table yet) */
        uint32_t s = (uint32_t)(uintptr_t)GetSysColorBrush(0);
        if (native32_gdi_handle(s) == s) return;
    }
    for (int i = 0; i < nt_ncolors(native32_guest_peb); i++) {
        /* a box colour gets its own brush (ponytail: never deleted, like the system's) */
        uint32_t h = (uint32_t)(uintptr_t)(g_boxcolor & (1u << i) ? CreateSolidBrush(*(uint32_t*)(psi + SO(0x6E8) + 4 * i))
                                                                   : GetSysColorBrush(i)), g = native32_gdi_handle(h);
        if (g == h) { *(uint32_t*)(psi + SO(0x75C)) = 0; return; }       /* (no table yet) */
        *(uint32_t*)(psi + SO(0x75C) + 4 * i) = g;
    }
}

static void (*g_prev_pre)(void);
static void user_pre(void) {        /* before every win32k service */
    server_info();
    sys_brushes();
    msg_fonts();
    if (native32_user_ahe) {
        thread_setup();
        /* DESKTOPINFO +8 spwnd: user32's GetDesktopWindow reads it */
        if (g_screen && !*(uint32_t*)(g_deskinfo + 8)) *(uint32_t*)(g_deskinfo + 8) = desktop_wnd();
        /* +0x50 spwndShell (GetShellWindow, client-side): the screen's shell, also
         * for a second guest process (explorer started to open a folder hands it
         * to the running shell instead of becoming one). Never the host's shell. */
        if (g_screen && !*(uint32_t*)(g_deskinfo + 0x50)) {
            HWND sh = (HWND)GetPropW(g_screen, L"pcrecomp.shell");
            if (sh && IsWindow(sh)) *(uint32_t*)(g_deskinfo + 0x50) = (uint32_t)(uintptr_t)native32_user_wnd(sh);
        }
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
        native32_nt_callback(CB(74), 0, 0, &o, &olen);
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
        fprintf(stderr, "[user] class %ls background %p (guest %08X)\n", (uintptr_t)w.lpszClassName < 0x10000 ? L"(atom)" : w.lpszClassName,
                w.hbrBackground, ((WNDCLASSEXW*)(uintptr_t)a[0])->hbrBackground);
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
    uint32_t k = nt_guest_vista(native32_guest_peb) ? 0x2C : nt_guest_xp(native32_guest_peb) ? 0x28 : 0x24;   /* (XP: pfnGhostWndProc before it; Vista one more) */
    for (uint32_t o = 0x1000; o + 0x2C < size; o += 4)
        if (MEM32(u + o) == dw)
            for (uint32_t p = 0x1000; p + 0x2C < size; p += 4)
                if (MEM32(u + p) == da && MEM32(u + p + k) == MEM32(u + o + k)) return MEM32(u + o + k);
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
static HWND g_shellwnd;
/* the shell window stays the screen's bottom child whatever moves it: a click
 * activates it (a host child without WS_CHILD), and activation raised it over
 * the taskbar and every program (the desktop then showed icons only) */
static void shell_pin(HWND h, UINT m, LPARAM l) {
    if (m == WM_WINDOWPOSCHANGING && h && h == g_shellwnd && l && !(((WINDOWPOS*)l)->flags & SWP_NOZORDER))
        ((WINDOWPOS*)l)->hwndInsertAfter = HWND_BOTTOM;
}
static LRESULT wnd_thunk_body(HWND h, UINT m, WPARAM w, LPARAM l);
/* With the machine held from the start: the body reads this thread's TEB through
 * g_fs_base and writes its CallbackWnd, and another guest thread holding the machine
 * meanwhile had g_fs_base as its own (explorer's tray thread sending to the Start
 * menu's: XP's user32 took that thread's hwnd with this window's procedure) */
static LRESULT CALLBACK wnd_thunk(HWND h, UINT m, WPARAM w, LPARAM l) {
    LRESULT r;
    mach_enter();
    r = wnd_thunk_body(h, m, w, l);
    mach_leave();
    return r;
}
static LRESULT wnd_thunk_body(HWND h, UINT m, WPARAM w, LPARAM l) {
    shell_pin(h, m, l);
    uint8_t* pw = native32_user_wnd(h);
    uint32_t pfn = pw ? *(uint32_t*)(pw + WO(0x5C)) : 0, args[4] = { (uint32_t)(uintptr_t)h, m, (uint32_t)w, (uint32_t)l };
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
        msg_call(CB(9), msg, sizeof msg, m, rep);
    } else if (m == WM_SETTEXT) {
        uint32_t msg[0x0C] = { 0 };
        char* a = NULL;
        msg[6] = (uint32_t)(uintptr_t)pw, msg[7] = m, msg[8] = args[2], msg[9] = pfn, msg[10] = g_dcm, msg[11] = args[3];
        if (ansi && l) {
            int n = WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)l, -1, NULL, 0, NULL, NULL);
            if ((a = (char*)malloc(n)) != NULL) WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)l, -1, a, n, NULL, NULL);
            msg[11] = (uint32_t)(uintptr_t)a;
        }
        msg_call(CB(25), msg, sizeof msg, m, rep);
        free(a);
    } else if (m == WM_GETTEXT && l && w) {
        uint32_t msg[0x0D] = { 0 };
        char* a = ansi ? (char*)malloc(w * 2) : NULL;
        msg[6] = (uint32_t)(uintptr_t)pw, msg[7] = m, msg[8] = args[2], msg[9] = pfn, msg[10] = g_dcm;
        msg[11] = a ? (uint32_t)(uintptr_t)a : args[3], msg[12] = (uint32_t)w * 2;
        if (msg_call(CB(7), msg, sizeof msg, m, rep) && rep[2]) {
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
        uint32_t o = 0, olen = 0, st = native32_nt_callback(CB(2), (uint32_t)(uintptr_t)msg, sizeof msg, &o, &olen);
        if (st == 0 && o && olen >= 4) rep[0] = MEM32(o);
        else if (st) fprintf(stderr, "[user] callback for message 0x%X: status %08X\n", m, st);
    }
    MEM32(teb + 0x6F4) = oh, MEM32(teb + 0x6F8) = op;
    /* the callback's return flushes the TEB's GDI batch, as win32k's does
     * (calc's owner-drawn buttons: DrawEdge's PatBlts are batched) */
    if (native32_win32k_pre) native32_win32k_pre();
    if (native32_cb_out) native32_cb_out(args, &rep[0]);
    shell_pin(h, m, l);
    return (LRESULT)rep[0];
}

/* A top-level frame: Windows 2000 sizes it with its own borders (one
 * SM_CXBORDER each for WS_EX_WINDOWEDGE x2 and a caption or modal frame,
 * GetWindowBorders); the host's frame is thicker (padded borders). The client
 * area is what the guest meant, so the difference goes on each side: at
 * creation and at every later size of a window of the virtual screen
 * (winmine sizes itself after creation and was clipped by 10 px). */
static int frame_pad(uint32_t style, uint32_t ex) {
    if (native32_themed) return 0;      /* XP's frame, laid out by the guest's own metrics (xp_ncrect) */
    int b = (ex & WS_EX_WINDOWEDGE) ? 2 : (ex & WS_EX_STATICEDGE) ? 1 : 0;
    RECT r = { 0, 0, 0, 0 };
    if (style & WS_CHILD) return 0;
    if ((style & WS_CAPTION) || (ex & WS_EX_DLGMODALFRAME)) b++;
    if (style & WS_THICKFRAME) { UINT g = 1; SystemParametersInfoW(SPI_GETBORDER, 0, &g, 0); b += g; }
    if (ex & WS_EX_CLIENTEDGE) b += 2;
    b *= GetSystemMetrics(SM_CXBORDER);
    AdjustWindowRectEx(&r, style, FALSE, ex);
    return -r.left > b ? -r.left - b : 0;
}
static int screen_pad(HWND h) {
    /* a captioned window only: the tray (a thick frame) and the BaseBar keep their sizes */
    return g_screen && GetAncestor(h, GA_PARENT) == g_screen && (GetWindowLongW(h, GWL_STYLE) & WS_CAPTION) == WS_CAPTION
        ? frame_pad((uint32_t)GetWindowLongW(h, GWL_STYLE), (uint32_t)GetWindowLongW(h, GWL_EXSTYLE)) : 0;
}
/* A window made top-level then put on the screen keeps the frame DWM drew for
 * it, so nobody painted its caption (winmine, the Run dialog: blank). DWM's
 * frame off, the classic (Windows 2000) caption and borders. */
static void screen_frame(HWND h) {
    typedef HRESULT (WINAPI *dwmset_t)(HWND, DWORD, LPCVOID, DWORD);
    typedef HRESULT (WINAPI *settheme_t)(HWND, LPCWSTR, LPCWSTR);
    static dwmset_t dwmset; static settheme_t settheme;
    DWORD off = 1;   /* DWMNCRP_DISABLED */
    if (!dwmset) dwmset = (dwmset_t)GetProcAddress(LoadLibraryW(L"dwmapi.dll"), "DwmSetWindowAttribute");
    if (!settheme) settheme = (settheme_t)GetProcAddress(LoadLibraryW(L"uxtheme.dll"), "SetWindowTheme");
    if (dwmset) dwmset(h, 2 /* DWMWA_NCRENDERING_POLICY */, &off, sizeof off);
    if (settheme) settheme(h, L"", L"");
    SetWindowPos(h, NULL, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
}
static LRESULT CALLBACK cbt_noactivate(int c, WPARAM w, LPARAM l) { return c == HCBT_ACTIVATE ? 1 : CallNextHookEx(NULL, c, w, l); }
/* NtUserCreateWindowEx(exstyle, LARGE_STRING* class, LARGE_STRING* name, style,
 * x, y, cx, cy, parent, menu, hInstance, lpParam, flags) */
static uint32_t s_create_window(uint32_t* a) {
    native32_theme_start();
    int cx = (int)a[6], cy = (int)a[7], p = frame_pad(a[3], a[0]);
    if (a[4] != CW_USEDEFAULT && cx > 0 && cy > 0 && cx != CW_USEDEFAULT) cx += 2 * p, cy += 2 * p;
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
    if (!h) {
        DWORD e = GetLastError();
        /* win32k's failure is the thread's last error (TEB LastErrorValue): XP's user32 reads
         * ERROR_CANNOT_FIND_WND_CLASS to load the class's side-by-side DLL (comctl32 6.0
         * registers "6.0.2600.5512!Button" then) and create again */
        MEM32(MEM32(g_fs_base + 0x18) + 0x34) = e;
        if (getenv("NATIVE32_SYSCALLS") || !(nt_guest_xp(native32_guest_peb) && e == ERROR_CANNOT_FIND_WND_CLASS && wcschr(lstr_name(a[1]) && (uintptr_t)lstr_name(a[1]) >= 0x10000 ? lstr_name(a[1]) : L"", L'!')))
            fprintf(stderr, "[user] CreateWindowExW %08X %ls failed: %lu (style %08X ex %08X parent %08X menu %08X inst %08X)\n", a[1], (uintptr_t)lstr_name(a[1]) < 0x10000 ? L"(atom)" : lstr_name(a[1]), e, a[3], a[0], a[8], a[9], a[10]);
    }
    if (h && g_screen && !(a[3] & WS_CHILD)) {   /* a top-level window: on the screen */
        /* the host activates a top-level window it makes a child; win32k never
         * activates at create (the tray lost activation to each hidden window
         * explorer made, and the Start menu's message filter disengaged) */
        HHOOK hk = SetWindowsHookExW(WH_CBT, cbt_noactivate, NULL, GetCurrentThreadId());
        SetParent(h, g_screen);
        if (hk) UnhookWindowsHookEx(hk);
        if ((a[3] & WS_CAPTION) == WS_CAPTION) screen_frame(h);
    }
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
static void shell_bottom(HWND h) {
    if (h && h == g_shellwnd) SetWindowPos(h, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
}
static uint32_t s_set_shell(uint32_t* a) {
    if (!own_window(a[0])) return 0;
    shell_bottom(g_shellwnd = (HWND)(uintptr_t)a[0]);
    if (g_screen) SetPropW(g_screen, L"pcrecomp.shell", g_shellwnd);
    return 1;
}
/* a broadcast stays in the guest (ponytail: dropped, not sent to the guest's
 * own top-level windows; send it to them when something waits for one) */
static uint32_t s_send_notify(uint32_t* a) {
    return own_window(a[0]) ? SendNotifyMessageW((HWND)(uintptr_t)a[0], a[1], a[2], a[3]) : 1;
}
/* NtUserSendMessageCallback(hwnd, msg, wParam, lParam, callback, data): to one
 * of the guest's own windows, sent now and the guest's SENDASYNCPROC called
 * with the result; a broadcast or another process's window stays in the guest
 * (dropped, as SendNotifyMessage). ponytail: the callback runs before the call
 * returns, not on the caller's next message wait; nothing has minded yet */
static uint32_t s_send_callback(uint32_t* a) {
    if (!own_window(a[0])) return 1;
    uint32_t r = (uint32_t)SendMessageW((HWND)(uintptr_t)a[0], a[1], a[2], a[3]);
    if (a[4]) {
        uint32_t args[4] = { a[0], a[1], a[5], r };
        native32_call_guest(a[4], 4, args);
    }
    return 1;
}
/* NtUserChangeDisplaySettings(device, devmode, hwnd, flags, lParam): the host's
 * display mode never changes. A test (CDS_TEST) passes; anything else is
 * DISP_CHANGE_FAILED, so Display's Apply says it could not (the box keeps the
 * applet's registry writes) */
static uint32_t s_change_display(uint32_t* a) {
    if (a[3] & CDS_TEST) return DISP_CHANGE_SUCCESSFUL;
    fprintf(stderr, "[user] ChangeDisplaySettings (flags %X): the host's display mode, refused\n", a[3]);
    return (uint32_t)DISP_CHANGE_FAILED;
}
/* NtUserEnumDisplayDevices(UNICODE_STRING* device, index, DISPLAY_DEVICEW*, flags)
 * and NtUserEnumDisplaySettings(UNICODE_STRING* device, mode, DEVMODEW*, flags):
 * NTSTATUS on NT 5. Read-only host queries (Display's Settings page); the
 * current/registry mode (-1/-2) is the virtual screen's size when there is one */
static const wchar_t* ustr_or_null(uint32_t u, wchar_t* buf) {
    if (!u || !MEM16(u)) return NULL;
    memcpy(buf, (void*)(uintptr_t)MEM32(u + 4), MEM16(u) < 126 ? MEM16(u) : 126);
    buf[(MEM16(u) < 126 ? MEM16(u) : 126) / 2] = 0;
    return buf;
}
static uint32_t s_enum_devices(uint32_t* a) {
    wchar_t n[64];
    DISPLAY_DEVICEW* d = (DISPLAY_DEVICEW*)(uintptr_t)a[2];
    const wchar_t* dev = ustr_or_null(a[0], n);
    if (!d) return 0xC0000001u;
    if (!g_screen) return EnumDisplayDevicesW(dev, a[1], d, a[3]) ? 0 : 0xC0000001u;
    /* a virtual screen is one display: the host's primary adapter (and its
     * first monitor), nothing more (Display took the host's other, detached
     * adapters as drivers with no modes) */
    if (a[1]) return 0xC0000001u;
    if (dev) return EnumDisplayDevicesW(dev, 0, d, a[3]) ? 0 : 0xC0000001u;
    for (DWORD i = 0; EnumDisplayDevicesW(NULL, i, d, a[3]); i++)
        if (d->StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE) return 0;
    return 0xC0000001u;
}
static uint32_t s_enum_settings(uint32_t* a) {
    wchar_t n[64];
    DEVMODEW* d = (DEVMODEW*)(uintptr_t)a[2];
    /* on a virtual screen the guest's own modes: its size first, then a
     * Windows 2000 list, at the host's depth, 60 Hz (the host's 4K list with
     * an 800x600 current mode: Display's "configuration parameters ...
     * invalid"). ponytail: one depth */
    static const uint16_t modes[][2] = { { 640, 480 }, { 800, 600 }, { 1024, 768 }, { 1152, 864 }, { 1280, 1024 } };
    const int nm = (int)(sizeof modes / sizeof modes[0]);
    uint32_t m = a[1];
    if (g_screen && m != ENUM_CURRENT_SETTINGS && m != ENUM_REGISTRY_SETTINGS && m >= (uint32_t)nm + 1) return 0xC0000001u;
    if (!d || !EnumDisplaySettingsExW(ustr_or_null(a[0], n), g_screen ? ENUM_CURRENT_SETTINGS : m, d, a[3])) return 0xC0000001u;
    if (g_screen) {
        int i = m == ENUM_CURRENT_SETTINGS || m == ENUM_REGISTRY_SETTINGS || m == 0 ? -1 : (int)m - 1;
        d->dmPelsWidth = i < 0 ? (DWORD)g_scx : modes[i][0];
        d->dmPelsHeight = i < 0 ? (DWORD)g_scy : modes[i][1];
        d->dmDisplayFrequency = 60;
        d->dmPosition.x = d->dmPosition.y = 0;
        /* a Windows 2000 driver's fields: Display takes a mode with any
         * other (the host's orientation, fixed output) as invalid */
        d->dmFields = DM_BITSPERPEL | DM_PELSWIDTH | DM_PELSHEIGHT | DM_DISPLAYFLAGS | DM_DISPLAYFREQUENCY |
                      (m == ENUM_CURRENT_SETTINGS || m == ENUM_REGISTRY_SETTINGS ? DM_POSITION : 0);
        d->dmDisplayFlags = 0;
        d->dmDisplayOrientation = d->dmDisplayFixedOutput = 0;
        d->dmDriverExtra = 0;
    }
    return 0;
}
static int own_thread(uint32_t tid) {
    HANDLE t = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    DWORD pid = t ? GetProcessIdOfThread(t) : 0;
    if (t) CloseHandle(t);
    return pid == GetCurrentProcessId();
}
static uint32_t s_post_thread(uint32_t* a) {
    return own_thread(a[0]) ? PostThreadMessageW(a[0], a[1], a[2], a[3]) : 0;
}
/* NtUserAttachThreadInput(idAttach, idAttachTo, fAttach): this process's
 * threads only, and answered without merging the host queues: merged, the Run
 * dialog's thread (attached to the tray's) hung in SetActiveWindow on a send
 * to the tray thread, which was waiting for that dialog.
 * ponytail: SetFocus/active across attached threads is then per-thread */
static uint32_t s_attach_input(uint32_t* a) { return own_thread(a[0]) && own_thread(a[1]); }
/* The shell hook, inside the virtual screen only (never the host's
 * RegisterShellHookWindow): win32k tells explorer's tray of top-level windows
 * with a posted "SHELLHOOK" message (HSHELL_WINDOWCREATED 1, DESTROYED 2,
 * ACTIVATED 4). The screen's other programs (a runner explorer started) are
 * other processes, so the screen polls its children (a timer, 250 ms): a
 * visible, unowned window of another process is a task, and so is one of
 * explorer's own with a caption (own_task) */
#define MAX_TASKS 64
static HWND g_shellhook, g_tasks[MAX_TASKS], g_task_top;
static int g_ntasks;
static void shell_post(WPARAM code, HWND h) {
    static UINT msg;
    if (!msg) msg = RegisterWindowMessageW(L"SHELLHOOK");
    if (h && code != HSHELL_WINDOWDESTROYED) native32_user_wnd(h);
   /* the guest's ValidateHwnd (GetWindowText) finds it */
    if (code == HSHELL_WINDOWCREATED) {
        wchar_t cls[64] = L"";
        RECT r = { 0 };
        GetClassNameW(h, cls, 64), GetWindowRect(h, &r);
        fprintf(stderr, "[user] shell hook 1: %p %ls style %08lX (%ld,%ld)-(%ld,%ld)\n", (void*)h, cls,
                (unsigned long)GetWindowLongW(h, GWL_STYLE), r.left, r.top, r.right, r.bottom);
    } else if (code != HSHELL_WINDOWACTIVATED) fprintf(stderr, "[user] shell hook %u: %p\n", (unsigned)code, (void*)h);
    PostMessageW(g_shellhook, msg, code, (LPARAM)h);
}
/* explorer's own top-level window is a task when captioned and not a tool
 * window (a folder window; not the tray, the desktop or the Start menu) */
static int own_task(HWND h) {
    return (GetWindowLongW(h, GWL_STYLE) & WS_CAPTION) == WS_CAPTION && !(GetWindowLongW(h, GWL_EXSTYLE) & WS_EX_TOOLWINDOW);
}
static void shell_poll(void) {
    HWND now[MAX_TASKS], top = NULL;
    int n = 0;
    if (!g_shellhook || !IsWindow(g_shellhook)) return;
    for (HWND c = GetWindow(g_screen, GW_CHILD); c && n < MAX_TASKS; c = GetWindow(c, GW_HWNDNEXT))
        if (IsWindowVisible(c) && !GetWindow(c, GW_OWNER) && (!own_window((uint32_t)(uintptr_t)c) || own_task(c))) {
            if (!top) top = c;
            now[n++] = c;
        }
    for (int i = 0; i < n; i++) {
        int k = 0;
        while (k < g_ntasks && g_tasks[k] != now[i]) k++;
        if (k == g_ntasks) shell_post(HSHELL_WINDOWCREATED, now[i]);
    }
    for (int k = 0; k < g_ntasks; k++) {
        int i = 0;
        while (i < n && now[i] != g_tasks[k]) i++;
        if (i == n) shell_post(HSHELL_WINDOWDESTROYED, g_tasks[k]);
    }
    if (top != g_task_top) shell_post(HSHELL_WINDOWACTIVATED, top);
    /* a themed frame is drawn active or not by what WM_NCACTIVATE said (the host
     * never activates the screen's windows): the top one active, as on XP */
    if (native32_themed && top != g_task_top) {
        if (g_task_top && IsWindow(g_task_top)) SendNotifyMessageW(g_task_top, WM_NCACTIVATE, FALSE, 0);
        if (top) SendNotifyMessageW(top, WM_NCACTIVATE, TRUE, 0);
    }
    memcpy(g_tasks, now, n * sizeof *now), g_ntasks = n, g_task_top = top;
}
/* The desktop's wallpaper, as win32k paints it: the box's Control Panel\Desktop
 * Wallpaper, a BMP named by its guest path (the file box's X:\ is
 * PCRECOMP_FILEBOX\X), stretched over the virtual screen (WallpaperStyle 2)
 * or centred, COLOR_BACKGROUND around it. ponytail: no tiling */
static HBITMAP wallpaper(int* style) {
    static int done, st;
    static HBITMAP bm;
    wchar_t v[MAX_PATH], box[MAX_PATH], path[2 * MAX_PATH];
    if (!done) {
        done = 1;
        if (native32_registry_box_sz(L"Control Panel\\Desktop", L"Wallpaper", v, MAX_PATH) && v[0] && v[1] == L':' &&
            GetEnvironmentVariableW(L"PCRECOMP_FILEBOX", box, MAX_PATH)) {
            _snwprintf(path, 2 * MAX_PATH - 1, L"%ls\\%c%ls", box, (wchar_t)(v[0] & ~0x20), v + 2), path[2 * MAX_PATH - 1] = 0;
            bm = (HBITMAP)LoadImageW(NULL, path, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE);
            if (native32_registry_box_sz(L"Control Panel\\Desktop", L"WallpaperStyle", v, MAX_PATH)) st = _wtoi(v);
            fprintf(stderr, "[user] wallpaper: %s\n", bm ? "loaded" : "not loaded");
        }
    }
    *style = st;
    return bm;
}
/* the wallpaper into a DC of window w (its client area), in screen coordinates */
static int paint_wallpaper(HDC dc, HWND w) {
    int st;
    HBITMAP bm = wallpaper(&st);
    BITMAP b;
    if (!bm || !g_screen || !GetObjectW(bm, sizeof b, &b)) return 0;
    POINT o = { 0, 0 };
    if (w && w != g_screen) MapWindowPoints(g_screen, w, &o, 1);
    RECT all = { o.x, o.y, o.x + g_scx, o.y + g_scy };
    HBRUSH bg = CreateSolidBrush(sys_color(COLOR_BACKGROUND));
    FillRect(dc, &all, bg);
    DeleteObject(bg);
    HDC m = CreateCompatibleDC(dc);
    HGDIOBJ old = SelectObject(m, bm);
    SetStretchBltMode(dc, COLORONCOLOR);
    if (st == 2) StretchBlt(dc, o.x, o.y, g_scx, g_scy, m, 0, 0, b.bmWidth, b.bmHeight, SRCCOPY);
    else BitBlt(dc, o.x + (g_scx - b.bmWidth) / 2, o.y + (g_scy - b.bmHeight) / 2, b.bmWidth, b.bmHeight, m, 0, 0, SRCCOPY);
    SelectObject(m, old);
    DeleteDC(m);
    return 1;
}
/* NtUserBuildNameList(hwinsta, cb, buffer, needed*): the window stations and desktops
 * are the host's, never listed (EnumDesktops fails; XP's uxtheme sent WM_THEMECHANGED
 * to every desktop it named, and named stack bytes forever) */
static uint32_t s_namelist(uint32_t* a) { (void)a; return 0xC0000022u; }   /* STATUS_ACCESS_DENIED */
/* NtUserPaintDesktop(hdc): the wallpaper; without one, COLOR_BACKGROUND */
static uint32_t s_paintdesktop(uint32_t* a) {
    HDC dc = (HDC)(uintptr_t)(native32_gdi_host(a[0]) ? native32_gdi_host(a[0]) : a[0]);
    HWND w = WindowFromDC(dc);
    if (paint_wallpaper(dc, w)) return 1;
    RECT r;
    HBRUSH bg = CreateSolidBrush(sys_color(COLOR_BACKGROUND));
    GetClipBox(dc, &r);
    FillRect(dc, &r, bg);
    DeleteObject(bg);
    return 1;
}
static LRESULT CALLBACK screen_proc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_TIMER && w == 1) { shell_poll(); return 0; }
    if (m == WM_ERASEBKGND && paint_wallpaper((HDC)w, h)) return 1;
    return DefWindowProcW(h, m, w, l);
}
/* NtUserCallHwnd(hwnd, index): 0x3C RegisterShellHookWindow, 0x39 Deregister */
static uint32_t s_callhwnd(uint32_t* a) {
    a[1] = nt_routine(native32_guest_peb, a[1]);   /* (XP: its routine numbers, as 2000's) */
    if (a[1] == 0x3C && own_window(a[0])) { g_shellhook = (HWND)(uintptr_t)a[0]; g_ntasks = 0; g_task_top = NULL; return 1; }
    if (a[1] == 0x39) { if (g_shellhook == (HWND)(uintptr_t)a[0]) g_shellhook = NULL; return 1; }
    fprintf(stderr, "[user] NtUserCallHwnd index 0x%X not answered\n", a[1]);
    return 0;
}
/* NtUserInternalGetWindowText(hwnd, buf, cch): the host's (no message: the
 * taskbar reads another program's title with it) */
static uint32_t s_internal_text(uint32_t* a) {
    return (uint32_t)InternalGetWindowText((HWND)(uintptr_t)a[0], (LPWSTR)(uintptr_t)a[1], (int)a[2]);
}
/* NtUserGetClassName(hwnd, bReal, UNICODE_STRING* out): the host's name into
 * out's buffer (MaximumLength bytes); characters copied. The taskbar asks it
 * of each window the shell hook names. ponytail: bReal (the base class of a
 * superclass) not told apart */
static uint32_t s_classname(uint32_t* a) {
    int n;
    if (!a[2] || !MEM32(a[2] + 4) || MEM16(a[2] + 2) < 2) return 0;
    n = GetClassNameW((HWND)(uintptr_t)a[0], (LPWSTR)(uintptr_t)MEM32(a[2] + 4), MEM16(a[2] + 2) / 2);
    MEM16(a[2]) = (uint16_t)(n * 2);
    return (uint32_t)n;
}
/* NtUserCallHwndOpt(hwnd, index): 0x3E SetProgmanWindow, 0x3F SetTaskmanWindow:
 * the screen's, never the host's (nothing reads them back yet) */
static uint32_t s_callhwnd_opt(uint32_t* a) {
    a[1] = nt_routine(native32_guest_peb, a[1]);   /* (XP: its routine numbers, as 2000's) */
    if (a[1] == 0x3E || a[1] == 0x3F) return 1;
    fprintf(stderr, "[user] NtUserCallHwndOpt index 0x%X not answered\n", a[1]);
    return 0;
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
/* NtUserBuildHwndList(hdesk, hwndParent, fChildren, idThread, cMax, HWND* list,
 * ULONG* count): a parent's descendants, the thread's windows, or the
 * screen's top-level ones (never the host's others), then 1 as the end
 * (count takes it in; too small: STATUS_BUFFER_TOO_SMALL and the count).
 * Unanswered, user32 enumerated 63 stack words: XP's uxtheme walks a
 * window's children with it. ponytail: idThread is this thread */
#define HWNDLIST_MAX 1024
static struct { HWND h[HWNDLIST_MAX]; int n; } g_hl;
static BOOL CALLBACK hwndlist_add(HWND h, LPARAM l) { (void)l; if (g_hl.n < HWNDLIST_MAX) g_hl.h[g_hl.n++] = h; return TRUE; }
static uint32_t s_hwndlist(uint32_t* a) {
    g_hl.n = 0;
    if (a[1] && a[2]) EnumChildWindows((HWND)(uintptr_t)a[1], hwndlist_add, 0);
    else if (a[3]) EnumThreadWindows(GetCurrentThreadId(), hwndlist_add, 0);
    else if (g_screen) for (HWND h = GetWindow(g_screen, GW_CHILD); h; h = GetWindow(h, GW_HWNDNEXT)) hwndlist_add(h, 0);
    else {
        DWORD pid;
        for (HWND h = GetTopWindow(NULL); h; h = GetWindow(h, GW_HWNDNEXT))
            if (GetWindowThreadProcessId(h, &pid) && pid == GetCurrentProcessId()) hwndlist_add(h, 0);
    }
    if (a[6]) MEM32(a[6]) = (uint32_t)g_hl.n + 1;
    if ((uint32_t)g_hl.n + 1 > a[4]) return 0xC0000023u;                /* STATUS_BUFFER_TOO_SMALL */
    for (int i = 0; i < g_hl.n; i++) MEM32(a[5] + 4 * i) = (uint32_t)(uintptr_t)g_hl.h[i];
    MEM32(a[5] + 4 * g_hl.n) = 1;
    return 0;
}
/* NtUserGetAncestor(hwnd, flags), NtUserGetTitleBarInfo(hwnd, TITLEBARINFO*),
 * NtUserGetGUIThreadInfo(tid, GUITHREADINFO*): the host's (XP's uxtheme
 * draws a frame's caption buttons from the title bar's states) */
static uint32_t s_ancestor(uint32_t* a) { return (uint32_t)(uintptr_t)GetAncestor((HWND)(uintptr_t)a[0], a[1]); }
static uint32_t s_titlebarinfo(uint32_t* a) { return GetTitleBarInfo((HWND)(uintptr_t)a[0], (TITLEBARINFO*)(uintptr_t)a[1]); }
static uint32_t s_guithreadinfo(uint32_t* a) { (void)a[0]; return GetGUIThreadInfo(GetCurrentThreadId(), (GUITHREADINFO*)(uintptr_t)a[1]); }
/* NtUserGetProcessWindowStation(): the host's. NtUserGetObjectInformation(h,
 * index, buf, len, needed*): only UOI_NAME (2) of it, the interactive
 * "WinSta0" (XP's uxtheme themes no process elsewhere); nothing else of the
 * host's objects (names, SIDs) is told */
static uint32_t s_winsta(uint32_t* a) { (void)a; return (uint32_t)(uintptr_t)GetProcessWindowStation(); }
static uint32_t s_objinfo(uint32_t* a) {
    static const wchar_t n[] = L"WinSta0";
    if (a[1] != 2 || (HWINSTA)(uintptr_t)a[0] != GetProcessWindowStation()) return 0;
    if (a[4]) MEM32(a[4]) = sizeof n;
    if (a[3] < sizeof n) return 0;
    memcpy((void*)(uintptr_t)a[2], n, sizeof n);
    return 1;
}
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
    a[2] = nt_routine(native32_guest_peb, a[2]);   /* (XP: its routine numbers, as 2000's) */
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
    /* SPI_GETDESKWALLPAPER: the box's (the host's names a host path), else none */
    if (a[0] == SPI_GETDESKWALLPAPER && a[2] && a[1]) {
        wchar_t v[MAX_PATH] = L"";
        native32_registry_box_sz(L"Control Panel\\Desktop", L"Wallpaper", v, MAX_PATH);
        lstrcpynW((wchar_t*)(uintptr_t)a[2], v, (int)a[1]);
        return 1;
    }
    if (g_screen && a[0] == SPI_SETWORKAREA) {
        if (a[2]) memcpy(&g_work, (void*)(uintptr_t)a[2], sizeof g_work);
        else SetRect(&g_work, 0, 0, g_scx, g_scy);
        if (g_mon) memcpy(g_mon + 0x20, &g_work, sizeof g_work);
        return 1;
    }
    /* SPI_GETMENUANIMATION / SPI_GETMENUFADE / SPI_GETSELECTIONFADE (the chosen
     * menu item fading out on a thread of its own, which spun): no. The virtual screen's
     * top-level windows are host child windows, which cannot be
     * WS_EX_LAYERED (not without a Windows 8 manifest), so AnimateWindow's
     * AW_BLEND failed and the Start menu never showed; its slide times
     * itself with the guest's GetTickCount, which reads KUSER_SHARED_DATA's
     * TickCountLow (0 on Windows 10/11) and spun forever. ponytail: menus
     * appear without animation; a moving guest tick is the upgrade (it sent
     * ole32 into the COM+ catalog at start, not looked at) */
    if (g_screen && (a[0] == SPI_GETMENUANIMATION || a[0] == SPI_GETMENUFADE || a[0] == SPI_GETSELECTIONFADE) && a[2]) { MEM32(a[2]) = 0; return 1; }
    if (!spi_get(a[0], a[2])) {
        fprintf(stderr, "[user] SystemParametersInfo 0x%X (a SET) refused\n", a[0]);
        return 0;
    }
    /* SPI_GETNONCLIENTMETRICS: Windows 2000's SystemParametersInfoA passes
     * its NONCLIENTMETRICSW with cbSize unset and uiParam the A size (0x154);
     * its win32k filled it anyway, the host refuses, and the A caller (the
     * Start menu's menuband) made its menu font from stack garbage: no item
     * text. The NT 5 size (no iPaddedBorderWidth). */
    if (a[0] == SPI_GETNONCLIENTMETRICS && a[2]) MEM32(a[2]) = a[1] = 0x1F4;
    return SystemParametersInfoW(a[0], a[1], (void*)(uintptr_t)a[2], 0);
}
/* NtUserGetDCEx(hwnd, hrgnClip, flags), NtUserGetWindowDC(hwnd) */
static uint32_t s_getdcex(uint32_t* a) {
    /* a region the guest never had a handle for is the host's own, passed through:
     * WM_NCPAINT's update region (XP's uxtheme paints a frame on GetDCEx(hwnd,
     * wParam, DCX_WINDOW | DCX_INTERSECTRGN); 1 is the whole window) */
    uint32_t r = native32_gdi_host(a[1]) ? native32_gdi_host(a[1]) : a[1] > 1 && GetObjectType((HGDIOBJ)(uintptr_t)a[1]) == OBJ_REGION ? a[1] : 0;
    return native32_gdi_handle((uint32_t)(uintptr_t)GetDCEx((HWND)(uintptr_t)a[0], (HRGN)(uintptr_t)r, a[2]));
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

/* The active caption on the screen. The host draws a re-parented top-level's
 * caption as its root window's activation says, and the screen (the host's
 * window) is never the host's active one, so every caption was grey: forcing
 * WM_NCACTIVATE TRUE and SetForegroundWindow did not change it (findings).
 * The screen's topmost captioned window is the active one, as on Windows 2000
 * (a program's window comes to the top when activated): after the host's
 * DefWindowProc paints its frame, its caption is painted again active, left
 * of the caption buttons. */
/* The menu bar the same way: the host greys a menu bar's text while its
 * window's queue is not the foreground one (a program explorer launched is
 * its own process); Windows 2000 never does. Each item's text again in
 * MENUTEXT on MENU, prefixes hidden (no keyboard cues). ponytail: text items
 * only, no hot or pushed state (the host draws those while it tracks). */
static void screen_menubar(HWND h) {
    HMENU m = GetMenu(h);
    RECT w;
    int n = m ? GetMenuItemCount(m) : 0;
    if (n <= 0 || !GetWindowRect(h, &w)) return;
    HDC dc = GetWindowDC(h);
    if (!dc) return;
    NONCLIENTMETRICSW ncm = { sizeof ncm };
    SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof ncm, &ncm, 0);
    HFONT font = CreateFontIndirectW(&ncm.lfMenuFont), old = (HFONT)SelectObject(dc, font);
    HBRUSH bg = CreateSolidBrush(sys_color(COLOR_MENU));
    SetBkMode(dc, TRANSPARENT);
    MENUBARINFO mb = { sizeof mb };
    if (GetMenuBarInfo(h, OBJID_MENU, 0, &mb)) OffsetRect(&mb.rcBar, -w.left, -w.top), FillRect(dc, &mb.rcBar, bg);   /* the bar in the box's MENU */
    for (int i = 0; i < n; i++) {
        wchar_t text[128];
        RECT r;
        MENUITEMINFOW mi = { sizeof mi, MIIM_STATE | MIIM_FTYPE };
        if (!GetMenuItemRect(h, m, (UINT)i, &r) || !GetMenuItemInfoW(m, (UINT)i, TRUE, &mi) || (mi.fType & (MFT_BITMAP | MFT_OWNERDRAW)) ||
            GetMenuStringW(m, (UINT)i, text, 128, MF_BYPOSITION) <= 0) continue;
        OffsetRect(&r, -w.left, -w.top);
        FillRect(dc, &r, bg);
        SetTextColor(dc, sys_color((mi.fState & MFS_DISABLED) ? COLOR_GRAYTEXT : COLOR_MENUTEXT));
        DrawTextW(dc, text, -1, &r, DT_SINGLELINE | DT_VCENTER | DT_CENTER | DT_HIDEPREFIX);
    }
    DeleteObject(bg);
    SelectObject(dc, old);
    DeleteObject(font);
    ReleaseDC(h, dc);
}
/* NtUserCalcMenuBar(hwnd, xLeft, xRight, yTop, RECT* window) and
 * NtUserPaintMenuBar(hwnd, hdc, xLeft, xRight, yTop, fActive): XP's uxtheme
 * lays out and paints a themed frame's menu bar through win32k; the menus are
 * the host's, drawn here: one row, each item's text in the menu font on
 * COLOR_MENUBAR, its height the answer. ponytail: no wrapping, no bitmaps,
 * no hot item (the host tracks the menu) */
static int menubar(HWND h, HDC dc, int left, int right, int top) {
    HMENU m = GetMenu(h);
    RECT w;
    int n = m ? GetMenuItemCount(m) : 0, cy = GetSystemMetrics(SM_CYMENU);
    if (n <= 0 || !GetWindowRect(h, &w)) return 0;
    if (!dc) return cy;
    NONCLIENTMETRICSW ncm = { sizeof ncm };
    SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof ncm, &ncm, 0);
    HFONT font = CreateFontIndirectW(&ncm.lfMenuFont), old = (HFONT)SelectObject(dc, font);
    HBRUSH bg = CreateSolidBrush(sys_color(COLOR_MENUBAR));
    RECT bar = { left, top, w.right - w.left - right, top + cy };
    FillRect(dc, &bar, bg);
    SetBkMode(dc, TRANSPARENT);
    for (int i = 0, x = left; i < n; i++) {
        wchar_t text[128];
        RECT r = { 0, 0, 0, 0 };
        MENUITEMINFOW mi = { sizeof mi, MIIM_STATE | MIIM_FTYPE };
        if (!GetMenuItemInfoW(m, (UINT)i, TRUE, &mi) || (mi.fType & (MFT_BITMAP | MFT_OWNERDRAW)) ||
            GetMenuStringW(m, (UINT)i, text, 128, MF_BYPOSITION) <= 0) continue;
        DrawTextW(dc, text, -1, &r, DT_SINGLELINE | DT_CALCRECT | DT_HIDEPREFIX);
        RECT t = { x, top, x + r.right + 12, top + cy };
        SetTextColor(dc, sys_color((mi.fState & MFS_DISABLED) ? COLOR_GRAYTEXT : COLOR_MENUTEXT));
        DrawTextW(dc, text, -1, &t, DT_SINGLELINE | DT_VCENTER | DT_CENTER | DT_HIDEPREFIX);
        x = t.right;
    }
    DeleteObject(bg);
    SelectObject(dc, old);
    DeleteObject(font);
    return cy;
}
static uint32_t s_calcmenubar(uint32_t* a) { return (uint32_t)menubar((HWND)(uintptr_t)a[0], NULL, (int)a[1], (int)a[2], (int)a[3]); }
static uint32_t s_paintmenubar(uint32_t* a) {
    HDC dc = (HDC)(uintptr_t)(native32_gdi_host(a[1]) ? native32_gdi_host(a[1]) : a[1]);
    return (uint32_t)menubar((HWND)(uintptr_t)a[0], dc, (int)a[2], (int)a[3], (int)a[4]);
}
static void screen_caption(HWND h) {
    /* XP's visual style draws a guest window's frame (uxtheme's hooks); a host-class one
     * (the Run dialog's #32770) keeps the host's classic frame, its caption in the box's colours */
    if (native32_themed && class_proc(h)) return;
    if (!g_screen || GetAncestor(h, GA_PARENT) != g_screen || (GetWindowLongW(h, GWL_STYLE) & WS_CAPTION) != WS_CAPTION) return;
    HWND top = GetWindow(g_screen, GW_CHILD);
    while (top && (!IsWindowVisible(top) || (GetWindowLongW(top, GWL_STYLE) & WS_CAPTION) != WS_CAPTION)) top = GetWindow(top, GW_HWNDNEXT);
    screen_menubar(h);
    if (top != h) return;
    TITLEBARINFOEX t = { sizeof t };
    RECT w;
    if (!SendMessageW(h, WM_GETTITLEBARINFOEX, 0, (LPARAM)&t) || !GetWindowRect(h, &w)) return;
    RECT r = t.rcTitleBar;
    r.left = w.left + (r.top - w.top);                 /* rcTitleBar leaves out the window menu: from the border (as thick as the top) */
    for (int i = 2; i <= 5; i++)                       /* minimize, maximize, help, close */
        if (!(t.rgstate[i] & (STATE_SYSTEM_INVISIBLE | STATE_SYSTEM_OFFSCREEN)) && t.rgrect[i].right > t.rgrect[i].left &&
            t.rgrect[i].left < r.right) r.right = t.rgrect[i].left - 2;
    if (r.right <= r.left) return;
    OffsetRect(&r, -w.left, -w.top);
    HDC dc = GetWindowDC(h);
    if (!dc) return;
    /* in the box's colours (DrawCaption takes the host's): the gradient, the small icon, the bold title */
    COLORREF c1 = sys_color(COLOR_ACTIVECAPTION), c2 = sys_color(COLOR_GRADIENTACTIVECAPTION);
    int wd = r.right - r.left, ht = r.bottom - r.top, x = r.left + 2;
    for (int i = 0; i < wd; i++) {
        RECT l = { r.left + i, r.top, r.left + i + 1, r.bottom };
        HBRUSH b = CreateSolidBrush(RGB(GetRValue(c1) + (GetRValue(c2) - GetRValue(c1)) * i / wd,
                                        GetGValue(c1) + (GetGValue(c2) - GetGValue(c1)) * i / wd,
                                        GetBValue(c1) + (GetBValue(c2) - GetBValue(c1)) * i / wd));
        FillRect(dc, &l, b);
        DeleteObject(b);
    }
    if (GetWindowLongW(h, GWL_STYLE) & WS_SYSMENU) {
        HICON ic = (HICON)SendMessageW(h, WM_GETICON, ICON_SMALL, 0);
        if (!ic) ic = (HICON)GetClassLongPtrW(h, GCLP_HICONSM);
        if (!ic) ic = (HICON)SendMessageW(h, WM_GETICON, ICON_BIG, 0);
        if (ic) DrawIconEx(dc, x, r.top + (ht - 16) / 2, ic, 16, 16, 0, NULL, DI_NORMAL), x += 18;
    }
    wchar_t text[256];
    int n = GetWindowTextW(h, text, 256);
    HFONT font = CreateFontW(-11, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, 0, 0, L"Tahoma"), old = (HFONT)SelectObject(dc, font);
    RECT tr = { x, r.top, r.right - 2, r.bottom };
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, sys_color(COLOR_CAPTIONTEXT));
    DrawTextW(dc, text, n, &tr, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
    SelectObject(dc, old);
    DeleteObject(font);
    ReleaseDC(h, dc);
}

/* NtUserMessageCall(hwnd, msg, wParam, lParam, xParam, fnid, bAnsi): the
 * kernel half of a message function, by fnid. 0x29E (FNID_DEFWINDOWPROC) is
 * DefWindowProc's: the host's. */
static uint32_t s_message_call(uint32_t* a) {
    HWND h = (HWND)(uintptr_t)a[0];
    a[5] = nt_fnid(native32_guest_peb, a[5]);   /* (XP: its FNIDs, as 2000's) */
    /* a DC the guest got in the message (WM_ERASEBKGND, WM_CTLCOLOR*, ...)
     * goes back to the host as the host's */
    if (a[2] && ((a[2] >> 16) & 0x1F) == 1 && native32_gdi_host(a[2])) a[2] = native32_gdi_host(a[2]);
    /* a GDI object in wParam (WM_SETFONT's font) goes to the host as the host's */
    if (a[2] && native32_gdi_host(a[2])) a[2] = native32_gdi_host(a[2]);
    /* BM_SETIMAGE / STM_SETIMAGE's bitmap in lParam (the Start button's logo
     * and text are one bitmap on the host's Button); the old one comes back
     * as the guest's */
    int img = (a[1] == BM_SETIMAGE || a[1] == STM_SETIMAGE) && a[2] == IMAGE_BITMAP;
    if (img && a[3] && native32_gdi_host(a[3])) a[3] = native32_gdi_host(a[3]);
    if (a[5] == 0x2AE) {                   /* SendMessage */
        LRESULT r = a[6] ? SendMessageA(h, a[1], a[2], a[3]) : SendMessageW(h, a[1], a[2], a[3]);
        if ((img || ((a[1] == BM_GETIMAGE || a[1] == STM_GETIMAGE) && a[2] == IMAGE_BITMAP)) && r)
            return native32_gdi_handle((uint32_t)r);
        return (uint32_t)(a[1] == WM_GETFONT && r ? native32_gdi_handle((uint32_t)r) : r);
    }
    if (a[5] == 0x29E && a[1] == WM_NCCALCSIZE && native32_themed && a[3] && g_screen && GetAncestor(h, GA_PARENT) == g_screen) {
        xp_ncrect(h, (RECT*)(uintptr_t)a[3]);
        return 0;
    }
    if (a[5] == 0x29E) {
        LRESULT r = a[6] ? DefWindowProcA(h, a[1], a[2], a[3]) : DefWindowProcW(h, a[1], a[2], a[3]);
        if (a[1] == WM_NCPAINT || a[1] == WM_NCACTIVATE || a[1] == WM_SETTEXT) screen_caption(h);
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
 * wID, +0xC spSubMenu, +0x18 lpstr, +0x1C cch, +0x20 dwItemData. Kept after
 * every call that changes a menu. GetMenuItemInfo/GetMenuString read the text
 * here: without it the Start menu's menuband items had none.
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
        MENUITEMINFOW mi = { sizeof mi, MIIM_FTYPE | MIIM_STATE | MIIM_ID | MIIM_SUBMENU | MIIM_DATA | MIIM_STRING };
        uint32_t str = *(uint32_t*)(it + 0x18), cap = *(uint32_t*)(it + 0x1C);   /* reused when the text fits */
        memset(it, 0, 0x4C);
        if (!GetMenuItemInfoW(m, i, TRUE, &mi)) continue;
        if (mi.cch) {
            if (mi.cch > cap || !str) str = (uint32_t)(uintptr_t)desk_alloc(2 * (mi.cch + 1));
            mi.dwTypeData = (LPWSTR)(uintptr_t)str, mi.cch++, mi.fMask = MIIM_STRING;
            if (str && GetMenuItemInfoW(m, i, TRUE, &mi)) *(uint32_t*)(it + 0x18) = str, *(uint32_t*)(it + 0x1C) = mi.cch;
            mi.fMask = MIIM_FTYPE | MIIM_STATE | MIIM_ID | MIIM_SUBMENU | MIIM_DATA;
            GetMenuItemInfoW(m, i, TRUE, &mi);
        }
        *(uint32_t*)(it + 0x20) = (uint32_t)mi.dwItemData;
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
    a[0] = nt_routine(native32_guest_peb, a[0]);   /* (XP: its routine numbers, as 2000's) */
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
    uint32_t own = a[1];
    /* XP's 0x26: GetCursorPos(POINT*), a service of its own on 2000; on the
     * virtual screen, in its coordinates (the guest's windows are its children) */
    if (nt_guest_xp(native32_guest_peb) && own == 0x26) {
        POINT p;
        if (!GetCursorPos(&p)) return 0;
        if (g_screen) ScreenToClient(g_screen, &p);
        MEM32(a[0]) = (uint32_t)p.x, MEM32(a[0] + 4) = (uint32_t)p.y;
        return 1;
    }
    a[1] = nt_routine(native32_guest_peb, a[1]);   /* (XP: its routine numbers, as 2000's) */
    if (a[1] == 0x19) return cur_new();
    if (a[1] == 0x18) return 1;   /* AllowSetForegroundWindow(pid): the guest's own, never the host's */
    if (a[1] == 0x21) return 1;   /* LockSetForegroundWindow: the guest's own, never the host's */
    if (a[1] == 0x16) return (uint32_t)(uintptr_t)BeginDeferWindowPos((int)a[0]);
    /* 0x24 MessageBeep, 0x26 PostQuitMessage, 0x2D ShowCursor, 0x33
     * GetProcessDefaultLayout (param: the DWORD* it fills) */
    if (a[1] == 0x24) return getenv("PCRECOMP_MUTE") ? 1 : MessageBeep(a[0]);   /* (muted runs stay silent) */
    /* 0x25 PlayEventSound(USER_SOUND_*): a message box's sound. ponytail: silent */
    if (a[1] == 0x25) return 1;
    if (a[1] == 0x26) { PostQuitMessage((int)a[0]); return 1; }
    if (a[1] == 0x2D) return (uint32_t)ShowCursor(a[0]);
    if (a[1] == 0x1E) return (uint32_t)(uintptr_t)GetKeyboardLayout(0);   /* (a guest tid: this thread's) */
    if (a[1] == 0x33) { DWORD l = 0; GetProcessDefaultLayout(&l); if (a[0]) MEM32(a[0]) = l; return 1; }
    if (a[1] == 0x29) {
        uint32_t h = native32_gdi_host(a[0]);
        return ReleaseDC(NULL, (HDC)(uintptr_t)(h ? h : a[0]));
    }
    fprintf(stderr, "[user] NtUserCallOneParam(%08X, 0x%X; the guest's 0x%X) not answered\n", a[0], a[1], own);
    return 0;
}

/* NtUserThunkedMenuItemInfo(hmenu, item, fByPosition, fInsert, MENUITEMINFOW*,
 * UNICODE_STRING* text) */
static uint32_t s_menu_item(uint32_t* a) {
    MENUITEMINFOW mi = *(MENUITEMINFOW*)(uintptr_t)a[4];
    mi.cbSize = sizeof mi;
    if (a[5] && MEM32(a[5] + 4)) mi.dwTypeData = (LPWSTR)(uintptr_t)MEM32(a[5] + 4), mi.cch = MEM16(a[5]) / 2;
    /* MIIM_TYPE with MIIM_FTYPE/STRING/BITMAP (shell32's Shell_MergeMenus copies an item
     * with every bit, 0x1FF): Windows 2000 took it, the host answers ERROR_INVALID_PARAMETER
     * (Control Panel's context menu was empty: a double-click on an applet opened nothing).
     * The newer bits say the same thing */
    if ((mi.fMask & MIIM_TYPE) && (mi.fMask & (MIIM_FTYPE | MIIM_STRING | MIIM_BITMAP))) mi.fMask &= ~MIIM_TYPE;
    BOOL r = a[3] ? InsertMenuItemW((HMENU)(uintptr_t)a[0], a[1], a[2], &mi)
                  : SetMenuItemInfoW((HMENU)(uintptr_t)a[0], a[1], a[2], &mi);
    if (!r) fprintf(stderr, "[user] %sMenuItem(%08X, %u, %u) failed: %lu (mask %X type %X)\n", a[3] ? "Insert" : "Set", a[0], a[1], a[2],
                    GetLastError(), mi.fMask, mi.fType);
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
/* NtUserRemoveMenu / NtUserDeleteMenu(hmenu, item, flags): explorer takes the
 * Start menu out of its LoadMenu bar with RemoveMenu before DestroyMenu(bar);
 * unanswered, the bar's destroy took the Start menu with it */
static uint32_t s_remove_menu(uint32_t* a) {
    BOOL r = RemoveMenu((HMENU)(uintptr_t)a[0], a[1], a[2]);
    menu_sync((HMENU)(uintptr_t)a[0]);
    return r;
}
static uint32_t s_delete_menu(uint32_t* a) {
    BOOL r = DeleteMenu((HMENU)(uintptr_t)a[0], a[1], a[2]);
    menu_sync((HMENU)(uintptr_t)a[0]);
    return r;
}

/* NtUserSetMenuDefaultItem(hmenu, item, fByPos): GetMenuDefaultItem is
 * client-side (MFS_DEFAULT in the synced items); unanswered, a context menu
 * had no default verb and a desktop double-click opened nothing */
static uint32_t s_menu_default(uint32_t* a) {
    BOOL r = SetMenuDefaultItem((HMENU)(uintptr_t)a[0], a[1], a[2]);
    menu_sync((HMENU)(uintptr_t)a[0]);
    return r;
}

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
    a[2] = nt_routine(native32_guest_peb, a[2]);   /* (XP: its routine numbers, as 2000's) */
    if (a[2] == 0x53) return EnableWindow((HWND)(uintptr_t)a[0], a[1]);
    fprintf(stderr, "[user] NtUserCallHwndParamLock index 0x%X not answered\n", a[2]);
    return 0;
}

/* NtUserCallHwndParam(hwnd, param, index): 0x43 attaches a dialog's DIALOG
 * structure: WND+0x9C, and WND+0x16 bit 0 says it is there */
static uint32_t s_hwnd_param(uint32_t* a) {
    a[2] = nt_routine(native32_guest_peb, a[2]);   /* (XP: its routine numbers, as 2000's) */
    uint8_t* w = native32_user_wnd((void*)(uintptr_t)a[0]);
    if (a[2] == 0x43 && w) {
        /* the window procedure becomes Windows 2000's own DefDlgProcW (its
         * apfnClientW dialog procedure): it keeps the dialog in that DIALOG
         * and calls the guest's dialog procedure, which the host's
         * DefDlgProc knows nothing of */
        static uint32_t ddp;
        if (!ddp) ddp = native32_export(native32_module("user32.dll"), "DefDlgProcW");
        *(uint32_t*)(w + WO(0x9C)) = a[1];
        w[0x16] |= 1;
        /* (a dialog of the guest's own class, calc's SciCalc, keeps its
         * procedure: that calls DefDlgProc itself) */
        if (ddp && !class_proc((HWND)(uintptr_t)a[0])) {
            SetWindowLongPtrW((HWND)(uintptr_t)a[0], GWLP_WNDPROC, (LONG_PTR)wnd_thunk);
            *(uint32_t*)(w + WO(0x5C)) = ddp;
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
    if (w) *(uint16_t*)(w + WO(0x2A)) = (uint16_t)a[1];
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
/* NtUserGetAtomName(atom, UNICODE_STRING* name): a name in USER's atom table
 * (window classes, registered messages, clipboard formats; XP's dialog
 * manager asks for its class's), from the host's, which is that table */
static uint32_t s_atom_name(uint32_t* a) {
    uint32_t us = a[1];
    if (!us || !MEM32(us + 4) || MEM16(us + 2) < 2) return 0;
    /* an integer atom (the dialog class's 0x8002) is named "#n", as win32k's are */
    int n = a[0] < 0xC000 ? _snwprintf((wchar_t*)(uintptr_t)MEM32(us + 4), MEM16(us + 2) / 2, L"#%u", a[0])
                          : GetClipboardFormatNameW(a[0], (LPWSTR)(uintptr_t)MEM32(us + 4), MEM16(us + 2) / 2);
    if (n > 0) MEM16(us) = (uint16_t)(2 * n);
    return n > 0 ? (uint32_t)n : 0;
}
/* NtUserSetWindowPos(hwnd, after, x, y, cx, cy, flags) */
static uint32_t s_setpos(uint32_t* a) {
    /* HWND_TOPMOST / NOTOPMOST on a window of the virtual screen (a host
     * child): the top of the screen's children (the Start menu's BaseBar) */
    if (g_screen && (a[1] == (uint32_t)-1 || a[1] == (uint32_t)-2) && GetAncestor((HWND)(uintptr_t)a[0], GA_PARENT) == g_screen)
        a[1] = a[1] == (uint32_t)-1 ? 0 : 1, a[6] |= a[1] ? SWP_NOZORDER : 0;
    if (!(a[6] & SWP_NOSIZE)) { int p = screen_pad((HWND)(uintptr_t)a[0]); a[4] += 2 * p, a[5] += 2 * p; }
    BOOL r = SetWindowPos((HWND)(uintptr_t)a[0], (HWND)(uintptr_t)a[1], (int)a[2], (int)a[3], (int)a[4], (int)a[5], a[6]);
    return r;
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
        old = *(uint32_t*)(w + WO(0x5C));
        if ((LONG_PTR)GetWindowLongPtrW(h, GWLP_WNDPROC) != (LONG_PTR)wnd_thunk)
            SetWindowLongPtrW(h, GWLP_WNDPROC, (LONG_PTR)wnd_thunk);
        *(uint32_t*)(w + WO(0x5C)) = a[2];
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
            uint32_t show = w && (v & WS_VISIBLE) && !(*(uint32_t*)(w + WO(0x20)) & WS_VISIBLE) ? WS_VISIBLE : 0;
            v = (v & ~WS_VISIBLE) | ((uint32_t)GetWindowLongW(h, GWL_STYLE) & WS_VISIBLE) | show;
        }
        old = (uint32_t)SetWindowLongW(h, (int)a[1], (LONG)v);
        if (w) *(uint32_t*)(w + ((int)a[1] == GWL_STYLE ? 0x20 : 0x1C)) = (uint32_t)GetWindowLongW(h, (int)a[1]);
        return old;
    }
    /* The window's extra bytes (index >= 0) are the WND's from +0x98, where
     * the guest's GetWindowLong reads them: RichEdit keeps its object at 0,
     * and without it every message it gets returns 0 (wordpad). A dialog
     * (WND+0x16 bit 0) reads DWL_USER from there too (+0xA0): the Run
     * dialog's RunDlgProc kept its data in it and faulted on 0. Its
     * DWL_DLGPROC (4) is not a plain slot and stays unanswered. */
    /* GWL_USERDATA is the WND's dwUserData (+0x94), read there by the guest's
     * GetWindowLong: MB_DlgProc keeps its MSGBOXDATA in it and faulted on 0
     * at OK (Display's "will now apply your new desktop settings") */
    if ((int)a[1] == GWLP_USERDATA) {
        uint8_t* w = native32_user_wnd(h);
        uint32_t old;
        if (!w) return 0;
        old = *(uint32_t*)(w + WO(0x94));
        *(uint32_t*)(w + WO(0x94)) = a[2];
        return old;
    }
    if ((int)a[1] >= 0) {
        uint8_t* w = native32_user_wnd(h);
        uint32_t old;
        if (!w || ((w[0x16] & 1) && a[1] != DWLP_USER) || a[1] + 4 > *(uint32_t*)(w + WO(0x88)) || a[1] + 4 > 0x200 - WO(0x98)) return 0;
        old = *(uint32_t*)(w + WO(0x98) + a[1]);
        *(uint32_t*)(w + WO(0x98) + a[1]) = a[2];
        return old;
    }
    /* ponytail: other indexes unanswered (0), as before: forwarded to the
     * host they broke winmine's Custom dialog (a guest dialog's DWL_* live in
     * its own DIALOG, not the host window) */
    return 0;
}
/* NtUserCallHwndLock(hwnd, index): 0x48 DrawMenuBar, 0x50 UpdateWindow */
static uint32_t s_hwnd_lock(uint32_t* a) {
    a[1] = nt_routine(native32_guest_peb, a[1]);   /* (XP: its routine numbers, as 2000's) */
    if (a[1] == 0x48) return DrawMenuBar((HWND)(uintptr_t)a[0]);
    if (a[1] == 0x50) return UpdateWindow((HWND)(uintptr_t)a[0]);
    /* 0x4D SetForegroundWindow: inside the virtual screen it activates the window, never the host's foreground
     * (another program on the screen, as a taskbar button raises it: the top of the screen) */
    if (a[1] == 0x4D && g_screen && !own_window(a[0]) && GetAncestor((HWND)(uintptr_t)a[0], GA_PARENT) == g_screen)
        return SetWindowPos((HWND)(uintptr_t)a[0], HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    if (a[1] == 0x4D) { if (!own_window(a[0])) return 0; SetActiveWindow((HWND)(uintptr_t)a[0]); return 1; }
    /* 0x4C: a new dialog with WS_SYSMENU and no size/min/max box has its
     * system menu trimmed (user32's dialog creation); the host made its own */
    if (a[1] == 0x4C) return 1;
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
/* NtUserDrawCaptionTemp(hwnd, hdc, RECT*, hfont, hicon, UNICODE_STRING* text,
 * flags): the host's DrawCaptionTempW. explorer draws the Start button's logo
 * and "Start" with it (DC_INBUTTON | DC_ICON | DC_TEXT) into the button's
 * bitmap; unanswered, the bitmap stayed black. A string with no buffer is
 * the window's own title (the taskbar's buttons: winmine's had none). */
static uint32_t s_drawcaptiontemp(uint32_t* a) {
    typedef BOOL (WINAPI *dct_t)(HWND, HDC, const RECT*, HFONT, HICON, LPCWSTR, UINT);
    static dct_t dct;
    uint32_t dc = native32_gdi_host(a[1]), f = a[3] ? native32_gdi_host(a[3]) : 0;
    wchar_t text[256] = { 0 };
    if (!dct) dct = (dct_t)GetProcAddress(GetModuleHandleA("user32.dll"), "DrawCaptionTempW");
    if (a[5] && MEM32(a[5] + 4)) wcsncpy(text, (const wchar_t*)(uintptr_t)MEM32(a[5] + 4), min(MEM16(a[5]) / 2, 255));
    return dct && dct((HWND)(uintptr_t)a[0], (HDC)(uintptr_t)(dc ? dc : a[1]), (const RECT*)(uintptr_t)a[2],
                      (HFONT)(uintptr_t)(f ? f : a[3]), (HICON)(uintptr_t)cur_host(a[4]), a[5] && MEM32(a[5] + 4) ? text : NULL, a[6]);
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
static uint32_t s_getprop(uint32_t* a) { return (uint32_t)(uintptr_t)GetPropW((HWND)(uintptr_t)a[0], MAKEINTATOM(a[1])); }
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
/* GetThreadState: focus (0), active (1), capture (2) are the host's per-thread answers (guest HWNDs are host HWNDs) */
static uint32_t s_thread_state(uint32_t* a) {
    switch (a[0]) {
    case 0: return (uint32_t)(uintptr_t)GetFocus();
    case 1: return (uint32_t)(uintptr_t)GetActiveWindow();
    case 2: return (uint32_t)(uintptr_t)GetCapture();
    case 0x11: return 1;
    }
    return 0;
}
/* ponytail: a guest that resizes from its own GetWindowRect grows by the pad each time; none on the screen does yet */
static uint32_t s_move(uint32_t* a) {
    int p = screen_pad(HW(a[0]));
    return MoveWindow(HW(a[0]), (int)a[1], (int)a[2], (int)a[3] + 2 * p, (int)a[4] + 2 * p, a[5]);
}
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
        { "NtUserRemoveMenu", s_remove_menu }, { "NtUserDeleteMenu", s_delete_menu }, { "NtUserSetMenuDefaultItem", s_menu_default },
        { "NtUserCheckMenuItem", s_check_menu }, { "NtUserEnableMenuItem", s_enable_menu },
        { "NtUserGetMenuItemRect", s_menu_rect }, { "NtUserFindExistingCursorIcon", s_find_icon }, { "NtUserSetCursorIconData", s_set_cursor_data },
        { "NtUserDrawCaptionTemp", s_drawcaptiontemp }, { "NtUserSetWindowsHookEx", s_sethook }, { "NtUserCallNextHookEx", s_nexthook }, { "NtUserUnhookWindowsHookEx", s_unhook },
        { "NtUserDestroyCursor", s_destroy_cursor }, { "NtUserGetIconSize", s_get_icon_size }, { "NtUserGetIconInfo", s_get_icon_info }, { "NtUserDrawIconEx", s_drawiconex }, { "NtUserDeferWindowPos", s_deferpos }, { "NtUserEndDeferWindowPosEx", s_enddeferpos },
        { "NtUserSetProp", s_setprop }, { "NtUserSelectPalette", s_selectpal }, { "NtUserSetParent", s_setparent }, { "NtUserSetScrollInfo", s_setscroll },
        { "NtUserWindowFromPoint", s_frompoint }, { "NtUserSetActiveWindow", s_setactive }, { "NtUserRemoveProp", s_removeprop }, { "NtUserSetWindowPlacement", s_setplacement }, { "NtUserGetWindowPlacement", s_getplacement }, { "NtUserGetClassInfo", s_classinfo },
        { "NtUserSetCursor", s_setcursor }, { "NtUserSetTimer", s_settimer }, { "NtUserKillTimer", s_killtimer },
        { "NtUserCallHwndParamLock", s_hwnd_param_lock }, { "NtUserCallHwndParam", s_hwnd_param },
        { "NtUserDestroyWindow", s_destroy }, { "NtUserSetWindowFNID", s_set_fnid }, { "NtUserSetFocus", s_setfocus },
        { "NtUserQueryWindow", s_query_window }, { "NtUserFillWindow", s_fill_window }, { "NtUserSetCapture", s_setcapture },
        { "NtUserWaitMessage", s_waitmessage }, { "NtUserRegisterWindowMessage", s_register_msg }, { "NtUserGetAtomName", s_atom_name }, { "NtUserCallHwndLock", s_hwnd_lock }, { "NtUserSetWindowLong", s_setlong },
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
    {   /* NT 6's: user32 connects to win32k itself, NtUserGetClassInfo is
         * ...Ex (the same arguments), and GetProp asks win32k (2000/XP: client-side) */
        static const struct { const char* name; native32_syscall_fn fn; } v6[] = {
            { "NtUserProcessConnect", native32_user_process_connect }, { "NtUserGetClassInfoEx", s_classinfo },
            { "NtUserGetProp", s_getprop } };
        for (int i = 0; i < (int)(sizeof v6 / sizeof v6[0]); i++)
            if (native32_nt_win32k_has(v6[i].name) && native32_nt_win32k_has("NtUserGetWindowMinimizeRect"))   /* (a Vista table) */
                native32_nt_win32k_override(v6[i].name, v6[i].fn);
    }
    native32_nt_win32k_override("NtUserGetDC", s_getdc);
    native32_nt_win32k_override("NtUserGetDCEx", s_getdcex);
    native32_nt_win32k_override("NtUserGetWindowDC", s_getwindowdc);
    native32_nt_win32k_override("NtUserSystemParametersInfo", s_spi);
    native32_nt_win32k_override("NtUserPaintDesktop", s_paintdesktop);
    native32_nt_win32k_override("NtUserBuildNameList", s_namelist);
    native32_nt_win32k_override("NtUserPostMessage", s_post);
    native32_nt_win32k_override("NtUserValidateTimerCallback", s_validate_timer);
    native32_nt_win32k_override("NtUserEnableScrollBar", s_enable_sb);
    native32_nt_win32k_override("NtUserFindWindowEx", s_findwindow);
    native32_nt_win32k_override("NtUserModifyUserStartupInfoFlags", s_one_u);
    native32_nt_win32k_override("NtUserRegisterHotKey", s_one_u);
    native32_nt_win32k_override("NtUserUnregisterHotKey", s_one_u);
    native32_nt_win32k_override("NtUserSetShellWindowEx", s_set_shell);
    native32_nt_win32k_override("NtUserSendNotifyMessage", s_send_notify);
    native32_nt_win32k_override("NtUserSendMessageCallback", s_send_callback);
    native32_nt_win32k_override("NtUserChangeDisplaySettings", s_change_display);
    native32_nt_win32k_override("NtUserEnumDisplayDevices", s_enum_devices);
    native32_nt_win32k_override("NtUserEnumDisplaySettings", s_enum_settings);
    native32_nt_win32k_override("NtUserPostThreadMessage", s_post_thread);
    native32_nt_win32k_override("NtUserCallHwnd", s_callhwnd);
    native32_nt_win32k_override("NtUserCallHwndOpt", s_callhwnd_opt);
    native32_nt_win32k_override("NtUserInternalGetWindowText", s_internal_text);
    native32_nt_win32k_override("NtUserGetClassName", s_classname);
    native32_nt_win32k_override("NtUserAttachThreadInput", s_attach_input);
    native32_nt_win32k_override("NtUserSetWindowRgn", s_setrgn);
    native32_nt_win32k_override("NtUserEnumDisplayMonitors", s_enum_monitors);
    native32_nt_win32k_override("NtUserGetDoubleClickTime", s_dblclick);
    native32_nt_win32k_override("NtUserGetKeyboardLayoutList", s_kblist);
    native32_nt_win32k_override("NtUserShowCaret", s_showcaret);
    native32_nt_win32k_override("NtUserHideCaret", s_hidecaret);
    native32_nt_win32k_override("NtUserGetThreadDesktop", s_threaddesk);
    native32_nt_win32k_override("NtUserGetProcessWindowStation", s_winsta);
    native32_nt_win32k_override("NtUserBuildHwndList", s_hwndlist);
    native32_nt_win32k_override("NtUserCalcMenuBar", s_calcmenubar);
    native32_nt_win32k_override("NtUserPaintMenuBar", s_paintmenubar);
    native32_nt_win32k_override("NtUserGetAncestor", s_ancestor);
    native32_nt_win32k_override("NtUserGetTitleBarInfo", s_titlebarinfo);
    native32_nt_win32k_override("NtUserGetGUIThreadInfo", s_guithreadinfo);
    native32_nt_win32k_override("NtUserGetObjectInformation", s_objinfo);
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

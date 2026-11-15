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
 * Messages: a class is registered with the host with the guest's window
 * procedure itself, so host user32 calls it through native32's trampoline.
 * ponytail: Windows 2000 sends them through KiUserCallbackDispatcher and
 * user32's __fn* routines (native32_nt_callback); that needs each routine's
 * message layout and is the next step.
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
static const wchar_t* lstr_name(uint32_t ls) { return ls < 0x10000 ? (const wchar_t*)(uintptr_t)ls : (const wchar_t*)(uintptr_t)MEM32(ls + 8); }

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
static struct { ATOM atom; uint32_t proc; } g_cls[MAX_CLASSES];
static int g_ncls;
static uint32_t class_proc(HWND h) {
    ATOM a = (ATOM)GetClassWord(h, GCW_ATOM);
    for (int i = 0; i < g_ncls; i++) if (g_cls[i].atom == a) return g_cls[i].proc;
    return 0;
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
    *(uint32_t*)(w + 0x30) = p && p != GetDesktopWindow() ? (uint32_t)(uintptr_t)native32_user_wnd(p) : 0;
    *(uint32_t*)(w + 0x38) = own ? (uint32_t)(uintptr_t)native32_user_wnd(own) : 0;
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
     * follow the WND at +0x9C (a dialog's: its DIALOG structure) */
    *(uint32_t*)(w + 0x88) = (uint32_t)GetClassLongW(h, GCL_CBWNDEXTRA);
    MEM32(e) = (uint32_t)(uintptr_t)w;
    MEM32(e + 4) = 0;
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
static void server_info(void) {
    static int done;
    uint8_t* psi = native32_user_psi;
    if (done || !psi) return;
    done = 1;
    for (int i = 0; i < 0x53; i++) *(int32_t*)(psi + 0x59C + 4 * i) = GetSystemMetrics(i);
    for (int i = 0; i < 0x1D; i++) *(uint32_t*)(psi + 0x6E8 + 4 * i) = GetSysColor(i);
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
    /* +0xE4A dmLogPixels: a dialog font's height is -MulDiv(points, it, 72) */
    {
        HDC s = GetDC(NULL);
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
        memcpy(mon + 0x10, &mi.rcMonitor, sizeof(RECT));
        memcpy(mon + 0x20, &mi.rcWork, sizeof(RECT));
        *(uint32_t*)(native32_user_disp + 0x2C) = 1;
        *(uint32_t*)(native32_user_disp + 0x30) = (uint32_t)(uintptr_t)mon;
        *(uint32_t*)(native32_user_disp + 0x34) = (uint32_t)(uintptr_t)mon;
    }
}

static void (*g_prev_pre)(void);
static void user_pre(void) {        /* before every win32k service */
    server_info();
    if (native32_user_ahe) { thread_setup(); wnd_sync_all(); }
    if (g_prev_pre) g_prev_pre();
}

static void (*g_prev_cb_in)(uint32_t* args);
static void cb_in(uint32_t* a) {             /* a window the guest is about to hear from */
    if (IsWindow((HWND)(uintptr_t)a[0])) native32_user_wnd((HWND)(uintptr_t)a[0]);
    if (native32_user_ahe) wnd_sync_all();
    if (g_prev_cb_in) g_prev_cb_in(a);
}

/* NtUserRegisterClassExWOW(WNDCLASSEXW*, PUNICODE_STRING class, CLSMENUNAME*,
 * WORD fnid, DWORD flags, DWORD* wow): the host class, with the guest's
 * window procedure and the host's background brush. */
static uint32_t s_register_class(uint32_t* a) {
    WNDCLASSEXW w = *(WNDCLASSEXW*)(uintptr_t)a[0];
    w.cbSize = sizeof w;
    w.lpszClassName = ustr_name(a[1]);
    if (a[2]) w.lpszMenuName = (LPCWSTR)(uintptr_t)MEM32(a[2] + 4);   /* pwszClientUnicodeMenuName */
    if ((uintptr_t)w.hbrBackground > 0x40 && native32_gdi_host((uint32_t)(uintptr_t)w.hbrBackground))
        w.hbrBackground = (HBRUSH)(uintptr_t)native32_gdi_host((uint32_t)(uintptr_t)w.hbrBackground);
    if (getenv("NATIVE32_SYSCALLS"))
        fprintf(stderr, "[user] class background %p (guest %08X)\n", w.hbrBackground, ((WNDCLASSEXW*)(uintptr_t)a[0])->hbrBackground);
    uint32_t guest_proc = (uint32_t)(uintptr_t)w.lpfnWndProc;
    w.lpfnWndProc = wnd_thunk;
    ATOM r = RegisterClassExW(&w);
    if (r && g_ncls < MAX_CLASSES) g_cls[g_ncls].atom = r, g_cls[g_ncls++].proc = guest_proc;
    if (!r) fprintf(stderr, "[user] RegisterClassExW %ls failed: %lu\n",
                    (uintptr_t)w.lpszClassName < 0x10000 ? L"(atom)" : w.lpszClassName, GetLastError());
    return r;
}

/* ---- messages: win32k's callback ------------------------------------------
 * A message the host sends a guest window reaches its procedure the way
 * Windows 2000's win32k delivers it: KeUserModeCallback(__fnDWORD, FNDWORDMSG
 * { pwnd, msg, wParam, lParam, xParam = the procedure, xpfnProc =
 * DispatchClientMessage }) through the guest ntdll's KiUserCallbackDispatcher
 * and user32's own __fnDWORD (KernelCallbackTable[2]), which returns the
 * result with NtCallbackReturn. DispatchClientMessage(pwnd, msg, w, l, pfn)
 * takes the HWND from CLIENTINFO's CallbackWnd (TEB+0x6F4), set first.
 * ponytail: every message through the generic DWORD layout; win32k's
 * per-message ones (__fnINLPCREATESTRUCT, __fnINSTRING, ...) copy and convert
 * A/W, which a flat in-process address space does not need yet. */
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
static LRESULT CALLBACK wnd_thunk(HWND h, UINT m, WPARAM w, LPARAM l) {
    uint8_t* pw = native32_user_wnd(h);
    uint32_t pfn = pw ? *(uint32_t*)(pw + 0x5C) : 0, args[4] = { (uint32_t)(uintptr_t)h, m, (uint32_t)w, (uint32_t)l };
    uint32_t teb, oh, op, out = 0, outlen = 0, r = 0;
    if (!g_dcm && (g_dcm = find_dcm()) != 0 && getenv("NATIVE32_SYSCALLS"))
        fprintf(stderr, "[user] messages through KiUserCallbackDispatcher, DispatchClientMessage %08X\n", g_dcm);
    if (!pfn || !g_dcm) return DefWindowProcW(h, m, w, l);
    if (native32_cb_in) native32_cb_in(args);   /* (as the bridge would: the WND, GDI handles) */
    teb = MEM32(g_fs_base + 0x18), oh = MEM32(teb + 0x6F4), op = MEM32(teb + 0x6F8);
    MEM32(teb + 0x6F4) = args[0], MEM32(teb + 0x6F8) = (uint32_t)(uintptr_t)pw;
    {
        uint32_t msg[6] = { (uint32_t)(uintptr_t)pw, args[1], args[2], args[3], pfn, g_dcm };
        uint32_t st = native32_nt_callback(2, (uint32_t)(uintptr_t)msg, sizeof msg, &out, &outlen);
        if (st == 0 && out && outlen >= 4) r = MEM32(out);
        else if (st) fprintf(stderr, "[user] callback for message 0x%X: status %08X\n", m, st);
    }
    MEM32(teb + 0x6F4) = oh, MEM32(teb + 0x6F8) = op;
    if (native32_cb_out) native32_cb_out(args, &r);
    return (LRESULT)r;
}

/* NtUserCreateWindowEx(exstyle, LARGE_STRING* class, LARGE_STRING* name, style,
 * x, y, cx, cy, parent, menu, hInstance, lpParam, flags) */
static uint32_t s_create_window(uint32_t* a) {
    /* A top-level frame: Windows 2000 sized it with its own borders (one
     * SM_CXBORDER each for WS_EX_WINDOWEDGE x2 and a caption or modal frame,
     * GetWindowBorders); the host's frame is thicker (padded borders). The
     * client area is what the guest meant, so the difference goes on. */
    int cx = (int)a[6], cy = (int)a[7];
    if (!(a[3] & WS_CHILD) && cx > 0 && cy > 0 && cx != CW_USEDEFAULT) {
        int b = (a[0] & WS_EX_WINDOWEDGE) ? 2 : (a[0] & WS_EX_STATICEDGE) ? 1 : 0;
        RECT r = { 0, 0, 0, 0 };
        if ((a[3] & WS_CAPTION) || (a[0] & WS_EX_DLGMODALFRAME)) b++;
        if (a[3] & WS_THICKFRAME) { UINT g = 1; SystemParametersInfoW(SPI_GETBORDER, 0, &g, 0); b += g; }
        if (a[0] & WS_EX_CLIENTEDGE) b += 2;
        b *= GetSystemMetrics(SM_CXBORDER);
        AdjustWindowRectEx(&r, a[3], FALSE, a[0]);
        if (-r.left > b) { cx += 2 * (-r.left - b); cy += 2 * (-r.left - b); }
    }
    HWND h = CreateWindowExW(a[0], lstr_name(a[1]), lstr_name(a[2]), a[3], (int)a[4], (int)a[5], cx, cy,
                             (HWND)(uintptr_t)a[8], (HMENU)(uintptr_t)a[9], (HINSTANCE)(uintptr_t)a[10],
                             (void*)(uintptr_t)a[11]);
    if (!h) fprintf(stderr, "[user] CreateWindowExW failed: %lu\n", GetLastError());
    /* a window of a host class (a dialog's #32770) never calls the guest
     * while it is made, so its WND is entered here */
    if (h) native32_user_wnd(h);
    return (uint32_t)(uintptr_t)h;
}
static uint32_t s_getdc(uint32_t* a) { return native32_gdi_handle((uint32_t)(uintptr_t)GetDC((HWND)(uintptr_t)a[0])); }
/* NtUserCreateAcceleratorTable(ACCEL*, count) */
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
    fprintf(stderr, "[user] NtUserCallNoParam %u not answered\n", a[0]);
    return 0;
}
/* NtUserCallOneParam(param, index): 0x29 ReleaseDC */
static uint32_t s_call_oneparam(uint32_t* a) {
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
static uint32_t s_setcursor(uint32_t* a) { return (uint32_t)(uintptr_t)SetCursor((HCURSOR)(uintptr_t)a[0]); }

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
        if (ddp) {
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

static uint32_t s_waitmessage(uint32_t* a) { (void)a; return WaitMessage(); }

#define HW(x) ((HWND)(uintptr_t)(x))
static uint32_t s_thread_state(uint32_t* a) { return a[0] == 0x11 ? 1 : 0; }
static uint32_t s_move(uint32_t* a) { return MoveWindow(HW(a[0]), (int)a[1], (int)a[2], (int)a[3], (int)a[4], a[5]); }
static uint32_t s_setmenu(uint32_t* a) { return SetMenu(HW(a[0]), (HMENU)(uintptr_t)a[1]); }
static uint32_t s_invalidate(uint32_t* a) { return InvalidateRect(HW(a[0]), (RECT*)(uintptr_t)a[1], a[2]); }
static uint32_t s_show(uint32_t* a) { return ShowWindow(HW(a[0]), (int)a[1]); }
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
        { "NtUserInvalidateRect", s_invalidate }, { "NtUserShowWindow", s_show },
        { "NtUserGetMessage", s_getmessage }, { "NtUserPeekMessage", s_peekmessage },
        { "NtUserTranslateMessage", s_translate }, { "NtUserDispatchMessage", s_dispatch },
        { "NtUserBeginPaint", s_beginpaint }, { "NtUserEndPaint", s_endpaint },
        { "NtUserThunkedMenuItemInfo", s_menu_item }, { "NtUserDestroyMenu", s_destroy_menu },
        { "NtUserCheckMenuItem", s_check_menu }, { "NtUserEnableMenuItem", s_enable_menu },
        { "NtUserGetMenuItemRect", s_menu_rect }, { "NtUserFindExistingCursorIcon", s_find_icon },
        { "NtUserSetCursor", s_setcursor }, { "NtUserSetTimer", s_settimer }, { "NtUserKillTimer", s_killtimer },
        { "NtUserCallHwndParamLock", s_hwnd_param_lock }, { "NtUserCallHwndParam", s_hwnd_param },
        { "NtUserDestroyWindow", s_destroy }, { "NtUserSetWindowFNID", s_set_fnid }, { "NtUserSetFocus", s_setfocus },
        { "NtUserQueryWindow", s_query_window }, { "NtUserFillWindow", s_fill_window }, { "NtUserSetCapture", s_setcapture },
        { "NtUserWaitMessage", s_waitmessage }, { "NtUserCallNoParam", s_call_noparam }, { "NtUserCallOneParam", s_call_oneparam },
    };
    for (int i = 0; i < (int)(sizeof svc / sizeof svc[0]); i++) native32_nt_win32k_override(svc[i].name, svc[i].fn);
    (void)s_update;
    g_prev_pre = native32_win32k_pre;
    native32_win32k_pre = user_pre;
    native32_nt_win32k_override("NtUserMessageCall", s_message_call);
    g_prev_cb_in = native32_cb_in;
    native32_cb_in = cb_in;
    native32_nt_win32k_override("NtUserCreateWindowEx", s_create_window);
    native32_nt_win32k_override("NtUserGetDC", s_getdc);
    native32_nt_win32k_override("NtUserCreateAcceleratorTable", s_accel);
    native32_nt_win32k_override("NtUserRegisterClassExWOW", s_register_class);
}

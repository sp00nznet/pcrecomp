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
static const wchar_t* lstr_name(uint32_t ls) { return ls ? (const wchar_t*)(uintptr_t)MEM32(ls + 8) : NULL; }

/* ---- the desktop heap, CLIENTINFO and the handle table -------------------
 * user32's ValidateHwnd: index = LOWORD(h) < psi->cHandleEntries (+8);
 * aheList entry (12 bytes) { phead, pOwner, bType (+8, 1 a window), bFlags
 * (+9, bit 0 destroyed), wUniq (+0xA) = HIWORD(h) }; then phead must lie in
 * the thread's desktop (CLIENTINFO at TEB+0x6CC: +0x18 pDeskInfo -> { base,
 * limit }) and the WND user32 reads is phead - CLIENTINFO+0x1C (the client
 * delta, 0 here: the heap is ours). A host HWND's own index and uniq are
 * used as they are. WND, Windows 2000 SP4: +0x00 hwnd (THRDESKHEAD.h),
 * +0x10 pSelf. */
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
    }
}

static uint8_t* desk_alloc(uint32_t n) {
    uint8_t* p = g_desk + g_desk_top;
    g_desk_top += (n + 15) & ~15u;
    return g_desk_top <= DESK_SIZE ? p : NULL;
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
    MEM32(e) = (uint32_t)(uintptr_t)w;
    MEM32(e + 4) = 0;
    MEM8(e + 8) = 1;                                                            /* TYPE_WINDOW */
    MEM8(e + 9) = 0;
    MEM16(e + 0xA) = (uint16_t)((uint32_t)(uintptr_t)h >> 16);
    return w;
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
}

static void (*g_prev_pre)(void);
static void user_pre(void) {        /* before every win32k service */
    server_info();
    if (native32_user_ahe) thread_setup();
    if (g_prev_pre) g_prev_pre();
}

static void (*g_prev_cb_in)(uint32_t* args);
static void cb_in(uint32_t* a) {             /* a window the guest is about to hear from */
    if (IsWindow((HWND)(uintptr_t)a[0])) native32_user_wnd((HWND)(uintptr_t)a[0]);
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
    ATOM r = RegisterClassExW(&w);
    if (!r) fprintf(stderr, "[user] RegisterClassExW %ls failed: %lu\n",
                    (uintptr_t)w.lpszClassName < 0x10000 ? L"(atom)" : w.lpszClassName, GetLastError());
    return r;
}

/* NtUserCreateWindowEx(exstyle, LARGE_STRING* class, LARGE_STRING* name, style,
 * x, y, cx, cy, parent, menu, hInstance, lpParam, flags) */
static uint32_t s_create_window(uint32_t* a) {
    HWND h = CreateWindowExW(a[0], lstr_name(a[1]), lstr_name(a[2]), a[3], (int)a[4], (int)a[5], (int)a[6], (int)a[7],
                             (HWND)(uintptr_t)a[8], (HMENU)(uintptr_t)a[9], (HINSTANCE)(uintptr_t)a[10],
                             (void*)(uintptr_t)a[11]);
    if (!h) fprintf(stderr, "[user] CreateWindowExW failed: %lu\n", GetLastError());
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
    if (a[5] == 0x29E) return (uint32_t)(a[6] ? DefWindowProcA(h, a[1], a[2], a[3]) : DefWindowProcW(h, a[1], a[2], a[3]));
    fprintf(stderr, "[user] NtUserMessageCall fnid 0x%X (msg 0x%X) not answered\n", a[5], a[1]);
    return 0;
}

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

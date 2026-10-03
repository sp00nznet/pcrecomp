/*
 * user32.c - win32hle USER32 message core, SDL-free. A Win32 GUI program's
 * control flow is: register a class, create a window, then pump messages —
 * GetMessage/TranslateMessage/DispatchMessage — and DispatchMessage calls the
 * window's WndProc. That whole loop is pure bookkeeping; only *presenting* a
 * window's pixels needs a display, and that (SDL2) is a separate layer. So this
 * file runs headless, which is what lets a lifted GUI program boot and reach
 * its own message loop with no display and no game binary (the selftest does
 * exactly that).
 *
 * The one interesting shim is DispatchMessageA: it calls back into lifted code
 * (the WndProc) through hle_call_guest — the native->guest path win32hle makes
 * an ordinary call instead of native32's exec-fault trampoline.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "win32hle.h"

#define WM_DESTROY 0x0002u
#define WM_QUIT    0x0012u

/* MSG is 28 bytes: hwnd, message, wParam, lParam, time, pt.x, pt.y. */
typedef struct { uint32_t hwnd, message, wParam, lParam; } msg_t;

/* A single process message queue (one thread's, which is all a boot needs). */
#define QN 256
static msg_t  g_q[QN];
static int    g_qhead, g_qtail;
static int    q_empty(void) { return g_qhead == g_qtail; }
static void   q_push(msg_t m) { g_q[g_qtail] = m; g_qtail = (g_qtail + 1) % QN; if (g_qtail == g_qhead) g_qhead = (g_qhead + 1) % QN; }
static int    q_pop(msg_t *m) { if (q_empty()) return 0; *m = g_q[g_qhead]; g_qhead = (g_qhead + 1) % QN; return 1; }

/* Class and window registries: name -> WndProc, then HWND -> WndProc. */
#define MAXW 64
static struct { char name[64]; uint32_t wndproc; } g_cls[MAXW];
static int g_cls_n;
static struct { uint32_t hwnd, wndproc; } g_win[MAXW];
static int g_win_n;
static uint32_t g_next_hwnd = 0x00010001u;

/* Optional pump hook: when the message queue is empty, GetMessage/PeekMessage
 * call this before giving up. The SDL present layer sets it (hle_present_enable)
 * so a guest's own message loop polls input and shows frames with no change to
 * the guest; left NULL (headless, no present) the queue behaves as before. */
static void (*g_pump)(void);
void hle_set_pump_hook(void (*fn)(void)) { g_pump = fn; }

static uint32_t cls_wndproc(const char *name) {
    for (int i = 0; i < g_cls_n; i++) if (!strcmp(g_cls[i].name, name)) return g_cls[i].wndproc;
    return 0;
}
static uint32_t win_wndproc(uint32_t hwnd) {
    for (int i = 0; i < g_win_n; i++) if (g_win[i].hwnd == hwnd) return g_win[i].wndproc;
    return 0;
}

/* Host-callable queue access, so an optional present/input layer (present.c)
 * can inject translated SDL events as WM_* messages and a host can drive the
 * queue — without user32 itself depending on SDL. */
void hle_post_message(uint32_t hwnd, uint32_t message, uint32_t wParam, uint32_t lParam) {
    msg_t m = { hwnd, message, wParam, lParam }; q_push(m);
}
int hle_msg_pop(uint32_t *message, uint32_t *wParam, uint32_t *lParam) {
    msg_t m;
    if (!q_pop(&m)) return 0;
    if (message) *message = m.message;
    if (wParam)  *wParam  = m.wParam;
    if (lParam)  *lParam  = m.lParam;
    return 1;
}
uint32_t hle_first_hwnd(void) { return g_win_n ? g_win[0].hwnd : 0; }

/* RegisterClassA(const WNDCLASSA*): lpfnWndProc at +4, lpszClassName at +36. */
static void u_RegisterClassA(void) {
    uint32_t wc = A32(0);
    uint32_t wndproc = MEM32(wc + 4);
    const char *name = (const char *)(uintptr_t)MEM32(wc + 36);
    if (g_cls_n < MAXW && name) { strncpy(g_cls[g_cls_n].name, name, 63); g_cls[g_cls_n].wndproc = wndproc; g_cls_n++; }
    RET(1, 1);
}

/* CreateWindowExA(exStyle, className, winName, style, x,y,w,h, parent, menu,
 * hInst, param) - 12 args. Look the class's WndProc up by name, mint an HWND,
 * and remember the pair so DispatchMessage can find it. */
static void u_CreateWindowExA(void) {
    const char *cls = (const char *)(uintptr_t)A32(1);
    uint32_t wndproc = cls ? cls_wndproc(cls) : 0;
    uint32_t hwnd = g_next_hwnd++;
    if (g_win_n < MAXW) { g_win[g_win_n].hwnd = hwnd; g_win[g_win_n].wndproc = wndproc; g_win_n++; }
    RET(hwnd, 12);
}

static void u_DefWindowProcA(void) { RET(0, 4); }                 /* (hwnd,msg,wParam,lParam) */
static void u_ShowWindow(void)     { RET(1, 2); }
static void u_UpdateWindow(void)   { RET(1, 1); }
static void u_DestroyWindow(void)  { RET(1, 1); }

static void u_PostMessageA(void) {                               /* (hwnd,msg,wParam,lParam) */
    msg_t m = { A32(0), A32(1), A32(2), A32(3) };
    q_push(m); RET(1, 4);
}
static void u_PostQuitMessage(void) {                            /* (exitCode) */
    msg_t m = { 0, WM_QUIT, A32(0), 0 };
    q_push(m); RETV(1);
}

/* GetMessageA(lpMsg, hWnd, min, max): block-less here (the queue drives the
 * boot). Fill *lpMsg; return 0 on WM_QUIT so the loop ends, else 1. */
static void u_GetMessageA(void) {
    uint32_t lp = A32(0);
    msg_t m;
    /* Block until a message arrives, pumping the present layer each turn so SDL
     * input becomes messages and a frame is shown. With no pump hook (headless)
     * an empty queue means WM_QUIT, so a loop still terminates. */
    while (!q_pop(&m)) {
        if (!g_pump) { m.hwnd = 0; m.message = WM_QUIT; m.wParam = 0; m.lParam = 0; break; }
        g_pump();
    }
    MEM32(lp + 0) = m.hwnd; MEM32(lp + 4) = m.message;
    MEM32(lp + 8) = m.wParam; MEM32(lp + 12) = m.lParam;
    RET(m.message == WM_QUIT ? 0u : 1u, 4);
}
/* PeekMessageA(lpMsg, hWnd, min, max, wRemove): return 1 and fill if a message
 * is waiting, else 0. (PM_REMOVE handling kept simple: always removes.) */
static void u_PeekMessageA(void) {
    uint32_t lp = A32(0);
    msg_t m;
    if (!q_pop(&m)) {
        if (g_pump) g_pump();          /* non-blocking: pump once, then re-check */
        if (!q_pop(&m)) RET(0, 5);
    }
    MEM32(lp + 0) = m.hwnd; MEM32(lp + 4) = m.message;
    MEM32(lp + 8) = m.wParam; MEM32(lp + 12) = m.lParam;
    RET(1, 5);
}
static void u_TranslateMessage(void) { RET(0, 1); }              /* no key translation yet */

/* DispatchMessageA(const MSG*): find the window's WndProc and call it, as
 * lifted code, through the explicit native->guest path. */
static void u_DispatchMessageA(void) {
    uint32_t lp = A32(0);
    uint32_t hwnd = MEM32(lp + 0), message = MEM32(lp + 4);
    uint32_t wParam = MEM32(lp + 8), lParam = MEM32(lp + 12);
    uint32_t wndproc = win_wndproc(hwnd);
    uint32_t result = 0;
    if (wndproc) {
        uint32_t args[4] = { hwnd, message, wParam, lParam };
        result = hle_call_guest(wndproc, 4, args);
    }
    RET(result, 1);
}
/* SendMessageA(hwnd,msg,wParam,lParam): synchronous WndProc call. */
static void u_SendMessageA(void) {
    uint32_t hwnd = A32(0), wndproc = win_wndproc(hwnd), result = 0;
    if (wndproc) { uint32_t args[4] = { hwnd, A32(1), A32(2), A32(3) }; result = hle_call_guest(wndproc, 4, args); }
    RET(result, 4);
}

/* --- RECT helpers (a RECT is left,top,right,bottom at +0,+4,+8,+12) --- */
static void u_CopyRect(void)     { uint32_t d=A32(0), s=A32(1); if(d&&s){MEM32(d)=MEM32(s);MEM32(d+4)=MEM32(s+4);MEM32(d+8)=MEM32(s+8);MEM32(d+12)=MEM32(s+12);} RET(1,2); }
static void u_SetRectEmpty(void) { uint32_t r=A32(0); if(r){MEM32(r)=0;MEM32(r+4)=0;MEM32(r+8)=0;MEM32(r+12)=0;} RET(1,1); }
static void u_SetRect(void)      { uint32_t r=A32(0); if(r){MEM32(r)=A32(1);MEM32(r+4)=A32(2);MEM32(r+8)=A32(3);MEM32(r+12)=A32(4);} RET(1,5); }
static void u_OffsetRect(void)   { uint32_t r=A32(0); int dx=(int)A32(1),dy=(int)A32(2); if(r){MEM32(r)+=dx;MEM32(r+4)+=dy;MEM32(r+8)+=dx;MEM32(r+12)+=dy;} RET(1,3); }
static void u_InflateRect(void)  { uint32_t r=A32(0); int dx=(int)A32(1),dy=(int)A32(2); if(r){MEM32(r)-=dx;MEM32(r+4)-=dy;MEM32(r+8)+=dx;MEM32(r+12)+=dy;} RET(1,3); }
static void u_PtInRect(void)     { RET(1,3); }

/* --- WinMain window setup: single-instance check, icons/cursors, metrics --- */
static void u_FindWindowA(void)      { RET(0, 2); }   /* no existing instance -> we're first */
static void u_LoadIconA(void)        { RET(0x1C000001u, 2); }
static void u_LoadCursorA(void)      { RET(0x1C000002u, 2); }
static void u_LoadImageA(void)       { RET(0x1C000003u, 6); }
static void u_LoadBitmapA(void)      { RET(0x1C000004u, 2); }
static void u_LoadAcceleratorsA(void){ RET(0x1C000005u, 2); }  /* nonzero: games treat NULL as fatal */
static void u_TranslateAcceleratorA(void){ RET(0, 3); }        /* not an accel key -> normal dispatch */
static void u_LoadMenuA(void)        { RET(0x1C000006u, 2); }
static void u_SetCursor(void)        { RET(0, 1); }   /* previous cursor */
static void u_GetDesktopWindow(void) { RET(0x00010000u, 0); }
static void u_GetParent(void)        { RET(0, 1); }
static void u_GetFocus(void)         { RET(0, 0); }
static void u_SetFocus(void)         { RET(0, 1); }
static void u_EnableWindow(void)     { RET(1, 2); }
static void u_SetForegroundWindow(void){ RET(1, 1); }
static void u_BringWindowToTop(void) { RET(1, 1); }
static void u_SetWindowPos(void)     { RET(1, 7); }
static void u_MoveWindow(void)       { RET(1, 6); }
static void u_SetWindowLongA(void)   { RET(0, 3); }
static void u_GetWindowLongA(void)   { RET(0, 2); }

/* GetSystemMetrics(nIndex): a 1600x960 primary display, standard small metrics. */
static void u_GetSystemMetrics(void) {
    switch (A32(0)) {
        case 0:  RET(1600, 1);          /* SM_CXSCREEN */
        case 1:  RET(960,  1);          /* SM_CYSCREEN */
        case 11: RET(32, 1); case 12: RET(32, 1);   /* SM_CX/CYICON */
        case 13: RET(32, 1); case 14: RET(32, 1);   /* SM_CX/CYCURSOR */
        case 15: RET(16, 1); case 16: RET(16, 1);   /* SM_CX/CYSMICON */
        case 4:  RET(19, 1);            /* SM_CYCAPTION */
        case 5:  RET(1, 1);  case 6: RET(1, 1);     /* SM_CX/CYBORDER */
        case 32: RET(4, 1);  case 33: RET(4, 1);    /* SM_CX/CYFRAME */
        default: RET(0, 1);
    }
}
/* client rect = full framebuffer; window rect same; Adjust* leave the rect. */
static void u_GetClientRect(void) {
    uint32_t r = A32(1);
    if (r) { MEM32(r + 0) = 0; MEM32(r + 4) = 0; MEM32(r + 8) = 1600; MEM32(r + 12) = 960; }
    RET(1, 2);
}
static void u_GetWindowRect(void) {
    uint32_t r = A32(1);
    if (r) { MEM32(r + 0) = 0; MEM32(r + 4) = 0; MEM32(r + 8) = 1600; MEM32(r + 12) = 960; }
    RET(1, 2);
}
static void u_AdjustWindowRect(void)   { RET(1, 3); }
static void u_AdjustWindowRectEx(void) { RET(1, 4); }
static void u_InvalidateRect(void)     { RET(1, 3); }
static void u_BeginPaint(void)         { RET(0x0DC00010u, 2); }  /* an HDC */
static void u_EndPaint(void)           { RET(1, 2); }
static void u_MessageBoxA(void) {                                /* (hwnd,text,caption,type) */
    fprintf(stderr, "[MessageBox] %s: %s\n", ASTR(2) ? ASTR(2) : "", ASTR(1) ? ASTR(1) : "");
    RET(1, 4);                                                   /* IDOK */
}

const win32hle_shim win32hle_user32[] = {
    { "CopyRect",           u_CopyRect },
    { "SetRectEmpty",       u_SetRectEmpty },
    { "SetRect",            u_SetRect },
    { "OffsetRect",         u_OffsetRect },
    { "InflateRect",        u_InflateRect },
    { "PtInRect",           u_PtInRect },
    { "FindWindowA",        u_FindWindowA },
    { "LoadIconA",          u_LoadIconA },
    { "LoadCursorA",        u_LoadCursorA },
    { "LoadImageA",         u_LoadImageA },
    { "LoadBitmapA",        u_LoadBitmapA },
    { "LoadAcceleratorsA",  u_LoadAcceleratorsA },
    { "TranslateAcceleratorA", u_TranslateAcceleratorA },
    { "LoadMenuA",          u_LoadMenuA },
    { "SetCursor",          u_SetCursor },
    { "GetDesktopWindow",   u_GetDesktopWindow },
    { "GetParent",          u_GetParent },
    { "GetFocus",           u_GetFocus },
    { "SetFocus",           u_SetFocus },
    { "EnableWindow",       u_EnableWindow },
    { "SetForegroundWindow",u_SetForegroundWindow },
    { "BringWindowToTop",   u_BringWindowToTop },
    { "SetWindowPos",       u_SetWindowPos },
    { "MoveWindow",         u_MoveWindow },
    { "SetWindowLongA",     u_SetWindowLongA },
    { "GetWindowLongA",     u_GetWindowLongA },
    { "GetSystemMetrics",   u_GetSystemMetrics },
    { "GetClientRect",      u_GetClientRect },
    { "GetWindowRect",      u_GetWindowRect },
    { "AdjustWindowRect",   u_AdjustWindowRect },
    { "AdjustWindowRectEx", u_AdjustWindowRectEx },
    { "InvalidateRect",     u_InvalidateRect },
    { "BeginPaint",         u_BeginPaint },
    { "EndPaint",           u_EndPaint },
    { "MessageBoxA",        u_MessageBoxA },
    { "RegisterClassA",   u_RegisterClassA },
    { "CreateWindowExA",  u_CreateWindowExA },
    { "DefWindowProcA",   u_DefWindowProcA },
    { "ShowWindow",       u_ShowWindow },
    { "UpdateWindow",     u_UpdateWindow },
    { "DestroyWindow",    u_DestroyWindow },
    { "PostMessageA",     u_PostMessageA },
    { "PostQuitMessage",  u_PostQuitMessage },
    { "GetMessageA",      u_GetMessageA },
    { "PeekMessageA",     u_PeekMessageA },
    { "TranslateMessage", u_TranslateMessage },
    { "DispatchMessageA", u_DispatchMessageA },
    { "SendMessageA",     u_SendMessageA },
    { 0, 0 }
};

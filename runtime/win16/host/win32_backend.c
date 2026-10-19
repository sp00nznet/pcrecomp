/*
 * win32_backend.c - Back the Win16 USER/GDI window shims with real Win32.
 *
 * We run on Windows, so the recompiled 16-bit engine can drive a real window:
 *   - RegisterClass captures the guest's WNDPROC (a lifted seg:off) and
 *     registers a real Win32 class whose C WndProc bridges back into guest code.
 *   - CreateWindow makes a real top-level window; a small table maps the 16-bit
 *     guest HWND/HDC handles to the real ones.
 *   - GetMessage/DispatchMessage drive the real Win32 message pump; on each
 *     dispatched message Win32 calls host_wndproc, which calls the guest WNDPROC
 *     via the runtime far-call dispatcher (PASCAL args + far frame).
 *
 * Drawing (GDI/WinG) is layered on top as the engine calls it.
 */
#include "runtime_api.h"
#include "ne_resources.h"
#include "recomp_game.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

extern CPU *g_cpu;

/* arg helpers (shim entry stack: [sp]=retIP, [sp+2]=retCS, [sp+4]=last arg) */
static inline uint16_t b_a16(CPU *cpu, int off) {
    return mem_read16(cpu, cpu->ss, (uint16_t)(cpu->sp + 4 + off));
}
static inline uint32_t b_a32(CPU *cpu, int off) {
    return (uint32_t)b_a16(cpu, off) | ((uint32_t)b_a16(cpu, off + 2) << 16);
}
static inline void b_ret(CPU *cpu, int purge) { cpu->sp += 4 + purge; }
static void b_asciiz(CPU *cpu, uint16_t seg, uint16_t off, char *out, int max);

/* ---- guest HWND/HDC handle tables (16-bit guest handle <-> real) ---- */
#define MAXH 256
static HWND g_hwnd[MAXH];
static HDC  g_hdc[MAXH];
static int  g_nhwnd = 1, g_nhdc = 1;   /* 0 reserved as NULL */

static void handle_table_full(const char *what) {
    static const char *told[4]; static int n;
    for (int i = 0; i < n; i++) if (told[i] == what) return;
    if (n < 4) told[n++] = what;
    fprintf(stderr, "[win32] %s handle table exhausted; the engine will see a creation failure\n", what);
}

static uint16_t put_hwnd(HWND h) {
    for (int i = 1; i < g_nhwnd; i++) if (g_hwnd[i] == h) return (uint16_t)i;
    if (g_nhwnd < MAXH) { g_hwnd[g_nhwnd] = h; return (uint16_t)g_nhwnd++; }
    handle_table_full("window");
    return 0;
}
static HWND get_hwnd(uint16_t g) { return (g && g < MAXH) ? g_hwnd[g] : NULL; }
/* Slots must be recycled: the engine takes a DC every frame, and a table that
 * only ever grows ran out within seconds -- put_hdc then returned 0 and the
 * engine reported "Closing already closed screen DC" for the rest of the run. */
static uint16_t put_hdc(HDC h) {
    if (!h) return 0;
    for (int i = 1; i < g_nhdc; i++) if (!g_hdc[i]) { g_hdc[i] = h; return (uint16_t)i; }
    if (g_nhdc < MAXH) { g_hdc[g_nhdc] = h; return (uint16_t)g_nhdc++; }
    handle_table_full("DC");
    return 0;
}
static void free_hdc(uint16_t g) { if (g && g < MAXH) g_hdc[g] = NULL; }
static HDC get_hdc(uint16_t g) { return (g && g < MAXH) ? g_hdc[g] : NULL; }

/* Any GDI call can be aimed at a WinG surface as easily as at a real DC. */
extern int  wing_is_dc(uint16_t);
extern HDC  wing_state_dc(CPU *, uint16_t);
extern HDC  wing_draw_begin(CPU *, uint16_t, const RECT *);
extern void wing_draw_end(CPU *, uint16_t, const RECT *);

/* GDI objects (bitmaps so far) get their own guest handle space. */
#define MAXGDI 256
static HGDIOBJ g_gdi[MAXGDI];
static int g_ngdi = 1;
/* A host HGDIOBJ is the object's identity, so the same one must always map to
 * the same guest handle. Handing out a fresh slot per call leaked the table dry
 * within seconds -- GetStockObject returns the same few singletons over and over
 * and SelectObject hands back the previous object on every single call. Once the
 * table filled, put_hgdi returned 0 and the engine reported "object created ...
 * failed" and stopped being able to make brushes and pens, which is why only a
 * couple of toys could ever be taken off the shelf. */
static uint16_t put_hgdi(HGDIOBJ h) {
    if (!h) return 0;
    for (int i = 1; i < g_ngdi; i++) if (g_gdi[i] == h) return (uint16_t)i;
    for (int i = 1; i < g_ngdi; i++) if (!g_gdi[i]) { g_gdi[i] = h; return (uint16_t)i; }
    if (g_ngdi >= MAXGDI) { handle_table_full("GDI object"); return 0; }
    g_gdi[g_ngdi] = h; return (uint16_t)g_ngdi++;
}

static HGDIOBJ get_hgdi(uint16_t g) { return (g && g < MAXGDI) ? g_gdi[g] : NULL; }

/* Stock objects are singletons GDI owns. Now that one host object maps to one
 * guest handle, letting the engine delete one would strand every other holder
 * of that handle -- and real GDI ignores DeleteObject on them anyway. */
static char g_gdi_stock[MAXGDI];

/* ---- guest window classes ----
 * One global WNDPROC was wrong: CATZ.WAD and CATZDLL each register their own
 * class, and every window was being routed to whichever registered last. The
 * engine's own window therefore ran the host shell's WNDPROC, so its WM_PAINT --
 * the one that blits the WinG surface -- never ran. Key the proc by class name,
 * and remember which proc each HWND was created with. */
#define MAXCLS 32
typedef struct { char name[64]; uint16_t seg, off; } GuestClass;
static GuestClass g_cls[MAXCLS];
static int g_ncls;

/* Parallel to g_hwnd: the guest WNDPROC this window was created with. */
static uint16_t g_hwnd_proc_seg[MAXH], g_hwnd_proc_off[MAXH];

/* Last class registered; the fallback for a window whose class we never saw. */
static uint16_t g_wndproc_seg = 0, g_wndproc_off = 0;

/* The first window created is the application frame; only it ends the app. */
static HWND g_main_hwnd;
static HWND g_screen_hwnd;
HWND g_main_hwnd_of(void)   { return g_main_hwnd; }
HWND g_screen_hwnd_of(void) { return g_screen_hwnd; }
/* The engine makes two windows: a framed playpen and a 640x480 WS_POPUP that
   is its pet overlay -- the thing it would normally paint straight onto the
   desktop. GetDC(NULL) asks for that overlay, so it has to go to the popup;
   sending it to the framed playpen painted the pet layer's clear colour over
   the whole pen. */
#define RECOMP_SCREEN_W 640
#define RECOMP_SCREEN_H 480


static GuestClass *cls_find(const char *name) {
    for (int i = 0; i < g_ncls; i++)
        if (!strcmp(g_cls[i].name, name)) return &g_cls[i];
    return NULL;
}

static void hwnd_proc(HWND h, uint16_t *seg, uint16_t *off) {
    for (int i = 1; i < g_nhwnd; i++)
        if (g_hwnd[i] == h) { *seg = g_hwnd_proc_seg[i]; *off = g_hwnd_proc_off[i]; return; }
    *seg = g_wndproc_seg; *off = g_wndproc_off;
}

/* Call the guest WNDPROC(hWnd, uMsg, wParam, lParam) via the far dispatcher.
 * Win16 PASCAL: push args left-to-right; lParam is a DWORD (hi word first). */
static uint16_t call_guest_wndproc(uint16_t pseg, uint16_t poff,
                                   uint16_t hwnd, uint16_t msg, uint16_t wparam, uint32_t lparam) {
    CPU *cpu = g_cpu;
    if (!pseg) return 0;
    /* The WNDPROC runs re-entrantly (CreateWindow delivers WM_NCCREATE/CREATE
     * synchronously while the guest is mid-call), so snapshot the FULL guest
     * register state and restore it afterwards. */
    CPU save = *cpu;
    /* The Borland C0 exception/cleanup machinery keeps THREE chain heads in the
     * task's stack segment: ss:[0x10] (a DLL's cleanup chain), ss:[0x14] (the
     * EXE's cleanup chain) and ss:[0x16] (the C++ catch/setjmp chain). The WNDPROC runs
     * re-entrantly on the SAME stack and pushes its own frames onto these chains;
     * once we restore the interrupted guest's SP those frames no longer exist, so
     * every head must be put back -- otherwise a head points at a discarded frame
     * (or a foreign module's setjmp buffer) and the interrupted guest's later
     * chain walk derails into a runaway loop. Snapshot all three alongside the
     * CPU. (Restoring only ss:[0x14] left 0x10/0x16 dangling, which corrupted the
     * cross-module EH chain non-deterministically.) */
    uint16_t saved_exc_head_10 = mem_read16(cpu, cpu->ss, 0x10);
    uint16_t saved_exc_head    = mem_read16(cpu, cpu->ss, 0x14);
    uint16_t saved_exc_head_16 = mem_read16(cpu, cpu->ss, 0x16);
    cpu->ds = cpu->es = recomp_dgroup_of_seg(pseg);   /* the proc's own module */
    push16(cpu, hwnd);
    push16(cpu, msg);
    push16(cpu, wparam);
    push16(cpu, (uint16_t)(lparam >> 16));
    push16(cpu, (uint16_t)(lparam & 0xFFFF));
    push16(cpu, cpu->cs); push16(cpu, 0);          /* far return frame */
    dispatch_far(cpu, pseg, poff);
    uint16_t ret = cpu->ax;
    /* restore everything except the heap/memory bookkeeping (which the WNDPROC
     * may have legitimately advanced via GlobalAlloc). */
    uint8_t *mem = cpu->mem; uint32_t *sel = cpu->sel_base;
    uint32_t hn = cpu->heap_next; uint16_t ns = cpu->next_sel;
    *cpu = save;
    cpu->mem = mem; cpu->sel_base = sel; cpu->heap_next = hn; cpu->next_sel = ns;
    /* Put the cleanup/catch chain heads back: the WNDPROC's frames no longer exist. */
    mem_write16(cpu, cpu->ss, 0x10, saved_exc_head_10);
    mem_write16(cpu, cpu->ss, 0x14, saved_exc_head);
    mem_write16(cpu, cpu->ss, 0x16, saved_exc_head_16);
    return ret;
}

/* Structural/creation messages carry host-only data (CREATESTRUCT/MINMAXINFO/
 * NCCALCSIZE far pointers the guest can't read) and must not be allowed to
 * fail creation, so we DefWindowProc them. Runtime messages (paint, timers,
 * input, command) are forwarded to the guest WNDPROC. */
static int forward_to_guest(UINT msg) {
    if (getenv("RECOMP_NO_WNDPROC")) return 0;   /* diagnostic: never call guest */
    switch (msg) {
        case WM_NCCREATE: case WM_CREATE: case WM_NCCALCSIZE:
        case WM_GETMINMAXINFO: case WM_NCDESTROY: case WM_DESTROY:
        case WM_WINDOWPOSCHANGING: case WM_WINDOWPOSCHANGED:
        case WM_GETICON: case WM_NCPAINT: case WM_NCACTIVATE:
            return 0;
        default:
            return 1;
    }
}

static LRESULT CALLBACK host_wndproc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    /* Only the application's own frame ends the app. Quitting on any window's
       WM_DESTROY meant closing a modal dialog tore down the whole program --
       which is exactly what happened the first time a valid serial let the
       wizard actually finish a dialog. */
    if (msg == WM_DESTROY) {
        if (hWnd == g_main_hwnd) { PostQuitMessage(0); return 0; }
        return 0;
    }
    /* The engine repaints every pixel it invalidates, straight out of its own
     * backdrop surface. Letting Windows erase to the class brush first only
     * flashes another colour under it -- and where the guest repaints a smaller
     * area than was invalidated, that colour is what stays on screen. Claim the
     * erase as done. */
    /* Repaint an exposed frame from the copy of what it was last shown. The
       engine repaints only what changed and assumes the window keeps the rest,
       which Windows does not promise -- so without this an exposed region stays
       as undefined pixels until something happens to move across it, and over
       the static parts of the playpen that is never. */
    if (msg == WM_ERASEBKGND && (hWnd == g_main_hwnd || hWnd == g_screen_hwnd)) {
        extern void recomp_present_paint(void *);
        recomp_present_paint((void *)wParam);
        return 1;
    }
    if (getenv("RECOMP_LOG_PAINT") && (msg == WM_PAINT || msg == WM_ERASEBKGND)) {
        static int n; if (n++ < 30)
            fprintf(stderr, "[paint] %s hwnd=%p %s\n",
                    msg == WM_PAINT ? "WM_PAINT " : "WM_ERASE ", (void *)hWnd,
                    hWnd == g_main_hwnd ? "(main)" :
                    hWnd == g_screen_hwnd ? "(overlay child)" : "(other)");
    }
    if (msg == WM_ERASEBKGND) return 1;
    /* RECOMP_LOG_CMD: every WM_COMMAND the engine dispatches to itself, with the
       command id. A menu item that does nothing either sends no command or
       sends one nothing acts on, and this separates the two. */
    if (getenv("RECOMP_LOG_CMD") && (msg == WM_COMMAND || msg == 0x083B)) {
        static int n; if (n++ < 400)
            fprintf(stderr, "[cmd] msg=%04X wParam=%u lParam=%08lX hwnd=%p\n",
                    msg, (unsigned)wParam, (unsigned long)lParam, (void *)hWnd);
    }
    uint16_t pseg, poff;
    hwnd_proc(hWnd, &pseg, &poff);
    if (pseg && forward_to_guest(msg)) {
        uint16_t gh = put_hwnd(hWnd);
        uint32_t glp = (uint32_t)lParam;
        /* The adoption dialog's breed buttons are owner-drawn: the engine paints
         * each cat's portrait itself in response to WM_DRAWITEM. lParam is a host
         * DRAWITEMSTRUCT pointer, which means nothing in guest memory, so the
         * handler read rubbish and the buttons came up blank. Marshal it into the
         * 26-byte Win16 layout and hand over a far pointer to that. */
        if (msg == WM_DRAWITEM && lParam) {
            const DRAWITEMSTRUCT *di = (const DRAWITEMSTRUCT *)lParam;
            extern uint16_t recomp_guest_scratch(CPU *, uint32_t);
            uint16_t sg = recomp_guest_scratch(g_cpu, 32);
            if (sg) {
                const uint16_t f[7] = {
                    (uint16_t)di->CtlType, (uint16_t)di->CtlID,
                    (uint16_t)di->itemID,  (uint16_t)di->itemAction,
                    (uint16_t)di->itemState,
                    put_hwnd(di->hwndItem), put_hdc(di->hDC),
                };
                for (int k = 0; k < 7; k++)
                    mem_write16(g_cpu, sg, (uint16_t)(k * 2), f[k]);
                const int16_t r[4] = { (int16_t)di->rcItem.left,  (int16_t)di->rcItem.top,
                                       (int16_t)di->rcItem.right, (int16_t)di->rcItem.bottom };
                for (int k = 0; k < 4; k++)
                    mem_write16(g_cpu, sg, (uint16_t)(14 + k * 2), (uint16_t)r[k]);
                mem_write16(g_cpu, sg, 22, (uint16_t)(di->itemData & 0xFFFF));
                mem_write16(g_cpu, sg, 24, (uint16_t)(di->itemData >> 16));
                glp = (uint32_t)sg << 16;
            }
        }
        LRESULT gr = call_guest_wndproc(pseg, poff, gh, (uint16_t)msg,
                                        (uint16_t)wParam, glp);
        /* The engine runs a shutdown chain on WM_CLOSE but never calls
           DestroyWindow or PostQuitMessage, so the window stayed up and the
           title-bar X did nothing. Let the guest run (it saves the pet), then
           apply the default: destroy the window. */
        if (msg == WM_CLOSE) return DefWindowProc(hWnd, msg, wParam, lParam);
        return gr;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

/* ===== USER: window class + creation ===== */

void USER_REGISTERCLASS(CPU *cpu) {
    /* Win16 WNDCLASS: style@0(2) lpfnWndProc@2(4 far) cbClsExtra@6 cbWndExtra@8
     * hInstance@10 hIcon@12 hCursor@14 hbrBackground@16 lpszMenuName@18(4)
     * lpszClassName@22(4). */
    uint16_t off = b_a16(cpu, 0), seg = b_a16(cpu, 2);
    uint16_t poff = mem_read16(cpu, seg, (uint16_t)(off + 2));
    uint16_t pseg = mem_read16(cpu, seg, (uint16_t)(off + 4));
    uint16_t noff = mem_read16(cpu, seg, (uint16_t)(off + 22));
    uint16_t nseg = mem_read16(cpu, seg, (uint16_t)(off + 24));

    char name[64] = "";
    if (nseg) b_asciiz(cpu, nseg, noff, name, sizeof name);
    if (!name[0]) snprintf(name, sizeof name, "RecompGuestCls%d", g_ncls);

    g_wndproc_seg = pseg; g_wndproc_off = poff;

    GuestClass *c = cls_find(name);
    if (!c && g_ncls < MAXCLS) {
        c = &g_cls[g_ncls++];
        snprintf(c->name, sizeof c->name, "%s", name);
        WNDCLASSA wc; memset(&wc, 0, sizeof wc);
        wc.style         = CS_OWNDC;
        wc.lpfnWndProc   = host_wndproc;
        wc.hInstance     = GetModuleHandle(NULL);
        wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = c->name;
        RegisterClassA(&wc);
    }
    if (c) { c->seg = pseg; c->off = poff; }

    fprintf(stderr, "[win32] RegisterClass(\"%s\") -> guest WNDPROC seg%u:%04X\n",
            name, pseg, poff);
    cpu->ax = 0xC001;
    b_ret(cpu, 4);
}

void USER_CREATEWINDOW(CPU *cpu) {
    /* CreateWindow(lpClassName@26, lpWindowName@22, dwStyle@18, x@16, y@14,
     * nWidth@12, nHeight@10, hWndParent@8, hMenu@6, hInstance@4, lpParam@0).
     * Every argument used to be ignored, so the engine's window was created as
     * another top-level 640x480 frame under the shell's class -- wrong size,
     * wrong parent, and wrong WNDPROC. */
    if (getenv("RECOMP_FAKE_WIN")) { cpu->ax = 0x0CA7; b_ret(cpu, 30); return; }

    uint16_t coff = b_a16(cpu, 26), cseg = b_a16(cpu, 28);
    uint16_t toff = b_a16(cpu, 22), tseg = b_a16(cpu, 24);
    uint32_t style = b_a32(cpu, 18);
    int x = (int16_t)b_a16(cpu, 16), y = (int16_t)b_a16(cpu, 14);
    int w = (int16_t)b_a16(cpu, 12), h = (int16_t)b_a16(cpu, 10);
    HWND parent = get_hwnd(b_a16(cpu, 8));

    char cname[64] = "", title[128] = "Catz (recomp)";
    if (cseg) b_asciiz(cpu, cseg, coff, cname, sizeof cname);
    if (tseg) b_asciiz(cpu, tseg, toff, title, sizeof title);

    GuestClass *c = cname[0] ? cls_find(cname) : NULL;
    const char *hostcls = c ? c->name : (g_ncls ? g_cls[0].name : "RecompGuestCls0");

    /* CW_USEDEFAULT is 0x8000 in Win16 and a different value in Win32. */
    if ((uint16_t)x == 0x8000) x = CW_USEDEFAULT;
    if ((uint16_t)y == 0x8000) y = CW_USEDEFAULT;
    if (w <= 0) w = 640;
    if (h <= 0) h = 480;
    /* A child needs a parent; without WS_CHILD force a top-level frame. */
    if (!(style & WS_CHILD)) parent = NULL;
    else if (!parent) style &= ~(uint32_t)WS_CHILD;

    /* The engine makes two top-level windows: the framed playpen, and a 640x480
       WS_POPUP it immediately hides because it means to paint the bare desktop.
       Showing both left two overlapping surfaces with different content, which
       looks exactly like the pet smearing. Keep the pet indoors instead: give
       the frame a client area of the 640x480 we already report through
       GetClientRect, and make the overlay a child filling it. One window, one
       drawing surface. RECOMP_DESKTOP=1 keeps the original two-window layout. */
    int as_child = 0;
    if (!getenv("RECOMP_DESKTOP") && g_main_hwnd && !g_screen_hwnd
        && (style & WS_POPUP) && !(style & WS_CHILD)) {
        as_child = 1;
        style  = WS_CHILD | WS_VISIBLE;
        parent = g_main_hwnd;
        x = y = 0;
        w = RECOMP_SCREEN_W;
        h = RECOMP_SCREEN_H;
    }

    HWND hw = CreateWindowExA(0, hostcls, title, (DWORD)style, x, y, w, h,
                              parent, NULL, GetModuleHandle(NULL), NULL);
    uint16_t gh = hw ? put_hwnd(hw) : 0;
    if (hw && !g_main_hwnd) {
        g_main_hwnd = hw;
        if (!getenv("RECOMP_DESKTOP")) {      /* client area == the engine's screen */
            /* The engine renders a fixed 640x480 playpen and reports exactly that
               through GetClientRect, so a resizable frame is a lie: drag the edge
               out and the extra client area is something the engine will never
               draw, which is simply black, and it looks for all the world like
               half the playpen has gone dark. Take the sizing grip and the
               maximise box away so the client cannot leave 640x480. */
            LONG st = GetWindowLongA(hw, GWL_STYLE);
            st &= ~(WS_THICKFRAME | WS_MAXIMIZEBOX);
            SetWindowLongA(hw, GWL_STYLE, st);
            RECT rc = { 0, 0, RECOMP_SCREEN_W, RECOMP_SCREEN_H };
            AdjustWindowRect(&rc, (DWORD)st, FALSE);
            SetWindowPos(hw, NULL, 0, 0, rc.right - rc.left, rc.bottom - rc.top,
                         SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
        }
    }
    if (hw && !g_screen_hwnd
        && (as_child || ((style & WS_POPUP) && !(style & WS_CHILD))))
        g_screen_hwnd = hw;
    if (gh) {
        g_hwnd_proc_seg[gh] = c ? c->seg : g_wndproc_seg;
        g_hwnd_proc_off[gh] = c ? c->off : g_wndproc_off;
    }
    fprintf(stderr, "[win32] CreateWindow(\"%s\" title=\"%s\" style=%08lX %dx%d parent=%p) "
                    "-> real=%p guest=%u proc=seg%u:%04X err=%lu\n",
            cname, title, (unsigned long)style, w, h, (void *)parent, (void *)hw, gh,
            gh ? g_hwnd_proc_seg[gh] : 0, gh ? g_hwnd_proc_off[gh] : 0,
            hw ? 0UL : (unsigned long)GetLastError());
    cpu->ax = gh;
    b_ret(cpu, 30);
}

/* The guest WNDPROC passes everything it does not handle to DefWindowProc,
 * which was a stub returning 0. WM_CLOSE is one of those: nothing called
 * DestroyWindow, so clicking the playpen's X did nothing at all. Hand the
 * message to the real DefWindowProc. Win16 window procs return a LONG in DX:AX.
 * Args are PASCAL: hwnd, msg, wParam, lParam. */
void USER_DEFWINDOWPROC(CPU *cpu) {
    uint16_t gh   = b_a16(cpu, 8);
    UINT     msg  = b_a16(cpu, 6);
    WPARAM   wp   = b_a16(cpu, 4);
    LPARAM   lp   = (LPARAM)(int32_t)b_a32(cpu, 0);
    HWND     h    = get_hwnd(gh);
    LRESULT  r    = h ? DefWindowProc(h, msg, wp, lp) : 0;
    cpu->ax = (uint16_t)(r & 0xFFFF);
    cpu->dx = (uint16_t)((uint32_t)r >> 16);
    b_ret(cpu, 10);
}

/* Both of these were stubs, so nothing could ever close: the engine's WM_CLOSE
 * handler called DestroyWindow, it did nothing, and the window stayed up. */
void USER_DESTROYWINDOW(CPU *cpu) {
    uint16_t g = b_a16(cpu, 0);
    HWND h = get_hwnd(g);
    if (h) { DestroyWindow(h); if (g < MAXH) g_hwnd[g] = NULL; }
    cpu->ax = 1;
    b_ret(cpu, 2);
}

void USER_POSTQUITMESSAGE(CPU *cpu) {
    PostQuitMessage((int)(int16_t)b_a16(cpu, 0));
    cpu->ax = 0;
    b_ret(cpu, 2);
}

/* nCmdShow was ignored and every call forced SW_SHOW, so a window the engine
 * asked to HIDE stayed up. It hides the 640x480 pet overlay right after
 * creating it -- leaving that visible put a second window full of older frames
 * on top of the playpen, which is indistinguishable from the pet smearing.
 * Win16 SW_* values match Win32, so pass it straight through. */
void USER_SHOWWINDOW(CPU *cpu) {          /* (hwnd@2, nCmdShow@0) */
    HWND h = get_hwnd(b_a16(cpu, 2));
    int cmd = (int)(int16_t)b_a16(cpu, 0);
    /* One deliberate exception: the engine hides the 640x480 popup because it
       wants to paint the bare desktop instead. We have repurposed exactly that
       window as the pet's screen (GetDC(NULL) returns its DC), so keeping the
       pet indoors means keeping it shown. Everything else is honoured. */
    if (h && h == g_screen_hwnd && cmd == SW_HIDE && !getenv("RECOMP_DESKTOP"))
        cmd = SW_SHOWNA;                  /* show it, but do not steal focus */
    cpu->ax = (uint16_t)(h ? ShowWindow(h, cmd) : 0);
    b_ret(cpu, 4);
}

void USER_UPDATEWINDOW(CPU *cpu) {
    HWND h = get_hwnd(b_a16(cpu, 0));
    if (h) UpdateWindow(h);
    cpu->ax = 0; b_ret(cpu, 2);
}

/* ---- GDI objects ----
 * These were stubs returning 0. The engine treats a null GDI handle as fatal:
 * XDrawPort's brush creation throws "exception 2" at WDRAW.CPP:1935 the moment
 * CreateSolidBrush comes back 0, which is where the first real frame died. */
void GDI_CREATESOLIDBRUSH(CPU *cpu) {          /* (COLORREF@0) */
    COLORREF c = (COLORREF)b_a32(cpu, 0);
    cpu->ax = put_hgdi(CreateSolidBrush(c));
    b_ret(cpu, 4);
}

void GDI_CREATEPEN(CPU *cpu) {                 /* (style@6, width@4, colour@0) */
    int style = (int16_t)b_a16(cpu, 6);
    int width = (int16_t)b_a16(cpu, 4);
    COLORREF c = (COLORREF)b_a32(cpu, 0);
    cpu->ax = put_hgdi(CreatePen(style, width, c));
    b_ret(cpu, 8);
}

void GDI_GETSTOCKOBJECT(CPU *cpu) {            /* (index@0) */
    uint16_t g = put_hgdi(GetStockObject((int)(int16_t)b_a16(cpu, 0)));
    if (g) g_gdi_stock[g] = 1;
    cpu->ax = g;
    b_ret(cpu, 2);
}

void GDI_SELECTOBJECT(CPU *cpu) {              /* (hdc@2, hgdiobj@0) -> previous */
    uint16_t gdc = b_a16(cpu, 2), gob = b_a16(cpu, 0);
    /* A WinG surface is not a real GDI object here; selecting one just records
       which surface that WinG DC draws to and blits from. */
    extern int wing_is_dc(uint16_t);
    extern int wing_is_bmp(uint16_t);
    extern uint16_t wing_select(uint16_t, uint16_t);
    if (wing_is_dc(gdc) && wing_is_bmp(gob)) {
        cpu->ax = wing_select(gdc, gob);
        b_ret(cpu, 4);
        return;
    }
    /* Anything else selected into a WinG DC -- a pen, a brush -- has to reach
       the host DC that actually draws on that surface, or the shapes come out
       in the stock black-on-white. */
    extern HDC wing_state_dc(CPU *, uint16_t);
    HDC dc = wing_is_dc(gdc) ? wing_state_dc(cpu, gdc) : get_hdc(gdc);
    HGDIOBJ o = get_hgdi(gob);
    HGDIOBJ prev = (dc && o) ? SelectObject(dc, o) : NULL;
    cpu->ax = prev ? put_hgdi(prev) : 0;
    b_ret(cpu, 4);
}

void GDI_DELETEOBJECT(CPU *cpu) {              /* (hgdiobj@0) */
    uint16_t g = b_a16(cpu, 0);
    HGDIOBJ o = get_hgdi(g);
    if (o && !g_gdi_stock[g]) { DeleteObject(o); g_gdi[g] = NULL; }
    cpu->ax = 1;
    b_ret(cpu, 2);
}

void GDI_CREATECOMPATIBLEDC(CPU *cpu) {        /* (hdc@0) */
    uint16_t g0 = b_a16(cpu, 0);
    HDC dc = wing_is_dc(g0) ? wing_state_dc(cpu, g0) : get_hdc(g0);
    HDC mem = CreateCompatibleDC(dc);
    cpu->ax = mem ? put_hdc(mem) : 0;
    b_ret(cpu, 2);
}

void GDI_DELETEDC(CPU *cpu) {                  /* (hdc@0) */
    uint16_t g = b_a16(cpu, 0);
    HDC dc = get_hdc(g);
    if (dc) DeleteDC(dc);
    free_hdc(g);
    cpu->ax = 1;
    b_ret(cpu, 2);
}

void GDI_CREATECOMPATIBLEBITMAP(CPU *cpu) {    /* (hdc@4, w@2, h@0) */
    uint16_t g0 = b_a16(cpu, 4);
    HDC dc = wing_is_dc(g0) ? wing_state_dc(cpu, g0) : get_hdc(g0);
    int w = (int16_t)b_a16(cpu, 2), h = (int16_t)b_a16(cpu, 0);
    HBITMAP bm = dc ? CreateCompatibleBitmap(dc, w, h) : NULL;
    cpu->ax = bm ? put_hgdi(bm) : 0;
    b_ret(cpu, 6);
}


/* GetTextExtent(hdc@6, lpString@2/4, nCount@0) -> width in AX, height in DX.
 * Stubbed to 0, so every string the engine measured came back zero wide -- and
 * it lays its panel's menu bar out from these. "&Options" and "&Help" were
 * given rectangles like (5,25)-(5,38), zero columns across, so DrawText clipped
 * them to nothing and all that survived was the underline under the accelerator.
 * That is the mangled text at the top of the shelf. */
void GDI_GETTEXTEXTENT(CPU *cpu) {
    uint16_t g  = b_a16(cpu, 6);
    uint16_t so = b_a16(cpu, 2), ss = b_a16(cpu, 4);
    int n       = (int16_t)b_a16(cpu, 0);
    extern HDC wing_state_dc(CPU *, uint16_t);
    HDC dc = wing_is_dc(g) ? wing_state_dc(cpu, g) : get_hdc(g);
    char buf[512] = "";
    if (ss) b_asciiz(cpu, ss, so, buf, sizeof buf);
    if (n < 0 || n > (int)strlen(buf)) n = (int)strlen(buf);
    SIZE sz = { 0, 0 };
    if (dc) GetTextExtentPoint32A(dc, buf, n, &sz);
    if (getenv("RECOMP_LOG_TEXT")) { static int k; if (k++ < 15)
        fprintf(stderr, "[ext] hdc=%u dc=%p \"%s\" n=%d -> %ldx%ld\n",
            g, (void*)dc, buf, n, (long)sz.cx, (long)sz.cy); }
    cpu->ax = (uint16_t)sz.cx;
    cpu->dx = (uint16_t)sz.cy;
    b_ret(cpu, 8);
}

/* The engine polls the mouse button rather than waiting on messages -- its menu
 * tracking, its drag loops and its hit testing all ask GetAsyncKeyState. Stubbed
 * to 0 it read "never pressed", so a menu item highlighted and then immediately
 * auto-unselected without ever running: most of the Options menu did nothing. */
void USER_GETASYNCKEYSTATE(CPU *cpu) {         /* (vKey@0) */
    int vk = (int16_t)b_a16(cpu, 0);
    /* RECOMP_CURSOR pins the pointer for testing; let it pin the button too, as
       "x,y,b", or a scripted click could never work the menus. */
    const char *fc = getenv("RECOMP_CURSOR");
    if (fc && (vk == VK_LBUTTON || vk == VK_RBUTTON)) {
        char buf[64] = "";
        if (fc[0] == '@') {
            FILE *f = fopen(fc + 1, "r");
            if (f) { if (!fgets(buf, sizeof buf, f)) buf[0] = 0; fclose(f); }
        } else snprintf(buf, sizeof buf, "%s", fc);
        const char *c = strchr(buf, ',');
        const char *b = c ? strchr(c + 1, ',') : NULL;
        int down = b ? atoi(b + 1) : 0;
        cpu->ax = (uint16_t)((down && vk == VK_LBUTTON) ? 0x8000 : 0);
        b_ret(cpu, 2);
        return;
    }
    cpu->ax = (uint16_t)GetAsyncKeyState(vk);
    b_ret(cpu, 2);
}

void USER_SWAPMOUSEBUTTON(CPU *cpu) {          /* (fSwap@0) -> previous */
    /* Report the setting, never change it. The real call swaps the buttons
       system-wide, and the engine passes 0 -- which would quietly un-swap the
       mouse of anyone running left-handed. */
    cpu->ax = (uint16_t)(GetSystemMetrics(SM_SWAPBUTTON) ? 1 : 0);
    b_ret(cpu, 2);
}

void USER_SETWINDOWTEXT(CPU *cpu) {            /* (hWnd@4, lpString@0/2) */
    HWND h = get_hwnd(b_a16(cpu, 4));
    uint16_t off = b_a16(cpu, 0), seg = b_a16(cpu, 2);
    char buf[256] = "";
    if (seg) b_asciiz(cpu, seg, off, buf, sizeof buf);
    if (h) SetWindowTextA(h, buf);
    cpu->ax = 1;
    b_ret(cpu, 6);
}

/* CheckMenuItem(hMenu@4, idCheckItem@2, uCheck@0). The engine draws its own
   menus, so the only real menu here is the window's system menu. */
void USER_CHECKMENUITEM(CPU *cpu) {
    HMENU m = GetSystemMenu(g_main_hwnd, FALSE);
    DWORD prev = m ? CheckMenuItem(m, b_a16(cpu, 2), b_a16(cpu, 0)) : (DWORD)-1;
    cpu->ax = (uint16_t)prev;
    b_ret(cpu, 6);
}

/* ===== cursors, capture and fonts =====
 * LoadCursor and SetCursor were stubs, so whatever the engine set last stuck:
 * it shows the hourglass while it loads and then restores the arrow, and with
 * the restore going nowhere the pointer stayed an hourglass over the whole
 * window. SetCapture and ReleaseCapture were stubs too, which is why a drag
 * that left the window lost the item. */
#define MAXCUR 32
static HCURSOR g_cur[MAXCUR];
static int g_ncur = 1;

static uint16_t put_hcur(HCURSOR h) {
    if (!h) return 0;
    for (int i = 1; i < g_ncur; i++) if (g_cur[i] == h) return (uint16_t)i;
    if (g_ncur >= MAXCUR) return 0;
    g_cur[g_ncur] = h; return (uint16_t)g_ncur++;
}

void USER_LOADCURSOR(CPU *cpu) {               /* (hInstance@4, lpCursorName@0/2) */
    uint16_t inst = b_a16(cpu, 4);
    uint16_t noff = b_a16(cpu, 0), nseg = b_a16(cpu, 2);
    HCURSOR h = NULL;
    if (!inst || !nseg) {
        /* A standard cursor: the name is an ordinal, and Win16 used the same
           IDC_ values Win32 still does. */
        h = LoadCursorA(NULL, MAKEINTRESOURCEA(noff ? noff : 32512));
    } else {
        char nm[64] = "";
        b_asciiz(cpu, nseg, noff, nm, sizeof nm);
        h = LoadCursorA(NULL, IDC_ARROW);      /* app cursors: arrow will do */
        (void)nm;
    }
    cpu->ax = put_hcur(h);
    b_ret(cpu, 6);
}

void USER_SETCURSOR(CPU *cpu) {                /* (hCursor@0) -> previous */
    uint16_t g = b_a16(cpu, 0);
    HCURSOR h = (g && g < MAXCUR) ? g_cur[g] : NULL;
    HCURSOR prev = SetCursor(h);
    cpu->ax = put_hcur(prev);
    b_ret(cpu, 2);
}

void USER_SETCAPTURE(CPU *cpu) {               /* (hWnd@0) -> previous */
    HWND h = get_hwnd(b_a16(cpu, 0));
    HWND prev = h ? SetCapture(h) : NULL;
    cpu->ax = prev ? put_hwnd(prev) : 0;
    b_ret(cpu, 2);
}

void USER_RELEASECAPTURE(CPU *cpu) {
    cpu->ax = (uint16_t)ReleaseCapture();
    b_ret(cpu, 0);
}

/* CreateFontIndirect(lpLogFont@0/2). The Win16 LOGFONT is packed: lfHeight@0(2)
 * lfWidth@2 lfEscapement@4 lfOrientation@6 lfWeight@8, then seven bytes of
 * flags, then a 32-byte face name. Stubbed to 0, every DrawText fell back to
 * the default system font, which is why the shelf's caption did not look
 * right. */
void GDI_CREATEFONTINDIRECT(CPU *cpu) {
    uint16_t o = b_a16(cpu, 0), sg = b_a16(cpu, 2);
    if (!sg) { cpu->ax = 0; b_ret(cpu, 4); return; }
    LOGFONTA lf;
    memset(&lf, 0, sizeof lf);
    lf.lfHeight      = (int16_t)mem_read16(cpu, sg, o);
    lf.lfWidth       = (int16_t)mem_read16(cpu, sg, (uint16_t)(o + 2));
    lf.lfEscapement  = (int16_t)mem_read16(cpu, sg, (uint16_t)(o + 4));
    lf.lfOrientation = (int16_t)mem_read16(cpu, sg, (uint16_t)(o + 6));
    lf.lfWeight      = (int16_t)mem_read16(cpu, sg, (uint16_t)(o + 8));
    lf.lfItalic         = mem_read8(cpu, sg, (uint16_t)(o + 10));
    lf.lfUnderline      = mem_read8(cpu, sg, (uint16_t)(o + 11));
    lf.lfStrikeOut      = mem_read8(cpu, sg, (uint16_t)(o + 12));
    lf.lfCharSet        = mem_read8(cpu, sg, (uint16_t)(o + 13));
    lf.lfOutPrecision   = mem_read8(cpu, sg, (uint16_t)(o + 14));
    lf.lfClipPrecision  = mem_read8(cpu, sg, (uint16_t)(o + 15));
    lf.lfQuality        = mem_read8(cpu, sg, (uint16_t)(o + 16));
    lf.lfPitchAndFamily = mem_read8(cpu, sg, (uint16_t)(o + 17));
    b_asciiz(cpu, sg, (uint16_t)(o + 18), lf.lfFaceName, LF_FACESIZE);
    cpu->ax = put_hgdi(CreateFontIndirectA(&lf));
    b_ret(cpu, 4);
}

static HDC draw_dc(CPU *cpu, uint16_t g, RECT b, RECT *used, int *wing);

/* GetSysColor returned 0 -- black -- for every system colour, and the engine
 * paints its own window chrome (the toy shelf's caption bar and the frames
 * round its buttons) out of them. */
void USER_GETSYSCOLOR(CPU *cpu) {              /* (nIndex@0) */
    COLORREF c = GetSysColor((int)(int16_t)b_a16(cpu, 0));
    cpu->ax = (uint16_t)(c & 0xFFFF); cpu->dx = (uint16_t)(c >> 16);
    b_ret(cpu, 2);
}

/* TextOut(hdc@10, x@8, y@6, lpString@2/4, nCount@0): exactly nCount bytes,
 * no terminator needed. */
void GDI_TEXTOUT(CPU *cpu) {
    uint16_t g = b_a16(cpu, 10);
    int x = (int16_t)b_a16(cpu, 8), y = (int16_t)b_a16(cpu, 6);
    uint16_t so = b_a16(cpu, 2), ss = b_a16(cpu, 4);
    int n = (int16_t)b_a16(cpu, 0);
    char buf[512];
    if (n < 0 || !ss) n = 0;
    if (n > (int)sizeof buf) n = sizeof buf;
    for (int i = 0; i < n; i++) buf[i] = (char)mem_read8(cpu, ss, (uint16_t)(so + i));
    /* ponytail: a generous box for a WinG target, not the measured extent */
    RECT r = { x, y - 64, x + 2048, y + 64 }, used = r; int wing = 0;
    HDC dc = n ? draw_dc(cpu, g, r, &used, &wing) : NULL;
    if (getenv("RECOMP_LOG_TEXT")) { static int k; if (k++ < 40)
        fprintf(stderr, "[text] TextOut hdc=%u (%d,%d) \"%.*s\"\n", g, x, y, n, buf); }
    cpu->ax = (uint16_t)(dc ? TextOutA(dc, x, y, buf, n) : n == 0);
    if (dc && wing) wing_draw_end(cpu, g, &used);
    b_ret(cpu, 12);
}

/* UnrealizeObject(hgdiobj): resets a brush origin or a palette's mapping;
 * Win32 does both for itself. */
void GDI_UNREALIZEOBJECT(CPU *cpu) { cpu->ax = 1; b_ret(cpu, 2); }

/* Window properties. A name whose segment is 0 is an atom (MAKEINTATOM);
 * the 16-bit data handle rides in the Win32 HANDLE. */
static LPCSTR prop_name(CPU *cpu, uint16_t seg, uint16_t off, char *buf, int max) {
    if (!seg) return (LPCSTR)(uintptr_t)off;
    b_asciiz(cpu, seg, off, buf, max);
    return buf;
}
void USER_SETPROP(CPU *cpu) {                  /* (hwnd@6, lpString@2/4, hData@0) */
    char nm[256]; HWND h = get_hwnd(b_a16(cpu, 6));
    LPCSTR p = prop_name(cpu, b_a16(cpu, 4), b_a16(cpu, 2), nm, sizeof nm);
    cpu->ax = (uint16_t)(h && SetPropA(h, p, (HANDLE)(uintptr_t)b_a16(cpu, 0)));
    b_ret(cpu, 8);
}
void USER_GETPROP(CPU *cpu) {                  /* (hwnd@4, lpString@0/2) */
    char nm[256]; HWND h = get_hwnd(b_a16(cpu, 4));
    LPCSTR p = prop_name(cpu, b_a16(cpu, 2), b_a16(cpu, 0), nm, sizeof nm);
    cpu->ax = (uint16_t)(uintptr_t)(h ? GetPropA(h, p) : NULL);
    b_ret(cpu, 6);
}
void USER_REMOVEPROP(CPU *cpu) {               /* (hwnd@4, lpString@0/2) */
    char nm[256]; HWND h = get_hwnd(b_a16(cpu, 4));
    LPCSTR p = prop_name(cpu, b_a16(cpu, 2), b_a16(cpu, 0), nm, sizeof nm);
    cpu->ax = (uint16_t)(uintptr_t)(h ? RemovePropA(h, p) : NULL);
    b_ret(cpu, 6);
}

/* DrawText(hdc@12, lpString@8/10, nCount@6, lpRect@2/4, uFormat@0) */
void USER_DRAWTEXT(CPU *cpu) {
    uint16_t g = b_a16(cpu, 12);
    uint16_t so = b_a16(cpu, 8), ss = b_a16(cpu, 10);
    int n       = (int16_t)b_a16(cpu, 6);
    uint16_t ro = b_a16(cpu, 2), rs = b_a16(cpu, 4);
    UINT fmt    = b_a16(cpu, 0);
    if (!rs || !ss) { cpu->ax = 0; b_ret(cpu, 14); return; }
    RECT r = { (int16_t)mem_read16(cpu, rs, ro),
               (int16_t)mem_read16(cpu, rs, (uint16_t)(ro + 2)),
               (int16_t)mem_read16(cpu, rs, (uint16_t)(ro + 4)),
               (int16_t)mem_read16(cpu, rs, (uint16_t)(ro + 6)) };
    char buf[512];
    int len = (n < 0) ? -1 : (n > (int)sizeof buf - 1 ? (int)sizeof buf - 1 : n);
    b_asciiz(cpu, ss, so, buf, sizeof buf);
    RECT used = r; int wing = 0;
    HDC dc = draw_dc(cpu, g, r, &used, &wing);
    if (getenv("RECOMP_LOG_TEXT")) { static int n; if (n++ < 20)
        fprintf(stderr, "[text] DrawText hdc=%u \"%s\" n=%d rect=(%ld,%ld)-(%ld,%ld) fmt=%04X\n",
            g, buf, n, (long)r.left, (long)r.top, (long)r.right, (long)r.bottom, fmt); }
    cpu->ax = (uint16_t)(dc ? DrawTextA(dc, buf, len, &r, fmt) : 0);
    if (dc && wing) wing_draw_end(cpu, g, &used);
    b_ret(cpu, 14);
}

/* A drawing call names a WinG surface as often as a real DC. Resolve either,
 * and when it is a WinG surface bracket the call so the pixels move in and
 * out of the DIB the host DC actually draws on. */
static HDC draw_dc(CPU *cpu, uint16_t g, RECT b, RECT *used, int *wing) {
    if (wing_is_dc(g)) {
        InflateRect(&b, 4, 4);            /* room for the pen */
        *used = b; *wing = 1;
        return wing_draw_begin(cpu, g, &b);
    }
    *wing = 0;
    return get_hdc(g);
}

/* The plain GDI drawing primitives. All of these were stubs returning 0, and
 * they are how the engine draws its picture sprites -- the milk bottle and the
 * cat's thought cloud among them, which is why a bottle taken off the shelf
 * vanished while the ball-based toys, drawn by the engine's own rasteriser,
 * came out fine. */
void GDI_ELLIPSE(CPU *cpu) {                   /* (hdc@8,l@6,t@4,r@2,b@0) */
    uint16_t g = b_a16(cpu, 8);
    RECT r = { (int16_t)b_a16(cpu, 6), (int16_t)b_a16(cpu, 4),
               (int16_t)b_a16(cpu, 2), (int16_t)b_a16(cpu, 0) };
    RECT used = r; int wing = 0;
    HDC dc = draw_dc(cpu, g, r, &used, &wing);
    cpu->ax = (uint16_t)(dc ? Ellipse(dc, r.left, r.top, r.right, r.bottom) : 0);
    if (dc && wing) wing_draw_end(cpu, g, &used);
    b_ret(cpu, 10);
}

void GDI_RECTANGLE(CPU *cpu) {                 /* (hdc@8,l@6,t@4,r@2,b@0) */
    uint16_t g = b_a16(cpu, 8);
    RECT r = { (int16_t)b_a16(cpu, 6), (int16_t)b_a16(cpu, 4),
               (int16_t)b_a16(cpu, 2), (int16_t)b_a16(cpu, 0) };
    RECT used = r; int wing = 0;
    HDC dc = draw_dc(cpu, g, r, &used, &wing);
    cpu->ax = (uint16_t)(dc ? Rectangle(dc, r.left, r.top, r.right, r.bottom) : 0);
    if (dc && wing) wing_draw_end(cpu, g, &used);
    b_ret(cpu, 10);
}

/* Polygon(hdc@6, lpPoints@2/4, nCount@0). Win16 POINT is two 16-bit ints. */
void GDI_POLYGON(CPU *cpu) {
    uint16_t g  = b_a16(cpu, 6);
    uint16_t po = b_a16(cpu, 2), ps = b_a16(cpu, 4);
    int n       = (int16_t)b_a16(cpu, 0);
    if (!ps || n < 2 || n > 1024) { cpu->ax = 0; b_ret(cpu, 8); return; }
    POINT *pt = malloc(sizeof(POINT) * (size_t)n);
    if (!pt) { cpu->ax = 0; b_ret(cpu, 8); return; }
    RECT r = { 0x7FFF, 0x7FFF, -0x7FFF, -0x7FFF };
    for (int i = 0; i < n; i++) {
        pt[i].x = (int16_t)mem_read16(cpu, ps, (uint16_t)(po + i * 4));
        pt[i].y = (int16_t)mem_read16(cpu, ps, (uint16_t)(po + i * 4 + 2));
        if (pt[i].x < r.left)   r.left   = pt[i].x;
        if (pt[i].x > r.right)  r.right  = pt[i].x;
        if (pt[i].y < r.top)    r.top    = pt[i].y;
        if (pt[i].y > r.bottom) r.bottom = pt[i].y;
    }
    r.right++; r.bottom++;
    RECT used = r; int wing = 0;
    HDC dc = draw_dc(cpu, g, r, &used, &wing);
    cpu->ax = (uint16_t)(dc ? Polygon(dc, pt, n) : 0);
    if (dc && wing) wing_draw_end(cpu, g, &used);
    free(pt);
    b_ret(cpu, 8);
}

/* FrameRect(hdc@6, lprc@2/4, hbr@0) */
void USER_FRAMERECT(CPU *cpu) {
    uint16_t g  = b_a16(cpu, 6);
    uint16_t ro = b_a16(cpu, 2), rs = b_a16(cpu, 4);
    HBRUSH br   = (HBRUSH)get_hgdi(b_a16(cpu, 0));
    cpu->ax = 0;
    if (rs) {
        RECT r = { (int16_t)mem_read16(cpu, rs, ro),
                   (int16_t)mem_read16(cpu, rs, (uint16_t)(ro + 2)),
                   (int16_t)mem_read16(cpu, rs, (uint16_t)(ro + 4)),
                   (int16_t)mem_read16(cpu, rs, (uint16_t)(ro + 6)) };
        RECT used = r; int wing = 0;
        HDC dc = draw_dc(cpu, g, r, &used, &wing);
        if (dc) cpu->ax = (uint16_t)FrameRect(dc, &r, br);
        if (dc && wing) wing_draw_end(cpu, g, &used);
    }
    b_ret(cpu, 8);
}

/* These three return the PREVIOUS value, which the engine saves and restores,
   so a stubbed 0 does not merely lose a colour -- it corrupts the restore. */
void GDI_SETBKCOLOR(CPU *cpu) {                /* (hdc@4, COLORREF@0) */
    uint16_t g = b_a16(cpu, 4);
    HDC dc = wing_is_dc(g) ? wing_state_dc(cpu, g) : get_hdc(g);
    COLORREF prev = dc ? SetBkColor(dc, (COLORREF)b_a32(cpu, 0)) : 0;
    cpu->ax = (uint16_t)(prev & 0xFFFF); cpu->dx = (uint16_t)(prev >> 16);
    b_ret(cpu, 6);
}

void GDI_SETTEXTCOLOR(CPU *cpu) {              /* (hdc@4, COLORREF@0) */
    uint16_t g = b_a16(cpu, 4);
    HDC dc = wing_is_dc(g) ? wing_state_dc(cpu, g) : get_hdc(g);
    COLORREF prev = dc ? SetTextColor(dc, (COLORREF)b_a32(cpu, 0)) : 0;
    cpu->ax = (uint16_t)(prev & 0xFFFF); cpu->dx = (uint16_t)(prev >> 16);
    b_ret(cpu, 6);
}

void GDI_SETBKMODE(CPU *cpu) {                 /* (hdc@2, mode@0) */
    uint16_t g = b_a16(cpu, 2);
    HDC dc = wing_is_dc(g) ? wing_state_dc(cpu, g) : get_hdc(g);
    cpu->ax = (uint16_t)(dc ? SetBkMode(dc, (int16_t)b_a16(cpu, 0)) : 0);
    b_ret(cpu, 4);
}

void GDI_PATBLT(CPU *cpu) {                    /* (hdc@12,x@10,y@8,w@6,h@4,rop@0) */
    uint16_t g = b_a16(cpu, 12);
    int x = (int16_t)b_a16(cpu, 10), y = (int16_t)b_a16(cpu, 8);
    int w = (int16_t)b_a16(cpu, 6), h = (int16_t)b_a16(cpu, 4);
    DWORD rop = b_a32(cpu, 0);
    RECT r = { x, y, x + w, y + h }, used = r; int wing = 0;
    HDC dc = draw_dc(cpu, g, r, &used, &wing);
    cpu->ax = (uint16_t)(dc ? PatBlt(dc, x, y, w, h, rop) : 0);
    if (dc && wing) wing_draw_end(cpu, g, &used);
    b_ret(cpu, 14);
}

void USER_FILLRECT(CPU *cpu) {                 /* (hdc@6, lpRect@2/4, hbr@0) */
    uint16_t g = b_a16(cpu, 6);
    uint16_t roff = b_a16(cpu, 2), rseg = b_a16(cpu, 4);
    HBRUSH br = (HBRUSH)get_hgdi(b_a16(cpu, 0));
    if (rseg && br) {
        RECT r;
        r.left   = (int16_t)mem_read16(cpu, rseg, roff);
        r.top    = (int16_t)mem_read16(cpu, rseg, (uint16_t)(roff + 2));
        r.right  = (int16_t)mem_read16(cpu, rseg, (uint16_t)(roff + 4));
        r.bottom = (int16_t)mem_read16(cpu, rseg, (uint16_t)(roff + 6));
        RECT used = r; int wing = 0;
        HDC dc = draw_dc(cpu, g, r, &used, &wing);
        if (dc) FillRect(dc, &r, br);
        if (dc && wing) wing_draw_end(cpu, g, &used);
    }
    cpu->ax = 1;
    b_ret(cpu, 8);
}

/* SetViewportOrgEx(hdc, X, Y, lpPoint) sets the DC's viewport origin and hands
 * the PREVIOUS one back through lpPoint. XDrawPort::XCopyBits uses it exactly
 * that way: it zeroes the origin, then offsets its destination rect by the old
 * value so the rect is in device coordinates for the WinG blit that follows.
 *
 * As a stub this popped its arguments and wrote nothing, so lpPoint kept
 * whatever was on the stack -- and the engine offset the pet's destination rect
 * by that junk. It sat next to the rect locals, so the garbage was usually the
 * previous rect's bottom: the pet was stamped `bottom` pixels too low, by a
 * different amount every frame as the frame height changed, which is what
 * smeared cat faces across the screen. */
/* The remaining out-parameter APIs the engine reaches. A stub that pops its
 * arguments but never writes through its pointer leaves the caller reading its
 * own stack -- that is how SetViewportOrgEx smeared the pet across the screen,
 * so fill these in rather than leave the same trap set. */
void GDI_GETOBJECT(CPU *cpu) {             /* (hgdiobj@6, cb@4, lpv@0/2) */
    HGDIOBJ o = get_hgdi(b_a16(cpu, 6));
    int cb = (int16_t)b_a16(cpu, 4);
    uint16_t off = b_a16(cpu, 0), seg = b_a16(cpu, 2);
    BITMAP bm;
    if (o && seg && cb >= 14 && GetObject(o, sizeof bm, &bm)) {
        /* Win16 BITMAP: bmType, bmWidth, bmHeight, bmWidthBytes (int16 each),
           bmPlanes, bmBitsPixel (bytes), bmBits (far pointer). */
        mem_write16(cpu, seg, off,                    (uint16_t)bm.bmType);
        mem_write16(cpu, seg, (uint16_t)(off + 2),    (uint16_t)bm.bmWidth);
        mem_write16(cpu, seg, (uint16_t)(off + 4),    (uint16_t)bm.bmHeight);
        mem_write16(cpu, seg, (uint16_t)(off + 6),    (uint16_t)bm.bmWidthBytes);
        mem_write8 (cpu, seg, (uint16_t)(off + 8),    (uint8_t)bm.bmPlanes);
        mem_write8 (cpu, seg, (uint16_t)(off + 9),    (uint8_t)bm.bmBitsPixel);
        mem_write16(cpu, seg, (uint16_t)(off + 10),   0);
        mem_write16(cpu, seg, (uint16_t)(off + 12),   0);
        cpu->ax = 14;
    } else {
        cpu->ax = 0;
    }
    b_ret(cpu, 8);
}

void MMSYSTEM_TIMEGETDEVCAPS(CPU *cpu) {   /* (lpTimeCaps@2/4, cb@0) */
    uint16_t off = b_a16(cpu, 2), seg = b_a16(cpu, 4);
    if (seg) {                              /* TIMECAPS { wPeriodMin, wPeriodMax } */
        mem_write16(cpu, seg, off, 1);
        mem_write16(cpu, seg, (uint16_t)(off + 2), 0xFFFF);
    }
    cpu->ax = 0;                            /* TIMERR_NOERROR */
    b_ret(cpu, 6);
}

void USER_GETDLGITEMINT(CPU *cpu) {        /* (hwnd@8, id@6, lpXlated@2/4, sgn@0) */
    uint16_t off = b_a16(cpu, 2), seg = b_a16(cpu, 4);
    if (seg) mem_write16(cpu, seg, off, 0); /* not translated */
    cpu->ax = 0;
    b_ret(cpu, 10);
}

/* GetCursorPos(LPPOINT) is another out-parameter API the engine calls every
 * frame -- it is how the pet knows where the mouse is. As a stub it wrote
 * nothing, so the engine read whatever was on the stack as the cursor position.
 * Report it in the same space as the DC we hand out for GetDC(NULL): the pet
 * overlay window's client area. */
void USER_GETCURSORPOS(CPU *cpu) {         /* (lpPoint@0/2) */
    uint16_t off = b_a16(cpu, 0), seg = b_a16(cpu, 2);
    POINT p = { 0, 0 };
    /* RECOMP_CURSOR=x,y pins the pointer where the engine thinks it is, so a
       click can be aimed at a widget without commandeering the real mouse. */
    const char *fc = getenv("RECOMP_CURSOR");
    char fbuf[64];
    if (fc && fc[0] == '@') {                 /* @path: re-read, so a drag can move */
        FILE *cf = fopen(fc + 1, "r");
        fbuf[0] = 0;
        if (cf) { if (!fgets(fbuf, sizeof fbuf, cf)) fbuf[0] = 0; fclose(cf); }
        fc = fbuf[0] ? fbuf : NULL;
    }
    if (fc) {
        p.x = atoi(fc);
        const char *c = strchr(fc, ',');
        p.y = c ? atoi(c + 1) : 0;
    } else {
        GetCursorPos(&p);
        HWND h = g_screen_hwnd ? g_screen_hwnd : g_main_hwnd;
        POINT raw = p;
        if (h) ScreenToClient(h, &p);
        /* The coordinate frame the engine hit-tests in. If this does not match
           where the playpen is actually drawn, every click lands somewhere
           other than where the pointer is. */
        if (getenv("RECOMP_LOG_CURSOR")) {
            static int n; static POINT last;
            if (n < 6 || raw.x != last.x || raw.y != last.y) {
                RECT wr = {0}, cr = {0}; POINT org = {0,0};
                if (h) { GetWindowRect(h, &wr); GetClientRect(h, &cr);
                         ClientToScreen(h, &org); }
                if (n < 30) fprintf(stderr,
                    "[cursor] screen(%ld,%ld) -> client(%ld,%ld) | win(%ld,%ld)-(%ld,%ld)"
                    " client=%ldx%ld origin(%ld,%ld)\n",
                    raw.x, raw.y, p.x, p.y, wr.left, wr.top, wr.right, wr.bottom,
                    cr.right, cr.bottom, org.x, org.y);
                n++; last = raw;
            }
        }
    }
    if (seg) {
        mem_write16(cpu, seg, off, (uint16_t)(int16_t)p.x);
        mem_write16(cpu, seg, (uint16_t)(off + 2), (uint16_t)(int16_t)p.y);
    }
    cpu->ax = 0;
    b_ret(cpu, 4);
}

void GDI_SETVIEWPORTORGEX(CPU *cpu) {      /* (hdc@8, X@6, Y@4, lpPoint@0/2) */
    /* The engine sets the origin on its WinG draw ports and keeps the value it
       gets back so it can restore it. A WinG DC is not in the host handle table,
       so this used to resolve to NULL: the set was dropped and the caller was
       handed (0,0) as the previous origin. With one sprite live that was
       survivable; with the mouse out as well, each sprite restored the other's
       origin as zero and their patches went to the wrong place. */
    uint16_t g0 = b_a16(cpu, 8);
    HDC dc = wing_is_dc(g0) ? wing_state_dc(cpu, g0) : get_hdc(g0);
    int x = (int16_t)b_a16(cpu, 6), y = (int16_t)b_a16(cpu, 4);
    uint16_t off = b_a16(cpu, 0), seg = b_a16(cpu, 2);
    POINT old = { 0, 0 };
    if (dc) SetViewportOrgEx(dc, x, y, &old);
    if (seg) {
        mem_write16(cpu, seg, off, (uint16_t)(int16_t)old.x);
        mem_write16(cpu, seg, (uint16_t)(off + 2), (uint16_t)(int16_t)old.y);
    }
    cpu->ax = 1;
    b_ret(cpu, 10);
}

void USER_GETDC(CPU *cpu) {
    uint16_t gw = b_a16(cpu, 0);
    HWND h = get_hwnd(gw);
    /* GetDC(NULL) is the SCREEN dc, not an error -- and it is what the engine
     * asks for: Catz walk on the desktop, so OpenScreenDrawPort wants the real
     * screen. Rejecting it left that port with no DC and every frame reported
     * "Closing already closed screen DC" instead of blitting.
     *
     * Painting the desktop directly is genuine Catz behaviour but it scribbles
     * over whatever else is on screen, so keep the pet inside the playpen window
     * by default and hand back the frame window's DC. Set RECOMP_DESKTOP=1 for the
     * original loose-on-the-desktop behaviour. */
    if (!gw && !getenv("RECOMP_DESKTOP")) {
        HWND alt = g_screen_hwnd ? g_screen_hwnd : g_main_hwnd;
        if (alt) h = alt;
    }
    HDC dc = GetDC(h);
    cpu->ax = dc ? put_hdc(dc) : 0;
    b_ret(cpu, 2);
}

/* BeginPaint/EndPaint. As stubs these returned a null HDC, so the engine's
 * WM_PAINT handler bailed AND the update region was never validated -- Windows
 * re-posted WM_PAINT forever and the engine did nothing else. Win16 PAINTSTRUCT
 * is 16-bit throughout: hdc@0, fErase@2, rcPaint@4 (4 x int16), fRestore@12,
 * fIncUpdate@14, rgbReserved@16..31. */
/* InvalidateRect is how the engine asks for its next frame. As a stub it did
 * nothing, so after the initial paints the window was never dirtied again and
 * the engine sat in GetMessage forever. NULL lpRect means the whole client. */
/* The engine's frame clock. As a stub returning 0 it created no timer, so after
 * init the engine sat in GetMessage with nothing ever waking it -- everything
 * ran once and then stopped. A NULL lpTimerFunc means "post WM_TIMER to the
 * window", which the WndProc bridge already delivers; a non-NULL one would need
 * a callback thunk, so say so rather than silently dropping it. */
/* The engine drives its own frame pipeline by posting WM_RECOMP_WINTERFACE to its
 * parent window on every timer tick, so a stubbed PostMessage means the pipeline
 * never advances past the tick that requests it. */
/* DialogBoxParam. The Catz playpen IS a dialog: the engine's whole frame
 * pipeline -- its own SetTimer, its WM_TIMER tick and its WM_PAINT (the one that
 * blits the WinG surface) -- lives in the DLGPROC passed here, not in the host
 * shell's WNDPROC. The old stub returned 0 immediately, so WM_INITDIALOG never
 * fired, the engine's timer was never created, and nothing ever rendered; the
 * caller (seg062_07B6) just re-created the dialog forever.
 *
 * ponytail: the Win16 DLGTEMPLATE is not converted to a Win32 one, so the
 * dialog is created as a plain window running the guest DLGPROC and no child
 * controls exist. That is enough for the playpen, which draws itself; add real
 * template conversion when a dialog's controls have to be interacted with.
 * Modal, per Win16: it pumps the whole queue until EndDialog. */
static int      g_dlg_depth;
static int      g_dlg_ended[8];
static uint16_t g_dlg_result[8];
static HWND     g_dlg_hwnd[8];

/* Dialog item text. No child controls exist (no template conversion), so the
 * engine's SetDlgItemText went nowhere and the matching GetDlgItemText came back
 * empty -- which is why the startup wizard's name screen never validated and
 * re-showed itself forever. Keep the text in a small store so it round-trips
 * exactly as a real edit control would. */
#define MAXDLGTXT 64
typedef struct { uint16_t hdlg, id; char text[128]; } DlgText;
static DlgText g_dlgtxt[MAXDLGTXT];
static int g_ndlgtxt;

static DlgText *dlgtxt(uint16_t hdlg, uint16_t id, int create) {
    for (int i = 0; i < g_ndlgtxt; i++)
        if (g_dlgtxt[i].hdlg == hdlg && g_dlgtxt[i].id == id) return &g_dlgtxt[i];
    if (!create || g_ndlgtxt >= MAXDLGTXT) return NULL;
    DlgText *t = &g_dlgtxt[g_ndlgtxt++];
    t->hdlg = hdlg; t->id = id; t->text[0] = 0;
    return t;
}

void USER_SETDLGITEMTEXT(CPU *cpu) {         /* (hDlg@6, nIDDlgItem@4, lpString@0/2) */
    uint16_t hdlg = b_a16(cpu, 6), id = b_a16(cpu, 4);
    uint16_t soff = b_a16(cpu, 0), sseg = b_a16(cpu, 2);
    char buf[128] = "";
    if (sseg) b_asciiz(cpu, sseg, soff, buf, sizeof buf);
    HWND c = GetDlgItem(get_hwnd(hdlg), id);
    if (c) SetWindowTextA(c, buf);            /* a real control now exists */
    DlgText *t = dlgtxt(hdlg, id, 1);         /* mirror it for items that do not */
    if (t) snprintf(t->text, sizeof t->text, "%s", buf);
    cpu->ax = 1;
    b_ret(cpu, 8);
}

void USER_GETDLGITEMTEXT(CPU *cpu) {         /* (hDlg@8, nID@6, lpString@2/4, nMax@0) */
    uint16_t hdlg = b_a16(cpu, 8), id = b_a16(cpu, 6);
    uint16_t soff = b_a16(cpu, 2), sseg = b_a16(cpu, 4);
    uint16_t nmax = b_a16(cpu, 0);
    char live[128] = "";
    HWND c = GetDlgItem(get_hwnd(hdlg), id);
    if (c) GetWindowTextA(c, live, sizeof live);
    DlgText *t = dlgtxt(hdlg, id, 0);
    const char *src = live[0] ? live : (t ? t->text : "");
    uint16_t n = 0;
    if (sseg && nmax) {
        for (; src[n] && n + 1 < nmax; n++)
            mem_write8(cpu, sseg, (uint16_t)(soff + n), (uint8_t)src[n]);
        mem_write8(cpu, sseg, (uint16_t)(soff + n), 0);
    }
    cpu->ax = n;
    b_ret(cpu, 10);
}

void USER_GETDLGITEM(CPU *cpu) {             /* (hDlg@2, nIDDlgItem@0) */
    /* No real control window, but returning 0 makes callers treat the item as
     * missing and bail. Hand back a stable non-zero pseudo-handle per id. */
    uint16_t hdlg = b_a16(cpu, 2), id = b_a16(cpu, 0);
    HWND c = GetDlgItem(get_hwnd(hdlg), id);
    cpu->ax = c ? put_hwnd(c) : (uint16_t)(0xD000 | (id & 0x0FFF));
    b_ret(cpu, 4);
}

void USER_ENDDIALOG(CPU *cpu) {
    HWND h        = get_hwnd(b_a16(cpu, 2));   /* hDlg@2 */
    uint16_t code = b_a16(cpu, 0);             /* nResult@0 */
    for (int i = g_dlg_depth - 1; i >= 0; i--) {
        if (h && g_dlg_hwnd[i] != h) continue;
        g_dlg_ended[i] = 1; g_dlg_result[i] = code;
        break;
    }
    fprintf(stderr, "[win32] EndDialog(result=%u)\n", code);
    cpu->ax = 1;
    b_ret(cpu, 4);
}

/* ---- Win16 DLGTEMPLATE -> real child controls ----
 * Rather than repack the template into a Win32 DLGTEMPLATE (aligned, Unicode,
 * a different layout end to end), parse the Win16 one and create each item with
 * CreateWindowEx against the matching predefined class. The dialog window itself
 * is ours already, so this is all that was missing: with no controls the engine
 * could set no text, read none back, and no button could ever be pressed.
 *
 *   DLGTEMPLATE: DWORD style; BYTE nItems; WORD x,y,cx,cy;
 *                sz menu; sz class; sz caption;
 *                [DS_SETFONT: WORD pointSize; sz typeface]
 *   DLGITEMTEMPLATE: WORD x,y,cx,cy; WORD id; DWORD style;
 *                    class (sz, or one byte 0x80..0x85); sz text; BYTE cbExtra
 */
#define DS_SETFONT_W16 0x40

static const uint8_t *w16_sz(const uint8_t *p, const uint8_t *end, char *out, int max) {
    int i = 0;
    while (p < end && *p) { if (i < max - 1) out[i++] = (char)*p; p++; }
    out[i] = 0;
    return (p < end) ? p + 1 : end;
}

static const char *w16_ctl_class(uint8_t ord) {
    switch (ord) {
        case 0x80: return "Button";
        case 0x81: return "Edit";
        case 0x82: return "Static";
        case 0x83: return "ListBox";
        case 0x84: return "ScrollBar";
        case 0x85: return "ComboBox";
        default:   return NULL;
    }
}

/* Returns the dialog's own size in dialog units converted to pixels, or 0. */
static int dlg_build(CPU *cpu, uint16_t hinst, uint16_t tmpl, HWND dlg,
                     int *out_w, int *out_h, char *cap, int capsz) {
    uint16_t hr = ne_find_resource(hinst, 5 /* RT_DIALOG */, NULL, (int)tmpl, NULL);
    uint32_t len = 0;
    const uint8_t *p = hr ? ne_resource_bytes(hr, &len) : NULL;
    if (!p || len < 14) return 0;
    const uint8_t *end = p + len;

    uint32_t style = (uint32_t)p[0] | ((uint32_t)p[1] << 8)
                   | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    int nitems = p[4];
    int cx = p[9] | (p[10] << 8), cy = p[11] | (p[12] << 8);
    p += 13;

    char buf[128];
    p = w16_sz(p, end, buf, sizeof buf);          /* menu    */
    p = w16_sz(p, end, buf, sizeof buf);          /* class   */
    p = w16_sz(p, end, cap, capsz);               /* caption */
    int pt = 0;
    char face[LF_FACESIZE] = "";
    if (style & DS_SETFONT_W16) {
        if (p + 2 <= end) { pt = p[0] | (p[1] << 8); p += 2; }   /* point size */
        p = w16_sz(p, end, face, sizeof face);                    /* typeface   */
    }

    /* Dialog units -> pixels. A template with its own font is laid out in THAT
     * font's units, as Windows does it: average width of the alphabet and the
     * font's height. The system dialog units of a modern Windows (8x16) made
     * Oddballz's 338x253-unit intro 676x506 -- bigger than the 640x480 screen
     * it was designed for, with its Next/Exit buttons off the bottom. At 8 pt
     * MS Sans Serif the same template is about 507x411. */
    LONG bu = GetDialogBaseUnits();
    int bux = LOWORD(bu), buy = HIWORD(bu);
    HFONT font = NULL;
    if (pt > 0 && face[0]) {
        HDC sdc = GetDC(NULL);
        font = CreateFontA(-MulDiv(pt, 96, 72), 0, 0, 0, FW_NORMAL, 0, 0, 0,
                           DEFAULT_CHARSET, 0, 0, DEFAULT_QUALITY, 0, face);
        HGDIOBJ old = SelectObject(sdc, font);
        SIZE sz; TEXTMETRICA tm;
        static const char az[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        if (GetTextExtentPoint32A(sdc, az, 52, &sz) && GetTextMetricsA(sdc, &tm)) {
            bux = (sz.cx / 26 + 1) / 2;
            buy = tm.tmHeight;
        }
        SelectObject(sdc, old);
        ReleaseDC(NULL, sdc);
    }
    *out_w = cx * bux / 4;
    *out_h = cy * buy / 8;

    int made = 0;
    for (int i = 0; i < nitems && p + 14 <= end; i++) {
        int ix = p[0] | (p[1] << 8), iy = p[2] | (p[3] << 8);
        int iw = p[4] | (p[5] << 8), ih = p[6] | (p[7] << 8);
        uint16_t id = (uint16_t)(p[8] | (p[9] << 8));
        uint32_t istyle = (uint32_t)p[10] | ((uint32_t)p[11] << 8)
                        | ((uint32_t)p[12] << 16) | ((uint32_t)p[13] << 24);
        p += 14;

        char cls[64] = "", text[128] = "";
        if (p < end && *p >= 0x80 && *p <= 0x85) {
            const char *k = w16_ctl_class(*p);
            snprintf(cls, sizeof cls, "%s", k ? k : "Static");
            p++;
        } else {
            p = w16_sz(p, end, cls, sizeof cls);
        }
        p = w16_sz(p, end, text, sizeof text);
        if (p < end) p += 1 + *p;                 /* cbExtra + creation data */

        HWND c = CreateWindowExA(0, cls, text,
                                 (DWORD)(istyle | WS_CHILD) & ~(DWORD)WS_POPUP,
                                 ix * bux / 4, iy * buy / 8,
                                 iw * bux / 4, ih * buy / 8,
                                 dlg, (HMENU)(UINT_PTR)id,
                                 GetModuleHandle(NULL), NULL);
        if (c) made++;
        /* The controls use the template font too, or their text overflows the
           rectangles it laid out. ponytail: one font per dialog, never freed;
           a handful per session. */
        if (c && font) SendMessageA(c, WM_SETFONT, (WPARAM)font, FALSE);
    }
    fprintf(stderr, "[win32] dialog %u template: %d/%d controls, %dx%d dlgunits "
                    "-> %dx%d px\n", tmpl, made, nitems, cx, cy, *out_w, *out_h);
    return 1;
}

/* Modeless dialogs. CreateDialog and CreateDialogParam were stubs returning 0,
 * and every Options entry that ends in "..." -- General Options, CatNapz
 * Options, Choose Another Kitten, Create Adoption Kit -- opens one. They
 * highlighted and did nothing. Same construction as the modal path, minus the
 * message pump: build the window from the template, run WM_INITDIALOG, show it
 * and hand the handle back.
 *
 * Win16: HWND CreateDialogParam(HINSTANCE@14, lpTemplate@10/12, hWndParent@8,
 *                               lpDialogFunc@4/6, dwInitParam@0) */
static void create_dialog_common(CPU *cpu, int purge, uint32_t param) {
    /* CreateDialog has no dwInitParam, so its whole argument list sits four
       bytes lower than CreateDialogParam's. */
    int k = (purge == 16) ? 0 : 4;
    uint16_t tmpl = b_a16(cpu, 10 - k);
    HWND parent   = get_hwnd(b_a16(cpu, 8 - k));
    uint16_t poff = b_a16(cpu, 4 - k), pseg = b_a16(cpu, 6 - k);
    if (!pseg) { cpu->ax = 0; b_ret(cpu, purge); return; }

    const char *hostcls = g_ncls ? g_cls[0].name : "RecompGuestCls0";
    HWND h = CreateWindowExA(0, hostcls, "Catz", WS_OVERLAPPEDWINDOW,
                             CW_USEDEFAULT, CW_USEDEFAULT, 470, 370,
                             NULL, NULL, GetModuleHandle(NULL), NULL);
    uint16_t gh = 0;
    if (h) {
        int tw = 0, th = 0;
        char cap[128] = "";
        if (dlg_build(cpu, b_a16(cpu, 14 - k), tmpl, h, &tw, &th, cap, sizeof cap)
                && tw > 16 && th > 16) {
            if (cap[0]) SetWindowTextA(h, cap);
            RECT want = { 0, 0, tw, th };
            AdjustWindowRect(&want, WS_OVERLAPPEDWINDOW, FALSE);
            SetWindowPos(h, NULL, 0, 0, want.right - want.left,
                         want.bottom - want.top, SWP_NOMOVE | SWP_NOZORDER);
        }
        gh = put_hwnd(h);
        if (gh) { g_hwnd_proc_seg[gh] = pseg; g_hwnd_proc_off[gh] = poff; }
        /* Honour the template's WS_VISIBLE rather than forcing the window up:
           the engine creates its shelf panel this way and shows it itself. */
        call_guest_wndproc(pseg, poff, gh, 0x0110 /* WM_INITDIALOG */, gh, param);
        if (GetWindowLongA(h, GWL_STYLE) & WS_VISIBLE) {
            ShowWindow(h, SW_SHOW);
            UpdateWindow(h);
        }
        fprintf(stderr, "[win32] CreateDialog(template=%u dlgproc=seg%u:%04X)"
                        " -> hwnd=%p guest=%u\n",
                tmpl, pseg, poff, (void *)h, gh);
    }
    (void)parent;
    cpu->ax = gh;
    b_ret(cpu, purge);
}

void USER_CREATEDIALOG(CPU *cpu)      { create_dialog_common(cpu, 12, 0); }
void USER_CREATEDIALOGPARAM(CPU *cpu) { create_dialog_common(cpu, 16, b_a32(cpu, 0)); }

void USER_DIALOGBOXPARAM(CPU *cpu) {
    uint16_t tmpl  = b_a16(cpu, 10);           /* lpTemplateName@10/12 (an id) */
    HWND parent    = get_hwnd(b_a16(cpu, 8));  /* hWndParent@8 */
    uint16_t poff  = b_a16(cpu, 4);            /* lpDialogFunc@4/6 */
    uint16_t pseg  = b_a16(cpu, 6);
    uint32_t param = b_a32(cpu, 0);            /* dwInitParam@0 */

    if (g_dlg_depth >= (int)(sizeof g_dlg_ended / sizeof g_dlg_ended[0]) || !pseg) {
        cpu->ax = 0; b_ret(cpu, 16); return;
    }
    int d = g_dlg_depth++;
    g_dlg_ended[d] = 0; g_dlg_result[d] = 0;

    RECT rc = { 0, 0, 470, 370 };
    if (parent) GetClientRect(parent, &rc);
    if (rc.right - rc.left < 16 || rc.bottom - rc.top < 16) { rc.right = 470; rc.bottom = 370; }

    const char *hostcls = g_ncls ? g_cls[0].name : "RecompGuestCls0";
    HWND h = CreateWindowExA(0, hostcls, "Catz", WS_OVERLAPPEDWINDOW,
                             CW_USEDEFAULT, CW_USEDEFAULT,
                             rc.right - rc.left, rc.bottom - rc.top,
                             NULL, NULL, GetModuleHandle(NULL), NULL);
    if (h) {
        int tw = 0, th = 0;
        char cap[128] = "";
        if (dlg_build(cpu, b_a16(cpu, 14), tmpl, h, &tw, &th, cap, sizeof cap)
                && tw > 16 && th > 16) {
            if (cap[0]) SetWindowTextA(h, cap);
            RECT want = { 0, 0, tw, th };
            AdjustWindowRect(&want, WS_OVERLAPPEDWINDOW, FALSE);
            SetWindowPos(h, NULL, 0, 0, want.right - want.left, want.bottom - want.top,
                         SWP_NOMOVE | SWP_NOZORDER);
        }
    }
    uint16_t gh = h ? put_hwnd(h) : 0;
    if (gh) { g_hwnd_proc_seg[gh] = pseg; g_hwnd_proc_off[gh] = poff; }
    g_dlg_hwnd[d] = h;
    fprintf(stderr, "[win32] DialogBoxParam(template=%u dlgproc=seg%u:%04X) "
                    "-> hwnd=%p guest=%u %dx%d\n",
            tmpl, pseg, poff, (void *)h, gh,
            (int)(rc.right - rc.left), (int)(rc.bottom - rc.top));

    if (h) {
        ShowWindow(h, SW_SHOW);
        /* WM_INITDIALOG is what the engine hangs its whole setup off. */
        call_guest_wndproc(pseg, poff, gh, 0x0110, gh, param);
        UpdateWindow(h);
        /* Bring-up knob: with no dialog controls nothing can press a button, so
           RECOMP_DLG_RESULT lets a run answer every dialog with one code and walk
           the startup wizard forward (0x7D4 is its "Next"). Off by default. */
        const char *forced = getenv("RECOMP_DLG_RESULT");
        if (forced) {
            /* Comma-separated: one answer per dialog shown, in order; the last
               value repeats. Enough to script a walk through the wizard. */
            static int seen = 0;
            const char *q = forced;
            for (int k = 0; k < seen; k++) {
                const char *c = strchr(q, (int)44);
                if (!c) break;
                q = c + 1;
            }
            seen++;
            long ans = strtol(q, NULL, 0);
            if (ans < 0) {          /* -1: leave this one for a real click */
                fprintf(stderr, "[win32] dialog %u left interactive\n", tmpl);
            } else {
                g_dlg_ended[d] = 1;
                g_dlg_result[d] = (uint16_t)ans;
                fprintf(stderr, "[win32] dialog %u auto-answered %u\n",
                        tmpl, g_dlg_result[d]);
            }
        }
        MSG m;
        while (!g_dlg_ended[d] && GetMessageA(&m, NULL, 0, 0)) {
            TranslateMessage(&m);
            DispatchMessageA(&m);
        }
        fprintf(stderr, "[win32] dialog loop exit: ended=%d (0 means WM_QUIT)\n",
                g_dlg_ended[d]);
        DestroyWindow(h);
    }
    g_dlg_depth--;
    cpu->ax = h ? g_dlg_result[d] : 0;
    b_ret(cpu, 16);
}

void USER_POSTMESSAGE(CPU *cpu) {
    HWND h        = get_hwnd(b_a16(cpu, 8));   /* hWnd@8 */
    uint16_t msg  = b_a16(cpu, 6);             /* uMsg@6 */
    uint16_t wp   = b_a16(cpu, 4);             /* wParam@4 */
    uint32_t lp   = ((uint32_t)b_a16(cpu, 2) << 16) | b_a16(cpu, 0);  /* lParam@0/2 */
    BOOL ok = h ? PostMessageA(h, msg, wp, (LPARAM)lp) : FALSE;
    if (getenv("RECOMP_LOG_POST")) { static int n;
        int at = atoi(getenv("RECOMP_LOG_POST"));
        if (++n == at) {            /* dump who is driving the post at this point */
            extern const char *g_fn_ring[]; extern unsigned g_fn_ring_pos;
            fprintf(stderr, "[postring] post #%d msg=%04X wp=%u lp=%08X, last 40 calls:\n",
                    n, msg, wp, lp);
            extern void dump_guest_stack(CPU *, int);
            dump_guest_stack(cpu, 64);
            fflush(stderr);
        }
    }
    cpu->ax = (uint16_t)(ok ? 1 : 0);
    b_ret(cpu, 10);
}

void USER_SETTIMER(CPU *cpu) {
    HWND h        = get_hwnd(b_a16(cpu, 8));   /* hWnd@8 */
    uint16_t id   = b_a16(cpu, 6);             /* nIDEvent@6 */
    uint16_t ms   = b_a16(cpu, 4);             /* uElapse@4 */
    uint16_t pseg = b_a16(cpu, 2);             /* lpTimerFunc@0/2 */
    if (pseg)
        fprintf(stderr, "[win16] *** SetTimer with a TIMERPROC (%04X) - "
                        "callback thunk not implemented, using WM_TIMER\n", pseg);
    /* Win16 timers run off the PC's 18.2 Hz tick, so SetTimer rounds the period
     * UP to a multiple of 54.925 ms and can go no faster. The engine asks for
     * 10 ms and got exactly that here, running the pet at ~100 Hz instead of
     * the ~18 it was written for -- the cat tore around the playpen. Round the
     * way KERNEL did. */
    UINT period = ms ? (UINT)(((ms + 54) / 55) * 55) : 55;
    UINT_PTR t = h ? SetTimer(h, id, period, NULL) : 0;
    fprintf(stderr, "[win32] SetTimer(id=%u, %ums -> %ums tick) -> %u\n",
            id, ms, period, (unsigned)t);
    cpu->ax = (uint16_t)t;
    b_ret(cpu, 10);
}

void USER_KILLTIMER(CPU *cpu) {
    HWND h      = get_hwnd(b_a16(cpu, 2));     /* hWnd@2 */
    uint16_t id = b_a16(cpu, 0);               /* nIDEvent@0 */
    if (h) KillTimer(h, id);
    cpu->ax = 1;
    b_ret(cpu, 4);
}

void USER_INVALIDATERECT(CPU *cpu) {
    HWND h = get_hwnd(b_a16(cpu, 6));                    /* hWnd@6 */
    uint16_t roff = b_a16(cpu, 2), rseg = b_a16(cpu, 4); /* lpRect@2/4 */
    BOOL erase = (BOOL)(int16_t)b_a16(cpu, 0);           /* bErase@0 */
    RECT r;
    if (rseg) {
        r.left   = (int16_t)mem_read16(cpu, rseg, roff);
        r.top    = (int16_t)mem_read16(cpu, rseg, (uint16_t)(roff + 2));
        r.right  = (int16_t)mem_read16(cpu, rseg, (uint16_t)(roff + 4));
        r.bottom = (int16_t)mem_read16(cpu, rseg, (uint16_t)(roff + 6));
    }
    if (h) InvalidateRect(h, rseg ? &r : NULL, erase);
    cpu->ax = 1;
    b_ret(cpu, 8);
}

/* timeGetTime -> DX:AX milliseconds. Returning 0 made every elapsed-time test
 * see no time passing, so nothing animated. Shares USER_GETTICKCOUNT's clock
 * so the engine's two time sources cannot disagree. */
void MMSYSTEM_TIMEGETTIME(CPU *cpu) {
    extern uint32_t recomp_tick_ms(void);
    uint32_t t = recomp_tick_ms();
    cpu->ax = (uint16_t)t; cpu->dx = (uint16_t)(t >> 16);
    b_ret(cpu, 0);
}

void USER_BEGINPAINT(CPU *cpu) {
    HWND h = get_hwnd(b_a16(cpu, 4));                    /* hWnd@4 */
    uint16_t poff = b_a16(cpu, 0), pseg = b_a16(cpu, 2); /* lpPaint@0/2 */
    PAINTSTRUCT ps;
    HDC dc = h ? BeginPaint(h, &ps) : NULL;
    uint16_t gdc = dc ? put_hdc(dc) : 0;
    if (pseg) {
        const int16_t f[8] = {
            (int16_t)gdc, (int16_t)(dc ? ps.fErase : 0),
            (int16_t)ps.rcPaint.left,  (int16_t)ps.rcPaint.top,
            (int16_t)ps.rcPaint.right, (int16_t)ps.rcPaint.bottom,
            0, 0,
        };
        for (int i = 0; i < 8; i++)
            mem_write16(cpu, pseg, (uint16_t)(poff + 2 * i), (uint16_t)f[i]);
        for (int i = 16; i < 32; i++)
            mem_write8(cpu, pseg, (uint16_t)(poff + i), 0);
    }
    cpu->ax = gdc;
    b_ret(cpu, 6);
}

void USER_ENDPAINT(CPU *cpu) {
    HWND h = get_hwnd(b_a16(cpu, 4));
    uint16_t poff = b_a16(cpu, 0), pseg = b_a16(cpu, 2);
    PAINTSTRUCT ps;
    memset(&ps, 0, sizeof ps);
    if (pseg) {
        ps.hdc          = get_hdc(mem_read16(cpu, pseg, poff));
        ps.fErase       = (BOOL)(int16_t)mem_read16(cpu, pseg, (uint16_t)(poff + 2));
        ps.rcPaint.left = (int16_t)mem_read16(cpu, pseg, (uint16_t)(poff + 4));
        ps.rcPaint.top  = (int16_t)mem_read16(cpu, pseg, (uint16_t)(poff + 6));
        ps.rcPaint.right  = (int16_t)mem_read16(cpu, pseg, (uint16_t)(poff + 8));
        ps.rcPaint.bottom = (int16_t)mem_read16(cpu, pseg, (uint16_t)(poff + 10));
    }
    if (h) EndPaint(h, &ps);
    if (pseg) free_hdc(mem_read16(cpu, pseg, poff));
    cpu->ax = 1;
    b_ret(cpu, 6);
}

void USER_RELEASEDC(CPU *cpu) {
    uint16_t gdc = b_a16(cpu, 0);   /* HWND@2, HDC@0 */
    HWND h = get_hwnd(b_a16(cpu, 2));
    HDC dc = get_hdc(gdc);
    if (h && dc) ReleaseDC(h, dc);
    free_hdc(gdc);
    cpu->ax = 1; b_ret(cpu, 4);
}

/* ===== USER: message loop ===== */

/* Win16 MSG: hwnd@0(2) message@2(2) wParam@4(2) lParam@6(4) time@10(4) pt@14(4) */
static void write_msg(CPU *cpu, uint16_t mseg, uint16_t moff, const MSG *m) {
    mem_write16(cpu, mseg, (uint16_t)(moff +  0), put_hwnd(m->hwnd));
    mem_write16(cpu, mseg, (uint16_t)(moff +  2), (uint16_t)m->message);
    mem_write16(cpu, mseg, (uint16_t)(moff +  4), (uint16_t)m->wParam);
    mem_write16(cpu, mseg, (uint16_t)(moff +  6), (uint16_t)(m->lParam & 0xFFFF));
    mem_write16(cpu, mseg, (uint16_t)(moff +  8), (uint16_t)(m->lParam >> 16));
    mem_write16(cpu, mseg, (uint16_t)(moff + 10), (uint16_t)(m->time & 0xFFFF));
    mem_write16(cpu, mseg, (uint16_t)(moff + 12), (uint16_t)(m->time >> 16));
    mem_write16(cpu, mseg, (uint16_t)(moff + 14), (uint16_t)(int16_t)m->pt.x);
    mem_write16(cpu, mseg, (uint16_t)(moff + 16), (uint16_t)(int16_t)m->pt.y);
}

void USER_GETMESSAGE(CPU *cpu) {
    /* GetMessage(LPMSG@2/4, HWND@.., UINT, UINT) -> BOOL. Pump real messages. */
    uint16_t moff = b_a16(cpu, 6), mseg = b_a16(cpu, 8);
    HWND filt     = get_hwnd(b_a16(cpu, 4));
    UINT lo       = b_a16(cpu, 2), hi = b_a16(cpu, 0);
    MSG m;
    BOOL r = GetMessageA(&m, filt, lo, hi);
    if (r) write_msg(cpu, mseg, moff, &m);
    cpu->ax = (uint16_t)(r ? 1 : 0);
    b_ret(cpu, 10);   /* lpMsg(4)+hWnd(2)+min(2)+max(2) */
}

void USER_PEEKMESSAGE(CPU *cpu) {
    /* PeekMessage(lpMsg@8/10, hWnd@6, wMsgFilterMin@4, wMsgFilterMax@2,
     * wRemoveMsg@0). Both filters were being dropped -- every call passed
     * (NULL, 0, 0) and so returned whatever was at the head of the queue.
     * CATZDLL's drag pump peeks for mouse messages only, 0x200..0x202, and
     * exits as soon as there are none; handing it the shell's own posted
     * WM_RECOMP_WINTERFACE instead meant it dispatched that, the shell re-posted
     * it, and the pump never came back -- the screen froze the moment a cat
     * was adopted. */
    uint16_t moff = b_a16(cpu, 8), mseg = b_a16(cpu, 10);
    HWND filt        = get_hwnd(b_a16(cpu, 6));
    UINT lo          = b_a16(cpu, 4), hi = b_a16(cpu, 2);
    uint16_t wRemove = b_a16(cpu, 0);
    MSG m;
    BOOL r = PeekMessageA(&m, filt, lo, hi, wRemove ? PM_REMOVE : PM_NOREMOVE);
    if (r) write_msg(cpu, mseg, moff, &m);
    cpu->ax = (uint16_t)(r ? 1 : 0);
    b_ret(cpu, 12);
}

void USER_TRANSLATEMESSAGE(CPU *cpu) { cpu->ax = 0; b_ret(cpu, 4); }

void USER_DISPATCHMESSAGE(CPU *cpu) {
    /* lpMsg far ptr @0/2: re-read and dispatch via real Win32 -> host_wndproc. */
    uint16_t moff = b_a16(cpu, 0), mseg = b_a16(cpu, 2);
    MSG m; memset(&m, 0, sizeof m);
    m.hwnd    = get_hwnd(mem_read16(cpu, mseg, (uint16_t)(moff + 0)));
    m.message = mem_read16(cpu, mseg, (uint16_t)(moff + 2));
    m.wParam  = mem_read16(cpu, mseg, (uint16_t)(moff + 4));
    m.lParam  = (uint32_t)mem_read16(cpu, mseg, (uint16_t)(moff + 6))
              | ((uint32_t)mem_read16(cpu, mseg, (uint16_t)(moff + 8)) << 16);
    DispatchMessageA(&m);
    cpu->ax = 0; b_ret(cpu, 4);
}

/* ---- resources: LoadBitmap ---- */

static void b_asciiz(CPU *cpu, uint16_t seg, uint16_t off, char *out, int max) {
    int i = 0;
    for (; i < max - 1; i++) {
        char c = (char)mem_read8(cpu, seg, (uint16_t)(off + i));
        if (!c) break;
        out[i] = c;
    }
    out[i] = 0;
}

/* LoadBitmap(HINSTANCE, LPCSTR) — a Win16 RT_BITMAP resource is a packed DIB:
 * BITMAPINFOHEADER, color table, then bits (no BITMAPFILEHEADER). Hand it to
 * GDI32 as a real HBITMAP so the engine's SelectObject/BitBlt path works. */
void USER_LOADBITMAP(CPU *cpu) {
    uint16_t noff = b_a16(cpu, 0), nseg = b_a16(cpu, 2), hinst = b_a16(cpu, 4);

    /* MAKEINTRESOURCE: a far pointer with a zero segment is an integer id. */
    char name[128] = "";
    int id = -1;
    if (nseg == 0) id = noff;
    else b_asciiz(cpu, nseg, noff, name, sizeof name);

    uint16_t hrsrc = ne_find_resource(hinst, 2 /* RT_BITMAP */, NULL,
                                      id, id < 0 ? name : NULL);
    uint32_t len = 0;
    const uint8_t *p = hrsrc ? ne_resource_bytes(hrsrc, &len) : NULL;
    if (!p || len < sizeof(BITMAPINFOHEADER)) {
        fprintf(stderr, "[win32] LoadBitmap(%04X, %s) NOT FOUND\n",
                hinst, id >= 0 ? "#id" : name);
        cpu->ax = 0; b_ret(cpu, 6); return;
    }

    const BITMAPINFOHEADER *bih = (const BITMAPINFOHEADER *)p;
    /* Colour table size: explicit biClrUsed, else 2^bitcount for <=8bpp. */
    unsigned ncolors = bih->biClrUsed;
    if (!ncolors && bih->biBitCount <= 8) ncolors = 1u << bih->biBitCount;
    const uint8_t *bits = p + bih->biSize + ncolors * sizeof(RGBQUAD);

    HDC dc = GetDC(NULL);
    HBITMAP hbm = CreateDIBitmap(dc, bih, CBM_INIT, bits,
                                 (const BITMAPINFO *)bih, DIB_RGB_COLORS);
    ReleaseDC(NULL, dc);

    cpu->ax = put_hgdi(hbm);
    fprintf(stderr, "[win32] LoadBitmap(%04X, %s) %ldx%ld %ubpp -> guest=%u\n",
            hinst, id >= 0 ? "#id" : name, (long)bih->biWidth, (long)bih->biHeight,
            bih->biBitCount, cpu->ax);
    b_ret(cpu, 6);
}

/* Expose the guest->real HDC mapping to the WinG blit in win16_impl.c. */
HDC recomp_real_hdc(uint16_t guest_hdc) { return get_hdc(guest_hdc); }
HWND recomp_real_hwnd(uint16_t guest_hwnd) { return get_hwnd(guest_hwnd); }

/* ==== USER/GDI shims first needed by Dogz and Oddballz ====
 * Argument offsets are from the last (rightmost) PASCAL argument at 0. Where a
 * Win16 API has no meaningful host equivalent here (menus on windows that have
 * no host menu bar, scroll bars on windows that have none) the shim answers the
 * way Windows would for an object in its initial state, rather than 0 --
 * a 0 from most of these reads as failure. */

/* A guest pointer as a host pointer into the flat image, or NULL if the range
   runs off the end. Huge objects are tiled over one flat range, so a pointer
   into one is contiguous for its whole length. */
static uint8_t *b_flat(CPU *cpu, uint16_t seg, uint16_t off, uint32_t len) {
    uint32_t base = cpu->sel_base[seg] + off;
    if (!seg || base + len > cpu->mem_size || base + len < base) return NULL;
    return cpu->mem + base;
}

static uint16_t hwnd_guest(HWND h) {        /* existing guest handle, or 0 */
    if (!h) return 0;
    for (int i = 1; i < g_nhwnd; i++) if (g_hwnd[i] == h) return (uint16_t)i;
    return 0;
}

static void b_rect_read(CPU *cpu, uint16_t seg, uint16_t off, RECT *r) {
    r->left   = (int16_t)mem_read16(cpu, seg, off);
    r->top    = (int16_t)mem_read16(cpu, seg, (uint16_t)(off + 2));
    r->right  = (int16_t)mem_read16(cpu, seg, (uint16_t)(off + 4));
    r->bottom = (int16_t)mem_read16(cpu, seg, (uint16_t)(off + 6));
}
static void b_rect_write(CPU *cpu, uint16_t seg, uint16_t off, const RECT *r) {
    mem_write16(cpu, seg, off, (uint16_t)r->left);
    mem_write16(cpu, seg, (uint16_t)(off + 2), (uint16_t)r->top);
    mem_write16(cpu, seg, (uint16_t)(off + 4), (uint16_t)r->right);
    mem_write16(cpu, seg, (uint16_t)(off + 6), (uint16_t)r->bottom);
}

/* SendMessage(hwnd@8, msg@6, wParam@4, lParam@0). A window with a guest
   WNDPROC gets the call directly, synchronously, as on Windows. Anything else
   is a host window (a dialog control, the desktop): only the standard WM_*
   range means the same thing on both sides, so only that is passed on. */
void USER_SENDMESSAGE(CPU *cpu) {
    uint16_t g = b_a16(cpu, 8);
    UINT msg = b_a16(cpu, 6);
    uint16_t wp = b_a16(cpu, 4);
    uint32_t lp = b_a32(cpu, 0);
    HWND h = get_hwnd(g);
    uint16_t ps = 0, po = 0;
    if (h) hwnd_proc(h, &ps, &po);
    b_ret(cpu, 10);                         /* pop first: the guest proc re-enters */
    if (h && ps) {
        cpu->ax = call_guest_wndproc(ps, po, g, (uint16_t)msg, wp, lp);
        cpu->dx = 0;
    } else {
        LRESULT r = (h && msg < WM_USER) ? SendMessageA(h, msg, wp, (LPARAM)lp) : 0;
        cpu->ax = (uint16_t)r; cpu->dx = (uint16_t)((uint32_t)r >> 16);
    }
}

/* CallWindowProc(lpPrevWndFunc@10/12, hwnd@8, msg@6, wParam@4, lParam@0/2) */
void USER_CALLWINDOWPROC(CPU *cpu) {
    uint16_t po = b_a16(cpu, 10), ps = b_a16(cpu, 12), g = b_a16(cpu, 8);
    UINT msg = b_a16(cpu, 6); uint16_t wp = b_a16(cpu, 4); uint32_t lp = b_a32(cpu, 0);
    b_ret(cpu, 14);
    if (ps) { cpu->ax = call_guest_wndproc(ps, po, g, (uint16_t)msg, wp, lp); cpu->dx = 0; }
    else {
        HWND h = get_hwnd(g);
        LRESULT r = h ? DefWindowProcA(h, msg, wp, (LPARAM)lp) : 0;
        cpu->ax = (uint16_t)r; cpu->dx = (uint16_t)((uint32_t)r >> 16);
    }
}

/* Window extra bytes (cbWndExtra) live here, not in the host window: the
   host class was registered without them, and the guest owns their layout. */
#define WEXTRA 64
static uint8_t g_wextra[MAXH][WEXTRA];

void USER_GETWINDOWLONG(CPU *cpu) {         /* (hwnd@2, nIndex@0) */
    uint16_t g = b_a16(cpu, 2); int idx = (int16_t)b_a16(cpu, 0);
    HWND h = get_hwnd(g);
    uint32_t v = 0;
    if (idx == -4 && g < MAXH)                              /* GWL_WNDPROC */
        v = ((uint32_t)g_hwnd_proc_seg[g] << 16) | g_hwnd_proc_off[g];
    else if (idx == -16 || idx == -20)                      /* GWL_STYLE / EXSTYLE */
        v = h ? (uint32_t)GetWindowLongA(h, idx) : 0;
    else if (idx >= 0 && idx + 4 <= WEXTRA && g < MAXH)
        memcpy(&v, &g_wextra[g][idx], 4);
    cpu->ax = (uint16_t)v; cpu->dx = (uint16_t)(v >> 16);
    b_ret(cpu, 4);
}

void USER_SETWINDOWLONG(CPU *cpu) {         /* (hwnd@6, nIndex@4, dwNewLong@0) */
    uint16_t g = b_a16(cpu, 6); int idx = (int16_t)b_a16(cpu, 4);
    uint32_t nv = b_a32(cpu, 0), old = 0;
    HWND h = get_hwnd(g);
    if (idx == -4 && g < MAXH) {                            /* subclassing */
        old = ((uint32_t)g_hwnd_proc_seg[g] << 16) | g_hwnd_proc_off[g];
        g_hwnd_proc_seg[g] = (uint16_t)(nv >> 16); g_hwnd_proc_off[g] = (uint16_t)nv;
    } else if ((idx == -16 || idx == -20) && h) {
        old = (uint32_t)SetWindowLongA(h, idx, (LONG)nv);
    } else if (idx >= 0 && idx + 4 <= WEXTRA && g < MAXH) {
        memcpy(&old, &g_wextra[g][idx], 4); memcpy(&g_wextra[g][idx], &nv, 4);
    }
    cpu->ax = (uint16_t)old; cpu->dx = (uint16_t)(old >> 16);
    b_ret(cpu, 8);
}

void USER_GETWINDOWWORD(CPU *cpu) {         /* (hwnd@2, nIndex@0) */
    uint16_t g = b_a16(cpu, 2); int idx = (int16_t)b_a16(cpu, 0);
    HWND h = get_hwnd(g);
    uint16_t v = 0;
    if (idx == -6) v = RECOMP_AUTO_DATA_SEG;                /* GWW_HINSTANCE */
    else if (idx == -8) v = h ? hwnd_guest(GetParent(h)) : 0;  /* GWW_HWNDPARENT */
    else if (idx == -12) v = h ? (uint16_t)GetDlgCtrlID(h) : 0; /* GWW_ID */
    else if (idx >= 0 && idx + 2 <= WEXTRA && g < MAXH) memcpy(&v, &g_wextra[g][idx], 2);
    cpu->ax = v;
    b_ret(cpu, 4);
}

void USER_SETWINDOWWORD(CPU *cpu) {         /* (hwnd@4, nIndex@2, wNewWord@0) */
    uint16_t g = b_a16(cpu, 4); int idx = (int16_t)b_a16(cpu, 2);
    uint16_t nv = b_a16(cpu, 0), old = 0;
    if (idx >= 0 && idx + 2 <= WEXTRA && g < MAXH) {
        memcpy(&old, &g_wextra[g][idx], 2); memcpy(&g_wextra[g][idx], &nv, 2);
    }
    cpu->ax = old;
    b_ret(cpu, 6);
}

void USER_GETCLASSWORD(CPU *cpu) { cpu->ax = 0; b_ret(cpu, 4); }   /* (hwnd, nIndex) */
void USER_SETCLASSWORD(CPU *cpu) { cpu->ax = 0; b_ret(cpu, 6); }   /* (hwnd, nIndex, w) */

void USER_GETCLASSNAME(CPU *cpu) {          /* (hwnd@6, lpClassName@2/4, nMax@0) */
    HWND h = get_hwnd(b_a16(cpu, 6));
    uint16_t bo = b_a16(cpu, 2), bs = b_a16(cpu, 4); int nmax = (int16_t)b_a16(cpu, 0);
    char buf[128] = "";
    int n = h ? GetClassNameA(h, buf, sizeof buf) : 0;
    if (n >= nmax) n = nmax > 0 ? nmax - 1 : 0;
    for (int i = 0; i < n; i++) mem_write8(cpu, bs, (uint16_t)(bo + i), (uint8_t)buf[i]);
    if (nmax > 0) mem_write8(cpu, bs, (uint16_t)(bo + n), 0);
    cpu->ax = (uint16_t)n;
    b_ret(cpu, 8);
}

void USER_GETWINDOWTEXT(CPU *cpu) {         /* (hwnd@6, lpString@2/4, nMax@0) */
    HWND h = get_hwnd(b_a16(cpu, 6));
    uint16_t bo = b_a16(cpu, 2), bs = b_a16(cpu, 4); int nmax = (int16_t)b_a16(cpu, 0);
    char buf[256] = "";
    int n = h ? GetWindowTextA(h, buf, sizeof buf) : 0;
    if (n >= nmax) n = nmax > 0 ? nmax - 1 : 0;
    for (int i = 0; i < n; i++) mem_write8(cpu, bs, (uint16_t)(bo + i), (uint8_t)buf[i]);
    if (nmax > 0) mem_write8(cpu, bs, (uint16_t)(bo + n), 0);
    cpu->ax = (uint16_t)n;
    b_ret(cpu, 8);
}

/* Win16 HWND_BOTTOM is 1 and HWND_TOPMOST/NOTOPMOST are -1/-2: small values
   that collide with guest handles, so they are decoded before the lookup. */
static HWND insert_after(uint16_t g) {
    switch (g) {
    case 0:      return HWND_TOP;
    case 1:      return HWND_BOTTOM;
    case 0xFFFF: return HWND_TOPMOST;
    case 0xFFFE: return HWND_NOTOPMOST;
    default:     return get_hwnd(g);
    }
}

/* The guest's screen is the playpen's 640x480 client area (GetWindowRect,
   GetClientRect and ClientToScreen all say so, win16_impl.c), so a position it
   gives a TOP-LEVEL window is in that space, not the host desktop's. Passing it
   through put Catz's frame at its saved "Playpen Window Location" on the
   host's primary monitor -- off the screen it was started on, and onto the
   person's own. So a top-level window never moves. It may still be SIZED --
   Dogz sizes its playpen after creating it -- except the application frame
   and the screen window, whose sizes the runtime sets to hold the 640x480
   playpen. Children, in their parent's coordinates, move and size freely. */
static int is_top_level(HWND h) { return !(GetWindowLongA(h, GWL_STYLE) & WS_CHILD); }
static int runtime_sized(HWND h) { return h == g_main_hwnd || h == g_screen_hwnd; }

/* SetWindowPos(hwnd@12, hWndInsertAfter@10, x@8, y@6, cx@4, cy@2, flags@0) */
void USER_SETWINDOWPOS(CPU *cpu) {
    HWND h = get_hwnd(b_a16(cpu, 12));
    HWND after = insert_after(b_a16(cpu, 10));
    int x = (int16_t)b_a16(cpu, 8), y = (int16_t)b_a16(cpu, 6);
    int cx = (int16_t)b_a16(cpu, 4), cy = (int16_t)b_a16(cpu, 2);
    UINT fl = b_a16(cpu, 0);
    if (h && is_top_level(h)) fl |= SWP_NOMOVE | (runtime_sized(h) ? SWP_NOSIZE : 0);
    if (getenv("RECOMP_LOG_WINPOS"))
        fprintf(stderr, "[winpos] SetWindowPos(guest %u %s%s, %d,%d %dx%d, flags %04X)\n",
                b_a16(cpu, 12), h && is_top_level(h) ? "top" : "child",
                h == g_main_hwnd ? " main" : h == g_screen_hwnd ? " screen" : "", x, y, cx, cy, fl);
    /* Never steal focus from whatever the person is doing. */
    cpu->ax = (uint16_t)(h ? SetWindowPos(h, after, x, y, cx, cy, fl | SWP_NOACTIVATE) : 0);
    b_ret(cpu, 14);
}

void USER_MOVEWINDOW(CPU *cpu) {            /* (hwnd@10, x@8, y@6, w@4, h@2, bRepaint@0) */
    HWND h = get_hwnd(b_a16(cpu, 10));
    cpu->ax = 1;
    if (getenv("RECOMP_LOG_WINPOS"))
        fprintf(stderr, "[winpos] MoveWindow(guest %u %s%s, %d,%d %dx%d)\n", b_a16(cpu, 10),
                h && is_top_level(h) ? "top" : "child",
                h == g_main_hwnd ? " main" : h == g_screen_hwnd ? " screen" : "",
                (int16_t)b_a16(cpu, 8), (int16_t)b_a16(cpu, 6),
                (int16_t)b_a16(cpu, 4), (int16_t)b_a16(cpu, 2));
    if (h && !is_top_level(h))
        cpu->ax = (uint16_t)MoveWindow(h, (int16_t)b_a16(cpu, 8), (int16_t)b_a16(cpu, 6),
                                       (int16_t)b_a16(cpu, 4), (int16_t)b_a16(cpu, 2),
                                       b_a16(cpu, 0));
    else if (h && !runtime_sized(h))
        SetWindowPos(h, NULL, 0, 0, (int16_t)b_a16(cpu, 4), (int16_t)b_a16(cpu, 2),
                     SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    b_ret(cpu, 12);
}

void USER_ISICONIC(CPU *cpu)        { HWND h = get_hwnd(b_a16(cpu, 0)); cpu->ax = (uint16_t)(h && IsIconic(h)); b_ret(cpu, 2); }
void USER_ISZOOMED(CPU *cpu)        { HWND h = get_hwnd(b_a16(cpu, 0)); cpu->ax = (uint16_t)(h && IsZoomed(h)); b_ret(cpu, 2); }
void USER_ISWINDOWVISIBLE(CPU *cpu) { HWND h = get_hwnd(b_a16(cpu, 0)); cpu->ax = (uint16_t)(h && IsWindowVisible(h)); b_ret(cpu, 2); }
void USER_ENABLEWINDOW(CPU *cpu)    { HWND h = get_hwnd(b_a16(cpu, 2)); cpu->ax = (uint16_t)(h ? EnableWindow(h, b_a16(cpu, 0)) : 0); b_ret(cpu, 4); }
void USER_GETDLGCTRLID(CPU *cpu)    { HWND h = get_hwnd(b_a16(cpu, 0)); cpu->ax = (uint16_t)(h ? GetDlgCtrlID(h) : 0); b_ret(cpu, 2); }

/* Focus and activation are the person's, not the guest's: report, never take. */
void USER_GETFOCUS(CPU *cpu)          { cpu->ax = hwnd_guest(GetFocus()); b_ret(cpu, 0); }
void USER_SETFOCUS(CPU *cpu)          { cpu->ax = hwnd_guest(GetFocus()); b_ret(cpu, 2); }
void USER_SETACTIVEWINDOW(CPU *cpu)   { cpu->ax = hwnd_guest(GetActiveWindow()); b_ret(cpu, 2); }
void USER_BRINGWINDOWTOTOP(CPU *cpu)  {
    HWND h = get_hwnd(b_a16(cpu, 0));
    if (h) SetWindowPos(h, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    cpu->ax = 1; b_ret(cpu, 2);
}

/* The desktop is the real one: games size their full-screen play area from it. */
void USER_GETDESKTOPWINDOW(CPU *cpu) { cpu->ax = put_hwnd(GetDesktopWindow()); b_ret(cpu, 0); }

void USER_SCREENTOCLIENT(CPU *cpu) {        /* (hwnd@4, lpPoint@0/2) */
    HWND h = get_hwnd(b_a16(cpu, 4));
    uint16_t po = b_a16(cpu, 0), ps = b_a16(cpu, 2);
    POINT p = { (int16_t)mem_read16(cpu, ps, po), (int16_t)mem_read16(cpu, ps, (uint16_t)(po + 2)) };
    if (h) ScreenToClient(h, &p);
    mem_write16(cpu, ps, po, (uint16_t)p.x); mem_write16(cpu, ps, (uint16_t)(po + 2), (uint16_t)p.y);
    b_ret(cpu, 6);
}

void USER_SETRECT(CPU *cpu) {               /* (lpRect@8/10, l@6, t@4, r@2, b@0) */
    RECT r = { (int16_t)b_a16(cpu, 6), (int16_t)b_a16(cpu, 4), (int16_t)b_a16(cpu, 2), (int16_t)b_a16(cpu, 0) };
    uint16_t ro = b_a16(cpu, 8), rs = b_a16(cpu, 10);
    if (rs) b_rect_write(cpu, rs, ro, &r);
    b_ret(cpu, 12);
}

void USER_SUBTRACTRECT(CPU *cpu) {          /* (lprcDst@8/10, lprcSrc1@4/6, lprcSrc2@0/2) */
    RECT a, b, d;
    b_rect_read(cpu, b_a16(cpu, 6), b_a16(cpu, 4), &a);
    b_rect_read(cpu, b_a16(cpu, 2), b_a16(cpu, 0), &b);
    cpu->ax = (uint16_t)SubtractRect(&d, &a, &b);
    b_rect_write(cpu, b_a16(cpu, 10), b_a16(cpu, 8), &d);
    b_ret(cpu, 12);
}

/* The cursor is the person's: the guest may hide its own over its windows,
   but it does not get to warp or confine the real one. */
void USER_SHOWCURSOR(CPU *cpu)   { static int count = 0; count += b_a16(cpu, 0) ? 1 : -1; cpu->ax = (uint16_t)count; b_ret(cpu, 2); }
void USER_SETCURSORPOS(CPU *cpu) { b_ret(cpu, 4); }
void USER_CLIPCURSOR(CPU *cpu)   { cpu->ax = 1; b_ret(cpu, 4); }
void USER_DESTROYICON(CPU *cpu)  { cpu->ax = 1; b_ret(cpu, 2); }

/* No second instance and no foreign windows to find: the recomp is the only
   Win16 program running. EnumWindows therefore enumerates nothing. */
void USER_FINDWINDOW(CPU *cpu)  { cpu->ax = 0; b_ret(cpu, 8); }
void USER_ENUMWINDOWS(CPU *cpu) { cpu->ax = 1; b_ret(cpu, 8); }

/* SystemParametersInfo(uiAction@8, uiParam@6, pvParam@2/4, fWinIni@0) */
void USER_SYSTEMPARAMETERSINFO(CPU *cpu) {
    UINT act = b_a16(cpu, 8);
    uint16_t po = b_a16(cpu, 2), ps = b_a16(cpu, 4);
    cpu->ax = 0;
    if (act == 48 && ps) {                  /* SPI_GETWORKAREA */
        RECT r; SystemParametersInfoA(SPI_GETWORKAREA, 0, &r, 0);
        b_rect_write(cpu, ps, po, &r); cpu->ax = 1;
    } else if ((act == 16 || act == 14) && ps) {  /* SPI_GETSCREENSAVEACTIVE / TIMEOUT */
        mem_write16(cpu, ps, po, 0); cpu->ax = 1;
    } else if (act == 17 || act == 15) {    /* set screen saver state: refuse politely */
        cpu->ax = 1;
    }
    b_ret(cpu, 10);
}

void USER_REDRAWWINDOW(CPU *cpu) {          /* (hwnd@8, lprcUpdate@4/6, hrgnUpdate@2, flags@0) */
    HWND h = get_hwnd(b_a16(cpu, 8));
    if (h) InvalidateRect(h, NULL, FALSE);
    cpu->ax = 1;
    b_ret(cpu, 10);
}

/* GetWindowPlacement(hwnd@4, lpwndpl@0/2). Win16 WINDOWPLACEMENT is all
   16-bit: length, flags, showCmd, ptMin, ptMax, rcNormal = 22 bytes. */
void USER_GETWINDOWPLACEMENT(CPU *cpu) {
    HWND h = get_hwnd(b_a16(cpu, 4));
    uint16_t o = b_a16(cpu, 0), s = b_a16(cpu, 2);
    WINDOWPLACEMENT wp = { sizeof wp };
    if (!h || !s || !GetWindowPlacement(h, &wp)) { cpu->ax = 0; b_ret(cpu, 6); return; }
    mem_write16(cpu, s, o, 22);
    mem_write16(cpu, s, (uint16_t)(o + 2), (uint16_t)wp.flags);
    mem_write16(cpu, s, (uint16_t)(o + 4), (uint16_t)wp.showCmd);
    mem_write16(cpu, s, (uint16_t)(o + 6), (uint16_t)wp.ptMinPosition.x);
    mem_write16(cpu, s, (uint16_t)(o + 8), (uint16_t)wp.ptMinPosition.y);
    mem_write16(cpu, s, (uint16_t)(o + 10), (uint16_t)wp.ptMaxPosition.x);
    mem_write16(cpu, s, (uint16_t)(o + 12), (uint16_t)wp.ptMaxPosition.y);
    b_rect_write(cpu, s, (uint16_t)(o + 14), &wp.rcNormalPosition);
    cpu->ax = 1;
    b_ret(cpu, 6);
}

/* CreateWindowEx takes CreateWindow's arguments with dwExStyle first -- i.e.
   deepest on the stack -- so the rest sit exactly where CreateWindow reads
   them. Run it, then drop the extra DWORD. */
void USER_CREATEWINDOWEX(CPU *cpu) {
    USER_CREATEWINDOW(cpu);
    cpu->sp = (uint16_t)(cpu->sp + 4);
}

/* ---- menus: guest handles only. The recomp's windows have no host menu bar
   (the engines draw their own), so a menu is bookkeeping the guest can build
   and query, not something shown. */
static uint16_t g_nmenu = 0x100;
void USER_LOADMENU(CPU *cpu)        { cpu->ax = g_nmenu++; b_ret(cpu, 6); }
void USER_CREATEPOPUPMENU(CPU *cpu) { cpu->ax = g_nmenu++; b_ret(cpu, 0); }
void USER_CREATEMENU(CPU *cpu)      { cpu->ax = g_nmenu++; b_ret(cpu, 0); }
void USER_DESTROYMENU(CPU *cpu)     { cpu->ax = 1; b_ret(cpu, 2); }
void USER_GETMENU(CPU *cpu)         { cpu->ax = 0; b_ret(cpu, 2); }
void USER_GETSUBMENU(CPU *cpu)      { cpu->ax = g_nmenu++; b_ret(cpu, 4); }
void USER_INSERTMENU(CPU *cpu)      { cpu->ax = 1; b_ret(cpu, 12); }
void USER_ENABLEMENUITEM(CPU *cpu)  { cpu->ax = 0; b_ret(cpu, 6); }   /* previous: enabled */

/* ---- scroll bars: none exist, so each is permanently at 0 of 0..0 ---- */
void USER_GETSCROLLPOS(CPU *cpu)    { cpu->ax = 0; b_ret(cpu, 4); }
void USER_SETSCROLLPOS(CPU *cpu)    { cpu->ax = 0; b_ret(cpu, 8); }
void USER_SETSCROLLRANGE(CPU *cpu)  { b_ret(cpu, 10); }
void USER_ENABLESCROLLBAR(CPU *cpu) { cpu->ax = 1; b_ret(cpu, 6); }

void USER_UNREGISTERCLASS(CPU *cpu) { cpu->ax = 1; b_ret(cpu, 6); }
void USER_WINHELP(CPU *cpu)         { cpu->ax = 1; b_ret(cpu, 12); }  /* no help viewer */

/* ---- dialogs. Controls are not materialised (see dlg_build); their state
   lives in the same store as their text, so it round-trips. */
void USER_ISDIALOGMESSAGE(CPU *cpu) { cpu->ax = 0; b_ret(cpu, 6); }  /* not a dialog message */

static void dlg_check_set(uint16_t hdlg, uint16_t id, int state) {
    DlgText *t = dlgtxt(hdlg, id, 1);
    if (t) { t->text[0] = (char)('0' + state); t->text[1] = 0; }
}
void USER_CHECKDLGBUTTON(CPU *cpu) {        /* (hDlg@4, nIDButton@2, uCheck@0) */
    dlg_check_set(b_a16(cpu, 4), b_a16(cpu, 2), b_a16(cpu, 0) ? 1 : 0);
    b_ret(cpu, 6);
}
void USER_CHECKRADIOBUTTON(CPU *cpu) {      /* (hDlg@6, first@4, last@2, check@0) */
    uint16_t d = b_a16(cpu, 6), first = b_a16(cpu, 4), last = b_a16(cpu, 2), on = b_a16(cpu, 0);
    for (uint16_t id = first; id <= last && id >= first; id++) dlg_check_set(d, id, id == on);
    b_ret(cpu, 8);
}
void USER_ISDLGBUTTONCHECKED(CPU *cpu) {    /* (hDlg@2, nIDButton@0) */
    DlgText *t = dlgtxt(b_a16(cpu, 2), b_a16(cpu, 0), 0);
    cpu->ax = (uint16_t)(t && t->text[0] == '1');
    b_ret(cpu, 4);
}
void USER_SETDLGITEMINT(CPU *cpu) {         /* (hDlg@6, nID@4, uValue@2, bSigned@0) */
    DlgText *t = dlgtxt(b_a16(cpu, 6), b_a16(cpu, 4), 1);
    if (t) snprintf(t->text, sizeof t->text, b_a16(cpu, 0) ? "%d" : "%u",
                    b_a16(cpu, 0) ? (int)(int16_t)b_a16(cpu, 2) : (int)b_a16(cpu, 2));
    b_ret(cpu, 8);
}
/* SendDlgItemMessage(hDlg@10, nID@8, msg@6, wParam@4, lParam@0/2): no control
   to receive it. 0 is "nothing selected / no text", the state of a new one. */
void USER_SENDDLGITEMMESSAGE(CPU *cpu) { cpu->ax = 0; cpu->dx = 0; b_ret(cpu, 12); }

/* DialogBox(hInst, lpTemplate, hWndParent, lpDialogFunc) is DialogBoxParam
   without the trailing lParam. Slide the return frame down two words and put a
   0 lParam where it was, and the stack is exactly DialogBoxParam's. */
void USER_DIALOGBOX(CPU *cpu) {
    uint16_t ip = mem_read16(cpu, cpu->ss, cpu->sp);
    uint16_t cs = mem_read16(cpu, cpu->ss, (uint16_t)(cpu->sp + 2));
    cpu->sp = (uint16_t)(cpu->sp - 4);
    mem_write16(cpu, cpu->ss, cpu->sp, ip);
    mem_write16(cpu, cpu->ss, (uint16_t)(cpu->sp + 2), cs);
    mem_write16(cpu, cpu->ss, (uint16_t)(cpu->sp + 4), 0);
    mem_write16(cpu, cpu->ss, (uint16_t)(cpu->sp + 6), 0);
    USER_DIALOGBOXPARAM(cpu);
}

/* ---- GDI ---- */
void GDI_GETBKMODE(CPU *cpu) {              /* (hdc@0) */
    uint16_t g = b_a16(cpu, 0);
    HDC dc = wing_is_dc(g) ? wing_state_dc(cpu, g) : get_hdc(g);
    cpu->ax = (uint16_t)(dc ? GetBkMode(dc) : OPAQUE);
    b_ret(cpu, 2);
}

/* CreateFont(h@28, w@26, esc@24, orient@22, weight@20, italic@18, underline@16,
   strikeout@14, charset@12, outprec@10, clipprec@8, quality@6, pitch@4, face@0/2) */
void GDI_CREATEFONT(CPU *cpu) {
    char face[LF_FACESIZE] = "";
    uint16_t fo = b_a16(cpu, 0), fs = b_a16(cpu, 2);
    if (fs) b_asciiz(cpu, fs, fo, face, sizeof face);
    HFONT f = CreateFontA((int16_t)b_a16(cpu, 28), (int16_t)b_a16(cpu, 26),
                          (int16_t)b_a16(cpu, 24), (int16_t)b_a16(cpu, 22),
                          (int16_t)b_a16(cpu, 20), (BYTE)b_a16(cpu, 18), (BYTE)b_a16(cpu, 16),
                          (BYTE)b_a16(cpu, 14), (BYTE)b_a16(cpu, 12), (BYTE)b_a16(cpu, 10),
                          (BYTE)b_a16(cpu, 8), (BYTE)b_a16(cpu, 6), (BYTE)b_a16(cpu, 4), face);
    cpu->ax = put_hgdi(f);
    b_ret(cpu, 30);
}

/* GetTextMetrics(hdc@4, lptm@0/2). Win16 TEXTMETRIC: eight ints, nine bytes,
   three ints -- 31 bytes. */
void GDI_GETTEXTMETRICS(CPU *cpu) {
    uint16_t g = b_a16(cpu, 4), o = b_a16(cpu, 0), s = b_a16(cpu, 2);
    HDC dc = wing_is_dc(g) ? wing_state_dc(cpu, g) : get_hdc(g);
    TEXTMETRICA tm; memset(&tm, 0, sizeof tm);
    int ok = dc && GetTextMetricsA(dc, &tm);
    if (ok && s) {
        const int16_t w[8] = { (int16_t)tm.tmHeight, (int16_t)tm.tmAscent, (int16_t)tm.tmDescent,
            (int16_t)tm.tmInternalLeading, (int16_t)tm.tmExternalLeading,
            (int16_t)tm.tmAveCharWidth, (int16_t)tm.tmMaxCharWidth, (int16_t)tm.tmWeight };
        for (int i = 0; i < 8; i++) mem_write16(cpu, s, (uint16_t)(o + 2 * i), (uint16_t)w[i]);
        const uint8_t b[9] = { tm.tmItalic, tm.tmUnderlined, tm.tmStruckOut, tm.tmFirstChar,
            tm.tmLastChar, tm.tmDefaultChar, tm.tmBreakChar, tm.tmPitchAndFamily, tm.tmCharSet };
        for (int i = 0; i < 9; i++) mem_write8(cpu, s, (uint16_t)(o + 16 + i), b[i]);
        mem_write16(cpu, s, (uint16_t)(o + 25), (uint16_t)tm.tmOverhang);
        mem_write16(cpu, s, (uint16_t)(o + 27), (uint16_t)tm.tmDigitizedAspectX);
        mem_write16(cpu, s, (uint16_t)(o + 29), (uint16_t)tm.tmDigitizedAspectY);
    }
    cpu->ax = (uint16_t)ok;
    b_ret(cpu, 6);
}

/* Current position per guest DC. A WinG surface's host DC is set up afresh
   for each drawing call (wing_draw_begin), so GDI cannot remember it there. */
static POINT g_curpos[MAXH];

static uint32_t move_to(uint16_t g, int x, int y) {
    POINT old = { 0, 0 };
    if (g < MAXH) { old = g_curpos[g]; g_curpos[g].x = x; g_curpos[g].y = y; }
    return ((uint32_t)(uint16_t)old.y << 16) | (uint16_t)old.x;
}
void GDI_MOVETO(CPU *cpu) {                 /* (hdc@4, x@2, y@0) -> DWORD old (y:x) */
    uint32_t r = move_to(b_a16(cpu, 4), (int16_t)b_a16(cpu, 2), (int16_t)b_a16(cpu, 0));
    cpu->ax = (uint16_t)r; cpu->dx = (uint16_t)(r >> 16);
    b_ret(cpu, 6);
}
void GDI_MOVETOEX(CPU *cpu) {               /* (hdc@8, x@6, y@4, lpPoint@0/2) */
    uint32_t r = move_to(b_a16(cpu, 8), (int16_t)b_a16(cpu, 6), (int16_t)b_a16(cpu, 4));
    uint16_t o = b_a16(cpu, 0), s = b_a16(cpu, 2);
    if (s) { mem_write16(cpu, s, o, (uint16_t)r); mem_write16(cpu, s, (uint16_t)(o + 2), (uint16_t)(r >> 16)); }
    cpu->ax = 1;
    b_ret(cpu, 10);
}
void GDI_LINETO(CPU *cpu) {                 /* (hdc@4, x@2, y@0) */
    uint16_t g = b_a16(cpu, 4);
    int x = (int16_t)b_a16(cpu, 2), y = (int16_t)b_a16(cpu, 0);
    POINT a = g < MAXH ? g_curpos[g] : (POINT){ 0, 0 };
    RECT r = { a.x < x ? a.x : x, a.y < y ? a.y : y, (a.x > x ? a.x : x) + 1, (a.y > y ? a.y : y) + 1 };
    RECT used = r; int wing = 0;
    HDC dc = draw_dc(cpu, g, r, &used, &wing);
    if (dc) { MoveToEx(dc, a.x, a.y, NULL); LineTo(dc, x, y); }
    if (dc && wing) wing_draw_end(cpu, g, &used);
    move_to(g, x, y);
    cpu->ax = (uint16_t)(dc != NULL);
    b_ret(cpu, 6);
}

void GDI_SETVIEWPORTORG(CPU *cpu) {         /* (hdc@4, x@2, y@0) -> DWORD old (y:x) */
    uint16_t g = b_a16(cpu, 4);
    HDC dc = wing_is_dc(g) ? wing_state_dc(cpu, g) : get_hdc(g);
    POINT old = { 0, 0 };
    if (dc) SetViewportOrgEx(dc, (int16_t)b_a16(cpu, 2), (int16_t)b_a16(cpu, 0), &old);
    cpu->ax = (uint16_t)old.x; cpu->dx = (uint16_t)old.y;
    b_ret(cpu, 6);
}

/* A Win16 BITMAPINFO in guest memory as a host copy: the 40-byte header plus
   the colour table (2 bytes per entry for DIB_PAL_COLORS, 4 for RGB). */
static BITMAPINFO *bmi_copy(CPU *cpu, uint16_t seg, uint16_t off, UINT usage) {
    uint8_t *p = b_flat(cpu, seg, off, sizeof(BITMAPINFOHEADER));
    if (!p) return NULL;
    BITMAPINFOHEADER h; memcpy(&h, p, sizeof h);
    uint32_t ncol = h.biClrUsed ? h.biClrUsed : (h.biBitCount <= 8 ? 1u << h.biBitCount : 0);
    uint32_t tbl = ncol * (usage == DIB_PAL_COLORS ? 2 : 4);
    if (h.biCompression == BI_BITFIELDS) tbl = 12;
    size_t n = sizeof(BITMAPINFOHEADER) + tbl;
    BITMAPINFO *bi = calloc(1, n + 16);
    uint8_t *src = b_flat(cpu, seg, off, (uint32_t)n);
    if (bi && src) memcpy(bi, src, n);
    return bi;
}
static uint32_t dib_bytes(const BITMAPINFOHEADER *h) {
    uint32_t stride = ((uint32_t)h->biWidth * h->biBitCount + 31) / 32 * 4;
    return stride * (uint32_t)(h->biHeight < 0 ? -h->biHeight : h->biHeight);
}

/* CreateDIBitmap(hdc@18, lpbmih@14/16, fdwInit@10/12, lpbInit@6/8, lpbmi@2/4, fuUsage@0) */
void GDI_CREATEDIBITMAP(CPU *cpu) {
    HDC dc = get_hdc(b_a16(cpu, 18));
    UINT usage = b_a16(cpu, 0);
    BITMAPINFO *hdr = bmi_copy(cpu, b_a16(cpu, 16), b_a16(cpu, 14), usage);
    BITMAPINFO *bmi = b_a16(cpu, 4) ? bmi_copy(cpu, b_a16(cpu, 4), b_a16(cpu, 2), usage) : NULL;
    DWORD init = b_a32(cpu, 10);
    const void *bits = NULL;
    if (init && bmi) bits = b_flat(cpu, b_a16(cpu, 8), b_a16(cpu, 6), dib_bytes(&bmi->bmiHeader));
    HDC screen = dc ? dc : GetDC(NULL);
    HBITMAP hb = hdr ? CreateDIBitmap(screen, &hdr->bmiHeader, bits ? CBM_INIT : 0, bits, bmi, usage) : NULL;
    if (!dc) ReleaseDC(NULL, screen);
    free(hdr); free(bmi);
    cpu->ax = put_hgdi(hb);
    b_ret(cpu, 20);
}

/* GetDIBits(hdc@16, hbm@14, uStartScan@12, cScanLines@10, lpvBits@6/8, lpbi@2/4, uUsage@0) */
void GDI_GETDIBITS(CPU *cpu) {
    HDC dc = get_hdc(b_a16(cpu, 16));
    HBITMAP hb = (HBITMAP)get_hgdi(b_a16(cpu, 14));
    UINT start = b_a16(cpu, 12), lines = b_a16(cpu, 10), usage = b_a16(cpu, 0);
    uint16_t bo = b_a16(cpu, 6), bs = b_a16(cpu, 8), io = b_a16(cpu, 2), is = b_a16(cpu, 4);
    BITMAPINFO *bi = calloc(1, sizeof(BITMAPINFOHEADER) + 256 * 4 + 16);
    uint8_t *gi = b_flat(cpu, is, io, sizeof(BITMAPINFOHEADER));
    int r = 0;
    if (bi && gi && hb) {
        memcpy(bi, gi, sizeof(BITMAPINFOHEADER));
        HDC screen = dc ? dc : GetDC(NULL);
        void *bits = NULL;
        if (bs) {
            r = GetDIBits(screen, hb, start, lines, NULL, bi, usage);   /* fills sizes */
            bits = b_flat(cpu, bs, bo, dib_bytes(&bi->bmiHeader));
            memcpy(bi, gi, sizeof(BITMAPINFOHEADER));
        }
        r = GetDIBits(screen, hb, start, lines, bits, bi, usage);
        if (!dc) ReleaseDC(NULL, screen);
        uint32_t ncol = bi->bmiHeader.biBitCount <= 8 ? 1u << bi->bmiHeader.biBitCount : 0;
        uint8_t *go = b_flat(cpu, is, io, sizeof(BITMAPINFOHEADER) + ncol * 4);
        if (go) memcpy(go, bi, sizeof(BITMAPINFOHEADER) + ncol * (usage == DIB_PAL_COLORS ? 2 : 4));
    }
    free(bi);
    cpu->ax = (uint16_t)r;
    b_ret(cpu, 18);
}

/* StretchDIBits(hdc@30, xD@28, yD@26, wD@24, hD@22, xS@20, yS@18, wS@16, hS@14,
                 lpBits@10/12, lpbmi@6/8, usage@4, rop@0/2) */
void GDI_STRETCHDIBITS(CPU *cpu) {
    uint16_t g = b_a16(cpu, 30);
    int xd = (int16_t)b_a16(cpu, 28), yd = (int16_t)b_a16(cpu, 26);
    int wd = (int16_t)b_a16(cpu, 24), hd = (int16_t)b_a16(cpu, 22);
    int xs = (int16_t)b_a16(cpu, 20), ys = (int16_t)b_a16(cpu, 18);
    int ws = (int16_t)b_a16(cpu, 16), hs = (int16_t)b_a16(cpu, 14);
    UINT usage = b_a16(cpu, 4); DWORD rop = b_a32(cpu, 0);
    BITMAPINFO *bi = bmi_copy(cpu, b_a16(cpu, 8), b_a16(cpu, 6), usage);
    const void *bits = bi ? b_flat(cpu, b_a16(cpu, 12), b_a16(cpu, 10), dib_bytes(&bi->bmiHeader)) : NULL;
    RECT r = { xd < xd + wd ? xd : xd + wd, yd < yd + hd ? yd : yd + hd,
               xd > xd + wd ? xd : xd + wd, yd > yd + hd ? yd : yd + hd };
    RECT used = r; int wing = 0;
    HDC dc = (bi && bits) ? draw_dc(cpu, g, r, &used, &wing) : NULL;
    int n = dc ? StretchDIBits(dc, xd, yd, wd, hd, xs, ys, ws, hs, bits, bi, usage, rop) : 0;
    if (dc && wing) wing_draw_end(cpu, g, &used);
    free(bi);
    cpu->ax = (uint16_t)n;
    b_ret(cpu, 32);
}

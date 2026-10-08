/*
 * user32.c - win32hle USER32: a window manager without a display.
 *
 * Windows here are bookkeeping: a tree of HWNDs with classes, procedures,
 * rectangles, styles, text and window data; a message queue with WM_PAINT
 * and WM_TIMER generated as Windows generates them; focus, capture and
 * activation; dialogs built from their templates; and the standard controls
 * (button, static, edit, list box, combo box, trackbar, ...) as procedures
 * that keep their state and notify their parents. Nothing is drawn: a game
 * that paints its own controls (Westwood's menus) paints them into its own
 * surfaces, and a presenter (present.c, or a host's) shows those.
 *
 * Every window procedure is called through hle_call_guest, the lifted ones
 * and these built-in ones alike (the built-ins are registered shims), so a
 * guest that subclasses a button and calls CallWindowProcA on the old
 * procedure lands here.
 *
 * Input comes from the host: hle_input_mouse/hle_input_key post the messages
 * a real mouse and keyboard would, to the window under the point or the one
 * with the focus, and keep the key and cursor state GetKeyState and
 * GetCursorPos answer.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <unistd.h>
#include "win32hle.h"

/* ---- messages ---- */
#define WM_CREATE          0x0001u
#define WM_DESTROY         0x0002u
#define WM_MOVE            0x0003u
#define WM_SIZE            0x0005u
#define WM_ACTIVATE        0x0006u
#define WM_SETFOCUS        0x0007u
#define WM_KILLFOCUS       0x0008u
#define WM_ENABLE          0x000Au
#define WM_SETTEXT         0x000Cu
#define WM_GETTEXT         0x000Du
#define WM_GETTEXTLENGTH   0x000Eu
#define WM_PAINT           0x000Fu
#define WM_CLOSE           0x0010u
#define WM_QUIT            0x0012u
#define WM_ERASEBKGND      0x0014u
#define WM_SHOWWINDOW      0x0018u
#define WM_ACTIVATEAPP     0x001Cu
#define WM_SETCURSOR       0x0020u
#define WM_MOUSEACTIVATE   0x0021u
#define WM_DRAWITEM        0x002Bu
#define WM_MEASUREITEM     0x002Cu
#define WM_SETFONT         0x0030u
#define WM_GETFONT         0x0031u
#define WM_WINDOWPOSCHANGED 0x0047u
#define WM_NCCREATE        0x0081u
#define WM_NCDESTROY       0x0082u
#define WM_NCHITTEST       0x0084u
#define WM_NCACTIVATE      0x0086u
#define WM_GETDLGCODE      0x0087u
#define WM_KEYDOWN         0x0100u
#define WM_KEYUP           0x0101u
#define WM_CHAR            0x0102u
#define WM_SYSKEYDOWN      0x0104u
#define WM_SYSKEYUP        0x0105u
#define WM_SYSCHAR         0x0106u
#define WM_INITDIALOG      0x0110u
#define WM_COMMAND         0x0111u
#define WM_SYSCOMMAND      0x0112u
#define WM_TIMER           0x0113u
#define WM_HSCROLL         0x0114u
#define WM_VSCROLL         0x0115u
#define WM_CTLCOLORMSGBOX  0x0132u
#define WM_CTLCOLORSTATIC  0x0138u
#define WM_MOUSEMOVE       0x0200u
#define WM_LBUTTONDOWN     0x0201u
#define WM_LBUTTONUP       0x0202u
#define WM_LBUTTONDBLCLK   0x0203u
#define WM_RBUTTONDOWN     0x0204u
#define WM_RBUTTONUP       0x0205u
#define WM_MBUTTONDOWN     0x0207u
#define WM_MBUTTONUP       0x0208u
#define WM_CAPTURECHANGED  0x0215u

#define WS_CHILD       0x40000000u
#define WS_VISIBLE     0x10000000u
#define WS_DISABLED    0x08000000u
#define WS_TABSTOP     0x00010000u
#define WS_GROUP       0x00020000u
#define DS_SETFONT     0x00000040u
#define DS_CENTER      0x00000800u

#define GWL_WNDPROC    (-4)
#define GWL_HINSTANCE  (-6)
#define GWL_HWNDPARENT (-8)
#define GWL_ID         (-12)
#define GWL_STYLE      (-16)
#define GWL_EXSTYLE    (-20)
#define GWL_USERDATA   (-21)
#define DWL_MSGRESULT  0
#define DWL_DLGPROC    4
#define DWL_USER       8

#define IDOK     1
#define IDCANCEL 2
#define VK_TAB    0x09
#define VK_RETURN 0x0D
#define VK_SHIFT  0x10
#define VK_CONTROL 0x11
#define VK_MENU   0x12
#define VK_ESCAPE 0x1B

/* Dialog base units of MS Sans Serif 8 at 96 dpi: a template's x is 4ths of
 * 6 pixels, its y 8ths of 13. */
#define DLG_BX 6
#define DLG_BY 13

/* ---- classes ---- */
enum { K_GUEST, K_DEFAULT, K_DIALOG, K_BUTTON, K_STATIC, K_EDIT, K_LISTBOX, K_COMBOBOX, K_SCROLLBAR,
       K_TRACKBAR, K_PROGRESS, K_HOTKEY, K_LISTVIEW };
#define MAX_CLASSES 64
static struct { char name[64]; uint32_t proc, style, extra, hinst, cursor; int kind; } g_cls[MAX_CLASSES];
static int g_ncls;

/* ---- windows ---- */
#define MAX_WIN 2048
typedef struct {
    int used, cls, kind, destroying;
    uint32_t hwnd, proc, parent, owner, style, exstyle, id, user, hinst, font, menu;
    int x, y, w, h;                      /* relative to the parent's client area; a top-level's to the screen */
    uint32_t dlgproc, msgresult, dlguser;
    int dlg_ended; uint32_t dlg_result;
    uint32_t extra[32];
    char text[512];
    int inval, ix0, iy0, ix1, iy1;       /* the update region, as a rectangle (client coordinates) */
    int seq;                             /* creation order: the z-order among siblings, first on top */
    /* the built-in controls' state */
    int state, check, pos, rmin, rmax, cursel, top, item_h, sel0, sel1, limit, dropped, tracking;
    int sel_h, drop_h;                   /* a combo box: its selection field, and its height dropped */
    struct item { char *text; uint32_t data; } *items;
    int nitems, citems;
} win_t;
static win_t g_win[MAX_WIN];
static int g_seq;

static uint32_t g_focus, g_capture, g_active;
static int g_screen_w = 640, g_screen_h = 480;
static int g_cursor_x, g_cursor_y, g_cursor_shown = 0;
static uint8_t g_keys[256];                      /* bit 7: down, bit 0: toggled */
static void (*g_pump)(void);

void hle_set_pump_hook(void (*fn)(void)) { g_pump = fn; }
void hle_set_screen_size(int w, int h) { g_screen_w = w, g_screen_h = h; }

#define HWND_OF(i) (0x00010000u | ((uint32_t)(i) << 4))
static win_t *W(uint32_t h) {
    if ((h & 0xFFFF000Fu) != 0x00010000u) return NULL;
    uint32_t i = (h - 0x00010000u) >> 4;
    return i < MAX_WIN && g_win[i].used && g_win[i].hwnd == h ? &g_win[i] : NULL;
}

/* ---- calling window procedures ----
 * hle_proc_hook sees every message a window procedure is given (a test
 * driver watching for a button's click). */
void (*hle_proc_hook)(uint32_t hwnd, uint32_t msg, uint32_t wParam, uint32_t lParam);
static int g_msgtrace = -1;                      /* HLE_MSGTRACE=1: every message, but paints and mouse moves */
static uint32_t call_proc(uint32_t proc, uint32_t h, uint32_t m, uint32_t w, uint32_t l) {
    if (hle_proc_hook) hle_proc_hook(h, m, w, l);
    if (!proc) return 0;
    if (g_msgtrace < 0) g_msgtrace = getenv("HLE_MSGTRACE") != NULL;
    win_t *x = g_msgtrace ? W(h) : NULL;
    if (x && m != WM_MOUSEMOVE && m != 0x0084u && m != 0x0020u)
        fprintf(stderr, "[msg] %05X %s#%u <- %04X %08X %08X\n", h, g_cls[x->cls].name, x->id, m, w, l);
    uint32_t a[4] = { h, m, w, l };
    uint32_t r = hle_call_guest(proc, 4, a);
    if (x && m != WM_MOUSEMOVE && m != 0x0084u && m != 0x0020u && r) fprintf(stderr, "[msg] %05X     -> %08X\n", h, r);
    return r;
}
uint32_t hle_send(uint32_t h, uint32_t m, uint32_t w, uint32_t l) {
    win_t *x = W(h);
    return x ? call_proc(x->proc, h, m, w, l) : 0;
}

/* ---- the queue ---- */
typedef struct { uint32_t hwnd, message, wParam, lParam, time; int x, y; } msg_t;
#define QN 1024
static msg_t g_q[QN];
static int g_qn;
static int g_quit; static uint32_t g_quit_code;

static void q_push(uint32_t h, uint32_t m, uint32_t w, uint32_t l) {
    if (g_qn == QN) { memmove(g_q, g_q + 1, sizeof g_q[0] * (QN - 1)); g_qn--; }
    msg_t x = { h, m, w, l, hle_ticks_ms(), g_cursor_x, g_cursor_y };
    g_q[g_qn++] = x;
}
void hle_post_message(uint32_t hwnd, uint32_t message, uint32_t wParam, uint32_t lParam) {
    if (message == WM_QUIT) { g_quit = 1, g_quit_code = wParam; return; }
    q_push(hwnd, message, wParam, lParam);
}
int hle_msg_pop(uint32_t *message, uint32_t *wParam, uint32_t *lParam) {
    if (!g_qn && g_quit) {                               /* WM_QUIT comes after the posted messages */
        g_quit = 0;
        if (message) *message = WM_QUIT;
        if (wParam) *wParam = g_quit_code;
        if (lParam) *lParam = 0;
        return 1;
    }
    if (!g_qn) return 0;
    if (message) *message = g_q[0].message;
    if (wParam) *wParam = g_q[0].wParam;
    if (lParam) *lParam = g_q[0].lParam;
    memmove(g_q, g_q + 1, sizeof g_q[0] * (size_t)--g_qn);
    return 1;
}

static int is_descendant(uint32_t h, uint32_t of) {
    for (win_t *x = W(h); x; x = W(x->parent)) if (x->hwnd == of) return 1;
    return 0;
}
static int visible(win_t *x) {
    for (; x; x = W(x->parent)) if (!(x->style & WS_VISIBLE)) return 0;
    return 1;
}

/* ---- timers ---- */
#define MAX_TIMERS 64
static struct { uint32_t hwnd, id, elapse, due, proc; int used; } g_timer[MAX_TIMERS];

/* ---- geometry ---- */
static void origin(win_t *x, int *ox, int *oy) {     /* the client origin in screen coordinates */
    *ox = *oy = 0;
    for (; x; x = W(x->parent)) *ox += x->x, *oy += x->y;
}
static void put_rect(uint32_t r, int l, int t, int rr, int b) {
    if (r) MEM32(r) = (uint32_t)l, MEM32(r + 4) = (uint32_t)t, MEM32(r + 8) = (uint32_t)rr, MEM32(r + 12) = (uint32_t)b;
}

static void invalidate(win_t *x, int all_children) {
    if (!x) return;
    x->inval = 1, x->ix0 = 0, x->iy0 = 0, x->ix1 = x->w, x->iy1 = x->h;
    if (all_children)
        for (int i = 0; i < MAX_WIN; i++) if (g_win[i].used && g_win[i].parent == x->hwnd) invalidate(&g_win[i], 1);
}

/* ---- creation ---- */
static int find_class(const char *name) {
    if (!name) return -1;
    if ((uintptr_t)name < 0x10000u) {                    /* an atom: one of ours, or a built-in's */
        uint32_t a = (uint32_t)(uintptr_t)name;
        const char *b = a == 0x80 ? "Button" : a == 0x81 ? "Edit" : a == 0x82 ? "Static" : a == 0x83 ? "ListBox"
                      : a == 0x84 ? "ScrollBar" : a == 0x85 ? "ComboBox" : a == 0x8002 ? "#32770" : NULL;
        if (b) return find_class(b);
        return a >= 0xC000u && a - 0xC000u < (uint32_t)g_ncls ? (int)(a - 0xC000u) : -1;
    }
    for (int i = 0; i < g_ncls; i++) if (!strcasecmp(g_cls[i].name, name)) return i;
    return -1;
}
static int add_class(const char *name, uint32_t proc, uint32_t style, uint32_t extra, uint32_t hinst, int kind) {
    int i = find_class(name);
    if (i < 0) { if (g_ncls >= MAX_CLASSES) return -1; i = g_ncls++; }
    snprintf(g_cls[i].name, sizeof g_cls[i].name, "%s", name);
    g_cls[i].proc = proc, g_cls[i].style = style, g_cls[i].extra = extra, g_cls[i].hinst = hinst, g_cls[i].kind = kind;
    return i;
}

static void measure(win_t *x);
static void item_free(win_t *x) {
    for (int i = 0; i < x->nitems; i++) free(x->items[i].text);
    free(x->items);
    x->items = NULL, x->nitems = x->citems = 0;
}

uint32_t hle_create_window(uint32_t exstyle, const char *cls, const char *title, uint32_t style, int px, int py, int pw, int ph,
                           uint32_t parent, uint32_t menu, uint32_t hinst, uint32_t param) {
    int c = find_class(cls);
    if (c < 0) {
        fprintf(stderr, "[user32] CreateWindowEx: no class %s\n", (uintptr_t)cls < 0x10000u ? "(atom)" : cls);
        hle_set_last_error(1407u);                       /* ERROR_CANNOT_FIND_WND_CLASS */
        return 0;
    }
    int i = 1;
    while (i < MAX_WIN && g_win[i].used) i++;
    if (i == MAX_WIN) return 0;
    win_t *x = &g_win[i];
    memset(x, 0, sizeof *x);
    x->used = 1, x->hwnd = HWND_OF(i), x->cls = c, x->kind = g_cls[c].kind, x->proc = g_cls[c].proc;
    x->style = style, x->exstyle = exstyle, x->hinst = hinst, x->seq = ++g_seq;
    if (style & WS_CHILD) x->parent = parent, x->id = menu;
    else x->owner = parent, x->menu = menu;
    if ((int)px == (int)0x80000000) px = 0, py = 0;      /* CW_USEDEFAULT */
    if ((int)pw == (int)0x80000000) pw = g_screen_w, ph = g_screen_h;
    x->x = px, x->y = py, x->w = pw, x->h = ph;
    x->cursel = -1, x->item_h = 13, x->rmax = 100, x->limit = 0x7FFFFFFE;
    if (title && (uintptr_t)title >= 0x10000u) snprintf(x->text, sizeof x->text, "%s", title);
    uint32_t cs[12] = { param, hinst, menu, parent, (uint32_t)ph, (uint32_t)pw, (uint32_t)py, (uint32_t)px, style,
                        (uint32_t)(uintptr_t)title, (uint32_t)(uintptr_t)cls, exstyle };
    uint32_t h = x->hwnd;
    hle_send(h, WM_NCCREATE, 0, (uint32_t)(uintptr_t)cs);
    if ((int32_t)hle_send(h, WM_CREATE, 0, (uint32_t)(uintptr_t)cs) == -1) {
        x = W(h);
        if (x) item_free(x), x->used = 0;
        return 0;
    }
    x = W(h);
    if (!x) return 0;
    if (x->kind == K_COMBOBOX || x->kind == K_LISTBOX) measure(x);
    if (!(x = W(h))) return 0;
    if (x->parent && !(x->exstyle & 0x4u)) {             /* WS_EX_NOPARENTNOTIFY */
        win_t *p = W(x->parent);
        if (p) hle_send(p->hwnd, 0x0210u, WM_CREATE | (x->id << 16), h);   /* WM_PARENTNOTIFY */
    }
    if (style & WS_VISIBLE) { invalidate(x, 0); hle_send(h, WM_SHOWWINDOW, 1, 0); }
    if (!x->parent && !g_active && (style & WS_VISIBLE)) g_active = h;
    return h;
}

/* A list's item height, and a combo box's selection field, as Windows works
 * them out: from the font (13 pixels, plus 4 for the field), or for an
 * owner-drawn one from the parent's answer to WM_MEASUREITEM. A drop-down
 * combo's window is only its field; the template's height is how tall it is
 * dropped. */
static void measure(win_t *x) {
    uint32_t h = x->hwnd;
    int combo = x->kind == K_COMBOBOX, owner = (x->style & 0x30u) != 0;
    win_t *p = W(x->parent);
    x->sel_h = 17, x->item_h = 13, x->drop_h = x->h;
    if (owner && p) {
        uint32_t mi[6] = { combo ? 3u : 2u, x->id, combo ? 0xFFFFFFFFu : 0u, (uint32_t)x->w, combo ? 11u : 13u, 0 };
        hle_send(p->hwnd, WM_MEASUREITEM, x->id, (uint32_t)(uintptr_t)mi);
        if (!(x = W(h))) return;
        if (combo) {
            x->sel_h = 6 + (int)mi[4];
            if (x->style & 0x10u) {                      /* CBS_OWNERDRAWFIXED: the list's items too */
                uint32_t li[6] = { 3u, x->id, 0, (uint32_t)x->w, 17u, 0 };
                hle_send(x->parent, WM_MEASUREITEM, x->id, (uint32_t)(uintptr_t)li);
                if (!(x = W(h))) return;
                x->item_h = (int)li[4];
            }
        } else {
            x->item_h = (int)mi[4];
        }
    }
    if (combo && (x->style & 3u) != 1u) x->h = x->sel_h + 4;   /* not CBS_SIMPLE */
}

static void destroy(uint32_t h) {
    win_t *x = W(h);
    if (!x || x->destroying) return;
    x->destroying = 1;
    for (int i = 0; i < MAX_WIN; i++)                    /* owned windows and children first */
        if (g_win[i].used && (g_win[i].parent == h || g_win[i].owner == h)) destroy(g_win[i].hwnd);
    hle_send(h, WM_DESTROY, 0, 0);
    hle_send(h, WM_NCDESTROY, 0, 0);
    x = W(h);
    if (!x) return;
    if (g_focus == h) g_focus = 0;
    if (g_capture == h) g_capture = 0;
    if (g_active == h) g_active = 0;
    for (int i = 0; i < MAX_TIMERS; i++) if (g_timer[i].used && g_timer[i].hwnd == h) g_timer[i].used = 0;
    for (int i = 0; i < g_qn; i++) if (g_q[i].hwnd == h) g_q[i].message = 0xFFFFFFFFu;   /* dropped when popped */
    item_free(x);
    x->used = 0;
}

static void set_focus(uint32_t h) {
    uint32_t old = g_focus;
    if (old == h) return;
    g_focus = h;
    if (old && W(old)) hle_send(old, WM_KILLFOCUS, h, 0);
    if (h && W(h)) hle_send(h, WM_SETFOCUS, old, 0);
}

static void notify(win_t *x, uint32_t code) {
    win_t *p = W(x->parent);
    if (p) hle_send(p->hwnd, WM_COMMAND, (x->id & 0xFFFF) | (code << 16), x->hwnd);
}

/* ---- the queue's reader ----
 * Posted messages first (input among them, in order), then WM_QUIT, then
 * WM_PAINT for a visible window with an update region, then due timers. */
static int matches(const msg_t *m, uint32_t hwnd, uint32_t lo, uint32_t hi) {
    if (m->message == 0xFFFFFFFFu) return 0;
    if (hwnd == 0xFFFFFFFFu) { if (m->hwnd) return 0; }
    else if (hwnd && !(m->hwnd == hwnd || is_descendant(m->hwnd, hwnd))) return 0;
    if (lo || hi) return m->message >= lo && m->message <= hi;
    return 1;
}

static int next_message(msg_t *out, uint32_t hwnd, uint32_t lo, uint32_t hi, int remove) {
    /* drop the dead (messages to destroyed windows) */
    while (g_qn && g_q[0].message == 0xFFFFFFFFu) memmove(g_q, g_q + 1, sizeof g_q[0] * (size_t)--g_qn);
    for (int i = 0; i < g_qn; i++)
        if (matches(&g_q[i], hwnd, lo, hi)) {
            *out = g_q[i];
            if (remove) memmove(g_q + i, g_q + i + 1, sizeof g_q[0] * (size_t)(--g_qn - i));
            return 1;
        }
    if (g_quit && (!(lo || hi) || (WM_QUIT >= lo && WM_QUIT <= hi))) {
        memset(out, 0, sizeof *out);
        out->message = WM_QUIT, out->wParam = g_quit_code, out->time = hle_ticks_ms();
        if (remove) g_quit = 0;
        return 1;
    }
    if (!(lo || hi) || (WM_PAINT >= lo && WM_PAINT <= hi))
        for (int i = 0; i < MAX_WIN; i++) {
            win_t *x = &g_win[i];
            if (x->used && x->inval && visible(x) && (!hwnd || hwnd == 0xFFFFFFFFu ? hwnd != 0xFFFFFFFFu : (x->hwnd == hwnd || is_descendant(x->hwnd, hwnd)))) {
                memset(out, 0, sizeof *out);
                out->hwnd = x->hwnd, out->message = WM_PAINT, out->time = hle_ticks_ms();
                return 1;                                /* stays until the window validates */
            }
        }
    if (!(lo || hi) || (WM_TIMER >= lo && WM_TIMER <= hi)) {
        uint32_t now = hle_ticks_ms();
        for (int i = 0; i < MAX_TIMERS; i++)
            if (g_timer[i].used && (int32_t)(now - g_timer[i].due) >= 0 &&
                (!hwnd || g_timer[i].hwnd == hwnd || is_descendant(g_timer[i].hwnd, hwnd))) {
                memset(out, 0, sizeof *out);
                out->hwnd = g_timer[i].hwnd, out->message = WM_TIMER, out->wParam = g_timer[i].id;
                out->lParam = g_timer[i].proc, out->time = now;
                if (remove) g_timer[i].due = now + g_timer[i].elapse;
                return 1;
            }
    }
    return 0;
}
static void put_msg(uint32_t lp, const msg_t *m) {
    MEM32(lp) = m->hwnd, MEM32(lp + 4) = m->message, MEM32(lp + 8) = m->wParam, MEM32(lp + 12) = m->lParam;
    MEM32(lp + 16) = m->time, MEM32(lp + 20) = (uint32_t)m->x, MEM32(lp + 24) = (uint32_t)m->y;
}
static void pump(void) {
    hle_ws_poll();
    if (g_pump) g_pump();
}
/* An empty queue with nothing to pump it is the end of a headless loop (the
 * selftests); with a pump, GetMessage waits, giving the machine up. */
static int wait_message(msg_t *m, uint32_t hwnd, uint32_t lo, uint32_t hi) {
    for (;;) {
        if (next_message(m, hwnd, lo, hi, 1)) return 1;
        if (!g_pump) { memset(m, 0, sizeof *m); m->message = WM_QUIT; return 1; }
        pump();
        if (next_message(m, hwnd, lo, hi, 1)) return 1;
        hle_block_begin();
        usleep(1000);
        hle_block_end();
    }
}

static void u_GetMessageA(void) {                        /* (msg, hwnd, min, max) */
    msg_t m;
    wait_message(&m, A32(1), A32(2), A32(3));
    put_msg(A32(0), &m);
    RET(m.message == WM_QUIT ? 0u : 1u, 4);
}
static void u_PeekMessageA(void) {                       /* (msg, hwnd, min, max, remove) */
    msg_t m;
    int remove = A32(4) & 1;
    if (!next_message(&m, A32(1), A32(2), A32(3), remove)) {
        pump();
        if (!next_message(&m, A32(1), A32(2), A32(3), remove)) RET(0, 5);
    }
    put_msg(A32(0), &m);
    RET(1, 5);
}
static void u_WaitMessage(void) {
    msg_t m;
    while (!next_message(&m, 0, 0, 0, 0)) {
        if (!g_pump) break;
        pump();
        hle_block_begin(); usleep(1000); hle_block_end();
    }
    RET(1, 0);
}
static void u_PostMessageA(void) {
    if (A32(1) == WM_QUIT) { g_quit = 1, g_quit_code = A32(2); RET(1, 4); }
    q_push(A32(0), A32(1), A32(2), A32(3));
    RET(1, 4);
}
static void u_PostQuitMessage(void) { g_quit = 1, g_quit_code = A32(0); RETV(1); }
static void u_SendMessageA(void) { RET(hle_send(A32(0), A32(1), A32(2), A32(3)), 4); }
static void u_CallWindowProcA(void) { RET(call_proc(A32(0), A32(1), A32(2), A32(3), A32(4)), 5); }

/* Virtual key to character, US layout, as TranslateMessage and ToAscii see it. */
static int vk_char(uint32_t vk, int shift) {
    static const char shifted_digits[] = ")!@#$%^&*(";
    if (vk >= 'A' && vk <= 'Z') return shift ^ ((g_keys[0x14] & 1) != 0) ? (int)vk : (int)vk + 32;
    if (vk >= '0' && vk <= '9') return shift ? shifted_digits[vk - '0'] : (int)vk;
    if (vk >= 0x60 && vk <= 0x69) return '0' + (int)(vk - 0x60);
    switch (vk) {
    case 0x20: return ' ';
    case 0x08: return 8;
    case 0x0D: return 13;
    case 0x1B: return 27;
    case 0x09: return 9;
    case 0xBA: return shift ? ':' : ';';
    case 0xBB: return shift ? '+' : '=';
    case 0xBC: return shift ? '<' : ',';
    case 0xBD: return shift ? '_' : '-';
    case 0xBE: return shift ? '>' : '.';
    case 0xBF: return shift ? '?' : '/';
    case 0xC0: return shift ? '~' : '`';
    case 0xDB: return shift ? '{' : '[';
    case 0xDC: return shift ? '|' : '\\';
    case 0xDD: return shift ? '}' : ']';
    case 0xDE: return shift ? '"' : '\'';
    case 0x6A: return '*';
    case 0x6B: return '+';
    case 0x6D: return '-';
    case 0x6E: return '.';
    case 0x6F: return '/';
    default: return 0;
    }
}
static void u_TranslateMessage(void) {
    uint32_t lp = A32(0), m = MEM32(lp + 4);
    if (m == WM_KEYDOWN || m == WM_SYSKEYDOWN) {
        int c = (g_keys[VK_CONTROL] & 0x80) && MEM32(lp + 8) >= 'A' && MEM32(lp + 8) <= 'Z'
              ? (int)(MEM32(lp + 8) - 'A' + 1) : vk_char(MEM32(lp + 8), (g_keys[VK_SHIFT] & 0x80) != 0);
        if (c) q_push(MEM32(lp), m == WM_KEYDOWN ? WM_CHAR : WM_SYSCHAR, (uint32_t)c, MEM32(lp + 12));
        RET(c != 0, 1);
    }
    RET(0, 1);
}
static void u_DispatchMessageA(void) {
    uint32_t lp = A32(0), h = MEM32(lp), m = MEM32(lp + 4);
    if (m == WM_TIMER && MEM32(lp + 12)) {               /* a TIMERPROC */
        uint32_t a[4] = { h, WM_TIMER, MEM32(lp + 8), hle_ticks_ms() };
        RET(hle_call_guest(MEM32(lp + 12), 4, a), 1);
    }
    win_t *x = W(h);
    if (!x) RET(0, 1);
    uint32_t r = call_proc(x->proc, h, m, MEM32(lp + 8), MEM32(lp + 12));
    if (m == WM_PAINT && (x = W(h)) && x->inval && x->kind != K_GUEST) x->inval = 0;
    RET(r, 1);
}

/* ---- host input ----
 * A button press goes to the deepest visible, enabled window under the point
 * that is not a static (statics pass clicks through, HTTRANSPARENT), or to
 * the window that has the capture; keys go to the focus, else the active
 * window. */
static int depth_of(win_t *x) { int n = 0; while ((x = W(x->parent))) n++; return n; }
uint32_t hle_window_at(int sx, int sy, int *cx, int *cy) {
    win_t *best = NULL;
    int bd = -1, bseq = 0;
    for (int i = 0; i < MAX_WIN; i++) {
        win_t *x = &g_win[i];
        if (!x->used || !visible(x) || (x->style & WS_DISABLED) || x->kind == K_STATIC) continue;
        int ox, oy;
        origin(x, &ox, &oy);
        if (sx < ox || sy < oy || sx >= ox + x->w || sy >= oy + x->h) continue;
        int d = depth_of(x);
        /* deepest wins; among equals, the later-created (a control over a group box) */
        if (d > bd || (d == bd && x->seq > bseq)) best = x, bd = d, bseq = x->seq;
    }
    if (best && cx) { int ox, oy; origin(best, &ox, &oy); *cx = sx - ox, *cy = sy - oy; }
    return best ? best->hwnd : 0;
}
uint32_t hle_focus_window(void) { return g_focus ? g_focus : g_active; }

static uint32_t mk_state(void) {
    return (g_keys[0x01] & 0x80 ? 1u : 0u) | (g_keys[0x02] & 0x80 ? 2u : 0u) | (g_keys[VK_SHIFT] & 0x80 ? 4u : 0u) |
           (g_keys[VK_CONTROL] & 0x80 ? 8u : 0u) | (g_keys[0x04] & 0x80 ? 0x10u : 0u);
}
void hle_input_mouse(uint32_t message, int sx, int sy) {
    g_cursor_x = sx, g_cursor_y = sy;
    uint32_t vk = message == WM_LBUTTONDOWN || message == WM_LBUTTONUP ? 1 : message == WM_RBUTTONDOWN || message == WM_RBUTTONUP ? 2
                : message == WM_MBUTTONDOWN || message == WM_MBUTTONUP ? 4 : 0;
    int down = message == WM_LBUTTONDOWN || message == WM_RBUTTONDOWN || message == WM_MBUTTONDOWN;
    if (vk) g_keys[vk] = down ? (uint8_t)(0x80 | ((g_keys[vk] & 1) ^ 1)) : (uint8_t)(g_keys[vk] & 1);
    int cx, cy;
    uint32_t t;
    if (g_capture && W(g_capture)) {
        int ox, oy;
        origin(W(g_capture), &ox, &oy);
        t = g_capture, cx = sx - ox, cy = sy - oy;
    } else {
        t = hle_window_at(sx, sy, &cx, &cy);
    }
    if (!t) return;
    q_push(t, message, mk_state(), ((uint32_t)(cy & 0xFFFF) << 16) | (uint32_t)(cx & 0xFFFF));
}
void hle_input_key(int down, uint32_t vk, uint32_t scan) {
    vk &= 0xFF;
    if (down) g_keys[vk] = (uint8_t)(0x80 | ((g_keys[vk] & 1) ^ !(g_keys[vk] & 0x80)));
    else g_keys[vk] &= 1;
    if (vk == 0xA0 || vk == 0xA1) { if (down) g_keys[VK_SHIFT] |= 0x80; else g_keys[VK_SHIFT] &= 1; }
    if (vk == 0xA2 || vk == 0xA3) { if (down) g_keys[VK_CONTROL] |= 0x80; else g_keys[VK_CONTROL] &= 1; }
    if (vk == 0xA4 || vk == 0xA5) { if (down) g_keys[VK_MENU] |= 0x80; else g_keys[VK_MENU] &= 1; }
    uint32_t t = hle_focus_window();
    int alt = (g_keys[VK_MENU] & 0x80) != 0;
    uint32_t l = 1u | (scan & 0xFFu) << 16 | (alt ? 1u << 29 : 0) | (down ? 0 : 3u << 30);
    if (t) q_push(t, alt || vk == VK_MENU || vk == 0x79 ? (down ? WM_SYSKEYDOWN : WM_SYSKEYUP) : (down ? WM_KEYDOWN : WM_KEYUP), vk, l);
}
void hle_input_cursor(int sx, int sy) { g_cursor_x = sx, g_cursor_y = sy; }
void hle_input_key_state(uint32_t vk, int down) { if (down) g_keys[vk & 0xFF] |= 0x80; else g_keys[vk & 0xFF] &= 1; }

/* ---- DefWindowProc ---- */
static uint32_t def_proc(uint32_t h, uint32_t m, uint32_t w, uint32_t l) {
    win_t *x = W(h);
    if (!x) return 0;
    switch (m) {
    case WM_NCCREATE: return 1;
    case WM_PAINT: x->inval = 0; return 0;
    case WM_ERASEBKGND: return 1;
    case WM_CLOSE: destroy(h); return 0;
    case WM_NCHITTEST: return 1;                         /* HTCLIENT */
    case WM_SETTEXT:
        snprintf(x->text, sizeof x->text, "%s", l ? (const char *)(uintptr_t)l : "");
        return 1;
    case WM_GETTEXT: {
        uint32_t n = (uint32_t)strlen(x->text);
        if (!w) return 0;
        if (n > w - 1) n = w - 1;
        memcpy((void *)(uintptr_t)l, x->text, n);
        ((char *)(uintptr_t)l)[n] = 0;
        return n;
    }
    case WM_GETTEXTLENGTH: return (uint32_t)strlen(x->text);
    case WM_SETFONT: x->font = w; return 0;
    case WM_GETFONT: return x->font;
    case WM_MOUSEACTIVATE: return 1;                     /* MA_ACTIVATE */
    case WM_SETCURSOR: return 0;
    case WM_SYSCOMMAND: if ((w & 0xFFF0u) == 0xF060u) hle_send(h, WM_CLOSE, 0, 0); return 0;   /* SC_CLOSE */
    case WM_CTLCOLORMSGBOX: case 0x0133: case 0x0134: case 0x0135: case 0x0136: case 0x0137: case WM_CTLCOLORSTATIC:
        return 0x0DB00001u;                              /* a stock white brush */
    default: return 0;
    }
}
static void p_DefWindowProc(void) { RET(def_proc(A32(0), A32(1), A32(2), A32(3)), 4); }
static void u_DefWindowProcA(void) { RET(def_proc(A32(0), A32(1), A32(2), A32(3)), 4); }

/* ---- the standard controls ---- */
static void owner_draw(win_t *x, uint32_t type, int item, uint32_t state, int l, int t, int r, int b) {
    win_t *p = W(x->parent);
    if (!p) return;
    uint32_t dis[12] = { type, x->id, (uint32_t)item, 1u /* ODA_DRAWENTIRE */, state, x->hwnd, 0x0DC00001u,
                         (uint32_t)l, (uint32_t)t, (uint32_t)r, (uint32_t)b, item >= 0 && item < x->nitems ? x->items[item].data : 0 };
    hle_send(p->hwnd, WM_DRAWITEM, x->id, (uint32_t)(uintptr_t)dis);
}

static void radio_group_clear(win_t *x) {
    win_t *p = W(x->parent);
    if (!p) return;
    for (int i = 0; i < MAX_WIN; i++) {
        win_t *s = &g_win[i];
        if (s->used && s->parent == p->hwnd && s != x && s->kind == K_BUTTON && ((s->style & 0xF) == 9 || (s->style & 0xF) == 4))
            if (s->check) s->check = 0, invalidate(s, 0);
    }
}
static void button_click(win_t *x) {
    uint32_t bs = x->style & 0xF;
    if (bs == 3) x->check = !x->check;                  /* BS_AUTOCHECKBOX */
    else if (bs == 6) x->check = (x->check + 1) % 3;    /* BS_AUTO3STATE */
    else if (bs == 9) { radio_group_clear(x); x->check = 1; }   /* BS_AUTORADIOBUTTON */
    invalidate(x, 0);
    notify(x, 0);                                        /* BN_CLICKED */
}
static uint32_t button_proc(win_t *x, uint32_t m, uint32_t w, uint32_t l) {
    uint32_t h = x->hwnd, bs = x->style & 0xF;
    switch (m) {
    case WM_GETDLGCODE:
        return bs == 1 ? 0x10u : bs == 0 || bs == 0xB ? 0x2000u : bs == 9 || bs == 4 ? 0x40u : 0;  /* DEF/UNDEF PUSH, RADIO */
    case 0x00F0u: return (uint32_t)x->check;            /* BM_GETCHECK */
    case 0x00F1u: x->check = (int)w; invalidate(x, 0); return 0;   /* BM_SETCHECK */
    case 0x00F2u: return (uint32_t)x->check | (x->state ? 4u : 0u) | (g_focus == h ? 8u : 0u);    /* BM_GETSTATE */
    case 0x00F3u: x->state = w != 0; invalidate(x, 0); return 0;   /* BM_SETSTATE */
    case 0x00F4u: x->style = (x->style & 0xFFFF0000u) | (w & 0xFFFF); invalidate(x, 0); return 0;  /* BM_SETSTYLE */
    case 0x00F5u: button_click(x); return 0;            /* BM_CLICK */
    case WM_LBUTTONDOWN: case WM_LBUTTONDBLCLK:
        if (bs == 7) return 0;                           /* a group box takes no clicks */
        x->state = 1, g_capture = h;
        set_focus(h);
        invalidate(x, 0);
        return 0;
    case WM_LBUTTONUP: {
        int was = x->state;
        int cx = (int16_t)(l & 0xFFFF), cy = (int16_t)(l >> 16);
        x->state = 0;
        if (g_capture == h) g_capture = 0;
        invalidate(x, 0);
        if (was && cx >= 0 && cy >= 0 && cx < x->w && cy < x->h) button_click(x);
        return 0;
    }
    case WM_KEYUP: if (w == ' ') button_click(x); return 0;
    case WM_SETFOCUS: case WM_KILLFOCUS: invalidate(x, 0); return 0;
    case WM_ENABLE: invalidate(x, 0); return 0;
    case WM_PAINT:
        if (bs == 0xB) owner_draw(x, 4 /* ODT_BUTTON */, 0, (x->state ? 1u : 0u) | (g_focus == h ? 0x10u : 0u) |
                                  (x->style & WS_DISABLED ? 4u : 0u), 0, 0, x->w, x->h);
        if ((x = W(h))) x->inval = 0;
        return 0;
    default: return def_proc(h, m, w, l);
    }
}

static uint32_t static_proc(win_t *x, uint32_t m, uint32_t w, uint32_t l) {
    switch (m) {
    case WM_NCHITTEST: return x->style & 0x100u ? 1u : 0xFFFFFFFFu;   /* SS_NOTIFY, else HTTRANSPARENT */
    case WM_LBUTTONDOWN: if (x->style & 0x100u) notify(x, 0); return 0;   /* STN_CLICKED */
    case 0x0172u: { uint32_t o = x->extra[0]; x->extra[0] = l; return o; }   /* STM_SETIMAGE */
    case 0x0173u: return x->extra[0];                    /* STM_GETIMAGE */
    case WM_PAINT:
        if ((x->style & 0x1Fu) == 0xDu) owner_draw(x, 5 /* ODT_STATIC */, 0, 0, 0, 0, x->w, x->h);   /* SS_OWNERDRAW */
        if ((x = W(x->hwnd))) x->inval = 0;
        return 0;
    default: return def_proc(x->hwnd, m, w, l);
    }
}

static uint32_t edit_proc(win_t *x, uint32_t m, uint32_t w, uint32_t l) {
    uint32_t h = x->hwnd;
    switch (m) {
    case WM_GETDLGCODE: return 0x1u | 0x2u | 0x80u | (x->style & 4u ? 0x4u : 0);   /* WANTARROWS|WANTTAB? no: CHARS|HASSETSEL */
    case WM_SETTEXT:
        def_proc(h, m, w, l);
        x->sel0 = x->sel1 = (int)strlen(x->text);
        invalidate(x, 0);
        notify(x, 0x0300u);                              /* EN_CHANGE */
        return 1;
    case WM_CHAR: {
        size_t n = strlen(x->text);
        if (x->style & 0x800u) return 0;                 /* ES_READONLY */
        if (x->sel1 > x->sel0) {                         /* replace the selection */
            memmove(x->text + x->sel0, x->text + x->sel1, n - (size_t)x->sel1 + 1);
            n = strlen(x->text), x->sel1 = x->sel0;
        }
        if (w == 8) {
            if (x->sel0 > 0) { memmove(x->text + x->sel0 - 1, x->text + x->sel0, n - (size_t)x->sel0 + 1); x->sel0--, x->sel1 = x->sel0; }
        } else if (w >= 32 && n + 1 < sizeof x->text && (int)n < x->limit) {
            memmove(x->text + x->sel0 + 1, x->text + x->sel0, n - (size_t)x->sel0 + 1);
            x->text[x->sel0++] = (char)w, x->sel1 = x->sel0;
        } else {
            return 0;
        }
        invalidate(x, 0);
        notify(x, 0x0400u);                              /* EN_UPDATE */
        notify(x, 0x0300u);                              /* EN_CHANGE */
        return 0;
    }
    case WM_KEYDOWN: {
        int n = (int)strlen(x->text);
        if (w == 0x25 && x->sel0 > 0) x->sel0--, x->sel1 = x->sel0;
        else if (w == 0x27 && x->sel0 < n) x->sel0++, x->sel1 = x->sel0;
        else if (w == 0x24) x->sel0 = x->sel1 = 0;
        else if (w == 0x23) x->sel0 = x->sel1 = n;
        else if (w == 0x2E && x->sel0 < n) { memmove(x->text + x->sel0, x->text + x->sel0 + 1, (size_t)(n - x->sel0)); notify(x, 0x0300u); }
        invalidate(x, 0);
        return 0;
    }
    case WM_LBUTTONDOWN: set_focus(h); return 0;
    case WM_SETFOCUS: notify(x, 0x0100u); invalidate(x, 0); return 0;   /* EN_SETFOCUS */
    case WM_KILLFOCUS: notify(x, 0x0200u); invalidate(x, 0); return 0;  /* EN_KILLFOCUS */
    case 0x00B0u:                                        /* EM_GETSEL */
        if (w) MEM32(w) = (uint32_t)x->sel0;
        if (l) MEM32(l) = (uint32_t)x->sel1;
        return (uint32_t)x->sel0 | (uint32_t)x->sel1 << 16;
    case 0x00B1u: {                                      /* EM_SETSEL */
        int n = (int)strlen(x->text), a = (int)w, b = (int)l;
        if (a < 0) { x->sel0 = x->sel1 = n; return 0; }
        if (b < 0 || b > n) b = n;
        if (a > n) a = n;
        x->sel0 = a < b ? a : b, x->sel1 = a < b ? b : a;
        return 0;
    }
    case 0x00C2u: {                                      /* EM_REPLACESEL */
        const char *s = (const char *)(uintptr_t)l;
        char tmp[512];
        snprintf(tmp, sizeof tmp, "%.*s%s%s", x->sel0, x->text, s ? s : "", x->text + x->sel1);
        x->sel0 += s ? (int)strlen(s) : 0, x->sel1 = x->sel0;
        snprintf(x->text, sizeof x->text, "%s", tmp);
        notify(x, 0x0300u);
        return 0;
    }
    case 0x00C5u: x->limit = w ? (int)w : 0x7FFFFFFE; return 0;   /* EM_LIMITTEXT */
    case 0x00D5u: return (uint32_t)x->limit;             /* EM_GETLIMITTEXT */
    case 0x00CFu: if (w) x->style |= 0x800u; else x->style &= ~0x800u; return 1;   /* EM_SETREADONLY */
    case 0x00B8u: return 0;                              /* EM_GETMODIFY */
    case 0x00BAu: return 1;                              /* EM_GETLINECOUNT */
    case WM_PAINT: x->inval = 0; return 0;
    default: return def_proc(h, m, w, l);
    }
}

/* list items, for the list box and the combo box */
static int item_add(win_t *x, int at, const char *s, uint32_t data, int sorted) {
    if (x->nitems == x->citems) {
        x->citems = x->citems ? x->citems * 2 : 16;
        x->items = (struct item *)realloc(x->items, sizeof *x->items * (size_t)x->citems);
    }
    if (sorted && s) { at = 0; while (at < x->nitems && strcasecmp(x->items[at].text ? x->items[at].text : "", s) <= 0) at++; }
    if (at < 0 || at > x->nitems) at = x->nitems;
    memmove(x->items + at + 1, x->items + at, sizeof *x->items * (size_t)(x->nitems - at));
    x->items[at].text = strdup(s ? s : "");
    x->items[at].data = data;
    x->nitems++;
    if (x->cursel >= at) x->cursel++;
    return at;
}
static int item_del(win_t *x, int at) {
    if (at < 0 || at >= x->nitems) return -1;
    free(x->items[at].text);
    memmove(x->items + at, x->items + at + 1, sizeof *x->items * (size_t)(x->nitems - at - 1));
    x->nitems--;
    if (x->cursel == at) x->cursel = -1; else if (x->cursel > at) x->cursel--;
    return x->nitems;
}
static int item_find(win_t *x, int after, const char *s, int exact) {
    if (!s) return -1;
    size_t n = strlen(s);
    for (int k = 0; k < x->nitems; k++) {
        int i = (after + 1 + k) % (x->nitems ? x->nitems : 1);
        const char *t = x->items[i].text ? x->items[i].text : "";
        if (exact ? !strcasecmp(t, s) : !strncasecmp(t, s, n)) return i;
    }
    return -1;
}
/* The list messages, LB_ and CB_ alike: `base` maps a CB_ code to its LB_ one. */
static uint32_t list_msg(win_t *x, uint32_t m, uint32_t w, uint32_t l, int *handled) {
    int sorted = x->kind == K_LISTBOX ? (x->style & 2u) != 0 : (x->style & 0x100u) != 0;   /* LBS_SORT, CBS_SORT */
    int strings = !(x->style & (x->kind == K_LISTBOX ? 0x30u : 0x30u)) || (x->style & (x->kind == K_LISTBOX ? 0x40u : 0x200u));
    *handled = 1;
    switch (m) {
    case 0x0180u: case 0x0143u: return (uint32_t)item_add(x, -1, strings ? (const char *)(uintptr_t)l : NULL, strings ? 0 : l, sorted);
    case 0x0181u: case 0x014Au: return (uint32_t)item_add(x, (int)w, strings ? (const char *)(uintptr_t)l : NULL, strings ? 0 : l, 0);
    case 0x0182u: case 0x0144u: return (uint32_t)item_del(x, (int)w);
    case 0x0184u: case 0x014Bu: item_free(x); x->cursel = -1, x->top = 0; invalidate(x, 0); return 0;
    case 0x0186u: case 0x014Eu:                          /* SETCURSEL */
        x->cursel = (int)w < x->nitems ? (int)w : -1;
        invalidate(x, 0);
        return x->cursel < 0 && (int)w != -1 ? 0xFFFFFFFFu : (uint32_t)x->cursel;
    case 0x0188u: case 0x0147u: return (uint32_t)x->cursel;   /* GETCURSEL */
    case 0x0187u: return (int)w == x->cursel;            /* LB_GETSEL */
    case 0x0185u: x->cursel = w ? (int)l : -1; invalidate(x, 0); return 0;   /* LB_SETSEL */
    case 0x0189u: case 0x0148u:                          /* GETTEXT / GETLBTEXT */
        if ((int)w < 0 || (int)w >= x->nitems) return 0xFFFFFFFFu;
        if (!strings) { MEM32(l) = x->items[w].data; return 4; }
        strcpy((char *)(uintptr_t)l, x->items[w].text);
        return (uint32_t)strlen(x->items[w].text);
    case 0x018Au: case 0x0149u:                          /* GETTEXTLEN */
        return (int)w < 0 || (int)w >= x->nitems ? 0xFFFFFFFFu : (uint32_t)strlen(x->items[w].text);
    case 0x018Bu: case 0x0146u: return (uint32_t)x->nitems;   /* GETCOUNT */
    case 0x018Cu: case 0x014Du: {                        /* SELECTSTRING */
        int i = item_find(x, (int)w, (const char *)(uintptr_t)l, 0);
        if (i >= 0) x->cursel = i, invalidate(x, 0);
        return (uint32_t)i;
    }
    case 0x018Fu: case 0x014Cu: return (uint32_t)item_find(x, (int)w, (const char *)(uintptr_t)l, 0);   /* FINDSTRING */
    case 0x01A2u: case 0x0158u: return (uint32_t)item_find(x, (int)w, (const char *)(uintptr_t)l, 1);   /* FINDSTRINGEXACT */
    case 0x018Eu: return (uint32_t)x->top;               /* LB_GETTOPINDEX */
    case 0x0197u: x->top = (int)w; invalidate(x, 0); return 0;   /* LB_SETTOPINDEX */
    case 0x0190u: return x->cursel >= 0;                 /* LB_GETSELCOUNT */
    case 0x0191u: if (x->cursel >= 0 && w) { MEM32(l) = (uint32_t)x->cursel; return 1; } return 0;   /* LB_GETSELITEMS */
    case 0x0199u: case 0x0150u: return (int)w >= 0 && (int)w < x->nitems ? x->items[w].data : 0xFFFFFFFFu;   /* GETITEMDATA */
    case 0x019Au: case 0x0151u: if ((int)w >= 0 && (int)w < x->nitems) x->items[w].data = l; return 0;     /* SETITEMDATA */
    case 0x0198u:                                        /* LB_GETITEMRECT */
        put_rect(l, 0, ((int)w - x->top) * x->item_h, x->w, ((int)w - x->top + 1) * x->item_h);
        return 1;
    case 0x01A0u: case 0x0153u: if (w != 0xFFFFFFFFu || x->kind == K_LISTBOX) x->item_h = (int)(l & 0xFFFF); return 0;   /* SETITEMHEIGHT */
    case 0x01A1u: case 0x0154u: return (uint32_t)x->item_h;   /* GETITEMHEIGHT */
    case 0x01A9u: {                                      /* LB_ITEMFROMPOINT */
        int i = x->top + (int16_t)(l >> 16) / (x->item_h ? x->item_h : 1);
        return i < x->nitems ? (uint32_t)i : (uint32_t)(x->nitems ? x->nitems - 1 : 0) | 0x10000u;
    }
    default: *handled = 0; return 0;
    }
}
static void paint_list(win_t *x) {
    uint32_t h = x->hwnd;
    if (x->style & (x->kind == K_LISTBOX ? 0x30u : 0x30u)) {   /* owner-drawn items */
        int rows = x->kind == K_LISTBOX ? x->h / (x->item_h ? x->item_h : 1) + 1 : 1;
        if (x->kind == K_COMBOBOX)                       /* the selection field, inside its border and left of the button */
            owner_draw(x, 3 /* ODT_COMBOBOX */, x->cursel, 0x1000u /* ODS_COMBOBOXEDIT */ | (g_focus == h ? 0x10u : 0u), 3, 3, x->w - 19, x->h - 3);
        else
            for (int r = 0; r < rows && x->top + r < x->nitems; r++) {
                owner_draw(x, 2 /* ODT_LISTBOX */, x->top + r, x->top + r == x->cursel ? 1u : 0u, 0, r * x->item_h, x->w, (r + 1) * x->item_h);
                if (!(x = W(h))) return;
            }
    }
    if ((x = W(h))) x->inval = 0;
}
static uint32_t listbox_proc(win_t *x, uint32_t m, uint32_t w, uint32_t l) {
    int handled;
    uint32_t r = list_msg(x, m, w, l, &handled);
    if (handled) return r;
    switch (m) {
    case WM_GETDLGCODE: return 0x1u | 0x2u;              /* DLGC_WANTARROWS | WANTCHARS... near enough */
    case WM_LBUTTONDOWN: case WM_LBUTTONDBLCLK: {
        int i = x->top + (int16_t)(l >> 16) / (x->item_h ? x->item_h : 1);
        set_focus(x->hwnd);
        if (i >= 0 && i < x->nitems && i != x->cursel) {
            x->cursel = i;
            invalidate(x, 0);
            if (x->style & 1u) notify(x, 1);             /* LBS_NOTIFY: LBN_SELCHANGE */
        }
        if (m == WM_LBUTTONDBLCLK && (x->style & 1u)) notify(x, 2);   /* LBN_DBLCLK */
        return 0;
    }
    case WM_KEYDOWN:
        if ((w == 0x26 && x->cursel > 0) || (w == 0x28 && x->cursel + 1 < x->nitems)) {
            x->cursel += w == 0x26 ? -1 : 1;
            invalidate(x, 0);
            if (x->style & 1u) notify(x, 1);
        }
        return 0;
    case WM_PAINT: paint_list(x); return 0;
    default: return def_proc(x->hwnd, m, w, l);
    }
}
static uint32_t combobox_proc(win_t *x, uint32_t m, uint32_t w, uint32_t l) {
    int handled;
    uint32_t r = list_msg(x, m, w, l, &handled);
    if (handled) {
        if (m == 0x014Eu && x->cursel >= 0) snprintf(x->text, sizeof x->text, "%s", x->items[x->cursel].text);
        return r;
    }
    switch (m) {
    case 0x014Fu: x->dropped = w != 0; notify(x, w ? 7u : 8u); return 1;   /* CB_SHOWDROPDOWN */
    case 0x0157u: return (uint32_t)x->dropped;           /* CB_GETDROPPEDSTATE */
    case 0x0152u: {                                      /* CB_GETDROPPEDCONTROLRECT: screen coordinates */
        int ox, oy;
        origin(x, &ox, &oy);
        put_rect(l, ox, oy, ox + x->w, oy + x->drop_h);
        return 1;
    }
    case 0x0141u: return 1;                              /* CB_LIMITTEXT */
    case 0x0155u: case 0x0156u: return 0;                /* CB_SETEXTENDEDUI / GETEXTENDEDUI */
    case WM_LBUTTONDOWN:
        set_focus(x->hwnd);
        x->dropped = !x->dropped;
        notify(x, x->dropped ? 7u : 8u);                 /* CBN_DROPDOWN / CBN_CLOSEUP */
        return 0;
    case WM_KEYDOWN:
        if ((w == 0x26 && x->cursel > 0) || (w == 0x28 && x->cursel + 1 < x->nitems)) {
            x->cursel += w == 0x26 ? -1 : 1;
            snprintf(x->text, sizeof x->text, "%s", x->items[x->cursel].text);
            invalidate(x, 0);
            notify(x, 1);                                /* CBN_SELCHANGE */
        }
        return 0;
    case WM_PAINT: paint_list(x); return 0;
    default: return def_proc(x->hwnd, m, w, l);
    }
}

static uint32_t trackbar_proc(win_t *x, uint32_t m, uint32_t w, uint32_t l) {
    uint32_t h = x->hwnd;
    switch (m) {
    case 0x0400u: return (uint32_t)x->pos;               /* TBM_GETPOS */
    case 0x0401u: return (uint32_t)x->rmin;              /* TBM_GETRANGEMIN */
    case 0x0402u: return (uint32_t)x->rmax;              /* TBM_GETRANGEMAX */
    case 0x0405u:                                        /* TBM_SETPOS */
        x->pos = (int)l < x->rmin ? x->rmin : (int)l > x->rmax ? x->rmax : (int)l;
        if (w) invalidate(x, 0);
        return 0;
    case 0x0406u: x->rmin = (int16_t)(l & 0xFFFF), x->rmax = (int16_t)(l >> 16); if (w) invalidate(x, 0); return 0;   /* TBM_SETRANGE */
    case 0x0407u: x->rmin = (int)l; return 0;            /* TBM_SETRANGEMIN */
    case 0x0408u: x->rmax = (int)l; return 0;            /* TBM_SETRANGEMAX */
    case 0x0414u: case 0x0415u: case 0x0417u: return 0;  /* TICFREQ, PAGESIZE, LINESIZE */
    case 0x0418u: case 0x041Fu: return 1;
    case 0x0419u: {                                      /* TBM_GETTHUMBRECT */
        int span = x->rmax > x->rmin ? x->rmax - x->rmin : 1, tx = 5 + (x->w - 10) * (x->pos - x->rmin) / span;
        put_rect(l, tx - 5, 0, tx + 5, x->h);
        return 0;
    }
    case 0x041Au: put_rect(l, 5, x->h / 2 - 2, x->w - 5, x->h / 2 + 2); return 0;   /* TBM_GETCHANNELRECT */
    case WM_LBUTTONDOWN: case WM_MOUSEMOVE: case WM_LBUTTONUP: {
        if (m == WM_MOUSEMOVE && !x->tracking) return 0;
        if (m == WM_LBUTTONDOWN) x->tracking = 1, g_capture = h, set_focus(h);
        int cx = (int16_t)(l & 0xFFFF), span = x->rmax - x->rmin, pos;
        pos = x->rmin + (span * (cx - 5) + (x->w - 10) / 2) / (x->w > 10 ? x->w - 10 : 1);
        x->pos = pos < x->rmin ? x->rmin : pos > x->rmax ? x->rmax : pos;
        invalidate(x, 0);
        win_t *p = W(x->parent);
        if (p) hle_send(p->hwnd, x->style & 2u ? WM_VSCROLL : WM_HSCROLL, (m == WM_LBUTTONUP ? 4u : 5u) | (uint32_t)x->pos << 16, h);
        if (m == WM_LBUTTONUP) {
            x->tracking = 0;
            if (g_capture == h) g_capture = 0;
            if ((p = W(x->parent))) hle_send(p->hwnd, x->style & 2u ? WM_VSCROLL : WM_HSCROLL, 8u /* TB_ENDTRACK */, h);
        }
        return 0;
    }
    case WM_PAINT: x->inval = 0; return 0;
    default: return def_proc(h, m, w, l);
    }
}
static uint32_t progress_proc(win_t *x, uint32_t m, uint32_t w, uint32_t l) {
    int old = x->pos;
    switch (m) {
    case 0x0401u: x->rmin = (int)(l & 0xFFFF), x->rmax = (int)(l >> 16); return 0;   /* PBM_SETRANGE */
    case 0x0402u: x->pos = (int)w; invalidate(x, 0); return (uint32_t)old;   /* PBM_SETPOS */
    case 0x0403u: x->pos += (int)w; invalidate(x, 0); return (uint32_t)old;  /* PBM_DELTAPOS */
    case 0x0404u: x->sel0 = (int)w; return 0;           /* PBM_SETSTEP */
    case 0x0405u: x->pos += x->sel0 ? x->sel0 : 10; invalidate(x, 0); return (uint32_t)old;   /* PBM_STEPIT */
    case 0x0406u: x->rmin = (int)w, x->rmax = (int)l; return 0;   /* PBM_SETRANGE32 */
    case 0x0408u: return (uint32_t)x->pos;               /* PBM_GETPOS */
    case WM_PAINT: x->inval = 0; return 0;
    default: return def_proc(x->hwnd, m, w, l);
    }
}
static uint32_t hotkey_proc(win_t *x, uint32_t m, uint32_t w, uint32_t l) {
    switch (m) {
    case 0x0401u: x->pos = (int)w; return 0;             /* HKM_SETHOTKEY */
    case 0x0402u: return (uint32_t)x->pos;               /* HKM_GETHOTKEY */
    case 0x0403u: return 0;                              /* HKM_SETRULES */
    case WM_PAINT: x->inval = 0; return 0;
    default: return def_proc(x->hwnd, m, w, l);
    }
}
static uint32_t listview_proc(win_t *x, uint32_t m, uint32_t w, uint32_t l) {
    if (m == WM_PAINT) { x->inval = 0; return 0; }
    if (m >= 0x1000u && m < 0x1100u) {                   /* LVM_*: an empty list view */
        if (m == 0x1004u) return 0;                      /* LVM_GETITEMCOUNT */
        if (m == 0x100Cu) return 0xFFFFFFFFu;            /* LVM_GETNEXTITEM */
        return m == 0x1007u || m == 0x101Bu || m == 0x1061u ? (uint32_t)x->nitems++ : 0;   /* INSERTITEM, INSERTCOLUMN */
    }
    return def_proc(x->hwnd, m, w, l);
}

/* ---- dialogs ---- */
static uint32_t dlg_call(win_t *x, uint32_t m, uint32_t w, uint32_t l) {
    return x->dlgproc ? call_proc(x->dlgproc, x->hwnd, m, w, l) : 0;
}
static uint32_t dialog_proc(win_t *x, uint32_t m, uint32_t w, uint32_t l) {
    uint32_t h = x->hwnd;
    uint32_t r = dlg_call(x, m, w, l);
    if (!(x = W(h))) return r;
    if (r) {
        if (m == WM_INITDIALOG || (m >= WM_CTLCOLORMSGBOX && m <= WM_CTLCOLORSTATIC) || m == 0x0039u ||
            m == 0x002Eu || m == 0x002Fu || m == 0x0037u)
            return r;
        return x->msgresult;
    }
    switch (m) {
    case WM_CLOSE: q_push(h, WM_COMMAND, IDCANCEL, 0); return 0;
    case WM_PAINT: x->inval = 0; return 0;
    case WM_ERASEBKGND: return 1;
    case WM_GETDLGCODE: return 0;
    default: return def_proc(h, m, w, l);
    }
}

/* The built-in procedures: one shim each, so CallWindowProcA on one (a
 * subclassing game's "old" procedure) comes back here. */
#define BUILTIN(name, fn) static void p_##name(void) { win_t *x = W(A32(0)); RET(x ? fn(x, A32(1), A32(2), A32(3)) : 0u, 4); }
BUILTIN(Button, button_proc)
BUILTIN(Static, static_proc)
BUILTIN(Edit, edit_proc)
BUILTIN(ListBox, listbox_proc)
BUILTIN(ComboBox, combobox_proc)
BUILTIN(Trackbar, trackbar_proc)
BUILTIN(Progress, progress_proc)
BUILTIN(Hotkey, hotkey_proc)
BUILTIN(ListView, listview_proc)
BUILTIN(Dialog, dialog_proc)
static const win32hle_shim g_builtin_procs[] = {
    { "hle.DefWindowProc", p_DefWindowProc }, { "hle.Button", p_Button }, { "hle.Static", p_Static },
    { "hle.Edit", p_Edit }, { "hle.ListBox", p_ListBox }, { "hle.ComboBox", p_ComboBox },
    { "hle.Trackbar", p_Trackbar }, { "hle.Progress", p_Progress }, { "hle.Hotkey", p_Hotkey },
    { "hle.ListView", p_ListView }, { "hle.Dialog", p_Dialog }, { 0, 0 } };

static void builtin_classes(void) {
    static int done;
    if (done) return;
    done = 1;
    win32hle_register(g_builtin_procs);
    add_class("#32770", hle_resolve("hle.Dialog"), 0, 30, 0, K_DIALOG);
    add_class("Button", hle_resolve("hle.Button"), 0, 0, 0, K_BUTTON);
    add_class("Static", hle_resolve("hle.Static"), 0, 0, 0, K_STATIC);
    add_class("Edit", hle_resolve("hle.Edit"), 0, 0, 0, K_EDIT);
    add_class("ListBox", hle_resolve("hle.ListBox"), 0, 0, 0, K_LISTBOX);
    add_class("ComboBox", hle_resolve("hle.ComboBox"), 0, 0, 0, K_COMBOBOX);
    add_class("ScrollBar", hle_resolve("hle.DefWindowProc"), 0, 0, 0, K_SCROLLBAR);
    add_class("msctls_trackbar32", hle_resolve("hle.Trackbar"), 0, 0, 0, K_TRACKBAR);
    add_class("msctls_progress32", hle_resolve("hle.Progress"), 0, 0, 0, K_PROGRESS);
    add_class("msctls_hotkey32", hle_resolve("hle.Hotkey"), 0, 0, 0, K_HOTKEY);
    add_class("SysListView32", hle_resolve("hle.ListView"), 0, 0, 0, K_LISTVIEW);
}

/* A template's string or ordinal (sz_Or_Ord), as a class/title pointer and
 * the position after it. */
static uint32_t sz_or_ord(uint32_t p, char *buf, size_t n, uint32_t *atom) {
    uint16_t c = MEM16(p);
    *atom = 0;
    buf[0] = 0;
    if (c == 0xFFFFu) { *atom = MEM16(p + 2); return p + 4; }
    size_t k = 0;
    for (; (c = MEM16(p)); p += 2) if (k + 1 < n) buf[k++] = (char)(c < 256 ? c : '?');
    buf[k] = 0;
    return p + 2;
}

static uint32_t create_dialog(uint32_t hinst, uint32_t tmpl, uint32_t parent, uint32_t proc, uint32_t param, int modal) {
    builtin_classes();
    int ex = MEM16(tmpl) == 1 && MEM16(tmpl + 2) == 0xFFFFu;
    uint32_t style, exstyle, p;
    int count, dx, dy, dcx, dcy;
    if (ex) {
        exstyle = MEM32(tmpl + 8), style = MEM32(tmpl + 12), count = MEM16(tmpl + 16);
        dx = (int16_t)MEM16(tmpl + 18), dy = (int16_t)MEM16(tmpl + 20), dcx = (int16_t)MEM16(tmpl + 22), dcy = (int16_t)MEM16(tmpl + 24);
        p = tmpl + 26;
    } else {
        style = MEM32(tmpl), exstyle = MEM32(tmpl + 4), count = MEM16(tmpl + 8);
        dx = (int16_t)MEM16(tmpl + 10), dy = (int16_t)MEM16(tmpl + 12), dcx = (int16_t)MEM16(tmpl + 14), dcy = (int16_t)MEM16(tmpl + 16);
        p = tmpl + 18;
    }
    char menu[64], cls[64], title[256], font[64];
    uint32_t atom, cls_atom;
    p = sz_or_ord(p, menu, sizeof menu, &atom);
    p = sz_or_ord(p, cls, sizeof cls, &cls_atom);
    p = sz_or_ord(p, title, sizeof title, &atom);
    if (style & DS_SETFONT) {
        p += ex ? 6 : 2;
        p = sz_or_ord(p, font, sizeof font, &atom);
    }
    int px = dx * DLG_BX / 4, py = dy * DLG_BY / 8, pw = dcx * DLG_BX / 4, ph = dcy * DLG_BY / 8;
    win_t *pp = W(parent);
    if ((style & DS_CENTER) || (!(style & WS_CHILD) && pp == NULL)) {
        px = (g_screen_w - pw) / 2, py = (g_screen_h - ph) / 2;
    } else if (!(style & WS_CHILD) && pp) {
        int ox, oy;
        origin(pp, &ox, &oy);
        px += ox, py += oy;
    }
    const char *dcls = cls[0] ? cls : cls_atom ? (const char *)(uintptr_t)cls_atom : "#32770";
    uint32_t h = hle_create_window(exstyle, dcls, title, style & ~WS_VISIBLE, px, py, pw, ph, parent, 0, hinst, param);
    win_t *d = W(h);
    if (!d) return 0;
    d->dlgproc = proc;
    if (d->kind == K_GUEST) d->kind = K_DIALOG;          /* a template's own class: still a dialog to us */
    for (int i = 0; i < count; i++) {
        p = (p + 3) & ~3u;
        uint32_t cs, cex, cid;
        int x, y, cx, cy;
        if (ex) {
            cex = MEM32(p + 4), cs = MEM32(p + 8);
            x = (int16_t)MEM16(p + 12), y = (int16_t)MEM16(p + 14), cx = (int16_t)MEM16(p + 16), cy = (int16_t)MEM16(p + 18);
            cid = MEM32(p + 20), p += 24;
        } else {
            cs = MEM32(p), cex = MEM32(p + 4);
            x = (int16_t)MEM16(p + 8), y = (int16_t)MEM16(p + 10), cx = (int16_t)MEM16(p + 12), cy = (int16_t)MEM16(p + 14);
            cid = MEM16(p + 16), p += 18;
        }
        char ccls[64], ctext[256];
        uint32_t catom, tatom;
        p = sz_or_ord(p, ccls, sizeof ccls, &catom);
        p = sz_or_ord(p, ctext, sizeof ctext, &tatom);
        uint16_t extra = MEM16(p);
        uint32_t cdata = extra ? p + 2 : 0;
        p += 2 + extra;
        const char *ctl_cls = ccls[0] ? ccls : (const char *)(uintptr_t)catom;
        uint32_t c = hle_create_window(cex | 0x4u /* NOPARENTNOTIFY */, ctl_cls, tatom ? "" : ctext, cs | WS_CHILD,
                                       x * DLG_BX / 4, y * DLG_BY / 8, cx * DLG_BX / 4, cy * DLG_BY / 8, h, cid, hinst, cdata);
        win_t *cw = W(c);
        if (cw && tatom) cw->extra[0] = tatom;           /* an icon/bitmap resource id */
        if (!c) fprintf(stderr, "[user32] dialog control %u (%s) not created\n", cid, catom ? "atom" : ccls);
    }
    if (!(d = W(h))) return 0;
    /* the first tab stop gets the focus unless WM_INITDIALOG says otherwise */
    uint32_t first = 0;
    for (int i = 0; i < MAX_WIN && !first; i++)
        if (g_win[i].used && g_win[i].parent == h && (g_win[i].style & WS_TABSTOP) && !(g_win[i].style & WS_DISABLED)) first = g_win[i].hwnd;
    if (hle_send(h, WM_INITDIALOG, first, param) && first && W(first)) set_focus(first);
    if ((d = W(h)) && ((style & WS_VISIBLE) || modal)) {
        d->style |= WS_VISIBLE;
        invalidate(d, 1);
        hle_send(h, WM_SHOWWINDOW, 1, 0);
        if (!(style & WS_CHILD)) g_active = h;
    }
    return h;
}

static uint32_t dialog_template(uint32_t hinst, uint32_t name) {
    uint32_t r = hle_find_resource(hinst, name, 5);
    if (!r && hinst) r = hle_find_resource(0, name, 5);
    return r ? hle_resource_data(hinst, r, NULL) : 0;
}

/* The host may want to know which dialog resource a window came from. */
void (*hle_dialog_hook)(uint32_t hwnd, uint32_t resource_id);

static void u_CreateDialogParamA(void) {                 /* (hinst, name, parent, proc, param) */
    uint32_t t = dialog_template(A32(0), A32(1));
    if (!t) { fprintf(stderr, "[user32] CreateDialogParamA: no dialog %u\n", A32(1)); RET(0, 5); }
    uint32_t h = create_dialog(A32(0), t, A32(2), A32(3), A32(4), 0);
    if (h && hle_dialog_hook) hle_dialog_hook(h, A32(1));
    RET(h, 5);
}
static void u_CreateDialogIndirectParamA(void) {
    uint32_t id = hle_dialog_resource_id(A32(1));
    uint32_t h = create_dialog(A32(0), A32(1), A32(2), A32(3), A32(4), 0);
    if (h && id && hle_dialog_hook) hle_dialog_hook(h, id);
    RET(h, 5);
}

static int is_dialog_message(uint32_t dlg, msg_t *m);
static uint32_t run_modal(uint32_t h) {
    win_t *d = W(h);
    if (!d) return 0xFFFFFFFFu;
    uint32_t owner = d->parent ? d->parent : d->owner;
    win_t *o = W(owner);
    int was_enabled = o && !(o->style & WS_DISABLED);
    if (o) o->style |= WS_DISABLED;
    while ((d = W(h)) && !d->dlg_ended) {
        msg_t m;
        if (!wait_message(&m, 0, 0, 0)) break;
        if (m.message == WM_QUIT) { g_quit = 1, g_quit_code = m.wParam; break; }
        if (!is_dialog_message(h, &m)) {
            uint32_t mm[7] = { m.hwnd, m.message, m.wParam, m.lParam, m.time, (uint32_t)m.x, (uint32_t)m.y };
            win_t *t = W(m.hwnd);
            if (m.message == WM_KEYDOWN || m.message == WM_SYSKEYDOWN) {
                int c = vk_char(m.wParam, (g_keys[VK_SHIFT] & 0x80) != 0);
                if (c) q_push(m.hwnd, m.message == WM_KEYDOWN ? WM_CHAR : WM_SYSCHAR, (uint32_t)c, m.lParam);
            }
            if (t) call_proc(t->proc, mm[0], mm[1], mm[2], mm[3]);
            if (m.message == WM_PAINT && (t = W(m.hwnd)) && t->inval && t->kind != K_GUEST) t->inval = 0;
        }
    }
    uint32_t r = d ? d->dlg_result : 0xFFFFFFFFu;
    if ((o = W(owner)) && was_enabled) o->style &= ~WS_DISABLED;
    destroy(h);
    if (owner && W(owner)) g_active = owner;
    return r;
}
static void u_DialogBoxParamA(void) {                    /* (hinst, name, parent, proc, param) */
    uint32_t t = dialog_template(A32(0), A32(1));
    if (!t) { fprintf(stderr, "[user32] DialogBoxParamA: no dialog %u\n", A32(1)); RET(0xFFFFFFFFu, 5); }
    uint32_t h = create_dialog(A32(0), t, A32(2), A32(3), A32(4), 1);
    if (h && hle_dialog_hook) hle_dialog_hook(h, A32(1));
    RET(run_modal(h), 5);
}
static void u_DialogBoxIndirectParamA(void) {
    uint32_t id = hle_dialog_resource_id(A32(1));
    uint32_t h = create_dialog(A32(0), A32(1), A32(2), A32(3), A32(4), 1);
    if (h && id && hle_dialog_hook) hle_dialog_hook(h, id);
    RET(run_modal(h), 5);
}
static void u_EndDialog(void) {
    win_t *d = W(A32(0));
    if (!d) RET(0, 2);
    d->dlg_ended = 1, d->dlg_result = A32(1);
    d->style &= ~WS_VISIBLE;
    RET(1, 2);
}

/* the next/previous tab stop among a dialog's controls */
static uint32_t next_tab(uint32_t dlg, uint32_t from, int prev) {
    win_t *list[256];
    int n = 0, at = -1;
    for (int i = 0; i < MAX_WIN && n < 256; i++)
        if (g_win[i].used && g_win[i].parent == dlg) list[n++] = &g_win[i];
    for (int i = 1; i < n; i++)                          /* creation order */
        for (int j = i; j > 0 && list[j - 1]->seq > list[j]->seq; j--) { win_t *t = list[j]; list[j] = list[j - 1]; list[j - 1] = t; }
    for (int i = 0; i < n; i++) if (list[i]->hwnd == from) at = i;
    for (int k = 1; k <= n; k++) {
        win_t *c = list[((at < 0 ? (prev ? 0 : -1) : at) + (prev ? -k : k) + 2 * n) % n];
        if ((c->style & WS_TABSTOP) && visible(c) && !(c->style & WS_DISABLED)) return c->hwnd;
    }
    return from;
}
static int is_dialog_message(uint32_t dlg, msg_t *m) {
    if (!W(dlg) || !(m->hwnd == dlg || is_descendant(m->hwnd, dlg))) return 0;
    if (m->message == WM_KEYDOWN) {
        uint32_t code = g_focus ? hle_send(g_focus, WM_GETDLGCODE, m->wParam, 0) : 0;
        if (m->wParam == VK_TAB && !(code & 0x4u /* WANTALLKEYS */) && !(code & 0x2u)) {
            uint32_t n = next_tab(dlg, g_focus, (g_keys[VK_SHIFT] & 0x80) != 0);
            if (n) set_focus(n);
            return 1;
        }
        if (m->wParam == VK_RETURN && !(code & 0x4u)) {
            win_t *f = W(g_focus);
            uint32_t id = f && f->kind == K_BUTTON && (f->style & 0xF) <= 1 ? f->id : IDOK;
            hle_send(dlg, WM_COMMAND, id, f ? f->hwnd : 0);
            return 1;
        }
        if (m->wParam == VK_ESCAPE && !(code & 0x4u)) {
            hle_send(dlg, WM_COMMAND, IDCANCEL, 0);
            return 1;
        }
    }
    win_t *t = W(m->hwnd);
    if (m->message == WM_KEYDOWN || m->message == WM_SYSKEYDOWN) {
        int c = vk_char(m->wParam, (g_keys[VK_SHIFT] & 0x80) != 0);
        if (c) q_push(m->hwnd, m->message == WM_KEYDOWN ? WM_CHAR : WM_SYSCHAR, (uint32_t)c, m->lParam);
    }
    if (t) call_proc(t->proc, m->hwnd, m->message, m->wParam, m->lParam);
    if (m->message == WM_PAINT && (t = W(m->hwnd)) && t->inval && t->kind != K_GUEST) t->inval = 0;
    return 1;
}
static void u_IsDialogMessageA(void) {                   /* (dlg, msg) */
    uint32_t lp = A32(1);
    msg_t m = { MEM32(lp), MEM32(lp + 4), MEM32(lp + 8), MEM32(lp + 12), MEM32(lp + 16), (int)MEM32(lp + 20), (int)MEM32(lp + 24) };
    RET((uint32_t)is_dialog_message(A32(0), &m), 2);
}

static uint32_t dlg_item(uint32_t dlg, uint32_t id) {
    for (int i = 0; i < MAX_WIN; i++) if (g_win[i].used && g_win[i].parent == dlg && g_win[i].id == id) return g_win[i].hwnd;
    return 0;
}
static void u_GetDlgItem(void) { RET(dlg_item(A32(0), A32(1)), 2); }
static void u_GetDlgCtrlID(void) { win_t *x = W(A32(0)); RET(x ? x->id : 0u, 1); }
static void u_SendDlgItemMessageA(void) { RET(hle_send(dlg_item(A32(0), A32(1)), A32(2), A32(3), A32(4)), 5); }
static void u_SetDlgItemTextA(void) { uint32_t c = dlg_item(A32(0), A32(1)); RET(c ? hle_send(c, WM_SETTEXT, 0, A32(2)) : 0u, 3); }
static void u_GetDlgItemTextA(void) { uint32_t c = dlg_item(A32(0), A32(1)); if (!c && A32(3)) MEM8(A32(2)) = 0; RET(c ? hle_send(c, WM_GETTEXT, A32(3), A32(2)) : 0u, 4); }
static void u_CheckDlgButton(void) { uint32_t c = dlg_item(A32(0), A32(1)); if (c) hle_send(c, 0xF1u, A32(2), 0); RET(c != 0, 3); }
static void u_IsDlgButtonChecked(void) { uint32_t c = dlg_item(A32(0), A32(1)); RET(c ? hle_send(c, 0xF0u, 0, 0) : 0u, 2); }
static void u_GetNextDlgTabItem(void) { RET(next_tab(A32(0), A32(1), A32(2) != 0), 3); }

/* ---- classes and windows ---- */
static void u_RegisterClassA(void) {                     /* WNDCLASSA: style, proc, clsExtra, wndExtra, hinst, icon, cursor, brush, menu, name */
    builtin_classes();
    uint32_t wc = A32(0);
    const char *name = (const char *)(uintptr_t)MEM32(wc + 36);
    int i = add_class((uintptr_t)name < 0x10000u ? "?" : name, MEM32(wc + 4), MEM32(wc), MEM32(wc + 12), MEM32(wc + 16), K_GUEST);
    RET(i < 0 ? 0u : 0xC000u + (uint32_t)i, 1);
}
static void u_RegisterClassExA(void) {                   /* WNDCLASSEXA: size, style, proc, ..., name at +40 */
    builtin_classes();
    uint32_t wc = A32(0);
    const char *name = (const char *)(uintptr_t)MEM32(wc + 40);
    int i = add_class((uintptr_t)name < 0x10000u ? "?" : name, MEM32(wc + 8), MEM32(wc + 4), MEM32(wc + 16), MEM32(wc + 20), K_GUEST);
    RET(i < 0 ? 0u : 0xC000u + (uint32_t)i, 1);
}
static void u_GetClassInfoA(void) {                      /* (hinst, name, &WNDCLASSA) */
    builtin_classes();
    int i = find_class(ASTR(1));
    if (i < 0) RET(0, 3);
    uint32_t wc = A32(2);
    memset((void *)(uintptr_t)wc, 0, 40);
    MEM32(wc) = g_cls[i].style, MEM32(wc + 4) = g_cls[i].proc, MEM32(wc + 12) = g_cls[i].extra;
    MEM32(wc + 16) = g_cls[i].hinst, MEM32(wc + 36) = A32(1);
    RET(1, 3);
}
static void u_CreateWindowExA(void) {
    builtin_classes();
    RET(hle_create_window(A32(0), ASTR(1), ASTR(2), A32(3), (int)A32(4), (int)A32(5), (int)A32(6), (int)A32(7),
                          A32(8), A32(9), A32(10), A32(11)), 12);
}
static void u_DestroyWindow(void) { int ok = W(A32(0)) != NULL; destroy(A32(0)); RET((uint32_t)ok, 1); }
static void u_IsWindow(void) { RET(W(A32(0)) != NULL, 1); }
static void u_IsWindowVisible(void) { win_t *x = W(A32(0)); RET(x && visible(x), 1); }
static void u_IsWindowEnabled(void) { win_t *x = W(A32(0)); RET(x && !(x->style & WS_DISABLED), 1); }
static void u_EnableWindow(void) {
    win_t *x = W(A32(0));
    if (!x) RET(0, 2);
    int was_disabled = (x->style & WS_DISABLED) != 0;
    if (A32(1)) x->style &= ~WS_DISABLED; else x->style |= WS_DISABLED;
    if (was_disabled == !A32(1)) RET((uint32_t)was_disabled, 2);
    hle_send(x->hwnd, WM_ENABLE, A32(1) != 0, 0);
    if (!A32(1) && g_focus == A32(0)) g_focus = 0;
    RET((uint32_t)was_disabled, 2);
}
static void u_ShowWindow(void) {
    win_t *x = W(A32(0));
    if (!x) RET(0, 2);
    int was = (x->style & WS_VISIBLE) != 0, show = A32(1) != 0;   /* SW_HIDE is 0 */
    if (show) x->style |= WS_VISIBLE; else x->style &= ~WS_VISIBLE;
    if (show != was) {
        hle_send(x->hwnd, WM_SHOWWINDOW, (uint32_t)show, 0);
        if ((x = W(A32(0))) && show) invalidate(x, 1);
    }
    if (x && show && !x->parent && A32(1) != 4 && A32(1) != 8) {   /* not SHOWNOACTIVATE / SHOWNA */
        uint32_t old = g_active;
        g_active = x->hwnd;
        if (old != x->hwnd) {
            hle_send(x->hwnd, WM_ACTIVATEAPP, 1, 0);
            hle_send(x->hwnd, WM_NCACTIVATE, 1, 0);
            hle_send(x->hwnd, WM_ACTIVATE, 1, old);
            if (!g_focus || !is_descendant(g_focus, x->hwnd)) set_focus(x->hwnd);
        }
    }
    RET((uint32_t)was, 2);
}
static void u_UpdateWindow(void) {
    win_t *x = W(A32(0));
    if (x && x->inval && visible(x)) hle_send(x->hwnd, WM_PAINT, 0, 0);
    if ((x = W(A32(0))) && x->kind != K_GUEST) x->inval = 0;
    RET(x != NULL, 1);
}
static void u_CloseWindow(void) { RET(W(A32(0)) != NULL, 1); }   /* minimize: nothing to minimize to */

static void u_GetParent(void) { win_t *x = W(A32(0)); RET(x ? (x->parent ? x->parent : x->owner) : 0u, 1); }
static void u_GetWindow(void) {                          /* (h, cmd) */
    win_t *x = W(A32(0));
    uint32_t cmd = A32(1), best = 0;
    int bseq = 0;
    if (!x) RET(0, 2);
    switch (cmd) {
    case 5:                                              /* GW_CHILD: the first created (top) */
        for (int i = 0; i < MAX_WIN; i++)
            if (g_win[i].used && g_win[i].parent == x->hwnd && (!best || g_win[i].seq < bseq)) best = g_win[i].hwnd, bseq = g_win[i].seq;
        RET(best, 2);
    case 2: case 3:                                      /* GW_HWNDNEXT / PREV among siblings */
        for (int i = 0; i < MAX_WIN; i++) {
            win_t *s = &g_win[i];
            if (!s->used || s->parent != x->parent || s == x || (!x->parent && s->parent)) continue;
            if (cmd == 2 ? s->seq > x->seq && (!best || s->seq < bseq) : s->seq < x->seq && (!best || s->seq > bseq))
                best = s->hwnd, bseq = s->seq;
        }
        RET(best, 2);
    case 4: RET(x->owner, 2);                            /* GW_OWNER */
    default: RET(0, 2);
    }
}
static void u_GetTopWindow(void) {
    uint32_t parent = A32(0), best = 0;
    int bseq = 0;
    for (int i = 0; i < MAX_WIN; i++)
        if (g_win[i].used && g_win[i].parent == parent && (!best || g_win[i].seq < bseq)) best = g_win[i].hwnd, bseq = g_win[i].seq;
    RET(best, 1);
}
static void u_EnumChildWindows(void) {                   /* (parent, proc, lParam): all descendants */
    uint32_t parent = A32(0), proc = A32(1), lp = A32(2);
    uint32_t list[MAX_WIN];
    int n = 0;
    for (int i = 0; i < MAX_WIN; i++) if (g_win[i].used && g_win[i].parent && is_descendant(g_win[i].parent, parent)) list[n++] = g_win[i].hwnd;
    for (int i = 0; i < n; i++) {
        if (!W(list[i])) continue;
        uint32_t a[2] = { list[i], lp };
        if (!hle_call_guest(proc, 2, a)) break;
    }
    RET(1, 3);
}
static void u_FindWindowA(void) {                        /* (class, title) */
    int c = find_class(ASTR(0));
    for (int i = 0; i < MAX_WIN; i++) {
        win_t *x = &g_win[i];
        if (!x->used || x->parent) continue;
        if (A32(0) && x->cls != c) continue;
        if (A32(1) && strcmp(x->text, ASTR(1))) continue;
        RET(x->hwnd, 2);
    }
    RET(0, 2);
}
static void u_GetClassNameA(void) {
    win_t *x = W(A32(0));
    if (!x || !A32(2)) RET(0, 3);
    snprintf(ASTR(1), A32(2), "%s", g_cls[x->cls].name);
    RET((uint32_t)strlen(ASTR(1)), 3);
}
static void u_SetWindowTextA(void) { RET(W(A32(0)) ? hle_send(A32(0), WM_SETTEXT, 0, A32(1)) : 0u, 2); }
static void u_GetWindowTextA(void) {
    if (!W(A32(0))) { if (A32(2)) MEM8(A32(1)) = 0; RET(0, 3); }
    RET(hle_send(A32(0), WM_GETTEXT, A32(2), A32(1)), 3);
}
static void u_GetWindowTextLengthA(void) { RET(W(A32(0)) ? hle_send(A32(0), WM_GETTEXTLENGTH, 0, 0) : 0u, 1); }

static uint32_t get_long(win_t *x, int i) {
    if (x->kind == K_DIALOG && i >= 0 && i <= 8) return i == DWL_MSGRESULT ? x->msgresult : i == DWL_DLGPROC ? x->dlgproc : x->dlguser;
    switch (i) {
    case GWL_WNDPROC: return x->proc;
    case GWL_HINSTANCE: return x->hinst;
    case GWL_HWNDPARENT: return x->parent ? x->parent : x->owner;
    case GWL_ID: return x->id;
    case GWL_STYLE: return x->style;
    case GWL_EXSTYLE: return x->exstyle;
    case GWL_USERDATA: return x->user;
    default: return i >= 0 && i / 4 < 32 ? x->extra[i / 4] : 0;
    }
}
static void u_GetWindowLongA(void) { win_t *x = W(A32(0)); RET(x ? get_long(x, (int)A32(1)) : 0u, 2); }
static void u_SetWindowLongA(void) {
    win_t *x = W(A32(0));
    int i = (int)A32(1);
    uint32_t v = A32(2);
    if (!x) RET(0, 3);
    uint32_t old = get_long(x, i);
    if (x->kind == K_DIALOG && i >= 0 && i <= 8) {
        if (i == DWL_MSGRESULT) x->msgresult = v; else if (i == DWL_DLGPROC) x->dlgproc = v; else x->dlguser = v;
        RET(old, 3);
    }
    switch (i) {
    case GWL_WNDPROC: x->proc = v; break;
    case GWL_HINSTANCE: x->hinst = v; break;
    case GWL_HWNDPARENT: if (x->parent) x->parent = v; else x->owner = v; break;
    case GWL_ID: x->id = v; break;
    case GWL_STYLE: x->style = v; break;
    case GWL_EXSTYLE: x->exstyle = v; break;
    case GWL_USERDATA: x->user = v; break;
    default: if (i >= 0 && i / 4 < 32) x->extra[i / 4] = v; break;
    }
    RET(old, 3);
}
static void u_GetWindowContextHelpId(void) { RET(0, 1); }
static void u_GetMenu(void) { win_t *x = W(A32(0)); RET(x ? x->menu : 0u, 1); }

/* geometry */
static void u_GetClientRect(void) { win_t *x = W(A32(0)); if (!x) RET(0, 2); put_rect(A32(1), 0, 0, x->w, x->h); RET(1, 2); }
static void u_GetWindowRect(void) {
    win_t *x = W(A32(0));
    if (!x) RET(0, 2);
    int ox, oy;
    origin(x, &ox, &oy);
    put_rect(A32(1), ox, oy, ox + x->w, oy + x->h);
    RET(1, 2);
}
static void u_ClientToScreen(void) {
    win_t *x = W(A32(0));
    int ox = 0, oy = 0;
    if (x) origin(x, &ox, &oy);
    if (A32(1)) MEM32(A32(1)) += (uint32_t)ox, MEM32(A32(1) + 4) += (uint32_t)oy;
    RET(x != NULL, 2);
}
static void u_ScreenToClient(void) {
    win_t *x = W(A32(0));
    int ox = 0, oy = 0;
    if (x) origin(x, &ox, &oy);
    if (A32(1)) MEM32(A32(1)) -= (uint32_t)ox, MEM32(A32(1) + 4) -= (uint32_t)oy;
    RET(x != NULL, 2);
}
static void u_MapWindowPoints(void) {                    /* (from, to, pts, n) */
    int fx = 0, fy = 0, tx = 0, ty = 0;
    if (W(A32(0))) origin(W(A32(0)), &fx, &fy);
    if (W(A32(1))) origin(W(A32(1)), &tx, &ty);
    for (uint32_t i = 0; i < A32(3); i++) MEM32(A32(2) + 8 * i) += (uint32_t)(fx - tx), MEM32(A32(2) + 8 * i + 4) += (uint32_t)(fy - ty);
    RET((uint32_t)(((fy - ty) & 0xFFFF) << 16 | ((fx - tx) & 0xFFFF)), 4);
}
static void move(win_t *x, int px, int py, int pw, int ph, int do_move, int do_size) {
    uint32_t h = x->hwnd;
    if (do_size && x->kind == K_COMBOBOX && (x->style & 3u) != 1u) x->drop_h = ph, ph = x->h;   /* sets the dropped height */
    if (do_move) x->x = px, x->y = py;
    if (do_size) x->w = pw, x->h = ph;
    invalidate(x, 1);
    if (do_size) hle_send(h, WM_SIZE, 0, (uint32_t)(x->h & 0xFFFF) << 16 | (uint32_t)(x->w & 0xFFFF));
    if ((x = W(h)) && do_move) hle_send(h, WM_MOVE, 0, (uint32_t)(x->y & 0xFFFF) << 16 | (uint32_t)(x->x & 0xFFFF));
}
static void u_MoveWindow(void) { win_t *x = W(A32(0)); if (x) move(x, (int)A32(1), (int)A32(2), (int)A32(3), (int)A32(4), 1, 1); RET(x != NULL, 6); }
static void u_SetWindowPos(void) {                       /* (h, after, x, y, cx, cy, flags) */
    win_t *x = W(A32(0));
    uint32_t fl = A32(6);
    if (!x) RET(0, 7);
    if (!(fl & 3u)) move(x, (int)A32(2), (int)A32(3), (int)A32(4), (int)A32(5), !(fl & 2u), !(fl & 1u));
    else if (!(fl & 2u)) move(x, (int)A32(2), (int)A32(3), 0, 0, 1, 0);
    else if (!(fl & 1u)) move(x, 0, 0, (int)A32(4), (int)A32(5), 0, 1);
    if ((x = W(A32(0)))) {
        if (fl & 0x40u) { x->style |= WS_VISIBLE; invalidate(x, 1); }   /* SWP_SHOWWINDOW */
        if (fl & 0x80u) x->style &= ~WS_VISIBLE;                        /* SWP_HIDEWINDOW */
    }
    RET(1, 7);
}
static void u_BringWindowToTop(void) { RET(W(A32(0)) != NULL, 1); }
static void u_WindowFromPoint(void) { RET(hle_window_at((int)A32(0), (int)A32(1), NULL, NULL), 2); }
static void u_ChildWindowFromPoint(void) {               /* (parent, x, y) in the parent's client coordinates */
    win_t *p = W(A32(0));
    if (!p) RET(0, 3);
    int px = (int)A32(1), py = (int)A32(2);
    if (px < 0 || py < 0 || px >= p->w || py >= p->h) RET(0, 3);
    uint32_t best = p->hwnd;
    int bseq = 0x7FFFFFFF;
    for (int i = 0; i < MAX_WIN; i++) {
        win_t *c = &g_win[i];
        if (c->used && c->parent == p->hwnd && px >= c->x && py >= c->y && px < c->x + c->w && py < c->y + c->h && c->seq < bseq)
            best = c->hwnd, bseq = c->seq;
    }
    RET(best, 3);
}

/* painting */
static void u_InvalidateRect(void) {                     /* (h, rect, erase) */
    win_t *x = W(A32(0));
    if (!A32(0)) { for (int i = 0; i < MAX_WIN; i++) if (g_win[i].used && !g_win[i].parent) invalidate(&g_win[i], 1); RET(1, 3); }
    if (!x) RET(0, 3);
    uint32_t r = A32(1);
    if (!r) { x->inval = 1, x->ix0 = 0, x->iy0 = 0, x->ix1 = x->w, x->iy1 = x->h; }
    else {
        int l = (int)MEM32(r), t = (int)MEM32(r + 4), rr = (int)MEM32(r + 8), b = (int)MEM32(r + 12);
        if (!x->inval) x->ix0 = l, x->iy0 = t, x->ix1 = rr, x->iy1 = b;
        else { if (l < x->ix0) x->ix0 = l; if (t < x->iy0) x->iy0 = t; if (rr > x->ix1) x->ix1 = rr; if (b > x->iy1) x->iy1 = b; }
        x->inval = 1;
    }
    RET(1, 3);
}
static void u_ValidateRect(void) { win_t *x = W(A32(0)); if (x) x->inval = 0; RET(x != NULL, 2); }
static void u_GetUpdateRect(void) {                      /* (h, rect, erase) */
    win_t *x = W(A32(0));
    if (!x || !x->inval) { put_rect(A32(1), 0, 0, 0, 0); RET(0, 3); }
    put_rect(A32(1), x->ix0, x->iy0, x->ix1, x->iy1);
    RET(1, 3);
}
static void u_RedrawWindow(void) {                       /* (h, rect, rgn, flags) */
    win_t *x = W(A32(0));
    uint32_t fl = A32(3);
    if (!x) RET(0, 4);
    if (fl & 0x1u) invalidate(x, (fl & 0x80u) != 0);    /* RDW_INVALIDATE [| RDW_ALLCHILDREN] */
    if (fl & 0x8u) x->inval = 0;                         /* RDW_VALIDATE */
    if (fl & 0x100u) {                                   /* RDW_UPDATENOW */
        uint32_t list[MAX_WIN];
        int n = 0;
        for (int i = 0; i < MAX_WIN; i++)
            if (g_win[i].used && g_win[i].inval && visible(&g_win[i]) && (g_win[i].hwnd == A32(0) || is_descendant(g_win[i].hwnd, A32(0))))
                list[n++] = g_win[i].hwnd;
        for (int i = 0; i < n; i++) {
            hle_send(list[i], WM_PAINT, 0, 0);
            win_t *y = W(list[i]);
            if (y && y->kind != K_GUEST) y->inval = 0;
        }
    }
    RET(1, 4);
}
static void u_BeginPaint(void) {                         /* (h, &PAINTSTRUCT) */
    win_t *x = W(A32(0));
    uint32_t ps = A32(1);
    if (ps) {
        memset((void *)(uintptr_t)ps, 0, 64);
        MEM32(ps) = 0x0DC00001u;
        if (x) put_rect(ps + 8, x->ix0, x->iy0, x->ix1, x->iy1);
    }
    if (x) x->inval = 0;
    RET(0x0DC00001u, 2);
}
static void u_EndPaint(void) { RET(1, 2); }

/* focus, capture, activation */
static void u_SetFocus(void) { uint32_t old = g_focus; if (!A32(0) || W(A32(0))) set_focus(A32(0)); RET(old, 1); }
static void u_GetFocus(void) { RET(g_focus, 0); }
static void u_SetCapture(void) { uint32_t old = g_capture; g_capture = A32(0); RET(old, 1); }
static void u_ReleaseCapture(void) {
    uint32_t old = g_capture;
    g_capture = 0;
    if (old && W(old)) hle_send(old, WM_CAPTURECHANGED, 0, 0);
    RET(1, 0);
}
static void u_GetCapture(void) { RET(g_capture, 0); }
static void u_GetActiveWindow(void) { RET(g_active, 0); }
static void u_GetForegroundWindow(void) { RET(g_active, 0); }
static void u_SetActiveWindow(void) { uint32_t old = g_active; if (W(A32(0))) g_active = A32(0); RET(old, 1); }
static void u_SetForegroundWindow(void) { if (W(A32(0))) g_active = A32(0); RET(1, 1); }
static void u_GetDesktopWindow(void) { RET(0x0000FFF0u, 0); }

/* timers */
static void u_SetTimer(void) {                           /* (h, id, elapse, proc) */
    uint32_t h = A32(0), id = A32(1);
    for (int i = 0; i < MAX_TIMERS; i++)
        if (g_timer[i].used && g_timer[i].hwnd == h && h && g_timer[i].id == id) {
            g_timer[i].elapse = A32(2) ? A32(2) : 1, g_timer[i].due = hle_ticks_ms() + g_timer[i].elapse, g_timer[i].proc = A32(3);
            RET(id, 4);
        }
    for (int i = 0; i < MAX_TIMERS; i++)
        if (!g_timer[i].used) {
            g_timer[i].used = 1, g_timer[i].hwnd = h, g_timer[i].id = h ? id : 0x100u + (uint32_t)i;
            g_timer[i].elapse = A32(2) ? A32(2) : 1, g_timer[i].due = hle_ticks_ms() + g_timer[i].elapse, g_timer[i].proc = A32(3);
            RET(g_timer[i].id, 4);
        }
    RET(0, 4);
}
static void u_KillTimer(void) {
    for (int i = 0; i < MAX_TIMERS; i++)
        if (g_timer[i].used && g_timer[i].hwnd == A32(0) && g_timer[i].id == A32(1)) { g_timer[i].used = 0; RET(1, 2); }
    RET(0, 2);
}

/* the keyboard and the mouse */
volatile int hle_lbutton_reads;                 /* how often the game has looked at the left button */
static void u_GetKeyState(void) {
    uint8_t k = g_keys[A32(0) & 0xFF];
    if ((A32(0) & 0xFF) == 1) hle_lbutton_reads++;
    RET((k & 0x80 ? 0xFF80u : 0u) | (k & 1u), 1);
}
static void u_GetAsyncKeyState(void) {
    if ((A32(0) & 0xFF) == 1) hle_lbutton_reads++;
    RET(g_keys[A32(0) & 0xFF] & 0x80 ? 0x8000u : 0u, 1);
}
static void u_GetKeyboardState(void) { memcpy(APTR(0), g_keys, 256); RET(1, 1); }
static void u_GetCursorPos(void) { if (A32(0)) MEM32(A32(0)) = (uint32_t)g_cursor_x, MEM32(A32(0) + 4) = (uint32_t)g_cursor_y; RET(1, 1); }
void (*hle_cursor_hook)(int x, int y);                   /* a host that moves its own pointer */
static void u_SetCursorPos(void) {
    g_cursor_x = (int)A32(0), g_cursor_y = (int)A32(1);
    if (hle_cursor_hook) hle_cursor_hook(g_cursor_x, g_cursor_y);
    RET(1, 2);
}
static void u_ShowCursor(void) { RET((uint32_t)(A32(0) ? ++g_cursor_shown : --g_cursor_shown), 1); }
static void u_SetCursor(void) { RET(0, 1); }
static void u_ClipCursor(void) { RET(1, 1); }
static void u_MapVirtualKeyA(void) {                     /* (code, type) */
    static const uint8_t scan_of[256] = {
        [0x08] = 0x0E, [0x09] = 0x0F, [0x0D] = 0x1C, [0x10] = 0x2A, [0x11] = 0x1D, [0x12] = 0x38, [0x1B] = 0x01, [0x20] = 0x39,
        ['1'] = 2, ['2'] = 3, ['3'] = 4, ['4'] = 5, ['5'] = 6, ['6'] = 7, ['7'] = 8, ['8'] = 9, ['9'] = 10, ['0'] = 11,
        ['Q'] = 0x10, ['W'] = 0x11, ['E'] = 0x12, ['R'] = 0x13, ['T'] = 0x14, ['Y'] = 0x15, ['U'] = 0x16, ['I'] = 0x17, ['O'] = 0x18, ['P'] = 0x19,
        ['A'] = 0x1E, ['S'] = 0x1F, ['D'] = 0x20, ['F'] = 0x21, ['G'] = 0x22, ['H'] = 0x23, ['J'] = 0x24, ['K'] = 0x25, ['L'] = 0x26,
        ['Z'] = 0x2C, ['X'] = 0x2D, ['C'] = 0x2E, ['V'] = 0x2F, ['B'] = 0x30, ['N'] = 0x31, ['M'] = 0x32,
        [0x70] = 0x3B, [0x71] = 0x3C, [0x72] = 0x3D, [0x73] = 0x3E, [0x74] = 0x3F, [0x75] = 0x40, [0x76] = 0x41, [0x77] = 0x42,
        [0x78] = 0x43, [0x79] = 0x44, [0x7A] = 0x57, [0x7B] = 0x58, [0x25] = 0x4B, [0x26] = 0x48, [0x27] = 0x4D, [0x28] = 0x50,
        [0x2D] = 0x52, [0x2E] = 0x53, [0x24] = 0x47, [0x23] = 0x4F, [0x21] = 0x49, [0x22] = 0x51 };
    uint32_t code = A32(0), type = A32(1);
    if (type == 0) RET(scan_of[code & 0xFF], 2);         /* VK -> scan */
    if (type == 1) { for (int i = 0; i < 256; i++) if (scan_of[i] == code && code) RET((uint32_t)i, 2); RET(0, 2); }   /* scan -> VK */
    if (type == 2) RET((uint32_t)vk_char(code, 0) & 0xFFu, 2);   /* VK -> char */
    RET(0, 2);
}
static void u_GetKeyNameTextA(void) {                    /* (lParam, buf, n) */
    static const char *const names[] = { [0x01] = "Esc", [0x0E] = "Backspace", [0x0F] = "Tab", [0x1C] = "Enter", [0x1D] = "Ctrl",
        [0x2A] = "Shift", [0x36] = "Right Shift", [0x38] = "Alt", [0x39] = "Space", [0x3A] = "Caps Lock",
        [0x3B] = "F1", [0x3C] = "F2", [0x3D] = "F3", [0x3E] = "F4", [0x3F] = "F5", [0x40] = "F6", [0x41] = "F7", [0x42] = "F8",
        [0x43] = "F9", [0x44] = "F10", [0x57] = "F11", [0x58] = "F12", [0x47] = "Home", [0x48] = "Up", [0x49] = "Page Up",
        [0x4B] = "Left", [0x4D] = "Right", [0x4F] = "End", [0x50] = "Down", [0x51] = "Page Down", [0x52] = "Insert", [0x53] = "Delete" };
    uint32_t scan = (A32(0) >> 16) & 0x7F;
    char tmp[32] = "";
    if (scan < sizeof names / sizeof *names && names[scan]) snprintf(tmp, sizeof tmp, "%s", names[scan]);
    else {
        static const char row[] = "\0\0" "1234567890-=\0\0" "QWERTYUIOP[]\0\0" "ASDFGHJKL;'`\0\\" "ZXCVBNM,./";
        if (scan < sizeof row && row[scan]) tmp[0] = row[scan], tmp[1] = 0;
    }
    if (!A32(2)) RET(0, 3);
    snprintf(ASTR(1), A32(2), "%s", tmp);
    RET((uint32_t)strlen(ASTR(1)), 3);
}
static void u_ToAscii(void) {                            /* (vk, scan, keystate, &out, flags) */
    const uint8_t *ks = (const uint8_t *)APTR(2);
    int c = vk_char(A32(0), ks && (ks[VK_SHIFT] & 0x80));
    if (!c || !A32(3)) RET(0, 5);
    MEM16(A32(3)) = (uint16_t)c;
    RET(1, 5);
}
static void u_CharToOemBuffA(void) { if (A32(0) != A32(1)) memmove(APTR(1), APTR(0), A32(2)); RET(1, 3); }
static void u_OemToCharBuffA(void) { if (A32(0) != A32(1)) memmove(APTR(1), APTR(0), A32(2)); RET(1, 3); }
static void u_CharUpperA(void) { uint32_t s = A32(0); if (s < 0x10000u) RET(s >= 'a' && s <= 'z' ? s - 32 : s, 1); for (char *p = ASTR(0); *p; p++) if (*p >= 'a' && *p <= 'z') *p -= 32; RET(s, 1); }
static void u_CharLowerA(void) { uint32_t s = A32(0); if (s < 0x10000u) RET(s >= 'A' && s <= 'Z' ? s + 32 : s, 1); for (char *p = ASTR(0); *p; p++) if (*p >= 'A' && *p <= 'Z') *p += 32; RET(s, 1); }
static void u_RegisterHotKey(void) { RET(1, 4); }
static void u_UnregisterHotKey(void) { RET(1, 2); }
static void u_TranslateAcceleratorA(void) { RET(0, 3); }
static void u_WinHelpA(void) { RET(0, 4); }
static void u_WaitForInputIdle(void) { RET(0, 2); }
static void u_MessageBeep(void) { RET(1, 1); }

/* GetSystemMetrics: the screen is the game's display mode. */
static void u_GetSystemMetrics(void) {
    switch (A32(0)) {
    case 0: case 16: case 78: RET((uint32_t)g_screen_w, 1);   /* SM_CXSCREEN, CXFULLSCREEN, CXVIRTUALSCREEN */
    case 1: case 17: case 79: RET((uint32_t)g_screen_h, 1);
    case 2: case 3: RET(16, 1);                          /* scroll bar widths */
    case 4: RET(19, 1);                                  /* SM_CYCAPTION */
    case 5: case 6: RET(1, 1);                           /* borders */
    case 7: case 8: RET(3, 1);                           /* dialog frames */
    case 11: case 12: case 13: case 14: RET(32, 1);      /* icons, cursors */
    case 19: RET(1, 1);                                  /* SM_MOUSEPRESENT */
    case 23: RET(0, 1);                                  /* SM_SWAPBUTTON */
    case 32: case 33: RET(4, 1);                         /* frames */
    case 36: case 37: RET(4, 1);                         /* SM_CXDOUBLECLK */
    case 43: RET(3, 1);                                  /* SM_CMOUSEBUTTONS */
    case 75: RET(1, 1);                                  /* SM_MOUSEWHEELPRESENT */
    case 80: RET(1, 1);                                  /* SM_CMONITORS */
    default: RET(0, 1);
    }
}

/* resources the presenter does not draw: handles that are not NULL */
static void u_LoadIconA(void)        { RET(0x1C000001u, 2); }
static void u_LoadCursorA(void)      { RET(0x1C000002u, 2); }
static void u_LoadImageA(void)       { RET(0x1C000003u, 6); }
static void u_LoadBitmapA(void)      { RET(0x1C000004u, 2); }
static void u_LoadAcceleratorsA(void){ RET(0x1C000005u, 2); }  /* nonzero: games treat NULL as fatal */
static void u_LoadMenuA(void)        { RET(0x1C000006u, 2); }

/* RECTs */
static void u_CopyRect(void)     { uint32_t d=A32(0), s=A32(1); if(d&&s){MEM32(d)=MEM32(s);MEM32(d+4)=MEM32(s+4);MEM32(d+8)=MEM32(s+8);MEM32(d+12)=MEM32(s+12);} RET(1,2); }
static void u_SetRectEmpty(void) { put_rect(A32(0), 0, 0, 0, 0); RET(1, 1); }
static void u_SetRect(void)      { put_rect(A32(0), (int)A32(1), (int)A32(2), (int)A32(3), (int)A32(4)); RET(1, 5); }
static void u_OffsetRect(void)   { uint32_t r=A32(0); int dx=(int)A32(1),dy=(int)A32(2); if(r){MEM32(r)+=dx;MEM32(r+4)+=dy;MEM32(r+8)+=dx;MEM32(r+12)+=dy;} RET(1,3); }
static void u_InflateRect(void)  { uint32_t r=A32(0); int dx=(int)A32(1),dy=(int)A32(2); if(r){MEM32(r)-=dx;MEM32(r+4)-=dy;MEM32(r+8)+=dx;MEM32(r+12)+=dy;} RET(1,3); }
static void u_PtInRect(void) {                           /* (rect, POINT by value) */
    uint32_t r = A32(0);
    int x = (int)A32(1), y = (int)A32(2);
    RET(r && x >= (int)MEM32(r) && x < (int)MEM32(r + 8) && y >= (int)MEM32(r + 4) && y < (int)MEM32(r + 12), 3);
}
static void u_IsRectEmpty(void) { uint32_t r = A32(0); RET(!r || (int)MEM32(r + 8) <= (int)MEM32(r) || (int)MEM32(r + 12) <= (int)MEM32(r + 4), 1); }
static void u_IntersectRect(void) {                      /* (dst, a, b) */
    uint32_t d = A32(0), a = A32(1), b = A32(2);
    int l = (int)MEM32(a) > (int)MEM32(b) ? (int)MEM32(a) : (int)MEM32(b);
    int t = (int)MEM32(a + 4) > (int)MEM32(b + 4) ? (int)MEM32(a + 4) : (int)MEM32(b + 4);
    int r = (int)MEM32(a + 8) < (int)MEM32(b + 8) ? (int)MEM32(a + 8) : (int)MEM32(b + 8);
    int bt = (int)MEM32(a + 12) < (int)MEM32(b + 12) ? (int)MEM32(a + 12) : (int)MEM32(b + 12);
    if (l >= r || t >= bt) { put_rect(d, 0, 0, 0, 0); RET(0, 3); }
    put_rect(d, l, t, r, bt);
    RET(1, 3);
}
static void u_UnionRect(void) {
    uint32_t d = A32(0), a = A32(1), b = A32(2);
    int l = (int)MEM32(a) < (int)MEM32(b) ? (int)MEM32(a) : (int)MEM32(b);
    int t = (int)MEM32(a + 4) < (int)MEM32(b + 4) ? (int)MEM32(a + 4) : (int)MEM32(b + 4);
    int r = (int)MEM32(a + 8) > (int)MEM32(b + 8) ? (int)MEM32(a + 8) : (int)MEM32(b + 8);
    int bt = (int)MEM32(a + 12) > (int)MEM32(b + 12) ? (int)MEM32(a + 12) : (int)MEM32(b + 12);
    put_rect(d, l, t, r, bt);
    RET(1, 3);
}
static void u_AdjustWindowRect(void)   { RET(1, 3); }    /* no non-client area here */
static void u_AdjustWindowRectEx(void) { RET(1, 4); }

/* text: one fixed-pitch measure for everything (the game draws its own) */
static void u_DrawTextA(void) {                          /* (hdc, text, n, rect, format) */
    const char *s = ASTR(1);
    int n = (int)A32(2);
    uint32_t r = A32(3);
    if (n < 0) n = s ? (int)strlen(s) : 0;
    if (r && (A32(4) & 0x400u)) MEM32(r + 8) = MEM32(r) + (uint32_t)(n * 6), MEM32(r + 12) = MEM32(r + 4) + 13;   /* DT_CALCRECT */
    RET(13, 5);
}

/* wsprintfA is cdecl: the caller pops, so only the return address goes. */
static void u_wsprintfA(void) {
    char *out = ASTR(0);
    const char *fmt = ASTR(1);
    va_list ap;
    char *first = (char *)(uintptr_t)(g_esp + 12);
    memcpy(&ap, &first, sizeof ap);
    int n = vsnprintf(out, 1024, fmt, ap);
    RET((uint32_t)(n < 0 ? 0 : n > 1023 ? 1023 : n), 0);
}
static void u_wvsprintfA(void) {
    char *out = ASTR(0);
    va_list ap;
    char *first = (char *)(uintptr_t)A32(2);
    memcpy(&ap, &first, sizeof ap);
    int n = vsnprintf(out, 1024, ASTR(1), ap);
    RET((uint32_t)(n < 0 ? 0 : n > 1023 ? 1023 : n), 3);
}

/* Message boxes print, and answer the first button. */
static void u_MessageBoxA(void) {
    fprintf(stderr, "[MessageBox] %s: %s\n", ASTR(2) ? ASTR(2) : "", ASTR(1) ? ASTR(1) : "");
    uint32_t b = A32(3) & 0xF;
    RET(b == 4 || b == 3 ? 6u : b == 5 ? 4u : 1u, 4);    /* IDYES, IDRETRY, IDOK */
}
static void u_MessageBoxIndirectA(void) {
    uint32_t p = A32(0);
    fprintf(stderr, "[MessageBox] %s: %s\n", MEM32(p + 12) ? (const char *)(uintptr_t)MEM32(p + 12) : "",
            MEM32(p + 8) ? (const char *)(uintptr_t)MEM32(p + 8) : "");
    RET(1, 1);
}

/* What a host (a test driver) may ask about a window. */
int hle_is_window(uint32_t h) { return W(h) != NULL; }
int hle_window_screen_rect(uint32_t h, int *l, int *t, int *r, int *b) {
    win_t *x = W(h);
    if (!x) return 0;
    int ox, oy;
    origin(x, &ox, &oy);
    *l = ox, *t = oy, *r = ox + x->w, *b = oy + x->h;
    return 1;
}
const char *hle_window_class(uint32_t h) { win_t *x = W(h); return x ? g_cls[x->cls].name : ""; }
uint32_t hle_window_parent(uint32_t h) { win_t *x = W(h); return x ? (x->parent ? x->parent : x->owner) : 0; }
uint32_t hle_dialog_item(uint32_t dlg, uint32_t id) { return dlg_item(dlg, id); }
uint32_t hle_window_style(uint32_t h) { win_t *x = W(h); return x ? x->style : 0; }

uint32_t hle_first_hwnd(void) {
    for (int i = 0; i < MAX_WIN; i++) if (g_win[i].used && !g_win[i].parent) return g_win[i].hwnd;
    return 0;
}

const win32hle_shim win32hle_user32[] = {
    { "CopyRect", u_CopyRect }, { "SetRectEmpty", u_SetRectEmpty }, { "SetRect", u_SetRect },
    { "OffsetRect", u_OffsetRect }, { "InflateRect", u_InflateRect }, { "PtInRect", u_PtInRect },
    { "IsRectEmpty", u_IsRectEmpty }, { "IntersectRect", u_IntersectRect }, { "UnionRect", u_UnionRect },
    { "AdjustWindowRect", u_AdjustWindowRect }, { "AdjustWindowRectEx", u_AdjustWindowRectEx },
    { "FindWindowA", u_FindWindowA }, { "LoadIconA", u_LoadIconA }, { "LoadCursorA", u_LoadCursorA },
    { "LoadImageA", u_LoadImageA }, { "LoadBitmapA", u_LoadBitmapA }, { "LoadAcceleratorsA", u_LoadAcceleratorsA },
    { "LoadMenuA", u_LoadMenuA }, { "TranslateAcceleratorA", u_TranslateAcceleratorA },
    { "SetCursor", u_SetCursor }, { "ShowCursor", u_ShowCursor }, { "ClipCursor", u_ClipCursor },
    { "GetCursorPos", u_GetCursorPos }, { "SetCursorPos", u_SetCursorPos },
    { "GetDesktopWindow", u_GetDesktopWindow }, { "GetParent", u_GetParent }, { "GetWindow", u_GetWindow },
    { "GetTopWindow", u_GetTopWindow }, { "EnumChildWindows", u_EnumChildWindows },
    { "GetFocus", u_GetFocus }, { "SetFocus", u_SetFocus }, { "SetCapture", u_SetCapture },
    { "ReleaseCapture", u_ReleaseCapture }, { "GetCapture", u_GetCapture },
    { "GetActiveWindow", u_GetActiveWindow }, { "GetForegroundWindow", u_GetForegroundWindow },
    { "SetActiveWindow", u_SetActiveWindow }, { "SetForegroundWindow", u_SetForegroundWindow },
    { "BringWindowToTop", u_BringWindowToTop }, { "EnableWindow", u_EnableWindow },
    { "IsWindowEnabled", u_IsWindowEnabled }, { "IsWindowVisible", u_IsWindowVisible }, { "IsWindow", u_IsWindow },
    { "SetWindowPos", u_SetWindowPos }, { "MoveWindow", u_MoveWindow },
    { "SetWindowLongA", u_SetWindowLongA }, { "GetWindowLongA", u_GetWindowLongA },
    { "GetWindowContextHelpId", u_GetWindowContextHelpId }, { "GetMenu", u_GetMenu },
    { "GetSystemMetrics", u_GetSystemMetrics }, { "GetClientRect", u_GetClientRect },
    { "GetWindowRect", u_GetWindowRect }, { "ClientToScreen", u_ClientToScreen },
    { "ScreenToClient", u_ScreenToClient }, { "MapWindowPoints", u_MapWindowPoints },
    { "WindowFromPoint", u_WindowFromPoint }, { "ChildWindowFromPoint", u_ChildWindowFromPoint },
    { "InvalidateRect", u_InvalidateRect }, { "ValidateRect", u_ValidateRect }, { "GetUpdateRect", u_GetUpdateRect },
    { "RedrawWindow", u_RedrawWindow }, { "UpdateWindow", u_UpdateWindow },
    { "BeginPaint", u_BeginPaint }, { "EndPaint", u_EndPaint },
    { "MessageBoxA", u_MessageBoxA }, { "MessageBoxIndirectA", u_MessageBoxIndirectA },
    { "RegisterClassA", u_RegisterClassA }, { "RegisterClassExA", u_RegisterClassExA },
    { "GetClassInfoA", u_GetClassInfoA }, { "GetClassNameA", u_GetClassNameA },
    { "CreateWindowExA", u_CreateWindowExA }, { "DefWindowProcA", u_DefWindowProcA },
    { "CallWindowProcA", u_CallWindowProcA }, { "ShowWindow", u_ShowWindow },
    { "CloseWindow", u_CloseWindow }, { "DestroyWindow", u_DestroyWindow },
    { "SetWindowTextA", u_SetWindowTextA }, { "GetWindowTextA", u_GetWindowTextA },
    { "GetWindowTextLengthA", u_GetWindowTextLengthA },
    { "PostMessageA", u_PostMessageA }, { "PostQuitMessage", u_PostQuitMessage },
    { "GetMessageA", u_GetMessageA }, { "PeekMessageA", u_PeekMessageA }, { "WaitMessage", u_WaitMessage },
    { "TranslateMessage", u_TranslateMessage }, { "DispatchMessageA", u_DispatchMessageA },
    { "SendMessageA", u_SendMessageA },
    { "CreateDialogParamA", u_CreateDialogParamA }, { "CreateDialogIndirectParamA", u_CreateDialogIndirectParamA },
    { "DialogBoxParamA", u_DialogBoxParamA }, { "DialogBoxIndirectParamA", u_DialogBoxIndirectParamA },
    { "EndDialog", u_EndDialog }, { "IsDialogMessageA", u_IsDialogMessageA }, { "IsDialogMessage", u_IsDialogMessageA },
    { "GetDlgItem", u_GetDlgItem }, { "GetDlgCtrlID", u_GetDlgCtrlID }, { "SendDlgItemMessageA", u_SendDlgItemMessageA },
    { "SetDlgItemTextA", u_SetDlgItemTextA }, { "GetDlgItemTextA", u_GetDlgItemTextA },
    { "CheckDlgButton", u_CheckDlgButton }, { "IsDlgButtonChecked", u_IsDlgButtonChecked },
    { "GetNextDlgTabItem", u_GetNextDlgTabItem },
    { "SetTimer", u_SetTimer }, { "KillTimer", u_KillTimer },
    { "GetKeyState", u_GetKeyState }, { "GetAsyncKeyState", u_GetAsyncKeyState },
    { "GetKeyboardState", u_GetKeyboardState }, { "MapVirtualKeyA", u_MapVirtualKeyA },
    { "GetKeyNameTextA", u_GetKeyNameTextA }, { "ToAscii", u_ToAscii },
    { "CharToOemBuffA", u_CharToOemBuffA }, { "OemToCharBuffA", u_OemToCharBuffA },
    { "CharUpperA", u_CharUpperA }, { "CharLowerA", u_CharLowerA },
    { "RegisterHotKey", u_RegisterHotKey }, { "UnregisterHotKey", u_UnregisterHotKey },
    { "WinHelpA", u_WinHelpA }, { "WaitForInputIdle", u_WaitForInputIdle }, { "MessageBeep", u_MessageBeep },
    { "DrawTextA", u_DrawTextA }, { "wsprintfA", u_wsprintfA }, { "wvsprintfA", u_wvsprintfA },
    { 0, 0 }
};

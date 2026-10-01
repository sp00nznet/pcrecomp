/*
 * ns_appkit.c - the slice of AppKit and Display PostScript an app reaches,
 * on SDL2.
 *
 * The objects are real guest instances of libNeXT's own classes, so state is
 * kept in their real ivars (View frame@12 bounds@28 window@52; Window
 * frame@12 contentView@28 delegate@32 firstResponder@36; Application
 * currentEvent@16 keyWindow@60 delegate@68) -- a subclass the app compiled
 * against AppKit's headers reads them directly.
 *
 * Drawing: every window is an SDL window; NXDrawBitmap converts the app's
 * bitmap to RGBA and presents it. Everything else PostScript is a no-op until
 * an app needs it.
 * Part of the pcrecomp toolbox.
 */
#include "ns_runtime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SDL_MAIN_HANDLED
#include <SDL.h>

/* ivars */
#define V_FRAME(v)   ((v) + 12)
#define V_BOUNDS(v)  ((v) + 28)
#define V_SUPER(v)   MEM32((v) + 44)
#define V_WINDOW(v)  MEM32((v) + 52)
#define W_FRAME(w)   ((w) + 12)
#define W_CONTENT(w) MEM32((w) + 28)
#define W_DELEGATE(w) MEM32((w) + 32)
#define W_FIRST(w)   MEM32((w) + 36)
#define A_EVENT(a)   ((a) + 16)
#define A_KEYWIN(a)  MEM32((a) + 60)
#define A_DELEGATE(a) MEM32((a) + 68)

/* NXEvent: type@0 location@4 time@12 flags@16 window@20 data@24 ctxt@36 */
#define NX_LMOUSEDOWN 1
#define NX_LMOUSEUP   2
#define NX_KEYDOWN    10
#define NX_KEYUP      11

#define NX_TWELVE_BIT_RGB_DEPTH 0x20C

static uint32_t g_app;                  /* NXApp */

/* ---- SDL window per NeXT window ------------------------------------------ */
#define MAX_WINDOWS 8
static struct { uint32_t win; SDL_Window *sdl; SDL_Renderer *r; SDL_Texture *tex; int tw, th; } g_wins[MAX_WINDOWS];

static int win_slot(uint32_t w, int create) {
    for (int i = 0; i < MAX_WINDOWS; i++) if (g_wins[i].win == w) return i;
    if (!create) return -1;
    for (int i = 0; i < MAX_WINDOWS; i++)
        if (!g_wins[i].win) { g_wins[i].win = w; return i; }
    return -1;
}

static void win_show(uint32_t w, const char *title) {
    int i = win_slot(w, 1);
    if (i < 0) return;
    int ww = (int)MEMF(W_FRAME(w) + 8), wh = (int)MEMF(W_FRAME(w) + 12);
    if (!g_wins[i].sdl) {
        SDL_InitSubSystem(SDL_INIT_VIDEO);
        g_wins[i].sdl = SDL_CreateWindow(title ? title : "NeXTSTEP", SDL_WINDOWPOS_CENTERED,
                                         SDL_WINDOWPOS_CENTERED, ww > 0 ? ww : 320, wh > 0 ? wh : 200,
                                         SDL_WINDOW_RESIZABLE);
        g_wins[i].r = SDL_CreateRenderer(g_wins[i].sdl, -1, SDL_RENDERER_PRESENTVSYNC);
    } else if (title) {
        SDL_SetWindowTitle(g_wins[i].sdl, title);
    }
}

/* ---- Application ---------------------------------------------------------- */
static void a_new(void) {
    if (!g_app) {
        g_app = ns_alloc_instance(ARG(0));
        uint32_t nxapp = ns_sym("_NXApp");
        if (nxapp) MEM32(nxapp) = g_app;
    }
    NS_RET(g_app);
}

/* ponytail: a nib is an NXTypedStream archive and is not parsed. Each of the
 * app's own non-View classes the nib names is instantiated, and the first
 * becomes NXApp's delegate -- enough for an app whose nib only wires a
 * delegate (NeXTDoom). A real typedstream reader is the next step for any
 * app whose windows live in its nibs (DoomEd). */
static void a_loadNib(void) {
    char path[2048];
    snprintf(path, sizeof path, "%s/English.lproj/%s/data.nib",
             ns_host_path(ns_bundle_dir()), GSTR(ARG(2)));
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "appkit: no nib %s\n", path); NS_RET(0); return; }
    static char buf[1 << 20];
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    uint32_t addr[64], size[64], view = ns_class("View");
    int ns = ns_sections("__OBJC", "__class", addr, size, 64);
    for (int s = 0; s < ns; s++)
    for (uint32_t c = addr[s]; c < addr[s] + size[s]; c += 40) {
        if (c >= 0x04000000u) break;                /* shlib classes: the app's sit low */
        const char *name = GSTR(MEM32(c + 8));
        size_t len = strlen(name);
        int named = 0;                              /* typedstream: length byte, then the name */
        for (size_t i = 1; i + len <= n && !named; i++)
            named = (uint8_t)buf[i - 1] == len && !memcmp(buf + i, name, len);
        int is_view = 0;
        for (uint32_t s = c; s; s = MEM32(s + 4)) is_view |= s == view;
        if (!named || is_view) continue;
        uint32_t obj = ns_send(ns_alloc_instance(c), "init", 0, NULL);
        fprintf(stderr, "appkit: %s: instantiated %s\n", GSTR(ARG(2)), name);
        if (!A_DELEGATE(g_app)) A_DELEGATE(g_app) = obj;
    }
    NS_RET(1);
}

static void pump_event(uint32_t app, int wait_ms);

static void a_run(void) {
    uint32_t app = ARG(0), del = A_DELEGATE(app);
    if (del) {
        uint32_t arg = app;
        if (ns_send(del, "respondsTo:", 1, (uint32_t[]){ ns_sel("appDidInit:") }))
            ns_send(del, "appDidInit:", 1, &arg);
    }
    for (;;) {                               /* until terminate: */
        pump_event(app, 100);
        if (MEM32(A_EVENT(app))) ns_send(app, "sendEvent:", 1, (uint32_t[]){ A_EVENT(app) });
    }
}

static void a_terminate(void) { fflush(NULL); SDL_Quit(); exit(0); }

static int sdl_to_nextchar(SDL_Keycode k) {
    switch (k) {
    case SDLK_LEFT: return 0xAC;  case SDLK_UP: return 0xAD;
    case SDLK_RIGHT: return 0xAE; case SDLK_DOWN: return 0xAF;
    case SDLK_RETURN: case SDLK_KP_ENTER: return 13;
    case SDLK_ESCAPE: return 27;  case SDLK_BACKSPACE: return 127;
    case SDLK_TAB: return 9;
    /* Doom's KEY_ codes for the modifiers and function keys: 0x80 + PC scancode */
    case SDLK_LCTRL: case SDLK_RCTRL: return 0x80 + 0x1D;
    case SDLK_LSHIFT: case SDLK_RSHIFT: return 0x80 + 0x36;
    case SDLK_LALT: case SDLK_RALT: return 0x80 + 0x38;
    case SDLK_PAUSE: return 0xFF;
    default:
        if (k >= SDLK_F1 && k <= SDLK_F10) return 0x80 + 0x3B + (k - SDLK_F1);
        if (k == SDLK_F11) return 0x80 + 0x57;
        if (k == SDLK_F12) return 0x80 + 0x58;
        if (k > 0 && k < 128) return k;
        return 0;
    }
}

/* Fill the app's currentEvent from SDL; type 0 = none. */
static void pump_event(uint32_t app, int wait_ms) {
    uint32_t ev = A_EVENT(app);
    SDL_Event e;
    MEM32(ev) = 0;
    int got = wait_ms > 0 ? SDL_WaitEventTimeout(&e, wait_ms) : SDL_PollEvent(&e);
    while (got) {
        if (e.type == SDL_QUIT) a_terminate();
        if ((e.type == SDL_KEYDOWN || e.type == SDL_KEYUP)) {
            int c = sdl_to_nextchar(e.key.keysym.sym);
            if (c) {
                memset(GUEST(ev), 0, 40);
                MEM32(ev) = e.type == SDL_KEYDOWN ? NX_KEYDOWN : NX_KEYUP;
                MEM32(ev + 12) = e.key.timestamp;
                MEM32(ev + 20) = 1;
                MEM16(ev + 26) = e.key.repeat;
                MEM16(ev + 30) = (uint16_t)c;       /* data.key.charCode */
                return;
            }
        }
        got = SDL_PollEvent(&e);
    }
}

/* getNextEvent:(int)mask waitFor:(double)timeout threshold:(int)level */
static void a_getNextEvent(void) {
    uint32_t app = ARG(0);
    double timeout = ARGD(3);
    pump_event(app, timeout > 0 ? (int)(timeout * 1000) : 0);
    NS_RET(MEM32(A_EVENT(app)) ? A_EVENT(app) : 0);
}

static void a_sendEvent(void) {
    uint32_t app = ARG(0), ev = ARG(2), type = MEM32(ev);
    uint32_t win = A_KEYWIN(app), resp = win ? W_FIRST(win) : 0;
    if (resp && (type == NX_KEYDOWN || type == NX_KEYUP))
        ns_send(resp, type == NX_KEYDOWN ? "keyDown:" : "keyUp:", 1, &ev);
    NS_RET(app);
}

static void a_delegate(void)    { NS_RET(A_DELEGATE(ARG(0))); }
static void a_setDelegate(void) { A_DELEGATE(ARG(0)) = ARG(2); NS_RET(ARG(0)); }
static void a_keyWindow(void)   { NS_RET(A_KEYWIN(ARG(0))); }

/* ---- Window ----------------------------------------------------------------- */
static void w_initContent(void) {
    uint32_t w = ARG(0);
    memcpy(GUEST(W_FRAME(w)), GUEST(ARG(2)), 16);
    NS_RET(w);
}
static void w_setTitle(void)   { win_show(ARG(0), GSTR(ARG(2))); NS_RET(ARG(0)); }
static void w_orderFront(void) {
    win_show(ARG(0), NULL);
    if (g_app) A_KEYWIN(g_app) = ARG(0);
    NS_RET(ARG(0));
}
static void w_contentView(void) { NS_RET(W_CONTENT(ARG(0))); }
static void w_setContentView(void) {
    uint32_t w = ARG(0), v = ARG(2);
    W_CONTENT(w) = v;
    if (v) { V_WINDOW(v) = w; V_SUPER(v) = 0; MEMF(V_FRAME(v)) = 0; MEMF(V_FRAME(v) + 4) = 0; }
    NS_RET(w);
}
static void w_makeFirstResponder(void) { W_FIRST(ARG(0)) = ARG(2); NS_RET(1); }
static void w_display(void) {
    uint32_t v = W_CONTENT(ARG(0));
    if (v) ns_send(v, "display", 0, NULL);
    NS_RET(ARG(0));
}
static void w_sizeWindow(void) {
    uint32_t w = ARG(0);
    MEMF(W_FRAME(w) + 8) = ARGF(2);
    MEMF(W_FRAME(w) + 12) = ARGF(3);
    int i = win_slot(w, 0);
    if (i >= 0 && g_wins[i].sdl) SDL_SetWindowSize(g_wins[i].sdl, (int)ARGF(2), (int)ARGF(3));
    if (W_CONTENT(w)) ns_send(W_CONTENT(w), "sizeTo::", 2, (uint32_t[]){ ARG(2), ARG(3) });
    NS_RET(w);
}
static void w_moveTo(void) {
    MEMF(W_FRAME(ARG(0))) = ARGF(2);
    MEMF(W_FRAME(ARG(0)) + 4) = ARGF(3);
    NS_RET(ARG(0));
}
static void w_getFrame(void) { memcpy(GUEST(ARG(2)), GUEST(W_FRAME(ARG(0))), 16); NS_RET(ARG(0)); }
static void w_convertBaseToScreen(void) {
    uint32_t w = ARG(0), p = ARG(2);
    MEMF(p) += MEMF(W_FRAME(w));
    MEMF(p + 4) += MEMF(W_FRAME(w) + 4);
    NS_RET(w);
}
static void w_depthLimit(void)  { NS_RET(NX_TWELVE_BIT_RGB_DEPTH); }
static void w_delegate(void)    { NS_RET(W_DELEGATE(ARG(0))); }
static void w_setDelegate(void) { W_DELEGATE(ARG(0)) = ARG(2); NS_RET(ARG(0)); }
static void w_windowNum(void)   { NS_RET(win_slot(ARG(0), 1) + 1); }

/* ---- View ------------------------------------------------------------------- */
static void v_initFrame(void) {
    uint32_t v = ARG(0);
    memcpy(GUEST(V_FRAME(v)), GUEST(ARG(2)), 16);
    memset(GUEST(V_BOUNDS(v)), 0, 8);
    memcpy(GUEST(V_BOUNDS(v) + 8), GUEST(ARG(2) + 8), 8);
    NS_RET(v);
}
/* -[View init] is [self initFrame:NULL] -- sent, so a subclass's initFrame:
 * runs (NeXTDoom's VGAView builds its window there). */
static void v_init(void) {
    uint32_t v = ARG(0), zero = ns_calloc(16);
    NS_RET(ns_send(v, "initFrame:", 1, &zero));
}
static void v_display(void) {
    uint32_t v = ARG(0);
    ns_send(v, "drawSelf::", 2, (uint32_t[]){ V_BOUNDS(v), 1 });
    NS_RET(v);
}
static void v_getBounds(void) { memcpy(GUEST(ARG(2)), GUEST(V_BOUNDS(ARG(0))), 16); NS_RET(ARG(0)); }
static void v_getFrame(void)  { memcpy(GUEST(ARG(2)), GUEST(V_FRAME(ARG(0))), 16); NS_RET(ARG(0)); }
static void v_window(void)    { NS_RET(V_WINDOW(ARG(0))); }
static void v_superview(void) { NS_RET(V_SUPER(ARG(0))); }
static void v_setDrawOrigin(void) {
    MEMF(V_BOUNDS(ARG(0))) = ARGF(2);
    MEMF(V_BOUNDS(ARG(0)) + 4) = ARGF(3);
    NS_RET(ARG(0));
}
static void v_sizeTo(void) {
    uint32_t v = ARG(0);
    MEMF(V_FRAME(v) + 8) = MEMF(V_BOUNDS(v) + 8) = ARGF(2);
    MEMF(V_FRAME(v) + 12) = MEMF(V_BOUNDS(v) + 12) = ARGF(3);
    NS_RET(v);
}
static void v_self(void) { NS_RET(ARG(0)); }
static void v_yes(void)  { NS_RET(1); }
static void v_no(void)   { NS_RET(0); }

/* ---- NXBundle --------------------------------------------------------------- */
static void b_mainBundle(void) {
    static uint32_t b;
    if (!b) b = ns_alloc_instance(ARG(0));
    NS_RET(b);
}
static void b_directory(void) {
    static uint32_t s;
    if (!s) s = ns_strdup(ns_bundle_dir());
    NS_RET(s);
}

/* ---- C functions: DPS and the NX helpers ----------------------------------- */
static void f_noop(void) { NS_RET(0); }
static void f_NXSetRect(void) {
    uint32_t r = ARG(0);
    for (int i = 0; i < 4; i++) MEMF(r + 4 * i) = ARGF(1 + i);
    NS_RET(0);
}
static void f_NXRunAlertPanel(void) {
    fprintf(stderr, "alert: %s: %s\n", ARG(0) ? GSTR(ARG(0)) : "",
            ARG(1) ? GSTR(ARG(1)) : "");
    NS_RET(1);                                 /* NX_ALERTDEFAULT */
}
/* NXColor is 16 bytes and opaque to the app; ours holds r, g, b, a floats.
 * NeXT's i386 gcc returns a struct through the address the caller left in
 * ebx, not a pushed hidden pointer. */
static void f_NXConvertRGBAToColor(void) {
    for (int i = 0; i < 4; i++) MEMF(g_ebx + 4 * i) = ARGF(i);
    NS_RET(g_ebx);
}
static void f_NXConvertColorToGrayAlpha(void) {
    float r = ARGF(0), g = ARGF(1), b = ARGF(2), a = ARGF(3);
    if (ARG(4)) MEMF(ARG(4)) = 0.299f * r + 0.587f * g + 0.114f * b;
    if (ARG(5)) MEMF(ARG(5)) = a;
    NS_RET(0);
}

/* NXDrawBitmap(rect, width, height, bps, spp, bpp, bpr, isPlanar, hasAlpha,
 *              colorSpace, data[5]) into the focused view's window. */
static uint32_t g_focus_view;
static void v_lockFocus(void)   { g_focus_view = ARG(0); NS_RET(1); }
static void v_unlockFocus(void) { NS_RET(ARG(0)); }

static void f_NXDrawBitmap(void) {
    int w = (int)ARG(1), h = (int)ARG(2), bps = (int)ARG(3), spp = (int)ARG(4);
    int bpp = (int)ARG(5), bpr = (int)ARG(6);
    const uint8_t *src = GUEST(MEM32(ARG(10)));
    uint32_t win = g_focus_view ? V_WINDOW(g_focus_view) : (g_app ? A_KEYWIN(g_app) : 0);
    int i = win_slot(win, 0);
    if (i < 0 || !g_wins[i].r || w <= 0 || h <= 0) { NS_RET(0); return; }
    if (!g_wins[i].tex || g_wins[i].tw != w || g_wins[i].th != h) {
        if (g_wins[i].tex) SDL_DestroyTexture(g_wins[i].tex);
        g_wins[i].tex = SDL_CreateTexture(g_wins[i].r, SDL_PIXELFORMAT_ARGB8888,
                                          SDL_TEXTUREACCESS_STREAMING, w, h);
        g_wins[i].tw = w; g_wins[i].th = h;
    }
    void *pix; int pitch;
    SDL_LockTexture(g_wins[i].tex, NULL, &pix, &pitch);
    for (int y = 0; y < h; y++) {
        const uint8_t *row = src + (size_t)y * bpr;
        uint32_t *out = (uint32_t *)((uint8_t *)pix + (size_t)y * pitch);
        for (int x = 0; x < w; x++) {
            uint32_t r, g, b;
            if (bps == 4 && bpp == 16) {                /* 12-bit RGB: RG BA nibbles */
                const uint8_t *p = row + 2 * x;
                r = (p[0] >> 4) * 17; g = (p[0] & 15) * 17; b = (p[1] >> 4) * 17;
            } else if (bps == 8 && spp >= 3) {
                const uint8_t *p = row + x * (bpp / 8);
                r = p[0]; g = p[1]; b = p[2];
            } else if (bps == 8) {
                r = g = b = row[x];
            } else {                                    /* 1- or 2-bit gray */
                int shift = 8 - bps - (x * bps) % 8, v = (row[x * bps / 8] >> shift) & ((1 << bps) - 1);
                r = g = b = v * 255 / ((1 << bps) - 1);
            }
            out[x] = 0xFF000000u | r << 16 | g << 8 | b;
        }
    }
    {   /* NS_SHOT=first,count,path saves frames first..first+count-1 as BMP;
         * path takes a printf %d for the frame number. How a headless check
         * (or a README gif) sees the picture. */
        static int frame;
        const char *shot = getenv("NS_SHOT");
        char *p;
        int first = shot ? (int)strtol(shot, &p, 10) : 0, count = shot && *p == ',' ? (int)strtol(p + 1, &p, 10) : 0;
        ++frame;
        if (shot && *p == ',' && frame >= first && frame < first + count) {
            char path[1024];
            snprintf(path, sizeof path, p + 1, frame);
            SDL_Surface *s = SDL_CreateRGBSurfaceWithFormatFrom(pix, w, h, 32, pitch, SDL_PIXELFORMAT_ARGB8888);
            SDL_SaveBMP(s, path);
            SDL_FreeSurface(s);
            if (frame == first + count - 1) fprintf(stderr, "appkit: frames %d..%d saved\n", first, frame);
        }
    }
    SDL_UnlockTexture(g_wins[i].tex);
    SDL_RenderClear(g_wins[i].r);
    SDL_RenderCopy(g_wins[i].r, g_wins[i].tex, NULL, NULL);
    SDL_RenderPresent(g_wins[i].r);
    (void)spp;
    NS_RET(0);
}

static const ns_shim_t appkit_shims[] = {
    { "+[Application new]", a_new },
    { "-[Application loadNibSection:owner:withNames:]", a_loadNib },
    { "-[Application loadNibSection:owner:]", a_loadNib },
    { "-[Application run]", a_run },
    { "-[Application terminate:]", a_terminate },
    { "-[Application getNextEvent:waitFor:threshold:]", a_getNextEvent },
    { "-[Application sendEvent:]", a_sendEvent },
    { "-[Application delegate]", a_delegate },
    { "-[Application setDelegate:]", a_setDelegate },
    { "-[Application keyWindow]", a_keyWindow },
    { "-[Window initContent:style:backing:buttonMask:defer:]", w_initContent },
    { "-[Window setTitle:]", w_setTitle },
    { "-[Window makeKeyAndOrderFront:]", w_orderFront },
    { "-[Window orderFront:]", w_orderFront },
    { "-[Window contentView]", w_contentView },
    { "-[Window setContentView:]", w_setContentView },
    { "-[Window makeFirstResponder:]", w_makeFirstResponder },
    { "-[Window display]", w_display },
    { "-[Window sizeWindow::]", w_sizeWindow },
    { "-[Window moveTo::]", w_moveTo },
    { "-[Window getFrame:]", w_getFrame },
    { "-[Window convertBaseToScreen:]", w_convertBaseToScreen },
    { "+[Window defaultDepthLimit]", w_depthLimit },
    { "-[Window depthLimit]", w_depthLimit },
    { "-[Window delegate]", w_delegate },
    { "-[Window setDelegate:]", w_setDelegate },
    { "-[Window windowNum]", w_windowNum },
    { "-[Window free]", v_no },
    { "-[View init]", v_init },
    { "-[View initFrame:]", v_initFrame },
    { "-[View display]", v_display },
    { "-[View getBounds:]", v_getBounds },
    { "-[View getFrame:]", v_getFrame },
    { "-[View window]", v_window },
    { "-[View superview]", v_superview },
    { "-[View setDrawOrigin::]", v_setDrawOrigin },
    { "-[View sizeTo::]", v_sizeTo },
    { "-[View lockFocus]", v_lockFocus },
    { "-[View unlockFocus]", v_unlockFocus },
    { "-[View allocateGState]", v_self },
    { "-[View convertPoint:fromView:]", v_self },
    { "-[View convertPoint:toView:]", v_self },
    { "-[View acceptsFirstResponder]", v_no },
    { "-[View free]", v_no },
    { "-[Responder acceptsFirstResponder]", v_no },
    { "-[Responder becomeFirstResponder]", v_yes },
    { "-[Responder resignFirstResponder]", v_yes },
    { "+[NXBundle mainBundle]", b_mainBundle },
    { "-[NXBundle directory]", b_directory },
    { "_NXPing", f_noop },            { "_PSlineto", f_noop },
    { "_PSmoveto", f_noop },          { "_PSsetgray", f_noop },
    { "_PSstroke", f_noop },          { "_NXEraseRect", f_noop },
    { "_PSobscurecursor", f_noop },   { "_NXSetRect", f_NXSetRect },
    { "_NXRunAlertPanel", f_NXRunAlertPanel },
    { "_NXConvertRGBAToColor", f_NXConvertRGBAToColor },
    { "_NXConvertColorToGrayAlpha", f_NXConvertColorToGrayAlpha },
    { "_NXDrawBitmap", f_NXDrawBitmap },
    { NULL, NULL }
};

void ns_appkit_init(void) {
    SDL_SetMainReady();
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_EVENTS) != 0)
        fprintf(stderr, "appkit: SDL_Init: %s\n", SDL_GetError());
    ns_register(appkit_shims);
}

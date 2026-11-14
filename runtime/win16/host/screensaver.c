/* screensaver.c - run a lifted Win16 screen saver (.scr) as a Win32 one.
 *
 * Windows 3.1's SCRNSAVE.LIB reads its command line as "/s" (run) or anything
 * else (configure). Windows 95 and later call a saver with
 *     /s            run full screen
 *     /p <hwnd>     draw a live preview inside <hwnd> (the Control Panel box)
 *     /c[:<hwnd>]   configure; no arguments at all means the same
 * so the host translates: /s and /p become the guest's "/s", /c becomes "/c".
 *
 * The guest believes the screen is RECOMP_SCREEN_W x RECOMP_SCREEN_H
 * (GetSystemMetrics). Its saver window is really the whole monitor (/s) or the
 * preview box (/p), and every DC on it carries an MM_ANISOTROPIC mapping, so
 * the guest's 640x480 drawing is scaled to fit and none of it has to know.
 *
 * In a preview the guest's own "close on mouse or key" logic must not run:
 * hovering over the Control Panel would end it. Input and activation messages
 * are not forwarded there; Windows ends the preview by destroying the parent,
 * which destroys the child, which quits.
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "recomp_game.h"

#ifndef RECOMP_SCREEN_W
#define RECOMP_SCREEN_W 640
#define RECOMP_SCREEN_H 480
#endif

int  recomp_scr_mode;               /* 0: not a saver run; 's', 'p', 'c' */
HWND recomp_scr_parent;             /* /p's window, /c:'s owner */
char recomp_guest_cmdline[16];      /* what InitTask hands the guest */
static HWND g_scr_hwnd;             /* the guest's saver window */

/* Consumes the switches in argv[1..]; returns the index of the first other
 * argument (main.c's image path), or argc. */
int recomp_scr_args(int argc, char **argv) {
    int i = 1;
    if (i < argc && (argv[i][0] == '/' || argv[i][0] == '-') && argv[i][1]) {
        char m = (char)(argv[i][1] | 0x20);
        const char *rest = argv[i] + 2;
        i++;
        if (*rest == ':' || *rest == ' ') rest++;
        else if (!*rest && i < argc && m == 'p') rest = argv[i++];   /* "/p 1234" */
        if (m == 's' || m == 'p' || m == 'c') {
            recomp_scr_mode = m;
            recomp_scr_parent = (HWND)(uintptr_t)strtoull(rest, NULL, 10);
            strcpy(recomp_guest_cmdline, m == 'c' ? "/c" : "/s");
        }
    }
    if (recomp_scr_mode == 'p' && !IsWindow(recomp_scr_parent)) exit(0);
    return i;
}

/* After CreateWindow: adopt the guest's first top-level window as the saver. */
void recomp_scr_window(HWND hw, uint32_t style) {
    if (!hw || g_scr_hwnd || (style & WS_CHILD)) return;
    if (recomp_scr_mode == 'p') {
        RECT r; GetClientRect(recomp_scr_parent, &r);
        SetWindowLongA(hw, GWL_STYLE, WS_CHILD | WS_VISIBLE);
        SetParent(hw, recomp_scr_parent);
        SetWindowPos(hw, NULL, 0, 0, r.right, r.bottom, SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
    } else if (recomp_scr_mode == 's') {
        SetWindowPos(hw, HWND_TOPMOST, 0, 0,
                     GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN), SWP_SHOWWINDOW);
    } else return;
    g_scr_hwnd = hw;
    RECT r; GetClientRect(hw, &r);
    fprintf(stderr, "[scr] /%c: the saver window is %ldx%ld\n", recomp_scr_mode, r.right, r.bottom);
}

int recomp_scr_owns(HWND h) { return h && h == g_scr_hwnd; }

/* Every DC on the saver window maps the guest's screen onto the real one. */
void recomp_scr_dc(HWND h, HDC dc) {
    if (!dc || !h || h != g_scr_hwnd) return;
    RECT r; GetClientRect(h, &r);
    if (getenv("RECOMP_LOG_WINPOS")) { static int n; if (n++ < 5) fprintf(stderr, "[scr] dc on %ldx%ld\n", r.right, r.bottom); }
    SetMapMode(dc, MM_ANISOTROPIC);
    SetWindowExtEx(dc, RECOMP_SCREEN_W, RECOMP_SCREEN_H, NULL);
    SetViewportExtEx(dc, r.right ? r.right : 1, r.bottom ? r.bottom : 1, NULL);
    SetStretchBltMode(dc, COLORONCOLOR);
}

/* 1: keep this message from the guest. */
int recomp_scr_filter(HWND h, UINT msg) {
    if (h != g_scr_hwnd) return 0;
    if (msg == WM_DESTROY) PostQuitMessage(0);        /* the parent went away */
    if (recomp_scr_mode != 'p') return 0;
    return (msg >= WM_MOUSEFIRST && msg <= WM_MOUSELAST) || (msg >= WM_KEYFIRST && msg <= WM_KEYLAST)
        || msg == WM_ACTIVATE || msg == WM_ACTIVATEAPP || msg == WM_SETCURSOR;
}

/*
 * w32klayout: Windows 2000's win32k shared state, in the layout its user32
 * and gdi32 read client-side. Host-independent: guest memory is reached
 * with MEM32 and friends (recomp_types.h), so the same code serves
 * w32kuser.c/w32kgdi.c over the host's USER and GDI on Windows and
 * w32kposix.c's own window manager on Linux. Offsets are Windows 2000 SP4's
 * (win2000-recomp docs/findings.md says where each came from).
 */
#ifndef W32KLAYOUT_H
#define W32KLAYOUT_H
#include <stdint.h>
#include "recomp_types.h"

/* ---- USER ----------------------------------------------------------------
 * The handle table (SHAREDINFO aheList): 12-byte entries { phead, pOwner,
 * bType, bFlags (bit 0 destroyed), wUniq }; a handle is index | wUniq << 16.
 * user32's ValidateHwnd checks index < SERVERINFO cHandleEntries, the type,
 * the uniq, and that phead lies in the thread's desktop heap. */
#define W2K_AHE_SIZE 12
enum { W2K_TYPE_FREE, W2K_TYPE_WINDOW, W2K_TYPE_MENU, W2K_TYPE_CURSOR, W2K_TYPE_ACCEL = 8 };

/* WND (THRDESKHEAD first) */
#define WND_HWND        0x00
#define WND_PTI         0x08
#define WND_PSELF       0x10
#define WND_STATE       0x14   /* bytes: +0x16 bit 0 a dialog (DIALOG at +0x9C) */
#define WND_EXSTYLE     0x1C
#define WND_STYLE       0x20
#define WND_HMODULE     0x24
#define WND_FNID        0x2A   /* the desktop's 0x29D, a dialog's 0x2A2 */
#define WND_NEXT        0x2C
#define WND_PARENT      0x30
#define WND_CHILD       0x34
#define WND_OWNER       0x38
#define WND_RCWINDOW    0x3C   /* screen coordinates */
#define WND_RCCLIENT    0x4C
#define WND_PROC        0x5C   /* called client-side by DispatchMessage */
#define WND_PCLS        0x60
#define WND_MENU        0x74   /* spmenu; a child's ID */
#define WND_STRNAME     0x7C   /* LARGE_UNICODE_STRING { Length, MaximumLength | bAnsi << 31, Buffer } */
#define WND_CBEXTRA     0x88
#define WND_USERDATA    0x94
#define WND_EXTRA       0x98   /* the window's extra bytes */
#define WND_SIZE        0x200

/* MENU / ITEM (CheckMenuItem and friends look items up client-side) */
#define MENU_PSELF      0x10
#define MENU_CITEMS     0x20
#define MENU_RGITEMS    0x34
#define ITEM_SIZE       0x4C   /* +0 fType, +4 fState, +8 wID, +0xC spSubMenu */

/* SERVERINFO */
#define SI_CHANDLES     0x008
#define SI_ATOMSYSCLASS 0x1A0  /* WORDs: Button, Edit, Static, ListBox, ScrollBar, ComboBox, MDIClient, ComboLBox */
#define SI_METRICS      0x59C  /* aiSysMet[0x53] */
#define SI_COLORS       0x6E8  /* argbSystem[0x1D] */
#define SI_BRUSHES      0x75C  /* ahbrSystem[0x1D] */
#define SI_CXSYSFONT    0x800
#define SI_CYSYSFONT    0x804
#define SI_GCLBORDER    0x7E4  /* gclBorder */
#define SI_LOGPIXELS    0xE4A
#define SI_PREFMASK     0xE50
#define SI_SIZE         0x10000

/* CLIENTINFO (TEB+0x6CC) */
#define TEB_W32THREAD   0x40
#define TEB_CLIENTINFO  0x6CC
#define CI_EXPWINVER    0x08
#define CI_DESKINFO     0x18   /* -> DESKTOPINFO { pvDesktopBase, pvDesktopLimit, spwnd } */
#define CI_CLIENTDELTA  0x1C
#define TEB_CBWND       0x6F4  /* CallbackWnd { hwnd, pwnd } */

/* DISPLAYINFO: +0x2C cMonitors, +0x30 pMonitorPrimary, +0x34 pMonitorFirst;
 * MONITOR: +0x0C flags, +0x10 rcMonitor, +0x20 rcWork */

/* win32k's callbacks into user32 (KernelCallbackTable indexes) */
#define W2K_CB_DWORD            2   /* __fnDWORD { pwnd, msg, w, l, xParam, xpfn } */
#define W2K_CB_INCNTOUTSTRING   7
#define W2K_CB_INLPCREATESTRUCT 9
#define W2K_CB_INSTRING        25
#define W2K_CB_LOADMENU        65   /* __ClientLoadMenu { header, hinst, UNICODE_STRING name } -> hmenu */
#define W2K_CB_THREADSETUP     74   /* __ClientThreadSetup */

#define FNID_DESKTOP       0x29D
#define FNID_DEFWINDOWPROC 0x29E
#define FNID_DIALOG        0x2A2
#define FNID_SENDMESSAGE   0x2AE

void w2k_ahe_set(uint32_t ahe, uint32_t h, uint32_t obj, uint8_t type, uint32_t owner);
void w2k_ahe_clear(uint32_t ahe, uint32_t h);
uint32_t w2k_ahe_obj(uint32_t ahe, uint32_t h, uint8_t type);   /* 0: not a live object of that type */
/* usersrv's ClientConnect: USERCONNECT { ulVersion, ulCurrentVersion,
 * dwDispatchCount, SHAREDINFO { psi, aheList, pDispInfo, ulSharedDelta, ...,
 * +0xE8 DefWindowMsgs } }. defmsgs: the 0x80-byte bitmap of messages
 * DefWindowProc hands to win32k */
void w2k_user_connect(uint32_t ci, uint32_t psi, uint32_t ahe, uint32_t disp, uint32_t defmsgs);
/* a thread's CLIENTINFO: its desktop (DESKTOPINFO), Win32ThreadInfo, 5.0 */
void w2k_client_info(uint32_t teb, uint32_t threadinfo, uint32_t deskinfo);
/* Windows 2000's classic defaults at 96 dpi: aiSysMet for a cx x cy screen
 * (a 28-pixel taskbar's work area) and argbSystem */
void w2k_metrics_2000(int32_t* m, int cx, int cy);
extern const uint32_t w2k_colors_2000[0x1D];
void w2k_monitor(uint32_t disp, uint32_t mon, int cx, int cy, int work_cy);

/* ---- GDI -----------------------------------------------------------------
 * Peb->GdiSharedHandleTable: 0x4000 entries of 16 bytes { pKernel, pid
 * (low bits clear), wHigh (the handle's high word), +0xA type (& 0x1F),
 * +0xC user-mode attributes (a DC's DC_ATTR, a region's RGNATTR) }; then
 * +0x40000 the display's DEVCAPS for gdi32's own GetDeviceCaps. A handle's
 * high word is uniq << 8 | type, 0x80 a stock object. */
#define GDI_ENTRIES    0x4000
#define GDI_TABLE_SIZE 0x80000
#define PEB_GDITABLE   0x94
enum { GDI_DC = 1, GDI_RGN = 4, GDI_BMP = 5, GDI_PAL = 8, GDI_FONT = 0xA, GDI_BRUSH = 0x10, GDI_PEN = 0x30 };
#define GDI_STOCK      0x80

/* DC_ATTR: gdi32 writes these in user mode, win32k reads them at a draw */
#define DCA_BRUSH     0x08
#define DCA_PEN       0x0C
#define DCA_BKCOLOR   0x14     /* (+0x10 the colour as given, +0x14 as realized) */
#define DCA_TEXTCOLOR 0x1C     /* (+0x18 / +0x1C) */
#define DCA_ROP2      0x38
#define DCA_BKMODE    0x39
#define DCA_CURX      0x3C
#define DCA_CURY      0x40
#define DCA_TEXTALIGN 0x7C     /* (+0x78 / +0x7C) */
#define DCA_FONT      0x90
#define DCA_MAPMODE   0x168
#define DCA_WINORG    0x174
#define DCA_WINEXT    0x17C
#define DCA_VPORG     0x184
#define DCA_VPEXT     0x18C
#define DCA_BRUSHORG  0x1B0
#define DCA_SIZE      0x400

void w2k_gdi_entry(uint32_t table, uint32_t h, uint32_t pid, uint32_t attr);
void w2k_gdi_clear(uint32_t table, uint32_t h);
int w2k_gdi_valid(uint32_t table, uint32_t h);
/* the display's DEVCAPS at +0x40000, from a GetDeviceCaps-like function */
void w2k_gdi_devcaps(uint32_t table, int (*caps)(int index));

/* The TEB batch: TEB+0x1D4 bytes used, +0x1D8 the DC, +0x1DC entries
 * { USHORT length, USHORT command, data }, +0xF70 their count. Commands:
 * 0 PatBlt { x, y, cx, cy, brush, rop, ... }, 1 PolyPatBlt { rop, mode,
 * count, ?, ?, ?, ?, then { x, y, cx, cy, brush } x count at +0x24 },
 * 2 TextOut { fg, bk, bkmode, ?, ?, x, y, options (bit 31 no rect), RECT,
 * cp, count, ?, font, align, viewport org, text at +0x48 }, 3 an opaque
 * ExtTextOut fill { bk, options, RECT }, 4 SetBrushOrg { x, y },
 * 5 ExtSelectClipRgn { mode (bit 31 no rect), RECT }, 6 select a font
 * { font }, 8 DeleteObject { handle }. fn gets each entry's address (the
 * command at +2, data from +4); the batch is empty after. */
enum { W2K_B_PATBLT, W2K_B_POLYPATBLT, W2K_B_TEXTOUT, W2K_B_EXTTEXTOUT, W2K_B_BRUSHORG, W2K_B_CLIPRGN, W2K_B_FONT, W2K_B_DELETE = 8 };
void w2k_gdi_batch(uint32_t teb, void (*fn)(uint32_t hdc, uint32_t cmd, uint32_t entry, uint32_t len));

#endif

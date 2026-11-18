/*
 * w32klayout: Windows 2000's win32k shared state, host-independent (see
 * w32klayout.h). The same layouts w32kuser.c/w32kgdi.c keep over the host's
 * USER and GDI on Windows; here as functions both hosts can call.
 */
#include <string.h>
#include "w32klayout.h"

/* ---- USER ---------------------------------------------------------------- */
void w2k_ahe_set(uint32_t ahe, uint32_t h, uint32_t obj, uint8_t type, uint32_t owner) {
    uint32_t e = ahe + W2K_AHE_SIZE * (h & 0xFFFF);
    MEM32(e) = obj;
    MEM32(e + 4) = owner;
    MEM8(e + 8) = type;
    MEM8(e + 9) = 0;
    MEM16(e + 0xA) = (uint16_t)(h >> 16);
}
void w2k_ahe_clear(uint32_t ahe, uint32_t h) {
    uint32_t e = ahe + W2K_AHE_SIZE * (h & 0xFFFF);
    MEM8(e + 9) = 1;                      /* destroyed: ValidateHwnd fails it */
    MEM8(e + 8) = W2K_TYPE_FREE;
    MEM32(e) = 0;
}
uint32_t w2k_ahe_obj(uint32_t ahe, uint32_t h, uint8_t type) {
    uint32_t e = ahe + W2K_AHE_SIZE * (h & 0xFFFF);
    if (!h || MEM8(e + 8) != type || MEM16(e + 0xA) != (uint16_t)(h >> 16) || (MEM8(e + 9) & 1)) return 0;
    return MEM32(e);
}

void w2k_user_connect(uint32_t ci, uint32_t psi, uint32_t ahe, uint32_t disp, uint32_t defmsgs) {
    MEM32(ci + 0x04) = MEM32(ci + 0x00);
    MEM32(ci + 0x0C) = psi;
    MEM32(ci + 0x10) = ahe;
    MEM32(ci + 0x14) = disp;
    /* ulSharedDelta: user32 subtracts it from every kernel pointer in the
     * shared section; ours are the guest's own addresses */
    MEM32(ci + 0x18) = 0;
    /* SHAREDINFO +0xE8 DefWindowMsgs { maxMsgs, abMsgs } (+0xF0
     * DefWindowSpecMsgs, the ones user32 answers itself: none) */
    MEM32(ci + 0x0C + 0xE8) = 0x3FF;
    MEM32(ci + 0x0C + 0xEC) = defmsgs;
    /* +0x10 awmControl[27] { maxMsgs, abMsgs }, by fnid from FNID_START
     * (0x29A): the messages each of user32's controls answers itself; the
     * rest its procedure hands to DefWindowProc. All of them, so a control's
     * own switch decides (left zero, the Edit control read its bitmap at
     * address msg >> 3) */
    for (int i = 0; i < 27; i++) MEM32(ci + 0x0C + 0x10 + 8 * i) = 0x3FF, MEM32(ci + 0x0C + 0x14 + 8 * i) = defmsgs;
}

void w2k_client_info(uint32_t teb, uint32_t threadinfo, uint32_t deskinfo) {
    uint32_t ci = teb + TEB_CLIENTINFO;
    /* TEB+0x40 Win32ThreadInfo: nonzero is a GUI thread */
    if (!MEM32(teb + TEB_W32THREAD)) MEM32(teb + TEB_W32THREAD) = threadinfo;
    if (MEM32(ci + CI_DESKINFO) != deskinfo) {
        MEM32(ci + CI_DESKINFO) = deskinfo;
        MEM32(ci + CI_CLIENTDELTA) = 0;
        /* dwExpWinVer (GETAPPVER) >= 4.0: dialogs get DS_3DLOOK. ponytail:
         * 5.0 for every program, the image's subsystem version if a 3.x one runs */
        MEM32(ci + CI_EXPWINVER) = 0x500;
    }
}

/* Windows 2000, classic scheme, 96 dpi, small fonts */
void w2k_metrics_2000(int32_t* m, int cx, int cy) {
    static const int32_t base[0x53] = {
        0, 0, 16, 16, 19, 1, 1, 3, 3, 16,          /* 0 CXSCREEN .. 9 CYVTHUMB */
        16, 32, 32, 32, 32, 19, 0, 0, 0, 1,        /* 10 CXHTHUMB .. 19 MOUSEPRESENT */
        16, 16, 0, 0, 0, 0, 0, 0, 112, 27,         /* 20 CYVSCROLL .. 29 CYMIN */
        18, 18, 4, 4, 112, 27, 4, 4, 75, 75,       /* 30 CXSIZE .. 39 CYICONSPACING */
        0, 0, 0, 3, 0, 2, 2, 160, 24, 16,          /* 40 MENUDROPALIGNMENT .. 49 CXSMICON */
        16, 15, 12, 14, 18, 18, 8, 160, 24, 0,     /* 50 CYSMICON .. 59 CXMAXTRACK */
        0, 0, 0, 3, 0, 0, 0, 0, 4, 4,              /* 60 CYMAXTRACK .. 69 CYDRAG */
        0, 13, 13, 0, 0, 1, 0, 0, 0, 0,            /* 70 SHOWSOUNDS .. 79 CYVIRTUALSCREEN */
        1, 1, 0 };                                 /* 80 CMONITORS .. 82 IMMENABLED */
    int work = cy - 28;
    memcpy(m, base, sizeof base);
    m[0] = m[78] = cx;                             /* SM_CXSCREEN, SM_CXVIRTUALSCREEN */
    m[1] = m[79] = cy;
    m[16] = cx;                                    /* SM_CXFULLSCREEN: the work area less a caption */
    m[17] = work - m[4];
    m[59] = cx + 12, m[60] = cy + 12;              /* SM_C?MAXTRACK */
    m[61] = cx + 2 * m[32], m[62] = work + 2 * m[33];   /* SM_C?MAXIMIZED */
}

/* argbSystem, classic: COLORREFs (0x00BBGGRR) */
const uint32_t w2k_colors_2000[0x1D] = {
    0xC8D0D4, 0xA56E3A, 0x6A240A, 0x808080, 0xC8D0D4, 0xFFFFFF, 0x000000, 0x000000,   /* SCROLLBAR .. MENUTEXT */
    0x000000, 0xFFFFFF, 0xC8D0D4, 0xC8D0D4, 0x808080, 0x6A240A, 0xFFFFFF, 0xC8D0D4,   /* WINDOWTEXT .. BTNFACE */
    0x808080, 0x808080, 0x000000, 0xC8D0D4, 0xFFFFFF, 0x404040, 0xC8D0D4, 0x000000,   /* BTNSHADOW .. INFOTEXT */
    0xE1FFFF, 0xB5B5B5, 0x800000, 0xF0CAA6, 0xC0C0C0 };                               /* INFOBK .. GRADIENTINACTIVE */

void w2k_monitor(uint32_t disp, uint32_t mon, int cx, int cy, int work_cy) {
    MEM32(mon + 0x0C) = 1;                         /* attached */
    MEM32(mon + 0x10) = 0, MEM32(mon + 0x14) = 0, MEM32(mon + 0x18) = (uint32_t)cx, MEM32(mon + 0x1C) = (uint32_t)cy;
    MEM32(mon + 0x20) = 0, MEM32(mon + 0x24) = 0, MEM32(mon + 0x28) = (uint32_t)cx, MEM32(mon + 0x2C) = (uint32_t)work_cy;
    MEM32(disp + 0x2C) = 1;
    MEM32(disp + 0x30) = mon;
    MEM32(disp + 0x34) = mon;
}

/* ---- GDI ----------------------------------------------------------------- */
void w2k_gdi_entry(uint32_t table, uint32_t h, uint32_t pid, uint32_t attr) {
    uint32_t e = table + 16 * (h & 0xFFFF);
    MEM32(e) = 0x80000000u | (h & 0xFFFF);        /* "the kernel object": nonzero */
    MEM32(e + 4) = pid & ~3u;
    MEM16(e + 8) = (uint16_t)(h >> 16);
    MEM8(e + 10) = (uint8_t)((h >> 16) & 0x1F);
    MEM32(e + 12) = attr;
}
void w2k_gdi_clear(uint32_t table, uint32_t h) {
    uint32_t e = table + 16 * (h & 0xFFFF);
    MEM32(e) = 0, MEM16(e + 8) = 0, MEM8(e + 10) = 0;
}
int w2k_gdi_valid(uint32_t table, uint32_t h) {
    uint32_t e = table + 16 * (h & 0xFFFF);
    return h && (h & 0xFFFF) < GDI_ENTRIES && MEM32(e) && MEM16(e + 8) == (uint16_t)(h >> 16);
}

void w2k_gdi_devcaps(uint32_t table, uint32_t off, int (*caps)(int index)) {
    /* { index, offset }, read off gdi32's GetDeviceCaps; the rest it asks
     * NtGdiGetDeviceCaps for */
    static const uint8_t map[][2] = { { 0, 0 }, { 2, 4 }, { 4, 8 }, { 6, 0xC }, { 8, 0x18 }, { 0xA, 0x1C }, { 0xC, 0x20 },
        { 0xE, 0x24 }, { 0x12, 0x28 }, { 0x16, 0x2C }, { 0x18, 0x30 }, { 0x22, 0x64 }, { 0x26, 0x34 }, { 0x28, 0x38 },
        { 0x2A, 0x3C }, { 0x58, 0x44 }, { 0x5A, 0x48 }, { 0x68, 0x4C }, { 0x6C, 0x50 }, { 0x6E, 0x54 }, { 0x6F, 0x58 },
        { 0x70, 0x5C }, { 0x71, 0x60 }, { 0x74, 0x68 }, { 0x75, 0x70 }, { 0x76, 0x6C }, { 0x77, 0x74 } };
    for (unsigned i = 0; i < sizeof map / sizeof map[0]; i++) MEM32(table + off + map[i][1]) = (uint32_t)caps(map[i][0]);
}

void w2k_gdi_batch(uint32_t teb, void (*fn)(uint32_t hdc, uint32_t cmd, uint32_t entry, uint32_t len)) {
    uint32_t used = MEM32(teb + 0x1D4), hdc = MEM32(teb + 0x1D8);
    if (!used) return;
    MEM32(teb + 0x1D4) = 0;               /* (first: a command may call back into a service) */
    for (uint32_t off = 0; off + 4 <= used && off < 0x4D8; ) {
        uint32_t e = teb + 0x1DC + off, len = MEM16(e);
        fn(hdc, MEM16(e + 2), e, len);
        if (len < 4) break;
        off += (len + 3) & ~3u;
    }
    MEM32(teb + 0x1D8) = 0;
    MEM32(teb + 0xF70) = 0;
}

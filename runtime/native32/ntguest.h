/*
 * ntguest: what differs between the NT guests this runtime serves (NT 4.0,
 * Windows 2000, NT 5.0, and Windows XP, NT 5.1), answered from the guest's own image
 * or its PEB's OSBuildNumber (+0xAC), never from a build-time switch.
 *
 * ntstub_parse: the service number and argument count of an NT system-call stub,
 * in either form ntdll/user32/gdi32 use:
 *   Windows 2000:     mov eax, N / lea edx, [esp+4] / int 2Eh / ret 4n
 *   Windows XP SP2+:  mov eax, N / mov edx, 7FFE0300h / call [edx] / ret 4n
 * (XP's call goes through KUSER_SHARED_DATA's SystemCall to KiFastSystemCall's
 * sysenter; the lifter turns the call itself into recomp_syscall, lift32.py.)
 */
#ifndef NTGUEST_H
#define NTGUEST_H
#include <stdint.h>
static inline int ntstub_parse(const uint8_t* b, uint32_t* svc, uint8_t* argc) {
    int r;
    if (b[0] != 0xB8) return 0;
    if (b[5] == 0x8D && b[6] == 0x54 && b[7] == 0x24 && b[8] == 0x04 && b[9] == 0xCD && b[10] == 0x2E) r = 11;
    else if (b[5] == 0xBA && b[6] == 0x00 && b[7] == 0x03 && b[8] == 0xFE && b[9] == 0x7F && b[10] == 0xFF && b[11] == 0x12) r = 12;
    else return 0;
    *svc = *(const uint32_t*)(b + 1);
    *argc = b[r] == 0xC2 ? (uint8_t)(*(const uint16_t*)(b + r + 1) / 4) : 0;
    return 1;
}

/* a guest address as a host pointer: ADDR() where recomp_types.h is in (the
 * Linux host, based on 64-bit hosts: a64), flat otherwise */
#ifdef ADDR
#define NTGUEST_VA(va) ADDR(va)
#else
#define NTGUEST_VA(va) ((uintptr_t)(uint32_t)(va))
#endif
/* NT 5.1 (Windows XP, build 2600) or later, by the guest PEB's build number */
static inline int nt_guest_xp(uint32_t peb) {
    return peb && *(const uint16_t*)NTGUEST_VA(peb + 0xAC) >= 2600;
}

/* NT 4.0 (build 1381), by the guest PEB's build number (Windows 2000's
 * release candidates, 2128..2183, are NT 5.0) */
static inline int nt_guest_nt4(uint32_t peb) {
    return peb && *(const uint16_t*)NTGUEST_VA(peb + 0xAC) < 2000;
}
/* CLIENTINFO in the TEB: Win32ClientInfo (+0x6CC) on NT 5, User32Reserved (+0x44) on
 * NT 4.0, with pDeskInfo and ulClientDelta at the same +0x18 / +0x1C. NT 4.0 has no
 * CallbackWnd (2000's +0x28): its DispatchClientMessage takes the hwnd from the WND. */
static inline uint32_t nt_teb_ci(uint32_t peb) { return nt_guest_nt4(peb) ? 0x44 : 0x6CC; }
/* the TEB's GDI batch: bytes used, then the DC, then the entries (NT 4.0's gdi32 PatBlt: +0x1FC) */
static inline uint32_t nt_teb_batch(uint32_t peb) { return nt_guest_nt4(peb) ? 0x1FC : 0x1D4; }
static inline uint32_t nt_teb_cbwnd(uint32_t peb) { return nt_guest_nt4(peb) ? 0 : 0x6F4; }
/* csrss api numbers, the guest's to Windows 2000's ((server << 16) | api;
 * 0xFFFFFFFF: an api Windows 2000 does not have). NT 4.0's csrsrv has
 * CsrNullApiCall at 0, so ClientConnect is 1 (2000: 0), ThreadConnect 2,
 * ProfileControl 3, IdentifyAlertableThread 4, SetPriorityClass 5 (read off
 * NT 4.0 SP6a ntdll's Csr* exports). */
static inline uint32_t nt_csr_api(uint32_t peb, uint32_t api) {
    if (!nt_guest_nt4(peb) || (api >> 16) != 0) return api;
    return (api & 0xFFFF) ? api - 1 : 0xFFFFFFFFu;
}

/* GDI's shared memory (Peb->GdiSharedHandleTable): the handle table, then
 * the display's DEVCAPS that gdi32's GetDeviceCaps reads. Windows 2000 has
 * 0x4000 16-byte entries (DEVCAPS at +0x40000), XP 0x10000 (+0x100000).
 * NT_GDI_SHARED_SIZE holds either. */
#define NT_GDI_SHARED_SIZE 0x110000
static inline uint32_t nt_gdi_devcaps(uint32_t peb) { return nt_guest_xp(peb) ? 0x100000 : 0x40000; }

/* DC_ATTR, by Windows 2000's offsets. NT 4.0's (its gdi32's Set/Get* and SelectObject): jROP2 /
 * jBkMode 0x28/0x29, ptlCurrent 0x2C, lBkMode 0x3C, fill and stretch modes 0x40/0x44, text align
 * 0x48/0x4C, hlfntNew 0x60, iMapMode 0x138, window/viewport origins and extents from 0x13C,
 * brush origin 0x170; the brush, pen and colours (0x08..0x1C) as 2000's */
static inline uint32_t nt_dca(uint32_t peb, uint32_t o) {
    if (!nt_guest_nt4(peb) || o < 0x20) return o;
    if (o == 0x38 || o == 0x39) return o - 0x10;
    if (o >= 0x3C && o < 0x58) return o - 0x10;
    if (o == 0x78 || o == 0x7C) return o - 0x30;
    if (o == 0x90) return 0x60;
    if (o == 0x168) return 0x138;
    if (o >= 0x174 && o < 0x194) return o - 0x38;
    if (o >= 0x1B0 && o < 0x1B8) return o - 0x40;
    return 0x1F0 + (o & 0xF);   /* ponytail: a field not mapped, out of the way (ATTR_SIZE is larger) */
}

/* ---- USER: XP's layouts as shifts of Windows 2000's ------------------------
 * The win32k layer keeps Windows 2000's offsets (read off its user32) and
 * asks these for the guest's. XP's numbers were read off its own user32
 * (winxp-recomp docs/survey.md): code that reads each field in both.
 *
 * WND: XP inserts spwndPrev at 0x30 (+4 from there), and two dwords after
 * dwUserData (pActCtx, ...): the extra bytes are at 0xA4, not 0x98. */
static inline uint32_t nt_wnd(uint32_t peb, uint32_t o) {
    /* NT 4.0 (its user32: GetWindowLong's GWL_* cases, GetWindowRect, GetClientRect,
     * GetParent, GetDlgCtrlID, IsWindowVisible): pSelf at 0xC, the links first (Next 0x14,
     * Parent 0x18, Child 0x1C, Owner 0x20), rcWindow 0x28, rcClient 0x38, lpfnWndProc 0x48,
     * pcls 0x4C, cbwndExtra 0x50, hrgnUpdate 0x54, spmenu (ID) 0x68, hMod16/fnid 0x78/0x7A,
     * dwUserData 0x80, then state, state2, ExStyle, style, hModule (0x9C..0xAC), extra 0xB0.
     * ponytail: spwndLastActive at 0x24 is a guess (the gap); fields not listed stay put. */
    if (nt_guest_nt4(peb)) {
        static const uint8_t m[][2] = {
            { 0x10, 0x0C }, { 0x14, 0x9C }, { 0x18, 0xA0 }, { 0x1C, 0xA4 }, { 0x20, 0xA8 }, { 0x24, 0xAC },
            { 0x28, 0x78 }, { 0x2A, 0x7A }, { 0x2C, 0x14 }, { 0x30, 0x18 }, { 0x34, 0x1C }, { 0x38, 0x20 },
            { 0x5C, 0x48 }, { 0x60, 0x4C }, { 0x64, 0x54 }, { 0x74, 0x68 }, { 0x88, 0x50 }, { 0x8C, 0x24 },
            { 0x94, 0x80 } };
        if (o >= 0x3C && o < 0x5C) return o - 0x14;          /* rcWindow, rcClient */
        if (o >= 0x98) return o + 0x18;                      /* the extra bytes */
        for (unsigned i = 0; i < sizeof m / sizeof m[0]; i++) if (m[i][0] == (o & ~3u)) return m[i][1] + (o & 3);
        return o;
    }
    if (!nt_guest_xp(peb) || o < 0x30) return o;
    return o < 0x98 ? o + 4 : o + 0xC;
}
/* SERVERINFO: +0xC from the start, +0x20 for atomSysClass, +0x24 from
 * wMaxBtnSize through aiSysMet; argbSystem (+0xB8) then ahbrSystem (+0xC0)
 * hold 0x1F colours, not 0x1D; +0xC8 after them. */
static inline uint32_t nt_si(uint32_t peb, uint32_t o) {
    /* NT 4.0 (its user32: ValidateHwnd, GetSystemMetrics, GetSysColor, GetDialogBaseUnits, the
     * dialog template's class ordinals): cHandleEntries +4, aiSysMet[0x4C] +0x170, argbSystem[0x19]
     * +0x2A0, ahbrSystem +0x304, atomSysClass +0x788, cx/cySysFontChar +0x7D4, cx/cyMsgFontChar
     * +0x7DC. A field NT 4.0 lacks or that is unmapped goes to scratch past its SERVERINFO. */
    if (nt_guest_nt4(peb)) {
        if (o == 0x8) return 0x4;
        if (o >= 0x59C && o < 0x6E8) return o - 0x59C + 0x170;
        if (o >= 0x6E8 && o < 0x75C) return o - 0x6E8 + 0x2A0;
        if (o >= 0x75C && o < 0x7D0) return o - 0x75C + 0x304;
        if (o >= 0x1A0 && o < 0x1C0) return o - 0x1A0 + 0x788;
        if (o >= 0x800 && o < 0x810) return o - 0x800 + 0x7D4;
        /* the display: dmLogPixels +0x754 (the dialog font's height), Planes / BitsPixel +0x75A /
         * +0x75B, BitCount +0x75C (DrawEdge, DrawFrameControl compare it with 1 and 8) */
        if (o == 0xE4A) return 0x754;
        if (o == 0xE4C) return 0x75A;
        if (o == 0xE4D) return 0x75B;
        if (o == 0xE48) return 0x75C;
        return 0xF000 + (o & 0xFFF);
    }
    if (!nt_guest_xp(peb) || o < 0x10) return o;
    return o < 0x1A0 ? o + 0xC : o < 0x1D4 ? o + 0x20 : o < 0x6E8 ? o + 0x24
         : o < 0x75C ? o + 0xB8 : o < 0x7D0 ? o + 0xC0 : o + 0xC8;
}
/* (an array's element i: nt_si(peb, start) + 4 * i, since XP's arrays are longer) */
static inline int nt_ncolors(uint32_t peb) { return nt_guest_xp(peb) ? 0x1F : nt_guest_nt4(peb) ? 0x19 : 0x1D; }
/* gdi32's TEB batch: XP's PolyPatBlt has its rectangles at +0x30 (2000: +0x24),
 * and its TextOut two more dwords before x (everything from x on is 8 later) */
static inline uint32_t nt_batch_polypatblt(uint32_t peb) { return nt_guest_xp(peb) ? 0x30 : nt_guest_nt4(peb) ? 0x18 : 0x24; }   /* (NT 4.0: gdi32 PolyPatBlt) */
static inline uint32_t nt_batch_textout(uint32_t peb) { return nt_guest_xp(peb) ? 8 : 0; }
/* SHAREDINFO.DefWindowMsgs: after awmControl[0x1D] (XP: [0x1F]; NT 4.0: [0x1B] from +0xC) */
static inline uint32_t nt_shared_defmsgs(uint32_t peb) { return nt_guest_xp(peb) ? 0x108 : nt_guest_nt4(peb) ? 0xE4 : 0xE8; }
/* KernelCallbackTable: XP has one more entry at 3 and another before
 * __ClientLoadMenu (2000's 65, XP's 67) */
static inline uint32_t nt_cb(uint32_t peb, uint32_t i) {
    /* NT 4.0: __fnDWORD 2, __fnINCNTOUTSTRING 7 as 2000's (the same code); __ClientThreadSetup
     * is 76 (2000's 74, matched by its body). ponytail: the four the win32k layer calls */
    if (nt_guest_nt4(peb)) return i == 74 ? 76 : i;
    if (!nt_guest_xp(peb) || i < 3) return i;
    return i < 62 ? i + 1 : i + 2;
}
/* NtUserCall* routine indexes, XP's (and NT 4.0's) to Windows 2000's: anchors read off the
 * user32 exports that pass each (both builds), the indexes between two
 * anchors with the same shift by that shift; 0xFFFF: no Windows 2000 match */
static inline uint32_t nt_routine(uint32_t peb, uint32_t x) {
    static const uint16_t a[][2] = {
        { 0x00, 0x00 }, { 0x01, 0x01 }, { 0x05, 0x02 }, { 0x08, 0x04 }, { 0x09, 0x05 }, { 0x0D, 0x08 }, { 0x18, 0x12 },
        { 0x1E, 0x16 }, { 0x21, 0x19 }, { 0x25, 0x1C }, { 0x28, 0x1E }, { 0x29, 0x1F }, { 0x2A, 0x33 }, { 0x2B, 0x20 },
        { 0x2C, 0x37 }, { 0x2E, 0x21 }, { 0x2F, 0x22 }, { 0x31, 0x24 }, { 0x33, 0x26 }, { 0x35, 0x27 }, { 0x39, 0x29 },
        { 0x3C, 0x2C }, { 0x3E, 0x30 }, { 0x3F, 0x34 }, { 0x40, 0x2D }, { 0x42, 0x2F }, { 0x45, 0x39 }, { 0x48, 0x3C },
        { 0x4A, 0x3E }, { 0x4B, 0x3F }, { 0x4E, 0x42 }, { 0x51, 0x45 }, { 0x54, 0x47 }, { 0x55, 0x48 }, { 0x5B, 0x4D },
        { 0x5E, 0x50 }, { 0x60, 0x53 }, { 0x62, 0x55 }, { 0x63, 0x56 }, { 0x65, 0x57 }, { 0x69, 0x5B }, { 0x6A, 0x5C },
        { 0x6E, 0x5E }, { 0x6F, 0x5F }, { 0x70, 0x60 } };
    int n = (int)(sizeof a / sizeof a[0]);
    if (nt_guest_nt4(peb)) {
        /* NT 4.0's apfnSimpleCall is ordered otherwise: no interpolation, each
         * index read off the user32 export that passes it (both builds; NoParam-
         * Translate 0xB/0xC are CreateMenu/CreatePopupMenu) */
        static const uint8_t m[][2] = {
            { 0x02, 0x05 }, { 0x07, 0x04 }, { 0x08, 0x08 }, { 0x0A, 0x02 }, { 0x0B, 0x00 }, { 0x0C, 0x01 },
            { 0x0D, 0x19 }, { 0x0F, 0x1C }, { 0x10, 0x1E }, { 0x11, 0x1F }, { 0x12, 0x20 }, { 0x14, 0x26 },
            { 0x15, 0x29 }, { 0x16, 0x2A }, { 0x17, 0x2B }, { 0x18, 0x2C }, { 0x19, 0x30 }, { 0x1A, 0x2F },
            { 0x1B, 0x2D }, { 0x1C, 0x2E }, { 0x1F, 0x22 }, { 0x20, 0x24 }, { 0x21, 0x27 }, { 0x25, 0x39 },
            { 0x26, 0x3B }, { 0x27, 0x3C }, { 0x2A, 0x47 }, { 0x2C, 0x48 }, { 0x31, 0x4D }, { 0x33, 0x50 },
            { 0x34, 0x3E }, { 0x35, 0x3F }, { 0x36, 0x5B }, { 0x37, 0x5C }, { 0x38, 0x5E }, { 0x39, 0x5F },
            { 0x3A, 0x60 }, { 0x3D, 0x42 }, { 0x3E, 0x45 }, { 0x3F, 0x41 }, { 0x41, 0x43 }, { 0x43, 0x46 }, { 0x44, 0x53 }, { 0x47, 0x55 }, { 0x48, 0x56 },
            { 0x49, 0x57 } };
        for (int i = 0; i < (int)(sizeof m / sizeof m[0]); i++) if (m[i][0] == x) return m[i][1];
        return 0xFFFF;
    }
    if (!nt_guest_xp(peb)) return x;
    for (int i = 0; i < n; i++) {
        if (a[i][0] == x) return a[i][1];
        if (i + 1 < n && a[i][0] < x && x < a[i + 1][0] &&
            a[i][0] - a[i][1] == a[i + 1][0] - a[i + 1][1]) return x - (a[i][0] - a[i][1]);
    }
    return 0xFFFF;
}
/* win32k services whose XP argument list has one more than 2000's: the
 * index of the extra one, which a 2000-shaped handler drops (-1: none).
 * CreateWindowEx and RegisterClassExWOW take the class's version-specific
 * name after the class name ("6.0.2600.5512!Button" under comctl32 v6's
 * activation context, else the name itself): the win32k layer registers and
 * creates by that one, dropping the base name (index 1) when it is there.
 * CreateWindowEx also has a last one, past 2000's 13. */
#include <string.h>
static inline int nt_w32k_xp_extra(const char* name) {
    if (!strcmp(name, "NtUserCreateWindowEx") || !strcmp(name, "NtUserRegisterClassExWOW")) return 2;
    return -1;
}
/* FNIDs: XP has two more before the controls' (from 2000's 0x2A0 on they
 * are 2 higher: FNID_DIALOG 0x2A4, FNID_SENDMESSAGE 0x2B0); XP's as 2000's */
static inline uint32_t nt_fnid(uint32_t peb, uint32_t x) {
    /* NT 4.0 has no FNID_MESSAGEWND (2000's 0x29F): from there on one lower (SendMessage 0x2AD) */
    if (nt_guest_nt4(peb)) return x >= 0x29F && x < 0x2C0 ? x + 1 : x;
    return nt_guest_xp(peb) && x >= 0x2A2 && x < 0x2C0 ? x - 2 : x;
}
#endif

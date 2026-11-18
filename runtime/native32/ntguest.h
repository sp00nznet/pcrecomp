/*
 * ntguest: what differs between the NT guests this runtime serves (Windows
 * 2000, NT 5.0, and Windows XP, NT 5.1), answered from the guest's own image
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

/* NT 5.1 (Windows XP, build 2600) or later, by the guest PEB's build number */
static inline int nt_guest_xp(uint32_t peb) {
    return peb && *(const uint16_t*)(uintptr_t)(peb + 0xAC) >= 2600;
}

/* GDI's shared memory (Peb->GdiSharedHandleTable): the handle table, then
 * the display's DEVCAPS that gdi32's GetDeviceCaps reads. Windows 2000 has
 * 0x4000 16-byte entries (DEVCAPS at +0x40000), XP 0x10000 (+0x100000).
 * NT_GDI_SHARED_SIZE holds either. */
#define NT_GDI_SHARED_SIZE 0x110000
static inline uint32_t nt_gdi_devcaps(uint32_t peb) { return nt_guest_xp(peb) ? 0x100000 : 0x40000; }

/* ---- USER: XP's layouts as shifts of Windows 2000's ------------------------
 * The win32k layer keeps Windows 2000's offsets (read off its user32) and
 * asks these for the guest's. XP's numbers were read off its own user32
 * (winxp-recomp docs/survey.md): code that reads each field in both.
 *
 * WND: XP inserts spwndPrev at 0x30 (+4 from there), and two dwords after
 * dwUserData (pActCtx, ...): the extra bytes are at 0xA4, not 0x98. */
static inline uint32_t nt_wnd(uint32_t peb, uint32_t o) {
    if (!nt_guest_xp(peb) || o < 0x30) return o;
    return o < 0x98 ? o + 4 : o + 0xC;
}
/* SERVERINFO: +0xC from the start, +0x20 for atomSysClass, +0x24 from
 * wMaxBtnSize through aiSysMet; argbSystem (+0xB8) then ahbrSystem (+0xC0)
 * hold 0x1F colours, not 0x1D; +0xC8 after them. */
static inline uint32_t nt_si(uint32_t peb, uint32_t o) {
    if (!nt_guest_xp(peb) || o < 0x10) return o;
    return o < 0x1A0 ? o + 0xC : o < 0x1D4 ? o + 0x20 : o < 0x6E8 ? o + 0x24
         : o < 0x75C ? o + 0xB8 : o < 0x7D0 ? o + 0xC0 : o + 0xC8;
}
/* (an array's element i: nt_si(peb, start) + 4 * i, since XP's arrays are longer) */
static inline int nt_ncolors(uint32_t peb) { return nt_guest_xp(peb) ? 0x1F : 0x1D; }
/* SHAREDINFO.DefWindowMsgs: after awmControl[0x1D] (XP: [0x1F]) */
static inline uint32_t nt_shared_defmsgs(uint32_t peb) { return nt_guest_xp(peb) ? 0x108 : 0xE8; }
/* KernelCallbackTable: XP has one more entry at 3 and another before
 * __ClientLoadMenu (2000's 65, XP's 67) */
static inline uint32_t nt_cb(uint32_t peb, uint32_t i) {
    if (!nt_guest_xp(peb) || i < 3) return i;
    return i < 62 ? i + 1 : i + 2;
}
/* NtUserCall* routine indexes, XP's to Windows 2000's: anchors read off the
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
 * CreateWindowEx and RegisterClassExWOW take the class's version name after
 * the class name (CreateWindowEx also a last one, past 2000's 13). */
#include <string.h>
static inline int nt_w32k_xp_extra(const char* name) {
    if (!strcmp(name, "NtUserCreateWindowEx") || !strcmp(name, "NtUserRegisterClassExWOW")) return 2;
    return -1;
}
#endif

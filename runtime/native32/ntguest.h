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
#endif

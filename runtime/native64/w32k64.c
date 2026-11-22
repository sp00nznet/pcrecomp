/*
 * w32k64.c: win32k for a lifted 64-bit user32/gdi32 (native64.c), the
 * first services: what a console program's user32 and gdi32 need to load.
 *
 * ponytail: answered just enough for user32's and gdi32's DLL init; a
 * window-drawing layer (native32's w32kuser/w32kgdi in x64 layouts) is
 * stage 3.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "native64.h"

/* NtGdiInit(): the kernel maps GDI's shared handle table into the process
 * (PEB+0xF8 GdiSharedHandleTable); 65536 x64 GDI_TABLE_ENTRYs of 24 bytes, then
 * the shared GDI data gdi32 reads at +0x180000 */
static uint64_t gdi_init(uint64_t* a) {
    (void)a;
    uint8_t* peb = (uint8_t*)(uintptr_t)native64_peb;
    if (!*(uint64_t*)(peb + 0xF8))
        *(uint64_t*)(peb + 0xF8) = (uint64_t)(uintptr_t)VirtualAlloc(NULL, 0x10000 * 24 + 0x10000,
                                                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    return 1;
}

void w32k64_install(void) {
    native64_w32k("NtGdiInit", gdi_init);
}

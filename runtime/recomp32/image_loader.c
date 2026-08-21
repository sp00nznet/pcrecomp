/*
 * image_loader.c - generic PE image loader for the recomp32 runtime.
 * See image_loader.h. Forged on the Fury3 (1995) recompilation.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "image_loader.h"

#pragma pack(push, 1)
typedef struct {
    char     name[8];
    uint32_t vsize;   /* VirtualSize        */
    uint32_t vaddr;   /* VirtualAddress (RVA)*/
    uint32_t rsize;   /* SizeOfRawData      */
    uint32_t roff;    /* PointerToRawData   */
    uint32_t reloc_ptr, lineno_ptr;
    uint16_t nreloc, nlineno;
    uint32_t chr;     /* Characteristics    */
} recomp_sechdr_t;
#pragma pack(pop)

uint32_t recomp_load_image(const char* path, uint32_t image_base) {
    FILE* f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "[loader] cannot open %s\n", path); return 0; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0x40) { fclose(f); return 0; }
    uint8_t* buf = (uint8_t*)malloc((size_t)sz);
    if (!buf) { fclose(f); return 0; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) { fclose(f); free(buf); return 0; }
    fclose(f);

    if (buf[0] != 'M' || buf[1] != 'Z') { free(buf); fprintf(stderr, "[loader] not MZ\n"); return 0; }
    uint32_t e_lfanew = *(uint32_t*)(buf + 0x3C);
    uint8_t* nt = buf + e_lfanew;
    if (nt[0] != 'P' || nt[1] != 'E') { free(buf); fprintf(stderr, "[loader] not PE\n"); return 0; }

    uint16_t nsec   = *(uint16_t*)(nt + 6);
    uint16_t opt_sz = *(uint16_t*)(nt + 20);
    recomp_sechdr_t* sec = (recomp_sechdr_t*)(nt + 24 + opt_sz);

    uint32_t max_end = 0;
    for (int i = 0; i < nsec; i++) {
        uint32_t vs  = sec[i].vsize ? sec[i].vsize : sec[i].rsize;
        uint32_t end = sec[i].vaddr + vs;
        if (end > max_end) max_end = end;
    }
    uint32_t span = (max_end + 0xFFFu) & ~0xFFFu;

    void* view = VirtualAlloc((void*)(uintptr_t)image_base, span,
                              MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!view) {
        /* Already reserved for us -- a launcher that held the range through
         * loader init (see the MSVC-host case) leaves it reserved, and
         * MEM_RESERVE over an existing reservation fails. Commit into it. */
        view = VirtualAlloc((void*)(uintptr_t)image_base, span,
                            MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }
    if (!view) {
        fprintf(stderr, "[loader] VirtualAlloc fixed @ 0x%08X failed (link host at a high base)\n",
                image_base);
        free(buf);
        return 0;
    }
    memset(view, 0, span);  /* zeroes .bss */

    for (int i = 0; i < nsec; i++) {
        if (sec[i].rsize == 0) continue;  /* uninitialized (.bss) */
        uint32_t va = image_base + sec[i].vaddr;
        uint32_t n  = sec[i].rsize;
        if (sec[i].vsize && sec[i].vsize < n) n = sec[i].vsize;
        memcpy((void*)(uintptr_t)va, buf + sec[i].roff, n);
    }
    free(buf);
    return span;
}

/*
 * pe_loader_selftest.c - builds a minimal but real PE32 in memory (one section,
 * two KERNEL32 imports, one HIGHLOW base relocation), writes it to a temp file,
 * then maps / binds / relocates it and checks each step. Proves the loader with
 * no game binary. Build -m32 -no-pie so the image's ImageBase (0x00400000) is
 * free to map fixed.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pe_format.h"
#include "pe_loader.h"
#include "win32hle.h"

/* No guest is run here, but host_lite's recomp_lookup references the dispatch
 * table the lifted program would define; an empty one satisfies the link. */
const recomp_dispatch_entry_t recomp_dispatch_table[] = { { 0, 0 } };
const uint32_t recomp_dispatch_count = 0;

static int fails;
static void ok(const char *w, int c) { if (!c) { printf("FAIL %s\n", w); fails++; } }

#define IMAGE_BASE 0x00400000u
#define SEC_RVA    0x1000u
#define SEC_FOFF   0x200u
#define FILE_SZ    0x400u

/* RVAs laid out inside the one section (offset = RVA - SEC_RVA). */
#define RVA_MARKER   0x1000u   /* a known dword, to prove the section mapped   */
#define RVA_RELTGT   0x1004u   /* an absolute VA, target of the base reloc     */
#define RVA_IMPDESC  0x1010u   /* import descriptors (one + null)              */
#define RVA_ILT      0x1040u   /* import name table                            */
#define RVA_IAT      0x1050u   /* import address table (bind writes here)      */
#define RVA_NAME0    0x1060u   /* hint+"GetTickCount"                          */
#define RVA_NAME1    0x1080u   /* hint+"HeapAlloc"                             */
#define RVA_DLLNAME  0x10A0u   /* "KERNEL32.dll"                               */
#define RVA_RELOC    0x1100u   /* base reloc block                             */

static void put32(uint8_t *sec, uint32_t rva, uint32_t v) { memcpy(sec + (rva - SEC_RVA), &v, 4); }
static void put16(uint8_t *sec, uint32_t rva, uint16_t v) { memcpy(sec + (rva - SEC_RVA), &v, 2); }
static void puts_(uint8_t *sec, uint32_t rva, const char *s) { strcpy((char *)sec + (rva - SEC_RVA), s); }

static void build_pe(const char *path) {
    uint8_t *img = (uint8_t *)calloc(1, FILE_SZ);

    pe_dos_header *dos = (pe_dos_header *)img;
    dos->e_magic = 0x5A4D;
    dos->e_lfanew = 0x40;

    pe_nt_headers32 *nt = (pe_nt_headers32 *)(img + 0x40);
    nt->Signature = 0x00004550;
    nt->FileHeader.Machine = 0x14C;                 /* i386 */
    nt->FileHeader.NumberOfSections = 1;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(pe_opt_header32);
    pe_opt_header32 *opt = &nt->OptionalHeader;
    opt->Magic = 0x10B;
    opt->AddressOfEntryPoint = SEC_RVA;             /* pretend code starts here */
    opt->ImageBase = IMAGE_BASE;
    opt->SectionAlignment = 0x1000;
    opt->FileAlignment = 0x200;
    opt->SizeOfImage = 0x2000;                      /* headers page + one section page */
    opt->SizeOfHeaders = SEC_FOFF;
    opt->NumberOfRvaAndSizes = 16;
    opt->DataDirectory[PE_DIR_IMPORT].VirtualAddress = RVA_IMPDESC;
    opt->DataDirectory[PE_DIR_IMPORT].Size = 2 * sizeof(pe_import_descriptor);
    opt->DataDirectory[PE_DIR_BASERELOC].VirtualAddress = RVA_RELOC;
    opt->DataDirectory[PE_DIR_BASERELOC].Size = 10;

    pe_section_header *sh = (pe_section_header *)(img + 0x40 + sizeof(pe_nt_headers32));
    memcpy(sh->Name, ".data", 5);
    sh->VirtualSize = 0x200;
    sh->VirtualAddress = SEC_RVA;
    sh->SizeOfRawData = 0x200;
    sh->PointerToRawData = SEC_FOFF;
    sh->Characteristics = 0xC0000040u;              /* initialised data, r/w */

    uint8_t *sec = img + SEC_FOFF;                  /* section raw data */
    put32(sec, RVA_MARKER, 0xCAFEBABEu);
    put32(sec, RVA_RELTGT, 0x00401000u);            /* an in-image absolute VA */

    pe_import_descriptor *d = (pe_import_descriptor *)(sec + (RVA_IMPDESC - SEC_RVA));
    d[0].OriginalFirstThunk = RVA_ILT;
    d[0].Name = RVA_DLLNAME;
    d[0].FirstThunk = RVA_IAT;
    /* d[1] stays zero: the terminator */

    put32(sec, RVA_ILT + 0, RVA_NAME0);
    put32(sec, RVA_ILT + 4, RVA_NAME1);
    put32(sec, RVA_ILT + 8, 0);
    put32(sec, RVA_IAT + 0, RVA_NAME0);             /* loader overwrites [0],[1] */
    put32(sec, RVA_IAT + 4, RVA_NAME1);
    put32(sec, RVA_IAT + 8, 0);
    put16(sec, RVA_NAME0, 0); puts_(sec, RVA_NAME0 + 2, "GetTickCount");
    put16(sec, RVA_NAME1, 0); puts_(sec, RVA_NAME1 + 2, "HeapAlloc");
    puts_(sec, RVA_DLLNAME, "KERNEL32.dll");

    /* one HIGHLOW reloc for the dword at page+0x004 (== RVA_RELTGT) */
    put32(sec, RVA_RELOC + 0, SEC_RVA);             /* block VirtualAddress (page) */
    put32(sec, RVA_RELOC + 4, 10);                  /* SizeOfBlock = 8 + one entry */
    put16(sec, RVA_RELOC + 8, (uint16_t)((PE_REL_HIGHLOW << 12) | 0x004));

    FILE *f = fopen(path, "wb");
    fwrite(img, 1, FILE_SZ, f);
    fclose(f);
    free(img);
}

int main(void) {
    win32hle_register(win32hle_kernel32);           /* so hle_resolve answers */
    const char *path = "/tmp/win32hle_mini_pe.bin";
    build_pe(path);

    pe_image img;
    ok("recomp_pe_map succeeds", recomp_pe_map(path, &img) == 0);
    ok("mapped at ImageBase",    img.base == IMAGE_BASE);
    ok("entry point VA",         img.entry == IMAGE_BASE + SEC_RVA);
    ok("section data at its VA",  *(uint32_t *)(uintptr_t)(img.base + RVA_MARKER) == 0xCAFEBABEu);

    int unresolved = recomp_pe_bind(&img, hle_resolve);
    ok("all imports resolved",   unresolved == 0);
    uint32_t *iat = (uint32_t *)(uintptr_t)(img.base + RVA_IAT);
    ok("IAT[0] -> GetTickCount shim", iat[0] == hle_resolve("GetTickCount") && iat[0] != 0);
    ok("IAT[1] -> HeapAlloc shim",    iat[1] == hle_resolve("HeapAlloc")    && iat[1] != 0);

    /* relocate the image +0x100000 and confirm the HIGHLOW fixup moved the
     * absolute VA by exactly the delta. */
    uint32_t before = *(uint32_t *)(uintptr_t)(img.base + RVA_RELTGT);
    recomp_pe_relocate(img.base, RVA_RELOC, 10, 0x00100000);
    uint32_t after = *(uint32_t *)(uintptr_t)(img.base + RVA_RELTGT);
    ok("base reloc applied the delta", before == 0x00401000u && after == 0x00501000u);

    if (fails == 0) printf("pe_loader_selftest: all checks passed\n");
    return fails != 0;
}

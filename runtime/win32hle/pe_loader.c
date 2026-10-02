/*
 * pe_loader.c - see pe_loader.h. Maps a 32-bit PE with mmap and binds its IAT
 * to resolver-provided addresses. No windows.h: that is the point.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "pe_format.h"
#include "pe_loader.h"

#define PAGE 0x1000u
static uint32_t round_up(uint32_t v, uint32_t a) { return (v + a - 1) & ~(a - 1); }

/* Read a whole file into a malloc'd buffer; *len gets the size. NULL on error. */
static uint8_t *slurp(const char *path, size_t *len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return NULL; }
    uint8_t *buf = (uint8_t *)malloc((size_t)st.st_size);
    ssize_t n = buf ? read(fd, buf, (size_t)st.st_size) : -1;
    close(fd);
    if (n != (ssize_t)st.st_size) { free(buf); return NULL; }
    *len = (size_t)st.st_size;
    return buf;
}

void recomp_pe_relocate(uint32_t base, uint32_t reloc_rva, uint32_t reloc_size, int32_t delta) {
    if (!reloc_rva || !reloc_size || !delta) return;
    uint32_t off = 0;
    while (off < reloc_size) {
        pe_base_reloc *blk = (pe_base_reloc *)(uintptr_t)(base + reloc_rva + off);
        if (blk->SizeOfBlock < sizeof *blk) break;
        uint32_t nent = (blk->SizeOfBlock - (uint32_t)sizeof *blk) / 2;
        uint16_t *ent = (uint16_t *)(blk + 1);
        for (uint32_t i = 0; i < nent; i++) {
            uint32_t type = ent[i] >> 12, where = ent[i] & 0x0FFF;
            if (type == PE_REL_HIGHLOW)
                *(uint32_t *)(uintptr_t)(base + blk->VirtualAddress + where) += (uint32_t)delta;
            /* type 0 (ABSOLUTE) is padding; others are unused on x86 PE32 */
        }
        off += blk->SizeOfBlock;
    }
}

int recomp_pe_map(const char *path, pe_image *img) {
    size_t flen;
    uint8_t *file = slurp(path, &flen);
    if (!file) { fprintf(stderr, "[pe] cannot read %s\n", path); return 1; }

    pe_dos_header *dos = (pe_dos_header *)file;
    if (flen < sizeof *dos || dos->e_magic != 0x5A4D) { free(file); fprintf(stderr, "[pe] not MZ\n"); return 1; }
    if ((size_t)dos->e_lfanew + sizeof(pe_nt_headers32) > flen) { free(file); fprintf(stderr, "[pe] bad e_lfanew\n"); return 1; }
    pe_nt_headers32 *nt = (pe_nt_headers32 *)(file + dos->e_lfanew);
    if (nt->Signature != 0x00004550 || nt->OptionalHeader.Magic != 0x10B) {
        free(file); fprintf(stderr, "[pe] not a PE32\n"); return 1;
    }
    pe_opt_header32 *opt = &nt->OptionalHeader;
    uint32_t image_base = opt->ImageBase;
    uint32_t span = round_up(opt->SizeOfImage, PAGE);

    /* Reserve the image's VA range, fixed. On a 32-bit host the VA is a real
     * host address, so a 1:1 map means every MEM32(va) in lifted code lands. */
    void *p = mmap((void *)(uintptr_t)image_base, span, PROT_READ | PROT_WRITE,
                   MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { free(file); fprintf(stderr, "[pe] mmap @ 0x%08X failed\n", image_base); return 1; }
    uint32_t base = (uint32_t)(uintptr_t)p;

    /* headers, then each section's raw data (the rest of VirtualSize is the
     * zero MAP_ANONYMOUS already gave us, i.e. .bss). */
    memcpy((void *)(uintptr_t)base, file, opt->SizeOfHeaders);
    pe_section_header *sec = (pe_section_header *)((uint8_t *)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        uint32_t copy = sec[i].SizeOfRawData < sec[i].VirtualSize ? sec[i].SizeOfRawData : sec[i].VirtualSize;
        if (copy && (size_t)sec[i].PointerToRawData + copy <= flen)
            memcpy((void *)(uintptr_t)(base + sec[i].VirtualAddress), file + sec[i].PointerToRawData, copy);
    }

    if (base != image_base) {
        pe_data_dir r = opt->DataDirectory[PE_DIR_BASERELOC];
        recomp_pe_relocate(base, r.VirtualAddress, r.Size, (int32_t)(base - image_base));
    }

    img->base = base;
    img->image_base = image_base;
    img->span = span;
    img->entry = base + opt->AddressOfEntryPoint;
    img->import_rva = opt->DataDirectory[PE_DIR_IMPORT].VirtualAddress;
    free(file);
    fprintf(stderr, "[pe] %s mapped at 0x%08X, span 0x%X\n", path, base, span);
    return 0;
}

int recomp_pe_bind(const pe_image *img, uint32_t (*resolve)(const char *name)) {
    if (!img->import_rva) return 0;
    uint32_t base = img->base;
    int unresolved = 0, bound = 0;
    pe_import_descriptor *d = (pe_import_descriptor *)(uintptr_t)(base + img->import_rva);
    for (; d->Name; d++) {
        const char *dll = (const char *)(uintptr_t)(base + d->Name);
        uint32_t *ilt = (uint32_t *)(uintptr_t)(base + (d->OriginalFirstThunk ? d->OriginalFirstThunk : d->FirstThunk));
        uint32_t *iat = (uint32_t *)(uintptr_t)(base + d->FirstThunk);
        for (; *ilt; ilt++, iat++) {
            uint32_t va = 0;
            if (*ilt & PE_ORDINAL_FLAG) {
                /* by ordinal: win32hle keys shims by name, so leave it for the
                 * resolver to answer by "DLL#N" if it chooses. */
                va = 0;
            } else {
                const char *name = (const char *)(uintptr_t)(base + *ilt + 2); /* skip hint word */
                va = resolve(name);
                if (!va) fprintf(stderr, "[pe] unresolved import %s!%s\n", dll, name);
            }
            if (va) bound++; else unresolved++;
            *iat = va;
        }
    }
    fprintf(stderr, "[pe] bound %d imports, %d unresolved\n", bound, unresolved);
    return unresolved;
}

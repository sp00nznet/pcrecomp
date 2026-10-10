/*
 * pe_loader.h - map a 32-bit PE at its VAs and bind its imports to win32hle
 * shims, on Linux. The portable counterpart of what native32 did with the
 * Windows loader + windows.h. See pe_format.h for the structures.
 */
#ifndef PE_LOADER_H
#define PE_LOADER_H
#include <stdint.h>

typedef struct {
    uint32_t base;        /* where the image is mapped (== image_base on success) */
    uint32_t image_base;  /* the PE's preferred ImageBase */
    uint32_t span;        /* SizeOfImage, page-rounded */
    uint32_t entry;       /* entry point VA (base + AddressOfEntryPoint) */
    uint32_t import_rva;  /* import directory RVA (0 if none) */
    uint32_t resource_rva, resource_size;  /* resource directory (0 if none) */
    uint32_t stamp;       /* FileHeader.TimeDateStamp: which build this is */
} pe_image;

/* Map `path` at its preferred ImageBase (MAP_FIXED): sections to their VAs,
 * .bss zero-filled, relocations applied if the base ended up different. Returns
 * 0 and fills *img on success, nonzero on failure (prints why). */
int recomp_pe_map(const char *path, pe_image *img);

/* Map `path` wherever there is room and relocate it there: a DLL. */
int recomp_pe_map_any(const char *path, pe_image *img);

/* Walk the import directory and write each IAT slot's resolved address, using
 * resolve(name) (hle_resolve for win32hle). Returns the count left unresolved. */
int recomp_pe_bind(const pe_image *img, uint32_t (*resolve)(const char *name));

/* Apply HIGHLOW base relocations for `delta` over the reloc directory at
 * base+reloc_rva (reloc_size bytes). Used by the loader when the base differs,
 * and exposed on its own so it can be tested directly. */
void recomp_pe_relocate(uint32_t base, uint32_t reloc_rva, uint32_t reloc_size, int32_t delta);

#endif /* PE_LOADER_H */

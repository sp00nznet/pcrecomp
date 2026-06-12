/*
 * image_loader.h - generic PE image loader for the recomp32 runtime.
 *
 * Maps an original 32-bit PE's sections into the host process at their real VAs,
 * so the recompiled code's MEM*(va) accessors read the program's actual initial
 * data. Parses the section table at runtime, so there are no hand-copied,
 * per-binary file offsets to maintain (unlike the original XWA main.c).
 *
 * The host executable MUST be linked at a high image base (e.g. 0x70000000, via
 * `-Wl,--image-base,0x70000000`) so the target's VA range is free and the mapping
 * is 1:1 (g_mem_base stays 0). On a 64-bit host, pointers are formed through
 * (uintptr_t) casts, so a fixed 32-bit VA mapping is fine.
 *
 * Part of the pcrecomp toolbox.
 */
#ifndef RECOMP_IMAGE_LOADER_H
#define RECOMP_IMAGE_LOADER_H

#include <stdint.h>

/*
 * Load `path` (the original PE) and map it at `image_base`.
 * Returns the page-rounded image span in bytes on success, 0 on failure.
 * On success the whole image is readable/writable at its VA and .bss is zeroed.
 */
uint32_t recomp_load_image(const char* path, uint32_t image_base);

#endif /* RECOMP_IMAGE_LOADER_H */

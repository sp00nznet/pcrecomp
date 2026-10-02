/*
 * host.c - the full win32hle host driver. See host.h. Maps a PE, binds its IAT
 * to the shims, and runs its entry point as lifted code. Portable C: no asm, no
 * OS exception handler (win32hle.h explains why neither is needed).
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include "win32hle.h"
#include "pe_loader.h"
#include "host.h"

static pe_image g_img;
static int      g_booted;

void recomp_host_init(void) {
    win32hle_register(win32hle_kernel32);
    win32hle_register(win32hle_kernel32_ext);
    win32hle_register(win32hle_gdi32);
    win32hle_register(win32hle_user32);
}

int recomp_host_boot(const char *path) {
    if (recomp_pe_map(path, &g_img) != 0) return 1;
    int unresolved = recomp_pe_bind(&g_img, hle_resolve);
    g_booted = 1;
    fprintf(stderr, "[host] %s booted: entry 0x%08X, %d unresolved imports\n",
            path, g_img.entry, unresolved);
    return unresolved ? 2 : 0;
}

uint32_t recomp_host_entry(void) { return g_booted ? g_img.entry : 0; }

uint32_t recomp_host_run(void) {
    if (!g_booted) { hle_fatal("recomp_host_run before boot"); }
    /* The CRT entry takes no arguments; it reads the command line itself
     * (GetCommandLineA). Run it on this thread's guest stack. */
    uint32_t args[1];
    return hle_call_guest(g_img.entry, 0, args);
}

int recomp_host_main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <image.exe> [args...]\n", argv[0]); return 64; }
    recomp_host_init();
    int rc = recomp_host_boot(argv[1]);
    if (rc) return rc;
    return (int)recomp_host_run();
}

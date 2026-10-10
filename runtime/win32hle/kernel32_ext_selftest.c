/*
 * kernel32_ext_selftest.c - drives the file-I/O, Global*, and .ini shims from a
 * synthetic lifted guest: write a file and read it back, round-trip a Global
 * block, and write then read an .ini key. Headless, no game. Build -m32.
 */
#define RECOMP_GENERATED_CODE
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "win32hle.h"

#define ENTRY_VA 0x00401000u
#define GENERIC_WRITE 0x40000000u
#define GENERIC_READ  0x80000000u
#define CREATE_ALWAYS 2u
#define OPEN_EXISTING 3u

static int fails;
static void ok(const char *w, int c) { if (!c) { printf("FAIL %s\n", w); fails++; } }
#define GUEST_PROLOGUE(va) \
    uint32_t _cf = 0; uint32_t _flag_k = FK_NONE; uint32_t _flag_a = 0, _flag_b = 0; RECOMP_ENTER(va)

static uint32_t V_Create, V_Read, V_Write, V_Close, V_GAlloc, V_GLock, V_GFree,
                V_WriteIni, V_GetIni;

/* scratch guest memory */
static char     g_path[]  = "/tmp/win32hle_k32ext.dat";
static char     g_ini[]   = "/tmp/win32hle_k32ext.ini";
static char     g_sec[]   = "video";
static char     g_key[]   = "width";
static char     g_val[]   = "1024";
static uint8_t  g_payload[16] = { 1,2,3,4,5,6,7,8, 9,10,11,12,13,14,15,16 };
static uint8_t  g_readbuf[16];
static char     g_inibuf[64];
static uint32_t g_io;     /* bytes read/written out-param */

static int mem_eq;
static uint32_t g_global_ptr;
static int ini_ok;

static void guest(void) {
    GUEST_PROLOGUE(ENTRY_VA);

    /* h = CreateFileA(path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0) */
    PUSH32(esp, 0); PUSH32(esp, 0); PUSH32(esp, CREATE_ALWAYS); PUSH32(esp, 0);
    PUSH32(esp, 0); PUSH32(esp, GENERIC_WRITE); PUSH32(esp, (uint32_t)(uintptr_t)g_path);
    RECOMP_ICALL(V_Create);
    uint32_t h = eax;
    /* WriteFile(h, payload, 16, &io, 0) */
    PUSH32(esp, 0); PUSH32(esp, (uint32_t)(uintptr_t)&g_io); PUSH32(esp, 16);
    PUSH32(esp, (uint32_t)(uintptr_t)g_payload); PUSH32(esp, h);
    RECOMP_ICALL(V_Write);
    PUSH32(esp, h); RECOMP_ICALL(V_Close);

    /* h = CreateFileA(path, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0); ReadFile */
    PUSH32(esp, 0); PUSH32(esp, 0); PUSH32(esp, OPEN_EXISTING); PUSH32(esp, 0);
    PUSH32(esp, 0); PUSH32(esp, GENERIC_READ); PUSH32(esp, (uint32_t)(uintptr_t)g_path);
    RECOMP_ICALL(V_Create);
    h = eax;
    PUSH32(esp, 0); PUSH32(esp, (uint32_t)(uintptr_t)&g_io); PUSH32(esp, 16);
    PUSH32(esp, (uint32_t)(uintptr_t)g_readbuf); PUSH32(esp, h);
    RECOMP_ICALL(V_Read);
    PUSH32(esp, h); RECOMP_ICALL(V_Close);
    mem_eq = (g_io == 16) && memcmp(g_payload, g_readbuf, 16) == 0;

    /* p = GlobalAlloc(GMEM_ZEROINIT, 32); GlobalLock(p); write; GlobalFree */
    PUSH32(esp, 32); PUSH32(esp, 0x40); RECOMP_ICALL(V_GAlloc);
    uint32_t p = eax;
    PUSH32(esp, p); RECOMP_ICALL(V_GLock);
    uint32_t locked = eax;
    MEM32(locked) = 0xABCD1234u;
    g_global_ptr = (p && locked == p && MEM32(p) == 0xABCD1234u);
    PUSH32(esp, p); RECOMP_ICALL(V_GFree);

    /* WritePrivateProfileStringA(sec,key,val,ini); GetPrivateProfileStringA back */
    PUSH32(esp, (uint32_t)(uintptr_t)g_ini); PUSH32(esp, (uint32_t)(uintptr_t)g_val);
    PUSH32(esp, (uint32_t)(uintptr_t)g_key); PUSH32(esp, (uint32_t)(uintptr_t)g_sec);
    RECOMP_ICALL(V_WriteIni);
    PUSH32(esp, (uint32_t)(uintptr_t)g_ini); PUSH32(esp, 64);
    PUSH32(esp, (uint32_t)(uintptr_t)g_inibuf); PUSH32(esp, 0 /*default*/);
    PUSH32(esp, (uint32_t)(uintptr_t)g_key); PUSH32(esp, (uint32_t)(uintptr_t)g_sec);
    RECOMP_ICALL(V_GetIni);
    ini_ok = strcmp(g_inibuf, "1024") == 0;

    eax = 0;
}

const recomp_dispatch_entry_t recomp_dispatch_table[] = { { ENTRY_VA, guest } };
const uint32_t recomp_dispatch_count = 1;

int main(void) {
    remove(g_ini);   /* the append-writer starts clean */
    win32hle_register(win32hle_kernel32);
    win32hle_register(win32hle_kernel32_ext);
    V_Create   = hle_resolve("CreateFileA");
    V_Read     = hle_resolve("ReadFile");
    V_Write    = hle_resolve("WriteFile");
    V_Close    = hle_resolve("CloseHandle");
    V_GAlloc   = hle_resolve("GlobalAlloc");
    V_GLock    = hle_resolve("GlobalLock");
    V_GFree    = hle_resolve("GlobalFree");
    V_WriteIni = hle_resolve("WritePrivateProfileStringA");
    V_GetIni   = hle_resolve("GetPrivateProfileStringA");
    ok("all kernel32_ext shims resolve",
       V_Create && V_Read && V_Write && V_Close && V_GAlloc && V_GLock && V_GFree && V_WriteIni && V_GetIni);

    mach_enter();
    guest();
    mach_leave();

    ok("file write then read round-trips", mem_eq);
    ok("GlobalAlloc/Lock write-through",    g_global_ptr);
    ok(".ini write then read round-trips",  ini_ok);

    /* A mod's overlay: its file read instead of the game's, the game's where
     * it has none, writes into the overlay (the game's file copied first when
     * kept), and the game's files untouched. */
    {
        char p[1024], q[1024];
        FILE *f;
        system("rm -rf /tmp/hleov && mkdir -p /tmp/hleov/game/maps /tmp/hleov/mod");
        f = fopen("/tmp/hleov/game/rules.ini", "w"); fputs("base", f); fclose(f);
        f = fopen("/tmp/hleov/game/maps/a.map", "w"); fputs("map", f); fclose(f);
        f = fopen("/tmp/hleov/mod/RULES.INI", "w"); fputs("mod", f); fclose(f);
        hle_set_drive('C', "/tmp/hleov/game");
        hle_set_overlay("/tmp/hleov/game", "/tmp/hleov/mod");
        ok("overlay: the mod's file is read", hle_host_path("C:\\rules.ini", p, sizeof p) && strstr(p, "/mod/RULES.INI"));
        ok("overlay: the game's where the mod has none", hle_host_path("C:\\maps\\a.map", p, sizeof p) && strstr(p, "/game/maps/a.map"));
        hle_host_path_for_write("C:\\saves\\one.sav", p, sizeof p, 0);
        ok("overlay: a new file goes to the mod, its directory made", !strcmp(p, "/tmp/hleov/mod/saves/one.sav") &&
           access("/tmp/hleov/mod/saves", F_OK) == 0);
        hle_host_path_for_write("C:\\maps\\a.map", p, sizeof p, 1);
        f = fopen(p, "r");
        ok("overlay: a kept file is copied into the mod first", f && fgets(q, sizeof q, f) && !strcmp(q, "map") &&
           strstr(p, "/mod/maps/a.map"));
        if (f) fclose(f);
        ok("overlay: the game's files untouched", access("/tmp/hleov/game/saves", F_OK) != 0);
        ok("overlay: a directory stays the game's (the cwd)", hle_host_path("C:\\", p, sizeof p) && !strcmp(p, "/tmp/hleov/game"));
        chdir("/tmp/hleov/game");
        ok("overlay: a name relative to the game's folder", hle_host_path("rules.ini", p, sizeof p) && strstr(p, "/mod/RULES.INI"));
        hle_set_overlay(NULL, NULL);
        ok("overlay off: the game's file again", hle_host_path("C:\\rules.ini", p, sizeof p) && strstr(p, "/game/rules.ini"));
    }

    if (fails == 0) printf("kernel32_ext_selftest: all checks passed\n");
    return fails != 0;
}

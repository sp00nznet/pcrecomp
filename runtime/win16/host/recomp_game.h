/* recomp_game.h - what the Win16 host runtime needs to know about ONE game.
 *
 * The runtime in this directory is generic Win16-on-Win32. A handful of things
 * are not: where the game believes it is installed, which INI files it reads
 * without naming a directory, which resource holds the palette its art was
 * drawn against, and what licence data the user has to supply. Each game repo
 * defines exactly one of these:
 *
 *     const RecompGame recomp_game = { .title = "Catz", ... };
 *
 * Everything else a game needs (a patch to its own lifted code, say) stays in
 * the game repo; this struct is only for values the shared shims consume.
 */
#ifndef RECOMP_GAME_H
#define RECOMP_GAME_H
#include <stdint.h>

typedef struct {
    const char *title;            /* log prefix and window-class fallback, e.g. "Catz" */
    const char *guest_dir;        /* install dir the guest believes in, e.g. "C:\\CATZ" */

    /* INIs the game opens by bare name before/without a path; served from
     * RECOMP_DATA_DIR. The first match wins. NULL-terminated. */
    const char *ini_fallbacks[6];

    /* A directory name the game builds absolute paths to, e.g. "ptzfiles" for
     * "C:\CATZ\ptzfiles\cat\...": everything from it on is taken
     * relative to RECOMP_DATA_DIR, whether or not the file exists yet (so a
     * save can be created). NULL: only the longest existing tail is used. */
    const char *path_anchor;

    /* INI values to stand in when the game's own files have none: a save from
     * an older version, say, predating a key the engine now requires. Pairs of
     * key, value; NULL-terminated. */
    const char *ini_defaults[8];

    /* A resource of (palette_type, palette_id) holding 256 RGB triples is
     * served as the system palette: on a real 256-colour Windows 3.1 the system
     * palette already held the game's colours when it started, and its art is
     * authored against them. 0 = use the synthetic default palette. */
    uint16_t palette_type, palette_id;

    /* PF Magic's engines (Dogz, Catz, Oddballz) ask FindResource by a 4-char
     * tag ("PALT", "STBL") and embed [tag][00 00][0C 00][type][id] records that
     * say which integer type the tag means. Non-zero: scan every module for
     * them. See ne_resources.c. */
    int resource_tags;

    /* When a LoadString/FindResource misses in the module it names, search the
     * other lifted modules too. Catz's engine passes the EXE's handle for
     * strings that live in its DLL; Windows would fail those. 0 = Windows. */
    int resource_fallback;

    /* Licence data the game reads from an INI and this project does not ship.
     * When the read comes back empty, serial_help is printed once. NULL = none. */
    const char *serial_key;
    const char *serial_help;

    /* The game has real child windows and asks about them. Non-zero:
     * GetClientRect/GetWindowRect report each window's own geometry, and
     * ClientToScreen/WindowFromPoint work on a virtual screen whose origin is
     * the main window's client area (where GetCursorPos already measures from).
     * 0, the PF Magic model: one window is the whole 640x480 screen, every
     * client rect is that screen and ClientToScreen is the identity. SimAnt: 1. */
    int real_windows;

    /* GetProcAddress into a module that was NOT lifted (a DLL the game loads at
     * run time by path, say). Fill a guest far pointer -- usually one from
     * recomp_host_thunk() -- and return 1, or return 0 to report no such
     * export. NULL: every such lookup fails. */
    int (*proc_address)(uint16_t hinst, const char *name, int ordinal,
                        uint16_t *seg, uint16_t *off);
} RecompGame;

struct CPU;
/* A native function the guest can call through a far pointer. The returned
 * value is seg<<16|off in a segment no lifted code occupies; dispatch_far runs
 * fn(cpu, arg) when the guest calls it. fn owns the return: pop the 4-byte far
 * return frame plus its PASCAL arguments, and leave results in AX / DX:AX.
 * 0 when the table is full. */
uint32_t recomp_host_thunk(void (*fn)(struct CPU *cpu, uint16_t arg), uint16_t arg);

extern const RecompGame recomp_game;

/* Module lookups over RECOMP_MODULES[] (mem_layout.h), defined in main.c. */
#include "mem_layout.h"
uint16_t recomp_dgroup_of_seg(uint16_t seg);
const RecompModule *recomp_module_of_hinst(uint16_t hinst);

/* A lifted module's hInstance is its DGROUP selector, and for the first few
 * modules that is a small number. Win16 reads any LoadLibrary result below 32
 * as an error code, so Oddballz (intro DLL: DGROUP 4) decided the load had
 * failed and threw. LoadLibrary hands out 0xE000|sel for those instead, and
 * every handle lookup folds it back. */
static inline uint16_t recomp_hinst_alias(uint16_t h)   { return h < 32 ? (uint16_t)(0xE000 | h) : h; }
static inline uint16_t recomp_hinst_unalias(uint16_t h) { return (h & 0xFFE0) == 0xE000 ? (uint16_t)(h & 0x1F) : h; }

#endif

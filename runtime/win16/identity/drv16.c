/* drv16.c - the Win16 drivers KRNL386's own LoadModule loads (SYSTEM.DRV,
 * KEYBOARD.DRV, MOUSE.DRV, DISPLAY.DRV), as stand-ins this file writes at
 * run time into the guest's WINDOWS\SYSTEM. Each is a small NE of our own:
 * one code segment whose bytes are a tag ("PCRD", the driver's index) and a
 * `retf` per entry; no Microsoft bytes. KRNL386 loads it like any library
 * (header, segment, entry table, its LibEntry), and a far call into the
 * segment (dispatch_far: no lifted function there) lands in drv_far, which
 * runs the entry's host function by ordinal. An entry with no host function
 * stops the run with its driver and ordinal. Nothing touches hardware. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "cpu.h"

uint32_t recomp_sel_base(uint32_t selector);
void w16_drv_stop(const char *what, unsigned a, unsigned b);

#define E_LIBENTRY 0x08     /* the NE's cs:ip */
#define E_FIRST    0x10     /* entry n (ordinal) at E_FIRST + 2 * (n - 1) */
#define NORD       140      /* ordinals 1..NORD exported (KEYBOARD goes to 136) */

typedef void (*drv_fn)(CPU *c);
typedef struct { const char *name; drv_fn fn[NORD + 1]; } drv_t;

static uint16_t arg16(CPU *c, int i) { return mem_read16(c, c->ss, (uint16_t)(c->sp + 4 + 2 * i)); }
static void ret_far(CPU *c, int argbytes) { c->sp = (uint16_t)(c->sp + 4 + argbytes); }
static void libentry(CPU *c) { c->ax = 1; ret_far(c, 0); }   /* LibEntry: success, nothing to set up */

static uint32_t argfar(CPU *c, int i) { return (uint32_t)arg16(c, i + 1) << 16 | arg16(c, i); }
static char *farptr(uint32_t p) { return (char *)(uintptr_t)(recomp_sel_base(p >> 16) + (p & 0xFFFF)); }

/* Code-page conversion between the guest's ANSI (1252) and OEM (437) sets: Win98 SE US.
 * ponytail: both fixed; read them off system.ini [boot.description]/the keyboard's tables if another locale turns up. */
static void cp_convert(const char *src, char *dst, int n, UINT from, UINT to) {
    WCHAR w[1024];
    while (n > 0) {
        int k = n > 1024 ? 1024 : n;
        MultiByteToWideChar(from, 0, src, k, w, k);
        WideCharToMultiByte(to, 0, w, k, dst, k, NULL, NULL);
        src += k; dst += k; n -= k;
    }
}
/* KEYBOARD.5 AnsiToOem(LPCSTR src, LPSTR dst) / .6 OemToAnsi: KRNL386 seg1 A5C2 (OpenFile's path)
 * calls them through DGROUP:1250 once the keyboard is loaded; pascal, TRUE back. */
static void kb_xlat(CPU *c, UINT from, UINT to) {
    char *dst = farptr(argfar(c, 0)), *src = farptr(argfar(c, 2));
    cp_convert(src, dst, (int)strlen(src) + 1, from, to);
    c->ax = 0xFFFF; ret_far(c, 8);
}
static void kb_ansi_to_oem(CPU *c) { kb_xlat(c, 1252, 437); }
static void kb_oem_to_ansi(CPU *c) { kb_xlat(c, 437, 1252); }

static drv_t g_drv[] = {
    { "SYSTEM",   { 0 } },
    { "KEYBOARD", { [5] = kb_ansi_to_oem, [6] = kb_oem_to_ansi } },
    { "MOUSE",    { 0 } },
    { "DISPLAY",  { 0 } },
    { "MMSOUND",  { 0 } },   /* SlowBoot: sound.drv= default; makes no sound */
    { "COMM",     { 0 } },   /* comm.drv=: no ports */
};
#define NDRV (int)(sizeof g_drv / sizeof *g_drv)

/* ---- the NE file ---- */
static uint8_t g_ne[0x800];
static size_t ne_build(int idx) {
    const char *name = g_drv[idx].name;
    uint8_t *f = g_ne;
    memset(f, 0, sizeof g_ne);
    f[0] = 'M'; f[1] = 'Z'; *(uint16_t *)(f + 2) = 0x40; *(uint16_t *)(f + 4) = 1; *(uint16_t *)(f + 8) = 4;
    *(uint16_t *)(f + 0x18) = 0x40; *(uint32_t *)(f + 0x3C) = 0x40;
    uint8_t *ne = f + 0x40, *p = ne + 0x40;
    ne[0] = 'N'; ne[1] = 'E'; ne[2] = 5; ne[3] = 10;
    *(uint16_t *)(ne + 0x0C) = 0x8000;            /* library, no automatic data segment */
    *(uint16_t *)(ne + 0x14) = E_LIBENTRY; *(uint16_t *)(ne + 0x16) = 1;   /* cs:ip = 1:LibEntry */
    *(uint16_t *)(ne + 0x1C) = 1;                 /* one segment */
    *(uint16_t *)(ne + 0x32) = 4;                 /* alignment shift: 16-byte sectors */
    ne[0x36] = 2;                                 /* Windows */
    *(uint16_t *)(ne + 0x3E) = 0x030A;
    /* segment table */
    *(uint16_t *)(ne + 0x22) = (uint16_t)(p - ne);
    uint8_t *seg = p; p += 8;
    /* resource table: none (offset = resident names) */
    *(uint16_t *)(ne + 0x24) = (uint16_t)(p - ne);
    *(uint16_t *)(ne + 0x26) = (uint16_t)(p - ne);
    size_t n = strlen(name);
    *p++ = (uint8_t)n; memcpy(p, name, n); p += n; *p++ = 0; *p++ = 0;   /* module name, ordinal 0 */
    *p++ = 0;
    *(uint16_t *)(ne + 0x28) = (uint16_t)(p - ne);   /* module references: none */
    *(uint16_t *)(ne + 0x2A) = (uint16_t)(p - ne);   /* imported names: one empty byte */
    *p++ = 0;
    /* entry table: one bundle of NORD fixed entries in segment 1, exported */
    *(uint16_t *)(ne + 0x04) = (uint16_t)(p - ne);
    uint8_t *et = p;
    *p++ = NORD; *p++ = 1;
    for (int i = 0; i < NORD; i++) { *p++ = 1; *(uint16_t *)p = (uint16_t)(E_FIRST + 2 * i); p += 2; }
    *p++ = 0;
    *(uint16_t *)(ne + 0x06) = (uint16_t)(p - et);
    /* nonresident names: the description */
    static const char desc[] = "pcrecomp host driver";
    *(uint32_t *)(ne + 0x2C) = (uint32_t)(p - f);
    uint8_t *nr = p;
    *p++ = sizeof desc - 1; memcpy(p, desc, sizeof desc - 1); p += sizeof desc - 1; *p++ = 0; *p++ = 0;
    *p++ = 0;
    *(uint16_t *)(ne + 0x20) = (uint16_t)(p - nr);
    /* the code segment, on a sector boundary */
    size_t at = ((size_t)(p - f) + 15) & ~(size_t)15;
    uint8_t *cs = f + at;
    uint16_t len = E_FIRST + 2 * NORD;
    memcpy(cs, "PCRD", 4); cs[4] = (uint8_t)idx;
    cs[E_LIBENTRY] = 0xCB;                        /* retf: never run, drv_far answers */
    for (int i = 0; i < NORD; i++) cs[E_FIRST + 2 * i] = 0xCB;
    *(uint16_t *)(seg + 0) = (uint16_t)(at >> 4);
    *(uint16_t *)(seg + 2) = len;
    *(uint16_t *)(seg + 4) = 0x0070;              /* code: moveable, pure, preload */
    *(uint16_t *)(seg + 6) = len;
    return at + len;
}

/* Write each stand-in to <sysdir>\<NAME>.DRV (the guest's own tree). */
void w16_drv_write(const char *sysdir) {
    for (int i = 0; i < NDRV; i++) {
        char path[512];
        snprintf(path, sizeof path, "%s\\%s.DRV", sysdir, g_drv[i].name);
        size_t n = ne_build(i);
        FILE *f = fopen(path, "wb");
        if (!f) { fprintf(stderr, "[drv] cannot write %s\n", path); continue; }
        fwrite(g_ne, 1, n, f);
        fclose(f);
    }
}

/* A far call into a segment that holds no lifted code: ours if tagged. */
int w16_drv_far(CPU *c, uint16_t sel, uint16_t off) {
    const uint8_t *b = (const uint8_t *)(uintptr_t)recomp_sel_base(sel);
    if (!(sel & 4) || !b || memcmp(b, "PCRD", 4) || b[4] >= NDRV) return 0;
    drv_t *d = &g_drv[b[4]];
    if (getenv("W16_TRACE")) fprintf(stderr, "[drv] %s %04X:%04X\n", d->name, sel, off);
    if (off == E_LIBENTRY) { libentry(c); return 1; }
    unsigned ord = off >= E_FIRST ? (off - E_FIRST) / 2u + 1 : 0;
    if (!ord || ord > NORD || (off - E_FIRST) % 2) w16_drv_stop("driver offset with no entry, idx:off", b[4], off);
    if (!d->fn[ord]) { fprintf(stderr, "\n[drv] %s.%u has no host function\n", d->name, ord); w16_drv_stop("driver entry not named yet, idx:ordinal", b[4], ord); }
    d->fn[ord](c);
    return 1;
}

/* identity.c - the Win16 runtime's glue for identity mode (RECOMP_W16_IDENTITY):
 * lifted 16-bit modules (ne_link with NE_IDENTITY_SEL=1) living in the same
 * flat address space as lifted 32-bit code, in a 32-bit native32 host.
 *
 * cpu->mem is 0, so a flat address is the host address; selectors are LDT
 * entries of native32 (vxd32.c's g_ldt), segment n's selector is (n<<3)|7.
 * This file supplies what runtime/win16/host/main.c supplies for a normal
 * Win16 host (dispatch, the trace ring, fatal stops), plus the bridge from
 * lifted 32-bit code into lifted 16-bit code:
 *
 *   w16_enter(target): native32's o16 `retf` (recomp_retf32, Win9x
 *   QT_Thunk) to a 16:16 target in a lifted code selector. The 32-bit
 *   registers are copied in, ss:sp is the 32-bit stack's 16-bit alias, the
 *   lifted function runs (its `retf N` pops the 16:16 return and the
 *   arguments), and the 32-bit side continues where that return's stub
 *   would have jumped (a 16-bit `jmp far 32:off`, 66 EA off32 sel16).
 *
 * Win16 code runs under the Win16Mutex, so one CPU serves every thread;
 * a 16 -> 32 -> 16 nesting saves and restores it around the inner call. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <setjmp.h>
#include "cpu.h"
#include "mem_layout.h"   /* RECOMP_NUM_SEG */
#define W16_PSP_PARA 0x1000   /* where the host puts KRNL386's PSP (w16test.c) */

int recomp_dispatch_lookup(CPU *cpu, uint16_t seg, uint16_t off);

/* the trace ring main.c keeps; only written here */
const char *g_fn_ring[RECOMP_FN_RING_SIZE];
unsigned g_fn_ring_pos;
int g_fncount, g_watch_ds;
uint16_t g_wsel;
/* per thread: kernel32's 16->32 dispatcher leaves the Win16Mutex, so another
 * guest thread can run 16-bit code while this one is inside a thunk */
static __declspec(thread) CPU g_w16;
void recomp_fn_hit(const char *n) {   /* g_fncount: W16_FN=1 (with fs when it changes) */
    static uint16_t fs;
    static int sp = -1;
    if (sp < 0) { const char *e = getenv("W16_FN"); sp = e && *e == '2'; }
    if (g_watch_ds) {   /* W16_WSEL=sel: say which function first sees sel's LDT descriptor change */
        extern uint8_t* native32_w9x_desc(uint16_t);
        static uint32_t last[2];
        uint32_t *d = (uint32_t*)native32_w9x_desc(g_wsel);
        if (d[0] != last[0] || d[1] != last[1]) { last[0] = d[0]; last[1] = d[1]; fprintf(stderr, "WATCH %04X = %08X %08X at %s\n", g_wsel, d[0], d[1], n); }
        if (!g_fncount) return;
    }
    {   /* W16_WW=ss:off: say which function first sees that word change */
        static int ww = -1; static uint16_t wss, last;
        if (ww < 0) { const char *e = getenv("W16_WW"); char *t; wss = e ? (uint16_t)strtoul(e, &t, 16) : 0; ww = e && *t == ':' ? (int)strtoul(t + 1, 0, 16) : 0x10000; }
        if (ww < 0x10000 && g_w16.ss == wss) { uint16_t v = mem_read16(&g_w16, g_w16.ss, (uint16_t)ww); if (v != last) { last = v; fprintf(stderr, "WW ss:%04X = %04X at %s\n", ww, v, n); } }
    }
    if (sp) fprintf(stderr, "FN %s ss:sp %04X:%04X bp %04X\n", n, g_w16.ss, g_w16.sp, g_w16.bp);
    else if (g_w16.fs != fs) { fs = g_w16.fs; fprintf(stderr, "FN %s fs=%04X\n", n, fs); }
    else fprintf(stderr, "FN %s\n", n);
}
void recomp_sel_write(uint16_t seg, uint16_t off, uint16_t val) { (void)seg; (void)off; (void)val; }

/* native32's registers (recomp32/recomp_types.h) and Win9x segment state (vxd32.c) */
extern uint32_t g_eax, g_ecx, g_edx, g_ebx, g_esp, g_ebp, g_esi, g_edi;
extern uint32_t g_ss_base;
extern uint16_t g_seg_cs, g_seg_ss, g_seg_ds, g_seg_es, g_seg_fs, g_seg_gs;
extern uint32_t g_ds_base, g_es_base;

static void w16_stop(const char *what, unsigned a, unsigned b) {
    fprintf(stderr, "\n[w16] %s %04X:%04X; last functions:", what, a, b);
    for (int i = 8; i > 0; i--) {
        const char *n = g_fn_ring[(g_fn_ring_pos - (unsigned)i) & (RECOMP_FN_RING_SIZE - 1)];
        if (n) fprintf(stderr, " %s", n);
    }
    fprintf(stderr, "\n");
    fflush(stderr);
    { const char *h = getenv("W16_HOLD"); if (h) Sleep((DWORD)atoi(h) * 1000); }   /* the display window stays up for a screenshot */
    exit(5);
}

void w16_drv_stop(const char *what, unsigned a, unsigned b) { w16_stop(what, a, b); }
void w16_retpast(CPU *c, uint16_t ip, const char *fn) {
    if (getenv("W16_TRACE")) fprintf(stderr, "[w16] %s: returned past (pushed %04X, ret popped %04X, sp %04X)\n", fn, ip, c->ret_ip, c->sp);
}
void recomp_unreachable(const char *seg, unsigned off) { w16_stop("unlifted target", (unsigned)strtoul(seg, NULL, 10), off); }
void recomp_div0(const char *kind) { (void)kind; w16_stop("divide error", 0, 0); }

/* ---- 16-bit interrupts: what VMM/DPMI would answer ----
 * This directory is ne_link's --shims for identity mode, so the generated
 * int_handler (print and carry on) is not made. Every service answered here
 * is named; anything else stops with its registers. */
uint8_t *native32_w9x_desc(uint16_t sel);
uint16_t native32_w9x_alloc_sel(uint32_t base, uint32_t limit);
uint16_t native32_w9x_next_sel(void);
static void ok(CPU *c) { c->flags &= (uint16_t)~FLAG_CF; }
static uint32_t d_base(const uint8_t *d) { return d[2] | d[3] << 8 | d[4] << 16 | (uint32_t)d[7] << 24; }
static void d_set_base(uint8_t *d, uint32_t b) { d[2] = (uint8_t)b; d[3] = (uint8_t)(b >> 8); d[4] = (uint8_t)(b >> 16); d[7] = (uint8_t)(b >> 24); }

/* Real-mode memory: the first megabyte a DOS box would have, at host
 * linear = paragraph * 16 (KRNL386's GlobalInit takes paragraph*16 as a
 * linear address: its conventional arena runs from its own DOS-loaded
 * segments up to a paragraph). A 32-bit Win11 process can map 0x10000 up
 * at a fixed address; the first 64 KB (paragraphs 0-0FFFh: the IVT, BIOS
 * data, DOS) stays unmapped. KRNL386's PSP is at 1000h. */
static int g_rm;
uint8_t g_w16_low[0x10000];   /* linear 0-FFFFh (cpu.h w16_lin) */
static __declspec(thread) uint32_t g_w16_ret;   /* the flat return of the innermost w16_enter on a big stack */

/* What a PC's first megabyte holds before DOS: every IVT vector at an iret
 * in the BIOS, a BIOS data area for a VGA colour text screen, 640 KB, no
 * serial ports, LPT1 at 378h, an empty keyboard buffer; option-ROM space
 * C0000-EFFFF reads FFh (no adapter ROMs: no 55AAh signature to find); the
 * BIOS segment has its reset jump, date and model byte (FCh: AT). Nothing
 * here is a real machine's; it only has to be believable. */
static void w16_bios(void) {
    uint8_t *lo = g_w16_low, *hi = (uint8_t *)(uintptr_t)0;
    for (int v = 0; v < 256; v++) *(uint32_t *)(lo + v * 4) = 0xF000FF53u;
    uint8_t *bda = lo + 0x400;
    *(uint16_t *)(bda + 0x08) = 0x378;                 /* LPT1 */
    *(uint16_t *)(bda + 0x10) = 0x0026;                /* equipment: FPU, PS/2 mouse, 80x25 colour */
    *(uint16_t *)(bda + 0x13) = 640;                   /* conventional memory, KB */
    *(uint16_t *)(bda + 0x1A) = *(uint16_t *)(bda + 0x1C) = 0x1E;   /* keyboard buffer empty */
    *(uint16_t *)(bda + 0x80) = 0x1E; *(uint16_t *)(bda + 0x82) = 0x3E;
    bda[0x49] = 3; *(uint16_t *)(bda + 0x4A) = 80; *(uint16_t *)(bda + 0x4C) = 4096;
    *(uint16_t *)(bda + 0x63) = 0x3D4; bda[0x65] = 0x29; bda[0x84] = 24; *(uint16_t *)(bda + 0x85) = 16;
    bda[0x87] = 0x60; bda[0x88] = 0x09; bda[0x89] = 0x11;   /* EGA/VGA flags */
    memset(hi + 0xC0000, 0xFF, 0x30000);               /* no option ROMs */
    memset(hi + 0xF0000, 0xFF, 0x10000);
    hi[0xFFF53] = 0xCF;                                /* iret */
    memcpy(hi + 0xFFFF0, "\xEA\x5B\xE0\x00\xF0" "06/23/99", 13);
    hi[0xFFFFE] = 0xFC;
}

uint32_t w16_real_base(void) {
    /* the launcher holds the range (native32_hold_range) before this
     * process's loader can put its own mappings there */
    if (!g_rm && !VirtualAlloc((void *)0x10000, 0x100000, MEM_COMMIT, PAGE_READWRITE) &&
        !VirtualAlloc((void *)0x10000, 0x100000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
        w16_stop("real-mode memory at 0x10000 is taken (native32_hold_range not called?)", GetLastError(), 0);
    if (!g_rm) w16_bios();
    g_rm = 1;
    return 0;
}
static uint16_t g_rm_sel[0x10000];   /* 0002 hands out one selector per paragraph */
static uint16_t rm_sel(uint16_t para) {
    if (!g_rm_sel[para]) g_rm_sel[para] = native32_w9x_alloc_sel(w16_real_base() + (uint32_t)para * 16, 0xFFFF);
    return g_rm_sel[para];
}

static uint16_t host_sel(void);
static uint32_t g_vec[256];          /* protected-mode vectors: int 21h 25h/35h, DPMI 0204/0205 */
static uint32_t g_exc[32];           /* DPMI 0202/0203 exception handlers */
static uint32_t g_rmvec[256];        /* DPMI 0200/0201 real-mode vectors */
#define H_EXC 0xFE00                 /* host_far: H_EXC + n, the default handler of exception n */

static void dpmi(CPU *c) {
    uint8_t *d = native32_w9x_desc(c->bx);
    switch (c->ax) {
    /* Vectors: what the guest set, read back. Nothing raises an exception
     * or a real-mode interrupt here, so a default handler only has to exist. */
    case 0x0200: c->cx = (uint16_t)(g_rmvec[c->bl] >> 16); c->dx = (uint16_t)g_rmvec[c->bl]; ok(c); return;
    case 0x0201: g_rmvec[c->bl] = (uint32_t)c->cx << 16 | c->dx; ok(c); return;
    case 0x0202: case 0x0203: case 0x0283:   /* 0283: KRNL386's form of 0203 (seg001_8268 restores with it what 0202 read) */
        if (c->bl >= 32) { c->flags |= FLAG_CF; return; }
        if (c->ax != 0x0202) { g_exc[c->bl] = (uint32_t)c->cx << 16 | c->dx; ok(c); return; }
        if (!g_exc[c->bl]) g_exc[c->bl] = (uint32_t)host_sel() << 16 | (H_EXC + c->bl);
        c->cx = (uint16_t)(g_exc[c->bl] >> 16); c->dx = (uint16_t)g_exc[c->bl]; ok(c); return;
    case 0x0204:
        if (!g_vec[c->bl]) g_vec[c->bl] = (uint32_t)host_sel() << 16 | (0xFF00 + c->bl);   /* H_INT + n */
        c->cx = (uint16_t)(g_vec[c->bl] >> 16); c->dx = (uint16_t)g_vec[c->bl]; ok(c); return;
    case 0x0205: g_vec[c->bl] = (uint32_t)c->cx << 16 | c->dx; ok(c); return;
    case 0x0000: {   /* allocate cx descriptors (consecutive: the allocator bumps) */
        uint16_t first = 0;
        if ((0x10000u - native32_w9x_next_sel()) / 8 < c->cx) { c->ax = 0x8011; c->flags |= FLAG_CF; return; }   /* descriptor unavailable */
        /* a 16-bit client's descriptors are 16-bit (B=0): KRNL386's thread stacks (032F)
         * are these, and kernel32's 16->32 return (`mov ss, dx; mov sp, si`) relies on it */
        for (unsigned i = 0; i < c->cx; i++) { uint16_t s = native32_w9x_alloc_sel(0, 0); native32_w9x_desc(s)[6] &= (uint8_t)~0x40; if (!i) first = s; }
        c->ax = first; ok(c); return;
    }
    case 0x0001: memset(d, 0, 8); ok(c); return;                       /* free descriptor */
    case 0x0002: c->ax = rm_sel(c->bx); ok(c); return;                /* real-mode segment to selector */
    case 0x0003: c->ax = 8; ok(c); return;                             /* selector increment */
    case 0x0004: case 0x0005: ok(c); return;                           /* lock/unlock selector (reserved, Windows-only): nothing to do */
    case 0x0006: { uint32_t b = d_base(d); c->cx = (uint16_t)(b >> 16); c->dx = (uint16_t)b; ok(c); return; }
    case 0x0007: d_set_base(d, (uint32_t)c->cx << 16 | c->dx); ok(c); return;
    case 0x0008: {                                                     /* set limit cx:dx */
        uint32_t l = (uint32_t)c->cx << 16 | c->dx;
        if (l > 0xFFFFF) { l >>= 12; d[6] |= 0x80; } else d[6] &= 0x7F;
        d[0] = (uint8_t)l; d[1] = (uint8_t)(l >> 8); d[6] = (uint8_t)((d[6] & 0xF0) | ((l >> 16) & 0x0F));
        ok(c); return;
    }
    case 0x0009: d[5] = c->cl; d[6] = (uint8_t)((d[6] & 0x0F) | (c->ch & 0xF0)); ok(c); return;   /* access rights */
    case 0x000A: {                                                     /* data alias of a code selector */
        uint16_t s = native32_w9x_alloc_sel(0, 0); uint8_t *n = native32_w9x_desc(s);
        memcpy(n, d, 8); n[5] = (uint8_t)((n[5] & 0xF0) | 0x02); c->ax = s; ok(c); return;
    }
    case 0x000B: memcpy((void *)(uintptr_t)(recomp_sel_base(c->es) + c->di), d, 8); ok(c); return;
    case 0x000C: memcpy(d, (void *)(uintptr_t)(recomp_sel_base(c->es) + c->di), 8); ok(c); return;
    case 0x0500: {   /* free memory info at es:di: a 64 MB machine, all of it free */
        uint32_t *m = (uint32_t *)(uintptr_t)(recomp_sel_base(c->es) + c->di);
        memset(m, 0xFF, 0x30);
        m[0] = 0x4000000; m[1] = m[2] = m[3] = m[4] = m[5] = m[6] = m[7] = 0x4000; m[8] = 0;
        ok(c); return;
    }
    case 0x0501: {   /* allocate bx:cx bytes -> bx:cx linear, si:di handle (the same) */
        uint32_t n = (uint32_t)c->bx << 16 | c->cx;
        /* top down: KRNL386 lays its heap from its own segments up to the end
         * of this block (seg001_C850), so the block must lie above them, as
         * DPMI memory lies above a DOS-loaded KRNL386 on a real machine */
        void *p = VirtualAlloc(NULL, n, MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE);
        if (!p) { c->ax = 0x8013; c->flags |= FLAG_CF; return; }
        uint32_t a = (uint32_t)(uintptr_t)p;
        c->bx = c->si = (uint16_t)(a >> 16); c->cx = c->di = (uint16_t)a; ok(c); return;
    }
    case 0x0502: VirtualFree((void *)(uintptr_t)((uint32_t)c->si << 16 | c->di), 0, MEM_RELEASE); ok(c); return;
    case 0x0600: case 0x0601: case 0x0602: case 0x0603:   /* lock/unlock, real-mode pageable */
    case 0x0702: case 0x0703: ok(c); return;               /* page hints */
    case 0x0300: {   /* simulate a real-mode int bl, es:di = the register block (ax at +1Ch) */
        const uint8_t *rb = (const uint8_t *)(uintptr_t)(recomp_sel_base(c->es) + c->di);
        uint16_t rax = *(const uint16_t *)(rb + 0x1C);
        /* 2F/160B, identify TSRs (USER seg72 20E7): nothing real-mode is
         * loaded, so no one fills in es:di and the block comes back as sent */
        if (c->bl == 0x2F && rax == 0x160B) { ok(c); return; }
        w16_stop("int 31h 0300: real-mode int, vec:ax", c->bl, rax);
    }
    }
    w16_stop("int 31h unknown, ax:bx", c->ax, c->bx);
}

/* Far entry points the host hands out (DPMI's mode switch, VxD entries):
 * one selector, the offset says which. A lifted far call into it pushed
 * cs:ip, so each answer pops 4 like the retf it stands for. */
enum { H_DPMI_SWITCH = 1, H_MSDOS_API, H_VXD = 0x100, H_INT = 0x10000 - 0x100 };   /* H_INT + n: the original vector n */
static uint16_t g_host_sel;
static uint16_t host_sel(void) { if (!g_host_sel) g_host_sel = native32_w9x_alloc_sel(0, 0); return g_host_sel; }
uint16_t native32_w9x_ldt_alias(void);

void int_handler(CPU *cpu, int vec);
static void host_far(CPU *c, uint16_t off) {
    if (off >= H_INT) {   /* pushf; call far [old vector]: the handler's iret pops 6 */
        int_handler(c, off - H_INT);
        c->sp += 6; return;   /* CF stays the service's, not the pushed flags */
    }
    if (off >= H_EXC && off < H_EXC + 32) w16_stop("exception with no handler of the guest's, n:ip", off - H_EXC, c->ip);
    c->sp += 4;
    switch (off) {
    case H_DPMI_SWITCH: { /* already in protected mode: cs/ds/ss are selectors; es = the PSP's,
                           * and the PSP's environment paragraph (+2Ch) becomes a selector, as DPMI does */
        uint16_t *env = (uint16_t *)(uintptr_t)(w16_real_base() + W16_PSP_PARA * 16u + 0x2C);
        if (*env) *env = rm_sel(*env);
        c->es = rm_sel(W16_PSP_PARA); ok(c); return;
    }
    case H_MSDOS_API:                    /* the "MS-DOS" vendor API (int 2Fh 168Ah) */
        if (c->ax == 0x100) { c->ax = native32_w9x_ldt_alias(); ok(c); return; }   /* LDT alias */
        break;
    }
    /* VTDAPI 9: the selector of the system-time dword (ms at offset 0); USER keeps 0:ax at
     * DGROUP:0 for its GetTickCount and event times, KRNL386 at DGROUP:1A88 (drv16's tick thread) */
    if (off == H_VXD + 0x442 && c->ax == 9) { uint16_t drv16_tick_sel(void); c->ax = drv16_tick_sel(); ok(c); return; }
    /* VMM 26Dh: KRNL386 seg1 B85A wants ah = 2 to read 26Eh too (DGROUP:1450);
     * ponytail: ax 0, the path it takes when VMM is absent */
    if (off == H_VXD + 0x001 && c->ax == 0x26D) { c->ax = 0; ok(c); return; }
    /* VMM 100h+: KRNL386's 16-bit registry (seg2 6B0C..), into regbox32 (vxd32
     * native32_w9x_reg16). The API's own frame holds the Pascal arguments at
     * bp+6 (push bp; mov bp, sp; push ds; call far [12A8h]), first declared
     * highest; which are far pointers is per service. dx:ax = the LONG. */
    if (off == H_VXD + 0x001 && c->ax >= 0x100 && c->ax < 0x120) {
        static const uint8_t nargs[15] = { 3, 3, 1, 2, 5, 4, 4, 2, 8, 6, 6, 1, 3, 2, 3 };
        static const uint8_t isptr[15] = { 6, 6, 0, 2, 0xA, 0xE, 4, 2, 0xFC, 0x3E, 0x12, 0, 6, 2, 6 };   /* bit i: arg i is far */
        uint32_t a[8] = { 0 }, n = c->ax - 0x100, r = ERROR_ACCESS_DENIED;
        if (n < 15) {
            for (uint32_t i = 0; i < nargs[n]; i++) {
                uint32_t v = mem_read32(c, c->ss, (uint16_t)(c->bp + 6 + 4 * (nargs[n] - 1 - i)));
                a[i] = (isptr[n] >> i & 1) && v ? (uint32_t)(uintptr_t)w16_lin(recomp_sel_base(v >> 16) + (v & 0xFFFF)) : v;
            }
            uint32_t native32_w9x_reg16(uint16_t svc, uint32_t *a);
            r = native32_w9x_reg16(c->ax, a);
        }
        if (getenv("W16_TRACE")) fprintf(stderr, "[w16] VMM %03Xh registry -> %u\n", c->ax, r);
        c->ax = (uint16_t)r; c->dx = (uint16_t)(r >> 16); ok(c); return;
    }
    /* 0Ah: KRNL386 seg2 38F9, once per loaded code segment (flags&5004h == 4004h), cx = sel|1;
     * the result is not read. ponytail: nothing to tell, no-op. */
    if (off == H_VXD + 0x442 && c->ax == 0x0A) { ok(c); return; }
    if (off == H_VXD + 0x17) switch (c->dx) {   /* SHELL's PM API, MSGSRV32's calls through its ds:[76h] */
    case 0x19: {   /* register the event callback ax:bx (89:0541); es back = a flat data selector
                    * (MSGSRV32 keeps it at [7Eh] and reads SHELL's event blocks through it).
                    * ponytail: the callback is kept nowhere: no SHELL events (appy time,
                    * ShellExecute from VxDs) here yet */
        static uint16_t flat;
        if (!flat) { flat = native32_w9x_alloc_sel(0, 0xFFFFF); native32_w9x_desc(flat)[6] |= 0x80; }
        c->es = flat; ok(c); return;
    }
    case 0x1B: case 0x1C: ok(c); return;   /* an event handled (89:0019, 89:0065): nothing to tell */
    case 0x13: ok(c); return;   /* USER seg55 5459, from seg53 144B right after it reads the shift/ctrl/alt
                                 * key states; nothing reads a result. ponytail: a notification, no-op */
    }
    if (off == H_VXD + 0x2A) switch (c->ah) {   /* VWIN32's PM API, KRNL386's calls through DGROUP:1A80 */
    case 0x00:   /* version: KRNL386 wants >= 100h (4.10, Win98); edx nonzero (seg001_6A63: the
                  * Win32 kernel is there: kernel32's base, ponytail: a guess, only tested != 0).
                  * KRNL386 then finds kernel32's export block ('KEXP', its first section) at flat
                  * 1000h and stores its DGROUP:1AC7 through the pointer at +4, into kernel32. */
        c->ax = 0x040A; c->edx = 0xBFF70000u;
        if (!memcmp((void *)(uintptr_t)0xBFF71000u, "KEXP", 4)) memcpy(g_w16_low + 0x1000, (void *)(uintptr_t)0xBFF71000u, 0x100);
        ok(c); return;
    case 0x04:   /* KERNEL.442 VWIN32_EventCreate (seg001_7898, shld into dx:ax): KRNL386 keeps one at
                  * DGROUP:12EC, USER's LibEntry one at es:[0FAEh] and fails on 0. A host event;
                  * ponytail: auto-reset, unsignaled (Set/Wait come as their own functions when called) */
        c->eax = (uint32_t)(uintptr_t)CreateEventA(NULL, FALSE, FALSE, NULL); ok(c); return;
    case 0x05:   /* KERNEL.443 VWIN32_EventDestroy (seg001_78AB): ebx = the event */
        CloseHandle((HANDLE)(uintptr_t)c->ebx); ok(c); return;
    case 0x06: {   /* KERNEL.450 VWIN32_EventWait (seg001_78C7): ebx = the event; blocks, the
                    * machine given up meanwhile (a thread created for USER's init waits here).
                    * ponytail: al (27h) not read */
        uint32_t native32_w9x_wait(void *h, uint32_t ms);
        CPU sv = *c;
        native32_w9x_wait((void *)(uintptr_t)c->ebx, INFINITE);
        *c = sv; ok(c); return;
    }
    case 0x07:   /* KERNEL.451 VWIN32_EventSet (seg001_78E3) and 479 (seg001_7903): ebx = the event */
        SetEvent((HANDLE)(uintptr_t)c->ebx); ok(c); return;
    case 0x0C:   /* KRNL386 registers with VWIN32 once kernel32 is up (seg001_6F7B): es = its code,
                  * bx/cx/dx/di/bp entry offsets in it (8D71, 0ACE, 0C2B, 7C44, 7CAA), esi =
                  * DGROUP:1338. eax comes back and goes (seg001_53FF) into the table at
                  * [13BE]:36h. ponytail: nothing kept, eax 0, until a VWIN32 caller of those
                  * entries exists here */
        if (getenv("W16_TRACE")) fprintf(stderr, "[w16] VWIN32 0C: es %04X bx %04X cx %04X dx %04X di %04X bp %04X esi %08X\n", c->es, c->bx, c->cx, c->dx, c->di, c->bp, c->esi);
        c->eax = 0; ok(c); return;
    case 0x01: {   /* task switch (seg1 73BA): ebx = the next task's r0 thread; back when switched to */
        void native32_w9x_switch_to(uint32_t r0);
        CPU sv = *c;
        /* CurTDB (DGROUP:122C; the boot block's +1C points at it) is ring 0's
         * to set on Win98: the thread that takes the CPU finds its own TDB
         * there (Reschedule's 5F57 reads it right after the switch). 73BA
         * calls with es = DGROUP, di = the next TDB (also put in 13E4).
         * ponytail: di, not the r0 thread's own TDB; the same thing for every
         * switch KRNL386 makes itself */
        extern uint16_t *g_w9x_curtdb;
        g_w9x_curtdb = (uint16_t *)(uintptr_t)(recomp_sel_base(c->es) + 0x122C);
        *g_w9x_curtdb = c->di;
        if (getenv("W16_TRACE")) fprintf(stderr, "[w16] VWIN32 01: CurTDB := %04X (ss:sp %04X:%04X) from ip %04X\n", c->di,
            c->di ? *(uint16_t *)(uintptr_t)(recomp_sel_base(c->di) + 4) : 0, c->di ? *(uint16_t *)(uintptr_t)(recomp_sel_base(c->di) + 2) : 0, c->ret_ip);
        if (getenv("W16_TRACE") && c->di) {
            const uint8_t *t = (const uint8_t *)(uintptr_t)recomp_sel_base(c->di);
            const uint16_t *f = (const uint16_t *)(uintptr_t)(recomp_sel_base(*(uint16_t *)(t + 4)) + *(uint16_t *)(t + 2));
            fprintf(stderr, "[w16]   frame:"); for (int i = 0; i < 12; i++) fprintf(stderr, " %04X", f[i]); fprintf(stderr, " (ss base %08X)\n", recomp_sel_base(*(uint16_t *)(t + 4)));
        }
        native32_w9x_switch_to(c->ebx);
        *c = sv; ok(c); return;
    }
    case 0x0F:   /* KRNL386 seg1 750A (thread id, delta): ebx = its r0 thread, ecx = delta;
                  * USER's SendMessage loop (seg54 1640/1693) calls it with -2 and then 2 on
                  * the receiving queue's thread (+3C) around its wait: a priority boost.
                  * ponytail: no-op, the host schedules; read as a boost from the -2/+2 pair */
        ok(c); return;
    case 0x0E:   /* KRNL386 seg1 7584 (thread id, value): ebx = its r0 thread, ecx = value.
                  * USER seg54 96B6 calls it with 0 for the queue that loses the foreground
                  * (ds:[14Eh]) and 1 for the new one: the foreground thread's boost.
                  * ponytail: no-op, the host schedules (read off the 0/1 callers) */
        ok(c); return;
    case 0x08: c->al = 0; ok(c); return;        /* -> DGROUP:1417, a flag read as "nonzero?" (ponytail: 0 until a caller needs 1) */
    case 0x03: {   /* VMM page services: args on the 16-bit stack, ecx bytes of them, which
                    * the entry removes (KRNL386 seg001_1FF7 pops what it pushed before them);
                    * result in eax */
        const uint32_t *a = (const uint32_t *)(uintptr_t)(recomp_sel_base(c->ss) + c->sp);
        void *p;
        c->sp = (uint16_t)(c->sp + c->cx);
        if (getenv("W16_TRACE")) fprintf(stderr, "[w16] VMM page service %u (%08X %08X %08X)\n", c->al, a[0], a[1], a[2]);
        switch (c->al) {
        case 0x00:   /* _PageReserve(page, npages, flags): PR_PRIVATE/SHARED/SYSTEM = anywhere.
                      * ponytail: committed at once (Windows commits lazily anyway): KRNL386
                      * commits only the whole pages inside a block and counts on the partial
                      * pages at its ends being there */
            p = VirtualAlloc(a[0] >= 0x80000000u ? NULL : (void *)(uintptr_t)(a[0] << 12), a[1] << 12, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            c->eax = p ? (uint32_t)(uintptr_t)p : 0xFFFFFFFFu; ok(c); return;
        case 0x01:   /* _PageCommit(page, npages, hpd, pagerdata, flags) */
            c->eax = VirtualAlloc((void *)(uintptr_t)(a[0] << 12), a[1] << 12, MEM_COMMIT, PAGE_READWRITE) != NULL; ok(c); return;
        case 0x02:   /* _PageDecommit(page, npages, flags): kept committed (see 0) */
            c->eax = 1; ok(c); return;
        case 0x03:   /* _PageFree(laddr, flags) */
            c->eax = VirtualFree((void *)(uintptr_t)a[0], 0, MEM_RELEASE) != 0; ok(c); return;
        }
        break;
    }
    }
    if (off >= H_VXD) w16_stop("VxD entry called, id:ax", off - H_VXD, c->ax);
    w16_stop("host entry, off:ax", off, c->ax);
}

static void int2f(CPU *c) {
    switch (c->ax) {
    case 0x4A16: case 0x4A17: case 0x4A18:   /* IO.SYS boot log open/write/close (KRNL386 seg002_4B5C): no BOOTLOG.TXT, ax unchanged */
        return;
    case 0x4A32:   /* IO.SYS service bl (USER seg072_3742: bl=5, result unread); ponytail: a no-op, ax unchanged */
        return;
    case 0x168D:  /* es:di into the table KRNL386 hands VWIN32 0Ch (seg001_6B2A, unchecked): kernel32
                    * is the host's already, so nothing reads it: 0:0 */
        c->es = 0; c->di = 0; return;
    case 0x150B:   /* MSCDEX drive check, cx = drive (KRNL386 seg001_7AD6, kernel32 thunk 0Dh: drive type):
                    * no MSCDEX (bx stays, not ADADh), no CD-ROM */
        c->ax = 0; return;
    case 0xFE03:   /* Norton Utilities TSR check (si:di 'CF','NU', CF set; KRNL386 seg001_8436): none, CF stays set */
        return;
    case 0x1687:   /* DPMI present: 32-bit clients, 386, v0.90, no private data, entry es:di */
        c->ax = 0; c->bx = 1; c->cl = 3; c->dx = 0x005A; c->si = 0;
        c->es = host_sel(); c->di = H_DPMI_SWITCH; return;
    case 0x168A: {  /* vendor API: only "MS-DOS" (ds:si) */
        const char *v = (const char *)(uintptr_t)(recomp_sel_base(c->ds) + c->si);
        if (!strcmp(v, "MS-DOS")) { c->al = 0; c->es = host_sel(); c->di = H_MSDOS_API; return; }
        break;
    }
    case 0x1684: { /* VxD protected-mode API for bx, named from the call site */
        static const struct { uint16_t id; const char *name; int present; } vxd[] = {
            { 0x0001, "VMM", 1 },        /* USER.EXE calls its entry unchecked; KRNL386 seg001_B83D (after BootStrap's reload): ax=26Dh/26Eh into DGROUP:1450, optional */
            { 0x000A, "VDD", 0 },        /* KRNL386 seg001_BF33 (after kernel32's boot); ponytail: absent until a display driver here asks */
            { 0x0021, "PAGEFILE", 0 },   /* KRNL386 seg001_BEF9: paging-file info (ax=1), optional */
            { 0x002A, "VWIN32", 1 },
            { 0x000C, "VMD", 0 },        /* USER.EXE LibEntry; ponytail: absent, the mouse is MOUSE.DRV's (drv16) */
            { 0x0037, "ENABLE", 0 },     /* accessibility, during USER.EXE's LibEntry; ponytail: absent (no StickyKeys etc.) */
            { 0x0017, "SHELL", 1 },      /* MSGSRV32 seg89 0E14 exits (4C01) without it */
            { 0x0442, "VTDAPI", 1 },     /* KRNL386 seg001_6E8D: ax=9 -> DGROUP:1A88 and the table it hands kernel32, unchecked */     /* KRNL386 seg001_7293: ah=0, then ah=8 -> al into DGROUP:1417; GlobalInit's caller needs it */
        };
        for (unsigned i = 0; i < sizeof vxd / sizeof *vxd; i++)
            if (vxd[i].id == c->bx) {   /* absent: 0:0; present: a tagged entry that stops when called */
                c->es = vxd[i].present ? host_sel() : 0;
                c->di = vxd[i].present ? (uint16_t)(H_VXD + c->bx) : 0;
                return;
            }
        /* any other VxD: absent (0:0), which every caller has to handle; ponytail: logged, not stopped */
        if (getenv("W16_TRACE")) fprintf(stderr, "[w16] VxD %04X asked for: absent\n", c->bx);
        c->es = 0; c->di = 0;
        return;
    }
    }
    w16_stop("int 2Fh unknown, ax:bx", c->ax, c->bx);
}

/* ---- int 21h from 16-bit code ----
 * What only a 16-bit caller asks (vectors, PSP, break flag) is answered
 * here; the rest goes to vxd32's Int21Dispatch table (the one kernel32's
 * VWIN32 10 uses) with ds:dx, ds:si, es:di made flat. A register the
 * service did not touch keeps its 16-bit value; an unknown AH stops there. */
int native32_w9x_int21(uint32_t eax, uint32_t ecx);

void dos_int21(CPU *c) {
    /* Exec goes to the guest's own int 21h hook when it set one: KRNL386's
     * WinExec (seg2 2A68) builds an exec block and does int 21h 4B00, and
     * KRNL386's handler (set with 2521h) turns it into LoadModule (which is
     * where a PE goes to kernel32's CreateProcess). A 4Bh it chains back
     * lands here again and goes to the host (no DOS VM).
     * ponytail: only 4Bh takes the hook; every other AH is answered here
     * as before (the hook's file-handle work would replace ours). */
    static int in_hook;
    if (c->ah == 0x4B && !in_hook && g_vec[0x21] && (uint16_t)(g_vec[0x21] >> 16) != host_sel()) {
        void dispatch_far(CPU *cpu, uint16_t sel, uint16_t off);
        in_hook = 1;
        static uint16_t seg_of(uint16_t sel);
        uint16_t sel = (uint16_t)(g_vec[0x21] >> 16), sp0;
        push16(c, c->flags); push16(c, host_sel()); push16(c, 0);   /* the handler's iret pops these */
        sp0 = c->sp;
        dispatch_far(c, sel, (uint16_t)g_vec[0x21]);
        /* its dispatch `ret`s into the AH's handler (seg1 8624), as under w16_farcall */
        while (c->sp < sp0)
            if (!recomp_dispatch_lookup(c, seg_of(sel), c->ret_ip)) w16_stop("int 21h hook ret into, seg:off", seg_of(sel), c->ret_ip);
        in_hook = 0;
        return;
    }
    switch (c->ah) {
    case 0x25: g_vec[c->al] = (uint32_t)c->ds << 16 | c->dx; ok(c); return;
    case 0x35:   /* never set: the host's own handler for that vector */
        if (!g_vec[c->al]) g_vec[c->al] = (uint32_t)host_sel() << 16 | (H_INT + c->al);
        c->es = (uint16_t)(g_vec[c->al] >> 16); c->bx = (uint16_t)g_vec[c->al]; ok(c); return;
    case 0x33: if (c->al == 0) c->dl = 0; ok(c); return;    /* ctrl-break flag: off */
    case 0x34: c->es = rm_sel(0x50); c->bx = 0; ok(c); return;   /* InDOS flag: a zero byte at 0050:0000 */
    case 0x09: {                                              /* print $-string (KRNL386's fatal messages) */
        const char *s = (const char *)(uintptr_t)(recomp_sel_base(c->ds) + c->dx);
        fprintf(stderr, "[w16] int 21h 09: %.*s\n", (int)strcspn(s, "$\r\n"), s);
        return;
    }
    case 0x02: fputc(c->dl, stderr); return;                  /* write a character (KRNL386's messages) */
    case 0x47:   /* current directory of drive dl at ds:si, no drive or leading '\': the root */
        *(char *)(uintptr_t)(recomp_sel_base(c->ds) + c->si) = 0; ok(c); return;
    case 0x50: {   /* set PSP: the parent int 21h 55h copies (KRNL386 seg2 4956 sets it around 55h) */
        void native32_w9x_set_psp(uint16_t sel);
        native32_w9x_set_psp(c->bx); ok(c); return;
    }
    case 0x06:   /* direct console I/O; DL FFh reads without waiting: no console, no key (ZF set, AL 0). KRNL386 seg1 80D9 drains it at boot */
        if (c->dl == 0xFF) { c->al = 0; c->flags |= FLAG_ZF; }
        ok(c); return;
    case 0x51: case 0x62: c->bx = rm_sel(W16_PSP_PARA); ok(c); return;
    }
    uint32_t s[8] = { g_eax, g_ecx, g_edx, g_ebx, g_esp, g_ebp, g_esi, g_edi };
    uint16_t sds = g_seg_ds, ses = g_seg_es;
    uint32_t sdb = g_ds_base, seb = g_es_base;   /* kernel32's handler may load ds/es: the 32-bit caller's come back too */
    uint32_t in_dx = recomp_sel_base(c->ds) + c->dx, in_si = recomp_sel_base(c->ds) + c->si,
             in_di = recomp_sel_base(c->es) + c->di, in_bx = c->bx, in_cx = c->cx;
    /* cx is a count and dx a value, not ds:dx, for seek (42h cx:dx), ioctl (44h) and file times (57h) */
    /* (and 55h's dx is the new PSP's selector) */
    if (c->ah == 0x42 || c->ah == 0x44 || c->ah == 0x57 || c->ah == 0x55) in_dx = c->dx;
    g_ebx = in_bx; g_ecx = in_cx; g_edx = in_dx; g_esi = in_si; g_edi = in_di;
    if (getenv("W16_TRACE") && (c->ah == 0x3C || c->ah == 0x3D || c->ah == 0x5B || c->ax == 0x716C))
        fprintf(stderr, "[w16] int 21h %04X \"%s\"\n", c->ax, (const char *)(uintptr_t)w16_lin(c->ax == 0x716C ? in_si : in_dx));
    int cf = native32_w9x_int21(c->ax, in_cx);
    c->ax = (uint16_t)g_eax;
    if (g_ebx != in_bx) c->bx = (uint16_t)g_ebx;
    if (g_ecx != in_cx) c->cx = (uint16_t)g_ecx;
    if (g_edx != in_dx) c->dx = (uint16_t)g_edx;
    if (cf) c->flags |= FLAG_CF; else c->flags &= (uint16_t)~FLAG_CF;
    g_eax = s[0]; g_ecx = s[1]; g_edx = s[2]; g_ebx = s[3]; g_esp = s[4]; g_ebp = s[5]; g_esi = s[6]; g_edi = s[7];
    g_seg_ds = sds; g_seg_es = ses; g_ds_base = sdb; g_es_base = seb;
}

void int_handler(CPU *cpu, int vec) {
    if (getenv("W16_TRACE")) fprintf(stderr, "[w16] int %02Xh ax=%04X bx=%04X cx=%04X dx=%04X\n", vec, cpu->ax, cpu->bx, cpu->cx, cpu->dx);
    if (vec == 0x31) { dpmi(cpu); return; }
    if (vec == 0x2F) { int2f(cpu); return; }
    if (vec == 0x21) { dos_int21(cpu); return; }
    if (vec == 0x11) { cpu->ax = 0x0022; return; }   /* BIOS equipment: FPU, 80x25 colour, no floppies */
    if (vec == 0x12) { cpu->ax = 640; return; }      /* BIOS base memory, KB */
    if (vec == 0x10) return;   /* BIOS video (KRNL386's fatal exit sets mode 3 before its message): no screen */
    if (vec == 0x41) return;   /* kernel debugger (WDEB386) calls: none present, ax stays (not F386h) */
    w16_stop("int, ax", (unsigned)vec << 8 | (cpu->ax >> 8), cpu->ax);
}
void bios_int10(CPU *cpu) { int_handler(cpu, 0x10); }
void bios_int16(CPU *cpu) { int_handler(cpu, 0x16); }

/* SEG_n (segments.h, identity mode) is g_w16_segsel[n]: the selector the
 * lifted code uses for its own segment n. It starts as (n<<3)|7 and follows
 * KRNL386's loader: when LoadSegment puts a segment in a block of its own
 * (BootStrap moves KERNEL's segments off the DOS-loaded image, LoadModule
 * loads GDI's and USER's), SEG_n becomes that block's selector, so `push
 * cs`, cs:[n] and DGROUP fixups name what KRNL386's own tables know. */
uint16_t g_w16_segsel[RECOMP_NUM_SEG + 1];
static void segsel_init(void) {   /* once per process: g_w16_ready is per thread */
    static int done;
    if (done++) return;
    for (uint16_t n = 0; n <= RECOMP_NUM_SEG; n++) g_w16_segsel[n] = (uint16_t)(n << 3 | 7);
}

static uint16_t g_alias[8192];

/* Bind a module's loaded segments to the selectors KRNL386 gave them, read
 * from its own data: sel's arena (KERNEL DGROUP:1234 selector table, in the
 * Burgermaster segment DGROUP:121E) names the owner, the module database
 * (NE header in memory: +1C segment count, +22 segment table of 10-byte
 * entries {.., +4 flags (4 = loaded), +8 handle}, +26 resident names with
 * the module name first). Returns sel's segment, or 0. */
static uint16_t w16_rebind(uint16_t sel, uint16_t want) {
    /* KERNEL's DGROUP: its bound selector, or cs:[2] before the first bind */
    uint16_t kd = RECOMP_MODULES[0].dgroup, dgs = g_w16_segsel[kd];
    if (dgs == (uint16_t)(kd << 3 | 7)) dgs = *(uint16_t *)(uintptr_t)(recomp_sel_base(g_w16_segsel[1]) + 2);
    uint32_t dg = recomp_sel_base(dgs);
    if (!dg) return 0;
    uint32_t bm = recomp_sel_base(*(uint16_t *)(uintptr_t)(dg + 0x121E));
    uint16_t len = *(uint16_t *)(uintptr_t)(dg + 0x1232);
    uint32_t tab = *(uint32_t *)(uintptr_t)(dg + 0x1234), ix = (uint32_t)(sel & ~7) >> 1;
    if (!bm || ix >= len) return 0;
    uint32_t a = *(uint32_t *)(uintptr_t)(bm + tab + ix);
    if (!a) return 0;
    uint16_t own = *(uint16_t *)(uintptr_t)(bm + a + 0x12);
    const uint8_t *ne = (const uint8_t *)(uintptr_t)recomp_sel_base(own | 1);
    if (!ne) return 0;   /* no 'NE' check: KERNEL's own reads 0 there during BootStrap */
    const uint8_t *nm = ne + *(uint16_t *)(ne + 0x26);
    if (getenv("W16_TRACE")) { const uint8_t *st = ne + *(uint16_t *)(ne + 0x22); fprintf(stderr, "[w16] rebind %04X: owner %04X @%p %.*s, %u segments, flags:handle %04X:%04X %04X:%04X %04X:%04X %04X:%04X\n", sel, own, (void *)ne, nm[0], nm + 1, *(uint16_t *)(ne + 0x1C), *(uint16_t *)(st + 4), *(uint16_t *)(st + 8), *(uint16_t *)(st + 14), *(uint16_t *)(st + 18), *(uint16_t *)(st + 24), *(uint16_t *)(st + 28), *(uint16_t *)(st + 34), *(uint16_t *)(st + 38)); }
    uint16_t hit = 0;
    for (int m = 0; m < RECOMP_NUM_MODULES; m++) {
        const RecompModule *rm = &RECOMP_MODULES[m];
        if (strlen(rm->name) != nm[0] || _strnicmp(rm->name, (const char *)nm + 1, nm[0])) continue;
        uint16_t cnt = *(uint16_t *)(ne + 0x1C);
        const uint8_t *st = ne + *(uint16_t *)(ne + 0x22);
        for (uint16_t s = 0; s < cnt && rm->first_seg + s <= rm->last_seg; s++) {
            uint16_t h = *(uint16_t *)(st + s * 10 + 8);
            uint16_t n = (uint16_t)(rm->first_seg + s), ns = (uint16_t)(h | 1);
            /* the segment called, and the module's DGROUP (loaded before any
             * of its code runs). Other segments may hold a handle before
             * their bytes are loaded (C597 allocates all of KERNEL's at
             * once; the flags say nothing), so they wait for their own call. */
            /* and its other data segments once loaded (flags 1|4): code reads them by
             * selector constant (USER's seg 33, its cursor/monitor table, is written
             * through DGROUP:[508] and read as SEG_84) */
            uint16_t fl = *(uint16_t *)(st + s * 10 + 4);
            if (!h || ((ns | 7) != (sel | 7) && n != rm->dgroup && n != want && (fl & 5) != 5)) continue;
            if (g_w16_segsel[n] != ns && getenv("W16_TRACE"))
                fprintf(stderr, "[w16] %s seg %u (lifted %u): selector %04X -> %04X\n", rm->name, s + 1, n, g_w16_segsel[n], ns);
            g_w16_segsel[n] = ns; g_alias[ns >> 3] = n;
            if (n != rm->dgroup || (ns | 7) == (sel | 7)) hit = n;
        }
    }
    return hit;
}

/* A code selector the 16-bit side made itself runs the lifted segment it
 * holds: one KRNL386 loaded a segment into (w16_rebind), or an alias over a
 * segment already in memory (same base). ponytail: a linear scan per first
 * sight, cached. */
static uint16_t seg_of(uint16_t sel) {
    uint16_t i = (uint16_t)(sel >> 3);
    if (i <= RECOMP_NUM_SEG) return i;
    if (!g_alias[i]) {
        uint32_t b = recomp_sel_base(sel);
        for (uint16_t n = 1; n <= RECOMP_NUM_SEG; n++)
            if (recomp_sel_base(g_w16_segsel[n]) == b) { g_alias[i] = n; break; }
        if (!g_alias[i]) w16_rebind(sel, 0);
    }
    return g_alias[i];
}
/* An o32 retf (66 CB) to sel:eip. KRNL386 calls into kernel32 this way
 * (seg001_6500, "call KEXP entry bx"): it switches to a flat stack, puts
 * the kernel32 function and the flat code selector on it, with a flat
 * return to its own 32-bit stub (seg 1 +656C), and does a 32-bit retf. The
 * function runs as lifted 32-bit code on that stack; the stub it returns
 * to is not lifted (32-bit code in a 16-bit segment), so its effect is
 * done here: ss = di, sp = esp - esi, push ss, push FFFFh, push ebx (the
 * 16:16 return), and a 16-bit retf to the sel:off it names (8E D7 2B E6
 * 66 16 66 68 FF FF 53 66 68 sel 66 68 off 66 CB). */
typedef void (*w16_fn32)(void);
w16_fn32 recomp_lookup(uint32_t va);
void dispatch_far(CPU *cpu, uint16_t sel, uint16_t off);
/* A flat 32-bit stack: B bit and base 0 (KRNL386's __FLATDS). ponytail: the host gives every
 * data selector it allocates the B bit (QT_Thunk's alias stack too), so B alone is not enough. */
int w16_ss_big(uint16_t ss) { return (ss & 4) && (native32_w9x_desc(ss)[6] & 0x40) && !recomp_sel_base(ss); }
typedef struct w16_ff { struct w16_ff *up; uint16_t ss, sp; } w16_ff;
static __declspec(thread) w16_ff *g_ff, *g_ff_to;
static __declspec(thread) uint32_t g_retf_at;   /* where the last plain retf went (dispatch_far) */
/* 16->32 calls in flight whose 32-bit side comes back by a far jump into
 * 16-bit code (w16_retf's generated stubs, w16_retf32's 16:16 returns):
 * w16_enter longjmps here when its target is the pending return. */
static __declspec(thread) struct { jmp_buf jb; uint32_t back; uint16_t ss, sp; } g_thk[16];   /* ss:sp: where back sits */
static __declspec(thread) int g_nthk;
void w16_retf32(CPU *c) {
    /* eip and a 32-bit cs from ss:esp when ss is a big (B) segment, else ss:sp */
    uint32_t sb = recomp_sel_base(c->ss);
    int big = w16_ss_big(c->ss);
    uint32_t sp = big ? c->esp : c->sp;
    uint32_t eip = *(uint32_t *)(uintptr_t)w16_lin(sb + sp);
    uint16_t sel = *(uint16_t *)(uintptr_t)w16_lin(sb + sp + 4);
    if (big) c->esp += 8; else c->sp = (uint16_t)(c->sp + 8);
    if (getenv("W16_TRACE")) fprintf(stderr, "[w16] far32 %04X:%08X ss:esp %04X:%08X\n", sel, eip, c->ss, c->esp);
    if (g_w16_ret && eip == g_w16_ret) return;   /* back to kernel32: w16_enter unwinds */
    w16_fn32 f = (sel & 4) && !recomp_sel_base(sel) ? recomp_lookup(eip) : NULL;   /* a flat code selector */
    if (!f) w16_stop("o32 retf to", sel, eip);
    uint32_t ret = *(uint32_t *)(uintptr_t)(sb + c->esp);
    if (getenv("W16_TRACE")) {   /* the first arguments, and what the first points at */
        const uint32_t *a = (const uint32_t *)(uintptr_t)(sb + c->esp + 4);
        fprintf(stderr, "[w16] far32 args %08X %08X %08X (fs %04X):", a[0], a[1], a[2], c->fs);
        if (a[0] > 0x10000 && !IsBadReadPtr((void *)(uintptr_t)a[0], 0xA0))
            for (int i = 0; i < 0xA0; i += 4) fprintf(stderr, "%s%08X", i % 32 ? " " : "\n  ", *(const uint32_t *)(uintptr_t)(a[0] + i));
        fprintf(stderr, "\n");
    }
    /* The return is a 16:16 address in a present code selector: the flat
     * function comes back by an o16 retf (USER seg 21 A7A7 pushes cs:A7E9,
     * then __FLATCS:user32 BFF540DA, which ends `66 CB`). Its retf reaches
     * w16_enter, which longjmps back here; the 16-bit code goes on there. */
    uint32_t rr;
    int recomp_lar32(uint16_t sel, uint32_t *rights);
    int back16 = (ret >> 16 & 4) && recomp_lar32((uint16_t)(ret >> 16), &rr) && (rr & 0x8800) == 0x8800 && recomp_sel_base(ret >> 16);
    static const uint8_t stub[] = { 0x66, 0x8E, 0xD7, 0x2B, 0xE6, 0x66, 0x16, 0x66, 0x68, 0xFF, 0xFF, 0x53, 0x66, 0x68 };
    const uint8_t *r = (const uint8_t *)(uintptr_t)ret;
    if (!back16 && (memcmp(r, stub, sizeof stub) || r[16] != 0x66 || r[17] != 0x68 || r[20] != 0x66 || r[21] != 0xCB))
        w16_stop("flat return is not KRNL386's 32->16 stub", ret >> 16, ret & 0xFFFF);
    uint32_t se[8] = { g_eax, g_ecx, g_edx, g_ebx, g_esp, g_ebp, g_esi, g_edi };
    uint16_t sss = g_seg_ss, sds = g_seg_ds, ses = g_seg_es; uint32_t ssb = g_ss_base, sdb = g_ds_base, seb = g_es_base;
    g_eax = c->eax; g_ecx = c->ecx; g_edx = c->edx; g_ebx = c->ebx;
    g_ebp = c->ebp; g_esi = c->esi; g_edi = c->edi;
    g_seg_ss = c->ss; g_ss_base = sb; g_esp = c->esp;
    g_seg_ds = c->ds; g_seg_es = c->es;
    /* fs and gs are the same registers on both sides: kernel32 reads the
     * TIB KRNL386 built for the boot thread (seg001_7240) through fs, and
     * whatever fs kernel32 leaves (its _INIT loads its own) is KRNL386's */
    void recomp_set_seg(int sreg, uint32_t sel);
    recomp_set_seg(4, c->fs); recomp_set_seg(5, c->gs);
    if (back16) {
        if (g_nthk == 16) w16_stop("16->32 calls nested too deep", 0, 0);
        CPU keep = *c;
        w16_ff *ff = g_ff;
        int k = g_nthk++;
        g_thk[k].back = ret; g_thk[k].ss = c->ss; g_thk[k].sp = c->sp;
        if (!setjmp(g_thk[k].jb)) {
            recomp_set_seg(3, c->ds); recomp_set_seg(0, c->es);
            f();
            w16_stop("flat function returned without its retf to", ret >> 16, ret & 0xFFFF);
        }
        g_nthk = k; g_ff = ff;
        *c = keep;
        c->eax = g_eax; c->ecx = g_ecx; c->edx = g_edx; c->ebx = g_ebx;
        c->ebp = g_ebp; c->esi = g_esi; c->edi = g_edi;
        c->ss = g_seg_ss; c->sp = (uint16_t)g_esp; c->ds = g_seg_ds; c->es = g_seg_es; c->fs = g_seg_fs; c->gs = g_seg_gs;
        g_eax = se[0]; g_ecx = se[1]; g_edx = se[2]; g_ebx = se[3]; g_esp = se[4]; g_ebp = se[5]; g_esi = se[6]; g_edi = se[7];
        g_seg_ss = sss; g_seg_ds = sds; g_seg_es = ses; g_ss_base = ssb; g_ds_base = sdb; g_es_base = seb;
        dispatch_far(c, (uint16_t)(ret >> 16), (uint16_t)ret);
        return;
    }
    f();
    c->fs = g_seg_fs; c->gs = g_seg_gs;
    c->eax = g_eax; c->ecx = g_ecx; c->edx = g_edx; c->ebx = g_ebx;
    c->ebp = g_ebp; c->esi = g_esi; c->edi = g_edi;
    uint32_t lin = g_esp + g_ss_base;   /* past the return the function popped */
    g_eax = se[0]; g_ecx = se[1]; g_edx = se[2]; g_ebx = se[3]; g_esp = se[4]; g_ebp = se[5]; g_esi = se[6]; g_edi = se[7];
    g_seg_ss = sss; g_seg_ds = sds; g_seg_es = ses; g_ss_base = ssb; g_ds_base = sdb; g_es_base = seb;   /* the bases too: the 32-bit side loaded 16-bit ds/es */
    c->ss = c->di; c->esp = lin - c->esi;
    push16(c, c->ss); push16(c, 0xFFFF); push32(c, c->ebx);
    dispatch_far(c, *(const uint16_t *)(r + 14), *(const uint16_t *)(r + 18));
}

/* W16_SEGIN: lifted code makes a direct far call into segment n, whose
 * fixup KRNL386's loader patched with the block it loaded n into. Bind n
 * through a segment of the same module that is already bound (its module
 * database is the one to read). ponytail: a module with nothing bound yet
 * stays on its placeholder until a dispatched far call reaches it. */
void w16_segin(uint16_t n) {
    if (getenv("W16_TRACE")) fprintf(stderr, "[w16] segin %u\n", n);
    for (int m = 0; m < RECOMP_NUM_MODULES; m++) {
        const RecompModule *rm = &RECOMP_MODULES[m];
        if (n < rm->first_seg || n > rm->last_seg) continue;
        for (uint16_t k = rm->first_seg; k <= rm->last_seg; k++)
            if (k != n && g_w16_segsel[k] != (uint16_t)(k << 3 | 7)) { w16_rebind(g_w16_segsel[k], n); return; }
    }
}
void dispatch_far(CPU *cpu, uint16_t sel, uint16_t off) {
    if (getenv("W16_TRACE")) fprintf(stderr, "[w16] far %04X:%04X (seg %u) ss:sp %04X:%04X\n", sel, off, seg_of(sel), cpu->ss, cpu->sp);
    if (sel && sel == g_host_sel) { host_far(cpu, off); return; }
    int w16_drv_far(CPU *c, uint16_t sel, uint16_t off);
    if (w16_drv_far(cpu, sel, off)) return;   /* a host driver's segment (drv16.c) */
    uint32_t pushed = mem_read32(cpu, cpu->ss, cpu->sp);   /* the far return the caller pushed */
    uint16_t ss0 = cpu->ss, sp0 = cpu->sp;
    if (!(sel & 4) || !recomp_dispatch_lookup(cpu, seg_of(sel), off)) {
        uint32_t b = (sel & 4) ? recomp_sel_base(sel) : 0;   /* what is there: a thunk built at run time? */
        const uint8_t *t = (const uint8_t *)(uintptr_t)(b + off);
        /* the 16-bit face of a 32-bit window procedure (calc's, through
         * USER's dispatch seg 54 9E87): `push dword proc32; push dword x;
         * jmp far sel:off`, written into a KERNEL-owned block at run time.
         * Its bytes are recognized, not run (as vxd32's flat-thunk stubs). */
        if (b && !IsBadReadPtr(t, 17) && t[0] == 0x66 && t[1] == 0x68 && t[6] == 0x66 && t[7] == 0x68 && t[12] == 0xEA) {
            push32(cpu, *(const uint32_t *)(t + 2));
            push32(cpu, *(const uint32_t *)(t + 8));
            dispatch_far(cpu, *(const uint16_t *)(t + 15), *(const uint16_t *)(t + 13));
            return;
        }
        if (b && !IsBadReadPtr((void *)(uintptr_t)(b + off), 24)) {
            fprintf(stderr, "[w16] %04X:%04X (base %08X):", sel, off, b);
            for (int i = 0; i < 24; i++) fprintf(stderr, " %02X", ((uint8_t *)(uintptr_t)(b + off))[i]);
            fputc('\n', stderr);
        }
        w16_stop("far call miss", sel, off);
    }
    /* The callee's last retf popped some other frame: a task switch-in
     * (KRNL386 seg1 5F7F loads the next task's ss:sp from its TDB, 5F8A
     * retfs into it -- a new task's entry, MSGSRV32 89:22EE). That code is
     * where control is; the C return to here is not. ponytail: only a
     * plain retf records its target (retf N does not), hence the ret_ip check */
    while (g_retf_at && g_retf_at != pushed && cpu->ret_ip == (uint16_t)g_retf_at && (g_retf_at >> 16 & 4)) {
        uint32_t at = g_retf_at; g_retf_at = 0;
        if (getenv("W16_TRACE")) fprintf(stderr, "[w16] retf to %04X:%04X, not the caller's %04X:%04X (ss:sp %04X:%04X, called at %04X:%04X)\n",
            at >> 16, at & 0xFFFF, pushed >> 16, pushed & 0xFFFF, cpu->ss, cpu->sp, ss0, sp0);
        if (!recomp_dispatch_lookup(cpu, seg_of((uint16_t)(at >> 16)), (uint16_t)at)) break;   /* mid-function: a C return after all */
    }
    g_retf_at = 0;
}
/* Exception n at cs:ip (a lifted ud0/ud2): what a DPMI host does. The
 * handler the guest set (0203) gets the 16-bit exception frame on a locked
 * stack of the host's: far return, error code, ip, cs, flags, sp, ss. When
 * it returns, execution goes on at the frame's cs:ip with its flags and
 * ss:sp (KRNL386 BootStrap rewrites cs:ip to continue past its ud0). */
void w16_raise(CPU *c, int n, uint16_t cs, uint16_t ip) {
    uint32_t h = n < 32 ? g_exc[n] : 0;
    if (!h || (uint16_t)(h >> 16) == g_host_sel) w16_stop("exception with no handler of the guest's, n:ip", (unsigned)n, ip);
    static uint16_t xss;
    if (!xss) xss = native32_w9x_alloc_sel((uint32_t)(uintptr_t)VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE), 0xFFF);
    uint16_t ss = c->ss, sp = c->sp;
    c->ss = xss; c->sp = 0x1000;
    push16(c, ss); push16(c, sp); push16(c, c->flags); push16(c, cs); push16(c, ip); push16(c, 0);
    push16(c, 0); push16(c, 0);   /* the far return the handler's retf pops */
    if (getenv("W16_TRACE")) fprintf(stderr, "[w16] exception %d at %04X:%04X -> handler %04X:%04X\n", n, cs, ip, h >> 16, h & 0xFFFF);
    if (!recomp_dispatch_lookup(c, seg_of((uint16_t)(h >> 16)), (uint16_t)h)) w16_stop("no lifted exception handler at", h >> 16, h & 0xFFFF);
    c->sp += 2;   /* error code */
    uint16_t nip = pop16(c), ncs = pop16(c);
    c->flags = pop16(c);
    uint16_t nsp = pop16(c); c->ss = pop16(c); c->sp = nsp;
    dispatch_far(c, ncs, nip);
}

/* A far return that does not come back to its C caller. KRNL386's
 * parameter validation (seg1 9D47) unwinds to the API's frame on an invalid
 * handle and returns through `push ax; push bx; retf` into the API's error
 * exit (GetModuleFileName(0): 2:00C4), whose retf N goes back to the API's
 * caller -- but the C stack still holds the API body after its validator
 * call. Every lifted direct far call runs through w16_farcall, which keeps
 * the 16-bit sp at entry (the far return's slot); w16_unwind, after such a
 * pushed retf, throws to the far call whose frame the 16-bit sp has passed.
 * ponytail: direct far calls only (not dispatch_far's indirect ones, not
 * `push cs; call near`); add them when an unwind targets one. */
#define W16_UNWIND_CODE 0xE0571601u
/* A callee that ends in a near `ret` with its far return still on the stack
 * jumped to an address it pushed (KRNL386's int 21h hook, seg1 852A: the
 * handler's offset goes in a saved-register slot, 8624 `ret`s into it): run
 * that continuation in the callee's segment, until the far return is popped. */
__declspec(thread) uint16_t g_w16_callseg;
void w16_farcall(CPU *c, void (*f)(CPU *)) {
    w16_ff fr = { g_ff, c->ss, c->sp };
    uint16_t seg = g_w16_callseg; g_w16_callseg = 0;
    g_ff = &fr;
    __try {
        f(c);
        while (seg && c->ss == fr.ss && c->sp < fr.sp) {
            if (getenv("W16_TRACE")) fprintf(stderr, "[w16] near ret into %u:%04X under a far call (sp %04X < %04X)\n", seg, c->ret_ip, c->sp, fr.sp);
            if (!recomp_dispatch_lookup(c, seg, c->ret_ip)) w16_stop("near ret under a far call into, seg:off", seg, c->ret_ip);
        }
    }
    __except (GetExceptionCode() == W16_UNWIND_CODE && g_ff_to == &fr ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        if (getenv("W16_TRACE")) fprintf(stderr, "[w16] unwound to the far call at ss:sp %04X:%04X (now %04X)\n", fr.ss, fr.sp, c->sp);
    }
    g_ff = fr.up;
}
/* The host's own entries (w16_enter, w16_call) into lifted code: a far call
 * frame with nothing above it, so an error return out of the entry lands here. */
static int w16_entry(CPU *c, uint16_t seg, uint16_t off) {
    w16_ff fr = { NULL, c->ss, c->sp }, *up = g_ff;
    int ok = 1;
    g_ff = &fr;
    __try { ok = recomp_dispatch_lookup(c, seg, off); }
    __except (GetExceptionCode() == W16_UNWIND_CODE && g_ff_to == &fr ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        if (getenv("W16_TRACE")) fprintf(stderr, "[w16] unwound to the host's entry at ss:sp %04X:%04X (now %04X)\n", fr.ss, fr.sp, c->sp);
    }
    g_ff = up;
    return ok;
}
void w16_unwind(CPU *c) {
    w16_ff *t = NULL;
    for (w16_ff *f = g_ff; f && f->ss == c->ss && (uint32_t)f->sp + 4 <= c->sp; f = f->up) t = f;
    if (!t) return;
    g_ff_to = t;
    RaiseException(W16_UNWIND_CODE, 0, 0, NULL);
}

/* `push seg; push off; retf`. To a lifted function: a far jump, whose own retf
 * comes back here, then w16_unwind. To no function (a return address in a
 * call site's middle: GDI's driver wrapper seg5 5FB0 retfs to 5:2941 after the
 * driver call): a return -- to the far call frame it passed, or as a C return
 * up a chain of tail calls (an indirect dispatch_far has no frame).
 * ponytail: the C-return case assumes the frames between are tail calls. */
void w16_jmpf(CPU *c, uint16_t sel, uint16_t off) {
    if ((sel & 4) && sel != g_host_sel && recomp_sel_base(sel) && memcmp((const void *)(uintptr_t)recomp_sel_base(sel), "PCRD", 4)) {
        if (recomp_dispatch_lookup(c, seg_of(sel), off)) { w16_unwind(c); return; }   /* ran it: the far jump */
        if (getenv("W16_TRACE")) fprintf(stderr, "[w16] retf to %04X:%04X: a return to a call site\n", sel, off);
        w16_unwind(c);
        return;
    }
    dispatch_far(c, sel, off);
    w16_unwind(c);
}

/* `push cont_seg; push cont_off; ...; push seg; push off; retf` (ne_lift: the
 * same straight run pushed both): a far call to seg:off whose retf comes back
 * to the pushed continuation. KRNL386 seg2 0D3A calls a DLL's LibEntry so
 * and goes on at 0D83. If the callee left some other way (an unwind, a
 * return elsewhere), that is where control is: no continuation. */
void w16_retf_call(CPU *c) {
    uint16_t off = pop16(c), sel = pop16(c);
    uint16_t co = mem_read16(c, c->ss, c->sp), cs = mem_read16(c, c->ss, (uint16_t)(c->sp + 2)), sp = c->sp;
    if (getenv("W16_TRACE")) fprintf(stderr, "[w16] retf call %04X:%04X, back to %04X:%04X\n", sel, off, cs, co);
    dispatch_far(c, sel, off);
    if (getenv("W16_TRACE")) fprintf(stderr, "[w16] retf call %04X:%04X returned ax %04X to %04X (sp %04X)\n", sel, off, c->ax, c->ret_ip, c->sp);
    if (c->ret_ip == co && c->sp > sp) dispatch_far(c, cs, co);
}

void dispatch_near(CPU *cpu, uint16_t seg, uint16_t off) {   /* seg: the segment index */
    if (!recomp_dispatch_lookup(cpu, seg, off)) w16_stop("near call miss", seg, off);
}
/* A near call to a function whose `ret` pops an address it pushed (KRNL386
 * seg1 852A rets into its int 21h handler): run each place it returned
 * into, in the caller's segment, until something returns to the call's ip.
 * ponytail: 256 hops, then a stop (no handler chains that long yet). */
void w16_retjump(CPU *c, uint16_t seg, uint16_t ip) {
    for (int n = 0; c->ret_ip != ip; n++) {
        if (getenv("W16_TRACE")) fprintf(stderr, "[w16] ret-jump into %u:%04X (for %04X, sp %04X)\n", seg, c->ret_ip, ip, c->sp);
        if (n == 256) w16_stop("ret-jump never came back, seg:ip", seg, ip);
        dispatch_near(c, seg, c->ret_ip);
    }
}


static __declspec(thread) CPU g_w16;
static __declspec(thread) int g_w16_ready;
static uint16_t seg_of(uint16_t sel);
int w16_ss_big(uint16_t ss);

/* A far return into a 16->32 thunk KRNL386 generated (seg001_76BA, the
 * first call of each of seg 3's kernel32 entries: it writes the stub over
 * the entry and retfs into it):
 *   B8 sel / 8E C0 / 66 0F B7 C9 / 67 66 26 8B 91 tab32 / 66 EA off32 sel16
 * = es = sel; ecx = cx; edx = es:[ecx + tab]; jmp far 32 sel16:off32, a
 * kernel32 dispatcher that runs entry edx and comes back to the 16-bit
 * caller with an o16 retf (w16_enter sees its return address and unwinds
 * here). Static code cannot hold it, so the runtime runs it. */
int w16_retf(CPU *c) {
    uint32_t at = mem_read32(c, c->ss, c->sp);
    g_retf_at = at;
    int recomp_lar32(uint16_t sel, uint32_t *rights);
    uint32_t r;   /* only a present code selector of the guest's (a C return names a placeholder) */
    if (!(at >> 16 & 4) || !recomp_lar32((uint16_t)(at >> 16), &r) || (r & 0x8800) != 0x8800 || !recomp_sel_base(at >> 16)) return 0;
    const uint8_t *p = (const uint8_t *)(uintptr_t)w16_lin(recomp_sel_base(at >> 16) + (at & 0xFFFF));
    static const uint8_t t1[] = { 0x8E, 0xC0, 0x66, 0x0F, 0xB7, 0xC9, 0x67, 0x66, 0x26, 0x8B, 0x91 };
    /* or seg001_7618's (a flat thunk's first call, e.g. USER's WNet ones):
     *   B8 sel / 8E C0 / 66 BA imm32 / 66 EA off32 sel16 = es = sel; edx = imm32 */
    static const uint8_t t2[] = { 0x8E, 0xC0, 0x66, 0xBA };
    int ft = p[0] == 0xB8 && !memcmp(p + 3, t2, sizeof t2) && p[0xB] == 0x66 && p[0xC] == 0xEA;
    if (!ft && (p[0] != 0xB8 || memcmp(p + 3, t1, sizeof t1) || p[0x12] != 0x66 || p[0x13] != 0xEA)) return 0;
    c->sp += 4;
    c->es = *(const uint16_t *)(p + 1);
    if (ft) c->edx = *(const uint32_t *)(p + 7);
    else {
        c->ecx = c->cx;
        c->edx = *(const uint32_t *)(uintptr_t)(recomp_sel_base(c->es) + c->ecx + *(const uint32_t *)(p + 0xE));
    }
    uint32_t eip = *(const uint32_t *)(p + (ft ? 0xD : 0x14));
    w16_fn32 f = recomp_lookup(eip);
    if (getenv("W16_TRACE")) fprintf(stderr, "[w16] stub %04X:%04X -> %08X (entry %08X, cx %04X) depth %d back %04X:%04X thread %lu\n", at >> 16, at & 0xFFFF, eip, c->edx, c->cx,
        g_nthk, mem_read16(c, c->ss, (uint16_t)(c->sp + 6)), mem_read16(c, c->ss, (uint16_t)(c->sp + 4)), GetCurrentThreadId());
    if (getenv("W16_TRACE")) {   /* the Pascal arguments above the far return, last pushed first */
        fprintf(stderr, "[w16]   stub args");
        for (int i = 0; i < 8; i++) fprintf(stderr, " %04X", mem_read16(c, c->ss, (uint16_t)(c->sp + 8 + 2 * i)));
        fprintf(stderr, "\n");
    }
    if (!f) w16_stop("generated stub jumps to no lifted function", eip >> 16, eip & 0xFFFF);
    if (g_nthk == 16) w16_stop("16->32 stubs nested too deep", 0, 0);
    uint32_t se[8] = { g_eax, g_ecx, g_edx, g_ebx, g_esp, g_ebp, g_esi, g_edi };
    uint16_t sss = g_seg_ss, sds = g_seg_ds, ses = g_seg_es; uint32_t ssb = g_ss_base, sdb = g_ds_base, seb = g_es_base;
    void recomp_set_seg(int sreg, uint32_t sel);
    g_eax = c->eax; g_ecx = c->ecx; g_edx = c->edx; g_ebx = c->ebx;
    g_ebp = c->ebp; g_esi = c->esi; g_edi = c->edi;
    recomp_set_seg(2, c->ss); g_esp = c->sp;
    recomp_set_seg(3, c->ds); recomp_set_seg(0, c->es); recomp_set_seg(4, c->fs); recomp_set_seg(5, c->gs);
    CPU keep = *c;
    w16_ff *ff = g_ff;   /* the stub's return longjmps past nested far calls */
    int k = g_nthk++;
    g_thk[k].back = mem_read32(c, c->ss, c->sp);   /* the 16-bit caller's far return */
    g_thk[k].ss = c->ss; g_thk[k].sp = c->sp;
    if (!setjmp(g_thk[k].jb)) {
        f();
        w16_stop("16->32 stub's function returned without its retf", eip >> 16, eip & 0xFFFF);
    }
    g_nthk = k; g_ff = ff;
    *c = keep;   /* g_w16 may have been reused by a nested 32->16 call */
    c->eax = g_eax; c->ecx = g_ecx; c->edx = g_edx; c->ebx = g_ebx;
    c->ebp = g_ebp; c->esi = g_esi; c->edi = g_edi;
    c->ss = g_seg_ss; c->sp = (uint16_t)g_esp; c->ds = g_seg_ds; c->es = g_seg_es; c->fs = g_seg_fs; c->gs = g_seg_gs;
    g_eax = se[0]; g_ecx = se[1]; g_edx = se[2]; g_ebx = se[3]; g_esp = se[4]; g_ebp = se[5]; g_esi = se[6]; g_edi = se[7];
    g_seg_ss = sss; g_seg_ds = sds; g_seg_es = ses; g_ss_base = ssb; g_ds_base = sdb; g_es_base = seb;   /* the bases too: the 32-bit side loaded 16-bit ds/es */
    return 1;
}

int w16_enter(uint32_t target) {
    if (g_nthk && target == g_thk[g_nthk - 1].back) {   /* a 16->32 stub's return */
        /* the outermost of a run with the same return: a flat thunk not yet
         * connected re-enters itself through KRNL386 (kernel32 0xBFF718AE ->
         * 16-bit connect -> jmp far32 0xBFF718C7), and both come back to the
         * one 16-bit caller, whose C frame is the outer one's. Only when the
         * return sits in the same 16-bit frame: a window procedure that sends
         * a message to itself (USER 30:3D12 -> calc -> SendMessage -> 3D12)
         * nests stubs with the same return on other frames, and each must
         * come back to its own C frame */
        int k = g_nthk - 1;
        while (k > 0 && g_thk[k - 1].back == target) {
            if (g_thk[k - 1].ss != g_thk[k].ss || g_thk[k - 1].sp != g_thk[k].sp) {
                if (getenv("W16_TRACE")) fprintf(stderr, "[w16] stub %d and %d share return %04X:%04X but not its frame (%04X:%04X, %04X:%04X)\n", k - 1, k, target >> 16, target & 0xFFFF, g_thk[k - 1].ss, g_thk[k - 1].sp, g_thk[k].ss, g_thk[k].sp);
                break;
            }
            k--;
        }
        if (getenv("W16_TRACE")) fprintf(stderr, "[w16] stub %d returns to %04X:%04X (thread %lu)\n", k, target >> 16, target & 0xFFFF, GetCurrentThreadId());
        longjmp(g_thk[k].jb, 1);
    }
    uint16_t sel = (uint16_t)(target >> 16), off = (uint16_t)target;
    if (!g_w16_ready) { cpu_init(&g_w16); g_w16.mem = NULL; g_w16_ready = 1; segsel_init(); }
    CPU saved = g_w16, *c = &g_w16;
    c->eax = g_eax; c->ecx = g_ecx; c->edx = g_edx; c->ebx = g_ebx;
    c->esi = g_esi; c->edi = g_edi; c->ebp = g_ebp; c->esp = g_esp;
    c->ss = g_seg_ss; c->ds = g_seg_ds; c->es = g_seg_es; c->fs = g_seg_fs; c->gs = g_seg_gs; c->cs = sel;
    /* On a flat (big) stack the caller is kernel32 calling KRNL386's own
     * 32->16 entry (seg 1 +6582, through the table at KEXP+4): [esp] is its
     * flat return, and the 16-bit side comes back by an o32 retf to it
     * (w16_retf32 sees g_w16_ret and unwinds). Otherwise it is QT_Thunk's
     * 16-bit alias stack: the far return the callee's retf pops names a
     * stub's `jmp far 32:off`. */
    uint32_t cont, prev = g_w16_ret;
    int big = w16_ss_big(c->ss);
    /* kernel32's Call16 (0xBFF71414, gdi32's thunks) is the same o32 frame on the
     * 16-bit stack: [sp] a flat return, [sp+4] kernel32's cs */
    int flat16 = 0;
    if (!big) {
        uint32_t r = mem_read32(c, c->ss, c->sp);
        const uint8_t *b = (r >> 16) & 4 ? (const uint8_t *)(uintptr_t)(recomp_sel_base(r >> 16) + (r & 0xFFFF)) : NULL;
        flat16 = !(b && recomp_sel_base(r >> 16) && b[0] == 0x66 && b[1] == 0xEA)
                 && mem_read16(c, c->ss, (uint16_t)(c->sp + 4)) == g_seg_cs;
    }
    if (flat16) c->esp = c->sp;
    if (big || flat16) {
        cont = *(uint32_t *)(uintptr_t)(recomp_sel_base(c->ss) + c->esp);
        if (getenv("W16_TRACE")) fprintf(stderr, "[w16] enter %04X:%04X ss:esp %04X:%08X ds %04X fs %04X@%08X (+C %04X +E %04X +18 %08X +1C %04X) flat ret %08X\n", sel, off, c->ss, c->esp, c->ds, c->fs, recomp_sel_base(c->fs),
            mem_read16(c, c->fs, 0xC), mem_read16(c, c->fs, 0xE), mem_read32(c, c->fs, 0x18), mem_read16(c, c->fs, 0x1C), cont);
        if (getenv("W16_TRACE")) { const uint16_t *a = (const uint16_t *)(uintptr_t)(recomp_sel_base(c->ss) + c->esp + 8);
            fprintf(stderr, "[w16]   args %04X %04X %04X %04X %04X %04X %04X %04X\n", a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]); }
        g_w16_ret = cont;
    } else {
        uint32_t ret = mem_read32(c, c->ss, c->sp);
        if (getenv("W16_TRACE")) fprintf(stderr, "[w16] enter %04X:%04X ss:sp %04X:%04X ds %04X ret %08X args %04X %04X\n", sel, off, c->ss, c->sp, c->ds, ret,
            mem_read16(c, c->ss, (uint16_t)(c->sp + 4)), mem_read16(c, c->ss, (uint16_t)(c->sp + 6)));
        const uint8_t *stub = (const uint8_t *)(uintptr_t)(recomp_sel_base(ret >> 16) + (ret & 0xFFFF));
        if (stub[0] != 0x66 || stub[1] != 0xEA) w16_stop("thunk return is not a jmp far 32", ret >> 16, ret & 0xFFFF);
        memcpy(&cont, stub + 2, 4);
    }
    if (!w16_entry(c, seg_of(sel), off)) {
        const uint8_t *b = (const uint8_t *)(uintptr_t)(recomp_sel_base(sel) + off);
        fprintf(stderr, "[w16] %04X:%04X (base %08X):", sel, off, recomp_sel_base(sel));
        for (int i = 0; recomp_sel_base(sel) && i < 32; i++) fprintf(stderr, " %02X", b[i]);
        fprintf(stderr, "\n");
        w16_stop("no lifted function at", sel, off);
    }
    g_w16_ret = prev;
    g_eax = c->eax; g_ecx = c->ecx; g_edx = c->edx; g_ebx = c->ebx;
    g_esi = c->esi; g_edi = c->edi; g_ebp = c->ebp;
    if (big || flat16) {   /* the o32 retf popped cont and cs: put cont back for the lifted retf that called us */
        g_esp = (big ? c->esp : c->sp) - 8;
        *(uint32_t *)(uintptr_t)(g_ss_base + g_esp) = cont;
        *(uint32_t *)(uintptr_t)(g_ss_base + g_esp + 4) = 0;
        g_w16 = saved;
        return 1;
    }
    /* back at the stub's target, as its jmp would land: esp keeps the 16-bit
     * sp (QT_Thunk's tail rebuilds the flat esp from sp itself), and the
     * lifted retf that called us pops [esp] as the place to go next. */
    g_esp = (uint32_t)c->sp - 8;
    *(uint32_t *)(uintptr_t)(g_ss_base + g_esp) = cont;
    *(uint32_t *)(uintptr_t)(g_ss_base + g_esp + 4) = 0;
    g_w16 = saved;
    return 1;
}

/* A 16 -> 16 far call from the host: *r gives the registers (cs:ip the
 * target, ss:sp a stack), a dummy far return is pushed (the lifted retf
 * just pops it), and *r gets the registers back. For module entry points
 * (LibMain) the host runs before any thunk. */
int w16_call(CPU *r) {
    if (!g_w16_ready) { cpu_init(&g_w16); g_w16.mem = NULL; g_w16_ready = 1; segsel_init(); }
    CPU saved = g_w16;
    g_w16 = *r; g_w16.mem = NULL;
    if (getenv("W16_FN")) g_fncount = 1;
    if (getenv("W16_WSEL")) { g_watch_ds = 1; g_wsel = (uint16_t)strtoul(getenv("W16_WSEL"), 0, 16); }   /* a descriptor watch (recomp_fn_hit) */
    push16(&g_w16, 0); push16(&g_w16, 0);
    int okc = w16_entry(&g_w16, seg_of(r->cs), r->ip);
    *r = g_w16;
    g_w16 = saved;
    return okc;
}

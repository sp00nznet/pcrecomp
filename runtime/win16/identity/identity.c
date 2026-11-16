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
#include "cpu.h"
#define W16_PSP_PARA 0x1000   /* where the host puts KRNL386's PSP (w16test.c) */

int recomp_dispatch_lookup(CPU *cpu, uint16_t seg, uint16_t off);

/* the trace ring main.c keeps; only written here */
const char *g_fn_ring[RECOMP_FN_RING_SIZE];
unsigned g_fn_ring_pos;
int g_fncount, g_watch_ds;
uint16_t g_wsel;
void recomp_fn_hit(const char *n) { fprintf(stderr, "FN %s\n", n); }   /* g_fncount: W16_FN=1 */
void recomp_sel_write(uint16_t seg, uint16_t off, uint16_t val) { (void)seg; (void)off; (void)val; }

/* native32's registers (recomp32/recomp_types.h) and Win9x segment state (vxd32.c) */
extern uint32_t g_eax, g_ecx, g_edx, g_ebx, g_esp, g_ebp, g_esi, g_edi;
extern uint32_t g_ss_base;
extern uint16_t g_seg_ss, g_seg_ds, g_seg_es;

static void w16_stop(const char *what, unsigned a, unsigned b) {
    fprintf(stderr, "\n[w16] %s %04X:%04X; last functions:", what, a, b);
    for (int i = 8; i > 0; i--) {
        const char *n = g_fn_ring[(g_fn_ring_pos - (unsigned)i) & (RECOMP_FN_RING_SIZE - 1)];
        if (n) fprintf(stderr, " %s", n);
    }
    fprintf(stderr, "\n");
    fflush(stderr);
    exit(5);
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
uint32_t w16_real_base(void) {
    /* the launcher holds the range (native32_hold_range) before this
     * process's loader can put its own mappings there */
    if (!g_rm && !VirtualAlloc((void *)0x10000, 0x100000, MEM_COMMIT, PAGE_READWRITE) &&
        !VirtualAlloc((void *)0x10000, 0x100000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
        w16_stop("real-mode memory at 0x10000 is taken (native32_hold_range not called?)", GetLastError(), 0);
    g_rm = 1;
    return 0;
}
static uint16_t g_rm_sel[0x10000];   /* 0002 hands out one selector per paragraph */
static uint16_t rm_sel(uint16_t para) {
    if (!g_rm_sel[para]) g_rm_sel[para] = native32_w9x_alloc_sel(w16_real_base() + (uint32_t)para * 16, 0xFFFF);
    return g_rm_sel[para];
}

static void dpmi(CPU *c) {
    uint8_t *d = native32_w9x_desc(c->bx);
    switch (c->ax) {
    case 0x0000: {   /* allocate cx descriptors (consecutive: the allocator bumps) */
        uint16_t first = 0;
        if ((0x10000u - native32_w9x_next_sel()) / 8 < c->cx) { c->ax = 0x8011; c->flags |= FLAG_CF; return; }   /* descriptor unavailable */
        for (unsigned i = 0; i < c->cx; i++) { uint16_t s = native32_w9x_alloc_sel(0, 0); if (!i) first = s; }
        c->ax = first; ok(c); return;
    }
    case 0x0001: memset(d, 0, 8); ok(c); return;                       /* free descriptor */
    case 0x0002: c->ax = rm_sel(c->bx); ok(c); return;                /* real-mode segment to selector */
    case 0x0003: c->ax = 8; ok(c); return;                             /* selector increment */
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
    c->sp += 4;
    switch (off) {
    case H_DPMI_SWITCH:   /* already in protected mode: cs/ds/ss are selectors; es = the PSP's */
        c->es = rm_sel(W16_PSP_PARA); ok(c); return;
    case H_MSDOS_API:                    /* the "MS-DOS" vendor API (int 2Fh 168Ah) */
        if (c->ax == 0x100) { c->ax = native32_w9x_ldt_alias(); ok(c); return; }   /* LDT alias */
        break;
    }
    if (off == H_VXD + 0x2A) switch (c->ah) {   /* VWIN32's PM API, KRNL386's calls through DGROUP:1A80 */
    case 0x00: c->ax = 0x040A; ok(c); return;   /* version: KRNL386 wants >= 100h (4.10, Win98) */
    case 0x08: c->al = 0; ok(c); return;         /* -> DGROUP:1417, a flag read as "nonzero?" (ponytail: 0 until a caller needs 1) */
    case 0x03: {   /* VMM page services: args on the 16-bit stack, ecx bytes of them, which
                    * the entry removes (KRNL386 seg001_1FF7 pops what it pushed before them);
                    * result in eax */
        const uint32_t *a = (const uint32_t *)(uintptr_t)(recomp_sel_base(c->ss) + c->sp);
        void *p;
        c->sp = (uint16_t)(c->sp + c->cx);
        if (getenv("W16_TRACE")) fprintf(stderr, "[w16] VMM page service %u (%08X %08X %08X)\n", c->al, a[0], a[1], a[2]);
        switch (c->al) {
        case 0x00:   /* _PageReserve(page, npages, flags): PR_PRIVATE/SHARED/SYSTEM = anywhere */
            p = VirtualAlloc(a[0] >= 0x80000000u ? NULL : (void *)(uintptr_t)(a[0] << 12), a[1] << 12, MEM_RESERVE, PAGE_READWRITE);
            c->eax = p ? (uint32_t)(uintptr_t)p : 0xFFFFFFFFu; ok(c); return;
        case 0x01:   /* _PageCommit(page, npages, hpd, pagerdata, flags) */
            c->eax = VirtualAlloc((void *)(uintptr_t)(a[0] << 12), a[1] << 12, MEM_COMMIT, PAGE_READWRITE) != NULL; ok(c); return;
        case 0x02:   /* _PageDecommit(page, npages, flags) */
            c->eax = VirtualFree((void *)(uintptr_t)(a[0] << 12), a[1] << 12, MEM_DECOMMIT) != 0; ok(c); return;
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
            { 0x0021, "PAGEFILE", 0 },   /* KRNL386 seg001_BEF9: paging-file info (ax=1), optional */
            { 0x002A, "VWIN32", 1 },     /* KRNL386 seg001_7293: ah=0, then ah=8 -> al into DGROUP:1417; GlobalInit's caller needs it */
        };
        for (unsigned i = 0; i < sizeof vxd / sizeof *vxd; i++)
            if (vxd[i].id == c->bx) {   /* absent: 0:0; present: a tagged entry that stops when called */
                c->es = vxd[i].present ? host_sel() : 0;
                c->di = vxd[i].present ? (uint16_t)(H_VXD + c->bx) : 0;
                return;
            }
        break;
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
static uint32_t g_vec[256];          /* int 21h 25h/35h: what the guest set */

void dos_int21(CPU *c) {
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
    case 0x47:   /* current directory of drive dl at ds:si, no drive or leading '\': the root */
        *(char *)(uintptr_t)(recomp_sel_base(c->ds) + c->si) = 0; ok(c); return;
    case 0x50: ok(c); return;                                 /* set PSP */
    case 0x51: case 0x62: c->bx = rm_sel(W16_PSP_PARA); ok(c); return;
    }
    uint32_t s[8] = { g_eax, g_ecx, g_edx, g_ebx, g_esp, g_ebp, g_esi, g_edi };
    uint16_t sds = g_seg_ds, ses = g_seg_es;
    uint32_t in_dx = recomp_sel_base(c->ds) + c->dx, in_si = recomp_sel_base(c->ds) + c->si,
             in_di = recomp_sel_base(c->es) + c->di, in_bx = c->bx, in_cx = c->cx;
    g_ebx = in_bx; g_edx = in_dx; g_esi = in_si; g_edi = in_di;
    int cf = native32_w9x_int21(c->ax, in_cx);
    c->ax = (uint16_t)g_eax;
    if (g_ebx != in_bx) c->bx = (uint16_t)g_ebx;
    if (g_ecx != in_cx) c->cx = (uint16_t)g_ecx;
    if (g_edx != in_dx) c->dx = (uint16_t)g_edx;
    if (cf) c->flags |= FLAG_CF; else c->flags &= (uint16_t)~FLAG_CF;
    g_eax = s[0]; g_ecx = s[1]; g_edx = s[2]; g_ebx = s[3]; g_esp = s[4]; g_ebp = s[5]; g_esi = s[6]; g_edi = s[7];
    g_seg_ds = sds; g_seg_es = ses;
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

void dispatch_far(CPU *cpu, uint16_t sel, uint16_t off) {
    if (sel && sel == g_host_sel) { host_far(cpu, off); return; }
    if (!(sel & 4) || !recomp_dispatch_lookup(cpu, (uint16_t)(sel >> 3), off)) w16_stop("far call miss", sel, off);
}
void dispatch_near(CPU *cpu, uint16_t seg, uint16_t off) {   /* seg: the segment index */
    if (!recomp_dispatch_lookup(cpu, seg, off)) w16_stop("near call miss", seg, off);
}


static CPU g_w16;
static int g_w16_ready;

int w16_enter(uint32_t target) {
    uint16_t sel = (uint16_t)(target >> 16), off = (uint16_t)target;
    if (!g_w16_ready) { cpu_init(&g_w16); g_w16.mem = NULL; g_w16_ready = 1; }
    CPU saved = g_w16, *c = &g_w16;
    c->eax = g_eax; c->ecx = g_ecx; c->edx = g_edx; c->ebx = g_ebx;
    c->esi = g_esi; c->edi = g_edi; c->ebp = g_ebp; c->esp = g_esp;
    c->ss = g_seg_ss; c->ds = g_seg_ds; c->es = g_seg_es; c->cs = sel;
    /* the far return the callee's retf will pop: a stub's `jmp far 32:off` */
    uint32_t ret = mem_read32(c, c->ss, c->sp);
    if (getenv("W16_TRACE")) fprintf(stderr, "[w16] enter %04X:%04X ss:sp %04X:%04X ds %04X ret %08X\n", sel, off, c->ss, c->sp, c->ds, ret);
    const uint8_t *stub = (const uint8_t *)(uintptr_t)(recomp_sel_base(ret >> 16) + (ret & 0xFFFF));
    if (stub[0] != 0x66 || stub[1] != 0xEA) w16_stop("thunk return is not a jmp far 32", ret >> 16, ret & 0xFFFF);
    uint32_t cont;
    memcpy(&cont, stub + 2, 4);
    if (!recomp_dispatch_lookup(c, (uint16_t)(sel >> 3), off)) w16_stop("no lifted function at", sel, off);
    g_eax = c->eax; g_ecx = c->ecx; g_edx = c->edx; g_ebx = c->ebx;
    g_esi = c->esi; g_edi = c->edi; g_ebp = c->ebp;
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
    if (!g_w16_ready) { cpu_init(&g_w16); g_w16.mem = NULL; g_w16_ready = 1; }
    CPU saved = g_w16;
    g_w16 = *r; g_w16.mem = NULL;
    if (getenv("W16_FN")) g_fncount = 1;
    push16(&g_w16, 0); push16(&g_w16, 0);
    int okc = recomp_dispatch_lookup(&g_w16, (uint16_t)(r->cs >> 3), r->ip);
    *r = g_w16;
    g_w16 = saved;
    return okc;
}

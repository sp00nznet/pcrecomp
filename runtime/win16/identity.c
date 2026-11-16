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
#include "cpu.h"

int recomp_dispatch_lookup(CPU *cpu, uint16_t seg, uint16_t off);

/* the trace ring main.c keeps; only written here */
const char *g_fn_ring[RECOMP_FN_RING_SIZE];
unsigned g_fn_ring_pos;
int g_fncount, g_watch_ds;
uint16_t g_wsel;
void recomp_fn_hit(const char *n) { (void)n; }
void recomp_sel_write(uint16_t seg, uint16_t off, uint16_t val) { (void)seg; (void)off; (void)val; }

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
void dos_int21(CPU *cpu) { w16_stop("int 21h, ax", cpu->ax, cpu->bx); }

void dispatch_far(CPU *cpu, uint16_t sel, uint16_t off) {
    if (!(sel & 4) || !recomp_dispatch_lookup(cpu, (uint16_t)(sel >> 3), off)) w16_stop("far call miss", sel, off);
}
void dispatch_near(CPU *cpu, uint16_t seg, uint16_t off) {   /* seg: the segment index */
    if (!recomp_dispatch_lookup(cpu, seg, off)) w16_stop("near call miss", seg, off);
}

/* native32's registers (recomp32/recomp_types.h) and Win9x segment state (vxd32.c) */
extern uint32_t g_eax, g_ecx, g_edx, g_ebx, g_esp, g_ebp, g_esi, g_edi;
extern uint32_t g_ss_base;
extern uint16_t g_seg_ss, g_seg_ds, g_seg_es;

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

/* cpu.h - Win16 NE recompilation runtime.
 *
 * Upstreamed from catz/runtime/, which grew it, with the project prefix
 * neutralised to RECOMP_/recomp_ so any Win16 target can use it unchanged.
 * That prefix matches ne_lift.PREFIX's default, so lifted code links against
 * this header with no renaming. catz keeps its own CATZ_-prefixed copy for
 * now; it should converge onto this one.
 */
/*
 * cpu.h - CPU State and Runtime for El-Fish Static Recompilation
 *
 * Extends pcrecomp's cpu.h with:
 * - x87 FPU state (8-register stack, control/status words)
 * - NE segment support (segment selectors map to flat memory regions)
 * - TSXLIB runtime stubs
 *
 * El-Fish is a protected-mode NE executable, NOT a real-mode MZ.
 * Memory addressing uses segment selectors that map to flat memory
 * regions rather than real-mode seg<<4+off computation.
 */

#ifndef RECOMP_WIN16_CPU_H
#define RECOMP_WIN16_CPU_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include "mem_layout.h"

/* ── Function-entry trace ──
 * Always-on lightweight ring buffer of the last function names entered, so a
 * shim (e.g. the OOM MessageBox) can dump the recent call history to reveal
 * which lifted functions form a loop / hit an error path. One pointer store per
 * call. Opt into stderr-per-call with -DCATZ_TRACE_FN. */
#define RECOMP_FN_RING_BITS 12
#define RECOMP_FN_RING_SIZE (1u << RECOMP_FN_RING_BITS)
extern const char *g_fn_ring[RECOMP_FN_RING_SIZE];
extern unsigned g_fn_ring_pos;
void dump_fn_ring(int n);
#ifdef RECOMP_WATCH_SP
/* Function-entry stack-rise detector: flags the first time guest sp jumps UP
 * sharply (a callee returned with imbalanced sp) — pinpoints the bad epilogue/
 * purge. Defined in main.c (needs g_cpu). */
void recomp_sp_check(const char *nm);
#define TRACE_FN(n) do { g_fn_ring[(g_fn_ring_pos++) & (RECOMP_FN_RING_SIZE-1)] = (n); \
    recomp_sp_check(n); } while (0)
#elif defined(RECOMP_TRACE_FN)
#define TRACE_FN(n) do { g_fn_ring[(g_fn_ring_pos++) & (RECOMP_FN_RING_SIZE-1)] = (n); \
    fprintf(stderr, "FN %s\n", (n)); } while (0)
#else
extern int g_fncount;
extern int g_watch_ds;
void recomp_fn_hit(const char *n);
#define TRACE_FN(n) do { g_fn_ring[(g_fn_ring_pos++) & (RECOMP_FN_RING_SIZE-1)] = (n); if (g_fncount | g_watch_ds) recomp_fn_hit(n); } while (0)
#endif

/* ── Flag bits ─────────────────────────────────────────────── */

#define FLAG_CF  0x0001
#define FLAG_PF  0x0004
#define FLAG_AF  0x0010
#define FLAG_ZF  0x0040
#define FLAG_SF  0x0080
#define FLAG_TF  0x0100
#define FLAG_IF  0x0200
#define FLAG_DF  0x0400
#define FLAG_OF  0x0800

/* ── FPU constants ─────────────────────────────────────────── */

#define FPU_STACK_SIZE  8
#define FPU_C0  0x0100
#define FPU_C1  0x0200
#define FPU_C2  0x0400
#define FPU_C3  0x4000

/* ── CPU State ─────────────────────────────────────────────── */

typedef struct CPU {
    /* General-purpose registers */
    union { struct { uint8_t al, ah; }; uint16_t ax; uint32_t eax; };
    union { struct { uint8_t bl, bh; }; uint16_t bx; uint32_t ebx; };
    union { struct { uint8_t cl, ch; }; uint16_t cx; uint32_t ecx; };
    union { struct { uint8_t dl, dh; }; uint16_t dx; uint32_t edx; };

    /* Index and pointer registers (32-bit unions for 0x66 operand-size ops;
     * low 16 bits alias si/di/bp/sp, matching x86 semantics). */
    union { uint16_t si; uint32_t esi; };
    union { uint16_t di; uint32_t edi; };
    union { uint16_t bp; uint32_t ebp; };
    union { uint16_t sp; uint32_t esp; };

    /* Segment registers */
    uint16_t cs;
    uint16_t ds;
    uint16_t es;
    uint16_t ss;
    uint16_t fs;   /* 386 extra segment regs (push/pop fs/gs in context save/restore) */
    uint16_t gs;

    /* Instruction pointer (debug) */
    uint16_t ip;

    /* Flags register */
    uint16_t flags;

    /* x87 FPU state */
    double   st[FPU_STACK_SIZE];  /* FPU register stack */
    int      fpu_top;             /* Top-of-stack pointer (0-7) */
    uint16_t fpu_control;         /* FPU control word */
    uint16_t fpu_status;          /* FPU status word */
    uint16_t fpu_tag;             /* FPU tag word */

    /* Flat memory */
    uint8_t *mem;
    uint32_t mem_size;

    /* Selector -> flat base table (65536 entries). Segments 1..NUM_SEG come
     * from the static image layout; dynamically allocated selectors (TSXLIB
     * memory alloc) are filled in at runtime. */
    uint32_t *sel_base;
    uint32_t  heap_next;   /* bump allocator cursor (flat offset) */
    uint32_t  heap_end;    /* end of usable memory */
    uint16_t  next_sel;    /* next dynamic selector to hand out */

    /* Emulated BIOS timer tick (0040:006C), advanced on each read so the
     * game's timer wait/calibration loops make progress. */
    uint32_t  bios_ticks;

    /* DOS file handle table (host FILE* per handle; 0..4 reserved). */
    void     *files[256];

    /* Halt flag */
    int halted;
} CPU;

/* Print the guest call stack. Defined in main.c. */
void dump_guest_stack(CPU *cpu, int max);

/* Reached a branch whose target the decoder never resolved, so it has no
 * lifted code (see ne_lift). Reports and exits. Defined in main.c — NOT in
 * runtime_api.h, which gen_win16_stubs.py regenerates. */
/* Entry trace. A lifted guest loop spanning function boundaries is host
 * recursion, so a crash 30,000 calls deep has no readable backtrace -- it blows
 * the stack long before you can read one. Each lifted body announces itself into
 * a ring buffer that is dumped when the C stack gets too deep, which turns "it
 * died somewhere" into the repeating cycle itself.
 *
 * Off unless the project is built with RECOMP_TRACE; then it is one call and one
 * compare per lifted function. Same contract as runtime/recomp16/cpu.h, which is
 * where this comes from -- catz's fork dropped it and every lifted body still
 * emits RECOMP_ENTER, so the header has to carry it. */
#ifdef RECOMP_TRACE
void recomp_enter(const char *fn);
void recomp_trace_dump(const char *why);
#define RECOMP_ENTER(name) recomp_enter(name)
#else
#define RECOMP_ENTER(name) ((void)0)
#endif

void recomp_unreachable(const char *seg, unsigned off);

/* Reported by the bpguard instrumentation when a callee returns with bp
 * changed (bp is callee-saved in every Borland Win16 frame). */
void recomp_bp_broke(const char *callee, uint16_t bp0, uint16_t bp1, uint16_t sp0, uint16_t sp1);
void recomp_ds_broke(const char *callee, uint16_t ds0, uint16_t ds1);
void recomp_sp_broke(const char *callee, uint16_t sp0, uint16_t sp1);
/* A guest divide by zero would #DE on real hardware; the host must not die
   silently instead. Guarded in the lifted code, reported once per kind here. */
void recomp_div0(const char *kind);

/* Where the current run of ds==0 began (main.c); always available. */
extern const char *g_ds_zero_from;
extern unsigned g_ds_run;

/* ── Memory access ─────────────────────────────────────────── */

/*
 * Protected-mode selector translation. The lifter normalizes every relocated
 * selector to its NE segment index (SEG_n == n); gen_image.py places each
 * segment at SEG_SEGMENT_BASE[n] in the flat image, copied into cpu->sel_base
 * at startup. Dynamically allocated selectors (TSXLIB memory alloc) get fresh
 * entries in sel_base. Unmapped selectors point at an isolated guard region.
 */
static inline uint32_t seg_off(CPU *cpu, uint16_t seg, uint16_t off) {
    return cpu->sel_base[seg] + off;
}

/* LAR/LSL: protected-mode selector queries the engine uses to validate a far
 * pointer before dereferencing it (e.g. Borland's per-instance record guard:
 * `lar ax,[sel]; jne bad; and ax,0x800; jne bad` -- proceed only if the
 * selector is valid AND a data segment). In our flat model a selector is valid
 * iff it maps to a real/allocated segment (its base isn't the guard region).
 * Returns 1 (valid) and fills *out, else 0. cpu_lar reports data-segment access
 * rights (0x9300: present, DPL0, data, writable -- executable bit 0x800 clear);
 * cpu_lsl reports a full 64K segment limit. */
static inline int cpu_lar(CPU *cpu, uint16_t sel, uint16_t *out) {
    if (sel == 0 || cpu->sel_base[sel] == RECOMP_GUARD_BASE) return 0;
    *out = 0x9300;
    return 1;
}
static inline int cpu_lsl(CPU *cpu, uint16_t sel, uint16_t *out) {
    if (sel == 0 || cpu->sel_base[sel] == RECOMP_GUARD_BASE) return 0;
    *out = 0xFFFF;
    return 1;
}

static inline uint8_t mem_read8(CPU *cpu, uint16_t seg, uint16_t off) {
    return cpu->mem[seg_off(cpu, seg, off)];
}

/* Write watchpoint: set RECOMP_WATCH=seg:off (hex) to get a host backtrace at
 * every write to that guest address. Finding "who filled this struct field with
 * garbage" by grepping the lifted code does not converge — struct offsets repeat
 * across unrelated classes — but a watchpoint names the writer in one run. */
#ifdef RECOMP_WATCH_MEM
extern uint16_t g_watch_seg, g_watch_off;
extern int g_watch_armed;
void recomp_watch_hit(uint16_t seg, uint16_t off, uint16_t val);
/* Gate the watchpoint to one frame's lifetime: stack slots alias across frames,
   so an ungated watch on a `ss:[bp-N]` slot reports mostly unrelated writers.
   Arm at the prologue that stores the slot, disarm where it is read back. */
void recomp_watch_frame(uint16_t seg, uint16_t off, int on);
#define RECOMP_WATCH_CHECK(s, o, v) \
    do { if ((s) == g_watch_seg && (o) == g_watch_off) recomp_watch_hit((s), (o), (v)); } while (0)
#else
#define RECOMP_WATCH_CHECK(s, o, v) ((void)0)
#define recomp_watch_frame(s, o, n) ((void)0)
#endif

/* Selector watch: attribute every byte written into a given selector (and its
   next tile) to the most recently entered function, so we can see who actually
   rasterises into a surface -- and who only clears it. */
extern uint16_t g_wsel;
void recomp_sel_write(uint16_t seg, uint16_t off, uint16_t val);
#define RECOMP_SELW(s, o, v) do { if (g_wsel == 0xFFFFu) recomp_sel_write((s), 0, (v)); else if (g_wsel && ((s) == g_wsel || (s) == (uint16_t)(g_wsel + 1))) recomp_sel_write((s), (o), (v)); } while (0)

static inline void mem_write8(CPU *cpu, uint16_t seg, uint16_t off, uint8_t val) {
    RECOMP_WATCH_CHECK(seg, off, val);
    RECOMP_SELW(seg, off, val);
    cpu->mem[seg_off(cpu, seg, off)] = val;
}

static inline uint16_t mem_read16(CPU *cpu, uint16_t seg, uint16_t off) {
    /* Absolute/BIOS-data selector 0xFFFF: emulate the 0040:006C timer tick so
     * the game's timer wait and speed-calibration loops terminate. */
    if (seg == 0xFFFF) {
        if (off == 0x6C) return (uint16_t)(cpu->bios_ticks++);
        if (off == 0x6E) return (uint16_t)(cpu->bios_ticks >> 16);
    }
    uint32_t addr = seg_off(cpu, seg, off);
    return (uint16_t)cpu->mem[addr] | ((uint16_t)cpu->mem[addr + 1] << 8);
}

static inline void mem_write16(CPU *cpu, uint16_t seg, uint16_t off, uint16_t val) {
    uint32_t addr = seg_off(cpu, seg, off);
    RECOMP_WATCH_CHECK(seg, off, val);
    RECOMP_SELW(seg, off, val);
#ifdef RECOMP_WATCH_EXC
    {   /* Stack-overflow detector: log the first time sp descends below a low
         * watermark — catches whatever is consuming the stack toward underflow. */
        static int _logged = 0;
        if (!_logged && cpu->sp != 0 && cpu->sp < 0x0600) {
            _logged = 1;
            fprintf(stderr, "[STACK-LOW] sp=%04X — histogram of the drain loop:\n", cpu->sp);
            dump_fn_ring(0);
        }
    }
    if (seg == 0x42 && (off == 0x14 || (off >= 0xFFBC && off <= 0xFFC0))) {
        fprintf(stderr, "[exc] ss:[%04X] <- %04X  (sp=%04X) ring:", off, val, cpu->sp);
        for (int _i = 16; _i > 0; _i--) {
            const char *nm = g_fn_ring[(g_fn_ring_pos - (unsigned)_i) & (RECOMP_FN_RING_SIZE - 1)];
            if (nm) fprintf(stderr, " %s", nm + 3);   /* skip "seg" prefix */
        }
        fprintf(stderr, "\n");
    }
#endif
    cpu->mem[addr] = (uint8_t)(val & 0xFF);
    cpu->mem[addr + 1] = (uint8_t)(val >> 8);
}

static inline uint32_t mem_read32(CPU *cpu, uint16_t seg, uint16_t off) {
    return (uint32_t)mem_read16(cpu, seg, off) |
           ((uint32_t)mem_read16(cpu, seg, off + 2) << 16);
}

static inline void mem_write32(CPU *cpu, uint16_t seg, uint16_t off, uint32_t val) {
    mem_write16(cpu, seg, off, (uint16_t)(val & 0xFFFF));
    mem_write16(cpu, seg, off + 2, (uint16_t)(val >> 16));
}

/* ── Stack operations ──────────────────────────────────────── */

static inline void push16(CPU *cpu, uint16_t val) {
    cpu->sp -= 2;
    mem_write16(cpu, cpu->ss, cpu->sp, val);
}

static inline uint16_t pop16(CPU *cpu) {
    uint16_t val = mem_read16(cpu, cpu->ss, cpu->sp);
    cpu->sp += 2;
    return val;
}

/* 32-bit stack ops (operand-size 0x66 prefix). SP is still 16-bit. */
static inline void push32(CPU *cpu, uint32_t val) {
    cpu->sp -= 4;
    mem_write32(cpu, cpu->ss, cpu->sp, val);
}

static inline uint32_t pop32(CPU *cpu) {
    uint32_t val = mem_read32(cpu, cpu->ss, cpu->sp);
    cpu->sp += 4;
    return val;
}

/* ── Flag helpers ──────────────────────────────────────────── */

static inline int parity8(uint8_t v) {
    v ^= v >> 4; v ^= v >> 2; v ^= v >> 1;
    return (~v) & 1;
}

static inline void set_szp8(CPU *cpu, uint8_t r) {
    cpu->flags &= ~(FLAG_SF | FLAG_ZF | FLAG_PF);
    if (r & 0x80) cpu->flags |= FLAG_SF;
    if (r == 0)   cpu->flags |= FLAG_ZF;
    if (parity8(r)) cpu->flags |= FLAG_PF;
}

static inline void set_szp16(CPU *cpu, uint16_t r) {
    cpu->flags &= ~(FLAG_SF | FLAG_ZF | FLAG_PF);
    if (r & 0x8000) cpu->flags |= FLAG_SF;
    if (r == 0)     cpu->flags |= FLAG_ZF;
    if (parity8((uint8_t)r)) cpu->flags |= FLAG_PF;
}

static inline uint8_t flags_add8(CPU *cpu, uint8_t a, uint8_t b) {
    uint16_t r = (uint16_t)a + b;
    uint8_t result = (uint8_t)r;
    cpu->flags &= ~(FLAG_CF | FLAG_OF | FLAG_AF);
    if (r > 0xFF) cpu->flags |= FLAG_CF;
    if (((a ^ result) & (b ^ result)) & 0x80) cpu->flags |= FLAG_OF;
    if (((a ^ b ^ result) & 0x10)) cpu->flags |= FLAG_AF;
    set_szp8(cpu, result);
    return result;
}

static inline uint16_t flags_add16(CPU *cpu, uint16_t a, uint16_t b) {
    uint32_t r = (uint32_t)a + b;
    uint16_t result = (uint16_t)r;
    cpu->flags &= ~(FLAG_CF | FLAG_OF | FLAG_AF);
    if (r > 0xFFFF) cpu->flags |= FLAG_CF;
    if (((a ^ result) & (b ^ result)) & 0x8000) cpu->flags |= FLAG_OF;
    if (((a ^ b ^ result) & 0x10)) cpu->flags |= FLAG_AF;
    set_szp16(cpu, result);
    return result;
}

static inline uint8_t flags_sub8(CPU *cpu, uint8_t a, uint8_t b) {
    uint16_t r = (uint16_t)a - b;
    uint8_t result = (uint8_t)r;
    cpu->flags &= ~(FLAG_CF | FLAG_OF | FLAG_AF);
    if (a < b) cpu->flags |= FLAG_CF;
    if (((a ^ b) & (a ^ result)) & 0x80) cpu->flags |= FLAG_OF;
    if (((a ^ b ^ result) & 0x10)) cpu->flags |= FLAG_AF;
    set_szp8(cpu, result);
    return result;
}

static inline uint16_t flags_sub16(CPU *cpu, uint16_t a, uint16_t b) {
    uint32_t r = (uint32_t)a - b;
    uint16_t result = (uint16_t)r;
    cpu->flags &= ~(FLAG_CF | FLAG_OF | FLAG_AF);
    if (a < b) cpu->flags |= FLAG_CF;
    if (((a ^ b) & (a ^ result)) & 0x8000) cpu->flags |= FLAG_OF;
    if (((a ^ b ^ result) & 0x10)) cpu->flags |= FLAG_AF;
    set_szp16(cpu, result);
    return result;
}

static inline void flags_cmp8(CPU *cpu, uint8_t a, uint8_t b)  { flags_sub8(cpu, a, b); }
static inline void flags_cmp16(CPU *cpu, uint16_t a, uint16_t b) { flags_sub16(cpu, a, b); }

static inline void flags_logic8(CPU *cpu, uint8_t r) {
    cpu->flags &= ~(FLAG_CF | FLAG_OF);
    set_szp8(cpu, r);
}

static inline void flags_logic16(CPU *cpu, uint16_t r) {
    cpu->flags &= ~(FLAG_CF | FLAG_OF);
    set_szp16(cpu, r);
}

static inline void flags_shift8(CPU *cpu, uint8_t r)  { set_szp8(cpu, r); }
static inline void flags_shift16(CPU *cpu, uint16_t r) { set_szp16(cpu, r); }

/* ── 32-bit flag helpers (operand-size 0x66 prefix) ────────── */

static inline void set_szp32(CPU *cpu, uint32_t r) {
    cpu->flags &= ~(FLAG_SF | FLAG_ZF | FLAG_PF);
    if (r & 0x80000000u) cpu->flags |= FLAG_SF;
    if (r == 0)          cpu->flags |= FLAG_ZF;
    if (parity8((uint8_t)r)) cpu->flags |= FLAG_PF;
}

static inline uint32_t flags_add32(CPU *cpu, uint32_t a, uint32_t b) {
    uint64_t r = (uint64_t)a + b;
    uint32_t result = (uint32_t)r;
    cpu->flags &= ~(FLAG_CF | FLAG_OF | FLAG_AF);
    if (r > 0xFFFFFFFFu) cpu->flags |= FLAG_CF;
    if (((a ^ result) & (b ^ result)) & 0x80000000u) cpu->flags |= FLAG_OF;
    if (((a ^ b ^ result) & 0x10)) cpu->flags |= FLAG_AF;
    set_szp32(cpu, result);
    return result;
}

static inline uint32_t flags_sub32(CPU *cpu, uint32_t a, uint32_t b) {
    uint32_t result = a - b;
    cpu->flags &= ~(FLAG_CF | FLAG_OF | FLAG_AF);
    if (a < b) cpu->flags |= FLAG_CF;
    if (((a ^ b) & (a ^ result)) & 0x80000000u) cpu->flags |= FLAG_OF;
    if (((a ^ b ^ result) & 0x10)) cpu->flags |= FLAG_AF;
    set_szp32(cpu, result);
    return result;
}

static inline void flags_cmp32(CPU *cpu, uint32_t a, uint32_t b) { flags_sub32(cpu, a, b); }

static inline void flags_logic32(CPU *cpu, uint32_t r) {
    cpu->flags &= ~(FLAG_CF | FLAG_OF);
    set_szp32(cpu, r);
}

static inline void flags_shift32(CPU *cpu, uint32_t r) { set_szp32(cpu, r); }

/* ── Flag test helpers ─────────────────────────────────────── */

static inline int cf(CPU *cpu) { return (cpu->flags & FLAG_CF) != 0; }
static inline int zf(CPU *cpu) { return (cpu->flags & FLAG_ZF) != 0; }
static inline int sf(CPU *cpu) { return (cpu->flags & FLAG_SF) != 0; }
static inline int of(CPU *cpu) { return (cpu->flags & FLAG_OF) != 0; }
static inline int pf(CPU *cpu) { return (cpu->flags & FLAG_PF) != 0; }
static inline int af(CPU *cpu) { return (cpu->flags & FLAG_AF) != 0; }
static inline int df(CPU *cpu) { return (cpu->flags & FLAG_DF) != 0; }

/* ── Condition code tests ──────────────────────────────────── */

static inline int cc_o(CPU *cpu)  { return of(cpu); }
static inline int cc_no(CPU *cpu) { return !of(cpu); }
static inline int cc_b(CPU *cpu)  { return cf(cpu); }
static inline int cc_ae(CPU *cpu) { return !cf(cpu); }
static inline int cc_e(CPU *cpu)  { return zf(cpu); }
static inline int cc_ne(CPU *cpu) { return !zf(cpu); }
static inline int cc_be(CPU *cpu) { return cf(cpu) || zf(cpu); }
static inline int cc_a(CPU *cpu)  { return !cf(cpu) && !zf(cpu); }
static inline int cc_s(CPU *cpu)  { return sf(cpu); }
static inline int cc_ns(CPU *cpu) { return !sf(cpu); }
static inline int cc_p(CPU *cpu)  { return pf(cpu); }
static inline int cc_np(CPU *cpu) { return !pf(cpu); }
static inline int cc_l(CPU *cpu)  { return sf(cpu) != of(cpu); }
static inline int cc_ge(CPU *cpu) { return sf(cpu) == of(cpu); }
static inline int cc_le(CPU *cpu) { return zf(cpu) || (sf(cpu) != of(cpu)); }
static inline int cc_g(CPU *cpu)  { return !zf(cpu) && (sf(cpu) == of(cpu)); }

/* ── FPU operations ────────────────────────────────────────── */

static inline void fpu_init(CPU *cpu) {
    memset(cpu->st, 0, sizeof(cpu->st));
    cpu->fpu_top = 0;
    cpu->fpu_control = 0x037F;  /* Default: all exceptions masked, round to nearest */
    cpu->fpu_status = 0;
    cpu->fpu_tag = 0xFFFF;      /* All registers empty */
}

static inline void fpu_push(CPU *cpu) {
    cpu->fpu_top = (cpu->fpu_top - 1) & 7;
    /* Shift logical stack: st[7] is lost, everything moves up */
    for (int i = 7; i > 0; i--)
        cpu->st[i] = cpu->st[i - 1];
    cpu->st[0] = 0.0;
}

static inline void fpu_pop(CPU *cpu) {
    for (int i = 0; i < 7; i++)
        cpu->st[i] = cpu->st[i + 1];
    cpu->st[7] = 0.0;
    cpu->fpu_top = (cpu->fpu_top + 1) & 7;
}

/* FPREM: ST(0) = ST(0) - ST(1)*trunc(ST(0)/ST(1)), with the low three bits of
   the quotient reported in C1/C3/C0. This is how the C runtime's sin/cos reduce
   their argument, so without it every angle past +-pi/2 came back with the wrong
   sign -- the ball rotation tables were unusable. The real 8087 reduces at most
   2^63 per execution and sets C2 to ask for another round; a full reduction in
   one step is exact here and simply reports C2 = 0 (done). */
static inline void fpu_prem(CPU *cpu) {
    double a = cpu->st[0], b = cpu->st[1];
    cpu->fpu_status &= ~(FPU_C0 | FPU_C1 | FPU_C2 | FPU_C3);
    if (b == 0.0 || a != a || b != b || a == a * 2.0) {   /* /0, NaN, or inf */
        cpu->fpu_status |= FPU_C2;
        cpu->st[0] = a - a;                               /* NaN */
        return;
    }
    double q = a / b;
    q = (q < 0.0) ? ceil(q) : floor(q);                   /* truncate toward 0 */
    cpu->st[0] = a - b * q;
    unsigned long long qi = (unsigned long long)(q < 0.0 ? -q : q);
    if (qi & 1u) cpu->fpu_status |= FPU_C1;
    if (qi & 2u) cpu->fpu_status |= FPU_C3;
    if (qi & 4u) cpu->fpu_status |= FPU_C0;
}

/* FXAM: classify ST(0) into C3/C2/C0, sign into C1. */
static inline void fpu_xam(CPU *cpu) {
    double v = cpu->st[0];
    cpu->fpu_status &= ~(FPU_C0 | FPU_C1 | FPU_C2 | FPU_C3);
    if (v < 0.0 || (v == 0.0 && 1.0 / v < 0.0)) cpu->fpu_status |= FPU_C1;
    if (v != v) {
        cpu->fpu_status |= FPU_C0;                        /* NaN */
    } else if (v == 0.0) {
        cpu->fpu_status |= FPU_C3;                        /* zero */
    } else if (v == v * 2.0) {
        cpu->fpu_status |= FPU_C0 | FPU_C2;               /* infinity */
    } else {
        cpu->fpu_status |= FPU_C2;                        /* normal finite */
    }
}

/* x87 condition codes live in the status word only -- no x87 instruction
   writes AH. Mirroring them into AH here clobbered the sign bit the C
   runtime's sin() stashes there across its argument reduction, so every
   negative angle came back with the wrong sign. FSTSW AX is the only path.  */
static inline void fpu_compare(CPU *cpu, double a, double b) {
    cpu->fpu_status &= ~(FPU_C0 | FPU_C2 | FPU_C3);
    if (a != a || b != b) {
        /* NaN: unordered */
        cpu->fpu_status |= FPU_C0 | FPU_C2 | FPU_C3;
    } else if (a > b) {
        /* Nothing set */
    } else if (a < b) {
        cpu->fpu_status |= FPU_C0;
    } else {
        /* Equal */
        cpu->fpu_status |= FPU_C3;
    }
}

/* FPU memory read/write helpers (placeholder - uses seg:off addressing) */
static inline double fpu_read_f32(CPU *cpu, uint16_t seg, uint16_t off) {
    uint32_t bits = mem_read32(cpu, seg, off);
    float f;
    memcpy(&f, &bits, sizeof(f));
    return (double)f;
}

static inline double fpu_read_f64(CPU *cpu, uint16_t seg, uint16_t off) {
    uint32_t lo = mem_read32(cpu, seg, off);
    uint32_t hi = mem_read32(cpu, seg, off + 4);
    uint64_t bits = (uint64_t)lo | ((uint64_t)hi << 32);
    double d;
    memcpy(&d, &bits, sizeof(d));
    return d;
}

static inline void fpu_write_f32(CPU *cpu, uint16_t seg, uint16_t off, double val) {
    float f = (float)val;
    uint32_t bits;
    memcpy(&bits, &f, sizeof(bits));
    mem_write32(cpu, seg, off, bits);
}

static inline void fpu_write_f64(CPU *cpu, uint16_t seg, uint16_t off, double val) {
    uint64_t bits;
    memcpy(&bits, &val, sizeof(bits));
    mem_write32(cpu, seg, off, (uint32_t)(bits & 0xFFFFFFFF));
    mem_write32(cpu, seg, off + 4, (uint32_t)(bits >> 32));
}

static inline int32_t fpu_read_i16(CPU *cpu, uint16_t seg, uint16_t off) {
    return (int32_t)(int16_t)mem_read16(cpu, seg, off);
}

static inline int32_t fpu_read_i32(CPU *cpu, uint16_t seg, uint16_t off) {
    return (int32_t)mem_read32(cpu, seg, off);
}

static inline void fpu_write_i16(CPU *cpu, uint16_t seg, uint16_t off, int32_t val) {
    mem_write16(cpu, seg, off, (uint16_t)(int16_t)val);
}

static inline void fpu_write_i32(CPU *cpu, uint16_t seg, uint16_t off, int32_t val) {
    mem_write32(cpu, seg, off, (uint32_t)val);
}

/* fild/fistp qword. The 64-bit forms were being lifted as 16-bit, so the C
   runtime's ftol wrote only the low word of its result and returned a stale
   DX -- every float-to-long in the engine came back garbage above 65535. */
/* 80-bit extended. These were read and written as plain doubles, which turned
   every tword constant into nonsense -- the C runtime keeps pi/4 (its sin/cos
   argument-reduction divisor) as a tword, so the reduction divided by garbage
   and every angle past the first octant came back with the wrong sign. */
static inline double fpu_read_f80(CPU *cpu, uint16_t seg, uint16_t off) {
    uint64_t m = (uint64_t)mem_read32(cpu, seg, off) |
                 ((uint64_t)mem_read32(cpu, seg, (uint16_t)(off + 4)) << 32);
    uint16_t se = mem_read16(cpu, seg, (uint16_t)(off + 8));
    int neg = (se >> 15) & 1;
    int exp = se & 0x7FFF;
    double v;
    if (exp == 0x7FFF)
        v = (m << 1) ? (double)NAN : (double)INFINITY;
    else if (exp == 0 && m == 0)
        v = 0.0;
    else                      /* explicit integer bit: value = m * 2^(exp-16383-63) */
        v = ldexp((double)m, (exp ? exp : 1) - 16383 - 63);
    return neg ? -v : v;
}

static inline void fpu_write_f80(CPU *cpu, uint16_t seg, uint16_t off, double v) {
    int neg = (v < 0.0) || (v == 0.0 && 1.0 / v < 0.0);
    double a = neg ? -v : v;
    uint16_t se;
    uint64_t m;
    if (a != a)            { se = 0x7FFF; m = ~(uint64_t)0; }
    else if (a == a * 2.0 && a != 0.0) { se = 0x7FFF; m = (uint64_t)1 << 63; }
    else if (a == 0.0)     { se = 0; m = 0; }
    else {
        int e;
        double f = frexp(a, &e);          /* 0.5 <= f < 1 */
        m = (uint64_t)ldexp(f, 64);       /* 2^63 <= m < 2^64 */
        se = (uint16_t)(e - 1 + 16383);
    }
    if (neg) se |= 0x8000;
    mem_write32(cpu, seg, off, (uint32_t)(m & 0xFFFFFFFFu));
    mem_write32(cpu, seg, (uint16_t)(off + 4), (uint32_t)(m >> 32));
    mem_write16(cpu, seg, (uint16_t)(off + 8), se);
}

static inline int64_t fpu_read_i64(CPU *cpu, uint16_t seg, uint16_t off) {
    return (int64_t)((uint64_t)mem_read32(cpu, seg, off) |
                     ((uint64_t)mem_read32(cpu, seg, (uint16_t)(off + 4)) << 32));
}

static inline void fpu_write_i64(CPU *cpu, uint16_t seg, uint16_t off, int64_t val) {
    mem_write32(cpu, seg, off, (uint32_t)((uint64_t)val & 0xFFFFFFFFu));
    mem_write32(cpu, seg, (uint16_t)(off + 4), (uint32_t)((uint64_t)val >> 32));
}

/* ── CPU lifecycle ─────────────────────────────────────────── */

static inline void cpu_init(CPU *cpu) {
    memset(cpu, 0, sizeof(*cpu));
    cpu->flags = 0x0002;
    fpu_init(cpu);
}

static inline int cpu_alloc_mem(CPU *cpu, uint32_t size) {
    cpu->mem = (uint8_t *)calloc(1, size);
    cpu->mem_size = size;
    cpu->sel_base = (uint32_t *)malloc(65536u * sizeof(uint32_t));
    if (!cpu->mem || !cpu->sel_base) return 0;
    /* Default every selector to the guard region, then map the static image
     * segments (1..NUM_SEG) to their flat bases. */
    for (uint32_t s = 0; s < 65536u; s++)
        cpu->sel_base[s] = RECOMP_GUARD_BASE;
    for (int s = 0; s <= RECOMP_NUM_SEG; s++)
        cpu->sel_base[s] = SEG_SEGMENT_BASE[s];
    /* Dynamic heap lives past the loaded image; selectors start well above the
     * NE range to avoid colliding with raw/hardcoded selectors. */
    cpu->heap_next = (RECOMP_IMAGE_SIZE + 0xFu) & ~0xFu;
    cpu->heap_end = size;
    cpu->next_sel = 0x4000;
    return 1;
}

/* Allocate `bytes` from the flat heap and bind a fresh selector to it.
 * Returns the selector (0 on out-of-memory). The region is already zeroed. */
static inline uint16_t cpu_alloc_selector(CPU *cpu, uint32_t bytes) {
    uint32_t base = (cpu->heap_next + 0xFu) & ~0xFu;
    if (bytes == 0) bytes = 16;
    if (base + bytes > cpu->heap_end || cpu->next_sel == 0)
        return 0;
    cpu->heap_next = base + bytes;
    uint16_t sel = cpu->next_sel++;
    cpu->sel_base[sel] = base;
    /* Blocks larger than a segment need TILED selectors, the way Win16 hands
     * back a huge block: sel addresses the first 64 KB, sel+1 the next, and so
     * on, and guest code walking past 0xFFFF increments the selector. Without
     * the tiles a 1024x640 WinG surface (655,360 bytes) was reachable only for
     * its first 65,536 -- exactly 64 scanlines -- so everything the engine drew
     * below that wrapped back over the top of the same surface. */
    for (uint32_t off = 0x10000u; off < bytes; off += 0x10000u) {
        if (cpu->next_sel == 0) break;
        uint16_t tile = cpu->next_sel++;
        cpu->sel_base[tile] = base + off;
    }
    return sel;
}

static inline void cpu_free(CPU *cpu) {
    free(cpu->mem);
    free(cpu->sel_base);
    cpu->mem = NULL;
    cpu->sel_base = NULL;
}

/* ── Port I/O stubs ────────────────────────────────────────── */

static inline uint8_t port_in8(CPU *cpu, uint16_t port) {
    (void)cpu; (void)port;
    return 0;
}

static inline void port_out8(CPU *cpu, uint16_t port, uint8_t val) {
    (void)cpu; (void)port; (void)val;
}


/* ---- Ported from runtime/recomp16/cpu.h ----
 * catz's fork of this header predates these and dropped them, but the lifter
 * emits all of them: ADC/SBB with carry-in, AAA/AAS, and the loop back-edge
 * tick. One source of truth for the semantics; see recomp16/cpu.h for why
 * flags_adc is not flags_add16(a, b + cf). */

static inline uint32_t flags_adc(CPU *cpu, uint32_t a, uint32_t b, int bits)
{
    uint32_t mask   = (bits == 32) ? 0xFFFFFFFFu : ((1u << bits) - 1u);
    uint32_t sign   = 1u << (bits - 1);
    uint64_t c      = (cpu->flags & FLAG_CF) ? 1u : 0u;
    uint64_t wide   = (uint64_t)(a & mask) + (uint64_t)(b & mask) + c;
    uint32_t result = (uint32_t)wide & mask;

    a &= mask; b &= mask;
    cpu->flags &= ~(FLAG_CF | FLAG_OF | FLAG_AF | FLAG_SF | FLAG_ZF | FLAG_PF);
    if (wide > (uint64_t)mask)              cpu->flags |= FLAG_CF;
    if ((~(a ^ b) & (a ^ result)) & sign)   cpu->flags |= FLAG_OF;
    if ((a ^ b ^ result) & 0x10)            cpu->flags |= FLAG_AF;
    if (result == 0)                        cpu->flags |= FLAG_ZF;
    if (result & sign)                      cpu->flags |= FLAG_SF;
    if (parity8((uint8_t)result))           cpu->flags |= FLAG_PF;
    return result;
}

static inline uint32_t flags_sbb(CPU *cpu, uint32_t a, uint32_t b, int bits)
{
    uint32_t mask   = (bits == 32) ? 0xFFFFFFFFu : ((1u << bits) - 1u);
    uint32_t sign   = 1u << (bits - 1);
    uint64_t c      = (cpu->flags & FLAG_CF) ? 1u : 0u;
    uint32_t result;

    a &= mask; b &= mask;
    result = (uint32_t)((uint64_t)a - (uint64_t)b - c) & mask;
    cpu->flags &= ~(FLAG_CF | FLAG_OF | FLAG_AF | FLAG_SF | FLAG_ZF | FLAG_PF);
    if ((uint64_t)a < (uint64_t)b + c)      cpu->flags |= FLAG_CF;
    if (((a ^ b) & (a ^ result)) & sign)    cpu->flags |= FLAG_OF;
    if ((a ^ b ^ result) & 0x10)            cpu->flags |= FLAG_AF;
    if (result == 0)                        cpu->flags |= FLAG_ZF;
    if (result & sign)                      cpu->flags |= FLAG_SF;
    if (parity8((uint8_t)result))           cpu->flags |= FLAG_PF;
    return result;
}

static inline void bcd_daa(CPU *cpu)
{
    uint8_t old_al = cpu->al;
    int old_cf = (cpu->flags & FLAG_CF) != 0;

    cpu->flags &= ~FLAG_CF;
    if ((cpu->al & 0x0F) > 9 || (cpu->flags & FLAG_AF)) {
        cpu->al = (uint8_t)(cpu->al + 6);
        cpu->flags |= FLAG_AF;
    } else {
        cpu->flags &= ~FLAG_AF;
    }
    if (old_al > 0x99 || old_cf) {
        cpu->al = (uint8_t)(cpu->al + 0x60);
        cpu->flags |= FLAG_CF;
    }
    set_szp8(cpu, cpu->al);
}

static inline void bcd_das(CPU *cpu)
{
    uint8_t old_al = cpu->al;
    int old_cf = (cpu->flags & FLAG_CF) != 0;

    cpu->flags &= ~FLAG_CF;
    if ((cpu->al & 0x0F) > 9 || (cpu->flags & FLAG_AF)) {
        if (old_al < 6) cpu->flags |= FLAG_CF;   /* borrow out of AL - 6 */
        if (old_cf)     cpu->flags |= FLAG_CF;
        cpu->al = (uint8_t)(cpu->al - 6);
        cpu->flags |= FLAG_AF;
    } else {
        cpu->flags &= ~FLAG_AF;
    }
    if (old_al > 0x99 || old_cf) {
        cpu->al = (uint8_t)(cpu->al - 0x60);
        cpu->flags |= FLAG_CF;
    }
    set_szp8(cpu, cpu->al);
}

static inline void bcd_aam(CPU *cpu, uint8_t base)
{
    if (base == 0) return;
    cpu->ah = (uint8_t)(cpu->al / base);
    cpu->al = (uint8_t)(cpu->al % base);
    set_szp8(cpu, cpu->al);
}

static inline void bcd_aad(CPU *cpu, uint8_t base)
{
    cpu->al = (uint8_t)(cpu->al + cpu->ah * base);
    cpu->ah = 0;
    set_szp8(cpu, cpu->al);
}

static inline void bcd_aaa(CPU *cpu)
{
    if ((cpu->al & 0x0F) > 9 || (cpu->flags & FLAG_AF)) {
        /* AX += 106h, not AL += 6 and AH += 1 separately: the carry out of AL
           propagates into AH, so AL = 0FFh lands on AH + 2. */
        cpu->ax = (uint16_t)(cpu->ax + 0x106);
        cpu->flags |= (FLAG_AF | FLAG_CF);
    } else {
        cpu->flags &= ~(FLAG_AF | FLAG_CF);
    }
    cpu->al &= 0x0F;
}

static inline void bcd_aas(CPU *cpu)
{
    if ((cpu->al & 0x0F) > 9 || (cpu->flags & FLAG_AF)) {
        /* AX -= 106h for the same reason: a borrow out of AL takes AH with it. */
        cpu->ax = (uint16_t)(cpu->ax - 0x106);
        cpu->flags |= (FLAG_AF | FLAG_CF);
    } else {
        cpu->flags &= ~(FLAG_AF | FLAG_CF);
    }
    cpu->al &= 0x0F;
}

#ifdef RECOMP_IRQ
extern int g_recomp_tick_budget;
void recomp_tick(CPU *cpu);
#define RECOMP_TICK(cpu) do { if (--g_recomp_tick_budget <= 0) recomp_tick(cpu); } while (0)
#else
#define RECOMP_TICK(cpu) ((void)0)
#endif

/* 16-bit port I/O, same stub contract as the 8-bit pair above. `outsw`/`insw`
 * in the lifted stream need these; VBRUN300 has 35 such sites. */
static inline uint16_t port_in16(CPU *cpu, uint16_t port) {
    (void)cpu; (void)port;
    return 0;
}

static inline void port_out16(CPU *cpu, uint16_t port, uint16_t val) {
    (void)cpu; (void)port; (void)val;
}

#endif /* RECOMP_WIN16_CPU_H */

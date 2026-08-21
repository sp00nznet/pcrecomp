/*
 * cpu.h - runtime for the CPU-struct x86-32 recompilation model
 *         (paired with tools/lift/lift32_cpu.py).
 *
 * Lifted x86 functions operate on an explicit CPU state struct, so several
 * machine states can be live at once - which is what a hybrid build needs when
 * real library code calls back into lifted code while an outer lifted call is
 * still on the stack. See runtime/hybrid/.
 *
 * The recomp runs as a 32-bit program so register values are real 32-bit host
 * pointers: the image's data sections live at their mapped VAs and heap comes
 * from malloc - both inside the 32-bit address space - so memory operands
 * dereference directly.
 *
 * Flags are computed eagerly by helpers after arithmetic/logic ops; Jcc reads
 * the stored bits. This is verbose but mechanical and easy to verify against
 * the hardware. (A lazy-flags optimization can come later.)
 */
#ifndef PCRECOMP_CPU_H
#define PCRECOMP_CPU_H

#include <stdint.h>
#include <string.h>
#if defined(_MSC_VER)
#include <intrin.h>   /* __readfsdword/__writefsdword: TIB-relative (fs:) access for SEH */
#endif

typedef struct {
    uint32_t eax, ecx, edx, ebx, esp, ebp, esi, edi;
    uint32_t eip;
    /* flags as discrete bits (0/1) */
    uint32_t cf, zf, sf, of, pf, af;
    /* x87: register-stack of doubles. st0 == st[fpu_top]; push pre-decrements. */
    double   st[8];
    int      fpu_top;
    uint32_t fpu_sw;   /* status word: only C0/C1/C2/C3 condition bits modelled */
    /* Segment registers: stored, but NOT used in address computation. The
     * memory model below is flat - a register holds a real 32-bit address - so
     * `mov ds, ax` records the selector and does nothing else. That is right
     * for code that only saves and restores them, which is the common case even
     * in segmented 32-bit code, and wrong for code that switches DS to reach
     * another segment's data. The latter needs a selector -> base mapping the
     * runtime does not have; such code should be caught rather than lifted
     * silently. */
    uint16_t cs, ds, es, fs, gs, ss;
} CPU;

/* ---- partial register access (preserve unaffected bits, like x86) ---- */
#define R8L(r)        ((uint8_t)(r))
#define R8H(r)        ((uint8_t)((r) >> 8))
#define R16(r)        ((uint16_t)(r))
#define SET8L(r, v)   ((r) = ((r) & 0xFFFFFF00u) | (uint8_t)(v))
#define SET8H(r, v)   ((r) = ((r) & 0xFFFF00FFu) | ((uint32_t)(uint8_t)(v) << 8))
#define SET16(r, v)   ((r) = ((r) & 0xFFFF0000u) | (uint16_t)(v))

/* ---- memory access: register holds a real 32-bit address ---- */
static inline uint8_t  rd8 (uint32_t a) { return *(uint8_t  *)(uintptr_t)a; }
static inline uint16_t rd16(uint32_t a) { return *(uint16_t *)(uintptr_t)a; }
static inline uint32_t rd32(uint32_t a) { return *(uint32_t *)(uintptr_t)a; }
static inline void wr8 (uint32_t a, uint8_t  v) { *(uint8_t  *)(uintptr_t)a = v; }
static inline void wr16(uint32_t a, uint16_t v) { *(uint16_t *)(uintptr_t)a = v; }
static inline void wr32(uint32_t a, uint32_t v) { *(uint32_t *)(uintptr_t)a = v; }

/* ---- EFLAGS pack/unpack (modelled bits only) ---- */
static inline uint32_t eflags_pack(CPU *c) {
    return 0x202u | (c->cf) | (c->pf << 2) | (c->af << 4) |
           (c->zf << 6) | (c->sf << 7) | (c->of << 11);
}
static inline void eflags_unpack(CPU *c, uint32_t v) {
    c->cf = v & 1; c->pf = (v >> 2) & 1; c->af = (v >> 4) & 1;
    c->zf = (v >> 6) & 1; c->sf = (v >> 7) & 1; c->of = (v >> 11) & 1;
}

/* ---- stack ---- */
static inline void push32(CPU *c, uint32_t v) { c->esp -= 4; wr32(c->esp, v); }
static inline uint32_t pop32(CPU *c) { uint32_t v = rd32(c->esp); c->esp += 4; return v; }

/* ---- absolute image references: abs VA at preferred base -> live address ---- */
extern uint32_t g_image_delta;   /* live_base - PE ImageBase (0 if loaded where it wanted) */
#define GVA(abs) ((uint32_t)((abs) + g_image_delta))

/* ---- flag helpers ---- */
static inline uint32_t parity8(uint8_t v) {
    v ^= v >> 4; v ^= v >> 2; v ^= v >> 1; return (~v) & 1;
}

/* logical ops (AND/OR/XOR/TEST): CF=OF=0 */
static inline void flags_logic32(CPU *c, uint32_t r) {
    c->cf = 0; c->of = 0; c->sf = r >> 31; c->zf = (r == 0); c->pf = parity8((uint8_t)r);
}
static inline void flags_logic8(CPU *c, uint8_t r) {
    c->cf = 0; c->of = 0; c->sf = (r >> 7) & 1; c->zf = (r == 0); c->pf = parity8(r);
}
/* cmp/sub (a - b) */
static inline uint32_t flags_sub32(CPU *c, uint32_t a, uint32_t b) {
    uint32_t r = a - b;
    c->cf = (a < b);
    c->zf = (r == 0);
    c->sf = r >> 31;
    c->of = (((a ^ b) & (a ^ r)) >> 31) & 1;
    c->af = ((a ^ b ^ r) >> 4) & 1;
    c->pf = parity8((uint8_t)r);
    return r;
}
/* add (a + b) */
static inline uint32_t flags_add32(CPU *c, uint32_t a, uint32_t b) {
    uint32_t r = a + b;
    c->cf = (r < a);
    c->zf = (r == 0);
    c->sf = r >> 31;
    c->of = ((~(a ^ b) & (a ^ r)) >> 31) & 1;
    c->af = ((a ^ b ^ r) >> 4) & 1;
    c->pf = parity8((uint8_t)r);
    return r;
}
/* inc/dec: like add/sub by 1 but CF preserved */
static inline uint32_t flags_inc32(CPU *c, uint32_t a) {
    uint32_t keepcf = c->cf, r = flags_add32(c, a, 1); c->cf = keepcf; return r;
}
static inline uint32_t flags_dec32(CPU *c, uint32_t a) {
    uint32_t keepcf = c->cf, r = flags_sub32(c, a, 1); c->cf = keepcf; return r;
}

/* ---- width-generic flag helpers (sz in {1,2,4}); used by generated code ---- */
static inline uint32_t mask_sz(int sz) { return sz == 1 ? 0xFFu : sz == 2 ? 0xFFFFu : 0xFFFFFFFFu; }
static inline uint32_t sign_sz(int sz) { return sz == 1 ? 0x80u : sz == 2 ? 0x8000u : 0x80000000u; }

static inline uint32_t flags_sub(CPU *c, uint32_t a, uint32_t b, int sz) {
    uint32_t m = mask_sz(sz), s = sign_sz(sz);
    a &= m; b &= m; uint32_t r = (a - b) & m;
    c->cf = (a < b); c->zf = (r == 0); c->sf = (r & s) != 0;
    c->of = (((a ^ b) & (a ^ r)) & s) != 0; c->af = ((a ^ b ^ r) & 0x10) != 0;
    c->pf = parity8((uint8_t)r); return r;
}
static inline uint32_t flags_add(CPU *c, uint32_t a, uint32_t b, int sz) {
    uint32_t m = mask_sz(sz), s = sign_sz(sz);
    a &= m; b &= m; uint32_t r = (a + b) & m;
    c->cf = (r < a); c->zf = (r == 0); c->sf = (r & s) != 0;
    c->of = ((~(a ^ b) & (a ^ r)) & s) != 0; c->af = ((a ^ b ^ r) & 0x10) != 0;
    c->pf = parity8((uint8_t)r); return r;
}
static inline uint32_t flags_logicz(CPU *c, uint32_t r, int sz) {
    uint32_t m = mask_sz(sz), s = sign_sz(sz); r &= m;
    c->cf = 0; c->of = 0; c->sf = (r & s) != 0; c->zf = (r == 0);
    c->pf = parity8((uint8_t)r); return r;
}
static inline uint32_t flags_incs(CPU *c, uint32_t a, int sz) {
    uint32_t keep = c->cf, r = flags_add(c, a, 1, sz); c->cf = keep; return r;
}
static inline uint32_t flags_decs(CPU *c, uint32_t a, int sz) {
    uint32_t keep = c->cf, r = flags_sub(c, a, 1, sz); c->cf = keep; return r;
}
static inline uint32_t flags_adc(CPU *c, uint32_t a, uint32_t b, int sz) {
    uint32_t m = mask_sz(sz), s = sign_sz(sz), cin = c->cf & 1;
    a &= m; b &= m; uint64_t full = (uint64_t)a + b + cin; uint32_t r = (uint32_t)full & m;
    c->cf = (full >> (sz * 8)) & 1; c->zf = (r == 0); c->sf = (r & s) != 0;
    c->of = ((~(a ^ b) & (a ^ r)) & s) != 0; c->af = ((a ^ b ^ r) & 0x10) != 0;
    c->pf = parity8((uint8_t)r); return r;
}
static inline uint32_t flags_sbb(CPU *c, uint32_t a, uint32_t b, int sz) {
    uint32_t m = mask_sz(sz), s = sign_sz(sz), bin = c->cf & 1;
    a &= m; b &= m; uint64_t full = (uint64_t)a - b - bin; uint32_t r = (uint32_t)full & m;
    c->cf = (full >> (sz * 8)) & 1; c->zf = (r == 0); c->sf = (r & s) != 0;
    c->of = (((a ^ b) & (a ^ r)) & s) != 0; c->af = ((a ^ b ^ r) & 0x10) != 0;
    c->pf = parity8((uint8_t)r); return r;
}

static inline uint32_t op_shl(CPU *c, uint32_t v, uint32_t cnt, int sz) {
    uint32_t m = mask_sz(sz); cnt &= 31; if (!cnt) return v & m;
    c->cf = (v >> (sz * 8 - cnt)) & 1; uint32_t r = (v << cnt) & m;
    c->zf = (r == 0); c->sf = (r & sign_sz(sz)) != 0; c->pf = parity8((uint8_t)r); return r;
}
static inline uint32_t op_shr(CPU *c, uint32_t v, uint32_t cnt, int sz) {
    uint32_t m = mask_sz(sz); v &= m; cnt &= 31; if (!cnt) return v;
    c->cf = (v >> (cnt - 1)) & 1; uint32_t r = v >> cnt;
    c->zf = (r == 0); c->sf = (r & sign_sz(sz)) != 0; c->pf = parity8((uint8_t)r); return r;
}
static inline uint32_t op_sar(CPU *c, uint32_t v, uint32_t cnt, int sz) {
    uint32_t m = mask_sz(sz), s = sign_sz(sz); v &= m; cnt &= 31; if (!cnt) return v;
    uint32_t ext = (v & s) ? (m << (sz * 8 - cnt)) & m : 0;
    c->cf = (v >> (cnt - 1)) & 1; uint32_t r = ((v >> cnt) | ext) & m;
    c->zf = (r == 0); c->sf = (r & s) != 0; c->pf = parity8((uint8_t)r); return r;
}

/* ---- shifts (set flags like x86; count masked to 5 bits) ---- */
static inline uint32_t shr32(CPU *c, uint32_t v, uint32_t cnt) {
    cnt &= 31; if (!cnt) return v;
    c->cf = (v >> (cnt - 1)) & 1;
    uint32_t r = v >> cnt;
    c->zf = (r == 0); c->sf = r >> 31; c->pf = parity8((uint8_t)r);
    return r;
}
static inline uint32_t shl32(CPU *c, uint32_t v, uint32_t cnt) {
    cnt &= 31; if (!cnt) return v;
    c->cf = (v >> (32 - cnt)) & 1;
    uint32_t r = v << cnt;
    c->zf = (r == 0); c->sf = r >> 31; c->pf = parity8((uint8_t)r);
    return r;
}
static inline uint8_t shr8(CPU *c, uint8_t v, uint32_t cnt) {
    cnt &= 31; if (!cnt) return v;
    if (cnt <= 8) c->cf = (v >> (cnt - 1)) & 1;
    uint8_t r = (cnt < 8) ? (uint8_t)(v >> cnt) : 0;
    c->zf = (r == 0); c->sf = (r >> 7) & 1; c->pf = parity8(r);
    return r;
}

/* ---- x87 FPU ---- */
#include <math.h>
static inline void   fpush(CPU *c, double v) { c->fpu_top = (c->fpu_top - 1) & 7; c->st[c->fpu_top] = v; }
static inline double fpop(CPU *c) { double v = c->st[c->fpu_top]; c->fpu_top = (c->fpu_top + 1) & 7; return v; }
static inline double *fst(CPU *c, int i) { return &c->st[(c->fpu_top + i) & 7]; }

/* float/double/int memory operands (memcpy avoids alignment/aliasing issues) */
static inline double rdf32(uint32_t a) { float  f; memcpy(&f, (void *)(uintptr_t)a, 4); return (double)f; }
static inline double rdf64(uint32_t a) { double d; memcpy(&d, (void *)(uintptr_t)a, 8); return d; }
static inline double rdi16(uint32_t a) { int16_t i; memcpy(&i, (void *)(uintptr_t)a, 2); return (double)i; }
static inline double rdi32(uint32_t a) { int32_t i; memcpy(&i, (void *)(uintptr_t)a, 4); return (double)i; }
static inline double rdi64(uint32_t a) { int64_t i; memcpy(&i, (void *)(uintptr_t)a, 8); return (double)i; }
static inline void   wrf32(uint32_t a, double v) { float  f = (float)v; memcpy((void *)(uintptr_t)a, &f, 4); }
static inline void   wrf64(uint32_t a, double v) { memcpy((void *)(uintptr_t)a, &v, 8); }
static inline void   wri32(uint32_t a, double v) { int32_t i = (int32_t)nearbyint(v); memcpy((void *)(uintptr_t)a, &i, 4); }
static inline void   wri16(uint32_t a, double v) { int16_t i = (int16_t)nearbyint(v); memcpy((void *)(uintptr_t)a, &i, 2); }
static inline void   wri64(uint32_t a, double v) { int64_t i = (int64_t)nearbyint(v); memcpy((void *)(uintptr_t)a, &i, 8); }

/* fcom/fcomp: set C3/C2/C0 (st0 vs v). Cleared C1. */
static inline void fcompare(CPU *c, double a, double b) {
    uint32_t sw = c->fpu_sw & ~0x4700u;
    if      (a > b)  { /* 000 */ }
    else if (a < b)  sw |= 0x0100u;          /* C0 */
    else if (a == b) sw |= 0x4000u;          /* C3 */
    else             sw |= 0x4700u;          /* unordered: C3|C2|C0 */
    c->fpu_sw = sw;
}
/* sahf: load AH into CF,PF,AF,ZF,SF */
static inline void do_sahf(CPU *c, uint8_t ah) {
    c->cf = ah & 1; c->pf = (ah >> 2) & 1; c->af = (ah >> 4) & 1;
    c->zf = (ah >> 6) & 1; c->sf = (ah >> 7) & 1;
}

#endif /* PCRECOMP_CPU_H */

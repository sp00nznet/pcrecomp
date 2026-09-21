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

/* ---- SSE register file ----
 *
 * One storage, several views - which is how the silicon works, and why this is
 * a union rather than eight float[4]. `movaps` moves a bit pattern, `pxor`
 * works on integers and `addss` works on floats, all through the same 128
 * bits; a float-only model corrupts the first two the moment a game stores a
 * mask in an XMM register, which every SSE-era game does.
 *
 * Scalar single precision is `float` here and NOT `double` like the x87 stack
 * below it. That difference is deliberate. An x87 register really is wider
 * than the values it holds, so widening it costs nothing - but SSE single
 * genuinely IS 32-bit, and computing `addss` in double rounds once where the
 * hardware rounds twice. The results differ in the low bits, and in a game
 * that feeds them to a coordinate transform the difference is visible. */
typedef union {
    float    f32[4];
    double   f64[2];
    uint32_t u32[4];
    uint64_t u64[2];
    int32_t  i32[4];
    /* The word lanes pextrw and pinsrw address. Expressing those two through
     * u32 and a shift works and reads like arithmetic; a lane array says what
     * the instruction says. */
    uint16_t u16[8];
    int16_t  i16[8];
    /* The byte lanes pslldq and psrldq shift through. Those two move the whole
     * register by a byte count, not each lane by a bit count, so they are the
     * one SSE shift that cannot be written in terms of any wider lane. */
    uint8_t  u8[16];
    int8_t   i8[16];
    int64_t  i64[2];
} XMM;

typedef struct {
    uint32_t eax, ecx, edx, ebx, esp, ebp, esi, edi;
    uint32_t eip;
    /* flags as discrete bits (0/1) */
    uint32_t cf, zf, sf, of, pf, af;
    /* x87: register-stack of doubles. st0 == st[fpu_top]; push pre-decrements. */
    double   st[8];
    int      fpu_top;
    /* SSE: xmm0..xmm7. A 32-bit target has no xmm8-15. */
    XMM      xmm[8];
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
/* movlps/movhps and friends move a lane as bits, not as a number: a double
 * round-trip would be exact for every value except the signalling NaNs a
 * mask-producing compare leaves behind. memcpy, because the address need
 * not be aligned. */
static inline uint64_t rd64(uint32_t a) { uint64_t v; memcpy(&v, (void *)(uintptr_t)a, 8); return v; }
static inline void wr64(uint32_t a, uint64_t v) { memcpy((void *)(uintptr_t)a, &v, 8); }

/* ---- EFLAGS pack/unpack (modelled bits only) ---- */
/* `lock`-prefixed read-modify-write.
 *
 * A recompiled game with a worker pool needs these to be real: the guest uses
 * `lock xadd` for every reference count and every queue index, and a
 * non-atomic one is a use-after-free an hour into a session rather than a
 * crash you can find. Nothing else in this header cares about other threads;
 * these do.
 *
 * The x86 semantics are "return the old value" for xadd, and for cmpxchg
 * "return what was there, and the caller compares" - the ZF the instruction
 * sets follows from that. */
#if defined(_MSC_VER)
static inline uint32_t atomic_xadd32(uint32_t a, uint32_t v) {
    return (uint32_t)_InterlockedExchangeAdd((volatile long *)(uintptr_t)a, (long)v);
}
static inline uint32_t atomic_cmpxchg32(uint32_t a, uint32_t cmp, uint32_t nv) {
    return (uint32_t)_InterlockedCompareExchange((volatile long *)(uintptr_t)a,
                                                 (long)nv, (long)cmp);
}
static inline uint32_t atomic_xchg32(uint32_t a, uint32_t v) {
    return (uint32_t)_InterlockedExchange((volatile long *)(uintptr_t)a, (long)v);
}
#else
static inline uint32_t atomic_xadd32(uint32_t a, uint32_t v) {
    return __sync_fetch_and_add((volatile uint32_t *)(uintptr_t)a, v);
}
static inline uint32_t atomic_cmpxchg32(uint32_t a, uint32_t cmp, uint32_t nv) {
    return __sync_val_compare_and_swap((volatile uint32_t *)(uintptr_t)a, cmp, nv);
}
static inline uint32_t atomic_xchg32(uint32_t a, uint32_t v) {
    return __sync_lock_test_and_set((volatile uint32_t *)(uintptr_t)a, v);
}
#endif

static inline uint32_t eflags_pack(CPU *c) {
    return 0x202u | (c->cf) | (c->pf << 2) | (c->af << 4) |
           (c->zf << 6) | (c->sf << 7) | (c->of << 11);
}
static inline void eflags_unpack(CPU *c, uint32_t v) {
    c->cf = v & 1; c->pf = (v >> 2) & 1; c->af = (v >> 4) & 1;
    c->zf = (v >> 6) & 1; c->sf = (v >> 7) & 1; c->of = (v >> 11) & 1;
}

/* ---- stack ----
 *
 * ESP is an address in a flat build, so the base is zero and these compile to
 * exactly what they did before. A segmented build defines STACK_BASE to its
 * SS base instead, because there ESP is an OFFSET: 16-bit code reaching its
 * arguments does `mov bp, sp` and then `[bp+6]`, and truncating a host address
 * to 16 bits produces a pointer to nothing. */
#ifndef STACK_BASE
#define STACK_BASE(c) 0u
#endif
static inline void push32(CPU *c, uint32_t v) { c->esp -= 4; wr32(STACK_BASE(c) + c->esp, v); }
static inline uint32_t pop32(CPU *c) { uint32_t v = rd32(STACK_BASE(c) + c->esp); c->esp += 4; return v; }

/* An instruction the lifter could not express. Plain abort() by default, so a
 * project that includes only cpu.h is unchanged; a runtime that can say
 * something useful - which guest address, which mnemonic, how it got there -
 * defines RECOMP_TODO before including this. A bare abort() in two million
 * lines becomes __fastfail in a release build, which no handler sees. */
#ifndef RECOMP_TODO
#define RECOMP_TODO(va, text) abort()
#endif

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

/* ---- rotates. Unlike the shifts these leave ZF/SF/PF alone, which is not an
   omission: x86 does not touch them here, and code that rotates then branches
   on the zero flag is reading the flag the PREVIOUS instruction set. ---- */
static inline uint32_t op_rol(CPU *c, uint32_t v, uint32_t cnt, int sz) {
    uint32_t m = mask_sz(sz); int w = sz * 8; v &= m;
    cnt &= 31; cnt %= (uint32_t)w; if (!cnt) return v;
    uint32_t r = ((v << cnt) | (v >> (w - cnt))) & m;
    c->cf = r & 1;
    c->of = (((r >> (w - 1)) & 1) ^ (c->cf & 1));
    return r;
}
static inline uint32_t op_ror(CPU *c, uint32_t v, uint32_t cnt, int sz) {
    uint32_t m = mask_sz(sz); int w = sz * 8; v &= m;
    cnt &= 31; cnt %= (uint32_t)w; if (!cnt) return v;
    uint32_t r = ((v >> cnt) | (v << (w - cnt))) & m;
    c->cf = (r >> (w - 1)) & 1;
    c->of = (((r >> (w - 1)) & 1) ^ ((r >> (w - 2)) & 1));
    return r;
}

/* ---- double-precision shifts: shift `d`, feeding in bits from `s` ---- */
static inline uint32_t op_shld(CPU *c, uint32_t d, uint32_t s, uint32_t cnt, int sz) {
    uint32_t m = mask_sz(sz); int w = sz * 8;
    d &= m; s &= m; cnt &= 31;
    if (!cnt || cnt > (uint32_t)w) return d;      /* count > width is undefined */
    uint32_t r = ((d << cnt) | (s >> (w - cnt))) & m;
    c->cf = (d >> (w - cnt)) & 1;
    c->zf = (r == 0); c->sf = (r & sign_sz(sz)) != 0; c->pf = parity8((uint8_t)r);
    return r;
}
/* BSF/BSR: the index of the lowest (or highest) set bit. The flag is the
 * whole interface - ZF says whether there WAS one - and when the source is
 * zero the destination is architecturally undefined, so it is left alone
 * rather than given a value that code might come to depend on. */
static inline uint32_t op_bsf(CPU *c, uint32_t d, uint32_t s, int sz) {
    uint32_t i, n = (uint32_t)sz * 8;
    c->zf = (s == 0);
    if (s == 0) return d;
    for (i = 0; i < n; i++) if (s & (1u << i)) return i;
    return d;
}

static inline uint32_t op_bsr(CPU *c, uint32_t d, uint32_t s, int sz) {
    uint32_t i, n = (uint32_t)sz * 8;
    c->zf = (s == 0);
    if (s == 0) return d;
    for (i = n; i-- > 0; ) if (s & (1u << i)) return i;
    return d;
}

/* BT/BTS/BTR/BTC: the selected bit into CF, then the register form's own
 * change to it. The count is taken modulo the operand width - which is what
 * makes `bt eax, 33` test bit 1 and not read past the register. Only the
 * register form is expressed here; the memory form of these addresses a bit
 * string that can run past the operand, and no lifted site uses it. */
static inline uint32_t op_bittest(CPU *c, uint32_t d, uint32_t bit, int sz, int op) {
    uint32_t mask = 1u << (bit & ((uint32_t)sz * 8 - 1));
    c->cf = (d & mask) ? 1 : 0;
    switch (op) {
        case 1: return d | mask;      /* bts */
        case 2: return d & ~mask;     /* btr */
        case 3: return d ^ mask;      /* btc */
        default: return d;            /* bt  */
    }
}

/* RCL/RCR rotate through CF, so the rotated quantity is one bit wider than
 * the operand and the count is taken modulo that wider width. Writing this as
 * a bit at a time is slower than the closed form and is the version that is
 * obviously right, which for an instruction this rare is the better trade. */
static inline uint32_t op_rcl(CPU *c, uint32_t d, uint32_t cnt, int sz) {
    uint32_t n = (uint32_t)sz * 8, i;
    uint32_t mask = (n == 32) ? 0xFFFFFFFFu : ((1u << n) - 1u);
    cnt %= (n + 1);
    if (cnt == 0) return d;        /* a zero count changes no flag at all */
    for (i = 0; i < cnt; i++) {
        uint32_t top = (d >> (n - 1)) & 1u;
        d = ((d << 1) | c->cf) & mask;
        c->cf = top;
    }
    /* OF is defined only for a count of one; hardware leaves something there
     * for the rest and nothing may read it. */
    if (cnt == 1) c->of = (uint32_t)(((d >> (n - 1)) & 1u) ^ c->cf);
    return d;
}

static inline uint32_t op_rcr(CPU *c, uint32_t d, uint32_t cnt, int sz) {
    uint32_t n = (uint32_t)sz * 8, i;
    uint32_t mask = (n == 32) ? 0xFFFFFFFFu : ((1u << n) - 1u);
    cnt %= (n + 1);
    if (cnt == 0) return d;
    /* RCR sets OF from the two top bits of the RESULT, and before the rotate
     * rather than after - but only the count-of-one case is defined, and for
     * that one the two are the same thing. */
    if (cnt == 1) c->of = (uint32_t)((((d >> 1) | (c->cf << (n - 1))) >> (n - 1)) & 1u)
                        ^ (uint32_t)((((d >> 1) | (c->cf << (n - 1))) >> (n - 2)) & 1u);
    for (i = 0; i < cnt; i++) {
        uint32_t bot = d & 1u;
        d = ((d >> 1) | (c->cf << (n - 1))) & mask;
        c->cf = bot;
    }
    return d;
}

static inline uint32_t op_shrd(CPU *c, uint32_t d, uint32_t s, uint32_t cnt, int sz) {
    uint32_t m = mask_sz(sz); int w = sz * 8;
    d &= m; s &= m; cnt &= 31;
    if (!cnt || cnt > (uint32_t)w) return d;
    uint32_t r = ((d >> cnt) | (s << (w - cnt))) & m;
    c->cf = (d >> (cnt - 1)) & 1;
    c->zf = (r == 0); c->sf = (r & sign_sz(sz)) != 0; c->pf = parity8((uint8_t)r);
    return r;
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

/* x87 extended precision, the ten-byte format `fld tbyte` reads. An x87
 * register is modelled here as a double, which is the right trade for every
 * load and store a compiler emits - except this one, which is the format the
 * register really has. Reading eight of the ten bytes as a double gives a
 * number that looks plausible and is not, so the conversion is done properly.
 *
 * Unlike every other float format the mantissa carries its integer bit
 * explicitly, so the value is just the mantissa scaled: 63 bits of fraction
 * under a bias of 16383. Rounding to a double's 53 bits is the cast's job and
 * it rounds to nearest, which is what the hardware would do converting the
 * same value down. */
static inline double rdf80(uint32_t a) {
    uint64_t m; uint16_t se; int e;
    memcpy(&m,  (void *)(uintptr_t)a,     8);
    memcpy(&se, (void *)(uintptr_t)(a + 8), 2);
    e = se & 0x7FFF;
    if (e == 0x7FFF) {
        double v = (m << 1) ? (double)NAN : (double)INFINITY;
        return (se & 0x8000) ? -v : v;
    }
    /* A zero exponent is a denormal, whose exponent is one above the encoding. */
    return ldexp((se & 0x8000) ? -(double)m : (double)m,
                 (e ? e : 1) - 16383 - 63);
}

static inline void wrf80(uint32_t a, double v) {
    uint64_t m; uint16_t se; int e, sign = signbit(v);
    if (v != v)             { m = 0xC000000000000000ULL; se = 0x7FFF; }
    else if (isinf(v))      { m = 0x8000000000000000ULL; se = 0x7FFF; }
    else if (v == 0.0)      { m = 0; se = 0; }
    else {
        double f = frexp(sign ? -v : v, &e);   /* v = f * 2^e, 0.5 <= f < 1 */
        m = (uint64_t)ldexp(f, 64);            /* so 2^63 <= m < 2^64 */
        se = (uint16_t)(e - 1 + 16383);
    }
    if (sign) se |= 0x8000;
    memcpy((void *)(uintptr_t)a,       &m,  8);
    memcpy((void *)(uintptr_t)(a + 8), &se, 2);
}

/* fcom/fcomp: set C3/C2/C0 (st0 vs v). Cleared C1. */
static inline void fcompare(CPU *c, double a, double b) {
    uint32_t sw = c->fpu_sw & ~0x4700u;
    if      (a > b)  { /* 000 */ }
    else if (a < b)  sw |= 0x0100u;          /* C0 */
    else if (a == b) sw |= 0x4000u;          /* C3 */
    else             sw |= 0x4700u;          /* unordered: C3|C2|C0 */
    c->fpu_sw = sw;
}
/* fcomi/fucomi: the same comparison, into EFLAGS instead of the status word.
 * The P6 forms exist so a compiler can branch on a float compare without
 * going through `fnstsw ax; test ah`. Note the mapping is not the integer
 * one: "unordered" is ZF=PF=CF=1, which is why `jp` after an fcomi is the
 * NaN test, and OF/SF/AF are cleared. */
static inline void fcompare_eflags(CPU *c, double a, double b) {
    c->of = c->sf = c->af = 0;
    if      (a > b)  { c->zf = 0; c->pf = 0; c->cf = 0; }
    else if (a < b)  { c->zf = 0; c->pf = 0; c->cf = 1; }
    else if (a == b) { c->zf = 1; c->pf = 0; c->cf = 0; }
    else             { c->zf = 1; c->pf = 1; c->cf = 1; }
}
/* sahf: load AH into CF,PF,AF,ZF,SF */
static inline void do_sahf(CPU *c, uint8_t ah) {
    c->cf = ah & 1; c->pf = (ah >> 2) & 1; c->af = (ah >> 4) & 1;
    c->zf = (ah >> 6) & 1; c->sf = (ah >> 7) & 1;
}

/* ---- SSE ----
 *
 * Enough of SSE/SSE2 for a Pentium 4-era game: scalar float and double, the
 * packed moves and bitwise ops, and the compares. Packed arithmetic beyond
 * that is not here yet - it lifts to a TODO rather than silently wrong code.
 */

/* Memory operands. Separate from the x87 rdf32/rdf64 above because those
 * widen to double for the 80-bit stack, and these must not. memcpy because an
 * SSE memory operand is frequently unaligned (movups exists for a reason). */
static inline float  rdss(uint32_t a) { float  f; memcpy(&f, (void *)(uintptr_t)a, 4); return f; }
static inline double rdsd(uint32_t a) { double d; memcpy(&d, (void *)(uintptr_t)a, 8); return d; }
static inline XMM    rdxm(uint32_t a) { XMM x;    memcpy(&x, (void *)(uintptr_t)a, 16); return x; }
static inline void   wrss(uint32_t a, float  v) { memcpy((void *)(uintptr_t)a, &v, 4); }
static inline void   wrsd(uint32_t a, double v) { memcpy((void *)(uintptr_t)a, &v, 8); }
static inline void   wrxm(uint32_t a, XMM    v) { memcpy((void *)(uintptr_t)a, &v, 16); }

/* MOVSS/MOVSD loading from memory zero the rest of the register; the
 * register-to-register forms leave the high lanes alone. Getting that
 * backwards is invisible until something reads the high lanes, which is why
 * it is a named helper and not an open-coded assignment. */
static inline void sse_load_ss(XMM *d, float  v) { d->u64[0] = 0; d->u64[1] = 0; d->f32[0] = v; }
static inline void sse_load_sd(XMM *d, double v) { d->u64[0] = 0; d->u64[1] = 0; d->f64[0] = v; }

/* UCOMISS/COMISS/UCOMISD/COMISD: the comparison lands in ZF/PF/CF, and clears
 * OF/SF/AF. An unordered compare - either operand NaN - sets all three, which
 * is exactly what makes `ucomiss; jp` a NaN test and `ucomiss; jbe` mean
 * "below or equal, or unordered". Note the flags are the UNSIGNED set: the
 * compiler emits `ja`/`jbe` after a float compare, never `jg`/`jle`. */
static inline void sse_compare(CPU *c, double a, double b) {
    c->of = 0; c->sf = 0; c->af = 0;
    if (a != a || b != b) { c->zf = 1; c->pf = 1; c->cf = 1; }   /* unordered */
    else                  { c->zf = (a == b); c->pf = 0; c->cf = (a < b); }
}

/* MINSS/MAXSS are not fmin/fmax. The manual defines them as
 *     if (dst OP src) then dst else src
 * and that "else src" is load-bearing in two cases fmin gets the other way
 * round: when the operands are equal - which includes +0.0 against -0.0, so
 * min(+0,-0) is -0 but min(-0,+0) is +0 - and when either is NaN, where the
 * comparison is false and the SECOND operand wins. Written in that exact
 * shape, C's own "any compare with NaN is false" rule delivers both for free.
 * Writing it the other way round, `(src < dst) ? src : dst`, looks identical
 * and is wrong on both. */
static inline float  sse_minf(float  d, float  s) { return (d < s) ? d : s; }
static inline float  sse_maxf(float  d, float  s) { return (d > s) ? d : s; }
static inline double sse_mind(double d, double s) { return (d < s) ? d : s; }
static inline double sse_maxd(double d, double s) { return (d > s) ? d : s; }

/* CVTTSS2SI and friends yield the "integer indefinite" value when the source
 * does not fit in 32 bits, where the equivalent C cast is undefined behaviour
 * and may trap. One comparison buys a defined answer that matches hardware. */
static inline int32_t sse_cvtt_i32(double v) {
    return (v >= -2147483648.0 && v < 2147483648.0) ? (int32_t)v : (int32_t)0x80000000;
}

/* The packed integer ops that saturate rather than wrap. PADDSW and friends
 * clamp to the lane's own range instead of carrying into the next lane, and
 * the arithmetic has to be done a width up for the clamp to see the overflow
 * at all - which is the whole reason these are functions and not expressions
 * in the generated code. */
static inline int8_t   sse_sat_i8 (int32_t v) { return v >  127 ?  127 : v < -128 ? -128 : (int8_t)v; }
static inline int16_t  sse_sat_i16(int32_t v) { return v >  32767 ?  32767 : v < -32768 ? -32768 : (int16_t)v; }
static inline uint8_t  sse_sat_u8 (int32_t v) { return v >  255 ?  255 : v < 0 ? 0 : (uint8_t)v; }
static inline uint16_t sse_sat_u16(int32_t v) { return v > 65535 ? 65535 : v < 0 ? 0 : (uint16_t)v; }

#endif /* PCRECOMP_CPU_H */

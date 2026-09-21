/*
 * cpu64.h - the runtime contract for lift64_cpu.py.
 *
 * The 64-bit sibling of recomp32_cpu/cpu.h, and deliberately a separate header
 * rather than an #ifdef inside that one. The two differ in the one place a
 * shared header cannot paper over: what a 32-bit register write does. On x86-32
 * `mov eax, 1` writes a whole register; on x86-64 `mov eax, 1` writes the low
 * half AND ZEROES THE HIGH HALF, while `mov ax, 1` preserves it. That rule is
 * not a special case, it is the single most common instruction in the binary
 * (1.3M of 3.6M here), so it belongs in the type system rather than in a flag.
 *
 * What is deliberately NOT here:
 *
 *   * x87. The Win64 ABI passes and returns floats in XMM, and a shipping
 *     UE3 build measured 421 x87 instructions in 3.6M - roughly all of them
 *     inside data that the unwind table does not cover and the disassembler
 *     walked into anyway. A stack of doubles that is never right is worse than
 *     an honest RECOMP_TODO, so the lifter emits the latter.
 *   * MMX. Four instructions in the whole image, same reasoning.
 *   * Segment bases. Long mode has none for cs/ds/es/ss, and the only segment
 *     that addresses anything is gs (the TEB). See rd_gs/wr_gs below.
 */
#ifndef RECOMP_CPU64_H
#define RECOMP_CPU64_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

/* A 128-bit SSE register. Same union as the 32-bit runtime, extended to the
 * sixteen that long mode has. f64[2] matters: x64 does all double arithmetic
 * here, where a 32-bit target would have used the x87 stack. */
typedef union {
    float    f32[4];
    double   f64[2];
    uint32_t u32[4];
    uint64_t u64[2];
    int32_t  i32[4];
    int64_t  i64[2];
    uint8_t  u8[16];
    /* The narrow lanes the packed-integer ops work in. A 32-bit target never
     * needed these because its compiler had x87 to convert with; a Win64 one
     * has only SSE, so pack/unpack/shift of bytes and words is everywhere. */
    int8_t   i8[16];
    uint16_t u16[8];
    int16_t  i16[8];
} XMM;

typedef struct {
    /* The sixteen general-purpose registers, in Intel encoding order so that
     * a register number from a REX-extended ModRM indexes this directly. */
    uint64_t rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rip;
    /* Flags as discrete 0/1 bytes, as in the 32-bit runtime. */
    uint64_t cf, zf, sf, of, pf, af;
    XMM      xmm[16];
    uint32_t mxcsr;
} CPU;

/* ---- partial register access ----
 *
 * The asymmetry below is the whole point of this header. Reads are plain
 * truncations; it is the WRITES that differ by width:
 *
 *   SET32  zeroes bits 63:32          (x86-64 rule, and the common case)
 *   SET16  preserves bits 63:16
 *   SET8L  preserves bits 63:8
 *   SET8H  preserves everything but bits 15:8
 *
 * Getting SET32 wrong does not fault. It leaves stale high bits in a register
 * that the next `lea`/`add` folds into an address, and the resulting pointer is
 * wrong by a multiple of 4 GB - which on Windows is an access violation a long
 * way from the instruction that caused it.
 */
#define R8L(r)        ((uint8_t)(r))
#define R8H(r)        ((uint8_t)((r) >> 8))
#define R16(r)        ((uint16_t)(r))
#define R32(r)        ((uint32_t)(r))
#define R64(r)        ((uint64_t)(r))

#define SET8L(r, v)   ((r) = ((r) & ~(uint64_t)0xFFu) | (uint64_t)(uint8_t)(v))
#define SET8H(r, v)   ((r) = ((r) & ~(uint64_t)0xFF00u) | ((uint64_t)(uint8_t)(v) << 8))
#define SET16(r, v)   ((r) = ((r) & ~(uint64_t)0xFFFFu) | (uint64_t)(uint16_t)(v))
#define SET32(r, v)   ((r) = (uint64_t)(uint32_t)(v))      /* zero-extends! */
#define SET64(r, v)   ((r) = (uint64_t)(v))

/* ---- memory access: a register holds a real 64-bit address ---- */
static inline uint8_t  rd8 (uint64_t a) { return *(uint8_t  *)(uintptr_t)a; }
static inline uint16_t rd16(uint64_t a) { return *(uint16_t *)(uintptr_t)a; }
static inline uint32_t rd32(uint64_t a) { return *(uint32_t *)(uintptr_t)a; }
static inline uint64_t rd64(uint64_t a) { return *(uint64_t *)(uintptr_t)a; }
static inline void wr8 (uint64_t a, uint8_t  v) { *(uint8_t  *)(uintptr_t)a = v; }
static inline void wr16(uint64_t a, uint16_t v) { *(uint16_t *)(uintptr_t)a = v; }
static inline void wr32(uint64_t a, uint32_t v) { *(uint32_t *)(uintptr_t)a = v; }
static inline void wr64(uint64_t a, uint64_t v) { *(uint64_t *)(uintptr_t)a = v; }

/* 128-bit move, for movaps/movups/movdqa and friends. memcpy rather than a
 * pointer store: the aligned and unaligned forms differ only in whether the
 * hardware faults, and a lifted build should not fault where the original did
 * not merely because the host allocator moved a buffer. */
static inline void rd128(uint64_t a, XMM *d) { memcpy(d, (const void *)(uintptr_t)a, 16); }
static inline void wr128(uint64_t a, const XMM *s) { memcpy((void *)(uintptr_t)a, s, 16); }

/* ---- gs: the TEB ----
 * The only segment in long mode with a base that addresses anything. Thread
 * information block accesses (stack limits, TLS, the SEH chain) come through
 * it and nothing else does. */
#if defined(_MSC_VER)
static inline uint64_t rd_gs64(uint64_t off) { return __readgsqword((unsigned long)off); }
static inline uint32_t rd_gs32(uint64_t off) { return __readgsdword((unsigned long)off); }
static inline void wr_gs64(uint64_t off, uint64_t v) { __writegsqword((unsigned long)off, v); }
static inline void wr_gs32(uint64_t off, uint32_t v) { __writegsdword((unsigned long)off, v); }
#else
static inline uint64_t rd_gs64(uint64_t off) {
    uint64_t v; __asm__ __volatile__("movq %%gs:(%1), %0" : "=r"(v) : "r"(off)); return v;
}
static inline uint32_t rd_gs32(uint64_t off) {
    uint32_t v; __asm__ __volatile__("movl %%gs:(%1), %0" : "=r"(v) : "r"(off)); return v;
}
static inline void wr_gs64(uint64_t off, uint64_t v) {
    __asm__ __volatile__("movq %0, %%gs:(%1)" :: "r"(v), "r"(off));
}
static inline void wr_gs32(uint64_t off, uint32_t v) {
    __asm__ __volatile__("movl %0, %%gs:(%1)" :: "r"(v), "r"(off));
}
#endif

/* ---- atomics ---- */
#if defined(_MSC_VER)
static inline uint32_t atomic_xadd32(uint64_t a, uint32_t v) {
    return (uint32_t)_InterlockedExchangeAdd((volatile long *)(uintptr_t)a, (long)v);
}
static inline uint64_t atomic_xadd64(uint64_t a, uint64_t v) {
    return (uint64_t)_InterlockedExchangeAdd64((volatile __int64 *)(uintptr_t)a, (__int64)v);
}
static inline uint32_t atomic_cmpxchg32(uint64_t a, uint32_t cmp, uint32_t nv) {
    return (uint32_t)_InterlockedCompareExchange((volatile long *)(uintptr_t)a, (long)nv, (long)cmp);
}
static inline uint64_t atomic_cmpxchg64(uint64_t a, uint64_t cmp, uint64_t nv) {
    return (uint64_t)_InterlockedCompareExchange64((volatile __int64 *)(uintptr_t)a,
                                                   (__int64)nv, (__int64)cmp);
}
static inline uint32_t atomic_xchg32(uint64_t a, uint32_t v) {
    return (uint32_t)_InterlockedExchange((volatile long *)(uintptr_t)a, (long)v);
}
static inline uint64_t atomic_xchg64(uint64_t a, uint64_t v) {
    return (uint64_t)_InterlockedExchange64((volatile __int64 *)(uintptr_t)a, (__int64)v);
}
#else
static inline uint32_t atomic_xadd32(uint64_t a, uint32_t v) {
    return __sync_fetch_and_add((volatile uint32_t *)(uintptr_t)a, v);
}
static inline uint64_t atomic_xadd64(uint64_t a, uint64_t v) {
    return __sync_fetch_and_add((volatile uint64_t *)(uintptr_t)a, v);
}
static inline uint32_t atomic_cmpxchg32(uint64_t a, uint32_t cmp, uint32_t nv) {
    return __sync_val_compare_and_swap((volatile uint32_t *)(uintptr_t)a, cmp, nv);
}
static inline uint64_t atomic_cmpxchg64(uint64_t a, uint64_t cmp, uint64_t nv) {
    return __sync_val_compare_and_swap((volatile uint64_t *)(uintptr_t)a, cmp, nv);
}
static inline uint32_t atomic_xchg32(uint64_t a, uint32_t v) {
    return __sync_lock_test_and_set((volatile uint32_t *)(uintptr_t)a, v);
}
static inline uint64_t atomic_xchg64(uint64_t a, uint64_t v) {
    return __sync_lock_test_and_set((volatile uint64_t *)(uintptr_t)a, v);
}
#endif

/* ---- RFLAGS pack/unpack (modelled bits only) ---- */
static inline uint64_t eflags_pack(CPU *c) {
    return 0x202u | (c->cf) | (c->pf << 2) | (c->af << 4) |
           (c->zf << 6) | (c->sf << 7) | (c->of << 11);
}
static inline void eflags_unpack(CPU *c, uint64_t v) {
    c->cf = v & 1; c->pf = (v >> 2) & 1; c->af = (v >> 4) & 1;
    c->zf = (v >> 6) & 1; c->sf = (v >> 7) & 1; c->of = (v >> 11) & 1;
}

/* ---- stack ----
 * RSP is a real address. Long mode has no SS base, so unlike the 32-bit header
 * there is no STACK_BASE hook to leave open. */
static inline void push64(CPU *c, uint64_t v) { c->rsp -= 8; wr64(c->rsp, v); }
static inline uint64_t pop64(CPU *c) { uint64_t v = rd64(c->rsp); c->rsp += 8; return v; }

/* ---- cpuid ----
 * Forwarded to the host, which is the same architecture: the guest is asking
 * what this CPU can do, and the lifted code will run on this CPU. Making up an
 * answer would either hide SSE levels the host has or promise ones it does
 * not. */
static inline void do_cpuid(CPU *c)
{
    int r[4] = { 0, 0, 0, 0 };
#if defined(_MSC_VER)
    __cpuidex(r, (int)(uint32_t)c->rax, (int)(uint32_t)c->rcx);
#endif
    SET32(c->rax, (uint32_t)r[0]);
    SET32(c->rbx, (uint32_t)r[1]);
    SET32(c->rcx, (uint32_t)r[2]);
    SET32(c->rdx, (uint32_t)r[3]);
}

#ifndef RECOMP_TODO
#define RECOMP_TODO(va, text) abort()
#endif

/* ---- absolute image references ----
 * A 64-bit PE is built to relocate and this one has a .reloc, but it asks for
 * 0x140000000 and the runtime reserves that range before anything else can take
 * it, so the delta is normally 0. GVA stays because "normally" is not "always":
 * a host with a conflicting reservation loads it elsewhere, and then every
 * RIP-relative address the lifter resolved statically needs the same shift. */
extern int64_t g_image_delta;   /* live_base - PE ImageBase */
#define GVA(abs) ((uint64_t)((int64_t)(abs) + g_image_delta))

/* ---- flag helpers ----
 *
 * Width-generic, because x86-64 operands come in four sizes and writing four
 * copies of each was how the 32-bit runtime grew its longest functions. `sz` is
 * in bytes and is always a compile-time constant at the call site, so the shifts
 * fold away.
 */
static inline uint64_t mask_sz(int sz) {
    return sz == 8 ? ~(uint64_t)0 : (((uint64_t)1 << (sz * 8)) - 1);
}
static inline uint64_t signbit_sz(int sz) { return (uint64_t)1 << (sz * 8 - 1); }

static inline uint32_t parity8(uint8_t v) {
    v ^= v >> 4; v ^= v >> 2; v ^= v >> 1; return (~v) & 1;
}

/* logical ops (AND/OR/XOR/TEST): CF=OF=0 */
static inline uint64_t flags_logicz(CPU *c, uint64_t r, int sz) {
    r &= mask_sz(sz);
    c->cf = 0; c->of = 0;
    c->sf = (r & signbit_sz(sz)) ? 1 : 0;
    c->zf = (r == 0);
    c->pf = parity8((uint8_t)r);
    return r;
}

static inline uint64_t flags_add(CPU *c, uint64_t a, uint64_t b, int sz) {
    uint64_t m = mask_sz(sz), sb = signbit_sz(sz);
    a &= m; b &= m;
    uint64_t r = (a + b) & m;
    c->cf = (r < a);
    c->zf = (r == 0);
    c->sf = (r & sb) ? 1 : 0;
    c->of = ((~(a ^ b) & (a ^ r)) & sb) ? 1 : 0;
    c->af = ((a ^ b ^ r) >> 4) & 1;
    c->pf = parity8((uint8_t)r);
    return r;
}

static inline uint64_t flags_sub(CPU *c, uint64_t a, uint64_t b, int sz) {
    uint64_t m = mask_sz(sz), sb = signbit_sz(sz);
    a &= m; b &= m;
    uint64_t r = (a - b) & m;
    c->cf = (a < b);
    c->zf = (r == 0);
    c->sf = (r & sb) ? 1 : 0;
    c->of = (((a ^ b) & (a ^ r)) & sb) ? 1 : 0;
    c->af = ((a ^ b ^ r) >> 4) & 1;
    c->pf = parity8((uint8_t)r);
    return r;
}

static inline uint64_t flags_adc(CPU *c, uint64_t a, uint64_t b, int sz) {
    uint64_t m = mask_sz(sz), sb = signbit_sz(sz), cin = c->cf;
    a &= m; b &= m;
    uint64_t r = (a + b + cin) & m;
    c->cf = cin ? (r <= a) : (r < a);
    c->zf = (r == 0);
    c->sf = (r & sb) ? 1 : 0;
    c->of = ((~(a ^ b) & (a ^ r)) & sb) ? 1 : 0;
    c->af = ((a ^ b ^ r) >> 4) & 1;
    c->pf = parity8((uint8_t)r);
    return r;
}

static inline uint64_t flags_sbb(CPU *c, uint64_t a, uint64_t b, int sz) {
    uint64_t m = mask_sz(sz), sb = signbit_sz(sz), cin = c->cf;
    a &= m; b &= m;
    uint64_t r = (a - b - cin) & m;
    c->cf = cin ? (a <= b) : (a < b);
    c->zf = (r == 0);
    c->sf = (r & sb) ? 1 : 0;
    c->of = (((a ^ b) & (a ^ r)) & sb) ? 1 : 0;
    c->af = ((a ^ b ^ r) >> 4) & 1;
    c->pf = parity8((uint8_t)r);
    return r;
}

/* inc/dec leave CF alone - the one thing that makes them not `add 1`. */
static inline uint64_t flags_incs(CPU *c, uint64_t a, int sz) {
    uint64_t keep = c->cf, r = flags_add(c, a, 1, sz); c->cf = keep; return r;
}
static inline uint64_t flags_decs(CPU *c, uint64_t a, int sz) {
    uint64_t keep = c->cf, r = flags_sub(c, a, 1, sz); c->cf = keep; return r;
}

/* ---- shifts ----
 * The count is masked to 6 bits for 64-bit operands and 5 bits otherwise, which
 * is the hardware rule and not the same as C's. A count of 0 leaves every flag
 * untouched.
 *
 * OF is defined ONLY for a count of 1. For any other count the manual leaves it
 * undefined, and both Intel and AMD leave it clear - which is what difftest64
 * measures against the real CPU. Setting it unconditionally from the operand's
 * sign bit, as the obvious reading of the manual's count-of-1 rule invites,
 * disagrees with the hardware on every multi-bit shift. */
static inline uint64_t op_shl(CPU *c, uint64_t v, uint64_t n, int sz) {
    n &= (sz == 8) ? 63 : 31;
    if (!n) return v & mask_sz(sz);
    uint64_t m = mask_sz(sz), sb = signbit_sz(sz);
    v &= m;
    uint64_t r = (v << n) & m;
    c->cf = (n <= sz * 8) ? ((v >> (sz * 8 - n)) & 1) : 0;
    /* SHL computes OF for EVERY count, unlike SHR which clears it for counts
     * above one. The manual defines OF only for a count of 1 in both cases, so
     * the difference is invisible in the spec and measurable on the CPU -
     * difftest64 caught it going both ways in one run. */
    c->of = (((r & sb) ? 1u : 0u) ^ (uint32_t)c->cf);
    c->zf = (r == 0); c->sf = (r & sb) ? 1 : 0; c->pf = parity8((uint8_t)r);
    return r;
}
static inline uint64_t op_shr(CPU *c, uint64_t v, uint64_t n, int sz) {
    n &= (sz == 8) ? 63 : 31;
    if (!n) return v & mask_sz(sz);
    uint64_t m = mask_sz(sz), sb = signbit_sz(sz);
    v &= m;
    uint64_t r = v >> n;
    c->cf = (v >> (n - 1)) & 1;
    c->of = (n == 1) ? ((v & sb) ? 1 : 0) : 0;
    c->zf = (r == 0); c->sf = (r & sb) ? 1 : 0; c->pf = parity8((uint8_t)r);
    return r;
}
static inline uint64_t op_sar(CPU *c, uint64_t v, uint64_t n, int sz) {
    n &= (sz == 8) ? 63 : 31;
    if (!n) return v & mask_sz(sz);
    uint64_t m = mask_sz(sz), sb = signbit_sz(sz);
    v &= m;
    /* sign-extend to 64, shift arithmetically, mask back */
    int64_t sv = (int64_t)(v | ((v & sb) ? ~m : 0));
    uint64_t r = ((uint64_t)(sv >> n)) & m;
    c->cf = (uint64_t)(sv >> (n - 1)) & 1;
    c->of = 0;
    c->zf = (r == 0); c->sf = (r & sb) ? 1 : 0; c->pf = parity8((uint8_t)r);
    return r;
}
static inline uint64_t op_rol(CPU *c, uint64_t v, uint64_t n, int sz) {
    int w = sz * 8;
    n &= (sz == 8) ? 63 : 31;
    n %= w;
    uint64_t m = mask_sz(sz);
    v &= m;
    if (!n) return v;
    uint64_t r = ((v << n) | (v >> (w - n))) & m;
    c->cf = r & 1;
    /* Computed for every count, as SHL does. Only SHR clears it. */
    c->of = (uint32_t)(((r & signbit_sz(sz)) ? 1u : 0u) ^ (uint32_t)c->cf);
    return r;
}
static inline uint64_t op_ror(CPU *c, uint64_t v, uint64_t n, int sz) {
    int w = sz * 8;
    n &= (sz == 8) ? 63 : 31;
    n %= w;
    uint64_t m = mask_sz(sz);
    v &= m;
    if (!n) return v;
    uint64_t r = ((v >> n) | (v << (w - n))) & m;
    c->cf = (r & signbit_sz(sz)) ? 1 : 0;
    /* ROR's OF is the XOR of the result's top two bits, for every count. */
    c->of = (((r >> (w - 1)) ^ (r >> (w - 2))) & 1) ? 1 : 0;
    return r;
}
static inline uint64_t op_shld(CPU *c, uint64_t d, uint64_t s, uint64_t n, int sz) {
    int w = sz * 8;
    n &= (sz == 8) ? 63 : 31;
    if (!n || n >= (uint64_t)w) return d & mask_sz(sz);
    uint64_t m = mask_sz(sz);
    d &= m; s &= m;
    uint64_t r = ((d << n) | (s >> (w - n))) & m;
    c->cf = (d >> (w - n)) & 1;
    c->zf = (r == 0); c->sf = (r & signbit_sz(sz)) ? 1 : 0; c->pf = parity8((uint8_t)r);
    return r;
}
static inline uint64_t op_shrd(CPU *c, uint64_t d, uint64_t s, uint64_t n, int sz) {
    int w = sz * 8;
    n &= (sz == 8) ? 63 : 31;
    if (!n || n >= (uint64_t)w) return d & mask_sz(sz);
    uint64_t m = mask_sz(sz);
    d &= m; s &= m;
    uint64_t r = ((d >> n) | (s << (w - n))) & m;
    c->cf = (d >> (n - 1)) & 1;
    c->zf = (r == 0); c->sf = (r & signbit_sz(sz)) ? 1 : 0; c->pf = parity8((uint8_t)r);
    return r;
}

/* ---- 64x64 -> 128 multiply ----
 *
 * MUL and IMUL with a 64-bit operand put a 128-bit product in RDX:RAX, and C
 * has no such type portably. MSVC has the intrinsics, GCC and Clang have
 * __int128; the fallback is the schoolbook split, which is what the other two
 * compile to anyway.
 *
 * The signed version is the unsigned one with a correction: interpreting a
 * negative operand as unsigned adds 2^64 times the other operand, so subtract
 * that back out of the high half. Doing it this way rather than negating the
 * operands avoids the INT64_MIN special case that trips the obvious version.
 */
static inline uint64_t mulu64_128(uint64_t a, uint64_t b, uint64_t *hi) {
#if defined(_MSC_VER) && defined(_M_X64)
    return _umul128(a, b, hi);
#elif defined(__SIZEOF_INT128__)
    unsigned __int128 p = (unsigned __int128)a * b;
    *hi = (uint64_t)(p >> 64);
    return (uint64_t)p;
#else
    uint64_t al = (uint32_t)a, ah = a >> 32;
    uint64_t bl = (uint32_t)b, bh = b >> 32;
    uint64_t ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh;
    uint64_t mid = (ll >> 32) + (uint32_t)lh + (uint32_t)hl;
    *hi = hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
    return (mid << 32) | (uint32_t)ll;
#endif
}

static inline uint64_t muls64_128(int64_t a, int64_t b, uint64_t *hi) {
#if defined(_MSC_VER) && defined(_M_X64)
    __int64 h;
    uint64_t lo = (uint64_t)_mul128(a, b, &h);
    *hi = (uint64_t)h;
    return lo;
#elif defined(__SIZEOF_INT128__)
    __int128 p = (__int128)a * b;
    *hi = (uint64_t)((unsigned __int128)p >> 64);
    return (uint64_t)p;
#else
    uint64_t h;
    uint64_t lo = mulu64_128((uint64_t)a, (uint64_t)b, &h);
    if (a < 0) h -= (uint64_t)b;
    if (b < 0) h -= (uint64_t)a;
    *hi = h;
    return lo;
#endif
}

/* ---- bit test family ---- */
static inline uint64_t op_bt(CPU *c, uint64_t v, uint64_t n, int sz) {
    n &= (sz == 8) ? 63 : 31;
    c->cf = (v >> n) & 1;
    return v;
}
static inline uint64_t op_bts(CPU *c, uint64_t v, uint64_t n, int sz) {
    n &= (sz == 8) ? 63 : 31; c->cf = (v >> n) & 1;
    return (v | ((uint64_t)1 << n)) & mask_sz(sz);
}
static inline uint64_t op_btr(CPU *c, uint64_t v, uint64_t n, int sz) {
    n &= (sz == 8) ? 63 : 31; c->cf = (v >> n) & 1;
    return (v & ~((uint64_t)1 << n)) & mask_sz(sz);
}
static inline uint64_t op_btc(CPU *c, uint64_t v, uint64_t n, int sz) {
    n &= (sz == 8) ? 63 : 31; c->cf = (v >> n) & 1;
    return (v ^ ((uint64_t)1 << n)) & mask_sz(sz);
}
/* bsf/bsr leave the destination UNCHANGED when the source is zero, which is
 * why these take the old value rather than returning a sentinel.
 *
 * Only ZF is architecturally defined; CF, OF, SF, AF and PF are undefined. Both
 * Intel and AMD clear them, which is what difftest64 measures, and leaving them
 * at whatever the previous instruction set produces a visible divergence from
 * the hardware for no benefit. Undefined means a correct program cannot depend
 * on the value - it does not mean any value is as good for a recompiler trying
 * to reproduce a specific machine. */
static inline void bitscan_undef_flags(CPU *c) {
    c->cf = 0; c->of = 0; c->sf = 0; c->af = 0; c->pf = 0;
}
static inline uint64_t op_bsf(CPU *c, uint64_t old, uint64_t v, int sz) {
    v &= mask_sz(sz);
    bitscan_undef_flags(c);
    if (!v) { c->zf = 1; return old; }
    c->zf = 0;
    uint64_t i = 0; while (!((v >> i) & 1)) i++;
    return i;
}
static inline uint64_t op_bsr(CPU *c, uint64_t old, uint64_t v, int sz) {
    v &= mask_sz(sz);
    bitscan_undef_flags(c);
    if (!v) { c->zf = 1; return old; }
    c->zf = 0;
    uint64_t i = sz * 8 - 1; while (!((v >> i) & 1)) i--;
    return i;
}

/* ---- SSE memory operands ----
 * memcpy throughout: an SSE memory operand is frequently unaligned (movups
 * exists for a reason), and on x64 the compiler emits movups far more often
 * than on x86 because it no longer has the x87 stack to fall back on. */
static inline float  rdss(uint64_t a) { float  f; memcpy(&f, (const void *)(uintptr_t)a, 4); return f; }
static inline double rdsd(uint64_t a) { double d; memcpy(&d, (const void *)(uintptr_t)a, 8); return d; }
static inline XMM    rdxm(uint64_t a) { XMM x;    memcpy(&x, (const void *)(uintptr_t)a, 16); return x; }
static inline float  rdf32(uint64_t a) { return rdss(a); }
static inline void   wrss(uint64_t a, float  v) { memcpy((void *)(uintptr_t)a, &v, 4); }
static inline void   wrsd(uint64_t a, double v) { memcpy((void *)(uintptr_t)a, &v, 8); }
static inline void   wrxm(uint64_t a, XMM    v) { memcpy((void *)(uintptr_t)a, &v, 16); }

/* MOVSS/MOVSD from memory zero the rest of the register; the register-to-
 * register forms leave the high lanes alone. Named helpers because getting it
 * backwards is invisible until something reads the high lanes. */
static inline void sse_load_ss(XMM *d, float  v) { d->u64[0] = 0; d->u64[1] = 0; d->f32[0] = v; }
static inline void sse_load_sd(XMM *d, double v) { d->u64[0] = 0; d->u64[1] = 0; d->f64[0] = v; }

/* UCOMISS/COMISS/UCOMISD/COMISD: the result lands in ZF/PF/CF and clears
 * OF/SF/AF. An unordered compare - either operand NaN - sets all three, which
 * is what makes `ucomiss; jp` a NaN test. The flags are the UNSIGNED set: a
 * compiler emits `ja`/`jbe` after a float compare, never `jg`/`jle`. */
static inline void sse_compare(CPU *c, double a, double b) {
    c->of = 0; c->sf = 0; c->af = 0;
    if (a != a || b != b) { c->zf = 1; c->pf = 1; c->cf = 1; }   /* unordered */
    else                  { c->zf = (a == b); c->pf = 0; c->cf = (a < b); }
}

/* MINSS/MAXSS are not fmin/fmax. The manual defines them as
 *     if (dst OP src) then dst else src
 * and that "else src" is load-bearing when the operands are equal (so
 * min(+0,-0) is -0 but min(-0,+0) is +0) and when either is NaN, where the
 * comparison is false and the SECOND operand wins. In this exact shape C's
 * "any compare with NaN is false" rule delivers both for free. */
static inline float  sse_minf(float  d, float  s) { return (d < s) ? d : s; }
static inline float  sse_maxf(float  d, float  s) { return (d > s) ? d : s; }
static inline double sse_mind(double d, double s) { return (d < s) ? d : s; }
static inline double sse_maxd(double d, double s) { return (d > s) ? d : s; }

/* CVTTSS2SI and friends yield "integer indefinite" when the source does not
 * fit, where the equivalent C cast is undefined behaviour and may trap. x64
 * adds the 64-bit destination forms, which the 32-bit runtime has no need of:
 * `cvttss2si rax, xmm0` is how a compiler converts a float to a size_t. */
static inline int32_t sse_cvtt_i32(double v) {
    return (v >= -2147483648.0 && v < 2147483648.0) ? (int32_t)v : (int32_t)0x80000000;
}
static inline int64_t sse_cvtt_i64(double v) {
    return (v >= -9223372036854775808.0 && v < 9223372036854775808.0)
           ? (int64_t)v : (int64_t)0x8000000000000000LL;
}

/* RCPPS/RSQRTSS are ~12-bit approximations on hardware. Computing them exactly
 * is the safer error: code that uses them feeds the result to a Newton step or
 * to a normalise, and a MORE accurate input never makes that worse. Matching
 * the hardware's exact error would mean reproducing a lookup table per stepping.
 *
 * The denormal flush is NOT an approximation and is not optional. These four
 * instructions treat a denormal input as a zero of the same sign regardless of
 * MXCSR.DAZ - it is in their specification, not a mode - so a denormal input
 * yields an infinity, where computing in C yields a large finite number.
 * difftest64 caught exactly that: native +Inf against a lifted 0x60B5054D. */
static inline float sse_flush_denormal(float v) {
    /* 0x00800000 is the smallest normal; anything below it with a zero exponent
     * is a denormal. Compared as bits to avoid the host's own FTZ affecting it. */
    uint32_t b; memcpy(&b, &v, 4);
    if ((b & 0x7F800000u) == 0) { b &= 0x80000000u; memcpy(&v, &b, 4); }
    return v;
}
/* The flush applies to the RESULT as well as the operand: a reciprocal small
 * enough to land in the denormal range comes back as a signed zero, not as a
 * denormal. difftest64 found this one lane at a time - `rcpps` where three
 * lanes agreed within the estimate's tolerance and the fourth was native
 * 0x00000000 against a lifted 0x002FF8A1. */
static inline float sse_rcp(float v) {
    return sse_flush_denormal(1.0f / sse_flush_denormal(v));
}
static inline float sse_rsqrt(float v) {
    return sse_flush_denormal(1.0f / sqrtf(sse_flush_denormal(v)));
}

/* MOVMSKPS gathers the four sign bits into the low four bits of a GPR. */
static inline uint32_t sse_movmskps(const XMM *x) {
    return ((x->u32[0] >> 31) & 1) | (((x->u32[1] >> 31) & 1) << 1) |
           (((x->u32[2] >> 31) & 1) << 2) | (((x->u32[3] >> 31) & 1) << 3);
}
static inline uint32_t sse_movmskpd(const XMM *x) {
    return (uint32_t)((x->u64[0] >> 63) & 1) | (uint32_t)(((x->u64[1] >> 63) & 1) << 1);
}

/* ---- control transfer, provided by the generated dispatch table ---- */
void dispatch(CPU *c, uint64_t target);
void dispatch_jmp(CPU *c, uint64_t target);

/* Guest C++ exception handling. Included here, after the CPU typedef, so
 * that every generated translation unit gets the ES3_EH_ENTER macros the
 * lifter emits without the generator having to add an include. */
#include "eh64.h"

#endif /* RECOMP_CPU64_H */

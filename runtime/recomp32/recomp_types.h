/*
 * X-Wing Alliance Static Recompilation - Core Type Definitions
 *
 * Global register model, memory access macros, stack operations,
 * condition macros, and indirect call dispatch.
 *
 * All recompiled functions include this header.
 */

#ifndef RECOMP_TYPES_H
#define RECOMP_TYPES_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

#ifdef _MSC_VER
#include <intrin.h>
#endif

/* ============================================================
 * Global Register Model
 *
 * x86 registers are global variables. ebp is local per-function
 * since most VC6 code uses FPO (Frame Pointer Omission).
 * ============================================================ */

/* Volatile (caller-saved) registers */
extern uint32_t g_eax, g_ecx, g_edx, g_esp;

/* Callee-saved registers (also global for implicit parameter passing).
 * ebp is global too, not a per-function local: MSVC's __EH_prolog sets its
 * CALLER's frame pointer (lea ebp, [esp+0xC]) and returns, so a local ebp
 * would discard it and every C++ EH function would then address off zero.
 * Real x86 has one ebp; FPO functions that never touch it simply pass the
 * caller's through, which is exactly the behaviour we want. */
extern uint32_t g_ebx, g_esi, g_edi, g_ebp;

/* The x87 FPU stack is GLOBAL (8 shared registers), not per-function: helpers
 * like __ftol receive their argument on the FPU stack from the caller, and the
 * control word persists across calls. A per-function local stack would make every
 * cross-call FPU value read as 0. */
extern double   g_st[8];
extern int      g_fp_top;
extern uint16_t g_fpu_cw;

/* The arithmetic flags a function RETURNS with. The lazy flag state is local
 * to each lifted function, but assembly and the CRT return results in flags:
 * MSVC's sin/cos call a helper that returns ZF = "argument is Inf/NaN", and
 * the caller's `je` read its own stale flags instead -- every sin took the
 * NaN path (Gunman's view vectors, and with them the whole frame, went
 * black). So every `ret` publishes the state and every call picks it back up;
 * where the caller overwrites the flags first, the compiler drops the loads.
 * Defined here, weakly, so no project's runtime has to. */
#if defined(_MSC_VER)
#define RECOMP_WEAK __declspec(selectany)
#else
#define RECOMP_WEAK __attribute__((weak))
#endif
RECOMP_WEAK uint32_t g_flag_k, g_flag_a, g_flag_b, g_flag_cf;
#define RECOMP_FLAGS_OUT() (g_flag_k = _flag_k, g_flag_a = _flag_a, g_flag_b = _flag_b, g_flag_cf = _cf)
#define RECOMP_FLAGS_IN()  (_flag_k = g_flag_k, _flag_a = g_flag_a, _flag_b = g_flag_b, _cf = g_flag_cf)

/* Segment registers (flat mode Win32 - effectively unused) */
extern uint16_t g_seg_cs, g_seg_ds, g_seg_es, g_seg_fs, g_seg_gs, g_seg_ss;

/* Function pointer type for recompiled functions */
typedef void (*recomp_func_t)(void);

/* Dispatch table entry */
typedef struct {
    uint32_t address;
    recomp_func_t func;
} recomp_dispatch_entry_t;

/* Dispatch table (generated) */
extern const recomp_dispatch_entry_t recomp_dispatch_table[];
extern const uint32_t recomp_dispatch_count;

/* ============================================================
 * Register Name Aliases (used in generated code)
 * ============================================================ */

#if defined(RECOMP_GENERATED_CODE) && defined(RECOMP_LOCAL_REGS)
/* RECOMP_LOCAL_REGS: each lifted function works on local copies of the eight
 * registers, loaded on entry and written back before every call, tail call
 * and return (and reloaded after calls, which may run native code, callbacks
 * or other lifted functions). Globals can alias any guest memory store, so
 * the optimiser had to reload them after every MEM32 write; locals whose
 * address is never taken stay in host registers. Opt-in: every exit from a
 * body must pass RECOMP_REGS_OUT, which generate.py arranges. */
#define eax l_eax
#define ecx l_ecx
#define edx l_edx
#define ebx l_ebx
#define esp l_esp
#define esi l_esi
#define edi l_edi
#define ebp l_ebp
#define RECOMP_REGS_LOCALS uint32_t l_eax = g_eax, l_ecx = g_ecx, l_edx = g_edx, l_ebx = g_ebx, l_esp = g_esp, l_esi = g_esi, l_edi = g_edi, l_ebp = g_ebp;
#define RECOMP_REGS_OUT() (g_eax = l_eax, g_ecx = l_ecx, g_edx = l_edx, g_ebx = l_ebx, g_esp = l_esp, g_esi = l_esi, g_edi = l_edi, g_ebp = l_ebp)
#define RECOMP_REGS_IN() (l_eax = g_eax, l_ecx = g_ecx, l_edx = g_edx, l_ebx = g_ebx, l_esp = g_esp, l_esi = g_esi, l_edi = g_edi, l_ebp = g_ebp)
#else
#define RECOMP_REGS_LOCALS
#define RECOMP_REGS_OUT() ((void)0)
#define RECOMP_REGS_IN() ((void)0)
#endif

#if defined(RECOMP_GENERATED_CODE) && !defined(RECOMP_LOCAL_REGS)
#define eax g_eax
#define ecx g_ecx
#define edx g_edx
#define ebx g_ebx
#define esp g_esp
#define esi g_esi
#define edi g_edi
#define ebp g_ebp
#endif
#ifdef RECOMP_GENERATED_CODE
/* x87 FPU stack is global; _fpu_cmp stays per-function (set+used within one fn) */
#define _st g_st
#define _fp_top g_fp_top
#define _fpu_cw g_fpu_cw
/* MMX file is global too. The lifter emits _mm[n] (see lift32.MMX_REGS), so the
 * alias has to exist alongside the others or every MMX body fails to compile. */
#define _mm g_mm
#define _seg_cs g_seg_cs
#define _seg_ds g_seg_ds
#define _seg_es g_seg_es
#define _seg_fs g_seg_fs
#define _seg_gs g_seg_gs
#define _seg_ss g_seg_ss
#endif

/* ============================================================
 * Sub-register Access
 * ============================================================ */

#define LO8(r)       ((uint8_t)((r) & 0xFF))
#define HI8(r)       ((uint8_t)(((r) >> 8) & 0xFF))
#define LO16(r)      ((uint16_t)((r) & 0xFFFF))

#define SET_LO8(r, v)   ((r) = ((r) & 0xFFFFFF00u) | ((uint32_t)(uint8_t)(v)))
#define SET_HI8(r, v)   ((r) = ((r) & 0xFFFF00FFu) | (((uint32_t)(uint8_t)(v)) << 8))
#define SET_LO16(r, v)  ((r) = ((r) & 0xFFFF0000u) | ((uint32_t)(uint16_t)(v)))

/* ============================================================
 * Memory Access
 *
 * The original XWA binary uses a fixed image base of 0x00400000.
 * We map the original data sections at their original VAs using
 * VirtualAlloc/CreateFileMapping so that address-dependent code
 * works correctly.
 *
 * g_mem_base is the offset from original VA to actual mapped address.
 * For fixed-base mapping, this is 0.
 * ============================================================ */

extern ptrdiff_t g_mem_base;

#ifdef RECOMP_FLAT_MEMORY
/* Guest VAs ARE host addresses (a 32-bit host mapping each module at its own
 * base): nothing to add, and no global to reload on every access. */
#define ADDR(va)     ((uintptr_t)(uint32_t)(va))
#else
#define ADDR(va)     ((uintptr_t)(uint32_t)(va) + g_mem_base)
#endif

/* Thread-relative segment bases. In Win32, fs: points at the TIB/TEB; gs is
 * unused on x86. The lifter emits fs:/gs: accesses as FS_BASE/GS_BASE + addr,
 * so the runtime points g_fs_base at a simulated TIB (VA). cs/ds/es/ss are flat. */
extern uint32_t g_fs_base;
extern uint32_t g_gs_base;
#define FS_BASE  g_fs_base
#define GS_BASE  g_gs_base

#define MEM8(addr)   (*(volatile uint8_t  *)ADDR(addr))
#define MEM16(addr)  (*(volatile uint16_t *)ADDR(addr))
#define MEM32(addr)  (*(volatile uint32_t *)ADDR(addr))
#define MEM64(addr)  (*(volatile uint64_t *)ADDR(addr))
#define MEMF(addr)   (*(volatile float    *)ADDR(addr))
#define MEMD(addr)   (*(volatile double   *)ADDR(addr))

/* Set 32-bit values in memory (for rep stosd) */
static inline void MEMSET32(void* dst, uint32_t val, uint32_t count) {
    uint32_t* p = (uint32_t*)dst;
    for (uint32_t i = 0; i < count; i++) p[i] = val;
}

/* And 16-bit, for `rep stosw` -- which is how a run-length codec writes a run
 * of one colour, and so how most of a 1990s background image gets drawn. */
static inline void MEMSET16(void* dst, uint16_t val, uint32_t count) {
    uint16_t* p = (uint16_t*)dst;
    for (uint32_t i = 0; i < count; i++) p[i] = val;
}

/* ============================================================
 * Stack Operations
 * ============================================================ */

/* Evaluate the operand BEFORE moving esp. x86 reads the source of
 * push dword ptr [esp+N] at the OLD esp; decrementing first makes every
 * esp-relative push read one slot too low -- which lands on the return
 * address the caller pushed, so the callee sees RECOMP_RETADDR as an
 * argument. */
#define PUSH32(sp, val) do { \
    uint32_t _pv = (uint32_t)(val); \
    (sp) -= 4; \
    MEM32(sp) = _pv; \
} while(0)

#define POP32_VAL(sp) ({ \
    uint32_t _v = MEM32(sp); \
    (sp) += 4; \
    _v; \
})

/* MSVC doesn't support statement expressions, so use a function */
#ifdef _MSC_VER
static inline uint32_t _pop32(uint32_t* sp) {
    uint32_t v = MEM32(*sp);
    *sp += 4;
    return v;
}
#undef POP32_VAL
#define POP32_VAL(sp) _pop32(&(sp))
#endif

/* Two-arg pop: store the popped value into an lvalue destination (register or
 * MEM32(...)). The lifter emits this form for `pop r/m32`. Defined via POP32_VAL
 * so it picks up the GCC statement-expr / MSVC inline-function variant above. */
#define POP32(sp, dest) do { (dest) = POP32_VAL(sp); } while(0)

/*
 * The 16-bit forms. `push bp` / `pop bp` (66 55 / 66 5D) move esp by TWO, and
 * the pop writes only BP -- the top half of EBP is untouched.
 *
 * Lifting them as their 32-bit cousins looks harmless while a push and a pop
 * are paired, because the stack still balances. The register does not: a
 * 32-bit pop into ebp replaces the whole of it with the zero-extended word, so
 * `push bp ... pop bp ... leave` came back with ebp = 0x0000FD48 instead of
 * 0x022AFD48, handed that to esp, and the next stack read was at 64 KB. This
 * game's sprite code is full of 16-bit register traffic; that is where it bit.
 */
#define PUSH16(sp, val) do { \
    uint16_t _pv = (uint16_t)(val); \
    (sp) -= 2; \
    MEM16(sp) = _pv; \
} while(0)

static inline uint16_t _pop16(uint32_t *sp) {
    uint16_t v = MEM16(*sp);
    *sp += 2;
    return v;
}
#define POP16_VAL(sp) _pop16(&(sp))

#define PUSHAD() do { \
    uint32_t _tmp_esp = esp; \
    PUSH32(esp, eax); PUSH32(esp, ecx); PUSH32(esp, edx); PUSH32(esp, ebx); \
    PUSH32(esp, _tmp_esp); PUSH32(esp, ebp); PUSH32(esp, esi); PUSH32(esp, edi); \
} while(0)

#define POPAD() do { \
    edi = POP32_VAL(esp); esi = POP32_VAL(esp); ebp = POP32_VAL(esp); \
    esp += 4; /* skip saved ESP */ \
    ebx = POP32_VAL(esp); edx = POP32_VAL(esp); ecx = POP32_VAL(esp); eax = POP32_VAL(esp); \
} while(0)

/* ============================================================
 * Condition Macros
 *
 * Pattern-matched from flag-setter (cmp/test/sub/etc.) to
 * flag-consumer (jcc/setcc/cmovcc).
 * ============================================================ */

/* Compare-based conditions (from cmp a, b) */
#define CMP_EQ(a, b)   ((uint32_t)(a) == (uint32_t)(b))
#define CMP_NE(a, b)   ((uint32_t)(a) != (uint32_t)(b))
#define CMP_B(a, b)    ((uint32_t)(a) < (uint32_t)(b))      /* unsigned < */
#define CMP_BE(a, b)   ((uint32_t)(a) <= (uint32_t)(b))     /* unsigned <= */
#define CMP_A(a, b)    ((uint32_t)(a) > (uint32_t)(b))      /* unsigned > */
#define CMP_AE(a, b)   ((uint32_t)(a) >= (uint32_t)(b))     /* unsigned >= */
#define CMP_L(a, b)    ((int32_t)(a) < (int32_t)(b))        /* signed < */
#define CMP_LE(a, b)   ((int32_t)(a) <= (int32_t)(b))       /* signed <= */
#define CMP_G(a, b)    ((int32_t)(a) > (int32_t)(b))        /* signed > */
#define CMP_GE(a, b)   ((int32_t)(a) >= (int32_t)(b))       /* signed >= */
#define CMP_S(a, b)    ((int32_t)((uint32_t)(a) - (uint32_t)(b)) < 0)  /* sign flag */
#define CMP_NS(a, b)   ((int32_t)((uint32_t)(a) - (uint32_t)(b)) >= 0)
#define CMP_O(a, b)    0  /* TODO: overflow detection */
#define CMP_NO(a, b)   1
#define CMP_P(a, b)    0  /* TODO: parity */
#define CMP_NP(a, b)   1

/* Test-based conditions (from test a, b) */
#define TEST_Z(a, b)   (((uint32_t)(a) & (uint32_t)(b)) == 0)
#define TEST_NZ(a, b)  (((uint32_t)(a) & (uint32_t)(b)) != 0)
#define TEST_S(a, b)   ((int32_t)((uint32_t)(a) & (uint32_t)(b)) < 0)
#define TEST_NS(a, b)  ((int32_t)((uint32_t)(a) & (uint32_t)(b)) >= 0)
#define TEST_G(a, b)   ((int32_t)((uint32_t)(a) & (uint32_t)(b)) > 0)
#define TEST_LE(a, b)  ((int32_t)((uint32_t)(a) & (uint32_t)(b)) <= 0)

/* Bit test (from bt) */
#define BT_CF(base, bit) (((uint32_t)(base) >> ((uint32_t)(bit) & 31)) & 1)

/*
 * Runtime flag kind.
 *
 * A jcc is normally paired with its flag-setter at lift time, but the setter
 * is not always statically known: MSVC routinely branches into a block whose
 * predecessors set the flags with different instructions (the signed-modulo
 * idiom `and/jns/dec/or/inc/je` is one join, 64-bit compares another). The
 * lifter used to fall back to a stale _cf at those sites, which made the
 * branch read whatever carry happened to be lying around.
 *
 * _flag_a/_flag_b already survive across blocks -- they are plain function
 * locals -- so recording which *kind* of instruction wrote them is enough to
 * evaluate any condition exactly, wherever the branch turns up.
 */
enum {
    FK_NONE = 0,
    FK_CMP,     /* cmp, sub       -- a - b            */
    FK_ADD,     /* add            -- a + b            */
    FK_TEST,    /* and/or/xor/test/shift -- a & b     */
    FK_BT,      /* bt             -- CF = bit b of a  */
    FK_FCOM,    /* fcom           -- a is -1/0/1, 2 = unordered */
    /* INC and DEC are ADD and SUB that do NOT write CF. No condition can tell
     * them apart (a jcc reading CF after an inc is reading a flag the
     * instruction never wrote), but PUSHFD can: it has to report the carry
     * that was already there rather than the one the addition would have
     * produced. */
    FK_INC,     /* inc            -- a + b, CF preserved */
    FK_DEC,     /* dec            -- a - b, CF preserved */
    /* The flags as a literal word, from POPFD. Nothing is derived: every flag
     * is read from its own bit. The lazy triple cannot express an arbitrary
     * combination of flags, and a program that restores a saved EFLAGS is
     * asking for exactly that. */
    FK_EFLAGS
};

/* A NARROW setter's kind carries its left-align shift (24 for 8-bit, 16 for
 * 16-bit) in bits 8 and up. CF, ZF, SF and OF come out of the left-aligned
 * operands at 32 bits unchanged (lift32's _flag_capture); PF and AF are read
 * off the result's LOW byte, and only the shift says where that byte is. The
 * lifter knows the width statically, but a jcc at a join point reads the kind
 * at runtime, and there `fnstsw ax; test ah, 5; jp` -- MSVC's `x < 0.0` --
 * needs the parity of AH. Every reader masks the kind with FK_KIND. */
#define FK_NARROW(k, shift) ((uint32_t)(k) | ((uint32_t)(shift) << 8))
#define FK_KIND(k)          ((k) & 0xFFu)
#define FK_SHIFT(k)         ((k) >> 8)

enum {
    CC_E = 0, CC_NE, CC_S, CC_NS, CC_G, CC_GE, CC_L, CC_LE,
    CC_A, CC_AE, CC_B, CC_BE, CC_O, CC_NO, CC_P, CC_NP
};

static inline uint32_t recomp_parity8(uint8_t v);

static inline int recomp_cond(uint32_t kind, uint32_t a, uint32_t b, int cc) {
    uint32_t r, sh = FK_SHIFT(kind);
    int zf, sf, cf, of, pf;

    kind = FK_KIND(kind);
    if (kind == FK_EFLAGS) {
        cf = (int)(a & 1u);
        pf = (int)((a >> 2) & 1u);
        zf = (int)((a >> 6) & 1u);
        sf = (int)((a >> 7) & 1u);
        of = (int)((a >> 11) & 1u);
        goto decide;
    }

    if (kind == FK_FCOM) {
        int32_t v = (int32_t)a;          /* -1 less, 0 equal, 1 greater, 2 unordered */
        if (v == 2) {                    /* NaN: ZF = PF = CF = 1, as fcomi/sahf leave them */
            switch (cc) {
            case CC_E: case CC_B: case CC_BE: case CC_P: return 1;
            default:                                     return 0;
            }
        }
        switch (cc) {
        case CC_NP:               return 1;
        case CC_E:                return v == 0;
        case CC_NE:               return v != 0;
        case CC_B:  case CC_L:    return v <  0;
        case CC_BE: case CC_LE:   return v <= 0;
        case CC_A:  case CC_G:    return v >  0;
        case CC_AE: case CC_GE:   return v >= 0;
        default:                  return 0;
        }
    }

    switch (kind) {
    case FK_ADD:
    case FK_INC:                          /* CF here is the ADD's; after INC the
                                             real CF is the preserved one --
                                             see recomp_cond_cf */
        r  = a + b;
        cf = (r < a);
        of = (int)((~(a ^ b) & (a ^ r)) >> 31);
        break;
    case FK_TEST:
        r  = a & b;
        cf = 0;
        of = 0;
        break;
    case FK_BT:
        r  = 0;
        cf = (int)((a >> (b & 31)) & 1u);
        of = 0;
        break;
    default:                              /* FK_CMP, FK_DEC and FK_NONE */
        r  = a - b;
        cf = (a < b);
        of = (int)(((a ^ b) & (a ^ r)) >> 31);
        break;
    }
    zf = (r == 0);
    sf = (int)(r >> 31);
    pf = (int)recomp_parity8((uint8_t)(r >> sh));

decide:
    switch (cc) {
    case CC_E:   return zf;
    case CC_NE:  return !zf;
    case CC_S:   return sf;
    case CC_NS:  return !sf;
    case CC_G:   return !zf && (sf == of);
    case CC_GE:  return sf == of;
    case CC_L:   return sf != of;
    case CC_LE:  return zf || (sf != of);
    case CC_A:   return !cf && !zf;
    case CC_AE:  return !cf;
    case CC_B:   return cf;
    case CC_BE:  return cf || zf;
    case CC_O:   return of;
    case CC_NO:  return !of;
    case CC_P:   return pf;
    case CC_NP:  return !pf;
    }
    return 0;
}

/* recomp_cond, with the carry that inc/dec PRESERVE. `cmp; inc; jae` reads
 * the cmp's CF, which the lifted code still has in _cf; deriving it from the
 * inc's operands is wrong (it corrupted MSVC 6's small-block heap). */
/* x87 compare outcome: -1 less, 0 equal, 1 greater, 2 unordered (a NaN). */
#define FPU_CMP(x, y) ((x) < (y) ? -1 : (x) > (y) ? 1 : (x) == (y) ? 0 : 2)

static inline int recomp_cond_cf(uint32_t kind, uint32_t a, uint32_t b, int cc,
                                 uint32_t cf) {
    if ((FK_KIND(kind) == FK_INC || FK_KIND(kind) == FK_DEC) &&
        (cc == CC_B || cc == CC_AE || cc == CC_A || cc == CC_BE)) {
        int zf = recomp_cond(kind, a, b, CC_E);
        switch (cc) {
        case CC_B:  return cf != 0;
        case CC_AE: return cf == 0;
        case CC_A:  return cf == 0 && !zf;
        default:    return cf != 0 || zf;
        }
    }
    return recomp_cond(kind, a, b, cc);
}

/* CF as adc/sbb read it: derived from an add/sub/cmp's operands (which do
 * not write `_cf`), otherwise the `_cf` the instruction kept (adc, sbb, shifts,
 * logic ops, inc/dec, popfd/sahf). The lifter's precise_carry option. */
static inline uint32_t recomp_carry(uint32_t kind, uint32_t a, uint32_t b, uint32_t cf) {
    switch (FK_KIND(kind)) {
    case FK_ADD: return a + b < a;
    case FK_CMP: return a < b;
    default:     return cf;
    }
}

/* Bit 1 reads as 1 on every x86, and IF is set in any process this runtime
 * will ever host. A PUSHFD that omitted them differs from hardware in a way
 * guest CPU-detection code notices. */
#define RECOMP_EFLAGS_FIXED 0x00000202u

static inline uint32_t recomp_parity8(uint8_t v) {
    v ^= (uint8_t)(v >> 4);
    v ^= (uint8_t)(v >> 2);
    v ^= (uint8_t)(v >> 1);
    return (uint32_t)((~v) & 1u);
}

/* PF of a lazily captured result: parity of its low byte. `shift` undoes the
 * left-alignment _flag_capture gives narrow operands (24 for 8-bit). */
#define RECOMP_PF(r, shift) ((int)recomp_parity8((uint8_t)((uint32_t)(r) >> (shift))))

/* The six arithmetic flags as a word, given a result and the three that do
 * not come from it. */
static inline uint32_t recomp_flags_pack(uint32_t r, uint32_t cf, uint32_t af,
                                         uint32_t of) {
    uint32_t e = RECOMP_EFLAGS_FIXED | (cf & 1u) | ((af & 1u) << 4) | ((of & 1u) << 11);
    if (r == 0) e |= 0x40u;               /* ZF */
    e |= (r >> 31) << 7;                  /* SF */
    e |= recomp_parity8((uint8_t)r) << 2; /* PF */
    return e;
}

/*
 * The flags as one word: PUSHFD, and the flag oracle the differential harness
 * compares against.
 *
 * The lazy tuple already holds everything the six arithmetic flags derive
 * from, so this is that derivation done all at once instead of one flag at a
 * time. CF is the exception: the tuple carries it for ADD/SUB/CMP, while
 * shifts, rotates, NEG, STC/CLC/CMC and ADC/SBB maintain the running `_cf` --
 * so every other kind takes the carry it is handed.
 *
 * AF exists here and nowhere else in the 32-bit model. It costs nothing --
 * (a ^ b ^ r) bit 4 comes out of operands the tuple already stored -- and
 * PUSHFD round-trips it, so code that saves and restores flags around a call
 * does not silently drop a flag it never mentions. Hardware leaves AF
 * undefined after a logic op; this reports 0 there, deterministically.
 */
static inline uint32_t recomp_eflags(uint32_t kind, uint32_t a, uint32_t b,
                                     uint32_t cf_in, int df) {
    uint32_t r, e, sh = FK_SHIFT(kind);
    uint32_t cf = cf_in & 1u, of = 0, af = 0;

    kind = FK_KIND(kind);

    if (kind == FK_EFLAGS) {
        /* Already a word. DF still comes from `_df`: a CLD after the POPFD
           moved it and the saved word did not follow.

           AC (18) and ID (21) ride along because a POPFD/PUSHFD pair is how
           every 1990s binary asks the CPU a yes/no question about itself: write
           the bit, read it back, see whether it stuck. ID is the CPUID probe --
           drop it here and the readback matches the original word, the program
           concludes there is no CPUID, and a game that needs MMX puts up "This
           CPU does not have an MMX unit" and quits. They are the only two bits
           user mode can actually toggle, so carrying them costs one mask. */
        e = (a & (1u | 4u | 0x10u | 0x40u | 0x80u | 0x800u
                  | 0x40000u | 0x200000u)) | RECOMP_EFLAGS_FIXED;
        return (df < 0) ? (e | 0x400u) : e;
    }

    switch (kind) {
    case FK_ADD: case FK_INC:
        r  = a + b;
        if (kind == FK_ADD) cf = (r < a);
        of = (~(a ^ b) & (a ^ r)) >> 31;
        af = ((a ^ b ^ r) >> (sh + 4)) & 1u;
        break;
    case FK_TEST:
        /* and/or/xor/test clear CF (the lifter stores that); a shift leaves
           the bit it shifted out in `_cf`. Either way the carry is `cf_in`. */
        r  = a & b;
        break;
    case FK_BT:
        r  = 0;
        cf = (a >> (b & 31)) & 1u;
        break;
    case FK_NONE: case FK_FCOM:
        /* Nothing has written the arithmetic flags (or fcom wrote a comparison
           this word cannot express). Report the carry we hold and leave the
           rest clear: deriving ZF and PF from an invented zero result would
           report two flags as set that no instruction ever set. */
        e = RECOMP_EFLAGS_FIXED | cf;
        return (df < 0) ? (e | 0x400u) : e;
    default:                              /* FK_CMP, FK_DEC */
        r  = a - b;
        if (kind == FK_CMP) cf = (a < b);
        of = ((a ^ b) & (a ^ r)) >> 31;
        af = ((a ^ b ^ r) >> (sh + 4)) & 1u;
        break;
    }

    e = recomp_flags_pack(r, cf, af, of);
    if (sh)                               /* narrow: PF of the low byte, at bit sh */
        e = (e & ~4u) | (recomp_parity8((uint8_t)(r >> sh)) << 2);
    if (df < 0) e |= 0x400u;              /* DF */
    return e;
}

/*
 * ADC and SBB take the carry as a THIRD input, and the lazy triple cannot hold
 * one: folding it into the source (`a + (b + c)`) loses it whenever b is all
 * ones, and modelling `a - b - c` as a SUB of `b + c` gets the borrow wrong
 * whenever a != b. So they compute their flags at the instruction and hand
 * back the finished word, which the caller stores as FK_EFLAGS -- the same
 * escape hatch POPFD uses.
 */
static inline uint32_t recomp_flags_adc(uint32_t a, uint32_t b, uint32_t c) {
    uint32_t r = a + b + c;
    return recomp_flags_pack(r,
                             c ? (r <= a) : (r < a),
                             ((a ^ b ^ r) >> 4) & 1u,
                             (~(a ^ b) & (a ^ r)) >> 31);
}

static inline uint32_t recomp_flags_sbb(uint32_t a, uint32_t b, uint32_t c) {
    uint32_t r = a - b - c;
    return recomp_flags_pack(r,
                             c ? (a <= b) : (a < b),
                             ((a ^ b ^ r) >> 4) & 1u,
                             ((a ^ b) & (a ^ r)) >> 31);
}

/*
 * A rotate writes CF and leaves ZF, SF and OF alone.
 *
 * The lazy flag triple cannot say that: it holds one instruction's operands, so
 * publishing the rotate's carry through it would have to throw away the compare
 * that set ZF, and NOT publishing it leaves a following `jae`/`jb` reading the
 * carry of whatever came before. The RLE sprite decoder in Gizmos & Gadgets
 * does exactly this -- `sub bx,cx; rcr cl,1; rep movsw; jae` -- where the jae
 * is asking whether the count was odd, and answering it with the sub's borrow
 * ran the decoder off the end of both the sprite and the framebuffer.
 *
 * So a rotate freezes the flags into a word, the same escape hatch ADC and
 * POPFD use, and overwrites just the carry.
 *
 * OF is carried over rather than recomputed: x86 only defines it for a rotate
 * of exactly 1, and no compiler emits a branch on it.
 */
static inline uint32_t recomp_eflags_setcf(uint32_t kind, uint32_t a, uint32_t b,
                                           uint32_t cf, int df) {
    return (recomp_eflags(kind, a, b, cf, df) & ~1u) | (cf & 1u);
}

/* ============================================================
 * Bit Manipulation
 * ============================================================ */

#define ROL32(val, n) (((uint32_t)(val) << ((n) & 31)) | ((uint32_t)(val) >> (32 - ((n) & 31))))
#define ROR32(val, n) (((uint32_t)(val) >> ((n) & 31)) | ((uint32_t)(val) << (32 - ((n) & 31))))
#define BSWAP32(val)  ( (((val) & 0xFF) << 24) | (((val) & 0xFF00) << 8) | \
                        (((val) >> 8) & 0xFF00) | (((val) >> 24) & 0xFF) )

/* ============================================================
 * MMX
 *
 * Eight 64-bit registers holding packed bytes/words/dwords. On real hardware
 * they alias the x87 stack, which is why MMX code must `emms` before touching
 * the FPU again; we keep the two apart, so `emms` is a no-op here and code that
 * deliberately interleaved them would behave differently. POD does not: it is
 * the MMX build, and its rasterizer is a well-formed MMX block per span.
 *
 * Global, like the rest of the register file here; a multi-threaded target
 * wants them thread-local instead.
 * ============================================================ */

extern uint64_t g_mm[8];

#define MM_W(v, i)  ((int16_t)((uint64_t)(v) >> ((i) * 16)))
#define MM_D(v, i)  ((int32_t)((uint64_t)(v) >> ((i) * 32)))
#define MM_PUT_W(i, x) ((uint64_t)(uint16_t)(x) << ((i) * 16))
#define MM_PUT_D(i, x) ((uint64_t)(uint32_t)(x) << ((i) * 32))

static inline int16_t mmx_sat16(int32_t v) {
    return (int16_t)(v > 32767 ? 32767 : v < -32768 ? -32768 : v);
}

static inline uint64_t mmx_paddw(uint64_t a, uint64_t b) {
    uint64_t r = 0;
    for (int i = 0; i < 4; i++) r |= MM_PUT_W(i, MM_W(a, i) + MM_W(b, i));
    return r;
}
static inline uint64_t mmx_psubw(uint64_t a, uint64_t b) {
    uint64_t r = 0;
    for (int i = 0; i < 4; i++) r |= MM_PUT_W(i, MM_W(a, i) - MM_W(b, i));
    return r;
}
static inline uint64_t mmx_paddd(uint64_t a, uint64_t b) {
    return MM_PUT_D(0, MM_D(a, 0) + MM_D(b, 0)) | MM_PUT_D(1, MM_D(a, 1) + MM_D(b, 1));
}
static inline uint64_t mmx_psubd(uint64_t a, uint64_t b) {
    return MM_PUT_D(0, MM_D(a, 0) - MM_D(b, 0)) | MM_PUT_D(1, MM_D(a, 1) - MM_D(b, 1));
}
static inline uint64_t mmx_paddsw(uint64_t a, uint64_t b) {
    uint64_t r = 0;
    for (int i = 0; i < 4; i++) r |= MM_PUT_W(i, mmx_sat16(MM_W(a, i) + MM_W(b, i)));
    return r;
}
static inline uint64_t mmx_psubsw(uint64_t a, uint64_t b) {
    uint64_t r = 0;
    for (int i = 0; i < 4; i++) r |= MM_PUT_W(i, mmx_sat16(MM_W(a, i) - MM_W(b, i)));
    return r;
}
/* High half of each signed 16x16 product -- the fixed-point multiply an MMX
 * rasterizer scales colour and texture coordinates with. */
static inline uint64_t mmx_pmulhw(uint64_t a, uint64_t b) {
    uint64_t r = 0;
    for (int i = 0; i < 4; i++)
        r |= MM_PUT_W(i, (int16_t)(((int32_t)MM_W(a, i) * MM_W(b, i)) >> 16));
    return r;
}
static inline uint64_t mmx_pmullw(uint64_t a, uint64_t b) {
    uint64_t r = 0;
    for (int i = 0; i < 4; i++) r |= MM_PUT_W(i, (int16_t)((int32_t)MM_W(a, i) * MM_W(b, i)));
    return r;
}
/* Two dwords, each the sum of a neighbouring pair of 16x16 products. */
static inline uint64_t mmx_pmaddwd(uint64_t a, uint64_t b) {
    uint64_t r = 0;
    for (int i = 0; i < 2; i++)
        r |= MM_PUT_D(i, (int32_t)MM_W(a, i*2) * MM_W(b, i*2)
                       + (int32_t)MM_W(a, i*2+1) * MM_W(b, i*2+1));
    return r;
}
/* Interleave: the low (or high) halves of a and b, a's element first. */
static inline uint64_t mmx_punpcklwd(uint64_t a, uint64_t b) {
    return MM_PUT_W(0, MM_W(a,0)) | MM_PUT_W(1, MM_W(b,0))
         | MM_PUT_W(2, MM_W(a,1)) | MM_PUT_W(3, MM_W(b,1));
}
static inline uint64_t mmx_punpckhwd(uint64_t a, uint64_t b) {
    return MM_PUT_W(0, MM_W(a,2)) | MM_PUT_W(1, MM_W(b,2))
         | MM_PUT_W(2, MM_W(a,3)) | MM_PUT_W(3, MM_W(b,3));
}
static inline uint64_t mmx_punpcklbw(uint64_t a, uint64_t b) {
    uint64_t r = 0;
    for (int i = 0; i < 4; i++) {
        r |= (uint64_t)(uint8_t)(a >> (i*8)) << (i*16);
        r |= (uint64_t)(uint8_t)(b >> (i*8)) << (i*16 + 8);
    }
    return r;
}
static inline uint64_t mmx_punpckhbw(uint64_t a, uint64_t b) {
    uint64_t r = 0;
    for (int i = 0; i < 4; i++) {
        r |= (uint64_t)(uint8_t)(a >> (32 + i*8)) << (i*16);
        r |= (uint64_t)(uint8_t)(b >> (32 + i*8)) << (i*16 + 8);
    }
    return r;
}
static inline uint64_t mmx_punpckldq(uint64_t a, uint64_t b) {
    return (uint64_t)(uint32_t)a | ((uint64_t)(uint32_t)b << 32);
}
static inline uint64_t mmx_punpckhdq(uint64_t a, uint64_t b) {
    return (uint64_t)(uint32_t)(a >> 32) | ((uint64_t)(uint32_t)(b >> 32) << 32);
}
/* Shifts. A count wider than the element is not a wrapped shift on x86: the
 * logical forms produce zero and the arithmetic ones produce the sign. */
static inline uint64_t mmx_psllq(uint64_t a, uint32_t c) { return c > 63 ? 0 : a << c; }
static inline uint64_t mmx_psrlq(uint64_t a, uint32_t c) { return c > 63 ? 0 : a >> c; }
static inline uint64_t mmx_psllw(uint64_t a, uint32_t c) {
    uint64_t r = 0;
    if (c > 15) return 0;
    for (int i = 0; i < 4; i++) r |= MM_PUT_W(i, (uint16_t)MM_W(a, i) << c);
    return r;
}
static inline uint64_t mmx_psrlw(uint64_t a, uint32_t c) {
    uint64_t r = 0;
    if (c > 15) return 0;
    for (int i = 0; i < 4; i++) r |= MM_PUT_W(i, (uint16_t)MM_W(a, i) >> c);
    return r;
}
static inline uint64_t mmx_psraw(uint64_t a, uint32_t c) {
    uint64_t r = 0;
    if (c > 15) c = 15;
    for (int i = 0; i < 4; i++) r |= MM_PUT_W(i, (int16_t)(MM_W(a, i) >> c));
    return r;
}
static inline uint64_t mmx_pslld(uint64_t a, uint32_t c) {
    if (c > 31) return 0;
    return MM_PUT_D(0, (uint32_t)MM_D(a,0) << c) | MM_PUT_D(1, (uint32_t)MM_D(a,1) << c);
}
static inline uint64_t mmx_psrld(uint64_t a, uint32_t c) {
    if (c > 31) return 0;
    return MM_PUT_D(0, (uint32_t)MM_D(a,0) >> c) | MM_PUT_D(1, (uint32_t)MM_D(a,1) >> c);
}
static inline uint64_t mmx_psrad(uint64_t a, uint32_t c) {
    if (c > 31) c = 31;
    return MM_PUT_D(0, MM_D(a,0) >> c) | MM_PUT_D(1, MM_D(a,1) >> c);
}
/* Pack with saturation, a's elements low. */
static inline uint64_t mmx_packssdw(uint64_t a, uint64_t b) {
    return MM_PUT_W(0, mmx_sat16(MM_D(a,0))) | MM_PUT_W(1, mmx_sat16(MM_D(a,1)))
         | MM_PUT_W(2, mmx_sat16(MM_D(b,0))) | MM_PUT_W(3, mmx_sat16(MM_D(b,1)));
}
static inline uint64_t mmx_packuswb(uint64_t a, uint64_t b) {
    uint64_t r = 0;
    for (int i = 0; i < 4; i++) {
        int16_t v = MM_W(a, i); uint8_t p = (uint8_t)(v < 0 ? 0 : v > 255 ? 255 : v);
        r |= (uint64_t)p << (i * 8);
        v = MM_W(b, i);         p = (uint8_t)(v < 0 ? 0 : v > 255 ? 255 : v);
        r |= (uint64_t)p << (32 + i * 8);
    }
    return r;
}
static inline uint64_t mmx_pcmpeqw(uint64_t a, uint64_t b) {
    uint64_t r = 0;
    for (int i = 0; i < 4; i++) r |= MM_PUT_W(i, MM_W(a,i) == MM_W(b,i) ? 0xFFFF : 0);
    return r;
}
static inline uint64_t mmx_pcmpgtw(uint64_t a, uint64_t b) {
    uint64_t r = 0;
    for (int i = 0; i < 4; i++) r |= MM_PUT_W(i, MM_W(a,i) > MM_W(b,i) ? 0xFFFF : 0);
    return r;
}
/* ============================================================
 * FPU Stack Helpers
 * ============================================================ */

/* The x87 register is 80 bits with a 64-bit mantissa; ours is a double with 53.
 * That is invisible for arithmetic but not for `fild qword / fistp qword`, the
 * era's idiom for moving 8 bytes (a packed x,y pair, a 64-bit counter): through
 * a double, a large high dword rounds away the low bits. Nocturne's clipper
 * copies vertices that way and got x = -20/65536 where the original had 0, then
 * filled a 65535-pixel span. So each slot shadows the exact int64 `fild qword`
 * loaded, and `fistp qword` stores the shadow while the slot's double still
 * equals it (nothing has computed on it since).
 *
 * selectany/weak: one shared instance, defined by the header itself, so no
 * project runtime has to grow a definition for it. */
#if defined(_MSC_VER)
#define RECOMP_SHARED_DATA __declspec(selectany)
#else
#define RECOMP_SHARED_DATA __attribute__((weak))
#endif
RECOMP_SHARED_DATA int64_t g_st_i64[8] = {0};

static inline void fp_push_impl(double* st, int* top, double val) {
    /* Shift stack down, push new value */
    for (int i = 7; i > 0; i--) { st[i] = st[i-1]; g_st_i64[i] = g_st_i64[i-1]; }
    st[0] = val;
    g_st_i64[0] = 0;
    (*top)++;
}

static inline double fp_pop_impl(double* st, int* top) {
    double val = st[0];
    for (int i = 0; i < 7; i++) { st[i] = st[i+1]; g_st_i64[i] = g_st_i64[i+1]; }
    st[7] = 0.0;
    g_st_i64[7] = 0;
    (*top)--;
    return val;
}

#define fp_push(val) fp_push_impl(_st, &_fp_top, (val))
#define fp_pop()     fp_pop_impl(_st, &_fp_top)

/* fild qword: push with the exact value shadowed. */
#define fp_push_i64(v) do { int64_t _pv = (int64_t)(v); \
    fp_push((double)_pv); g_st_i64[0] = _pv; } while (0)
/* fxch st(i), keeping each slot's shadow with its value. */
#define fp_xch(i) do { double _t = _st[0]; _st[0] = _st[i]; _st[i] = _t; \
    int64_t _ti = g_st_i64[0]; g_st_i64[0] = g_st_i64[i]; g_st_i64[i] = _ti; } while (0)

/* fist/fistp round by the control word's RC field (bits 10-11), not by C's
 * truncating cast. MSVC's __ftol sets chop before its fistp, so a plain cast
 * looked right for years; Quake-lineage rasterisers deliberately run fistp in
 * nearest (the default), floor or ceil mode, and a cast shifts every span and
 * texture coordinate by up to one. */
static inline double fp_round_cw(double v, uint16_t cw) {
    switch ((cw >> 10) & 3) {
    case 0:  return nearbyint(v);   /* nearest-even: the host default mode */
    case 1:  return floor(v);
    case 2:  return ceil(v);
    default: return trunc(v);
    }
}
#define fp_to_int(v) fp_round_cw((v), _fpu_cw)

/* fistp qword: the exact shadow while st0 is still the value fild loaded. */
static inline int64_t fp_st0_to_i64(double v0, int64_t shadow, uint16_t cw) {
    return (v0 == (double)shadow) ? shadow : (int64_t)fp_round_cw(v0, cw);
}

/* The 80-bit extended format, for `fld/fstp xword`. The model's stack is
 * double, so a load rounds to double and a store widens. The CRT keeps 2*pi
 * and friends as xword constants; a load that pushed 0.0 made sin/cos reduce
 * by fmod(x, 0) = NaN, and Gunman's AngleVectors drew nothing. */
static inline double fp_ld80(const uint8_t* p) {
    uint64_t m; uint16_t se;
    memcpy(&m, p, 8); memcpy(&se, p + 8, 2);
    int e = se & 0x7FFF;
    double v;
    if (e == 0x7FFF)
        v = (m << 1) ? NAN : INFINITY;
    else
        v = ldexp((double)m, (e ? e : 1) - 16383 - 63);
    return (se & 0x8000) ? -v : v;
}
static inline void fp_st80(uint8_t* p, double v) {
    uint64_t m = 0; uint16_t se = signbit(v) ? 0x8000 : 0;
    if (isnan(v)) { se |= 0x7FFF; m = 0xC000000000000000ull; }
    else if (isinf(v)) { se |= 0x7FFF; m = 0x8000000000000000ull; }
    else if (v != 0.0) {
        int e; double f = frexp(fabs(v), &e);      /* f in [0.5, 1) */
        m = (uint64_t)ldexp(f, 64);                /* exact: 53 bits */
        se |= (uint16_t)(e - 1 + 16383);
    }
    memcpy(p, &m, 8); memcpy(p + 8, &se, 2);
}

/* ============================================================
 * CPUID stub
 * ============================================================ */

/* Feature bits the guest may see, ANDed into leaf 1 (edx/ecx) and leaf
 * 0x80000001 (edx: 3DNow!). All ones by default. Libraries that dispatch on
 * CPUID -- D3DX above all -- pick SSE/3DNow! paths on a modern host, and the
 * global-register lifter does not implement most of those instructions; a
 * host that clears the bits gets the x87 paths instead (The Movies: 16,977
 * unimplemented SIMD sites against a handful of x87 ones). */
RECOMP_WEAK uint32_t g_cpuid_edx1 = 0xFFFFFFFFu, g_cpuid_ecx1 = 0xFFFFFFFFu;
RECOMP_WEAK uint32_t g_cpuid_edx_ext = 0xFFFFFFFFu;

static inline void CPUID_impl(uint32_t eax_val, uint32_t ebx_val, uint32_t ecx_val, uint32_t edx_val) {
#ifdef _MSC_VER
    int info[4];
    __cpuidex(info, eax_val, ecx_val);
    g_eax = info[0]; g_ebx = info[1]; g_ecx = info[2]; g_edx = info[3];
    if (eax_val == 1) { g_edx &= g_cpuid_edx1; g_ecx &= g_cpuid_ecx1; }
    if (eax_val == 0x80000001u) g_edx &= g_cpuid_edx_ext;
    (void)ebx_val; (void)edx_val;
#else
    (void)eax_val; (void)ebx_val; (void)ecx_val; (void)edx_val;
#endif
}

/* CPUID_impl writes the global registers */
#define CPUID(a, b, c, d) do { RECOMP_REGS_OUT(); CPUID_impl(a, b, c, d); RECOMP_REGS_IN(); } while (0)

/* ============================================================
 * Indirect Call Dispatch
 * ============================================================ */

/* The VA of the function currently executing (see RECOMP_ENTER below); an
 * unresolved dispatch is far more useful with its caller named. */
extern uint32_t g_cur_func;

/* ICALL trace ring buffer for crash diagnostics.
 *
 * Both halves matter. A target on its own says which vtable slot ran; the
 * CALLER is what you actually need, because an indirect call is how a null
 * `this` or a null argument gets handed across a module boundary, and the
 * function that built the argument is the one to read. Recovering it by hand
 * means a --calltrace and guessing which nearby entry was still on the stack,
 * and the entry ring is no help when the answer is 33 entries back. */
/* 32 was too small the first time it mattered: a method that makes a few
 * indirect calls of its own scrolls its own entry out of the ring, so the
 * report showed it as a caller and never as a target, and the function that
 * handed it a null argument was already gone. 128 costs a kilobyte. */
#define ICALL_TRACE_SIZE 128
extern uint32_t g_icall_trace[ICALL_TRACE_SIZE];
extern uint32_t g_icall_from[ICALL_TRACE_SIZE];
extern uint32_t g_icall_trace_idx;
extern uint32_t g_icall_count;

/* Lookup functions */
recomp_func_t recomp_lookup(uint32_t va);          /* binary search in dispatch table */
recomp_func_t recomp_lookup_manual(uint32_t va);    /* manual overrides */
recomp_func_t recomp_lookup_import(uint32_t va);    /* import bridges */

/* The dummy return address pushed before a recompiled call. The callee's lifted
 * `ret` pops it. 0xDEAD0000 is a recognizable marker, but if a stack imbalance
 * ever leaks it into a value (e.g. a size argument) the high bits are destructive.
 * Projects that have hit such a leak can define RECOMP_RETADDR=0u so a leak is
 * benign while it's tracked down. */
#ifndef RECOMP_RETADDR
#define RECOMP_RETADDR 0xDEAD0000u
#endif

/* Flags cross every transfer, as on the CPU: each call and tail hands the
 * caller's flags over (RECOMP_FLAGS_OUT), every function starts from them
 * (RECOMP_ENTER), and `ret` hands the callee's back. Without the first two, a
 * function reached by a tail jump started from FK_NONE, and one whose first
 * conditional reads flags its predecessor set took an arbitrary branch: the
 * MSVC CRT's `cos` runs a load helper, then falls into `_CIcos`, a separate
 * function whose first `je` tests the helper's ZF (Bunghole in One's ball
 * never moved). */

/* Direct call to a known recompiled function */
#define RECOMP_CALL(func) do { \
    uint32_t _caller = g_cur_func; \
    PUSH32(esp, RECOMP_RETADDR); /* dummy return address */ \
    RECOMP_FLAGS_OUT(); \
    RECOMP_REGS_OUT(); \
    func(); \
    RECOMP_REGS_IN(); \
    g_cur_func = _caller;  /* the callee RECOMP_ENTER clobbered it */ \
} while(0)

/* Indirect call through dispatch */
#define RECOMP_ICALL(target_va) do { \
    uint32_t _va = (uint32_t)(target_va); \
    g_icall_trace[g_icall_trace_idx & (ICALL_TRACE_SIZE-1)] = _va; \
    g_icall_from[g_icall_trace_idx & (ICALL_TRACE_SIZE-1)] = g_cur_func; \
    g_icall_trace_idx++; \
    g_icall_count++; \
    recomp_func_t _fn = recomp_lookup_manual(_va); \
    if (!_fn) _fn = recomp_lookup(_va); \
    if (!_fn) _fn = recomp_lookup_import(_va); \
    if (_fn) { \
        uint32_t _caller = g_cur_func; \
        PUSH32(esp, RECOMP_RETADDR); \
        RECOMP_FLAGS_OUT(); \
        RECOMP_REGS_OUT(); \
        _fn(); \
        RECOMP_REGS_IN(); \
        g_cur_func = _caller;  /* the callee RECOMP_ENTER clobbered it */ \
    } else { \
        /* Nothing was pushed on this path, so there is nothing to pop: an \
         * `esp += 4` here shifted the caller's stack by one slot per miss. \
         * (Nocturne's CRT init runner lost its saved registers that way and \
         * skipped ~90 static constructors after its first unlifted entry.) */ \
        fprintf(stderr, "ICALL: unresolved VA 0x%08X from 0x%08X\n", _va, g_cur_func); \
        eax = 0; \
    } \
} while(0)

/* Indirect tail call (jmp through dispatch) */
#define RECOMP_ITAIL(target_va) do { \
    uint32_t _va = (uint32_t)(target_va); \
    g_icall_trace[g_icall_trace_idx & (ICALL_TRACE_SIZE-1)] = _va; \
    g_icall_from[g_icall_trace_idx & (ICALL_TRACE_SIZE-1)] = g_cur_func; \
    g_icall_trace_idx++; \
    g_icall_count++; \
    recomp_func_t _fn = recomp_lookup_manual(_va); \
    if (!_fn) _fn = recomp_lookup(_va); \
    if (!_fn) _fn = recomp_lookup_import(_va); \
    if (_fn) { RECOMP_FLAGS_OUT(); RECOMP_REGS_OUT(); _fn(); RECOMP_REGS_IN(); } \
    else if (_va == RECOMP_RETADDR) { /* setjmp and friends return by jumping \
        to the saved return address; that is a return, not a missing target. */ } \
    else { fprintf(stderr, "ITAIL: unresolved VA 0x%08X from 0x%08X\n", _va, g_cur_func); } \
} while(0)

/* ============================================================
 * Optional function-entry tracer (enable with -DRECOMP_TRACE).
 *
 * Each lifted function records its VA into a ring buffer on entry, so a crash
 * or unexpected exit can dump the last N functions that ran -- a poor-man's
 * backtrace when no debugger is available. Zero cost unless RECOMP_TRACE is set.
 * ============================================================ */
/* Always-on: the VA of the function currently executing. A plain global store
 * (no call), so unlike the ring tracer below it doesn't force register reloads --
 * useful for pinning a crash to a function without perturbing codegen. */
extern uint32_t g_cur_func;

#ifdef RECOMP_TRACE
#define RECOMP_ENTER_SIZE 1024
extern uint32_t g_enter_trace[RECOMP_ENTER_SIZE];
extern uint32_t g_enter_idx;
void recomp_trace_enter(uint32_t va);
#define RECOMP_ENTER(va) do { g_cur_func = (va); RECOMP_FLAGS_IN(); recomp_trace_enter(va); } while (0)
#else
#define RECOMP_ENTER(va) (g_cur_func = (va), RECOMP_FLAGS_IN())
#endif
/* Always-callable trace dump (no-op unless RECOMP_TRACE). */
void recomp_dump_trace(const char* why);

/* Stub macro for unimplemented imports */
#define STUB(name) do { \
    static int _warned = 0; \
    if (!_warned) { fprintf(stderr, "STUB: %s called\n", name); _warned = 1; } \
} while(0)

#endif /* RECOMP_TYPES_H */

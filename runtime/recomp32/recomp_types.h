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

#ifdef RECOMP_GENERATED_CODE
#define eax g_eax
#define ecx g_ecx
#define edx g_edx
#define ebx g_ebx
#define esp g_esp
#define esi g_esi
#define edi g_edi
#define ebp g_ebp
/* x87 FPU stack is global; _fpu_cmp stays per-function (set+used within one fn) */
#define _st g_st
#define _fp_top g_fp_top
#define _fpu_cw g_fpu_cw
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

#define ADDR(va)     ((uintptr_t)(uint32_t)(va) + g_mem_base)

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
    FK_CMP,     /* cmp, sub, dec  -- a - b            */
    FK_ADD,     /* add, inc       -- a + b            */
    FK_TEST,    /* and/or/xor/test -- a & b, CF=OF=0  */
    FK_BT,      /* bt             -- CF = bit b of a  */
    FK_FCOM     /* fcom           -- a is -1/0/1      */
};

enum {
    CC_E = 0, CC_NE, CC_S, CC_NS, CC_G, CC_GE, CC_L, CC_LE,
    CC_A, CC_AE, CC_B, CC_BE, CC_O, CC_NO
};

static inline int recomp_cond(uint32_t kind, uint32_t a, uint32_t b, int cc) {
    uint32_t r;
    int zf, sf, cf, of;

    if (kind == FK_FCOM) {
        int32_t v = (int32_t)a;          /* -1 less, 0 equal, 1 greater */
        switch (cc) {
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
    default:                              /* FK_CMP and FK_NONE */
        r  = a - b;
        cf = (a < b);
        of = (int)(((a ^ b) & (a ^ r)) >> 31);
        break;
    }
    zf = (r == 0);
    sf = (int)(r >> 31);

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
    }
    return 0;
}

/* ============================================================
 * Bit Manipulation
 * ============================================================ */

#define ROL32(val, n) (((uint32_t)(val) << ((n) & 31)) | ((uint32_t)(val) >> (32 - ((n) & 31))))
#define ROR32(val, n) (((uint32_t)(val) >> ((n) & 31)) | ((uint32_t)(val) << (32 - ((n) & 31))))
#define BSWAP32(val)  ( (((val) & 0xFF) << 24) | (((val) & 0xFF00) << 8) | \
                        (((val) >> 8) & 0xFF00) | (((val) >> 24) & 0xFF) )

/* ============================================================
 * FPU Stack Helpers
 * ============================================================ */

static inline void fp_push_impl(double* st, int* top, double val) {
    /* Shift stack down, push new value */
    for (int i = 7; i > 0; i--) st[i] = st[i-1];
    st[0] = val;
    (*top)++;
}

static inline double fp_pop_impl(double* st, int* top) {
    double val = st[0];
    for (int i = 0; i < 7; i++) st[i] = st[i+1];
    st[7] = 0.0;
    (*top)--;
    return val;
}

#define fp_push(val) fp_push_impl(_st, &_fp_top, (val))
#define fp_pop()     fp_pop_impl(_st, &_fp_top)

/* ============================================================
 * CPUID stub
 * ============================================================ */

static inline void CPUID(uint32_t eax_val, uint32_t ebx_val, uint32_t ecx_val, uint32_t edx_val) {
    /* Return something reasonable for a Pentium III era check */
#ifdef _MSC_VER
    int info[4];
    __cpuid(info, eax_val);
    g_eax = info[0]; g_ebx = info[1]; g_ecx = info[2]; g_edx = info[3];
#else
    (void)eax_val; (void)ebx_val; (void)ecx_val; (void)edx_val;
#endif
}

/* ============================================================
 * Indirect Call Dispatch
 * ============================================================ */

/* The VA of the function currently executing (see RECOMP_ENTER below); an
 * unresolved dispatch is far more useful with its caller named. */
extern uint32_t g_cur_func;

/* ICALL trace ring buffer for crash diagnostics */
#define ICALL_TRACE_SIZE 32
extern uint32_t g_icall_trace[ICALL_TRACE_SIZE];
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

/* Direct call to a known recompiled function */
#define RECOMP_CALL(func) do { \
    uint32_t _caller = g_cur_func; \
    PUSH32(esp, RECOMP_RETADDR); /* dummy return address */ \
    func(); \
    g_cur_func = _caller;  /* the callee RECOMP_ENTER clobbered it */ \
} while(0)

/* Indirect call through dispatch */
#define RECOMP_ICALL(target_va) do { \
    uint32_t _va = (uint32_t)(target_va); \
    g_icall_trace[g_icall_trace_idx & (ICALL_TRACE_SIZE-1)] = _va; \
    g_icall_trace_idx++; \
    g_icall_count++; \
    recomp_func_t _fn = recomp_lookup_manual(_va); \
    if (!_fn) _fn = recomp_lookup(_va); \
    if (!_fn) _fn = recomp_lookup_import(_va); \
    if (_fn) { \
        uint32_t _caller = g_cur_func; \
        PUSH32(esp, RECOMP_RETADDR); \
        _fn(); \
        g_cur_func = _caller;  /* the callee RECOMP_ENTER clobbered it */ \
    } else { \
        fprintf(stderr, "ICALL: unresolved VA 0x%08X from 0x%08X\n", _va, g_cur_func); \
        esp += 4; /* pop dummy ret addr */ \
        eax = 0; \
    } \
} while(0)

/* Indirect tail call (jmp through dispatch) */
#define RECOMP_ITAIL(target_va) do { \
    uint32_t _va = (uint32_t)(target_va); \
    g_icall_trace[g_icall_trace_idx & (ICALL_TRACE_SIZE-1)] = _va; \
    g_icall_trace_idx++; \
    g_icall_count++; \
    recomp_func_t _fn = recomp_lookup_manual(_va); \
    if (!_fn) _fn = recomp_lookup(_va); \
    if (!_fn) _fn = recomp_lookup_import(_va); \
    if (_fn) { _fn(); } \
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
#define RECOMP_ENTER(va) do { g_cur_func = (va); recomp_trace_enter(va); } while (0)
#else
#define RECOMP_ENTER(va) (g_cur_func = (va))
#endif
/* Always-callable trace dump (no-op unless RECOMP_TRACE). */
void recomp_dump_trace(const char* why);

/* Stub macro for unimplemented imports */
#define STUB(name) do { \
    static int _warned = 0; \
    if (!_warned) { fprintf(stderr, "STUB: %s called\n", name); _warned = 1; } \
} while(0)

#endif /* RECOMP_TYPES_H */

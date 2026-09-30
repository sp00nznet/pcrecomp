/* flags_selftest -- flags cross calls and tail jumps between lifted functions.
 *
 * The shape is the MSVC CRT's `cos`: a load helper sets ZF and returns, the
 * caller falls through (a tail transfer, since the next address is its own
 * catalogued entry, `_CIcos`), and that function's first `je` tests the
 * helper's ZF. Written the way lift32 emits it: FUNCTION_LOCALS, RECOMP_ENTER,
 * RECOMP_CALL + RECOMP_FLAGS_IN, `ret` as RECOMP_FLAGS_OUT.
 *
 *   cl /I. flags_selftest.c && flags_selftest
 */
#include <stdio.h>
#include <stdint.h>
#ifndef RECOMP_TLS
#define RECOMP_TLS
#endif
#define RECOMP_FLAT_MEMORY
#define RECOMP_GENERATED_CODE     /* the register names, as in lifted C */
#include "recomp_types.h"

uint32_t g_eax, g_ecx, g_edx, g_esp, g_ebx, g_esi, g_edi, g_ebp, g_cur_func;
ptrdiff_t g_mem_base;
uint32_t g_icall_trace[ICALL_TRACE_SIZE], g_icall_from[ICALL_TRACE_SIZE];
uint32_t g_icall_trace_idx, g_icall_count;
#ifdef RECOMP_TRACE
void recomp_trace_enter(uint32_t va) { (void)va; }
#endif

static int took_je;

#define LOCALS int _fpu_cmp = 0; uint32_t _cf = 0; int _df = 1; \
               uint32_t _flag_k = FK_NONE; uint32_t _flag_a = 0, _flag_b = 0; \
               uint32_t _itail_tgt = 0; (void)_fpu_cmp; (void)_df; (void)_itail_tgt;

/* 0x1000: cmp eax, 7; ret  -- ZF = (eax == 7) */
static void helper(void) {
    LOCALS RECOMP_REGS_LOCALS RECOMP_ENTER(0x1000u);
    _flag_a = eax; _flag_b = 7; _cf = CMP_B(_flag_a, _flag_b); _flag_k = FK_CMP;
    RECOMP_FLAGS_OUT(); esp += 4; RECOMP_REGS_OUT(); return;
}

/* 0x2000: _CIcos -- je on flags it did not set */
static void ci_entry(void) {
    LOCALS RECOMP_REGS_LOCALS RECOMP_ENTER(0x2000u);
    took_je = recomp_cond_cf(_flag_k, _flag_a, _flag_b, CC_E, _cf);
    RECOMP_FLAGS_OUT(); esp += 4; RECOMP_REGS_OUT(); return;
}

/* 0x3000: cos -- call helper, then fall through into 0x2000 */
static void outer(void) {
    LOCALS RECOMP_REGS_LOCALS RECOMP_ENTER(0x3000u);
    RECOMP_CALL(helper);
    RECOMP_FLAGS_IN();
    RECOMP_ITAIL(0x2000u); RECOMP_REGS_OUT(); return;
}

/* 0x4000: cmp eax, 1 with eax = 0 (ZF = 0), then call 0x2000 directly */
static void caller_nz(void) {
    LOCALS RECOMP_REGS_LOCALS RECOMP_ENTER(0x4000u);
    _flag_a = eax; _flag_b = 1; _cf = CMP_B(_flag_a, _flag_b); _flag_k = FK_CMP;
    RECOMP_CALL(ci_entry);
    RECOMP_FLAGS_IN();
    RECOMP_FLAGS_OUT(); esp += 4; RECOMP_REGS_OUT(); return;
}

recomp_func_t recomp_lookup_manual(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup(uint32_t va) { return va == 0x2000u ? ci_entry : NULL; }
recomp_func_t recomp_lookup_import(uint32_t va) { (void)va; return NULL; }

int main(void) {
    static uint32_t stack[256];
    int fails = 0;
    g_esp = (uint32_t)(uintptr_t)&stack[250];

    for (uint32_t v = 0; v < 2; v++) {        /* both ways, so a default cannot pass */
        g_eax = v ? 7 : 0;
        took_je = -1;
        PUSH32(g_esp, RECOMP_RETADDR);
        outer();
        if (took_je != (int)v) {
            printf("FAIL tail: je after the helper's cmp %u, 7 went %d\n", g_eax, took_je);
            fails++;
        }
    }

    g_eax = 0;
    took_je = -1;
    PUSH32(g_esp, RECOMP_RETADDR);
    caller_nz();
    if (took_je != 0) { printf("FAIL call: je after the caller's cmp 0, 1 went %d\n", took_je); fails++; }

    printf("flags selftest: %s\n", fails ? "FAILED" : "ok");
    return fails != 0;
}

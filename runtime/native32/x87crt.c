/*
 * x87crt: the msvcrt helpers that take their arguments on the x87 stack.
 *
 * native32's bridge copies a native callee's *stack* arguments and moves an
 * x87 result back onto the lifted FPU stack, but lifted code keeps its FPU
 * stack in g_st[], not in the CPU's registers. A helper that reads its input
 * from st(0) therefore ran natively on whatever the real FPU held. MSVC
 * compiles every float->integer cast as `call _ftol`, and the intrinsic forms
 * of pow, fmod, sqrt, sin... as `call _CIpow` and friends, so a guest that
 * links msvcrt.dll dynamically got the integer indefinite (0x80000000) from
 * every cast. A title that links the CRT statically lifts these and never
 * notices.
 *
 * So these are native32 built-ins, run inside the lifted model: operands
 * popped from g_st (st(0) the right-hand one for the binary ones, as the
 * compiler pushes `x` then `y`), the result pushed back or returned in
 * edx:eax. Semantics are the documented C ones; nothing here is derived from
 * another runtime's source.
 */
#include <math.h>
#include "recomp_types.h"

/* Included at the end of native32.c, so every host that builds native32.c
 * gets these without a change to its build. */
#define X87_POP()   fp_pop_impl(g_st, &g_fp_top)
#define X87_PUSH(v) fp_push_impl(g_st, &g_fp_top, (v))

/* _ftol: st(0) to a 64-bit integer, truncating whatever the control word
 * says (that is the C cast), popped, in edx:eax. A value fild loaded exactly
 * keeps its exact integer (g_st_i64 shadow). */
void native32_shim_ftol(void) {
    int64_t q = fp_st0_to_i64(g_st[0], g_st_i64[0], 0x0C7F);   /* RC = chop */
    (void)X87_POP();
    g_eax = (uint32_t)q;
    g_edx = (uint32_t)((uint64_t)q >> 32);
    g_esp += 4;
}

/* _controlfp(new, mask) and _control87: the FPU's precision and rounding
 * mode. Run natively they set the real control word, which native code
 * (an original module, Galaxy's built mixers) does use; but lifted fistp and
 * frndint round by g_fpu_cw. Unreal sets its mode this way at startup, and
 * its renderer's rasterisation went wrong without it. So the real call runs,
 * then the hardware word it left is copied into g_fpu_cw. cdecl: the caller
 * pops the two arguments. */
typedef unsigned int (__cdecl *controlfp_t)(unsigned int, unsigned int);

static void control_word(const char* name) {
    static controlfp_t fn[2];
    int k = name[8] == '8';                       /* _control87 */
    if (!fn[k]) fn[k] = (controlfp_t)GetProcAddress(LoadLibraryA("msvcrt.dll"), name);
    uint16_t cw;
    g_eax = fn[k](MEM32(g_esp + 4), MEM32(g_esp + 8));
    __asm fnstcw cw
    g_fpu_cw = cw;
    g_esp += 4;
}

void native32_shim_controlfp(void) { control_word("_controlfp"); }
void native32_shim_control87(void) { control_word("_control87"); }

#define UNARY(name, expr)                                                   \
    void native32_shim_##name(void) { double x = X87_POP(); X87_PUSH(expr); g_esp += 4; }
#define BINARY(name, expr)                                                    \
    void native32_shim_##name(void) {                                         \
        double y = X87_POP(), x = X87_POP(); X87_PUSH(expr); g_esp += 4; }

UNARY(CIsqrt, sqrt(x))
UNARY(CIsin, sin(x))
UNARY(CIcos, cos(x))
UNARY(CItan, tan(x))
UNARY(CIasin, asin(x))
UNARY(CIacos, acos(x))
UNARY(CIatan, atan(x))
UNARY(CIexp, exp(x))
UNARY(CIlog, log(x))
UNARY(CIlog10, log10(x))
UNARY(CIsinh, sinh(x))
UNARY(CIcosh, cosh(x))
UNARY(CItanh, tanh(x))
BINARY(CIpow, pow(x, y))
BINARY(CIfmod, fmod(x, y))
BINARY(CIatan2, atan2(x, y))

/* Visual Basic's Pentium-FDIV-safe helpers (MSVBVM60 exports, "Pentium FDIV
 * safe" is on by default in a VB native build): the same x87 operation the
 * compiler would have inlined, on the lifted stack. The m* forms take their
 * memory operand pushed by value and pop it (ret 4 / ret 8); the register
 * forms take none. fprem/fprem1 leave the whole reduction done in one step.
 * ponytail: _adj_fdiv_r (operands picked by a code in eax) is not here; add
 * it when a title calls it (it then shows as a native call on the real FPU). */
#define ADJ_M(name, T, nbytes, expr)                                          \
    void native32_shim_##name(void) {                                         \
        double m = (double)*(T*)(uintptr_t)(g_esp + 4), x = X87_POP();        \
        X87_PUSH(expr); g_esp += 4 + (nbytes); }
ADJ_M(adj_fdiv_m64, double, 8, x / m)
ADJ_M(adj_fdiv_m32, float, 4, x / m)
ADJ_M(adj_fdiv_m16i, int16_t, 4, x / m)
ADJ_M(adj_fdiv_m32i, int32_t, 4, x / m)
ADJ_M(adj_fdivr_m64, double, 8, m / x)
ADJ_M(adj_fdivr_m32, float, 4, m / x)
ADJ_M(adj_fdivr_m16i, int16_t, 4, m / x)
ADJ_M(adj_fdivr_m32i, int32_t, 4, m / x)

void native32_shim_adj_fprem(void) { g_st[0] = fmod(g_st[0], g_st[1]); g_esp += 4; }
void native32_shim_adj_fprem1(void) { g_st[0] = remainder(g_st[0], g_st[1]); g_esp += 4; }
void native32_shim_adj_fptan(void) { g_st[0] = tan(g_st[0]); X87_PUSH(1.0); g_esp += 4; }
void native32_shim_adj_fpatan(void) { double x = X87_POP(); g_st[0] = atan2(g_st[0], x); g_esp += 4; }

/* cpu_selftest.c - check the CPU helpers against known-good values.
 *
 * These are bit operations where an off-by-one in a shift width produces
 * plausible-looking output rather than a crash, so they are worth pinning to
 * values worked out by hand. Rotates in particular are easy to get subtly
 * wrong: they do NOT touch ZF/SF/PF on x86, and a helper that sets them looks
 * fine until lifted code branches on a flag the previous instruction set.
 *
 *   cl /nologo cpu_selftest.c && cpu_selftest.exe
 *   cc -o cpu_selftest cpu_selftest.c && ./cpu_selftest
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "cpu.h"

static int fails;

static void eqf(const char *what, float got, float want)
{
    /* Compare the bit patterns, not the values: -0.0 == +0.0 is true in C and
     * the whole point of the min/max checks below is telling those apart. */
    uint32_t g, w;
    memcpy(&g, &got, 4); memcpy(&w, &want, 4);
    if (g != w) {
        printf("FAIL %-28s got %g (0x%08X) want %g (0x%08X)\n", what, got, g, want, w);
        fails++;
    }
}

static void eqd(const char *what, double got, double want)
{
    uint64_t g, w;
    memcpy(&g, &got, 8); memcpy(&w, &want, 8);
    if (g != w) {
        printf("FAIL %-28s got %.17g (0x%016llX) want %.17g (0x%016llX)\n", what,
               got, (unsigned long long)g, want, (unsigned long long)w);
        fails++;
    }
}

static void eq(const char *what, uint32_t got, uint32_t want)
{
    if (got != want) {
        printf("FAIL %-28s got 0x%08X want 0x%08X\n", what, got, want);
        fails++;
    }
}

int main(void)
{
    CPU c = {0};

    /* rotates: 32-bit */
    eq("rol 0x12345678, 8", op_rol(&c, 0x12345678u, 8, 4), 0x34567812u);
    eq("ror 0x12345678, 8", op_ror(&c, 0x12345678u, 8, 4), 0x78123456u);
    eq("rol by 0 is identity", op_rol(&c, 0xDEADBEEFu, 0, 4), 0xDEADBEEFu);
    eq("rol by 32 is identity", op_rol(&c, 0xDEADBEEFu, 32, 4), 0xDEADBEEFu);

    /* rotates are width-sensitive: the same count differs per operand size */
    eq("rol 0x1234, 8 (16-bit)", op_rol(&c, 0x1234u, 8, 2), 0x3412u);
    eq("ror 0x12, 4 (8-bit)", op_ror(&c, 0x12u, 4, 1), 0x21u);

    /* a rotate must leave ZF alone - x86 does not set it here */
    c.zf = 1;
    (void)op_rol(&c, 0x00000001u, 1, 4);
    eq("rol preserves ZF", c.zf, 1);

    /* double-precision shifts */
    eq("shld F0F0F0F0 <- 0F0F0F0F, 4",
       op_shld(&c, 0xF0F0F0F0u, 0x0F0F0F0Fu, 4, 4), 0x0F0F0F00u);
    eq("shrd F0F0F0F0 <- 0F0F0F0F, 4",
       op_shrd(&c, 0xF0F0F0F0u, 0x0F0F0F0Fu, 4, 4), 0xFF0F0F0Fu);
    eq("shld by 0 is identity", op_shld(&c, 0xAAAAAAAAu, 0u, 0, 4), 0xAAAAAAAAu);

    /* segment registers exist and are 16-bit storage */
    c.ds = 0x1234; c.es = 0xFFFF; c.gs = 0x0007;
    eq("ds", c.ds, 0x1234u);
    eq("es", c.es, 0xFFFFu);
    eq("gs", c.gs, 0x0007u);

    /* ---- SSE ---- */

    /* The union really is one storage seen several ways - if it is not, every
     * movaps of a float mask silently corrupts something. */
    XMM x = {0};
    x.f32[0] = 1.0f;
    eq("xmm f32/u32 alias", x.u32[0], 0x3F800000u);

    /* A scalar load zeroes the rest of the register; a scalar reg-to-reg move
     * does not. Only the load has a helper, so only the load is checked here. */
    x.u64[0] = x.u64[1] = 0xAAAAAAAAAAAAAAAAull;
    sse_load_ss(&x, 2.0f);
    eq("movss load zeroes 32..63", x.u32[1], 0u);
    eq("movss load zeroes 64..127 lo", x.u32[2], 0u);
    eq("movss load zeroes 64..127 hi", x.u32[3], 0u);
    eqf("movss load keeps the value", x.f32[0], 2.0f);

    /* ucomiss sets the UNSIGNED flags - the compiler emits ja/jbe after a
     * float compare, never jg/jle - and an unordered compare sets all three,
     * which is what makes `ucomiss; jp` a NaN test. */
    sse_compare(&c, 2.0, 1.0);
    eq("ucomiss 2>1 zf", c.zf, 0u); eq("ucomiss 2>1 cf", c.cf, 0u);
    eq("ucomiss 2>1 pf", c.pf, 0u);
    sse_compare(&c, 1.0, 2.0);
    eq("ucomiss 1<2 cf", c.cf, 1u); eq("ucomiss 1<2 zf", c.zf, 0u);
    sse_compare(&c, 1.0, 1.0);
    eq("ucomiss 1==1 zf", c.zf, 1u); eq("ucomiss 1==1 cf", c.cf, 0u);
    c.sf = c.of = c.af = 1;
    sse_compare(&c, NAN, 1.0);
    eq("ucomiss NaN zf", c.zf, 1u);
    eq("ucomiss NaN pf", c.pf, 1u);
    eq("ucomiss NaN cf", c.cf, 1u);
    eq("ucomiss clears of", c.of, 0u);
    eq("ucomiss clears sf", c.sf, 0u);
    eq("ucomiss clears af", c.af, 0u);

    /* min/max are "if (dst OP src) dst else src", so the second operand wins
     * every tie. These four are the ones fmin/fmax get wrong.
     *
     * Through volatile, because the signed-zero pair has to be computed and
     * not folded: given two literals MSVC recognises the ternary as a min and
     * constant-folds it by a rule that does not keep the sign of a zero, so
     * the check would be measuring the compiler's front end rather than the
     * helper the lifted code actually calls. It reported +0 for both orders,
     * which no evaluation of `(d < s) ? d : s` can produce. */
    {
        volatile float pz = 0.0f, nz = -0.0f, one = 1.0f, two = 2.0f,
                       three = 3.0f, nan = (float)NAN;
        eqf("minss(1,2)", sse_minf(one, two), 1.0f);
        eqf("minss(2,1)", sse_minf(two, one), 1.0f);
        eqf("minss(+0,-0) is src", sse_minf(pz, nz), -0.0f);
        eqf("minss(-0,+0) is src", sse_minf(nz, pz), 0.0f);
        eqf("minss(NaN,3) is src", sse_minf(nan, three), 3.0f);
        eqf("minss(3,NaN) is src", sse_minf(three, nan), (float)NAN);
        eqf("maxss(1,2)", sse_maxf(one, two), 2.0f);
        eqf("maxss(NaN,3) is src", sse_maxf(nan, three), 3.0f);
    }

    /* Out of range, x86 yields the integer indefinite rather than whatever a
     * C cast would have done - which is undefined and may trap. */
    eq("cvttss2si 3.9 truncates", (uint32_t)sse_cvtt_i32(3.9), 3u);
    eq("cvttss2si -3.9 truncates", (uint32_t)sse_cvtt_i32(-3.9), (uint32_t)-3);
    eq("cvttss2si 1e18 indefinite", (uint32_t)sse_cvtt_i32(1e18), 0x80000000u);
    eq("cvttss2si NaN indefinite", (uint32_t)sse_cvtt_i32(NAN), 0x80000000u);

    /* x87 compares. Both forms of the same comparison, and the four outcomes
     * each - the unordered one above all, because it is the only case where
     * "not greater" and "less" differ, and a model that folds NaN into one of
     * the ordered answers makes a game take the wrong branch exactly when a
     * value has already gone wrong. The status-word bits are C3|C2|C0 of a
     * 0x4700 mask; the EFLAGS mapping is not the integer one. */
    fcompare(&c, 2.0, 1.0);  eq("fcom greater  -> sw", c.fpu_sw & 0x4700u, 0x0000u);
    fcompare(&c, 1.0, 2.0);  eq("fcom less     -> C0", c.fpu_sw & 0x4700u, 0x0100u);
    fcompare(&c, 1.0, 1.0);  eq("fcom equal    -> C3", c.fpu_sw & 0x4700u, 0x4000u);
    fcompare(&c, NAN, 1.0);  eq("fcom unord -> C3|C2|C0", c.fpu_sw & 0x4700u, 0x4700u);

#define FLAGS3(cc) (((cc).zf << 2) | ((cc).pf << 1) | (cc).cf)
    fcompare_eflags(&c, 2.0, 1.0); eq("fcomi greater  -> 000", FLAGS3(c), 0u);
    fcompare_eflags(&c, 1.0, 2.0); eq("fcomi less     -> CF",  FLAGS3(c), 1u);
    fcompare_eflags(&c, 1.0, 1.0); eq("fcomi equal    -> ZF",  FLAGS3(c), 4u);
    fcompare_eflags(&c, NAN, 1.0); eq("fcomi unord -> ZF|PF|CF", FLAGS3(c), 7u);
    /* and it must clear OF/SF/AF, which an integer compare would have set */
    c.of = c.sf = c.af = 1;
    fcompare_eflags(&c, 1.0, 2.0);
    eq("fcomi clears OF|SF|AF", (uint32_t)(c.of | c.sf | c.af), 0u);
#undef FLAGS3

    /* ---- x87 extended, the ten-byte format ----
     *
     * The patterns are what a real x87 stores: taken from a compiler whose
     * long double IS this format, which MSVC's is not - it makes long double
     * a double, so comparing against it here would compare nothing. Pinning
     * the bytes instead means the check works in the build that matters.
     *
     * Reading eight of the ten bytes as a double would give a number that
     * looks plausible and is not, which is the whole reason these exist. */
    {
        static const struct { double v; uint64_t m; uint16_t se; } x87[] = {
            { 1.0,                 0x8000000000000000ULL, 0x3FFF },
            { 0.5,                 0x8000000000000000ULL, 0x3FFE },
            { -3.14159265358979,   0xC90FDAA221688800ULL, 0xC000 },
            { 1e300,               0xBF21E44003ACE000ULL, 0x43E3 },
            { -1e-300,             0xAB70FE17C79AC800ULL, 0xBC1A },
            { 0.0,                 0x0000000000000000ULL, 0x0000 },
            { -0.0,                0x0000000000000000ULL, 0x8000 },
            { 2147483648.0,        0x8000000000000000ULL, 0x401E },
            { 1.0 / 3.0,           0xAAAAAAAAAAAAA800ULL, 0x3FFD },
        };
        unsigned k;
        for (k = 0; k < sizeof(x87) / sizeof(x87[0]); k++) {
            unsigned char buf[16];
            uint64_t m; uint16_t se;

            memcpy(buf,     &x87[k].m,  8);
            memcpy(buf + 8, &x87[k].se, 2);
            eqd("fld tbyte", rdf80((uint32_t)(uintptr_t)buf), x87[k].v);

            memset(buf, 0xCC, sizeof buf);
            wrf80((uint32_t)(uintptr_t)buf, x87[k].v);
            memcpy(&m,  buf,     8);
            memcpy(&se, buf + 8, 2);
            eq("fstp tbyte mantissa hi", (uint32_t)(m >> 32), (uint32_t)(x87[k].m >> 32));
            eq("fstp tbyte mantissa lo", (uint32_t)m,         (uint32_t)x87[k].m);
            eq("fstp tbyte sign+exp",    se,                  x87[k].se);
        }
    }

    if (fails == 0)
        printf("cpu_selftest: all checks passed\n");
    return fails != 0;
}

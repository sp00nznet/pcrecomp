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
#include "cpu.h"

static int fails;

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

    if (fails == 0)
        printf("cpu_selftest: all checks passed\n");
    return fails != 0;
}

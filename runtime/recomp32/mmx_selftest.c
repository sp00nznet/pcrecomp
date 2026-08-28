/* mmx_selftest -- the MMX helpers in recomp_types.h against hand-worked values.
 *
 * Every case here is one the Intel manual answers directly. The interleaves and
 * the saturating adds are the ones worth pinning: an off-by-one in an element
 * index or a wrong saturation bound produces plausible-looking pixels rather
 * than a crash, and a rasterizer full of them just looks slightly wrong.
 *
 *   cl /I. mmx_selftest.c && mmx_selftest
 */
#include <stdio.h>
#include <stdint.h>
#ifndef RECOMP_TLS
#define RECOMP_TLS
#endif
#include "recomp_types.h"

static int fails;
static void chk(const char* name, uint64_t got, uint64_t want) {
    if (got != want) {
        printf("FAIL %-12s got %016llX want %016llX\n", name,
               (unsigned long long)got, (unsigned long long)want);
        fails++;
    }
}

int main(void) {
    const uint64_t A = 0x4444333322221111ULL;   /* words a3..a0 */
    const uint64_t B = 0x8888777766665555ULL;

    /* Interleave: a's element first, then b's. */
    chk("punpcklwd", mmx_punpcklwd(A, B), 0x6666222255551111ULL);
    chk("punpckhwd", mmx_punpckhwd(A, B), 0x8888444477773333ULL);
    chk("punpckldq", mmx_punpckldq(A, B), 0x6666555522221111ULL);
    chk("punpckhdq", mmx_punpckhdq(A, B), 0x8888777744443333ULL);
    chk("punpcklbw", mmx_punpcklbw(0x0000000004030201ULL, 0x0000000008070605ULL),
        0x0804070306020501ULL);  /* interleaved a0,b0,a1,b1,... */

    /* 0x4000 * 0x4000 = 0x1000'0000; the high half is 0x1000. */
    chk("pmulhw", mmx_pmulhw(0x4000400040004000ULL, 0x4000400040004000ULL),
        0x1000100010001000ULL);
    chk("pmullw", mmx_pmullw(0x0003000300030003ULL, 0x0005000500050005ULL),
        0x000F000F000F000FULL);

    /* words (4,3,2,1) . (8,7,6,5) -> dwords (3*7+4*8, 1*5+2*6) = (53, 17) */
    chk("pmaddwd", mmx_pmaddwd(0x0004000300020001ULL, 0x0008000700060005ULL),
        0x0000003500000011ULL);

    /* 0x7000 + 0x7000 saturates to 0x7FFF; -0x7000 + -0x7000 to 0x8000. */
    chk("paddsw+", mmx_paddsw(0x7000700070007000ULL, 0x7000700070007000ULL),
        0x7FFF7FFF7FFF7FFFULL);
    chk("paddsw-", mmx_paddsw(0x9000900090009000ULL, 0x9000900090009000ULL),
        0x8000800080008000ULL);
    chk("psubsw", mmx_psubsw(0x0005000500050005ULL, 0x0003000300030003ULL),
        0x0002000200020002ULL);
    chk("paddw", mmx_paddw(0x0001000200030004ULL, 0x0010002000300040ULL),
        0x0011002200330044ULL);
    chk("psubw", mmx_psubw(0x0011002200330044ULL, 0x0001000200030004ULL),
        0x0010002000300040ULL);
    chk("paddd", mmx_paddd(0x0000000100000002ULL, 0x0000001000000020ULL),
        0x0000001100000022ULL);
    chk("psubd", mmx_psubd(0x0000001100000022ULL, 0x0000000100000002ULL),
        0x0000001000000020ULL);

    /* Shifts are per-element, and a count wider than the element clears it. */
    chk("psllq", mmx_psllq(0x0000000000000001ULL, 8), 0x0000000000000100ULL);
    chk("psrlq", mmx_psrlq(0x0000000000000100ULL, 8), 0x0000000000000001ULL);
    chk("psrlq>63", mmx_psrlq(0xFFFFFFFFFFFFFFFFULL, 64), 0ULL);
    chk("psllw", mmx_psllw(0x0001000100010001ULL, 4), 0x0010001000100010ULL);
    chk("psrlw", mmx_psrlw(0x0010001000100010ULL, 4), 0x0001000100010001ULL);
    chk("psraw", mmx_psraw(0x8000800080008000ULL, 4), 0xF800F800F800F800ULL);
    chk("pslld", mmx_pslld(0x0000000100000001ULL, 4), 0x0000001000000010ULL);
    chk("psrld", mmx_psrld(0x0000001000000010ULL, 4), 0x0000000100000001ULL);
    chk("psrad", mmx_psrad(0x8000000080000000ULL, 4), 0xF8000000F8000000ULL);

    /* Pack: a's elements low, saturating. */
    chk("packssdw", mmx_packssdw(0x0000FFFF00000001ULL, 0x000000020000FFFFULL),
        0x00027FFF7FFF0001ULL);
    chk("packuswb", mmx_packuswb(0x00FF000100FF0001ULL, 0x0002000200020002ULL),
        0x02020202FF01FF01ULL);
    chk("pcmpeqw", mmx_pcmpeqw(0x0001000200030004ULL, 0x0001999900030004ULL),
        0xFFFF0000FFFFFFFFULL);
    chk("pcmpgtw", mmx_pcmpgtw(0x0005000500050005ULL, 0x0004000600040006ULL),
        0xFFFF0000FFFF0000ULL);

    printf(fails ? "%d FAILURE(S)\n" : "all MMX helpers agree (%d failures)\n", fails);
    return fails != 0;
}

/* lz32_selftest.c - SZDD expansion: literals, a back-reference to what was
 * just written, one into the window's starting spaces, and a file that is
 * not SZDD left alone. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "win32hle.h"

uint8_t *hle_szdd_expand(const uint8_t *in, uint32_t n, uint32_t *out_n);

static void none(void) { }
const recomp_dispatch_entry_t recomp_dispatch_table[] = { { 0x1000u, none } };   /* no guest: the decoder is host code */
const uint32_t recomp_dispatch_count = 1;

int main(void) {
    /* flags 0x17 = items L L L R L R: "ABC", then (offset 4080, where 'A' went,
     * length 3) "ABC", 'x', then (offset 0, length 4) four of the spaces. */
    const uint8_t szdd[] = { 'S', 'Z', 'D', 'D', 0x88, 0xF0, 0x27, 0x33, 'A', 0, 11, 0, 0, 0,
                             0x17, 'A', 'B', 'C', 0xF0, 0xF0, 'x', 0x00, 0x01 };
    uint32_t n = 0;
    uint8_t *out = hle_szdd_expand(szdd, sizeof szdd, &n);
    int ok = out && n == 11 && !memcmp(out, "ABCABCx    ", 11);
    printf("SZDD expand: %s (%u bytes: \"%.*s\")\n", ok ? "ok" : "FAILED", n, (int)n, out ? (char *)out : "");
    const uint8_t plain[] = "not compressed";
    ok &= hle_szdd_expand(plain, sizeof plain, &n) == NULL;
    free(out);
    printf("lz32_selftest: %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

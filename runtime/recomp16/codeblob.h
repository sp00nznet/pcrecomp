/*
 * codeblob.h - real-mode code that exists only at run time, lifted ahead of time.
 *
 * Some DOS programs unpack code into their heap and far-call it: Origin's
 * compressed .DRV sound and timer drivers (Wing Commander), DIGPAK-style
 * drivers, anything decompressed at boot. None of it is in the executable, so
 * the static lift cannot see it. This closes the loop the same way dispatch
 * misses do:
 *
 *   1. run:  a call or jump into code that is not the executable's (its bytes
 *            differ from the load image, or lie outside it) is a miss; the
 *            host calls codeblob_capture(), which writes the 64 KB from
 *            seg:0000 to work/<game>/blobs/SSSS.bin and logs the miss as usual.
 *   2. lift: pcrecomp tools/lift/codeblob16.py gives each capture a virtual
 *            code segment (paragraph 0x10000 + 0x1000*k, above anything real),
 *            lifts its entries there, and emits g_blobs[]: per entry its
 *            offset, the first CODEBLOB_SIG bytes, and a slot. Each blob's
 *            SEG_<virt> constant becomes g_blob_seg[slot], so cs: operands and
 *            pushed return segments are the live segment, not the virtual one.
 *   3. run:  codeblob_lookup() turns a live seg:off into the lifted key. A
 *            segment already bound to a slot maps directly; otherwise an entry
 *            whose signature matches the bytes at seg:off binds it.
 *
 * ponytail: one live copy per blob (one segment per slot); a program that
 * keeps two copies of the same driver loaded at once needs per-call slots.
 */
#ifndef RECOMP16_CODEBLOB_H
#define RECOMP16_CODEBLOB_H
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CODEBLOB_SIG 24

typedef struct {
    uint32_t virt;            /* the lifted key of seg:0000: virtual paragraph * 16 */
    uint16_t off;             /* an entry the capture runs saw called */
    uint16_t slot;
    uint8_t  sig[CODEBLOB_SIG];
} CodeBlobEntry;

extern const CodeBlobEntry g_blobs[];
extern const unsigned g_blob_count;
extern uint16_t g_blob_seg[];      /* live segment of each slot, 0 = not seen yet */
extern const uint32_t g_blob_virt[]; /* virtual base of each slot */
extern const unsigned g_blob_slots;

/* The lifted key for live seg:off inside a known blob, or -1. */
static inline int64_t codeblob_lookup(const uint8_t *mem, uint16_t seg, uint16_t off)
{
    for (unsigned s = 0; s < g_blob_slots; s++)
        if (g_blob_seg[s] == seg) return (int64_t)g_blob_virt[s] + off;
    const uint8_t *p = &mem[(((uint32_t)seg << 4) + off) & 0xFFFFF];
    for (unsigned i = 0; i < g_blob_count; i++)
        if (g_blobs[i].off == off && !memcmp(p, g_blobs[i].sig, CODEBLOB_SIG)) {
            g_blob_seg[g_blobs[i].slot] = seg;
            return (int64_t)g_blobs[i].virt + off;
        }
    return -1;
}

/* Dump seg:0000..FFFF to <dir>/SSSS.bin, unless an earlier run already did. */
static inline void codeblob_capture(const uint8_t *mem, uint16_t seg, const char *dir)
{
    static uint16_t done[64]; static unsigned ndone;
    for (unsigned i = 0; i < ndone; i++) if (done[i] == seg) return;
    if (ndone < 64) done[ndone++] = seg;
    char p[512]; snprintf(p, sizeof p, "%s/%04X.bin", dir, seg);
    FILE *f = fopen(p, "rb");
    if (f) { fclose(f); return; }          /* the first capture is the pristine one */
    f = fopen(p, "wb");
    if (!f) return;
    uint32_t base = (uint32_t)seg << 4, n = base + 0x10000 > 0xA0000 ? 0xA0000 - base : 0x10000;
    fwrite(mem + base, 1, n, f);
    fclose(f);
    fprintf(stderr, "[blob] captured %04X:0000 (%u bytes) -> %s\n", seg, (unsigned)n, p);
}

#endif

/*
 * lz32.c - win32hle LZ32: files compressed by COMPRESS.EXE, read as their
 * expansion.
 *
 * An installer-era program opens its data through LZOpenFileA so that a file
 * shipped compressed (an SZDD header) reads as the original. Here the whole
 * file is read at open and, if it is SZDD, expanded into memory; a file that
 * is not compressed is the same buffer, unexpanded. Reads, seeks and close
 * work on that buffer.
 *
 * SZDD is LZSS: a 4096-byte window that starts full of spaces with its write
 * position 16 short of the end, and a flag byte before every eight items - a
 * set bit is a literal byte, a clear one a 12-bit window offset and a 4-bit
 * length less 3. lz32_selftest.c checks the decoder.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "win32hle.h"

#define LZ_BIAS     0x400u                   /* LZ handles are 1024 up, as LZ32's are */
#define LZ_MAX      64
#define LZERROR_BADINHANDLE 0xFFFFFFFFu      /* -1 */
#define LZERROR_BADOUTHANDLE 0xFFFFFFFEu     /* -2: what a failed open answers */
#define LZERROR_READ        0xFFFFFFFDu      /* -3 */
#define LZERROR_BADVALUE    0xFFFFFFF9u      /* -7 */

static struct { uint8_t *data; uint32_t size, pos; int used; } g_lz[LZ_MAX];

/* SZDD's expansion of in[0..n), or NULL if it is not SZDD; *out_n its size. */
uint8_t *hle_szdd_expand(const uint8_t *in, uint32_t n, uint32_t *out_n) {
    static const uint8_t magic[8] = { 'S', 'Z', 'D', 'D', 0x88, 0xF0, 0x27, 0x33 };
    if (n < 14 || memcmp(in, magic, 8) || in[8] != 'A') return NULL;
    uint32_t size = in[10] | in[11] << 8 | in[12] << 16 | (uint32_t)in[13] << 24;
    uint8_t *out = (uint8_t *)malloc(size ? size : 1), win[4096];
    if (!out) return NULL;
    memset(win, ' ', sizeof win);
    uint32_t at = 14, o = 0, pos = 4096 - 16;
    while (at < n && o < size) {
        uint8_t flags = in[at++];
        for (int bit = 0; bit < 8 && at < n && o < size; bit++) {
            if (flags & (1u << bit)) {
                out[o++] = win[pos++ & 4095] = in[at++];
            } else {
                if (at + 1 >= n) { at = n; break; }
                uint32_t off = in[at] | (in[at + 1] & 0xF0u) << 4, len = (in[at + 1] & 0x0Fu) + 3;
                at += 2;
                for (uint32_t k = 0; k < len && o < size; k++) out[o++] = win[pos++ & 4095] = win[(off + k) & 4095];
            }
        }
    }
    *out_n = o;
    return out;
}

static int slot_of(uint32_t h) {
    uint32_t i = h - LZ_BIAS;
    return h >= LZ_BIAS && i < LZ_MAX && g_lz[i].used ? (int)i : -1;
}

/* LZOpenFileA(name, &OFSTRUCT, style): OpenFile's arguments; read whole. */
static void z_LZOpenFileA(void) {
    char path[1024];
    const char *name = ASTR(0);
    uint8_t *of = (uint8_t *)APTR(1);
    if (of) { memset(of, 0, 136); of[0] = 136, of[1] = 1; snprintf((char *)of + 8, 128, "%s", name ? name : ""); }
    if (!name || !hle_host_path(name, path, sizeof path)) RET(LZERROR_BADOUTHANDLE, 3);
    FILE *f = fopen(path, "rb");
    if (!f) RET(LZERROR_BADOUTHANDLE, 3);
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *raw = (uint8_t *)malloc(n > 0 ? (size_t)n : 1);
    uint32_t size = raw && n > 0 ? (uint32_t)fread(raw, 1, (size_t)n, f) : 0;
    fclose(f);
    int i = 0;
    while (i < LZ_MAX && g_lz[i].used) i++;
    if (!raw || i == LZ_MAX) { free(raw); RET(LZERROR_BADINHANDLE, 3); }
    uint32_t xn = 0;
    uint8_t *x = hle_szdd_expand(raw, size, &xn);
    if (x) free(raw), raw = x, size = xn;
    g_lz[i].data = raw, g_lz[i].size = size, g_lz[i].pos = 0, g_lz[i].used = 1;
    if (hle_filetrace()) fprintf(stderr, "[file] LZOpenFileA \"%s\" -> %u bytes%s\n", name, size, x ? " (SZDD)" : "");
    RET(LZ_BIAS + (uint32_t)i, 3);
}

static void z_LZRead(void) {                     /* (h, buf, count) */
    int i = slot_of(A32(0));
    if (i < 0) RET(LZERROR_BADINHANDLE, 3);
    uint32_t n = A32(2), left = g_lz[i].size - g_lz[i].pos;
    if (n > left) n = left;
    if (n && !APTR(1)) RET(LZERROR_READ, 3);
    if (n) memcpy(APTR(1), g_lz[i].data + g_lz[i].pos, n);
    g_lz[i].pos += n;
    RET(n, 3);
}

static void z_LZSeek(void) {                     /* (h, offset, origin) */
    int i = slot_of(A32(0));
    if (i < 0) RET(LZERROR_BADINHANDLE, 3);
    int64_t base = A32(2) == 1 ? g_lz[i].pos : A32(2) == 2 ? g_lz[i].size : 0, p = base + (int32_t)A32(1);
    if (p < 0 || p > g_lz[i].size) RET(LZERROR_BADVALUE, 3);
    g_lz[i].pos = (uint32_t)p;
    RET((uint32_t)p, 3);
}

static void z_LZClose(void) {
    int i = slot_of(A32(0));
    if (i >= 0) free(g_lz[i].data), memset(&g_lz[i], 0, sizeof g_lz[i]);
    RETV(1);
}

const win32hle_shim win32hle_lz32[] = {
    { "LZOpenFileA", z_LZOpenFileA }, { "LZRead", z_LZRead },
    { "LZSeek", z_LZSeek }, { "LZClose", z_LZClose },
    { 0, 0 }
};

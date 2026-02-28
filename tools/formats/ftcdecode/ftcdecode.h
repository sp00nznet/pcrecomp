/*
 * ftcdecode.h - Clean-room FTC (Fractal Transform Codec) decoder
 *
 * Decodes FTC images (magic "FTC\0") used by Encarta 97.
 * Based on the FVF/IFS fractal codec documented by Kostya Shishkov
 * and Alyssa Milburn, with header format reverse-engineered from
 * DECO_32.DLL binary analysis.
 *
 * Color space: GBR 4:2:0 (full-res green/luma, half-res blue/red)
 * Block size: 4x4 pixels
 * Affine transform: output = pixel * 3/4 + bias
 */

#ifndef FTCDECODE_H
#define FTCDECODE_H

#include <stdint.h>
#include <stdbool.h>

/* ------------------------------------------------------------------ */
/* FTC file header structures                                          */
/* ------------------------------------------------------------------ */

#pragma pack(push, 1)

/* Primary header: 28 bytes at offset 0 */
typedef struct {
    char     magic[4];          /* "FTC\0" */
    uint8_t  version_a;         /* 1 */
    uint8_t  version_b;         /* 1 */
    uint16_t format;            /* 0x0102 = YUV mode */
    uint16_t width;             /* image width */
    uint16_t height;            /* image height */
    uint16_t bpp;               /* bits per pixel (24) */
    uint16_t planes;            /* 1 */
    uint16_t hdr_size;          /* total header size (67 = 28 + 39) */
    uint16_t reserved;          /* 0 */
    uint32_t data_size;         /* compressed data size */
    uint32_t reserved2;         /* 0 */
} FTCHeader;

/* Sub-header: 39 bytes at offset 28 */
typedef struct {
    uint8_t  sub_ver_a;         /* 1 */
    uint8_t  sub_ver_b;         /* 1 */
    uint16_t sub_field;         /* 16 */
    uint32_t zero;              /* 0 */
    uint16_t width2;            /* same as primary width */
    uint16_t height2;           /* same as primary height */
    uint32_t zero2;             /* 0 */
    uint16_t block_w;           /* block width (4) */
    uint16_t block_h;           /* block height (4) */
    uint16_t chroma_subsample;  /* chroma subsampling factor (2) */
    uint8_t  channels;          /* number of channels (3) */
    uint8_t  iterations;        /* fractal iteration count (7) */
    uint8_t  remaining[15];     /* remaining fields */
} FTCSubHeader;

#pragma pack(pop)

/* ------------------------------------------------------------------ */
/* BMP output structures                                               */
/* ------------------------------------------------------------------ */

#pragma pack(push, 1)
typedef struct {
    uint16_t bfType;
    uint32_t bfSize;
    uint16_t bfReserved1;
    uint16_t bfReserved2;
    uint32_t bfOffBits;
} BMPFileHeader;

typedef struct {
    uint32_t biSize;
    int32_t  biWidth;
    int32_t  biHeight;
    uint16_t biPlanes;
    uint16_t biBitCount;
    uint32_t biCompression;
    uint32_t biSizeImage;
    int32_t  biXPelsPerMeter;
    int32_t  biYPelsPerMeter;
    uint32_t biClrUsed;
    uint32_t biClrImportant;
} BMPInfoHeader;
#pragma pack(pop)

/* ------------------------------------------------------------------ */
/* Bitstream reader (LSB-first)                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    const uint8_t *data;
    size_t         size;
    size_t         byte_pos;
    int            bit_pos;     /* bits consumed in current byte (0-7) */
} BitReader;

static inline void br_init(BitReader *br, const uint8_t *data, size_t size)
{
    br->data = data;
    br->size = size;
    br->byte_pos = 0;
    br->bit_pos = 0;
}

/* Read N bits LSB-first (N <= 24) */
static inline uint32_t br_read(BitReader *br, int n)
{
    uint32_t val = 0;
    int shift = 0;

    while (n > 0) {
        if (br->byte_pos >= br->size)
            return val; /* EOF — return partial */

        int avail = 8 - br->bit_pos;
        int take = (n < avail) ? n : avail;
        uint32_t bits = (br->data[br->byte_pos] >> br->bit_pos) & ((1u << take) - 1);
        val |= bits << shift;

        shift += take;
        n -= take;
        br->bit_pos += take;
        if (br->bit_pos >= 8) {
            br->bit_pos = 0;
            br->byte_pos++;
        }
    }

    return val;
}

/* Align to next byte boundary */
static inline void br_align(BitReader *br)
{
    if (br->bit_pos > 0) {
        br->bit_pos = 0;
        br->byte_pos++;
    }
}

/* Check if we have at least N bits remaining */
static inline bool br_has_bits(const BitReader *br, int n)
{
    size_t total_bits = (br->size - br->byte_pos) * 8 - br->bit_pos;
    return (size_t)n <= total_bits;
}

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define FTC_BLOCK_W     4
#define FTC_BLOCK_H     4
#define FTC_SOURCE_W    8   /* source block for downsampling */
#define FTC_SOURCE_H    8

/* Opcodes (3-bit LSB) */
#define OP_AFFINE_0     0   /* Affine with symmetry mode 0 */
#define OP_AFFINE_1     1   /* Affine with symmetry mode 1 */
#define OP_AFFINE_2     2   /* Affine with symmetry mode 2 */
#define OP_AFFINE_3     3   /* Affine with symmetry mode 3 */
#define OP_SKIP         4   /* Skip 1-32 blocks */
#define OP_INTERFRAME   5   /* Inter-frame (treat as skip for stills) */
#define OP_RAW          6   /* Raw 4x4 block */
#define OP_EXTENDED     7   /* Extended operation (read 4 more bits) */

#endif /* FTCDECODE_H */

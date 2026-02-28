/*
 * ftcdecode - Clean-room FTC fractal image decoder
 *
 * Decodes FTC (Fractal Transform Codec) images used by Encarta 97.
 * This is a clean-room implementation that does not depend on DECO_32.DLL.
 *
 * Algorithm: IFS (Iterated Function System) fractal decoding
 *   - 3-bit LSB opcodes per 4x4 block
 *   - Affine transform: output = pixel * 3/4 + bias (iterated N times)
 *   - GBR 4:2:0 color space (full-res green, half-res blue/red)
 *
 * Usage:
 *   ftcdecode <input.ftc> <output.bmp>    Decode FTC to BMP
 *   ftcdecode -i <input.ftc>              Show header info
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "ftcdecode.h"

/* ------------------------------------------------------------------ */
/* Affine transform lookup table                                       */
/* ------------------------------------------------------------------ */

/*
 * Pre-computed: scale_table[bias_index][pixel] = clamp(pixel * 3/4 + bias)
 * bias_index = bias + 64, where bias is in [-64, 63] (7-bit signed)
 * This avoids per-pixel multiply during iteration.
 */
static uint8_t scale_table[128][256];

static void init_scale_table(void)
{
    for (int b = 0; b < 128; b++) {
        int bias = b - 64;
        for (int p = 0; p < 256; p++) {
            int val = (p * 3 + 2) / 4 + bias; /* round-to-nearest */
            if (val < 0)   val = 0;
            if (val > 255) val = 255;
            scale_table[b][p] = (uint8_t)val;
        }
    }
}

/* ------------------------------------------------------------------ */
/* File I/O helpers                                                    */
/* ------------------------------------------------------------------ */

static uint8_t *read_file(const char *path, long *out_size)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *data = (uint8_t *)malloc(size);
    if (!data) { fclose(f); return NULL; }

    fread(data, 1, size, f);
    fclose(f);

    *out_size = size;
    return data;
}

/* ------------------------------------------------------------------ */
/* BMP writer                                                          */
/* ------------------------------------------------------------------ */

static bool write_bmp(const char *path, int width, int height,
                      const uint8_t *bgr_pixels)
{
    int row_bytes = ((width * 3 + 3) / 4) * 4; /* 4-byte aligned */
    int image_size = row_bytes * height;

    BMPFileHeader fh;
    BMPInfoHeader ih;

    memset(&fh, 0, sizeof(fh));
    memset(&ih, 0, sizeof(ih));

    fh.bfType = 0x4D42; /* 'BM' */
    fh.bfOffBits = sizeof(BMPFileHeader) + sizeof(BMPInfoHeader);
    fh.bfSize = fh.bfOffBits + image_size;

    ih.biSize = sizeof(BMPInfoHeader);
    ih.biWidth = width;
    ih.biHeight = height; /* positive = bottom-up */
    ih.biPlanes = 1;
    ih.biBitCount = 24;
    ih.biCompression = 0;
    ih.biSizeImage = image_size;
    ih.biXPelsPerMeter = 2835;
    ih.biYPelsPerMeter = 2835;

    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "Error: cannot create '%s'\n", path);
        return false;
    }

    fwrite(&fh, 1, sizeof(fh), f);
    fwrite(&ih, 1, sizeof(ih), f);

    /* Write rows bottom-up (BMP convention) */
    for (int y = height - 1; y >= 0; y--) {
        const uint8_t *row = bgr_pixels + y * width * 3;
        fwrite(row, 1, width * 3, f);
        int pad = row_bytes - width * 3;
        if (pad > 0) {
            uint8_t zeros[4] = {0};
            fwrite(zeros, 1, pad, f);
        }
    }

    fclose(f);
    return true;
}

/* ------------------------------------------------------------------ */
/* Header parsing                                                      */
/* ------------------------------------------------------------------ */

static bool parse_header(const uint8_t *data, long file_size,
                         FTCHeader *hdr, FTCSubHeader *sub)
{
    if (file_size < (long)sizeof(FTCHeader)) {
        fprintf(stderr, "Error: file too small for FTC header\n");
        return false;
    }

    memcpy(hdr, data, sizeof(FTCHeader));

    if (memcmp(hdr->magic, "FTC", 3) != 0 || hdr->magic[3] != '\0') {
        fprintf(stderr, "Error: not an FTC file (magic: %02X %02X %02X %02X)\n",
                (uint8_t)hdr->magic[0], (uint8_t)hdr->magic[1],
                (uint8_t)hdr->magic[2], (uint8_t)hdr->magic[3]);
        return false;
    }

    if (hdr->hdr_size > (uint16_t)file_size) {
        fprintf(stderr, "Error: header size %u exceeds file size %ld\n",
                hdr->hdr_size, file_size);
        return false;
    }

    /* Parse sub-header if present */
    if (hdr->hdr_size >= sizeof(FTCHeader) + sizeof(FTCSubHeader)) {
        memcpy(sub, data + sizeof(FTCHeader), sizeof(FTCSubHeader));
    } else {
        /* Defaults for files without sub-header */
        memset(sub, 0, sizeof(FTCSubHeader));
        sub->block_w = FTC_BLOCK_W;
        sub->block_h = FTC_BLOCK_H;
        sub->chroma_subsample = 2;
        sub->channels = 3;
        sub->iterations = 7;
    }

    return true;
}

static void print_header_info(const FTCHeader *hdr, const FTCSubHeader *sub)
{
    printf("FTC Header:\n");
    printf("  Magic:           %.3s\\0\n", hdr->magic);
    printf("  Version:         %u.%u\n", hdr->version_a, hdr->version_b);
    printf("  Format:          0x%04X\n", hdr->format);
    printf("  Width:           %u\n", hdr->width);
    printf("  Height:          %u\n", hdr->height);
    printf("  BPP:             %u\n", hdr->bpp);
    printf("  Planes:          %u\n", hdr->planes);
    printf("  Header size:     %u\n", hdr->hdr_size);
    printf("  Data size:       %u\n", hdr->data_size);
    printf("\n");
    printf("Sub-Header:\n");
    printf("  Sub version:     %u.%u\n", sub->sub_ver_a, sub->sub_ver_b);
    printf("  Sub field:       %u\n", sub->sub_field);
    printf("  Width2:          %u\n", sub->width2);
    printf("  Height2:         %u\n", sub->height2);
    printf("  Block size:      %ux%u\n", sub->block_w, sub->block_h);
    printf("  Chroma subsamp:  %u\n", sub->chroma_subsample);
    printf("  Channels:        %u\n", sub->channels);
    printf("  Iterations:      %u\n", sub->iterations);

    /* Derived info */
    int bw = (hdr->width + sub->block_w - 1) / sub->block_w;
    int bh = (hdr->height + sub->block_h - 1) / sub->block_h;
    printf("\nDerived:\n");
    printf("  Luma blocks:     %d x %d = %d\n", bw, bh, bw * bh);
    if (sub->chroma_subsample > 0) {
        int cw = (hdr->width / sub->chroma_subsample + sub->block_w - 1) / sub->block_w;
        int ch = (hdr->height / sub->chroma_subsample + sub->block_h - 1) / sub->block_h;
        printf("  Chroma blocks:   %d x %d = %d (per plane)\n", cw, ch, cw * ch);
    }
}

/* ------------------------------------------------------------------ */
/* Plane decoder                                                       */
/* ------------------------------------------------------------------ */

/*
 * Apply symmetry transform to indices when copying from source to dest.
 * mode bits: bit 0 = mirror horizontal, bit 1 = flip vertical
 */
static inline void get_src_coords(int mode, int dx, int dy,
                                  int *sx, int *sy)
{
    /* dx, dy are in [0..3] for a 4x4 destination block.
     * Source is 8x8, sampled at stride 2, so base source coords are dx*2, dy*2.
     */
    int x = dx;
    int y = dy;

    if (mode & 1) x = 3 - x; /* mirror horizontal */
    if (mode & 2) y = 3 - y; /* flip vertical */

    *sx = x * 2;
    *sy = y * 2;
}

/*
 * Decode one plane (luma or chroma).
 * plane_w, plane_h: pixel dimensions of this plane
 * front/back: ping-pong buffers, each plane_w * plane_h
 * br: bitstream reader (advanced in-place)
 * iterations: number of fractal iterations
 *
 * Returns true on success.
 */
static bool decode_plane(int plane_w, int plane_h,
                         uint8_t *front, uint8_t *back,
                         BitReader *br, int iterations,
                         int block_w, int block_h)
{
    int blocks_x = (plane_w + block_w - 1) / block_w;
    int blocks_y = (plane_h + block_h - 1) / block_h;
    int total_blocks = blocks_x * blocks_y;

    /*
     * We need to record the operations from the bitstream on the first pass,
     * then replay them for each subsequent iteration.
     */
    typedef struct {
        uint8_t opcode;         /* 0-7 */
        uint8_t sym_mode;       /* symmetry mode for affine ops (0-3) */
        uint8_t bias_index;     /* 0-127 for affine ops */
        uint16_t src_block;     /* source block index for affine ops */
        uint8_t raw_pixels[16]; /* for raw blocks */
        uint8_t skip_count;     /* for skip ops */
    } BlockOp;

    BlockOp *ops = (BlockOp *)calloc(total_blocks, sizeof(BlockOp));
    if (!ops) {
        fprintf(stderr, "Error: cannot allocate block operations\n");
        return false;
    }

    /* Initialize buffers to 0x80 (mid-gray) */
    memset(front, 0x80, plane_w * plane_h);
    memset(back, 0x80, plane_w * plane_h);

    /* ---- Pass 1: Parse bitstream and record operations ---- */
    int block_idx = 0;
    while (block_idx < total_blocks) {
        if (!br_has_bits(br, 3)) break;

        uint32_t opcode = br_read(br, 3);

        if (opcode <= OP_AFFINE_3) {
            /* Affine transform: 3-bit opcode encodes symmetry mode */
            if (!br_has_bits(br, 7 + 14)) break;
            ops[block_idx].opcode = (uint8_t)opcode;
            ops[block_idx].sym_mode = (uint8_t)opcode; /* mode IS the opcode */
            ops[block_idx].bias_index = (uint8_t)br_read(br, 7);
            ops[block_idx].src_block = (uint16_t)br_read(br, 14);
            block_idx++;

        } else if (opcode == OP_SKIP) {
            /* Skip: read 5-bit count (0-31 means skip 1-32 blocks) */
            if (!br_has_bits(br, 5)) break;
            uint32_t count = br_read(br, 5) + 1;
            for (uint32_t i = 0; i < count && block_idx < total_blocks; i++) {
                ops[block_idx].opcode = OP_SKIP;
                ops[block_idx].skip_count = 1;
                block_idx++;
            }

        } else if (opcode == OP_INTERFRAME) {
            /* Inter-frame: treat as skip for still images */
            ops[block_idx].opcode = OP_SKIP;
            ops[block_idx].skip_count = 1;
            block_idx++;

        } else if (opcode == OP_RAW) {
            /* Raw block: align to byte boundary, read 16 literal pixels */
            br_align(br);
            if (!br_has_bits(br, 16 * 8)) break;
            ops[block_idx].opcode = OP_RAW;
            for (int i = 0; i < 16; i++) {
                ops[block_idx].raw_pixels[i] = (uint8_t)br_read(br, 8);
            }
            block_idx++;

        } else if (opcode == OP_EXTENDED) {
            /* Extended: read 4 more bits for sub-opcode */
            if (!br_has_bits(br, 4)) break;
            uint32_t ext_op = br_read(br, 4);

            if (ext_op == 0) {
                /* Extended affine on 8x8 superblock (4 sub-blocks) */
                /* For now, treat as 4 individual affine ops */
                for (int sub = 0; sub < 4 && block_idx < total_blocks; sub++) {
                    if (!br_has_bits(br, 7 + 14)) { block_idx = total_blocks; break; }
                    ops[block_idx].opcode = OP_AFFINE_0;
                    ops[block_idx].sym_mode = 0;
                    ops[block_idx].bias_index = (uint8_t)br_read(br, 7);
                    ops[block_idx].src_block = (uint16_t)br_read(br, 14);
                    block_idx++;
                }
            } else if (ext_op == 1) {
                /* Extended raw 8x8: 4 raw sub-blocks */
                br_align(br);
                for (int sub = 0; sub < 4 && block_idx < total_blocks; sub++) {
                    if (!br_has_bits(br, 16 * 8)) { block_idx = total_blocks; break; }
                    ops[block_idx].opcode = OP_RAW;
                    for (int i = 0; i < 16; i++) {
                        ops[block_idx].raw_pixels[i] = (uint8_t)br_read(br, 8);
                    }
                    block_idx++;
                }
            } else if (ext_op == 2) {
                /* Extended skip */
                if (!br_has_bits(br, 8)) break;
                uint32_t count = br_read(br, 8) + 1;
                for (uint32_t i = 0; i < count && block_idx < total_blocks; i++) {
                    ops[block_idx].opcode = OP_SKIP;
                    ops[block_idx].skip_count = 1;
                    block_idx++;
                }
            } else {
                /* Unknown extended op — skip block */
                ops[block_idx].opcode = OP_SKIP;
                ops[block_idx].skip_count = 1;
                block_idx++;
            }
        }
    }

    /* ---- Pass 2+: Iterate fractal transform ---- */
    for (int iter = 0; iter < iterations; iter++) {
        /* Swap: back becomes the source, front becomes the destination */
        uint8_t *src_buf = back;
        uint8_t *dst_buf = front;

        /* Copy front to back (back = previous iteration result) */
        memcpy(back, front, plane_w * plane_h);

        for (int bi = 0; bi < total_blocks; bi++) {
            int bx = bi % blocks_x;
            int by = bi / blocks_x;
            int dst_x0 = bx * block_w;
            int dst_y0 = by * block_h;

            switch (ops[bi].opcode) {
            case OP_AFFINE_0:
            case OP_AFFINE_1:
            case OP_AFFINE_2:
            case OP_AFFINE_3: {
                /* Resolve source block coordinates */
                int src_bi = ops[bi].src_block;
                int src_bx = src_bi % blocks_x;
                int src_by = src_bi / blocks_x;
                int src_x0 = src_bx * block_w;
                int src_y0 = src_by * block_h;
                int mode = ops[bi].sym_mode;
                int bias = ops[bi].bias_index;

                /* Downsample 8x8 source region to 4x4, apply symmetry + affine */
                for (int dy = 0; dy < block_h; dy++) {
                    for (int dx = 0; dx < block_w; dx++) {
                        int sx, sy;
                        get_src_coords(mode, dx, dy, &sx, &sy);

                        /* Source pixel from back buffer (with bounds check) */
                        int abs_sx = src_x0 + sx;
                        int abs_sy = src_y0 + sy;
                        if (abs_sx >= plane_w) abs_sx = plane_w - 1;
                        if (abs_sy >= plane_h) abs_sy = plane_h - 1;
                        if (abs_sx < 0) abs_sx = 0;
                        if (abs_sy < 0) abs_sy = 0;

                        uint8_t src_pixel = src_buf[abs_sy * plane_w + abs_sx];

                        /* Apply affine: output = pixel * 3/4 + bias */
                        uint8_t result = scale_table[bias][src_pixel];

                        /* Write to destination */
                        int abs_dx = dst_x0 + dx;
                        int abs_dy = dst_y0 + dy;
                        if (abs_dx < plane_w && abs_dy < plane_h) {
                            dst_buf[abs_dy * plane_w + abs_dx] = result;
                        }
                    }
                }
                break;
            }

            case OP_RAW: {
                /* Write raw pixels directly (same every iteration — convergence) */
                for (int dy = 0; dy < block_h; dy++) {
                    for (int dx = 0; dx < block_w; dx++) {
                        int abs_dx = dst_x0 + dx;
                        int abs_dy = dst_y0 + dy;
                        if (abs_dx < plane_w && abs_dy < plane_h) {
                            dst_buf[abs_dy * plane_w + abs_dx] =
                                ops[bi].raw_pixels[dy * block_w + dx];
                        }
                    }
                }
                break;
            }

            case OP_SKIP:
                /* Copy from back buffer (no change) — already done by memcpy */
                break;
            }
        }
    }

    free(ops);
    return true;
}

/* ------------------------------------------------------------------ */
/* GBR 4:2:0 to BGR conversion                                        */
/* ------------------------------------------------------------------ */

/*
 * The FTC color space is GBR:
 *   Plane 0 = Green (full resolution) — acts as luma
 *   Plane 1 = Blue  (half resolution in both axes)
 *   Plane 2 = Red   (half resolution in both axes)
 *
 * Simple nearest-neighbor upscaling for chroma.
 */
static void gbr420_to_bgr(const uint8_t *g_plane,
                           const uint8_t *b_plane,
                           const uint8_t *r_plane,
                           int width, int height,
                           int chroma_sub,
                           uint8_t *bgr_out)
{
    int chroma_w = width / chroma_sub;

    for (int y = 0; y < height; y++) {
        int cy = y / chroma_sub;
        for (int x = 0; x < width; x++) {
            int cx = x / chroma_sub;
            int luma_idx = y * width + x;
            int chroma_idx = cy * chroma_w + cx;
            int out_idx = luma_idx * 3;

            bgr_out[out_idx + 0] = b_plane[chroma_idx]; /* B */
            bgr_out[out_idx + 1] = g_plane[luma_idx];   /* G */
            bgr_out[out_idx + 2] = r_plane[chroma_idx]; /* R */
        }
    }
}

/* ------------------------------------------------------------------ */
/* Main decode function                                                */
/* ------------------------------------------------------------------ */

static int decode_ftc(const char *input_path, const char *output_path)
{
    long file_size = 0;
    uint8_t *file_data = read_file(input_path, &file_size);
    if (!file_data) {
        fprintf(stderr, "Error: cannot read '%s'\n", input_path);
        return 1;
    }

    FTCHeader hdr;
    FTCSubHeader sub;
    if (!parse_header(file_data, file_size, &hdr, &sub)) {
        free(file_data);
        return 1;
    }

    fprintf(stderr, "FTC: %s (%ld bytes)\n", input_path, file_size);
    fprintf(stderr, "  Dimensions: %u x %u, %u bpp\n", hdr.width, hdr.height, hdr.bpp);
    fprintf(stderr, "  Block size: %ux%u, chroma subsample: %u\n",
            sub.block_w, sub.block_h, sub.chroma_subsample);
    fprintf(stderr, "  Iterations: %u, channels: %u\n", sub.iterations, sub.channels);

    int width = hdr.width;
    int height = hdr.height;
    int block_w = sub.block_w ? sub.block_w : FTC_BLOCK_W;
    int block_h = sub.block_h ? sub.block_h : FTC_BLOCK_H;
    int chroma_sub = sub.chroma_subsample ? sub.chroma_subsample : 2;
    int iterations = sub.iterations ? sub.iterations : 7;

    /* Ensure dimensions are valid */
    if (width <= 0 || height <= 0 || width > 4096 || height > 4096) {
        fprintf(stderr, "Error: invalid dimensions %d x %d\n", width, height);
        free(file_data);
        return 1;
    }

    /* Chroma plane dimensions */
    int chroma_w = width / chroma_sub;
    int chroma_h = height / chroma_sub;

    /* Allocate plane buffers (front + back for each plane) */
    int luma_size = width * height;
    int chroma_size = chroma_w * chroma_h;

    uint8_t *g_front = (uint8_t *)malloc(luma_size);
    uint8_t *g_back  = (uint8_t *)malloc(luma_size);
    uint8_t *b_front = (uint8_t *)malloc(chroma_size);
    uint8_t *b_back  = (uint8_t *)malloc(chroma_size);
    uint8_t *r_front = (uint8_t *)malloc(chroma_size);
    uint8_t *r_back  = (uint8_t *)malloc(chroma_size);

    if (!g_front || !g_back || !b_front || !b_back || !r_front || !r_back) {
        fprintf(stderr, "Error: cannot allocate plane buffers\n");
        free(g_front); free(g_back);
        free(b_front); free(b_back);
        free(r_front); free(r_back);
        free(file_data);
        return 1;
    }

    /* Initialize scale table */
    init_scale_table();

    /* Set up bitstream reader at start of compressed data */
    size_t data_offset = hdr.hdr_size;
    const uint8_t *compressed = file_data + data_offset;
    size_t compressed_size = file_size - data_offset;

    BitReader br;
    br_init(&br, compressed, compressed_size);

    /* Decode green (luma) plane at full resolution */
    fprintf(stderr, "  Decoding green/luma plane (%d x %d)...\n", width, height);
    if (!decode_plane(width, height, g_front, g_back, &br, iterations,
                      block_w, block_h)) {
        fprintf(stderr, "Error: failed to decode luma plane\n");
        goto fail;
    }

    /* Decode blue chroma plane at half resolution */
    fprintf(stderr, "  Decoding blue chroma plane (%d x %d)...\n",
            chroma_w, chroma_h);
    if (!decode_plane(chroma_w, chroma_h, b_front, b_back, &br, iterations,
                      block_w, block_h)) {
        fprintf(stderr, "Error: failed to decode blue chroma plane\n");
        goto fail;
    }

    /* Decode red chroma plane at half resolution */
    fprintf(stderr, "  Decoding red chroma plane (%d x %d)...\n",
            chroma_w, chroma_h);
    if (!decode_plane(chroma_w, chroma_h, r_front, r_back, &br, iterations,
                      block_w, block_h)) {
        fprintf(stderr, "Error: failed to decode red chroma plane\n");
        goto fail;
    }

    /* Convert GBR 4:2:0 to BGR 24-bit */
    fprintf(stderr, "  Converting GBR 4:2:0 to BGR...\n");
    uint8_t *bgr = (uint8_t *)malloc(width * height * 3);
    if (!bgr) {
        fprintf(stderr, "Error: cannot allocate output buffer\n");
        goto fail;
    }

    gbr420_to_bgr(g_front, b_front, r_front, width, height, chroma_sub, bgr);

    /* Write BMP */
    if (write_bmp(output_path, width, height, bgr)) {
        fprintf(stderr, "Wrote: %s (%d x %d, 24-bit BMP)\n",
                output_path, width, height);
    }

    free(bgr);
    free(g_front); free(g_back);
    free(b_front); free(b_back);
    free(r_front); free(r_back);
    free(file_data);
    return 0;

fail:
    free(g_front); free(g_back);
    free(b_front); free(b_back);
    free(r_front); free(r_back);
    free(file_data);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Header info mode                                                    */
/* ------------------------------------------------------------------ */

static int show_info(const char *input_path)
{
    long file_size = 0;
    uint8_t *file_data = read_file(input_path, &file_size);
    if (!file_data) {
        fprintf(stderr, "Error: cannot read '%s'\n", input_path);
        return 1;
    }

    FTCHeader hdr;
    FTCSubHeader sub;
    if (!parse_header(file_data, file_size, &hdr, &sub)) {
        free(file_data);
        return 1;
    }

    print_header_info(&hdr, &sub);

    printf("\nFile: %s (%ld bytes)\n", input_path, file_size);
    printf("Compressed data offset: %u\n", hdr.hdr_size);
    printf("Compressed data size:   %u (file has %ld)\n",
           hdr.data_size, file_size - hdr.hdr_size);

    free(file_data);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "ftcdecode - Clean-room FTC fractal image decoder\n\n");
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  ftcdecode <input.ftc> <output.bmp>   Decode FTC to BMP\n");
        fprintf(stderr, "  ftcdecode -i <input.ftc>             Show header info\n");
        return 1;
    }

    if (strcmp(argv[1], "-i") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: -i requires an input file\n");
            return 1;
        }
        return show_info(argv[2]);
    }

    if (argc < 3) {
        fprintf(stderr, "Error: need both input and output paths\n");
        return 1;
    }

    return decode_ftc(argv[1], argv[2]);
}

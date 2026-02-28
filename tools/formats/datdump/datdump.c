/*
 * datdump - Encarta 97 DAT file parser
 *
 * Exploratory parser for various Encarta 97 .DAT files:
 *   ENCART97.DAT  - Application configuration database
 *   SEEALSO.DAT   - Cross-reference link table
 *   TIMEDB.DAT    - Timeline event database
 *   MTIMEDB.DAT   - Media timeline database
 *   PORTIONS.DAT  - Content segment definitions
 *
 * Usage:
 *   datdump <file.DAT>           Dump header and auto-detect format
 *   datdump -r <file.DAT> <n>    Dump first n records (raw hex)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static void print_hex_line(const uint8_t *data, size_t offset, int len)
{
    printf("%08zX: ", offset);
    for (int i = 0; i < len; i++) {
        printf("%02X ", data[i]);
        if (i == 7) printf(" ");
    }
    /* Pad if short line */
    for (int i = len; i < 16; i++) {
        printf("   ");
        if (i == 7) printf(" ");
    }
    printf(" |");
    for (int i = 0; i < len; i++) {
        char c = (char)data[i];
        printf("%c", (c >= 0x20 && c <= 0x7E) ? c : '.');
    }
    printf("|\n");
}

static void hex_dump(const uint8_t *data, size_t offset, size_t len)
{
    size_t pos = 0;
    while (pos < len) {
        int line_len = (int)((len - pos > 16) ? 16 : (len - pos));
        print_hex_line(data + pos, offset + pos, line_len);
        pos += line_len;
    }
}

/* ------------------------------------------------------------------ */
/* Format detection and parsing                                        */
/* ------------------------------------------------------------------ */

/*
 * ENCART97.DAT format:
 *   - 32-byte header
 *   - Array of 4-byte packed values
 *   - Low 12 bits typically 0 (4K-aligned offsets)
 */
static void parse_encart97(const uint8_t *data, size_t size)
{
    printf("=== ENCART97.DAT analysis ===\n\n");

    printf("Header (first 64 bytes):\n");
    hex_dump(data, 0, size < 64 ? size : 64);

    if (size < 32) return;

    /* Parse header fields */
    printf("\nHeader fields (uint32 LE):\n");
    for (int i = 0; i < 8 && (size_t)(i * 4) < 32; i++) {
        uint32_t val;
        memcpy(&val, data + i * 4, 4);
        printf("  [%02d] 0x%08X  (%u)\n", i, val, val);
    }

    /* Analyze records after header */
    size_t rec_start = 32;
    size_t rec_space = size - rec_start;
    size_t num_u32 = rec_space / 4;

    printf("\nRecords: %zu uint32 values after header\n", num_u32);

    /* Analyze alignment patterns */
    int aligned_4k = 0, nonzero = 0;
    for (size_t i = 0; i < num_u32; i++) {
        uint32_t val;
        memcpy(&val, data + rec_start + i * 4, 4);
        if (val != 0) nonzero++;
        if ((val & 0xFFF) == 0) aligned_4k++;
    }

    printf("Non-zero values: %d / %zu (%.1f%%)\n",
           nonzero, num_u32, 100.0 * nonzero / (num_u32 ? num_u32 : 1));
    printf("4K-aligned values: %d / %zu (%.1f%%)\n",
           aligned_4k, num_u32, 100.0 * aligned_4k / (num_u32 ? num_u32 : 1));

    /* Show first 20 records */
    printf("\nFirst 20 records (uint32):\n");
    for (size_t i = 0; i < 20 && i < num_u32; i++) {
        uint32_t val;
        memcpy(&val, data + rec_start + i * 4, 4);
        printf("  [%4zu] 0x%08X  high20=0x%05X  low12=0x%03X\n",
               i, val, val >> 12, val & 0xFFF);
    }

    /* Look for other record sizes */
    printf("\nTrying different record sizes:\n");
    for (int rs = 2; rs <= 32; rs += 2) {
        size_t nrec = rec_space / rs;
        if (rec_space % rs == 0) {
            printf("  %d-byte records: %zu records (divides evenly)\n", rs, nrec);
        }
    }
}

/*
 * SEEALSO.DAT format:
 *   Cross-reference link table mapping topic IDs to related topics
 */
static void parse_seealso(const uint8_t *data, size_t size)
{
    printf("=== SEEALSO.DAT analysis ===\n\n");

    printf("Header (first 64 bytes):\n");
    hex_dump(data, 0, size < 64 ? size : 64);

    printf("\nHeader fields (uint32 LE):\n");
    for (int i = 0; i < 16 && (size_t)(i * 4) < size; i++) {
        uint32_t val;
        memcpy(&val, data + i * 4, 4);
        printf("  [%02d] offset=%2d  0x%08X  (%u)\n", i, i * 4, val, val);
    }

    /* Try to find string data */
    printf("\nSearching for null-terminated strings...\n");
    int str_count = 0;
    size_t pos = 0;
    while (pos < size && str_count < 20) {
        if (data[pos] >= 0x20 && data[pos] <= 0x7E) {
            size_t start = pos;
            while (pos < size && data[pos] >= 0x20 && data[pos] <= 0x7E)
                pos++;
            size_t len = pos - start;
            if (len >= 4) {
                printf("  @0x%06zX [%3zu] \"", start, len);
                fwrite(data + start, 1, len > 60 ? 60 : len, stdout);
                if (len > 60) printf("...");
                printf("\"\n");
                str_count++;
            }
        }
        pos++;
    }
}

/*
 * TIMEDB.DAT / MTIMEDB.DAT format:
 *   Timeline event databases
 */
static void parse_timedb(const uint8_t *data, size_t size)
{
    printf("=== Timeline DB analysis ===\n\n");

    printf("Header (first 128 bytes):\n");
    hex_dump(data, 0, size < 128 ? size : 128);

    printf("\nHeader fields (uint32 LE):\n");
    for (int i = 0; i < 32 && (size_t)(i * 4) < size; i++) {
        uint32_t val;
        memcpy(&val, data + i * 4, 4);
        printf("  [%02d] offset=%3d  0x%08X  (%u)\n", i, i * 4, val, val);
    }

    /* Look for year values (likely int16 or int32) */
    printf("\nSearching for year-like values (1000-2000 range)...\n");
    int year_count = 0;
    for (size_t pos = 0; pos + 2 <= size && year_count < 30; pos += 2) {
        int16_t val;
        memcpy(&val, data + pos, 2);
        if (val >= -5000 && val <= 2000 && val != 0) {
            /* Check if this looks like a plausible year in context */
            if (abs(val) >= 500 || val == 0) {
                printf("  @0x%06zX: %d\n", pos, val);
                year_count++;
            }
        }
    }
}

/*
 * PORTIONS.DAT format:
 *   Content segment definitions
 */
static void parse_portions(const uint8_t *data, size_t size)
{
    printf("=== PORTIONS.DAT analysis ===\n\n");

    printf("Header (first 128 bytes):\n");
    hex_dump(data, 0, size < 128 ? size : 128);

    printf("\nHeader fields (uint32 LE):\n");
    for (int i = 0; i < 32 && (size_t)(i * 4) < size; i++) {
        uint32_t val;
        memcpy(&val, data + i * 4, 4);
        printf("  [%02d] offset=%3d  0x%08X  (%u)\n", i, i * 4, val, val);
    }
}

/*
 * Generic/unknown DAT format
 */
static void parse_generic(const uint8_t *data, size_t size,
                          const char *filename)
{
    printf("=== %s analysis ===\n\n", filename);

    printf("File size: %zu bytes (0x%zX)\n\n", size, size);

    printf("First 256 bytes:\n");
    hex_dump(data, 0, size < 256 ? size : 256);

    printf("\nLast 64 bytes:\n");
    if (size > 64)
        hex_dump(data + size - 64, size - 64, 64);
    else
        hex_dump(data, 0, size);

    /* Magic byte analysis */
    printf("\nMagic: ");
    for (int i = 0; i < 4 && (size_t)i < size; i++)
        printf("%02X ", data[i]);
    printf("\n");

    /* Byte frequency analysis (first 4KB) */
    int freq[256] = {0};
    size_t sample = size < 4096 ? size : 4096;
    for (size_t i = 0; i < sample; i++)
        freq[data[i]]++;

    printf("\nByte frequency (first %zu bytes):\n", sample);
    printf("  Null bytes: %d (%.1f%%)\n", freq[0],
           100.0 * freq[0] / sample);

    int printable = 0;
    for (int i = 0x20; i <= 0x7E; i++)
        printable += freq[i];
    printf("  Printable: %d (%.1f%%)\n", printable,
           100.0 * printable / sample);
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "datdump - Encarta 97 DAT file parser\n\n");
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  datdump <file.DAT>           Auto-detect and analyze\n");
        fprintf(stderr, "  datdump -r <file.DAT> [n]    Raw hex dump (first n bytes)\n");
        return 1;
    }

    const char *filepath;
    bool raw_mode = false;
    int raw_bytes = 512;

    if (strcmp(argv[1], "-r") == 0) {
        raw_mode = true;
        if (argc < 3) {
            fprintf(stderr, "Error: need a file path\n");
            return 1;
        }
        filepath = argv[2];
        if (argc >= 4) raw_bytes = atoi(argv[3]);
    } else {
        filepath = argv[1];
    }

    /* Read file */
    FILE *f = fopen(filepath, "rb");
    if (!f) {
        fprintf(stderr, "Error: cannot open '%s'\n", filepath);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *data = (uint8_t *)malloc(file_size);
    if (!data) {
        fprintf(stderr, "Error: cannot allocate %ld bytes\n", file_size);
        fclose(f);
        return 1;
    }

    fread(data, 1, file_size, f);
    fclose(f);

    if (raw_mode) {
        printf("File: %s (%ld bytes)\n\n", filepath, file_size);
        int dump_len = (raw_bytes > file_size) ? (int)file_size : raw_bytes;
        hex_dump(data, 0, dump_len);
        free(data);
        return 0;
    }

    /* Auto-detect format by filename */
    const char *basename = strrchr(filepath, '/');
    if (!basename) basename = strrchr(filepath, '\\');
    if (basename) basename++; else basename = filepath;

    /* Case-insensitive filename matching */
    if (_stricmp(basename, "ENCART97.DAT") == 0) {
        parse_encart97(data, file_size);
    } else if (_stricmp(basename, "SEEALSO.DAT") == 0) {
        parse_seealso(data, file_size);
    } else if (_stricmp(basename, "TIMEDB.DAT") == 0 ||
               _stricmp(basename, "MTIMEDB.DAT") == 0) {
        parse_timedb(data, file_size);
    } else if (_stricmp(basename, "PORTIONS.DAT") == 0) {
        parse_portions(data, file_size);
    } else {
        parse_generic(data, file_size, basename);
    }

    free(data);
    return 0;
}

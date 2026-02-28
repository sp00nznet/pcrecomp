/*
 * strdump - Encarta 97 string table extractor
 *
 * Reads ENC97S.STR / ENC97F.STR files which contain null-terminated
 * CP1252 strings (photo credits, captions, audio attributions).
 * Outputs numbered lines to stdout or a UTF-8 text file.
 *
 * Usage: strdump <input.STR> [output.txt]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* CP1252 bytes 0x80-0x9F that differ from Latin-1 → Unicode codepoints */
static const uint16_t cp1252_extra[32] = {
    0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
    0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,
    0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
    0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178
};

/* Encode a Unicode codepoint as UTF-8 into buf, return bytes written */
static int encode_utf8(uint8_t *buf, uint16_t cp)
{
    if (cp < 0x80) {
        buf[0] = (uint8_t)cp;
        return 1;
    } else if (cp < 0x800) {
        buf[0] = 0xC0 | (cp >> 6);
        buf[1] = 0x80 | (cp & 0x3F);
        return 2;
    } else {
        buf[0] = 0xE0 | (cp >> 12);
        buf[1] = 0x80 | ((cp >> 6) & 0x3F);
        buf[2] = 0x80 | (cp & 0x3F);
        return 3;
    }
}

/* Convert a CP1252 byte to its Unicode codepoint */
static uint16_t cp1252_to_unicode(uint8_t ch)
{
    if (ch >= 0x80 && ch <= 0x9F)
        return cp1252_extra[ch - 0x80];
    return ch; /* 0x00-0x7F and 0xA0-0xFF match Latin-1/Unicode */
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: strdump <input.STR> [output.txt]\n");
        fprintf(stderr, "  Extracts null-separated CP1252 strings from Encarta 97 .STR files.\n");
        return 1;
    }

    const char *input_path = argv[1];
    const char *output_path = argc >= 3 ? argv[2] : NULL;

    /* Read entire file */
    FILE *fin = fopen(input_path, "rb");
    if (!fin) {
        fprintf(stderr, "Error: cannot open '%s'\n", input_path);
        return 1;
    }

    fseek(fin, 0, SEEK_END);
    long file_size = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    if (file_size <= 0) {
        fprintf(stderr, "Error: file is empty or unreadable\n");
        fclose(fin);
        return 1;
    }

    uint8_t *data = (uint8_t *)malloc((size_t)file_size);
    if (!data) {
        fprintf(stderr, "Error: out of memory (%ld bytes)\n", file_size);
        fclose(fin);
        return 1;
    }

    size_t nread = fread(data, 1, (size_t)file_size, fin);
    fclose(fin);

    if ((long)nread != file_size) {
        fprintf(stderr, "Error: short read (%zu of %ld bytes)\n", nread, file_size);
        free(data);
        return 1;
    }

    /* Open output */
    FILE *fout = stdout;
    if (output_path) {
        fout = fopen(output_path, "wb");
        if (!fout) {
            fprintf(stderr, "Error: cannot create '%s'\n", output_path);
            free(data);
            return 1;
        }
        /* Write UTF-8 BOM */
        fwrite("\xEF\xBB\xBF", 1, 3, fout);
    }

    /* Walk through null-separated strings */
    int index = 0;
    size_t pos = 0;
    uint8_t utf8buf[4];

    while (pos < nread) {
        /* Find end of current string */
        size_t start = pos;
        while (pos < nread && data[pos] != 0)
            pos++;

        /* Output: index and converted string */
        fprintf(fout, "%d\t", index);

        for (size_t i = start; i < pos; i++) {
            uint16_t cp = cp1252_to_unicode(data[i]);
            int len = encode_utf8(utf8buf, cp);
            fwrite(utf8buf, 1, (size_t)len, fout);
        }

        fprintf(fout, "\n");

        /* Skip the null terminator */
        if (pos < nread)
            pos++;
        index++;
    }

    if (output_path) {
        fclose(fout);
        fprintf(stderr, "Extracted %d strings from '%s' to '%s'\n",
                index, input_path, output_path);
    } else {
        fprintf(stderr, "Extracted %d strings from '%s'\n", index, input_path);
    }

    free(data);
    return 0;
}

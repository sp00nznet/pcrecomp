/*
 * m20dump - M20/MVB (Multimedia Viewer 2.0) container parser & extractor
 *
 * Parses the WHIFS (WinHelp Internal File System) B-tree directory
 * in M20 files to enumerate and extract internal files.
 *
 * Usage:
 *   m20dump -l <file.M20>              List all directory entries
 *   m20dump -x <file.M20> -o <dir>     Extract internal files
 *   m20dump -i <file.M20>              Show file and B-tree header info
 *   m20dump -d <file.M20> -o <dir>     Extract + LZ77 decompress topics
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <direct.h>
#include "m20format.h"

/* ------------------------------------------------------------------ */
/* Utility helpers                                                     */
/* ------------------------------------------------------------------ */

static void print_hex(const uint8_t *data, int len)
{
    for (int i = 0; i < len; i++)
        printf("%02X ", data[i]);
}

static bool make_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0)
        return true;
    return _mkdir(path) == 0;
}

/* Make a filename safe for the filesystem */
static void sanitize_filename(char *out, const char *in, size_t max_len)
{
    size_t j = 0;
    for (size_t i = 0; in[i] && j < max_len - 1; i++) {
        char c = in[i];
        if (c == '|' || c == '>' || c == '<' || c == ':' ||
            c == '"' || c == '/' || c == '\\' || c == '?' || c == '*')
            out[j++] = '_';
        else
            out[j++] = c;
    }
    out[j] = '\0';
}

/* ------------------------------------------------------------------ */
/* File reading helpers                                                */
/* ------------------------------------------------------------------ */

typedef struct {
    FILE    *fp;
    uint8_t *data;       /* Memory-mapped file data */
    size_t   size;       /* File size */
    M20Header header;
    BTreeHeader btree;
} M20File;

static bool m20_open(M20File *m, const char *path)
{
    memset(m, 0, sizeof(*m));

    m->fp = fopen(path, "rb");
    if (!m->fp) {
        fprintf(stderr, "Error: cannot open '%s'\n", path);
        return false;
    }

    /* Get file size */
    fseek(m->fp, 0, SEEK_END);
    m->size = (size_t)ftell(m->fp);
    fseek(m->fp, 0, SEEK_SET);

    /* Read entire file into memory */
    m->data = (uint8_t *)malloc(m->size);
    if (!m->data) {
        fprintf(stderr, "Error: cannot allocate %zu bytes\n", m->size);
        fclose(m->fp);
        return false;
    }

    size_t nread = fread(m->data, 1, m->size, m->fp);
    if (nread != m->size) {
        fprintf(stderr, "Error: short read (%zu of %zu)\n", nread, m->size);
        free(m->data);
        fclose(m->fp);
        return false;
    }

    return true;
}

static void m20_close(M20File *m)
{
    if (m->data) free(m->data);
    if (m->fp) fclose(m->fp);
    memset(m, 0, sizeof(*m));
}

static bool m20_parse_headers(M20File *m)
{
    if (m->size < sizeof(M20Header)) {
        fprintf(stderr, "Error: file too small for M20 header\n");
        return false;
    }

    memcpy(&m->header, m->data, sizeof(M20Header));

    if (m->header.magic != M20_MAGIC) {
        fprintf(stderr, "Error: bad M20 magic (got 0x%08X, expected 0x%08X)\n",
                m->header.magic, M20_MAGIC);
        return false;
    }

    if (m->header.file_size != (uint32_t)m->size) {
        fprintf(stderr, "Warning: header file_size (%u) != actual size (%zu)\n",
                m->header.file_size, m->size);
    }

    /* Validate directory region */
    if (m->header.dir_start >= m->size) {
        fprintf(stderr, "Error: dir_start (0x%X) >= file size\n", m->header.dir_start);
        return false;
    }

    uint32_t expected_dir_size = m->header.file_size - m->header.dir_start;
    if (m->header.dir_size != expected_dir_size) {
        fprintf(stderr, "Warning: dir_size mismatch (%u != %u)\n",
                m->header.dir_size, expected_dir_size);
    }

    /* Parse B-tree header at dir_start */
    if (m->header.dir_start + sizeof(BTreeHeader) > m->size) {
        fprintf(stderr, "Error: B-tree header extends past EOF\n");
        return false;
    }

    memcpy(&m->btree, m->data + m->header.dir_start, sizeof(BTreeHeader));

    if (m->btree.magic != BTREE_MAGIC) {
        fprintf(stderr, "Error: bad B-tree magic (got 0x%04X, expected 0x%04X)\n",
                m->btree.magic, BTREE_MAGIC);
        return false;
    }

    return true;
}

/* ------------------------------------------------------------------ */
/* B-tree directory entry                                              */
/* ------------------------------------------------------------------ */

typedef struct {
    char     key[256];     /* Internal filename */
    uint8_t  key_len;
    uint8_t  data[16];     /* Raw data bytes */
    int      data_len;
    uint32_t file_offset;  /* Varint-decoded file offset */
    uint32_t file_size;    /* Varint-decoded file size */
    uint8_t  file_flags;   /* 1-byte flag field */
} DirEntry;

typedef struct {
    DirEntry *entries;
    uint32_t  count;
    uint32_t  capacity;
} DirEntries;

static void entries_init(DirEntries *d)
{
    d->count = 0;
    d->capacity = 4096;
    d->entries = (DirEntry *)calloc(d->capacity, sizeof(DirEntry));
}

static void entries_add(DirEntries *d, const DirEntry *e)
{
    if (d->count >= d->capacity) {
        d->capacity *= 2;
        d->entries = (DirEntry *)realloc(d->entries, d->capacity * sizeof(DirEntry));
    }
    d->entries[d->count++] = *e;
}

static void entries_free(DirEntries *d)
{
    free(d->entries);
    memset(d, 0, sizeof(*d));
}

/* ------------------------------------------------------------------ */
/* B-tree walker                                                       */
/* ------------------------------------------------------------------ */

/*
 * Check if the byte at `pos` looks like a valid key_len for the next entry.
 * Validates: reasonable length (2-200) and first key char is printable ASCII.
 */
static bool looks_like_entry_start(const uint8_t *pos, const uint8_t *page_end)
{
    if (pos + 2 > page_end) return false;
    uint8_t len = pos[0];
    uint8_t first_char = pos[1];
    return (len >= 2 && len <= 200 &&
            first_char >= 0x20 && first_char <= 0x7E);
}

/*
 * Decode a varint (LEB128) from a byte buffer.
 * Returns the decoded value and advances *pos past the varint bytes.
 * Each byte contributes 7 bits of value; high bit = more bytes follow.
 */
static uint32_t decode_varint(const uint8_t *data, int len, int *pos)
{
    uint32_t val = 0;
    int shift = 0;
    while (*pos < len) {
        uint8_t b = data[(*pos)++];
        val |= (uint32_t)(b & 0x7F) << shift;
        shift += 7;
        if ((b & 0x80) == 0) break;
    }
    return val;
}

/*
 * Walk a single leaf page and collect entries.
 *
 * Entry data format (empirically determined for "VOO1" B-trees):
 *   4 bytes:  file offset (uint32 LE)
 *   N bytes:  additional value bytes (typically 2-3, never 0x00)
 *   1 byte:   0x00 terminator
 *
 * Total data = 4 + N + 1.  Usually N=2 → data=7; occasionally N=3 → data=8.
 *
 * We scan for the 0x00 terminator and validate by checking that the
 * next byte looks like a valid key_len for the following entry.
 */
static bool walk_leaf_page(const M20File *m, uint32_t page_num,
                           DirEntries *entries)
{
    uint32_t pages_start = m->header.dir_start + sizeof(BTreeHeader);
    uint32_t page_offset = pages_start + page_num * m->btree.page_size;

    if (page_offset + m->btree.page_size > m->size) {
        fprintf(stderr, "Warning: page %u extends past EOF\n", page_num);
        return false;
    }

    const uint8_t *page = m->data + page_offset;
    LeafPageHeader lph;
    memcpy(&lph, page, sizeof(lph));

    const uint8_t *p = page + sizeof(LeafPageHeader);
    const uint8_t *page_end = page + m->btree.page_size;

    for (uint16_t i = 0; i < lph.num_entries; i++) {
        if (p >= page_end) break;

        DirEntry e;
        memset(&e, 0, sizeof(e));

        e.key_len = *p++;
        if (e.key_len == 0 || e.key_len > 200 || p + e.key_len + 5 > page_end) {
            fprintf(stderr, "Warning: bad entry at page %u, entry %u "
                    "(key_len=%u, remaining=%td)\n",
                    page_num, i, e.key_len, page_end - p);
            break;
        }

        memcpy(e.key, p, e.key_len);
        e.key[e.key_len] = '\0';
        p += e.key_len;

        /* Parse data: scan for 0x00 terminator after the 4-byte offset.
         * Minimum data = 5 bytes (4 offset + 1 null).
         * We validate that 0x00 is a true terminator by checking whether
         * the following byte starts a valid entry (or we're at the last entry).
         */
        const uint8_t *data_start = p;
        bool found_terminator = false;

        /* Start scanning from byte 4 onward (skip the 4-byte offset) */
        const uint8_t *scan = p + 4;
        while (scan < page_end) {
            if (*scan == 0x00) {
                const uint8_t *after_null = scan + 1;
                bool is_last = (i == lph.num_entries - 1);

                if (is_last ||
                    after_null >= page_end ||
                    looks_like_entry_start(after_null, page_end)) {
                    /* This is the real terminator */
                    scan++; /* include the 0x00 in data */
                    found_terminator = true;
                    break;
                }
                /* 0x00 is a data byte, not a terminator — keep scanning */
            }
            scan++;
        }

        if (!found_terminator) {
            /* Couldn't find a valid terminator — use remaining page data */
            fprintf(stderr, "Warning: no terminator at page %u, entry %u\n",
                    page_num, i);
            break;
        }

        e.data_len = (int)(scan - data_start);
        if (e.data_len > (int)sizeof(e.data))
            e.data_len = (int)sizeof(e.data);
        memcpy(e.data, data_start, e.data_len);
        p = scan;

        /* Decode data fields: varint offset, varint size, 1-byte flag.
         * Format "VOO1": V=length-prefixed key, O=varint, O=varint, 1=byte */
        {
            int dp = 0;
            e.file_offset = decode_varint(e.data, e.data_len, &dp);
            e.file_size   = decode_varint(e.data, e.data_len, &dp);
            e.file_flags  = (dp < e.data_len) ? e.data[dp] : 0;
        }

        entries_add(entries, &e);
    }

    return true;
}

/*
 * Find all leaf pages by walking the B-tree from the root.
 * Collects leaf page numbers in order.
 */
static void collect_leaf_pages(const M20File *m, uint32_t page_num,
                               int level, uint32_t *leaf_pages,
                               uint32_t *leaf_count, uint32_t max_leaves)
{
    uint32_t pages_start = m->header.dir_start + sizeof(BTreeHeader);
    uint32_t page_offset = pages_start + page_num * m->btree.page_size;

    if (page_offset + m->btree.page_size > m->size) return;
    if (*leaf_count >= max_leaves) return;

    const uint8_t *page = m->data + page_offset;

    if (level <= 1) {
        /* This is a leaf page */
        leaf_pages[(*leaf_count)++] = page_num;
        return;
    }

    /* This is an index page — walk children */
    IndexPageHeader iph;
    memcpy(&iph, page, sizeof(iph));

    /* First child (leftmost, before any keys) */
    collect_leaf_pages(m, iph.first_child, level - 1,
                       leaf_pages, leaf_count, max_leaves);

    /* Walk key-child pairs */
    const uint8_t *p = page + sizeof(IndexPageHeader);
    const uint8_t *page_end = page + m->btree.page_size;

    for (uint16_t i = 0; i < iph.num_entries; i++) {
        if (p >= page_end) break;

        uint8_t key_len = *p++;
        if (key_len == 0 || p + key_len + 4 > page_end) break;

        p += key_len; /* Skip key */

        uint32_t child_page;
        memcpy(&child_page, p, 4);
        p += 4;

        collect_leaf_pages(m, child_page, level - 1,
                           leaf_pages, leaf_count, max_leaves);
    }
}

static bool walk_btree(const M20File *m, DirEntries *entries)
{
    uint32_t max_leaves = m->btree.total_pages + 1;
    uint32_t *leaf_pages = (uint32_t *)calloc(max_leaves, sizeof(uint32_t));
    uint32_t leaf_count = 0;

    collect_leaf_pages(m, m->btree.root_page, m->btree.num_levels,
                       leaf_pages, &leaf_count, max_leaves);

    fprintf(stderr, "Found %u leaf pages\n", leaf_count);

    for (uint32_t i = 0; i < leaf_count; i++) {
        if (!walk_leaf_page(m, leaf_pages[i], entries)) {
            fprintf(stderr, "Warning: failed to walk leaf page %u\n",
                    leaf_pages[i]);
        }
    }

    free(leaf_pages);
    return true;
}

/* ------------------------------------------------------------------ */
/* LZ77 decompression (WinHelp-compatible)                             */
/* ------------------------------------------------------------------ */

/*
 * Decompress LZ77-compressed data from WinHelp/MVB topic blocks.
 *
 * Format:
 *   Control byte: 8 bits, LSB first.
 *     Bit 0 = literal byte follows
 *     Bit 1 = match reference follows (16-bit: pos:12, len:4)
 *   Match decoding:
 *     uint16_t desc = (hi << 8) | lo
 *     pos = desc >> 4          (12-bit ring buffer position)
 *     len = (desc & 0x0F) + 3  (minimum match length = 3)
 *     Copy len bytes from ring buffer at (dest - pos - 1)
 */
static int lz77_decompress(const uint8_t *src, int src_len,
                           uint8_t *dst, int dst_max)
{
    int si = 0, di = 0;
    uint8_t ring[LZ77_RING_SIZE];
    int ring_pos = 0;
    memset(ring, 0, sizeof(ring));

    while (si < src_len && di < dst_max) {
        if (si >= src_len) break;
        uint8_t control = src[si++];

        for (int bit = 0; bit < 8 && si < src_len && di < dst_max; bit++) {
            if (control & (1 << bit)) {
                /* Match reference */
                if (si + 1 >= src_len) goto done;
                uint8_t lo = src[si++];
                uint8_t hi = src[si++];
                uint16_t desc = ((uint16_t)hi << 8) | lo;
                int pos = desc >> 4;
                int len = (desc & 0x0F) + LZ77_MATCH_MIN;

                for (int j = 0; j < len && di < dst_max; j++) {
                    uint8_t b = ring[(pos + j) % LZ77_RING_SIZE];
                    dst[di++] = b;
                    ring[ring_pos] = b;
                    ring_pos = (ring_pos + 1) % LZ77_RING_SIZE;
                }
            } else {
                /* Literal byte */
                if (si >= src_len) goto done;
                uint8_t b = src[si++];
                dst[di++] = b;
                ring[ring_pos] = b;
                ring_pos = (ring_pos + 1) % LZ77_RING_SIZE;
            }
        }
    }

done:
    return di;
}

/* ------------------------------------------------------------------ */
/* Commands                                                            */
/* ------------------------------------------------------------------ */

static void cmd_info(M20File *m, const char *path)
{
    printf("File: %s\n", path);
    printf("Size: %zu bytes (0x%zX)\n", m->size, m->size);
    printf("\n--- M20 Header ---\n");
    printf("Magic:        0x%08X %s\n", m->header.magic,
           m->header.magic == M20_MAGIC ? "(OK)" : "(BAD)");
    printf("Dir start:    0x%08X (%u)\n", m->header.dir_start, m->header.dir_start);
    printf("First free:   0x%08X\n", m->header.first_free);
    printf("Internal hdr: 0x%08X (%u)\n", m->header.internal_hdr, m->header.internal_hdr);
    printf("File size:    0x%08X (%u)\n", m->header.file_size, m->header.file_size);
    printf("Dir size:     0x%08X (%u)\n", m->header.dir_size, m->header.dir_size);
    printf("Content info: 0x%08X (%u)\n", m->header.content_info, m->header.content_info);

    uint32_t content_size = m->header.dir_start - sizeof(M20Header);
    printf("Content rgn:  0x%08X .. 0x%08X (%u bytes)\n",
           (uint32_t)sizeof(M20Header), m->header.dir_start, content_size);

    printf("\n--- B-tree Header ---\n");
    printf("Magic:        0x%04X %s\n", m->btree.magic,
           m->btree.magic == BTREE_MAGIC ? "(OK)" : "(BAD)");
    printf("Flags:        0x%04X\n", m->btree.flags);
    printf("Page size:    %u bytes\n", m->btree.page_size);
    printf("Format:       \"%.16s\"\n", m->btree.format);
    printf("Page splits:  %u\n", m->btree.page_splits);
    printf("Root page:    %u\n", m->btree.root_page);
    printf("Total pages:  %u\n", m->btree.total_pages);
    printf("Num levels:   %u\n", m->btree.num_levels);
    printf("Total entries:%u\n", m->btree.total_entries);

    /* Show first leaf page header for debugging */
    printf("\n--- Page 0 (first page) ---\n");
    uint32_t pg0 = m->header.dir_start + sizeof(BTreeHeader);
    if (pg0 + 12 <= m->size) {
        LeafPageHeader lph;
        memcpy(&lph, m->data + pg0, sizeof(lph));
        printf("Flags:        0x%04X\n", lph.flags);
        printf("Num entries:  %u\n", lph.num_entries);
        printf("Prev page:    %d\n", lph.prev_page);
        printf("Next page:    %d\n", lph.next_page);

        /* Show first few entries (null-terminated data parsing) */
        printf("\nFirst entries:\n");
        const uint8_t *p = m->data + pg0 + sizeof(LeafPageHeader);
        const uint8_t *pg_end = m->data + pg0 + m->btree.page_size;
        for (int i = 0; i < 5 && i < lph.num_entries && p < pg_end; i++) {
            uint8_t kl = *p++;
            printf("  [%d] len=%u key=\"", i, kl);
            for (int j = 0; j < kl && j < 64; j++) {
                char c = (char)p[j];
                if (c >= 0x20 && c <= 0x7E)
                    putchar(c);
                else
                    printf("\\x%02X", (unsigned char)c);
            }
            printf("\" data=");
            p += kl;
            /* Scan for null terminator after 4-byte offset */
            const uint8_t *data_start = p;
            p += 4; /* skip offset */
            while (p < pg_end && *p != 0x00) p++;
            if (p < pg_end) p++; /* include 0x00 */
            int dlen = (int)(p - data_start);
            print_hex(data_start, dlen);
            printf(" (%d bytes)\n", dlen);
        }
    }
}

static void cmd_list(M20File *m)
{
    DirEntries entries;
    entries_init(&entries);

    if (!walk_btree(m, &entries)) {
        fprintf(stderr, "Error: failed to walk B-tree\n");
        entries_free(&entries);
        return;
    }

    printf("%-40s  %-10s  %-10s  %s\n", "Key", "Offset", "Size", "RawData");
    printf("%-40s  %-10s  %-10s  %s\n",
           "----------------------------------------",
           "----------", "----------",
           "--------------------");

    /* Count entry types */
    uint32_t topic_count = 0, file_count = 0, system_count = 0;

    for (uint32_t i = 0; i < entries.count; i++) {
        DirEntry *e = &entries.entries[i];

        printf("%-40s  0x%08X  %-10u  ",
               e->key, e->file_offset, e->file_size);
        print_hex(e->data, e->data_len);
        printf("\n");

        if (e->key[0] == '>')
            topic_count++;
        else if (e->key[0] == '|')
            system_count++;
        else
            file_count++;
    }

    fprintf(stderr, "\nTotal: %u entries (%u topics, %u system, %u files)\n",
            entries.count, topic_count, system_count, file_count);

    entries_free(&entries);
}

static void cmd_extract(M20File *m, const char *outdir, bool decompress)
{
    DirEntries entries;
    entries_init(&entries);

    if (!walk_btree(m, &entries)) {
        fprintf(stderr, "Error: failed to walk B-tree\n");
        entries_free(&entries);
        return;
    }

    if (!make_dir(outdir)) {
        fprintf(stderr, "Error: cannot create output directory '%s'\n", outdir);
        entries_free(&entries);
        return;
    }

    uint32_t extracted = 0, skipped = 0;

    for (uint32_t i = 0; i < entries.count; i++) {
        DirEntry *e = &entries.entries[i];

        /* Varint-decoded offset points directly to file data */
        if (e->file_offset == 0 || e->file_size == 0) {
            skipped++;
            continue;
        }

        if (e->file_offset + e->file_size > m->size) {
            /* Clamp to available data */
            if (e->file_offset < m->size) {
                e->file_size = (uint32_t)(m->size - e->file_offset);
            } else {
                skipped++;
                continue;
            }
        }

        /* Build output filename */
        char safename[256];
        sanitize_filename(safename, e->key, sizeof(safename));

        char filepath[512];
        snprintf(filepath, sizeof(filepath), "%s/%s", outdir, safename);

        const uint8_t *file_data = m->data + e->file_offset;
        uint32_t data_len = e->file_size;

        if (decompress) {
            /* LZ77 decompress */
            int decomp_size = (int)data_len * 4 + 65536;
            uint8_t *decomp = (uint8_t *)malloc(decomp_size);
            if (decomp) {
                int actual = lz77_decompress(file_data, (int)data_len,
                                             decomp, decomp_size);
                FILE *fout = fopen(filepath, "wb");
                if (fout) {
                    fwrite(decomp, 1, actual, fout);
                    fclose(fout);
                    extracted++;
                }
                free(decomp);
            }
        } else {
            /* Write raw */
            FILE *fout = fopen(filepath, "wb");
            if (fout) {
                fwrite(file_data, 1, data_len, fout);
                fclose(fout);
                extracted++;
            }
        }
    }

    fprintf(stderr, "Extracted %u files, skipped %u (total %u entries)\n",
            extracted, skipped, entries.count);

    entries_free(&entries);
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr, "m20dump - M20/MVB container parser & extractor\n\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s -i <file.M20>              Show header info\n", prog);
    fprintf(stderr, "  %s -l <file.M20>              List directory entries\n", prog);
    fprintf(stderr, "  %s -x <file.M20> -o <dir>     Extract raw files\n", prog);
    fprintf(stderr, "  %s -d <file.M20> -o <dir>     Extract + decompress\n", prog);
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    char mode = 0;
    const char *input = NULL;
    const char *outdir = "m20_output";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "-l") == 0 ||
            strcmp(argv[i], "-x") == 0 || strcmp(argv[i], "-d") == 0) {
            mode = argv[i][1];
            if (i + 1 < argc && argv[i + 1][0] != '-')
                input = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            outdir = argv[++i];
        } else if (!input) {
            input = argv[i];
        }
    }

    if (!input) {
        fprintf(stderr, "Error: no input file specified\n");
        usage(argv[0]);
        return 1;
    }

    if (!mode) mode = 'i'; /* Default to info mode */

    M20File m;
    if (!m20_open(&m, input))
        return 1;

    if (!m20_parse_headers(&m)) {
        m20_close(&m);
        return 1;
    }

    switch (mode) {
    case 'i':
        cmd_info(&m, input);
        break;
    case 'l':
        cmd_list(&m);
        break;
    case 'x':
        cmd_extract(&m, outdir, false);
        break;
    case 'd':
        cmd_extract(&m, outdir, true);
        break;
    default:
        usage(argv[0]);
        break;
    }

    m20_close(&m);
    return 0;
}

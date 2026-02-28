/*
 * m20format.h - M20/MVB (Multimedia Viewer Book) 2.0 format structures
 *
 * The M20 format is Microsoft's Multimedia Viewer 2.0 container, an
 * extension of the Windows Help (WinHelp) Internal File System (WHIFS).
 *
 * File layout:
 *   [0x00 .. 0x30)            MVB file header (48 bytes)
 *   [0x30 .. content_end)     Internal file data (topic blocks, images, etc.)
 *   [content_end .. file_end) WHIFS B-tree directory
 *
 * The B-tree directory maps internal filenames to file offsets:
 *   ">XXXXXXXX"    Topic entries (8 hex-digit topic IDs)
 *   "|SYSTEM"      System configuration
 *   "|TOPIC"       Topic data stream
 *   "|CONTEXT"     Context number → topic offset mapping
 *   "|Phrases"     Phrase decompression table
 *   "TXXXXXXXA.*"  Baggage files (embedded images, etc.)
 */

#ifndef M20FORMAT_H
#define M20FORMAT_H

#include <stdint.h>

#pragma pack(push, 1)

/* MVB 2.0 file header — 48 bytes at offset 0 */
typedef struct {
    uint32_t magic;          /* 0x0104_5F3F for MVB 2.0 */
    uint32_t dir_start;      /* Offset to WHIFS B-tree directory */
    uint32_t first_free;     /* First free block offset (0 = none) */
    uint32_t internal_hdr;   /* Internal file header size (0x28 = 40) */
    uint32_t reserved1;
    uint32_t file_size;      /* Total file size in bytes */
    uint32_t reserved2;
    uint32_t dir_size;       /* Size of directory region = file_size - dir_start */
    uint32_t reserved3;
    uint32_t reserved4;
    uint32_t content_info;   /* Related to content region size */
    uint32_t reserved5;
} M20Header;

#define M20_MAGIC 0x01045F3FUL

/* B-tree header — 48 bytes at dir_start */
typedef struct {
    uint16_t magic;          /* 0x293B */
    uint16_t flags;          /* 0x0102 for MVB directory */
    uint16_t page_size;      /* Page size in bytes (typically 0x2000 = 8192) */
    char     format[16];     /* Format string, e.g. "VOO1\0..." */
    uint32_t must_be_zero;   /* Always 0 */
    uint32_t page_splits;    /* Number of page splits during construction */
    uint32_t root_page;      /* Page number of the root node */
    int32_t  must_be_neg1;   /* Always -1 */
    uint32_t total_pages;    /* Total number of B-tree pages */
    uint16_t num_levels;     /* Number of tree levels (1=flat, 2=root+leaves) */
    uint32_t total_entries;  /* Total number of entries across all leaves */
} BTreeHeader;

#define BTREE_MAGIC 0x293BU

/* Leaf page header — 12 bytes at start of each leaf page */
typedef struct {
    uint16_t flags;          /* Page flags / ID (varies) */
    uint16_t num_entries;    /* Number of entries in this page */
    int32_t  prev_page;      /* Previous leaf page number (-1 = none) */
    int32_t  next_page;      /* Next leaf page number (-1 = none) */
} LeafPageHeader;

/* Index page header — 8 bytes at start of each index page */
typedef struct {
    uint16_t flags;          /* Page flags / ID */
    uint16_t num_entries;    /* Number of key-child entries */
    uint32_t first_child;    /* Page number of leftmost child */
} IndexPageHeader;

/*
 * B-tree entry format (variable-length):
 *
 * Leaf entries (format "VOO1"):
 *   uint8_t  key_len;     Length of key string in bytes
 *   char     key[key_len]; Key string (NOT null-terminated)
 *   varint   file_offset; LEB128-encoded file offset within M20
 *   varint   file_size;   LEB128-encoded file size in bytes
 *   uint8_t  flags;       Always 0x00 in observed data
 *
 * Index entries:
 *   uint8_t  key_len;     Length of key string in bytes
 *   char     key[key_len]; Key string (NOT null-terminated)
 *   uint32_t child_page;  Page number of child node
 *
 * Varint encoding (LEB128):
 *   Each byte contributes 7 bits of value (bits 0-6).
 *   Bit 7 = 1 means more bytes follow; bit 7 = 0 means final byte.
 *   Bytes are stored LSB-first.
 *
 * The data field size varies per entry (typically 6-8 bytes total)
 * depending on the magnitude of the offset and size values.
 * Topic offsets (large) need 4-byte varints, while baggage file
 * offsets (smaller) may only need 3-byte varints.
 *
 * The file_offset points directly to file data (no internal file header).
 */

/* LZ77 decompression parameters (WinHelp-compatible) */
#define LZ77_RING_SIZE      4096
#define LZ77_MATCH_MIN      3
#define LZ77_CONTROL_BITS   8

/* Topic block sizes */
#define TOPIC_BLOCK_RAW     4096    /* Raw compressed block size */
#define TOPIC_BLOCK_DECOMP  16384   /* Decompressed block size */

#pragma pack(pop)

#endif /* M20FORMAT_H */

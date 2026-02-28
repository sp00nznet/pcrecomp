/*
 * spamdump - SPAM (CMF/MDF/TDF) format parser
 *
 * Parses the Encarta 97 SPAM multimedia files:
 *   - MDF (Media Directory File): directory of media entries
 *   - CMF (Compressed Media File): compressed media blob container
 *   - TDF (Topic Definition File): OLE2 structured storage
 *
 * Usage:
 *   spamdump -l <file.MDF>                 List MDF directory entries
 *   spamdump -x <file.MDF> <file.CMF> -o <dir>  Extract CMF blobs
 *   spamdump -t <file.TDF>                 List TDF OLE2 streams
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <direct.h>

#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <objbase.h>

#pragma pack(push, 1)

/* MDF header — at offset 0 */
typedef struct {
    uint16_t magic1;        /* 0x002A */
    uint16_t magic2;        /* 0x0003 */
    uint32_t num_entries1;  /* Entry count (first field) */
    uint32_t num_entries2;  /* Entry count (second field, may differ) */
    uint32_t cmf_size;      /* Referenced CMF file size */
} MDFHeader;

#define MDF_MAGIC1 0x002A
#define MDF_MAGIC2 0x0003

/* MDF entry — 22 bytes each */
typedef struct {
    uint32_t cmf_offset;    /* Offset into CMF file */
    uint32_t cmf_size;      /* Size of blob in CMF */
    uint32_t field3;        /* Unknown field */
    uint32_t field4;        /* Unknown field */
    uint16_t field5;        /* Unknown field */
    uint16_t type_id;       /* Media type identifier */
    uint16_t field7;        /* Unknown field */
} MDFEntry;

/* CMF header — at offset 0 */
typedef struct {
    uint16_t magic1;        /* 0x01FD */
    uint16_t magic2;        /* 0x0003 */
    uint32_t file_size;     /* Total CMF file size */
} CMFHeader;

#define CMF_MAGIC1 0x01FD
#define CMF_MAGIC2 0x0003

#pragma pack(pop)

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static bool make_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0)
        return true;
    return _mkdir(path) == 0;
}

static uint8_t *read_file(const char *path, long *out_size)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *data = (uint8_t *)malloc(size);
    if (!data) { fclose(f); return NULL; }

    size_t nread = fread(data, 1, size, f);
    fclose(f);

    if ((long)nread != size) { free(data); return NULL; }

    *out_size = size;
    return data;
}

static void print_hex(const uint8_t *data, int len)
{
    for (int i = 0; i < len; i++)
        printf("%02X ", data[i]);
}

/* ------------------------------------------------------------------ */
/* MDF parser                                                          */
/* ------------------------------------------------------------------ */

static void cmd_list_mdf(const char *path)
{
    long size = 0;
    uint8_t *data = read_file(path, &size);
    if (!data) {
        fprintf(stderr, "Error: cannot read '%s'\n", path);
        return;
    }

    if (size < (long)sizeof(MDFHeader)) {
        fprintf(stderr, "Error: file too small for MDF header\n");
        free(data);
        return;
    }

    MDFHeader hdr;
    memcpy(&hdr, data, sizeof(hdr));

    printf("MDF File: %s\n", path);
    printf("Magic:    0x%04X 0x%04X", hdr.magic1, hdr.magic2);
    if (hdr.magic1 == MDF_MAGIC1 && hdr.magic2 == MDF_MAGIC2)
        printf(" (OK)\n");
    else
        printf(" (unexpected)\n");

    printf("Entries1: %u\n", hdr.num_entries1);
    printf("Entries2: %u\n", hdr.num_entries2);
    printf("CMF size: %u (0x%X)\n", hdr.cmf_size, hdr.cmf_size);

    /* Calculate number of entries that fit */
    long entries_space = size - sizeof(MDFHeader);
    long max_entries = entries_space / sizeof(MDFEntry);
    uint32_t num_entries = hdr.num_entries1;
    if (num_entries > (uint32_t)max_entries)
        num_entries = (uint32_t)max_entries;

    printf("\n%-6s  %-10s  %-10s  %-10s  %-10s  %-6s  %-6s  %-6s\n",
           "Index", "CMFOffset", "CMFSize", "Field3", "Field4",
           "Fld5", "Type", "Fld7");

    const MDFEntry *entries = (const MDFEntry *)(data + sizeof(MDFHeader));

    uint32_t total_blob_size = 0;
    for (uint32_t i = 0; i < num_entries; i++) {
        const MDFEntry *e = &entries[i];
        printf("%-6u  0x%08X  %-10u  0x%08X  0x%08X  0x%04X  0x%04X  0x%04X\n",
               i, e->cmf_offset, e->cmf_size, e->field3, e->field4,
               e->field5, e->type_id, e->field7);
        total_blob_size += e->cmf_size;
    }

    printf("\nTotal: %u entries, %u bytes of blob data\n",
           num_entries, total_blob_size);

    free(data);
}

/* ------------------------------------------------------------------ */
/* CMF blob extraction                                                 */
/* ------------------------------------------------------------------ */

static void cmd_extract_cmf(const char *mdf_path, const char *cmf_path,
                            const char *outdir)
{
    long mdf_size = 0, cmf_size = 0;
    uint8_t *mdf_data = read_file(mdf_path, &mdf_size);
    uint8_t *cmf_data = read_file(cmf_path, &cmf_size);

    if (!mdf_data) {
        fprintf(stderr, "Error: cannot read MDF '%s'\n", mdf_path);
        return;
    }
    if (!cmf_data) {
        fprintf(stderr, "Error: cannot read CMF '%s'\n", cmf_path);
        free(mdf_data);
        return;
    }

    /* Validate CMF header */
    if (cmf_size >= (long)sizeof(CMFHeader)) {
        CMFHeader cmf_hdr;
        memcpy(&cmf_hdr, cmf_data, sizeof(cmf_hdr));
        printf("CMF Magic: 0x%04X 0x%04X", cmf_hdr.magic1, cmf_hdr.magic2);
        if (cmf_hdr.magic1 == CMF_MAGIC1 && cmf_hdr.magic2 == CMF_MAGIC2)
            printf(" (OK)\n");
        else
            printf(" (unexpected)\n");
        printf("CMF declared size: %u, actual: %ld\n",
               cmf_hdr.file_size, cmf_size);
    }

    MDFHeader mdf_hdr;
    memcpy(&mdf_hdr, mdf_data, sizeof(mdf_hdr));

    long entries_space = mdf_size - sizeof(MDFHeader);
    long max_entries = entries_space / sizeof(MDFEntry);
    uint32_t num_entries = mdf_hdr.num_entries1;
    if (num_entries > (uint32_t)max_entries)
        num_entries = (uint32_t)max_entries;

    if (!make_dir(outdir)) {
        fprintf(stderr, "Error: cannot create '%s'\n", outdir);
        free(mdf_data);
        free(cmf_data);
        return;
    }

    const MDFEntry *entries = (const MDFEntry *)(mdf_data + sizeof(MDFHeader));
    uint32_t extracted = 0, skipped = 0;

    for (uint32_t i = 0; i < num_entries; i++) {
        const MDFEntry *e = &entries[i];

        if (e->cmf_offset + e->cmf_size > (uint32_t)cmf_size) {
            fprintf(stderr, "Warning: entry %u offset 0x%X + size %u exceeds CMF\n",
                    i, e->cmf_offset, e->cmf_size);
            skipped++;
            continue;
        }

        char filepath[512];
        snprintf(filepath, sizeof(filepath), "%s/blob_%06u_t%04X.bin",
                 outdir, i, e->type_id);

        FILE *f = fopen(filepath, "wb");
        if (f) {
            fwrite(cmf_data + e->cmf_offset, 1, e->cmf_size, f);
            fclose(f);
            extracted++;
        } else {
            skipped++;
        }
    }

    fprintf(stderr, "Extracted %u blobs, skipped %u\n", extracted, skipped);

    free(mdf_data);
    free(cmf_data);
}

/* ------------------------------------------------------------------ */
/* TDF (OLE2) parser                                                   */
/* ------------------------------------------------------------------ */

static void walk_storage(IStorage *pStg, const wchar_t *prefix, int depth)
{
    IEnumSTATSTG *pEnum = NULL;
    HRESULT hr = IStorage_EnumElements(pStg, 0, NULL, 0, &pEnum);
    if (FAILED(hr)) {
        fprintf(stderr, "Error: EnumElements failed (0x%08lX)\n", hr);
        return;
    }

    STATSTG stat;
    while (IEnumSTATSTG_Next(pEnum, 1, &stat, NULL) == S_OK) {
        /* Print indentation */
        for (int i = 0; i < depth; i++) printf("  ");

        switch (stat.type) {
        case STGTY_STORAGE:
            wprintf(L"[DIR]  %s\n", stat.pwcsName);
            {
                IStorage *pChild = NULL;
                hr = IStorage_OpenStorage(pStg, stat.pwcsName, NULL,
                    STGM_READ | STGM_SHARE_EXCLUSIVE, NULL, 0, &pChild);
                if (SUCCEEDED(hr)) {
                    walk_storage(pChild, stat.pwcsName, depth + 1);
                    IStorage_Release(pChild);
                }
            }
            break;

        case STGTY_STREAM:
            wprintf(L"[STM]  %-30s  %llu bytes\n",
                    stat.pwcsName, stat.cbSize.QuadPart);
            break;

        default:
            wprintf(L"[???]  %s  (type=%d)\n", stat.pwcsName, stat.type);
            break;
        }

        CoTaskMemFree(stat.pwcsName);
    }

    IEnumSTATSTG_Release(pEnum);
}

static void cmd_list_tdf(const char *path)
{
    /* Convert path to wide string */
    int wlen = MultiByteToWideChar(CP_ACP, 0, path, -1, NULL, 0);
    wchar_t *wpath = (wchar_t *)malloc(wlen * sizeof(wchar_t));
    MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, wlen);

    HRESULT hr = CoInitialize(NULL);
    if (FAILED(hr)) {
        fprintf(stderr, "Error: COM initialization failed\n");
        free(wpath);
        return;
    }

    IStorage *pStg = NULL;
    hr = StgOpenStorage(wpath, NULL,
        STGM_READ | STGM_SHARE_DENY_WRITE, NULL, 0, &pStg);

    if (FAILED(hr)) {
        fprintf(stderr, "Error: cannot open OLE2 storage '%s' (0x%08lX)\n",
                path, hr);
        /* Maybe it's not an OLE2 file — dump first bytes */
        FILE *f = fopen(path, "rb");
        if (f) {
            uint8_t buf[32];
            size_t n = fread(buf, 1, sizeof(buf), f);
            fclose(f);
            fprintf(stderr, "First %zu bytes: ", n);
            print_hex(buf, (int)n);
            fprintf(stderr, "\n");
        }
        CoUninitialize();
        free(wpath);
        return;
    }

    printf("TDF File: %s (OLE2 Structured Storage)\n\n", path);
    walk_storage(pStg, L"", 0);

    IStorage_Release(pStg);
    CoUninitialize();
    free(wpath);
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "spamdump - SPAM (CMF/MDF/TDF) format parser\n\n");
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  spamdump -l <file.MDF>                     List MDF entries\n");
        fprintf(stderr, "  spamdump -x <file.MDF> <file.CMF> -o <dir> Extract blobs\n");
        fprintf(stderr, "  spamdump -t <file.TDF>                     List TDF streams\n");
        return 1;
    }

    char mode = argv[1][1];

    switch (mode) {
    case 'l':
        cmd_list_mdf(argv[2]);
        break;

    case 'x':
        if (argc < 4) {
            fprintf(stderr, "Error: need both MDF and CMF files\n");
            return 1;
        }
        {
            const char *outdir = "spam_output";
            for (int i = 4; i < argc - 1; i++) {
                if (strcmp(argv[i], "-o") == 0)
                    outdir = argv[++i];
            }
            cmd_extract_cmf(argv[2], argv[3], outdir);
        }
        break;

    case 't':
        cmd_list_tdf(argv[2]);
        break;

    default:
        fprintf(stderr, "Unknown mode '-%c'\n", mode);
        return 1;
    }

    return 0;
}

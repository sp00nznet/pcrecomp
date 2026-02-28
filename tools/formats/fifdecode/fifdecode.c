/*
 * fifdecode - FIF image decoder using DECO_32.DLL bridge
 *
 * Loads Iterated Systems' DECO_32.DLL at runtime and uses its exported
 * functions to decode FIF (Fractal Image Format) images to BMP files.
 *
 * Usage:
 *   fifdecode <input.fif> <output.bmp> [deco_32.dll path]
 *   fifdecode -e                        List DLL exports (diagnostic)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "fifdecode.h"

/* Vectored exception handler for debugging DLL crashes */
static LONG CALLBACK crash_handler(PEXCEPTION_POINTERS info)
{
    if (info->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        fprintf(stderr, "  CRASH at EIP=0x%08lX\n",
                (unsigned long)info->ContextRecord->Eip);
        fprintf(stderr, "  Access type: %s address 0x%08lX\n",
                info->ExceptionRecord->ExceptionInformation[0] ? "WRITE" : "READ",
                (unsigned long)info->ExceptionRecord->ExceptionInformation[1]);
        fprintf(stderr, "  EAX=0x%08lX EBX=0x%08lX ECX=0x%08lX EDX=0x%08lX\n",
                info->ContextRecord->Eax, info->ContextRecord->Ebx,
                info->ContextRecord->Ecx, info->ContextRecord->Edx);
        fprintf(stderr, "  ESI=0x%08lX EDI=0x%08lX ESP=0x%08lX EBP=0x%08lX\n",
                info->ContextRecord->Esi, info->ContextRecord->Edi,
                info->ContextRecord->Esp, info->ContextRecord->Ebp);
        fflush(stderr);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* Default DLL search paths */
static const char *dll_search_paths[] = {
    "DECO_32.DLL",
    ".\\DECO_32.DLL",
    "C:\\encarta\\analysis\\DECO_32.DLL",
    "F:\\AAMSSTP\\ENCARTA\\DECO_32.DLL",
    NULL
};

/* ------------------------------------------------------------------ */
/* DLL loading                                                         */
/* ------------------------------------------------------------------ */

static HMODULE find_and_load_dll(const char *explicit_path)
{
    HMODULE h;

    if (explicit_path) {
        h = LoadLibraryA(explicit_path);
        if (h) return h;
        fprintf(stderr, "Warning: cannot load '%s' (error %lu)\n",
                explicit_path, GetLastError());
    }

    for (int i = 0; dll_search_paths[i]; i++) {
        h = LoadLibraryA(dll_search_paths[i]);
        if (h) {
            fprintf(stderr, "Loaded DLL from: %s\n", dll_search_paths[i]);
            return h;
        }
    }

    return NULL;
}

#define RESOLVE(funcs, name) do { \
    (funcs)->name = (pfn##name)GetProcAddress((funcs)->hDLL, #name); \
    if (!(funcs)->name) { \
        fprintf(stderr, "Warning: export '%s' not found\n", #name); \
    } \
} while(0)

#define REQUIRE(funcs, name) do { \
    RESOLVE(funcs, name); \
    if (!(funcs)->name) { \
        fprintf(stderr, "Error: required export '%s' not found\n", #name); \
        return false; \
    } \
} while(0)

static bool resolve_exports(DecoFuncs *f)
{
    REQUIRE(f, OpenDecompressor);
    REQUIRE(f, CloseDecompressor);
    REQUIRE(f, SetFIFBuffer);
    REQUIRE(f, ClearFIFBuffer);
    REQUIRE(f, DecompressToBuffer);

    /* Optional but useful */
    RESOLVE(f, GetFIFFTTFileName);
    RESOLVE(f, SetFTTBuffer);
    RESOLVE(f, ClearFTTBuffer);
    RESOLVE(f, GetOriginalResolution);
    RESOLVE(f, SetOutputResolution);
    RESOLVE(f, GetOutputResolution);
    RESOLVE(f, SetOutputFormat);
    RESOLVE(f, GetOutputFormat);
    RESOLVE(f, GetFIFColorTable);
    RESOLVE(f, SetOutputColorTable);
    RESOLVE(f, GetOutputColorTable);
    RESOLVE(f, GetPhysicalDimensions);
    RESOLVE(f, DecompressToYUV);
    RESOLVE(f, GetDecoVersion);

    return true;
}

/* ------------------------------------------------------------------ */
/* BMP writer                                                          */
/* ------------------------------------------------------------------ */

#pragma pack(push, 1)
typedef struct {
    uint16_t bfType;
    uint32_t bfSize;
    uint16_t bfReserved1;
    uint16_t bfReserved2;
    uint32_t bfOffBits;
} BMPFILEHEADER;

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
} BMPINFOHEADER;
#pragma pack(pop)

static bool write_bmp(const char *path, int width, int height,
                      int bpp, const uint8_t *pixels, int stride)
{
    int row_bytes = ((width * bpp + 31) / 32) * 4; /* BMP row alignment */
    int image_size = row_bytes * abs(height);

    BMPFILEHEADER fh;
    BMPINFOHEADER ih;

    memset(&fh, 0, sizeof(fh));
    memset(&ih, 0, sizeof(ih));

    fh.bfType = 0x4D42; /* 'BM' */
    fh.bfOffBits = sizeof(BMPFILEHEADER) + sizeof(BMPINFOHEADER);
    fh.bfSize = fh.bfOffBits + image_size;

    ih.biSize = sizeof(BMPINFOHEADER);
    ih.biWidth = width;
    ih.biHeight = height; /* Positive = bottom-up */
    ih.biPlanes = 1;
    ih.biBitCount = (uint16_t)bpp;
    ih.biCompression = 0; /* BI_RGB */
    ih.biSizeImage = image_size;
    ih.biXPelsPerMeter = 2835; /* 72 DPI */
    ih.biYPelsPerMeter = 2835;

    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "Error: cannot create '%s'\n", path);
        return false;
    }

    fwrite(&fh, 1, sizeof(fh), f);
    fwrite(&ih, 1, sizeof(ih), f);

    /* Write pixel rows (BMP is bottom-up, FIF output may already be) */
    int src_stride = (stride > 0) ? stride : width * (bpp / 8);
    for (int y = 0; y < abs(height); y++) {
        const uint8_t *row = pixels + y * src_stride;
        fwrite(row, 1, width * (bpp / 8), f);
        /* Pad to 4-byte alignment */
        int pad = row_bytes - width * (bpp / 8);
        if (pad > 0) {
            uint8_t zeros[4] = {0};
            fwrite(zeros, 1, pad, f);
        }
    }

    fclose(f);
    return true;
}

/* ------------------------------------------------------------------ */
/* List DLL exports (diagnostic)                                       */
/* ------------------------------------------------------------------ */

static void list_exports(const char *dll_path)
{
    HMODULE h = find_and_load_dll(dll_path);
    if (!h) {
        fprintf(stderr, "Error: cannot load DECO_32.DLL\n");
        return;
    }

    /* Parse PE export table manually */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)h;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)h + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(
        (BYTE*)h + nt->OptionalHeader.DataDirectory[0].VirtualAddress);

    DWORD *names = (DWORD*)((BYTE*)h + exports->AddressOfNames);
    WORD  *ordinals = (WORD*)((BYTE*)h + exports->AddressOfNameOrdinals);
    DWORD *functions = (DWORD*)((BYTE*)h + exports->AddressOfFunctions);

    printf("DECO_32.DLL exports (%lu functions):\n", exports->NumberOfNames);
    printf("%-4s  %-30s  %-10s\n", "Ord", "Name", "RVA");

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char *name = (const char*)((BYTE*)h + names[i]);
        WORD ordinal = ordinals[i] + (WORD)exports->Base;
        DWORD rva = functions[ordinals[i]];
        printf("%-4u  %-30s  0x%08lX\n", ordinal, name, rva);
    }

    FreeLibrary(h);
}

/* ------------------------------------------------------------------ */
/* FIF decode pipeline                                                 */
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

static int decode_fif(const char *input_path, const char *output_path,
                      const char *dll_path)
{
    DecoFuncs funcs;
    memset(&funcs, 0, sizeof(funcs));

    AddVectoredExceptionHandler(1, crash_handler);

    /* Load DLL */
    funcs.hDLL = find_and_load_dll(dll_path);
    if (!funcs.hDLL) {
        fprintf(stderr, "Error: cannot find DECO_32.DLL\n");
        fprintf(stderr, "Searched in:\n");
        for (int i = 0; dll_search_paths[i]; i++)
            fprintf(stderr, "  %s\n", dll_search_paths[i]);
        if (dll_path)
            fprintf(stderr, "  %s\n", dll_path);
        return 1;
    }

    if (!resolve_exports(&funcs)) {
        FreeLibrary(funcs.hDLL);
        return 1;
    }

    fprintf(stderr, "Exports resolved successfully\n");

    /* Skip GetDecoVersion — may crash if called before OpenDecompressor */

    /* Read FIF file */
    long fif_size = 0;
    uint8_t *fif_data = read_file(input_path, &fif_size);
    if (!fif_data) {
        fprintf(stderr, "Error: cannot read '%s'\n", input_path);
        FreeLibrary(funcs.hDLL);
        return 1;
    }

    fprintf(stderr, "FIF file: %s (%ld bytes)\n", input_path, fif_size);

    /* Open decompressor — returns error code, writes handle to output param */
    fprintf(stderr, "Calling OpenDecompressor...\n");
    fflush(stderr);
    HDECOMP hd = NULL;
    int open_ret = funcs.OpenDecompressor(&hd);
    fprintf(stderr, "OpenDecompressor returned %d, handle=%p\n", open_ret, hd);
    fflush(stderr);
    if (open_ret != 0 || !hd) {
        fprintf(stderr, "Error: OpenDecompressor() failed (ret=%d)\n", open_ret);
        free(fif_data);
        FreeLibrary(funcs.hDLL);
        return 1;
    }

    /* Set FIF buffer */
    fprintf(stderr, "Calling SetFIFBuffer (%ld bytes)...\n", fif_size);
    fflush(stderr);
    int ret = funcs.SetFIFBuffer(hd, fif_data, (int)fif_size);
    fprintf(stderr, "SetFIFBuffer returned %d\n", ret);
    fflush(stderr);

    /* Check for FTT file */
    if (funcs.GetFIFFTTFileName) {
        const char *ftt_name = funcs.GetFIFFTTFileName(hd);
        if (ftt_name && ftt_name[0]) {
            fprintf(stderr, "FTT file required: %s\n", ftt_name);

            /* Try to find and load FTT file */
            char ftt_path[512];

            /* Try same directory as input */
            const char *last_sep = strrchr(input_path, '\\');
            if (!last_sep) last_sep = strrchr(input_path, '/');
            if (last_sep) {
                int dir_len = (int)(last_sep - input_path + 1);
                snprintf(ftt_path, sizeof(ftt_path), "%.*s%s",
                         dir_len, input_path, ftt_name);
            } else {
                snprintf(ftt_path, sizeof(ftt_path), "%s", ftt_name);
            }

            long ftt_size = 0;
            uint8_t *ftt_data = read_file(ftt_path, &ftt_size);
            if (ftt_data && funcs.SetFTTBuffer) {
                fprintf(stderr, "Loaded FTT: %s (%ld bytes)\n",
                        ftt_path, ftt_size);
                funcs.SetFTTBuffer(hd, ftt_data, (int)ftt_size);
                free(ftt_data);
            } else {
                fprintf(stderr, "Warning: cannot find FTT file '%s'\n",
                        ftt_path);
            }
        }
    }

    /* Get original resolution */
    int width = 0, height = 0;
    if (funcs.GetOriginalResolution) {
        funcs.GetOriginalResolution(hd, &width, &height);
        fprintf(stderr, "Original resolution: %d x %d\n", width, height);
    }

    if (width <= 0 || height <= 0) {
        fprintf(stderr, "Error: invalid image dimensions %d x %d\n",
                width, height);
        funcs.ClearFIFBuffer(hd);
        funcs.CloseDecompressor(hd);
        free(fif_data);
        FreeLibrary(funcs.hDLL);
        return 1;
    }

    /* Set output format to 24-bit BGR (standard Windows DIB) */
    if (funcs.SetOutputFormat) {
        funcs.SetOutputFormat(hd, FIF_FMT_BGR24);
    }

    /* Set output resolution */
    if (funcs.SetOutputResolution) {
        funcs.SetOutputResolution(hd, width, height);
    }

    /* Allocate output buffer */
    int stride = ((width * 3 + 3) & ~3); /* 4-byte aligned row stride */
    int buf_size = stride * height;
    uint8_t *pixels = (uint8_t *)calloc(1, buf_size);
    if (!pixels) {
        fprintf(stderr, "Error: cannot allocate %d bytes for image\n", buf_size);
        funcs.ClearFIFBuffer(hd);
        funcs.CloseDecompressor(hd);
        free(fif_data);
        FreeLibrary(funcs.hDLL);
        return 1;
    }

    /* Decompress */
    fprintf(stderr, "Decompressing...\n");
    ret = funcs.DecompressToBuffer(hd, pixels, stride);
    if (ret != 0) {
        fprintf(stderr, "Warning: DecompressToBuffer returned %d\n", ret);
    }

    /* Write BMP */
    if (write_bmp(output_path, width, height, 24, pixels, stride)) {
        fprintf(stderr, "Wrote: %s (%d x %d, 24-bit BMP)\n",
                output_path, width, height);
    }

    /* Cleanup */
    free(pixels);
    funcs.ClearFIFBuffer(hd);
    funcs.CloseDecompressor(hd);
    free(fif_data);
    FreeLibrary(funcs.hDLL);

    return 0;
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "fifdecode - FIF image decoder (DECO_32.DLL bridge)\n\n");
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  fifdecode <input.fif> <output.bmp> [deco_32.dll]\n");
        fprintf(stderr, "  fifdecode -e [deco_32.dll]   List DLL exports\n");
        return 1;
    }

    if (strcmp(argv[1], "-e") == 0) {
        list_exports(argc >= 3 ? argv[2] : NULL);
        return 0;
    }

    if (argc < 3) {
        fprintf(stderr, "Error: need both input and output paths\n");
        return 1;
    }

    const char *dll_path = (argc >= 4) ? argv[3] : NULL;
    return decode_fif(argv[1], argv[2], dll_path);
}

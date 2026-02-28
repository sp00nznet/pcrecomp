/*
 * fifdecode.h - FIF image decoder function types
 *
 * Function signatures for DECO_32.DLL, Iterated Systems' FIF
 * (Fractal Image Format) decompressor. The DLL is loaded at runtime
 * via LoadLibrary and functions resolved via GetProcAddress.
 *
 * Calling convention: __stdcall (typical for 32-bit Windows DLLs)
 * All 28 exports use C linkage (no name mangling).
 */

#ifndef FIFDECODE_H
#define FIFDECODE_H

#include <windows.h>
#include <stdint.h>

/* Opaque decompressor handle */
typedef void *HDECOMP;

/* Output format constants (DIB formats) */
#define FIF_FMT_BGR24    0   /* 24-bit BGR (standard Windows DIB) */
#define FIF_FMT_BGR32    1   /* 32-bit BGRA */
#define FIF_FMT_PALETTE8 2   /* 8-bit palettized */

/*
 * DECO_32.DLL export function types
 *
 * These are discovered from the DLL's export table.
 * Parameter types are inferred from Ghidra analysis and
 * documented FIF SDK conventions.
 */

/*
 * Calling convention: __cdecl (confirmed by disassembly — plain RET, no RET N).
 * OpenDecompressor takes a pointer parameter and returns error code,
 * NOT a handle directly (confirmed by crash analysis showing MOV [EBX], EAX
 * at the function epilogue — writing result to an output parameter).
 */

/* Decompressor lifecycle */
typedef int      (__cdecl *pfnOpenDecompressor)(HDECOMP *);
typedef void     (__cdecl *pfnCloseDecompressor)(HDECOMP);

/* FIF data input */
typedef int      (__cdecl *pfnSetFIFBuffer)(HDECOMP, const void*, int);
typedef void     (__cdecl *pfnClearFIFBuffer)(HDECOMP);

/* FTT (Fractal Transform Table) */
typedef const char* (__cdecl *pfnGetFIFFTTFileName)(HDECOMP);
typedef int      (__cdecl *pfnSetFTTBuffer)(HDECOMP, const void*, int);
typedef void     (__cdecl *pfnClearFTTBuffer)(HDECOMP);

/* Resolution and format queries */
typedef int      (__cdecl *pfnGetOriginalResolution)(HDECOMP, int*, int*);
typedef int      (__cdecl *pfnSetOutputResolution)(HDECOMP, int, int);
typedef int      (__cdecl *pfnGetOutputResolution)(HDECOMP, int*, int*);
typedef int      (__cdecl *pfnSetOutputFormat)(HDECOMP, int);
typedef int      (__cdecl *pfnGetOutputFormat)(HDECOMP);

/* Color table management */
typedef int      (__cdecl *pfnGetFIFColorTable)(HDECOMP, void*);
typedef int      (__cdecl *pfnSetOutputColorTable)(HDECOMP, const void*);
typedef int      (__cdecl *pfnGetOutputColorTable)(HDECOMP, void*);

/* Physical dimensions */
typedef int      (__cdecl *pfnGetPhysicalDimensions)(HDECOMP, int*, int*);

/* Decompression */
typedef int      (__cdecl *pfnDecompressToBuffer)(HDECOMP, void*, int);
typedef int      (__cdecl *pfnDecompressToYUV)(HDECOMP, void*, void*, void*, int, int);

/* Version info */
typedef int      (__cdecl *pfnGetDecoVersion)(void);

/* All DECO_32.DLL function pointers */
typedef struct {
    HMODULE                  hDLL;
    pfnOpenDecompressor      OpenDecompressor;
    pfnCloseDecompressor     CloseDecompressor;
    pfnSetFIFBuffer          SetFIFBuffer;
    pfnClearFIFBuffer        ClearFIFBuffer;
    pfnGetFIFFTTFileName     GetFIFFTTFileName;
    pfnSetFTTBuffer          SetFTTBuffer;
    pfnClearFTTBuffer        ClearFTTBuffer;
    pfnGetOriginalResolution GetOriginalResolution;
    pfnSetOutputResolution   SetOutputResolution;
    pfnGetOutputResolution   GetOutputResolution;
    pfnSetOutputFormat       SetOutputFormat;
    pfnGetOutputFormat       GetOutputFormat;
    pfnGetFIFColorTable      GetFIFColorTable;
    pfnSetOutputColorTable   SetOutputColorTable;
    pfnGetOutputColorTable   GetOutputColorTable;
    pfnGetPhysicalDimensions GetPhysicalDimensions;
    pfnDecompressToBuffer    DecompressToBuffer;
    pfnDecompressToYUV       DecompressToYUV;
    pfnGetDecoVersion        GetDecoVersion;
} DecoFuncs;

#endif /* FIFDECODE_H */

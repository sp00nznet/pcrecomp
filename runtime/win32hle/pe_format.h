/*
 * pe_format.h - the 32-bit PE structures the loader needs, defined portably so
 * no windows.h is required (native32 got these from windows.h, which is exactly
 * what kept it on Windows). Little-endian, byte-packed; the fields are only the
 * ones recomp_pe_map / recomp_pe_bind read.
 */
#ifndef PE_FORMAT_H
#define PE_FORMAT_H
#include <stdint.h>

#pragma pack(push, 1)

typedef struct {
    uint16_t e_magic;      /* 'MZ' = 0x5A4D */
    uint16_t e_cblp[29];   /* rest of the DOS header, unused */
    int32_t  e_lfanew;     /* file offset of the PE signature */
} pe_dos_header;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} pe_file_header;

typedef struct { uint32_t VirtualAddress, Size; } pe_data_dir;

typedef struct {
    uint16_t    Magic;                 /* 0x10B = PE32 */
    uint8_t     MajorLinkerVersion, MinorLinkerVersion;
    uint32_t    SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    uint32_t    AddressOfEntryPoint, BaseOfCode, BaseOfData;
    uint32_t    ImageBase;
    uint32_t    SectionAlignment, FileAlignment;
    uint16_t    MajorOSVersion, MinorOSVersion, MajorImageVersion, MinorImageVersion;
    uint16_t    MajorSubsystemVersion, MinorSubsystemVersion;
    uint32_t    Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    uint16_t    Subsystem, DllCharacteristics;
    uint32_t    SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit;
    uint32_t    LoaderFlags, NumberOfRvaAndSizes;
    pe_data_dir DataDirectory[16];
} pe_opt_header32;

typedef struct {
    uint32_t        Signature;         /* 'PE\0\0' = 0x00004550 */
    pe_file_header  FileHeader;
    pe_opt_header32 OptionalHeader;
} pe_nt_headers32;

typedef struct {
    uint8_t  Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations, PointerToLinenumbers;
    uint16_t NumberOfRelocations, NumberOfLinenumbers;
    uint32_t Characteristics;
} pe_section_header;

typedef struct {
    uint32_t OriginalFirstThunk;   /* RVA of the import name table (ILT) */
    uint32_t TimeDateStamp, ForwarderChain;
    uint32_t Name;                 /* RVA of the DLL name */
    uint32_t FirstThunk;           /* RVA of the IAT */
} pe_import_descriptor;

typedef struct { uint32_t VirtualAddress, SizeOfBlock; } pe_base_reloc;

#pragma pack(pop)

#define PE_DIR_IMPORT    1
#define PE_DIR_BASERELOC 5
#define PE_REL_HIGHLOW   3
#define PE_ORDINAL_FLAG  0x80000000u

#endif /* PE_FORMAT_H */

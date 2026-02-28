/*
 * startup.c - MSC 5.x C Runtime Startup Replacement
 *
 * The original CIV.EXE entry point (CS:IP = 2A10:0010) is the MSC 5.x
 * C runtime startup code (crt0). It initializes the data segment, BSS,
 * stack, copies initialized data, then calls through __astart to main().
 *
 * Full startup chain traced from the binary:
 *   1. res_02A310 (crt0)    -> copies 0x14E9 bytes init data, RETF
 *   2. res_0204E3 (__astart) -> CRT init, BSS clear, sets DS=SS
 *   3. res_001A66 (C main)  -> title screen, game setup, turn loop
 *     3a. res_001EE4         -> game data initialization
 *     3b. res_0022DA         -> new game/load game handler
 *     3c. ovl05_02F800       -> new game world generation + state setup
 *     3d. res_0023F0 (loop)  -> per-turn processing loop
 *
 * In our recompilation, the EXE image is loaded into flat memory.
 * We replicate the essential parts of crt0 and __astart, then call
 * res_001A66 (C main) directly.
 *
 * MSC DGROUP model: DS = SS (data and stack in same segment).
 * The __astart code sets SS from its header, then DS = SS.
 * The crt0 DS_OFFSET (0x30C8) gives the runtime data segment.
 *
 * Memory layout within DS:
 *   0x0000 - 0x14E8: Initialized data (.data) - copied from crt0 segment
 *   0x14E9 - 0x64C1: More initialized data (already in place from EXE load)
 *   0x64C2 - 0xF7F0: BSS (.bss) - cleared to zero by __astart
 *   0xF7F0+:          Stack (grows downward from SP=0xFFEE)
 *
 * Part of the Civ Recomp project (sp00nznet/civ)
 */

#include "recomp/cpu.h"
#include <stdio.h>
#include <string.h>

/* MSC startup fields from the CIV.EXE header */
#define CIV_DS_OFFSET  0x30C8   /* DS = LOAD_SEG + this */
#define CIV_LOAD_SEG   0x0100   /* DOS load segment */

/* The crt0 copies 0x14E9 bytes of initialized data from the crt0
 * segment (CS:0000) to the data segment (DS:0000). */
#define CIV_CRT0_SEG       0x2A10  /* CS value of crt0 segment */
#define CIV_DATA_COPY_SIZE  0x14E9

/* BSS region within DGROUP (from __astart's rep stosb) */
#define CIV_BSS_START  0x64C2   /* First byte of BSS in DS */
#define CIV_BSS_END    0xF7F0   /* One past last byte of BSS in DS */

/* Stack setup (matching __astart) */
#define CIV_SP_INIT    0xFFEE   /* SP after __astart setup */

/*
 * res_02A310 - Entry point replacement
 *
 * Replaces the MSC crt0 + __astart startup sequence.
 * Initializes CPU segment registers, copies initialized data,
 * clears BSS, sets up the stack, then calls the game's C main()
 * function (res_001A66).
 */
void res_02A310(CPU *cpu)
{
    /*
     * Set segment registers.
     * MSC DGROUP model: DS = ES = SS (all point to the same segment).
     * This matches what __astart does: mov ss, di; push ss; pop ds.
     */
    cpu->ds = CIV_LOAD_SEG + CIV_DS_OFFSET;
    cpu->es = cpu->ds;
    cpu->ss = cpu->ds;     /* DS = SS = DGROUP */
    cpu->sp = CIV_SP_INIT;

    printf("[STARTUP] DS=%04X ES=%04X SS=%04X SP=%04X\n",
           cpu->ds, cpu->es, cpu->ss, cpu->sp);

    /*
     * Replicate the crt0 data copy: copy 0x14E9 bytes of initialized
     * data from the crt0 code segment to the data segment.
     * Source: (LOAD_SEG + CRT0_SEG):0000
     * Dest:   DS:0000
     */
    uint32_t src_flat = seg_off(CIV_LOAD_SEG + CIV_CRT0_SEG, 0);
    uint32_t dst_flat = seg_off(cpu->ds, 0);
    if (src_flat + CIV_DATA_COPY_SIZE <= MEM_SIZE &&
        dst_flat + CIV_DATA_COPY_SIZE <= MEM_SIZE) {
        memcpy(cpu->mem + dst_flat, cpu->mem + src_flat, CIV_DATA_COPY_SIZE);
        printf("[STARTUP] Copied %d bytes of initialized data to DS:0000\n",
               CIV_DATA_COPY_SIZE);
    }

    /*
     * Clear BSS: zero out DS:0x64C2 through DS:0xF7F0.
     * This matches __astart's: mov di, 0x64C2; mov cx, 0xF7F0;
     * sub cx, di; xor ax, ax; rep stosb
     */
    uint32_t bss_flat = dst_flat + CIV_BSS_START;
    uint32_t bss_size = CIV_BSS_END - CIV_BSS_START;
    if (bss_flat + bss_size <= MEM_SIZE) {
        memset(cpu->mem + bss_flat, 0, bss_size);
        printf("[STARTUP] Cleared BSS: DS:%04X - DS:%04X (%u bytes)\n",
               CIV_BSS_START, CIV_BSS_END, bss_size);
    }

    /*
     * Save CRT state variables that __astart normally stores.
     * Some MSC library functions reference these.
     */
    mem_write16(cpu, cpu->ss, 0x5840, cpu->sp);   /* __astktop */
    mem_write16(cpu, cpu->ss, 0x583C, cpu->sp);   /* __astkbot */
    mem_write16(cpu, cpu->ss, 0x58B1, cpu->ds);   /* __aintdiv saved DS */

    /* Set up the stack frame as MSC expects for main() */
    cpu->bp = 0;  /* __astart does xor bp, bp before calling main */

    printf("[STARTUP] Calling C main (res_001A66)...\n");

    /*
     * Call the game's C main() function.
     *
     * In the original binary, __astart pushes argc, argv, envp:
     *   push word ds:[0x58D2]  ; envp
     *   push word ds:[0x58D0]  ; argv
     *   push word ds:[0x58CE]  ; argc
     *   call res_001A66
     *
     * The game doesn't use command line args, so we push zeros.
     * The pushes set up the stack frame that res_001A66 expects.
     */
    push16(cpu, 0);  /* envp */
    push16(cpu, 0);  /* argv */
    push16(cpu, 0);  /* argc */

    extern void res_001A66(CPU *cpu);
    push16(cpu, 0);  /* near call return addr */
    res_001A66(cpu);

    printf("[STARTUP] C main returned, setting halted flag\n");
    cpu->halted = 1;
}

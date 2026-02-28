/*
 * cpu.c - CPU state management for Civilization static recompilation
 *
 * Part of the Civ Recomp project (sp00nznet/civ)
 */

#include "recomp/cpu.h"
#include <stdlib.h>
#include <stdio.h>

int cpu_alloc_mem(CPU *cpu)
{
    cpu->mem = (uint8_t *)calloc(1, MEM_SIZE);
    if (!cpu->mem) {
        fprintf(stderr, "Error: failed to allocate %d bytes for CPU memory\n", MEM_SIZE);
        return -1;
    }
    return 0;
}

void cpu_free(CPU *cpu)
{
    if (cpu->mem) {
        free(cpu->mem);
        cpu->mem = NULL;
    }
}

int cpu_load(CPU *cpu, const char *path, uint16_t seg, uint16_t off)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Error: cannot open '%s'\n", path);
        return -1;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint32_t addr = seg_off(seg, off);
    if (addr + size > MEM_SIZE) {
        fprintf(stderr, "Error: binary too large for memory (addr=0x%X, size=%ld)\n",
                addr, size);
        fclose(f);
        return -1;
    }

    size_t read = fread(cpu->mem + addr, 1, size, f);
    fclose(f);

    if ((long)read != size) {
        fprintf(stderr, "Error: short read (%zu of %ld bytes)\n", read, size);
        return -1;
    }

    printf("Loaded %ld bytes at %04X:%04X (flat 0x%06X)\n", size, seg, off, addr);
    return 0;
}

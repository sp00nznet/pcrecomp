/*
 * cpu.h - 8086/8088 CPU State for Static Recompilation
 *
 * This struct represents the complete CPU state that recompiled code
 * operates on. Each recompiled function takes a pointer to this struct
 * and manipulates it directly, preserving the exact behavior of the
 * original 16-bit x86 code.
 *
 * Memory model: The original game runs in 16-bit real mode with a
 * 1 MB address space (20-bit physical = segment << 4 + offset).
 * We allocate a flat 1 MB + 64K buffer and translate segment:offset
 * addresses to flat offsets at runtime.
 *
 * Part of the Civ Recomp project (sp00nznet/civ)
 */

#ifndef CIV_RECOMP_CPU_H
#define CIV_RECOMP_CPU_H

#include <stdint.h>
#include <string.h>

/* ---------- Flag bits ---------- */
#define FLAG_CF  0x0001  /* Carry */
#define FLAG_PF  0x0004  /* Parity */
#define FLAG_AF  0x0010  /* Auxiliary carry */
#define FLAG_ZF  0x0040  /* Zero */
#define FLAG_SF  0x0080  /* Sign */
#define FLAG_TF  0x0100  /* Trap */
#define FLAG_IF  0x0200  /* Interrupt enable */
#define FLAG_DF  0x0400  /* Direction */
#define FLAG_OF  0x0800  /* Overflow */

/* ---------- Memory constants ---------- */
#define MEM_SIZE          (1024 * 1024 + 65536)  /* 1 MB + 64 KB overflow */
#define VGA_SEGMENT       0xA000
#define VGA_FRAMEBUFFER   (VGA_SEGMENT << 4)     /* 0xA0000 */
#define VGA_FB_SIZE       65536
#define BIOS_DATA_SEG     0x0040
#define DOS_PSP_SIZE      256

/* ---------- CPU State ---------- */
typedef struct CPU {
    /* General-purpose registers (low byte, high byte, word access) */
    union { struct { uint8_t al, ah; }; uint16_t ax; uint32_t eax; };
    union { struct { uint8_t bl, bh; }; uint16_t bx; uint32_t ebx; };
    union { struct { uint8_t cl, ch; }; uint16_t cx; uint32_t ecx; };
    union { struct { uint8_t dl, dh; }; uint16_t dx; uint32_t edx; };

    /* Index and pointer registers */
    uint16_t si;
    uint16_t di;
    uint16_t bp;
    uint16_t sp;

    /* Segment registers */
    uint16_t cs;
    uint16_t ds;
    uint16_t es;
    uint16_t ss;

    /* Instruction pointer (for debugging/tracing) */
    uint16_t ip;

    /* Flags register */
    uint16_t flags;

    /* Flat memory (1 MB address space) */
    uint8_t *mem;

    /* Direction flag cache (1 = decrement, 0 = increment) for string ops */
    int dir;

    /* Halt flag (set by HLT or INT 20h / program exit) */
    int halted;

} CPU;

/* ---------- Segment:offset → flat address ---------- */
/* Real mode multiplies the segment by 16, which is what a DOS binary means
 * and what this defaults to. Protected mode does not: a selector is an index
 * into a descriptor table and its base has nothing to do with its numeric
 * value, so a Windows NE needs a lookup instead. Defining SEG_OFF before
 * including this header replaces the rule and nothing else - the accessors
 * below, and every lifted `mem_read16(cpu, cpu->ds, off)`, are unchanged. */
#ifndef SEG_OFF
#define SEG_OFF(seg, off) ((((uint32_t)(uint16_t)(seg)) << 4) + (uint32_t)(uint16_t)(off))
#endif

static inline uint32_t seg_off(uint16_t seg, uint16_t off)
{
    return SEG_OFF(seg, off);
}

/* ---------- Memory access ---------- */
static inline uint8_t mem_read8(CPU *cpu, uint16_t seg, uint16_t off)
{
    return cpu->mem[seg_off(seg, off)];
}

static inline uint16_t mem_read16(CPU *cpu, uint16_t seg, uint16_t off)
{
    uint32_t addr = seg_off(seg, off);
    return (uint16_t)cpu->mem[addr] | ((uint16_t)cpu->mem[addr + 1] << 8);
}

static inline void mem_write8(CPU *cpu, uint16_t seg, uint16_t off, uint8_t val)
{
    cpu->mem[seg_off(seg, off)] = val;
}

static inline void mem_write16(CPU *cpu, uint16_t seg, uint16_t off, uint16_t val)
{
    uint32_t addr = seg_off(seg, off);
    cpu->mem[addr] = (uint8_t)(val & 0xFF);
    cpu->mem[addr + 1] = (uint8_t)(val >> 8);
}

/* 32-bit memory access from a 16-bit segment. A 386 in 16-bit code reads
 * and writes dwords with an operand-size prefix, and code that handles
 * far pointers or 32-bit fields does it constantly. The offset still wraps
 * at 16 bits, so it is computed as uint16_t on purpose. */
static inline uint32_t mem_read32(CPU *cpu, uint16_t seg, uint16_t off)
{
    uint32_t lo = mem_read16(cpu, seg, off);
    uint32_t hi = mem_read16(cpu, seg, (uint16_t)(off + 2));
    return lo | (hi << 16);
}

static inline void mem_write32(CPU *cpu, uint16_t seg, uint16_t off, uint32_t val)
{
    mem_write16(cpu, seg, off, (uint16_t)(val & 0xFFFF));
    mem_write16(cpu, seg, (uint16_t)(off + 2), (uint16_t)(val >> 16));
}

/* Data segment shortcuts (most common) */
static inline uint8_t ds_read8(CPU *cpu, uint16_t off)
{
    return mem_read8(cpu, cpu->ds, off);
}

static inline uint16_t ds_read16(CPU *cpu, uint16_t off)
{
    return mem_read16(cpu, cpu->ds, off);
}

static inline void ds_write8(CPU *cpu, uint16_t off, uint8_t val)
{
    mem_write8(cpu, cpu->ds, off, val);
}

static inline void ds_write16(CPU *cpu, uint16_t off, uint16_t val)
{
    mem_write16(cpu, cpu->ds, off, val);
}

/* Stack operations */
static inline void push16(CPU *cpu, uint16_t val)
{
    cpu->sp -= 2;
    mem_write16(cpu, cpu->ss, cpu->sp, val);
}

static inline uint16_t pop16(CPU *cpu)
{
    uint16_t val = mem_read16(cpu, cpu->ss, cpu->sp);
    cpu->sp += 2;
    return val;
}

/* 32-bit stack operations in a 16-bit segment.
 *
 * Not a contradiction: a 16-bit code segment on a 386 can carry an
 * operand-size prefix and push a dword, and real code does - IR32's 16-bit
 * half passes 32-bit arguments to its 32-bit half that way. SP is still a
 * 16-bit offset into SS and still wraps as one, so the arithmetic is done
 * in uint16_t deliberately. */
static inline void push32(CPU *cpu, uint32_t val)
{
    cpu->sp = (uint16_t)(cpu->sp - 4);
    mem_write16(cpu, cpu->ss, cpu->sp, (uint16_t)(val & 0xFFFF));
    mem_write16(cpu, cpu->ss, (uint16_t)(cpu->sp + 2), (uint16_t)(val >> 16));
}

static inline uint32_t pop32(CPU *cpu)
{
    uint32_t lo = mem_read16(cpu, cpu->ss, cpu->sp);
    uint32_t hi = mem_read16(cpu, cpu->ss, (uint16_t)(cpu->sp + 2));
    cpu->sp = (uint16_t)(cpu->sp + 4);
    return lo | (hi << 16);
}

/* ---------- Flags computation ---------- */

/* Parity lookup table (1 if even number of set bits in low byte) */
static inline int parity8(uint8_t v)
{
    v ^= v >> 4;
    v ^= v >> 2;
    v ^= v >> 1;
    return (~v) & 1;
}

/* Set SF, ZF, PF based on result (8-bit) */
static inline void set_szp8(CPU *cpu, uint8_t result)
{
    cpu->flags &= ~(FLAG_SF | FLAG_ZF | FLAG_PF);
    if (result == 0)           cpu->flags |= FLAG_ZF;
    if (result & 0x80)         cpu->flags |= FLAG_SF;
    if (parity8(result))       cpu->flags |= FLAG_PF;
}

/* Set SF, ZF, PF based on result (16-bit) */
static inline void set_szp16(CPU *cpu, uint16_t result)
{
    cpu->flags &= ~(FLAG_SF | FLAG_ZF | FLAG_PF);
    if (result == 0)             cpu->flags |= FLAG_ZF;
    if (result & 0x8000)         cpu->flags |= FLAG_SF;
    if (parity8(result & 0xFF))  cpu->flags |= FLAG_PF;
}

/* Full flags for ADD (8-bit) */
static inline uint8_t flags_add8(CPU *cpu, uint8_t a, uint8_t b)
{
    uint16_t r = (uint16_t)a + b;
    uint8_t result = (uint8_t)r;
    cpu->flags &= ~(FLAG_CF | FLAG_OF | FLAG_AF | FLAG_SF | FLAG_ZF | FLAG_PF);
    if (r > 0xFF)                              cpu->flags |= FLAG_CF;
    if (((a ^ b ^ 0x80) & (a ^ result)) & 0x80) cpu->flags |= FLAG_OF;  /* wrong */
    /* Corrected OF: signed overflow when both operands same sign but result differs */
    cpu->flags &= ~FLAG_OF;
    if (((~(a ^ b)) & (a ^ result)) & 0x80)   cpu->flags |= FLAG_OF;
    if ((a ^ b ^ result) & 0x10)               cpu->flags |= FLAG_AF;
    set_szp8(cpu, result);
    return result;
}

/* Full flags for ADD (16-bit) */
static inline uint16_t flags_add16(CPU *cpu, uint16_t a, uint16_t b)
{
    uint32_t r = (uint32_t)a + b;
    uint16_t result = (uint16_t)r;
    cpu->flags &= ~(FLAG_CF | FLAG_OF | FLAG_AF | FLAG_SF | FLAG_ZF | FLAG_PF);
    if (r > 0xFFFF)                                cpu->flags |= FLAG_CF;
    if (((~(a ^ b)) & (a ^ result)) & 0x8000)     cpu->flags |= FLAG_OF;
    if ((a ^ b ^ result) & 0x10)                   cpu->flags |= FLAG_AF;
    set_szp16(cpu, result);
    return result;
}

/* Full flags for SUB (8-bit) */
static inline uint8_t flags_sub8(CPU *cpu, uint8_t a, uint8_t b)
{
    uint16_t r = (uint16_t)a - b;
    uint8_t result = (uint8_t)r;
    cpu->flags &= ~(FLAG_CF | FLAG_OF | FLAG_AF | FLAG_SF | FLAG_ZF | FLAG_PF);
    if (a < b)                                     cpu->flags |= FLAG_CF;
    if (((a ^ b) & (a ^ result)) & 0x80)           cpu->flags |= FLAG_OF;
    if ((a ^ b ^ result) & 0x10)                   cpu->flags |= FLAG_AF;
    set_szp8(cpu, result);
    return result;
}

/* Full flags for SUB (16-bit) */
static inline uint16_t flags_sub16(CPU *cpu, uint16_t a, uint16_t b)
{
    uint32_t r = (uint32_t)a - b;
    uint16_t result = (uint16_t)r;
    cpu->flags &= ~(FLAG_CF | FLAG_OF | FLAG_AF | FLAG_SF | FLAG_ZF | FLAG_PF);
    if (a < b)                                       cpu->flags |= FLAG_CF;
    if (((a ^ b) & (a ^ result)) & 0x8000)           cpu->flags |= FLAG_OF;
    if ((a ^ b ^ result) & 0x10)                     cpu->flags |= FLAG_AF;
    set_szp16(cpu, result);
    return result;
}

/* Flags-only CMP (doesn't store result) */
static inline void flags_cmp8(CPU *cpu, uint8_t a, uint8_t b)
{
    flags_sub8(cpu, a, b);
}

static inline void flags_cmp16(CPU *cpu, uint16_t a, uint16_t b)
{
    flags_sub16(cpu, a, b);
}

/* Logical operation flags (CF=0, OF=0) */
static inline void flags_logic8(CPU *cpu, uint8_t result)
{
    cpu->flags &= ~(FLAG_CF | FLAG_OF);
    set_szp8(cpu, result);
}

static inline void flags_logic16(CPU *cpu, uint16_t result)
{
    cpu->flags &= ~(FLAG_CF | FLAG_OF);
    set_szp16(cpu, result);
}

/* Shift/rotate flags (partial - CF set by caller) */
static inline void flags_shift8(CPU *cpu, uint8_t result)
{
    set_szp8(cpu, result);
}

static inline void flags_shift16(CPU *cpu, uint16_t result)
{
    set_szp16(cpu, result);
}

/* ---------- 32-bit arithmetic from 16-bit code ----------
 *
 * A 386 running a 16-bit segment does 32-bit arithmetic with an operand-size
 * prefix, and 16-bit code that handles far pointers, file offsets or 32-bit
 * fields does it often. Same rules as the 16-bit forms with the sign bit and
 * the carry boundary moved: SF is bit 31, and CF for ADD is the carry out of
 * bit 31, which needs a 64-bit intermediate to see.
 *
 * SZP is set from the 32-bit result, and PF - as on real hardware - is the
 * parity of the LOW BYTE only, not of the whole result. */
static inline void set_szp32(CPU *cpu, uint32_t v)
{
    cpu->flags &= ~(FLAG_SF | FLAG_ZF | FLAG_PF);
    if (v & 0x80000000u) cpu->flags |= FLAG_SF;
    if (v == 0)          cpu->flags |= FLAG_ZF;
    uint8_t low = (uint8_t)v;
    low ^= (uint8_t)(low >> 4);
    low ^= (uint8_t)(low >> 2);
    low ^= (uint8_t)(low >> 1);
    if (!(low & 1)) cpu->flags |= FLAG_PF;
}

static inline uint32_t flags_add32(CPU *cpu, uint32_t a, uint32_t b)
{
    uint64_t r = (uint64_t)a + b;
    uint32_t result = (uint32_t)r;
    cpu->flags &= ~(FLAG_CF | FLAG_OF | FLAG_AF | FLAG_SF | FLAG_ZF | FLAG_PF);
    if (r > 0xFFFFFFFFu)                                cpu->flags |= FLAG_CF;
    if (((~(a ^ b)) & (a ^ result)) & 0x80000000u)      cpu->flags |= FLAG_OF;
    if ((a ^ b ^ result) & 0x10)                        cpu->flags |= FLAG_AF;
    set_szp32(cpu, result);
    return result;
}

static inline uint32_t flags_sub32(CPU *cpu, uint32_t a, uint32_t b)
{
    uint32_t result = a - b;
    cpu->flags &= ~(FLAG_CF | FLAG_OF | FLAG_AF | FLAG_SF | FLAG_ZF | FLAG_PF);
    if (a < b)                                       cpu->flags |= FLAG_CF;
    if (((a ^ b) & (a ^ result)) & 0x80000000u)      cpu->flags |= FLAG_OF;
    if ((a ^ b ^ result) & 0x10)                     cpu->flags |= FLAG_AF;
    set_szp32(cpu, result);
    return result;
}

static inline void flags_cmp32(CPU *cpu, uint32_t a, uint32_t b)
{
    flags_sub32(cpu, a, b);
}

static inline void flags_logic32(CPU *cpu, uint32_t result)
{
    cpu->flags &= ~(FLAG_CF | FLAG_OF);
    set_szp32(cpu, result);
}

static inline void flags_shift32(CPU *cpu, uint32_t result)
{
    set_szp32(cpu, result);
}


/* ---------- Flag test helpers ---------- */
static inline int cf(CPU *cpu) { return (cpu->flags & FLAG_CF) != 0; }
static inline int zf(CPU *cpu) { return (cpu->flags & FLAG_ZF) != 0; }
static inline int sf(CPU *cpu) { return (cpu->flags & FLAG_SF) != 0; }
static inline int of(CPU *cpu) { return (cpu->flags & FLAG_OF) != 0; }
static inline int pf(CPU *cpu) { return (cpu->flags & FLAG_PF) != 0; }
static inline int af(CPU *cpu) { return (cpu->flags & FLAG_AF) != 0; }
static inline int df(CPU *cpu) { return (cpu->flags & FLAG_DF) != 0; }

/* Condition code tests (matching x86 Jcc encodings) */
static inline int cc_o(CPU *cpu)  { return of(cpu); }
static inline int cc_no(CPU *cpu) { return !of(cpu); }
static inline int cc_b(CPU *cpu)  { return cf(cpu); }         /* below / carry */
static inline int cc_ae(CPU *cpu) { return !cf(cpu); }        /* above-or-equal */
static inline int cc_e(CPU *cpu)  { return zf(cpu); }         /* equal / zero */
static inline int cc_ne(CPU *cpu) { return !zf(cpu); }        /* not equal */
static inline int cc_be(CPU *cpu) { return cf(cpu) || zf(cpu); } /* below-or-equal */
static inline int cc_a(CPU *cpu)  { return !cf(cpu) && !zf(cpu); } /* above */
static inline int cc_s(CPU *cpu)  { return sf(cpu); }         /* sign */
static inline int cc_ns(CPU *cpu) { return !sf(cpu); }        /* not sign */
static inline int cc_p(CPU *cpu)  { return pf(cpu); }         /* parity even */
static inline int cc_np(CPU *cpu) { return !pf(cpu); }        /* parity odd */
static inline int cc_l(CPU *cpu)  { return sf(cpu) != of(cpu); } /* less */
static inline int cc_ge(CPU *cpu) { return sf(cpu) == of(cpu); } /* greater-or-equal */
static inline int cc_le(CPU *cpu) { return zf(cpu) || (sf(cpu) != of(cpu)); } /* less-or-equal */
static inline int cc_g(CPU *cpu)  { return !zf(cpu) && (sf(cpu) == of(cpu)); } /* greater */

/* ---------- CPU lifecycle ---------- */

/* Initialize CPU state */
static inline void cpu_init(CPU *cpu)
{
    memset(cpu, 0, sizeof(*cpu));
    cpu->mem = NULL;
    cpu->flags = 0x0002; /* bit 1 always set on 8086 */
}

/* Allocate flat memory */
int cpu_alloc_mem(CPU *cpu);

/* Free CPU resources */
void cpu_free(CPU *cpu);

/* Load binary into memory at segment:offset */
int cpu_load(CPU *cpu, const char *path, uint16_t seg, uint16_t off);

#endif /* CIV_RECOMP_CPU_H */

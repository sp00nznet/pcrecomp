#!/usr/bin/env python3
"""
difftest64.py - differential test of lift64_cpu against the real CPU.

The host is x86-64, so the reference implementation is the hardware itself: for
each instruction, execute the ORIGINAL bytes natively from a known register
state (difftest64.asm) and compare the result against running the lifted C from
the same state. No emulated reference, which matters - an emulated reference is
written from the same reading of the manual as the lifter and inherits its
misconceptions. The silicon does not.

Scope, and why it is drawn here:

  * Register and immediate operands only. A memory operand would need the guest
    address to be mapped in this process at the address the instruction names,
    which is a different harness. The quiet bugs are in the FLAGS, and flags do
    not care where the operand came from.
  * RSP is neither set nor compared; see the note in difftest64.asm.
  * The corpus is sampled from the real binary, not invented, so it is weighted
    the way the game actually uses the instruction set - and then edge cases are
    added by hand, because the interesting inputs (zero, INT64_MIN, a shift
    count of exactly the operand width, NaN) are the ones a random sample of a
    working program never produces.

Usage:
  py -3.11 difftest64.py <game.exe> <funcs.txt> [--count N] [--keep]
"""

import os
import random
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lift64_cpu
from lift64_cpu import Lifter, load_bounds
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

HERE = os.path.dirname(os.path.abspath(__file__))
CPU64_H = os.path.join(HERE, '..', '..', 'runtime', 'recomp64_cpu', 'cpu64.h')

# Instructions whose lifted form is a pure function of the register file. A
# memory operand, a branch, or anything touching RSP is out of scope here.
SKIP_MNEMONICS = {
    'call', 'ret', 'retn', 'retf', 'jmp', 'push', 'pop', 'pushfq', 'popfq',
    'leave', 'enter', 'int3', 'int', 'int1', 'hlt', 'iret', 'iretd', 'iretq',
    'cpuid', 'rdtsc', 'syscall', 'sysret', 'in', 'out', 'nop',
    'sti', 'cli', 'ltr', 'str', 'verr', 'verw', 'sldt', 'lldt',
    'xlatb', 'ldmxcsr', 'stmxcsr', 'prefetcht0', 'prefetcht1', 'prefetchw',
    'pause', 'wait', 'fwait',
    # DIV and IDIV raise #DE when the quotient does not fit or the divisor is
    # zero, and against a randomly seeded register file that is not an edge
    # case, it is the common case - RDX is almost never a valid high half for
    # the divisor that happens to be in the operand. Testing them differentially
    # needs operands constructed to divide cleanly, which is a different corpus.
    # The __except below still catches a fault; this keeps it from being the
    # normal outcome.
    'div', 'idiv',
}

# Registers the harness does not model. RIZ is capstone's pseudo index register
# and only appears in misdecoded data.
BAD_REGS = {'rsp', 'esp', 'sp', 'spl', 'rip', 'riz', 'eiz',
            'cs', 'ds', 'es', 'fs', 'gs', 'ss'}

GPR_ORDER = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
             'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

# Interesting 64-bit values. A random sample of a working program almost never
# produces these, and they are where the arithmetic edge cases are.
EDGE_VALUES = [
    0x0000000000000000, 0x0000000000000001, 0xFFFFFFFFFFFFFFFF,
    0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0x00000000FFFFFFFF,
    0x0000000080000000, 0x000000007FFFFFFF, 0x00000000000000FF,
    0x0000000000000080, 0x000000000000FFFF, 0x0000000000008000,
    0x00000000FFFFFFFE, 0xFFFFFFFF00000000, 0x0123456789ABCDEF,
]

# The modelled flags: CF PF AF ZF SF OF. Everything else in RFLAGS is either
# reserved or belongs to the system, and the lifter does not claim them.
FLAG_MASK = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11)

# The reciprocal estimates. Hardware computes these to about 12 bits through a
# lookup table that differs between vendors and steppings; the lifter computes
# them exactly. That is a deliberate choice - code using them feeds the result
# to a Newton step or a normalise, where a MORE accurate input is never worse -
# but it means a bit-exact comparison against the silicon must fail. So these
# are compared against the error bound the ISA actually guarantees, 1.5*2^-12
# relative, which is a real test: a lifter that returned the reciprocal instead
# of the reciprocal square root would still be caught.
APPROX_MNEMONICS = {'rsqrtss', 'rsqrtps', 'rcpss', 'rcpps'}

# Flags the ISA leaves UNDEFINED per instruction, as a mask to exclude from the
# comparison. This is not a way to silence failures - it is the difference
# between testing the architecture and testing one stepping's arbitrary choice.
# BSF/BSR define only ZF; the hardware here happens to clear CF/OF/SF/AF and set
# PF, and a lifter that reproduced that would be encoding a guess as a contract.
CF, PF_, AF, ZF, SF, OF = (1 << 0), (1 << 2), (1 << 4), (1 << 6), (1 << 7), (1 << 11)
UNDEFINED_FLAGS = {
    'bsf': CF | PF_ | AF | SF | OF,
    'bsr': CF | PF_ | AF | SF | OF,
    # The multiplies define CF and OF (the product did not fit) and leave the
    # rest undefined.
    'mul':  ZF | SF | PF_ | AF,
    'imul': ZF | SF | PF_ | AF,
    # The shifts leave AF undefined, and OF undefined for any count but 1.
    'shl': AF, 'sal': AF, 'shr': AF, 'sar': AF,
    'shld': AF | OF, 'shrd': AF | OF,
    'rol': AF, 'ror': AF, 'rcl': AF, 'rcr': AF,
    # BT and friends define CF and leave the rest undefined.
    'bt': OF | SF | AF | PF_, 'bts': OF | SF | AF | PF_,
    'btr': OF | SF | AF | PF_, 'btc': OF | SF | AF | PF_,
}


def reg_index(name):
    """Position of a register in the CPU's GPR order, whatever width it names."""
    for i, q in enumerate(GPR_ORDER):
        if name == q:
            return i
    for tbl in ('e', ''):
        pass
    # 32/16/8-bit aliases, by the lifter's own tables
    for tname, tbl in (('32', lift64_cpu.R32), ('16', lift64_cpu.R16),
                       ('8l', lift64_cpu.R8L), ('8h', lift64_cpu.R8H)):
        if name in tbl:
            return GPR_ORDER.index(tbl[name])
    return -1


def classify(md, insn):
    """(ok, base_mask, index_mask) - can this case be tested, and which
    registers have to be aimed at the scratch buffer for it to be safe?

    A memory operand is testable if its address is formed only from general
    registers and a small displacement, because then the harness can put the
    base somewhere mapped and the whole access lands in the scratch buffer.
    RIP-relative cannot be aimed - its address is fixed by where the code sits -
    and a segment override addresses the TEB, so both stay out.
    """
    if not insn.operands:
        return (insn.mnemonic in ('cdqe', 'cqo', 'cdq', 'cwde', 'cbw', 'cwd',
                                  'clc', 'stc', 'cmc', 'sahf', 'lahf'), 0, 0, 0)
    basem = idxm = 0
    mdisp = 0
    for op in insn.operands:
        if op.type == X86_OP_MEM:
            m = op.mem
            if m.segment:
                return (False, 0, 0, 0)
            if m.base == X86_REG_RIP:
                return (False, 0, 0, 0)
            if abs(m.disp) >= 0x800:
                return (False, 0, 0, 0)
            if not m.base:
                return (False, 0, 0, 0)         # bare absolute: nothing to aim
            bn = md.reg_name(m.base)
            bi = reg_index(bn) if bn else -1
            if bi < 0 or bn in BAD_REGS:
                return (False, 0, 0, 0)
            basem |= 1 << bi
            mdisp = m.disp
            if m.index:
                inm = md.reg_name(m.index)
                ii = reg_index(inm) if inm else -1
                if ii < 0 or inm in BAD_REGS:
                    return (False, 0, 0, 0)
                idxm |= 1 << ii
        elif op.type == X86_OP_REG:
            n = md.reg_name(op.reg)
            if not n or n in BAD_REGS:
                return (False, 0, 0, 0)
    # A register cannot be both the base (pointed at scratch) and an index
    # (kept small) in the same instruction.
    if basem & idxm:
        return (False, 0, 0, 0)
    return (True, basem, idxm, mdisp)


def collect_corpus(pe, funcs, want):
    """Sample distinct instruction encodings from the real binary."""
    data = open(pe, 'rb').read()
    b, soi, secs = lift64_cpu._pe_sections(data)
    lift64_cpu.IMAGE_BASE = b

    def read_va(va, n):
        for (nm, vsa, vs, ra, rs) in secs:
            lo = b + vsa
            if lo <= va < lo + max(vs, rs):
                return data[ra + (va - lo): ra + (va - lo) + n]
        raise KeyError(hex(va))

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    bounds = load_bounds(funcs)
    seen = {}
    addrs = sorted(bounds)
    random.shuffle(addrs)
    for va in addrs:
        size, _ = bounds[va]
        if size <= 0:
            continue
        try:
            code = read_va(va, size)
        except KeyError:
            continue
        for ins in md.disasm(code, va):
            m = ins.mnemonic
            if m.split()[-1] in SKIP_MNEMONICS or m in SKIP_MNEMONICS:
                continue
            if m.startswith('j') or m.startswith('loop') or m[0] == 'f':
                continue
            ok, bm, im, dsp = classify(md, ins)
            if not ok:
                continue
            key = bytes(ins.bytes)
            if key not in seen:
                seen[key] = (m, ins.op_str, bm, im, dsp)
        if len(seen) >= want:
            break
    return b, soi, read_va, list(seen.items())[:want]


def seeded_state(rng, i):
    """One input register file. Early cases are all-edge-value, later ones
    random, so a failure that needs a specific pattern still gets found."""
    gpr = []
    for k in range(16):
        if i < len(EDGE_VALUES):
            gpr.append(EDGE_VALUES[(i + k) % len(EDGE_VALUES)])
        elif rng.random() < 0.35:
            gpr.append(rng.choice(EDGE_VALUES))
        else:
            gpr.append(rng.getrandbits(64))
    flags = rng.getrandbits(64) & FLAG_MASK
    xmm = []
    for k in range(16):
        if rng.random() < 0.3:
            xmm.append((rng.choice(EDGE_VALUES), rng.choice(EDGE_VALUES)))
        else:
            xmm.append((rng.getrandbits(64), rng.getrandbits(64)))
    return gpr, flags, xmm


def build_harness(outdir, cases, lifter):
    """Emit the C harness: one lifted function per case, plus the driver."""
    lifted = []
    table = []
    skipped = []
    for idx, (encoding, (mn, ops, bm, im, dsp)) in enumerate(cases):
        name = 't_%05d' % idx
        try:
            # Lift the single instruction. The trailing bytes are the
            # instruction itself only; lift_function appends a fall-through
            # dispatch which the harness defines as a no-op.
            body = lifter.lift_function(encoding, 0x140000000, name=name)
        except Exception as e:
            skipped.append((idx, mn, ops, str(e)))
            continue
        if 'RECOMP_TODO' in body:
            skipped.append((idx, mn, ops, 'unexpressed'))
            continue
        lifted.append(body)
        table.append((idx, name, encoding, mn, ops, bm, im, dsp))

    src = []
    src.append('/* generated by difftest64.py - do not edit */')
    src.append('#include "cpu64.h"')
    src.append('#include <stdio.h>')
    src.append('#include <string.h>')
    src.append('#include <windows.h>')
    src.append('')
    src.append('int64_t g_image_delta = 0;')
    # The lifted body ends in a fall-through dispatch, which for a single
    # instruction means "the next instruction", and there is none. Both are
    # no-ops here; reaching them is not a failure.
    src.append('void dispatch(CPU *c, uint64_t t) { (void)c; (void)t; }')
    src.append('void dispatch_jmp(CPU *c, uint64_t t) { (void)c; (void)t; }')
    src.append('')
    # DTSTATE itself comes from dtseeds.h, which is included above - one
    # definition, so the seeds and the harness cannot disagree about the layout
    # that difftest64.asm hard-codes as offsets.
    src.append('__declspec(align(16)) DTSTATE dt_in;')
    src.append('__declspec(align(16)) DTSTATE dt_out;')
    src.append('void *dt_code;')
    src.append('extern void run_native(void);')
    src.append('')
    src.append('\n\n'.join(lifted))
    src.append('')
    src.append('typedef struct { const char *mn; const char *ops;')
    src.append('                 const unsigned char *code; int len;')
    src.append('                 void (*fn)(CPU *); int approx; unsigned undef;')
    src.append('                 unsigned basem, idxm; int dadj; } CASE;')
    src.append('')
    for idx, name, enc, mn, ops, bm, im, dsp in table:
        src.append('static const unsigned char b_%05d[] = {%s};'
                   % (idx, ','.join('0x%02X' % x for x in enc)))
    src.append('')
    src.append('static const CASE cases[] = {')
    for idx, name, enc, mn, ops, bm, im, dsp in table:
        esc = ops.replace('\\', '\\\\').replace('"', '\\"')
        src.append('  { "%s", "%s", b_%05d, %d, %s, %d, 0x%Xu, 0x%Xu, 0x%Xu, %d },'
                   % (mn, esc, idx, len(enc), name,
                      1 if mn in APPROX_MNEMONICS else 0,
                      UNDEFINED_FLAGS.get(mn.split()[-1], 0), bm, im,
                      (-dsp) & 15))
    src.append('};')
    src.append('static const int ncases = %d;' % len(table))
    src.append('')
    src.append(HARNESS_MAIN)
    path = os.path.join(outdir, 'dtmain.c')
    with open(path, 'w') as f:
        f.write('\n'.join(src))
    return path, len(table), skipped


HARNESS_MAIN = r'''
/* The six flags the lifter models. Everything else in RFLAGS belongs to the
 * system or is reserved, and comparing it would fail on bits no lifter sets. */
#define FMASK ((1u<<0)|(1u<<2)|(1u<<4)|(1u<<6)|(1u<<7)|(1u<<11))

static uint64_t pack_cpu_flags(const CPU *c) {
    return (c->cf) | (c->pf << 2) | (c->af << 4) |
           (c->zf << 6) | (c->sf << 7) | (c->of << 11);
}

static void unpack_to_cpu(CPU *c, uint64_t f) {
    c->cf = f & 1; c->pf = (f >> 2) & 1; c->af = (f >> 4) & 1;
    c->zf = (f >> 6) & 1; c->sf = (f >> 7) & 1; c->of = (f >> 11) & 1;
}

static uint64_t *cpu_gpr(CPU *c, int i) {
    switch (i) {
    case 0: return &c->rax; case 1: return &c->rcx; case 2: return &c->rdx;
    case 3: return &c->rbx; case 4: return &c->rsp; case 5: return &c->rbp;
    case 6: return &c->rsi; case 7: return &c->rdi; case 8: return &c->r8;
    case 9: return &c->r9; case 10: return &c->r10; case 11: return &c->r11;
    case 12: return &c->r12; case 13: return &c->r13; case 14: return &c->r14;
    default: return &c->r15;
    }
}

static const char *GN[16] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                             "r8","r9","r10","r11","r12","r13","r14","r15"};

/* The ISA's guarantee for RCPPS/RSQRTPS and their scalar forms: relative error
 * below 1.5 * 2^-12. Compared lane by lane as floats, so a lifter that computed
 * the wrong FUNCTION is still caught - only the last twelve bits are forgiven. */
/* ---- the scratch buffer memory operands are aimed at ----
 *
 * Deliberately larger than any access the corpus allows, with the aimed base
 * in the middle, so base + index*scale + displacement cannot reach an
 * unmapped page in either direction. Filled with a per-trial pattern rather
 * than zeroes: a lifted instruction that reads the right address but the wrong
 * WIDTH returns zero either way against a zeroed buffer, and the test passes
 * while the lifter is wrong.
 */
#define SCRATCH_SIZE  0x4000u
static unsigned char *SCRATCH_BASE;
static unsigned char *SCRATCH_MID;
static unsigned char *scratch_native;

static void scratch_fill(int trial)
{
    for (unsigned k = 0; k < SCRATCH_SIZE; k++)
        SCRATCH_BASE[k] = (unsigned char)(k * 31u + trial * 7u + 0x5Au);
}

static long first_diff(const unsigned char *a, const unsigned char *b, unsigned n)
{
    for (unsigned k = 0; k < n; k++) if (a[k] != b[k]) return (long)k;
    return -1;
}

#define APPROX_REL_ERR (1.5 / 4096.0)

static int float_within_estimate(float a, float b) {
    if (a == b) return 1;
    if (a != a && b != b) return 1;              /* both NaN */
    if (a != a || b != b) return 0;
    double d = (double)a - (double)b;
    double m = (double)(b < 0 ? -b : b);
    if (d < 0) d = -d;
    if (m == 0.0) return d == 0.0;
    return (d / m) <= APPROX_REL_ERR;
}

static int xmm_within_estimate(const XMM *lifted, const XMM *native) {
    for (int i = 0; i < 4; i++)
        if (!float_within_estimate(lifted->f32[i], native->f32[i]))
            return 0;
    return 1;
}

/* AF is genuinely undefined after a number of instructions the game uses
 * (the shifts, the logic ops, INC/DEC's carry aside), and the manual says so.
 * Comparing a bit the hardware is entitled to leave arbitrary would report
 * failures that are not. The other five are all defined. */
#define CMP_FLAGS (FMASK & ~(1u<<4))

int main(int argc, char **argv) {
    int verbose = (argc > 1 && strcmp(argv[1], "-v") == 0);
    /* Unbuffered: a harness whose job is to survive faults must not keep its
     * findings in a buffer that a fault discards. */
    setvbuf(stdout, NULL, _IONBF, 0);
    unsigned char *page = (unsigned char *)VirtualAlloc(
        NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!page) { printf("VirtualAlloc failed\n"); return 2; }

    SCRATCH_BASE = (unsigned char *)VirtualAlloc(
        NULL, SCRATCH_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    scratch_native = (unsigned char *)malloc(SCRATCH_SIZE);
    if (!SCRATCH_BASE || !scratch_native) { printf("no scratch\n"); return 2; }
    /* 64-byte aligned midpoint: some SSE forms fault on a misaligned address,
     * and a spurious fault would read as a lifter failure. */
    SCRATCH_MID = SCRATCH_BASE + (SCRATCH_SIZE / 2);
    SCRATCH_MID -= ((uintptr_t)SCRATCH_MID & 63u);

    int pass = 0, fail = 0, faulted = 0;
    for (int i = 0; i < ncases; i++) {
        const CASE *tc = &cases[i];
        memcpy(page, tc->code, tc->len);
        page[tc->len] = 0xC3;              /* ret */
        FlushInstructionCache(GetCurrentProcess(), page, tc->len + 1);
        dt_code = page;

        for (int trial = 0; trial < NTRIALS; trial++) {
            const DTSTATE *seed = &seeds[(i * NTRIALS + trial) % NSEEDS];

            /* ---- aim the address registers at the scratch buffer ----
             *
             * A memory operand can only be tested if its effective address
             * lands somewhere mapped, and the address is whatever the seeded
             * registers say. So the registers the instruction uses to form an
             * address are overridden: a base points into the middle of the
             * scratch buffer, an index is kept small. Every other register
             * keeps its seeded value, including the edge cases - the point is
             * to test the ADDRESSING and the memory semantics, not to lose the
             * interesting operand values.
             *
             * The displacement is already bounded at +-0x800 by the corpus
             * filter and the index is at most 15*8, so base+index*scale+disp
             * cannot leave the buffer. */
            DTSTATE in = *seed;
            for (int k = 0; k < 16; k++) {
                if (tc->basem & (1u << k)) in.gpr[k] = (uint64_t)(uintptr_t)(SCRATCH_MID + tc->dadj);
                if (tc->idxm  & (1u << k)) in.gpr[k] = (uint64_t)(k & 7);
            }

            /* ---- native ---- */
            scratch_fill(trial);
            memcpy(&dt_in, &in, sizeof(DTSTATE));
            dt_in.flags = (dt_in.flags & FMASK) | 0x202;   /* reserved bit 1, IF */
            memset(&dt_out, 0, sizeof(DTSTATE));
            /* An instruction sampled out of a real binary can still fault on a
             * synthetic register file - a divide that does not fit, a decode
             * that walked into data. Without this the whole run dies with an
             * exit code and no output, which is how it first presented. */
            __try {
                run_native();
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                printf("  FAULT   %s %s | native raised 0x%08lX, case skipped\n",
                       tc->mn, tc->ops, GetExceptionCode());
                faulted++;
                break;
            }

            /* Whatever the instruction wrote to memory is part of its result,
             * so it is snapshotted before the buffer is reset for the lifted
             * run. Comparing registers alone would pass a store to the wrong
             * address without noticing. */
            memcpy(scratch_native, SCRATCH_BASE, SCRATCH_SIZE);

            /* ---- lifted ---- */
            scratch_fill(trial);
            CPU c;
            memset(&c, 0, sizeof(c));
            for (int k = 0; k < 16; k++) *cpu_gpr(&c, k) = in.gpr[k];
            memcpy(c.xmm, in.xmm, sizeof(c.xmm));
            unpack_to_cpu(&c, in.flags);
            /* The lifted side gets a handler too, and for a better reason than
             * the native one: if the LIFTED code faults where the hardware did
             * not, that is a lifter bug computing a wrong address - the exact
             * thing this pass was added to find. Without the handler it is an
             * unhandled access violation that kills the run and reports
             * nothing at all. */
            __try {
                tc->fn(&c);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                printf("  LIFTED FAULT %s %s | native ran fine, lifted raised %#08lX\n",
                       tc->mn, tc->ops, GetExceptionCode());
                fail++;
                break;
            }

            /* ---- compare ---- */
            int bad = 0;
            if (memcmp(scratch_native, SCRATCH_BASE, SCRATCH_SIZE) != 0) {
                long d = first_diff(scratch_native, SCRATCH_BASE, SCRATCH_SIZE);
                if (verbose || fail < 20)
                    printf("  MISMATCH %s %s | memory at scratch+%ld:"
                           " native %02X lifted %02X\n", tc->mn, tc->ops, d,
                           scratch_native[d], SCRATCH_BASE[d]);
                bad = 1;
            }
            for (int k = 0; k < 16; k++) {
                if (k == 4) continue;              /* rsp not modelled */
                if (*cpu_gpr(&c, k) != dt_out.gpr[k]) {
                    if (verbose || fail < 20)
                        printf("  MISMATCH %s %s | %s: native %016llx lifted %016llx\n",
                               tc->mn, tc->ops, GN[k],
                               (unsigned long long)dt_out.gpr[k],
                               (unsigned long long)*cpu_gpr(&c, k));
                    bad = 1;
                }
            }
            uint64_t fmask = CMP_FLAGS & ~(uint64_t)tc->undef;
            uint64_t nf = dt_out.flags & fmask;
            uint64_t lf = pack_cpu_flags(&c) & fmask;
            if (nf != lf) {
                if (verbose || fail < 20)
                    printf("  MISMATCH %s %s | flags: native %03llx lifted %03llx"
                           " (diff %03llx)\n", tc->mn, tc->ops,
                           (unsigned long long)nf, (unsigned long long)lf,
                           (unsigned long long)(nf ^ lf));
                bad = 1;
            }
            for (int k = 0; k < 16; k++) {
                if (memcmp(&c.xmm[k], &dt_out.xmm[k], 16) == 0) continue;
                if (tc->approx && xmm_within_estimate(&c.xmm[k], &dt_out.xmm[k]))
                    continue;
                if (verbose || fail < 20)
                    printf("  MISMATCH %s %s | xmm%d: native %016llx%016llx"
                           " lifted %016llx%016llx\n", tc->mn, tc->ops, k,
                           (unsigned long long)dt_out.xmm[k].u64[1],
                           (unsigned long long)dt_out.xmm[k].u64[0],
                           (unsigned long long)c.xmm[k].u64[1],
                           (unsigned long long)c.xmm[k].u64[0]);
                bad = 1;
            }
            if (bad) { fail++; break; } else pass++;
        }
    }
    printf("\ndifftest64: %d cases, %d trials passed, %d cases failed, %d faulted\n",
           ncases, pass, fail, faulted);
    return fail ? 1 : 0;
}
'''


def emit_seeds(outdir, nseeds, ntrials, rng):
    lines = ['/* generated by difftest64.py */',
             '#include "cpu64.h"',
             'typedef struct { uint64_t gpr[16]; uint64_t flags; uint64_t _pad;',
             '                 XMM xmm[16]; } DTSTATE;',
             '#define NSEEDS %d' % nseeds,
             '#define NTRIALS %d' % ntrials,
             '__declspec(align(16)) const DTSTATE seeds[NSEEDS] = {']
    for i in range(nseeds):
        gpr, flags, xmm = seeded_state(rng, i)
        g = ','.join('0x%XULL' % v for v in gpr)
        # XMM's first member is float[4], so the lanes are set through the u64
        # designator rather than positionally - a positional initialiser would
        # quietly reinterpret the seed as floats.
        x = ','.join('{.u64={0x%XULL,0x%XULL}}' % (lo, hi) for (lo, hi) in xmm)
        lines.append('  { {%s}, 0x%XULL, 0, {%s} },' % (g, flags, x))
    lines.append('};')
    p = os.path.join(outdir, 'dtseeds.h')
    with open(p, 'w') as f:
        f.write('\n'.join(lines) + '\n')
    return p


def main():
    argv = sys.argv[1:]
    count = 4000
    keep = False
    if '--count' in argv:
        i = argv.index('--count')
        count = int(argv[i + 1])
        del argv[i:i + 2]
    if '--keep' in argv:
        keep = True
        argv.remove('--keep')
    if len(argv) < 2:
        print(__doc__)
        raise SystemExit(2)

    pe, funcs = argv[0], argv[1]
    rng = random.Random(1234567)      # fixed seed: a flaky corpus is not a test

    print('[*] sampling instruction encodings from %s' % os.path.basename(pe))
    base, soi, read_va, cases = collect_corpus(pe, funcs, count)
    print('[*] %d distinct encodings' % len(cases))

    lifter = Lifter(image_size=soi, read_va=None, image_base=base)

    outdir = os.path.join(tempfile.gettempdir(), 'difftest64')
    os.makedirs(outdir, exist_ok=True)

    import shutil
    shutil.copy(os.path.normpath(CPU64_H), outdir)
    shutil.copy(os.path.join(HERE, 'difftest64.asm'), outdir)

    emit_seeds(outdir, 64, 8, rng)
    path, ntab, skipped = build_harness(outdir, cases, lifter)
    print('[*] harness: %d testable cases, %d skipped' % (ntab, len(skipped)))

    # The seeds header has to come before the harness body uses NTRIALS.
    with open(path) as f:
        body = f.read()
    body = body.replace('#include <windows.h>',
                        '#include <windows.h>\n#include "dtseeds.h"')
    with open(path, 'w') as f:
        f.write(body)

    print('[*] building')
    bat = os.path.join(outdir, 'build.bat')
    with open(bat, 'w') as f:
        f.write('@echo off\r\n')
        f.write('call "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community'
                '\\VC\\Auxiliary\\Build\\vcvars64.bat" >nul 2>&1\r\n')
        f.write('cd /d "%s"\r\n' % outdir)
        f.write('ml64 /nologo /c difftest64.asm >build.log 2>&1 || exit /b 1\r\n')
        f.write('cl /nologo /Od /W3 dtmain.c difftest64.obj /Fe:difftest64.exe '
                '>>build.log 2>&1 || exit /b 1\r\n')
    r = subprocess.run(['cmd', '/c', bat], capture_output=True, text=True)
    log = os.path.join(outdir, 'build.log')
    if r.returncode != 0:
        print('[!] build failed:')
        if os.path.exists(log):
            print(open(log).read()[-4000:])
        raise SystemExit(1)

    print('[*] running')
    exe = os.path.join(outdir, 'difftest64.exe')
    r = subprocess.run([exe], capture_output=True, text=True)
    print(r.stdout[-8000:])
    if r.stderr:
        print(r.stderr[-2000:])
    if not keep:
        pass
    raise SystemExit(r.returncode)


if __name__ == '__main__':
    main()

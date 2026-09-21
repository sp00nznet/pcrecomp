#!/usr/bin/env python3
"""
lift64_cpu.py - mechanical x86-64 -> C static recompiler, CPU-struct model.

The 64-bit sibling of lift32_cpu.py. Emits `void L_<addr>(CPU *c)` against
runtime/recomp64_cpu/cpu64.h, one C statement per instruction, with calls and
returns modelled on the emulated stack exactly as the hardware does them.

Why this is a separate module and not a mode flag on lift32_cpu
---------------------------------------------------------------
Three differences run through every operand, so a flag would have to be
consulted in every method and a missed one fails silently:

  1. A 32-bit register write ZERO-EXTENDS to 64 bits. `mov eax, 1` clears
     RAX's high half; `mov ax, 1` does not clear anything above bit 15. This is
     the most common instruction in a 64-bit binary (1.3M of 3.6M measured on
     Star Wars Battle Pods), so it is not an edge case to bolt on. Miss it and
     a stale high half folds into the next address computation, giving a
     pointer wrong by some multiple of 4 GB - an access violation a long way
     from the instruction that caused it.
  2. RIP-relative addressing. x86-64 reaches its own globals as a signed
     displacement from the NEXT instruction, so an address is not in the
     instruction at all; it has to be reconstructed. 202,114 operands in the
     measured binary. lift32 has no notion of it.
  3. Sixteen GPRs and sixteen XMM registers, with new 8-bit encodings
     (spl/bpl/sil/dil) that alias what are AH/CH/DH/BH without a REX prefix.

Shared with lift32_cpu, by import rather than by copy: the SSE tables, the
string-op set and the TODO formatter. The SSE *semantics* are identical between
modes and having two copies drift apart is the failure this avoids.

What is deliberately not translated
-----------------------------------
x87 and MMX. The Win64 ABI puts every float in XMM; a shipping UE3 build
measures 421 x87 and 4 MMX instructions in 3.6M, essentially all inside data
that the disassembler walked into. These emit RECOMP_TODO, which names the
address and mnemonic, rather than a plausible-looking wrong answer.

Usage:
  py -3.11 lift64_cpu.py <pe-file> <funcs.txt> <out.c> [0xADDR ...]

funcs.txt lines: "0xADDR  size  name" (an IDA/Ghidra export).
"""
import sys
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import (
    X86_OP_REG, X86_OP_IMM, X86_OP_MEM, X86_REG_RIP,
)

# One source of truth for the SSE semantics and the TODO shape. These tables are
# mode-independent: a `mulss` means the same thing in both.
from lift32_cpu import (
    SSE_ARITH, SSE_BITWISE, SSE_CMP_PRED, SSE_CMP_RE, SSE_MOV128,
    SSE_AMBIGUOUS, SSE_MNEMONICS, STRING_OPS, REP_PREFIXES, _todo,
)

IMAGE_BASE = 0x140000000     # overridden from the PE's ImageBase in main()

# The string operations, plus the quadword forms that only exist in long mode.
#
# STRING_OPS comes from lift32_cpu and stops at the doubleword, because a
# 32-bit target has no MOVSQ. Inheriting that set unchanged left movsq, stosq,
# lodsq, scasq and cmpsq falling through to a RECOMP_TODO - and `rep movsq` is
# how a 64-bit compiler inlines a structure copy, so the gap sits directly in
# the path of anything that copies memory. It aborted Battle Pods inside the
# package loader the moment the packages actually started loading.
STRING_OPS64 = STRING_OPS | frozenset((
    'movsq', 'stosq', 'lodsq', 'scasq', 'cmpsq',
))


# ---- register tables -------------------------------------------------------
#
# Built rather than written out: sixteen registers times five widths is eighty
# names, and a hand-written table of eighty is a table with a typo in it.

_LOW8 = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di']

R64 = {}        # name -> itself
R32 = {}        # name -> 64-bit parent
R16 = {}
R8L = {}
R8H = {'ah': 'rax', 'ch': 'rcx', 'dh': 'rdx', 'bh': 'rbx'}

for _i, _n in enumerate(_LOW8):
    _q = 'r' + _n                      # rax rcx rdx rbx rsp rbp rsi rdi
    R64[_q] = _q
    R32['e' + _n] = _q                 # eax ...
    R16[_n] = _q                       # ax ...
    # al/cl/dl/bl for the first four; spl/bpl/sil/dil for the rest. The latter
    # are REX-only encodings that occupy the slots AH/CH/DH/BH use without REX.
    R8L[('a', 'c', 'd', 'b')[_i] + 'l' if _i < 4 else _n + 'l'] = _q

for _i in range(8, 16):
    _q = 'r%d' % _i
    R64[_q] = _q
    R32[_q + 'd'] = _q
    R16[_q + 'w'] = _q
    R8L[_q + 'b'] = _q

# Segment registers. In long mode only GS has a base that addresses anything
# (the TEB); the rest are stored for completeness and take no part in an
# address. Anything that actually reads one is caught as a TODO rather than
# lifted into a flat access that is quietly wrong.
SEG = {'cs', 'ds', 'es', 'fs', 'gs', 'ss'}

ALL_REGS = {}
for _t, _w in ((R64, 8), (R32, 4), (R16, 2), (R8L, 1), (R8H, 1)):
    for _k in _t:
        ALL_REGS[_k] = _w


def reg_parent(name):
    for t in (R64, R32, R16, R8L, R8H):
        if name in t:
            return t[name]
    return None


def reg_read(name):
    """The C expression for a register's current value, at its own width."""
    if name in R64:
        return 'c->%s' % name
    if name in R32:
        return 'R32(c->%s)' % R32[name]
    if name in R16:
        return 'R16(c->%s)' % R16[name]
    if name in R8L:
        return 'R8L(c->%s)' % R8L[name]
    if name in R8H:
        return 'R8H(c->%s)' % R8H[name]
    raise NotImplementedError('reg_read %s' % name)


def reg_write(name, val):
    """The C statement that writes a register.

    SET32 is the one that matters - see the header. Everything else preserves
    the bits above its own width, exactly as the hardware does.
    """
    if name in R64:
        return 'SET64(c->%s, %s);' % (name, val)
    if name in R32:
        return 'SET32(c->%s, %s);' % (R32[name], val)      # zero-extends
    if name in R16:
        return 'SET16(c->%s, %s);' % (R16[name], val)
    if name in R8L:
        return 'SET8L(c->%s, %s);' % (R8L[name], val)
    if name in R8H:
        return 'SET8H(c->%s, %s);' % (R8H[name], val)
    raise NotImplementedError('reg_write %s' % name)


def reg_size(name):
    return ALL_REGS.get(name, 8)


# Packed SSE. lift32_cpu deliberately omits these - on a 32-bit target they are
# rare enough that a TODO beats a guess. On x86-64 they are not rare: the
# measured binary has 10,086 mulps, 9,986 shufps and 6,632 addps, because the
# compiler vectorises the vector maths that a 32-bit build left on the x87
# stack. Omitting them here would TODO out most of the engine's transform code.
PACKED_ARITH = {
    'addps': ('+', 'f32', 4), 'subps': ('-', 'f32', 4),
    'mulps': ('*', 'f32', 4), 'divps': ('/', 'f32', 4),
    'addpd': ('+', 'f64', 2), 'subpd': ('-', 'f64', 2),
    'mulpd': ('*', 'f64', 2), 'divpd': ('/', 'f64', 2),
}

PACKED_MINMAX = {
    'minps': ('sse_minf', 'f32', 4), 'maxps': ('sse_maxf', 'f32', 4),
    'minpd': ('sse_mind', 'f64', 2), 'maxpd': ('sse_maxd', 'f64', 2),
}

# cmpps/cmppd write an all-ones or all-zeros mask per lane, for a branchless
# select. Capstone spells the predicate into the mnemonic, as it does for the
# scalar forms.
PACKED_CMP_RE = re.compile(r'^cmp(%s)(ps|pd)$' % '|'.join(SSE_CMP_PRED))

SSE64_EXTRA = (
    frozenset(PACKED_ARITH) | frozenset(PACKED_MINMAX)
    | frozenset({'shufps', 'shufpd', 'unpcklps', 'unpckhps',
                 'unpcklpd', 'unpckhpd', 'movhlps', 'movlhps',
                 'movmskps', 'movmskpd', 'sqrtps', 'rcpps',
                 'rsqrtps', 'rsqrtss', 'rcpss', 'cvtdq2pd',
                 'movlps', 'movhps', 'movlpd', 'movhpd',
                 'cvtsi2ssl', 'cvtsi2sdl', 'cvtsi2ssq', 'cvtsi2sdq',
                 'ldmxcsr', 'stmxcsr'})
)

# ---- packed integer ----
#
# The 32-bit lifter has none of these: a Win32 game of that era does its pixel
# and audio conversion in x87 or by hand. A Win64 build has no x87 to fall back
# on, so the compiler emits the pack/unpack/shift family freely, and UE3's
# colour and texture paths are full of it.
#
# All of them are MMX as well as SSE, with mm0-7 and half the width. _xi raises
# on an mm operand, which turns into a per-instruction TODO rather than a
# silently 128-bit translation of 64-bit code.
PUNPCK = {
    'punpcklbw':  ('u8',  8, 0), 'punpckhbw':  ('u8',  8, 8),
    'punpcklwd':  ('u16', 4, 0), 'punpckhwd':  ('u16', 4, 4),
    'punpckldq':  ('u32', 2, 0), 'punpckhdq':  ('u32', 2, 2),
    'punpcklqdq': ('u64', 1, 0), 'punpckhqdq': ('u64', 1, 1),
}

# (source field, destination field, low, high) - the saturation bounds are the
# destination type's, and packuswb is the odd one: signed source, UNSIGNED
# destination, which is what makes it the one used for colour clamping.
PACK = {
    'packsswb': ('i16', 'i8',  8, -0x80, 0x7f),
    'packssdw': ('i32', 'i16', 4, -0x8000, 0x7fff),
    'packuswb': ('i16', 'u8',  8, 0, 0xff),
}

PSHIFT = {
    'psllw': ('u16', 8, 'l'), 'psrlw': ('u16', 8, 'r'), 'psraw': ('i16', 8, 'a'),
    'pslld': ('u32', 4, 'l'), 'psrld': ('u32', 4, 'r'), 'psrad': ('i32', 4, 'a'),
    'psllq': ('u64', 2, 'l'), 'psrlq': ('u64', 2, 'r'),
}

# Lane-wise, wrapping. The unsigned C types wrap the way the hardware does, so
# the signed forms use the unsigned lane and differ only in the compare.
PLANE = {
    'paddb': ('u8', 16, '+'),  'paddw': ('u16', 8, '+'),
    'paddd': ('u32', 4, '+'),  'paddq': ('u64', 2, '+'),
    'psubb': ('u8', 16, '-'),  'psubw': ('u16', 8, '-'),
    'psubd': ('u32', 4, '-'),  'psubq': ('u64', 2, '-'),
}

# (lane, count, signed, add, low, high)
PSAT = {
    'paddsb':  ('i8', 16, 1, 1, -0x80, 0x7f),
    'paddsw':  ('i16', 8, 1, 1, -0x8000, 0x7fff),
    'psubsb':  ('i8', 16, 1, 0, -0x80, 0x7f),
    'psubsw':  ('i16', 8, 1, 0, -0x8000, 0x7fff),
    'paddusb': ('u8', 16, 0, 1, 0, 0xff),
    'paddusw': ('u16', 8, 0, 1, 0, 0xffff),
    'psubusb': ('u8', 16, 0, 0, 0, 0xff),
    'psubusw': ('u16', 8, 0, 0, 0, 0xffff),
}

# A lane compare writes all-ones or zero, not 0/1.
PCMP = {
    'pcmpeqb': ('u8', 16, '=='), 'pcmpeqw': ('u16', 8, '=='),
    'pcmpeqd': ('u32', 4, '=='), 'pcmpeqq': ('u64', 2, '=='),
    'pcmpgtb': ('i8', 16, '>'),  'pcmpgtw': ('i16', 8, '>'),
    'pcmpgtd': ('i32', 4, '>'),
}

PMINMAX = {
    'pminub': ('u8', 16, '<'),  'pmaxub': ('u8', 16, '>'),
    'pminsw': ('i16', 8, '<'),  'pmaxsw': ('i16', 8, '>'),
    'pminsb': ('i8', 16, '<'),  'pmaxsb': ('i8', 16, '>'),
    'pminuw': ('u16', 8, '<'),  'pmaxuw': ('u16', 8, '>'),
    'pminsd': ('i32', 4, '<'),  'pmaxsd': ('i32', 4, '>'),
    'pminud': ('u32', 4, '<'),  'pmaxud': ('u32', 4, '>'),
}

# (lane, count, selector width, base lane) - pshufd picks four dwords across
# the register; the lw/hw forms shuffle one half and copy the other.
PSHUF = {
    'pshufd':  ('u32', 4, 0, 4),
    'pshuflw': ('u16', 4, 0, 8),
    'pshufhw': ('u16', 4, 4, 8),
}

# The 128-bit moves lift32_cpu's SSE_MOV128 does not carry. Identical to their
# ordinary forms here: the non-temporal hint is about a cache this runtime is
# not managing, and lddqu differs from movdqu only across a cache line.
#
# movntps/movntpd/movntdq were here too until the 32-bit line added them; they
# are imported from SSE_MOV128 now rather than declared twice, which is the
# whole reason the tables are shared instead of copied.
SSE64_MOV128 = frozenset({'movntdqa', 'lddqu'})

PINTEGER_MISC = frozenset({
    'pmullw', 'pmulhw', 'pmulhuw', 'pmaddwd', 'pavgb', 'pavgw',
    'pmovmskb', 'pslldq', 'psrldq', 'pextrw', 'pinsrw', 'pshufb',
})

SSE64_MNEMONICS = (SSE_MNEMONICS | SSE64_EXTRA
                   | frozenset(PUNPCK) | frozenset(PACK) | frozenset(PSHIFT)
                   | frozenset(PLANE) | frozenset(PSAT) | frozenset(PCMP)
                   | frozenset(PMINMAX) | frozenset(PSHUF) | PINTEGER_MISC
                   | SSE64_MOV128)


class Lifter:
    def __init__(self, image_size, read_va=None, image_base=None):
        self.image_lo = IMAGE_BASE if image_base is None else image_base
        self.image_hi = self.image_lo + image_size
        self.read_va = read_va            # (va, n) -> bytes
        self.func_start = 0
        self.func_end = 0
        self.jumptables = {}
        self.lea_targets = set()          # rip-relative addresses taken by lea
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True

    # ---- helpers ----------------------------------------------------------
    def in_image(self, a):
        return self.image_lo <= a < self.image_hi

    def rname(self, reg):
        return self.md.reg_name(reg)

    def areg(self, name):
        """A register used to form an address.

        Always read at full width. An address register in long mode is the
        64-bit one even when the instruction names its 32-bit half - except
        under a 0x67 address-size prefix, where the EA really is computed in 32
        bits and then zero-extended. Capstone reports the half it was given, so
        honour that: R32() on a 32-bit name reproduces the truncation.
        """
        if name in R64:
            return 'c->%s' % name
        return reg_read(name)

    def addr_expr(self, insn, op):
        """The effective address of a memory operand.

        RIP-relative is the case that does not exist in 32-bit code and is
        202k operands here. The displacement is relative to the END of the
        instruction, which is why this needs `insn` and not just `op`: getting
        the anchor wrong by the instruction's own length yields an address that
        is plausible, in-image, and points at the wrong global.
        """
        m = op.mem
        if m.base == X86_REG_RIP:
            target = (insn.address + insn.size + m.disp) & 0xFFFFFFFFFFFFFFFF
            return 'GVA(0x%X)' % target

        terms = []
        if m.base:
            terms.append(self.areg(self.rname(m.base)))
        if m.index:
            terms.append('%s*%d' % (self.areg(self.rname(m.index)), m.scale))
        d = m.disp
        if d or not terms:
            # A bare absolute displacement in long mode is either a real
            # absolute address (rare - it needs a 64-bit moffs form or a
            # 32-bit displacement that happens to be in range) or a small
            # constant offset from a base register. Only the former gets GVA.
            if not terms and self.in_image(d & 0xFFFFFFFFFFFFFFFF):
                terms.append('GVA(0x%X)' % (d & 0xFFFFFFFFFFFFFFFF))
            elif d < 0:
                terms.append('(int64_t)(%d)' % d)
            else:
                terms.append('0x%Xull' % d)
        return '(' + ' + '.join(terms) + ')'

    def seg_name(self, op):
        seg = getattr(op.mem, 'segment', 0)
        return self.rname(seg) if seg else None

    def seg_off(self, insn, op):
        m = op.mem
        terms = []
        if m.base:
            terms.append(self.areg(self.rname(m.base)))
        if m.index:
            terms.append('%s*%d' % (self.areg(self.rname(m.index)), m.scale))
        d = m.disp
        if d or not terms:
            terms.append('0x%Xull' % (d & 0xFFFFFFFFFFFFFFFF))
        return '(' + ' + '.join(terms) + ')'

    def _bad_size(self, insn, op, what):
        return NotImplementedError(
            '%s: %d-byte memory operand at %#x (%s %s)'
            % (what, op.size, insn.address, insn.mnemonic, insn.op_str))

    def rd(self, insn, op):
        sz = op.size
        if self.seg_name(op) == 'gs':      # TEB-relative
            off = self.seg_off(insn, op)
            if sz == 8:
                return 'rd_gs64(%s)' % off
            if sz == 4:
                return 'rd_gs32(%s)' % off
            raise self._bad_size(insn, op, 'rd gs:')
        a = self.addr_expr(insn, op)
        if sz not in (1, 2, 4, 8):
            raise self._bad_size(insn, op, 'rd')
        return {1: 'rd8(%s)', 2: 'rd16(%s)', 4: 'rd32(%s)', 8: 'rd64(%s)'}[sz] % a

    def wr(self, insn, op, val):
        sz = op.size
        if self.seg_name(op) == 'gs':
            off = self.seg_off(insn, op)
            if sz == 8:
                return 'wr_gs64(%s, %s);' % (off, val)
            if sz == 4:
                return 'wr_gs32(%s, (uint32_t)(%s));' % (off, val)
            raise self._bad_size(insn, op, 'wr gs:')
        a = self.addr_expr(insn, op)
        if sz not in (1, 2, 4, 8):
            raise self._bad_size(insn, op, 'wr')
        cast = {1: 'uint8_t', 2: 'uint16_t', 4: 'uint32_t', 8: 'uint64_t'}[sz]
        fn = {1: 'wr8', 2: 'wr16', 4: 'wr32', 8: 'wr64'}[sz]
        return '%s(%s, (%s)(%s));' % (fn, a, cast, val)

    def src(self, insn, op):
        if op.type == X86_OP_REG:
            return reg_read(self.rname(op.reg))
        if op.type == X86_OP_IMM:
            # Capstone hands back a sign-extended value. Mask to the operand's
            # own width so the C literal has the bit pattern the hardware sees;
            # the sign extension that x86-64 really does for a 32-bit immediate
            # into a 64-bit operand is then explicit below.
            sz = op.size
            if sz == 8:
                v = op.imm & 0xFFFFFFFFFFFFFFFF
                # movabs and friends: a 64-bit immediate that lands in the
                # image is an absolute address and must track the load base.
                if self.in_image(v):
                    return 'GVA(0x%X)' % v
                return '0x%Xull' % v
            mask = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF}[sz]
            return '0x%Xu' % (op.imm & mask)
        if op.type == X86_OP_MEM:
            return self.rd(insn, op)
        raise NotImplementedError('src type')

    def src_ext(self, insn, op, dstsz):
        """A source operand sign-extended to the destination's width.

        x86-64's 32-bit immediates are sign-extended into 64-bit operands:
        `add rax, -1` encodes 0xFFFFFFFF and means -1, not 4294967295. Reading
        it unsigned adds four billion instead of subtracting one.
        """
        if op.type == X86_OP_IMM and dstsz == 8 and op.size == 4:
            return '(uint64_t)(int64_t)(int32_t)0x%Xu' % (op.imm & 0xFFFFFFFF)
        return self.src(insn, op)

    def dst_write(self, insn, op, val):
        if op.type == X86_OP_REG:
            return reg_write(self.rname(op.reg), val)
        if op.type == X86_OP_MEM:
            return self.wr(insn, op, val)
        raise NotImplementedError('dst type')

    def _read_dst(self, insn, op):
        if op.type == X86_OP_REG:
            return reg_read(self.rname(op.reg))
        if op.type == X86_OP_MEM:
            return self.rd(insn, op)
        raise NotImplementedError('read dst')

    def _target(self, insn, op):
        if op.type == X86_OP_IMM:
            return '0x%Xull' % (op.imm & 0xFFFFFFFFFFFFFFFF)
        if op.type == X86_OP_REG:
            return reg_read(self.rname(op.reg))
        if op.type == X86_OP_MEM:
            return self.rd(insn, op)
        raise NotImplementedError('target')

    def _cond(self, m):
        return {
            'je': 'c->zf', 'jz': 'c->zf', 'jne': '!c->zf', 'jnz': '!c->zf',
            'jbe': '(c->cf || c->zf)', 'jna': '(c->cf || c->zf)',
            'ja': '(!c->cf && !c->zf)', 'jnbe': '(!c->cf && !c->zf)',
            'jb': 'c->cf', 'jc': 'c->cf', 'jnae': 'c->cf',
            'jae': '!c->cf', 'jnb': '!c->cf', 'jnc': '!c->cf',
            'jl': '(c->sf != c->of)', 'jnge': '(c->sf != c->of)',
            'jge': '(c->sf == c->of)', 'jnl': '(c->sf == c->of)',
            'jle': '(c->zf || (c->sf != c->of))', 'jng': '(c->zf || (c->sf != c->of))',
            'jg': '(!c->zf && (c->sf == c->of))', 'jnle': '(!c->zf && (c->sf == c->of))',
            'js': 'c->sf', 'jns': '!c->sf', 'jo': 'c->of', 'jno': '!c->of',
            'jp': 'c->pf', 'jpe': 'c->pf', 'jnp': '!c->pf', 'jpo': '!c->pf',
            'jrcxz': '(c->rcx == 0)', 'jecxz': '(R32(c->rcx) == 0)',
        }.get(m)

    # ---- SSE --------------------------------------------------------------
    def _is_xmm(self, op):
        return op.type == X86_OP_REG and self.rname(op.reg).startswith('xmm')

    def _xi(self, op):
        name = self.rname(op.reg) if op.type == X86_OP_REG else '<mem>'
        if not name.startswith('xmm') or not name[3:].isdigit():
            raise NotImplementedError('not an xmm operand: %s' % name)
        return int(name[3:])

    def is_sse(self, insn):
        m = insn.mnemonic
        if m not in SSE64_MNEMONICS and not SSE_CMP_RE.match(m) \
                and not PACKED_CMP_RE.match(m):
            return False
        if m in SSE_AMBIGUOUS:
            return any(self._is_xmm(o) for o in insn.operands)
        return True

    def _ss(self, insn, op):
        if self._is_xmm(op):
            return 'c->xmm[%d].f32[0]' % self._xi(op)
        return 'rdss(%s)' % self.addr_expr(insn, op)

    def _sd(self, insn, op):
        if self._is_xmm(op):
            return 'c->xmm[%d].f64[0]' % self._xi(op)
        return 'rdsd(%s)' % self.addr_expr(insn, op)

    def _xm(self, insn, op):
        if self._is_xmm(op):
            return 'c->xmm[%d]' % self._xi(op)
        return 'rdxm(%s)' % self.addr_expr(insn, op)

    def sse(self, insn):
        m = insn.mnemonic
        ops = insn.operands
        d = ops[0]
        s = ops[1] if len(ops) > 1 else None
        ea = insn.address

        # ---- packed integer ----
        if m in PLANE:
            fld, n, op = PLANE[m]
            k = self._xi(d)
            out = ['{ XMM _s = %s;' % self._xm(insn, s)]
            for i in range(n):
                out.append(' c->xmm[%d].%s[%d] %s= _s.%s[%d];' % (k, fld, i, op, fld, i))
            out.append(' }')
            return [''.join(out)]

        if m in PSAT:
            fld, n, _sgn, add, lo, hi = PSAT[m]
            k = self._xi(d)
            cast = ('int%s_t' if fld[0] == 'i' else 'uint%s_t') % fld[1:]
            out = ['{ XMM _d = c->xmm[%d], _s = %s; int64_t _v;' % (k, self._xm(insn, s))]
            for i in range(n):
                out.append(' _v = (int64_t)_d.%s[%d] %s (int64_t)_s.%s[%d];'
                           ' c->xmm[%d].%s[%d] = (%s)(_v < %d ? %d : _v > %d ? %d : _v);'
                           % (fld, i, '+' if add else '-', fld, i,
                              k, fld, i, cast, lo, lo, hi, hi))
            out.append(' }')
            return [''.join(out)]

        if m in PCMP:
            fld, n, op = PCMP[m]
            k = self._xi(d)
            ufld = 'u' + fld[1:]
            ones = (1 << (128 // n)) - 1
            out = ['{ XMM _d = c->xmm[%d], _s = %s;' % (k, self._xm(insn, s))]
            for i in range(n):
                out.append(' c->xmm[%d].%s[%d] = (_d.%s[%d] %s _s.%s[%d])'
                           ' ? UINT64_C(%d) : 0;'
                           % (k, ufld, i, fld, i, op, fld, i, ones))
            out.append(' }')
            return [''.join(out)]

        if m in PMINMAX:
            fld, n, op = PMINMAX[m]
            k = self._xi(d)
            out = ['{ XMM _d = c->xmm[%d], _s = %s;' % (k, self._xm(insn, s))]
            for i in range(n):
                out.append(' c->xmm[%d].%s[%d] = _d.%s[%d] %s _s.%s[%d]'
                           ' ? _d.%s[%d] : _s.%s[%d];'
                           % (k, fld, i, fld, i, op, fld, i, fld, i, fld, i))
            out.append(' }')
            return [''.join(out)]

        if m in PSHUF:
            fld, n, base, total = PSHUF[m]
            k = self._xi(d)
            imm = ops[2].imm & 0xFF
            sel = [(imm >> (2 * i)) & 3 for i in range(4)]
            out = ['{ XMM _s = %s;' % self._xm(insn, s)]
            # The half this form does not touch is still COPIED, because the
            # source may be memory or another register.
            for i in range(total):
                if base <= i < base + n:
                    out.append(' c->xmm[%d].%s[%d] = _s.%s[%d];'
                               % (k, fld, i, fld, base + sel[i - base]))
                else:
                    out.append(' c->xmm[%d].%s[%d] = _s.%s[%d];' % (k, fld, i, fld, i))
            out.append(' }')
            return [''.join(out)]

        if m in ('pmullw', 'pmulhw', 'pmulhuw'):
            k = self._xi(d)
            fld = 'u16' if m == 'pmulhuw' else 'i16'
            shift = 0 if m == 'pmullw' else 16
            out = ['{ XMM _d = c->xmm[%d], _s = %s;' % (k, self._xm(insn, s))]
            for i in range(8):
                out.append(' c->xmm[%d].u16[%d] = (uint16_t)(((int32_t)_d.%s[%d] *'
                           ' (int32_t)_s.%s[%d]) >> %d);'
                           % (k, i, fld, i, fld, i, shift))
            out.append(' }')
            return [''.join(out)]

        if m == 'pmaddwd':
            k = self._xi(d)
            out = ['{ XMM _d = c->xmm[%d], _s = %s;' % (k, self._xm(insn, s))]
            for i in range(4):
                out.append(' c->xmm[%d].i32[%d] = (int32_t)_d.i16[%d] * _s.i16[%d]'
                           ' + (int32_t)_d.i16[%d] * _s.i16[%d];'
                           % (k, i, 2 * i, 2 * i, 2 * i + 1, 2 * i + 1))
            out.append(' }')
            return [''.join(out)]

        if m in ('pavgb', 'pavgw'):
            k = self._xi(d)
            fld, n = ('u8', 16) if m == 'pavgb' else ('u16', 8)
            cast = 'uint8_t' if m == 'pavgb' else 'uint16_t'
            out = ['{ XMM _d = c->xmm[%d], _s = %s;' % (k, self._xm(insn, s))]
            for i in range(n):
                out.append(' c->xmm[%d].%s[%d] = (%s)(((uint32_t)_d.%s[%d] +'
                           ' _s.%s[%d] + 1) >> 1);'
                           % (k, fld, i, cast, fld, i, fld, i))
            out.append(' }')
            return [''.join(out)]

        if m == 'pmovmskb':
            n = self._xi(s)
            expr = ' | '.join('((uint32_t)(c->xmm[%d].u8[%d] >> 7) << %d)'
                              % (n, i, i) for i in range(16))
            return [self.dst_write(insn, d, '(%s)' % expr)]

        if m in ('pslldq', 'psrldq'):
            # A whole-register BYTE shift, not a lane shift - the one member of
            # the family whose count is in bytes.
            k = self._xi(d)
            nb = min(ops[1].imm & 0xFF, 16)
            left = m == 'pslldq'
            out = ['{ XMM _d = c->xmm[%d];' % k]
            for i in range(16):
                src = i - nb if left else i + nb
                out.append(' c->xmm[%d].u8[%d] = %s;'
                           % (k, i, ('_d.u8[%d]' % src) if 0 <= src < 16 else '0'))
            out.append(' }')
            return [''.join(out)]

        if m == 'pshufb':
            k = self._xi(d)
            out = ['{ XMM _d = c->xmm[%d], _s = %s;' % (k, self._xm(insn, s))]
            for i in range(16):
                out.append(' c->xmm[%d].u8[%d] = (_s.u8[%d] & 0x80) ? 0 :'
                           ' _d.u8[_s.u8[%d] & 15];' % (k, i, i, i))
            out.append(' }')
            return [''.join(out)]

        if m == 'pextrw':
            n = self._xi(s)
            return [self.dst_write(insn, d,
                                   '(uint32_t)c->xmm[%d].u16[%d]'
                                   % (n, ops[2].imm & 7))]

        if m == 'pinsrw':
            k = self._xi(d)
            return ['c->xmm[%d].u16[%d] = (uint16_t)(%s);'
                    % (k, ops[2].imm & 7, self.src(insn, s))]

        if m in PUNPCK:
            fld, n, base = PUNPCK[m]
            k = self._xi(d)
            out = ['{ XMM _d = c->xmm[%d], _s = %s;' % (k, self._xm(insn, s))]
            for i in range(n):
                out.append(' c->xmm[%d].%s[%d] = _d.%s[%d];'
                           % (k, fld, 2 * i, fld, base + i))
                out.append(' c->xmm[%d].%s[%d] = _s.%s[%d];'
                           % (k, fld, 2 * i + 1, fld, base + i))
            out.append(' }')
            return [''.join(out)]

        if m in PACK:
            sf, df, n, lo, hi = PACK[m]
            k = self._xi(d)
            out = ['{ XMM _d = c->xmm[%d], _s = %s; int64_t _v;' % (k, self._xm(insn, s))]
            for i in range(2 * n):
                src = '_d' if i < n else '_s'
                j = i if i < n else i - n
                cast = ('int%s_t' if df[0] == 'i' else 'uint%s_t') % df[1:]
                out.append(' _v = %s.%s[%d];'
                           ' c->xmm[%d].%s[%d] = (%s)(_v < %d ? %d : _v > %d ? %d : _v);'
                           % (src, sf, j, k, df, i, cast, lo, lo, hi, hi))
            out.append(' }')
            return [''.join(out)]

        if m in PSHIFT:
            fld, n, kind = PSHIFT[m]
            k = self._xi(d)
            if s.type == X86_OP_IMM:
                cnt = 'UINT64_C(%d)' % (s.imm & 0xFF)
            elif self._is_xmm(s):
                cnt = 'c->xmm[%d].u64[0]' % self._xi(s)
            else:
                return [_todo(ea, '%s %s' % (m, insn.op_str))]
            width = {'u16': 16, 'i16': 16, 'u32': 32, 'i32': 32, 'u64': 64}[fld]
            out = ['{ uint64_t _n = %s;' % cnt]
            # A count at or past the width zeroes the lanes, except for an
            # arithmetic shift, which saturates to the sign. Not an edge case:
            # `psrad xmm, 31` broadcasting a sign mask is the idiom this family
            # is mostly used for, and 31 is one short of the cliff.
            if kind == 'a':
                out.append(' if (_n > %d) _n = %d;' % (width - 1, width - 1))
                body = ' c->xmm[%d].%s[%%d] = (%s)(c->xmm[%d].%s[%%d] >> _n);' \
                       % (k, fld, fld.replace('i', 'int') + '_t', k, fld)
            else:
                out.append(' if (_n > %d) _n = %d;' % (width, width))
                op = '<<' if kind == 'l' else '>>'
                body = ' c->xmm[%d].%s[%%d] = _n == %d ? 0 :' \
                       ' (c->xmm[%d].%s[%%d] %s _n);' \
                       % (k, fld, width, k, fld, op)
            for i in range(n):
                out.append(body % (i, i))
            out.append(' }')
            return [''.join(out)]

        # ---- scalar moves ----
        if m in ('movss', 'movsd'):
            wide = m == 'movsd'
            rd_ = self._sd if wide else self._ss
            if self._is_xmm(d) and self._is_xmm(s):
                return ['%s = %s;' % (rd_(insn, d), rd_(insn, s))]
            if self._is_xmm(d):
                return ['sse_load_s%s(&c->xmm[%d], %s);'
                        % ('d' if wide else 's', self._xi(d), rd_(insn, s))]
            st = 'wrsd' if wide else 'wrss'
            return ['%s(%s, %s);' % (st, self.addr_expr(insn, d), rd_(insn, s))]

        if m == 'movd':
            if self._is_xmm(d):
                n = self._xi(d)
                return ['c->xmm[%d].u64[0] = (uint32_t)(%s); c->xmm[%d].u64[1] = 0;'
                        % (n, self.src(insn, s), n)]
            return [self.dst_write(insn, d, 'c->xmm[%d].u32[0]' % self._xi(s))]

        if m == 'movq':
            # On x64 movq also moves a whole 64-bit GPR to/from an xmm lane,
            # which the 32-bit lifter never sees.
            if self._is_xmm(d) and self._is_xmm(s):
                return ['c->xmm[%d].u64[0] = c->xmm[%d].u64[0]; c->xmm[%d].u64[1] = 0;'
                        % (self._xi(d), self._xi(s), self._xi(d))]
            if self._is_xmm(d):
                n = self._xi(d)
                if s.type == X86_OP_REG:
                    return ['c->xmm[%d].u64[0] = %s; c->xmm[%d].u64[1] = 0;'
                            % (n, reg_read(self.rname(s.reg)), n)]
                return ['c->xmm[%d].u64[0] = rd64(%s); c->xmm[%d].u64[1] = 0;'
                        % (n, self.addr_expr(insn, s), n)]
            if d.type == X86_OP_REG and not self._is_xmm(d):
                return [reg_write(self.rname(d.reg), 'c->xmm[%d].u64[0]' % self._xi(s))]
            return ['wr64(%s, c->xmm[%d].u64[0]);'
                    % (self.addr_expr(insn, d), self._xi(s))]

        # ---- 128-bit moves ----
        if m in SSE_MOV128 or m in SSE64_MOV128:
            if self._is_xmm(d):
                return ['c->xmm[%d] = %s;' % (self._xi(d), self._xm(insn, s))]
            return ['wrxm(%s, c->xmm[%d]);' % (self.addr_expr(insn, d), self._xi(s))]

        # ---- 64-bit half moves ----
        if m in ('movlps', 'movlpd'):
            if self._is_xmm(d):
                return ['c->xmm[%d].u64[0] = rd64(%s);'
                        % (self._xi(d), self.addr_expr(insn, s))]
            return ['wr64(%s, c->xmm[%d].u64[0]);'
                    % (self.addr_expr(insn, d), self._xi(s))]
        if m in ('movhps', 'movhpd'):
            if self._is_xmm(d):
                return ['c->xmm[%d].u64[1] = rd64(%s);'
                        % (self._xi(d), self.addr_expr(insn, s))]
            return ['wr64(%s, c->xmm[%d].u64[1]);'
                    % (self.addr_expr(insn, d), self._xi(s))]
        if m == 'movhlps':
            return ['c->xmm[%d].u64[0] = c->xmm[%d].u64[1];'
                    % (self._xi(d), self._xi(s))]
        if m == 'movlhps':
            return ['c->xmm[%d].u64[1] = c->xmm[%d].u64[0];'
                    % (self._xi(d), self._xi(s))]

        # ---- bitwise over the whole register ----
        if m in SSE_BITWISE:
            op = SSE_BITWISE[m]
            n = self._xi(d)
            if op == 'andn':
                lanes = ('c->xmm[%d].u64[0] = ~c->xmm[%d].u64[0] & _s.u64[0];'
                         ' c->xmm[%d].u64[1] = ~c->xmm[%d].u64[1] & _s.u64[1];'
                         % (n, n, n, n))
            else:
                lanes = ('c->xmm[%d].u64[0] %s= _s.u64[0];'
                         ' c->xmm[%d].u64[1] %s= _s.u64[1];' % (n, op, n, op))
            return ['{ XMM _s = %s; %s }' % (self._xm(insn, s), lanes)]

        # ---- scalar arithmetic ----
        if m[:-2] in SSE_ARITH and m[-2:] in ('ss', 'sd'):
            wide = m[-2:] == 'sd'
            rd_ = self._sd if wide else self._ss
            return ['%s = %s %s %s;' % (rd_(insn, d), rd_(insn, d),
                                        SSE_ARITH[m[:-2]], rd_(insn, s))]

        # ---- packed arithmetic ----
        #
        # Source into a local first: `mulps xmm0, xmm0` is ordinary code and the
        # lanes alias. Writing lane 0 before reading lane 1 of the same register
        # would be right by luck here but not for shufps below, so both do it.
        if m in PACKED_ARITH:
            op, fld, lanes = PACKED_ARITH[m]
            n = self._xi(d)
            body = ' '.join('c->xmm[%d].%s[%d] = c->xmm[%d].%s[%d] %s _s.%s[%d];'
                            % (n, fld, i, n, fld, i, op, fld, i)
                            for i in range(lanes))
            return ['{ XMM _s = %s; %s }' % (self._xm(insn, s), body)]

        if m in PACKED_MINMAX:
            fn, fld, lanes = PACKED_MINMAX[m]
            n = self._xi(d)
            body = ' '.join('c->xmm[%d].%s[%d] = %s(c->xmm[%d].%s[%d], _s.%s[%d]);'
                            % (n, fld, i, fn, n, fld, i, fld, i)
                            for i in range(lanes))
            return ['{ XMM _s = %s; %s }' % (self._xm(insn, s), body)]

        if m in ('sqrtss', 'sqrtsd'):
            wide = m == 'sqrtsd'
            rd_ = self._sd if wide else self._ss
            return ['%s = %s(%s);' % (rd_(insn, d), 'sqrt' if wide else 'sqrtf',
                                      rd_(insn, s))]
        if m == 'sqrtps':
            n = self._xi(d)
            body = ' '.join('c->xmm[%d].f32[%d] = sqrtf(_s.f32[%d]);' % (n, i, i)
                            for i in range(4))
            return ['{ XMM _s = %s; %s }' % (self._xm(insn, s), body)]

        if m in ('rsqrtss', 'rcpss'):
            fn = 'sse_rsqrt' if m == 'rsqrtss' else 'sse_rcp'
            return ['%s = %s(%s);' % (self._ss(insn, d), fn, self._ss(insn, s))]
        if m in ('rsqrtps', 'rcpps'):
            fn = 'sse_rsqrt' if m == 'rsqrtps' else 'sse_rcp'
            n = self._xi(d)
            body = ' '.join('c->xmm[%d].f32[%d] = %s(_s.f32[%d]);' % (n, i, fn, i)
                            for i in range(4))
            return ['{ XMM _s = %s; %s }' % (self._xm(insn, s), body)]

        if m in ('minss', 'maxss', 'minsd', 'maxsd'):
            wide = m.endswith('sd')
            rd_ = self._sd if wide else self._ss
            fn = 'sse_%s%s' % (m[:3], 'd' if wide else 'f')
            return ['%s = %s(%s, %s);' % (rd_(insn, d), fn,
                                          rd_(insn, d), rd_(insn, s))]

        # ---- compares that set flags ----
        if m in ('ucomiss', 'comiss', 'ucomisd', 'comisd'):
            rd_ = self._sd if m.endswith('sd') else self._ss
            return ['sse_compare(c, %s, %s);' % (rd_(insn, d), rd_(insn, s))]

        # ---- compares that write a mask ----
        mm = SSE_CMP_RE.match(m)
        if mm:
            pred, width = mm.group(1), mm.group(2)
            wide = width == 'sd'
            rd_ = self._sd if wide else self._ss
            ctype = 'double' if wide else 'float'
            n = self._xi(d)
            lane = 'c->xmm[%d].u64[0]' % n if wide else 'c->xmm[%d].u32[0]' % n
            ones = '~(uint64_t)0' if wide else '0xFFFFFFFFu'
            zero = '(uint64_t)0' if wide else '0u'
            return ['{ %s _a = %s, _b = %s; %s = %s ? %s : %s; }'
                    % (ctype, rd_(insn, d), rd_(insn, s), lane,
                       SSE_CMP_PRED[pred], ones, zero)]

        pm = PACKED_CMP_RE.match(m)
        if pm:
            pred, width = pm.group(1), pm.group(2)
            wide = width == 'pd'
            fld, ufld, lanes = ('f64', 'u64', 2) if wide else ('f32', 'u32', 4)
            ctype = 'double' if wide else 'float'
            ones = '~(uint64_t)0' if wide else '0xFFFFFFFFu'
            zero = '(uint64_t)0' if wide else '0u'
            n = self._xi(d)
            body = []
            for i in range(lanes):
                body.append('{ %s _a = c->xmm[%d].%s[%d], _b = _s.%s[%d];'
                            ' c->xmm[%d].%s[%d] = %s ? %s : %s; }'
                            % (ctype, n, fld, i, fld, i,
                               n, ufld, i, SSE_CMP_PRED[pred], ones, zero))
            return ['{ XMM _s = %s; %s }' % (self._xm(insn, s), ' '.join(body))]

        # ---- shuffles and unpacks ----
        #
        # shufps takes its two low lanes from the DESTINATION and its two high
        # lanes from the SOURCE. That asymmetry is the instruction; reading all
        # four from one register is the mistake it invites, and it produces a
        # transform that is subtly wrong rather than obviously broken.
        if m == 'shufps' and len(ops) == 3 and ops[2].type == X86_OP_IMM:
            n, imm = self._xi(d), ops[2].imm & 0xFF
            sel = [(imm >> (2 * i)) & 3 for i in range(4)]
            return ['{ XMM _d = c->xmm[%d], _s = %s;'
                    ' c->xmm[%d].u32[0] = _d.u32[%d]; c->xmm[%d].u32[1] = _d.u32[%d];'
                    ' c->xmm[%d].u32[2] = _s.u32[%d]; c->xmm[%d].u32[3] = _s.u32[%d]; }'
                    % (n, self._xm(insn, s), n, sel[0], n, sel[1],
                       n, sel[2], n, sel[3])]
        if m == 'shufpd' and len(ops) == 3 and ops[2].type == X86_OP_IMM:
            n, imm = self._xi(d), ops[2].imm & 0xFF
            return ['{ XMM _d = c->xmm[%d], _s = %s;'
                    ' c->xmm[%d].u64[0] = _d.u64[%d]; c->xmm[%d].u64[1] = _s.u64[%d]; }'
                    % (n, self._xm(insn, s), n, imm & 1, n, (imm >> 1) & 1)]
        if m in ('unpcklps', 'unpckhps'):
            n = self._xi(d)
            lo = 0 if m == 'unpcklps' else 2
            return ['{ XMM _d = c->xmm[%d], _s = %s;'
                    ' c->xmm[%d].u32[0] = _d.u32[%d]; c->xmm[%d].u32[1] = _s.u32[%d];'
                    ' c->xmm[%d].u32[2] = _d.u32[%d]; c->xmm[%d].u32[3] = _s.u32[%d]; }'
                    % (n, self._xm(insn, s), n, lo, n, lo, n, lo + 1, n, lo + 1)]
        if m in ('unpcklpd', 'unpckhpd'):
            n = self._xi(d)
            i = 0 if m == 'unpcklpd' else 1
            return ['{ XMM _d = c->xmm[%d], _s = %s;'
                    ' c->xmm[%d].u64[0] = _d.u64[%d]; c->xmm[%d].u64[1] = _s.u64[%d]; }'
                    % (n, self._xm(insn, s), n, i, n, i)]

        if m in ('movmskps', 'movmskpd'):
            fn = 'sse_movmskps' if m == 'movmskps' else 'sse_movmskpd'
            return [self.dst_write(insn, d, '%s(&c->xmm[%d])' % (fn, self._xi(s)))]

        # ---- conversions ----
        #
        # x86-64 adds 64-bit integer forms of every cvt. Capstone reports the
        # width through the operand, so branch on that rather than on the
        # mnemonic - `cvtsi2ss xmm0, rax` and `cvtsi2ss xmm0, eax` share a name.
        if m.startswith('cvtsi2ss') or m.startswith('cvtsi2sd'):
            wide = 'sd' in m[:9]
            lane = self._sd if wide else self._ss
            isz = s.size if s is not None else 4
            cast = 'int64_t' if isz == 8 else 'int32_t'
            # The outer cast is the conversion the instruction performs, and
            # saying so explicitly matters: without it MSVC warns C4244 on every
            # one of these, and across four million lines of generated C a
            # warning that is always benign is a warning nobody reads.
            fcast = 'double' if wide else 'float'
            return ['%s = (%s)(%s)(%s);'
                    % (lane(insn, d), fcast, cast, self.src(insn, s))]
        if m in ('cvttss2si', 'cvttsd2si'):
            rd_ = self._sd if m.startswith('cvttsd') else self._ss
            fn = 'sse_cvtt_i64' if d.size == 8 else 'sse_cvtt_i32'
            return [self.dst_write(insn, d, '%s(%s)' % (fn, rd_(insn, s)))]
        if m in ('cvtss2si', 'cvtsd2si'):
            rd_ = self._sd if m.startswith('cvtsd') else self._ss
            fn = 'sse_cvtt_i64' if d.size == 8 else 'sse_cvtt_i32'
            return [self.dst_write(insn, d, '%s(nearbyint(%s))' % (fn, rd_(insn, s)))]
        if m == 'cvtss2sd':
            return ['c->xmm[%d].f64[0] = %s;' % (self._xi(d), self._ss(insn, s))]
        if m == 'cvtsd2ss':
            return ['c->xmm[%d].f32[0] = (float)(%s);' % (self._xi(d), self._sd(insn, s))]

        if m in ('cvtdq2ps', 'cvtps2dq', 'cvttps2dq'):
            n = self._xi(d)
            body = []
            for i in range(4):
                if m == 'cvtdq2ps':
                    body.append('c->xmm[%d].f32[%d] = (float)_s.i32[%d];' % (n, i, i))
                elif m == 'cvttps2dq':
                    body.append('c->xmm[%d].i32[%d] = sse_cvtt_i32(_s.f32[%d]);' % (n, i, i))
                else:
                    body.append('c->xmm[%d].i32[%d] = sse_cvtt_i32(nearbyintf(_s.f32[%d]));'
                                % (n, i, i))
            return ['{ XMM _s = %s; %s }' % (self._xm(insn, s), ' '.join(body))]

        if m == 'cvtdq2pd':
            # Two ints from the LOW 64 bits, two doubles out.
            n = self._xi(d)
            return ['{ XMM _s = %s; int32_t _a = _s.i32[0], _b = _s.i32[1];'
                    ' c->xmm[%d].f64[0] = _a; c->xmm[%d].f64[1] = _b; }'
                    % (self._xm(insn, s), n, n)]

        if m == 'cvtps2pd':
            n = self._xi(d)
            if self._is_xmm(s):
                j = self._xi(s)
                return ['{ float _a = c->xmm[%d].f32[0], _b = c->xmm[%d].f32[1];'
                        ' c->xmm[%d].f64[0] = _a; c->xmm[%d].f64[1] = _b; }'
                        % (j, j, n, n)]
            return ['{ uint64_t _p = %s; float _a = rdf32(_p), _b = rdf32(_p + 4u);'
                    ' c->xmm[%d].f64[0] = _a; c->xmm[%d].f64[1] = _b; }'
                    % (self.addr_expr(insn, s), n, n)]

        if m == 'cvtpd2ps':
            n = self._xi(d)
            return ['{ XMM _s = %s;'
                    ' c->xmm[%d].f32[0] = (float)_s.f64[0];'
                    ' c->xmm[%d].f32[1] = (float)_s.f64[1];'
                    ' c->xmm[%d].i32[2] = 0; c->xmm[%d].i32[3] = 0; }'
                    % (self._xm(insn, s), n, n, n, n)]

        # MXCSR: rounding mode and the flush-to-zero bits. The lifted build does
        # all its arithmetic in C at the host's rounding mode, so storing and
        # reloading the register is honest bookkeeping and changing rounding is
        # not modelled - which is right as long as the game only saves and
        # restores it, and that is what these six sites do.
        if m == 'stmxcsr':
            return [self.wr(insn, d, 'c->mxcsr')]
        if m == 'ldmxcsr':
            return ['c->mxcsr = %s;' % self.rd(insn, d)]

        return [_todo(ea, 'sse %s %s' % (m, insn.op_str))]

    # ---- per-instruction translation --------------------------------------
    def translate(self, insn, labels):
        m = insn.mnemonic
        ops = insn.operands
        ea = insn.address
        nxt = insn.address + insn.size

        if m.startswith('lock '):
            m = m[5:]

        # An F3/F2 prefix is only a REP on a string instruction. On anything
        # else it is a hint, and the one that matters is `repz ret` (F3 C3) -
        # AMD's branch-prediction idiom for a plain `ret`, which MSVC emits at
        # every branch target that returns. 1,899 of them in this binary, and
        # left unstripped every one becomes an abort at the point a function
        # tries to return.
        _p = m.split()
        if len(_p) > 1 and _p[0] in REP_PREFIXES and _p[-1] not in STRING_OPS64:
            m = _p[-1]

        def two():
            return ops[0], ops[1]

        def sz0():
            return ops[0].size

        # x87 and MMX are not modelled - see the module docstring. Caught here
        # so they cannot fall through into a same-named integer handler.
        if m[0] == 'f' and m not in ('fs',):
            return [_todo(ea, '%s %s (x87 not modelled)' % (m, insn.op_str))]

        if self.is_sse(insn):
            return self.sse(insn)

        if m.startswith('prefetch'):
            return ['/* prefetch: hint only */']

        if m.startswith('cmov'):
            cond = self._cond('j' + m[4:])
            if cond:
                d, sop = ops[0], ops[1]
                # A 32-bit destination is zero-extended EVEN WHEN THE CONDITION
                # IS FALSE. The hardware always writes the register - with the
                # source or with the destination's own old value - and a 32-bit
                # write always clears bits 63:32. Guarding the write with an
                # `if` skips that, leaving a stale high half that the next
                # address computation folds in. Caught by difftest64 against
                # the real CPU; it is invisible in any test that only checks
                # the taken path.
                if d.size == 4:
                    return [self.dst_write(
                        insn, d, '(%s) ? (uint32_t)(%s) : %s'
                                 % (cond, self.src(insn, sop),
                                    self._read_dst(insn, d)))]
                return ['if (%s) { %s }'
                        % (cond, self.dst_write(insn, d, self.src(insn, sop)))]

        # ---- data movement ----
        if m in ('mov', 'movabs'):
            d, s = two()
            return [self.dst_write(insn, d, self.src_ext(insn, s, d.size))]
        if m == 'lea':
            d, s = two()
            # `lea r64, [rip+disp]` is how x64 takes an address, and when the
            # address is code it is a function pointer - a sort predicate, a
            # callback, a hand-built vtable. Nothing CALLS those, and they do
            # not appear in .reloc either because the address is computed and
            # not stored, so the catalog has no other way to learn about them.
            # Recorded rather than acted on here: generate64 decides which of
            # them really are entries.
            if s.type == X86_OP_MEM and s.mem.base == X86_REG_RIP:
                self.lea_targets.add(
                    (insn.address + insn.size + s.mem.disp) & 0xFFFFFFFFFFFFFFFF)
            return [reg_write(self.rname(d.reg), self.addr_expr(insn, s))]
        if m == 'movzx':
            d, s = two()
            return [self.dst_write(insn, d, '(%s)' % self.src(insn, s))]
        if m == 'movsx':
            d, s = two()
            cast = {1: 'int8_t', 2: 'int16_t', 4: 'int32_t'}[s.size]
            wide = 'int64_t' if d.size == 8 else 'int32_t'
            return [self.dst_write(insn, d, '(uint64_t)(%s)(%s)(%s)'
                                   % (wide, cast, self.src(insn, s)))]
        if m == 'movsxd':
            # The 64-bit-only sign extend: 32 -> 64. A compiler emits it for
            # every `int` used as an array index, so it is 30k instructions
            # here. Reading it as a zero extend breaks every negative index.
            d, s = two()
            return [self.dst_write(insn, d, '(uint64_t)(int64_t)(int32_t)(%s)'
                                   % self.src(insn, s))]

        # ---- arithmetic / logic ----
        if m in ('add', 'sub', 'and', 'or', 'xor', 'adc', 'sbb'):
            d, s = two()
            sz = sz0()
            a = self._read_dst(insn, d)
            b = self.src_ext(insn, s, sz)
            if m == 'add':
                r = 'flags_add(c, %s, %s, %d)' % (a, b, sz)
            elif m == 'sub':
                r = 'flags_sub(c, %s, %s, %d)' % (a, b, sz)
            elif m == 'adc':
                r = 'flags_adc(c, %s, %s, %d)' % (a, b, sz)
            elif m == 'sbb':
                r = 'flags_sbb(c, %s, %s, %d)' % (a, b, sz)
            elif m == 'and':
                r = 'flags_logicz(c, %s & %s, %d)' % (a, b, sz)
            elif m == 'or':
                r = 'flags_logicz(c, %s | %s, %d)' % (a, b, sz)
            else:
                r = 'flags_logicz(c, %s ^ %s, %d)' % (a, b, sz)
            return [self.dst_write(insn, d, r)]
        if m == 'cmp':
            d, s = two()
            return ['flags_sub(c, %s, %s, %d);'
                    % (self._read_dst(insn, d), self.src_ext(insn, s, d.size), d.size)]
        if m == 'test':
            d, s = two()
            return ['flags_logicz(c, %s & %s, %d);'
                    % (self._read_dst(insn, d), self.src_ext(insn, s, d.size), d.size)]
        if m == 'inc':
            d = ops[0]
            return [self.dst_write(insn, d, 'flags_incs(c, %s, %d)'
                                   % (self._read_dst(insn, d), d.size))]
        if m == 'dec':
            d = ops[0]
            return [self.dst_write(insn, d, 'flags_decs(c, %s, %d)'
                                   % (self._read_dst(insn, d), d.size))]
        if m == 'neg':
            d = ops[0]
            return [self.dst_write(insn, d, 'flags_sub(c, 0, %s, %d)'
                                   % (self._read_dst(insn, d), d.size))]
        if m == 'not':
            d = ops[0]
            return [self.dst_write(insn, d, '(~(%s))' % self._read_dst(insn, d))]

        if m in ('shl', 'sal', 'shr', 'sar'):
            d = ops[0]
            cnt = self.src(insn, ops[1]) if len(ops) > 1 else '1'
            fn = {'shl': 'op_shl', 'sal': 'op_shl', 'shr': 'op_shr', 'sar': 'op_sar'}[m]
            return [self.dst_write(insn, d, '%s(c, %s, %s, %d)'
                                   % (fn, self._read_dst(insn, d), cnt, d.size))]
        if m in ('rol', 'ror'):
            d = ops[0]
            cnt = self.src(insn, ops[1]) if len(ops) > 1 else '1'
            fn = 'op_rol' if m == 'rol' else 'op_ror'
            return [self.dst_write(insn, d, '%s(c, %s, %s, %d)'
                                   % (fn, self._read_dst(insn, d), cnt, d.size))]
        if m in ('shld', 'shrd'):
            d, s2 = ops[0], ops[1]
            cnt = self.src(insn, ops[2]) if len(ops) > 2 else 'R8L(c->rcx)'
            fn = 'op_shld' if m == 'shld' else 'op_shrd'
            return [self.dst_write(insn, d, '%s(c, %s, %s, %s, %d)'
                                   % (fn, self._read_dst(insn, d),
                                      self.src(insn, s2), cnt, d.size))]

        if m in ('bt', 'bts', 'btr', 'btc'):
            d, s = two()
            fn = 'op_' + m
            if m == 'bt':
                return ['%s(c, %s, %s, %d);'
                        % (fn, self._read_dst(insn, d), self.src(insn, s), d.size)]
            return [self.dst_write(insn, d, '%s(c, %s, %s, %d)'
                                   % (fn, self._read_dst(insn, d),
                                      self.src(insn, s), d.size))]
        if m in ('bsf', 'bsr'):
            d, s = two()
            fn = 'op_' + m
            # A zero source means the destination is NOT WRITTEN - and with a
            # 32-bit destination that also means the usual zero-extension does
            # not happen, so the high half survives. Exactly the opposite of
            # CMOVcc, which writes (and zero-extends) even when not taken.
            # Writing unconditionally clears bits 63:32 that the hardware keeps.
            # Both were found by difftest64; neither is visible in the manual,
            # which calls the destination "undefined" here.
            return ['{ uint64_t _s = %s;' % self.src(insn, s),
                    '  if (_s) { %s }'
                    % self.dst_write(insn, d, '%s(c, %s, _s, %d)'
                                     % (fn, self._read_dst(insn, d), s.size)),
                    '  else { c->zf = 1; bitscan_undef_flags(c); } }']

        # ---- sign-extension of the accumulator ----
        # Four mnemonics, three widths, and the names do not say which is which.
        if m == 'cdqe':     # eax -> rax, sign extended
            return ['SET64(c->rax, (uint64_t)(int64_t)(int32_t)R32(c->rax));']
        if m == 'cqo':      # rax -> rdx:rax
            return ['c->rdx = ((int64_t)c->rax < 0) ? ~(uint64_t)0 : (uint64_t)0;']
        if m == 'cdq':      # eax -> edx:eax
            return ['SET32(c->rdx, (R32(c->rax) & 0x80000000u) ? 0xFFFFFFFFu : 0u);']
        if m == 'cwde':     # ax -> eax
            return ['SET32(c->rax, (uint32_t)(int32_t)(int16_t)R16(c->rax));']
        if m == 'cbw':
            return ['SET16(c->rax, (uint16_t)(int16_t)(int8_t)R8L(c->rax));']
        if m == 'cwd':
            return ['SET16(c->rdx, (R16(c->rax) & 0x8000u) ? 0xFFFFu : 0u);']

        if m == 'xchg':
            d, s = two()
            return ['{ uint64_t _t = %s; %s %s }'
                    % (self._read_dst(insn, d),
                       self.dst_write(insn, d, self.src(insn, s)),
                       self.dst_write(insn, s, '_t'))]

        # ---- interlocked ----
        if m in ('xadd', 'cmpxchg') and sz0() in (4, 8):
            d, s = two()
            sz = sz0()
            if d.type == X86_OP_MEM:
                a = self.addr_expr(insn, d)
                w = 64 if sz == 8 else 32
                acc = 'c->rax' if sz == 8 else 'R32(c->rax)'
                if m == 'xadd':
                    return ['{ uint%d_t _v = (uint%d_t)(%s);' % (w, w, self.src(insn, s)),
                            '  uint%d_t _old = atomic_xadd%d(%s, _v);' % (w, w, a),
                            '  %s' % self.dst_write(insn, s, '_old'),
                            '  flags_add(c, _old, _v, %d); }' % sz]
                return ['{ uint%d_t _old = atomic_cmpxchg%d(%s, (uint%d_t)%s, (uint%d_t)(%s));'
                        % (w, w, a, w, acc, w, self.src(insn, s)),
                        '  flags_sub(c, %s, _old, %d);' % (acc, sz),
                        '  if (_old != (uint%d_t)%s) %s }'
                        % (w, acc, reg_write('rax' if sz == 8 else 'eax', '_old'))]

        if m.startswith('set') and m not in ('setssbsy',):
            cond = self._cond('j' + m[3:])
            if cond is not None:
                return [self.dst_write(insn, ops[0], '((%s) ? 1 : 0)' % cond)]

        # ---- stack ----
        if m == 'push':
            return ['push64(c, %s);' % self.src_ext(insn, ops[0], 8)]
        if m == 'pop':
            return [self.dst_write(insn, ops[0], 'pop64(c)')]
        if m == 'pushfq':
            return ['push64(c, eflags_pack(c));']
        if m == 'popfq':
            return ['eflags_unpack(c, pop64(c));']
        if m == 'enter':
            n = ops[0].imm if ops else 0
            return ['push64(c, c->rbp); c->rbp = c->rsp; c->rsp -= %d;' % n]
        if m == 'leave':
            return ['c->rsp = c->rbp; c->rbp = pop64(c);']

        if m == 'sahf':
            return ['eflags_unpack(c, (eflags_pack(c) & ~(uint64_t)0xFF) | R8H(c->rax));']
        if m == 'lahf':
            return ['SET8H(c->rax, (uint8_t)((c->sf<<7)|(c->zf<<6)|(c->af<<4)'
                    '|(c->pf<<2)|2|c->cf));']

        # ---- multiply / divide ----
        if m == 'mul':
            s = ops[0]
            sz = s.size
            v = self.src(insn, s)
            if sz == 8:
                return ['{ uint64_t _hi, _lo = mulu64_128(c->rax, (uint64_t)(%s), &_hi);' % v,
                        '  c->rax = _lo; c->rdx = _hi; c->cf = c->of = (_hi != 0); }']
            if sz == 4:
                return ['{ uint64_t _p=(uint64_t)R32(c->rax)*(uint32_t)(%s);'
                        ' SET32(c->rax,(uint32_t)_p); SET32(c->rdx,(uint32_t)(_p>>32));'
                        ' c->cf=c->of=((_p>>32)!=0); }' % v]
            if sz == 2:
                return ['{ uint32_t _p=(uint32_t)R16(c->rax)*(uint16_t)(%s);'
                        ' SET16(c->rax,_p); SET16(c->rdx,_p>>16);'
                        ' c->cf=c->of=((_p>>16)!=0); }' % v]
            return ['{ uint16_t _p=(uint16_t)R8L(c->rax)*(uint8_t)(%s);'
                    ' SET16(c->rax,_p); c->cf=c->of=((_p>>8)!=0); }' % v]

        if m == 'imul':
            if len(ops) == 1:
                s = ops[0]
                sz = s.size
                v = self.src(insn, s)
                if sz == 8:
                    return ['{ uint64_t _hi, _lo = muls64_128((int64_t)c->rax, (int64_t)(%s), &_hi);' % v,
                            '  c->rax = _lo; c->rdx = _hi;',
                            '  c->cf = c->of = (_hi != (((int64_t)_lo < 0) ? ~(uint64_t)0 : (uint64_t)0)); }']
                if sz == 4:
                    return ['{ int64_t _p=(int64_t)(int32_t)R32(c->rax)*(int32_t)(%s);'
                            ' SET32(c->rax,(uint32_t)_p); SET32(c->rdx,(uint32_t)((uint64_t)_p>>32));'
                            ' c->cf=c->of=((int32_t)_p!=_p); }' % v]
                if sz == 2:
                    return ['{ int32_t _p=(int32_t)(int16_t)R16(c->rax)*(int16_t)(%s);'
                            ' SET16(c->rax,_p); SET16(c->rdx,_p>>16);'
                            ' c->cf=c->of=((int16_t)_p!=_p); }' % v]
                return ['{ int16_t _p=(int16_t)(int8_t)R8L(c->rax)*(int8_t)(%s);'
                        ' SET16(c->rax,_p); c->cf=c->of=((int8_t)_p!=_p); }' % v]
            d = ops[0]
            sz = d.size
            cast = {1: 'int8_t', 2: 'int16_t', 4: 'int32_t', 8: 'int64_t'}[sz]
            if len(ops) == 2:
                a, b = self._read_dst(insn, d), self.src_ext(insn, ops[1], sz)
            else:
                a, b = self.src(insn, ops[1]), self.src_ext(insn, ops[2], sz)
            if sz == 8:
                # CF/OF say the full product did not fit in 64 bits, which needs
                # the high half - so this goes through the same helper as the
                # one-operand form rather than approximating the flags away.
                return ['{ uint64_t _hi, _lo = muls64_128((int64_t)(%s), (int64_t)(%s), &_hi);'
                        % (a, b),
                        '  %s' % self.dst_write(insn, d, '_lo'),
                        '  c->cf=c->of=(_hi != (((int64_t)_lo < 0) ? ~(uint64_t)0 : (uint64_t)0)); }']
            return ['{ int64_t _p=(int64_t)(%s)(%s)*(%s)(%s); %s c->cf=c->of=((%s)_p!=_p); }'
                    % (cast, a, cast, b,
                       self.dst_write(insn, d, '(uint64_t)_p'), cast)]

        if m in ('div', 'idiv'):
            s = ops[0]
            sz = s.size
            v = self.src(insn, s)
            sg = (m == 'idiv')
            if sz == 8:
                # The true operation is 128/64. A compiler emits this shape only
                # after setting rdx to the sign extension of rax (cqo) or to
                # zero, so the 64/64 form below is what actually runs. A genuine
                # 128-bit numerator would need __int128 and is caught, not guessed.
                if sg:
                    return ['{ int64_t _n=(int64_t)c->rax, _d=(int64_t)(%s);' % v,
                            '  if ((c->rdx != 0) && (c->rdx != ~(uint64_t)0))'
                            ' RECOMP_TODO(0x%X, "idiv: true 128-bit numerator");' % ea,
                            '  c->rax=(uint64_t)(_n/_d); c->rdx=(uint64_t)(_n%_d); }']
                return ['{ uint64_t _n=c->rax, _d=(uint64_t)(%s);' % v,
                        '  if (c->rdx != 0) RECOMP_TODO(0x%X, "div: true 128-bit numerator");' % ea,
                        '  c->rax=_n/_d; c->rdx=_n%_d; }']
            if sz == 4:
                if sg:
                    return ['{ int64_t _n=(int64_t)(((uint64_t)R32(c->rdx)<<32)|R32(c->rax));'
                            ' int32_t _d=(int32_t)(%s);'
                            ' SET32(c->rax,(uint32_t)(_n/_d)); SET32(c->rdx,(uint32_t)(_n%%_d)); }' % v]
                return ['{ uint64_t _n=((uint64_t)R32(c->rdx)<<32)|R32(c->rax);'
                        ' uint32_t _d=(uint32_t)(%s);'
                        ' SET32(c->rax,(uint32_t)(_n/_d)); SET32(c->rdx,(uint32_t)(_n%%_d)); }' % v]
            if sz == 2:
                if sg:
                    return ['{ int32_t _n=(int32_t)(((uint32_t)R16(c->rdx)<<16)|R16(c->rax));'
                            ' int16_t _d=(int16_t)(%s);'
                            ' SET16(c->rax,(uint16_t)(int16_t)(_n/_d));'
                            ' SET16(c->rdx,(uint16_t)(int16_t)(_n%%_d)); }' % v]
                return ['{ uint32_t _n=((uint32_t)R16(c->rdx)<<16)|R16(c->rax);'
                        ' uint16_t _d=(uint16_t)(%s);'
                        ' SET16(c->rax,_n/_d); SET16(c->rdx,_n%%_d); }' % v]
            if sg:
                return ['{ int16_t _n=(int16_t)R16(c->rax); int8_t _d=(int8_t)(%s);'
                        ' SET8L(c->rax,(uint8_t)(int8_t)(_n/_d));'
                        ' SET8H(c->rax,(uint8_t)(int8_t)(_n%%_d)); }' % v]
            return ['{ uint16_t _n=R16(c->rax); uint8_t _d=(uint8_t)(%s);'
                    ' SET8L(c->rax,_n/_d); SET8H(c->rax,_n%%_d); }' % v]

        # ---- string ops ----
        parts = m.split()
        if parts[-1] in STRING_OPS64:
            return self.string_op(insn, parts)

        # ---- control flow ----
        if m == 'jmp':
            t = ops[0]
            if t.type == X86_OP_IMM and t.imm in labels:
                return ['goto L_%012X;' % t.imm]
            if ea in self.jumptables:
                tgts = self.jumptables[ea]
                out = ['{ uint64_t _jt = %s;' % self._jt_load(insn, t)]
                for tv in sorted(set(tgts)):
                    if tv in labels:
                        out.append('  if (_jt == GVA(0x%X)) goto L_%012X;' % (tv, tv))
                    else:
                        out.append('  if (_jt == GVA(0x%X)) { dispatch(c, 0x%Xull); return; }'
                                   % (tv, tv))
                # An arm this walk did not enumerate. Same reasoning as the
                # register-indirect case: try the local labels before giving up
                # to the global dispatcher.
                out.append('  _ind = _jt; goto _ljump; }')
                return out
            if t.type == X86_OP_IMM:
                return ['dispatch(c, 0x%Xull); return;' % t.imm]
            # An indirect jump. MSVC's x64 switch is
            #     lea r11, [rip+table] / mov eax,[r11+rax*4] / add rax,r11 / jmp rax
            # so the target is computed in a REGISTER and is not a literal
            # anywhere in the image - no amount of static analysis of the
            # emitted text will find it, and the arm is usually an address
            # inside this very function, just after a `ret`. Sending it to the
            # global dispatcher fails: the dispatch table holds function
            # entries and cannot enter a body part-way through.
            #
            # So it goes to the local label dispatch instead, which can, and
            # only falls back to the global one for a genuine cross-function
            # tail call. See the _ljump block in lift_function.
            return ['{ _ind = %s; goto _ljump; }' % self._target(insn, t)]

        if m == 'call':
            t = ops[0]
            tgt = self._target(insn, t)
            # c->rip is restored to the RETURN address after the call.
            #
            # Without this the guest PC keeps whatever block the callee last
            # entered, so a fault in the caller is reported against the callee -
            # and for a one-instruction IAT thunk like `jmp [__imp_memset]` that
            # reads as "the crash is in memset", which is both wrong and
            # convincing. One store per call buys a PC that means what it says.
            if t.type == X86_OP_IMM:
                return ['push64(c, 0x%Xull); dispatch(c, %s); c->rip = 0x%Xull;'
                        % (nxt, tgt, nxt)]
            # Resolve the target BEFORE pushing: `call qword ptr [rsp+0x18]`
            # reads its target with the pre-push rsp, and pushing first shifts
            # every rsp-relative operand by 8.
            return ['{ uint64_t _ct = %s; push64(c, 0x%Xull); dispatch(c, _ct); }'
                    ' c->rip = 0x%Xull;' % (tgt, nxt, nxt)]

        if m in ('ret', 'retn'):
            n = (ops[0].imm if ops and ops[0].type == X86_OP_IMM else 0)
            return ['c->rsp += %d; return;' % (8 + n)]
        if m == 'retf':
            return ['/* retf: far frame unwound by the caller */ return;']

        if m.startswith('j'):
            cond = self._cond(m)
            if cond is None:
                return [_todo(ea, m)]
            t = ops[0]
            if t.type == X86_OP_IMM and t.imm in labels:
                return ['if (%s) goto L_%012X;' % (cond, t.imm)]
            if t.type == X86_OP_IMM:
                return ['if (%s) { dispatch(c, 0x%Xull); return; }' % (cond, t.imm)]
            return [_todo(ea, 'jcc %s %s' % (m, insn.op_str))]

        if m in ('loop', 'loope', 'loopz', 'loopne', 'loopnz'):
            t = ops[0]
            extra = ''
            if m in ('loope', 'loopz'):
                extra = ' && c->zf'
            elif m in ('loopne', 'loopnz'):
                extra = ' && !c->zf'
            if t.type == X86_OP_IMM and t.imm in labels:
                return ['c->rcx--; if (c->rcx%s) goto L_%012X;' % (extra, t.imm)]
            return ['c->rcx--; if (c->rcx%s) { dispatch(c, 0x%Xull); return; }'
                    % (extra, t.imm)]

        # ---- no-ops and flag fiddling ----
        if m in ('nop', 'int3', 'hint_nop', 'pause', 'wait', 'fwait', 'endbr64'):
            return ['/* %s */' % m]
        if m == 'cld':
            return ['/* cld */']
        if m == 'std':
            return ['/* std (DF=1 unsupported; string ops assume forward) */']
        if m == 'clc':
            return ['c->cf = 0;']
        if m == 'stc':
            return ['c->cf = 1;']
        if m == 'cmc':
            return ['c->cf = !c->cf;']
        if m == 'cpuid':
            return ['do_cpuid(c);']
        if m == 'xlatb':
            return ['SET8L(c->rax, rd8(c->rbx + R8L(c->rax)));']

        return [_todo(ea, '%s %s' % (m, insn.op_str))]

    def _jt_load(self, insn, op):
        """Read one jump-table entry.

        MSVC's x64 switch tables hold 32-bit RVAs from the image base, not
        absolute pointers - the whole point is to keep the table half the size
        in a binary that can load anywhere. Reading them as absolute addresses
        gives a target near zero, every time.
        """
        return 'GVA((int32_t)rd32(%s))' % self.addr_expr(insn, op)

    def string_op(self, insn, parts):
        """movs/stos/lods/scas/cmps, with or without a rep prefix.

        DF is assumed 0 (forward). The four `std` sites in the measured binary
        are inside data; real code sets DF only around a backwards copy, and if
        one appears the TODO in `std` above is what catches it.
        """
        ea = insn.address
        base = parts[-1]
        pfx = parts[0] if len(parts) > 1 and parts[0] in REP_PREFIXES else None
        width = {'b': 1, 'w': 2, 'd': 4, 'q': 8}.get(base[-1])
        if width is None:
            return [_todo(ea, '%s %s' % (insn.mnemonic, insn.op_str))]
        op = base[:-1]

        rd_ = {1: 'rd8', 2: 'rd16', 4: 'rd32', 8: 'rd64'}[width]
        wr_ = {1: 'wr8', 2: 'wr16', 4: 'wr32', 8: 'wr64'}[width]
        acc = {1: 'R8L(c->rax)', 2: 'R16(c->rax)',
               4: 'R32(c->rax)', 8: 'c->rax'}[width]

        if op == 'movs':
            body = '%s(c->rdi, %s(c->rsi)); c->rsi += %d; c->rdi += %d;' % (
                wr_, rd_, width, width)
        elif op == 'stos':
            body = '%s(c->rdi, %s); c->rdi += %d;' % (wr_, acc, width)
        elif op == 'lods':
            body = '%s c->rsi += %d;' % (
                reg_write({1: 'al', 2: 'ax', 4: 'eax', 8: 'rax'}[width],
                          '%s(c->rsi)' % rd_), width)
        elif op == 'scas':
            body = 'flags_sub(c, %s, %s(c->rdi), %d); c->rdi += %d;' % (
                acc, rd_, width, width)
        elif op == 'cmps':
            body = 'flags_sub(c, %s(c->rsi), %s(c->rdi), %d); c->rsi += %d; c->rdi += %d;' % (
                rd_, rd_, width, width, width)
        else:
            return [_todo(ea, '%s %s' % (insn.mnemonic, insn.op_str))]

        if not pfx:
            return [body]

        # repe/repne additionally stop when ZF says so, and only the compare
        # forms set ZF - a `rep stos` with repe spelled on it is still just a
        # count loop.
        if pfx in ('repe', 'repz') and op in ('scas', 'cmps'):
            return ['while (c->rcx) { c->rcx--; %s if (!c->zf) break; }' % body]
        if pfx in ('repne', 'repnz') and op in ('scas', 'cmps'):
            return ['while (c->rcx) { c->rcx--; %s if (c->zf) break; }' % body]
        return ['while (c->rcx) { c->rcx--; %s }' % body]

    # ---- function-level ---------------------------------------------------
    def resolve_jumptable(self, table_va, count=256):
        """Walk an x64 switch table of 32-bit image-relative offsets."""
        targets = []
        if not self.read_va:
            return targets
        for i in range(count):
            try:
                raw = self.read_va(table_va + 4 * i, 4)
            except Exception:
                break
            off = int.from_bytes(raw, 'little', signed=True)
            t = (self.image_lo + off) & 0xFFFFFFFFFFFFFFFF
            if self.in_image(t):
                targets.append(t)
            else:
                break
        return targets

    eh_funcs = frozenset()

    def lift_function(self, code, start, name=None):
        self.jumptables = {}
        insns = list(self.md.disasm(code, start))
        end = start + len(code)

        # An extent that ends mid-instruction: read the few extra bytes that
        # finish it, so the fall-through address is a real instruction boundary
        # rather than the middle of one.
        if insns and self.read_va:
            tail = insns[-1].address + insns[-1].size
            if tail < end:
                try:
                    extra = self.read_va(tail, (end - tail) + 15)
                except Exception:
                    extra = b''
                for ins in self.md.disasm(extra, tail):
                    if ins.address >= end:
                        break
                    insns.append(ins)
                if insns:
                    end = max(end, insns[-1].address + insns[-1].size)

        self.func_start, self.func_end = start, end
        insn_addrs = set(i.address for i in insns)
        labels = set()
        for ins in insns:
            mn = ins.mnemonic
            if mn.startswith('j') or mn.startswith('loop'):
                for op in ins.operands:
                    if op.type == X86_OP_IMM and op.imm in insn_addrs:
                        labels.add(op.imm)
                    elif op.type == X86_OP_MEM and mn == 'jmp':
                        # `jmp [rax*4 + table]`, the x64 switch shape. The
                        # scaled index is what tells it apart from an IAT
                        # thunk (`jmp [__imp_X]`, of which a PE has hundreds);
                        # walking the import table as a jump table would invent
                        # thousands of branch targets out of hint RVAs.
                        if op.mem.index and op.mem.scale == 4:
                            if op.mem.base == X86_REG_RIP:
                                tbl = ins.address + ins.size + op.mem.disp
                            else:
                                tbl = op.mem.disp
                            if self.in_image(tbl):
                                tg = self.resolve_jumptable(tbl)
                                if tg:
                                    self.jumptables[ins.address] = tg
                                    labels.update(t for t in tg if t in insn_addrs)

        # An indirect jump can compute ANY instruction in this function as its
        # target - a switch arm is often the instruction right after a `ret`,
        # which is a leader no branch points at - so when one is present every
        # instruction needs a label for the local dispatch below to reach. The
        # labels are all referenced by that switch, so none is unreferenced.
        has_indirect = any(
            i.mnemonic == 'jmp' and i.operands and i.operands[0].type != X86_OP_IMM
            for i in insns)

        # A function the original built with a try/catch needs the same
        # local dispatch, for the same reason: a catch resumes at a
        # continuation address the handler funclet picks at run time, which
        # is an indirect jump into the middle of this body by another name.
        # See runtime eh64.c - without the landing pad a guest throw has
        # nowhere to land, and a failure the game would have swallowed
        # kills the process instead.
        has_eh = start in self.eh_funcs
        if has_indirect or has_eh:
            labels = set(insn_addrs)

        fname = name or ('L_%012X' % start)
        out = ['void %s(CPU *c)' % fname, '{']
        # The entry is a block leader too, and it is not always in `labels`.
        out.append('    c->rip = 0x%Xull;' % start)
        if has_indirect or has_eh:
            out.append('    uint64_t _ind = 0;')
        if has_eh:
            out.append('    ES3_EH_ENTER(0x%Xull);' % start)
        for ins in insns:
            if ins.address in labels:
                out.append('L_%012X:' % ins.address)
                # The guest PC, maintained at basic-block granularity.
                #
                # A fault in generated C reports a HOST address, and there is no
                # way back from that to the guest instruction - the lifted body
                # has no relation to the original layout. One store per block
                # gives the fault handler a guest address to name, locating a
                # crash to within a few instructions instead of within a
                # function that may be two thousand bytes long. Per instruction
                # would be exact and cost far more; per block is free next to
                # the dispatch it already went through.
                out.append('    c->rip = 0x%Xull;' % ins.address)
            # Per instruction, not per function. A single operand the lifter
            # cannot express - a segment-register move, capstone's `riz`
            # pseudo-index, a 1-byte gs: access - is data that the extent
            # walked into, and there is a lot of it: constant pools and jump
            # tables sit inside functions. Letting that raise loses the whole
            # body, including the several-thousand-byte real function wrapped
            # around it. A TODO costs one instruction and keeps the rest.
            try:
                lines = self.translate(ins, labels)
            except Exception as e:
                lines = [_todo(ins.address, '%s %s [%s]'
                               % (ins.mnemonic, ins.op_str, type(e).__name__))]
            for line in lines:
                out.append('    %-60s /* %012X: %s %s */'
                           % (line, ins.address, ins.mnemonic, ins.op_str))

        # A body whose last instruction is not a transfer falls THROUGH into
        # whatever follows, and on x86 that is a real control transfer. Returning
        # instead would skip the callee's `ret` and leave rsp eight bytes low,
        # so the caller resumes reading its own frame one slot out - nothing
        # faults and every value after it is wrong.
        last = insns[-1].mnemonic.split()[-1] if insns else None
        if last not in ('ret', 'retn', 'retf', 'jmp', 'iret', 'iretd', 'iretq', 'hlt'):
            nxt = insns[-1].address + insns[-1].size if insns else end
            out.append('    /* extent ends mid-function: fall through */')
            out.append('    dispatch(c, 0x%Xull); return;' % nxt)

        if has_indirect or has_eh:
            # The local label dispatch. A computed target inside this function
            # becomes a goto; anything else is a real cross-function tail call
            # and goes to the global dispatcher, which is also what catches a
            # jump through an IAT slot.
            out.append('  _ljump:')
            out.append('    switch (_ind) {')
            for a in sorted(labels):
                out.append('      case 0x%Xull: goto L_%012X;' % (a, a))
            out.append('      default: dispatch_jmp(c, _ind); return;')
            out.append('    }')

        out.append('}')
        if has_eh:
            out = [ln.replace('return;', 'ES3_EH_LEAVE(); return;')
                   for ln in out]
        return '\n'.join(out)


# ---- PE plumbing -----------------------------------------------------------
def load_bounds(path):
    """Read an IDA/Ghidra export: `0xADDR  size  name` per line."""
    bounds = {}
    with open(path) as f:
        for line in f:
            if line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) >= 3 and parts[0].startswith('0x'):
                bounds[int(parts[0], 16)] = (int(parts[1], 16), parts[2])
    return bounds


def _pe_sections(data):
    import struct
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    nsec = struct.unpack_from('<H', data, pe + 6)[0]
    optsz = struct.unpack_from('<H', data, pe + 20)[0]
    magic = struct.unpack_from('<H', data, pe + 24)[0]
    if magic != 0x20b:
        raise SystemExit('not a PE32+ (x86-64) image: optional header magic %#x' % magic)
    base = struct.unpack_from('<Q', data, pe + 24 + 24)[0]
    size_of_image = struct.unpack_from('<I', data, pe + 24 + 56)[0]
    secs = []
    off = pe + 24 + optsz
    for i in range(nsec):
        n, vs, va, rs, ra = struct.unpack_from('<8sIIII', data, off + i * 40)
        secs.append((n.rstrip(b'\0').decode(), va, vs, ra, rs))
    return base, size_of_image, secs


def selftest():
    """Lift a hand-assembled function and check the parts that x64 gets wrong.

    Every assertion here is a bug this lifter can plausibly have: the
    zero-extension rule, the RIP anchor, movsxd's signedness, and the shufps
    lane split. A round-trip that merely produces C would pass while being
    wrong about all four.
    """
    lf = Lifter(image_size=0x1000000, image_base=0x140000000)

    #   mov eax, ecx          ; 32-bit write must ZERO the high half
    #   mov rdx, [rip+0x10]   ; RIP anchor is the NEXT instruction
    #   movsxd rax, ecx       ; sign extend, not zero extend
    #   shufps xmm0, xmm1, 0x1B
    #   ret
    code = bytes([
        0x89, 0xC8,                          # mov eax, ecx
        0x48, 0x8B, 0x15, 0x10, 0x00, 0x00, 0x00,   # mov rdx, [rip+0x10]
        0x48, 0x63, 0xC1,                    # movsxd rax, ecx
        0x0F, 0xC6, 0xC1, 0x1B,              # shufps xmm0, xmm1, 0x1B
        0xC3,                                # ret
    ])
    base = 0x140001000
    out = lf.lift_function(code, base)

    assert 'SET32(c->rax' in out, 'mov eax,ecx must use SET32 (zero-extending)'
    assert 'SET64(c->rax, R32' not in out, 'mov eax,ecx must not write 64 bits raw'

    # The rdx load is at 0x140001002 and is 7 bytes, so it ends at 0x140001009;
    # +0x10 makes 0x140001019. An anchor at the START of the instruction would
    # give 0x140001012 - in image, plausible, and the wrong global.
    assert 'GVA(0x140001019)' in out, 'RIP-relative anchor is wrong: %s' % (
        [l for l in out.splitlines() if 'rd64' in l])

    assert '(int64_t)(int32_t)' in out, 'movsxd must sign-extend'

    # shufps 0x1B = 00 01 10 11 -> lanes 3,2 from dst and 1,0 from src.
    assert '_d.u32[3]' in out and '_s.u32[0]' in out, \
        'shufps must take low lanes from dst and high lanes from src'

    # Flags and sizes
    lf2 = Lifter(image_size=0x1000, image_base=0x140000000)
    #   add rax, -1   (48 83 C0 FF) - imm8 sign extended
    out2 = lf2.lift_function(bytes([0x48, 0x83, 0xC0, 0xFF, 0xC3]), 0x140000000)
    assert 'flags_add' in out2 and ', 8)' in out2, 'add rax must be an 8-byte op'

    # push/pop are 64-bit
    out3 = lf2.lift_function(bytes([0x50, 0x58, 0xC3]), 0x140000000)
    assert 'push64' in out3 and 'pop64' in out3

    # A 32-bit register source read must truncate, not read the whole 64.
    assert 'R32(c->rcx)' in out, 'mov eax,ecx must read ecx as 32 bits'

    print('lift64_cpu selftest: ok')


def main():
    global IMAGE_BASE
    if '--selftest' in sys.argv:
        selftest()
        return
    if len(sys.argv) < 4:
        print(__doc__)
        raise SystemExit(2)

    pe_path, funcs_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    want = [int(a, 16) for a in sys.argv[4:]]

    data = open(pe_path, 'rb').read()
    base, size_of_image, secs = _pe_sections(data)
    IMAGE_BASE = base

    def read_va(va, n):
        for (nm, vsa, vs, ra, rs) in secs:
            lo = base + vsa
            if lo <= va < lo + max(vs, rs):
                off = ra + (va - lo)
                return data[off:off + n]
        raise KeyError('va %#x not mapped' % va)

    lf = Lifter(image_size=size_of_image, read_va=read_va, image_base=base)
    bounds = load_bounds(funcs_path)
    todo = want or sorted(bounds)

    bodies = []
    errs = 0
    for va in todo:
        if va not in bounds:
            continue
        size, name = bounds[va]
        try:
            bodies.append(lf.lift_function(read_va(va, size), va))
        except Exception as e:
            errs += 1
            bodies.append('/* ERROR %s at %#x: %s */\nvoid L_%012X(CPU *c) { RECOMP_TODO(%#x, "lift error"); }'
                          % (name, va, e, va, va))

    with open(out_path, 'w') as f:
        f.write('/* generated by lift64_cpu.py - do not edit */\n')
        f.write('#include "cpu64.h"\n\n')
        f.write('\n\n'.join(bodies))
        f.write('\n')
    print('[lift64] %d functions, %d errors -> %s' % (len(bodies), errs, out_path))


if __name__ == '__main__':
    main()

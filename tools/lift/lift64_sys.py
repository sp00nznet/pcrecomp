#!/usr/bin/env python3
"""
lift64_sys.py - lift64_cpu for bare-metal x86-64: an operating system's own code.

lift64_cpu lifts a Win64 user-mode PE. A kernel differs in four ways, and this
subclass adds exactly those, compiled against cpu64.h with RECOMP64_SYSTEM:

  1. Ring-0 instructions. in/out, cli/sti/hlt, rdmsr/wrmsr, mov crN, lgdt/lidt,
     iretq, int n, fxsave... become calls into the host (sys_in, sys_op, ...),
     which models the machine in C. Nothing here executes guest bytes.
  2. fs and gs are guest segment bases (c->fs_base, c->gs_base), not the host
     TEB. A kernel keeps its per-task and per-CPU pointers there.
  3. x87. lift64_cpu leaves it out because the Win64 ABI puts floats in XMM; an
     OS compiler need not (TempleOS's HolyC does all F64 math on the x87
     stack). The x87 translations are lift32_cpu's, borrowed, so there is one
     copy of them; only what differs in long mode is overridden here.
  4. DF and bit strings. A kernel's memmove runs backwards with std, and
     `bts [mem], reg` addresses a bit string, not one operand.

Interrupts are delivered at safe points - calls and backward branches carry
SYS_POLL - which is where a lifted program can take one without splitting an
instruction. A `ret` records the address it popped, and every call site checks
it against its own return address: code that returns somewhere it was not
called from (a pushed address, a hand-made frame) stops and says so rather
than resuming in the wrong place.

Usage (raw image, not a PE):
  python lift64_sys.py --raw <image.bin> <load_va> <funcs.txt> <out.c>
funcs.txt lines: "0xADDR  0xSIZE  name".
"""
import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lift64_cpu
from lift64_cpu import Lifter, reg_read, reg_write, _todo, STRING_OPS64, REP_PREFIXES
import lift32_cpu
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

SIZES = {1: '8', 2: '16', 4: '32', 8: '64'}


class _Reachable:
    """Capstone, except that one call to disasm() can be told the exact
    instruction addresses to decode. Code with data inside it (a switch table
    between two arms) desyncs a linear sweep; decoding only what discovery
    reached cannot."""
    def __init__(self, md):
        self._md, self.only = md, None

    def disasm(self, code, start):
        if self.only is not None:
            only, self.only = self.only, None
            out = []
            for a in sorted(only):
                off = a - start
                ins = next(self._md.disasm(code[off:off + 16], a), None) if 0 <= off < len(code) else None
                if ins is not None and (not out or out[-1].address + out[-1].size <= a):
                    out.append(ins)       # never two instructions over the same bytes
            return out
        return self._md.disasm(code, start)

    def __getattr__(self, k):
        return getattr(self._md, k)


class SysLifter(Lifter):
    dyn_calls = frozenset()   # call sites whose rel32 the guest patches at run time
    dyn_all = False           # every rel32 call: code a JIT made, whose imports resolve later

    # lift32's x87 translations, reused. They read self.addr_expr, self.wr,
    # self.md, self._st_idx and self._fmem, all of which exist here.
    _st_idx = lift32_cpu.Lifter._st_idx
    _fmem = lift32_cpu.Lifter._fmem
    _fpu32 = lift32_cpu.Lifter.fpu

    # ---- segment-relative operands ----------------------------------------
    def _seg_ea(self, insn, op):
        seg = self.seg_name(op)
        if seg in ('fs', 'gs'):
            return '(c->%s_base + %s)' % (seg, self.seg_off(insn, op))
        return None

    def addr_expr(self, insn, op):
        e = self._seg_ea(insn, op)
        return e if e else Lifter.addr_expr(self, insn, op)

    def rd(self, insn, op):
        if op.size not in (1, 2, 4, 8):
            raise self._bad_size(insn, op, 'rd')
        return 'rd%s(%s)' % (SIZES[op.size], self.addr_expr(insn, op))

    def wr(self, insn, op, val):
        if op.size not in (1, 2, 4, 8):
            raise self._bad_size(insn, op, 'wr')
        cast = {1: 'uint8_t', 2: 'uint16_t', 4: 'uint32_t', 8: 'uint64_t'}[op.size]
        return 'wr%s(%s, (%s)(%s));' % (SIZES[op.size], self.addr_expr(insn, op), cast, val)

    # ---- x87 ----------------------------------------------------------------
    def fpu(self, insn):
        m = insn.mnemonic
        ops = insn.operands
        memop = ops[0] if ops and ops[0].type == X86_OP_MEM else None
        if m in ('fist', 'fistp'):
            pop = ' fpop(c);' if m == 'fistp' else ''
            st = {2: 'wri16', 4: 'wri32', 8: 'wri64'}[memop.size]
            return ['%s(%s, fround(c, *fst(c, 0)));%s' % (st, self.addr_expr(insn, memop), pop)]
        if m == 'fisttp':
            st = {2: 'wri16', 4: 'wri32', 8: 'wri64'}[memop.size]
            return ['%s(%s, trunc(*fst(c, 0))); fpop(c);' % (st, self.addr_expr(insn, memop))]
        if m == 'frndint':
            return ['*fst(c, 0) = fround(c, *fst(c, 0));']
        if m == 'fldcw':
            return ['c->fpu_cw = %s;' % self.rd(insn, memop)]
        if m in ('fnstcw', 'fstcw'):
            return [self.wr(insn, memop, 'c->fpu_cw')]
        if m in ('fnstsw', 'fstsw'):
            if ops and ops[0].type == X86_OP_REG:
                return ['SET16(c->rax, fpu_sw_get(c));']
            return [self.wr(insn, ops[0], 'fpu_sw_get(c)')]
        if m in ('fninit', 'finit'):
            return ['c->fpu_top = 0; c->fpu_sw = 0; c->fpu_cw = 0x037F;']
        if m in ('ffree', 'ffreep'):
            return ['fpop(c);' if m == 'ffreep' else '/* ffree */']
        if m in ('fincstp',):
            return ['c->fpu_top = (c->fpu_top + 1) & 7;']
        if m in ('fdecstp',):
            return ['c->fpu_top = (c->fpu_top - 1) & 7;']
        if m == 'fxam':
            return ['{ double _v = *fst(c, 0); uint32_t _sw = c->fpu_sw & ~0x4700u;'
                    ' if (signbit(_v)) _sw |= 0x200u;'
                    ' if (_v != _v) _sw |= 0x100u; else if (isinf(_v)) _sw |= 0x500u;'
                    ' else if (_v == 0.0) _sw |= 0x4000u; else _sw |= 0x400u;'
                    ' c->fpu_sw = _sw; }']
        if m in ('fxsave', 'fxsave64', 'fxrstor', 'fxrstor64'):
            op = 'SYSOP_FXSAVE' if m.startswith('fxsave') else 'SYSOP_FXRSTOR'
            return ['sys_op(c, %s, %s, 0);' % (op, self.addr_expr(insn, memop))]
        out = self._fpu32(insn)
        return [l.replace('c->eax', 'c->rax') for l in out]

    # ---- string ops, with DF ----------------------------------------------
    def string_op(self, insn, parts):
        ea = insn.address
        base = parts[-1]
        pfx = parts[0] if len(parts) > 1 and parts[0] in REP_PREFIXES else None
        width = {'b': 1, 'w': 2, 'd': 4, 'q': 8}.get(base[-1])
        if width is None:
            return [_todo(ea, '%s %s' % (insn.mnemonic, insn.op_str))]
        op = base[:-1]
        rd_, wr_ = 'rd' + SIZES[width], 'wr' + SIZES[width]
        acc = {1: 'R8L(c->rax)', 2: 'R16(c->rax)', 4: 'R32(c->rax)', 8: 'c->rax'}[width]
        st = '_st'
        if op == 'movs':
            body = '%s(c->rdi, %s(c->rsi)); c->rsi += %s; c->rdi += %s;' % (wr_, rd_, st, st)
        elif op == 'stos':
            body = '%s(c->rdi, %s); c->rdi += %s;' % (wr_, acc, st)
        elif op == 'lods':
            body = '%s c->rsi += %s;' % (reg_write({1: 'al', 2: 'ax', 4: 'eax', 8: 'rax'}[width],
                                                   '%s(c->rsi)' % rd_), st)
        elif op == 'scas':
            body = 'flags_sub(c, %s, %s(c->rdi), %d); c->rdi += %s;' % (acc, rd_, width, st)
        elif op == 'cmps':
            body = 'flags_sub(c, %s(c->rsi), %s(c->rdi), %d); c->rsi += %s; c->rdi += %s;' % (
                rd_, rd_, width, st, st)
        else:
            return [_todo(ea, '%s %s' % (insn.mnemonic, insn.op_str))]
        pre = '{ int64_t _st = c->df ? -%d : %d; ' % (width, width)
        if not pfx:
            return [pre + body + ' }']
        if pfx in ('repe', 'repz') and op in ('scas', 'cmps'):
            return [pre + 'while (c->rcx) { c->rcx--; %s if (!c->zf) break; } }' % body]
        if pfx in ('repne', 'repnz') and op in ('scas', 'cmps'):
            return [pre + 'while (c->rcx) { c->rcx--; %s if (c->zf) break; } }' % body]
        # Forward byte/qword copies and fills, the common case, as memmove/memset
        # would be wrong across MMIO, so stay per element; the compiler folds it.
        return [pre + 'while (c->rcx) { c->rcx--; %s } }' % body]

    # ---- the instruction set a kernel adds ----------------------------------
    def translate(self, insn, labels):
        m = insn.mnemonic
        ops = insn.operands
        ea = insn.address
        nxt = ea + insn.size
        if m.startswith('lock '):
            m = m[5:]
        bare = m.split()[-1]

        if m[0] == 'f' and m not in ('fs',):
            return self.fpu(insn)

        if m == 'in':
            sz = ops[0].size
            port = 'R16(c->rdx)' if ops[1].type == X86_OP_REG else '0x%Xu' % ops[1].imm
            return [reg_write(self.rname(ops[0].reg), 'sys_in(c, %s, %d)' % (port, sz))]
        if m == 'out':
            sz = ops[1].size
            port = 'R16(c->rdx)' if ops[0].type == X86_OP_REG else '0x%Xu' % ops[0].imm
            return ['sys_out(c, %s, %s, %d);' % (port, reg_read(self.rname(ops[1].reg)), sz)]
        if bare in ('insb', 'insw', 'insd', 'outsb', 'outsw', 'outsd'):
            w = {'b': 1, 'w': 2, 'd': 4}[bare[-1]]
            rep = m.startswith('rep')
            if bare.startswith('ins'):
                body = 'wr%s(c->rdi, (uint%s_t)sys_in(c, R16(c->rdx), %d)); c->rdi += _st;' % (SIZES[w], SIZES[w], w)
            else:
                body = 'sys_out(c, R16(c->rdx), rd%s(c->rsi), %d); c->rsi += _st;' % (SIZES[w], w)
            pre = '{ int64_t _st = c->df ? -%d : %d; ' % (w, w)
            return [pre + ('while (c->rcx) { c->rcx--; %s } }' % body if rep else body + ' }')]

        if m == 'cli':
            return ['c->ifl = 0;']
        if m == 'sti':
            return ['c->ifl = 1;']
        if m == 'hlt':
            return ['sys_hlt(c);']
        if m == 'cld':
            return ['c->df = 0;']
        if m == 'std':
            return ['c->df = 1;']
        if m == 'pushfq':
            return ['push64(c, rflags_get(c));']
        if m == 'popfq':
            return ['rflags_set(c, pop64(c));']
        if m in ('iretq', 'iretd', 'iret'):
            return ['sys_iret(c); return;']
        if m == 'int3':
            return ['sys_int(c, 3, 0x%Xull); return;' % nxt]
        if m == 'int':
            return ['sys_int(c, %d, 0x%Xull); return;' % (ops[0].imm, nxt)]
        if m == 'ud2':
            return ['sys_op(c, SYSOP_UD2, 0x%Xull, 0); return;' % ea]
        if m in ('rdtsc', 'rdtscp'):
            return ['sys_op(c, SYSOP_RDTSC, 0, 0);']
        if m == 'rdmsr':
            return ['sys_op(c, SYSOP_RDMSR, 0, 0);']
        if m == 'wrmsr':
            return ['sys_op(c, SYSOP_WRMSR, 0, 0);']
        if m in ('lgdt', 'lidt', 'ltr'):
            op = {'lgdt': 'SYSOP_LGDT', 'lidt': 'SYSOP_LIDT', 'ltr': 'SYSOP_LTR'}[m]
            a = self.addr_expr(insn, ops[0]) if ops[0].type == X86_OP_MEM else self.src(insn, ops[0])
            return ['sys_op(c, %s, %s, 0);' % (op, a)]
        if m in ('invlpg', 'clflush', 'clflushopt'):
            return ['/* %s */' % m]
        if m in ('wbinvd', 'invd', 'lfence', 'mfence', 'sfence', 'swapgs', 'clts'):
            return ['/* %s */' % m]
        if m in ('xsave', 'xrstor'):
            return [_todo(ea, m)]
        if m == 'rdrand':
            return [reg_write(self.rname(ops[0].reg), 'sys_rd(c, 100)') + ' c->cf = 1;']
        if m == 'mov' and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
            d, s_ = self.rname(ops[0].reg), self.rname(ops[1].reg)
            if re.match(r'cr\d+$', d):
                return ['sys_op(c, SYSOP_MOVCR, %s, %s);' % (d[2:], reg_read(s_))]
            if re.match(r'cr\d+$', s_):
                return [reg_write(d, 'sys_rd(c, %s)' % s_[2:])]
            if re.match(r'dr\d+$', d) or re.match(r'dr\d+$', s_):
                return ['/* debug register */'] if d.startswith('dr') else [reg_write(d, '0')]
        if m in ('mov', 'push', 'pop') and any(
                o.type == X86_OP_REG and self.rname(o.reg) in ('cs', 'ds', 'es', 'ss', 'fs', 'gs')
                for o in ops):
            # Segment registers: long mode ignores ds/es/ss and the base of
            # fs/gs is set through MSRs, so a selector load changes nothing we
            # model. Reads give the flat data selector.
            if m == 'push':
                return ['push64(c, 0x10);']
            if m == 'pop':
                return ['c->rsp += 8;']
            if ops[0].type == X86_OP_REG and self.rname(ops[0].reg) in ('cs', 'ds', 'es', 'ss', 'fs', 'gs'):
                return ['/* mov %s */' % insn.op_str]
            return [self.dst_write(insn, ops[0], '0x10')]

        # bt family on memory with a register index: a bit string.
        if bare in ('bt', 'bts', 'btr', 'btc') and ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_REG:
            sz = ops[0].size
            bits = sz * 8
            idx = reg_read(self.rname(ops[1].reg))
            sidx = '(int64_t)(int%d_t)%s' % (bits if bits > 8 else 16, idx) if bits < 64 else '(int64_t)%s' % idx
            a = '(%s + (uint64_t)((%s >> %d) * %d))' % (self.addr_expr(insn, ops[0]), sidx,
                                                         {16: 4, 32: 5, 64: 6}[bits], sz)
            n = '((uint64_t)%s & %d)' % (idx, bits - 1)
            r = 'rd%s(_a)' % SIZES[sz]
            if bare == 'bt':
                return ['{ uint64_t _a = %s; op_bt(c, %s, %s, %d); }' % (a, r, n, sz)]
            return ['{ uint64_t _a = %s; wr%s(_a, (uint%s_t)op_%s(c, %s, %s, %d)); }'
                    % (a, SIZES[sz], SIZES[sz], bare, r, n, sz)]

        # Safe points for interrupts, and the return-address check.
        if m == 'call' and (ea in self.dyn_calls or (self.dyn_all and ops[0].type == X86_OP_IMM)):
            # A call whose rel32 the guest's own loader patches later (an
            # import resolved when another module loads): read it at run time.
            return ['SYS_POLL(c);',
                    '{ uint64_t _ct = 0x%Xull + (uint64_t)(int64_t)(int32_t)rd32(0x%Xull);'
                    ' push64(c, 0x%Xull); dispatch(c, _ct); } c->rip = 0x%Xull;' % (nxt, ea + 1, nxt, nxt),
                    'if (c->last_ret != 0x%Xull) sys_ret_mismatch(c, 0x%Xull);' % (nxt, nxt)]
        if m == 'call':
            out = Lifter.translate(self, insn, labels)
            return ['SYS_POLL(c);'] + out + [
                'if (c->last_ret != 0x%Xull) sys_ret_mismatch(c, 0x%Xull);' % (nxt, nxt)]
        if m in ('ret', 'retn'):
            n = ops[0].imm if ops and ops[0].type == X86_OP_IMM else 0
            return ['c->last_ret = rd64(c->rsp); c->rsp += %d; return;' % (8 + n)]
        if (m.startswith('j') or m.startswith('loop')) and ops and ops[0].type == X86_OP_IMM \
                and ops[0].imm <= ea and ops[0].imm in labels:
            return ['SYS_POLL(c);'] + Lifter.translate(self, insn, labels)

        return Lifter.translate(self, insn, labels)


def lift_raw(image, base, funcs, out_path, header='cpu64.h', prefix='', dyn_calls=(), dyn_all=False):
    """Lift `funcs` ({va: (size, name)}) out of a raw image loaded at `base`."""
    def read_va(va, n):
        off = va - base
        if off < 0 or off >= len(image):
            raise KeyError('va %#x not in image' % va)
        return image[off:off + n]
    lf = SysLifter(image_size=len(image), read_va=read_va, image_base=base)
    lf.md = _Reachable(lf.md)
    lf.dyn_calls = frozenset(dyn_calls)
    lf.dyn_all = dyn_all
    bodies, errs = [], 0
    for va in sorted(funcs):
        size, name = funcs[va][:2]
        if len(funcs[va]) > 2 and funcs[va][2] is not None:   # the instructions discovery reached
            lf.md.only = funcs[va][2]
        try:
            bodies.append(lf.lift_function(read_va(va, size), va))
        except Exception as e:
            errs += 1
            bodies.append('/* ERROR %s at %#x: %s */\nvoid L_%012X(CPU *c) { RECOMP_TODO(0x%Xull, "lift error"); }'
                          % (name, va, e, va, va))
    with open(out_path, 'w') as f:
        f.write('/* generated by lift64_sys.py - do not edit */\n#include "%s"\n\n' % header)
        f.write('\n\n'.join(bodies))
        f.write('\n')
    return len(bodies), errs


def main():
    if len(sys.argv) != 6 or sys.argv[1] != '--raw':
        print(__doc__)
        raise SystemExit(2)
    image = open(sys.argv[2], 'rb').read()
    base = int(sys.argv[3], 0)
    funcs = {}
    for line in open(sys.argv[4]):
        p = line.split()
        if len(p) >= 2 and p[0].startswith('0x'):
            funcs[int(p[0], 16)] = (int(p[1], 16), p[2] if len(p) > 2 else '')
    n, e = lift_raw(image, base, funcs, sys.argv[5])
    print('[lift64_sys] %d functions, %d errors -> %s' % (n, e, sys.argv[5]))


if __name__ == '__main__':
    main()

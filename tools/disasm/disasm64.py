#!/usr/bin/env python3
"""
disasm64.py - x86-64 function recovery for PE32+, with no IDA.

The 64-bit sibling of disasm32. It writes the catalog generate64 lifts from
(`--funcs-txt`, `0xADDR size name`) and the JSON score_recovery reads, so the
64-bit path no longer starts from an IDA export.

A 64-bit Windows image carries far more than a 32-bit one about where its code
starts, and the seeds come from that first, heuristics second:

  .pdata     every function with a frame. An entry whose unwind info is
             UNW_FLAG_CHAININFO is a cold or split CHUNK of another function,
             not an entry, and is kept apart - that is most of what made
             generate64 call .pdata "not a function list".
  Guard CF   /guard:cf images (all of Windows) list every address-taken
             function in the load config: callbacks, vtable slots, exports.
  exports, the entry point, DIR64 relocations into code, EH funclets,
             and the int3-padded `jmp rel32` thunks (both from generate64).

Recursive descent from those finds the rest: the frameless leaves .pdata
leaves out are reached by `call rel32`. Within a function it follows jumps and
MSVC's x64 switch (`lea rB,[__ImageBase]; mov r32,[rB+rI*4+tableRVA];
add r,rB; jmp r`, optionally behind a byte index table). A `jmp` to another
known start is a tail call, and decoding stops at any known start.

A function's end is the end of the contiguous code from its start. Chunks
reached by jumps belong to the function but are not counted in its size,
which is how a PDB records them too.

Usage:
  python disasm64.py <image.dll|exe|sys> -o funcs.json [--funcs-txt funcs.txt]
  python disasm64.py --selftest
"""

import argparse
import bisect
import json
import os
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP, CS_GRP_CALL
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lift'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from disasm32 import decode  # noqa: E402
from generate64 import (rva_to_off, reloc_code_pointers, jmp_thunks,  # noqa: E402
                        eh_tables, _fh4_uint)

IMAGE_SCN_MEM_EXECUTE = 0x20000000
TERMINATORS = {'ret', 'retf', 'int3', 'ud2', 'hlt', 'iretq', 'sysret'}
# An undecoded run is cut here, so a missed terminator costs this much, not
# the rest of the section.
MAX_RUN = 0x4000
MAX_TABLE = 4096


class PE64:
    """The parts of a PE32+ this needs: sections, data directories, exports."""

    def __init__(self, data):
        self.data = data
        pe = struct.unpack_from('<I', data, 0x3c)[0]
        nsec = struct.unpack_from('<H', data, pe + 6)[0]
        optsz = struct.unpack_from('<H', data, pe + 20)[0]
        opt = pe + 24
        if struct.unpack_from('<H', data, opt)[0] != 0x20b:
            raise SystemExit('not a PE32+ image')
        self.base = struct.unpack_from('<Q', data, opt + 24)[0]
        self.entry = struct.unpack_from('<I', data, opt + 16)[0]
        ndd = struct.unpack_from('<I', data, opt + 108)[0]
        self.dd = [struct.unpack_from('<II', data, opt + 112 + 8 * i) for i in range(min(ndd, 16))]
        self.dd += [(0, 0)] * (16 - len(self.dd))
        self.secs, self.exec = [], []          # secs: generate64's 5-tuples
        off = opt + optsz
        for i in range(nsec):
            n, vs, va, rs, ra = struct.unpack_from('<8sIIII', data, off + 40 * i)
            chars = struct.unpack_from('<I', data, off + 40 * i + 36)[0]
            self.secs.append((n.rstrip(b'\0').decode('latin-1'), va, vs, ra, rs))
            if chars & IMAGE_SCN_MEM_EXECUTE:
                # Only the bytes on disk: past raw size is zero fill, not code.
                self.exec.append((self.base + va, self.base + va + (min(vs, rs) if vs else rs), ra))
        self.exec.sort()
        self._lo = [e[0] for e in self.exec]

    def exec_range(self, va):
        i = bisect.bisect_right(self._lo, va) - 1
        if i >= 0 and va < self.exec[i][1]:
            return self.exec[i]
        return None

    def read(self, va, n):
        r = self.exec_range(va)
        if r is None:
            return b''
        off = r[2] + (va - r[0])
        return self.data[off:off + min(n, r[1] - va)]

    def u32_rva(self, rva):
        o = rva_to_off(self.secs, rva)
        return struct.unpack_from('<I', self.data, o)[0] if o is not None else None

    def pdata(self):
        """(primary starts, chunk starts) from the exception directory."""
        rva, size = self.dd[3]
        o = rva_to_off(self.secs, rva) if rva else None
        primary, chunks = set(), set()
        if o is None:
            return primary, chunks
        for i in range(size // 12):
            begin, end, unwind = struct.unpack_from('<III', self.data, o + 12 * i)
            if not begin:
                continue
            # Low bit set: UnwindData points at another RUNTIME_FUNCTION, which
            # is a chained chunk spelt the short way.
            uo = None if unwind & 1 else rva_to_off(self.secs, unwind)
            if uo is None or self.data[uo] & 0x20:      # UNW_FLAG_CHAININFO
                chunks.add(self.base + begin)
            else:
                primary.add(self.base + begin)
        return primary, chunks - primary

    def seh_scopes(self):
        """({function start: {__except targets}}, {filter/finally funclets}).

        A __try/__except's handler body is reached only through the scope
        table __C_specific_handler reads, never by a jump, so without this the
        function stops before it. The table follows the handler RVA in the
        unwind info: a count, then {Begin, End, Handler, JumpTarget} RVAs.
        Any personality routine could sit there, so a table is believed only
        when every scope lies inside the function .pdata says it covers.
        """
        rva, size = self.dd[3]
        o = rva_to_off(self.secs, rva) if rva else None
        targets, funclets = {}, set()
        for i in range(size // 12 if o is not None else 0):
            begin, end, unwind = struct.unpack_from('<III', self.data, o + 12 * i)
            uo = None if unwind & 1 else rva_to_off(self.secs, unwind)
            if uo is None or not self.data[uo] & 0x03:      # EHANDLER | UHANDLER
                continue
            if self.data[uo] & 0x20:                        # chained: no handler here
                continue
            lsda = unwind + 4 + ((self.data[uo + 2] + 1) & ~1) * 2 + 4
            n = self.u32_rva(lsda)
            if not n or n > 64:
                continue
            so = rva_to_off(self.secs, lsda + 4)
            if so is None or so + 16 * n > len(self.data):
                continue
            scopes = [struct.unpack_from('<IIII', self.data, so + 16 * k) for k in range(n)]
            if not all(begin <= b < e <= end for b, e, _h, _j in scopes):
                continue
            for _b, _e, h, j in scopes:
                if j and self.exec_range(self.base + j):
                    targets.setdefault(self.base + begin, set()).add(self.base + j)
                if h > 1 and self.exec_range(self.base + h):  # 1: EXCEPTION_EXECUTE_HANDLER
                    funclets.add(self.base + h)
        return targets, funclets

    def guard_cf(self):
        """Every address-taken function, from the load config's CFG table."""
        rva, size = self.dd[10]
        o = rva_to_off(self.secs, rva) if rva else None
        if o is None or size < 0x94:
            return set()
        sz = struct.unpack_from('<I', self.data, o)[0]
        if sz < 0x94:
            return set()
        table, count, flags = struct.unpack_from('<QQI', self.data, o + 0x80)
        if not table or not count:
            return set()
        stride = 4 + ((flags >> 28) & 0xF)              # per-entry metadata bytes
        to = rva_to_off(self.secs, table - self.base)
        if to is None:
            return set()
        return {self.base + struct.unpack_from('<I', self.data, to + i * stride)[0]
                for i in range(count)}

    def exports(self):
        """{va: name} for exports into code (forwarders and data excluded)."""
        rva, size = self.dd[0]
        o = rva_to_off(self.secs, rva) if rva else None
        out = {}
        if o is None:
            return out
        nfun, nnames, afun, anames, aords = struct.unpack_from('<IIIII', self.data, o + 20)
        names = {}
        for i in range(nnames):
            nrva = self.u32_rva(anames + 4 * i)
            ordi = struct.unpack_from('<H', self.data, rva_to_off(self.secs, aords + 2 * i))[0]
            no = rva_to_off(self.secs, nrva)
            names[ordi] = self.data[no:self.data.index(b'\0', no)].decode('latin-1')
        for i in range(nfun):
            f = self.u32_rva(afun + 4 * i)
            if f and self.exec_range(self.base + f):
                out.setdefault(self.base + f, names.get(i, 'ord_%d' % i))
        return out


def looks_like_string(b):
    """Does `b` open with a NUL-terminated ASCII or UTF-16LE string (4+ chars)?

    ntoskrnl keeps string literals in its code sections (PAGE, INIT, .text):
    a relocated pointer to one is a DIR64 into code that is not a function,
    and 2,166 of them were catalogued as functions before this check.
    """
    def text(c):
        return 0x20 <= c < 0x7f or c in (9, 10, 13)
    if b[:1] == b'\0':          # "" or L"": and no function opens `add [rax], al`
        return True
    n = 0
    while n < len(b) and text(b[n]):
        n += 1
    if n >= 4 and n < len(b) and b[n] == 0:
        return True
    n = 0
    while 2 * n + 1 < len(b) and text(b[2 * n]) and b[2 * n + 1] == 0:
        n += 1
    return n >= 4 and b[2 * n:2 * n + 2] == b'\0\0'


def _canon(reg):
    """'eax'/'rax'/'ax' -> 'ax'; 'r9d' -> 'r9'. Same register, any width."""
    if reg[0] == 'r' and reg[1:2].isdigit():
        return reg.rstrip('dwb')
    return reg[1:] if len(reg) == 3 and reg[0] in 're' else reg


class Disassembler64:
    def __init__(self, data):
        self.pe = PE64(data)
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True

    def seeds(self):
        pe = self.pe
        primary, self.chunks = pe.pdata()
        lo, hi = pe.exec[0][0], pe.exec[-1][1]
        ex = pe.exports()
        eh_starts, funclets = eh_tables(pe.data, pe.base, pe.secs)
        self.inner, seh_funclets = pe.seh_scopes()
        funclets = set(funclets) | seh_funclets
        s = {'pdata': primary, 'guard_cf': pe.guard_cf(), 'exports': set(ex),
             'entry': {pe.base + pe.entry} if pe.entry else set(),
             'reloc': reloc_code_pointers(pe.data, pe.base, pe.secs, pe.dd[5][0],
                                          pe.dd[5][1], lo, hi),
             'thunk': jmp_thunks(pe.data, pe.base, pe.secs, lo, hi),
             'funclet': set(funclets)}
        s['reloc'] = {v for v in s['reloc'] if not looks_like_string(pe.read(v, 256))}
        for k in s:
            s[k] = {v for v in s[k] if pe.exec_range(v) and v not in self.chunks}
        return s, ex

    def jump_table(self, fn, jmp):
        """Targets of an MSVC x64 switch ending in `jmp jmp.reg`, or []."""
        prior = sorted(a for a in fn if a < jmp.address)[-16:]
        prior = [fn[a] for a in prior]
        target = _canon(jmp.reg_name(jmp.operands[0].reg))
        bases, load = {}, None
        # imagebase leas, in order. The base is often taken once at the top of
        # a long function (XP x64's ntdll: `lea rdx, [rip-...]` hundreds of
        # bytes before its switches), so every earlier lea counts, not only
        # the last 16 instructions'.
        for ins in [fn[a] for a in sorted(a for a in fn if a < jmp.address)]:
            if ins.mnemonic == 'lea' and ins.operands[1].type == X86_OP_MEM:
                m = ins.operands[1].mem
                if m.base == X86_REG_RIP and m.index == 0 and \
                        ins.address + ins.size + m.disp == self.pe.base:
                    bases[_canon(ins.reg_name(ins.operands[0].reg))] = True
        for ins in reversed(prior):         # mov r32, [rB + rI*4 + table]
            if ins.mnemonic in ('mov', 'movsxd') and len(ins.operands) == 2 and \
                    ins.operands[0].type == X86_OP_REG and ins.operands[1].type == X86_OP_MEM:
                m = ins.operands[1].mem
                if m.scale == 4 and m.base and m.index and \
                        _canon(ins.reg_name(m.base)) in bases:
                    load = ins
                    break
        if load is None:
            return []
        m = load.operands[1].mem
        idx = _canon(load.reg_name(m.index))
        table = self.pe.base + m.disp
        # A byte index table in front: movzx rI, byte [rB + rJ + bytes].
        bytes_at = None
        for ins in reversed(prior):
            if ins.address >= load.address:
                continue
            if ins.mnemonic == 'movzx' and ins.operands[1].type == X86_OP_MEM and \
                    ins.operands[1].size == 1 and \
                    _canon(ins.reg_name(ins.operands[0].reg)) == idx:
                bm = ins.operands[1].mem
                # A byte table indexed by a register: `movzx eax, byte [rB+0x1234]`
                # with no index is a plain load, not the switch's index table
                # (diagtrack.dll on 26100.4349 has one, and it crashed here).
                if bm.base and bm.index and bm.scale == 1 and \
                        _canon(ins.reg_name(bm.base)) in bases:
                    bytes_at, idx = self.pe.base + bm.disp, _canon(ins.reg_name(bm.index))
                break
        bound = None
        for ins in reversed(prior):         # cmp rI, N ; ja default
            if ins.mnemonic == 'cmp' and ins.operands[0].type == X86_OP_REG and \
                    ins.operands[1].type == X86_OP_IMM and \
                    _canon(ins.reg_name(ins.operands[0].reg)) == idx:
                nxt = fn.get(ins.address + ins.size)
                if nxt is not None and nxt.mnemonic in ('ja', 'jae'):
                    bound = ins.operands[1].imm + (1 if nxt.mnemonic == 'ja' else 0)
                break
        _ = target  # the add/jmp register is not needed once the table is found
        n = bound
        if bytes_at is not None:
            if bound is None:
                return []
            raw = self._read_any(bytes_at, bound)
            if len(raw) < bound:
                return []
            n = max(raw) + 1
        out = []
        for i in range(min(n or MAX_TABLE, MAX_TABLE)):
            rva = self.pe.u32_rva(table - self.pe.base + 4 * i)
            if rva is None:
                break
            t = self.pe.base + rva
            if not self.pe.exec_range(t):
                if n is None:
                    break               # unbounded: the table ends where code does
                continue
            out.append(t)
        return out

    def _drops_return(self, va):
        """Does the code at `va` open by popping its own return address?

        No function does: `add rsp, 8` / `lea rsp, [rsp+8]` as the first
        instruction throws away the address it would return to. ntoskrnl's
        RSB-filling loops are 2,304 such call targets.
        """
        ins = next(self.md.disasm(self.pe.read(va, 16), va, 1), None)
        if ins is None or len(ins.operands) != 2 or ins.operands[0].type != X86_OP_REG \
                or ins.reg_name(ins.operands[0].reg) != 'rsp':
            return False
        src = ins.operands[1]
        if ins.mnemonic == 'add':
            return src.type == X86_OP_IMM and src.imm >= 8
        if ins.mnemonic == 'lea':
            return src.type == X86_OP_MEM and ins.reg_name(src.mem.base) == 'rsp' \
                and src.mem.disp >= 8
        return False

    def _padding(self, lo, hi):
        """Is [lo, hi) nothing but int3 and nops (including `0f 1f` forms)?"""
        n = lo
        for ins in self.md.disasm(self.pe.read(lo, hi - lo), lo):
            if ins.mnemonic not in ('int3', 'nop'):
                return False
            n += ins.size
        return n == hi

    def _read_any(self, va, n):
        o = rva_to_off(self.pe.secs, va - self.pe.base)
        return self.pe.data[o:o + n] if o is not None else b''

    def walk(self, start, starts):
        """Decode one function. Returns (insn sizes, calls, tails)."""
        fn, calls, tails = {}, set(), set()
        work, seen = [start] + sorted(self.inner.get(start, ())), set()
        while work:
            a = work.pop()
            if a in seen or a in fn:
                continue
            seen.add(a)
            for ins in decode(self.md, self.pe.read(a, MAX_RUN), a):
                va = ins.address
                if va != a and va in starts:
                    tails.add(va)           # fell through into the next function
                    break
                if va in fn:
                    break
                fn[va] = ins
                m = ins.mnemonic
                if m in TERMINATORS or (m == 'int' and ins.operands[0].imm == 0x29):
                    break
                if ins.group(CS_GRP_CALL):
                    op = ins.operands[0]
                    if op.type == X86_OP_IMM and self.pe.exec_range(op.imm):
                        if self._drops_return(op.imm):
                            # Return-stack stuffing (a Spectre mitigation):
                            # `call` over a trap to code that discards the
                            # return address. A jump, not a function.
                            work.append(op.imm)
                        else:
                            calls.add(op.imm)
                    continue
                if ins.group(CS_GRP_JUMP):
                    op = ins.operands[0]
                    if op.type == X86_OP_IMM:
                        t = op.imm
                        if t != start and t in starts:
                            tails.add(t)
                        elif self.pe.exec_range(t):
                            work.append(t)
                        if m == 'jmp':
                            break
                        continue
                    if op.type == X86_OP_REG:
                        work.extend(self.jump_table(fn, ins))
                    break               # jmp [mem]: an import or a tail call
        return fn, calls, tails

    def find_functions(self, progress=None):
        seeds, names = self.seeds()
        starts = set().union(*seeds.values())
        work = sorted(starts)
        funcs = {}
        while work:
            va = work.pop()
            if va in funcs:
                continue
            fn, calls, tails = self.walk(va, starts)
            # The contiguous run from the start is the function's size; code
            # reached past a gap (a chunk, a shared tail) is not counted. A gap
            # of int3/nop padding is not a gap: MSVC lays out-of-line blocks
            # after an unreached int3, and stopping there cut 3,306 of
            # ntdll's functions short.
            end, later = va, sorted(a for a in fn if a > va)
            i = 0
            while True:
                while end in fn:
                    end += fn[end].size
                i = bisect.bisect_left(later, end, i)
                if i == len(later) or later[i] - end > 32 or \
                        not self._padding(end, later[i]):
                    break
                end = later[i]
            funcs[va] = {'address': va, 'end': end, 'size': end - va,
                         'name': names.get(va, 'sub_%X' % va),
                         'num_instructions': len(fn), 'entry_kind': 'start',
                         'is_thunk': len(fn) == 1 and fn[va].mnemonic == 'jmp',
                         'calls_to': sorted(calls)}
            for t in calls | tails:
                if t not in starts:
                    starts.add(t)
                    work.append(t)
            if progress and len(funcs) % 5000 == 0:
                progress(len(funcs), len(work))
        self.seed_counts = {k: len(v) for k, v in seeds.items()}
        return funcs


def selftest():
    """A hand-built PE32+: a switch, a leaf reached only by call, a tail call,
    and a .pdata chunk that must not become a function."""
    base, text = 0x180000000, 0x1000
    code = bytearray(b'\xcc' * 0x200)
    # 0x1000 f0: cmp ecx,2 ; ja +def ; lea rdx,[rip-X] (=base) ;
    #            mov eax,[rdx+rcx*4+0x1100] ; add rax,rdx ; jmp rax
    f0 = bytearray(b'\x83\xf9\x02' b'\x77\x00')
    lea_at = len(f0)
    f0 += b'\x48\x8d\x15' + b'\0\0\0\0'
    f0 += b'\x8b\x84\x8a' + struct.pack('<I', 0x1200)
    f0 += b'\x48\x01\xd0' b'\xff\xe0'
    def_at = len(f0)
    f0 += b'\xe8' + b'\0\0\0\0' + b'\xc3'                 # default: call leaf ; ret
    case_at = len(f0)
    f0 += b'\x31\xc0\xc3'                                  # case: xor eax,eax ; ret
    f0 += b'\xe9' + b'\0\0\0\0'                            # (unreached filler)
    f0[4] = def_at - 5                                     # ja -> default
    struct.pack_into('<i', f0, lea_at + 3, -(text + lea_at + 7))
    leaf = 0x80
    struct.pack_into('<i', f0, def_at + 1, leaf - (def_at + 5))
    code[:len(f0)] = f0
    code[leaf:leaf + 5] = b'\xe9' + struct.pack('<i', 0xA0 - (leaf + 5))  # tail -> f2
    code[0xA0:0xA4] = b'\x31\xc0\xc3\xcc'                   # f2 (pdata primary)
    code[0xC0:0xC3] = b'\x90\x90\xc3'                       # chunk (pdata chained)
    tbl = struct.pack('<III', text + case_at, text + case_at, text + def_at)
    rdata = bytearray(0x100)
    rdata[0:12] = tbl
    # .rdata at rva 0x1200: table, .pdata (+0x40), unwind infos (+0x80)
    unw_plain = 0x1280
    unw_chain = 0x1290
    rdata[0x80:0x84] = b'\x01\x00\x00\x00'                  # ver 1, no flags
    rdata[0x90:0x94] = b'\x21\x00\x00\x00'                  # ver 1, CHAININFO
    pdata = struct.pack('<III', text, text + 0x40, unw_plain) + \
        struct.pack('<III', text + 0xA0, text + 0xA4, unw_plain) + \
        struct.pack('<III', text + 0xC0, text + 0xC3, unw_chain)
    rdata[0x40:0x40 + len(pdata)] = pdata
    hdr = bytearray(0x400)
    struct.pack_into('<I', hdr, 0x3c, 0x80)
    hdr[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HH', hdr, 0x84, 0x8664, 2)
    struct.pack_into('<H', hdr, 0x94, 0xF0)
    opt = 0x98
    struct.pack_into('<H', hdr, opt, 0x20b)
    struct.pack_into('<I', hdr, opt + 16, text)
    struct.pack_into('<Q', hdr, opt + 24, base)
    struct.pack_into('<I', hdr, opt + 108, 16)
    struct.pack_into('<II', hdr, opt + 112 + 3 * 8, 0x1240, len(pdata))
    sh = opt + 0xF0
    struct.pack_into('<8sIIII', hdr, sh, b'.text', 0x200, text, 0x200, 0x400)
    struct.pack_into('<I', hdr, sh + 36, 0x60000020)
    struct.pack_into('<8sIIII', hdr, sh + 40, b'.rdata', 0x100, 0x1200, 0x100, 0x600)
    struct.pack_into('<I', hdr, sh + 40 + 36, 0x40000040)
    img = bytes(hdr) + bytes(code) + bytes(rdata)
    d = Disassembler64(img)
    funcs = d.find_functions()
    got = sorted(f - base for f in funcs)
    assert got == [0x1000, 0x1080, 0x10A0], [hex(g) for g in got]
    f0r = funcs[base + text]
    assert f0r['end'] == base + text + case_at + 3, hex(f0r['end'])   # case reached via table
    assert base + text + leaf in f0r['calls_to']
    assert base + text + 0xC0 not in funcs                           # chunk, not a function
    assert _canon('r9d') == 'r9' and _canon('eax') == _canon('rax') == 'ax'
    assert looks_like_string(b'PAGE\0') and looks_like_string('Event\0'.encode('utf-16le'))
    assert not looks_like_string(b'\x48\x89\x5c\x24\x08\x57\x48\x83\xec\x20')  # a prologue
    d.pe.data = d.pe.data[:0x400 + 0x100] + b'\x48\x83\xc4\x08' + d.pe.data[0x404 + 0x100:]
    assert d._drops_return(base + text + 0x100)                     # add rsp, 8
    assert not d._drops_return(base + text + 0xA0)                  # xor eax, eax
    # FH4 compressed ints: 1, 2, 3, 4 and 5-byte forms
    assert _fh4_uint(b'\x0a', 0) == (5, 1)
    assert _fh4_uint(b'\x05\x01', 0) == (0x41, 2)
    assert _fh4_uint(b'\x0b\x00\x01', 0) == (0x2001, 3)
    assert _fh4_uint(b'\x17\x00\x00\x01', 0) == (0x100001, 4)
    assert _fh4_uint(b'\x0f\x78\x56\x34\x12', 0) == (0x12345678, 5)
    print('disasm64 selftest: ok')


def main(argv=None):
    ap = argparse.ArgumentParser(description='x86-64 PE function recovery (pcrecomp).')
    ap.add_argument('image', nargs='?')
    ap.add_argument('-o', '--output', help='catalog JSON (score_recovery shape)')
    ap.add_argument('--funcs-txt', help='generate64 catalog: 0xADDR size name')
    ap.add_argument('--selftest', action='store_true')
    a = ap.parse_args(argv)
    if a.selftest:
        selftest()
        return 0
    if not a.image:
        ap.error('an image is required (or --selftest)')
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, OSError):
        pass
    d = Disassembler64(open(a.image, 'rb').read())
    funcs = d.find_functions(lambda n, q: print('[*] %d functions, %d queued' % (n, q)))
    fl = sorted(funcs.values(), key=lambda f: f['address'])
    code = sum(hi - lo for lo, hi, _ in d.pe.exec)
    print('[*] %s: base=%#x, %d exec sections, %s code bytes'
          % (os.path.basename(a.image), d.pe.base, len(d.pe.exec), format(code, ',')))
    print('[*] seeds: ' + ', '.join('%s=%d' % kv for kv in d.seed_counts.items())
          + ', chunks=%d' % len(d.chunks))
    print('[*] functions: %d (%d thunks)' % (len(fl), sum(f['is_thunk'] for f in fl)))
    if a.output:
        with open(a.output, 'w') as f:
            json.dump({'exe': os.path.basename(a.image), 'image_base': d.pe.base,
                       'functions': fl}, f, indent=0)
    if a.funcs_txt:
        with open(a.funcs_txt, 'w') as f:
            for fn in fl:
                if fn['size']:
                    f.write('0x%X %x %s\n' % (fn['address'], fn['size'], fn['name']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

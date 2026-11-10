"""
ne_codemap.py - Build an NE code map natively, with no IDA.

Emits the same shape tools/ida/ida_export.py does -- per CODE segment, keyed by
the module's own NE segment number:

    {"3": {"functions": [...], "heads": [...], "code_ranges": [[s, e], ...]}}

so ne_decode / ne_link consume it unchanged. ne_decode.load_ida_data builds
one with this module whenever no exported map is given, which makes it the
default.

How it finds code (recursive descent; a linear sweep decodes data as code),
strongest evidence first, so a later guess can never overwrite it:
  1. What Windows calls, decoded unconditionally: the header CS:IP and every
     entry-table export, plus any --seeds. From each, follow fall-through,
     conditional and unconditional relative branches, near calls (function
     entries), far calls/jumps a relocation resolves into this module, and
     jump tables (`jmp cs:[bx+tbl]`) read out of the code segment, bounded by
     the `cmp` on the register that indexes them (or, unbounded, ending at
     the first case they point to), MSC's sparse `mov cx,N / mov bx,VALUES`
     form included. Table bytes are marked data.
  2. Speculative seeds, each decoded as one transaction and kept only if all
     it reaches decodes cleanly, lands on no byte already claimed and holds no
     `00 00` (`add [bx+si],al`: zeros, not code):
       - far-pointer relocation targets (window procs and callbacks in data,
         far calls from code the descent has not reached yet). Speculative
         because MSC C++ keeps EH records -- far pointers and all -- in CS;
       - prologues in bytes still unclaimed: MSC/Borland `push bp; mov bp,sp`,
         the exported far forms `inc bp; push bp; mov bp,sp` behind
         `push ds; pop ax; nop` / `mov ax,ds|ss; nop`, the frameless
         `mov ax,ds; nop; push ds; mov ds,ax`, and `enter`;
       - OFFSET relocations into code (Borland EH catch handlers, near method
         tables) and the offset beside a SELECTOR one (`push seg fn / push
         offset fn` for MakeProcInstance and friends);
       - the first byte behind every ret/retf/jmp, past alignment fill and
         Turbo Pascal string literals: code nothing references, which is how
         IDA's final pass finds Borland's RTL too.

Scored against IDA's exports (tools/ne/test_ne_codemap.py): instruction heads
agree to 98.5-100% both ways on Bermuda, CivNet, Space Bucks and Jazz.

    python tools/ne/ne_codemap.py GAME.EXE map.json
"""
import heapq
import json
import os
import re
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'disasm'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from decode16 import Decoder, OpType   # noqa: E402
from ne_parse import parse_ne          # noqa: E402

_STOP = frozenset(('ret', 'retf', 'iret', 'hlt'))
# Prologues, longest first so a far export is entered at its first byte.
_PROLOGUES = [re.compile(p, re.S) for p in (
    rb'\x1E\x58\x90\x45\x55\x8B\xEC',      # push ds; pop ax; nop; inc bp; push bp; mov bp,sp
    rb'\x8C\xD8\x90\x45\x55\x8B\xEC',      # mov ax,ds; nop; inc bp; ...
    rb'\x8C\xD0\x90\x45\x55\x8B\xEC',      # mov ax,ss; nop; inc bp; ... (SS == DGROUP)
    rb'\x8C[\xD0\xD8]\x90\x1E\x8E\xD8',    # mov ax,ss|ds; nop; push ds; mov ds,ax (no frame)
    rb'\x45\x55\x8B\xEC',                  # inc bp; push bp; mov bp,sp (far frame)
    rb'\x55\x8B\xEC',                      # push bp; mov bp,sp
    rb'\x55\x89\xE5',                      # same, other encoding
    rb'\xC8[\x00-\xff][\x00-\xff][\x00\x01]',   # enter n, 0|1
)]


class _Bad(Exception):
    """A speculative seed reached something that is not code."""


class _Seg:
    def __init__(self, seg):
        self.seg = seg
        self.data = seg.data
        self.dec = Decoder(seg.data, base_offset=0)
        self.owner = bytearray(len(seg.data))   # 0 free, 1 code, 2 data
        self.heads = {}                          # off -> length
        self.funcs = set()
        self.weak = set()                        # entries guessed from layout alone
        self.branched = set()                    # relative jump targets
        self.relocs = {}                         # fixup site -> Relocation
        for r in seg.relocations:
            off, seen = r.offset, set()
            while 0 <= off < len(seg.data) - 1 and off not in seen:
                seen.add(off)
                self.relocs[off] = r
                if r.additive:
                    break
                off = struct.unpack_from('<H', seg.data, off)[0]
                if off == 0xFFFF:
                    break


class CodeMap:
    def __init__(self, ne, seeds=()):
        self.ne = ne
        self.seeds = list(seeds)                 # (seg, off, True), global numbering
        self.segs = {s.index: _Seg(s) for s in ne.segments if s.is_code and s.data}

    # -- decoding ---------------------------------------------------------
    def _decode(self, s, off):
        s.dec.pos = off
        try:
            inst = s.dec.decode_one()
        except (IndexError, KeyError):
            return None
        if inst is None or inst.mnemonic in ('db', '?') or inst.mnemonic.startswith('grp4_'):
            return None
        return inst

    def _far_target(self, s, off, inst):
        """(seg, off) a direct far call/jmp at `off` resolves to, or None."""
        r = s.relocs.get(off + 1)
        if r is not None and (r.flags & 3) == 0 and r.src_type in (3, 11):
            return r.target_seg, r.target_off
        r = s.relocs.get(off + 3)
        if r is not None and (r.flags & 3) == 0 and r.src_type == 2:
            return r.target_seg, inst.op1.disp & 0xFFFF
        return None

    def _table(self, s, off, inst, recent):
        """[(site, target)] of a jump table `jmp cs:[bx+tbl]` reads, and the
        [site] of any value table beside it, or ([], [])."""
        op = inst.op1
        if op is None or op.type != OpType.MEM or op.size != 2 or op.base != 'bx' or op.index:
            return [], []
        if op.seg not in ('', 'cs'):
            return [], []
        imm = {}                         # the last `mov reg, imm16` per register
        n = None
        for prev in recent[-12:]:
            if (prev.mnemonic == 'mov' and prev.op1 is not None and prev.op1.type == OpType.REG16
                    and prev.op2 is not None and prev.op2.type == OpType.IMM16):
                imm[prev.op1.reg] = prev.op2.disp & 0xFFFF
            elif (prev.op1 is not None and prev.op1.type == OpType.REG16
                    and prev.mnemonic not in ('cmp', 'test', 'push')):
                imm.pop(prev.op1.reg, None)       # overwritten: no longer that constant
        # The bound: `cmp idx, N` on the register that ends up in bx, found by
        # walking back through `shl/add bx` and `mov bx, reg`. A cmp on anything
        # else (or one older than bx's last load) bounds some other test.
        idx = 3
        for prev in reversed(recent[-12:-1]):
            o1, o2 = prev.op1, prev.op2
            if o1 is None or o1.type != OpType.REG16 or o1.reg != idx:
                continue
            if prev.mnemonic == 'cmp':
                if o2 is not None and o2.type in (OpType.IMM8, OpType.IMM16):
                    n = (o2.disp & 0xFFFF) + 1
                break
            if prev.mnemonic in ('mov', 'xchg') and o2 is not None and o2.type == OpType.REG16:
                idx = o2.reg
            elif prev.mnemonic not in ('shl', 'sal', 'add', 'dec', 'inc', 'sub', 'and', 'test'):
                break
        disp = op.disp & 0xFFFF
        values = []
        if 3 in imm and 1 in imm and disp == 2 * imm[1]:
            # MSC's sparse switch: `mov cx, N / mov bx, VALUES / scan cs:[bx] /
            # jmp cs:[bx+2N]` -- N case values, then N targets.
            n, tbl = imm[1], imm[3] + disp
            values = [imm[3] + 2 * k for k in range(n)]
        elif 3 in imm or (n is None and inst.raw[inst.raw.index(0xFF) + 1] >> 6 == 1):
            # bx is a pointer, not an index: `jmp cs:[bx+6]` with an 8-bit
            # displacement calls through a field of a structure (Oddballz); a
            # table the linker placed at 0xB7 is still encoded with 16 bits
            return [], []
        else:
            tbl = disp
        bounded = n is not None and n <= 512
        out, lo = [], len(s.data)
        for k in range(n if bounded else 512):
            p = tbl + 2 * k
            # Unbounded, the table ends at the first case it points to (MSC
            # puts the cases right behind it) or at code already decoded.
            if p + 2 > len(s.data) or (not bounded and (s.owner[p] == 1 or tbl < lo <= p)):
                break
            t = s.data[p] | s.data[p + 1] << 8
            if t >= len(s.data) or (not bounded and tbl <= t < p + 2):
                break
            lo = min(lo, t)
            out.append((p, t))
        return out, values

    def _run(self, work, spec, log):
        """Decode from every (seg, off, is_func) in `work`, appending what it
        claims to `log`. With `spec`, raise _Bad on anything that is not clean
        code; the caller undoes `log`."""
        while work:
            sidx, off, is_func, *ctx = work.pop()
            s = self.segs.get(sidx)
            if s is None or not 0 <= off < len(s.data):
                if spec:
                    raise _Bad('outside', sidx, off)
                continue
            if is_func:
                log.append(('w' if is_func == 2 else 'f', s, off, 0))
            recent = list(ctx[0]) if ctx else []   # the path here: jump-table guards
            if len(ctx) > 1 and off not in s.heads:
                # A jump-table entry is a guess at the table's extent: one that
                # lands inside an instruction is past the table's end (or an
                # unused slot), not evidence that the function is data.
                first = self._decode(s, off)
                if first is None or any(s.owner[off:off + first.length]):
                    continue
            while True:
                if off in s.heads:
                    break
                if off >= len(s.data) or s.owner[off]:
                    if spec:
                        raise _Bad('overlap', sidx, off)
                    break                     # runs into an instruction or data
                inst = self._decode(s, off)
                if inst is None or off + inst.length > len(s.data) or \
                        any(s.owner[off:off + inst.length]) or \
                        spec and inst.raw[:2] == b'\x00\x00':  # add [bx+si],al: zeros, not code
                    if spec:
                        raise _Bad('undecodable', sidx, off)
                    break
                s.heads[off] = inst.length
                s.owner[off:off + inst.length] = b'\x01' * inst.length
                log.append(('h', s, off, inst.length))
                recent.append(inst)
                m, op = inst.mnemonic, inst.op1
                nxt = off + inst.length
                if op is not None and op.type in (OpType.REL8, OpType.REL16):
                    t = op.disp
                    if spec and not 0 <= t < len(s.data):
                        raise _Bad('branch out of segment', sidx, off)
                    if m == 'call':
                        work.append((sidx, t, True))
                    else:
                        work.append((sidx, t, False, recent[-12:]))
                        log.append(('j', s, t, 0))
                        if m == 'jmp':
                            break
                elif op is not None and op.type == OpType.FAR:
                    tgt = self._far_target(s, off, inst)
                    if tgt is not None and tgt[0] in self.segs:
                        work.append((tgt[0], tgt[1], m == 'call'))
                    if m == 'jmp':
                        break
                elif m == 'jmp' or m == 'jmp far':
                    tgts, values = self._table(s, off, inst, recent)
                    for p in [p for p, _ in tgts] + values:
                        if p + 2 <= len(s.data) and not s.owner[p] and not s.owner[p + 1]:
                            s.owner[p:p + 2] = b'\x02\x02'
                            log.append(('d', s, p, 2))
                    # lowest first: of two entries a byte apart the lower is the case
                    work.extend((sidx, t, False, recent[-12:], True)
                                for t in sorted({t for _, t in tgts}, reverse=True))
                    break
                elif m in _STOP or (m == 'int' and op is not None and (op.disp & 0xFF) == 0x20):
                    break
                off = nxt

    def _seed(self, items, spec, follow=False):
        """Decode from each item, lowest address first. With `follow`, every
        accepted run also queues the bytes behind its own terminators, so a
        chain of switch cases (each ending in a jmp) is walked in one call."""
        todo = list(set(items))
        heapq.heapify(todo)
        while todo:
            item = heapq.heappop(todo)
            s = self.segs.get(item[0])
            if spec and s is not None and item[1] in s.heads:
                continue        # a label already decoded: evidence of nothing new
            log = []
            try:
                self._run([item], spec, log)
            except _Bad:
                for kind, s, off, n in log:    # undo the transaction
                    if kind == 'h':
                        del s.heads[off]
                    s.owner[off:off + n] = bytes(n)
                continue
            for kind, s, off, n in log:
                if kind == 'f':
                    s.funcs.add(off)
                elif kind == 'w':
                    s.weak.add(off)
                elif kind == 'j':
                    s.branched.add(off)
            if follow:
                for nxt in self._behind((s.seg.index, off, n) for kind, s, off, n in log if kind == 'h'):
                    heapq.heappush(todo, nxt)

    # -- seeds ------------------------------------------------------------
    def authoritative(self):
        """What Windows itself calls: CS:IP and every entry-table export."""
        ne, out = self.ne, []
        if ne.cs:
            out.append((ne.cs, ne.ip, True))
        for e in ne.entries or ():
            if e.segment in self.segs:
                out.append((e.segment, e.offset, True))
        return out

    def relocated(self, src_types):
        """Internal relocation targets in a code segment, from fixups of the
        given kinds anywhere in the module. Not authoritative: MSC C++ keeps
        its EH records in the code segment, far pointers and all, so a target
        can be a data record that only a descent from real code tells apart."""
        out = []
        for seg in self.ne.segments:
            sites = self.segs[seg.index].relocs if seg.index in self.segs else _Seg(seg).relocs
            for site, r in sites.items():
                if (r.flags & 3) or r.target_seg not in self.segs or r.src_type not in src_types:
                    continue
                if r.src_type != 2:
                    out.append((r.target_seg, r.target_off, True))
                    continue
                # push seg fn / push offset fn, or mov ax,seg fn / mov dx,offset fn:
                # the offset is the imm16 of the instruction before or after.
                for p in (site - 3, site + 3):
                    if 1 <= p and p + 2 <= len(seg.data) and seg.data[p - 1] in (0x68, 0xB8, 0xB9, 0xBA, 0xBB, 0xBE, 0xBF):
                        out.append((r.target_seg, seg.data[p] | seg.data[p + 1] << 8, True))
        return out

    def after_terminators(self):
        """The first free byte after each ret/retf/iret/jmp, past alignment
        fill. Code nothing references -- Borland's RTL is full of it, reached
        only through computed calls -- still sits right behind the previous
        function; IDA's final pass finds it this way too."""
        return self._behind((i, h, n) for i, s in self.segs.items() for h, n in s.heads.items())

    def _behind(self, heads):
        out = []
        for sidx, h, n in heads:
            s = self.segs[sidx]
            d = s.data
            b = h
            while b < h + n and d[b] in (0x26, 0x2E, 0x36, 0x3E, 0xF2, 0xF3):
                b += 1
            op = d[b]
            if not (op in (0xC2, 0xC3, 0xCA, 0xCB, 0xCF, 0xE9, 0xEA, 0xEB)
                    or op == 0xFF and b + 1 < len(d) and (d[b + 1] >> 3) & 7 in (4, 5)):
                continue
            p = h + n
            while p < len(d) and not s.owner[p]:
                if p < h + n + 16 and d[p] in (0x00, 0x90, 0xCC):
                    p += 1              # alignment fill
                elif 1 <= d[p] <= 80 and all(0x20 <= c < 0x7F for c in d[p + 1:p + 1 + d[p]]) \
                        and p + 1 + d[p] <= len(d):
                    p += 1 + d[p]       # a Turbo Pascal string literal, kept in CS
                else:
                    break
            if p < len(d) and not s.owner[p]:
                # behind a return: a new function; behind a jmp: more often
                # the rest of this one (an else arm reached some other way)
                out.append((sidx, p, 2 if op in (0xC2, 0xC3, 0xCA, 0xCB, 0xCF) else 0))
        return out

    def prologues(self):
        out = []
        for sidx, s in self.segs.items():
            for pat in _PROLOGUES:
                for mt in pat.finditer(s.data):
                    o = mt.start()
                    if not any(s.owner[o:mt.end()]):
                        out.append((sidx, o, True))
        return out

    def build(self):
        # Strongest evidence first: what a later seed may not overwrite.
        self._seed(self.authoritative() + self.seeds, False)
        self._seed(self.relocated((3, 11)), True)       # far pointers
        for _ in range(4):                    # a prologue found can reveal more
            before = sum(len(s.heads) for s in self.segs.values())
            self._seed(self.prologues(), True)
            if sum(len(s.heads) for s in self.segs.values()) == before:
                break
        self._seed(self.relocated((5, 13, 2)), True)    # offsets, seg+imm pairs
        self._seed(self.after_terminators(), True, follow=True)
        return self.result()

    def result(self):
        out = {}
        for sidx, s in self.segs.items():
            heads = sorted(s.heads)
            ranges = []
            for h in heads:
                e = h + s.heads[h]
                if ranges and ranges[-1][1] == h:
                    ranges[-1][1] = e
                else:
                    ranges.append([h, e])
            # A layout guess that something jumps to is the rest of a function.
            funcs = sorted(f for f in s.funcs | (s.weak - s.branched) if f in s.heads)
            out[str(sidx - self.ne.seg_base)] = {
                'functions': funcs, 'heads': heads, 'code_ranges': ranges}
        return out


def build(ne, seeds=()):
    """The code map for one parsed NE module (see module docstring). `seeds`:
    extra (module-local segment, offset) function entries, taken as given --
    the targets of indirect calls a run found missing (ne_link --seeds)."""
    return CodeMap(ne, [(seg + ne.seg_base, off, True) for seg, off in seeds]).build()


def main():
    if len(sys.argv) != 3:
        raise SystemExit('usage: ne_codemap.py <module.exe|dll> <out.json>')
    m = build(parse_ne(sys.argv[1]))
    with open(sys.argv[2], 'w', encoding='utf-8') as f:
        json.dump(m, f)
    print(f'Wrote {sys.argv[2]}: {len(m)} code segments, '
          f'{sum(len(v["functions"]) for v in m.values())} functions, '
          f'{sum(len(v["heads"]) for v in m.values())} code heads (native)')


if __name__ == '__main__':
    main()

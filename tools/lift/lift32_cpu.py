#!/usr/bin/env python3
"""
lift32_cpu.py - mechanical x86-32 -> C static recompiler, CPU-struct model.

Disassembles a function (capstone) and emits `void L_<addr>(CPU *c)` against the
runtime in runtime/recomp32_cpu/cpu.h, one C statement per x86 instruction.
Calls and returns are modelled on the emulated stack exactly like x86 (the
caller pushes a return slot, the callee's `ret` pops it), so stack layout and
argument access match the original byte for byte.

How this differs from lift32.py (the other x86-32 lifter here):

  lift32.py       global registers (g_eax), PUSH32/MEM32 macros, RECOMP_CALL
                  dispatch. Simple and fast to read; one implicit machine.
  lift32_cpu.py   explicit `CPU *c` passed down. Reentrant - several machine
                  states can be live at once, which is what a HYBRID build needs
                  when real library code calls back into lifted code while an
                  outer lifted call is still on the stack (runtime/hybrid).

Also here and not in lift32.py:

  * `.reloc`-driven relocation. Address immediates AND absolute displacements
    inside memory operands are wrapped in GVA() so the output is correct at any
    load base. `mov dl, [ecx + 0x56d902]` is a table lookup at an absolute
    address just as much as `mov eax, [0x58d428]` is - the presence of a base
    register says nothing about it, and the reloc table is the authority.
  * `fs:` segment access -> __readfsdword/__writefsdword, so SEH prologues work.
  * x87 FPU as a register stack of doubles.

Usage:
  py -3.11 lift32_cpu.py <pe-file> <funcs.txt> <out.c> [0xADDR ...]

funcs.txt lines: "0xADDR  size  name" (IDA/Ghidra export), used for bounds.
With no addresses given, lifts every function in funcs.txt.
"""
import sys, re
from capstone import *
from capstone.x86 import *

IMAGE_BASE = 0x11000000   # overridden from the PE's ImageBase in main()

# ---- register field mapping ----
R32 = {"eax","ecx","edx","ebx","esp","ebp","esi","edi"}
R16 = {"ax":"eax","cx":"ecx","dx":"edx","bx":"ebx","sp":"esp","bp":"ebp","si":"esi","di":"edi"}
R8L = {"al":"eax","cl":"ecx","dl":"edx","bl":"ebx"}
R8H = {"ah":"eax","ch":"ecx","dh":"edx","bh":"ebx"}
# Segment registers. A flat PE never touches these, but segmented 32-bit code
# does - IR32.DLL's decode core loads DS and ES constantly - and without them
# every function containing one fails to lift at all. See cpu.h: they are
# storage only, and do not take part in addressing.
SEG = {"cs","ds","es","fs","gs","ss"}

def reg_read(name):
    if name in R32: return f"c->{name}"
    if name in R16: return f"R16(c->{R16[name]})"
    if name in R8L: return f"R8L(c->{R8L[name]})"
    if name in R8H: return f"R8H(c->{R8H[name]})"
    if name in SEG: return f"c->{name}"
    raise NotImplementedError(f"reg_read {name}")

def reg_write(name, val):
    if name in R32: return f"c->{name} = (uint32_t)({val});"
    if name in R16: return f"SET16(c->{R16[name]}, {val});"
    if name in R8L: return f"SET8L(c->{R8L[name]}, {val});"
    if name in R8H: return f"SET8H(c->{R8H[name]}, {val});"
    if name in SEG: return f"c->{name} = (uint16_t)({val});"
    raise NotImplementedError(f"reg_write {name}")

def reg_size(name):
    if name in R32: return 4
    if name in R16 or name in SEG: return 2
    return 1

class Lifter:
    def __init__(self, dll_path, image_size, read_va=None):
        self.image_lo = IMAGE_BASE
        self.image_hi = IMAGE_BASE + image_size
        self.read_va = read_va           # (va, n) -> bytes
        self.func_start = 0
        self.func_end = 0
        self.jumptables = {}             # jmp ea -> [target VAs]
        self.reloc_vas = set()           # VAs of relocatable address immediates
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True

    def resolve_jumptable(self, table_va):
        """Read consecutive dword targets from a jump table that point within
        the current function; stop at the first that doesn't (heuristic)."""
        targets = []
        if not self.read_va:
            return targets
        for i in range(256):
            try:
                raw = self.read_va(table_va + 4 * i, 4)
            except Exception:
                break
            t = int.from_bytes(raw, "little")
            if self.func_start <= t < self.func_end:
                targets.append(t)
            else:
                break
        return targets

    def in_image(self, a):
        return self.image_lo <= (a & 0xffffffff) < self.image_hi

    def disp_is_addr(self, insn, d):
        """Is a memory operand's displacement an absolute address (needs GVA) or
        a plain constant offset? `.reloc` marks exactly the former, and it marks
        them whether or not the operand also has a base register - `mov dl,
        [ecx + 0x56d902]` indexes a table at an absolute address just as much as
        `mov eax, [0x58d428]` does. Fall back to a range check only when we have
        no reloc table at all."""
        enc = getattr(insn, "encoding", None)
        do = getattr(enc, "disp_offset", 0) if enc else 0
        if self.reloc_vas and do:
            return ((insn.address + do) & 0xffffffff) in self.reloc_vas
        return self.in_image(d)

    # ---- operand rendering ----
    def addr_expr(self, insn, op):
        m = op.mem
        terms = []
        base = self.md.reg_name(m.base) if m.base else None
        index = self.md.reg_name(m.index) if m.index else None
        d = m.disp & 0xffffffff
        if base: terms.append(f"c->{base}")
        if index: terms.append(f"c->{index}*{m.scale}")
        if d or not terms:
            terms.append(f"GVA(0x{d:08X})" if self.disp_is_addr(insn, d) else f"0x{d:08X}u")
        return "(" + " + ".join(terms) + ")"

    def seg_name(self, op):
        seg = getattr(op.mem, "segment", 0)
        return self.md.reg_name(seg) if seg else None

    def seg_off(self, insn, op):
        """raw segment offset (base+index+disp, NOT image-relative / no GVA)"""
        m = op.mem
        terms = []
        if m.base:  terms.append(f"c->{self.md.reg_name(m.base)}")
        if m.index: terms.append(f"c->{self.md.reg_name(m.index)}*{m.scale}")
        d = m.disp & 0xffffffff
        if d or not terms: terms.append(f"0x{d:08X}u")
        return "(" + " + ".join(terms) + ")"

    def rd(self, insn, op):
        sz = op.size
        if self.seg_name(op) == "fs":   # TIB-relative (SEH chain etc.) -> real fs
            off = self.seg_off(insn, op)
            return {1:f"__readfsbyte({off})",2:f"__readfsword({off})",4:f"__readfsdword({off})"}[sz]
        a = self.addr_expr(insn, op)
        return {1:f"rd8({a})", 2:f"rd16({a})", 4:f"rd32({a})"}[sz]

    def wr(self, insn, op, val):
        sz = op.size
        if self.seg_name(op) == "fs":
            off = self.seg_off(insn, op)
            return {1:f"__writefsbyte({off}, {val});",2:f"__writefsword({off}, (unsigned short)({val}));",
                    4:f"__writefsdword({off}, {val});"}[sz]
        a = self.addr_expr(insn, op)
        return {1:f"wr8({a}, {val});", 2:f"wr16({a}, {val});", 4:f"wr32({a}, {val});"}[sz]

    def src(self, insn, op):
        """read value of an operand"""
        if op.type == X86_OP_REG: return reg_read(self.md.reg_name(op.reg))
        if op.type == X86_OP_IMM:
            sz = op.size
            mask = {1:0xFF,2:0xFFFF,4:0xFFFFFFFF}[sz]
            v = op.imm & mask
            # a 4-byte immediate sitting at a relocated VA is an absolute address
            # (e.g. `push offset table`); emit GVA so it tracks the load base.
            if sz == 4 and self.reloc_vas:
                enc = getattr(insn, "encoding", None)
                io = getattr(enc, "imm_offset", 0) if enc else 0
                if io and ((insn.address + io) & 0xffffffff) in self.reloc_vas:
                    return f"GVA(0x{v:08X})"
            return f"0x{v:X}u"
        if op.type == X86_OP_MEM: return self.rd(insn, op)
        raise NotImplementedError("src type")

    def dst_write(self, insn, op, val):
        if op.type == X86_OP_REG: return reg_write(self.md.reg_name(op.reg), val)
        if op.type == X86_OP_MEM: return self.wr(insn, op, val)
        raise NotImplementedError("dst type")

    def op_size(self, insn, op):
        return op.size

    # ---- per-instruction translation ----
    def translate(self, insn, labels):
        m = insn.mnemonic
        ops = insn.operands
        ea = insn.address
        nxt = insn.address + insn.size

        def two(): return ops[0], ops[1]
        def sz0(): return ops[0].size

        if m[0] == "f":
            return self.fpu(insn)
        if m == "sahf":
            return ["do_sahf(c, R8H(c->eax));"]
        if m == "lahf":
            return ["SET8H(c->eax, (c->sf<<7)|(c->zf<<6)|(c->af<<4)|(c->pf<<2)|2|c->cf);"]

        # arithmetic / logic
        if m == "mov":
            d, s = two(); return [self.dst_write(insn, d, self.src(insn, s))]
        if m == "lea":
            d, s = two(); return [reg_write(self.md.reg_name(d.reg), self.addr_expr(insn, s))]
        if m in ("add","sub","and","or","xor","adc","sbb"):
            d, s = two(); sz = sz0(); a = self._read_dst(insn, d); b = self.src(insn, s)
            if m == "add": r = f"flags_add(c, {a}, {b}, {sz})"
            elif m == "sub": r = f"flags_sub(c, {a}, {b}, {sz})"
            elif m == "adc": r = f"flags_adc(c, {a}, {b}, {sz})"
            elif m == "sbb": r = f"flags_sbb(c, {a}, {b}, {sz})"
            elif m == "and": r = f"flags_logicz(c, {a} & {b}, {sz})"
            elif m == "or":  r = f"flags_logicz(c, {a} | {b}, {sz})"
            elif m == "xor": r = f"flags_logicz(c, {a} ^ {b}, {sz})"
            return [self.dst_write(insn, d, r)]
        if m == "cmp":
            d, s = two(); return [f"flags_sub(c, {self._read_dst(insn,d)}, {self.src(insn,s)}, {d.size});"]
        if m == "test":
            d, s = two(); return [f"flags_logicz(c, {self._read_dst(insn,d)} & {self.src(insn,s)}, {d.size});"]
        if m == "inc":
            d = ops[0]; return [self.dst_write(insn, d, f"flags_incs(c, {self._read_dst(insn,d)}, {d.size})")]
        if m == "dec":
            d = ops[0]; return [self.dst_write(insn, d, f"flags_decs(c, {self._read_dst(insn,d)}, {d.size})")]
        if m == "neg":
            d = ops[0]; return [self.dst_write(insn, d, f"flags_sub(c, 0, {self._read_dst(insn,d)}, {d.size})")]
        if m == "not":
            d = ops[0]; return [self.dst_write(insn, d, f"(~({self._read_dst(insn,d)}))")]
        if m in ("shl","sal","shr","sar"):
            d = ops[0]; cnt = self.src(insn, ops[1]) if len(ops) > 1 else "1"
            fn = {"shl":"op_shl","sal":"op_shl","shr":"op_shr","sar":"op_sar"}[m]
            return [self.dst_write(insn, d, f"{fn}(c, {self._read_dst(insn,d)}, {cnt}, {d.size})")]
        if m == "movzx":
            d, s = two(); return [self.dst_write(insn, d, f"({self.src(insn,s)})")]
        if m == "movsx":
            d, s = two(); ssz = s.size
            cast = {1:"int8_t",2:"int16_t"}[ssz]
            raw = self._read_raw(insn, s)
            return [self.dst_write(insn, d, f"(uint32_t)(int32_t)({cast})({raw})")]
        if m == "cdq":
            return ["c->edx = (c->eax & 0x80000000u) ? 0xFFFFFFFFu : 0u;"]
        if m == "cwde":
            return ["c->eax = (uint32_t)(int32_t)(int16_t)R16(c->eax);"]
        if m == "xchg":
            d, s = two()
            return [f"{{ uint32_t _t = {self._read_dst(insn,d)}; " +
                    self.dst_write(insn, d, self.src(insn, s)).rstrip(';') + "; " +
                    self.dst_write(insn, s, "_t").rstrip(';') + "; }"]
        if m.startswith("set") and m not in ("setssbsy",):   # setcc r/m8
            cond = self._cond("j" + m[3:])
            if cond is not None:
                return [self.dst_write(insn, ops[0], f"(({cond}) ? 1 : 0)")]
        if m == "pushfd": return ["push32(c, eflags_pack(c));"]
        if m == "popfd":  return ["eflags_unpack(c, pop32(c));"]
        if m == "pushf":  return ["push32(c, eflags_pack(c) & 0xFFFFu);"]
        if m == "popf":   return ["eflags_unpack(c, pop32(c) & 0xFFFFu);"]
        if m in ("cbw",):  return ["SET16(c->eax, (uint16_t)(int16_t)(int8_t)R8L(c->eax));"]
        if m in ("cwd",):  return ["SET16(c->edx, (R16(c->eax) & 0x8000u) ? 0xFFFFu : 0u);"]
        if m in ("wait","fwait","nop","int3","cld","fnop","hint_nop"): return [f"/* {m} */"]
        if m == "std": return ["/* std (DF=1 unsupported; string ops assume forward) */"]
        if m == "enter":
            n = ops[0].imm if ops else 0
            return [f"push32(c, c->ebp); c->ebp = c->esp; c->esp -= {n};"]
        if m in ("loop","loope","loopz","loopne","loopnz"):
            t = ops[0]
            extra = ""
            if m in ("loope","loopz"): extra = " && c->zf"
            elif m in ("loopne","loopnz"): extra = " && !c->zf"
            if t.type == X86_OP_IMM and t.imm in labels:
                return [f"c->ecx--; if (c->ecx{extra}) goto L_{t.imm:08X};"]
            return [f"c->ecx--; if (c->ecx{extra}) {{ dispatch(c, 0x{t.imm:08X}u); return; }}"]

        # multiply / divide (1-operand edx:eax forms + imul r,rm[,imm])
        if m == "mul":
            s = ops[0]; sz = s.size; v = self.src(insn, s)
            if sz == 4: return [f"{{ uint64_t _p=(uint64_t)c->eax*(uint32_t)({v}); c->eax=(uint32_t)_p; c->edx=(uint32_t)(_p>>32); c->cf=c->of=(c->edx!=0); }}"]
            if sz == 2: return [f"{{ uint32_t _p=(uint32_t)R16(c->eax)*(uint16_t)({v}); SET16(c->eax,_p); SET16(c->edx,_p>>16); c->cf=c->of=((_p>>16)!=0); }}"]
            return [f"{{ uint16_t _p=(uint16_t)R8L(c->eax)*(uint8_t)({v}); SET16(c->eax,_p); c->cf=c->of=((_p>>8)!=0); }}"]
        if m == "imul":
            if len(ops) == 1:
                s = ops[0]; sz = s.size; v = self.src(insn, s)
                if sz == 4: return [f"{{ int64_t _p=(int64_t)(int32_t)c->eax*(int32_t)({v}); c->eax=(uint32_t)_p; c->edx=(uint32_t)((uint64_t)_p>>32); c->cf=c->of=((int32_t)_p!=_p); }}"]
                if sz == 2: return [f"{{ int32_t _p=(int32_t)(int16_t)R16(c->eax)*(int16_t)({v}); SET16(c->eax,_p); SET16(c->edx,_p>>16); c->cf=c->of=((int16_t)_p!=_p); }}"]
                return [f"{{ int16_t _p=(int16_t)(int8_t)R8L(c->eax)*(int8_t)({v}); SET16(c->eax,_p); c->cf=c->of=((int8_t)_p!=_p); }}"]
            d = ops[0]; sz = d.size; cast = {1:"int8_t",2:"int16_t",4:"int32_t"}[sz]
            if len(ops) == 2: a = self._read_dst(insn, d); b = self.src(insn, ops[1])
            else:             a = self.src(insn, ops[1]); b = self.src(insn, ops[2])
            return [f"{{ int64_t _p=(int64_t)({cast})({a})*({cast})({b}); " +
                    self.dst_write(insn, d, "(uint32_t)_p").rstrip(';') + f"; c->cf=c->of=(({cast})_p!=_p); }}"]
        if m in ("div","idiv"):
            s = ops[0]; sz = s.size; v = self.src(insn, s); sg = (m == "idiv")
            if sz == 4:
                if sg: return [f"{{ int64_t _n=(int64_t)(((uint64_t)c->edx<<32)|c->eax); int32_t _d=(int32_t)({v}); c->eax=(uint32_t)(_n/_d); c->edx=(uint32_t)(_n%_d); }}"]
                return [f"{{ uint64_t _n=((uint64_t)c->edx<<32)|c->eax; uint32_t _d=(uint32_t)({v}); c->eax=(uint32_t)(_n/_d); c->edx=(uint32_t)(_n%_d); }}"]
            if sz == 2:
                if sg: return [f"{{ int32_t _n=(int32_t)(((uint32_t)R16(c->edx)<<16)|R16(c->eax)); int16_t _d=(int16_t)({v}); SET16(c->eax,(uint16_t)(int16_t)(_n/_d)); SET16(c->edx,(uint16_t)(int16_t)(_n%_d)); }}"]
                return [f"{{ uint32_t _n=((uint32_t)R16(c->edx)<<16)|R16(c->eax); uint16_t _d=(uint16_t)({v}); SET16(c->eax,_n/_d); SET16(c->edx,_n%_d); }}"]
            if sg: return [f"{{ int16_t _n=(int16_t)R16(c->eax); int8_t _d=(int8_t)({v}); SET8L(c->eax,(uint8_t)(int8_t)(_n/_d)); SET8H(c->eax,(uint8_t)(int8_t)(_n%_d)); }}"]
            return [f"{{ uint16_t _n=R16(c->eax); uint8_t _d=(uint8_t)({v}); SET8L(c->eax,_n/_d); SET8H(c->eax,_n%_d); }}"]

        # string ops (assume DF=0 / forward; rep prefix loops on ECX)
        parts = m.split()
        if parts[0] in ("rep","repe","repz","repne","repnz") or parts[0] in ("movsb","movsd","movsw","stosb","stosd","stosw","scasb","scasd","scasw","lodsb","lodsd","lodsw","cmpsb","cmpsd","cmpsw"):
            rep = parts[0] if len(parts) > 1 else None
            base = parts[1] if rep else parts[0]
            esz = {"b":1,"w":2,"d":4}[base[-1]]
            wfn = {1:"wr8",2:"wr16",4:"wr32"}[esz]; rfn = {1:"rd8",2:"rd16",4:"rd32"}[esz]
            areg = {1:"R8L(c->eax)",2:"R16(c->eax)",4:"c->eax"}[esz]
            if base.startswith("stos"): body = f"{wfn}(c->edi, {areg}); c->edi += {esz};"
            elif base.startswith("movs"): body = f"{wfn}(c->edi, {rfn}(c->esi)); c->esi += {esz}; c->edi += {esz};"
            elif base.startswith("lods"): body = f"{('SET8L(c->eax,'+rfn+'(c->esi))') if esz==1 else (('SET16(c->eax,'+rfn+'(c->esi))') if esz==2 else 'c->eax = '+rfn+'(c->esi)')}; c->esi += {esz};"
            elif base.startswith("scas"):
                cmp = f"flags_sub(c, {areg}, {rfn}(c->edi), {esz}); c->edi += {esz};"
                if rep in ("repe","repz"):  return [f"while (c->ecx) {{ c->ecx--; {cmp} if (!c->zf) break; }}"]
                if rep in ("repne","repnz"):return [f"while (c->ecx) {{ c->ecx--; {cmp} if (c->zf) break; }}"]
                return [cmp]
            elif base.startswith("cmps"):
                cmp = f"flags_sub(c, {rfn}(c->esi), {rfn}(c->edi), {esz}); c->esi += {esz}; c->edi += {esz};"
                if rep in ("repe","repz"):  return [f"while (c->ecx) {{ c->ecx--; {cmp} if (!c->zf) break; }}"]
                if rep in ("repne","repnz"):return [f"while (c->ecx) {{ c->ecx--; {cmp} if (c->zf) break; }}"]
                return [cmp]
            else:
                return [f"/* TODO string {m} {insn.op_str} */ abort();"]
            if rep: return [f"while (c->ecx) {{ {body} c->ecx--; }}"]
            return [body]

        # stack
        if m == "push":
            return [f"push32(c, {self.src(insn, ops[0])});"]
        if m == "pop":
            d = ops[0]
            if d.type == X86_OP_REG: return [reg_write(self.md.reg_name(d.reg), "pop32(c)")]
            return [self.wr(insn, d, "pop32(c)")]

        # control flow
        if m == "jmp":
            t = ops[0]
            if t.type == X86_OP_IMM and t.imm in labels:
                return [f"goto L_{t.imm:08X};"]
            if ea in self.jumptables:                       # switch via jump table
                tgts = self.jumptables[ea]
                addr = self.addr_expr(insn, t)
                out = [f"{{ uint32_t _jt = rd32({addr});"]
                for tv in sorted(set(tgts)):
                    out.append(f"  if (_jt == GVA(0x{tv:08X})) goto L_{tv:08X};")
                out.append("  abort(); }")
                return out
            if t.type == X86_OP_IMM:                        # tail call to another function
                return [f"dispatch(c, 0x{t.imm:08X}u); return;"]
            return [f"/* indirect jmp */ dispatch_jmp(c, {self._target(insn,t)}); return;"]
        if m == "call":
            t = ops[0]
            tgt = self._target(insn, t)
            if t.type == X86_OP_IMM:
                return [f"push32(c, 0x{nxt:08X}u); dispatch(c, {tgt});"]
            # Indirect: resolve the target BEFORE pushing the return address.
            # `call dword ptr [esp+0x18]` reads its target with the pre-push esp;
            # pushing first shifts every esp-relative operand by 4 and calls the
            # wrong slot (seen in the wild: read a zero, jumped to 0).
            return [f"{{ uint32_t _ct = {tgt};"
                    f" push32(c, 0x{nxt:08X}u); dispatch(c, _ct); }}"]
        if m == "ret":
            n = (ops[0].imm if ops and ops[0].type == X86_OP_IMM else 0)
            return [f"c->esp += {4 + n}; return;"]
        if m.startswith("j"):
            cond = self._cond(m)
            if cond is None: return [f"/* TODO {m} */ abort();"]
            t = ops[0]
            if t.type == X86_OP_IMM and t.imm in labels:
                return [f"if ({cond}) goto L_{t.imm:08X};"]
            if t.type == X86_OP_IMM:        # conditional jump to another function (shared epilogue)
                return [f"if ({cond}) {{ dispatch(c, 0x{t.imm:08X}u); return; }}"]
            return [f"/* TODO jcc {m} {insn.op_str} */ abort();"]
        if m in ("nop","hint_nop"): return ["/* nop */"]
        if m == "leave":
            return ["c->esp = c->ebp; c->ebp = pop32(c);"]

        return [f"/* TODO {m} {insn.op_str} */ abort();"]

    # ---- x87 FPU ----
    def _st_idx(self, op):
        mm = re.match(r"st\((\d)\)", self.md.reg_name(op.reg))
        return int(mm.group(1)) if mm else 0

    def _fmem(self, insn, op, kind):
        a = self.addr_expr(insn, op); sz = op.size
        if kind == "f":  return f"rdf32({a})" if sz == 4 else f"rdf64({a})"
        return {2: f"rdi16({a})", 4: f"rdi32({a})", 8: f"rdi64({a})"}[sz]

    def fpu(self, insn):
        m = insn.mnemonic; ops = insn.operands
        memop = ops[0] if ops and ops[0].type == X86_OP_MEM else None

        if m in ("fld",):
            if memop: return [f"fpush(c, {self._fmem(insn, memop, 'f')});"]
            return [f"fpush(c, *fst(c, {self._st_idx(ops[0])}));"]
        if m in ("fild",):
            return [f"fpush(c, {self._fmem(insn, memop, 'i')});"]
        if m in ("fldz",): return ["fpush(c, 0.0);"]
        if m in ("fld1",): return ["fpush(c, 1.0);"]
        if m in ("fst", "fstp"):
            pop = "; fpop(c);" if m == "fstp" else ";"
            if memop:
                sz = memop.size; a = self.addr_expr(insn, memop)
                st = "wrf32" if sz == 4 else "wrf64"
                return [f"{st}({a}, *fst(c, 0)){pop}"]
            return [f"*fst(c, {self._st_idx(ops[0])}) = *fst(c, 0){pop}"]
        if m in ("fist", "fistp"):
            pop = "; fpop(c);" if m == "fistp" else ";"
            sz = memop.size; a = self.addr_expr(insn, memop)
            st = {2: "wri16", 4: "wri32", 8: "wri64"}[sz]
            return [f"{st}({a}, *fst(c, 0)){pop}"]
        if m in ("fchs",): return ["*fst(c, 0) = -*fst(c, 0);"]
        if m in ("fabs",): return ["*fst(c, 0) = fabs(*fst(c, 0));"]
        if m in ("fsqrt",): return ["*fst(c, 0) = sqrt(*fst(c, 0));"]
        if m in ("fsin",):  return ["*fst(c, 0) = sin(*fst(c, 0));"]
        if m in ("fcos",):  return ["*fst(c, 0) = cos(*fst(c, 0));"]
        if m in ("fptan",): return ["*fst(c, 0) = tan(*fst(c, 0)); fpush(c, 1.0);"]
        if m in ("fpatan",):return ["*fst(c, 1) = atan2(*fst(c, 1), *fst(c, 0)); fpop(c);"]
        if m in ("frndint",): return ["*fst(c, 0) = nearbyint(*fst(c, 0));"]
        if m in ("fscale",): return ["*fst(c, 0) = ldexp(*fst(c, 0), (int)*fst(c, 1));"]
        if m in ("fsincos",): return ["{ double _s=sin(*fst(c,0)), _c=cos(*fst(c,0)); *fst(c,0)=_s; fpush(c,_c); }"]
        if m in ("fxch",):
            i = self._st_idx(ops[0]) if ops else 1
            return [f"{{ double _t = *fst(c, 0); *fst(c, 0) = *fst(c, {i}); *fst(c, {i}) = _t; }}"]
        if m in ("fadd","fsub","fsubr","fmul","fdiv","fdivr",
                 "faddp","fsubp","fsubrp","fmulp","fdivp","fdivrp"):
            pops = m.endswith("p"); base = m[:-1] if pops else m
            rev = base in ("fsubr","fdivr"); core = base[:-1] if rev else base
            opc = {"fadd":"+","fsub":"-","fmul":"*","fdiv":"/"}[core]
            if memop:                              # st0 OP= mem  (no pop for mem form)
                src = self._fmem(insn, memop, "f"); dst = "(*fst(c, 0))"
                expr = f"{src} {opc} {dst}" if rev else f"{dst} {opc} {src}"
                return [f"*fst(c, 0) = {expr};"]
            # register form: default dst st(0) when single operand
            if len(ops) == 2:
                a = self._st_idx(ops[0]); b = self._st_idx(ops[1])
            else:
                a = 0; b = self._st_idx(ops[0]) if ops else 1
            dst = f"(*fst(c, {a}))"; src = f"(*fst(c, {b}))"
            expr = f"{src} {opc} {dst}" if rev else f"{dst} {opc} {src}"
            line = f"*fst(c, {a}) = {expr};"
            return [line + (" fpop(c);" if pops else "")]
        if m in ("fiadd","fisub","fisubr","fimul","fidiv","fidivr"):
            src = self._fmem(insn, memop, "i")          # (double) of an integer mem operand
            core = "f" + m[2:]                          # fidiv -> fdiv, fiadd -> fadd, ...
            rev = core in ("fsubr","fdivr"); base = core[:-1] if rev else core
            opc = {"fadd":"+","fsub":"-","fmul":"*","fdiv":"/"}[base]
            dst = "(*fst(c, 0))"
            expr = f"{src} {opc} {dst}" if rev else f"{dst} {opc} {src}"
            return [f"*fst(c, 0) = {expr};"]
        if m in ("ficom","ficomp"):
            out = [f"fcompare(c, *fst(c, 0), {self._fmem(insn, memop, 'i')});"]
            if m == "ficomp": out.append("fpop(c);")
            return out
        if m in ("fcom","fcomp","fcompp"):
            if memop: src = self._fmem(insn, memop, "f")
            elif ops: src = f"*fst(c, {self._st_idx(ops[0])})"
            else: src = "*fst(c, 1)"
            out = [f"fcompare(c, *fst(c, 0), {src});"]
            if m == "fcomp": out.append("fpop(c);")
            if m == "fcompp": out += ["fpop(c);", "fpop(c);"]
            return out
        if m == "fnstsw":
            if ops and ops[0].type == X86_OP_REG:   # ax
                return ["SET16(c->eax, (uint16_t)c->fpu_sw);"]
            return [self.wr(insn, ops[0], "(uint16_t)c->fpu_sw")]
        if m == "fnstcw":
            return [self.wr(insn, ops[0], "0x027Fu")]   # default control word
        if m in ("fldcw", "fwait", "wait", "fnclex", "fclex", "fninit"):
            return [f"/* {m} ignored */"]
        if m in ("fldenv", "fnstenv"):
            return [f"/* {m} ignored (no FP exceptions modelled) */"]
        return [f"/* TODO fpu {m} {insn.op_str} */ abort();"]

    def _read_dst(self, insn, op):
        # read a dst operand (for read-modify-write)
        if op.type == X86_OP_REG: return reg_read(self.md.reg_name(op.reg))
        if op.type == X86_OP_MEM: return self.rd(insn, op)
        raise NotImplementedError

    def _read_raw(self, insn, op):
        return self.src(insn, op)

    def _target(self, insn, op):
        if op.type == X86_OP_IMM: return f"0x{op.imm:08X}u"
        if op.type == X86_OP_REG: return reg_read(self.md.reg_name(op.reg))
        if op.type == X86_OP_MEM: return self.rd(insn, op)
        raise NotImplementedError

    def _cond(self, m):
        return {
            "je":"c->zf","jz":"c->zf","jne":"!c->zf","jnz":"!c->zf",
            "jbe":"(c->cf || c->zf)","jna":"(c->cf || c->zf)",
            "ja":"(!c->cf && !c->zf)","jnbe":"(!c->cf && !c->zf)",
            "jb":"c->cf","jc":"c->cf","jnae":"c->cf",
            "jae":"!c->cf","jnb":"!c->cf","jnc":"!c->cf",
            "jl":"(c->sf != c->of)","jnge":"(c->sf != c->of)",
            "jge":"(c->sf == c->of)","jnl":"(c->sf == c->of)",
            "jle":"(c->zf || (c->sf != c->of))","jng":"(c->zf || (c->sf != c->of))",
            "jg":"(!c->zf && (c->sf == c->of))","jnle":"(!c->zf && (c->sf == c->of))",
            "js":"c->sf","jns":"!c->sf","jo":"c->of","jno":"!c->of",
            "jp":"c->pf","jpe":"c->pf","jnp":"!c->pf","jpo":"!c->pf",
            "jecxz":"(c->ecx == 0)","jcxz":"(R16(c->ecx) == 0)",
        }.get(m)

    def lift_function(self, code, start):
        insns = list(self.md.disasm(code, start))
        # collect intra-function branch targets
        end = start + len(code)
        self.func_start, self.func_end = start, end
        insn_addrs = set(ins.address for ins in insns)   # only these can be goto labels
        labels = set()
        for ins in insns:
            if ins.mnemonic.startswith("j") or ins.mnemonic in ("loop","loopne","loope","loopz","loopnz","loope"):
                for op in ins.operands:
                    # only label real instruction boundaries; targets that land
                    # mid-instruction or outside the func are handled via dispatch
                    if op.type == X86_OP_IMM and op.imm in insn_addrs:
                        labels.add(op.imm)
                    elif op.type == X86_OP_MEM and ins.mnemonic == "jmp":
                        d = op.mem.disp & 0xffffffff      # jump table base
                        if self.in_image(d):
                            tgts = [t for t in self.resolve_jumptable(d) if t in insn_addrs]
                            if tgts:
                                self.jumptables[ins.address] = tgts
                                labels.update(tgts)
        out = []
        out.append(f"void L_{start:08X}(CPU *c)")
        out.append("{")
        for ins in insns:
            if ins.address in labels:
                out.append(f"L_{ins.address:08X}:")
            for line in self.translate(ins, labels):
                out.append(f"    {line:<60} /* {ins.address:08X}: {ins.mnemonic} {ins.op_str} */")
        out.append("}")
        return "\n".join(out)


def load_bounds(path):
    bounds = {}
    with open(path) as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 3 and parts[0].startswith("0x"):
                bounds[int(parts[0], 16)] = int(parts[1])
    return bounds


def main():
    dll, funcs_txt, out_c = sys.argv[1], sys.argv[2], sys.argv[3]
    # targets: explicit 0xADDR args, or "@file" of addrs, or (none) => ALL in funcs_txt
    if len(sys.argv) >= 5 and sys.argv[4].startswith("@"):
        targets = [int(x, 16) for x in open(sys.argv[4][1:]).read().split()]
    else:
        targets = [int(x, 16) for x in sys.argv[4:]]
    import pefile
    pe = pefile.PE(dll, fast_load=True)
    global IMAGE_BASE
    IMAGE_BASE = pe.OPTIONAL_HEADER.ImageBase
    image_size = pe.OPTIONAL_HEADER.SizeOfImage
    print(f"[*] image base {IMAGE_BASE:#x}, size {image_size:#x}", file=sys.stderr)
    # flat reader: VA -> bytes
    def read_va(va, n):
        rva = va - IMAGE_BASE
        return pe.get_data(rva, n)
    # Base relocations: the set of VAs holding a 32-bit absolute address that the
    # loader fixes up. An instruction immediate at such a VA is a relocatable
    # address (e.g. `push offset table`) and must be emitted as GVA(imm) so the
    # lifted code is correct at any load base.
    reloc_vas = set()
    try:
        import pefile as _pf
        pe.parse_data_directories(directories=[_pf.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']])
        for br in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []):
            for e in br.entries:
                if e.type == 3:   # IMAGE_REL_BASED_HIGHLOW
                    reloc_vas.add((IMAGE_BASE + e.rva) & 0xffffffff)
    except Exception as ex:
        print(f"[!] reloc parse failed: {ex}", file=sys.stderr)
    print(f"[*] {len(reloc_vas)} base relocations (address immediates -> GVA)", file=sys.stderr)
    bounds = load_bounds(funcs_txt)
    if not targets:                       # no addrs given => lift every function
        targets = sorted(bounds)
        print(f"[*] no targets given; lifting ALL {len(targets)} functions", file=sys.stderr)
    lifter = Lifter(dll, image_size, read_va)
    lifter.reloc_vas = reloc_vas

    chunks = ["/* AUTO-GENERATED by lift32_cpu.py - do not edit */",
              '#include "cpu.h"', ""]
    done = []
    for t in targets:
        size = bounds.get(t)
        if not size:
            print(f"[!] no size for {t:#x}", file=sys.stderr); continue
        code = read_va(t, size)
        chunks.append(lifter.lift_function(code, t))
        chunks.append("")
        done.append(t)
        print(f"[+] lifted L_{t:08X} ({size} bytes)", file=sys.stderr)
    with open(out_c, "w") as f:
        f.write("\n".join(chunks))
    # companion X-macro listing every lifted function (auto-syncs the dispatch table)
    list_h = out_c.rsplit(".", 1)[0] + "_list.h"
    with open(list_h, "w") as f:
        f.write("/* AUTO-GENERATED by lift32_cpu.py */\n#define LIFTED_FUNCS(X) \\\n")
        f.write(" \\\n".join(f"    X({t:08X})" for t in done) + "\n")
    print(f"[*] wrote {out_c} and {list_h} ({len(done)} funcs)", file=sys.stderr)


if __name__ == "__main__":
    main()

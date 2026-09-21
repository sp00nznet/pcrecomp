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

# String instructions, and the prefixes that may legitimately precede one. An
# F3/F2 prefix on anything else is not a REP - see translate().
REP_PREFIXES = frozenset(("rep", "repe", "repz", "repne", "repnz"))
STRING_OPS = frozenset((
    "movsb", "movsw", "movsd", "stosb", "stosw", "stosd",
    "scasb", "scasw", "scasd", "lodsb", "lodsw", "lodsd",
    "cmpsb", "cmpsw", "cmpsd", "insb", "insw", "insd",
    "outsb", "outsw", "outsd",
))

# ---- SSE ----
# Scalar ops, by mnemonic, to the C operator they are. The packed forms of
# these are deliberately absent: they need per-lane code and are rare enough in
# real binaries that a TODO is better than a plausible-looking wrong lane.
SSE_ARITH = {"add": "+", "sub": "-", "mul": "*", "div": "/"}

# Bitwise ops on the whole 128 bits. andn is `~dst & src`, note the order.
SSE_BITWISE = {
    "andps": "&", "andpd": "&", "pand": "&",
    "orps":  "|", "orpd":  "|", "por":  "|",
    "xorps": "^", "xorpd": "^", "pxor": "^",
    "andnps": "andn", "andnpd": "andn", "pandn": "andn",
}

# CMPccSS/SD. These do not set flags - they write an all-ones or all-zeros mask
# into the destination lane, so the result can be ANDed as a branchless select.
# Every predicate is written so C's "any comparison with NaN is false" rule
# gives the unordered behaviour the hardware has.
SSE_CMP_PRED = {
    "eq":    "(_a == _b)",
    "lt":    "(_a < _b)",
    "le":    "(_a <= _b)",
    "unord": "(_a != _a || _b != _b)",
    "neq":   "!(_a == _b)",
    "nlt":   "!(_a < _b)",
    "nle":   "!(_a <= _b)",
    "ord":   "!(_a != _a || _b != _b)",
}
SSE_CMP_RE = re.compile(r"^cmp(%s)(ss|sd)$" % "|".join(SSE_CMP_PRED))

# Moves of the whole register. Aligned and unaligned differ only in whether the
# hardware faults on a misaligned address; the movnt* forms differ only in a
# cache hint, which a host that is not managing the guest cache can ignore.
# They are all a 128-bit copy here.
SSE_MOV128 = frozenset({"movaps", "movups", "movapd", "movupd", "movdqa", "movdqu",
                        "movntps", "movntpd", "movntdq"})

# Mnemonics that are SSE only when an XMM register is involved. `movsd` is also
# "move string dword"; `movq`/`movd` and every `p*` op below are also MMX, where
# the operands are mm0-7 and 64 bits wide. Routing these by name alone
# mistranslates string loops and MMX code into nonsense that still compiles.
SSE_AMBIGUOUS = frozenset({"movsd", "movq", "movd", "pxor", "pand", "por", "pandn"})

SSE_MNEMONICS = (
    SSE_MOV128 | SSE_AMBIGUOUS | frozenset(SSE_BITWISE)
    | frozenset({"movss", "sqrtss", "sqrtsd", "sqrtps",
                 "shufps", "unpcklps", "unpckhps",
                 "minps", "maxps", "minpd", "maxpd", "minss", "maxss", "minsd", "maxsd",
                 "ucomiss", "comiss", "ucomisd", "comisd",
                 "cvtsi2ss", "cvtsi2sd", "cvttss2si", "cvttsd2si",
                 "cvtss2si", "cvtsd2si", "cvtss2sd", "cvtsd2ss",
                 "cvtdq2ps", "cvtps2dq", "cvttps2dq",
                 "cvtps2pd", "cvtpd2ps"})
    | frozenset(o + w for o in SSE_ARITH for w in ("ss", "sd", "ps", "pd"))
)

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

def _todo(va, what):
    """An instruction the lifter cannot express.

    A bare `abort()` in two million lines of generated C says nothing at all -
    and in a release build MSVC turns it into `__fastfail`, which no exception
    handler sees, so the process vanishes with 0xC0000409 and an empty log. It
    took a memory-mapped dispatch trail to find the last one.

    RECOMP_TODO carries the address and the mnemonic to whatever the runtime
    wants to do with them. cpu.h defines it as plain abort() unless the runtime
    says otherwise, so nothing that already includes cpu.h changes.
    """
    return 'RECOMP_TODO(0x%08X, "%s");' % (va, what.replace('"', "'").strip())


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
        """Read consecutive dword targets from a jump table.

        The old rule - stop at the first entry outside the *current function* -
        silently truncated any table whose last arms were recovered as
        functions of their own, which on a stripped binary happens constantly:
        an arm that is also a branch target gets its own catalog entry, the
        clamp ends the containing function there, and every arm past it
        disappears.

        It cost a day in Mario Kart. The window procedure's table has ten arms;
        arm nine, WM_NCCREATE, lives past a neighbour that recovery had called
        a function. The lifter emitted nine `goto`s and an `abort()`, so no
        window could ever be created - CreateWindowExW returned NULL with
        ERROR_NOT_ENOUGH_MEMORY and nothing said why.

        The image's own range is the bound that a real table has anyway: the
        dword after the last arm is whatever follows it in `.rdata` - here the
        byte index table the same switch uses - and is not an address at all.
        """
        targets = []
        if not self.read_va:
            return targets
        for i in range(256):
            try:
                raw = self.read_va(table_va + 4 * i, 4)
            except Exception:
                break
            t = int.from_bytes(raw, "little")
            if self.in_image(t):
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
    def areg(self, name):
        """A register used to form an address.

        `c->bp` does not exist: the CPU struct holds 32-bit registers and the
        16-bit ones are windows onto them. Emitting the raw name works for
        eax..edi and produces uncompilable C the moment an address-size prefix
        puts a 16-bit register in the operand, which segmented code does."""
        if name in R32: return "c->%s" % name
        if name in R16: return "R16(c->%s)" % R16[name]
        if name in R8L: return "R8L(c->%s)" % R8L[name]
        if name in R8H: return "R8H(c->%s)" % R8H[name]
        return "c->%s" % name

    def mem_addr(self, insn, op):
        """The address of a memory operand, for instructions that need it
        directly rather than through rd/wr - `lds`/`les` and friends.

        Flat builds want exactly addr_expr. A segmented one needs the segment
        base added, the same as every other access, and overriding rd/wr does
        not cover this because the far-pointer load computes its own address.
        Getting it wrong reads the pointer from a near-null address and yields
        a plausible-looking selector:offset pair made of whatever was there."""
        return self.addr_expr(insn, op)

    def addr_expr(self, insn, op):
        m = op.mem
        terms = []
        base = self.md.reg_name(m.base) if m.base else None
        index = self.md.reg_name(m.index) if m.index else None
        d = m.disp & 0xffffffff
        if base: terms.append(self.areg(base))
        if index: terms.append(f"{self.areg(index)}*{m.scale}")
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
        if m.base:  terms.append(self.areg(self.md.reg_name(m.base)))
        if m.index: terms.append("%s*%d" % (self.areg(self.md.reg_name(m.index)),
                                            m.scale))
        d = m.disp & 0xffffffff
        if d or not terms: terms.append(f"0x{d:08X}u")
        return "(" + " + ".join(terms) + ")"

    def _bad_size(self, insn, op, what):
        """A memory operand these cannot express. Raised rather than guessed at,
        and named rather than left as a bare KeyError: the size is the whole
        diagnosis. 6 is an m16:32 far pointer, 10 an x87 extended double - both
        real, both needing their own handling in translate() rather than a
        width-indexed accessor here."""
        return NotImplementedError(
            "%s: %d-byte memory operand at %#x (%s %s) - %s"
            % (what, op.size, insn.address, insn.mnemonic, insn.op_str,
               "far pointer (m16:32)" if op.size == 6 else
               "x87 extended (m80)" if op.size == 10 else "unsupported width"))

    def rd(self, insn, op):
        sz = op.size
        if self.seg_name(op) == "fs":   # TIB-relative (SEH chain etc.) -> real fs
            off = self.seg_off(insn, op)
            if sz not in (1, 2, 4): raise self._bad_size(insn, op, "rd fs:")
            return {1:f"__readfsbyte({off})",2:f"__readfsword({off})",4:f"__readfsdword({off})"}[sz]
        a = self.addr_expr(insn, op)
        if sz not in (1, 2, 4): raise self._bad_size(insn, op, "rd")
        return {1:f"rd8({a})", 2:f"rd16({a})", 4:f"rd32({a})"}[sz]

    def wr(self, insn, op, val):
        sz = op.size
        if self.seg_name(op) == "fs":
            off = self.seg_off(insn, op)
            if sz not in (1, 2, 4): raise self._bad_size(insn, op, "wr fs:")
            return {1:f"__writefsbyte({off}, {val});",2:f"__writefsword({off}, (unsigned short)({val}));",
                    4:f"__writefsdword({off}, {val});"}[sz]
        a = self.addr_expr(insn, op)
        if sz not in (1, 2, 4): raise self._bad_size(insn, op, "wr")
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

        # capstone keeps the `lock` prefix in the mnemonic. The instruction
        # underneath is the one to translate; the atomicity is in the helper
        # the xadd/cmpxchg cases below reach for, and for everything else a
        # `lock` on a single store is what the hardware does anyway.
        if m.startswith("lock "):
            m = m[5:]

        def two(): return ops[0], ops[1]
        def sz0(): return ops[0].size

        # ---- bit test and friends ----
        if m in ("bt", "bts", "btr", "btc"):
            opnum = {"bt": 0, "bts": 1, "btr": 2, "btc": 3}[m]
            d, s2 = ops[0], ops[1]
            idx = self.src(insn, s2)
            if d.type == X86_OP_MEM:
                return ["bit_string_op(c, %s, (int32_t)(%s), %d);"
                        % (self.addr_expr(insn, d), idx, opnum)]
            return ["bit_reg_op(c, &c->%s, %s, %d);"
                    % (self.md.reg_name(d.reg), idx, opnum)]

        # ---- LOCK-prefixed read-modify-write ----
        # Capstone folds the prefix into the mnemonic. Only the forms that turn
        # up are here: these are what libstdc++ compiles a reference count to,
        # and a game with several threads sharing strings really does race on
        # them. Anything else keeps its TODO rather than quietly losing the
        # atomicity, which would fail as a use-after-free somewhere unrelated.
        if m.startswith("lock "):
            base = m[5:]
            d, s2 = (ops[0], ops[1]) if len(ops) > 1 else (ops[0], None)
            if base in ("add", "xadd") and d.type == X86_OP_MEM and s2 is not None:
                addr = self.addr_expr(insn, d)
                val = self.src(insn, s2)
                out = ["{ uint32_t _old = atomic_xadd32(%s, %s);" % (addr, val)]
                if base == "xadd":
                    # xadd hands the register the value memory held before.
                    out[0] += " " + reg_write(self.md.reg_name(s2.reg), "_old")
                out[0] += " flags_add(c, _old, %s, 4); }" % val
                return out
            return [f"RECOMP_TODO(0x{ea:08X}, \"{m} {insn.op_str}\");"]

        if m[0] == "f":
            return self.fpu(insn)
        if self.is_sse(insn):
            return self.sse(insn)

        # Prefetches are hints. They move no data and set no flags, so the
        # correct translation really is nothing at all - and leaving them as a
        # TODO aborts a game in the middle of code that was working.
        if m.startswith("prefetch"):
            return ["/* prefetch: hint only */"]

        # cmovcc. Same conditions as Jcc, so the table is already written.
        # Note x86 reads the source operand unconditionally - an unmapped
        # address faults whether the move happens or not - but a C `if` reading
        # a live address is the shape every caller actually relies on.
        if m.startswith("cmov"):
            cond = self._cond("j" + m[4:])
            if cond:
                d, sop = ops[0], ops[1]
                return [f"if ({cond}) {{ {self.dst_write(insn, d, self.src(insn, sop))} }}"]
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
        if m in ("rol", "ror"):
            d = ops[0]; cnt = self.src(insn, ops[1]) if len(ops) > 1 else "1"
            fn = "op_rol" if m == "rol" else "op_ror"
            return [self.dst_write(insn, d,
                                   f"{fn}(c, {self._read_dst(insn,d)}, {cnt}, {d.size})")]
        if m == "bswap":
            # Register only, and 32-bit only: the 16-bit encoding is undefined
            # on real parts, so anything else here is data read as code.
            d = ops[0]
            if d.size == 4:
                return [self.dst_write(insn, d,
                                       f"op_bswap32({self._read_dst(insn, d)})")]
        if m in ("shld", "shrd"):
            d, s2 = ops[0], ops[1]
            cnt = self.src(insn, ops[2]) if len(ops) > 2 else "R8L(c->ecx)"
            fn = "op_shld" if m == "shld" else "op_shrd"
            return [self.dst_write(insn, d,
                                   f"{fn}(c, {self._read_dst(insn,d)}, "
                                   f"{self.src(insn,s2)}, {cnt}, {d.size})")]
        if m in ("lds", "les", "lfs", "lgs", "lss"):
            # Load a far pointer: the offset into the register, the selector
            # into a segment register. A flat PE never does this; segmented
            # 32-bit code does it constantly. See the CPU struct: the selector
            # is stored and does not affect any later access, so this is right
            # only while every segment shares one address space.
            d, src = ops[0], ops[1]
            seg = m[1:]
            sz = d.size
            return ["{ uint32_t _a = %s; %s c->%s = rd16(_a + %d); }"
                    % (self.mem_addr(insn, src),
                       self.dst_write(insn, d, "rd%d(_a)" % (sz * 8)),
                       seg, sz)]
        if m == "retf":
            # The far frame belongs to whoever called across the segment
            # boundary, and in a lifted build that is the runtime, not us.
            n = (ops[0].imm if ops and ops[0].type == X86_OP_IMM else 0)
            return ["/* retf %d: far frame unwound by the caller */ return;" % n]
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

        # xadd / cmpxchg - the interlocked pair.
        #
        # A game's reference counts and queue indices are these, and a
        # recompiled one has as many threads as the original, so they go to
        # real atomics in cpu.h rather than a read-modify-write that is right
        # until it is not. Only the 32-bit memory form is written out, because
        # that is the only one a Win32 compiler emits for Interlocked*.
        if m in ("xadd", "cmpxchg") and sz0() == 4:
            d, s = two()
            if d.type == X86_OP_MEM:
                a = self.addr_expr(insn, d)
                if m == "xadd":
                    return [f"{{ uint32_t _v = {self.src(insn, s)};",
                            f"  uint32_t _old = atomic_xadd32({a}, _v);",
                            f"  {self.dst_write(insn, s, '_old')}",
                            "  flags_add(c, _old, _v, 4); }"]
                return [f"{{ uint32_t _old = atomic_cmpxchg32({a}, c->eax, {self.src(insn,s)});",
                        "  flags_sub(c, c->eax, _old, 4);",
                        "  if (_old != c->eax) c->eax = _old; }"]
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
        # An F3 prefix is only a REP on a string instruction. On anything else
        # it is a hint, and the one that matters is `repz ret` (F3 C3) - AMD's
        # branch-prediction idiom for a plain `ret`, which MSVC emits at every
        # branch target that returns. Strip the prefix and let the real handler
        # for the base mnemonic have it. Without this the block below indexed
        # base[-1] and died on the 't' of "ret".
        if parts[0] in REP_PREFIXES and len(parts) > 1 and parts[1] not in STRING_OPS:
            m = parts[1]
            parts = [m]
        if parts[0] in REP_PREFIXES or parts[0] in STRING_OPS:
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
                return [_todo(ea, f"string {m} {insn.op_str}")]
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
        if m in ("jmp", "call") and ops and ops[0].type == X86_OP_MEM \
                and ops[0].size == 6:
            # `jmp/call fword ptr [...]` - an m16:32 far pointer. The CPU model
            # is flat and has one code segment, so there is no correct
            # translation: loading CS is the whole point of the instruction.
            # An honest abort beats reading four of the six bytes and jumping
            # somewhere plausible. In a 32-bit PE this is almost always a
            # WOW64/segment transition in code the program never reaches, or a
            # data run the catalog mistook for a function.
            return [_todo(ea, f"far {m} m16:32")]
        if m == "jmp":
            t = ops[0]
            if t.type == X86_OP_IMM and t.imm in labels:
                return [f"goto L_{t.imm:08X};"]
            if ea in self.jumptables:                       # switch via jump table
                tgts = self.jumptables[ea]
                addr = self.addr_expr(insn, t)
                out = [f"{{ uint32_t _jt = rd32({addr});"]
                for tv in sorted(set(tgts)):
                    if tv in labels:
                        out.append(f"  if (_jt == GVA(0x{tv:08X})) goto L_{tv:08X};")
                    else:
                        # An arm outside this function - a neighbour recovery
                        # called a function of its own, or the same code lifted
                        # twice under two extents. Written as a literal
                        # dispatch rather than left to the computed one below,
                        # because a literal is something a build step can SEE:
                        # the driver closes every address the generated text
                        # dispatches to, and a target that only appears in a
                        # register is a runtime abort nobody predicted.
                        out.append(f"  if (_jt == GVA(0x{tv:08X}))"
                                   f" {{ dispatch(c, 0x{tv:08X}u); return; }}")
                # Anything else the table holds - an entry this walk did not
                # enumerate at all. Aborting here was a guess that the table
                # could not hold anything else, and it was wrong.
                out.append("  dispatch_jmp(c, _jt); return; }")
                return out
            if t.type == X86_OP_IMM:                        # tail call to another function
                return [f"dispatch(c, 0x{t.imm:08X}u); return;"]
            return [f"/* indirect jmp */ dispatch_jmp(c, {self._target(insn,t)}); return;"]
        if m == "call":
            t = ops[0]
            tgt = self._target(insn, t)
            if t.type == X86_OP_IMM and t.imm == nxt:
                # The position-independent "get PC" idiom: a call to the very
                # next instruction, whose only purpose is to push EIP so the
                #  that follows can read it and form a GOT pointer. There
                # is no callee. Dispatching would look up an address in the
                # middle of this same function and find nothing - so do what
                # the hardware does, push the address and fall through.
                #   call 0x8072d9d   <- next instruction
                #   pop  ebx         <- ebx = 0x8072d9d
                #   add  ebx, ...    <- ebx = _GLOBAL_OFFSET_TABLE_
                # Every PIC i386 binary opens with this, which is every .so and
                # every PIE executable.
                return [f"push32(c, 0x{nxt:08X}u); /* get-PC, no callee */"]
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
            if cond is None: return [_todo(ea, m)]
            t = ops[0]
            if t.type == X86_OP_IMM and t.imm in labels:
                return [f"if ({cond}) goto L_{t.imm:08X};"]
            if t.type == X86_OP_IMM:        # conditional jump to another function (shared epilogue)
                return [f"if ({cond}) {{ dispatch(c, 0x{t.imm:08X}u); return; }}"]
            return [_todo(ea, f"jcc {m} {insn.op_str}")]
        if m in ("nop","hint_nop"): return ["/* nop */"]
        if m == "leave":
            return ["c->esp = c->ebp; c->ebp = pop32(c);"]

        return [_todo(ea, f"{m} {insn.op_str}")]

    # ---- x87 FPU ----
    def _st_idx(self, op):
        mm = re.match(r"st\((\d)\)", self.md.reg_name(op.reg))
        return int(mm.group(1)) if mm else 0

    def _fmem(self, insn, op, kind):
        a = self.addr_expr(insn, op); sz = op.size
        if kind == "f":
            if sz == 10: return f"rdf80({a})"      # x87 extended, explicit integer bit 
            return f"rdf32({a})" if sz == 4 else f"rdf64({a})"
        return {2: f"rdi16({a})", 4: f"rdi32({a})", 8: f"rdi64({a})"}[sz]

    def fpu(self, insn):
        m = insn.mnemonic; ops = insn.operands
        memop = ops[0] if ops and ops[0].type == X86_OP_MEM else None

        # An x87 register here is a `double`, and that is a deliberate model
        # choice: a real x87 register is wider than the values it holds, so
        # widening costs nothing for the loads and stores a compiler emits.
        # It does cost something for the ones it does not. `fld tbyte` reads a
        # genuine 80-bit extended double, `fbld`/`fbstp` read and write packed
        # BCD, and `fldenv`/`fnstenv`/`fsave`/`frstor` move the whole 28-byte
        # FPU environment. None of those fit, and reading eight of ten bytes as
        # a double produces a number that looks plausible and is not.
        # `fld tbyte` and `fstp tbyte` are now honoured - see rdf80/wrf80 - but
        # the rest of the wide operands still are not. fbld/fbstp read and write
        # packed BCD, which is ten bytes of something else entirely, and
        # fldenv/fnstenv/fsave/frstor move the whole FPU environment.
        if m in ("fbld", "fbstp"):
            return [_todo(insn.address, f"x87 packed BCD: {m} {insn.op_str}")]
        if memop is not None and memop.size in (28, 94, 108):
            return [_todo(insn.address, f"x87 m{memop.size * 8}: {m} {insn.op_str}")]

        if m in ("fld",):
            if memop: return [f"fpush(c, {self._fmem(insn, memop, 'f')});"]
            return [f"fpush(c, *fst(c, {self._st_idx(ops[0])}));"]
        if m in ("fild",):
            return [f"fpush(c, {self._fmem(insn, memop, 'i')});"]
        if m in ("fldz",): return ["fpush(c, 0.0);"]
        if m in ("fld1",): return ["fpush(c, 1.0);"]
        # The other five constants the 8087 carries in microcode. A compiler
        # emits fldln2 and fldl2e for log() and exp() whenever it cannot call
        # the CRT helper, and fldpi turns up in any code that builds a rotation
        # - so "rare" they are not. Written to more digits than a double can
        # hold on purpose: the value that matters is the nearest double to the
        # real constant, not to a shortened decimal.
        if m in ("fldpi",):
            return ["fpush(c, 3.14159265358979323846264338327950288);"]
        if m in ("fldl2e",):
            return ["fpush(c, 1.44269504088896340735992468100189214);"]
        if m in ("fldl2t",):
            return ["fpush(c, 3.32192809488736234787031942948939018);"]
        if m in ("fldlg2",):
            return ["fpush(c, 0.301029995663981195213738894724493027);"]
        if m in ("fldln2",):
            return ["fpush(c, 0.693147180559945309417232121458176568);"]
        if m in ("fst", "fstp"):
            pop = "; fpop(c);" if m == "fstp" else ";"
            if memop:
                sz = memop.size; a = self.addr_expr(insn, memop)
                st = "wrf32" if sz == 4 else ("wrf80" if sz == 10 else "wrf64")
                return [f"{st}({a}, *fst(c, 0)){pop}"]
            return [f"*fst(c, {self._st_idx(ops[0])}) = *fst(c, 0){pop}"]
        if m in ("fist", "fistp"):
            pop = "; fpop(c);" if m == "fistp" else ";"
            sz = memop.size; a = self.addr_expr(insn, memop)
            st = {2: "wri16", 4: "wri32", 8: "wri64"}[sz]
            return [f"{st}({a}, *fst(c, 0)){pop}"]
        if m in ("fprem", "fprem1"):
            return ["*fst(c, 0) = fprem_op(c, *fst(c, 0), *fst(c, 1));"]
        if m.startswith("fcmov"):
            # Conditional move between x87 registers, on the integer flags the
            # preceding fucomi or test left behind. Same conditions as cmovcc,
            # spelled the FPU way: fcmovb/fcmove/fcmovbe/fcmovu and their
            # negations.
            tail = m[5:]
            cond = {"b": "c->cf", "e": "c->zf", "be": "(c->cf || c->zf)",
                    "u": "c->pf", "nb": "!c->cf", "ne": "!c->zf",
                    "nbe": "(!c->cf && !c->zf)", "nu": "!c->pf"}.get(tail)
            if cond:
                return [f"if ({cond}) *fst(c, 0) = *fst(c, {self._st_idx(ops[-1])});"]
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
        # The rest of the 8087's transcendental set. These are not exotic: a
        # compiler builds log() out of `fldln2; fxch; fyl2x` and exp() out of
        # `fldl2e; fmul; ...; f2xm1; fscale`, so a game that takes a logarithm
        # anywhere reaches them. Each one consumes st(0) the way the manual
        # says, which is the only part that is easy to get wrong: fyl2x pops,
        # f2xm1 does not.
        if m in ("fyl2x",):        # st(1) = st(1) * log2(st(0)), pop
            return ["{ double _x = *fst(c, 0), _y = *fst(c, 1);"
                    " fpop(c); *fst(c, 0) = _y * log2(_x); }"]
        if m in ("fyl2xp1",):      # st(1) = st(1) * log2(st(0) + 1), pop
            return ["{ double _x = *fst(c, 0), _y = *fst(c, 1);"
                    " fpop(c); *fst(c, 0) = _y * log2(_x + 1.0); }"]
        if m in ("f2xm1",):        # st(0) = 2**st(0) - 1, no pop
            return ["*fst(c, 0) = pow(2.0, *fst(c, 0)) - 1.0;"]
        if m in ("fprem", "fprem1"):
            # Both leave the remainder in st(0) and do not pop. The difference
            # is the rounding of the implied quotient - truncating for fprem,
            # to-nearest for fprem1 - which is fmod and remainder exactly.
            f = "fmod" if m == "fprem" else "remainder"
            return [f"*fst(c, 0) = {f}(*fst(c, 0), *fst(c, 1));"]
        if m in ("fxtract",):      # st(0) -> exponent, then push the mantissa
            return ["{ int _e = 0; double _m = frexp(*fst(c, 0), &_e);"
                    " *fst(c, 0) = (double)(_e - 1); fpush(c, _m * 2.0); }"]
        if m in ("ftst",):         # compare st(0) with zero, flags only
            return ["fcompare(c, *fst(c, 0), 0.0);"]
        if m in ("fxch",):
            # ops[-1], not ops[0]. Capstone prints `fxch st(1)` but reports it
            # with BOTH registers, st(0) first, so ops[0] is always st(0) and
            # the swap this emitted was st(0) with st(0) - a no-op, for every
            # fxch in the program.
            #
            # It is the kind of wrong that does not look wrong: an fxch is
            # usually followed by an fstp, so the value that gets stored is
            # simply the other one, and the arithmetic downstream stays
            # plausible. In Mario Kart it turned a fixed-timestep accumulator
            # into an infinite loop - the game subtracted its step from the
            # wrong register, the step was negative, and the guest thread never
            # came out of the frame it was in.
            #
            # Found twice, independently, on two branches that reached the same
            # line of code. Which is the argument for one toolbox and not
            # three.
            i = self._st_idx(ops[-1]) if ops else 1
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
            # register form. Which register is the DESTINATION depends on
            # whether this pops, and capstone prints one operand for both:
            #
            #   fadd  st(1)   (D8 C1)  st(0) = st(0) + st(1)   dst is st(0)
            #   faddp st(1)   (DE C1)  st(1) = st(1) + st(0)   dst is st(1)
            #
            # The popping forms name their destination, which is the opposite
            # of the non-popping ones, and treating them alike wrote the result
            # into the register the very next fpop threw away - so `faddp`
            # returned the operand it was supposed to have added to. Forty
            # thousand of them in one game.
            if len(ops) == 2:
                a = self._st_idx(ops[0]); b = self._st_idx(ops[1])
            elif pops:
                a = self._st_idx(ops[0]) if ops else 1; b = 0
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
        # fcom and fucom are the same comparison. They differ only in which
        # NaNs raise an invalid-operation exception - a QNaN is quiet for
        # fucom and not for fcom - and this model does not raise FP exceptions
        # at all, so the translation is identical. Which matters a great deal
        # in practice: MSVC emits `fucompp; fnstsw ax; test ah` for an ordinary
        # float comparison, so the unordered forms are the common ones. In one
        # game (Mario Kart Arcade GP DX) `fucompp` alone was 40,796 of the
        # 50,555 instructions the lifter could not express - 81% of the entire
        # gap was this one mnemonic, missing because only `fcompp` was listed.
        if m in ("fcom", "fcomp", "fcompp", "fucom", "fucomp", "fucompp"):
            if memop: src = self._fmem(insn, memop, "f")
            elif ops: src = f"*fst(c, {self._st_idx(ops[0])})"
            else: src = "*fst(c, 1)"
            out = [f"fcompare(c, *fst(c, 0), {src});"]
            if m in ("fcomp", "fucomp"): out.append("fpop(c);")
            if m in ("fcompp", "fucompp"): out += ["fpop(c);", "fpop(c);"]
            return out
        # The P6 forms put the result in EFLAGS instead of the status word, so
        # the compiler can branch on it directly without `fnstsw`. Capstone
        # spells the popping ones both ways (`fcomip` and `fcompi`).
        if m in ("fcomi", "fucomi", "fcomip", "fucomip", "fcompi", "fucompi"):
            src = f"*fst(c, {self._st_idx(ops[-1])})" if ops else "*fst(c, 1)"
            out = [f"fcompare_eflags(c, *fst(c, 0), {src});"]
            if m != "fcomi" and m != "fucomi": out.append("fpop(c);")
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
        return [_todo(insn.address, f"fpu {m} {insn.op_str}")]

    # ---- SSE ----
    def _is_xmm(self, op):
        return op.type == X86_OP_REG and self.md.reg_name(op.reg).startswith("xmm")

    def _xi(self, op):
        """xmm register index. 32-bit code has xmm0..xmm7 and no more."""
        name = self.md.reg_name(op.reg) if op.type == X86_OP_REG else "<mem>"
        if not name.startswith("xmm") or not name[3:].isdigit():
            raise NotImplementedError("not an xmm operand: %s" % name)
        return int(name[3:])

    def is_sse(self, insn):
        m = insn.mnemonic
        if m not in SSE_MNEMONICS and not SSE_CMP_RE.match(m):
            return False
        if m in SSE_AMBIGUOUS:
            return any(self._is_xmm(o) for o in insn.operands)
        return True

    def _ss(self, insn, op):
        """operand as a float (scalar single)"""
        if self._is_xmm(op): return f"c->xmm[{self._xi(op)}].f32[0]"
        return f"rdss({self.addr_expr(insn, op)})"

    def _sd(self, insn, op):
        """operand as a double (scalar double)"""
        if self._is_xmm(op): return f"c->xmm[{self._xi(op)}].f64[0]"
        return f"rdsd({self.addr_expr(insn, op)})"

    def _xm(self, insn, op):
        """operand as a whole 128-bit register value"""
        if self._is_xmm(op): return f"c->xmm[{self._xi(op)}]"
        return f"rdxm({self.addr_expr(insn, op)})"

    def sse(self, insn):
        m = insn.mnemonic
        ops = insn.operands
        d = ops[0]
        s = ops[1] if len(ops) > 1 else None

        # ---- scalar moves ----
        # Loading from memory zeroes the rest of the register; the
        # register-to-register form moves only the low lane. See sse_load_ss.
        if m in ("movss", "movsd"):
            wide = m == "movsd"
            rd_ = self._sd if wide else self._ss
            if self._is_xmm(d) and self._is_xmm(s):
                return [f"{rd_(insn, d)} = {rd_(insn, s)};"]
            if self._is_xmm(d):
                return [f"sse_load_s{'d' if wide else 's'}(&c->xmm[{self._xi(d)}], "
                        f"{rd_(insn, s)});"]
            st = "wrsd" if wide else "wrss"
            return [f"{st}({self.addr_expr(insn, d)}, {rd_(insn, s)});"]

        # movd/movq: the integer-lane moves. Same asymmetry as above.
        if m == "movd":
            if self._is_xmm(d):
                return [f"c->xmm[{self._xi(d)}].u64[0] = {self.src(insn, s)};"
                        f" c->xmm[{self._xi(d)}].u64[1] = 0;"]
            return [self.dst_write(insn, d, f"c->xmm[{self._xi(s)}].u32[0]")]
        if m == "movq":
            if self._is_xmm(d) and self._is_xmm(s):
                return [f"c->xmm[{self._xi(d)}].u64[0] = c->xmm[{self._xi(s)}].u64[0];"
                        f" c->xmm[{self._xi(d)}].u64[1] = 0;"]
            if self._is_xmm(d):
                return [f"c->xmm[{self._xi(d)}].u64[0] = "
                        f"rdxm({self.addr_expr(insn, s)}).u64[0];"
                        f" c->xmm[{self._xi(d)}].u64[1] = 0;"]
            return [f"wrsd({self.addr_expr(insn, d)}, c->xmm[{self._xi(s)}].f64[0]);"]

        # ---- 128-bit moves ----
        if m in SSE_MOV128:
            if self._is_xmm(d):
                return [f"c->xmm[{self._xi(d)}] = {self._xm(insn, s)};"]
            return [f"wrxm({self.addr_expr(insn, d)}, c->xmm[{self._xi(s)}]);"]

        # ---- bitwise, on the whole register ----
        if m in SSE_BITWISE:
            op = SSE_BITWISE[m]
            n = self._xi(d)
            lanes = (f"c->xmm[{n}].u64[0] = ~c->xmm[{n}].u64[0] & _s.u64[0];"
                     f" c->xmm[{n}].u64[1] = ~c->xmm[{n}].u64[1] & _s.u64[1];"
                     if op == "andn" else
                     f"c->xmm[{n}].u64[0] {op}= _s.u64[0];"
                     f" c->xmm[{n}].u64[1] {op}= _s.u64[1];")
            return [f"{{ XMM _s = {self._xm(insn, s)}; {lanes} }}"]

        # ---- scalar arithmetic ----
        if m[:-2] in SSE_ARITH and m[-2:] in ("ss", "sd"):
            wide = m[-2:] == "sd"
            rd_ = self._sd if wide else self._ss
            return [f"{rd_(insn, d)} = {rd_(insn, d)} {SSE_ARITH[m[:-2]]} {rd_(insn, s)};"]
        if m in ("sqrtss", "sqrtsd"):
            wide = m == "sqrtsd"
            rd_ = self._sd if wide else self._ss
            fn = "sqrt" if wide else "sqrtf"
            return [f"{rd_(insn, d)} = {fn}({rd_(insn, s)});"]
        if m in ("minss", "maxss", "minsd", "maxsd"):
            wide = m.endswith("sd")
            rd_ = self._sd if wide else self._ss
            fn = f"sse_{m[:3]}{'d' if wide else 'f'}"
            return [f"{rd_(insn, d)} = {fn}({rd_(insn, d)}, {rd_(insn, s)});"]

        # ---- packed arithmetic, lane by lane ----
        if m[:-2] in SSE_ARITH and m[-2:] in ("ps", "pd"):
            wide = m[-2:] == "pd"
            n, lanes, fld = self._xi(d), (2 if wide else 4), ("f64" if wide else "f32")
            op = SSE_ARITH[m[:-2]]
            return ["{ XMM _s = %s; for (int _i = 0; _i < %d; _i++)"
                    " c->xmm[%d].%s[_i] = c->xmm[%d].%s[_i] %s _s.%s[_i]; }"
                    % (self._xm(insn, s), lanes, n, fld, n, fld, op, fld)]
        if m in ("minps", "maxps", "minpd", "maxpd"):
            wide = m.endswith("pd")
            n, lanes, fld = self._xi(d), (2 if wide else 4), ("f64" if wide else "f32")
            fn = "sse_%s%s" % (m[:3], "d" if wide else "f")
            return ["{ XMM _s = %s; for (int _i = 0; _i < %d; _i++)"
                    " c->xmm[%d].%s[_i] = %s(c->xmm[%d].%s[_i], _s.%s[_i]); }"
                    % (self._xm(insn, s), lanes, n, fld, fn, n, fld, fld)]
        if m in ("sqrtps",):
            n = self._xi(d)
            return ["{ XMM _s = %s; for (int _i = 0; _i < 4; _i++)"
                    " c->xmm[%d].f32[_i] = sqrtf(_s.f32[_i]); }"
                    % (self._xm(insn, s), n)]

        # ---- lane shuffles ----
        # Every one of these reads the destination while writing it, so the
        # destination has to be copied first. Writing lane 0 before reading
        # lane 2 for lane 1 is the classic way to get this subtly wrong.
        if m == "shufps":
            n = self._xi(d)
            imm = insn.operands[2].imm & 0xFF
            sel = [(imm >> 0) & 3, (imm >> 2) & 3, (imm >> 4) & 3, (imm >> 6) & 3]
            return ["{ XMM _d = c->xmm[%d], _s = %s;"
                    " c->xmm[%d].f32[0] = _d.f32[%d]; c->xmm[%d].f32[1] = _d.f32[%d];"
                    " c->xmm[%d].f32[2] = _s.f32[%d]; c->xmm[%d].f32[3] = _s.f32[%d]; }"
                    % (n, self._xm(insn, s), n, sel[0], n, sel[1], n, sel[2], n, sel[3])]
        if m in ("unpcklps", "unpckhps"):
            n = self._xi(d)
            lo = m == "unpcklps"
            a, b = (0, 1) if lo else (2, 3)
            return ["{ XMM _d = c->xmm[%d], _s = %s;"
                    " c->xmm[%d].f32[0] = _d.f32[%d]; c->xmm[%d].f32[1] = _s.f32[%d];"
                    " c->xmm[%d].f32[2] = _d.f32[%d]; c->xmm[%d].f32[3] = _s.f32[%d]; }"
                    % (n, self._xm(insn, s), n, a, n, a, n, b, n, b)]

        # ---- compares that set flags ----
        if m in ("ucomiss", "comiss", "ucomisd", "comisd"):
            rd_ = self._sd if m.endswith("sd") else self._ss
            return [f"sse_compare(c, {rd_(insn, d)}, {rd_(insn, s)});"]

        # ---- compares that write a mask ----
        mm = SSE_CMP_RE.match(m)
        if mm:
            pred, width = mm.group(1), mm.group(2)
            wide = width == "sd"
            rd_ = self._sd if wide else self._ss
            ctype = "double" if wide else "float"
            lane = f"c->xmm[{self._xi(d)}].u64[0]" if wide else f"c->xmm[{self._xi(d)}].u32[0]"
            ones = "~(uint64_t)0" if wide else "0xFFFFFFFFu"
            zero = "(uint64_t)0" if wide else "0u"
            return [f"{{ {ctype} _a = {rd_(insn, d)}, _b = {rd_(insn, s)};"
                    f" {lane} = {SSE_CMP_PRED[pred]} ? {ones} : {zero}; }}"]

        # ---- conversions ----
        if m in ("cvtsi2ss", "cvtsi2sd"):          # int32 -> float, low lane only
            lane = self._sd if m.endswith("sd") else self._ss
            return [f"{lane(insn, d)} = (int32_t)({self.src(insn, s)});"]
        if m in ("cvttss2si", "cvttsd2si"):        # float -> int32, truncating
            rd_ = self._sd if m.startswith("cvttsd") else self._ss
            return [self.dst_write(insn, d, f"sse_cvtt_i32({rd_(insn, s)})")]
        if m in ("cvtss2si", "cvtsd2si"):          # float -> int32, to nearest
            rd_ = self._sd if m.startswith("cvtsd") else self._ss
            return [self.dst_write(insn, d, f"sse_cvtt_i32(nearbyint({rd_(insn, s)}))")]
        if m == "cvtss2sd":
            return [f"c->xmm[{self._xi(d)}].f64[0] = {self._ss(insn, s)};"]
        if m == "cvtsd2ss":
            return [f"c->xmm[{self._xi(d)}].f32[0] = (float)({self._sd(insn, s)});"]

        # ---- packed conversions ----
        #
        # All four lanes, which is what a compiler emits for a float4 cast and
        # what the scalar forms above deliberately do not do. cvtps2dq rounds
        # to nearest (the default mode; the game never changes MXCSR) and
        # cvttps2dq truncates - the extra `t` is the whole difference and
        # getting it backwards is a silently wrong coordinate.
        if m in ("cvtdq2ps", "cvtps2dq", "cvttps2dq"):
            n, i = self._xi(d), None
            src = f"_s"
            body = []
            for i in range(4):
                if m == "cvtdq2ps":
                    body.append(f"c->xmm[{n}].f32[{i}] = (float)_s.i32[{i}];")
                elif m == "cvttps2dq":
                    body.append(f"c->xmm[{n}].i32[{i}] = sse_cvtt_i32(_s.f32[{i}]);")
                else:
                    body.append(f"c->xmm[{n}].i32[{i}] = "
                                f"sse_cvtt_i32(nearbyintf(_s.f32[{i}]));")
            return [f"{{ XMM _s = {self._xm(insn, s)}; " + " ".join(body) + " }"]

        # ---- the two that change lane width ----
        #
        # cvtps2pd reads TWO floats - the low 64 bits - and writes two doubles.
        # That asymmetry is the whole reason it needs its own case: reading the
        # source with _xm() would fetch sixteen bytes for an eight-byte
        # operand, which is a fault the moment the operand sits in the last
        # eight bytes of a page. So the memory form reads exactly the two
        # floats it is entitled to.
        #
        # Both read the source into locals before writing the destination,
        # because `cvtps2pd xmm0, xmm0` is real code and the lanes overlap.
        if m == "cvtps2pd":
            n = self._xi(d)
            if self._is_xmm(s):
                j = self._xi(s)
                src = f"c->xmm[{j}].f32[0], _b = c->xmm[{j}].f32[1]"
                return [f"{{ float _a = {src};"
                        f" c->xmm[{n}].f64[0] = _a; c->xmm[{n}].f64[1] = _b; }}"]
            return [f"{{ uint32_t _p = {self.addr_expr(insn, s)};"
                    f" float _a = rdf32(_p), _b = rdf32(_p + 4u);"
                    f" c->xmm[{n}].f64[0] = _a; c->xmm[{n}].f64[1] = _b; }}"]

        # cvtpd2ps is the other way: two doubles in, two floats into the low 64
        # bits, and the top 64 bits ZEROED - which is architectural, not tidy,
        # and code that then reads lane 2 or 3 depends on it.
        if m == "cvtpd2ps":
            n = self._xi(d)
            return [f"{{ XMM _s = {self._xm(insn, s)};"
                    f" c->xmm[{n}].f32[0] = (float)_s.f64[0];"
                    f" c->xmm[{n}].f32[1] = (float)_s.f64[1];"
                    f" c->xmm[{n}].i32[2] = 0; c->xmm[{n}].i32[3] = 0; }}"]

        return [_todo(insn.address, f"sse {m} {insn.op_str}")]

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
        # Per function, not per Lifter. Two lifted functions can cover the same
        # `jmp [table]` - carving by descent produces overlapping extents - and
        # a stale entry here makes the second one emit `goto` to labels that
        # only exist in the first, which the C compiler rejects outright.
        self.jumptables = {}
        insns = list(self.md.disasm(code, start))
        # collect intra-function branch targets
        end = start + len(code)

        # An extent that ends in the middle of an instruction.
        #
        # Clamping a recovered function against the next catalog entry does
        # this whenever that entry is false, and on a stripped binary some
        # always are. Capstone then stops one instruction early, and the
        # function's fall-through address is *inside* a real instruction:
        # dispatching there decodes its tail as something else. `74 5B` - a
        # two-byte `je` - read from its second byte is `pop ebx`, and a guest
        # stack one slot out is the worst failure this project can produce.
        #
        # The bytes are in the image either way, so read the few more that
        # finish the instruction and keep it. The fall-through then lands where
        # the program's own code does, which is somewhere with a body.
        if insns and self.read_va:
            tail = insns[-1].address + insns[-1].size
            if tail < end:
                try:
                    extra = self.read_va(tail, (end - tail) + 15)
                except Exception:
                    extra = b""
                for ins in self.md.disasm(extra, tail):
                    if ins.address >= end:
                        break
                    insns.append(ins)
                end = max(end, insns[-1].address + insns[-1].size)

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
                        # A switch indexes: `jmp [reg*4 + table]`. Without the
                        # scaled index this is `jmp [__imp_memcpy]` - an IAT
                        # thunk, of which a PE has hundreds - and walking the
                        # import table as if it were a jump table invents
                        # thousands of branch targets out of hint RVAs.
                        if (op.mem.index and op.mem.scale == 4 and
                                self.in_image(d)):
                            tgts = self.resolve_jumptable(d)
                            if tgts:
                                self.jumptables[ins.address] = tgts
                                # Only the arms that are instruction boundaries
                                # in THIS function can be goto labels; the rest
                                # are dispatched, see the emitter.
                                labels.update(t for t in tgts if t in insn_addrs)
        out = []
        out.append(f"void L_{start:08X}(CPU *c)")
        out.append("{")
        for ins in insns:
            if ins.address in labels:
                out.append(f"L_{ins.address:08X}:")
            for line in self.translate(ins, labels):
                out.append(f"    {line:<60} /* {ins.address:08X}: {ins.mnemonic} {ins.op_str} */")

        # A body whose last instruction is not a transfer falls THROUGH into
        # whatever follows it, and on x86 that is a real control transfer - so
        # the C function must make it one rather than just return. Returning
        # instead skips the callee's `ret`, leaves esp four bytes low, and the
        # caller resumes reading its own frame one slot out. That is the worst
        # class of bug this project can produce: nothing faults, and every
        # value after it is off by one slot.
        #
        # It happens whenever the extent is shorter than the real function:
        # a bounds file that disagrees, a catalog clamped to the next function
        # start (disasm32.clamp_extents), or a decode that stopped early on
        # bytes capstone would not take.
        # `repz ret` is a plain ret with an F3 prefix, so compare the last word
        # of the mnemonic, not the whole thing.
        last = insns[-1].mnemonic.split()[-1] if insns else None
        if last not in ("ret", "retn", "retf", "jmp", "iret", "iretd", "hlt"):
            # After the last instruction decoded, NOT at the end of the extent.
            # They differ exactly when the extent cuts an instruction in half -
            # a clamp to a false function start does that - and then the extent
            # end is an address in the middle of a real instruction. Dispatching
            # there decodes the tail of it as something else: `74 5B`, a two-byte
            # `je`, becomes a one-byte `pop ebx` at the second byte, and the
            # guest stack is one slot out from then on with nothing to show for
            # it. Mario Kart lost a pointer to a memcpy that way.
            nxt = insns[-1].address + insns[-1].size if insns else end
            out.append(f"    /* extent ends mid-function: fall through */")
            out.append(f"    dispatch(c, 0x{nxt:08X}u); return;")

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


def selftest():
    """The x87 forms where capstone's operand list is a trap.

    difftest.py runs lifted C against Unicorn, and it covers lift32.py - the
    global-register lifter - not this one. Both of the bugs below had already
    been found and fixed there and came back here, so this is the smallest
    check that says so: lift the bytes and read the C.

    Text assertions, because the thing being tested is a code generator and the
    text is its output. Run it directly:  python tools/lift/lift32_cpu.py --selftest
    """
    lf = Lifter(None, 0x100000)
    def emit(code):
        insn = next(lf.md.disasm(code, 0x401000))
        return " ".join(lf.fpu(insn))

    # fxch st(N) is reported as [st(0), st(N)]: the first operand is always
    # st(0), so an emitter reading ops[0] swaps st(0) with itself and every
    # fxch in the program does nothing.
    for code, want in ((b"\xd9\xc9", 1), (b"\xd9\xca", 2), (b"\xd9\xcd", 5)):
        out = emit(code)
        assert f"*fst(c, {want})" in out and "fst(c, 0) = *fst(c, 0)" not in out, \
            "fxch st(%d) lifted as a no-op: %s" % (want, out)

    # The popping arithmetic names its DESTINATION - `faddp st(1)` is
    # st(1) += st(0) - which is the opposite of `fadd st(1)`, st(0) += st(1).
    # Writing to st(0) puts the result in the slot fpop() then discards.
    assert emit(b"\xde\xc1").startswith("*fst(c, 1) ="), \
        "faddp st(1) writes the wrong register: " + emit(b"\xde\xc1")
    assert emit(b"\xde\xca").startswith("*fst(c, 2) ="), \
        "fmulp st(2) writes the wrong register: " + emit(b"\xde\xca")
    # ...while the non-popping form still lands in st(0).
    assert emit(b"\xd8\xc1").startswith("*fst(c, 0) ="), \
        "fadd st(1) writes the wrong register: " + emit(b"\xd8\xc1")
    # fsubrp st(1): st(1) = st(0) - st(1), reversed as well as redirected.
    out = emit(b"\xde\xe1")
    assert out.startswith("*fst(c, 1) =") and "(*fst(c, 0)) - (*fst(c, 1))" in out, \
        "fsubrp st(1) is wrong: " + out

    print("lift32_cpu x87 selftest: ok")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        main()

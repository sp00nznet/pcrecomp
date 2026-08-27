"""
decode16.py - 16-bit x86 Instruction Decoder for Civilization Recomp

Table-driven decoder for 8086/80186 instructions as emitted by
Microsoft C 5.x. Handles all real-mode addressing, segment overrides,
ModR/M byte decoding, and the MSC overlay manager INT 3Fh calls.

Part of the Civ Recomp project (sp00nznet/civ)
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

# ─── Operand types ───────────────────────────────────────────────

class OpType(Enum):
    NONE = auto()
    REG8 = auto()      # 8-bit register (AL, CL, DL, BL, AH, CH, DH, BH)
    REG16 = auto()     # 16-bit register (AX, CX, DX, BX, SP, BP, SI, DI)
    REG32 = auto()     # 32-bit register (EAX..EDI) - operand-size 0x66 prefix
    SREG = auto()      # Segment register (ES, CS, SS, DS)
    MEM = auto()        # Memory operand [seg:base+index+disp]
    IMM8 = auto()      # 8-bit immediate
    IMM16 = auto()     # 16-bit immediate
    IMM32 = auto()     # 32-bit immediate - operand-size 0x66 prefix
    REL8 = auto()      # 8-bit relative offset (for short jumps)
    REL16 = auto()     # 16-bit relative offset (for near jumps/calls)
    FAR = auto()        # Far pointer seg:off (for far jumps/calls)
    MOFFS = auto()     # Direct memory offset (MOV AL,[addr] etc.)

REG8_NAMES  = ['al', 'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh']
REG16_NAMES = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di']
REG32_NAMES = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
SREG_NAMES  = ['es', 'cs', 'ss', 'ds', 'fs', 'gs']

# 16-bit ModR/M effective address components
EA_BASES = [
    ('bx', 'si'), ('bx', 'di'), ('bp', 'si'), ('bp', 'di'),
    ('si', None),  ('di', None),  ('bp', None),  ('bx', None),
]
# Default segment for each r/m value (mod != 11)
EA_DEFAULT_SEG = ['ds', 'ds', 'ss', 'ss', 'ds', 'ds', 'ss', 'ds']

@dataclass
class Operand:
    type: OpType = OpType.NONE
    reg: int = 0           # Register index
    seg: str = ''          # Segment override or far segment
    base: str = ''         # Base register name
    index: str = ''        # Index register name
    disp: int = 0          # Displacement or immediate value
    size: int = 0          # Operand size in bytes (1 or 2)
    far_seg: int = 0       # Far pointer segment value

    def __repr__(self):
        if self.type == OpType.REG8:
            return REG8_NAMES[self.reg]
        elif self.type == OpType.REG16:
            return REG16_NAMES[self.reg]
        elif self.type == OpType.REG32:
            return REG32_NAMES[self.reg]
        elif self.type == OpType.SREG:
            return SREG_NAMES[self.reg]
        elif self.type == OpType.IMM32:
            return f'0x{self.disp & 0xFFFFFFFF:X}'
        elif self.type == OpType.IMM8 or self.type == OpType.IMM16:
            return f'0x{self.disp & 0xFFFF:X}'
        elif self.type == OpType.REL8 or self.type == OpType.REL16:
            return f'0x{self.disp & 0xFFFF:04X}'
        elif self.type == OpType.FAR:
            return f'{self.far_seg:04X}:{self.disp:04X}'
        elif self.type == OpType.MEM:
            prefix = f'{self.seg}:' if self.seg else ''
            sz = 'byte ' if self.size == 1 else 'word ' if self.size == 2 else 'dword ' if self.size == 4 else ''
            parts = []
            if self.base: parts.append(self.base)
            if self.index: parts.append(self.index)
            if self.disp or not parts:
                if self.disp < 0 and parts:
                    parts.append(f'-0x{(-self.disp) & 0xFFFF:X}')
                else:
                    parts.append(f'0x{self.disp & 0xFFFF:X}')
            return f'{sz}{prefix}[{"+".join(parts)}]'
        elif self.type == OpType.MOFFS:
            prefix = f'{self.seg}:' if self.seg else 'ds:'
            sz = 'byte ' if self.size == 1 else 'word ' if self.size == 2 else 'dword ' if self.size == 4 else ''
            return f'{sz}{prefix}[0x{self.disp & 0xFFFF:X}]'
        return '?'


# ─── Instruction representation ──────────────────────────────────

@dataclass
class Instruction:
    offset: int = 0         # File offset of this instruction
    address: int = 0        # Logical address (segment-relative)
    length: int = 0         # Total instruction length in bytes
    raw: bytes = b''        # Raw instruction bytes

    mnemonic: str = ''      # Instruction mnemonic
    op1: Optional[Operand] = None
    op2: Optional[Operand] = None
    op3: Optional[Operand] = None   # third operand (e.g. SHLD/SHRD count)
    prefix: str = ''        # REP/REPZ/REPNZ prefix
    seg_override: str = ''  # Segment override prefix (es/cs/ss/ds)

    # For overlay calls (INT 3Fh)
    overlay_num: int = -1
    overlay_off: int = 0

    def __repr__(self):
        parts = []
        if self.prefix:
            parts.append(self.prefix)
        parts.append(self.mnemonic)
        if self.op1:
            s = repr(self.op1)
            if self.op2:
                s += f', {repr(self.op2)}'
            parts.append(s)
        return ' '.join(parts)


# ─── Decoder ─────────────────────────────────────────────────────


class EndOfSegment(IndexError):
    """A read ran past the end of the segment being decoded.

    Subclasses IndexError so the existing `except IndexError` recovery paths --
    which turn a truncated instruction into a `db` byte -- keep working."""

class Decoder:
    """16-bit x86 instruction decoder."""

    def __init__(self, data: bytes, base_offset: int = 0):
        self.data = data
        self.base = base_offset
        self.pos = 0

    # A segment can end mid-instruction -- the tail is usually padding or data the
    # linker never filled. Reading past it raised IndexError and aborted the whole
    # decode (Dogz's THINK.DLL does this on its first code segment). Raise a
    # private end-of-segment signal instead, so the caller can drop the partial
    # instruction and stop the walk. Fabricating zero bytes would be worse: the
    # padding decodes as `add [bx+si], al` and invents instructions that are not
    # there.
    def _u8(self) -> int:
        if self.pos >= len(self.data):
            raise EndOfSegment()
        b = self.data[self.pos]
        self.pos += 1
        return b

    def _s8(self) -> int:
        b = self._u8()
        return b if b < 128 else b - 256

    def _u16(self) -> int:
        lo = self._u8()
        hi = self._u8()
        return lo | (hi << 8)

    def _s16(self) -> int:
        v = self._u16()
        return v if v < 32768 else v - 65536

    def _u32(self) -> int:
        return self._u16() | (self._u16() << 16)

    def _s32(self) -> int:
        v = self._u32()
        return v if v < 0x80000000 else v - 0x100000000

    # ── Operand-size (0x66) aware builders ──
    def _wbytes(self) -> int:
        """Wide-operand size in bytes: 4 with 0x66 prefix, else 2."""
        return 4 if getattr(self, 'op32', False) else 2

    def _wreg(self, reg: int) -> 'Operand':
        """A wide register: EAX.. with 0x66, else AX.."""
        if getattr(self, 'op32', False):
            return Operand(type=OpType.REG32, reg=reg, size=4)
        return Operand(type=OpType.REG16, reg=reg, size=2)

    def _wimm(self) -> 'Operand':
        """A wide immediate: imm32 with 0x66, else imm16."""
        if getattr(self, 'op32', False):
            return Operand(type=OpType.IMM32, disp=self._u32(), size=4)
        return Operand(type=OpType.IMM16, disp=self._u16(), size=2)

    def _decode_modrm(self, wide: bool, seg_override: str = '') -> tuple:
        """Decode ModR/M byte. Returns (reg_operand, rm_operand, reg).
        For wide operands, honors the 0x66 operand-size prefix (32-bit regs/mem).
        Addressing stays 16-bit (0x66 changes operand size, not address size)."""
        op32 = wide and getattr(self, 'op32', False)
        wsize = 4 if op32 else 2
        wtype = OpType.REG32 if op32 else OpType.REG16
        modrm = self._u8()
        mod = (modrm >> 6) & 3
        reg = (modrm >> 3) & 7
        rm  = modrm & 7

        if wide:
            reg_op = Operand(type=wtype, reg=reg, size=wsize)
        else:
            reg_op = Operand(type=OpType.REG8, reg=reg, size=1)

        if mod == 3:
            # Register direct
            if wide:
                rm_op = Operand(type=wtype, reg=rm, size=wsize)
            else:
                rm_op = Operand(type=OpType.REG8, reg=rm, size=1)
        else:
            # Memory
            base_r, idx_r = EA_BASES[rm]
            disp = 0
            seg = seg_override

            if mod == 0 and rm == 6:
                # Special: [disp16]
                disp = self._u16()
                base_r = ''
                idx_r = None
                if not seg: seg = 'ds'
            elif mod == 1:
                disp = self._s8()
            elif mod == 2:
                disp = self._s16()

            if not seg:
                seg = EA_DEFAULT_SEG[rm] if not (mod == 0 and rm == 6) else 'ds'

            rm_op = Operand(
                type=OpType.MEM,
                base=base_r,
                index=idx_r or '',
                disp=disp,
                seg=seg,
                size=(wsize if wide else 1),
            )

        return reg_op, rm_op, reg

    def _safe(self, n: int = 1) -> bool:
        """Check if n bytes remain."""
        return self.pos + n <= len(self.data)

    def decode_one(self) -> Optional[Instruction]:
        """Decode a single instruction at the current position."""
        if self.pos >= len(self.data):
            return None

        inst = Instruction()
        inst.offset = self.base + self.pos
        inst.address = self.pos
        start = self.pos

        # Handle prefixes
        seg_override = ''
        rep_prefix = ''
        self.op32 = False     # 0x66 operand-size override (16<->32)
        self.addr32 = False   # 0x67 address-size override
        while self.pos < len(self.data):
            b = self.data[self.pos]
            if b == 0x26:
                seg_override = 'es'; self.pos += 1
            elif b == 0x2E:
                seg_override = 'cs'; self.pos += 1
            elif b == 0x36:
                seg_override = 'ss'; self.pos += 1
            elif b == 0x3E:
                seg_override = 'ds'; self.pos += 1
            elif b == 0x64:
                seg_override = 'fs'; self.pos += 1
            elif b == 0x65:
                # FS/GS are 386 additions, so 16-bit code is not "supposed" to
                # use them -- but performance-minded 16-bit code does. Indeo 3's
                # IR32.DLL keeps decoder state in an FS-addressed block and
                # reaches it with `64 89 2E ..` / `67 64 89 ..`. Without these
                # two prefixes the 0x64 byte decodes as an unknown opcode, the
                # sweep resyncs one byte in, and the misalignment then blames
                # perfectly ordinary movs that follow it.
                seg_override = 'gs'; self.pos += 1
            elif b == 0x66:
                self.op32 = True; self.pos += 1   # operand-size override
            elif b == 0x67:
                self.addr32 = True; self.pos += 1  # address-size override
            elif b == 0x9B and self.pos + 1 < len(self.data)                     and 0xD8 <= self.data[self.pos + 1] <= 0xDF:
                # FWAIT immediately before an ESC opcode is part of that x87
                # instruction, and IDA marks the head on the 0x9B. Decoding it
                # as a standalone `wait` swallowed the head and the real opcode
                # was never decoded at all -- `9B DD 7E E0` (fstsw m16) vanished,
                # so Borland's compare idiom
                #   fcomp ...; fstsw [bp-N]; mov ax,[bp-N]; sahf; jbe
                # loaded a stale stack local and every float comparison in the
                # engine branched on garbage. Treat it as a prefix.
                self.pos += 1
            elif b == 0xF2:
                rep_prefix = 'repnz'; self.pos += 1
            elif b == 0xF3:
                rep_prefix = 'rep'; self.pos += 1
            elif b == 0xF0:
                self.pos += 1  # LOCK prefix (ignore)
            else:
                break

        inst.seg_override = seg_override
        inst.prefix = rep_prefix

        if self.pos >= len(self.data):
            return None

        opcode = self._u8()

        # ─── Main opcode decode ───

        # ALU ops: ADD, OR, ADC, SBB, AND, SUB, XOR, CMP
        # Pattern: 0x00-0x3F (groups of 8, 6 encodings each)
        ALU_NAMES = ['add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp']
        alu_group = opcode >> 3
        alu_sub = opcode & 7

        if opcode <= 0x3F and alu_sub <= 5 and alu_group < 8:
            mnem = ALU_NAMES[alu_group]
            inst.mnemonic = mnem
            if alu_sub == 0:    # r/m8, reg8
                reg, rm, _ = self._decode_modrm(False, seg_override)
                inst.op1 = rm; inst.op2 = reg
            elif alu_sub == 1:  # r/m16, reg16
                reg, rm, _ = self._decode_modrm(True, seg_override)
                inst.op1 = rm; inst.op2 = reg
            elif alu_sub == 2:  # reg8, r/m8
                reg, rm, _ = self._decode_modrm(False, seg_override)
                inst.op1 = reg; inst.op2 = rm
            elif alu_sub == 3:  # reg16, r/m16
                reg, rm, _ = self._decode_modrm(True, seg_override)
                inst.op1 = reg; inst.op2 = rm
            elif alu_sub == 4:  # AL, imm8
                inst.op1 = Operand(type=OpType.REG8, reg=0, size=1)
                inst.op2 = Operand(type=OpType.IMM8, disp=self._u8(), size=1)
            elif alu_sub == 5:  # (e)AX, imm16/32
                inst.op1 = self._wreg(0)
                inst.op2 = self._wimm()

        # PUSH/POP segment registers
        elif opcode in (0x06, 0x0E, 0x16, 0x1E):
            sreg = (opcode >> 3) & 3
            inst.mnemonic = 'push'
            inst.op1 = Operand(type=OpType.SREG, reg=sreg, size=2)
        elif opcode in (0x07, 0x17, 0x1F):
            sreg = (opcode >> 3) & 3
            inst.mnemonic = 'pop'
            inst.op1 = Operand(type=OpType.SREG, reg=sreg, size=2)

        # DAA, DAS, AAA, AAS
        elif opcode == 0x27: inst.mnemonic = 'daa'
        elif opcode == 0x2F: inst.mnemonic = 'das'
        elif opcode == 0x37: inst.mnemonic = 'aaa'
        elif opcode == 0x3F: inst.mnemonic = 'aas'

        # INC reg16/32 (0x40-0x47)
        elif 0x40 <= opcode <= 0x47:
            inst.mnemonic = 'inc'
            inst.op1 = self._wreg(opcode - 0x40)

        # DEC reg16/32 (0x48-0x4F)
        elif 0x48 <= opcode <= 0x4F:
            inst.mnemonic = 'dec'
            inst.op1 = self._wreg(opcode - 0x48)

        # PUSH reg16/32 (0x50-0x57)
        elif 0x50 <= opcode <= 0x57:
            inst.mnemonic = 'push'
            inst.op1 = self._wreg(opcode - 0x50)

        # POP reg16/32 (0x58-0x5F)
        elif 0x58 <= opcode <= 0x5F:
            inst.mnemonic = 'pop'
            inst.op1 = self._wreg(opcode - 0x58)

        # PUSHA/POPA (80186+); PUSHAD/POPAD with 0x66
        elif opcode == 0x60: inst.mnemonic = 'pushad' if self.op32 else 'pusha'
        elif opcode == 0x61: inst.mnemonic = 'popad' if self.op32 else 'popa'

        # PUSH imm16/32 (80186+)
        elif opcode == 0x68:
            inst.mnemonic = 'push'
            inst.op1 = self._wimm()

        # IMUL r16/32, r/m, imm16/32 (80186+)
        elif opcode == 0x69:
            reg, rm, rn = self._decode_modrm(True, seg_override)
            inst.mnemonic = 'imul'
            inst.op1 = reg
            inst.op2 = self._wimm()

        # PUSH imm8 (sign-extended to operand size) (80186+)
        elif opcode == 0x6A:
            inst.mnemonic = 'push'
            if self.op32:
                inst.op1 = Operand(type=OpType.IMM32, disp=self._s8() & 0xFFFFFFFF, size=4)
            else:
                inst.op1 = Operand(type=OpType.IMM8, disp=self._s8() & 0xFFFF, size=2)

        # IMUL r16, r/m16, imm8 (80186+)
        elif opcode == 0x6B:
            reg, rm, rn = self._decode_modrm(True, seg_override)
            inst.mnemonic = 'imul'
            inst.op1 = reg
            inst.op2 = Operand(type=OpType.IMM8, disp=self._s8() & 0xFFFF, size=2)

        # Jcc short (0x70-0x7F)
        elif 0x70 <= opcode <= 0x7F:
            CC_NAMES = ['jo','jno','jb','jae','je','jne','jbe','ja',
                        'js','jns','jp','jnp','jl','jge','jle','jg']
            inst.mnemonic = CC_NAMES[opcode - 0x70]
            rel = self._s8()
            target = (self.pos + rel) & 0xFFFF
            inst.op1 = Operand(type=OpType.REL8, disp=target, size=2)

        # Group 1: ALU r/m, imm
        elif opcode in (0x80, 0x81, 0x82, 0x83):
            wide = opcode in (0x81, 0x83)
            sign_ext = opcode in (0x82, 0x83)
            reg, rm, alu_op = self._decode_modrm(wide, seg_override)
            inst.mnemonic = ALU_NAMES[alu_op]
            inst.op1 = rm
            if sign_ext and wide:        # 0x83: imm8 sign-extended to operand size
                if self.op32:
                    inst.op2 = Operand(type=OpType.IMM32, disp=self._s8() & 0xFFFFFFFF, size=4)
                else:
                    inst.op2 = Operand(type=OpType.IMM8, disp=self._s8() & 0xFFFF, size=2)
            elif wide:                   # 0x81: imm16/imm32
                inst.op2 = self._wimm()
            else:
                inst.op2 = Operand(type=OpType.IMM8, disp=self._u8(), size=1)

        # TEST r/m, reg
        elif opcode == 0x84:
            reg, rm, _ = self._decode_modrm(False, seg_override)
            inst.mnemonic = 'test'; inst.op1 = rm; inst.op2 = reg
        elif opcode == 0x85:
            reg, rm, _ = self._decode_modrm(True, seg_override)
            inst.mnemonic = 'test'; inst.op1 = rm; inst.op2 = reg

        # XCHG r/m, reg
        elif opcode == 0x86:
            reg, rm, _ = self._decode_modrm(False, seg_override)
            inst.mnemonic = 'xchg'; inst.op1 = rm; inst.op2 = reg
        elif opcode == 0x87:
            reg, rm, _ = self._decode_modrm(True, seg_override)
            inst.mnemonic = 'xchg'; inst.op1 = rm; inst.op2 = reg

        # MOV r/m, reg and MOV reg, r/m
        elif opcode == 0x88:
            reg, rm, _ = self._decode_modrm(False, seg_override)
            inst.mnemonic = 'mov'; inst.op1 = rm; inst.op2 = reg
        elif opcode == 0x89:
            reg, rm, _ = self._decode_modrm(True, seg_override)
            inst.mnemonic = 'mov'; inst.op1 = rm; inst.op2 = reg
        elif opcode == 0x8A:
            reg, rm, _ = self._decode_modrm(False, seg_override)
            inst.mnemonic = 'mov'; inst.op1 = reg; inst.op2 = rm
        elif opcode == 0x8B:
            reg, rm, _ = self._decode_modrm(True, seg_override)
            inst.mnemonic = 'mov'; inst.op1 = reg; inst.op2 = rm

        # MOV r/m16, sreg
        elif opcode == 0x8C:
            reg, rm, rn = self._decode_modrm(True, seg_override)
            inst.mnemonic = 'mov'
            inst.op1 = rm
            inst.op2 = Operand(type=OpType.SREG, reg=rn & 3, size=2)

        # LEA reg16, m
        elif opcode == 0x8D:
            reg, rm, _ = self._decode_modrm(True, seg_override)
            inst.mnemonic = 'lea'; inst.op1 = reg; inst.op2 = rm

        # MOV sreg, r/m16
        elif opcode == 0x8E:
            reg, rm, rn = self._decode_modrm(True, seg_override)
            inst.mnemonic = 'mov'
            inst.op1 = Operand(type=OpType.SREG, reg=rn & 3, size=2)
            inst.op2 = rm

        # POP r/m16
        elif opcode == 0x8F:
            _, rm, _ = self._decode_modrm(True, seg_override)
            inst.mnemonic = 'pop'; inst.op1 = rm

        # NOP (XCHG AX, AX)
        elif opcode == 0x90:
            inst.mnemonic = 'nop'

        # XCHG (e)AX, reg16/32
        elif 0x91 <= opcode <= 0x97:
            inst.mnemonic = 'xchg'
            inst.op1 = self._wreg(0)
            inst.op2 = self._wreg(opcode - 0x90)

        # CBW/CWDE, CWD/CDQ
        elif opcode == 0x98: inst.mnemonic = 'cwde' if self.op32 else 'cbw'
        elif opcode == 0x99: inst.mnemonic = 'cdq' if self.op32 else 'cwd'

        # CALL far ptr
        elif opcode == 0x9A:
            off = self._u16()
            seg = self._u16()
            inst.mnemonic = 'call'
            inst.op1 = Operand(type=OpType.FAR, disp=off, far_seg=seg, size=4)

        # PUSHF/PUSHFD, POPF/POPFD
        elif opcode == 0x9C: inst.mnemonic = 'pushfd' if self.op32 else 'pushf'
        elif opcode == 0x9D: inst.mnemonic = 'popfd' if self.op32 else 'popf'

        # SAHF, LAHF
        elif opcode == 0x9E: inst.mnemonic = 'sahf'
        elif opcode == 0x9F: inst.mnemonic = 'lahf'

        # MOV AL/AX, moffs
        elif opcode == 0xA0:
            inst.mnemonic = 'mov'
            inst.op1 = Operand(type=OpType.REG8, reg=0, size=1)
            inst.op2 = Operand(type=OpType.MOFFS, disp=self._u16(), seg=seg_override or 'ds', size=1)
        elif opcode == 0xA1:
            inst.mnemonic = 'mov'
            inst.op1 = self._wreg(0)
            inst.op2 = Operand(type=OpType.MOFFS, disp=self._u16(), seg=seg_override or 'ds', size=self._wbytes())

        # MOV moffs, AL/AX
        elif opcode == 0xA2:
            inst.mnemonic = 'mov'
            inst.op1 = Operand(type=OpType.MOFFS, disp=self._u16(), seg=seg_override or 'ds', size=1)
            inst.op2 = Operand(type=OpType.REG8, reg=0, size=1)
        elif opcode == 0xA3:
            inst.mnemonic = 'mov'
            inst.op1 = Operand(type=OpType.MOFFS, disp=self._u16(), seg=seg_override or 'ds', size=self._wbytes())
            inst.op2 = self._wreg(0)

        # String ops (word form -> dword with 0x66)
        elif opcode == 0xA4: inst.mnemonic = 'movsb'
        elif opcode == 0xA5: inst.mnemonic = 'movsd' if self.op32 else 'movsw'
        elif opcode == 0xA6: inst.mnemonic = 'cmpsb'
        elif opcode == 0xA7: inst.mnemonic = 'cmpsd' if self.op32 else 'cmpsw'

        # TEST AL/AX, imm
        elif opcode == 0xA8:
            inst.mnemonic = 'test'
            inst.op1 = Operand(type=OpType.REG8, reg=0, size=1)
            inst.op2 = Operand(type=OpType.IMM8, disp=self._u8(), size=1)
        elif opcode == 0xA9:
            inst.mnemonic = 'test'
            inst.op1 = self._wreg(0)
            inst.op2 = self._wimm()

        # STOSB/W/D, LODSB/W/D, SCASB/W/D
        elif opcode == 0xAA: inst.mnemonic = 'stosb'
        elif opcode == 0xAB: inst.mnemonic = 'stosd' if self.op32 else 'stosw'
        elif opcode == 0xAC: inst.mnemonic = 'lodsb'
        elif opcode == 0xAD: inst.mnemonic = 'lodsd' if self.op32 else 'lodsw'
        elif opcode == 0xAE: inst.mnemonic = 'scasb'
        elif opcode == 0xAF: inst.mnemonic = 'scasd' if self.op32 else 'scasw'

        # MOV reg8, imm8 (0xB0-0xB7)
        elif 0xB0 <= opcode <= 0xB7:
            inst.mnemonic = 'mov'
            inst.op1 = Operand(type=OpType.REG8, reg=opcode - 0xB0, size=1)
            inst.op2 = Operand(type=OpType.IMM8, disp=self._u8(), size=1)

        # MOV reg16/32, imm16/32 (0xB8-0xBF)
        elif 0xB8 <= opcode <= 0xBF:
            inst.mnemonic = 'mov'
            inst.op1 = self._wreg(opcode - 0xB8)
            inst.op2 = self._wimm()

        # Shift group (0xC0/0xC1 = shift r/m, imm8) (80186+)
        elif opcode in (0xC0, 0xC1):
            wide = opcode == 0xC1
            reg, rm, shift_op = self._decode_modrm(wide, seg_override)
            SHIFT_NAMES = ['rol','ror','rcl','rcr','shl','shr','sal','sar']
            inst.mnemonic = SHIFT_NAMES[shift_op]
            inst.op1 = rm
            inst.op2 = Operand(type=OpType.IMM8, disp=self._u8(), size=1)

        # RET near imm16
        elif opcode == 0xC2:
            inst.mnemonic = 'ret'
            inst.op1 = Operand(type=OpType.IMM16, disp=self._u16(), size=2)

        # RET near
        elif opcode == 0xC3:
            inst.mnemonic = 'ret'

        # LES reg16, m
        elif opcode == 0xC4:
            reg, rm, _ = self._decode_modrm(True, seg_override)
            inst.mnemonic = 'les'; inst.op1 = reg; inst.op2 = rm

        # LDS reg16, m
        elif opcode == 0xC5:
            reg, rm, _ = self._decode_modrm(True, seg_override)
            inst.mnemonic = 'lds'; inst.op1 = reg; inst.op2 = rm

        # MOV r/m8, imm8
        elif opcode == 0xC6:
            _, rm, _ = self._decode_modrm(False, seg_override)
            inst.mnemonic = 'mov'
            inst.op1 = rm
            inst.op2 = Operand(type=OpType.IMM8, disp=self._u8(), size=1)

        # MOV r/m16/32, imm16/32
        elif opcode == 0xC7:
            _, rm, _ = self._decode_modrm(True, seg_override)
            inst.mnemonic = 'mov'
            inst.op1 = rm
            inst.op2 = self._wimm()

        # ENTER (80186+)
        elif opcode == 0xC8:
            size = self._u16()
            level = self._u8()
            inst.mnemonic = 'enter'
            inst.op1 = Operand(type=OpType.IMM16, disp=size, size=2)
            inst.op2 = Operand(type=OpType.IMM8, disp=level, size=1)

        # LEAVE (80186+)
        elif opcode == 0xC9:
            inst.mnemonic = 'leave'

        # RETF imm16
        elif opcode == 0xCA:
            inst.mnemonic = 'retf'
            inst.op1 = Operand(type=OpType.IMM16, disp=self._u16(), size=2)

        # RETF
        elif opcode == 0xCB:
            inst.mnemonic = 'retf'

        # INT 3
        elif opcode == 0xCC:
            inst.mnemonic = 'int'
            inst.op1 = Operand(type=OpType.IMM8, disp=3, size=1)

        # INT imm8
        elif opcode == 0xCD:
            int_num = self._u8()
            inst.mnemonic = 'int'
            inst.op1 = Operand(type=OpType.IMM8, disp=int_num, size=1)

            # Special: MSC overlay call (INT 3Fh)
            if int_num == 0x3F and self.pos + 2 < len(self.data):
                inst.overlay_num = self._u8()
                inst.overlay_off = self._u16()

        # INTO
        elif opcode == 0xCE: inst.mnemonic = 'into'

        # IRET
        elif opcode == 0xCF: inst.mnemonic = 'iret'

        # Shift group (0xD0-0xD3)
        elif opcode in (0xD0, 0xD1, 0xD2, 0xD3):
            wide = opcode in (0xD1, 0xD3)
            by_cl = opcode in (0xD2, 0xD3)
            reg, rm, shift_op = self._decode_modrm(wide, seg_override)
            SHIFT_NAMES = ['rol','ror','rcl','rcr','shl','shr','sal','sar']
            inst.mnemonic = SHIFT_NAMES[shift_op]
            inst.op1 = rm
            if by_cl:
                inst.op2 = Operand(type=OpType.REG8, reg=1, size=1)  # CL
            else:
                inst.op2 = Operand(type=OpType.IMM8, disp=1, size=1)

        # AAM, AAD
        elif opcode == 0xD4:
            inst.mnemonic = 'aam'
            self._u8()  # base (usually 0x0A)
        elif opcode == 0xD5:
            inst.mnemonic = 'aad'
            self._u8()  # base

        # XLAT
        elif opcode == 0xD7: inst.mnemonic = 'xlat'

        # ESC (FPU) - 0xD8-0xDF - read ModR/M and skip
        elif 0xD8 <= opcode <= 0xDF:
            self._decode_modrm(False, seg_override)
            inst.mnemonic = f'esc_{opcode - 0xD8}'

        # LOOPNZ, LOOPZ, LOOP, JCXZ
        elif opcode == 0xE0:
            inst.mnemonic = 'loopnz'
            rel = self._s8()
            inst.op1 = Operand(type=OpType.REL8, disp=(self.pos + rel) & 0xFFFF, size=2)
        elif opcode == 0xE1:
            inst.mnemonic = 'loopz'
            rel = self._s8()
            inst.op1 = Operand(type=OpType.REL8, disp=(self.pos + rel) & 0xFFFF, size=2)
        elif opcode == 0xE2:
            inst.mnemonic = 'loop'
            rel = self._s8()
            inst.op1 = Operand(type=OpType.REL8, disp=(self.pos + rel) & 0xFFFF, size=2)
        elif opcode == 0xE3:
            inst.mnemonic = 'jcxz'
            rel = self._s8()
            inst.op1 = Operand(type=OpType.REL8, disp=(self.pos + rel) & 0xFFFF, size=2)

        # IN AL/AX, imm8
        elif opcode == 0xE4:
            inst.mnemonic = 'in'
            inst.op1 = Operand(type=OpType.REG8, reg=0, size=1)
            inst.op2 = Operand(type=OpType.IMM8, disp=self._u8(), size=1)
        elif opcode == 0xE5:
            inst.mnemonic = 'in'
            inst.op1 = Operand(type=OpType.REG16, reg=0, size=2)
            inst.op2 = Operand(type=OpType.IMM8, disp=self._u8(), size=1)

        # OUT imm8, AL/AX
        elif opcode == 0xE6:
            inst.mnemonic = 'out'
            inst.op1 = Operand(type=OpType.IMM8, disp=self._u8(), size=1)
            inst.op2 = Operand(type=OpType.REG8, reg=0, size=1)
        elif opcode == 0xE7:
            inst.mnemonic = 'out'
            inst.op1 = Operand(type=OpType.IMM8, disp=self._u8(), size=1)
            inst.op2 = Operand(type=OpType.REG16, reg=0, size=2)

        # CALL rel16
        elif opcode == 0xE8:
            rel = self._s16()
            target = (self.pos + rel) & 0xFFFF
            inst.mnemonic = 'call'
            inst.op1 = Operand(type=OpType.REL16, disp=target, size=2)

        # JMP rel16
        elif opcode == 0xE9:
            rel = self._s16()
            target = (self.pos + rel) & 0xFFFF
            inst.mnemonic = 'jmp'
            inst.op1 = Operand(type=OpType.REL16, disp=target, size=2)

        # JMP far
        elif opcode == 0xEA:
            off = self._u16()
            seg = self._u16()
            inst.mnemonic = 'jmp'
            inst.op1 = Operand(type=OpType.FAR, disp=off, far_seg=seg, size=4)

        # JMP rel8
        elif opcode == 0xEB:
            rel = self._s8()
            target = (self.pos + rel) & 0xFFFF
            inst.mnemonic = 'jmp'
            inst.op1 = Operand(type=OpType.REL8, disp=target, size=2)

        # IN AL/AX, DX
        elif opcode == 0xEC:
            inst.mnemonic = 'in'
            inst.op1 = Operand(type=OpType.REG8, reg=0, size=1)
            inst.op2 = Operand(type=OpType.REG16, reg=2, size=2)
        elif opcode == 0xED:
            inst.mnemonic = 'in'
            inst.op1 = Operand(type=OpType.REG16, reg=0, size=2)
            inst.op2 = Operand(type=OpType.REG16, reg=2, size=2)

        # OUT DX, AL/AX
        elif opcode == 0xEE:
            inst.mnemonic = 'out'
            inst.op1 = Operand(type=OpType.REG16, reg=2, size=2)
            inst.op2 = Operand(type=OpType.REG8, reg=0, size=1)
        elif opcode == 0xEF:
            inst.mnemonic = 'out'
            inst.op1 = Operand(type=OpType.REG16, reg=2, size=2)
            inst.op2 = Operand(type=OpType.REG16, reg=0, size=2)

        # HLT
        elif opcode == 0xF4: inst.mnemonic = 'hlt'

        # CMC
        elif opcode == 0xF5: inst.mnemonic = 'cmc'

        # Group 3: TEST/NOT/NEG/MUL/IMUL/DIV/IDIV
        elif opcode in (0xF6, 0xF7):
            wide = opcode == 0xF7
            reg, rm, grp_op = self._decode_modrm(wide, seg_override)
            GRP3 = ['test', 'test', 'not', 'neg', 'mul', 'imul', 'div', 'idiv']
            inst.mnemonic = GRP3[grp_op]
            inst.op1 = rm
            if grp_op <= 1:  # TEST r/m, imm
                if wide:
                    inst.op2 = self._wimm()
                else:
                    inst.op2 = Operand(type=OpType.IMM8, disp=self._u8(), size=1)

        # CLC, STC, CLI, STI, CLD, STD
        elif opcode == 0xF8: inst.mnemonic = 'clc'
        elif opcode == 0xF9: inst.mnemonic = 'stc'
        elif opcode == 0xFA: inst.mnemonic = 'cli'
        elif opcode == 0xFB: inst.mnemonic = 'sti'
        elif opcode == 0xFC: inst.mnemonic = 'cld'
        elif opcode == 0xFD: inst.mnemonic = 'std'

        # Group 4/5: INC/DEC/CALL/JMP/PUSH
        elif opcode in (0xFE, 0xFF):
            wide = opcode == 0xFF
            reg, rm, grp_op = self._decode_modrm(wide, seg_override)
            if opcode == 0xFE:
                if grp_op == 0: inst.mnemonic = 'inc'
                elif grp_op == 1: inst.mnemonic = 'dec'
                else: inst.mnemonic = f'grp4_{grp_op}'
                inst.op1 = rm
            else:
                GRP5 = ['inc', 'dec', 'call', 'call', 'jmp', 'jmp', 'push', '?']
                inst.mnemonic = GRP5[grp_op]
                inst.op1 = rm
                if grp_op in (3, 5):  # FAR variants
                    inst.mnemonic += ' far'

        # WAIT
        elif opcode == 0x9B: inst.mnemonic = 'wait'

        # ── Two-byte opcodes (0x0F): 386+ ──
        elif opcode == 0x0F:
            op2b = self._u8()
            CC = ['o','no','b','ae','e','ne','be','a','s','ns','p','np','l','ge','le','g']
            if 0x80 <= op2b <= 0x8F:          # Jcc near rel16
                inst.mnemonic = 'j' + CC[op2b - 0x80]
                rel = self._s16()
                inst.op1 = Operand(type=OpType.REL16, disp=(self.pos + rel) & 0xFFFF, size=2)
            elif 0x90 <= op2b <= 0x9F:        # SETcc r/m8
                _, rm, _ = self._decode_modrm(False, seg_override)
                inst.mnemonic = 'set' + CC[op2b - 0x90]
                inst.op1 = rm
            elif op2b == 0xAF:                # IMUL r, r/m
                reg, rm, _ = self._decode_modrm(True, seg_override)
                inst.mnemonic = 'imul'; inst.op1 = reg; inst.op2 = rm
            elif op2b in (0xB6, 0xB7, 0xBE, 0xBF):   # MOVZX/MOVSX
                reg, rm, _ = self._decode_modrm(True, seg_override)
                src_word = op2b in (0xB7, 0xBF)
                if rm.type in (OpType.REG16, OpType.REG32):
                    rm.type = OpType.REG16 if src_word else OpType.REG8
                rm.size = 2 if src_word else 1
                inst.mnemonic = 'movsx' if op2b in (0xBE, 0xBF) else 'movzx'
                inst.op1 = reg; inst.op2 = rm
            elif op2b in (0xA3, 0xAB, 0xB3, 0xBB):   # BT/BTS/BTR/BTC r/m, r
                reg, rm, _ = self._decode_modrm(True, seg_override)
                inst.mnemonic = {0xA3:'bt',0xAB:'bts',0xB3:'btr',0xBB:'btc'}[op2b]
                inst.op1 = rm; inst.op2 = reg
            elif op2b == 0xBA:                # BT-group r/m, imm8
                _, rm, sub = self._decode_modrm(True, seg_override)
                inst.mnemonic = ['?','?','?','?','bt','bts','btr','btc'][sub]
                inst.op1 = rm
                inst.op2 = Operand(type=OpType.IMM8, disp=self._u8(), size=1)
            elif op2b in (0xA4, 0xA5, 0xAC, 0xAD):   # SHLD/SHRD
                reg, rm, _ = self._decode_modrm(True, seg_override)
                inst.mnemonic = 'shld' if op2b in (0xA4, 0xA5) else 'shrd'
                inst.op1 = rm; inst.op2 = reg
                if op2b in (0xA4, 0xAC):
                    inst.op3 = Operand(type=OpType.IMM8, disp=self._u8(), size=1)
                else:                         # 0xA5/0xAD: count in CL
                    inst.op3 = Operand(type=OpType.REG8, reg=1, size=1)  # CL
            elif op2b in (0x02, 0x03):        # LAR / LSL r16, r/m16 (selector validity)
                reg, rm, _ = self._decode_modrm(True, seg_override)
                inst.mnemonic = 'lar' if op2b == 0x02 else 'lsl'
                inst.op1 = reg; inst.op2 = rm
            elif op2b in (0xB2, 0xB4, 0xB5):  # LSS / LFS / LGS r16, m16:16 (load far ptr)
                reg, rm, _ = self._decode_modrm(True, seg_override)
                inst.mnemonic = {0xB2: 'lss', 0xB4: 'lfs', 0xB5: 'lgs'}[op2b]
                inst.op1 = reg; inst.op2 = rm
            elif op2b in (0xA0, 0xA1, 0xA8, 0xA9):   # PUSH/POP FS/GS
                inst.mnemonic = 'push' if op2b in (0xA0, 0xA8) else 'pop'
                inst.op1 = Operand(type=OpType.SREG, reg=(4 if op2b in (0xA0, 0xA1) else 5), size=2)
            elif op2b == 0x1F:                # multi-byte NOP
                self._decode_modrm(True, seg_override)
                inst.mnemonic = 'nop'
            else:                             # unknown 0F xx: re-sync at op2b
                inst.mnemonic = 'db'
                inst.op1 = Operand(type=OpType.IMM8, disp=0x0F, size=1)
                self.pos -= 1

        else:
            inst.mnemonic = 'db'
            inst.op1 = Operand(type=OpType.IMM8, disp=opcode, size=1)

        inst.length = self.pos - start
        inst.raw = self.data[start:self.pos]
        return inst

    def decode_range(self, start: int, end: int):
        """Decode all instructions in [start, end)."""
        self.pos = start
        instructions = []
        while self.pos < end:
            saved_pos = self.pos
            try:
                inst = self.decode_one()
            except (IndexError, KeyError):
                # Decoding failed (truncated instruction, etc.)
                self.pos = saved_pos
                inst = Instruction()
                inst.offset = self.base + self.pos
                inst.address = self.pos
                inst.mnemonic = 'db'
                b = self.data[self.pos] if self.pos < len(self.data) else 0
                inst.op1 = Operand(type=OpType.IMM8, disp=b, size=1)
                inst.raw = self.data[self.pos:self.pos+1]
                inst.length = 1
                self.pos += 1
            if inst is None:
                break
            instructions.append(inst)
        return instructions

    def decode_all(self):
        """Decode the entire data buffer."""
        return self.decode_range(0, len(self.data))


# ─── CLI for testing ─────────────────────────────────────────────

def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: decode16.py <binary> [start_offset] [length]")
        print("       decode16.py <civ.exe> --resident   (decode resident code)")
        print("       decode16.py <civ.exe> --overlay N  (decode overlay N)")
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    start = 0
    length = len(data)

    if '--resident' in sys.argv:
        # Skip MZ header (32 paragraphs = 512 bytes)
        import struct
        hdr_paras = struct.unpack_from('<H', data, 8)[0]
        start = hdr_paras * 16
        # Calculate image size
        pages = struct.unpack_from('<H', data, 4)[0]
        last_page = struct.unpack_from('<H', data, 2)[0]
        img_size = (pages - 1) * 512 + last_page if last_page else pages * 512
        length = img_size - start
        print(f"; Resident code: offset 0x{start:X}, {length} bytes")
    elif '--overlay' in sys.argv:
        idx = sys.argv.index('--overlay')
        ovl_num = int(sys.argv[idx + 1])
        import struct
        pages = struct.unpack_from('<H', data, 4)[0]
        last_page = struct.unpack_from('<H', data, 2)[0]
        img_size = (pages - 1) * 512 + last_page if last_page else pages * 512
        scan = (img_size + 0x1FF) & ~0x1FF
        found = 0
        while scan + 28 < len(data):
            if data[scan] == 0x4D and data[scan+1] == 0x5A:
                op = struct.unpack_from('<H', data, scan + 4)[0]
                olp = struct.unpack_from('<H', data, scan + 2)[0]
                ohp = struct.unpack_from('<H', data, scan + 8)[0]
                if op > 0 and op < 500 and ohp > 0 and ohp < 100:
                    found += 1
                    if found == ovl_num:
                        hdr_sz = ohp * 16
                        o_img = (op - 1) * 512 + olp if olp else op * 512
                        start = scan + hdr_sz
                        length = o_img - hdr_sz
                        print(f"; Overlay {ovl_num}: file offset 0x{scan:X}, "
                              f"code at 0x{start:X}, {length} bytes")
                        break
            scan += 0x200
        else:
            print(f"Error: overlay {ovl_num} not found")
            sys.exit(1)
    else:
        if len(sys.argv) >= 3:
            start = int(sys.argv[2], 0)
        if len(sys.argv) >= 4:
            length = int(sys.argv[3], 0)

    decoder = Decoder(data[start:start+length], base_offset=start)
    instructions = decoder.decode_all()

    for inst in instructions:
        hex_str = ' '.join(f'{b:02X}' for b in inst.raw[:8])
        ovl_str = ''
        if inst.overlay_num >= 0:
            ovl_str = f'  ; OVL {inst.overlay_num:02X}:{inst.overlay_off:04X}'
        print(f'{inst.offset:06X}  {hex_str:<24s} {inst!r}{ovl_str}')

    print(f"\n; {len(instructions)} instructions decoded")


if __name__ == '__main__':
    main()

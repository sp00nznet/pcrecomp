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
    SREG = auto()      # Segment register (ES, CS, SS, DS)
    MEM = auto()        # Memory operand [seg:base+index+disp]
    IMM8 = auto()      # 8-bit immediate
    IMM16 = auto()     # 16-bit immediate
    REL8 = auto()      # 8-bit relative offset (for short jumps)
    REL16 = auto()     # 16-bit relative offset (for near jumps/calls)
    FAR = auto()        # Far pointer seg:off (for far jumps/calls)
    MOFFS = auto()     # Direct memory offset (MOV AL,[addr] etc.)

REG8_NAMES  = ['al', 'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh']
REG16_NAMES = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di']
SREG_NAMES  = ['es', 'cs', 'ss', 'ds']

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
        elif self.type == OpType.SREG:
            return SREG_NAMES[self.reg]
        elif self.type == OpType.IMM8 or self.type == OpType.IMM16:
            return f'0x{self.disp & 0xFFFF:X}'
        elif self.type == OpType.REL8 or self.type == OpType.REL16:
            return f'0x{self.disp & 0xFFFF:04X}'
        elif self.type == OpType.FAR:
            return f'{self.far_seg:04X}:{self.disp:04X}'
        elif self.type == OpType.MEM:
            prefix = f'{self.seg}:' if self.seg else ''
            sz = 'byte ' if self.size == 1 else 'word ' if self.size == 2 else ''
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
            sz = 'byte ' if self.size == 1 else 'word ' if self.size == 2 else ''
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

class Decoder:
    """16-bit x86 instruction decoder."""

    def __init__(self, data: bytes, base_offset: int = 0):
        self.data = data
        self.base = base_offset
        self.pos = 0

    def _u8(self) -> int:
        b = self.data[self.pos]
        self.pos += 1
        return b

    def _s8(self) -> int:
        b = self.data[self.pos]
        self.pos += 1
        return b if b < 128 else b - 256

    def _u16(self) -> int:
        lo = self.data[self.pos]
        hi = self.data[self.pos + 1]
        self.pos += 2
        return lo | (hi << 8)

    def _s16(self) -> int:
        v = self._u16()
        return v if v < 32768 else v - 65536

    def _decode_modrm(self, wide: bool, seg_override: str = '') -> tuple:
        """Decode ModR/M byte. Returns (reg_operand, rm_operand)."""
        modrm = self._u8()
        mod = (modrm >> 6) & 3
        reg = (modrm >> 3) & 7
        rm  = modrm & 7

        if wide:
            reg_op = Operand(type=OpType.REG16, reg=reg, size=2)
        else:
            reg_op = Operand(type=OpType.REG8, reg=reg, size=1)

        if mod == 3:
            # Register direct
            if wide:
                rm_op = Operand(type=OpType.REG16, reg=rm, size=2)
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
                size=2 if wide else 1,
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
            elif alu_sub == 5:  # AX, imm16
                inst.op1 = Operand(type=OpType.REG16, reg=0, size=2)
                inst.op2 = Operand(type=OpType.IMM16, disp=self._u16(), size=2)

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

        # INC reg16 (0x40-0x47)
        elif 0x40 <= opcode <= 0x47:
            inst.mnemonic = 'inc'
            inst.op1 = Operand(type=OpType.REG16, reg=opcode - 0x40, size=2)

        # DEC reg16 (0x48-0x4F)
        elif 0x48 <= opcode <= 0x4F:
            inst.mnemonic = 'dec'
            inst.op1 = Operand(type=OpType.REG16, reg=opcode - 0x48, size=2)

        # PUSH reg16 (0x50-0x57)
        elif 0x50 <= opcode <= 0x57:
            inst.mnemonic = 'push'
            inst.op1 = Operand(type=OpType.REG16, reg=opcode - 0x50, size=2)

        # POP reg16 (0x58-0x5F)
        elif 0x58 <= opcode <= 0x5F:
            inst.mnemonic = 'pop'
            inst.op1 = Operand(type=OpType.REG16, reg=opcode - 0x58, size=2)

        # PUSHA/POPA (80186+)
        elif opcode == 0x60: inst.mnemonic = 'pusha'
        elif opcode == 0x61: inst.mnemonic = 'popa'

        # PUSH imm16 (80186+)
        elif opcode == 0x68:
            inst.mnemonic = 'push'
            inst.op1 = Operand(type=OpType.IMM16, disp=self._u16(), size=2)

        # IMUL r16, r/m16, imm16 (80186+)
        elif opcode == 0x69:
            reg, rm, rn = self._decode_modrm(True, seg_override)
            inst.mnemonic = 'imul'
            inst.op1 = reg
            inst.op2 = Operand(type=OpType.IMM16, disp=self._u16(), size=2)

        # PUSH imm8 (sign-extended to 16) (80186+)
        elif opcode == 0x6A:
            inst.mnemonic = 'push'
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
            if sign_ext and wide:
                inst.op2 = Operand(type=OpType.IMM8, disp=self._s8() & 0xFFFF, size=2)
            elif wide:
                inst.op2 = Operand(type=OpType.IMM16, disp=self._u16(), size=2)
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

        # XCHG AX, reg16
        elif 0x91 <= opcode <= 0x97:
            inst.mnemonic = 'xchg'
            inst.op1 = Operand(type=OpType.REG16, reg=0, size=2)
            inst.op2 = Operand(type=OpType.REG16, reg=opcode - 0x90, size=2)

        # CBW, CWD
        elif opcode == 0x98: inst.mnemonic = 'cbw'
        elif opcode == 0x99: inst.mnemonic = 'cwd'

        # CALL far ptr
        elif opcode == 0x9A:
            off = self._u16()
            seg = self._u16()
            inst.mnemonic = 'call'
            inst.op1 = Operand(type=OpType.FAR, disp=off, far_seg=seg, size=4)

        # PUSHF, POPF
        elif opcode == 0x9C: inst.mnemonic = 'pushf'
        elif opcode == 0x9D: inst.mnemonic = 'popf'

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
            inst.op1 = Operand(type=OpType.REG16, reg=0, size=2)
            inst.op2 = Operand(type=OpType.MOFFS, disp=self._u16(), seg=seg_override or 'ds', size=2)

        # MOV moffs, AL/AX
        elif opcode == 0xA2:
            inst.mnemonic = 'mov'
            inst.op1 = Operand(type=OpType.MOFFS, disp=self._u16(), seg=seg_override or 'ds', size=1)
            inst.op2 = Operand(type=OpType.REG8, reg=0, size=1)
        elif opcode == 0xA3:
            inst.mnemonic = 'mov'
            inst.op1 = Operand(type=OpType.MOFFS, disp=self._u16(), seg=seg_override or 'ds', size=2)
            inst.op2 = Operand(type=OpType.REG16, reg=0, size=2)

        # String ops
        elif opcode == 0xA4: inst.mnemonic = 'movsb'
        elif opcode == 0xA5: inst.mnemonic = 'movsw'
        elif opcode == 0xA6: inst.mnemonic = 'cmpsb'
        elif opcode == 0xA7: inst.mnemonic = 'cmpsw'

        # TEST AL/AX, imm
        elif opcode == 0xA8:
            inst.mnemonic = 'test'
            inst.op1 = Operand(type=OpType.REG8, reg=0, size=1)
            inst.op2 = Operand(type=OpType.IMM8, disp=self._u8(), size=1)
        elif opcode == 0xA9:
            inst.mnemonic = 'test'
            inst.op1 = Operand(type=OpType.REG16, reg=0, size=2)
            inst.op2 = Operand(type=OpType.IMM16, disp=self._u16(), size=2)

        # STOSB, STOSW, LODSB, LODSW, SCASB, SCASW
        elif opcode == 0xAA: inst.mnemonic = 'stosb'
        elif opcode == 0xAB: inst.mnemonic = 'stosw'
        elif opcode == 0xAC: inst.mnemonic = 'lodsb'
        elif opcode == 0xAD: inst.mnemonic = 'lodsw'
        elif opcode == 0xAE: inst.mnemonic = 'scasb'
        elif opcode == 0xAF: inst.mnemonic = 'scasw'

        # MOV reg8, imm8 (0xB0-0xB7)
        elif 0xB0 <= opcode <= 0xB7:
            inst.mnemonic = 'mov'
            inst.op1 = Operand(type=OpType.REG8, reg=opcode - 0xB0, size=1)
            inst.op2 = Operand(type=OpType.IMM8, disp=self._u8(), size=1)

        # MOV reg16, imm16 (0xB8-0xBF)
        elif 0xB8 <= opcode <= 0xBF:
            inst.mnemonic = 'mov'
            inst.op1 = Operand(type=OpType.REG16, reg=opcode - 0xB8, size=2)
            inst.op2 = Operand(type=OpType.IMM16, disp=self._u16(), size=2)

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

        # MOV r/m16, imm16
        elif opcode == 0xC7:
            _, rm, _ = self._decode_modrm(True, seg_override)
            inst.mnemonic = 'mov'
            inst.op1 = rm
            inst.op2 = Operand(type=OpType.IMM16, disp=self._u16(), size=2)

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
                    inst.op2 = Operand(type=OpType.IMM16, disp=self._u16(), size=2)
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

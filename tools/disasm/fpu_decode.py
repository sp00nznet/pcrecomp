"""
fpu_decode.py - x87 FPU Instruction Decoder

Decodes x87 floating-point instructions (opcodes 0xD8-0xDF) into proper
mnemonics. Format-agnostic: feed it the ESC opcode plus a decoded ModR/M and
it returns a structured FPUInstruction. Pairs with the 16-bit decoder
(decode16.py) and 32-bit disassembler (disasm32.py) to give either lifter
real x87 mnemonics instead of opaque `esc_*` placeholders.

The x87 encoding uses the ESC opcode (0xD8-0xDF) followed by a ModR/M byte.
If mod=11 (register-register), the instruction operates on FPU stack registers.
Otherwise, it's a memory operand instruction.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class FPUInstruction:
    """A decoded FPU instruction."""
    mnemonic: str           # e.g., 'fld', 'fadd', 'fstp'
    operand: str = ''       # e.g., 'st(0), st(1)', 'dword [bp+4]', 'qword [si]'
    mem_size: str = ''      # 'dword', 'qword', 'tword', 'word', '', etc.
    is_memory: bool = False # True if memory operand
    st_src: int = -1        # Source ST register (-1 if none)
    st_dst: int = -1        # Dest ST register (-1 if none)


# Memory operand mnemonics indexed by [opcode-0xD8][reg_field]
# Format: (mnemonic, mem_size)
MEM_TABLE = {
    0xD8: [  # float32 arithmetic
        ('fadd',  'dword'), ('fmul',  'dword'), ('fcom',  'dword'), ('fcomp', 'dword'),
        ('fsub',  'dword'), ('fsubr', 'dword'), ('fdiv',  'dword'), ('fdivr', 'dword'),
    ],
    0xD9: [  # float32 load/store + transcendentals
        ('fld',   'dword'), ('???',   ''),      ('fst',   'dword'), ('fstp',  'dword'),
        ('fldenv','14byte'),('fldcw', 'word'),   ('fstenv','14byte'),('fstcw', 'word'),
    ],
    0xDA: [  # int32 arithmetic
        ('fiadd', 'dword'), ('fimul', 'dword'), ('ficom', 'dword'), ('ficomp','dword'),
        ('fisub', 'dword'), ('fisubr','dword'), ('fidiv', 'dword'), ('fidivr','dword'),
    ],
    0xDB: [  # int32 load/store + float80 load/store
        ('fild',  'dword'), ('fisttp','dword'), ('fist',  'dword'), ('fistp', 'dword'),
        ('???',   ''),      ('fld',   'tword'), ('???',   ''),      ('fstp',  'tword'),
    ],
    0xDC: [  # float64 arithmetic
        ('fadd',  'qword'), ('fmul',  'qword'), ('fcom',  'qword'), ('fcomp', 'qword'),
        ('fsub',  'qword'), ('fsubr', 'qword'), ('fdiv',  'qword'), ('fdivr', 'qword'),
    ],
    0xDD: [  # float64 load/store
        ('fld',   'qword'), ('fisttp','qword'), ('fst',   'qword'), ('fstp',  'qword'),
        ('frstor','94byte'),('???',   ''),      ('fsave', '94byte'),('fstsw', 'word'),
    ],
    0xDE: [  # int16 arithmetic (with pop)
        ('fiadd', 'word'),  ('fimul', 'word'),  ('ficom', 'word'),  ('ficomp','word'),
        ('fisub', 'word'),  ('fisubr','word'),   ('fidiv', 'word'),  ('fidivr','word'),
    ],
    0xDF: [  # int16 load/store + misc
        ('fild',  'word'),  ('fisttp','word'),  ('fist',  'word'),  ('fistp', 'word'),
        ('fbld',  'tword'), ('fild',  'qword'), ('fbstp', 'tword'),('fistp', 'qword'),
    ],
}

# Register-register instructions for mod=11
# Indexed by [opcode-0xD8][full byte - 0xC0]
# Most use pattern: mnemonic st(0), st(i) or mnemonic st(i), st(0)

def decode_reg_d8(byte2):
    """D8 C0-FF: fadd/fmul/fcom/fcomp/fsub/fsubr/fdiv/fdivr st(0), st(i)"""
    i = byte2 & 7
    ops = ['fadd', 'fmul', 'fcom', 'fcomp', 'fsub', 'fsubr', 'fdiv', 'fdivr']
    op = ops[(byte2 - 0xC0) >> 3]
    return FPUInstruction(op, f'st(0), st({i})', st_src=i, st_dst=0)

def decode_reg_d9(byte2):
    """D9 C0-FF: fld st(i), fxch st(i), fnop, and transcendentals"""
    if 0xC0 <= byte2 <= 0xC7:
        return FPUInstruction('fld', f'st({byte2 & 7})', st_src=byte2 & 7)
    elif 0xC8 <= byte2 <= 0xCF:
        return FPUInstruction('fxch', f'st({byte2 & 7})', st_src=byte2 & 7, st_dst=0)
    elif byte2 == 0xD0:
        return FPUInstruction('fnop')
    elif byte2 == 0xE0:
        return FPUInstruction('fchs')
    elif byte2 == 0xE1:
        return FPUInstruction('fabs')
    elif byte2 == 0xE4:
        return FPUInstruction('ftst')
    elif byte2 == 0xE5:
        return FPUInstruction('fxam')
    elif byte2 == 0xE8:
        return FPUInstruction('fld1')
    elif byte2 == 0xE9:
        return FPUInstruction('fldl2t')
    elif byte2 == 0xEA:
        return FPUInstruction('fldl2e')
    elif byte2 == 0xEB:
        return FPUInstruction('fldpi')
    elif byte2 == 0xEC:
        return FPUInstruction('fldlg2')
    elif byte2 == 0xED:
        return FPUInstruction('fldln2')
    elif byte2 == 0xEE:
        return FPUInstruction('fldz')
    elif byte2 == 0xF0:
        return FPUInstruction('f2xm1')
    elif byte2 == 0xF1:
        return FPUInstruction('fyl2x')
    elif byte2 == 0xF2:
        return FPUInstruction('fptan')
    elif byte2 == 0xF3:
        return FPUInstruction('fpatan')
    elif byte2 == 0xF4:
        return FPUInstruction('fxtract')
    elif byte2 == 0xF5:
        return FPUInstruction('fprem1')
    elif byte2 == 0xF6:
        return FPUInstruction('fdecstp')
    elif byte2 == 0xF7:
        return FPUInstruction('fincstp')
    elif byte2 == 0xF8:
        return FPUInstruction('fprem')
    elif byte2 == 0xF9:
        return FPUInstruction('fyl2xp1')
    elif byte2 == 0xFA:
        return FPUInstruction('fsqrt')
    elif byte2 == 0xFB:
        return FPUInstruction('fsincos')
    elif byte2 == 0xFC:
        return FPUInstruction('frndint')
    elif byte2 == 0xFD:
        return FPUInstruction('fscale')
    elif byte2 == 0xFE:
        return FPUInstruction('fsin')
    elif byte2 == 0xFF:
        return FPUInstruction('fcos')
    return FPUInstruction(f'fpu_d9_{byte2:02X}')

def decode_reg_da(byte2):
    """DA C0-FF: fcmovCC and fucompp"""
    if byte2 == 0xE9:
        return FPUInstruction('fucompp')
    i = byte2 & 7
    ops = ['fcmovb', 'fcmove', 'fcmovbe', 'fcmovu', '???', '???', '???', '???']
    op = ops[(byte2 - 0xC0) >> 3]
    return FPUInstruction(op, f'st(0), st({i})', st_src=i, st_dst=0)

def decode_reg_db(byte2):
    """DB C0-FF: fcmovCC, fclex, finit"""
    if byte2 == 0xE2:
        return FPUInstruction('fclex')
    elif byte2 == 0xE3:
        return FPUInstruction('finit')
    i = byte2 & 7
    ops = ['fcmovnb', 'fcmovne', 'fcmovnbe', 'fcmovnu', '???', 'fucomi', 'fcomi', '???']
    op = ops[(byte2 - 0xC0) >> 3]
    return FPUInstruction(op, f'st(0), st({i})', st_src=i, st_dst=0)

def decode_reg_dc(byte2):
    """DC C0-FF: fadd/fmul/fcom/fcomp/fsub/fsubr/fdiv/fdivr st(i), st(0)"""
    i = byte2 & 7
    # Note: fsub/fsubr and fdiv/fdivr are swapped for DC vs D8
    ops = ['fadd', 'fmul', 'fcom', 'fcomp', 'fsubr', 'fsub', 'fdivr', 'fdiv']
    op = ops[(byte2 - 0xC0) >> 3]
    return FPUInstruction(op, f'st({i}), st(0)', st_src=0, st_dst=i)

def decode_reg_dd(byte2):
    """DD C0-FF: ffree, fst, fstp, fucom, fucomp"""
    i = byte2 & 7
    if 0xC0 <= byte2 <= 0xC7:
        return FPUInstruction('ffree', f'st({i})', st_src=i)
    elif 0xD0 <= byte2 <= 0xD7:
        return FPUInstruction('fst', f'st({i})', st_dst=i)
    elif 0xD8 <= byte2 <= 0xDF:
        return FPUInstruction('fstp', f'st({i})', st_dst=i)
    elif 0xE0 <= byte2 <= 0xE7:
        return FPUInstruction('fucom', f'st({i})', st_src=i)
    elif 0xE8 <= byte2 <= 0xEF:
        return FPUInstruction('fucomp', f'st({i})', st_src=i)
    return FPUInstruction(f'fpu_dd_{byte2:02X}')

def decode_reg_de(byte2):
    """DE C0-FF: faddp/fmulp/fcompp/fsubrp/fsubp/fdivrp/fdivp"""
    i = byte2 & 7
    if byte2 == 0xD9:
        return FPUInstruction('fcompp')
    ops = ['faddp', 'fmulp', 'fcomp', '???', 'fsubrp', 'fsubp', 'fdivrp', 'fdivp']
    op = ops[(byte2 - 0xC0) >> 3]
    return FPUInstruction(op, f'st({i}), st(0)', st_src=0, st_dst=i)

def decode_reg_df(byte2):
    """DF C0-FF: ffreep, fstsw ax, fucomip, fcomip"""
    i = byte2 & 7
    if byte2 == 0xE0:
        return FPUInstruction('fstsw', 'ax')
    if 0xC0 <= byte2 <= 0xC7:
        return FPUInstruction('ffreep', f'st({i})', st_src=i)
    elif 0xE8 <= byte2 <= 0xEF:
        return FPUInstruction('fucomip', f'st(0), st({i})', st_src=i, st_dst=0)
    elif 0xF0 <= byte2 <= 0xF7:
        return FPUInstruction('fcomip', f'st(0), st({i})', st_src=i, st_dst=0)
    return FPUInstruction(f'fpu_df_{byte2:02X}')


REG_DECODERS = {
    0xD8: decode_reg_d8,
    0xD9: decode_reg_d9,
    0xDA: decode_reg_da,
    0xDB: decode_reg_db,
    0xDC: decode_reg_dc,
    0xDD: decode_reg_dd,
    0xDE: decode_reg_de,
    0xDF: decode_reg_df,
}


def decode_fpu(opcode: int, modrm: int, mod: int, reg: int, rm: int,
               mem_operand: str = '') -> FPUInstruction:
    """Decode an x87 FPU instruction.

    Args:
        opcode: The ESC opcode (0xD8-0xDF)
        modrm: The full ModR/M byte
        mod: ModR/M mod field (0-3)
        reg: ModR/M reg field (0-7) - selects the operation for memory ops
        rm: ModR/M rm field (0-7)
        mem_operand: String representation of memory operand (if mod != 3)

    Returns:
        FPUInstruction with decoded mnemonic and operands
    """
    if mod == 3:
        # Register-register operation
        decoder = REG_DECODERS.get(opcode)
        if decoder:
            return decoder(modrm)
        return FPUInstruction(f'fpu_{opcode:02X}_{modrm:02X}')
    else:
        # Memory operand
        table = MEM_TABLE.get(opcode, [])
        if reg < len(table):
            mnemonic, mem_size = table[reg]
            operand = f'{mem_size} {mem_operand}' if mem_operand else mem_size
            return FPUInstruction(mnemonic, operand, mem_size=mem_size, is_memory=True)
        return FPUInstruction(f'fpu_{opcode:02X}_m{reg}', mem_operand, is_memory=True)


def format_fpu(fpu: FPUInstruction) -> str:
    """Format FPU instruction as string."""
    if fpu.operand:
        return f'{fpu.mnemonic} {fpu.operand}'
    return fpu.mnemonic

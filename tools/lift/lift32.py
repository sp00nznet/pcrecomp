"""
x86-32 to C Lifter for XWA static recompilation.
Translates x86 instructions into C code using a global register model.

Follows the burnout3 pattern: global registers (g_eax, g_ecx, etc.),
PUSH32/POP32 macros, MEM* memory access, pattern-matched condition
generation from flag-setters to flag-consumers.
"""

from dataclasses import dataclass, field
from typing import Optional
from capstone.x86 import (
    X86_OP_REG, X86_OP_IMM, X86_OP_MEM,
    X86_REG_EAX, X86_REG_ECX, X86_REG_EDX, X86_REG_EBX,
    X86_REG_ESP, X86_REG_EBP, X86_REG_ESI, X86_REG_EDI,
    X86_REG_AX, X86_REG_CX, X86_REG_DX, X86_REG_BX,
    X86_REG_SP, X86_REG_BP, X86_REG_SI, X86_REG_DI,
    X86_REG_AL, X86_REG_CL, X86_REG_DL, X86_REG_BL,
    X86_REG_AH, X86_REG_CH, X86_REG_DH, X86_REG_BH,
    X86_REG_FS, X86_REG_GS,
    X86_REG_CS, X86_REG_DS, X86_REG_ES, X86_REG_SS,
    X86_REG_ST0,
    X86_REG_MM0,
)


# MMX: mm0..mm7 are eight 64-bit registers. Their C home is _mm[0..7].
MMX_REGS = {X86_REG_MM0 + i: i for i in range(8)}

# Packed operations, as C expressions over two uint64_t. The bitwise ones need no
# helper; everything element-wise lives beside the register file in the runtime.
MMX_BINOPS = {
    'pand':      '({a} & {b})',
    'pandn':     '(~{a} & {b})',
    'por':       '({a} | {b})',
    'pxor':      '({a} ^ {b})',
    'paddw':     'mmx_paddw({a}, {b})',
    'paddd':     'mmx_paddd({a}, {b})',
    'paddsw':    'mmx_paddsw({a}, {b})',
    'psubw':     'mmx_psubw({a}, {b})',
    'psubd':     'mmx_psubd({a}, {b})',
    'psubsw':    'mmx_psubsw({a}, {b})',
    'pmulhw':    'mmx_pmulhw({a}, {b})',
    'pmullw':    'mmx_pmullw({a}, {b})',
    'pmaddwd':   'mmx_pmaddwd({a}, {b})',
    'punpcklwd': 'mmx_punpcklwd({a}, {b})',
    'punpckhwd': 'mmx_punpckhwd({a}, {b})',
    'punpcklbw': 'mmx_punpcklbw({a}, {b})',
    'punpckhbw': 'mmx_punpckhbw({a}, {b})',
    'punpckldq': 'mmx_punpckldq({a}, {b})',
    'punpckhdq': 'mmx_punpckhdq({a}, {b})',
    'packssdw':  'mmx_packssdw({a}, {b})',
    'packuswb':  'mmx_packuswb({a}, {b})',
    'pcmpeqw':   'mmx_pcmpeqw({a}, {b})',
    'pcmpgtw':   'mmx_pcmpgtw({a}, {b})',
    'pcmpeqd':   'mmx_pcmpeqd({a}, {b})',
    'pcmpgtd':   'mmx_pcmpgtd({a}, {b})',
    'paddb':     'mmx_paddb({a}, {b})',
    'psubb':     'mmx_psubb({a}, {b})',
    'paddsb':    'mmx_paddsb({a}, {b})',
    'psubsb':    'mmx_psubsb({a}, {b})',
    'paddusb':   'mmx_paddusb({a}, {b})',
    'psubusb':   'mmx_psubusb({a}, {b})',
    'paddusw':   'mmx_paddusw({a}, {b})',
    'psubusw':   'mmx_psubusw({a}, {b})',
    'pcmpeqb':   'mmx_pcmpeqb({a}, {b})',
    'pcmpgtb':   'mmx_pcmpgtb({a}, {b})',
    'packsswb':  'mmx_packsswb({a}, {b})',
}

# Shifts take their count from an immediate or from another MMX register.
MMX_SHIFTS = {
    'psllq': 'mmx_psllq', 'psrlq': 'mmx_psrlq',
    'psllw': 'mmx_psllw', 'psrlw': 'mmx_psrlw', 'psraw': 'mmx_psraw',
    'pslld': 'mmx_pslld', 'psrld': 'mmx_psrld', 'psrad': 'mmx_psrad',
}


# Register name mappings (Capstone ID -> C name)
REG_NAMES_32 = {
    X86_REG_EAX: 'eax', X86_REG_ECX: 'ecx', X86_REG_EDX: 'edx', X86_REG_EBX: 'ebx',
    X86_REG_ESP: 'esp', X86_REG_EBP: 'ebp', X86_REG_ESI: 'esi', X86_REG_EDI: 'edi',
}

REG_NAMES_16 = {
    X86_REG_AX: 'eax', X86_REG_CX: 'ecx', X86_REG_DX: 'edx', X86_REG_BX: 'ebx',
    X86_REG_SP: 'esp', X86_REG_BP: 'ebp', X86_REG_SI: 'esi', X86_REG_DI: 'edi',
}

REG_NAMES_8L = {
    X86_REG_AL: 'eax', X86_REG_CL: 'ecx', X86_REG_DL: 'edx', X86_REG_BL: 'ebx',
}

REG_NAMES_8H = {
    X86_REG_AH: 'eax', X86_REG_CH: 'ecx', X86_REG_DH: 'edx', X86_REG_BH: 'ebx',
}

ALL_REG_IDS = set(REG_NAMES_32) | set(REG_NAMES_16) | set(REG_NAMES_8L) | set(REG_NAMES_8H)


# Condition map: jcc mnemonic -> (cmp_macro, test_macro, description)
COND_MAP = {
    'je':   ('CMP_EQ',  'TEST_Z',  'equal / zero'),
    'jz':   ('CMP_EQ',  'TEST_Z',  'equal / zero'),
    'jne':  ('CMP_NE',  'TEST_NZ', 'not equal / not zero'),
    'jnz':  ('CMP_NE',  'TEST_NZ', 'not equal / not zero'),
    'ja':   ('CMP_A',   None,      'above (unsigned >)'),
    'jae':  ('CMP_AE',  None,      'above or equal (unsigned >=)'),
    'jb':   ('CMP_B',   None,      'below (unsigned <)'),
    'jbe':  ('CMP_BE',  None,      'below or equal (unsigned <=)'),
    'jg':   ('CMP_G',   None,      'greater (signed >)'),
    'jge':  ('CMP_GE',  None,      'greater or equal (signed >=)'),
    'jl':   ('CMP_L',   'TEST_S',  'less (signed <)'),
    'jle':  ('CMP_LE',  None,      'less or equal (signed <=)'),
    'js':   ('CMP_S',   'TEST_S',  'sign (negative)'),
    'jns':  ('CMP_NS',  'TEST_NS', 'not sign (positive)'),
    'jo':   ('CMP_O',   None,      'overflow'),
    'jno':  ('CMP_NO',  None,      'not overflow'),
    'jp':   ('CMP_P',   None,      'parity'),
    'jnp':  ('CMP_NP',  None,      'not parity'),
}

# Which runtime flag kind each setter corresponds to; see recomp_cond().
FLAG_KIND = {
    'cmp': 'FK_CMP', 'sub': 'FK_CMP', 'dec': 'FK_DEC',
    'add': 'FK_ADD', 'inc': 'FK_INC',
    'and': 'FK_TEST', 'or': 'FK_TEST', 'xor': 'FK_TEST', 'test': 'FK_TEST',
    'bt': 'FK_BT', 'bts': 'FK_BT', 'btr': 'FK_BT', 'btc': 'FK_BT', 'fcom': 'FK_FCOM',
    'eflags': 'FK_EFLAGS',
}

# jcc -> runtime condition code, for the sites where the setter is not known
# statically (a branch reached from blocks with different flag-setters).
COND_CODE = {
    'je': 'CC_E', 'jz': 'CC_E', 'jne': 'CC_NE', 'jnz': 'CC_NE',
    'js': 'CC_S', 'jns': 'CC_NS',
    'jg': 'CC_G', 'jnle': 'CC_G', 'jge': 'CC_GE', 'jnl': 'CC_GE',
    'jl': 'CC_L', 'jnge': 'CC_L', 'jle': 'CC_LE', 'jng': 'CC_LE',
    'ja': 'CC_A', 'jnbe': 'CC_A', 'jae': 'CC_AE', 'jnb': 'CC_AE', 'jnc': 'CC_AE',
    'jb': 'CC_B', 'jnae': 'CC_B', 'jc': 'CC_B', 'jbe': 'CC_BE', 'jna': 'CC_BE',
    'jo': 'CC_O', 'jno': 'CC_NO',
    'jp': 'CC_P', 'jpe': 'CC_P', 'jnp': 'CC_NP', 'jpo': 'CC_NP',
}


# Setcc follows same pattern
SETCC_MAP = {f'set{k[1:]}': v for k, v in COND_MAP.items()}

# CMOVcc follows same pattern
CMOVCC_MAP = {f'cmov{k[1:]}': v for k, v in COND_MAP.items()}


_SEG_REGS = (X86_REG_CS, X86_REG_DS, X86_REG_ES, X86_REG_FS, X86_REG_GS, X86_REG_SS)


def _stack_bits(insn, op):
    """Width of a push/pop: the operand's, except a segment register moves the
    stack by the operand size (32) unless a 66h prefix says 16."""
    if op.type == X86_OP_REG and op.reg in _SEG_REGS:
        # No modrm or immediate on these forms, so every byte before the
        # opcode is a prefix (works for Capstone insns and LinearInstruction).
        return 16 if 0x66 in bytes(insn.bytes)[:-1] else 32
    return op_bits(op)


def reg_name(reg_id: int) -> str:
    """Get the C variable name for a Capstone register ID."""
    if reg_id in REG_NAMES_32:
        return REG_NAMES_32[reg_id]
    if reg_id in REG_NAMES_16:
        return REG_NAMES_16[reg_id]
    if reg_id in REG_NAMES_8L:
        return REG_NAMES_8L[reg_id]
    if reg_id in REG_NAMES_8H:
        return REG_NAMES_8H[reg_id]
    # FPU ST(i) registers: Capstone uses IDs 224-231 for st(0)-st(7)
    if X86_REG_ST0 <= reg_id <= X86_REG_ST0 + 7:
        return f"_st[{reg_id - X86_REG_ST0}]"
    # Segment registers (flat mode - effectively no-ops)
    # CS=11, DS=17, ES=28, FS=29, GS=30, SS=49
    # Use capstone's symbolic register constants rather than hardcoded IDs:
    # the numeric IDs vary across capstone versions (fs/gs surfaced as 32/33 here).
    seg_names = {X86_REG_CS: '_seg_cs', X86_REG_DS: '_seg_ds', X86_REG_ES: '_seg_es',
                 X86_REG_FS: '_seg_fs', X86_REG_GS: '_seg_gs', X86_REG_SS: '_seg_ss'}
    if reg_id in seg_names:
        return seg_names[reg_id]
    return f"0 /* unknown reg {reg_id} */"


def is_16bit_reg(reg_id: int) -> bool:
    return reg_id in REG_NAMES_16

def is_8bit_lo(reg_id: int) -> bool:
    return reg_id in REG_NAMES_8L

def is_8bit_hi(reg_id: int) -> bool:
    return reg_id in REG_NAMES_8H


def op_bits(op) -> int:
    """Operand width in bits. Capstone reports x86 operand size in bytes, for
    registers and memory alike, so this covers both.

    Shifts need it: the bit a left shift pushes into CF is bit (width - count)
    of the original value, and the bits a double shift pulls in from its source
    come from (width - count). Hardcoding 32 there is silently wrong on every
    narrower operand -- `shl ax, 1` would read bit 31 of a 16-bit value and set
    CF to 0 forever.
    """
    return (getattr(op, 'size', 4) or 4) * 8


# Per-function scratch that lifted bodies assume exists. The lifter emits
# references to these (e.g. `_flag_k = FK_CMP;` from a flag-setting instruction,
# `recomp_cond(_flag_k, _flag_a, _flag_b, cc)` from the jcc that reads it) but it
# cannot declare them itself -- it emits statements, not function bodies. Project
# drivers write the function preamble, so before this existed each driver carried
# a hand-copied list and every one of them silently went stale whenever the lifter
# started using a new local. Declaring the contract here means the drivers ask
# instead of remembering.
#
# The x87 stack (_st / _fp_top / _fpu_cw) is deliberately NOT here: it is shared
# across calls and lives as a global in recomp_types.h.
#
# Neither is `ebp`, and that one was learned the hard way. It looks like a local
# -- a well-behaved function pushes it, uses it as its frame pointer and pops it,
# so a private copy starting at 0 is indistinguishable from the real thing. But
# an optimising compiler splits one function's blocks across the image and jumps
# between them, and every one of those blocks addresses the *same* frame through
# ebp. Lifted as separate bodies (which they must be -- something jumps directly
# to them) a private ebp makes each one start with a frame pointer of 0, and the
# first `[ebp-0x20]` reads 0xFFFFFFE0. ebp is a register like any other; it lives
# in recomp_types.h with the rest of the file.
FUNCTION_LOCALS = (
    'int _fpu_cmp = 0;',
    'uint32_t _cf = 0;',
    'int _df = 1;',
    'uint32_t _flag_k = FK_NONE;',
    'uint32_t _flag_a = 0, _flag_b = 0;',
    'uint32_t _itail_tgt = 0;',
)


def _is_far_indirect(insn) -> bool:
    """call/jmp m16:32: opcode FF with ModRM reg 3 (call) or 5 (jmp)."""
    b = bytes(insn.bytes)
    i = 0
    while i < len(b) and b[i] in (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF2, 0xF3):
        i += 1
    return i + 1 < len(b) and b[i] == 0xFF and ((b[i + 1] >> 3) & 7) in (3, 5)


# Lifted only with Lifter(dos=True); see Lifter._lift_dos.
DOS_OPS = {'int', 'iretd', 'in', 'out', 'insb', 'insw', 'insd', 'outsb', 'outsw', 'outsd',
           'cli', 'sti', 'hlt'}
# Segment registers whose base the DOS host tracks, by x86 sreg number. The
# host keeps g_seg_* and the matching *_BASE in step (recomp_set_seg).
DOS_SEG_IDX = {X86_REG_ES: 0, X86_REG_FS: 4, X86_REG_GS: 5}

class Lifter:
    """Lifts x86 instructions to C code using a global register model."""

    def __init__(self, iat_map: dict = None, func_names: dict = None,
                 lifted: set = None, precise_sbb: bool = False,
                 patch_sites: set = None, precise_carry: bool = False,
                 reloc=None, dos: bool = False, call_pop: set = None):
        """
        iat_map: VA -> (dll, func_name) for import resolution
        func_names: VA -> name for known function names
        """
        self.iat_map = iat_map or {}
        self.func_names = func_names or {}
        # VAs that will actually be emitted. Direct calls to anything else
        # (garbage targets from data decoded as code) degrade to RECOMP_ICALL,
        # which logs at runtime instead of failing the link on a symbol nobody
        # will ever define. None = trust every target, as before.
        self.lifted = lifted
        self.precise_sbb = precise_sbb
        # adc/sbb take their carry-in from the lazy flag state (recomp_carry)
        # instead of the `_cf` variable, which add/sub/cmp never write. Quake's
        # span stepper is `add edx, eax; sbb ecx, ecx; add ebx, ebp; adc esi,
        # [ecx*4 + step]`: reading `_cf`, every texel step lost its carry and
        # Gunman's textures smeared along each span. Opt-in because Fury3
        # leans on the old imprecision (see the sbb note below).
        self.precise_carry = precise_carry
        # reloc(va) -> new va, or None: moves static data. Every absolute
        # displacement and every immediate that points into a moved block is
        # rewritten to the same offset in its new home -- how Gunman's
        # resolution-sized tables get room for 4K (run_lift.py RELOCS).
        self.reloc = reloc
        # Code addresses the program writes a dword to (see _patched_imm). An
        # instruction whose trailing imm32 sits on one of these is patched at
        # runtime, so its constant in the file is a placeholder.
        self.patch_sites = patch_sites or set()
        # A DOS-extender program (LE, see tools/le/): int, port I/O, cli/sti,
        # hlt and iretd call into the host instead of being dropped.
        self.dos = dos
        # Call targets whose first instruction is `pop r32` (see the call case).
        self.call_pop = call_pop or set()
        self._patched_imm = None
        self._patched_disp = None   # (placeholder, expr) for a patched disp32
        self._labels = None        # block starts of the function being lifted
        self._jump_targets = None  # arms its switch tables dispatch to
        self._flag_state = None  # (setter_mnemonic, operands_str)
        self._flag_seq = 0       # bumped whenever the flags are written
        self._fp_depth = 0  # FPU stack depth tracking

    def _mm_read(self, op) -> str:
        """Read an operand as a 64-bit MMX value."""
        if op.type == X86_OP_REG and op.reg in MMX_REGS:
            return f"_mm[{MMX_REGS[op.reg]}]"
        if op.type == X86_OP_MEM:
            return f"MEM64({self._fmt_mem_addr(op.mem)})"
        return f"(uint64_t)({self._fmt_read(op)})"

    def _mm_write(self, op, value: str) -> str:
        """Assign a 64-bit MMX value to an operand."""
        if op.type == X86_OP_REG and op.reg in MMX_REGS:
            return f"_mm[{MMX_REGS[op.reg]}] = {value}"
        if op.type == X86_OP_MEM:
            return f"MEM64({self._fmt_mem_addr(op.mem)}) = {value}"
        return self._fmt_write(op, f"(uint32_t)({value})")

    def _mm_count(self, op) -> str:
        """Shift count: an immediate, or the whole of another MMX register."""
        if op.type == X86_OP_IMM:
            return str(op.imm & 0xFF)
        if op.type == X86_OP_REG and op.reg in MMX_REGS:
            return f"(_mm[{MMX_REGS[op.reg]}] > 63 ? 64 : (uint32_t)_mm[{MMX_REGS[op.reg]}])"
        return f"(uint32_t)({self._fmt_read(op)})"

    def _fmt_read(self, op) -> str:
        """Format an operand for reading (rvalue)."""
        if op.type == X86_OP_REG:
            r = op.reg
            if r in REG_NAMES_32:
                return REG_NAMES_32[r]
            if r in REG_NAMES_16:
                return f"LO16({REG_NAMES_16[r]})"
            if r in REG_NAMES_8L:
                return f"LO8({REG_NAMES_8L[r]})"
            if r in REG_NAMES_8H:
                return f"HI8({REG_NAMES_8H[r]})"
            return reg_name(r)
        elif op.type == X86_OP_IMM:
            if self._patched_imm:
                return self._patched_imm
            val = op.imm & 0xFFFFFFFF
            if self.reloc and val > 0xFFFF:
                val = self.reloc(val) or val
            if val > 0xFFFF:
                return f"0x{val:08X}u"
            elif val > 9:
                return f"0x{val:X}u"
            else:
                return str(val)
        elif op.type == X86_OP_MEM:
            return self._fmt_mem_read(op.mem, op.size)
        return "???"

    def _fmt_write(self, op, value: str) -> str:
        """Format an assignment to an operand (lvalue = value)."""
        if op.type == X86_OP_REG:
            r = op.reg
            if r in REG_NAMES_32:
                return f"{REG_NAMES_32[r]} = {value}"
            if r in REG_NAMES_16:
                return f"SET_LO16({REG_NAMES_16[r]}, {value})"
            if r in REG_NAMES_8L:
                return f"SET_LO8({REG_NAMES_8L[r]}, {value})"
            if r in REG_NAMES_8H:
                return f"SET_HI8({REG_NAMES_8H[r]}, {value})"
            # Segment registers and FPU ST(i) - use as comment
            if X86_REG_ST0 <= r <= X86_REG_ST0 + 7:
                return f"_st[{r - X86_REG_ST0}] = {value}"
            if self.dos and r in DOS_SEG_IDX:
                return f"recomp_set_seg({DOS_SEG_IDX[r]}, {value})"
            # Segment registers - no-op in flat mode
            if r in (11, 17, 28, 29, 30, 49):
                return f"(void)({value}) /* seg reg write */"
            return f"(void)({value}) /* unknown reg {r} */"
        elif op.type == X86_OP_MEM:
            return self._fmt_mem_write(op.mem, op.size, value)
        return f"??? = {value}"

    def _fmt_mem_addr(self, mem) -> str:
        """Format the effective address calculation for a memory operand."""
        parts = []
        if mem.base != 0:
            parts.append(reg_name(mem.base))
        if mem.index != 0:
            idx = reg_name(mem.index)
            if mem.scale > 1:
                parts.append(f"{idx} * {mem.scale}")
            else:
                parts.append(idx)
        if self._patched_disp and (mem.disp & 0xFFFFFFFF) == self._patched_disp[0]:
            parts.append(self._patched_disp[1])
        elif mem.disp != 0:
            moved = self.reloc(mem.disp & 0xFFFFFFFF) if self.reloc else None
            if moved is not None:
                parts.append(f"0x{moved:X}")
            elif mem.disp > 0:
                parts.append(f"0x{mem.disp:X}")
            else:
                parts.append(f"(-0x{-mem.disp:X})")
        if not parts:
            parts.append("0")
        addr = ' + '.join(parts)
        # Segment override: fs/gs are thread-relative (TIB/TEB) and must NOT be
        # treated as flat. Route them through a runtime base so e.g. `fs:[0]`
        # (the SEH chain head) reads the simulated TIB instead of VA 0.
        # cs/ds/es/ss are flat in Win32 and need no base.
        seg = getattr(mem, 'segment', 0)
        if seg == X86_REG_FS:
            return f"FS_BASE + ({addr})"
        if seg == X86_REG_GS:
            return f"GS_BASE + ({addr})"
        # Under a DOS extender es is a real selector: the startup code reads
        # the PSP and environment through it. ds/ss/cs stay flat (base 0).
        # ponytail: explicit es: overrides only; stos/movs still write flat
        # through edi, which holds while the program keeps es == ds for them.
        if seg == X86_REG_ES and self.dos:
            return f"ES_BASE + ({addr})"
        return addr

    def _fmt_mem_read(self, mem, size: int) -> str:
        """Format a memory read."""
        addr = self._fmt_mem_addr(mem)
        if size == 1:
            return f"MEM8({addr})"
        elif size == 2:
            return f"MEM16({addr})"
        elif size == 4:
            return f"MEM32({addr})"
        elif size == 8:
            return f"MEM64({addr})"
        return f"MEM32({addr})"

    def _fmt_mem_write(self, mem, size: int, value: str) -> str:
        """Format a memory write."""
        addr = self._fmt_mem_addr(mem)
        if size == 1:
            return f"MEM8({addr}) = (uint8_t)({value})"
        elif size == 2:
            return f"MEM16({addr}) = (uint16_t)({value})"
        elif size == 4:
            return f"MEM32({addr}) = {value}"
        elif size == 8:
            return f"MEM64({addr}) = {value}"
        return f"MEM32({addr}) = {value}"

    def _fmt_lea(self, mem) -> str:
        """Format LEA (just the address calculation, no memory access)."""
        return self._fmt_mem_addr(mem)

    @staticmethod
    def _string_cmp_base(insn, m):
        """The cmps/scas mnemonic, if this really is a string instruction.

        `cmpsd` is also an SSE mnemonic (CMPSD xmm, xmm, imm8), so the mnemonic
        alone cannot decide. The opcode can: string compare is A6/A7 and string
        scan is AE/AF, after any prefixes. Returns None for anything else.
        """
        base = m.split()[-1]
        if base not in ('cmpsb', 'cmpsw', 'cmpsd', 'scasb', 'scasw', 'scasd'):
            return None
        prefixes = {0xF0, 0xF2, 0xF3, 0x66, 0x67,
                    0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65}
        for byte in insn.bytes:
            if byte in prefixes:
                continue
            return base if byte in (0xA6, 0xA7, 0xAE, 0xAF) else None
        return None

    def _shift_count(self, op):
        """x86 masks a shift count to its low 5 bits before doing anything --
        for BYTE and WORD operands too, not just DWORD. `shl dword [ecx], 0x6e`
        shifts by 14, not by 110.

        Emitting the raw immediate made the generated C shift by more than the
        width of the type, which is undefined behaviour: the compiler is free to
        keep the operand unchanged, produce zero, or use only the low bits, and
        those disagree. MechCommander Gold has 172 such sites.

        Returns (expression, constant) -- the constant is None for a count that
        is only known at runtime (`shl eax, cl`), and folding it when it IS known
        matters, because a compiler still type-checks the unreachable half of a
        ternary and warns about the negative shift inside it.
        """
        if op.type == X86_OP_IMM:
            n = op.imm & 31
            return f"{n}u", n
        return f"(({self._fmt_read(op)}) & 31)", None

    def _shift_out_cf(self, a, count, n, width, kind):
        """CF is the last bit shifted out of the operand.

        A masked count can still exceed the operand width (`shl byte, 21` is a
        legal encoding), which leaves no such bit. Intel documents CF as
        undefined there for SHL/SHR, so zero is conformant and, unlike
        `a >> (8 - 21)`, is not undefined behaviour in C. SAR is the exception:
        its result is all sign bits, and so is its carry.
        """
        top = width - 1
        if n == 0:
            # `shl dword [edx], 0xa0` masks to zero. A shift of zero touches
            # nothing at all, so CF keeps its value -- and asking for "the bit
            # shifted out" would index one past the operand (>> 32).
            return "_cf"
        if n is not None:                       # count folded at generation time
            if kind == 'left':
                return f"((({a}) >> {width - n}) & 1u)" if n <= width else "0u"
            if kind == 'right':
                return f"((({a}) >> {n - 1}) & 1u)" if n <= width else "0u"
            return f"((({a}) >> {n - 1 if n <= width else top}) & 1u)"
        if kind == 'left':
            return (f"(({count}) <= {width} ? "
                    f"((({a}) >> ({width} - ({count}))) & 1u) : 0u)")
        if kind == 'right':
            return (f"(({count}) <= {width} ? "
                    f"((({a}) >> (({count}) - 1)) & 1u) : 0u)")
        return (f"(({count}) <= {width} ? ((({a}) >> (({count}) - 1)) & 1u) "
                f": ((({a}) >> {top}) & 1u))")

    def _shift_flags(self, res, count, width):
        """Publish a shift's flags: CF from _cf, ZF/SF from the result.

        The lazy triple holds two operands and a kind. A shift needs the bit it
        shifted out AND the result, and `('or', result, result)` -- what this
        used to record -- says the carry is zero. Every carry-conditional after
        a shift then read a constant: CMP_AE(r, r) is `r >= r`, which is always
        true.

        The background blitter in Gizmos & Gadgets is
        `shr ecx,1; rep movsw; jae skip; movsb`, copying width/2 words and then
        the odd byte. With that jae always taken, every row of every background
        lost its last byte, and the picture came out as a diagonal smear.

        A shift of zero writes no flags at all, so the whole thing is guarded --
        which also retires the `shift.by-zero` divergence the harness carried.
        """
        aligned = res if width >= 32 else f"((uint32_t)({res}) << {32 - width})"
        return (f"if ({count}) {{ _flag_a = recomp_flags_pack({aligned}, _cf, 0, 0); "
                f"_flag_b = 0; _flag_k = FK_EFLAGS; }}")

    def _flag_capture(self, a, b, width=32):
        """Snapshot flag operands into temps and record the flag state to use them.

        A jcc reads the flags set by an earlier cmp/test/sub/... The old code
        stored the operand *expressions* and re-evaluated them at the jcc, so any
        instruction in between that wrote the operand (e.g. `test eax,eax; mov
        eax,0; jne`, or `sub eax,ebx; jl` where eax is the destination) corrupted
        the condition. Capturing the values at the flag-setter fixes that.
        Returns the C snapshot statement to append; sets self._flag_state to temps.

        A NARROW operand is stored left-aligned: shifted up so that its own top
        bit lands on bit 31.

        The tuple holds two values and a kind, but no width, and every consumer
        derives its flags at 32 bits. `add ax,cx` with ax=0xFFFF and cx=2 wraps
        at 16 bits and sets CF; the same two numbers at 32 bits do not. So every
        flag off a narrow compare was wrong -- and in a Borland binary whose
        drawing code is ported 16-bit assembly, that is most of the compares in
        the program.

        Left-aligning fixes it without a width anywhere. At the top of the word
        a 16-bit value's sign bit IS bit 31, and its carry out IS the carry out
        of 32 bits, so CF, ZF, SF and OF all come out right through the macros
        that are already there -- no runtime cost, and no change at the hundreds
        of sites that pair a jcc with its setter statically.

        PF and AF are read off the bottom of the result -- parity of the low
        byte, bit 4 -- which is now zeros. A jcc paired with its setter
        statically knows the width (_flag_width); one that reads the kind at
        runtime learns it from the kind itself, FK_NARROW(kind, shift). The
        MSVC float compare `fnstsw ax; test ah, 5; jp` is a narrow test whose
        jp lands at runtime whenever the jp is a join point or its function
        labels every instruction.
        """
        self._flag_seq += 1
        self._flag_width = width      # PF needs it: parity is of the LOW byte
        self._insn_flag_width = width # ... and so does the kind this instruction writes
        if width >= 32:
            return f"_flag_a = (uint32_t)({a}); _flag_b = (uint32_t)({b});"
        sh = 32 - width
        return (f"_flag_a = (uint32_t)({a}) << {sh}; "
                f"_flag_b = (uint32_t)({b}) << {sh};")

    def _make_condition(self, jcc_mnemonic: str) -> str:
        """
        Generate a C condition expression by pattern-matching the flag-setter
        with the flag-consumer (jcc/setcc/cmovcc).
        """
        mnem = jcc_mnemonic
        # Normalize: je/jz -> je, jne/jnz -> jne
        if mnem.startswith('cmov'):
            cond_key = mnem
            map_to_use = CMOVCC_MAP
        elif mnem.startswith('set'):
            cond_key = mnem
            map_to_use = SETCC_MAP
        else:
            cond_key = mnem
            map_to_use = COND_MAP

        entry = map_to_use.get(cond_key)
        if not entry:
            return f"/* unknown condition: {mnem} */ _cf"

        cmp_macro, test_macro, desc = entry

        # setcc and cmovcc carry exactly the condition of the matching jcc, so
        # normalise to that spelling ONCE. Every table below is keyed on the
        # jcc form, and looking one up with the raw mnemonic silently misses:
        # `jle` after a test got TEST_LE and `setle` after the same test got
        # CMP_LE, which compares the two operands instead of the AND result --
        # for `test ebx, ebx` that is `ebx <= ebx`, true for every value. That
        # is how PacketFile::seekPacket came to fail on every call.
        if mnem.startswith('cmov'):
            jform = 'j' + mnem[4:]
        elif mnem.startswith('set'):
            jform = 'j' + mnem[3:]
        else:
            jform = mnem

        if self._flag_state is None:
            # Reached from blocks with different flag-setters: decide at runtime.
            cc = COND_CODE.get(jform)
            if cc:
                # _cf rides along: after inc/dec the carry is the preserved one
                return f"recomp_cond_cf(_flag_k, _flag_a, _flag_b, {cc}, _cf)"
            return f"/* no flag state for {mnem} */ _cf"

        setter, ops = self._flag_state

        # inc/dec leave CF UNTOUCHED: a carry read after them is the carry of
        # whatever set it before, and that value is already in _cf (inc/dec
        # never write it). MSVC schedules exactly this:
        #     cmp edi, 0x20 / mov [ebp+0xf], cl / inc cl / mov [..], cl / jae
        # -- the CRT small-block heap's __sbh_free_block (sw.dll 0x100A3E58).
        # Evaluating jae from the inc's operands corrupted the heap in every
        # Gunman module that links the CRT.
        if setter in ('inc', 'dec') and jform in ('jb', 'jae', 'ja', 'jbe'):
            zf = (f"CMP_EQ({ops})" if setter == 'dec'
                  else f"recomp_cond(_flag_k, {ops}, CC_E)")
            return {'jb': "(_cf != 0)", 'jae': "(_cf == 0)",
                    'ja': f"(_cf == 0 && !{zf})", 'jbe': f"(_cf != 0 || {zf})"}[jform]

        # PF: parity of the result's low byte. MSVC's float compares test it:
        # `fnstsw ax; test ah, 5; jp` is `x < 0.0` (C0|C2), and with CMP_P a
        # constant 0 the MxO client's `while (x < 0) x += 1.0` texture-wrap loop
        # never exited. The result is rebuilt from the captured operands per
        # setter; narrow operands were left-aligned by _flag_capture, so the
        # low byte of an N-bit result sits at bit 32-N.
        if jform in ('jp', 'jnp'):
            parts = [x.strip() for x in ops.split(',')]
            fa, fb = (parts + [None])[:2]
            res = None if fb is None else {'cmp': f"({fa} - {fb})", 'sub': f"({fa} - {fb})", 'dec': f"({fa} - {fb})",
                   'add': f"({fa} + {fb})", 'inc': f"({fa} + {fb})",
                   'test': f"({fa} & {fb})", 'and': f"({fa} & {fb})",
                   'or': f"({fa} & {fb})", 'xor': f"({fa} & {fb})"}.get(setter)
            if res:
                w = getattr(self, '_flag_width', 32)
                pf = f"RECOMP_PF({res}, {32 - w if w < 32 else 0})"
                return pf if jform == 'jp' else f"(!{pf})"

        if setter == 'eflags':
            # an EFLAGS image (sahf): PF is bit 2; the rest recomp_cond decodes
            if jform in ('jp', 'jnp'):
                pf = "((_flag_a >> 2) & 1u)"
                return pf if jform == 'jp' else f"(!{pf})"
            cc = COND_CODE.get(jform)
            if cc:
                return f"recomp_cond(FK_EFLAGS, _flag_a, 0, {cc})"
            return f"/* eflags: unmapped {mnem} */ 0"

        if setter == 'cmp':
            return f"{cmp_macro}({ops})"
        elif setter in ('test', 'and', 'or', 'xor'):
            # After `test` (and `and`, whose result is the same value), CF=0 and
            # OF=0, so the unsigned/signed-ordering jccs reduce to ZF/SF tests
            # against the AND result -- NOT cmp(a,b), which would compare the two
            # operands as if subtracted. Map them directly.
            #
            # `or` and `xor` capture their RESULT in both slots, so TEST_*(r, r)
            # tests exactly r and the same table is exact for them too. They used
            # to fall to cmp_macro: `xor eax, [b]; jge` ("same sign?") became
            # CMP_GE(r, r), always true. Unreal's clipper asks whether an edge
            # crosses a plane that way, never saw one cross, and drew every
            # clipped polygon as stretched shards.
            test_only = {
                'jbe': f"TEST_Z({ops})",  'ja':  f"TEST_NZ({ops})",   # CF=0: jbe==je, ja==jne
                'jb':  "0",               'jae': "1",                 # CF=0: jb never, jae always
                'jg':  f"TEST_G({ops})",  'jle': f"TEST_LE({ops})",
                'jge': f"TEST_NS({ops})", 'jl':  f"TEST_S({ops})",
            }
            if jform in test_only:
                return test_only[jform]
            if test_macro:
                return f"{test_macro}({ops})"
            return f"{cmp_macro}({ops})"
        elif setter == 'sub':
            # sub and cmp leave the same flags, and the CMP_* macros are written
            # as a subtraction, so the pairing is exact.
            return f"/* sub result */ {cmp_macro}({ops})"
        elif setter == 'dec':
            # dec's operands are (value, 1) and its result is value - 1, which
            # is what a CMP_* macro computes. Same as sub.
            return f"/* dec result */ {cmp_macro}({ops})"
        elif setter in ('add', 'inc'):
            # NOT the CMP_* macros: those subtract, and these added.
            #
            # `inc eax; jne` is the ordinary way to ask "was that -1?" -- the
            # increment makes it zero -- and paired with a subtracting macro it
            # asked "was that 1?" instead. Treasure Cove opens its resource DLL,
            # tests the handle exactly that way, and put up "Could not find
            # Resource File!" over a file it had just opened successfully.
            #
            # There is no macro to reach for: ZF and SF could be written against
            # the sum, but CF and OF need both operands and the direction. The
            # runtime derivation already knows all of that from FK_ADD/FK_INC.
            jcc = (mnem.replace('cmov', 'j', 1) if mnem.startswith('cmov')
                   else ('j' + mnem[3:] if mnem.startswith('set') else mnem))
            cc = COND_CODE.get(jcc)
            if cc:
                return f"/* {setter} result */ recomp_cond(_flag_k, {ops}, {cc})"
            return f"/* {setter}: unmapped {mnem} */ 0"
        elif setter == 'fcom':
            # fcom/fcomp + fnstsw + sahf loads C0->CF and C3->ZF, so MSVC tests the
            # FPU comparison with the UNSIGNED jccs. `ops` is the -1/0/1 result.
            fpu_cond = {
                'jb': '<', 'jbe': '<=', 'ja': '>', 'jae': '>=',
                'jl': '<', 'jle': '<=', 'jg': '>', 'jge': '>=',
                'je': '==', 'jz': '==', 'jne': '!=', 'jnz': '!=',
            }
            op = fpu_cond.get(jcc_mnemonic.replace('set', 'j').replace('cmov', 'j'))
            if op:
                return f"({ops} {op} 0)"
            return f"/* fcom: unmapped {jcc_mnemonic} */ ({ops} != 0)"
        elif setter == 'bt':
            # BT sets CF = bit tested. jb/jc take CF=1, jae/jnc take CF=0 --
            # both used to return BT_CF, which inverted every `bt; jae`: the
            # CRT's strpbrk then matched every character, so _stat's wildcard
            # check rejected every path and Gunman's engine could not find
            # gfx.wad.
            if cmp_macro == 'CMP_B':
                return f"BT_CF({ops})"
            if cmp_macro == 'CMP_AE':
                return f"(!BT_CF({ops}))"
            return f"/* bt */ {cmp_macro}({ops})"
        else:
            return f"/* flag from {setter} */ {cmp_macro}({ops})"

    def lift_instruction(self, insn) -> list:
        """Lift one instruction, recording the runtime flag kind if it wrote flags."""
        seq0 = self._flag_seq
        self._insn_flag_width = 32    # only this instruction's _flag_capture narrows it
        lines = self._lift_instruction(insn)
        if self._flag_seq != seq0 and self._flag_state is not None:
            fk = FLAG_KIND.get(self._flag_state[0], 'FK_CMP')
            if self._insn_flag_width < 32:
                fk = f"FK_NARROW({fk}, {32 - self._insn_flag_width})"
            lines.append(f"_flag_k = {fk};")
        return lines

    def _lift_instruction(self, insn) -> list:
        """
        Lift a single x86 instruction to C statement(s).
        Returns a list of C code strings.
        """
        # Self-modifying code: if the program stores a dword onto this
        # instruction's trailing imm32, read the immediate from memory rather
        # than emitting the placeholder that happens to be in the file.
        # The trailing dword may be the immediate (`cmp esi, 0x12345678`) or the
        # displacement (`mov esi, [0x12345678]`, `mov al, [eax+0x12345678]`);
        # the shipped placeholder bytes say which operand they belong to. Both
        # occur in Gunman's sw.dll span generator.
        site = insn.address + insn.size - 4
        self._patched_imm = self._patched_disp = None
        if site in self.patch_sites:
            ph = int.from_bytes(bytes(insn.bytes[-4:]), 'little')
            expr = f"MEM32(0x{site:08X}u)"
            ops_ = insn.operands if insn.operands else []
            if any(o.type == X86_OP_IMM and (o.imm & 0xFFFFFFFF) == ph for o in ops_):
                self._patched_imm = expr
            elif any(o.type == X86_OP_MEM and (o.mem.disp & 0xFFFFFFFF) == ph for o in ops_):
                self._patched_disp = (ph, expr)
        m = insn.mnemonic
        # Capstone reports `lock inc dword ptr [x]` with mnemonic 'lock inc' (or
        # plain 'lock' + op_str); the operands are decoded either way. Single-
        # threaded semantics are exact here because the runtime runs lifted code
        # under one machine lock.
        if m.startswith('lock'):
            m = m[4:].strip() or (insn.op_str.split() or [''])[0]
        ops = insn.operands if insn.operands else []
        lines = []

        # Address comment
        comment = f"/* 0x{insn.address:08X}: {insn.mnemonic} {insn.op_str} */"

        # --- Data Movement ---
        if m == 'mov':
            if len(ops) == 2:
                val = self._fmt_read(ops[1])
                lines.append(f"{self._fmt_write(ops[0], val)}; {comment}")

        elif m == 'movzx':
            if len(ops) == 2:
                val = self._fmt_read(ops[1])
                lines.append(f"{self._fmt_write(ops[0], f'(uint32_t){val}')}; {comment}")

        elif m == 'movsx':
            if len(ops) == 2:
                val = self._fmt_read(ops[1])
                src_size = ops[1].size
                if src_size == 1:
                    cast = '(int32_t)(int8_t)'
                else:
                    cast = '(int32_t)(int16_t)'
                lines.append(f"{self._fmt_write(ops[0], f'{cast}{val}')}; {comment}")

        elif m == 'lea':
            if len(ops) == 2 and ops[1].type == X86_OP_MEM:
                addr = self._fmt_lea(ops[1].mem)
                lines.append(f"{self._fmt_write(ops[0], addr)}; {comment}")

        elif m == 'xchg':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(f"{{ uint32_t _tmp = {a}; {comment}")
                lines.append(f"  {self._fmt_write(ops[0], b)};")
                lines.append(f"  {self._fmt_write(ops[1], '_tmp')}; }}")

        elif m == 'bswap':
            if len(ops) == 1:
                r = self._fmt_read(ops[0])
                lines.append(f"{self._fmt_write(ops[0], f'BSWAP32({r})')}; {comment}")

        # --- Stack Operations ---
        #
        # Width matters. `push bp` / `pop bp` (66 55 / 66 5D) move esp by two,
        # and the pop writes BP only -- EBP keeps its top half. Lifting them as
        # the 32-bit forms balances the stack, so it looks fine, and then the
        # pop replaces the whole of ebp with a zero-extended word. A `leave`
        # after that hands the truncated value to esp and the next stack access
        # is down at 64 KB.
        #
        # Segment registers are the exception: `push es` / `pop es` in 32-bit
        # code move esp by FOUR (the default operand size), even though ES is a
        # 16-bit register. Only an explicit 66h prefix makes them two. Watcom's
        # CRT brackets its init-table calls with push es / pop es; lifted as two
        # bytes, every [esp+N] after the push reads two bytes off.
        elif m == 'push':
            if len(ops) == 1:
                val = self._fmt_read(ops[0])
                macro = 'PUSH16' if _stack_bits(insn, ops[0]) == 16 else 'PUSH32'
                lines.append(f"{macro}(esp, {val}); {comment}")

        elif m == 'pop':
            if len(ops) == 1:
                if _stack_bits(insn, ops[0]) == 16:
                    # _fmt_write keeps a 16-bit destination's upper half, for a
                    # register (SET_LO16) and for memory (MEM16) alike.
                    lines.append(f"{self._fmt_write(ops[0], 'POP16_VAL(esp)')}; {comment}")
                else:
                    lines.append(f"POP32(esp, {self._fmt_read(ops[0])}); {comment}")
                    # For pop to register, need assignment form
                    if ops[0].type == X86_OP_REG:
                        r = reg_name(ops[0].reg)
                        lines[-1] = f"{r} = POP32_VAL(esp); {comment}"
                        if self.dos and ops[0].reg in DOS_SEG_IDX:
                            lines[-1] = (f"recomp_set_seg({DOS_SEG_IDX[ops[0].reg]}, POP32_VAL(esp));"
                                         f" {comment}")

        elif m in ('pushad', 'pushal'):   # Capstone spells PUSHAD as 'pushal' in 32-bit
            lines.append(f"PUSHAD(); {comment}")

        elif m in ('popad', 'popal'):      # Capstone spells POPAD as 'popal' in 32-bit
            lines.append(f"POPAD(); {comment}")

        elif m == 'pushfd':
            # Pushing a constant 0 was observable: the CRT's CPU detection
            # toggles a bit in the saved EFLAGS and reads it back to decide
            # whether CPUID exists, and a word that never changes answers
            # every such probe the same wrong way. The lazy tuple holds
            # everything the arithmetic flags derive from, so hand it over.
            lines.append(f"PUSH32(esp, recomp_eflags(_flag_k, _flag_a, _flag_b, _cf, _df)); {comment}")

        elif m == 'popfd':
            lines.append(f"{{ uint32_t _fl = POP32_VAL(esp); {comment}")
            lines.append(f"  _flag_k = FK_EFLAGS; _flag_a = _fl; _flag_b = 0;")
            lines.append(f"  _cf = _fl & 1u; _df = (_fl & 0x400u) ? -1 : 1; }}")
            # The restored word, not whatever instruction last set the flags,
            # is what the next jcc reads -- so drop the static pairing and let
            # it go through recomp_cond.
            self._flag_state = None

        # --- Arithmetic ---
        elif m == 'add':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(self._flag_capture(a, b, op_bits(ops[0])))
                # add writes CF, and `add eax, eax / adc edx, edx` -- a 64-bit
                # shift left -- reads it straight from _cf. Unpublished, the adc
                # took whatever an earlier imul left there, and Nocturne's
                # fixed-point polygon clipper put clipped x a hair below zero:
                # a 65535-pixel span. The capture is left-aligned for narrow
                # operands, so the carry out of bit 31 is the carry at any width.
                lines.append("_cf = (uint32_t)((uint32_t)(_flag_a + _flag_b) < (uint32_t)_flag_a);")
                lines.append(f"{self._fmt_write(ops[0], f'{a} + {b}')}; {comment}")
                self._flag_state = ('add', "_flag_a, _flag_b")

        elif m == 'sub':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(self._flag_capture(a, b, op_bits(ops[0])))
                # sub writes CF too -- same reasoning as cmp above. Publish it
                # before the write-back, while _flag_a/_flag_b still hold the
                # operands rather than the result.
                lines.append("_cf = (uint32_t)CMP_B(_flag_a, _flag_b);")
                lines.append(f"{self._fmt_write(ops[0], f'{a} - {b}')}; {comment}")
                self._flag_state = ('sub', "_flag_a, _flag_b")

        elif m == 'inc':
            if len(ops) == 1:
                a = self._fmt_read(ops[0])
                lines.append(self._flag_capture(a, "1", op_bits(ops[0])))
                lines.append(f"{self._fmt_write(ops[0], f'{a} + 1')}; {comment}")
                self._flag_state = ('inc', "_flag_a, _flag_b")

        elif m == 'dec':
            if len(ops) == 1:
                a = self._fmt_read(ops[0])
                lines.append(self._flag_capture(a, "1", op_bits(ops[0])))
                lines.append(f"{self._fmt_write(ops[0], f'{a} - 1')}; {comment}")
                self._flag_state = ('dec', "_flag_a, _flag_b")

        elif m == 'neg':
            if len(ops) == 1:
                a = self._fmt_read(ops[0])
                lines.append(self._flag_capture("0", a, op_bits(ops[0])))
                # NEG sets CF = (operand != 0), and MSVC leans on it for a
                # branchless null check:
                #     neg ecx / sbb ecx, ecx / and ecx, esi / add ecx, 8
                # i.e. `ecx = (ecx ? esi : 0) + 8`. Without this, sbb reads a
                # stale _cf, the select always yields 0, and the callee gets 8
                # as its `this` -- which is how it presents: a __thiscall
                # method dereferencing address 8. Unlike the cmp/sbb case
                # below, NEG's carry is unambiguous and purely local.
                lines.append(f"_cf = ({a}) != 0;")
                lines.append(f"{self._fmt_write(ops[0], f'(uint32_t)(-(int32_t){a})')}; {comment}")
                self._flag_state = ('sub', "_flag_a, _flag_b")

        elif m == 'not':
            if len(ops) == 1:
                a = self._fmt_read(ops[0])
                lines.append(f"{self._fmt_write(ops[0], f'~{a}')}; {comment}")

        elif m in ('mul', 'imul') and len(ops) == 1:
            # One operand: its width picks the registers -- AL * r8 -> AX,
            # AX * r16 -> DX:AX, EAX * r32 -> EDX:EAX. Lifting every width as
            # the 32-bit form overwrote EDX (and all of EAX) for `mul cl`.
            # CF = OF = "the high half is more than the low half's extension";
            # SF, ZF, AF and PF are undefined. The pair goes in as a literal
            # flags word, the way POPFD's does.
            a = self._fmt_read(ops[0])
            w = ops[0].size
            if w == 1 and m == 'mul':
                lines.append(f"{{ uint32_t _r = (uint32_t)LO8(eax) * (uint8_t)({a}); {comment}")
                lines.append("  SET_LO16(eax, _r); uint32_t _ov = (_r >> 8) != 0;")
            elif w == 1:
                lines.append(f"{{ int32_t _r = (int32_t)(int8_t)LO8(eax) * (int8_t)({a}); {comment}")
                lines.append("  SET_LO16(eax, (uint16_t)_r); uint32_t _ov = _r != (int8_t)_r;")
            elif w == 2 and m == 'mul':
                lines.append(f"{{ uint32_t _r = (uint32_t)LO16(eax) * (uint16_t)({a}); {comment}")
                lines.append("  SET_LO16(eax, _r); SET_LO16(edx, _r >> 16); uint32_t _ov = (_r >> 16) != 0;")
            elif w == 2:
                lines.append(f"{{ int32_t _r = (int32_t)(int16_t)LO16(eax) * (int16_t)({a}); {comment}")
                lines.append("  SET_LO16(eax, (uint16_t)_r); SET_LO16(edx, (uint16_t)(_r >> 16));"
                             " uint32_t _ov = _r != (int16_t)_r;")
            elif m == 'mul':
                lines.append(f"{{ uint64_t _r = (uint64_t)eax * (uint32_t)({a}); {comment}")
                lines.append("  eax = (uint32_t)_r; edx = (uint32_t)(_r >> 32); uint32_t _ov = edx != 0;")
            else:
                lines.append(f"{{ int64_t _r = (int64_t)(int32_t)eax * (int32_t)({a}); {comment}")
                lines.append("  eax = (uint32_t)_r; edx = (uint32_t)(_r >> 32); uint32_t _ov = _r != (int32_t)_r;")
            lines.append("  _flag_k = FK_EFLAGS; _flag_a = _ov ? 0x801u : 0u; _flag_b = 0; _cf = _ov; }")
            self._flag_state = None

        elif m == 'imul':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(f"{self._fmt_write(ops[0], f'(uint32_t)((int32_t){a} * (int32_t){b})')}; {comment}")
            elif len(ops) == 3:
                b = self._fmt_read(ops[1])
                c = self._fmt_read(ops[2])
                lines.append(f"{self._fmt_write(ops[0], f'(uint32_t)((int32_t){b} * (int32_t){c})')}; {comment}")

        elif m in ('div', 'idiv'):
            if len(ops) == 1:
                divisor = self._fmt_read(ops[0])
                # Evaluate the divisor once (it may be a memory read with side effects)
                # and guard against divide-by-zero. On real x86 a zero divisor raises
                # #DE; the original relied on never hitting it (or caught it via SEH),
                # so producing 0 and continuing is the safe recomp behaviour instead of
                # crashing the host process (e.g. degenerate spans / z=0 in the
                # perspective-divide texture mappers).
                #
                # The width picks the registers: AX / r8 -> AL, AH; DX:AX / r16 ->
                # AX, DX; EDX:EAX / r32 -> EAX, EDX. `div cl` lifted as the 32-bit
                # form overwrote EDX, and SimCity 2000 kept a pointer there.
                # Signed INT_MIN / -1 is #DE on the CPU and undefined in C, so it
                # takes the zero-divisor path too.
                w = ops[0].size
                if w == 1 and m == 'div':
                    lines.append(f"{{ uint32_t _n = LO16(eax), _d = (uint8_t)({divisor}); {comment}")
                    lines.append("  SET_LO16(eax, _d ? ((_n % _d) << 8) | ((_n / _d) & 0xFFu) : 0u); }")
                elif w == 1:
                    lines.append(f"{{ int32_t _n = (int16_t)LO16(eax), _d = (int8_t)({divisor}); {comment}")
                    lines.append("  SET_LO16(eax, _d ? (((uint32_t)(_n % _d) & 0xFFu) << 8)"
                                 " | ((uint32_t)(_n / _d) & 0xFFu) : 0u); }")
                elif w == 2 and m == 'div':
                    lines.append(f"{{ uint32_t _n = (LO16(edx) << 16) | LO16(eax), _d = (uint16_t)({divisor}); {comment}")
                    lines.append("  SET_LO16(eax, _d ? _n / _d : 0u); SET_LO16(edx, _d ? _n % _d : 0u); }")
                elif w == 2:
                    lines.append(f"{{ int32_t _n = (int32_t)((LO16(edx) << 16) | LO16(eax)), _d = (int16_t)({divisor}); {comment}")
                    lines.append("  int _ok = _d && !(_d == -1 && _n == INT32_MIN);")
                    lines.append("  SET_LO16(eax, _ok ? (uint32_t)(_n / _d) : 0u); SET_LO16(edx, _ok ? (uint32_t)(_n % _d) : 0u); }")
                elif m == 'div':
                    lines.append(f"{{ uint64_t _dividend = ((uint64_t)edx << 32) | eax; uint32_t _dv = (uint32_t){divisor}; {comment}")
                    lines.append(f"  if (_dv) {{ eax = (uint32_t)(_dividend / _dv); edx = (uint32_t)(_dividend % _dv); }}")
                    lines.append(f"  else {{ eax = 0; edx = 0; }} }}")
                else:
                    lines.append(f"{{ int64_t _dividend = ((int64_t)(int32_t)edx << 32) | eax; int32_t _dv = (int32_t){divisor}; {comment}")
                    lines.append(f"  if (_dv && !(_dv == -1 && _dividend == INT64_MIN)) {{ eax = (uint32_t)((int32_t)(_dividend / _dv)); edx = (uint32_t)((int32_t)(_dividend % _dv)); }}")
                    lines.append(f"  else {{ eax = 0; edx = 0; }} }}")

        # --- Logical ---
        elif m == 'and':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(self._flag_capture(a, b, op_bits(ops[0])))
                lines.append(f"{self._fmt_write(ops[0], f'{a} & {b}')}; {comment}")
                lines.append("_cf = 0;")
                self._flag_state = ('and', "_flag_a, _flag_b")

        elif m == 'or':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(self._flag_capture(f"({a} | {b})", f"({a} | {b})", op_bits(ops[0])))
                lines.append(f"{self._fmt_write(ops[0], f'{a} | {b}')}; {comment}")
                lines.append("_cf = 0;")
                self._flag_state = ('or', "_flag_a, _flag_b")

        elif m == 'xor':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                # Detect xor reg, reg (zero idiom)
                carry = '_cf'
                if ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG and ops[0].reg == ops[1].reg:
                    lines.append(self._flag_capture("0", "0", op_bits(ops[0])))
                    lines.append(f"{self._fmt_write(ops[0], '0')}; {comment}")
                else:
                    lines.append(self._flag_capture(f"({a} ^ {b})", f"({a} ^ {b})", op_bits(ops[0])))
                    lines.append(f"{self._fmt_write(ops[0], f'{a} ^ {b}')}; {comment}")
                lines.append("_cf = 0;")
                self._flag_state = ('xor', "_flag_a, _flag_b")

        # --- Shifts ---
        # shl/shr/sar set ZF/SF/PF from the result (when the count != 0). Capture
        # the result so a following jcc tests it -- otherwise it reads the prior
        # instruction's stale flags (e.g. `shr ecx,2; je` wrongly using a dec's ZF,
        # which sent the Watcom memset's count off into a multi-GB overrun).
        elif m == 'shl' or m == 'sal':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b, bn = self._shift_count(ops[1])
                res = f"({a} << {b})"
                w = op_bits(ops[0])
                lines.append(f"if ({b}) _cf = {self._shift_out_cf(a, b, bn, w, 'left')}; {comment}")
                lines.append(self._shift_flags(res, b, w))
                lines.append(f"{self._fmt_write(ops[0], f'{a} << {b}')}; {comment}")
                self._flag_state = None

        elif m == 'shr':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b, bn = self._shift_count(ops[1])
                w = op_bits(ops[0])
                res = f"({a} >> {b})"
                lines.append(f"if ({b}) _cf = {self._shift_out_cf(a, b, bn, w, 'right')}; {comment}")
                lines.append(self._shift_flags(res, b, w))
                lines.append(f"{self._fmt_write(ops[0], f'{a} >> {b}')}; {comment}")
                self._flag_state = None

        elif m == 'sar':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b, bn = self._shift_count(ops[1])
                w = op_bits(ops[0])
                # Sign-extend from the operand's own width first: a narrow read
                # is unsigned (LO16, MEM16), so `(int32_t)` alone made `sar word`
                # a logical shift for every negative value. Theme Park halves
                # its sprite offsets with `sar word ptr [x], 1` and drew every
                # sprite 32768 pixels away.
                sa = a if w == 32 else f"(int32_t)(int{w}_t)({a})"
                res = f"((uint32_t)((int32_t){sa} >> {b}))"
                # sar must publish CF for a following rcr (the clip's `sar;rcr` lerp).
                lines.append(f"if ({b}) _cf = {self._shift_out_cf(a, b, bn, w, 'arith')}; {comment}")
                lines.append(self._shift_flags(res, b, w))
                lines.append(f"{self._fmt_write(ops[0], f'(uint32_t)((int32_t){sa} >> {b})')};")
                self._flag_state = None

        # shld/shrd: double-precision shift (64-bit window across dst:src). Used pervasively
        # for 64-bit / fixed-point math; leaving them unimplemented silently dropped the
        # write -> garbage 3D vertex/clip math. CF = last bit shifted out of dst.
        # The count is masked to 5 bits here too, and a masked count that still
        # reaches the operand width leaves the result undefined on x86 -- so
        # hold dst rather than shift a uint32_t by a negative amount.
        elif m == 'shrd':
            if len(ops) == 3:
                d = self._fmt_read(ops[0]); s = self._fmt_read(ops[1])
                c, cn = self._shift_count(ops[2])
                w = op_bits(ops[0])
                live = f"({c}) && ({c}) < {w}" if cn is None else (
                    "1" if 0 < cn < w else "0")
                if live == "0":
                    # Statically dead. Emitting the ternary anyway would leave
                    # `{w} - {c}` as a negative constant in the unreachable half,
                    # which the compiler still type-checks and warns about.
                    lines.append(f"/* shrd by {c}: undefined, dst held */ {comment}")
                    self._flag_state = None
                    return lines
                expr = (f"(({live}) ? ((({d}) >> ({c})) | "
                        f"((uint32_t)({s}) << ({w} - ({c})))) : ({d}))")
                lines.append(f"if ({live}) _cf = "
                             f"{self._shift_out_cf(d, c, cn, w, 'right')}; {comment}")
                lines.append(self._shift_flags(expr, live, w))
                lines.append(f"{self._fmt_write(ops[0], expr)};")
                self._flag_state = None

        elif m == 'shld':
            if len(ops) == 3:
                d = self._fmt_read(ops[0]); s = self._fmt_read(ops[1])
                c, cn = self._shift_count(ops[2])
                w = op_bits(ops[0])
                live = f"({c}) && ({c}) < {w}" if cn is None else (
                    "1" if 0 < cn < w else "0")
                if live == "0":
                    # Statically dead. Emitting the ternary anyway would leave
                    # `{w} - {c}` as a negative constant in the unreachable half,
                    # which the compiler still type-checks and warns about.
                    lines.append(f"/* shld by {c}: undefined, dst held */ {comment}")
                    self._flag_state = None
                    return lines
                expr = (f"(({live}) ? ((({d}) << ({c})) | "
                        f"((uint32_t)({s}) >> ({w} - ({c})))) : ({d}))")
                lines.append(f"if ({live}) _cf = "
                             f"{self._shift_out_cf(d, c, cn, w, 'left')}; {comment}")
                lines.append(self._shift_flags(expr, live, w))
                lines.append(f"{self._fmt_write(ops[0], expr)};")
                self._flag_state = None

        # rol/ror/rcl/rcr: one emitter, because they share both of the things
        # that were wrong with them.
        #
        # They were hard-coded 32-bit: ROL32 on an 8-bit operand rotates bits in
        # from three bytes that are not part of it, and `rcr cl,1` fed the carry
        # in at bit 31, where the write back to CL then dropped it.
        #
        # And they published nothing. A rotate writes CF; the lazy flag triple
        # holds the PREVIOUS instruction's operands, so a following `jae`/`jb`
        # was reading that instruction's carry instead. `sub bx,cx; rcr cl,1;
        # rep movsw; jae` -- the jae asking "was the count odd?" -- is how the
        # Gizmos & Gadgets sprite decoder says it, and it ran off the end of the
        # sprite when the answer came from the sub.
        elif m in ('rol', 'ror', 'rcl', 'rcr'):
            if len(ops) == 2:
                a  = self._fmt_read(ops[0])
                b  = self._fmt_read(ops[1])
                w  = op_bits(ops[0])
                wr = self._fmt_write(ops[0], '_rv')
                mask = '0xFFFFFFFFu' if w == 32 else f'{(1 << w) - 1}u'
                # Through-carry rotates are w+1 bits wide (the carry is the
                # extra bit); the plain ones are w.
                modulo = w + 1 if m in ('rcl', 'rcr') else w
                if m == 'rcr':
                    step = (f"uint32_t _rb = _rv & 1u; "
                            f"_rv = ((_rv >> 1) | (_cf << {w - 1})) & {mask}; _cf = _rb;")
                elif m == 'rcl':
                    step = (f"uint32_t _rb = (_rv >> {w - 1}) & 1u; "
                            f"_rv = ((_rv << 1) | _cf) & {mask}; _cf = _rb;")
                elif m == 'ror':
                    step = (f"uint32_t _rb = _rv & 1u; "
                            f"_rv = ((_rv >> 1) | (_rb << {w - 1})) & {mask}; _cf = _rb;")
                else:  # rol
                    step = (f"uint32_t _rb = (_rv >> {w - 1}) & 1u; "
                            f"_rv = ((_rv << 1) | _rb) & {mask}; _cf = _rb;")
                lines.append(f"{{ uint32_t _rv = ({a}) & {mask}, _rn = (({b}) & 31) % {modulo}u; "
                             f"for (uint32_t _i=0;_i<_rn;_i++){{ {step} }} "
                             f"if (_rn) {{ _flag_a = recomp_eflags_setcf(_flag_k, _flag_a, _flag_b, _cf, _df); "
                             f"_flag_b = 0; _flag_k = FK_EFLAGS; }} {wr}; }} {comment}")
                # Not a compile-time kind: a rotate of zero leaves the previous
                # instruction's flags standing, so the following jcc has to read
                # _flag_k at runtime rather than be told what it is here.
                self._flag_state = None

        # --- Compare / Test (flag setters only, no writeback) ---
        elif m == 'cmp':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(f"/* cmp {a}, {b} */ {comment}")
                lines.append(self._flag_capture(a, b, op_bits(ops[0])))
                # cmp writes CF, and something later reads it. The lazy triple
                # serves the jcc/setcc that ask by condition, but `sbb r, r` and
                # `adc` read the running _cf directly -- and that used to hold
                # whatever an unrelated earlier instruction left there.
                #
                # `cmp; sbb eax,eax` is how the MSVC 6 CRT turns a comparison
                # into -1/0/+1: both memcmp and strcmp end that way, and with a
                # stale carry memcmp called two identical buffers different.
                # MechCommander's config parser is built on those, so it found
                # none of its keys in a file it had read correctly.
                #
                # CMP_B is the borrow at the operand's width, which is exactly
                # CF, and _flag_a/_flag_b are already width-aligned by the
                # capture above.
                lines.append("_cf = (uint32_t)CMP_B(_flag_a, _flag_b);")
                self._flag_state = ('cmp', "_flag_a, _flag_b")
            self._flag_seq += 1

        elif m == 'test':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(f"/* test {a}, {b} */ {comment}")
                lines.append(self._flag_capture(a, b, op_bits(ops[0])))
                lines.append("_cf = 0;")
                self._flag_state = ('test', "_flag_a, _flag_b")

        elif m in ('bt', 'bts', 'btr', 'btc'):
            # A memory operand with a REGISTER bit offset addresses a bit
            # string, not one dword: the dword is at ea + 4*(offset >> 5)
            # (signed). The CRT's strcspn/strpbrk run `bt/bts [esp], eax` over
            # a 256-bit character map, so reading [ea] for every bit got every
            # character above 31 wrong. An immediate offset stays in the dword.
            if len(ops) == 2:
                if ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_REG:
                    off = self._fmt_read(ops[1])
                    base = self._fmt_mem_addr(ops[0].mem)
                    addr = f"(({base}) + (uint32_t)(((int32_t)({off}) >> 5) * 4))"
                    a = f"MEM32({addr})"
                    idx = f"(({off}) & 31)"
                    write = lambda v: f"MEM32({addr}) = {v}"
                else:
                    a = self._fmt_read(ops[0])
                    idx = f"(({self._fmt_read(ops[1])}) & 31)"
                    write = lambda v: self._fmt_write(ops[0], v)
                lines.append(f"/* {m} {a}, {idx} */ {comment}")
                lines.append(self._flag_capture(a, idx))
                self._flag_state = ('bt', "_flag_a, _flag_b")
                if m != 'bt':
                    op = {'bts': '|', 'btr': '& ~', 'btc': '^'}[m]
                    lines.append(f"{write(f'_flag_a {op} (1u << _flag_b)')}; {comment}")

        # --- Setcc ---
        elif m in SETCC_MAP:
            if len(ops) == 1:
                cond = self._make_condition(m)
                lines.append(f"{self._fmt_write(ops[0], f'({cond}) ? 1 : 0')}; {comment}")

        # --- CMOVcc ---
        elif m in CMOVCC_MAP:
            if len(ops) == 2:
                cond = self._make_condition(m)
                src = self._fmt_read(ops[1])
                dst = self._fmt_read(ops[0])
                lines.append(f"if ({cond}) {{ {self._fmt_write(ops[0], src)}; }} {comment}")

        # --- Carry arithmetic ---
        elif m == 'adc':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                # The carry OUT matters as much as the carry in: `add; adc; adc`
                # is how every 64- and 96-bit addition is written, and each adc
                # reads the one before it. Snapshot the operands, write the
                # result, then publish the whole flag word.
                cin = 'recomp_carry(_flag_k, _flag_a, _flag_b, _cf)' if self.precise_carry else '_cf'
                lines.append(f"{{ uint32_t _aa = {a}, _ab = {b}, _ac = {cin}; {comment}")
                lines.append(f"  {self._fmt_write(ops[0], '_aa + _ab + _ac')};")
                lines.append(f"  _flag_a = recomp_flags_adc(_aa, _ab, _ac); _flag_b = 0;")
                lines.append(f"  _flag_k = FK_EFLAGS; _cf = _flag_a & 1u; }}")
                self._flag_state = None

        elif m == 'sbb':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                # sbb reg, reg -> CF ? 0xFFFFFFFF : 0  (common `cmp; sbb r,r` idiom)
                # NOTE: CF here reads the running `_cf` variable, NOT the carry of an
                # immediately-preceding cmp/sub. That is technically imprecise (a real
                # `cmp X,Y; sbb r,r` would see CF=(X<Y)). Synthesizing the precise carry
                # was tried (global, adjacent-only, and sbb-r,r-only variants) and every
                # variant DETERMINISTICALLY broke Fury3's new-game->briefing transition
                # while baseline reaches flight reliably -- a downstream path depends on
                # the current behavior (a compensating imprecision elsewhere). Until a
                # per-site differential trace isolates that path, keep the conservative
                # `_cf`. The one gameplay-affecting case (the cheat reader sub_43BFB0) is
                # handled by a targeted host shim instead. See fury3-target.md Phase 8.
                carry = 'recomp_carry(_flag_k, _flag_a, _flag_b, _cf)' if self.precise_carry else '_cf'
                if ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG and ops[0].reg == ops[1].reg:
                    # With precise_sbb, take the carry from the comparison that
                    # actually set it rather than the running `_cf`. `cmp X, 1;
                    # sbb r, r; neg r` is how compilers write `r = (X == 0)`,
                    # and MGL returns success that way everywhere -- read from a
                    # stale `_cf` the result is arbitrary, so GTA1's display
                    # initialisation reported failure after doing its work
                    # correctly. Off by default: see the note above.
                    if (self.precise_sbb and self._flag_state
                            and self._flag_state[0] in ('cmp', 'sub')):
                        carry = f"(uint32_t)CMP_B({self._flag_state[1]})"
                    value = '_sc ? 0xFFFFFFFFu : 0'
                else:
                    value = '_sa - _sb - _sc'
                # Like adc: the borrow out is what the next sbb of a multi-word
                # subtraction reads, so publish the flags rather than leave the
                # previous instruction's.
                lines.append(f"{{ uint32_t _sa = {a}, _sb = {b}, _sc = {carry}; {comment}")
                lines.append(f"  {self._fmt_write(ops[0], value)};")
                lines.append(f"  _flag_a = recomp_flags_sbb(_sa, _sb, _sc); _flag_b = 0;")
                lines.append(f"  _flag_k = FK_EFLAGS; _cf = _flag_a & 1u; }}")
                self._flag_state = None

        # --- String Operations ---
        # The rep/repne prefix (F3/F2) on movs/stos/lods means "repeat ECX times".
        # For these ops F2 and F3 are EQUIVALENT (the E/NE distinction only matters
        # for cmps/scas). Detect the prefix from the raw bytes so Watcom's
        # F2-prefixed memcpy (repne movsd/movsb) is handled, not just the F3 spelling.
        # capstone is inconsistent: it may fold the prefix into the mnemonic
        # ("repne movsb") or leave a bare "movsd" with the prefix in the bytes.
        # Direction is assumed forward (DF clear), as in any compiled memcpy/memset.
        elif (m.split()[-1] in ('movsb', 'movsd', 'movsw',
                                'stosb', 'stosw', 'stosd',
                                'lodsb', 'lodsw', 'lodsd')
              and insn.bytes
              and next((b for b in insn.bytes
                        if b not in (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3)), 0)
                  in (0xA4, 0xA5, 0xAA, 0xAB, 0xAC, 0xAD)):
            # (the opcode guard excludes SSE movsd/movss, which share the mnemonic
            #  but are 0x0F-escaped, not single-byte string opcodes)
            base = m.split()[-1]
            rep = (' ' in m) or any(b in (0xF2, 0xF3) for b in (insn.bytes[:4] if insn.bytes else ()))
            esz = {'movsb': 1, 'movsw': 2, 'movsd': 4,
                   'stosb': 1, 'stosw': 2, 'stosd': 4,
                   'lodsb': 1, 'lodsw': 2, 'lodsd': 4}[base]
            if base.startswith('movs'):
                if rep:
                    # DF decides the direction, and the rep forms used to ignore
                    # it -- they always copied forward and always incremented.
                    # With `std` set a real CPU walks DOWN from esi/edi, so the
                    # lifted copy read and wrote from the wrong end and ran off
                    # into whatever followed. VFX_pane_copy takes exactly that
                    # path for an overlapping blit, and it smashed the object
                    # sitting after its destination.
                    #
                    # memmove, not memcpy: overlap is the whole reason the
                    # backward form exists.
                    lines.append(
                        f"{{ uint32_t _n = ecx, _b = _n * {esz}u; {comment}"
                        f" if (_df > 0) {{ memmove((void*)ADDR(edi),"
                        f" (void*)ADDR(esi), _b); esi += _b; edi += _b; }}"
                        f" else {{ memmove((void*)ADDR(edi - _b + {esz}u),"
                        f" (void*)ADDR(esi - _b + {esz}u), _b);"
                        f" esi -= _b; edi -= _b; }} ecx = 0; }}")
                elif esz == 1:
                    lines.append(f"MEM8(edi) = MEM8(esi); esi += _df; edi += _df; {comment}")
                elif esz == 2:
                    lines.append(f"MEM16(edi) = MEM16(esi); esi += _df * 2; edi += _df * 2; {comment}")
                else:
                    lines.append(f"MEM32(edi) = MEM32(esi); esi += _df * 4; edi += _df * 4; {comment}")
            elif base.startswith('stos'):
                if rep:
                    # Same direction-flag story as movs. The fill value is
                    # uniform, so only the start address and the pointer update
                    # change -- but they change by the whole span.
                    fill = {1: "memset((void*)ADDR(%s), LO8(eax), _n)",
                            2: "MEMSET16((void*)ADDR(%s), (uint16_t)LO16(eax), _n)",
                            4: "MEMSET32((void*)ADDR(%s), eax, _n)"}[esz]
                    lines.append(
                        f"{{ uint32_t _n = ecx, _b = _n * {esz}u; {comment}"
                        f" if (_df > 0) {{ {fill % 'edi'}; edi += _b; }}"
                        f" else {{ {fill % f'edi - _b + {esz}u'}; edi -= _b; }}"
                        f" ecx = 0; }}")
                elif esz == 1:
                    lines.append(f"MEM8(edi) = LO8(eax); edi += _df; {comment}")
                elif esz == 2:
                    lines.append(f"MEM16(edi) = (uint16_t)LO16(eax); edi += _df * 2; {comment}")
                else:
                    lines.append(f"MEM32(edi) = eax; edi += _df * 4; {comment}")
            else:  # lodsb/lodsw/lodsd
                if esz == 1:
                    lines.append(f"SET_LO8(eax, MEM8(esi)); esi += _df; {comment}")
                elif esz == 2:
                    lines.append(f"SET_LO16(eax, MEM16(esi)); esi += _df * 2; {comment}")
                else:
                    lines.append(f"eax = MEM32(esi); esi += _df * 4; {comment}")

        # --- String compare and scan: cmps/scas, every width, with or without
        # a rep prefix.
        #
        # Only the byte forms existed, so `repe cmpsd` lifted to an empty
        # statement -- and that is the aligned fast path in the MSVC 6 memcmp.
        # memcmp then returned whatever happened to be in eax, so two identical
        # buffers compared as different, and MechCommander's config parser found
        # none of its keys in a file it had read perfectly.
        #
        # Two semantics matter. The count is decremented and the pointers
        # advanced for EVERY element processed, including the one that ends the
        # loop -- a do-while, not a pre-test, or the strlen idiom
        # `repne scasb; not ecx; dec ecx` reports -1 for an empty string. And
        # the flags must reflect the LAST pair compared, because that is what
        # the following jcc asks about.
        elif Lifter._string_cmp_base(insn, m):
            base = Lifter._string_cmp_base(insn, m)
            parts = m.split()
            rep = parts[0] if len(parts) > 1 else ''
            size = {'b': 1, 'w': 2, 'd': 4}[base[-1]]
            mem = {1: 'MEM8', 2: 'MEM16', 4: 'MEM32'}[size]
            step = '_df' if size == 1 else f'(_df * {size})'
            if base.startswith('cmps'):
                load = (f"_a = {mem}(esi); _b = {mem}(edi); "
                        f"esi += {step}; edi += {step};")
            else:
                acc = {1: 'LO8(eax)', 2: 'LO16(eax)', 4: 'eax'}[size]
                load = f"_a = {acc}; _b = {mem}(edi); edi += {step};"
            if rep in ('rep', 'repe', 'repz'):
                stop = '_a != _b'          # repeat while equal
            elif rep in ('repne', 'repnz'):
                stop = '_a == _b'          # repeat while different
            else:
                stop = None
            # CF too, not just the lazy pair: `repe cmpsb; sbb ebx, ebx` (the
            # inlined memcmp sign idiom) reads _cf directly, and without this it
            # read whatever the previous instruction left -- every differing
            # string then compared "greater", and std::map<string> lookups
            # returned the first node for any key.
            if stop is None:
                lines.append(f"{{ uint32_t _a, _b; {load} "
                             f"_flag_a = _a; _flag_b = _b; "
                             f"_cf = (uint32_t)CMP_B(_a, _b); }} {comment}")
                self._flag_state = ('cmp', "_flag_a, _flag_b")
            else:
                # With ECX = 0 nothing is compared and the flags are left as
                # they were -- kind and all -- so the next jcc cannot assume a
                # compare wrote them; it evaluates the lazy state instead.
                # strstr falls out of its search loop on exactly that.
                lines.append(f"if (ecx) {{ uint32_t _a = 0, _b = 0; "
                             f"while (ecx) {{ {load} ecx--; if ({stop}) break; }} "
                             f"_flag_a = _a; _flag_b = _b; "
                             f"_cf = (uint32_t)CMP_B(_a, _b); _flag_k = FK_CMP; }} {comment}")
                self._flag_state = None
            self._flag_seq += 1

        # --- Control Flow ---
        elif m == 'call' and insn.get_branch_target() in self.call_pop:
            # The callee's first instruction pops the return address: a jump
            # that hands over where it came from (get-EIP, or code that patches
            # its caller). Push the real address and jump; there is no return.
            target = insn.get_branch_target()
            lines.append(f"PUSH32(esp, 0x{insn.address + insn.size:08X}u); RECOMP_FLAGS_OUT();"
                         f" RECOMP_ITAIL(0x{target:08X}u); return; {comment}")

        elif m == 'call':
            target = insn.get_branch_target()
            if target:
                # Check IAT (import)
                if target in self.iat_map:
                    dll, fname = self.iat_map[target]
                    lines.append(f"/* call [{dll}]{fname} */")
                    lines.append(f"RECOMP_ICALL(0x{target:08X}u); {comment}")
                elif target in self.func_names:
                    lines.append(f"RECOMP_CALL(recomp_{self.func_names[target]}); {comment}")
                elif self.lifted is not None and target not in self.lifted:
                    lines.append(f"RECOMP_ICALL(0x{target:08X}u); {comment} /* not lifted */")
                else:
                    lines.append(f"RECOMP_CALL(sub_{target:08X}); {comment}")
            else:
                # Indirect call
                if ops and ops[0].type == X86_OP_MEM and self.dos and _is_far_indirect(insn):
                    # call m16:32: CS goes on the stack under the return
                    # address, and the callee's retf takes both off. A DOS
                    # extender's timer and driver callbacks are called this way.
                    addr = self._fmt_mem_addr(ops[0].mem)
                    lines.append(f"PUSH32(esp, _seg_cs); RECOMP_ICALL(MEM32({addr})); {comment}")
                elif ops and ops[0].type == X86_OP_MEM:
                    addr = self._fmt_mem_addr(ops[0].mem)
                    lines.append(f"RECOMP_ICALL(MEM32({addr})); {comment}")
                elif ops and ops[0].type == X86_OP_REG:
                    r = self._fmt_read(ops[0])
                    lines.append(f"RECOMP_ICALL({r}); {comment}")
                else:
                    lines.append(f"RECOMP_ICALL(0); /* unresolved */ {comment}")
            # the callee's flags (see RECOMP_FLAGS_OUT)
            lines.append("RECOMP_FLAGS_IN();")
            self._flag_state = None

        elif m == 'ret' or m == 'retn':
            # Pop the return address that RECOMP_CALL/ICALL pushed (esp += 4), plus
            # any stdcall callee-cleanup bytes (ret N -> esp += 4 + N). Without the
            # +4 the simulated ESP drifts down 4 bytes per call and eventually the
            # 0xDEAD0000 dummy return address gets read as a function argument.
            if self.dos:
                # `push target; ret` is a computed jump, and Watcom's int386x
                # makes one into its table of `int N; ret` stubs. A return
                # address the caller did not push is not ours to pop: it is
                # where control goes, with the stack as it was before the push.
                lines.append(f"if (MEM32(esp) != RECOMP_RETADDR) {{ uint32_t _rt = MEM32(esp); esp += 4;"
                             f" RECOMP_FLAGS_OUT(); RECOMP_RET_JUMP(_rt); return; }}")
            if ops and ops[0].type == X86_OP_IMM:
                n = ops[0].imm
                lines.append(f"RECOMP_FLAGS_OUT(); esp += {4 + n}; return; {comment}")
            else:
                lines.append(f"RECOMP_FLAGS_OUT(); esp += 4; return; {comment}")

        elif m == 'retf':
            if self.dos:
                # Pops EIP and CS (and an immediate's worth): the far call
                # above pushed both. Outside DOS mode nothing pushes a CS.
                n = ops[0].imm if ops and ops[0].type == X86_OP_IMM else 0
                lines.append(f"RECOMP_FLAGS_OUT(); esp += {8 + n}; return; /* far return */ {comment}")
            else:
                lines.append(f"return; /* far return */ {comment}")

        elif m == 'jmp':
            target = insn.get_branch_target()
            if target and self._labels is not None and target not in self._labels:
                # Branch leaves the function: a tail call, or a run of bytes that
                # was never really code. Either way there is no label to jump to,
                # so dispatch and return instead of emitting an undefined goto.
                lines.append(f"RECOMP_ITAIL(0x{target:08X}u); return; {comment}")
            elif target:
                lines.append(f"goto L_{target:08X}; {comment}")
            else:
                # Indirect jump: a switch dispatch, or a tail call through a
                # pointer. C has no computed goto, so branch on the address --
                # arms of a switch land back inside this function and MUST stay
                # here; dispatching them as calls turns a loop into recursion.
                if ops and ops[0].type == X86_OP_MEM:
                    lines.extend(self._computed_jump(
                        f"MEM32({self._fmt_mem_addr(ops[0].mem)})", comment))
                elif ops and ops[0].type == X86_OP_REG:
                    lines.extend(self._computed_jump(self._fmt_read(ops[0]), comment))
                else:
                    lines.append(f"RECOMP_ITAIL(0); return; /* unresolved */ {comment}")

        elif m in COND_MAP:
            target = insn.get_branch_target()
            cond = self._make_condition(m)
            if target and self._labels is not None and target not in self._labels:
                lines.append(f"if ({cond}) {{ RECOMP_ITAIL(0x{target:08X}u); return; }} {comment}")
            elif target:
                lines.append(f"if ({cond}) goto L_{target:08X}; {comment}")
            else:
                lines.append(f"if ({cond}) {{ /* indirect jcc */ }} {comment}")

        # --- x87 FPU ---
        elif m == 'fld':
            if ops:
                if ops[0].type == X86_OP_MEM:
                    if ops[0].size == 4:
                        val = self._fmt_mem_read(ops[0].mem, 4)
                        lines.append(f"fp_push(*(float*)&{val}); {comment}")
                    elif ops[0].size == 8:
                        addr = self._fmt_mem_addr(ops[0].mem)
                        lines.append(f"fp_push(*(double*)ADDR({addr})); {comment}")
                    else:
                        addr = self._fmt_mem_addr(ops[0].mem)
                        lines.append(f"fp_push(fp_ld80((const uint8_t*)ADDR({addr}))); {comment}")
                else:
                    lines.append(f"fp_push(_st[{ops[0].reg - X86_REG_ST0}]); {comment}")  # ST(i) hack

        elif m == 'fild':
            if ops and ops[0].type == X86_OP_MEM:
                if ops[0].size == 2:
                    addr = self._fmt_mem_addr(ops[0].mem)
                    lines.append(f"fp_push((double)(int16_t)MEM16({addr})); {comment}")
                elif ops[0].size == 4:
                    addr = self._fmt_mem_addr(ops[0].mem)
                    lines.append(f"fp_push((double)(int32_t)MEM32({addr})); {comment}")
                else:
                    # Exact: see g_st_i64 in recomp_types.h (fild/fistp qword
                    # is an 8-byte copy, and a double keeps only 53 bits).
                    addr = self._fmt_mem_addr(ops[0].mem)
                    lines.append(f"fp_push_i64((int64_t)MEM64({addr})); {comment}")

        elif m == 'fstp':
            if ops:
                if ops[0].type == X86_OP_MEM:
                    addr = self._fmt_mem_addr(ops[0].mem)
                    if ops[0].size == 4:
                        lines.append(f"{{ float _v = (float)fp_pop(); *(float*)ADDR({addr}) = _v; }} {comment}")
                    elif ops[0].size == 8:
                        lines.append(f"{{ double _v = fp_pop(); *(double*)ADDR({addr}) = _v; }} {comment}")
                    else:
                        lines.append(f"fp_st80((uint8_t*)ADDR({addr}), fp_pop()); {comment}")
                else:
                    # fstp st(i): ST(i) <- ST(0) THEN pop. The copy uses the
                    # pre-pop numbering, so after the pop the written value lands at
                    # st(i-1). Writing `_st[i] = fp_pop()` (pop first, then store) is
                    # off by one -- and for fstp st(0) it wrongly keeps the popped top.
                    i = ops[0].reg - X86_REG_ST0
                    lines.append(f"{{ _st[{i}] = _st[0]; g_st_i64[{i}] = g_st_i64[0]; fp_pop(); }} {comment}")

        elif m == 'fst':
            if ops and ops[0].type == X86_OP_MEM:
                addr = self._fmt_mem_addr(ops[0].mem)
                if ops[0].size == 4:
                    lines.append(f"{{ float _v = (float)_st[0]; *(float*)ADDR({addr}) = _v; }} {comment}")
                elif ops[0].size == 8:
                    lines.append(f"*(double*)ADDR({addr}) = _st[0]; {comment}")

        elif m in ('fistp', 'fist'):
            # Round by the control word (fp_to_int), not by C's truncating cast.
            if ops and ops[0].type == X86_OP_MEM:
                addr = self._fmt_mem_addr(ops[0].mem)
                src = 'fp_pop()' if m == 'fistp' else '_st[0]'
                if ops[0].size == 2:
                    lines.append(f"MEM16({addr}) = (int16_t)fp_to_int({src}); {comment}")
                elif ops[0].size == 4:
                    lines.append(f"MEM32({addr}) = (uint32_t)(int32_t)fp_to_int({src}); {comment}")
                else:
                    pop = ' (void)fp_pop();' if m == 'fistp' else ''
                    lines.append(f"{{ int64_t _q = fp_st0_to_i64(_st[0], g_st_i64[0], _fpu_cw);{pop} "
                                 f"MEM64({addr}) = (uint64_t)_q; }} {comment}")

        elif m == 'fadd':
            if ops:
                lines.append(f"{self._fpu_dst(ops)} += {self._fmt_fpu_src(ops)}; {comment}")
            else:
                lines.append(f"_st[0] += _st[1]; {comment}")

        elif m == 'faddp':
            lines.append(f"{{ double _v = fp_pop(); {self._fpu_popdst(ops)} += _v; }} {comment}")

        elif m == 'fsub':
            if ops:
                lines.append(f"{self._fpu_dst(ops)} -= {self._fmt_fpu_src(ops)}; {comment}")
            else:
                lines.append(f"_st[0] -= _st[1]; {comment}")

        elif m == 'fsubp':
            d = self._fpu_popdst(ops)
            lines.append(f"{{ double _v = fp_pop(); {d} -= _v; }} {comment}")

        elif m == 'fsubr':
            if ops:
                lines.append(f"{self._fpu_dst(ops)} = {self._fmt_fpu_src(ops)} - {self._fpu_dst(ops)}; {comment}")

        elif m == 'fsubrp':
            d = self._fpu_popdst(ops)
            lines.append(f"{{ double _v = fp_pop(); {d} = _v - {d}; }} {comment}")

        elif m == 'fmul':
            if ops:
                lines.append(f"{self._fpu_dst(ops)} *= {self._fmt_fpu_src(ops)}; {comment}")
            else:
                lines.append(f"_st[0] *= _st[1]; {comment}")

        elif m == 'fmulp':
            lines.append(f"{{ double _v = fp_pop(); {self._fpu_popdst(ops)} *= _v; }} {comment}")

        elif m == 'fdiv':
            if ops:
                lines.append(f"{self._fpu_dst(ops)} /= {self._fmt_fpu_src(ops)}; {comment}")
            else:
                lines.append(f"_st[0] /= _st[1]; {comment}")

        elif m == 'fdivp':
            d = self._fpu_popdst(ops)
            lines.append(f"{{ double _v = fp_pop(); {d} = _v == 0.0 ? {d} : {d} / _v; }} {comment}")

        elif m == 'fdivr':
            if ops:
                lines.append(f"{self._fpu_dst(ops)} = {self._fmt_fpu_src(ops)} / {self._fpu_dst(ops)}; {comment}")

        elif m == 'fdivrp':
            d = self._fpu_popdst(ops)
            lines.append(f"{{ double _v = fp_pop(); {d} = {d} == 0.0 ? _v : _v / {d}; }} {comment}")

        elif m == 'fchs':
            lines.append(f"_st[0] = -_st[0]; {comment}")

        elif m == 'fabs':
            lines.append(f"_st[0] = fabs(_st[0]); {comment}")

        elif m in ('fimul', 'fiadd', 'fisub', 'fisubr', 'fidiv', 'fidivr'):
            # The memory operand is a 16- or 32-bit INTEGER, not a float.
            if ops and ops[0].type == X86_OP_MEM:
                addr = self._fmt_mem_addr(ops[0].mem)
                src = (f"(double)(int16_t)MEM16({addr})" if ops[0].size == 2
                       else f"(double)(int32_t)MEM32({addr})")
                op = {'fimul': '*', 'fiadd': '+', 'fisub': '-', 'fidiv': '/'}.get(m)
                if op:
                    lines.append(f"_st[0] = _st[0] {op} {src}; {comment}")
                elif m == 'fisubr':
                    lines.append(f"_st[0] = {src} - _st[0]; {comment}")
                else:
                    lines.append(f"_st[0] = {src} / _st[0]; {comment}")

        elif m == 'fsqrt':
            lines.append(f"_st[0] = sqrt(_st[0]); {comment}")

        elif m == 'fxch':
            # capstone reports fxch st(N) as [st(0), st(N)]; swap st(0) with the
            # OTHER operand (the last one), not st(0) with itself.
            if ops:
                i = ops[-1].reg - X86_REG_ST0
                lines.append(f"fp_xch({i}); {comment}")
            else:
                lines.append(f"fp_xch(1); {comment}")

        # FPU stack-pointer ops. In our fixed-window stack (st[0] is always top),
        # `fincstp; ffree st(7)` is the standard "pop without storing" idiom, so we
        # model fincstp as a discarding pop and ffree as a no-op. fdecstp pushes a
        # slot (rare).
        elif m == 'fincstp':
            lines.append(f"(void)fp_pop(); {comment}")
        elif m == 'fdecstp':
            lines.append(f"fp_push(0.0); {comment}")
        elif m in ('ffree', 'ffreep'):
            lines.append(f"/* {m} (no-op in fixed-window FPU stack) */ {comment}")

        # fucompp is fcompp that does not fault on a quiet NaN; FPU_CMP already
        # reports unordered for a NaN either way. It was unimplemented: the
        # compare never ran (so _fpu_cmp kept its last value) and its two pops
        # never happened, leaking two x87 slots per call. The Movies has 3,244
        # of them; its audio code read every position/length ratio as 1.0.
        elif m in ('fcomip', 'fucomip', 'fcompp', 'fucompp'):
            lines.append(f"_fpu_cmp = FPU_CMP(_st[0], _st[1]); {comment}")
            if m in ('fcompp', 'fucompp'):
                lines.append(f"fp_pop(); fp_pop();")
            else:
                lines.append(f"fp_pop();")
            lines.append("_flag_a = (uint32_t)_fpu_cmp; _flag_b = 0;")
            self._flag_state = ('fcom', '_fpu_cmp')
            self._flag_seq += 1

        elif m in ('fcom', 'fcomp', 'fucom', 'fucomp'):
            if ops:
                src = self._fmt_fpu_src(ops)
                lines.append(f"_fpu_cmp = FPU_CMP(_st[0], {src}); {comment}")
            else:
                lines.append(f"_fpu_cmp = FPU_CMP(_st[0], _st[1]); {comment}")
            if m in ('fcomp', 'fucomp'):
                lines.append(f"fp_pop();")
            lines.append("_flag_a = (uint32_t)_fpu_cmp; _flag_b = 0;")
            self._flag_state = ('fcom', '_fpu_cmp')
            self._flag_seq += 1

        elif m == 'fnstsw' or m == 'fstsw':
            # The x87 status word, built from the last compare.
            #
            # MSVC's float comparison is `fcom*; fnstsw ax; test ah, 0x41; jcc`,
            # and this was a comment -- so `ah` kept whatever happened to be in
            # it. With ah = 0, `test ah, 0x41` always set ZF and the `je` was
            # always taken. In Force Commander that made sub_006AB3B0 -- a
            # convergence loop that subtracts a constant until the value crosses
            # a threshold -- spin forever, and there are 5,369 fnstsw sites in
            # that one binary, every one of them a float comparison branching on
            # a stale register.
            #
            # The `setter == 'fcom'` path below handles the case where the jcc
            # follows the compare directly; it cannot help here, because the
            # intervening `test` legitimately takes over the flag state. The
            # status word has to be real.
            #
            # C0 is bit 8, C2 bit 10, C3 bit 14. With no NaN modelling only the
            # three ordered outcomes arise:
            #     st0 <  src -> C0=1  -> 0x0100, ah = 0x01
            #     st0 == src -> C3=1  -> 0x4000, ah = 0x40
            #     st0 >  src ->       -> 0x0000, ah = 0x00
            # which is exactly what `test ah, 0x41` is written to distinguish.
            # Unordered (a NaN operand) sets C3, C2 and C0 together: 0x4500.
            # Without it a NaN read as "equal" (C3 only), and MSVC's
            # `while (x >= 1.0) x -= 1.0` wrap loop -- which exits on C0 --
            # spun forever on x = NaN in the MxO client's frame loop.
            # An fxam result is carried as 0x10000 | its C3..C0 bits (tested as
            # >= 0x10000: the fcom "less" state is -1, which has bit 16 set) and
            # reported verbatim.
            sw = ("((_fpu_cmp >= 0x10000) ? (uint32_t)(_fpu_cmp & 0x4700) : "
                  "_fpu_cmp == 2 ? 0x4500u : _fpu_cmp < 0 ? 0x0100u : "
                  "_fpu_cmp == 0 ? 0x4000u : 0x0000u)")
            if ops and ops[0].type == X86_OP_REG:
                lines.append(f"eax = (eax & 0xFFFF0000u) | {sw}; {comment}")
            elif ops and ops[0].type == X86_OP_MEM:
                addr = self._fmt_mem_addr(ops[0].mem)
                lines.append(f"MEM16({addr}) = (uint16_t){sw}; {comment}")
            else:
                lines.append(f"eax = (eax & 0xFFFF0000u) | {sw}; {comment}")
            # The flag state is left alone on purpose: `fnstsw` changes no
            # flags, so a following `sahf` (2 sites in Focom.exe) still finds
            # the 'fcom' state and the unsigned jcc after it maps correctly.

        elif m == 'sahf':
            # SF ZF AF PF CF <- ah bits 7 6 4 2 0. This was a comment, so a
            # `jp` after it read the parity of whatever compare came before:
            # the CRT fmod loop `fprem; fnstsw ax; sahf; jp again` in Gunman's
            # gunman.dll then spun forever the moment a map started (the jp
            # saw `cmp [flag], 1` with flag 0: 0xFFFFFFFF, even parity). The
            # fcom idiom is unaffected: fnstsw builds ah from the compare, and
            # decoding ah gives the same answers (and unordered correctly).
            lines.append(f"_flag_a = (eax >> 8) & 0xD5u; _flag_b = 0; "
                         f"_cf = _flag_a & 1u; _flag_k = FK_EFLAGS; {comment}")
            self._flag_state = ('eflags', '_flag_a, _flag_b')
            self._flag_seq += 1

        elif m == 'fxam':
            # Classify st(0) into C3 C2 C0 (+ C1 = sign). It was UNIMPLEMENTED,
            # which only mattered once `sahf` was real: the CRT math functions
            # (fmod, the trig family) classify their arguments with
            # `fxam; fnstsw ax; ... xlatb` and dispatch on the class, and a
            # stale class made Gunman's server fmod return NaN -- then its
            # angle-wrap loop `while (a >= 360) a -= 360` never ended.
            lines.append("{ double _v = _st[0]; uint32_t _c = "
                         "isnan(_v) ? 0x0100u : isinf(_v) ? 0x0500u : _v == 0.0 ? 0x4000u : "
                         "(fabs(_v) < 2.2250738585072014e-308) ? 0x4400u : 0x0400u; "
                         "if (signbit(_v)) _c |= 0x0200u; _fpu_cmp = (int)(0x10000u | _c); } "
                         f"{comment}")

        elif m == 'xlatb' or m == 'xlat':
            lines.append(f"SET_LO8(eax, MEM8(ebx + LO8(eax))); {comment}")

        elif m == 'ftst':
            # Compare ST(0) with 0.0. Same -1/0/1 convention as fcom, which is
            # what the flag-consumer path already reads.
            lines.append(f"_fpu_cmp = FPU_CMP(_st[0], 0.0); {comment}")
            self._flag_state = ('fcom', '_fpu_cmp')
            self._flag_seq += 1

        elif m == 'fldl2e':
            lines.append(f"fp_push(1.4426950408889634); /* log2(e) */ {comment}")

        elif m == 'fldl2t':
            lines.append(f"fp_push(3.321928094887362); /* log2(10) */ {comment}")

        elif m == 'fldln2':
            lines.append(f"fp_push(0.6931471805599453); /* ln(2) */ {comment}")

        elif m == 'fldlg2':
            lines.append(f"fp_push(0.30102999566398120); /* log10(2) */ {comment}")

        elif m == 'fyl2x':
            # st(1) = st(1) * log2(st(0)), then pop. The pair with fldl2e/f2xm1
            # is how an x87 build computes pow().
            lines.append(f"{{ double _x = fp_pop(); _st[0] *= log(_x) / 0.6931471805599453; }} {comment}")

        elif m == 'fyl2xp1':
            lines.append(f"{{ double _x = fp_pop(); _st[0] *= log(_x + 1.0) / 0.6931471805599453; }} {comment}")

        elif m == 'f2xm1':
            lines.append(f"_st[0] = pow(2.0, _st[0]) - 1.0; {comment}")

        elif m == 'fptan':
            # tan into ST(0), then push 1.0 -- the 8087 leaves a ratio behind.
            lines.append(f"_st[0] = tan(_st[0]); fp_push(1.0); _fpu_cmp = 1; {comment}")

        elif m == 'fpatan':
            lines.append(f"{{ double _x = fp_pop(); _st[0] = atan2(_st[0], _x); }} {comment}")

        elif m == 'fprem' or m == 'fprem1':
            # One fmod is the WHOLE reduction, so C2 ("incomplete, go again")
            # must read clear: fnstsw builds the status word from _fpu_cmp,
            # and 1 is the state whose word has C2 = 0. Code after fprem only
            # tests C2; C0/C1/C3 hold quotient bits nothing here reads.
            lines.append(f"_st[0] = fmod(_st[0], _st[1]); _fpu_cmp = 1; {comment}")

        elif m == 'fscale':
            lines.append(f"_st[0] *= pow(2.0, (double)(int)_st[1]); {comment}")

        elif m == 'fnclex' or m == 'fclex':
            lines.append(f"/* fclex: no exception state modelled */ {comment}")

        elif m == 'fnsave' or m == 'fsave' or m == 'frstor':
            # The register file is ours, not a 108-byte x87 image; a save/restore
            # pair round-trips through memory we never interpret, so as long as
            # both sides are no-ops the stack is exactly where it was.
            lines.append(f"/* {m}: FPU state is not a memory image here */ {comment}")

        elif m == 'fld1':
            lines.append(f"fp_push(1.0); {comment}")

        elif m == 'fldz':
            lines.append(f"fp_push(0.0); {comment}")

        elif m == 'fldpi':
            lines.append(f"fp_push(3.14159265358979323846); {comment}")

        # The trig ops clear C2 ("in range": the host's sin reduces any
        # argument). The CRT tests it -- `fsin; fnstsw ax; sahf; jp reduce` --
        # and a C2 left over from its own fxam sent every call down the
        # reduction path. _fpu_cmp = 1 is the status word with C2 clear.
        elif m == 'fsin':
            lines.append(f"_st[0] = sin(_st[0]); _fpu_cmp = 1; {comment}")

        elif m == 'fcos':
            lines.append(f"_st[0] = cos(_st[0]); _fpu_cmp = 1; {comment}")

        elif m == 'fsincos':
            lines.append(f"{{ double _a = _st[0]; _st[0] = cos(_a); fp_push(sin(_a)); }} _fpu_cmp = 1; {comment}")

        elif m == 'fpatan':
            lines.append(f"{{ double _v = fp_pop(); _st[0] = atan2(_v, _st[0]); }} {comment}")

        elif m == 'f2xm1':
            lines.append(f"_st[0] = pow(2.0, _st[0]) - 1.0; {comment}")

        elif m == 'fscale':
            lines.append(f"_st[0] = _st[0] * pow(2.0, (int)_st[1]); {comment}")

        elif m == 'frndint':
            # Round by the control word, like fist. `(double)(int)x` always
            # truncated (and overflowed past 2^31), so the CRT's floor/ceil --
            # `fldcw` down/up, `frndint`, `fldcw` back -- both truncated:
            # ceil(0.3) came out 0, and Gunman's engine computed zero-sized
            # surface extents at map load ("D_SCAlloc: bad cache size 0").
            lines.append(f"_st[0] = fp_round_cw(_st[0], _fpu_cw); /* frndint */ {comment}")

        # --- SSE scalar float ---
        elif m == 'movss':
            if len(ops) == 2:
                lines.append(f"/* {m} */ {comment}")  # TODO: XMM support
                lines.append(f"/* SSE movss not yet implemented */")

        # --- Misc ---
        elif m == 'nop' or m.startswith('nop'):
            lines.append(f"/* nop */ {comment}")

        elif m == 'int3':
            # int3 is a trap, so nothing reaches the byte after it. Returning
            # says so, and it matters: a body can continue past a padding run
            # (see linear_disassemble_function's resume), and without this the
            # unreachable fallthrough would run the next block's code.
            lines.append(f"/* int3 breakpoint */ return; {comment}")

        elif m == 'cdq':
            lines.append(f"edx = ((int32_t)eax < 0) ? 0xFFFFFFFFu : 0; {comment}")

        elif m == 'cwde':
            lines.append(f"eax = (uint32_t)(int32_t)(int16_t)LO16(eax); {comment}")

        elif m == 'cwd':
            lines.append(f"edx = ((int16_t)LO16(eax) < 0) ? 0xFFFFu : 0; {comment}")

        elif m == 'cbw':
            lines.append(f"SET_LO16(eax, (uint16_t)(int16_t)(int8_t)LO8(eax)); {comment}")

        elif m == 'cld':
            lines.append(f"_df = 1; {comment}")

        elif m == 'std':
            lines.append(f"_df = -1; {comment}")

        # clc/stc/cmc write CF and nothing else -- and they have to SAY so, or
        # the branch that reads the carry reads the last arithmetic instruction's
        # instead. Borland's strcpy and strcat are one routine with two entry
        # points, `clc` at one and `stc` at the other, and a single `jb` deciding
        # whether to scan for the end of the destination first. With the carry
        # unpublished, strcpy ran as strcat: Treasure MathStorm built every data
        # file's path on the end of the previous one and could open none of them.
        elif m in ('clc', 'stc', 'cmc'):
            # cmc has to read the carry before it can complement it, and `_cf`
            # is not where it lives: a cmp writes the lazy tuple and never
            # touches _cf, so `_cf = !_cf` complements a carry from some earlier
            # instruction. Derive the real one first.
            if m == 'cmc':
                set_cf = ("_cf = !(recomp_eflags(_flag_k, _flag_a, _flag_b, _cf, _df) & 1u);")
            else:
                set_cf = '_cf = 0;' if m == 'clc' else '_cf = 1;'
            lines.append(f"{{ {set_cf} _flag_a = recomp_eflags_setcf(_flag_k, _flag_a, _flag_b, _cf, _df); "
                         f"_flag_b = 0; _flag_k = FK_EFLAGS; }} {comment}")
            self._flag_state = None

        elif m == 'leave':
            lines.append(f"esp = ebp; ebp = POP32_VAL(esp); {comment}")

        elif m == 'enter':
            if len(ops) >= 2:
                size = self._fmt_read(ops[0])
                lines.append(f"PUSH32(esp, ebp); ebp = esp; esp -= {size}; {comment}")

        elif m == 'cpuid':
            lines.append(f"CPUID(eax, ebx, ecx, edx); {comment}")

        elif m == 'rdtsc':
            lines.append(f"{{ uint64_t _t = __rdtsc(); eax = (uint32_t)_t; edx = (uint32_t)(_t >> 32); }} {comment}")

        elif m in ('jecxz', 'jcxz'):
            t = ops[0].imm if ops and ops[0].type == X86_OP_IMM else None
            reg = 'ecx' if m == 'jecxz' else 'LO16(ecx)'
            if t is not None:
                lines.append(f"if ({reg} == 0) goto L_{t:08X}; {comment}")

        elif m in ('loop', 'loope', 'loopne'):
            t = ops[0].imm if ops and ops[0].type == X86_OP_IMM else None
            extra = {'loop': '', 'loope': ' && _cf == 0', 'loopne': ' && _cf == 0'}[m]
            if t is not None:
                lines.append(f"if (--ecx != 0{extra}) goto L_{t:08X}; {comment}")

        elif m == 'scasd':
            lines.append(f"_flag_a = eax; _flag_b = MEM32(edi); _flag_k = FK_CMP; "
                         f"edi += _df * 4; {comment}")
            self._flag_state = ('cmp', '_flag_a, _flag_b')
            self._flag_seq += 1

        elif m in ('les', 'lds', 'lfs', 'lgs', 'lss'):
            # Flat model: the offset is the whole address; the selector is kept
            # only so code that saves and restores it round-trips.
            if len(ops) >= 2 and ops[1].type == X86_OP_MEM:
                addr = self._fmt_mem_addr(ops[1].mem)
                seg = {'les': X86_REG_ES, 'lfs': X86_REG_FS, 'lgs': X86_REG_GS}.get(m)
                if self.dos and seg:
                    lines.append(f"recomp_set_seg({DOS_SEG_IDX[seg]}, MEM16({addr} + 4)); "
                                 f"{self._fmt_write(ops[0], f'MEM32({addr})')}; {comment}")
                else:
                    lines.append(f"{self._fmt_write(ops[0], f'MEM32({addr})')}; "
                                 f"_seg_{m[1:]} = MEM16({addr} + 4); {comment}")

        elif self.dos and (m.split()[-1] in DOS_OPS):
            lines.extend(self._lift_dos(insn, m.split()[-1], ops, comment))

        elif m == 'out' or m == 'outsb' or m == 'outsd' or m == 'in':
            lines.append(f"/* {m}: no port I/O under Win32 */ {comment}")

        elif m == 'wait' or m == 'fwait':
            lines.append(f"/* fwait */ {comment}")

        elif m == 'fnstcw' or m == 'fstcw':
            if ops and ops[0].type == X86_OP_MEM:
                addr = self._fmt_mem_addr(ops[0].mem)
                lines.append(f"MEM16({addr}) = _fpu_cw; {comment}")

        elif m == 'fldcw':
            if ops and ops[0].type == X86_OP_MEM:
                addr = self._fmt_mem_addr(ops[0].mem)
                lines.append(f"_fpu_cw = MEM16({addr}); {comment}")

        elif m == 'fninit' or m == 'finit':
            lines.append(f"/* finit */ {comment}")

        elif m in MMX_BINOPS:
            expr = MMX_BINOPS[m].format(a=self._mm_read(ops[0]), b=self._mm_read(ops[1]))
            lines.append(f"{self._mm_write(ops[0], expr)}; {comment}")

        elif m in MMX_SHIFTS:
            expr = f"{MMX_SHIFTS[m]}({self._mm_read(ops[0])}, {self._mm_count(ops[1])})"
            lines.append(f"{self._mm_write(ops[0], expr)}; {comment}")

        elif m in ('movq', 'movntq'):
            # movntq is movq to memory with a non-temporal hint: the store
            # itself is the same, and the hint means nothing to lifted code.
            lines.append(f"{self._mm_write(ops[0], self._mm_read(ops[1]))}; {comment}")

        elif m in ('sfence', 'lfence', 'mfence') or m.startswith('prefetch'):
            # Ordering and cache hints. The lifted code runs on one thread's
            # view of plain memory, so there is nothing for them to do.
            lines.append(f"/* {m} */ {comment}")

        elif m == 'movd':
            # 32 bits between an MMX register and a GPR or memory, zero-extended
            # on the way in and truncated on the way out.
            if ops[0].type == X86_OP_REG and ops[0].reg in MMX_REGS:
                src = self._fmt_read(ops[1])
                lines.append(f"_mm[{MMX_REGS[ops[0].reg]}] = (uint64_t)(uint32_t)({src}); {comment}")
            else:
                lines.append(f"{self._fmt_write(ops[0], f'(uint32_t){self._mm_read(ops[1])}')}; {comment}")

        elif m == 'emms':
            # We keep the MMX registers separate from the x87 stack, so there is
            # no aliasing to undo. See the register file in the runtime header.
            lines.append(f"/* emms */ {comment}")

        else:
            # A null statement, not a bare comment: this may be the only thing
            # after a label, and C requires a label to be followed by a statement.
            lines.append(f"; /* UNIMPLEMENTED: {insn.mnemonic} {insn.op_str} */ {comment}")

        return lines

    def _lift_dos(self, insn, m, ops, comment) -> list:
        """The instructions a DOS-extender program uses and Win32 code never does.

        Each becomes a call into the host (see runtime/dos32/dos32.h): `int n`
        is the whole DOS/DPMI/BIOS surface, in/out reach the emulated VGA,
        timer, keyboard and sound ports, and cli/sti/hlt tell the host when an
        IRQ may be delivered. Registers and flags are published around `int`
        so the handler reads and writes the guest state directly, and it hands
        back EFLAGS (CF is how DOS reports failure).
        """
        lines = []
        if m == 'int':
            n = ops[0].imm & 0xFF
            lines.append(f"RECOMP_FLAGS_OUT(); RECOMP_REGS_OUT(); recomp_int({n:#04x});"
                         f" RECOMP_REGS_IN(); RECOMP_FLAGS_IN(); {comment}")
            self._flag_state = None
        elif m == 'iretd':
            # The host delivers an IRQ by pushing EFLAGS, CS and the dummy
            # return address, as the CPU would, and calling the handler.
            lines.append(f"RECOMP_FLAGS_OUT(); esp += 12; return; {comment}")
        elif m in ('in', 'out'):
            data, port = (ops[0], ops[1]) if m == 'in' else (ops[1], ops[0])
            bits = op_bits(data)
            p = f"{port.imm & 0xFFFF}u" if port.type == X86_OP_IMM else "(edx & 0xFFFFu)"
            if m == 'in':
                lines.append(f"{self._fmt_write(data, f'recomp_in{bits}({p})')}; {comment}")
            else:
                lines.append(f"recomp_out{bits}({p}, {self._fmt_read(data)}); {comment}")
        elif m in ('insb', 'insw', 'insd', 'outsb', 'outsw', 'outsd'):
            esz = {'b': 1, 'w': 2, 'd': 4}[m[-1]]
            rep = any(b in (0xF2, 0xF3) for b in bytes(insn.bytes[:4]))
            n = 'ecx' if rep else '1u'
            if m.startswith('ins'):
                lines.append(f"recomp_ins(edx & 0xFFFFu, edi, {esz}, {n}, _df); edi += _df * {esz} * {n};"
                             f"{' ecx = 0;' if rep else ''} {comment}")
            else:
                lines.append(f"recomp_outs(edx & 0xFFFFu, esi, {esz}, {n}, _df); esi += _df * {esz} * {n};"
                             f"{' ecx = 0;' if rep else ''} {comment}")
        elif m == 'cli':
            lines.append(f"recomp_cli(); {comment}")
        elif m == 'sti':
            lines.append(f"recomp_sti(); {comment}")
        elif m == 'hlt':
            lines.append(f"RECOMP_REGS_OUT(); recomp_hlt(); RECOMP_REGS_IN(); {comment}")
        return lines

    def _fmt_fpu_src(self, ops) -> str:
        """Format an FPU source operand."""
        if not ops:
            return "_st[1]"
        op = ops[0] if len(ops) == 1 else ops[1] if len(ops) > 1 else ops[0]
        if op.type == X86_OP_MEM:
            addr = self._fmt_mem_addr(op.mem)
            if op.size == 4:
                return f"(double)*(float*)ADDR({addr})"
            elif op.size == 8:
                return f"*(double*)ADDR({addr})"
            return f"(double)MEM32({addr})"
        elif op.type == X86_OP_REG:
            # ST(i) register
            return f"_st[{op.reg - X86_REG_ST0}]"
        return "_st[1]"

    def _fpu_popdst(self, ops) -> str:
        """Destination of `fOPp st(i), st(0)`.

        These compute into ST(i) and then pop, so the result ends up in st(i-1)
        once the stack has shifted. The index is not decoration: POD's hand
        written fixed-point helpers use `fmulp st(5)` and `fsubp st(3)`, and
        treating every one of them as st(1) silently computes with the wrong
        registers. Capstone gives the destination as the single operand.
        """
        i = 1
        if ops and ops[0].type == X86_OP_REG and X86_REG_ST0 <= ops[0].reg <= X86_REG_ST0 + 7:
            i = ops[0].reg - X86_REG_ST0
        return f"_st[{i - 1 if i else 0}]"

    def _fpu_dst(self, ops) -> str:
        """Destination lvalue for an FPU arithmetic insn. For `OP st(i), st(0)`
        (capstone gives [st(i), st(0)]) the destination is st(i), NOT st(0); for
        `OP st(i)` / `OP mem` it is the implicit st(0)."""
        if len(ops) >= 2 and ops[0].type == X86_OP_REG:
            return f"_st[{ops[0].reg - X86_REG_ST0}]"
        return "_st[0]"

    def lift_basic_block(self, block) -> list:
        """Lift an entire basic block to C code."""
        lines = []
        lines.append(f"L_{block.start:08X}:")

        emitted = 0
        for insn in block.instructions:
            lifted = self.lift_instruction(insn)
            for line in lifted:
                lines.append(f"    {line}")
                if not line.lstrip().startswith('/*'):
                    emitted += 1

        # A C label has to be followed by a statement, and some instructions
        # lift to nothing but a comment -- `int3` is the common one. A function
        # that is only padding then generates `L_x: /* int3 */ }`, which does
        # not compile. GTA1 never hit this; London has int3 padding that the
        # data scan picks up as function starts.
        if not emitted:
            lines.append("    ;")

        return lines

    def _computed_jump(self, expr: str, comment: str) -> list:
        """Emit an indirect jump: goto for targets inside this function, tail
        dispatch for anything else."""
        # Only the arms this function's switches actually dispatch to. Listing
        # every label instead is correct but quadratic: one 500-function file
        # went from 5 MB to 20 MB and crashed the compiler outright.
        arms = sorted((self._jump_targets or set()) & (self._labels or set()))
        if not arms:
            return [f"RECOMP_ITAIL({expr}); return; {comment}"]
        lines = [f"{{ uint32_t _jt = {expr}; {comment}", "switch (_jt) {"]
        for label in arms:
            lines.append(f"case 0x{label:08X}u: goto L_{label:08X};")
        lines.append("default: RECOMP_ITAIL(_jt); return;")
        lines.append("} }")
        return lines

    def lift_function(self, func) -> str:
        """Lift an entire function to C code."""
        lines = []
        name = func.name

        lines.append(f"void {name}(void) {{")
        lines.append(f"    int _fpu_cmp = 0;")
        lines.append(f"    uint32_t _cf = 0;  /* carry flag */")
        lines.append(f"    int _df = 1;  /* direction flag (1=forward, -1=backward) */")
        lines.append(f"    uint32_t _flag_a = 0, _flag_b = 0;  /* flag-operand snapshots */")
        lines.append(f"    uint32_t _flag_k = FK_NONE;  /* which instruction wrote them */")
        lines.append(f"    /* _st[8]/_fp_top/_fpu_cw are GLOBAL (shared x87 stack) */")
        # Records the VA of the function currently running, so a crash names it.
        # A plain global store; the ring-buffer half only exists under -DRECOMP_TRACE.
        lines.append(f"    RECOMP_ENTER(0x{func.address:08X}u);")
        lines.append(f"")

        # Emit blocks in address order
        self._labels = set(func.blocks.keys())
        self._jump_targets = set(getattr(func, 'jump_targets', ()) or ())
        sorted_addrs = sorted(func.blocks.keys())
        # Blocks are emitted lowest-address-first, but the entry is not always
        # the lowest: a function sharing a body with one below it (a jump-table
        # arm, a shared tail) would otherwise start executing in the wrong
        # block and run code that was never called.
        if sorted_addrs and sorted_addrs[0] != func.address and func.address in self._labels:
            lines.append(f"    goto L_{func.address:08X};")
            lines.append("")
        # A block reached only by falling through a conditional jump still has
        # the flags the compare set -- a jcc does not touch them. MSVC leans on
        # this constantly (jg/jl/jae chains off one `test` for 64-bit compares),
        # and resetting at every block start turned the second jcc of every such
        # chain into a read of a stale _cf.
        targeted = set()
        for b in func.blocks.values():
            for insn in b.instructions:
                if insn.mnemonic.startswith('j') or insn.mnemonic.startswith('loop'):
                    op = insn.op_str.strip()
                    if op.startswith('0x'):
                        try:
                            targeted.add(int(op, 16))
                        except ValueError:
                            pass

        prev_end = None
        prev_was_jcc = False
        for addr in sorted_addrs:
            block = func.blocks[addr]
            carry = (prev_was_jcc and prev_end == addr and addr not in targeted)
            if not carry:
                self._flag_state = None
            last = block.instructions[-1] if block.instructions else None
            prev_was_jcc = bool(last and last.mnemonic.startswith('j')
                                and last.mnemonic not in ('jmp',))
            prev_end = (last.address + last.size) if last else None
            block_lines = self.lift_basic_block(block)
            lines.extend(block_lines)
            lines.append("")

        lines.append("}")
        return '\n'.join(lines)

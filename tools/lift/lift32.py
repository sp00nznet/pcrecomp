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
)


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

# Setcc follows same pattern
SETCC_MAP = {f'set{k[1:]}': v for k, v in COND_MAP.items()}

# CMOVcc follows same pattern
CMOVCC_MAP = {f'cmov{k[1:]}': v for k, v in COND_MAP.items()}


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
    if 224 <= reg_id <= 231:
        return f"_st[{reg_id - 224}]"
    # Segment registers (flat mode - effectively no-ops)
    # CS=11, DS=17, ES=28, FS=29, GS=30, SS=49
    seg_names = {11: '_seg_cs', 17: '_seg_ds', 28: '_seg_es', 29: '_seg_fs', 30: '_seg_gs', 49: '_seg_ss'}
    if reg_id in seg_names:
        return seg_names[reg_id]
    return f"0 /* unknown reg {reg_id} */"


def is_16bit_reg(reg_id: int) -> bool:
    return reg_id in REG_NAMES_16

def is_8bit_lo(reg_id: int) -> bool:
    return reg_id in REG_NAMES_8L

def is_8bit_hi(reg_id: int) -> bool:
    return reg_id in REG_NAMES_8H


class Lifter:
    """Lifts x86 instructions to C code using a global register model."""

    def __init__(self, iat_map: dict = None, func_names: dict = None):
        """
        iat_map: VA -> (dll, func_name) for import resolution
        func_names: VA -> name for known function names
        """
        self.iat_map = iat_map or {}
        self.func_names = func_names or {}
        self._flag_state = None  # (setter_mnemonic, operands_str)
        self._fp_depth = 0  # FPU stack depth tracking

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
            val = op.imm & 0xFFFFFFFF
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
            if 224 <= r <= 231:
                return f"_st[{r - 224}] = {value}"
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
        if mem.disp != 0:
            if mem.disp > 0:
                parts.append(f"0x{mem.disp:X}")
            else:
                parts.append(f"(-0x{-mem.disp:X})")
        if not parts:
            parts.append("0")
        return ' + '.join(parts)

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

        if self._flag_state is None:
            return f"/* no flag state for {mnem} */ _cf"

        setter, ops = self._flag_state

        if setter == 'cmp':
            return f"{cmp_macro}({ops})"
        elif setter == 'test':
            if test_macro:
                return f"{test_macro}({ops})"
            else:
                # Fall back to cmp-style for conditions that test doesn't directly support
                return f"{cmp_macro}({ops})"
        elif setter in ('sub', 'add'):
            # Result-based condition
            return f"/* {setter} result */ {cmp_macro}({ops})"
        elif setter in ('and', 'or', 'xor'):
            # Logical ops clear CF, set ZF/SF based on result
            if test_macro:
                return f"/* {setter} result */ {test_macro}({ops})"
            return f"/* {setter} result */ {cmp_macro}({ops})"
        elif setter in ('dec', 'inc'):
            return f"/* {setter} result */ {cmp_macro}({ops})"
        elif setter == 'bt':
            # BT sets CF = bit tested
            if cmp_macro in ('CMP_B', 'CMP_AE'):  # jb/jae test CF
                return f"BT_CF({ops})"
            return f"/* bt */ {cmp_macro}({ops})"
        else:
            return f"/* flag from {setter} */ {cmp_macro}({ops})"

    def lift_instruction(self, insn) -> list:
        """
        Lift a single x86 instruction to C statement(s).
        Returns a list of C code strings.
        """
        m = insn.mnemonic
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
        elif m == 'push':
            if len(ops) == 1:
                val = self._fmt_read(ops[0])
                lines.append(f"PUSH32(esp, {val}); {comment}")

        elif m == 'pop':
            if len(ops) == 1:
                lines.append(f"POP32(esp, {self._fmt_read(ops[0])}); {comment}")
                # For pop to register, need assignment form
                if ops[0].type == X86_OP_REG:
                    r = reg_name(ops[0].reg)
                    lines[-1] = f"{r} = POP32_VAL(esp); {comment}"

        elif m == 'pushad':
            lines.append(f"PUSHAD(); {comment}")

        elif m == 'popad':
            lines.append(f"POPAD(); {comment}")

        elif m == 'pushfd':
            lines.append(f"PUSH32(esp, 0); /* pushfd - flags not tracked */ {comment}")

        elif m == 'popfd':
            lines.append(f"(void)POP32_VAL(esp); /* popfd - flags not tracked */ {comment}")

        # --- Arithmetic ---
        elif m == 'add':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(f"{self._fmt_write(ops[0], f'{a} + {b}')}; {comment}")
                self._flag_state = ('add', f"{a}, {b}")

        elif m == 'sub':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(f"{self._fmt_write(ops[0], f'{a} - {b}')}; {comment}")
                self._flag_state = ('sub', f"{a}, {b}")

        elif m == 'inc':
            if len(ops) == 1:
                a = self._fmt_read(ops[0])
                lines.append(f"{self._fmt_write(ops[0], f'{a} + 1')}; {comment}")
                self._flag_state = ('inc', f"{a}, 1")

        elif m == 'dec':
            if len(ops) == 1:
                a = self._fmt_read(ops[0])
                lines.append(f"{self._fmt_write(ops[0], f'{a} - 1')}; {comment}")
                self._flag_state = ('dec', f"{a}, 1")

        elif m == 'neg':
            if len(ops) == 1:
                a = self._fmt_read(ops[0])
                lines.append(f"{self._fmt_write(ops[0], f'(uint32_t)(-(int32_t){a})')}; {comment}")
                self._flag_state = ('sub', f"0, {a}")

        elif m == 'not':
            if len(ops) == 1:
                a = self._fmt_read(ops[0])
                lines.append(f"{self._fmt_write(ops[0], f'~{a}')}; {comment}")

        elif m == 'imul':
            if len(ops) == 1:
                # One-operand: edx:eax = eax * ops[0]
                a = self._fmt_read(ops[0])
                lines.append(f"{{ int64_t _r = (int64_t)(int32_t)eax * (int64_t)(int32_t){a}; {comment}")
                lines.append(f"  eax = (uint32_t)_r; edx = (uint32_t)(_r >> 32); }}")
            elif len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(f"{self._fmt_write(ops[0], f'(uint32_t)((int32_t){a} * (int32_t){b})')}; {comment}")
            elif len(ops) == 3:
                b = self._fmt_read(ops[1])
                c = self._fmt_read(ops[2])
                lines.append(f"{self._fmt_write(ops[0], f'(uint32_t)((int32_t){b} * (int32_t){c})')}; {comment}")

        elif m == 'mul':
            if len(ops) == 1:
                a = self._fmt_read(ops[0])
                lines.append(f"{{ uint64_t _r = (uint64_t)eax * (uint64_t){a}; {comment}")
                lines.append(f"  eax = (uint32_t)_r; edx = (uint32_t)(_r >> 32); }}")

        elif m in ('div', 'idiv'):
            if len(ops) == 1:
                divisor = self._fmt_read(ops[0])
                if m == 'div':
                    lines.append(f"{{ uint64_t _dividend = ((uint64_t)edx << 32) | eax; {comment}")
                    lines.append(f"  eax = (uint32_t)(_dividend / (uint32_t){divisor});")
                    lines.append(f"  edx = (uint32_t)(_dividend % (uint32_t){divisor}); }}")
                else:
                    lines.append(f"{{ int64_t _dividend = ((int64_t)(int32_t)edx << 32) | eax; {comment}")
                    lines.append(f"  eax = (uint32_t)((int32_t)(_dividend / (int32_t){divisor}));")
                    lines.append(f"  edx = (uint32_t)((int32_t)(_dividend % (int32_t){divisor})); }}")

        # --- Logical ---
        elif m == 'and':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(f"{self._fmt_write(ops[0], f'{a} & {b}')}; {comment}")
                self._flag_state = ('and', f"{a}, {b}")

        elif m == 'or':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(f"{self._fmt_write(ops[0], f'{a} | {b}')}; {comment}")
                self._flag_state = ('or', f"{a}, {b}")

        elif m == 'xor':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                # Detect xor reg, reg (zero idiom)
                if ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG and ops[0].reg == ops[1].reg:
                    lines.append(f"{self._fmt_write(ops[0], '0')}; {comment}")
                else:
                    lines.append(f"{self._fmt_write(ops[0], f'{a} ^ {b}')}; {comment}")
                self._flag_state = ('xor', f"{a}, {b}")

        # --- Shifts ---
        elif m == 'shl' or m == 'sal':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(f"{self._fmt_write(ops[0], f'{a} << {b}')}; {comment}")

        elif m == 'shr':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(f"{self._fmt_write(ops[0], f'{a} >> {b}')}; {comment}")

        elif m == 'sar':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(f"{self._fmt_write(ops[0], f'(uint32_t)((int32_t){a} >> {b})')}; {comment}")

        elif m == 'rol':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(f"{self._fmt_write(ops[0], f'ROL32({a}, {b})')}; {comment}")

        elif m == 'ror':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(f"{self._fmt_write(ops[0], f'ROR32({a}, {b})')}; {comment}")

        # --- Compare / Test (flag setters only, no writeback) ---
        elif m == 'cmp':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(f"/* cmp {a}, {b} */ {comment}")
                self._flag_state = ('cmp', f"{a}, {b}")

        elif m == 'test':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(f"/* test {a}, {b} */ {comment}")
                self._flag_state = ('test', f"{a}, {b}")

        elif m == 'bt':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(f"/* bt {a}, {b} */ {comment}")
                self._flag_state = ('bt', f"{a}, {b}")

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
                lines.append(f"{self._fmt_write(ops[0], f'{a} + {b} + _cf')}; {comment}")

        elif m == 'sbb':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                # sbb reg, reg -> _cf ? 0xFFFFFFFF : 0
                if ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG and ops[0].reg == ops[1].reg:
                    lines.append(f"{self._fmt_write(ops[0], '_cf ? 0xFFFFFFFFu : 0')}; {comment}")
                else:
                    lines.append(f"{self._fmt_write(ops[0], f'{a} - {b} - _cf')}; {comment}")

        # --- String Operations ---
        elif m == 'rep movsb':
            lines.append(f"memcpy((void*)ADDR(edi), (void*)ADDR(esi), ecx); {comment}")
            lines.append(f"esi += ecx; edi += ecx; ecx = 0;")

        elif m == 'rep movsd':
            lines.append(f"memcpy((void*)ADDR(edi), (void*)ADDR(esi), ecx * 4); {comment}")
            lines.append(f"esi += ecx * 4; edi += ecx * 4; ecx = 0;")

        elif m == 'rep stosb':
            lines.append(f"memset((void*)ADDR(edi), LO8(eax), ecx); {comment}")
            lines.append(f"edi += ecx; ecx = 0;")

        elif m == 'rep stosd':
            lines.append(f"MEMSET32((void*)ADDR(edi), eax, ecx); {comment}")
            lines.append(f"edi += ecx * 4; ecx = 0;")

        elif m == 'movsb':
            lines.append(f"MEM8(edi) = MEM8(esi); esi += _df; edi += _df; {comment}")

        elif m == 'movsd':
            lines.append(f"MEM32(edi) = MEM32(esi); esi += _df * 4; edi += _df * 4; {comment}")

        elif m == 'stosb':
            lines.append(f"MEM8(edi) = LO8(eax); edi += _df; {comment}")

        elif m == 'stosd':
            lines.append(f"MEM32(edi) = eax; edi += _df * 4; {comment}")

        elif m == 'lodsb':
            lines.append(f"SET_LO8(eax, MEM8(esi)); esi += _df; {comment}")

        elif m == 'lodsd':
            lines.append(f"eax = MEM32(esi); esi += _df * 4; {comment}")

        elif m == 'scasb':
            lines.append(f"/* scasb */ _cf = (LO8(eax) < MEM8(edi)); edi += _df; {comment}")
            self._flag_state = ('cmp', f"LO8(eax), MEM8(edi)")

        elif m in ('repne scasb', 'repnz scasb'):
            lines.append(f"{{ while (ecx && LO8(eax) != MEM8(edi)) {{ edi += _df; ecx--; }} }} {comment}")

        elif m in ('repe cmpsb', 'repz cmpsb'):
            lines.append(f"{{ while (ecx && MEM8(esi) == MEM8(edi)) {{ esi += _df; edi += _df; ecx--; }} }} {comment}")

        # --- Control Flow ---
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
                else:
                    lines.append(f"RECOMP_CALL(sub_{target:08X}); {comment}")
            else:
                # Indirect call
                if ops and ops[0].type == X86_OP_MEM:
                    addr = self._fmt_mem_addr(ops[0].mem)
                    lines.append(f"RECOMP_ICALL(MEM32({addr})); {comment}")
                elif ops and ops[0].type == X86_OP_REG:
                    r = self._fmt_read(ops[0])
                    lines.append(f"RECOMP_ICALL({r}); {comment}")
                else:
                    lines.append(f"RECOMP_ICALL(0); /* unresolved */ {comment}")

        elif m == 'ret' or m == 'retn':
            if ops and ops[0].type == X86_OP_IMM:
                n = ops[0].imm
                lines.append(f"esp += {n}; return; {comment}")
            else:
                lines.append(f"return; {comment}")

        elif m == 'retf':
            lines.append(f"return; /* far return */ {comment}")

        elif m == 'jmp':
            target = insn.get_branch_target()
            if target:
                lines.append(f"goto L_{target:08X}; {comment}")
            else:
                # Indirect jump (switch table or vtable)
                if ops and ops[0].type == X86_OP_MEM:
                    addr = self._fmt_mem_addr(ops[0].mem)
                    lines.append(f"RECOMP_ITAIL(MEM32({addr})); return; {comment}")
                elif ops and ops[0].type == X86_OP_REG:
                    r = self._fmt_read(ops[0])
                    lines.append(f"RECOMP_ITAIL({r}); return; {comment}")
                else:
                    lines.append(f"RECOMP_ITAIL(0); return; /* unresolved */ {comment}")

        elif m in COND_MAP:
            target = insn.get_branch_target()
            cond = self._make_condition(m)
            if target:
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
                        lines.append(f"fp_push(0.0); /* fld size={ops[0].size} */ {comment}")
                else:
                    lines.append(f"fp_push(_st[{ops[0].reg - 224}]); {comment}")  # ST(i) hack

        elif m == 'fild':
            if ops and ops[0].type == X86_OP_MEM:
                if ops[0].size == 2:
                    addr = self._fmt_mem_addr(ops[0].mem)
                    lines.append(f"fp_push((double)(int16_t)MEM16({addr})); {comment}")
                elif ops[0].size == 4:
                    addr = self._fmt_mem_addr(ops[0].mem)
                    lines.append(f"fp_push((double)(int32_t)MEM32({addr})); {comment}")
                else:
                    addr = self._fmt_mem_addr(ops[0].mem)
                    lines.append(f"fp_push((double)(int64_t)MEM64({addr})); {comment}")

        elif m == 'fstp':
            if ops:
                if ops[0].type == X86_OP_MEM:
                    addr = self._fmt_mem_addr(ops[0].mem)
                    if ops[0].size == 4:
                        lines.append(f"{{ float _v = (float)fp_pop(); *(float*)ADDR({addr}) = _v; }} {comment}")
                    elif ops[0].size == 8:
                        lines.append(f"{{ double _v = fp_pop(); *(double*)ADDR({addr}) = _v; }} {comment}")
                    else:
                        lines.append(f"fp_pop(); /* fstp size={ops[0].size} */ {comment}")
                else:
                    lines.append(f"_st[{ops[0].reg - 224}] = fp_pop(); {comment}")

        elif m == 'fst':
            if ops and ops[0].type == X86_OP_MEM:
                addr = self._fmt_mem_addr(ops[0].mem)
                if ops[0].size == 4:
                    lines.append(f"{{ float _v = (float)_st[0]; *(float*)ADDR({addr}) = _v; }} {comment}")
                elif ops[0].size == 8:
                    lines.append(f"*(double*)ADDR({addr}) = _st[0]; {comment}")

        elif m == 'fistp':
            if ops and ops[0].type == X86_OP_MEM:
                addr = self._fmt_mem_addr(ops[0].mem)
                if ops[0].size == 2:
                    lines.append(f"MEM16({addr}) = (int16_t)fp_pop(); {comment}")
                elif ops[0].size == 4:
                    lines.append(f"MEM32({addr}) = (uint32_t)(int32_t)fp_pop(); {comment}")
                else:
                    lines.append(f"MEM64({addr}) = (int64_t)fp_pop(); {comment}")

        elif m == 'fadd':
            if ops:
                lines.append(f"_st[0] += {self._fmt_fpu_src(ops)}; {comment}")
            else:
                lines.append(f"_st[0] += _st[1]; {comment}")

        elif m == 'faddp':
            lines.append(f"{{ double _v = fp_pop(); _st[0] += _v; }} {comment}")

        elif m == 'fsub':
            if ops:
                lines.append(f"_st[0] -= {self._fmt_fpu_src(ops)}; {comment}")
            else:
                lines.append(f"_st[0] -= _st[1]; {comment}")

        elif m == 'fsubp':
            lines.append(f"{{ double _v = fp_pop(); _st[0] = _v - _st[0]; }} {comment}")

        elif m == 'fsubr':
            if ops:
                lines.append(f"_st[0] = {self._fmt_fpu_src(ops)} - _st[0]; {comment}")

        elif m == 'fsubrp':
            lines.append(f"{{ double _v = fp_pop(); _st[0] -= _v; }} {comment}")

        elif m == 'fmul':
            if ops:
                lines.append(f"_st[0] *= {self._fmt_fpu_src(ops)}; {comment}")
            else:
                lines.append(f"_st[0] *= _st[1]; {comment}")

        elif m == 'fmulp':
            lines.append(f"{{ double _v = fp_pop(); _st[0] *= _v; }} {comment}")

        elif m == 'fdiv':
            if ops:
                lines.append(f"_st[0] /= {self._fmt_fpu_src(ops)}; {comment}")
            else:
                lines.append(f"_st[0] /= _st[1]; {comment}")

        elif m == 'fdivp':
            lines.append(f"{{ double _v = fp_pop(); _st[0] = _v / _st[0]; }} {comment}")

        elif m == 'fdivr':
            if ops:
                lines.append(f"_st[0] = {self._fmt_fpu_src(ops)} / _st[0]; {comment}")

        elif m == 'fdivrp':
            lines.append(f"{{ double _v = fp_pop(); _st[0] /= _v; }} {comment}")

        elif m == 'fchs':
            lines.append(f"_st[0] = -_st[0]; {comment}")

        elif m == 'fabs':
            lines.append(f"_st[0] = fabs(_st[0]); {comment}")

        elif m == 'fsqrt':
            lines.append(f"_st[0] = sqrt(_st[0]); {comment}")

        elif m == 'fxch':
            if ops:
                lines.append(f"{{ double _t = _st[0]; _st[0] = _st[{ops[0].reg - 224}]; _st[{ops[0].reg - 224}] = _t; }} {comment}")
            else:
                lines.append(f"{{ double _t = _st[0]; _st[0] = _st[1]; _st[1] = _t; }} {comment}")

        elif m in ('fcomip', 'fucomip', 'fcompp'):
            lines.append(f"_fpu_cmp = (_st[0] < _st[1]) ? -1 : (_st[0] > _st[1]) ? 1 : 0; {comment}")
            if m == 'fcompp':
                lines.append(f"fp_pop(); fp_pop();")
            else:
                lines.append(f"fp_pop();")
            self._flag_state = ('fcom', '_fpu_cmp')

        elif m in ('fcom', 'fcomp', 'fucom', 'fucomp'):
            if ops:
                src = self._fmt_fpu_src(ops)
                lines.append(f"_fpu_cmp = (_st[0] < {src}) ? -1 : (_st[0] > {src}) ? 1 : 0; {comment}")
            else:
                lines.append(f"_fpu_cmp = (_st[0] < _st[1]) ? -1 : (_st[0] > _st[1]) ? 1 : 0; {comment}")
            if m in ('fcomp', 'fucomp'):
                lines.append(f"fp_pop();")
            self._flag_state = ('fcom', '_fpu_cmp')

        elif m == 'fnstsw' or m == 'fstsw':
            lines.append(f"/* fnstsw - FPU status to ax */ {comment}")
            # After fcom+fnstsw, the test ah pattern follows

        elif m == 'sahf':
            lines.append(f"/* sahf - load flags from ah */ {comment}")
            # Often follows fnstsw ax; sahf; jcc pattern

        elif m == 'fld1':
            lines.append(f"fp_push(1.0); {comment}")

        elif m == 'fldz':
            lines.append(f"fp_push(0.0); {comment}")

        elif m == 'fldpi':
            lines.append(f"fp_push(3.14159265358979323846); {comment}")

        elif m == 'fsin':
            lines.append(f"_st[0] = sin(_st[0]); {comment}")

        elif m == 'fcos':
            lines.append(f"_st[0] = cos(_st[0]); {comment}")

        elif m == 'fsincos':
            lines.append(f"{{ double _a = _st[0]; _st[0] = cos(_a); fp_push(sin(_a)); }} {comment}")

        elif m == 'fpatan':
            lines.append(f"{{ double _v = fp_pop(); _st[0] = atan2(_v, _st[0]); }} {comment}")

        elif m == 'f2xm1':
            lines.append(f"_st[0] = pow(2.0, _st[0]) - 1.0; {comment}")

        elif m == 'fscale':
            lines.append(f"_st[0] = _st[0] * pow(2.0, (int)_st[1]); {comment}")

        elif m == 'frndint':
            lines.append(f"_st[0] = (double)(int)_st[0]; /* frndint */ {comment}")

        # --- SSE scalar float ---
        elif m == 'movss':
            if len(ops) == 2:
                lines.append(f"/* {m} */ {comment}")  # TODO: XMM support
                lines.append(f"/* SSE movss not yet implemented */")

        # --- Misc ---
        elif m == 'nop' or m.startswith('nop'):
            lines.append(f"/* nop */ {comment}")

        elif m == 'int3':
            lines.append(f"/* int3 breakpoint */ {comment}")

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

        elif m == 'clc':
            lines.append(f"_cf = 0; {comment}")

        elif m == 'stc':
            lines.append(f"_cf = 1; {comment}")

        elif m == 'cmc':
            lines.append(f"_cf = !_cf; {comment}")

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

        else:
            lines.append(f"/* UNIMPLEMENTED: {insn.mnemonic} {insn.op_str} */ {comment}")

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
            return f"_st[{op.reg - 224}]"
        return "_st[1]"

    def lift_basic_block(self, block) -> list:
        """Lift an entire basic block to C code."""
        lines = []
        lines.append(f"L_{block.start:08X}:")

        for insn in block.instructions:
            lifted = self.lift_instruction(insn)
            for line in lifted:
                lines.append(f"    {line}")

        return lines

    def lift_function(self, func) -> str:
        """Lift an entire function to C code."""
        lines = []
        name = func.name

        lines.append(f"void {name}(void) {{")
        lines.append(f"    uint32_t ebp = 0;  /* local frame pointer */")
        lines.append(f"    double _st[8] = {{0}};  /* FPU stack */")
        lines.append(f"    int _fp_top = 0;")
        lines.append(f"    int _fpu_cmp = 0;")
        lines.append(f"    uint32_t _cf = 0;  /* carry flag */")
        lines.append(f"    int _df = 1;  /* direction flag (1=forward, -1=backward) */")
        lines.append(f"    uint16_t _fpu_cw = 0x037F;  /* FPU control word */")
        lines.append(f"")

        # Emit blocks in address order
        sorted_addrs = sorted(func.blocks.keys())
        for addr in sorted_addrs:
            block = func.blocks[addr]
            self._flag_state = None
            block_lines = self.lift_basic_block(block)
            lines.extend(block_lines)
            lines.append("")

        lines.append("}")
        return '\n'.join(lines)

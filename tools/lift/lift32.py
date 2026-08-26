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

# Which runtime flag kind each setter corresponds to; see recomp_cond().
FLAG_KIND = {
    'cmp': 'FK_CMP', 'sub': 'FK_CMP', 'dec': 'FK_CMP',
    'add': 'FK_ADD', 'inc': 'FK_ADD',
    'and': 'FK_TEST', 'or': 'FK_TEST', 'xor': 'FK_TEST', 'test': 'FK_TEST',
    'bt': 'FK_BT', 'fcom': 'FK_FCOM',
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


class Lifter:
    """Lifts x86 instructions to C code using a global register model."""

    def __init__(self, iat_map: dict = None, func_names: dict = None,
                 lifted: set = None, precise_sbb: bool = False):
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
        self._labels = None        # block starts of the function being lifted
        self._jump_targets = None  # arms its switch tables dispatch to
        self._flag_state = None  # (setter_mnemonic, operands_str)
        self._flag_seq = 0       # bumped whenever the flags are written
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
            if X86_REG_ST0 <= r <= X86_REG_ST0 + 7:
                return f"_st[{r - X86_REG_ST0}] = {value}"
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

    def _flag_capture(self, a, b):
        """Snapshot flag operands into temps and record the flag state to use them.

        A jcc reads the flags set by an earlier cmp/test/sub/... The old code
        stored the operand *expressions* and re-evaluated them at the jcc, so any
        instruction in between that wrote the operand (e.g. `test eax,eax; mov
        eax,0; jne`, or `sub eax,ebx; jl` where eax is the destination) corrupted
        the condition. Capturing the values at the flag-setter fixes that.
        Returns the C snapshot statement to append; sets self._flag_state to temps.
        """
        self._flag_seq += 1
        return f"_flag_a = (uint32_t)({a}); _flag_b = (uint32_t)({b});"

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
            # Reached from blocks with different flag-setters: decide at runtime.
            jcc = mnem.replace('cmov', 'j', 1) if mnem.startswith('cmov') else                   ('j' + mnem[3:] if mnem.startswith('set') else mnem)
            cc = COND_CODE.get(jcc)
            if cc:
                return f"recomp_cond(_flag_k, _flag_a, _flag_b, {cc})"
            return f"/* no flag state for {mnem} */ _cf"

        setter, ops = self._flag_state

        if setter == 'cmp':
            return f"{cmp_macro}({ops})"
        elif setter == 'test':
            # After `test`, CF=0 and OF=0, so the unsigned/signed-ordering jccs
            # reduce to ZF/SF tests against the AND result -- NOT cmp(a,b) (which
            # would compare the two operands as if subtracted). Map them directly.
            test_only = {
                'jbe': f"TEST_Z({ops})",  'ja':  f"TEST_NZ({ops})",   # CF=0: jbe==je, ja==jne
                'jb':  "0",               'jae': "1",                 # CF=0: jb never, jae always
                'jg':  f"TEST_G({ops})",  'jle': f"TEST_LE({ops})",
                'jge': f"TEST_NS({ops})", 'jl':  f"TEST_S({ops})",
            }
            if jcc_mnemonic in test_only:
                return test_only[jcc_mnemonic]
            if test_macro:
                return f"{test_macro}({ops})"
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
            # BT sets CF = bit tested
            if cmp_macro in ('CMP_B', 'CMP_AE'):  # jb/jae test CF
                return f"BT_CF({ops})"
            return f"/* bt */ {cmp_macro}({ops})"
        else:
            return f"/* flag from {setter} */ {cmp_macro}({ops})"

    def lift_instruction(self, insn) -> list:
        """Lift one instruction, recording the runtime flag kind if it wrote flags."""
        seq0 = self._flag_seq
        lines = self._lift_instruction(insn)
        if self._flag_seq != seq0 and self._flag_state is not None:
            lines.append(f"_flag_k = {FLAG_KIND.get(self._flag_state[0], 'FK_CMP')};")
        return lines

    def _lift_instruction(self, insn) -> list:
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

        elif m in ('pushad', 'pushal'):   # Capstone spells PUSHAD as 'pushal' in 32-bit
            lines.append(f"PUSHAD(); {comment}")

        elif m in ('popad', 'popal'):      # Capstone spells POPAD as 'popal' in 32-bit
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
                lines.append(self._flag_capture(a, b))
                lines.append(f"{self._fmt_write(ops[0], f'{a} + {b}')}; {comment}")
                self._flag_state = ('add', "_flag_a, _flag_b")

        elif m == 'sub':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(self._flag_capture(a, b))
                lines.append(f"{self._fmt_write(ops[0], f'{a} - {b}')}; {comment}")
                self._flag_state = ('sub', "_flag_a, _flag_b")

        elif m == 'inc':
            if len(ops) == 1:
                a = self._fmt_read(ops[0])
                lines.append(self._flag_capture(a, "1"))
                lines.append(f"{self._fmt_write(ops[0], f'{a} + 1')}; {comment}")
                self._flag_state = ('inc', "_flag_a, _flag_b")

        elif m == 'dec':
            if len(ops) == 1:
                a = self._fmt_read(ops[0])
                lines.append(self._flag_capture(a, "1"))
                lines.append(f"{self._fmt_write(ops[0], f'{a} - 1')}; {comment}")
                self._flag_state = ('dec', "_flag_a, _flag_b")

        elif m == 'neg':
            if len(ops) == 1:
                a = self._fmt_read(ops[0])
                lines.append(self._flag_capture("0", a))
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
                # Evaluate the divisor once (it may be a memory read with side effects)
                # and guard against divide-by-zero. On real x86 a zero divisor raises
                # #DE; the original relied on never hitting it (or caught it via SEH),
                # so producing 0 and continuing is the safe recomp behaviour instead of
                # crashing the host process (e.g. degenerate spans / z=0 in the
                # perspective-divide texture mappers).
                if m == 'div':
                    lines.append(f"{{ uint64_t _dividend = ((uint64_t)edx << 32) | eax; uint32_t _dv = (uint32_t){divisor}; {comment}")
                    lines.append(f"  if (_dv) {{ eax = (uint32_t)(_dividend / _dv); edx = (uint32_t)(_dividend % _dv); }}")
                    lines.append(f"  else {{ eax = 0; edx = 0; }} }}")
                else:
                    lines.append(f"{{ int64_t _dividend = ((int64_t)(int32_t)edx << 32) | eax; int32_t _dv = (int32_t){divisor}; {comment}")
                    lines.append(f"  if (_dv) {{ eax = (uint32_t)((int32_t)(_dividend / _dv)); edx = (uint32_t)((int32_t)(_dividend % _dv)); }}")
                    lines.append(f"  else {{ eax = 0; edx = 0; }} }}")

        # --- Logical ---
        elif m == 'and':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(self._flag_capture(a, b))
                lines.append(f"{self._fmt_write(ops[0], f'{a} & {b}')}; {comment}")
                self._flag_state = ('and', "_flag_a, _flag_b")

        elif m == 'or':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(self._flag_capture(f"({a} | {b})", f"({a} | {b})"))
                lines.append(f"{self._fmt_write(ops[0], f'{a} | {b}')}; {comment}")
                self._flag_state = ('or', "_flag_a, _flag_b")

        elif m == 'xor':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                # Detect xor reg, reg (zero idiom)
                if ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG and ops[0].reg == ops[1].reg:
                    lines.append(self._flag_capture("0", "0"))
                    lines.append(f"{self._fmt_write(ops[0], '0')}; {comment}")
                else:
                    lines.append(self._flag_capture(f"({a} ^ {b})", f"({a} ^ {b})"))
                    lines.append(f"{self._fmt_write(ops[0], f'{a} ^ {b}')}; {comment}")
                self._flag_state = ('xor', "_flag_a, _flag_b")

        # --- Shifts ---
        # shl/shr/sar set ZF/SF/PF from the result (when the count != 0). Capture
        # the result so a following jcc tests it -- otherwise it reads the prior
        # instruction's stale flags (e.g. `shr ecx,2; je` wrongly using a dec's ZF,
        # which sent the Watcom memset's count off into a multi-GB overrun).
        elif m == 'shl' or m == 'sal':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                res = f"({a} << {b})"
                lines.append(self._flag_capture(res, res))
                lines.append(f"{self._fmt_write(ops[0], f'{a} << {b}')}; {comment}")
                self._flag_state = ('or', "_flag_a, _flag_b")

        elif m == 'shr':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                res = f"({a} >> {b})"
                lines.append(self._flag_capture(res, res))
                lines.append(f"{self._fmt_write(ops[0], f'{a} >> {b}')}; {comment}")
                self._flag_state = ('or', "_flag_a, _flag_b")

        elif m == 'sar':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                res = f"((uint32_t)((int32_t){a} >> {b}))"
                # sar must publish CF for a following rcr (the clip's `sar;rcr` lerp).
                lines.append(f"if ({b}) _cf = ((({a}) >> (({b}) - 1)) & 1u); {comment}")
                lines.append(self._flag_capture(res, res))
                lines.append(f"{self._fmt_write(ops[0], f'(uint32_t)((int32_t){a} >> {b})')};")
                self._flag_state = ('or', "_flag_a, _flag_b")

        # shld/shrd: double-precision shift (64-bit window across dst:src). Used pervasively
        # for 64-bit / fixed-point math; leaving them unimplemented silently dropped the
        # write -> garbage 3D vertex/clip math. CF = last bit shifted out of dst.
        elif m == 'shrd':
            if len(ops) == 3:
                d = self._fmt_read(ops[0]); s = self._fmt_read(ops[1]); c = self._fmt_read(ops[2])
                expr = f"(({c}) ? ((({d}) >> ({c})) | ((uint32_t)({s}) << (32 - ({c})))) : ({d}))"
                lines.append(f"if ({c}) _cf = ((({d}) >> (({c}) - 1)) & 1u); {comment}")
                lines.append(self._flag_capture(expr, expr))
                lines.append(f"{self._fmt_write(ops[0], expr)};")
                self._flag_state = ('or', "_flag_a, _flag_b")

        elif m == 'shld':
            if len(ops) == 3:
                d = self._fmt_read(ops[0]); s = self._fmt_read(ops[1]); c = self._fmt_read(ops[2])
                expr = f"(({c}) ? ((({d}) << ({c})) | ((uint32_t)({s}) >> (32 - ({c})))) : ({d}))"
                lines.append(f"if ({c}) _cf = ((({d}) >> (32 - ({c}))) & 1u); {comment}")
                lines.append(self._flag_capture(expr, expr))
                lines.append(f"{self._fmt_write(ops[0], expr)};")
                self._flag_state = ('or', "_flag_a, _flag_b")

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

        # rcr/rcl: rotate-through-carry (33-bit rotate of CF:operand). The clip-intersection
        # forms its 64-bit lerp dividend with `sar edx,1; rcr eax,1`; without rcr the carry
        # bit was dropped -> garbage clip vertices -> the flight rasterizer hung on huge spans.
        elif m == 'rcr':
            if len(ops) == 2:
                a = self._fmt_read(ops[0]); b = self._fmt_read(ops[1])
                wr = self._fmt_write(ops[0], '_rv')
                lines.append(f"{{ uint32_t _rv = {a}, _rn = ({b}) & 31; for (uint32_t _i=0;_i<_rn;_i++){{ "
                             f"uint32_t _rb = _rv & 1u; _rv = (_rv >> 1) | (_cf << 31); _cf = _rb; }} {wr}; }} {comment}")

        elif m == 'rcl':
            if len(ops) == 2:
                a = self._fmt_read(ops[0]); b = self._fmt_read(ops[1])
                wr = self._fmt_write(ops[0], '_rv')
                lines.append(f"{{ uint32_t _rv = {a}, _rn = ({b}) & 31; for (uint32_t _i=0;_i<_rn;_i++){{ "
                             f"uint32_t _rb = _rv >> 31; _rv = (_rv << 1) | _cf; _cf = _rb; }} {wr}; }} {comment}")

        # --- Compare / Test (flag setters only, no writeback) ---
        elif m == 'cmp':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(f"/* cmp {a}, {b} */ {comment}")
                lines.append(self._flag_capture(a, b))
                self._flag_state = ('cmp', "_flag_a, _flag_b")
            self._flag_seq += 1

        elif m == 'test':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(f"/* test {a}, {b} */ {comment}")
                lines.append(self._flag_capture(a, b))
                self._flag_state = ('test', "_flag_a, _flag_b")

        elif m == 'bt':
            if len(ops) == 2:
                a = self._fmt_read(ops[0])
                b = self._fmt_read(ops[1])
                lines.append(f"/* bt {a}, {b} */ {comment}")
                lines.append(self._flag_capture(a, b))
                self._flag_state = ('bt', "_flag_a, _flag_b")

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
                        cf = f"CMP_B({self._flag_state[1]})"
                        lines.append(f"{self._fmt_write(ops[0], f'{cf} ? 0xFFFFFFFFu : 0')}; {comment}")
                    else:
                        lines.append(f"{self._fmt_write(ops[0], '_cf ? 0xFFFFFFFFu : 0')}; {comment}")
                else:
                    lines.append(f"{self._fmt_write(ops[0], f'{a} - {b} - _cf')}; {comment}")

        # --- String Operations ---
        # The rep/repne prefix (F3/F2) on movs/stos/lods means "repeat ECX times".
        # For these ops F2 and F3 are EQUIVALENT (the E/NE distinction only matters
        # for cmps/scas). Detect the prefix from the raw bytes so Watcom's
        # F2-prefixed memcpy (repne movsd/movsb) is handled, not just the F3 spelling.
        # capstone is inconsistent: it may fold the prefix into the mnemonic
        # ("repne movsb") or leave a bare "movsd" with the prefix in the bytes.
        # Direction is assumed forward (DF clear), as in any compiled memcpy/memset.
        elif (m.split()[-1] in ('movsb', 'movsd', 'movsw', 'stosb', 'stosd', 'lodsb', 'lodsd')
              and insn.bytes
              and next((b for b in insn.bytes
                        if b not in (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3)), 0)
                  in (0xA4, 0xA5, 0xAA, 0xAB, 0xAC, 0xAD)):
            # (the opcode guard excludes SSE movsd/movss, which share the mnemonic
            #  but are 0x0F-escaped, not single-byte string opcodes)
            base = m.split()[-1]
            rep = (' ' in m) or any(b in (0xF2, 0xF3) for b in (insn.bytes[:4] if insn.bytes else ()))
            esz = {'movsb': 1, 'movsd': 4, 'movsw': 2, 'stosb': 1, 'stosd': 4, 'lodsb': 1, 'lodsd': 4}[base]
            if base.startswith('movs'):
                if rep:
                    lines.append(f"memcpy((void*)ADDR(edi), (void*)ADDR(esi), ecx * {esz}u); {comment}")
                    lines.append(f"esi += ecx * {esz}u; edi += ecx * {esz}u; ecx = 0;")
                elif esz == 1:
                    lines.append(f"MEM8(edi) = MEM8(esi); esi += _df; edi += _df; {comment}")
                elif esz == 2:
                    lines.append(f"MEM16(edi) = MEM16(esi); esi += _df * 2; edi += _df * 2; {comment}")
                else:
                    lines.append(f"MEM32(edi) = MEM32(esi); esi += _df * 4; edi += _df * 4; {comment}")
            elif base.startswith('stos'):
                if rep and esz == 1:
                    lines.append(f"memset((void*)ADDR(edi), LO8(eax), ecx); {comment}")
                    lines.append(f"edi += ecx; ecx = 0;")
                elif rep:
                    lines.append(f"MEMSET32((void*)ADDR(edi), eax, ecx); {comment}")
                    lines.append(f"edi += ecx * 4; ecx = 0;")
                elif esz == 1:
                    lines.append(f"MEM8(edi) = LO8(eax); edi += _df; {comment}")
                else:
                    lines.append(f"MEM32(edi) = eax; edi += _df * 4; {comment}")
            else:  # lodsb/lodsd
                if esz == 1:
                    lines.append(f"SET_LO8(eax, MEM8(esi)); esi += _df; {comment}")
                else:
                    lines.append(f"eax = MEM32(esi); esi += _df * 4; {comment}")

        elif m == 'scasb':
            # Compare AL with [EDI] (capture flags BEFORE advancing EDI).
            lines.append(f"_flag_a = LO8(eax); _flag_b = MEM8(edi); edi += _df; {comment}")
            self._flag_state = ('cmp', "_flag_a, _flag_b")
            self._flag_seq += 1

        elif m in ('repne scasb', 'repnz scasb'):
            # repne scasb: scan [EDI] for AL. Real x86 decrements ECX and advances
            # EDI for EACH byte processed (incl. the match) and stops on match --
            # a do-while, not a pre-test. (A pre-test loop miscomputes the strlen
            # idiom `repne scasb; not ecx; dec ecx` for an empty string as -1.)
            # ZF=1 iff a match was found, for a following je/jne.
            lines.append(f"{{ uint32_t _t = LO8(eax); "
                         f"while (ecx) {{ _t = MEM8(edi); edi += _df; ecx--; "
                         f"if (LO8(eax) == _t) break; }} "
                         f"_flag_a = LO8(eax); _flag_b = _t; }} {comment}")
            self._flag_state = ('cmp', "_flag_a, _flag_b")
            self._flag_seq += 1

        elif m in ('repe cmpsb', 'repz cmpsb'):
            # repe cmpsb: compare [ESI] vs [EDI] while equal; stop on first mismatch
            # or ECX==0. Flags reflect the last byte pair (for strcmp's jcc).
            lines.append(f"{{ uint32_t _a = 0, _b = 0; "
                         f"while (ecx) {{ _a = MEM8(esi); _b = MEM8(edi); "
                         f"esi += _df; edi += _df; ecx--; if (_a != _b) break; }} "
                         f"_flag_a = _a; _flag_b = _b; }} {comment}")
            self._flag_state = ('cmp', "_flag_a, _flag_b")
            self._flag_seq += 1

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
                elif self.lifted is not None and target not in self.lifted:
                    lines.append(f"RECOMP_ICALL(0x{target:08X}u); {comment} /* not lifted */")
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
            # Pop the return address that RECOMP_CALL/ICALL pushed (esp += 4), plus
            # any stdcall callee-cleanup bytes (ret N -> esp += 4 + N). Without the
            # +4 the simulated ESP drifts down 4 bytes per call and eventually the
            # 0xDEAD0000 dummy return address gets read as a function argument.
            if ops and ops[0].type == X86_OP_IMM:
                n = ops[0].imm
                lines.append(f"esp += {4 + n}; return; {comment}")
            else:
                lines.append(f"esp += 4; return; {comment}")

        elif m == 'retf':
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
                        lines.append(f"fp_push(0.0); /* fld size={ops[0].size} */ {comment}")
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
                    # fstp st(i): ST(i) <- ST(0) THEN pop. The copy uses the
                    # pre-pop numbering, so after the pop the written value lands at
                    # st(i-1). Writing `_st[i] = fp_pop()` (pop first, then store) is
                    # off by one -- and for fstp st(0) it wrongly keeps the popped top.
                    i = ops[0].reg - X86_REG_ST0
                    lines.append(f"{{ _st[{i}] = _st[0]; fp_pop(); }} {comment}")

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
                lines.append(f"{self._fpu_dst(ops)} += {self._fmt_fpu_src(ops)}; {comment}")
            else:
                lines.append(f"_st[0] += _st[1]; {comment}")

        elif m == 'faddp':
            lines.append(f"{{ double _v = fp_pop(); _st[0] += _v; }} {comment}")

        elif m == 'fsub':
            if ops:
                lines.append(f"{self._fpu_dst(ops)} -= {self._fmt_fpu_src(ops)}; {comment}")
            else:
                lines.append(f"_st[0] -= _st[1]; {comment}")

        elif m == 'fsubp':
            lines.append(f"{{ double _v = fp_pop(); _st[0] = _v - _st[0]; }} {comment}")

        elif m == 'fsubr':
            if ops:
                lines.append(f"{self._fpu_dst(ops)} = {self._fmt_fpu_src(ops)} - {self._fpu_dst(ops)}; {comment}")

        elif m == 'fsubrp':
            lines.append(f"{{ double _v = fp_pop(); _st[0] -= _v; }} {comment}")

        elif m == 'fmul':
            if ops:
                lines.append(f"{self._fpu_dst(ops)} *= {self._fmt_fpu_src(ops)}; {comment}")
            else:
                lines.append(f"_st[0] *= _st[1]; {comment}")

        elif m == 'fmulp':
            lines.append(f"{{ double _v = fp_pop(); _st[0] *= _v; }} {comment}")

        elif m == 'fdiv':
            if ops:
                lines.append(f"{self._fpu_dst(ops)} /= {self._fmt_fpu_src(ops)}; {comment}")
            else:
                lines.append(f"_st[0] /= _st[1]; {comment}")

        elif m == 'fdivp':
            lines.append(f"{{ double _v = fp_pop(); _st[0] = _v / _st[0]; }} {comment}")

        elif m == 'fdivr':
            if ops:
                lines.append(f"{self._fpu_dst(ops)} = {self._fmt_fpu_src(ops)} / {self._fpu_dst(ops)}; {comment}")

        elif m == 'fdivrp':
            lines.append(f"{{ double _v = fp_pop(); _st[0] /= _v; }} {comment}")

        elif m == 'fchs':
            lines.append(f"_st[0] = -_st[0]; {comment}")

        elif m == 'fabs':
            lines.append(f"_st[0] = fabs(_st[0]); {comment}")

        elif m == 'fsqrt':
            lines.append(f"_st[0] = sqrt(_st[0]); {comment}")

        elif m == 'fxch':
            # capstone reports fxch st(N) as [st(0), st(N)]; swap st(0) with the
            # OTHER operand (the last one), not st(0) with itself.
            if ops:
                i = ops[-1].reg - X86_REG_ST0
                lines.append(f"{{ double _t = _st[0]; _st[0] = _st[{i}]; _st[{i}] = _t; }} {comment}")
            else:
                lines.append(f"{{ double _t = _st[0]; _st[0] = _st[1]; _st[1] = _t; }} {comment}")

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

        elif m in ('fcomip', 'fucomip', 'fcompp'):
            lines.append(f"_fpu_cmp = (_st[0] < _st[1]) ? -1 : (_st[0] > _st[1]) ? 1 : 0; {comment}")
            if m == 'fcompp':
                lines.append(f"fp_pop(); fp_pop();")
            else:
                lines.append(f"fp_pop();")
            lines.append("_flag_a = (uint32_t)_fpu_cmp; _flag_b = 0;")
            self._flag_state = ('fcom', '_fpu_cmp')
            self._flag_seq += 1

        elif m in ('fcom', 'fcomp', 'fucom', 'fucomp'):
            if ops:
                src = self._fmt_fpu_src(ops)
                lines.append(f"_fpu_cmp = (_st[0] < {src}) ? -1 : (_st[0] > {src}) ? 1 : 0; {comment}")
            else:
                lines.append(f"_fpu_cmp = (_st[0] < _st[1]) ? -1 : (_st[0] > _st[1]) ? 1 : 0; {comment}")
            if m in ('fcomp', 'fucomp'):
                lines.append(f"fp_pop();")
            lines.append("_flag_a = (uint32_t)_fpu_cmp; _flag_b = 0;")
            self._flag_state = ('fcom', '_fpu_cmp')
            self._flag_seq += 1

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
            # A null statement, not a bare comment: this may be the only thing
            # after a label, and C requires a label to be followed by a statement.
            lines.append(f"; /* UNIMPLEMENTED: {insn.mnemonic} {insn.op_str} */ {comment}")

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

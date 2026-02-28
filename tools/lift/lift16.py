"""
lift.py - 16-bit x86 to C Code Lifter

Translates decoded x86-16 instructions into C code that operates on
the CPU state struct. Each original function becomes a C function
taking a CPU* parameter.

Generated code style:
    void res_001234(CPU *cpu) {
        push16(cpu, cpu->bp);           // push bp
        cpu->bp = cpu->sp;              // mov bp, sp
        cpu->sp -= 0x10;               // sub sp, 0x10
        ...
    }

Part of the Civ Recomp project (sp00nznet/civ)
"""

from decode16 import Decoder, Instruction, OpType, Operand, REG8_NAMES, REG16_NAMES, SREG_NAMES


def _reg8(op: Operand) -> str:
    """Generate C expression for 8-bit register access."""
    return f'cpu->{REG8_NAMES[op.reg]}'

def _reg16(op: Operand) -> str:
    """Generate C expression for 16-bit register access."""
    return f'cpu->{REG16_NAMES[op.reg]}'

def _sreg(op: Operand) -> str:
    """Generate C expression for segment register access."""
    return f'cpu->{SREG_NAMES[op.reg]}'

def _mem_addr(op: Operand) -> tuple:
    """Generate (seg_expr, off_expr) for memory operand."""
    seg = f'cpu->{op.seg}' if op.seg else 'cpu->ds'

    parts = []
    if op.base:
        parts.append(f'cpu->{op.base}')
    if op.index:
        parts.append(f'cpu->{op.index}')

    if op.disp:
        if op.disp < 0:
            disp_str = f'- 0x{(-op.disp) & 0xFFFF:X}'
        else:
            disp_str = f'+ 0x{op.disp & 0xFFFF:X}'
        if parts:
            off = f'(uint16_t)({" + ".join(parts)} {disp_str})'
        else:
            off = f'0x{op.disp & 0xFFFF:X}'
    elif parts:
        if len(parts) == 1:
            off = parts[0]
        else:
            off = f'(uint16_t)({" + ".join(parts)})'
    else:
        off = '0'

    return seg, off

def _read(op: Operand) -> str:
    """Generate C expression to read an operand value."""
    if op.type == OpType.REG8:
        return _reg8(op)
    elif op.type == OpType.REG16:
        return _reg16(op)
    elif op.type == OpType.SREG:
        return _sreg(op)
    elif op.type in (OpType.IMM8, OpType.IMM16):
        return f'0x{op.disp & 0xFFFF:X}'
    elif op.type == OpType.MEM or op.type == OpType.MOFFS:
        seg, off = _mem_addr(op)
        if op.size == 1:
            return f'mem_read8(cpu, {seg}, {off})'
        else:
            return f'mem_read16(cpu, {seg}, {off})'
    return '/* ??? */'

def _write(op: Operand, val: str) -> str:
    """Generate C statement to write a value to an operand."""
    if op.type == OpType.REG8:
        return f'{_reg8(op)} = (uint8_t)({val});'
    elif op.type == OpType.REG16:
        return f'{_reg16(op)} = (uint16_t)({val});'
    elif op.type == OpType.SREG:
        return f'{_sreg(op)} = (uint16_t)({val});'
    elif op.type == OpType.MEM or op.type == OpType.MOFFS:
        seg, off = _mem_addr(op)
        if op.size == 1:
            return f'mem_write8(cpu, {seg}, {off}, (uint8_t)({val}));'
        else:
            return f'mem_write16(cpu, {seg}, {off}, (uint16_t)({val}));'
    return f'/* write ??? = {val} */;'

def _label(addr: int, prefix: str = '') -> str:
    """Generate a label name for an address."""
    if prefix:
        return f'L_{prefix}_{addr:06X}'
    return f'L_{addr:06X}'


class Lifter:
    """Lifts x86-16 instructions to C code."""

    def __init__(self, overlay_bases=None, hdr_size=0x200, known_funcs=None):
        self.output = []
        self.indent = 1
        self.labels_needed = set()
        self.func_calls = set()     # Near call targets in this function
        self.ovl_calls = set()      # Overlay call targets
        self.func_name = ''         # Current function name (for label uniqueness)
        self.valid_addrs = set()    # Valid instruction addresses in current function
        # Map overlay number -> code_offset (absolute file offset of overlay code start)
        self.overlay_bases = overlay_bases or {}
        # MZ header size (for computing far call file offsets)
        self.hdr_size = hdr_size
        # Set of known function file offsets (for resolving far calls)
        self.known_funcs = known_funcs or set()

    def _emit(self, code: str, comment: str = ''):
        """Emit a line of C code with optional comment."""
        pad = '    ' * self.indent
        if comment:
            # Align comments
            line = f'{pad}{code}'
            if len(line) < 44:
                line += ' ' * (44 - len(line))
            line += f' /* {comment} */'
        else:
            line = f'{pad}{code}'
        self.output.append(line)

    def _emit_label(self, addr: int):
        """Emit a label if it's referenced."""
        if addr in self.labels_needed:
            self.output.append(f'{_label(addr, self.func_name)}:;')

    def lift_instruction(self, inst: Instruction, func_start: int):
        """Lift a single instruction to C code."""
        m = inst.mnemonic
        op1 = inst.op1
        op2 = inst.op2

        # Emit label if this address is a jump target
        self._emit_label(inst.address)

        # Format original instruction as comment
        raw_hex = ' '.join(f'{b:02X}' for b in inst.raw[:6])
        orig = repr(inst)

        # ─── Data movement ───

        if m == 'mov':
            self._emit(_write(op1, _read(op2)), orig)

        elif m == 'xchg':
            self._emit(f'{{ uint16_t _t = {_read(op1)}; '
                       f'{_write(op1, _read(op2))} '
                       f'{_write(op2, "_t")} }}', orig)

        elif m == 'lea':
            # LEA computes effective address without memory access
            _, off = _mem_addr(op2)
            self._emit(_write(op1, off), orig)

        elif m == 'lds':
            seg, off = _mem_addr(op2)
            self._emit(f'{_reg16(op1)} = mem_read16(cpu, {seg}, {off});', orig)
            self._emit(f'cpu->ds = mem_read16(cpu, {seg}, (uint16_t)({off} + 2));')

        elif m == 'les':
            seg, off = _mem_addr(op2)
            self._emit(f'{_reg16(op1)} = mem_read16(cpu, {seg}, {off});', orig)
            self._emit(f'cpu->es = mem_read16(cpu, {seg}, (uint16_t)({off} + 2));')

        elif m == 'cbw':
            self._emit('cpu->ax = (uint16_t)(int16_t)(int8_t)cpu->al;', orig)

        elif m == 'cwd':
            self._emit('cpu->dx = (cpu->ax & 0x8000) ? 0xFFFF : 0x0000;', orig)

        # ─── Stack ───

        elif m == 'push':
            self._emit(f'push16(cpu, {_read(op1)});', orig)

        elif m == 'pop':
            self._emit(_write(op1, 'pop16(cpu)'), orig)

        elif m == 'pushf':
            self._emit('push16(cpu, cpu->flags);', orig)

        elif m == 'popf':
            self._emit('cpu->flags = pop16(cpu);', orig)

        elif m == 'pusha':
            self._emit('{ uint16_t _sp = cpu->sp; '
                       'push16(cpu, cpu->ax); push16(cpu, cpu->cx); '
                       'push16(cpu, cpu->dx); push16(cpu, cpu->bx); '
                       'push16(cpu, _sp); push16(cpu, cpu->bp); '
                       'push16(cpu, cpu->si); push16(cpu, cpu->di); }', orig)

        elif m == 'popa':
            self._emit('cpu->di = pop16(cpu); cpu->si = pop16(cpu); '
                       'cpu->bp = pop16(cpu); (void)pop16(cpu); /* skip SP */ '
                       'cpu->bx = pop16(cpu); cpu->dx = pop16(cpu); '
                       'cpu->cx = pop16(cpu); cpu->ax = pop16(cpu);', orig)

        # ─── Arithmetic ───

        elif m == 'add':
            if op1.size == 1 or op1.type == OpType.REG8:
                self._emit(_write(op1,
                    f'flags_add8(cpu, {_read(op1)}, {_read(op2)})'), orig)
            else:
                self._emit(_write(op1,
                    f'flags_add16(cpu, {_read(op1)}, {_read(op2)})'), orig)

        elif m == 'adc':
            if op1.size == 1 or op1.type == OpType.REG8:
                self._emit(_write(op1,
                    f'flags_add8(cpu, {_read(op1)}, {_read(op2)} + cf(cpu))'), orig)
            else:
                self._emit(_write(op1,
                    f'flags_add16(cpu, {_read(op1)}, {_read(op2)} + cf(cpu))'), orig)

        elif m == 'sub':
            if op1.size == 1 or op1.type == OpType.REG8:
                self._emit(_write(op1,
                    f'flags_sub8(cpu, {_read(op1)}, {_read(op2)})'), orig)
            else:
                self._emit(_write(op1,
                    f'flags_sub16(cpu, {_read(op1)}, {_read(op2)})'), orig)

        elif m == 'sbb':
            if op1.size == 1 or op1.type == OpType.REG8:
                self._emit(_write(op1,
                    f'flags_sub8(cpu, {_read(op1)}, {_read(op2)} + cf(cpu))'), orig)
            else:
                self._emit(_write(op1,
                    f'flags_sub16(cpu, {_read(op1)}, {_read(op2)} + cf(cpu))'), orig)

        elif m == 'cmp':
            if op1.size == 1 or op1.type == OpType.REG8:
                self._emit(f'flags_cmp8(cpu, {_read(op1)}, {_read(op2)});', orig)
            else:
                self._emit(f'flags_cmp16(cpu, {_read(op1)}, {_read(op2)});', orig)

        elif m == 'inc':
            if op1.size == 1 or op1.type == OpType.REG8:
                self._emit(f'{{ int _cf = cf(cpu); '
                           f'{_write(op1, f"flags_add8(cpu, {_read(op1)}, 1)")} '
                           f'if (_cf) cpu->flags |= FLAG_CF; '
                           f'else cpu->flags &= ~FLAG_CF; }}', orig)
            else:
                self._emit(f'{{ int _cf = cf(cpu); '
                           f'{_write(op1, f"flags_add16(cpu, {_read(op1)}, 1)")} '
                           f'if (_cf) cpu->flags |= FLAG_CF; '
                           f'else cpu->flags &= ~FLAG_CF; }}', orig)

        elif m == 'dec':
            if op1.size == 1 or op1.type == OpType.REG8:
                self._emit(f'{{ int _cf = cf(cpu); '
                           f'{_write(op1, f"flags_sub8(cpu, {_read(op1)}, 1)")} '
                           f'if (_cf) cpu->flags |= FLAG_CF; '
                           f'else cpu->flags &= ~FLAG_CF; }}', orig)
            else:
                self._emit(f'{{ int _cf = cf(cpu); '
                           f'{_write(op1, f"flags_sub16(cpu, {_read(op1)}, 1)")} '
                           f'if (_cf) cpu->flags |= FLAG_CF; '
                           f'else cpu->flags &= ~FLAG_CF; }}', orig)

        elif m == 'neg':
            if op1.size == 1 or op1.type == OpType.REG8:
                self._emit(_write(op1, f'flags_sub8(cpu, 0, {_read(op1)})'), orig)
            else:
                self._emit(_write(op1, f'flags_sub16(cpu, 0, {_read(op1)})'), orig)

        elif m == 'mul':
            if op1.size == 1 or op1.type == OpType.REG8:
                self._emit(f'{{ uint16_t _r = (uint16_t)cpu->al * {_read(op1)}; '
                           f'cpu->ax = _r; '
                           f'cpu->flags = (cpu->flags & ~(FLAG_CF|FLAG_OF)) | '
                           f'(_r > 0xFF ? FLAG_CF|FLAG_OF : 0); }}', orig)
            else:
                self._emit(f'{{ uint32_t _r = (uint32_t)cpu->ax * {_read(op1)}; '
                           f'cpu->ax = (uint16_t)_r; cpu->dx = (uint16_t)(_r >> 16); '
                           f'cpu->flags = (cpu->flags & ~(FLAG_CF|FLAG_OF)) | '
                           f'(cpu->dx ? FLAG_CF|FLAG_OF : 0); }}', orig)

        elif m == 'imul':
            if op1.size == 1 or op1.type == OpType.REG8:
                self._emit(f'{{ int16_t _r = (int16_t)(int8_t)cpu->al * '
                           f'(int8_t){_read(op1)}; '
                           f'cpu->ax = (uint16_t)_r; '
                           f'cpu->flags = (cpu->flags & ~(FLAG_CF|FLAG_OF)) | '
                           f'((uint16_t)_r != (uint16_t)(int16_t)(int8_t)_r ? '
                           f'FLAG_CF|FLAG_OF : 0); }}', orig)
            else:
                self._emit(f'{{ int32_t _r = (int32_t)(int16_t)cpu->ax * '
                           f'(int16_t){_read(op1)}; '
                           f'cpu->ax = (uint16_t)_r; '
                           f'cpu->dx = (uint16_t)((uint32_t)_r >> 16); '
                           f'cpu->flags = (cpu->flags & ~(FLAG_CF|FLAG_OF)) | '
                           f'((uint32_t)_r != (uint32_t)(int32_t)(int16_t)_r ? '
                           f'FLAG_CF|FLAG_OF : 0); }}', orig)

        elif m == 'div':
            if op1.size == 1 or op1.type == OpType.REG8:
                self._emit(f'{{ uint16_t _n = cpu->ax; uint8_t _d = {_read(op1)}; '
                           f'cpu->al = (uint8_t)(_n / _d); '
                           f'cpu->ah = (uint8_t)(_n % _d); }}', orig)
            else:
                self._emit(f'{{ uint32_t _n = ((uint32_t)cpu->dx << 16) | cpu->ax; '
                           f'uint16_t _d = {_read(op1)}; '
                           f'cpu->ax = (uint16_t)(_n / _d); '
                           f'cpu->dx = (uint16_t)(_n % _d); }}', orig)

        elif m == 'idiv':
            if op1.size == 1 or op1.type == OpType.REG8:
                self._emit(f'{{ int16_t _n = (int16_t)cpu->ax; '
                           f'int8_t _d = (int8_t){_read(op1)}; '
                           f'cpu->al = (uint8_t)(int8_t)(_n / _d); '
                           f'cpu->ah = (uint8_t)(int8_t)(_n % _d); }}', orig)
            else:
                self._emit(f'{{ int32_t _n = (int32_t)(((uint32_t)cpu->dx << 16) '
                           f'| cpu->ax); int16_t _d = (int16_t){_read(op1)}; '
                           f'cpu->ax = (uint16_t)(int16_t)(_n / _d); '
                           f'cpu->dx = (uint16_t)(int16_t)(_n % _d); }}', orig)

        # ─── Logic ───

        elif m == 'and':
            val = f'{_read(op1)} & {_read(op2)}'
            sz = '8' if (op1.size == 1 or op1.type == OpType.REG8) else '16'
            self._emit(f'{{ uint{sz}_t _r = {val}; '
                       f'flags_logic{sz}(cpu, _r); '
                       f'{_write(op1, "_r")} }}', orig)

        elif m == 'or':
            val = f'{_read(op1)} | {_read(op2)}'
            sz = '8' if (op1.size == 1 or op1.type == OpType.REG8) else '16'
            self._emit(f'{{ uint{sz}_t _r = {val}; '
                       f'flags_logic{sz}(cpu, _r); '
                       f'{_write(op1, "_r")} }}', orig)

        elif m == 'xor':
            val = f'{_read(op1)} ^ {_read(op2)}'
            sz = '8' if (op1.size == 1 or op1.type == OpType.REG8) else '16'
            self._emit(f'{{ uint{sz}_t _r = {val}; '
                       f'flags_logic{sz}(cpu, _r); '
                       f'{_write(op1, "_r")} }}', orig)

        elif m == 'test':
            val = f'{_read(op1)} & {_read(op2)}'
            sz = '8' if (op1.size == 1 or op1.type == OpType.REG8) else '16'
            self._emit(f'flags_logic{sz}(cpu, {val});', orig)

        elif m == 'not':
            self._emit(_write(op1, f'~{_read(op1)}'), orig)

        # ─── Shifts ───

        elif m in ('shl', 'sal'):
            r = _read(op1)
            cnt = _read(op2)
            sz = '8' if (op1.size == 1 or op1.type == OpType.REG8) else '16'
            bits = 8 if sz == '8' else 16
            self._emit(f'{{ uint{sz}_t _v = {r}; uint8_t _c = {cnt}; '
                       f'uint{sz}_t _r = _v << _c; '
                       f'cpu->flags = (cpu->flags & ~FLAG_CF) | '
                       f'((_v >> ({bits} - _c)) & 1 ? FLAG_CF : 0); '
                       f'flags_shift{sz}(cpu, _r); '
                       f'{_write(op1, "_r")} }}', orig)

        elif m == 'shr':
            r = _read(op1)
            cnt = _read(op2)
            sz = '8' if (op1.size == 1 or op1.type == OpType.REG8) else '16'
            self._emit(f'{{ uint{sz}_t _v = {r}; uint8_t _c = {cnt}; '
                       f'uint{sz}_t _r = _v >> _c; '
                       f'cpu->flags = (cpu->flags & ~FLAG_CF) | '
                       f'((_v >> (_c - 1)) & 1 ? FLAG_CF : 0); '
                       f'flags_shift{sz}(cpu, _r); '
                       f'{_write(op1, "_r")} }}', orig)

        elif m == 'sar':
            r = _read(op1)
            cnt = _read(op2)
            sz = '8' if (op1.size == 1 or op1.type == OpType.REG8) else '16'
            stype = 'int8_t' if sz == '8' else 'int16_t'
            self._emit(f'{{ {stype} _v = ({stype}){r}; uint8_t _c = {cnt}; '
                       f'{stype} _r = _v >> _c; '
                       f'cpu->flags = (cpu->flags & ~FLAG_CF) | '
                       f'((_v >> (_c - 1)) & 1 ? FLAG_CF : 0); '
                       f'flags_shift{sz}(cpu, (uint{sz}_t)_r); '
                       f'{_write(op1, f"(uint{sz}_t)_r")} }}', orig)

        elif m in ('rol', 'ror', 'rcl', 'rcr'):
            # Rotate instructions - emit as helper call
            r = _read(op1)
            cnt = _read(op2)
            sz = '8' if (op1.size == 1 or op1.type == OpType.REG8) else '16'
            self._emit(f'/* TODO: {m} {r}, {cnt} */', orig)

        # ─── Control flow ───

        elif m == 'jmp':
            if op1 and op1.type in (OpType.REL8, OpType.REL16):
                target = op1.disp
                if target in self.valid_addrs:
                    self.labels_needed.add(target)
                    self._emit(f'goto {_label(target, self.func_name)};', orig)
                else:
                    self._emit(f'/* jmp out of function to 0x{target:06X} */', orig)
            elif op1 and op1.type == OpType.MEM:
                self._emit(f'/* indirect jmp via {_read(op1)} - needs dispatch */', orig)
            else:
                self._emit(f'/* jmp {repr(op1)} */', orig)

        elif m in ('jo','jno','jb','jae','je','jne','jbe','ja',
                    'js','jns','jp','jnp','jl','jge','jle','jg'):
            CC_MAP = {
                'jo': 'cc_o', 'jno': 'cc_no', 'jb': 'cc_b', 'jae': 'cc_ae',
                'je': 'cc_e', 'jne': 'cc_ne', 'jbe': 'cc_be', 'ja': 'cc_a',
                'js': 'cc_s', 'jns': 'cc_ns', 'jp': 'cc_p', 'jnp': 'cc_np',
                'jl': 'cc_l', 'jge': 'cc_ge', 'jle': 'cc_le', 'jg': 'cc_g',
            }
            target = op1.disp
            cc = CC_MAP[m]
            if target in self.valid_addrs:
                self.labels_needed.add(target)
                self._emit(f'if ({cc}(cpu)) goto {_label(target, self.func_name)};', orig)
            else:
                self._emit(f'/* {m} out of function to 0x{target:06X} */', orig)

        elif m == 'loop':
            target = op1.disp
            if target in self.valid_addrs:
                self.labels_needed.add(target)
                self._emit(f'cpu->cx--; if (cpu->cx != 0) goto {_label(target, self.func_name)};', orig)
            else:
                self._emit(f'/* loop out of function to 0x{target:06X} */', orig)

        elif m == 'loopz':
            target = op1.disp
            if target in self.valid_addrs:
                self.labels_needed.add(target)
                self._emit(f'cpu->cx--; if (cpu->cx != 0 && zf(cpu)) '
                           f'goto {_label(target, self.func_name)};', orig)
            else:
                self._emit(f'/* loopz out of function to 0x{target:06X} */', orig)

        elif m == 'loopnz':
            target = op1.disp
            if target in self.valid_addrs:
                self.labels_needed.add(target)
                self._emit(f'cpu->cx--; if (cpu->cx != 0 && !zf(cpu)) '
                           f'goto {_label(target, self.func_name)};', orig)
            else:
                self._emit(f'/* loopnz out of function to 0x{target:06X} */', orig)

        elif m == 'jcxz':
            target = op1.disp
            if target in self.valid_addrs:
                self.labels_needed.add(target)
                self._emit(f'if (cpu->cx == 0) goto {_label(target, self.func_name)};', orig)
            else:
                self._emit(f'/* jcxz out of function to 0x{target:06X} */', orig)

        elif m == 'call':
            if op1 and op1.type == OpType.REL16:
                target = func_start + op1.disp
                # Look up known function name at this address
                if target in self.known_funcs:
                    func_name = self.known_funcs[target]
                else:
                    func_name = f'res_{target:06X}'
                self.func_calls.add(func_name)
                # Simulate NEAR CALL: push 2-byte return IP on CPU stack
                self._emit(f'push16(cpu, 0);', f'near call return addr')
                self._emit(f'{func_name}(cpu);', orig)
            elif op1 and op1.type == OpType.FAR:
                # Resolve far call segment:offset to a known function.
                # CIV.EXE has NO MZ relocations - the MSC overlay manager
                # patches segment values at runtime. The linker-assigned
                # segments need a correction to map to file offsets:
                #   file_off = seg*16 + off - 0x14  (most segments)
                #   file_off = seg*16 + off - 0x1A  (segment 0x205A)
                # We try both corrected and uncorrected formulas.
                func_name = None
                seg = op1.far_seg
                off = op1.disp
                # Try corrected formula (seg-specific adjustment)
                corr = 0x1A if seg == 0x205A else 0x14
                far_file_off = seg * 16 + off - corr
                if far_file_off in self.known_funcs:
                    func_name = self.known_funcs[far_file_off]
                else:
                    # Try original formula (hdr_size + seg*16 + off)
                    far_file_off2 = self.hdr_size + seg * 16 + off
                    if far_file_off2 in self.known_funcs:
                        func_name = self.known_funcs[far_file_off2]
                if not func_name:
                    func_name = f'far_{seg:04X}_{off:04X}'
                self.func_calls.add(func_name)
                # Simulate FAR CALL: push 4-byte return CS:IP on CPU stack
                self._emit(f'push16(cpu, cpu->cs); push16(cpu, 0);', f'far call return addr')
                self._emit(f'{func_name}(cpu);', orig)
            else:
                self._emit(f'/* indirect call {repr(op1)} - needs dispatch */', orig)

        elif m == 'ret':
            # Simulate NEAR RET: pop 2-byte return IP + optional extra bytes
            if op1:
                total = op1.disp + 2
                self._emit(f'cpu->sp += 0x{total:X}; return;', orig)
            else:
                self._emit('cpu->sp += 2; return;', orig)

        elif m == 'retf':
            # Simulate FAR RETF: pop 4-byte return CS:IP + optional extra bytes
            if op1:
                total = op1.disp + 4
                self._emit(f'cpu->sp += 0x{total:X}; return;', orig)
            else:
                self._emit('cpu->sp += 4; return;', orig)

        elif m == 'int':
            int_num = op1.disp
            if int_num == 0x3F and inst.overlay_num >= 0:
                # Overlay call - resolved to direct function call (far call semantics)
                # Compute absolute file offset from overlay base + relative offset
                ovl_num = inst.overlay_num
                ovl_off = inst.overlay_off
                if ovl_num in self.overlay_bases:
                    abs_addr = self.overlay_bases[ovl_num] + ovl_off
                    func_name = f'ovl{ovl_num:02d}_{abs_addr:06X}'
                else:
                    func_name = f'ovl{ovl_num:02d}_{ovl_off:04X}'
                self.ovl_calls.add(func_name)
                # Simulate FAR CALL for overlay dispatch
                self._emit(f'push16(cpu, cpu->cs); push16(cpu, 0);',
                           f'overlay far call return addr')
                self._emit(f'{func_name}(cpu);',
                           f'INT 3Fh -> OVL {ovl_num:02X}:{ovl_off:04X}')
            elif int_num == 0x21:
                self._emit(f'dos_int21(cpu);', orig)
            elif int_num == 0x10:
                self._emit(f'bios_int10(cpu);', orig)
            elif int_num == 0x16:
                self._emit(f'bios_int16(cpu);', orig)
            elif int_num == 0x33:
                self._emit(f'mouse_int33(cpu);', orig)
            else:
                self._emit(f'int_handler(cpu, 0x{int_num:02X});', orig)

        # ─── String ops ───

        elif m == 'movsb':
            self._emit(f'mem_write8(cpu, cpu->es, cpu->di, '
                       f'mem_read8(cpu, cpu->ds, cpu->si)); '
                       f'cpu->si += df(cpu) ? -1 : 1; '
                       f'cpu->di += df(cpu) ? -1 : 1;', orig)

        elif m == 'movsw':
            self._emit(f'mem_write16(cpu, cpu->es, cpu->di, '
                       f'mem_read16(cpu, cpu->ds, cpu->si)); '
                       f'cpu->si += df(cpu) ? -2 : 2; '
                       f'cpu->di += df(cpu) ? -2 : 2;', orig)

        elif m == 'stosb':
            self._emit(f'mem_write8(cpu, cpu->es, cpu->di, cpu->al); '
                       f'cpu->di += df(cpu) ? -1 : 1;', orig)

        elif m == 'stosw':
            self._emit(f'mem_write16(cpu, cpu->es, cpu->di, cpu->ax); '
                       f'cpu->di += df(cpu) ? -2 : 2;', orig)

        elif m == 'lodsb':
            self._emit(f'cpu->al = mem_read8(cpu, cpu->ds, cpu->si); '
                       f'cpu->si += df(cpu) ? -1 : 1;', orig)

        elif m == 'lodsw':
            self._emit(f'cpu->ax = mem_read16(cpu, cpu->ds, cpu->si); '
                       f'cpu->si += df(cpu) ? -2 : 2;', orig)

        elif m == 'scasb':
            self._emit(f'flags_cmp8(cpu, cpu->al, mem_read8(cpu, cpu->es, cpu->di)); '
                       f'cpu->di += df(cpu) ? -1 : 1;', orig)

        elif m == 'scasw':
            self._emit(f'flags_cmp16(cpu, cpu->ax, mem_read16(cpu, cpu->es, cpu->di)); '
                       f'cpu->di += df(cpu) ? -2 : 2;', orig)

        elif m == 'cmpsb':
            self._emit(f'flags_cmp8(cpu, mem_read8(cpu, cpu->ds, cpu->si), '
                       f'mem_read8(cpu, cpu->es, cpu->di)); '
                       f'cpu->si += df(cpu) ? -1 : 1; '
                       f'cpu->di += df(cpu) ? -1 : 1;', orig)

        elif m == 'cmpsw':
            self._emit(f'flags_cmp16(cpu, mem_read16(cpu, cpu->ds, cpu->si), '
                       f'mem_read16(cpu, cpu->es, cpu->di)); '
                       f'cpu->si += df(cpu) ? -2 : 2; '
                       f'cpu->di += df(cpu) ? -2 : 2;', orig)

        # ─── Flags ───

        elif m == 'clc': self._emit('cpu->flags &= ~FLAG_CF;', orig)
        elif m == 'stc': self._emit('cpu->flags |= FLAG_CF;', orig)
        elif m == 'cmc': self._emit('cpu->flags ^= FLAG_CF;', orig)
        elif m == 'cld': self._emit('cpu->flags &= ~FLAG_DF;', orig)
        elif m == 'std': self._emit('cpu->flags |= FLAG_DF;', orig)
        elif m == 'cli': self._emit('cpu->flags &= ~FLAG_IF;', orig)
        elif m == 'sti': self._emit('cpu->flags |= FLAG_IF;', orig)

        elif m == 'sahf':
            self._emit('cpu->flags = (cpu->flags & 0xFF00) | cpu->ah;', orig)
        elif m == 'lahf':
            self._emit('cpu->ah = (uint8_t)(cpu->flags & 0xFF);', orig)

        # ─── Misc ───

        elif m == 'nop':
            self._emit('/* nop */', orig)

        elif m == 'xlat':
            self._emit('cpu->al = mem_read8(cpu, cpu->ds, '
                       '(uint16_t)(cpu->bx + cpu->al));', orig)

        elif m == 'hlt':
            self._emit('cpu->halted = 1; return;', orig)

        elif m == 'iret':
            self._emit('/* iret - return from interrupt */', orig)
            self._emit('return;')

        elif m == 'enter':
            size_val = op1.disp
            self._emit(f'push16(cpu, cpu->bp); cpu->bp = cpu->sp; '
                       f'cpu->sp -= 0x{size_val:X};', orig)

        elif m == 'leave':
            self._emit('cpu->sp = cpu->bp; cpu->bp = pop16(cpu);', orig)

        elif m == 'in':
            if op2 and op2.type == OpType.IMM8:
                port_expr = f'0x{op2.disp & 0xFF:02X}'
            else:
                port_expr = _read(op2) if op2 else 'cpu->dx'
            self._emit(_write(op1, f'port_in8(cpu, {port_expr})'), orig)

        elif m == 'out':
            if op1 and op1.type == OpType.IMM8:
                port_expr = f'0x{op1.disp & 0xFF:02X}'
            else:
                port_expr = _read(op1) if op1 else 'cpu->dx'
            val_expr = _read(op2) if op2 else 'cpu->al'
            self._emit(f'port_out8(cpu, {port_expr}, {val_expr});', orig)

        elif m == 'wait':
            self._emit('/* wait */', orig)

        elif m.startswith('esc_'):
            self._emit(f'/* FPU: {orig} */', orig)

        elif m == 'db':
            self._emit(f'/* data byte: 0x{op1.disp:02X} */', orig)

        elif m.startswith('daa') or m.startswith('das') or \
             m.startswith('aaa') or m.startswith('aas') or \
             m.startswith('aam') or m.startswith('aad'):
            self._emit(f'/* BCD: {orig} - stub */', orig)

        else:
            self._emit(f'/* UNHANDLED: {orig} */', orig)

    def lift_function(self, name: str, instructions: list, func_start: int,
                      is_far: bool = False) -> str:
        """Lift an entire function to C code."""
        self.output = []
        self.labels_needed = set()
        self.func_calls = set()
        self.ovl_calls = set()
        self.func_name = name
        self.indent = 1

        # Build set of valid instruction addresses for this function
        self.valid_addrs = set(inst.address for inst in instructions)

        # First pass: collect jump targets for labels (only within function)
        for inst in instructions:
            m = inst.mnemonic
            if m in ('jmp', 'jo','jno','jb','jae','je','jne','jbe','ja',
                     'js','jns','jp','jnp','jl','jge','jle','jg',
                     'loop', 'loopz', 'loopnz', 'jcxz'):
                if inst.op1 and inst.op1.type in (OpType.REL8, OpType.REL16):
                    target = inst.op1.disp
                    if target in self.valid_addrs:
                        self.labels_needed.add(target)

        # Second pass: generate C code
        self.output.append(f'void {name}(CPU *cpu)')
        self.output.append('{')

        for inst in instructions:
            if inst.prefix == 'rep' and inst.mnemonic in ('movsb','movsw','stosb','stosw'):
                self._emit_label(inst.address)
                self._emit(f'while (cpu->cx != 0) {{ cpu->cx--;', f'rep {inst.mnemonic}')
                self.indent += 1
                # Emit the string op body (set address to -1 to avoid duplicate label)
                stripped = Instruction()
                stripped.__dict__.update(inst.__dict__)
                stripped.prefix = ''
                stripped.address = -1
                self.lift_instruction(stripped, func_start)
                self.indent -= 1
                self._emit('}')
            elif inst.prefix == 'rep' and inst.mnemonic in ('scasb','scasw','cmpsb','cmpsw'):
                self._emit_label(inst.address)
                self._emit(f'while (cpu->cx != 0) {{ cpu->cx--;', f'repz {inst.mnemonic}')
                self.indent += 1
                stripped = Instruction()
                stripped.__dict__.update(inst.__dict__)
                stripped.prefix = ''
                stripped.address = -1
                self.lift_instruction(stripped, func_start)
                self._emit('if (!zf(cpu)) break;')
                self.indent -= 1
                self._emit('}')
            elif inst.prefix == 'repnz' and inst.mnemonic in ('scasb','scasw','cmpsb','cmpsw'):
                self._emit_label(inst.address)
                self._emit(f'while (cpu->cx != 0) {{ cpu->cx--;', f'repnz {inst.mnemonic}')
                self.indent += 1
                stripped = Instruction()
                stripped.__dict__.update(inst.__dict__)
                stripped.prefix = ''
                stripped.address = -1
                self.lift_instruction(stripped, func_start)
                self._emit('if (zf(cpu)) break;')
                self.indent -= 1
                self._emit('}')
            else:
                self.lift_instruction(inst, func_start)

        self.output.append('}')

        return '\n'.join(self.output)

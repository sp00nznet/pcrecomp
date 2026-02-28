"""
Fast code generation using linear sweep disassembly.

Instead of recursive descent per function (slow), this uses a single linear
sweep through the entire code section and splits by known function boundaries.
"""

import sys
import os
import time
import json
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.pe_analyze import analyze_pe, build_iat_map
from tools.lifter import Lifter
from capstone import Cs, CS_ARCH_X86, CS_MODE_32


COND_JUMPS = {
    'je', 'jne', 'jz', 'jnz', 'ja', 'jae', 'jb', 'jbe',
    'jg', 'jge', 'jl', 'jle', 'js', 'jns', 'jo', 'jno',
    'jp', 'jnp', 'jcxz', 'jecxz',
}


class LinearInstruction:
    """Lightweight instruction wrapper matching the Lifter's expected interface."""
    __slots__ = ['address', 'size', 'mnemonic', 'op_str', 'bytes', 'operands',
                 'is_call', 'is_ret', 'is_cond_jump', 'is_uncond_jump', 'is_jump']

    def __init__(self, insn):
        self.address = insn.address
        self.size = insn.size
        self.mnemonic = insn.mnemonic
        self.op_str = insn.op_str
        self.bytes = bytes(insn.bytes)
        self.operands = list(insn.operands) if insn.operands else []
        self.is_call = insn.mnemonic == 'call'
        self.is_ret = insn.mnemonic in ('ret', 'retn', 'retf')
        self.is_cond_jump = insn.mnemonic in COND_JUMPS
        self.is_uncond_jump = insn.mnemonic == 'jmp'
        self.is_jump = self.is_cond_jump or self.is_uncond_jump

    @property
    def end_address(self):
        return self.address + self.size

    def get_branch_target(self):
        from capstone.x86 import X86_OP_IMM
        if self.operands:
            op = self.operands[0]
            if op.type == X86_OP_IMM:
                return op.imm & 0xFFFFFFFF
        return None

    def __repr__(self):
        return f"0x{self.address:08X}: {self.mnemonic} {self.op_str}"


def find_entries(code_data, code_start, code_end):
    """Find function entry points via call target + prologue scanning."""
    call_targets = set()
    for i in range(len(code_data) - 5):
        if code_data[i] == 0xE8:
            rel = struct.unpack_from('<i', code_data, i + 1)[0]
            target = (code_start + i + 5 + rel) & 0xFFFFFFFF
            if code_start <= target < code_end:
                call_targets.add(target)

    prologues = set()
    for i in range(len(code_data) - 3):
        if code_data[i:i+3] == b'\x55\x8B\xEC':
            prologues.add(code_start + i)
        # sub esp, imm8 after padding
        if i > 0 and code_data[i-1] in (0xCC, 0x90, 0xC3):
            if code_data[i] == 0x83 and code_data[i+1] == 0xEC:
                prologues.add(code_start + i)

    return sorted(call_targets | prologues)


def linear_disassemble_function(md, code_data, code_start, func_start, func_end):
    """
    Disassemble a function using linear sweep between known boundaries.
    Returns list of LinearInstruction and set of basic block leaders.
    """
    offset = func_start - code_start
    size = func_end - func_start
    if offset < 0 or offset + size > len(code_data):
        return [], set()

    raw = code_data[offset:offset + size]
    instructions = []
    leaders = {func_start}  # First instruction is always a leader

    for insn in md.disasm(raw, func_start):
        li = LinearInstruction(insn)
        instructions.append(li)

        if li.is_cond_jump:
            target = li.get_branch_target()
            if target and func_start <= target < func_end:
                leaders.add(target)
            leaders.add(li.end_address)  # fallthrough
        elif li.is_uncond_jump:
            target = li.get_branch_target()
            if target and func_start <= target < func_end:
                leaders.add(target)
            # Next instruction (if any) is a new leader
            leaders.add(li.end_address)

        # Stop at int3 / padding
        if li.mnemonic == 'int3':
            break

    return instructions, leaders


def lift_function_linear(lifter, name, instructions, leaders, func_start):
    """Lift a linearly-disassembled function to C code."""
    lines = []
    lines.append(f'void {name}(void) {{')
    lines.append(f'    uint32_t ebp = 0;')
    lines.append(f'    double _st[8] = {{0}};')
    lines.append(f'    int _fp_top = 0;')
    lines.append(f'    int _fpu_cmp = 0;')
    lines.append(f'    uint32_t _cf = 0;')
    lines.append(f'    int _df = 1;')
    lines.append(f'    uint16_t _fpu_cw = 0x037F;')
    lines.append(f'')

    lifter._flag_state = None

    for insn in instructions:
        # Emit label if this is a block leader
        if insn.address in leaders:
            lines.append(f'L_{insn.address:08X}:')

        # Lift the instruction
        lifted = lifter.lift_instruction(insn)
        for line in lifted:
            lines.append(f'    {line}')

    # Ensure function doesn't fall off the end without return
    if instructions and not instructions[-1].is_ret:
        lines.append('    return; /* end of function */')

    lines.append('}')
    return '\n'.join(lines)


def write_chunk(output_dir, file_idx, funcs):
    """Write function code to a source file."""
    filename = f'recomp_{file_idx:04d}.c'
    filepath = os.path.join(output_dir, filename)
    with open(filepath, 'w') as f:
        f.write('/* Auto-generated by XWA recompiler - DO NOT EDIT */\n')
        f.write(f'/* File {file_idx}: {len(funcs)} functions */\n\n')
        f.write('#define RECOMP_GENERATED_CODE\n')
        f.write('#include "recomp_types.h"\n')
        f.write('#include "recomp_funcs.h"\n')
        f.write('#include <math.h>\n')
        f.write('#include <string.h>\n\n')
        for code, addr, name in funcs:
            f.write(code)
            f.write('\n\n')


def main():
    exe_path = sys.argv[1] if len(sys.argv) > 1 else 'config/xwingalliance_decrypted.exe'
    output_dir = sys.argv[2] if len(sys.argv) > 2 else 'src/game/recomp/gen'
    split_size = int(sys.argv[3]) if len(sys.argv) > 3 else 500

    os.makedirs(output_dir, exist_ok=True)

    print(f'[*] Loading PE: {exe_path}', flush=True)
    info = analyze_pe(exe_path)
    iat_map = build_iat_map(info)

    with open(exe_path, 'rb') as f:
        pe_data = f.read()

    code_start = info.code_start
    code_end = info.code_end

    # Read code section
    text_sect = [s for s in info.sections if s.name == '.text'][0]
    offset = text_sect.raw_offset
    size = min(text_sect.virtual_size, text_sect.raw_size)
    code_data = pe_data[offset:offset + size]
    print(f'[*] Code: 0x{code_start:08X}-0x{code_end:08X} ({len(code_data):,} bytes)', flush=True)

    # Phase 1: Find entries
    print('[*] Phase 1: Finding function entries...', flush=True)
    entries = find_entries(code_data, code_start, code_end)
    print(f'[*] Found {len(entries)} function entries', flush=True)

    # Phase 2: Disassemble + lift
    print('[*] Phase 2: Disassembling and lifting...', flush=True)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    lifter = Lifter(iat_map=iat_map)

    all_entries = []
    func_stats = []
    error_count = 0
    file_idx = 0
    chunk_funcs = []
    start = time.time()

    for idx, addr in enumerate(entries):
        # Function end = next entry or code end (cap at 64KB)
        if idx + 1 < len(entries):
            func_end = min(entries[idx + 1], addr + 65536)
        else:
            func_end = min(code_end, addr + 65536)

        if func_end - addr < 2:
            continue

        name = f'sub_{addr:08X}'

        try:
            instructions, leaders = linear_disassemble_function(
                md, code_data, code_start, addr, func_end)

            if not instructions:
                continue

            # Trim: stop at first int3, and skip garbage after ret
            # unless a label follows (which indicates a reachable block)
            trimmed = []
            seen_ret = False
            for insn in instructions:
                if insn.mnemonic == 'int3':
                    break
                # After a ret, only continue if this address is a jump target
                if seen_ret:
                    if insn.address not in leaders:
                        continue  # skip garbage between ret and next label
                    seen_ret = False  # found a label, resume
                trimmed.append(insn)
                if insn.is_ret:
                    seen_ret = True
            if not trimmed:
                continue

            code = lift_function_linear(lifter, name, trimmed, leaders, addr)
            chunk_funcs.append((code, addr, name))
            all_entries.append((addr, name))

            func_stats.append({
                'address': f'0x{addr:08X}',
                'address_int': addr,
                'name': name,
                'num_instructions': len(trimmed),
            })

        except Exception as e:
            stub = f'/* ERROR: {name} at 0x{addr:08X}: {e} */\nvoid {name}(void) {{ /* error */ }}\n'
            chunk_funcs.append((stub, addr, name))
            all_entries.append((addr, name))
            error_count += 1

        # Write chunk
        if len(chunk_funcs) >= split_size:
            write_chunk(output_dir, file_idx, chunk_funcs)
            elapsed = time.time() - start
            rate = len(all_entries) / elapsed if elapsed > 0 else 0
            print(f'[*] {len(all_entries)}/{len(entries)} functions '
                  f'({file_idx + 1} files, {rate:.0f}/s, {error_count} err)', flush=True)
            file_idx += 1
            chunk_funcs = []

    # Write remaining
    if chunk_funcs:
        write_chunk(output_dir, file_idx, chunk_funcs)
        file_idx += 1

    # Phase 3: Header + dispatch
    print('[*] Phase 3: Generating header and dispatch table...', flush=True)

    header_path = os.path.join(output_dir, 'recomp_funcs.h')
    with open(header_path, 'w') as f:
        f.write('#pragma once\n#include <stdint.h>\n\n')
        f.write(f'/* {len(all_entries)} recompiled functions */\n\n')
        for addr, name in all_entries:
            f.write(f'void {name}(void);  /* 0x{addr:08X} */\n')

    dispatch_path = os.path.join(output_dir, 'recomp_dispatch.c')
    with open(dispatch_path, 'w') as f:
        f.write('#include "recomp_types.h"\n')
        f.write('#include "recomp_funcs.h"\n\n')
        f.write('const recomp_dispatch_entry_t recomp_dispatch_table[] = {\n')
        for addr, name in sorted(all_entries, key=lambda x: x[0]):
            f.write(f'    {{ 0x{addr:08X}u, {name} }},\n')
        f.write('};\n\n')
        f.write(f'const uint32_t recomp_dispatch_count = {len(all_entries)};\n')

    # Export function list
    with open('config/functions.json', 'w') as f:
        json.dump(func_stats, f, indent=2)

    elapsed = time.time() - start
    total_lines = 0
    total_bytes = 0
    for fn in os.listdir(output_dir):
        fp = os.path.join(output_dir, fn)
        if os.path.isfile(fp):
            total_bytes += os.path.getsize(fp)
            with open(fp, 'r') as f:
                total_lines += sum(1 for _ in f)

    print(f'\n[*] === COMPLETE ===', flush=True)
    print(f'[*] {len(all_entries)} functions recompiled', flush=True)
    print(f'[*] {file_idx} source files + header + dispatch', flush=True)
    print(f'[*] {error_count} errors', flush=True)
    print(f'[*] {total_lines:,} total lines of C', flush=True)
    print(f'[*] {total_bytes / 1048576:.1f} MB of generated code', flush=True)
    print(f'[*] Time: {elapsed:.1f}s', flush=True)


if __name__ == '__main__':
    main()

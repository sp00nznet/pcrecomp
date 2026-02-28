"""
x86-32 Disassembler for XWA static recompilation.
Uses Capstone to disassemble code, build basic blocks, and identify
function boundaries via recursive descent.
"""

import struct
from dataclasses import dataclass, field
from typing import Optional
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_INT
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG


# Conditional jump mnemonics
COND_JUMPS = {
    'je', 'jne', 'jz', 'jnz', 'ja', 'jae', 'jb', 'jbe',
    'jg', 'jge', 'jl', 'jle', 'js', 'jns', 'jo', 'jno',
    'jp', 'jnp', 'jcxz', 'jecxz',
}

# Unconditional jump
UNCOND_JUMPS = {'jmp'}

# Call instructions
CALLS = {'call'}

# Return instructions
RETS = {'ret', 'retn', 'retf'}


@dataclass
class Instruction:
    address: int
    size: int
    mnemonic: str
    op_str: str
    bytes: bytes
    operands: list = None  # Capstone operand list

    @property
    def is_call(self) -> bool:
        return self.mnemonic in CALLS

    @property
    def is_ret(self) -> bool:
        return self.mnemonic in RETS

    @property
    def is_cond_jump(self) -> bool:
        return self.mnemonic in COND_JUMPS

    @property
    def is_uncond_jump(self) -> bool:
        return self.mnemonic in UNCOND_JUMPS

    @property
    def is_jump(self) -> bool:
        return self.is_cond_jump or self.is_uncond_jump

    @property
    def is_terminator(self) -> bool:
        return self.is_ret or self.is_jump

    @property
    def end_address(self) -> int:
        return self.address + self.size

    def get_branch_target(self) -> Optional[int]:
        """Get the immediate branch/call target, or None for indirect."""
        if self.operands:
            op = self.operands[0]
            if op.type == X86_OP_IMM:
                return op.imm & 0xFFFFFFFF
        return None

    def get_mem_operand(self) -> Optional[tuple]:
        """Get memory operand details (base_reg, index_reg, scale, disp)."""
        if self.operands:
            for op in self.operands:
                if op.type == X86_OP_MEM:
                    return (op.mem.base, op.mem.index, op.mem.scale, op.mem.disp)
        return None

    def __repr__(self):
        return f"0x{self.address:08X}: {self.mnemonic} {self.op_str}"


@dataclass
class BasicBlock:
    start: int
    end: int  # address past last instruction
    instructions: list = field(default_factory=list)
    successors: list = field(default_factory=list)  # target addresses
    is_exit: bool = False  # ends with ret

    @property
    def last_insn(self) -> Optional[Instruction]:
        return self.instructions[-1] if self.instructions else None


@dataclass
class Function:
    address: int
    end: int = 0
    name: str = ""
    blocks: dict = field(default_factory=dict)  # addr -> BasicBlock
    calls_to: set = field(default_factory=set)  # addresses this function calls
    called_from: set = field(default_factory=set)  # addresses that call this function
    is_thunk: bool = False  # single-jmp wrapper
    size: int = 0

    @property
    def num_instructions(self) -> int:
        return sum(len(b.instructions) for b in self.blocks.values())


class Disassembler:
    def __init__(self, pe_data: bytes, image_base: int, sections: list):
        """
        pe_data: raw bytes of the PE file
        image_base: PE image base address
        sections: list of Section objects from pe_analyze
        """
        self.pe_data = pe_data
        self.image_base = image_base
        self.sections = sections
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True

        # Build VA -> file offset cache for code sections
        # adj = raw_offset - va_start, so file_offset = va + adj
        self._code_sections = [(s.virtual_address + image_base,
                                s.virtual_address + image_base + s.raw_size,
                                s.raw_offset - (s.virtual_address + image_base))
                               for s in sections if s.is_code and s.name != '.bind']

    def is_code_address(self, va: int) -> bool:
        """Check if a VA falls within a code section."""
        for start, end, _ in self._code_sections:
            if start <= va < end:
                return True
        return False

    def is_data_address(self, va: int) -> bool:
        """Check if a VA falls within any non-code section."""
        rva = va - self.image_base
        for s in self.sections:
            if not s.is_code and s.virtual_address <= rva < s.virtual_address + s.virtual_size:
                return True
        return False

    def _va_to_offset(self, va: int) -> Optional[int]:
        """Convert VA to file offset within code sections."""
        for start, end, adj in self._code_sections:
            if start <= va < end:
                return va + adj
        return None

    def read_bytes(self, va: int, size: int) -> Optional[bytes]:
        """Read raw bytes at a VA."""
        offset = self._va_to_offset(va)
        if offset is None:
            # Try data sections too
            rva = va - self.image_base
            for s in self.sections:
                if s.virtual_address <= rva < s.virtual_address + s.raw_size:
                    fo = s.raw_offset + (rva - s.virtual_address)
                    return self.pe_data[fo:fo + size]
            return None
        return self.pe_data[offset:offset + size]

    def disassemble_at(self, va: int, max_bytes: int = 4096) -> list:
        """Disassemble instructions starting at VA."""
        data = self.read_bytes(va, max_bytes)
        if data is None:
            return []

        instructions = []
        for insn in self.md.disasm(data, va):
            instructions.append(Instruction(
                address=insn.address,
                size=insn.size,
                mnemonic=insn.mnemonic,
                op_str=insn.op_str,
                bytes=bytes(insn.bytes),
                operands=list(insn.operands) if insn.operands else [],
            ))
        return instructions

    def disassemble_function(self, start_va: int, iat_map: dict = None) -> Optional[Function]:
        """
        Disassemble a complete function using recursive descent from start_va.
        Returns a Function with fully built basic blocks and CFG.
        """
        if not self.is_code_address(start_va):
            return None

        func = Function(address=start_va, name=f"sub_{start_va:08X}")
        visited = set()
        work = [start_va]
        block_leaders = {start_va}

        # Pass 1: discover all block leaders
        while work:
            addr = work.pop()
            if addr in visited or not self.is_code_address(addr):
                continue
            visited.add(addr)

            insns = self.disassemble_at(addr, max_bytes=8192)
            for insn in insns:
                if insn.is_call:
                    target = insn.get_branch_target()
                    if target and self.is_code_address(target):
                        func.calls_to.add(target)
                    # After call, next instruction is a new leader (fallthrough)
                    # but within the same function
                    continue

                if insn.is_cond_jump:
                    target = insn.get_branch_target()
                    if target and self.is_code_address(target):
                        # Target within reasonable distance is likely same function
                        if abs(target - start_va) < 0x100000:
                            block_leaders.add(target)
                            if target not in visited:
                                work.append(target)
                    # Fallthrough is also a leader
                    fallthrough = insn.end_address
                    block_leaders.add(fallthrough)
                    if fallthrough not in visited:
                        work.append(fallthrough)
                    break  # end this linear scan

                if insn.is_uncond_jump:
                    target = insn.get_branch_target()
                    if target and self.is_code_address(target):
                        if abs(target - start_va) < 0x100000:
                            block_leaders.add(target)
                            if target not in visited:
                                work.append(target)
                    break  # end this linear scan

                if insn.is_ret:
                    break  # end this linear scan

                # Check for int 3 (padding/alignment)
                if insn.mnemonic == 'int3':
                    break

        # Pass 2: build basic blocks
        all_leaders = sorted(block_leaders)
        for leader in all_leaders:
            if not self.is_code_address(leader):
                continue

            block = BasicBlock(start=leader, end=leader)
            insns = self.disassemble_at(leader, max_bytes=4096)

            for insn in insns:
                # If we hit another block leader (not our start), stop
                if insn.address != leader and insn.address in block_leaders:
                    block.successors.append(insn.address)
                    break

                block.instructions.append(insn)
                block.end = insn.end_address

                if insn.is_ret:
                    block.is_exit = True
                    break

                if insn.is_cond_jump:
                    target = insn.get_branch_target()
                    if target:
                        block.successors.append(target)
                    block.successors.append(insn.end_address)  # fallthrough
                    break

                if insn.is_uncond_jump:
                    target = insn.get_branch_target()
                    if target:
                        block.successors.append(target)
                    else:
                        # Indirect jump - could be switch table
                        pass
                    break

                if insn.mnemonic == 'int3':
                    block.is_exit = True
                    break

            if block.instructions:
                func.blocks[leader] = block

        # Calculate function end
        if func.blocks:
            func.end = max(b.end for b in func.blocks.values())
            func.size = func.end - func.address

        return func

    def find_call_targets(self, start_va: int, end_va: int) -> set:
        """
        Linear scan through code to find all CALL targets.
        This is a quick heuristic pass before recursive descent.
        """
        targets = set()
        data = self.read_bytes(start_va, end_va - start_va)
        if data is None:
            return targets

        offset = 0
        while offset < len(data) - 5:
            # Look for E8 xx xx xx xx (near call)
            if data[offset] == 0xE8:
                rel = struct.unpack_from('<i', data, offset + 1)[0]
                target = (start_va + offset + 5 + rel) & 0xFFFFFFFF
                if self.is_code_address(target):
                    targets.add(target)
                offset += 5
            else:
                offset += 1

        return targets

    def find_functions(self, code_start: int, code_end: int, iat_map: dict = None) -> dict:
        """
        Find all functions in the code section.
        Uses call target analysis + common prologue patterns.
        Returns dict of addr -> Function.
        """
        print(f"[*] Scanning for call targets in 0x{code_start:08X}-0x{code_end:08X}...")
        call_targets = self.find_call_targets(code_start, code_end)
        print(f"[*] Found {len(call_targets)} potential call targets")

        # Also look for common function prologues
        prologue_targets = set()
        data = self.read_bytes(code_start, code_end - code_start)
        if data:
            for offset in range(len(data) - 3):
                va = code_start + offset
                # push ebp; mov ebp, esp (55 8B EC)
                if data[offset:offset + 3] == b'\x55\x8B\xEC':
                    prologue_targets.add(va)
                # push ebp; mov ebp, esp with sub esp (55 8B EC 83 EC)
                # Also push esi; push edi patterns after push ebp

        print(f"[*] Found {len(prologue_targets)} prologue patterns")

        # Merge targets
        all_targets = call_targets | prologue_targets
        # Filter to code range
        all_targets = {t for t in all_targets if code_start <= t < code_end}
        print(f"[*] Total unique function candidates: {len(all_targets)}")

        # Disassemble each function
        functions = {}
        sorted_targets = sorted(all_targets)
        total = len(sorted_targets)

        for i, addr in enumerate(sorted_targets):
            if i % 1000 == 0 and i > 0:
                print(f"[*] Disassembling function {i}/{total}...")

            func = self.disassemble_function(addr, iat_map)
            if func and func.blocks:
                functions[addr] = func

                # Check for thunks (single jmp instruction)
                if len(func.blocks) == 1:
                    block = list(func.blocks.values())[0]
                    if len(block.instructions) == 1 and block.instructions[0].is_uncond_jump:
                        func.is_thunk = True

        print(f"[*] Successfully disassembled {len(functions)} functions")
        return functions

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

    def find_data_code_pointers(self, code_start: int, code_end: int,
                                covered: set, queued: set) -> set:
        """Function pointers that exist only in data.

        A vtable slot, a callback table or a message-handler array can hold the
        only reference to a function: no CALL names it, so recursive descent
        never reaches it and it surfaces at runtime as an unresolved ICALL.
        Scan every byte offset of each non-code section for values landing in
        the code range and not already part of decoded code. Unaligned on
        purpose: packed struct arrays put function pointers at odd addresses
        (GTA1's handler table starts at 0x4B4AD1), and an aligned-only scan
        misses them entirely. False positives just become dead functions --
        harmless now that out-of-function branches tail-dispatch.
        """
        found = set()
        for s in self.sections:
            if s.is_code:
                continue
            base = self.image_base + s.virtual_address
            data = self.read_bytes(base, s.raw_size)
            if not data:
                continue
            for off in range(len(data) - 3):
                va = int.from_bytes(data[off:off + 4], 'little')
                if not (code_start <= va < code_end):
                    continue
                if va in covered or va in queued:
                    continue
                found.add(va)
        return found

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

        # Disassemble each function. Then iterate to a fixpoint, following
        # unconditional-jmp and call targets that land on code not yet covered by
        # any discovered function (tail calls and jmp-thunk chains reach functions
        # that no direct CALL targets and that lack a standard prologue, e.g. a
        # thunk `jmp X` -> X, where X starts with `cmp`/`test`). Without this they
        # are silently missing and show up at runtime as unresolved ITAIL/ICALL.
        functions = {}
        covered = set()          # every instruction start address across all funcs
        queue = list(all_targets)
        queued = set(all_targets)

        def _add_func(addr):
            func = self.disassemble_function(addr, iat_map)
            if not (func and func.blocks):
                return None
            functions[addr] = func
            if len(func.blocks) == 1:
                block = next(iter(func.blocks.values()))
                if len(block.instructions) == 1 and block.instructions[0].is_uncond_jump:
                    func.is_thunk = True
            for b in func.blocks.values():
                for ins in b.instructions:
                    covered.add(ins.address)
            return func

        round_no = 0
        data_scanned = False
        while True:
          while queue:
              round_no += 1
              sorted_targets = sorted(queue)
              queue = []
              total = len(sorted_targets)
              if round_no == 1:
                  print(f"[*] Disassembling {total} initial candidates...")
              else:
                  print(f"[*] Discovery round {round_no}: {total} new jmp/call targets...")
              for i, addr in enumerate(sorted_targets):
                  if round_no == 1 and i % 1000 == 0 and i > 0:
                      print(f"[*] Disassembling function {i}/{total}...")
                  if addr in functions:
                      continue
                  _add_func(addr)

              # Harvest jmp/call immediate targets from everything decoded so far,
              # enqueue any that don't start an already-decoded instruction.
              for func in list(functions.values()):
                  for b in func.blocks.values():
                      for ins in b.instructions:
                          if not (ins.is_uncond_jump or ins.is_call):
                              continue
                          tgt = ins.get_branch_target()
                          if tgt is None or tgt in queued:
                              continue
                          if not self.is_code_address(tgt):
                              continue
                          if tgt in covered:          # intra-function / known entry
                              continue
                          queued.add(tgt)
                          queue.append(tgt)

              # Callbacks: a function passed as an argument is named only by the
              # immediate that pushes its address (`push 0x48d4e0` ahead of a
              # DirectDraw EnumDisplayModes). Nothing CALLs it and it sits in no
              # data table, so neither the call scan nor the data scan finds it;
              # it surfaces at runtime as a callback that cannot be dispatched.
              for func in list(functions.values()):
                  for b in func.blocks.values():
                      for ins in b.instructions:
                          if ins.is_call or ins.is_jump or not ins.operands:
                              continue
                          for op in ins.operands:
                              if op.type != X86_OP_IMM:
                                  continue
                              tgt = op.imm & 0xFFFFFFFF
                              if tgt in queued or tgt in covered:
                                  continue
                              if not self.is_code_address(tgt):
                                  continue
                              queued.add(tgt)
                              queue.append(tgt)
          if data_scanned:
              break
          data_scanned = True
          ptrs = self.find_data_code_pointers(code_start, code_end, covered, queued)
          if not ptrs:
              break
          print(f"[*] Data scan: {len(ptrs)} functions reachable only via data pointers...")
          queued |= ptrs
          queue = sorted(ptrs)

        print(f"[*] Successfully disassembled {len(functions)} functions"
              f" ({round_no} discovery rounds)")
        return functions


# ---------------------------------------------------------------------------
# Command-line interface
#
# Usage:
#   python disasm32.py GAME.EXE --output functions.json
#   python disasm32.py GAME.EXE --pe-json pe_analysis.json --output functions.json
#
# Recursive-descent disassembly of every code section. Recovers function
# boundaries from CALL targets + standard prologues, builds per-function basic
# blocks and a direct call graph, and writes a JSON catalog for the next phase
# (classification / lifting). Part of the pcrecomp toolbox.
# ---------------------------------------------------------------------------
def _func_to_dict(func, full: bool = False) -> dict:
    """Serialize a Function to a plain dict for JSON output."""
    d = {
        "address": func.address,
        "address_hex": f"0x{func.address:08X}",
        "name": func.name,
        "end": func.end,
        "size": func.size,
        "num_blocks": len(func.blocks),
        "num_instructions": func.num_instructions,
        "is_thunk": func.is_thunk,
        "calls_to": sorted(func.calls_to),
    }
    if full:
        d["blocks"] = [
            {
                "start": b.start,
                "end": b.end,
                "is_exit": b.is_exit,
                "successors": sorted(set(b.successors)),
                "instructions": [
                    {"address": i.address, "mnemonic": i.mnemonic, "op_str": i.op_str,
                     "bytes": i.bytes.hex()}
                    for i in b.instructions
                ],
            }
            for b in sorted(func.blocks.values(), key=lambda x: x.start)
        ]
    return d


def main(argv=None):
    import argparse, json, os, sys

    # Allow running both as `python -m tools.disasm.disasm32` and as a loose script.
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pe"))
    from pe_analyze import analyze_pe, build_iat_map  # noqa: E402

    ap = argparse.ArgumentParser(
        description="Recursive-descent x86-32 disassembler + function recovery (pcrecomp).")
    ap.add_argument("exe", help="Path to the 32-bit PE executable")
    ap.add_argument("--output", "-o", help="Write function catalog as JSON to this path")
    ap.add_argument("--pe-json", help="(optional) reserved: path to a pe_analyze JSON; "
                                      "analysis is recomputed from the exe regardless")
    ap.add_argument("--full", action="store_true",
                    help="Include per-instruction detail in the JSON (large output)")
    ap.add_argument("--min-size", type=int, default=0,
                    help="Drop recovered functions smaller than N bytes from the catalog")
    args = ap.parse_args(argv)

    info = analyze_pe(args.exe)
    iat = build_iat_map(info)
    with open(args.exe, "rb") as f:
        pe_data = f.read()

    print(f"[*] {os.path.basename(args.exe)}: base=0x{info.image_base:08X} "
          f"code=0x{info.code_start:08X}-0x{info.code_end:08X} "
          f"imports(IAT)={len(iat)}")

    dis = Disassembler(pe_data, info.image_base, info.sections)
    functions = dis.find_functions(info.code_start, info.code_end, iat)

    funcs = [f for f in functions.values() if f.size >= args.min_size]
    funcs.sort(key=lambda x: x.address)

    thunks = sum(1 for f in funcs if f.is_thunk)
    leaves = sum(1 for f in funcs if not f.calls_to)
    total_insns = sum(f.num_instructions for f in funcs)
    code_bytes = info.code_end - info.code_start

    # Honest byte coverage: union of per-function [address, end) intervals,
    # each clamped to the code range. Recursive descent can follow a far jump
    # and inflate an individual func.end, and functions can overlap shared tail
    # code, so summing func.size would multi-count. Union + clamp avoids both.
    intervals = sorted((f.address, min(f.end, info.code_end)) for f in funcs
                       if f.end > f.address)
    covered = 0
    cur_lo = cur_hi = None
    for lo, hi in intervals:
        if cur_hi is None or lo > cur_hi:
            if cur_hi is not None:
                covered += cur_hi - cur_lo
            cur_lo, cur_hi = lo, hi
        else:
            cur_hi = max(cur_hi, hi)
    if cur_hi is not None:
        covered += cur_hi - cur_lo

    print(f"[*] Functions: {len(funcs)}  (thunks={thunks}, leaves={leaves})")
    print(f"[*] Instructions: {total_insns:,}")
    print(f"[*] Byte coverage: {covered:,} / {code_bytes:,} "
          f"({100.0 * covered / code_bytes:.1f}% of code range)")

    if args.output:
        out = {
            "exe": os.path.basename(args.exe),
            "image_base": info.image_base,
            "code_start": info.code_start,
            "code_end": info.code_end,
            "iat_count": len(iat),
            "stats": {
                "functions": len(funcs),
                "thunks": thunks,
                "leaves": leaves,
                "instructions": total_insns,
                "covered_bytes": covered,
                "code_bytes": code_bytes,
                "coverage_pct": round(100.0 * covered / code_bytes, 2),
            },
            "functions": [_func_to_dict(f, full=args.full) for f in funcs],
        }
        with open(args.output, "w") as f:
            json.dump(out, f, indent=1)
        print(f"[*] Wrote {args.output} ({os.path.getsize(args.output):,} bytes)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

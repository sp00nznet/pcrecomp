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
    # loop/loope/loopne are conditional branches with a fallthrough, and the
    # lifter emits them as `if (--ecx) goto L_target`. Leaving them out here
    # does not lose the jump -- it loses the LABEL, because block leaders only
    # come from this set, and a `loop` back into the middle of its own block
    # then compiles to a goto with nothing to go to.
    'loop', 'loope', 'loopz', 'loopne', 'loopnz',
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
    jump_targets: set = field(default_factory=set)
    # "start" -- we believe a function begins here.
    # "alias" -- we do NOT. Something branches into the middle of another
    # function (a shared epilogue, a switch arm reached from elsewhere, an
    # alternate entry point), and the lifter needs a dispatchable body at that
    # address or the branch is unresolved at runtime. The body deliberately
    # overlaps the function that contains it.
    #
    # The distinction is not cosmetic. Scored against Trespasser's linker map,
    # 6,427 of 7,364 "false positives" were aliases -- addresses the catalog
    # never claimed were function starts, counted as if it had. That is 87% of
    # the error in a precision number, and it was measuring a design decision
    # rather than a defect.
    entry_kind: str = "start"

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

        # A second decoder with detail OFF, for probes_as_function_body. The
        # probe wants mnemonics and sizes and nothing else; building capstone
        # operand detail for every instruction it walks past is the whole cost
        # of running it, and it throws all of it away.
        self._probe_md = Cs(CS_ARCH_X86, CS_MODE_32)

        # Build VA -> file offset cache for code sections
        # adj = raw_offset - va_start, so file_offset = va + adj
        self._code_sections = [(s.virtual_address + image_base,
                                s.virtual_address + image_base + s.raw_size,
                                s.raw_offset - (s.virtual_address + image_base))
                               for s in sections if s.is_code and s.name != '.bind']

    def code_section_bounds(self, va: int):
        """(start, end) of the code section holding `va`, or None."""
        for start, end, _ in self._code_sections:
            if start <= va < end:
                return start, end
        return None

    def probes_as_function_body(self, va: int, window: int = 4096) -> bool:
        """Read-only: does the instruction stream at `va` look like code?

        Corroboration for a candidate that came out of a raw byte scan rather
        than out of an instruction we actually decoded. `find_data_code_pointers`
        reads four bytes at every offset of every data section and calls each
        value in the code range a function; `find_branch_targets` does the same
        for every `E8`/`E9` byte. Both therefore accept anything that merely
        *looks* like an address -- a float, a string fragment, the middle of a
        wider immediate. On Trespasser that was 2,905 function starts invented
        out of data, each of which lifts to garbage.

        The test is whether the bytes decode as a run of instructions that
        reaches a `ret` or a tail `jmp`. Data almost never does; code almost
        always does. Alignment was the obvious alternative and is not good
        enough -- a real MSVC function start is only aligned when the linker had
        a reason to pad it, and the optimised accessors this repo keeps losing
        are exactly the ones it does not pad.

        Decoding cleanly for a whole `window` without terminating counts as a
        pass: garbage does not stay decodable for four kilobytes. Running off
        the end of the *section* without terminating does not -- real code does
        not end by falling out of .text.

        Nothing here is recorded. The probe uses its own detail-free decoder and
        touches no state, so running it cannot change what the sweep produces.
        """
        bounds = self.code_section_bounds(va)
        if bounds is None:
            return False
        sec_end = bounds[1]

        size = min(window, sec_end - va)
        data = self.read_bytes(va, size)
        if not data:
            return False

        end = va
        for insn in self._probe_md.disasm(data, va):
            if insn.mnemonic in RETS or insn.mnemonic in UNCOND_JUMPS:
                return True
            end = insn.address + insn.size

        # The decode stopped short of the window: a byte that is not an
        # instruction, which is the signature of data read as code.
        #
        # Except at the very end, where the window itself truncates the last
        # instruction and capstone stops for a reason that has nothing to do
        # with the bytes. An x86 instruction is at most 15 bytes, so anything
        # stopping inside that much of the end ran out of window rather than
        # out of code. Without this a function longer than the window is
        # rejected for being long: Trespasser 0x005D4DE0 decodes 1,031
        # instructions, consumes 4,092 of 4,096 bytes, and needs 5 more for
        # the call it stopped on.
        if end < va + size - 15:
            return False
        # It consumed everything we gave it. Clean for a full window is a pass;
        # clean right up to the section end without a terminator is not.
        return va + size < sec_end

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

    def disassemble_at(self, va: int, max_bytes: int = 4096):
        """Yield instructions starting at VA.

        A generator on purpose, and it must stay one. Every caller breaks out of
        its loop at the first branch, ret, or known block leader -- usually
        within a handful of instructions. Materialising the window first built
        an Instruction, with capstone detail operands, for every one of up to
        8 KB of decoded bytes and then threw nearly all of them away.

        That was this tool's dominant cost, measured rather than guessed: ~4 ms
        per byte of code, near-linear at O(code^1.10), which is 2.6 hours for a
        2.4 MB image. Yielding makes each caller pay only for what it consumes.

        Callers must iterate the result at most once.
        """
        data = self.read_bytes(va, max_bytes)
        if data is None:
            return

        for insn in self.md.disasm(data, va):
            yield Instruction(
                address=insn.address,
                size=insn.size,
                mnemonic=insn.mnemonic,
                op_str=insn.op_str,
                bytes=bytes(insn.bytes),
                operands=list(insn.operands) if insn.operands else [],
            )

    def jump_table_targets(self, insn, limit: int = 256) -> list:
        """Entries of the jump table an indirect `jmp` dispatches through.

        MSVC puts the table in .text beside the function. Nothing names the arms
        but this one instruction, so recursive descent cannot reach them and they
        surface at runtime as unresolved dispatches. Stop at the first entry that
        is not a code address -- that is where the table ends.
        """
        if not insn.operands:
            return []
        op = insn.operands[0]
        if op.type != X86_OP_MEM or op.mem.scale != 4 or not op.mem.index:
            return []
        table = op.mem.disp & 0xFFFFFFFF
        out = []
        misses = 0
        for k in range(limit):
            raw = self.read_bytes(table + k * 4, 4)
            if not raw or len(raw) < 4:
                break
            tgt = int.from_bytes(raw, 'little')
            if self.is_code_address(tgt):
                out.append(tgt)
                misses = 0
                continue
            # The entries do not always begin exactly at the displacement: the
            # index can be biased, or alignment padding sits in front of the
            # table (memcpy's [eax*4 + 0x49E140] really starts at 0x49E144, and
            # slot 0 reads as the tail of the preceding instruction). Stopping
            # at the first non-code slot therefore finds nothing at all for such
            # a table. Tolerate a couple, and end the table only once entries
            # have actually been seen.
            misses += 1
            if out and misses >= 2:
                break
            if not out and misses >= 4:
                break
        return out

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
                    elif target is None:
                        func.jump_targets.update(self.jump_table_targets(insn))
                        # `jmp dword ptr [table + idx*4]` -- a switch. The arms
                        # belong to THIS function: they are its loop body, not
                        # tail calls, so they have to become blocks here. Lift
                        # them as separate functions and a `continue` inside the
                        # switch turns into mutual recursion that never ends.
                        for arm in func.jump_targets:
                            block_leaders.add(arm)
                            if arm not in visited:
                                work.append(arm)
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

    def find_branch_targets(self, start_va: int, end_va: int) -> set:
        """
        Linear scan through code for direct rel32 branch targets -- both
        `call` (E8) and `jmp` (E9). A quick heuristic seed pass before
        recursive descent.

        The `jmp` half is not optional. An optimising compiler turns
        `call f; ret` into `jmp f`, so a small method that is only ever
        tail-called is named by no CALL anywhere in the image. Seeding E8
        alone left those functions undiscovered unless recursive descent
        happened to reach the caller first -- and if the caller was itself
        only tail-called, the whole chain stayed dark.

        Measured on an 8.8 MB MSVC C++ binary with a linker map for ground
        truth: seeding E8 only missed 7,331 real functions, 89% of which were
        reached by `jmp rel32` and nothing else. 95% were C++ mangled names
        and 61% were 8 bytes or smaller -- optimised __thiscall accessors with
        no `push ebp; mov ebp, esp` prologue to match on either. Adding E9
        recovers 6,550 of them.
        """
        targets = set()
        data = self.read_bytes(start_va, end_va - start_va)
        if data is None:
            return targets

        offset = 0
        while offset < len(data) - 5:
            # E8 xx xx xx xx = near call, E9 xx xx xx xx = near jmp
            if data[offset] in (0xE8, 0xE9):
                rel = struct.unpack_from('<i', data, offset + 1)[0]
                target = (start_va + offset + 5 + rel) & 0xFFFFFFFF
                if self.is_code_address(target):
                    targets.add(target)
                offset += 5
            else:
                offset += 1

        return targets

    def find_data_code_pointers(self, code_start: int, code_end: int,
                                covered: set, queued: set,
                                interior: bytearray = None) -> set:
        """Function pointers that exist only in data.

        A vtable slot, a callback table or a message-handler array can hold the
        only reference to a function: no CALL names it, so recursive descent
        never reaches it and it surfaces at runtime as an unresolved ICALL.
        Scan every byte offset of each non-code section for values landing in
        the code range and not already part of decoded code. Unaligned on
        purpose: packed struct arrays put function pointers at odd addresses
        (GTA1's handler table starts at 0x4B4AD1), and an aligned-only scan
        misses them entirely.

        `interior` is a byte per address in the code range, non-zero where a
        byte is INSIDE an instruction some already-decoded function owns. A
        pointer landing there is not a function start and cannot be one: the
        decode from that byte is a different instruction stream than the one
        the program runs. It still passes probes_as_function_body, because
        garbage that decodes cleanly to a `ret` is exactly what the middle of
        real code looks like -- on Mario Kart, 0x007BBF1B is the second byte of
        `mov ebp, esp`, decodes as `in al, dx`, reaches a `ret` forty bytes
        later, and killed the boot when a truncated neighbour fell into it.

        Every hit is then corroborated by decoding it -- see
        probes_as_function_body. Without that the scan accepts any four bytes
        that happen to look like a code address: a float, a string fragment,
        the middle of a wider immediate. Measured against Trespasser's linker
        map, the unchecked scan invented 2,905 function starts. Calling those
        harmless because they lift to dead code was the wrong trade: they
        poison the precision number, bury the real misses in noise, and spend
        codegen on decoded garbage.
        """
        found = set()
        probed = rejected = mid = 0
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
                if va in covered or va in queued or va in found:
                    continue
                if interior is not None and interior[va - code_start]:
                    mid += 1
                    continue
                probed += 1
                if not self.probes_as_function_body(va):
                    rejected += 1
                    continue
                found.add(va)
        if probed or mid:
            print(f"[*] Data scan: probed {probed} pointer targets, "
                  f"rejected {rejected} that do not decode as code "
                  f"and {mid} that land inside an instruction")
        return found

    def find_functions(self, code_start: int, code_end: int, iat_map: dict = None,
                       seeds=(), release_operands: bool = False) -> dict:
        """
        Find all functions in the code section.
        Uses call target analysis + common prologue patterns.

        `seeds` are addresses that are functions whether or not anything here
        recognises them -- the PE entry point above all. Nothing calls it, and
        a CRT startup does not have to open with `push ebp; mov ebp, esp`, so
        both heuristics can miss the one function the program begins with.

        `release_operands` frees each instruction's capstone operand list once
        this pass has finished with it. It saves a great deal of memory on a
        large image, and it is safe ONLY if the caller is going to export the
        catalog rather than lift it in process -- the lifter reads operands.

        Returns dict of addr -> Function.
        """
        print(f"[*] Scanning for call targets in 0x{code_start:08X}-0x{code_end:08X}...")
        call_targets = self.find_branch_targets(code_start, code_end)
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
        all_targets = call_targets | prologue_targets | set(seeds)
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
        interior = bytearray(max(0, code_end - code_start))   # ...and every byte within one
        owner = {}               # instruction address -> the function that decoded it
        alias_entries = set()    # entry points inside another function's body
        queue = list(all_targets)
        queued = set(all_targets)

        def _add_func(addr, entry_kind="start"):
            func = self.disassemble_function(addr, iat_map)
            if not (func and func.blocks):
                return None
            func.entry_kind = entry_kind
            functions[addr] = func
            if len(func.blocks) == 1:
                block = next(iter(func.blocks.values()))
                if len(block.instructions) == 1 and block.instructions[0].is_uncond_jump:
                    func.is_thunk = True
            for b in func.blocks.values():
                for ins in b.instructions:
                    covered.add(ins.address)
                    owner.setdefault(ins.address, addr)
                    # Every byte after the first is inside this instruction, and
                    # so cannot be the start of anything. A bytearray and not a
                    # set: an image this size has tens of millions of interior
                    # bytes and a set of them costs more than the image.
                    for k in range(ins.address + 1, ins.address + ins.size):
                        if code_start <= k < code_end:
                            interior[k - code_start] = 1
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
              new_funcs = []
              for i, addr in enumerate(sorted_targets):
                  if round_no == 1 and i % 1000 == 0 and i > 0:
                      print(f"[*] Disassembling function {i}/{total}...")
                  if addr in functions:
                      continue
                  f = _add_func(addr, "alias" if addr in alias_entries else "start")
                  if f is not None:
                      new_funcs.append(f)

              # Harvest jmp/call immediate targets from the functions decoded in
              # THIS round -- not from every function decoded so far.
              #
              # Re-walking the whole catalog each round was quadratic and bought
              # nothing: a function is harvested in the round it is decoded, and
              # every target that harvest accepts lands in `queued`, which the
              # first test below skips forever after. The only other exit from
              # the loop body skips without queuing, and its conditions
              # (`tgt in functions`, `owner[tgt] == func.address`) never go from
              # true back to false. So a re-walk can only re-skip what it already
              # skipped. Harvesting once also means an instruction's capstone
              # operands stop being live state, which is what lets them be freed
              # below.
              for func in new_funcs:
                  for b in func.blocks.values():
                      for ins in b.instructions:
                          if not (ins.is_uncond_jump or ins.is_call):
                              continue
                          tgt = ins.get_branch_target()
                          if tgt is None or tgt in queued:
                              continue
                          if not self.is_code_address(tgt):
                              continue
                          if tgt in covered:
                              # A jump INTO another function's body -- a shared
                              # epilogue, or a switch arm the table scan reached
                              # first. It has no label in the jumping function, so
                              # the lifter tail-dispatches to it; make it a real
                              # entry point or that dispatch is unresolved at
                              # runtime. Safe now that ebp is a global register:
                              # the caller's frame carries through.
                              if tgt in functions or owner.get(tgt) == func.address:
                                  continue
                              # It is an entry point, but it is NOT a function
                              # start and the catalog must not say it is.
                              alias_entries.add(tgt)
                          queued.add(tgt)
                          queue.append(tgt)

              # Callbacks: a function passed as an argument is named only by the
              # immediate that pushes its address (`push 0x48d4e0` ahead of a
              # DirectDraw EnumDisplayModes). Nothing CALLs it and it sits in no
              # data table, so neither the call scan nor the data scan finds it;
              # it surfaces at runtime as a callback that cannot be dispatched.
              for func in new_funcs:
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

              # Both harvests are done with these instructions. Each retained
              # operand list pins a whole capstone cs_detail struct, and holding
              # them for an entire image is what took a 2.4 MB input past 4 GB
              # and killed a run -- so a caller that only wants the catalog can
              # say so and get them dropped.
              #
              # It is opt-in because "nothing downstream reads operands" is only
              # true of the JSON path. Every project here drives the lifter in
              # process (run_pipeline.py -> Lifter.lift_function), and lift32
              # reads insn.operands directly: with them dropped, each handler's
              # `if len(ops) == 2` is false and the instruction vanishes, no
              # error. That lifts an image to a third of its real size, with the
              # gotos and every instruction that has an operand quietly missing.
              if release_operands:
                  for func in new_funcs:
                      for b in func.blocks.values():
                          for ins in b.instructions:
                              ins.operands = None

          if data_scanned:
              break
          data_scanned = True
          ptrs = self.find_data_code_pointers(code_start, code_end, covered, queued,
                                              interior)
          if not ptrs:
              break
          print(f"[*] Data scan: {len(ptrs)} functions reachable only via data pointers...")
          queued |= ptrs
          queue = sorted(ptrs)

        print(f"[*] Successfully disassembled {len(functions)} functions"
              f" ({round_no} discovery rounds)")
        sizes = {a: f.size for a, f in functions.items()}
        gone = drop_mid_instruction_entries(
            lambda va, n: self.read_bytes(va, n), sizes, code_start, code_end)
        for a in list(functions):
            if a not in sizes:
                del functions[a]

        moved = clamp_extents(functions, code_end)
        if moved:
            print(f"[*] Clamped {moved} function extents to the next function start")
        return functions


def drop_mid_instruction_entries(read_va, functions, code_start, code_end,
                                 max_rounds=4, verbose=True):
    """Remove catalog entries that are not instruction boundaries.

    An address inside an instruction cannot be the start of anything: decoding
    from it produces a stream the program never runs. On Mario Kart Arcade GP
    DX, 0x0081C100 is the third byte of `fld dword ptr [0x8E0848]` and decodes
    as `dec eax; or byte ptr [esi - 0x3be22700], cl; hlt` - which lifts,
    compiles, and kills the game a thousand calls into its boot.

    find_functions already refuses these when the containing function was
    decoded first. Two candidates from the SAME data-scan batch never see each
    other, and a C++ initialiser table produces exactly that: the initialiser
    and a false pointer into its middle arrive in the same round.

    So this runs afterwards, over the whole catalog at once, and iterates - a
    dropped entry's own bogus decode has to stop marking bytes interior, or it
    can take a real function down with it. Two rounds is normally enough.

    `functions` is {addr: size}, edited in place. Returns how many went.
    """
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    dropped = 0
    gone = set()

    # Decode to a terminator, NOT to the recorded size, and this is the whole
    # subtlety. clamp_extents has already cut each function at the next start -
    # including at the false one - so the recorded extent stops exactly where
    # the evidence would have been. Walking to the `ret` the function really
    # ends at is what puts the bogus entry back inside an instruction.
    #
    # Stopping at the terminator also keeps this from marking the NEXT
    # function's bytes and dropping a real start: over-marking is the only way
    # this can do harm, and a `ret` is where over-marking would begin.
    ENDS = ("ret", "retn", "retf", "iret", "iretd")
    WINDOW = 0x2000

    # No function is bigger than this, and a branch further than this is a tail
    # call into somewhere else - which is not ours to mark.
    REACH = 0x10000

    def body_instructions(addr):
        """Walk a function's real extent as a graph, not as a line.

        Stopping at a `jmp` was the obvious rule and is wrong: MSVC emits them
        inside a function constantly - around a loop, out of a switch arm, to a
        shared tail - and stopping there ends the walk in the middle of the
        body. `0x00768220` ends at `jmp 0x76825F` twenty-three instructions in,
        so a false entry at `0x00768279` was never reached and survived two
        passes.

        Stopping at `ret` is wrong for exactly the same reason, and it is the
        more common one: a `ret` ends a PATH, not a function. Any function with
        an early exit - a guard clause, a failed check, `if (!ok) return false;`
        - has its whole real body after the first `ret`, and a linear walk
        never sees a byte of it.

        `0x007464E0` in Mario Kart Arcade GP DX is thirteen instructions of
        error path ending in `ret` at `0x00746516`, and a hundred more after
        it. Three false entries sat inside the `call __security_check_cookie`
        at `0x0074656F`, were never marked interior, survived every round, and
        the lifter emitted a "function" whose entire body was `or byte ptr
        [eax], al` decoded from the middle of that call's operand. It faulted
        on the first frame the game tried to draw.

        So: a worklist. Follow both edges of a conditional branch, follow an
        unconditional one, end a path at `ret` or an indirect jump, then take
        the next pending target. Bounded by REACH and a visited set, because
        over-marking is the only way this can do harm - marking a real function
        start as interior would drop it.
        """
        pending = [addr]
        seen = set()
        n = 0
        while pending and n < 8192:
            va = pending.pop()
            while va is not None and n < 8192:
                if va in seen:
                    break
                seen.add(va)
                try:
                    code = read_va(va, min(WINDOW, code_end - va))
                except Exception:
                    break
                advanced = False
                for ins in md.disasm(code, va):
                    advanced = True
                    n += 1
                    va = ins.address + ins.size
                    yield ins
                    m = ins.mnemonic.split()[-1]
                    if m in ENDS:
                        va = None
                        break
                    # A call returns, so its target is somebody else's body but
                    # the instruction after it is still ours.
                    if m != "call" and m.startswith("j"):
                        op = ins.op_str.strip()
                        t = int(op, 16) if op.startswith("0x") else None
                        if t is not None and addr <= t < code_end and \
                           t - addr < REACH and t not in seen:
                            pending.append(t)
                        if m == "jmp":
                            va = None    # unconditional: this path ends here
                            break
                    if va in seen:
                        break
                if not advanced:
                    break

    for _ in range(max_rounds):
        interior = bytearray(max(0, code_end - code_start))
        for addr in functions:
            if functions[addr] <= 0:
                continue
            for ins in body_instructions(addr):
                for k in range(ins.address + 1, ins.address + ins.size):
                    if code_start <= k < code_end:
                        interior[k - code_start] = 1

        bogus = [a for a in functions
                 if code_start <= a < code_end and interior[a - code_start]]
        if not bogus:
            break
        for a in bogus:
            del functions[a]
        gone.update(bogus)
        dropped += len(bogus)
        if verbose:
            print("[*] Dropped %d entries that are not instruction boundaries"
                  % len(bogus))

    # Re-open the neighbours the dropped entries had truncated.
    #
    # clamp_extents cut each real function at the next start, and for these the
    # next start was the false one - so a function whose extent ends exactly at
    # a dropped address is a function that was cut short to make room for
    # something that does not exist. Left alone it ends in a fallthrough to an
    # address nothing lifts, which is a worse failure than the one this
    # function just fixed: before, the game ran a wrong instruction; now it
    # would stop dead at a dispatch.
    if gone:
        import bisect
        starts = sorted(functions)
        for addr in list(functions):
            if addr + functions[addr] in gone:
                i = bisect.bisect_right(starts, addr)
                functions[addr] = (starts[i] if i < len(starts) else code_end) - addr
    return dropped


def close_dispatch_targets(read_va, functions, code_start, code_end,
                           aliases=None, max_rounds=3, verbose=True):
    """Make every direct branch target dispatchable.

    The lifter turns a `jcc`/`jmp`/`call` into a `goto` when the target is
    inside the function being lifted and into a `dispatch()` when it is not.
    So every target that leaves its own extent has to BE an entry, or the game
    stops on "no lifted function at ...".

    Clamping is what creates these. A shared epilogue is a legitimate entry -
    several functions jump to it - but recording it as a *start* cuts the
    function that contains it in half, and the second half's branch targets
    suddenly point outside the extent. Mario Kart stopped on 0x007B96F3, an
    ordinary `mov eax, [ebp+0x18]` in the middle of a function that had been
    truncated at the `pop/pop/pop/ret` five bytes earlier.

    New entries are aliases: they overlap whatever contains them on purpose,
    and must not be used as clamp limits. Their addresses are added to
    `aliases` if one is given. Returns how many were added.
    """
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    import bisect
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    BRANCH = ("jmp", "call", "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe",
              "jg", "jge", "jl", "jle", "js", "jns", "jo", "jno", "jp", "jnp",
              "jcxz", "jecxz", "loop", "loope", "loopz", "loopne", "loopnz")
    added_total = 0

    for _ in range(max_rounds):
        wanted = set()
        for addr, size in list(functions.items()):
            if size <= 0:
                continue
            try:
                code = read_va(addr, size)
            except Exception:
                continue
            end = addr + size
            for ins in md.disasm(code, addr):
                if ins.mnemonic.split()[-1] not in BRANCH:
                    continue
                for op in ins.operands:
                    if op.type != X86_OP_IMM:
                        continue
                    t = op.imm & 0xFFFFFFFF
                    # Inside this extent the lifter emits a goto, and an
                    # address that is already an entry is already dispatchable.
                    if addr <= t < end or t in functions:
                        continue
                    if code_start <= t < code_end:
                        wanted.add(t)
        if not wanted:
            break
        starts = sorted(functions)
        for t in sorted(wanted):
            i = bisect.bisect_right(starts, t)
            nxt = starts[i] if i < len(starts) else code_end
            functions[t] = nxt - t
            if aliases is not None:
                aliases.add(t)
        added_total += len(wanted)
        if verbose:
            print("[*] Added %d branch targets that had no dispatchable body"
                  % len(wanted))
    return added_total


def clamp_extents(functions, code_end, starts=None):
    """No function extends past the next function's entry. Returns how many
    had to be shortened.

    `func.end` comes out of recursive descent as `max(block.end)`, and descent
    follows unconditional jumps - so one `jmp` to a shared epilogue, or a jump
    table whose arms are scattered, puts `end` far past the body and everything
    in between is counted as part of this function. The lifter then reads
    `size` bytes LINEARLY from the entry, so it lifts every unrelated function
    in the gap into this one, over and over.

    Measured on Mario Kart Arcade GP DX: 28,597 recovered functions claiming
    **89.5 MB of bodies for a 4.3 MB code range** - 271 of them over 64 KB and
    one at 1.3 MB - which lifted to 18.8 million lines and 1.9 GB of C that no
    compiler will take. Clamping brings the claim to 6.7 MB. The 1.55x that
    remains is the 3,619 alias entries, which overlap their host function
    deliberately and are the reason this clamps only against `entry_kind ==
    "start"`: clamping against an alias would truncate the function containing
    it.

    A real function whose body is genuinely split around another one - MSVC
    does move cold blocks away - loses its far blocks here. That shows up as a
    named, findable unresolved dispatch at run time, which is much better than
    a lift nobody can build.

    Accepts the {addr: Function} that find_functions returns, or the plain
    {addr: size} a project keeps in a catalog. In the second shape there is no
    entry_kind to read, so pass `starts` - the addresses that are function
    starts - or every entry acts as a limit for every other and an alias
    truncates the function it sits inside. Mutates and returns in place.
    """
    import bisect

    if starts is None:
        starts = [a for a, f in functions.items()
                  if getattr(f, "entry_kind", "start") == "start"]
    starts = sorted(starts)
    moved = 0
    for addr, func in functions.items():
        size = func.size if hasattr(func, "size") else func
        if size <= 0:
            continue
        i = bisect.bisect_right(starts, addr)
        limit = starts[i] if i < len(starts) else code_end
        if addr + size <= limit:
            continue
        new = max(0, limit - addr)
        if hasattr(func, "size"):
            func.size = new
            func.end = addr + new
        else:
            functions[addr] = new
        moved += 1
    return moved


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
        "entry_kind": func.entry_kind,
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


def demo():
    """One runnable check for probes_as_function_body: code passes, data does not.

    A fake single-section image, so the probe is exercised without needing a PE
    on disk. Every assertion below is a decision the probe has to get right for
    the data-pointer scan to stop inventing functions.
    """
    class _Sec:
        def __init__(self, name, va, raw_off, raw_size, is_code):
            self.name, self.virtual_address = name, va
            self.raw_offset, self.raw_size = raw_off, raw_size
            self.virtual_size, self.is_code = raw_size, is_code

    BASE = 0x400000
    body = (b"\x55"                      # push ebp
            b"\x8b\xec"                  # mov ebp, esp
            b"\x33\xc0"                  # xor eax, eax
            b"\xc3")                     # ret
    tail = (b"\x8b\x44\x24\x04"          # mov eax, [esp+4]
            b"\xe9\x00\x00\x00\x00")     # jmp rel32 -- a tail call terminates too
    junk = b"\x0f\xff" * 4               # 0F FF is not an x86 instruction
    text = body + tail + junk
    text += b"\x90" * (0x200 - len(text))   # nops out to the section end

    d = Disassembler(b"\x00" * 0x400 + text, BASE,
                     [_Sec(".text", 0x1000, 0x400, 0x200, True)])

    a_body = BASE + 0x1000
    a_tail = a_body + len(body)
    a_junk = a_tail + len(tail)

    assert d.probes_as_function_body(a_body), "a prologue reaching ret is code"
    assert d.probes_as_function_body(a_tail), "a tail jmp is a terminator too"
    assert not d.probes_as_function_body(a_junk), \
        "bytes that do not decode are not a function body"
    assert not d.probes_as_function_body(BASE + 0x9000), \
        "an address outside every code section is not code"

    # Nops decode cleanly forever. Running to the end of .text without ever
    # reaching a terminator is still a reject: real code does not end by
    # falling out of its section.
    assert not d.probes_as_function_body(BASE + 0x11F0), \
        "clean decode to the section end without a terminator is not a body"

    # The same nops, when there is more section after them than the probe
    # window, are a pass -- garbage does not stay decodable that long.
    assert d.probes_as_function_body(BASE + 0x1100, window=16), \
        "a full clean window counts as corroboration"

    # A window that cuts its own last instruction in half stopped for a reason
    # that has nothing to do with the bytes, and must not read as a reject.
    # Here 6 bytes hold the 4-byte mov and only 2 of the 5-byte jmp after it.
    # Getting this wrong rejects every function longer than the window: measured
    # against Trespasser's linker map it cost exactly one real function start
    # out of 34,159, which is the kind of defect that hides forever unless
    # something is scoring against symbols.
    assert d.probes_as_function_body(a_tail, window=6), \
        "out of window is not out of code"

    # drop_mid_instruction_entries: the real case in miniature. `fld dword ptr
    # [0x8E0848]` is six bytes; an entry three bytes into it is not a function
    # and decodes as something the program never runs.
    blob = (bytes([0xD9, 0x05, 0x48, 0x08, 0x8E, 0x00]) +   # fld  [0x8E0848]
            bytes([0xD9, 0x1D, 0xC4, 0x35, 0x95, 0x00]) +   # fstp [0x9535C4]
            bytes([0xC3]))                                  # ret

    def _read(va, n):
        off = va - 0x1000
        return blob[off:off + n] if 0 <= off < len(blob) else b""

    cat = {0x1000: len(blob), 0x1002: len(blob) - 2}
    gone = drop_mid_instruction_entries(_read, cat, 0x1000, 0x1000 + len(blob),
                                        verbose=False)
    assert gone == 1 and 0x1002 not in cat and 0x1000 in cat, (gone, cat)

    # ...and a neighbour that had been clamped onto the dropped entry gets its
    # extent back. Left at 2 bytes it would end in a fallthrough to an address
    # nothing lifts - a worse failure than the wrong instruction just removed.
    cat = {0x1000: 2, 0x1002: len(blob) - 2}
    assert drop_mid_instruction_entries(_read, cat, 0x1000, 0x1000 + len(blob),
                                        verbose=False) == 1, cat
    assert cat == {0x1000: len(blob)}, cat

    # A real boundary is never dropped, and an entry never drops itself.
    cat = {0x1000: len(blob), 0x1006: len(blob) - 6}
    assert drop_mid_instruction_entries(_read, cat, 0x1000, 0x1000 + len(blob),
                                        verbose=False) == 0, cat
    assert len(cat) == 2, cat

    # A `ret` ends a path, not a function. This is the shape that survived
    # every round in Mario Kart: a guard clause returning early, the real body
    # after it, and a false entry inside an instruction in that real body.
    #
    #   0x1000  test eax, eax
    #   0x1002  jne  0x1006        -> the real body
    #   0x1004  ret                -> the early exit a linear walk stops at
    #   0x1005  nop
    #   0x1006  fld dword [0x8E0848]   6 bytes; 0x1009 is inside it
    #   0x100C  ret
    early = (bytes([0x85, 0xC0]) +                          # test eax, eax
             bytes([0x75, 0x02]) +                          # jne  0x1006
             bytes([0xC3]) +                                # ret
             bytes([0x90]) +                                # nop
             bytes([0xD9, 0x05, 0x48, 0x08, 0x8E, 0x00]) +  # fld  [0x8E0848]
             bytes([0xC3]))                                 # ret

    def _read_early(va, n):
        off = va - 0x1000
        return early[off:off + n] if 0 <= off < len(early) else b""

    cat = {0x1000: len(early), 0x1009: len(early) - 9}
    gone = drop_mid_instruction_entries(_read_early, cat, 0x1000,
                                        0x1000 + len(early), verbose=False)
    assert gone == 1 and 0x1009 not in cat and 0x1000 in cat, (gone, cat)

    # close_dispatch_targets: a branch that leaves its own extent needs an
    # entry at the target, or the lifter emits a dispatch nothing answers.
    jmpblob = (bytes([0x74, 0x02]) +                  # 0x1000: je 0x1004
               bytes([0x33, 0xC0]) +                  # 0x1002: xor eax, eax
               bytes([0xC3]) +                        # 0x1004: ret
               bytes([0x8B, 0x45, 0x18]) +            # 0x1005: mov eax,[ebp+0x18]
               bytes([0xC3]))                         # 0x1008: ret

    def _readj(va, n):
        off = va - 0x1000
        return jmpblob[off:off + n] if 0 <= off < len(jmpblob) else b""

    # Truncated at 0x1004, so the `je 0x1004` now leaves the extent.
    cat, als = {0x1000: 4, 0x1005: 4}, set()
    n = close_dispatch_targets(_readj, cat, 0x1000, 0x1000 + len(jmpblob),
                               aliases=als, verbose=False)
    assert n == 1 and 0x1004 in cat and 0x1004 in als, (n, cat, als)
    # ...and the new entry runs to the next one, not past it.
    assert cat[0x1004] == 1, cat

    # A branch that stays inside its own extent adds nothing.
    cat = {0x1000: len(jmpblob)}
    assert close_dispatch_targets(_readj, cat, 0x1000, 0x1000 + len(jmpblob),
                                  verbose=False) == 0, cat

    # clamp_extents: an over-extended function must be cut at the next START,
    # an alias inside a function must NOT cut it, and a function that already
    # ends before the next start must be left exactly alone. Plain {addr: size}
    # bounds maps have to work too, because that is what a catalog holds.
    fns = {
        0x1000: Function(address=0x1000, end=0x9000, size=0x8000),   # over-extended
        0x1200: Function(address=0x1200, end=0x1300, size=0x100),    # honest
        0x1250: Function(address=0x1250, end=0x1280, size=0x30,      # alias inside it
                         entry_kind="alias"),
        0x2000: Function(address=0x2000, end=0x2010, size=0x10),
    }
    moved = clamp_extents(fns, 0x9000)
    assert moved == 1, moved
    assert fns[0x1000].size == 0x200, hex(fns[0x1000].size)   # cut at 0x1200
    assert fns[0x1200].size == 0x100, "an honest extent was changed"
    assert fns[0x1250].size == 0x30, "an alias was clamped"
    assert fns[0x2000].size == 0x10
    # ...and the alias at 0x1250 did not become the limit for 0x1200.
    bounds = {0x1000: 0x8000, 0x1200: 0x100}
    assert clamp_extents(bounds, 0x9000) == 1
    assert bounds == {0x1000: 0x200, 0x1200: 0x100}, bounds

    print("disasm32.py self-test OK")


def main(argv=None):
    import argparse, json, os, sys

    # Allow running both as `python -m tools.disasm.disasm32` and as a loose script.
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pe"))
    from pe_analyze import analyze_pe, build_iat_map  # noqa: E402

    ap = argparse.ArgumentParser(
        description="Recursive-descent x86-32 disassembler + function recovery (pcrecomp).")
    ap.add_argument("exe", nargs="?", help="Path to the 32-bit PE executable")
    ap.add_argument("--selftest", action="store_true",
                    help="Run the built-in checks and exit")
    ap.add_argument("--output", "-o", help="Write function catalog as JSON to this path")
    ap.add_argument("--pe-json", help="(optional) reserved: path to a pe_analyze JSON; "
                                      "analysis is recomputed from the exe regardless")
    ap.add_argument("--full", action="store_true",
                    help="Include per-instruction detail in the JSON (large output)")
    ap.add_argument("--min-size", type=int, default=0,
                    help="Drop recovered functions smaller than N bytes from the catalog")
    ap.add_argument("--seed-functions", metavar="FILE",
                    help="JSON list of addresses that are functions whether or "
                         "not the scans find them. Produced by seed_from_log.py "
                         "from a run's unresolved dispatches; also fine to "
                         "hand-write.")
    args = ap.parse_args(argv)

    # This pass takes hours on a multi-megabyte image and prints its progress as
    # it goes. Redirected to a file or a pipe, stdout is block-buffered, so none
    # of that progress is visible -- and if the run dies partway (a 2.4 MB image
    # peaks past 4 GB), the buffer dies with it and the log is zero bytes. Ask
    # for line buffering so the progress is worth having.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, OSError):
        pass

    if args.selftest:
        demo()
        return 0
    if not args.exe:
        ap.error("an executable is required (or --selftest)")

    info = analyze_pe(args.exe)
    iat = build_iat_map(info)
    with open(args.exe, "rb") as f:
        pe_data = f.read()

    print(f"[*] {os.path.basename(args.exe)}: base=0x{info.image_base:08X} "
          f"code=0x{info.code_start:08X}-0x{info.code_end:08X} "
          f"imports(IAT)={len(iat)}")

    # The entry point is the one function guaranteed to exist and not
    # guaranteed to be found: nothing calls it, and a CRT startup need not open
    # with `push ebp; mov ebp, esp`, so both heuristics can miss the address
    # the program actually begins at. find_functions has taken seeds for this
    # all along and main never passed any.
    seeds = set()
    if info.entry_point_rva:
        seeds.add(info.image_base + info.entry_point_rva)

    if args.seed_functions:
        with open(args.seed_functions) as f:
            doc = json.load(f)
        for e in doc:
            if isinstance(e, dict):
                e = e.get("address", e.get("address_hex"))
            seeds.add(int(e, 0) if isinstance(e, str) else e)
        print(f"[*] {len(doc)} seeds from {args.seed_functions}")

    dis = Disassembler(pe_data, info.image_base, info.sections)
    # This CLI exports a catalog and never lifts, so it is the caller that can
    # afford to let the operand lists go -- which is where the memory went on a
    # multi-megabyte image.
    functions = dis.find_functions(info.code_start, info.code_end, iat,
                                   seeds=seeds, release_operands=True)

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

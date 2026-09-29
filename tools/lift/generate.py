"""
Fast code generation using linear sweep disassembly.

Instead of recursive descent per function (slow), this uses a single linear
sweep through the entire code section and splits by known function boundaries.
"""

import sys
import os
import re
import time
import json

# The lifter and the PE reader are siblings under tools/, not a package. This
# file used to import them as `tools.pe_analyze` / `tools.lifter`, which have
# never been the paths -- so it did not import at all, and every project forked
# it instead of using it.
_TOOLS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _d in ('pe', 'lift', 'disasm'):
    _p = os.path.join(_TOOLS, _d)
    if _p not in sys.path:
        sys.path.insert(0, _p)

import lift32
from pe_analyze import analyze_pe, build_iat_map
from lift32 import Lifter
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM, X86_OP_MEM
from disasm32 import decode


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


MAX_RESUMES = 64        # see the resume note in linear_disassemble_function


def linear_disassemble_function(md, code_data, code_start, func_start, func_end,
                                reached=None):
    """
    Disassemble a function using linear sweep between known boundaries.
    Returns list of LinearInstruction and set of basic block leaders.

    With `reached` (the instruction set true_extent walked), decode exactly
    those instructions: a pass stops at the first address outside the set and
    the next resumes at the lowest reached address not yet decoded. A jump
    table sitting between a switch and its arms is then never decoded as
    code, where a plain sweep turns its bytes into `pushal` and loses the arms.
    """
    offset = func_start - code_start
    size = func_end - func_start
    if offset < 0 or offset + size > len(code_data):
        return [], set()

    raw = code_data[offset:offset + size]
    instructions = []
    leaders = {func_start}  # First instruction is always a leader
    seen = set()            # addresses already decoded, so a resume cannot loop
    pc = func_start
    resumes = 0

    while pc is not None:
        over = None        # target of the last uncond jmp decoded in this pass
        hit_pad = False
        for insn in decode(md, raw[pc - func_start:], pc):
            li = LinearInstruction(insn)
            if li.address in seen:
                break           # walked into a block already decoded
            if reached is not None and li.address not in reached:
                break           # past what the walk reached: data, or another body
            seen.add(li.address)
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
                    over = target
                # Next instruction (if any) is a new leader
                leaders.add(li.end_address)

            # int3 is inter-function padding -- but MSVC also emits it INSIDE a
            # function, as the unreachable fallthrough of __assume(0) and of a
            # range-checked switch:
            #
            #     0077C86F  jbe  0x77c872
            #     0077C871  int3
            #     0077C872  <the rest of the function>
            #
            # Breaking at the first one truncated the body there. The extent
            # walk had the right answer and 0x0077C872 was already a known
            # leader, but the instructions were gone, so generate.py had a
            # label it could not place, emitted a tail transfer instead, and
            # RECOMP_ITAIL could not resolve a VA that was never lifted -- the
            # transfer silently did nothing and the function fell through to
            # its caller. In Force Commander that handed a null `this` to the
            # DX7 pixel-pipe manager, several calls away, with one
            # "ITAIL: unresolved VA" line as the only evidence.
            #
            # So an int3 ends the SWEEP when the instruction after it is not a
            # leader -- nothing steps over it -- and the loop below then
            # resumes at the next leader that has not been decoded yet.
            if li.mnemonic == 'int3' and li.end_address not in leaders:
                hit_pad = True
                break

        # Resume where the jump that stepped over the gap was going.
        #
        # sub_0066E150 ends a block with `jmp 0x66e27d`, and what MSVC put in
        # between is not padding -- it is one int3 followed by
        # `mov eax, 0x66e277 / ret`, the EH state thunk for the try region.
        # Stopping at the int3 dropped four leaders and every one came out as a
        # RECOMP_ITAIL to a VA nobody lifted; the transfer silently did nothing
        # and the function fell through to its caller.
        #
        # The bound is the whole difficulty, and three looser rules were
        # measured and thrown away before this one:
        #
        #   - continuing the linear sweep past the int3 decoded data as
        #     instructions for the whole extent: one 400-function chunk came
        #     out at 104 MB;
        #   - resuming at the next undecoded leader looked tight, since leaders
        #     come from decoded branches, but in the region of overlapping
        #     entries around 0x005A5840 the leaders are themselves derived from
        #     garbage and a chunk passed 60 MB still growing;
        #   - resuming only across a run of 0xCC/0x90 does not fix the case it
        #     was written for, because the gap is a code thunk.
        #
        # So resume at the target of the unconditional jump this pass last
        # took, and only if that target has not been decoded. That is exactly
        # "something stepped over this gap, and here is where it went", it needs
        # no judgement about the extent, and it cannot invent a destination.
        #
        # ponytail: MAX_RESUMES caps the rest. Two gaps is the most any real
        # body has shown; the symptom of needing more is a returning
        # "ITAIL: unresolved VA".
        pc = None
        if reached is not None:
            rest = [a for a in reached if a not in seen and func_start <= a < func_end]
            pc = min(rest) if rest else None
        elif hit_pad and over is not None and over not in seen                 and resumes < MAX_RESUMES:
            pc = over
            resumes += 1

    # The emitter walks the list in order and places a label per leader, so the
    # blocks have to come back sorted even though they were decoded out of
    # order.
    instructions.sort(key=lambda i: i.address)

    return instructions, leaders


# The x87 condition-code helper the lifter emits for fcom-family compares.
FPU_CMP = {'EQ': '==', 'NE': '!=', 'B': '<', 'BE': '<=', 'A': '>', 'AE': '>=',
           'L': '<', 'LE': '<=', 'G': '>', 'GE': '>='}


def push_return_label(insn, nxt, leaders):
    """The label of a `push label; jmp func` pair, or None."""
    if (nxt is not None and insn.mnemonic == 'push' and nxt.mnemonic == 'jmp'
            and nxt.get_branch_target() is not None):
        t = insn.get_branch_target()      # the push's immediate
        if t is not None and t in leaders:
            return t
    return None


def lift_function_linear(lifter, name, instructions, leaders, func_start,
                         indirect_targets=None):
    """Lift a linearly-disassembled function to C code.

    The preamble comes from `lift32.FUNCTION_LOCALS`, not from a list written
    out here. That list used to be hand-copied into every project driver, and
    every copy went stale the moment the lifter started using a new local --
    which is why lift32 declares the contract and this asks for it.

    Two of the declarations this function used to emit were not merely stale,
    they were wrong, and both failed quietly:

      * `double _st[8]` / `int _fp_top` / `uint16_t _fpu_cw`. recomp_types.h
        defines `_st` as `g_st`, so those lines expanded to locals *named*
        g_st/g_fp_top/g_fpu_cw that shadowed the globals. The x87 stack is
        shared across calls -- MSVC returns a float in st0 -- so a private copy
        per function silently drops every floating-point return value.
      * `uint32_t ebp = 0`. An optimising compiler splits one function's blocks
        across the image and jumps between them, and each block addresses the
        same frame through ebp. Lifted as separate bodies, a private ebp starts
        each at 0 and the first `[ebp-0x20]` reads 0xFFFFFFE0.
    """
    va = func_start & 0xFFFFFFFF
    lines = [f'void {name}(void) {{']
    for decl in lift32.FUNCTION_LOCALS:
        lines.append(f'    {decl}')
    lines.append('    RECOMP_REGS_LOCALS')   # empty unless RECOMP_LOCAL_REGS
    lines.append(f'    RECOMP_ENTER(0x{va:08X}u);')
    lines.append('')

    lifter._flag_state = None

    # An indirect jump inside a function (a switch/jump table) can compute a
    # target that lands on ANY instruction in it, so when one is present every
    # instruction needs a label for the local dispatch below to reach.
    #
    # indirect_targets: the caller KNOWS every local target of this body's
    # indirect jumps (jump-table arms, entry-vector labels -- all already in
    # `leaders`). Then only real leaders get labels and the switch lists just
    # those targets. Labelling every instruction makes each one a join point,
    # and the optimiser can keep nothing in registers across any of them:
    # Gunman's span drawer ran slower as one body than as seven tail calls
    # until this. None = unknown targets, label everything, as before.
    has_indirect = any(i.is_uncond_jump and i.get_branch_target() is None
                       for i in instructions)
    label_all = has_indirect and indirect_targets is None

    # A body can hold code BELOW its entry: a branch back to a block the
    # compiler (or an assembly programmer) put before the label. The C runs in
    # address order, so enter at the entry.
    if instructions and instructions[0].address != va:
        lines.append(f'    goto L_{va:08X};')
        leaders = set(leaders) | {va}

    # A branch target is a join point: the lifter's static flag state describes
    # the textually preceding instruction, not the flags a jump arrives with.
    # Carried across the label, `cmp ebx,0x102; jae L` reached L's `jbe` as the
    # TEST_Z of an unrelated `and` just above it (Nocturne's window procedure
    # never saw a WM_CHAR). Forget it there; the jcc reads _flag_k at runtime.
    targets = {t for i in instructions if i.is_jump
               for t in [i.get_branch_target()] if t is not None}

    skip = False
    for k, insn in enumerate(instructions):
        if label_all or insn.address in leaders:
            lines.append(f'L_{insn.address:08X}:')
            if label_all or insn.address in targets:
                lifter._flag_state = None
        if skip:
            skip = False
            continue
        # `push label; jmp func` is a call that returns to `label` (Quake's
        # R_GenerateSpans reaches TrailingEdge this way). A lifted callee
        # returns to its C caller whatever address was pushed, so lifting the
        # jmp as a tail call ended the span loop at the first trailing edge.
        nxt = instructions[k + 1] if k + 1 < len(instructions) else None
        ret = push_return_label(insn, nxt, leaders)
        if ret is not None:
            tgt = nxt.get_branch_target()
            call = (f'RECOMP_CALL(sub_{tgt:08X});' if lifter.lifted is None or tgt in lifter.lifted
                    else f'RECOMP_ICALL(0x{tgt:08X}u);')
            lines.append(f"    {call} RECOMP_FLAGS_IN(); goto L_{ret:08X}; /* 0x{insn.address:08X}: push 0x{ret:08X}; jmp 0x{tgt:08X} */")
            skip = True
            continue
        for line in lifter.lift_instruction(insn):
            lines.append(f'    {line}')

    # A body that runs off its end falls through into whatever the catalog
    # starts there -- typically an epilogue MSVC shares between two paths and
    # the disassembler catalogued as its own entry. A bare `return` skips it:
    # Gunman's vgui.dll small-block heap lost `pop edi/esi/ebx` that way and
    # came back with ebx = 0. So fall through the way the CPU does, as a tail
    # call to the next address.
    if instructions and not (instructions[-1].is_ret or
                             instructions[-1].is_uncond_jump or
                             instructions[-1].mnemonic in ('int3', 'hlt')):
        nxt = instructions[-1].end_address
        lines.append(f'    RECOMP_ITAIL(0x{nxt:08X}u); return; /* falls through */')
    elif instructions and not instructions[-1].is_ret:
        lines.append('    return; /* end of function */')

    # Intra-function indirect jumps lift to RECOMP_ITAIL(expr), but the global
    # dispatch table only knows function *entries* -- it cannot resolve a label
    # inside this body, so every switch statement would break. Route indirect
    # tails through a local label dispatch first and fall back to the global one
    # for genuine cross-function tail calls.
    body = '\n'.join(lines)
    defined = sorted(set(re.findall(r'(?m)^\s*(L_[0-9A-Fa-f]{8})\s*:', body)))
    indirect = [i for i, l in enumerate(lines)
                if 'RECOMP_ITAIL(' in l and 'RECOMP_ITAIL(0x' not in l]
    if indirect and defined:
        for i in indirect:
            m = re.search(r'RECOMP_ITAIL\((.+?)\);\s*return;', lines[i])
            if m:
                lines[i] = ('    { _itail_tgt = (uint32_t)(%s); goto _ljump; }'
                            % m.group(1))
        lines.append('  _ljump:')
        lines.append('    switch (_itail_tgt) {')
        cases = (defined if indirect_targets is None else
                 [lbl for lbl in defined if int(lbl[2:], 16) in indirect_targets])
        for lbl in cases:
            lines.append(f'      case 0x{int(lbl[2:], 16):08X}u: goto {lbl};')
        lines.append('      default: RECOMP_ITAIL(_itail_tgt); return;')
        lines.append('    }')

    # A `goto L_x` whose label is outside this body (the disassembly split a
    # function the compiler did not) has to become a real tail call.
    refed = set(re.findall(r'goto\s+(L_[0-9A-Fa-f]{8})', '\n'.join(lines)))
    for lbl in sorted(refed - set(defined)):
        lines.append(f'    {lbl}: RECOMP_ITAIL(0x{int(lbl[2:], 16):08X}u); return;')

    # With RECOMP_LOCAL_REGS every exit writes the registers back (the macro
    # is empty otherwise), including a body that runs off its closing brace.
    lines.append('    RECOMP_REGS_OUT();')
    lines.append('}')
    out = re.sub(r'\breturn;', '{ RECOMP_REGS_OUT(); return; }', '\n'.join(lines))
    return re.sub(r'CMP_(\w+)\(_fpu_cmp\)',
                  lambda m: f'((_fpu_cmp) {FPU_CMP.get(m.group(1), "==")} 0)', out)


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


EXTENT_REACH = 0x40000      # cap on how far one function's body may reach


def _jump_table(ins, code, code_start, lo, hi, limit=1024):
    """Arms of `jmp dword ptr [reg*4 + table]`, read while they land in [lo, hi)."""
    if not ins.operands or ins.operands[0].type != X86_OP_MEM:
        return []
    mem = ins.operands[0].mem
    if mem.base or not mem.index or mem.scale != 4:
        return []
    arms, at = [], (mem.disp & 0xFFFFFFFF) - code_start
    while 0 <= at <= len(code) - 4 and len(arms) < limit:
        t = int.from_bytes(code[at:at + 4], 'little')
        if not lo <= t < hi:
            break
        arms.append(t)
        at += 4
    return arms


def true_extent(md, code, code_start, start, hard_end, entries, reached=None, behind=None):
    """Exact end of the body at `start`: the highest address reached by
    fallthrough and direct branches. Returns (end, clean).

    A catalog gives an entry and a reachability bound, and neither is an
    extent. Clamping to the next entry cuts functions in half at false starts;
    trusting a reachability `end` decodes unrelated code as one body. Walking
    the branches settles it (forcecommander, where both were tried and broke).

    * A `jmp` to another entry in `entries` is a tail call and ends the path.
      `entries` must hold only real starts, not alias entries: an ordinary
      jump to an alias would stop the walk early (forcecommander 0x00554A00).
    * Fallthrough into another entry ends the path only after a `call`: that
      is the one way real code falls into the next function (a call to a
      noreturn function with nothing after it). After any other instruction
      the "entry" is a false start inside this body, and stopping there cut
      CRT parse_cmdline at 0x00AE7147 into an infinite `dec eax; jmp` loop
      (The Movies).
    * `hard_end` is a reach cap (EXTENT_REACH), never the catalog's clamped
      end. MSVC calls a function's own __finally block with a `call` into the
      middle of its body; the block is then an entry, and the parent's exit
      path jumps past it. Bounded by the clamp, CRT calloc lost its epilogue
      to an unresolved ITAIL (The Movies, 0x00AD578C).

    * `jmp [reg*4 + table]` (an MSVC switch) is followed through the table:
      each dword is an arm while it lands inside [start, hard_end). Without
      this every arm past the table was outside the body and CRT memcpy's
      tail copies became unresolved ITAILs (The Movies, 0x00ACDE33).

    `clean` is False when no path reached ret, int3, a tail call or another
    entry: a health metric for the catalog, not an error.

    Pass a set as `reached` to get every instruction address the walk
    decoded; linear_disassemble_function takes it to lift exactly those, so a
    jump table's bytes are never decoded as instructions.

    Pass a set as `behind` to collect direct branch targets below `start` that
    are not entries: the evidence find_splits() uses.
    """
    view = memoryview(code)
    seen = reached if reached is not None else set()
    work, top, clean = [start], start, False
    while work:
        va = work.pop()
        if va in seen or not (start <= va < hard_end):
            continue
        after_call = False
        for ins in decode(md, view[va - code_start:hard_end - code_start], va):
            if ins.address in seen:
                break
            if after_call and ins.address in entries:
                clean = True        # a noreturn call fell into the next function
                break
            after_call = ins.mnemonic == 'call'
            seen.add(ins.address)
            top = max(top, ins.address + ins.size)
            m = ins.mnemonic
            t = None
            if ins.operands and ins.operands[0].type == X86_OP_IMM:
                t = ins.operands[0].imm & 0xFFFFFFFF
            if m in ('ret', 'retn', 'retf', 'iret', 'int3', 'hlt'):
                clean = True
                break
            if (behind is not None and t is not None and t < start and t not in entries
                    and (m == 'jmp' or m in COND_JUMPS or m.startswith('loop'))):
                behind.add(t)
            if m == 'jmp':
                if t is not None and start < t < hard_end and t not in entries:
                    work.append(t)
                elif t is None:
                    arms = [a for a in _jump_table(ins, code, code_start, start, hard_end)
                            if a not in entries]
                    work.extend(arms)
                    clean = clean or not arms   # an indirect tail call ends the body
                else:
                    clean = True
                break
            if ((m in COND_JUMPS or m.startswith('loop')) and t is not None
                    and start < t < hard_end and t not in entries):
                work.append(t)
    return top, clean


def find_splits(md, code, code_start, code_end, entries):
    """Entries that are really the middle of the entry before them.

    A catalog splits a function when it takes a loop head or a jump target for
    a start. Two things then break: the parent's walk stops when it falls
    through into the false entry, and the false entry's own backward jumps
    land in its parent, where there is no label, so they become unresolved
    ITAILs (The Movies: 2,080 of them in one region).

    The code says which entries these are. A real function does not branch
    backward into the body of the function before it; a split does. So an
    entry E is a split when a walk from E branches to an address that is not
    an entry, lies below E, and lies at or above the entry before E. Treat the
    result like alias entries: remove them from the set true_extent's
    `entries` gets, and keep them dispatchable.
    """
    ordered = sorted(e for e in entries if code_start <= e < code_end)
    splits = set()
    for i, e in enumerate(ordered):
        if i == 0:
            continue
        back = set()
        true_extent(md, code, code_start, e, min(e + EXTENT_REACH, code_end), entries,
                    behind=back)
        if any(ordered[i - 1] <= t < e for t in back):
            splits.add(e)
    return splits


def closure(functions, roots, limit):
    """Breadth-first call-graph closure from `roots`, at most `limit` entries.

    `functions` maps address -> catalog entry with a `calls_to` list (disasm32's
    output). Breadth-first because the first N functions reached from the
    entry point are the startup path, which is what a first run needs; lift
    that, stub the rest to report themselves, and grow by measurement.
    """
    from collections import deque
    seen, order, q = set(), [], deque(r for r in roots if r in functions)
    seen.update(q)
    while q and len(order) < limit:
        a = q.popleft()
        order.append(a)
        for t in functions[a].get('calls_to', ()):
            if t in functions and t not in seen:
                seen.add(t)
                q.append(t)
    return order


def _selftest():
    """Lift a hand-assembled function and check the emitted C.

    This file spent its whole life unimportable -- `from tools.pe_analyze import
    ...` was never a valid path -- so every project forked it instead. A test
    that merely imports it would already have caught that, which is most of why
    this exists.
    """
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    #   push ebp / mov ebp,esp / mov eax,[ebp+8] / jmp eax   (indirect tail)
    code = bytes([0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0xFF, 0xE0])
    base = 0x00401000
    insns, leaders = linear_disassemble_function(
        md, code, base, base, base + len(code))
    assert insns, 'nothing disassembled'
    assert any(i.is_uncond_jump and i.get_branch_target() is None for i in insns),         'the indirect jmp was not recognised'

    out = lift_function_linear(Lifter(iat_map={}), 'sub_00401000',
                              insns, leaders, base)

    # The preamble is the contract lift32 publishes, and nothing more.
    for decl in lift32.FUNCTION_LOCALS:
        assert decl in out, 'missing declared local: %s' % decl

    # The two declarations that used to be emitted here and were wrong. Both
    # expand through recomp_types.h macros, so a local of the same name shadows
    # the global and the breakage is silent.
    for bad in ('double _st[8]', 'int _fp_top = 0', 'uint16_t _fpu_cw',
                'uint32_t ebp = 0'):
        assert bad not in out, 'emitted a shadowing declaration: %s' % bad

    assert 'RECOMP_ENTER(0x00401000u);' in out, out

    # An indirect jump must route through the local label dispatch, so a switch
    # arm inside this same function is reachable; the global dispatch table only
    # knows function entries and would fail to resolve it.
    assert '_ljump:' in out and 'switch (_itail_tgt)' in out, out
    assert 'default: RECOMP_ITAIL(_itail_tgt);' in out, out
    # ...and with an indirect jump present, every instruction gets a label.
    labels = re.findall(r'(?m)^\s*(L_[0-9A-Fa-f]{8})\s*:', out)
    assert len(labels) >= len(insns) - 1, (len(labels), len(insns))

    # int3 is padding BETWEEN functions and unreachable filler INSIDE one.
    #   cmp ebx,0x6c / jbe +1 / int3 / xor eax,eax / ret
    # MSVC emits exactly this for __assume(0), and breaking at the int3 dropped
    # everything a jcc jumped over -- silently, because the target was still a
    # known leader, so the body kept a label it could not place and turned it
    # into a tail transfer to a VA nobody lifted.
    over = bytes([0x83, 0xFB, 0x6C,        # cmp ebx, 0x6c
                  0x76, 0x01,              # jbe +1  (over the int3)
                  0xCC,                    # int3
                  0x33, 0xC0, 0xC3])       # xor eax,eax / ret
    i3, l3 = linear_disassemble_function(md, over, base, base, base + len(over))
    assert i3[-1].mnemonic == 'ret', [i.mnemonic for i in i3]
    assert base + 6 in l3, 'the jumped-over continuation is not a leader'
    out3 = lift_function_linear(Lifter(iat_map={}), 'sub_00401000', i3, l3, base)
    assert 'RECOMP_ITAIL' not in out3, 'the continuation became a tail transfer'

    # A body cut before a shared epilogue must fall INTO it, not return past
    # it: push ebx / xor ebx,ebx -- and the pop/ret belongs to the next entry.
    fall = bytes([0x53, 0x33, 0xDB])
    i4, l4 = linear_disassemble_function(md, fall, base, base, base + len(fall))
    out4 = lift_function_linear(Lifter(iat_map={}), 'sub_00401000', i4, l4, base)
    assert 'RECOMP_ITAIL(0x00401003u); { RECOMP_REGS_OUT(); return; } /* falls through */' in out4, out4

    # ...and trailing int3 padding still ends the body: the first one is
    # emitted (it lifts to a trap, which is correct for unreachable filler) and
    # the sweep stops rather than decoding the rest of the padding run.
    pad = bytes([0x33, 0xC0, 0xC3, 0xCC, 0xCC, 0xCC])
    i4, _ = linear_disassemble_function(md, pad, base, base, base + len(pad))
    assert [i.mnemonic for i in i4] == ['xor', 'ret', 'int3'],         [i.mnemonic for i in i4]

    # ...and a jmp OVER a padding run must not end the body either. MSVC left
    # thirteen int3 between a `jmp` and its target in sub_0066E150, and
    # stopping at the first one dropped four leaders, each of which came out as
    # a RECOMP_ITAIL to a VA nobody lifted.
    #   xor eax,eax / jmp +2 / int3 / int3 / ret
    gap = bytes([0x33, 0xC0,               # xor eax, eax
                 0xEB, 0x02,               # jmp +2  (over both int3)
                 0xCC, 0xCC,               # padding
                 0xC3])                    # ret
    i5, l5 = linear_disassemble_function(md, gap, base, base, base + len(gap))
    assert [i.mnemonic for i in i5] == ['xor', 'jmp', 'int3', 'ret'],         [i.mnemonic for i in i5]
    assert base + 6 in l5, 'the jump target past the padding is not a leader'
    out5 = lift_function_linear(Lifter(iat_map={}), 'sub_00401000', i5, l5, base)
    assert 'RECOMP_ITAIL' not in out5, 'the block past the padding was dropped'
    # ...and the int3 before the gap must not fall through into it.
    assert 'int3 breakpoint */ { RECOMP_REGS_OUT(); return; }' in out5, out5

    # A straight-line function needs no dispatch machinery at all.
    ret = bytes([0x33, 0xC0, 0xC3])            # xor eax,eax / ret
    i2, l2 = linear_disassemble_function(md, ret, base, base, base + len(ret))
    out2 = lift_function_linear(Lifter(iat_map={}), 'sub_00401000', i2, l2, base)
    assert '_ljump' not in out2 and 'switch (_itail_tgt)' not in out2, out2

    # MSVC's float comparison, which is the shape that matters: the branch is
    # taken on `ah`, not on the compare, so `fnstsw` has to produce a real
    # status word. Emitted as a comment it left `ah` stale and every float
    # comparison in the binary branched on whatever was in it.
    #
    #   fld dword [ebp+8] / fcomp dword [ebp+0xc] / fnstsw ax / test ah,0x41 / ret
    fcmp = bytes([0xD9, 0x45, 0x08,
                  0xD8, 0x5D, 0x0C,
                  0xDF, 0xE0,
                  0xF6, 0xC4, 0x41,
                  0xC3])
    i3, l3 = linear_disassemble_function(md, fcmp, base, base, base + len(fcmp))
    out3 = lift_function_linear(Lifter(iat_map={}), 'sub_00401000', i3, l3, base)
    assert '_fpu_cmp' in out3, out3
    assert 'fnstsw - FPU status to ax' not in out3, 'fnstsw is still a comment'
    assert '0x4000u' in out3 and '0x0100u' in out3, out3
    assert 'eax = (eax & 0xFFFF0000u)' in out3, out3

    # true_extent: the calloc shape. A calls its own __finally block B, jumps
    # over it, and its exit path (jne) lands on an epilogue past B. The catalog
    # has B as an entry; the extent must still reach the epilogue, and stop at
    # C, which A never reaches. C ends in a (noreturn) call that falls into D,
    # and must stop there.
    #   1000 test eax,eax / 1002 jne 100c / 1004 call 100b / 1009 jmp 100c
    #   100b B: ret / 100c xor eax,eax / 100e ret / 100f C: call 1000 / 1014 D: ret
    code = bytes([0x85, 0xC0, 0x75, 0x08, 0xE8, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x01,
                  0xC3, 0x31, 0xC0, 0xC3, 0xE8, 0xEC, 0xFF, 0xFF, 0xFF, 0xC3])
    ents = {0x1000, 0x100B, 0x100F, 0x1014}
    assert true_extent(md, code, 0x1000, 0x1000, 0x1015, ents) == (0x100F, True)
    assert true_extent(md, code, 0x1000, 0x100F, 0x1015, ents) == (0x1014, True)
    # ...and the old bound (the catalog clamp at B) is exactly what lost it.
    assert true_extent(md, code, 0x1000, 0x1000, 0x100B, ents)[0] == 0x100B
    # Falling into an "entry" after anything but a call means the entry is a
    # false start inside this body (CRT parse_cmdline): keep going.
    assert true_extent(md, bytes([0x90, 0x90, 0xC3]), 0x1000, 0x1000, 0x1003,
                       {0x1000, 0x1001}) == (0x1003, True)

    # A switch: jmp [eax*4 + 0x1008], a pad byte, the table (arms 0x1010,
    # 0x1012), then the arms. The walk must reach both arms, and the sweep
    # given the walk's set must decode the arms and not the table bytes.
    #   1000 jmp [eax*4+1008] / 1007 int3 / 1008 dd 1010, 1012 / 1010 xor / 1012 ret
    code = bytes([0xFF, 0x24, 0x85, 0x08, 0x10, 0x00, 0x00, 0xCC,
                  0x10, 0x10, 0x00, 0x00, 0x12, 0x10, 0x00, 0x00,
                  0x31, 0xC0, 0xC3])
    got = set()
    assert true_extent(md, code, 0x1000, 0x1000, 0x1013, {0x1000}, reached=got) == (0x1013, True)
    assert got == {0x1000, 0x1010, 0x1012}, sorted(map(hex, got))
    insns, _ = linear_disassemble_function(md, code, 0x1000, 0x1000, 0x1013, reached=got)
    assert [i.address for i in insns] == [0x1000, 0x1010, 0x1012], [hex(i.address) for i in insns]

    # A split: the catalog took 0x1003, the middle of a loop, for an entry.
    #   1000 xor eax,eax / 1002 inc eax / 1003 cmp eax,5 / 1006 jb 1002 / 1008 ret
    code = bytes([0x31, 0xC0, 0x40, 0x83, 0xF8, 0x05, 0x72, 0xFA, 0xC3])
    ents = {0x1000, 0x1003}
    assert true_extent(md, code, 0x1000, 0x1000, 0x1009, ents) == (0x1009, True)  # walks through it
    assert find_splits(md, code, 0x1000, 0x1009, ents) == {0x1003}
    assert true_extent(md, code, 0x1000, 0x1000, 0x1009, ents - {0x1003}) == (0x1009, True)
    # ...and a real neighbour is not a split: C above only falls into D.
    code = bytes([0x90, 0x90, 0xC3, 0x40, 0xC3])     # 1000 nop,nop,ret / 1003 D: inc, ret
    assert find_splits(md, code, 0x1000, 0x1005, {0x1000, 0x1003}) == set()

    fns = {1: {'calls_to': [2, 3]}, 2: {'calls_to': [4]}, 3: {}, 4: {'calls_to': [1]}}
    assert closure(fns, [1], 10) == [1, 2, 3, 4]
    assert closure(fns, [1], 2) == [1, 2]

    print('generate.py self-test OK')


def main():
    if '--selftest' in sys.argv:
        _selftest()
        return
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

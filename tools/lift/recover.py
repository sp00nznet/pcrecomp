"""
recover.py - Find the functions your disassembler's catalog is missing.

IDA (or any function-boundary source) misses two kinds of entry point, and both
break a static recompile in ways that are annoying to diagnose:

  * **Unlisted functions** reached only through jmp-thunk chains or tail calls,
    with no direct CALL and no standard prologue, and functions reached only
    through a stored function pointer (`mov [table], imm` / `push imm`). At
    runtime these surface as `ITAIL/ICALL: unresolved VA ...` and stall.

  * **Alternate entry points**: a direct CALL to an address *inside* a listed
    function's body, because several small routines got merged into one. The CPU
    will execute from there, so it needs its own lifted body. Without one the
    lifter emits a call to a function nobody defines and the build dies at link
    time with an unresolved external.

Both are found here, so project drivers stop carrying a hand-maintained list of
addresses that only grows when someone reads a link error.

    from recover import recover_functions
    extra = recover_functions(code_data, code_start, code_end, known_fns)
    # -> [(start, end), ...] sorted, exact bounds, none already listed

`code_data` is the code image, indexed by (va - code_start). `known_fns` is an
iterable of (start, end). `forced` adds entries that must be recovered even
though they overlap a listed body -- for targets this scan cannot see, such as
one reached only through a computed jump.

Part of the pcrecomp toolbox.
"""
import bisect

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM

__all__ = ['recover_functions']

_COND_J = {'je', 'jne', 'jz', 'jnz', 'ja', 'jae', 'jb', 'jbe', 'jg', 'jge',
           'jl', 'jle', 'js', 'jns', 'jo', 'jno', 'jp', 'jnp', 'jcxz', 'jecxz',
           'loop', 'loope', 'loopne'}

_STOP = ('ret', 'retn', 'retf', 'iret', 'int3')

# How far past a seed an intra-function jump may land. Beyond this we treat the
# jump as a tail call into a different function instead of a branch within this
# one. 16 KB is comfortably larger than any single function seen in practice.
_INTRA_SPAN = 0x4000

# Bytes to decode from a seed before giving up on finding its end.
_DECODE_WINDOW = 2048


def recover_functions(code_data, code_start, code_end, known_fns, forced=()):
    """Recover (start, end) for entry points missing from `known_fns`."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    fns = sorted(known_fns)
    starts = [a for a, _ in fns]
    entries = {a for a, _ in fns}

    def covered(a):
        i = bisect.bisect_right(starts, a) - 1
        return i >= 0 and fns[i][0] <= a < fns[i][1]

    def imm_of(ins):
        ops = ins.operands
        if ops and ops[0].type == X86_OP_IMM:
            return ops[0].imm & 0xFFFFFFFF
        return None

    def slice_at(va, n=_DECODE_WINDOW):
        o = va - code_start
        return code_data[o:o + n] if 0 <= o < len(code_data) else b''

    def in_code(t):
        return t is not None and code_start <= t < code_end

    # Pass 1: sweep every known body for
    #   (a) direct jmp/call targets that land outside all known functions,
    #   (b) any code-address immediate at all (function pointers stored to a
    #       table, which have no direct call anywhere), and
    #   (c) direct CALL targets that ARE covered but are not that body's entry --
    #       the alternate entry points.
    # Pass 2 validates every seed by decoding it, so a stray data immediate that
    # merely looks like a code address just decodes to code nobody calls.
    # For (c) only `call` counts: a `jmp` into a covered range is ordinary
    # intra-function control flow, not a separate routine.
    seeds = set()
    alt_entries = set()
    for ea, end in fns:
        last = None
        for ins in md.disasm(slice_at(ea, end - ea), ea):
            last = ins
            if ins.mnemonic in ('jmp', 'call'):
                t = imm_of(ins)
                if in_code(t) and t not in entries:
                    if not covered(t):
                        seeds.add(t)
                    elif ins.mnemonic == 'call':
                        alt_entries.add(t)
                    elif not (ea <= t < end):
                        # A `jmp` landing inside a *different* function's body is
                        # an alternate entry too. Only a jump within this same
                        # function is ordinary control flow -- that distinction
                        # matters, because a cross-function jump is a tail call
                        # to a mid-body address and needs its own lifted body.
                        alt_entries.add(t)
            for op in (ins.operands or []):
                if op.type == X86_OP_IMM:
                    t = op.imm & 0xFFFFFFFF
                    if in_code(t) and t not in entries and not covered(t):
                        seeds.add(t)

        # A body whose last instruction neither returns nor jumps falls through
        # into whatever follows, so that address has to be dispatchable: the
        # lifted body ends in a tail call to it, and the `ret` that pops the
        # caller's return address usually lives there. Catalogs split routines
        # this way routinely.
        if last is not None and last.mnemonic not in _STOP and last.mnemonic != 'jmp':
            t = last.address + last.size
            if in_code(t) and t not in entries:
                (seeds if not covered(t) else alt_entries).add(t)

    # Pass 2: recursively decode each seed, plus everything it reaches, to a
    # fixpoint, computing exact [start, end) bounds.
    recovered = {}
    forced_set = {s for s in (set(forced) | alt_entries)
                  if code_start <= s < code_end and s not in entries}
    work = list(seeds) + list(forced_set)

    while work:
        s = work.pop()
        # Forced entries are allowed to overlap an existing body; seeds are not.
        if s in recovered or (covered(s) and s not in forced_set):
            continue
        visited = set()
        blocks = [s]
        maxend = s
        while blocks:
            va = blocks.pop()
            if va in visited:
                continue
            for ins in md.disasm(slice_at(va), va):
                if ins.address in visited:
                    break
                visited.add(ins.address)
                maxend = max(maxend, ins.address + ins.size)
                m = ins.mnemonic
                t = imm_of(ins)
                if m == 'call':
                    if in_code(t) and t not in entries and not covered(t):
                        work.append(t)
                    continue
                if m == 'jmp':
                    if t is not None:
                        if s <= t < s + _INTRA_SPAN and not covered(t):
                            blocks.append(t)          # intra-function jump
                        elif in_code(t) and t not in entries and not covered(t):
                            work.append(t)            # tail call / thunk target
                    break
                if m in _COND_J:
                    if t is not None and s <= t < s + _INTRA_SPAN and not covered(t):
                        blocks.append(t)
                    continue
                if m in _STOP:
                    break
        recovered[s] = maxend

    return sorted(recovered.items())


def _selftest():
    """Assemble a tiny image exercising both kinds of missed entry point."""
    BASE, END = 0x1000, 0x3000
    img = bytearray(b'\x90' * (END - BASE))     # nop fill

    def put(va, data):
        img[va - BASE:va - BASE + len(data)] = data

    def call(at, target):
        return b'\xe8' + ((target - (at + 5)) & 0xFFFFFFFF).to_bytes(4, 'little')

    # A listed function 0x1000..0x1010:
    #   calls 0x2000 -- outside every listed function  -> a missed function
    #   calls 0x100F -- inside its own body, not its entry -> alternate entry
    put(0x1000, call(0x1000, 0x2000))
    put(0x1005, call(0x1005, 0x100F))
    put(0x100F, b'\xc3')                        # ret, the alternate entry
    put(0x2000, b'\xc3')                        # the missed function

    known = [(0x1000, 0x1010)]
    got = dict(recover_functions(bytes(img), BASE, END, known))

    assert 0x2000 in got, "missed the uncovered call target: %r" % (got,)
    assert got[0x2000] == 0x2001, "wrong end for 0x2000: %#x" % got[0x2000]
    assert 0x100F in got, "missed the alternate entry point: %r" % (got,)
    assert got[0x100F] == 0x1010, "wrong end for 0x100F: %#x" % got[0x100F]
    assert 0x1000 not in got, "re-recovered a function that was already listed"

    # A *jmp* into a covered body is ordinary control flow, not a new entry.
    img2 = bytearray(b'\x90' * (END - BASE))
    img2[0x1000 - BASE:0x1000 - BASE + 5] = (
        b'\xe9' + ((0x100F - 0x1005) & 0xFFFFFFFF).to_bytes(4, 'little'))
    img2[0x100F - BASE] = 0xC3
    got2 = dict(recover_functions(bytes(img2), BASE, END, [(0x1000, 0x1010)]))
    assert 0x100F not in got2, "a jmp into a covered body must not become an entry"

    # ...but a jmp into a *different* function's body is an alternate entry.
    img3 = bytearray(b'\x90' * (END - BASE))
    img3[0x1010 - BASE:0x1010 - BASE + 5] = (
        b'\xe9' + ((0x1008 - 0x1015) & 0xFFFFFFFF).to_bytes(4, 'little'))
    img3[0x1008 - BASE] = 0xC3
    img3[0x100F - BASE] = 0xC3
    got3 = dict(recover_functions(bytes(img3), BASE, END,
                                  [(0x1000, 0x1010), (0x1010, 0x1020)]))
    assert 0x1008 in got3, "cross-function jmp target was not recovered: %r" % (got3,)

    # A body that neither returns nor jumps falls through, and the address it
    # falls into must be dispatchable.
    img4 = bytearray(b'\x90' * (END - BASE))
    img4[0x1005 - BASE] = 0xC3
    got4 = dict(recover_functions(bytes(img4), BASE, END, [(0x1000, 0x1005)]))
    assert 0x1005 in got4, "fall-through target was not recovered: %r" % (got4,)

    # Nothing to find in an image of pure returns.
    img5 = bytes(b'\xc3' * (END - BASE))
    assert recover_functions(img5, BASE, END, [(0x1000, 0x1001)]) == []

    print("recover.py self-test OK")


if __name__ == '__main__':
    import sys
    if sys.argv[1:2] == ['--selftest']:
        _selftest()
    else:
        print(__doc__.strip())

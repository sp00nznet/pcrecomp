"""Where a lifted x86-32 function resumes after one of its catch blocks.

The runtime half is runtime/native32/eh32.c, which has the whole scheme. A
guest throw that a function catches ends with the catch funclet returning an
address *inside that function* (`mov eax, offset $L; ret`), and execution
continues there with the frame's ebp and saved esp. Lifted, that address must
be a label the function's local dispatch can reach, and the function needs a
landing pad for the runtime to longjmp to. This module finds both from the
same data MSVC's __CxxFrameHandler reads:

    push ebp; mov ebp, esp; push -1; push offset handler
    mov eax, fs:[0]; push eax; mov fs:[0], esp       <- installs the frame
    handler:  mov eax, offset FuncInfo; jmp __CxxFrameHandler
    FuncInfo: magic 0x1993052x, maxState, pUnwindMap, nTryBlocks, pTryBlockMap
    TryBlockMapEntry: tryLow, tryHigh, catchHigh, nCatches, pHandlerArray
    HandlerType: adjectives, pType, dispCatchObj, addressOfHandler

The frame's handlers put ebp at record + 12. With `push ebp; mov ebp, esp`
first that is the function's own ebp (entry esp - 4); a frame-pointer-omitted
function (`push -1; push handler; mov eax, fs:[0]` at entry, how VC6 /O2
builds most of them) has it at entry esp itself. frame() works out which by
counting the prologue's pushes, and the runtime matches a landing pad by it.

__try/__except frames (_except_handler3) are found the same way:

    push ebp; mov ebp, esp; push -1; push offset scopetable
    push offset __except_handler3; mov eax, fs:[0]; push eax; mov fs:[0], esp
    scopetable[i]: enclosing level, filter, handler (12 bytes)

and _except_handler3 enters an __except block (filter != 0) by calling its
handler address with ebp = record + 16. Those addresses are the resume
points. The filters and __finally blocks are called and return, so they are
ordinary entries (disasm32.eh_entries); an __except block must NOT be a
dispatch entry, or the call would run it as a function of its own.
"""
import struct

EH_MAGICS = (0x19930520, 0x19930521, 0x19930522)
PROLOGUE_WINDOW = 12     # instructions: the frame is installed right at entry
FUNCLET_WINDOW = 0x800   # bytes of a catch funclet scanned for its returns
STUB_WINDOW = 40         # bytes of a handler stub searched for its FuncInfo


def funcinfo(read, handler):
    """FuncInfo VA a C++ EH handler stub names, or None. The stub is
    `mov eax, FuncInfo; jmp __CxxFrameHandler`, after a /GS cookie check in
    VC8 and later (so the mov is searched for in its first bytes)."""
    h = read(handler, STUB_WINDOW + 7) or b''
    for k in range(min(len(h) - 6, STUB_WINDOW)):
        if h[k] == 0xB8 and (h[k + 5] == 0xE9 or h[k + 5:k + 7] == bytes((0xFF, 0x25))):
            fi = struct.unpack_from('<I', h, k + 1)[0]
            m = read(fi, 4)
            if m and len(m) == 4 and struct.unpack('<I', m)[0] in EH_MAGICS:
                return fi
    return None


def catch_funclets(read, fi):
    """Every catch funclet VA a FuncInfo names."""
    ntry, tries = struct.unpack('<II', read(fi + 12, 8))
    out = []
    for t in range(min(ntry, 4096)):
        _lo, _hi, _chi, ncatch, handlers = struct.unpack('<5I', read(tries + 20 * t, 20))
        for c in range(min(ncatch, 256)):
            out.append(struct.unpack('<I', read(handlers + 16 * c + 12, 4))[0])
    return out


def funclet_returns(md, read, va):
    """Addresses a catch funclet returns (`mov eax, imm32` just before `ret`)."""
    code = read(va, FUNCLET_WINDOW) or b''
    out, prev = set(), None
    for ins in md.disasm(code, va):
        if ins.mnemonic == 'ret' and prev is not None:
            out.add(prev)
        prev = None
        if ins.mnemonic == 'mov' and ins.op_str.startswith('eax, 0x'):
            prev = int(ins.op_str[5:], 16)
        if ins.mnemonic == 'int3':
            break
    return out


def _int(text):
    try:
        return int(text, 0)
    except ValueError:
        return None


def scope_table(read, table, levels):
    """(filter, handler) for each of a scope table's first `levels` entries."""
    out = []
    for k in range(min(levels, 256)):
        raw = read(table + 12 * k, 12)
        if not raw or len(raw) < 12:
            break
        _enclosing, flt, handler = struct.unpack('<3I', raw)
        out.append((flt, handler))
    return out


def try_levels(insns):
    """1 + the highest __try level the body sets (`mov [ebp-4], N`)."""
    top = -1
    for ins in insns:
        if ins.mnemonic == 'mov' and ins.op_str.startswith('dword ptr [ebp - 4], '):
            n = _int(ins.op_str.rsplit(', ', 1)[1])
            if n is not None and 0 <= n < 0x10000:
                top = max(top, n)
    return top + 1


def frame(md, read, insns):
    """None if the function installs no MSVC EH frame in its prologue; else
    (resume points, off): the addresses inside it that a handler continues
    at, and entry esp minus the ebp its handlers use (RECOMP_EH_FRAME)."""
    depth, imms = 0, []      # bytes pushed since entry; immediates pushed
    for ins in insns[:PROLOGUE_WINDOW]:
        m, op = ins.mnemonic, ins.op_str
        if m == 'push':
            depth += 4
            if _int(op) is not None:
                imms.append(_int(op) & 0xFFFFFFFF)
        elif m == 'mov' and op == 'dword ptr fs:[0], esp':
            # The record is at entry - depth; the handler was pushed last.
            if not imms:
                return None
            fi = funcinfo(read, imms[-1])
            if fi is not None:
                out = set()
                for f in catch_funclets(read, fi):
                    out |= funclet_returns(md, read, f)
                return out, depth - 12
            if len(imms) >= 2:          # SEH: ..., scope table, handler
                out = {h for flt, h in scope_table(read, imms[-2], try_levels(insns)) if flt}
                return (out, depth - 16) if out else None
            return None
        elif not (m == 'mov' and (op == 'ebp, esp' or op.endswith('dword ptr fs:[0]'))):
            return None
    return None


def resume_points(md, read, insns):
    """frame()'s resume points alone, for drivers written before it."""
    f = frame(md, read, insns)
    return None if f is None else f[0]


def _selftest():
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    mem = {}

    def put(va, raw):
        mem.update({va + i: b for i, b in enumerate(raw)})

    def read(va, n):
        return bytes(mem.get(va + i, 0xCC) for i in range(n))
    # An MSVC6 guarded function at 0x1000: handler stub at 0x2000, FuncInfo at
    # 0x3000, one try block with one catch(...) whose funclet at 0x1100 resumes
    # at 0x1050.
    put(0x1000, bytes.fromhex('558bec6aff6800200000' '64a100000000' '50' '64892500000000'))
    put(0x2000, bytes.fromhex('b800300000' 'e900000000'))
    put(0x3000, struct.pack('<5I', 0x19930520, 1, 0x3100, 1, 0x3200))
    put(0x3200, struct.pack('<5I', 0, 0, 1, 1, 0x3300))
    put(0x3300, struct.pack('<4I', 0, 0, 0, 0x1100))
    put(0x1100, bytes.fromhex('b850100000' 'c3'))
    insns = list(md.disasm(read(0x1000, 24), 0x1000))
    assert resume_points(md, read, insns) == {0x1050}, resume_points(md, read, insns)
    # A plain function.
    assert resume_points(md, read, list(md.disasm(bytes.fromhex('558bec33c05dc3'), 0x4000))) is None
    # The same frame, frame-pointer omitted: the handlers' ebp is entry esp.
    put(0x1400, bytes.fromhex('6aff6800200000' '64a100000000' '50' '64892500000000'))
    fpo = list(md.disasm(read(0x1400, 24), 0x1400))
    assert frame(md, read, fpo) == ({0x1050}, 0), frame(md, read, fpo)
    assert frame(md, read, insns) == ({0x1050}, 4)
    # A __try with two levels: 0 an __except (filter 0x1700, block 0x1710),
    # 1 a __finally (no filter, so no resume point).
    put(0x1600, bytes.fromhex('558bec6aff6800400000' '6800500000' '64a100000000' '50' '64892500000000'
                              'c745fc00000000' 'c745fc01000000'))
    put(0x4000, struct.pack('<6I', 0xFFFFFFFF, 0x1700, 0x1710, 0, 0, 0x1720))
    put(0x5000, bytes.fromhex('558bec'))       # _except_handler3: not a FuncInfo stub
    seh = list(md.disasm(read(0x1600, 40), 0x1600))
    assert frame(md, read, seh) == ({0x1710}, 4), frame(md, read, seh)
    print('eh32 selftest: ok')


if __name__ == '__main__':
    _selftest()

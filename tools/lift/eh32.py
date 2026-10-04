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

The runtime finds a frame's ebp as record + 12 and requires that to be the
function's own `push ebp; mov ebp, esp` frame (entry esp - 4), so a function
whose prologue does not open with that gets no landing pad, and a throw it
would catch is reported as uncaught rather than resumed in the wrong place.
"""
import struct

EH_MAGICS = (0x19930520, 0x19930521, 0x19930522)
PROLOGUE_WINDOW = 12     # instructions: the frame is installed right at entry
FUNCLET_WINDOW = 0x800   # bytes of a catch funclet scanned for its returns


def funcinfo(read, handler):
    """FuncInfo VA a C++ EH handler stub names, or None."""
    h = read(handler, 11)
    if not h or h[0] != 0xB8 or not (h[5] == 0xE9 or h[5:7] == b'\xFF\x25'):
        return None
    fi = struct.unpack_from('<I', h, 1)[0]
    m = read(fi, 4)
    return fi if m and struct.unpack('<I', m)[0] in EH_MAGICS else None


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


def resume_points(md, read, insns):
    """None if the function installs no C++ EH frame of its own; else the set
    of addresses its catch funclets resume at (possibly empty: a frame with
    only unwind actions still needs no landing pad, but is reported)."""
    head = insns[:PROLOGUE_WINDOW]
    if len(head) < 2 or head[0].mnemonic != 'push' or head[0].op_str != 'ebp' \
            or head[1].mnemonic != 'mov' or head[1].op_str != 'ebp, esp':
        return None
    handler = None
    for ins in head:
        if ins.mnemonic == 'push' and ins.op_str.startswith('0x'):
            handler = int(ins.op_str, 16)
        elif ins.mnemonic == 'mov' and ins.op_str.endswith('dword ptr fs:[0]') and handler is not None:
            fi = funcinfo(read, handler)
            if fi is None:
                return None
            out = set()
            for f in catch_funclets(read, fi):
                out |= funclet_returns(md, read, f)
            return out
    return None


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
    # Without push ebp; mov ebp, esp first, no landing pad.
    assert resume_points(md, read, insns[1:]) is None
    # A plain function.
    assert resume_points(md, read, list(md.disasm(bytes.fromhex('558bec33c05dc3'), 0x4000))) is None
    print('eh32 selftest: ok')


if __name__ == '__main__':
    _selftest()

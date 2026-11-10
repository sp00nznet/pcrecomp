"""`Lifter(computed_ret=True)`: a `ret` to an address the code pushed is a jump.

Hand-written asm chains handlers through the stack. Messiah's movie decoder
does `push loop; push [h2]; jmp [h1]`: h1's `ret` goes to h2, h2's to the loop.
Lifted as plain returns, the first `ret` left the decoder entirely, two slots
off, and its caller walked its chunk list with a pixel pair for a length.

With the option, a `ret` that finds anything but the dummy return address on
top of the stack pops it and jumps there; without it, nothing changes.

Run: py -3 tools/lift/test_computed_ret.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import capstone

from generate import LinearInstruction
from lift32 import Lifter


def emit(encoding, **kw):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    insn = LinearInstruction(next(iter(md.disasm(encoding, 0x1000))))
    return "\n".join(Lifter(**kw).lift_instruction(insn))


def main():
    bad = 0
    for enc in (b"\xc3", b"\xc2\x08\x00"):         # ret, ret 8
        on, off = emit(enc, computed_ret=True), emit(enc)
        if "RECOMP_RET_JUMP(_rt)" not in on or "MEM32(esp) != RECOMP_RETADDR" not in on:
            print("FAIL %s with computed_ret: no computed jump:\n%s" % (enc.hex(), on))
            bad += 1
        if "RECOMP_RET_JUMP" in off:
            print("FAIL %s without computed_ret: changed:\n%s" % (enc.hex(), off))
            bad += 1
        if "return;" not in on:
            print("FAIL %s with computed_ret: the plain return is gone:\n%s" % (enc.hex(), on))
            bad += 1
    # jmp edx: a return when edx holds the dummy return address it popped.
    on, off = emit(bytes((0xFF, 0xE2)), computed_ret=True), emit(bytes((0xFF, 0xE2)))
    if "edx == RECOMP_RETADDR" not in on or "RECOMP_RETADDR" in off:
        print("FAIL jmp edx: the popped-return check is wrong:", on, off, sep=chr(10))
        bad += 1
    print("computed_ret: %s" % ("FAIL" if bad else "ok"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

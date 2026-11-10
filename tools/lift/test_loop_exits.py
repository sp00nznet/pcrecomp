"""loop, loope, loopne and jecxz leave the function the way jmp and jcc do.

A taken branch whose target is not a block of the function being lifted has
no label to go to. jmp and jcc already dispatch and return there; loop and
jecxz emitted `goto L_<target>` regardless, and the generated file failed to
compile with an undefined label.

Run: py -3 tools/lift/test_loop_exits.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import capstone

from generate import LinearInstruction
from lift32 import Lifter


def lift(code, labels):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    lifter = Lifter()
    lifter._labels = labels
    out = []
    for insn in md.disasm(code, 0x1000):
        out += lifter.lift_instruction(LinearInstruction(insn))
    return "\n".join(out)


def branch_line(c, mnemonic):
    return next(l for l in c.splitlines() if mnemonic in l)


def main():
    bad = 0
    # Each branches back to 0x1000 (the inc): a block of the function in the
    # first case, outside it in the second.
    cases = [
        (b"\x47\xe2\xfd", "loop"),     # inc edi; loop -3
        (b"\x47\xe1\xfd", "loope"),    # inc edi; loope -3
        (b"\x47\xe0\xfd", "loopne"),   # inc edi; loopne -3
        (b"\x47\xe3\xfd", "jecxz"),    # inc edi; jecxz -3
    ]
    for code, m in cases:
        inside = branch_line(lift(code, {0x1000}), m)
        if "goto L_00001000;" not in inside or "RECOMP_ITAIL" in inside:
            print("FAIL %s inside: %s" % (m, inside))
            bad += 1
        outside = branch_line(lift(code, {0x2000}), m)
        if "goto" in outside or "RECOMP_ITAIL(0x00001000u); return;" not in outside:
            print("FAIL %s outside: %s" % (m, outside))
            bad += 1
    print("test_loop_exits: %s" % ("FAILED" if bad else "ok"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

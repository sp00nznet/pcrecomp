"""fninit resets the x87 control word: the FPU probe reads it right after.

Run: py -3 tools/lift/test_finit.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import capstone

from generate import LinearInstruction
from lift32 import Lifter


def main():
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    bad = 0
    for enc in (bytes((0xDB, 0xE3)),):     # fninit (finit is wait + fninit)
        insn = LinearInstruction(next(iter(md.disasm(enc, 0x1000))))
        out = "\n".join(Lifter().lift_instruction(insn))
        if "_fpu_cw = 0x037F" not in out:
            print("FAIL %s does not reset the control word:\n%s" % (enc.hex(), out))
            bad += 1
    print("finit: %s" % ("FAIL" if bad else "ok"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

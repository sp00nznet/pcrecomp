"""fcmovcc copies st(i) to st(0) on the EFLAGS condition fucomip just set.

Run: py -3 tools/lift/test_fcmov.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import capstone

from generate import LinearInstruction
from lift32 import Lifter

CASES = (                       # encoding, mnemonic, the condition it must read
    (bytes((0xDB, 0xC1)), 'fcmovnb', 'CC_AE'),
    (bytes((0xDA, 0xC2)), 'fcmovb', 'CC_B'),
    (bytes((0xDA, 0xC9)), 'fcmove', 'CC_E'),
    (bytes((0xDA, 0xD1)), 'fcmovbe', 'CC_BE'),
    (bytes((0xDA, 0xD9)), 'fcmovu', '_flag_a >> 2'),
)


def main():
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    bad = 0
    for enc, mn, cond in CASES:
        lf = Lifter()
        lines = []
        for b in (bytes((0xDF, 0xE9)), enc):          # fucomip st(1), then the fcmov
            insn = LinearInstruction(next(iter(md.disasm(b, 0x1000))))
            lines += lf.lift_instruction(insn)
        out = "\n".join(lines)
        i = enc[1] & 7
        if insn.mnemonic != mn or "UNIMPLEMENTED" in out or cond not in out \
                or ("_st[0] = _st[%d]" % i) not in out:
            print("FAIL %s (%s):\n%s" % (enc.hex(), insn.mnemonic, out))
            bad += 1
    print("fcmov: %s" % ("FAIL" if bad else "ok"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

"""`repz ret` (F3 C3) lifts as a ret, and ends a function's extent.

AMD's branch-prediction idiom for a plain `ret`. MSVC 2005 and later emit it,
and the one that matters is __security_check_cookie's:

    cmp ecx, [__security_cookie]; jne fail; repz ret; fail: jmp __report_gsfailure

lift32 left it UNIMPLEMENTED, so a cookie that matched fell through into the
failure path, and every /GS-checked function ended the process with
0xC0000409. Found on Tiberium Wars, eleven calls into its CRT startup.

Run: py -3 tools/lift/test_repz_ret.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import capstone

from generate import LinearInstruction, true_extent
from lift32 import Lifter


def emit(encoding):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    insn = LinearInstruction(next(iter(md.disasm(encoding, 0x1000))))
    return "\n".join(Lifter().lift_instruction(insn)), insn


def main():
    bad = 0
    for enc in (b"\xf3\xc3", b"\xf2\xc3", b"\xc3"):   # repz ret, bnd ret, ret
        c, insn = emit(enc)
        if "UNIMPLEMENTED" in c or "return" not in c or "esp += 4" not in c:
            print("FAIL %s: not a ret:\n%s" % (enc.hex(), c))
            bad += 1
        if not insn.is_ret:
            print("FAIL %s: is_ret is False" % enc.hex())
            bad += 1
    # __security_check_cookie's shape, then a neighbour: the extent stops at the
    # `repz ret` path's jmp, and is clean, rather than running on.
    code = (b"\x3b\x0d\x90\xc5\xb7\x00"   # cmp ecx, [0xb7c590]
            b"\x75\x02"                   # jne +2
            b"\xf3\xc3"                   # repz ret
            b"\xf3\xc3"                   # (the jne target: another repz ret)
            b"\x90" * 8)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    end, clean = true_extent(md, code, 0x1000, 0x1000, 0x1000 + len(code), {0x1000})
    if not clean or end != 0x1000 + 12:
        print("FAIL extent: end 0x%X clean %s, want 0x%X clean True" % (end, clean, 0x1000 + 12))
        bad += 1
    print("test_repz_ret: %s" % ("FAILED" if bad else "ok"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

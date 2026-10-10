"""movntq and the SSE cache hints: how an Unreal Engine 2 appMemcpy copies.

UE2's Core inlines an MMX/SSE block copy into every module: movq loads,
movntq stores, prefetchnta ahead, sfence at the end. Lifted as no-ops, the
stores vanished and the copy left its destination untouched.

Run: py -3 tools/lift/test_nontemporal.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import capstone

from lift32 import Lifter


def emit(encoding):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    insn = next(iter(md.disasm(encoding, 0x1000)))
    return " ".join(Lifter(iat_map={}, lifted=set()).lift_instruction(insn))


def main():
    movq = emit(b"\x0f\x7f\x47\xc0")          # movq   [edi-0x40], mm0
    movntq = emit(b"\x0f\xe7\x47\xc0")        # movntq [edi-0x40], mm0
    assert "UNIMPLEMENTED" not in movntq, movntq
    assert movntq.split(";")[0] == movq.split(";")[0], (movq, movntq)  # the same store
    for enc in (b"\x0f\x18\x06",              # prefetchnta [esi]
                b"\x0f\x18\x4e\x40",          # prefetcht0 [esi+0x40]
                b"\x0f\xae\xf8",              # sfence
                b"\x0f\xae\xe8",              # lfence
                b"\x0f\xae\xf0"):             # mfence
        c = emit(enc)
        assert "UNIMPLEMENTED" not in c and "MEM" not in c, c
    print("test_nontemporal: ok")


if __name__ == "__main__":
    main()

"""Lifter(dos=True): the instructions a DOS-extender program needs from its host.

Without the flag, `int 21h` is UNIMPLEMENTED and `out dx, al` a comment,
which is right for Win32 code (where they are dead bytes) and fatal for a
DOS/4GW game, whose every file read, palette write and timer tick goes
through them. Found on Theme Park (Watcom, LE).

Run: py -3 tools/lift/test_dos_hooks.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import capstone

from generate import LinearInstruction
from lift32 import Lifter


def emit(encoding, dos=True):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    insn = LinearInstruction(next(iter(md.disasm(encoding, 0x1000))))   # as generate.py hands it over
    return " ".join(Lifter(dos=dos).lift_instruction(insn))


def main():
    cases = [
        (b"\xcd\x21", "recomp_int(0x21)"),
        (b"\xcd\x31", "RECOMP_FLAGS_IN()"),           # CF comes back from DPMI
        (b"\xee", "recomp_out8((edx & 0xFFFFu), LO8(eax))"),
        (b"\x66\xef", "recomp_out16((edx & 0xFFFFu), LO16(eax))"),
        (b"\xe6\x43", "recomp_out8(67u, "),
        (b"\xec", "recomp_in8((edx & 0xFFFFu))"),
        (b"\xe4\x60", "recomp_in8(96u)"),
        (b"\xf3\x6e", "recomp_outs(edx & 0xFFFFu, esi, 1, ecx, _df)"),
        (b"\xfa", "recomp_cli()"),
        (b"\xfb", "recomp_sti()"),
        (b"\xf4", "recomp_hlt()"),
        (b"\xcf", "esp += 12; return;"),
        (b"\xc3", "RECOMP_RET_JUMP(_rt)"),                  # push x; ret is a jump
        (b"\xff\x18", "PUSH32(esp, _seg_cs); RECOMP_ICALL(MEM32("),  # call far [eax]
        (b"\xcb", "esp += 8; return;"),                     # retf
        (b"\xca\x04\x00", "esp += 12; return;"),            # retf 4
        # Segment loads keep the host's base in step; es: reads through it.
        (b"\x8e\xe8", "recomp_set_seg(5, "),                # mov gs, ax
        (b"\x07", "recomp_set_seg(0, POP32_VAL(esp))"),     # pop es
        (b"\xc4\x38", "recomp_set_seg(0, MEM16("),          # les edi, [eax]
        (b"\x26\x8b\x1d\x5c\x00\x00\x00", "ES_BASE + (0x5C)"),  # mov ebx, es:[0x5c]
        (b"\x65\x8a\x40\x02", "GS_BASE + ("),               # mov al, gs:[eax+2]
    ]
    bad = 0
    for enc, want in cases:
        got = emit(enc)
        if want not in got:
            print("FAIL %s: want %r in %r" % (enc.hex(), want, got))
            bad += 1
    # Off by default: Win32 titles keep their old output.
    if "recomp_int" in emit(b"\xcd\x21", dos=False):
        print("FAIL: int lifted to a hook without dos=True")
        bad += 1
    print("%d/%d passed" % (len(cases) + 1 - bad, len(cases) + 1))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

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


def decode(encoding):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    return LinearInstruction(next(iter(md.disasm(encoding, 0x1000))))   # as generate.py hands it over


def emit(encoding, dos=True, ds_fn=False):
    lifter = Lifter(dos=dos)
    lifter._seg_fn = ds_fn          # what generate.py sets for a function that loads ds
    return " ".join(lifter.lift_instruction(decode(encoding)))


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
        (b"\xff\x18", "PUSH32(esp, _seg_cs);"),            # call far [eax]
        (b"\xff\x18", "RECOMP_ICALL(CS_BASE + MEM32("),    # ... at the selector's base (a loaded driver)
        (b"\x2e\x8b\xad\x73\x28\x00\x00", "CS_BASE + ("),  # mov ebp, cs:[ebp+0x2873]
        # pushf/popf, both widths; under DOS the word carries the host's IF.
        (b"\x66\x9c", "PUSH16(esp, "),
        (b"\x66\x9c", "recomp_get_if()"),
        (b"\x9c", "PUSH32(esp, "),
        (b"\x66\x9d", "POP16_VAL(esp)"),
        (b"\x9d", "recomp_set_if(_fl & 0x200u)"),
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
    # A function that loads ds (Watcom's movedata, peek/poke) addresses its
    # default-ds operands and string sources through DS_BASE; the rest stay flat.
    ds_cases = [
        (b"\x8e\xd8", False, "recomp_set_seg(3, eax)"),               # mov ds, ax
        (b"\x1f", False, "recomp_set_seg(3, POP32_VAL(esp))"),        # pop ds
        (b"\x8b\x06", True, "MEM32(DS_BASE + (esi))"),                # mov eax, [esi]
        (b"\x8b\x45\x08", True, "MEM32(ebp + 0x8)"),                  # mov eax, [ebp+8]: the stack is flat
        (b"\xf3\xa5", True, "recomp_rep_movs(ES_BASE + edi, DS_BASE + esi"),
        (b"\x8b\x06", False, "MEM32(esi)"),                           # elsewhere: flat, as before
        # lds esi, [eax]: offset and selector both read through the old ds
        (b"\xc5\x30", True, "uint32_t _o = MEM32(DS_BASE + (eax)); "
                            "uint16_t _s = MEM16(DS_BASE + (eax) + 4); esi = _o; recomp_set_seg(3, _s);"),
    ]
    for enc, ds_fn, want in ds_cases:
        got = emit(enc, ds_fn=ds_fn)
        if want not in got:
            print("FAIL %s: want %r in %r" % (enc.hex(), want, got))
            bad += 1
    loads = [Lifter.ds_function([decode(e)]) for e in (b"\x8e\xd8", b"\x1f", b"\xc5\x30", b"\x8b\x06", b"\x8e\xc0")]
    if loads != [True, True, True, False, False]:   # mov ds / pop ds / lds load it; mov eax, [esi] / mov es don't
        print("FAIL: ds_function %r" % loads)
        bad += 1
    n = len(cases) + 1 + len(ds_cases) + 1
    print("%d/%d passed" % (n - bad, n))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

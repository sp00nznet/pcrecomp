"""32-bit addressing (the 67h prefix) in 16-bit code.

Found in Epic Pinball's MASI Sound Blaster driver, which indexes per-channel
arrays as `mov word [ebx*4+7A4h], ax`, jumps through `jmp word [ebx*2+2524h]`
and counts its mixing loops in ECX with `67 E2 xx`. decode16 knew the prefix
and ignored it, so the first came out as `mov [si], ax` followed by four bytes
of garbage, and the jump table as `jmp word [si]`.

The decoded operands are checked by name; the lifted C by the expression it
must contain. Behaviour against real x86 is difftest16's job (an effective
address past FFFFh faults on hardware in real mode, so a random vector that
lands there is not a comparison).

Run: py -3 tools/lift/test_addr32_16.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'disasm'))
sys.path.insert(0, HERE)

from decode16 import Decoder  # noqa: E402
import lift16                   # noqa: E402
from lift16 import Lifter      # noqa: E402


def dec(raw):
    d = Decoder(bytes(raw) + b'\x90' * 8, 0)
    d.pos = 0
    ins = d.decode_one()
    return ins


def lifted(raw):
    ins = dec(raw)
    lf = Lifter()
    lf.output, lf.indent, lf.labels_emitted = [], 1, set()
    lift16._CODE_SEG = None
    lf.lift_instruction(ins, 0)
    return '\n'.join(lf.output)


def main():
    # mov word ds:[ebx*4+0x7A4], ax -- SIB, scaled index, disp32
    i = dec([0x67, 0x89, 0x04, 0x9D, 0xA4, 0x07, 0, 0])
    assert i.length == 8 and i.addr32, i
    assert repr(i) == 'mov word ds:[ebx*4+0x7A4], ax', repr(i)
    assert 'cpu->ebx * 4 + 0x7A4' in lifted([0x67, 0x89, 0x04, 0x9D, 0xA4, 0x07, 0, 0])

    # add [eax+ecx*8+100h], dx -- base and scaled index
    i = dec([0x67, 0x01, 0x94, 0xC8, 0, 1, 0, 0])
    assert repr(i) == 'add word ds:[eax+ecx*8+0x100], dx', repr(i)

    # mov al, [ebx+10h] -- disp8, no SIB
    i = dec([0x67, 0x8A, 0x43, 0x10])
    assert i.length == 4 and repr(i) == 'mov al, byte ds:[ebx+0x10]', repr(i)

    # [ebp+disp8] defaults to SS, as [bp+...] does
    i = dec([0x67, 0x8B, 0x45, 0x04])
    assert i.op2.seg == 'ss', i.op2.seg

    # [disp32] alone (mod 0, rm 5) and moffs32 (A1)
    i = dec([0x67, 0x8B, 0x05, 0x34, 0x12, 0, 0])
    assert i.length == 7 and not i.op2.base and i.op2.disp == 0x1234, repr(i)
    i = dec([0x67, 0xA1, 0x20, 0, 0, 0])
    assert i.length == 6 and i.op2.disp == 0x20, repr(i)

    # jmp word ds:[ebx*2+0x2524] -- a jump table index with no base
    i = dec([0x67, 0xFF, 0x24, 0x5D, 0x24, 0x25, 0, 0])
    assert i.mnemonic == 'jmp' and i.op1.index == 'ebx' and i.op1.scale == 2 \
        and not i.op1.base and i.op1.disp == 0x2524, repr(i)

    # lea eax, [ebx+ebx*2] is 32-bit arithmetic: no 16-bit wrap
    c = lifted([0x66, 0x67, 0x8D, 0x04, 0x5B])
    assert 'cpu->ebx * 2' in c and 'uint16_t' not in c, c

    # loop with 67h counts ECX; without it, CX
    assert 'cpu->ecx--' in lifted([0x67, 0xE2, 0xFE])
    assert 'cpu->cx--' in lifted([0xE2, 0xFE])

    # string ops with 67h walk ESI/EDI: not modelled, so said so
    assert 'UNHANDLED: addr32' in lifted([0x67, 0xA4])

    # and without 67h nothing changes
    i = dec([0x89, 0x04])
    assert repr(i) == 'mov word ds:[si], ax' and not i.addr32, repr(i)

    print('addr32 (16-bit): ok')


if __name__ == '__main__':
    main()

"""lift16 Lifter.vectored_ints: an `int n` listed there goes through the vector
table (int_handler) instead of the runtime's direct BIOS/DOS call, so a program
that hooks INT 16h (its own INT 9 keyboard buffer) reaches its handler. Found on
Stunts and MechWarrior (1989).

Run: py -3 tools/lift/test_vectored_ints.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, '..', 'disasm'))

from decode16 import Decoder
from lift16 import Lifter


def lift(code, vectored=()):
    d = Decoder(code, 0)
    insts = []
    while d.pos < len(code):
        insts.append(d.decode_one())
    lf = Lifter(known_funcs={0: 'fn_00000'})
    lf.vectored_ints = set(vectored)
    return lf.lift_function('fn_00000', insts, 0, entry_addr=0)


def main():
    code = b'\xcd\x16\xcd\x21\xc3'                     # int 16h / int 21h / ret
    plain = lift(code)
    assert 'bios_int16(cpu);' in plain and 'dos_int21(cpu);' in plain, plain
    hooked = lift(code, {0x16})
    assert 'int_handler(cpu, 0x16);' in hooked and 'bios_int16' not in hooked, hooked
    assert 'dos_int21(cpu);' in hooked, hooked           # only the listed vectors change
    print('test_vectored_ints: ok')


if __name__ == '__main__':
    main()

"""A use32 NE code segment (flag 2000h, Win9x GDI's DIB engine) decodes with
32-bit operands and addresses by default; 66h/67h select the 16-bit ones.
GDI seg 37's entry, decoded as 16-bit code, read `ds:[esi+esi]` off a bad
pointer (the My Computer crash)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from decode16 import Decoder, OpType

# push bp; movzx ebp,sp; sub sp,56h; call rel32; 66 retf
code = bytes.fromhex('6655' '0fb7ec' '6683ec56' 'e800000000' '66cb')
d = Decoder(code, use32=True)
ins = d.decode_range(0, len(code))
m = [(i.mnemonic, i.op32) for i in ins]
assert m == [('push', False), ('movzx', True), ('sub', False), ('call', True), ('retf', False)], m
assert ins[0].op1.type == OpType.REG16 and ins[1].op1.type == OpType.REG32
assert ins[3].op1.disp == 0xE and ins[3].length == 5      # rel32: the next instruction
# the same bytes as 16-bit code keep their old meaning
assert Decoder(bytes.fromhex('6655'), use32=False).decode_one().op1.type == OpType.REG32
print('decode16 use32: ok')

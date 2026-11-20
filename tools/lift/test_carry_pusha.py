"""clc/stc/cmc and pushad/popad in lift32_cpu.

QNX 4 system code returns status in CF (`clc; int 0xF2; jae ok`), and its
kernel entry saves state with pushad, so these have to lift rather than TODO.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lift32_cpu as L

def lift(code):
    lf = L.Lifter('t', 0x100, lambda a, n: b'')
    return lf.translate(next(lf.md.disasm(code, 0)), set())

def test_carry():
    assert lift(b'\xf8') == ['c->cf = 0;']
    assert lift(b'\xf9') == ['c->cf = 1;']
    assert lift(b'\xf5') == ['c->cf ^= 1;']

def test_pusha_popa():
    pa = ' '.join(lift(b'\x60'))
    # ESP pushed is the value before the first push, and EDI goes last
    assert pa.index('_sp = c->esp') < pa.index('push32(c, c->eax)') < pa.index('push32(c, _sp)') < pa.index('push32(c, c->edi)')
    po = ' '.join(lift(b'\x61'))
    assert 'c->esp += 4' in po and 'c->esp = pop32' not in po
    assert po.index('c->edi') < po.index('c->eax')


def test_jump_table_honours_segment_override():
    """A switch in segmented code reads its table through cs:; the table read
    must go through rd() so a subclass that models segments sees it."""
    class Seg(L.Lifter):
        def rd(self, insn, op):
            if self.seg_name(op) == 'cs':
                return 'CS_RD(%s)' % self.addr_expr(insn, op)
            return super().rd(insn, op)
    lf = Seg('t', 0x1000, lambda a, n: (b'\x10\x00\x00\x00' * 8)[:n])
    lf.image_lo, lf.image_hi = 0, 0x1000
    out = lf.lift_function(b'\x2e\xff\x24\x85\x00\x01\x00\x00', 0x10)
    assert '_jt = CS_RD(' in out
    flat = L.Lifter('t', 0x1000, lambda a, n: (b'\x10\x00\x00\x00' * 8)[:n])
    flat.image_lo, flat.image_hi = 0, 0x1000
    assert '_jt = rd32(' in flat.lift_function(b'\xff\x24\x85\x00\x01\x00\x00', 0x10)

if __name__ == '__main__':
    test_carry(); test_pusha_popa(); test_jump_table_honours_segment_override(); print('ok')

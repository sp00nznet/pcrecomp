#!/usr/bin/env python3
"""
codeblob16.py - lift real-mode code that a program unpacks at run time.

The run-time half is runtime/recomp16/codeblob.h, which explains the scheme.
A host that captures blobs leaves work/<game>/blobs/SSSS.bin (64 KB from
SSSS:0000, taken before the first instruction there ran) and the usual
SSSS:OOOO miss lines. This module turns those into extra code segments a
16-bit lifter can walk like any other:

    blobs, rest = codeblob16.load(blob_dir, misses)   # misses: {(seg, off)} live segments
    for b in blobs: b.virt, b.data, b.entries          # virtual paragraph, bytes, offsets
    codeblob16.c_tables(blobs)                         # g_blobs[] and friends, as C

Each blob gets virtual paragraph VIRT_BASE + 0x1000 * k: above 1 MB, so its
lifted keys (paragraph * 16 + offset) never collide with the real image's.
The lifter keys functions as usual and emits `#define SEG_<virt> g_blob_seg[k]`
so the blob's cs: operands follow the live copy.

    python tools/lift/codeblob16.py      # self-check, no game needed
"""
import os

VIRT_BASE = 0x10000
SIG = 24                                  # CODEBLOB_SIG in codeblob.h


class Blob:
    def __init__(self, live, virt, data):
        self.live, self.virt, self.data = live, virt, data
        self.entries = set()

    def image(self):
        """The bytes laid out at their virtual linear address, for code that
        indexes an image by linear address (jump tables). Zero below."""
        return bytes(self.virt * 16) + self.data


def load(blob_dir, misses):
    """({live seg -> Blob}, misses not inside any blob). Misses are live
    seg:off pairs; one in a captured segment becomes an entry of that blob."""
    blobs = {}
    if os.path.isdir(blob_dir):
        names = sorted(n for n in os.listdir(blob_dir) if n.upper().endswith('.BIN'))
        for k, n in enumerate(names):
            live = int(n[:-4], 16)
            blobs[live] = Blob(live, VIRT_BASE + 0x1000 * k,
                               open(os.path.join(blob_dir, n), 'rb').read())
    rest = set()
    for seg, off in misses:
        b = blobs.get(seg)
        if b is not None and off < len(b.data):
            b.entries.add(off)
        else:
            rest.add((seg, off))
    return [b for b in blobs.values() if b.entries], rest


def seg_defines(blobs):
    return ''.join(f'extern uint16_t g_blob_seg[];\n#define SEG_{b.virt:04X} g_blob_seg[{k}]\n'
                   for k, b in enumerate(blobs))


def c_tables(blobs):
    """The tables codeblob.h declares. Valid (empty) with no blobs."""
    out = ['#include "recomp16/codeblob.h"']
    rows = []
    for k, b in enumerate(blobs):
        for off in sorted(b.entries):
            sig = b.data[off:off + SIG].ljust(SIG, b'\0')
            rows.append(f'  {{0x{b.virt * 16:X}, 0x{off:04X}, {k}, {{{",".join(str(x) for x in sig)}}}}},')
    n = max(len(blobs), 1)
    out.append(f'const CodeBlobEntry g_blobs[] = {{\n' + '\n'.join(rows or ['  {0}']) + '\n};')
    out.append(f'const unsigned g_blob_count = {len(rows)};')
    out.append(f'uint16_t g_blob_seg[{n}];')
    out.append(f'const uint32_t g_blob_virt[{n}] = {{' + (', '.join(f'0x{b.virt * 16:X}' for b in blobs) or '0') + '};')
    out.append(f'const unsigned g_blob_slots = {len(blobs)};')
    return '\n'.join(out) + '\n'


def _selftest():
    import tempfile
    d = tempfile.mkdtemp()
    open(os.path.join(d, '36B4.bin'), 'wb').write(b'\x55\x8b\xec' + bytes(0x2000))
    open(os.path.join(d, '4000.bin'), 'wb').write(b'\xcb' * 16)       # captured, never an entry
    blobs, rest = load(d, {(0x36B4, 0x0000), (0x36B4, 0x14A0), (0x0110, 0x13D9)})
    assert [b.live for b in blobs] == [0x36B4], blobs
    assert blobs[0].virt == VIRT_BASE and blobs[0].entries == {0, 0x14A0}
    assert rest == {(0x0110, 0x13D9)}
    assert blobs[0].image()[VIRT_BASE * 16:VIRT_BASE * 16 + 3] == b'\x55\x8b\xec'
    c = c_tables(blobs)
    assert 'g_blob_count = 2;' in c and '{0x100000, 0x0000, 0, {85,139,236,' in c, c
    assert 'g_blob_count = 0;' in c_tables([])
    assert seg_defines(blobs) == 'extern uint16_t g_blob_seg[];\n#define SEG_10000 g_blob_seg[0]\n'
    print('codeblob16: ok')


if __name__ == '__main__':
    _selftest()

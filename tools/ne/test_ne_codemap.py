"""ne_codemap against IDA: the native NE code map must keep up with the oracle.

Two parts:
  - a hand-built segment that always runs: an entry, a guarded jump table with
    data behind it, and an unreferenced far prologue after a retf;
  - every game whose IDA export is on this machine, scored with
    score_recovery: instruction-head recall/precision and function recall.
    A game whose binary or export is missing prints SKIP.

The exports are the four Win16 recomps' work/ida/*.json (gitignored, made once
with tools/ida/ida_export.py), looked for beside this checkout
(../<game>/...). PCRECOMP_NE_ORACLES="exe=ida.json;..." adds others.

Run: py -3 tools/ne/test_ne_codemap.py
"""
import json
import os
import sys
import tempfile
from types import SimpleNamespace as NS

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, '..', 'disasm'))

import ne_codemap                       # noqa: E402
import score_recovery                   # noqa: E402
from ne_parse import parse_ne           # noqa: E402

PC_PARENT = os.path.abspath(os.path.join(HERE, '..', '..', '..'))
# (binary, export, min head recall, min head precision, min function recall).
# Head recall below 1.0 is mostly IDA splitting `fwait` from its x87 op, which
# ne_decode folds back into one instruction.
ORACLES = [
    ('bermuda/game/SCN/BERMUDA.EXE', 'bermuda/work/ida/BERMUDA.json', .995, .99, .99),
    ('civnet/game/CIVNET.EXE', 'civnet/work/ida/CIVNET.json', .995, .99, .99),
    ('civnet/game/SMEDSNET.DLL', 'civnet/work/ida/SMEDSNET.json', .995, .99, .99),
    ('civnet/game/TIMERDLL.DLL', 'civnet/work/ida/TIMERDLL.json', .995, .99, .99),
    ('spacebucks/game/SPACEBUC.EXE', 'spacebucks/work/ida/SPACEBUC.json', .98, .99, .99),
    ('jazz/game/FILE0001.EXE', 'jazz/work/ida/FILE0001.json', .995, .95, .98),
]


def synthetic():
    code = bytearray(0x60)
    # 0x00: entry. cmp bx,2 / ja 0x0E / shl bx,1 / jmp cs:[bx+0x20]
    code[0:14] = bytes.fromhex('83fb02' '7709' 'd1e3' '2effa72000' '90' 'c3')
    code[0x0E] = 0xC3                                 # default: ret
    code[0x20:0x26] = bytes.fromhex('3000' '3400' '3800')   # the table
    code[0x30:0x3C] = bytes.fromhex('40c3' '0000' '41c3' '0000' '42c3' '0000')
    code[0x3C] = 0xCB                                 # retf, then fill
    code[0x40:0x48] = bytes.fromhex('4555' '8bec' '5d' '4d' 'cb' '00')  # far prologue
    seg = NS(index=1, data=bytes(code), relocations=[], is_code=True)
    ne = NS(segments=[seg], entries=[NS(segment=1, offset=0)], cs=1, ip=0, seg_base=0)
    m = ne_codemap.build(ne)['1']
    heads = set(m['heads'])
    assert {0, 3, 5, 7, 0x0E} <= heads, sorted(heads)
    assert {0x30, 0x34, 0x38} <= heads, 'jump-table targets not decoded'
    assert not heads & set(range(0x20, 0x26)), 'jump table decoded as code'
    assert 0x40 in m['functions'], 'unreferenced far prologue not found'
    assert 0 in m['functions']
    print('synthetic: ok')


def oracles():
    pairs = [(os.path.join(PC_PARENT, b), os.path.join(PC_PARENT, j), *t) for b, j, *t in ORACLES]
    for item in filter(None, os.environ.get('PCRECOMP_NE_ORACLES', '').split(';')):
        b, j = item.split('=')
        pairs.append((b, j, .97, .95, .98))
    failed = 0
    for exe, ida, want_hr, want_hp, want_fr in pairs:
        name = os.path.basename(exe)
        if not (os.path.exists(exe) and os.path.exists(ida)):
            print(f'{name}: SKIP (no binary or IDA export here)')
            continue
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, 'native.json')
            with open(out, 'w') as f:
                json.dump(ne_codemap.build(parse_ne(exe)), f)
            ref, rh = score_recovery.load_codemap(ida)
            cand, ch = score_recovery.load_codemap(out)
        c = score_recovery.classify(ref, [(a, None, k) for a, _, k in cand])
        p, r, _ = score_recovery.score(c)
        h = score_recovery.score_heads(rh, ch)
        ok = h['head_recall'] >= want_hr and h['head_precision'] >= want_hp and r >= want_fr
        failed += not ok
        print(f"{name}: {'ok' if ok else 'FAIL'}  heads recall {h['head_recall']:.2%} "
              f"precision {h['head_precision']:.2%}  functions recall {r:.2%} "
              f"precision {p:.2%} ({c['fp_split']} split, {c['fp_invented']} invented)")
    return failed


if __name__ == '__main__':
    synthetic()
    sys.exit(1 if oracles() else 0)

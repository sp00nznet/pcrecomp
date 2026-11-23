"""
seed_misses.py - Turn indirect-call misses from a run log into lift seeds.

An indirect call (`call far [bx+4]`, a vtable, a callback) resolves at run time
to a (segment, offset) that nothing in the image branches to, so neither a code
map nor the decoder's own seeding may have made it a function. The runtime then
reports it:

    [dispatch] far MISS seg=64 off=1DFC

This reads those lines, maps each global segment back to (module, the module's
own segment number) the same way ne_link.py numbered them, and adds the offset
to the seeds file ne_link.py --seeds reads. Re-link and the target is lifted.

    python seed_misses.py run.log --seeds tools/entry_seeds.json \\
        game/CATZDLL.DLL game/CATZ.WAD

Pass the modules in the same order as to ne_link.py.

Upstreamed from catz/tools/fix_misses.py, which wrote straight into two IDA maps
with its module boundary (59) hardcoded.
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ne_parse import parse_ne

MISS_RE = re.compile(r'(?:dispatch_)?(?:far|near) MISS seg=(\d+) off=([0-9A-Fa-f]+)')
# Win16 identity mode (runtime/win16/identity): "[w16] unlifted target SSSS:OOOO"
# and "[w16] near call miss SSSS:OOOO", the global segment in hex
W16_RE = re.compile(r'\[w16\] (?:unlifted target|near call miss|near ret under a far call into, seg:off) ([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4})')
# "[w16] far call miss SEL:OOOO" through a segment's own identity selector (n << 3 | 7)
W16_FAR_RE = re.compile(r'\[w16\] far call miss ([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4})')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('log')
    ap.add_argument('modules', nargs='+', help='NE files, in ne_link.py order')
    ap.add_argument('--seeds', required=True, help='seeds JSON to update')
    args = ap.parse_args()

    ranges, base = [], 0
    for path in args.modules:
        ne = parse_ne(path)
        ranges.append((base, base + len(ne.segments), ne.module_name.upper()))
        base += len(ne.segments)

    seeds = {}
    if os.path.exists(args.seeds):
        seeds = json.load(open(args.seeds, encoding='utf-8'))
    text = open(args.log, encoding='utf-8', errors='replace').read()
    added = 0
    found = {(int(a), int(b, 16)) for a, b in MISS_RE.findall(text)} | {(int(a, 16), int(b, 16)) for a, b in W16_RE.findall(text)} \
        | {(int(a, 16) >> 3, int(b, 16)) for a, b in W16_FAR_RE.findall(text) if int(a, 16) & 7 == 7}
    for seg, off in sorted(found):
        mod = next(((m, seg - lo) for lo, hi, m in ranges if lo < seg <= hi), None)
        if mod is None:
            print(f'  seg{seg}:{off:04X} is in no module, skipped')
            continue
        name, local = mod
        lst = seeds.setdefault(name, {}).setdefault(str(local), [])
        if f'0x{off:04X}' not in lst:
            lst.append(f'0x{off:04X}')
            lst.sort()
            added += 1
            print(f'  {name} seg {local} (global {seg}) : 0x{off:04X}')
    with open(args.seeds, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(seeds, f, indent=1)
        f.write('\n')
    print(f'{added} new seeds -> {args.seeds}')


if __name__ == '__main__':
    main()

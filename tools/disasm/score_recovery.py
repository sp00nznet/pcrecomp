#!/usr/bin/env python3
"""Score function recovery against a reference catalog.

Recursive descent tells you how many functions it found. It cannot tell you
how many of them are real. This scores a disasm32 catalog against a reference
-- a linker map, a PDB export, or another tool's analysis -- and reports
precision and recall on function *start addresses*.

The interesting output is not the score but the shape of the errors, because
two very different defects both read as "false positive":

  split     the address lands inside a function the reference knows about, so
            one function got entered twice. Harmless-ish for a lift: it
            duplicates code rather than inventing it.
  invented  the address lands outside every known function, so the scan
            probably decoded data as code. That lifts to garbage.

Telling them apart needs function *ranges*, not just starts, so references
that carry an end address (IDA exports, PDBs) get the better breakdown.

    python score_recovery.py --reference ida_funcs.json --candidate funcs.json
    python score_recovery.py --selftest

A reference is a second opinion, not truth, unless it came from symbols.
Where the two disagree, go look before believing either.
"""

import argparse
import bisect
import json
import sys

# Reference and candidate catalogs use different key names for the same thing.
START_KEYS = ('address', 'ea', 'va', 'start')
END_KEYS = ('end', 'end_ea')


def _pick(d, keys):
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return None


def load_catalog(path):
    """[(start, end_or_None)] sorted, from any of the catalog shapes we emit."""
    with open(path) as f:
        doc = json.load(f)
    funcs = doc['functions'] if isinstance(doc, dict) else doc
    out = []
    for fn in funcs:
        start = _pick(fn, START_KEYS)
        if start is None:
            continue
        out.append((start, _pick(fn, END_KEYS)))
    out.sort()
    return out


def classify(reference, candidate):
    """Score candidate starts against reference starts.

    Returns counts plus, for each false positive, whether it fell inside a
    known reference function (a split) or outside every one (invented).
    """
    ref_starts = [s for s, _ in reference]
    ref_set = set(ref_starts)
    cand_starts = sorted({s for s, _ in candidate})

    # Ranges let us say "inside function X". Without an end we can only say
    # "after X's start", which would call every trailing address a split.
    ranges = [(s, e) for s, e in reference if e is not None and e > s]
    range_starts = [s for s, _ in ranges]

    cand_set = set(cand_starts)
    tp = [s for s in cand_starts if s in ref_set]
    fp = [s for s in cand_starts if s not in ref_set]
    fn = [s for s in ref_starts if s not in cand_set]

    split = invented = 0
    for addr in fp:
        i = bisect.bisect_right(range_starts, addr) - 1
        if i >= 0 and ranges[i][0] < addr < ranges[i][1]:
            split += 1
        else:
            invented += 1

    return {
        'reference': len(ref_starts), 'candidate': len(cand_starts),
        'true_positives': len(tp), 'false_positives': len(fp),
        'false_negatives': len(fn),
        'fp_split': split, 'fp_invented': invented,
        'has_ranges': bool(ranges),
    }


def score(counts):
    tp, fp, fn = (counts['true_positives'], counts['false_positives'],
                  counts['false_negatives'])
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f1


def demo():
    """One runnable check: a match, a split, an invention, and a miss."""
    # reference: two functions, 0x1000-0x1100 and 0x1100-0x1200
    ref = [(0x1000, 0x1100), (0x1100, 0x1200)]
    # candidate: one exact hit, one address inside fn 1, one out in data,
    # and it never finds fn 2.
    cand = [(0x1000, None), (0x1040, None), (0x9000, None)]
    c = classify(ref, cand)
    assert c['true_positives'] == 1, c
    assert c['false_positives'] == 2, c
    assert c['false_negatives'] == 1, c
    assert c['fp_split'] == 1, f"0x1040 is inside fn 1: {c}"
    assert c['fp_invented'] == 1, f"0x9000 is outside every fn: {c}"

    p, r, f1 = score(c)
    assert abs(p - 1 / 3) < 1e-9 and abs(r - 0.5) < 1e-9, (p, r)

    # A reference start must never be counted as a split of itself.
    c2 = classify(ref, [(0x1100, None)])
    assert c2['true_positives'] == 1 and c2['fp_split'] == 0, c2

    # Without ranges, nothing can be called a split rather than invented.
    c3 = classify([(0x1000, None)], [(0x1040, None)])
    assert c3['fp_split'] == 0 and c3['fp_invented'] == 1, c3
    print('selftest ok')


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--reference', help='reference catalog (IDA/PDB/map export)')
    ap.add_argument('--candidate', help='disasm32 catalog to score')
    ap.add_argument('--range', help='restrict to VA range, e.g. 0x401000-0x10A4601')
    ap.add_argument('-o', '--output', help='write the scorecard as JSON')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        demo()
        return 0
    if not (args.reference and args.candidate):
        ap.error('need --reference and --candidate, or --selftest')

    ref = load_catalog(args.reference)
    cand = load_catalog(args.candidate)

    if args.range:
        lo, hi = (int(x, 0) for x in args.range.split('-'))
        ref = [f for f in ref if lo <= f[0] < hi]
        cand = [f for f in cand if lo <= f[0] < hi]

    counts = classify(ref, cand)
    p, r, f1 = score(counts)

    print(f"reference {counts['reference']:>9,} functions")
    print(f"candidate {counts['candidate']:>9,} entries\n")
    print(f"  true positives   {counts['true_positives']:>9,}")
    print(f"  false positives  {counts['false_positives']:>9,}")
    if counts['has_ranges']:
        print(f"      split        {counts['fp_split']:>9,}  (inside a known function)")
        print(f"      invented     {counts['fp_invented']:>9,}  (outside every known function)")
    print(f"  false negatives  {counts['false_negatives']:>9,}")
    print(f"\n  precision {p:>8.2%}\n  recall    {r:>8.2%}\n  F1        {f1:>8.2%}")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump({'precision': p, 'recall': r, 'f1': f1, **counts}, f, indent=1)
        print(f'\nwrote {args.output}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

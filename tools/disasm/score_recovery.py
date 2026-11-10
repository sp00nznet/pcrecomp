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

A third kind is not an error at all and must not be scored as one. A catalog
entry marked `"entry_kind": "alias"` is the disassembler saying "something
branches here and the lifter needs a body at this address" -- explicitly NOT
"a function starts here". A shared epilogue, a switch arm reached from another
function, an alternate entry point. It is expected to land inside a known
function, because that is what it is for.

Counting those as false positives measures a design decision instead of a
defect, and it is not a rounding error: on Trespasser 6,427 of 7,364 false
positives were aliases -- 87% of the reported error. Precision here is computed
over `entry_kind == "start"` only, and aliases are reported on their own line.

Telling them apart needs function *ranges*, not just starts, so references
that carry an end address (IDA exports, PDBs) get the better breakdown.

    python score_recovery.py --reference ida_funcs.json --candidate funcs.json
    python score_recovery.py --selftest

Segmented (NE) code maps -- the {seg: {functions, heads, code_ranges}} JSON
tools/ida/ida_export.py and tools/ne/ne_codemap.py write -- score with --ne.
Starts are flattened to seg<<16 | offset, function ranges come from the next
start, and instruction-head agreement is reported beside the function score:
a head the reference has and the candidate lacks is code never lifted, one the
candidate adds is (usually) data decoded as code.

    python score_recovery.py --ne --reference ida.json --candidate native.json

Where the reference carries end addresses, function *ends* are scored too, over
the true positives only -- an end is meaningless for an address where no
function starts. A wrong end is a different failure from a wrong start and the
scan can be perfect at one and bad at the other:

  short     the recovered function stops before the real one does, so its tail
            was never lifted. When the tail is the epilogue, every caller
            silently loses whatever the prologue saved.
  long      it runs past the real end and swallows what follows.

Make both sides mean the same thing by "end" before trusting the end numbers.
A disassembler's end is the end of the last instruction it decoded. IDA's runs
to the start of the next function, so it includes the linker's alignment
padding, and comparing the two directly makes correct functions look truncated.

That is not a rounding error. On Trespasser, 2,417 functions scored short
against untrimmed ends and 1,984 of them -- 82% -- had nothing but 0xCC and
0x90 in the gap. They were right. The 433 that remained were real, and 98% of
those were embedded jump tables, which is a genuine defect worth chasing. Left
uncorrected, the reference buried a 433-function signal under four times as
much noise.

So walk each reference end back over trailing 0xCC and 0x90 when you build it.
Not 0x00: that is a legal encoding () and trimming it eats real
code.

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
    """[(start, end_or_None, kind)] sorted, from any catalog shape we emit.

    `kind` is "start" unless the entry says otherwise. References never carry
    it; a catalog from a disassembler that does not distinguish entry kinds
    reads as all-starts, which is what it was doing before.
    """
    with open(path) as f:
        doc = json.load(f)
    funcs = doc['functions'] if isinstance(doc, dict) else doc
    out = []
    for fn in funcs:
        start = _pick(fn, START_KEYS)
        if start is None:
            continue
        out.append((start, _pick(fn, END_KEYS), fn.get('entry_kind', 'start')))
    out.sort()
    return out


def load_codemap(path):
    """(catalog, heads) from an NE code map: catalog as load_catalog returns,
    each function running to the next start in its segment; heads as a set of
    seg<<16 | offset."""
    with open(path) as f:
        doc = json.load(f)
    cat, heads = [], set()
    for seg, v in doc.items():
        base = int(seg) << 16
        fs = sorted(set(v.get('functions', ())))
        for i, a in enumerate(fs):
            end = fs[i + 1] if i + 1 < len(fs) else 0x10000
            cat.append((base | a, base | end, 'start'))
        heads.update(base | h for h in v.get('heads', ()))
    cat.sort()
    return cat, heads


def score_heads(ref_heads, cand_heads):
    both = len(ref_heads & cand_heads)
    return {'ref_heads': len(ref_heads), 'cand_heads': len(cand_heads),
            'heads_both': both,
            'head_recall': both / len(ref_heads) if ref_heads else 0.0,
            'head_precision': both / len(cand_heads) if cand_heads else 0.0}


def classify(reference, candidate):
    """Score candidate function starts against reference starts.

    Alias entries are held out of precision entirely -- they are not a claim
    that a function starts there -- and reported separately. An alias that
    lands outside every known function IS worth knowing about, because it
    means we created a dispatchable body pointing at nothing.
    """
    ref_starts = [s for s, _, _ in reference]
    ref_set = set(ref_starts)

    cand_starts = sorted({s for s, _, k in candidate if k != 'alias'})
    cand_alias = sorted({s for s, _, k in candidate if k == 'alias'} - set(cand_starts))

    # Ranges let us say "inside function X". Without an end we can only say
    # "after X's start", which would call every trailing address a split.
    ranges = [(s, e) for s, e, _ in reference if e is not None and e > s]
    range_starts = [s for s, _ in ranges]

    def inside_known(addr):
        i = bisect.bisect_right(range_starts, addr) - 1
        return i >= 0 and ranges[i][0] < addr < ranges[i][1]

    cand_set = set(cand_starts)
    tp = [s for s in cand_starts if s in ref_set]
    end_counts = _score_ends(tp, reference, candidate)
    fp = [s for s in cand_starts if s not in ref_set]
    # An alias sitting exactly on a reference start is a real function we
    # mislabelled -- worth its own number, since it means a genuine start was
    # demoted and will not be reported as found.
    alias_on_start = [a for a in cand_alias if a in ref_set]
    fn = [s for s in ref_starts if s not in cand_set]

    split = invented = 0
    for addr in fp:
        if inside_known(addr):
            split += 1
        else:
            invented += 1

    alias_inside = sum(1 for a in cand_alias if inside_known(a))

    return {
        'reference': len(ref_starts), 'candidate': len(cand_starts),
        'true_positives': len(tp), 'false_positives': len(fp),
        'false_negatives': len(fn),
        'fp_split': split, 'fp_invented': invented,
        'aliases': len(cand_alias), 'alias_inside_known': alias_inside,
        'alias_on_reference_start': len(alias_on_start),
        'has_ranges': bool(ranges),
        **end_counts,
    }


def _score_ends(tp, reference, candidate):
    """End accuracy over the true positives.

    Scored only where both sides carry an end. Aliases are excluded: an alias
    deliberately runs to the end of the function containing it, so its end is
    not a claim about anything and matching it would mean nothing.
    """
    ref_end = {a: e for a, e, _ in reference if e is not None and e > a}
    cand_end = {a: e for a, e, k in candidate
                if k != 'alias' and e is not None and e > a}

    exact = short = long_ = 0
    short_by = []
    for a in tp:
        want, got = ref_end.get(a), cand_end.get(a)
        if want is None or got is None:
            continue
        if got == want:
            exact += 1
        elif got < want:
            short += 1
            short_by.append(want - got)
        else:
            long_ += 1

    scored = exact + short + long_
    short_by.sort()
    return {
        'ends_scored': scored,
        'end_exact': exact, 'end_short': short, 'end_long': long_,
        'end_short_median_bytes': (short_by[len(short_by) // 2] if short_by else 0),
        'end_short_max_bytes': (short_by[-1] if short_by else 0),
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
    ref = [(0x1000, 0x1100, 'start'), (0x1100, 0x1200, 'start')]
    # candidate: one exact hit, one address inside fn 1, one out in data,
    # and it never finds fn 2.
    cand = [(0x1000, None, 'start'), (0x1040, None, 'start'), (0x9000, None, 'start')]
    c = classify(ref, cand)
    assert c['true_positives'] == 1, c
    assert c['false_positives'] == 2, c
    assert c['false_negatives'] == 1, c
    assert c['fp_split'] == 1, f"0x1040 is inside fn 1: {c}"
    assert c['fp_invented'] == 1, f"0x9000 is outside every fn: {c}"

    p, r, f1 = score(c)
    assert abs(p - 1 / 3) < 1e-9 and abs(r - 0.5) < 1e-9, (p, r)

    # A reference start must never be counted as a split of itself.
    c2 = classify(ref, [(0x1100, None, 'start')])
    assert c2['true_positives'] == 1 and c2['fp_split'] == 0, c2

    # Without ranges, nothing can be called a split rather than invented.
    c3 = classify([(0x1000, None, 'start')], [(0x1040, None, 'start')])
    assert c3['fp_split'] == 0 and c3['fp_invented'] == 1, c3

    # An alias inside a known function is the expected shape and must not
    # touch precision -- that is the whole point of the distinction.
    c4 = classify(ref, [(0x1000, None, 'start'), (0x1040, None, 'alias')])
    assert c4['false_positives'] == 0, f"an alias is not a false positive: {c4}"
    assert c4['aliases'] == 1 and c4['alias_inside_known'] == 1, c4
    p4, _, _ = score(c4)
    assert p4 == 1.0, f"one correct start and one alias is 100% precision: {p4}"

    # An alias out in the weeds still gets counted, separately: we built a
    # dispatchable body for an address in no function at all.
    c5 = classify(ref, [(0x9000, None, 'alias')])
    assert c5['aliases'] == 1 and c5['alias_inside_known'] == 0, c5

    # An alias landing exactly on a real function start is a demotion, and a
    # demoted start is not reported as found.
    c6 = classify(ref, [(0x1100, None, 'alias')])
    assert c6['alias_on_reference_start'] == 1, c6
    assert c6['false_negatives'] == 2, f"both starts still unfound: {c6}"

    # Ends: one exact, one stopping 0x40 short of the real end.
    c7 = classify(ref, [(0x1000, 0x1100, 'start'), (0x1100, 0x11C0, 'start')])
    assert c7['ends_scored'] == 2, c7
    assert c7['end_exact'] == 1 and c7['end_short'] == 1 and c7['end_long'] == 0, c7
    assert c7['end_short_median_bytes'] == 0x40, c7

    # An end past the real one is the other failure and must not read as short.
    c8 = classify(ref, [(0x1000, 0x1180, 'start')])
    assert c8['end_long'] == 1 and c8['end_short'] == 0, c8

    # A candidate with no end at all is simply not scored, rather than counted
    # as a perfect or a broken one.
    c9 = classify(ref, [(0x1000, None, 'start')])
    assert c9['ends_scored'] == 0, c9
    assert c9['true_positives'] == 1, "no end is not a missing function"

    # An alias end is not a claim about anything and is never scored.
    c10 = classify(ref, [(0x1000, 0x1100, 'start'), (0x1040, 0x1100, 'alias')])
    assert c10['ends_scored'] == 1, c10

    h = score_heads({1, 2, 3, 4}, {2, 3, 4, 9})
    assert h['heads_both'] == 3 and h['head_recall'] == 0.75 and h['head_precision'] == 0.75, h

    print('selftest ok')


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--reference', help='reference catalog (IDA/PDB/map export)')
    ap.add_argument('--candidate', help='disasm32 catalog to score')
    ap.add_argument('--range', help='restrict to VA range, e.g. 0x401000-0x10A4601')
    ap.add_argument('-o', '--output', help='write the scorecard as JSON')
    ap.add_argument('--ne', action='store_true',
                    help='both sides are NE code maps (ida_export / ne_codemap JSON)')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        demo()
        return 0
    if not (args.reference and args.candidate):
        ap.error('need --reference and --candidate, or --selftest')

    heads = None
    if args.ne:
        ref, rh = load_codemap(args.reference)
        cand, ch = load_codemap(args.candidate)
        cand = [(a, None, k) for a, _, k in cand]    # ends: not a claim here
        heads = score_heads(rh, ch)
    else:
        ref = load_catalog(args.reference)
        cand = load_catalog(args.candidate)

    if args.range:
        lo, hi = (int(x, 0) for x in args.range.split('-'))
        ref = [f for f in ref if lo <= f[0] < hi]
        cand = [f for f in cand if lo <= f[0] < hi]

    counts = classify(ref, cand)
    p, r, f1 = score(counts)

    print(f"reference {counts['reference']:>9,} functions")
    print(f"candidate {counts['candidate']:>9,} function starts\n")
    print(f"  true positives   {counts['true_positives']:>9,}")
    print(f"  false positives  {counts['false_positives']:>9,}")
    if counts['has_ranges']:
        print(f"      split        {counts['fp_split']:>9,}  (inside a known function)")
        print(f"      invented     {counts['fp_invented']:>9,}  (outside every known function)")
    print(f"  false negatives  {counts['false_negatives']:>9,}")
    if counts['aliases']:
        print(f"\n  alias entries    {counts['aliases']:>9,}  (not scored: alternate entry points)")
        if counts['has_ranges']:
            print(f"      inside a known function  {counts['alias_inside_known']:>9,}  (expected)")
            outside = counts['aliases'] - counts['alias_inside_known']
            print(f"      outside every one        {outside:>9,}  (suspect: a body pointing at nothing)")
        if counts['alias_on_reference_start']:
            print(f"      on a reference start     "
                  f"{counts['alias_on_reference_start']:>9,}  (a real function demoted)")
    print(f"\n  precision {p:>8.2%}\n  recall    {r:>8.2%}\n  F1        {f1:>8.2%}")

    if counts['ends_scored']:
        n = counts['ends_scored']
        print(f"\n  function ends scored {n:>9,}  (true positives with an end on both sides)")
        print(f"      exact        {counts['end_exact']:>9,}  ({counts['end_exact'] / n:.2%})")
        print(f"      short        {counts['end_short']:>9,}  (tail never lifted; "
              f"median {counts['end_short_median_bytes']:,} bytes, "
              f"max {counts['end_short_max_bytes']:,})")
        print(f"      long         {counts['end_long']:>9,}  (ran past the real end)")

    if heads:
        counts.update(heads)
        print(f"\n  instruction heads  reference {heads['ref_heads']:,}  candidate {heads['cand_heads']:,}"
              f"  both {heads['heads_both']:,}")
        print(f"      head recall    {heads['head_recall']:>8.2%}")
        print(f"      head precision {heads['head_precision']:>8.2%}")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump({'precision': p, 'recall': r, 'f1': f1, **counts}, f, indent=1)
        print(f'\nwrote {args.output}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""
largemodel16.py - Call-graph completion for 16-bit large-model DOS binaries.

The base analyzer (analyze.py) detects functions by prologue and tracks *near*
calls (E8 rel16). That is enough for small/medium-model programs, but large-model
code compiled by Borland C / Turbo C / MSC emits the bulk of its calls as FAR
calls (9A seg:off) -- which analyze.py records as unresolved (seg, off) tuples
and never connects. The result is a call graph that looks mostly disconnected
(hundreds of false "roots").

This module adds the two pieces that make a large-model map usable, with no
changes to analyze.py (purely additive, import-and-use):

  detect_code_end(analyzer)
      Find the file offset where prologue-driven code stops and the DGROUP
      initialized-data segment begins. The base analyzer treats the whole MZ
      image as code, so the data section decodes into one bogus multi-KB
      "function"; this clips it off.

  resolve_far_target(hdr_size, seg, off)
      A far call stores its target segment relative to the image load base (the
      MZ relocation table fixes it up at load time), so the file offset is
      simply hdr_size + seg*16 + off.

  build_call_graph(funcs, hdr_size, code_end=None)
      Connect both near and far edges over the real functions and return
      (callees, callers, stats). >99% of far calls in a well-formed large-model
      exe resolve straight into the code region.

Validated on DinoPark Tycoon (Borland large model): 3609/3611 far calls resolved.
Reusable for any Borland/MSC large-model 16-bit DOS recomp (civ, bolo, coaster…).
"""
import bisect


def detect_code_end(analyzer, min_blob=8192):
    """File offset where code ends and DGROUP data begins, or img_size if none.

    Heuristic: real functions are small and dense; the data section decodes as
    one anomalously large pseudo-function in the top third of the image. The
    boundary is the start of the first such >= min_blob function up there.
    """
    img, hdr = analyzer.img_size, analyzer.hdr_size
    top_third = hdr + (img - hdr) * 2 // 3
    for f in sorted(analyzer.functions, key=lambda x: x.start):
        if f.size >= min_blob and f.start >= top_third:
            return f.start
    return img


def real_functions(analyzer, code_end=None, max_size=8192):
    """Functions inside the code region, excluding oversized false hits."""
    if code_end is None:
        code_end = detect_code_end(analyzer)
    fs = [f for f in analyzer.functions if f.start < code_end and f.size < max_size]
    fs.sort(key=lambda f: f.start)
    return fs, code_end


def resolve_far_target(hdr_size, seg, off):
    """File offset of a far-call target (segment is image-load-base relative)."""
    return hdr_size + seg * 16 + off


def build_call_graph(funcs, hdr_size, code_end=None):
    """Connect near + far edges. Returns (callees, callers, stats) keyed by start.

    funcs: list of analyze.Function (with .start/.end/.calls). .calls holds ints
    for near targets and (seg, off) tuples for far targets.
    """
    funcs = sorted(funcs, key=lambda f: f.start)
    starts = [f.start for f in funcs]
    ends = {f.start: f.end for f in funcs}

    def containing(off):
        i = bisect.bisect_right(starts, off) - 1
        if 0 <= i < len(funcs) and starts[i] <= off < ends[starts[i]]:
            return starts[i]
        return None

    callees = {s: set() for s in starts}
    callers = {s: set() for s in starts}
    stats = {"near": 0, "near_resolved": 0, "far": 0, "far_resolved": 0}

    for f in funcs:
        for tgt in f.calls:
            callee = None
            if isinstance(tgt, int):
                stats["near"] += 1
                callee = containing(tgt)
                if callee is not None:
                    stats["near_resolved"] += 1
            elif isinstance(tgt, tuple) and len(tgt) == 2:
                stats["far"] += 1
                callee = containing(resolve_far_target(hdr_size, *tgt))
                if callee is not None:
                    stats["far_resolved"] += 1
            if callee is not None:
                callees[f.start].add(callee)
                callers[callee].add(f.start)

    return callees, callers, stats

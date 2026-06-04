"""
ida_export.py - Export an accurate code map from IDA for the toolkit's lifters.

IDA's auto-analysis classifies code vs. data far better than a linear sweep,
especially on binaries with data-in-code (jump tables, inline constants). This
script exports that knowledge so a disassembler/lifter can decode at exactly
the instruction heads IDA verified, instead of guessing.

For each CODE segment it dumps:
  - functions:   sorted list of function entry offsets (segment-relative)
  - heads:       sorted list of every code instruction-head offset
  - code_ranges: merged [start, end) ranges IDA classified as code

The result is a JSON object keyed by segment. The key mode controls what the
keys are, so the same export feeds different toolchains:
  - ne     (default): NE segment number == IDA segment index + 1.
                      Consumed by tools/ne/ne_decode.py (--ida-json).
  - index:            raw IDA segment index.
  - name:             IDA segment name (e.g. ".text").
  - va:               segment start effective address (hex string).

Offsets are segment-relative for `ne`/`index`/`name` keys and absolute for the
`va` key (flat 32-bit images). Run inside IDA's Python (idalib/idapro):

    py -3 tools/ida/ida_export.py <binary> <out.json> [--key ne|index|name|va]
"""
import sys
import json
import idapro
import ida_auto, ida_segment, ida_funcs, ida_bytes, idautils


def _parse_args(argv):
    key = "ne"
    rest = []
    i = 0
    while i < len(argv):
        if argv[i] == "--key" and i + 1 < len(argv):
            key = argv[i + 1]
            i += 2
        else:
            rest.append(argv[i])
            i += 1
    if len(rest) < 2:
        raise SystemExit(
            "usage: ida_export.py <binary> <out.json> [--key ne|index|name|va]")
    return rest[0], rest[1], key


def main():
    binary, out_path, key_mode = _parse_args(sys.argv[1:])

    if idapro.open_database(binary, run_auto_analysis=True):
        raise SystemExit("open failed")
    ida_auto.auto_wait()

    result = {}
    try:
        n = ida_segment.get_segm_qty()
        for i in range(n):
            s = ida_segment.getnseg(i)
            cls = ida_segment.get_segm_class(s) or ""
            if cls != "CODE":
                continue

            # `va` mode keys flat images by absolute address and keeps offsets
            # absolute; the segmented modes are segment-relative.
            relative = key_mode != "va"
            base = s.start_ea if relative else 0

            if key_mode == "ne":
                key = str(i + 1)
            elif key_mode == "index":
                key = str(i)
            elif key_mode == "name":
                key = ida_segment.get_segm_name(s) or str(i)
            elif key_mode == "va":
                key = f"0x{s.start_ea:08X}"
            else:
                raise SystemExit(f"unknown --key mode: {key_mode}")

            funcs = sorted(int(ea - base)
                           for ea in idautils.Functions(s.start_ea, s.end_ea))
            heads = []
            ranges = []
            cur_start = None
            prev_end = None
            ea = s.start_ea
            while ea < s.end_ea:
                flags = ida_bytes.get_flags(ea)
                sz = ida_bytes.get_item_size(ea)
                if sz <= 0:
                    sz = 1
                if ida_bytes.is_code(flags):
                    heads.append(int(ea - base))
                    if cur_start is None:
                        cur_start = ea
                    prev_end = ea + sz
                else:
                    if cur_start is not None:
                        ranges.append([int(cur_start - base), int(prev_end - base)])
                        cur_start = None
                ea += sz
            if cur_start is not None:
                ranges.append([int(cur_start - base), int(prev_end - base)])
            result[key] = {"functions": funcs, "heads": heads, "code_ranges": ranges}
    finally:
        idapro.close_database(save=False)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f)

    tot_f = sum(len(v["functions"]) for v in result.values())
    tot_h = sum(len(v["heads"]) for v in result.values())
    print(f"Wrote {out_path}: {len(result)} code segments, "
          f"{tot_f} functions, {tot_h} code heads (key={key_mode})")


if __name__ == "__main__":
    main()

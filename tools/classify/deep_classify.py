"""
Deep classification: Match FUN_* functions by analyzing their string references
against known SDK source strings and Rewolf-specific content.

This uses the decompiled C output to extract string references from each function,
then checks whether those strings appear in the HL SDK source code or are unique
to Gunman Chronicles.
"""
import os
import re
from collections import defaultdict

SDK_PATH = "D:/recomp/pc/gunman/ref/halflife-sdk"
DISASM_PATH = "D:/recomp/pc/gunman/disasm"


def build_sdk_string_index(sdk_path):
    """Build index: string -> source file(s) where it appears."""
    index = {}  # string -> set of source files
    for subdir in ['dlls', 'cl_dll', 'common', 'pm_shared', 'game_shared']:
        dir_path = os.path.join(sdk_path, subdir)
        if not os.path.isdir(dir_path):
            continue
        for root, dirs, files in os.walk(dir_path):
            for f in files:
                if not f.endswith(('.cpp', '.h', '.c')):
                    continue
                filepath = os.path.join(root, f)
                relpath = os.path.relpath(filepath, sdk_path)
                with open(filepath, 'r', errors='replace') as fh:
                    content = fh.read()
                for m in re.finditer(r'"([^"]+)"', content):
                    s = m.group(1)
                    if len(s) >= 3:
                        if s not in index:
                            index[s] = set()
                        index[s].add(relpath)
    return index


def build_sdk_entity_map(sdk_path):
    """Map entity names -> class names -> source files."""
    entity_map = {}
    for root, dirs, files in os.walk(os.path.join(sdk_path, 'dlls')):
        for f in files:
            if not f.endswith('.cpp'):
                continue
            filepath = os.path.join(root, f)
            relpath = os.path.relpath(filepath, sdk_path)
            with open(filepath, 'r', errors='replace') as fh:
                content = fh.read()
            for m in re.finditer(r'LINK_ENTITY_TO_CLASS\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)', content):
                entity_map[m.group(1)] = (m.group(2), relpath)
    return entity_map


def extract_function_strings(decompiled_path):
    """Extract strings referenced by each function from decompiled C output."""
    func_data = {}
    current_func = None
    current_addr = None
    current_size = 0

    with open(decompiled_path, 'r', errors='replace') as f:
        for line in f:
            # Function header
            m = re.match(r' \* Function:\s+(.+)', line)
            if m:
                current_func = m.group(1).strip()
                continue
            m = re.match(r' \* Address:\s+(\w+)', line)
            if m:
                current_addr = m.group(1).strip()
                continue
            m = re.match(r' \* Size:\s+(\d+)', line)
            if m:
                current_size = int(m.group(1))
                if current_func:
                    func_data[current_func] = {
                        'addr': current_addr,
                        'size': current_size,
                        'strings': [],
                        'model_refs': [],
                        'sound_refs': [],
                    }
                continue

            if not current_func or current_func not in func_data:
                continue

            # Extract Ghidra string references (format: s_<content>_<hex_addr>)
            for sm in re.finditer(r's_([a-zA-Z0-9_./%+\\-]+?)_[0-9a-f]{6,}', line):
                raw = sm.group(1)
                # Reconstruct the string (Ghidra replaces some chars)
                decoded = raw.replace('_', ' ').strip()
                func_data[current_func]['strings'].append(raw)

                # Categorize
                raw_lower = raw.lower()
                if 'models/' in raw_lower or '.mdl' in raw_lower:
                    func_data[current_func]['model_refs'].append(raw)
                elif 'sound/' in raw_lower or '.wav' in raw_lower:
                    func_data[current_func]['sound_refs'].append(raw)

    return func_data


# Rewolf-specific keywords (never in HL SDK)
REWOLF_KEYWORDS = {
    'ourano', 'xenome', 'xmbryo', 'rustb', 'rustfl', 'rustgn', 'rustgun',
    'chemical', 'chemgun', 'beamgun', 'minigun', 'gausspistol', 'mechagun',
    'dml', 'polarisblade', 'polaris', 'aicore', 'mule',
    'raptor', 'microraptor', 'renesaur', 'rheptor', 'beak',
    'gator', 'hatchetfish', 'dragonfly', 'butterfly', 'cricket', 'maggot',
    'manta', 'scorpion', 'largescorpion',
    'bandit', 'demoman', 'chopper', 'gunman', 'aigirl',
    'mayan', 'rebar', 'city1', 'city2',
    'prdroid', 'trainingbot', 'endboss',
    'gascan', 'gastank', 'sodacan',
    'rewolf', 'gunman_chronicles',
    'w_beam.mdl', 'w_dml.mdl', 'w_gauss.mdl', 'w_chem.mdl',
    'w_minigun.mdl', 'w_mechagun.mdl', 'w_mule.mdl',
    'w_fists.mdl', 'w_polaris.mdl', 'w_shotgun2.mdl',
    'anime', 'cluster', 'tankshell',
    'dart', 'darttrap',
}


def classify_function(name, strings, model_refs, sound_refs, sdk_strings, sdk_entities):
    """Deep classify a function based on its string references."""

    all_refs = strings + model_refs + sound_refs
    if not all_refs:
        return 'NO_STRINGS', '', 0.0

    sdk_hits = 0
    rewolf_hits = 0
    total_refs = len(all_refs)

    sdk_files = defaultdict(int)

    for ref in all_refs:
        ref_lower = ref.lower()

        # Check for Rewolf keywords
        is_rewolf = False
        for kw in REWOLF_KEYWORDS:
            if kw in ref_lower:
                is_rewolf = True
                rewolf_hits += 1
                break

        if not is_rewolf:
            # Check if string appears in SDK source
            # Try variations of the string
            candidates = [ref, ref.replace(' ', '/'), ref.replace(' ', '_')]
            found_in_sdk = False
            for c in candidates:
                if c in sdk_strings:
                    sdk_hits += 1
                    for src_file in sdk_strings[c]:
                        sdk_files[src_file] += 1
                    found_in_sdk = True
                    break

    # Determine classification
    if total_refs == 0:
        return 'NO_STRINGS', '', 0.0

    rewolf_ratio = rewolf_hits / total_refs
    sdk_ratio = sdk_hits / total_refs

    if rewolf_hits > 0 and sdk_hits == 0:
        confidence = min(1.0, rewolf_ratio + 0.3)
        return 'REWOLF', '', confidence
    elif sdk_hits > 0 and rewolf_hits == 0:
        # Find most likely SDK source file
        best_file = max(sdk_files, key=sdk_files.get) if sdk_files else ''
        confidence = min(1.0, sdk_ratio + 0.2)
        return 'SDK', best_file, confidence
    elif rewolf_hits > sdk_hits:
        confidence = rewolf_ratio * 0.8
        return 'REWOLF_MIXED', '', confidence
    elif sdk_hits > rewolf_hits:
        best_file = max(sdk_files, key=sdk_files.get) if sdk_files else ''
        confidence = sdk_ratio * 0.8
        return 'SDK_MIXED', best_file, confidence
    else:
        return 'AMBIGUOUS', '', 0.5


def main():
    print("Building SDK string index...")
    sdk_strings = build_sdk_string_index(SDK_PATH)
    print(f"  {len(sdk_strings)} unique strings indexed from SDK")

    sdk_entities = build_sdk_entity_map(SDK_PATH)
    print(f"  {len(sdk_entities)} entities mapped")

    for dll_name, decomp_file in [
        ('gunman.dll (server)', 'gunman_decompiled.c'),
        ('client.dll (client)', 'client_decompiled.c'),
    ]:
        print(f"\nProcessing {dll_name}...")
        func_data = extract_function_strings(os.path.join(DISASM_PATH, decomp_file))
        print(f"  {len(func_data)} functions with parsed data")

        counts = defaultdict(int)
        sizes = defaultdict(int)
        classified = []

        for func_name, data in func_data.items():
            category, detail, confidence = classify_function(
                func_name,
                data['strings'],
                data['model_refs'],
                data['sound_refs'],
                sdk_strings,
                sdk_entities,
            )
            counts[category] += 1
            sizes[category] += data['size']
            classified.append((func_name, data['addr'], data['size'], category, detail, confidence))

        # Print summary
        total = sum(counts.values())
        total_size = sum(sizes.values())
        sdk_total = sum(v for k, v in counts.items() if 'SDK' in k)
        rewolf_total = sum(v for k, v in counts.items() if 'REWOLF' in k)
        sdk_size = sum(v for k, v in sizes.items() if 'SDK' in k)
        rewolf_size = sum(v for k, v in sizes.items() if 'REWOLF' in k)

        print(f"\n  {'=' * 60}")
        print(f"  {dll_name} - Deep Classification Results")
        print(f"  {'=' * 60}")
        print(f"  Total: {total} functions ({total_size:,} bytes)")
        print(f"  SDK-related:    {sdk_total:4d} functions ({sdk_size:>10,} bytes) ({sdk_total*100//total}%)")
        print(f"  Rewolf custom:  {rewolf_total:4d} functions ({rewolf_size:>10,} bytes) ({rewolf_total*100//total}%)")
        print(f"  No strings:     {counts['NO_STRINGS']:4d} functions ({sizes['NO_STRINGS']:>10,} bytes)")
        print(f"  Ambiguous:      {counts['AMBIGUOUS']:4d} functions ({sizes['AMBIGUOUS']:>10,} bytes)")
        print()
        for cat in sorted(counts.keys()):
            print(f"    {cat:20s}: {counts[cat]:4d} funcs  ({sizes[cat]:>10,} bytes)")

        # Write detailed results
        base = decomp_file.replace('_decompiled.c', '')
        out_path = os.path.join(DISASM_PATH, f"{base}_deep_classification.txt")
        with open(out_path, 'w') as f:
            f.write(f"# Deep Classification: {dll_name}\n")
            f.write(f"# SDK: {sdk_total} funcs ({sdk_size:,} bytes)\n")
            f.write(f"# Rewolf: {rewolf_total} funcs ({rewolf_size:,} bytes)\n")
            f.write(f"# No strings: {counts['NO_STRINGS']} funcs\n")
            f.write(f"# Ambiguous: {counts['AMBIGUOUS']} funcs\n\n")

            for cat in ['REWOLF', 'REWOLF_MIXED', 'SDK', 'SDK_MIXED', 'AMBIGUOUS', 'NO_STRINGS']:
                cat_funcs = [(n, a, s, d, c) for n, a, s, cat2, d, c in classified if cat2 == cat]
                if not cat_funcs:
                    continue
                cat_funcs.sort(key=lambda x: x[1])
                f.write(f"\n{'=' * 70}\n")
                f.write(f"  {cat} ({len(cat_funcs)} functions)\n")
                f.write(f"{'=' * 70}\n")
                for name, addr, size, detail, conf in cat_funcs:
                    f.write(f"  {addr} | {size:6d} | {conf:.2f} | {name}")
                    if detail:
                        f.write(f"  -> {detail}")
                    f.write("\n")

        print(f"  Written to: {out_path}")


if __name__ == '__main__':
    main()

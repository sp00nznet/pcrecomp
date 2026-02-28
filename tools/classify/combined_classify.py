"""
Combined function classifier for Gunman Chronicles recompilation.

Uses multiple signals to classify functions as SDK or Rewolf-custom:
1. Name-based matching (class names, method names from HL SDK)
2. String reference analysis (SDK strings vs Rewolf keywords)
3. Call graph propagation (neighbors of known functions)
4. Address clustering (functions from same .cpp are typically adjacent)
"""
import os
import re
from collections import defaultdict

SDK_PATH = "D:/recomp/pc/gunman/ref/halflife-sdk"
DISASM_PATH = "D:/recomp/pc/gunman/disasm"

# ── Rewolf-specific keywords ──────────────────────────────────────────
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
    'drone', 'seeker',
}

# Known SDK class names (from Half-Life SDK 2.3)
SDK_CLASSES = set()
# Known Rewolf class names
REWOLF_CLASSES = set()


def build_sdk_class_list(sdk_path):
    """Extract class names defined in the HL SDK."""
    classes = set()
    for subdir in ['dlls', 'cl_dll', 'common', 'pm_shared', 'game_shared',
                   'engine', 'public']:
        dir_path = os.path.join(sdk_path, subdir)
        if not os.path.isdir(dir_path):
            continue
        for root, dirs, files in os.walk(dir_path):
            for f in files:
                if not f.endswith(('.cpp', '.h', '.c')):
                    continue
                filepath = os.path.join(root, f)
                with open(filepath, 'r', errors='replace') as fh:
                    content = fh.read()
                # Match class declarations
                for m in re.finditer(r'class\s+(\w+)', content):
                    classes.add(m.group(1))
    return classes


def build_sdk_string_index(sdk_path):
    """Build index: string -> source file(s) where it appears."""
    index = {}
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


def build_sdk_function_names(sdk_path):
    """Extract function/method names from SDK source."""
    names = set()
    for subdir in ['dlls', 'cl_dll', 'common', 'pm_shared', 'game_shared']:
        dir_path = os.path.join(sdk_path, subdir)
        if not os.path.isdir(dir_path):
            continue
        for root, dirs, files in os.walk(dir_path):
            for f in files:
                if not f.endswith(('.cpp', '.h', '.c')):
                    continue
                filepath = os.path.join(root, f)
                with open(filepath, 'r', errors='replace') as fh:
                    content = fh.read()
                # Match function definitions: ReturnType ClassName::MethodName(
                for m in re.finditer(r'(\w+)::(\w+)\s*\(', content):
                    names.add(f"{m.group(1)}::{m.group(2)}")
                    names.add(m.group(2))
                # Match standalone functions
                for m in re.finditer(r'\n\w[\w\s*&]*\s+(\w+)\s*\([^)]*\)\s*\{', content):
                    name = m.group(1)
                    if len(name) > 2 and name not in ('if', 'for', 'while', 'switch', 'return'):
                        names.add(name)
    return names


def parse_functions_file(filepath):
    """Parse a Ghidra function export file."""
    functions = []
    with open(filepath, 'r', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('='):
                continue
            parts = line.split('|')
            if len(parts) >= 6:
                addr = parts[0].strip()
                try:
                    size = int(parts[1].strip())
                except ValueError:
                    continue
                name = parts[5].strip()
                functions.append({
                    'addr': addr,
                    'size': size,
                    'name': name,
                    'addr_int': int(addr, 16),
                })
    return functions


def parse_decompiled(filepath):
    """Parse decompiled C output to extract per-function data."""
    func_data = {}
    current_func = None
    current_addr = None
    current_body = []

    with open(filepath, 'r', errors='replace') as f:
        for line in f:
            # Function header
            m = re.match(r' \* Function:\s+(.+)', line)
            if m:
                # Save previous function
                if current_func and current_func in func_data:
                    func_data[current_func]['body'] = ' '.join(current_body)
                current_func = m.group(1).strip()
                current_body = []
                continue

            m = re.match(r' \* Address:\s+(\w+)', line)
            if m:
                current_addr = m.group(1).strip()
                continue

            m = re.match(r' \* Size:\s+(\d+)', line)
            if m:
                size = int(m.group(1))
                if current_func:
                    func_data[current_func] = {
                        'addr': current_addr,
                        'addr_int': int(current_addr, 16) if current_addr else 0,
                        'size': size,
                        'strings': [],
                        'calls': [],
                        'class_refs': [],
                    }
                    current_body = []
                continue

            if not current_func or current_func not in func_data:
                continue

            current_body.append(line.rstrip())

            # Extract Ghidra string references
            for sm in re.finditer(r's_([a-zA-Z0-9_./%+\\-]+?)_[0-9a-f]{6,}', line):
                func_data[current_func]['strings'].append(sm.group(1))

            # Extract function calls (FUN_xxxx and ClassName::Method)
            for cm in re.finditer(r'FUN_([0-9a-f]{8})', line):
                func_data[current_func]['calls'].append(f"FUN_{cm.group(1)}")
            for cm in re.finditer(r'(\w+)::(\w+)', line):
                cls = cm.group(1)
                func_data[current_func]['class_refs'].append(cls)

    # Save last function
    if current_func and current_func in func_data:
        func_data[current_func]['body'] = ' '.join(current_body)

    return func_data


def classify_by_name(name, sdk_classes, sdk_func_names):
    """Classify a function by its name."""
    if name.startswith('FUN_') or name.startswith('thunk_FUN_'):
        return 'UNKNOWN', 0.0

    # Check class-based names (ClassName::Method)
    if '::' in name:
        cls = name.split('::')[0]
        # Strip thunk prefix
        cls = cls.replace('thunk_', '')

        cls_lower = cls.lower()
        # Check for Rewolf-specific class names
        for kw in REWOLF_KEYWORDS:
            if kw in cls_lower:
                return 'REWOLF', 0.9

        if cls in sdk_classes:
            return 'SDK', 0.85

        # Common SDK base classes
        sdk_base_classes = {
            'CBaseEntity', 'CBaseMonster', 'CBasePlayer', 'CBasePlayerItem',
            'CBasePlayerWeapon', 'CBaseToggle', 'CBaseDoor', 'CBaseButton',
            'CBaseTrigger', 'CBaseDelay', 'CBaseAnimating', 'CPointEntity',
            'CSquadMonster', 'CFlyingMonster', 'CTalkMonster', 'CFollowingMonster',
            'CGrenade', 'CBasePlayerAmmo', 'CWorld', 'CDecal', 'CCorpse',
            'CSprite', 'CBeam', 'CLaser', 'CGib', 'CBubbling',
            'CEnvExplosion', 'CBreakable', 'CPushable', 'CFuncWall',
            'CPathTrack', 'CFuncTrain', 'CFuncTrackTrain', 'CPlatTrigger',
            'CFuncPlat', 'CFuncPlatRot', 'CMultiSource', 'CRenderFxManager',
            'CLight', 'CEnvLight', 'CMessage', 'CEnvSpark', 'CGameText',
            'CGameTeamMaster', 'CGameTeamSet', 'CGamePlayerZone',
            'CGamePlayerHurt', 'CGameCounter', 'CGameEnd',
            'CRuleEntity', 'CRulePointEntity', 'CRuleBrushEntity',
            'CItemSuit', 'CItemBattery', 'CItemAntidote', 'CItemSecurity',
            'CItemLongJump', 'CHealthKit', 'CWallHealth', 'CAirtank',
            'CNodeViewer', 'CTestHull', 'CGraph', 'CLink', 'CNode',
            'CHalfLifeMultiplay', 'CHalfLifeRules', 'CHalfLifeTraining',
            'CGameRules', 'CMultiplayGameMgrHelper',
        }
        if cls in sdk_base_classes:
            return 'SDK', 0.9

        return 'UNKNOWN', 0.3

    # Check standalone function names
    name_lower = name.lower()
    for kw in REWOLF_KEYWORDS:
        if kw in name_lower:
            return 'REWOLF', 0.85

    if name in sdk_func_names:
        return 'SDK', 0.7

    # Common SDK function patterns
    sdk_patterns = [
        r'^(UTIL_|CL_|HUD_|V_|EV_|PM_)',
        r'^(pfn|SV_|NET_)',
        r'^(R_|W_|S_|Key)',
        r'^(FireTargets|SUB_)',
    ]
    for pat in sdk_patterns:
        if re.match(pat, name):
            return 'SDK', 0.6

    return 'UNKNOWN', 0.0


def classify_by_strings(strings, sdk_strings):
    """Classify based on string references."""
    if not strings:
        return 'UNKNOWN', 0.0

    sdk_hits = 0
    rewolf_hits = 0
    sdk_files = defaultdict(int)

    for ref in strings:
        ref_lower = ref.lower()
        is_rewolf = False
        for kw in REWOLF_KEYWORDS:
            if kw in ref_lower:
                is_rewolf = True
                rewolf_hits += 1
                break

        if not is_rewolf:
            candidates = [ref, ref.replace(' ', '/'), ref.replace(' ', '_')]
            for c in candidates:
                if c in sdk_strings:
                    sdk_hits += 1
                    for src in sdk_strings[c]:
                        sdk_files[src] += 1
                    break

    total = len(strings)
    if rewolf_hits > 0 and sdk_hits == 0:
        return 'REWOLF', min(1.0, rewolf_hits / total + 0.3)
    elif sdk_hits > 0 and rewolf_hits == 0:
        best_file = max(sdk_files, key=sdk_files.get) if sdk_files else ''
        return f'SDK:{best_file}', min(1.0, sdk_hits / total + 0.2)
    elif rewolf_hits > sdk_hits:
        return 'REWOLF', rewolf_hits / total * 0.8
    elif sdk_hits > rewolf_hits:
        best_file = max(sdk_files, key=sdk_files.get) if sdk_files else ''
        return f'SDK:{best_file}', sdk_hits / total * 0.8
    elif rewolf_hits > 0:
        return 'AMBIGUOUS', 0.4
    return 'UNKNOWN', 0.0


def propagate_call_graph(func_data, classifications):
    """Propagate classification through call graph."""
    # Build reverse call graph
    callers = defaultdict(set)  # func -> set of functions that call it
    callees = defaultdict(set)  # func -> set of functions it calls

    for fname, data in func_data.items():
        for call in data.get('calls', []):
            if call in func_data:
                callees[fname].add(call)
                callers[call].add(fname)

    # Propagate: if an unknown function is predominantly called by/calls
    # SDK or Rewolf functions, classify it accordingly
    changes = True
    iteration = 0
    while changes and iteration < 5:
        changes = False
        iteration += 1
        for fname in list(func_data.keys()):
            if fname in classifications and classifications[fname][0] != 'UNKNOWN':
                continue

            # Count SDK vs Rewolf in neighbors
            sdk_score = 0
            rewolf_score = 0

            # Check callers
            for caller in callers.get(fname, set()):
                if caller in classifications:
                    cat = classifications[caller][0]
                    if 'SDK' in cat:
                        sdk_score += 1
                    elif 'REWOLF' in cat:
                        rewolf_score += 1

            # Check callees
            for callee in callees.get(fname, set()):
                if callee in classifications:
                    cat = classifications[callee][0]
                    if 'SDK' in cat:
                        sdk_score += 0.5
                    elif 'REWOLF' in cat:
                        rewolf_score += 0.5

            # Check class references in body
            for cls in func_data[fname].get('class_refs', []):
                if cls in SDK_CLASSES:
                    sdk_score += 0.3
                elif any(kw in cls.lower() for kw in REWOLF_KEYWORDS):
                    rewolf_score += 0.3

            total = sdk_score + rewolf_score
            if total >= 2:
                if sdk_score > rewolf_score * 2:
                    classifications[fname] = ('SDK_INFERRED', min(0.6, sdk_score / total))
                    changes = True
                elif rewolf_score > sdk_score * 2:
                    classifications[fname] = ('REWOLF_INFERRED', min(0.6, rewolf_score / total))
                    changes = True

    return classifications


def cluster_by_address(func_list, classifications):
    """Use address proximity to infer classification of nearby functions."""
    # Sort by address
    sorted_funcs = sorted(func_list, key=lambda f: f['addr_int'])

    # Sliding window: if surrounded by SDK or Rewolf functions, infer same
    window_size = 5
    for i, func in enumerate(sorted_funcs):
        name = func['name']
        if name in classifications and classifications[name][0] != 'UNKNOWN':
            continue

        # Look at neighbors
        sdk_count = 0
        rewolf_count = 0
        for j in range(max(0, i - window_size), min(len(sorted_funcs), i + window_size + 1)):
            if j == i:
                continue
            neighbor = sorted_funcs[j]['name']
            if neighbor in classifications:
                cat = classifications[neighbor][0]
                # Weight closer neighbors more
                weight = 1.0 / (abs(j - i))
                if 'SDK' in cat:
                    sdk_count += weight
                elif 'REWOLF' in cat:
                    rewolf_count += weight

        total = sdk_count + rewolf_count
        if total >= 1.5:
            if sdk_count > rewolf_count * 1.5:
                classifications[name] = ('SDK_CLUSTERED', min(0.5, sdk_count / (total + 1)))
            elif rewolf_count > sdk_count * 1.5:
                classifications[name] = ('REWOLF_CLUSTERED', min(0.5, rewolf_count / (total + 1)))

    return classifications


def main():
    print("=" * 70)
    print("  COMBINED FUNCTION CLASSIFIER")
    print("  Gunman Chronicles Recompilation Project")
    print("=" * 70)

    # Build SDK indices
    print("\nBuilding SDK indices...")
    global SDK_CLASSES
    SDK_CLASSES = build_sdk_class_list(SDK_PATH)
    print(f"  {len(SDK_CLASSES)} SDK class names")

    sdk_strings = build_sdk_string_index(SDK_PATH)
    print(f"  {len(sdk_strings)} SDK strings indexed")

    sdk_func_names = build_sdk_function_names(SDK_PATH)
    print(f"  {len(sdk_func_names)} SDK function/method names")

    for dll_label, func_file, decomp_file in [
        ('gunman.dll (server)', 'gunman_functions.txt', 'gunman_decompiled.c'),
        ('client.dll (client)', 'client_functions.txt', 'client_decompiled.c'),
    ]:
        print(f"\n{'=' * 70}")
        print(f"  Processing: {dll_label}")
        print(f"{'=' * 70}")

        # Parse function list
        func_list = parse_functions_file(os.path.join(DISASM_PATH, func_file))
        print(f"  {len(func_list)} functions from export")

        # Parse decompiled code
        func_data = parse_decompiled(os.path.join(DISASM_PATH, decomp_file))
        print(f"  {len(func_data)} functions from decompiled output")

        classifications = {}

        # Pass 1: Name-based classification
        print("\n  Pass 1: Name-based classification...")
        for func in func_list:
            cat, conf = classify_by_name(func['name'], SDK_CLASSES, sdk_func_names)
            if cat != 'UNKNOWN':
                classifications[func['name']] = (cat, conf)

        named = sum(1 for v in classifications.values() if v[0] != 'UNKNOWN')
        print(f"    {named} functions classified by name")

        # Pass 2: String reference classification
        print("  Pass 2: String reference classification...")
        str_classified = 0
        for fname, data in func_data.items():
            if fname in classifications and classifications[fname][0] != 'UNKNOWN':
                continue
            cat, conf = classify_by_strings(data['strings'], sdk_strings)
            if cat != 'UNKNOWN':
                classifications[fname] = (cat, conf)
                str_classified += 1
        print(f"    {str_classified} additional functions classified by strings")

        # Pass 3: Call graph propagation
        print("  Pass 3: Call graph propagation...")
        before = sum(1 for v in classifications.values() if v[0] != 'UNKNOWN')
        classifications = propagate_call_graph(func_data, classifications)
        after = sum(1 for v in classifications.values() if v[0] != 'UNKNOWN')
        print(f"    {after - before} additional functions classified by call graph")

        # Pass 4: Address clustering
        print("  Pass 4: Address clustering...")
        before = after
        classifications = cluster_by_address(func_list, classifications)
        after = sum(1 for v in classifications.values() if v[0] != 'UNKNOWN')
        print(f"    {after - before} additional functions classified by address clustering")

        # Build final summary
        all_names = set(f['name'] for f in func_list)
        all_names.update(func_data.keys())

        sdk_funcs = []
        rewolf_funcs = []
        unknown_funcs = []

        sdk_bytes = 0
        rewolf_bytes = 0
        unknown_bytes = 0

        # Get size info
        size_map = {}
        for f in func_list:
            size_map[f['name']] = f['size']
        for fname, data in func_data.items():
            if fname not in size_map:
                size_map[fname] = data['size']

        for name in sorted(all_names):
            size = size_map.get(name, 0)
            if name in classifications:
                cat, conf = classifications[name]
                if 'SDK' in cat:
                    sdk_funcs.append((name, cat, conf, size))
                    sdk_bytes += size
                elif 'REWOLF' in cat:
                    rewolf_funcs.append((name, cat, conf, size))
                    rewolf_bytes += size
                else:
                    unknown_funcs.append((name, cat, conf, size))
                    unknown_bytes += size
            else:
                unknown_funcs.append((name, 'UNKNOWN', 0.0, size))
                unknown_bytes += size

        total_funcs = len(all_names)
        total_bytes = sdk_bytes + rewolf_bytes + unknown_bytes

        print(f"\n  {'=' * 60}")
        print(f"  FINAL RESULTS: {dll_label}")
        print(f"  {'=' * 60}")
        print(f"  Total:   {total_funcs:5d} functions  ({total_bytes:>10,} bytes)")
        print(f"  SDK:     {len(sdk_funcs):5d} functions  ({sdk_bytes:>10,} bytes)  "
              f"({len(sdk_funcs)*100//total_funcs}% funcs, {sdk_bytes*100//total_bytes if total_bytes else 0}% bytes)")
        print(f"  Rewolf:  {len(rewolf_funcs):5d} functions  ({rewolf_bytes:>10,} bytes)  "
              f"({len(rewolf_funcs)*100//total_funcs}% funcs, {rewolf_bytes*100//total_bytes if total_bytes else 0}% bytes)")
        print(f"  Unknown: {len(unknown_funcs):5d} functions  ({unknown_bytes:>10,} bytes)  "
              f"({len(unknown_funcs)*100//total_funcs}% funcs, {unknown_bytes*100//total_bytes if total_bytes else 0}% bytes)")

        # Breakdown by classification type
        cat_counts = defaultdict(lambda: [0, 0])  # cat -> [count, bytes]
        for name, cat, conf, size in sdk_funcs + rewolf_funcs + unknown_funcs:
            cat_counts[cat][0] += 1
            cat_counts[cat][1] += size

        print(f"\n  Breakdown by method:")
        for cat in sorted(cat_counts.keys()):
            count, size = cat_counts[cat]
            print(f"    {cat:25s}: {count:5d} funcs  ({size:>10,} bytes)")

        # Write detailed output
        base = decomp_file.replace('_decompiled.c', '')
        out_path = os.path.join(DISASM_PATH, f"{base}_combined_classification.txt")
        with open(out_path, 'w') as f:
            f.write(f"# Combined Classification: {dll_label}\n")
            f.write(f"# Generated by combined_classify.py\n")
            f.write(f"# Total: {total_funcs} functions ({total_bytes:,} bytes)\n")
            f.write(f"# SDK: {len(sdk_funcs)} functions ({sdk_bytes:,} bytes)\n")
            f.write(f"# Rewolf: {len(rewolf_funcs)} functions ({rewolf_bytes:,} bytes)\n")
            f.write(f"# Unknown: {len(unknown_funcs)} functions ({unknown_bytes:,} bytes)\n\n")

            # SDK functions grouped by source file
            f.write(f"\n{'=' * 70}\n")
            f.write(f"  SDK FUNCTIONS ({len(sdk_funcs)})\n")
            f.write(f"{'=' * 70}\n\n")

            # Group by detail (source file for string-matched)
            sdk_by_source = defaultdict(list)
            for name, cat, conf, size in sorted(sdk_funcs, key=lambda x: x[0]):
                source = ''
                if ':' in cat:
                    source = cat.split(':', 1)[1]
                    cat_base = cat.split(':')[0]
                else:
                    cat_base = cat
                sdk_by_source[source or cat_base].append((name, cat_base, conf, size))

            for source in sorted(sdk_by_source.keys()):
                funcs = sdk_by_source[source]
                f.write(f"\n  -- {source} ({len(funcs)} functions) --\n")
                for name, cat, conf, size in funcs:
                    f.write(f"    {size:6d}B  {conf:.2f}  [{cat:20s}]  {name}\n")

            # Rewolf functions
            f.write(f"\n{'=' * 70}\n")
            f.write(f"  REWOLF CUSTOM FUNCTIONS ({len(rewolf_funcs)})\n")
            f.write(f"{'=' * 70}\n\n")
            for name, cat, conf, size in sorted(rewolf_funcs, key=lambda x: x[0]):
                f.write(f"    {size:6d}B  {conf:.2f}  [{cat:20s}]  {name}\n")

            # Unknown functions
            f.write(f"\n{'=' * 70}\n")
            f.write(f"  UNKNOWN/UNCLASSIFIED FUNCTIONS ({len(unknown_funcs)})\n")
            f.write(f"{'=' * 70}\n\n")
            # Sort by address for easier manual review
            addr_map = {}
            for func in func_list:
                addr_map[func['name']] = func['addr']
            for fname, fdata in func_data.items():
                if fname not in addr_map:
                    addr_map[fname] = fdata['addr']

            unknown_sorted = sorted(unknown_funcs,
                                    key=lambda x: int(addr_map.get(x[0], '0'), 16))
            for name, cat, conf, size in unknown_sorted:
                addr = addr_map.get(name, '????????')
                f.write(f"    {addr}  {size:6d}B  {name}\n")

        print(f"\n  Written to: {out_path}")

    print(f"\n{'=' * 70}")
    print(f"  DONE")
    print(f"{'=' * 70}")


if __name__ == '__main__':
    main()

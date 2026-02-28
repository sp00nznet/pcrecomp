"""
Classify functions in Gunman Chronicles DLLs as SDK vs Rewolf custom.

Strategy:
1. Extract all function/method/class names from the HL SDK source
2. Extract all entity names from LINK_ENTITY_TO_CLASS macros in SDK
3. Compare against named functions in Ghidra export
4. Classify unnamed FUN_* functions by analyzing their string references
   in the decompiled C output
"""
import os
import re
import sys
from collections import defaultdict

SDK_PATH = "D:/recomp/pc/gunman/ref/halflife-sdk"
DISASM_PATH = "D:/recomp/pc/gunman/disasm"


def extract_sdk_entities(sdk_path):
    """Extract all LINK_ENTITY_TO_CLASS entity names from SDK."""
    entities = {}
    dlls_path = os.path.join(sdk_path, "dlls")
    for root, dirs, files in os.walk(dlls_path):
        for f in files:
            if f.endswith(('.cpp', '.h')):
                filepath = os.path.join(root, f)
                with open(filepath, 'r', errors='replace') as fh:
                    for line in fh:
                        m = re.search(r'LINK_ENTITY_TO_CLASS\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)', line)
                        if m:
                            entity_name = m.group(1)
                            class_name = m.group(2)
                            entities[entity_name] = {
                                'class': class_name,
                                'file': os.path.relpath(filepath, sdk_path)
                            }
    return entities


def extract_sdk_functions(sdk_path):
    """Extract function/method names from SDK source files."""
    functions = set()
    classes = set()

    for subdir in ['dlls', 'cl_dll', 'common', 'pm_shared', 'game_shared', 'engine']:
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

                # Extract class declarations
                for m in re.finditer(r'class\s+(\w+)', content):
                    classes.add(m.group(1))

                # Extract function definitions (simplified pattern)
                # Matches: returntype ClassName::MethodName(
                for m in re.finditer(r'(\w+)\s*::\s*(\w+)\s*\(', content):
                    cls = m.group(1)
                    method = m.group(2)
                    functions.add(f"{cls}::{method}")
                    functions.add(method)
                    classes.add(cls)

                # Extract standalone function definitions
                for m in re.finditer(r'^(?:void|int|float|BOOL|char|unsigned|long|double|EXPORT|extern|static)\s+(?:__\w+\s+)?(\w+)\s*\(', content, re.MULTILINE):
                    functions.add(m.group(1))

                # Extract Think/Touch/Use callback assignments
                for m in re.finditer(r'(?:SetThink|SetTouch|SetUse)\s*\(\s*(?:&\w+::)?(\w+)\s*\)', content):
                    functions.add(m.group(1))

    return functions, classes


def extract_sdk_strings(sdk_path):
    """Extract all string literals from SDK that would appear in binaries."""
    strings = set()
    for subdir in ['dlls', 'cl_dll']:
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
                for m in re.finditer(r'"([^"]{4,})"', content):
                    strings.add(m.group(1))
    return strings


def parse_ghidra_functions(filepath):
    """Parse a Ghidra function export file."""
    functions = []
    with open(filepath, 'r') as f:
        for line in f:
            if line.startswith('#'):
                continue
            parts = line.strip().split('|')
            if len(parts) >= 6:
                addr = parts[0].strip()
                size = int(parts[1].strip())
                refs = int(parts[2].strip())
                cc = parts[3].strip()
                flags = parts[4].strip()
                name = parts[5].strip()
                functions.append({
                    'addr': addr,
                    'size': size,
                    'refs': refs,
                    'cc': cc,
                    'flags': flags,
                    'name': name,
                    'is_auto': name.startswith('FUN_') or name.startswith('Unwind@'),
                })
    return functions


def extract_strings_from_decompiled(decompiled_path, func_name, func_addr):
    """Extract string references from a specific function in decompiled output."""
    strings = []
    # This is expensive - we'll do it in batch instead
    return strings


def classify_named_function(name, sdk_entities, sdk_functions, sdk_classes):
    """Classify a named function as SDK or custom."""

    # Check if it's an entity factory function matching SDK
    if name in sdk_entities:
        return 'SDK_ENTITY', sdk_entities[name]['file']

    # Check if method name matches SDK
    # Strip class prefix if present (e.g., "CAirtank::TankThink" -> check CAirtank and TankThink)
    if '::' in name:
        cls, method = name.split('::', 1)
        if cls in sdk_classes and method in sdk_functions:
            return 'SDK_METHOD', f"{cls}::{method}"
        if cls in sdk_classes:
            return 'SDK_CLASS_CUSTOM_METHOD', cls
        # Unknown class = likely Rewolf custom
        return 'REWOLF_METHOD', cls

    # Check if standalone function matches SDK
    if name in sdk_functions:
        return 'SDK_FUNCTION', name

    # Known HL SDK patterns
    sdk_patterns = [
        r'^Dispatch\w+',        # DispatchSpawn, DispatchThink, etc.
        r'^Client\w+',          # ClientCommand, ClientConnect, etc.
        r'^Player\w+Think$',    # PlayerPreThink, PlayerPostThink
        r'^Server\w+',          # ServerActivate, ServerDeactivate
        r'^StartFrame$',
        r'^GiveFnptrsToDll$',
        r'^GetEntityAPI\d?$',
        r'^PM_\w+',             # Player movement
        r'^HUD_\w+',            # HUD functions (client)
        r'^V_\w+',              # View functions (client)
        r'^CL_\w+',             # Client functions
        r'^IN_\w+',             # Input functions
        r'^KB_\w+',             # Keyboard functions
    ]

    for pattern in sdk_patterns:
        if re.match(pattern, name):
            return 'SDK_FUNCTION', name

    # Known Gunman-specific entity prefixes
    gunman_entities = [
        'monster_ourano', 'monster_raptor', 'monster_microraptor', 'monster_renesaur',
        'monster_beak', 'monster_beakbirther', 'monster_xenome', 'monster_tube',
        'monster_tubequeen', 'monster_rustbit', 'monster_rustbot', 'monster_rustflier',
        'monster_rustgnr', 'monster_rustgunr', 'monster_aigirl', 'monster_gator',
        'monster_butterfly', 'monster_cricket', 'monster_critter', 'monster_dragonfly',
        'monster_hatchetfish', 'monster_maggot', 'monster_manta', 'monster_scorpion',
        'monster_largescorpion', 'monster_dart', 'monster_darttrap', 'monster_endboss',
        'monster_human_bandit', 'monster_human_chopper', 'monster_human_demoman',
        'monster_human_gunman', 'monster_gunner', 'monster_gunner_friendly',
        'monster_tank', 'monster_tank_rocket', 'monster_trainingbot',
        'monster_flashlight', 'monster_rheptor',
        'weapon_pistol', 'weapon_gausspistol', 'weapon_shotgun', 'weapon_minigun',
        'weapon_chemgun', 'weapon_SPchemicalgun', 'weapon_beamgun', 'weapon_dml',
        'weapon_dmlGrenade', 'weapon_mechagun', 'weapon_mule', 'weapon_fists',
        'weapon_polarisblade', 'weapon_aicore',
        'ammo_chemical', 'ammo_minigunClip', 'ammo_beamgunclip', 'ammo_dmlclip',
        'ammo_dmlsingle', 'ammo_mechgunClip', 'ammo_gaussclip',
        'item_gascan', 'item_gastank', 'item_sodacan', 'item_armor',
        'trigger_gunmanteleport', 'trigger_tank', 'trigger_tankeject',
        'trigger_tankoutofgas', 'trigger_tankshell',
        'cycler_prdroid', 'func_tanklaserrust', 'func_wind',
        'env_clusterExplosion', 'env_debris',
        'player_togglehud', 'player_giveitems', 'player_armor', 'player_speaker',
    ]

    if name in gunman_entities:
        return 'REWOLF_ENTITY', name

    # Gunman-specific function patterns
    gunman_patterns = [
        r'(?i)chemical', r'(?i)anime.*rocket', r'(?i)backpack',
        r'(?i)rustb', r'(?i)xenome', r'(?i)ourano', r'(?i)mayan',
        r'(?i)vehicle', r'(?i)tank(?!controls)', r'(?i)minigun',
        r'(?i)gausspistol', r'(?i)beamgun', r'(?i)dml',
        r'(?i)mechagun', r'(?i)mule', r'(?i)polarisblade',
        r'(?i)cluster', r'(?i)cust_',
    ]

    for pattern in gunman_patterns:
        if re.search(pattern, name):
            return 'REWOLF_FUNCTION', name

    # Common SDK callback patterns that could be either
    callback_patterns = [
        r'\w+Think$', r'\w+Touch$', r'\w+Use$', r'\w+Spawn$',
        r'\w+Die$', r'\w+Killed$', r'\w+Blocked$',
    ]

    for pattern in callback_patterns:
        if re.match(pattern, name):
            return 'AMBIGUOUS_CALLBACK', name

    return 'UNKNOWN', name


def analyze_decompiled_strings(decompiled_path):
    """Extract string references per function from decompiled C output."""
    func_strings = {}
    current_func = None

    with open(decompiled_path, 'r', errors='replace') as f:
        for line in f:
            # Look for function headers
            m = re.match(r' \* Function:\s+(.+)', line)
            if m:
                current_func = m.group(1).strip()
                func_strings[current_func] = []
                continue

            # Look for string literals in the decompiled code
            if current_func:
                for sm in re.finditer(r's_([a-zA-Z0-9_/\\.-]+?)_[0-9a-f]+', line):
                    # Ghidra encodes string refs as s_<content>_<address>
                    string_val = sm.group(1).replace('_', ' ').strip()
                    func_strings[current_func].append(sm.group(1))

    return func_strings


def main():
    print("=" * 90)
    print("GUNMAN CHRONICLES: SDK vs REWOLF CODE CLASSIFIER")
    print("=" * 90)

    # Step 1: Extract SDK data
    print("\n[1/5] Extracting SDK entity definitions...")
    sdk_entities = extract_sdk_entities(SDK_PATH)
    print(f"  Found {len(sdk_entities)} SDK entities")

    print("\n[2/5] Extracting SDK function names...")
    sdk_functions, sdk_classes = extract_sdk_functions(SDK_PATH)
    print(f"  Found {len(sdk_functions)} SDK functions, {len(sdk_classes)} SDK classes")

    print("\n[3/5] Extracting SDK string literals...")
    sdk_strings = extract_sdk_strings(SDK_PATH)
    print(f"  Found {len(sdk_strings)} SDK strings")

    # Step 2: Parse Ghidra function lists
    print("\n[4/5] Parsing Ghidra function exports...")
    server_funcs = parse_ghidra_functions(os.path.join(DISASM_PATH, "gunman_functions.txt"))
    client_funcs = parse_ghidra_functions(os.path.join(DISASM_PATH, "client_functions.txt"))
    print(f"  Server: {len(server_funcs)} functions")
    print(f"  Client: {len(client_funcs)} functions")

    # Step 3: Analyze decompiled strings
    print("\n[5/5] Analyzing string references in decompiled code...")
    server_strings = analyze_decompiled_strings(os.path.join(DISASM_PATH, "gunman_decompiled.c"))
    client_strings = analyze_decompiled_strings(os.path.join(DISASM_PATH, "client_decompiled.c"))
    print(f"  Server: {len(server_strings)} functions with string refs")
    print(f"  Client: {len(client_strings)} functions with string refs")

    # Step 4: Classify each function
    results = {'server': {}, 'client': {}}
    categories = defaultdict(lambda: defaultdict(int))
    category_funcs = defaultdict(lambda: defaultdict(list))

    for dll_name, funcs, decomp_strings in [
        ('server', server_funcs, server_strings),
        ('client', client_funcs, client_strings),
    ]:
        for func in funcs:
            name = func['name']
            addr = func['addr']

            if func['is_auto']:
                # Try to classify by string references
                strings = decomp_strings.get(name, [])

                # Check if any strings match SDK patterns
                has_sdk_strings = False
                has_rewolf_strings = False
                for s in strings:
                    s_lower = s.lower().replace('/', ' ').replace('\\', ' ')
                    # Rewolf-specific strings
                    if any(x in s_lower for x in [
                        'rewolf', 'ourano', 'xenome', 'rustb', 'chemical',
                        'minigun', 'beamgun', 'dml', 'gausspistol', 'mechagun',
                        'mule', 'polaris', 'gunman', 'mayan', 'rebar',
                        'raptor', 'scorpion', 'gator', 'butterfly', 'cricket',
                        'hatchetfish', 'dragonfly', 'maggot', 'manta',
                        'bandit', 'chopper', 'demoman', 'aigirl',
                        'tank ', 'gascan', 'gastank',
                    ]):
                        has_rewolf_strings = True
                    # SDK-specific strings
                    if any(x in s_lower for x in [
                        'halflife', 'half-life', 'valve',
                    ]):
                        has_sdk_strings = True

                if has_rewolf_strings:
                    category = 'REWOLF_AUTO'
                elif has_sdk_strings:
                    category = 'SDK_AUTO'
                else:
                    category = 'UNCLASSIFIED'

                results[dll_name][addr] = {
                    'name': name,
                    'category': category,
                    'size': func['size'],
                    'detail': f"{len(strings)} string refs",
                }
            else:
                category, detail = classify_named_function(
                    name, sdk_entities, sdk_functions, sdk_classes
                )
                results[dll_name][addr] = {
                    'name': name,
                    'category': category,
                    'size': func['size'],
                    'detail': detail,
                }

            categories[dll_name][results[dll_name][addr]['category']] += 1
            category_funcs[dll_name][results[dll_name][addr]['category']].append(
                (name, func['size'], addr)
            )

    # Step 5: Output results
    print("\n" + "=" * 90)
    print("CLASSIFICATION RESULTS")
    print("=" * 90)

    for dll_name in ['server', 'client']:
        total = sum(categories[dll_name].values())
        sdk_count = sum(v for k, v in categories[dll_name].items() if k.startswith('SDK'))
        rewolf_count = sum(v for k, v in categories[dll_name].items() if k.startswith('REWOLF'))
        ambiguous = categories[dll_name].get('AMBIGUOUS_CALLBACK', 0)
        unknown = categories[dll_name].get('UNKNOWN', 0)
        unclassified = categories[dll_name].get('UNCLASSIFIED', 0)

        # Calculate code sizes
        sdk_size = sum(f[1] for cat, funcs in category_funcs[dll_name].items()
                      if cat.startswith('SDK') for f in funcs)
        rewolf_size = sum(f[1] for cat, funcs in category_funcs[dll_name].items()
                        if cat.startswith('REWOLF') for f in funcs)
        other_size = sum(f[1] for cat, funcs in category_funcs[dll_name].items()
                        if not cat.startswith('SDK') and not cat.startswith('REWOLF') for f in funcs)

        print(f"\n{'-' * 60}")
        dll_file = 'gunman.dll' if dll_name == 'server' else 'client.dll'
        print(f"  {dll_file}")
        print(f"{'-' * 60}")
        print(f"  Total functions: {total}")
        print(f"  SDK-matching:    {sdk_count:4d} ({sdk_count*100//total}%)  [{sdk_size:,} bytes]")
        print(f"  Rewolf custom:   {rewolf_count:4d} ({rewolf_count*100//total}%)  [{rewolf_size:,} bytes]")
        print(f"  Ambiguous:       {ambiguous:4d} ({ambiguous*100//total}%)")
        print(f"  Unknown named:   {unknown:4d} ({unknown*100//total}%)")
        print(f"  Unclassified:    {unclassified:4d} ({unclassified*100//total}%)")
        print()

        for cat in sorted(categories[dll_name].keys()):
            count = categories[dll_name][cat]
            print(f"  {cat:30s}: {count:4d}")

    # Write detailed classification to file
    out_path = os.path.join(DISASM_PATH, "classification.txt")
    with open(out_path, 'w') as f:
        for dll_name in ['server', 'client']:
            dll_file = 'gunman.dll' if dll_name == 'server' else 'client.dll'
            f.write(f"{'=' * 90}\n")
            f.write(f"  {dll_file} CLASSIFICATION\n")
            f.write(f"{'=' * 90}\n\n")

            for cat in sorted(category_funcs[dll_name].keys()):
                funcs = category_funcs[dll_name][cat]
                f.write(f"\n--- {cat} ({len(funcs)} functions) ---\n")
                for name, size, addr in sorted(funcs, key=lambda x: x[2]):
                    f.write(f"  {addr} | {size:6d} | {name}\n")

    print(f"\nDetailed classification written to: {out_path}")

    # Write Rewolf-only functions for focused RE work
    rewolf_path = os.path.join(DISASM_PATH, "rewolf_custom_functions.txt")
    with open(rewolf_path, 'w') as f:
        f.write("# Rewolf Custom Functions - These need full reverse engineering\n")
        f.write("# These are NOT in the Half-Life SDK and represent Gunman-specific code\n\n")
        for dll_name in ['server', 'client']:
            dll_file = 'gunman.dll' if dll_name == 'server' else 'client.dll'
            f.write(f"\n{'=' * 70}\n")
            f.write(f"  {dll_file}\n")
            f.write(f"{'=' * 70}\n\n")

            rewolf_funcs = []
            for cat, funcs in category_funcs[dll_name].items():
                if cat.startswith('REWOLF'):
                    rewolf_funcs.extend(funcs)

            rewolf_funcs.sort(key=lambda x: x[2])
            total_size = sum(f[1] for f in rewolf_funcs)
            f.write(f"  Total: {len(rewolf_funcs)} functions, {total_size:,} bytes\n\n")

            for name, size, addr in rewolf_funcs:
                f.write(f"  {addr} | {size:6d} | {name}\n")

    print(f"Rewolf custom functions written to: {rewolf_path}")

    # Write SDK-matching functions
    sdk_path_out = os.path.join(DISASM_PATH, "sdk_matching_functions.txt")
    with open(sdk_path_out, 'w') as f:
        f.write("# SDK-Matching Functions - These can be rebuilt from Half-Life SDK 2.3 source\n\n")
        for dll_name in ['server', 'client']:
            dll_file = 'gunman.dll' if dll_name == 'server' else 'client.dll'
            f.write(f"\n{'=' * 70}\n")
            f.write(f"  {dll_file}\n")
            f.write(f"{'=' * 70}\n\n")

            sdk_funcs = []
            for cat, funcs in category_funcs[dll_name].items():
                if cat.startswith('SDK'):
                    sdk_funcs.extend([(name, size, addr, cat) for name, size, addr in funcs])

            sdk_funcs.sort(key=lambda x: x[2])
            total_size = sum(f[1] for f in sdk_funcs)
            f.write(f"  Total: {len(sdk_funcs)} functions, {total_size:,} bytes\n\n")

            for name, size, addr, cat in sdk_funcs:
                f.write(f"  {addr} | {size:6d} | {cat:30s} | {name}\n")

    print(f"SDK-matching functions written to: {sdk_path_out}")


if __name__ == '__main__':
    main()

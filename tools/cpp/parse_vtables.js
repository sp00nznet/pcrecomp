#!/usr/bin/env node
// Parse bw1-decomp's rdata.100-vftables.asm into JSON for the Ghidra VtableMatcher script
// Input:  vendor/bw1-decomp/src/asm/unprocessed/rdata.100-vftables.asm
// Output: work/vtable_data.json

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const ASM_PATH = path.join(ROOT, 'vendor/bw1-decomp/src/asm/unprocessed/rdata.100-vftables.asm');
const OUT_PATH = path.join(ROOT, 'work/vtable_data.json');

const lines = fs.readFileSync(ASM_PATH, 'utf8').split('\n');

// Output: simple line-based text format (no JSON parsing needed in Ghidra)
// Format:
//   VTABLE ClassName entryCount
//   mangledName1
//   mangledName2
//   ...
const TXT_PATH = path.join(ROOT, 'work/vtable_data.txt');

const vtables = {};       // className -> [mangled_name, ...]
let currentClass = null;

for (const rawLine of lines) {
    const line = rawLine.trim();

    // New vtable: VftableAndRTTI ClassName   // [offset] base + offset = abs_addr
    const vtMatch = line.match(/^VftableAndRTTI\s+(\S+)/);
    if (vtMatch) {
        currentClass = vtMatch[1];
        vtables[currentClass] = [];
        continue;
    }

    // Function pointer entry: .long ?MangledName@... or .long _OldStyleName__...
    if (currentClass && line.startsWith('.long ')) {
        const symbol = line.substring(6).trim();
        // Filter: must start with ? (MSVC mangled) or _ (old-style mangled)
        if (symbol.startsWith('?') || symbol.startsWith('_')) {
            // Strip any trailing comment
            const cleanSymbol = symbol.split(/\s+\/\//)[0].trim();
            vtables[currentClass].push(cleanSymbol);
        }
        continue;
    }
}

// Compute stats
let totalEntries = 0;
const uniqueFuncs = new Set();
for (const [cls, entries] of Object.entries(vtables)) {
    totalEntries += entries.length;
    for (const e of entries) uniqueFuncs.add(e);
}

console.log(`Parsed ${Object.keys(vtables).length} vtable definitions`);
console.log(`Total vtable entries: ${totalEntries}`);
console.log(`Unique function symbols: ${uniqueFuncs.size}`);

// Write simple line-based text format
const lines2 = [];
for (const [cls, entries] of Object.entries(vtables)) {
    lines2.push(`VTABLE ${cls} ${entries.length}`);
    for (const e of entries) {
        lines2.push(e);
    }
}
fs.writeFileSync(TXT_PATH, lines2.join('\n') + '\n');
console.log(`Written to: ${TXT_PATH}`);

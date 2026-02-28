#!/bin/bash
# Extract all files from InstallShield CAB by index
# Skips files that can't be extracted (read-only conflicts, etc.)

I6COMP="/c/Windows/SysWOW64/UniExtract/bin/i6comp"
CAB_PATH="$1"
OUT_DIR="$2"

if [ -z "$CAB_PATH" ] || [ -z "$OUT_DIR" ]; then
    echo "Usage: $0 <cab_path> <output_dir>"
    exit 1
fi

mkdir -p "$OUT_DIR"
cd "$OUT_DIR" || exit 1
chmod -R +w . 2>/dev/null

SUCCESS=0
FAIL=0

for i in $(seq 0 1027); do
    # Make any existing files writable
    chmod -R +w . 2>/dev/null
    OUTPUT=$("$I6COMP" e "$CAB_PATH" "$i" 2>&1)
    FNAME=$(echo "$OUTPUT" | grep -v "^─\|InstallShield\|Version\|fOSSiL\|Morlac\|DarkSoul\|General\|Could not\|not stored\|Check in\|^$" | head -1)
    if [ -n "$FNAME" ] && [ "$FNAME" != "" ]; then
        SUCCESS=$((SUCCESS + 1))
    else
        FAIL=$((FAIL + 1))
    fi
    # Progress every 100 files
    if [ $((i % 100)) -eq 0 ]; then
        echo "Progress: index $i, extracted $SUCCESS, skipped $FAIL"
    fi
done

echo "Done! Extracted $SUCCESS files, skipped $FAIL"

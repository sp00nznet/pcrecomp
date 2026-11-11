#!/bin/bash
# Xbox 360 (libxenon, for XeLL on RGH/JTAG): no SDL2, so the lite game runs on
# sdl2lite (src/sdl2lite: a software SDL2 slice) with its libxenon backend.
#   image: free60/libxenon      out: build-xenon/skifree.elf32
set -e
DEVKITXENON="${DEVKITXENON:-/usr/local/xenon}"
. "$(dirname "$0")/env.sh"   # SkiFree's; here as recipes/env.skifree.sh
OUT="${1:-$ROOT/build-xenon}"
mkdir -p "$OUT/obj" && cd "$OUT/obj"
CC="$DEVKITXENON/bin/xenon-gcc"
MACHDEP="-DXENON -m32 -maltivec -fno-pic -mpowerpc64 -mhard-float"
CFLAGS="$MACHDEP -O2 -I$ROOT/src/sdl2lite -I$DEVKITXENON/usr/include -w"
# the load addresses libxenon's own test scripts use
sed -e 's|0x80000000|0x82000000|' -e 's|0x9E000000|0xA0000000|' -e 's|0xa0000000|0xA2000000|' "$DEVKITXENON/app.lds" > xenon.lds
LDFLAGS="$MACHDEP -L$DEVKITXENON/xenon/lib/32 -L$DEVKITXENON/usr/lib -T xenon.lds"
LIBS="sdl2lite.o backend_xenon.o -lxenon -lm -lc -lgcc"
for s in sdl2lite backend_xenon; do echo "  cc  src/sdl2lite/$s.c"; $CC $CFLAGS -c "$ROOT/src/sdl2lite/$s.c" -o $s.o; done
lite_build skifree.elf
"$DEVKITXENON/bin/xenon-objcopy" -O elf32-powerpc skifree.elf ../skifree.elf32
"$DEVKITXENON/bin/xenon-strip" ../skifree.elf32
ls -lh ../skifree.elf32

#!/bin/bash
# PS3: PSL1GHT, no SDL2, so the lite game runs on sdl2lite (src/sdl2lite: a
# software SDL2 slice) with its PSL1GHT backend. The display's size (720p).
#   image: ps3dev/ps3dev:submodules      out: build-ps3/EBOOT.BIN (fake-signed self: RPCS3, CFW)
set -e
export PS3DEV=/usr/local/ps3dev PSL1GHT=/usr/local/ps3dev
export PATH=$PS3DEV/bin:$PS3DEV/ppu/bin:$PATH
. "$(dirname "$0")/env.sh"   # SkiFree's; here as recipes/env.skifree.sh
OUT="${1:-$ROOT/build-ps3}"
mkdir -p "$OUT/obj" && cd "$OUT/obj"
CC=powerpc64-ps3-elf-gcc
MACHDEP="-mcpu=cell -mhard-float -fmodulo-sched -ffunction-sections -fdata-sections"
CFLAGS="$MACHDEP -O2 -I$ROOT/src/sdl2lite -I$PSL1GHT/ppu/include -w"
LDFLAGS="$MACHDEP -Wl,--gc-sections -L$PSL1GHT/ppu/lib"
LIBS="sdl2lite.o backend_ps3.o -lrsx -lgcm_sys -lio -lsysutil -laudio -lrt -llv2 -lm"
for s in sdl2lite backend_ps3; do echo "  cc  src/sdl2lite/$s.c"; $CC $CFLAGS -c "$ROOT/src/sdl2lite/$s.c" -o $s.o; done
lite_build skifree.elf
powerpc64-ps3-elf-strip skifree.elf -o skifree.stripped.elf
sprxlinker skifree.stripped.elf
fself.py skifree.stripped.elf ../EBOOT.BIN
ls -lh ../EBOOT.BIN

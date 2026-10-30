#!/bin/bash
# Dreamcast: KallistiOS, no SDL2, so the lite game runs on sdl2lite
# (src/sdl2lite: a software SDL2 slice) with its KOS backend. 640x480 RGB565.
#   image: kazade/dreamcast-sdk      out: build-dreamcast/skifree.elf (+ skifree.cdi)
set -e
source "${KOS_ENVIRON:-/opt/toolchains/dc/kos/environ.sh}"
. "$(dirname "$0")/env.sh"   # SkiFree's; here as recipes/env.skifree.sh
OUT="${1:-$ROOT/build-dreamcast}"
mkdir -p "$OUT/obj" && cd "$OUT/obj"
CC=kos-cc
# KOS has its own net_init/net_shutdown: rename the game's (stubs in the lite build)
CFLAGS="-O2 -I$ROOT/src/sdl2lite -Dnet_init=skifree_net_init -Dnet_shutdown=skifree_net_shutdown -w"
LDFLAGS=""
LIBS="sdl2lite.o backend_dreamcast.o -lm"
for s in sdl2lite backend_dreamcast; do echo "  cc  src/sdl2lite/$s.c"; $CC $CFLAGS -c "$ROOT/src/sdl2lite/$s.c" -o $s.o; done
lite_build skifree_dbg.elf
sh-elf-strip skifree_dbg.elf -o ../skifree.elf
# a self-booting CD image, for Flycast or a burned CD-R / ODE
if command -v mkdcdisc >/dev/null; then rm -f ../skifree.cdi; mkdcdisc -q -N -e ../skifree.elf -o ../skifree.cdi -n SkiFree -a sp00nznet; fi
ls -lh ../skifree.elf ../skifree.cdi 2>/dev/null || true

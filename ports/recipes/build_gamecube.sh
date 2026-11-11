#!/bin/bash
# GameCube: SDL2 from devkitPro portlibs (libogc). Fullscreen at the TV mode (640x480).
#   image: devkitpro/devkitppc      out: build-gamecube/skifree.dol
set -e
. "$(dirname "$0")/env.sh"   # SkiFree's; here as recipes/env.skifree.sh
OUT="${1:-$ROOT/build-gamecube}"
mkdir -p "$OUT/obj" && cd "$OUT/obj"
DKP=/opt/devkitpro
PKG="$DKP/portlibs/gamecube/bin/powerpc-eabi-pkg-config"
CC="$DKP/devkitPPC/bin/powerpc-eabi-gcc"
MACHDEP="-DGEKKO -mogc -mcpu=750 -meabi -mhard-float"
# libogc has its own net_init/net_connect/net_shutdown: rename the game's stubs.
CFLAGS="$MACHDEP -O2 -Dnet_init=sf_net_init -Dnet_connect=sf_net_connect -Dnet_shutdown=sf_net_shutdown -I$DKP/libogc/include $($PKG --cflags sdl2) -w"
LDFLAGS="$MACHDEP"
LIBS="$($PKG --libs sdl2)"
LITE_SRC="$LITE_SRC src/lite/platform_ogc.c"   # stdout to the debug UART (Dolphin log)
lite_build skifree.elf
"$DKP/tools/bin/elf2dol" skifree.elf ../skifree.dol
ls -lh ../skifree.dol

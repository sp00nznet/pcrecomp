#!/bin/bash
# PS2: SDL2 from the ps2dev ports (gsKit renderer, ps2_drivers loads the IOP
# modules for pads and audio). Fullscreen at the TV mode (640x448 NTSC).
#   image: ps2dev/ps2dev (apk add bash first)      out: build-ps2/skifree.elf
set -e
. "$(dirname "$0")/env.sh"   # SkiFree's; here as recipes/env.skifree.sh
OUT="${1:-$ROOT/build-ps2}"
mkdir -p "$OUT/obj" && cd "$OUT/obj"
: "${PS2DEV:=/usr/local/ps2dev}" "${PS2SDK:=$PS2DEV/ps2sdk}"
CC=mips64r5900el-ps2-elf-gcc
CFLAGS="-D_EE -DPS2 -D__PS2__ -G0 -O2 -I$PS2SDK/ee/include -I$PS2SDK/common/include $(PKG_CONFIG_PATH=$PS2SDK/ports/lib/pkgconfig pkg-config --cflags sdl2 2>/dev/null || $PS2SDK/ports/bin/sdl2-config --cflags) -w"
LDFLAGS="-T$PS2SDK/ee/startup/linkfile -L$PS2SDK/ee/lib -L$PS2SDK/ports/lib -L$PS2DEV/gsKit/lib -Wl,-zmax-page-size=128"
# SDL2main supplies main() (it calls the game's SDL_main).
LIBS="-lSDL2main -lSDL2 -lm -lpatches -lgskit -ldmakit -lps2_drivers"
lite_build skifree.elf
mips64r5900el-ps2-elf-strip skifree.elf -o ../skifree.elf
ls -lh ../skifree.elf

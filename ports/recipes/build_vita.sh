#!/bin/bash
# PS Vita: SDL2 from VitaSDK. 960x544.
#   image: vitasdk/vitasdk      out: build-vita/skifree.vpk
set -e
. "$(dirname "$0")/env.sh"   # SkiFree's; here as recipes/env.skifree.sh
OUT="${1:-$ROOT/build-vita}"
LITE_SRC="$LITE_SRC src/lite/vita_hints.c"
mkdir -p "$OUT/obj" && cd "$OUT/obj"
CC=arm-vita-eabi-gcc
CFLAGS="-O2 -ffunction-sections $(arm-vita-eabi-pkg-config --cflags sdl2) -w"
LDFLAGS="-Wl,-q -Wl,--gc-sections"
LIBS="$(arm-vita-eabi-pkg-config --libs sdl2) -lSceShaccCgExt -ltaihen_stub -lstdc++ -lpthread"
lite_build skifree.elf
vita-elf-create skifree.elf skifree.velf
vita-make-fself -s skifree.velf eboot.bin
vita-mksfoex -s TITLE_ID=SKIF00001 "SkiFree" param.sfo
vita-pack-vpk -s param.sfo -b eboot.bin ../skifree.vpk
ls -lh ../skifree.vpk

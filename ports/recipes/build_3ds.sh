#!/bin/bash
# Nintendo 3DS: SDL2 built from source (devkitPro ships no 3ds-sdl2), on the
# 400x240 top screen.
#   image: devkitpro/devkitarm      out: build-3ds/skifree.3dsx
set -e
. "$(dirname "$0")/env.sh"   # SkiFree's; here as recipes/env.skifree.sh
OUT="${1:-$ROOT/build-3ds}"
export DEVKITPRO=/opt/devkitpro DEVKITARM=/opt/devkitpro/devkitARM
export PATH="$DEVKITARM/bin:$DEVKITPRO/tools/bin:$PATH"
mkdir -p "$OUT/obj" && cd "$OUT/obj"

# SDL2 for 3DS, built once and kept in $OUT/obj/sdl2.
SDLV=2.32.10
SDL="$OUT/obj/sdl2"
if [ ! -f "$SDL/lib/libSDL2.a" ]; then
    [ -d SDL2-$SDLV ] || curl -sL https://github.com/libsdl-org/SDL/releases/download/release-$SDLV/SDL2-$SDLV.tar.gz | tar xz
    cmake -S SDL2-$SDLV -B sdl2-build -DCMAKE_TOOLCHAIN_FILE=$DEVKITPRO/cmake/3DS.cmake \
          -DCMAKE_BUILD_TYPE=Release -DSDL_SHARED=OFF -DSDL_STATIC=ON -DSDL_TEST=OFF \
          -DCMAKE_INSTALL_PREFIX="$SDL" >/dev/null
    cmake --build sdl2-build -j"$(nproc)" >/dev/null
    cmake --install sdl2-build >/dev/null
fi

ARCH="-march=armv6k -mtune=mpcore -mfloat-abi=hard -mtp=soft"
CC=arm-none-eabi-gcc
CFLAGS="$ARCH -O2 -mword-relocations -ffunction-sections -D__3DS__ -I$SDL/include -I$SDL/include/SDL2 -I$DEVKITPRO/libctru/include -w"
LDFLAGS="-specs=3dsx.specs $ARCH -Wl,--gc-sections"
LIBS="-L$SDL/lib -lSDL2main -lSDL2 -L$DEVKITPRO/libctru/lib -lcitro3d -lctru -lm"
lite_build skifree.elf
smdhtool --create "SkiFree" "Ski, dodge trees, flee the Yeti" "Chris Pirih (1991); recomp" \
    $DEVKITPRO/libctru/default_icon.png skifree.smdh
3dsxtool skifree.elf ../skifree.3dsx --smdh=skifree.smdh
ls -lh ../skifree.3dsx

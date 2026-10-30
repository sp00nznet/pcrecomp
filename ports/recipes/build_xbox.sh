#!/bin/bash
# Original Xbox: SDL2 from nxdk. Fullscreen at 640x480.
#   image: ghcr.io/xboxdev/nxdk (apk add bash first)      out: build-xbox/skifree.xbe, build-xbox/skifree.iso
# nxdk's Makefile writes each .obj beside its .c, so the lite sources are copied
# into $OUT/obj first (keeps src/ clean; the list stays env.sh's LITE_SRC).
set -e
. "$(dirname "$0")/env.sh"   # SkiFree's; here as recipes/env.skifree.sh
OUT="${1:-$ROOT/build-xbox}"
mkdir -p "$OUT/obj" && cd "$OUT/obj"
: "${NXDK_DIR:=/usr/src/nxdk}"
export PATH="$NXDK_DIR/bin:$PATH"
SRCS=""
for s in $LITE_SRC src/lite/xbox_main.c; do
    mkdir -p "$(dirname "$s")" && cp "$ROOT/$s" "$s"
    SRCS="$SRCS $PWD/$s"
done
# LITE_INC goes in CC so it comes before nxdk's own -I paths, which hold a real
# SDL_ttf.h and an unrelated config.h. SCREEN_WIDTH/HEIGHT clash with nxdk's hal.
make -f "$NXDK_DIR/Makefile" -j"$(nproc)" NXDK_DIR="$NXDK_DIR" NXDK_SDL=y \
    XBE_TITLE=SkiFree GEN_XISO=skifree.iso OUTPUT_DIR=bin SRCS="$SRCS" \
    CC="nxdk-cc $LITE_INC" \
    CFLAGS="-O2 -include $ROOT/src/lite/xbox_compat.h -DSCREEN_WIDTH=sf_SCREEN_WIDTH -DSCREEN_HEIGHT=sf_SCREEN_HEIGHT -w"
cp bin/default.xbe ../skifree.xbe
cp skifree.iso ../skifree.iso
ls -lh ../skifree.xbe ../skifree.iso

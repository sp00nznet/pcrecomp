#!/bin/sh
# Build and run every win32hle selftest under gcc -m32, each linked with the
# whole layer. Needs gcc-multilib and SDL2 + SDL2_ttf for i386 (README).
set -u
cd "$(dirname "$0")"
CORE=$(ls *.c | grep -v _selftest.c)
LIBS=$(PKG_CONFIG_PATH=/usr/lib/i386-linux-gnu/pkgconfig pkg-config --cflags --libs sdl2 SDL2_ttf)
TMP=${TMPDIR:-/tmp}
fail=0
for t in *_selftest.c; do
  exe=$TMP/${t%.c}
  # shellcheck disable=SC2086  # CORE and LIBS are lists
  if gcc -m32 -O1 -Wall -Wno-unused-function -Wno-unused-but-set-variable -I../recomp32 -I. $CORE "$t" $LIBS -lpthread -lm -o "$exe"; then
    if SDL_VIDEODRIVER=dummy SDL_AUDIODRIVER=dummy "$exe" > "$exe.out" 2>&1; then echo "ok    $t"; else echo "FAIL  $t"; tail -5 "$exe.out"; fail=1; fi
  else
    echo "BUILD FAIL  $t"; fail=1
  fi
done
exit $fail

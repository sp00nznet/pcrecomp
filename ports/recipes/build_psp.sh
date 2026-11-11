#!/bin/bash
# PSP: SDL2 from pspdev. 480x272.
#   image: pspdev/pspdev      out: build-psp/EBOOT.PBP
set -e
. "$(dirname "$0")/env.sh"   # SkiFree's; here as recipes/env.skifree.sh
OUT="${1:-$ROOT/build-psp}"
mkdir -p "$OUT/obj" && cd "$OUT/obj"
CC=psp-gcc
CFLAGS="-O2 -G0 -D_PSP_FW_VERSION=600 $(psp-pkg-config --cflags sdl2) -w"
LDFLAGS="-L$(psp-config --pspsdk-path)/lib -Wl,-zmax-page-size=128"
LIBS="$(psp-pkg-config --libs sdl2) -lpspdebug -lpspdisplay -lpspge -lpspctrl -lpspnet -lpspnet_apctl -lpsputility -lpsprtc -lpsppower"
lite_build skifree.elf
psp-fixup-imports skifree.elf
psp-strip skifree.elf -o skifree_strip.elf
mksfoex -d MEMSIZE=1 "SkiFree" PARAM.SFO
pack-pbp ../EBOOT.PBP PARAM.SFO NULL NULL NULL NULL NULL skifree_strip.elf NULL
ls -lh ../EBOOT.PBP

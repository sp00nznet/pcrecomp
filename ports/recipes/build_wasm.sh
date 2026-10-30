#!/bin/bash
# The browser: WebAssembly with Emscripten's SDL2 port. ASYNCIFY lets the
# game keep its own main loop (SDL_Delay yields to the browser).
#   image: emscripten/emsdk      out: build-wasm/skifree.html (+ .js, .wasm)
set -e
. "$(dirname "$0")/env.sh"   # SkiFree's; here as recipes/env.skifree.sh
OUT="${1:-$ROOT/build-wasm}"
mkdir -p "$OUT/obj" && cd "$OUT/obj"
CC=emcc
CFLAGS="-O2 -sUSE_SDL=2 -w"
LDFLAGS="-O2 -sUSE_SDL=2 -sASYNCIFY -sALLOW_MEMORY_GROWTH -sINITIAL_MEMORY=64MB"
LIBS=""
lite_build ../skifree.html
ls -lh ../skifree.html ../skifree.js ../skifree.wasm

# Sourced by every scripts/build_<console>.sh: where things are, and the lite
# build (SKIFREE_LITE: SDL2 alone, no menus, no network game, an 8x8 font).
#
#   lite_build OUT.elf   compiles and links with $CC $CFLAGS $LDFLAGS $LIBS
#
# The build scripts run inside the console's toolchain image with this repo
# at /src, or anywhere else the toolchain is installed.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
GEN="$ROOT/build-gen"   # embedded_resources.h, from scripts/prep.sh

if [ ! -f "$GEN/embedded_resources.h" ]; then
    echo "$GEN/embedded_resources.h is missing: run scripts/prep.sh first (setup-consoles does)." >&2
    exit 1
fi

LITE_SRC="src/skifree.c src/resources.c src/config.c src/sound.c src/ai.c src/physics.c src/replay.c
          src/win32_menu.c src/win32_dialogs.c src/saveload.c src/input_bind.c src/lite/lite_stubs.c
          third_party/cjson/cJSON.c"
LITE_INC="-DSKIFREE_LITE -I$ROOT/src/lite -I$ROOT/src -I$ROOT/third_party/cjson -I$GEN"

lite_build() {
    local out="$1" objs=() s o
    for s in $LITE_SRC; do
        o="$(basename "${s%.c}").o"
        echo "  cc  $s"
        $CC $LITE_INC $CFLAGS -c "$ROOT/$s" -o "$o" || return 1
        objs+=("$o")
    done
    echo "  ld  $out"
    $CC $LDFLAGS "${objs[@]}" $LIBS -o "$out"
}

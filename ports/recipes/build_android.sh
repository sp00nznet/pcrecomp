#!/bin/bash
# Android: the lite game on SDL2, as an APK for x86_64 (the emulator) and
# arm64-v8a (phones). Landscape, fullscreen; touch steers (SDL turns touch into
# the mouse), a tap jumps, and a game controller works too.
#   image: skifree-android (docker/skifree-android.Dockerfile)   out: build-android/skifree.apk
#
# SDL2 isn't vendored: this stages the image's SDL2 source ($SDL2_SRC) into
# android/ (gitignored) and runs Gradle. Anywhere else, set ANDROID_HOME and
# SDL2_SRC yourself.
set -e
. "$(dirname "$0")/env.sh"   # SkiFree's; here as recipes/env.skifree.sh
OUT="${1:-$ROOT/build-android}"
: "${ANDROID_HOME:?set ANDROID_HOME to the Android SDK}"
: "${SDL2_SRC:?set SDL2_SRC to an SDL2 2.32.x source tree}"
P="$ROOT/android"
mkdir -p "$OUT"

echo '[1/3] Staging SDL2 source'
rm -rf "$P/app/jni/SDL"
mkdir -p "$P/app/jni/SDL" "$P/app/src/main/java"
cp -r "$SDL2_SRC"/. "$P/app/jni/SDL/"
rm -rf "$P/app/jni/SDL/android-project"
cp -r "$SDL2_SRC/android-project/app/src/main/java/." "$P/app/src/main/java/"
# ponytail: SDL's stock launcher icon (gitignored); track SkiFree mipmaps in res/ and drop this line to replace it
cp -r "$SDL2_SRC"/android-project/app/src/main/res/mipmap-* "$P/app/src/main/res/"
echo "sdk.dir=$ANDROID_HOME" > "$P/local.properties"

echo '[2/3] gradle assembleDebug'
export SKIFREE_LITE_SRC="$LITE_SRC"   # read by android/app/jni/CMakeLists.txt
# Gradle's own cache goes under OUT, so a rerun doesn't download it again.
GRADLE_USER_HOME="$OUT/.gradle" bash "$P/gradlew" -p "$P" assembleDebug --console=plain

cp "$P/app/build/outputs/apk/debug/app-debug.apk" "$OUT/skifree.apk"
echo "[3/3] APK: $OUT/skifree.apk"
ls -lh "$OUT/skifree.apk"

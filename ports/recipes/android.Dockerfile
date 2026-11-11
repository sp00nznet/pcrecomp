# The Android toolchain this repo's Gradle project expects, in one image:
# SDK 34, NDK 27.2, CMake 3.22.1 and the SDL2 2.32.10 source that
# scripts/build_android.sh stages into android/. Built locally on first use
# (setup.sh / tools/setup.ps1); Docker caches it after that.
FROM ghcr.io/cirruslabs/android-sdk:34
RUN yes | sdkmanager --licenses >/dev/null && \
    sdkmanager "ndk;27.2.12479018" "cmake;3.22.1" "build-tools;34.0.0" "platforms;android-34" >/dev/null
RUN curl -fsSL https://github.com/libsdl-org/SDL/releases/download/release-2.32.10/SDL2-2.32.10.tar.gz \
      | tar -xz -C /opt
ENV SDL2_SRC=/opt/SDL2-2.32.10

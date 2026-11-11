#!/bin/bash
# PS4: SDL2 from OpenOrbis. Fullscreen at the video-out size (1920x1080).
#   image: openorbisofficial/toolchain      out: build-ps4/skifree.pkg
# Homebrew pkg (fake-signed eboot): installs on a jailbroken PS4 only.
set -e
. "$(dirname "$0")/env.sh"   # SkiFree's; here as recipes/env.skifree.sh
OUT="${1:-$ROOT/build-ps4}"
mkdir -p "$OUT/obj" && cd "$OUT/obj"
TC="${OO_PS4_TOOLCHAIN:-/lib/OpenOrbisSDK}"
# Compile with clang, link with ld.lld itself (clang's FreeBSD driver would add
# a host -L/usr/lib and a dynamic linker the PS4 doesn't have).
ps4cc() { case " $* " in *" -c "*) clang "$@" ;; *) ld.lld "$@" "$TC/lib/crt1.o" ;; esac; }
CC=ps4cc
CFLAGS="--target=x86_64-pc-freebsd12-elf -fPIC -funwind-tables -O2 -isysroot $TC -isystem $TC/include -isystem $TC/include/SDL2 -Wno-everything"
LDFLAGS="-m elf_x86_64 -pie --script $TC/link.x --eh-frame-hdr -L$TC/lib"
# libkernel before libc: its sem_* are the real ones (libc.a has musl futex versions)
LIBS="-lSDL2 -lkernel -lc -lSceUserService -lSceVideoOut -lSceAudioOut -lScePad -lSceSysmodule"
lite_build skifree.elf

# eboot.bin, then the .pkg (same steps as linksawakening's package_ps4.sh)
TITLE_ID=SKIF00001
CONTENT_ID="IV0000-${TITLE_ID}_00-SKIFREE000000000"
PKGTOOL="$TC/bin/linux/PkgTool.Core"
export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1   # PkgTool's .NET has no ICU
rm -rf pkg && mkdir -p pkg/sce_sys/about pkg/sce_module && cd pkg
"$TC/bin/linux/create-eboot" -in ../skifree.elf -out ../skifree.oelf -paid 0x3800000000000011   # writes ./eboot.bin
sfo() { "$PKGTOOL" sfo_setentry sce_sys/param.sfo "$1" --type "$2" --maxsize "$3" --value "$4"; }
"$PKGTOOL" sfo_new sce_sys/param.sfo
sfo APP_TYPE Integer 4 1;           sfo APP_VER Utf8 8 1.00
sfo ATTRIBUTE Integer 4 0;          sfo CATEGORY Utf8 4 gd
sfo CONTENT_ID Utf8 48 "$CONTENT_ID"; sfo DOWNLOAD_DATA_SIZE Integer 4 0
sfo SYSTEM_VER Integer 4 0;         sfo TITLE Utf8 128 SkiFree
sfo TITLE_ID Utf8 12 "$TITLE_ID";   sfo VERSION Utf8 8 1.00
# ponytail: OpenOrbis's sample icon; swap in SkiFree art when there is some
cp "$TC/bin/data/icon0.png" sce_sys/icon0.png
cp "$TC/bin/data/right.sprx" sce_sys/about/right.sprx
cp "$TC/bin/data/modules/libc.prx" "$TC/bin/data/modules/libSceFios2.prx" sce_module/
FILES="eboot.bin sce_sys/param.sfo sce_sys/icon0.png sce_sys/about/right.sprx sce_module/libc.prx sce_module/libSceFios2.prx"
{
    echo '<?xml version="1.0"?>'
    echo '<psproject fmt="gp4" version="1000">'
    echo '  <volume>'
    echo '    <volume_type>pkg_ps4_app</volume_type>'
    echo '    <volume_id>PS4VOLUME</volume_id>'
    echo "    <volume_ts>$(date -u '+%Y-%m-%d %H:%M:%S')</volume_ts>"
    echo "    <package content_id=\"$CONTENT_ID\" passcode=\"00000000000000000000000000000000\" storage_type=\"digital50\" app_type=\"full\" />"
    echo '    <chunk_info chunk_count="1" scenario_count="1">'
    echo '      <chunks><chunk id="0" layer_no="0" label="Chunk #0" /></chunks>'
    echo '      <scenarios default_id="0"><scenario id="0" type="sp" initial_chunk_count="1" label="Scenario #0">0</scenario></scenarios>'
    echo '    </chunk_info>'
    echo '  </volume>'
    echo '  <files img_no="0">'
    for f in $FILES; do echo "    <file targ_path=\"$f\" orig_path=\"$f\" />"; done
    echo '  </files>'
    echo '  <rootdir><dir targ_name="sce_sys"><dir targ_name="about" /></dir><dir targ_name="sce_module" /></rootdir>'
    echo '</psproject>'
} > pkg.gp4
"$PKGTOOL" pkg_build pkg.gp4 .
mv "$CONTENT_ID.pkg" ../../skifree.pkg
ls -lh ../../skifree.pkg

#!/bin/sh
# tools/envscrub_check.sh GUEST_ROOT CMD_EXE: a lifted NT cmd.exe's `set` shows the guest's
# environment (syscall32.c), not the host's: a fake host secret must not reach it, while
# PCRECOMP_GUEST_SET entries and the guest identity do. Run from the guest repo's root
# (the lifted cmd finds its loader directory relative to it), e.g.
#   cd G:/recomp/pc/win2000 && sh ../pcrecomp/tools/envscrub_check.sh . build/cmd.exe
cd "$1" || exit 1
B=work/envtest; rm -rf $B; mkdir -p $B/C
export MSYS_NO_PATHCONV=1 PCRECOMP_MUTE=1 PCRECOMP_FILEBOX="$(cygpath -w "$PWD/$B")"
export PCRECOMP_LEAKTEST=xyz_fake_secret PCRECOMP_GUEST_SET='GOODVAR=ok;OTHER=two'
L=$(timeout 30 "$2" --mute -- /c set 2>/dev/null | tr -d '\r')
fail=0; ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; fail=1; }
[ -n "$L" ] && ok "set printed $(echo "$L" | wc -l) entries" || bad "set printed nothing"
echo "$L" | grep -q 'LEAKTEST\|xyz_fake_secret' && bad "host variable reached the guest" || ok "host variable not in the guest"
echo "$L" | grep -qx 'GOODVAR=ok' && echo "$L" | grep -qx 'OTHER=two' && ok "PCRECOMP_GUEST_SET passed" || bad "PCRECOMP_GUEST_SET missing"
echo "$L" | grep -qx 'USERNAME=User' && ok "USERNAME=User" || bad "USERNAME not User"
echo "$L" | grep -qi '^PCRECOMP_\|^NATIVE32_' && bad "runner variable in the guest" || ok "no runner variables"
rm -rf $B
exit $fail

#!/bin/bash
# Build a title for every console in its ports/targets.tsv, inside Docker:
# nothing but Docker is installed on the machine. Run it from the title's repo:
#
#   ../tools/ports/setup-consoles.sh [--yes] [--game-dir <folder>] [--targets wii,psp]
#
# The title's ports/ports.conf (sourced) names it and its prep step:
#   TITLE="Theme Park"
#   PREP_IMAGE=alpine:3.20                  # where the prep runs
#   PREP_CMD="apk add -q bash python3 && bash ports/prep.sh"
#   PREP_DONE=build-gen/.done               # skip the prep when this exists
#   GAME_HINT="the folder with your GOG install"
# The prep sees the game at /game (read-only) and the repo at /src.
#
# ports/targets.tsv, one target per line, tab-separated:
#   target  image  command (bash in the image, cwd /src)  files in build-<target>/  state
# An image named in ports/docker/<image>.Dockerfile is built first.
#
# Each step prints "[n/N] ..." and a failure ends with "Setup stopped: ...",
# which the recomp launcher shows. A target that fails doesn't stop the rest;
# its log is in build-logs/. The builds land in builds/<target>/.
# No "set -u": macOS bash 3.2 treats an empty array as unset under it.
# ponytail: no PowerShell twin; on Windows run this from WSL or Git Bash with
# Docker Desktop. Add one when a title ships a console installer for Windows.
ROOT="$(pwd)"
[ -f ports/ports.conf ] && [ -f ports/targets.tsv ] ||
    { echo "Setup stopped: run this from a title's repo (it needs ports/ports.conf and ports/targets.tsv)."; exit 1; }
TITLE="" PREP_IMAGE="" PREP_CMD="" PREP_DONE="" GAME_HINT="the folder with the game"
. ports/ports.conf
YES=0 GAME="" ONLY=""
while [ $# -gt 0 ]; do
    case "$1" in
        --yes|-y) YES=1 ;;
        --game-dir|--game) GAME="$2"; shift ;;
        --targets) ONLY=",$2,"; shift ;;
        *) echo "unknown argument: $1"; exit 2 ;;
    esac
    shift
done
mkdir -p build-logs
exec > >(tee setup.log) 2>&1

TARGETS=()
while IFS= read -r line; do
    case "$line" in \#*|"") continue ;; esac
    t="${line%%$'\t'*}"
    [ -z "$ONLY" ] || [[ "$ONLY" == *",$t,"* ]] && TARGETS+=("$line")
done < ports/targets.tsv
N=$((2 + ${#TARGETS[@]}))

step() { echo; echo "[$1/$N] $2"; }
fail() { echo; echo "Setup stopped: $1"; echo "Details are in $ROOT/setup.log"; exit 1; }
# Containers run as root; give what they wrote back to you (Linux).
mine() { [ "$(uname)" = Linux ] && docker run --rm -v "$ROOT:/src" alpine chown -R "$(id -u):$(id -g)" "${@/#//src/}" >/dev/null 2>&1; true; }

step 1 "Checking Docker"
command -v docker >/dev/null || fail "Docker isn't installed. Install it (https://docs.docker.com/get-docker/), start it, and run this again."
docker info >/dev/null 2>&1 || fail "Docker isn't running. Start it and run this again."
echo "  Docker $(docker version --format '{{.Server.Version}}')"

step 2 "Preparing $TITLE from your copy"
if [ -n "$PREP_CMD" ] && { [ -z "$PREP_DONE" ] || [ ! -e "$PREP_DONE" ]; }; then
    if [ -z "$GAME" ]; then
        [ $YES = 1 ] && fail "no game given. Pass $GAME_HINT with --game-dir."
        read -r -p "Where is the game ($GAME_HINT)? " GAME
    fi
    [ -e "$GAME" ] || fail "there's nothing at '$GAME'."
    [ -f "$GAME" ] && GAME="$(dirname "$GAME")"
    out="$(docker run --rm -u 0 -v "$ROOT:/src" -v "$(cd "$GAME" && pwd):/game:ro" -w /src "$PREP_IMAGE" sh -c "$PREP_CMD" 2>&1)"
    code=$?
    echo "$out" | tail -n 4 | sed 's/^/  /'
    mine .
    if [ $code -ne 0 ]; then
        why="$(echo "$out" | sed -n 's/.*Setup stopped: //p' | tail -n 1)"
        fail "${why:-the prep failed (the lines above say why).}"
    fi
else
    echo "  Already done."
fi

n=2; ok=(); bad=()
for line in "${TARGETS[@]}"; do
    IFS=$'\t' read -r t image cmd files state <<<"$line"
    n=$((n + 1))
    step $n "$t: building (a few minutes; the first run also downloads its toolchain)"
    if [ -f "ports/docker/$image.Dockerfile" ] && ! docker image inspect "$image" >/dev/null 2>&1; then
        docker build -q -t "$image" -f "ports/docker/$image.Dockerfile" ports/docker > "build-logs/$t.log" 2>&1 ||
            { echo "  Building the $t toolchain image failed."; bad+=("$t"); continue; }
    fi
    if docker run --rm -u 0 -v "$ROOT:/src" -w /src "$image" sh -c "$cmd" > "build-logs/$t.log" 2>&1; then
        mkdir -p "builds/$t"
        for f in $files; do
            # rm first: a copy a container left there is root's (Linux); the folder is ours
            [ -f "build-$t/$f" ] && rm -f "builds/$t/$f" && cp "build-$t/$f" "builds/$t/$f"
        done
        ok+=("$t"); echo "  Built. $state."
    else
        bad+=("$t"); echo "  Failed. The last lines of build-logs/$t.log:"; tail -n 5 "build-logs/$t.log" | sed 's/^/    /'
    fi
    mine "build-$t" builds build-logs
done

{
    echo "$TITLE console builds ($(date +%Y-%m-%d))."
    echo
    for line in "${TARGETS[@]}"; do
        IFS=$'\t' read -r t image cmd files state <<<"$line"
        if [[ " ${ok[*]} " == *" $t "* ]]; then echo "  $t: built. $state."; else echo "  $t: FAILED (build-logs/$t.log)"; fi
    done
} > builds/README.txt 2>/dev/null || true

echo; cat builds/README.txt 2>/dev/null
[ ${#ok[@]} -gt 0 ] || fail "nothing built. The logs in build-logs/ say why."
echo
echo "Done: ${#ok[@]} of ${#TARGETS[@]} built${bad:+ (failed: ${bad[*]})}. They're in builds/."

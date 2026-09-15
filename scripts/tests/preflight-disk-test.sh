#!/usr/bin/env bash
# Tests for scripts/preflight-disk.sh and scripts/lib/docker-reclaim.sh.
#
# Why (2026-09-15): `make up` refused to start at 95% Docker disk and its first
# printed remedy (`docker builder prune -f --keep-storage 20GB`) reclaimed 0 B
# on the operator's machine, with nothing on screen to say so. The remedies
# now print what is reclaimable, put `docker image prune` first, and use the
# `builder prune` spelling this client knows. A fake `docker` on PATH drives
# every branch; no real daemon is touched, so this runs anywhere (CI:
# quality.yml `audit` job).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
SCRIPT="$REPO/scripts/preflight-disk.sh"

fails=0
check() { # check <label> <expected> <actual>
    if [ "$2" = "$3" ]; then printf '  ok   %s\n' "$1"; else printf '  FAIL %s\n       expected: %s\n       actual:   %s\n' "$1" "$2" "$3"; fails=$((fails+1)); fi
}
has() { if printf '%s' "$1" | grep -qF -- "$2"; then echo yes; else echo no; fi; }
line_of() { printf '%s\n' "$1" | grep -nF -- "$2" | head -1 | cut -d: -f1; }

T="$(mktemp -d)"
# A run that stops early must FAIL: on macOS bash 3.2 an abort inside an `if`
# exits 0 and skips every later check (the launchd-path test's measured lesson).
completed=""
on_exit() {
    local st=$?
    rm -rf "$T"
    if [[ -z "$completed" ]]; then
        echo "✗ preflight disk test stopped before its last check (status $st)" >&2
        exit 1
    fi
    exit "$st"
}
trap on_exit EXIT

# The fake docker. Behaviour comes from the environment:
#   SHIM_PCT      the `df -P /` Capacity (default 50)
#   SHIM_HELP     new | old      — whether `builder prune --help` lists --reserved-space
#   SHIM_NO_INFO  1              — `system df` and `buildx du` fail
# Every call is appended to $SHIM_LOG.
mkdir -p "$T/bin"
cat > "$T/bin/docker" <<'SHIM'
#!/usr/bin/env bash
echo "$*" >> "$SHIM_LOG"
case "$*" in
  "image inspect "*) exit 0 ;;
  "run --rm --pull=never "*" df -P /")
    printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
    printf 'overlay 100 %s 0 %s%% /\n' "${SHIM_PCT:-50}" "${SHIM_PCT:-50}" ;;
  "builder prune --help")
    if [ "${SHIM_HELP:-new}" = new ]; then
      printf '      --keep-storage bytes\n      --reserved-space bytes   Amount of disk space always allowed to keep for cache\n'
    else
      printf '      --keep-storage bytes     Amount of disk space to keep for cache\n'
    fi ;;
  "system df --format "*)
    [ "${SHIM_NO_INFO:-}" = 1 ] && exit 1
    printf 'Images\t9.5GB (40%%)\nContainers\t0B (0%%)\nLocal Volumes\t6GB (52%%)\nBuild Cache\t0B\n' ;;
  "buildx du")
    [ "${SHIM_NO_INFO:-}" = 1 ] && exit 1
    printf 'ID RECLAIMABLE SIZE LAST ACCESSED\nShared:\t\t5.2GB\nPrivate:\t52.7GB\nReclaimable:\t52.7GB\nTotal:\t\t57.9GB\n' ;;  # every figure distinct, so reading the wrong line cannot pass
  *) exit 0 ;;
esac
SHIM
chmod +x "$T/bin/docker"
export SHIM_LOG="$T/calls.log"

run_preflight() { # env assignments are passed through by the caller
    : > "$SHIM_LOG"
    set +e
    out="$(PATH="$T/bin:/usr/bin:/bin" bash "$SCRIPT" 2>&1)"
    status=$?
    set -e
}

echo "▶ healthy disk"
SHIM_PCT=50 run_preflight
check "exit 0" 0 "$status"
check "prints nothing" "" "$out"
check "no reporting calls on the healthy path" no "$(has "$(cat "$SHIM_LOG")" "buildx du")"

echo "▶ 85% — warn, continue"
SHIM_PCT=85 run_preflight
check "exit 0" 0 "$status"
check "warns" yes "$(has "$out" "Docker VM disk is 85% full")"
check "shows reclaimable images" yes "$(has "$out" "reclaimable now: images 9.5GB (40%)")"
check "shows reclaimable build cache" yes "$(has "$out" "reclaimable now: build cache 52.7GB")"
check "image prune comes before builder prune" yes "$([ "$(line_of "$out" "docker image prune -f")" -lt "$(line_of "$out" "docker builder prune -af")" ] && echo yes || echo no)"
check "uses the flag this client knows" yes "$(has "$out" "docker builder prune -af --reserved-space 20GB")"
check "no deprecated spelling on a new client" no "$(has "$out" "--keep-storage")"
check "never suggests deleting volumes as a fix" no "$(printf '%s\n' "$out" | grep -v 'do NOT run' | grep -c 'volume prune' | sed 's/^0$/no/;s/^[1-9].*/yes/')"

echo "▶ 96% — refuse"
SHIM_PCT=96 run_preflight
check "exit 1" 1 "$status"
check "refuses" yes "$(has "$out" "refusing to start the stack")"
check "names the override" yes "$(has "$out" "TALOS_UP_SKIP_DISK_CHECK=1 make up")"
check "remedies printed on refusal" yes "$(has "$out" "docker builder prune -af --reserved-space 20GB")"

echo "▶ older client without --reserved-space"
SHIM_PCT=96 SHIM_HELP=old run_preflight
check "falls back to --keep-storage" yes "$(has "$out" "docker builder prune -af --keep-storage 20GB")"
check "helper agrees" "--keep-storage" "$(SHIM_HELP=old PATH="$T/bin:/usr/bin:/bin" bash "$REPO/scripts/lib/docker-reclaim.sh" reserve-flag)"
check "helper on a new client" "--reserved-space" "$(SHIM_HELP=new PATH="$T/bin:/usr/bin:/bin" bash "$REPO/scripts/lib/docker-reclaim.sh" reserve-flag)"

echo "▶ reporting calls fail"
SHIM_PCT=96 SHIM_NO_INFO=1 run_preflight
check "still refuses" 1 "$status"
check "figures are omitted, not invented" no "$(has "$out" "reclaimable now")"
check "remedies still printed" yes "$(has "$out" "docker image prune -f")"

echo "▶ opt-out"
SHIM_PCT=99 TALOS_UP_SKIP_DISK_CHECK=1 run_preflight
check "exit 0" 0 "$status"
check "no docker call at all" "" "$(cat "$SHIM_LOG")"

echo "▶ make clean uses the helper, image prune first"
clean="$(awk '/^clean:/{f=1;next} f&&/^[^\t]/{exit} f' "$REPO/Makefile")"
check "builder prune takes the helper's flag" yes "$(has "$clean" 'docker builder prune -af $$(bash scripts/lib/docker-reclaim.sh reserve-flag) 8gb')"
check "image prune before builder prune" yes "$([ "$(line_of "$clean" "docker image prune -f")" -lt "$(line_of "$clean" "docker builder prune")" ] && echo yes || echo no)"
check "no hardcoded --keep-storage" no "$(has "$clean" "--keep-storage")"

completed=yes
if [ "$fails" -gt 0 ]; then
    echo "✗ $fails preflight disk check(s) failed"
    exit 1
fi
echo "✓ preflight disk checks passed"

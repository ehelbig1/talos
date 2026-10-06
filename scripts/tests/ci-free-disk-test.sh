#!/usr/bin/env bash
# Tests for scripts/ci-free-disk.sh, on made-up directories in a temp folder
# (no sudo, nothing outside it).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../ci-free-disk.sh"

fails=0
ok()   { printf '  ok   %s\n' "$1"; }
bad()  { printf '  FAIL %s\n' "$1"; fails=$((fails+1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

T="$(mktemp -d)"
completed=""
on_exit() {
    local st=$?
    rm -rf "$T"
    if [[ -z "$completed" ]]; then
        echo "✗ ci-free-disk test stopped before its last check (status $st)" >&2
        exit 1
    fi
    exit "$st"
}
trap on_exit EXIT

seed() {
    rm -rf "$T/w"; mkdir -p "$T/w/a/deep" "$T/w/b/inner" "$T/w/keep"
    : > "$T/w/a/deep/file"; : > "$T/w/b/inner/file"; : > "$T/w/b/file"; : > "$T/w/keep/file"
}
leftovers() { find "$T/w" -name '*.ci-doomed-*' | wc -l | tr -d ' '; }
# run <paths> [env VAR=value …] — a runner SHORT of disk unless a case says otherwise.
run() { TALOS_CI_FREE_DISK_SUDO="" TALOS_CI_FREE_DISK_AVAIL_GB="${AVAIL:-5}" TALOS_CI_FREE_DISK_PATHS="$1" "${@:2}" bash "$SCRIPT" 2>&1; }

echo "foreground: every listed path is removed, nothing else"
seed
OUT="$(run "$T/w/a:$T/w/b/inner:$T/w/b/:$T/w/missing::relative/path" env TALOS_CI_FREE_DISK_WAIT=1)"
check "a is gone"                         '[[ ! -e "$T/w/a" ]]'
check "b (and the path inside it) is gone" '[[ ! -e "$T/w/b" ]]'
check "an unlisted directory is kept"     '[[ -f "$T/w/keep/file" ]]'
check "no renamed copy is left"           '[[ "$(leftovers)" == 0 ]]'
check "names what it queued"              'grep -qF "queued for deletion: $T/w/a" <<< "$OUT"'
check "a missing or relative path is skipped" '! grep -qE "missing|relative" <<< "$OUT"'

echo "background: the paths are gone at once and a recreated one survives"
seed
OUT="$(run "$T/w/a:$T/w/b")"
check "a is gone when the script returns" '[[ ! -e "$T/w/a" && ! -e "$T/w/b" ]]'
check "says it deletes in the background" 'grep -qF "in the background" <<< "$OUT"'
# What a later step does: recreate the directory and write into it.
mkdir -p "$T/w/a"; : > "$T/w/a/new-file"
for _ in $(seq 1 100); do [[ "$(leftovers)" == 0 ]] && break; sleep 0.1; done
check "the renamed copies are deleted"    '[[ "$(leftovers)" == 0 ]]'
check "the recreated directory is untouched" '[[ -f "$T/w/a/new-file" ]]'

echo "nothing to free is not an error"
seed
OUT="$(run "$T/w/missing")"
check "says so" 'grep -qF "nothing to free" <<< "$OUT"'
check "keeps everything" '[[ -f "$T/w/a/deep/file" && -f "$T/w/keep/file" ]]'

echo "enough free disk: nothing is touched"
seed
OUT="$(AVAIL=86 run "$T/w/a:$T/w/b")"
check "says nothing was deleted"   'grep -qF "86 GB free (threshold 40 GB): nothing deleted" <<< "$OUT"'
check "keeps every directory"      '[[ -f "$T/w/a/deep/file" && -f "$T/w/b/inner/file" ]]'
check "renames nothing"            '[[ "$(leftovers)" == 0 ]]'
OUT="$(AVAIL=40 run "$T/w/a")"
check "exactly the threshold is enough" '[[ -f "$T/w/a/deep/file" ]]'
OUT="$(AVAIL=39 run "$T/w/a" env TALOS_CI_FREE_DISK_WAIT=1)"
check "one GB under it frees"      '[[ ! -e "$T/w/a" ]]'

echo "an unreadable free-space figure frees the disk"
seed
OUT="$(AVAIL=unknown run "$T/w/a" env TALOS_CI_FREE_DISK_WAIT=1)"
check "treated as short"           '[[ ! -e "$T/w/a" ]]'
seed
OUT="$(run "$T/w/a" env TALOS_CI_FREE_DISK_MIN_GB=lots || true)"
check "a threshold that is not a number is refused" 'grep -qF "must be a whole number" <<< "$OUT" && [[ -f "$T/w/a/deep/file" ]]'

echo "the real reading of free space is a number"
seed
OUT="$(TALOS_CI_FREE_DISK_SUDO="" TALOS_CI_FREE_DISK_PATHS="$T/w/a" TALOS_CI_FREE_DISK_MIN_GB=0 bash "$SCRIPT" 2>&1)"
check "reads df and reports GB"    'grep -qE "^[0-9]+ GB free \\(threshold 0 GB\\): nothing deleted" <<< "$OUT"'

completed=1
if [ "$fails" -gt 0 ]; then
    echo "✗ $fails check(s) failed"
    exit 1
fi
echo "✓ ci-free-disk: all checks passed"

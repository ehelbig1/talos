#!/usr/bin/env bash
# Tests for scripts/ci-changed-areas.sh in a throwaway git repository: which
# job groups a diff turns on, and whether it touches dependency files.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../ci-changed-areas.sh"

fails=0
T="$(mktemp -d)"
completed=""
on_exit() {
    local st=$?
    rm -rf "$T"
    if [[ -z "$completed" ]]; then
        echo "✗ ci-changed-areas test stopped before its last check (status $st)" >&2
        exit 1
    fi
    exit "$st"
}
trap on_exit EXIT

g() { git -C "$T" -c user.name=test -c user.email=test@example.test -c commit.gpgsign=false "$@"; }
g init -q -b main
: > "$T/README.md"; g add -A; g commit -q -m base
BASE="$(g rev-parse HEAD)"

# areas <file …> — commit those files on top of BASE and print the answer on one line.
areas() {
    g checkout -q -B probe "$BASE"
    for f in "$@"; do mkdir -p "$T/$(dirname "$f")"; echo x > "$T/$f"; done
    g add -A; g commit -q -m probe
    (cd "$T" && bash "$SCRIPT" "$BASE" "$(g rev-parse HEAD)") | tr '\n' ' '
}
expect() { # expect <label> <answer> <key=value …>
    local label="$1" got="$2"; shift 2
    local ok=1 kv
    for kv in "$@"; do case " $got" in *" $kv "*) ;; *) ok=0 ;; esac; done
    if [ "$ok" = 1 ]; then printf '  ok   %s\n' "$label"; else printf '  FAIL %s\n       want %s\n       got  %s\n' "$label" "$*" "$got"; fails=$((fails+1)); fi
}

echo "which job groups a diff turns on"
expect "docs only: nothing"            "$(areas docs/x.md)"                 rust=false frontend=false observability=false migrations=false
expect "a Rust source"                 "$(areas crate/src/lib.rs)"          rust=true frontend=false
expect "a frontend source"             "$(areas frontend/src/a.tsx)"        rust=false frontend=true
expect "a migration"                   "$(areas migrations/1_x.sql)"        rust=true migrations=true
expect "the workflow: everything"      "$(areas .github/workflows/q.yml)"   rust=true frontend=true observability=true migrations=true
expect "the shard table: everything"   "$(areas scripts/ci-test-weights.tsv)" rust=true frontend=true

echo "whether it touches dependency files"
expect "docs only: neither"            "$(areas docs/x.md)"                 rust_deps=false frontend_deps=false
expect "a Rust source is not a dependency change" "$(areas crate/src/lib.rs)" rust_deps=false frontend_deps=false
expect "Cargo.lock"                    "$(areas Cargo.lock)"                rust_deps=true frontend_deps=false
expect "a crate's Cargo.toml"          "$(areas crate/Cargo.toml)"          rust_deps=true
expect "deny.toml"                     "$(areas deny.toml)"                 rust_deps=true
expect "the frontend lockfile"         "$(areas frontend/package-lock.json)" frontend_deps=true rust_deps=false
expect "the advisory exceptions"       "$(areas frontend/audit-exceptions.json)" frontend_deps=true
expect "a frontend source is not one"  "$(areas frontend/src/a.tsx)"        frontend_deps=false
expect "the workflow alone: known, and no" "$(areas .github/workflows/q.yml)" rust_deps=false frontend_deps=false
expect "the workflow with a lockfile"  "$(areas .github/workflows/q.yml Cargo.lock)" rust=true rust_deps=true frontend_deps=false

echo "no diff to read"
expect "--all: every group, dependencies unknown" "$(cd "$T" && bash "$SCRIPT" --all | tr '\n' ' ')" rust=true frontend=true rust_deps=unknown frontend_deps=unknown
expect "an unreadable commit: every group, unknown" "$(cd "$T" && bash "$SCRIPT" 1111111111111111111111111111111111111111 "$BASE" 2>/dev/null | tr '\n' ' ')" rust=true rust_deps=unknown frontend_deps=unknown

completed=1
if [ "$fails" -gt 0 ]; then
    echo "✗ $fails check(s) failed"
    exit 1
fi
echo "✓ ci-changed-areas: all checks passed"

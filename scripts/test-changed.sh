#!/usr/bin/env bash
# `make test-changed` — run `cargo nextest` for ONLY the workspace crates
# you've touched vs a base ref (default origin/main), instead of the whole
# 110-crate workspace. Fast inner-loop feedback.
#
# SCOPE / HONESTY: this runs the tests OF the changed crates. It does NOT run
# their reverse-dependencies' tests — a change to a low-level crate (e.g.
# talos-memory) can still break a consumer (controller) whose tests live
# elsewhere. So this is a fast inner-loop check, NOT a substitute for
# `make test` / the pre-push hook / CI. Run those before pushing.
#
# Usage:
#   make test-changed                 # vs origin/main, run the tests
#   make test-changed BASE=HEAD~3     # vs a different base
#   make test-changed ARGS=--list     # just print the crates, don't run
#   BASE=… ./scripts/test-changed.sh [--list]

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

BASE="${BASE:-origin/main}"
LIST_ONLY=0
[ "${1:-}" = "--list" ] && LIST_ONLY=1

RED=$'\033[1;31m'; GRN=$'\033[1;32m'; YEL=$'\033[1;33m'; DIM=$'\033[2m'; RST=$'\033[0m'

if ! git rev-parse --verify --quiet "$BASE" >/dev/null; then
  printf '%s✗ base ref %q not found.%s Fetch it (git fetch origin) or pass BASE=<ref>.\n' "$RED" "$BASE" "$RST"
  exit 1
fi

# All paths that differ from BASE (committed since the merge-base AND
# uncommitted working-tree edits), plus new untracked files.
changed_paths=$(
  {
    git diff --name-only --merge-base "$BASE" 2>/dev/null
    git ls-files --others --exclude-standard 2>/dev/null
  } | sort -u
)

# Map a file path to its owning workspace crate name: walk up to the nearest
# ancestor dir holding a Cargo.toml with a [package] section, and read `name`.
crate_for() {
  local dir; dir=$(dirname "$1")
  while [ "$dir" != "." ] && [ "$dir" != "/" ]; do
    if [ -f "$dir/Cargo.toml" ] && grep -q '^\[package\]' "$dir/Cargo.toml" 2>/dev/null; then
      grep -m1 '^name[[:space:]]*=' "$dir/Cargo.toml" | sed -E 's/^name[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/'
      return 0
    fi
    dir=$(dirname "$dir")
  done
  return 1
}

crates=""
root_manifest_touched=0
while IFS= read -r path; do
  [ -z "$path" ] && continue
  case "$path" in
    *.rs|*/Cargo.toml|Cargo.toml|*.wit) ;;
    *) continue ;;
  esac
  # A bare root Cargo.toml / Cargo.lock change affects the whole workspace.
  if [ "$path" = "Cargo.toml" ] || [ "$path" = "Cargo.lock" ]; then
    root_manifest_touched=1
    continue
  fi
  if c=$(crate_for "$path"); then
    crates="$crates$c"$'\n'
  fi
done <<< "$changed_paths"

crates=$(printf '%s' "$crates" | sed '/^$/d' | sort -u)

if [ "$root_manifest_touched" = "1" ]; then
  printf '%s⚠ root Cargo.toml/Cargo.lock changed%s — that can affect the whole workspace; consider %smake test%s.\n' \
    "$YEL" "$RST" "$DIM" "$RST"
fi

if [ -z "$crates" ]; then
  printf '%sNo changed workspace crate vs %s.%s Nothing to test.\n' "$GRN" "$BASE" "$RST"
  exit 0
fi

count=$(printf '%s\n' "$crates" | wc -l | tr -d ' ')
printf '%sChanged crates vs %s%s (%s):\n' "$GRN" "$BASE" "$RST" "$count"
printf '%s\n' "$crates" | sed 's/^/  • /'

if [ "$LIST_ONLY" = "1" ]; then
  exit 0
fi

if ! command -v cargo-nextest >/dev/null 2>&1; then
  printf '%s✗ cargo-nextest missing%s — install: cargo install cargo-nextest --locked\n' "$RED" "$RST"
  exit 1
fi

# Build the -p flag list.
pkg_args=()
while IFS= read -r c; do
  [ -n "$c" ] && pkg_args+=(-p "$c")
done <<< "$crates"

printf '\n%s↳ cargo nextest run %s --no-fail-fast%s\n\n' "$DIM" "${pkg_args[*]}" "$RST"
exec cargo nextest run "${pkg_args[@]}" --no-fail-fast

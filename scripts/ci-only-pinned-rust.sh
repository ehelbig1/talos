#!/usr/bin/env bash
# Remove every Rust toolchain on the runner except the one this workflow pins.
#
# Swatinem/rust-cache builds its cache key from EVERY toolchain `rustup
# toolchain list` names, not the one in use. GitHub's runner image ships its
# own `stable`, which this repository never uses. Measured 2026-10-06 (runs
# 37464963912, 37476202275): the pinned toolchain was identical on both images
# in service (1.96.1, 31fca3adb), the preinstalled one was 1.98.1 on image
# 20260927 and 1.99.0 on image 20261004 — so a job that landed on the newer
# image computed a different key, found no cache and compiled every
# dependency: the DB-free job 12.0 minutes instead of 7.7, the unit job 12.2
# instead of 8, an integration shard 14 instead of 9. It recurs with every
# image that bumps the preinstalled Rust, for as long as the rollout takes.
#
# With only the pinned toolchain installed, the key depends on what the build
# uses. Run it after the toolchain is installed and before the cache step.
#
#   RUST_TOOLCHAIN=1.96 ci-only-pinned-rust.sh
set -euo pipefail

keep="${RUST_TOOLCHAIN:?RUST_TOOLCHAIN names the toolchain to keep}"
installed="$(rustup toolchain list --quiet)"

kept=0
others=()
while IFS= read -r t; do
    [ -n "$t" ] || continue
    case "$t" in
        "$keep"|"$keep"-*) kept=$((kept + 1)) ;;
        *) others+=("$t") ;;
    esac
done <<< "$installed"

# Never leave the runner with no toolchain: if the pinned one is not there,
# the step before this one did not do what this script assumes.
if [ "$kept" -eq 0 ]; then
    echo "✗ no installed toolchain matches '$keep' — refusing to remove the others:" >&2
    printf '    %s\n' "$installed" >&2
    exit 1
fi

for t in ${others[@]+"${others[@]}"}; do
    echo "removing unused toolchain $t"
    rustup toolchain uninstall "$t"
done
echo "toolchains now installed:"
rustup toolchain list --quiet | sed 's/^/    /'

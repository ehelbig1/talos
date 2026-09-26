#!/usr/bin/env bash
# Run every DB-free integration-test binary — the `dbfree` category of
# scripts/ci_test_targets.py — one `cargo nextest run` per crate.
#
# quality.yml's unit job used to name each of these binaries by hand
# (`--test edge_routing --test loop_body_gates …`), so every PR adding a test
# edited the same lines. The list is now derived from the tree: dropping a new
# file into a crate's tests/ directory registers it here, unless it declares a
# service store (`// ci-store:`) or opts out (`// ci-ungated:`).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

groups="$(python3 scripts/ci_test_targets.py grouped dbfree)"
[ -n "$groups" ] || { echo "✗ no DB-free test targets discovered — refusing to pass vacuously" >&2; exit 1; }

rc=0
while IFS=$'\t' read -r crate bins; do
    [ -n "$crate" ] || continue
    args=()
    for b in $bins; do args+=(--test "$b"); done
    echo "▶ ${crate}: ${bins}"
    if ! cargo nextest run -p "$crate" "${args[@]}" --no-fail-fast; then
        rc=1
    fi
done <<< "$groups"
exit "$rc"

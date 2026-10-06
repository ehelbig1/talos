#!/usr/bin/env bash
# Run every test of the repository's own scripts: each scripts/tests/*.sh and
# deploy/k3s/tests/*.sh, and the --self-test of each scripts/*.py that has
# one. `make test-scripts`.
#
# Discovered, not listed. Until 2026-10-06 quality.yml named each of them in
# its own step, so a new script test ran only if someone also edited the
# workflow, and there was no way to run the set locally.
#
# One self-test is left out: scripts/new-integration.py generates a crate and
# runs clippy and tests on it (minutes, needs the Rust toolchain); it has its
# own target, `make test-integration-scaffold`.
#
# Every test runs even after one fails; the exit status is the number that
# failed, and each failure's output is printed.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root" || exit 2

SKIP_SELF_TEST="scripts/new-integration.py"

failed=()
ran=0
run() { # label, command...
    local label="$1" out rc
    shift
    out="$("$@" 2>&1)"
    rc=$?
    ran=$((ran + 1))
    if [ "$rc" -eq 0 ]; then
        printf '  \033[1;32m✓\033[0m %s\n' "$label"
    else
        printf '  \033[1;31m✗\033[0m %s (exit %s)\n' "$label" "$rc"
        printf '%s\n' "$out" | sed 's/^/      /'
        failed+=("$label")
    fi
}

for t in scripts/tests/*.sh deploy/k3s/tests/*.sh; do
    [ -f "$t" ] || continue
    run "$t" bash "$t"
done

while IFS= read -r f; do
    case " $SKIP_SELF_TEST " in *" $f "*) continue ;; esac
    run "$f --self-test" python3 "$f" --self-test
done < <(grep -l -- '"--self-test"' scripts/*.py | sort)

if [ "$ran" -eq 0 ]; then
    printf '\033[1;31m✗ no script test was found — has scripts/tests moved?\033[0m\n' >&2
    exit 2
fi
if [ "${#failed[@]}" -gt 0 ]; then
    printf '\033[1;31m✗ %s of %s script tests failed:\033[0m %s\n' "${#failed[@]}" "$ran" "${failed[*]}" >&2
    exit 1
fi
printf '\033[1;32m✓ %s script tests passed\033[0m\n' "$ran"

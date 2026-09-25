#!/usr/bin/env bash
# Decide which quality.yml job groups a change can affect.
#
#   scripts/ci-changed-areas.sh <base-sha> <head-sha>   → key=true|false lines
#   scripts/ci-changed-areas.sh --all                    → every area true
#
# Areas:
#   rust          Rust sources, manifests, migrations, WIT, catalog templates,
#                 the sqlx cache, and the scripts that drive the Rust jobs
#   frontend      frontend/
#   observability alert rules and their promtool fixtures
#   migrations    migrations/ (the baseline verifier)
#
# A change to the CI plumbing itself (.github/workflows/, this script, the
# test-target classifier, the Makefile) turns EVERY area on: a workflow edit
# must prove itself on the whole suite. So does a diff that cannot be
# computed — a skipped check that should have run is the failure this avoids,
# never an extra run.
set -euo pipefail

emit_all() {
    for a in rust frontend observability migrations; do echo "${a}=true"; done
}

if [ "${1:-}" = "--all" ] || [ $# -lt 2 ] || [ -z "${1:-}" ] || [ -z "${2:-}" ]; then
    emit_all
    exit 0
fi

base="$1"; head="$2"
for sha in "$base" "$head"; do
    git cat-file -e "${sha}^{commit}" 2>/dev/null \
        || git fetch --no-tags --depth=1 origin "$sha" >/dev/null 2>&1 \
        || { echo "::warning::cannot read $sha — running every job" >&2; emit_all; exit 0; }
done

if ! files="$(git diff --name-only "$base" "$head")"; then
    echo "::warning::git diff failed — running every job" >&2
    emit_all
    exit 0
fi

has() { printf '%s\n' "$files" | grep -qE "$1"; }

if has '^\.github/workflows/|^scripts/ci-changed-areas\.sh$|^scripts/ci_test_targets\.py$|^scripts/ci-run-dbfree-tests\.sh$|^Makefile$'; then
    emit_all
    exit 0
fi

rust=false; frontend=false; observability=false; migrations=false
has '\.rs$|(^|/)Cargo\.(toml|lock)$|^\.cargo/|^rust-toolchain\.toml$|^migrations/|^wit/|^module-templates/|^\.sqlx/|\.sql$|^deny\.toml$|^audit\.toml$|^clippy\.toml$|^scripts/(test-integration\.sh|lint-sql-prepare\.py)$' && rust=true
has '^frontend/' && frontend=true
has '^observability/|^deploy/helm/talos/templates/prometheusrule\.yaml$' && observability=true
has '^migrations/' && migrations=true

echo "rust=$rust"
echo "frontend=$frontend"
echo "observability=$observability"
echo "migrations=$migrations"

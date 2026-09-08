#!/usr/bin/env bash
# CANDIDATE lint (2026-09-08) — BUILT, MEASURED and REJECTED. Kept in the tree
# so the numbers below can be re-derived rather than re-argued.
#
# Rule: "a watch-create entry point that accepts a caller-supplied `module_id`
# must consult the shared module-binding gate."
#
# Detector: a `fn` in an integration crate whose parameter list carries
# `module_id: Option<Uuid>`, in a file that does not name `check_module_binding`.
#
# Usage: bash scripts/lint-watch-module-binding-candidate.sh [tree-root]
set -uo pipefail
ROOT="${1:-.}"
cd "$ROOT" || exit 2

echo "── functions taking a caller-supplied module_id, per integration crate ──"
TOTAL=0
UNGATED=0
for crate in talos-gmail talos-google-calendar talos-google-cloud; do
    [ -d "$crate/src" ] || continue
    while IFS= read -r hit; do
        file="${hit%%:*}"
        TOTAL=$((TOTAL + 1))
        if grep -q "check_module_binding" "$file"; then
            echo "  gated   $hit"
        else
            echo "  UNGATED $hit"
            UNGATED=$((UNGATED + 1))
        fi
    done < <(grep -rn "module_id: Option<Uuid>" "$crate/src" --include='*.rs' | grep -v '^\s*//')
done
echo "── functions=$TOTAL ungated=$UNGATED ──"

#!/usr/bin/env bash
# The frontend's dependency-advisory gate: `make audit-frontend`.
#
# Moved out of quality.yml unchanged on 2026-10-06, so the gate has one
# definition that CI and a developer both run. What it decides:
#
#   * every moderate-or-worse ADVISORY must be fixed, or covered by an
#     unexpired, reviewed exception in frontend/audit-exceptions.json (one
#     advisory each, with a reason and an expiry date). Excepted advisories
#     are printed as warnings on every run;
#   * when the advisory service cannot be read (no answer in 300 s, no JSON,
#     an error object), it says the state is UNKNOWN and exits 0 — an outage
#     at npm must not fail every pull request, and must not read as clean.
#
# In CI, EVENT and PR_BASE (the workflow sets them) let a failure say whether
# the change touches the frontend's dependency files at all. Locally they are
# unset and the answer is "unknown".
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root/frontend" || exit 2

# GitHub annotations in CI; plain lines anywhere else.
warn() {
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
        echo "::warning title=Frontend advisory state UNKNOWN::$1"
    else
        printf '\033[1;33m⊘ frontend advisory state UNKNOWN:\033[0m %s\n' "$1"
    fi
}

# `timeout` is GNU coreutils: present on the CI runners, absent on a stock
# Mac (where it may be `gtimeout`, or missing — then npm's own limits apply).
limit=()
if command -v timeout >/dev/null 2>&1; then
    limit=(timeout 300)
elif command -v gtimeout >/dev/null 2>&1; then
    limit=(gtimeout 300)
fi

set +e
out="$(${limit[@]+"${limit[@]}"} npm audit --json --audit-level=moderate 2>/dev/null)"
rc=$?
set -e

if [ "$rc" -eq 124 ]; then
    warn "npm audit did not answer within 300s and was stopped. This is NOT a clean result — the advisory state was not read. The nightly run re-checks."
    exit 0
fi

if [ -z "$out" ] || ! printf '%s' "$out" | jq -e . >/dev/null 2>&1; then
    warn "npm audit produced no parseable JSON (exit $rc). This is NOT a clean result — the advisory state was not read."
    exit 0
fi

if printf '%s' "$out" | jq -e '.error' >/dev/null 2>&1; then
    detail="$(printf '%s' "$out" | jq -r '.error.summary // .error.detail // .error | tostring' | head -c 400)"
    warn "npm audit could not reach the advisory service, so no claim is made about frontend CVEs: $detail"
    exit 0
fi

python3 ../scripts/frontend_audit_gate.py --self-test >/dev/null

# Whether this change touches the frontend's dependency files, so a failure
# can say whether it can be this change's doing.
deps=unknown
if [ "${EVENT:-}" = "pull_request" ] && [ -n "${PR_BASE:-}" ]; then
    case "$(bash ../scripts/ci-changed-areas.sh "$PR_BASE" "$(git rev-parse HEAD)" 2>/dev/null | sed -n 's/^frontend_deps=//p' || true)" in
        true) deps=yes ;;
        false) deps=no ;;
    esac
fi
printf '%s' "$out" | python3 ../scripts/frontend_audit_gate.py --deps-changed "$deps" --exceptions audit-exceptions.json

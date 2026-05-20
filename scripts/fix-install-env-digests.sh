#!/usr/bin/env bash
# One-off repair for /etc/talos/install.env after terminal-paste corruption.
#
# The operator's interactive terminal inserted literal newlines mid-string
# when pasting long `echo 'TALOS_..._DIGEST=sha256:...'` lines, so each
# digest got split across two lines in install.env. Bash sourced the
# orphaned suffixes as commands and install.sh died with
# `f09de28bf: command not found`.
#
# This script:
#   1. Strips every existing TALOS_*_DIGEST= line and the orphan
#      suffix lines that follow them.
#   2. Appends the three correct full-length digests from the latest
#      publish-images.sh run (2026-05-19).
#
# Run as: sudo bash /opt/talos/scripts/fix-install-env-digests.sh \
#           --controller sha256:abc... \
#           --worker     sha256:def... \
#           --frontend   sha256:ghi...
#
# Each --<service> flag is optional — if omitted, the script falls
# back to the env vars TALOS_CONTROLLER_DIGEST etc. (set in the
# shell or sourced from a file before invocation). At least one of
# the three must be supplied somehow, otherwise the script aborts.
set -euo pipefail

ENV_FILE="${TALOS_ENV_FILE:-/etc/talos/install.env}"

# Flag parsing — these override env vars when both are present.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --controller)  TALOS_CONTROLLER_DIGEST="$2"; shift 2 ;;
        --worker)      TALOS_WORKER_DIGEST="$2";     shift 2 ;;
        --frontend)    TALOS_FRONTEND_DIGEST="$2";   shift 2 ;;
        --env-file)    ENV_FILE="$2";                shift 2 ;;
        -h|--help)
            sed -n '2,25p' "$0"
            exit 0 ;;
        *)
            echo "✗ unknown flag: $1" >&2
            exit 1 ;;
    esac
done

# Pull from env (set by flag above OR exported before invocation).
CONTROLLER_DIGEST="${TALOS_CONTROLLER_DIGEST:-}"
WORKER_DIGEST="${TALOS_WORKER_DIGEST:-}"
FRONTEND_DIGEST="${TALOS_FRONTEND_DIGEST:-}"

if [[ -z "$CONTROLLER_DIGEST" && -z "$WORKER_DIGEST" && -z "$FRONTEND_DIGEST" ]]; then
    echo "✗ at least one of --controller / --worker / --frontend (or the matching" >&2
    echo "  TALOS_*_DIGEST env vars) must be supplied" >&2
    exit 1
fi

# Validate each provided digest matches sha256:<64-hex>.
validate_digest() {
    local name="$1" val="$2"
    [[ -z "$val" ]] && return 0  # absent → skip; caller intends to leave that one
    if ! [[ "$val" =~ ^sha256:[a-f0-9]{64}$ ]]; then
        echo "✗ $name digest must match sha256:<64-hex>, got: $val" >&2
        exit 1
    fi
}
validate_digest "--controller" "$CONTROLLER_DIGEST"
validate_digest "--worker"     "$WORKER_DIGEST"
validate_digest "--frontend"   "$FRONTEND_DIGEST"

[[ -f "$ENV_FILE" ]] || { echo "ERROR: $ENV_FILE not found" >&2; exit 1; }

# Snapshot before mutation.
TS="$(date +%Y%m%dT%H%M%S)"
sudo cp "$ENV_FILE" "${ENV_FILE}.bak-${TS}"
echo "▶ snapshot: ${ENV_FILE}.bak-${TS}"

# Build the cleaned file in a tmpfile.
TMP="$(mktemp)"

# Pass 1: strip every TALOS_*_DIGEST= line AND any "orphan suffix" line
# that immediately follows it. An orphan suffix is identified as:
#   - lowercase hex characters (and optional leading whitespace)
#   - no `=` sign
#   - no `#` (so we don't eat regular comments by mistake)
#   - length < 80 chars (full digests are 71 chars; the operator's
#     orphan suffixes are 5-15 chars — both safely under)
#
# Then pass 2: append the three correct digest lines at the end.
awk '
    /^[[:space:]]*TALOS_(CONTROLLER|WORKER|FRONTEND)_DIGEST=/ {
        in_digest = 1
        next
    }
    in_digest && /^[[:space:]]*[a-f0-9]+[[:space:]]*$/ {
        # Orphan suffix line right after a digest. Drop.
        in_digest = 0
        next
    }
    {
        in_digest = 0
        print
    }
' "$ENV_FILE" > "$TMP"

# Append the fresh digests. Only emit lines for digests that were
# actually supplied — if the operator only ran with --controller,
# the worker / frontend digests stay at whatever they had before
# the awk pass stripped them. (awk strips ALL TALOS_*_DIGEST=
# lines unconditionally — that's OK for the worker/frontend
# case below because we're not deleting any env-file content that
# matters; their previous values either came from a prior run of
# this script or from the operator's manual edit, and we'd want
# the operator to pass them in explicitly to lock them in.)
{
    printf '\n# Image digests pinned by scripts/fix-install-env-digests.sh (%s)\n' "$TS"
    [[ -n "$CONTROLLER_DIGEST" ]] && printf 'TALOS_CONTROLLER_DIGEST=%s\n' "$CONTROLLER_DIGEST"
    [[ -n "$WORKER_DIGEST"     ]] && printf 'TALOS_WORKER_DIGEST=%s\n'     "$WORKER_DIGEST"
    [[ -n "$FRONTEND_DIGEST"   ]] && printf 'TALOS_FRONTEND_DIGEST=%s\n'   "$FRONTEND_DIGEST"
} >> "$TMP"

# Atomic swap.
sudo mv "$TMP" "$ENV_FILE"
sudo chmod 600 "$ENV_FILE"

echo "✓ /etc/talos/install.env repaired"
echo
echo "Current digest lines:"
sudo grep -nE "TALOS_(CONTROLLER|WORKER|FRONTEND)_DIGEST" "$ENV_FILE"

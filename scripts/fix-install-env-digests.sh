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
# Run as: sudo bash /opt/talos/scripts/fix-install-env-digests.sh
set -euo pipefail

ENV_FILE="${TALOS_ENV_FILE:-/etc/talos/install.env}"

CONTROLLER_DIGEST="sha256:89d0843c2aca7d656e59a697702774458f190671bb2420244697f49f09de28bf"
WORKER_DIGEST="sha256:00d6cb99a3977a3c46c0db9b30a7b713cd2a7073af5588364c67e428a52517cd"
FRONTEND_DIGEST="sha256:f6ba99978f97f322e467c77f1169277f09d8b0a2cf93e6c32b9e5b4180ce8d4b"

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

# Append the fresh digests.
cat >> "$TMP" <<EOF

# Image digests pinned by scripts/fix-install-env-digests.sh ($TS)
TALOS_CONTROLLER_DIGEST=$CONTROLLER_DIGEST
TALOS_WORKER_DIGEST=$WORKER_DIGEST
TALOS_FRONTEND_DIGEST=$FRONTEND_DIGEST
EOF

# Atomic swap.
sudo mv "$TMP" "$ENV_FILE"
sudo chmod 600 "$ENV_FILE"

echo "✓ /etc/talos/install.env repaired"
echo
echo "Current digest lines:"
sudo grep -nE "TALOS_(CONTROLLER|WORKER|FRONTEND)_DIGEST" "$ENV_FILE"

#!/usr/bin/env bash
# Tests for the backup drill's Vault gate (scripts/drills/backup-restore.sh,
# TALOS_DRILL_VAULT): Vault is drilled exactly when it is on the recovery
# path (KEK_PROVIDER=vault), can be forced on, and cannot be skipped when it
# holds the key.
#
# Runs the REAL drill script with a fake `docker` on PATH, a made-up key file
# and an empty backup folder, all in a temp directory. Every case stops in
# step 1 (artifact selection) — the point is which artifact it asks for —
# so no container, build or network is involved.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

fails=0
check() { # check <label> <expected yes|no> <haystack> <needle>
    local got=no
    if printf '%s' "$3" | grep -qF -- "$4"; then got=yes; fi
    if [ "$got" = "$2" ]; then printf '  ok   %s\n' "$1"; else printf '  FAIL %s\n       expected %s for: %s\n' "$1" "$2" "$4"; fails=$((fails+1)); fi
}

T="$(mktemp -d)"
completed=""
on_exit() {
    local st=$?
    rm -rf "$T"
    if [[ -z "$completed" ]]; then
        echo "✗ drill-vault-gate test stopped before its last check (status $st)" >&2
        exit 1
    fi
    exit "$st"
}
trap on_exit EXIT

mkdir -p "$T/bin" "$T/backups" "$T/metrics" "$T/escrow"
cat > "$T/bin/docker" <<'SHIM'
#!/usr/bin/env bash
# The daemon answers; no scratch container or volume exists; nothing else works.
case "$1" in info) exit 0 ;; *) exit 1 ;; esac
SHIM
chmod +x "$T/bin/docker"
printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n' > "$T/escrow/kek"
chmod 600 "$T/escrow/kek"
: > "$T/backups/talos-20260101-000000.dump"

# drill [VAR=value …] — the real drill; in practice it stops in step 1. Sets OUT.
drill() {
    rm -f "$T/metrics"/*.prom
    set +e
    OUT="$(cd "$REPO" && env PATH="$T/bin:$PATH" NO_COLOR=1 \
        TALOS_DRILL_BACKUP_DIR="$T/backups" TALOS_DRILL_TEXTFILE_DIR="$T/metrics" \
        TALOS_DRILL_ESCROW_KEY_FILE="$T/escrow/kek" TALOS_DRILL_REPORT=off \
        TALOS_DRILL_MAX_ARTIFACT_AGE_HOURS=0 \
        "$@" bash scripts/drills/backup-restore.sh --source artifact 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"
    set -e
}

echo "KEK_PROVIDER=env (the default): Vault is not drilled"
drill
check "says Vault is not drilled"                yes "$OUT" "Vault is not drilled: KEK_PROVIDER=env"
# GNU and BSD `stat`/`date` differ; a wrong one left the date unread ("?") or
# killed the age check outright on Linux.
check "reads the artifact's date"                no  "$OUT" "taken ?"
check "reads the artifact's age"                 yes "$OUT" "is 0h old"
check "does not ask for a Vault backup"          no  "$OUT" "no vault-*.tar.gz"
check "gets past Vault to the next artifact"     yes "$OUT" "no neo4j-*.tar.gz"
check "writes no vault kind line"                no  "$(cat "$T/metrics"/*.prom 2>/dev/null || true)" 'kind="vault"'

echo "KEK_PROVIDER=vault: Vault is required"
drill TALOS_DRILL_KEK_PROVIDER=vault
check "asks for the Vault backup"                yes "$OUT" "no vault-*.tar.gz"
check "does not say it skipped Vault"            no  "$OUT" "Vault is not drilled"

echo "TALOS_DRILL_VAULT=on with env: drilled anyway"
drill TALOS_DRILL_VAULT=on
check "asks for the Vault backup"                yes "$OUT" "no vault-*.tar.gz"

echo "TALOS_DRILL_VAULT=off with KEK_PROVIDER=vault: refused"
drill TALOS_DRILL_KEK_PROVIDER=vault TALOS_DRILL_VAULT=off
check "refuses to skip the key's holder"         yes "$OUT" "Vault wraps the root key, so the drill cannot skip it"

echo "an unknown TALOS_DRILL_VAULT value: refused"
drill TALOS_DRILL_VAULT=maybe
check "names the allowed values"                 yes "$OUT" "TALOS_DRILL_VAULT must be 'auto', 'on' or 'off'"

completed=1
if [ "$fails" -gt 0 ]; then
    echo "✗ $fails check(s) failed"
    exit 1
fi
echo "✓ drill-vault-gate: all checks passed"

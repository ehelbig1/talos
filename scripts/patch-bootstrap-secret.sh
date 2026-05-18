#!/usr/bin/env bash
# Patch the talos bootstrap secret to add or rotate one or more keys WITHOUT
# rotating TALOS_MASTER_KEY (which would orphan every encrypted DEK).
#
# Why this exists: deploy/k3s/install.sh is "create-once" for the bootstrap
# secret — after the first install, re-running it leaves the secret untouched.
# That's correct for safety (master-key rotation is catastrophic), but it
# means there's no documented path to add NEW keys (e.g. flipping embedding
# providers, adding a new OAuth client). Operators historically had to
# hand-craft a `kubectl patch secret` JSON-merge call. This script is the
# documented version of that, with safety checks for the common footguns:
#
#   * runs against the right namespace + secret name (default `talos`/`talos-bootstrap`)
#   * uses `stringData` (kubectl base64-encodes for you — no manual encoding)
#   * accepts KEY=VALUE pairs as arguments OR reads VALUE securely from stdin
#     (so the secret never lands in shell history)
#   * triggers a rolling restart of the controller so the new env values take
#     effect (env-from-secret is read at pod startup, not on every pod tick)
#
# Usage:
#   # 1. Inline (shows up in shell history — only use for non-secret values):
#   scripts/patch-bootstrap-secret.sh \
#     EMBEDDING_API_URL=https://api.voyageai.com/v1/embeddings \
#     EMBEDDING_MODEL=voyage-3 \
#     EMBEDDING_DIMENSIONS=1024
#
#   # 2. Stdin for sensitive values — VALUE comes from stdin when set to "-":
#   echo -n "$VOYAGE_KEY" | scripts/patch-bootstrap-secret.sh EMBEDDING_API_KEY=-
#
#   # 3. From a heredoc (multiple sensitive values at once):
#   scripts/patch-bootstrap-secret.sh < <(printf '%s\n' \
#     "EMBEDDING_API_KEY=$VOYAGE_KEY" \
#     "ANOTHER_SECRET=$OTHER_KEY")
#
# Env overrides:
#   TALOS_NAMESPACE          (default: talos)
#   TALOS_BOOTSTRAP_SECRET   (default: talos-bootstrap)
#   TALOS_CONTROLLER_DEPLOY  (default: talos-controller)
#   TALOS_SKIP_RESTART=1     skip the rolling restart (when patching multiple
#                              secrets back-to-back; do one explicit restart at the end)

set -euo pipefail

NAMESPACE="${TALOS_NAMESPACE:-talos}"
SECRET="${TALOS_BOOTSTRAP_SECRET:-talos-bootstrap}"
DEPLOY="${TALOS_CONTROLLER_DEPLOY:-talos-controller}"

# ── Colours ──────────────────────────────────────────────────────────────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    BOLD=$'\033[1m'; GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'
    DIM=$'\033[2m'; RESET=$'\033[0m'
else
    BOLD=""; GREEN=""; RED=""; YELLOW=""; DIM=""; RESET=""
fi
say()  { printf '%s%s%s\n' "$BOLD" "$1" "$RESET"; }
ok()   { printf '%s✓%s %s\n' "$GREEN" "$RESET" "$1"; }
warn() { printf '%s⚠%s %s\n' "$YELLOW" "$RESET" "$1"; }
err()  { printf '%s✗%s %s\n' "$RED" "$RESET" "$1" >&2; }

# ── Pick a kubectl that can reach the cluster ────────────────────────────────
# On k3s, the kubeconfig lives at /etc/rancher/k3s/k3s.yaml and root needs
# either KUBECONFIG set or the `k3s kubectl` shim. We prefer the latter so
# the script Just Works on a stock k3s install.
if command -v k3s >/dev/null 2>&1 && [ -f /etc/rancher/k3s/k3s.yaml ]; then
    KUBECTL=(k3s kubectl)
elif [ -n "${KUBECONFIG:-}" ] && command -v kubectl >/dev/null 2>&1; then
    KUBECTL=(kubectl)
elif command -v kubectl >/dev/null 2>&1; then
    KUBECTL=(kubectl)
    warn "Using default kubectl context — make sure it points at the right cluster."
else
    err "No kubectl found. Install kubectl, or run on the k3s host."
    exit 1
fi

# ── Confirm secret exists ────────────────────────────────────────────────────
if ! "${KUBECTL[@]}" -n "$NAMESPACE" get secret "$SECRET" >/dev/null 2>&1; then
    err "Secret $NAMESPACE/$SECRET not found."
    err "  This script PATCHES an existing bootstrap secret — first install"
    err "  must be done via deploy/k3s/install.sh. If you're trying to seed"
    err "  the secret for the first time, run install.sh instead."
    exit 1
fi

# ── Collect KEY=VALUE pairs from args + stdin ────────────────────────────────
declare -A pairs=()
declare -a key_order=()

add_pair() {
    local kv="$1"
    if [[ "$kv" != *=* ]]; then
        err "Bad pair (no '='): $kv"
        exit 1
    fi
    local key="${kv%%=*}"
    local val="${kv#*=}"
    if [[ ! "$key" =~ ^[A-Z][A-Z0-9_]*$ ]]; then
        err "Bad key '$key' — must be uppercase + underscores only."
        exit 1
    fi
    if [ "$val" = "-" ]; then
        if ! IFS= read -r val; then
            err "No stdin available for key '$key' with value '-'."
            exit 1
        fi
    fi
    if [ -z "${pairs[$key]+set}" ]; then
        key_order+=("$key")
    fi
    pairs["$key"]="$val"
}

if [ $# -gt 0 ]; then
    for arg in "$@"; do
        add_pair "$arg"
    done
elif [ ! -t 0 ]; then
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        add_pair "$line"
    done
else
    cat <<EOF >&2
Usage: $0 KEY=VALUE [KEY=VALUE ...]
   or: cat pairs | $0
   or: echo -n \$SECRET_VALUE | $0 KEY=-

See the comment block at the top of this script for full examples.
EOF
    exit 1
fi

if [ ${#pairs[@]} -eq 0 ]; then
    err "No KEY=VALUE pairs supplied."
    exit 1
fi

# ── Build patch JSON ─────────────────────────────────────────────────────────
# Use stringData so kubectl base64-encodes for us. Build via jq with one
# --arg per (k,v) pair so values containing quotes / backslashes / newlines
# are escaped correctly — `printf` in a heredoc would mangle them.
if ! command -v jq >/dev/null 2>&1; then
    err "jq not found — install jq (apt: 'apt install jq'; mac: 'brew install jq')."
    err "  We use jq to JSON-encode patch values so quotes/backslashes don't break the patch."
    exit 1
fi

jq_args=()
jq_filter='{stringData: {}}'
for i in "${!key_order[@]}"; do
    k="${key_order[$i]}"
    v="${pairs[$k]}"
    jq_args+=(--arg "k$i" "$k" --arg "v$i" "$v")
    jq_filter+=" | .stringData[\$k$i] = \$v$i"
done
patch_json=$(jq -n "${jq_args[@]}" "$jq_filter")

say "Patching $NAMESPACE/$SECRET with ${#pairs[@]} key(s):"
for k in "${key_order[@]}"; do
    # Mask the value (show length only) so secrets don't end up in the
    # operator's terminal scrollback.
    printf '  %s%s%s = <%d chars>\n' "$DIM" "$k" "$RESET" "${#pairs[$k]}"
done

if ! "${KUBECTL[@]}" -n "$NAMESPACE" patch secret "$SECRET" -p "$patch_json"; then
    err "Patch failed."
    exit 1
fi
ok "Secret patched."

# ── Trigger rolling restart so the new env values take effect ────────────────
if [ "${TALOS_SKIP_RESTART:-0}" = "1" ]; then
    warn "TALOS_SKIP_RESTART=1 — skipping rolling restart. Run manually:"
    warn "  ${KUBECTL[*]} -n $NAMESPACE rollout restart deploy/$DEPLOY"
    exit 0
fi

say "Restarting deploy/$DEPLOY so new env vars are picked up"
if ! "${KUBECTL[@]}" -n "$NAMESPACE" rollout restart "deploy/$DEPLOY"; then
    err "Rollout restart failed — patch took effect but pods are still on old env."
    err "  Run manually: ${KUBECTL[*]} -n $NAMESPACE rollout restart deploy/$DEPLOY"
    exit 1
fi
"${KUBECTL[@]}" -n "$NAMESPACE" rollout status "deploy/$DEPLOY" --timeout=120s
ok "Rolling restart complete. New env vars active."

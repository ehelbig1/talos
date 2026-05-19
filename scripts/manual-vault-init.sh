#!/usr/bin/env bash
# One-off manual replacement for the chart's vault-init Job. Use when
# the in-cluster Job keeps failing in obscure ways but the underlying
# Vault is healthy and you just need to get the controller running.
#
# Steps (all idempotent):
#   1. Read root token from /vault/file/bootstrap.json on the
#      running talos-vault-0 pod.
#   2. Ensure the talos-controller policy + KEK key exist in Vault.
#   3. Mint a fresh talos-controller periodic token.
#   4. Patch the talos-bootstrap Secret's VAULT_TOKEN key with that
#      token.
#   5. Restart the talos-controller Deployment so the new pod picks
#      up the patched VAULT_TOKEN.
#
# This is everything the chart's vault-init Job is supposed to do,
# minus the secret-patcher tooling that's been giving us grief.
#
# Usage: sudo bash /opt/talos/scripts/manual-vault-init.sh
set -euo pipefail

NS="${TALOS_NAMESPACE:-talos}"
VAULT_POD="${TALOS_VAULT_POD:-talos-vault-0}"
SECRET="${TALOS_BOOTSTRAP_SECRET:-talos-bootstrap}"
CONTROLLER_DEPLOY="${TALOS_CONTROLLER_DEPLOY:-talos-controller}"
KEK_KEY_NAME="${TALOS_KEK_KEY_NAME:-talos-kek}"

echo "▶ Reading root token from $VAULT_POD's bootstrap.json"
ROOT_TOKEN=$(kubectl -n "$NS" exec "$VAULT_POD" -- sh -c \
  'sed -n "s/.*\"root_token\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" /vault/file/bootstrap.json | head -1')

if [ -z "$ROOT_TOKEN" ]; then
    echo "ERROR: could not extract root_token from $VAULT_POD:/vault/file/bootstrap.json" >&2
    exit 1
fi
echo "  root token: ${ROOT_TOKEN:0:10}…(${#ROOT_TOKEN} chars)"

echo "▶ Ensuring transit engine + KEK key + talos-controller policy exist"
kubectl -n "$NS" exec "$VAULT_POD" -- env VAULT_TOKEN="$ROOT_TOKEN" \
    sh -c 'vault secrets enable -path=transit transit 2>/dev/null || true'
kubectl -n "$NS" exec "$VAULT_POD" -- env VAULT_TOKEN="$ROOT_TOKEN" \
    sh -c "vault write -f transit/keys/${KEK_KEY_NAME} 2>/dev/null || true"

# Write the policy via stdin. The KEK key name is the only template
# point.
POLICY_BODY=$(cat <<EOF
path "transit/encrypt/${KEK_KEY_NAME}" { capabilities = ["update"] }
path "transit/decrypt/${KEK_KEY_NAME}" { capabilities = ["update"] }
path "transit/keys/${KEK_KEY_NAME}"    { capabilities = ["read"] }
EOF
)
echo "$POLICY_BODY" | kubectl -n "$NS" exec -i "$VAULT_POD" -- env VAULT_TOKEN="$ROOT_TOKEN" \
    sh -c 'vault policy write talos-controller -'

echo "▶ Minting a fresh talos-controller token"
TOKEN_JSON=$(kubectl -n "$NS" exec "$VAULT_POD" -- env VAULT_TOKEN="$ROOT_TOKEN" \
    vault token create \
        -policy=talos-controller \
        -period=768h \
        -orphan \
        -display-name=talos-controller \
        -format=json)

CONTROLLER_TOKEN=$(echo "$TOKEN_JSON" \
    | sed -n 's/.*"client_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
    | head -1)

if [ -z "$CONTROLLER_TOKEN" ]; then
    echo "ERROR: failed to extract client_token from vault token create response" >&2
    echo "raw response:" >&2
    echo "$TOKEN_JSON" | head -20 >&2
    exit 1
fi
echo "  controller token: ${CONTROLLER_TOKEN:0:10}…(${#CONTROLLER_TOKEN} chars)"

echo "▶ Patching $SECRET.VAULT_TOKEN"
NEW_B64=$(printf '%s' "$CONTROLLER_TOKEN" | base64 | tr -d '\n')
kubectl -n "$NS" patch secret "$SECRET" --type=merge \
    -p "{\"data\":{\"VAULT_TOKEN\":\"${NEW_B64}\"}}"
echo "  patched"

echo "▶ Restarting $CONTROLLER_DEPLOY so the new pod reads the patched secret"
kubectl -n "$NS" rollout restart deployment "$CONTROLLER_DEPLOY"

echo
echo "═══════════════════════════════════════════════════════════"
echo "  done. The new controller pod should boot cleanly within"
echo "  a minute. Verify with:"
echo
echo "    kubectl -n $NS get pods -l app.kubernetes.io/component=controller -w"
echo "    kubectl -n $NS logs -l app.kubernetes.io/component=controller --tail=20"
echo "═══════════════════════════════════════════════════════════"

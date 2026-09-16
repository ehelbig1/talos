# vault-init.sh — the body of the chart's vault-init Job
# (templates/vault/init-job.yaml renders it with `.Files.Get`).
#
# Initializes the in-chart Vault on first install, unseals it, provisions the
# transit KEK + the least-privilege `talos-controller` policy, and — only while
# the bootstrap Secret still holds a placeholder — mints the controller's
# periodic token and rolls the controller.
#
# Package BY (2026-09-16) changes, each measured on hashicorp/vault:1.18.5:
#   * NO STANDING ROOT TOKEN. `vault operator init` wrote the root token into
#     /vault/file/bootstrap.json and every run reused it, forever. Each run now
#     derives a fresh root token from the unseal key (the generate-root flow),
#     uses it, and revokes it on exit — including on a failed run. A
#     bootstrap.json written by an earlier chart has its root_token revoked and
#     removed on the next run.
#   * ONE CONTROLLER TOKEN. Step 7 minted a new orphan 768h token on EVERY run
#     and discarded it unless the Secret held a placeholder, so every upgrade
#     left a valid, unused, never-revoked token behind. It now mints only when
#     it will be used.
#   * KEY MATERIAL STAYS IN THE VAULT POD. The unseal key is read and used
#     inside the pod (`vault write sys/unseal key=-` reads stdin), and tokens
#     reach the in-pod CLI on stdin, never on a command line.
#
# Stated limit: the unseal key still lives on the Vault volume, next to the
# data it protects (a single-operator, self-contained chart has nowhere else to
# keep it). Anyone who can read that volume can unseal and generate a root
# token. The only full answer is auto-unseal against an external KMS / transit.
set -eu

: "${NAMESPACE:?}" "${VAULT_POD:?}" "${BOOTSTRAP_SECRET:?}" "${CONTROLLER_DEPLOY:?}" "${KEK_KEY:?}"

# Run a program inside the Vault server container. -c vault: the pod also runs
# the `unsealer` sidecar.
vexec() {
    kubectl -n "$NAMESPACE" exec -i -c vault "$VAULT_POD" -- "$@"
}

# Shell fragment, evaluated INSIDE the Vault pod, that sets KEY from
# bootstrap.json without printing it.
READ_KEY='F=/vault/file/bootstrap.json; KEY=$(awk "/unseal_keys_b64/{f=1;next} /\]/{f=0} f" "$F" | sed -n "s/.*\"\([^\"]*\)\".*/\1/p" | head -1)'

ROOT_TOKEN=""
revoke_root() {
    if [ -n "$ROOT_TOKEN" ]; then
        if printf '%s' "$ROOT_TOKEN" | vexec sh -c 'VAULT_TOKEN=$(cat); export VAULT_TOKEN; vault token revoke -self >/dev/null'; then
            echo "vault-init: this run's root token revoked"
        else
            echo "vault-init: WARNING — could not revoke this run's root token" >&2
        fi
        ROOT_TOKEN=""
    fi
}
trap revoke_root EXIT

# ── 1. Wait for the Vault pod to be Ready ───────────────────────────────────
echo "vault-init: waiting for $VAULT_POD to be Ready (max 5 min)..."
for _ in $(seq 1 60); do
    phase="$(kubectl -n "$NAMESPACE" get pod "$VAULT_POD" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    ready="$(kubectl -n "$NAMESPACE" get pod "$VAULT_POD" -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null || true)"
    if [ "$phase" = "Running" ] && [ "$ready" = "true" ]; then
        echo "vault-init: $VAULT_POD ready"
        break
    fi
    sleep 5
done

# ── 2. Initialize Vault on first install ────────────────────────────────────
INIT_STATE="$(vexec sh -c 'vault status -format=json 2>&1 | grep -o "\"initialized\":[[:space:]]*true" || true')"
if [ -z "$INIT_STATE" ]; then
    echo "vault-init: initializing fresh Vault storage"
    vexec sh -c 'umask 077 && vault operator init -key-shares=1 -key-threshold=1 -format=json > /vault/file/bootstrap.json'
else
    echo "vault-init: existing Vault storage detected"
    if ! vexec test -f /vault/file/bootstrap.json; then
        echo "vault-init: ERROR — Vault initialized but bootstrap.json missing." >&2
        echo "vault-init: restore the file from backup OR delete the Vault PVC and re-run (data loss)." >&2
        exit 1
    fi
fi

# ── 3. Unseal if needed (the unseal sidecar also does this) ─────────────────
if vexec sh -c 'vault status -format=json 2>&1 | grep -q "\"sealed\":[[:space:]]*true"'; then
    echo "vault-init: unsealing"
    vexec sh -c "$READ_KEY"'; printf "%s" "$KEY" | vault write -format=json sys/unseal key=- >/dev/null'
fi

# ── 4. A root token for THIS run only ───────────────────────────────────────
# A root token left in bootstrap.json by an earlier chart is revoked and
# removed first; then a fresh one is generated from the unseal key.
vexec sh -c "$READ_KEY"'
OLD=$(sed -n "s/.*\"root_token\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$F" | head -1)
if [ -n "$OLD" ]; then
    printf "%s" "$OLD" | { VAULT_TOKEN=$(cat); export VAULT_TOKEN; vault token revoke -self >/dev/null 2>&1 || true; }
    umask 077
    awk "/\"root_token\"/ { sub(/,[[:space:]]*\$/, \"\", prev); next } NR > 1 { print prev } { prev = \$0 } END { print prev }" "$F" > "$F.tmp"
    mv "$F.tmp" "$F"
    echo "vault-init: stored root token revoked and removed from bootstrap.json" >&2
fi'
ROOT_TOKEN="$(vexec sh -c "$READ_KEY"'
vault operator generate-root -cancel >/dev/null 2>&1 || true
OTP=$(vault operator generate-root -generate-otp)
NONCE=$(vault write -format=json sys/generate-root/attempt otp="$OTP" | tr -d "\n" | sed -n "s/.*\"nonce\":[[:space:]]*\"\([^\"]*\)\".*/\1/p")
ENC=$(printf "%s" "$KEY" | vault write -format=json sys/generate-root/update nonce="$NONCE" key=- | tr -d "\n" | sed -n "s/.*\"encoded_token\":[[:space:]]*\"\([^\"]*\)\".*/\1/p")
vault operator generate-root -decode="$ENC" -otp="$OTP"')"
if [ -z "$ROOT_TOKEN" ]; then
    echo "vault-init: ERROR — could not generate a root token from the unseal key" >&2
    exit 1
fi

# vroot: run a vault CLI script inside the pod as this run's root token, which
# travels on the first line of stdin (the rest of stdin is the script's own).
vroot() {
    vexec sh -c 'read -r VAULT_TOKEN; export VAULT_TOKEN; '"$1"
}

# ── 5. Ensure transit engine + KEK key ──────────────────────────────────────
printf '%s\n' "$ROOT_TOKEN" | vroot "vault secrets enable -path=transit transit >/dev/null 2>&1 || true"
printf '%s\n' "$ROOT_TOKEN" | vroot "vault write -f transit/keys/$KEK_KEY >/dev/null 2>&1 || true"

# ── 6. Write the least-privilege controller policy ──────────────────────────
{
    printf '%s\n' "$ROOT_TOKEN"
    cat <<POLICY
path "transit/encrypt/$KEK_KEY" { capabilities = ["update"] }
path "transit/decrypt/$KEK_KEY" { capabilities = ["update"] }
path "transit/keys/$KEK_KEY"    { capabilities = ["read"] }
POLICY
} | vroot "vault policy write talos-controller - >/dev/null"

# ── 7. Mint + patch + roll ONLY while the Secret holds a placeholder ───────
CURRENT_B64="$(kubectl -n "$NAMESPACE" get secret "$BOOTSTRAP_SECRET" -o jsonpath='{.data.VAULT_TOKEN}' 2>/dev/null || true)"
CURRENT=""
if [ -n "$CURRENT_B64" ]; then
    CURRENT="$(printf '%s' "$CURRENT_B64" | base64 -d 2>/dev/null || true)"
fi

case "$CURRENT" in
    __pending_vault_init__|dev-root|"")
        echo "vault-init: VAULT_TOKEN is a placeholder ('${CURRENT:-<empty>}'); minting the controller token"
        # -orphan: not revoked with its parent (this run's root, revoked below).
        # -period=768h: each RENEWAL restores 32 days; the controller renews it
        # (VaultTransitProvider::run_token_renewal) — Vault does not renew on use.
        TOKEN_JSON="$(printf '%s\n' "$ROOT_TOKEN" | vroot "vault token create -policy=talos-controller -period=768h -orphan -display-name=talos-controller -format=json")"
        CONTROLLER_TOKEN="$(printf '%s' "$TOKEN_JSON" | sed -n 's/.*"client_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
        if [ -z "$CONTROLLER_TOKEN" ]; then
            echo "vault-init: ERROR — failed to mint talos-controller token" >&2
            exit 1
        fi
        NEW_B64="$(printf '%s' "$CONTROLLER_TOKEN" | base64 | tr -d '\n')"
        PAYLOAD="$(printf '{"data":{"VAULT_TOKEN":"%s"}}' "$NEW_B64")"
        if ! kubectl -n "$NAMESPACE" patch secret "$BOOTSTRAP_SECRET" --type=merge -p "$PAYLOAD" >/dev/null; then
            # A minted token that never reaches the Secret is a live credential
            # nobody holds: revoke it before failing, so a retry mints cleanly.
            printf '%s\n' "$CONTROLLER_TOKEN" | vexec sh -c 'VAULT_TOKEN=$(cat); export VAULT_TOKEN; vault token revoke -self >/dev/null' \
                || echo "vault-init: WARNING — could not revoke the unused controller token" >&2
            echo "vault-init: ERROR — could not patch the bootstrap secret; the minted token was revoked" >&2
            exit 1
        fi
        echo "vault-init: bootstrap secret patched"
        if kubectl -n "$NAMESPACE" get deployment "$CONTROLLER_DEPLOY" >/dev/null 2>&1; then
            NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            ROLL_PATCH="$(printf '{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":"%s"}}}}}' "$NOW")"
            kubectl -n "$NAMESPACE" patch deployment "$CONTROLLER_DEPLOY" --type=strategic -p "$ROLL_PATCH" >/dev/null
            echo "vault-init: controller rollout triggered"
        else
            echo "vault-init: controller deployment not yet present; skipping rollout"
        fi
        ;;
    *)
        echo "vault-init: VAULT_TOKEN is already set (not a placeholder); no token minted"
        ;;
esac

revoke_root
echo "vault-init: complete"

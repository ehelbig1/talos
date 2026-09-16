# vault-unseal-loop.sh — the `unsealer` sidecar in the chart's Vault StatefulSet
# (templates/vault/statefulset.yaml renders it with `.Files.Get`).
#
# Package BY (2026-09-16). Vault's seal state lives in process memory: a Vault
# pod that restarts (node reboot, eviction, OOM, upgrade) comes back SEALED.
# Measured on hashicorp/vault:1.18 with the chart's own init and unseal
# commands: sealed=false before a container restart, sealed=true after. The
# chart unsealed only from the vault-init Job, which runs at install / upgrade,
# so after any restart between upgrades every KEK wrap and unwrap failed once
# the controller's 5-minute DEK cache drained — and deploy/k3s/README.md said
# "unseal survives pod restart".
#
# This loop polls the co-located Vault over loopback and, when it is initialized
# and sealed, unseals it with the key in bootstrap.json. The key is read inside
# this container and reaches Vault on stdin (`key=-`), never on a command line
# and never in a log line.
#
# Stated limit: this is auto-unseal from a key on the same volume as the data.
# It restores availability; it does not separate the key from the data (see
# vault-init.sh).
set -u

KEY_FILE="${VAULT_BOOTSTRAP_FILE:-/vault/file/bootstrap.json}"
INTERVAL="${VAULT_UNSEAL_INTERVAL_SECS:-10}"
missing_logged=0

echo "vault-unsealer: watching the local Vault every ${INTERVAL}s"
while :; do
    status="$(vault status -format=json 2>/dev/null | tr -d '\n ')"
    case "$status" in
        *'"initialized":true'*)
            case "$status" in
                *'"sealed":true'*)
                    if [ -r "$KEY_FILE" ]; then
                        missing_logged=0
                        key="$(awk '/unseal_keys_b64/{f=1;next} /\]/{f=0} f' "$KEY_FILE" | sed -n 's/.*"\([^"]*\)".*/\1/p' | head -1)"
                        if [ -n "$key" ] && printf '%s' "$key" | vault write -format=json sys/unseal key=- >/dev/null 2>&1; then
                            echo "vault-unsealer: Vault was sealed; unsealed"
                        else
                            echo "vault-unsealer: Vault is sealed and the unseal attempt failed" >&2
                        fi
                        key=""
                    elif [ "$missing_logged" -eq 0 ]; then
                        echo "vault-unsealer: Vault is sealed and $KEY_FILE is not readable; waiting" >&2
                        missing_logged=1
                    fi
                    ;;
            esac
            ;;
    esac
    sleep "$INTERVAL"
done

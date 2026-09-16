#!/usr/bin/env bash
# Tests for the chart's Vault lifecycle scripts, against a REAL Vault.
#
#   deploy/helm/talos/files/vault-init.sh         (the vault-init Job body)
#   deploy/helm/talos/files/vault-unseal-loop.sh  (the Vault `unsealer` sidecar)
#
# Why (package BY, 2026-09-16): the chart's Vault came back SEALED after any
# pod restart and nothing re-unsealed it until the next upgrade; the init Job
# kept the root token in bootstrap.json forever and minted a new, unused,
# never-revoked controller token on every run. These scripts are shell against
# the Vault CLI, so the only test that means anything drives them against the
# pinned Vault image the chart ships. A fake `kubectl` on PATH plays the
# cluster (pod readiness, the bootstrap Secret, the controller Deployment);
# its `exec -i -c vault talos-vault-0 --` is forwarded to the container.
#
# Needs docker; SKIPS LOUDLY without it (CI: quality.yml `audit` job has it).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
INIT="$REPO/deploy/helm/talos/files/vault-init.sh"
LOOP="$REPO/deploy/helm/talos/files/vault-unseal-loop.sh"
IMAGE="$(awk '/^vault:/{v=1} v&&/repository:/{r=$2} v&&/tag:/{gsub(/"/,"",$2); t=$2} v&&/digest:/{gsub(/"/,"",$2); print r":"t"@"$2; exit}' "$REPO/deploy/helm/talos/values.yaml")"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    if [ "${TALOS_REQUIRE_DOCKER:-}" = 1 ]; then
        echo "✗ vault chart init test needs a docker daemon (TALOS_REQUIRE_DOCKER=1)" >&2
        exit 1
    fi
    echo "⊘ vault chart init test SKIPPED — no docker daemon (CI runs it with TALOS_REQUIRE_DOCKER=1)"
    exit 0
fi
[ -n "$IMAGE" ] && case "$IMAGE" in *@sha256:*) : ;; *) echo "✗ could not read the pinned vault image from values.yaml" >&2; exit 1 ;; esac

fails=0
check() { # check <label> <expected> <actual>
    if [ "$2" = "$3" ]; then printf '  ok   %s\n' "$1"; else printf '  FAIL %s\n       expected: %s\n       actual:   %s\n' "$1" "$2" "$3"; fails=$((fails+1)); fi
}

T="$(mktemp -d)"
NAME="talos-vault-init-test-$$"
completed=""
on_exit() {
    local st=$?
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker volume rm "$NAME" >/dev/null 2>&1 || true
    rm -rf "$T"
    if [[ -z "$completed" ]]; then
        echo "✗ vault chart init test stopped before its last check (status $st)" >&2
        exit 1
    fi
    exit "$st"
}
trap on_exit EXIT

# ── The fake cluster ──────────────────────────────────────────────────────────
mkdir -p "$T/bin" "$T/state"
cat > "$T/bin/kubectl" <<'SHIM'
#!/usr/bin/env bash
# Strip `-n <ns>`.
args=()
while [ $# -gt 0 ]; do
    if [ "$1" = "-n" ]; then shift 2; continue; fi
    args+=("$1"); shift
done
set -- "${args[@]}"
S="$KUBE_STATE"
case "$1 $2" in
  "get pod")
    case "$*" in
      *phase*) printf 'Running' ;;
      *ready*) printf 'true' ;;
    esac ;;
  "get secret")
    [ "${KUBE_SECRET_FAIL:-}" = 1 ] && exit 1
    cat "$S/secret_b64" 2>/dev/null || true ;;
  "patch secret")
    [ "${KUBE_PATCH_FAIL:-}" = 1 ] && exit 1
    payload=""
    while [ $# -gt 0 ]; do [ "$1" = "-p" ] && payload="$2"; shift; done
    printf '%s' "$payload" | sed -n 's/.*"VAULT_TOKEN":"\([^"]*\)".*/\1/p' > "$S/secret_b64"
    echo x >> "$S/secret_patches" ;;
  "get deployment") exit 0 ;;
  "patch deployment") echo x >> "$S/rollouts" ;;
  "exec -i")
    # The chart's exact exec shape, forwarded to the test container.
    [ "$3 $4 $5 $6" = "-c vault talos-vault-0 --" ] || { echo "fake kubectl: unexpected exec shape: $*" >&2; exit 98; }
    shift 6
    exec docker exec -i "$VAULT_CONTAINER" "$@" ;;
  *) echo "fake kubectl: unexpected call: $*" >&2; exit 97 ;;
esac
SHIM
chmod +x "$T/bin/kubectl"

run_init() {
    PATH="$T/bin:$PATH" KUBE_STATE="$T/state" \
    NAMESPACE=talos VAULT_POD=talos-vault-0 BOOTSTRAP_SECRET=talos-bootstrap \
    CONTROLLER_DEPLOY=talos-controller KEK_KEY=talos-kek \
    VAULT_CONTAINER="$NAME" \
    sh "$INIT" > "$T/init.log" 2>&1
}

vault_status() { docker exec "$NAME" vault status -format=json 2>/dev/null | tr -d '\n ' ; }
# Capture first: under pipefail, `grep -q` closing the pipe early fails the
# upstream `docker exec` and reads as "not sealed" (this test's own first bug).
sealed() { local st; st="$(vault_status)"; case "$st" in *'"sealed":true'*) echo true ;; *) echo false ;; esac; }

# A root token for the TEST's own inspection, generated from the unseal key.
test_root() {
    docker exec -i "$NAME" sh -c 'F=/vault/file/bootstrap.json; KEY=$(awk "/unseal_keys_b64/{f=1;next} /\]/{f=0} f" "$F" | sed -n "s/.*\"\([^\"]*\)\".*/\1/p" | head -1)
vault operator generate-root -cancel >/dev/null 2>&1 || true
OTP=$(vault operator generate-root -generate-otp)
NONCE=$(vault write -format=json sys/generate-root/attempt otp="$OTP" | tr -d "\n" | sed -n "s/.*\"nonce\":[[:space:]]*\"\([^\"]*\)\".*/\1/p")
ENC=$(printf "%s" "$KEY" | vault write -format=json sys/generate-root/update nonce="$NONCE" key=- | tr -d "\n" | sed -n "s/.*\"encoded_token\":[[:space:]]*\"\([^\"]*\)\".*/\1/p")
vault operator generate-root -decode="$ENC" -otp="$OTP"'
}
# Every live token, as "policies" lines, excluding the inspecting token itself.
live_tokens() { # live_tokens <inspecting root>
    printf '%s' "$1" | docker exec -i "$NAME" sh -c '
VAULT_TOKEN=$(cat); export VAULT_TOKEN
SELF=$(vault token lookup -format=json | tr -d "\n " | sed -n "s/.*\"accessor\":\"\([^\"]*\)\".*/\1/p")
for a in $(vault list -format=json auth/token/accessors | tr -d "[]\" " | tr "," " "); do
    [ "$a" = "$SELF" ] && continue
    vault token lookup -format=json -accessor "$a" | tr -d "\n " | sed -n "s/.*\"policies\":\[\([^]]*\)\].*/\1/p"
done | sort'
}
revoke() { printf '%s' "$1" | docker exec -i "$NAME" sh -c 'VAULT_TOKEN=$(cat); export VAULT_TOKEN; vault token revoke -self >/dev/null'; }
token_valid() { # token_valid <token>
    if printf '%s' "$1" | docker exec -i "$NAME" sh -c 'VAULT_TOKEN=$(cat); export VAULT_TOKEN; vault token lookup >/dev/null 2>&1'; then echo yes; else echo no; fi
}

# ── The Vault server ──────────────────────────────────────────────────────────
docker volume create "$NAME" >/dev/null
docker run -d --name "$NAME" -v "$NAME:/vault/file" -e VAULT_ADDR=http://127.0.0.1:8200 \
  -e 'VAULT_LOCAL_CONFIG={"storage":{"file":{"path":"/vault/file"}},"listener":[{"tcp":{"address":"127.0.0.1:8200","tls_disable":true}}],"disable_mlock":true,"api_addr":"http://127.0.0.1:8200"}' \
  "$IMAGE" server >/dev/null
for _ in $(seq 1 60); do [ -n "$(vault_status)" ] && break; sleep 1; done

echo "▶ first run on a fresh Vault"
printf '%s' "$(printf '__pending_vault_init__' | base64)" > "$T/state/secret_b64"
run_init && rc=0 || rc=$?
check "first run exits 0" 0 "$rc"
[ "$rc" = 0 ] || cat "$T/init.log"
check "vault is initialized and unsealed" '"initialized":true,"sealed":false' "$(vault_status | grep -o '"initialized":[a-z]*,"sealed":[a-z]*')"
check "bootstrap.json holds no root token" 0 "$(docker exec "$NAME" grep -c root_token /vault/file/bootstrap.json || true)"
check "bootstrap.json is owner-only" "-rw-------" "$(docker exec "$NAME" ls -l /vault/file/bootstrap.json | cut -c1-10)"
check "the Secret was patched once" 1 "$(wc -l < "$T/state/secret_patches" | tr -d ' ')"
check "the controller was rolled once" 1 "$(wc -l < "$T/state/rollouts" | tr -d ' ')"
CTRL="$(base64 -d < "$T/state/secret_b64")"
check "the patched token is valid" yes "$(token_valid "$CTRL")"
LOOKUP="$(printf '%s' "$CTRL" | docker exec -i "$NAME" sh -c 'VAULT_TOKEN=$(cat); export VAULT_TOKEN; vault token lookup -format=json' | tr -d '\n ')"
check "the patched token carries the talos-controller policy" '"default","talos-controller"' "$(printf '%s' "$LOOKUP" | sed -n 's/.*"policies":\[\([^]]*\)\].*/\1/p')"
check "the patched token is periodic (768h)" 2764800 "$(printf '%s' "$LOOKUP" | sed -n 's/.*"period":\([0-9]*\).*/\1/p')"
check "the patched token is an orphan" true "$(printf '%s' "$LOOKUP" | sed -n 's/.*"orphan":\([a-z]*\).*/\1/p')"
R="$(test_root)"
check "the only live token besides the test's is the controller's" '"default","talos-controller"' "$(live_tokens "$R")"
check "the transit KEK exists" yes "$(printf '%s' "$R" | docker exec -i "$NAME" sh -c 'VAULT_TOKEN=$(cat); export VAULT_TOKEN; vault read transit/keys/talos-kek >/dev/null 2>&1 && echo yes || echo no')"
revoke "$R"

echo "▶ second run with the Secret already set"
run_init && rc=0 || rc=$?
check "second run exits 0" 0 "$rc"
check "no second patch" 1 "$(wc -l < "$T/state/secret_patches" | tr -d ' ')"
check "no second rollout" 1 "$(wc -l < "$T/state/rollouts" | tr -d ' ')"
R="$(test_root)"
check "no token minted, no root token left behind" '"default","talos-controller"' "$(live_tokens "$R")"
revoke "$R"

echo "▶ a bootstrap.json written by an earlier chart (root token stored)"
LEGACY="$(test_root)"
docker exec -i "$NAME" sh -c 'F=/vault/file/bootstrap.json; TOK=$(cat); sed "\$d" "$F" | sed "\$s/\$/,/" > "$F.tmp"; printf "  \"root_token\": \"%s\"\n}\n" "$TOK" >> "$F.tmp"; mv "$F.tmp" "$F"; chmod 600 "$F"' <<< "$LEGACY"
check "(setup) the legacy file carries a root token" 1 "$(docker exec "$NAME" grep -c root_token /vault/file/bootstrap.json || true)"
run_init && rc=0 || rc=$?
check "legacy run exits 0" 0 "$rc"
check "the stored root token is revoked" no "$(token_valid "$LEGACY")"
check "the stored root token is removed from the file" 0 "$(docker exec "$NAME" grep -c root_token /vault/file/bootstrap.json || true)"
check "the rewritten file is still valid for unseal (key present)" 1 "$(docker exec "$NAME" grep -c unseal_keys_b64 /vault/file/bootstrap.json)"

echo "▶ a run whose Secret patch fails after minting"
printf '%s' "$(printf '__pending_vault_init__' | base64)" > "$T/state/secret_b64"
KUBE_PATCH_FAIL=1 run_init && rc=0 || rc=$?
check "the failing run exits non-zero" yes "$([ "$rc" != 0 ] && echo yes || echo no)"
R="$(test_root)"
check "neither the unused minted token nor the root token survives" '"default","talos-controller"' "$(live_tokens "$R")"
check "the first run's controller token is still valid" yes "$(token_valid "$CTRL")"
revoke "$R"

echo "▶ the unsealer sidecar after a Vault restart"
docker restart "$NAME" >/dev/null
for _ in $(seq 1 60); do [ -n "$(vault_status)" ] && break; sleep 1; done
check "(setup) a restarted Vault comes back sealed" true "$(sealed)"
docker cp "$LOOP" "$NAME:/tmp/vault-unseal-loop.sh" >/dev/null
docker exec -d -e VAULT_UNSEAL_INTERVAL_SECS=1 "$NAME" sh -c 'sh /tmp/vault-unseal-loop.sh > /tmp/unsealer.log 2>&1'
for _ in $(seq 1 20); do [ "$(sealed)" = false ] && break; sleep 1; done
check "the sidecar unsealed it" false "$(sealed)"
KEYVAL="$(docker exec "$NAME" sh -c 'awk "/unseal_keys_b64/{f=1;next} /\]/{f=0} f" /vault/file/bootstrap.json | sed -n "s/.*\"\([^\"]*\)\".*/\1/p" | head -1')"
check "the sidecar log never contains the key" 0 "$(docker exec "$NAME" grep -cF "$KEYVAL" /tmp/unsealer.log || true)"
check "the sidecar log says it unsealed" 1 "$(docker exec "$NAME" grep -c 'Vault was sealed; unsealed' /tmp/unsealer.log || true)"

echo "▶ the chart runs these files (TEXTUAL pin — a template that inlined its own script would bypass every check above)"
TPL="$REPO/deploy/helm/talos/templates/vault"
check "init-job.yaml renders files/vault-init.sh" 1 "$(grep -c '.Files.Get "files/vault-init.sh"' "$TPL/init-job.yaml")"
check "statefulset.yaml renders files/vault-unseal-loop.sh" 1 "$(grep -c '.Files.Get "files/vault-unseal-loop.sh"' "$TPL/statefulset.yaml")"
check "no vault CLI script inlined in the vault templates" 0 "$(grep -hvE '^[[:space:]]*#' "$TPL"/*.yaml | grep -cE 'vault (operator|write|token|policy|secrets)' || true)"

completed=1
if [ "$fails" -gt 0 ]; then
    echo "✗ $fails vault chart init check(s) failed"
    exit 1
fi
echo "✓ all vault chart init checks passed"

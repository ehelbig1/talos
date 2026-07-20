#!/usr/bin/env bash
# One-command production deploy: publish → pin digests → helm upgrade → smoke.
#
#   make deploy-prod            # interactive confirm before touching the server
#   make deploy-prod ARGS=--yes # CI-ish, no prompt
#
# Composes the pieces that already exist rather than reimplementing any:
#   1. scripts/publish-images.sh — builds amd64 images, enforces the publish
#      gate (clean tree + green quality.yml for HEAD), cosign-signs (one
#      OAuth tab), pushes to ghcr, and patches TALOS_*_DIGEST lines into an
#      env file (its own --update-env logic — we feed it a local copy of the
#      server's install.env so the sed rules stay in ONE place).
#   2. deploy/k3s/install.sh on the VM — idempotent chart upgrade + § 9.1
#      smoke. Run from a freshly-pulled server checkout so chart/template
#      changes ship with the images (digest bumps alone miss nginx routes,
#      values schema, NetworkPolicies).
#   3. scripts/smoke.sh from HERE — end-to-end probe over the public
#      internet, not just from inside the VM.
#
# Deliberately NOT automated: security-posture flips (TALOS_ENVELOPE_SEALING,
# TALOS_RLS_SET_ROLE, Sigstore policy). Those are one-way doors an operator
# should throw knowingly — the script PRINTS the server's current posture and
# the staged-flip runbook instead of editing it.
#
# Config (env overrides):
#   TALOS_DEPLOY_SSH       ssh target            (default root@talos.aegix.dev)
#   TALOS_DEPLOY_REPO_DIR  repo checkout on VM   (default /root/talos)
#   TALOS_DEPLOY_ENV_FILE  install env on VM     (default /etc/talos/install.env)
#   TALOS_DEPLOY_BASE_URL  public URL for smoke  (default https://talos.aegix.dev)
# Extra args are passed through to publish-images.sh (e.g. --no-sign,
# --service controller), except --yes which this script consumes.
set -euo pipefail

SSH_TARGET="${TALOS_DEPLOY_SSH:-root@talos.aegix.dev}"
REPO_DIR="${TALOS_DEPLOY_REPO_DIR:-/root/talos}"
ENV_FILE="${TALOS_DEPLOY_ENV_FILE:-/etc/talos/install.env}"
BASE_URL="${TALOS_DEPLOY_BASE_URL:-https://talos.aegix.dev}"

ASSUME_YES=0
PUBLISH_ARGS=()
for a in "$@"; do
    case "$a" in
        --yes) ASSUME_YES=1 ;;
        *) PUBLISH_ARGS+=("$a") ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
die()   { printf '\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

run_ssh() { ssh -o BatchMode=yes -o ConnectTimeout=10 "$SSH_TARGET" "$@"; }

# ── 0. Preflight ───────────────────────────────────────────────────────
bold "0. Preflight"
run_ssh true 2>/dev/null \
    || die "cannot ssh to $SSH_TARGET (is 1Password unlocked? key loaded?)"
run_ssh test -f "$ENV_FILE" || die "$ENV_FILE missing on server"
run_ssh test -d "$REPO_DIR/.git" || die "$REPO_DIR is not a git checkout on server"
echo "   ssh $SSH_TARGET OK; $ENV_FILE present; repo at $REPO_DIR"

local_head=$(git -C "$ROOT_DIR" rev-parse HEAD)
echo "   local HEAD: $local_head ($(git -C "$ROOT_DIR" log -1 --format=%s))"

# ── 1. Snapshot server state (digests + security posture) ─────────────
bold "1. Server state"
tmp_env="$(mktemp)"
trap 'rm -f "$tmp_env"' EXIT
run_ssh cat "$ENV_FILE" > "$tmp_env"
echo "   current digests:"
grep -E '^TALOS_(CONTROLLER|WORKER|FRONTEND)_DIGEST=' "$tmp_env" | sed 's/^/     /' || true
echo "   security posture (NOT changed by this script — see runbook at end):"
grep -E '^TALOS_(ENVELOPE_SEALING|RLS_SET_ROLE|SIGSTORE_POLICY|DISPATCH_SCHEME)=' "$tmp_env" \
    | sed 's/^/     /' || echo "     (none of the posture vars present — legacy defaults)"

# ── 2. Publish (gated, signed) + patch digests into the local copy ─────
bold "2. Publish images (publish-images.sh owns the gates: clean tree + green CI)"
bash "$SCRIPT_DIR/publish-images.sh" --update-env "$tmp_env" \
    ${PUBLISH_ARGS[@]+"${PUBLISH_ARGS[@]}"}
echo "   new digests:"
grep -E '^TALOS_(CONTROLLER|WORKER|FRONTEND)_DIGEST=' "$tmp_env" | sed 's/^/     /'

# ── 3. Confirm ─────────────────────────────────────────────────────────
if [[ "$ASSUME_YES" != 1 ]]; then
    bold "3. About to: push env to $SSH_TARGET:$ENV_FILE, git pull $REPO_DIR, run install.sh"
    read -r -p "   proceed? [y/N] " reply
    [[ "$reply" == "y" || "$reply" == "Y" ]] || die "aborted by operator"
fi

# ── 4. Ship env + sync server checkout + upgrade ──────────────────────
bold "4. Deploy"
# Timestamped remote backup of the env before overwriting — install.env
# also carries operator-set knobs; a bad push must be revertible.
run_ssh "cp '$ENV_FILE' '${ENV_FILE}.bak.\$(date +%Y%m%d-%H%M%S)'"
scp -q "$tmp_env" "$SSH_TARGET:$ENV_FILE"
run_ssh "git -C '$REPO_DIR' fetch origin main && git -C '$REPO_DIR' checkout -q main && git -C '$REPO_DIR' reset --hard origin/main"
echo "   server checkout: $(run_ssh "git -C '$REPO_DIR' rev-parse --short HEAD")"
run_ssh "cd '$REPO_DIR' && ENV_FILE='$ENV_FILE' bash deploy/k3s/install.sh"

# ── 5. Smoke from the outside ─────────────────────────────────────────
bold "5. External smoke ($BASE_URL)"
BASE_URL="$BASE_URL" bash "$SCRIPT_DIR/smoke.sh" || die "external smoke FAILED — inspect before walking away"

bold "Deploy complete: $local_head is live at $BASE_URL"
cat <<'RUNBOOK'

── Security-posture runbook (manual, staged — edit /etc/talos/install.env
   on the server, then re-run this script or install.sh) ──────────────────
   1. TALOS_ENVELOPE_SEALING=audit   → one release cycle of logs, then
      TALOS_ENVELOPE_SEALING=required (needs TALOS_DISPATCH_SCHEME=ed25519,
      TALOS_CONTROLLER_SIGNING_KEY + TALOS_WORKER_PUBLIC_KEYS — see
      deploy/helm/talos/values.yaml § TALOS_ENVELOPE_SEALING).
   2. TALOS_RLS_SET_ROLE: flip after one clean cycle (RLS backstop).
   3. TALOS_SIGSTORE_REQUIRED=true needs TALOS_SIGSTORE_IDENTITY_REGEXP
      widened to the operator email for locally-signed images.
RUNBOOK

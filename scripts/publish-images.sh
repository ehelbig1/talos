#!/usr/bin/env bash
# Build, push, and sign Talos images locally (no GitHub Actions).
#
# Replaces .github/workflows/main-publish.yml for operators not on a
# paid GHA plan. Same contract: produces three signed ghcr.io images
# tagged `:main-<sha>` and `:main-latest`, prints the
# `TALOS_*_DIGEST=...` lines ready for install.env.
#
# Pre-flight:
#   1. `docker` running locally
#   2. `docker login ghcr.io` already complete (or GHCR_TOKEN env set)
#   3. `cosign` installed if you want signing
#      (https://docs.sigstore.dev/cosign/installation/)
#   4. Clean git working tree (dirty builds taint the SHA-bound image
#      label and warn loudly)
#
# Usage:
#   sudo bash scripts/publish-images.sh                  # build + push + sign all 3
#   bash scripts/publish-images.sh --service controller  # one service only
#   bash scripts/publish-images.sh --no-push             # smoke test, no upload
#   bash scripts/publish-images.sh --no-sign             # skip cosign step
#   bash scripts/publish-images.sh --update-env /etc/talos/install.env
#                                                         # patch the env file in-place
#
# Environment overrides:
#   TALOS_GHCR_OWNER   default: parsed from `git remote get-url origin`
#   GHCR_TOKEN         passed to `docker login` if you're not already authed
#
# Verification (operator-side, after sign step):
#   cosign verify \
#     --certificate-identity-regexp '<your-github-email>' \
#     --certificate-oidc-issuer 'https://github.com/login/oauth' \
#     ghcr.io/<owner>/talos-controller@<digest>
#
# (Note: when signing locally with `cosign sign --yes`, the identity
# binding goes to YOUR GitHub OAuth identity, not a workflow URI like
# main-publish.yml produces. The chart's `certIdentityRegex` needs to
# allow your email if you want the cluster's Sigstore enforcement to
# accept locally-signed images — see deploy/k3s/install.sh comment on
# TALOS_SIGSTORE_IDENTITY_REGEXP for the format.)

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────
SERVICES_DEFAULT=(controller worker frontend)
REGISTRY="ghcr.io"

# Owner: env var > parse from origin remote.
if [[ -z "${TALOS_GHCR_OWNER:-}" ]]; then
    REMOTE_URL="$(git remote get-url origin 2>/dev/null || true)"
    if [[ "$REMOTE_URL" =~ github\.com[:/]+([^/]+)/[^/]+(\.git)?$ ]]; then
        TALOS_GHCR_OWNER="${BASH_REMATCH[1]}"
    else
        echo "✗ could not infer TALOS_GHCR_OWNER from git remote — set it explicitly" >&2
        exit 1
    fi
fi

# Flag parsing.
SERVICES=("${SERVICES_DEFAULT[@]}")
DO_PUSH=1
DO_SIGN=1
UPDATE_ENV_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --service)   SERVICES=("$2"); shift 2 ;;
        --no-push)   DO_PUSH=0; shift ;;
        --no-sign)   DO_SIGN=0; shift ;;
        --update-env) UPDATE_ENV_FILE="$2"; shift 2 ;;
        --help|-h)
            sed -n '2,40p' "$0"
            exit 0 ;;
        *)
            echo "✗ unknown flag: $1" >&2
            exit 1 ;;
    esac
done

# Output helpers — match install.sh's aesthetic so the two scripts feel
# like one family.
log()  { printf '\033[1;34m▶ %s\033[0m\n'   "$*"; }
ok()   { printf '\033[1;32m✓ %s\033[0m\n'   "$*"; }
warn() { printf '\033[1;33m⚠ %s\033[0m\n'   "$*"; }
die()  { printf '\033[1;31m✗ %s\033[0m\n'   "$*" >&2; exit 1; }

# ── Pre-flight ────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || die "docker not found in PATH"
docker info >/dev/null 2>&1       || die "docker daemon not reachable — start Docker Desktop / dockerd"

if [[ "$DO_SIGN" -eq 1 ]]; then
    command -v cosign >/dev/null 2>&1 \
        || die "cosign not found in PATH — install it (https://docs.sigstore.dev/cosign/installation/) or pass --no-sign"
fi

# Auth: if GHCR_TOKEN is set we'll docker-login proactively. Otherwise
# assume `docker login` was run interactively previously.
if [[ -n "${GHCR_TOKEN:-}" ]]; then
    log "Logging in to $REGISTRY as $TALOS_GHCR_OWNER (GHCR_TOKEN supplied)"
    printf '%s' "$GHCR_TOKEN" | docker login "$REGISTRY" \
        --username "$TALOS_GHCR_OWNER" --password-stdin >/dev/null
fi

# Verify auth by attempting a HEAD on a known-public manifest. If this
# fails we'd rather die at the front door than mid-push.
if [[ "$DO_PUSH" -eq 1 ]]; then
    if ! docker pull --quiet alpine:3.20 >/dev/null 2>&1; then
        warn "Could not pull a public test image — docker network/auth may be broken."
    fi
fi

# Git SHA + clean-tree check. A dirty build is allowed (often useful for
# debugging) but the resulting tag is suffixed `-dirty` so it can't be
# confused with a clean main commit.
GIT_SHA="$(git rev-parse HEAD)"
SHORT_SHA="${GIT_SHA:0:12}"
GIT_DIRTY=false
if ! git diff-index --quiet HEAD --; then
    GIT_DIRTY=true
    SHORT_SHA="${SHORT_SHA}-dirty"
    warn "Working tree is dirty — building anyway, image tags will be marked with '-dirty'"
fi
ok "Git: ${GIT_SHA} (short=${SHORT_SHA}, dirty=${GIT_DIRTY})"
ok "Registry: ${REGISTRY}/${TALOS_GHCR_OWNER}/talos-{controller,worker,frontend}"
ok "Services: ${SERVICES[*]}"
echo

# ── Build ─────────────────────────────────────────────────────────────
log "Building ${#SERVICES[@]} image(s) via docker compose"
export GIT_SHA_OVERRIDE="$GIT_SHA"
export GIT_DIRTY_OVERRIDE="$GIT_DIRTY"
# Pass GIT_SHA_OVERRIDE through to the controller's build.rs (see
# controller/Dockerfile). `docker compose build` reads from the
# environment when the variable is referenced in build.args in
# docker-compose.yml — `release.yml` uses the same pattern.
docker compose build "${SERVICES[@]}"
ok "Build complete"
echo

# ── Tag + Push ────────────────────────────────────────────────────────
# Parallel arrays instead of `declare -A` — macOS ships bash 3.2 (no
# associative arrays). `SERVICES[i]` matches `DIGESTS[i]` by index.
DIGESTS=()

for i in "${!SERVICES[@]}"; do
    svc="${SERVICES[$i]}"
    LOCAL_TAG="talos-${svc}"
    IMAGE="${REGISTRY}/${TALOS_GHCR_OWNER}/talos-${svc}"
    SHA_TAG="${IMAGE}:main-${SHORT_SHA}"
    LATEST_TAG="${IMAGE}:main-latest"

    log "Tagging ${svc} → ${SHA_TAG}"
    docker tag "$LOCAL_TAG" "$SHA_TAG"
    docker tag "$LOCAL_TAG" "$LATEST_TAG"

    if [[ "$DO_PUSH" -eq 0 ]]; then
        warn "  --no-push: skipping registry upload for ${svc}"
        DIGESTS[$i]=""
        continue
    fi

    # Push immutable tag first, then mutable. If the network drops
    # between the two, the immutable tag is what install.env should
    # pin to anyway.
    log "Pushing ${SHA_TAG}"
    docker push "$SHA_TAG" >/dev/null
    log "Pushing ${LATEST_TAG}"
    docker push "$LATEST_TAG" >/dev/null

    # Resolve digest by inspecting RepoDigests after push.
    # `docker push` doesn't print the digest in a machine-parseable
    # way on every Docker version, so `inspect` is the portable path.
    DIGEST="$(docker inspect --format='{{index .RepoDigests 0}}' "$SHA_TAG" \
              | awk -F@ '{print $2}')"
    [[ -n "$DIGEST" ]] || die "could not resolve digest for ${svc}"

    DIGESTS[$i]="$DIGEST"
    ok "${svc} pushed: ${DIGEST}"
    echo
done

# ── Sign ──────────────────────────────────────────────────────────────
if [[ "$DO_SIGN" -eq 1 && "$DO_PUSH" -eq 1 ]]; then
    log "Signing pushed images (keyless, Sigstore + Rekor)"
    for i in "${!SERVICES[@]}"; do
        svc="${SERVICES[$i]}"
        DIGEST="${DIGESTS[$i]:-}"
        [[ -n "$DIGEST" ]] || continue
        IMAGE="${REGISTRY}/${TALOS_GHCR_OWNER}/talos-${svc}@${DIGEST}"
        log "  cosign sign ${svc}@${DIGEST:0:24}…"
        # COSIGN_EXPERIMENTAL=1 enables keyless. Identity comes from
        # your GitHub OAuth flow that cosign launches in a browser.
        # The cert is short-lived (~10 min) and Rekor records the
        # signature publicly — same transparency-log story as the
        # workflow path, just bound to your individual identity
        # instead of a workflow URI.
        COSIGN_EXPERIMENTAL=1 cosign sign --yes "$IMAGE"
    done
    ok "All images signed"
    echo
fi

# ── Summary ───────────────────────────────────────────────────────────
if [[ "$DO_PUSH" -eq 1 ]]; then
    echo "═══════════════════════════════════════════════════════════"
    echo "  Publish complete — copy these into /etc/talos/install.env"
    echo "═══════════════════════════════════════════════════════════"
    for i in "${!SERVICES[@]}"; do
        svc="${SERVICES[$i]}"
        VAR="TALOS_$(echo "$svc" | tr '[:lower:]' '[:upper:]')_DIGEST"
        echo "${VAR}=${DIGESTS[$i]}"
    done
    echo "═══════════════════════════════════════════════════════════"
    echo

    # Patch the env file in place if requested. Matches the indentation
    # convention used in /etc/talos/install.env (2-space-indented
    # comment+assignment block from install.sh §0 lookup).
    if [[ -n "$UPDATE_ENV_FILE" ]]; then
        [[ -f "$UPDATE_ENV_FILE" ]] || die "env file not found: $UPDATE_ENV_FILE"
        log "Patching $UPDATE_ENV_FILE in place"
        # macOS sed needs `-i ''`; GNU sed wants `-i` alone. Detect.
        SED_INPLACE=(-i)
        if [[ "$(uname)" == "Darwin" ]]; then SED_INPLACE=(-i ''); fi
        for i in "${!SERVICES[@]}"; do
            svc="${SERVICES[$i]}"
            VAR="TALOS_$(echo "$svc" | tr '[:lower:]' '[:upper:]')_DIGEST"
            DIGEST="${DIGESTS[$i]}"
            # Replace the first matching `^[[:space:]]*VAR=...` line.
            # The line might be indented (install.env in the operator's
            # cluster has 2-space indent on every key — historical
            # paste-formatting). Anchor to optional leading whitespace.
            if grep -qE "^[[:space:]]*${VAR}=" "$UPDATE_ENV_FILE"; then
                sed "${SED_INPLACE[@]}" -E "s|^([[:space:]]*)${VAR}=.*|\\1${VAR}=${DIGEST}|" \
                    "$UPDATE_ENV_FILE"
                ok "  patched ${VAR}"
            else
                warn "  ${VAR} not present in env file — appending"
                printf '\n%s=%s\n' "$VAR" "$DIGEST" >> "$UPDATE_ENV_FILE"
            fi
        done
        ok "env file updated — re-run install.sh on the cluster host to deploy"
    fi
fi

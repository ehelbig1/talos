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
#   3. `cosign` installed (signing is ON by default; pass --no-sign to skip)
#      (https://docs.sigstore.dev/cosign/installation/)
#   4. Clean git working tree (dirty publishes are REFUSED; --allow-dirty
#      to override for debugging, tags get a `-dirty` suffix)
#   5. `gh` CLI authed — the publish gate verifies a green quality.yml
#      run exists for HEAD before pushing (--skip-ci-check to override)
#
# Usage:
#   bash scripts/publish-images.sh                       # build + push + sign
#   bash scripts/publish-images.sh --service controller  # one service only
#   bash scripts/publish-images.sh --no-push             # smoke test, no upload
#   bash scripts/publish-images.sh --no-sign             # skip cosign signing
#   bash scripts/publish-images.sh --update-env /etc/talos/install.env
#                                                         # patch the env file in-place
#
# Signing default: ON (flipped 2026-07-01; was OFF since 2026-05-20).
# Rationale for the flip: provenance should be the default act and
# skipping it the deliberate one. The batched flow signs all images in
# ONE cosign invocation (one browser tab), so the old 3-tab cost that
# justified default-OFF is gone. Operators without cosign or without
# Sigstore enforcement pass `--no-sign` explicitly.
#
# Publish gate (2026-07-01): pushing requires (a) a clean tree and (b) a
# green quality.yml conclusion for HEAD, checked via `gh run list`.
# Nothing else stands between a local build and a production image —
# these two checks are the CI-parity seam for the local-canonical path.
#
# Environment overrides:
#   TALOS_GHCR_OWNER               default: parsed from `git remote get-url origin`
#   GHCR_TOKEN                     passed to `docker login` if you're not already authed
#   TALOS_PUBLISH_SIGN=0           disable signing without passing --no-sign every time
#   TALOS_PUBLISH_ALLOW_DIRTY=1    same as --allow-dirty
#   TALOS_PUBLISH_SKIP_CI_CHECK=1  same as --skip-ci-check
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
# Sign-by-default: ON (2026-07-01). History: default-OFF (2026-05-20)
# was justified by the 3-tab OAuth cascade, but the batched single-call
# flow removed that cost, and a codebase review flagged that the typical
# publish shipping with NO cryptographic provenance inverted the right
# default. Signing is now the default act; `--no-sign` (or
# TALOS_PUBLISH_SIGN=0) is the deliberate opt-out.
DO_SIGN=1
if [[ "${TALOS_PUBLISH_SIGN:-1}" == "0" ]]; then
    DO_SIGN=0
fi
# Publish gate defaults: refuse dirty trees, require a green quality.yml
# run for HEAD. Both overridable — explicitly, so the bypass shows up in
# shell history / terminal scrollback rather than happening silently.
ALLOW_DIRTY="${TALOS_PUBLISH_ALLOW_DIRTY:-0}"
REQUIRE_CI="$([[ "${TALOS_PUBLISH_SKIP_CI_CHECK:-0}" == "1" ]] && echo 0 || echo 1)"
UPDATE_ENV_FILE=""
# Default to linux/amd64 because the production k3s VM is x86_64.
# Apple-Silicon Macs default Docker to linux/arm64; building without
# explicit platform produces images the VM can't exec — symptom is
# `exec /usr/local/cargo/bin/sqlx: exec format error` in the
# migrations Job. Override via --platform if you're targeting a
# different cluster arch.
PLATFORM="linux/amd64"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --service)   SERVICES=("$2"); shift 2 ;;
        --no-push)   DO_PUSH=0; shift ;;
        --no-sign)   DO_SIGN=0; shift ;;
        --sign)      DO_SIGN=1; shift ;;
        --allow-dirty)   ALLOW_DIRTY=1; shift ;;
        --skip-ci-check) REQUIRE_CI=0; shift ;;
        --update-env) UPDATE_ENV_FILE="$2"; shift 2 ;;
        --platform)  PLATFORM="$2"; shift 2 ;;
        --help|-h)
            sed -n '2,44p' "$0"
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

# Git SHA + clean-tree check. Publishing from a dirty tree is REFUSED by
# default — the pushed image would contain changes no commit records, so
# digest-pinning in install.env stops meaning "this code". --allow-dirty
# keeps the old debugging escape hatch; the tag still gets a `-dirty`
# suffix so it can't be confused with a clean main commit.
GIT_SHA="$(git rev-parse HEAD)"
SHORT_SHA="${GIT_SHA:0:12}"
GIT_DIRTY=false
if ! git diff-index --quiet HEAD --; then
    if [[ "$ALLOW_DIRTY" != "1" ]]; then
        die "Working tree is dirty — commit or stash first. (--allow-dirty to build anyway; tags get a '-dirty' suffix and must not be deployed to production.)"
    fi
    GIT_DIRTY=true
    SHORT_SHA="${SHORT_SHA}-dirty"
    warn "Working tree is dirty (--allow-dirty) — image tags will be marked with '-dirty'"
fi
ok "Git: ${GIT_SHA} (short=${SHORT_SHA}, dirty=${GIT_DIRTY})"
ok "Registry: ${REGISTRY}/${TALOS_GHCR_OWNER}/talos-{controller,worker,frontend}"
ok "Services: ${SERVICES[*]}"
ok "Platform: ${PLATFORM}"
echo

# ── CI-green gate ─────────────────────────────────────────────────────
# The local publish path has no CI between code and a production image;
# quality.yml (full test suite + integration tests + RUSTSEC scan) runs
# on PRs and nightly, but nothing previously verified the image being
# pushed came from a commit that PASSED it. Require a successful
# quality.yml conclusion for HEAD before pushing. Skipped for --no-push
# (smoke builds publish nothing). Override: --skip-ci-check /
# TALOS_PUBLISH_SKIP_CI_CHECK=1 — an explicit act, by design.
if [[ "$DO_PUSH" -eq 1 && "$REQUIRE_CI" -eq 1 ]]; then
    command -v gh >/dev/null 2>&1 \
        || die "gh CLI not found — cannot verify quality.yml passed for HEAD. Install gh (https://cli.github.com) or pass --skip-ci-check."
    log "Checking for a green quality.yml run for ${SHORT_SHA}"
    GREEN_RUNS="$(gh run list --workflow quality.yml --commit "$GIT_SHA" \
                    --json conclusion --jq '[.[] | select(.conclusion == "success")] | length' \
                    2>/dev/null)" \
        || die "could not query GitHub Actions (gh not authed / offline?). Fix gh auth or pass --skip-ci-check."
    if [[ "${GREEN_RUNS:-0}" -lt 1 ]]; then
        die "no successful quality.yml run found for HEAD (${GIT_SHA}).
  Trigger one:   gh workflow run quality.yml --ref $(git rev-parse --abbrev-ref HEAD)
  Then re-run this script once it's green (gh run watch).
  Deliberate bypass: --skip-ci-check"
    fi
    ok "quality.yml green for HEAD (${GREEN_RUNS} successful run(s))"
    echo
fi

# ── RustSec advisory pre-flight ───────────────────────────────────────
# A vulnerable dependency reaching production is the real harm `cargo audit`
# prevents, and the publish step is the last point before it ships. This is the
# same advisory scan `make audit` (cargo-deny) and lint check 36 run; surfacing
# it HERE catches a vulnerable dep — or a freshly-published advisory against an
# existing one (e.g. RUSTSEC-2026-0149 in wasmtime, fixed 2026-06-01) — at the
# ship boundary. WARN-only by default to honour the operator-responsibility
# model (the dirty-tree check above warns rather than blocks). Set
# TALOS_PUBLISH_REQUIRE_AUDIT=1 to make a vulnerability abort the publish.
if command -v cargo-audit >/dev/null 2>&1; then
    if cargo audit >/dev/null 2>&1; then
        ok "cargo audit: no RustSec advisories"
    elif [ "${TALOS_PUBLISH_REQUIRE_AUDIT:-0}" = "1" ]; then
        die "cargo audit found a vulnerable dependency (TALOS_PUBLISH_REQUIRE_AUDIT=1). \
Run \`cargo audit\` for details; fix or downgrade before publishing."
    else
        warn "cargo audit found a vulnerable dependency — building/pushing anyway."
        warn "  Run \`cargo audit\` for the advisory + fixed-version range, or set"
        warn "  TALOS_PUBLISH_REQUIRE_AUDIT=1 to make this abort the publish."
    fi
else
    warn "cargo-audit not installed — skipping the RustSec advisory pre-flight."
    warn "  Install: cargo install cargo-audit --locked (or run \`make audit\`)."
fi
echo

# ── Build ─────────────────────────────────────────────────────────────
log "Building ${#SERVICES[@]} image(s) for ${PLATFORM}"

# DOCKER_DEFAULT_PLATFORM forces BuildKit to produce images for the
# specified target arch regardless of host arch. On Apple Silicon this
# means QEMU-emulated x86_64 compilation — slower (~3x cold) but
# necessary because the production VM is x86_64. See PLATFORM block
# in flag parsing for the rationale.
export DOCKER_DEFAULT_PLATFORM="$PLATFORM"

export GIT_SHA_OVERRIDE="$GIT_SHA"
export GIT_DIRTY_OVERRIDE="$GIT_DIRTY"

# Build each service. Most use `docker compose build` (picks up build
# args from docker-compose.yml), but the frontend gets a separate
# `docker build` against frontend/Dockerfile (production) — the
# compose file points the frontend service at Dockerfile.dev for
# local-dev `docker compose up` (Vite hot-reload), which is the
# wrong mode for production:
#   * vite --host 0.0.0.0 wants to write to /app/node_modules/.vite-temp
#     but our chart sets readOnlyRootFilesystem=true → ENOENT
#   * no minification, no production assets, ships dev-only HMR
#     overhead to every client
# The prod Dockerfile does `npm run build` then serves the static
# bundle via nginx — the correct production shape.
COMPOSE_SERVICES=()
NEEDS_FRONTEND_BUILD=0
for svc in "${SERVICES[@]}"; do
    if [[ "$svc" == "frontend" ]]; then
        NEEDS_FRONTEND_BUILD=1
    else
        COMPOSE_SERVICES+=("$svc")
    fi
done

if [[ ${#COMPOSE_SERVICES[@]} -gt 0 ]]; then
    docker compose build "${COMPOSE_SERVICES[@]}"
fi

if [[ "$NEEDS_FRONTEND_BUILD" -eq 1 ]]; then
    log "Building frontend separately (prod Dockerfile, not Dockerfile.dev)"
    docker build \
        --platform "$PLATFORM" \
        -f frontend/Dockerfile \
        -t talos-frontend \
        frontend/
fi
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
# Batched-sign: pass ALL image@digest refs to a single `cosign sign`
# invocation. Cosign keyless does ONE OAuth flow up-front, then
# issues a fresh Fulcio cert per image (each cert is bound to the
# same OAuth identity). The previous one-call-per-image loop opened
# THREE browser tabs for a 3-service publish — annoying after the
# first publish, infuriating on the tenth.
#
# Fallback: if the operator's cosign version is too old to accept
# multiple image args, we fall back to the per-image loop. cosign
# has supported batched signing since v2.0 (Sep 2023); the chart's
# pinned 2.4.1 in worker/Dockerfile, so the modern path is the
# common case.
if [[ "$DO_SIGN" -eq 1 && "$DO_PUSH" -eq 1 ]]; then
    SIGN_REFS=()
    for i in "${!SERVICES[@]}"; do
        svc="${SERVICES[$i]}"
        DIGEST="${DIGESTS[$i]:-}"
        [[ -n "$DIGEST" ]] || continue
        SIGN_REFS+=("${REGISTRY}/${TALOS_GHCR_OWNER}/talos-${svc}@${DIGEST}")
    done
    if [[ ${#SIGN_REFS[@]} -eq 0 ]]; then
        warn "No digests to sign — push must have been skipped"
    else
        log "Signing ${#SIGN_REFS[@]} image(s) in a single cosign call (keyless, Sigstore + Rekor)"
        # COSIGN_EXPERIMENTAL=1 enables keyless. Identity comes from
        # your GitHub OAuth flow that cosign launches in a browser —
        # ONCE — and the token gets reused across every image in this
        # invocation. The cert per image is short-lived (~10 min) and
        # Rekor records each signature publicly.
        if ! COSIGN_EXPERIMENTAL=1 cosign sign --yes "${SIGN_REFS[@]}"; then
            warn "Batched cosign sign failed — falling back to per-image loop"
            warn "(this WILL open one browser tab per image)"
            for ref in "${SIGN_REFS[@]}"; do
                log "  cosign sign $ref"
                COSIGN_EXPERIMENTAL=1 cosign sign --yes "$ref"
            done
        fi
        ok "${#SIGN_REFS[@]} image(s) signed"
        echo
    fi
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

#!/usr/bin/env bash
# Release builder for the Talos controller + worker images.
#
# Why this exists: `docker compose build` defaults to the host architecture.
# On Apple Silicon developer machines that produces linux/arm64 images, which
# fail at runtime on the linux/amd64 prod node with "exec format error" — and
# the failure manifests as a Helm pre-upgrade hook timing out with no logs
# (the failed pod is GC'd before kubectl can read it). This script forces
# linux/amd64 via `docker buildx --platform`, pushes both the version tag and
# `:latest`, and writes the resulting registry digests to a file so the
# install.env update is mechanical instead of "did I copy the right sha256?".
#
# Usage:
#   scripts/release.sh VERSION [SERVICE...]
#
# VERSION   — required, e.g. 1.0.0-r225 (no leading "v"; matches Cargo.toml)
# SERVICE   — optional, one or more of: controller worker frontend
#             defaults to: controller worker
#
# Required env (or auto-detected):
#   TALOS_GHCR_OWNER  — defaults to the GitHub owner derived from `git remote
#                       get-url origin`. Override to push to a different namespace.
#
# Outputs:
#   release-digests.txt — machine-readable digests for the version tag.
#                         Format:
#                           controller=ghcr.io/OWNER/talos-controller@sha256:...
#                           worker=ghcr.io/OWNER/talos-worker@sha256:...
#
# Pre-flight checks:
#   * `docker buildx ls` includes a builder that supports linux/amd64
#   * Logged in to ghcr.io (~/.docker/config.json has an entry)
#   * VERSION matches the controller/Cargo.toml `version` field — the most
#     common release-script footgun is a stale Cargo.toml producing an image
#     whose internal version doesn't match its tag.
#
# Exit codes:
#   0  — every requested service built + pushed; digests written
#   1  — pre-flight failed (not built)
#   2  — build/push failure (partial state possible — see release-digests.txt)

set -euo pipefail

# ── Args ─────────────────────────────────────────────────────────────────────
VERSION="${1:-}"
shift || true

# MCP-1214 (2026-05-18): support `--auto` to derive SERVICES from git
# diff against the previously-released SHA. Pre-fix, callers who
# omitted services got the static `controller worker` default — over-
# building when only one side changed AND silently failing to rebuild
# the worker when ONLY shared crates / `worker/src/*` changed (the
# MCP-1213 deploy was a real example: the user redeployed expecting
# the worker fix to land, but the deploy script only kicked the
# controller because that was the most recent surface they touched).
# `--auto` walks `git diff <previous-release-sha>..HEAD` against a
# parsed-from-Cargo.toml map of which crate-dirs link into which
# binary and rebuilds exactly the affected images. Existing CI / manual
# `scripts/release.sh VERSION controller worker frontend` invocations
# are unaffected — auto-detect only fires when SERVICES is empty AND
# `--auto` is passed (or, as a safety, when `release-digests.txt`
# carries the previous SHA and SERVICES is empty).
AUTO_DETECT=0
SINCE_SHA=""
SERVICES=()
for arg in "$@"; do
    case "$arg" in
        --auto)
            AUTO_DETECT=1
            ;;
        --since=*)
            SINCE_SHA="${arg#--since=}"
            AUTO_DETECT=1
            ;;
        --*)
            echo "✗ Unknown flag: $arg" >&2
            echo "  Valid flags: --auto, --since=<sha>" >&2
            exit 1
            ;;
        *)
            SERVICES+=("$arg")
            ;;
    esac
done

if [ -z "$VERSION" ]; then
    cat <<'EOF' >&2
Usage: scripts/release.sh VERSION [SERVICE...] [--auto] [--since=<sha>]
  VERSION       e.g. 1.0.0-r225 (must match controller/Cargo.toml)
  SERVICE       optional; defaults to: controller worker
                valid: controller worker frontend
  --auto        derive SERVICES from `git diff <since>..HEAD` (since
                defaults to the `# Git:` line in release-digests.txt,
                or HEAD~1 if absent).  Mutually exclusive with explicit
                SERVICE args — if both are passed, explicit wins.
  --since=<sha> override the diff base; implies --auto.
Examples:
  scripts/release.sh 1.0.0-r225
  scripts/release.sh 1.0.0-r225 --auto
  scripts/release.sh 1.0.0-r225 --since=v1.0.0-r224
  scripts/release.sh 1.0.0-r225 controller
  scripts/release.sh 1.0.0-r225 controller worker frontend
EOF
    exit 1
fi

# ── Config ───────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DIGESTS_FILE="$REPO_ROOT/release-digests.txt"
PLATFORM="${PLATFORM:-linux/amd64}"
BUILDER="${TALOS_BUILDX_BUILDER:-talos-build}"

# Auto-detect GHCR owner from git remote unless overridden. Lowercase per
# OCI registry naming rules — uppercase paths are rejected by ghcr.
if [ -z "${TALOS_GHCR_OWNER:-}" ]; then
    remote=$(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null || true)
    detected=$(echo "$remote" | sed -nE 's|.*github\.com[:/]([^/]+)/.*|\1|p' | tr '[:upper:]' '[:lower:]')
    if [ -z "$detected" ]; then
        echo "✗ TALOS_GHCR_OWNER not set and could not derive from git remote" >&2
        echo "  Set TALOS_GHCR_OWNER=<gh-owner> or run from a git checkout" >&2
        exit 1
    fi
    TALOS_GHCR_OWNER="$detected"
fi

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

# ── Auto-detect services (MCP-1214) ──────────────────────────────────────────
# `--auto` walks `git diff <SINCE_SHA>..HEAD` (across BOTH the talos
# repo AND the sibling talos-workflow-engine repo) and maps each
# changed path to the binary that links it. Returns a sorted, deduped
# space-separated list to stdout. Returns empty stdout when nothing
# requires a rebuild (e.g., docs-only change); caller surfaces an
# error if that means "nothing to build".
#
# Mapping table:
#   worker/*                          → worker
#   controller/*                      → controller
#   frontend/*                        → frontend
#   migrations/*                      → controller (sqlx-prepare bakes against schema)
#   wit/*, module-templates/*         → controller (template bundling)
#   Cargo.toml, Cargo.lock, rust-toolchain.toml → controller AND worker
#   <crate-dir>                       → derived from worker/Cargo.toml's path-deps
#                                       — worker-linked crates rebuild BOTH (controller
#                                       transitively includes most of them), other
#                                       talos-* crates rebuild controller only
#   .github/*, docs/*, deploy/*, scripts/*, tests/*  → no rebuild
#   ../talos-workflow-engine/*        → controller AND worker (both link the engine)
parse_worker_path_deps() {
    # Parse `talos-foo = { path = "../talos-foo" }` from worker/Cargo.toml.
    # Outputs one REPO_ROOT-relative directory name per line. Sibling-repo
    # deps (`path = "../../talos-workflow-engine/..."`) are intentionally
    # EXCLUDED — they're handled by the separate engine-repo diff branch
    # below, and matching `../../...` against a talos-repo-relative diff
    # path would never hit anyway.
    sed -nE 's|^talos-[a-z-]+ = \{ path = "\.\./([a-zA-Z][^"]*)".*|\1|p' \
        "$REPO_ROOT/worker/Cargo.toml" | sort -u
}

detect_services_from_diff() {
    local since="$1"
    local since_engine="$2"
    local changed_talos=""
    local changed_engine=""

    if ! changed_talos=$(git -C "$REPO_ROOT" diff --name-only "$since"..HEAD 2>&1); then
        err "git diff $since..HEAD failed: $changed_talos"
        return 1
    fi

    if [ -d "$REPO_ROOT/../talos-workflow-engine/.git" ]; then
        if [ -z "$since_engine" ]; then
            # First-run / pre-MCP-1214 release-digests.txt: no engine SHA
            # recorded. Fall back to rebuilding BOTH binaries — safe over-
            # rebuild matches the pre-fix default behaviour rather than
            # risk missing an engine change (e.g., a `signing_payload()`
            # field add that requires coordinated controller+worker
            # restart per the wire-format-stability rule). On the NEXT
            # release this script will write the engine SHA, after which
            # subsequent invocations get the tighter diff.
            changed_engine="UNKNOWN_FORCES_BOTH"
        elif git -C "$REPO_ROOT/../talos-workflow-engine" rev-parse --verify --quiet "$since_engine" >/dev/null; then
            changed_engine=$(git -C "$REPO_ROOT/../talos-workflow-engine" diff --name-only "$since_engine"..HEAD 2>/dev/null || true)
        else
            warn "Engine SHA '$since_engine' not in ../talos-workflow-engine — assuming both binaries need rebuild"
            changed_engine="UNKNOWN_FORCES_BOTH"
        fi
    fi

    local worker_deps=()
    while IFS= read -r dep; do
        [ -n "$dep" ] && worker_deps+=("$dep")
    done < <(parse_worker_path_deps)

    local need_controller=0 need_worker=0 need_frontend=0

    while IFS= read -r path; do
        [ -z "$path" ] && continue
        case "$path" in
            worker/*)                  need_worker=1 ;;
            controller/*)              need_controller=1 ;;
            frontend/*)                need_frontend=1 ;;
            migrations/*)              need_controller=1 ;;
            wit/*|module-templates/*)  need_controller=1 ;;
            Cargo.toml|Cargo.lock|rust-toolchain.toml)
                need_controller=1; need_worker=1
                ;;
            .github/*|docs/*|deploy/*|scripts/*|tests/*|drills/*|load-test/*|soc2/*|README*|CHANGELOG*|LICENSE*)
                # No rebuild — meta / deploy / docs / test scaffolding.
                ;;
            *)
                # Walk the worker's path-dep list. A match here means BOTH
                # binaries link the crate, so both rebuild. Otherwise, if
                # it looks like a workspace crate (`talos-*/` prefix), it's
                # controller-only.
                local matched=0
                for dep in "${worker_deps[@]}"; do
                    if [ "$path" = "$dep" ] || [[ "$path" == "$dep"/* ]]; then
                        need_worker=1
                        need_controller=1
                        matched=1
                        break
                    fi
                done
                if [ "$matched" = "0" ]; then
                    case "$path" in
                        talos-*) need_controller=1 ;;
                    esac
                fi
                ;;
        esac
    done <<< "$changed_talos"

    # Workflow-engine sibling repo: any change rebuilds BOTH (controller and
    # worker both link the engine crates).
    if [ -n "$changed_engine" ]; then
        # Only count meaningful changes — engine repo has docs/CI files too.
        local engine_meaningful=""
        engine_meaningful=$(printf '%s\n' "$changed_engine" \
            | grep -v -E '^(\.github/|docs/|README|CHANGELOG|LICENSE|scripts/)' \
            || true)
        if [ -n "$engine_meaningful" ]; then
            need_controller=1
            need_worker=1
        fi
    fi

    local out=()
    [ "$need_controller" = "1" ] && out+=(controller)
    [ "$need_worker" = "1" ] && out+=(worker)
    [ "$need_frontend" = "1" ] && out+=(frontend)
    printf '%s\n' "${out[@]}"
}

resolve_since_sha() {
    # Priority: --since arg > release-digests.txt `# Git:` line > HEAD~1.
    if [ -n "$SINCE_SHA" ]; then
        echo "$SINCE_SHA"
        return
    fi
    if [ -f "$DIGESTS_FILE" ]; then
        local prev
        prev=$(grep -E '^# Git: ' "$DIGESTS_FILE" 2>/dev/null | head -1 | awk '{print $3}')
        if [ -n "$prev" ] && git -C "$REPO_ROOT" rev-parse --verify --quiet "$prev" >/dev/null; then
            echo "$prev"
            return
        fi
    fi
    # Conservative fallback — likely under-detects (single commit only) but
    # the caller can pass --since explicitly. Better to be too narrow than
    # to silently scan back to the dawn of the repo.
    git -C "$REPO_ROOT" rev-parse HEAD~1 2>/dev/null || echo "HEAD"
}

resolve_since_engine_sha() {
    # Pull the engine SHA from release-digests.txt's `# Engine:` line if
    # present (added by THIS script on each release). Returns empty if
    # the line is missing — the detect function then conservatively
    # rebuilds both binaries.
    if [ -f "$DIGESTS_FILE" ]; then
        grep -E '^# Engine: ' "$DIGESTS_FILE" 2>/dev/null | head -1 | awk '{print $3}'
    fi
}

if [ "$AUTO_DETECT" = "1" ]; then
    if [ ${#SERVICES[@]} -gt 0 ]; then
        warn "explicit SERVICES args + --auto: explicit wins, --auto ignored"
    else
        since=$(resolve_since_sha)
        since_engine=$(resolve_since_engine_sha)
        say "Auto-detecting affected services from git diff $since..HEAD"
        if [ -n "$since_engine" ]; then
            echo "${DIM}  (engine diff base: $since_engine)${RESET}"
        else
            echo "${DIM}  (no engine SHA recorded in release-digests.txt — engine diff will conservatively rebuild both)${RESET}"
        fi
        # mapfile-style read; populates SERVICES from one-service-per-line stdout.
        while IFS= read -r svc; do
            [ -n "$svc" ] && SERVICES+=("$svc")
        done < <(detect_services_from_diff "$since" "$since_engine")
        if [ ${#SERVICES[@]} -eq 0 ]; then
            warn "Auto-detect found no service-affecting changes since $since"
            warn "(docs / deploy / scripts / CI-only changes don't trigger a rebuild)"
            warn "Pass services explicitly to force a rebuild anyway, e.g.:"
            warn "  $0 $VERSION controller worker"
            exit 0
        fi
        ok "Detected services: ${SERVICES[*]}"
    fi
fi

# When neither explicit SERVICES nor --auto was given, fall back to the
# legacy default. Keeps existing call sites (CI, muscle memory) working.
if [ ${#SERVICES[@]} -eq 0 ]; then
    SERVICES=(controller worker)
fi

# ── Pre-flight ───────────────────────────────────────────────────────────────
say "Pre-flight checks"

# 1. Cargo.toml version matches.
cargo_version=$(grep -E '^version = ' "$REPO_ROOT/controller/Cargo.toml" \
    | head -1 | sed -E 's/version = "(.+)"/\1/')
if [ "$cargo_version" != "$VERSION" ]; then
    err "controller/Cargo.toml version is '$cargo_version' but you asked for '$VERSION'"
    err "  Bump Cargo.toml first (or pass the matching VERSION)."
    exit 1
fi
ok "controller/Cargo.toml version matches: $VERSION"

# 2. Builder exists and supports the target platform.
if ! docker buildx inspect "$BUILDER" >/dev/null 2>&1; then
    err "buildx builder '$BUILDER' not found"
    err "  Create one: docker buildx create --name $BUILDER --use --bootstrap"
    exit 1
fi
# Capture inspect output FIRST then grep — `grep -q` exits on first match,
# and with `set -o pipefail` that causes docker to receive SIGPIPE and the
# whole pipeline to be marked failed, even when the platform IS supported.
builder_info=$(docker buildx inspect "$BUILDER" 2>/dev/null || true)
if ! printf '%s\n' "$builder_info" | grep -F -q "$PLATFORM"; then
    err "builder '$BUILDER' does not advertise $PLATFORM"
    err "  On Apple Silicon you may need: docker run --privileged --rm tonistiigi/binfmt --install all"
    exit 1
fi
ok "buildx builder '$BUILDER' supports $PLATFORM"

# 3. Logged in to ghcr.io. We can't easily verify the token works without
#    a probe push, but absence of the entry means definitely-not-logged-in.
if ! grep -q '"ghcr.io"' "${HOME}/.docker/config.json" 2>/dev/null; then
    err "no ghcr.io entry in ~/.docker/config.json"
    err "  Log in: echo \$GITHUB_TOKEN | docker login ghcr.io -u \$USER --password-stdin"
    exit 1
fi
ok "docker is logged in to ghcr.io"

# ── Build + push ─────────────────────────────────────────────────────────────
GIT_SHA=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo "unknown")
say "Releasing $VERSION as ghcr.io/$TALOS_GHCR_OWNER/talos-{${SERVICES[*]// /,}} ($PLATFORM)"
echo "${DIM}git sha: $GIT_SHA${RESET}"
echo

# Each service's Dockerfile lives under <service>/Dockerfile; the worker and
# controller both consume the workflow_engine sibling repo via additional
# build context. Frontend doesn't, so we only set additional_contexts when
# it's actually needed — keeps the buildx command short and the failure mode
# obvious if the sibling repo is missing.
build_one() {
    local svc="$1"
    local dockerfile="$REPO_ROOT/$svc/Dockerfile"
    if [ ! -f "$dockerfile" ]; then
        err "no Dockerfile at $dockerfile — skipping"
        return 1
    fi
    local ver_tag="ghcr.io/$TALOS_GHCR_OWNER/talos-$svc:$VERSION"
    local latest_tag="ghcr.io/$TALOS_GHCR_OWNER/talos-$svc:latest"
    local args=(
        --builder "$BUILDER"
        --platform "$PLATFORM"
        -f "$dockerfile"
        --build-arg "GIT_SHA_OVERRIDE=$GIT_SHA"
        -t "$ver_tag"
        -t "$latest_tag"
        --push
    )
    # Controller and worker depend on the sibling workflow-engine repo via
    # additional build context. Frontend doesn't.
    if [ "$svc" = "controller" ] || [ "$svc" = "worker" ]; then
        if [ ! -d "$REPO_ROOT/../talos-workflow-engine" ]; then
            err "../talos-workflow-engine missing — required for $svc build"
            return 1
        fi
        args+=(--build-context "workflow_engine=$REPO_ROOT/../talos-workflow-engine")
    fi
    # Only the controller's build.rs needs DATABASE_URL (sqlx-prepare). Pass
    # whatever's in the env; build.rs falls back to its prepared cache when
    # unset, so the empty-string default is correct.
    if [ "$svc" = "controller" ]; then
        args+=(--build-arg "DATABASE_URL=${DATABASE_URL:-}")
    fi
    args+=("$REPO_ROOT")

    say "Building $svc"
    local log
    log=$(mktemp -t "talos-release-$svc-XXXXXX.log")
    if docker buildx build "${args[@]}" 2>&1 | tee "$log" | tail -5; then
        # Extract the registry digest from the build log. buildx emits lines
        # of the form `pushing manifest for <repo>:<tag>@sha256:<digest>`.
        # `docker inspect` does NOT work for cross-platform pushed images —
        # the local image cache doesn't have the manifest list.
        local digest
        digest=$(grep -oE "pushing manifest for $ver_tag@sha256:[a-f0-9]{64}" "$log" \
            | head -1 | sed -E 's/.*@(sha256:[a-f0-9]{64})/\1/')
        if [ -z "$digest" ]; then
            err "$svc pushed but could not extract digest from build log: $log"
            return 1
        fi
        ok "$svc pushed: $ver_tag@$digest"
        echo "$svc=ghcr.io/$TALOS_GHCR_OWNER/talos-$svc@$digest" >> "$DIGESTS_FILE.tmp"
        rm -f "$log"
        return 0
    else
        err "$svc build/push failed — see $log"
        return 1
    fi
}

# MCP-1214: also record the sibling workflow-engine repo's HEAD sha so
# `--auto` on the NEXT release can diff the engine repo precisely
# (otherwise it falls back to conservatively-rebuilding-both).
ENGINE_SHA=""
if [ -d "$REPO_ROOT/../talos-workflow-engine/.git" ]; then
    ENGINE_SHA=$(git -C "$REPO_ROOT/../talos-workflow-engine" rev-parse HEAD 2>/dev/null || echo "")
fi

# Truncate the digests file at start of run so the final state reflects only
# this release. Atomic-ish: write to .tmp, rename at end.
: > "$DIGESTS_FILE.tmp"
{
    echo "# Talos release digests — $VERSION"
    echo "# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# Git: $GIT_SHA"
    if [ -n "$ENGINE_SHA" ]; then
        echo "# Engine: $ENGINE_SHA"
    fi
    echo "# Platform: $PLATFORM"
    echo
} >> "$DIGESTS_FILE.tmp"

failed=0
for svc in "${SERVICES[@]}"; do
    if ! build_one "$svc"; then
        failed=$((failed + 1))
    fi
    echo
done

mv "$DIGESTS_FILE.tmp" "$DIGESTS_FILE"

if [ $failed -gt 0 ]; then
    err "$failed service(s) failed; partial digests in $DIGESTS_FILE"
    exit 2
fi

# ── Post-flight ──────────────────────────────────────────────────────────────
say "Release complete"
echo "Digests written to: $DIGESTS_FILE"
echo
cat "$DIGESTS_FILE"
echo
say "Update the prod VM:"
sed_args=()
for svc in "${SERVICES[@]}"; do
    digest=$(grep -E "^$svc=" "$DIGESTS_FILE" | sed -E "s|.*@(sha256:[a-f0-9]+)$|\1|")
    upper=$(echo "$svc" | tr '[:lower:]' '[:upper:]')
    sed_args+=("  -e 's|^TALOS_${upper}_DIGEST=.*|TALOS_${upper}_DIGEST=$digest|'")
done
# Every -e line (including the last) needs a trailing backslash because
# the line AFTER the last -e is the file path. `sed 's/$/ \\/'` applied
# to every line achieves that.
cat <<EOF
sudo sed -i \\
$(printf '%s\n' "${sed_args[@]}" | sed 's/$/ \\/')
  /etc/talos/install.env

kubectl -n talos delete job talos-migrations --ignore-not-found
sudo /opt/talos/deploy/k3s/install.sh
EOF

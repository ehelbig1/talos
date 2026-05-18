#!/usr/bin/env bash
#
# build-compiler-image.sh — Build the talos-builder container image.
#
# Usage:
#   ./scripts/build-compiler-image.sh [--no-cache]
#
# Prefers podman; falls back to docker if podman is not installed.
# The resulting image is tagged as talos-builder:latest and used by
# controller/src/compilation/container.rs to isolate cargo builds.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE_NAME="talos-builder:latest"
DOCKERFILE="$REPO_ROOT/Dockerfile.builder"

# Detect container runtime (prefer podman for rootless)
if command -v podman &>/dev/null; then
    RUNTIME="podman"
elif command -v docker &>/dev/null; then
    RUNTIME="docker"
else
    echo "ERROR: Neither podman nor docker found in PATH." >&2
    echo "Install podman (preferred) or docker to build the compiler image." >&2
    exit 1
fi

echo "Using container runtime: $RUNTIME"
echo "Building image: $IMAGE_NAME"
echo "Dockerfile: $DOCKERFILE"
echo ""

EXTRA_ARGS=()
if [[ "${1:-}" == "--no-cache" ]]; then
    EXTRA_ARGS+=("--no-cache")
    echo "Build cache disabled."
fi

$RUNTIME build \
    -f "$DOCKERFILE" \
    -t "$IMAGE_NAME" \
    "${EXTRA_ARGS[@]}" \
    "$REPO_ROOT"

echo ""
echo "================================================"
echo "  Image built successfully: $IMAGE_NAME"
echo "================================================"
echo ""
echo "Usage:"
echo "  The controller uses this image automatically when"
echo "  TALOS_COMPILATION_CONTAINER=true (default in production)."
echo ""
echo "  To test manually:"
echo "    $RUNTIME run --rm $IMAGE_NAME cargo component --version"
echo ""
echo "  To verify security flags:"
echo "    $RUNTIME run --rm --network=none --read-only --tmpfs /tmp:rw,size=1g \\"
echo "      --memory=2g --cpus=2 --user=1000:1000 $IMAGE_NAME whoami"
echo ""

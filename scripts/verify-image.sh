#!/usr/bin/env bash
# verify-image.sh — verify a Talos image's signature, SBOM attestation,
# and SLSA provenance before deploying it.
#
# What this proves on success:
#   1. Image was signed by Sigstore.
#   2. Signing identity is OUR GitHub Actions release workflow on
#      `ehelbig1/talos`, signed during a `v*` tag push (not a fork,
#      not a branch push, not a manual run).
#   3. Image carries an SBOM attestation signed by the same identity.
#   4. Image carries SLSA Level 3 provenance signed by the SLSA-framework
#      reusable workflow (also Sigstore-anchored).
#
# Usage:
#   scripts/verify-image.sh ghcr.io/ehelbig1/talos-controller:1.2.3
#   scripts/verify-image.sh ghcr.io/ehelbig1/talos-worker@sha256:abc...
#
# Exit code: 0 = all checks passed, 1 = any check failed.
#
# Prereqs: cosign >= 2.4 installed (`brew install cosign` or download
# from https://github.com/sigstore/cosign/releases).

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <image-ref>" >&2
    exit 2
fi

IMAGE="$1"

# Bind verification to OUR repo + OUR release workflow + a tag push.
# Anything else is rejected — even a workflow run on the same repo from
# a malicious branch would fail this check.
EXPECTED_IDENTITY_REGEXP='^https://github.com/ehelbig1/talos/\.github/workflows/release\.yml@refs/tags/v.*'
EXPECTED_OIDC_ISSUER='https://token.actions.githubusercontent.com'

# SLSA generator runs from its own reusable workflow, signed by its own
# OIDC identity. Provenance verification needs that identity, not ours.
SLSA_IDENTITY_REGEXP='^https://github.com/slsa-framework/slsa-github-generator/\.github/workflows/generator_container_slsa3\.yml@refs/tags/v.*'

if ! command -v cosign >/dev/null; then
    echo "ERROR: cosign not installed. Install via:" >&2
    echo "  brew install cosign  # macOS" >&2
    echo "  https://github.com/sigstore/cosign/releases" >&2
    exit 2
fi

echo "→ Verifying image: $IMAGE"

# 1. Image signature itself.
echo "→ [1/3] Image signature..."
if cosign verify \
        --certificate-identity-regexp "$EXPECTED_IDENTITY_REGEXP" \
        --certificate-oidc-issuer "$EXPECTED_OIDC_ISSUER" \
        "$IMAGE" >/dev/null 2>&1; then
    echo "    ✓ Signed by ehelbig1/talos release workflow"
else
    echo "    ✗ Signature verification FAILED — image may be tampered or from a different builder" >&2
    exit 1
fi

# 2. SBOM attestation — proves the dependency tree we built against.
echo "→ [2/3] SBOM attestation..."
if cosign verify-attestation \
        --type spdxjson \
        --certificate-identity-regexp "$EXPECTED_IDENTITY_REGEXP" \
        --certificate-oidc-issuer "$EXPECTED_OIDC_ISSUER" \
        "$IMAGE" >/dev/null 2>&1; then
    echo "    ✓ SBOM attestation valid (use 'cosign download attestation' to inspect)"
else
    echo "    ✗ SBOM attestation FAILED — image lacks a signed dependency manifest" >&2
    exit 1
fi

# 3. SLSA provenance — proves WHO built it (this is the L2/L3 contract).
echo "→ [3/3] SLSA provenance..."
if cosign verify-attestation \
        --type slsaprovenance \
        --certificate-identity-regexp "$SLSA_IDENTITY_REGEXP" \
        --certificate-oidc-issuer "$EXPECTED_OIDC_ISSUER" \
        "$IMAGE" >/dev/null 2>&1; then
    echo "    ✓ SLSA provenance valid (built by slsa-github-generator)"
else
    echo "    ✗ SLSA provenance FAILED — no verifiable build attestation" >&2
    exit 1
fi

echo
echo "✅ $IMAGE passed all SLSA L2 verification checks"
echo "   Safe to deploy."

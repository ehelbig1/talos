# syntax=docker/dockerfile:1
# ══════════════════════════════════════════════════════════════════════════════
# Stage 1: Build the worker binary
# ══════════════════════════════════════════════════════════════════════════════
# Base image digest matches controller/Dockerfile so both binaries link
# against the same glibc/OpenSSL versions. Bump together when rotating.
FROM rust:1.91@sha256:867f1d1162913c401378a8504fb17fe2032c760dc316448766f150a130204aad AS builder

# All Talos crates — including the engine + protocol crates folded
# back from the sibling repo in May-2026 — live in this single
# workspace. The Dockerfile no longer needs `additional_contexts` to
# pull the engine from an external path.
WORKDIR /app/talos

# Install mold — a modern linker that is 5-10x faster than GNU ld for the final link step.
RUN apt-get update && apt-get install -y mold && rm -rf /var/lib/apt/lists/*

# opt-level=1 uses ~4x less LLVM memory than release; 8 jobs is safe on a 16-CPU host.
ENV CARGO_BUILD_JOBS=8
ENV RUSTFLAGS="-C link-arg=-fuse-ld=mold --cfg rustix_use_libc"

# Copy the entire workspace in one shot. .dockerignore is the contract:
# it excludes **/target, .env*, private keys, frontend node_modules, .git,
# etc. — keep that file conservative.
#
# Why one COPY instead of the previous two-phase manifest+stub+source
# pattern: that pattern bought slightly tighter Docker layer-cache hits
# at the cost of an explicit hard-coded list of every workspace member,
# which broke the release every time a new talos-* crate was added
# (3+ incidents through r292 — the workspace now has 90+ crates).
# The BuildKit cache mounts on /usr/local/cargo/registry and
# /app/talos/target survive Docker layer-cache invalidation, so cargo's
# incremental compilation still skips unchanged crates on every
# subsequent build. The practical perf delta is small; the maintenance
# burden disappears.
COPY . .

# Final build: cache mounts persist registry + target across builds, so
# only crates with changed source recompile.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/talos/target \
    cargo build --profile docker --bin worker 2>&1 && \
    cp target/docker/worker /app/worker-bin

# ══════════════════════════════════════════════════════════════════════════════
# Stage 2: Minimal runtime image
# ══════════════════════════════════════════════════════════════════════════════
# IMPORTANT: The runtime base MUST match the builder's Debian version.
# rust:1.91 is based on Debian trixie (glibc 2.39, OpenSSL 3.3).
# Using bookworm-slim (glibc 2.36, OpenSSL 3.0) causes "GLIBC_2.38 not found"
# and "OPENSSL_3.3.0 not found" crashes at startup.
FROM debian:trixie-slim

# `cosign` (~80 MB) is bundled so the worker can verify Sigstore-signed OCI
# template artifacts before executing their WASM. See `verify_oci_signature`
# in worker/src/main.rs and TALOS_SIGSTORE_REQUIRED env in the Helm chart.
# We pull a pinned release directly from sigstore/cosign rather than apt
# (Debian package lags upstream by months and lacks SLSA-3 attestations).
#
# The downloaded binary is the runtime trust root for every WASM module —
# a poisoned cosign would silently validate attacker-signed artifacts.
# We verify against the upstream-published SHA256 from cosign_checksums.txt
# at the same release tag; bump COSIGN_SHA256 in lockstep with COSIGN_VERSION.
ARG COSIGN_VERSION=v2.4.1
ARG COSIGN_SHA256=8b24b946dd5809c6bd93de08033bcf6bc0ed7d336b7785787c080f574b89249b
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl libssl3t64 \
 && curl -fsSL \
      --retry 5 --retry-delay 5 --retry-connrefused \
      --connect-timeout 30 --max-time 180 \
      "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64" \
      -o /usr/local/bin/cosign \
 && echo "${COSIGN_SHA256}  /usr/local/bin/cosign" | sha256sum -c - \
 && chmod +x /usr/local/bin/cosign \
 && /usr/local/bin/cosign version \
 && apt-get purge -y curl && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/worker-bin /app/worker

RUN groupadd -r talos && useradd -r -g talos -u 1000 talos && chown talos:talos /app/worker
USER talos
CMD ["/app/worker"]

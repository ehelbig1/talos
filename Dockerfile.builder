# Dockerfile.builder — Isolated compilation container for Talos WASM modules.
#
# This image wraps `cargo component build` in a rootless container to prevent
# proc-macro escape from the WASM sandbox. User-supplied Rust code is compiled
# inside this container with --network=none, --read-only, and memory/cpu limits.
#
# Build:
#   docker build -f Dockerfile.builder -t talos-builder:latest .
#   (or use scripts/build-compiler-image.sh)

# ---------- stage 1: install toolchain + cargo extensions ----------
FROM rust:1.91-slim-bookworm@sha256:8514999d4786ef12efe89239e86b3d0a021b94b9d35108c8efe6c79ca7dc1a65 AS builder-base

ENV DEBIAN_FRONTEND=noninteractive

# Install minimal OS dependencies for cargo-component and cargo-audit
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Add the WASM target
RUN rustup target add wasm32-wasip2

# Install cargo-component (WASM component model toolchain) and cargo-audit (CVE scanner)
RUN cargo install cargo-component@0.21.1 --locked && \
    cargo install cargo-audit --locked

# Pre-fetch the RustSec advisory database. The runtime container runs
# `cargo audit --no-fetch --db /opt/talos-advisory-db` (network is denied
# in the sandbox), which requires the database to already exist at that
# explicit path. Without this step the audit invocation fails on first
# use with "Couldn't load advisory database", returns non-zero, and the
# controller's production gate fails every compile request — the
# 2026-04-27 prod regression.
#
# Stable path /opt/talos-advisory-db (rather than $CARGO_HOME/advisory-db)
# so the controller can pass it explicitly via --db; this matches the
# controller image, keeping the compilation code path uniform across
# the two execution modes (sandbox container vs direct fallback).
#
# Clone the upstream advisory-db git repo directly (`cargo audit fetch`
# was removed in cargo-audit 0.18). git is already available in the
# rust:slim base image. --depth 1 keeps the image size down.
#
# Freshness: the DB is frozen at image-build time. Rebuild the builder
# image monthly (scripts/build-compiler-image.sh) to absorb new RustSec
# advisories.
# Pin to a known-good commit. Without this, an upstream compromise of
# rustsec/advisory-db could silence advisories or inject false positives
# for every sandbox compile. Bump in lockstep with controller/Dockerfile.
ARG ADVISORY_DB_COMMIT=20377f44edabca7c4a765ccdcd05935331b6191f
RUN apt-get update && apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/* && \
    git clone --filter=tree:0 https://github.com/RustSec/advisory-db /opt/talos-advisory-db && \
    git -C /opt/talos-advisory-db checkout --detach "${ADVISORY_DB_COMMIT}" && \
    chmod -R a+rX /opt/talos-advisory-db

# ---------- stage 2: slim runtime image ----------
FROM rust:1.91-slim-bookworm@sha256:8514999d4786ef12efe89239e86b3d0a021b94b9d35108c8efe6c79ca7dc1a65

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the WASM target from stage 1
COPY --from=builder-base /usr/local/rustup/toolchains/ /usr/local/rustup/toolchains/

# Copy cargo-component and cargo-audit binaries
COPY --from=builder-base /usr/local/cargo/bin/cargo-component /usr/local/cargo/bin/cargo-component
COPY --from=builder-base /usr/local/cargo/bin/cargo-audit /usr/local/cargo/bin/cargo-audit

# Create non-root builder user (uid 1000)
RUN groupadd --gid 1000 builder && \
    useradd --uid 1000 --gid 1000 --create-home builder

# Create directories the builder will need write access to
RUN mkdir -p /home/builder/.cargo/registry && \
    chown -R builder:builder /home/builder

# Copy the pre-fetched RustSec advisory database from stage 1 to the
# stable, image-baked path the controller passes via `--db`. World-readable
# so the unprivileged builder user can read it without owning the tree.
COPY --from=builder-base /opt/talos-advisory-db /opt/talos-advisory-db

# Set cargo home so the registry cache mount works
ENV CARGO_HOME=/home/builder/.cargo

# Switch to non-root user
USER builder
WORKDIR /home/builder

# No entrypoint — commands are passed via `podman run ... <command>`

# syntax=docker/dockerfile:1

# ════════════════════════════════════════════════════════════════════════════
# Stage 1: Runtime tools (cached — only rebuilds when this block changes)
# ════════════════════════════════════════════════════════════════════════════
FROM rust:1.95@sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3 AS runtime-base

RUN apt-get update && apt-get install -y ca-certificates git && rm -rf /var/lib/apt/lists/*
# The base image's toolchain IS the pin (rust-toolchain.toml's channel) — no
# `rustup default stable`, which floated to whatever stable was current at
# build time for every host-fallback compile.
RUN rustup component add rustfmt && \
    rustup target add wasm32-wasip1 wasm32-wasip2

# Install tools one at a time (each cached independently). Every install is
# version-pinned: an unpinned `cargo install` resolves to the newest release
# at build time (sqlx-cli would silently jump to 0.9 while the workspace
# links sqlx 0.8.6).
RUN cargo install sqlx-cli --version 0.8.6 --locked --features postgres
RUN cargo install wizer --version 9.0.0 --features="env_logger structopt"
RUN cargo install cargo-component --version 0.21.1 --locked
# cargo-audit gates every WASM compile in production. The compilation
# service prefers the talos-builder sandbox image (TALOS_COMPILATION_CONTAINER
# path) but falls back to direct `cargo audit` when no podman/docker is
# present in the controller pod — which is the typical k3s/Kubernetes
# setup. Without cargo-audit on the runtime image, that fallback fails
# with "no such subcommand: audit" and every install_module_from_catalog
# / compile_custom_sandbox / inline rust_code request blocks.
RUN cargo install cargo-audit --version 0.22.2 --locked

# `cosign` verifies the Sigstore signature of the OCI template index and every
# template before the controller's catalog sync (talos-registry::sync) trusts
# them. Without it that sync answers `cosign_unavailable` for every artifact.
# Same pinned release + upstream sha256 as worker/Dockerfile — bump together.
ARG TARGETARCH
ARG COSIGN_VERSION=v2.4.1
ARG COSIGN_SHA256_AMD64=8b24b946dd5809c6bd93de08033bcf6bc0ed7d336b7785787c080f574b89249b
ARG COSIGN_SHA256_ARM64=3b2e2e3854d0356c45fe6607047526ccd04742d20bd44afb5be91fa2a6e7cb4a
RUN case "${TARGETARCH}" in \
      amd64) COSIGN_SHA256="${COSIGN_SHA256_AMD64}" ;; \
      arm64) COSIGN_SHA256="${COSIGN_SHA256_ARM64}" ;; \
      *) echo "unsupported TARGETARCH ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && curl -fsSL \
      --retry 5 --retry-delay 5 --retry-connrefused \
      --connect-timeout 30 --max-time 180 \
      "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-${TARGETARCH}" \
      -o /usr/local/bin/cosign \
 && echo "${COSIGN_SHA256}  /usr/local/bin/cosign" | sha256sum -c - \
 && chmod +x /usr/local/bin/cosign \
 && /usr/local/bin/cosign version

RUN groupadd -r talos && useradd -r -g talos -u 1001 talos

# Pre-fetch the RustSec advisory database to a stable, image-baked path.
# We use /opt/talos-advisory-db rather than $CARGO_HOME/advisory-db
# because the runtime sets CARGO_HOME=/tmp/cargo-cache (tmpfs, wiped
# per pod) — cargo-audit's default discovery would always come up empty.
# The compilation service passes `--db /opt/talos-advisory-db` to every
# `cargo audit` invocation so the path is explicit, not env-derived.
#
# We clone the upstream rustsec/advisory-db git repo directly rather
# than calling `cargo audit fetch` — the `fetch` subcommand was removed
# in cargo-audit 0.18 (May 2023) in favour of auto-fetch on `cargo audit`,
# which the network-isolated sandbox cannot reach.
#
# Pinned to a known-good commit (bump in lockstep with image rotation).
# Without a commit pin, an upstream compromise of rustsec/advisory-db
# could silence advisories or inject false positives for every
# compile_custom_sandbox / install_module_from_catalog request.
# Same monthly-rebuild caveat: the database is frozen at image-build
# time; rebuild monthly to absorb new advisories.
ARG ADVISORY_DB_COMMIT=20377f44edabca7c4a765ccdcd05935331b6191f
RUN git clone --filter=tree:0 https://github.com/RustSec/advisory-db /opt/talos-advisory-db && \
    git -C /opt/talos-advisory-db checkout --detach "${ADVISORY_DB_COMMIT}" && \
    chmod -R a+rX /opt/talos-advisory-db

# JS + Python componentize toolchains for the HOST-fallback compile path —
# the same reason cargo/cargo-component live in this image: dev compose runs
# compiles host-direct inside the controller container. Pins mirror
# Dockerfile.builder (the sandboxed production path); bump both together.
COPY --from=node:22.17.0-bookworm-slim@sha256:b04ce4ae4e95b522112c2e5c52f781471a5cbc3b594527bcddedee9bc48c03a0 /usr/local/bin/node /usr/local/bin/node
COPY --from=node:22.17.0-bookworm-slim@sha256:b04ce4ae4e95b522112c2e5c52f781471a5cbc3b594527bcddedee9bc48c03a0 /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm && \
    npm install -g @bytecodealliance/jco@1.25.1 && \
    npm cache clean --force && \
    apt-get update && apt-get install -y --no-install-recommends python3 python3-pip && \
    rm -rf /var/lib/apt/lists/* && \
    pip3 install --no-cache-dir --break-system-packages componentize-py==0.24.0

# ════════════════════════════════════════════════════════════════════════════
# Stage 2: Build the controller binary
# ════════════════════════════════════════════════════════════════════════════
FROM rust:1.95@sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3 AS builder

# All Talos crates — including the engine + protocol crates folded
# back from the sibling repo in May-2026 — live in this single
# workspace. The Dockerfile no longer needs `additional_contexts` to
# pull the engine from an external path.
WORKDIR /app/talos

# Install mold — a modern linker that is 5-10x faster than GNU ld for the final link step.
RUN apt-get update && apt-get install -y mold && rm -rf /var/lib/apt/lists/*

# Cargo profile. `docker` (opt-level=1, 256 CGUs) is the fast dev-compose build
# and uses ~4x less LLVM memory than release, so 8 parallel jobs are safe on a
# 16-CPU / 23 GB Docker Desktop host. Published images pass
# CARGO_PROFILE=dist (main-publish.yml, release.yml, publish-images.sh).
ARG CARGO_PROFILE=docker
ENV CARGO_BUILD_JOBS=8
ENV RUSTFLAGS="-C link-arg=-fuse-ld=mold --cfg rustix_use_libc"

# Build-time git SHA + dirty flag passed by docker-compose.yml. Captured by
# controller/build.rs and exposed as `GIT_SHA` / `GIT_DIRTY` env! constants
# at compile time so session_start.server_version reflects the deployed code.
ARG GIT_SHA_OVERRIDE=unknown
ARG GIT_DIRTY_OVERRIDE=false
ENV GIT_SHA_OVERRIDE=${GIT_SHA_OVERRIDE}
ENV GIT_DIRTY_OVERRIDE=${GIT_DIRTY_OVERRIDE}

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

# sqlx offline mode resolves query files against $CARGO_MANIFEST_DIR/.sqlx
# (i.e. /app/talos/controller/.sqlx) — already present via `COPY . .`.
ENV SQLX_OFFLINE=1

# sharing=locked: see worker/Dockerfile — the parallel image builds race
# the shared registry cache mount without it (cargo unpack "File exists").
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/app/talos/target,sharing=locked \
    cargo build --profile "${CARGO_PROFILE}" --bin controller && \
    cp "/app/talos/target/${CARGO_PROFILE}/controller" /app/controller-bin

# ════════════════════════════════════════════════════════════════════════════
# Stage 3: Final runtime image
# ════════════════════════════════════════════════════════════════════════════
FROM runtime-base

WORKDIR /app

# Set ownership at copy time via --chown rather than a post-copy `chown -R /app`.
# A recursive chown traverses every file in /app (potentially GB of templates),
# which exhausts Docker Desktop's VM memory/disk and exits with code 1.
COPY --chown=talos:talos --from=builder /app/controller-bin /app/controller
COPY --chown=talos:talos --from=builder /app/talos/migrations /app/migrations
COPY --chown=talos:talos --from=builder /app/talos/wit /app/wit
COPY --chown=talos:talos --from=builder /app/talos/talos_sdk_macros /app/talos_sdk_macros
COPY --chown=talos:talos --from=builder /app/talos/module-templates /app/module-templates
COPY --chown=talos:talos --from=builder /app/talos/workflow-templates /app/workflow-templates

# Tell the CompilationService where the WIT fixture lives at runtime.
# The builder stage's baked path (/app/talos/wit/talos.wit) points at the
# build-time tree; at runtime we keep the file at /app/wit/talos.wit. Without
# this override, every sandbox compile fails with "Failed to copy WIT file".
ENV TALOS_WIT_PATH=/app/wit/talos.wit

# Only chown the three runtime-writable directories (not /app recursively).
RUN mkdir -p /home/talos /tmp/cargo-cache /tmp/talos-compilations /tmp/cargo-target && \
    chown talos:talos /home/talos /tmp/talos-compilations && \
    chmod 1777 /tmp/cargo-cache /tmp/cargo-target

USER talos

ENV HOME=/home/talos
ENV CARGO_HOME=/tmp/cargo-cache
ENV PATH=$CARGO_HOME/bin:$PATH
# cargo-component (and other tools using the dirs crate) write to
# $XDG_CACHE_HOME / $XDG_DATA_HOME, which default to $HOME/.cache and
# $HOME/.local/share. The k3s deployment runs with readOnlyRootFilesystem:true
# so $HOME (/home/talos) is read-only — without these overrides, every
# compile fails with "Unable to create cache directory: Read-only file
# system". Point both at the same writable tmpfs mount that already
# backs CARGO_HOME.
ENV XDG_CACHE_HOME=/tmp/cargo-cache
ENV XDG_DATA_HOME=/tmp/cargo-cache
# Shared target directory for sandbox compilations.
# Without this, each compile_custom_sandbox call creates a fresh UUID workspace
# with its own target/ dir (deleted after compilation), rebuilding serde,
# serde_json, wit-bindgen-rt, and talos_sdk_macros from source every time.
# With a shared target/, cargo reuses compiled dependency .rlib artifacts across
# runs — warm compilation drops from ~25 s to <2 s for unchanged deps.
ENV CARGO_TARGET_DIR=/tmp/cargo-target

EXPOSE 8000
CMD ["/app/controller"]

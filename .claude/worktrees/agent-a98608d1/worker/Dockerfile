# Build stage
FROM rust:1.90 AS builder

WORKDIR /app

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY job-protocol ./job-protocol
COPY worker ./worker
COPY vendor ./vendor
COPY wit ./wit

# The root workspace lists controller and example-node as members.
# Cargo must be able to read their Cargo.toml files to resolve the workspace
# dependency graph even when we only build --bin worker.
# Copy only the manifests; no source compilation of those crates is needed.
# Stub source files are required so Cargo's auto-detection finds targets in each manifest.
COPY controller/Cargo.toml ./controller/Cargo.toml
COPY example-node/Cargo.toml ./example-node/Cargo.toml
COPY talos_sdk_macros/Cargo.toml ./talos_sdk_macros/Cargo.toml
RUN mkdir -p controller/src example-node/src talos_sdk_macros/src \
    && echo 'fn main() {}' > controller/src/main.rs \
    && touch controller/src/lib.rs \
    && touch example-node/src/lib.rs \
    && touch talos_sdk_macros/src/lib.rs

# Build only the worker binary
RUN cargo build --release --bin worker

# Runtime stage – use the same glibc version as the builder to avoid missing symbols
FROM rust:1.90-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the built binary
COPY --from=builder /app/target/release/worker /app/worker

# Run as non-root user for defense-in-depth
RUN groupadd -r talos && useradd -r -g talos -u 1000 talos \
    && chown talos:talos /app/worker

USER talos

CMD ["/app/worker"]

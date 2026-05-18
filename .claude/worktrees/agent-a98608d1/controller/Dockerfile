# Build stage
FROM rust:1.90 AS builder

WORKDIR /app

# Use stable Rust for better SQLx compatibility
# Nightly is no longer required for this codebase
RUN rustup default stable

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY job-protocol ./job-protocol
COPY controller ./controller
COPY worker ./worker
COPY vendor ./vendor
COPY wit ./wit
COPY module-templates ./module-templates
COPY migrations ./migrations
COPY example-node ./example-node
COPY talos_sdk_macros ./talos_sdk_macros

# Copy SQLx prepared query cache for offline compilation
COPY .sqlx ./.sqlx

# Build the controller binary
# Note: SQLx offline mode disabled - queries are checked at build time
ARG DATABASE_URL
ENV DATABASE_URL=${DATABASE_URL}
# Use offline mode: queries are checked against cached schema files.
ENV SQLX_OFFLINE=1
RUN cargo build --release --bin controller

# Runtime stage - needs Rust for runtime compilation
FROM rust:1.90

WORKDIR /app

# Install runtime dependencies
#   * ca-certificates – required for HTTPS calls (Google token endpoint)
#   * cargo-component – builds Wasm components at runtime
#   * sqlx-cli – runs DB migrations on start‑up
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/* && \
    rustup default stable && \
    rustup component add rustfmt && \
    rustup target add wasm32-wasip1 wasm32-wasip2 && \
    cargo install cargo-component --locked && \
    cargo install wizer --version 9.0.0 --features="env_logger structopt" && \
    cargo install sqlx-cli --locked --features postgres

# Create non-root user for security
RUN groupadd -r talos && useradd -r -g talos -u 1001 talos

# Copy the built binary
COPY --from=builder /app/target/release/controller /app/controller

# Copy migration scripts so the container can run them at start-up
COPY --from=builder /app/migrations /app/migrations

# Copy WIT files needed for runtime compilation
COPY --from=builder /app/wit /app/wit

# Copy talos_sdk_macros so dynamic compilations can use #[talos_node]
COPY --from=builder /app/talos_sdk_macros /app/talos_sdk_macros

# Create home directory and cargo cache for runtime compilation
# cargo-component needs both HOME and CARGO_HOME to be writable
RUN mkdir -p /home/talos /tmp/cargo-cache /tmp/talos-compilations && \
    chown -R talos:talos /app /home/talos /tmp/cargo-cache /tmp/talos-compilations

# Switch to non-root user
USER talos

# Set HOME and CARGO_HOME for runtime compilation (cargo-component needs this)
ENV HOME=/home/talos
ENV CARGO_HOME=/tmp/cargo-cache
ENV PATH=$CARGO_HOME/bin:$PATH

# Expose the GraphQL API port
EXPOSE 8000

# Run the controller
CMD ["/app/controller"]

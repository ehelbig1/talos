# Talos — Secure Agentic Workflow Platform

**The only workflow platform with WASM-sandboxed execution, 9-tier capability isolation, per-module secret scoping, and built-in AI agent primitives.**

Talos executes untrusted agent code inside capability-gated WebAssembly sandboxes. Modules can only access the host functions their declared capability world permits — a `minimal-node` module physically cannot make HTTP requests, even if the code tries. Write modules in Rust, Python, or TypeScript.

## 🚀 Quick Start

```bash
# 1. Create environment file
POSTGRES_PASSWORD=$(openssl rand -hex 32)
TALOS_MASTER_KEY=$(openssl rand -hex 32)  # dev only — production uses Vault transit (KEK_PROVIDER=vault)
JWT_SECRET=$(openssl rand -hex 32)

cat > .env <<EOF
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
TALOS_MASTER_KEY=${TALOS_MASTER_KEY}
KEK_PROVIDER=env  # dev default; switch to 'vault' for production (see docs/deployment.md)
JWT_SECRET=${JWT_SECRET}
DATABASE_URL=postgres://talos:${POSTGRES_PASSWORD}@localhost:5432/talos
RUST_LOG=info,controller=debug
BASE_URL=http://localhost:8000
FRONTEND_URL=http://localhost:3000
ALLOWED_ORIGIN=http://localhost:3000
TRUSTED_IPS=127.0.0.1,::1
EOF

# 2. Start database and run migrations
docker-compose up -d postgres
sleep 5
sqlx migrate run

# 3. Start all services
docker-compose up -d
```

## Features

### WASM Sandbox Execution
- **9 capability tiers**: minimal, http, llm, network, secrets, filesystem, messaging, cache, governance, database, automation
- **Fuel limits**: configurable per-execution instruction budget (default 1M)
- **Memory caps**: per-module memory limits enforced at instantiation
- **Content hash verification**: SHA-256 verified at load time (tamper detection)
- **Containerized compilation**: Podman sandbox with `--network=none --cap-drop=ALL` for build-time isolation

### AI Agent Primitives
- **Agent loop nodes**: ReAct-style iterative reasoning with configurable history
- **Judge nodes**: LLM-as-judge quality gates (0.0-1.0 scoring with rubrics)
- **Ensemble nodes**: Self-consistency voting (majority_vote, best_of_n)
- **LLM dispatch nodes**: Mixture-of-experts semantic routing
- **Confidence gates**: Threshold-based pass/pause/error routing
- **Human-in-the-loop**: 5 built-in approval triggers + custom Rhai expressions

### Multi-Language SDKs
- **Rust**: `#[talos_module(world = "http-node")]` proc macro
- **Python**: `@talos_module(world="http-node")` decorator (via componentize-py)
- **TypeScript**: `talosModule({ world: "http-node" })` wrapper (via ComponentizeJS)

### Security
- **At-rest encryption (everywhere user data lives)**: AES-256-GCM envelope encryption on `secrets`, `oauth_tokens`, `actor_memory`, `module_executions.{input,output,trigger_metadata}_data`, and `workflow_executions.output_data`. Pluggable KEK via `KekProvider` trait — `EnvKekProvider` for dev, `VaultTransitProvider` for production (KEK never enters controller process memory).
- **Per-actor LLM data-egress ceiling** (`actors.max_llm_tier`): tier-1 actors physically cannot reach Anthropic / OpenAI / Gemini — enforced at five worker surfaces (`llm::*` host fns, `wit_http::fetch`, `fetch_all`, GraphQL, webhook, HTTP-stream) PLUS HMAC-bound in `JobRequest` + `PipelineJobRequest` signing. Use for actors handling medical, financial, or other sensitive content.
- **Auth**: JWT (HS256/RS256) + TOTP 2FA with replay prevention, constant-time comparisons.
- **CSRF**: double-submit cookie with rotation on every mutation.
- **DLP**: PII redaction on every payload before encryption (defense in depth).
- **Rate limiting**: per-IP, per-agent, per-user, per-webhook (Redis-backed).
- **Supply chain**: `cargo deny check` (RUSTSEC + license + source policy) + `cargo audit` gated in CI; every Docker image pinned by SHA-256 digest; Dependabot weekly bumps grouped by domain.
- **SLSA L2 signing**: every release image cosign-signed (Sigstore keyless via OIDC), SBOM attested, SLSA-3 provenance via `slsa-github-generator`. Verify with `make verify-image IMAGE=...`.
- **Module template signing** (Sigstore keyless): every OCI template artifact published by `.github/workflows/template-publish.yml` is `cosign sign --yes`ed using GitHub Actions OIDC. Workers verify before pulling — `TALOS_SIGSTORE_REQUIRED=true` refuses unsigned/tampered artifacts at runtime. See `deploy/k3s/README.md` § *Trust model: Sigstore signing*.

### Module Templates
54+ built-in modules: RAG pipeline, multi-agent router, human review gate, PII scrubber, Slack webhook, Anthropic Claude, data validator, HTTP retry, and many more.

### Visual Workflow Editor
- React Flow drag-and-drop graph editor
- Real-time execution monitoring with timeline and waterfall views
- Per-node timing visualization (server-side, trigger-computed)
- Approval gate UI with pending/approved/rejected states

## Architecture

```
┌─────────────┐  GraphQL/WS  ┌──────────────┐  NATS   ┌──────────────┐
│  Frontend   │◄────────────►│  Controller  │◄───────►│   Worker     │
│ React+Vite  │              │  Rust/Axum   │         │  Wasmtime RT │
│ ReactFlow   │              │  MCP (302+)  │         │  9 linkers   │
└─────────────┘              └──────┬───────┘         └──────┬───────┘
                                    │                         │
                              ┌─────┼─────┐           ┌──────┴───────┐
                              │     │     │           │  WASM Module │
                         ┌────┴┐ ┌──┴──┐ ┌┴────┐     │  (sandboxed) │
                         │ PG  │ │Redis│ │MinIO│     │  fuel+memory │
                         │ 16  │ │(TLS)│ │audit│     │  cap-gated   │
                         └─────┘ └─────┘ └─────┘     └──────────────┘
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Rust (Axum, SQLx, async-graphql, wasmtime) |
| **Frontend** | React 19, TypeScript, Vite, ReactFlow, Zustand |
| **Database** | PostgreSQL 16 (pgvector) |
| **Runtime** | Wasmtime (WASM Component Model, wasip2) |
| **Messaging** | NATS JetStream |
| **Cache** | Redis (TLS enforced in production) |
| **Auth** | JWT (HS256), OAuth2, TOTP 2FA |
| **Audit** | NATS WORM stream + S3/MinIO + PostgreSQL |
| **SDKs** | Rust, Python, TypeScript |

## Project Structure

```
talos/
├── controller/          # Rust/Axum API server (GraphQL + MCP)
├── worker/              # Rust WASM runtime (wasmtime-based)
├── frontend/            # React/TypeScript visual workflow editor
├── talos-secrets/       # SecretProvider trait + vault implementation
├── talos_sdk_macros/    # Rust proc macro (#[talos_module])
├── sdks/python/         # Python SDK (@talos_module decorator)
├── sdks/typescript/     # TypeScript SDK (talosModule function)
├── module-templates/    # 54 pre-built workflow templates
├── migrations/          # PostgreSQL migrations (sqlx)
├── wit/                 # WebAssembly Interface Types (talos.wit)
├── docs/                # Security, compliance, architecture docs
├── scripts/             # SOC 2 evidence, encryption backfill, CI
└── Dockerfile.builder   # Compilation sandbox image
```

## Development

```bash
make up-dev              # Start all services + ngrok tunnel
make lint                # Lint Rust + frontend
make coverage            # Run tests with coverage
make builder-image       # Build Podman compilation sandbox
make verify-encryption   # Check execution output encryption status
make soc2-evidence       # Collect SOC 2 audit evidence
make sdk-python-lint     # Lint Python SDK
make sdk-ts-lint         # Type-check TypeScript SDK
cargo check --workspace  # Quick Rust compilation check
```

## Documentation

- `deploy/k3s/README.md` — Phase 1 single-VM production runbook (Hetzner CPX31 + k3s + Helm). Image rebuild flow, OCI template registry switch-over, Sigstore enforcement, backups, troubleshooting.
- `docs/deployment.md` — Service inventory, env-var reference, Vault/KEK rotation, Prometheus metrics. Read alongside the k3s runbook for production deploys.
- `docs/security/operational-runbook.md` — Encryption posture matrix, KEK + DEK rotation, supply-chain hygiene, incident playbooks.
- `docs/security/threat-model.md` — STRIDE threat model (7 trust boundaries)
- `docs/security/architecture.md` — Security architecture with diagrams
- `docs/security/pentest-scope.md` — Pentest preparation package
- `docs/compliance/soc2-control-mapping.md` — SOC 2 control mapping (40+ controls)
- `docs/architecture/managed-cloud.md` — Managed cloud design document
- `CHANGELOG.md` — Detailed changelog
- `CLAUDE.md` — Development guidelines and security rules

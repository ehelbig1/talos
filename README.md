# Talos

**A verifiable agent execution runtime: credential-free workers, signed cross-process data plane, per-actor data-egress policy.**

Talos is a Rust runtime for executing AI agent code inside WebAssembly sandboxes with capability gating, AES-256-GCM-encrypted per-job secrets, and HMAC-signed inter-process boundaries. It was built around the architectural bet that **the worker process should not be able to decrypt its own secrets, and should not be able to forge requests back to the controller** — and that those two properties are the foundation for safely running untrusted agent code in regulated environments.

It's also a complete reference implementation: a workflow engine, visual editor, and ~60 module templates are built on top of the runtime as one consumer. They are not the product. The runtime is.

> **Status: pre-1.0.** Wire formats and APIs are still stabilizing. The codebase has ~2,900 unit + integration tests, a 20-check structural-lint script, and incident-driven CHANGELOG entries — but it has not yet been deployed in anger against an SLA, and you should treat it as such.

---

## Why this exists

Most agent runtimes in 2026 — LangGraph, CrewAI, in-process Python SDKs, even Temporal worker patterns — hold every credential the agent might need in the worker process. That model is fine when "the agent" is your own code. It stops being fine when agents come from vendor marketplaces, third-party modules, customer uploads, MCP servers, or AI-generated code. A compromised worker (prompt-injection escape, memory dump from a sibling tenant, vulnerable dependency) leaks every credential it was holding.

Talos asks the question differently: *what would it look like if the worker physically could not see the credential at all?* The answer turns out to be a stack of architectural decisions that compose:

1. The controller owns every secret. The worker never holds a master key.
2. Per-job DEKs are wrapped by the worker's session key and bound, via AEAD, to the signed `JobRequest`. A replayed or swapped ciphertext fails to decrypt.
3. Every cross-process call is HMAC-SHA256 signed with replay protection (two-generation rotating nonce cache, atomic O(1) rotation).
4. WASM modules see opaque `u64` handles to secrets, not strings — even the worker process never exposes plaintext to guest code.
5. A per-actor `max_llm_tier` ceiling is HMAC-bound into the job signing payload. An on-wire attacker cannot downgrade a tier-1 actor to tier-2 even with full network access between controller and worker.

The result: a runtime where the blast radius of a worker compromise is bounded by the secrets in a single in-flight job, where vendor module marketplaces become safe to run, and where regulated-industry actors carry a cryptographically-enforced data-egress policy with them.

---

## Core architectural decisions

The interesting code is in a few specific files. If you're reading the repo to understand the design, start here:

### Credential-free worker
- `worker/src/host_impl.rs` — the WASM host functions. Note `check_secret_allowlist` and the LLM-tier enforcement at five surfaces.
- `talos-secrets-manager/` — controller-side secret resolution and the encrypted-secrets envelope builder.
- `talos-module-payload-encryption/` — AES-256-GCM AEAD envelope that binds ciphertext to the signed job request.

### Signed cross-process data plane
- `talos-memory/src/rpc_auth.rs` — HMAC-SHA256 verify, two-generation nonce cache via `ArcSwap<DashMap>`, constant-time MAC comparison, asymmetric freshness window (60s past / 5s future).
- `talos-workflow-job-protocol/src/lib.rs` — `JobRequest` / `JobResult` signing format. Note the `verify()` / `verify_no_replay()` split: passive observers (audit subscribers) must use `verify_no_replay` to avoid the nonce-cache collision that otherwise occurs when two consumers verify the same signed message.

### Capability lattice
- `talos-capability-world/src/lib.rs:208` — `is_subset_of` partial-order semantics. The capability worlds form a lattice, not flat tiers: `Filesystem ⊄ Secrets`, `Database ⊄ Agent`.
- `wit/talos.wit` — the WebAssembly Interface Types that define what each capability world exposes.

### Per-actor LLM tier ceiling
- `talos-actor-types/src/llm_tier.rs` — the `LlmTier` enum (`Tier1` blocks external LLM providers; `Tier2` allows them). The column is `actors.max_llm_tier`; the enum carries the value through the system.
- `worker/src/host_impl.rs` — multiple enforcement surfaces all branching on `self.max_llm_tier == Tier1`: `get_llm_api_key` and `get_llm_api_key_by_name` (refuse external-provider vault keys), `resolve_vault_header` (refuse `vault://anthropic|openai|gemini/*` header substitution), `wit_http::fetch` / `fetch_all` (refuse hosts in `EXTERNAL_LLM_HOSTS`), `wit_graphql::execute` and `wit_webhook::send` / `wit_http_stream` (same host deny-list).
- `talos-workflow-engine/src/secrets_pipeline.rs` — `build_encrypted_secrets_for` skips the LLM-provider key pre-fetch entirely when the job's `max_llm_tier == Tier1`, so tier-1 jobs never have an external-provider key on the wire (encrypted or otherwise). Defense in depth on top of the worker-side gates.

### Sigstore-verified module supply chain
- `talos-registry/src/` — OCI module pulls with mandatory `cosign verify` against pinned certificate-identity + OIDC issuer regexps. Two-layer attestation: the `_index:latest` artifact is signature-verified before its config blob is parsed; each template entry is verified again at fetch time.
- `worker/src/main.rs` — `verify_oci_layer` recomputes the SHA-256 of pulled bytes against the manifest's declared digest before the module is instantiated or cached.

---

## What's built on top of the runtime

The repo ships a complete reference stack so you can see the runtime in production conditions:

- **Workflow engine** (`talos-workflow-engine/`) — graph-based DAG executor with 20 system-node kinds: control flow (wait, while-loop, repeat-loop, loop, error-handler, verify, fan-in, collect, synthesize, sub-workflow), and AI primitives gated behind the `llm-primitives` feature (judge, inline-judge, ensemble, confidence-gate, agent-loop, react-loop, reflective-retry, llm-dispatch, dynamic-dispatch, capability-dispatch).
- **Visual editor** (`frontend/`) — React Flow drag-and-drop graph editor with real-time execution monitoring, per-node timing visualization, and approval-gate UI for human-in-the-loop steps.
- **Module SDKs** — `#[talos_module(world = "http-node")]` proc macro for Rust, `@talos_module(world="http-node")` decorator for Python (via componentize-py), `talosModule({ world: "http-node" })` wrapper for TypeScript (via ComponentizeJS).
- **~60 module templates** (`module-templates/`) — RAG pipeline, multi-agent router, human-review gate, PII scrubber, OAuth-aware Gmail / Google Calendar / Slack / Atlassian integrations, data validators, HTTP retry, and more. Compiled, signed, and OCI-distributed.
- **MCP surface** (`talos-mcp-handlers/`) — ~280 tools across 21 handler-domain modules (actor, advanced, alerts, analytics, auth, capability-worlds, configuration, executions, graph, knowledge-graph, modules, ollama, platform, resources, sandbox, schedules, search, secrets, versions, webhooks, workflows) so the entire platform is drivable from an MCP client.

These are useful examples, not the differentiator. The runtime primitives are what make running them safely interesting.

---

## Architecture

```
┌─────────────┐  GraphQL/WS  ┌──────────────┐  signed NATS  ┌──────────────┐
│  Frontend   │◄────────────►│  Controller  │◄─────────────►│   Worker     │
│ React+Vite  │              │  Rust/Axum   │   HMAC + AEAD │  Wasmtime RT │
│ ReactFlow   │              │ owns all KEK │               │  cap-gated   │
└─────────────┘              └──────┬───────┘               └──────┬───────┘
                                    │                              │
                              ┌─────┼─────┐                ┌───────┴──────┐
                              │     │     │                │  WASM Module │
                         ┌────┴┐ ┌──┴──┐ ┌┴────┐           │ opaque u64   │
                         │ PG  │ │Redis│ │MinIO│           │ secret refs  │
                         │ pgv │ │(TLS)│ │audit│           │ fuel+memory  │
                         └─────┘ └─────┘ └─────┘           └──────────────┘
```

Trust levels: controller (most), NATS-in-flight (encrypted + signed), worker (least). The worker is given encrypted blobs per-job and decrypts only with a per-job DEK that's part of the signed request — it has no standing access to anything.

---

## Tech stack

| Layer | Technology |
|-------|-----------|
| Backend | Rust (Axum, SQLx, async-graphql, wasmtime) |
| Frontend | React 19, TypeScript, Vite, ReactFlow, Zustand |
| Database | PostgreSQL 16 (dev) / 17 (production helm chart), pgvector extension |
| WASM runtime | Wasmtime (Component Model, wasip2) |
| Messaging | NATS JetStream (signed, HMAC + nonce cache) |
| Cache | Redis (TLS enforced in production) |
| Auth | JWT (HS256/RS256), OAuth2, TOTP 2FA |
| KEK | HashiCorp Vault transit (production) / env-var (dev) |
| Audit | NATS WORM stream + S3/MinIO + PostgreSQL |
| Supply chain | cargo-deny + cargo-audit + Sigstore (cosign + Fulcio + Rekor) |

---

## Project structure

```
talos/
├── controller/                    # Axum API server (GraphQL + MCP)
├── worker/                        # Credential-free WASM runtime
├── frontend/                      # React workflow editor (one consumer of the runtime)
├── talos-memory/                  # Signed RPC layer (rpc_auth.rs)
├── talos-workflow-job-protocol/   # JobRequest/JobResult signing format
├── talos-capability-world/        # Capability lattice (is_subset_of)
├── talos-actor-types/             # Actor model + max_llm_tier
├── talos-secrets-manager/         # Encrypted-secrets envelope builder
├── talos-registry/                # Sigstore-verified OCI module pulls
├── talos-workflow-engine/         # Reference workflow executor
├── talos-mcp-handlers/            # MCP tool surface (300+)
├── talos_sdk_macros/              # #[talos_module] proc macro
├── sdks/{python,typescript}/      # Language SDKs
├── module-templates/              # Pre-built modules (OCI-distributed)
├── migrations/                    # PostgreSQL migrations (sqlx)
├── wit/                           # WebAssembly Interface Types
├── deploy/                        # Helm chart + k3s install script
└── docs/                          # Security, compliance, architecture
```

---

## Quick start

```bash
# Generate dev secrets
cat > .env <<EOF
POSTGRES_PASSWORD=$(openssl rand -hex 32)
TALOS_MASTER_KEY=$(openssl rand -hex 32)   # dev only; production: KEK_PROVIDER=vault
KEK_PROVIDER=env
JWT_SECRET=$(openssl rand -hex 32)
DATABASE_URL=postgres://talos:\${POSTGRES_PASSWORD}@localhost:5432/talos
RUST_LOG=info,controller=debug
BASE_URL=http://localhost:8000
FRONTEND_URL=http://localhost:3000
ALLOWED_ORIGIN=http://localhost:3000
TRUSTED_IPS=127.0.0.1,::1
EOF

# Bring up infra and run migrations
docker-compose up -d postgres
sleep 5 && sqlx migrate run

# Start the stack
docker-compose up -d
```

Production deployments use the Helm chart in `deploy/helm/talos/` and HashiCorp Vault for the KEK. See `deploy/k3s/README.md` for the single-VM runbook (Hetzner CPX31 + k3s + Sigstore enforcement enabled).

---

## Development

```bash
make up-dev                # Start all services
make lint                  # Lint Rust + frontend + structural lint
make coverage              # Tests with coverage
cargo check --workspace    # Quick Rust compile check
cargo test --workspace     # Full test suite (~2,900 tests)
```

The `make lint` step runs `scripts/lint-structural.sh`, which enforces 20 architectural invariants tied to specific past regressions — raw `actor_memory` SQL outside `talos-memory/`, controller route ↔ nginx ConfigMap drift, the legacy `__agent_context__` key, per-call `SecretsManager::new(...)` outside canonical wiring, helm chart clean-render with toggles, raw sqlx in MCP handlers, clippy parity, `trigger_type` / boolean column drift against schema, silent `let _ = sqlx::query(...).await` swallows outside tests, misleading-success Err-only webhook fires, caller-supplied limit clamp drift, chart-wide labels under NetworkPolicy selectors, async-graphql `Error::new` missing `.extend_safe()`, graph-JSON writes via canonical chokepoint, WIT-file drift between `wit/` and `module-templates/wit/`, `encrypted_secrets: Default::default()` outside tests, JobResult `.sign()` not using `sign_with_worker_id`, worker dual-publishing of JobResult, and wasmtime WASM proposal opt-in/out drift.

---

## Comparison

| Property | Talos | LangGraph / CrewAI | Temporal | Microsoft Wassette | HiddenLayer agentic runtime |
|---|---|---|---|---|---|
| WASM sandbox | yes | no | no | yes | runtime monitoring, not sandboxing |
| Capability gating | yes (lattice, 11 worlds) | no | no | yes (deny-by-default) | no |
| Credential-free worker | yes | no | partial | no | no |
| Signed cross-process RPC | HMAC + nonce cache | no | yes (built-in) | no | no |
| Per-actor data-egress policy | yes (HMAC-bound tier ceiling) | no | no | no | no |
| Sigstore-verified module supply chain | yes | no | no | partial | no |
| AI agent primitives built in | yes (judge / ensemble / dispatch) | yes | no (BYO) | no | no |

The differentiators are the credential-isolation primitive and the signed data plane. WASM sandboxing alone has become commodity (Wassette is excellent at it); the runtime properties that compose on top of the sandbox are where this project's bet lives.

---

## Documentation

- `deploy/k3s/README.md` — Single-VM production runbook
- `docs/deployment.md` — Service inventory, env-var reference, Vault/KEK rotation
- `docs/security/architecture.md` — Security architecture with diagrams
- `docs/security/threat-model.md` — STRIDE threat model (7 trust boundaries)
- `docs/security/operational-runbook.md` — Encryption posture, KEK/DEK rotation, supply-chain hygiene
- `docs/compliance/soc2-control-mapping.md` — SOC 2 control mapping
- `docs/architecture/managed-cloud.md` — Managed-cloud design document
- `CHANGELOG.md` — Detailed changelog
- `CLAUDE.md` — Development guidelines + structural-lint rationale

---

## License

Dual-licensed under [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE), at your option. Pick whichever fits your downstream needs.

## About

Built by Evan Helbig as a personal portfolio project exploring what a security-first agent execution runtime would look like if designed from the ground up. Talos is unaffiliated with any employer and uses no proprietary or employer-derived code.

If you're working on agent runtime security, AI sandboxing, or AppSec for agentic systems and the architecture here is relevant to what you're building, I'd be glad to hear from you — open a GitHub Discussion or reach out via the contact links on my profile.

# Talos Configuration Reference

> Authoritative inventory of every environment variable read by the Talos
> workspace. Generated 2026-07-24 by sweeping all Rust `env::var` /
> `std::env::var` / `option_env!` read sites (352 direct sites across the
> workspace) plus the `talos-config` accessor wrappers (`get_env`,
> `read_env_or_file`, `bool_env_or_default`, `positive_env_or_default`,
> `nonzero_env_or_default`, `validate_shared_secret_token`), cross-referenced
> against `.env.example`, docker-compose, and the Helm chart.
>
> **Total: ~205 distinct runtime variables** (≈155 operator-facing config
> vars + ≈50 memory/ML/integration tuning knobs), plus a handful of
> compile-time `env!()` values and ~14 test-only vars listed separately at
> the end. This matches the expected count for the workspace.

## Naming convention (binding rule going forward)

**New environment variables MUST be `TALOS_`-prefixed.** Bare names
(`DATABASE_URL`, `BCRYPT_COST`, `EMBEDDING_MODEL`, …) are **legacy**: they
predate the convention, are widely deployed, and stay supported — but no new
bare-named variable should be introduced. The prefix prevents collisions with
other software sharing the environment (systemd units, sidecars, CI) and
makes `env | grep TALOS_` a complete operator audit.

Workspace-wide read conventions:

- **Empty string = unset.** Nearly all optional reads use
  `.ok().filter(|v| !v.is_empty())` — `VAR=""` behaves like the variable is
  absent (intentional hardening; see the MCP-590/591/597/598 fix family and
  the `zero_env_var_footgun` pattern).
- **`<VAR>_FILE` siblings.** Secrets that support the Docker-secrets pattern
  are read through `talos_config::read_env_or_file`, which prefers the
  `_FILE` path variant when set.
- **`<VAR>_PREVIOUS` siblings.** Keys that support zero-downtime rotation
  accept the previous value under a `_PREVIOUS` name during the overlap
  window.

Column legend — **Component**: controller / worker / both (read in a shared
crate used by both) / crate name for leaf-crate reads. **Sensitive**: 🔒 =
secret material, trust anchor, or a security-posture switch; never log its
value, log presence only.

---

## 1. Core / Database / NATS / Redis / Neo4j

| Variable | Default | Component | Purpose | Sensitive |
|---|---|---|---|---|
| `DATABASE_URL` | required | both | Primary Postgres DSN; pool creation | 🔒 (embeds credentials) |
| `DATABASE_READ_REPLICA_URL` | none (optional) | controller | Read-replica DSN; falls back to primary if unset (`talos-db`) | 🔒 |
| `DB_MAX_CONNECTIONS` | `30` | controller | Postgres pool max connections | |
| `DB_READ_REPLICA_MAX_CONNECTIONS` | `20` | controller | Replica pool max connections | |
| `DB_STATEMENT_TIMEOUT_SECS` | `60` | both | Per-statement timeout applied to the pool | |
| `DB_EXECUTION_TIMEOUT_SECS` | `300` | both | Longer statement timeout for the execution-path pool | |
| `REDIS_URL` | none (optional) | both | Redis connection; Redis-backed features disabled when unset | 🔒 |
| `NATS_URL` | none (controller) / effectively required (worker) | both | NATS server URL | |
| `NATS_USER` | none (optional) | both | NATS username | |
| `NATS_PASSWORD` (+`_FILE`) | none (optional) | both | NATS password | 🔒 |
| `NATS_CA_FILE` | none (optional) | both | PEM path added as trusted root for NATS TLS (`talos-nats-tls`) | 🔒 |
| `NATS_JOB_TOPIC` | built-in topic | worker | Single-job subscription subject | |
| `NATS_PIPELINE_TOPIC` | built-in topic | worker | Pipeline-job subscription subject | |
| `WORKFLOW_NATS_PREFIX` | `workflow` | both | NATS subject prefix for engine dispatch | |
| `NEO4J_URI` | none (optional) | both | Graph-RAG Neo4j URI; graph features disabled when unset | |
| `NEO4J_USER` | `neo4j` | both | Neo4j username | |
| `NEO4J_PASSWORD` | required if Neo4j used | both | Neo4j password | 🔒 |
| `TALOS_DEPLOYMENT_TOPOLOGY` | `single_pod` | controller | Deployment topology selector | |
| `RUST_ENV` | `development` | both | Master environment switch; `production` gates fail-closed behavior workspace-wide (`talos_config::is_production`) | 🔒 (posture) |

Production TLS note: Redis/NATS/Postgres/Neo4j production connections refuse
plaintext URLs at boot (lint check 44, `tls-prod-gate-*`).

## 2. Auth / Security

### Sessions, JWT, passwords, 2FA

| Variable | Default | Component | Purpose | Sensitive |
|---|---|---|---|---|
| `JWT_SECRET` (+`_FILE`) | required (HS\*) | both | HMAC JWT signing secret | 🔒 |
| `JWT_PRIVATE_KEY` (+`_FILE`) | required (RS/ES) | both | Asymmetric JWT signing key (PEM) | 🔒 |
| `JWT_PUBLIC_KEY` (+`_FILE`) | required (RS/ES) | both | JWT verification key | 🔒 |
| `JWT_PUBLIC_KEY_PREVIOUS` (+`_FILE`) | none (optional) | both | Previous JWT public key for rotation overlap | 🔒 |
| `JWT_ALGORITHM` | `HS256` | both | JWT algorithm selection | |
| `JWT_ALGORITHM_PREVIOUS` | none (optional) | both | Previous algorithm during rotation (`talos-auth`) | |
| `JWT_REQUIRE_AUD` | `false` | both | Enforce the JWT `aud` claim per request | 🔒 (posture) |
| `BCRYPT_COST` | `12` | both | Bcrypt cost factor for password hashing | 🔒 (tuning) |
| `API_KEY_BCRYPT_COST` | built-in default | talos-api-keys | Bcrypt cost for API-key hashing | 🔒 (tuning) |
| `TOTP_ISSUER` | `Talos` | both | TOTP issuer label shown in authenticator apps | |
| `BOOTSTRAP_FIRST_USER_EMAIL` | none (optional) | both | Pin the first bootstrap admin user email (`talos-auth`) | |

### Encryption keys / Vault (KEK/DEK)

| Variable | Default | Component | Purpose | Sensitive |
|---|---|---|---|---|
| `TALOS_MASTER_KEY` (+`_FILE`) | required when `KEK_PROVIDER=env` | both | Master KEK for envelope encryption | 🔒 |
| `KEK_PROVIDER` | `env` | controller | KEK provider kind (`env` / `vault`) | 🔒 |
| `TALOS_ALLOW_ENV_KEK` | unset (refuse) | controller | Explicit opt-in required to boot production with an env-var KEK (lint check 45; fails closed) | 🔒 |
| `KEK_DISABLE_LEGACY` | `false` | controller | Disable the legacy KEK path | 🔒 |
| `DEK_CACHE_TTL_SECS` | `300` | both | DEK cache TTL | |
| `VAULT_ADDR` (+`_FILE`) | none | both | HashiCorp Vault address | 🔒 |
| `VAULT_TOKEN` (+`_FILE`) | none | both | Vault auth token | 🔒 |
| `VAULT_TRANSIT_KEY_NAME` (+`_FILE`) | none | both | Vault transit key name | 🔒 |
| `VAULT_TRANSIT_MOUNT` (+`_FILE`) | none | both | Vault transit mount path | 🔒 |
| `VAULT_CACERT` | none (optional) | controller | Vault CA certificate path | 🔒 |

### Admin / network-edge gates

| Variable | Default | Component | Purpose | Sensitive |
|---|---|---|---|---|
| `ADMIN_SECRET_KEY` | `""` (disabled) | both | Constant-time `X-Admin-Secret` compare for admin endpoints | 🔒 |
| `ENABLE_ADMIN_OPS` | `false` | both | "Big red button" gate enabling admin ops | 🔒 |
| `PROMETHEUS_SCRAPE_TOKEN` | none (optional) | controller | Bearer token gating `/metrics` scrape | 🔒 |
| `METRICS_AUTH_TOKENS` | none (optional) | worker | Comma-separated tokens gating the worker metrics endpoint | 🔒 |
| `ALLOWED_ORIGIN` | dev: localhost list; prod: **required** (panics unset) | both | CORS allowed origins (credentialed requests) | 🔒 |
| `ALLOW_DEV_UNSAFE_CSRF_BYPASS` | `false` | both | Dev-only `/graphql` CSRF disable; panics in production if truthy | 🔒 |
| `CSP_REPORT_URI` | none (optional) | both | Content-Security-Policy report endpoint | |
| `ENABLE_HSTS` | bool default | both | Emit HSTS header | |
| `TRUSTED_IPS` | none (optional) | controller | IP allowlist | 🔒 |
| `TRUSTED_PROXY_CIDRS` | `""` | both | Trusted reverse-proxy CIDRs for RFC 7239 client-IP extraction (rate limiting) | 🔒 |
| `FRONTEND_URL` | `http://localhost:3000` | both | Frontend base for OAuth redirects (validated; open-redirect guard) | 🔒 |
| `BASE_URL` | `http://localhost:8000` | both | Public API base for webhook/callback URLs (`talos_config::get_base_url`) | 🔒 |
| `CACHE_ADMIN_USER_IDS` | none | controller | User ids permitted cache-admin operations | 🔒 |

### RLS / tenancy / RPC posture

| Variable | Default | Component | Purpose | Sensitive |
|---|---|---|---|---|
| `TALOS_RLS_SET_ROLE` | none (optional) | both | Role name for the RLS `SET ROLE` enforcement path | 🔒 |
| `TALOS_ALLOW_RLS_DISABLED` | unset (refuse) | both | Explicit opt-in to run with Postgres RLS disabled | 🔒 |
| `TALOS_RPC_REQUIRE_ED25519` | unset | both | Require Ed25519-signed NATS-RPC auth | 🔒 |
| `TALOS_RPC_GUEST_ROLE` | none (optional) | both | Guest role for unauthenticated RPC (`talos-rpc-subscribers`) | 🔒 |
| `TALOS_ALLOW_UNSCOPED_DB_SANDBOX` | unset | both | Allow unscoped DB access in the SQL sandbox | 🔒 |

### Controller↔worker dispatch trust (signing keys)

| Variable | Default | Component | Purpose | Sensitive |
|---|---|---|---|---|
| `TALOS_CONTROLLER_SIGNING_KEY` | required for signed dispatch | controller | Ed25519 seed (hex) signing job dispatch + SealedSecrets | 🔒 |
| `TALOS_CONTROLLER_PUBLIC_KEY` / `_PREVIOUS` | none | worker | Controller Ed25519 verify key(s) | 🔒 |
| `TALOS_WORKER_SIGNING_KEY` | none | worker | Worker Ed25519 signing key | 🔒 |
| `TALOS_WORKER_PUBLIC_KEYS` | none | controller | Worker Ed25519 public keys (static fleet identity) for result verification | 🔒 |
| `TALOS_DISPATCH_SCHEME` | `""` | both | Dispatch signing scheme selector (`ed25519`) | 🔒 |
| `TALOS_DISPATCH_REQUIRE_ED25519` | unset (fail-open to HMAC) | worker | Require Ed25519-signed dispatch (fail-closed flag) | 🔒 |
| `TALOS_RESULT_REQUIRE_ED25519` | unset | controller | Require Ed25519-signed job results | 🔒 |
| `TALOS_SIGNATURE_DIAG` | off | both | Signature diagnostic logging | |
| `WORKER_SHARED_KEY` (+`_FILE`, `_PREVIOUS`) | none | both | HMAC shared key for worker auth (rotation-capable); also the IKM for checkpoint/envelope AEAD derivations | 🔒 |
| `TALOS_AOT_HMAC_KEY` / `_PREVIOUS` | none | worker | HMAC key signing AOT-compiled WASM cache entries | 🔒 |
| `TALOS_AUDIT_SIGNING_KEY` / `_PREVIOUS` | none | both | Key signing hash-chained audit-ledger entries (`talos-audit-event`) | 🔒 |
| `TALOS_WORKFLOW_SIGNING_KEY` | none | both | Key for workflow-definition signatures | 🔒 |
| `TALOS_WORKFLOW_SIGNING_STRICT` | `false` | both | Reject unsigned workflows | 🔒 |
| `TALOS_WORKER_REGISTRATION_TOKEN` | none (optional) | controller | Shared token for worker self-registration | 🔒 |
| `TALOS_WORKER_REG_REQUIRE_BOUND_TOKEN` | unset | controller | Require a bound registration token | 🔒 |
| `TALOS_WORKER_KEY_REFRESH_SECS` | `60` | controller | Worker key refresh sweep interval | |
| `TALOS_ENVELOPE_SEALING` | unset (OFF = legacy inline WSK envelope) | both | Per-execution secret-envelope sealing mode (`audit` / `required`; RFC 0010 P3) | 🔒 |

### SSO / OAuth login providers

| Variable | Default | Component | Purpose | Sensitive |
|---|---|---|---|---|
| `OKTA_DOMAIN` | none (optional) | both | Okta SSO domain (rejects `@` in value) | 🔒 |
| `OKTA_CLIENT_ID` / `OKTA_CLIENT_SECRET` / `OKTA_REDIRECT_URI` | none | both | Okta OAuth client credentials + redirect | 🔒 (id/secret) |
| `SNYK_CLIENT_ID` / `SNYK_CLIENT_SECRET` / `SNYK_REDIRECT_URI` | none | both | Snyk OAuth integration credentials + redirect | 🔒 (id/secret) |

## 3. Worker / WASM runtime

| Variable | Default | Component | Purpose | Sensitive |
|---|---|---|---|---|
| `TALOS_WORKER_ID` | derived | worker | Explicit worker identity override | |
| `HOSTNAME` | pod hostname | both | Fallback worker id / job host tag | |
| `WASM_EXECUTION_TIMEOUT_SECS` | `120` | both | Per-node WASM execution timeout | |
| `TALOS_MAX_CONCURRENT_NODES` | `8` (clamped ≥1) | both | Max concurrent node dispatch within an execution | |
| `TALOS_MAX_CONCURRENT_EXECUTIONS` | built-in default | both | Execution-level concurrency semaphore | |
| `WASM_RESULT_CACHE_CAPACITY` | `256` | worker | Result-cache entry cap | |
| `WASM_INSTANCE_CACHE_MAX_PER_TIER` | `256` | worker | Instance-cache cap per tier | |
| `WASM_RESULT_CACHE_TTL_SECS` | none (disabled if unset) | worker | Result-cache TTL | |
| `TALOS_DISABLE_POOLING` | `false` | worker | Disable wasmtime instance pooling | |
| `TALOS_WASM_DEBUG_INFO` | off | worker | Emit WASM debug info | |
| `WASM_MAX_JSON_SIZE` | built-in default | worker | Max JSON parse/serialize size in host functions | |
| `WASM_MAX_SOURCE_BYTES` | built-in default | talos-compilation | Cap on module source size before compile | |
| `WASM_ALLOW_INSECURE_HTTP` | off | worker | Allow plaintext HTTP egress from modules | 🔒 |
| `WASM_CACHE_RETENTION_DAYS` | `30` | controller | WASM cache row retention | |
| `WASM_CACHE_MAX_MODULES` | `1000` | controller | WASM cache module cap | |
| `WASM_CACHE_MAX_SIZE_MB` | `500` | controller | WASM cache size cap | |
| `WORKER_MAX_JOB_RESULT_BYTES` | 4 MiB | worker | Max serialized job result size | |
| `WORKER_MAX_OCI_LAYER_BYTES` | 32 MiB | worker | Max OCI layer size pulled when fetching modules | |
| `WORKER_ALLOW_PRIVATE_HOST_TARGETS` | `false` | worker | Allow module egress to private/internal IPs (SSRF gate) | 🔒 |
| `METRICS_PORT` | `9090` | worker | Worker Prometheus port | |
| `TALOS_INLINE_WASM_MAX_BYTES` | built-in default | both | Cap on inline-dispatched WASM bytes | |
| `TALOS_ENCRYPT_EXECUTION_OUTPUT` | flag | both | Encrypt stored execution output | 🔒 |
| `TALOS_SQL_PERMISSIVE_EMPTY_ALLOWLIST` | unset | worker | Permit an empty SQL allowlist in the sandbox | 🔒 |
| `TALOS_WIT_GRAPHQL_BLOCK_INTROSPECTION` | unset | worker | Block GraphQL introspection from guest modules | 🔒 |
| `TALOS_DEFAULT_WIT_WORLD` | `minimal-node` | both | Default WIT capability world | |
| `CIRCUIT_BREAKER_CLEANUP_SECS` | `300` | worker | Circuit-breaker cleanup interval | |
| `CIRCUIT_BREAKER_MAX_AGE_SECS` | `1800` | worker | Max age before breaker state is pruned | |
| `CIRCUIT_BREAKER_SUCCESS_RATE` | built-in default (f64) | worker | Success-rate threshold to close the breaker | |

## 4. Module compilation / build toolchain

| Variable | Default | Component | Purpose | Sensitive |
|---|---|---|---|---|
| `TALOS_MAX_COMPILATIONS` | `3` (clamped ≥1) | talos-compilation | Concurrent-compile semaphore | |
| `TALOS_WIT_PATH` | `$CARGO_MANIFEST_DIR/../wit/talos.wit` | talos-compilation | Override WIT fixture path (host-side runs) | |
| `TALOS_SDK_MACROS_PATH` | `/app/talos_sdk_macros` | talos-compilation | Path to the SDK macros crate for scaffolding | |
| `CARGO_TARGET_DIR` | cargo default | talos-compilation | Cargo target dir for runtime compiles | |
| `TALOS_COMPILE_TARGET_CACHE` | enabled | talos-compilation | Enable the per-USER persistent compile target cache (per-user scoping is a security invariant — never fleet-share) | 🔒 |
| `TALOS_COMPILE_TARGET_CACHE_DIR` | `/tmp/cargo-target/per-user` | talos-compilation | Target-cache directory root | |
| `TALOS_COMPILE_TARGET_CACHE_TTL_HOURS` | built-in default | talos-compilation | Target-cache idle TTL | |
| `TALOS_COMPILATION_CONTAINER` | built-in default | talos-compilation | Container image/runtime for sandboxed compiles | |
| `TALOS_COMPILATION_ALLOW_HOST_FALLBACK` | off (prod requires the literal ack token `acknowledge-single-tenant-rce-risk`) | talos-compilation | Allow host-side JS/Python compile (RCE risk) | 🔒 |
| `TALOS_ADVISORY_DB_MAX_AGE_DAYS` | `90` | talos-compilation | Max RustSec advisory-DB age; fails closed in prod | 🔒 |
| `MCP_ALLOWED_CRATE_DEPENDENCIES` | built-in allowlist | talos-compilation | Replace the allowed crate-dependency allowlist | 🔒 |
| `MCP_ALLOWED_CRATE_DEPENDENCIES_EXTRA` | none | talos-compilation | Append extra allowed crate dependencies | 🔒 |
| `COMPILE_DIR` | `/tmp/talos-compilations` | talos-compilation | Compilation workspace root | |

## 5. LLM providers / embeddings

| Variable | Default | Component | Purpose | Sensitive |
|---|---|---|---|---|
| `ANTHROPIC_API_KEY` | none (vault-first; env is fallback) | both | Anthropic key fallback for LLM + graph-RAG | 🔒 |
| `OPENAI_API_KEY` | none (optional) | controller | OpenAI key for embeddings fallback | 🔒 |
| `OLLAMA_URL` | `http://ollama:11434` | both | Local Ollama endpoint (Tier-1 local LLM) | |
| `EMBEDDING_API_URL` | none (optional) | both | Embedding service URL | |
| `EMBEDDING_API_KEY` | none (optional) | both | Embedding API key | 🔒 |
| `EMBEDDING_MODEL` | built-in default | both | Embedding model name | |
| `EMBEDDING_DIMENSIONS` | `768` | both | Embedding vector dimension | |
| `EMBEDDING_TIMEOUT_SECS` | `8` (clamped 1–60) | both | Embedding request timeout | |
| `TALOS_GRAPH_RAG_MODEL` | `qwen2.5:7b` | both | Graph-RAG entity-extraction model | |
| `TALOS_GRAPH_RAG_TIER1_LOCAL_OK` | `false` | controller | Attestation that Ollama is on-host so Tier-1 graph extraction may run locally | 🔒 (privacy) |
| `SEMANTIC_SEARCH_MIN_SCORE` | `0.40` (clamped 0–1) | controller | Default cosine floor for semantic search | |

Note: LLM provider API keys are **vault-first** (`job_protocol::LLM_PROVIDER_VAULT_PATHS`);
the env vars above are fallbacks only. See CLAUDE.md "LLM key resolution".

## 6. Integrations (Google / Gmail / Slack / Atlassian / Email / S3 / DLP)

| Variable | Default | Component | Purpose | Sensitive |
|---|---|---|---|---|
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` / `GOOGLE_REDIRECT_URI` | none (canonical) | both | Google OAuth client credentials + redirect | 🔒 (id/secret) |
| `GMAIL_CLIENT_ID` / `GMAIL_CLIENT_SECRET` / `GMAIL_REDIRECT_URI` | none | talos-gmail / talos-oauth | **Legacy fallback** spelling for the Google OAuth credentials (see duplicates) | 🔒 (id/secret) |
| `GMAIL_PUBSUB_TOPIC` | none (optional) | controller | Gmail push Pub/Sub topic | |
| `GMAIL_PUBSUB_AUDIENCE` | none (optional) | controller | JWT audience for Gmail push verification | 🔒 |
| `GMAIL_PUBSUB_SERVICE_ACCOUNT` | none (optional) | controller | Expected service-account email for Gmail push | 🔒 |
| `GMAIL_DEFAULT_LABEL_IDS` | `INBOX` | controller | Default Gmail labels to watch | |
| `GOOGLE_CALENDAR_REDIRECT_URI` | none (optional) | talos-google-calendar | Calendar-specific connect redirect | |
| `GOOGLE_CLOUD_CLIENT_ID` / `GOOGLE_CLOUD_CLIENT_SECRET` / `GOOGLE_CLOUD_REDIRECT_URI` | none (fall back to `GOOGLE_*`) | talos-google-cloud | GCP OAuth client credentials + redirect | 🔒 (id/secret) |
| `GCP_PUBSUB_AUDIENCE` | none (optional) | controller | JWT audience for GCP Pub/Sub push verification | 🔒 |
| `SLACK_CLIENT_ID` / `SLACK_CLIENT_SECRET` / `SLACK_REDIRECT_URI` | none | talos-slack | Slack OAuth credentials + redirect | 🔒 (id/secret) |
| `ATLASSIAN_CLIENT_ID` / `ATLASSIAN_CLIENT_SECRET` / `ATLASSIAN_REDIRECT_URI` | none | talos-atlassian | Atlassian OAuth credentials + redirect | 🔒 (id/secret) |
| `EMAIL_API_URL` | none (optional) | worker | Outbound email API URL (host function) | |
| `EMAIL_API_KEY` | none (optional) | worker | Email API key | 🔒 |
| `EMAIL_FROM` | built-in default | worker | Default From address | |
| `S3_ENDPOINT` | none (optional) | worker | S3 endpoint for module host storage | |
| `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` | none | worker | S3 credentials | 🔒 |
| `S3_REGION` | built-in default | worker | S3 region | |
| `DLP_PROVIDER` | `builtin` | talos-dlp-provider | DLP provider selection | |
| `DLP_WEBHOOK_URL` | `""` | talos-dlp-provider | External DLP webhook URL | |
| `DLP_WEBHOOK_TOKEN` | none (optional) | talos-dlp-provider | DLP webhook auth token | 🔒 |
| `TALOS_POLICY_NOTIFICATION_WEBHOOK` | none (optional) | talos-actor-policies | Webhook for actor-policy violation alerts | |

## 7. Publishing / Deploy / OCI registry / Attestation

| Variable | Default | Component | Purpose | Sensitive |
|---|---|---|---|---|
| `TALOS_REGISTRY_URL` | none (opt-in; empty = disk seeding) | both | OCI registry URL for template sync (mutually exclusive with disk seeding) | |
| `TALOS_REGISTRY_NAMESPACE` | `talos-tools` | talos-registry | OCI namespace for templates | |
| `OCI_REGISTRY_USERNAME` / `OCI_REGISTRY_PASSWORD` | none (anonymous) | both | OCI registry basic-auth (PAT works as password for GHCR) | 🔒 |
| `REGISTRY_PUBLISH_TOKEN` | none (optional) | talos-registry | Bearer token gating the template publish API | 🔒 |
| `TALOS_SIGSTORE_REQUIRED` | prod refuses OCI sync unless an explicit policy is set | both | Sigstore verification policy: `required` / `audit` / `disabled` | 🔒 |
| `TALOS_SIGSTORE_IDENTITY_REGEXP` | `""` | both | cosign `--certificate-identity-regexp` (pin to the publish workflow URL or operator identity) | 🔒 |
| `TALOS_SIGSTORE_OIDC_ISSUER` | `https://token.actions.githubusercontent.com` | both | cosign OIDC issuer pin | 🔒 |
| `TALOS_COSIGN_MIN_VERSION` | none (optional) | worker | Minimum cosign binary version | 🔒 |
| `TALOS_COSIGN_SHA256` | none (optional) | worker | Pin the cosign binary SHA-256 | 🔒 |
| `TALOS_ALLOW_UNATTESTED_WASM` | off | worker | Permit unattested WASM modules | 🔒 |
| `TALOS_OCI_ACCEPT_UNVERIFIED_MANIFESTS` | off | worker | Accept unverified OCI manifests | 🔒 |

Script-level publish knobs (`scripts/publish-images.sh`, not Rust reads):
`TALOS_PUBLISH_SIGN`, `TALOS_PUBLISH_SKIP_CI_CHECK`, `GITHUB_TOKEN`/`GHCR_TOKEN` 🔒.

## 8. Observability / telemetry

| Variable | Default | Component | Purpose | Sensitive |
|---|---|---|---|---|
| `JAEGER_ENDPOINT` | none (optional) | both | OTLP/Jaeger trace export endpoint | |
| `OTEL_TRACES_SAMPLER` | none (optional) | both | OTel trace sampler selection | |
| `OTEL_TRACES_SAMPLER_ARG` | none (optional) | both | OTel sampler argument | |
| `OTEL_METRICS_ENABLED` | bool default | both | Enable OTel metrics export | |
| `TALOS_SELF_ALERTS` | flag | talos-ops-alerts-repository | Enable self-monitoring ops alerts | |

## 9. Public URL / tunnel

| Variable | Default | Component | Purpose | Sensitive |
|---|---|---|---|---|
| `TALOS_PUBLIC_BASE_URL` | none (optional; wins over discovery) | both | Explicit public origin for external URLs (validated) | 🔒 (open-redirect) |
| `TALOS_NGROK_API_URL` | none (optional) | both | ngrok local API to auto-discover the tunnel URL | |
| `TALOS_PUBLIC_URL_REFRESH_SECS` | `60` (min 10) | both | ngrok URL refresh interval | |
| `NGROK_AUTHTOKEN` | none | compose (shell) | Starts the ngrok sidecar (compose profile `public`) | 🔒 |
| `NGROK_STATIC_DOMAIN` | none | compose (shell) | Reserved ngrok domain | |
| `VITE_API_URL` | `http://localhost:4003` | frontend (build) | Frontend GraphQL endpoint | |

## 10. Tuning knobs / caches / timeouts / retention

| Variable | Default | Component | Purpose | Sensitive |
|---|---|---|---|---|
| `EXECUTION_RETENTION_DAYS` | `30` | controller | Workflow-execution retention (destructive-zero guarded) | |
| `EXECUTION_MAX_ROWS` | `100000` | controller | Max execution rows retained | |
| `ARCHIVE_AFTER_DAYS` | `30` | controller | Archive-after age | |
| `AUDIT_LOG_RETENTION_DAYS` | `90` | controller | Audit-log retention | |
| `STUCK_EXECUTION_TIMEOUT_MINS` | `30` | controller | Mark executions stuck after N minutes | |
| `EXECUTION_RESUME_STALE_MINS` | `5` | controller | Stale threshold to resume executions | |
| `STALE_EXECUTION_MINUTES` | `60` | controller | Stale-execution sweep threshold | |
| `SCHEDULER_EXECUTION_TIMEOUT_SECS` | `3600` | talos-scheduler | Scheduled-execution timeout | |
| `TALOS_APPROVAL_TIMEOUT_SECS` | `86400` | both | Human-approval-gate timeout | |
| `TALOS_SEAL_ORPHAN_TTL_SECS` | `600` | both | Envelope-seal orphan lease TTL | |
| `TALOS_SEAL_SWEEP_INTERVAL_SECS` | `60` | both | Envelope-seal sweep cadence | |
| `LLM_KEYS_SWEEP_INTERVAL_SECS` | `300` | controller | LLM-key cache sweep interval | |
| `AUDIT_CHAIN_SWEEP_INTERVAL_SECS` | `3600` | controller | Audit-chain verify sweep | |
| `MODULES_RECONCILE_INTERVAL_SECS` | `600` | controller | Module reconcile loop interval | |
| `CHECKPOINT_EVERY_N_NODES` | `1` | both | Execution checkpoint frequency | |
| `EXECUTION_CHECKPOINTING_ENABLED` | bool default | both | Enable execution checkpointing | |
| `TALOS_CHAIN_MAX_WORKFLOWS` | `50` | both | Max workflows in a chain | |
| `TALOS_CHAIN_CONCURRENCY` | `8` | both | Chain fan-out concurrency | |
| `TALOS_NATS_TIMEOUT_SECS` | `0` (disabled) | both | NATS request-reply timeout | |
| `TALOS_ADAPTIVE_FUEL` | flag | both | Adaptive WASM fuel metering | |
| `TALOS_NODE_CACHE` | bool default | both | Node-output cache | |
| `TALOS_MAX_YAML_BYTES` | 1 MiB | both | Max YAML workflow size | |
| `ENABLE_EDGE_ROUTING` | `false` | both | Per-user vs shared NATS dispatch topic | |
| `ENFORCE_RATE_LIMITS_IN_DEV` | bool default | both | Apply rate limits in dev | |
| `TALOS_WEBHOOK_USER_RPM` | `300` | talos-webhooks | Per-user webhook rate limit | |
| `MCP_AGENT_RATE_LIMIT_PER_MIN` | `1000` | both | MCP agent rate limit | |
| `MCP_USER_RATE_LIMIT_PER_MIN` | `5000` | both | MCP user rate limit | |
| `MCP_AUTH_RATE_LIMIT` | `60` | both | MCP auth attempts per window | |
| `MCP_AUTH_RATE_WINDOW` | `60` | both | MCP auth window (seconds) | |
| `MCP_EXPENSIVE_OP_RATE_LIMIT` | `10` | both | Rate limit for expensive MCP operations | |
| `MCP_TOKEN_REVALIDATION_INTERVAL_SECS` | `60` | both | MCP token revalidation cadence | |
| `TALOS_WRITE_CEILING_ENFORCED` | bool default | both | Enforce actor write ceiling | 🔒 (posture) |
| `TALOS_WRITE_CEILING_STRICT_EGRESS` | bool default | both | Strict egress under the write ceiling | 🔒 (posture) |
| `TALOS_DISTRIBUTED_REPLAY` | off | controller | Enable distributed replay | |
| `TALOS_REPLAY_FAIL_CLOSED` | policy default | both | Fail closed on replay-guard errors | 🔒 (posture) |
| `TALOS_VERSION` | derived from build | controller | Build/version string override | |
| `TALOS_BASE_URL` | none (optional) | controller | Platform base-URL override for status responses (see duplicates) | |

### Memory / adaptive-ranking feature flags & weights (`talos-config`; both components)

Several default **ON** as of the 2026-07 "Tier 3" learning-loops cutover.

| Variable | Default | Purpose | Sensitive |
|---|---|---|---|
| `ENABLE_SMART_MEMORY_CONTEXT` | on | Smart (bounded/ranked) memory-context assembly vs legacy | |
| `ENABLE_ACTOR_CONTEXT_INJECTION` | on | Fleet-wide kill-switch for `__actor_context__` injection | |
| `ENABLE_RANKED_RECALL` | on | Ranked memory recall | |
| `ENABLE_SMART_MEMORY_HYDE` | off | HyDE query expansion for recall | |
| `ENABLE_MEMORY_CONSOLIDATION` | on | Background memory consolidation loop | |
| `ENABLE_MEMORY_REFLECTION` | on | Background memory reflection loop | |
| `ENABLE_MEMORY_RANK_PROVENANCE` | on | Record rank-provenance rows | |
| `ENABLE_ADAPTIVE_RANK` | on | Per-actor learned ranking weights | |
| `ENABLE_ADAPTIVE_RANK_TRAINING` | on | Background rank-weight training | |
| `MEMORY_CONSOLIDATION_TIER1_LOCAL_OK` | `false` | Attestation: consolidation LLM is local (Tier-1 actors) | 🔒 (privacy) |
| `MEMORY_REFLECTION_TIER1_LOCAL_OK` | `false` | Attestation: reflection LLM is local (Tier-1 actors) | 🔒 (privacy) |
| `SMART_MEMORY_CONTEXT_BYTE_BUDGET` | `12000` | Context byte budget | |
| `SMART_MEMORY_CONTEXT_PER_MEMORY_CAP` | `3000` | Per-memory byte cap | |
| `SMART_MEMORY_CONTEXT_MIN_SCORE` | `0.25` | Min fused score to include | |
| `SMART_MEMORY_CONTEXT_W_RELEVANCE` | `1.0` | Fused-rank relevance weight | |
| `SMART_MEMORY_CONTEXT_W_RECENCY` | `0.3` | Fused-rank recency weight | |
| `SMART_MEMORY_CONTEXT_W_IMPORTANCE` | `0.5` | Fused-rank importance weight | |
| `SMART_MEMORY_CONTEXT_RECENCY_HALFLIFE_DAYS` | `7.0` | Recency decay half-life | |
| `SMART_MEMORY_CONTEXT_GRAPH_BASELINE` | `0.6` | Graph-signal baseline | |
| `SMART_MEMORY_CONTEXT_RECENCY_BASELINE` | `0.4` | Recency baseline | |
| `SMART_MEMORY_CONTEXT_ACCESS_WEIGHT` | `0.15` | Access-frequency weight | |
| `MEMORY_CONSOLIDATION_INTERVAL_SECS` | `86400` | Consolidation cadence | |
| `MEMORY_CONSOLIDATION_MIN_AGE_DAYS` | `30.0` | Min memory age to consolidate | |
| `MEMORY_CONSOLIDATION_MAX_IMPORTANCE` | `0.4` | Max importance to consolidate | |
| `MEMORY_CONSOLIDATION_BATCH_SIZE` | `20` | Rows per consolidation batch | |
| `MEMORY_CONSOLIDATION_MAX_ACTORS_PER_TICK` | `25` | Actor fan-out cap per tick | |
| `MEMORY_CONSOLIDATION_MODEL` | `qwen2.5:7b` | Consolidation LLM model | |
| `MEMORY_REFLECTION_INTERVAL_SECS` | `86400` | Reflection cadence | |
| `MEMORY_REFLECTION_INPUT_CAP` | `40` | Max memories fed to reflection | |
| `MEMORY_REFLECTION_MIN_MEMORIES` | `8` | Min memories before reflecting | |
| `MEMORY_REFLECTION_MAX_ACTORS_PER_TICK` | `25` | Actor fan-out cap per tick | |
| `MEMORY_REFLECTION_MODEL` | `qwen2.5:7b` | Reflection LLM model | |
| `MEMORY_RANK_PROVENANCE_RETENTION_DAYS` | `90` | Provenance row retention | |
| `ADAPTIVE_RANK_MIN_EXAMPLES` | `50` | Min examples before training | |
| `ADAPTIVE_RANK_TRAINING_INTERVAL_SECS` | `21600` | Training cadence | |
| `ADAPTIVE_RANK_LOOKBACK_DAYS` | `30` | Training lookback window | |
| `ADAPTIVE_RANK_MAX_ACTORS_PER_TICK` | `50` | Actor fan-out cap per tick | |
| `MEMORY_LOOP_MAX_ACTORS_PER_ORG_PER_TICK` | `0` (disabled) | Shared per-org fan-out cap across memory loops | |

### ML lifecycle jobs (`talos-ml`; controller-side)

| Variable | Default | Purpose |
|---|---|---|
| `ML_DIGEST_INTERVAL_SECS` | built-in (min 60) | ML digest job cadence |
| `ML_POLICY_EVAL_INTERVAL_SECS` | built-in (min 30) | Lifecycle-policy evaluation cadence |
| `ML_POLICY_EVAL_MIN_INTERVAL_SECS` | `3600` | Min interval between policy evaluations per model |
| `TALOS_TEACHER_AUDIT_INTERVAL_DAYS` | built-in (clamped) | Teacher-vs-gold audit cadence |
| `TALOS_TEACHER_AUDIT_CHECK_INTERVAL_SECS` | built-in (min bound) | Audit-due check cadence |

### Audit ledger / S3 WORM (`talos-audit-ledger`; both)

| Variable | Default | Purpose | Sensitive |
|---|---|---|---|
| `TALOS_AUDIT_S3_OBJECT_LOCK` | none (optional) | Enable S3 Object Lock on audit objects | 🔒 (posture) |
| `TALOS_AUDIT_S3_RETENTION_DAYS` | none (optional) | S3 retention period | |
| `AWS_ENDPOINT_URL` | none (optional) | Custom S3 endpoint | |
| `MINIO_ENDPOINT` | none (optional) | MinIO endpoint | |
| `MINIO_BUCKET` | `audit-logs` | Audit bucket name | |
| (standard `AWS_*` credential vars) | SDK defaults | Read implicitly by the AWS SDK (`load_defaults`) | 🔒 |

---

## Duplicate / deprecated / drift pairs

| Pair | Status |
|---|---|
| `GOOGLE_CLIENT_ID`/`_SECRET` ← `GMAIL_CLIENT_ID`/`_SECRET` | `GOOGLE_*` is canonical; the `GMAIL_*` spelling is a **legacy fallback** read second (`talos-oauth/src/credentials.rs`). Configure `GOOGLE_*` for new deployments. |
| `GOOGLE_CLOUD_CLIENT_ID`/`_SECRET` ← `GOOGLE_CLIENT_ID`/`_SECRET` | GCP-specific vars override; generic `GOOGLE_*` is the fallback. Intentional layering, not deprecation. |
| `BASE_URL` default drift | **RESOLVED 2026-07-24**: `talos-api-docs` previously read `BASE_URL` with a drifted `http://localhost:3000` default; it now calls the canonical `talos_config::get_base_url()` accessor (default `http://localhost:8000`, validated). One default everywhere. |
| `TALOS_BASE_URL` vs `BASE_URL` | Distinct today: `TALOS_BASE_URL` is a platform-status display override (`talos-mcp-handlers`), `BASE_URL` builds real callback/webhook URLs. Confusable naming; prefer `BASE_URL` (via `get_base_url`) for anything functional. |
| `<VAR>_FILE` / `<VAR>_PREVIOUS` families | Not duplicates — the Docker-secrets and key-rotation patterns: `JWT_SECRET(_FILE)`, `JWT_PRIVATE_KEY(_FILE)`, `JWT_PUBLIC_KEY(_FILE/_PREVIOUS)`, `JWT_ALGORITHM(_PREVIOUS)`, `WORKER_SHARED_KEY(_FILE/_PREVIOUS)`, `TALOS_AOT_HMAC_KEY(_PREVIOUS)`, `TALOS_AUDIT_SIGNING_KEY(_PREVIOUS)`, `TALOS_CONTROLLER_PUBLIC_KEY(_PREVIOUS)`, `TALOS_MASTER_KEY(_FILE)`, `VAULT_*(_FILE)`, `NATS_PASSWORD(_FILE)`. |
| `TALOS_MAX_CONCURRENT_EXECUTIONS` vs `TALOS_MAX_CONCURRENT_NODES` | Distinct knobs (execution-level vs node-level concurrency) — easily confused, not duplicates. |
| `OLLAMA_URL` | Read in ≥3 crates (worker host LLM, talos-config memory loops, controller graph-RAG) with the same default — widely read, not drifted. |

## Compile-time values (`env!()` — read at image build, not runtime)

- `CARGO_MANIFEST_DIR` — path resolution in `talos_sdk_macros`, `talos-registry`, `talos-module-templates`, `talos-compilation`.
- `CARGO_PKG_VERSION` — version strings in `talos-mcp-handlers`, `talos-api-docs`, `talos-trace`.
- `GIT_SHA`, `GIT_DIRTY`, `BUILD_TIME` — baked by `build.rs`; build-time inputs `GIT_SHA_OVERRIDE`, `GIT_DIRTY_OVERRIDE`.

## Test-only / dev-only

`TALOS_TEST_DATABASE_URL`, `TALOS_TEST_REDIS_URL`, `TALOS_TEST_NATS_URL`,
`TALOS_TEST_ACTOR_ID`, `TALOS_TEST_COMPILE_CACHE`, `TALOS_TEST_JSPY_SANDBOX`,
`NATS_TEST_URL`, `NATS_TEST_USER`, `NATS_TEST_PASS`,
`GRAPH_RAG_TEST_OLLAMA_URL`, `GRAPH_RAG_TEST_MODEL`,
`GRAPH_RAG_TEST_TIER1_ACTOR`. Lint-gate opt-ins: `TALOS_LINT_CLIPPY`,
`TALOS_LINT_AUDIT`.

Excluded from the count: shell-internal locals in `scripts/*.sh` (loop vars,
computed intermediates) — not application config. Shell/compose pass-throughs
that ARE real config (`DATABASE_URL`, `ADMIN_SECRET_KEY`, `NGROK_AUTHTOKEN`,
`VITE_API_URL`, backup knobs `BACKUP_DIR`/`BACKUP_INTERVAL_HOURS`) correspond
to reads captured above.

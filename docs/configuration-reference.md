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
| ~~`DB_EXECUTION_TIMEOUT_SECS`~~ | n/a | — | **Not a variable (removed 2026-09-11).** It was read and logged in the connect line as `execution_timeout=300s`, but reached no `SET` and no pool — there is no "execution-path pool"; every statement runs under `DB_STATEMENT_TIMEOUT_SECS`. Setting it changed nothing, and now nothing reads it | |
| `REDIS_URL` | none (optional) | both | Redis connection; Redis-backed features disabled when unset | 🔒 |
| `NATS_URL` | none (controller) / effectively required (worker) | both | NATS server URL | |
| `NATS_USER` | none (optional) | both | NATS username. In the chart and both compose files the WORKER receives the worker credential (Secret / `.env` keys `NATS_WORKER_USER`) under this name — the binary does not care what its user is called; the broker binds that user to the worker permission set (`docs/nats-subjects.md` § Broker permissions) | |
| `NATS_PASSWORD` (+`_FILE`) | none (optional) | both | NATS password (the worker's is `NATS_WORKER_PASSWORD` at the deployment layer) | 🔒 |
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
| `TALOS_ALLOW_PLAINTEXT_VAULT` | unset | controller | Escape hatch for the production `https://`-only gate on `VAULT_ADDR` (`tls-prod-gate-vault`, check 44). Every DEK wrap/unwrap carries the plaintext DEK and `X-Vault-Token`, so a plaintext `VAULT_ADDR` in production refuses to boot unless this is set; intended for an in-pod Vault agent sidecar on loopback only. Setting it writes an audit WARN at boot. | 🔒 |

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
| `TALOS_RLS_SET_ROLE` | unset (off) | controller | **Boolean** (`1`/`true`/`yes`/`on`), not a role name: when on, every tenant-scoped transaction runs `SET LOCAL ROLE talos_app` (a fixed `NOLOGIN` role from migration `20260529220000`) so the RFC 0004/0005 RLS policies enforce even on a superuser pool. Read by `talos-db` (controller). In production, `enforce_production_rls_posture` refuses to boot unless RLS is effective or `TALOS_ALLOW_RLS_DISABLED` is set. The chart and compose set it `true`. | 🔒 |
| `TALOS_ALLOW_RLS_DISABLED` | unset (refuse) | both | Explicit opt-in to run with Postgres RLS disabled | 🔒 |
| `TALOS_RPC_REQUIRE_ED25519` | unset | both | Require Ed25519-signed NATS-RPC auth | 🔒 |
| `TALOS_RPC_GUEST_ROLE` | unset (guest SQL runs as the app user) | controller | Postgres role the `database`-world SQL sandbox runs guest statements under (`SET LOCAL ROLE`, `talos-rpc-subscribers`); `talos_guest` ships with **no** table grants, so an operator grants what modules may read. Not about RPC authentication — every NATS-RPC message is HMAC/Ed25519-signed regardless. In production `enforce_production_db_sandbox_posture` refuses to boot without it unless `TALOS_ALLOW_UNSCOPED_DB_SANDBOX` is set. | 🔒 |
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
| `TALOS_WORKER_REGISTRATION_TOKEN` | none (optional) | both | Shared token for worker self-registration — the SAME value on controller (gate) and worker (bearer); unset on either side disables the handshake | 🔒 |
| `TALOS_CONTROLLER_URL` | none (dev compose: `http://controller:8000`) | worker | Controller base URL the worker self-registers against — not a secret. Registration also requires the token above **and** `TALOS_WORKER_SIGNING_KEY`; with all three, the worker reports its build into `get_platform_info.fleet` | |
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
| `WASM_CACHE_RETENTION_DAYS` | `30` | controller | Idle window for the six-hourly WASM cache sweep. A user module not dispatched for this many days (recency = `modules.last_used_at`, stamped throttled on every dispatch read, or its latest `module_executions` row, whichever is newer; `created_at` if neither) has its compiled `wasm_bytes` NULLed and `wasm_evicted_at` stamped — the ROW, `source_code`, execution history and FK children are KEPT, and `hot_update_module` restores it. Exempt whatever their age: shared catalog rows, and any module referenced by a workflow (`workflow_module_refs` or `graph_json`, archived included), a `webhook_triggers.module_id`, or an active gcal watch channel. Gmail/GCP push bindings live in `integration_state` JSON and are NOT visible to the sweep — such a module is protected only while it keeps firing. Until 2026-09-10 this knob was inert (`last_used_at` had no writer) and the sweep DELETED rows. | |
| `WASM_CACHE_MAX_MODULES` | `1000` | controller | Cap on modules holding compiled bytes. Over cap, the sweep evicts BYTES (never rows) coldest-first from the same evictable set as `WASM_CACHE_RETENTION_DAYS` — so it cannot touch a referenced module or one dispatched within the retention window. When the in-use set alone exceeds the cap it evicts nothing and WARNs on `talos_audit` with `unevictable_count_overage`; raise the cap or prune unused modules. Measured against `COUNT(*) WHERE wasm_bytes IS NOT NULL` over ALL rows (catalog included) so an over-cap catalog is reported, not hidden. | |
| `WASM_CACHE_MAX_SIZE_MB` | `500` | controller | Cap on the summed `size_bytes` of modules holding compiled bytes. Same semantics and same exemptions as `WASM_CACHE_MAX_MODULES`; the shortfall is reported as `unevictable_size_overage_bytes`. At 13–18 MB per JS/Python component the default is ~30 such modules, which is why the caps evict bytes and exempt anything referenced or recently run. | |
| `WORKER_MAX_JOB_RESULT_BYTES` | 4 MiB | worker | Max serialized job result size | |
| `WORKER_MAX_OCI_LAYER_BYTES` | 32 MiB | worker | Max OCI layer size pulled when fetching modules | |
| `WORKER_ALLOW_PRIVATE_HOST_TARGETS` | `false` | worker | Allow module egress to private/internal IPs (SSRF gate) | 🔒 |
| `METRICS_PORT` | `9090` | worker | Worker Prometheus port | |
| `TALOS_WORKER_HEARTBEAT_INTERVAL_SECS` | `30` (clamped to 5..45) | worker | Seconds between signed NATS fleet heartbeats. `0` disables publishing entirely — a supported setting, but the controller cannot detect it, so pair it with `SCHEDULER_FLEET_READINESS_BARRIER=false` on the controller or the scheduler's readiness barrier will hold, give up, and report degraded forever. Unparseable values fall back to the default and are logged, never silently disabling the publisher | |
| `TALOS_INLINE_WASM_MAX_BYTES` | built-in default | both | Cap on inline-dispatched WASM bytes | |
| `TALOS_ENCRYPT_EXECUTION_OUTPUT` | flag | both | Encrypt stored execution output | 🔒 |
| `TALOS_SQL_PERMISSIVE_EMPTY_ALLOWLIST` | unset | worker | Permit an empty SQL allowlist in the sandbox | 🔒 |
| `TALOS_WIT_GRAPHQL_BLOCK_INTROSPECTION` | unset | worker | Block GraphQL introspection from guest modules | 🔒 |
| `TALOS_DEFAULT_WIT_WORLD` | `minimal-node` | both | Default WIT capability world | |
| `CIRCUIT_BREAKER_CLEANUP_SECS` | `300` | worker | Circuit-breaker cleanup interval | |
| `CIRCUIT_BREAKER_MAX_AGE_SECS` | `1800` | worker | Max age before breaker state is pruned | |
| `CIRCUIT_BREAKER_SUCCESS_RATE` | built-in default (f64) | worker | Success-rate threshold to close the breaker | |
| `TALOS_WORKER_MAX_JOB_FUEL` | `50000000` (`MAX_JOB_FUEL`) | worker | Ceiling the worker clamps a dispatch's `max_fuel` (and every pipeline step's) to, whatever the signed request asks for. The controller caps at the same constant; this is the worker-side belt (2026-09-10 review — `max_fuel` was the one policy field not bound into the dispatch signature). | 🔒 |
| `TALOS_SSE_IDLE_TIMEOUT_SECS` | `900` | worker | Idle timeout for a guest `http_stream` (SSE) reader task: a stream that delivers nothing for this long is closed with `IdleTimeout`. Reader tasks are also aborted when their job's Store drops, so this is a backstop for a stream nothing ever reads, not the primary bound. `0` disables. | |

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
| `TALOS_LOCAL_LLM_MAX_IN_FLIGHT` | `1` | worker | Simultaneous LOCAL (ollama) `llm::complete*` exchanges permitted PER WORKER PROCESS. The gate QUEUES and never refuses: a call that cannot get a permit within 120 s proceeds ungated, i.e. degrades to the pre-gate behaviour. `0` disables it entirely; an unparseable value falls back to `1`, never to `0`. **Raise it to match a backend that genuinely serves requests in parallel** — Talos cannot see the backend's `OLLAMA_NUM_PARALLEL`, and the default is set for the single-slot Ollama the bundled `docker-compose.yml` provides. The effective fleet ceiling against a shared backend is `WORKER_REPLICAS x this`. | |
| `TALOS_LLM_BOOT_WARMUP` | `true` | controller | Warm the ≤3 most-referenced local (ollama) generation models at boot, after the reachability probe, so the first scheduled run doesn't pay the cold model load. Fail-soft, spawned, never delays boot. Local provider only. | |
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
| `S3_ENDPOINT` | none (optional) | worker | Endpoint for the `talos:core/object-storage` WIT host functions a WASM module calls. Imported only by the `automation-node` world; the host fns answer `NotConfigured` for any other capability world. **Unrelated to the audit ledger** (that reads `AWS_ENDPOINT_URL`/`MINIO_ENDPOINT`) and unrelated to module artifact storage (compiled WASM lives in `modules.wasm_bytes` and the OCI registry). | |
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
| `JAEGER_ENDPOINT` | none — tracing DISABLED | both | OTLP/gRPC trace export endpoint. Highest precedence of the three. | 🔒 (may carry an ingest key; logged redacted) |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | none | both | Standard OTel signal-specific endpoint. Used when `JAEGER_ENDPOINT` is unset/empty. | 🔒 (same) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | none | both | Standard OTel generic endpoint. Lowest precedence of the three. | 🔒 (same) |
| `OTEL_TRACES_SAMPLER` | none (optional) | both | OTel trace sampler selection | |
| `OTEL_TRACES_SAMPLER_ARG` | none (optional) | both | OTel sampler argument | |
| `OTEL_METRICS_ENABLED` | bool default | both | Enable OTel metrics export | |
| `TALOS_SELF_ALERTS` | flag | talos-ops-alerts-repository | Enable self-monitoring ops alerts | |

**Trace export is OFF unless one of the three endpoint variables above holds a
non-empty value.** Resolution is a single chokepoint —
`talos_trace::endpoint_from_env`, shared by the controller and the worker — and
an empty value counts as unset. With none set, both binaries print
`Tracing DISABLED (no endpoint configured; …)` at startup, build no exporter and
attempt no export.

That is worth stating explicitly because until #649 it was false: both binaries
substituted `http://localhost:4317` for the unset case, which inside a container
is the process itself. Neither the dev stack nor the Helm chart sets any of
these variables, so every unconfigured deployment built a span exporter aimed at
itself and logged a `BatchSpanProcessor.ExportError` on every flush while the
trace backend stayed empty. If you see that error, the endpoint you configured is
unreachable *from inside the container* — check that you used the
compose/Kubernetes service name (`http://jaeger:4317`), not `localhost`.

The Helm chart sets none of these and needs no new key for them: pass one via
`controller.env` / `worker.env` in `values.yaml`, which are rendered verbatim
into both deployments.

> **⚠ Do not enable trace export yet — there is an unclosed redaction gap.**
> `worker/src/main.rs:1165` (single-node) and `:1493` (pipeline) stamp the RAW
> WASM guest error string onto the exported job span, as both an `error`
> attribute and the span's error status. `sanitize_error_message` strips file
> paths, line numbers and internal IPs and then truncates — it performs **no
> secret redaction**. The sibling sink at
> `talos-worker-runtime/src/runtime.rs:4071` DLP-redacts the same text, and its
> comment names `sk-*` / `ghp_*` / Bearer tokens as the reason. So a module that
> echoes an upstream 401 writes that provider's token into whatever trace
> backend you point these variables at.
>
> This repo's rule is that plaintext secrets leave the controller host by
> exactly two audited paths (outbound `vault://` headers, and opt-in Tier-2
> `expose_secret`). Span export is not one of them. Setting one of these
> variables today opts you into a third, unaudited one.
>
> **Unblocks when** those two sites route through
> `talos_dlp_provider::redact_str` — ideally pushed down into
> `ExecutionSpan::end_error` so a future caller cannot regress it. The transport
> itself is known-good: it was verified end-to-end (span delivered to Jaeger and
> read back via `/api/traces`) with a scratch probe during #649.

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
| `EXECUTION_RETENTION_DAYS` | `30` | controller | Days an **archived** execution is kept before permanent deletion, clocked on `archived_at` (destructive-zero guarded). **Changed 2026-09-04:** this used to delete rows from the LIVE table; live rows are now MOVED to `workflow_executions_archive` after `ARCHIVE_AFTER_DAYS` and purged from there after this window. Default total lifetime is therefore 30 + 30 = 60 days, not 30.  **2026-09-10:** the TOTAL lifetime (`ARCHIVE_AFTER_DAYS` + this) is also the clock for `llm_usage` (`recorded_at`), `judge_scores` (`created_at`) and orphaned `execution_state` rows — three tables that had a writer and no reaper; they are reaped by the same 6-hourly pass, in 5 000-row batches capped at 20 batches per tier per tick (the log says `truncated=true` when the cap bound, and the backlog continues next tick). | |
| ~~`EXECUTION_MAX_ROWS`~~ | n/a | — | **Not a variable (removed 2026-09-11).** No count-based eviction exists; the accessor had zero callers since it was written. Retention is by AGE only: `ARCHIVE_AFTER_DAYS` (live → archive) then `EXECUTION_RETENTION_DAYS` (archive → deleted) | |
| `ARCHIVE_AFTER_DAYS` | `30` | controller | Days an execution stays in `workflow_executions` before being MOVED to the archive. This is the window that bounds the LIVE table, and the one `execution_events` / `workflow_execution_logs` / `execution_approval_tokens` CASCADE at. Overridden per-cluster by `system_settings.archive_after_days` (`set_archive_policy`). **What an operator sees past this window:** the execution row itself stays fully readable by id — `get_execution_status` / `get_execution_output` / `get_execution_cost` and friends answer from `workflow_executions_archive` and stamp the response `archived: true` with `archived_at`. What is GONE is the per-node detail: `get_execution_logs`, `get_execution_trace`, `get_execution_timeline`, `get_execution_waterfall` and `analyze_execution_failure` all read `execution_events`, which the move CASCADEs away, so they say so rather than rendering an empty node list. Operations that ACT on a live row (`cancel_execution`, `retry_execution`, `replay_execution`, `acknowledge_execution_failure`, `watch_execution`) refuse with "archived" as the stated reason — never "not found or access denied", which was the pre-2026-09-04 behaviour and is false in both clauses. Set this longer if per-node traces matter to you more than live-table size. | |
| `AUDIT_LOG_RETENTION_DAYS` | `90` | controller | Retention for the webhook request log and webhook DLQ (daily at 02:00 UTC). **It does NOT apply to `auth_audit_log` or `secret_audit_log`** — both carry the `prevent_audit_modification` BEFORE DELETE trigger (migration `20260408000001`) and are append-only by security policy; until 2026-09-10 the cleanup tried anyway and logged a `42501` ERROR every night while deleting nothing. It now reads the policy from the catalog and logs `append-only by policy` at INFO. Dropping that trigger is an operator decision; if it is dropped, the batched delete runs under this window. | |
| `TALOS_AUDIT_TABLE_RETENTION_DAYS` | `180` | controller | **Added 2026-09-10.** Age-based reaper for the audit-shaped tables that are NOT immutable and grew forever: `actor_action_log` (`"timestamp"`), `module_update_history` (`created_at`) and **resolved** `ops_alerts` (`resolved_at`; `new`/`acked` alerts are never touched, however old). Runs inside the 6-hourly `ExecutionRetention` pass in 5 000-row batches, 20 batches per table per tick. **Floor 30 days**: any value below 30 is raised to 30 with a WARN, so a typo (`18` for `180`) cannot wipe an audit trail; non-positive or unparseable values fall to the default. `admin_event_log` is deliberately NOT covered — it is append-only by trigger and permanent. The per-user `cleanup_ops_alerts` MCP tool is unchanged and can be stricter. | |
| `GRAPHQL_HEAVY_MUTATION_PER_USER_PER_MIN` | `10` | controller | **Added 2026-09-10.** Per-USER token bucket on the GraphQL mutations whose cost is an LLM call or a synchronous compile/execute: `createWorkflowFromDescription`, `testModule` (up to 120 s of WASM inline), `testWorkflow`. Refusal is a `RATE_LIMITED` error carrying `retryAfterSecs`. In-memory per controller replica, so the fleet ceiling is `replicas × N`; the per-IP limiter still applies underneath. `0`/empty → default (never deny-all). | |
| `GRAPHQL_RHAI_PER_USER_PER_MIN` | `60` | controller | **Added 2026-09-10.** Same bucket shape for the synchronous Rhai evaluators (`analyzeRhai`, `testRhaiExpression`, 100 KB scripts). | |
| `STUCK_EXECUTION_TIMEOUT_MINS` | `30` | controller | Mark executions stuck after N minutes | |
| `EXECUTION_RESUME_STALE_MINS` | `5` | controller | Stale threshold to resume executions | |
| `STALE_EXECUTION_MINUTES` | `60` | controller | Stale-execution sweep threshold | |
| `SCHEDULER_EXECUTION_TIMEOUT_SECS` | `3600` | talos-scheduler | Scheduled-execution timeout | |
| `SCHEDULER_MAX_CONCURRENT_EXECUTIONS` | `16` | talos-scheduler | Ceiling on concurrently-running scheduled executions (steady state). See the boot-herd knobs below — raising this makes a boot burst **worse**, not better | |
| `SCHEDULER_STARTUP_MAX_CONCURRENT` | `4` | talos-scheduler | Tighter ceiling applied only to a **backlog batch**: the schedules found due by the first poll after a controller boot (`phase=startup`), or by a later poll holding a schedule overdue by more than 90 s — six poll intervals — without a boot (`phase=catchup`: host suspend/resume, DB outage; measured 2026-09-10, when a 10-schedule resume herd ran under the 16-wide steady ceiling because the classification keyed on process age alone). Admission control, not delay: the first run starts immediately, the rest queue behind permits. This is the load-bearing protection against the 2026-08-10 boot herd; `TalosSchedulerStartupHerdNotAbsorbed` (selecting both phases) is the signal that tells you whether it was enough. The threshold is the constant `CATCHUP_OVERDUE_SECS`, not a knob | |
| `SCHEDULER_FLEET_READINESS_BARRIER` | `true` | talos-scheduler | Whether the first poll waits for a worker to become visible in the NATS heartbeat view. Set `false` **only** on a deployment whose workers publish no heartbeats (`TALOS_WORKER_HEARTBEAT_INTERVAL_SECS=0`); the controller cannot detect that setting, and with it left on, the barrier can only hold, give up, and report degraded forever | |
| `SCHEDULER_READINESS_TIMEOUT_SECS` | `135` | talos-scheduler | Bound on that one pre-loop wait. Derived from the protocol (3× the largest configurable heartbeat interval, `WORKER_HEARTBEAT_MAX_INTERVAL_SECS` = 45 s), not guessed — a worker that booted before the controller subscribed loses its unretained first heartbeat and is only learned about on the second. Overshooting is nearly free: the wait returns the instant a worker appears | |
| `SCHEDULER_READINESS_MAX_HOLDS` | `20` | talos-scheduler | Consecutive polls the barrier may hold (≈5 min at the 15 s interval) before giving up and dispatching anyway, setting `talos_scheduler_readiness_degraded`. An empty fleet view is ambiguous, not proof of absence, so the barrier degrades rather than wedging. The gauge re-arms by itself once a heartbeat is seen | |
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
| ~~`TALOS_NODE_CACHE`~~ | — | — | **Removed 2026-09-12.** Read only by `talos-node-cache`, a crate nothing constructed ("not yet wired into the engine" since May); the knob controlled nothing. Crate, shim and the empty `node_result_cache` table deleted (migration `20260912110000`). | |
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
| `TALOS_WRITE_CEILING_ENFORCED` | bool default | both | Enforce actor write ceiling. **Set it on BOTH** — the worker gates mutating host calls, the controller gates the `__memory_write__` envelope it persists on node completion (#750); on the worker alone a `readonly` actor is refused one route and permitted the other. The worker reports its value to the controller at self-registration, diagnostic only, outside the registration proof (`get_platform_info.fleet.write_ceiling`). | 🔒 (posture) |
| `TALOS_WRITE_CEILING_STRICT_EGRESS` | bool default | worker | Strict egress under the write ceiling; inert unless the flag above is on. Reported alongside it at self-registration. | 🔒 (posture) |
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
| `SMART_MEMORY_CONTEXT_BYTE_BUDGET` | `12000` | Context byte budget for the injected `__actor_context__` payload. Reachable range: the packer fills from at most 20 candidates (every production caller's limit), each capped at `SMART_MEMORY_CONTEXT_PER_MEMORY_CAP`, so a budget above `20 × cap` (60 000 at defaults) is inert, and on an actor with fewer than 20 memories the ceiling is `memories × cap` | |
| `SMART_MEMORY_CONTEXT_PER_MEMORY_CAP` | `3000` | Per-memory byte cap (values above it are truncated at a char boundary and marked). Clamped to ≤ the byte budget at pack time | |
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
| `ADAPTIVE_RANK_LOOKBACK_DAYS` | `30` | Training lookback window. **Effective DOWNWARD only** — see the note below | |
| `ADAPTIVE_RANK_MAX_ACTORS_PER_TICK` | `50` | Actor fan-out cap per tick | |
| `MEMORY_LOOP_MAX_ACTORS_PER_ORG_PER_TICK` | `0` (disabled) | Shared per-org fan-out cap across memory loops | |

**`ADAPTIVE_RANK_LOOKBACK_DAYS` is bounded by four things, and it is the
weakest of them.** The clamp on the variable itself is `[1, 3650]` days, but the
fit cannot see anything like 3650 days, and raising the knob past the ceilings
below changes nothing about the model — it only widens the population the
truncation disclosure reports as dropped, which reads as the change taking
effect. Measured on the reference deployment 2026-09-09 with the knob at its
default 30: the fit saw **6.56 days**, and every value from 7 to 3650 produced a
bit-identical model.

| ceiling | value | effective window at ~2 900 provenance rows/day |
| --- | --- | --- |
| per-actor training row cap (`TRAINING_FETCH_CAP`, hardcoded) | 20 000 rows | **~6.6 days** |
| the fetch's own hard clamp (`RANK_TRAINING_EXAMPLE_MAX`, hardcoded) | 50 000 rows | ~17 days |
| execution **archival** (`ARCHIVE_AFTER_DAYS`) | 30 days | **~30 days** |
| provenance retention (`MEMORY_RANK_PROVENANCE_RETENTION_DAYS`) | 90 days | 90 days |

The third is the one to understand before changing the first two: past
`ARCHIVE_AFTER_DAYS` a provenance row's execution has moved to
`workflow_executions_archive`, which the training fetch does not read, so the
row arrives with no status and no judge verdict and is dropped as UNLABELED.
Measured: rows-with-a-live-execution saturates at 72 712 from 30 days onward
while the raw row count keeps climbing to 110 812 at 60 days. **So lifting the
row cap alone would not extend the training window past ~30 days.**

Where to SEE the effective window rather than infer it:
`get_operator_digest`'s learned panel (`configured_lookback_days`,
`effective_lookback_days`, `lookback_knob_inert`, `window_note`), the
`rank_training_truncated` WARN, the stored model's `fetch` object, and the
`talos_rank_training_*` Prometheus series.

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
| `AWS_S3_FORCE_PATH_STYLE` | `false` | Path-style addressing; required `true` for MinIO. Read by BOTH the writer and the verifier. | |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | `us-east-1` (verifier only) | Region. **Asymmetric on purpose-by-accident, so state it:** the VERIFIER resolves these itself and falls back to `us-east-1`; the WRITER takes whatever `aws_config::load_defaults` resolves from its own chain (env, profile, IMDS). A deployment that sets neither can therefore have a writer that fails on region while the verifier quietly assumes one. | |
| (standard `AWS_*` credential vars) | SDK defaults | The WRITE path only. Read implicitly by the AWS SDK (`load_defaults`) in `build_audit_s3_client`. On this platform these are the `audit_write_only` identity: `s3:PutObject` and nothing else, so they CANNOT read the chain back — that is the design, not a gap. | 🔒 |
| `AUDIT_VERIFIER_ACCESS_KEY_ID` | none | The READ path. Access key id of the read-only audit-chain verifier identity (`audit_read_only`: `s3:ListBucket` + `s3:GetObject`). Empty is treated as unset. The chain it reads is keyed PER JOB — every object key is `<module_executions.id>/…` — so the sweep enumerates `module_executions` and rolls its per-job outcomes up to workflow executions. | 🔒 |
| `AUDIT_VERIFIER_SECRET_ACCESS_KEY` | none | Secret key for the above. **Both halves required**; one without the other reads as unset. With them absent the chain-verification sweep does not start, logs one `audit_chain_verifier_identity_missing` ERROR, increments `talos_audit_chain_unverifiable_total{reason="no_credentials"}`, and `security_audit`'s `audit_chain_verification` check reports the control as non-functional. There is deliberately **no `AWS_*` fallback** — that identity is write-only and every listing under it returns AccessDenied. | 🔒 |
| `AUDIT_CHAIN_SWEEP_INTERVAL_SECS` | `3600` | Chain-verification sweep interval, clamped [300, 86400]. `0` disables the sweep entirely — a flat `talos_audit_chain_unverifiable_total` then means "never looked", not "verified clean". Each pass covers a window of 2× this value and caps at 2000 job chains; the cap is disclosed as `audit_chain_sweep_incomplete` rather than folded into a clean count. | |

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

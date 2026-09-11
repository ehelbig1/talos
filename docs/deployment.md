# Production Deployment Guide

This document is the **service-level reference** — every env var the
controller and worker accept, KEK rotation procedures, Prometheus
scrape config, etc. It assumes you've already chosen a deploy model.

## Choosing a deploy model

| Model | Doc | When |
|---|---|---|
| **k3s + Helm on a single VM** (Phase 1) | `deploy/k3s/README.md` | Production single-tenant deploys (~$50–80/month on Hetzner CPX31). End-to-end runbook including OCI template registry switch-over and Sigstore enforcement. |
| **Managed Kubernetes** (Phase 2) | `deploy/k3s/README.md` § *Phase 2 migration* | Multi-instance / managed-cloud. The Helm chart is the same; only values change. |
| **Docker Compose** | This doc | Local dev, CI fixtures, and small single-host trials. Not the recommended production target — k3s+Helm is. |

Whichever model you pick, the env-var table below is canonical for
controller / worker configuration.

## Architecture Overview

Talos consists of the following services:

| Service | Port | Description |
|---------|------|-------------|
| **Controller** | 8000 | GraphQL API, webhook router, workflow engine |
| **Worker** | 8001 | WASM execution runtime, receives jobs via NATS |
| **PostgreSQL** | 5432 | Primary data store |
| **Redis** | 6379 | Caching (WASM modules, DEK cache, session revocation) |
| **NATS** | 4222 | Message queue (job dispatch, audit events, logs) |
| **MinIO** | 9000 | S3-compatible object storage for audit ledger |

## Docker Compose Deployment

### Development

```bash
docker compose up -d
```

### Production

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

The production overlay:
- Removes dev port mappings for internal services
- Requires explicit credentials (no defaults)
- Sets `RUST_ENV=production` on controller and worker
- Enables HSTS and strict rate limiting
- Drops all Linux capabilities and sets read-only root filesystem

## Required Environment Variables

> **`docs/configuration-reference.md` is the authoritative variable list** —
> every variable, its default, which PROCESS reads it, and whether it is
> sensitive. The tables below are the deploy-time subset and must agree with
> it; where they disagree, that file wins. (They had drifted: until
> 2026-09-07 the "Optional Configuration" table and the "S3 / MinIO"
> section below both described the four `S3_*` variables as the audit
> ledger's, which they have never been.)


### Controller

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgres://user:pass@postgres:5432/talos` |
| `JWT_SECRET` | JWT signing key (min 32 chars, not default) | `<random-64-char-hex>` |
| `KEK_PROVIDER` | `env` (dev, uses `TALOS_MASTER_KEY`) or `vault` (prod, uses Vault transit) | `vault` |
| `TALOS_MASTER_KEY` | (dev-only) Envelope-encryption KEK, 32-byte hex. Used when `KEK_PROVIDER=env`. Production deployments MUST use `vault` and leave this unset so the key never lives in process memory. | `<random-64-char-hex>` |
| `VAULT_ADDR` | Vault API endpoint. Required when `KEK_PROVIDER=vault`. | `https://vault.internal:8200` |
| `VAULT_TOKEN` | Vault token with `transit/encrypt` + `transit/decrypt` caps on `talos-kek` only. Issue via a transit-only policy; do not reuse a root token. | `hvs.xxx...` |
| `VAULT_TRANSIT_MOUNT` | Transit engine mount path. Default `transit`. | `transit` |
| `VAULT_TRANSIT_KEY_NAME` | Key name under the transit mount. Default `talos-kek`. | `talos-kek` |
| `OAUTH_STATE_SECRET` | Secret for signing OAuth state tokens | `<random-32-char>` |
| `REDIS_URL` | Redis connection URL | `redis://redis:6379` |
| `NATS_URL` | NATS server URL | `nats://nats:4222` |
| `ALLOWED_ORIGIN` | Comma-separated allowed CORS origins | `https://app.example.com` |
| `FRONTEND_URL` | Frontend URL for OAuth redirects | `https://app.example.com` |
| `BASE_URL` | Controller's public URL | `https://api.example.com` |
| `RUST_ENV` | Must be `production` for security features | `production` |

### Worker

| Variable | Description | Example |
|----------|-------------|---------|
| `NATS_URL` | NATS server URL | `nats://nats:4222` |
| `WORKER_SHARED_KEY` | Pre-shared key for HMAC job signing | `<same-as-controller>` |
| `REDIS_URL` | Redis for WASM state interface | `redis://redis:6379` |

### Optional Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `BCRYPT_COST` | `12` | Password hashing cost (10-14) |
| `API_RATE_LIMIT` | `100` | API requests/min per IP |
| `WEBHOOK_RATE_LIMIT` | `60` | Webhook requests/min per IP |
| `GLOBAL_RATE_LIMIT` | `1000` | Total requests/min globally |
| `ARCHIVE_AFTER_DAYS` | `30` | Days an execution stays live before being moved to `workflow_executions_archive` |
| `EXECUTION_RETENTION_DAYS` | `30` | Days an **archived** execution is kept before permanent deletion (total lifetime = the two windows summed) |
| ~~`EXECUTION_MAX_ROWS`~~ | n/a | **Not a variable.** No count-based eviction exists and nothing read this name (removed 2026-09-11); execution lifetime is the two AGE windows above |
| `AUDIT_LOG_RETENTION_DAYS` | `90` | Days to keep audit logs |
| `AUDIT_CHAIN_SWEEP_INTERVAL_SECS` | `3600` | Cadence of the continuous WORM audit-chain verification sweep (clamped [300, 86400]; `0` disables). No-op without a WORM S3/MinIO endpoint; verification also needs `TALOS_AUDIT_SIGNING_KEY`. Each pass verifies up to 2000 JOB chains (`module_executions`) whose `completed_at` falls in the last 2× the interval, and logs `audit_chain_verification_failed` on any break. Lower the interval if your completion rate puts more than 2000 module executions in one window — the sweep keeps no cursor, so rows past the cap age out unverified and say so via `audit_chain_sweep_incomplete`. |
| `WASM_CACHE_RETENTION_DAYS` | `30` | Idle window after which an UNREFERENCED user module's compiled bytes are evicted (`wasm_bytes` set NULL; the row, its source and its execution history are kept). Modules named by a workflow graph, a webhook trigger or a calendar watch channel, or dispatched inside the window, are exempt. Live since 2026-09-10 — before that nothing wrote `last_used_at`, so the knob was inert. |
| `WASM_CACHE_MAX_MODULES` | `1000` | Count cap for compiled user modules; over the cap, bytes are evicted from the same exempt-aware candidate set (never rows). An over-cap set that is entirely in use WARNs and evicts nothing. |
| `WASM_CACHE_MAX_SIZE_MB` | `500` | Byte cap for compiled user modules; same eviction semantics as the count cap. |
| `STUCK_EXECUTION_TIMEOUT_MINS` | `30` | Minutes before marking stuck executions |
| `EXECUTION_CHECKPOINTING_ENABLED` | `false` | Persist per-node checkpoints so an interrupted run resumes from the last node instead of restarting (see RFC 0003). Requires `WORKER_SHARED_KEY`. |
| `CHECKPOINT_EVERY_N_NODES` | `1` | Checkpoint cadence when enabled — save every Nth node completion. Raise on large graphs to cut re-encryption cost (resume then re-runs up to N trailing nodes). |
| ~~`GRAPHQL_MAX_DEPTH`~~ | n/a | **Not a variable.** The depth limit is hardcoded `limit_depth(15)` in `controller/src/bootstrap/services.rs`; nothing reads this name. The `10` documented here until 2026-09-07 was not even the live value. Setting it changes nothing |
| ~~`GRAPHQL_MAX_COMPLEXITY`~~ | n/a | **Not a variable.** Hardcoded `limit_complexity(5000)` in the same builder. The number was right; the knob never existed |
| `TRUSTED_IPS` | (none) | IPs that bypass rate limiting |
| `TRUSTED_PROXY_CIDRS` | (none) | Reverse proxy CIDRs for X-Forwarded-For |
| `COMPILE_DIR` | `/tmp/talos-compilations` | Directory for WASM compilation artifacts |
| `NATS_USER` / `NATS_PASSWORD` | (none) | NATS authentication credentials — the CONTROLLER pair (unrestricted) |
| `NATS_WORKER_USER` / `NATS_WORKER_PASSWORD` | (none) | Deployment-layer keys (bootstrap Secret / compose `.env`) for the WORKER's NATS credential, handed to the worker as its `NATS_USER`/`NATS_PASSWORD`. The broker binds this user to the worker permission set generated from `talos_workflow_job_protocol::nats_permissions` (subscribe allow-list, publish deny-list — `docs/nats-subjects.md`). `install.sh` mints and back-fills both; `make up` back-fills `.env`; External-Secrets operators must add them BEFORE upgrading (the NATS StatefulSet mounts them as required keys) |
| `ANTHROPIC_API_KEY` | (none) | Enable LLM features (Anthropic Claude) |
| `OPENAI_API_KEY` | (none) | Enable LLM features (OpenAI GPT) |
| `GEMINI_API_KEY` | (none) | Enable LLM features (Google Gemini) |
| `S3_ENDPOINT` | (none) | **Worker only.** Endpoint for the `talos:core/object-storage` WIT host functions, which only `automation-node` modules may import. Nothing to do with the audit ledger — see "S3 / MinIO" below |
| `S3_ACCESS_KEY_ID` | (none) | Access key for the same module-facing object store |
| `S3_SECRET_ACCESS_KEY` | (none) | Secret key for the same |
| `S3_REGION` | `us-east-1` | Region for the same |
| `EMAIL_API_URL` | (none) | SendGrid-compatible email API endpoint |
| `EMAIL_API_KEY` | (none) | Email service API key |
| `EMAIL_FROM` | (none) | Default sender email address |

## Database Migrations

Migrations are managed with `sqlx`. Run before starting the controller:

```bash
cd controller
sqlx migrate run --database-url "$DATABASE_URL"
```

Key migration files are located in `/migrations/`.

## Health Monitoring

### Unified Health Check

```
GET /health
```

Returns JSON with subsystem status:

```json
{
    "status": "ok",
    "version": "0.1.0",
    "checks": {
        "database": "ok",
        "redis": "ok",
        "nats": "ok"
    }
}
```

- Returns **200** when database is reachable (even if Redis/NATS are down -- status will be "degraded")
- Returns **503** when database is unreachable
- Each sub-check has a 2-second timeout

### Individual Checks

```
GET /health/redis
GET /health/nats
```

The `/health` endpoint is unauthenticated and suitable for load balancer health probes. It returns aggregate status across Postgres, Redis, and NATS. A response of `"status": "ok"` indicates all subsystems are reachable. A response of `"status": "degraded"` means the database is reachable but one or more ancillary services (Redis, NATS) are down. A `503` response means the database is unreachable.

## Graceful Degradation

When infrastructure services are unavailable:

| Service Down | Impact |
|-------------|--------|
| **Redis** | WASM cache disabled, session revocation delayed, DEK cache falls back to in-memory |
| **NATS** | Webhooks return 503, workflow execution disabled, audit streaming disabled, cron scheduler disabled |
| **Both** | Core API (GraphQL queries, auth) still operational; write operations degraded |

The controller starts successfully even without Redis or NATS. Features requiring those services return appropriate error messages.

## Security Checklist

Before deploying to production:

- [ ] `RUST_ENV=production` is set
- [ ] `JWT_SECRET` is a strong random value (min 32 chars)
- [ ] `TALOS_MASTER_KEY` is a strong random hex value
- [ ] `OAUTH_STATE_SECRET` is set independently
- [ ] `ALLOWED_ORIGIN` is set to exact frontend origin(s)
- [ ] `DANGER_DISABLE_*` flags are NOT set
- [ ] `ALLOW_DEV_UNSAFE_CSRF_BYPASS` is NOT set
- [ ] NATS authentication is enabled (`NATS_USER`/`NATS_PASSWORD`)
- [ ] The worker uses its OWN NATS credential (`NATS_WORKER_USER`/`NATS_WORKER_PASSWORD`), not the controller's — check the worker pod's env resolves to the worker Secret keys
- [ ] `WORKER_SHARED_KEY` is set on both controller and worker
- [ ] PostgreSQL uses strong credentials (not defaults)
- [ ] Redis requires authentication in production
- [ ] MinIO uses non-default credentials
- [ ] TLS is terminated at the reverse proxy
- [ ] `TRUSTED_PROXY_CIDRS` is set to proxy CIDRs only

## Background Tasks

The controller runs the following background tasks:

| Task | Interval | Description |
|------|----------|-------------|
| Session cleanup | 1 hour | Remove expired auth sessions |
| API key cleanup | 1 hour | Deactivate expired API keys |
| Rate limiter cleanup | 10 min | Evict stale IP buckets |
| Execution cleanup | 1 hour | Delete old executions, enforce row limits |
| Audit log cleanup | Daily 2AM | Prune old audit entries |
| WASM cache cleanup | 6 hours | Evict unused modules, enforce size limits |
| Webhook rate limiter cleanup | 5 min | Evict stale webhook token buckets |
| Stuck execution cleanup | 5 min | Timeout orphaned executions |
| DEK cache cleanup | 10 min | Evict expired encryption key cache |
| Cron scheduler | 15 sec | Check and trigger scheduled workflows |
| OCI registry sync | Configurable | Sync module templates from OCI registry |
| Google Calendar renewal | 1 hour | Renew push notification channels |

## Graceful Shutdown

The worker handles `SIGTERM` gracefully:

1. Stops accepting new jobs from NATS.
2. Drains all in-flight job executions (up to 30-second timeout).
3. Sends final heartbeat indicating shutdown.
4. Exits cleanly.

During the drain period, running WASM modules are allowed to complete. If a job exceeds the 30-second drain timeout, it is marked as failed and can be retried via the dead letter queue.

## Encryption Key Rotation

Talos uses envelope encryption: a **KEK** wraps per-row Data Encryption
Keys (DEKs), which in turn encrypt each secret / OAuth token / actor
memory / execution payload. The KEK backend is pluggable via the
`KekProvider` trait (see `controller/src/secrets/kek_provider.rs`).

### KEK backends

**Production (`KEK_PROVIDER=vault`)** — HashiCorp Vault transit engine
holds the KEK. The controller calls `transit/encrypt` +
`transit/decrypt` over HTTPS; the master key never enters the
controller process memory. Rotation uses Vault's own API and does NOT
require re-wrapping DEKs client-side — Vault keeps the prior key
version active for decryption:

```bash
# Rotate the transit key (adds a new version; old ciphertexts still decrypt)
vault write -f transit/keys/talos-kek/rotate

# Optional: retire older key versions (irreversibly decommissions them)
vault write transit/keys/talos-kek/config min_decryption_version=N
```

See operational-runbook §2.1.1 for the full Vault transit procedure +
unseal-key custody guidance.

**Development (`KEK_PROVIDER=env`)** — `TALOS_MASTER_KEY` env var holds
a 32-byte hex key. The legacy `rotateEncryptionKey` GraphQL mutation
(admin only) re-wraps every DEK with a new env-supplied key:

```graphql
mutation {
    rotateEncryptionKey
}
```

This path is appropriate for single-host dev deployments. Production
should migrate to Vault using the Phase 3 dual-wrap procedure
documented in `docs/security/kek-to-kms-plan.md` (kept as historical
reference; the migration itself shipped 2026-04-24).

### Rotating Data Encryption Keys

Use the `rotateDek` mutation to generate a new DEK, followed by
`reEncryptSecrets` to re-encrypt all secrets with the new DEK. These
can also be run as a scheduled job via cron. The DEK rotation path is
backend-agnostic — works identically with `env` and `vault` providers.

## Prometheus Metrics

The worker exposes Prometheus-compatible metrics on `METRICS_PORT` (default
`9090`) at `/metrics`. Access requires a bearer token listed in
`METRICS_AUTH_TOKENS` (comma-separated). The worker also needs
`OTEL_METRICS_ENABLED=true` — it defaults to FALSE and the runtime skips
building the metrics subsystem entirely when unset, so `/metrics` answers with
an essentially empty body and every `wasm_*` alert is blind.

Every table below was WRONG until 2026-08-02: it named five `talos_*`-prefixed
series (`talos_job_duration_seconds`, `talos_jobs_total`,
`talos_wasm_cache_{hits,misses}_total`, `talos_active_jobs`) that no producer
in this workspace has ever registered, and the wrong env var
(`METRICS_BEARER_TOKEN`). The worker's series are `wasm_*`, exported through
OpenTelemetry — the exporter replaces `.` with `_` and appends `_total` to
every counter, so do NOT put `total` in an instrument name. The authoritative
list is the assertion set in `exported_prometheus_names_are_stable_and_idle_
seeds_at_zero` (`talos-worker-runtime/src/metrics_tests.rs`); structural lint
check 65(c) fails the build if an alert names a series no instrument exports.

| Metric | Type | Description |
|--------|------|-------------|
| `wasm_executions_total{status}` | Counter | Executions COMPLETED, by terminal status. Seeded at 0 for `success`/`error`/`retry_exhausted` at startup |
| `wasm_executions_started_total` | Counter | Executions STARTED (incremented at dispatch); deliberately not seeded |
| `wasm_execution_duration_ms_{bucket,sum,count}` | Histogram | Execution duration |
| `wasm_errors_total{type}` | Counter | Errors by normalized type |
| `wasm_retries_total{reason}` | Counter | Retry attempts by reason |
| `wasm_cache_hits_total` / `wasm_cache_misses_total` | Counter | Module compilation cache; both seeded at 0 |
| `wasm_cache_hit_ratio` | Gauge | Cache hit ratio, 0.0–1.0 |
| `wasm_instances_active` | Gauge (UpDownCounter) | Currently active instances, process-local |

The **controller** exposes metrics on its main port at `/metrics/prometheus`
(bearer `PROMETHEUS_SCRAPE_TOKEN`). Beyond the crypto-invariant gauges, it
samples its Postgres connection pool every 15s:

| Metric | Type | Description |
|--------|------|-------------|
| `talos_db_pool_connections` | Gauge | Total pooled connections (idle + in-use) |
| `talos_db_pool_idle_connections` | Gauge | Idle connections available to hand out |
| `talos_db_pool_in_use_connections` | Gauge | Connections currently checked out |
| `talos_db_pool_max_connections` | Gauge | Configured pool ceiling (`DB_MAX_CONNECTIONS`) |

Alert on saturation with `in_use / max > 0.9` (shipped as `TalosDBPoolSaturated`
in `deploy/observability/alerts.yaml`).

Example Prometheus scrape configuration:

```yaml
scrape_configs:
  - job_name: 'talos-worker'
    bearer_token: '<METRICS_BEARER_TOKEN>'
    static_configs:
      - targets: ['worker:9090']
```

## S3 / MinIO Configuration

**`docs/configuration-reference.md` is the authoritative variable list.** The
tables here name the same variables and must agree with it; when they do not,
that file wins. What this section adds is *which subsystem each set belongs
to*, because there are TWO unrelated object-storage users in this platform and
they read DIFFERENT variables.

Corrected 2026-09-07. This section previously said "Talos uses S3-compatible
object storage for the audit ledger and module artifact storage" and then
listed `S3_ENDPOINT` / `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` /
`S3_REGION`. Both halves of that sentence were wrong, and the failure was
silent: an operator on AWS who set exactly those four got no error and a
**dark audit ledger**, because the ledger does not read any of them.

### (a) The WORM audit ledger — controller only

Written by `talos-audit-ledger` in the CONTROLLER process. The WORKER
publishes audit events to the NATS subject `talos.audit.ledger` and never
touches the object store; it carries no S3 identity for it.

| Variable | Default | Purpose |
|---|---|---|
| `AWS_ENDPOINT_URL` | (none) | Endpoint. `MINIO_ENDPOINT` is the fallback spelling; empty is treated as unset. **If neither is set there is no ledger store at all** and both the writer and the verifier report `NoEndpoint` |
| `MINIO_ENDPOINT` | (none) | Fallback for the above |
| `MINIO_BUCKET` | `audit-logs` | Bucket name |
| `AWS_S3_FORCE_PATH_STYLE` | `false` | Required `true` for MinIO |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | SDK chain | The **writer**, read implicitly by `aws_config::load_defaults`. On this platform they are the `audit_write_only` identity (`s3:PutObject` and nothing else) |
| `AUDIT_VERIFIER_ACCESS_KEY_ID` / `AUDIT_VERIFIER_SECRET_ACCESS_KEY` | (none) | The **verifier**, resolved EXPLICITLY with no `load_defaults` on the path. Both halves required |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | `us-east-1` (verifier) | Region. Note the asymmetry: the verifier resolves these itself and falls back to `us-east-1`; the writer takes whatever the SDK's own chain resolves, so a deployment that sets neither can have a writer that errors on region and a verifier that quietly assumes one |
| `TALOS_AUDIT_S3_OBJECT_LOCK` / `TALOS_AUDIT_S3_RETENTION_DAYS` | (none) | Object-Lock posture on written objects |
| `AUDIT_CHAIN_SWEEP_INTERVAL_SECS` | `3600` | Chain-verification sweep cadence; `0` disables it |

The two identities are the subject of the next subsection and must not be
merged.

### (b) The module-facing object store — worker only

`S3_ENDPOINT` / `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` / `S3_REGION` are
read by `talos-worker-runtime` (`context.rs`) and feed the
`talos:core/object-storage` WIT host functions — `put` / `get` / `delete` /
`list_objects` called BY A WASM MODULE. That interface is imported only by the
`automation-node` world, and the host functions refuse
(`Error::NotConfigured`) for any module whose resolved capability world is not
`Trusted`, so leaving all four unset is the correct posture unless you are
deliberately handing Trusted modules a bucket. They are unset in
`docker-compose.yml` and in the Helm chart.

**Module artifacts do not live in S3 at all.** Compiled WASM is stored in
Postgres (`modules.wasm_bytes`) and distributed through the OCI template
registry (`TALOS_REGISTRY_URL`). Nothing in this workspace writes a module
artifact to an object store.

### (c) `talos-offhost-backup`

A separate binary with its own `AWS_*` credentials and its own target bucket
(see `docs/backup-restore.md`). It is not configured by either set above.

For local development, the default Docker Compose setup includes a MinIO
instance and provisions (a)'s two identities via the `minio-init` container.
For production, use AWS S3 or a self-hosted MinIO cluster with TLS and
non-default credentials.

### The audit bucket has TWO identities, deliberately

The WORM audit ledger is written by one principal and verified by a different
one, and they must not be merged:

| Identity | Compose / Secret keys | Controller env | Policy |
|---|---|---|---|
| **Writer** | `MINIO_CONTROLLER_USER` / `MINIO_CONTROLLER_PASSWORD` | `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | `audit_write_only` — `s3:PutObject` on `audit-logs/*` and nothing else |
| **Verifier** | `MINIO_VERIFIER_USER` / `MINIO_VERIFIER_PASSWORD` | `AUDIT_VERIFIER_ACCESS_KEY_ID` / `AUDIT_VERIFIER_SECRET_ACCESS_KEY` | `audit_read_only` — `s3:ListBucket` on the bucket + `s3:GetObject` on its objects; **no Put, no Delete** |

A writer that can also list and get is a writer that can survey and target what
it wrote; a verifier that can write is not evidence of anything. **Do not widen
the writer's policy to make verification work** — the fix is the separate
read-only identity.

Both users and both policies are provisioned by the `minio-init` container in
`docker-compose.yml` and by the `minio-provisioning` Job in the Helm chart
(`minio.provisioning.enabled`, default true), which mirror each other and are
idempotent.

**If the verifier is not configured**, the ledger is still written and nothing
verifies it. The controller says so rather than staying quiet: the sweep refuses
to start with one `audit_chain_verifier_identity_missing` ERROR, the
`talos_audit_chain_unverifiable_total{reason="no_credentials"}` counter moves,
`TalosAuditChainUnverifiable` fires, and `security_audit`'s
`audit_chain_verification` check renders `fail`. That instrumentation exists
because the opposite state — a verifier silently running as the writer, every
listing denied, and no surface able to report it — was live on the dev stack
from 2026-07-08 to 2026-09-06.

### What gets verified: one chain PER JOB

The ledger has no chain at the grain of a workflow execution. A chain is
created per MODULE DISPATCH: the worker builds
`ExecutionLedger::new(workflow_execution_id, job_id)`, `job_id` IS
`module_executions.id`, and every object key is
`<module_executions.id>/<min>_<max>_<nanos>.jsonl`. The genesis hash binds BOTH
halves, so a verifier that names the wrong `workflow_id` reports a break on a
healthy chain rather than quietly getting a near-miss.

So a run with four module dispatches has FOUR chains. The hourly sweep verifies
each and rolls the outcomes up to the workflow execution, **worst outcome
wins** — one broken chain among four makes that run's audit trail broken, not
three-quarters clean — and its summary line carries both grains
(`jobs_scanned` / `jobs_verified_ok` / … beside `workflow_executions_covered` /
`workflow_executions_verified_ok` / …). The admin `verifyAuditChain` GraphQL
query takes the workflow-execution id you already have, resolves it to its jobs,
and returns per-job reports under an aggregate.

**An empty prefix is not a verified chain**, and this is the trap worth
knowing: `verify_chain` over zero events answers `ok == true` (there are no
gaps, no broken links and no bad signatures in nothing). It is reported under
its own reason (`talos_audit_chain_unverifiable_total{reason="empty_chain"}`),
never as `verified_ok`, and it never stamps the "last verified ok" gauge. If it
is the whole population, suspect the audit-ledger subscriber rather than the
verifier — the identity demonstrably works or the reason would be
`access_denied`.

## Email Configuration

Talos sends emails via a SendGrid-compatible HTTP API. Configure via environment variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `EMAIL_API_URL` | Email service API endpoint | `https://api.sendgrid.com/v3/mail/send` |
| `EMAIL_API_KEY` | API key for the email service | `SG.xxxxxxxx` |
| `EMAIL_FROM` | Default sender email address | `noreply@example.com` |

When not configured, the `email` WIT interface returns an `unauthorized` error. Modules using the `email` interface should handle this gracefully.

## Scaling

- **Controller**: Stateless (background sweeps coordinate through Postgres — e.g. the scheduler uses `FOR UPDATE SKIP LOCKED` so N replicas don't double-fire). Can run multiple instances behind a load balancer. Use sticky sessions for WebSocket connections. **Connection-pool note:** each controller replica holds its own `DB_MAX_CONNECTIONS`-sized pool; the *sum* across replicas must stay below the backend's server-side connection ceiling. The `talos_db_pool_*` gauges (see Prometheus Metrics) and the `TalosDBPoolSaturated` alert exist to catch this.
- **Worker**: Stateless. Scale horizontally — NATS queue-group load balancing distributes jobs across the fleet. Each worker registers with the controller via NATS heartbeats. CPU-based HPA is wired by default; queue-depth-based KEDA autoscaling lands with the JetStream durable consumer (see High Availability below).
- **PostgreSQL**: Single primary. Use connection pooling (sqlx pool size configurable).
- **Redis**: Single instance sufficient for most deployments. Used for caching, not primary storage.
- **NATS**: Can be clustered for HA. Used for job dispatch and event streaming.

## High Availability & Single Points of Failure

**Recommended production topology: external-managed datastores.** The Helm
chart's in-cluster datastore mode (`postgres.enabled: true`, in-cluster
Neo4j/Vault/MinIO) is single-replica and intended for homelab / single-region
/ evaluation use. For production, point Talos at managed services and leave the
in-cluster StatefulSets disabled (the default for Postgres):

| Component | In-cluster default | Production recommendation |
|-----------|--------------------|---------------------------|
| **PostgreSQL** | Single StatefulSet replica, daily `pg_dump`, no PITR | Managed Postgres with replication + PITR (Neon, RDS, Cloud SQL). Set `DATABASE_URL`; keep `postgres.enabled: false`. |
| **Redis** | External only (no in-cluster option) | Managed Redis with Multi-AZ failover (ElastiCache, Upstash). |
| **Neo4j** | Single StatefulSet replica | Managed Neo4j (AuraDB) or a causal cluster. Graph-RAG degrades (semantic recall still works) if Neo4j is down; the platform stays up. |
| **Vault** | Single StatefulSet replica | Vault in HA mode (3-replica Raft) or a managed KMS for the transit/KEK backend. A sealed/down Vault blocks DEK unwrap → controller CrashLoops. Back up `bootstrap.json` (unseal material) off-cluster. |
| **MinIO** | Single StatefulSet replica | Managed S3 or distributed MinIO (4+ nodes). Holds the WORM audit sink. |
| **NATS** | 3-replica StatefulSet, `minAvailable: 2` PDB | Already HA. Keep ≥3 replicas; set JetStream stream replication ≥2 for the audit-event ledger. (Job dispatch is core-NATS request/reply with controller-side retry — see RFC 0003 — so it doesn't rely on JetStream durability.) |

**Availability alerts.** `deploy/observability/alerts.yaml` ships
`TalosSingleReplicaInfraDown` (any in-cluster stateful SPOF at 0 ready
replicas), `TalosNatsBelowQuorum`, `TalosPodCrashLooping`,
`TalosControllerDown`/`TalosWorkerDown`, and the pool-saturation alerts. Deploy
them with the chart via `monitoring.prometheusRule.enabled: true` (requires
kube-prometheus-stack), or apply the file directly.

**Worker queue-depth autoscaling.** CPU-based HPA lags the real backlog (CPU
only spikes once a job is *running*, but the fuel budget of an in-flight job
means CPU underreports a deep queue). True queue-depth autoscaling via KEDA's
NATS JetStream scaler depends on the JetStream durable consumer (at-least-once
job delivery); see the engine durability work. Until then, size
`worker.autoscaling.maxReplicas` for peak concurrency rather than relying on
CPU to track backlog.

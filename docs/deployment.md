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
| `EXECUTION_RETENTION_DAYS` | `30` | Days to keep workflow executions |
| `EXECUTION_MAX_ROWS` | `100000` | Max execution rows before eviction |
| `AUDIT_LOG_RETENTION_DAYS` | `90` | Days to keep audit logs |
| `WASM_CACHE_RETENTION_DAYS` | `30` | Days to keep unused WASM modules |
| `WASM_CACHE_MAX_MODULES` | `1000` | Max cached WASM modules |
| `WASM_CACHE_MAX_SIZE_MB` | `500` | Max WASM cache size in MB |
| `STUCK_EXECUTION_TIMEOUT_MINS` | `30` | Minutes before marking stuck executions |
| `GRAPHQL_MAX_DEPTH` | `10` | Max GraphQL query nesting depth |
| `GRAPHQL_MAX_COMPLEXITY` | `5000` | Max GraphQL query complexity score |
| `TRUSTED_IPS` | (none) | IPs that bypass rate limiting |
| `TRUSTED_PROXY_CIDRS` | (none) | Reverse proxy CIDRs for X-Forwarded-For |
| `COMPILE_DIR` | `/tmp/talos-compilations` | Directory for WASM compilation artifacts |
| `NATS_USER` / `NATS_PASSWORD` | (none) | NATS authentication credentials |
| `ANTHROPIC_API_KEY` | (none) | Enable LLM features (Anthropic Claude) |
| `OPENAI_API_KEY` | (none) | Enable LLM features (OpenAI GPT) |
| `GEMINI_API_KEY` | (none) | Enable LLM features (Google Gemini) |
| `S3_ENDPOINT` | (none) | S3-compatible storage endpoint URL |
| `S3_ACCESS_KEY_ID` | (none) | S3 access key ID |
| `S3_SECRET_ACCESS_KEY` | (none) | S3 secret access key |
| `S3_REGION` | `us-east-1` | S3 region |
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

The worker exposes Prometheus-compatible metrics on port `9090` at the `/metrics` endpoint. Access requires a bearer token set via the `METRICS_BEARER_TOKEN` environment variable.

Available metrics include:

| Metric | Type | Description |
|--------|------|-------------|
| `talos_job_duration_seconds` | Histogram | WASM job execution duration |
| `talos_jobs_total` | Counter | Total jobs processed (by status) |
| `talos_wasm_cache_hits_total` | Counter | WASM module cache hits |
| `talos_wasm_cache_misses_total` | Counter | WASM module cache misses |
| `talos_active_jobs` | Gauge | Currently executing jobs |

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

Talos uses S3-compatible object storage for the audit ledger and module artifact storage. Configure via environment variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `S3_ENDPOINT` | S3-compatible endpoint URL | `http://minio:9000` |
| `S3_ACCESS_KEY_ID` | Access key ID | `minioadmin` |
| `S3_SECRET_ACCESS_KEY` | Secret access key | `minioadmin` |
| `S3_REGION` | AWS region (or `us-east-1` for MinIO) | `us-east-1` |

For local development, the default Docker Compose setup includes a MinIO instance. For production, use AWS S3 or a self-hosted MinIO cluster with TLS and non-default credentials.

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
| **NATS** | 3-replica StatefulSet, `minAvailable: 2` PDB | Already HA. Keep ≥3 replicas; JetStream stream replication ≥2 for at-least-once job delivery. |

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

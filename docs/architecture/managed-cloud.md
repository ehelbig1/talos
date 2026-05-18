# Managed Cloud Design Document

## Context

Talos is currently self-hosted only. Every competitor (Temporal Cloud, Inngest, Prefect Cloud) offers a managed tier. This document outlines the architecture for a Talos Cloud offering that preserves the platform's security guarantees while enabling SaaS delivery.

## Design Principles

1. **Security parity**: Cloud tenants get the same WASM isolation, capability tiers, and secret scoping as self-hosted
2. **Tenant isolation**: A compromise in tenant A must not affect tenant B
3. **Zero-trust data plane**: Tenant data is encrypted with tenant-managed keys; Talos operators cannot read it
4. **Metered billing**: Pay for what you use (executions, fuel, compilation minutes)

---

## Tenant Isolation Architecture

### Option A: Schema-per-Tenant (Recommended)

Each tenant gets a dedicated PostgreSQL schema within a shared database cluster.

```
talos_cloud (database)
  ├── tenant_abc123 (schema)  ← Tenant A's tables
  │     ├── workflows
  │     ├── workflow_executions
  │     ├── secrets
  │     └── ...
  ├── tenant_def456 (schema)  ← Tenant B's tables
  └── shared (schema)         ← Billing, tenant metadata, control plane
```

**Advantages:**
- Strong isolation (cross-schema access requires explicit `SET search_path`)
- Per-tenant backup/restore possible
- Compatible with pgBouncer connection pooling
- Row-level security as defense-in-depth (belt and suspenders)

**Disadvantages:**
- Schema migration must run per-tenant (tooling needed)
- Connection pool per schema (manageable with pgBouncer)

### Option B: Row-Level Security (Alternative)

Shared tables with `tenant_id` column and PostgreSQL RLS policies.

**Advantages:** Simpler migrations, single schema
**Disadvantages:** RLS bypass risk if policies misconfigured, harder to audit, no per-tenant backup

**Decision:** Schema-per-tenant for data isolation, with RLS as defense-in-depth on the `secrets` table.

---

## Compute Isolation

### Worker Pool Architecture

```
                    ┌─────────────────┐
                    │  Control Plane   │
                    │  (shared)        │
                    └────────┬────────┘
                             │ NATS (tenant-scoped subjects)
                ┌────────────┼────────────┐
                │            │            │
         ┌──────┴──────┐ ┌──┴────────┐ ┌─┴──────────┐
         │ Worker Pool │ │ Worker    │ │ Worker     │
         │ Tenant A    │ │ Pool B    │ │ Pool C     │
         │ (2 workers) │ │(4 workers)│ │(1 worker)  │
         └─────────────┘ └──────────┘ └────────────┘
```

- **Dedicated worker pools per tenant**: NATS subject routing (`talos.jobs.{tenant_id}`)
- **Shared WASM runtime**: Workers run multiple tenants' WASM modules, but the WASM sandbox provides isolation. This is cost-efficient and the isolation is already proven.
- **Premium tier**: Dedicated worker instances for tenants requiring physical isolation (compliance requirement)

### Compilation Isolation

- Containerized compilation (Podman, `--network=none`) is already implemented
- Cloud adds per-tenant compilation queue with priority scheduling
- Container image pinned per tenant (allows tenant-specific Rust toolchain versions)

---

## Secrets Isolation

### Per-Tenant KEK Hierarchy

```
Cloud Master Key (HSM-backed, AWS KMS / GCP Cloud KMS)
  └── Tenant KEK (unique per tenant, rotated annually)
        └── DEK (data encryption key, rotated per policy)
              └── Encrypts: secrets, execution output, audit logs
```

- **Tenant KEK** stored in the tenant's schema, encrypted by Cloud Master Key
- **Customer-Managed Keys (CMK)**: Enterprise tier allows tenants to bring their own KMS key. The Cloud Master Key is replaced with the tenant's KMS key for their KEK hierarchy.
- **Key rotation**: Automated annual rotation with re-encryption of active DEKs. Old DEKs retained for decryption of historical data.
- **Deletion**: When a tenant is offboarded, their KEK is deleted from KMS. All encrypted data becomes irrecoverable.

---

## Authentication & Identity

### Control Plane Auth

- **SSO**: SAML 2.0 and OIDC for enterprise identity providers
- **MFA**: Required for all accounts (TOTP, WebAuthn)
- **API Keys**: Scoped per-tenant, with rate limits
- **Service Accounts**: For CI/CD and automation

### Data Plane Auth

- **mTLS**: Worker-to-controller communication uses mutual TLS with per-tenant certificates
- **NATS Auth**: Per-tenant NATS credentials scoped to `talos.jobs.{tenant_id}.*`

---

## Billing Metering

### Metered Dimensions

| Dimension | Unit | Granularity | Source |
|-----------|------|-------------|--------|
| Workflow executions | Count | Per execution | `workflow_executions` table |
| WASM fuel consumed | Fuel units (millions) | Per execution | Worker fuel counter |
| Compilation minutes | Minutes (ceil) | Per compilation | Compilation service timer |
| Secret accesses | Count | Per access | `secret_audit_log` |
| Storage | GB-months | Daily snapshot | `pg_total_relation_size()` per schema |
| Outbound HTTP requests | Count | Per request | Worker HTTP counter |
| Concurrent workers | Peak per hour | Per hour | Worker pool autoscaler |

### Billing Pipeline

```
Worker/Controller → Prometheus metrics → Billing aggregator (hourly)
                                          → Stripe Usage Records (daily)
                                          → Invoice (monthly)
```

- Real-time usage dashboard via Grafana (tenant-scoped)
- Budget alerts at 80% and 100% of configured spending limits
- Hard cap option: suspend executions at budget limit (mirrors actor budget `on_budget_exceeded: suspend`)

---

## Control Plane API

### Tenant Lifecycle

```
POST   /api/v1/tenants              Create tenant (provisions schema + worker pool)
GET    /api/v1/tenants/:id          Get tenant details + usage
PATCH  /api/v1/tenants/:id          Update tenant config (worker count, tier)
DELETE /api/v1/tenants/:id          Offboard tenant (delete KEK → data irrecoverable)
```

### Worker Pool Management

```
GET    /api/v1/tenants/:id/workers           List worker instances
POST   /api/v1/tenants/:id/workers/scale     Scale worker pool (min/max/target)
GET    /api/v1/tenants/:id/workers/metrics   Worker utilization metrics
```

### Billing

```
GET    /api/v1/tenants/:id/usage             Current billing period usage
GET    /api/v1/tenants/:id/usage/history     Historical usage
POST   /api/v1/tenants/:id/budget            Set spending limit + alert thresholds
```

---

## Deployment Topology

```
┌──────────────────────────────────────────────────┐
│                 Cloud Provider (AWS/GCP)           │
│                                                    │
│  ┌────────────┐  ┌──────────┐  ┌──────────────┐  │
│  │ Control    │  │ NATS     │  │ PostgreSQL   │  │
│  │ Plane      │  │ Cluster  │  │ Cluster      │  │
│  │ (Axum)     │  │ (3 node) │  │ (Primary +   │  │
│  │ 3 replicas │  │          │  │  2 replicas) │  │
│  └────────────┘  └──────────┘  └──────────────┘  │
│         │              │              │            │
│  ┌──────┴──────────────┴──────────────┴──────┐   │
│  │        Worker Nodes (Kubernetes)           │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐     │   │
│  │  │Worker A1│ │Worker B1│ │Worker C1│     │   │
│  │  │Worker A2│ │Worker B2│ │         │     │   │
│  │  └─────────┘ └─────────┘ └─────────┘     │   │
│  └───────────────────────────────────────────┘   │
│                                                    │
│  ┌────────────┐  ┌──────────┐  ┌──────────────┐  │
│  │ Redis      │  │ S3/MinIO │  │ KMS          │  │
│  │ Cluster    │  │ (audit)  │  │ (KEK mgmt)   │  │
│  └────────────┘  └──────────┘  └──────────────┘  │
└──────────────────────────────────────────────────┘
```

---

## Migration Path from Self-Hosted

1. **Export**: `talos export --format cloud-bundle` creates a tarball of workflows, modules, templates, secrets (encrypted), and audit logs
2. **Import**: Control plane API accepts the bundle and provisions a new tenant schema
3. **DNS cutover**: Update MCP endpoint URL from self-hosted to `{tenant}.talos.cloud`
4. **Verification**: Run existing workflows against the cloud instance, compare outputs

---

## Open Questions

1. **Region selection**: Single region initially, or multi-region from day one?
2. **Compliance tier**: Separate VPC for HIPAA/SOC 2 tenants, or shared with stronger controls?
3. **Free tier**: Include a free tier (e.g., 1000 executions/month, 1 worker) for adoption?
4. **Self-hosted parity**: Should cloud features (team RBAC, SSO) also ship to self-hosted?

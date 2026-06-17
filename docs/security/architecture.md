# Talos Security Architecture

**Document version:** 1.0
**Date:** 2026-04-08
**Classification:** CONFIDENTIAL -- share only with authorized auditors and pentest firms.

---

## 1. System Architecture and Request Flow

```
                          INTERNET
                             |
                         [TLS 1.2+]
                             |
                    +--------v--------+
                    |   Load Balancer |
                    |   (HTTPS term)  |
                    +--------+--------+
                             |
              +--------------+--------------+
              |              |              |
         /graphql        /webhooks/*     /mcp
         (GraphQL)       (REST+HMAC)     (JSON-RPC)
              |              |              |
              v              v              v
     +--------+--------------+--------------+--------+
     |                  CONTROLLER                    |
     |              (Rust / Axum)                     |
     |                                                |
     |  +----------+  +----------+  +-----------+    |
     |  |  Auth    |  | Rate     |  |  CSRF     |    |
     |  |  Layer   |  | Limiter  |  |  Guard    |    |
     |  | (JWT/    |  | (governor|  | (double-  |    |
     |  |  API key |  |  +Redis) |  |  submit)  |    |
     |  |  +2FA)   |  |          |  |           |    |
     |  +----+-----+  +----+-----+  +-----+-----+   |
     |       |              |              |          |
     |       v              v              v          |
     |  +-------------------------------------------+ |
     |  |           Request Handler                 | |
     |  |  (GraphQL resolver / MCP dispatch / REST) | |
     |  +----+------------------+-------------------+ |
     |       |                  |                     |
     |  +----v-----+     +-----v------+              |
     |  | Secrets  |     | Workflow   |              |
     |  | Manager  |     | Engine     |              |
     |  | (AES-256 |     | (parallel  |              |
     |  |  GCM)    |     |  executor) |              |
     |  +----+-----+     +-----+------+              |
     |       |                  |                     |
     +-------+------------------+---------------------+
             |                  |
        +----v-----+     +-----v------+
        |PostgreSQL |     |    NATS    |
        |(encrypted |     | JetStream  |
        | at rest)  |     | (signed    |
        +-----------+     |  jobs)     |
                          +-----+------+
                                |
                          [HMAC verified]
                                |
                    +-----------v-----------+
                    |        WORKER         |
                    |    (Rust / wasmtime)  |
                    |                       |
                    |  +------------------+ |
                    |  | Capability World | |
                    |  | Enforcement      | |
                    |  +--------+---------+ |
                    |           |           |
                    |  +--------v---------+ |
                    |  |   WASM Guest     | |
                    |  | (sandboxed       | |
                    |  |  user code)      | |
                    |  +------------------+ |
                    +-----------------------+
```

---

## 2. Secret Lifecycle

### 2.1 Encryption Architecture (Envelope Encryption)

```
  KEK (Key Encryption Key)        Data Encryption Key (DEK)
  ========================        ========================
  - Pluggable via KekProvider     - 256-bit AES key
    trait (controller/src/        - Generated per rotation
    secrets/kek_provider.rs)      - Wrapped by KEK provider
  - Production: Vault transit     - Stored in encryption_keys table
    (KEK_PROVIDER=vault) — key      (single `encrypted_key` column;
    NEVER enters controller         wire format opaque, defined by
    process memory; wrap/unwrap     the provider)
    is an HTTPS call to Vault     - Cached in DashMap (5-min TTL)
  - Dev: EnvKekProvider (KEK_
    PROVIDER=env) — TALOS_MASTER_
    KEY env var, in-process

  Encryption flow:
  +-----------+   KekProvider       +--------------+    stored in DB
  | Plaintext |   .wrap_dek()       | Wrapped DEK  | ----------------->
  |   DEK     |  ----------------> | (opaque bytes)|   encryption_keys
  +-----------+   (Vault transit    +--------------+   table
                  OR local AES-GCM)

  Per-row data storage (every column carrying user data):
  +----------+   DEK → per-context   +-------------+    stored in DB
  | Plaintext|   HKDF subkey         | Ciphertext  | ----------------->
  |  value   |   AES-256-GCM         |  + key_id   |   secrets,
  +----------+   (AAD-bound,         +-------------+   oauth_tokens,
                  random nonce)                        actor_memory.value_enc,
                                                       module_executions.{input,
                                                         output,trigger_metadata}_enc,
                                                       workflow_executions.output_data_enc
```

**Per-context key derivation (format v3, finding #1).** The cached DEK is the
derivation *root*, not the data key. Each row is sealed under a per-context
subkey `HKDF-SHA256(ikm = DEK, salt = label, info = aad_context)`, where the
context is the row's identity (secret_id / actor_id‖key / execution_id /
per-slot tag) — the same bytes bound as AES-GCM AAD. This keeps the per-key
message count at ~1, so the random-96-bit-nonce birthday bound is never
approached, and a leaked single-row subkey can't decrypt any other context. A
per-row `encryption_format_version` selects the scheme; legacy v0/v1/v2 rows
still decrypt under lazy migration (`SecretsManager::decrypt_versioned`).

The `KekProvider` abstraction means every encrypted column above
behaves identically regardless of whether the KEK is a local AES key
or a Vault transit operation — call sites never branch on backend.
See `docs/deployment.md` for the env→Vault migration procedure
(historical reference: `docs/security/kek-to-kms-plan.md`).

### 2.2 Secret Lifecycle Steps

| Step | Action | Location | Security Control |
|------|--------|----------|-----------------|
| 1. Creation | User provides secret value via API | Controller | Input validation; TLS in transit |
| 2. DEK retrieval | Active DEK fetched (cache or DB) | SecretsManager | DashMap cache with 5-min TTL; Zeroizing memory |
| 3. Encryption | Secret encrypted under a per-context HKDF subkey of the DEK | SecretsManager | AES-256-GCM (format v3); AAD-bound to secret_id; per-context subkey so each key encrypts ~1 message; random 12-byte nonce prepended to ciphertext |
| 4. Storage | Encrypted blob stored in DB | PostgreSQL | Parameterized INSERT; `key_path` indexed for lookup |
| 5. Audit | Access logged to `secret_audit_log` | Controller | Append-only table; immutability trigger; DLP redaction on payload |
| 6. Retrieval | Module requests secret by key_path | Worker host | `allowed_secrets` allowlist check; deny-all default |
| 7. Slot handle | Opaque `SlotHandle(u64)` returned to WASM | Worker | Raw value never crosses WASM boundary |
| 8. Usage | Module calls `into_auth_header()` | Worker host | Single plaintext exit point; grep-able |
| 9. Release | Slot released after use or TTL (300s) | Worker | `Zeroizing<String>` ensures memory is zeroed |
| 10. Rotation | New DEK created; old secrets re-encrypted | Controller | Old DEK deactivated; new DEK set active; cache invalidated |

### 2.3 DEK Caching

```
  Request arrives
       |
       v
  Check DashMap cache  ----[hit + within TTL]----> Return cached DEK (<1ms)
       |
  [miss or expired]
       |
       v
  Query encryption_keys WHERE active=true
       |
       v
  Decrypt with master key (AES-256-GCM)
       |
       v
  Store in cache (RwLock<Option<CachedDek>>)
       |
       v
  Return DEK (~50ms first access)
```

---

## 3. Authentication Flow

### 3.1 Login with Password + 2FA

```
  Client                          Controller                    PostgreSQL / Redis
    |                                 |                              |
    |-- POST /login (email, pass) --> |                              |
    |                                 |-- Check rate limit --------> |
    |                                 |   (5/min auth per IP)        |
    |                                 |                              |
    |                                 |-- Fetch user by email -----> |
    |                                 |<- User record (bcrypt hash)--|
    |                                 |                              |
    |                                 |-- bcrypt::verify(pass, hash) |
    |                                 |                              |
    |                                 |   [If 2FA enabled]           |
    |<-- 200 { requires_2fa: true } --|                              |
    |                                 |                              |
    |-- POST /verify-2fa (code) ----> |                              |
    |                                 |-- Check 2FA rate limit ----> |
    |                                 |   (5 attempts, 15min lockout)|
    |                                 |                              |
    |                                 |-- Redis SETNX totp:{code} -> |
    |                                 |   (replay prevention, NX)    |
    |                                 |                              |
    |                                 |-- Constant-time verify ----> |
    |                                 |   (subtle::ConstantTimeEq)   |
    |                                 |   3-window tolerance (t-1,t,t+1)
    |                                 |                              |
    |                                 |-- Generate JWT ------------> |
    |                                 |   sub: user_id               |
    |                                 |   iss: "talos"               |
    |                                 |   exp: now + 15min           |
    |                                 |   is_2fa_verified: true      |
    |                                 |                              |
    |<-- Set-Cookie: HttpOnly --------|                              |
    |    Secure; SameSite=Strict      |                              |
    |    + CSRF token (non-HttpOnly)  |                              |
```

### 3.2 JWT Validation

| Check | Implementation | File |
|-------|---------------|------|
| Algorithm | HS256 only; reject others | `controller/src/auth/mod.rs` |
| Issuer claim | Must match `"talos"` | `Claims.iss` field, validated in `verify_token` |
| Expiration | 15-minute TTL | `Claims.exp` checked by jsonwebtoken crate |
| 2FA status | `is_2fa_verified` claim | Enforced at handler level for sensitive operations |

### 3.3 API Key Authentication

```
  Format:  talos_sk_<random_base64>

  Validation:
  1. Constant-time prefix check (subtle::ConstantTimeEq, 512-byte padded buffer)
  2. SHA256 lookup hash for O(1) database query (not security -- for speed)
  3. bcrypt verification of full key against stored hash
  4. Scope check against endpoint requirements
  5. Audit log entry recorded

  Scopes:
  - workflows:read   -- Read workflow definitions and execution status
  - workflows:write  -- Create, modify, trigger workflows
  - secrets:read     -- List secrets (not values)
  - secrets:write    -- Create, rotate, delete secrets
  - webhooks:access  -- Configure and receive webhooks
  - admin            -- Full platform access
```

### 3.4 Refresh Token Flow

```
  Client                          Controller
    |                                 |
    |-- POST /refresh (cookie) -----> |
    |                                 |-- Rate limit check (per-user in-memory)
    |                                 |-- Validate refresh token (SHA256 lookup + bcrypt)
    |                                 |-- Check session not revoked
    |                                 |-- Issue new JWT (15-min TTL)
    |                                 |-- Rotate refresh token
    |<-- New JWT + new refresh -------|
```

---

## 4. Authorization Model

### 4.1 Capability World System (9 Tiers)

The capability world system controls what WIT (WebAssembly Interface Types) imports are available to each WASM module. Higher tiers unlock more host functions.

| Tier | World Name | Capabilities | Use Case |
|------|-----------|-------------|----------|
| 1 | `minimal` | Pure computation, no host access | Data transforms, validation |
| 2 | `minimal-node` | Minimal + node I/O | Default for new modules |
| 3 | `http-node` | HTTP client (outbound, SSRF-protected) | API integrations |
| 4 | `secrets-node` | Vault access (per-module allowlist) | Authenticated API calls |
| 5 | `automation-node` | Secrets + filesystem (scoped) | File processing |
| 6 | `database-node` | Read-only database queries | Analytics, reporting |
| 7 | `governance-node` | Approval gates, actor management | Human-in-the-loop workflows |
| 8 | `full-node` | All standard capabilities | Trusted internal modules |
| 9 | `admin-node` | Platform administration | System management |

**Enforcement points:**
- Compilation time: module's declared world checked against actor's max ceiling
- Runtime: wasmtime only links WIT imports for the declared world
- MCP tools: `add_node_to_workflow` checks capability ceiling BEFORE compilation

### 4.2 Actor Budget System

Each actor (human or agent) has resource budgets enforced per time window:

| Budget Field | Purpose | Enforcement |
|-------------|---------|-------------|
| `max_executions_per_hour` | Execution rate limit | Checked at trigger time |
| `max_concurrent_executions` | Parallel execution cap | Checked at trigger time |
| `max_cpu_seconds_per_hour` | CPU budget | Fuel metering in WASM |
| `max_memory_mb` | Memory cap | wasmtime memory limits |
| `max_network_requests_per_hour` | Outbound HTTP cap | Host function counter |
| `max_secret_accesses_per_hour` | Vault access rate | Host function counter |
| `max_db_queries_per_hour` | DB query rate | Host function counter |
| `max_file_ops_per_hour` | Filesystem operation rate | Host function counter |

All 8 fields validated: positive integers only, zero/negative rejected with explicit error.

### 4.3 RBAC (Role-Based Access Control)

| Role | Permissions |
|------|------------|
| User | Own workflows, own executions, own secrets |
| Org Member | Organization workflows (shared), org secrets |
| Admin | All resources, platform configuration, actor management, audit access |

Admin check: `is_admin()` method (replaces all inline string checks as of r155).

### 4.4 Approval Gates

Human-in-the-loop governance for sensitive workflows:

| Policy Mode | Behavior |
|------------|----------|
| `block` | Execution paused until approved; requires non-empty approvers list |
| `notify` | Execution paused, notifications sent; requires non-empty approvers list |
| `log` | Execution continues, event logged; no approvers required |

Approval flow: Redis pub/sub for real-time notification; `execution_approvals` table for persistence; MCP tools `list_pending_approvals` and `submit_workflow_approval` with ownership verification.

---

## 5. Network Security

### 5.1 SSRF Protection

The `check_outbound_url_no_ssrf()` function (in `controller/src/mcp/utils.rs`) blocks:

| Blocked Range | Reason |
|--------------|--------|
| `127.0.0.1`, `localhost`, `::1`, `0.0.0.0` | Loopback |
| `10.0.0.0/8` | RFC1918 private |
| `172.16.0.0/12` | RFC1918 private |
| `192.168.0.0/16` | RFC1918 private |
| `169.254.0.0/16` | Link-local |
| `169.254.169.254` | AWS/GCP/Azure metadata endpoint |
| `metadata.google.internal` | GCP metadata endpoint |
| `fc00::/7` (fd, fc prefixes) | IPv6 ULA |
| `fe80::/10` | IPv6 link-local |
| IPv4-mapped IPv6 (`::ffff:10.x.x.x`) | IPv6-wrapped private addresses |

HTTPS enforced for all outbound webhook URLs.

### 5.2 Rate Limiting Architecture

```
  Request
    |
    v
  Per-IP Rate Limiter (governor crate, in-memory)
  - API: 300/min (configurable via RATE_LIMIT_API_PER_MIN)
  - Auth: 5/min (configurable via RATE_LIMIT_AUTH_PER_MIN)
    |
    v
  Distributed Rate Limiter (Redis, sliding window)
  - Per-user MCP: 5000/min
  - Per-agent MCP: 1000/min
  - Webhook per-trigger: configurable
    |
    v
  Application-level limits
  - GraphQL depth: 15, complexity: 5000
  - TOTP: 5 attempts, 15-min lockout
  - Refresh token: per-user in-memory
```

### 5.3 TLS Requirements

| Connection | Development | Production |
|-----------|-------------|------------|
| Client to Controller | HTTP allowed | HTTPS required (via LB/proxy) |
| Controller to Redis | `redis://` allowed | `rediss://` enforced (panic on violation) |
| Controller to PostgreSQL | Plaintext allowed | TLS recommended (sslmode=require) |
| Controller to NATS | Plaintext allowed | TLS recommended |
| Outbound webhooks | HTTP allowed | HTTPS enforced by SSRF check |

---

## 6. Audit and Monitoring

### 6.1 Audit Tables

| Table | Purpose | Immutability | DLP |
|-------|---------|-------------|-----|
| `audit_events` | Primary security audit ledger | Trigger: `trg_audit_events_immutable` | Yes |
| `auth_audit_log` | Login/logout events | Trigger: `trg_auth_audit_log_immutable` | Yes |
| `secret_audit_log` | Secret access events | Trigger: `trg_secret_audit_log_immutable` | Yes |
| `admin_event_log` | Admin action events | Trigger: `trg_admin_event_log_immutable` | Yes |

All triggers use `prevent_audit_modification()` function: BEFORE UPDATE OR DELETE, raises SQLSTATE 42501 (insufficient_privilege).

#### 6.1.1 WORM ledger cryptographic verification (finding #2)

The worker emits a per-execution, **HMAC-SHA256-signed SHA-256 hash chain**
of audit events (`talos-audit-event`) over `talos.audit.ledger`. The
controller-side consumer (`talos-audit-ledger`):

- **Inline, before S3 persist (Layer 1):** recomputes each event's hash and
  verifies it equals the published hash (integrity), and verifies the HMAC
  against the configured keys (authenticity). Events that fail are **not**
  persisted to the ledger — they are quarantined to an Object-Locked
  `rejected/` prefix (evidence retained) and logged at ERROR, rather than the
  pre-fix silent ACK-drop. Persistence is to S3 with Object-Lock Compliance
  (WORM) when enabled.
- **Offline (Layer 2):** `verify_chain` / `verify_execution_chain` re-derive
  the chain over the full ordered record set and detect sequence gaps
  (deletion / never-persisted events), broken `previous_hash` linkage
  (reorder/substitution), genesis mismatch, and per-event HMAC failures —
  the stateful checks that need the whole chain and so can't run in the
  streaming persister.
- **Continuous (Layer 2, wired):** a controller-side background sweep
  (`run_chain_verification_sweep`, interval `AUDIT_CHAIN_SWEEP_INTERVAL_SECS`,
  default 3600s; `0` disables) runs the offline verifier over executions that
  reached a terminal state in the recent window (a 120s settle floor skips
  events still batching to S3) and emits one structured
  `audit_chain_verification_failed` ERROR per broken chain plus an
  `audit_chain_sweep_summary` per pass — the SIEM alerting signal. Self-disables
  when no S3/WORM endpoint is configured.

Signing requires `TALOS_AUDIT_SIGNING_KEY` (32+ bytes) on workers AND the
controller; `TALOS_AUDIT_SIGNING_KEY_PREVIOUS` supports rotation overlap.

### 6.2 Observability Stack

| Layer | Technology | Metrics |
|-------|-----------|---------|
| Application metrics | Prometheus (`prometheus` crate) | Webhook counts/latency, auth success/failure, execution counts/duration, rate limit hits, cache hit/miss, DLQ drops |
| Distributed tracing | OpenTelemetry (OTLP export) | Per-tenant tracer providers; LRU cache (100 providers); configurable endpoint per user |
| Structured logging | `tracing` crate | JSON-formatted in production; span context propagation |
| Audit streaming | NATS JetStream | Real-time audit event stream to external SIEM; consumer verifies HMAC + hash before WORM (S3 Object Lock) persist, quarantining failures to `rejected/`; offline chain verifier for linkage/sequence/genesis (§6.1.1) |

### 6.3 Sensitive Value Logging Policy

The following values are NEVER logged (presence-only logging):
- JWT tokens, refresh tokens, API keys
- Secret values, encryption keys, master key
- TOTP seeds, TOTP codes
- Cookie values, CSRF tokens
- Webhook signing secrets
- OAuth tokens (encrypted before storage; plaintext columns dropped in migration 036)

Implementation: `User` struct's `Debug` impl redacts `password_hash` and `totp_secret` with `[REDACTED]`.

---

## 7. Compilation Security

### 7.1 Module Compilation Pipeline

```
  User submits Rust source code
       |
       v
  Crate allowlist check
  (DEFAULT_ALLOWED_DEPENDENCIES in utils.rs)
  - reqwest explicitly blocked (wasm-bindgen incompatible)
  - Only pre-approved crates allowed
       |
       v
  cargo-audit gate
  (Reject modules with known vulnerable dependencies)
       |
       v
  Containerized compilation (Podman)
  - --network=none (no network during build)
  - Isolated filesystem
  - Resource limits
       |
       v
  WASM binary output
  - Component model magic check (8 bytes)
  - wasm32-wasip1 vs wasip2 detection
       |
       v
  Macro injection (RE_RUN_FN targets `fn run(`)
  - #[talos_module] / #[talos_node] / #[talos_agent]
  - catch_unwind for panic recovery
  - Dependency injection for SDK imports
       |
       v
  Store compiled module
  (wasm_modules table with capability_world)
```

### 7.2 Pre-bundled Crates

The compilation pipeline pre-bundles certain crates to avoid duplicate key errors:
- `serde`
- `serde_json`
- `wit-bindgen`
- `talos_sdk_macros`

These are skipped during user dependency resolution.

---

## 8. Data Classification

| Classification | Examples | Storage | Access |
|---------------|----------|---------|--------|
| Critical | KEK (master key) | Vault transit (`KEK_PROVIDER=vault`, prod) — never enters controller memory. `TALOS_MASTER_KEY` env var (`KEK_PROVIDER=env`, dev only). | Vault transit token / controller process |
| Secret | User secrets, OAuth tokens, signing keys, **actor memory**, **module-execution payloads**, **workflow-execution outputs** | AES-256-GCM envelope encryption in PostgreSQL (per-row DEK wrapped by KEK) | Per-module allowlist; per-actor LLM tier ceiling for LLM payloads |
| Sensitive | Admin events (`admin_event_log`), audit logs | PostgreSQL append-only (DLP-redacted, intentionally NOT envelope-encrypted to preserve query-ability for incident triage — see runbook §1.2) | Authenticated + authorized |
| Internal | Workflow definitions, module source code, WASM bytes | PostgreSQL | Owner + org members |
| Public | Health check, API schema (dev only) | N/A | Unauthenticated |

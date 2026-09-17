# Talos Security Architecture

**Document version:** 1.1
**Date:** 2026-09-16
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
        |PostgreSQL |     | NATS (core |
        |(encrypted |     | req/reply; |
        | at rest)  |     | signed     |
        +-----------+     |  jobs)     |
                          +-----+------+
                                |
                   [HMAC or Ed25519 verified]
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

Job dispatch uses core NATS request/reply (`talos.jobs`, `talos.pipeline.jobs`),
not JetStream; the worker's NATS credential is denied the `$JS.>` API namespace
(`talos-workflow-job-protocol/src/nats_permissions.rs`). The only JetStream
stream is the audit ledger buffer (§6.1.1). The worker verifies each dispatch
as HMAC-SHA256 under the fleet-shared `WORKER_SHARED_KEY` or as an Ed25519
signature from the controller key; HMAC dispatches are accepted unless the
worker runs with `TALOS_DISPATCH_REQUIRE_ED25519` (`worker/src/main.rs`).

---

## 2. Secret Lifecycle

### 2.1 Encryption Architecture (Envelope Encryption)

```
  KEK (Key Encryption Key)        Data Encryption Key (DEK)
  ========================        ========================
  - Pluggable via KekProvider     - 256-bit AES key
    trait (talos-secrets-         - One global DEK + one per org;
    manager/src/kek_provider.rs)    new one per rotation
  - Vault transit (KEK_PROVIDER=  - Wrapped by KEK provider
    vault, chart default) — key   - Stored in encryption_keys table
    NEVER enters controller         (single `encrypted_key` column;
    process memory; wrap/unwrap     wire format opaque, defined by
    is an HTTPS call to Vault       the provider)
  - EnvKekProvider (KEK_PROVIDER= - Unwrapped DEKs cached in memory
    env, code default) —            (5-min TTL, DEK_CACHE_TTL_SECS)
    TALOS_MASTER_KEY env var,
    in-process AES-256-GCM;
    refused in production unless
    TALOS_ALLOW_ENV_KEK is set

  Encryption flow:
  +-----------+   KekProvider       +--------------+    stored in DB
  | Plaintext |   .wrap_dek()       | Wrapped DEK  | ----------------->
  |   DEK     |  ----------------> | (opaque bytes)|   encryption_keys
  +-----------+   (Vault transit    +--------------+   table
                  OR local AES-GCM)

  Per-row data storage (every column carrying user data):
  +----------+   DEK → per-context   +-------------+    stored in DB
  | Plaintext|   HKDF subkey         | Ciphertext  | ----------------->
  |  value   |   AES-256-GCM         |  + key_id   |   secrets (incl. OAuth
  +----------+   (AAD-bound,         +-------------+     tokens at oauth/…),
                  random nonce)                        actor_memory.value_enc,
                                                       module_executions.{input,
                                                         output,trigger_metadata}_enc,
                                                       workflow_executions.output_data_enc
```

OAuth access and refresh tokens are not a separate table: they are stored as
encrypted rows in `secrets` at `oauth/<provider>/<user_id>/<provider_key>/…`
paths (`talos-oauth/src/credentials.rs`); `integration_credentials` holds only
the paths and metadata.

**Per-context key derivation + per-ORG root DEKs (formats v3/v4).** A DEK is the
derivation *root*, not the data key. Each row is sealed under a per-context subkey
`HKDF-SHA256(ikm = DEK, salt = label, info = aad_context)`, where the context is
the row's identity (secret_id / actor_id‖key / execution_id / per-slot tag) — the
same bytes bound as AES-GCM AAD. This keeps the per-key message count at ~1, so
the random-96-bit-nonce birthday bound is never approached, and a leaked
single-row subkey can't decrypt any other context.

**DEKs are scoped per-organization** (`encryption_keys.org_id`): one global DEK
(`org_id IS NULL`) plus one active DEK per org. A writer seals under its org's DEK
(format `v4`) when an org is resolvable, else the global DEK (`v3`) for
legitimately org-less rows — so **a compromised root DEK is bounded to one tenant,
not the whole deployment.** Decrypt is identical for v3/v4 (the row's `*_key_id`
names the DEK); a per-row `*_format` column selects the scheme and
`SecretsManager::decrypt_versioned` handles v0/v1/v2/v3/v4 under lazy migration.
Existing rows move to per-org via `re_encrypt_*_to_org` sweeps; the
`dekMigrationStatus` query reports remaining work. OTLP auth headers use this
same DEK envelope (with a domain-tagged `user_id` AAD,
`talos-audit-ledger/src/lib.rs::encrypt_otlp_auth_headers`). Checkpoint
encryption and the default worker secret envelope do not use the DEK: they
derive keys from `WORKER_SHARED_KEY` and are not per-org. When claim-based
sealing is enabled (`TALOS_ENVELOPE_SEALING`), job secrets are instead sealed
to a per-execution ephemeral X25519 key
(`talos-workflow-job-protocol/src/envelope_seal.rs`).

The `KekProvider` abstraction means every encrypted column above
behaves identically regardless of whether the KEK is a local AES key
or a Vault transit operation — call sites never branch on backend.
See `docs/deployment.md` for the env→Vault migration procedure.

### 2.2 Secret Lifecycle Steps

| Step | Action | Location | Security Control |
|------|--------|----------|-----------------|
| 1. Creation | User provides secret value via API | Controller | Input validation; TLS in transit |
| 2. DEK retrieval | The org's active DEK fetched (cache or DB), or the global DEK for org-less rows | SecretsManager | In-memory caches (per-org + global) with 5-min TTL; `Zeroizing` key bytes |
| 3. Encryption | Secret encrypted under a per-context HKDF subkey of the org's DEK (v4) or the global DEK (v3) | SecretsManager | AES-256-GCM; AAD-bound to secret_id; per-context subkey so each key encrypts ~1 message; random 12-byte nonce prepended to ciphertext |
| 4. Storage | Encrypted blob stored in DB | PostgreSQL | Parameterized INSERT; `key_path` indexed for lookup |
| 5. Audit | Access logged to `secret_audit_log` | Controller | Append-only table; immutability trigger; DLP redaction of the error field |
| 6. Retrieval | Module requests secret by key_path | Worker host | `allowed_secrets` allowlist check; deny-all default |
| 7. Slot handle | Opaque `SlotHandle(u64)` returned to WASM | Worker | Raw value does not cross the WASM boundary on this path |
| 8. Usage | Host uses the slot via `into_auth_header()`, `sign()` or `decrypt()` | Worker host | Three auditable plaintext exits on `SecretProvider` (`talos-secrets/src/provider.rs`); a fourth, Tier-2 `expose_secret`, returns plaintext to the guest only when the module opts in with `allow_tier2_exposure` (every dispatch path sets `false`), rate-limited and logged at WARN |
| 9. Release | Slot released after use or TTL (300s) | Worker | `Zeroizing<String>` ensures memory is zeroed |
| 10. Rotation | GraphQL `rotateDek` creates a new global DEK | Controller | Old global DEK deactivated; new one set active; `DEK_ROTATED` written to `secret_audit_log`; active-DEK cache cleared. Existing rows are NOT re-encrypted by rotation — they keep decrypting under the old DEK until the separate `reEncryptSecrets` mutation is run. Per-org DEKs are not touched by `rotateDek`; `SecretsManager::rotate_dek_for_org` exists but no API calls it |

### 2.3 DEK Caching

```
  Request arrives
       |
       v
  Check in-memory cache  ----[hit + within TTL]----> Return cached DEK
  (by key_id: DashMap;
   active global: RwLock<Option<CachedDek>>;
   active per-org: DashMap)
       |
  [miss or expired]
       |
       v
  Query encryption_keys (by id, or active = true
  AND org_id IS NULL / org_id = $1)
       |
       v
  Unwrap via the configured KekProvider (unwrap_dek);
  on failure, try the legacy provider if one is configured
       |
       v
  Store in cache (TTL: DEK_CACHE_TTL_SECS, default 300)
       |
       v
  Return DEK
```

---

## 3. Authentication Flow

### 3.1 Login with Password + 2FA

Login, 2FA verification and token refresh are GraphQL mutations (`login`,
`verifyTwoFactor`, `refreshToken`) on `/graphql`, not REST routes
(`talos-api/src/schema/auth/mutations.rs`).

```
  Client                          Controller                    PostgreSQL / Redis
    |                                 |                              |
    |-- mutation login -------------> |                              |
    |   (email, password)             |-- Check rate limit --------> |
    |                                 |   (5/min per IP, Redis;      |
    |                                 |    fail-closed in production)|
    |                                 |                              |
    |                                 |-- Fetch user by email -----> |
    |                                 |<- User record (bcrypt hash)--|
    |                                 |                              |
    |                                 |-- bcrypt::verify(pass, hash) |
    |                                 |                              |
    |<-- AuthPayload { user {         |                              |
    |      twoFactorEnabled,          |                              |
    |      isTwoFactorVerified } }    |                              |
    |    + session cookies (JWT       |                              |
    |      is_2fa_verified = false    |                              |
    |      when 2FA is enabled)       |                              |
    |                                 |                              |
    |-- mutation verifyTwoFactor ---> |                              |
    |   (code; pre-2FA session)       |-- Per-IP rate limit (5/min)  |
    |                                 |-- Per-user attempt counter ->|
    |                                 |   (5 attempts, 15min lockout;|
    |                                 |    Redis, fail-closed in prod)|
    |                                 |                              |
    |                                 |-- Constant-time verify       |
    |                                 |   (subtle::ConstantTimeEq)   |
    |                                 |   3-window tolerance (t-1,t,t+1)
    |                                 |                              |
    |                                 |-- Redis SET NX EX 90 ------> |
    |                                 |   totp_used:{user_id}:{code} |
    |                                 |   (replay prevention, after  |
    |                                 |    a valid code; fail-closed)|
    |                                 |                              |
    |                                 |-- Generate JWT               |
    |                                 |   sub: user_id               |
    |                                 |   iss: "talos", aud: "talos" |
    |                                 |   exp: now + 15min           |
    |                                 |   is_2fa_verified: true      |
    |                                 |-- Revoke pre-2FA sessions    |
    |                                 |                              |
    |<-- AuthPayload + Set-Cookie ----|                              |
    |    HttpOnly; SameSite=Strict;   |                              |
    |    Secure (production only)     |                              |
    |    (CSRF cookie is non-HttpOnly)|                              |
```

A 12-hex-character backup code is accepted in place of a TOTP code (bcrypt-verified
against the stored backup codes). In production, `verifyTwoFactor` refuses to run
when no Redis client is configured (`talos-totp-2fa/src/lib.rs`).

### 3.2 JWT Validation

| Check | Implementation | File |
|-------|---------------|------|
| Algorithm | Pinned to the configured `JWT_ALGORITHM` — `HS256` (default), `RS256` or `ES256`; a token signed with any other algorithm is rejected. During a key/algorithm migration the previous key pair's algorithm is also accepted | `talos-auth/src/lib.rs::verify_token` |
| Issuer claim | Must match `"talos"` | `Claims.iss` field, validated in `verify_token` |
| Audience claim | If present, must be `"talos"`; tokens with no `aud` are accepted unless `JWT_REQUIRE_AUD=true` | `talos-auth/src/lib.rs::verify_token` |
| Expiration | 15-minute TTL | `Claims.exp` checked by jsonwebtoken crate |
| 2FA status | `is_2fa_verified` claim | Enforced at handler level for sensitive operations (`require_2fa`) |

### 3.3 API Key Authentication

```
  Format:  talos_sk_<8 hex prefix><64 hex secret>
           (4 + 32 random bytes from OsRng, hex-encoded)

  Validation (talos-api-keys/src/lib.rs::validate_key):
  1. Constant-time check of the literal "talos_sk_" prefix (subtle::ConstantTimeEq)
  2. Rate limit: 60 validations/min per 8-hex key prefix (Redis when configured,
     plus an in-process counter)
  3. Candidate lookup by the 8-hex `key_prefix` column (active keys only)
  4. Expiry check, then bcrypt verification of the full key against each candidate
  5. last_used_at / usage_count updated (atomic re-check that the key is still active)
  6. Scope check in the GraphQL resolver (require_scope)

  No audit-log row is written on validation; admin_event_log rows are
  written when keys are created, revoked, deleted, rotated or expired.

  Scopes:
  - workflows:read   -- Read workflow definitions and execution status
  - workflows:write  -- Create, modify, trigger workflows
  - secrets:read     -- List secrets (not values)
  - secrets:write    -- Create, rotate, delete secrets
  - webhooks:access  -- Configure and receive webhooks
  - admin            -- Satisfies every scope check
```

Scopes constrain API-key callers only: `require_scope` passes a cookie-session
caller without checking a scope, and an API-key caller is treated as
2FA-verified (`talos-api/src/schema/mod.rs`).

### 3.4 Refresh Token Flow

```
  Client                          Controller
    |                                 |
    |-- mutation refreshToken ------> |
    |   (talos_refresh_token cookie)  |-- Per-IP rate limit (auth limiter, 5/min)
    |                                 |-- Look up session by SHA-256 lookup hash
    |                                 |   (miss on a rotated token >= 5s old ⇒
    |                                 |    reuse detected: revoke ALL user sessions)
    |                                 |-- Per-user rate limit: 10/min (Redis when
    |                                 |   available, plus an in-memory counter)
    |                                 |-- bcrypt verify of the refresh token
    |                                 |-- Check session not revoked
    |                                 |-- Issue new JWT (15-min TTL)
    |                                 |-- Rotate refresh token (7-day TTL)
    |<-- AuthPayload + new cookies ---|
```

---

## 4. Authorization Model

### 4.1 Capability World System (12 worlds, a lattice)

The capability world system controls which WIT (WebAssembly Interface Types)
imports a WASM module can link, and which worlds an actor may be given. There
are **12** actor-ceiling worlds (`talos_capability_world::ACTOR_CEILING_WORLDS`);
11 are compilable module worlds, and `llm-node` exists only as an actor
ceiling. The worlds form a **partial order, not a ladder**: a ceiling permits
a world only when that world's interfaces are a subset of the ceiling's
(`talos_capability_world::ceiling_permits`). The permitted sets below are what
the GraphQL `capabilityWorldHierarchy` query serves from that function:

| Ceiling | Adds | Permits |
|---------|------|---------|
| `minimal-node` | Pure computation, no host access | `minimal-node` |
| `http-node` | Outbound HTTP (SSRF-protected), events, SSE | `minimal-node`, `http-node`, `llm-node` |
| `llm-node` | Native LLM host bindings, no vault | `minimal-node`, `http-node`, `llm-node` |
| `network-node` | Raw socket access | `minimal-node`, `http-node`, `llm-node`, `network-node` |
| `secrets-node` | Vault access (per-module allowlist) + LLM | `minimal-node`, `http-node`, `llm-node`, `network-node`, `secrets-node` |
| `governance-node` | Human-approval gates | `minimal-node`, `governance-node` |
| `messaging-node` | NATS pub/sub | `minimal-node`, `http-node`, `llm-node`, `network-node`, `messaging-node` |
| `filesystem-node` | Scoped file I/O | `minimal-node`, `http-node`, `llm-node`, `network-node`, `filesystem-node` |
| `cache-node` | Redis cache | `minimal-node`, `http-node`, `llm-node`, `network-node`, `cache-node` |
| `database-node` | Sandboxed SQL | `minimal-node`, `http-node`, `llm-node`, `network-node`, `secrets-node`, `database-node` |
| `agent-node` | LLM + secrets + memory + governance + orchestration | `minimal-node`, `http-node`, `llm-node`, `network-node`, `secrets-node`, `governance-node`, `agent-node` |
| `automation-node` | All interfaces | all 12 |

There is no `full-node`, `admin-node` or `standard-node`; those
names were retired and every gate reads them as unrecognised.

**Enforcement points** (lattice: `talos-capability-world/src/lib.rs`):
- Authoring: `add_node_to_workflow` / inline compile check the actor's ceiling
  before compilation.
- Dispatch: the engine refuses a module whose world the bound actor's ceiling
  does not permit (`talos-workflow-engine/src/capability_ceiling.rs::refuse_module_over_ceiling`,
  both single and pipeline paths), which also covers sub-workflow children.
- Runtime: wasmtime links only the WIT imports of the module's declared world.
- Grants: a user's own ceiling lives in `user_capability_grants`, whose CHECK
  constraint admits exactly the 12 worlds; an actor's world cannot exceed it.

### 4.2 Actor Budget System

Each actor may have one `actor_budget_policies` row. Every limit is optional
(NULL = no cap) except the two with column defaults. Enforcement is at
execution-row creation, inside one transaction under a per-actor advisory lock
(`talos-workflow-repository/src/executions.rs::create_execution_under_concurrency_limit`),
plus a lock-free pre-check on the trigger paths
(`talos-actor-repository/src/budget_precheck.rs`). Sub-workflow children run
in-process, create no execution row, and are not counted.

| Column | Purpose | Enforcement |
|-------------|---------|-------------|
| `max_executions_per_hour` | Execution rate limit | ENFORCED: count of the actor's executions started in the last hour, at row creation |
| `max_executions_total` | Lifetime execution cap | ENFORCED: live + archived execution count, at row creation |
| `max_workflows_per_minute` (default 10) | Trigger-rate cap | ENFORCED: executions started in the last minute, at row creation |
| `max_fuel_per_hour` | Hourly WASM fuel budget | ENFORCED: sum of `execution_cost_rollup.fuel_consumed` over the last hour, at row creation (refuses the next run; does not stop a running one) |
| `max_llm_tokens_per_day` | LLM token budget | ENFORCED: trailing-24h sum of prompt + completion tokens in `llm_usage`, at row creation; the memory-consolidation and graph-RAG background paths also skip external LLM calls when it is exhausted (fail-open on read error) |
| `max_workflow_count` | Number of workflows bound to the actor | ENFORCED when a workflow is created bound to the actor (`talos-workflow-authorization/src/lib.rs`) |
| `max_fuel_per_execution` | Per-execution fuel ceiling | NOT ENFORCED: stored and returned only; per-execution fuel comes from module/node configuration |
| `max_outbound_requests_per_hour` | Outbound HTTP cap | NOT ENFORCED: stored and returned only |
| `max_compilations_per_hour` (default 20) | Compilation rate | NOT ENFORCED: stored and returned only |
| `on_budget_exceeded` | `suspend` (default) / `alert` / `block` | `suspend` auto-suspends the actor when the hourly pre-check trips; `alert` and `block` behave identically — the request is refused and nothing else happens |

The MCP `set_actor_budget` tool rejects zero, negative and non-integer values for
all nine numeric columns (`talos-mcp-handlers/src/actor.rs`).

### 4.3 RBAC (Role-Based Access Control)

| Role | Source | Permissions |
|------|--------|------------|
| Resource owner | `user_id` on the row | Own workflows, executions, secrets, actors |
| Org `viewer` / `member` / `admin` / `owner` | `organization_members.role` (`talos-auth-types/src/org_role.rs`) | All roles read org resources; `member` and above write; `admin` and `owner` manage members; only `owner` deletes the organization |
| Platform admin | `users.is_platform_admin` | System-wide operations (e.g. `rotateDek`, `reEncryptSecrets`, `verifyAuditChain`), gated by `require_platform_admin` (`talos-api/src/schema/mod.rs`) |
| MCP agent | `allowed_capabilities` on the agent token | `AgentIdentity::is_admin()` is true for a `*` or `admin` capability (`talos-mcp-handlers/src/auth.rs`); it is an agent-capability check, not a user role, and some platform-wide MCP tools additionally require the user's `is_platform_admin` |

### 4.4 Approval Gates

Actor approval policies (`actor_approval_policies`) are evaluated only on a
`publish_version` event today: the `first_workflow_deploy` trigger and custom
Rhai triggers fire there; `new_external_host`, `database_write`, `email_send`
and `new_secret_access` are stored but no code path evaluates them
(`talos-actor-types/src/policy.rs`, `talos-actor-policies/src/evaluator.rs`).

| Policy Mode | Behavior |
|------------|----------|
| `block` | The publish is refused and an approval gate is created (approve/reject URLs); approving does not retry the action. Requires a non-empty approvers list |
| `notify` | Does NOT pause or refuse. Posts to `TALOS_POLICY_NOTIFICATION_WEBHOOK` when configured, otherwise writes a `policy_notification_pending` action-log row. Requires a non-empty approvers list |
| `log` | Action continues; event written to the actor action log. No approvers required |

Execution-level approvals are separate: a pending approval is recorded in
`execution_approvals` (`talos-engine/src/approval_gate.rs`); the `governance`
host function publishes the pending notification on NATS subject
`talos.approvals.pending` and waits on a per-execution NATS reply subject, using
Redis only as key-value storage for reply-subject routing
(`talos-worker-runtime/src/host/governance.rs`). MCP tools
`list_pending_approvals` and `submit_workflow_approval` verify execution
ownership.

---

## 5. Network Security

### 5.1 SSRF Protection

The `check_outbound_url_no_ssrf()` function (`talos-http-utils/src/ssrf.rs`) blocks:

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

It also rejects `127.0.0.0/8`, `0.0.0.0/8`, `100.64.0.0/10` (CGNAT) and
obfuscated IPv4 forms. Any URL not starting with `https://` is rejected, in
every environment.

### 5.2 Rate Limiting Architecture

```
  Request
    |
    v
  Per-IP limiters (governor, in-memory, per controller process;
  keyed on the client IP from the trusted-proxy X-Forwarded-For walk)
  - tower_governor: 10 req/s, burst 20 (production only)
  - Global (one bucket, not per IP): GLOBAL_RATE_LIMIT, default 1000/min
    (production only)
  - API routes: API_RATE_LIMIT, default 100/min
  - Webhook routes: WEBHOOK_RATE_LIMIT, default 60/min
    (API/webhook limiters are skipped outside production unless
     ENFORCE_RATE_LIMITS_IN_DEV is set)
    |
    v
  Auth mutations (login / verifyTwoFactor / refreshToken / signup)
  - 5/min per IP, fixed window in Redis (INCR + EXPIRE);
    fail-closed in production, in-memory fallback in development
    |
    v
  MCP limiters (in-process fixed windows)
  - MCP auth: MCP_AUTH_RATE_LIMIT, default 60 per MCP_AUTH_RATE_WINDOW (60s) per IP
  - Per-user MCP: MCP_USER_RATE_LIMIT_PER_MIN, default 5000/min
  - Per-agent MCP: MCP_AGENT_RATE_LIMIT_PER_MIN, default 1000/min
    |
    v
  Application-level limits
  - Webhook per-trigger: max_requests_per_minute (clamped 1..10000);
    per-user aggregate TALOS_WEBHOOK_USER_RPM, default 300/min (in-memory)
  - API key validation: 60/min per key prefix
  - GraphQL depth: 15, complexity: 5000 (hardcoded)
  - TOTP: 5 attempts, 15-min lockout
  - Refresh token: 10/min per user
```

### 5.3 TLS Requirements

| Connection | Development | Production |
|-----------|-------------|------------|
| Client to Controller | HTTP allowed | HTTPS required (via LB/proxy) |
| Controller to Redis | `redis://` allowed | `rediss://` enforced when `REDIS_URL` is set (panic on violation) |
| Controller to PostgreSQL | Plaintext allowed | Boot refused unless `DATABASE_URL` sets `sslmode=require`, `verify-ca` or `verify-full` (`talos-db/src/lib.rs`) |
| Controller and worker to NATS | Plaintext allowed | Boot refused unless `NATS_URL` is `tls://` or `nats+tls://` (`controller/src/bootstrap/services.rs`, `worker/src/main.rs`) |
| Controller to Neo4j | Plaintext allowed | Boot refused unless `NEO4J_URI` uses `neo4j+s`, `neo4j+ssc`, `bolt+s` or `bolt+ssc` (when set) |
| Controller to Vault | `http://` allowed | `VAULT_ADDR` must be `https://` unless `TALOS_ALLOW_PLAINTEXT_VAULT` is set (`talos-secrets-manager/src/vault_kek_provider.rs`) |
| Outbound webhooks | HTTPS required by SSRF check | HTTPS required by SSRF check |

---

## 6. Audit and Monitoring

### 6.1 Audit Tables

| Table | Purpose | Immutability | DLP |
|-------|---------|-------------|-----|
| S3/MinIO WORM bucket (not a table) | Execution audit ledger: per-job HMAC hash chain written by the worker, verified hourly by the controller sweep (`talos_audit_verification_failures_total`) | Object-store WORM + hash chain; `audit_events` table dropped 2026-09-11 (never written) | n/a |
| `auth_audit_log` | Authentication events: `signup`, `login_success`, `login_failed`, `account_locked`, `token_refresh`, `refresh_token_reuse_detected`, `password_change` (no logout event is written) | Trigger: `trg_auth_audit_log_immutable` | Partial: `user_agent` redacted; `email` and `failure_reason` stored as-is |
| `secret_audit_log` | Secret access events | Trigger: `trg_secret_audit_log_immutable` | Partial: error message redacted; stores `key_hash`, not values |
| `admin_event_log` | Admin action events | Trigger: `trg_admin_event_log_immutable` | Partial: the actor-repository and API-key writers redact summary/details; the ML lifecycle and worker-provisioning-token writers insert without redaction |

All triggers use `prevent_audit_modification()` function: BEFORE UPDATE OR DELETE, raises SQLSTATE 42501 (insufficient_privilege).
The retention cleanup for `auth_audit_log` and `secret_audit_log` checks the
catalog for that trigger first and, when present, issues no DELETE and reports
`ImmutableByPolicy`. The trigger blocks row-level UPDATE/DELETE; it does not
stop a database role that can disable or drop the trigger.

#### 6.1.1 WORM ledger cryptographic verification (finding #2)

The worker emits a per-job, **HMAC-SHA256-signed SHA-256 hash chain**
of audit events (`talos-audit-event`) over `talos.audit.ledger`, buffered in
the `AUDIT_LEDGER` JetStream stream (30-day max age). The
controller-side consumer (`talos-audit-ledger`):

- **Inline, before S3 persist (Layer 1):** recomputes each event's hash and
  verifies it equals the published hash (integrity), and verifies the HMAC
  against the configured keys (authenticity). Events with a hash mismatch or
  a bad signature are **not** persisted to the ledger — they are quarantined
  to an Object-Locked `rejected/` prefix (evidence retained) and logged at
  ERROR. An **unsigned** event is accepted and persisted (logged when keys are
  configured); the offline verifier then reports it as `ChainBreak::Unsigned`,
  which counts as tamper evidence. Persistence is to S3 with Object-Lock
  Compliance (WORM) when enabled.
- **Offline (Layer 2):** `verify_chain` / `verify_execution_chain` re-derive
  the chain over the full ordered record set and detect sequence gaps
  (deletion / never-persisted events), broken `previous_hash` linkage
  (reorder/substitution), genesis mismatch, per-event HMAC failures and
  unsigned events when keys are configured, and check the chain's terminal
  anchor (a removed or rewritten tail whose anchor survives fails; a chain with
  no anchor is reported as unanchored) — the stateful checks that need the
  whole chain and so can't run in the streaming persister.
- **Continuous (Layer 2, wired):** a controller-side background sweep
  (`run_chain_verification_sweep`, interval `AUDIT_CHAIN_SWEEP_INTERVAL_SECS`,
  default 3600s, clamped to 300–86400s; `0` disables) runs the offline verifier
  over jobs (`module_executions`) that reached a terminal state in the recent
  window (a 120s settle floor skips events still batching to S3) and emits one
  structured `audit_chain_verification_failed` ERROR per broken chain plus an
  `audit_chain_sweep_summary` per pass — the SIEM alerting signal. Skips
  when no S3/WORM endpoint is configured; with an endpoint but no
  `AUDIT_VERIFIER_ACCESS_KEY_ID` / `AUDIT_VERIFIER_SECRET_ACCESS_KEY`, it
  reports the chain as unverifiable.
- **On-demand (Layer 2, forensic):** the GraphQL `verifyAuditChain(executionId)`
  query (platform-admin only, via `is_platform_admin`) runs the same verifier
  over the jobs of a single workflow execution and returns the structured break
  list — for investigating a specific alert.

Signing requires `TALOS_AUDIT_SIGNING_KEY` (32+ bytes of effective entropy) on
workers AND the controller; `TALOS_AUDIT_SIGNING_KEY_PREVIOUS` supports rotation
overlap. A missing or weaker key does not stop boot: events are emitted
unsigned, with an ERROR logged in production (`talos-audit-event/src/lib.rs`).

### 6.2 Observability Stack

| Layer | Technology | Metrics |
|-------|-----------|---------|
| Application metrics | Prometheus (`prometheus` crate) | Auth attempts/failures, 2FA and API-key validation outcomes, workflow and module execution counts/duration, rate limit hits, DLQ entries/drops, audit-chain verification failures |
| Distributed tracing | OpenTelemetry (OTLP export) | Per-tenant tracer providers; LRU cache (100 providers); configurable endpoint per user |
| Structured logging | `tracing` crate | Plain-text `fmt` layer in both binaries (no JSON formatter); span context propagation |
| Audit streaming | NATS JetStream | `AUDIT_LEDGER` stream buffers worker audit events for the controller consumer, which verifies HMAC + hash before WORM (S3 Object Lock) persist, quarantining failures to `rejected/`; offline chain verifier for linkage/sequence/genesis/anchor (§6.1.1). Per-tenant export to an external collector is over OTLP |

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
  Macro injection (RE_RUN_FN targets `fn run(`)
  - adds #[talos_sdk_macros::talos_module(world = …)] unless the source
    already carries #[talos_module] / #[talos_node] or wit_bindgen::generate!
       |
       v
  Crate allowlist check
  (DEFAULT_ALLOWED_DEPENDENCIES in talos-compilation/src/dependency_allowlist.rs,
   replaced by MCP_ALLOWED_CRATE_DEPENDENCIES,
   extended by MCP_ALLOWED_CRATE_DEPENDENCIES_EXTRA)
  - reqwest explicitly blocked (wasm-bindgen incompatible)
  - Only pre-approved crates allowed
       |
       v
  cargo-audit gate
  (Reject modules with known vulnerable dependencies)
       |
       v
  Containerized compilation (Podman, else Docker)
  - on by default in production (TALOS_COMPILATION_CONTAINER); a host
    compile in production needs the host-fallback ack token
  - --network=none, --read-only, --cap-drop=ALL, no-new-privileges
  - --memory / --cpus / --pids-limit, non-root user
       |
       v
  WASM binary output
  - Component model magic check (8 bytes)
  - wasm32-wasip1 vs wasip2 detection
       |
       v
  Store compiled module
  (`modules` table with capability_world)
```

The generated `run` wrapper contains `catch_unwind`, but it is unreachable on
wasm32-wasip2 (panic = abort); guest panics are recovered host-side from WASI
stderr (`talos_sdk_macros/src/lib.rs`).

### 7.2 Pre-bundled Crates

The compilation pipeline pre-bundles certain crates to avoid duplicate key errors:
- `serde`
- `serde_json`
- `wit-bindgen`
- `wit-bindgen-rt`
- `talos_sdk_macros` / `talos-sdk-macros`

These are skipped during user dependency resolution.

---

## 8. Data Classification

| Classification | Examples | Storage | Access |
|---------------|----------|---------|--------|
| Critical | KEK (master key) | Vault transit (`KEK_PROVIDER=vault`, chart default) — never enters controller memory. `TALOS_MASTER_KEY` env var (`KEK_PROVIDER=env`, code default; refused in production unless `TALOS_ALLOW_ENV_KEK` is set). | Vault transit token / controller process |
| Secret | User secrets, OAuth tokens, signing keys, **actor memory**, **module-execution payloads**, **workflow-execution outputs** | AES-256-GCM in PostgreSQL under per-context HKDF subkeys of a per-org (or global) DEK, which is wrapped by the KEK | Per-module allowlist; per-actor LLM tier ceiling for LLM payloads |
| Sensitive | Admin events (`admin_event_log`), audit logs | PostgreSQL append-only (DLP-redacted on most writers, intentionally NOT envelope-encrypted to preserve query-ability for incident triage — see runbook §1.2) | Authenticated + authorized |
| Internal | Workflow definitions, module source code, WASM bytes | PostgreSQL | Owner + org members |
| Public | Health check, API schema (dev only) | N/A | Unauthenticated |

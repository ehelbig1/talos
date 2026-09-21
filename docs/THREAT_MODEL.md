# Talos Platform STRIDE Threat Model

**Version:** 2.1
**Date:** 2026-09-16 (v2.0: 2026-04-09)
**Methodology:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
**Scope:** All externally reachable and internally critical attack surfaces
**Classification:** CONFIDENTIAL -- share only with authorized auditors and pentest firms.

**Revision 2.1 (2026-09-16).** Every claim in v2.0 was re-checked against the
code at this date and corrected where the code disagreed (MCP authentication,
API-key lookup, Rhai limits, audit-table count, DLP coverage, rate limits,
pagination, admin-tool gating, WASM resource defaults, secret-slot lifecycle,
job-envelope key derivation, SQL compile-time checking, master-key storage).
The separate v1.0 model (`docs/security/threat-model.md`, 2026-04-08) was merged
into this document on the same date: its trust-boundary table, Redis analysis,
compilation-injection analysis and risk matrix are carried here after the same
re-verification, and where v1.0 and v2.0 contradicted each other this document
states what the code does. `docs/security/threat-model.md` is now a pointer to
this file.

---

## 1. System Architecture

Talos is a workflow automation platform with user-submitted WASM module execution.

| Component | Role | Source |
|-----------|------|--------|
| Controller | Rust/Axum API server (GraphQL, REST, MCP JSON-RPC, webhooks). Holds the Postgres, Neo4j and KEK-provider credentials and serves the worker's data-plane RPCs. | `controller/` |
| Worker | Rust WASM runtime (wasmtime, sandboxed execution). Credential-free: no Postgres connection; data access goes through signed NATS-RPC to the controller. | `worker/` |
| PostgreSQL | Primary data store (workflows, secrets, sessions, audit tables, executions) | `migrations/` |
| Redis | Distributed auth rate limiting, TOTP replay prevention, webhook / push deduplication and idempotency keys, WASM module-bytes cache, envelope-sealing claim leases, the pending approval's reply-topic key. Not a session store (sessions and refresh tokens live in PostgreSQL `user_sessions`). Approval responses are published over NATS, not Redis pub/sub. | Controller and worker connect via `REDIS_URL` |
| NATS | Job dispatch is **core-NATS signed request/reply** (controller pre-allocates a reply inbox; queue-group workers reply; the controller retries on timeout — controller-driven redelivery, NOT a durable JetStream work queue). **JetStream** backs the tamper-evident audit-event ledger. The worker's data-plane calls (memory, graph, database, state, ML) are signed NATS-RPC to the controller. | `talos-workflow-job-protocol` (in-workspace) |
| Frontend | React/TypeScript visual workflow editor (untrusted client) | `frontend/` |

---

## 2. Trust Boundaries

```
  +-----------------+       HTTPS/WSS        +--------------------+
  | Browser / CLI   | ---------------------> |    Controller      |
  | (untrusted)     | <--------------------- |    (Rust/Axum)     |
  +-----------------+  JWT cookie + CSRF, or +---+-----+------+---+
                       API key / MCP token       |     |      |
                                                 |     |      | NATS (signed jobs;
                        TLS (prod)               |     |      |  signed data-plane RPC)
            +------------------------------------+     |      +-----------------+
            |                                          |                        |
      +-----v------+                            +------v-----+           +------v------+
      | PostgreSQL |                            |   Redis    |<--------- |   Worker    |
      | (secrets,  |                            | (limiter,  |  rediss   | (wasmtime,  |
      |  sessions, |                            |  dedup,    |  (prod)   |  no DB      |
      |  audit)    |                            |  caches)   |           |  creds)     |
      +------------+                            +------------+           +------+------+
                                                                                |
                                                                         WASM sandbox
                                                                         +------v------+
                                                                         | WASM Guest  |
                                                                         | (untrusted  |
                                                                         |  user code) |
                                                                         +-------------+
```

### Boundary Definitions

| ID | Boundary | From | To | Transport / control |
|----|----------|------|----|-----------|
| B1 | Internet edge | Browser/CLI | Controller | HTTPS, terminated at the ingress. No minimum TLS version is configured in this repository; the ingress controller's defaults decide. |
| B2 | Controller-to-DB | Controller | PostgreSQL | Production refuses to boot unless `DATABASE_URL` sets `sslmode=require`, `verify-ca` or `verify-full` (`talos-db/src/lib.rs`) |
| B3 | Controller / worker to Redis | Controller, Worker | Redis | Production requires `rediss://`: the controller panics at boot and the worker exits on a `redis://` URL (`controller/src/bootstrap/services.rs`, `worker/src/main.rs`) |
| B4 | Controller-to-NATS | Controller | NATS (core for jobs; JetStream for audit ledger) | Production refuses to boot unless `NATS_URL` is `tls://` or `nats+tls://` (controller and worker) |
| B5 | NATS-to-Worker | NATS | Worker | TLS (production) + signed `JobRequest` (HMAC-SHA256, or Ed25519 with `TALOS_DISPATCH_SCHEME=ed25519`). The worker's own NATS credential has a subscribe allow-list (`deploy/nats/worker-permissions.conf`, rendered from `talos-workflow-job-protocol/src/nats_permissions.rs`). |
| B6 | Worker-to-WASM | Worker host | WASM guest | wasmtime sandbox (capability worlds) |
| B7 | Webhook ingress | External service | Controller `/webhooks/{id}` | HTTPS + per-trigger HMAC signature or static verification token |
| B8 | Worker-to-controller data plane | Worker | Controller | Signed NATS-RPC: HMAC-SHA256 over `(subject, actor_id, nonce, body)`, nonce replay cache, 60 s past / 5 s future freshness window (`talos-memory/src/rpc_auth.rs`). Controller replicas bind these subjects in one NATS queue group (`talos-rpc-subscribers/src/kernel.rs`), so a request is delivered to one replica; the Redis cross-replica replay guard then only ever sees a genuine replay |

---

## 3. Attack Surface 1: MCP JSON-RPC Interface

The MCP endpoint exposes several hundred static tools (the count is computed at
runtime by `talos-mcp-handlers/src/lib.rs::static_tool_count` and rendered in the
server instructions) plus dynamically registered catalog-template tools, via JSON-RPC over SSE and
Streamable HTTP transports.

### Spoofing
- **Threat:** Unauthenticated tool invocation; forged agent identity.
- **Mitigation:** MCP requests authenticate with an **opaque per-agent bearer token**, not a JWT. The token is read from the `Authorization: Bearer` header or a `?token=` query parameter; the controller computes its SHA-256 (`token_lookup_hash`) to find the active `mcp_agents` row, then verifies the token against the row's bcrypt hash. A verified identity is cached for 10 s (`BCRYPT_CACHE_TTL_SECS`). The resulting `AgentIdentity` carries the agent's `allowed_capabilities`. Every request is rate-limited per IP before the token is checked (`MCP_AUTH_RATE_LIMIT`, default 60 per `MCP_AUTH_RATE_WINDOW`, default 60 s) and counted on `talos_mcp_auth_total{outcome}`. A revoked token (`is_active = false`) is indistinguishable from an unknown one. REST/GraphQL **API keys** are a separate credential: `talos_sk_`-prefixed, scoped (`workflows:read`, `workflows:write`, `secrets:read`, `secrets:write`, `webhooks:access`, `admin`), stored as a bcrypt hash (cost `API_KEY_BCRYPT_COST`, default 12), and looked up by their plaintext 8-hex `key_prefix` column before the bcrypt verify — API keys have no SHA-256 lookup hash.
- **File:** `talos-mcp-handlers/src/auth.rs`, `talos-api-keys/src/lib.rs`, `talos-auth-types/src/scope.rs`

### Tampering
- **Threat:** Manipulated tool parameters bypass validation (e.g., negative `max_depth`, float `timeout_secs`).
- **Mitigation:** Per-parameter validation with explicit rejection (not silent clamping) on the numeric fields that have been hardened: `fract() != 0.0` float guards, positivity checks, bounds validation. Input size caps where implemented: 1 MB (1,048,576 bytes) on test/replay payloads; 2,000 characters on a node `skip_condition`, an edge `condition` and an approval-policy `trigger_condition` (Rhai). The GraphQL `testRhaiExpression` query caps a script at 100 KB. There is no 10 KB Rhai cap.
- **File:** `talos-mcp-handlers/src/workflows.rs`, `talos-mcp-handlers/src/graph.rs`, `talos-mcp-handlers/src/actor.rs`

### Repudiation
- **Threat:** Admin invokes destructive operations (delete workflow, modify secrets) without audit trail.
- **Mitigation:** Audit ledger with HMAC-signed events and hash chains. The WORM consumer **verifies the per-event HMAC and recomputes the event hash inline before S3 persist**, quarantining failures to a `rejected/` prefix (not silently dropped); those objects — like the ledger objects — are written with S3 Object Lock (Compliance mode, `TALOS_AUDIT_S3_RETENTION_DAYS`, default 2555 days) **only when `TALOS_AUDIT_S3_OBJECT_LOCK=true`**. The production read path, `verify_execution_chain`, runs `verify_chain_anchored`, which checks sequence contiguity, `previous_hash` linkage, genesis and the chain's terminal anchor (finding #2). Immutability triggers on the PostgreSQL audit tables refuse UPDATE, DELETE and TRUNCATE (the table list is in §8, Tampering). `admin_event_log` records administrative lifecycle events from its writers (workflow, module, actor, ML-model, API-key, MCP-agent and similar changes); it is not an exhaustive record of every administrative call. Credential and privilege changes (API keys, 2FA, capability grants, MCP agents, actor ceilings, module permissions, workflow actor binding, module capability world) are recorded in the same transaction as the change, with the value each replaced, so one of them cannot happen without its record.
- **Two identities, and the separation is load-bearing.** The audit bucket has a
  WRITER and a VERIFIER and they must not be the same principal:
  - **Writer** — `MINIO_CONTROLLER_USER`, policy `audit_write_only`
    (`s3:PutObject` on `audit-logs/*` and nothing else), reaching the controller
    as `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`. A writer that can also list
    and get is a writer that can survey and target what it wrote.
  - **Verifier** — `MINIO_VERIFIER_USER`, policy `audit_read_only`
    (`s3:ListBucket` on the bucket + `s3:GetObject` on its objects; NO Put, NO
    Delete), reaching the controller as `AUDIT_VERIFIER_ACCESS_KEY_ID` /
    `AUDIT_VERIFIER_SECRET_ACCESS_KEY`. The chain-verification sweep (every
    `AUDIT_CHAIN_SWEEP_INTERVAL_SECS`, default 3600 s, clamped to 300–86400 s,
    `0` disables it) and the on-demand admin `verifyAuditChain` query build
    their S3 client from these EXPLICITLY — there is no `AWS_*` fallback,
    because `AWS_*` is the write-only writer.
  Until 2026-09-06 both read paths borrowed the writer's key. Measured on the
  dev stack that day: the bucket held 48,946 execution prefixes written since
  2026-07-08, the sweep logged 37 unverifiable executions in one hour, and the
  controller's entire history contained ZERO verified chains — every
  `list_objects_v2` came back AccessDenied. **The mitigation above was written
  and never functioned**, and no counter, alert or audit check could say so.
  With the verifier absent the sweep now refuses to start, logs one
  `audit_chain_verifier_identity_missing` ERROR, increments
  `talos_audit_chain_unverifiable_total{reason="no_credentials"}`, and
  `security_audit`'s `audit_chain_verification` check reports the control as
  non-functional rather than reporting nothing.
- **The ledger is keyed PER JOB, and every reader now names that id space.**
  A chain exists per MODULE DISPATCH, not per workflow execution: the worker
  builds `ExecutionLedger::new_for_attempt(req.workflow_execution_id, req.job_id,
  dispatch_attempt)` (through `build_job_ledger`), `job_id` IS
  `module_executions.id`, and the S3 object key is
  `<module_executions.id>/<min>_<max>_<nanos>.jsonl`. The genesis hash binds
  BOTH ids, so naming the wrong `workflow_id` is a reported break rather
  than a near miss. Measured live 2026-09-06, both directions: 200 of 200
  newest ledger prefixes resolve to a `module_executions` row and 0 to a
  `workflow_executions` row; 200 of 200 recent settled module executions have a
  non-empty prefix and 0 of 200 recent workflow executions do. Driving the real
  verifier with read-capable credentials, the pair
  `(module_executions.workflow_execution_id, module_executions.id)` returns
  `ok=true total_events=1`, `(workflows.id, module_executions.id)` returns
  `ok=false breaks=1`, and the pre-fix sweep's own shape returns `ok=true
  total_events=0`. That last one is the trap: **`verify_chain` over an empty
  event set answers `ok == true`**, so repairing the identity alone would have
  converted 37 loud AccessDenied warnings into 37 silent verifications of
  nothing. The sweep, `security_audit`'s round-trip check and the admin
  `verifyAuditChain` query all enumerate `module_executions`; the sweep and the
  GraphQL query roll their per-job outcomes up to the workflow execution an
  operator asks about, worst outcome wins, and neither reports `ok` from an
  empty job set.
- **Truncation is only partly detectable.** The anchored verifier hard-fails a
  chain whose terminal anchor survives and disagrees with the events (records
  removed, a rewritten count, records appended after completion, multiple
  anchors). A deletion of the tail that INCLUDES the anchor leaves a chain
  indistinguishable from a pre-anchor chain; that verdict is `Unanchored`, a
  soft outcome the sweep counts separately
  (`talos_audit_chain_jobs_swept_total{outcome="unanchored"}`) and reports as a
  finding, but which does not fail the chain.
- **An EXACT REDELIVERY is deduped at write and tolerated at verify; a
  CONFLICTING one is still tamper evidence.** At-least-once is the transport's
  contract, so the same signed event can reach the ledger twice, and until
  2026-09-07 the verifier reported that as `DuplicateSequence` under "possible
  tampering, deletion, reorder, or corruption". Two duplicate kinds, and only
  one of them says anything about integrity:
  - **Byte-identical** (same `sequence_num`, same recomputed hash, same HMAC) —
    one event that arrived twice. Nothing altered, added or removed. The WRITER
    drops the surplus copy inside a batch (`talos_audit_ledger::batch_dedupe`,
    counting `talos_audit_ledger_duplicate_deliveries_total{scope="batch"}`) and
    the VERIFIER reports `ChainBreak::DuplicateDelivery`, which does not clear
    `ok`, is not counted in the sweep's `failed`, and pages nobody. Chain
    continuity is computed over the deduped sequence.
  - **Conflicting** (one sequence, two contents) — a substitution. Still
    `ChainBreak::DuplicateSequence`, still `ok == false`, still CRITICAL.
  The split is not symmetric on purpose: the writer can only dedupe copies that
  share a batch, because its S3 identity is **write-only by design** and reading
  the prefix back to find an earlier copy would hand a compromised writer the
  whole audit trail. Cross-batch copies are therefore classified at the reader,
  where the read-only verifier identity already belongs.
  Measured 2026-09-07: 196 of 49,461 job prefixes carried more than one terminal
  anchor; 35 byte-identical, 161 conflicting. The conflicting majority was a
  PRODUCER defect, not a transport one — the worker's in-process retry loop
  built a fresh `ExecutionLedger` per attempt and anchored each, so every
  attempt emitted an `execution_complete` event claiming `sequence_num` 1.
  Attempts now share one ledger and the job is anchored once, so the chain is
  one monotonic sequence over the whole job. Note the residual: the anchor is
  one per DISPATCH, and a controller-level retry re-dispatches the same
  `job_id`; reconstructing a prior dispatch's ledger would need persisted state
  the credential-free worker cannot read.
- **A JOB IS ONE CHAIN PER CONTROLLER DISPATCH ATTEMPT.** That residual is now
  closed at the source rather than at the verifier. `JobRequest.dispatch_attempt`
  (default 0, bound into the job signature by conditional append so an all-default
  dispatch is byte-identical on the wire and in its MAC) tells the credential-free
  worker which dispatch it is running; the worker stamps it on every `AuditEvent` it
  appends (also conditional, so an attempt-0 event's hash and HMAC are byte-for-byte
  what they were before the field existed and every object already in the bucket
  keeps verifying), and the verifier PARTITIONS a prefix by attempt and
  verifies each partition as its own chain **from the same genesis** — the
  attempt is a partition key, never a genesis input, so old and new chains share
  one rule. Within one attempt `DuplicateDelivery` and `DuplicateSequence` keep
  the meanings above. The attempt is bound both ways: stripping it re-merges two
  dispatches and manufactures a false `DuplicateSequence`; forging one splits a
  tampered chain into partitions that each verify — both fail signature
  verification. Two sites set the attempt: the dispatcher's first send stamps
  `DispatchJob::dispatch_attempt_base` (0 for an ordinary dispatch; the OAuth
  credential-repair re-dispatch of the same `job_id` starts from
  `redispatch_attempt_base()` so it cannot collide with the first dispatch's
  retries), and `resign_payload_for_retry` stamps each retry counting up from
  that base. Disclosed, never silent: the sweep reports
  `jobs_with_multiple_attempts`, `security_audit`'s round-trip check names the
  attempt count on the chain it probed, the GraphQL job report carries
  `dispatchAttempts`, and `talos_audit_chain_multi_attempt_jobs_total` is
  pre-seeded at 0. Nothing alerts on it — a retry is the platform working.
  **Deploy ordering: workers roll first or together.** Attempt 0 is
  byte-identical so first dispatches are unaffected in both directions, but a new
  controller's RETRY is signed over `:attempt=n`, which an old worker's signing
  payload cannot reproduce — it refuses the retry (fail-closed, bounded to the
  width of the rollout).
  **Historical prefixes carry no attempt on either copy, so they partition into
  one attempt and stay CONFLICTING**; they age out of the sweep's lookback
  window (2 × the sweep interval: 2 h at the default).
- **File:** `talos-audit-event/src/lib.rs` (shared chain/HMAC, `verify_chain`, `verify_chain_anchored`, the duplicate classification, the per-attempt partition), `talos-audit-ledger/src/lib.rs` (consumer, inline verify, `batch_dedupe`, `verify_execution_chain`, Object Lock config), `talos-audit-ledger/src/verifier.rs` (the read-only identity and the failure classification), `talos-workflow-engine-nats/src/dispatcher.rs` (`resign_payload_for_retry` and the first-send attempt base), `talos-workflow-engine-core/src/dispatcher.rs::redispatch_attempt_base`, `talos-worker-runtime/src/runtime.rs` (`build_job_ledger`, `seal_job_audit_chain`), `controller/src/bootstrap/background.rs` (sweep interval and lookback)

### Information Disclosure
- **Threat:** Tool responses leak internal errors, stack traces, or secret values.
- **Mitigation:** Generic error messages returned to clients; full errors logged server-side only. MCP is read-only for secrets and no tool returns a plaintext secret value. DLP redaction (`talos_dlp_provider::redact_json` / `redact_str`) is applied at persistence boundaries such as module-execution input/output before it is stored. **DLP is NOT applied to WORM audit-ledger events**: the consumer persists the signed event bytes verbatim (event payloads can carry, for example, the guest's raw SQL text), and only the OTLP span copy of each event is passed through `talos_trace::redact_span_text`. Every `admin_event_log` writer goes through `talos-admin-event-log`, which DLP-redacts `summary` and `details` before insert (since 2026-09-17; structural lint check 94 keeps the INSERT there).
- **File:** `talos-dlp-provider/src/lib.rs`, `talos-engine/src/module_execution_store.rs`, `talos-audit-ledger/src/lib.rs`, `talos-trace/src/lib.rs::redact_span_text`, `talos-worker-runtime/src/host/database.rs`, `talos-worker-identity-repository/src/lib.rs`, `talos-ml/src/lifecycle_job.rs`

### Denial of Service
- **Threat:** Rapid tool invocation exhausts server resources; unbounded pagination.
- **Mitigation:** Per-IP API rate limit `API_RATE_LIMIT` (code default 100 requests/min, burst `max(limit/5, 10)`; the Helm chart sets 1000) and a global limit `GLOBAL_RATE_LIMIT` (code default 1000/min; chart 10000). Both are **in-memory per controller replica** (governor), so N replicas admit N× the rate. The per-IP limiter is **disabled outside production** unless `ENFORCE_RATE_LIMITS_IN_DEV` is set; the global limiter always runs. Only the authentication limiter (5 requests/min per IP, burst 2) is Redis-backed and shared across replicas, and it **fails closed in production** when Redis is unreachable. MCP token authentication has its own per-IP limiter (see Spoofing). List tools use `limit`/`offset` pagination with per-tool maximums; there is no cursor pagination except in the platform-admin `query_paginated` tool, which offers keyset pagination.
- **File:** `talos-rate-limit/src/middleware.rs`, `controller/src/bootstrap/services.rs`, `talos-mcp-handlers/src/advanced.rs`

### Elevation of Privilege
- **Threat:** Non-admin user invokes admin-only tools (e.g., `set_wasm_config`, `publish_built_in_templates`).
- **Mitigation:** Deployment-wide admin tools (`set_wasm_config`, `publish_built_in_templates`, `query_paginated`, `set_archive_policy`, `security_audit` and others) check the caller's `users.is_platform_admin` column in each handler; the agent-level `AgentIdentity::is_admin()` capability is no longer consulted for them. Agent `allowed_capabilities` filter only the dynamically registered catalog-template tools in `tools/list`; the static tools are listed to every authenticated agent, and data access is bounded by per-user tenancy scoping and the actor ceilings (capability world, LLM tier, write ceiling, egress scope).
- **File:** `talos-mcp-handlers/src/platform.rs`, `talos-mcp-handlers/src/advanced.rs`, `talos-mcp-handlers/src/lib.rs`, `talos-mcp-handlers/src/actor.rs`

---

## 4. Attack Surface 2: GraphQL API

### Spoofing
- **Threat:** Stolen JWT replayed to impersonate user; credential brute force; stolen API key.
- **Mitigation:** Access-token JWT with 15-min TTL, issuer and audience validation (`talos`), refresh-token rotation (refresh TTL 7 days; the rotated token's lookup hash is recorded in `rotated_session_audit` so a replay is detectable). A replay past a 5-second tab-race grace window revokes every session for the affected user, writes an `auth_audit_log` row and counts on `talos_auth_token_reuse_total{outcome}`, alerted at `critical` — and a failure of the detector's own read is reported as `detector_unreadable` rather than as no-reuse, with `talos_auth_rotation_audit_arm_total{outcome}` saying whether each rotation armed the detector at all. Before 2026-09-21 this control's only output was a single log line on a tracing target with no subscriber, and its read was written so that a database failure and "no reuse record" were one branch: on a blip the response silently did not run. Signing algorithm `JWT_ALGORITHM`: HS256 by default (`JWT_SECRET` must be at least 32 bytes), RS256 or ES256 with a key pair. Session cookies are HttpOnly and SameSite=Strict always, and `Secure` only when running in production. Login: password length 12–72 characters with at least 2 of 4 character classes, bcrypt hashing (`BCRYPT_COST`, 10–14), account lockout for 15 minutes after 5 failed attempts (login and password change share one counter), auth-endpoint rate limit 5/min per IP. A signed-in user changes their password with the current password (`changePassword`; never an API key, never a pending session, and with 2FA enrolled only from a session that verified it), and the change signs out every session in the same transaction as the new hash and its audit row. An account with no password (OAuth sign-up, synthetic MCP-agent users, the local dev user) stores bcrypt of 32 CSPRNG bytes nobody holds (`talos-unusable-password/src/lib.rs`); until 2026-09-18 OAuth sign-ups stored bcrypt of a fixed public string that DID verify, so login and password choice refuse that string for rows written before. TOTP 2FA: seed stored encrypted, constant-time code comparison over the previous/current/next step, one-time use enforced with Redis `SET NX EX 90` (2FA login fails closed in production without Redis), lockout for 900 s after 5 failed codes (shared across replicas through Redis; production refuses the code check when Redis is unreachable or not configured, and the in-memory counter is the development fallback). API keys: see §3 Spoofing; the `talos_sk_` prefix is compared in constant time.
- **Step-up for privileged operations:** a stolen password alone, or a stolen API key, cannot rotate keys, run the re-encryption sweeps, mint API keys or MCP agents, grant capability ceilings, change audit settings or transfer ownership: those require a session whose second factor was verified (`second_factor_verified`, recorded per session and carried across refresh) and is still enrolled. Enabling 2FA signs out every earlier session, so a refresh token stolen before enrolment stops working.
- **File:** `talos-auth/src/lib.rs`, `talos-api/src/schema/auth/mod.rs`, `talos-totp-2fa/src/lib.rs`, `talos-api-keys/src/lib.rs`, `talos-api/src/schema/mod.rs`

### Tampering
- **Threat:** CSRF on mutation endpoints.
- **Mitigation:** Double-submit cookie pattern with constant-time comparison (`constant_time_eq`). SameSite=Strict. CSRF token rotation after each mutation.
- **File:** `talos-csrf/src/lib.rs`

### Information Disclosure
- **Threat:** Schema introspection reveals internal types and fields.
- **Mitigation:** Introspection disabled in production via `Schema::build(...).disable_introspection()` gated on `config::is_production()`. Password hashes never returned. `[REDACTED]` in Debug impl for sensitive types.
- **File:** `controller/src/bootstrap/services.rs` (search for `disable_introspection`)

### Denial of Service
- **Threat:** Deeply nested or high-complexity queries exhaust CPU/memory.
- **Mitigation:** Query depth limit 15; complexity limit 5000 (both hardcoded); per-IP and global rate limiting as in §3. Input caps: `testRhaiExpression` scripts 100 KB; test-workflow mock inputs 1,000,000 bytes.
- **File:** `controller/src/bootstrap/services.rs`, `talos-api/src/schema/workflows/queries.rs`, `talos-api/src/schema/workflows/mutations.rs`

### Elevation of Privilege
- **Threat:** User accesses another user's workflows via GraphQL.
- **Mitigation:** Resolvers scope reads and writes to the authenticated user (application-layer predicates), and tenant tables are read inside user- or org-scoped transactions (`begin_user_scoped` / `begin_org_scoped`) that set the RLS context. PostgreSQL RLS is enforced only when `TALOS_RLS_SET_ROLE` is on (default off); a production boot refuses to start when RLS would not be effective unless `TALOS_ALLOW_RLS_DISABLED` acknowledges it. That every resolver carries an owner predicate is enforced by structural lints and review, not proven exhaustively here.
- **File:** `talos-api/src/schema/workflows/queries.rs`, `talos-db/src/lib.rs`

---

## 5. Attack Surface 3: Webhook Ingestion Endpoints

### Spoofing
- **Threat:** Forged webhook payloads trigger unauthorized workflow executions.
- **Mitigation:** Per-trigger signing secrets (stored encrypted) with HMAC-SHA256 verification and constant-time comparison (`subtle::ConstantTimeEq`), in three formats: Slack (`X-Slack-Signature` over `v0:<timestamp>:<body>`), GitHub (`X-Hub-Signature-256` over the body alone) and generic (`X-Signature` over `<timestamp>.<body>` with `X-Webhook-Timestamp`). A trigger without a signing secret authenticates with a static `X-Verification-Token` (constant-time compare; no signature). When a signing secret is configured but cannot be decrypted, the request is refused rather than downgraded to the static token.
- **File:** `talos-webhooks/src/signature.rs`, `talos-webhooks/src/router.rs`

### Tampering
- **Threat:** Replay of previously valid webhook payloads.
- **Mitigation:** Slack and generic formats reject a timestamp more than 300 s (±5 min) from the controller clock, and the timestamp is inside the signed bytes. **The GitHub format has no timestamp window**: its only replay defence is Redis deduplication keyed on the verified signature, with a 24-hour window (`GITHUB_DEDUP_WINDOW_SECS`; every other format holds its claim for 1 hour, `DEDUP_WINDOW_SECS`), and GitHub-format requests are refused outright when deduplication (Redis) is not configured OR when the deduplication backend errors. A captured GitHub-format delivery can therefore be replayed after 24 hours. **That horizon is also a redelivery blackout**: the GitHub fingerprint is `HMAC(secret, body)`, deterministic in the body, and GitHub's manual *Redeliver* re-sends the same body, so a legitimate redelivery is indistinguishable from a replay in every authenticated field and is suppressed (200, nothing dispatched) for the same 24 hours — counted on `talos_webhook_duplicate_suppressed_total{format="github"}`. Static-token triggers deduplicate on the body hash only.
- **File:** `talos-webhooks/src/signature.rs`, `talos-webhooks/src/router.rs`

### Denial of Service
- **Threat:** Webhook flooding overwhelms execution queue.
- **Mitigation:** Per-trigger rate limiting (`max_requests_per_minute`). Circuit breaker that counts authentication failures (invalid signature, invalid verification token, IP not allowed) per source IP. IP allowlist per trigger. Dead letter queue (DLQ) for dispatch failures.
- **File:** `talos-webhooks/src/router.rs`, `talos-webhooks/src/rate_limiter.rs`

### Elevation of Privilege
- **Threat:** SSRF via user-configured webhook URLs (controller makes outbound requests to attacker-controlled URLs).
- **Mitigation:** `check_outbound_url_no_ssrf()` requires `https://` and blocks loopback, RFC1918, link-local, IPv6 ULA, cloud metadata endpoints (169.254.169.254, metadata.google.internal), IPv4-mapped IPv6 forms of those, and non-canonical IPv4 encodings. **DNS rebinding is closed at connect time** for clients built by `build_outbound_webhook_client[_with_timeout]`: `ControllerSsrfResolver` re-applies the private-IP filter to the addresses actually resolved (lint check 40 requires files calling the SSRF check to use that client).
- **File:** `talos-http-utils/src/ssrf.rs`, `talos-http-utils/src/outbound.rs`

---

## 6. Attack Surface 4: WASM Module Execution (User-Submitted Code)

This is the highest-risk attack surface. Users submit arbitrary Rust source code that compiles to WASM and runs on the worker.

### Spoofing
- **Threat:** Malicious module impersonates a trusted catalog module.
- **Mitigation:** Module UUIDs are server-assigned. Catalog modules are system-owned (user_id IS NULL). User-installed modules are scoped to user. The worker refuses WASM bytes loaded from cache, Redis or filesystem whose SHA-256 does not match the signed `expected_wasm_hash`, and in production refuses such bytes when no hash was supplied and they were not attested in the same run.
- **File:** `worker/src/main.rs`, `talos-worker-runtime/src/module_fetcher.rs`

### Tampering (compilation injection and supply chain)
- **Threat:** Supply-chain attack via malicious dependency in user code; user source that escapes the build (proc-macros and `build.rs` run at compile time).
- **Mitigation:** Crate allowlist enforcement (only pre-approved dependencies compile; `reqwest` is not on the allowlist). `cargo-audit` gate against a baked advisory database rejects known-vulnerable crates. Containerized compilation (podman preferred, docker otherwise) with `--network=none`, a read-only root, memory/CPU limits and a pids limit. Container mode defaults to ON only in production (`TALOS_COMPILATION_CONTAINER` unset ⇒ `is_production()`); In production a host compile — whether `TALOS_COMPILATION_CONTAINER=false` turned container mode off or no runtime was found — is refused unless `TALOS_COMPILATION_ALLOW_HOST_FALLBACK=acknowledge-single-tenant-rce-risk` (see §13); outside production `TALOS_COMPILATION_CONTAINER=false` compiles on the host. Macro injection targets `fn run(` specifically, preserving user helper functions.
- **File:** `talos-compilation/src/dependency_allowlist.rs`, `talos-compilation/src/container.rs`, `talos-compilation/src/lib.rs`

### Information Disclosure
- **Threat:** Module reads secrets beyond its allowlist; exfiltrates via HTTP.
- **Mitigation:** Per-module `allowed_secrets` (column on `modules`) with deny-all default; LLM provider key paths are denied to guests even with `allowed_secrets: ["*"]`. Vault slot handles (opaque `SlotHandle(u64)`) cross the WASM boundary, not raw values. The `SecretProvider` has three auditable plaintext-use methods — `into_auth_header`, `sign` (HMAC with the slot's key) and `decrypt` (not supported by the in-process provider) — and the WIT `expose-secret` function returns plaintext to the guest only for a module with `allow_tier2_exposure: true`, which every engine dispatch path sets to `false`. A slot older than 300 s (`DEFAULT_MAX_SLOT_AGE_SECS`) is **rejected on use**; slots are not auto-released — `release()` is explicit and the per-execution provider is dropped with the execution. Recording: guest `get-secret` and `expose-secret` calls are appended to the WORM ledger (`wasi:secrets_get`, `wasi:secrets_expose`); host-side credential uses (vault header substitution, LLM keys, email API key) are ledgered as `wasi:secret_use` with the SHA-256 of the key path and the destination, once per (surface, key, destination) per execution up to 64 entries; PostgreSQL `secret_audit_log` records controller-side secret operations (secret id, action, actor, module, timestamp — no key path).
- **File:** `talos-secrets/src/provider.rs`, `talos-secrets/src/talos_vault.rs`, `talos-worker-runtime/src/host/secrets.rs`, `talos-worker-runtime/src/context.rs`

### Denial of Service
- **Threat:** Module runs infinite loop or allocates unbounded memory; guest panics.
- **Mitigation:** Fuel-based instruction metering: an engine-dispatched node gets its `max_fuel` override or the module's `modules.max_fuel` (column default 2,000,000), raised by any learned ceiling and capped at `DEFAULT_MAX_FUEL_PER_NODE` (50,000,000); the worker additionally clamps to `TALOS_WORKER_MAX_JOB_FUEL`, and a job carrying no fuel value falls back to `WASM_FUEL_LIMIT` (default 10,000,000). Wall-clock timeout: a node without `timeout_secs` gets `WASM_EXECUTION_TIMEOUT_SECS` or 120 s; per-node `timeout_secs` values are not clamped; the default workflow budget is 300 s. Memory: a single-node NATS job runs with a 128 MiB limit (set in the worker's dispatch call, not read from `modules.max_memory_mb`), and with the default pooling allocator every linear memory is capped at 128 MiB. `set_wasm_config`'s 5–300 s and 16–512 MB ranges are input bounds on advisory defaults, not runtime clamps. Panics: wasmtime component compilation runs under `guard_codegen_panic` so a codegen panic fails the job, not the worker; guest panics are captured from WASI stderr and surfaced as an error.
- **File:** `talos-workflow-engine/src/engine_config.rs`, `talos-workflow-engine/src/engine.rs`, `talos-workflow-engine-core/src/retry.rs`, `talos-worker-runtime/src/runtime.rs`, `worker/src/main.rs`

### Elevation of Privilege
- **Threat:** Module accesses host functions beyond its capability world (e.g., filesystem, network, governance).
- **Mitigation:** 12 actor-ceiling worlds (11 compilable plus the actor-only `llm-node`) ordered as a documented partial order and compared with `ceiling_permits`; tests pin specific comparable and incomparable pairs rather than proving the order axioms. Default `minimal-node` grants zero host access. Only two internal capability worlds (Filesystem and Trusted) receive a WASI filesystem preopen; all others receive none. Granting a ceiling to another user requires `users.is_platform_admin`, and a granter cannot grant a world their own ceiling does not permit. The actor's ceiling is checked when a workflow is created or a node is added (`try_get_actor_max_world`), at trigger (`authorize_workflow_trigger`) and at dispatch (`refuse_module_over_ceiling`).
- **File:** `talos-capability-world/src/lib.rs`, `talos-workflow-authorization/src/lib.rs`, `talos-workflow-engine/src/capability_ceiling.rs`, `talos-mcp-handlers/src/actor.rs`, `talos-worker-runtime/src/context.rs`

---

## 7. Attack Surface 5: NATS Job Protocol (Controller to Worker)

### Spoofing
- **Threat:** Attacker with NATS access injects forged job requests.
- **Mitigation:** Every `JobRequest` is signed: HMAC-SHA256 with the fleet-shared `WORKER_SHARED_KEY` by default, or Ed25519 with the controller's key when `TALOS_DISPATCH_SCHEME=ed25519` (a production boot refuses a requested Ed25519 scheme without a usable `TALOS_CONTROLLER_SIGNING_KEY` unless `TALOS_ALLOW_DISPATCH_SCHEME_FALLBACK` is set; workers reject HMAC dispatch only with `TALOS_DISPATCH_REQUIRE_ED25519`). The worker verifies the signature before execution. Nonce = `<unix seconds>:<16 random bytes hex>`; the worker rejects a dispatch older than 300 s and a nonce it has already seen. Job results are signed by the worker (HMAC, or Ed25519 for a worker with an identity key) and verified by the controller.
- **File:** `talos-workflow-job-protocol/src/lib.rs`, `talos-engine/src/nats_run.rs`, `worker/src/main.rs`

### Tampering
- **Threat:** Job payload modified in transit to alter execution behavior.
- **Mitigation:** The signature covers a canonical projection of the request — job id, nonce, SHA-256 of the input payload, of the secret envelope and of the WASM bytes (or the expected WASM hash), sorted allowed hosts/methods/secrets/SQL operations, actor id, LLM tier and the other ceilings — not the raw serialized bytes. Secrets travel in a separate AES-256-GCM envelope (see Information Disclosure).

### Information Disclosure
- **Threat:** Secrets visible in NATS messages if intercepted.
- **Mitigation:** Secrets are encrypted before placement in the `JobRequest`. Default mode: AES-256-GCM under a **per-job HKDF-SHA256 subkey derived from `WORKER_SHARED_KEY`** (label `envelope-aead/v2-per-job`, AAD bound to the workflow execution id) — there is no per-job DEK, and any holder of the fleet-shared key can open any envelope. With `TALOS_ENVELOPE_SEALING` (`audit` / `required`, requires the Ed25519 controller key), the worker claims the secrets per execution and they are sealed with an ephemeral X25519 exchange → HKDF → AES-GCM. NATS TLS is required in production (§2, B4). The controller's DEK cache (`DEK_CACHE_TTL_SECS`, default 300 s, `Zeroizing<Vec<u8>>`) belongs to at-rest encryption (§8), not to this envelope.
- **File:** `talos-workflow-job-protocol/src/lib.rs`, `talos-workflow-job-protocol/src/envelope_seal.rs`

### Denial of Service
- **Threat:** Job queue flooding starves legitimate executions.
- **Mitigation:** Per-workflow concurrency limits (`max_concurrent_executions`, checked and inserted in one transaction). Queue status monitoring. `enqueue_workflow` rate limiting (`rate_per_second`, max 20).
- **File:** `talos-workflow-repository/src/executions.rs`, `talos-mcp-handlers/src/executions.rs`

---

## 8. Attack Surface 6: PostgreSQL Database

### Spoofing
- **Threat:** Unauthorized database access via compromised credentials.
- **Mitigation:** Connection via sqlx connection pool (`DB_MAX_CONNECTIONS`, default 30) with environment-based credentials held only by the controller. TLS required in production (§2, B2).

### Tampering
- **Threat:** Direct modification of audit records to cover tracks.
- **Mitigation:** Immutability triggers on all 7 audit tables (`auth_audit_log`, `secret_audit_log`, `admin_event_log`, `schema_audit_log`, `oauth_audit_log`, `gmail_integration_audit_log`, `slack_integration_audit_log`), refusing UPDATE, DELETE and TRUNCATE; the execution audit ledger is the S3 WORM hash chain verified by the controller sweep (`audit_events`, a table nothing ever wrote, was dropped 2026-09-11). BEFORE UPDATE OR DELETE raises SQLSTATE 42501. Append-only design.
- **File:** `migrations/20260911160000_drop_dead_audit_events_table.sql` (and the trigger definitions in the schema baseline)

### Information Disclosure
- **Threat:** Secret values exfiltrated from database dump.
- **Mitigation:** AES-256-GCM envelope encryption. DEKs are **per-organization** (`encryption_keys.org_id`; one global DEK + one active per org), each wrapped by the master KEK, never stored in DB plaintext. The KEK provider is `KEK_PROVIDER`: `vault` (Vault transit; the Helm chart default — every wrap/unwrap is a call to Vault and the KEK stays in Vault) or `env` (`TALOS_MASTER_KEY` in process memory; a production boot refuses it unless `TALOS_ALLOW_ENV_KEK` is set, logged at ERROR). A row seals under its org's DEK (format v4) when an org is resolvable, else the global DEK (v3) — so a compromised root DEK is bounded to one tenant. DEKs cached (per-org + global) with Zeroizing memory. Within an org, each AEAD operation encrypts under a **per-context HKDF subkey** of the DEK (per secret / actor-key / execution / per-slot), not the shared DEK directly — the per-key message count is ~1, so the random-96-bit-nonce birthday bound is unreachable. (Checkpoint / worker-envelope / OTLP encryption use a separate `WORKER_SHARED_KEY`/`user_id` root, not the DEK.)
- **File:** `talos-secrets-manager/src/manager.rs`, `talos-secrets-manager/src/kek_provider.rs`, `talos-secrets-manager/src/vault_kek_provider.rs`, `controller/src/bootstrap/services.rs`

### Denial of Service
- **Threat:** Expensive queries lock tables or exhaust connections.
- **Mitigation:** Connection pool limits. Database indexes on frequently queried column combinations. `WHERE id = ANY($1)` batch patterns instead of N+1 queries.

### Elevation of Privilege
- **Threat:** SQL injection to bypass row-level access control.
- **Mitigation:** Queries use sqlx bind parameters (`$1`, `$2`) for values. Compile-time checking via the sqlx offline cache covers only the `query!`-family **macro** forms (a small minority of statements); the far larger set of function-form `sqlx::query("…")` statements is not compile-checked. Those static statements are PREPAREd against a migrated schema by structural lint check 88 (`scripts/lint-sql-prepare.py`), which `scripts/test-integration.sh` runs in CI — this proves a statement parses and plans, not that it is injection-safe. A few dozen statements are assembled at runtime from constants and predicate builders (`format!`/`concat!`); the probe cannot check those, and their injection safety is not enumerated here.
- **File:** `scripts/lint-sql-prepare.py`, `scripts/test-integration.sh`

---

## 8a. Attack Surface 7: Redis

Redis holds no state of record; it holds rate-limit counters, replay and
deduplication keys, caches and leases (§1).

| Threat | Category | Mitigations | Residual Risk |
|--------|----------|-------------|---------------|
| Interception of Redis traffic | Info Disclosure | `rediss://` (TLS) required in production for the controller and the worker (§2, B3) | Development may use plaintext. Push-deduplication keys embed identifiers in the key name (the Gmail key contains the mailbox address), so Redis key names are personal data. |
| Cache poisoning of WASM module bytes | Tampering | The worker verifies loaded bytes against the signed `expected_wasm_hash` and, in production, refuses unattested bytes with no hash (§6 Spoofing) | A Redis writer can cause refusals (availability), not substitution |
| Poisoning of counters, dedup or replay keys | Tampering | TOTP replay uses atomic `SET NX EX 90`; approval reply topics read from Redis are validated before publishing to NATS | Deleting a dedup key re-enables a webhook replay; resetting counters temporarily lifts the auth rate limit |
| TOTP replay | Spoofing | One-time use enforced with `SET NX`; key TTL (90 s) covers the ±1 step window | Redis unavailability in production makes 2FA login fail closed |
| Redis unavailable | DoS | Auth limiter and 2FA fail closed in production; GitHub-format webhooks are refused without deduplication | Availability impact by design |

**File:** `talos-totp-2fa/src/lib.rs`, `talos-rate-limit/src/middleware.rs`, `talos-webhooks/src/approval.rs`, `talos-worker-runtime/src/host/governance.rs`, `talos-envelope-seal/src/lease.rs`, `worker/src/main.rs`

---

## 9. Rhai Scripting Engine

Rhai is used for approval condition evaluation, node skip conditions, edge conditions and expression-based dispatch routing.

| Threat | Mitigation | File |
|--------|-----------|------|
| Arbitrary code execution via `eval()` | Every evaluating engine is built by `sandboxed_engine`, which calls `engine.disable_symbol("eval")` (lint check 63 forbids constructing a Rhai `Engine` elsewhere). Authoring-time string checks add operator feedback: an edge `condition` is rejected if its lowercased text contains `eval(`; an approval `trigger_condition` is rejected if it contains an `eval` call (case-sensitive, word-boundary match). | `talos-rhai-sandbox/src/lib.rs`, `talos-mcp-handlers/src/workflows.rs`, `talos-actor-policies/src/rhai_eval.rs` |
| Module import escape | `DummyModuleResolver` set on every sandboxed engine. Authoring-time: an edge `condition` containing `import ` is rejected; an approval `trigger_condition` using the `import` keyword is rejected. | `talos-rhai-sandbox/src/lib.rs`, `talos-mcp-handlers/src/workflows.rs`, `talos-actor-policies/src/rhai_eval.rs` |
| Resource exhaustion | All profiles: `max_call_levels(16)`, `max_string_size(65536)`, `max_array_size(500)`, `max_map_size(500)`. Operation cap: 1,000 in the Expression profile (conditions, approval policies, `testRhaiExpression`); 10,000 in the Dispatch profile used by expression-dispatch routing. | `talos-rhai-sandbox/src/lib.rs`, `talos-engine/src/rhai_helpers.rs`, `talos-workflow-engine/src/scheduler_handlers.rs` |
| Syntax injection at save time | Node `skip_condition` and edge `condition` are compiled with `Engine::new_raw().compile()` (no evaluation) before persistence. An approval `trigger_condition` is instead checked by evaluating it once against an empty context with the sandboxed engine, rejecting only syntax errors. | `talos-mcp-handlers/src/graph.rs`, `talos-mcp-handlers/src/actor.rs`, `talos-actor-policies/src/rhai_eval.rs` |

---

## 10. DLP / PII Protection

| Threat | Mitigation | File |
|--------|-----------|------|
| PII leakage in stored data | `DlpProvider` with `BuiltinDlpProvider` regex patterns (SSN, credit card with Luhn, email, phone, JWT, and credential formats), selected by `DLP_PROVIDER` (`builtin` default, `external`, `none`). Applied at persistence boundaries such as module-execution input/output, not to every table. | `talos-dlp-provider/src/lib.rs`, `talos-engine/src/module_execution_store.rs`, `talos-module-executions/src/lib.rs` |
| PII in audit records | **Not redacted before persistence.** WORM ledger events are stored as their signed bytes (redaction would break the HMAC); only the OTLP span copy is redacted. `admin_event_log` rows are DLP-redacted by their one writer. | `talos-audit-ledger/src/lib.rs`, `talos-trace/src/lib.rs::redact_span_text`, `talos-admin-event-log/src/lib.rs` |
| External DLP integration | `ExternalDlpProvider` POSTs payloads to `DLP_WEBHOOK_URL` (5 s timeout, no redirects) and falls back to the built-in patterns when the call fails | `talos-dlp-provider/src/lib.rs` |
| DLP bypass | DLP never blocks execution. `DLP_PROVIDER=none` selects `PassthroughDlpProvider` (no redaction; logged at ERROR in production). | `talos-dlp-provider/src/lib.rs` |

---

## 11. Security Headers and Transport

| Header | Value | File |
|--------|-------|------|
| Content-Security-Policy | Production: `script-src 'self'` (no inline or eval). Non-production allows `'unsafe-inline' 'unsafe-eval'`. | `talos-security-headers/src/lib.rs` |
| X-Frame-Options | DENY | `talos-security-headers/src/lib.rs` |
| Strict-Transport-Security | `max-age=31536000; includeSubDomains; preload`, sent only when `ENABLE_HSTS` is on (default: on in production) | `talos-security-headers/src/lib.rs` |
| X-Content-Type-Options | nosniff | `talos-security-headers/src/lib.rs` |

---

## 12. Existing Mitigations Summary

| Control | Implementation | File Path |
|---------|---------------|-----------|
| WASM sandboxing | Fuel limits, memory caps, capability worlds, wall-clock timeout | `talos-worker-runtime/src/runtime.rs` |
| Job signing | HMAC-SHA256 (default) or Ed25519 signature, nonce + 300 s freshness per job; secrets in AES-256-GCM under a per-job HKDF subkey, or claim-based X25519 sealing | `talos-workflow-job-protocol/src/lib.rs` |
| Audit ledger | HMAC-signed events, hash chains, DB immutability triggers on 7 tables (UPDATE/DELETE and TRUNCATE), **consumer-side inline HMAC+hash verify before WORM persist (poison → `rejected/`; Object Lock only with `TALOS_AUDIT_S3_OBJECT_LOCK=true`), anchored verification of sequence/linkage/genesis/terminal anchor** | `talos-audit-event/src/lib.rs`, `talos-audit-ledger/src/lib.rs` |
| SQL validation (guest SQL) | AST-parsed via sqlparser: single statement, fail-closed parse, DDL and a statement deny-list blocked, CTE mutations classified, disallowed-function list. It validates statement shape; it does not require bind parameters (SQL with literal values is accepted). | `talos-worker-runtime/src/sql_validator.rs` |
| DLP | PII redaction (SSN, CC, email, phone, JWT), Luhn validation, at persistence boundaries; not on WORM ledger events | `talos-dlp-provider/src/lib.rs` |
| Rate limiting | Per-IP and global in-memory limiters per replica (per-IP off outside production unless `ENFORCE_RATE_LIMITS_IN_DEV`); Redis-backed auth limiter fail-closed in production; MCP token-auth limiter | `talos-rate-limit/src/middleware.rs` |
| JWT auth | HS256 (default) / RS256 / ES256, issuer + audience validation, 15-min TTL | `talos-auth/src/lib.rs` |
| MCP auth | Opaque per-agent bearer token, SHA-256 lookup + bcrypt verify | `talos-mcp-handlers/src/auth.rs` |
| Capability lattice | 12 actor-ceiling worlds (partial order), platform-admin gate for cross-user grants | `talos-capability-world/src/lib.rs` |
| CSRF | Double-submit cookies, constant-time comparison | `talos-csrf/src/lib.rs` |
| Security headers | CSP, X-Frame-Options, HSTS, X-Content-Type-Options | `talos-security-headers/src/lib.rs` |
| SSRF protection | RFC1918/link-local/metadata endpoint blocking; connect-time resolver re-check (controller and worker) | `talos-http-utils/src/ssrf.rs`, `talos-http-utils/src/outbound.rs`, `talos-worker-runtime/src/ssrf_resolver.rs` |
| Secret encryption | AES-256-GCM envelope encryption, master KEK (Vault transit or env), **per-organization DEKs** (one global + one per org; format v4/v3), per-context HKDF subkey derivation (per secret/actor/execution/per-slot; ~1 message per key), Zeroizing DEK cache | `talos-secrets-manager/src/manager.rs` |

---

## 13. Residual Risks (Acknowledged)

| Risk | Severity | Likelihood | Rationale |
|------|----------|------------|-----------|
| No formal verification of WASM component model adapter | Critical | Very Low | wasmtime is memory-safe Rust with active security team. Mitigated by capability worlds limiting blast radius. See `docs/wasmtime-version-tracking.md` for upgrade cadence. |
| Single-region deployment | High | Low | Multi-region scaffolded but not proven. Mitigated by database replication; worker-crash is covered by controller-side dispatch retry, and interrupted runs are resumable via opt-in per-node checkpointing (RFC 0003). |
| DLP patterns are regex-based (no ML-based PII detection) | Medium | Medium | Known PII formats covered. Novel PII patterns may pass through. Mitigated by ExternalDlpProvider hook for enterprise ML systems. |
| Audit records are not DLP-redacted | Medium | Medium | WORM ledger events are stored as signed bytes (event payloads can include guest SQL text), and some `admin_event_log` writers store unredacted text. Anyone with read access to the audit bucket or the audit table can read that content. |
| KEK compromise (Vault path) | Critical | Low | The KEK stays in Vault and the controller's token policy allows only `transit/encrypt` and `transit/decrypt` (update) and `read` on the named key. The token is an orphan periodic token (`-period=768h`) that the controller renews (at boot, then at most hourly), so it does not expire while the controller runs; a production boot refuses a non-renewable token. A stolen token remains usable until revoked in Vault. The chart's Vault init Job initializes Vault with `-key-shares=1 -key-threshold=1` and stores the single unseal key in `/vault/file/bootstrap.json` on the Vault data PVC (an `unsealer` sidecar uses it to unseal after a pod restart); no root token is stored or left valid — each Job run generates one from the unseal key and revokes it on exit — but access to that volume yields the unseal key, and with it a root token; multi-replica or multi-operator deployments must replace the Job with Shamir-split keys held by distinct people. |
| Master key in environment variable (env KEK path) | Critical | Low | With `KEK_PROVIDER=env` the KEK is `TALOS_MASTER_KEY` in a Secret and process memory, recoverable from the Secret or a heap dump. A production boot refuses this unless `TALOS_ALLOW_ENV_KEK` is set (logged at ERROR). `rotateMasterKey` performs env→env re-wrapping only, in batches each in its own transaction; Vault keys are rotated in Vault. |
| DB superuser drops audit triggers | High | Very Low | The immutability triggers do not bind a superuser. Mitigate with pgaudit and a separate, non-owner audit role. |
| DNS rebinding bypasses SSRF check | High | Low | **Closed.** Controller outbound webhooks: `ControllerSsrfResolver` re-applies the private-IP filter at connect time. Worker egress (M4, 2026-05-22): `SsrfFilteringResolver` does the same at the reqwest resolve point. See `talos-http-utils/src/outbound.rs` and `talos-worker-runtime/src/ssrf_resolver.rs`. |
| Long-lived API keys and MCP agent tokens | Medium | Medium | API-key expiry is optional; MCP agent tokens have no expiry column; `revokeMcpAgent` deletes the row and records the revocation in `admin_event_log` in the same transaction. Recommend rotation reminders and a maximum lifetime. |
| Distributed brute-force from many IPs | Medium | Medium | Per-IP rate limiting only, and the general API limiter is per replica. Recommend CDN/WAF layer with global rate limiting. |
| Webhook replay | Medium | Low | Slack and generic formats accept a 300 s skew window (clock skew widens it; NTP monitoring recommended). GitHub-format deliveries have no timestamp and are protected only by the 24-hour Redis deduplication window, which is equally a blackout on legitimate redelivery of an unchanged payload; static-token triggers carry no signature. |
| Redis unavailability causes fail-closed auth | Low | Low | By design, but may cause availability impact. |
| `TALOS_COMPILATION_ALLOW_HOST_FALLBACK` runs proc-macros / `build.rs` unsandboxed on the controller host | Critical | Low (opt-in only) | Production fail-closes by default if no container runtime is detected. In production only the value `acknowledge-single-tenant-rce-risk` enables the fallback; `true`/`1`/`yes` are ignored there with a `host_fallback_prod_short_form_rejected` WARN (they work outside production). The flag is an **explicit operator opt-in** for single-tenant deployments where the operator authors all modules. Every production fallback compilation emits a structured `compilation_unsandboxed_fallback` WARN event (target=`talos_compilation`); operators MUST alert on this if the flag is ever set. Multi-tenant deployments MUST NOT set this flag. `TALOS_COMPILATION_CONTAINER=false` in production is gated by the same token (`fallback_reason=container_disabled`). See `talos-compilation/src/container.rs::host_fallback_allowed` and `talos-compilation/src/container.rs::build_command`. |
| `WORKER_ALLOW_PRIVATE_HOST_TARGETS=1` permits private IPs for explicitly-listed `allowed_hosts` | Medium | Low (opt-in, narrowly scoped) | Per-execution scoping (M4): the bypass requires BOTH the global env toggle AND the literal hostname in the module's `allowed_hosts` (wildcards stripped). Used for local-development cases (`host.docker.internal`). The worker ignores the toggle in production (with a WARN). |
| `TALOS_AOT_HMAC_KEY` length check is byte-length only (no entropy measurement) | Medium | Low | In production the worker panics if the key is unset or shorter than 32 bytes; outside production an unset key is replaced by an ephemeral random key. The canonical operator instruction is `openssl rand -hex 32` (256-bit entropy). Entropy measurement is impractical to enforce in code; mitigated by the security_audit MCP tool's check and operator documentation. |

---

## 14. Programmatic Audit

Use the `security_audit` MCP tool (platform-admin only) for automated security posture checks. It validates:
- Production mode configuration
- JWT algorithm strength (asymmetric recommended)
- Master encryption key presence
- Job signing key presence
- AOT integrity key presence
- Audit event signing key presence
- Redis TLS configuration
- Database audit immutability triggers
- CORS origin configuration
- Write-ceiling enforcement (controller gate and worker fleet)
- Audit-chain verification (round trip through the real verifier)

Run via MCP: `{"method": "tools/call", "params": {"name": "security_audit", "arguments": {}}}`

**File:** `talos-security-audit/src/lib.rs`

---

## 15. Review Schedule

This threat model should be reviewed:
- After any new trust boundary is added
- After any change to the capability world system
- After wasmtime major version upgrades
- Quarterly as part of SOC 2 continuous monitoring
- Before any pentest engagement (to guide scope)

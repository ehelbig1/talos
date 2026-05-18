# Talos Platform STRIDE Threat Model

**Version:** 2.0
**Date:** 2026-04-09
**Methodology:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
**Scope:** All externally reachable and internally critical attack surfaces

---

## 1. System Architecture

Talos is a workflow automation platform with user-submitted WASM module execution.

| Component | Role | Source |
|-----------|------|--------|
| Controller | Rust/Axum API server (GraphQL, REST, MCP JSON-RPC, webhooks) | `controller/` |
| Worker | Rust WASM runtime (wasmtime, sandboxed execution) | `worker/` |
| PostgreSQL | Primary data store (workflows, secrets, audit, executions) | `migrations/` |
| Redis | Session cache, rate limiting, TOTP replay prevention, approval pub/sub | Controller connects via `REDIS_URL` |
| NATS JetStream | Job queue (controller-to-worker), audit event streaming | `talos-workflow-job-protocol` (sibling repo `../talos-workflow-engine/talos-workflow-job-protocol/`) |
| Frontend | React/TypeScript visual workflow editor (untrusted client) | `frontend/` |

---

## 2. Trust Boundaries

```
  +-----------------+       HTTPS/WSS        +--------------------+
  | Browser / CLI   | ---------------------> |    Controller      |
  | (untrusted)     | <--------------------- |    (Rust/Axum)     |
  +-----------------+   JWT + CSRF tokens    +---+------+---------+
                                                 |      |
                        TLS (prod)               |      | NATS (HMAC-signed)
                   +----------------------------+      +------------------+
                   |                                                      |
             +-----v-----+                                        +------v------+
             |   Redis    |                                        |   Worker    |
             | (sessions, |                                        | (wasmtime)  |
             |  rate lim) |                                        +------+------+
             +-----------+                                                |
                                                                    WASM sandbox
             +-----------+                                        +------v------+
             | PostgreSQL | <------ sqlx (parameterized) -------> | WASM Guest  |
             | (secrets,  |                                        | (untrusted  |
             |  audit)    |                                        |  user code) |
             +-----------+                                        +-------------+
```

---

## 3. Attack Surface 1: MCP JSON-RPC Interface (348+ tools)

The MCP endpoint exposes 348+ tools via JSON-RPC over SSE and Streamable HTTP transports.

### Spoofing
- **Threat:** Unauthenticated tool invocation; forged agent identity.
- **Mitigation:** JWT-based authentication on all MCP endpoints; `AgentIdentity` extracted from token with capability grants. API keys scoped to specific operations (`workflows:read`, `secrets:write`, etc.) with bcrypt-hashed storage and SHA256 lookup hash.
- **File:** `controller/src/auth/mod.rs`, `controller/src/api_keys.rs`

### Tampering
- **Threat:** Manipulated tool parameters bypass validation (e.g., negative `max_depth`, float `timeout_secs`).
- **Mitigation:** Per-parameter validation with explicit rejection (not silent clamping). `fract() != 0.0` float guard, positivity checks, bounds validation on all numeric fields. Input size caps (1MB for payloads, 10KB for Rhai scripts).
- **File:** `controller/src/mcp/workflows.rs`, `controller/src/mcp/actor.rs`

### Repudiation
- **Threat:** Admin invokes destructive operations (delete workflow, modify secrets) without audit trail.
- **Mitigation:** Audit ledger with HMAC-signed events and hash chains. Immutability triggers on 4 audit tables prevent UPDATE/DELETE. `admin_event_log` records all admin actions.
- **File:** `controller/src/audit_ledger.rs`, `worker/src/audit.rs`

### Information Disclosure
- **Threat:** Tool responses leak internal errors, stack traces, or secret values.
- **Mitigation:** Generic error messages returned to clients; full errors logged server-side only. DLP redaction applied to audit log payloads. Secret values never returned in API responses.
- **File:** `controller/src/dlp.rs`, `controller/src/mcp/utils.rs`

### Denial of Service
- **Threat:** Rapid tool invocation exhausts server resources; unbounded pagination.
- **Mitigation:** Per-IP rate limiting (300 req/min API, 5/min auth). Fail-closed in production (rate limiter failure = request rejected). Pagination with cursor-based limits.
- **File:** `controller/src/rate_limit.rs`

### Elevation of Privilege
- **Threat:** Non-admin user invokes admin-only tools (e.g., `set_wasm_config`, `publish_built_in_templates`).
- **Mitigation:** `is_admin()` check at dispatch entry for admin tools. Capability-filtered tool lists (agents only see tools within their capability grants). `governance-node` ceiling per actor.
- **File:** `controller/src/mcp/platform.rs`, `controller/src/mcp/actor.rs`

---

## 4. Attack Surface 2: GraphQL API

### Spoofing
- **Threat:** Stolen JWT replayed to impersonate user.
- **Mitigation:** JWT with 15-min TTL, issuer claim validation, refresh token rotation. HttpOnly + Secure + SameSite=Strict cookies.
- **File:** `controller/src/auth/mod.rs`

### Tampering
- **Threat:** CSRF on mutation endpoints.
- **Mitigation:** Double-submit cookie pattern with constant-time comparison (`constant_time_eq`). SameSite=Strict. CSRF token rotation after each mutation.
- **File:** `controller/src/csrf.rs`

### Information Disclosure
- **Threat:** Schema introspection reveals internal types and fields.
- **Mitigation:** Introspection disabled in production via `Schema::build(...).disable_introspection()` gated on `config::is_production()`. Password hashes never returned. `[REDACTED]` in Debug impl for sensitive types.
- **File:** `controller/src/main.rs` (search for `disable_introspection`)

### Denial of Service
- **Threat:** Deeply nested or high-complexity queries exhaust CPU/memory.
- **Mitigation:** Query depth limit 15; complexity limit 5000; per-IP rate limiting.

### Elevation of Privilege
- **Threat:** User accesses another user's workflows via GraphQL.
- **Mitigation:** All queries filter by `user_id` from JWT. Row-level ownership enforcement on workflows, secrets, executions.
- **File:** `controller/src/api/schema/workflows/queries.rs`

---

## 5. Attack Surface 3: Webhook Ingestion Endpoints

### Spoofing
- **Threat:** Forged webhook payloads trigger unauthorized workflow executions.
- **Mitigation:** HMAC-SHA256 signature verification with constant-time comparison (`subtle::ConstantTimeEq`). Per-trigger signing secrets. Slack-specific signature format support.
- **File:** `controller/src/api/schema/webhooks/mutations.rs`

### Tampering
- **Threat:** Replay of previously valid webhook payloads.
- **Mitigation:** Timestamp validation with +/-5 minute tolerance window.

### Denial of Service
- **Threat:** Webhook flooding overwhelms execution queue.
- **Mitigation:** Per-trigger rate limiting. Circuit breaker with auth failure tracking per source IP. IP allowlist per trigger. Dead letter queue (DLQ) for overflow.

### Elevation of Privilege
- **Threat:** SSRF via user-configured webhook URLs (controller makes outbound requests to attacker-controlled URLs).
- **Mitigation:** `check_outbound_url_no_ssrf()` blocks RFC1918, link-local, localhost, IPv6 ULA, cloud metadata endpoints (169.254.169.254, metadata.google.internal). HTTPS enforced for outbound.
- **File:** `controller/src/mcp/utils.rs`

---

## 6. Attack Surface 4: WASM Module Execution (User-Submitted Code)

This is the highest-risk attack surface. Users submit arbitrary Rust source code that compiles to WASM and runs on the worker.

### Spoofing
- **Threat:** Malicious module impersonates a trusted catalog module.
- **Mitigation:** Module UUIDs are server-assigned. Catalog modules are system-owned (user_id IS NULL). User-installed modules are scoped to user.

### Tampering
- **Threat:** Supply-chain attack via malicious dependency in user code.
- **Mitigation:** Crate allowlist enforcement (only pre-approved dependencies compile). `cargo-audit` gate rejects known-vulnerable crates. `reqwest` explicitly blocked. Containerized compilation (Podman with `--network=none`).
- **File:** `controller/src/compilation/mod.rs`

### Information Disclosure
- **Threat:** Module reads secrets beyond its allowlist; exfiltrates via HTTP.
- **Mitigation:** Per-module `allowed_secrets` with deny-all default. Vault slot handles (opaque `SlotHandle(u64)`) cross WASM boundary, not raw values. `into_auth_header()` is the single plaintext exit. Slot TTL 300s with auto-release. Secret audit log records every access.
- **File:** `worker/src/runtime.rs`, `worker/src/context.rs`

### Denial of Service
- **Threat:** Module runs infinite loop or allocates unbounded memory.
- **Mitigation:** Fuel-based instruction metering (default 10M fuel units). `tokio::time::timeout` wall-clock limits (default 30s, configurable 5-300s). Memory limit (default 128MB, max 512MB).
- **File:** `worker/src/runtime.rs`

### Elevation of Privilege
- **Threat:** Module accesses host functions beyond its capability world (e.g., filesystem, network, governance).
- **Mitigation:** 12-tier capability world system verified as partial order. Default `minimal-node` grants zero host access. Capability escalation requires admin approval. `get_actor_max_world()` checked before compilation.
- **File:** `worker/src/wit_inspector.rs`

---

## 7. Attack Surface 5: NATS Job Protocol (Controller to Worker)

### Spoofing
- **Threat:** Attacker with NATS access injects forged job requests.
- **Mitigation:** Every `JobRequest` signed with HMAC-SHA256 using pre-shared `WORKER_SHARED_KEY`. Worker verifies signature before execution. Nonce freshness validation (timestamp + random hex).
- **File:** `talos-workflow-job-protocol/src/lib.rs` (sibling repo)

### Tampering
- **Threat:** Job payload modified in transit to alter execution behavior.
- **Mitigation:** HMAC covers full serialized payload. Secrets encrypted separately within job payload using AES-256-GCM with per-job DEK.

### Information Disclosure
- **Threat:** Secrets visible in NATS messages if intercepted.
- **Mitigation:** Secrets encrypted with AES-256-GCM before placement in JobRequest. NATS TLS when configured. DEK cached in-memory with 5-min TTL and `Zeroizing<String>` wrappers.

### Denial of Service
- **Threat:** Job queue flooding starves legitimate executions.
- **Mitigation:** Per-workflow concurrency limits (`max_concurrent_executions`). Queue status monitoring. Per-workflow rate limiting on enqueue.

---

## 8. Attack Surface 6: PostgreSQL Database

### Spoofing
- **Threat:** Unauthorized database access via compromised credentials.
- **Mitigation:** Connection via sqlx connection pool with environment-based credentials. TLS enforced in production.

### Tampering
- **Threat:** Direct modification of audit records to cover tracks.
- **Mitigation:** Immutability triggers on all 4 audit tables (`audit_events`, `auth_audit_log`, `secret_audit_log`, `admin_event_log`). BEFORE UPDATE OR DELETE raises SQLSTATE 42501. Append-only design.
- **File:** `migrations/` (trigger migrations)

### Information Disclosure
- **Threat:** Secret values exfiltrated from database dump.
- **Mitigation:** AES-256-GCM envelope encryption. DEK encrypted by master KEK (`TALOS_MASTER_KEY`). Master key from env/file, never stored in DB. DEK cached with Zeroizing memory.
- **File:** `controller/src/db.rs`

### Denial of Service
- **Threat:** Expensive queries lock tables or exhaust connections.
- **Mitigation:** Connection pool limits. Database indexes on frequently queried columns. `WHERE id = ANY($1)` batch patterns instead of N+1 queries.

### Elevation of Privilege
- **Threat:** SQL injection to bypass row-level access control.
- **Mitigation:** All queries use sqlx parameterized bindings (`$1`, `$2`). No string concatenation. Compile-time query checking via sqlx offline mode.

---

## 9. Rhai Scripting Engine

Rhai is used for approval condition evaluation and expression-based dispatch routing.

| Threat | Mitigation | File |
|--------|-----------|------|
| Arbitrary code execution via `eval()` | `engine.disable_symbol("eval")`; case-insensitive string-layer block | `controller/src/engine/rhai_helpers.rs` |
| Module import escape | `import` blocked at string layer; `DummyModuleResolver` | `controller/src/engine/rhai_helpers.rs` |
| Resource exhaustion | `max_operations(1000)`, `max_call_levels(16)`, `max_string_size(65536)`, `max_array_size(500)`, `max_map_size(500)` | `controller/src/engine/rhai_helpers.rs` |
| Syntax injection at save time | `Engine::new_raw().compile()` validates syntax before persistence | `controller/src/mcp/actor.rs` |

---

## 10. DLP / PII Protection

| Threat | Mitigation | File |
|--------|-----------|------|
| PII leakage in audit logs | `DlpProvider` with regex-based patterns: SSN, credit card (Luhn), email, phone, JWT detection | `controller/src/dlp.rs` |
| PII in execution outputs | DLP redaction applied before audit persistence | `controller/src/audit_ledger.rs` |
| External DLP integration | `ExternalDlpProvider` sends payloads to enterprise DLP webhook | `controller/src/dlp.rs` |

---

## 11. Security Headers and Transport

| Header | Value | File |
|--------|-------|------|
| Content-Security-Policy | Strict CSP blocking inline scripts | `controller/src/security_headers.rs` |
| X-Frame-Options | DENY | `controller/src/security_headers.rs` |
| Strict-Transport-Security | max-age=31536000; includeSubDomains | `controller/src/security_headers.rs` |
| X-Content-Type-Options | nosniff | `controller/src/security_headers.rs` |

---

## 12. Existing Mitigations Summary

| Control | Implementation | File Path |
|---------|---------------|-----------|
| WASM sandboxing | Fuel limits, memory caps, capability worlds, wall-clock timeout | `worker/src/runtime.rs` |
| Job signing | HMAC-SHA256 + AES-256-GCM + nonce per job | `talos-workflow-job-protocol/src/lib.rs` (sibling repo) |
| Audit ledger | HMAC-signed events, hash chains, immutability triggers | `worker/src/audit.rs`, `controller/src/audit_ledger.rs` |
| SQL validation | AST-parsed via sqlparser, parameterized queries only | `worker/src/sql_validator.rs` |
| DLP | PII redaction (SSN, CC, email, phone, JWT), Luhn validation | `controller/src/dlp.rs` |
| Rate limiting | Per-IP, per-route, fail-closed in production | `controller/src/rate_limit.rs` |
| JWT auth | HS256/RS256/ES256, issuer validation, 15-min TTL | `controller/src/auth/mod.rs` |
| Capability lattice | 12 worlds, verified partial order, admin escalation gate | `worker/src/wit_inspector.rs` |
| CSRF | Double-submit cookies, constant-time comparison | `controller/src/csrf.rs` |
| Security headers | CSP, X-Frame-Options, HSTS, X-Content-Type-Options | `controller/src/security_headers.rs` |
| SSRF protection | RFC1918/link-local/metadata endpoint blocking | `controller/src/mcp/utils.rs` |
| Secret encryption | AES-256-GCM envelope encryption, master KEK, Zeroizing DEK cache | `controller/src/db.rs` |

---

## 13. Residual Risks (Acknowledged)

| Risk | Severity | Likelihood | Rationale |
|------|----------|------------|-----------|
| No formal verification of WASM component model adapter | Critical | Very Low | wasmtime is memory-safe Rust with active security team. Mitigated by capability worlds limiting blast radius. |
| Single-region deployment | High | Low | Multi-region scaffolded but not proven. Mitigated by database replication and job queue durability. |
| DLP patterns are regex-based (no ML-based PII detection) | Medium | Medium | Known PII formats covered. Novel PII patterns may pass through. Mitigated by ExternalDlpProvider hook for enterprise ML systems. |
| Master key in environment variable | Critical | Low | Standard practice but not HSM-backed. Recommend migration to AWS KMS / GCP Cloud KMS for production. |
| DNS rebinding bypasses SSRF check | High | Low | URL validated at config time, not at request time. Recommend re-resolution with TTL check. |
| Long-lived API keys | Medium | Medium | Scoped but no mandatory expiry. Recommend adding rotation reminders and maximum lifetime. |
| Distributed brute-force from many IPs | Medium | Medium | Per-IP rate limiting only. Recommend CDN/WAF layer with global rate limiting. |
| Redis unavailability causes fail-closed auth | Low | Low | By design, but may cause availability impact. |

---

## 14. Programmatic Audit

Use the `security_audit` MCP tool for automated security posture checks. It validates:
- Production mode configuration
- JWT algorithm strength (asymmetric recommended)
- Master encryption key presence
- Job signing key presence
- AOT integrity key presence
- Audit event signing key presence
- Redis TLS configuration
- Database audit immutability triggers
- CORS origin configuration

Run via MCP: `{"method": "tools/call", "params": {"name": "security_audit", "arguments": {}}}`

---

## 15. Review Schedule

This threat model should be reviewed:
- After any new trust boundary is added
- After any change to the capability world system
- After wasmtime major version upgrades
- Quarterly as part of SOC 2 continuous monitoring
- Before any pentest engagement (to guide scope)

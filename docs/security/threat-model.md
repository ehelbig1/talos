# Talos Platform Threat Model

**Document version:** 1.0
**Date:** 2026-04-08
**Methodology:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
**Classification:** CONFIDENTIAL -- share only with authorized auditors and pentest firms.

---

## 1. System Overview

Talos is a workflow automation platform built on:

- **Controller** -- Rust/Axum HTTP server (GraphQL API, REST API, MCP JSON-RPC, webhook ingress)
- **Worker** -- Rust WASM runtime (wasmtime-based, executes user-authored modules in sandboxed guests)
- **PostgreSQL** -- primary data store (workflows, secrets, audit logs, execution state)
- **Redis** -- session cache, TOTP replay prevention, distributed rate limiting, approval gate pub/sub
- **NATS** -- job dispatch between controller and worker is core-NATS signed request/reply (queue-group load balancing + controller-side retry on timeout, not a durable JetStream queue); JetStream backs the tamper-evident audit-event ledger. Optional per-node checkpointing (RFC 0003) makes interrupted runs resumable.
- **Browser/CLI** -- untrusted client (React SPA, MCP clients such as Claude Desktop)

---

## 2. Trust Boundaries

```
 +------------------+       HTTPS/WSS        +---------------------+
 |  Browser / CLI   | ----------------------> |     Controller      |
 |  (untrusted)     | <---------------------- |  (Rust/Axum)        |
 +------------------+    JWT + CSRF tokens    +-----+-----+---------+
                                                    |     |
                           TLS (prod)               |     |  NATS (signed jobs)
                    +-------------------------------+     +------------------+
                    |                                                        |
              +-----v-----+                                          +------v------+
              |   Redis    |                                          |   Worker    |
              | (sessions, |                                          | (wasmtime)  |
              |  rate lim) |                                          +------+------+
              +-----------+                                                  |
                                                                      WASM sandbox
              +-----------+                                          +------v------+
              | PostgreSQL | <-------- sqlx (parameterized) -------> | WASM Guest  |
              | (secrets,  |                                          | (untrusted  |
              |  audit)    |                                          |  user code) |
              +-----------+                                          +-------------+
```

### Boundary Definitions

| ID | Boundary | From | To | Transport |
|----|----------|------|----|-----------|
| B1 | Internet edge | Browser/CLI | Controller | HTTPS (TLS 1.2+) |
| B2 | Controller-to-DB | Controller | PostgreSQL | TCP (TLS in prod) |
| B3 | Controller-to-Redis | Controller | Redis | `rediss://` enforced in prod |
| B4 | Controller-to-NATS | Controller | NATS (core for jobs; JetStream for audit ledger) | TLS (when configured) |
| B5 | NATS-to-Worker | NATS | Worker | TLS + HMAC-SHA256 job signing |
| B6 | Worker-to-WASM | Worker host | WASM guest | wasmtime sandbox (capability worlds) |
| B7 | Webhook ingress | External service | Controller `/webhooks/*` | HTTPS + HMAC signature |

---

## 3. STRIDE Analysis by Trust Boundary

### B1: Internet Edge (Browser/CLI to Controller)

| Threat | Category | Mitigations | Residual Risk |
|--------|----------|-------------|---------------|
| Stolen JWT used to impersonate user | Spoofing | JWT HS256 with issuer claim validation; 15-min TTL; HttpOnly+Secure+SameSite=Strict cookies; refresh token rotation | Token theft during TTL window if browser is compromised |
| CSRF on state-changing endpoints | Tampering | Double-submit cookie pattern with constant-time comparison (`constant_time_eq`); SameSite=Strict; CSRF token rotation after each mutation | None -- double-submit + SameSite provides layered defense |
| Credential brute-force | Spoofing | Per-IP rate limit (5/min auth, 300/min API); account lockout after 5 failed attempts; bcrypt cost factor; 2FA via TOTP | Distributed brute-force from many IPs (mitigate at CDN/WAF layer) |
| GraphQL resource exhaustion | DoS | Query depth limit 15; complexity limit 5000; introspection disabled in production | Complex but shallow queries could still be expensive; add per-query cost accounting |
| Session hijacking | Spoofing | TOTP 2FA with encrypted seed storage; replay prevention via Redis NX (one-time codes); constant-time TOTP verification; 15-min lockout after 5 failed 2FA attempts | SIM-swap attacks on TOTP recovery flow (out of scope -- requires U2F/WebAuthn) |
| API key theft | Spoofing | API keys scoped (workflows:read, workflows:write, secrets:read, secrets:write, webhooks:access, admin); bcrypt-hashed storage; SHA256 lookup hash; constant-time prefix validation | Long-lived keys -- mitigate with rotation policy and expiry |
| Password discovery | Info Disclosure | bcrypt hashing; 12-72 char length enforcement; 2-of-4 character class requirement; password hash never returned in API responses; `[REDACTED]` in Debug impl | Offline brute-force if DB is exfiltrated (bcrypt cost factor provides time defense) |

### B2: Controller to PostgreSQL

| Threat | Category | Mitigations | Residual Risk |
|--------|----------|-------------|---------------|
| SQL injection | Tampering | All queries use sqlx parameterized bindings (`$1`, `$2`); no string concatenation of SQL; compile-time query checking via sqlx offline mode | Zero -- sqlx enforces parameterization at compile time |
| Secret exfiltration via DB access | Info Disclosure | AES-256-GCM envelope encryption: every secret / OAuth token / actor memory / module-execution payload / workflow-execution output sealed with a DEK; DEK wrapped by a pluggable KEK provider (`KekProvider` trait — `EnvKekProvider` for dev, `VaultTransitProvider` for production). Production deployments set `KEK_PROVIDER=vault` so the KEK never enters controller process memory — every wrap/unwrap is an HTTPS call to Vault transit. DEK plaintext cached in-memory with 5-min TTL (DashMap + Zeroizing). **DEKs are scoped per-organization** (`encryption_keys.org_id`; one global DEK + one active per org): a row seals under its org's DEK (format v4) when an org is resolvable, else the global DEK (v3) — so a single compromised root DEK is bounded to ONE tenant's data, not the whole deployment. Within that, each row is encrypted under a **per-context HKDF subkey** of the DEK (per secret / actor-key / execution / per-slot), not the shared DEK directly — the per-key message count is ~1, so the random-96-bit-nonce birthday bound is unreachable. | KEK compromise (unwraps ALL DEKs, global + per-org) — mitigated by Vault sealing + transit-only token policies. Env-var provider (dev) keeps the KEK in process memory; not for production. Org-less rows (personal secrets, standalone module execs) legitimately remain under the global DEK. |
| KEK compromise (Vault path) | Info Disclosure | Vault sealed at rest; unseal keys distributed via Shamir 3-of-5 to multiple operators; transit token scoped to `transit/encrypt` + `transit/decrypt` on the named key only (never a root token); `vault transit/keys/talos-kek/rotate` adds new key versions without re-wrapping ciphertexts; old versions can be retired via `min_decryption_version`. Operational runbook §2.1.1 covers rotation, revocation, and the lost-KEK recovery procedure. | Vault host compromise = unbounded read until token revocation propagates. Mitigation: short token TTLs + audit-log monitoring on transit endpoints. |
| KEK compromise (env path, dev only) | Info Disclosure | `TALOS_MASTER_KEY` lives in process memory + env. `rotateEncryptionKey` GraphQL mutation (admin only) re-wraps every DEK with a new KEK in one transaction. | Process-memory inspection by root user reveals the key. Production must use `KEK_PROVIDER=vault`. |
| Audit log tampering | Repudiation | Immutability triggers on all 4 audit tables (`audit_events`, `auth_audit_log`, `secret_audit_log`, `admin_event_log`); BEFORE UPDATE OR DELETE raises SQLSTATE 42501; append-only design. The WORM audit-event ledger is HMAC-signed + hash-chained; the consumer **verifies HMAC + recomputes the hash inline before S3 (Object Lock) persist** (poison → Object-Locked `rejected/`), and offline `verify_chain`/`verify_execution_chain` checks sequence contiguity, `previous_hash` linkage, and genesis (finding #2) | Superuser can DROP the DB-side trigger (mitigate with pgaudit + separate audit DB user); WORM verification depends on `TALOS_AUDIT_SIGNING_KEY` being set on workers + controller |
| Unauthorized data access | EoP | Per-module secret allowlists with deny-all default; vault path prefix/glob matching; `allowed_secrets` field per wasm_modules installation | Misconfigured allowlist granting wildcard access (surface in risk assessment tool) |

### B3: Controller to Redis

| Threat | Category | Mitigations | Residual Risk |
|--------|----------|-------------|---------------|
| Session data interception | Info Disclosure | `rediss://` (TLS) enforced in production; controller panics on startup if `redis://` used in prod | Development environments may use plaintext (acceptable for dev) |
| Redis poisoning (cache corruption) | Tampering | Redis used for ephemeral data only (rate limits, TOTP nonces, approval pub/sub); no long-term secrets stored; all state of record in PostgreSQL | Poisoned rate limit counters could temporarily bypass limits |
| TOTP replay attack | Spoofing | Redis NX (set-if-not-exists) for one-time TOTP code consumption; key TTL matches TOTP window | Redis unavailability in prod causes fail-closed (auth rejected) |

### B4/B5: Controller to NATS to Worker

| Threat | Category | Mitigations | Residual Risk |
|--------|----------|-------------|---------------|
| Forged job injection | Spoofing | Every JobRequest signed with HMAC-SHA256 using pre-shared `WORKER_SHARED_KEY`; worker verifies signature before execution | Key compromise (mitigate with key rotation) |
| Job replay attack | Tampering | `job_nonce` field (timestamp + random hex) included in every job; worker validates nonce freshness | Nonce window tolerance (clock skew) |
| Secret interception on wire | Info Disclosure | Secrets encrypted with AES-256-GCM before placement in JobRequest under a **per-job HKDF subkey derived from `WORKER_SHARED_KEY`** (per-context key separation — ~1 message per key); worker decrypts only in memory | The subkey is derived from the shared root (not transmitted), so this is genuine confidentiality, not just defense-in-depth; residual risk is `WORKER_SHARED_KEY` compromise (mitigate with rotation) |
| Unauthorized job results | Tampering | Job results signed with same shared key; controller verifies before accepting | Same shared key risk as above |

### B6: Worker Host to WASM Guest (Critical Boundary)

| Threat | Category | Mitigations | Residual Risk |
|--------|----------|-------------|---------------|
| WASM sandbox escape | EoP | wasmtime with 9-tier capability world system; each world restricts available WIT imports (filesystem, network, secrets, HTTP, governance); `minimal-node` default grants no host access | wasmtime CVE (mitigate with prompt updates; wasmtime is memory-safe Rust) |
| Resource exhaustion by guest | DoS | Fuel-based instruction metering; tokio::time::timeout wall-clock limits; per-module rate limiting | Fuel calibration may allow expensive operations within budget |
| Filesystem escape | Info Disclosure | WASI filesystem access only granted to specific capability worlds; preopened directories scoped; most modules run without filesystem access | Symlink traversal if filesystem world is granted (restrict preopened paths) |
| Secret exfiltration from guest | Info Disclosure | Per-module `allowed_secrets` allowlist (deny-all default); vault slot handles (not raw values) cross WASM boundary; `into_auth_header` is the single plaintext exit; slots have 300s TTL with auto-release; `__secret_tier2_exposed__` flag in execution output | Module with legitimate secret access could exfiltrate via HTTP (mitigate with SSRF blocking + network isolation) |
| Panic/trap denial of service | DoS | WASI stderr capture (BufferCapture); catch_unwind in macros; panic messages surfaced as `Err("PANIC: message")`; wall-clock timeout prevents infinite loops | None -- all panic paths are handled |

### B7: Webhook Ingress

| Threat | Category | Mitigations | Residual Risk |
|--------|----------|-------------|---------------|
| Webhook spoofing | Spoofing | HMAC-SHA256 signature verification with constant-time comparison (`subtle::ConstantTimeEq`); per-trigger signing secrets; Slack-specific signature format support | Signing secret compromise (mitigate with rotation) |
| Replay attack | Tampering | Timestamp validation with +/-5 minute tolerance window | Replay within 5-min window (acceptable trade-off for webhook reliability) |
| Webhook flooding | DoS | Per-trigger rate limiting; circuit breaker with failure type tracking (auth failure, IP not allowed); IP allowlist per trigger; DLQ for overflow | Distributed flood from many IPs (mitigate at CDN/WAF) |
| SSRF via webhook URL configuration | Tampering | `check_outbound_url_no_ssrf()` blocks RFC1918, link-local (169.254.0.0/16), localhost, IPv6 ULA/link-local, cloud metadata (169.254.169.254, metadata.google.internal), IPv4-mapped IPv6; HTTPS enforced | DNS rebinding (mitigate with re-resolution at request time) |

---

## 4. Attack Surface Detail

### 4.1 WASM Sandbox Escape

**Attack vector:** Malicious user-authored module exploits wasmtime bug to break out of WASM sandbox.

**Mitigations:**
- 9-tier capability world system limits WIT imports per module tier
- Default `minimal-node` world grants zero host access (no filesystem, no network, no secrets)
- Capability escalation requires admin approval (governance-node ceiling per actor)
- Compilation pipeline validates crate allowlist before building
- `cargo-audit` gate rejects modules with known vulnerable dependencies

**Residual:** wasmtime memory-safety bug. Severity: Critical. Likelihood: Very Low (Rust memory safety, active security team).

### 4.2 Compilation Injection

**Attack vector:** User submits malicious Rust source that escapes the compilation sandbox or includes supply-chain attack dependencies.

**Mitigations:**
- Crate allowlist enforcement (only pre-approved dependencies compile)
- `cargo-audit` run during compilation rejects known-vulnerable crates
- Containerized compilation (Podman with `--network=none` -- no network access during build)
- `reqwest` explicitly blocked (incompatible with wasm32-wasip2, prevents outbound HTTP during build)
- Macro injection targets `fn run(` specifically (RE_RUN_FN), preserving user helper functions

**Residual:** Build-time exploitation before network isolation takes effect. Severity: High. Likelihood: Low.

### 4.3 Secret Exfiltration

**Attack vector:** Attacker with module authoring access attempts to read secrets beyond their allowlist.

**Mitigations:**
- Per-module `allowed_secrets` with deny-all default (empty list = no access)
- Vault slot handles (opaque `SlotHandle(u64)`) cross WASM boundary, not raw secret values
- `into_auth_header()` is the single grep-able plaintext exit point
- Slot TTL (300s default) with auto-release prevents handle accumulation
- Secret audit log records every access (key path, requestor, timestamp)
- `vault_path_permitted()` enforces prefix/glob matching
- Wildcard grant (`*`) surfaced as medium security recommendation in platform hygiene report

**Residual:** Module with legitimate access exfiltrates via permitted HTTP calls. Severity: Medium. Likelihood: Low.

### 4.4 GraphQL Abuse

**Attack vector:** Crafted deeply nested or complex GraphQL queries exhaust server resources.

**Mitigations:**
- Depth limit: 15 levels
- Complexity limit: 5000 score
- Introspection disabled in production (prevents schema enumeration)
- Per-IP rate limiting (300 req/min API)
- Input size limits (mock_inputs 1MB, Rhai scripts 100KB)

**Residual:** Complex-but-shallow queries that stay within limits. Severity: Medium. Likelihood: Medium.

### 4.5 Webhook Spoofing

**Attack vector:** Attacker sends forged webhook payloads to trigger workflow executions.

**Mitigations:**
- HMAC-SHA256 signature verification (constant-time via `subtle::ConstantTimeEq`)
- Timestamp replay window (+/-5 minutes)
- Per-trigger IP allowlists
- Circuit breaker tracks auth failures per source IP
- Webhook signing secrets stored encrypted (AES-256-GCM envelope encryption)

**Residual:** Signing secret compromise. Severity: High. Likelihood: Low.

### 4.6 NATS Job Forgery

**Attack vector:** Attacker with NATS access injects malicious job requests.

**Mitigations:**
- HMAC-SHA256 job signing with `WORKER_SHARED_KEY`
- Nonce freshness validation (timestamp + random hex)
- Secrets encrypted separately within job payload (AES-256-GCM)
- Worker verifies signature before any execution

**Residual:** Shared key compromise. Severity: Critical. Likelihood: Very Low (key in env, not in DB).

### 4.7 Redis Cache Poisoning

**Attack vector:** Attacker with Redis access corrupts rate limit counters or approval gate state.

**Mitigations:**
- Redis TLS enforced in production (`rediss://`)
- Redis stores only ephemeral data (rate limits, TOTP nonces, approval pub/sub)
- All state of record in PostgreSQL (Redis loss = temporary disruption, not data loss)
- TOTP replay prevention uses atomic NX operations

**Residual:** Temporary rate limit bypass if counters are reset. Severity: Low. Likelihood: Very Low.

---

## 5. Rhai Scripting Engine Threats

Rhai is used for approval conditions and expression-based dispatch routing.

| Threat | Mitigation |
|--------|-----------|
| Arbitrary code execution via `eval()` | `eval` disabled via `engine.disable_symbol("eval")`; string-layer block catches case-insensitive `eval(` |
| Module import escape | `import` blocked at string layer; `DummyModuleResolver` set on engine |
| Resource exhaustion | `max_operations(1000)`; `max_call_levels(16)`; `max_string_size(65536)`; `max_array_size(500)`; `max_map_size(500)` |
| Syntax injection at save time | `Engine::new_raw().compile()` validates syntax before persistence |

---

## 6. DLP / PII Protection

| Threat | Mitigation |
|--------|-----------|
| PII leakage in audit logs | `DlpProvider` trait with `BuiltinDlpProvider` (regex-based: SSN, credit card with Luhn, email, phone patterns); applied to all audit log payloads |
| PII in execution outputs | DLP redaction on audit ledger entries before persistence |
| External DLP integration | `ExternalDlpProvider` sends payloads to webhook for enterprise DLP systems |
| DLP bypass | Fail-open design (DLP never blocks execution); `PassthroughDlpProvider` for explicit opt-out |

---

## 7. Risk Summary Matrix

| Risk | Likelihood | Impact | Current Status | Recommended Action |
|------|-----------|--------|----------------|-------------------|
| wasmtime CVE | Very Low | Critical | Mitigated (capability worlds + fuel) | Pin wasmtime version, subscribe to advisories |
| Master key compromise | Low | Critical | Env var / file-based storage | Migrate to HSM/KMS for production |
| DB superuser drops audit triggers | Very Low | High | Trigger-based protection | Enable pgaudit extension; separate audit DB role |
| DNS rebinding bypasses SSRF check | Low | High | URL validation at config time | Re-resolve DNS at request time |
| Long-lived API keys | Medium | Medium | Scoped keys with bcrypt hashing | Add mandatory expiry and rotation reminders |
| Distributed brute-force | Medium | Medium | Per-IP rate limiting | Add CDN/WAF layer with global rate limiting |
| Clock skew in webhook replay window | Low | Low | 5-min tolerance | NTP monitoring; consider narrower window |

---

## 8. Review Schedule

This threat model should be reviewed:
- After any new trust boundary is added
- After any change to the capability world system
- After wasmtime major version upgrades
- Quarterly as part of SOC 2 continuous monitoring
- Before any pentest engagement (to guide scope)

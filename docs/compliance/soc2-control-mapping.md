# SOC 2 Type II Control Mapping -- Talos Platform

**Document version:** 1.0
**Date:** 2026-04-08
**Framework:** AICPA Trust Services Criteria (2017)
**Classification:** CONFIDENTIAL -- for auditor use.

---

## Overview

This document maps Talos platform security controls to SOC 2 Trust Services Criteria (TSC). Each control includes a description, implementation details, evidence location, and testing procedure.

---

## CC6: Logical and Physical Access Controls

### CC6.1 -- Logical Access Security

**Criteria:** The entity implements logical access security software, infrastructure, and architectures over protected information assets.

| Control ID | Control Description | Implementation | Evidence Location |
|-----------|-------------------|----------------|-------------------|
| CC6.1-01 | JWT-based session authentication | HS256 JWT with issuer claim, 15-min TTL; HttpOnly + Secure + SameSite=Strict cookies | `controller/src/auth/mod.rs` (Claims struct, verify_token fn) |
| CC6.1-02 | Role-based access control | Admin/User/Org Member roles; `is_admin()` method; per-endpoint authorization checks | `controller/src/auth/mod.rs`, `controller/src/mcp/actor.rs` |
| CC6.1-03 | API key scoped access | 6 scope levels (workflows:read/write, secrets:read/write, webhooks:access, admin); bcrypt-hashed storage | `controller/src/api_keys.rs` (ApiKeyScope enum) |
| CC6.1-04 | WASM capability world enforcement | 9-tier capability system restricts host function access per module; checked at compile time and runtime | `controller/src/compilation/mod.rs`, `worker/src/runtime.rs` |
| CC6.1-05 | Per-module secret allowlists | Deny-all default; modules can only access secrets in their allowlist; wildcard flagged in hygiene report | `controller/src/secrets/mod.rs`, `worker/src/host_impl.rs` |
| CC6.1-06 | Actor budget enforcement | 8-field resource budgets per actor; validated positive integers; enforced at trigger time | `controller/src/mcp/actor.rs` |
| CC6.1-07 | GraphQL query limits | Depth limit 15; complexity limit 5000; introspection disabled in production | `controller/src/main.rs` line ~1435 |

**Testing procedure:**
1. Verify JWT validation rejects expired, wrong-issuer, and tampered tokens
2. Confirm non-admin users cannot access admin-only endpoints
3. Verify API key with `workflows:read` scope cannot write workflows
4. Attempt to access a secret from a module without allowlist entry

### CC6.2 -- Prior to Issuing System Credentials

**Criteria:** Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users.

| Control ID | Control Description | Implementation | Evidence Location |
|-----------|-------------------|----------------|-------------------|
| CC6.2-01 | Password complexity enforcement | 12-72 characters; 2-of-4 character classes (upper, lower, digit, symbol) | `controller/src/auth/mod.rs` (validate_password fn) |
| CC6.2-02 | Email format validation | Regex validation; 254-char max | `controller/src/auth/mod.rs` (validate_email fn) |
| CC6.2-03 | Password hashing | bcrypt with DEFAULT_COST factor | `controller/src/auth/mod.rs` |
| CC6.2-04 | TOTP 2FA enrollment | Encrypted TOTP seed storage via SecretsManager; QR code provisioning | `controller/src/totp_2fa.rs` (TotpService) |
| CC6.2-05 | API key generation | Cryptographic random generation; `talos_sk_` prefix; SHA256 lookup hash + bcrypt verification | `controller/src/api_keys.rs` |
| CC6.2-06 | Account lockout | 5 failed login attempts triggers lockout; `locked_until` timestamp | `controller/src/auth/mod.rs` (User struct), `controller/src/totp_2fa.rs` |
| CC6.2-07 | Secret rotation support | DEK rotation (create new, re-encrypt); secret value rotation via API | `controller/src/secrets/mod.rs`, `controller/src/secrets_rotation.rs` |
| CC6.2-08 | Session revocation | Refresh token invalidation; JWT short-lived (15 min) | `controller/src/auth/mod.rs` |

**Testing procedure:**
1. Attempt registration with weak password (< 12 chars, single char class)
2. Verify locked account cannot authenticate
3. Confirm TOTP seed is encrypted in database (not plaintext)
4. Verify refresh token rotation on each use

### CC6.3 -- Encryption of Data

**Criteria:** The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles.

| Control ID | Control Description | Implementation | Evidence Location |
|-----------|-------------------|----------------|-------------------|
| CC6.3-01 | Envelope encryption for secrets | AES-256-GCM; DEK wrapped by KEK provider; random 12-byte nonce per operation | `controller/src/secrets/mod.rs` (SecretsManager) |
| CC6.3-02 | Transit encryption (client) | HTTPS enforced; HSTS headers in production | Load balancer configuration |
| CC6.3-03 | Transit encryption (Redis) | `rediss://` TLS enforced in production; startup panic on `redis://` | `controller/src/main.rs` line ~178 |
| CC6.3-04 | Transit encryption (NATS jobs) | Secrets encrypted with AES-256-GCM before NATS transmission; separate encryption per job | `talos-workflow-job-protocol/src/lib.rs` (EncryptedSecrets; sibling repo `../talos-workflow-engine/talos-workflow-job-protocol/`) |
| CC6.3-05 | KEK management (production) | HashiCorp Vault transit engine; KEK never enters controller process memory; transit token scoped to encrypt+decrypt on `talos-kek` only; rotation via `vault transit/keys/talos-kek/rotate` | `controller/src/secrets/vault_kek_provider.rs`, runbook §2.1.1 |
| CC6.3-05a | KEK management (dev only) | Env var or Docker secret file mount (`TALOS_MASTER_KEY` / `TALOS_MASTER_KEY_FILE`); 256-bit; Zeroizing memory; NOT for production | `controller/src/config.rs`, `controller/src/secrets/kek_provider.rs::EnvKekProvider` |
| CC6.3-05b | Pluggable KEK abstraction | `KekProvider` trait isolates KEK backend from call sites; switching env↔Vault is a config flip + dual-wrap migration, not a code change | `controller/src/secrets/kek_provider.rs` |
| CC6.3-06 | TOTP seed encryption | TOTP secrets encrypted via SecretsManager before DB storage | `controller/src/totp_2fa.rs` |
| CC6.3-07 | OAuth token encryption | OAuth tokens encrypted before storage; plaintext columns dropped (migration 036) | `controller/src/oauth/credentials.rs`, `migrations/036_drop_plaintext_tokens.sql` |
| CC6.3-08 | Webhook signing secret encryption | Stored encrypted via envelope encryption | `migrations/20260312000200_encrypt_webhook_signing_secrets.sql` |
| CC6.3-09 | DEK caching with TTL | In-memory DashMap cache; configurable TTL (default 300s via DEK_CACHE_TTL_SECS) | `controller/src/secrets/mod.rs` (CachedDek) |
| CC6.3-10 | Actor memory at-rest encryption | AES-256-GCM envelope encryption on `actor_memory.value_enc` + `value_key_id` (NOT NULL); plaintext `value` column dropped Phase B 2026-04-24 | `talos-memory/src/lib.rs` (MemoryCryptoHook), migrations `20260423235406` + `20260424010000` |
| CC6.3-11 | Module-execution payload encryption | AES-256-GCM envelope encryption on `module_executions.{input_data, output_data, trigger_metadata}_enc` + shared `payload_enc_key_id`; all writers route through `module_payload_encryption::encrypt_payload_bundle` | `controller/src/module_payload_encryption.rs`, migration `20260424030501` |
| CC6.3-12 | Workflow-execution output encryption | AES-256-GCM envelope encryption on `workflow_executions.output_data_enc` + `output_enc_key_id`; all writer paths route through encryption-aware methods | `controller/src/execution_repository.rs::mark_execution_completed`, `mark_execution_waiting`, `mark_execution_failed` |
| CC6.3-13 | Per-actor LLM data-egress ceiling | `actors.max_llm_tier` (tier1/tier2) HMAC-bound in JobRequest + PipelineJobRequest signing; enforced at 5 worker surfaces (`llm::*`, `wit_http`, `wit_graphql`, `wit_webhook`, HTTP-stream) + vault-header gate; tier changes audit-logged | `worker/src/host_impl.rs::decide_llm_tier_access`, migration `20260424100000`, runbook §1.3 |
| CC6.3-14 | Supply-chain integrity | `cargo deny check` (RUSTSEC + license + ban + source policy) + `cargo audit` gated in CI; every Docker image pinned by SHA-256 digest; weekly Dependabot bumps grouped by domain; SLSA L2 cosign-signed release images with SBOM + provenance attestations | `deny.toml`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `scripts/verify-image.sh`, `.github/dependabot.yml` |

**Testing procedure:**
1. Query `secrets` table directly -- verify all values are encrypted blobs (not plaintext)
2. Verify Redis connection uses `rediss://` in production
3. Query `encryption_keys` table -- verify `encrypted_key` column contains ciphertext
4. Run `scripts/soc2/verify-controls.sql` -- check no plaintext secrets exist

### CC6.6 -- System Boundaries

**Criteria:** The entity implements logical access security measures to protect against threats from sources outside its system boundaries.

| Control ID | Control Description | Implementation | Evidence Location |
|-----------|-------------------|----------------|-------------------|
| CC6.6-01 | WASM sandbox isolation | wasmtime sandbox with 9-tier capability worlds; no ambient host access | `worker/src/runtime.rs`, `controller/src/compilation/mod.rs` |
| CC6.6-02 | SSRF protection | `check_outbound_url_no_ssrf()` blocks RFC1918, link-local, cloud metadata, IPv6 ULA | `controller/src/mcp/utils.rs` |
| CC6.6-03 | Per-IP rate limiting | governor crate; 300/min API, 5/min auth; configurable via env vars | `controller/src/rate_limit.rs` |
| CC6.6-04 | Distributed rate limiting | Redis sliding window; per-user MCP 5000/min, per-agent MCP 1000/min | `controller/src/distributed_ratelimit.rs` |
| CC6.6-05 | Compilation sandbox | Containerized build (Podman, --network=none); crate allowlist; cargo-audit gate | `controller/src/compilation/mod.rs` |
| CC6.6-06 | CSRF protection | Double-submit cookie pattern; constant-time comparison; SameSite=Strict | `controller/src/csrf.rs` |
| CC6.6-07 | Webhook authentication | HMAC-SHA256 signatures; timestamp replay window; IP allowlists; circuit breaker | `controller/src/webhook_security.rs`, `controller/src/webhooks/mod.rs` |
| CC6.6-08 | Rhai sandbox | eval disabled; import blocked; max_operations 1000; max_call_levels 16; max_string_size 64KB | `controller/src/engine/rhai_helpers.rs` |
| CC6.6-09 | Input size limits | GraphQL: mock_inputs 1MB, scripts 100KB; Rhai: context 1MB | `controller/src/api/schema/workflows/mutations.rs`, `controller/src/api/schema/workflows/queries.rs` |
| CC6.6-10 | CORS restrictions | Explicit origin allowlist; wildcard and "null" blocked in production | `controller/src/config.rs` (get_allowed_origins) |

**Testing procedure:**
1. Deploy WASM module requesting `governance-node` world as non-admin actor -- verify rejection
2. Configure webhook URL to `http://169.254.169.254` -- verify SSRF block
3. Send 301 requests in 60 seconds from single IP -- verify rate limit
4. Submit Rhai script with `eval("malicious")` -- verify rejection

---

## CC7: System Operations

### CC7.1 -- Detection and Monitoring

**Criteria:** To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in the introduction of new vulnerabilities.

| Control ID | Control Description | Implementation | Evidence Location |
|-----------|-------------------|----------------|-------------------|
| CC7.1-01 | Immutable audit logs | 4 audit tables with BEFORE UPDATE/DELETE triggers; SQLSTATE 42501 on modification | `migrations/20260408000001_audit_log_immutability.sql` |
| CC7.1-02 | Prometheus metrics | Webhook requests, auth attempts, execution counts, rate limit hits, cache stats, DLQ drops | `controller/src/metrics.rs` (TalosMetrics) |
| CC7.1-03 | OpenTelemetry tracing | Per-tenant OTLP export; LRU tracer cache (100 providers); configurable endpoint | `controller/src/audit_ledger.rs` |
| CC7.1-04 | Structured logging | `tracing` crate with JSON output; span context; structured fields | Throughout controller and worker |
| CC7.1-05 | Secret access audit | Every secret access logged to `secret_audit_log` (key_path, requestor, timestamp) | `controller/src/secrets/mod.rs` |
| CC7.1-06 | Admin event log | Privileged operations recorded (MCP agent registration/revocation, actor changes) | `migrations/20260407000001_admin_event_log.sql` |
| CC7.1-07 | Auth audit log | Login/logout events with IP, user-agent, success/failure | `controller/src/auth/mod.rs` |
| CC7.1-08 | NATS audit streaming | Real-time audit event stream to external SIEM via JetStream | `controller/src/audit_ledger.rs` |

**Testing procedure:**
1. Attempt `UPDATE audit_events SET ...` -- verify trigger rejection
2. Run `scripts/soc2/collect-evidence.sh` -- verify audit exports contain expected entries
3. Verify Prometheus `/metrics` endpoint returns expected metric families
4. Check `secret_audit_log` after secret access -- verify entry exists

### CC7.2 -- Anomaly Detection

**Criteria:** The entity monitors system components for anomalies that are indicative of malicious acts, natural disasters, and errors of concern.

| Control ID | Control Description | Implementation | Evidence Location |
|-----------|-------------------|----------------|-------------------|
| CC7.2-01 | DLP/PII redaction | `BuiltinDlpProvider` regex patterns (SSN, credit card with Luhn, email, phone); applied to audit payloads | `controller/src/dlp.rs` |
| CC7.2-02 | External DLP integration | `ExternalDlpProvider` webhook for enterprise DLP systems | `controller/src/dlp.rs` (ExternalDlpProvider) |
| CC7.2-03 | Circuit breaker on webhooks | Failure type tracking (auth failure, IP not allowed); automatic circuit open on repeated failures | `controller/src/webhooks/mod.rs` |
| CC7.2-04 | Authentication failure tracking | `failed_login_attempts` counter per user; locked_until timestamp; Prometheus auth_failures_total | `controller/src/auth/mod.rs`, `controller/src/metrics.rs` |
| CC7.2-05 | Webhook DLQ | Failed webhook deliveries queued in Dead Letter Queue; replay capability with admin authentication | `controller/src/webhooks/mod.rs` |
| CC7.2-06 | Secret tier-2 exposure flag | `__secret_tier2_exposed__` injected into execution output when raw secret value exits vault | `worker/src/runtime.rs` |
| CC7.2-07 | Wildcard secret grant detection | Platform hygiene report flags modules with wildcard (`*`) secret access | `controller/src/mcp/platform.rs` |
| CC7.2-08 | Execution anomaly alerts | Alert table for execution failures; alert counts tracked | `migrations/20260314000100_add_alerts_table.sql` |

**Testing procedure:**
1. Submit audit log entry containing SSN pattern -- verify redacted in stored record
2. Trigger 5+ webhook auth failures from single IP -- verify circuit breaker opens
3. Check platform hygiene report for wildcard secret grant warnings
4. Verify DLQ contains failed deliveries after simulated webhook endpoint downtime

---

## CC8: Change Management

### CC8.1 -- Changes to Infrastructure and Software

**Criteria:** The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure and software.

| Control ID | Control Description | Implementation | Evidence Location |
|-----------|-------------------|----------------|-------------------|
| CC8.1-01 | Database migration system | Timestamped migration files; `IF NOT EXISTS` / `IF EXISTS` for idempotency; never modify applied migrations | `migrations/` directory |
| CC8.1-02 | Compile-time SQL validation | sqlx offline mode; compile-time query checking | `controller/Cargo.toml` (sqlx feature flags) |
| CC8.1-03 | Dependency vulnerability scanning | `cargo-audit` gate during module compilation; known CVEs block build | `controller/src/compilation/mod.rs` |
| CC8.1-04 | Crate allowlist | Only pre-approved Rust crates compile; reqwest explicitly blocked | `controller/src/mcp/utils.rs`, `controller/src/mcp/tests.rs` |
| CC8.1-05 | Environment-aware configuration | `config::is_production()` gates debug features, introspection, TLS enforcement | `controller/src/config.rs` |
| CC8.1-06 | Migration service | Docker Compose migrate service (one-shot, runs `sqlx migrate run`); controller depends on completion | `docker-compose.yml` |
| CC8.1-07 | Version tracking | `CARGO_PKG_VERSION` from `controller/Cargo.toml`; `TALOS_VERSION` env override | `controller/Cargo.toml`, MCP `get_platform_info` tool |

**Testing procedure:**
1. Verify migration checksums match between environments
2. Confirm `cargo-audit` rejects a module with a known-vulnerable dependency
3. Attempt to add `reqwest` as dependency in module -- verify compilation rejection
4. Verify `is_production()` returns correct value per environment

---

## CC9: Risk Mitigation

### CC9.1 -- Risk Assessment and Mitigation

| Control ID | Control Description | Implementation | Evidence Location |
|-----------|-------------------|----------------|-------------------|
| CC9.1-01 | Workflow risk assessment | `get_workflow_risk_assessment` evaluates secret access patterns, capability levels, dependency risks | `controller/src/mcp/advanced.rs` |
| CC9.1-02 | Platform hygiene report | `get_platform_hygiene_report` checks wildcard secrets, unused modules, configuration drift | `controller/src/mcp/platform.rs` |
| CC9.1-03 | Workflow validation | `validate_workflow` checks secret allowlists, vault path permissions, module compatibility | `controller/src/mcp/workflows.rs` |
| CC9.1-04 | Quickstart readiness check | `get_workflow_quickstart` surfaces blockers (missing secrets, wrong capability world, vault access denied) | `controller/src/mcp/workflows.rs` |

---

## Evidence Collection

### Automated Evidence

| Evidence Type | Collection Method | Frequency |
|--------------|-------------------|-----------|
| Audit log exports | `scripts/soc2/collect-evidence.sh` | Monthly (90-day rolling) |
| Control verification | `scripts/soc2/verify-controls.sql` | Monthly |
| Dependency audit | `cargo audit` in CI/CD pipeline | Every build |
| Metric snapshots | Prometheus scrape + Grafana dashboards | Continuous |

### Manual Evidence

| Evidence Type | Responsible Party | Frequency |
|--------------|-------------------|-----------|
| Access review | Platform admin | Quarterly |
| Penetration test | External firm | Annual |
| Threat model review | Security team | Quarterly / after changes |
| Incident response drill | Operations team | Semi-annual |

---

## Gap Analysis and Remediation Plan

| Gap | SOC 2 Criteria | Current State | Remediation | Priority |
|-----|---------------|---------------|-------------|----------|
| No HSM/KMS for master key | CC6.3 | Env var / file-based | Integrate AWS KMS or HashiCorp Vault for KEK management | High |
| No mandatory API key expiry | CC6.2 | Keys are long-lived | Add `expires_at` field and rotation reminders | Medium |
| No WAF/CDN rate limiting | CC6.6 | Application-level only | Deploy Cloudflare/AWS WAF for DDoS protection | Medium |
| No pgaudit extension | CC7.1 | Trigger-based audit protection | Enable pgaudit for DB-level statement logging | Low |
| No U2F/WebAuthn support | CC6.1 | TOTP only | Add hardware security key support | Low |
| No automated access reviews | CC6.1 | Manual process | Build automated access certification workflow | Medium |

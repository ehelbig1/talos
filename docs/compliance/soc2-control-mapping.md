# SOC 2 Type II Control Mapping -- Talos Platform

**Document version:** 1.1
**Date:** 2026-09-16 (last reviewed against the code; first issued 2026-04-08)
**Framework:** AICPA Trust Services Criteria (2017)
**Classification:** CONFIDENTIAL -- for auditor use.

---

## Overview

This document maps Talos platform security controls to SOC 2 Trust Services Criteria (TSC). Each control includes a description, implementation details, evidence location, and testing procedure. Where a control is production-only, env-configurable, opt-in or partial, the row says so; controls that do not exist in code are listed under the Gap Analysis instead of as controls.

---

## CC6: Logical and Physical Access Controls

### CC6.1 -- Logical Access Security

**Criteria:** The entity implements logical access security software, infrastructure, and architectures over protected information assets.

| Control ID | Control Description | Implementation | Evidence Location |
|-----------|-------------------|----------------|-------------------|
| CC6.1-01 | JWT-based session authentication | JWT signed HS256 by default (`JWT_ALGORITHM` also accepts RS256 / ES256; HS256 requires a `JWT_SECRET` of at least 32 bytes); issuer `talos` and `exp` validated; 15-min access-token TTL; session cookies are HttpOnly + SameSite=Strict, and carry `Secure` only when `RUST_ENV=production` | `talos-auth/src/lib.rs` (`verify_token`), `talos-api/src/schema/auth/mod.rs::set_session_cookies` |
| CC6.1-02 | Role-based access control | Four authorization layers, no global Admin/User role: (1) organization roles Viewer / Member / Admin / Owner (`check_resource_access` requires Viewer to read and Member to write an org resource); (2) a per-user platform-admin flag `users.is_platform_admin` (`require_platform_admin`) for cross-tenant operations; (3) API-key scopes (CC6.1-03, `require_scope`); (4) MCP agent capabilities, where `AgentIdentity::is_admin()` is true for a `*` or `admin` capability | `talos-auth-types/src/org_role.rs::OrgRole`, `talos-api/src/schema/mod.rs` (`require_platform_admin`, `check_resource_access`, `require_scope`), `talos-mcp-handlers/src/auth.rs::AgentIdentity` |
| CC6.1-03 | API key scoped access | 6 scopes (workflows:read/write, secrets:read/write, webhooks:access, admin); key hashed with bcrypt before storage | `talos-auth-types/src/scope.rs::ApiKeyScope`, `talos-api-keys/src/lib.rs` |
| CC6.1-04 | WASM capability world enforcement | 12-world capability lattice restricts host function access per module; checked at compile time and runtime | `talos-capability-world/src/lib.rs` (ceiling_permits), `talos-compilation/src/lib.rs`, `talos-worker-runtime/src/runtime.rs` |
| CC6.1-05 | Per-module secret allowlists | Empty `allowed_secrets` denies every secret; a module can only resolve paths its allowlist permits (exact path, `prefix/` subpath, or `*`); LLM-provider key paths are host-reserved and denied to guest code even under `*`; wildcard (`*`) grants are flagged in the platform hygiene report | `talos-workflow-job-protocol/src/lib.rs::vault_path_permitted`, `talos-worker-runtime/src/host/vault.rs` (`check_secret_allowlist`), `talos-hygiene-service/src/lib.rs` |
| CC6.1-06 | Actor budget enforcement | 9 numeric per-actor budget fields plus an `on_budget_exceeded` policy; explicitly supplied values must be positive integers. Six are enforced: `max_executions_per_hour`, `max_executions_total`, `max_workflows_per_minute`, `max_fuel_per_hour` and `max_llm_tokens_per_day` at execution-row creation — by one in-transaction check that every start path runs (trigger, schedule, webhook, enqueue batch, continuation, replay, retry, handoff, test runs; chain starts before dispatch, not atomically with their row) — and `max_workflow_count` at workflow creation. Three are stored but NOT enforced: `max_fuel_per_execution`, `max_compilations_per_hour`, `max_outbound_requests_per_hour` | `talos-mcp-handlers/src/actor.rs` (`set_actor_budget`), `talos-actor-budget-refusal/src/admission.rs::admit_actor_budget`, `talos-workflow-repository/src/executions.rs::create_execution_under_concurrency_limit`, `talos-actor-repository/src/budget_precheck.rs`, `talos-workflow-authorization/src/lib.rs` |
| CC6.1-07 | GraphQL query limits | Depth limit 15; complexity limit 5000 (both hardcoded); introspection disabled when `RUST_ENV=production` | `controller/src/bootstrap/services.rs` (schema builder) |

**Testing procedure:**
1. Verify JWT validation rejects expired, wrong-issuer, and tampered tokens
2. Confirm a user without `users.is_platform_admin` is refused on a platform-admin operation (e.g. the `verifyAuditChain` query)
3. Verify API key with `workflows:read` scope cannot write workflows
4. Attempt to access a secret from a module without allowlist entry

### CC6.2 -- Prior to Issuing System Credentials

**Criteria:** Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users.

| Control ID | Control Description | Implementation | Evidence Location |
|-----------|-------------------|----------------|-------------------|
| CC6.2-01 | Password complexity enforcement | 12-72 characters; 2-of-4 character classes (upper, lower, digit, symbol) | `talos-auth/src/lib.rs` (validate_password fn) |
| CC6.2-02 | Email format validation | Regex validation; 254-char max | `talos-auth/src/lib.rs` (validate_email fn) |
| CC6.2-03 | Password hashing | bcrypt; cost from `BCRYPT_COST` (default 12, bcrypt's `DEFAULT_COST`); the auth service refuses to start with a cost outside 10-14 | `controller/src/bootstrap/services.rs`, `talos-auth/src/lib.rs` (`AuthService::new`) |
| CC6.2-04 | TOTP 2FA enrollment | TOTP seed encrypted via SecretsManager before storage; QR code provisioning | `talos-totp-2fa/src/lib.rs` (TotpService) |
| CC6.2-05 | API key generation | 32 random bytes plus a 4-byte random prefix from the OS RNG; format `talos_sk_<8-hex prefix><64-hex secret>`; stored as a bcrypt hash (`API_KEY_BCRYPT_COST`, default 12, below 10 refused in production); validation looks up candidate rows by the stored 8-hex `key_prefix`, then bcrypt-verifies the full key | `talos-api-keys/src/lib.rs` (`generate_key`, `validate_key`) |
| CC6.2-06 | Account lockout | 5 wrong passwords — at login or as the current password of a password change, one counter — lock the account for 15 minutes (`locked_until`); 5 failed 2FA attempts lock 2FA verification for 15 minutes, counted in Redis so the limit holds across controller instances (production refuses verification when Redis is unavailable; the in-memory counter is a development fallback) | `talos-auth/src/lib.rs`, `talos-totp-2fa/src/lib.rs` |
| CC6.2-07 | Secret rotation support | DEK rotation (create new, re-encrypt) + master-key rotation, both operator-invoked; secret value rotation via the GraphQL secrets mutations | `talos-secrets-manager` (`rotate_dek`, `rotate_dek_for_org`, `rotate_master_key`, `rotate_secret_value_by_id`), `talos-api/src/schema/security/mutations.rs` (`rotateDek`, `rotateOrgDek`, `rotateMasterKey`, `rotateEncryptionKey`, the `reEncrypt*` sweeps, which re-key rows under a retired org DEK) |
| CC6.2-08 | Step-up authentication for privileged operations | Key-material and privilege-granting operations (master-key and DEK rotation, re-encryption sweeps, API-key creation and rotation, MCP agent registration, capability grants, audit settings, ownership transfer) require an interactive session whose second factor was verified and is still enrolled; API keys are refused. Enabling 2FA signs out the account's earlier sessions. An API key cannot set up, enable or verify 2FA, and `verifyTwoFactor` completes only a session waiting for its code, so a key cannot obtain such a session (it could until 2026-09-25). Every check is counted on `talos_privileged_op_total{outcome}` since 2026-09-23 — `permitted` plus six refusal reasons, all pre-seeded at 0, recorded at one site so an admitted call and a refused one are both on the record; a rule that cannot be READ is its own `unreadable` value and REFUSES, never grants. The cross-tenant gate beside it counts `talos_platform_admin_checks_total{outcome}` the same way. No alert references either series yet: a threshold needs a baseline they have not produced | `talos-api/src/schema/mod.rs` (require_second_factor, require_platform_admin), `talos-auth-types/src/claims.rs` (SessionAuth), `talos-metrics/src/security.rs` (PrivilegedOpOutcome, PlatformAdminOutcome) |
| CC6.2-09 | Session revocation | Refresh tokens (7-day cookie) are stored as a bcrypt hash plus a SHA-256 lookup hash, rotated on every use, and reuse of a rotated token is detected; single-session and all-session revocation revoke refresh tokens. An already-issued access JWT is not checked against the session table and stays valid until its 15-minute expiry. Reuse past a 5-second tab-race grace window revokes every session for the affected user, writes an `auth_audit_log` row and counts on `talos_auth_token_reuse_total{outcome}` (`detected` / `revoke_failed` — the response ran or did not — alerted at `critical`); a failure of the detector's OWN read is reported as `detector_unreadable`, never as no-reuse, and whether each rotation armed the detector is counted on `talos_auth_rotation_audit_arm_total{outcome}`. Until 2026-09-21 the whole control emitted one log line on a tracing target nothing subscribed to, and a read failure was indistinguishable from "no reuse record" | `talos-auth/src/lib.rs` (`refresh_access_token`, `classify_token_reuse`, `revoke_refresh_token`, `revoke_all_sessions`), `talos-metrics/src/security.rs` (`TokenReuseOutcome`, `RotationAuditArmOutcome`) |
| CC6.2-10 | Password change | A signed-in user changes their own password (`changePassword`, Settings → Password) with the current password; an API key cannot, a session waiting for its 2FA code cannot, and on an account with 2FA enrolled only a session that verified it can. The new hash, the lockout-counter reset, the revocation of every session of the account and the `password_change` row in `auth_audit_log` commit in ONE transaction (all or nothing); the hash is replaced only if it is still the one just verified, so a concurrent change is refused, not overwritten. Refused attempts are recorded as `password_change_failed` and counted on `talos_password_changes_total{outcome}`. Access tokens already issued remain valid until their 15-minute expiry. No self-service password reset exists | `talos-auth/src/lib.rs` (`change_password`, `password_matches`), `talos-api/src/schema/auth/mutations.rs` (`change_password`) |

**Testing procedure:**
1. Attempt registration with weak password (< 12 chars, single char class)
2. Verify locked account cannot authenticate
3. Confirm TOTP seed is encrypted in database (not plaintext)
4. Verify refresh token rotation on each use

### CC6.3 -- Encryption of Data

**Criteria:** The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles.

| Control ID | Control Description | Implementation | Evidence Location |
|-----------|-------------------|----------------|-------------------|
| CC6.3-01 | Envelope encryption for secrets | AES-256-GCM; DEK wrapped by KEK provider; **per-context HKDF-SHA256 subkey derived per row** (`HKDF(DEK, info=secret_id)`) so each key encrypts ~1 message and the random-nonce birthday bound is never approached; format v4 (the secret's organization root DEK) when the row has an org, format v3 (the global DEK) otherwise; AAD-bound; random 12-byte nonce per operation | `talos-secrets-manager/src/manager.rs` (`encrypt_value_aad_v4_or_global`, `derive_per_context_subkey`) |
| CC6.3-02 | Transit encryption (client) | The Helm chart's ingresses terminate TLS (cert-manager issuer annotation + TLS secret); the SPA's nginx sends `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every response (not environment-gated). The chart does not configure an HTTP-to-HTTPS redirect; that is the ingress controller's behaviour | `deploy/helm/talos/values.yaml` (`frontend.ingress`, `controller.ingress`), `deploy/helm/talos/templates/frontend/configmap.yaml`, `frontend/nginx.conf` |
| CC6.3-03 | Transit encryption (Redis) | `rediss://` TLS enforced when `RUST_ENV=production`; the controller panics at startup on a `redis://` URL | `controller/src/bootstrap/services.rs` (`tls-prod-gate-redis`) |
| CC6.3-04 | Transit encryption (NATS jobs) | Secrets encrypted with AES-256-GCM before NATS transmission under a **per-job HKDF subkey derived from `WORKER_SHARED_KEY`** (label `envelope-aead/v2-per-job`; per-context key separation; ~1 message per key) | `talos-workflow-job-protocol/src/lib.rs` (EncryptedSecrets) |
| CC6.3-05 | KEK management (production) | HashiCorp Vault transit engine (`KEK_PROVIDER=vault`, the Helm chart default; the code default is `env`); KEK never enters controller process memory; the chart-minted controller token's policy grants `update` on `transit/encrypt/<key>` and `transit/decrypt/<key>` and `read` on `transit/keys/<key>` (key name `VAULT_TRANSIT_KEY_NAME`, default `talos-kek`); rotation via `vault transit/keys/talos-kek/rotate` | `talos-secrets-manager/src/vault_kek_provider.rs`, `deploy/helm/talos/templates/vault/init-job.yaml`, runbook §2.1.1 |
| CC6.3-05a | KEK management (env) | Env var or Docker secret file mount (`TALOS_MASTER_KEY` / `TALOS_MASTER_KEY_FILE`); 256-bit (any other length rejected); held in Zeroizing memory. When `RUST_ENV=production` the controller refuses to boot with `KEK_PROVIDER=env` unless `TALOS_ALLOW_ENV_KEK` is set to true/1/yes/on, and logs an ERROR (`env_kek_in_production`) when that override is used | `talos-config/src/lib.rs`, `talos-secrets-manager/src/kek_provider.rs::EnvKekProvider`, `controller/src/bootstrap/services.rs` (`prod-kek-guard`) |
| CC6.3-05b | Pluggable KEK abstraction | `KekProvider` trait isolates KEK backend from call sites; switching env↔Vault is a config flip + dual-wrap migration, not a code change | `talos-secrets-manager/src/kek_provider.rs` |
| CC6.3-06 | TOTP seed encryption | TOTP secrets encrypted via SecretsManager before DB storage | `talos-totp-2fa/src/lib.rs` |
| CC6.3-07 | OAuth token encryption | OAuth tokens encrypted before storage; plaintext columns dropped (migration 036) | `talos-oauth/src/credentials.rs`, `migrations/036_drop_plaintext_tokens.sql` |
| CC6.3-08 | Webhook signing secret encryption | Stored encrypted via envelope encryption | `migrations/20260312000200_encrypt_webhook_signing_secrets.sql` |
| CC6.3-09 | DEK caching with TTL | In-memory DashMap cache; configurable TTL (default 300s via DEK_CACHE_TTL_SECS) | `talos-secrets-manager/src/manager.rs` (CachedDek) |
| CC6.3-10 | Actor memory at-rest encryption | AES-256-GCM on `actor_memory.value_enc` + `value_key_id` (NOT NULL) under a **per-context HKDF subkey** (`info = actor_id‖0x00‖key`); format v4 (the actor's organization root DEK) when the actor has an org, v3 (global DEK) otherwise; plaintext `value` column dropped Phase B 2026-04-24 | `talos-memory/src/lib.rs` (MemoryCryptoHook), `talos-memory-crypto/src/lib.rs`, migrations `20260423235406` + `20260424010000` + `20260617120000` |
| CC6.3-11 | Module-execution payload encryption | AES-256-GCM on `module_executions.{input_data, output_data, trigger_metadata}_enc` + shared `payload_enc_key_id` under a **per-context HKDF subkey** (`info = execution_id‖0x00‖slot`); format v4 when the owning workflow's org resolves, v3 (global DEK) otherwise; the start writers seal through `module_payload_encryption::encrypt_payload_bundle` and all three completion writers (the engine store, `complete_execution`, `complete_execution_from_worker`) through `encrypt_output_for_row`, under the key and format the row already names. Until 2026-09-21 `complete_execution_from_worker` — the completion path of module-bound webhooks and pushes — stored its DLP-redacted output in the plaintext column (3 of 34 153 outputs in 30 days on the reference deployment); rows written before that date are NOT re-sealed: the fix is forward-only, and the plaintext backfill (`controller/examples/backfill_module_payload_encryption.rs`) selects `payload_enc_key_id IS NULL`, which these rows do not satisfy because their input was sealed; they stay plaintext until an operator clears them or enables the module-payload retention sweep (`MODULE_PAYLOAD_RETENTION_ENABLED`, default off) | `talos-module-payload-encryption/src/lib.rs`, migrations `20260424030501` + `20260617120000` |
| CC6.3-12 | Workflow-execution output encryption | AES-256-GCM on `workflow_executions.output_data_enc` + `output_enc_key_id` under a **per-context HKDF subkey** (`info = execution_id`); format v4 when the workflow has an org, v3 (global DEK) otherwise. Applies when the finalizing repository holds a SecretsManager (`ExecutionRepository` additionally honours `TALOS_ENCRYPT_EXECUTION_OUTPUT`, default on); otherwise a DLP-redacted plaintext output is stored in `output_data` | `talos-execution-repository/src/lib.rs::mark_execution_completed`, `mark_execution_waiting`, `mark_execution_failed`, `talos-workflow-repository/src/executions.rs`, `talos-execution-finalizer/src/lib.rs` |
| CC6.3-13 | Per-actor LLM data-egress ceiling | `actors.max_llm_tier` (tier1/tier2) HMAC-bound in JobRequest + PipelineJobRequest signing; enforced at 5 worker surfaces (`llm::*`, `wit_http`, `wit_graphql`, `wit_webhook`, HTTP-stream) + vault-header gate; tier changes audit-logged | `talos-worker-runtime/src/host/llm.rs::decide_llm_tier_access`, migration `20260424100000`, runbook §1.3 |
| CC6.3-14 | Supply-chain integrity | `make audit` runs `cargo deny check` (RUSTSEC advisories + licenses + bans + sources), a secret-pattern scan and a migration-idempotency check in `quality.yml` on every pull request to main, every push to main, and nightly. `cargo audit` runs only in `ci.yml`, which is `workflow_dispatch`-only. Every container image reference is pinned by SHA-256 digest — Dockerfile `FROM` / `COPY --from`, compose and workflow `image:` values, Helm values image blocks, and `docker run`/`pull` arguments in scripts (including the CI integration runner) — and one `repository:tag` names one digest across the tree, enforced by structural lint check 93 (`scripts/lint-image-pins.py`) on every pull request; the only unpinned references are an image this repository builds locally and a probe that runs only when its image is already present, each carrying an `allow-unpinned-image` marker. Images named in Rust source (the compilation sandbox's `TALOS_BUILDER_IMAGE` default, a locally built image) are outside the check. Weekly Dependabot bumps grouped by domain, including digest updates for the root, `controller/`, `worker/` and `frontend/` Dockerfiles. `release.yml` produces cosign-signed images with SBOM + SLSA provenance attestations and `main-publish.yml` produces cosign-signed images with buildx provenance; both are `workflow_dispatch`-only | `deny.toml`, `Makefile` (`audit` target), `.github/workflows/quality.yml`, `.github/workflows/release.yml`, `.github/workflows/main-publish.yml`, `scripts/verify-image.sh`, `.github/dependabot.yml`, `worker/Dockerfile`, `docker-compose.yml`, `scripts/lint-image-pins.py` |

**Testing procedure:**
1. Query `secrets` table directly -- verify all values are encrypted blobs (not plaintext)
2. Verify Redis connection uses `rediss://` in production
3. Query `encryption_keys` table -- verify `encrypted_key` column contains ciphertext
4. Run `scripts/soc2/verify-controls.sql` -- check no plaintext secrets exist

### CC6.6 -- System Boundaries

**Criteria:** The entity implements logical access security measures to protect against threats from sources outside its system boundaries.

| Control ID | Control Description | Implementation | Evidence Location |
|-----------|-------------------|----------------|-------------------|
| CC6.6-01 | WASM sandbox isolation | wasmtime sandbox with a 12-world capability lattice; no ambient host access | `talos-worker-runtime/src/runtime.rs`, `talos-compilation/src/lib.rs` |
| CC6.6-02 | SSRF protection | `check_outbound_url_no_ssrf()` blocks RFC1918, link-local, cloud metadata, IPv6 ULA | `talos-http-utils/src/ssrf.rs` |
| CC6.6-03 | Per-IP rate limiting | In-process `governor` limiters, per controller replica: per-IP API limit `API_RATE_LIMIT` (default 100/min, burst `API_RATE_LIMIT`/5, minimum 10), per-IP webhook limit `WEBHOOK_RATE_LIMIT` (default 60/min), global limit `GLOBAL_RATE_LIMIT` (default 1000/min). The per-IP limiters are skipped unless `RUST_ENV=production` or `ENFORCE_RATE_LIMITS_IN_DEV` is set. Auth mutations (signup, login and siblings) use a separate limiter: 5 requests per 60 s per client IP (hardcoded), counted in Redis and fail-closed in production (a Redis error rejects the request) | `controller/src/bootstrap/services.rs` (`build_rate_limiters`, auth limiter), `talos-rate-limit/src/middleware.rs` (`rate_limit_middleware`, `DistributedRateLimiter`), `talos-api/src/schema/auth/mutations.rs` |
| CC6.6-04 | MCP rate limiting | Per-user MCP limit `MCP_USER_RATE_LIMIT_PER_MIN` (default 5000/min) and per-agent limit `MCP_AGENT_RATE_LIMIT_PER_MIN` (default 1000/min), each an in-process fixed 60-second window per controller replica (not Redis-backed); MCP authentication has a per-IP limit `MCP_AUTH_RATE_LIMIT` (default 60 per `MCP_AUTH_RATE_WINDOW`, default 60 s) | `talos-mcp-handlers/src/lib.rs` (`AgentRateLimiter`), `talos-mcp-handlers/src/auth.rs` |
| CC6.6-05 | Compilation sandbox | Containerized build (Podman preferred, Docker fallback) with `--network=none` and `--read-only`; containerized compilation defaults on when `RUST_ENV=production` (`TALOS_COMPILATION_CONTAINER`); in production a host compile — a missing container runtime or `TALOS_COMPILATION_CONTAINER=false` — is refused unless `TALOS_COMPILATION_ALLOW_HOST_FALLBACK=acknowledge-single-tenant-rce-risk`, and an acknowledged one logs a `compilation_unsandboxed_fallback` WARN. Crate allowlist; cargo-audit gate | `talos-compilation/src/container.rs` (`build_command`), `talos-compilation/src/dependency_allowlist.rs`, `talos-compilation/src/lib.rs` |
| CC6.6-06 | CSRF protection | Double-submit cookie pattern; constant-time comparison; SameSite=Strict | `talos-csrf/src/lib.rs` |
| CC6.6-07 | Webhook authentication | HMAC-SHA256 signatures, constant-time compare; a ±300 s timestamp replay window for the Slack and generic formats, whose signature binds the timestamp. **The GitHub format (`X-Hub-Signature-256`) signs the body alone and has NO freshness window**: its replay defence is Redis deduplication keyed on the verified signature, retained 24 h for that format and 1 h for the others, and a GitHub-format request is refused when deduplication is unconfigured or unavailable. IP allowlists; per-IP circuit breaker on authentication failures | `talos-webhooks/src/signature.rs`, `talos-webhooks/src/router.rs`, `talos-webhooks/src/rate_limiter.rs` |
| CC6.6-08 | Rhai sandbox | `eval` disabled; module resolver replaced (`import` fails); max_operations 1000 for condition/verdict expressions and 10 000 for dispatch expressions; max_call_levels 16; max_string_size 64 KiB; `print`/`debug` output discarded | `talos-rhai-sandbox/src/lib.rs` (`sandboxed_engine`) |
| CC6.6-09 | Input size limits | GraphQL: mock_inputs 1MB, scripts 100KB; Rhai: context 1MB | `talos-api/src/schema/workflows/mutations.rs`, `talos-api/src/schema/workflows/queries.rs` |
| CC6.6-10 | CORS restrictions | Explicit origin allowlist; wildcard and "null" blocked in production | `talos-config/src/lib.rs` (get_allowed_origins) |

**Testing procedure:**
1. Deploy WASM module requesting `governance-node` world as a user whose capability ceiling does not permit that world -- verify rejection
2. Configure webhook URL to `http://169.254.169.254` -- verify SSRF block
3. On a production deployment (or with `ENFORCE_RATE_LIMITS_IN_DEV` set), send more requests from a single IP than the per-IP burst (default 20) in under one second -- verify HTTP 429 (or a `RATE_LIMITED` error on `/graphql`)
4. Submit Rhai script with `eval("malicious")` -- verify rejection

---

## CC7: System Operations

### CC7.1 -- Detection and Monitoring

**Criteria:** To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in the introduction of new vulnerabilities.

| Control ID | Control Description | Implementation | Evidence Location |
|-----------|-------------------|----------------|-------------------|
| CC7.1-01 | Immutable audit logs | 7 audit tables (`auth_audit_log`, `secret_audit_log`, `admin_event_log`, `schema_audit_log`, `oauth_audit_log`, `gmail_integration_audit_log`, `slack_integration_audit_log`) with BEFORE UPDATE/DELETE row triggers AND BEFORE TRUNCATE statement triggers raising SQLSTATE 42501 (a fourth, `audit_events`, never held rows and was dropped 2026-09-11). The application's retention cleanups read the trigger from the catalog and delete nothing while it is present. The triggers do not block `TRUNCATE`, and a role that can drop the trigger can bypass them | `migrations/20260408000001_audit_log_immutability.sql`, `migrations/20260911160000_drop_dead_audit_events_table.sql`, `talos-auth/src/lib.rs` (`cleanup_audit_logs`) |
| CC7.1-01a | Audit-ledger cryptographic verification | Worker emits a per-execution HMAC-SHA256-signed SHA-256 hash chain; the WORM consumer **verifies each event's HMAC + recomputes its hash inline before S3 persist**, quarantining failures to a `rejected/` prefix instead of ACK-dropping them (an event with no signature is persisted and logged, not rejected). S3 Object Lock (Compliance mode, `TALOS_AUDIT_S3_RETENTION_DAYS`, default 2555 days) is applied only when `TALOS_AUDIT_S3_OBJECT_LOCK=true` (chart value `controller.audit.s3ObjectLock.enabled`, default false). A **continuous controller-side sweep** (`AUDIT_CHAIN_SWEEP_INTERVAL_SECS`, default 3600 s, 0 disables) runs `verify_execution_chain` over recently completed jobs and emits an `audit_chain_verification_failed` event per broken chain (sequence contiguity, `previous_hash` linkage, genesis, per-event HMAC, and the terminal anchor's committed event count, which detects a removed tail while the anchor survives; a chain with no anchor is reported separately as unanchored); a platform-admin GraphQL `verifyAuditChain(executionId)` query exposes the same verifier on demand for forensic review | `talos-audit-event/src/lib.rs` (`verify_chain`, `verify_chain_anchored`), `talos-audit-ledger/src/lib.rs` (inline verify + S3 verifier + sweep), `controller/src/bootstrap/background.rs` (sweep wiring), `talos-api/src/schema/platform/queries.rs` (`verifyAuditChain`) |
| CC7.1-02 | Prometheus metrics | Auth attempts and failures, 2FA attempts, API-key validations, MCP authentication outcomes, workflow and module execution counts, rate-limit hits, webhook DLQ drops | `talos-metrics/src/lib.rs` (TalosMetrics) |
| CC7.1-03 | OpenTelemetry tracing | Per-tenant OTLP export; LRU tracer cache (100 providers); configurable endpoint | `talos-audit-ledger/src/lib.rs` |
| CC7.1-04 | Structured logging | `tracing` crate with structured fields and span context, rendered by the plain-text `fmt` formatter (not JSON) on both binaries | `controller/src/main.rs`, `worker/src/main.rs` |
| CC7.1-05 | Secret access audit | `secret_audit_log` rows (secret_id, action, actor_type/actor_id, module_id, success, DLP-redacted failure detail, ip_address, timestamp) are written for secret create / update / delete / rotation and for single-secret reads through `SecretsManager::get_secret`, including failures. The table has no key-path column. The bulk resolution performed at job dispatch (`get_module_secrets`, `get_secrets_by_paths`, `get_llm_vault_keys`) writes no row. Inside a worker execution, host-side use of a resolved credential is recorded in the WORM ledger as `wasi:secret_use` with a SHA-256 hash of the key path, deduplicated per surface / key / destination per execution and capped at 64 events plus one suppression event | `talos-secrets-manager/src/manager.rs` (`log_audit`, `log_audit_in_tx`), `migrations/.baseline/schema.sql`, `talos-worker-runtime/src/context.rs` (`record_secret_use`) |
| CC7.1-06 | Admin event log | Privileged operations recorded in `admin_event_log`, including MCP agent registration and revocation (each committed in the same transaction as the `mcp_agents` insert / delete, so a credential is never created or removed without its record; the revocation event carries the deleted row's name, role, `created_at` and `last_connected_at`), capability-ceiling grants and revocations on every surface (GraphQL, MCP and the first-user bootstrap; the record names the ceiling granted and the one it replaced or withdrew), API-key creation / rotation / revocation / deletion / expiry, and two-factor enrolment and disable — each of these committed in the same transaction as the change it records, so a credential or privilege never changes without its record and each change is recorded once (until 2026-09-18 these records were written after the change by a detached task, the GraphQL capability-grant mutations wrote none, and every API-key change was written twice). Privilege changes are recorded the same way, with the value each replaced: actor LLM-tier / write-ceiling / egress-scope changes and actor capability-ceiling changes (the dashboard's only surface for these wrote no record before 2026-09-19), module `allowed_secrets` / `allowed_hosts` / `allowed_methods` replacements, workflow actor binding on both surfaces, and module capability-world changes by hot-update or inline recompile (recorded by the module write itself, so a failed compile records nothing). Workflow deletion is recorded the same way on every surface — MCP single / batch / prefix cleanup, hygiene `fix_all` and the dashboard's GraphQL delete — by the delete's own transaction, and the record names each workflow removed (until 2026-09-21 the MCP records were detached and carried only the id, and the dashboard delete and the hygiene fix wrote none). Module deletion is recorded the same way since 2026-09-21 — single, batch, unreferenced-module cleanup, version cleanup and hygiene `fix_all` — naming each module and its capability world (before that the batch, version-cleanup and hygiene deletes wrote no record and the cleanup record carried only a count). The operator stale-execution cleanups (the MCP tool and hygiene `fix_all`) record which runs they marked failed inside the cleanup's own transaction (until 2026-09-21 the tool's record was detached and said the runs were "hard-deleted" — they are marked `failed`, never deleted — and the hygiene cleanup wrote none). Since 2026-09-21 the remaining operator actions are recorded the same way: execution pause / resume (with the state replaced), failure-notification webhook changes (with the URL replaced), bulk archive (naming what was archived), the built-in marketplace republish, and ML policy / lifecycle / shadow-window changes. No writer records after its change any more: the detached helper and the pool-taking writer were deleted, so the only `admin_event_log` entry points take the connection that carries the change. | `migrations/20260407000001_admin_event_log.sql`, `talos-admin-event-log/src/lib.rs` (`insert_on_conn`), `talos-actor-repository/src/lib.rs` (`upsert_capability_grant`, `delete_capability_grant`, `set_actor_ceiling_recorded`, `update_actor_fields_scoped`, `insert_admin_event_log_on_conn`), `talos-module-repository/src/lib.rs` (`set_module_permission_recorded`, `mirror_module_write_recorded`, `record_module_deletes`), `talos-workflow-repository/src/workflows.rs` (`set_workflow_actor_id`, `record_workflow_deletes`, `archive_workflows_by_ids`, `set_failure_webhook_url_column`), `talos-execution-pause/src/lib.rs` (`set_execution_paused_recorded`), `talos-advanced-repository/src/lib.rs` (`republish_system_templates_recorded`), `talos-mcp-handlers/src/ml.rs` (`record_then_commit`), `talos-api-keys/src/lib.rs` (`record_key_event`), `talos-totp-2fa/src/lib.rs` (`enable_2fa`, `disable_2fa`), `talos-auth/src/bootstrap.rs` (`promote_first_user_if_needed`), `talos-api/src/schema/actors/mutations.rs` (`register_mcp_agent_recorded`, `revoke_mcp_agent_recorded`) |
| CC7.1-07 | Auth audit log | `auth_audit_log` rows with IP, user-agent and success/failure for signup, login success, login failure, account lock, token refresh, refresh-token reuse detection and password change; logout is not recorded | `talos-auth/src/lib.rs` (`log_auth_event`) |
| CC7.1-08 | NATS audit streaming | Workers publish audit events to the `AUDIT_LEDGER` JetStream stream (messages expire after 30 days); the WORM consumer verifies each event's HMAC + recomputes its hash before persisting to S3, quarantining verification failures to a `rejected/` prefix rather than ACK-dropping them. No forwarder to an external SIEM exists in the repository | `talos-audit-ledger/src/lib.rs` |

**Testing procedure:**
1. Attempt `UPDATE auth_audit_log SET success = true` -- verify trigger rejection (SQLSTATE 42501)
2. Run `scripts/soc2/collect-evidence.sh` -- verify audit exports contain expected entries
3. Verify the controller's Prometheus `/metrics/prometheus` endpoint returns expected metric families
4. Read a secret through `get_secret` and check `secret_audit_log` -- verify a `read` entry exists
5. Feed a tampered (bad-HMAC) audit event into the JetStream consumer -- verify it lands in the `rejected/` prefix and is NOT persisted to the main WORM path
6. Run `verify_execution_chain` over an exported chain with an injected sequence gap / broken `previous_hash` -- verify the break is reported

### CC7.2 -- Anomaly Detection

**Criteria:** The entity monitors system components for anomalies that are indicative of malicious acts, natural disasters, and errors of concern.

| Control ID | Control Description | Implementation | Evidence Location |
|-----------|-------------------|----------------|-------------------|
| CC7.2-01 | DLP/PII redaction | `BuiltinDlpProvider` regex patterns (SSN, credit card with Luhn, email, phone); applied to audit payloads | `talos-dlp-provider/src/lib.rs` |
| CC7.2-02 | External DLP integration | `ExternalDlpProvider` webhook for enterprise DLP systems | `talos-dlp-provider/src/lib.rs` (ExternalDlpProvider) |
| CC7.2-03 | Circuit breaker on webhooks | Per-IP, in-process breaker: 10 authentication failures (invalid signature, invalid verification token, or IP not allowed) within 300 s block that IP for 60 s; trigger-state failures (disabled, not found, rate limit, internal error) do not count | `talos-webhooks/src/rate_limiter.rs` (`CircuitBreaker`) |
| CC7.2-04 | Authentication failure tracking | `failed_login_attempts` counter per user; locked_until timestamp; Prometheus auth_failures_total | `talos-auth/src/lib.rs`, `talos-metrics/src/lib.rs` |
| CC7.2-05 | Webhook DLQ | Inbound webhook requests dropped at the circuit-breaker / rate-limit gate or failing dispatch after authentication are queued in the Dead Letter Queue. Replay (`replayWebhookDeadLetterEntry`) requires 2FA, the `workflows:write` scope and ownership of the trigger, and refuses entries captured before the request authenticated | `talos-webhooks/src/dlq.rs`, `talos-webhooks/src/router.rs`, `talos-api/src/schema/webhooks/mutations.rs` |
| CC7.2-06 | Secret tier-2 exposure | Tier-2 plaintext secret exposure (`expose-secret`) is disabled platform-wide: every dispatch path sets `allow_tier2_exposure: false` and the worker refuses the call when that flag is false. The worker keeps an in-memory `secret_tier2_exposed` flag and a WARN log for the exposed case, but nothing writes a `__secret_tier2_exposed__` marker into execution output | `talos-worker-runtime/src/host/secrets.rs`, `talos-workflow-engine/src/engine_dispatch_single.rs` |
| CC7.2-07 | Wildcard secret grant detection | Platform hygiene report flags modules with wildcard (`*`) secret access | `talos-hygiene-service/src/lib.rs`, `talos-mcp-handlers/src/analytics.rs` (`get_platform_hygiene_report`) |
| CC7.2-08 | Execution anomaly alerts | Alert table for execution failures; alert counts tracked | `migrations/20260314000100_add_alerts_table.sql` |

**Testing procedure:**
1. Submit audit log entry containing SSN pattern -- verify redacted in stored record
2. Send 10 webhook requests with invalid signatures from a single IP within 300 seconds to one controller replica -- verify further requests from that IP are refused for 60 seconds
3. Check platform hygiene report for wildcard secret grant warnings
4. Verify a DLQ entry is written when an authenticated inbound webhook fails to dispatch, and that replay of an entry captured before authentication is refused

---

## CC8: Change Management

### CC8.1 -- Changes to Infrastructure and Software

**Criteria:** The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure and software.

| Control ID | Control Description | Implementation | Evidence Location |
|-----------|-------------------|----------------|-------------------|
| CC8.1-01 | Database migration system | Timestamped migration files; `IF NOT EXISTS` / `IF EXISTS` for idempotency; never modify applied migrations | `migrations/` directory |
| CC8.1-02 | Compile-time SQL validation | `query!` macro statements are checked against the committed sqlx offline cache (`.sqlx/`, verified by `make sqlx-check` in `quality.yml`). Function-form `sqlx::query` statements are not compile-checked; they are PREPAREd against the migrated schema by `scripts/lint-sql-prepare.py` in the integration job | `controller/Cargo.toml` (sqlx feature flags), `.github/workflows/quality.yml`, `scripts/lint-sql-prepare.py` |
| CC8.1-03 | Dependency vulnerability scanning | `cargo-audit --no-fetch` gate during module compilation against an advisory database baked into the image; known CVEs block the build. The snapshot's freshness is itself a control: `check_advisory_db_age` warns at 30 days and refuses every compile in production past `TALOS_ADVISORY_DB_MAX_AGE_DAYS` (default 90), and the controller samples the age hourly onto `talos_advisory_db_age_days` (alerts `TalosAdvisoryDbAging`, `TalosAdvisoryDbExpired`, `TalosAdvisoryDbUnreadable`). Stated limit: the sampled copy is the controller's; in container mode `cargo audit` reads the builder image's own copy, built by the same pipeline but not sampled | `talos-compilation/src/advisory_db.rs`, `talos-compilation/src/lib.rs` |
| CC8.1-04 | Crate allowlist | Only pre-approved Rust crates compile; reqwest explicitly blocked | `talos-compilation/src/dependency_allowlist.rs::validate_dependencies`, `talos-mcp-handlers/src/tests.rs` |
| CC8.1-05 | Environment-aware configuration | `config::is_production()` gates debug features, introspection, TLS enforcement | `talos-config/src/lib.rs` |
| CC8.1-06 | Migration service | Docker Compose migrate service (one-shot, runs `sqlx migrate run`); controller depends on completion | `docker-compose.yml` |
| CC8.1-07 | Version tracking | MCP `get_platform_info` reports `<CARGO_PKG_VERSION>+<git sha>` (with `-dirty` for a dirty tree) from the `talos-mcp-handlers` crate, which takes the workspace version; `TALOS_VERSION` overrides it. `controller/Cargo.toml` carries its own version string, which that tool does not report | `talos-mcp-handlers/src/platform.rs`, `talos-mcp-handlers/build.rs`, `Cargo.toml` |

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
| CC9.1-01 | Workflow risk assessment | `get_workflow_risk_assessment` reports missing timeouts, missing retry configuration, missing error edges, `continue_on_error` nodes, stale modules, expiring or no-expiry secrets, high-failure sub-workflows, sandbox modules and wildcard secret grants | `talos-mcp-handlers/src/analytics.rs` |
| CC9.1-02 | Platform hygiene report | `get_platform_hygiene_report` reports undescribed workflows, workflows missing capabilities or embeddings, orphaned modules, stuck executions, dormant workflows, idle agents, orphaned secrets, API-token secrets without expiry, and wildcard secret grants | `talos-mcp-handlers/src/analytics.rs`, `talos-hygiene-service/src/lib.rs` |
| CC9.1-03 | Workflow validation | `validate_workflow` checks that referenced modules exist, graph cycles, missing required node config, and `vault://` references blocked by the module's secret allowlist | `talos-mcp-handlers/src/workflows.rs`, `talos-workflow-validation/src/lib.rs` |
| CC9.1-04 | Quickstart readiness check | `get_workflow_quickstart` surfaces per-node required-config gaps and secrets that still need provisioning, with a next-steps checklist | `talos-mcp-handlers/src/workflows.rs` |

---

## Evidence Collection

### Automated Evidence

| Evidence Type | Collection Method | Frequency |
|--------------|-------------------|-----------|
| Audit log exports | `scripts/soc2/collect-evidence.sh` | Monthly (90-day rolling) |
| Control verification | `scripts/soc2/verify-controls.sql` | Monthly |
| Dependency audit | `make audit` (`cargo deny check`, incl. RUSTSEC advisories) in `quality.yml` | Every pull request to main, every push to main, nightly |
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
| In-chart Vault key material co-located with the data it protects | CC6.3 | The chart's Vault is initialized with a single unseal key share (`-key-shares=1 -key-threshold=1`); the unseal key is written to `bootstrap.json` on the Vault data volume, alongside the transit keys, and the chart's `unsealer` sidecar reads it to unseal Vault after a pod restart. The init Job keeps no standing root token: each run generates one from the unseal key and revokes it on exit, a root token written by an earlier chart is revoked and removed, and a controller token is minted only while the bootstrap Secret holds a placeholder (`deploy/helm/talos/files/vault-init.sh`, tested against a real Vault by `scripts/tests/vault-chart-init-test.sh`). Access to the volume still yields the unseal key, from which a root token can be generated. No HSM. Env KEK is refused in production unless `TALOS_ALLOW_ENV_KEK` | Operator-side: use an external Vault / KMS, or replace the init Job with Shamir-split unseal keys held by distinct people | High |
| No mandatory API key expiry | CC6.2 | `expires_at` exists but is optional (`expires_in_days` may be omitted); keys without it never expire | Require an expiry at issuance and add rotation reminders | Medium |
| No WAF/CDN rate limiting | CC6.6 | Application-level only | Deploy Cloudflare/AWS WAF for DDoS protection | Medium |
| Per-replica API and MCP rate limits | CC6.6 | Per-IP API, webhook, global and MCP per-user / per-agent limits are in-process per controller replica, so N replicas allow up to N× the configured rate; only the auth-mutation limiter is Redis-backed | Back the per-IP and MCP limiters with a shared store | Unassigned |
| Secret access audit does not cover dispatch-time resolution | CC7.1 | Bulk secret resolution at job dispatch writes no `secret_audit_log` row (see CC7.1-05); guest-code use is recorded only in the WORM ledger | Record dispatch-time resolutions | Unassigned |
| No external SIEM forwarding | CC7.1 | Audit events reach the `AUDIT_LEDGER` JetStream stream and the S3 WORM ledger only | Attach a SIEM consumer to the stream | Unassigned |
| No pgaudit extension | CC7.1 | Trigger-based audit protection | Enable pgaudit for DB-level statement logging | Low |
| No U2F/WebAuthn support | CC6.1 | TOTP only | Add hardware security key support | Low |
| No automated access reviews | CC6.1 | Manual process | Build automated access certification workflow | Medium |

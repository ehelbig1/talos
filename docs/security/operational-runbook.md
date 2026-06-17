# Talos Operational Security Runbook

**Version:** 1.0  •  **Last reviewed:** 2026-04-23

This document captures the operational procedures that turn the security
*architecture* (see `docs/security/architecture.md`, `docs/THREAT_MODEL.md`,
`docs/SECRETS_MANAGEMENT.md`) into an actually-defended deployment. If
you're new to operating Talos, read this top to bottom before you put
anything sensitive in the system.

---

## 1. Current security posture (be honest with yourself)

| Asset | At-rest protection | In-transit | Notes |
|---|---|---|---|
| User secrets (`secrets`, `webhook_triggers.signing_secret_enc`) | ✅ Envelope encryption (AES-256-GCM via `SecretsManager`) | ✅ TLS in prod | DEKs in `encryption_keys`, KEK pluggable via `KekProvider` (Vault default) |
| OAuth tokens (`oauth_tokens`) | ✅ Envelope encryption | ✅ TLS | Same DEK lineage as user secrets |
| Workflow definitions (`workflows.graph_json`) | ⚠️ Plaintext JSONB | ✅ TLS | Generally non-sensitive; treat as code |
| Module source code (`modules.source_code`) | ⚠️ Plaintext | ✅ TLS | User-authored Rust; not encrypted |
| Module WASM bytes (`modules.wasm_bytes`) | ⚠️ Plaintext | ✅ TLS | Compiled artifacts; recoverable from source |
| **Actor memory (`actor_memory.value_enc`)** | ✅ Envelope encryption (AES-256-GCM, Phase A + Phase B shipped 2026-04-23) | ✅ TLS | Same KEK / DEK lineage as user secrets. Legacy `value` column dropped; `value_enc` + `value_key_id` are NOT NULL. |
| Module executions (`module_executions.input_data_enc`, `output_data_enc`, `trigger_metadata_enc`) | ✅ Envelope encryption (Phase A shipped 2026-04-23) | ✅ TLS | Same DEK lineage. DLP redaction still runs pre-encrypt as defense-in-depth. Phase B (drop legacy plaintext columns) deferred until a soak. Several non-canonical writers (`engine/module_execution_store`, `webhooks/mod`, `scheduler`) still write plaintext — see §1.1 below. |
| Workflow execution outputs (`workflow_executions.output_data_enc`) | ✅ Envelope encryption (wired 2026-04-23) | ✅ TLS | Backfilled 52 plaintext rows. All three writer paths (mark_execution_completed, scheduler, ActorRepository::complete_execution) route through encryption-aware methods. |
| Admin events (`admin_event_log.details`) | ⚠️ DLP-redacted plaintext (intentional — see §1.2) | ✅ TLS | NOT encrypted by design: incident-triage queryability outweighs the marginal info-disclosure risk for admin-action metadata. |
| DEK ciphertext | ✅ Provider-defined wire format | n/a | Lives in `encryption_keys.encrypted_key` (Vault transit `vault:vN:<base64>` by default; AES-GCM bytes when `KEK_PROVIDER=env`) |
| KEK | ✅ Vault transit (KEK→KMS Phase 6 shipped 2026-04-23) | TLS to Vault | Master key never leaves Vault. Env-var fallback (`KEK_PROVIDER=env`) retained for dev / single-host deployments. |

**Read this carefully:** if your Postgres dump leaks, the **only** values
that stay sealed are the columns marked ✅. Treat anything in actor memory,
workflow graphs, or module source as if it could be read by whoever
gets that dump.

### 1.1 Module-executions encryption coverage (closed 2026-04-24)

All writers that touch payload columns now route through the shared
`module_payload_encryption::encrypt_payload_bundle` helper:

- `ModuleExecutionService::{create_execution, complete_execution}` — MCP-driven path
- `engine::module_execution_store::PostgresModuleExecutionStore::{record_started, record_completed}` — workflow-runtime path
- `webhooks::WebhookRouter` webhook-trigger INSERT

Reader-side decryption is wired on `ModuleRepository::with_encryption` so
`find_latest_completed_execution_io` and `list_completed_module_executions`
transparently decrypt `*_enc` columns when present. The runbook
previously listed three other "writer paths" (`scheduler.rs`,
`advanced_repository.rs`, `workflow_repository.rs`) — auditing showed
those only update status / error_message and never touch payload
columns.

Backfill leftovers periodically with
`cargo run --example backfill_module_payload_encryption -p controller`.
Last run 2026-04-24: 206 rows backfilled, current state is 0 plaintext
/ 100% encrypted.

### 1.2 Admin-event-log policy

`admin_event_log.details` is intentionally NOT envelope-encrypted. The
table is the primary surface for incident triage:

- Operators query `details` by hand during investigations (e.g.
  "show all secret-deletion events in the last 24h with their
  parameters") — encrypted JSONB defeats every ad-hoc query.
- Append-only enforcement (`prevent_audit_modification` trigger)
  + DLP scrubbing covers the realistic threat model: an attacker
  reading a Postgres dump shouldn't gain *new* info from admin
  metadata they couldn't already infer from observing the system.
- The actual sensitive material referenced by admin events
  (secret values, OAuth tokens, etc.) is encrypted in its OWN
  table; `admin_event_log.details` only references it by id/path.

If a future audit-event captures something genuinely sensitive
(e.g. raw user payloads), encrypt the specific field at write time
inside `record_admin_event` rather than blanket-encrypting the column.

### 1.3 LLM data-egress tier ceiling (per-actor privacy gate)

Actors can have a `max_llm_tier` ceiling that restricts which LLM
providers a job dispatched on their behalf may reach:

- **`tier1`** — local Ollama only. Payloads MUST NOT leave the host.
  Use for actors handling medical, financial, relationship context,
  anything where third-party retention is unacceptable. Enforced at
  the worker's `llm::complete` / `llm-tools` / `llm-streaming` host
  functions: a tier-1 job's attempt to resolve an Anthropic / OpenAI /
  Gemini key returns `None` with a logged warning, and the LLM call
  fails closed with "missing provider key".
- **`tier2`** (default) — external providers allowed (Anthropic,
  OpenAI, Gemini). DLP scrubbing still runs pre-send as defense in
  depth, but "anything here is potentially seen by the provider".

The ceiling is HMAC-bound in the `JobRequest` signing payload so an
on-wire attacker can't downgrade a tier-1 actor to tier-2.

**Setting the ceiling:** `set_actor_llm_tier_ceiling` MCP tool with
`actor_id` + `tier: "tier1" | "tier2"`. Takes effect on the next
dispatched job.

**Local-model capability:** default Tier-1 model is `qwen2.5:32b`
(best-in-class at this size for agent tool-use and JSON mode;
~20 GB on disk, fits 32 GB RAM). For users with 64 GB+ RAM, build
Ollama with `--build-arg TIER1_MODEL=llama3.3:70b` for a flagship-
class local model at ~3× slower generation.

### 1.4 Lost-KEK disaster (Vault dev mode)

The local `docker-compose.yml` Vault service runs in `-dev` mode but
**now uses a persistent volume** (`vault_data:/vault/file`) so transit
keys survive container restarts. Without the volume, `docker compose
restart vault` wipes every transit key — every DEK wrapped against
the lost key becomes unrecoverable, and so does every secret /
oauth_token / actor_memory row that DEK protected. Production Vault
deployments must use raft / consul / postgres backend with proper
unseal-key custody; the `-dev` + volume combination here is a dev
convenience only.

Recovery (dev only): truncate `encryption_keys` + cascading data
(`secrets`, `oauth_tokens`, `actor_memory.value_enc`, …), restart
controller. `SecretsManager.initialize()` creates a fresh DEK against
the current Vault. Active dev session 2026-04-23 documents the exact
SQL — search for `session_replication_role = replica` to bypass the
audit-log immutability trigger when cleaning orphan secrets.

See §1.3 for the per-actor LLM tier ceiling, which is a complementary
privacy control at the data-egress boundary.

### 1.5 Audit-ledger cryptographic verification (finding #2)

The WORM audit ledger is HMAC-signed + hash-chained, and the chain is now
**verified**, not just persisted:

- **Ingest (inline).** The `talos.audit.ledger` consumer recomputes each
  event's hash and verifies its HMAC before writing to S3. Failures are
  quarantined to an Object-Locked `rejected/<execution_id>/` prefix (never
  silently dropped) and logged at ERROR with `event_kind =
  "audit_event_verification_failed"`.
- **Continuous (sweep).** A controller background task verifies the full
  chain of recently-completed executions on an interval and emits
  `event_kind = "audit_chain_verification_failed"` (one per broken chain,
  with the structured `breaks` list) plus an `audit_chain_sweep_summary` per
  pass.

**Required config.** Set `TALOS_AUDIT_SIGNING_KEY` (32+ hex bytes;
`openssl rand -hex 32`) on **every worker AND the controller**, and
`TALOS_AUDIT_SIGNING_KEY_PREVIOUS` (comma-separated) during a signing-key
rotation. Without a key, events are persisted but logged as UNVERIFIED
(`audit_event_unsigned`) — in production that is a misconfiguration.

**Sweep tuning.** `AUDIT_CHAIN_SWEEP_INTERVAL_SECS` (default 3600, clamped
[300, 86400]; `0` disables). The sweep self-disables when no S3/WORM
endpoint (`AWS_ENDPOINT_URL` / `MINIO_ENDPOINT`) is configured.

**SIEM alerting.** Page on `audit_event_verification_failed` and
`audit_chain_verification_failed` (target `talos_audit`) — both are positive
tamper/corruption evidence. Alert (lower severity) on
`audit_event_quarantine_failed` and a sustained `audit_event_unsigned`.

**On a failure.** A `*_verification_failed` event names the `execution_id`.
Re-verify on demand via the platform-admin GraphQL query
`verifyAuditChain(executionId: "<id>")` — it returns `{ ok, totalEvents,
signaturesChecked, breaks { kind, sequence, expected, found } }`, where
`kind` distinguishes a sequence gap / deletion from a linkage break / forged
HMAC. Then inspect the quarantined objects under `rejected/<execution_id>/`
in the WORM bucket.

---

## 2. Routine procedures (set quarterly calendar reminders)

### 2.1 KEK protection check (monthly)

The Key Encryption Key (KEK) is the root of the encryption tree — if it
leaks, every DEK can be decrypted, and every secret/token in the database
becomes recoverable. Talos supports two KEK backends, selected by
`KEK_PROVIDER` (default `env`):

- `env`: 32-byte AES key from `TALOS_MASTER_KEY` (env var or
  `TALOS_MASTER_KEY_FILE`). Key sits in controller process memory.
  Suitable for development.
- `vault`: HashiCorp Vault transit engine. Master key never leaves
  Vault; controller calls `POST /v1/transit/encrypt|decrypt` with
  `X-Vault-Token`. Production default. See §2.1.1 below for ops.

Monthly verification (BOTH backends):
- [ ] `TALOS_MASTER_KEY` and `VAULT_TOKEN` are **not** in any committed
      file:
  ```bash
  git -C ~/projects/talos grep -iE "TALOS_MASTER_KEY=|VAULT_TOKEN=" -- :!docs
  # Should return ZERO matches outside docs.
  ```
- [ ] Neither value appears in any process listing accessible to
      non-root users (check `/proc/<pid>/environ` permissions).
- [ ] (env backend) KEK length is exactly 32 bytes (64 hex chars).
- [ ] (vault backend) Vault is sealed at rest; unseal keys are
      distributed (Shamir 3-of-5 or similar) and NOT stored on the
      same host as the controller.

#### 2.1.1 Vault transit operational basics

| Operation | Command (operator host with `vault` CLI) |
|---|---|
| Sanity check (authenticated, can encrypt) | `vault status && vault token lookup -self` |
| Rotate the underlying key (transit-managed) | `vault write -f transit/keys/talos-kek/rotate` — adds a new key version. Existing ciphertexts continue to decrypt; new encrypts use the latest version. |
| Revoke a leaked token | `vault token revoke <token-accessor>` — issue a fresh token, update controller env, restart. |
| Check key versions in use | `vault read transit/keys/talos-kek` — `latest_version` is the encryption target; `min_decryption_version` controls which old versions still decrypt. |
| Issue a transit-only token | `vault token create -policy=talos-transit -ttl=720h` (policy must allow `transit/encrypt/talos-kek` + `transit/decrypt/talos-kek` only). |

**Rotating to a new transit key version** (no re-wrap needed — Vault
handles versioning internally; existing ciphertexts include the version
in the `vault:vN:<base64>` prefix):

```bash
vault write -f transit/keys/talos-kek/rotate
# All NEW DEKs created after this run wrap with the new version.
# OLD DEKs continue to decrypt using the version embedded in their
# vault:vN: prefix until you `vault write transit/keys/talos-kek/config
# min_decryption_version=N` to retire old versions.
```

**Switching between backends** (e.g. dev `env` ↔ prod `vault`):
the dual-wrap migration in `kek-to-kms-plan.md` is the only safe path.
Phase 4's reader-cutover keeps both providers wired during the soak so
a rollback is just a `KEK_PROVIDER` env flip + container restart.

### 2.2 DEK rotation (quarterly)

Talos supports multiple active DEKs — new writes use the latest, old
reads use whichever DEK encrypted them.

**Procedure:**
```bash
# 1. Confirm current active DEK
docker exec talos-postgres psql -U talos -d talos -c \
  "SELECT id, created_at, is_active FROM encryption_keys ORDER BY created_at DESC LIMIT 5;"

# 2. Generate + insert a new DEK (ciphertext is encrypted by current KEK)
#    Currently no MCP tool for this — MCP is read-only for secrets
#    (MCP-1201). Options:
#      (a) Run the SecretsManager directly via a one-shot Rust binary.
#      (b) SAFE INTERIM: rotate user-facing secrets via the GraphQL
#          `rotateSecret(name: ...)` mutation (Settings → Secrets in
#          the dashboard) — each rotation generates fresh ciphertext
#          under the active DEK, accumulating coverage organically.
```

**Backfill old ciphertext to the new DEK** (separate session):
```bash
# Touch every secret + oauth_token + webhook signing_secret so it gets
# re-encrypted under the new active DEK. Old DEKs can then be marked
# inactive after a grace window during which no rows reference them.
```

> **Status:** the rotation primitive exists in `SecretsManager`; a
> quarterly automation task is **not yet wired**. Run manually until
> a `RotationManager::run_quarterly_sweep` task lands.

### 2.3 JWT secret rotation (every 6 months OR on suspected compromise)

```bash
# 1. Generate a new 256-bit secret
NEW=$(openssl rand -base64 32)

# 2. Update env (controller restart required)
#    JWT_SECRET=<new value>

# 3. All existing user sessions invalidate (acceptable — users re-login)
#    All in-flight MCP agent tokens INVALIDATE — agents must re-register.
```

**Side effect:** every Claude Code / MCP client must reconnect after this.
Coordinate with whoever uses the platform.

### 2.4 Worker shared key rotation (every 6 months)

The HMAC key the controller uses to sign job dispatches to the worker.

```bash
# 1. Generate
WORKER_SHARED_KEY=$(openssl rand -base64 32)

# 2. Set in BOTH controller and worker env (rolling restart NOT safe —
#    job HMAC will fail until both sides have the new key)
# 3. Stop both, update env, start both
```

### 2.5 OAuth provider credential refresh

For each integration (Gmail, Calendar, Jira, etc.):
- [ ] Verify provider's OAuth client_id / client_secret hasn't been rotated
      by the provider (check provider console)
- [ ] Verify webhook URLs are still valid (Google push notifications expire
      every 7 days — `gmail` and `google_calendar` services auto-renew via
      background tasks; check `controller` logs for renewal failures)
- [ ] User OAuth refresh tokens auto-refresh; no manual action

### 2.6 Backup verification drill (quarterly)

Backups you've never tested don't count.

```bash
# 1. Take a fresh snapshot of postgres
docker exec talos-postgres pg_dump -U talos -d talos -F c \
  > /tmp/talos-restore-test-$(date +%Y%m%d).dump

# 2. Spin up a clean throwaway postgres + restore
#    (use a separate compose project / namespace)

# 3. Verify:
#    - Row counts match production for: users, actors, workflows, modules,
#      secrets, oauth_tokens, actor_memory, webhook_triggers
#    - SecretsManager can decrypt at least 1 secret per DEK in the restore
#      (proves the KEK + ciphertext both survived)
#    - At least 1 workflow runs end-to-end against the restore

# 4. Document the date + result in a ledger (spreadsheet, markdown, whatever)
```

**Failure modes to look for:**
- DEK rows imported but KEK changed in the meantime → unable to decrypt
  anything. Mitigation: KEK MUST be backed up out-of-band, separately from
  the database backup.
- Embedding column (vector(768)) requires the pgvector extension to be
  installed on the restore target.
- `_sqlx_migrations` checksums must match the committed migrations or
  next controller boot will fail.

### 2.7 Supply-chain hygiene (weekly, automated; review monthly)

Three automations run without operator intervention; the monthly
review is just "look at the output, approve/investigate":

- **Dependabot** (`.github/dependabot.yml`) — weekly PRs for cargo /
  Docker / docker-compose / GitHub Actions. Grouped by domain to
  control review load. Security advisories override grouping and
  ship as dedicated PRs.
- **`cargo audit`** + **`cargo deny check`** — both run on every CI
  push, both block merge on failure. Justified exemptions live in
  `deny.toml`; silent suppressions forbidden.
- **SLSA signing** — every tag push produces signed images + SBOM +
  provenance (see §4.1 for verification).
- **Sigstore-signed module templates** — `.github/workflows/template-publish.yml`
  signs every OCI template artifact via cosign keyless OIDC on each push
  to `module-templates/**`. The worker's `verify_oci_signature`
  enforces the signature BEFORE pulling the WASM bytes when
  `TALOS_SIGSTORE_REQUIRED=true`. The pinned identity regexp lives in
  the chart `worker.sigstore.identityRegexp` value and MUST end with
  `@` (without it, a fork-named workflow could match the prefix). See
  `deploy/k3s/README.md` § *Trust model: Sigstore signing* for the
  three-mode policy table and verification commands.

**Monthly review checklist:**

- [ ] Scan open Dependabot PRs. Merge cleanly-green bumps. Escalate
      anything red.
- [ ] Check `deny.toml` for expired re-review dates on exempted
      advisories (each ignore entry lists "re-review YYYY-QN").
      Confirm exemptions still apply; drop any that are now moot.
- [ ] Run `cargo deny check` locally — should match CI. If it drifts,
      a CI gate was likely skipped.
- [ ] `grep -r RUSTSEC-` in `deny.toml` vs. `cargo audit` fresh output
      — every current advisory should either be fixed by an update or
      documented as an exemption. No unmentioned advisories.
- [ ] Verify the latest release image's signature locally with
      `make verify-image IMAGE=ghcr.io/.../talos-controller:latest`.
      Confirms signing pipeline is still working.

**Quarterly review checklist (in addition to monthly):**

- [ ] Re-resolve the digest-pinned Docker images in `docker-compose.yml`
      and compare to the pinned values. A new upstream publish =
      dependabot PR incoming; an unexplained digest drift = investigate.
- [ ] Audit `deny.toml` exemptions for upstream fixes. Any advisory
      where an upstream-tracking-link now shows a fix shipped = drop
      the exemption, run `cargo update`, verify.

---

## 3. Incident response playbooks

### 3.1 Suspected KEK leak

**Scope:** every user secret + every OAuth token + every webhook signing
secret in the system is potentially compromised.

**Immediate (T+0):**
1. Rotate every user-facing OAuth integration token at the **provider**
   (Google, GitHub, Atlassian) — do not rely on rotating Talos's stored
   copy alone.
2. Treat all secrets stored in the vault as exposed; rotate at the
   *upstream* provider (e.g. regenerate Anthropic API key from their
   console; revoke the old one).
3. Generate a new KEK and **rewrap all DEKs** (ciphertext stays valid;
   the wrapping changes). Procedure: extract DEK plaintext using the old
   KEK, re-encrypt with the new KEK, write back to `encryption_keys`.

**Within T+24h:**
4. Audit `admin_event_log` for any access patterns that look like
   bulk decryption or secret enumeration since the suspected leak window.
5. Force JWT secret rotation (§2.3) — all sessions die.
6. Audit MCP agent registrations — any `Claude Code N` rows you don't
   recognize → revoke.

### 3.2 Suspected database compromise

If an attacker has read access to Postgres:

1. **They have:** all `actor_memory.value` (plaintext), all
   `workflows.graph_json`, all `modules.source_code`, all
   DLP-redacted execution outputs.
2. **They don't have (yet):** plaintext secrets — those are encrypted —
   *unless* they also have the KEK.
3. **Action:** assume KEK leak → execute §3.1 plus rotate all upstream
   credentials. Inform any users whose `actor_memory` may contain
   sensitive info (this is the "encrypt agent_memory at rest" gap —
   see `agent-memory-encryption-plan.md`).

### 3.3 Suspected worker compromise (hostile WASM module)

The wasmtime sandbox is robust but not infinite. If you suspect a
malicious module escaped:

1. Identify the module: `SELECT id, name, user_id, created_at FROM modules
   ORDER BY created_at DESC LIMIT 50;` — look for recent uploads with
   unusual capability worlds (`automation-node`, `database-node`).
2. Disable the module: `UPDATE modules SET wasm_bytes = NULL WHERE id = '...';`
3. Kill running executions: `cancel_queued_executions` MCP tool.
4. Scrub any secrets the module had `allowed_secrets` access to — assume
   they were exfiltrated (the WASM runtime CAN exfiltrate via outbound
   HTTP if the world includes `http`; check `allowed_hosts` to bound
   the egress vector).
5. File a wasmtime security issue if you have a reproducible escape POC.

### 3.4 Suspected actor token (MCP agent token) leak

```bash
# 1. Find the agent
docker exec talos-postgres psql -U talos -d talos -c \
  "SELECT id, name, last_connected_at FROM mcp_agents WHERE name = '...';"

# 2. Revoke (set is_active = false)
docker exec talos-postgres psql -U talos -d talos -c \
  "UPDATE mcp_agents SET is_active = false WHERE id = '...';"

# 3. Audit the agent's recent activity
#    Look at admin_event_log + module_executions for the user_id
```

The token itself is unrecoverable from the DB (only `token_lookup_hash`
+ bcrypt of the token is stored), so revocation is the only remediation.

---

## 4. Pre-deployment security checklist

Before pointing this at anything sensitive — especially before exposing
the controller to the public internet — verify every box:

- [ ] `RUST_ENV=production` set on controller. This disables `/mcp/local`
      (the unauthenticated dev endpoint) and other dev-mode shortcuts.
- [ ] `KEK_PROVIDER=vault` set + `VAULT_ADDR` / `VAULT_TOKEN` configured.
      `KEK_PROVIDER=env` (with `TALOS_MASTER_KEY` in env or file) is
      dev-only — production deployments must use Vault transit so the
      KEK never enters controller process memory. See §2.1.1.
- [ ] `JWT_SECRET` is ≥32 bytes, generated cryptographically random,
      not committed.
- [ ] `WORKER_SHARED_KEY` is ≥32 bytes, set on BOTH controller + worker.
- [ ] `POSTGRES_PASSWORD` not in any committed file.
- [ ] TLS termination in front of the controller. The Axum server has
      no built-in TLS — use a reverse proxy (Caddy, nginx, ALB).
- [ ] Public-facing webhook URLs use HTTPS. The vault:// header
      substitution path REQUIRES HTTPS to keep secrets off the wire
      in plaintext.
- [ ] Postgres + Redis bound to private network ONLY. Current
      `docker-compose.yml` exposes `127.0.0.1:5433` for dev — remove
      that port mapping in prod.
- [ ] Backups configured + the verification drill (§2.6) has been run
      at least once.
- [ ] Rate limits tuned to your traffic — defaults (10K/min API,
      5K/min webhook) are dev-friendly, may be too generous for prod.
- [ ] `auto_archive_stale_days` configured if you expect lots of test
      workflows.
- [ ] Approval gates configured for any workflow that sends external
      messages, moves money, or touches real user data.
- [ ] `set_actor_budget` set on every actor that runs autonomously
      (else a buggy LLM loop can burn unbounded LLM tokens).
- [ ] Every image about to be deployed has been verified — see §4.1.

### 4.1 Supply-chain verification before deploy (SLSA L2)

Every release-tagged Talos image (`controller`, `worker`, `frontend`)
ships with three signed artifacts attached:

1. **Image signature** — Sigstore keyless, bound to the GitHub Actions
   release workflow's OIDC identity. Proves "this image was built by
   our CI on a tag push, not by anyone else."
2. **SBOM attestation** — SPDX-JSON dependency manifest, signed by the
   same identity. Lets you answer "what was in the image?" *after*
   deploy.
3. **SLSA Level 3 provenance** — in-toto attestation generated by
   `slsa-framework/slsa-github-generator`. Records source commit, ref,
   builder, build-time inputs. Verifiable offline against the Rekor
   transparency log.

**Verification (REQUIRED before a production deploy):**

```bash
# Verify a single image:
make verify-image IMAGE=ghcr.io/ehelbig1/talos-controller:1.2.3

# Verify all three at a release version:
make verify-all-images VERSION=1.2.3 GITHUB_OWNER=ehelbig1
```

The script (`scripts/verify-image.sh`) runs three `cosign verify` /
`cosign verify-attestation` calls and fails closed on any mismatch.
A passing run prints `✅ ... passed all SLSA L2 verification checks`.

**What to do if verification fails:**

- **"signature verification FAILED"** — the image was either
  (a) built outside our CI (someone else pushed to the same tag),
  (b) tampered with after push, or (c) signed during a workflow run
  that doesn't match `^https://github.com/ehelbig1/talos/.github/workflows/release.yml@refs/tags/v.*`.
  DO NOT DEPLOY. Investigate the GHCR push history + GitHub Actions run
  log for the affected tag.
- **"SBOM attestation FAILED"** — the image is signed but the SBOM
  attestation step didn't complete. Acceptable in development; **block
  deploy** for production. Re-run the release workflow.
- **"SLSA provenance FAILED"** — the SLSA generator subworkflow didn't
  complete or its identity doesn't match. Same response as SBOM — block
  + re-run.

**Identity rotation (if the GitHub repo moves or is forked):**

The `EXPECTED_IDENTITY_REGEXP` in `scripts/verify-image.sh` hardcodes
`ehelbig1/talos` as the trusted builder. If you fork the repo and
publish your own images, update both the regexp and any deployed
verification configs in lockstep — leaving the old regexp would let
the original repo's images pass verification on your fork's deploys.

---

## 5. Monitoring + alerts to wire up

The platform records useful signals — what's missing is the alerting
glue. Wire these to your monitoring stack (Grafana, Datadog, whatever):

- **Auth failures** — `admin_event_log` rows with `event_type =
  'auth_failed'`. Threshold: >10/min from a single IP → block.
- **Webhook circuit breaker trips** — controller log line
  `"circuit breaker triggered for IP"`.
- **Secret-rotation overdue** — `encryption_keys.created_at` older than
  90 days for the active DEK.
- **OAuth refresh failures** — controller log line
  `"oauth refresh failed"` with provider tag. Spike → upstream provider
  has revoked the credential.
- **WASM execution failures by module** — `module_executions WHERE
  status = 'failed' GROUP BY module_id` — unusually high failure rate
  on a module is either a bug or an attack.
- **Disk pressure on Postgres** — execution traces + module_executions
  grow without bound; configure a retention policy or `cleanup_*` MCP
  tools as a recurring task.

---

## 6. Quarterly review cadence

Set calendar reminders. The procedures above don't help if you don't run
them.

- **Monthly:** §2.1 (KEK protection check)
- **Quarterly:** §2.2 (DEK rotation), §2.6 (backup verification drill),
  full pass through this document for drift
- **Every 6 months:** §2.3 (JWT secret rotation), §2.4 (worker shared
  key rotation)
- **As needed:** §3.x incident playbooks

---

## 7. What this runbook does NOT cover (yet)

Honest list of operational gaps you should be aware of:

- **HA / failover.** The platform is single-controller, single-postgres,
  single-Redis, single-NATS. A node failure = downtime. Multi-region
  active-passive failover is a months-long project.
- **External pen test.** No third-party security review has been done.
  See `docs/security/pentest-scope.md` for what to ask for when you
  schedule one.
- **SOC2 / ISO 27001.** Control mapping started in
  `docs/compliance/soc2-control-mapping.md` but not audited.
- **`agent_memory.value` at-rest encryption** (the highest-risk gap on
  the matrix in §1) — see `agent-memory-encryption-plan.md` for the
  implementation roadmap.
- **Row-level security in Postgres** — currently every query
  defends-in-depth via `WHERE user_id = $1`, but a code path that
  forgets that filter would silently leak across tenants. Postgres RLS
  would catch it at the DB layer.
- **Secret deletion right-of-erasure (GDPR)** — `delete_secret` removes
  the row but historical `admin_event_log` still references it by hash;
  an "irreversible erasure" procedure isn't documented.

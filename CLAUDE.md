# Talos Development Guidelines

## Build & Test Commands
```bash
make up-dev          # Start all services
make lint            # Lint Rust + frontend
make coverage        # Run tests with coverage
cargo check --workspace  # Quick Rust compilation check
cd frontend && npx vitest run  # Frontend unit tests
```

## Architecture
- **controller/** - Rust/Axum API server (GraphQL + REST). Owns Postgres + Neo4j credentials. Hosts NATS-RPC subscribers for memory / graph / database / state ops.
- **worker/** - Rust WASM runtime (wasmtime-based). **Credential-free**: no Postgres connection, no embedding-provider keys, no Neo4j. All data-plane access goes through signed NATS-RPC to the controller.
- **frontend/** - React/TypeScript visual workflow editor.
- **talos-workflow-engine/**, **talos-workflow-engine-core/**, **talos-workflow-engine-nats/**, **talos-workflow-engine-test-utils/**, **talos-workflow-job-protocol/** - Workflow executor + trait boundaries + signed-NATS job/pipeline message types. Folded back into this workspace in May-2026 from the sibling `../talos-workflow-engine/` repo to simplify releases (one workspace, one `cargo check`, no `additional_contexts` indirection in image builds). Controller depends on `talos-workflow-engine-core`, `talos-workflow-engine`, `talos-workflow-engine-nats`; both controller and worker depend on `talos-workflow-job-protocol`. The engine's `SCHEMA_DOC` constant pulls from `docs/workflow-engine/graph-json-schema.md`.
- **talos-memory/** - Shared crate: canonical actor-memory service (writes, reads, semantic search, embedding LRU + thundering-herd dedupe), plus the four signed RPC protocols (`memory_rpc`, `graph_rpc`, `database_rpc`, `state_rpc`) and `rpc_auth` (HMAC + nonce replay cache + freshness window + canonical-bytes signing).
- **talos-secrets/**, **talos-dlp/**, **talos_sdk_macros/** - Other shared crates.
- **migrations/** - PostgreSQL migrations (sqlx).

## RPC layer (worker → controller)

Every cross-process data call uses the same signed-NATS-RPC pattern:

| Subject | Protocol | Sub | Notes |
|---|---|---|---|
| `talos.memory.op` | `memory_rpc::MemoryOp` (Get/Set/Delete/ListKeys/Search) | request/reply, in-flight cap 16 | All actor_memory access |
| `talos.graph.search` | `graph_rpc::GraphSearchRequest` | request/reply, cap 8 | Neo4j graph-RAG |
| `talos.database.query` | `database_rpc::DatabaseRpcRequest` | request/reply, cap 8 | Sandbox SQL via `database` WIT |
| `talos.state.write` | `state_rpc::StateWriteRequest` | fire-and-forget, cap 32 | `execution_state` durability |

**Before adding a new signed-RPC primitive**, walk `docs/platform-primitive-checklist.md` end-to-end. It captures the ten individual defense-in-depth and correctness fixes made across six review passes on integration_state (2026-04-15) so the next primitive doesn't repeat them. Pattern-copying from `memory_rpc` is NOT a substitute — several of the fixes were on issues that exist in `memory_rpc` too (e.g. zombie semaphore permits under DB outage, `tokio::spawn` orphaning on shutdown).

**Before adding ANY integration** (OAuth provider, third-party API, push source), read `docs/adding-an-integration.md` — the single authoritative guide + checklist. It names the correct-by-default toolkit (`talos_http_utils::trusted_client` for fixed hosts, `talos_http_body::read_json_capped` for bodies, `talos_oauth::OAuthIntegration` + `authorization_url`/`handle_oauth_callback` drivers for the OAuth flow, `OAuthCredentialService` for user-scoped tokens, `integration_state` for per-user watch state) and the non-negotiable tenancy/secret/SSRF/perf rules, cross-referenced to the lint checks (31/37/40/41/49) that enforce them. `talos-slack` is the canonical `OAuthIntegration` reference impl.

**Before adding a new push-notification integration** (watch channels / webhooks / Pub/Sub push on top of `integration_state`), walk `docs/integration-pattern.md` end-to-end. It distills the ten-file shape we converged on across `google_calendar` (first) and `gmail` (second) — what goes where, which helpers to reuse (`RenewalFailure`, `looks_like_oauth_failure`), and the pitfalls each reference implementation paid for. The third integration should be significantly faster than the second; reaching that only happens if the doc is consulted before coding, not after.

Efficient flow for Claude Code specifically: (a) spawn an **Explore** subagent in parallel against `controller/src/google_calendar/` and `controller/src/gmail/` to survey the two reference implementations; (b) spawn a **Plan** subagent to lay out the 10-file sequence; (c) implement file-by-file with green tests between pieces; (d) send the webhook-auth and renewal-path layers to a **code review** subagent before declaring done — those two are the highest-blast-radius parts of the pattern.

**Security invariants** (enforced by `talos_memory::rpc_auth` and the per-RPC `verify()` methods):
- HMAC-SHA256 signature bound to `(subject, actor_id, nonce, body)`
- Two-generation rotating nonce cache via `ArcSwap<DashMap>` — atomic O(1) rotation, no replay within `PAST_WINDOW_MS` (60 s)
- Asymmetric freshness window: 60 s past tolerance, 5 s future tolerance
- Constant-time MAC compare (`subtle::ConstantTimeEq`)
- Canonical byte-form signing — sorted-key recursive JSON for nested `Value`s, fixed variant tags with build-time uniqueness guard, LE-encoded numbers
- NaN/Inf rejected in signed numeric fields (non-deterministic encoding otherwise)
- `MAX_CANONICAL_DEPTH = 128` matches serde_json's default; deeper payloads fail signing closed
- Per-subject concurrency semaphore + structured `target: "talos_rpc"` metric events with split `queue_ms` / `exec_ms`

**Verify-once rule for signed NATS messages** (`talos-workflow-engine/talos-workflow-job-protocol`, learned the hard way r300 / r301, 2026-05-05). Every signed message type (`JobResult`, `PipelineJobResult`, …) MUST have **exactly one primary `verify()` caller per controller process**. Passive observers (audit subscribers, metrics emitters, anything whose only side effect is an idempotent DB write) MUST use `verify_no_replay()` — HMAC + freshness without touching the process-local `JOB_NONCE_CACHE`. Two `verify()` calls against the same signed message will deterministically fail with `"result_nonce already seen"` because both insert into the same shared cache. The worker MUST single-publish each result to ONE NATS subject (reply inbox OR global audit topic, branched on `reply_topic` presence) — dual-publishing primes the cache race even when both consumers correctly use the split API. Background incident: see `memory/rpc_dual_verify_pattern.md`. Adding a new signed message type? Add both `verify()` and `verify_no_replay()` together up front; the prophylactic split is cheap, the regression is total (every job fails).

**Anything that needs to read or write `actor_memory` MUST go through `talos_memory::*` functions** — do not write inline `INSERT INTO actor_memory` SQL anywhere. The service is the only path that computes embeddings and runs graph-RAG entity extraction. Bulk clone is `talos_memory::clone_memories(pool, source_actor, target_actor)` — copies the live semantic+episodic memories (v0 rows pass ciphertext through; v1/v3/v4 rows are decrypt+re-encrypted to re-base their `actor_id`-bound AAD AND re-key onto the TARGET actor's org DEK), preserves `metadata`. Caller must verify both actors belong to the same user before invoking — this is a **tenancy/privacy** rule (don't copy one user's agent memory into another's), NOT a crypto one. (DEKs are per-ORGANIZATION, with a global DEK fallback for org-less data — there is no per-USER DEK; per-actor isolation comes from the per-`(actor_id,key)` HKDF-derived AEAD subkey under the actor's org DEK, so a cross-user copy would in fact decrypt fine. See the "Per-context AEAD subkeys + per-ORG root DEKs" section below.)

**This rule is now lint-enforced.** `make lint` runs `scripts/lint-structural.sh`, which fails on raw `INSERT/UPDATE/DELETE` against `actor_memory` outside `talos-memory/`, and on the legacy `value, value_enc` column projection (the pattern that broke 7 sites during Phase B's column drop). If you have a documented reason to write raw SQL, add `// allow-actor-memory-sql: <reason>` within 8 lines above the SQL — but the default path is `talos_memory::recall_*` / `persist_memory` / `clone_memories`.

**`metadata.kind` convention for synthetic outputs.** Any workflow that runs
`LLM-synthesize → persist → agent_memory::search` on the same actor MUST
stamp its writes with a stable `metadata.kind` label so future recalls can
exclude them. Without this, the LLM cites its own prior output as "source"
and hallucinations amplify on every run. Current labels in use:
- `meeting_prep` — pa-meeting-prep briefs
- `recall` — pa-recall Q+A pairs (convention: label matches workflow-name stem)
- `daily_brief` — pa-daily-brief summaries

**The `__memory_write__` protocol is OPT-IN per node.** A node persists to
actor_memory ONLY when its output JSON contains a `__memory_write__` key
with a non-empty `key` field — for example:
`{ "__memory_write__": { "key": "daily_brief/2026-04-21", "value": {...},
"metadata": {"kind": "daily_brief"}, "ttl_hours": 720 } }`. There is no
implicit "persist every node output" behavior. The hook fires at both
node-completion AND per-pipeline-step so chain-dispatched modules can
emit memory writes too.

Accepted `__memory_write__` fields:
* `key` (string, required) — the actor_memory key
* `value` (JSON, default null) — the stored payload
* `memory_type` (string, default `"episodic"`)
* `metadata` (JSON object, optional) — stored in the dedicated
  `actor_memory.metadata` JSONB column. Readers can filter via
  `agent_memory::search_filtered(exclude_kinds: [...])`. Use this to stamp
  synthetic LLM outputs with `metadata.kind` so they don't poison
  same-actor recalls. Non-object metadata is ignored. Available without
  the `agent-node` capability ceiling — the http-node ceiling is enough.
* `ttl_hours` (number, default 168) — TTL from now; semantic memories ignore TTL

Writes that omit `metadata` produce rows with `metadata IS NULL`, which
pass every filter — the right default for engine-trace style writes that
shouldn't be excluded from recall. Readers don't need an `"execution"`
entry in their exclude list.

Readers that want to skip synthetic entries call
`agent_memory::search_filtered(query, SearchOptions { limit, exclude_kinds })`
instead of the bare `search`. The filter is applied at the DB layer
(`talos_memory::recall_semantic_filtered`, parameterized `text[]` bind)
— not post-hoc in Rust, so it composes with limit + min_score cleanly.

## Sub-workflow dispatch (engine)

Every parent node that runs a sub-workflow (judge, ensemble, reflective-retry, llm-dispatch, sub_workflow) uses the shared dispatcher pattern in `controller/src/engine/parallel.rs`:

1. **`execute_subworkflow_graph(wf_id, trigger_input, nats, shared_key)`** — the canonical invocation path. Loads the graph, builds an engine, registers a synthetic `__trigger__` node, runs `run_with_seed`, collapses the output. Returns `Result<JsonValue, SubflowError>`.
2. **`collapse_subworkflow_output(ctx_results, sub_engine)`** — flattens per-node results. Single terminal → its unwrapped output (what parent nodes expect). Multiple terminals → label-keyed map (diamond fallback).
3. **`JudgeVerdict::from_collapsed(&collapsed)`** — types the `{score, passed, reasoning, feedback}` parse; `malformed_field_count` > 0 surfaces bad judge workflows loudly.
4. **`dispatch_judge / dispatch_subworkflow / dispatch_ensemble / dispatch_reflective_retry / dispatch_llm_dispatch`** — one `&self async fn` per system-node kind, called from BOTH the main `run()` loop and `run_with_seed()`. Never re-inline the dispatch logic — extend the dispatcher.

Use `test_subworkflow_contract` MCP tool while authoring a judge/reflection/classifier sub-workflow — it runs the same `execute_subworkflow_graph` + `collapse_subworkflow_output` path the parent will use, plus per-contract interpretation (judge verdict parse, class extraction). Catches shape bugs before wiring up.

## LLM key resolution (vault-first everywhere)

Canonical LLM provider vault paths live in **one place**: `job_protocol::LLM_PROVIDER_VAULT_PATHS` + `is_llm_provider_vault_path(path)`. Three consumers import from there:
- `controller/src/engine/parallel.rs::prefetch_llm_vault_keys` — injects keys into every worker job's secrets map so `llm::*` host functions can resolve them.
- `controller/src/secrets/mod.rs::get_llm_vault_keys` — per-user 60s-TTL cache; eagerly invalidated by `create_secret`/`update_secret`/`delete_secret` when path matches. Background sweep task in `main.rs` evicts expired entries every 300s (`LLM_KEYS_SWEEP_INTERVAL_SECS`).
- `worker/src/host_impl.rs::check_secret_allowlist` — DENIES these paths from WASM guest code even when `allowed_secrets: ["*"]`. Reserved for host-internal `llm::*` consumption.

Controller-side `LlmClient` uses `with_vault(SecretsManager, env_fallback)` — per-request resolution hits the same cache, so `rotate_secret anthropic/api_key` propagates to controller scaffolding AND worker sandbox LLM calls within one TTL window. Use `LlmClient::new(env_only)` only in tests.

**Adding a new LLM provider** = one change to `job_protocol::LLM_PROVIDER_VAULT_PATHS`. Everything else picks it up automatically. Also update `worker::host_impl::llm_key_lookup_paths` for the `vault_path → env_name` fallback mapping. **And** add the provider's API hostname to `job_protocol::EXTERNAL_LLM_HOSTS` — without this, a tier-1 actor's HTTP-host gate won't deny the new provider's endpoint.

## Per-actor LLM tier ceiling (data-egress privacy gate)

Actors carry a `max_llm_tier` ceiling — `tier1` = local Ollama only (data
must not leave host), `tier2` = external providers allowed (default).
Schema: `actors.max_llm_tier text NOT NULL DEFAULT 'tier2'` (migration
`20260424100000_actors_max_llm_tier.sql`). Operator tool:
`set_actor_llm_tier_ceiling(actor_id, tier)` (writes to `admin_event_log`
on every change).

The tier travels with the job — HMAC-bound in BOTH `JobRequest` AND
`PipelineJobRequest` signing payloads (appended at end per the
wire-format stability rule). An on-wire attacker can't downgrade a
tier-1 ceiling to tier-2 without invalidating the signature.

**Five enforcement surfaces in the worker** (all guarded by `self.max_llm_tier == Tier1`):
1. `host_impl::get_llm_api_key` / `get_llm_api_key_by_name` — refuse to resolve external-provider vault keys (the `decide_llm_tier_access` helper centralises this — see `llm_tier_decision_tests`).
2. `host_impl::resolve_vault_header` — refuse `vault://anthropic|openai|gemini/*` substitution into HTTP headers.
3. `wit_http::fetch` + `wit_http::fetch_all` — refuse hosts in `job_protocol::EXTERNAL_LLM_HOSTS` regardless of `allowed_hosts`.
4. `wit_graphql::execute` — same host deny-list.
5. `wit_webhook::send` + `wit_http_stream` — same host deny-list.

**Defense in depth on the controller side:** `build_encrypted_secrets_for` takes `max_llm_tier` and SKIPS the `resolve_llm_keys` prefetch entirely when `Tier1`. Tier-1 jobs never have an Anthropic/OpenAI/Gemini key on the wire (encrypted or otherwise) — bounds blast radius if a future bypass slips.

**Stamping the tier on a workflow execution:** ALWAYS use `ActorRepository::apply_actor_to_engine(&mut engine, actor_id)` — it sets `actor_id` AND `max_llm_tier` together and fail-closes to Tier-1 on DB error. Never call bare `engine.set_actor_id(aid)` — the audit team would catch it (`grep -n 'engine.set_actor_id' controller/src/` should match only `actor_repository.rs:1093` after this rule).

**Module-bound dispatch** (Gmail/GCal/webhook push notifications) is intentionally Tier-2 default — those paths fire individual modules without an owning actor. Operators who need tier-1 enforcement for inbound-event processing wrap the module in a workflow with an actor that has `max_llm_tier=tier1`.

## Secret Handling Rules (CRITICAL — security invariant)

**Plaintext secret values MUST NEVER leave the controller host** except through two audited paths:
1. **Outbound HTTP headers** — `vault://` resolution places the secret into a header for an external API call; the `Zeroizing<String>` is cleared after use.
2. **Tier-2 `expose_secret`** — explicit opt-in per module (`allow_tier2_exposure: true`), rate-limited (10/execution, 100/user/day), audit-logged at WARN level. Currently hardcoded to `false` across all engine dispatch paths.

**Every engine dispatch path MUST call `build_encrypted_secrets()`** (or the equivalent inline block) to populate the job's `encrypted_secrets` field. Sending `Default::default()` means the module silently loses access to all secrets — vault:// headers fail with `Notfound`, LLM calls fail with missing keys. This was a real bug in loop-node dispatches fixed 2026-04-16. When adding a new dispatch path (new system-node kind, new parallel executor, etc.), grep for `encrypted_secrets:` in `parallel.rs` and verify the new site matches the existing pattern.

**Secret flow through the system:**
- Controller: `SecretsManager::get_module_secrets(node_id)` + `get_secrets_by_paths(vault_paths)` + `prefetch_llm_vault_keys(user_id)` → plaintext `HashMap<String, String>` → `EncryptedSecrets::encrypt(map, key)` → AES-256-GCM ciphertext in `JobRequest.encrypted_secrets` → NATS publish.
- Worker: `EncryptedSecrets::decrypt(key)` → plaintext `HashMap` loaded into `SecretProvider` DashMap → WASM guest receives opaque `u64` handle only (Tier-1), never the string.
- No MCP handler, GraphQL query, or REST endpoint returns plaintext secret values. `get_secret` is internal-only. MCP is **read-only for secrets** (MCP-1201): `set_secret` / `delete_secret` / `set_secret_namespace` / `set_secret_expiry` / `rotate_secret` were removed because MCP API keys are long-lived bearer tokens with no 2FA equivalent — secret writes would have bypassed the `require_2fa + SecretsWrite` discipline the GraphQL surface enforces. Mutations go through `talos-api/src/schema/secrets/mutations.rs`; MCP retains the read surface (list, namespaces, usage, health, normalize). `refresh_oauth_token` is the lone MCP write that touches vault — provider-side token rotation, no MCP-supplied value crosses the boundary. The GraphQL `Secret` type has no `value` field.
- DLP `redact_json()` is applied to module execution output before DB storage (catches `sk-*`, `ghp_*`, Bearer tokens, etc.).
- Audit logs record `key_hash` (SHA-256 of path), never the value.
- Error messages reference `key_path`/`name` only, never decrypted content.

**Per-context AEAD subkeys + per-ORG root DEKs (formats v3/v4).** Every AES-GCM
path derives a PER-CONTEXT key — `HKDF-SHA256(ikm = a DEK, salt = label, info =
aad_context)` — rather than encrypting many rows under one shared key (keeps the
per-key message count ~1, so the random-96-bit-nonce birthday bound is
unreachable). **There are two DEK scopes** (`encryption_keys.org_id`): one
**global** DEK (`org_id IS NULL`) and one **per-organization** root DEK per org
(`org_id` set; exactly one active per org, lazily provisioned on first use). Both
partial-unique-indexed. So:
- **v3** = per-context subkey from the GLOBAL DEK.
- **v4** = the SAME derivation but from the writer-org's root DEK — so a
  compromised root key is bounded to one tenant, not the whole system.

DB-backed paths (`SecretsManager`: secrets / actor_memory / TOTP / webhook
secrets / exec output / module payloads) write **v4** when an org is resolvable,
falling back to **v3 (global)** for legitimately org-less rows (personal secrets,
standalone module executions). **Decrypt is IDENTICAL for v3 and v4** — the row's
`*_key_id` names the DEK (`get_dek` resolves global-or-org by id) and the subkey
re-derives from the same AAD; `decrypt_versioned` dispatches v0/v1/v2/v3/v4 on the
per-row `*_format` column. Only ENCRYPT differs (which DEK is the IKM).

**Adding a new AEAD writer?** Call `encrypt_value_aad_v4_or_global(value,
target_org, aad)` and resolve `target_org` from context — the workflow's org for
executions, the actor's org for memory, the secret's `org_id`. For
personal/user-keyed tables use `encrypt_value_aad_v4_for_user(value, user_id,
aad)` (resolves the user's personal org). **Bind the RETURNED format version,
never hardcode 3/4** (a v4 row mislabeled v3 fails to decrypt), and widen that
table's `*_format` CHECK to include 4. If a table has its OWN decrypt dispatch
(e.g. `decrypt_secret_record`) add the v4 arm there too, and guard any global
re-encrypt sweep to skip `format = 4` (don't downgrade org rows).

**Migrating EXISTING rows to per-org** (the cutover only converts NEW writes):
per-table sweeps `SecretsManager::re_encrypt_*_to_org` /
`ModuleExecutionService::re_encrypt_module_payloads_to_org` /
`talos_memory::re_encrypt_memories_to_org`, exposed as platform-admin mutations
`reEncrypt{Secrets,Memories,Outputs,ModulePayloads}ToOrg`. Poll the
`dekMigrationStatus` query until each `pending` is 0 → the global DEK is no longer
load-bearing for migratable data (org-less rows stay global by design). The
personal tables (totp/webhook/audit) have no sweep — they migrate lazily on next
write.

**Separate, NON-DEK derivations (NOT per-org, do not "fix"):** checkpoints fold
`execution_id` from the `WORKER_SHARED_KEY` (`checkpoint-aead/v2-per-execution`);
the worker secret-envelope folds the per-job AAD from the WSK
(`envelope-aead/v2-per-job`); OTLP headers fold `user_id`. These don't use the DEK
at all, so they're already isolated from a DEK compromise.

**Envelope deploy ordering:** workers must roll first/together with controllers —
a v1-only worker can't open a v2-sealed envelope (the v2→v1 decrypt fallback only
covers the reverse). New AEAD format versions need the format CHECK widened in a
migration (`20260617120000` introduced v3; the `2026062612*`–`2026062624*` set
introduced per-org v4 per table).

**Worker-side secret isolation:**
- `check_secret_allowlist(key_path)` enforces BOTH the per-module `allowed_secrets` grant AND the host-reserved deny-list (`is_reserved_host_secret_path`). The deny-list blocks LLM provider keys even with `allowed_secrets: ["*"]`.
- The allowlist matcher lives in ONE place: `job_protocol::vault_path_permitted`. Both controller (validation) and worker (runtime enforcement) import from there.

## Security Rules (MUST follow)
- NEVER log sensitive values (tokens, cookies, API keys, secrets). Log presence only.
- NEVER return internal error details to API clients. Log full errors server-side, return generic messages.
- NEVER fall back to plaintext credential storage in production. Require SecretsManager.
- NEVER store secrets unencrypted in the database. Use envelope encryption via SecretsManager.
- NEVER send `encrypted_secrets: Default::default()` in a dispatch path that should have secrets — use `build_encrypted_secrets()`.
- NEVER modify already-applied migration files. Create new migrations instead.
- ALWAYS use parameterized queries (sqlx `$1` bind params). Never string-concatenate SQL.
- ALWAYS use constant-time comparison for security-sensitive values (tokens, HMAC, CSRF).
- ALWAYS set HttpOnly, Secure, SameSite=Strict on authentication cookies.
- ALWAYS validate and sanitize external input at API boundaries.
- ALWAYS cap resource consumption (timeouts, memory limits, rate limits) for untrusted inputs.

## Performance Rules
- NEVER use N+1 query patterns. Batch with `WHERE id = ANY($1)` when processing collections.
- NEVER use unbounded in-memory collections. Set explicit size limits and eviction policies.
- ALWAYS add database indexes for frequently queried column combinations.
- Use `CREATE INDEX` (not `CONCURRENTLY`) in migration files (sqlx runs in transactions).

## Git Safety Rules (MUST follow)
- NEVER run `git checkout --`, `git restore`, or `git reset --hard` on files that show as modified in `git status` without first running `git stash`. Uncommitted changes are irrecoverable.
- ALWAYS run `git status` before any destructive git operation to understand what will be affected.
- ALWAYS use `git stash` (not `git checkout --`) when you need to temporarily revert files. Use `git stash pop` to restore.
- NEVER use worktree-isolated agents (`isolation: "worktree"`) when `git status` shows uncommitted modifications to files the agent will touch. Worktrees branch from HEAD, not the working tree — the agent will miss all uncommitted work.
- ALWAYS complete and verify data model changes (struct fields, migrations, protocol types) BEFORE launching parallel agents that construct those types. Otherwise agents use stale field names requiring manual reconciliation.

## Docker Build Notes
- BuildKit uses persistent exec cache mounts for `/usr/local/cargo/registry` and `/app/target`
  (see `controller/Dockerfile` lines 58-60 and 79-82).
- These survive `docker compose build --no-cache`. If builds produce stale artifacts, run:
  `make docker-clean-rebuild` to prune cache mounts and rebuild from scratch.
- `make rebuild` clears Docker layer cache but NOT BuildKit exec cache mounts.
- `make recover` fixes corrupted BuildKit metadata but not stale exec caches.
- **cargo-audit + RustSec advisory database are baked into both the
  controller and builder images** at image-build time at the stable path
  `/opt/talos-advisory-db`. The compilation service passes
  `--db /opt/talos-advisory-db` to every `cargo audit` invocation so the
  path is explicit (see `compilation::container::ADVISORY_DB_PATH`) — env
  derivation via `$CARGO_HOME` would silently break because the runtime
  points it at a tmpfs path that gets wiped per pod. The DB is frozen at
  build — rebuild images monthly to absorb new advisories. Without the
  bake-in step, every `compile_custom_sandbox` / `install_module_from_catalog`
  / inline `rust_code` request fails closed in production with "cargo-audit
  exited with an error". This was the 2026-04-27 prod regression —
  cargo-audit was missing from `controller/Dockerfile` AND the advisory DB
  was missing from `Dockerfile.builder`.

## WASM Module Development Rules (MUST follow)
- NEVER use top-level `serde_json::Value` to parse upstream payloads. Use typed `#[derive(serde::Deserialize)]` structs — 3-10x cheaper in WASM fuel. The `Value` type allocates a `HashMap<String, Value>` per JSON object; typed structs skip unneeded fields entirely.
- ALWAYS set explicit `max_fuel` on every workflow node. Default fuel (1M-5M) is rarely correct. Use `fuel_budget` in `hot_update_module` / `compile_custom_sandbox` to auto-calculate from expected payload shape.
- ALWAYS use `format=metadata` (Gmail) or field-limited queries (Jira `fields` param) when full response bodies aren't needed. Smaller payloads = less fuel + avoids the 65KB input limit.
- ALWAYS cap collection sizes: `MAX_RESULTS`, `take(N)`, thread caps. Match caps to schedule cadence (e.g., 15-min poll → `newer_than:15m`, not 30m).
- ALWAYS specify `capability_world` explicitly when compiling modules. Use least-privilege: `minimal-node` unless HTTP/secrets/etc. are needed.
- ALWAYS validate required config keys early in `run()` with clear error messages (e.g., `ok_or("Missing AUTH_HEADER config")`).
- ALWAYS use versioned API endpoints (e.g., `/rest/api/3/` not `/rest/api/2/`). Pin to the latest stable version to avoid deprecation (HTTP 410).
- ALWAYS run `validate_workflow` after modifying node configs. ALWAYS run `test_workflow` with assertions before considering a workflow production-ready.
- NEVER assume upstream input shape — check multiple possible formats (arrays, nested objects, trigger input) and return graceful empty results when no data is found.
- When rewriting modules, use `hot_update_module` with `fuel_budget` to recompute max_fuel from actual payload characteristics.

## Code Conventions
- Rust: Follow existing patterns. Use `anyhow::Result` for error handling. Use `tracing` for logging.
- Frontend: React functional components with hooks. Zustand for state. No `dangerouslySetInnerHTML`.
- Environment-aware behavior: Check `config::is_production()` or `RUST_ENV=production`.
- Tests: Don't modify test files unless fixing tests for code you changed.

## Migration Rules
- Never modify an already-applied migration (changes the checksum, breaks sqlx). If an applied migration is buggy, ship a follow-up migration that corrects it — don't edit the original. See `20260414115200` (buggy envelope-split) + `20260414124348` (the actual fix) as an example.
- Always create new migration files with timestamp prefix: `YYYYMMDDHHMMSS_description.sql`
- Use `IF NOT EXISTS` / `IF EXISTS` for idempotency.
- No `CONCURRENTLY` (incompatible with sqlx transaction wrapper).
- For row-level data migrations that may hit malformed rows, use a PL/pgSQL `FOR ... LOOP` with nested `BEGIN/EXCEPTION` per iteration — the nested block creates an implicit SAVEPOINT so one bad row doesn't abort the batch. A bare `DO $$ ... EXCEPTION WHEN others $$` at the outer level catches errors but rolls back everything, silently no-op'ing the migration.

## Architectural Mandate (CRITICAL)

**Workspace topology after the May-2026 spike.** The controller bin is now ~7.3k LoC (down from ~95k); 105 `talos-*` workspace crates own the implementation. The bin is bootstrap (main.rs ~6.4k, lib.rs + ~59 re-export shims under 10 LoC each). Every former top-level module in `controller/src/*` is now a small re-export shim pointing at its canonical home crate; do not write new logic in those shims. When a path like `crate::foo::bar` appears in remaining controller code, treat it as syntactic sugar for `talos_foo::bar` — the dep tree, lints, and ownership belong to the underlying crate.

The MCP handler tree lives in `talos-mcp-handlers` (~65k LoC, 27 source files: 21 handler-domain modules + lib/types/utils/schemas/tests support). The GraphQL surface lives in `talos-api`. Both keep `pub mod` re-export shims at `controller/src/mcp/mod.rs` and `controller/src/api/mod.rs` so existing import paths keep resolving. **When the priority-extraction list below references `mcp/foo.rs`, the actual file is now `talos-mcp-handlers/src/foo.rs` — the work is the same, the path moved.**

**Incremental clean architecture extraction.** MCP handlers must be thin wrappers (~30–50 lines):
1. Parse args → validate → call service → format response.
2. New domain logic → goes in a domain/application service, NOT inline in the handler.
3. Touching an existing handler → extract SQL into a repository method, extract validation into a validator.

**Priority extractions (highest value, do these when touching related code).**
Paths reference `talos-mcp-handlers/src/*.rs` post-extraction (the historical
`controller/src/mcp/*.rs` paths still resolve via the re-export shim).
**Status (2026-05-05, post-r304):** raw-sqlx-in-handlers count is
**0** workspace-wide. The two named LoC monsters from prior sessions
(`handle_replay_workflow_mode` and `handle_add_node_to_workflow`'s
inline-Rust dispatch) are extracted; replay shipped in r303,
inline-compile in r304. Architectural mandate is fully on the
service-extraction track now — the cross-protocol Arc-injected
service pattern (see r295 `ExecutionOrchestrationService`, r302
`WorkflowManifestService`, r303 `ReplayService`, r304
`InlineCompileService` in "Completed extractions") is the canonical
shape: typed input + outcome structs, `thiserror` enum with stable
`jsonrpc_code()` mapping, `user_facing_message()` collapsing
internal errors to a generic message (security: never leak
schema/query details), Arc-wrapped dep injection, single instance
shared across MCP and GraphQL ctx. Remaining structural work below:
- `search.rs` → **next up.** Semantic search uses an embedding
  fallback chain (Anthropic / Ollama / OpenAI / etc.) that wants to
  live in a `SearchService` so the chain runs from one place. Same
  pattern as r303/r304; smaller LoC than either but completes the
  named-priority list.
- `secrets.rs` → extend `SecretsManager`. Already raw-sqlx-free;
  extraction here is about reconciling the name+namespace vs.
  key_path semantic mismatch in `handle_*`, not pulling SQL. More
  design problem than mechanical extraction — touches the security
  surface, so plan carefully.
- `workflows.rs` → most heavy lifters already extracted (r297/r298/r299
  pure-helper passes + r304's inline-compile lift shaved ~590 LoC
  total across `handle_test_workflow`, `handle_test_workflow_draft`,
  `handle_add_node_to_workflow`). `handle_create_workflow` is now
  ~300 LoC of orchestration; further reduction would be
  diminishing-return helper churn unless a NEW consumer requires it.
  `handle_add_node_to_workflow` is now ~516 LoC (down from ~767);
  remaining content is graph-mutation orchestration that already
  uses helpers — not a structural target.

**Completed extractions (follow the pattern):**
- `AdvancedRepository`, `AnalyticsRepository`, `ExecutionRepository` — repository-per-domain.
- `WorkflowRepository` — 45+ methods. `mcp/graph.rs` handlers use `fetch_graph_json` / `save_graph_json` helpers that delegate here. Tag/embedding methods added 2026-04-16.
- `ActorRepository` — `get_actor_full_summary` (LATERAL join consolidation), approval policies, action log, budget, secret grants, status transitions. `resolve_actor_via_repo` used by all 20+ handlers. `spawn_log_action` + `spawn_log_admin_event` lifted here in May-2026.
- `ModuleRepository` — ref counting, delete/batch-delete, rename, org sharing. Created 2026-04-16.
- `ParallelWorkflowEngine` — dispatcher unification + `build_encrypted_secrets()` helper (consolidates 5-step secret pre-fetch; fixed loop-node dispatch gap 2026-04-16).
- `SubworkflowContractService` — handler extraction model. Use as the template for future thin-handler extractions.
- `LlmClient::with_vault` — vault-first key resolution with env fallback.
- `WorkflowCreationService` (May-2026) — pulled out of `handle_create_workflow_from_description` (1,104 → 173 LoC). Cross-protocol consumer: same service backs MCP and the GraphQL `createWorkflowFromDescription` mutation.
- `HotUpdateService` (May-2026) — pulled out of `handle_hot_update_module` (530 → 78 LoC). Pure-helper-tested transformation logic (`resolve_source`, `wrap_source_with_module_macro`, fuel cascade, world-short mapping); typed `HotUpdateError` enum maps cleanly to JSON-RPC codes.
- `ExecutionOrchestrationService` (r295, May-2026) — pulled out of `handle_trigger_workflow` (493 LoC), `handle_retry_execution` (137 LoC), `handle_replay_execution` (190 LoC), `handle_replay_execution_with_input` (197 LoC) — ~1020 LoC of orchestration across `executions.rs` + `workflows.rs` collapsed into one cross-protocol service. Same `Arc` is consumed by the MCP handlers AND the GraphQL `triggerWorkflow` mutation; one engine builder, one NATS dispatch path, one auth gate. Includes a TOCTOU fix in r296 (`WorkflowRepository::create_execution_under_concurrency_limit` — `SELECT ... FOR UPDATE` + COUNT + INSERT in one transaction). The canonical reference for the cross-protocol service pattern.
- `WorkflowManifestService` (r302, May-2026) — pulled out of `handle_export_platform_state` (87 LoC) + `handle_import_platform_state` (290 LoC). Both handlers became thin wrappers (~9 LoC, ~41 LoC). `ManifestError::user_facing_message()` security invariant: `Internal` collapses to `"Database error"` so the protocol response never leaks schema/query details (locked in by a unit test). Cross-protocol-ready; same Arc can back a future GraphQL mutation. `platform.rs` 1739 → 1429 LoC.
- `ReplayService` (r303, May-2026) — pulled out of two ~340 LoC handlers in `sandbox.rs` (`handle_replay_module_regression` and `handle_replay_workflow_mode`). Both paths share one private `run_replays()` kernel — load-with-template-fallback, secret prefetch, governance/unknown world rejection, and per-row execute-and-diff loop run from one place. Pure-helper `plan_workflow_replay` walks the graph for fan-in detection; testable without runtime. `sandbox.rs` 3822 → 3354 LoC. 18 unit tests cover the fan-in path, capability-world rejection, error code stability, internal-error message redaction, and counter aggregation. Output shape preserved byte-for-byte.
- `InlineCompileService` (r304, May-2026) — pulled out of `handle_add_node_to_workflow`'s `rust_code` branch (~340 LoC of capability check + lint + compile + shared-module guard + permission-drift guard + persistence). Handler 766 → 516 LoC. Pre-compile actor capability check inside the service (saves 30–60 s of compile budget on a doomed request); post-compile defense-in-depth check stays in the handler since it covers BOTH the inline-Rust path AND the `module_id` path. Every operator-recognised error string copied verbatim from the pre-extraction handler — `"Compiled successfully but no WASM bytes were generated"` and friends are locked in by unit tests. 12 unit tests; cross-protocol-ready.

**May-2026 workspace decomposition** (controller bin ~95k → ~7.3k LoC). New crates that own former controller modules whole-cloth:
- `talos-templates`, `talos-llm`, `talos-atlassian`, `talos-slack`, `talos-compilation`, `talos-wit-inspector` — leaf services.
- `talos-integration-helpers` — shared `RenewalFailure` + `looks_like_oauth_failure` for push-notification integrations (breaks the gmail↔gcal coupling).
- `talos-google-calendar`, `talos-gmail` — push-notification stacks per `docs/integration-pattern.md`.
- `talos-continuation-trigger` — approval-gate / suspension dispatch (was `pub(crate)` in mcp::advanced; lifted so webhooks can call it without depending on mcp).
- `talos-webhooks` — inbound webhook router + dispatch chain.
- `talos-api` — entire GraphQL surface (QueryRoot/MutationRoot/SubscriptionRoot, 40 handler files, dataloaders, validation, `TalosSchema` alias).
- `talos-api-docs` — GraphQL Playground + REST docs.
- `talos-ws-auth` — GraphQL-over-WebSocket handshake + auth.
- `talos-mcp-handlers` — entire MCP handler tree (27 source files, ~65k LoC, ~280 tool handlers across 21 handler-domain modules, McpState).
- `talos-audit-event` — shared cryptographic audit-event primitives (the hash-chained, HMAC-signed `AuditEvent` + `ExecutionLedger` + offline `verify_chain`). SINGLE SOURCE OF TRUTH for audit hashing/signing: the worker producer AND the `talos-audit-ledger` WORM consumer both depend on it so the verifier can never drift from the producer. `worker/src/audit.rs` is now a re-export shim.

**Good examples to follow:** `ModuleExecutionService`, `AuthService`, `SecretsManager`, `CompilationService`, `SubworkflowContractService`, `ParallelWorkflowEngine`, `ActorRepository::get_actor_full_summary` (LATERAL join pattern), `graph.rs::fetch_graph_json` (helper delegation pattern).
**Anti-pattern to avoid:** Raw `sqlx::query(...)` calls directly inside MCP handler functions. **Down to 0** in `talos-mcp-handlers/src/*.rs` as of 2026-05-04 and held at 0 through r303/r304 (down from 371 → 276 → 0). The lint-equivalent invariant is now: any new handler PR adding raw `sqlx::query` to a `talos-mcp-handlers` file is a regression — push the SQL into the relevant repository crate first. `encrypted_secrets: Default::default()` in any dispatch path is the other regression class.

## Testing Conventions
- **Unit tests exercise real production code.** Don't shadow production logic with a test-local copy (it drifts). Extract the logic into a `pub(crate)` method and call it from both sides. See `SecretsManager::try_llm_keys_cache_hit` + `llm_keys_cache_tests` for the pattern.
- **Stub constructors for test-only deps.** Use `SecretsManager::test_stub_for_cache()` as the pattern — a real struct with a lazy DB pool that panics if touched, so cache-layer tests don't need Postgres.
- **Tests that hit async code** need `#[tokio::test]`, not `#[test]`. `sqlx::PgPoolOptions::connect_lazy` panics outside a Tokio runtime.

## Pre-deploy validation
- **`make lint` enforces structural rules** via `scripts/lint-structural.sh`. 43 checks today (the authoritative, inline-documented list lives in the script), each tied to a specific past regression so it catches at PR-time the class of bug that survives `cargo check` cleanly but breaks at CI or request time:
  1. raw `actor_memory` writes + legacy `value`-column projections outside `talos-memory/`
  2. bidirectional `controller/src/main.rs` route ↔ `deploy/helm/talos/templates/frontend/configmap.yaml` location alignment (opt-outs: `// no-nginx-route`, `# no-controller-route`)
  3. legacy `__agent_context__` key regressions (canonical is `__actor_context__`; opt-out `// allow-agent-context-key`)
  4. per-call `SecretsManager::new(...)` outside canonical wiring (opt-out `// allow-secrets-manager-new`)
  5. `helm template` clean-render with defaults AND with every `enabled: false` toggled on
  6. raw `sqlx::query*` inside `talos-mcp-handlers/` (opt-out `// allow-mcp-sqlx`)
  7. `cargo clippy --workspace --no-deps -- -D warnings` matching CI (gated behind `TALOS_LINT_CLIPPY=1` because clippy is a 60-90s build; opt in locally for parity at PR time)
  8. `trigger_type` column references against `workflow_executions` schema
  9. boolean-column drift against `workflow_schedules` / `webhook_triggers`
  10. `let _ = sqlx::query(...).await` silent-swallow outside tests
  11. misleading-success Err-only outbound webhook fires
  12. caller-supplied limit clamp drift (the `.unwrap_or().min()` shape)
  13. chart-wide labels under NetworkPolicy `from:` / `to:` selectors
  14. `talos-api` `Err(async_graphql::Error::new)` missing `.extend_safe()`
  15. `graph_json` writes via canonical chokepoint (MCP-1226/1227/1228/1229)
  16. `wit/talos.wit` ↔ `module-templates/wit/talos.wit` drift
  17. `encrypted_secrets: Default::default()` outside tests
  18. `JobResult.sign()` in worker must use `sign_with_worker_id`
  19. worker must single-publish each `JobResult` (no dual NATS publish)
  20. every wasmtime WASM proposal must be explicitly opted in/out
  21. integer-cast wraparound (`.as_u64()…as u32` / `map(|i| i as i32)`)
  22. GraphQL queries with sibling mutations must have a scope gate
  23. `encrypt_value()`/`decrypt_value_by_key()` without AAD outside the secrets table
  24. inline control-char predicate in a write surface (use `talos_validation`)
  25. bare-pool queries on RLS tables in `talos-api/src/schema` (must be tenant-scoped tx)
  26. in-flight status literal must include `'resuming'`
  27. `make_interval(<int arg> => $N)` must cast `$N::int` (int4-only pg arg)
  28. OFFSET pagination needs a unique `ORDER BY` tiebreaker
  29. no bare `engine.set_actor_id()` outside the actor-application path
  30. no `CONCURRENTLY` in migrations (sqlx runs them in a transaction)
  31. outbound HTTP response bodies must be read through `talos-http-body` (cap OOM)
  32. `reqwest Client::builder()` must set an explicit `.redirect()` policy
  33. capability-world ranking must use `talos-capability-world`, not a local re-impl
  34. `actor_memory` `value_format` reads must fail loud (MCP-S2 AAD dispatch)
  35. `cargo fmt --all -- --check` (rustfmt drift) — runs by default
  36. `cargo audit` (RustSec advisories) — env-gated `TALOS_LINT_AUDIT=1`
  37. secret-holding structs must redact in `Debug` (no `derive(Debug)` over a plaintext secret)
  38. raw `wasi:sockets` grant (`allow_wasi_network`) must gate on `max_llm_tier` — a tier-1 actor with raw sockets bypasses `allowed_hosts` + the host-fn tier gate and can egress to any public IP (PR #156); opt-out `// allow-wasi-network-no-tier` for Tier2-default actor-less paths
  39. `workflow_executions` status writes must carry a status guard — a bare `SET status='<lit>' … WHERE id=$N` clobbers a row another writer owns (crash-recovery `resuming` claim, terminal re-clobber, the resume `pending` TOCTOU; PR #158/#159); add `AND status NOT IN ('completed','failed','cancelled','resuming')` or use the guarded repo methods; opt-out `// allow-bare-status-write`
  40. SSRF-checked outbound URLs must use the shared safe HTTP client — a file calling `check_outbound_url_no_ssrf` is firing a user-supplied URL, so its reqwest client MUST come from `talos_http_utils::outbound::build_outbound_webhook_client[_with_timeout]` (connect-time `ControllerSsrfResolver` closes the DNS-rebinding TOCTOU the call-time check can't; PR #162); a raw `reqwest::Client::builder()` there is the gap; opt-out `// allow-raw-reqwest-ssrf-checked`
  41. approval-gate token lookups must key on `token_hash`, not the raw token — a file referencing `workflow_approval_gates` must not do a bare `WHERE token = $N` equality (raw-secret byte comparison); the `/approvals/<token>/{approve,reject}` handler + preview look up `WHERE token_hash = sha256_hex(provided)` then constant-time compare the full token (`approval_token_matches`, generated `token_hash` column, PR #217). The check ignores `token_hash`, `state_token` (OAuth CSRF nonce), and `verification_token`; opt-out `// allow-approval-token-raw-lookup`
  42. org-pinned-table creates must run on a tenant-scoped tx — an `INSERT INTO {workflows,actors,secrets}` (the org-setting write) must execute on a `begin_org_scoped` / `begin_personal_org_write` tx, NOT the bare `&self.db_pool`/`db_pool`, so the org-pin RLS WITH CHECK (`org_id = app.current_org_id`) enforces once `TALOS_RLS_SET_ROLE` flips on (RFC 0006 / RFC 0005 S3, PRs #219–#222). A bare-pool create only passes via `unset → permit` (silently un-enforced). Comment lines are skipped; UPDATE/DELETE that don't move `org_id` are out of scope; opt-out `// allow-unscoped-org-write` for engine/system/seeding paths
  43. controller test setup must use the isolated-DB harness, not `init_pool()` — `controller/tests/common::setup_test_context` / `isolated_db_pool` give every test its OWN database (a `CREATE DATABASE … TEMPLATE` clone of the migrated DB, dropped on scope-exit), retiring the global-`DELETE FROM …` shared-state cleanup + the nextest serialization it forced. A test calling `controller::db::init_pool()` connects to the shared `DATABASE_URL` directly — reintroducing the cross-binary flake and writing to the `talos_ctl` TEMPLATE the other binaries clone. Only `env_vars.rs` (which TESTS init_pool's missing-URL path) is exempt; opt-out `// allow-test-init-pool: <reason>`
- **`scripts/smoke.sh` end-to-end probe.** Runs every public path against a deployed cluster (`/health`, `/auth/csrf` cookie seeding, `/graphql` with full CSRF round-trip, `/ws` handshake, `/mcp`); optional Phase-B encryption write→read round-trip with `SMOKE_AGENT_TOKEN` + `SMOKE_ACTOR_ID`. `deploy/k3s/install.sh` invokes it as §9.1 at the tail of every deploy — a failed smoke warns but doesn't abort install. Run manually any time with `make smoke BASE_URL=https://…`.
- **When introducing a new top-level path on the controller**: add a matching `location` block to the chart's nginx ConfigMap, OR mark the route `// no-nginx-route: <reason>` (kubelet probes, in-cluster scrape, etc.). The lint check 2 catches drift either way; the smoke test fails fast in production if the path is supposed to be public but nginx routes it to the SPA.

## Image publishing
- **Local-build path is canonical** (May-2026): auto-triggers on the four image/publish workflow files (`ci.yml`, `release.yml`, `main-publish.yml`, `template-publish.yml`) are gated to `workflow_dispatch:` only. The workflow YAML is preserved as reference (and for future GHA re-enable) — the `push:` / `pull_request:` / `tags:` blocks are commented out, not deleted.
- **Exception — `quality.yml` IS auto-triggered** (Jun-2026): the heavy correctness gates too slow/networked for the pre-push hook — full Rust test suite, the env-gated **integration** tests (`make test-integration`: RLS isolation, crash-recovery, …) that `cargo nextest` alone skips, the networked RUSTSEC advisory scan (`make audit`), and a frontend lint+test backstop — run on `pull_request` to main + a nightly `schedule` + `workflow_dispatch`. It deliberately excludes the expensive image-build jobs (those stay in `ci.yml`). This is the unbypassable backstop for the gates the (opt-in) pre-push hook can't cover; it exists because the gated integration suite silently rotted (a security RLS suite sat red on main for days — PR #181/#182).
- **`scripts/publish-images.sh`** is the canonical build path. Mirrors `main-publish.yml`'s contract: builds via `docker compose build controller worker` plus a separate `docker build -f frontend/Dockerfile` (the compose file points the frontend at `Dockerfile.dev` for local-dev), pushes `:main-<sha>` (+ `:main-latest`) to `ghcr.io/<owner>/talos-*`, captures digests via `docker inspect`. Flags: `--no-push`, `--no-sign` (signing default ON — see below), `--allow-dirty`, `--skip-ci-check`, `--service NAME`, `--platform linux/amd64` (default, mandatory on Apple Silicon → x86_64 deploys), `--update-env PATH`. Emits a copy-pasteable `TALOS_*_DIGEST=…` block for `/etc/talos/install.env`.
- **Publish gate (2026-07-01)**: pushing requires (a) a **clean tree** (dirty publishes REFUSED; `--allow-dirty` for debugging, tags suffixed `-dirty`) and (b) a **green `quality.yml` run for HEAD**, verified via `gh run list --commit`. `quality.yml` gained a `push: branches: [main]` trigger so squash-merged main commits have a run bound to their own SHA (PR runs attach to the PR head SHA). Bypass is explicit: `--skip-ci-check` / `TALOS_PUBLISH_SKIP_CI_CHECK=1`.
- **Signing is DEFAULT-ON** (flipped 2026-07-01; provenance is the default act, skipping it the deliberate one — the batched single-OAuth-tab flow removed the cost that justified default-OFF). Opt out with `--no-sign` or `TALOS_PUBLISH_SIGN=0`. The script BATCHES all images into a single `cosign sign --yes` invocation — one browser tab, one OAuth token, three Fulcio cert issues. Fallback to per-image loop only if the batched call fails (old cosign versions, etc.).
- **Signing identity binding**: locally-signed images carry the operator's GitHub OAuth identity (via Fulcio), NOT a workflow URI. Production clusters with Sigstore enforcement enabled (`TALOS_SIGSTORE_REQUIRED=true`) need their `TALOS_SIGSTORE_IDENTITY_REGEXP` widened to match the operator's email pattern. The chart-level signing contract is otherwise identical (cosign + Fulcio + Rekor public-log entry).
- **Secret rotation auto-bounce (MCP-1231)**: every dependent pod template (controller / worker / NATS / Neo4j / postgres) carries a `checksum/<secret>-data` annotation rendered from `helm lookup` over the live secret content. When install.sh rotates the bootstrap / postgres-credentials / neo4j-auth secrets out of band, the NEXT `helm upgrade` notices the data hash changed and rolls the consumer pods automatically. Pre-MCP-1231, every rotation required manual `kubectl delete pod talos-{nats,neo4j,postgres}-0` rituals — observed three days in a row during the in-cluster Postgres rollout.
- **Dirty-tree publishes are refused** by default (see publish gate above). With `--allow-dirty` the tags are suffixed `-dirty` so they can never be confused with a clean-main image. Don't deploy `-dirty` builds to production.
- **CI gates** (lint, test, structural lint) run locally via `make lint` and `cargo test --workspace`. Run `make hooks` once per clone to install the git hooks (`core.hooksPath=.githooks`): the **pre-push** hook runs `make lint` (fmt + structural + `clippy --workspace --no-deps -D warnings` + offline cargo-deny) **and `make lint-frontend`** (frontend eslint + prettier + vitest) so the CI-parity gates can't silently regress between manual runs, and the **pre-commit** hook keeps the fast secret/migration/compile checks on every commit. Emergency bypass: `git push --no-verify`. Still run `cargo test --workspace` + `make lint` before `bash scripts/publish-images.sh`.

## Postgres deployment modes
- **Default (`postgres.enabled: false`)** — operator wires `DATABASE_URL` in the bootstrap Secret pointing at a managed Postgres (Neon, RDS, Cloud SQL, etc.). This is the recommended path for any multi-node or production deployment. `install.sh` requires `TALOS_POSTGRES_URL` in this mode.
- **In-cluster (`TALOS_USE_INTERNAL_POSTGRES=yes` → `postgres.enabled: true`)** — chart deploys `pgvector/pgvector:pg17` as a single StatefulSet replica on a `local-path` PVC. The pgvector team's official image (Debian-based, derived from `postgres:17`) is required — NOT stock `postgres:17` / `postgres:17-alpine` — because the Talos schema uses `vector(N)` columns and migration `20260406000001` fails with "type vector does not exist" against any image without pgvector compiled in. The migration's `CREATE EXTENSION IF NOT EXISTS vector` is wrapped in `EXCEPTION WHEN OTHERS THEN` so it silently no-ops on stock postgres, then a later migration trips loudly on the missing type. Single-user / homelab path. Limitations: no streaming replication, no PITR, no off-host backup (daily `pg_dump` to a separate local PVC, retain 7 days). NOT for multi-node production.
  - Credentials live in a separate `<release>-talos-postgres-credentials` Secret (NOT in `talos-bootstrap`) so the Postgres pod only mounts its own user/password/db, not the full bootstrap blast radius (Vault tokens, master DEK, LLM keys, etc.).
  - Postgres runs as uid/gid **999** — the postgres user in the Debian-based pgvector image. The StatefulSet has its own `securityContext` block instead of inheriting the chart-wide 10001 default; pod-side `fsGroup: 999` matches the PVC ownership. Switching FROM `postgres:17-alpine` (uid 70) requires wiping the PVC because the old data dir is chowned to uid 70 and the new pod can't write into it.
  - postgresql.conf tuning lives in `templates/postgres/configmap.yaml` and is calibrated for a 4 GiB shared VM (shared_buffers=256MB, effective_cache_size=512MB, max_connections=60, scram-sha-256 password encryption). Override via `postgres.config.*` in values.
  - NetworkPolicy restricts ingress to three clients: controller, migrations Job, postgres-backup CronJob. Workers DO NOT reach Postgres directly — they route through signed NATS-RPC to the controller. Same isolation rule as Neo4j.
  - `helm.sh/resource-policy: keep` on both the credentials Secret AND the backup PVC so `helm uninstall` doesn't wipe the password or daily dumps.
- **Both Secrets MUST be in lockstep** if internal mode is used. To rotate: delete `talos-bootstrap`, `<release>-talos-neo4j`, AND `<release>-talos-postgres-credentials` together, then re-run `install.sh`. Deleting any subset puts the cluster in an inconsistent state — controller refuses to start when the Secrets disagree.

## Cache Patterns
- **TTL-bounded cache = read-path eviction + periodic sweep.** Read-path `remove()` handles active users; sweep handles users who went dark. Without the sweep, memory grows monotonically with distinct-users-ever-seen. See `SecretsManager::sweep_expired_llm_keys` wired into `main.rs` at the sweep interval.
- **Cache invalidation on write paths must be scoped.** Use `RETURNING id, owner_user_id` to scope invalidation to the affected user; fall back to `invalidate_all_*` only for legacy rows with NULL owner. Avoid "flush everything" on every write.
- **Short TTL for rotation-sensitive caches** (e.g. 60s for LLM keys) so rotations propagate quickly. Longer TTLs (5 min for DEKs) are fine for cryptographic material that rotates via explicit operator action.

## OCI template registry
- **Two source-of-truth modes, mutually exclusive.** `TALOS_REGISTRY_URL` set → controller pulls catalog from OCI registry, skips disk seeding entirely. Unset → disk seeding from `module-templates/` baked into the image. Don't mix; the previous "both run, OCI overrides" model created a 5-min regression window on every pod restart where the disk baseline overwrote operator-curated versions.
- **Discovery is via index artifact, not `/v2/_catalog`.** GHCR / GAR / ECR don't expose `_catalog`. The publish workflow pushes a `talos-tools/_index:latest` artifact whose **config blob** is JSON `{"templates": [{"name": "...", "tag": "..."}]}` listing every template. `registry::sync::IndexConfig` parses it. Self-hosted Docker registries fall back to `/v2/_catalog` automatically. Adding a new template = re-running `template-publish.yml`; the index is regenerated.
- **Publish via the controller binary, not a CI re-implementation.** `controller publish-templates --templates-dir ... --output ...` reuses the production `CompilationService` (cargo-component scaffold, WIT bindings, dependency allowlist). The GH Actions workflow `template-publish.yml` mounts the controller image and runs the subcommand — CI never re-implements the scaffold, so it can't drift. Updating compilation logic only happens in one place.
- **WASM digest verification on every pull.** `verify_oci_layer` (worker/src/main.rs) recomputes sha256 of pulled bytes and compares to the manifest's declared digest. Mismatch = fail closed (don't execute, don't cache, return JobStatus::Failed). Manifest with no layer descriptor = accept-with-warning. Pure function so it's unit-tested without a registry. Don't introduce a "trust mode" that bypasses this — the digest check is the only thing standing between a corrupted/MITM'd registry and arbitrary WASM execution.
- **Redis OCI cache has a 24h TTL** (`OCI_CACHE_TTL_SECS`). Without it, distinct module URIs accumulate forever. Tag-based URIs refresh daily; digest-based URIs (immutable) re-cache the same bytes harmlessly. Cache writes happen ONLY after digest verification passes.
- **Auth model**: anonymous works for public packages (recommended for templates — they aren't secrets, signing provides trust). Private packages: set `OCI_REGISTRY_USERNAME` + `OCI_REGISTRY_PASSWORD` in worker AND controller envs (PAT works as the password for GHCR). Bearer-token OAuth challenge flow is NOT implemented in the controller's reqwest paths or in the worker — `oci_distribution::Client` handles it for the controller's `pull_manifest_and_config` (uses oci-distribution), but the worker's reqwest fallback paths only support Basic.
- **Sigstore signing is the runtime trust boundary.** Every OCI artifact (templates + index) is `cosign sign --yes`ed in the publish workflow using GitHub Actions keyless OIDC. The worker `verify_oci_signature` shells out to `cosign verify` BEFORE the OCI pull body is processed — verification failure with `TALOS_SIGSTORE_REQUIRED=true` returns `JobStatus::Failed` and the WASM is never executed nor cached. Three policies: `Disabled` (dev), `Audit` (verify+log+continue, migration window), `Required` (verify+refuse, production). `cosign_verify_argv` is a pure function so the security-critical command construction is unit-tested without invoking cosign — DO NOT bypass `--certificate-identity-regexp` or `--certificate-oidc-issuer`; either omission lets a valid Sigstore signature from any other workflow on any other repo pass verification. **Two-layer attestation:** the `_index:latest` artifact itself is signature-verified BEFORE its config blob is parsed (`talos-registry/src/sync.rs::try_pull_index`), AND each template entry is verified again at template-fetch time. A `Disabled` policy in dev would let an attacker replacing the index alone redirect template names → attacker-controlled tags; the startup gate (`enforce_production_sigstore_policy_explicit`) refuses to boot in prod without an explicit policy choice, so the dev-only fall-through is non-exploitable in any real deploy.
- **Sigstore identity regexp pins to the workflow URL.** Format: `^https://github\\.com/OWNER/talos/\\.github/workflows/template-publish\\.yml@`. Without the trailing `@`, an attacker who creates a fork named `template-publish.yml-evil.yml` could match. The OIDC issuer pin (`https://token.actions.githubusercontent.com`) restricts to GitHub Actions tokens specifically. Cosign is bundled in the worker Dockerfile at a pinned version so verification doesn't depend on operator's PATH or apt repository state.

## HTTP middleware & router rules
- **`cors_middleware` short-circuits ALL `OPTIONS` requests** (`controller/src/main.rs::cors_middleware`). It builds an empty 200 response and returns immediately, never calling `next.run`. Consequence: an `OPTIONS` preflight cannot trigger ANY downstream middleware (including `csrf_protection_graphql`). Don't try to seed cookies or run validation logic via OPTIONS — pick a real GET endpoint.
- **`tower_cookies::CookieManagerLayer` on a sub-router merged AFTER the outer `CookieManagerLayer` is unreliable.** When a sub-router is `.merge`d into the parent app and you re-add `CookieManagerLayer + cookie-modifying middleware` inside that sub-router, `Set-Cookie` headers can fail to appear in the response (root cause not pinned down — likely a layer-ordering interaction with axum's response mapping). For cookie writes on routes that bypass the main cookie layer, build the `Set-Cookie` header by hand in the handler. See `seed_csrf_handler` for the reference pattern.
- **Probe and exempt routes need their own Extension layers.** `probe_routes` is merged AFTER the rate-limit layers (so kubelet probes can't be 429'd). The Extension layers (`db_pool`, `redis_client`, `nats_client`) attached to the main app DON'T propagate to merged sub-routers — re-attach them on the sub-router or the handlers panic with "Extension not found". The `mcp_router` follows the same pattern.
- **Per-IP rate-limit identification MUST use RFC 7239 right-to-left X-Forwarded-For walk** (`rate_limit::extract_client_ip`). Reading the leftmost entry is exploitable: any client behind a trusted proxy can prepend a fake IP and the server attributes their requests to it. The walk skips trusted-proxy entries from the right; the first untrusted entry is the real client.
- **Probe paths are exempt from rate limiting two ways**: (1) architectural — `probe_routes` merged after rate-limit layers; (2) defence in depth — `is_rate_limit_exempt_path()` early-returns from `rate_limit_middleware` and `global_rate_limit_middleware`. With Traefik on `externalTrafficPolicy: Cluster`, kube-proxy SNATs all external traffic to a single node IP, so without the exemption a busy site evicts kubelet probes from the per-IP bucket → pod marked NotReady → 502 cascade.
- **Helm controller probes use `/live` and `/ready`, not `/health`.** `/live` is a trivial process-alive check (no DB/Redis/NATS calls) — a Postgres hiccup can't restart the pod. `/ready` returns 503 only when Postgres is down (Redis/NATS report degraded but still 200). `/health` is the user-facing combined check, kept for the frontend's `seedCsrfCookie` and ad-hoc curl.
- **WebSocket handlers MUST extract Origin from the request HeaderMap** and pass it into `ws_auth::handle_websocket_auth` — passing `None` makes EVERY WS connection fail in production with "missing Origin header" because `is_production()` requires the header. The handshake still returns `101` (the upgrade succeeds), then the socket is immediately closed by `handle_websocket_auth`, which the browser surfaces as `WebSocket connection failed:` with no detail.

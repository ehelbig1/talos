# 2026-09-26 — whole-codebase review: the fix packages

**What this is.** The fixes that followed a full review of the workspace at
`ef220804`, delivered as one branch (`claude/awesome-mccarthy-nesiu3`). Each
section below is one package, in the digest form CLAUDE.md's package bullets
used before 2026-09-25 (decided / deliberately NOT / measured / stated limits /
one home). They were first written as CLAUDE.md bullets EV–FE and moved here
when the branch was merged with `main`, because `main` had closed CLAUDE.md to
new package bullets. The letters are dropped: `main`'s own record for #959 is
also lettered EV.

**Rules that stayed in CLAUDE.md**, per the packages README: the correction
notes on `build_encrypted_secrets_for` being the one dispatch-secret home and
on the current workspace size.

## Merged with #959 (2026-09-25) — which implementation won

#959 bounded several of the same resource-exhaustion paths in parallel. Where
both sides fixed the same thing, the merge keeps one:

- **`fetch_all` batch response budget** — #959's `BatchByteBudget` (32 MiB per
  call, or one full response if larger; bytes RELEASED when an entry fails).
  This branch's guest-memory-sized budget was removed; its WARN line on refusal
  was kept.
- **SSE reader** — #959's `run_sse_reader` / `SseParser` (per-stream buffered
  byte budget, linear parse). This branch's UTF-8 fix is ported into
  `SseParser`: it buffers BYTES and decodes a line only once complete, so a
  multi-byte character split across two network chunks no longer becomes two
  U+FFFD (`a_multibyte_character_split_across_chunks_decodes_intact`).
  `host::line_reader` remains, used by `llm_streaming` only.
- **Graph-extraction pending cap** — #959's `admit_graph_extraction`
  (semaphore slot moved into the task, shed counter). This branch's
  `PendingSlot` was removed; its 180 s `GRAPH_EXTRACTION_TIMEOUT` around the
  hook call was kept, so a hung backend releases its concurrency permit.
- **Actor-memory persist** — #959's capped `PERSIST_MEMORY_ROW_SQL`. This
  branch's overwrite semantics were ported into it: `embedding`,
  `embedding_model` and `metadata` take the NEW write's values (NULL when
  absent), never the old row's. Both integration tests are kept.
- **Webhook auth circuit breaker** — this branch's keying was kept (per
  (source, trigger) for credential failures, a source-wide block after 20
  DISTINCT unknown trigger ids, an IPv6 source is its /64). #959's API was
  adopted on top: `reset_ip(ip, Option<trigger>) -> ResetOutcome` (now
  normalising to the /64 and clearing the source-wide block on a whole-source
  reset), `record_success(ip, trigger)`, and `blocked_ips()` returning
  `(source, Option<trigger>, until)` — `None` is the source-wide block, which
  `get_webhook_stats` renders as `trigger_id: null`. `reset_source` was
  removed (no caller).
- **AOT deserialize** — #959 moved compilation off the executor
  (`compile_component_guarded_on` / `load_precompiled_on`); this branch's
  `#[allow(unsafe_code)]` moved with the `Component::deserialize` call.
- **Check 54** — #959's sibling (#957) replaced CLAUDE.md's numbered check
  list with a one-line index and checks it. This branch's leg 54(b) over the
  old list was removed; the FB section's sentence about it is superseded.

## worker runtime: local-only egress is STRICTER than public; bounded host calls; typed fuel check; OCI bytes bound to the verified digest.

The local-egress-only connect-time resolver KEPT private/loopback/link-local addresses (incl. 169.254.169.254), so tier-1 guest HTTP (`wasi:http`, and fetch/graphql/webhook/stream via rebinding) reached internal hosts; now public is always denied and private only under the dev bypass (`resolved_addr_permitted`, one reader `allow_private_host_targets`). `fetch_all` has a batch-wide response budget bounded by guest memory; cache host fns have per-execution call (1000) / byte (64 MiB) budgets and every key a TTL (default 24 h, max 30 d); the ResourceLimiter charges a STORE-wide total. One byte-level SSE line reader (`host::line_reader`): linear, UTF-8 safe across chunks. Fuel exhaustion = `wasmtime::Trap::OutOfFuel` in the chain, never `"fuel"` in Debug text. `module_fetcher` resolves tag→digest ONCE, cosign-verifies `repo@digest`, fetches by digest; the `TALOS_OCI_ACCEPT_UNVERIFIED_MANIFESTS` escape is deleted and a non-`oci://`/`redis:` module_uri is refused in production. Claimed secrets are `Zeroizing` (`ZeroizingSecretMaps`); the metrics server reads the whole head; undecodable job messages count on `talos_worker_rejected_job_messages_total` and deliberately get NO fail-fast reply (nothing in them is authenticated). Boot uses `validate_sigstore_identity_regexp_for_policy`. **Not done**: one shared admission fn for `fetch`/`fetch_all` (each still ~1000 lines).
## engine: cancel finalizes module rows, resumes run the pinned version, oversized output fails, inline system nodes keep polling the pool.

A cancel calls `cancel_running_module_executions(…, SiblingCancelReason::WorkflowCancelled)` (the DB trigger fires only on `failed`); `WorkflowEngineError::CancelledByOperator` is distinct from the fence's `Cancelled` (`fence::was_cancelled_by_operator`). Crash/approval resume reads ONE `RESUME_GRAPH_SQL` (draft only when `workflow_version_id IS NULL`; a deleted pinned version skips). An oversized output is a node FAILURE; a batched sub-workflow sibling honours its own `skip_condition`; inline system-node awaits buffer module completions with arrival time (`await_polling_in_flight!`, heap-pinned — a stack pin overflowed `subflow_recursion`); the accumulated-context memo keys on mutation only; the scheduler confines a failed row write to a SAVEPOINT; the continuation claim is three-valued (`QueuedClaim`). Decrypted `__actor_context__` is never persisted: `WithoutEngineAuthoredKeys` for the `node_input` preview, `lift_actor_context_for_storage` + `EngineOpts::with_actor_context` for stored payloads. The delivery-error retry uses `next_dispatch_attempt`. `ParallelWorkflowEngine::build_encrypted_secrets` deleted. **Stated limits**: orphaned `InFlightSeals` on a mid-dispatch cancel are bounded by the periodic sweep; the SAVEPOINT has no test here.
## auth/API: atomic lockout and rotation, digest-verified API keys, hardening off `is_production()`.

Login claims an attempt slot BEFORE bcrypt (concurrent guesses no longer exceed 5); refresh consumes the session row atomically (a replay is reuse); `BOOTSTRAP_FIRST_USER_EMAIL` never falls back to first-user-wins and never grants on an unproven signup. API keys: SHA-256 digest + constant-time compare (legacy bcrypt rows upgraded), limiter charged on FAILURES only, `usage_count` throttled, deactivated owners refused. IPv6 clients key on /64. Idempotency never replays a GraphQL `errors` body or a `Cache-Control: no-store` response and binds method+path; credential-minting resolvers call `mark_response_no_store`. ONE predicate `talos_auth_types::browser_hardening_required()` (false only for unset/`development`/`dev`/`local`/`test`) drives Secure cookies, GraphiQL, the dev CSRF bypass and the scrape-token requirement, so `RUST_ENV=staging` is hardened. The REST cookie CSRF gate refuses the `X-API-Key` exemption; `generateCode`/`createModuleFromTemplate` join the heavy throttle; `update_member_role` requires Admin inside its tx; GraphQL webhook creation takes the MCP cap (`MAX_WEBHOOKS_PER_USER`, one lock helper). `ApiKeyOrgScope` DELETED (never inserted). **Not done**: an org-invite acceptance flow (product feature).
## crypto: master-key rotation is STAGED; a secret must name a DEK of its own scope.

`rotate_master_key` refuses unless every controller runs `TALOS_MASTER_KEY=<new>` + `TALOS_MASTER_KEY_PREVIOUS=<old>` (now transported by compose and the chart), rewraps only DEKs the new key cannot open (retry resumes), matches the requested key by derived identity; DEK creation takes the rotation lock SHARED and wraps after locking. `decrypt_secret_record` refuses v3 naming a non-global DEK and v4 naming another org's (`secret_dek_scope_mismatch`); the per-org sweep counts such a row failed (test rewritten to pin the refusal). Nonce cache refuses at its hard cap, nonces ≤96 B, canonical nonce checked before the Redis guard; DLP redacts past its depth cap; one AES-GCM framing (`aead_seal`/`aead_open_utf8`, layout pinned). `talos-workflow-signing` DELETED (migration `20260926150000`), `ProcessLocalReplayGuard` deleted. **Not done**: binding key_id+org_id as AAD into the DEK wrap (design: `wrap_format` column, migrated by the next rotation).
## integrations, marketplace, registry.

SSRF guard classifies the host AS reqwest parses it (percent-encoded IP literals caught) and the classifier covers 192.0.0.0/24, 198.18/15, 240/4, SIIT, 64:ff9b:1::/48. Webhook breaker keyed per trigger (IPv6 /64); suspension callbacks looked up by hash; DLQ cap enforced; typed router errors. Watch rows update under a row lock (`update_existing`, no insert); Gmail `find_by_email` defers (503) on a failed read; gcal disconnect stops every channel. OAuth: `invalid_grant` sets `needs_reauth_at`, login `?scopes=` allowlisted, Snyk emails unverified, raw `?error=` sanitised before logging. External DLP refuses `http://` in production (falls back to builtin; NOT in check 44, which requires a boot refusal), runs on dedicated threads, re-applies the credential-key pass. Marketplace: UNIQUE `(publisher_id, name, version)` (migration `20260926130000`), verified names reserved, publish freezes a snapshot, install gates the agent role on the INSPECTED world and never inherits `allowed_secrets`. Registry sync verifies and fetches by digest; catalog refresh is compare-and-set; stale-ref fallback tenant-scoped; ref-less Sigstore workflow pins refused under Required. Hot-update dependent scans owner-scoped and structural.
## memory/ML/LLM/data.

Classifier templates neutralise closing tags (pinned to `talos_memory::spotlight`); keyword fallback no longer resurrects below-floor rows or claims ~1.0 scores; background LLM spend carries the actor (`usage::scoped_actor`); linear training capped at 2000 class-balanced rows, fits on the blocking pool, non-finite models refused; every Neo4j op has `NEO4J_QUERY_TIMEOUT` (8 s) and write-path extraction is capped at 64 pending; fulltext seeds drop ASCII tokens <3 chars; ONE `talos_llm::anthropic` home with `send_with_retry` (honours `Retry-After`; transport errors deliberately NOT retried — a timed-out completion may be billed); an overwrite never keeps the old embedding or `metadata.kind`; per-org sweeps paged; migrations run on a dedicated connection (5 s lock_timeout); the controller sets `PR_SET_DUMPABLE=0` so a host-fallback `build.rs` cannot read `/proc/<ppid>/environ`.
## deploy/CI/frontend.

Publish workflows refuse non-main refs and every documented Sigstore pin ends `@refs/heads/main$`; published images build `[profile.dist]` (opt 3, thin LTO, unwind kept for check 53) on digest-pinned `rust:1.95` with pinned `sqlx-cli`/`cargo-audit`/`wizer --locked`; the controller image carries cosign; the cargo-audit ignore list is `.cargo/audit.toml`, synced to `deny.toml` by check 36; installer and vault-init keep secrets off argv; API-free pods get no SA token; Node 22. Check 54(b) requires this file's numbered list to cover 1..N once each. Frontend: WS retry resets on ack only and auth recovery is bounded; `ExecutionStatus` typed from the generated enum (17 dead comparisons, incl. the approval-pause teardown); editor save-race guard + unsaved-changes blocker (data router); server-`safe` errors shown; batched execution events; one-tab token refresh.
## an operator cancel is its own metric outcome; stored payloads keep no engine-authored keys; one failure-webhook dispatcher; `unsafe_code` denied.

`talos_scheduler_dispatches_total` gains `outcome="cancelled"` (6 outcomes, 18 pre-seeded series) and `talos_crash_recovery_total` a closed `CRASH_RECOVERY_OUTCOMES` (now also seeding `fenced`), so operator action no longer hides inside the split-brain signal; the herd alert excludes `cancelled` like `fenced`. `workflow_executions.input_data` has ONE writer (continuation); the other persisted payload is `output_data.__trigger_input__` — MCP `test_workflow_draft` copied decrypted `__actor_context__` into it and now calls `lift_actor_context_for_storage`, and `extract_trigger_input` strips engine-authored keys so replay/retry cannot re-persist a pre-fix row (forward-only). The failure-webhook dispatcher has ONE home, `talos_execution_orchestration::failure_webhook` (an unreadable URL is logged; a TLS-init failure logs per fire instead of panicking a detached task). `talos_github::verify_app_webhook_signature` deleted (a future App receiver reuses `talos_webhooks::signature`). `[workspace.lints.rust] unsafe_code = "deny"`: all 17 sites (3 production) carry a local `#[allow(unsafe_code)]` beside their SAFETY comment; the engine/protocol crates do not inherit workspace lints and have no unsafe. **Not changed, stated**: `module_executions.input_data`'s plaintext fallback (only without a `SecretsManager`) still carries the merged node input.
## backend gaps the frontend recorded.

`talos_memory::list_memories_with_ciphertext_batched_scoped` takes `MemoryKeyMatch { prefix, suffix }` — two independent SQL `LIKE … ESCAPE '\'` predicates through the one in-crate `escape_like_literal` (five copies folded), ≤256 B, refused not truncated — and windows each actor by `updated_at DESC` (an upsert never moved `created_at`, so rewritten keys fell out of the 1000-row window); GraphQL `actorsMemories(keyPrefix, keySuffix)`, Briefings asks `"/latest"`. `Workflow.nodeCount`/`edgeCount` derive in SQL over the requested page only (`pg_input_is_valid` guard — `graph_json` is TEXT; null on malformed), `graph_json` is projected only when the look-ahead selects it and an unloaded `graphJson` errors rather than rendering empty; the dashboard no longer downloads graphs. **`llmStream` has NO publisher** — worker streaming is guest-only, the worker credential is denied `talos.llm.stream.>`, `JobRequest` carries no node id — so the subscription has never yielded a token; `{nodeId, token}` needs a publisher decision (guest LLM output onto NATS: DLP, tier-1), a deny-list change and a signed or relay-mapped node id. Deliberately NOT built; the schema description now says so. Stated limit: the counts SQL is PREPARE-gated (check 88), not DB-tested.
## the URL gates `fetch`, `fetch_all` and `wasi:http` each copied have one home.

`host::egress_admission::admit_url` / `admit_parsed_url` (pure) decide URL byte cap → parse → scheme → empty allowlist → denied IP literal → `allowed_hosts` → egress posture and return `UrlAdmitted` (incl. `host_for_limit`) or `UrlRefusal`; `TalosContext::refuse_url` is the one recorder (audit denial, then latch). A characterization suite (`http_admission_characterization_tests`, 22 cases, no socket) was written FIRST and passes unmodified; it pins discriminant, class, diagnostic and budget per refusal. **Deliberately NOT extracted**: write-ceiling, strict egress, method allowlist, rate limits, DNS, breaker and vault — each already has one implementation, their POSITION differs by surface, and per-file source pins count them. **Recorded divergences, not unified** (each pinned): body cap before parse in `fetch_all` vs after the breaker in `fetch`; a dry-run mutation skips the method allowlist only in `fetch`; a per-host limit refusal is a metric in `fetch` but an audit row in `fetch_all`; `fetch` charges the budget before the method/cap/vault gates, `fetch_all` only for admitted entries; a DNS failure gets a diagnostic only in `fetch`. Log-only behaviour change. LoC `fetch` 970→831, `fetch_all` 1013→921. Stated limit: write-ceiling and strict-egress are not driven through either surface (process-global `OnceLock`).

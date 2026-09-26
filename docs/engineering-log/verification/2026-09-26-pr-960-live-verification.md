# 2026-09-26 — live verification of #960 on the reference fleet

**Deployed:** `server_version = 0.1.0+9fca35d` (MCP `session_start`), images
built 16:09Z, controller/worker/frontend started **T0 = 2026-09-26 16:12:06Z**.
Verification ran 17:56–18:10Z, so the post-deploy window is ~1 h 50 min. It is
compared against the same window 24 h earlier. Every read was read-only: SQL
inside `BEGIN READ ONLY … ROLLBACK`, Prometheus, container logs and MCP read
tools. Nothing was triggered, replayed or restarted.

**Environment facts that decide several checks:** `RUST_ENV` is unset on both
processes (development), so `browser_hardening_required()` is false and the
production-only refusals (non-OCI `module_uri`, Sigstore `Required`) are
inactive. `TALOS_SIGSTORE_REQUIRED` is unset (policy `Disabled`).
`WORKER_ALLOW_PRIVATE_HOST_TARGETS=false`. `TALOS_WRITE_CEILING_ENFORCED=1` and
`TALOS_ENVELOPE_SEALING=required` are set on both processes.

## Phase 0 — boot log since T0

No `ERROR` line in either process. Six distinct WARN lines:

| Line | Class |
|---|---|
| `TALOS_MASTER_KEY_PREVIOUS env var is set to empty — treating as missing` (1 per boot) | **NEW** — #960 made compose transport `${TALOS_MASTER_KEY_PREVIOUS:-}`, so every boot outside a key rotation logs it. Steady-state WARN (check 69's class). Fix candidate P1. |
| `WIT world over-declared … declared_world=agent-node detected_world=agent` (×3 per boot) | **Known line, newly diagnosed as a false positive**: the check compares `CapabilityWorld`'s short `Display` form (`agent`) against the source string (`agent-node`) with `eq_ignore_ascii_case`. The two are the SAME world. 3 of 3 occurrences in the retained log are this pair. Fix candidate P2. |
| `GitHub App connect flow DISABLED …` | Expected (package ET): user-auth credentials unset on dev. |
| `JWK refresh failed` / `google push: JWT verification failed` / `JWK refresh recovered … refused_in_previous_window=84` | Known (packages AP/ET): one 60 s backoff at 16:23:34, 11 min after boot (not a boot race). The 84 refused pushes are Pub/Sub redeliveries, which it retries. |

## Phase 1 — checklist

| # | Check | Result | Evidence |
|---|---|---|---|
| A1 | Migrations `20260926110000/120000/120100/130000/150000` | PASS | All five present, `success = t`, installed 16:12:05Z. |
| A2 | `api_keys.key_digest`, `integration_credentials.needs_reauth_at` | PASS | Both columns exist. |
| A3 | Workflow-version signing columns gone | PASS | `workflow_versions` has 11 columns; neither `graph_hash` nor `graph_signature`. |
| A4 | `UNIQUE (publisher_id, name, version)` | PASS | `module_marketplace_publisher_name_version_key` on `module_marketplace`. |
| A5 | Alerts: nothing newly firing / pending >15 min | PASS | Only firing alert is `TalosBackupRestoreDrillLastRunFailed`, active since 2026-09-23 (known: `op` 2.16.1, package EO). Since T0: `LowCacheHitRate` pending (known benign, package W), `TalosFuelHeadroomDetectorBlind` pending ~2 min after restart then cleared (pre-existing post-restart shape: the gauge is 0 until the first sweep). `TalosAdvisoryDbAging` STOPPED firing because the rebuilt image refreshed the DB. |
| A6 | Pre-seeded series | PASS | `absent()` empty for all four; `count(talos_scheduler_dispatches_total) = 18`, 3 with `outcome="cancelled"`. |
| B1 | Workflow outcomes vs 24 h earlier | PASS | Post: 28 completed / 0 failed. Previous window: 32 / 0. Six workflows ran in both windows at matching rates. 7-day baseline: 29 failed of 2 756. |
| B2 | Module executions | PASS | Post: 88 completed, 0 failed (previous window 104/0). No `reason_class`/capability-denied line since T0. |
| B3 | Tier-1 actors still work under the stricter resolver | PASS / partly UNVERIFIED | `personal-assistant` (tier1 + public): 27 runs since T0, all completed, 112 Gmail OAuth resolutions, HTTP 200s to `gmail.googleapis.com`. `personal-finance` (tier1 + public): no run since T0 (draft, manual only) → UNVERIFIED. `content-pipeline` (tier1, egress NULL → **local**, the posture the change affects): its only node is `LLM Inference` (secrets-node, no `allowed_hosts`). By code, `llm::complete*` to Ollama uses the dedicated `local_llm_http_client()`, NOT the guest SSRF resolver, so it is unaffected. Live proof is its next run, 2026-09-28 12:00Z. 0 modules grant a private/LAN/internal host. |
| B4 | `module_uri` refusal | N/A (dev) | `RUST_ENV` unset → the refusal is inactive. The fleet dispatches `redis:wasm:…` URIs, which would pass in production too. |
| B5 | Sigstore boot lines | N/A | Policy `Disabled` (unset). The boot validates a regexp only when one is configured, so there is no line to find; the `Required` refusal is unit-tested only. |
| C1 | MCP agent-token auth | PASS | This session's Talos MCP calls (`session_start`, `security_audit`, …) authenticated; unauthenticated `POST :8000/mcp` → 401. |
| C2 | Legacy API keys upgrade to `key_digest` | N/A | `api_keys` has 0 rows. |
| C3 | Refresh rotation atomic | UNVERIFIED (needs operator) | No browser session since 2026-09-24 17:14Z: `rotated_session_audit` last row then, 0 `auth_audit_log` events since T0, all `talos_auth_token_reuse_total` outcomes 0. |
| C4 | Browser hardening | N/A | `RUST_ENV` unset → hardening off by design; login over `http://localhost:3002` unaffected. |
| C5 | WebSocket hub | UNVERIFIED (needs operator) | `talos_ws_active_sessions = 0`, all handshake outcomes 0 since T0: no page open. |
| D1 | Secrets decrypt | PASS | 0 `secret_dek_scope_mismatch`; 112 Gmail OAuth resolutions; `pa-ask-email` completed 15×. 0 of 17 secrets and 0 of 19 memories pending an org DEK (`talos_org_dek_pending`). |
| D2 | `__actor_context__` never persisted | PASS (forward) | `workflow_executions.input_data` (the continuation writer, `pa-ask-email`): **848 of 848** rows in the prior 7 days carried `__actor_context__`, the last at 16:10:37Z; **0 of 8** since T0. `output_data` is encrypted on 32/32 post rows; a sampled post-T0 output via `get_execution_output` held neither `__actor_context__` nor `__trigger_input__`. `module_executions` payloads are 100% encrypted. **Residue (forward-only, as the record states):** 3 245 live + 1 804 archived rows still hold decrypted actor memory in plaintext `input_data`. See FAIL list. |
| D3 | Memory overwrite takes the new write's metadata/embedding | PASS, not discriminating | `personal-assistant/inbox_organizer/latest` rewritten 17:25:25Z by `pa-inbox-organizer-work`: `kind=inbox_organizer` (matches its writer's envelope), embedding present (`mxbai-embed-large`). The old and new kind are identical, so this cannot tell the new semantics from the old. The integration tests are the proof. |
| D4 | GraphQL Briefings / dashboard counts | UNVERIFIED (needs operator) | `pg_stat_statements` holds no statement using `pg_input_is_valid` or the key-suffix `LIKE … ESCAPE` since the stats window began: the pages have not been loaded. |
| E1 | Webhook breaker `trigger_id` rendering | PASS (not exercised) | `get_webhook_security_stats`: `blocked_ips: []`, before and after the route crawl. |
| E2 | OAuth `needs_reauth_at` | PASS | 0 of 7 credentials flagged; all refreshed within the last hour. |
| E3 | Security audit | PASS | Grade C, 70/100, 0 fail / 0 warn; the 30 forfeited points are the three dev-posture `info` items (production mode, ephemeral AOT key, plaintext Redis). Write-ceiling controller gate exercised (`round_trip`); audit chain 122/122 job chains verified. Matches the last recorded posture ("grade C at fail:0"). |
| E4 | `make smoke BASE_URL=http://localhost:3002` | FAIL (pre-existing; not #960) | 4 pass / 1 fail / 3 skip. `/mcp → 404`: the dev frontend is the Vite dev server (`Dockerfile.dev`), whose proxy covers only `/graphql`, `/api`, `/auth/oauth`, `/auth/csrf`, `/ws`. The controller's own `/mcp` answers 401. **And the `/health → 200` pass is false**: the body is the SPA's `index.html` (`Content-Type: text/html`), because the check tests status only. See FAIL list. |
| E5 | `make check-route-extensions` (controller `:8000`) | PASS | 99 route/method pairs, 0 unreachable, no missing-extension rejection; 52 stopped at 401. |

## FAILs and findings, most severe first

1. **Plaintext decrypted actor memory at rest (residue of a fixed defect).**
   3 245 live `workflow_executions` rows (2026-08-27 → 2026-09-26 16:10Z) and
   1 804 archived rows carry `__actor_context__` in plaintext `input_data`. That
   is the decrypted memory of `personal-assistant`, which is otherwise stored
   only as ciphertext. The writer is fixed (0/8 since T0). The rows age out under
   the 30+30-day lifetime by about 2026-11-25; database backups keep them longer.
   *Hypothesis/evidence:* the D2 query above. *Option:* a one-shot migration
   `UPDATE … SET input_data = input_data - '__actor_context__'` on both tables. It
   is a data write, so it needs the operator's decision. Checked: neither table
   carries an immutability trigger (only `trg_cancel_siblings_on_workflow_fail`,
   `trg_set_default_actor` and the `updated_at` trigger on the live table), and
   the live residue is 13 MB of `input_data`.
2. **`scripts/smoke.sh` certifies `/health` from the SPA fallback.** The check
   is status-only, so a missing proxy route reads as ✓ — the exact "nginx routes
   it to the SPA" case the script says it catches. On this stack it also reports
   `/mcp` as a failure that is a property of the Vite dev server, not of #960.
   Pre-existing.
3. **Steady-state boot WARN introduced by #960** (`TALOS_MASTER_KEY_PREVIOUS`
   empty). It fires on every compose boot outside a rotation. Cosmetic, but it
   is the only NEW line and it teaches operators to skip WARNs.
4. **False "WIT world over-declared" WARN** (string compare of two spellings of
   one world). 3 per boot. Pre-existing.

Observation, not a platform defect: `pa-inbox-organizer` and
`pa-inbox-organizer-work` both write `personal-assistant/inbox_organizer/latest`
through the same `gmail-organize` module, so each run overwrites the other's
summary and `pa_recall` sees whichever ran last.

## UNVERIFIED — operator actions

| Item | Action |
|---|---|
| C3 refresh rotation, C5 WS hub, D4 Briefings + dashboard counts | Open `http://localhost:3002`, log in, visit the workflow dashboard and the Briefings page, and leave one tab open for 20 min plus a second tab for 5 min. Then I read `rotated_session_audit`, `talos_auth_token_reuse_total{outcome="detected"}` (must stay 0), `talos_ws_active_sessions` (≈ open tabs), `talos_ws_handshakes_total` (must not climb while idle) and `pg_stat_statements` for the count and suffix SQL. In devtools → Network → WS: one socket, no reconnect loop. |
| B3 `content-pipeline` (tier1, local egress) | None. It runs on schedule 2026-09-28 12:00Z; I read its execution then. |
| B3 `personal-finance` (Plaid, tier1 + public) | Run `personal-finance-daily` once when convenient (it reads Plaid sandbox). |
| C2 API-key digest upgrade | None possible: no API keys exist. |

## Verified / Fixed / Open

- **Verified:** A1–A6, B1, B2, B3 (personal-assistant), C1, D1, D2 (forward), E2, E3, E5.
- **Fixed (PR pending):** finding 1 — migration `20260926170000` (package
  `2026-09-26-scrub-persisted-actor-context`), which also covers 22 264
  `node_input` previews in `execution_events` found while measuring it.
- **Open:** findings 2–4 above; UNVERIFIED items C3, C5, D4, B3 (content-pipeline, personal-finance), D3 (discriminating case).

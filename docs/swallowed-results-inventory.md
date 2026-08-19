# Inventory — swallowed `let _ = <expr>.await` (production code)

Produced on `911a457` (= `origin/main`) by `scripts/lint-swallow-inventory.py`;
verdicts in `scripts/swallow-verdicts.py`. Re-derive with:

```sh
python3 scripts/lint-swallow-inventory.py . > /tmp/sites.json
```

**109 non-test sites**, closed and classified: **7 (a)**, **36 (b)**, **66 (c)**.

* **(a) reported-success-on-failure** — a caller is told OK/"done" while the write failed.
* **(b) silent data loss** — the write is the point of the call and nothing reports its failure,
  but no success is claimed either.
* **(c) legitimate fire-and-forget** — the Result genuinely does not matter; the reason is stated
  per site, not asserted collectively.

`test_file` and `#[cfg(test)] mod` regions are excluded. Line numbers are the `let _ =` line.
Multi-line statements are counted: **29** of the 109 fit on one line, **80** do not, so a
single-line grep sees 27% of the population.


## (a) reported-success-on-failure — 7 sites

### `AdvancedRepository::update_scratch_code` — 1 site(s)

* `talos-mcp-handlers/src/advanced.rs:1425`

run_scratch_session persists caller-supplied `code`, then RE-READS the session from the DB (get_scratch_session, l.1441) and compiles THAT. A failed write => the OLD code is compiled, run, and its output returned as the result of the submitted code. The comment 20 lines above (l.1400-1410) documents fixing this exact 'configure-success-but-wrong-value class'.

### `WorkflowRepository::update_workflow_intent_and_capabilities` — 1 site(s)

* `talos-mcp-handlers/src/versions.rs:194`

publish_version writes caller-supplied intent/capabilities, then publishes and returns success. Failure => neither is recorded, response says published. Method returns Result<u64>, so `let _` also discards rows_affected==0.

### `WorkflowRepository::set_workflow_status("active")` — 1 site(s)

* `talos-mcp-handlers/src/versions.rs:251`

After a successful publish the workflow is moved to 'active'. Failure => workflow stays draft while the response reports the published version and a 'deploy_workflow' next-step checklist.

### `WorkflowRepository::mark_execution_{waiting,completed}` — 2 site(s)

* `talos-mcp-handlers/src/workflows.rs:4436`
* `talos-mcp-handlers/src/workflows.rs:4441`

call_workflow: the detached task returns Ok(("completed"|"waiting", output)) UNCONDITIONALLY, and the sync-wait path renders that status to the caller. A failed status write => response says completed while workflow_executions.status is still running; the caller's own get_execution_status disagrees, and the stale-execution sweeper later marks it failed.

### `WorkflowRepository::mark_execution_{waiting,completed}` — 2 site(s)

* `talos-mcp-handlers/src/workflows.rs:6571`
* `talos-mcp-handlers/src/workflows.rs:6576`

handle_test_workflow: identical shape to call_workflow — the spawn's status string is the response's `status`, and `assert_status` is evaluated against it.

## (b) silent data loss — 36 sites

### `CalendarApi::stop_watch` — 2 site(s)

* `talos-google-calendar/src/watch.rs:296`
* `talos-google-calendar/src/watch.rs:404`

Remote watch-channel teardown. Failure => Google keeps pushing to a channel we no longer track (resource leak + stray webhook traffic). No caller is told anything.

### `IdempotencyService::release` — 1 site(s)

* `talos-idempotency/src/lib.rs:631`

Body-too-large path. Its two ADJACENT siblings at l.611 and l.623 both use `if let Err(e) = ... warn!`; this one is the outlier. Failure => the idempotency key stays in-flight and a legitimate retry is blocked until lease expiry.

### `AdvancedRepository::update_scratch_{error,no_wasm,output}` — 6 site(s)

* `talos-mcp-handlers/src/advanced.rs:1501`
* `talos-mcp-handlers/src/advanced.rs:1513`
* `talos-mcp-handlers/src/advanced.rs:1537`
* `talos-mcp-handlers/src/advanced.rs:1545`
* `talos-mcp-handlers/src/advanced.rs:1599`
* `talos-mcp-handlers/src/advanced.rs:1607`

The run outcome IS returned to the caller verbatim, so the response is honest; only the durable session row (readable later via list_scratch_sessions) goes stale.

### `AdvancedRepository::expire_stale_approval_gates` — 1 site(s)

* `talos-mcp-handlers/src/advanced.rs:3396`

Display-only refresh before list_approval_gates. NOT a security gap: the resolve path enforces expiry independently (`talos-webhooks/src/approval.rs:285` and the UPDATE's `AND expires_at > NOW()` at l.438). Failure => a listing over-reports pending gates.

### `AdvancedRepository::activate_workflow` — 1 site(s)

* `talos-mcp-handlers/src/advanced.rs:4141`

promote_workflow. Response reports `published: true` (true) but never claims active, so not (a). Failure => promoted workflow silently not activated. The adjacent schedule create in the SAME function (l.4172) uses `.is_ok()` and only reports schedule_id when it worked — the honest twin.

### `AnalyticsRepository::set_capabilities_if_empty` — 1 site(s)

* `talos-mcp-handlers/src/analytics.rs:144`

RECLASSIFIED from (c). The first pass called it (c) because auto_suggest_capabilities returns () 'so there is nothing to propagate to' — but that is the definition of (b). A lost capability tag does matter: it is what capability search and get_workflows_by_capability read.

### `WorkflowRepository::mark_execution_failed` — 1 site(s)

* `talos-mcp-handlers/src/executions.rs:2764`

Bulk replay loop; the per-input outcome is reported. Same shape as the workflows.rs family.

### `ActorRepository::insert_admin_event_log` — 3 site(s)

* `talos-mcp-handlers/src/ml.rs:1311`
* `talos-mcp-handlers/src/ml.rs:1402`
* `talos-mcp-handlers/src/ml.rs:1559`

AUDIT WRITE — ranked first. Operator-initiated ML policy / lifecycle / shadow-epoch changes are committed, then the admin_event_log row is written and its Result discarded. Every OTHER admin_event_log caller in the workspace logs the failure: actor.rs:2628/2733/2838 use `if let Err(e) = ... warn!`, and spawn_log_admin_event warns inside the task. These 3 are the only silent ones. A gap in the audit trail for a privileged change is invisible by construction.

### `WorkflowRepository::mark_execution_failed` — 12 site(s)

* `talos-mcp-handlers/src/workflows.rs:3082`
* `talos-mcp-handlers/src/workflows.rs:3135`
* `talos-mcp-handlers/src/workflows.rs:4383`
* `talos-mcp-handlers/src/workflows.rs:4449`
* `talos-mcp-handlers/src/workflows.rs:4495`
* `talos-mcp-handlers/src/workflows.rs:5320`
* `talos-mcp-handlers/src/workflows.rs:5369`
* `talos-mcp-handlers/src/workflows.rs:5760`
* `talos-mcp-handlers/src/workflows.rs:5809`
* `talos-mcp-handlers/src/workflows.rs:6516`
* `talos-mcp-handlers/src/workflows.rs:6583`
* `talos-mcp-handlers/src/workflows.rs:6605`

Failure-marking writes on paths that DO return an error to the caller, so the response is honest. Failure => the row never reaches 'failed' and is left to the stale-execution sweeper.

### `WorkflowRepository::mark_execution_{waiting,completed}` — 6 site(s)

* `talos-mcp-handlers/src/workflows.rs:3122`
* `talos-mcp-handlers/src/workflows.rs:3126`
* `talos-mcp-handlers/src/workflows.rs:5356`
* `talos-mcp-handlers/src/workflows.rs:5360`
* `talos-mcp-handlers/src/workflows.rs:5796`
* `talos-mcp-handlers/src/workflows.rs:5800`

test_workflow_draft / bulk_trigger_workflow / trigger_workflow_as_actors. Unlike the (a) twins, these handlers answer `status: running` / `N executions queued — use get_execution_status`, so nothing is over-claimed. Failure => row stuck in a non-terminal status.

### `WorkflowRepository::record_reuse_event` — 1 site(s)

* `talos-mcp-handlers/src/workflows.rs:4319`

Reuse analytics counter. Failure => under-counted get_workflow_reuse_stats.

### `WorkflowRepository::update_workflow_graph` — 1 site(s)

* `talos-mcp-handlers/src/workflows.rs:7465`

auto_fill_config background task. The swallow is followed by an UNCONDITIONAL `debug!("auto_fill_config: patched graph for workflow {}")` — a log that asserts success on failure (misleading-report class). No API response involved, hence (b) not (a).

## (c) legitimate fire-and-forget — 66 sites

### `JoinHandle::await` — 1 site(s)

* `controller/src/bootstrap/services.rs:2384`

Shutdown join.

### `spawn_blocking(bcrypt verify dummy)` — 2 site(s)

* `talos-auth/src/lib.rs:867`
* `talos-auth/src/lib.rs:907`

Deliberate constant-time work against a dummy hash — the RESULT is what must be discarded.

### `tokio::fs::remove_dir_all` — 2 site(s)

* `talos-compilation/src/lib.rs:2354`
* `talos-compilation/src/lib.rs:2472`

Temp-workspace cleanup.

### `read_error_text_capped` — 2 site(s)

* `talos-github/src/client.rs:107`
* `talos-github/src/client.rs:142`

Draining an error body we are about to discard.

### `OAuthCredentialService::refresh_oauth_token_if_needed` — 1 site(s)

* `talos-gmail/src/integration.rs:143`

Pre-emptive refresh; a failure surfaces loudly on the API call that follows.

### `refresh_oauth_token_if_needed` — 2 site(s)

* `talos-google-calendar/src/lib.rs:347`
* `talos-google-cloud/src/integration.rs:290`

Same as gmail.

### `read_json_capped` — 1 site(s)

* `talos-llm/src/lib.rs:891`

Draining a body on an error path.

### `Transaction::rollback` — 1 site(s)

* `talos-mcp-handlers/src/actor.rs:5849`

Rollback on an error path already being reported.

### `redis SETEX` — 2 site(s)

* `talos-node-cache/src/lib.rs:154`
* `talos-node-cache/src/lib.rs:184`

Cache hydration; a miss is free.

### `sqlx INSERT node_result_cache` — 1 site(s)

* `talos-node-cache/src/lib.rs:208`

Cache hydration; already carries `// allow-sqlx-swallow` (check 10's opt-out).

### `sqlx UPDATE integration_credentials` — 1 site(s)

* `talos-oauth/src/credentials.rs:503`

Already carries `// allow-sqlx-swallow`; the chained `.map_err` logs the cause at WARN.

### `async_nats::Client::publish(reply_to, ...)` — 13 site(s)

* `talos-rpc-subscribers/src/lib.rs:779`
* `talos-rpc-subscribers/src/lib.rs:813`
* `talos-rpc-subscribers/src/lib.rs:840`
* `talos-rpc-subscribers/src/lib.rs:865`
* `talos-rpc-subscribers/src/lib.rs:880`
* `talos-rpc-subscribers/src/lib.rs:991`
* `talos-rpc-subscribers/src/lib.rs:1050`
* `talos-rpc-subscribers/src/lib.rs:1329`
* `talos-rpc-subscribers/src/lib.rs:1608`
* `talos-rpc-subscribers/src/lib.rs:1724`
* `talos-rpc-subscribers/src/lib.rs:2018`
* `talos-rpc-subscribers/src/lib.rs:2739`
* `talos-rpc-subscribers/src/lib.rs:2864`

NATS request/reply replies. A failed publish is indistinguishable to us from a vanished requester; the peer's own timeout is the recovery path and there is no second delivery attempt to make. Nothing claims success.

### `broadcast/mpsc send(())` — 1 site(s)

* `talos-shutdown/src/lib.rs:81`

Shutdown signal; Err == no receivers == already shutting down.

### `nats.publish` — 3 site(s)

* `talos-worker-runtime/src/context.rs:1562`
* `talos-worker-runtime/src/host/logging.rs:94`
* `talos-worker-runtime/src/host/logging.rs:218`

Guest-log telemetry.

### `mpsc Sender::send` — 9 site(s)

* `talos-worker-runtime/src/host/llm_streaming.rs:107`
* `talos-worker-runtime/src/host/llm_streaming.rs:118`
* `talos-worker-runtime/src/host/llm_streaming.rs:128`
* `talos-worker-runtime/src/host/llm_streaming.rs:162`
* `talos-worker-runtime/src/host/llm_streaming.rs:184`
* `talos-worker-runtime/src/host/llm_streaming.rs:206`
* `talos-worker-runtime/src/host/llm_streaming.rs:215`
* `talos-worker-runtime/src/host/llm_streaming.rs:241`
* `talos-worker-runtime/src/host/llm_streaming.rs:252`

Streaming chunks to the consumer channel. Err == receiver dropped == client gone; the loop's next iteration exits on the same condition.

### `nats.publish` — 1 site(s)

* `talos-worker-runtime/src/host/messaging.rs:457`

Guest `messaging` WIT publish on the fire-and-forget arm.

### `SecretProvider::release` — 1 site(s)

* `talos-worker-runtime/src/host/secrets.rs:228`

Same as vault.rs — infallible in every impl.

### `SecretProvider::release` — 3 site(s)

* `talos-worker-runtime/src/host/vault.rs:611`
* `talos-worker-runtime/src/host/vault.rs:719`
* `talos-worker-runtime/src/host/vault.rs:768`

PROVABLY INFALLIBLE: every impl returns Ok(()) — talos-secrets/src/talos_vault.rs:284 is a DashMap remove, auditing.rs:63 delegates to it. The Result exists only for future KMS-backed providers. Checked rather than assumed because a failed slot release would leave secret material resident.

### `redis SET EX` — 1 site(s)

* `talos-worker-runtime/src/runtime.rs:2558`

Result cache hydration.

### `nats.publish(wasm.log.<exec>)` — 4 site(s)

* `talos-worker-runtime/src/runtime.rs:3351`
* `talos-worker-runtime/src/runtime.rs:3388`
* `talos-worker-runtime/src/runtime.rs:3455`
* `talos-worker-runtime/src/runtime.rs:3793`

Guest-log fan-out to the diagnostics topic. Best-effort telemetry.

### `Client::flush` — 1 site(s)

* `talos-workflow-engine-nats/src/transport.rs:123`

Documented in place: 'errors here are not fatal — next() will simply time out'.

### `Transaction::commit` — 1 site(s)

* `talos-workflow-repository/src/workflows.rs:1412`

Commit of a READ-ONLY (SELECT EXISTS) tenancy-scoped tx in workflow_exists.

### `WebSocket send/close` — 12 site(s)

* `talos-ws-auth/src/lib.rs:32`
* `talos-ws-auth/src/lib.rs:37`
* `talos-ws-auth/src/lib.rs:43`
* `talos-ws-auth/src/lib.rs:134`
* `talos-ws-auth/src/lib.rs:136`
* `talos-ws-auth/src/lib.rs:147`
* `talos-ws-auth/src/lib.rs:162`
* `talos-ws-auth/src/lib.rs:164`
* `talos-ws-auth/src/lib.rs:191`
* `talos-ws-auth/src/lib.rs:285`
* `talos-ws-auth/src/lib.rs:332`
* `talos-ws-auth/src/lib.rs:349`

Terminal close frames and best-effort error/ack text on a socket that is being torn down. A failed send means the peer is already gone.

## What this PR changed (the list above is the `911a457` BASELINE, unedited)

The list is deliberately the pre-fix state, so a future re-run can be diffed
against it. Changed here:

* all **7 (a)** sites — the caller's RESPONSE now reflects the failure, not
  only a log line;
* the **3 audit writes** (`ml.rs`) and **30 further (b)** sites in
  `talos-mcp-handlers/src/` — converted to `if let Err(e) = … { warn!(…) }`;
* `talos-idempotency/src/lib.rs:631` — brought into line with its two siblings;
* `talos-mcp-handlers/src/actor.rs:5849` — the one genuine fire-and-forget left
  in that crate — given `// allow-swallowed-result: <reason>`.

`talos-mcp-handlers/src/` therefore contains **zero** unmarked
`let _ = <expr>.await`, which is what lets the widened lint check 10 ship as a
hard rule rather than a ratchet.

Not changed: the 66 (c) sites outside that crate, and the 6 (b) sites outside
it (`talos-google-calendar/src/watch.rs:296,404` stop_watch — the only (b)
sites in this inventory left unaddressed, both remote-resource-teardown leaks).

## What this inventory does NOT cover

Adjacent swallow shapes, deliberately out of scope — a floor, not a ceiling:

* `let _ = <expr>;` on a **non-awaited** `Result`.
* `if let Err(_) = …` — matched and discarded.
* `.ok()` on a `Result` that matters (the `Option`-ising swallow).
* `.unwrap_or(…)` / `.unwrap_or_default()` / `.unwrap_or_else(…)` on a read or
  write — the shape recorded in
  `swallowed-error-unwrap-or-masks-broken-query`. One instance was hit in
  passing while reading the (a) sites: `handle_run_scratch_session` resolves the
  session with `.get_scratch_session(...).await.unwrap_or(None)`, so a DB error
  reaches the caller as "Scratch session 'x' not found". Recorded, not fixed.
* `let _ = tokio::spawn(async { … })` where the SPAWNED BODY swallows — the
  scanner sees the outer statement, not the inner one.

---

# Part 2 — error rendered as an ABSENCE (#661)

Produced on `757cf45` (= `origin/main`, i.e. #660's merge) by
`scripts/lint-absence-inventory.py`; verdicts in `scripts/absence-verdicts.py`.
Re-derive with:

```sh
python3 scripts/lint-absence-inventory.py . > /tmp/sites.json
python3 scripts/absence-verdicts.py                    # counts + per-site list
```

**A distinct class from Part 1.** Part 1 (#660) covered *failure rendered as
SUCCESS* — `let _ = <expr>.await`, where a caller is told OK while the write
failed. This part covers *failure rendered as ABSENCE*: a fallible operation
whose `Err` becomes `None` or an empty collection, so the caller takes the
not-found branch and behaves as though the row genuinely does not exist.
Downstream that becomes "no such session", "no memories", "no schedule", "never
ran", "no grant" — each of which some code path treats as a legitimate,
actionable state.

## Population, re-derived (production only; test files and `#[cfg(test)] mod`
## regions excluded)

| anchor | prod sites | of which the expression contains `.await` |
|---|---|---|
| `.unwrap_or(None)` | 53 | 47 |
| `.unwrap_or_else(\|_\| None)` | 0 | 0 |
| `.ok()` (value used) | 675 | 78 |
| `.ok();` (pure discard — Part 1's class, not this one) | 54 | 17 |
| `.unwrap_or(<empty literal>)` | 294 | 3 |

783 of the 1076 anchors are multi-line statements.

**`grep -c 'unwrap_or(None)'` gives 67; the truth is 53.** The 14-site gap is
not multi-line chains (in Part 1 the gap ran the other way): **all 14 are
comments inside code that has ALREADY been fixed for this class** — MCP-535 /
MCP-551 / MCP-552 left explanatory comments behind, e.g.

    // MCP-552: previously `.unwrap_or(None)` silently treated a DB read
    // `.unwrap_or(None)` collapsed both into "owner = None" -> 404. The

Any count that does not strip comments over-reports by ~26%, and over-reports
*precisely in the files that were already fixed*.

## Scope closed, and what "closed" means here

1076 anchors is too many to read a caller for, and most are not this class at
all (`header.to_str().ok()`, `Uuid::parse_str(..).ok()`). The **closed set** is
every anchor whose swallowed expression is a fallible I/O read — the 128
`.await`-bearing anchors — plus the 6 non-I/O `unwrap_or(None)` sites and the
`try_get` schema-drift reads found alongside them. **129 sites, every one read
at the caller, no residual "unclassified" bucket:**

| class | count |
|---|---|
| **(a)** error-as-absence, ACTED ON | **94** |
| **(b)** error-as-absence, INERT (reason stated per site) | **26** |
| **(c)** not this class (an `Option`/parse the grep caught) | **9** |
| total | **129** |

Everything outside that set is stated in "Not covered" below rather than
silently dropped.

## (a) is emphatically NOT just the one instance #660 named

#660 named `get_scratch_session(...).unwrap_or(None)` — a DB error reported as
"scratch session not found". That site is real and is in the list
(`talos-mcp-handlers/src/advanced.rs:1468`), and it is one of **94**.

### Ranked first: the absence causes or skips a WRITE (20 sites)

The plan's own ranking — creating a duplicate, re-running a job, or skipping a
dedupe/uniqueness check because the DB blipped outranks rendering a wrong number.

* `talos-worker-runtime/src/host/graphql.rs:1079` — **the sharpest.** A Redis
  `GET` failure reads as "no counter yet today" on the **tier-2
  `expose_secret` daily cap**, which both allows the call and runs
  `set_ex(key, 1, 86400)` — overwriting the day's accumulated count with 1 and
  restarting the 24 h window. The guard erases its own state. The caller
  (`host/secrets.rs:387`) already routes `Err` to an in-memory fallback,
  preserving MCP-722's "never-configured = the same fail-closed path as an
  outage"; the `.ok()` inside the callee created a **third** path — *GET
  failed* — reaching neither arm.
* `talos-api/src/schema/actors/mutations.rs:278,647`,
  `talos-mcp-handlers/src/actor.rs:1168`, `talos-actor-scaffold/src/lib.rs:827`
  — the capability-grant read. A DB error lands in the same arm as an
  *unrecognised* grant value and yields `http-node` (`world_rank` **1**) for a
  user granted `minimal-node` (rank **0**) — one rank of escalation on the left
  side of the `ceiling_permits` lattice gate, **persisted** into the actor row.
* `controller/src/bootstrap/background.rs:2227` — `archive_after_days`
  unreadable → the env default (30) binds into a CTE that DELETEs from
  `workflow_executions`. On a 365-day deployment that is ~11 months of history
  swept out on the next daily tick.
* `talos-gmail/src/watch.rs:278` — `get_integration` error skips the whole
  `if let Some(integration)` block, so `users.stop()` is never called;
  `google_err` stays `None`, so the audit row records **`success = true`**, and
  `delete_row` still removes the local row. An orphaned Gmail push channel keeps
  delivering, audited as a clean stop.
* `talos-mcp-handlers/src/sandbox.rs:1126` — skipped compile dedupe → a full
  WASM recompile plus a duplicate persisted template row.
* `talos-mcp-handlers/src/workflows.rs:2298` — node config-schema validation
  skipped; the unvalidated node is written into `graph_json`.
* `talos-mcp-handlers/src/workflows.rs:10390,10397` — `plan_and_execute`
  publishes an **empty** passthrough subtask workflow (`{"nodes":[]}`) and runs
  it as a silent no-op.
* `talos-actor-lifecycle-service/src/handoff.rs:539` — the handed-off execution
  row is created with a **NULL version**, so it runs against the live draft
  graph and loses its replay pin.
* `talos-atlassian/src/integration.rs:326` — the credential UPSERT writes
  `account_id = NULL` and `EXCLUDED.account_id` **overwrites a previously-good
  value**.
* `talos-oauth/src/credentials.rs:843` — persists `scope = ""`, wiping the
  recorded grant scope kept for 401/403 scope-drift auditing.
* `talos-mcp-handlers/src/lib.rs:484,492` — `find_first_user_id` error → "no
  users" → `ensure_dev_user()` creates a synthetic dev user; and if *that*
  errors, `agent.user_id = None` for the whole session, which the code's own
  comment says makes every write land NULL while tools report success.
  (`/mcp/local` dev endpoint only.)
* `controller/src/bootstrap/router.rs:2158` — the Google Calendar integration
  is never created, with **no `else` and no log**, while the OAuth callback
  completes and logs a successful login.

### Then: authorisation and existence checks, with the direction stated

**Fails OPEN** (the dangerous direction) — 7:
`totp-2fa:140` (2FA lockout gate skipped on an HGET error; backstopped by the
HINCRBY pre-charge, so narrow), the four capability-grant sites above,
`analytics.rs:4626` (the high-severity `repeated_auth_failures` finding is
silently omitted from the risk assessment), `analytics-repository:1955` (the
background SLA loop's `_ => continue` **skips SLA-violation alerting**,
indistinguishable from "fewer than 3 executions"), `analytics-repository:4329`
(the hygiene report claims no module holds a `*` secret grant),
`oauth/credentials.rs:550` (the provider-side revoke is skipped while the local
rows are deleted, leaving a live OAuth grant the platform has forgotten),
`actor.rs:2885` and `modules.rs:2492` (an actor is reported as having no budget
policy; a module as unthrottled).

**Fails CLOSED** — 21. Safe direction, and the defect is
[[misleading-report-field-class]]: the response asserts a conclusion the code
never reached. `executions.rs:5601` (approval ownership), `sandbox.rs:1813,3102`
and `workflows.rs:2806` (actor ownership), `handoff.rs:312,336,436`,
`platform.rs:1710`, `modules.rs:976,1139`, `graph.rs:4215`,
`analytics.rs:1170,1913,2066,2230`, `versions.rs:731`, `webhooks.rs:613`,
`schedules.rs:569`, `advanced.rs:1468`, `system-repo:218`, `actor.rs:6404`, and
`google-calendar/admin.rs:250,288` (403 *"no audit record of this channel being
created for this user"* / 404 *"no active gcal integration for this user"*).

Note `schedules.rs:569`'s **honest twin in the same handler**: the stats read
below it stamps a `data_warning` instead of collapsing to a 404.

### Schema-drift reads that structural check 52 could not see

Check 52 (`silent try_get().unwrap_or`) was burned 526 → 0 and **graduated to a
hard rule**. Its regex needs `.try_get(...)` and `.unwrap_or` on one line; the
script's own comment admitted a split-across-lines read "still slips past ...
rare and caught in review". Measured: check 52's grep reports **0**, and there
were **5**.

| site | column | error/NULL read as | why it matters |
|---|---|---|---|
| `talos-workflow-repository/src/workflows.rs:1881` | `timezone` | `"UTC"` | the workflow-schedule EXPORT row — a 09:00 America/Toronto cron round-trips as 09:00 UTC |
| `talos-execution-repository/src/lib.rs:528` | `created_at` | `Utc::now()` | an unreadable timestamp reads as "created this instant"; age-based readers never reach the row |
| `talos-secrets-manager/src/manager.rs:3524` | `namespace` | `"default"` | namespace is half the identity this lookup exists to resolve |
| `talos-actor-repository/src/lib.rs:3742` | `description` | `None` | display only; listed because it is the odd one out in a struct whose other three fields propagate |
| `talos-workflow-repository/src/templates.rs:549` | `source_code` | `None` | the module EXPORT manifest says "this module has no source", which a re-import faithfully reproduces |

`talos-registry/src/lib.rs:892` was a **false positive of my first detector** —
a `.context(...)?` sits between the two lines, which is the *fixed* form. It is
struck from the list and is what the shipped check correctly does not flag.

**The bigger hole in the same check is `.ok()`, and it is NOT closed.**
`.try_get(...).ok()` has identical semantics — drift reads as `None`, never as
an error — and neither check-52 leg mentions `.ok` at all, so it is invisible on
one line or many. Measured: **84** workspace-wide, including
`talos-memory/src/lib.rs:431-433, 1076-1077, 1959-1960, 2233-2234` — `value`,
`value_enc`, `value_key_id`, the **encryption-envelope columns** on the table
whose sibling `value_format` read check 34 exists specifically to make fail
loud. That is a burn-down cycle, not a lint change: gating it today means
re-adding a baseline, which check 52's own rule forbids.

## (b) — inert, 26 sites, each with its reason

* **The node-label decoration group (12)** — `executions.rs:1137, 1593, 1830,
  1980, 3067, 3288, 3431, 4159, 4293, 4717`, `analytics.rs:2530`,
  `failure-analysis-service/lib.rs:579`. All are
  `get_workflow_graph*(..).await.ok().flatten()` feeding `build_node_label_map`,
  whose only consumer is `map.get(uuid).unwrap_or(uuid.to_string())`. An empty
  map renders raw UUIDs — the honest "label unknown", identical to what a
  genuinely graph-less workflow renders — and never removes a row, adds a row,
  or changes a count. The substantive payload comes from separately-checked
  queries that `return mcp_error` on their own `Err`.
* `executions.rs:5893` — the empty-map fallback re-derives the UUID with the
  same `SHA256(rf_id)[..16]` used to build the map. Byte-identical result.
* `node-cache/lib.rs:145`, `workflow-repository/search.rs:25,82` — cache reads.
  A read error and a genuine miss both mean "recompute", and the recompute is
  the correct answer either way.
* `actor.rs:1907,2179` — the terminal-state guard falls through, but the
  `suspend_actor` / `update_actor_status` SQL re-gates terminal states and its
  `Ok(0)` arm emits the same operator-facing error (MCP-645/646).
* `actor.rs:2598,2811`, `search.rs:629`, `api/platform/queries.rs:103`,
  `google-calendar/handlers.rs:186` — a decoration on an answer that stands
  without it; nothing branches on the field and a genuine NULL renders the same.
* `registry/sync.rs:122` — `which cosign` → falls back to a PATH walk;
  verification still runs, only the PATH-pinning defence-in-depth is lost, and
  the doc comment says a resolution failure deliberately does not cache a
  sentinel so the next call retries.
* **`talos-scheduler/src/lib.rs:2083` — the model shape, kept for contrast.**
  The fence-epoch read is `.ok().flatten()` and is *immediately* followed by
  `if fence_epoch.is_none() { warn!("… running unfenced") }`, with a comment
  saying why unfenced is acceptable. The absence is observable and the
  degradation is named. That is what a correct fallback looks like.
* `secrets-manager/manager.rs:3495` — see the correction below.

## A correction the inventory forced, recorded per [[inventory-before-naming-the-fix]]

I ranked `SecretsManager::find_name_collision` the top (a) on sight. Its doc
says *"Best-effort — DB errors return `None` so a transient hiccup doesn't break
the upsert"*, four lines under a doc describing the harm it prevents (*"later
calls `delete_secret(name="foo")` and watches the wrong secret disappear"*): a
read whose absence causes a write, self-documented.

It has **zero callers** — one occurrence workspace-wide, its own definition. The
warning is never emitted for any reason. Inert for this class, and a
signal-nobody-consumes item instead. Sample of one, wrong generalisation, caught
only by closing the caller set.

## Not covered — the floor, not the ceiling

* **`unwrap_or_default()` as a class — 1127 sites, deliberately excluded.** It
  is dominated by legitimate config and `Option` handling and sweeping it would
  bury the signal. Individual `unwrap_or_default()` sites reached through an
  adjacent finding ARE included (`analytics-repository:4329`,
  `oauth/credentials.rs:843`), so the exclusion is of the *sweep*, not of the
  shape.
* **`.try_get(...).ok()` — 84 sites**, measured and reported above, not fixed
  and not gated.
* **`.ok()` on non-I/O expressions — ~597 sites.** A malformed input genuinely
  is an absence of a valid value; that is a different (and usually correct)
  judgement from a DB blip.
* **`Err(_) => return Ok(())` and `Err(_) => None` match arms** are the same
  class in a spelling no anchor here catches. One was found incidentally while
  verifying another site: `talos-gmail/src/watch.rs:269` — `find_by_id` error →
  `return Ok(())`, documented as "Idempotent: missing rows succeed silently".
  Not enumerated; the population is unknown.
* `unwrap_or_else`, `map_or`, and `?` on a call whose error type erases the
  distinction — not enumerated.


# Part 3 — `.try_get(...).ok()`: check 52's forbidden shape in a spelling it cannot see (#662)

Produced on `248d690` (= `origin/main`) by `scripts/lint-tryget-ok-inventory.py`;
verdicts in `scripts/tryget-ok-verdicts.py`. Re-derive and cross-check with:

```sh
python3 scripts/lint-tryget-ok-inventory.py . > /tmp/sites.json
python3 scripts/tryget-ok-verdicts.py --check /tmp/sites.json
```

`row.try_get("col").ok()` is **identical in effect** to the
`row.try_get("col").unwrap_or(default)` that structural check 52 forbids
workspace-wide: a renamed / dropped / retyped column produces `Err`, `.ok()`
turns it into `None`, and the caller cannot tell that from a legitimate SQL
NULL. Check 52's regex names `.unwrap_or` and nothing else, and 52b's perl pass
names it too, so this spelling is invisible to both on one line or many. #661
measured it at 84 and deliberately did **not** gate it, because check 52's own
header says *"Do NOT re-add a baseline."* This part is the burn-down; the check
follows at zero.

**90 sites**, closed and classified: **49 (a)**, **41 (b)**, **0 (c)**.

* **(a) drift-hiding that changes behaviour or defeats a check** — encryption,
  tenancy, security-report and assertion columns, plus the three sites where the
  `.ok()` is masking something other than NULL.
* **(b) genuinely NULLable** — `None` is a real value; the correct form is
  `.try_get::<Option<_>, _>("col")?`, which still errors on drift while allowing
  NULL. Mechanical, and the whole risk is silently changing NULL handling.
* **(c) not a DB column read** — none. Every site in this population is a real
  `sqlx::Row` read.

Nullability was resolved against `information_schema.columns` on the live
`talos` database, which is **fully migrated** (308 `_sqlx_migrations` rows == 308
files in `migrations/`), not against the surrounding code's assumptions. Three
sites read a column the code assumed was there and it is not; two read a NOT
NULL column the code treats as optional.

## Reconciling the count — 84 vs 85 vs 90

| view | count |
|---|---|
| `scripts/lint-tryget-ok-inventory.py` (balanced parens + balanced angle brackets) | **90** |
| check-52-shaped line grep `\.try_get(::<[^(]*>)?\([^)]*\)\.ok\(\)` | 84 |
| #661's stated figure | 84 |
| a line sweep for `try_get` co-occurring with `.ok()` | 85 |

Both directions are closed, and the first attempt at each was wrong in a way
worth recording, since it is this class one level up.

* **The line grep misses 7 sites, and it is not the nested generics.** All 7 are
  the house style breaking the chain *after* the argument list:
  `.try_get::<Option<String>, _>("status")` then `.ok()` on the next line. A
  line-based regex cannot see them — the same multi-line hole #661 measured for
  check 52 and closed with 52b, still open in this spelling.
  (`talos-actor-repository` 3486, 3491; `talos-advanced-repository` 2667, 2672;
  `talos-memory` 1601; `talos-module-repository` 609;
  `talos-workflow-repository/src/search.rs` 752.)
* **The grep also falsely counts 1**: prose inside a `#661` comment in
  `talos-secrets-manager/src/manager.rs:3528`. 84 − 1 + 7 = 90.
* **The first version of the script above missed 8 of the 90** — every
  `::<Option<i64>, _>` turbofish, because a non-nesting `[^>]*>` stops at the
  inner `>`. Seven of those eight were also the multi-line ones, so a first
  reconciliation attributed the grep's gap to nested generics. It is not: the
  two blind spots are independent, and
  `talos-advanced-repository/src/lib.rs:2745` is the single-line nested-generic
  site that the grep sees and the broken script did not.

**7 of the 90 span two lines.** The `multiline` field in the first run of the
inventory reported 0, because it compared the line of the try_get's *closing
paren* rather than the line of the `.ok` token — and every one of these breaks
after `("col")`, not inside it. The number the check must be built against is 7,
not 0; a single-line leg alone would ship at "zero" while leaving them in place.
All 90 name their column with a string literal.

**Nothing is in a `tests/` directory or a `#[cfg(test)] mod`.** Nine sites are in
`controller/examples/` — operator backfill and verification binaries, excluded
from the "production crate" count of 81 but **in scope for the check**, whose
grep excludes only `target/`, `.git/`, `.claude/` and `node_modules/`.

## (a) — 49 sites

### `talos-memory`: `value_enc` / `value_key_id` — 8 sites

`talos-memory/src/lib.rs` 432, 433 (`decrypt_row_value`), 1076, 1077
(`recall_exact`), 1959, 1960 (`recall_semantic_filtered`), 2233, 2234
(`rows_to_memory_hits`).

Both columns are **NOT NULL** in the live schema, so a `None` can only mean
SELECT-projection drift or a decode change. `resolve_stored_value` (l.383) falls
through `if let (Some(enc), Some(key_id)) = …` to
`Ok(value_plain.unwrap_or(Value::Null))` — and `value_plain` is **always** `None`
because Phase B dropped the `value` column. So the drift resolves to **an empty
memory, returned as success, with no decrypt attempted and no error**. Not a
wrong-format branch — a silent empty read (the `encrypted_output_select_blindness`
class, MCP-680).

The sharp part: in each of those four functions the *next* line reads
`value_format` with `.context(...)?` under a five-to-eight-line comment
explaining that a silent default there would mask SELECT-projection drift. The
identical argument applies to the two lines above it and was not applied.
`clone_memories` l.3176-3177 already does it right —
`let value_enc: Vec<u8> = r.try_get("value_enc")?;`.

**Honest severity: latent, not live.** Every in-repo SELECT feeding those four
functions projects both columns today.

### `talos-memory:431` — a read of a DROPPED column whose `.ok()` is load-bearing

`try_get("value")` returns `Err(ColumnNotFound)` on **every** call, and `.ok()`
is what lets every memory decrypt proceed; the doc comment at l.411-413 says so
in as many words. Converting this one site to `?` would break the entire memory
read path. It is the one site in the population where the mechanical conversion
is actively wrong, and it is in the highest-ranked file. Fixed by **deleting**
the read: `resolve_stored_value` is already called with a literal `None` at all
five other call sites.

### `controller/examples/verify_module_payload_encryption.rs` 93-97 — 5 sites

Every one feeds an `assert!`, including
`assert!(pt_input.is_none(), "PLAINTEXT LEAK: input_data is non-NULL")`. A
drifted or renamed column reads as `None`, so **the plaintext-leak assertion
passes vacuously** — a gate that cannot fail on the condition it checks (#624's
class), inside the tool that certifies payload encryption.

### `controller/examples/backfill_module_payload_encryption.rs` 85-87 — 3 sites

The three plaintext columns are read with `.ok()`, encrypted, and then the row is
`UPDATE`d with `input_data = NULL, output_data = NULL, trigger_metadata = NULL`
alongside the ciphertext. A silent `None` writes empty ciphertext **and** nulls
the plaintext — irreversible loss. A one-shot operator migration, but the
shape — swallowed read feeding a destructive update — is the sharpest in the set.

### `talos-module-executions` — 19 sites

`364, 365, 367, 368, 369` (`re_encrypt_module_payloads_to_org`), `988-994`
(`get_execution`), `1101-1107` (`list_module_executions`). The `*_enc`,
`payload_enc_key_id` and `workflow_execution_id` columns are all genuinely
NULLable, so the `Option` is right and the fix is purely `.ok().flatten()` → `?`.
Ranked (a) because they are the payload-encryption path and because the same
functions harden `payload_format` with an explicit match-and-fail arm three lines
below — the identical asymmetry to `talos-memory`.

### `talos-analytics-repository:2096` — `workflow_schedules.timezone`

**NOT NULL.** #661 fixed this exact column at
`talos-workflow-repository/src/workflows.rs:1881`, where a silent default ran
every exported cron in UTC. Here the `None` surfaces at
`talos-mcp-handlers/src/analytics.rs:4776` as
`r.timezone.as_deref().unwrap_or("UTC")` — a schedule in `America/Vancouver`
would be *reported* as UTC. Display path, not the executor, so it misinforms
rather than misfires: #661's defect, one spelling over, and its fix could not see
it.

### `talos-analytics-repository:4332` — the wildcard-secret hygiene check

`filter_map(|r| r.try_get::<String, _>("name").ok())` over
`SELECT DISTINCT name FROM modules WHERE '*' = ANY(allowed_secrets)`. Drift drops
rows silently, so the platform-hygiene report says "no wildcard modules" for a
reason unrelated to there being none.

### `talos-totp-2fa:854` — `users.backup_codes`

Nullable, so the `Option` is right. Drift ⇒ `None` ⇒ rollback +
`record_2fa_failure` + `Ok(false)`: **fail-closed**, so not an auth bypass, but
every backup code is rejected and the operator sees a wrong-code error rather
than a schema error.

### Silent row-SKIPs — 8 sites

`talos-module-repository` 458, 1445, 1448, 3318, 3319;
`talos-workflow-repository/src/templates.rs:169`;
`talos-registry/src/reconcile.rs:391`;
`controller/examples/verify_restore.rs:446`.

`filter_map(|r| r.try_get(…).ok())` and
`let Some(id) = r.try_get::<Uuid, _>("id").ok() else { continue };`. The columns
are NOT NULL projections, so the only reachable skip **is** drift, and the batch
silently shortens. The in-place comment at l.1443-1444 says *"skip a malformed
row rather than abort the batch (preserves the prior filter_map behaviour)"* —
i.e. **this shape was introduced by the check-52 burn-down itself**: the swallow
moved into the spelling the check cannot see. `reconcile.rs:391` and
`verify_restore.rs:446` matter most: an under-reported stale-module warning, and
an org whose secrets the restore verifier never checked.

### `talos-workflow-repository/src/workflows.rs` 151, 152 — the `.ok()` masks a missing projection

`list_workflows`' two SELECT branches (l.104, l.122) **do not project
`w.status` or `w.workflow_type` at all**, so both reads return `None` on every
call. Its sibling `list_workflows_paginated` (l.170) does project them. Fixed by
adding the two columns to both branches, then `?`. **Latent**:
`WorkflowRepository::list_workflows` has zero callers workspace-wide — the MCP
handler uses the paginated twin.

## (b) — 41 sites

Genuinely NULLable (or NOT NULL feeding an `Option`-typed field), converted to
`.try_get::<Option<_>, _>("col")?` with the existing default kept verbatim:

| file | lines | columns |
|---|---|---|
| `talos-actor-repository/src/lib.rs` | 3484, 3486, 3491, 3495, 3667 | `actors.description`, `status`, `max_capability_world`, `updated_at`, computed `score` |
| `talos-advanced-repository/src/lib.rs` | 1476, 2667, 2672, 2743, 2744, 2745 | `next_trigger_at`, `status`, `max_capability_world`, `started_at`, `completed_at`, computed `duration_ms` |
| `talos-analytics-repository/src/lib.rs` | 2097, 2098 | `last_triggered_at`, `next_trigger_at` |
| `talos-execution-repository/src/lib.rs` | 2965, 2967, 2968, 2969 | LEFT JOIN `workflow_name`, `started_at`, `completed_at`, `error_message` |
| `talos-memory/src/lib.rs` | 1601, 3180 | `actor_memory.metadata` |
| `talos-module-repository/src/lib.rs` | 283, 284, 609, 626, 785, 787, 936 | computed `score`/`same_category`, `config`, `max_fuel`, `capability_world`, `usage_count`, `template_id` |
| `talos-webhook-repository/src/lib.rs` | 467 | LEFT JOIN `trigger_name` |
| `talos-webhooks/src/dlq.rs` | 214, 223, 224 | LEFT JOIN `workflow_id`, `user_id`, `org_id` |
| `talos-workflow-repository/src/search.rs` | 752 | computed `match_score` |
| `talos-workflow-repository/src/workflows.rs` | 144, 146, 147, 148, 254, 256, 257, 258, 261, 262 | `description`, `tags`, LATERAL `last_status`/`last_exec_at`, `status`, `workflow_type` |

`dlq.rs` is the one (b) that cannot use `?`: the enclosing `flush_batch` returns
`()`. Converted to an explicit `match` that logs the drift at `error!` and keeps
the fire-and-forget event flowing — loud, not silent.

## Not covered by the new check leg — the floor, not the ceiling

Stated so the next cycle does not have to re-measure it, and because overstating
a lint is the defect one level up.

* **`.ok()` on a `try_get` reached through a variable** — `let r =
  row.try_get(…); … r.ok()` is invisible to any chain-shaped matcher, including
  the new leg. **0 sites today** (no `let … = <recv>.try_get` binding a `Result`
  exists workspace-wide), so this is the next spelling, not a current gap.
* **`.map_or` on a `try_get`** — **0 sites**, single-line and multi-line. NOT
  matched by check 52's regex either, so it is the cheapest escape available and
  is deliberately left ungated rather than gated on an empty population.
* **`.unwrap_or_else` / `.unwrap_or_default` on a `try_get`** — 0 in the
  swallowing form; 85 sites exist in the fixed `?.unwrap_or_default(…)` form.
  Already covered by check 52 regardless: its `\.unwrap_or` has no trailing word
  boundary, so it matches both as a prefix.
* **`if let Ok(v) = row.try_get(…)` and `match row.try_get(…) { Err(_) => … }`** —
  the same swallow as a control-flow shape, and NOT covered. **14 sites**
  (`talos-mcp-handlers/src/advanced.rs` ×7, `talos-module-executions` ×2,
  `talos-execution-repository` ×2, `talos-registry/src/lib.rs`,
  `talos-workflow-repository/src/templates.rs`,
  `controller/examples/verify_restore.rs`). Not classified here, because the
  correct verdict is per-site and several are the shape used *correctly*:
  `advanced.rs` probes an unknown column's type by trying each one in turn, and
  `talos-module-executions`' `payload_format` arms deliberately fail loud only
  when ciphertext is present. A blanket gate would be wrong; an inventory is the
  next cycle's work.
* **`?` on a `try_get` whose error type erases which column failed** — every
  fixed site propagates `sqlx::Error::ColumnNotFound`, which names the column, so
  this is not a live loss here; it would be if a caller mapped it into a bare
  `anyhow!("db error")`.

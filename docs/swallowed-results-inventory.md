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

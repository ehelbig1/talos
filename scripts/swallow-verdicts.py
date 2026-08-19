# (file, line) -> (bucket, callee, evidence)
# bucket: a = reported-success-on-failure, b = silent data loss, c = legitimate fire-and-forget
V = {}
def add(f, lines, bucket, callee, ev):
    for l in lines:
        V[(f, l)] = (bucket, callee, ev)

# ── (a) reported-success-on-failure ────────────────────────────────────────
add("talos-mcp-handlers/src/advanced.rs", [1425], "a", "AdvancedRepository::update_scratch_code",
    "run_scratch_session persists caller-supplied `code`, then RE-READS the session from the DB "
    "(get_scratch_session, l.1441) and compiles THAT. A failed write => the OLD code is compiled, "
    "run, and its output returned as the result of the submitted code. The comment 20 lines above "
    "(l.1400-1410) documents fixing this exact 'configure-success-but-wrong-value class'.")
add("talos-mcp-handlers/src/versions.rs", [194], "a", "WorkflowRepository::update_workflow_intent_and_capabilities",
    "publish_version writes caller-supplied intent/capabilities, then publishes and returns success. "
    "Failure => neither is recorded, response says published. Method returns Result<u64>, so `let _` "
    "also discards rows_affected==0.")
add("talos-mcp-handlers/src/versions.rs", [251], "a", "WorkflowRepository::set_workflow_status(\"active\")",
    "After a successful publish the workflow is moved to 'active'. Failure => workflow stays draft "
    "while the response reports the published version and a 'deploy_workflow' next-step checklist.")
add("talos-mcp-handlers/src/workflows.rs", [4436, 4441], "a", "WorkflowRepository::mark_execution_{waiting,completed}",
    "call_workflow: the detached task returns Ok((\"completed\"|\"waiting\", output)) UNCONDITIONALLY, "
    "and the sync-wait path renders that status to the caller. A failed status write => response says "
    "completed while workflow_executions.status is still running; the caller's own get_execution_status "
    "disagrees, and the stale-execution sweeper later marks it failed.")
add("talos-mcp-handlers/src/workflows.rs", [6571, 6576], "a", "WorkflowRepository::mark_execution_{waiting,completed}",
    "handle_test_workflow: identical shape to call_workflow — the spawn's status string is the "
    "response's `status`, and `assert_status` is evaluated against it.")

# ── (b) silent data loss, no success claimed ───────────────────────────────
add("talos-mcp-handlers/src/ml.rs", [1311, 1402, 1559], "b", "ActorRepository::insert_admin_event_log",
    "AUDIT WRITE — ranked first. Operator-initiated ML policy / lifecycle / shadow-epoch changes are "
    "committed, then the admin_event_log row is written and its Result discarded. Every OTHER "
    "admin_event_log caller in the workspace logs the failure: actor.rs:2628/2733/2838 use "
    "`if let Err(e) = ... warn!`, and spawn_log_admin_event warns inside the task. These 3 are the "
    "only silent ones. A gap in the audit trail for a privileged change is invisible by construction.")
add("talos-mcp-handlers/src/workflows.rs", [7465], "b", "WorkflowRepository::update_workflow_graph",
    "auto_fill_config background task. The swallow is followed by an UNCONDITIONAL "
    "`debug!(\"auto_fill_config: patched graph for workflow {}\")` — a log that asserts success on "
    "failure (misleading-report class). No API response involved, hence (b) not (a).")
add("talos-mcp-handlers/src/advanced.rs", [4141], "b", "AdvancedRepository::activate_workflow",
    "promote_workflow. Response reports `published: true` (true) but never claims active, so not (a). "
    "Failure => promoted workflow silently not activated. The adjacent schedule create in the SAME "
    "function (l.4172) uses `.is_ok()` and only reports schedule_id when it worked — the honest twin.")
add("talos-mcp-handlers/src/workflows.rs", [3122, 3126, 5356, 5360, 5796, 5800], "b",
    "WorkflowRepository::mark_execution_{waiting,completed}",
    "test_workflow_draft / bulk_trigger_workflow / trigger_workflow_as_actors. Unlike the (a) twins, "
    "these handlers answer `status: running` / `N executions queued — use get_execution_status`, so "
    "nothing is over-claimed. Failure => row stuck in a non-terminal status.")
add("talos-mcp-handlers/src/workflows.rs", [3082, 3135, 4383, 4449, 4495, 5320, 5369, 5760, 5809, 6516, 6583, 6605], "b",
    "WorkflowRepository::mark_execution_failed",
    "Failure-marking writes on paths that DO return an error to the caller, so the response is honest. "
    "Failure => the row never reaches 'failed' and is left to the stale-execution sweeper.")
add("talos-mcp-handlers/src/executions.rs", [2764], "b", "WorkflowRepository::mark_execution_failed",
    "Bulk replay loop; the per-input outcome is reported. Same shape as the workflows.rs family.")
add("talos-mcp-handlers/src/advanced.rs", [1501, 1513, 1537, 1545, 1599, 1607], "b",
    "AdvancedRepository::update_scratch_{error,no_wasm,output}",
    "The run outcome IS returned to the caller verbatim, so the response is honest; only the durable "
    "session row (readable later via list_scratch_sessions) goes stale.")
add("talos-idempotency/src/lib.rs", [631], "b", "IdempotencyService::release",
    "Body-too-large path. Its two ADJACENT siblings at l.611 and l.623 both use "
    "`if let Err(e) = ... warn!`; this one is the outlier. Failure => the idempotency key stays "
    "in-flight and a legitimate retry is blocked until lease expiry.")
add("talos-google-calendar/src/watch.rs", [296, 404], "b", "CalendarApi::stop_watch",
    "Remote watch-channel teardown. Failure => Google keeps pushing to a channel we no longer track "
    "(resource leak + stray webhook traffic). No caller is told anything.")
add("talos-mcp-handlers/src/advanced.rs", [3396], "b", "AdvancedRepository::expire_stale_approval_gates",
    "Display-only refresh before list_approval_gates. NOT a security gap: the resolve path enforces "
    "expiry independently (`talos-webhooks/src/approval.rs:285` and the UPDATE's "
    "`AND expires_at > NOW()` at l.438). Failure => a listing over-reports pending gates.")
add("talos-mcp-handlers/src/workflows.rs", [4319], "b", "WorkflowRepository::record_reuse_event",
    "Reuse analytics counter. Failure => under-counted get_workflow_reuse_stats.")

# ── (c) legitimate fire-and-forget ─────────────────────────────────────────
add("talos-rpc-subscribers/src/lib.rs",
    [779, 813, 840, 865, 880, 991, 1050, 1329, 1608, 1724, 2018, 2739, 2864], "c",
    "async_nats::Client::publish(reply_to, ...)",
    "NATS request/reply replies. A failed publish is indistinguishable to us from a vanished "
    "requester; the peer's own timeout is the recovery path and there is no second delivery attempt "
    "to make. Nothing claims success.")
add("talos-ws-auth/src/lib.rs", [32, 37, 43, 134, 136, 147, 162, 164, 191, 285, 332, 349], "c",
    "WebSocket send/close",
    "Terminal close frames and best-effort error/ack text on a socket that is being torn down. A "
    "failed send means the peer is already gone.")
add("talos-worker-runtime/src/host/llm_streaming.rs", [107, 118, 128, 162, 184, 206, 215, 241, 252], "c",
    "mpsc Sender::send",
    "Streaming chunks to the consumer channel. Err == receiver dropped == client gone; the loop's "
    "next iteration exits on the same condition.")
add("talos-worker-runtime/src/runtime.rs", [3351, 3388, 3455, 3793], "c", "nats.publish(wasm.log.<exec>)",
    "Guest-log fan-out to the diagnostics topic. Best-effort telemetry.")
add("talos-worker-runtime/src/host/logging.rs", [94, 218], "c", "nats.publish", "Guest-log telemetry.")
add("talos-worker-runtime/src/context.rs", [1562], "c", "nats.publish", "Guest-log telemetry.")
add("talos-worker-runtime/src/host/messaging.rs", [457], "c", "nats.publish",
    "Guest `messaging` WIT publish on the fire-and-forget arm.")
add("talos-worker-runtime/src/host/vault.rs", [611, 719, 768], "c", "SecretProvider::release",
    "PROVABLY INFALLIBLE: every impl returns Ok(()) — talos-secrets/src/talos_vault.rs:284 is a "
    "DashMap remove, auditing.rs:63 delegates to it. The Result exists only for future KMS-backed "
    "providers. Checked rather than assumed because a failed slot release would leave secret "
    "material resident.")
add("talos-worker-runtime/src/host/secrets.rs", [228], "c", "SecretProvider::release", "Same as vault.rs — infallible in every impl.")
add("talos-node-cache/src/lib.rs", [154, 184], "c", "redis SETEX", "Cache hydration; a miss is free.")
add("talos-node-cache/src/lib.rs", [208], "c", "sqlx INSERT node_result_cache",
    "Cache hydration; already carries `// allow-sqlx-swallow` (check 10's opt-out).")
add("talos-oauth/src/credentials.rs", [503], "c", "sqlx UPDATE integration_credentials",
    "Already carries `// allow-sqlx-swallow`; the chained `.map_err` logs the cause at WARN.")
add("talos-worker-runtime/src/runtime.rs", [2558], "c", "redis SET EX", "Result cache hydration.")
add("talos-compilation/src/lib.rs", [2354, 2472], "c", "tokio::fs::remove_dir_all", "Temp-workspace cleanup.")
add("talos-github/src/client.rs", [107, 142], "c", "read_error_text_capped", "Draining an error body we are about to discard.")
add("talos-llm/src/lib.rs", [891], "c", "read_json_capped", "Draining a body on an error path.")
add("talos-auth/src/lib.rs", [867, 907], "c", "spawn_blocking(bcrypt verify dummy)",
    "Deliberate constant-time work against a dummy hash — the RESULT is what must be discarded.")
add("controller/src/bootstrap/services.rs", [2384], "c", "JoinHandle::await", "Shutdown join.")
add("talos-shutdown/src/lib.rs", [81], "c", "broadcast/mpsc send(())",
    "Shutdown signal; Err == no receivers == already shutting down.")
add("talos-workflow-engine-nats/src/transport.rs", [123], "c", "Client::flush",
    "Documented in place: 'errors here are not fatal — next() will simply time out'.")
add("talos-workflow-repository/src/workflows.rs", [1412], "c", "Transaction::commit",
    "Commit of a READ-ONLY (SELECT EXISTS) tenancy-scoped tx in workflow_exists.")
add("talos-mcp-handlers/src/actor.rs", [5849], "c", "Transaction::rollback", "Rollback on an error path already being reported.")
add("talos-gmail/src/integration.rs", [143], "c", "OAuthCredentialService::refresh_oauth_token_if_needed",
    "Pre-emptive refresh; a failure surfaces loudly on the API call that follows.")
add("talos-google-calendar/src/lib.rs", [347], "c", "refresh_oauth_token_if_needed", "Same as gmail.")
add("talos-google-cloud/src/integration.rs", [290], "c", "refresh_oauth_token_if_needed", "Same as gmail.")
add("talos-mcp-handlers/src/analytics.rs", [144], "b", "AnalyticsRepository::set_capabilities_if_empty",
    "RECLASSIFIED from (c). The first pass called it (c) because auto_suggest_capabilities returns () "
    "'so there is nothing to propagate to' — but that is the definition of (b). A lost capability tag "
    "does matter: it is what capability search and get_workflows_by_capability read.")

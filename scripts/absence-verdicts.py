#!/usr/bin/env python3
"""Per-site verdicts for the error-as-absence inventory (#661).

Sibling of `scripts/swallow-verdicts.py` (#660). The enumeration lives in
`scripts/lint-absence-inventory.py`; this file holds the CLASSIFICATION, which a
grep cannot produce because the verdict depends on what the CALLER does with the
`None`.

Line numbers are on `757cf45` (= `origin/main` at the time of the sweep). Some
have since drifted by the fixes in this same commit; re-derive with the scanner
rather than trusting them verbatim.

    python3 scripts/lint-absence-inventory.py . > /tmp/sites.json
    python3 scripts/absence-verdicts.py            # regenerates the doc body

Classes:
  a -- error-as-absence, ACTED ON. The not-found branch does something an
       operator or user observes: reports "none", skips work, causes a write,
       returns 404/403, or asserts a conclusion the code never established.
  b -- error-as-absence, INERT. The distinction genuinely cannot change
       behaviour. A reason is required per site; "the impact is small" is not
       one.
  c -- not this class. The grep caught an Option/parse, not a fallible I/O
       Result.
"""

# (file, line, class, effect). WRITE=... marks a site where the absence causes
# or skips a WRITE; SEC=open/closed marks an authorisation or existence check.
SITES = [
    # ---- (a) absence causes or skips a WRITE — ranked first -----------------
    ("talos-worker-runtime/src/host/graphql.rs", 1079, "a", "WRITE. Redis GET error -> 'no counter today' -> set_ex(key,1,86400): the tier-2 expose_secret daily cap is skipped AND the day's accumulated count is overwritten with 1. The caller's Err arm (host/secrets.rs:387, in-memory fallback) is never reached. SEC=open. FIXED."),
    ("talos-api/src/schema/actors/mutations.rs", 278, "a", "WRITE. Grant read error -> 'http-node' (rank 1) on the left of ceiling_permits, for a user granted minimal-node (rank 0). Escalation persisted into the created actor row. SEC=open. FIXED."),
    ("talos-api/src/schema/actors/mutations.rs", 647, "a", "WRITE. Same, on the ceiling-RAISE path. SEC=open. FIXED."),
    ("talos-mcp-handlers/src/actor.rs", 1168, "a", "WRITE. user_max_world: same shape, feeds create_actor / grant_capability_ceiling / clone_actor. SEC=open. FIXED."),
    ("talos-actor-scaffold/src/lib.rs", 827, "a", "WRITE. Same helper, scaffold path. SEC=open. FIXED."),
    ("controller/src/bootstrap/background.rs", 2227, "a", "WRITE. system_settings.archive_after_days unreadable -> env default (30) -> the daily CTE DELETEs workflow_executions on a retention the operator did not configure. FIXED (skip the tick)."),
    ("talos-hot-update-service/src/lib.rs", 424, "a", "WRITE. Previous history hash unreadable -> chain restarts at 'initial', forking the module update-history chain. FIXED."),
    ("talos-hot-update-service/src/lib.rs", 491, "a", "WRITE. Declared dependencies unreadable -> module recompiled WITHOUT them -> E0433 naming a crate the user correctly declared. FIXED."),
    ("talos-hot-update-service/src/lib.rs", 501, "a", "WRITE. Same, wasm-module fallback read. FIXED."),
    ("talos-mcp-handlers/src/sandbox.rs", 1126, "a", "WRITE. find_compiled_sandbox_template error -> cache 'miss' -> full WASM recompile plus a duplicate persisted template row. Skipped dedupe."),
    ("talos-mcp-handlers/src/lib.rs", 484, "a", "WRITE. find_first_user_id error -> 'no users' -> ensure_dev_user() creates a synthetic dev user on a database that already has real ones. /mcp/local dev endpoint only."),
    ("talos-mcp-handlers/src/lib.rs", 492, "a", "WRITE. ensure_dev_user error -> agent.user_id=None -> per the comment 8 lines above, every user-scoped INSERT writes NULL and every SELECT returns zero rows; tools report success, nothing persists."),
    ("talos-mcp-handlers/src/workflows.rs", 2298, "a", "WRITE. find_template_id_via_wasm_module error -> template lookup misses -> node config-schema validation SKIPPED and the unvalidated node is written into graph_json."),
    ("talos-mcp-handlers/src/workflows.rs", 10390, "a", "WRITE. Module resolution error -> module_id=None -> plan_and_execute publishes an EMPTY passthrough subtask workflow ({'nodes':[]}) and executes it as a no-op."),
    ("talos-mcp-handlers/src/workflows.rs", 10397, "a", "WRITE. Same, ilike fallback leg."),
    ("talos-actor-lifecycle-service/src/handoff.rs", 539, "a", "WRITE. get_active_workflow_version_id error -> the handed-off execution row is created with a NULL version, so it runs against the live draft graph and loses its replay pin."),
    ("talos-atlassian/src/integration.rs", 326, "a", "WRITE. /rest/api/3/myself body-read failure -> account_id=None -> the credential UPSERT writes NULL and EXCLUDED.account_id OVERWRITES a previously-good value, breaking currentUser JQL scoping."),
    ("talos-oauth/src/credentials.rs", 843, "a", "WRITE. Provider omits scope on refresh + DB error reading the previous scope -> store_credentials persists scope='', wiping the recorded grant scope kept for 401/403 scope-drift auditing."),
    ("talos-gmail/src/watch.rs", 278, "a", "WRITE. get_integration error -> the whole `if let Some(integration)` block is skipped, so users.stop() is never called; google_err stays None so the audit row records success=true, and delete_row still removes the local row. An orphaned Gmail push channel keeps delivering, audited as a clean stop."),
    ("controller/src/bootstrap/router.rs", 2158, "a", "WRITE skipped. oauth_accounts lookup error -> the `if let Some(..)` block is skipped with NO else and NO log; the Google Calendar integration is never created while the OAuth callback completes and logs a successful login."),

    # ---- (a) security-relevant, FAIL OPEN ----------------------------------
    ("talos-totp-2fa/src/lib.rs", 140, "a", "SEC=open. HGET error -> 'not locked' -> the 2FA lockout gate is skipped. Backstopped by the HINCRBY pre-charge, so narrow — but the three sibling Redis ops in this function all log their failures with the impact spelled out and this one, the op that DECIDES the lockout, was silent. FIXED."),
    ("talos-mcp-handlers/src/analytics.rs", 4626, "a", "SEC=open. count_recent_auth_failures error -> the high-severity repeated_auth_failures finding is silently OMITTED from get_workflow_risk_assessment."),
    ("talos-analytics-repository/src/lib.rs", 1955, "a", "SEC=open. get_sla_window_stats returns None on DB error; the background loop's `_ => continue` (controller/src/bootstrap/background.rs:3084) then SKIPS SLA-violation alerting for that workflow, indistinguishable from 'fewer than 3 executions'."),
    ("talos-analytics-repository/src/lib.rs", 4329, "a", "SEC=open. fetch_all(..).unwrap_or_default() -> no wildcard-secret modules -> the hygiene report claims no module holds a '*' grant AND re-runs the orphaned-secrets scan, flagging covered secrets as orphaned."),
    ("talos-oauth/src/credentials.rs", 550, "a", "SEC=open. try_get_access_token swallows EVERY get_valid_access_token error (vault decrypt, refresh, network), not just 'row missing' -> revoke_and_cleanup skips the provider-side revoke while deleting the local rows, leaving a live OAuth grant the platform has forgotten."),
    ("talos-mcp-handlers/src/actor.rs", 2885, "a", "SEC=open (as read). Budget-policy read error -> 'policy': null in get_actor_budget: the actor is reported as having no fuel/exec/token limits."),
    ("talos-mcp-handlers/src/modules.rs", 2492, "a", "SEC=open (as read). Rate-limit read error -> rate_limit_per_minute: null: the module is reported as unthrottled."),

    # ---- (a) security-relevant, FAIL CLOSED (safe direction, false claim) ---
    ("talos-mcp-handlers/src/executions.rs", 5601, "a", "SEC=closed. Owner read error -> 'Execution not found or access denied'. The response SHOULD stay indistinguishable (existence leak) — what was missing is the server-side log; the None arm was the only arm that logged nothing. Twin of the talos-webhooks::approval_handler site fixed under MCP-535. FIXED."),
    ("talos-google-calendar/src/admin.rs", 250, "a", "SEC=closed. Audit-log EXISTS read error -> 403 'no audit record of this channel being created for this user' — a tenancy conclusion the code never reached."),
    ("talos-google-calendar/src/admin.rs", 288, "a", "SEC=closed. Integration lookup error -> 404 'no active gcal integration for this user'."),
    ("talos-mcp-handlers/src/sandbox.rs", 1813, "a", "SEC=closed. find_actor_for_user(..).unwrap_or(None).is_some() -> owned=false -> 'Actor not owned by you'."),
    ("talos-mcp-handlers/src/sandbox.rs", 3102, "a", "SEC=closed. Same shape."),
    ("talos-mcp-handlers/src/workflows.rs", 2806, "a", "SEC=closed. Same shape, actor_owned."),
    ("talos-mcp-handlers/src/actor.rs", 6404, "a", "SEC=closed. Tier read Err doesn't match Ok(Some(Tier2)) -> external_embed_blocked -> get_few_shot_examples silently degrades to keyword search."),
    ("talos-system-repo/src/lib.rs", 218, "a", "SEC=closed. is_agent_active -> false on DB error -> the SSE revocation poller tears down a live session. Documented and deliberate, but it is an action on an unestablished conclusion."),
    ("talos-actor-lifecycle-service/src/handoff.rs", 312, "a", "SEC=closed. Actor-status read error -> FromActorNotFound; the handoff is rejected."),
    ("talos-actor-lifecycle-service/src/handoff.rs", 336, "a", "SEC=closed. Same, ToActorNotFound."),
    ("talos-actor-lifecycle-service/src/handoff.rs", 436, "a", "SEC=closed. Graph read error -> WorkflowNotFound, rejected BEFORE the capability-world gate runs."),
    ("talos-mcp-handlers/src/platform.rs", 1710, "a", "SEC=closed. get_actor_card_info error -> 'Actor not found or access denied'."),
    ("talos-mcp-handlers/src/modules.rs", 976, "a", "SEC=closed. Template read error -> 'Module not found or access denied'."),
    ("talos-mcp-handlers/src/modules.rs", 1139, "a", "SEC=closed. Same, test_secret_access template leg."),
    ("talos-mcp-handlers/src/graph.rs", 4215, "a", "SEC=closed. find_template_id_by_name_ci error -> \"Module 'X' not found\" plus a fuzzy-suggestion list, for a module that exists."),
    ("talos-mcp-handlers/src/analytics.rs", 1170, "a", "SEC=closed. workflow_not_found_error (404) from the changelog handler."),
    ("talos-mcp-handlers/src/analytics.rs", 1913, "a", "SEC=closed. Same, SLA report."),
    ("talos-mcp-handlers/src/analytics.rs", 2066, "a", "SEC=closed. Same, trigger list."),
    ("talos-mcp-handlers/src/analytics.rs", 2230, "a", "SEC=closed. Recursive dependency walk emits {'error':'Workflow not found or access denied'} as a TREE NODE for a workflow that exists."),
    ("talos-mcp-handlers/src/versions.rs", 731, "a", "SEC=closed. Draft-graph read error -> 404."),
    ("talos-mcp-handlers/src/webhooks.rs", 613, "a", "SEC=closed. Graph read error -> 404 from list_workflow_webhooks."),
    ("talos-mcp-handlers/src/schedules.rs", 569, "a", "SEC=closed. get_with_workflow_info error -> 'Schedule not found or access denied'. NOTE the stats read below it deliberately does the opposite and stamps data_warning — the honest twin, in the same handler."),
    ("talos-mcp-handlers/src/advanced.rs", 1468, "a", "SEC=closed. get_scratch_session error -> \"Scratch session 'X' not found\". THE SITE #660 NAMED."),

    # ---- (a) a reported value or verdict, no write --------------------------
    ("talos-mcp-handlers/src/actor.rs", 4407, "a", "get_my_capability_ceiling reports source:'default' + 'no explicit grant. Contact an admin' — a positive claim that no grant exists, to the one person who acts on it. FIXED."),
    ("talos-mcp-handlers/src/workflows.rs", 3943, "a", "Readiness inputs default to the EMPTY-result value, so a failed read scores exactly like a workflow that never ran and has no description. Recorded prior instance of this exact shape: get_schedule_health returning zeros. FIXED (degraded_inputs + note)."),
    ("talos-mcp-handlers/src/workflows.rs", 3945, "a", "Same, workflow metadata. FIXED."),
    ("talos-audit-ledger/src/lib.rs", 349, "a", ".ok()?? collapsed 'streaming off', 'no settings row' and 'row unreadable' into one None; the third silently disables a user's audit streaming. FIXED (distinguishable in the log; fallback unchanged)."),
    ("talos-mcp-handlers/src/executions.rs", 4024, "a", "resolve_rf_id_from_label -> None on a graph-read error -> get_node_output renders the 'node not found' key list and get_node_execution_history returns an empty history for a node that exists."),
    ("talos-mcp-handlers/src/executions.rs", 4216, "a", "Fuel rollup error -> total_fuel_consumed: 0 reported as the execution's real cost."),
    ("talos-mcp-handlers/src/executions.rs", 4839, "a", "Fuel-by-label error -> every node in the waterfall reports fuel_consumed: 0 / effective_max_fuel: 0."),
    ("talos-mcp-handlers/src/executions.rs", 5030, "a", "list_child_executions error -> sub_executions: [], asserting the execution fanned out to nothing."),
    ("talos-mcp-handlers/src/actor.rs", 2706, "a", "Egress-scope read error -> previous_egress_scope: 'default' in the APPEND-ONLY security audit row: a positive claim that the actor had no egress override when it may have been 'local'."),
    ("talos-mcp-handlers/src/ml.rs", 1126, "a", "Model card reports dataset_stats: null — indistinguishable from 'dataset empty' / 'not yours'."),
    ("talos-mcp-handlers/src/ml.rs", 1147, "a", "shadow: null on the model card — the figure an operator uses to decide whether promotion is safe."),
    ("talos-mcp-handlers/src/ml.rs", 1153, "a", "Same, shadow_lifetime."),
    ("talos-mcp-handlers/src/ml.rs", 1164, "a", "teacher_audit: null, which the code's own comment defines as 'null until ml_teacher_audit runs' — asserting the audit was never run."),
    ("talos-mcp-handlers/src/platform.rs", 275, "a", "whoami reports email: null — an identity fact the tool exists to produce."),
    ("talos-mcp-handlers/src/platform.rs", 276, "a", "whoami reports organization: null — the tenancy fact used to diagnose 'my workflows don't show in the UI'."),
    ("talos-mcp-handlers/src/platform.rs", 280, "a", "Reports capability_ceiling 'http-node' (the floor) as an established fact."),
    ("talos-mcp-handlers/src/modules.rs", 905, "a", "get_wasm_module_info error -> falls through to the node_templates path, so get_module_info reports the TEMPLATE row's capability_world/allowed_hosts as if it were the compiled module's."),
    ("talos-mcp-handlers/src/modules.rs", 1122, "a", "test_secret_access: wasm-module read error -> the gate verdict is computed from the TEMPLATE row's allowed_secrets/capability_world instead of the compiled module's."),
    ("talos-mcp-handlers/src/workflows.rs", 2535, "a", "get_max_fuel error -> applied_max_fuel: null, which the surrounding comment says drives callers to conclude their fuel_budget was dropped and issue a redundant update_node_config."),
    ("talos-mcp-handlers/src/workflows.rs", 8046, "a", "find_compiled_template_by_name error -> module lands in missing_modules -> 'install them with install_module_from_catalog', which if followed installs a duplicate."),
    ("talos-mcp-handlers/src/workflows.rs", 9572, "a", "Input-schema read error -> schema_present: false, unvalidated: true — the exact claim the surrounding comment calls 'a security-broken default'."),
    ("talos-mcp-handlers/src/versions.rs", 742, "a", "get_active_version_graph_text error -> {'diff': null, 'note': 'No published version — all changes are new'}. An agent acting on that re-publishes."),
    ("talos-mcp-handlers/src/advanced.rs", 1777, "a", "get_archive_policy error -> reports the ARCHIVE_AFTER_DAYS env default as the effective retention policy, hiding a configured DB override."),
    ("talos-mcp-handlers/src/analytics.rs", 2100, "a", "Graph read error -> no module ids -> list_workflow_triggers reports the workflow has NO webhook triggers."),
    ("talos-mcp-handlers/src/analytics.rs", 3044, "a", "Graph read error -> empty module_ids -> suggest_retry_config falls through every module-type branch to the generic '2 retries / 1s linear' and labels it basis: module_type_defaults."),
    ("talos-mcp-handlers/src/analytics.rs", 5653, "a", "Analytics row error -> workflow_type reported as 'production' for what may be a draft."),
    ("talos-mcp-handlers/src/analytics.rs", 5707, "a", "get_max_execution_started_at error -> days_since_last=None -> compute_freshness_score hits `_ => 0.0`, deducting the full 20-point freshness component as if the workflow had never run."),
    ("talos-registry/src/lib.rs", 970, "a", "Stale-module-ref fallback: a DB error abandons resolution and bail!s 'Module {id} not found. Re-install with install_module_from_catalog' — the in-flight execution fails and the operator is told to re-install a module that exists."),
    ("talos-registry/src/lib.rs", 987, "a", "Same, successor lookup leg."),
    ("talos-engine/src/sub_actor_context_resolver.rs", 53, "a", "Workflow read error -> resolve() returns None -> the sub-workflow executes with NO actor memory injected, producing different agent output with no signal."),
    ("talos-engine/src/sub_actor_context_resolver.rs", 72, "a", "Same, get_relevant_actor_context leg."),
    ("talos-failure-analysis-service/src/lib.rs", 721, "a", "apply_fix path: a graph read error skips the `if let Some(..)` block with no else — the requested auto-fix silently does NOT write, and the response still carries apply_fix_available: true."),
    ("talos-cost-attribution/src/lib.rs", 149, "a", "check_fuel_budget error -> budget_usage: None in ActorCostReport, reported as 'no daily fuel budget configured'."),
    ("talos-integrations/src/handlers.rs", 74, "a", "Workflow-id query error -> HTTP 404 'create a workflow named daily-morning-briefing first', which if followed creates a duplicate."),
    ("talos-integrations/src/handlers.rs", 127, "a", "Execution query error -> HTTP 404 'run the daily-morning-briefing workflow first'."),
    ("talos-ml/src/lifecycle.rs", 196, "a", "policy_json read error -> CorrectionsCfg::default() -> eval runs with default correction weight / gold fraction, which the comment says mis-calibrates the confidence thresholds recorded in metrics_json — and those metrics are PERSISTED."),
    ("talos-replay-service/src/lib.rs", 616, "a", "Graph read error -> lookup_node_config_for_module returns None -> the caller falls back to {} and the module is RE-EXECUTED with an empty static config instead of its real one."),
    ("talos-session-brief-service/src/lib.rs", 323, "a", "get_next_scheduled_run error -> next_schedule: null: the brief reports no upcoming scheduled run, the field the comment says exists to distinguish 'no schedule' from 'far out'."),
    ("talos-worker-runtime/src/runtime.rs", 2511, "a", "A Redis TTL command error is treated like 'no TTL' -> the in-memory copy gets a flat 60 s window that can outlive a shorter Redis TTL, serving a stale module result for up to a minute."),

    # ---- (a) schema-drift reads that check 52 could not see -----------------
    ("talos-workflow-repository/src/workflows.rs", 1881, "a", "try_get('timezone') split across lines -> drift reads as UTC. The workflow-schedule EXPORT row: a 09:00 America/Toronto cron round-trips as 09:00 UTC. FIXED + check 52b."),
    ("talos-execution-repository/src/lib.rs", 528, "a", "try_get('created_at').unwrap_or_else(|_| Utc::now()) -> an unreadable timestamp is reported as 'created this instant', so age-based readers never reach the row. FIXED."),
    ("talos-secrets-manager/src/manager.rs", 3524, "a", "try_get('namespace') -> 'default' on error: namespace is half the identity this lookup exists to resolve. FIXED."),
    ("talos-actor-repository/src/lib.rs", 3742, "a", "try_get('description') -> None. Display-only; listed because it is the odd one out in a struct whose other three fields propagate. FIXED."),
    ("talos-workflow-repository/src/templates.rs", 549, "a", "try_get('source_code') -> None in the module EXPORT manifest: 'this module has no source', which a re-import faithfully reproduces. capability_world/category on the two lines above use .ok() — same class, invisible to BOTH check-52 legs. FIXED."),

    # ---- (b) inert, with the reason ----------------------------------------
    ("talos-mcp-handlers/src/executions.rs", 1137, "b", "GROUP 'node-label decoration' (12 sites): get_workflow_graph*(..).ok().flatten() feeding build_node_label_map / build_node_display_label_map, whose only consumer is map.get(uuid).unwrap_or(uuid.to_string()). An empty map renders raw UUIDs — the honest 'label unknown', identical to what a genuinely graph-less workflow renders — and never removes a row, adds a row, or changes a count. The substantive payload (events, outputs, diffs, failure counts) comes from separately-checked queries that return mcp_error on their own Err."),
    ("talos-mcp-handlers/src/executions.rs", 1593, "b", "See the node-label decoration group above."),
    ("talos-mcp-handlers/src/executions.rs", 1830, "b", "See the node-label decoration group above."),
    ("talos-mcp-handlers/src/executions.rs", 1980, "b", "See the node-label decoration group above."),
    ("talos-mcp-handlers/src/executions.rs", 3067, "b", "See the node-label decoration group above."),
    ("talos-mcp-handlers/src/executions.rs", 3288, "b", "See the node-label decoration group above."),
    ("talos-mcp-handlers/src/executions.rs", 3431, "b", "See the node-label decoration group above."),
    ("talos-mcp-handlers/src/executions.rs", 4159, "b", "See the node-label decoration group above."),
    ("talos-mcp-handlers/src/executions.rs", 4293, "b", "See the node-label decoration group above."),
    ("talos-mcp-handlers/src/executions.rs", 4717, "b", "See the node-label decoration group above."),
    ("talos-mcp-handlers/src/analytics.rs", 2530, "b", "See the node-label decoration group above."),
    ("talos-failure-analysis-service/src/lib.rs", 579, "b", "See the node-label decoration group above."),
    ("talos-mcp-handlers/src/executions.rs", 5893, "b", "The map resolves rf_id->UUID only, and the empty-map fallback re-derives the UUID with the same SHA256(rf_id)[..16] used to build it. Byte-identical result; the lookup cannot change."),
    ("talos-mcp-handlers/src/actor.rs", 1907, "b", "Terminal-state guard falls through the catch-all, but suspend_actor's SQL re-gates terminal states and its Ok(0) arm emits the SAME operator-facing error (MCP-645/646). Fails closed via the SQL backstop."),
    ("talos-mcp-handlers/src/actor.rs", 2179, "b", "Same, update_actor_status."),
    ("talos-mcp-handlers/src/actor.rs", 2598, "b", "Prior tier renders as the literal 'unknown' in the audit row and response; a genuine NULL renders 'unknown' too and nothing branches on it."),
    ("talos-mcp-handlers/src/actor.rs", 2811, "b", "Same, write ceiling."),
    ("talos-mcp-handlers/src/search.rs", 629, "b", "Module-name batch lookup -> name: null beside a module_id that is still emitted. Ornament on an answer that stands without it; no count or ranking uses it."),
    ("talos-scheduler/src/lib.rs", 2083, "b", "THE MODEL SHAPE. Fence-epoch read is .ok().flatten() and is IMMEDIATELY followed by `if fence_epoch.is_none() { warn!(\"running unfenced\") }` with a comment stating why unfenced is acceptable. The absence is observable and the degradation is named."),
    ("talos-registry/src/sync.rs", 122, "b", "`which cosign` -> None -> falls back to Command::new(\"cosign\") (PATH walk). Verification still runs; only the PATH-pinning defense-in-depth is lost, and the doc comment says a resolution failure deliberately does not cache a sentinel so the next call retries."),
    ("talos-node-cache/src/lib.rs", 145, "b", "Textbook cache case: a read error and a genuine miss both mean 'recompute the node', and the recompute is the correct answer either way."),
    ("talos-workflow-repository/src/search.rs", 25, "b", "Exact execution-cache lookup: same argument."),
    ("talos-workflow-repository/src/search.rs", 82, "b", "Semantic execution-cache lookup: same argument."),
    ("talos-api/src/schema/platform/queries.rs", 103, "b", "granted_by_email: null decorates a CapabilityCeilingDetail whose ceiling/source/granted_at come from an already-error-checked query; nothing branches on the email, and null is what a deleted granter yields anyway."),
    ("talos-google-calendar/src/handlers.rs", 186, "b", "email: null decorates an integration info struct whose id/scope/is_active/oauth_account_id are the answer and come from an already-matched Ok(Some(..))."),
    ("talos-secrets-manager/src/manager.rs", 3495, "b", "find_name_collision: DEAD CODE — zero callers workspace-wide, one occurrence (its own definition). Its doc says 'Best-effort — DB errors return None so a transient hiccup doesn't break the upsert' four lines under a doc describing the harm it prevents. I ranked it the top (a) on sight; closing the caller set demoted it. Separately a signal-nobody-consumes item."),

    # ---- (c) not this class -------------------------------------------------
    ("talos-mcp-handlers/src/executions.rs", 2983, "c", "s.parse::<Uuid>().ok() on the caller's execution_id string."),
    ("talos-mcp-handlers/src/executions.rs", 2996, "c", "Same, workflow_id."),
    ("talos-mcp-handlers/src/graph.rs", 5503, "c", "Uuid::parse_str(judge_workflow_id).ok() on caller input."),
    ("talos-mcp-handlers/src/schemas.rs", 285, "c", "cache::get('counter').unwrap_or(None) inside a JSON DOCUMENTATION STRING of guest-WASM example code. Not executed."),
    ("talos-idempotency/src/lib.rs", 530, "c", "header.to_str().ok() on Idempotency-Key."),
    ("controller/src/bootstrap/router.rs", 1733, "c", "headers.get('X-API-Key').to_str().ok()."),
    ("talos-webhooks/src/router.rs", 1445, "c", "serde_json::from_str(&response_body).ok() — a parse of the module's response text, not an I/O Result."),
    ("talos-module-repository/src/lib.rs", 458, "c", "r.try_get::<String,_>('id').ok() — an in-memory column decode inside a sample list; the authoritative webhook_count above it is ?-propagated and is what the delete guard reads."),
    ("talos-analytics-repository/src/lib.rs", 4332, "c", "r.try_get::<String,_>('name').ok() — a column decode. The real error-as-absence is 3 lines up at 4329 and is listed there."),
]

if __name__ == "__main__":
    import collections
    c = collections.Counter(s[2] for s in SITES)
    print(f"(a) acted on: {c['a']}   (b) inert: {c['b']}   (c) not this class: {c['c']}"
          f"   total: {len(SITES)}")
    for cls in ("a", "b", "c"):
        print(f"\n## ({cls})")
        for f, ln, k, why in SITES:
            if k == cls:
                print(f"* `{f}:{ln}` — {why}")

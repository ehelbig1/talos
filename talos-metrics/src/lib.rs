//! Prometheus metrics instrumentation for Talos controller.
//!
//! This module provides metrics for:
//! - Webhook request counts and latencies
//! - Authentication success/failure rates
//! - Module execution counts and duration
//! - Rate limiter hits
//! - Cache hit/miss rates
//! - DLQ metrics

use prometheus::{
    exponential_buckets, Counter, CounterVec, Gauge, HistogramVec, IntGauge, Registry,
};
use std::sync::{Arc, OnceLock};

/// The complete, closed set of `phase` label values on
/// `talos_scheduler_dispatches_total`.
///
/// Shared by the pre-seed loop in [`TalosMetrics::new`] and by every emitting
/// site in `talos_scheduler`, so a new value cannot be emitted without also
/// being seeded — the drift that makes an `increase(...) > 0` alert
/// unfireable on the one series that matters.
pub const SCHEDULER_DISPATCH_PHASES: [&str; 2] = [SCHEDULER_PHASE_STARTUP, SCHEDULER_PHASE_STEADY];

/// The startup backlog: schedules found due by the FIRST poll after boot.
pub const SCHEDULER_PHASE_STARTUP: &str = "startup";
/// Every poll after the first one.
pub const SCHEDULER_PHASE_STEADY: &str = "steady";

/// The complete, closed set of `outcome` label values on
/// `talos_scheduler_dispatches_total`. See [`SCHEDULER_DISPATCH_PHASES`].
///
/// **These five values PARTITION the scheduler's dispatch attempts**, and that
/// is a load-bearing property rather than a tidiness one: the alert runbook
/// tells operators to reconcile this counter against the boot backlog size
/// logged by `event_kind="scheduler_startup_backlog"`, and a counter with
/// uncounted terminal paths cannot reconcile against anything. Every task
/// spawned by `talos_scheduler::SchedulerService::spawn_workflow_execution`
/// records exactly one of these before it returns. When adding a terminal
/// `return` to that path, add its `record_dispatch` in the same edit — the
/// crate's `every_terminal_path_records_an_outcome` test documents the
/// enumeration, but only a human keeps it true.
pub const SCHEDULER_DISPATCH_OUTCOMES: [&str; 5] = [
    SCHEDULER_OUTCOME_COMPLETED,
    SCHEDULER_OUTCOME_FAILED,
    SCHEDULER_OUTCOME_SKIPPED,
    SCHEDULER_OUTCOME_DENIED,
    SCHEDULER_OUTCOME_FENCED,
];

/// The execution reached a terminal success.
pub const SCHEDULER_OUTCOME_COMPLETED: &str = "completed";
/// The run errored — engine failure, engine-build failure, or a DB error on
/// any of the pre-dispatch loads (workflow row, graph, execution-row INSERT,
/// fail-closed auth-gate lookup).
pub const SCHEDULER_OUTCOME_FAILED: &str = "failed";
/// The fire was refused before it ran because CAPACITY was exhausted — the
/// per-workflow concurrency cap, the actor-budget pre-check, or the atomic
/// actor-budget backstop. Visibly skipped, not silently dropped: for a daily
/// cron this means the run is lost until tomorrow. This is the herd-shaped
/// refusal, which is why the startup-herd alert selects it alongside `failed`.
pub const SCHEDULER_OUTCOME_SKIPPED: &str = "skipped";
/// The fire was refused by POLICY — the bound actor is archived/terminated/
/// not-runnable, or a node exceeds the actor's capability ceiling. Deliberately
/// NOT `skipped`: these are chronic configuration states that are unchanged by
/// how many schedules came due at once, so folding them into the herd alert
/// would make it fire on every deploy with a cause it cannot support.
pub const SCHEDULER_OUTCOME_DENIED: &str = "denied";
/// The run was superseded mid-flight by a crash-recovery reclaim (the execution
/// row's epoch advanced under it). Neither a success nor a failure of THIS
/// dispatch — the row now belongs to the resumer — but it is a terminal path,
/// and an uncounted terminal path is what stops the counter being a partition.
pub const SCHEDULER_OUTCOME_FENCED: &str = "fenced";

/// Process-global metrics registry.
///
/// Initialised once in `main.rs` after [`TalosMetrics::new`] succeeds.
/// Subsystems use [`global()`] to emit metrics without threading an
/// `Arc<TalosMetrics>` through every constructor. Safe concurrent reads;
/// writes are one-shot at startup.
static METRICS: OnceLock<Arc<TalosMetrics>> = OnceLock::new();

/// Install the process-global metrics registry. Idempotent —
/// subsequent calls return the already-installed value.
pub fn set_global(metrics: Arc<TalosMetrics>) {
    let _ = METRICS.set(metrics);
}

/// Access the process-global metrics registry. Returns `None` when
/// called before [`set_global`] (e.g. from a unit test). Callers MUST
/// use `.map(|m| m.counter.inc())` idiom — never unwrap.
pub fn global() -> Option<&'static Arc<TalosMetrics>> {
    METRICS.get()
}

/// Record a terminal workflow-execution outcome on the process-global
/// `talos_workflow_executions_total{status}` counter. Inert when metrics
/// aren't wired (unit tests, any process without `set_global`) — never
/// unwraps, mirroring [`global`]'s contract.
///
/// Called from the two terminal-write chokepoints
/// (`mark_execution_completed` → `"success"`, `mark_execution_failed` →
/// `"failure"`) so every finalizing caller (trigger / retry / replay /
/// crash-recovery / GraphQL / MCP) feeds the counter without each site
/// remembering to. This is the metric the TalosWorkflowFailureRateHigh
/// alert fires on — before this wiring the counter was registered but
/// never incremented (dead), so any alert on it would never have fired.
pub fn record_workflow_outcome(status: &str) {
    if let Some(m) = global() {
        m.workflow_executions_total
            .with_label_values(&[status])
            .inc();
    }
}

/// Global metrics registry and collectors
pub struct TalosMetrics {
    pub registry: Registry,

    // Webhook metrics
    pub webhook_requests_total: CounterVec,
    pub webhook_request_duration_seconds: HistogramVec,
    pub webhook_dlq_drops_total: Counter,

    // Authentication metrics.
    //
    // `auth_attempts_total` / `auth_failures_total` are the denominator and
    // numerator of the `TalosControllerHighErrorRate` alert. Emitted for
    // INTERACTIVE logins only — `method=password` (`talos_auth::AuthService::
    // login`) and `method=oauth` (the controller's `oauth_callback_handler`).
    // API-key validation is deliberately excluded: it runs on every GraphQL
    // request, so folding it into the same `sum(rate(...))` would swamp the
    // interactive population and leave a credential-stuffing burst unable to
    // move the ratio — an alert that is technically live but still cannot
    // fire. `api_key_validations_total` below is that surface's own series
    // (currently unwired; no alert references it).
    pub auth_attempts_total: CounterVec,
    pub auth_failures_total: CounterVec,
    pub auth_2fa_attempts_total: CounterVec,
    pub api_key_validations_total: CounterVec,

    // Execution metrics
    pub module_executions_total: CounterVec,
    pub module_execution_duration_seconds: HistogramVec,
    pub workflow_executions_total: CounterVec,
    pub workflow_execution_duration_seconds: HistogramVec,

    // Crash-recovery metrics (durable execution, RFC 0003). Labeled by
    // `outcome`: resumed | failed | reclaimed. Lets operators alert on a
    // restart-resume sweep that silently does nothing or whose resumes fail.
    pub crash_recovery_total: CounterVec,

    // ---- Detector metrics (2026-08) ----
    //
    // Each of the five below existed as a WARN/ERROR log line ONLY. Every
    // alert this platform ships is metric-based, so a log-only detector is a
    // signal nothing can consume — the same defect as a signal never emitted.
    // Adding the counter is what makes the detector page-able.
    //
    // DO NOT collapse these into a shared `warn_and_count!` macro. A macro
    // body would contain the literal `.field….inc()` for every metric it can
    // touch, so all of them would read as LIVE to structural check 58 from one
    // definition site — re-blinding the lint in exactly the way #620 just
    // fixed. If a future author does build such a helper, check 58 must first
    // be taught to require an INVOCATION naming the field rather than a
    // textual match.
    /// WASM log lines discarded because they could not be routed to any
    /// execution row. Labels: `kind=no_execution_row|unparseable_id`, a
    /// closed set of `&'static str` — never the guest-authored message body,
    /// never the execution id (an orphaned line may carry module output, and
    /// a per-execution label would be unbounded cardinality).
    pub wasm_log_orphaned_total: CounterVec,
    /// `module_executions` start-row INSERT failures at the single
    /// `PostgresModuleExecutionStore::record_started` chokepoint. The upstream
    /// CAUSE of `wasm_log_orphaned_total{kind="no_execution_row"}`, and
    /// independently it means `get_execution_logs` / `get_node_io` / cost
    /// attribution are quietly missing rows.
    pub module_execution_record_started_failures_total: Counter,
    /// `module_executions` rows the stuck-execution sweep had to convert to
    /// `'timeout'` because nothing ever finalized them.
    ///
    /// A HEALTHY fleet increments this rarely — a genuinely dead worker, a
    /// controller killed mid-execution. Sustained non-zero means rows are
    /// being opened and never closed, which is a broken LEDGER rather than a
    /// broken fleet, and it is the shape that hid for over a month: from the
    /// table's first row until 2026-08-12 every single-node workflow dispatch
    /// landed here (21,065 rows, zero `completed` rows ever), silently
    /// emptying `replay_module_regression`'s `WHERE status='completed'`
    /// corpus. Nothing observed the sweep's return value except a WARN log.
    ///
    /// Unlabelled deliberately. The sweep's `UPDATE … LIMIT 100` returns a
    /// row count and nothing else — it does not know which module, user or
    /// workflow the rows belonged to, and any of those would be unbounded
    /// cardinality. An unlabelled `Counter` is also exported at 0 from
    /// process start (unlike a `CounterVec`, which emits nothing until a
    /// label set is touched), so an alert on it is never silenced by the
    /// absent-is-not-zero trap.
    pub module_executions_swept_stuck_total: Counter,
    /// Job results discarded by the fire-and-forget `talos.results.*`
    /// subscriber because the payload would not deserialize into a
    /// `JobResult`.
    ///
    /// That subject is single-producer and single-type — only the worker
    /// publishes there (`worker/src/main.rs::publish_result_with_retry`, the
    /// no-reply-topic branch), pipeline results go to a different subject,
    /// and guest WASM is denied the whole `talos.` prefix. So a message that
    /// does not parse is an anomaly, never routine traffic, and the drop is
    /// not free: that subscriber is the ONLY finalizer for the four
    /// fire-and-forget dispatch paths that publish with no reply inbox (Gmail
    /// push, Google-Calendar push, GCP Monitoring Pub/Sub, and the webhook
    /// DLQ replay `talos_webhooks::router::dispatch_replay`). The live
    /// webhook path uses `nats.request()` and is NOT one of them. One dropped
    /// message loses the
    /// terminal `module_executions` status write, the `output_data` payload,
    /// and the `__ops_alert__` ingest that hangs off
    /// `complete_execution_from_worker` — after which the 30-minute sweep
    /// rewrites the row to `'timeout'`. Pre-metric this was a
    /// `tracing::debug!`, a level not enabled by default, so the loss left no
    /// operator-visible trace at all.
    ///
    /// UNLABELLED on purpose, for two independent reasons. The serde error
    /// text is derived from an attacker-influenceable payload, so it is an
    /// unbounded-cardinality surface on a scrapeable endpoint; and `job_id`
    /// is unavailable by construction (the parse that would have produced it
    /// is the thing that failed). Registration alone exports an unlabelled
    /// `Counter` at 0 from process start, so `> 0` cannot be silenced by the
    /// series being absent (a `CounterVec` emits nothing until a label set is
    /// first touched).
    pub job_results_dropped_unparseable_total: Counter,
    /// WORM audit-ledger verification failures. Labels:
    /// `stage=event|chain` — `event` is the inline per-message
    /// authenticity/integrity check at ingest (the message is quarantined,
    /// never persisted); `chain` is the offline hash-chain sweep over a
    /// completed execution's full ordered record set. Either means the
    /// compliance artifact is void for that execution.
    pub audit_verification_failures_total: CounterVec,
    /// Worker-key trust-on-first-use conflicts at the self-registration
    /// endpoint: a `worker_id` presented a key that is not its bound
    /// identity. In-fleet impersonation, or an operator rotating off the
    /// managed path. UNLABELLED on purpose — `worker_id` and the submitted
    /// key are both caller-supplied at a network endpoint, so neither may
    /// become a label (unbounded cardinality, attacker-driven).
    pub worker_key_tofu_conflicts_total: Counter,
    /// Number of distinct `worker_id`s with an ACTIVE `worker_identities` row
    /// whose reported build provably differs from this controller's. A GAUGE,
    /// recomputed from a query each sweep (always `set`, never `inc`/`dec`) so a
    /// worker catching up, or having its key deactivated, lowers it. A counter
    /// would be wrong at both ends: it would fire on every rolling deploy AND go
    /// quiet while a fleet stayed skewed.
    ///
    /// ACTIVE means "row not deactivated", NOT "process running", and
    /// `last_seen_at` is boot-only so no age filter can tell the two apart. A
    /// reaper DOES exist (`reap_departed_identities`, added #631/#632) but it
    /// is OFF by default, and its automatic arm only matches rows with a
    /// non-NULL `last_liveness_at`; a worker that never ran the liveness
    /// pinger needs the separately-gated `reap_pre_protocol_identities`. So on
    /// a fleet whose `worker_id` is the pod name (the chart default), retired
    /// pods keep this above zero after a controller upgrade until an operator
    /// deactivates their keys or enables BOTH reaper arms. See
    /// `controller::bootstrap::background::publish_worker_build_skew`.
    ///
    /// "Unverifiable" workers are NOT counted here (absence of evidence is
    /// not evidence of skew — #578).
    pub worker_build_skew_workers: IntGauge,

    /// Catalog templates (`kind='catalog' AND user_id IS NULL`) whose
    /// `wasm_bytes` is NULL or empty **and which carry no `oci_url`** — i.e.
    /// templates with neither local bytes nor a registry reference, which
    /// therefore **cannot run at all**.
    ///
    /// The `oci_url` half of that predicate is not defensive trimming. In OCI
    /// mode `talos_registry::sync` inserts every catalog row with
    /// `source_code = ''` and no `wasm_bytes` BY DESIGN — the worker pulls the
    /// bytes from the registry at execution time — so a count without it
    /// equals the entire healthy catalog and this gauge's alert pages on a
    /// working cluster.
    ///
    /// A GAUGE, recomputed from one query after each boot's background
    /// compiles settle (always `set`, never `inc`), because the condition is
    /// durable state rather than an event: a template with no WASM stays
    /// broken until someone fixes it, and a counter would go quiet exactly
    /// while the fleet stayed broken.
    ///
    /// This exists because the failure it detects was, for its whole
    /// lifetime, visible ONLY as a boot-time WARN whose text
    /// ("keeping existing wasm_bytes") actively implied there were bytes to
    /// keep. Three shipped templates sat at NULL for months.
    ///
    /// UNLABELLED on purpose. In OCI mode the template name is
    /// registry-supplied, so a per-template label is an unbounded-cardinality
    /// surface; the names live in `get_catalog_status` → `never_compiled`,
    /// which is a queried surface rather than a scraped one.
    ///
    /// Published at boot on every exit of the seeding pass (disk seed, OCI
    /// early return, missing-`module-templates/` early return) so the alert is
    /// fireable in every supported mode, AND re-measured every 300 s by
    /// `spawn_metrics_gauge_tasks` so it tracks current state rather than the
    /// state at the last restart.
    ///
    /// **Until 2026-08-26 the boot publish was the ONLY writer**, which broke
    /// the gauge in both directions: a row that lost its bytes after boot left
    /// it at 0 and the alert could never fire, and a row repaired after boot
    /// left it above 0 and the alert fired until the next restart. The
    /// periodic sweep is what makes `> 0` mean "right now".
    ///
    /// **Holds its last value when the query fails; it is NOT zeroed and no
    /// sentinel is folded in** — `get_catalog_status` and the alert's
    /// `{{ $value }}` both read this as a row count, and a synthetic value
    /// would make it untrustworthy to them. Telling a held value from a
    /// measured one is the job of the SEPARATE series below.
    pub catalog_templates_missing_wasm: IntGauge,

    /// Unix time of the last sweep in which `talos_catalog_templates_missing_wasm`
    /// was successfully measured.
    ///
    /// **This is the companion "the detector could not measure" signal**, in
    /// the same form and for the same reason as
    /// `crypto_orphan_scan_last_success_timestamp_seconds` (#667). An
    /// `IntGauge` exports 0 from registration, so
    /// `talos_catalog_templates_missing_wasm == 0` covers BOTH "measured, every
    /// catalog template can run" and "the `SELECT COUNT(*)` errored and nothing
    /// was ever measured". Before the periodic sweep those two readings were
    /// not merely ambiguous but PERMANENTLY so: the boot publish never retried,
    /// so one failed query at boot switched the detector off for the life of
    /// the process while it read as a clean bill of health.
    ///
    /// **Why a freshness timestamp rather than a `blind`/`failed` gauge.** A
    /// `blind == 0` gauge is itself an unmeasured zero: if the sweep task never
    /// spawns, panics, or is dropped in a refactor, nothing sets it and it
    /// reads "not blind" forever — this exact defect one level up. A timestamp
    /// degrades the right way in all four cases: query error, task death, task
    /// never spawned, and a controller build predating the sweep (0 from
    /// registration, which reads as maximally stale).
    ///
    /// `TalosCatalogMissingWasmDetectorBlind` is the alert that consumes it.
    pub catalog_missing_wasm_scan_last_success_timestamp_seconds: Gauge,

    // ---- Worker-identity liveness + reaper (2026-08) ----
    //
    // Before these, the entire proof-of-possession liveness path and the
    // reaper that consumes it were UNINSTRUMENTED: no metric, no alert. That
    // is not a gap like an ordinary missing counter, because the reaper's
    // worst failure — deactivating the signing key of a LIVE worker — is
    // silent for a whole trust window (24h by default) and then presents as
    // fleet-wide signature-verification failure with nothing pointing at the
    // cause. The five series below exist so that failure is visible BEFORE
    // it happens, which is the precondition for turning the reaper on at all.
    /// Liveness pings received at `POST /internal/worker-liveness`.
    /// Labels: `outcome=accepted|rejected_request|rejected_proof|
    /// inactive_identity|error` — a closed set of `&'static str` DERIVED FROM
    /// THE RESPONSE STATUS the endpoint already returns
    /// (`controller::bootstrap::router::liveness_outcome_label`).
    ///
    /// TWO PROPERTIES THAT MUST NOT BE WEAKENED, both because this endpoint
    /// is unauthenticated and reachable by any caller that can open a socket
    /// to the controller:
    ///  * NO caller-derived label. Not `worker_id`, not the presented public
    ///    key, not an error string — each would hand an unauthenticated
    ///    caller control of series cardinality (an OOM DoS on the scrape
    ///    path). The identifying detail lives in the `talos_security` log,
    ///    which is rate-limited and DLP-scrubbed; a metric label is neither.
    ///  * NO new distinction. Deriving the label from the HTTP status makes
    ///    it STRUCTURALLY impossible for this counter to tell an observer
    ///    anything the endpoint's own response does not already — so it can
    ///    never become an existence oracle for "is this worker registered".
    ///    (The endpoint already answers 401 for a bad proof and 404 for a key
    ///    that is not an active identity, and 404 is only reachable AFTER a
    ///    valid proof-of-possession, i.e. by someone who already holds the
    ///    private key.) Do not "improve" this by labelling from inside the
    ///    handler's branches.
    pub worker_liveness_pings_total: CounterVec,
    /// Worker signing keys deactivated by the reaper. Labels:
    /// `arm=departed|pre_protocol` — `departed` is the automatic arm keyed on
    /// liveness silence, `pre_protocol` the opt-in arm keyed on registration
    /// age for rows that never participated. Counts KEYS, not workers (a
    /// worker mid-rotation holds two rows).
    ///
    /// This is the "what just happened" pointer for the failure this whole
    /// area exists to survive: a false reap manifests as signature failures
    /// across the fleet, and without this counter there is nothing in the
    /// metrics tying that to a trust-boundary write. UNLABELLED by worker —
    /// same cardinality rule as above, and the reaper's own WARN already
    /// carries the count.
    pub worker_identity_reaps_total: CounterVec,
    /// Reactive OAuth credential repairs — one increment per credential per
    /// repair attempt, fired only after a dispatched job has ALREADY failed
    /// with an authentication error on a Talos-held OAuth credential.
    ///
    /// Labels: `outcome=repaired|not_refreshed|refresh_failed`, a closed set
    /// of three `&'static str`. **Deliberately not labelled by provider,
    /// user, or vault path**: the provider segment comes from a
    /// workflow-authored `vault://oauth/<provider>/…` string (unbounded
    /// cardinality from caller data), and the remaining segments are the
    /// user id and — for gmail/google_calendar — the user's e-mail address.
    ///
    /// This counter is what makes the two failure MODES distinguishable,
    /// which is the whole operator-facing point of the reactive path:
    ///
    /// * `repaired` — the credential was dead, a new token was obtained, and
    ///   the node was re-dispatched. Self-healed; no action. A rising rate
    ///   means the PREDICTIVE refresh is losing races and is worth a look,
    ///   because each one costs a doubled dispatch.
    /// * `refresh_failed` — the token endpoint refused. For Google and
    ///   Atlassian that is what a REVOKED or expired grant looks like
    ///   (`HTTP 400 invalid_grant`). The node failed and **will keep failing
    ///   until a human re-consents** — this is the arm that needs a person.
    /// * `not_refreshed` — nothing to refresh (no refresh endpoint for the
    ///   provider, e.g. non-expiring Slack bot tokens). The 401 was not a
    ///   staleness problem and the node was NOT retried.
    ///
    /// All three are pre-seeded at 0: the healthy steady state is that none
    /// of them ever moves, which is exactly the case where an absent series
    /// silently unfires an `increase(...) > 0` alert.
    pub oauth_reactive_refresh_total: CounterVec,
    /// Distinct `worker_id`s with an ACTIVE `worker_identities` row that have
    /// proved liveness at least once — i.e. **the automatic reaper's
    /// population**. A row enters it on its first ping and never leaves
    /// (nothing clears `last_liveness_at`) until the row is deactivated, so
    /// this is exactly the set of identities the reaper is able to act on.
    ///
    /// A GAUGE recomputed from the fleet query each sweep (always `set`), for
    /// the same reason as `worker_build_skew_workers`: it must be able to
    /// fall as well as rise.
    pub worker_liveness_participants: IntGauge,
    /// The subset of [`Self::worker_liveness_participants`] whose most recent
    /// liveness proof is inside the participation horizon — i.e. **the set
    /// still actively pinging**.
    ///
    /// THE PAIR IS THE POINT, and neither number is useful alone. The
    /// difference `participants - recent_participants` is the count of keys
    /// that are in the reaper's population and have STOPPED proving liveness:
    /// the pre-reap signature of a false reap, visible for the whole gap
    /// between the horizon and the trust window (~22h at defaults) BEFORE any
    /// key is deactivated. Publishing only the difference would have hidden
    /// the denominator — "3 silent" reads very differently at 3 participants
    /// than at 300 — so both are exported and the alert does the subtraction.
    ///
    /// On a fleet that has NEVER participated both are 0 and the difference
    /// is 0, which is why the alert cannot fire on a fleet that legitimately
    /// does not ping (the chart default: the liveness ping is blocked at the
    /// network layer unless two opt-in NetworkPolicy rules are enabled).
    pub worker_liveness_recent_participants: IntGauge,
    /// 1 when the liveness DETECTOR can no longer see the whole population the
    /// REAPER can act on, 0 otherwise.
    ///
    /// **This closes the one gap that would have reintroduced the exact silent
    /// false reap the pair above exists to prevent.** The two participation
    /// gauges are computed from
    /// `WorkerIdentityRepository::list_active_builds`, which is bounded
    /// (`ORDER BY worker_id, public_key LIMIT MAX_FLEET_BUILD_ROWS`, 200). The
    /// reaper's `UPDATE` is NOT bounded. So above 200 active rows a worker
    /// whose row sorts after the 200th was invisible to both gauges and fully
    /// reapable — `TalosWorkerLivenessParticipationDropped` could not warn
    /// about it, and the runbook's "participants must equal your worker count"
    /// gate silently became uncheckable.
    ///
    /// The fix is FAIL-SAFE rather than cosmetic: while this gauge is 1 the
    /// reaper SKIPS its sweep entirely and deactivates nothing (see
    /// `controller::bootstrap::background`). This series is what makes that
    /// refusal visible — a fail-safe you cannot see is just a silent state,
    /// which is the defect one level up. `TalosWorkerIdentityReapBlinded`
    /// alerts on it.
    ///
    /// SATURATING, not a count: the bounded SELECT returning exactly 200 rows
    /// means "at least 200 active rows, possibly more". Knowing HOW many are
    /// unobserved would need a second query, and the number does not change
    /// the response — drain the ghost rows with `deactivate-worker-identity`
    /// until the detector is whole again.
    pub worker_liveness_population_truncated: IntGauge,

    // ---- NATS fleet heartbeat (2026-08) ----
    //
    // A THIRD, INDEPENDENT view of the fleet, and the only one that works in
    // the chart's DEFAULT posture. The two series above describe registered
    // `worker_identities` rows and are structurally silent on a fleet pinned
    // through the static `TALOS_WORKER_PUBLIC_KEYS` ring (no registration
    // endpoint, no rows); the liveness ping needs worker→controller HTTP,
    // which `networkPolicy.workerControllerEgress` blocks unless enabled.
    // The heartbeat needs neither — every worker already speaks NATS.
    //
    // WHAT THE EVIDENCE IS WORTH, because it is weaker than it looks: a
    // heartbeat is HMAC-signed under the FLEET-SHARED `WORKER_SHARED_KEY`, so
    // any process holding that key can mint one naming any worker. These are
    // liveness HINTS for observability. Nothing here may gate trust, and
    // `worker_id` is caller-supplied so it is NOT a label on any of them.
    /// Distinct `worker_id`s that published a fleet heartbeat within the
    /// staleness window. A GAUGE recomputed from the fleet view each sweep
    /// (always `set`), so an id that stops heartbeating lowers it within
    /// `STALE_AFTER + PRUNE_INTERVAL`.
    ///
    /// **WHETHER THIS IS A REPLICA COUNT DEPENDS ON THE POSTURE, so establish
    /// the posture before reading the number.** The fleet view is a map keyed
    /// on `worker_id`, and the two shipped postures differ:
    ///
    /// * **DISTINCT ids — the chart DEFAULT.** Nothing in
    ///   `deploy/helm/talos/templates/worker/deployment.yaml` renders
    ///   `TALOS_WORKER_ID`; the `values.yaml` line offering it is COMMENTED
    ///   OUT inside the opt-in RFC-0010 worker-trust block. So a default
    ///   `helm install` falls through to `worker_identity()`'s step 2,
    ///   `HOSTNAME` → the pod name, and every replica carries its own id.
    ///   Here the gauge IS a replica count: five replicas report 5, and
    ///   scaling 5→1 lowers it to 1.
    /// * **ONE SHARED id.** The dev compose stack sets a single
    ///   `TALOS_WORKER_ID` for every replica (`.env`), and the RFC-0010
    ///   single-key Ed25519 block does the same once an operator uncomments
    ///   it. Every replica then writes the SAME entry: a fleet of any size
    ///   reports 1, and scaling 5→1 still reports 1.
    ///
    /// The earlier wording here ("so a scaled-down worker lowers it") was true
    /// of the first posture and silently false of the second; it is corrected
    /// rather than renamed, per the misleading-report-field rule (#579/#580).
    /// Where a shared id is deliberate, do NOT "fix" it to make this gauge
    /// nicer: the static `TALOS_WORKER_PUBLIC_KEYS` ring looks a worker's
    /// public key up BY `worker_id`, so varying it alone breaks dispatch
    /// verification.
    ///
    /// What it answers in EVERY posture is "how many distinct heartbeating
    /// identities?", which is the honest denominator for
    /// [`Self::worker_fleet_build_skew_workers`] and
    /// [`Self::worker_fleet_unverifiable_workers`] (all three are derived from
    /// this same map). It is an answer to "are all my replicas up?" only under
    /// distinct ids, and under a shared id nothing in this file can answer
    /// that — see the fleet crate's module header for why replica-loss
    /// detection is a separate problem.
    ///
    /// 0 is AMBIGUOUS and must be read as "no heartbeat observed": it covers
    /// a genuinely empty fleet, a fleet on a build too old to publish, and a
    /// broken subscription. It is not evidence that workers are absent.
    pub worker_fleet_live_workers: IntGauge,
    /// DISTINCT builds observed within the staleness window — **the
    /// denominator for the two gauges below, and the one to read beside them.**
    ///
    /// This is a different population from
    /// [`Self::worker_fleet_live_workers`], which counts heartbeating
    /// IDENTITIES. Reading a builds numerator against an ids denominator is
    /// how "1 skewed build of 1 live worker" comes to read as 100% of a fleet
    /// that is in fact 1 pod in 10 — the misleading-report-field defect
    /// (#579/#580) this pair exists to avoid. The two skew gauges are computed
    /// over THIS population, so:
    /// `live_builds == build_skew_builds + unverifiable_builds + agreeing`.
    ///
    /// A healthy fleet reads 1. A fleet mid-roll reads 2, steadily, for as
    /// long as both builds keep heartbeating — which is the property that lets
    /// an alert hold a `for:` duration.
    ///
    /// 0 is AMBIGUOUS in exactly the same way as `live_workers`: nothing has
    /// been observed, which is not the same as nothing running.
    pub worker_fleet_live_builds: IntGauge,
    /// Of [`Self::worker_fleet_live_builds`], those that PROVABLY differ from
    /// this controller's build.
    ///
    /// **COUNTS BUILDS, NOT PROCESSES.** Five workers stuck on one old build
    /// report 1 here, not 5. The magnitude is not lost from the export —
    /// [`Self::worker_fleet_build_skew_workers`] carries it — but it is not
    /// recoverable from THIS number, and it is this number the alert is built
    /// on, because it is the only one that survives every posture.
    ///
    /// **Why the ALERT lives here and not on the `_workers` gauge.** The fleet
    /// view is keyed on `worker_id`. Where replicas share one id — the dev
    /// compose stack, and the RFC-0010 single-key block once uncommented — a
    /// per-worker skew count ALTERNATES on a mixed-build fleet (the map is
    /// last-write-wins, so the retained build is whichever replica spoke
    /// last), and no `for:` duration can ever elapse. This build-keyed count
    /// is steady in BOTH postures, so the detector holds in both.
    ///
    /// **State the old defect precisely.** The `_workers` gauge could not
    /// hold a `for:` on a MIXED-build SHARED-id fleet — a roll stuck partway.
    /// It was steady and alerted correctly on a uniformly skewed shared-id
    /// fleet, and it is steady and correct in ALL cases under distinct ids
    /// (the chart default), which is why it is exported again beside this one
    /// rather than deleted. "It could not fire" is the overstatement; this is
    /// the claim.
    ///
    /// Still the live-process twin of `worker_build_skew_workers`, which counts
    /// REGISTERED ROWS. Neither subsumes the other — a ghost row appears only
    /// in the former, a static-key worker with no registry row only here.
    pub worker_fleet_build_skew_builds: IntGauge,
    /// Of [`Self::worker_fleet_live_builds`], those that cannot be compared
    /// with the controller's.
    ///
    /// TWO CAUSES, and the second is easy to misread off the number alone:
    /// the WORKER reported no usable sha (none, `unknown`, or a value refused
    /// by `talos_worker_fleet::well_formed_build_key`, all of which collapse
    /// onto one bucket), **or the CONTROLLER's own build has no usable sha** —
    /// in which case nothing is comparable and every observed build lands here
    /// regardless of what was reported. So this gauge equalling `live_builds`
    /// says "no comparison was possible", not "no worker reported a build".
    ///
    /// Exported so a 0 on the skew gauge is readable: 0 skewed out of 0
    /// comparable builds is not "the fleet agrees" (#578). Same deliberate
    /// under-count as the registry-backed gauge, made visible.
    ///
    /// Its population moved from workers to builds in 2026-08 alongside the
    /// gauge above; the NAME did not have to change because it already said
    /// `builds`, which is now accurate rather than merely plausible. The
    /// per-identity companion is [`Self::worker_fleet_unverifiable_workers`].
    ///
    /// **WHEN THIS EQUALS [`Self::worker_fleet_live_builds`] THE SKEW
    /// DETECTOR CANNOT FIRE AT ALL** — nothing was comparable, so
    /// `build_skew_builds` is pinned at 0 by construction rather than by
    /// agreement. `TalosWorkerFleetBuildSkewUndetectable` is the alert that
    /// says so, and it exists because the "read this gauge first" mitigation
    /// otherwise lives only in the annotation of an alert that requires
    /// `build_skew_builds > 0` — i.e. it would be delivered in every state
    /// EXCEPT the one it warns about.
    pub worker_fleet_unverifiable_builds: IntGauge,
    /// Of [`Self::worker_fleet_live_workers`], the heartbeating IDENTITIES
    /// whose reported build PROVABLY differs from this controller's — the
    /// MAGNITUDE that [`Self::worker_fleet_build_skew_builds`] cannot carry.
    ///
    /// **INFORMATIONAL. NO ALERT IS BUILT ON THIS, and one must not be**, for
    /// the reason spelled out on the builds gauge: under a shared `worker_id`
    /// the underlying map is last-write-wins, so on a MIXED-build fleet this
    /// alternates 1/0 across sweeps and no `for:` duration can elapse.
    ///
    /// **The posture decides whether the number means anything:**
    ///
    /// * **DISTINCT ids (the chart DEFAULT — `HOSTNAME` → pod name, because
    ///   nothing renders `TALOS_WORKER_ID`)**: every replica holds its own map
    ///   entry, so this is exactly "how many running pods are on a build that
    ///   differs from mine". Steady, and the honest magnitude.
    /// * **ONE SHARED id (dev compose; the RFC-0010 single-key block once
    ///   uncommented)**: the map holds ONE entry for the whole fleet, so this
    ///   is 0 or 1 regardless of fleet size, and it FLAPS whenever the fleet
    ///   is mid-roll. Read `talos_worker_fleet_build_skew_builds` there, and
    ///   `get_platform_info.fleet` for per-worker detail.
    ///
    /// It was briefly dropped while the ALERT was moved to the build-keyed
    /// population (#644 review) and kept on purpose: dropping it would have
    /// lost the magnitude on the DEFAULT posture, where the per-identity view
    /// was never broken, in order to fix a defect only shared-id installs
    /// have. It is not a dead metric — `publish_worker_fleet_gauges` `set`s it
    /// every sweep from `WorkerManager::live_build_versions`.
    ///
    /// Its denominator is [`Self::worker_fleet_live_workers`], NOT
    /// `live_builds`, and the identity population decomposes exactly the same
    /// way the build one does: `live_workers == build_skew_workers +
    /// unverifiable_workers + agreeing`.
    pub worker_fleet_build_skew_workers: IntGauge,
    /// Of [`Self::worker_fleet_live_workers`], the heartbeating identities
    /// whose build could not be compared with this controller's.
    ///
    /// Exists so that [`Self::worker_fleet_build_skew_workers`] has a
    /// published denominator decomposition and a 0 on it is readable: 0 skewed
    /// of 5 live identities means something quite different when 4 of them
    /// were never comparable. Shipping the numerator without this would repeat,
    /// one population over, the exact defect the builds trio was built to
    /// avoid — an absence rendered as a negative result (#578).
    ///
    /// Same two causes as [`Self::worker_fleet_unverifiable_builds`]: the
    /// WORKER reported no usable sha, or THIS CONTROLLER's own build has none,
    /// in which case every identity lands here at once. Same posture caveat as
    /// its sibling above: under a shared `worker_id` this counts map entries,
    /// of which there is one.
    pub worker_fleet_unverifiable_workers: IntGauge,
    /// Heartbeats refused because the fleet view was at its hard cap
    /// (`talos_worker_fleet::MAX_TRACKED_WORKERS`), cumulative since process
    /// start.
    ///
    /// An IntGauge rather than a Counter because it is republished from the
    /// subscriber's own running total each sweep rather than incremented here;
    /// it is monotonic within a process and resets on restart. Non-zero means
    /// either a misconfigured fleet or someone using the shared key to flood
    /// distinct worker ids — the bound held, but say so out loud.
    ///
    /// **TRAP FOR ANY ALERT WRITTEN ON THIS.** It has COUNTER semantics
    /// but a GAUGE type and no `_total` suffix, so `rate()` / `increase()`
    /// will not apply counter reset handling and will misread every
    /// controller restart. Alert on the level (`> 0`) or on
    /// `delta(...[1h]) > 0`, not on a rate.
    ///
    /// **IT SUPPRESSES THE BUILD-SKEW DETECTOR, not just the fleet census.**
    /// `handle_heartbeat` refuses an untracked id at the cap and returns
    /// BEFORE `record_build_observation`, so a heartbeat dropped here never
    /// reaches the build map either — a straggling worker that boots during a
    /// flood is invisible to `worker_fleet_build_skew_builds` as well as to
    /// `worker_fleet_live_workers`. `TalosWorkerFleetWorkerViewSaturated` consumes
    /// this counter, and `TalosWorkerFleetBuildViewSaturated` its build-map
    /// sibling, for that reason.
    pub worker_fleet_capacity_dropped_heartbeats: IntGauge,
    /// Build observations refused because the BUILD map was at its hard cap
    /// (`talos_worker_fleet::MAX_TRACKED_BUILDS`), cumulative since process
    /// start.
    ///
    /// Separate from [`Self::worker_fleet_capacity_dropped_heartbeats`] on
    /// purpose: they are different refusal causes over different key spaces,
    /// and a single number covering both would be unreadable. The build map
    /// saturates on a shape the worker cap cannot see — ONE `worker_id`
    /// publishing many distinct build strings — because the worker map has a
    /// single entry throughout.
    ///
    /// Non-zero means the bound held while something published more distinct
    /// builds than a fleet can have. `build_version` is signed, so only a
    /// holder of the fleet-shared key can do it; signing bounds WHO, never HOW
    /// MUCH, which is what the cap is for.
    ///
    /// **NAME THE SUPPRESSION DIRECTION FIRST, because it is the one the skew
    /// alert exists for and an earlier version of this comment gave only the
    /// other one.** At the cap a NEW key is REFUSED (`record_build_observation`
    /// returns early); tracked keys keep refreshing. `builds_match` compares
    /// only the `+sha` suffix, so `v0+<sha>` … `v63+<sha>` are 64 distinct keys
    /// that all classify as AGREEING. A shared-key holder can therefore fill
    /// the map with agreeing-but-distinct builds, after which a genuinely
    /// straggling worker's build is a new key, is refused, and is INVISIBLE:
    /// `build_skew_builds` reads 0, `TalosWorkerFleetBuildSkew` stays silent,
    /// and every published number looks healthy. That is a FALSE NEGATIVE on
    /// the detector, not a nuisance. Inflation (fabricated builds landing in
    /// the skew or unverifiable counts before the cap is reached) is the other
    /// direction and is the milder one — it is loud.
    ///
    /// The same suppression reaches this map through the WORKER cap too:
    /// `handle_heartbeat` returns early at
    /// `talos_worker_fleet::MAX_TRACKED_WORKERS` BEFORE recording the build,
    /// so a flood of distinct ids hides a straggler's build as effectively as
    /// a flood of distinct builds does. `TalosWorkerFleetBuildViewSaturated` and
    /// `TalosWorkerFleetWorkerViewSaturated` alert on the two counters for
    /// exactly that reason.
    ///
    /// Same COUNTER-semantics-with-GAUGE-type trap as its sibling: alert on
    /// the level (`> 0`) or `delta(...[1h]) > 0`, never on a `rate()`.
    pub worker_fleet_capacity_dropped_builds: IntGauge,

    /// Terminal outcomes of scheduler-driven workflow dispatches, split by
    /// whether the dispatch belonged to the **startup backlog** or to steady
    /// state.
    ///
    /// `phase=startup` is the set of schedules found due by the FIRST poll
    /// after a controller boot — i.e. the runs that accumulated while the
    /// process was down. That set is dispatched under a tighter concurrency
    /// ceiling than steady state precisely because releasing it all at once
    /// self-inflicts an outage: on 2026-08-10 fifteen schedules fired within
    /// 20 ms of each other, their WASM jobs opened ~16 simultaneous TLS
    /// connects to Google hosts, five consecutive connect failures tripped
    /// the worker's per-host circuit breaker, and the remaining eight
    /// workflows then failed instantly against an OPEN breaker. Nothing
    /// alerted, and the platform looked healthy minutes later.
    ///
    /// Splitting on `phase` is the whole point: a steady-state failure and a
    /// startup-window failure have completely different causes, and pooling
    /// them hides a defect that fires on EVERY deploy inside a background
    /// failure rate. `outcome=skipped` is the visibly-refused branch (the
    /// per-workflow concurrency cap and the actor budget) — it is NOT a
    /// success, and it is how a dropped daily cron becomes observable rather
    /// than a WARN nobody reads.
    ///
    /// The five outcomes are a PARTITION of dispatch attempts, not a sample:
    /// see [`SCHEDULER_DISPATCH_OUTCOMES`]. Ten closed series, all pre-seeded.
    /// Deliberately carries NO workflow name, schedule id or user id — those
    /// are unbounded cardinality.
    pub scheduler_dispatches_total: CounterVec,

    // ---- Fuel-headroom detector (2026-08) ----
    //
    // WHY THIS EXISTS, because it is not another "we had a log, add a
    // counter" case. The number these two publish — peak `fuel_consumed`
    // against the ceiling a worker actually enforced — was **already in the
    // database and had never been compared to anything**.
    // `pa-read-later-digest/digest` sat at 96.9% of its budget for 16 days,
    // ACROSS A SUCCESSFUL RUN, and then failed two of its four scheduled
    // runs. Every fuel surface the platform had was structurally unable to
    // see it: `get_fuel_usage_report` aggregates per MODULE, behind a
    // `min_executions` default of 3, and the adaptive-fuel learner needs
    // `MIN_SAMPLES = 5`. The node had two samples.
    //
    // That report ALSO divided by the shared `modules.max_fuel` rather than
    // the ceiling a worker enforced, so a node-scoped override read against
    // the wrong denominator. **That half is fixed** (2026-08-18): both the
    // per-module and per-node surfaces now measure against the enforced
    // ceiling, so the report no longer contradicts this gauge. The reason
    // THIS pair still has to exist is the OTHER half, which is unchanged and
    // unfixable there — the per-module surface aggregates away the node, uses
    // a percentile rather than a peak, and hides anything under
    // `min_executions`. A node with two runs remains invisible to it.
    //
    // So the defining property of this pair is that it has **NO SAMPLE
    // FLOOR**. It fires at n=1. Adding one back — for smoothing, for
    // noise, for any reason — deletes the only case it was built for.
    /// `(workflow, node)` pairs whose peak observed `fuel_consumed` is at or
    /// above [`crate`-external] threshold × the ceiling most recently enforced
    /// for them, over the detector's window.
    ///
    /// A GAUGE, recomputed from one query each sweep (always `set`, never
    /// `inc`), because the condition is durable state: an under-provisioned
    /// node stays under-provisioned until someone changes the number, and a
    /// counter would go quiet exactly while the fleet stayed exposed.
    ///
    /// UNLABELLED. `workflow_id` and the node label are both author-supplied
    /// and unbounded — a per-node label is an unbounded-cardinality surface on
    /// the scrape path. The names go to a WARN log
    /// (`controller::bootstrap::background::publish_fuel_utilisation`) and to
    /// `get_fuel_usage_report`'s `high_utilisation_nodes`, which are queried
    /// surfaces rather than scraped ones. Same rule and same escape hatch as
    /// `catalog_templates_missing_wasm`.
    ///
    /// TEST EXECUTIONS ARE EXCLUDED from the population. `test_workflow`
    /// writes rollup rows, and a hand-crafted probe payload is traffic that
    /// never happened.
    pub fuel_high_utilisation_nodes: IntGauge,
    /// The DENOMINATOR of [`Self::fuel_high_utilisation_nodes`]: every
    /// `(workflow, node)` pair the detector could evaluate in the window.
    ///
    /// **Published because otherwise a 0 above is unreadable**, and unreadable
    /// in the specific direction that matters. `high = 0` covers both "77 pairs
    /// examined, all healthy" and "the sweep is broken / the rollup is empty /
    /// nothing has run", and an IntGauge exports 0 from registration — so a
    /// detector that never ran looks exactly like a healthy fleet. That is the
    /// blindness this whole change exists to remove, one level up. Same
    /// argument as `worker_fleet_unverifiable_builds`, and
    /// `TalosFuelHeadroomDetectorBlind` is the alert that consumes it.
    pub fuel_utilisation_observed_nodes: IntGauge,

    /// Scheduler poll iterations HELD by the fleet-readiness barrier because
    /// the controller's NATS heartbeat view contained no live worker.
    ///
    /// A hold advances nothing: the barrier runs before the poll's
    /// transaction opens, so `next_trigger_at` is untouched and every due
    /// schedule is still due on the next tick.
    ///
    /// The ORDINARY boot case does not appear here. A worker that booted
    /// before the controller subscribed loses its first heartbeat outright
    /// (NATS core delivery is not retained), so the controller typically waits
    /// most of one heartbeat interval to see it — measured at ~50 s on
    /// 2026-08-10. That wait is absorbed by the scheduler's ONE bounded
    /// pre-loop wait, which deliberately does not count a hold, so a healthy
    /// boot leaves this at 0. It only starts moving once that bound has
    /// already elapsed, i.e. the fleet has been invisible far longer than the
    /// protocol can explain.
    pub scheduler_readiness_holds_total: Counter,

    /// 1 when the scheduler has GIVEN UP waiting for the fleet to become
    /// visible and is dispatching without that evidence; 0 while the barrier
    /// is functioning normally.
    ///
    /// This exists because an empty fleet view is **ambiguous, not proof of
    /// absence** — the same reading covers a genuinely empty fleet, a fleet on
    /// a build too old to publish heartbeats, a broken subscription, and an
    /// operator who set `TALOS_WORKER_HEARTBEAT_INTERVAL_SECS=0` (a supported
    /// configuration that disables heartbeat publishing outright). A barrier
    /// that treated 0 as "known cold" and refused forever would therefore
    /// silently stop ALL scheduled work on a perfectly healthy fleet — strictly
    /// worse than the boot herd it was added to prevent. So the barrier gives
    /// up after a bounded number of consecutive holds and says so here, rather
    /// than blocking indefinitely on a signal it cannot fully trust.
    ///
    /// 1 means: schedules ARE running, but the readiness guarantee is not in
    /// force, so a boot herd could recur.
    ///
    /// **This is a level, not a latch.** It returns to 0 the moment any
    /// heartbeat is seen. As a one-way latch it pinned at 1 on a healthy fleet
    /// — a slow worker image pull outlasts the give-up bound, the worker then
    /// arrives, and the alert fires until the controller restarts. On a
    /// deployment that publishes no heartbeats at all (worker-side
    /// `TALOS_WORKER_HEARTBEAT_INTERVAL_SECS=0`, which the controller cannot
    /// detect) the barrier is switched off wholesale with
    /// `SCHEDULER_FLEET_READINESS_BARRIER=false` and this stays 0, rather than
    /// documenting an alert as expected-to-fire-forever.
    pub scheduler_readiness_degraded: IntGauge,

    // Rate limiting metrics
    pub rate_limit_hits_total: CounterVec,

    // Cache metrics
    pub cache_hits_total: CounterVec,
    pub cache_misses_total: CounterVec,

    // NOTE — no circuit-breaker metrics here, deliberately.
    //
    // `talos_circuit_breaker_opens_total` / `_blocks_total` were declared and
    // registered on THIS registry from the day this crate was written, and
    // could never have been incremented: the breaker they name is a
    // per-process `OnceLock<HttpCircuitBreaker>` inside `talos-worker-runtime`,
    // running in the WORKER. Both exported a flat 0 forever while the breaker
    // was, in fact, failing scheduled workflows. They now live with their
    // producer (`talos-worker-runtime/src/circuit_breaker.rs`) and are exported
    // under the SAME names by the worker's already-scraped `/metrics`
    // (`job="talos-worker"`). Do not re-declare them here: two producers for
    // one series name, one of them permanently zero, is the false-negative
    // this move removed.

    // DLQ metrics
    pub dlq_entries_total: Counter,
    pub dlq_drops_total: Counter,
    pub dlq_db_errors_total: Counter,

    // Crypto-invariant metrics. These are the highest-blast-radius
    // signals the platform exposes — a Vault outage or KEK / DEK
    // drift causes silent encrypted-at-rest data loss.
    // See deploy/observability/alerts.yaml for the SLOs built on top.
    pub kek_decrypt_failures_total: CounterVec,
    pub memory_write_failures_total: CounterVec,
    /// `ops_alerts` ingest failures from the `__ops_alert__` hook.
    /// Labels: reason=validation|db|tenancy. Sustained bump means alert
    /// envelopes emitted by parser modules are being lost.
    pub ops_alert_ingest_failures_total: CounterVec,
    /// Alerts auto-resolved by a source-signaled recovery
    /// (`status_event: "resolved"` in the __ops_alert__ envelope).
    pub ops_alert_auto_resolved_total: Counter,
    pub module_payload_encryption_failures_total: CounterVec,
    /// Per-row secret-decrypt failures from `SecretsManager::get_module_secrets`.
    /// Labels: reason=missing_dek|cipher_init|aead|invalid_utf8|too_short.
    /// Sustained bump means a module is missing some of its expected
    /// secrets at runtime — `vault://` substitutions will fail with
    /// `Notfound` and HTTP calls will be unauthenticated.
    pub secret_decrypt_failures_total: CounterVec,
    pub actor_memory_orphaned_rows: IntGauge,
    pub module_execution_orphaned_rows: IntGauge,
    pub workflow_execution_orphaned_rows: IntGauge,
    /// Unix time of the last crypto-orphan sweep in which **all three** of the
    /// gauges above were successfully measured.
    ///
    /// **This is the companion "the detector could not measure" signal for the
    /// three `critical` / data-loss orphan alerts**, and it exists for exactly
    /// the reason `fuel_utilisation_observed_nodes` exists for
    /// `fuel_high_utilisation_nodes`: an `IntGauge` exports 0 from
    /// registration, so `talos_actor_memory_orphaned_rows == 0` covers BOTH
    /// "measured, and there are no orphans" and "the `SELECT COUNT(*)` errored
    /// and nothing was ever measured". Those two readings are the same number,
    /// and one of them means the only automated notice that at-rest ciphertext
    /// has become unrecoverable is switched off.
    ///
    /// **Deliberately NOT folded into the orphan counts.** Publishing a
    /// sentinel (`-1`, or a synthetic large value) on failure would make the
    /// counts untrustworthy to every other consumer — `get_health_dashboard`,
    /// the runbook's psql cross-check, and the `{{ $value }}` in the alert
    /// summary all read them as row counts. The blind signal is a separate
    /// series; the counts keep their meaning and simply stop advancing.
    ///
    /// **Why a freshness timestamp rather than a `blind`/`failed` counter.**
    /// A `blind == 0` gauge is itself an unmeasured zero: if the sweep task
    /// never spawns, panics, or is removed in a refactor, nothing sets it and
    /// it reads "not blind" forever — the same defect one level up, which is
    /// the failure mode this whole change exists to remove. A timestamp that
    /// only ever advances on a fully successful sweep degrades the right way
    /// in all four cases: query error, task death, task never spawned, and
    /// controller build predating the sweep (0 from registration, which reads
    /// as maximally stale). The form is the same one
    /// `talos_backup_drill_last_success_timestamp_seconds` already uses.
    ///
    /// **PARTIAL failure counts as blind, on purpose.** Only a sweep in which
    /// all three probes returned advances this. One broken probe leaves two
    /// trustworthy gauges and still raises the alert; for a data-loss detector
    /// that is the right side to err on, and the WARN log
    /// (`target: "talos_crypto"`) names which table failed.
    ///
    /// `TalosCryptoOrphanDetectorBlind` is the alert that consumes it.
    pub crypto_orphan_scan_last_success_timestamp_seconds: Gauge,
    pub dek_cache_size: IntGauge,
    /// Total connections currently held by the controller's sqlx
    /// Postgres pool (idle + in-use). Sampled periodically by a
    /// controller sweep task. Bounded above by `DB_MAX_CONNECTIONS`.
    pub db_pool_connections: IntGauge,
    /// Connections in the pool that are idle (available to hand out).
    pub db_pool_idle_connections: IntGauge,
    /// Connections currently checked out and in use
    /// (`connections - idle`). When this sits at `DB_MAX_CONNECTIONS`,
    /// new acquisitions block on the 10 s acquire timeout — the pool is
    /// saturated and request latency climbs across the whole process.
    pub db_pool_in_use_connections: IntGauge,
    /// The configured max pool size (`DB_MAX_CONNECTIONS`), exported as
    /// a gauge so alerts can compute a saturation RATIO
    /// (`in_use / max`) without hardcoding the limit in PromQL.
    pub db_pool_max_connections: IntGauge,
}

impl TalosMetrics {
    /// Create and register all metrics
    pub fn new() -> anyhow::Result<Arc<Self>> {
        let registry = Registry::new();

        // Webhook metrics
        let webhook_requests_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_webhook_requests_total",
                "Total number of webhook requests received",
            ),
            &["trigger_id", "status"],
        )?;
        registry.register(Box::new(webhook_requests_total.clone()))?;

        let webhook_request_duration_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "talos_webhook_request_duration_seconds",
                "Webhook request duration in seconds",
            )
            .buckets(exponential_buckets(0.001, 2.0, 15).expect("valid exponential buckets")),
            &["trigger_id"],
        )?;
        registry.register(Box::new(webhook_request_duration_seconds.clone()))?;

        let webhook_dlq_drops_total = Counter::new(
            "talos_webhook_dlq_drops_total",
            "Total number of webhook requests dropped to DLQ",
        )?;
        registry.register(Box::new(webhook_dlq_drops_total.clone()))?;

        // Authentication metrics
        let auth_attempts_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_auth_attempts_total",
                "Total number of authentication attempts",
            ),
            // Emitted values: password | oauth. See the struct-field comment
            // for why api_key is deliberately not in this population.
            &["method"],
        )?;
        registry.register(Box::new(auth_attempts_total.clone()))?;
        // Pre-seed the two `method` values that are actually emitted
        // (`talos_auth::AUTH_METHOD_PASSWORD` / `_OAUTH`), so a controller
        // that has served no interactive login still EXPORTS the series at 0
        // instead of omitting it. A `CounterVec` emits nothing at all until a
        // label set is first touched, which makes "detector present and
        // quiet" indistinguishable from "detector deleted" on a healthy
        // stack — the exact ambiguity that let five alerted CounterVecs here
        // sit unexercised. `api_key` is deliberately NOT seeded: it is not in
        // this population (see the talos-auth header for why folding it in
        // would make TalosControllerHighErrorRate unfireable in practice).
        //
        // Note precisely what this proves and what it does not: a present
        // denominator shows the auth counters were registered in THIS
        // process. It does not show the failure leg is still wired — that is
        // what the talos-auth unit tests driving the production login path
        // are for.
        for method in ["password", "oauth"] {
            auth_attempts_total.with_label_values(&[method]).inc_by(0.0);
        }

        let auth_failures_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_auth_failures_total",
                "Total number of authentication failures",
            ),
            // Emitted reasons are a closed literal set owned by the emitting
            // crate — see the `AUTH_REASON_*` constants in `talos-auth`.
            // Never a username, IP, or key id: this endpoint is scrapeable
            // and the label set must stay bounded.
            &["method", "reason"],
        )?;
        registry.register(Box::new(auth_failures_total.clone()))?;
        // DELIBERATELY NOT PRE-SEEDED, unlike its denominator above. The
        // `reason` values are a closed set of `&'static str` constants, but
        // the (method, reason) PRODUCT is not a valid population: only 9 of
        // the 16 pairs have an emitting call site (`unknown_user`, `locked`,
        // `lockout_triggered`, `invalid_password` are password-only;
        // `provider_error`, `csrf_state`, `link_failed` are oauth-only), and
        // seeding a pair nothing writes would imply a wired signal that does
        // not exist. Encoding the real pairing here would also mean copying
        // talos-auth's constants across a dependency edge that only points
        // the other way (talos-auth depends on this crate), so the two could
        // drift silently. Absence of a failure series is the correct
        // non-alerting answer anyway — see the TalosControllerHighErrorRate
        // comment in deploy/helm/talos/files/alerts.yaml.

        let auth_2fa_attempts_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_auth_2fa_attempts_total",
                "Total number of 2FA verification attempts",
            ),
            &["status"], // success, failure
        )?;
        registry.register(Box::new(auth_2fa_attempts_total.clone()))?;

        let api_key_validations_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_api_key_validations_total",
                "Total number of API key validations",
            ),
            &["status"], // valid, invalid, expired, rate_limited
        )?;
        registry.register(Box::new(api_key_validations_total.clone()))?;

        // Execution metrics
        let module_executions_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_module_executions_total",
                "Total number of module executions",
            ),
            &["status", "trigger_type"], // success, failure, timeout
        )?;
        registry.register(Box::new(module_executions_total.clone()))?;

        let module_execution_duration_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "talos_module_execution_duration_seconds",
                "Module execution duration in seconds",
            )
            .buckets(exponential_buckets(0.01, 2.0, 15).expect("valid exponential buckets")),
            &["status"],
        )?;
        registry.register(Box::new(module_execution_duration_seconds.clone()))?;

        let workflow_executions_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_workflow_executions_total",
                "Total number of workflow executions",
            ),
            &["status"], // success, failure, timeout, cancelled
        )?;
        registry.register(Box::new(workflow_executions_total.clone()))?;
        // Pre-seed the two terminal outcomes the finalizers write (success /
        // failure) at 0 — same reasoning as crash_recovery_total below: the
        // series must exist in steady state so `rate()` in the
        // TalosWorkflowFailureRateHigh alert (deploy/helm files/alerts.yaml)
        // has something to reference before the first failure. `timeout` /
        // `cancelled` are deliberately NOT seeded: nothing increments them yet
        // (the scheduler writes those states via a raw UPDATE), so seeding
        // them would imply a wired signal that doesn't exist.
        for outcome in ["success", "failure"] {
            workflow_executions_total
                .with_label_values(&[outcome])
                .inc_by(0.0);
        }

        let workflow_execution_duration_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "talos_workflow_execution_duration_seconds",
                "Workflow execution duration in seconds",
            )
            .buckets(exponential_buckets(0.1, 2.0, 15).expect("valid exponential buckets")),
            &["status"],
        )?;
        registry.register(Box::new(workflow_execution_duration_seconds.clone()))?;

        let crash_recovery_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_crash_recovery_total",
                "Total crash-recovery resume outcomes since process start",
            ),
            &["outcome"], // resumed, failed, reclaimed
        )?;
        registry.register(Box::new(crash_recovery_total.clone()))?;
        // Pre-seed the outcome series to 0. Unlike the high-frequency execution
        // counters above, crash-recovery only fires on a restart-with-orphans,
        // so without seeding these series would be absent in steady state and
        // `rate()` / absence alerts + dashboard panels would have nothing to
        // reference. A counter seeded at 0 is correct and always present.
        for outcome in ["resumed", "failed", "reclaimed"] {
            crash_recovery_total
                .with_label_values(&[outcome])
                .inc_by(0.0);
        }

        // ---- Detector metrics (2026-08) ----
        let wasm_log_orphaned_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_wasm_log_orphaned_total",
                "WASM log lines discarded because they could not be routed to \
                 any execution row. Labels: kind=no_execution_row|unparseable_id. \
                 Non-zero means a dispatch path is minting execution ids without \
                 recording a row — those executions' logs are lost.",
            ),
            &["kind"],
        )?;
        registry.register(Box::new(wasm_log_orphaned_total.clone()))?;
        // Pre-seed both kinds at 0, same reasoning as crash_recovery_total: the
        // expected steady state is zero, so without seeding the series would be
        // ABSENT and `increase(...[15m]) > 0` would have nothing to reference
        // until the first incident. Seeding at 0 also lets a dashboard show
        // "detector present and quiet" rather than "detector missing".
        for kind in ["no_execution_row", "unparseable_id"] {
            wasm_log_orphaned_total
                .with_label_values(&[kind])
                .inc_by(0.0);
        }

        let module_execution_record_started_failures_total = Counter::new(
            "talos_module_execution_record_started_failures_total",
            "Failures writing the module_executions start row at the \
             PostgresModuleExecutionStore::record_started chokepoint. Non-fatal \
             by design, so the execution proceeds — but its row is missing, its \
             WASM logs orphan, and get_execution_logs / get_node_io / cost \
             attribution silently under-report.",
        )?;
        registry.register(Box::new(
            module_execution_record_started_failures_total.clone(),
        ))?;

        let module_executions_swept_stuck_total = Counter::new(
            "talos_module_executions_swept_stuck_total",
            "module_executions rows the stuck-execution sweep converted to \
             'timeout' because nothing ever finalized them. Sustained non-zero \
             means rows are opened and never closed — a broken ledger, not a \
             broken fleet. Registration alone exports it at 0, so an alert on \
             it cannot be silenced by the series being absent.",
        )?;
        registry.register(Box::new(module_executions_swept_stuck_total.clone()))?;

        let job_results_dropped_unparseable_total = Counter::new(
            "talos_job_results_dropped_unparseable_total",
            "Job results discarded by the talos.results.* subscriber because \
             the payload would not deserialize into a JobResult. That \
             subscriber is the only finalizer for the fire-and-forget \
             module-bound dispatch paths, so each drop loses a terminal \
             module_executions status write, its output_data, and its \
             __ops_alert__ ingest. Registration alone exports it at 0, so an \
             alert on it cannot be silenced by the series being absent.",
        )?;
        registry.register(Box::new(job_results_dropped_unparseable_total.clone()))?;

        let audit_verification_failures_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_audit_verification_failures_total",
                "WORM audit-ledger verification failures. Labels: \
                 stage=event|chain. stage=event is the inline per-message check \
                 at ingest (message quarantined, not persisted); stage=chain is \
                 the offline hash-chain sweep over a completed execution. Either \
                 is positive tamper/corruption evidence.",
            ),
            &["stage"],
        )?;
        registry.register(Box::new(audit_verification_failures_total.clone()))?;
        // Seeded for the same reason as the orphan counter above — the CRITICAL
        // alert on this series must have something to reference in steady state.
        for stage in ["event", "chain"] {
            audit_verification_failures_total
                .with_label_values(&[stage])
                .inc_by(0.0);
        }

        let worker_key_tofu_conflicts_total = Counter::new(
            "talos_worker_key_tofu_conflicts_total",
            "Worker self-registration refusals where the presented key is not \
             the worker_id's bound trust-on-first-use identity. Possible \
             in-fleet impersonation; legitimate rotation goes through the \
             operator CLI or a worker_id-bound provisioning token.",
        )?;
        registry.register(Box::new(worker_key_tofu_conflicts_total.clone()))?;

        let worker_build_skew_workers = IntGauge::new(
            "talos_worker_build_skew_workers",
            "Distinct worker_ids with an ACTIVE worker_identities row whose \
             build PROVABLY differs from this controller's (different commit \
             sha, or -dirty on one side only). Recomputed each sweep, so it \
             falls back to 0 once the fleet converges OR the stale rows are \
             deactivated — ACTIVE means 'row not deactivated', not 'process \
             running'. A departed pod's row is reaped only if the identity \
             reaper is enabled (OFF by default), and a row that never sent a \
             liveness ping needs its second, separately-gated arm; otherwise \
             it must be deactivated by an operator. Workers \
             that report no usable sha are 'unverifiable' and are NOT counted.",
        )?;
        registry.register(Box::new(worker_build_skew_workers.clone()))?;

        let catalog_templates_missing_wasm = IntGauge::new(
            "talos_catalog_templates_missing_wasm",
            "Catalog templates whose wasm_bytes is NULL/empty AND which carry no \
             oci_url — they have neither local bytes nor a registry reference and \
             cannot run at all. Published at boot after that boot's background \
             compiles settle, then re-measured every 300s, so it falls back to 0 \
             once the templates build and rises again if a row loses its bytes \
             mid-life. HOLDS its last value if the query fails rather than \
             zeroing; talos_catalog_missing_wasm_scan_last_success_timestamp_seconds \
             is how a held value is told from a measured one. Names are in \
             get_catalog_status → never_compiled (deliberately not a label: \
             template names are registry-supplied in OCI mode).",
        )?;
        registry.register(Box::new(catalog_templates_missing_wasm.clone()))?;

        let catalog_missing_wasm_scan_last_success_timestamp_seconds = Gauge::new(
            "talos_catalog_missing_wasm_scan_last_success_timestamp_seconds",
            "Unix time of the last sweep that successfully measured \
             talos_catalog_templates_missing_wasm. Not seeded and not reset: it \
             reads 0 until the first successful measurement, which is maximally \
             stale, so a controller that never ran the sweep is loud rather than \
             silent. The missing-wasm gauge reads 0 both when every template can \
             run and when the query never returned; this is how those cases are \
             told apart. TalosCatalogMissingWasmDetectorBlind alerts on it.",
        )?;
        registry.register(Box::new(
            catalog_missing_wasm_scan_last_success_timestamp_seconds.clone(),
        ))?;

        // ---- Worker-identity liveness + reaper ----
        let worker_liveness_pings_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_worker_liveness_pings_total",
                "Proof-of-possession liveness pings received at \
                 POST /internal/worker-liveness. Labels: outcome=accepted|\
                 rejected_request|rejected_proof|inactive_identity|error, \
                 derived from the response status so the counter can never \
                 distinguish more than the endpoint's own reply. Never \
                 labelled by worker_id or key — the endpoint is \
                 unauthenticated and a caller-derived label is unbounded \
                 cardinality.",
            ),
            &["outcome"],
        )?;
        registry.register(Box::new(worker_liveness_pings_total.clone()))?;
        // Seed ALL FIVE: every value has a live emitting site, because the
        // label is derived from the status and each status class is reachable
        // (`liveness_outcome_label` maps 2xx/400/401/404/5xx). Seeding matters
        // more here than for most detectors: the steady state of the two
        // failure-shaped values is 0, and at the enablement runbook's step 0
        // (does the instrumentation exist at all) and step 4 (THE GATE) an
        // operator reads these series to decide whether the fleet is pinging
        // at all. An ABSENT series and a 0 one answer that question
        // differently, and absent is the answer that gets a fleet reaped.
        for outcome in [
            "accepted",
            "rejected_request",
            "rejected_proof",
            "inactive_identity",
            "error",
        ] {
            worker_liveness_pings_total
                .with_label_values(&[outcome])
                .inc_by(0.0);
        }

        let worker_identity_reaps_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_worker_identity_reaps_total",
                "Worker signing keys deactivated by the worker-identity \
                 reaper. Labels: arm=departed|pre_protocol. `departed` is the \
                 automatic arm (liveness silence past \
                 TALOS_WORKER_IDENTITY_REAP_HOURS); `pre_protocol` is the \
                 opt-in arm for rows that never participated. A reaped key \
                 cannot re-register itself — every count here needs an \
                 operator if the worker is still alive.",
            ),
            &["arm"],
        )?;
        registry.register(Box::new(worker_identity_reaps_total.clone()))?;
        // Both arms seeded: both have a live emitting site in the reaper
        // sweep. `pre_protocol` only ever moves when an operator sets its env
        // var, but the code path exists unconditionally — same case as
        // crash_recovery_total's `reclaimed`. The expected steady state of
        // BOTH is 0 forever, which is precisely why they must be present
        // rather than absent: `increase(...) > 0` over an absent series
        // matches nothing, so an un-seeded counter would leave the reap alert
        // unfireable until the first reap it was supposed to warn about.
        for arm in ["departed", "pre_protocol"] {
            worker_identity_reaps_total
                .with_label_values(&[arm])
                .inc_by(0.0);
        }

        let oauth_reactive_refresh_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_oauth_reactive_refresh_total",
                "Reactive OAuth credential repairs attempted after a job \
                 failed with an authentication error on a Talos-held OAuth \
                 credential. Labels: \
                 outcome=repaired|not_refreshed|refresh_failed. \
                 `refresh_failed` is the arm that needs a human — the token \
                 endpoint refused, which for Google/Atlassian means the grant \
                 is revoked or expired and the integration must be \
                 re-consented.",
            ),
            &["outcome"],
        )?;
        registry.register(Box::new(oauth_reactive_refresh_total.clone()))?;
        // Seed all three: the healthy steady state is that NONE of them ever
        // moves, so without seeding the whole family is absent and
        // `increase(...) > 0` — the shape the re-auth alert uses — matches
        // nothing. Every one of the three has a live emitting site in
        // `OAuthCredentialService::force_refresh_oauth_tokens_in_batch`.
        for outcome in ["repaired", "not_refreshed", "refresh_failed"] {
            oauth_reactive_refresh_total
                .with_label_values(&[outcome])
                .inc_by(0.0);
        }

        let worker_liveness_participants = IntGauge::new(
            "talos_worker_liveness_participants",
            "Distinct worker_ids with an ACTIVE worker_identities row that \
             have proved liveness at least once — the automatic reaper's \
             population. Recomputed each sweep. Rows that never pinged \
             (last_liveness_at IS NULL) are NOT counted: the automatic reaper \
             cannot act on them.",
        )?;
        registry.register(Box::new(worker_liveness_participants.clone()))?;

        let worker_liveness_recent_participants = IntGauge::new(
            "talos_worker_liveness_recent_participants",
            "The subset of talos_worker_liveness_participants whose last \
             liveness proof is inside the participation horizon (2h, or the \
             configured trust window if shorter) — i.e. still actively \
             pinging. participants MINUS this is the number of trusted keys \
             that have stopped proving liveness and are heading for a reap.",
        )?;
        registry.register(Box::new(worker_liveness_recent_participants.clone()))?;

        let worker_liveness_population_truncated = IntGauge::new(
            "talos_worker_liveness_population_truncated",
            "1 when the ACTIVE worker_identities population exceeds the bound \
             on the query the participation gauges are computed from \
             (MAX_FLEET_BUILD_ROWS = 200), i.e. the liveness detector can no \
             longer see every row the reaper could act on. The reaper REFUSES \
             to sweep while this is 1, so nothing is deactivated blind. Drain \
             ghost rows with deactivate-worker-identity to clear it.",
        )?;
        registry.register(Box::new(worker_liveness_population_truncated.clone()))?;

        // ---- NATS fleet heartbeat ----
        let worker_fleet_live_workers = IntGauge::new(
            "talos_worker_fleet_live_workers",
            "Distinct worker_ids that published a NATS fleet heartbeat within \
             the staleness window. Recomputed each sweep. WHETHER IT IS A \
             REPLICA COUNT DEPENDS ON THE POSTURE: with distinct ids (the \
             chart DEFAULT — nothing renders TALOS_WORKER_ID, so the worker \
             falls back to HOSTNAME/pod name) it IS one, and checking it \
             against your replica count is valid; where every replica shares \
             one TALOS_WORKER_ID (the dev compose stack, and the commented-out \
             RFC-0010 single-key block once enabled) a fleet of any size \
             reports 1. 0 is AMBIGUOUS in both — it \
             covers an empty fleet, a fleet on a build too old to publish \
             heartbeats, and a broken subscription alike, so it is not \
             evidence that workers are absent. Heartbeats are HMAC-signed \
             under the FLEET-SHARED key, so this is a liveness hint for \
             observability and never a trust signal.",
        )?;
        registry.register(Box::new(worker_fleet_live_workers.clone()))?;

        let worker_fleet_live_builds = IntGauge::new(
            "talos_worker_fleet_live_builds",
            "DISTINCT builds observed in NATS fleet heartbeats within the \
             staleness window. THE DENOMINATOR for the two gauges below, which \
             are computed over this same population — read it beside them, NOT \
             talos_worker_fleet_live_workers, which counts heartbeating \
             IDENTITIES and is a different population. A healthy fleet reads \
             1; a fleet mid-roll reads 2 steadily. 0 is AMBIGUOUS in the same \
             way as live_workers: nothing observed is not nothing running.",
        )?;
        registry.register(Box::new(worker_fleet_live_builds.clone()))?;

        let worker_fleet_build_skew_builds = IntGauge::new(
            "talos_worker_fleet_build_skew_builds",
            "DISTINCT observed builds that PROVABLY differ from this \
             controller's, over the denominator talos_worker_fleet_live_builds. \
             THE ALERTABLE ONE, because it is steady in every posture. COUNTS \
             BUILDS, NOT PROCESSES: five workers stuck on one old build report \
             1, not 5 — for the magnitude read \
             talos_worker_fleet_build_skew_workers (meaningful under distinct \
             worker_ids, which is the chart default) or get_platform_info.fleet \
             for per-worker detail. The alert is here rather than on that gauge \
             because where replicas share one worker_id the fleet map is \
             last-write-wins, so a per-worker count alternates on a MIXED-build \
             fleet and no for: duration can elapse (a uniformly skewed shared-id \
             fleet was always steady). Still the live-process twin of \
             talos_worker_build_skew_workers, which counts REGISTERED ROWS; \
             neither subsumes the other.",
        )?;
        registry.register(Box::new(worker_fleet_build_skew_builds.clone()))?;

        let worker_fleet_unverifiable_builds = IntGauge::new(
            "talos_worker_fleet_unverifiable_builds",
            "DISTINCT observed builds that cannot be compared with the \
             controller's. Covers a worker reporting no usable commit sha AND \
             — for every observed build at once — the case where the \
             CONTROLLER's own build has no usable sha, since nothing can be \
             compared then. Exported so a 0 on \
             talos_worker_fleet_build_skew_builds is readable: 0 skewed out \
             of 0 comparable builds is not 'the fleet agrees'.",
        )?;
        registry.register(Box::new(worker_fleet_unverifiable_builds.clone()))?;

        let worker_fleet_build_skew_workers = IntGauge::new(
            "talos_worker_fleet_build_skew_workers",
            "Heartbeating worker_ids whose reported build PROVABLY differs \
             from this controller's, over the denominator \
             talos_worker_fleet_live_workers. INFORMATIONAL MAGNITUDE — do NOT \
             build an alert on it. Under distinct worker_ids (the chart \
             DEFAULT: nothing renders TALOS_WORKER_ID, so each pod is its own \
             id) it is steady and answers 'how many running pods are on the \
             wrong build'. Where replicas share one worker_id the fleet map \
             holds a single entry, so it is 0 or 1 at any fleet size and \
             ALTERNATES while the fleet is mid-roll — which is why the alert \
             is on talos_worker_fleet_build_skew_builds, whose population is \
             steady in both postures.",
        )?;
        registry.register(Box::new(worker_fleet_build_skew_workers.clone()))?;

        let worker_fleet_unverifiable_workers = IntGauge::new(
            "talos_worker_fleet_unverifiable_workers",
            "Heartbeating worker_ids whose build cannot be compared with the \
             controller's — same two causes as \
             talos_worker_fleet_unverifiable_builds (the worker reported no \
             usable sha, or THIS CONTROLLER has none, in which case every \
             identity lands here at once). Published so \
             talos_worker_fleet_build_skew_workers has its decomposition \
             beside it: live_workers == build_skew_workers + \
             unverifiable_workers + agreeing. Same posture caveat as that \
             gauge.",
        )?;
        registry.register(Box::new(worker_fleet_unverifiable_workers.clone()))?;

        let worker_fleet_capacity_dropped_heartbeats = IntGauge::new(
            "talos_worker_fleet_capacity_dropped_heartbeats",
            "Heartbeats refused because the controller's fleet view was at its \
             hard cap (MAX_TRACKED_WORKERS). Cumulative within a controller \
             process; resets on restart. Non-zero means the bound held but \
             something is publishing under more distinct worker ids than the \
             fleet has. IT ALSO SUPPRESSES THE SKEW DETECTOR: a heartbeat \
             refused here never reaches the build map, so a straggling worker \
             that boots during a flood is invisible to \
             talos_worker_fleet_build_skew_builds too. Counter semantics on a \
             gauge type: alert on the level, never on rate().",
        )?;
        registry.register(Box::new(worker_fleet_capacity_dropped_heartbeats.clone()))?;

        let worker_fleet_capacity_dropped_builds = IntGauge::new(
            "talos_worker_fleet_capacity_dropped_builds",
            "Build observations refused because the controller's BUILD view \
             was at its hard cap (MAX_TRACKED_BUILDS). Cumulative within a \
             controller process; resets on restart. Saturates on a shape the \
             worker cap cannot see — one worker_id publishing many distinct \
             build strings. THE SUPPRESSION DIRECTION MATTERS MOST: at the \
             cap a NEW key is refused, and builds_match compares only the \
             +sha suffix, so a shared-key holder can fill the map with 64 \
             agreeing-but-distinct builds after which a genuinely straggling \
             worker's build is refused and talos_worker_fleet_build_skew_builds \
             reads 0 while looking healthy. Inflation by fabricated builds is \
             the milder, louder direction. Only a holder of the fleet-shared \
             key can do either, and the cap is what bounds how much. Counter \
             semantics on a gauge type: alert on the level, never on rate().",
        )?;
        registry.register(Box::new(worker_fleet_capacity_dropped_builds.clone()))?;

        // Seed all eight at 0. A gauge that has never been `set` is ABSENT, not
        // zero, and every common PromQL idiom reads absent as "no match" — so
        // an alert on a fleet that has never heartbeated could not fire on the
        // cold-dead case, which is the one that matters (#625). These are
        // closed, label-free series with live `set` sites in
        // `controller::bootstrap::background::publish_worker_fleet_gauges`, so
        // seeding them asserts nothing that is not wired.
        worker_fleet_live_workers.set(0);
        worker_fleet_live_builds.set(0);
        worker_fleet_build_skew_builds.set(0);
        worker_fleet_unverifiable_builds.set(0);
        worker_fleet_build_skew_workers.set(0);
        worker_fleet_unverifiable_workers.set(0);
        worker_fleet_capacity_dropped_heartbeats.set(0);
        worker_fleet_capacity_dropped_builds.set(0);

        // ---- Fuel-headroom detector ----
        let fuel_high_utilisation_nodes = IntGauge::new(
            "talos_fuel_high_utilisation_nodes",
            "(workflow, node) pairs whose PEAK observed fuel_consumed is at or \
             above the detector threshold (default 80%) of the ceiling a worker \
             most recently ENFORCED for them. Recomputed each sweep from \
             execution_cost_rollup. NO SAMPLE FLOOR — it fires at n=1, which is \
             the point: the node it was built for sat at 96.9% on two samples, \
             below every percentile-and-floor surface the platform had. Test \
             executions are excluded. Names are in the controller WARN log and \
             get_fuel_usage_report.high_utilisation_nodes, deliberately not \
             labels (node labels are author-supplied and unbounded).",
        )?;
        registry.register(Box::new(fuel_high_utilisation_nodes.clone()))?;

        let fuel_utilisation_observed_nodes = IntGauge::new(
            "talos_fuel_utilisation_observed_nodes",
            "The DENOMINATOR of talos_fuel_high_utilisation_nodes: every \
             (workflow, node) pair the detector could evaluate in the window. \
             Exported so a 0 on the numerator is readable — 0 of 77 examined is \
             a healthy fleet, 0 of 0 is a detector that measured nothing, and an \
             IntGauge reads 0 in both cases. TalosFuelHeadroomDetectorBlind \
             alerts on the second.",
        )?;
        registry.register(Box::new(fuel_utilisation_observed_nodes.clone()))?;

        // Seed the pair at 0. Same rule as the fleet gauges above: a gauge that
        // has never been `set` is ABSENT, and `absent >= 1` matches nothing —
        // so before the first sweep the detector would be silent for the reason
        // it exists to make loud. Both have live `set` sites in
        // `controller::bootstrap::background::publish_fuel_utilisation`.
        fuel_high_utilisation_nodes.set(0);
        fuel_utilisation_observed_nodes.set(0);

        // ---- Scheduler startup-herd detection ----
        let scheduler_dispatches_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_scheduler_dispatches_total",
                "Terminal outcomes of scheduler-driven workflow dispatches. \
                 Labels: phase=startup|steady (startup = the backlog found \
                 due by the first poll after a controller boot), \
                 outcome=completed|failed|skipped|denied|fenced. skipped = \
                 refused for CAPACITY (concurrency cap or actor budget), \
                 which for a daily cron means the run is lost until tomorrow; \
                 denied = refused by POLICY (actor not runnable, capability \
                 ceiling); fenced = superseded by a crash-recovery reclaim. \
                 The five outcomes PARTITION every dispatch attempt, so the \
                 total reconciles against the boot backlog size. Ten closed \
                 series; never labelled by workflow, schedule or user — \
                 unbounded cardinality.",
            ),
            &["phase", "outcome"],
        )?;
        registry.register(Box::new(scheduler_dispatches_total.clone()))?;
        // Seed all ten. The healthy steady state of every startup-phase
        // series is 0 forever, which is exactly the case where absent and
        // zero diverge: the herd alert is built on `increase(...)` — a
        // threshold arm and a ratio arm — and an absent counter matches
        // nothing, so the detector would be silenced by precisely the
        // condition it exists to catch (#625). The ratio arm needs the
        // seeding twice over: an absent denominator term does not make the
        // ratio absent, it makes it WRONG. Every (phase,
        // outcome) pair is reachable from a live site in
        // `talos_scheduler::SchedulerService`, so seeding asserts nothing
        // that is not wired.
        for phase in SCHEDULER_DISPATCH_PHASES {
            for outcome in SCHEDULER_DISPATCH_OUTCOMES {
                scheduler_dispatches_total
                    .with_label_values(&[phase, outcome])
                    .inc_by(0.0);
            }
        }

        let scheduler_readiness_holds_total = Counter::new(
            "talos_scheduler_readiness_holds_total",
            "Scheduler poll iterations held because the controller's NATS \
             fleet heartbeat view contained no live worker. A hold advances \
             no schedule state, so nothing is lost — the same schedules are \
             still due on the next tick. Non-zero at boot is normal (a \
             worker that booted first loses its unretained first heartbeat); \
             sustained growth means the fleet is genuinely absent.",
        )?;
        registry.register(Box::new(scheduler_readiness_holds_total.clone()))?;
        // Same reasoning as above: on a healthy single-node stack this is 0
        // forever, and an absent counter cannot be distinguished from a
        // scheduler that never started.
        scheduler_readiness_holds_total.inc_by(0.0);

        let scheduler_readiness_degraded = IntGauge::new(
            "talos_scheduler_readiness_degraded",
            "1 when the scheduler has given up waiting for the worker fleet to \
             become visible and is dispatching without that evidence. An empty \
             fleet view is ambiguous (empty fleet / old build / broken \
             subscription / heartbeats deliberately disabled), so the barrier \
             degrades after a bounded number of holds instead of stopping all \
             scheduled work forever on a signal it cannot fully trust.",
        )?;
        registry.register(Box::new(scheduler_readiness_degraded.clone()))?;
        // 0 is the healthy value AND the value this sits at forever on a
        // working fleet, so it must be exported rather than absent — an alert
        // on `== 1` over an absent series can never fire.
        scheduler_readiness_degraded.set(0);

        // Rate limiting metrics
        let rate_limit_hits_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_rate_limit_hits_total",
                "Total number of rate limit hits",
            ),
            &["type"], // ip, api_key, webhook
        )?;
        registry.register(Box::new(rate_limit_hits_total.clone()))?;

        // Cache metrics
        let cache_hits_total = CounterVec::new(
            prometheus::Opts::new("talos_cache_hits_total", "Total number of cache hits"),
            &["cache_type"], // wasm, secret, dek
        )?;
        registry.register(Box::new(cache_hits_total.clone()))?;

        let cache_misses_total = CounterVec::new(
            prometheus::Opts::new("talos_cache_misses_total", "Total number of cache misses"),
            &["cache_type"],
        )?;
        registry.register(Box::new(cache_misses_total.clone()))?;

        // (circuit-breaker metrics moved to talos-worker-runtime — see the
        // note on the struct definition above.)

        // DLQ metrics
        let dlq_entries_total = Counter::new(
            "talos_dlq_entries_total",
            "Total number of DLQ entries created",
        )?;
        registry.register(Box::new(dlq_entries_total.clone()))?;

        let dlq_drops_total = Counter::new(
            "talos_dlq_drops_total",
            "Total number of DLQ entries dropped (channel full)",
        )?;
        registry.register(Box::new(dlq_drops_total.clone()))?;

        let dlq_db_errors_total = Counter::new(
            "talos_dlq_db_errors_total",
            "Total number of DLQ database write errors",
        )?;
        registry.register(Box::new(dlq_db_errors_total.clone()))?;

        // ---- Crypto-invariant metrics ----
        let kek_decrypt_failures_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_kek_decrypt_failures_total",
                "DEK unwrap failures. Labels: provider=active|legacy|both. \
                 Any bump here means encrypted-at-rest data is currently \
                 unreadable — page operator immediately.",
            ),
            &["provider"],
        )?;
        registry.register(Box::new(kek_decrypt_failures_total.clone()))?;
        // Seed only the two `provider` values with a live emitting site:
        // `active` and `both`, both in `SecretsManager::decrypt_dek`. The
        // description's third value, `legacy`, has NO emitter anywhere in the
        // workspace — a total legacy-provider failure is reported as `both`.
        // Seeding `legacy` would put a permanent flat 0 on a dashboard for a
        // condition nothing can ever report, which reads as "watched and
        // healthy" rather than "not watched".
        for provider in ["active", "both"] {
            kek_decrypt_failures_total
                .with_label_values(&[provider])
                .inc_by(0.0);
        }

        let memory_write_failures_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_memory_write_failures_total",
                "actor_memory persistence failures from the __memory_write__ \
                 hook. Labels: reason=crypto|db|validation. Sustained bump \
                 means node outputs are being lost to disk.",
            ),
            &["reason"],
        )?;
        registry.register(Box::new(memory_write_failures_total.clone()))?;
        // Closed set, and every value has a live emitter: the label comes
        // from `MemoryWriteError::metric_label()`, whose four variants are
        // exhaustively matched at the two `__memory_write__` hook sites in
        // talos-engine. Note the description above lists only three — the
        // catch-all `other` was added to the type without updating it; the
        // seed follows the CODE, which is what actually emits.
        for reason in ["crypto", "db", "validation", "other"] {
            memory_write_failures_total
                .with_label_values(&[reason])
                .inc_by(0.0);
        }

        let ops_alert_ingest_failures_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_ops_alert_ingest_failures_total",
                "ops_alerts persistence failures from the __ops_alert__ \
                 hook. Labels: reason=validation|db|tenancy. Sustained bump \
                 means parser-module alert envelopes are being lost.",
            ),
            &["reason"],
        )?;
        registry.register(Box::new(ops_alert_ingest_failures_total.clone()))?;

        let ops_alert_auto_resolved_total = Counter::new(
            "talos_ops_alert_auto_resolved_total",
            "ops_alerts rows resolved by a status_event: 'resolved' signal \
             from the ingest pipeline (source-reported recovery, e.g. a \
             Cloud Monitoring incident closing).",
        )?;
        registry.register(Box::new(ops_alert_auto_resolved_total.clone()))?;

        let module_payload_encryption_failures_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_module_payload_encryption_failures_total",
                "module_executions payload encrypt/decrypt failures. \
                 Labels: op=encrypt|decrypt, stage=input|output|trigger_metadata.",
            ),
            &["op", "stage"],
        )?;
        registry.register(Box::new(module_payload_encryption_failures_total.clone()))?;
        // All six combinations are reachable, so all six are seeded:
        // `encrypt_payload_bundle` loops over all three `PayloadSlot`s and
        // `decrypt_payload_slot` is called for each of them, and both wrap
        // their failures through `inc_payload_crypto_failure`. Cardinality is
        // fixed at 6 by construction (both labels are `&'static str` from
        // closed sets) — the same bound that crate's own doc comment states.
        for op in ["encrypt", "decrypt"] {
            for stage in ["input", "output", "trigger_metadata"] {
                module_payload_encryption_failures_total
                    .with_label_values(&[op, stage])
                    .inc_by(0.0);
            }
        }

        let secret_decrypt_failures_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_secret_decrypt_failures_total",
                "Per-row secret decrypt failures inside get_module_secrets. \
                 Labels: reason=missing_dek|cipher_init|aead|invalid_utf8|too_short.",
            ),
            &["reason"],
        )?;
        registry.register(Box::new(secret_decrypt_failures_total.clone()))?;

        let actor_memory_orphaned_rows = IntGauge::new(
            "talos_actor_memory_orphaned_rows",
            "Rows in actor_memory whose value_key_id points at a DEK that \
             no longer exists in encryption_keys. Should be 0. Non-zero = \
             data loss already occurred, investigate immediately.",
        )?;
        registry.register(Box::new(actor_memory_orphaned_rows.clone()))?;

        let module_execution_orphaned_rows = IntGauge::new(
            "talos_module_execution_orphaned_rows",
            "Rows in module_executions whose payload_enc_key_id points at a \
             missing DEK. Should be 0.",
        )?;
        registry.register(Box::new(module_execution_orphaned_rows.clone()))?;

        let workflow_execution_orphaned_rows = IntGauge::new(
            "talos_workflow_execution_orphaned_rows",
            "Rows in workflow_executions whose output_enc_key_id points at a \
             missing DEK. Should be 0.",
        )?;
        registry.register(Box::new(workflow_execution_orphaned_rows.clone()))?;

        let crypto_orphan_scan_last_success_timestamp_seconds = Gauge::new(
            "talos_crypto_orphan_scan_last_success_timestamp_seconds",
            "Unix time of the last crypto-orphan sweep in which ALL THREE \
             talos_*_orphaned_rows gauges were measured. Not seeded and not \
             reset: it reads 0 until the first fully successful sweep, which \
             is maximally stale, so a controller that never ran the sweep is \
             loud rather than silent. The three orphan gauges read 0 both when \
             clean and when unmeasured; this is how those cases are told \
             apart. TalosCryptoOrphanDetectorBlind alerts on it.",
        )?;
        registry.register(Box::new(
            crypto_orphan_scan_last_success_timestamp_seconds.clone(),
        ))?;

        let dek_cache_size = IntGauge::new(
            "talos_dek_cache_size",
            "Current number of DEKs held in the in-memory decryption cache. \
             Bounded by TTL eviction + write-path invalidation.",
        )?;
        registry.register(Box::new(dek_cache_size.clone()))?;

        let db_pool_connections = IntGauge::new(
            "talos_db_pool_connections",
            "Total connections held by the controller's Postgres pool (idle + in-use).",
        )?;
        registry.register(Box::new(db_pool_connections.clone()))?;

        let db_pool_idle_connections = IntGauge::new(
            "talos_db_pool_idle_connections",
            "Idle connections in the controller's Postgres pool (available to hand out).",
        )?;
        registry.register(Box::new(db_pool_idle_connections.clone()))?;

        let db_pool_in_use_connections = IntGauge::new(
            "talos_db_pool_in_use_connections",
            "Connections currently checked out of the controller's Postgres pool. \
             At DB_MAX_CONNECTIONS the pool is saturated and acquisitions block.",
        )?;
        registry.register(Box::new(db_pool_in_use_connections.clone()))?;

        let db_pool_max_connections = IntGauge::new(
            "talos_db_pool_max_connections",
            "Configured maximum size of the controller's Postgres pool (DB_MAX_CONNECTIONS).",
        )?;
        registry.register(Box::new(db_pool_max_connections.clone()))?;

        Ok(Arc::new(Self {
            registry,
            webhook_requests_total,
            webhook_request_duration_seconds,
            webhook_dlq_drops_total,
            auth_attempts_total,
            auth_failures_total,
            auth_2fa_attempts_total,
            api_key_validations_total,
            module_executions_total,
            module_execution_duration_seconds,
            workflow_executions_total,
            workflow_execution_duration_seconds,
            crash_recovery_total,
            wasm_log_orphaned_total,
            module_execution_record_started_failures_total,
            module_executions_swept_stuck_total,
            job_results_dropped_unparseable_total,
            audit_verification_failures_total,
            worker_key_tofu_conflicts_total,
            worker_build_skew_workers,
            catalog_templates_missing_wasm,
            catalog_missing_wasm_scan_last_success_timestamp_seconds,
            worker_liveness_pings_total,
            worker_identity_reaps_total,
            oauth_reactive_refresh_total,
            worker_liveness_participants,
            worker_liveness_recent_participants,
            worker_liveness_population_truncated,
            worker_fleet_live_workers,
            worker_fleet_live_builds,
            worker_fleet_build_skew_builds,
            worker_fleet_unverifiable_builds,
            worker_fleet_build_skew_workers,
            worker_fleet_unverifiable_workers,
            worker_fleet_capacity_dropped_heartbeats,
            worker_fleet_capacity_dropped_builds,
            fuel_high_utilisation_nodes,
            fuel_utilisation_observed_nodes,
            scheduler_dispatches_total,
            scheduler_readiness_holds_total,
            scheduler_readiness_degraded,
            rate_limit_hits_total,
            cache_hits_total,
            cache_misses_total,
            dlq_entries_total,
            dlq_drops_total,
            dlq_db_errors_total,
            kek_decrypt_failures_total,
            memory_write_failures_total,
            ops_alert_ingest_failures_total,
            ops_alert_auto_resolved_total,
            module_payload_encryption_failures_total,
            secret_decrypt_failures_total,
            actor_memory_orphaned_rows,
            module_execution_orphaned_rows,
            workflow_execution_orphaned_rows,
            crypto_orphan_scan_last_success_timestamp_seconds,
            dek_cache_size,
            db_pool_connections,
            db_pool_idle_connections,
            db_pool_in_use_connections,
            db_pool_max_connections,
        }))
    }

    /// Export metrics in Prometheus text format
    pub fn gather(&self) -> Vec<prometheus::proto::MetricFamily> {
        self.registry.gather()
    }

    /// Render the gathered registry into the Prometheus text exposition
    /// format. Returned string is UTF-8 and safe to drop into a
    /// `text/plain; version=0.0.4` HTTP response body.
    pub fn render_prometheus(&self) -> Result<String, prometheus::Error> {
        use prometheus::Encoder as _;
        let encoder = prometheus::TextEncoder::new();
        let mut buf = Vec::with_capacity(8192);
        encoder.encode(&self.gather(), &mut buf)?;
        String::from_utf8(buf).map_err(|e| prometheus::Error::Msg(format!("utf-8: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = TalosMetrics::new();
        assert!(metrics.is_ok());
    }

    #[test]
    fn test_metrics_increment() {
        let metrics = TalosMetrics::new().unwrap();

        // Increment a counter
        metrics.dlq_entries_total.inc();

        // Verify it was incremented
        let families = metrics.gather();
        let dlq_metric = families
            .iter()
            .find(|f| f.get_name() == "talos_dlq_entries_total");
        assert!(dlq_metric.is_some());
    }

    // Sanity-check that every crypto-invariant metric is actually
    // registered AND surfaces in the rendered Prometheus text format.
    // Catches typos in registry.register / series-name drift — a regression
    // here means the alerts in deploy/observability/alerts.yaml would
    // silently never fire.
    #[test]
    fn crypto_invariant_metrics_render() {
        let m = TalosMetrics::new().unwrap();

        m.kek_decrypt_failures_total
            .with_label_values(&["active"])
            .inc();
        m.kek_decrypt_failures_total
            .with_label_values(&["both"])
            .inc_by(2.0);
        m.memory_write_failures_total
            .with_label_values(&["crypto"])
            .inc();
        m.module_payload_encryption_failures_total
            .with_label_values(&["encrypt", "output"])
            .inc();
        m.actor_memory_orphaned_rows.set(3);
        m.module_execution_orphaned_rows.set(0);
        m.workflow_execution_orphaned_rows.set(0);
        m.dek_cache_size.set(42);

        let rendered = m.render_prometheus().expect("render");
        for name in [
            "talos_kek_decrypt_failures_total",
            "talos_memory_write_failures_total",
            "talos_module_payload_encryption_failures_total",
            "talos_actor_memory_orphaned_rows",
            "talos_module_execution_orphaned_rows",
            "talos_workflow_execution_orphaned_rows",
            // The meta-detector's series. It is registered but deliberately
            // NOT set above: the assertion below is that it renders as 0 on a
            // registry nothing has stamped, because `time() - 0` is what makes
            // TalosCryptoOrphanDetectorBlind fire for a controller whose sweep
            // never completed.
            "talos_crypto_orphan_scan_last_success_timestamp_seconds",
            "talos_dek_cache_size",
        ] {
            assert!(
                rendered.contains(name),
                "rendered output missing metric {name}\n--- output ---\n{rendered}"
            );
        }
        // Spot-check values land correctly.
        assert!(rendered.contains(r#"talos_kek_decrypt_failures_total{provider="active"} 1"#));
        assert!(rendered.contains(r#"talos_kek_decrypt_failures_total{provider="both"} 2"#));
        assert!(rendered.contains("talos_actor_memory_orphaned_rows 3"));
        assert!(rendered.contains("talos_dek_cache_size 42"));
        assert!(
            rendered.contains("talos_crypto_orphan_scan_last_success_timestamp_seconds 0"),
            "an unstamped freshness gauge must EXPORT 0, not be absent — an \
             absent series makes `time() - x > 600` an empty vector, which is \
             the detector silenced by its own condition (#625)"
        );
    }

    /// Absence is not zero. A `CounterVec` emits NOTHING until some label set
    /// is first touched, so on a healthy controller that has had no auth
    /// traffic and no crypto failure, ALL FIVE alerted CounterVecs were
    /// simply missing from `/metrics/prometheus` (verified 2026-08-02 against
    /// the live endpoint) — indistinguishable from the wiring having been
    /// deleted. Pre-seeding the combinations that have a live emitter makes
    /// idle read `0` instead; that fixes FOUR of the five, and
    /// `talos_auth_failures_total` deliberately stays absent (asserted
    /// below), because only 9 of its 16 (method, reason) pairs have an
    /// emitting call site.
    ///
    /// This test asserts the seeds on a FRESH registry with nothing recorded,
    /// which is the state that matters (`crypto_invariant_metrics_render`
    /// above increments first, so it cannot see this).
    #[test]
    fn alerted_counter_vecs_are_seeded_at_zero_on_a_cold_registry() {
        let m = TalosMetrics::new().unwrap();
        let rendered = m.render_prometheus().expect("render");

        for expected in [
            r#"talos_auth_attempts_total{method="password"} 0"#,
            r#"talos_auth_attempts_total{method="oauth"} 0"#,
            r#"talos_kek_decrypt_failures_total{provider="active"} 0"#,
            r#"talos_kek_decrypt_failures_total{provider="both"} 0"#,
            r#"talos_memory_write_failures_total{reason="crypto"} 0"#,
            r#"talos_memory_write_failures_total{reason="db"} 0"#,
            r#"talos_memory_write_failures_total{reason="validation"} 0"#,
            r#"talos_memory_write_failures_total{reason="other"} 0"#,
            r#"talos_module_payload_encryption_failures_total{op="encrypt",stage="input"} 0"#,
            r#"talos_module_payload_encryption_failures_total{op="encrypt",stage="output"} 0"#,
            r#"talos_module_payload_encryption_failures_total{op="encrypt",stage="trigger_metadata"} 0"#,
            r#"talos_module_payload_encryption_failures_total{op="decrypt",stage="input"} 0"#,
            r#"talos_module_payload_encryption_failures_total{op="decrypt",stage="output"} 0"#,
            r#"talos_module_payload_encryption_failures_total{op="decrypt",stage="trigger_metadata"} 0"#,
            // Worker-identity liveness + reaper. The steady state of every
            // one of these is 0 forever on a healthy fleet, which is exactly
            // the case where "absent" and "zero" diverge: the reap alert is
            // an `increase(...) > 0`, and an absent counter matches nothing.
            r#"talos_worker_liveness_pings_total{outcome="accepted"} 0"#,
            r#"talos_worker_liveness_pings_total{outcome="rejected_request"} 0"#,
            r#"talos_worker_liveness_pings_total{outcome="rejected_proof"} 0"#,
            r#"talos_worker_liveness_pings_total{outcome="inactive_identity"} 0"#,
            r#"talos_worker_liveness_pings_total{outcome="error"} 0"#,
            r#"talos_worker_identity_reaps_total{arm="departed"} 0"#,
            r#"talos_worker_identity_reaps_total{arm="pre_protocol"} 0"#,
            // Reactive OAuth repair. Same absent-is-not-zero reasoning: the
            // healthy steady state is that no arm ever moves, and the re-auth
            // alert is an `increase(...) > 0`.
            r#"talos_oauth_reactive_refresh_total{outcome="repaired"} 0"#,
            r#"talos_oauth_reactive_refresh_total{outcome="not_refreshed"} 0"#,
            r#"talos_oauth_reactive_refresh_total{outcome="refresh_failed"} 0"#,
            // The D2 pair. Plain IntGauges, so they are exported from
            // registration — asserted anyway because the alert subtracts one
            // from the other and a vector match against a missing series
            // silently yields NO RESULT, i.e. a detector that cannot fire.
            "talos_worker_liveness_participants 0",
            "talos_worker_liveness_recent_participants 0",
            // The detector-completeness flag. 0 = the participation pair
            // above describes the WHOLE reapable population; the reaper only
            // sweeps in that state.
            "talos_worker_liveness_population_truncated 0",
            // The NATS fleet-heartbeat view. Same reasoning one step further:
            // the state these sit in on a fleet that has never published a
            // heartbeat is precisely the state an operator most needs to be
            // able to distinguish from "the controller stopped publishing",
            // and `absent()` cannot tell them apart if the series never
            // existed.
            "talos_worker_fleet_live_workers 0",
            "talos_worker_fleet_live_builds 0",
            "talos_worker_fleet_build_skew_builds 0",
            "talos_worker_fleet_unverifiable_builds 0",
            "talos_worker_fleet_build_skew_workers 0",
            "talos_worker_fleet_unverifiable_workers 0",
            "talos_worker_fleet_capacity_dropped_heartbeats 0",
            "talos_worker_fleet_capacity_dropped_builds 0",
            // The fuel-headroom pair. The numerator's healthy steady state is
            // 0 forever, and it is read by a `>= 1` alert — absent would
            // match nothing. The DENOMINATOR is asserted for the opposite
            // reason: its alert fires on `== 0`, and an absent series makes
            // `== 0` match nothing too, so the meta-detector that catches a
            // dead sweep would itself be silenced by a dead sweep.
            "talos_fuel_high_utilisation_nodes 0",
            "talos_fuel_utilisation_observed_nodes 0",
            // The scheduler startup-herd detector. On a healthy fleet the
            // startup-phase series sit at 0 forever, and the alert on them is
            // built on `increase(...)` — so an absent series is a
            // detector that cannot fire on the very condition it exists to
            // catch. All ten are asserted, not just the alerted ones: an
            // operator comparing startup against steady needs both halves to
            // exist before either number means anything, and the herd alert's
            // ratio arm divides by the sum over ALL outcomes — an absent
            // denominator term makes the ratio silently wrong rather than
            // absent.
            r#"talos_scheduler_dispatches_total{outcome="completed",phase="startup"} 0"#,
            r#"talos_scheduler_dispatches_total{outcome="failed",phase="startup"} 0"#,
            r#"talos_scheduler_dispatches_total{outcome="skipped",phase="startup"} 0"#,
            r#"talos_scheduler_dispatches_total{outcome="denied",phase="startup"} 0"#,
            r#"talos_scheduler_dispatches_total{outcome="fenced",phase="startup"} 0"#,
            r#"talos_scheduler_dispatches_total{outcome="completed",phase="steady"} 0"#,
            r#"talos_scheduler_dispatches_total{outcome="failed",phase="steady"} 0"#,
            r#"talos_scheduler_dispatches_total{outcome="skipped",phase="steady"} 0"#,
            r#"talos_scheduler_dispatches_total{outcome="denied",phase="steady"} 0"#,
            r#"talos_scheduler_dispatches_total{outcome="fenced",phase="steady"} 0"#,
            "talos_scheduler_readiness_holds_total 0",
            "talos_scheduler_readiness_degraded 0",
        ] {
            assert!(
                rendered.contains(expected),
                "cold registry must EXPORT `{expected}` — an absent series is \
                 not a zero one, and every alert built on these reads absence \
                 as 'no match'\n--- output ---\n{rendered}"
            );
        }

        // The two deliberate non-seeds, asserted so a later "tidy-up" that
        // seeds them has to argue with a test rather than slip through.
        assert!(
            !rendered.contains("talos_auth_failures_total{"),
            "talos_auth_failures_total is deliberately unseeded: only 9 of its \
             16 (method, reason) pairs have an emitter, and seeding a pair \
             nothing writes implies a signal that does not exist\n{rendered}"
        );
        assert!(
            !rendered.contains(r#"provider="legacy""#),
            "provider=\"legacy\" has no emitting site anywhere in the \
             workspace; a flat 0 there would read as 'watched' when it is \
             not\n{rendered}"
        );
    }

    // Crash-recovery outcome counter (durable execution, RFC 0003) must be
    // registered, pre-seeded at 0 for all three outcomes (so dashboards/alerts
    // have a series in steady state), and increment correctly. A regression
    // here means the crash-recovery observability surface silently disappears.
    #[test]
    fn crash_recovery_metric_seeded_and_increments() {
        let m = TalosMetrics::new().unwrap();

        // Pre-seeded at 0 from new() — present before any recovery runs.
        let rendered = m.render_prometheus().expect("render");
        for outcome in ["resumed", "failed", "reclaimed"] {
            assert!(
                rendered.contains(&format!(
                    "talos_crash_recovery_total{{outcome=\"{outcome}\"}} 0"
                )),
                "crash_recovery_total[{outcome}] not pre-seeded at 0\n{rendered}"
            );
        }

        // Increment behaves: counts accumulate per outcome label.
        m.crash_recovery_total.with_label_values(&["resumed"]).inc();
        m.crash_recovery_total
            .with_label_values(&["reclaimed"])
            .inc_by(3.0);
        let rendered = m.render_prometheus().expect("render");
        assert!(rendered.contains(r#"talos_crash_recovery_total{outcome="resumed"} 1"#));
        assert!(rendered.contains(r#"talos_crash_recovery_total{outcome="reclaimed"} 3"#));
        assert!(rendered.contains(r#"talos_crash_recovery_total{outcome="failed"} 0"#));
    }

    // workflow_executions_total must be pre-seeded at 0 for success+failure
    // (so the TalosWorkflowFailureRateHigh alert's rate() has a series in
    // steady state) and increment per status label. Before this wiring the
    // counter was registered but never incremented — a dead metric that made
    // any alert on it silently un-fireable.
    #[test]
    fn workflow_executions_metric_seeded_and_increments() {
        let m = TalosMetrics::new().unwrap();
        let rendered = m.render_prometheus().expect("render");
        for status in ["success", "failure"] {
            assert!(
                rendered.contains(&format!(
                    "talos_workflow_executions_total{{status=\"{status}\"}} 0"
                )),
                "workflow_executions_total[{status}] not pre-seeded at 0\n{rendered}"
            );
        }
        m.workflow_executions_total
            .with_label_values(&["failure"])
            .inc();
        m.workflow_executions_total
            .with_label_values(&["success"])
            .inc_by(3.0);
        let rendered = m.render_prometheus().expect("render");
        assert!(rendered.contains(r#"talos_workflow_executions_total{status="failure"} 1"#));
        assert!(rendered.contains(r#"talos_workflow_executions_total{status="success"} 3"#));
    }

    // record_workflow_outcome is inert (no panic) when metrics aren't wired —
    // the finalizers call it unconditionally, and unit tests / any process
    // without set_global must not blow up.
    #[test]
    fn record_workflow_outcome_is_inert_without_global() {
        // Does not panic even though set_global may not have run in this test
        // binary. (If a sibling test already set the global, this still just
        // increments harmlessly.)
        super::record_workflow_outcome("failure");
        super::record_workflow_outcome("success");
    }

    // set_global / global round-trip. One-shot semantics: subsequent
    // sets are no-ops (and crucially must not panic).
    #[test]
    fn global_metrics_oncelock_round_trip() {
        // If another test already initialised the global, the value will
        // reflect that — this test is side-effect-tolerant. We care that
        // global() returns Some AFTER set_global.
        let m = TalosMetrics::new().unwrap();
        set_global(m.clone());
        let fetched = global().expect("global registry installed");
        // Increment via global; verify via the local Arc.
        fetched.dek_cache_size.set(7);
        // Both references share the same underlying prometheus collectors.
        assert_eq!(m.dek_cache_size.get(), 7);
    }
}

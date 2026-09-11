//! Two instruments for the one failure this process cannot otherwise
//! report: **a background task that stops running.**
//!
//! Measured 2026-09-07 on `origin/main`: `controller/src/bootstrap/` +
//! `controller/src/main.rs` hold **54** `tokio::spawn` call sites, **45**
//! of which spawn a long-lived loop, and **exactly one** binds the
//! `JoinHandle` (and only to sequence a metrics gauge — it discards the
//! `JoinError` too). There was **no `std::panic::set_hook`** anywhere in
//! `controller/` or `worker/`. So a panicking loop produced one
//! unstructured stderr line, incremented nothing, was never restarted,
//! and every operator-facing surface kept reporting the subsystem as
//! configured. Package 22 fixed the one such panic that was found (the
//! SLA monitor's NULL webhook decode); the CLASS stayed open.
//!
//! **That 54 was a SCOPE, not a population.** Re-measured 2026-09-08
//! over `talos-*/src` + `worker/src` as well: **127** further bare
//! `tokio::spawn` call sites, **32** of them long-lived loops, in 34
//! crates the first pass never looked at. Seven of those loops were
//! supervised in the first pass of that day.
//!
//! Later the same day the remaining 28 `loop` rows were classified BY
//! READING each body. **Eleven more** are supervised — eight with a
//! real exit path (a `select!` shutdown arm, or a `Notify`-driven
//! flush-and-break) and three pure `loop { tick; f() }` tickers admitted
//! for panic ATTRIBUTION at one line each — bringing the library-crate
//! total to **18**. Of the 17 rows the walk still reports, **13 are
//! false positives of its 60-line window** (startup one-shots,
//! per-connection and per-execution tasks, a test-only file, a demo
//! binary, and — until the crate was deleted 2026-09-11 — `talos-jobs`'
//! `start_processor`, which had zero callers) and **4 are real, all in
//! the WORKER**, all pure
//! tickers. Those four are NOT supervised, and the reason is measured:
//! `BackgroundTask::ALL` is what the CONTROLLER pre-seeds, so a
//! worker-side variant costs a process partition of this table rather
//! than one line. The full per-site classification is in
//! `scripts/background-task-inventory.py`'s docstring.
//!
//! # The two instruments answer different questions
//!
//! * [`install_panic_hook`] covers **every** panic in the process —
//!   spawned task, request handler, or the main thread — and is the only
//!   thing that can see a panic in code this crate does not wrap. It
//!   cannot name the TASK: a tokio worker thread is called
//!   `tokio-runtime-worker`, and the panic LOCATION is wherever the
//!   panic was raised, usually inside a callee.
//! * [`spawn_supervised`] covers only what it wraps, and sees the case a
//!   panic hook structurally cannot: **a clean exit.** A loop that
//!   `break`s, or whose `while let Some(_) = rx.recv().await` ends
//!   because the channel closed, returns `Ok(())` — no panic, no log,
//!   no trace, and the subsystem is simply off for the process lifetime.
//!
//! # A clean exit is not one thing ([`TaskExit`])
//!
//! Shipped 2026-09-07, the wrapper's future returned `()`, so "the loop
//! stopped" and "this task chose not to start under this configuration"
//! were the SAME VALUE. Its own first boot proved that mattered: two of
//! the forty-two supervised bodies returned within a second and both
//! were logged at ERROR as loops that had died. The future now returns
//! [`TaskExit`]. A genuine `loop {}` has type `!` and coerces, so every
//! real loop compiles unchanged; every body that CAN return must say
//! which of the three things happened, and the compiler — not a grep —
//! enumerates that population.
//!
//! Neither is a supervisor: nothing is restarted. Restarting a loop
//! whose panic is deterministic would spin; deciding per-task whether a
//! restart is safe is a separate change. What these buy is that the
//! death is SAYABLE.
//!
//! # Cardinality
//!
//! `task` is a label on a `CounterVec`, so its value set must be closed
//! and compile-time known ([`BackgroundTask`] is an enum, so the
//! compiler enforces that — there is no string to drift), and every
//! `(task, outcome)` pair is PRE-SEEDED at 0 by [`register_metrics`]:
//! `increase(...) > 0` over an ABSENT series matches nothing, which is
//! exactly how a loop that has never exited would look identical to one
//! whose instrument was never wired.

use prometheus::{CounterVec, Opts, Registry};
use std::future::Future;
use std::sync::OnceLock;

/// The closed set of supervised background tasks.
///
/// Declared through a macro so the enum, its metric label and the
/// `ALL` array that pre-seeds the counter come from ONE table — a
/// hand-maintained parallel list is the rot mode this repo has paid for
/// more than once (checks 64, 74). Adding a variant without adding it to
/// `ALL` is not expressible.
macro_rules! background_tasks {
    ($( $variant:ident => $label:literal ),+ $(,)?) => {
        /// One supervised long-lived background task. The `&'static str`
        /// form is the `task` label value on
        /// `talos_background_task_exits_total`.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum BackgroundTask {
            $( #[allow(missing_docs)] $variant ),+
        }

        impl BackgroundTask {
            /// Every declared task, in declaration order. Used to
            /// pre-seed the counter and by the uniqueness test.
            pub const ALL: &'static [BackgroundTask] = &[ $( BackgroundTask::$variant ),+ ];

            /// The metric label / log field for this task.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( BackgroundTask::$variant => $label ),+
                }
            }
        }
    };
}

background_tasks! {
    // ── Controller bootstrap loops (controller/src/bootstrap/background.rs) ──
    WorkerFleetGauge            => "worker_fleet_gauge",
    EmbeddingProviderProbe      => "embedding_provider_probe",
    CryptoInvariantGauge        => "crypto_invariant_gauge",
    CatalogMissingWasmGauge     => "catalog_missing_wasm_gauge",
    NodeFuelHeadroomGauge       => "node_fuel_headroom_gauge",
    FleetBuildSkewGauge         => "fleet_build_skew_gauge",
    WorkerIdentityReaper        => "worker_identity_reaper",
    DbPoolGauge                 => "db_pool_gauge",
    RegistrySync                => "registry_sync",
    LlmKeysCacheSweep           => "llm_keys_cache_sweep",
    MemoryRankProvenanceSweep   => "memory_rank_provenance_sweep",
    OpsAlertsSelfMonitor        => "ops_alerts_self_monitor",
    WorkerKeyRefresh            => "worker_key_refresh",
    AuditChainVerificationSweep => "audit_chain_verification_sweep",
    ModuleTableReconcile        => "module_table_reconcile",
    SessionCleanup              => "session_cleanup",
    ApiKeyCleanup               => "api_key_cleanup",
    OauthStateCleanup           => "oauth_state_cleanup",
    ExecutionRetention          => "execution_retention",
    AuditLogCleanup             => "audit_log_cleanup",
    SuspensionExpiry            => "suspension_expiry",
    WasmCacheCleanup            => "wasm_cache_cleanup",
    WebhookRateLimitCleanup     => "webhook_rate_limit_cleanup",
    AuthRateLimitCleanup        => "auth_rate_limit_cleanup",
    StuckExecutionCleanup       => "stuck_execution_cleanup",
    ModulePayloadRetention      => "module_payload_retention",
    ModuleExecutionRowRetention => "module_execution_row_retention",
    DekCacheCleanup             => "dek_cache_cleanup",
    ActorMemoryTtlSweep         => "actor_memory_ttl_sweep",
    WorkflowReadinessRecompute  => "workflow_readiness_recompute",
    SlaDegradationMonitor       => "sla_degradation_monitor",
    GmailWatchRenewal           => "gmail_watch_renewal",
    GmailCreateLockSweep        => "gmail_create_lock_sweep",
    GcpCreateLockSweep          => "gcp_create_lock_sweep",
    GcalChannelRenewal          => "gcal_channel_renewal",
    GcalRateLimitCleanup        => "gcal_rate_limit_cleanup",
    WasmLogSubscriber           => "wasm_log_subscriber",
    JobResultSubscriber         => "job_result_subscriber",
    StaleExecutionSweep         => "stale_execution_sweep",
    Scheduler                   => "scheduler",
    SlaBreachMonitor            => "sla_breach_monitor",

    // ── Loops owned by LIBRARY crates (2026-09-08). ──
    //
    // These are the loops whose LAUNCHER the controller used to
    // supervise, plus their siblings in the same crates. Supervision
    // belongs where the loop is: `WorkerFleetManagement` (dropped
    // above) named a function that spawned these two and returned
    // `Ok(())` at once, so the wrapper recorded a healthy launch as a
    // death and the two loops that matter stayed exactly as
    // unobserved as they were before the wrapper existed.
    WorkerFleetHeartbeat        => "worker_fleet_heartbeat",
    WorkerFleetPrune            => "worker_fleet_prune",
    AuditLedgerSubscriber       => "audit_ledger_subscriber",
    EnvelopeSealClaimResponder  => "envelope_seal_claim_responder",
    EnvelopeSealOrphanSweep     => "envelope_seal_orphan_sweep",
    IntegrationStateSweeper     => "integration_state_sweeper",
    // One variant per signed-RPC subject rather than one shared
    // `rpc_subscriber`: the whole value of the `task` label is naming
    // WHICH loop stopped, and the seven subjects fail independently
    // (a dead `talos.memory.op` subscriber times out every actor-memory
    // call while `talos.state.write` keeps running).
    GraphRpcSubscriber          => "graph_rpc_subscriber",
    MlPredictRpcSubscriber      => "ml_predict_rpc_subscriber",
    MlFewshotRpcSubscriber      => "ml_fewshot_rpc_subscriber",
    MemoryRpcSubscriber         => "memory_rpc_subscriber",
    DatabaseRpcSubscriber       => "database_rpc_subscriber",
    StateWriteRpcSubscriber     => "state_write_rpc_subscriber",
    IntegrationStateRpcSubscriber => "integration_state_rpc_subscriber",

    // ── 2026-09-08 (package thirty): the remaining LIBRARY-crate loops.
    //
    // Classified by READING each body, not by a windowed scan. The
    // eight below all have an exit the compiler can now name — seven a
    // `select!` shutdown arm, one a `Notify`-driven flush-and-break —
    // which is the shape `spawn_supervised` exists for: they can stop
    // WITHOUT panicking, and until now that stop was invisible.
    BcryptCacheRevocationSweep  => "bcrypt_cache_revocation_sweep",
    MemoryConsolidationScheduler => "memory_consolidation_scheduler",
    MemoryReflectionScheduler   => "memory_reflection_scheduler",
    RankTrainingScheduler       => "rank_training_scheduler",
    MlDisagreementDigest        => "ml_disagreement_digest",
    MlPolicyEvaluator           => "ml_policy_evaluator",
    MlTeacherAudit              => "ml_teacher_audit",
    DlqBatchProcessor           => "dlq_batch_processor",

    // The three below are `loop { tick; f() }` with NO exit path at
    // all: they cannot stop cleanly, so supervision buys per-task
    // ATTRIBUTION of a panic the process hook already counts, and
    // nothing else. Stated plainly rather than sold as closing a
    // silent-death gap — see the crate docs. Each cost exactly one
    // line at the call site (the `loop` has type `!`, which coerces),
    // which is the bar they were admitted on.
    ActorPolicyCacheSweep       => "actor_policy_cache_sweep",
    PublicUrlDiscovery          => "public_url_discovery",
    EngineRateLimitEviction     => "engine_rate_limit_eviction",
}

/// Why a supervised body stopped running.
///
/// This is the return type of every supervised future, and the point is
/// that **the compiler enumerates the population**. A genuine
/// `loop { .. }` with no `break` has type `!`, which coerces to this
/// enum, so every task that really does run for the process lifetime
/// compiles unchanged and says nothing. Every body that CAN return must
/// now say why — which is the fact [`spawn_supervised`] could not
/// represent when its future returned `()`.
///
/// Measured live 2026-09-08, on the first boot after the wrapper
/// shipped: two of the forty-two supervised bodies returned one second
/// after boot and were both recorded `completed` and logged at ERROR —
/// `registry_sync` (OCI sync is opt-in and `TALOS_REGISTRY_URL` is
/// unset on this fleet) and `worker_fleet_management` (a LAUNCHER that
/// spawned its own two loops and returned `Ok(())`). Neither is a loop
/// that stopped; both read exactly like one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use = "a supervised body's exit must be reported, not dropped"]
pub enum TaskExit {
    /// The task deliberately did not start under this configuration.
    /// Not a failure: logged at INFO, recorded under the `declined`
    /// outcome, and EXCLUDED from `TalosBackgroundTaskExited`.
    Declined(DeclineReason),
    /// The task ran and stopped because the process is shutting down.
    /// Also not a failure — but deliberately NOT folded into
    /// [`TaskExit::Declined`], which is a statement about configuration
    /// at START. Calling a shutdown "declined" would assert the task
    /// never ran, which is the same false-report class this type
    /// removes.
    ShuttingDown,
    /// The task's own loop ended. Recorded `completed`, logged at ERROR
    /// and alerted — this is the finding the instrument exists for, and
    /// it keeps every property it had.
    LoopEnded,
}

impl TaskExit {
    /// The `outcome` label value for this exit.
    #[must_use]
    pub const fn outcome(self) -> &'static str {
        match self {
            TaskExit::Declined(_) => "declined",
            TaskExit::ShuttingDown => "shutdown",
            TaskExit::LoopEnded => "completed",
        }
    }

    /// Whether this exit is a finding an operator should be woken by.
    /// Kept as ONE predicate so the log level and the alert's own
    /// `outcome!~` selector cannot drift apart.
    #[must_use]
    pub const fn is_finding(self) -> bool {
        matches!(self, TaskExit::LoopEnded)
    }
}

/// Why a task declined to start. A CLOSED enum, not a `&str`: the reason
/// reaches a log FIELD (never a metric label — `outcome` is the only
/// label this adds, and it has five compile-time values), and a closed
/// set means the population of "tasks that can legitimately not start"
/// is enumerable from the type rather than by grep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeclineReason {
    /// A required endpoint, URL or credential is not configured, so the
    /// subsystem this task maintains is not in use on this deployment.
    NotConfigured,
    /// An opt-in feature flag is off. The task exists; the operator has
    /// not asked for it.
    FeatureDisabled,
    /// A policy choice this task refuses to guess was not made
    /// explicitly, so it withholds itself rather than run unverified.
    PolicyNotExplicit,
}

impl DeclineReason {
    /// The `reason` log-field value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            DeclineReason::NotConfigured => "not_configured",
            DeclineReason::FeatureDisabled => "feature_disabled",
            DeclineReason::PolicyNotExplicit => "policy_not_explicit",
        }
    }
}

/// How a supervised task stopped. FIVE values, and each split is a
/// distinction some reader acts on:
/// * a `JoinError` is either a panic or a cancellation, and folding an
///   abort into "panicked" would report a deliberate shutdown as a
///   defect;
/// * `declined` and `shutdown` are the two ways a body returns WITHOUT
///   anything having gone wrong, and until 2026-09-08 both rendered as
///   `completed` — an ERROR line and an alertable increment on a
///   healthy boot, which is precisely the train-the-operator-to-ignore-it
///   defect (check 69's class) inside the instrument built to remove it.
pub const EXIT_OUTCOMES: &[&str] = &["panicked", "completed", "cancelled", "declined", "shutdown"];

/// Longest panic message kept in the log line. A panic payload is
/// arbitrary caller text — it can carry a whole formatted struct — and
/// a hook that allocates without bound while unwinding is a second
/// failure on top of the first.
const MAX_PANIC_MESSAGE: usize = 300;

struct Instruments {
    panics: CounterVec,
    exits: CounterVec,
}

static INSTRUMENTS: OnceLock<Instruments> = OnceLock::new();
static PROCESS: OnceLock<&'static str> = OnceLock::new();

fn instruments() -> &'static Instruments {
    INSTRUMENTS.get_or_init(|| Instruments {
        panics: CounterVec::new(
            Opts::new(
                "talos_task_panics_total",
                "Panics observed by the process-wide panic hook, by process. \
                 A panic in a spawned task is never 'working as designed': \
                 nobody is awaiting it, nothing restarts it, and every \
                 operator-facing surface keeps reporting the subsystem as \
                 configured. Pre-seeded at 0 for THIS process only — a \
                 label value for a process that cannot increment it would \
                 imply a signal that does not exist.",
            ),
            &["process"],
        )
        .expect("static metric opts"),
        exits: exits_collector(),
    })
}

/// The exits collector's construction, split out so a test can build a
/// FRESH one: `INSTRUMENTS` is a process-global `OnceLock`, so a sibling
/// test that records an exit leaves that child present in every later
/// `Registry` the same collector is registered into — an assertion about
/// what seeding does could not otherwise be made in one test binary.
fn exits_collector() -> CounterVec {
    CounterVec::new(
        Opts::new(
            "talos_background_task_exits_total",
            "Terminations of a supervised long-lived background task, by \
                 task and outcome. Every one of these loops is meant to run \
                 for the process lifetime, so ANY outcome here is a finding — \
                 'completed' most of all, because a clean exit is the one a \
                 panic hook structurally cannot see.",
        ),
        &["task", "outcome"],
    )
    .expect("static metric opts")
}

/// Pre-seed every `(task, outcome)` pair the CALLING process can produce
/// at 0. `increase(...) > 0` over an ABSENT series matches nothing, so
/// an unseeded pair makes "this loop has never exited" and "this
/// instrument was never wired" render identically; seeding a pair the
/// process CANNOT produce is the mirror defect (check 58).
fn seed_exits(exits: &CounterVec, supervised: &[BackgroundTask]) {
    for task in supervised {
        for outcome in EXIT_OUTCOMES {
            exits
                .with_label_values(&[task.as_str(), outcome])
                .inc_by(0.0);
        }
    }
}

/// Install the process-wide panic hook.
///
/// `process` is a compile-time constant (`"controller"` / `"worker"`) and
/// becomes the single seeded value of the `process` label in THIS
/// process. Idempotent: a second call replaces the hook with an
/// equivalent one and leaves the recorded process name as the first.
///
/// The hook must never panic itself — a panic inside a panic hook
/// aborts the process, turning a recoverable single-task failure into a
/// whole-fleet outage — so everything it touches is infallible:
/// the payload downcast falls back to a fixed string, the message is
/// control-char-scrubbed and truncated on a char boundary, and the
/// counter is a `CounterVec` that has already been constructed.
pub fn install_panic_hook(process: &'static str) {
    let _ = PROCESS.set(process);
    let recorded = *PROCESS.get().unwrap_or(&process);
    // Touch the instruments now so the hook never constructs anything
    // while unwinding.
    let _ = instruments();
    std::panic::set_hook(Box::new(move |info| {
        let message = scrub_panic_payload(info);
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());
        let thread = std::thread::current()
            .name()
            .map(scrub)
            .unwrap_or_else(|| "unnamed".to_string());
        instruments().panics.with_label_values(&[recorded]).inc();
        tracing::error!(
            target: "talos_audit",
            event_kind = "task_panicked",
            process = recorded,
            thread = %thread,
            location = %location,
            message = %message,
            "a task panicked — nothing restarts it and no caller is awaiting it"
        );
    }));
}

/// Register both collectors into `registry` and PRE-SEED every series
/// **this process can increment** at 0.
///
/// `supervised` is the set of tasks THIS binary wraps, and it is a
/// required argument rather than `BackgroundTask::ALL` because seeding
/// more than that is the defect the seeding exists to avoid. Measured
/// live 2026-09-08: the worker calls this function and supervises
/// nothing, so its `/metrics` exposed all 126 controller-only
/// `talos_background_task_exits_total` series at 0 — a seeded
/// combination nothing in that process can ever increment, which is
/// check 58's own rule, and the same claim this crate's docs made about
/// the `process` label while breaking it for `task`. The controller
/// passes [`BackgroundTask::ALL`]; the worker passes `&[]` and exposes
/// only its (live) panic counter.
///
/// Split from [`install_panic_hook`] deliberately: the hook must go in
/// before anything can panic, which is earlier than the metrics registry
/// exists. Counts accumulated between the two calls are preserved — the
/// collector is the same object, only its registration is deferred.
///
/// # Errors
/// Propagates a duplicate-registration error from `prometheus`.
pub fn register_metrics(
    registry: &Registry,
    supervised: &[BackgroundTask],
) -> prometheus::Result<()> {
    let inst = instruments();
    registry.register(Box::new(inst.panics.clone()))?;
    registry.register(Box::new(inst.exits.clone()))?;
    if let Some(p) = PROCESS.get() {
        inst.panics.with_label_values(&[p]).inc_by(0.0);
    }
    seed_exits(&inst.exits, supervised);
    Ok(())
}

/// Spawn a long-lived background task and RECORD how it stops.
///
/// The future is spawned in its own task; a thin outer task awaits the
/// join handle and classifies the outcome. The cost is one extra idle
/// task per supervised loop.
///
/// Nothing is restarted — see the crate docs for why.
pub fn spawn_supervised<F>(task: BackgroundTask, fut: F) -> tokio::task::JoinHandle<()>
where
    F: Future<Output = TaskExit> + Send + 'static,
{
    tokio::spawn(async move {
        let inner = tokio::spawn(fut);
        match inner.await {
            Ok(exit) => record_exit(task, exit),
            Err(e) if e.is_panic() => record_join_failure(task, "panicked"),
            Err(_) => record_join_failure(task, "cancelled"),
        }
    })
}

/// Record one supervised-task termination that the body itself
/// classified. Public so a task that owns its own join plumbing can
/// report through the same instrument rather than inventing a second
/// one.
pub fn record_exit(task: BackgroundTask, exit: TaskExit) {
    instruments()
        .exits
        .with_label_values(&[task.as_str(), exit.outcome()])
        .inc();
    if exit.is_finding() {
        tracing::error!(
            target: "talos_audit",
            event_kind = "background_task_exited",
            task = task.as_str(),
            outcome = exit.outcome(),
            "a long-lived background task stopped; it will not be restarted"
        );
        return;
    }
    // NOT a finding: INFO, under its OWN event_kind so a log-based
    // detector keyed on `background_task_exited` keeps meaning exactly
    // what it meant. An ERROR that fires on every healthy boot trains
    // operators to ignore ERROR — the exact defect this instrument was
    // built to make visible, one level up.
    match exit {
        TaskExit::Declined(reason) => tracing::info!(
            target: "talos_audit",
            event_kind = "background_task_declined",
            task = task.as_str(),
            outcome = exit.outcome(),
            reason = reason.as_str(),
            "a supervised background task did not start under this configuration"
        ),
        TaskExit::ShuttingDown => tracing::info!(
            target: "talos_audit",
            event_kind = "background_task_shutdown",
            task = task.as_str(),
            outcome = exit.outcome(),
            "a supervised background task stopped because the process is shutting down"
        ),
        // Unreachable: `is_finding()` returned above for this variant.
        // Written as an exhaustive arm rather than a `_` so a sixth
        // variant cannot silently inherit the INFO path.
        TaskExit::LoopEnded => {}
    }
}

/// Record a termination the BODY could not classify because it never
/// returned: a panic or an abort observed through the `JoinError`.
/// Always a finding.
fn record_join_failure(task: BackgroundTask, outcome: &'static str) {
    instruments()
        .exits
        .with_label_values(&[task.as_str(), outcome])
        .inc();
    tracing::error!(
        target: "talos_audit",
        event_kind = "background_task_exited",
        task = task.as_str(),
        outcome = outcome,
        "a long-lived background task stopped; it will not be restarted"
    );
}

/// Count the supervised and BARE `tokio::spawn` sites in one source
/// file's PRODUCTION text, so a crate that owns a supervised loop can
/// pin its own wiring in five lines.
///
/// **Why this exists at all.** A supervised spawn site reverted to a
/// bare `tokio::spawn` is behaviourally identical on a healthy process
/// and silent on a dead one — no test, no metric and no log can see it,
/// which is exactly what `task_supervision_wiring_tests` pins for
/// `controller/src/bootstrap/background.rs` and
/// `the_two_fleet_loops_are_supervised_not_their_launcher` pins for
/// `talos-worker-fleet`. From 2026-09-08 eleven more loops in eight
/// LIBRARY crates go through the wrapper, and each needs the same pin.
/// The COUNTING RULE lives here so eight copies of it cannot drift; the
/// ASSERTION stays in the crate that owns the file, because only that
/// crate knows how many of each its file should have.
///
/// Everything from the first column-0 `#[cfg(test)]` onward is dropped —
/// otherwise a pin's own prose, which necessarily quotes both
/// expressions, counts itself (check 73's self-report trap). Whole-line
/// `//` comments are dropped from the bare count for the same reason.
///
/// **Stated limits**, so nobody reads more into a green pin than it
/// carries: this is TEXTUAL and per-FILE. It cannot say whether a site
/// wraps the RIGHT future or names the right [`BackgroundTask`], it
/// cannot see a loop moved to another file, and a `#[cfg(test)]`
/// attribute that is indented rather than at column 0 leaves test text
/// in the haystack (a false POSITIVE — the loud direction).
#[must_use]
pub fn production_spawn_counts(src: &str) -> (usize, usize) {
    let production = src.split("\n#[cfg(test)]").next().unwrap_or(src);
    let supervised = production
        .matches("spawn_supervised(")
        .count()
        .saturating_sub(production.matches("fn spawn_supervised(").count());
    let bare = production
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            !t.starts_with("//") && t.contains("tokio::spawn(")
        })
        .count();
    (supervised, bare)
}

/// Test-only read of the panic counter for this process.
#[doc(hidden)]
#[must_use]
pub fn panic_count_for_tests() -> f64 {
    match PROCESS.get() {
        Some(p) => instruments().panics.with_label_values(&[p]).get(),
        None => 0.0,
    }
}

/// Test-only read of one `(task, outcome)` exit counter.
#[doc(hidden)]
#[must_use]
pub fn exit_count_for_tests(task: BackgroundTask, outcome: &str) -> f64 {
    instruments()
        .exits
        .with_label_values(&[task.as_str(), outcome])
        .get()
}

/// Replace control characters (including the newline that would let a
/// panic payload forge a second log line) with `·`, then truncate on a
/// char boundary. Never allocates more than `MAX_PANIC_MESSAGE + 1`
/// chars' worth beyond the input.
fn scrub(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(MAX_PANIC_MESSAGE) + 1);
    for (i, c) in s.chars().enumerate() {
        if i >= MAX_PANIC_MESSAGE {
            out.push('…');
            break;
        }
        out.push(if c.is_control() { '·' } else { c });
    }
    out
}

fn scrub_panic_payload(info: &std::panic::PanicHookInfo<'_>) -> String {
    let payload = info.payload();
    if let Some(s) = payload.downcast_ref::<&str>() {
        scrub(s)
    } else if let Some(s) = payload.downcast_ref::<String>() {
        scrub(s)
    } else {
        // A panic payload can be ANY `Box<dyn Any>`; there is nothing
        // safe to print for the rest.
        "<non-string panic payload>".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_labels_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for t in BackgroundTask::ALL {
            assert!(
                seen.insert(t.as_str()),
                "duplicate background-task label {:?}",
                t.as_str()
            );
        }
        assert_eq!(seen.len(), BackgroundTask::ALL.len());
    }

    #[test]
    fn task_labels_are_snake_case_and_bounded() {
        for t in BackgroundTask::ALL {
            let s = t.as_str();
            assert!(!s.is_empty() && s.len() <= 48, "bad label {s:?}");
            assert!(
                s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "label {s:?} is not snake_case"
            );
        }
    }

    /// A process that supervises NOTHING must expose NO exit series.
    ///
    /// Measured live 2026-09-08: the worker did — all 126 of them, at 0
    /// — because it called `register_metrics` and the seeding walked the
    /// whole `BackgroundTask` table regardless of caller. Those are
    /// seeded combinations nothing in that process can ever increment,
    /// which is check 58's own rule and exactly the claim this crate's
    /// docs made about the `process` label while breaking it for `task`.
    ///
    /// Driven against a FRESH collector rather than through
    /// `register_metrics`: `INSTRUMENTS` is a process-global `OnceLock`,
    /// so a sibling test that records one exit leaves that child in
    /// every later registry and the assertion would be order-dependent.
    /// The seeding routine under test is the same one `register_metrics`
    /// calls.
    #[test]
    fn a_process_that_supervises_nothing_seeds_no_exit_series() {
        let empty = exits_collector();
        seed_exits(&empty, &[]);
        let reg = Registry::new();
        reg.register(Box::new(empty)).expect("register");
        assert!(
            !render(&reg).contains("talos_background_task_exits_total{"),
            "a non-supervising process must export no `(task, outcome)` series"
        );

        // Positive control on the same fresh collector: the seeding IS
        // wired, so an empty result means "nothing asked for", not
        // "seeding is broken".
        let full = exits_collector();
        seed_exits(&full, BackgroundTask::ALL);
        let reg2 = Registry::new();
        reg2.register(Box::new(full)).expect("register");
        let n = render(&reg2)
            .lines()
            .filter(|l| l.starts_with("talos_background_task_exits_total{"))
            .count();
        assert_eq!(n, BackgroundTask::ALL.len() * EXIT_OUTCOMES.len());
    }

    fn render(reg: &Registry) -> String {
        use prometheus::Encoder as _;
        let mut buf = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&reg.gather(), &mut buf)
            .expect("encode");
        String::from_utf8(buf).expect("utf8")
    }

    #[test]
    fn registering_seeds_every_pair_at_zero() {
        let reg = Registry::new();
        register_metrics(&reg, BackgroundTask::ALL).expect("register");
        let rendered = render(&reg);
        // Absent is not zero: every pair must be present in the
        // exposition BEFORE anything has ever exited.
        for t in BackgroundTask::ALL {
            for o in EXIT_OUTCOMES {
                // prometheus sorts label pairs alphabetically in the
                // exposition, so `outcome` precedes `task`.
                let want = format!("outcome=\"{}\",task=\"{}\"", o, t.as_str());
                assert!(
                    rendered.contains(&want),
                    "missing pre-seeded series for {want}"
                );
            }
        }
    }

    /// The one predicate the log level AND the alert's `outcome!~`
    /// selector both rest on. If these two ever disagree, an ERROR line
    /// exists with no alert behind it, or an alert fires on a line
    /// nobody logged at ERROR.
    #[test]
    fn only_a_stopped_loop_is_a_finding() {
        assert!(TaskExit::LoopEnded.is_finding());
        assert!(!TaskExit::ShuttingDown.is_finding());
        for r in [
            DeclineReason::NotConfigured,
            DeclineReason::FeatureDisabled,
            DeclineReason::PolicyNotExplicit,
        ] {
            assert!(!TaskExit::Declined(r).is_finding());
            assert_eq!(TaskExit::Declined(r).outcome(), "declined");
        }
        assert_eq!(TaskExit::ShuttingDown.outcome(), "shutdown");
        assert_eq!(TaskExit::LoopEnded.outcome(), "completed");
        // Every outcome a body can produce must be in the seeded set,
        // or its series is ABSENT until the first one happens — and
        // absent is not zero for `increase(...) > 0`.
        for o in ["declined", "shutdown", "completed"] {
            assert!(EXIT_OUTCOMES.contains(&o), "{o} is not pre-seeded");
        }
    }

    #[test]
    fn scrub_removes_newlines_and_truncates() {
        let s = scrub("a\nb\tc");
        assert_eq!(s, "a·b·c");
        let long = "x".repeat(1000);
        let out = scrub(&long);
        assert_eq!(out.chars().count(), MAX_PANIC_MESSAGE + 1);
        assert!(out.ends_with('…'));
        // Multi-byte input must not be split mid-character.
        let multi = "é".repeat(1000);
        assert!(scrub(&multi).chars().count() <= MAX_PANIC_MESSAGE + 1);
    }
}

/// Tests that drive the REAL process-global panic hook.
///
/// The hook is process-global, so these are deliberately serialized
/// behind one mutex and assert DELTAS rather than absolute values —
/// the `OnceLock`-race shape check 82's entry records. They live in
/// `src/` rather than `tests/` so they run in CI's ordinary unit job
/// with no runner registration to rot (check 64's lesson, and the
/// `schema_snapshot_tests` precedent).
#[cfg(test)]
mod hook_tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
    use tracing_subscriber::Registry as SubRegistry;

    /// Serializes every test that installs the hook or panics on a
    /// worker thread. `#[should_panic]` siblings elsewhere in this crate
    /// would otherwise move the same counter.
    static HOOK_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<String>>>);

    struct Collect(Vec<(String, String)>);
    impl Visit for Collect {
        fn record_debug(&mut self, f: &Field, v: &dyn std::fmt::Debug) {
            self.0.push((f.name().to_string(), format!("{v:?}")));
        }
        fn record_str(&mut self, f: &Field, v: &str) {
            self.0.push((f.name().to_string(), v.to_string()));
        }
    }

    impl<S: tracing::Subscriber> Layer<S> for Captured {
        fn on_event(&self, ev: &tracing::Event<'_>, _cx: Context<'_, S>) {
            let mut c = Collect(Vec::new());
            ev.record(&mut c);
            let fields =
                c.0.iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(" ");
            if let Ok(mut g) = self.0.lock() {
                g.push(format!("target={} {}", ev.metadata().target(), fields));
            }
        }
    }

    /// Install a capturing global subscriber once for this test binary.
    fn capture() -> Captured {
        static CAP: OnceLock<Captured> = OnceLock::new();
        CAP.get_or_init(|| {
            let cap = Captured::default();
            let sub = SubRegistry::default().with(cap.clone());
            // Best-effort: if a sibling already installed one we still
            // assert on the counter below.
            let _ = tracing::subscriber::set_global_default(sub);
            cap
        })
        .clone()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_panicking_supervised_task_is_counted_and_logged() {
        let _guard = HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let cap = capture();
        install_panic_hook("controller");
        let before_panics = panic_count_for_tests();
        let before_exits = exit_count_for_tests(BackgroundTask::Scheduler, "panicked");
        if let Ok(mut g) = cap.0.lock() {
            g.clear();
        }

        spawn_supervised(BackgroundTask::Scheduler, async {
            panic!("scheduler blew up\nwith a second line");
        })
        .await
        .expect("supervisor task itself must not panic");

        assert_eq!(
            panic_count_for_tests() - before_panics,
            1.0,
            "the panic hook must count exactly once"
        );
        assert_eq!(
            exit_count_for_tests(BackgroundTask::Scheduler, "panicked") - before_exits,
            1.0,
            "the supervisor must classify the exit as a panic"
        );

        let lines = cap.0.lock().expect("capture").clone();
        let panicked = lines
            .iter()
            .find(|l| l.contains("task_panicked"))
            .unwrap_or_else(|| panic!("no task_panicked event in {lines:?}"));
        assert!(panicked.contains("target=talos_audit"), "{panicked}");
        assert!(panicked.contains("process=controller"), "{panicked}");
        assert!(panicked.contains("location="), "{panicked}");
        // The payload's newline must not have forged a second line.
        assert!(
            panicked.contains("scheduler blew up·with a second line"),
            "{panicked}"
        );
        let exited = lines
            .iter()
            .find(|l| l.contains("background_task_exited"))
            .unwrap_or_else(|| panic!("no exit event in {lines:?}"));
        assert!(exited.contains("task=scheduler"), "{exited}");
        assert!(exited.contains("outcome=panicked"), "{exited}");
    }

    /// The case a panic hook structurally cannot see: a loop that simply
    /// RETURNS. No panic, no stderr line — and before this wrapper, no
    /// trace of any kind.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_clean_exit_is_counted_too() {
        let _guard = HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let before_panics = panic_count_for_tests();
        let before = exit_count_for_tests(BackgroundTask::RegistrySync, "completed");
        spawn_supervised(BackgroundTask::RegistrySync, async { TaskExit::LoopEnded })
            .await
            .expect("supervisor task");
        assert_eq!(
            exit_count_for_tests(BackgroundTask::RegistrySync, "completed") - before,
            1.0
        );
        assert_eq!(
            panic_count_for_tests(),
            before_panics,
            "a clean exit must not touch the panic counter"
        );
    }

    /// **THE REGRESSION.** `registry_sync` is a by-config return on this
    /// fleet — `TALOS_REGISTRY_URL` is unset, so the loop declines to
    /// start and disk seeding remains the source of truth. Until
    /// 2026-09-08 that landed on `outcome="completed"` and an ERROR line
    /// one second after every boot, alongside `worker_fleet_management`.
    ///
    /// The pre-fix code could not have been given this test: the future
    /// returned `()`, so a declined start and a dead loop were literally
    /// the same value and no assertion could separate them. What stood
    /// in for it was the live read — `talos_background_task_exits_total`
    /// summing to 2 across 126 series on a healthy controller, and two
    /// `event_kind="background_task_exited"` ERROR lines at
    /// 2026-09-08T11:53:14Z. This test is what that reading is worth
    /// now: the declined outcome moves, `completed` does NOT, and the
    /// log line is an INFO carrying the reason.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_by_config_return_is_declined_not_completed() {
        let _guard = HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let cap = capture();
        let before_completed = exit_count_for_tests(BackgroundTask::RegistrySync, "completed");
        let before_declined = exit_count_for_tests(BackgroundTask::RegistrySync, "declined");
        if let Ok(mut g) = cap.0.lock() {
            g.clear();
        }

        spawn_supervised(BackgroundTask::RegistrySync, async {
            TaskExit::Declined(DeclineReason::NotConfigured)
        })
        .await
        .expect("supervisor task");

        assert_eq!(
            exit_count_for_tests(BackgroundTask::RegistrySync, "declined") - before_declined,
            1.0,
            "a declined start must be recorded under its own outcome"
        );
        assert_eq!(
            exit_count_for_tests(BackgroundTask::RegistrySync, "completed"),
            before_completed,
            "a declined start must NOT move `completed` — that is the series \
             TalosBackgroundTaskExited fires on, and this is a healthy boot"
        );

        let lines = cap.0.lock().expect("capture").clone();
        assert!(
            !lines.iter().any(|l| l.contains("background_task_exited")),
            "a declined start must emit no `background_task_exited` line at all: {lines:?}"
        );
        let declined = lines
            .iter()
            .find(|l| l.contains("background_task_declined"))
            .unwrap_or_else(|| panic!("no decline event in {lines:?}"));
        assert!(declined.contains("target=talos_audit"), "{declined}");
        assert!(declined.contains("task=registry_sync"), "{declined}");
        assert!(declined.contains("outcome=declined"), "{declined}");
        assert!(declined.contains("reason=not_configured"), "{declined}");
    }

    /// A loop that stops because the PROCESS is stopping is the other
    /// healthy return, and it is deliberately not spelled `declined`:
    /// three of the five bodies the 2026-09-08 measurement examined
    /// (both integration renewals and the workflow scheduler) run for
    /// the whole process lifetime and return only on the shutdown watch.
    /// Calling that "declined" would assert they never ran.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_shutdown_return_is_neither_completed_nor_declined() {
        let _guard = HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let cap = capture();
        let before_completed = exit_count_for_tests(BackgroundTask::Scheduler, "completed");
        let before_declined = exit_count_for_tests(BackgroundTask::Scheduler, "declined");
        let before_shutdown = exit_count_for_tests(BackgroundTask::Scheduler, "shutdown");
        if let Ok(mut g) = cap.0.lock() {
            g.clear();
        }

        spawn_supervised(BackgroundTask::Scheduler, async { TaskExit::ShuttingDown })
            .await
            .expect("supervisor task");

        assert_eq!(
            exit_count_for_tests(BackgroundTask::Scheduler, "shutdown") - before_shutdown,
            1.0
        );
        assert_eq!(
            exit_count_for_tests(BackgroundTask::Scheduler, "completed"),
            before_completed
        );
        assert_eq!(
            exit_count_for_tests(BackgroundTask::Scheduler, "declined"),
            before_declined
        );
        let lines = cap.0.lock().expect("capture").clone();
        assert!(
            !lines.iter().any(|l| l.contains("background_task_exited")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("background_task_shutdown")),
            "{lines:?}"
        );
    }

    /// `completed` KEEPS everything it had: the ERROR line and the
    /// alertable increment. The point of the split is that the finding
    /// stays a finding.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_loop_that_fell_out_still_errors() {
        let _guard = HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let cap = capture();
        let before = exit_count_for_tests(BackgroundTask::JobResultSubscriber, "completed");
        if let Ok(mut g) = cap.0.lock() {
            g.clear();
        }
        spawn_supervised(BackgroundTask::JobResultSubscriber, async {
            TaskExit::LoopEnded
        })
        .await
        .expect("supervisor task");
        assert_eq!(
            exit_count_for_tests(BackgroundTask::JobResultSubscriber, "completed") - before,
            1.0
        );
        let lines = cap.0.lock().expect("capture").clone();
        let exited = lines
            .iter()
            .find(|l| l.contains("background_task_exited"))
            .unwrap_or_else(|| panic!("no exit event in {lines:?}"));
        assert!(exited.contains("task=job_result_subscriber"), "{exited}");
        assert!(exited.contains("outcome=completed"), "{exited}");
    }
}

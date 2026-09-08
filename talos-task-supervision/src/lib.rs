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
    WorkerFleetManagement       => "worker_fleet_management",
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
}

/// How a supervised task stopped. Three values, not two: a `JoinError`
/// is either a panic or a cancellation, and folding an abort into
/// "panicked" would report a deliberate shutdown as a defect.
pub const EXIT_OUTCOMES: &[&str] = &["panicked", "completed", "cancelled"];

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
        exits: CounterVec::new(
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
        .expect("static metric opts"),
    })
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
/// this process can increment at 0.
///
/// Split from [`install_panic_hook`] deliberately: the hook must go in
/// before anything can panic, which is earlier than the metrics registry
/// exists. Counts accumulated between the two calls are preserved — the
/// collector is the same object, only its registration is deferred.
///
/// # Errors
/// Propagates a duplicate-registration error from `prometheus`.
pub fn register_metrics(registry: &Registry) -> prometheus::Result<()> {
    let inst = instruments();
    registry.register(Box::new(inst.panics.clone()))?;
    registry.register(Box::new(inst.exits.clone()))?;
    if let Some(p) = PROCESS.get() {
        inst.panics.with_label_values(&[p]).inc_by(0.0);
    }
    for task in BackgroundTask::ALL {
        for outcome in EXIT_OUTCOMES {
            inst.exits
                .with_label_values(&[task.as_str(), outcome])
                .inc_by(0.0);
        }
    }
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
    F: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let inner = tokio::spawn(fut);
        let outcome = match inner.await {
            Ok(()) => "completed",
            Err(e) if e.is_panic() => "panicked",
            Err(_) => "cancelled",
        };
        record_exit(task, outcome);
    })
}

/// Record one supervised-task termination. Public so a task that owns
/// its own join plumbing can report through the same instrument rather
/// than inventing a second one.
pub fn record_exit(task: BackgroundTask, outcome: &'static str) {
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

    #[test]
    fn registering_seeds_every_pair_at_zero() {
        let reg = Registry::new();
        register_metrics(&reg).expect("register");
        let rendered = {
            use prometheus::Encoder as _;
            let mut buf = Vec::new();
            prometheus::TextEncoder::new()
                .encode(&reg.gather(), &mut buf)
                .expect("encode");
            String::from_utf8(buf).expect("utf8")
        };
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
        spawn_supervised(BackgroundTask::RegistrySync, async {})
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
}
